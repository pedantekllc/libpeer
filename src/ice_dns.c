#include "ice_dns.h"

#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "ports.h"
#include "utils.h"

typedef struct {
  char host[64];
  IceDnsState state;
  Address addr;
  uint32_t next_due_ms;
  int due_now; /* resolve at the next pass regardless of next_due_ms */
} IceDnsEntry;

static struct {
  pthread_mutex_t mtx;
  pthread_cond_t cv;
  IceDnsEntry entries[ICE_DNS_MAX_HOSTS];
  int count;
  IceDnsResolver resolver;
  pthread_t thread;
  int running;
  int stop;
} g = {.mtx = PTHREAD_MUTEX_INITIALIZER, .cv = PTHREAD_COND_INITIALIZER};

void ice_dns_set_resolver(IceDnsResolver resolver) {
  pthread_mutex_lock(&g.mtx);
  g.resolver = resolver;
  pthread_mutex_unlock(&g.mtx);
}

/* Caller holds g.mtx. */
static IceDnsEntry* find_or_add_locked(const char* host) {
  for (int i = 0; i < g.count; i++) {
    if (strcmp(g.entries[i].host, host) == 0) return &g.entries[i];
  }
  if (g.count >= ICE_DNS_MAX_HOSTS || strlen(host) >= sizeof(g.entries[0].host)) {
    LOGW("ice dns: cannot watch %s (table full or name too long)", host);
    return NULL;
  }
  IceDnsEntry* e = &g.entries[g.count++];
  memset(e, 0, sizeof(*e));
  snprintf(e->host, sizeof(e->host), "%s", host);
  e->state = ICE_DNS_NEVER_RESOLVED;
  e->due_now = 1;
  pthread_cond_signal(&g.cv);
  return e;
}

void ice_dns_watch(const char* host) {
  if (!host || !host[0]) return;
  pthread_mutex_lock(&g.mtx);
  (void)find_or_add_locked(host);
  pthread_mutex_unlock(&g.mtx);
}

int ice_dns_parse_url(const char* url, bool* is_tls, char* host, size_t host_cap, int* port) {
  if (!url) return -1;
  const char* colon = strchr(url, ':');
  if (!colon) return -1;
  size_t scheme_len = (size_t)(colon - url);
  *is_tls = (scheme_len > 0 && url[scheme_len - 1] == 's');
  const char* h = colon + 1;
  const char* p = strchr(h, ':');
  if (!p) return -1;
  int prt = atoi(p + 1);
  if (prt <= 0) return -1;
  size_t hl = (size_t)(p - h);
  if (hl == 0 || hl >= host_cap) return -1;
  memcpy(host, h, hl);
  host[hl] = '\0';
  *port = prt;
  return 0;
}

void ice_dns_watch_url(const char* url) {
  bool tls;
  char host[64];
  int port;
  if (ice_dns_parse_url(url, &tls, host, sizeof(host), &port) != 0 || tls) return;
  ice_dns_watch(host);
}

IceDnsLookup ice_dns_lookup(const char* host) {
  IceDnsLookup out;
  memset(&out, 0, sizeof(out));
  out.state = ICE_DNS_NEVER_RESOLVED;
  if (!host || !host[0]) return out;
  pthread_mutex_lock(&g.mtx);
  IceDnsEntry* e = find_or_add_locked(host);
  if (e && e->state == ICE_DNS_RESOLVED) {
    out.state = ICE_DNS_RESOLVED;
    out.addr = e->addr;
  }
  pthread_mutex_unlock(&g.mtx);
  return out;
}

static int time_reached(uint32_t now, uint32_t due) { return (int32_t)(now - due) >= 0; }

void ice_dns_refresh_due(uint32_t now_ms) {
  for (int i = 0;; i++) {
    char host[64];
    IceDnsResolver resolver;
    pthread_mutex_lock(&g.mtx);
    if (i >= g.count) {
      pthread_mutex_unlock(&g.mtx);
      return;
    }
    IceDnsEntry* e = &g.entries[i];
    if (!e->due_now && !time_reached(now_ms, e->next_due_ms)) {
      pthread_mutex_unlock(&g.mtx);
      continue;
    }
    snprintf(host, sizeof(host), "%s", e->host);
    resolver = g.resolver ? g.resolver : ports_resolve_addr;
    e->due_now = 0;
    pthread_mutex_unlock(&g.mtx);

    Address addr;
    memset(&addr, 0, sizeof(addr));
    int rc = resolver(host, &addr); /* the network wait, outside the lock */

    pthread_mutex_lock(&g.mtx);
    /* ice_dns_reset may have emptied the table meanwhile. */
    if (i < g.count && strcmp(g.entries[i].host, host) == 0) {
      e = &g.entries[i];
      if (rc == 0) {
        e->addr = addr;
        e->state = ICE_DNS_RESOLVED;
        e->next_due_ms = now_ms + ICE_DNS_REFRESH_MS;
      } else {
        /* A failed refresh keeps the last good address. */
        e->next_due_ms = now_ms + ICE_DNS_RETRY_MS;
        LOGW("ice dns: resolve %s failed%s", host,
             e->state == ICE_DNS_RESOLVED ? ", keeping the last address" : "");
      }
    }
    pthread_mutex_unlock(&g.mtx);
  }
}

static uint32_t mono_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint32_t)((uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u);
}

static void* dns_thread(void* arg) {
  (void)arg;
  pthread_mutex_lock(&g.mtx);
  while (!g.stop) {
    pthread_mutex_unlock(&g.mtx);
    ice_dns_refresh_due(mono_ms());
    pthread_mutex_lock(&g.mtx);
    if (g.stop) break;
    int pending = 0;
    for (int i = 0; i < g.count; i++) pending |= g.entries[i].due_now;
    if (!pending) {
      struct timespec until;
      clock_gettime(CLOCK_REALTIME, &until);
      until.tv_sec += 1;
      pthread_cond_timedwait(&g.cv, &g.mtx, &until);
    }
  }
  pthread_mutex_unlock(&g.mtx);
  return NULL;
}

void ice_dns_start(void) {
  pthread_mutex_lock(&g.mtx);
  if (g.running) {
    pthread_mutex_unlock(&g.mtx);
    return;
  }
  g.stop = 0;
  if (pthread_create(&g.thread, NULL, dns_thread, NULL) == 0) {
    g.running = 1;
  } else {
    LOGE("ice dns: refresh thread did not start");
  }
  pthread_mutex_unlock(&g.mtx);
}

void ice_dns_stop(void) {
  pthread_mutex_lock(&g.mtx);
  if (!g.running) {
    pthread_mutex_unlock(&g.mtx);
    return;
  }
  g.stop = 1;
  pthread_cond_signal(&g.cv);
  pthread_mutex_unlock(&g.mtx);
  pthread_join(g.thread, NULL);
  pthread_mutex_lock(&g.mtx);
  g.running = 0;
  pthread_mutex_unlock(&g.mtx);
}

void ice_dns_reset(void) {
  pthread_mutex_lock(&g.mtx);
  g.count = 0;
  memset(g.entries, 0, sizeof(g.entries));
  pthread_mutex_unlock(&g.mtx);
}
