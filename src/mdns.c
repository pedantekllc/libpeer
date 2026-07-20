#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <time.h>
#include <unistd.h>
#include "address.h"
#include "socket.h"
#include "utils.h"

#define MDNS_GROUP "224.0.0.251"
#define MDNS_PORT 5353

typedef struct DnsHeader {
  uint16_t id;
  uint16_t flags;
  uint16_t qestions;
  uint16_t answer_rrs;
  uint16_t authority_rrs;
  uint16_t additional_rrs;
} DnsHeader;

typedef struct DnsAnswer {
  uint16_t type;
  uint16_t class;
  uint32_t ttl;
  uint16_t length;
  uint8_t data[0];
} DnsAnswer;

typedef struct DnsQuery {
  uint16_t type;
  uint16_t class;
} DnsQuery;

static int mdns_add_hostname(const char* hostname, uint8_t* buf, int size) {
  const char *label, *dot;
  int len, offset;

  offset = 0;
  label = hostname;
  while (*label) {
    dot = strchr(label, '.');
    if (!dot) {
      dot = label + strlen(label);
    }
    len = dot - label;
    buf[offset++] = len;
    memcpy(buf + offset, label, len);
    offset += len;
    label = *dot ? dot + 1 : dot;
  }
  buf[offset++] = 0x00;
  return offset;
}
int mdns_parse_answer(uint8_t* buf, int size, Address* addr, const char* hostname) {
  int flags_qr, offset;
  DnsHeader* header;
  DnsAnswer* answer;
  uint8_t name[256];

  if (size < sizeof(DnsHeader)) {
    LOGE("response too short");
    return -1;
  }

  header = (DnsHeader*)buf;
  flags_qr = ntohs(header->flags) >> 15;
  if (flags_qr != 1) {
    LOGD("flag is not a DNS response");
    return -1;
  }

  buf += sizeof(DnsHeader);
  offset = mdns_add_hostname(hostname, name, sizeof(name));
  // compare hostname
  if (memcmp(buf, name, offset)) {
    LOGI("not a mDNS response");
    return -1;
  }

  answer = (DnsAnswer*)(buf + offset);
  LOGD("type: %" PRIu16 ", class: %" PRIu16 ", ttl: %" PRIu32 ", length: %" PRIu16 "", ntohs(answer->type), ntohs(answer->class), ntohl(answer->ttl), ntohs(answer->length));
  if (ntohs(answer->length) != 4) {
    LOGI("invalid length");
    return -1;
  }

  memcpy(&addr->sin.sin_addr, answer->data, 4);
  return 0;
}

int mdns_build_query(const char* hostname, uint8_t* buf, int size) {
  int total_size, offset;
  DnsHeader* dns_header;
  DnsQuery* dns_query;

  total_size = sizeof(DnsHeader) + strlen(hostname) + sizeof(DnsQuery) + 2;
  if (size < total_size) {
    printf("buf size is not enough");
    return -1;
  }

  memset(buf, 0, size);
  dns_header = (DnsHeader*)buf;
  dns_header->qestions = 0x0100;
  offset = sizeof(DnsHeader);

  // Append hostname to query
  offset += mdns_add_hostname(hostname, buf + offset, size - offset);

  dns_query = (DnsQuery*)(buf + offset);
  dns_query->type = 0x0100;
  dns_query->class = 0x0100;
  return total_size;
}

// Overall budget for resolving one .local name, and how often we re-send the
// query within it. A browser's mDNS responder can be slow to answer right
// after the device (or the phone) wakes, and on a busy LAN the answer can be
// lost or arrive behind unrelated mDNS chatter — so we keep listening (without
// a fixed packet budget) and re-query periodically until the deadline.
#define MDNS_TOTAL_TIMEOUT_MS 2000
#define MDNS_RESEND_INTERVAL_MS 250

static uint64_t mdns_now_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

int mdns_resolve_addr(const char* hostname, Address* addr) {
  Address mcast_addr = {0};
  UdpSocket udp_socket;
  uint8_t buf[256];
  char addr_string[ADDRSTRLEN];
  fd_set rfds;
  int size, ret;
  uint64_t deadline, next_send, now, wait_until, wait_ms;

  if (udp_socket_open(&udp_socket, AF_INET, MDNS_PORT) < 0) {
    LOGE("Failed to create socket");
    return 0;  // 0 == unresolved (callers treat non-zero as success)
  }

  addr_from_string(MDNS_GROUP, &mcast_addr);
  addr_set_port(&mcast_addr, MDNS_PORT);
  if (udp_socket_add_multicast_group(&udp_socket, &mcast_addr) < 0) {
    LOGE("Failed to add multicast group");
    udp_socket_close(&udp_socket);
    return 0;
  }

  deadline = mdns_now_ms() + MDNS_TOTAL_TIMEOUT_MS;
  next_send = 0;  // 0 forces an immediate first query below

  while ((now = mdns_now_ms()) < deadline) {
    // (Re)send the query periodically to survive multicast loss.
    if (now >= next_send) {
      size = mdns_build_query(hostname, buf, sizeof(buf));
      if (size > 0) {
        udp_socket_sendto(&udp_socket, &mcast_addr, buf, size);
      }
      next_send = now + MDNS_RESEND_INTERVAL_MS;
    }

    // Wait for a packet, but never past the next resend or the overall
    // deadline. Recompute the timeout each iteration rather than relying on
    // select() decrementing tv (Linux-only behaviour).
    wait_until = next_send < deadline ? next_send : deadline;
    wait_ms = wait_until > now ? wait_until - now : 0;

    FD_ZERO(&rfds);
    FD_SET(udp_socket.fd, &rfds);
    struct timeval tv = {(time_t)(wait_ms / 1000), (suseconds_t)((wait_ms % 1000) * 1000)};
    ret = select(udp_socket.fd + 1, &rfds, NULL, NULL, &tv);

    if (ret < 0) {
      LOGE("select error");
      break;
    }
    if (ret == 0 || !FD_ISSET(udp_socket.fd, &rfds)) {
      continue;  // slice timed out; loop re-checks deadline and re-sends
    }

    ret = udp_socket_recvfrom(&udp_socket, NULL, buf, sizeof(buf));
    if (ret > 0 && mdns_parse_answer(buf, ret, addr, hostname) == 0) {
      addr_set_family(addr, AF_INET);
      addr_to_string(addr, addr_string, sizeof(addr_string));
      LOGI("Resolved %s -> %s", hostname, addr_string);
      udp_socket_close(&udp_socket);
      return 1;
    }
    // Non-matching packet (other devices' mDNS chatter): ignore and keep
    // listening. Crucially we do NOT consume a fixed retry budget here, so
    // noise can't starve us out before the real answer arrives.
  }

  LOGI("Failed to resolve hostname %s", hostname);
  udp_socket_close(&udp_socket);
  return 0;
}

// ── Async resolver (see mdns.h) ─────────────────────────────────────────────
// One shared 5353 multicast socket, opened while any query is pending, plus a
// small state table. Everything runs on the caller's (reactor) thread.

#define MDNS_ASYNC_MAX 8
#define MDNS_ASYNC_CACHE_MS 30000  /* keep a result this long for late lookups */
#define MDNS_ASYNC_FAIL_CACHE_MS 5000

typedef enum {
  MDNS_ENTRY_FREE = 0,
  MDNS_ENTRY_PENDING,
  MDNS_ENTRY_RESOLVED,
  MDNS_ENTRY_FAILED,
} MdnsEntryState;

typedef struct {
  MdnsEntryState state;
  char hostname[128];
  Address addr;         /* RESOLVED: the answer (IP only) */
  uint64_t deadline;    /* PENDING: give up at this time */
  uint64_t next_send;   /* PENDING: next query (re)send */
  uint64_t expire_at;   /* RESOLVED/FAILED: free the slot at this time */
} MdnsAsyncEntry;

static MdnsAsyncEntry g_mdns_entries[MDNS_ASYNC_MAX];
static UdpSocket g_mdns_async_socket;
static int g_mdns_async_socket_open = 0;

static int mdns_async_ensure_socket(void) {
  Address mcast_addr = {0};
  if (g_mdns_async_socket_open) {
    return 0;
  }
  if (udp_socket_open(&g_mdns_async_socket, AF_INET, MDNS_PORT) < 0) {
    LOGE("mdns-async: failed to open socket");
    return -1;
  }
  addr_from_string(MDNS_GROUP, &mcast_addr);
  addr_set_port(&mcast_addr, MDNS_PORT);
  if (udp_socket_add_multicast_group(&g_mdns_async_socket, &mcast_addr) < 0) {
    LOGE("mdns-async: failed to join multicast group");
    udp_socket_close(&g_mdns_async_socket);
    return -1;
  }
  g_mdns_async_socket_open = 1;
  return 0;
}

int mdns_async_request(const char* hostname) {
  int i, free_slot = -1;
  uint64_t now = mdns_now_ms();

  for (i = 0; i < MDNS_ASYNC_MAX; i++) {
    MdnsAsyncEntry* e = &g_mdns_entries[i];
    if (e->state != MDNS_ENTRY_FREE && strcmp(e->hostname, hostname) == 0) {
      return 0;  /* already pending or cached */
    }
    if (e->state == MDNS_ENTRY_FREE && free_slot < 0) {
      free_slot = i;
    }
  }
  if (free_slot < 0) {
    LOGW("mdns-async: pending table full, dropping %s", hostname);
    return -1;
  }
  if (mdns_async_ensure_socket() != 0) {
    return -1;
  }

  MdnsAsyncEntry* e = &g_mdns_entries[free_slot];
  memset(e, 0, sizeof(*e));
  snprintf(e->hostname, sizeof(e->hostname), "%s", hostname);
  e->state = MDNS_ENTRY_PENDING;
  e->deadline = now + MDNS_TOTAL_TIMEOUT_MS;
  e->next_send = 0;  /* poll sends the first query immediately */
  return 0;
}

void mdns_async_poll(void) {
  uint8_t buf[256];
  uint8_t query[256];
  char addr_string[ADDRSTRLEN];
  Address mcast_addr = {0};
  fd_set rfds;
  struct timeval tv;
  uint64_t now = mdns_now_ms();
  int i, ret, size, any_pending = 0;

  for (i = 0; i < MDNS_ASYNC_MAX; i++) {
    MdnsAsyncEntry* e = &g_mdns_entries[i];
    switch (e->state) {
      case MDNS_ENTRY_PENDING:
        if (now >= e->deadline) {
          LOGI("mdns-async: %s did not resolve", e->hostname);
          e->state = MDNS_ENTRY_FAILED;
          e->expire_at = now + MDNS_ASYNC_FAIL_CACHE_MS;
          break;
        }
        any_pending = 1;
        if (now >= e->next_send && g_mdns_async_socket_open) {
          size = mdns_build_query(e->hostname, query, sizeof(query));
          if (size > 0) {
            addr_from_string(MDNS_GROUP, &mcast_addr);
            addr_set_port(&mcast_addr, MDNS_PORT);
            udp_socket_sendto(&g_mdns_async_socket, &mcast_addr, query, size);
          }
          e->next_send = now + MDNS_RESEND_INTERVAL_MS;
        }
        break;
      case MDNS_ENTRY_RESOLVED:
      case MDNS_ENTRY_FAILED:
        if (now >= e->expire_at) {
          e->state = MDNS_ENTRY_FREE;
        }
        break;
      default:
        break;
    }
  }

  if (!g_mdns_async_socket_open) {
    return;
  }

  /* Drain every available datagram without blocking (0-timeout select). */
  for (;;) {
    FD_ZERO(&rfds);
    FD_SET(g_mdns_async_socket.fd, &rfds);
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    ret = select(g_mdns_async_socket.fd + 1, &rfds, NULL, NULL, &tv);
    if (ret <= 0 || !FD_ISSET(g_mdns_async_socket.fd, &rfds)) {
      break;
    }
    ret = udp_socket_recvfrom(&g_mdns_async_socket, NULL, buf, sizeof(buf));
    if (ret <= 0) {
      break;
    }
    for (i = 0; i < MDNS_ASYNC_MAX; i++) {
      MdnsAsyncEntry* e = &g_mdns_entries[i];
      if (e->state != MDNS_ENTRY_PENDING) {
        continue;
      }
      if (mdns_parse_answer(buf, ret, &e->addr, e->hostname) == 0) {
        addr_set_family(&e->addr, AF_INET);
        addr_to_string(&e->addr, addr_string, sizeof(addr_string));
        LOGI("mdns-async: resolved %s -> %s", e->hostname, addr_string);
        e->state = MDNS_ENTRY_RESOLVED;
        e->expire_at = now + MDNS_ASYNC_CACHE_MS;
        break;
      }
    }
  }

  /* No queries in flight: release the shared socket (reopened on demand). */
  if (!any_pending) {
    udp_socket_close(&g_mdns_async_socket);
    g_mdns_async_socket_open = 0;
  }
}

int mdns_async_lookup(const char* hostname, Address* addr) {
  int i;
  for (i = 0; i < MDNS_ASYNC_MAX; i++) {
    MdnsAsyncEntry* e = &g_mdns_entries[i];
    if (e->state == MDNS_ENTRY_FREE || strcmp(e->hostname, hostname) != 0) {
      continue;
    }
    switch (e->state) {
      case MDNS_ENTRY_PENDING:
        return 0;
      case MDNS_ENTRY_RESOLVED:
        *addr = e->addr;
        return 1;
      default:
        return -1;
    }
  }
  return -1;
}
