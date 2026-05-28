// Multi-PeerConnection datachannel throughput bench.
//
// Tests whether N independent PeerConnections (each its own DTLS session,
// own usrsctp association, own mbedtls context, own pc_task thread) actually
// deliver multi-core throughput. The single-PC bench (bench_dc_net) saturates
// one core at ~7 MB/s on Pi 3 B+; an SCTP+DTLS association is fundamentally
// single-threaded inside mbedtls and usrsctp, so the only way to use more
// cores is more PeerConnections.
//
//   recv (answerer): bench_dc_pool recv <port> [N]
//   send (offerer) : bench_dc_pool send <recv_ip> <recv_port> [N]
//
// Default N=4. All N SDP exchanges go over a single TCP rendezvous socket
// (same shape as a production app multiplexing N SDPs over one MQTT topic).
//
// Env: BENCH_MB, BENCH_SECS (per-PC byte/time target), BENCH_CHUNK, BENCH_QUIET
//
// All bench output goes to stderr; libpeer's zlog goes to stdout (use
// `>/dev/null` to suppress). RESULT line at the end is grep-friendly.

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "peer.h"

#define DCNAME "libpeer-pool"
#define HELLO "HELLO"
#define MAX_PCS 16

static volatile int g_stop = 0;

typedef struct {
  int idx;
  PeerConnection* pc;
  volatile uint64_t recv_bytes;
  volatile uint64_t sent_bytes;
  volatile uint64_t eagain;
  volatile int hello_seen;   /* on_msg saw a HELLO from the peer */
  volatile int hello_echoed; /* we sent HELLO back (recv side) */
  volatile int dc_open;      /* sender successfully called create_datachannel */
} PcCtx;

static PcCtx g_ctxs[MAX_PCS];
static int g_n = 0;

static double now_s(void) {
  struct timespec t;
  clock_gettime(CLOCK_MONOTONIC, &t);
  return t.tv_sec + t.tv_nsec / 1e9;
}
static void on_state(PeerConnectionState s, void* u) {
  PcCtx* c = (PcCtx*)u;
  fprintf(stderr, "pc[%d] state: %s\n", c->idx, peer_connection_state_to_string(s));
}
static void on_ice(char* d, void* u) {}

static void on_msg(char* msg, size_t len, void* u, uint16_t sid) {
  PcCtx* c = (PcCtx*)u;
  if (len == sizeof(HELLO) && strcmp(msg, HELLO) == 0) {
    c->hello_seen = 1;
    return;
  }
  c->recv_bytes += len;
}

static void* pc_loop(void* u) {
  PeerConnection* pc = (PeerConnection*)u;
  while (!g_stop) {
    peer_connection_loop(pc);
    usleep(1000);
  }
  return NULL;
}

/* Per-PC sender thread: pump bytes until SECS expires or TARGET reached. */
typedef struct {
  PcCtx* ctx;
  uint64_t target_bytes;
  double secs;
  size_t chunk;
  double t0;
} SenderArgs;

static void* sender_loop(void* u) {
  SenderArgs* a = (SenderArgs*)u;
  PcCtx* c = a->ctx;
  uint8_t* buf = malloc(a->chunk);
  memset(buf, 0xAB, a->chunk);
  while (!g_stop) {
    double now = now_s();
    if (a->secs > 0.0) {
      if (now - a->t0 >= a->secs) break;
    } else if (c->sent_bytes >= a->target_bytes) {
      break;
    }
    int r = peer_connection_datachannel_send_binary(c->pc, buf, a->chunk);
    if (r < 0) {
      c->eagain++;
      usleep(200);
    } else {
      c->sent_bytes += a->chunk;
    }
  }
  free(buf);
  return NULL;
}

/* length-prefixed blocking send/recv of an SDP blob over TCP */
static int blob_write(int fd, const char* s) {
  uint32_t n = htonl((uint32_t)strlen(s));
  if (write(fd, &n, 4) != 4) return -1;
  size_t off = 0, len = strlen(s);
  while (off < len) {
    ssize_t w = write(fd, s + off, len - off);
    if (w <= 0) return -1;
    off += w;
  }
  return 0;
}
static char* blob_read(int fd) {
  uint32_t n;
  if (read(fd, &n, 4) != 4) return NULL;
  n = ntohl(n);
  char* b = malloc(n + 1);
  size_t off = 0;
  while (off < n) {
    ssize_t r = read(fd, b + off, n - off);
    if (r <= 0) {
      free(b);
      return NULL;
    }
    off += r;
  }
  b[n] = 0;
  return b;
}

static void quiet_stdout(void) {
  int devnull = open("/dev/null", O_WRONLY);
  if (devnull >= 0) {
    dup2(devnull, STDOUT_FILENO);
    close(devnull);
  }
}

int main(int argc, char** argv) {
  if (argc < 2) {
    fprintf(stderr, "usage: %s recv <port> [N] | send <ip> <port> [N]\n", argv[0]);
    return 2;
  }
  int is_send = strcmp(argv[1], "send") == 0;
  if ((is_send && argc < 4) || (!is_send && argc < 3)) {
    fprintf(stderr, "usage: %s recv <port> [N] | send <ip> <port> [N]\n", argv[0]);
    return 2;
  }
  int n_arg_idx = is_send ? 4 : 3;
  g_n = (argc > n_arg_idx) ? atoi(argv[n_arg_idx]) : 4;
  if (g_n < 1 || g_n > MAX_PCS) {
    fprintf(stderr, "N must be in [1,%d]\n", MAX_PCS);
    return 2;
  }
  const uint64_t TARGET_MB = (uint64_t)(getenv("BENCH_MB") ? atoll(getenv("BENCH_MB")) : 100);
  const uint64_t TARGET = TARGET_MB * 1024 * 1024;
  const double SECS = getenv("BENCH_SECS") ? atof(getenv("BENCH_SECS")) : 0.0;
  const size_t CHUNK = getenv("BENCH_CHUNK") ? atoll(getenv("BENCH_CHUNK")) : 16384;
  const int quiet = getenv("BENCH_QUIET") != NULL;

  peer_init();

  /* Create all N PeerConnections + spawn pc_task threads up front. */
  pthread_t pc_threads[MAX_PCS];
  for (int i = 0; i < g_n; i++) {
    g_ctxs[i].idx = i;
    PeerConfiguration cfg = {
        .ice_servers = {{.urls = "stun:stun.l.google.com:19302"}},
        .datachannel = DATA_CHANNEL_STRING,
        .video_codec = CODEC_H264,
        .audio_codec = CODEC_OPUS,
        .user_data = &g_ctxs[i],
    };
    g_ctxs[i].pc = peer_connection_create(&cfg);
    peer_connection_oniceconnectionstatechange(g_ctxs[i].pc, on_state);
    peer_connection_onicecandidate(g_ctxs[i].pc, on_ice);
    peer_connection_ondatachannel(g_ctxs[i].pc, on_msg, NULL, NULL);
    pthread_create(&pc_threads[i], NULL, pc_loop, g_ctxs[i].pc);
  }

  /* TCP rendezvous: N sequential SDP exchanges over one socket. */
  int cs;
  if (!is_send) {
    int port = atoi(argv[2]);
    int ls = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = INADDR_ANY;
    a.sin_port = htons(port);
    if (bind(ls, (struct sockaddr*)&a, sizeof a) < 0) {
      perror("bind");
      return 1;
    }
    listen(ls, 1);
    fprintf(stderr, "recv: waiting for sender on :%d (N=%d)\n", port, g_n);
    cs = accept(ls, NULL, NULL);
    for (int i = 0; i < g_n; i++) {
      char* offer = blob_read(cs);
      if (!offer) {
        fprintf(stderr, "no offer for pc[%d]\n", i);
        return 1;
      }
      peer_connection_set_remote_description(g_ctxs[i].pc, offer, SDP_TYPE_OFFER);
      const char* ans = peer_connection_create_answer(g_ctxs[i].pc);
      while (!ans) {
        usleep(10000);
        ans = peer_connection_create_answer(g_ctxs[i].pc);
      }
      blob_write(cs, ans);
      free(offer);
      fprintf(stderr, "recv: pc[%d] SDP exchanged\n", i);
    }
  } else {
    int port = atoi(argv[3]);
    cs = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    inet_pton(AF_INET, argv[2], &a.sin_addr);
    while (connect(cs, (struct sockaddr*)&a, sizeof a) < 0) {
      fprintf(stderr, "connect retry...\n");
      sleep(1);
    }
    for (int i = 0; i < g_n; i++) {
      const char* offer = peer_connection_create_offer(g_ctxs[i].pc);
      while (!offer) {
        usleep(10000);
        offer = peer_connection_create_offer(g_ctxs[i].pc);
      }
      blob_write(cs, offer);
      char* ans = blob_read(cs);
      if (!ans) {
        fprintf(stderr, "no answer for pc[%d]\n", i);
        return 1;
      }
      peer_connection_set_remote_description(g_ctxs[i].pc, ans, SDP_TYPE_ANSWER);
      free(ans);
      fprintf(stderr, "send: pc[%d] SDP exchanged\n", i);
    }
  }

  /* Wait for all PCs to reach COMPLETED + open DCs (sender) + HELLO ack
   * across the pool. Hard-bound the wait to avoid runaway hangs. */
  double t_setup = now_s();
  if (is_send) {
    /* Sender: open one DC per PC, then HELLO until echoed on each. */
    while (now_s() - t_setup < 30.0) {
      int all_dc = 1;
      for (int i = 0; i < g_n; i++) {
        if (!g_ctxs[i].dc_open) {
          if (peer_connection_get_state(g_ctxs[i].pc) == PEER_CONNECTION_COMPLETED) {
            int r = peer_connection_create_datachannel(g_ctxs[i].pc, DATA_CHANNEL_RELIABLE, 0,
                                                       0, DCNAME, "bar");
            if (r > 0) g_ctxs[i].dc_open = 1;
          }
          all_dc = 0;
        }
      }
      if (all_dc) break;
      usleep(50000);
    }
    int n_dc = 0;
    for (int i = 0; i < g_n; i++)
      if (g_ctxs[i].dc_open) n_dc++;
    fprintf(stderr, "send: %d/%d datachannels open\n", n_dc, g_n);
    if (n_dc == 0) return 1;

    /* HELLO-echo handshake per PC. */
    double t_hello = now_s();
    while (now_s() - t_hello < 10.0) {
      int all_acked = 1;
      for (int i = 0; i < g_n; i++) {
        if (g_ctxs[i].dc_open && !g_ctxs[i].hello_seen) {
          peer_connection_datachannel_send(g_ctxs[i].pc, HELLO, sizeof(HELLO));
          all_acked = 0;
        }
      }
      if (all_acked) break;
      usleep(50000);
    }
    int n_ready = 0;
    for (int i = 0; i < g_n; i++)
      if (g_ctxs[i].hello_seen) n_ready++;
    fprintf(stderr, "send: %d/%d PCs HELLO-acked, starting bulk push (chunk=%zu, %s)\n", n_ready,
            g_n, CHUNK, SECS > 0.0 ? "time-bound" : "byte-bound");
  } else {
    /* Receiver: echo HELLO once per PC. */
    while (now_s() - t_setup < 30.0) {
      int all_echoed = 1;
      for (int i = 0; i < g_n; i++) {
        if (g_ctxs[i].hello_seen && !g_ctxs[i].hello_echoed) {
          peer_connection_datachannel_send(g_ctxs[i].pc, HELLO, sizeof(HELLO));
          g_ctxs[i].hello_echoed = 1;
        }
        if (!g_ctxs[i].hello_echoed) all_echoed = 0;
      }
      if (all_echoed) break;
      usleep(10000);
    }
    int n_ready = 0;
    for (int i = 0; i < g_n; i++)
      if (g_ctxs[i].hello_echoed) n_ready++;
    fprintf(stderr, "recv: %d/%d PCs HELLO-echoed, waiting for bulk data\n", n_ready, g_n);
  }

  if (quiet) quiet_stdout();

  /* Steady-state phase. Sender: spawn N sender threads. Receiver: just sample. */
  double t0 = now_s();
  pthread_t sender_threads[MAX_PCS];
  SenderArgs sargs[MAX_PCS];
  if (is_send) {
    for (int i = 0; i < g_n; i++) {
      if (!g_ctxs[i].hello_seen) continue;  /* skip unready PCs */
      sargs[i].ctx = &g_ctxs[i];
      sargs[i].target_bytes = TARGET;
      sargs[i].secs = SECS;
      sargs[i].chunk = CHUNK;
      sargs[i].t0 = t0;
      pthread_create(&sender_threads[i], NULL, sender_loop, &sargs[i]);
    }
  }

  /* 1Hz progress sampler. */
  double last_report = t0;
  uint64_t last_total = 0;
  while (1) {
    double now = now_s();
    /* Pool-wide stop condition. */
    uint64_t total = 0;
    for (int i = 0; i < g_n; i++) {
      total += is_send ? g_ctxs[i].sent_bytes : g_ctxs[i].recv_bytes;
    }
    if (SECS > 0.0) {
      if (now - t0 >= SECS) break;
    } else if (total >= TARGET * (uint64_t)g_n) {
      break;
    } else if (now - t0 > 120.0) {
      break;
    }
    if (now - last_report >= 1.0) {
      double mbps = (double)(total - last_total) / 1e6 / (now - last_report);
      /* per-PC line for visibility into how evenly the pool spreads */
      fprintf(stderr, "[%5.1fs] %s total=%llu MB rate=%.2f MB/s (%.0f Mbit/s) [", now - t0,
              is_send ? "sent" : "recv", (unsigned long long)(total / 1024 / 1024), mbps,
              mbps * 8);
      for (int i = 0; i < g_n; i++) {
        uint64_t b = is_send ? g_ctxs[i].sent_bytes : g_ctxs[i].recv_bytes;
        fprintf(stderr, "%s%llu", i ? "/" : "", (unsigned long long)(b / 1024 / 1024));
      }
      fprintf(stderr, "MB]\n");
      last_report = now;
      last_total = total;
    }
    usleep(50000);
  }
  double t1 = now_s();

  if (is_send) {
    for (int i = 0; i < g_n; i++) {
      if (g_ctxs[i].hello_seen) pthread_join(sender_threads[i], NULL);
    }
  }

  /* Final stats. */
  uint64_t total_bytes = 0, total_eagain = 0;
  for (int i = 0; i < g_n; i++) {
    total_bytes += is_send ? g_ctxs[i].sent_bytes : g_ctxs[i].recv_bytes;
    total_eagain += g_ctxs[i].eagain;
  }
  double elapsed = t1 - t0;
  double mbps = (double)total_bytes / 1e6 / elapsed;
  fprintf(stderr, "\n=== bench_dc_pool %s N=%d ===\n", is_send ? "sender" : "receiver", g_n);
  for (int i = 0; i < g_n; i++) {
    uint64_t b = is_send ? g_ctxs[i].sent_bytes : g_ctxs[i].recv_bytes;
    double m = (double)b / 1e6 / elapsed;
    fprintf(stderr, "  pc[%d] %llu B  %.2f MB/s (%.0f Mbit/s)  eagain=%llu\n", i,
            (unsigned long long)b, m, m * 8, (unsigned long long)g_ctxs[i].eagain);
  }
  fprintf(stderr, "AGGREGATE %llu B in %.2fs -> %.2f MB/s (%.0f Mbit/s) [eagain=%llu]\n",
          (unsigned long long)total_bytes, elapsed, mbps, mbps * 8,
          (unsigned long long)total_eagain);
  fprintf(stderr,
          "RESULT mode=%s N=%d bytes=%llu time=%.3f mbps=%.3f mbits=%.1f eagain=%llu chunk=%zu\n",
          is_send ? "send" : "recv", g_n, (unsigned long long)total_bytes, elapsed, mbps,
          mbps * 8, (unsigned long long)total_eagain, CHUNK);

  /* Optional drain time on the sender side. */
  if (is_send) sleep(2);

  g_stop = 1;
  for (int i = 0; i < g_n; i++) pthread_join(pc_threads[i], NULL);
  for (int i = 0; i < g_n; i++) peer_connection_destroy(g_ctxs[i].pc);
  peer_deinit();
  return 0;
}
