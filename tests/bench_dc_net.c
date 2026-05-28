// Two-process libpeer datachannel throughput bench over a REAL network.
//   recv (answerer): bench_dc_net recv <listen_port>
//   send (offerer) : bench_dc_net send <recv_ip> <recv_port>
// SDP offer/answer are exchanged over a small TCP rendezvous socket; the media
// (DTLS-SCTP datachannel) then runs over ICE host candidates = the wire.
//
// Real scenario = camera(Pi) sends to viewer(Mac): run `send` on the Pi,
// `recv` on the Mac. The Pi encrypts (software AES), Mac decrypts.
//
// All bench output goes to stderr; libpeer's zlog goes to stdout (it's
// chatty — every SCTP EAGAIN logs an ERROR line). Run with `>/dev/null`
// to suppress libpeer noise:
//   ./bench_dc_net recv 9000 >/dev/null
//   ./bench_dc_net send 192.168.2.254 9000 >/dev/null
// BENCH_QUIET=1 dup2s stdout to /dev/null inside the process so libpeer's
// own logging doesn't burn CPU formatting strings during the throughput
// loop (matters on the Pi).
//
// Env:
//   BENCH_MB     total MB to push (default 100; ignored if BENCH_SECS set)
//   BENCH_SECS   time-bound mode: push for N seconds instead of N MB
//   BENCH_CHUNK  send chunk size bytes (default 16384)
//   BENCH_QUIET  if set, mute libpeer stdout after init (recommended)
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

#define DCNAME "libpeer-datachannel"
#define HELLO "HELLO"

static volatile int g_stop = 0;
static volatile uint64_t g_recv = 0;
static volatile int g_hello = 0;

static double now_s(void) {
  struct timespec t;
  clock_gettime(CLOCK_MONOTONIC, &t);
  return t.tv_sec + t.tv_nsec / 1e9;
}
static void on_state(PeerConnectionState s, void* u) {
  fprintf(stderr, "state: %s\n", peer_connection_state_to_string(s));
}
static void on_ice(char* d, void* u) {}
static void on_msg(char* msg, size_t len, void* u, uint16_t sid) {
  if (len == sizeof(HELLO) && strcmp(msg, HELLO) == 0) {
    g_hello = 1;
    return;
  }
  g_recv += len;
}
static void* loop_task(void* u) {
  PeerConnection* pc = (PeerConnection*)u;
  while (!g_stop) {
    peer_connection_loop(pc);
    usleep(1000);
  }
  return NULL;
}

// length-prefixed blocking send/recv of a text blob over TCP
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

// Mute libpeer's stdout chatter so it doesn't eat throughput.
static void quiet_stdout(void) {
  int devnull = open("/dev/null", O_WRONLY);
  if (devnull >= 0) {
    dup2(devnull, STDOUT_FILENO);
    close(devnull);
  }
}

int main(int argc, char* argv[]) {
  if (argc < 2) {
    fprintf(stderr, "usage: %s recv <port> | send <ip> <port>\n", argv[0]);
    return 2;
  }
  const uint64_t TARGET_MB = (uint64_t)(getenv("BENCH_MB") ? atoll(getenv("BENCH_MB")) : 100);
  const uint64_t TARGET = TARGET_MB * 1024 * 1024;
  const double SECS = getenv("BENCH_SECS") ? atof(getenv("BENCH_SECS")) : 0.0;
  const size_t CHUNK = getenv("BENCH_CHUNK") ? atoll(getenv("BENCH_CHUNK")) : 16384;
  const int quiet = getenv("BENCH_QUIET") != NULL;
  int is_send = strcmp(argv[1], "send") == 0;

  PeerConfiguration config = {.ice_servers = {{.urls = "stun:stun.l.google.com:19302"}},
                              .datachannel = DATA_CHANNEL_STRING,
                              .video_codec = CODEC_H264,
                              .audio_codec = CODEC_OPUS};
  peer_init();
  PeerConnection* pc = peer_connection_create(&config);
  peer_connection_oniceconnectionstatechange(pc, on_state);
  peer_connection_onicecandidate(pc, on_ice);
  peer_connection_ondatachannel(pc, on_msg, NULL, NULL);
  pthread_t th;
  pthread_create(&th, NULL, loop_task, pc);

  if (!is_send) {
    // RECEIVER / answerer
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
    fprintf(stderr, "recv: waiting for sender on :%d\n", port);
    int cs = accept(ls, NULL, NULL);
    char* offer = blob_read(cs);
    if (!offer) {
      fprintf(stderr, "no offer\n");
      return 1;
    }
    peer_connection_set_remote_description(pc, offer, SDP_TYPE_OFFER);
    const char* ans = peer_connection_create_answer(pc);
    while (!ans) {
      usleep(10000);
      ans = peer_connection_create_answer(pc);
    }
    blob_write(cs, ans);
    fprintf(stderr, "recv: answer sent, waiting for HELLO + data...\n");

    // When the sender's HELLO arrives, echo it back so the sender knows the
    // channel is bidirectional. on_msg sets g_hello and won't count HELLO in
    // g_recv. We poll g_hello here from the main thread.
    int echoed = 0;
    while (!echoed) {
      if (g_hello) {
        peer_connection_datachannel_send(pc, HELLO, sizeof(HELLO));
        echoed = 1;
        fprintf(stderr, "recv: HELLO received, echoed back\n");
      }
      usleep(10000);
    }

    if (quiet) quiet_stdout();

    // Wait for first bulk byte
    while (g_recv == 0 && !g_stop) usleep(2000);
    double t0 = now_s();
    double last_report = t0;
    uint64_t last_recv = g_recv;
    // Stop condition: byte-bound or time-bound
    while (!g_stop) {
      double now = now_s();
      if (SECS > 0.0) {
        if (now - t0 >= SECS) break;
      } else {
        if (g_recv >= TARGET) break;
        if (now - t0 > 120.0) break;  // hard ceiling
      }
      if (now - last_report >= 1.0) {
        uint64_t delta = g_recv - last_recv;
        double mbps = (double)delta / 1e6 / (now - last_report);
        fprintf(stderr, "[%5.1fs] recv=%llu MB rate=%.2f MB/s (%.0f Mbit/s)\n",
                now - t0, (unsigned long long)(g_recv / 1024 / 1024), mbps, mbps * 8);
        last_report = now;
        last_recv = g_recv;
      }
      usleep(50000);
    }
    double t1 = now_s();
    double mbps = (double)g_recv / 1e6 / (t1 - t0);
    fprintf(stderr, "\n=== bench_dc_net receiver ===\n");
    fprintf(stderr, "recv %llu B in %.2fs -> %.2f MB/s (%.0f Mbit/s)\n",
            (unsigned long long)g_recv, t1 - t0, mbps, mbps * 8);
    fprintf(stderr, "RESULT mode=recv bytes=%llu time=%.3f mbps=%.3f mbits=%.1f\n",
            (unsigned long long)g_recv, t1 - t0, mbps, mbps * 8);
  } else {
    // SENDER / offerer
    int cs = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_port = htons(atoi(argv[3]));
    inet_pton(AF_INET, argv[2], &a.sin_addr);
    while (connect(cs, (struct sockaddr*)&a, sizeof a) < 0) {
      fprintf(stderr, "connect retry...\n");
      sleep(1);
    }
    const char* offer = peer_connection_create_offer(pc);
    while (!offer) {
      usleep(10000);
      offer = peer_connection_create_offer(pc);
    }
    blob_write(cs, offer);
    char* ans = blob_read(cs);
    if (!ans) {
      fprintf(stderr, "no answer\n");
      return 1;
    }
    peer_connection_set_remote_description(pc, ans, SDP_TYPE_ANSWER);

    // Wait for ICE complete, then create the datachannel ONCE. The earlier
    // version checked the return value against the magic number 18 (a stale
    // copy from test_peer_connection.c — the actual return is the SCTP-send
    // length, ~34 for this label) and so spammed create_datachannel every
    // 50ms, filling the receiver's stream table and starving ICE consent
    // renewal until the 10s timer closed the connection. Single call: any
    // positive return means the SCTP open chunk went out.
    int dc = 0, tries = 0;
    while (!dc && tries++ < 400) {
      if (peer_connection_get_state(pc) == PEER_CONNECTION_COMPLETED) {
        int r = peer_connection_create_datachannel(pc, DATA_CHANNEL_RELIABLE, 0, 0, DCNAME, "bar");
        if (r > 0) dc = 1;
      }
      usleep(50000);
    }
    if (!dc) {
      fprintf(stderr, "send: datachannel never opened\n");
      return 1;
    }
    // Send HELLO until the receiver echoes — proves bidirectional + that the
    // receiver's on_msg handler is registered with the inherited datachannel.
    int hello_tries = 0;
    while (!g_hello && hello_tries++ < 100) {
      peer_connection_datachannel_send(pc, HELLO, sizeof(HELLO));
      usleep(50000);
    }
    if (!g_hello) {
      fprintf(stderr, "send: no HELLO echo after %d tries\n", hello_tries);
      return 1;
    }
    fprintf(stderr, "send: channel open + HELLO acked, chunk=%zu, %s\n", CHUNK,
            SECS > 0.0 ? "time-bound" : "byte-bound");

    if (quiet) quiet_stdout();

    uint8_t* buf = malloc(CHUNK);
    memset(buf, 0xAB, CHUNK);
    uint64_t sent = 0, eag = 0;
    double t0 = now_s();
    double last_report = t0;
    uint64_t last_sent = 0;
    uint64_t last_eag = 0;
    while (1) {
      double now = now_s();
      if (SECS > 0.0) {
        if (now - t0 >= SECS) break;
      } else {
        if (sent >= TARGET) break;
      }
      int r = peer_connection_datachannel_send_binary(pc, buf, CHUNK);
      if (r < 0) {
        eag++;
        usleep(200);
      } else {
        sent += CHUNK;
      }
      if (now - last_report >= 1.0) {
        uint64_t dB = sent - last_sent;
        uint64_t dE = eag - last_eag;
        double mbps = (double)dB / 1e6 / (now - last_report);
        fprintf(stderr, "[%5.1fs] sent=%llu MB rate=%.2f MB/s (%.0f Mbit/s) eagain=%llu (+%llu)\n",
                now - t0, (unsigned long long)(sent / 1024 / 1024), mbps, mbps * 8,
                (unsigned long long)eag, (unsigned long long)dE);
        last_report = now;
        last_sent = sent;
        last_eag = eag;
      }
    }
    double t1 = now_s();
    double mbps = (double)sent / 1e6 / (t1 - t0);
    fprintf(stderr, "\n=== bench_dc_net sender ===\n");
    fprintf(stderr, "sent %llu B in %.2fs -> %.2f MB/s (%.0f Mbit/s) into-buffer [eagain=%llu]\n",
            (unsigned long long)sent, t1 - t0, mbps, mbps * 8, (unsigned long long)eag);
    fprintf(stderr,
            "RESULT mode=send bytes=%llu time=%.3f mbps=%.3f mbits=%.1f eagain=%llu chunk=%zu\n",
            (unsigned long long)sent, t1 - t0, mbps, mbps * 8, (unsigned long long)eag, CHUNK);
    free(buf);
    sleep(3);  // let receiver drain
  }
  g_stop = 1;
  pthread_join(th, NULL);
  peer_connection_destroy(pc);
  peer_deinit();
  return 0;
}
