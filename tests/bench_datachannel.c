// Single-process libpeer datachannel throughput bench — NO browser/MQTT/app.
// Two PeerConnections in one process (offerer<->answerer), real ICE/DTLS/SCTP,
// then pump bytes offerer->answerer and measure throughput. Isolates libpeer's
// datachannel ceiling from Chrome and the app's segment-request pattern.
//
// NOTE: loopback has all four threads (2x pc loops + 2x sctp libs + main) on
// the same host fighting for CPU AND for kernel UDP loopback. It's mostly a
// sanity check (does libpeer's datachannel work end-to-end at all). For real
// numbers run bench_dc_net across two hosts.
//
// Run with `>/dev/null` to suppress libpeer's chatty stdout zlog. Results
// go to stderr.
//
// Env: BENCH_MB (default 100), BENCH_SECS (time-bound), BENCH_CHUNK
// (default 16384), BENCH_QUIET (mute libpeer stdout after init).
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "peer.h"

#define MAX_CONNECTION_ATTEMPTS 50
#define OFFER_MSG "Hello World"
#define ANSWER_MSG "Foobar"
#define DCNAME "libpeer-datachannel"

static volatile int test_complete = 0;
static volatile uint64_t g_recv_bytes = 0;

typedef struct {
  int onmessage_offer_called, onmessage_answer_called;
} TestUserData;

static double now_s(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return ts.tv_sec + ts.tv_nsec / 1e9;
}

static void on_state_off(PeerConnectionState s, void* u) {
  fprintf(stderr, "offer: %s\n", peer_connection_state_to_string(s));
}
static void on_state_ans(PeerConnectionState s, void* u) {
  fprintf(stderr, "answer: %s\n", peer_connection_state_to_string(s));
}
static void on_ice_noop(char* d, void* u) {}

static void on_msg_offer(char* msg, size_t len, void* u, uint16_t sid) {
  TestUserData* t = (TestUserData*)u;
  if (len == sizeof(ANSWER_MSG) && strcmp(msg, ANSWER_MSG) == 0) t->onmessage_offer_called = 1;
}
// Answerer receives the bulk stream — count everything except the tiny handshake.
static void on_msg_answer(char* msg, size_t len, void* u, uint16_t sid) {
  TestUserData* t = (TestUserData*)u;
  if (len == sizeof(OFFER_MSG) && strcmp(msg, OFFER_MSG) == 0) {
    t->onmessage_answer_called = 1;
    return;
  }
  g_recv_bytes += len;
}

static void* pc_task(void* u) {
  PeerConnection* pc = (PeerConnection*)u;
  while (!test_complete) {
    peer_connection_loop(pc);
    usleep(1000);
  }
  return NULL;
}

static void quiet_stdout(void) {
  int devnull = open("/dev/null", O_WRONLY);
  if (devnull >= 0) {
    dup2(devnull, STDOUT_FILENO);
    close(devnull);
  }
}

int main(int argc, char* argv[]) {
  const uint64_t TARGET_MB = (uint64_t)(getenv("BENCH_MB") ? atoll(getenv("BENCH_MB")) : 100);
  const uint64_t TARGET = TARGET_MB * 1024 * 1024;
  const double SECS = getenv("BENCH_SECS") ? atof(getenv("BENCH_SECS")) : 0.0;
  const size_t CHUNK = getenv("BENCH_CHUNK") ? atoll(getenv("BENCH_CHUNK")) : 16384;
  const int quiet = getenv("BENCH_QUIET") != NULL;
  pthread_t off_t, ans_t;
  TestUserData ud = {0};

  PeerConfiguration config = {
      .ice_servers = {{.urls = "stun:stun.l.google.com:19302"}},
      .datachannel = DATA_CHANNEL_STRING,
      .video_codec = CODEC_H264,
      .audio_codec = CODEC_OPUS,
      .user_data = &ud,
  };

  peer_init();
  PeerConnection* off = peer_connection_create(&config);
  PeerConnection* ans = peer_connection_create(&config);
  peer_connection_oniceconnectionstatechange(off, on_state_off);
  peer_connection_oniceconnectionstatechange(ans, on_state_ans);
  peer_connection_onicecandidate(off, on_ice_noop);
  peer_connection_onicecandidate(ans, on_ice_noop);
  peer_connection_ondatachannel(off, on_msg_offer, NULL, NULL);
  peer_connection_ondatachannel(ans, on_msg_answer, NULL, NULL);

  pthread_create(&off_t, NULL, pc_task, off);
  pthread_create(&ans_t, NULL, pc_task, ans);

  const char* offer = peer_connection_create_offer(off);
  peer_connection_set_remote_description(ans, offer, SDP_TYPE_OFFER);
  const char* answer = peer_connection_create_answer(ans);
  peer_connection_set_remote_description(off, answer, SDP_TYPE_ANSWER);

  int attempts = 0, dc = 0;
  while (attempts < MAX_CONNECTION_ATTEMPTS) {
    if (!dc && peer_connection_get_state(off) == PEER_CONNECTION_COMPLETED) {
      if (peer_connection_create_datachannel(off, DATA_CHANNEL_RELIABLE, 0, 0, DCNAME, "bar") == 18) dc = 1;
    }
    if (peer_connection_get_state(off) == PEER_CONNECTION_COMPLETED &&
        peer_connection_get_state(ans) == PEER_CONNECTION_COMPLETED && ud.onmessage_offer_called &&
        ud.onmessage_answer_called)
      break;
    peer_connection_datachannel_send(off, OFFER_MSG, sizeof(OFFER_MSG));
    peer_connection_datachannel_send(ans, ANSWER_MSG, sizeof(ANSWER_MSG));
    attempts++;
    usleep(250000);
  }
  if (attempts >= MAX_CONNECTION_ATTEMPTS) {
    fprintf(stderr, "FAILED to connect\n");
    return 1;
  }
  fprintf(stderr, "connected. chunk=%zu %s\n", CHUNK,
          SECS > 0.0 ? "(time-bound)" : "(byte-bound)");

  if (quiet) quiet_stdout();

  uint8_t* buf = malloc(CHUNK);
  memset(buf, 0xAB, CHUNK);
  uint64_t sent = 0;
  uint64_t eagain = 0;
  double t0 = now_s();
  double last_report = t0;
  uint64_t last_sent = 0;
  uint64_t last_recv = 0;
  while (1) {
    double now = now_s();
    if (SECS > 0.0) {
      if (now - t0 >= SECS) break;
    } else {
      if (sent >= TARGET) break;
    }
    int r = peer_connection_datachannel_send_binary(off, buf, CHUNK);
    if (r < 0) {
      eagain++;
      usleep(200);
    } else {
      sent += CHUNK;
    }
    if (now - last_report >= 1.0) {
      double mbps_s = (double)(sent - last_sent) / 1e6 / (now - last_report);
      double mbps_r = (double)(g_recv_bytes - last_recv) / 1e6 / (now - last_report);
      fprintf(stderr, "[%5.1fs] send=%.2f MB/s recv=%.2f MB/s eagain=%llu\n",
              now - t0, mbps_s, mbps_r, (unsigned long long)eagain);
      last_report = now;
      last_sent = sent;
      last_recv = g_recv_bytes;
    }
  }
  double t_sent = now_s();
  // Drain
  double drain_deadline = t_sent + 20.0;
  uint64_t target_recv = SECS > 0.0 ? sent : TARGET;
  while (g_recv_bytes < target_recv && now_s() < drain_deadline) usleep(2000);
  double t1 = now_s();

  double send_s = t_sent - t0, wall_s = t1 - t0;
  double mbps_sent = (double)sent / 1e6 / send_s;
  double mbps_recv = (double)g_recv_bytes / 1e6 / wall_s;
  fprintf(stderr, "\n=== bench_datachannel (loopback) ===\n");
  fprintf(stderr, "sent  %llu B in %.2fs -> %.2f MB/s (%.0f Mbit/s) into-buffer  [eagain=%llu]\n",
          (unsigned long long)sent, send_s, mbps_sent, mbps_sent * 8, (unsigned long long)eagain);
  fprintf(stderr, "recv  %llu B in %.2fs -> %.2f MB/s (%.0f Mbit/s) end-to-end\n",
          (unsigned long long)g_recv_bytes, wall_s, mbps_recv, mbps_recv * 8);
  fprintf(stderr,
          "RESULT mode=loopback sent=%llu recv=%llu send_s=%.3f wall_s=%.3f "
          "send_mbps=%.3f recv_mbps=%.3f eagain=%llu chunk=%zu\n",
          (unsigned long long)sent, (unsigned long long)g_recv_bytes, send_s, wall_s, mbps_sent,
          mbps_recv, (unsigned long long)eagain, CHUNK);

  test_complete = 1;
  pthread_join(off_t, NULL);
  pthread_join(ans_t, NULL);
  peer_connection_destroy(off);
  peer_connection_destroy(ans);
  peer_deinit();
  free(buf);
  return 0;
}
