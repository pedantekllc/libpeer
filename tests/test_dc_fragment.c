/* Regression test: data-channel message larger than the SCTP path MTU.
 *
 * The canonical test_peer_connection.c only sends "Hello World" (11 bytes) so
 * everything fits in a single SCTP DATA chunk and never exercises the SCTP
 * fragmentation / DTLS-record path.
 *
 * This test sends one 16 KB binary message — ~14 SCTP DATA chunks ~= 14 DTLS
 * records ~= 14 UDP datagrams that the receiver must decrypt, hand to usrsctp,
 * and reassemble before on_msg fires. If SCTP's path MTU is set wrong (e.g.,
 * the SCTP_PEER_ADDR_PARAMS / SPP_PMTUD_DISABLE block in sctp.c gets dropped
 * again), fragments get truncated at libpeer's CONFIG_MTU UDP-buffer boundary
 * and the receiver never sees the message.
 *
 * Passes when on_msg fires once with the expected 16 KB payload. Fails (and
 * the bench_datachannel benchmark stalls at exactly the SCTP sndbuf cap) when
 * the receive path silently drops fragments.
 */
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "peer.h"

#define DCNAME "libpeer-fragment-test"
#define MSG_SIZE (16 * 1024)
#define MAX_WAIT_S 15.0

static volatile int g_stop = 0;
static volatile int g_got_msg = 0;
static volatile size_t g_got_len = 0;
static uint8_t g_send_buf[MSG_SIZE];
static uint8_t g_recv_buf[MSG_SIZE];

static double now_s(void) {
  struct timespec t;
  clock_gettime(CLOCK_MONOTONIC, &t);
  return t.tv_sec + t.tv_nsec / 1e9;
}

static void on_state(PeerConnectionState s, void* u) {
  fprintf(stderr, "state: %s\n", peer_connection_state_to_string(s));
}
static void on_ice(char* d, void* u) {}

/* Offerer's callback: we only care that the answerer doesn't bounce anything
 * back. Discard. */
static void on_msg_off(char* msg, size_t len, void* u, uint16_t sid) {}

/* Answerer's callback: the bulk message lands here. */
static void on_msg_ans(char* msg, size_t len, void* u, uint16_t sid) {
  if (len == MSG_SIZE && g_got_len == 0) {
    memcpy(g_recv_buf, msg, len);
    g_got_len = len;
    g_got_msg = 1;
  }
}

static void* pc_task(void* u) {
  PeerConnection* pc = (PeerConnection*)u;
  while (!g_stop) {
    peer_connection_loop(pc);
    usleep(1000);
  }
  return NULL;
}

int main(void) {
  /* Seed deterministic but non-trivial payload — make it easy to spot
   * truncation if it ever happens. */
  for (size_t i = 0; i < MSG_SIZE; i++) g_send_buf[i] = (uint8_t)(i * 13 + 7);

  PeerConfiguration cfg = {
      .ice_servers = {{.urls = "stun:stun.l.google.com:19302"}},
      .datachannel = DATA_CHANNEL_STRING,
      .video_codec = CODEC_H264,
      .audio_codec = CODEC_OPUS,
  };
  peer_init();
  PeerConnection* off = peer_connection_create(&cfg);
  PeerConnection* ans = peer_connection_create(&cfg);
  peer_connection_oniceconnectionstatechange(off, on_state);
  peer_connection_oniceconnectionstatechange(ans, on_state);
  peer_connection_onicecandidate(off, on_ice);
  peer_connection_onicecandidate(ans, on_ice);
  peer_connection_ondatachannel(off, on_msg_off, NULL, NULL);
  peer_connection_ondatachannel(ans, on_msg_ans, NULL, NULL);

  pthread_t off_th, ans_th;
  pthread_create(&off_th, NULL, pc_task, off);
  pthread_create(&ans_th, NULL, pc_task, ans);

  const char* offer = peer_connection_create_offer(off);
  peer_connection_set_remote_description(ans, offer, SDP_TYPE_OFFER);
  const char* answer = peer_connection_create_answer(ans);
  peer_connection_set_remote_description(off, answer, SDP_TYPE_ANSWER);

  /* Wait for both sides to complete ICE/DTLS/SCTP and open the data channel. */
  double t0 = now_s();
  int dc = 0;
  while (now_s() - t0 < MAX_WAIT_S) {
    if (!dc && peer_connection_get_state(off) == PEER_CONNECTION_COMPLETED) {
      int r = peer_connection_create_datachannel(off, DATA_CHANNEL_RELIABLE, 0, 0, DCNAME, "bar");
      if (r > 0) dc = 1;
    }
    if (dc && peer_connection_get_state(ans) == PEER_CONNECTION_COMPLETED) break;
    usleep(20000);
  }
  if (!dc) {
    fprintf(stderr, "FAIL: never reached COMPLETED + datachannel open\n");
    g_stop = 1;
    pthread_join(off_th, NULL);
    pthread_join(ans_th, NULL);
    peer_connection_destroy(off);
    peer_connection_destroy(ans);
    peer_deinit();
    return 1;
  }
  /* Give SCTP a moment after the open-ack before we slam a big message in. */
  usleep(200000);

  /* The send. ONE call, MSG_SIZE bytes — bigger than the path MTU so SCTP
   * will fragment it. */
  int sent = peer_connection_datachannel_send_binary(off, g_send_buf, MSG_SIZE);
  if (sent < 0) {
    fprintf(stderr, "FAIL: datachannel_send_binary returned %d\n", sent);
    g_stop = 1;
    pthread_join(off_th, NULL);
    pthread_join(ans_th, NULL);
    return 2;
  }
  fprintf(stderr, "sent %d bytes, waiting for receiver...\n", sent);

  /* Wait for on_msg_ans to fire with the full message. */
  double t_send = now_s();
  while (!g_got_msg && now_s() - t_send < MAX_WAIT_S) usleep(2000);

  int rc = 0;
  if (!g_got_msg) {
    fprintf(stderr, "FAIL: on_msg never fired after %.1fs (sender's send buffer\n"
                    "      probably filled and never drained; check SCTP path MTU\n"
                    "      configuration in sctp_create_association)\n",
            MAX_WAIT_S);
    rc = 3;
  } else if (g_got_len != MSG_SIZE) {
    fprintf(stderr, "FAIL: received %zu bytes, expected %d\n", g_got_len, MSG_SIZE);
    rc = 4;
  } else if (memcmp(g_send_buf, g_recv_buf, MSG_SIZE) != 0) {
    fprintf(stderr, "FAIL: received payload differs from sent\n");
    rc = 5;
  } else {
    fprintf(stderr, "PASS: %d-byte fragmented message round-tripped in %.3fs\n",
            sent, now_s() - t_send);
  }

  g_stop = 1;
  pthread_join(off_th, NULL);
  pthread_join(ans_th, NULL);
  peer_connection_destroy(off);
  peer_connection_destroy(ans);
  peer_deinit();
  return rc;
}
