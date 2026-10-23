// Peer identity in DTLS-SRTP rests solely on the SDP certificate fingerprint:
// dtls_srtp_cert_verify() clears NOT_TRUSTED / CN_MISMATCH, so the compare of
// remote_fingerprint against the digest of the peer's presented certificate in
// dtls_srtp_handshake() is the only authentication. This test pins that down.
//
// Harness: a real DTLS client and server (DtlsSrtp, shared self-signed cert)
// are wired back to back through in-memory datagram queues by overriding
// udp_send/udp_recv, and stepped alternately the way peer_connection_loop()
// drives them (one dtls_srtp_handshake() call per tick, DTLS_SRTP_HS_WANT
// meaning "in progress").
//
//   matching fingerprint   -> both sides return 0
//   mismatched fingerprint -> the checking side returns -1 and never 0

#include <stdio.h>
#include <string.h>

#include "dtls_srtp.h"

#define QUEUE_DEPTH 64
#define MAX_DGRAM 2048
#define MAX_TICKS 5000

typedef struct Queue {
  uint8_t data[QUEUE_DEPTH][MAX_DGRAM];
  size_t len[QUEUE_DEPTH];
  int head;
  int count;
} Queue;

typedef struct Endpoint {
  Queue inbox;
  struct Endpoint* peer;
} Endpoint;

static int mem_send(void* ctx, const uint8_t* buf, size_t len) {
  DtlsSrtp* d = (DtlsSrtp*)ctx;
  Endpoint* me = (Endpoint*)d->user_data;
  Queue* q = &me->peer->inbox;
  if (len > MAX_DGRAM || q->count == QUEUE_DEPTH) {
    return (int)len;  // datagram transport: drop, DTLS retransmits
  }
  int idx = (q->head + q->count) % QUEUE_DEPTH;
  memcpy(q->data[idx], buf, len);
  q->len[idx] = len;
  q->count++;
  return (int)len;
}

static int mem_recv(void* ctx, uint8_t* buf, size_t len) {
  DtlsSrtp* d = (DtlsSrtp*)ctx;
  Endpoint* me = (Endpoint*)d->user_data;
  Queue* q = &me->inbox;
  if (q->count == 0) {
    return MBEDTLS_ERR_SSL_WANT_READ;
  }
  size_t n = q->len[q->head] < len ? q->len[q->head] : len;
  memcpy(buf, q->data[q->head], n);
  q->head = (q->head + 1) % QUEUE_DEPTH;
  q->count--;
  return (int)n;
}

static int g_failures = 0;

#define CHECK(cond)                                          \
  do {                                                       \
    if (!(cond)) {                                           \
      printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
      g_failures++;                                          \
    }                                                        \
  } while (0)

typedef struct Result {
  int client_ret;  // last dtls_srtp_handshake() result, DTLS_SRTP_HS_WANT if unfinished
  int server_ret;
  int client_ever_zero;
} Result;

// Run a handshake. client_expected / server_expected are the fingerprints the
// respective side believes the peer's certificate has.
static Result run_handshake(const char* client_expected, const char* server_expected) {
  static Endpoint client_ep, server_ep;
  memset(&client_ep, 0, sizeof(client_ep));
  memset(&server_ep, 0, sizeof(server_ep));
  client_ep.peer = &server_ep;
  server_ep.peer = &client_ep;

  DtlsSrtp client, server;
  Address client_addr, server_addr;
  memset(&client_addr, 0, sizeof(client_addr));
  memset(&server_addr, 0, sizeof(server_addr));

  CHECK(dtls_srtp_init(&client, DTLS_SRTP_ROLE_CLIENT, &client_ep) == 0);
  CHECK(dtls_srtp_init(&server, DTLS_SRTP_ROLE_SERVER, &server_ep) == 0);
  client.udp_send = server.udp_send = mem_send;
  client.udp_recv = server.udp_recv = mem_recv;

  memset(client.remote_fingerprint, 0, sizeof(client.remote_fingerprint));
  memset(server.remote_fingerprint, 0, sizeof(server.remote_fingerprint));
  snprintf(client.remote_fingerprint, sizeof(client.remote_fingerprint), "%s", client_expected);
  snprintf(server.remote_fingerprint, sizeof(server.remote_fingerprint), "%s", server_expected);

  Result r = {DTLS_SRTP_HS_WANT, DTLS_SRTP_HS_WANT, 0};
  for (int tick = 0; tick < MAX_TICKS; tick++) {
    if (r.client_ret == DTLS_SRTP_HS_WANT) {
      r.client_ret = dtls_srtp_handshake(&client, &server_addr);
      if (r.client_ret == 0) r.client_ever_zero = 1;
    }
    if (r.server_ret == DTLS_SRTP_HS_WANT) {
      r.server_ret = dtls_srtp_handshake(&server, &client_addr);
    }
    if (r.client_ret != DTLS_SRTP_HS_WANT && r.server_ret != DTLS_SRTP_HS_WANT) {
      break;
    }
    // Once the client has failed it sends nothing more; stop waiting on a
    // server that has no one left to talk to.
    if (r.client_ret != DTLS_SRTP_HS_WANT && r.client_ret != 0 && r.server_ret == DTLS_SRTP_HS_WANT && tick > 200) {
      break;
    }
  }

  dtls_srtp_deinit(&client);
  dtls_srtp_deinit(&server);
  return r;
}

static void test_matching_fingerprint_completes(void) {
  const char* fp = dtls_srtp_get_fingerprint();
  CHECK(fp != NULL);
  Result r = run_handshake(fp, fp);
  CHECK(r.client_ret == 0);
  CHECK(r.server_ret == 0);
}

static void test_mismatched_fingerprint_rejected(void) {
  const char* fp = dtls_srtp_get_fingerprint();
  CHECK(fp != NULL);

  // Well-formed SHA-256 fingerprint (32 colon-separated hex bytes) that is not
  // the certificate's. Flip the first byte so it is guaranteed to differ.
  char other[DTLS_SRTP_FINGERPRINT_LENGTH];
  snprintf(other, sizeof(other), "%s", fp);
  other[0] = (other[0] == 'A') ? 'B' : 'A';
  CHECK(strlen(other) == strlen(fp));
  CHECK(strcmp(other, fp) != 0);

  // Client expects the wrong fingerprint; server's expectation is correct.
  Result r = run_handshake(other, fp);
  CHECK(r.client_ret == -1);
  CHECK(!r.client_ever_zero);

  // Same, with the roles of checker reversed: the server expects the wrong one.
  r = run_handshake(fp, other);
  CHECK(r.server_ret == -1);
  CHECK(r.server_ret != 0);

  // Empty expectation (no fingerprint from SDP) must not authenticate either.
  r = run_handshake("", fp);
  CHECK(r.client_ret == -1);
  CHECK(!r.client_ever_zero);
}

int main(void) {
  if (dtls_srtp_init_cert() != 0) {
    printf("FAIL dtls_srtp_init_cert\n");
    return 1;
  }
  test_matching_fingerprint_completes();
  test_mismatched_fingerprint_rejected();
  if (g_failures) {
    printf("%d failure(s)\n", g_failures);
    return 1;
  }
  printf("test_dtls_fingerprint: ok\n");
  return 0;
}
