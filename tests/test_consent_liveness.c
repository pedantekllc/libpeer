// Liveness on an established connection. The peer's own Binding requests renew
// it; when they stop, the agent sends consent checks of its own and a valid
// response to one renews it instead. Time is injected: every agent entry point
// takes the clock reading, so the test steps a synthetic clock rather than
// sleeping. The peer is a real loopback UDP socket, so the checks are real
// datagrams that the test parses.

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "agent.h"
#include "config.h"
#include "ice.h"
#include "stun.h"

static int g_failures = 0;

#define CHECK(cond)                                          \
  do {                                                       \
    if (!(cond)) {                                           \
      printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
      g_failures++;                                          \
    }                                                        \
  } while (0)

#define STEP_MS 100

typedef enum { REPLY_NONE, REPLY_VALID, REPLY_WRONG_PASSWORD, REPLY_WRONG_TXID } ReplyKind;

typedef struct Fixture {
  Agent agent;
  int peer_fd;
  Address peer_addr;
  // Requests the peer received carrying USE_CANDIDATE.
  int nominating_requests;
} Fixture;

// An established connection: one SUCCEEDED, nominated and selected pair whose
// remote is a loopback socket the test reads.
static void fixture_open(Fixture* f, AgentMode mode) {
  memset(f, 0, sizeof(*f));
  Agent* a = &f->agent;
  CHECK(agent_create(a) == 0);
  a->mode = mode;
  snprintf(a->remote_upwd, sizeof(a->remote_upwd), "%s", "IexbSoY7JulyMbjKwISsG9");
  snprintf(a->remote_ufrag, sizeof(a->remote_ufrag), "%s", "rmt1");
  snprintf(a->local_upwd, sizeof(a->local_upwd), "%s", "localpasswordlocalpass24");
  snprintf(a->local_ufrag, sizeof(a->local_ufrag), "%s", "lcl1");

  f->peer_fd = socket(AF_INET, SOCK_DGRAM, 0);
  struct sockaddr_in sin;
  memset(&sin, 0, sizeof(sin));
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  CHECK(bind(f->peer_fd, (struct sockaddr*)&sin, sizeof(sin)) == 0);
  socklen_t len = sizeof(sin);
  getsockname(f->peer_fd, (struct sockaddr*)&sin, &len);
  memset(&f->peer_addr, 0, sizeof(f->peer_addr));
  addr_from_string("127.0.0.1", &f->peer_addr);
  addr_set_port(&f->peer_addr, ntohs(sin.sin_port));

  Address local;
  memset(&local, 0, sizeof(local));
  addr_from_string("127.0.0.1", &local);
  addr_set_port(&local, 1);
  ice_candidate_create(&a->local_candidates[0], 0, ICE_CANDIDATE_TYPE_HOST, &local);
  a->local_candidates_count = 1;
  ice_candidate_create(&a->remote_candidates[0], 0, ICE_CANDIDATE_TYPE_HOST, &f->peer_addr);
  a->remote_candidates_count = 1;
  a->candidate_pairs[0].local = &a->local_candidates[0];
  a->candidate_pairs[0].remote = &a->remote_candidates[0];
  a->candidate_pairs[0].priority = (uint64_t)a->local_candidates[0].priority + a->remote_candidates[0].priority;
  a->candidate_pairs[0].state = ICE_CANDIDATE_STATE_SUCCEEDED;
  a->candidate_pairs_num = 1;
  a->selected_pair = &a->candidate_pairs[0];
  a->nominated_pair = &a->candidate_pairs[0];
}

static void fixture_close(Fixture* f) {
  close(f->peer_fd);
  agent_destroy(&f->agent);
}

static int peer_drain(Fixture* f, uint32_t now_ms, ReplyKind kind);

// The agent answers a request with a response and, as CONTROLLING, a triggered
// check of its own. Both are datagrams this test did not ask for: let loopback
// deliver them and throw them away so they are not counted as consent checks.
static void settle_and_discard(Fixture* f, uint32_t now_ms) {
  usleep(3000);
  peer_drain(f, now_ms, REPLY_NONE);
}

// The peer's consent check, as the browser sends it.
static void peer_sends_request(Fixture* f, uint32_t now_ms) {
  StunMessage req;
  memset(&req, 0, sizeof(req));
  stun_msg_create(&req, STUN_CLASS_REQUEST | STUN_METHOD_BINDING);
  stun_msg_finish(&req, STUN_CREDENTIAL_SHORT_TERM, f->agent.local_upwd, strlen(f->agent.local_upwd));
  stun_parse_msg_buf(&req);
  agent_process_stun_request(&f->agent, &req, &f->peer_addr, now_ms);
  settle_and_discard(f, now_ms);
}

// Whether a STUN message carries an attribute of `type` (attributes follow the
// 20-byte header as type/length/value, each value padded to 4 bytes).
static int stun_has_attr(const uint8_t* buf, ssize_t n, uint16_t type) {
  ssize_t off = 20;
  while (off + 4 <= n) {
    uint16_t t = (uint16_t)((buf[off] << 8) | buf[off + 1]);
    uint16_t len = (uint16_t)((buf[off + 2] << 8) | buf[off + 3]);
    if (t == type) return 1;
    off += 4 + ((len + 3) & ~3);
  }
  return 0;
}

// Reads every datagram waiting at the peer. Each Binding request among them is
// handed to `reply` (if non-NULL) as a response with the request's transaction
// id, signed with `password`. Returns the number of requests seen.
static int peer_drain(Fixture* f, uint32_t now_ms, ReplyKind kind) {
  uint8_t buf[1400];
  int requests = 0;
  ssize_t n;
  while ((n = recv(f->peer_fd, buf, sizeof(buf), MSG_DONTWAIT)) > 0) {
    StunMessage in;
    memset(&in, 0, sizeof(in));
    memcpy(in.buf, buf, n);
    in.size = n;
    stun_parse_msg_buf(&in);
    if (in.stunclass != STUN_CLASS_REQUEST) {
      continue;  // the agent's response to the peer's own request
    }
    requests++;
    if (stun_has_attr(buf, n, STUN_ATTR_TYPE_USE_CANDIDATE)) {
      f->nominating_requests++;
    }
    if (kind == REPLY_NONE) {
      continue;
    }
    StunMessage resp;
    memset(&resp, 0, sizeof(resp));
    stun_msg_create(&resp, STUN_CLASS_RESPONSE | STUN_METHOD_BINDING);
    StunHeader* rh = (StunHeader*)resp.buf;
    memcpy(rh->transaction_id, ((StunHeader*)in.buf)->transaction_id, sizeof(rh->transaction_id));
    if (kind == REPLY_WRONG_TXID) {
      rh->transaction_id[0] ^= 0x5a5a5a5a;
    }
    const char* pw = kind == REPLY_WRONG_PASSWORD ? "not-the-remote-password!" : f->agent.remote_upwd;
    stun_msg_finish(&resp, STUN_CREDENTIAL_SHORT_TERM, (char*)pw, strlen(pw));
    stun_parse_msg_buf(&resp);
    agent_process_stun_response(&f->agent, &resp, &f->peer_addr, now_ms);
  }
  return requests;
}

static void check_pair_untouched(Fixture* f) {
  CHECK(f->agent.candidate_pairs_num == 1);
  CHECK(f->agent.selected_pair == &f->agent.candidate_pairs[0]);
  CHECK(f->agent.nominated_pair == &f->agent.candidate_pairs[0]);
  CHECK(f->agent.candidate_pairs[0].state == ICE_CANDIDATE_STATE_SUCCEEDED);
  CHECK(f->agent.remote_candidates_count == 1);
}

// The peer's inbound requests stop but it answers the agent's checks: the
// connection outlives CONFIG_KEEPALIVE_TIMEOUT by a wide margin.
static void test_answered_consent_keeps_connection(AgentMode mode) {
  Fixture f;
  fixture_open(&f, mode);
  peer_sends_request(&f, 0);
  int ever_expired = 0;
  for (uint32_t t = STEP_MS; t <= 4 * CONFIG_KEEPALIVE_TIMEOUT; t += STEP_MS) {
    agent_consent_tick(&f.agent, t);
    peer_drain(&f, t, REPLY_VALID);
    if (agent_liveness_expired(&f.agent, t)) ever_expired = 1;
  }
  CHECK(!ever_expired);
  // An answer does not pause the checks: while the peer's own checks stay
  // absent they go out at the retry cadence, so a peer that discarded the
  // path re-learns it within one retry.
  const uint32_t span = 4 * CONFIG_KEEPALIVE_TIMEOUT - CONFIG_CONSENT_SILENCE_MS;
  CHECK(f.agent.consent_sent_total + 1 >= span / CONFIG_CONSENT_RETRY_MS);
  check_pair_untouched(&f);
  fixture_close(&f);
}

// The peer neither sends requests nor answers: closes once the timeout passes,
// and not before.
static void test_unanswered_consent_expires(AgentMode mode) {
  Fixture f;
  fixture_open(&f, mode);
  peer_sends_request(&f, 0);
  CHECK(!agent_liveness_expired(&f.agent, CONFIG_KEEPALIVE_TIMEOUT));
  for (uint32_t t = STEP_MS; t <= CONFIG_KEEPALIVE_TIMEOUT; t += STEP_MS) {
    agent_consent_tick(&f.agent, t);
    peer_drain(&f, t, REPLY_NONE);
    CHECK(!agent_liveness_expired(&f.agent, t));
  }
  CHECK(agent_liveness_expired(&f.agent, CONFIG_KEEPALIVE_TIMEOUT + 1));
  fixture_close(&f);
}

// Responses that are not an integrity-checked answer to one of our checks renew
// nothing.
static void test_unproven_responses_do_not_renew(AgentMode mode) {
  ReplyKind kinds[] = {REPLY_WRONG_PASSWORD, REPLY_WRONG_TXID};
  for (int k = 0; k < 2; k++) {
    Fixture f;
    fixture_open(&f, mode);
    peer_sends_request(&f, 0);
    for (uint32_t t = STEP_MS; t <= CONFIG_KEEPALIVE_TIMEOUT; t += STEP_MS) {
      agent_consent_tick(&f.agent, t);
      peer_drain(&f, t, kinds[k]);
    }
    CHECK(f.agent.consent_sent_total > 0);
    CHECK(agent_liveness_expired(&f.agent, CONFIG_KEEPALIVE_TIMEOUT + 1));
    fixture_close(&f);
  }
}

// During silence the agent sends nothing before CONFIG_CONSENT_SILENCE_MS and
// then at most one check per CONFIG_CONSENT_RETRY_MS, however often it ticks.
static void test_consent_checks_are_rate_limited(AgentMode mode) {
  Fixture f;
  fixture_open(&f, mode);
  peer_sends_request(&f, 0);
  settle_and_discard(&f, 0);  // the response and, as CONTROLLING, the triggered check
  f.nominating_requests = 0;
  int sent = 0;
  uint32_t last_sent = 0;
  const uint32_t window = CONFIG_KEEPALIVE_TIMEOUT - 1000;
  for (uint32_t t = 1; t <= window; t += 10) {
    uint32_t before = f.agent.consent_sent_total;
    agent_consent_tick(&f.agent, t);
    agent_consent_tick(&f.agent, t);  // a second tick in the same ms sends nothing
    uint32_t n = f.agent.consent_sent_total - before;
    CHECK(n <= 1);
    if (n == 1) {
      if (sent == 0) {
        CHECK(t >= CONFIG_CONSENT_SILENCE_MS);
      } else {
        CHECK(t - last_sent >= CONFIG_CONSENT_RETRY_MS);
      }
      sent++;
      last_sent = t;
    }
  }
  // Sends at silence, silence+retry, ... while inside the window.
  int expected = (int)((window - CONFIG_CONSENT_SILENCE_MS) / CONFIG_CONSENT_RETRY_MS) + 1;
  CHECK(sent == expected || sent == expected - 1);  // 10 ms tick granularity
  // Each counted check is one datagram on the wire.
  usleep(20000);
  CHECK(peer_drain(&f, window, REPLY_NONE) == sent);
  // The peer was silent, so every request was a consent check, and a consent
  // check asks whether the peer is there; it never nominates.
  CHECK(f.nominating_requests == 0);
  fixture_close(&f);
}

// A healthy peer whose own checks keep arriving is never asked anything.
static void test_healthy_peer_is_not_probed(AgentMode mode) {
  Fixture f;
  fixture_open(&f, mode);
  for (uint32_t t = 0; t <= 60000; t += STEP_MS) {
    if (t % 2500 == 0) peer_sends_request(&f, t);
    agent_consent_tick(&f.agent, t);
    peer_drain(&f, t, REPLY_NONE);
  }
  CHECK(f.agent.consent_sent_total == 0);
  fixture_close(&f);
}

int main(void) {
  AgentMode modes[] = {AGENT_MODE_CONTROLLED, AGENT_MODE_CONTROLLING};
  for (int m = 0; m < 2; m++) {
    test_answered_consent_keeps_connection(modes[m]);
    test_unanswered_consent_expires(modes[m]);
    test_unproven_responses_do_not_renew(modes[m]);
    test_consent_checks_are_rate_limited(modes[m]);
    test_healthy_peer_is_not_probed(modes[m]);
  }
  if (g_failures == 0) {
    printf("test_consent_liveness: all checks passed\n");
  } else {
    printf("test_consent_liveness: %d check(s) FAILED\n", g_failures);
  }
  return g_failures == 0 ? 0 : 1;
}
