// Unit tests for peer-reflexive ICE candidate learning (agent.c) and the
// supporting addr_equal() comparison (address.c).
//
// These cover the same-LAN case where a browser hides its host candidate
// behind an mDNS .local name: the device must learn the real address from
// the source of the inbound connectivity check instead of resolving mDNS.

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "agent.h"
#include "ice.h"

static int g_failures = 0;

#define CHECK(cond)                                                    \
  do {                                                                 \
    if (!(cond)) {                                                     \
      printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);           \
      g_failures++;                                                    \
    }                                                                  \
  } while (0)

static void make_addr(const char* ip, uint16_t port, Address* addr) {
  memset(addr, 0, sizeof(*addr));
  // Match mdns.c ordering: resolve the string (sets family + sin_addr), then
  // apply the port (sets the canonical port field + sin_port).
  addr_from_string(ip, addr);
  addr_set_port(addr, port);
}

static void test_addr_equal(void) {
  Address a, b;

  make_addr("10.0.0.1", 1000, &a);
  make_addr("10.0.0.1", 1000, &b);
  CHECK(addr_equal(&a, &b) == 1);  // identical

  make_addr("10.0.0.2", 1000, &b);
  CHECK(addr_equal(&a, &b) == 0);  // different IP

  make_addr("10.0.0.1", 1001, &b);
  CHECK(addr_equal(&a, &b) == 0);  // different port
}

// A novel inbound source becomes a PRFLX remote candidate with a primed
// (INPROGRESS) pair against each local candidate; repeats dedup; distinct
// addresses (including same-IP/different-port) are tracked separately.
static void test_prflx_learning(void) {
  Agent agent;
  memset(&agent, 0, sizeof(agent));

  // One local host candidate to pair against.
  Address local;
  make_addr("192.168.1.10", 5000, &local);
  ice_candidate_create(&agent.local_candidates[0], 0, ICE_CANDIDATE_TYPE_HOST, &local);
  agent.local_candidates_count = 1;

  // The browser's real address (hidden behind mDNS in the SDP) arrives as the
  // source of its connectivity check.
  Address peer1;
  make_addr("192.168.1.248", 54321, &peer1);

  int idx = agent_add_prflx_candidate(&agent, &peer1);
  CHECK(idx == 0);
  CHECK(agent.remote_candidates_count == 1);
  CHECK(agent.remote_candidates[0].type == ICE_CANDIDATE_TYPE_PRFLX);
  CHECK(addr_equal(&agent.remote_candidates[0].addr, &peer1));
  CHECK(agent.candidate_pairs_num == 1);
  CHECK(agent.candidate_pairs[0].remote == &agent.remote_candidates[0]);
  CHECK(agent.candidate_pairs[0].local == &agent.local_candidates[0]);
  CHECK(agent.candidate_pairs[0].state == ICE_CANDIDATE_STATE_INPROGRESS);

  // Idempotent: the same source must not create a duplicate.
  int idx_dup = agent_add_prflx_candidate(&agent, &peer1);
  CHECK(idx_dup == 0);
  CHECK(agent.remote_candidates_count == 1);
  CHECK(agent.candidate_pairs_num == 1);

  // A distinct address is a distinct candidate.
  Address peer2;
  make_addr("192.168.1.249", 11111, &peer2);
  int idx2 = agent_add_prflx_candidate(&agent, &peer2);
  CHECK(idx2 == 1);
  CHECK(agent.remote_candidates_count == 2);
  CHECK(agent.candidate_pairs_num == 2);

  // Same IP, different port is also distinct (addr_equal compares the port).
  Address peer1b;
  make_addr("192.168.1.248", 60000, &peer1b);
  int idx3 = agent_add_prflx_candidate(&agent, &peer1b);
  CHECK(idx3 == 2);
  CHECK(agent.remote_candidates_count == 3);
  CHECK(agent.candidate_pairs_num == 3);
}

// The whole point of the fix: a learned direct (PRFLX) path must outrank a
// relay so ICE prefers it. RFC 8445 type preferences: host > prflx > srflx >
// relay. With equal local preference (same port) the candidate priority must
// follow that order.
static void test_prflx_priority_beats_relay(void) {
  Address addr;
  make_addr("1.2.3.4", 9, &addr);

  IceCandidate host, prflx, srflx, relay;
  ice_candidate_create(&host, 0, ICE_CANDIDATE_TYPE_HOST, &addr);
  ice_candidate_create(&prflx, 0, ICE_CANDIDATE_TYPE_PRFLX, &addr);
  ice_candidate_create(&srflx, 0, ICE_CANDIDATE_TYPE_SRFLX, &addr);
  ice_candidate_create(&relay, 0, ICE_CANDIDATE_TYPE_RELAY, &addr);

  CHECK(host.priority > prflx.priority);
  CHECK(prflx.priority > srflx.priority);
  CHECK(srflx.priority > relay.priority);
}

int main(void) {
  test_addr_equal();
  test_prflx_learning();
  test_prflx_priority_beats_relay();

  if (g_failures == 0) {
    printf("test_prflx: all checks passed\n");
  } else {
    printf("test_prflx: %d check(s) FAILED\n", g_failures);
  }
  return g_failures == 0 ? 0 : 1;
}
