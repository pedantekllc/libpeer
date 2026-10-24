// A Binding Response credits the pair(s) whose remote is the address it came
// from — in any state — and nothing else. The old nominated_pair fallback
// credited a pair that had never answered (embed-sdk bug report 1d44db37).

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "agent.h"
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

static void make_addr(const char* ip, uint16_t port, Address* addr) {
  memset(addr, 0, sizeof(*addr));
  addr_from_string(ip, addr);
  addr_set_port(addr, port);
}

static void make_pair(Agent* agent, int idx, IceCandidate* local, IceCandidate* remote, IceCandidateState st) {
  agent->candidate_pairs[idx].local = local;
  agent->candidate_pairs[idx].remote = remote;
  agent->candidate_pairs[idx].priority = (uint64_t)local->priority + remote->priority;
  agent->candidate_pairs[idx].state = st;
}

// A valid Binding Response under the agent's remote password.
static void make_response(Agent* agent, StunMessage* msg) {
  memset(msg, 0, sizeof(*msg));
  stun_msg_create(msg, STUN_CLASS_RESPONSE | STUN_METHOD_BINDING);
  stun_msg_finish(msg, STUN_CREDENTIAL_SHORT_TERM, agent->remote_upwd, strlen(agent->remote_upwd));
  stun_parse_msg_buf(msg);
}

int main(void) {
  Agent agent;
  memset(&agent, 0, sizeof(agent));
  snprintf(agent.remote_upwd, sizeof(agent.remote_upwd), "%s", "IexbSoY7JulyMbjKwISsG9");

  Address la, srflx, host;
  make_addr("10.0.0.5", 36770, &la);
  make_addr("192.0.2.10", 62277, &srflx);  // the browser's public address: never answers
  make_addr("10.0.0.184", 62277, &host);   // the browser's LAN address: the one that does
  ice_candidate_create(&agent.local_candidates[0], 0, ICE_CANDIDATE_TYPE_HOST, &la);
  agent.local_candidates_count = 1;
  ice_candidate_create(&agent.remote_candidates[0], 0, ICE_CANDIDATE_TYPE_SRFLX, &srflx);
  ice_candidate_create(&agent.remote_candidates[1], 1, ICE_CANDIDATE_TYPE_HOST, &host);
  agent.remote_candidates_count = 2;

  // pair[0]: the srflx check, in progress and nominated. pair[1]: the host,
  // paired late and still FROZEN behind the in-progress slots.
  make_pair(&agent, 0, &agent.local_candidates[0], &agent.remote_candidates[0], ICE_CANDIDATE_STATE_INPROGRESS);
  make_pair(&agent, 1, &agent.local_candidates[0], &agent.remote_candidates[1], ICE_CANDIDATE_STATE_FROZEN);
  agent.candidate_pairs_num = 2;
  agent.nominated_pair = &agent.candidate_pairs[0];

  StunMessage resp;
  make_response(&agent, &resp);

  // The browser answers from its LAN address. Only the host pair may succeed.
  agent_process_stun_response(&agent, &resp, &host, 0);
  CHECK(agent.candidate_pairs[1].state == ICE_CANDIDATE_STATE_SUCCEEDED);
  CHECK(agent.candidate_pairs[0].state == ICE_CANDIDATE_STATE_INPROGRESS);
  CHECK(agent_best_succeeded_pair(&agent) == &agent.candidate_pairs[1]);

  // A response from an address that is no pair's remote credits nothing —
  // in particular not the nominated pair.
  agent.candidate_pairs[1].state = ICE_CANDIDATE_STATE_FROZEN;
  Address stranger;
  make_addr("198.51.100.7", 4444, &stranger);
  agent_process_stun_response(&agent, &resp, &stranger, 0);
  CHECK(agent.candidate_pairs[0].state == ICE_CANDIDATE_STATE_INPROGRESS);
  CHECK(agent.candidate_pairs[1].state == ICE_CANDIDATE_STATE_FROZEN);
  CHECK(agent_best_succeeded_pair(&agent) == NULL);

  // A response that fails integrity credits nothing either.
  snprintf(agent.remote_upwd, sizeof(agent.remote_upwd), "%s", "wrong-password-wrong-pass");
  agent_process_stun_response(&agent, &resp, &host, 0);
  CHECK(agent.candidate_pairs[1].state == ICE_CANDIDATE_STATE_FROZEN);

  if (g_failures == 0) {
    printf("test_stun_response_credit: all checks passed\n");
  } else {
    printf("test_stun_response_credit: %d check(s) FAILED\n", g_failures);
  }
  return g_failures == 0 ? 0 : 1;
}
