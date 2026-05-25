// Unit tests for highest-priority pair selection (agent_best_succeeded_pair).
// This is the core of relay-avoidance: whenever a direct (host/prflx/srflx)
// pair has succeeded it must be chosen over a relay, regardless of which
// succeeded first or where it sits in the (partially unsorted) pair array.

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "agent.h"
#include "ice.h"

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

int main(void) {
  Agent agent;
  memset(&agent, 0, sizeof(agent));

  Address ra;
  make_addr("1.2.3.4", 100, &ra);
  // Remote candidates: a relay (lowest type pref) and a prflx (high pref).
  ice_candidate_create(&agent.remote_candidates[0], 0, ICE_CANDIDATE_TYPE_RELAY, &ra);
  ice_candidate_create(&agent.remote_candidates[1], 1, ICE_CANDIDATE_TYPE_PRFLX, &ra);
  agent.remote_candidates_count = 2;

  Address la;
  make_addr("1.2.3.5", 200, &la);
  ice_candidate_create(&agent.local_candidates[0], 0, ICE_CANDIDATE_TYPE_HOST, &la);
  agent.local_candidates_count = 1;

  // pair[0] = local-host x remote-relay (low priority)
  // pair[1] = local-host x remote-prflx (higher priority) — appended AFTER the
  //           relay pair, mirroring how learned prflx pairs land at the end.
  agent.candidate_pairs[0].local = &agent.local_candidates[0];
  agent.candidate_pairs[0].remote = &agent.remote_candidates[0];
  agent.candidate_pairs[0].priority =
      (uint64_t)agent.local_candidates[0].priority + agent.remote_candidates[0].priority;
  agent.candidate_pairs[0].state = ICE_CANDIDATE_STATE_FROZEN;

  agent.candidate_pairs[1].local = &agent.local_candidates[0];
  agent.candidate_pairs[1].remote = &agent.remote_candidates[1];
  agent.candidate_pairs[1].priority =
      (uint64_t)agent.local_candidates[0].priority + agent.remote_candidates[1].priority;
  agent.candidate_pairs[1].state = ICE_CANDIDATE_STATE_FROZEN;
  agent.candidate_pairs_num = 2;

  // Sanity: the prflx pair must outrank the relay pair.
  CHECK(agent.candidate_pairs[1].priority > agent.candidate_pairs[0].priority);

  // Nothing succeeded yet.
  CHECK(agent_best_succeeded_pair(&agent) == NULL);

  // Only the relay pair has succeeded → it is the best available.
  agent.candidate_pairs[0].state = ICE_CANDIDATE_STATE_SUCCEEDED;
  CHECK(agent_best_succeeded_pair(&agent) == &agent.candidate_pairs[0]);

  // The higher-priority prflx pair then succeeds → selection switches to it
  // even though it appears later in the array (this is the relay→direct win).
  agent.candidate_pairs[1].state = ICE_CANDIDATE_STATE_SUCCEEDED;
  CHECK(agent_best_succeeded_pair(&agent) == &agent.candidate_pairs[1]);

  // FAILED / INPROGRESS pairs are never selected: fail the prflx pair and the
  // relay (still succeeded) becomes best again.
  agent.candidate_pairs[1].state = ICE_CANDIDATE_STATE_FAILED;
  CHECK(agent_best_succeeded_pair(&agent) == &agent.candidate_pairs[0]);

  agent.candidate_pairs[0].state = ICE_CANDIDATE_STATE_INPROGRESS;
  CHECK(agent_best_succeeded_pair(&agent) == NULL);

  if (g_failures == 0) {
    printf("test_pair_select: all checks passed\n");
  } else {
    printf("test_pair_select: %d check(s) FAILED\n", g_failures);
  }
  return g_failures == 0 ? 0 : 1;
}
