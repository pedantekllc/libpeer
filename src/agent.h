#ifndef AGENT_H_
#define AGENT_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "base64.h"
#include "ice.h"
#include "socket.h"
#include "stun.h"
#include "utils.h"

#ifndef AGENT_MAX_DESCRIPTION
#define AGENT_MAX_DESCRIPTION 40960
#endif

#ifndef AGENT_MAX_CANDIDATES
#define AGENT_MAX_CANDIDATES 10
#endif

#ifndef AGENT_MAX_CANDIDATE_PAIRS
#define AGENT_MAX_CANDIDATE_PAIRS 100
#endif

typedef enum AgentState {

  AGENT_STATE_GATHERING_ENDED = 0,
  AGENT_STATE_GATHERING_STARTED,
  AGENT_STATE_GATHERING_COMPLETED,

} AgentState;

typedef enum AgentMode {

  AGENT_MODE_CONTROLLED = 0,
  AGENT_MODE_CONTROLLING

} AgentMode;

// A remote ".local" (mDNS-obfuscated) candidate parked while its name resolves
// asynchronously (mdns_async_*). `candidate` is complete except its IP.
#define AGENT_MAX_PENDING_MDNS 4

typedef struct AgentPendingMdns {
  int active;
  char hostname[128];
  IceCandidate candidate;
} AgentPendingMdns;

typedef struct Agent Agent;

struct Agent {
  char remote_ufrag[ICE_UFRAG_LENGTH + 1];
  char remote_upwd[ICE_UPWD_LENGTH + 1];

  char local_ufrag[ICE_UFRAG_LENGTH + 1];
  char local_upwd[ICE_UPWD_LENGTH + 1];

  IceCandidate local_candidates[AGENT_MAX_CANDIDATES];
  IceCandidate remote_candidates[AGENT_MAX_CANDIDATES];

  int local_candidates_count;
  int remote_candidates_count;

  UdpSocket udp_sockets[2];

  /* Optional interface to pin ICE to (copied from PeerConfiguration.bind_iface
   * before agent_create). Empty = legacy first-interface behaviour. 16 ==
   * IFNAMSIZ. */
  char bind_iface[16];

  /* Optional fixed port to bind the media UDP socket to (0 = ephemeral).
   * Copied from PeerConfiguration.media_port before agent_create. */
  uint16_t media_port;

  Address host_addr;
  int b_host_addr;
  /* Epoch-ms of the last inbound STUN binding request from the peer (its consent
   * checks, arriving continuously on an established connection). This is a
   * spec-appropriate liveness signal (RFC 7675: liveness/consent is renewed by
   * STUN, NOT by received media — media can be replayed/spoofed). Drives the
   * keepalive timeout and is exposed via peer_connection_get_last_stun_rx_time()
   * for higher-level watchdogs (e.g. the sigcore GC). */
  uint64_t binding_request_time;
  uint32_t first_success_time;  // ms (ports_get_epoch_time) of first pair success; 0 = none yet
  AgentState state;

  AgentMode mode;

  IceCandidatePair candidate_pairs[AGENT_MAX_CANDIDATE_PAIRS];
  IceCandidatePair* selected_pair;
  IceCandidatePair* nominated_pair;

  int candidate_pairs_num;
  int use_candidate;
  uint32_t transaction_id[3];

  /* Remote .local candidates awaiting async mDNS resolution (see
   * agent_queue_mdns_candidate / agent_poll_mdns_candidates). */
  AgentPendingMdns pending_mdns[AGENT_MAX_PENDING_MDNS];

  /* ── Connection-attempt diagnostics (Plane A observability) ────────────────
   * Cumulative for this Agent's lifetime (one Agent per PeerConnection, one
   * PeerConnection per connection attempt — there is no ICE restart today, so
   * "per Agent" == "per attempt"). Read via peer_connection_get_diag(). Reset
   * to their zero/-1 defaults in agent_clear_candidates() (called once at
   * agent_create() and again at the top of every SDP_TYPE_OFFER, i.e. before
   * gathering starts for this attempt). */
  uint32_t turn_alloc_ok;         /* TURN Allocate succeeded (see agent_create_turn_addr) */
  uint32_t turn_alloc_rejected;   /* TURN authenticated Allocate rejected                 */
  uint32_t mdns_resolved;         /* remote .local candidate resolved + paired            */
  uint32_t mdns_queued;           /* remote .local candidate EVER queued for async resolve
                                   * this attempt (agent_queue_mdns_candidate) — the
                                   * "had a pending mDNS candidate" signal for Plane-B's
                                   * per-attempt died-at inference (webrtc-connection-
                                   * reliability.md). Distinct from mdns_resolved: an
                                   * attempt can queue N candidates and resolve zero of
                                   * them (the RC2 failure signature) or resolve none
                                   * because it never offered any (queued==0) — the two
                                   * cases must not be conflated. */
  int      selected_remote_type;  /* IceCandidateType of the selected pair's remote
                                   * candidate once agent_connectivity_check commits
                                   * (host=0/srflx=1/prflx=2/relay=3); -1 = not yet
                                   * selected for this attempt. */
};

void agent_gather_candidate(Agent* agent, const char* urls, const char* username, const char* credential);

void agent_create_ice_credential(Agent* agent);

void agent_get_local_description(Agent* agent, char* description, int length);

int agent_send(Agent* agent, const uint8_t* buf, int len);

int agent_recv(Agent* agent, uint8_t* buf, int len);

void agent_set_remote_description(Agent* agent, char* description);

// Pair one late-arriving remote candidate against every same-family local
// candidate (append-only; safe mid-CHECKING — see agent_add_prflx_candidate).
// Used for trickled candidates and async-resolved mDNS candidates, which land
// after the answer-time bulk pairing and would otherwise never be checked.
void agent_pair_remote_candidate(Agent* agent, IceCandidate* remote);

// Park a parsed-but-unresolved ".local" remote candidate (from
// ice_candidate_from_description returning 1) and kick off its async mDNS
// resolution. Idempotent per hostname.
void agent_queue_mdns_candidate(Agent* agent, const IceCandidate* candidate, const char* hostname);

// Pump pending .local resolutions (call every peer_connection_loop tick; cheap
// no-op when none are pending). A resolved name becomes a real remote
// candidate, incrementally paired against every local candidate — same
// append-only discipline as agent_add_prflx_candidate, so it is safe while
// connectivity checks are in flight. Failed/expired names are dropped.
void agent_poll_mdns_candidates(Agent* agent);

// Learn a peer-reflexive remote candidate from the source address of a
// validated inbound STUN binding request, and form candidate pairs for it.
// Lets a same-LAN connection succeed without resolving the browser's
// obfuscated mDNS (.local) host candidate. Returns the index of the (new or
// existing) remote candidate, or -1 if the candidate table is full.
int agent_add_prflx_candidate(Agent* agent, Address* addr);

// Returns the highest-priority candidate pair currently in the SUCCEEDED
// state, or NULL if none have succeeded. Used to prefer a direct (host/prflx/
// srflx) path over a relay regardless of which succeeded first or where it
// sits in the (partially unsorted) pair array.
IceCandidatePair* agent_best_succeeded_pair(Agent* agent);

int agent_select_candidate_pair(Agent* agent);

int agent_connectivity_check(Agent* agent);

void agent_clear_candidates(Agent* agent);

int agent_create(Agent* agent);

void agent_destroy(Agent* agent);

void agent_update_candidate_pairs(Agent* agent);

#endif  // AGENT_H_
