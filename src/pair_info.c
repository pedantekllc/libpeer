#include "pair_info.h"

#include <string.h>

#include "ice.h"

static void address_to_storage(const Address* a, struct sockaddr_storage* out) {
  memset(out, 0, sizeof(*out));
  if (a->family == AF_INET6)
    memcpy(out, &a->sin6, sizeof(a->sin6));
  else
    memcpy(out, &a->sin, sizeof(a->sin));
}

static peer_cand_type cand_type(IceCandidateType t) {
  switch (t) {
    case ICE_CANDIDATE_TYPE_SRFLX:
      return PEER_CAND_SRFLX;
    case ICE_CANDIDATE_TYPE_PRFLX:
      return PEER_CAND_PRFLX;
    case ICE_CANDIDATE_TYPE_RELAY:
      return PEER_CAND_RELAY;
    case ICE_CANDIDATE_TYPE_HOST:
    default:
      return PEER_CAND_HOST;
  }
}

void peer_pair_info_from_pair(const struct IceCandidatePair* pair, peer_pair_info* out) {
  memset(out, 0, sizeof(*out));
  if (!pair || pair->state != ICE_CANDIDATE_STATE_SUCCEEDED || !pair->local || !pair->remote)
    return;
  out->valid = 1;
  out->local_type = cand_type(pair->local->type);
  out->remote_type = cand_type(pair->remote->type);
  address_to_storage(&pair->local->addr, &out->local_addr);
  address_to_storage(&pair->remote->addr, &out->remote_addr);
}

int peer_pair_info_equal(const peer_pair_info* a, const peer_pair_info* b) {
  return a->valid == b->valid && a->local_type == b->local_type && a->remote_type == b->remote_type &&
         memcmp(&a->local_addr, &b->local_addr, sizeof(a->local_addr)) == 0 &&
         memcmp(&a->remote_addr, &b->remote_addr, sizeof(a->remote_addr)) == 0;
}

uint32_t peer_pair_tracker_update(peer_pair_tracker* t, const peer_pair_info* cur) {
  if (!peer_pair_info_equal(&t->last, cur)) {
    t->last = *cur;
    t->generation++;
  }
  return t->generation;
}
