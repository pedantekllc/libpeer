#ifndef PAIR_INFO_H_
#define PAIR_INFO_H_

/*
 * The ICE pair a connection sends on, in a form callers can read without the
 * agent's types, and a tracker that numbers each change of that pair.
 */

#include <stdint.h>
#include <sys/socket.h>

struct IceCandidatePair;

typedef enum {
  PEER_CAND_HOST,
  PEER_CAND_SRFLX,
  PEER_CAND_PRFLX,
  PEER_CAND_RELAY,
} peer_cand_type;

typedef struct {
  int valid; /* 1 when a succeeded pair is in use; the rest is zero otherwise */
  peer_cand_type local_type;
  peer_cand_type remote_type;
  struct sockaddr_storage local_addr;
  struct sockaddr_storage remote_addr;
} peer_pair_info;

/* Describe `pair`; a NULL pair, or one that has not succeeded, yields valid=0. */
void peer_pair_info_from_pair(const struct IceCandidatePair* pair, peer_pair_info* out);

/* 1 when two descriptions name the same pair (types and both addresses). */
int peer_pair_info_equal(const peer_pair_info* a, const peer_pair_info* b);

typedef struct {
  peer_pair_info last;
  uint32_t generation;
} peer_pair_tracker;

/* Record `cur`; the generation advances when it differs from the last one
 * recorded. Returns the generation. Not thread-safe: one caller polls. */
uint32_t peer_pair_tracker_update(peer_pair_tracker* t, const peer_pair_info* cur);

#endif  // PAIR_INFO_H_
