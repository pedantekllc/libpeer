#ifndef RTX_HISTORY_H_
#define RTX_HISTORY_H_

/*
 * The sent-packet history a NACK is answered from (RFC 4588 retransmission).
 *
 * It holds every media packet of the largest frame sent so far, and as many
 * packets again after it: a receiver can only NACK a packet of a keyframe once
 * the packets after the gap arrive, so the whole keyframe has to still be held
 * when the first NACK for it comes back. A slot ring indexed by sequence
 * number; it starts at `initial` slots and doubles, keeping every packet it
 * holds, whenever the frame being stored would fill more than half of it, up to
 * `max` slots. It never shrinks. A frame ends at the RTP marker bit.
 *
 * Pure: no lock, no clock, no I/O. The caller serialises every call.
 */

#include <stddef.h>
#include <stdint.h>

#include "config.h"

#define RTX_SLOT_BYTES (CONFIG_MTU + 128)

typedef struct {
  uint16_t seq;            /* media seq stored here (slot = seq % cap)  */
  uint16_t len;            /* 0 = empty                                 */
  uint32_t last_resend_ms; /* monotonic ms of its last retransmission   */
  uint8_t data[RTX_SLOT_BYTES]; /* final pre-SRTP media packet          */
} rtx_slot_t;

typedef struct {
  rtx_slot_t* slots;
  unsigned cap;        /* slots held; a power of two dividing 65536     */
  unsigned max_cap;
  unsigned frame_pkts; /* packets of the frame being stored so far      */
} rtx_history;

/* 0 on success. `initial` and `max` are powers of two, initial <= max <= 65536. */
int rtx_history_init(rtx_history* h, unsigned initial, unsigned max);
void rtx_history_free(rtx_history* h);

/* Record one outgoing media packet. A packet shorter than an RTP header or
 * longer than a slot is not recorded. A failed grow keeps the current ring. */
void rtx_history_store(rtx_history* h, const uint8_t* pkt, size_t len);

/* The slot holding `seq`, or NULL when it is no longer held. */
rtx_slot_t* rtx_history_find(rtx_history* h, uint16_t seq);

#endif /* RTX_HISTORY_H_ */
