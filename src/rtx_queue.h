#ifndef RTX_QUEUE_H_
#define RTX_QUEUE_H_

/*
 * The NACKed sequence numbers waiting for the retransmission thread's pace.
 *
 * One entry per sequence: a sequence queued or being sent is not queued again, so a
 * receiver repeating its NACK every few milliseconds while the packet waits adds
 * nothing. An entry that has waited longer than RTX_QUEUE_MAX_AGE_MS is dropped at
 * the pop and not sent: its frame is past playout and the receiver has asked again
 * or moved on to the next keyframe.
 *
 * Pure: no lock, no clock, no I/O. The caller serialises every call.
 */

#include <stdint.h>

#define RTX_QUEUE_MAX_AGE_MS 500u

typedef enum {
  RTX_PUSH_QUEUED = 0,
  RTX_PUSH_DUP, /* the sequence is already queued or being sent */
  RTX_PUSH_FULL,
} rtx_push_result;

typedef struct {
  uint16_t* seq;
  uint32_t* queued_ms;
  uint8_t* held; /* 65536-bit set: sequence queued or in flight */
  unsigned cap, first, n;
} rtx_queue;

/* 0 on success. */
int rtx_queue_init(rtx_queue* q, unsigned cap);
void rtx_queue_free(rtx_queue* q);

rtx_push_result rtx_queue_push(rtx_queue* q, uint16_t seq, uint32_t now_ms);

/* The oldest entry still younger than RTX_QUEUE_MAX_AGE_MS at `now_ms`, which stays
 * held until rtx_queue_done. Older entries ahead of it are discarded and counted in
 * `*stale`. Returns 0 when nothing is left to send. */
int rtx_queue_pop(rtx_queue* q, uint32_t now_ms, uint16_t* seq, uint32_t* queued_ms, uint32_t* stale);

/* The popped sequence has left (or was abandoned): it may be queued again. */
void rtx_queue_done(rtx_queue* q, uint16_t seq);

#endif /* RTX_QUEUE_H_ */
