/* rtx_queue.c — the retransmission queue. Contract: rtx_queue.h. */
#include "rtx_queue.h"

#include <stdlib.h>

#define HELD_BYTES (65536u / 8u)

int rtx_queue_init(rtx_queue* q, unsigned cap) {
  q->seq = malloc(cap * sizeof(*q->seq));
  q->queued_ms = malloc(cap * sizeof(*q->queued_ms));
  q->held = calloc(HELD_BYTES, 1);
  q->cap = cap;
  q->first = q->n = 0;
  if (!q->seq || !q->queued_ms || !q->held) {
    rtx_queue_free(q);
    return -1;
  }
  return 0;
}

void rtx_queue_free(rtx_queue* q) {
  free(q->seq);
  free(q->queued_ms);
  free(q->held);
  q->seq = NULL;
  q->queued_ms = NULL;
  q->held = NULL;
  q->cap = q->first = q->n = 0;
}

static int is_held(const rtx_queue* q, uint16_t seq) {
  return (q->held[seq >> 3] >> (seq & 7)) & 1;
}

rtx_push_result rtx_queue_push(rtx_queue* q, uint16_t seq, uint32_t now_ms) {
  if (is_held(q, seq)) return RTX_PUSH_DUP;
  if (q->n >= q->cap) return RTX_PUSH_FULL;
  unsigned at = (q->first + q->n) % q->cap;
  q->seq[at] = seq;
  q->queued_ms[at] = now_ms;
  q->n++;
  q->held[seq >> 3] |= (uint8_t)(1u << (seq & 7));
  return RTX_PUSH_QUEUED;
}

void rtx_queue_done(rtx_queue* q, uint16_t seq) {
  q->held[seq >> 3] &= (uint8_t)~(1u << (seq & 7));
}

int rtx_queue_pop(rtx_queue* q, uint32_t now_ms, uint16_t* seq, uint32_t* queued_ms, uint32_t* stale) {
  while (q->n > 0) {
    uint16_t s = q->seq[q->first];
    uint32_t at = q->queued_ms[q->first];
    q->first = (q->first + 1) % q->cap;
    q->n--;
    if (now_ms - at > RTX_QUEUE_MAX_AGE_MS) {
      rtx_queue_done(q, s);
      (*stale)++;
      continue;
    }
    *seq = s;
    *queued_ms = at;
    return 1;
  }
  return 0;
}
