/* rtx_stats.c — retransmission counters. Contract: rtx_stats.h. */
#include "rtx_stats.h"

#include <stdlib.h>
#include <string.h>

void rtx_stats_init(rtx_stats* s) {
  memset(s, 0, sizeof(*s));
}

void rtx_stats_on_miss(rtx_stats* s) {
  s->miss++;
}

void rtx_stats_on_pli(rtx_stats* s) {
  s->pli++;
}

void rtx_stats_on_dup(rtx_stats* s) {
  s->suppressed++;
}

void rtx_stats_on_stale(rtx_stats* s, uint32_t n) {
  s->stale += n;
}

uint32_t rtx_guard_ms(rtx_rtt rtt) {
  if (!rtt.known) return RTX_GUARD_FALLBACK_MS;
  uint32_t half = rtt.ms / 2;
  if (half < RTX_GUARD_MIN_MS) return RTX_GUARD_MIN_MS;
  return half > RTX_GUARD_MAX_MS ? RTX_GUARD_MAX_MS : half;
}

void rtx_stats_on_sent(rtx_stats* s, uint32_t wait_ms) {
  s->sent++;
  if (wait_ms > s->wait_max_ms) s->wait_max_ms = wait_ms;
  if (s->wait_n < RTX_STATS_WAIT_SAMPLES) s->waits[s->wait_n++] = (uint16_t)(wait_ms > 0xffffu ? 0xffffu : wait_ms);
}

rtx_slot_t* rtx_stats_on_nack_seq(rtx_stats* s, rtx_history* h, uint16_t seq, uint32_t now_ms,
                                  uint32_t guard_ms) {
  s->nacked++;
  rtx_slot_t* slot = rtx_history_find(h, seq);
  if (!slot) {
    s->miss++;
    return NULL;
  }
  if (slot->last_resend_ms != 0 && now_ms - slot->last_resend_ms < guard_ms) {
    s->suppressed++;
    return NULL;
  }
  return slot;
}

static int cmp_u16(const void* a, const void* b) {
  return (int)*(const uint16_t*)a - (int)*(const uint16_t*)b;
}

rtx_stats_snapshot rtx_stats_drain(rtx_stats* s) {
  rtx_stats_snapshot out = {
      .nacked = s->nacked,
      .sent = s->sent,
      .miss = s->miss,
      .suppressed = s->suppressed,
      .pli = s->pli,
      .stale = s->stale,
      .wait_max_ms = s->wait_max_ms,
      .wait_n = s->wait_n,
  };
  if (s->wait_n > 0) {
    qsort(s->waits, s->wait_n, sizeof(s->waits[0]), cmp_u16);
    out.wait_p50_ms = s->waits[(s->wait_n - 1) / 2];
  }
  rtx_stats_init(s);
  return out;
}
