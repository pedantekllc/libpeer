#include "pacer.h"

#define PACER_MIN_LEFT_NS 1000000ull

uint32_t pacer_effective_bps(uint32_t bps, uint64_t queued_bytes, uint64_t queued_for_ns, uint64_t queue_limit_ns) {
  if (bps == 0) return 0;
  uint64_t left = queue_limit_ns > queued_for_ns ? queue_limit_ns - queued_for_ns : 0;
  if (left < PACER_MIN_LEFT_NS) left = PACER_MIN_LEFT_NS;
  /* bits per second = bytes * 8 / seconds; kept in double so a large queue
   * with a millisecond left cannot overflow. */
  double needed = (double)queued_bytes * 8.0 * 1e9 / (double)left;
  if (needed <= (double)bps) return bps;
  return needed >= 4294967295.0 ? UINT32_MAX : (uint32_t)needed;
}

int pacer_abandons(int leaving, uint32_t bps, uint64_t queued_bytes, uint64_t queued_for_ns, uint64_t queue_limit_ns) {
  if (!leaving || bps == 0) return 0;
  return pacer_effective_bps(bps, queued_bytes, queued_for_ns, queue_limit_ns) > bps;
}

pacer_queue pacer_video_queue(uint64_t queue_limit_ns, uint64_t au_bytes, uint64_t au_age_ns, uint64_t ring_bytes, uint64_t ring_wait_ns) {
  if (queue_limit_ns < PACER_QUEUE_LIMIT_NS) {
    pacer_queue own = {au_bytes, au_age_ns};
    return own;
  }
  pacer_queue whole = {au_bytes + ring_bytes, au_age_ns > ring_wait_ns ? au_age_ns : ring_wait_ns};
  return whole;
}

/* Time since `last`, never negative: the media and retransmission threads read their
 * clocks before taking the lock, so a stamp can be later than this call's. */
static uint64_t elapsed_ns(uint64_t last, uint64_t now) {
  return now > last ? now - last : 0;
}

uint64_t pacer_take(pacer_state* p, uint32_t bps, uint64_t queued_bytes, uint64_t queued_for_ns, size_t bytes, uint64_t now_ns, uint64_t queue_limit_ns) {
  if (bps == 0) return 0;
  uint32_t rate = pacer_effective_bps(bps, queued_bytes, queued_for_ns, queue_limit_ns);

  if (!p->started) {
    p->started = 1;
    p->last_ns = now_ns;
    p->budget_bytes = PACER_BURST_BYTES;
  }
  double elapsed = (double)elapsed_ns(p->last_ns, now_ns) / 1e9;
  if (now_ns > p->last_ns) p->last_ns = now_ns;

  p->budget_bytes += elapsed * (double)rate / 8.0;
  if (p->budget_bytes > PACER_BURST_BYTES) p->budget_bytes = PACER_BURST_BYTES;

  p->budget_bytes -= (double)bytes;
  if (p->budget_bytes >= 0) return 0;
  double wait_ns = -p->budget_bytes * 8.0 / (double)rate * 1e9;
  if (wait_ns > (double)PACER_MAX_SLEEP_NS) wait_ns = (double)PACER_MAX_SLEEP_NS;
  /* The deficit is repaid by the elapsed-time refill on the next call. */
  return (uint64_t)wait_ns;
}

void pacer_shared_init(pacer_shared* p) {
  pthread_mutex_init(&p->mtx, NULL);
  p->st = (pacer_state){0};
}

void pacer_shared_destroy(pacer_shared* p) {
  pthread_mutex_destroy(&p->mtx);
}

uint64_t pacer_shared_take(pacer_shared* p, uint32_t bps, uint64_t queued_bytes, uint64_t queued_for_ns, size_t bytes, uint64_t now_ns, uint64_t queue_limit_ns) {
  pthread_mutex_lock(&p->mtx);
  uint64_t wait_ns = pacer_take(&p->st, bps, queued_bytes, queued_for_ns, bytes, now_ns, queue_limit_ns);
  pthread_mutex_unlock(&p->mtx);
  return wait_ns;
}

uint64_t pacer_shared_take_rtx(pacer_shared* p, uint32_t bps, size_t bytes, uint64_t now_ns) {
  if (bps == 0) return 0;
  pthread_mutex_lock(&p->mtx);
  pacer_state* st = &p->st;
  if (!st->rtx_started) {
    st->rtx_started = 1;
    st->rtx_last_ns = now_ns;
    st->rtx_budget_bytes = PACER_BURST_BYTES;
  }
  double rtx_rate = (double)bps * PACER_RTX_SHARE_PCT / 100.0;
  st->rtx_budget_bytes += (double)elapsed_ns(st->rtx_last_ns, now_ns) / 1e9 * rtx_rate / 8.0;
  if (now_ns > st->rtx_last_ns) st->rtx_last_ns = now_ns;
  if (st->rtx_budget_bytes > PACER_BURST_BYTES) st->rtx_budget_bytes = PACER_BURST_BYTES;
  st->rtx_budget_bytes -= (double)bytes;

  /* The media's bucket pays for the same bytes. */
  if (st->started) {
    st->budget_bytes += (double)elapsed_ns(st->last_ns, now_ns) / 1e9 * (double)bps / 8.0;
    if (now_ns > st->last_ns) st->last_ns = now_ns;
    if (st->budget_bytes > PACER_BURST_BYTES) st->budget_bytes = PACER_BURST_BYTES;
    st->budget_bytes -= (double)bytes;
  }

  uint64_t wait_ns = 0;
  if (st->rtx_budget_bytes < 0) {
    double w = -st->rtx_budget_bytes * 8.0 / rtx_rate * 1e9;
    wait_ns = w > (double)PACER_RTX_MAX_SLEEP_NS ? PACER_RTX_MAX_SLEEP_NS : (uint64_t)w;
  }
  pthread_mutex_unlock(&p->mtx);
  return wait_ns;
}
