#include "pacer.h"

#define PACER_MIN_LEFT_NS 1000000ull

uint32_t pacer_effective_bps(uint32_t bps, uint64_t queued_bytes, uint64_t queued_for_ns) {
  if (bps == 0) return 0;
  uint64_t left = PACER_QUEUE_LIMIT_NS > queued_for_ns ? PACER_QUEUE_LIMIT_NS - queued_for_ns : 0;
  if (left < PACER_MIN_LEFT_NS) left = PACER_MIN_LEFT_NS;
  /* bits per second = bytes * 8 / seconds; kept in double so a large queue
   * with a millisecond left cannot overflow. */
  double needed = (double)queued_bytes * 8.0 * 1e9 / (double)left;
  if (needed <= (double)bps) return bps;
  return needed >= 4294967295.0 ? UINT32_MAX : (uint32_t)needed;
}

uint64_t pacer_take(pacer_state* p, uint32_t bps, uint64_t queued_bytes, uint64_t queued_for_ns, size_t bytes, uint64_t now_ns) {
  if (bps == 0) return 0;
  uint32_t rate = pacer_effective_bps(bps, queued_bytes, queued_for_ns);

  if (!p->started) {
    p->started = 1;
    p->last_ns = now_ns;
    p->budget_bytes = PACER_BURST_BYTES;
  }
  double elapsed = (double)(now_ns - p->last_ns) / 1e9;
  p->last_ns = now_ns;

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

uint64_t pacer_shared_take(pacer_shared* p, uint32_t bps, uint64_t queued_bytes, uint64_t queued_for_ns, size_t bytes, uint64_t now_ns) {
  pthread_mutex_lock(&p->mtx);
  uint64_t wait_ns = pacer_take(&p->st, bps, queued_bytes, queued_for_ns, bytes, now_ns);
  pthread_mutex_unlock(&p->mtx);
  return wait_ns;
}
