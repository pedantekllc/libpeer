#ifndef PACER_H_
#define PACER_H_

/*
 * Token-bucket send pacer with libwebrtc's queue-time bound (PacingController
 * queue_time_limit / drain_large_queues): when the data still waiting would take
 * longer than the limit to drain at the configured rate, the rate is raised so
 * it drains within the limit.
 *
 * What "the queue" is: the unsent rest of the access unit being sent plus the
 * bytes still waiting in the caller's ring behind it (peer_backlog_fn), the
 * whole queue as libwebrtc counts it; the time already spent is the longer wait
 * of the two. The caller computes both and passes them to pacer_take.
 *
 * One pacer is shared by the media send worker and the retransmission thread;
 * pacer_shared serialises their budget updates.
 *
 * Pure: the clock is a parameter and the result is the time to sleep.
 */

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

/* Three MTUs may leave back-to-back: libwebrtc's pacer releases about one 5 ms process
 * interval of budget at a time, a few packets at a live-view rate. A larger allowance
 * doubles the short-term rate, and a narrow uplink's shallow queue drops the excess. */
#define PACER_BURST_BYTES 4096.0

/* The longest the queue may take to drain: libwebrtc's kMaxExpectedQueueLength. A
 * shorter limit releases a keyframe at line rate whenever the pace is a little under its
 * size per limit, and a burst at line rate overflows a narrow uplink's queue. Live
 * freshness is the ring's job (kfcore's flush limit), not the pacer's. */
#define PACER_QUEUE_LIMIT_NS 2000000000ull

/* Per-packet sleep cap: guards against a pathological rate stalling a worker. */
#define PACER_MAX_SLEEP_NS 50000000ull

typedef struct {
  double budget_bytes; /* current bucket level (may go negative) */
  uint64_t last_ns;
  int started;
} pacer_state;

/* A pacer that two threads draw on. The sleep a take returns is served by the
 * caller outside the lock. */
typedef struct {
  pthread_mutex_t mtx;
  pacer_state st;
} pacer_shared;

void pacer_shared_init(pacer_shared* p);
void pacer_shared_destroy(pacer_shared* p);

/* The rate to pace at: `bps`, or more when `queued_bytes` would not drain
 * within the time left of `queue_limit_ns` after `queued_for_ns` already
 * spent (at least 1 ms is always left). Never below `bps`. The limit is
 * PACER_QUEUE_LIMIT_NS unless the caller paces an access unit that must leave
 * sooner. */
uint32_t pacer_effective_bps(uint32_t bps, uint64_t queued_bytes, uint64_t queued_for_ns, uint64_t queue_limit_ns);

/* What a video packet's pace draws on. */
typedef struct {
  uint64_t bytes;     /* the queue, in bytes */
  uint64_t waited_ns; /* how long it has waited */
} pacer_queue;

/* The queue a video packet is paced against. With the default limit it is the whole
 * queue: the rest of the access unit in hand (`au_bytes`, waiting `au_age_ns` since the
 * access unit entered the pacer) plus the caller's ring behind it (`ring_bytes`, its
 * oldest frame having waited `ring_wait_ns`), the longer wait of the two. A limit
 * shorter than the default belongs to an access unit that must leave on its own, so it
 * is measured from that access unit's own start and covers its bytes only: the ring
 * behind it, however long it waited for the connection, neither shortens that time nor
 * adds to what must drain in it. */
pacer_queue pacer_video_queue(uint64_t queue_limit_ns, uint64_t au_bytes, uint64_t au_age_ns, uint64_t ring_bytes, uint64_t ring_wait_ns);

/* Spend `bytes` of a packet sent at `now_ns` with `queued_bytes` (this packet
 * included) still queued, the queue having waited `queued_for_ns` against
 * `queue_limit_ns`. Returns the nanoseconds to sleep before sending (0 = send
 * now). `bps` 0 disables pacing. */
uint64_t pacer_take(pacer_state* p, uint32_t bps, uint64_t queued_bytes, uint64_t queued_for_ns, size_t bytes, uint64_t now_ns, uint64_t queue_limit_ns);

/* pacer_take on the shared bucket. Media and retransmissions both come through
 * here, so a retransmission is charged against the same budget as the media. */
uint64_t pacer_shared_take(pacer_shared* p, uint32_t bps, uint64_t queued_bytes, uint64_t queued_for_ns, size_t bytes, uint64_t now_ns, uint64_t queue_limit_ns);

#endif  // PACER_H_
