#ifndef PACER_H_
#define PACER_H_

/*
 * Token-bucket send pacer with libwebrtc's queue-time bound (PacingController
 * queue_time_limit / drain_large_queues): when the data still waiting would take
 * longer than the limit to drain at the configured rate, the rate is raised so
 * it drains within the limit.
 *
 * What "the queue" is here: the rest of the access unit being sent. The pacer
 * runs inside the send worker, one packet at a time, and the only backlog it can
 * see is the unsent remainder of the frame handed to peer_connection_send_video
 * and how long that frame has been in the pacer. Frames waiting in the lane's
 * ring ahead of the worker are outside this module.
 *
 * Pure: the clock is a parameter and the result is the time to sleep.
 */

#include <stddef.h>
#include <stdint.h>

/* A dozen MTUs may leave back-to-back before pacing starts. */
#define PACER_BURST_BYTES 16384.0

/* The longest the queue may take to drain (libwebrtc kMaxQueueTime default). */
#define PACER_QUEUE_LIMIT_NS 2000000000ull

/* Per-packet sleep cap: guards against a pathological rate stalling a worker. */
#define PACER_MAX_SLEEP_NS 50000000ull

typedef struct {
  double budget_bytes; /* current bucket level (may go negative) */
  uint64_t last_ns;
  int started;
} pacer_state;

/* The rate to pace at: `bps`, or more when `queued_bytes` would not drain
 * within the time left of PACER_QUEUE_LIMIT_NS after `queued_for_ns` already
 * spent (at least 1 ms is always left). Never below `bps`. */
uint32_t pacer_effective_bps(uint32_t bps, uint64_t queued_bytes, uint64_t queued_for_ns);

/* Spend `bytes` of a packet sent at `now_ns` with `queued_bytes` (this packet
 * included) still queued, the queue having waited `queued_for_ns`. Returns the
 * nanoseconds to sleep before sending (0 = send now). `bps` 0 disables pacing. */
uint64_t pacer_take(pacer_state* p, uint32_t bps, uint64_t queued_bytes, uint64_t queued_for_ns, size_t bytes, uint64_t now_ns);

#endif  // PACER_H_
