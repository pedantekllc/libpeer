#ifndef RTCP_WALK_H_
#define RTCP_WALK_H_

/*
 * Pure walk over a compound RTCP packet received from the peer, and the
 * round-trip-time sample derived from receiver-report blocks.
 *
 * The walk reads only bytes inside [buf, buf+len): every packet header must fit,
 * carry version 2 and a length that stays inside the compound, and every packet
 * type the walk reads fields from must be long enough for those fields. The
 * first packet that fails stops the walk; the packets before it were already
 * delivered. No sockets, threads or clock: the owner passes the clock in.
 */

#include <stddef.h>
#include <stdint.h>

typedef struct {
  uint32_t ssrc;
  uint8_t fraction_lost; /* 8-bit fixed point, loss / 256 */
  uint32_t cum_lost;     /* 24 bits */
  uint32_t ext_highest_seq;
  uint32_t jitter;
  uint32_t lsr;  /* middle 32 bits of the NTP time of the last SR received; 0 = none yet */
  uint32_t dlsr; /* delay since that SR, 1/65536 s */
} rtcp_report;

typedef struct {
  /* RR: all `n` report blocks (n <= 31), in wire order. */
  void (*receiver_report)(void* ctx, uint32_t sender_ssrc, const rtcp_report* blocks, size_t n);
  /* RTPFB fmt 1 (Generic NACK) / fmt 15 (transport-wide feedback): the whole
   * packet, header included, at least 12 bytes and fully inside the compound. */
  void (*nack)(void* ctx, const uint8_t* pkt, size_t len);
  void (*twcc)(void* ctx, const uint8_t* pkt, size_t len);
  /* PSFB fmt 1 (PLI) or fmt 4 (FIR). */
  void (*keyframe_request)(void* ctx);
} rtcp_walk_ops;

typedef enum {
  RTCP_WALK_OK = 0,
  RTCP_WALK_TRUNCATED_HEADER, /* fewer than 4 bytes left for a header */
  RTCP_WALK_BAD_VERSION,
  RTCP_WALK_LENGTH_OVERRUN, /* the length field runs past the compound */
  RTCP_WALK_SHORT_BODY      /* the packet is too short for its type's fixed fields or report count */
} rtcp_walk_status;

typedef struct {
  size_t packets; /* packets walked before the stop, each delivered to the ops that apply */
  rtcp_walk_status status;
} rtcp_walk_result;

/* Walk the compound. Any op may be NULL. */
rtcp_walk_result rtcp_walk(const uint8_t* buf, size_t len, const rtcp_walk_ops* ops, void* ctx);

/* ── RTT from report blocks ───────────────────────────────────────────────── */

#define RTCP_SR_HISTORY_SLOTS 16

/* The Sender Reports we sent: the middle 32 bits of each SR's NTP field with the
 * sender monotonic time it left. The SR's NTP field is the frame capture time,
 * which precedes the send time by the pipeline latency, so the round trip is
 * measured against the recorded send time, not against the NTP field. */
typedef struct {
  struct {
    uint32_t lsr;
    uint64_t sent_us;
  } slot[RTCP_SR_HISTORY_SLOTS];
  size_t next;
  size_t count;
} rtcp_sr_history;

void rtcp_sr_history_init(rtcp_sr_history* h);

/* Record an SR sent at `sent_us` whose NTP timestamp is `ntp`. */
void rtcp_sr_history_add(rtcp_sr_history* h, uint64_t ntp, uint64_t sent_us);

/* Round trip in microseconds for a report block received at `now_us`. Returns 1
 * and sets *rtt_us when the block's LSR names an SR in the history, 0 otherwise
 * (no SR received by the peer yet, LSR=0, or an SR no longer remembered). A
 * non-positive result is raised to 1 ms, as libwebrtc does. */
int rtcp_rtt_sample(const rtcp_sr_history* h, uint32_t lsr, uint32_t dlsr, uint64_t now_us, uint32_t* rtt_us);

#endif  // RTCP_WALK_H_
