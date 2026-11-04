#ifndef TWCC_H_
#define TWCC_H_

/*
 * Transport-wide congestion control wire layer
 * (draft-holmer-rmcat-transport-wide-cc-extensions-01).
 *
 * Pure byte/data code: no sockets, no threads, no clock. Two parts:
 *   - RTP header extension helpers (one-byte form, RFC 8285) that reserve and
 *     stamp the 16-bit transport-wide sequence number,
 *   - the RTCP RTPFB FMT 15 parser and encoder, and the expansion of a parsed
 *     report into per-packet arrivals.
 * Nothing here locks.
 */

#include <stddef.h>
#include <stdint.h>

/* RFC 8285 one-byte extension id we offer for the transport-wide sequence
 * number. Kept in sync with the extmap line in sdp.c. */
#define RTP_EXT_ID_TRANSPORT_CC 5
#define TWCC_EXTMAP_URI "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01"

/* ── RTP header extension ─────────────────────────────────────────────────── */

/* Locate extension element `id` in a one-byte-form (0xBEDE) block. Returns 1
 * and fills *data_off / *data_len (offset of the element's data bytes within
 * pkt) when present, 0 when the packet has no such element. */
int twcc_ext_find(const uint8_t* pkt, size_t size, uint8_t id, size_t* data_off, size_t* data_len);

/* Add a 2-byte element `id` (value zero) to the packet's one-byte extension
 * block, creating the block when the packet has none and keeping every other
 * element. Idempotent when the element is already present. `*size` is updated;
 * `cap` is the capacity of the buffer behind `pkt`. Returns 0, or a negative
 * TWCC_ERR_* (packet untouched). */
int twcc_ext_reserve(uint8_t* pkt, size_t* size, size_t cap, uint8_t id);

/* Write `seq` into element `id`. Returns 1 when the element exists, else 0. */
int twcc_ext_stamp(uint8_t* pkt, size_t size, uint8_t id, uint16_t seq);

/* Build a padding-only RTP packet: P and X set, one-byte extension block
 * holding a zeroed transport-wide seq element, then 255 bytes of padding (the
 * last byte is the count). Returns the packet size, or 0 when `cap` is too
 * small. */
#define TWCC_PADDING_PACKET_SIZE (12 + 8 + 255)
size_t twcc_build_padding_packet(uint8_t* out, size_t cap, uint8_t pt, uint32_t ssrc, uint16_t seq, uint32_t rtp_ts, uint8_t ext_id);

/* ── Feedback ─────────────────────────────────────────────────────────────── */

#define TWCC_ERR_FORMAT (-1)    /* not an RTPFB FMT 15 packet / truncated */
#define TWCC_ERR_RESERVED (-2)  /* reserved status symbol 3 */
#define TWCC_ERR_NOMEM (-4)
#define TWCC_ERR_RANGE (-5)  /* a value the wire form cannot carry */
#define TWCC_ERR_SPACE (-6)  /* output buffer too small */

/* libwebrtc's TransportFeedback::kMaxReportedPackets: a status count is 16 bits. */
#define TWCC_MAX_PACKETS 0xFFFF
#define TWCC_DELTA_TICK_US 250
#define TWCC_REF_TICK_US 64000

typedef struct {
  uint16_t seq;
  uint8_t received;
  int32_t recv_delta_us; /* from the previous received packet (the first: from the reference time); 0 when !received */
} twcc_status;

typedef struct {
  uint32_t sender_ssrc;
  uint32_t media_ssrc;
  uint16_t base_seq;
  uint32_t ref_time; /* 24 bits, units of 64 ms */
  uint8_t fb_count;
  size_t count;          /* packets described, seq = base_seq .. base_seq + count - 1 (mod 2^16) */
  twcc_status* results;  /* heap, count entries; NULL when count == 0 */
} twcc_feedback;

/* Parse one RTCP RTPFB FMT 15 packet (header included, `len` = bytes
 * available). On success fills *fb (results heap-allocated; release with
 * twcc_feedback_free) and returns 0. */
int twcc_parse(const uint8_t* pkt, size_t len, twcc_feedback* fb);
void twcc_feedback_free(twcc_feedback* fb);

/* Encode `fb` the way Pion's twcc recorder does (greedy chunking, small delta
 * for 0..255 ticks else large). recv_delta_us must be a multiple of 250 within
 * int16 ticks. Returns the packet size, or a negative TWCC_ERR_*. */
int twcc_encode(const twcc_feedback* fb, uint8_t* out, size_t cap);

/* The 24-bit reference time as an unwrapped microsecond clock: successive
 * values advance by the signed 24-bit difference, so wraparound is invisible. */
typedef struct {
  int64_t ref_ticks;
  uint8_t init;
  int64_t offset_us; /* twcc_ref_local_us */
  uint32_t last_ref;
  uint8_t local_init;
} twcc_ref_clock;

/* The unwrapped reference counter in microseconds. Its zero is the first
 * reference time, so it is a count, not a point on the sender's clock, and
 * differences between values are the only meaningful use. */
int64_t twcc_ref_unwrap(twcc_ref_clock* c, uint32_t ref_time);

/* The reference time of a feedback as a point on the sender's clock, the way
 * libwebrtc anchors it: the first feedback is placed at `now_us` (the sender
 * clock when it arrived), later ones advance by the signed 24-bit change of the
 * reference time, and a step back larger than the time already accumulated
 * restarts at `now_us`. Never below zero while `now_us` is not. Use one clock
 * (the one stamping the sent records) for `now_us`. */
int64_t twcc_ref_local_us(twcc_ref_clock* c, uint32_t ref_time, int64_t now_us);

/* ── Arrivals ─────────────────────────────────────────────────────────────── */

/* One packet of a feedback report on the receiver's clock. The estimator joins
 * it with its own send history by `seq`. */
typedef struct {
  uint16_t seq;
  uint8_t received;
  int64_t recv_us; /* receiver clock, unwrapped; meaningful only when received */
} twcc_arrival;

/* Expand `fb` into per-packet arrivals. `ref_us` is the unwrapped reference time
 * in microseconds; each received packet's time is the reference plus the
 * running sum of the deltas. Returns the number written to `out` (at most
 * `cap`). */
size_t twcc_arrivals(const twcc_feedback* fb, int64_t ref_us, twcc_arrival* out, size_t cap);

#endif  // TWCC_H_
