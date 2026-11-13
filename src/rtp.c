#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "address.h"
#include "config.h"
#include "peer_connection.h"
#include "rtp.h"
#include "utils.h"

typedef enum RtpH264Type {

  NALU = 23,
  STAP_A = 24,
  FU_A = 28,

} RtpH264Type;

typedef struct NaluHeader {
  uint8_t type : 5;
  uint8_t nri : 2;
  uint8_t f : 1;
} NaluHeader;

typedef struct FuHeader {
  uint8_t type : 5;
  uint8_t r : 1;
  uint8_t e : 1;
  uint8_t s : 1;
} FuHeader;

typedef struct NaluInfo {
  uint8_t* data;
  size_t size;
  uint8_t type;
} NaluInfo;

#define RTP_PAYLOAD_SIZE (CONFIG_MTU - sizeof(RtpHeader))
#define FU_PAYLOAD_SIZE (CONFIG_MTU - sizeof(RtpHeader) - sizeof(FuHeader) - sizeof(NaluHeader))

/* NTP epoch offset: seconds between 1900-01-01 and 1970-01-01. */
#define NTP_EPOCH_OFFSET_S 2208988800ULL

uint64_t unix_ns_to_ntp(uint64_t unix_ns) {
  uint64_t unix_sec  = unix_ns / 1000000000ULL;
  uint64_t frac_ns   = unix_ns % 1000000000ULL;
  uint64_t ntp_sec   = unix_sec + NTP_EPOCH_OFFSET_S;
  /* NTP fraction: frac_ns * 2^32 / 1e9.  Compute as (frac_ns << 32) / 1e9
   * but avoid 128-bit by doing (frac_ns * 4294967296ULL) / 1000000000ULL;
   * max frac_ns < 1e9 so product < 4.3e18, fits in uint64_t.              */
  uint64_t ntp_frac  = (frac_ns * 4294967296ULL) / 1000000000ULL;
  return (ntp_sec << 32) | (ntp_frac & 0xFFFFFFFFULL);
}

size_t rtp_insert_extensions(uint8_t* data, size_t size, int has_capture_time, uint64_t capture_ntp) {
  /* Need a fixed 12-byte header present (CSRC=0 assumed throughout).
   *
   * We do NOT trust the X bit that is already set: the FU-A packetizer sets
   * extension=0 only ONCE before its fragment loop and reuses rtp_encoder->buf,
   * so once X is set on fragment 1 it persists into fragments 2..N. Treating
   * that as a real extension would misread the FU payload as an extension
   * header (~75% loss / undecodable frames). The caller invokes this exactly
   * once per packet from the single send chokepoint, so always rebuild from a
   * clean 12-byte-header assumption: clear X, then add the block when needed.  */
  if (size < 12)
    return size;

  const size_t hdr = 12;  /* CSRC=0, so payload starts at byte 12 */
  data[0] &= (uint8_t)~0x10;

  if (!has_capture_time)
    return size;

  /* One element: abs-capture-time (id 4, 8 B).
   *
   * Element: 1 + 8 = 9 bytes   (id=4, len-1=7)
   * Total data: 9 bytes -> pad to next multiple of 4 -> 12 bytes = 3 words
   * Ext block total: 4 (profile+len) + 12 = 16 bytes, length field = 3 words
   *
   * Byte map:
   *   [0..1] 0xBEDE
   *   [2..3] 0x0003          length = 3 words (12-byte data region)
   *   [4]    0x47            id=4 | (len-1=7)
   *   [5..8] capture_ntp high 32 bits BE
   *   [9..12] capture_ntp low 32 bits BE
   *   [13..15] 0x00 0x00 0x00  padding to word boundary
   */
  memmove(data + hdr + 16, data + hdr, size - hdr);
  data[hdr + 0] = 0xBE;
  data[hdr + 1] = 0xDE;
  data[hdr + 2] = 0x00;
  data[hdr + 3] = 0x03;
  data[hdr + 4] = (uint8_t)((RTP_EXT_ID_ABS_CAPTURE_TIME << 4) | 0x07);
  data[hdr + 5] = (uint8_t)((capture_ntp >> 56) & 0xFF);
  data[hdr + 6] = (uint8_t)((capture_ntp >> 48) & 0xFF);
  data[hdr + 7] = (uint8_t)((capture_ntp >> 40) & 0xFF);
  data[hdr + 8] = (uint8_t)((capture_ntp >> 32) & 0xFF);
  data[hdr + 9] = (uint8_t)((capture_ntp >> 24) & 0xFF);
  data[hdr + 10] = (uint8_t)((capture_ntp >> 16) & 0xFF);
  data[hdr + 11] = (uint8_t)((capture_ntp >> 8) & 0xFF);
  data[hdr + 12] = (uint8_t)(capture_ntp & 0xFF);
  data[hdr + 13] = 0x00;
  data[hdr + 14] = 0x00;
  data[hdr + 15] = 0x00;
  data[0] |= 0x10;
  return size + 16;
}

void rtp_playout_delay_encode(uint32_t min_ms, uint32_t max_ms, uint8_t out[3]) {
  uint32_t lo = (min_ms > RTP_PLAYOUT_DELAY_MAX_MS ? RTP_PLAYOUT_DELAY_MAX_MS : min_ms);
  uint32_t hi = (max_ms > RTP_PLAYOUT_DELAY_MAX_MS ? RTP_PLAYOUT_DELAY_MAX_MS : max_ms);
  lo = (lo + 5) / 10;
  hi = (hi + 5) / 10;
  if (hi < lo)
    hi = lo;
  out[0] = (uint8_t)(lo >> 4);
  out[1] = (uint8_t)(((lo & 0x0F) << 4) | (hi >> 8));
  out[2] = (uint8_t)(hi & 0xFF);
}

size_t rtp_insert_extensions_pd(uint8_t* data, size_t size, int has_capture_time, uint64_t capture_ntp, uint8_t pd_id,
                                const uint8_t pd[3]) {
  if (pd_id == 0 || pd_id > 14 || !pd)
    return rtp_insert_extensions(data, size, has_capture_time, capture_ntp);
  if (size < 12)
    return size;

  /* Same clean-header rule as rtp_insert_extensions: clear X, rebuild the block.
   * Elements, in order: abs-capture-time (id 4, 8 B) when asked, playout-delay
   * (pd_id, 3 B). The data region is padded to a word boundary. */
  const size_t hdr = 12;
  uint8_t el[16];
  size_t k = 0;
  data[0] &= (uint8_t)~0x10;
  if (has_capture_time) {
    el[k++] = (uint8_t)((RTP_EXT_ID_ABS_CAPTURE_TIME << 4) | 0x07);
    for (int i = 7; i >= 0; i--)
      el[k++] = (uint8_t)((capture_ntp >> (8 * i)) & 0xFF);
  }
  el[k++] = (uint8_t)((pd_id << 4) | 0x02);
  el[k++] = pd[0];
  el[k++] = pd[1];
  el[k++] = pd[2];
  size_t words = (k + 3) / 4;
  size_t add = 4 + 4 * words;
  memmove(data + hdr + add, data + hdr, size - hdr);
  data[hdr + 0] = 0xBE;
  data[hdr + 1] = 0xDE;
  data[hdr + 2] = (uint8_t)(words >> 8);
  data[hdr + 3] = (uint8_t)(words & 0xFF);
  memcpy(data + hdr + 4, el, k);
  memset(data + hdr + 4 + k, 0, 4 * words - k);
  data[0] |= 0x10;
  return size + add;
}

int rtp_packet_validate(uint8_t* packet, size_t size) {
  if (size < 12)
    return 0;

  RtpHeader* rtp_header = (RtpHeader*)packet;
  return ((rtp_header->type < 64) || (rtp_header->type >= 96));
}

uint32_t rtp_get_ssrc(uint8_t* packet) {
  RtpHeader* rtp_header = (RtpHeader*)packet;
  return ntohl(rtp_header->ssrc);
}

/* Send a single NAL unit as one RTP packet.
 * Caller (rtp_encoder_encode_h264) manages timestamp and marker bit. */
static int rtp_encoder_encode_h264_single(RtpEncoder* rtp_encoder, uint8_t* buf, size_t size, int is_last_nalu) {
  RtpPacket* rtp_packet = (RtpPacket*)rtp_encoder->buf;

  rtp_packet->header.version = 2;
  rtp_packet->header.padding = 0;
  rtp_packet->header.extension = 0;
  rtp_packet->header.csrccount = 0;
  rtp_packet->header.type = rtp_encoder->type;
  rtp_packet->header.seq_number = htons(rtp_encoder->seq_number++);
  rtp_packet->header.timestamp = htonl(rtp_encoder->timestamp);
  rtp_packet->header.ssrc = htonl(rtp_encoder->ssrc);

  /* Marker bit: set on the last packet of the last NAL unit in the access unit */
  rtp_packet->header.markerbit = is_last_nalu ? 1 : 0;

  memcpy(rtp_packet->payload, buf, size);
  rtp_encoder->on_packet(rtp_encoder->buf, size + sizeof(RtpHeader), rtp_encoder->user_data);
  return 0;
}

/* Fragment a large NAL unit using FU-A.
 * Caller (rtp_encoder_encode_h264) manages timestamp and marker bit. */
static int rtp_encoder_encode_h264_fu_a(RtpEncoder* rtp_encoder, uint8_t* buf, size_t size, int is_last_nalu) {
  RtpPacket* rtp_packet = (RtpPacket*)rtp_encoder->buf;

  rtp_packet->header.version = 2;
  rtp_packet->header.padding = 0;
  rtp_packet->header.extension = 0;
  rtp_packet->header.csrccount = 0;
  rtp_packet->header.markerbit = 0;
  rtp_packet->header.type = rtp_encoder->type;
  rtp_packet->header.timestamp = htonl(rtp_encoder->timestamp);
  rtp_packet->header.ssrc = htonl(rtp_encoder->ssrc);
  uint8_t type = buf[0] & 0x1f;
  uint8_t nri = (buf[0] & 0x60) >> 5;
  buf = buf + 1;
  size = size - 1;

  NaluHeader* fu_indicator = (NaluHeader*)rtp_packet->payload;
  FuHeader* fu_header = (FuHeader*)rtp_packet->payload + sizeof(NaluHeader);
  fu_header->s = 1;

  while (size > 0) {
    fu_indicator->type = FU_A;
    fu_indicator->nri = nri;
    fu_indicator->f = 0;
    fu_header->type = type;
    fu_header->r = 0;
    rtp_packet->header.seq_number = htons(rtp_encoder->seq_number++);

    if (size <= FU_PAYLOAD_SIZE) {
      fu_header->e = 1;
      /* Marker bit on last fragment only if this is the last NALU in the access unit */
      rtp_packet->header.markerbit = is_last_nalu ? 1 : 0;
      memcpy(rtp_packet->payload + sizeof(NaluHeader) + sizeof(FuHeader), buf, size);
      rtp_encoder->on_packet(rtp_encoder->buf, size + sizeof(RtpHeader) + sizeof(NaluHeader) + sizeof(FuHeader), rtp_encoder->user_data);
      break;
    }

    fu_header->e = 0;

    memcpy(rtp_packet->payload + sizeof(NaluHeader) + sizeof(FuHeader), buf, FU_PAYLOAD_SIZE);
    rtp_encoder->on_packet(rtp_encoder->buf, CONFIG_MTU, rtp_encoder->user_data);
    size -= FU_PAYLOAD_SIZE;
    buf += FU_PAYLOAD_SIZE;

    fu_header->s = 0;
  }
  return 0;
}

/* Bundle multiple small NAL units into a single STAP-A RTP packet (RFC 6184 §5.7.1).
 *
 * Chrome's H.264 depacketizer incorrectly sets is_first_packet_in_frame=true for
 * every single-NAL RTP packet, breaking multi-slice frame assembly. STAP-A avoids
 * this by delivering all NALUs in one packet, so frame boundaries are unambiguous.
 * See: https://issues.webrtc.org/issues/346608838 */
static int rtp_encoder_encode_h264_stap_a(RtpEncoder* rtp_encoder, NaluInfo* nalus, int nalu_count) {
  RtpPacket* rtp_packet = (RtpPacket*)rtp_encoder->buf;

  rtp_packet->header.version = 2;
  rtp_packet->header.padding = 0;
  rtp_packet->header.extension = 0;
  rtp_packet->header.csrccount = 0;
  rtp_packet->header.type = rtp_encoder->type;
  rtp_packet->header.seq_number = htons(rtp_encoder->seq_number++);
  rtp_packet->header.timestamp = htonl(rtp_encoder->timestamp);
  rtp_packet->header.ssrc = htonl(rtp_encoder->ssrc);
  rtp_packet->header.markerbit = 1;  /* Single packet = entire access unit */

  /* STAP-A header: F=0, NRI=max of all NALUs, Type=24 */
  uint8_t max_nri = 0;
  for (int i = 0; i < nalu_count; i++) {
    uint8_t nri = (nalus[i].data[0] >> 5) & 0x03;
    if (nri > max_nri) max_nri = nri;
  }

  uint8_t* p = rtp_packet->payload;
  *p++ = (max_nri << 5) | STAP_A;

  /* Each NALU: 2-byte big-endian size prefix + NALU data */
  for (int i = 0; i < nalu_count; i++) {
    uint16_t ns = (uint16_t)nalus[i].size;
    *p++ = (ns >> 8) & 0xFF;
    *p++ = ns & 0xFF;
    memcpy(p, nalus[i].data, nalus[i].size);
    p += nalus[i].size;
  }

  size_t total = (size_t)(p - rtp_packet->payload);
  rtp_encoder->on_packet(rtp_encoder->buf, total + sizeof(RtpHeader), rtp_encoder->user_data);
  return 0;
}

/* Annex-B start-code scan shared by the H.264 and H.265 packetizers: returns
 * the first byte after the next 00 00 01 at or after buf_start+2, or buf_end. */
static uint8_t* annexb_find_nalu(uint8_t* buf_start, uint8_t* buf_end) {
  uint8_t* p = buf_start + 2;

  while (p < buf_end) {
    if (*(p - 2) == 0x00 && *(p - 1) == 0x00 && *p == 0x01)
      return p + 1;
    p++;
  }

  return buf_end;
}

/* Encode one H.264 access unit (frame) into RTP packets.
 *
 * Per RFC 6184: all NAL units in one access unit share the same RTP timestamp,
 * and the marker bit is set only on the last packet of the last NAL unit.
 * The timestamp increments once per access unit (frame), not per NAL unit.
 *
 * Multi-slice frames (common with libx264) have multiple type-1 or type-5
 * NAL units per frame. Each slice must share the same timestamp. */
static int rtp_encoder_encode_h264(RtpEncoder* rtp_encoder, uint8_t* buf, size_t size) {
  uint8_t* buf_end = buf + size;
  uint8_t *pstart, *pend;
  size_t nalu_size;
  int has_vcl_nalu = 0;

  /* First pass: collect all NALUs and find the last one */
  NaluInfo nalus[64];  /* max 64 NALUs per access unit */
  int nalu_count = 0;

  for (pstart = annexb_find_nalu(buf, buf_end); pstart < buf_end && nalu_count < 64; pstart = pend) {
    pend = annexb_find_nalu(pstart, buf_end);
    nalu_size = pend - pstart;

    if (pend != buf_end)
      nalu_size--;

    while (nalu_size > 0 && pstart[nalu_size - 1] == 0x00)
      nalu_size--;

    if (nalu_size == 0)
      continue;

    uint8_t nalu_type = pstart[0] & 0x1f;
    nalus[nalu_count].data = pstart;
    nalus[nalu_count].size = nalu_size;
    nalus[nalu_count].type = nalu_type;
    nalu_count++;

    /* Track if this access unit contains VCL NALUs (types 1-5) */
    if (nalu_type >= 1 && nalu_type <= 5)
      has_vcl_nalu = 1;
  }

  /* Check if all NALUs fit in a single STAP-A packet.
   * STAP-A overhead: 1 byte header + (2 byte size prefix per NALU). */
  size_t stap_a_size = 1;
  int all_fit_stap_a = (nalu_count > 1);
  for (int i = 0; i < nalu_count && all_fit_stap_a; i++) {
    stap_a_size += 2 + nalus[i].size;
    if (stap_a_size > RTP_PAYLOAD_SIZE)
      all_fit_stap_a = 0;
  }

  if (all_fit_stap_a) {
    /* Bundle all NALUs into one STAP-A packet */
    rtp_encoder_encode_h264_stap_a(rtp_encoder, nalus, nalu_count);
  } else {
    /* Second pass: encode each NALU individually */
    for (int i = 0; i < nalu_count; i++) {
      int is_last = (i == nalu_count - 1);

      if (nalus[i].size <= RTP_PAYLOAD_SIZE) {
        rtp_encoder_encode_h264_single(rtp_encoder, nalus[i].data, nalus[i].size, is_last);
      } else {
        rtp_encoder_encode_h264_fu_a(rtp_encoder, nalus[i].data, nalus[i].size, is_last);
      }
    }
  }

  /* Video timestamp is set by rtp_encoder_encode() from the caller's
   * capture_time_ns BEFORE this function runs, so we don't increment
   * here — that was the old fixed-rate behaviour that drifted against
   * any non-exactly-30fps producer. has_vcl_nalu detection is still
   * useful for callers that want to know whether this access unit
   * advanced media time, but the RTP layer itself no longer cares.
   */
  (void)has_vcl_nalu;
  return 0;
}

/* ── H.265 (RFC 7798) ─────────────────────────────────────────────────────
 * NAL unit header: 2 bytes, F(1) Type(6) LayerId(6) TID(3); type =
 * (b0 >> 1) & 0x3F. Packet kinds used here: the NAL itself (single NAL unit
 * packet), Aggregation Packet (type 48, §4.4.2) and Fragmentation Unit
 * (type 49, §4.4.3: 2-byte payload header + 1-byte FU header S|E|FuType).
 * As for H.264 the packetiser fills a placeholder seq; the transmit tail
 * (peer_connection_xmit_rtp) draws the wire seq. */
#define H265_NAL_HDR_SIZE 2
#define H265_NAL_TYPE_AP 48
#define H265_NAL_TYPE_FU 49
#define H265_FU_HDR_SIZE 1
#define H265_FU_PAYLOAD_SIZE (RTP_PAYLOAD_SIZE - H265_NAL_HDR_SIZE - H265_FU_HDR_SIZE)

/* Fill the fixed RTP header of the next packet; returns the payload pointer. */
static uint8_t* rtp_encoder_h265_header(RtpEncoder* rtp_encoder, int marker) {
  RtpPacket* rtp_packet = (RtpPacket*)rtp_encoder->buf;
  rtp_packet->header.version = 2;
  rtp_packet->header.padding = 0;
  rtp_packet->header.extension = 0;
  rtp_packet->header.csrccount = 0;
  rtp_packet->header.markerbit = marker ? 1 : 0;
  rtp_packet->header.type = rtp_encoder->type;
  rtp_packet->header.seq_number = htons(rtp_encoder->seq_number++);
  rtp_packet->header.timestamp = htonl(rtp_encoder->timestamp);
  rtp_packet->header.ssrc = htonl(rtp_encoder->ssrc);
  return rtp_packet->payload;
}

static void rtp_encoder_h265_single(RtpEncoder* rtp_encoder, const NaluInfo* nalu, int is_last_nalu) {
  uint8_t* p = rtp_encoder_h265_header(rtp_encoder, is_last_nalu);
  memcpy(p, nalu->data, nalu->size);
  rtp_encoder->on_packet(rtp_encoder->buf, nalu->size + sizeof(RtpHeader), rtp_encoder->user_data);
}

/* Split one NAL across FU packets; S on the first, E on the last; the marker
 * rides the last fragment of the last NAL of the access unit. */
static void rtp_encoder_h265_fu(RtpEncoder* rtp_encoder, const NaluInfo* nalu, int is_last_nalu) {
  uint8_t hdr0 = (uint8_t)((nalu->data[0] & 0x81) | (H265_NAL_TYPE_FU << 1));
  uint8_t hdr1 = nalu->data[1];
  uint8_t fu_type = (uint8_t)((nalu->data[0] >> 1) & 0x3F);
  const uint8_t* src = nalu->data + H265_NAL_HDR_SIZE;
  size_t left = nalu->size - H265_NAL_HDR_SIZE;
  int first = 1;

  while (left > 0) {
    size_t chunk = left < H265_FU_PAYLOAD_SIZE ? left : H265_FU_PAYLOAD_SIZE;
    int last = (chunk == left);
    uint8_t* p = rtp_encoder_h265_header(rtp_encoder, last && is_last_nalu);
    p[0] = hdr0;
    p[1] = hdr1;
    p[2] = (uint8_t)((first ? 0x80 : 0) | (last ? 0x40 : 0) | fu_type);
    memcpy(p + H265_NAL_HDR_SIZE + H265_FU_HDR_SIZE, src, chunk);
    rtp_encoder->on_packet(rtp_encoder->buf,
                           chunk + sizeof(RtpHeader) + H265_NAL_HDR_SIZE + H265_FU_HDR_SIZE,
                           rtp_encoder->user_data);
    src += chunk;
    left -= chunk;
    first = 0;
  }
}

/* All NAL units of the access unit in one Aggregation Packet: F = OR of the
 * NAL F bits, LayerId and TID = the lowest of the aggregated NALs. Each NAL is
 * preceded by its 16-bit big-endian size. */
static void rtp_encoder_h265_ap(RtpEncoder* rtp_encoder, const NaluInfo* nalus, int nalu_count) {
  uint8_t* p = rtp_encoder_h265_header(rtp_encoder, 1);
  uint8_t f = 0;
  uint8_t layer_id = 0x3F;
  uint8_t tid = 0x07;
  for (int i = 0; i < nalu_count; i++) {
    f |= (uint8_t)(nalus[i].data[0] >> 7);
    uint8_t lid = (uint8_t)(((nalus[i].data[0] & 0x01) << 5) | (nalus[i].data[1] >> 3));
    uint8_t t = nalus[i].data[1] & 0x07;
    if (lid < layer_id) layer_id = lid;
    if (t < tid) tid = t;
  }
  uint8_t* w = p;
  *w++ = (uint8_t)((f << 7) | (H265_NAL_TYPE_AP << 1) | (layer_id >> 5));
  *w++ = (uint8_t)(((layer_id & 0x1F) << 3) | tid);
  for (int i = 0; i < nalu_count; i++) {
    *w++ = (uint8_t)(nalus[i].size >> 8);
    *w++ = (uint8_t)(nalus[i].size & 0xFF);
    memcpy(w, nalus[i].data, nalus[i].size);
    w += nalus[i].size;
  }
  rtp_encoder->on_packet(rtp_encoder->buf, (size_t)(w - p) + sizeof(RtpHeader), rtp_encoder->user_data);
}

/* Encode one H.265 access unit (Annex-B) into RTP packets. All NAL units share
 * the RTP timestamp; the marker bit is on the last packet of the access unit.
 * An access unit whose NAL units all fit one packet goes out as one
 * Aggregation Packet (as H.264 uses STAP-A); otherwise each NAL is sent on its
 * own, FU-fragmented when larger than a packet. */
static int rtp_encoder_encode_h265(RtpEncoder* rtp_encoder, uint8_t* buf, size_t size) {
  uint8_t* buf_end = buf + size;
  uint8_t *pstart, *pend;
  NaluInfo nalus[64];  /* max 64 NALUs per access unit */
  int nalu_count = 0;

  for (pstart = annexb_find_nalu(buf, buf_end); pstart < buf_end && nalu_count < 64; pstart = pend) {
    pend = annexb_find_nalu(pstart, buf_end);
    size_t nalu_size = (size_t)(pend - pstart);

    if (pend != buf_end)
      nalu_size--;

    while (nalu_size > 0 && pstart[nalu_size - 1] == 0x00)
      nalu_size--;

    /* A NAL unit header is 2 bytes; anything shorter is not a NAL unit. */
    if (nalu_size < H265_NAL_HDR_SIZE)
      continue;

    nalus[nalu_count].data = pstart;
    nalus[nalu_count].size = nalu_size;
    nalus[nalu_count].type = (uint8_t)((pstart[0] >> 1) & 0x3F);
    nalu_count++;
  }

  size_t ap_size = H265_NAL_HDR_SIZE;
  int all_fit_ap = (nalu_count > 1);
  for (int i = 0; i < nalu_count && all_fit_ap; i++) {
    ap_size += 2 + nalus[i].size;
    if (ap_size > RTP_PAYLOAD_SIZE)
      all_fit_ap = 0;
  }

  if (all_fit_ap) {
    rtp_encoder_h265_ap(rtp_encoder, nalus, nalu_count);
    return 0;
  }
  for (int i = 0; i < nalu_count; i++) {
    int is_last = (i == nalu_count - 1);
    if (nalus[i].size <= RTP_PAYLOAD_SIZE)
      rtp_encoder_h265_single(rtp_encoder, &nalus[i], is_last);
    else
      rtp_encoder_h265_fu(rtp_encoder, &nalus[i], is_last);
  }
  return 0;
}

int rtp_video_pt(MediaCodec codec) {
  switch (codec) {
    case CODEC_H264:
      return PT_H264;
    case CODEC_H265:
      return PT_H265;
    default:
      return -1;
  }
}

int rtp_is_video_pt(int pt) {
  return pt == PT_H264 || pt == PT_H265;
}

static int rtp_encoder_encode_generic(RtpEncoder* rtp_encoder, uint8_t* buf, size_t size) {
  RtpHeader* rtp_header = (RtpHeader*)rtp_encoder->buf;
  rtp_header->version = 2;
  rtp_header->padding = 0;
  rtp_header->extension = 0;
  rtp_header->csrccount = 0;
  rtp_header->markerbit = 0;
  rtp_header->type = rtp_encoder->type;
  rtp_header->seq_number = htons(rtp_encoder->seq_number++);
  rtp_header->timestamp = htonl(rtp_encoder->timestamp);
  rtp_encoder->timestamp += rtp_encoder->timestamp_increment;
  rtp_header->ssrc = htonl(rtp_encoder->ssrc);
  memcpy(rtp_encoder->buf + sizeof(RtpHeader), buf, size);

  rtp_encoder->on_packet(rtp_encoder->buf, size + sizeof(RtpHeader), rtp_encoder->user_data);

  return 0;
}

void rtp_encoder_init(RtpEncoder* rtp_encoder, MediaCodec codec, RtpOnPacket on_packet, void* user_data) {
  rtp_encoder->on_packet = on_packet;
  rtp_encoder->user_data = user_data;
  rtp_encoder->timestamp = 0;
  rtp_encoder->seq_number = 0;
  rtp_encoder->timestamp_increment = 0;
  rtp_encoder->clock_rate_hz = 0;

  switch (codec) {
    case CODEC_H264:
      rtp_encoder->type = PT_H264;
      rtp_encoder->ssrc = SSRC_H264;
      /* No timestamp_increment for video — see header doc. The clock
       * rate matters because we convert caller-supplied capture_time_ns
       * into RTP ticks via (ns * rate / 1e9).                           */
      rtp_encoder->clock_rate_hz = 90000;
      rtp_encoder->encode_func = rtp_encoder_encode_h264;
      break;
    case CODEC_H265:
      rtp_encoder->type = PT_H265;
      rtp_encoder->ssrc = SSRC_H265;
      rtp_encoder->clock_rate_hz = 90000;
      rtp_encoder->encode_func = rtp_encoder_encode_h265;
      break;
    case CODEC_PCMA:
      rtp_encoder->type = PT_PCMA;
      rtp_encoder->ssrc = SSRC_PCMA;
      rtp_encoder->clock_rate_hz = 8000;
      rtp_encoder->timestamp_increment = CONFIG_AUDIO_DURATION * 8000 / 1000;
      rtp_encoder->encode_func = rtp_encoder_encode_generic;
      break;
    case CODEC_PCMU:
      rtp_encoder->type = PT_PCMU;
      rtp_encoder->ssrc = SSRC_PCMU;
      rtp_encoder->clock_rate_hz = 8000;
      rtp_encoder->timestamp_increment = CONFIG_AUDIO_DURATION * 8000 / 1000;
      rtp_encoder->encode_func = rtp_encoder_encode_generic;
      break;
    case CODEC_OPUS:
      rtp_encoder->type = PT_OPUS;
      rtp_encoder->ssrc = SSRC_OPUS;
      rtp_encoder->clock_rate_hz = 48000;
      rtp_encoder->timestamp_increment = CONFIG_AUDIO_DURATION * 48000 / 1000;
      rtp_encoder->encode_func = rtp_encoder_encode_generic;
      break;
    default:
      break;
  }
}

uint32_t rtp_timestamp_from_ns(uint64_t capture_time_ns, uint32_t clock_rate_hz) {
  /* Whole seconds and the sub-second remainder are scaled separately: a
   * CLOCK_REALTIME ns value times the clock rate exceeds 2^64. The remainder
   * product stays below 1e9 * rate, and uint32 truncation keeps the sum exact
   * mod 2^32. */
  uint64_t sec = capture_time_ns / 1000000000ULL;
  uint64_t rem = capture_time_ns % 1000000000ULL;
  return (uint32_t)(sec * clock_rate_hz + (rem * clock_rate_hz) / 1000000000ULL);
}

/* One RTP tick of the 90 kHz video clock, rounded up so a rebased frame's timestamp
 * is strictly above the last one's. */
#define RTP_VIDEO_TICK_NS 11112ULL

uint64_t rtp_video_clock_map(RtpVideoClock* clock, uint64_t capture_time_ns) {
  uint64_t mapped = (uint64_t)((int64_t)capture_time_ns + clock->offset_ns);
  if (clock->started && mapped < clock->last_ns) {
    const uint64_t target = clock->last_ns + RTP_VIDEO_TICK_NS;
    clock->offset_ns += (int64_t)(target - mapped);
    mapped = target;
  }
  clock->started = 1;
  clock->last_ns = mapped;
  return mapped;
}

int rtp_encoder_encode(RtpEncoder* rtp_encoder, const uint8_t* buf, size_t size, uint64_t capture_time_ns) {
  /* Video path: stamp RTP timestamp from the caller's capture time so
   * the receiver plays frames at the wall-clock pace they were produced,
   * regardless of how off-nominal the encoder's actual rate is.
   *
   * Audio path: capture_time_ns is ignored; the encode_func auto-
   * increments timestamp by samples-per-packet (the sample clock is
   * already the authoritative timebase and produces monotonic, regular
   * timestamps with no rate drift to correct for).
   */
  if (rtp_is_video_pt(rtp_encoder->type)) {
    rtp_encoder->timestamp = rtp_timestamp_from_ns(capture_time_ns, rtp_encoder->clock_rate_hz);
  }
  return rtp_encoder->encode_func(rtp_encoder, (uint8_t*)buf, size);
}

static int rtp_decode_h264(RtpDecoder* rtp_decoder, uint8_t* buf, size_t size) {
  static const uint32_t nalu_start_4bytecode = 0x01000000;
  /* Use per-decoder reassembly state (nalu_buf / nalu_offset) instead of
   * function-static locals.  Function-statics are shared across all
   * RtpDecoder instances and are not thread-safe when two decoders run
   * concurrently (e.g. the WebRTC RX path and the rtsp_source ingest
   * thread).  The per-decoder buffer is allocated in rtp_decoder_init(). */
  uint8_t* nalu_buf = rtp_decoder->nalu_buf;
  int* offset = &rtp_decoder->nalu_offset;
  if (!nalu_buf) return -1;  /* not initialised */
  if (size <= sizeof(RtpHeader)) {
    /* No payload at all (or not even a full RTP header): reading
     * rtp_packet->payload[0] below would be an out-of-bounds read, and
     * payload_size would be <= 0. Never legitimate for H.264. */
    return -1;
  }
  RtpPacket* rtp_packet = (RtpPacket*)buf;
  uint8_t nalu_type = *rtp_packet->payload & 0x1f;
  int payload_size = size - sizeof(RtpHeader);
  if (nalu_type > 0 && nalu_type < 24) {
    // NALU type 1-23 are single NALUs
    memcpy(nalu_buf, &nalu_start_4bytecode, sizeof(nalu_start_4bytecode));
    *offset = sizeof(nalu_start_4bytecode);
    memcpy(nalu_buf + *offset, rtp_packet->payload, payload_size);
    *offset += payload_size;
    if (rtp_decoder->on_packet != NULL) {
      rtp_decoder->on_packet(nalu_buf, *offset, rtp_decoder->user_data);
    }
    return (int)size;
  } else if (nalu_type == STAP_A) {
    /* STAP-A (RFC 6184 §5.7.1): [STAP-A hdr(1)][ (NALsize:2 BE)(NAL) ]* — emit
     * each aggregated NAL as its own Annex-B unit. ffmpeg/mediamtx bundle SPS+PPS
     * into a STAP-A; without this they fall into the FU-A branch, get mangled,
     * and the decoder never receives the parameter sets ("non-existing PPS").
     * (The .169 Reolink sent SPS/PPS as plain single NALs, so we never hit this
     * until the ffmpeg-backed E2E producer.) */
    const uint8_t* sp = rtp_packet->payload + 1;  /* skip the STAP-A header byte */
    int srem = payload_size - 1;
    while (srem >= 2) {
      int nsz = (sp[0] << 8) | sp[1];
      sp += 2; srem -= 2;
      if (nsz <= 0 || nsz > srem) break;
      if ((int)sizeof(nalu_start_4bytecode) + nsz <= CONFIG_MAX_NALU_SIZE) {
        memcpy(nalu_buf, &nalu_start_4bytecode, sizeof(nalu_start_4bytecode));
        int o = (int)sizeof(nalu_start_4bytecode);
        memcpy(nalu_buf + o, sp, nsz);
        o += nsz;
        if (rtp_decoder->on_packet != NULL) {
          rtp_decoder->on_packet(nalu_buf, o, rtp_decoder->user_data);
        }
      }
      sp += nsz; srem -= nsz;
    }
    *offset = 0;  /* aggregated NALs are complete; keep FU-A reassembly clean */
  } else if (nalu_type == FU_A) {
    if (payload_size < (int)(sizeof(NaluHeader) + sizeof(FuHeader))) {
      // Not enough payload to hold the FU indicator + FU header (2 bytes) —
      // never a legitimate FU-A packet. Without this guard the subtraction
      // below goes negative and the resulting (size_t)-cast length in the
      // memcpy below wraps to a huge value.
      return 0;
    }
    NaluHeader* fu_indicator = (NaluHeader*)rtp_packet->payload;
    FuHeader* fu_header = (FuHeader*)(rtp_packet->payload + sizeof(NaluHeader));
    uint8_t reconstructed_nalu_type = (fu_indicator->f << 7) |
                                      (fu_indicator->nri << 5) |
                                      fu_header->type;
    payload_size -= sizeof(NaluHeader) + sizeof(FuHeader);
    if (fu_header->s) {
      if ((int)sizeof(nalu_start_4bytecode) + 1 + payload_size <= CONFIG_MAX_NALU_SIZE) {
        // Mirror the continuation branch's CONFIG_MAX_NALU_SIZE bound: a
        // start fragment writes 4 (start code) + 1 (reconstructed NAL
        // header) + payload_size bytes into nalu_buf from offset 0, and
        // without this check that write was completely unbounded.
        memcpy(nalu_buf, &nalu_start_4bytecode, sizeof(nalu_start_4bytecode));
        *offset = sizeof(nalu_start_4bytecode);
        memcpy(nalu_buf + *offset, &reconstructed_nalu_type, 1);
        *offset += 1;
        memcpy(nalu_buf + *offset, rtp_packet->payload + 2, payload_size);
        *offset += payload_size;
      } else {
        LOGW("rtp h264: FU-A start fragment exceeds CONFIG_MAX_NALU_SIZE (%d B); dropping (%d B)",
             CONFIG_MAX_NALU_SIZE, (int)payload_size);
        *offset = 0;
      }
    } else if (*offset > 0 && *offset + payload_size <= CONFIG_MAX_NALU_SIZE) {
      memcpy(nalu_buf + *offset, rtp_packet->payload + 2, payload_size);
      *offset += payload_size;
      if (fu_header->e) {
        // end of fragmented NALU
        if (rtp_decoder->on_packet != NULL) {
          rtp_decoder->on_packet(nalu_buf, *offset, rtp_decoder->user_data);
        }
        *offset = 0;  // reset for next NALU
      }
    } else if (*offset > 0) {
      // Appending would overrun nalu_buf: this fragmented NALU is larger than
      // CONFIG_MAX_NALU_SIZE. Drop the WHOLE NALU (never emit a truncated one —
      // the decoder rejects it anyway) and resync on the next start fragment.
      // Loud on purpose: a recurring hit means CONFIG_MAX_NALU_SIZE is too small.
      LOGW("rtp h264: fragmented NALU exceeds CONFIG_MAX_NALU_SIZE (%d B); dropping (had %d B + %d)",
           CONFIG_MAX_NALU_SIZE, *offset, (int)payload_size);
      *offset = 0;
    }
  }
  return 0;
}

/* The payload of a received packet: past the CSRC list and the header-extension block
 * (a browser sets X once transport-cc is negotiated) and short of RTP padding. False for a
 * packet whose header claims more than it carries. */
static int rtp_payload_span(const uint8_t* buf, size_t size, size_t* off, size_t* len) {
  if (size < sizeof(RtpHeader)) return 0;
  const RtpHeader* h = (const RtpHeader*)buf;
  size_t o = sizeof(RtpHeader) + 4u * h->csrccount;
  if (h->extension) {
    if (size < o + 4) return 0;
    o += 4 + 4u * (((size_t)buf[o + 2] << 8) | buf[o + 3]);
  }
  size_t end = size;
  if (h->padding) {
    size_t pad = buf[size - 1];
    if (pad == 0 || pad > end) return 0;
    end -= pad;
  }
  if (o > end) return 0;
  *off = o;
  *len = end - o;
  return 1;
}

static int rtp_decode_generic(RtpDecoder* rtp_decoder, uint8_t* buf, size_t size) {
  size_t off, len;
  if (!rtp_payload_span(buf, size, &off, &len)) return (int)size;
  if (rtp_decoder->on_packet != NULL && len > 0)
    rtp_decoder->on_packet(buf + off, len, rtp_decoder->user_data);
  // even if there is no callback set, assume everything is ok for caller and do not return an error
  return (int)size;
}

void rtp_decoder_init(RtpDecoder* rtp_decoder, MediaCodec codec, RtpOnPacket on_packet, void* user_data) {
  rtp_decoder->on_packet = on_packet;
  rtp_decoder->user_data = user_data;
  rtp_decoder->nalu_buf = NULL;
  rtp_decoder->nalu_offset = 0;

  switch (codec) {
    case CODEC_H264:
      rtp_decoder->decode_func = rtp_decode_h264;
      /* Allocate per-decoder H.264 FU-A reassembly buffer. */
      rtp_decoder->nalu_buf = (uint8_t*)malloc(CONFIG_MAX_NALU_SIZE);
      /* On allocation failure nalu_buf stays NULL; rtp_decode_h264 guards it. */
      break;
    case CODEC_PCMA:
    case CODEC_PCMU:
    case CODEC_OPUS:
      rtp_decoder->decode_func = rtp_decode_generic;
    default:
      break;
  }
}

void rtp_decoder_deinit(RtpDecoder* rtp_decoder) {
  if (rtp_decoder->nalu_buf) {
    free(rtp_decoder->nalu_buf);
    rtp_decoder->nalu_buf = NULL;
  }
  rtp_decoder->nalu_offset = 0;
  rtp_decoder->decode_func = NULL;
  rtp_decoder->on_packet = NULL;
  rtp_decoder->user_data = NULL;
}

int rtp_decoder_decode(RtpDecoder* rtp_decoder, const uint8_t* buf, size_t size) {
  if (rtp_decoder->decode_func == NULL)
    return -1;
  return rtp_decoder->decode_func(rtp_decoder, (uint8_t*)buf, size);
}
