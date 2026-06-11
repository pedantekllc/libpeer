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

size_t rtp_insert_extensions(uint8_t* data, size_t size, uint32_t ast24,
                             int has_capture_time, uint64_t capture_ntp) {
  /* Need a fixed 12-byte header present (CSRC=0 assumed throughout).
   *
   * We do NOT skip when the X bit is already set: the FU-A packetizer sets
   * extension=0 only ONCE before its fragment loop and reuses rtp_encoder->buf,
   * so once we set X on fragment 1 that bit persists into fragments 2..N.
   * Guarding on X there would send them with X=1 and NO extension (the FU
   * payload misread as an extension header → ~75% loss / undecodable frames).
   * The caller invokes this exactly once per packet from the single send
   * chokepoint, so always rebuild from a clean 12-byte-header assumption.   */
  if (size < 12)
    return size;

  const size_t hdr = 12;  /* CSRC=0, so payload starts at byte 12 */

  if (!has_capture_time) {
    /* ── single element: abs-send-time (id 3, 3 bytes) ────────────────────
     * Extension block layout (8 bytes):
     *   [0..1] 0xBEDE          profile
     *   [2..3] 0x0001          length = 1 word
     *   [4]    (3<<4)|2=0x32   id | (len-1)
     *   [5..7] ast24 BE        3-byte timestamp
     */
    memmove(data + hdr + 8, data + hdr, size - hdr);
    data[hdr + 0] = 0xBE;
    data[hdr + 1] = 0xDE;
    data[hdr + 2] = 0x00;
    data[hdr + 3] = 0x01;  /* 1 word */
    data[hdr + 4] = (uint8_t)((RTP_EXT_ID_ABS_SEND_TIME << 4) | 0x02);
    data[hdr + 5] = (uint8_t)((ast24 >> 16) & 0xFF);
    data[hdr + 6] = (uint8_t)((ast24 >> 8)  & 0xFF);
    data[hdr + 7] = (uint8_t)( ast24        & 0xFF);
    data[0] |= 0x10;
    return size + 8;
  }

  /* ── two elements: abs-send-time (id 3, 3 B) + abs-capture-time (id 4, 8 B)
   *
   * Element 1: 1 + 3 = 4 bytes   (id=3, len-1=2)
   * Element 2: 1 + 8 = 9 bytes   (id=4, len-1=7)
   * Total data: 13 bytes → pad to next multiple of 4 → 16 bytes = 4 words
   * Ext block total: 4 (profile+len) + 16 = 20 bytes, length field = 4 words
   *
   * Byte map:
   *   [0..1] 0xBEDE
   *   [2..3] 0x0004          length = 4 words (16-byte data region)
   *   [4]    0x32            id=3 | (len-1=2)
   *   [5..7] ast24 BE
   *   [8]    0x47            id=4 | (len-1=7)
   *   [9..12] capture_ntp high 32 bits BE
   *   [13..16] capture_ntp low 32 bits BE
   *   [17..19] 0x00 0x00 0x00  padding to word boundary
   */
  memmove(data + hdr + 20, data + hdr, size - hdr);
  data[hdr +  0] = 0xBE;
  data[hdr +  1] = 0xDE;
  data[hdr +  2] = 0x00;
  data[hdr +  3] = 0x04;  /* 4 words = 16-byte data region (13 bytes + 3 pad) */
  /* element 1: abs-send-time */
  data[hdr +  4] = (uint8_t)((RTP_EXT_ID_ABS_SEND_TIME << 4) | 0x02);
  data[hdr +  5] = (uint8_t)((ast24 >> 16) & 0xFF);
  data[hdr +  6] = (uint8_t)((ast24 >> 8)  & 0xFF);
  data[hdr +  7] = (uint8_t)( ast24        & 0xFF);
  /* element 2: abs-capture-time (8-byte NTP) */
  data[hdr +  8] = (uint8_t)((RTP_EXT_ID_ABS_CAPTURE_TIME << 4) | 0x07);
  data[hdr +  9] = (uint8_t)((capture_ntp >> 56) & 0xFF);
  data[hdr + 10] = (uint8_t)((capture_ntp >> 48) & 0xFF);
  data[hdr + 11] = (uint8_t)((capture_ntp >> 40) & 0xFF);
  data[hdr + 12] = (uint8_t)((capture_ntp >> 32) & 0xFF);
  data[hdr + 13] = (uint8_t)((capture_ntp >> 24) & 0xFF);
  data[hdr + 14] = (uint8_t)((capture_ntp >> 16) & 0xFF);
  data[hdr + 15] = (uint8_t)((capture_ntp >>  8) & 0xFF);
  data[hdr + 16] = (uint8_t)( capture_ntp        & 0xFF);
  /* 3 padding bytes to reach 16-byte data region (3 words) */
  data[hdr + 17] = 0x00;
  data[hdr + 18] = 0x00;
  data[hdr + 19] = 0x00;
  data[0] |= 0x10;
  return size + 20;
}

size_t rtp_insert_abs_send_time(uint8_t* data, size_t size, int ext_id, uint32_t ast24) {
  /* Legacy wrapper — ext_id is ignored (always uses RTP_EXT_ID_ABS_SEND_TIME = 3);
   * parameter kept for API stability.  Calls the multi-element writer with a single
   * element; see rtp_insert_extensions() for the FU-A / no-X-guard rationale.      */
  (void)ext_id;
  return rtp_insert_extensions(data, size, ast24, 0, 0);
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

static uint8_t* h264_find_nalu(uint8_t* buf_start, uint8_t* buf_end) {
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

  for (pstart = h264_find_nalu(buf, buf_end); pstart < buf_end && nalu_count < 64; pstart = pend) {
    pend = h264_find_nalu(pstart, buf_end);
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
  if (rtp_encoder->type == PT_H264) {
    /* (ns * rate) overflows uint64_t only past ~6 thousand years, fine. */
    rtp_encoder->timestamp = (uint32_t)((capture_time_ns * rtp_encoder->clock_rate_hz) / 1000000000ULL);
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
    NaluHeader* fu_indicator = (NaluHeader*)rtp_packet->payload;
    FuHeader* fu_header = (FuHeader*)(rtp_packet->payload + sizeof(NaluHeader));
    uint8_t reconstructed_nalu_type = (fu_indicator->f << 7) |
                                      (fu_indicator->nri << 5) |
                                      fu_header->type;
    payload_size -= sizeof(NaluHeader) + sizeof(FuHeader);
    if (fu_header->s) {
      memcpy(nalu_buf, &nalu_start_4bytecode, sizeof(nalu_start_4bytecode));
      *offset = sizeof(nalu_start_4bytecode);
      memcpy(nalu_buf + *offset, &reconstructed_nalu_type, 1);
      *offset += 1;
      memcpy(nalu_buf + *offset, rtp_packet->payload + 2, payload_size);
      *offset += payload_size;
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

static int rtp_decode_generic(RtpDecoder* rtp_decoder, uint8_t* buf, size_t size) {
  RtpPacket* rtp_packet = (RtpPacket*)buf;
  if (rtp_decoder->on_packet != NULL)
    rtp_decoder->on_packet(rtp_packet->payload, size - sizeof(RtpHeader), rtp_decoder->user_data);
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
