#ifndef RTP_H_
#define RTP_H_

#include <stdint.h>

#ifdef __BYTE_ORDER
/* __BYTE_ORDER already defined, define the constants */
#define __BIG_ENDIAN 4321
#define __LITTLE_ENDIAN 1234
#elif defined(__APPLE__)
#include <machine/endian.h>
/* macOS uses BYTE_ORDER, not __BYTE_ORDER - map them */
#define __BYTE_ORDER BYTE_ORDER
#define __BIG_ENDIAN BIG_ENDIAN
#define __LITTLE_ENDIAN LITTLE_ENDIAN
#else
#include <endian.h>
#endif

#include "config.h"
#include "peer_connection.h"

typedef enum RtpPayloadType {

  PT_PCMU = 0,
  PT_PCMA = 8,
  PT_G722 = 9,
  PT_H264 = 96,
  PT_OPUS = 111,
  /* RED (RFC 2198) + ULPFEC (RFC 5109) — send-side FEC for video. Dynamic
   * PTs we offer in sdp_append_h264_fec(); the browser answers with the
   * offerer's numbers. Media rides inside RED; FEC packets share the SSRC
   * and sequence space. */
  PT_RED = 118,
  PT_ULPFEC = 119

} RtpPayloadType;

typedef enum RtpSsrc {

  SSRC_H264 = 1,
  SSRC_PCMA = 4,
  SSRC_PCMU = 5,
  SSRC_OPUS = 6,

} RtpSsrc;

typedef struct RtpHeader {
#if __BYTE_ORDER == __BIG_ENDIAN
  uint16_t version : 2;
  uint16_t padding : 1;
  uint16_t extension : 1;
  uint16_t csrccount : 4;
  uint16_t markerbit : 1;
  uint16_t type : 7;
#elif __BYTE_ORDER == __LITTLE_ENDIAN
  uint16_t csrccount : 4;
  uint16_t extension : 1;
  uint16_t padding : 1;
  uint16_t version : 2;
  uint16_t type : 7;
  uint16_t markerbit : 1;
#endif
  uint16_t seq_number;
  uint32_t timestamp;
  uint32_t ssrc;
  uint32_t csrc[0];

} RtpHeader;

typedef struct RtpPacket {
  RtpHeader header;
  uint8_t payload[0];

} RtpPacket;

typedef struct RtpMap {
  int pt_h264;
  int pt_opus;
  int pt_pcma;

} RtpMap;

typedef struct RtpEncoder RtpEncoder;
typedef struct RtpDecoder RtpDecoder;
typedef void (*RtpOnPacket)(uint8_t* packet, size_t bytes, void* user_data);

struct RtpDecoder {
  RtpPayloadType type;
  RtpOnPacket on_packet;
  int (*decode_func)(RtpDecoder* rtp_decoder, uint8_t* data, size_t size);
  void* user_data;
  /* Per-decoder H.264 FU-A reassembly state (replaces static locals in
   * rtp_decode_h264, which were not thread-safe when two RtpDecoder instances
   * were used concurrently — e.g. the libpeer WebRTC receive path and the
   * rtsp_source ingest thread).  Allocated in rtp_decoder_init(), freed in
   * rtp_decoder_deinit().                                                   */
  uint8_t* nalu_buf;   /* CONFIG_MAX_NALU_SIZE bytes */
  int      nalu_offset;
};

struct RtpEncoder {
  RtpPayloadType type;
  RtpOnPacket on_packet;
  int (*encode_func)(RtpEncoder* rtp_encoder, uint8_t* data, size_t size);
  void* user_data;
  uint16_t seq_number;
  uint32_t ssrc;
  uint32_t timestamp;
  /* Audio-only: how many RTP-clock ticks each packet represents
   * (e.g. PCMA 20ms → 160 ticks). Auto-applied in rtp_encoder_encode
   * for audio codecs. Unused for video, which gets its timestamp set
   * per call from the caller-provided capture time.                  */
  uint32_t timestamp_increment;
  /* RTP clock rate for this stream (90000 for video, sample-rate for
   * audio). Used to convert caller-provided capture_time_ns into RTP
   * ticks on the video path.                                         */
  uint32_t clock_rate_hz;
  uint8_t buf[CONFIG_MTU + 128];
};

/* RFC 8285 one-byte header-extension ids for abs-send-time and abs-capture-time.
 * We are the offerer, so these are the ids we advertise in sdp.c and stamp on
 * outgoing video RTP. Keep in sync with the extmap literals in sdp_append_h264(). */
#define RTP_EXT_ID_ABS_SEND_TIME    3
#define RTP_EXT_ID_ABS_CAPTURE_TIME 4

/* Convert a CLOCK_REALTIME (or realtime-derived) nanosecond timestamp to a
 * 64-bit NTP timestamp (RFC 3550):
 *   high 32 bits = seconds since NTP epoch (1900-01-01), i.e. unix_sec + 2208988800
 *   low  32 bits = fractional seconds, units of 2^-32 s (= frac_ns * 2^32 / 1e9)
 * Used by abs-capture-time and RTCP Sender Reports.                              */
uint64_t unix_ns_to_ntp(uint64_t unix_ns);

/* Insert a one-byte RFC 8285 header-extension block into an already-built RTP
 * packet (12-byte header + payload, CSRC=0).  Always rebuilds the extension —
 * see rtp.c for the FU-A buffer-reuse rationale.
 *
 * `has_capture_time`:  non-zero  → emit abs-send-time (id 3, 3 B) + abs-capture-
 *   time (id 4, 8 B) in a single 0xBEDE block (20 bytes total inserted).
 *                      zero      → emit abs-send-time only (8 bytes total inserted).
 * `ast24`            : abs-send-time value (6.18 fixed-point, low 24 bits).
 * `capture_ntp`      : 64-bit NTP capture time (only used when has_capture_time!=0).
 * Caller must guarantee >= 20 bytes headroom past `size` in the buffer.
 * Returns the new packet length.                                                    */
size_t rtp_insert_extensions(uint8_t* data, size_t size, uint32_t ast24,
                             int has_capture_time, uint64_t capture_ntp);

/* Legacy single-element wrapper — kept for back-compat; calls rtp_insert_extensions
 * with has_capture_time=0.  Caller must guarantee >= 8 bytes headroom.             */
size_t rtp_insert_abs_send_time(uint8_t* data, size_t size, int ext_id, uint32_t ast24);

int rtp_packet_validate(uint8_t* packet, size_t size);

void rtp_encoder_init(RtpEncoder* rtp_encoder, MediaCodec codec, RtpOnPacket on_packet, void* user_data);

/**
 * Packetise and emit an access unit / audio packet.
 *
 * @param capture_time_ns  Monotonic capture timestamp in nanoseconds.
 *   - Video (H.264): set the RTP timestamp to capture_time_ns converted
 *     to the 90kHz RTP clock. Receivers play frames at the wall-clock
 *     pace dictated by these timestamps — drift between encoder rate
 *     and real time stays bounded at "one frame".
 *   - Audio (PCMA/PCMU/Opus): ignored. Audio timestamps auto-increment
 *     by samples-per-packet because the audio sample clock is the
 *     authoritative timebase. Caller may pass 0.
 *
 * Absolute value doesn't matter to receivers; only deltas within an
 * SSRC do, so any consistent monotonic source works (CLOCK_MONOTONIC,
 * gettimeofday, capture pipeline PTS converted to ns, …).
 */
int rtp_encoder_encode(RtpEncoder* rtp_encoder, const uint8_t* data, size_t size, uint64_t capture_time_ns);

void rtp_decoder_init(RtpDecoder* rtp_decoder, MediaCodec codec, RtpOnPacket on_packet, void* user_data);
void rtp_decoder_deinit(RtpDecoder* rtp_decoder);

int rtp_decoder_decode(RtpDecoder* rtp_decoder, const uint8_t* data, size_t size);

uint32_t rtp_get_ssrc(uint8_t* packet);

#endif  // RTP_H_
