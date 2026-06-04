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
  PT_OPUS = 111

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

/* RFC 8285 one-byte header-extension id for abs-send-time. We are the offerer,
 * so this is the id we advertise in sdp.c (a=extmap:3 …abs-send-time) and stamp
 * on outgoing video RTP. Keep in sync with the literal in sdp_append_h264(). */
#define RTP_EXT_ID_ABS_SEND_TIME 3

/* Insert a one-byte RFC 8285 header extension carrying abs-send-time into an
 * already-built RTP packet (12-byte header + payload, contiguous, CSRC=0). Used
 * by the send path so the browser's REMB estimator sees per-packet send time.
 *
 * `ast24` is absolute send time in 6.18-fixed-point seconds, low 24 bits.
 * Shifts the payload right 8 bytes, writes [0xBE 0xDE][len=1][id|2][3B ast],
 * sets the X bit, and returns the NEW packet length. No-op (returns `size`
 * unchanged) if the packet is < 12 bytes or already has X set. Caller must
 * guarantee >= 8 bytes of headroom past `size` in the buffer.               */
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

int rtp_decoder_decode(RtpDecoder* rtp_decoder, const uint8_t* data, size_t size);

uint32_t rtp_get_ssrc(uint8_t* packet);

#endif  // RTP_H_
