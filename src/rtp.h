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
  /* H.265 (RFC 7798) rides its own dynamic PT; a connection offers exactly
   * one video codec, so only one of PT_H264 / PT_H265 is ever on the wire. */
  PT_H265 = 98,
  PT_OPUS = 111,
  /* RED (RFC 2198) + ULPFEC (RFC 5109) — send-side FEC for video. Dynamic
   * PTs we offer in sdp_append_h264_fec(); the browser answers with the
   * offerer's numbers. Media rides inside RED; FEC packets share the SSRC
   * and sequence space. */
  PT_RED = 118,
  PT_ULPFEC = 119,
  /* RTX retransmissions (RFC 4588): separate SSRC (RTX_SSRC), own sequence
   * space, payload = 2-byte OSN + original payload. Offered as
   * "a=rtpmap:97 rtx/90000" + "a=fmtp:97 apt=<video PT>" + ssrc-group:FID. */
  PT_RTX = 97

} RtpPayloadType;

typedef enum RtpSsrc {

  SSRC_H264 = 1,
  SSRC_H265 = 1,
  SSRC_PCMA = 4,
  SSRC_PCMU = 5,
  SSRC_OPUS = 6,

} RtpSsrc;

/* RTP payload type a video codec is sent on, or -1 when `codec` is not a video
 * codec this encoder packetises. */
int rtp_video_pt(MediaCodec codec);

/* 1 when `pt` is the payload type of a codec rtp_video_pt() knows. */
int rtp_is_video_pt(int pt);

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
/* A received audio payload with the packet's RTP timestamp and sequence number (host
 * order), for a consumer that re-times the stream (a jitter buffer). */
typedef void (*RtpOnAudioPacket)(uint8_t* payload, size_t bytes, uint32_t rtp_ts, uint16_t seq,
                                 void* user_data);

struct RtpDecoder {
  RtpPayloadType type;
  RtpOnPacket on_packet;
  RtpOnAudioPacket on_audio_packet; /* generic (audio) payloads: wins over on_packet */
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
  /* Audio's wire seq. Video packets are re-numbered at the transmit tail
   * (peer_connection.c video_seq / out_seq), so this counter is only the
   * packetiser's placeholder there. */
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

/* RFC 8285 one-byte header-extension id for abs-capture-time. We are the
 * offerer, so this is the id we advertise in sdp.c and stamp on the first
 * outgoing video packet of each access unit. Keep in sync with the extmap
 * literals in sdp.c. */
#define RTP_EXT_ID_ABS_CAPTURE_TIME 4

/* RFC 8285 id and URI of the playout-delay extension (video only). The offer
 * carries the id; the answer's id is the one written (peer_connection reads it
 * back). Keep in sync with the extmap literals in sdp.c. */
#define RTP_EXT_ID_PLAYOUT_DELAY 6
#define RTP_PLAYOUT_DELAY_URI "http://www.webrtc.org/experiments/rtp-hdrext/playout-delay"
/* Largest value either field carries: 12 bits of 10 ms units. */
#define RTP_PLAYOUT_DELAY_MAX_MS (4095u * 10u)

/* The 3 data bytes of the playout-delay extension: 12-bit minimum then 12-bit
 * maximum, big-endian, in 10 ms units (rounded to nearest, clamped to
 * RTP_PLAYOUT_DELAY_MAX_MS; the maximum is raised to the minimum when below it). */
void rtp_playout_delay_encode(uint32_t min_ms, uint32_t max_ms, uint8_t out[3]);

/* Convert a CLOCK_REALTIME (or realtime-derived) nanosecond timestamp to a
 * 64-bit NTP timestamp (RFC 3550):
 *   high 32 bits = seconds since NTP epoch (1900-01-01), i.e. unix_sec + 2208988800
 *   low  32 bits = fractional seconds, units of 2^-32 s (= frac_ns * 2^32 / 1e9)
 * Used by abs-capture-time and RTCP Sender Reports.                              */
uint64_t unix_ns_to_ntp(uint64_t unix_ns);

/* Reset the header-extension state of an already-built RTP packet (12-byte
 * header + payload, CSRC=0) and, when `has_capture_time` is non-zero, insert a
 * one-byte RFC 8285 block holding abs-capture-time (id 4, 8 B; 16 bytes
 * inserted). Always rebuilds: the X bit is cleared first — see rtp.c for the
 * FU-A buffer-reuse rationale. Caller must guarantee >= 16 bytes headroom past
 * `size`. Returns the new packet length. */
size_t rtp_insert_extensions(uint8_t* data, size_t size, int has_capture_time, uint64_t capture_ntp);

/* rtp_insert_extensions plus the playout-delay element: when `pd_id` is non-zero
 * the 3 bytes of `pd` (rtp_playout_delay_encode) go into the same one-byte block
 * under that id. Up to 20 bytes are inserted, so the caller guarantees >= 20 bytes
 * headroom. With `pd_id` 0 this is rtp_insert_extensions. */
size_t rtp_insert_extensions_pd(uint8_t* data, size_t size, int has_capture_time, uint64_t capture_ntp, uint8_t pd_id,
                                const uint8_t pd[3]);

int rtp_packet_validate(uint8_t* packet, size_t size);

void rtp_encoder_init(RtpEncoder* rtp_encoder, MediaCodec codec, RtpOnPacket on_packet, void* user_data);

/**
 * Packetise and emit an access unit / audio packet.
 *
 * @param capture_time_ns  Frame capture time, CLOCK_REALTIME nanoseconds.
 *   - Video (H.264): set the RTP timestamp to capture_time_ns converted
 *     to the 90kHz RTP clock. Receivers play frames at the wall-clock
 *     pace dictated by these timestamps — drift between encoder rate
 *     and real time stays bounded at "one frame".
 *   - Audio (PCMA/PCMU/Opus): ignored. Audio timestamps auto-increment
 *     by samples-per-packet because the audio sample clock is the
 *     authoritative timebase. Caller may pass 0.
 *
 * The absolute value is part of the contract: a viewer matches overlay
 * messages to frames by computing (capture epoch ms * 90) mod 2^32 and
 * comparing it with the video RTP timestamp.
 */
int rtp_encoder_encode(RtpEncoder* rtp_encoder, const uint8_t* data, size_t size, uint64_t capture_time_ns);

/* RTP timestamp for a capture time in ns at clock_rate_hz, mod 2^32. */
uint32_t rtp_timestamp_from_ns(uint64_t capture_time_ns, uint32_t clock_rate_hz);

/* The capture clock one video stream (one SSRC) is sent on. */
typedef struct {
  int started;
  uint64_t last_ns;  /* the last frame's capture time on the wire clock */
  int64_t offset_ns; /* added to the caller's capture times (rebases a step back) */
} RtpVideoClock;

/* The capture time to send a frame with: `capture_time_ns` plus the clock's offset,
 * which grows whenever a frame's capture time is earlier than the previous frame's.
 * The frame is then sent one RTP tick after the previous one and the frames after it
 * keep their spacing, so the RTP timestamp, abs-capture-time and RTCP SR of a stream
 * never step back. */
uint64_t rtp_video_clock_map(RtpVideoClock* clock, uint64_t capture_time_ns);

void rtp_decoder_init(RtpDecoder* rtp_decoder, MediaCodec codec, RtpOnPacket on_packet, void* user_data);
void rtp_decoder_deinit(RtpDecoder* rtp_decoder);

int rtp_decoder_decode(RtpDecoder* rtp_decoder, const uint8_t* data, size_t size);

uint32_t rtp_get_ssrc(uint8_t* packet);

#endif  // RTP_H_
