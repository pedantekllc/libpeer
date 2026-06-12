/**
 * @file peer_connection.h
 * @brief Struct PeerConnection
 */
#ifndef PEER_CONNECTION_H_
#define PEER_CONNECTION_H_

#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum SdpType {
  SDP_TYPE_OFFER = 0,
  SDP_TYPE_ANSWER,
} SdpType;

typedef enum PeerConnectionState {

  PEER_CONNECTION_CLOSED = 0,
  PEER_CONNECTION_NEW,
  PEER_CONNECTION_CHECKING,
  PEER_CONNECTION_CONNECTED,
  PEER_CONNECTION_COMPLETED,
  PEER_CONNECTION_FAILED,
  PEER_CONNECTION_DISCONNECTED,

} PeerConnectionState;

typedef enum DataChannelType {

  DATA_CHANNEL_NONE = 0,
  DATA_CHANNEL_STRING,
  DATA_CHANNEL_BINARY,

} DataChannelType;

typedef enum DecpChannelType {
  DATA_CHANNEL_RELIABLE = 0x00,
  DATA_CHANNEL_RELIABLE_UNORDERED = 0x80,
  DATA_CHANNEL_PARTIAL_RELIABLE_REXMIT = 0x01,
  DATA_CHANNEL_PARTIAL_RELIABLE_REXMIT_UNORDERED = 0x81,
  DATA_CHANNEL_PARTIAL_RELIABLE_TIMED = 0x02,
  DATA_CHANNEL_PARTIAL_RELIABLE_TIMED_UNORDERED = 0x82,
} DecpChannelType;

typedef enum MediaCodec {

  CODEC_NONE = 0,

  /* Video */
  CODEC_H264,
  CODEC_VP8,    // not implemented yet
  CODEC_MJPEG,  // not implemented yet

  /* Audio */
  CODEC_OPUS,  // not implemented yet
  CODEC_PCMA,
  CODEC_PCMU,

} MediaCodec;

typedef struct IceServer {
  const char* urls;
  const char* username;
  const char* credential;

} IceServer;

typedef struct PeerConfiguration {
  IceServer ice_servers[5];

  MediaCodec audio_codec;
  MediaCodec video_codec;
  DataChannelType datachannel;

  void (*onaudiotrack)(uint8_t* data, size_t size, void* userdata);
  void (*onvideotrack)(uint8_t* data, size_t size, void* userdata);
  void (*on_request_keyframe)(void* userdata);
  void* user_data;

  /* Optional: pin ICE to a single local interface (e.g. "eth0"). When set, the
   * host candidate is gathered from this interface's address AND the UDP
   * sockets are SO_BINDTODEVICE-bound to it, so both the advertised candidate
   * and the egress media leave on this NIC regardless of the routing table.
   * Empty string = legacy behaviour (CONFIG_IFACE_PREFIX / first interface).
   * 16 == IFNAMSIZ. */
  char bind_iface[16];

  /* Optional send pacer: cap the instantaneous outgoing RTP rate to this many
   * bits/sec by sleeping between packets at the send chokepoint (token bucket
   * with a small burst allowance). Without it, one large access unit (a 4K
   * keyframe = hundreds of packets) is blasted back-to-back at line rate and
   * overflows shallow downstream queues (Wi-Fi APs) — bursty loss that NACK
   * recovery then amplifies. Pace at a MULTIPLE of the stream rate (libwebrtc
   * uses ~2.5x): pacing smooths bursts, it must not throttle below the
   * encoder's output. 0 = disabled (legacy line-rate bursts).
   * Runtime updates via peer_connection_set_pacer_bps(). */
  uint32_t pacer_bps;

  /* Send-side forward error correction for video: ULPFEC (RFC 5109) over RED
   * (RFC 2198), the FEC all major browsers can receive. Media is RED-
   * encapsulated; one XOR repair packet is emitted per group of
   * FEC_GROUP_SIZE media packets (or at frame end), sharing the video SSRC
   * and sequence space. Repairs random single losses per group without RTX
   * round trips — this fork sends no retransmissions, so without FEC every
   * lost packet costs a PLI -> fresh keyframe. ~15-20%% bandwidth overhead
   * when enabled. 0 = off (default). */
  uint8_t fec;

} PeerConfiguration;

typedef struct PeerConnection PeerConnection;

/* Update the send pacer rate at runtime (0 = disable). Written by the
 * controller thread, read by the send path — a benign aligned-word race. */
void peer_connection_set_pacer_bps(PeerConnection* pc, uint32_t bps);

const char* peer_connection_state_to_string(PeerConnectionState state);

PeerConnectionState peer_connection_get_state(PeerConnection* pc);

void* peer_connection_get_sctp(PeerConnection* pc);

PeerConnection* peer_connection_create(PeerConfiguration* config);

void peer_connection_destroy(PeerConnection* pc);

void peer_connection_close(PeerConnection* pc);

int peer_connection_loop(PeerConnection* pc);

int peer_connection_create_datachannel(PeerConnection* pc, DecpChannelType channel_type, uint16_t priority, uint32_t reliability_parameter, char* label, char* protocol);

int peer_connection_create_datachannel_sid(PeerConnection* pc, DecpChannelType channel_type, uint16_t priority, uint32_t reliability_parameter, char* label, char* protocol, uint16_t sid);

/**
 * @brief send message to data channel
 * @param[in] peer connection
 * @param[in] message buffer
 * @param[in] length of message
 */
int peer_connection_datachannel_send(PeerConnection* pc, char* message, size_t len);

int peer_connection_datachannel_send_sid(PeerConnection* pc, char* message, size_t len, uint16_t sid);

/**
 * @brief Send binary data on the data channel (always PPID_BINARY regardless of config)
 *
 * @param[in] peer connection
 * @param[in] data buffer
 * @param[in] length of data
 */
int peer_connection_datachannel_send_binary(PeerConnection* pc, const uint8_t* data, size_t len);

int peer_connection_send_audio(PeerConnection* pc, const uint8_t* packet, size_t bytes);

/**
 * Send an H.264 access unit on the video transceiver.
 *
 * @param capture_time_ns  Monotonic nanoseconds at which this frame was
 *   captured / produced by the encoder pipeline. Used to derive the RTP
 *   timestamp at the receiver's 90kHz clock — drives playout pacing.
 *   See rtp_encoder_encode() doc for the full rationale.
 *
 *   Recommended sources, in preference order:
 *     1. A real capture-pipeline PTS converted to nanoseconds.
 *     2. clock_gettime(CLOCK_MONOTONIC) at the moment of encode.
 *     3. gettimeofday-derived ns (less robust to NTP jumps).
 *
 *   The absolute value doesn't matter to receivers; consistency across
 *   frames on the same SSRC does.
 */
int peer_connection_send_video(PeerConnection* pc, const uint8_t* packet, size_t bytes, uint64_t capture_time_ns);

/* Latest capture reference: the most recent frame's on-wire RTP timestamp and
 * its capture NTP (the same (RTP, NTP) pair the RTCP SR uses). Lets the app
 * publish a data-channel clock-map for browsers that can't read abs-capture-time
 * (Firefox). Returns 0 and fills the out-params, or -1 if no frame sent yet. */
int peer_connection_get_capture_ref(PeerConnection* pc, uint32_t* rtp, uint64_t* ntp);

void peer_connection_set_remote_description(PeerConnection* pc, const char* sdp, SdpType sdp_type);

void peer_connection_set_local_description(PeerConnection* pc, const char* sdp, SdpType sdp_type);

const char* peer_connection_create_offer(PeerConnection* pc);

const char* peer_connection_create_answer(PeerConnection* pc);

/**
 * @brief register callback function to handle packet loss from RTCP receiver report
 * @param[in] peer connection
 * @param[in] callback function void (*cb)(float fraction_loss, uint32_t total_loss, void *userdata)
 * @param[in] userdata for callback function
 */
void peer_connection_on_receiver_packet_loss(PeerConnection* pc,
                                             void (*on_receiver_packet_loss)(float fraction_loss, uint32_t total_loss, void* userdata));

/**
 * @brief register callback for the browser's REMB (goog-remb) bandwidth
 *        estimate, in bits/sec. Fires on each RTCP AFB (PT=206, fmt=15)
 *        carrying "REMB". Drives the send-rate controller (browser-side BWE).
 */
void peer_connection_on_remb(PeerConnection* pc,
                             void (*on_remb)(uint32_t bitrate_bps, void* userdata));

/**
 * @brief Set the callback function to handle onicecandidate event.
 * @param A PeerConnection.
 * @param A callback function to handle onicecandidate event.
 * @param A userdata which is pass to callback function.
 */
void peer_connection_onicecandidate(PeerConnection* pc, void (*onicecandidate)(char* sdp_text, void* userdata));

/**
 * @brief Set the callback function to handle oniceconnectionstatechange event.
 * @param A PeerConnection.
 * @param A callback function to handle oniceconnectionstatechange event.
 * @param A userdata which is pass to callback function.
 */
void peer_connection_oniceconnectionstatechange(PeerConnection* pc,
                                                void (*oniceconnectionstatechange)(PeerConnectionState state, void* userdata));

/**
 * @brief register callback function to handle event of datachannel
 * @param[in] peer connection
 * @param[in] callback function when message received
 * @param[in] callback function when connection is opened
 * @param[in] callback function when connection is closed
 */
void peer_connection_ondatachannel(PeerConnection* pc,
                                   void (*onmessage)(char* msg, size_t len, void* userdata, uint16_t sid),
                                   void (*onopen)(void* userdata),
                                   void (*onclose)(void* userdata));

int peer_connection_lookup_sid(PeerConnection* pc, const char* label, uint16_t* sid);

char* peer_connection_lookup_sid_label(PeerConnection* pc, uint16_t sid);

/**
 * @brief adds a new remote candidate to the peer connection
 * @param[in] peer connection
 * @param[in] ice candidate
 */
int peer_connection_add_ice_candidate(PeerConnection* pc, char* ice_candidate);

#ifdef __cplusplus
}
#endif

#endif  // PEER_CONNECTION_H_
