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

  /* Optional: bind the media UDP socket to this specific port instead of an
   * OS-assigned ephemeral port.  0 = ephemeral (legacy).  Use this to pre-map
   * a fixed host port (e.g. -p 127.0.0.1:PORT:PORT/udp in Docker) that an
   * external viewer can reach. */
  uint16_t media_port;

  /* Optional extra host candidate to inject into the SDP offer/answer in
   * addition to the locally-detected host address.  Format: "IP:PORT" where
   * IP is the externally-reachable address (e.g. "127.0.0.1:PORT" on Docker
   * so the browser on the host reaches the container's mapped port).
   * Empty string = no extra candidate (legacy). */
  char host_candidate_override[64];

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

  /* RTX retransmissions (RFC 4588): keep a short history of sent video RTP
   * packets and answer the receiver's RTCP Generic NACKs with retransmits on
   * a dedicated SSRC/PT (negotiated via rtx/apt + ssrc-group:FID — both
   * Chrome and Firefox use it by default). Without it every lost packet
   * costs a PLI -> full keyframe. ~770KB history per peer when enabled.
   * 0 = off. */
  uint8_t rtx;

} PeerConfiguration;

typedef struct PeerConnection PeerConnection;

/* Update the send pacer rate at runtime (0 = disable). Written by the
 * controller thread, read by the send path — a benign aligned-word race. */
void peer_connection_set_pacer_bps(PeerConnection* pc, uint32_t bps);

const char* peer_connection_state_to_string(PeerConnectionState state);

PeerConnectionState peer_connection_get_state(PeerConnection* pc);

/* Milliseconds since the last inbound STUN binding request from the peer
 * (RFC 7675 liveness; UINT64_MAX if none). A live stream refreshes it
 * ~continuously via consent; a dead peer stops. For higher-level idle watchdogs. */
uint64_t peer_connection_get_last_stun_rx_age_ms(PeerConnection* pc);

/* Fill `buf` with a compact one-line session diagnostic (state, sctp-connected,
 * STUN-consent age, inbound packet tallies, selected ICE pair + bound iface).
 * Always-on; the caller (sigshell) logs it per-camera so a bug report shows why
 * a session wedged — e.g. inData=0 stunAgeMs huge = dead browser→device path. */
void peer_connection_get_session_diag(PeerConnection* pc, char* buf, size_t len);

/* Connection-attempt diagnostics for the Plane-A WebRTC KPI (see
 * docs/architecture/webrtc-connection-reliability.md). One PeerConnection is
 * one connection attempt (no ICE restart today), so these are naturally
 * per-attempt counters — cumulative for this pc's Agent, reset at
 * agent_clear_candidates() (agent_create + every fresh offer). */
typedef struct {
  uint32_t turn_alloc_ok;         /* TURN Allocate succeeded this attempt        */
  uint32_t turn_alloc_rejected;   /* TURN authenticated Allocate rejected        */
  uint32_t mdns_resolved;         /* remote .local candidate(s) resolved+paired  */
  uint32_t mdns_queued;           /* remote .local candidate(s) EVER queued for
                                   * async resolve this attempt (see agent.h's
                                   * mdns_queued) — Plane-B's "had a pending mDNS
                                   * candidate" signal, distinct from resolved.  */
  int      selected_remote_type;  /* IceCandidateType of the selected pair's
                                   * remote candidate (0=host,1=srflx,2=prflx,
                                   * 3=relay); -1 = no pair selected yet.        */
  uint32_t dtls_complete_ms;      /* wall-clock ms (ports_get_epoch_time domain,
                                   * same as PeerConnection.dtls_complete_ms) the
                                   * DTLS handshake finished this attempt; 0 = DTLS
                                   * never completed. For Plane-B's dtls_ms (paired
                                   * with the PC-creation wall-clock stamp the shell
                                   * keeps in the SAME domain — see sigshell_bind.c's
                                   * lane_side.created_epoch_ms). */
} PeerConnectionDiag;

/* Snapshot the above into `out`. Safe to call at any time (reads the live
 * Agent fields); the caller decides when the numbers are meaningful (e.g. once
 * per lane at CONNECTED, or once more at teardown for an unconnected lane). */
void peer_connection_get_diag(PeerConnection* pc, PeerConnectionDiag* out);

void* peer_connection_get_sctp(PeerConnection* pc);

/* Test-only: arm dropping the next `count` server DTLS final flights, to
 * reproduce the lost-final-flight wedge in e2e (count>=2 also forces the
 * proactive-retransmit recovery path). Driven by the SDK's "drop_dtls_flight"
 * MQTT control action (SDK_LOCAL_TEST_DRIVER only) — never called on a real
 * device. */
void peer_connection_test_arm_flight_drop(int count);

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
