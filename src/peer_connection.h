/**
 * @file peer_connection.h
 * @brief Struct PeerConnection
 */
#ifndef PEER_CONNECTION_H_
#define PEER_CONNECTION_H_

#include <stdint.h>
#include <stdlib.h>

#include "pacer.h"
#include "pair_info.h"
#include "twcc.h"
#include "twcc_send.h"

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
  CODEC_H265,
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

  /* One received audio payload with its RTP timestamp and sequence number. */
  void (*onaudiotrack)(uint8_t* data, size_t size, uint32_t rtp_ts, uint16_t seq, void* userdata);
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

/* The pacer rate now in force (0 = pacing disabled). */
uint32_t peer_connection_pacer_bps(PeerConnection* pc);

/* 1 when the answer kept the playout-delay extension, else 0. Decided when the answer
 * is set; stays 0 before that. */
int peer_connection_playout_delay_negotiated(PeerConnection* pc);

/* Set the playout-delay the next frames carry: `min_ms`/`max_ms` (rtp.h encoding) and
 * whether packets of the NEXT peer_connection_send_video frame carry the extension.
 * Call on the lane's send worker immediately before peer_connection_send_video; the
 * extension is written only when negotiated. */
void peer_connection_set_playout_delay(PeerConnection* pc, uint32_t min_ms, uint32_t max_ms, int include);

/* The caller's send queue behind the access unit being sent: its bytes and how long its
 * oldest entry has waited. Called by the pacer on the send path, once per video packet. */
typedef void (*peer_backlog_fn)(void* ctx, uint64_t* bytes, uint64_t* oldest_wait_ns);

/* The pacer counts this backlog in its queue-time rule (pacer.h). NULL clears it. */
void peer_connection_set_send_backlog(PeerConnection* pc, peer_backlog_fn fn, void* ctx);

const char* peer_connection_state_to_string(PeerConnectionState state);

PeerConnectionState peer_connection_get_state(PeerConnection* pc);

/* Milliseconds since the last STUN proof of liveness from the peer (RFC 7675):
 * an inbound binding request or a response to one of our consent checks;
 * UINT64_MAX if none. A live peer refreshes it continuously; a dead peer
 * stops. For higher-level idle watchdogs. */
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
/* Why a connection reached PEER_CONNECTION_FAILED. Only ever set on the
 * transition into FAILED; NONE for a connection that has not failed. */
typedef enum {
  PEER_ICE_FAILURE_NONE = 0,
  PEER_ICE_FAILURE_NO_PAIRS,       /* remote candidate set complete, zero pairs
                                    * could be formed (every remote candidate
                                    * unresolvable or address-family-mismatched) */
  PEER_ICE_FAILURE_CHECKS_FAILED,  /* pairs existed; every connectivity check
                                    * failed after the remote set was complete  */
  PEER_ICE_FAILURE_DTLS,           /* ICE selected a pair; the DTLS handshake
                                    * on it failed                               */
} PeerIceFailure;

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
  uint32_t mdns_timed_out;        /* remote .local candidate(s) whose resolve gave
                                   * up this attempt — the mDNS timeouts that
                                   * actually happened, not an inference from
                                   * resolved==0.                               */
  uint32_t mdns_pending;          /* remote .local candidate(s) still resolving at
                                   * the moment of the snapshot                  */
  int      remote_end_of_candidates; /* the remote signalled its candidate set is
                                   * complete (SDP attribute or trickle message) */
  uint32_t candidate_pairs;       /* pairs in the check list right now; one per
                                   * (local, remote), so a remote that arrived
                                   * both trickled and in the answer counts once */
  PeerIceFailure ice_failure;     /* why FAILED was reached; NONE if it was not  */
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
 * reproduce the lost-final-flight wedge in e2e (count>=2 also drops the
 * reactive resend). Driven by the SDK's "drop_dtls_flight"
 * MQTT control action (SDK_LOCAL_TEST_DRIVER only) — never called on a real
 * device. */
void peer_connection_test_arm_flight_drop(int count);

/* Test-only: drop the next `count` inbound ClientHello fragments carrying
 * offset 0, leaving the peer's hello to arrive tail-first with its head
 * missing. Wired to the "drop_clienthello_head" MQTT control action; never
 * called on a real device. */
void peer_connection_test_arm_clienthello_drop(int count);

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
 *   frames on the same SSRC does: a frame captured earlier than the last one sent
 *   on this pc is rebased (rtp_video_clock_map), so the RTP timestamp,
 *   abs-capture-time and RTCP SR never step back.
 *
 *   `queue_limit_ns` is the pacer queue limit (pacer.h) this access unit is paced
 *   against: PACER_QUEUE_LIMIT_NS, or a shorter limit for an access unit that must
 *   leave on its own (pacer_video_queue). It applies to this frame's media packets only.
 */
int peer_connection_send_video(PeerConnection* pc, const uint8_t* packet, size_t bytes, uint64_t capture_time_ns, uint64_t queue_limit_ns);

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
 * @brief register callback for transport-wide congestion control feedback.
 *        Every RTCP RTPFB FMT 15 from the browser is parsed into one array of
 *        per-packet arrivals (sequence, received flag, receiver-clock arrival
 *        time in microseconds, unwrapped). The estimator joins them with the
 *        records drained by peer_connection_drain_sent(). Runs on the thread
 *        that drives peer_connection_loop(); `arrivals` is valid only for the
 *        duration of the call. Fires only on connections where
 *        peer_connection_transport_cc_negotiated() is 1.
 */
void peer_connection_on_transport_feedback(PeerConnection* pc,
                                           void (*on_transport_feedback)(const twcc_arrival* arrivals, size_t count, void* userdata));

/* 1 when the answer kept the transport-cc extension and feedback request, 0
 * when this connection has no sender-side estimator. Decided when the answer is
 * set; stays 0 before that. */
int peer_connection_transport_cc_negotiated(PeerConnection* pc);

/* Probe-send failures (negative return of peer_connection_send_probe). */
#define PEER_PROBE_ERR_ARGS (-1)
#define PEER_PROBE_ERR_NO_TRANSPORT_CC (-2)
#define PEER_PROBE_ERR_NOT_CONNECTED (-3)
#define PEER_PROBE_ERR_UNSUPPORTED (-4) /* FEC on and no RTX: padding on the video SSRC would corrupt FEC groups */
#define PEER_PROBE_ERR_THREAD (-6)

/**
 * @brief queue a probe cluster (libwebrtc BitrateProber semantics). One
 *        cluster is active at a time per connection, in request order. While it
 *        is active every packet sent on the connection, media and padding, is
 *        tagged with `cluster_id` in its sent record. Padding-only RTP (padding
 *        bit, 255 padding bytes; RTX SSRC when RTX was negotiated, else the
 *        video SSRC) fills only the gap between the bytes already sent in the
 *        cluster (media included) and `bps`. The cluster ends when
 *        `min_bytes`, `min_packets` (packets of any kind, media included) and
 *        `min_duration_ms` are all met. A request is never refused: when more
 *        than TWCC_PROBE_MAX_PENDING clusters are pending the oldest queued
 *        ones are dropped, and one not started within TWCC_PROBE_TIMEOUT_US
 *        expires; each is reported by peer_connection_drain_probe_events().
 *        Returns at once: a
 *        per-connection thread paces and sends outside send_mtx, so the caller
 *        never waits on a pace. Returns 0 when queued, else a PEER_PROBE_ERR_*.
 */
int peer_connection_send_probe(PeerConnection* pc, uint16_t cluster_id, uint32_t bps, uint32_t min_bytes, uint32_t min_packets, uint32_t min_duration_ms);

/**
 * @brief move up to `cap` probe-cluster events into `out`, oldest first: every
 *        cluster that was dropped from the queue, expired, or cancelled (the
 *        connection was not up). The estimator closes such a cluster as
 *        not-sent instead of timing it out as a failed probe. Pollable from the
 *        reactor; takes send_mtx briefly. Returns 0 on a connection without
 *        transport-cc.
 */
size_t peer_connection_drain_probe_events(PeerConnection* pc, twcc_probe_event* out, size_t cap);

/**
 * @brief move up to `cap` sent-packet records into `out`, oldest first. One
 *        record per RTP packet stamped with a transport-wide sequence number
 *        (video, audio, RTX, FEC, padding), appended under the send lock at the
 *        stamping point. The ring holds TWCC_SENT_RING_CAP records; records
 *        overwritten before they were drained are counted in
 *        peer_connection_sent_dropped(). Returns 0 records on a connection
 *        without transport-cc. Takes send_mtx briefly.
 */
size_t peer_connection_drain_sent(PeerConnection* pc, twcc_sent_record* out, size_t cap);

/* Sent records overwritten before they were drained, since negotiation. */
uint64_t peer_connection_sent_dropped(PeerConnection* pc);

/**
 * @brief the latest round-trip time, measured from the peer's receiver reports:
 *        a report block for the video SSRC names (LSR) one of our Sender
 *        Reports, and the time since that SR left, minus the peer's hold time
 *        (DLSR), is the round trip. Returns 0 and sets *out_ms (rounded up, at
 *        least 1) once a sample exists; -1 before the first sample. A report
 *        with LSR=0 (the peer has received no SR yet) gives no sample.
 *        Callable from any thread.
 */
int peer_connection_rtt_ms(PeerConnection* pc, uint32_t* out_ms);

/**
 * @brief the ICE pair this connection sends on (the agent's nominated pair).
 *        Returns 0 and fills `out` (valid=1) once a pair has succeeded, else
 *        -1 with out->valid=0.
 */
int peer_connection_selected_pair(PeerConnection* pc, peer_pair_info* out);

/* A counter that advances each time the pair in use changes (first selection
 * included). Call from one thread (the reactor), once per tick. */
uint32_t peer_connection_pair_generation(PeerConnection* pc);

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
