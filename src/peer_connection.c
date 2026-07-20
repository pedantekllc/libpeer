#include <arpa/inet.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "agent.h"
#include "config.h"
#include "dtls_srtp.h"
#include "peer_connection.h"
#include "ports.h"
#include "rtcp.h"
#include "rtp.h"
#include "sctp.h"
#include "sdp.h"
#include "utils.h"

#define STATE_CHANGED(pc, curr_state)                                 \
  if (pc->oniceconnectionstatechange && pc->state != curr_state) {    \
    pc->oniceconnectionstatechange(curr_state, pc->config.user_data); \
    pc->state = curr_state;                                           \
  }

/* RTCP SR interval: 1 second (ms).  Shorter than the RFC 5 s default so
 * Chrome's RTP↔NTP estimator converges fast and captureTime is populated
 * within the first couple of seconds of a stream.                        */
#define RTCP_SR_INTERVAL_MS 1000

/* TEMP INSTRUMENT (pc.loop phase decomposition): a bug report captured a
 * single peer_connection_loop() iteration taking dur_ms=16497 for one
 * connected peer (see the "slow pc.loop" warn in sigshell.c, which already
 * times the loop() call as a whole but not its internals). This threshold
 * gates a one-line-per-slow-iteration breakdown of WHERE inside the
 * PEER_CONNECTION_COMPLETED case the time went (recv drain / DTLS resend /
 * RTCP-in incl. NACK-driven RTX / DTLS-read drain / RTP-in / periodic RTCP SR
 * send_mtx-wait vs. encrypt+send) — see the LOGI at the end of that case.
 * Matches sigshell.c's SLOW_PC_LOOP_THRESHOLD_MS so both logs fire together.
 * Remove once the multi-second tail is found. */
#define PC_LOOP_SLOW_MS 50

/* Forward declaration for fragment state */
typedef struct dtls_fragment_state_s dtls_fragment_state_t;

/* ── RTX retransmission machinery (RFC 4588) ──────────────────────────────── */

#define RTX_SSRC          2u     /* media is a=ssrc:1; FID-paired in the SDP  */
#define RTX_HISTORY_SLOTS 512    /* ~0.5-2.5s of video at typical rates       */
#define RTX_SLOT_BYTES    (CONFIG_MTU + 128)
/* Don't answer repeat-NACKs for the same seq more often than this. */
#define RTX_MIN_RESEND_MS 40

typedef struct {
  uint16_t seq;            /* media seq stored here (slot = seq % SLOTS)      */
  uint16_t len;            /* 0 = empty                                       */
  uint32_t last_resend_ms; /* monotonic ms of last retransmit of this seq     */
  uint8_t  data[RTX_SLOT_BYTES];   /* final pre-SRTP media packet             */
} rtx_slot_t;


struct PeerConnection {
  PeerConfiguration config;
  PeerConnectionState state;
  Agent agent;
  DtlsSrtp dtls_srtp;
  Sctp sctp;

  char sdp[CONFIG_SDP_BUFFER_SIZE];

  void (*onicecandidate)(char* sdp, void* user_data);
  void (*oniceconnectionstatechange)(PeerConnectionState state, void* user_data);
  void (*on_connected)(void* userdata);
  void (*on_receiver_packet_loss)(float fraction_loss, uint32_t total_loss, void* user_data);
  void (*on_remb)(uint32_t bitrate_bps, void* user_data);

  uint8_t temp_buf[CONFIG_MTU];
  uint8_t agent_buf[CONFIG_MTU];
  int agent_ret;
  int b_local_description_created;

  RtpEncoder artp_encoder;
  RtpEncoder vrtp_encoder;
  RtpDecoder vrtp_decoder;
  RtpDecoder artp_decoder;

  uint32_t remote_assrc;
  uint32_t remote_vssrc;

  /* Per-connection DTLS fragment reassembly state */
  dtls_fragment_state_t* frag_state;

  /* ── Orphan / half-open peer visibility (bug-report diagnostic) ──────────
   * A peer whose DTLS handshake completed but whose SCTP association never
   * comes up (browser refreshed away mid-handshake; the datachannel INIT it
   * sent us was lost or it vanished before replying) sits here retransmitting
   * its last DTLS flight forever unless something reaps it. dtls_complete_ms
   * is the wall-clock stamp (ports_get_epoch_time — same clock as last_sr_ms
   * above) taken the moment DTLS finishes; sctp_retransmit_count counts every
   * "peer retransmitting flight post-complete" event (see PEER_CONNECTION_
   * COMPLETED below) WITHOUT adding a log line per retransmit (that would
   * reintroduce the per-iteration spam already removed elsewhere).
   * half_open_logged latches so the "stuck half-open" LOGI fires exactly ONCE
   * per peer, the first time it's been stuck >3s, so a bug report can see
   * orphans accumulating at a low, readable count across a few browser
   * refreshes instead of a flood. */
  uint32_t dtls_complete_ms;
  uint32_t sctp_retransmit_count;
  int      b_half_open_logged;   /* 0/1; matches b_local_description_created style */

  /* Gates the "Starting DTLS handshake" LOGI in PEER_CONNECTION_CONNECTED to
   * fire exactly once per handshake attempt. That case is now step-wise (see
   * dtls_srtp_handshake / DTLS_SRTP_HS_WANT) and stays CONNECTED across many
   * peer_connection_loop() ticks while a handshake is in progress, so without
   * this guard the line would repeat every tick (~75 Hz) for the whole
   * handshake instead of once. Reset to 0 on every fresh CHECKING->CONNECTED
   * transition (a new handshake attempt) below. */
  int      b_dtls_handshake_logged;

  /* ── Glass-to-glass latency: abs-capture-time + RTCP SR ───────────────── */

  /* NTP capture time of the current video frame, stashed in send_video() and
   * read by the send chokepoint for the frame's first packet.               */
  uint64_t cur_frame_capture_ntp;

  /* Last RTP timestamp seen at the send chokepoint.  A change from the
   * previous value marks the first packet of a new access unit.            */
  uint32_t last_rtp_ts;

  /* RTCP SR counters — cumulative across the connection lifetime.           */
  uint32_t sr_packets_sent;  /* RTP packets sent for video SSRC */
  uint32_t sr_octets_sent;   /* RTP payload octets sent (wraps at 2^32) */

  /* Wall-clock ms of the last SR send (from ports_get_epoch_time()).        */
  uint32_t last_sr_ms;

  /* ── Send pacer (see PeerConfiguration.pacer_bps) ─────────────────────────
   * Token bucket drained at the send chokepoint. All state below is touched
   * ONLY on the send path's thread (per-lane send worker); pacer_bps itself
   * is also written by the controller thread via the setter (benign aligned-
   * word race). */
  uint32_t pacer_bps;             /* 0 = pacing disabled                      */
  double pacer_budget_bytes;      /* current bucket level (may go negative)   */
  struct timespec pacer_last;     /* last refill time (CLOCK_MONOTONIC)       */

  /* ── ULPFEC/RED send state (see PeerConfiguration.fec) ────────────────────
   * All touched only on the send path (per-lane send worker). The chokepoint
   * owns the outgoing sequence space when FEC is on (media + FEC interleave
   * on one SSRC), so it re-stamps every header from out_seq. */
  uint16_t out_seq;
  int      fec_group_cnt;            /* media packets in the open group      */
  uint16_t fec_snbase;               /* seq of the group's first packet      */
  size_t   fec_maxlen;               /* protection length = max(len - 12)    */
  uint8_t  fec_hdr_xor[2];           /* XOR: byte0&0x3F (P|X|CC), byte1 (M|PT)*/
  uint8_t  fec_ts_xor[4];            /* XOR of media timestamps              */
  uint16_t fec_len_xor;              /* XOR of media payload lengths         */
  uint8_t  fec_last_hdr[12];         /* last media fixed header (TS/SSRC src)*/
  uint8_t  fec_xor[CONFIG_MTU + 128];/* XOR of media bytes [12..]            */

  /* ── RTX retransmission state (see PeerConfiguration.rtx) ─────────────────
   * History is WRITTEN by the send path (per-lane send worker, at the
   * chokepoint) and READ by the NACK handler (reactor thread, inside
   * incoming_rtcp) — guarded by rtx_mtx. */
  rtx_slot_t* rtx_history;           /* RTX_HISTORY_SLOTS slots; NULL = off  */
  pthread_mutex_t rtx_mtx;
  uint16_t rtx_seq;                  /* RTX stream's own sequence space      */

  /* Serialises every srtp_protect/_rtcp + agent_send on this connection.
   * libsrtp sessions are NOT thread-safe, and three threads transmit: the
   * per-lane send worker (media), the reactor (RTX retransmits + RTCP SR).
   * Unguarded concurrency here corrupts the SRTP stream state — observed as
   * a SIGSEGV on the gateway under Wi-Fi NACK storms. The pacer sleep stays
   * OUTSIDE this lock so the reactor never waits on a pace. */
  pthread_mutex_t send_mtx;

  /* Per-peer inbound tallies at the agent layer (see peer_connection_get_session_diag).
   * data = DTLS/RTP/RTCP packets (agent_recv>0); stun = STUN handled internally
   * (agent_recv==0). A wedged peer with data=0 stun=0 receives NOTHING (dead
   * browser→device path); stun>0 data=0 = the path carries STUN but not media. */
  uint32_t in_data_pkts;
  uint32_t in_stun_pkts;
  uint32_t sctp_nc_logs;   /* rate-limit counter for the "sctp not connected" flood */

  /* SR reference pair, refreshed every frame in send_video: the most recent
   * frame's ON-WIRE RTP timestamp and its capture NTP. The Sender Report uses
   * THIS pair (not an independently-sampled clock) so its RTP↔NTP mapping is in
   * the same timebase as the RTP timestamps the receiver actually sees and
   * consistent with abs-capture-time — required when the capture clock isn't
   * CLOCK_MONOTONIC (e.g. the emulator's synthetic frame clock).            */
  uint32_t sr_ref_rtp;
  uint64_t sr_ref_ntp;
};

/* Absolute send time in 6.18-fixed-point seconds, low 24 bits (RFC abs-send-
 * time). Monotonic source: only inter-packet DELTAS matter to the receiver's
 * delay-gradient estimator, and the 24-bit field wraps ~64s (handled by the
 * estimator). No wall-clock / NTP needed for the BWE path. */
static uint32_t peer_connection_abs_send_time_24(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  uint64_t secs = (uint64_t)ts.tv_sec;
  uint64_t frac = ((uint64_t)ts.tv_nsec << 18) / 1000000000ULL;  /* < 2^18 */
  return (uint32_t)(((secs << 18) + frac) & 0x00FFFFFFULL);
}

static uint32_t rtx_now_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint32_t)((uint64_t)ts.tv_sec * 1000ull + ts.tv_nsec / 1000000ull);
}

/* Payload offset = fixed header + extension block (CSRC always 0 here). */
static size_t rtp_payload_offset(const uint8_t* data, size_t size) {
  size_t hdr = 12;
  if (size >= 16 && (data[0] & 0x10)) {
    uint16_t words = (uint16_t)((data[hdr + 2] << 8) | data[hdr + 3]);
    hdr += 4 + 4u * words;
  }
  return hdr <= size ? hdr : size;
}

/* Burst allowance: a dozen MTUs may leave back-to-back before pacing kicks in,
 * so small frames (P-frames of a few packets) are never delayed at all. */
#define PACER_BURST_BYTES 16384.0
/* Per-packet sleep cap — guards against a pathological/zeroed rate stalling a
 * send worker for seconds. 50 ms at 1300 B implies a ~200 kbps floor. */
#define PACER_MAX_SLEEP_S 0.05

/*
 * Token-bucket send pacer. Refill at pacer_bps, spend per packet; when the
 * bucket goes negative, sleep until it would be level again. Runs on the
 * per-lane send worker, so a sleep delays only THIS peer's packets (the frame
 * thread already handed the access unit off via the lane ring).
 */
/* TEMP INSTRUMENT (send_ms decomposition): per-send-worker-thread accumulators.
 * xmit_rtp runs synchronously inside send_video on the lane's send worker, so
 * __thread isolates each lane. send_video resets them, xmit_rtp accumulates the
 * three segments (pacer sleep / send_mtx acquire wait / locked encrypt+send),
 * send_video logs the split when a send is slow. Tells us where a 100ms send
 * goes: pace, mutex contention, or the socket. Remove once the tail is fixed. */
static __thread uint64_t sb_pace_ns, sb_lockwait_ns, sb_srtp_ns, sb_send_ns;
static __thread int      sb_pkts;
static inline uint64_t sb_mono_ns(void) {
  struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static void peer_connection_pace(PeerConnection* pc, size_t bytes) {
  uint32_t bps = pc->pacer_bps;
  if (bps == 0) return;

  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);
  if (pc->pacer_last.tv_sec == 0 && pc->pacer_last.tv_nsec == 0) {
    pc->pacer_last = now;
    pc->pacer_budget_bytes = PACER_BURST_BYTES;
  }
  double elapsed = (double)(now.tv_sec - pc->pacer_last.tv_sec) +
                   (double)(now.tv_nsec - pc->pacer_last.tv_nsec) / 1e9;
  pc->pacer_last = now;

  pc->pacer_budget_bytes += elapsed * (double)bps / 8.0;
  if (pc->pacer_budget_bytes > PACER_BURST_BYTES)
    pc->pacer_budget_bytes = PACER_BURST_BYTES;

  pc->pacer_budget_bytes -= (double)bytes;
  if (pc->pacer_budget_bytes < 0) {
    double wait_s = -pc->pacer_budget_bytes * 8.0 / (double)bps;
    if (wait_s > PACER_MAX_SLEEP_S) wait_s = PACER_MAX_SLEEP_S;
    struct timespec ts;
    ts.tv_sec = (time_t)wait_s;
    ts.tv_nsec = (long)((wait_s - (double)ts.tv_sec) * 1e9);
    nanosleep(&ts, NULL);
    /* The deficit is repaid by the elapsed-time refill on the next call. */
  }
}

void peer_connection_set_pacer_bps(PeerConnection* pc, uint32_t bps) {
  if (pc) pc->pacer_bps = bps;
}

/* Final transmit tail shared by media and FEC packets: SRTP protect, pace,
 * send. (The pre-SRTP form is what FEC protects, so XOR accumulation happens
 * before this is called.) */
static void peer_connection_xmit_rtp(PeerConnection* pc, uint8_t* data, size_t size) {
  /* Pace BEFORE taking the send lock (sleeps must never hold it); budget on
   * the approximate on-wire size (payload + ~10-byte SRTP auth trailer). */
  uint64_t t0 = sb_mono_ns();
  peer_connection_pace(pc, size + 10);
  uint64_t t1 = sb_mono_ns();
  pthread_mutex_lock(&pc->send_mtx);
  uint64_t t2 = sb_mono_ns();
  dtls_srtp_encrypt_rtp_packet(&pc->dtls_srtp, data, (int*)&size);
  uint64_t t2b = sb_mono_ns();
  agent_send(&pc->agent, data, size);
  uint64_t t3 = sb_mono_ns();
  pthread_mutex_unlock(&pc->send_mtx);
  sb_pace_ns += t1 - t0;         /* TEMP INSTRUMENT: pacer sleep        */
  sb_lockwait_ns += t2 - t1;     /* TEMP INSTRUMENT: send_mtx acquire   */
  sb_srtp_ns += t2b - t2;        /* TEMP INSTRUMENT: SRTP encrypt       */
  sb_send_ns += t3 - t2b;        /* TEMP INSTRUMENT: agent_send/sendto  */
  sb_pkts++;
}

/* TEMP INSTRUMENT (pc.loop phase decomposition): reactor-thread-only per-call
 * accumulators for time spent in peer_connection_rtx_resend()'s send_mtx
 * acquire vs. the subsequent encrypt+send. peer_connection_rtx_resend is
 * invoked nested (peer_connection_loop -> peer_connection_incoming_rtcp ->
 * peer_connection_handle_nack -> peer_connection_rtx_resend), and only the
 * single reactor thread ever walks that chain, so a plain __thread pair
 * (mirroring the sb_* pattern above) is simpler than threading an
 * accumulator pointer through three call levels. Reset at the top of the
 * PEER_CONNECTION_COMPLETED case in peer_connection_loop(); read at the end
 * of that case to build the "pc.loop slow" breakdown. Remove alongside the
 * rest of the pc.loop phase timing once the tail is found. */
static __thread uint32_t pl_rtx_lockwait_ms, pl_rtx_send_ms;

/* Record one outgoing media packet (final pre-SRTP form) for NACK-driven
 * retransmission. Send-worker thread; the NACK reader holds the same mutex. */
static void peer_connection_rtx_store(PeerConnection* pc, const uint8_t* data, size_t size) {
  if (!pc->rtx_history || size < 12 || size > RTX_SLOT_BYTES) return;
  uint16_t seq = (uint16_t)((data[2] << 8) | data[3]);
  rtx_slot_t* slot = &pc->rtx_history[seq % RTX_HISTORY_SLOTS];
  pthread_mutex_lock(&pc->rtx_mtx);
  slot->seq = seq;
  slot->len = (uint16_t)size;
  slot->last_resend_ms = 0;
  memcpy(slot->data, data, size);
  pthread_mutex_unlock(&pc->rtx_mtx);
}

/* Answer one NACKed sequence number with an RTX packet (RFC 4588: original
 * header with RTX SSRC/PT/seq, payload = 2-byte OSN + original payload).
 * Reactor thread — sends directly, NEVER through the pacer (a pacer sleep
 * here would stall signaling for every peer). */
static void peer_connection_rtx_resend(PeerConnection* pc, uint16_t seq) {
  uint8_t buf[RTX_SLOT_BYTES + 2 + 64];   /* +OSN +SRTP trailer slack */
  size_t out_len = 0;

  pthread_mutex_lock(&pc->rtx_mtx);
  rtx_slot_t* slot = &pc->rtx_history[seq % RTX_HISTORY_SLOTS];
  if (slot->len >= 12 && slot->seq == seq) {
    uint32_t now = rtx_now_ms();
    if (slot->last_resend_ms == 0 || now - slot->last_resend_ms >= RTX_MIN_RESEND_MS) {
      slot->last_resend_ms = now;
      size_t off = rtp_payload_offset(slot->data, slot->len);
      /* header + extensions verbatim, then OSN, then original payload */
      memcpy(buf, slot->data, off);
      buf[off]     = (uint8_t)(seq >> 8);          /* OSN */
      buf[off + 1] = (uint8_t)(seq & 0xFF);
      memcpy(buf + off + 2, slot->data + off, slot->len - off);
      out_len = slot->len + 2;
      /* rewrite identity: RTX PT (marker preserved), own seq, RTX SSRC */
      uint16_t rseq = pc->rtx_seq++;
      buf[1] = (uint8_t)((buf[1] & 0x80) | PT_RTX);
      buf[2] = (uint8_t)(rseq >> 8);
      buf[3] = (uint8_t)(rseq & 0xFF);
      buf[8] = 0; buf[9] = 0; buf[10] = 0; buf[11] = RTX_SSRC;
    }
  }
  pthread_mutex_unlock(&pc->rtx_mtx);

  if (out_len > 0) {
    /* TEMP INSTRUMENT (pc.loop phase decomposition): time the send_mtx
     * acquire separately from the locked encrypt+send — see pl_rtx_lockwait_ms
     * / pl_rtx_send_ms above. */
    uint32_t rt0 = ports_get_epoch_time();
    pthread_mutex_lock(&pc->send_mtx);
    uint32_t rt1 = ports_get_epoch_time();
    dtls_srtp_encrypt_rtp_packet(&pc->dtls_srtp, buf, (int*)&out_len);
    agent_send(&pc->agent, buf, out_len);
    pthread_mutex_unlock(&pc->send_mtx);
    uint32_t rt2 = ports_get_epoch_time();
    pl_rtx_lockwait_ms += (rt1 - rt0);
    pl_rtx_send_ms += (rt2 - rt1);
  }
}

/* Parse one RTCP Generic NACK (RTPFB fmt=1) and retransmit every named seq.
 * FCI = N x { PID(16) | BLP(16) }: PID itself plus each set BLP bit (PID+i+1). */
static void peer_connection_handle_nack(PeerConnection* pc, const uint8_t* fb, size_t len) {
  if (!pc->config.rtx || !pc->rtx_history || len < 16) return;
  size_t fci = 12;                       /* hdr(4) + sender ssrc + media ssrc */
  while (fci + 4 <= len) {
    uint16_t pid = (uint16_t)((fb[fci] << 8) | fb[fci + 1]);
    uint16_t blp = (uint16_t)((fb[fci + 2] << 8) | fb[fci + 3]);
    peer_connection_rtx_resend(pc, pid);
    for (int i = 0; i < 16; i++) {
      if (blp & (1u << i)) peer_connection_rtx_resend(pc, (uint16_t)(pid + i + 1));
    }
    fci += 4;
  }
}

/* One XOR repair packet per this many media packets (or at frame end with at
 * least 2 accumulated). Repairs any SINGLE loss within the group. */
#define FEC_GROUP_SIZE 6

/* Accumulate one media packet (its FINAL pre-SRTP form: header + extensions +
 * payload, PT still the media PT, seq already final) into the open FEC group.
 * Field layout per RFC 5109 §7.4: the FEC header recovers P/X/CC/M/PT/TS/len
 * by XOR; the level-0 payload XOR covers everything after the fixed 12-byte
 * header. */
static void peer_connection_fec_accumulate(PeerConnection* pc, const uint8_t* data, size_t size) {
  if (size < 12) return;
  size_t plen = size - 12;
  if (plen > sizeof(pc->fec_xor)) plen = sizeof(pc->fec_xor);

  if (pc->fec_group_cnt == 0) {
    pc->fec_snbase = (uint16_t)((data[2] << 8) | data[3]);
    pc->fec_maxlen = 0;
    pc->fec_len_xor = 0;
    memset(pc->fec_hdr_xor, 0, sizeof(pc->fec_hdr_xor));
    memset(pc->fec_ts_xor, 0, sizeof(pc->fec_ts_xor));
    memset(pc->fec_xor, 0, sizeof(pc->fec_xor));
  }

  pc->fec_hdr_xor[0] ^= data[0] & 0x3F;          /* P, X, CC                  */
  pc->fec_hdr_xor[1] ^= data[1];                 /* M, PT                     */
  for (int i = 0; i < 4; i++) pc->fec_ts_xor[i] ^= data[4 + i];
  pc->fec_len_xor ^= (uint16_t)plen;
  /* XOR the post-header bytes, but with MUTABLE header extensions zeroed —
   * libwebrtc's receiver zeroes abs-send-time (ext id 3) before FEC decode
   * (RtpPacket::ZeroMutableExtensions, webrtc bug 7859), so parity computed
   * over the live value yields corrupt recoveries. Our extension block layout
   * is fixed (built by rtp_insert_extensions): 0xBEDE at [12], abs-send-time
   * element data at [17..19]. abs-capture-time (id 4) is NOT mutable. */
  size_t skip_lo = 0, skip_hi = 0;
  if ((data[0] & 0x10) && size >= 20 &&
      data[12] == 0xBE && data[13] == 0xDE &&
      (data[16] >> 4) == 3 /* RTP_EXT_ID_ABS_SEND_TIME */) {
    skip_lo = 17 - 12;   /* offsets relative to byte 12 */
    skip_hi = 20 - 12;
  }
  for (size_t i = 0; i < plen; i++) {
    uint8_t b = data[12 + i];
    if (skip_hi && i >= skip_lo && i < skip_hi) b = 0;
    pc->fec_xor[i] ^= b;
  }
  if (plen > pc->fec_maxlen) pc->fec_maxlen = plen;
  memcpy(pc->fec_last_hdr, data, 12);
  pc->fec_group_cnt++;
}

/* Emit the repair packet for the open group (RED-encapsulated ULPFEC on the
 * same SSRC, next sequence number) and reset the group. */
static void peer_connection_fec_flush(PeerConnection* pc) {
  int cnt = pc->fec_group_cnt;
  if (cnt < 2) { pc->fec_group_cnt = 0; return; }

  uint8_t buf[12 + 1 + 10 + 4 + sizeof(pc->fec_xor)];
  uint16_t seq = pc->out_seq++;

  /* RTP header: V=2, M=0, PT=RED; TS/SSRC from the last protected packet. */
  buf[0] = 0x80;
  buf[1] = PT_RED;
  buf[2] = (uint8_t)(seq >> 8);
  buf[3] = (uint8_t)(seq & 0xFF);
  memcpy(buf + 4, pc->fec_last_hdr + 4, 4);   /* timestamp */
  memcpy(buf + 8, pc->fec_last_hdr + 8, 4);   /* SSRC      */

  size_t off = 12;
  buf[off++] = PT_ULPFEC & 0x7F;              /* RED header: F=0, block PT   */

  /* FEC header (10 bytes, RFC 5109 §7.3): E=0, L=0 (16-bit mask). */
  buf[off++] = pc->fec_hdr_xor[0];            /* E|L=0 | P|X|CC recovery     */
  buf[off++] = pc->fec_hdr_xor[1];            /* M | PT recovery             */
  buf[off++] = (uint8_t)(pc->fec_snbase >> 8);
  buf[off++] = (uint8_t)(pc->fec_snbase & 0xFF);
  memcpy(buf + off, pc->fec_ts_xor, 4); off += 4;
  buf[off++] = (uint8_t)(pc->fec_len_xor >> 8);
  buf[off++] = (uint8_t)(pc->fec_len_xor & 0xFF);

  /* Level 0 header: protection length + mask (bit i of the 16 = snbase+i,
   * MSB first; the group is consecutive). */
  uint16_t mask = (uint16_t)(((1u << cnt) - 1u) << (16 - cnt));
  buf[off++] = (uint8_t)(pc->fec_maxlen >> 8);
  buf[off++] = (uint8_t)(pc->fec_maxlen & 0xFF);
  buf[off++] = (uint8_t)(mask >> 8);
  buf[off++] = (uint8_t)(mask & 0xFF);

  memcpy(buf + off, pc->fec_xor, pc->fec_maxlen);
  off += pc->fec_maxlen;

  pc->fec_group_cnt = 0;
  peer_connection_xmit_rtp(pc, buf, off);
}

/* RED-encapsulate a media packet in place: 1-byte RED header (F=0 | media PT)
 * inserted at the start of the payload (after header + extensions), RTP PT
 * rewritten to RED. Returns the new size. */
static size_t peer_connection_red_wrap(uint8_t* data, size_t size) {
  size_t hdr = 12;
  if (data[0] & 0x10) {                        /* X bit: skip extension block */
    if (size < hdr + 4) return size;
    uint16_t words = (uint16_t)((data[hdr + 2] << 8) | data[hdr + 3]);
    hdr += 4 + 4u * words;
  }
  if (size < hdr) return size;
  memmove(data + hdr + 1, data + hdr, size - hdr);
  uint8_t media_pt = data[1] & 0x7F;
  data[hdr] = media_pt;                        /* F=0 | block PT              */
  data[1] = (data[1] & 0x80) | PT_RED;
  return size + 1;
}

static void peer_connection_outgoing_rtp_packet(uint8_t* data, size_t size, void* user_data) {
  PeerConnection* pc = (PeerConnection*)user_data;
  /* Stamp abs-send-time on every outgoing VIDEO RTP packet (PT_H264=96) so the
   * browser's REMB estimator sees per-packet send time.  On the first packet of
   * each access unit (detected by RTP-timestamp change) also add abs-capture-time
   * so Chrome can compute skew-free glass-to-glass latency.
   *
   * All insertions happen here — a single send chokepoint — BEFORE srtp_protect
   * so the extension is authenticated.  rtp_insert_extensions always rebuilds the
   * extension block from a clean 12-byte-header assumption (no X-bit guard): the
   * FU-A packetizer sets extension=0 once before its fragment loop and reuses the
   * encoder buffer, so a stale X bit from fragment 1 persists into 2..N; guarding
   * on X there would forward X=1 packets with no real extension → ~75% loss.
   * Verified by the live-decode E2E (framesDecoded>0, zero loss).               */
  if (size >= 12 && (data[1] & 0x7f) == PT_H264) {
    /* Extract the RTP timestamp from the packet (bytes 4..7, big-endian). */
    uint32_t rtp_ts = ((uint32_t)data[4] << 24) | ((uint32_t)data[5] << 16)
                    | ((uint32_t)data[6] <<  8) |  (uint32_t)data[7];
    int is_first_packet = (rtp_ts != pc->last_rtp_ts);
    pc->last_rtp_ts = rtp_ts;

    size = rtp_insert_extensions(data, size,
                                 peer_connection_abs_send_time_24(),
                                 is_first_packet,
                                 pc->cur_frame_capture_ntp);

    /* Track cumulative counters for RTCP SR.  Payload length = total packet
     * size minus the 12-byte RTP fixed header (the extension is already part
     * of the packet at this point, but SR octet count counts only payload
     * octets per RFC 3550 §6.4.1; subtract the header only, not the ext).  */
    pc->sr_packets_sent++;
    if (size > 12)
      pc->sr_octets_sent += (uint32_t)(size - 12);
  }
  if (pc->config.fec && size >= 12 && (data[1] & 0x7F) == PT_H264) {
    /* FEC path: the chokepoint owns the sequence space (media + repair
     * packets interleave on one SSRC), so re-stamp the encoder's seq. */
    uint16_t seq = pc->out_seq++;
    data[2] = (uint8_t)(seq >> 8);
    data[3] = (uint8_t)(seq & 0xFF);
    int frame_end = (data[1] & 0x80) != 0;     /* marker = last pkt of AU    */

    peer_connection_fec_accumulate(pc, data, size);   /* pre-RED media form  */
    size = peer_connection_red_wrap(data, size);
    peer_connection_xmit_rtp(pc, data, size);

    /* CRITICAL: the FU-A packetizer REUSES this buffer for the next fragment
     * and rewrites payload/seq/marker but NOT the PT byte (same buffer-reuse
     * trap the extensions comment above describes). Leaving PT=RED here makes
     * every subsequent fragment skip this branch and go out unstamped/unwrapped
     * on the encoder's own seq space — two interleaved sequence spaces, and
     * the receiver rejects nearly everything. Restore the media PT. */
    data[1] = (uint8_t)((frame_end ? 0x80 : 0x00) | PT_H264);

    if (pc->fec_group_cnt >= FEC_GROUP_SIZE ||
        (frame_end && pc->fec_group_cnt >= 2)) {
      peer_connection_fec_flush(pc);
    }
    return;
  }
  if (pc->rtx_history && size >= 12 && (data[1] & 0x7F) == PT_H264) {
    peer_connection_rtx_store(pc, data, size);
  }
  peer_connection_xmit_rtp(pc, data, size);
}

/*
 * DTLS handshake fragment reassembly for ClientHello
 *
 * Firefox with DTLS 1.3 + PQC sends ~1531 byte ClientHello which gets fragmented.
 * mbedtls does not support reassembling fragmented ClientHello messages.
 * We reassemble fragments here before passing to mbedtls.
 *
 * DTLS record header (13 bytes):
 *   [0]      Content type (22 = handshake)
 *   [1-2]    Version
 *   [3-4]    Epoch
 *   [5-10]   Sequence number (6 bytes)
 *   [11-12]  Length
 *
 * Handshake message header (12 bytes, after record header):
 *   [0]      Handshake type (1 = ClientHello)
 *   [1-3]    Total message length (24-bit big-endian)
 *   [4-5]    Message sequence
 *   [6-8]    Fragment offset (24-bit big-endian)
 *   [9-11]   Fragment length (24-bit big-endian)
 */

#define DTLS_RECORD_HEADER_LEN 13
#define DTLS_HANDSHAKE_HEADER_LEN 12
#define DTLS_CONTENT_TYPE_HANDSHAKE 22
#define DTLS_HANDSHAKE_TYPE_CLIENT_HELLO 1
#define DTLS_MAX_HANDSHAKE_SIZE 4096

/* Fragment reassembly state - stored per-connection to support multiple peers */
struct dtls_fragment_state_s {
  uint8_t data[DTLS_MAX_HANDSHAKE_SIZE];
  uint32_t total_len;        /* Expected total handshake message length */
  uint32_t received_len;     /* Bytes received so far */
  uint16_t msg_seq;          /* Message sequence number */
  uint8_t version[2];        /* DTLS version from first fragment */
  uint8_t epoch[2];          /* Epoch from first fragment */
  uint8_t seq_num[6];        /* Sequence number from first fragment */
  int active;                /* Reassembly in progress */
};

static uint32_t read_uint24_be(const uint8_t* p) {
  return ((uint32_t)p[0] << 16) | ((uint32_t)p[1] << 8) | p[2];
}

static void write_uint24_be(uint8_t* p, uint32_t val) {
  p[0] = (val >> 16) & 0xFF;
  p[1] = (val >> 8) & 0xFF;
  p[2] = val & 0xFF;
}

/* peer_connection_dtls_srtp_recv — the mbedtls BIO recv callback.
 *
 * Contract with mbedtls (callers MUST NOT relax this — getting it wrong is
 * silent and ends in MBEDTLS_ERR_SSL_TIMEOUT loops):
 *
 *   - Return > 0  ........... bytes copied into buf for ONE DTLS record. mbedtls
 *                             may call us again inside the same ssl_read if it
 *                             needs more bytes (continuation / next record).
 *   - Return MBEDTLS_ERR_SSL_WANT_READ  ... no data available right now; mbedtls
 *                             treats this as "poll again later" via its timer.
 *   - Any other negative .... hard error; mbedtls aborts the read.
 *
 * Cache invariant: pc->agent_ret/pc->agent_buf hold ONE wire packet that the
 * outer dispatch loop in peer_connection_loop just stashed via agent_recv.
 * This callback serves it ONCE and then clears pc->agent_ret. Without that
 * clear, mbedtls re-reads the same record on every internal read and (at
 * steady-state bulk traffic) the decrypted SCTP DATA chunks never reach the
 * application — the sender's send buffer fills to its 4 MB cap and stays.
 *
 * NON-BLOCKING (this is the real fix for the reactor-freeze bug — the
 * dtls_srtp.c step-wise conversion alone is not enough, because THIS
 * function, not dtls_srtp_udp_recv in dtls_srtp.c, is the BIO recv mbedtls
 * actually calls: peer_connection_create_sdp() overrides
 * dtls_srtp->udp_recv/udp_send to peer_connection_dtls_srtp_recv/_send right
 * after dtls_srtp_init(), for every PeerConnection). This function used to
 * retry `agent_recv()` in an internal loop up to CONFIG_TLS_READ_TIMEOUT
 * (3000) times whenever no cached packet was available (the `while
 * (recv_max < CONFIG_TLS_READ_TIMEOUT ...)` below). agent_recv() ultimately
 * calls agent_socket_recv(), which blocks in select() for up to
 * AGENT_POLL_TIMEOUT (1ms) per attempt — so a SINGLE call to this function
 * could genuinely block the calling thread for ~3000 * 1ms ≈ 3 seconds via
 * real syscalls, not just spin. With dtls_srtp_do_handshake()'s outer retry
 * loop removed (see dtls_srtp.c), one handshake step now calls this function
 * only a small, bounded number of times — but each of THOSE calls could
 * still eat up to ~3s if this internal loop were left in place, still
 * enough to starve every other peer on the single-threaded reactor for
 * seconds at a time. So this is now a SINGLE attempt: try agent_recv() once;
 * if there's nothing usable, return MBEDTLS_ERR_SSL_WANT_READ immediately
 * (bounded to agent_recv's own ~1ms select() wait) and let the next
 * peer_connection_loop() tick — reached via dtls_srtp_do_handshake's
 * DTLS_SRTP_HS_WANT step return — bring us back. This is safe for the
 * ClientHello fragment-reassembly path below too: `frag` is
 * pc->frag_state, which persists across calls, so an in-progress
 * reassembly picks up exactly where it left off on the next call instead of
 * blocking here waiting for the remaining fragments to arrive. */
static int peer_connection_dtls_srtp_recv(void* ctx, unsigned char* buf, size_t len) {
  int ret = -1;
  DtlsSrtp* dtls_srtp = (DtlsSrtp*)ctx;
  PeerConnection* pc = (PeerConnection*)dtls_srtp->user_data;
  dtls_fragment_state_t* frag = pc->frag_state;
  uint8_t recv_buf[2048];

  if (pc->agent_ret > 0 && (size_t)pc->agent_ret <= len) {
    int n = pc->agent_ret;
    memcpy(buf, pc->agent_buf, n);
    pc->agent_ret = 0;  /* single-shot: see contract above */
    return n;
  }

  /* This direct agent_recv() path only makes sense during the CONNECTED-state
   * handshake (before the COMPLETED-state outer dispatch loop takes over
   * pre-fetching packets into pc->agent_ret/pc->agent_buf, per the cache
   * invariant above). Matches the defensive intent of the old loop's
   * `&& pc->state == PEER_CONNECTION_CONNECTED` guard. */
  if (pc->state != PEER_CONNECTION_CONNECTED) {
    return MBEDTLS_ERR_SSL_WANT_READ;
  }

  ret = agent_recv(&pc->agent, recv_buf, sizeof(recv_buf));

  if (ret <= 0) {
    /* ret == 0: a STUN packet (incl. any consent response) was consumed
     * internally by agent_recv. ret < 0: nothing available this attempt.
     * Either way there is no DTLS payload to hand back right now — tell
     * mbedtls to retry rather than spinning here for it ourselves. */
    return MBEDTLS_ERR_SSL_WANT_READ;
  }

  /* Check if this is a DTLS handshake record */
  if (ret < DTLS_RECORD_HEADER_LEN + DTLS_HANDSHAKE_HEADER_LEN) {
    /* Too short to be a handshake, pass through */
    memcpy(buf, recv_buf, ret);
    return ret;
  }

  uint8_t content_type = recv_buf[0];
  if (content_type != DTLS_CONTENT_TYPE_HANDSHAKE) {
    /* Not a handshake message, pass through */
    memcpy(buf, recv_buf, ret);
    return ret;
  }

  /* Parse handshake header (starts after 13-byte record header) */
  const uint8_t* hs = recv_buf + DTLS_RECORD_HEADER_LEN;
  uint8_t hs_type = hs[0];
  uint32_t hs_total_len = read_uint24_be(hs + 1);
  uint16_t hs_msg_seq = ((uint16_t)hs[4] << 8) | hs[5];
  uint32_t frag_offset = read_uint24_be(hs + 6);
  uint32_t frag_len = read_uint24_be(hs + 9);

  LOGD("Handshake: type=%d, total=%u, seq=%u, frag_off=%u, frag_len=%u",
       hs_type, hs_total_len, hs_msg_seq, frag_offset, frag_len);

  /* Only reassemble ClientHello (type 1) */
  if (hs_type != DTLS_HANDSHAKE_TYPE_CLIENT_HELLO) {
    /* Not ClientHello, pass through */
    memcpy(buf, recv_buf, ret);
    return ret;
  }

  /* Check if this is a fragmented message */
  if (frag_offset == 0 && frag_len == hs_total_len) {
    /* Not fragmented, pass through */
    LOGD("ClientHello not fragmented, passing through");
    memcpy(buf, recv_buf, ret);
    return ret;
  }

  /* Fragmented ClientHello - need to reassemble */
  LOGI("ClientHello fragmented: offset=%u, len=%u, total=%u", frag_offset, frag_len, hs_total_len);

  /* Check if this is the start of a new message */
  if (frag_offset == 0) {
    /* Start new reassembly */
    memset(frag, 0, sizeof(*frag));
    frag->active = 1;
    frag->total_len = hs_total_len;
    frag->msg_seq = hs_msg_seq;
    /* Save record header fields for reconstruction */
    memcpy(frag->version, recv_buf + 1, 2);
    memcpy(frag->epoch, recv_buf + 3, 2);
    memcpy(frag->seq_num, recv_buf + 5, 6);
    LOGI("Starting ClientHello reassembly, total_len=%u", hs_total_len);
  }

  /* Validate this fragment belongs to current reassembly */
  if (!frag->active || hs_msg_seq != frag->msg_seq || hs_total_len != frag->total_len) {
    LOGW("Fragment mismatch, resetting");
    frag->active = 0;
    memcpy(buf, recv_buf, ret);
    return ret;
  }

  /* Bounds check */
  if (frag_offset + frag_len > frag->total_len) {
    LOGE("Fragment exceeds total length");
    frag->active = 0;
    memcpy(buf, recv_buf, ret);
    return ret;
  }

  if (frag_offset + frag_len > DTLS_MAX_HANDSHAKE_SIZE - DTLS_HANDSHAKE_HEADER_LEN) {
    LOGE("Handshake message too large for reassembly buffer");
    frag->active = 0;
    memcpy(buf, recv_buf, ret);
    return ret;
  }

  /* Copy fragment data (handshake payload, after 12-byte handshake header) */
  const uint8_t* frag_data = hs + DTLS_HANDSHAKE_HEADER_LEN;
  memcpy(frag->data + DTLS_HANDSHAKE_HEADER_LEN + frag_offset, frag_data, frag_len);
  frag->received_len += frag_len;

  LOGI("Received fragment: offset=%u, len=%u, total_received=%u/%u",
       frag_offset, frag_len, frag->received_len, frag->total_len);

  /* Check if reassembly is complete */
  if (frag->received_len >= frag->total_len) {
    LOGI("ClientHello reassembly complete (%u bytes)", frag->total_len);

    /* Build the complete handshake header */
    frag->data[0] = DTLS_HANDSHAKE_TYPE_CLIENT_HELLO;
    write_uint24_be(frag->data + 1, frag->total_len);
    frag->data[4] = (frag->msg_seq >> 8) & 0xFF;
    frag->data[5] = frag->msg_seq & 0xFF;
    write_uint24_be(frag->data + 6, 0);  /* fragment_offset = 0 */
    write_uint24_be(frag->data + 9, frag->total_len);  /* fragment_length = total */

    /* Build complete DTLS record */
    uint32_t handshake_size = DTLS_HANDSHAKE_HEADER_LEN + frag->total_len;
    uint32_t total_record_len = DTLS_RECORD_HEADER_LEN + handshake_size;

    if (total_record_len > len) {
      LOGE("Reassembled message too large for buffer");
      frag->active = 0;
      return -1;
    }

    /* Build record header */
    buf[0] = DTLS_CONTENT_TYPE_HANDSHAKE;
    memcpy(buf + 1, frag->version, 2);
    memcpy(buf + 3, frag->epoch, 2);
    memcpy(buf + 5, frag->seq_num, 6);
    buf[11] = (handshake_size >> 8) & 0xFF;
    buf[12] = handshake_size & 0xFF;

    /* Copy handshake data */
    memcpy(buf + DTLS_RECORD_HEADER_LEN, frag->data, handshake_size);

    frag->active = 0;
    return total_record_len;
  }

  /* Not complete yet: more fragments still needed. Rather than blocking here
   * waiting for them (the old behavior), tell mbedtls WANT_READ and let the
   * reactor bring us back on a later tick — frag->active stays 1 so the next
   * call resumes this same reassembly. */
  return MBEDTLS_ERR_SSL_WANT_READ;
}

/* Test-only: armed by peer_connection_test_arm_flight_drop(count) (wired to the
 * SDK_LOCAL_TEST_DRIVER MQTT control action "drop_dtls_flight", compiled out of
 * production). Drops the next `count` server DTLS final flights — each begins
 * with a ChangeCipherSpec, content_type 0x14 — deterministically reproducing the
 * lost-final-flight wedge in e2e without flaky netem loss. count=1 loses the
 * original flight (recovered by the peer's retransmit); count>=2 also loses the
 * reactive resend, forcing the device's proactive retransmit timer to recover
 * (the field case where resends themselves are lost on wifi). Never set on a
 * real device. */
static volatile int g_test_drop_remaining = 0;
void peer_connection_test_arm_flight_drop(int count) { g_test_drop_remaining = count; }

static int peer_connection_dtls_srtp_send(void* ctx, const uint8_t* buf, size_t len) {
  DtlsSrtp* dtls_srtp = (DtlsSrtp*)ctx;
  PeerConnection* pc = (PeerConnection*)dtls_srtp->user_data;

  if (g_test_drop_remaining > 0 && len > 0 &&
      buf[0] == 0x14 /* ChangeCipherSpec = start of the server's final flight */) {
    g_test_drop_remaining--;
    LOGW("TEST: dropping server DTLS final flight (CCS, len=%zu, %d left) — simulating loss",
         len, g_test_drop_remaining);
    return (int)len;  /* lie to mbedtls: report the datagram as sent */
  }

  // LOGD("send %.4x %.4x, %ld", *(uint16_t*)buf, *(uint16_t*)(buf + 2), len);
  return agent_send(&pc->agent, buf, len);
}

static void peer_connection_incoming_rtcp(PeerConnection* pc, uint8_t* buf, size_t len) {
  RtcpHeader* rtcp_header;
  size_t pos = 0;

  while (pos < len) {
    rtcp_header = (RtcpHeader*)(buf + pos);

    switch (rtcp_header->type) {
      case RTCP_RR:
        LOGD("RTCP_RR");
        /* Receiver-report loss → the rate controller's loss EWMA + emergency
         * brake. Parse THIS report block (buf + pos), not buf — compound RTCP
         * puts later packets past pos. fraction-lost is the top byte of the
         * first word. Report EVERY RR including fraction==0: the ratecore loss
         * EWMA only decays when it is fed clean intervals, so suppressing zeros
         * makes it a one-way ratchet that stays pinned at a historical (or
         * other-viewer) loss value forever, permanently throttling the grant. */
        if (rtcp_header->rc > 0) {
          RtcpRr rtcp_rr = rtcp_parse_rr(buf + pos);
          uint32_t fraction = ntohl(rtcp_rr.report_block[0].flcnpl) >> 24;
          uint32_t total = ntohl(rtcp_rr.report_block[0].flcnpl) & 0x00FFFFFF;
          if (pc->on_receiver_packet_loss) {
            pc->on_receiver_packet_loss((float)fraction / 256.0f, total, pc->config.user_data);
          }
        }
        break;
      case RTCP_RTPFB: {
        /* Transport-layer FB; fmt 1 = Generic NACK -> RTX retransmits. */
        if (rtcp_header->rc == 1) {
          size_t fb_len = 4u * ntohs(rtcp_header->length) + 4u;
          if (pos + fb_len <= len)
            peer_connection_handle_nack(pc, buf + pos, fb_len);
        }
        break;
      }
      case RTCP_PSFB: {
        int fmt = rtcp_header->rc;
        LOGD("RTCP_PSFB %d", fmt);
        if ((fmt == 1 || fmt == 4) && pc->config.on_request_keyframe) {
          /* PLI (1) / FIR (4): request a keyframe. */
          pc->config.on_request_keyframe(pc->config.user_data);
        } else if (fmt == 15 && pc->on_remb) {
          /* goog-remb (AFB, fmt 15): the browser's bandwidth estimate → the
           * rate controller. */
          uint32_t bps = 0;
          if (rtcp_parse_remb(buf + pos, len - pos, &bps) && bps > 0)
            pc->on_remb(bps, pc->config.user_data);
        }
        break;
      }
      default:
        break;
    }

    pos += 4 * ntohs(rtcp_header->length) + 4;
  }
}

const char* peer_connection_state_to_string(PeerConnectionState state) {
  switch (state) {
    case PEER_CONNECTION_NEW:
      return "new";
    case PEER_CONNECTION_CHECKING:
      return "checking";
    case PEER_CONNECTION_CONNECTED:
      return "connected";
    case PEER_CONNECTION_COMPLETED:
      return "completed";
    case PEER_CONNECTION_FAILED:
      return "failed";
    case PEER_CONNECTION_CLOSED:
      return "closed";
    case PEER_CONNECTION_DISCONNECTED:
      return "disconnected";
    default:
      return "unknown";
  }
}

PeerConnectionState peer_connection_get_state(PeerConnection* pc) {
  return pc->state;
}

/* Milliseconds since the last inbound STUN binding request from the peer — a
 * spec-appropriate (RFC 7675) liveness signal, distinct from the PC state
 * machine (which can sit in COMPLETED after a peer has silently gone). Returns
 * UINT64_MAX if none seen yet. Higher-level watchdogs use this to tell a
 * live-but-signalling-quiet stream (consent still flowing) from a dead peer.
 * The clock (ports_get_epoch_time, uint32 ms, wrap-correct for deltas) stays
 * internal to libpeer. */
uint64_t peer_connection_get_last_stun_rx_age_ms(PeerConnection* pc) {
  if (pc->agent.binding_request_time == 0) return UINT64_MAX;
  uint32_t age = (uint32_t)ports_get_epoch_time() - (uint32_t)pc->agent.binding_request_time;
  return (uint64_t)age;
}

void peer_connection_get_session_diag(PeerConnection* pc, char* buf, size_t len) {
  if (!pc || !buf || len == 0) return;
  char local[ADDRSTRLEN + 8] = "-";
  int ltype = -1, rtype = -1;
  IceCandidatePair* sp = pc->agent.selected_pair;
  if (sp && sp->local) {
    addr_to_string_with_port(&sp->local->addr, local, sizeof(local));
    ltype = (int)sp->local->type;
  }
  if (sp && sp->remote) rtype = (int)sp->remote->type;
  snprintf(buf, len,
      "state=%d sctp=%d stunAgeMs=%llu inData=%u inStun=%u ncFloods=%u pair=%s ltype=%d rtype=%d iface=%s",
      (int)pc->state, sctp_is_connected(&pc->sctp),
      (unsigned long long)peer_connection_get_last_stun_rx_age_ms(pc),
      pc->in_data_pkts, pc->in_stun_pkts, pc->sctp_nc_logs,
      local, ltype, rtype, pc->config.bind_iface[0] ? pc->config.bind_iface : "-");
}

void peer_connection_get_diag(PeerConnection* pc, PeerConnectionDiag* out) {
  if (!pc || !out) return;
  out->turn_alloc_ok = pc->agent.turn_alloc_ok;
  out->turn_alloc_rejected = pc->agent.turn_alloc_rejected;
  out->mdns_resolved = pc->agent.mdns_resolved;
  out->mdns_queued = pc->agent.mdns_queued;
  out->selected_remote_type = pc->agent.selected_remote_type;
  out->dtls_complete_ms = pc->dtls_complete_ms;
}

void* peer_connection_get_sctp(PeerConnection* pc) {
  return &pc->sctp;
}

PeerConnection* peer_connection_create(PeerConfiguration* config) {
  PeerConnection* pc = calloc(1, sizeof(PeerConnection));
  if (!pc) {
    return NULL;
  }

  /* Allocate per-connection DTLS fragment reassembly state */
  pc->frag_state = calloc(1, sizeof(dtls_fragment_state_t));
  if (!pc->frag_state) {
    free(pc);
    return NULL;
  }

  memcpy(&pc->config, config, sizeof(PeerConfiguration));

  /* Send pacer initial rate (0 = off); see PeerConfiguration.pacer_bps. */
  pc->pacer_bps = pc->config.pacer_bps;

  /* RTX: history ring + lock (skipped entirely when disabled). */
  pthread_mutex_init(&pc->rtx_mtx, NULL);
  pthread_mutex_init(&pc->send_mtx, NULL);
  if (pc->config.rtx) {
    pc->rtx_history = calloc(RTX_HISTORY_SLOTS, sizeof(rtx_slot_t));
    if (!pc->rtx_history)
      LOGW("rtx history alloc failed - retransmissions disabled for this peer");
  }

  /* Propagate the optional interface pin into the agent BEFORE agent_create so
   * the UDP sockets are SO_BINDTODEVICE-bound at open time. */
  memcpy(pc->agent.bind_iface, pc->config.bind_iface, sizeof(pc->agent.bind_iface));

  /* Propagate the optional fixed media port (0 = ephemeral). */
  pc->agent.media_port = pc->config.media_port;

  agent_create(&pc->agent);

  memset(&pc->sctp, 0, sizeof(pc->sctp));

  if (pc->config.audio_codec) {
    rtp_encoder_init(&pc->artp_encoder, pc->config.audio_codec,
                     peer_connection_outgoing_rtp_packet, (void*)pc);

    rtp_decoder_init(&pc->artp_decoder, pc->config.audio_codec,
                     pc->config.onaudiotrack, pc->config.user_data);
  }

  if (pc->config.video_codec) {
    rtp_encoder_init(&pc->vrtp_encoder, pc->config.video_codec,
                     peer_connection_outgoing_rtp_packet, (void*)pc);

    rtp_decoder_init(&pc->vrtp_decoder, pc->config.video_codec,
                     pc->config.onvideotrack, pc->config.user_data);
  }

  return pc;
}

void peer_connection_destroy(PeerConnection* pc) {
  if (pc) {
    sctp_destroy_association(&pc->sctp);
    dtls_srtp_deinit(&pc->dtls_srtp);
    agent_destroy(&pc->agent);
    rtp_decoder_deinit(&pc->vrtp_decoder);
    rtp_decoder_deinit(&pc->artp_decoder);
    if (pc->frag_state) {
      free(pc->frag_state);
    }
    free(pc->rtx_history);
    pthread_mutex_destroy(&pc->rtx_mtx);
    pthread_mutex_destroy(&pc->send_mtx);
    free(pc);
    pc = NULL;
  }
}

void peer_connection_close(PeerConnection* pc) {
  pc->state = PEER_CONNECTION_CLOSED;
}

int peer_connection_send_audio(PeerConnection* pc, const uint8_t* buf, size_t len) {
  if (pc->state != PEER_CONNECTION_COMPLETED) {
    // LOGE("dtls_srtp not connected");
    return -1;
  }
  /* Audio timestamps come from the encoder's sample counter — capture_time_ns
   * is ignored for audio codecs. Pass 0 for clarity.                         */
  return rtp_encoder_encode(&pc->artp_encoder, buf, len, 0);
}

int peer_connection_send_video(PeerConnection* pc, const uint8_t* buf, size_t len, uint64_t capture_time_ns) {
  if (pc->state != PEER_CONNECTION_COMPLETED) {
    return -1;
  }
  /* Derive the frame's capture WALL-CLOCK (→ abs-capture-time) and refresh the
   * SR reference pair. capture_time_ns is the frame's timestamp; on a real
   * sensor it is CLOCK_MONOTONIC, so latency = (mono_now − capture) is a small
   * positive number and capture_realtime = now − latency is exact. Some sources
   * (notably the emulator) stamp frames with a synthetic stream-relative clock
   * that is NOT comparable to CLOCK_MONOTONIC; an implausible latency detects
   * that and we fall back to "captured ≈ now" (a valid wall-clock; g2g then
   * omits only the small capture→send delay). Without this guard a foreign
   * clock produces a years-off NTP and the browser computes nonsense g2g. */
  {
    struct timespec rt, mono;
    clock_gettime(CLOCK_REALTIME,  &rt);
    clock_gettime(CLOCK_MONOTONIC, &mono);
    int64_t rt_ns   = (int64_t)rt.tv_sec   * 1000000000LL + rt.tv_nsec;
    int64_t mono_ns = (int64_t)mono.tv_sec * 1000000000LL + mono.tv_nsec;
    int64_t latency_ns = mono_ns - (int64_t)capture_time_ns;
    int64_t capture_realtime_ns = (latency_ns >= 0 && latency_ns < 5000000000LL)
                                    ? rt_ns - latency_ns
                                    : rt_ns;
    pc->cur_frame_capture_ntp = unix_ns_to_ntp((uint64_t)capture_realtime_ns);
    /* SR reference: this frame's on-wire RTP timestamp paired with its capture
     * NTP — a true (RTP, NTP) point in the wire timebase, consistent with both
     * the per-packet RTP timestamps and abs-capture-time. */
    pc->sr_ref_rtp = (uint32_t)((capture_time_ns * 90000ULL) / 1000000000ULL);
    pc->sr_ref_ntp = pc->cur_frame_capture_ntp;
  }
  /* TEMP INSTRUMENT (send_ms decomposition): reset the per-thread segment
   * accumulators, run the send, and if it was slow log where the time went. */
  sb_pace_ns = sb_lockwait_ns = sb_srtp_ns = sb_send_ns = 0;
  sb_pkts = 0;
  uint64_t sv_t0 = sb_mono_ns();
  int rc = rtp_encoder_encode(&pc->vrtp_encoder, buf, len, capture_time_ns);
  uint64_t total_ms = (sb_mono_ns() - sv_t0) / 1000000ull;
  if (total_ms >= 30) {
    LOGD("sendbreak len=%zu pkts=%d total_ms=%llu pace_ms=%llu lockwait_ms=%llu srtp_ms=%llu sock_ms=%llu",
         len, sb_pkts, (unsigned long long)total_ms,
         (unsigned long long)(sb_pace_ns / 1000000ull),
         (unsigned long long)(sb_lockwait_ns / 1000000ull),
         (unsigned long long)(sb_srtp_ns / 1000000ull),
         (unsigned long long)(sb_send_ns / 1000000ull));
  }
  return rc;
}

int peer_connection_datachannel_send(PeerConnection* pc, char* message, size_t len) {
  return peer_connection_datachannel_send_sid(pc, message, len, 0);
}

int peer_connection_datachannel_send_sid(PeerConnection* pc, char* message, size_t len, uint16_t sid) {
  if (!sctp_is_connected(&pc->sctp)) {
    if ((pc->sctp_nc_logs++ % 500) == 0)   /* rate-limit: don't roll the log buffer */
      LOGE("sctp not connected a=%p (x%u)", (void*)&pc->sctp, pc->sctp_nc_logs);
    return -1;
  }
  if (pc->config.datachannel == DATA_CHANNEL_STRING)
    return sctp_outgoing_data(&pc->sctp, message, len, PPID_STRING, sid);
  else
    return sctp_outgoing_data(&pc->sctp, message, len, PPID_BINARY, sid);
}

int peer_connection_datachannel_send_binary(PeerConnection* pc, const uint8_t* data, size_t len) {
  if (!sctp_is_connected(&pc->sctp)) {
    if ((pc->sctp_nc_logs++ % 500) == 0)   /* rate-limit: don't roll the log buffer */
      LOGE("sctp not connected a=%p (x%u)", (void*)&pc->sctp, pc->sctp_nc_logs);
    return -1;
  }
  /* Always use PPID_BINARY regardless of datachannel config */
  return sctp_outgoing_data(&pc->sctp, (char*)data, len, PPID_BINARY, 0);
}

int peer_connection_create_datachannel(PeerConnection* pc, DecpChannelType channel_type, uint16_t priority, uint32_t reliability_parameter, char* label, char* protocol) {
  return peer_connection_create_datachannel_sid(pc, channel_type, priority, reliability_parameter, label, protocol, 0);
}

int peer_connection_create_datachannel_sid(PeerConnection* pc, DecpChannelType channel_type, uint16_t priority, uint32_t reliability_parameter, char* label, char* protocol, uint16_t sid) {
  int rtrn = -1;

  if (!sctp_is_connected(&pc->sctp)) {
    if ((pc->sctp_nc_logs++ % 500) == 0)   /* rate-limit: don't roll the log buffer */
      LOGE("sctp not connected a=%p (x%u)", (void*)&pc->sctp, pc->sctp_nc_logs);
    return rtrn;
  }

  //  0                   1                   2                   3
  //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  // |  Message Type |  Channel Type |            Priority           |
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  // |                    Reliability Parameter                      |
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  // |         Label Length          |       Protocol Length         |
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  // |                                                               |
  // |                             Label                             |
  // |                                                               |
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  // |                                                               |
  // |                            Protocol                           |
  // |                                                               |
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  int msg_size = 12 + strlen(label) + strlen(protocol);
  uint16_t priority_big_endian = htons(priority);
  uint32_t reliability_big_endian = ntohl(reliability_parameter);
  uint16_t label_length = htons(strlen(label));
  uint16_t protocol_length = htons(strlen(protocol));
  char* msg = calloc(1, msg_size);
  if (!msg) {
    return rtrn;
  }

  msg[0] = DATA_CHANNEL_OPEN;
  memcpy(msg + 2, &priority_big_endian, sizeof(uint16_t));
  memcpy(msg + 4, &reliability_big_endian, sizeof(uint32_t));
  memcpy(msg + 8, &label_length, sizeof(uint16_t));
  memcpy(msg + 10, &protocol_length, sizeof(uint16_t));
  memcpy(msg + 12, label, strlen(label));
  memcpy(msg + 12 + strlen(label), protocol, strlen(protocol));

  rtrn = sctp_outgoing_data(&pc->sctp, msg, msg_size, PPID_CONTROL, sid);
  free(msg);
  return rtrn;
}

static char* peer_connection_dtls_role_setup_value(DtlsSrtpRole d) {
  return d == DTLS_SRTP_ROLE_SERVER ? "a=setup:passive" : "a=setup:active";
}

int peer_connection_loop(PeerConnection* pc) {
  uint32_t ssrc = 0;
  memset(pc->agent_buf, 0, sizeof(pc->agent_buf));
  pc->agent_ret = -1;

  /* Pump async mDNS (.local) candidate resolution — no-op unless the remote
   * offered mDNS-obfuscated candidates that are still resolving. */
  agent_poll_mdns_candidates(&pc->agent);

  /* Per-iteration — must stay LOGD (like agent_recv/RTCP/DTLS below), else it
   * floods every connected session: the loop runs ~75 Hz per PeerConnection, so
   * on a live device this one INFO line was 64–97% of the whole log buffer,
   * shrinking the retained window to ~1 min and adding sync-log overhead on the
   * Pi 3. State transitions are already logged by STATE_CHANGED. */
  LOGD("peer_connection_loop: state=%d", pc->state);

  switch (pc->state) {
    case PEER_CONNECTION_NEW:
      break;

    case PEER_CONNECTION_CHECKING:
      if (agent_select_candidate_pair(&pc->agent) < 0) {
        STATE_CHANGED(pc, PEER_CONNECTION_FAILED);
      } else if (agent_connectivity_check(&pc->agent) == 0) {
        pc->b_dtls_handshake_logged = 0;  /* fresh handshake attempt: re-arm the once-only log below */
        STATE_CHANGED(pc, PEER_CONNECTION_CONNECTED);
      }
      break;

    case PEER_CONNECTION_CONNECTED: {
      /* Pass the selected remote candidate's address to DTLS handshake.
       * This is critical for multi-client support - mbedtls uses the transport ID
       * (derived from this address) to distinguish between simultaneous DTLS sessions.
       * Without a unique transport ID per client, cookies and sessions get confused.
       *
       * STEP-WISE / NON-BLOCKING: dtls_srtp_handshake() performs at most one
       * mbedtls_ssl_handshake() step per call and returns DTLS_SRTP_HS_WANT
       * while the handshake is still in progress (see dtls_srtp.c). This case
       * must therefore be re-entered — state stays CONNECTED — on later
       * peer_connection_loop() ticks rather than blocking here until the
       * handshake finishes or times out. That is what stops one peer's DTLS
       * handshake (e.g. hung because a browser vanished mid-connect) from
       * freezing every OTHER peer's turn on the single-threaded signaling
       * reactor for up to DTLS_HANDSHAKE_TIMEOUT_S (15s) — previously the
       * do/while inside dtls_srtp_do_handshake() ran entirely inside this one
       * call before returning control here. */
      if (!pc->b_dtls_handshake_logged) {
        LOGI("Starting DTLS handshake (PEER_CONNECTION_CONNECTED)");
        pc->b_dtls_handshake_logged = 1;
      }

      int dtls_ret = dtls_srtp_handshake(&pc->dtls_srtp, &pc->agent.selected_pair->remote->addr);

      if (dtls_ret == DTLS_SRTP_HS_WANT) {
        /* Not done yet — stay in CONNECTED and yield back to the reactor so
         * every other peer gets its turn this tick; we resume the handshake
         * (dtls_srtp's internal state/deadline persist) next time we're
         * called. */
        break;
      }

      if (dtls_ret == 0) {
        LOGD("DTLS-SRTP handshake done");

        /* Half-open-peer diagnostic baseline (see the struct field comment):
         * stamp the moment DTLS finished so a later stuck-SCTP retransmit loop
         * can report how long this peer has been half-open. */
        pc->dtls_complete_ms = ports_get_epoch_time();
        pc->sctp_retransmit_count = 0;
        pc->b_half_open_logged = 0;

        if (pc->config.datachannel) {
          LOGI("SCTP create socket");
          sctp_create_association(&pc->sctp, &pc->dtls_srtp);
          pc->sctp.userdata = pc->config.user_data;
        }

        STATE_CHANGED(pc, PEER_CONNECTION_COMPLETED);
      } else {
        /* DTLS handshake failed - move to FAILED state to stop retrying */
        LOGE("DTLS handshake failed with error %d, connection failed", dtls_ret);
        STATE_CHANGED(pc, PEER_CONNECTION_FAILED);
      }
      break;
    }
    case PEER_CONNECTION_COMPLETED: {
      /* TEMP INSTRUMENT (pc.loop phase decomposition — see PC_LOOP_SLOW_MS
       * above): per-phase wall-clock accumulators for THIS call of
       * peer_connection_loop(), same clock (ports_get_epoch_time, ms) as the
       * caller's "slow pc.loop" timer in sigshell.c. Reset every call; the
       * pl_rtx_* pair is __thread (nested through incoming_rtcp/handle_nack)
       * and reset here too. Logged once at the end of this case iff the
       * case's total wall time exceeds PC_LOOP_SLOW_MS — no per-call spam. */
      uint32_t pl_case_start_ms = ports_get_epoch_time();
      uint32_t pl_recv_ms = 0, pl_dtls_resend_ms = 0, pl_rtcp_ms = 0,
               pl_dtls_read_ms = 0, pl_rtp_ms = 0,
               pl_sr_lockwait_ms = 0, pl_sr_send_ms = 0;
      pl_rtx_lockwait_ms = 0;
      pl_rtx_send_ms = 0;

      /* Drain all pending packets from the socket.
       * STUN consent requests arrive frequently (~16/sec) and we must respond
       * to all of them. agent_recv returns 0 for STUN (handled internally,
       * INCLUDING any consent-response send — there is no separate STUN send
       * call site at this level, so its cost is folded into pl_recv_ms),
       * >0 for data packets, <0 when no more data is available. */
      for (;;) {
        uint32_t pl_recv_t0 = ports_get_epoch_time();
        pc->agent_ret = agent_recv(&pc->agent, pc->agent_buf, sizeof(pc->agent_buf));
        pl_recv_ms += ports_get_epoch_time() - pl_recv_t0;
        if (pc->agent_ret < 0) break;

        if (pc->agent_ret == 0) {
          /* STUN packet was handled internally, continue draining */
          pc->in_stun_pkts++;
          continue;
        }
        pc->in_data_pkts++;

        LOGD("agent_recv %d", pc->agent_ret);

        if (pc->agent_buf[0] == 0x14 /* CCS */ || pc->agent_buf[0] == 0x16 /* handshake */) {
          /* A ChangeCipherSpec or handshake record arriving AFTER we reached
           * COMPLETED means the PEER's DTLS handshake did not finish: it is
           * retransmitting its last flight because it never received OUR final
           * flight (CCS+Finished lost in transit). This MUST be checked before
           * rtp_packet_validate — that classifier only inspects the RTP payload-
           * type bits and mis-claims a DTLS record (its 2nd byte 0xfe makes
           * pt==126, which passes `>= 96`), so a handshake retransmit would
           * otherwise be decoded as RTP and dropped, never reaching this
           * recovery. Real RTP/RTCP always has the version bit set (byte0 >=
           * 0x80), so 0x14/0x16 is unambiguously DTLS. mbedtls kept our last
           * flight for exactly this case (RFC 6347 §4.2.4) — resend it so a lost
           * final flight self-heals instead of wedging the data channel forever
           * (DTLS half-open, SCTP INIT retransmitted into the void, no video).
           * Guard on datachannel + SCTP-not-up: once the peer's DTLS completes it
           * sends app-data (0x17), not handshake records, so this goes quiet. */
          if (pc->config.datachannel && !sctp_is_connected(&pc->sctp)) {
            pc->sctp_retransmit_count++;
            LOGW("DTLS peer retransmitting flight post-complete (ct=0x%02x), SCTP down"
                 " — resending server final flight", pc->agent_buf[0]);
            {
              uint32_t pl_dr_t0 = ports_get_epoch_time();
              dtls_srtp_resend(&pc->dtls_srtp);
              pl_dtls_resend_ms += ports_get_epoch_time() - pl_dr_t0;
            }

            /* Orphan/half-open visibility: fire ONCE per peer, the first time
             * it's been stuck (DTLS up, SCTP never opened) for >3s. Low-volume
             * by design — this is what lets a bug report show orphaned peers
             * accumulating across a handful of browser refreshes without
             * re-introducing per-retransmit log spam (the LOGW above already
             * fires every retransmit; this does not). */
            if (!pc->b_half_open_logged) {
              uint32_t age_ms = ports_get_epoch_time() - pc->dtls_complete_ms;
              if (age_ms > 3000) {
                LOGI("peer half-open (DTLS up, SCTP down) age_ms=%u retransmits=%u",
                     age_ms, pc->sctp_retransmit_count);
                pc->b_half_open_logged = 1;
              }
            }
          }

        } else if (rtcp_probe(pc->agent_buf, pc->agent_ret)) {
          LOGD("Got RTCP packet");
          uint32_t pl_rtcp_t0 = ports_get_epoch_time();
          dtls_srtp_decrypt_rtcp_packet(&pc->dtls_srtp, pc->agent_buf, &pc->agent_ret);
          /* NOTE: peer_connection_incoming_rtcp may itself call
           * peer_connection_rtx_resend() (NACK -> RTX retransmit), which
           * accumulates into pl_rtx_lockwait_ms/pl_rtx_send_ms — so pl_rtcp_ms
           * below is a SUPERSET that includes any nested RTX resend time; the
           * two rtx_* fields in the final log break that portion back out. */
          peer_connection_incoming_rtcp(pc, pc->agent_buf, pc->agent_ret);
          pl_rtcp_ms += ports_get_epoch_time() - pl_rtcp_t0;

        } else if (dtls_srtp_probe(pc->agent_buf)) {
          /* Drain ssl_read until WANT_READ (returned as 0). mbedtls returns
           * ONE plaintext record per ssl_read call but a single UDP datagram
           * can carry multiple DTLS records — without the drain loop, every
           * record after the first in the same packet gets silently dropped
           * (it sits in mbedtls's internal buffer until the next BIO_recv
           * overwrites it). */
          int ret;
          uint32_t pl_dread_t0 = ports_get_epoch_time();
          do {
            ret = dtls_srtp_read(&pc->dtls_srtp, pc->temp_buf, sizeof(pc->temp_buf));
            LOGD("Got DTLS data %d", ret);
            if (ret > 0) {
              sctp_incoming_data(&pc->sctp, (char*)pc->temp_buf, ret);
            } else if (ret < 0) {
              /* dtls_srtp_read itself logs the mbedtls code; this LOGW marks
               * the corresponding inbound wire packet so the two can be
               * correlated when triaging silent drops. */
              LOGW("DTLS dispatch: dropping %d-byte wire packet (decrypt failed) a=%p ret=%d",
                   pc->agent_ret, (void*)&pc->sctp, ret);   /* TEMP: correlate to the wedged assoc */
            }
          } while (ret > 0);
          pl_dtls_read_ms += ports_get_epoch_time() - pl_dread_t0;

        } else if (rtp_packet_validate(pc->agent_buf, pc->agent_ret)) {
          LOGD("Got RTP packet");

          uint32_t pl_rtp_t0 = ports_get_epoch_time();
          dtls_srtp_decrypt_rtp_packet(&pc->dtls_srtp, pc->agent_buf, &pc->agent_ret);

          ssrc = rtp_get_ssrc(pc->agent_buf);
          if (ssrc == pc->remote_assrc) {
            rtp_decoder_decode(&pc->artp_decoder, pc->agent_buf, pc->agent_ret);
          } else if (ssrc == pc->remote_vssrc) {
            rtp_decoder_decode(&pc->vrtp_decoder, pc->agent_buf, pc->agent_ret);
          }
          pl_rtp_ms += ports_get_epoch_time() - pl_rtp_t0;

        } else {
          LOGW("Unknown data");
        }
      }

      if (CONFIG_KEEPALIVE_TIMEOUT > 0 && (ports_get_epoch_time() - pc->agent.binding_request_time) > CONFIG_KEEPALIVE_TIMEOUT) {
        LOGI("binding request timeout");
        STATE_CHANGED(pc, PEER_CONNECTION_CLOSED);
      }

      /* ── Periodic RTCP Sender Report ───────────────────────────────────
       * Send ~1 s SR for the video SSRC.  The SR's NTP↔RTP mapping lets
       * Chrome's RemoteNtpTimeEstimator cancel inter-machine clock skew so
       * requestVideoFrameCallback.captureTime is skew-free.
       * Only emitted if we've sent at least one RTP packet (sr_packets_sent > 0)
       * so we don't flood before the stream starts.                           */
      {
        uint32_t now_ms = ports_get_epoch_time();
        if (pc->sr_packets_sent > 0 &&
            (pc->last_sr_ms == 0 || (now_ms - pc->last_sr_ms) >= RTCP_SR_INTERVAL_MS)) {
          pc->last_sr_ms = now_ms;

          /* Use the most recent frame's (RTP, NTP) reference captured in
           * send_video. This is a true point in the WIRE RTP timebase paired
           * with its capture wall-clock, so the receiver's RTP↔NTP estimator
           * stays consistent with the per-packet RTP timestamps and with
           * abs-capture-time — even when the capture clock isn't CLOCK_MONOTONIC.
           * (Independently sampling clock_gettime here desynced the mapping from
           * the wire whenever capture_time_ns came from a foreign clock.)      */
          uint64_t ntp_now    = pc->sr_ref_ntp;
          uint32_t rtp_ts_now = pc->sr_ref_rtp;

          uint8_t sr_buf[28 + SRTP_MAX_TRAILER_LEN + 4];
          int sr_len = rtcp_build_sr(sr_buf, SSRC_H264, ntp_now, rtp_ts_now,
                                     pc->sr_packets_sent, pc->sr_octets_sent);
          /* TEMP INSTRUMENT (pc.loop phase decomposition): time the send_mtx
           * acquire separately from the locked encrypt+send. */
          uint32_t pl_sr_t0 = ports_get_epoch_time();
          pthread_mutex_lock(&pc->send_mtx);
          uint32_t pl_sr_t1 = ports_get_epoch_time();
          dtls_srtp_encrypt_rctp_packet(&pc->dtls_srtp, sr_buf, &sr_len);
          if (sr_len > 0) {
            agent_send(&pc->agent, sr_buf, (size_t)sr_len);
            LOGD("RTCP SR sent: ntp=0x%016llx rtp_ts=%u pkts=%u octets=%u",
                 (unsigned long long)ntp_now, rtp_ts_now,
                 pc->sr_packets_sent, pc->sr_octets_sent);
          }
          pthread_mutex_unlock(&pc->send_mtx);
          uint32_t pl_sr_t2 = ports_get_epoch_time();
          pl_sr_lockwait_ms += pl_sr_t1 - pl_sr_t0;
          pl_sr_send_ms += pl_sr_t2 - pl_sr_t1;
        }
      }

      /* TEMP INSTRUMENT (pc.loop phase decomposition — see PC_LOOP_SLOW_MS
       * above): one line, only when this call of the COMPLETED case ran long,
       * pinpointing which phase ate the time. rtcp_ms is a superset of
       * rtx_lockwait_ms+rtx_send_ms (see the note at the RTCP branch above). */
      {
        uint32_t pl_total_ms = ports_get_epoch_time() - pl_case_start_ms;
        if (pl_total_ms >= PC_LOOP_SLOW_MS) {
          LOGI("pc.loop slow dur_ms=%u [recv=%u dtlsresend=%u rtcp=%u "
               "rtx_lockwait=%u rtx_send=%u dtlsread=%u rtp=%u "
               "sr_lockwait=%u sr_send=%u]",
               pl_total_ms, pl_recv_ms, pl_dtls_resend_ms, pl_rtcp_ms,
               pl_rtx_lockwait_ms, pl_rtx_send_ms, pl_dtls_read_ms, pl_rtp_ms,
               pl_sr_lockwait_ms, pl_sr_send_ms);
        }
      }

      break;
    }
    case PEER_CONNECTION_FAILED:
      break;
    case PEER_CONNECTION_DISCONNECTED:
      break;
    case PEER_CONNECTION_CLOSED:
      break;
    default:
      break;
  }

  return 0;
}

void peer_connection_set_remote_description(PeerConnection* pc, const char* sdp, SdpType type) {
  char* start = (char*)sdp;
  char* line = NULL;
  char buf[256];
  char* val_start = NULL;
  uint32_t* ssrc = NULL;
  DtlsSrtpRole role = DTLS_SRTP_ROLE_SERVER;
  int is_update = 0;
  Agent* agent = &pc->agent;

  while ((line = strstr(start, "\r\n"))) {
    line = strstr(start, "\r\n");
    strncpy(buf, start, line - start);
    buf[line - start] = '\0';

    if (strstr(buf, "a=setup:passive")) {
      role = DTLS_SRTP_ROLE_CLIENT;
    }

    if (strstr(buf, "a=fingerprint")) {
      strncpy(pc->dtls_srtp.remote_fingerprint, buf + 22, DTLS_SRTP_FINGERPRINT_LENGTH);
    }

    if (strstr(buf, "a=ice-ufrag") &&
        strlen(agent->remote_ufrag) != 0 &&
        (strncmp(buf + strlen("a=ice-ufrag:"), agent->remote_ufrag, strlen(agent->remote_ufrag)) == 0)) {
      is_update = 1;
    }

    if (strstr(buf, "m=video")) {
      ssrc = &pc->remote_vssrc;
    } else if (strstr(buf, "m=audio")) {
      ssrc = &pc->remote_assrc;
    }

    if ((val_start = strstr(buf, "a=ssrc:")) && ssrc) {
      *ssrc = strtoul(val_start + 7, NULL, 10);
      LOGD("SSRC: %" PRIu32, *ssrc);
    }

    start = line + 2;
  }

  if (is_update) {
    return;
  }

  agent_set_remote_description(&pc->agent, (char*)sdp);
  if (type == SDP_TYPE_ANSWER) {
    agent_update_candidate_pairs(&pc->agent);
    STATE_CHANGED(pc, PEER_CONNECTION_CHECKING);
  }
}

static const char* peer_connection_create_sdp(PeerConnection* pc, SdpType sdp_type) {
  char* description = (char*)pc->temp_buf;

  memset(pc->temp_buf, 0, sizeof(pc->temp_buf));
  DtlsSrtpRole role = DTLS_SRTP_ROLE_SERVER;

  pc->sctp.connected = 0;

  switch (sdp_type) {
    case SDP_TYPE_OFFER:
      role = DTLS_SRTP_ROLE_SERVER;
      agent_clear_candidates(&pc->agent);
      pc->agent.mode = AGENT_MODE_CONTROLLING;
      break;
    case SDP_TYPE_ANSWER:
      role = DTLS_SRTP_ROLE_CLIENT;
      pc->agent.mode = AGENT_MODE_CONTROLLED;
      break;
    default:
      break;
  }

  dtls_srtp_reset_session(&pc->dtls_srtp);
  dtls_srtp_init(&pc->dtls_srtp, role, pc);
  pc->dtls_srtp.udp_recv = peer_connection_dtls_srtp_recv;
  pc->dtls_srtp.udp_send = peer_connection_dtls_srtp_send;

  memset(pc->sdp, 0, sizeof(pc->sdp));
  // TODO: check if we have video or audio codecs
  sdp_create(pc->sdp,
             pc->config.video_codec != CODEC_NONE,
             pc->config.audio_codec != CODEC_NONE,
             pc->config.datachannel);

  agent_create_ice_credential(&pc->agent);
  sdp_append(pc->sdp, "a=ice-ufrag:%s", pc->agent.local_ufrag);
  sdp_append(pc->sdp, "a=ice-pwd:%s", pc->agent.local_upwd);
  sdp_append(pc->sdp, "a=fingerprint:sha-256 %s", pc->dtls_srtp.local_fingerprint);
  sdp_append(pc->sdp, peer_connection_dtls_role_setup_value(role));

  if (pc->config.video_codec == CODEC_H264) {
    if (pc->config.fec)
      sdp_append_h264_fec(pc->sdp);
    else if (pc->config.rtx && pc->rtx_history)
      sdp_append_h264_rtx(pc->sdp);
    else
      sdp_append_h264(pc->sdp);
  }

  switch (pc->config.audio_codec) {
    case CODEC_PCMA:
      sdp_append_pcma(pc->sdp);
      break;
    case CODEC_PCMU:
      sdp_append_pcmu(pc->sdp);
      break;
    case CODEC_OPUS:
      sdp_append_opus(pc->sdp);
    default:
      break;
  }

  if (pc->config.datachannel) {
    sdp_append_datachannel(pc->sdp);
  }

  pc->b_local_description_created = 1;

  agent_gather_candidate(&pc->agent, NULL, NULL, NULL);  // host address

  /* Inject an extra host candidate when host_candidate_override is set (e.g.
   * "127.0.0.1:PORT" so a browser on the Docker host can reach the mapped
   * port without needing STUN/TURN).  The override candidate shares the same
   * UDP socket — the port in the string must match the socket's bound port. */
  if (pc->config.host_candidate_override[0] != '\0') {
    char override_ip[ADDRSTRLEN];
    int  override_port = 0;
    const char* colon = strrchr(pc->config.host_candidate_override, ':');
    if (colon && colon != pc->config.host_candidate_override) {
      size_t ip_len = (size_t)(colon - pc->config.host_candidate_override);
      if (ip_len < sizeof(override_ip)) {
        memcpy(override_ip, pc->config.host_candidate_override, ip_len);
        override_ip[ip_len] = '\0';
        override_port = atoi(colon + 1);
      }
    }
    if (override_port > 0) {
      Address override_addr;
      memset(&override_addr, 0, sizeof(override_addr));
      override_addr.family = AF_INET;
      override_addr.sin.sin_family = AF_INET;
      override_addr.sin.sin_addr.s_addr = inet_addr(override_ip);
      override_addr.sin.sin_port = htons((uint16_t)override_port);
      override_addr.port = override_port;
      IceCandidate* cand = pc->agent.local_candidates + pc->agent.local_candidates_count;
      ice_candidate_create(cand, pc->agent.local_candidates_count, ICE_CANDIDATE_TYPE_HOST, &override_addr);
      pc->agent.local_candidates_count++;
      LOGI("Added host candidate override: %s:%d", override_ip, override_port);
    }
  }

  for (int i = 0; i < sizeof(pc->config.ice_servers) / sizeof(pc->config.ice_servers[0]); ++i) {
    if (pc->config.ice_servers[i].urls) {
      LOGI("ice server: %s", pc->config.ice_servers[i].urls);
      agent_gather_candidate(&pc->agent, pc->config.ice_servers[i].urls, pc->config.ice_servers[i].username, pc->config.ice_servers[i].credential);
    }
  }

  agent_get_local_description(&pc->agent, description, sizeof(pc->temp_buf));
  sdp_append(pc->sdp, description);

  if (pc->onicecandidate) {
    pc->onicecandidate(pc->sdp, pc->config.user_data);
  }

  return pc->sdp;
}

const char* peer_connection_create_offer(PeerConnection* pc) {
  return peer_connection_create_sdp(pc, SDP_TYPE_OFFER);
}

const char* peer_connection_create_answer(PeerConnection* pc) {
  const char* sdp = peer_connection_create_sdp(pc, SDP_TYPE_ANSWER);
  agent_update_candidate_pairs(&pc->agent);
  STATE_CHANGED(pc, PEER_CONNECTION_CHECKING);
  return sdp;
}

int peer_connection_send_rtcp_pil(PeerConnection* pc, uint32_t ssrc) {
  int ret = -1;
  uint8_t plibuf[128];
  rtcp_get_pli(plibuf, 12, ssrc);

  // TODO: encrypt rtcp packet
  // guint size = 12;
  // dtls_transport_encrypt_rctp_packet(pc->dtls_transport, plibuf, &size);
  // ret = nice_agent_send(pc->nice_agent, pc->stream_id, pc->component_id, size, (gchar*)plibuf);

  return ret;
}

// callbacks
void peer_connection_on_connected(PeerConnection* pc, void (*on_connected)(void* userdata)) {
  pc->on_connected = on_connected;
}

void peer_connection_on_receiver_packet_loss(PeerConnection* pc,
                                             void (*on_receiver_packet_loss)(float fraction_loss, uint32_t total_loss, void* userdata)) {
  pc->on_receiver_packet_loss = on_receiver_packet_loss;
}

void peer_connection_on_remb(PeerConnection* pc,
                             void (*on_remb)(uint32_t bitrate_bps, void* userdata)) {
  pc->on_remb = on_remb;
}

int peer_connection_get_capture_ref(PeerConnection* pc, uint32_t* rtp, uint64_t* ntp) {
  if (!pc || !rtp || !ntp || pc->sr_ref_ntp == 0)
    return -1;  /* no video frame sent yet → no reference */
  *rtp = pc->sr_ref_rtp;
  *ntp = pc->sr_ref_ntp;
  return 0;
}

void peer_connection_onicecandidate(PeerConnection* pc, void (*onicecandidate)(char* sdp, void* userdata)) {
  pc->onicecandidate = onicecandidate;
}

void peer_connection_oniceconnectionstatechange(PeerConnection* pc,
                                                void (*oniceconnectionstatechange)(PeerConnectionState state, void* userdata)) {
  pc->oniceconnectionstatechange = oniceconnectionstatechange;
}

void peer_connection_ondatachannel(PeerConnection* pc,
                                   void (*onmessage)(char* msg, size_t len, void* userdata, uint16_t sid),
                                   void (*onopen)(void* userdata),
                                   void (*onclose)(void* userdata)) {
  if (pc) {
    sctp_onopen(&pc->sctp, onopen);
    sctp_onclose(&pc->sctp, onclose);
    sctp_onmessage(&pc->sctp, onmessage);
  }
}

int peer_connection_lookup_sid(PeerConnection* pc, const char* label, uint16_t* sid) {
  for (int i = 0; i < pc->sctp.stream_count; i++) {
    if (strncmp(pc->sctp.stream_table[i].label, label, sizeof(pc->sctp.stream_table[i].label)) == 0) {
      *sid = pc->sctp.stream_table[i].sid;
      return 0;
    }
  }
  return -1;  // Not found
}

char* peer_connection_lookup_sid_label(PeerConnection* pc, uint16_t sid) {
  for (int i = 0; i < pc->sctp.stream_count; i++) {
    if (pc->sctp.stream_table[i].sid == sid) {
      return pc->sctp.stream_table[i].label;
    }
  }
  return NULL;  // Not found
}

int peer_connection_add_ice_candidate(PeerConnection* pc, char* candidate) {
  Agent* agent = &pc->agent;
  char mdns_hostname[128];
  int parsed, i;

  if (agent->remote_candidates_count >= AGENT_MAX_CANDIDATES) {
    LOGW("Remote candidate table full; ignoring trickled candidate");
    return -1;
  }
  IceCandidate* slot = &agent->remote_candidates[agent->remote_candidates_count];
  parsed = ice_candidate_from_description(slot, candidate, candidate + strlen(candidate),
                                          mdns_hostname, sizeof(mdns_hostname));
  if (parsed < 0) {
    return -1;
  }
  if (parsed == 1) {
    /* .local candidate: resolve asynchronously; promoted + paired on resolve. */
    agent_queue_mdns_candidate(agent, slot, mdns_hostname);
    return 0;
  }

  /* Dedupe by foundation, same rule as the SDP parse path (a candidate often
   * arrives both in the answer SDP and as a trickle). */
  for (i = 0; i < agent->remote_candidates_count; i++) {
    if (strcmp(agent->remote_candidates[i].foundation, slot->foundation) == 0) {
      return 0;
    }
  }

  LOGD("Add candidate: %s", candidate);
  agent->remote_candidates_count++;
  /* Pair it now. Trickled candidates land AFTER the answer-time
   * agent_update_candidate_pairs() (the only bulk pairing call), so without
   * this they sat in the table unpaired and were never checked. */
  agent_pair_remote_candidate(agent, slot);
  return 0;
}
