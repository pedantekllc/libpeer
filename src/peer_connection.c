#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

/* Forward declaration for fragment state */
typedef struct dtls_fragment_state_s dtls_fragment_state_t;

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
};

static void peer_connection_outgoing_rtp_packet(uint8_t* data, size_t size, void* user_data) {
  PeerConnection* pc = (PeerConnection*)user_data;
  dtls_srtp_encrypt_rtp_packet(&pc->dtls_srtp, data, (int*)&size);
  agent_send(&pc->agent, data, size);
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

static int peer_connection_dtls_srtp_recv(void* ctx, unsigned char* buf, size_t len) {
  int recv_max = 0;
  int ret = -1;
  DtlsSrtp* dtls_srtp = (DtlsSrtp*)ctx;
  PeerConnection* pc = (PeerConnection*)dtls_srtp->user_data;
  dtls_fragment_state_t* frag = pc->frag_state;
  uint8_t recv_buf[2048];

  /* Check if there's already buffered data from agent */
  if (pc->agent_ret > 0 && pc->agent_ret <= len) {
    memcpy(buf, pc->agent_buf, pc->agent_ret);
    return pc->agent_ret;
  }

  while (recv_max < CONFIG_TLS_READ_TIMEOUT && pc->state == PEER_CONNECTION_CONNECTED) {
    ret = agent_recv(&pc->agent, recv_buf, sizeof(recv_buf));

    if (ret <= 0) {
      recv_max++;
      continue;
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

    /* Not complete yet, continue receiving more fragments */
    /* Don't increment recv_max here - we're actively reassembling */
  }

  return ret;
}

static int peer_connection_dtls_srtp_send(void* ctx, const uint8_t* buf, size_t len) {
  DtlsSrtp* dtls_srtp = (DtlsSrtp*)ctx;
  PeerConnection* pc = (PeerConnection*)dtls_srtp->user_data;

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
        LOGD("RTCP_PR");
        if (rtcp_header->rc > 0) {
// TODO: REMB, GCC ...etc
#if 0
          RtcpRr rtcp_rr = rtcp_parse_rr(buf);
          uint32_t fraction = ntohl(rtcp_rr.report_block[0].flcnpl) >> 24;
          uint32_t total = ntohl(rtcp_rr.report_block[0].flcnpl) & 0x00FFFFFF;
          if(pc->on_receiver_packet_loss && fraction > 0) {

            pc->on_receiver_packet_loss((float)fraction/256.0, total, pc->config.user_data);
          }
#endif
        }
        break;
      case RTCP_PSFB: {
        int fmt = rtcp_header->rc;
        LOGD("RTCP_PSFB %d", fmt);
        // PLI and FIR
        if ((fmt == 1 || fmt == 4) && pc->config.on_request_keyframe) {
          pc->config.on_request_keyframe(pc->config.user_data);
        }
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
    if (pc->frag_state) {
      free(pc->frag_state);
    }
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
    static int last_state_logged = -999;
    if (pc->state != last_state_logged) {
      LOGW("[ts-debug] send_video skipped: pc->state=%d (was %d)", pc->state, last_state_logged);
      last_state_logged = pc->state;
    }
    return -1;
  }
  {
    static uint32_t debug_count = 0;
    static uint64_t last_cap_ns = 0;
    static uint32_t last_rtp_ts = 0;
    static int last_state_logged_ok = -1;
    static uint64_t encode_total_ns = 0;
    static uint64_t encode_max_ns = 0;
    debug_count++;
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    int rc = rtp_encoder_encode(&pc->vrtp_encoder, buf, len, capture_time_ns);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    uint64_t dt = (uint64_t)(t1.tv_sec - t0.tv_sec) * 1000000000ULL
                + (uint64_t)(t1.tv_nsec - t0.tv_nsec);
    encode_total_ns += dt;
    if (dt > encode_max_ns) encode_max_ns = dt;

    uint32_t rtp_ts_now = pc->vrtp_encoder.timestamp;
    if (last_state_logged_ok != pc->state) {
      LOGW("[ts-debug] send_video OK: pc->state=COMPLETED");
      last_state_logged_ok = pc->state;
    }
    if (debug_count % 30 == 0 && last_cap_ns != 0) {
      uint64_t cap_dt_ns = capture_time_ns - last_cap_ns;
      uint32_t rtp_dt = rtp_ts_now - last_rtp_ts;
      double cap_dt_ms = cap_dt_ns / 1e6 / 30.0;
      double rtp_dt_per_call = (double)rtp_dt / 30.0;
      double encode_avg_ms = (double)encode_total_ns / debug_count / 1e6;
      double encode_max_ms = (double)encode_max_ns / 1e6;
      LOGI("[ts-debug] libpeer send_video #%u  cap_dt=%.3fms/frame  "
           "rtp_dt=%.1fticks/frame  encode_avg=%.3fms  encode_max=%.3fms",
           debug_count, cap_dt_ms, rtp_dt_per_call, encode_avg_ms, encode_max_ms);
    }
    if (debug_count % 30 == 0 || debug_count == 1) {
      last_cap_ns = capture_time_ns;
      last_rtp_ts = rtp_ts_now;
    }
    return rc;
  }
}

int peer_connection_datachannel_send(PeerConnection* pc, char* message, size_t len) {
  return peer_connection_datachannel_send_sid(pc, message, len, 0);
}

int peer_connection_datachannel_send_sid(PeerConnection* pc, char* message, size_t len, uint16_t sid) {
  if (!sctp_is_connected(&pc->sctp)) {
    LOGE("sctp not connected");
    return -1;
  }
  if (pc->config.datachannel == DATA_CHANNEL_STRING)
    return sctp_outgoing_data(&pc->sctp, message, len, PPID_STRING, sid);
  else
    return sctp_outgoing_data(&pc->sctp, message, len, PPID_BINARY, sid);
}

int peer_connection_datachannel_send_binary(PeerConnection* pc, const uint8_t* data, size_t len) {
  if (!sctp_is_connected(&pc->sctp)) {
    LOGE("sctp not connected");
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
    LOGE("sctp not connected");
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

  switch (pc->state) {
    case PEER_CONNECTION_NEW:
      break;

    case PEER_CONNECTION_CHECKING:
      if (agent_select_candidate_pair(&pc->agent) < 0) {
        STATE_CHANGED(pc, PEER_CONNECTION_FAILED);
      } else if (agent_connectivity_check(&pc->agent) == 0) {
        STATE_CHANGED(pc, PEER_CONNECTION_CONNECTED);
      }
      break;

    case PEER_CONNECTION_CONNECTED: {
      /* Pass the selected remote candidate's address to DTLS handshake.
       * This is critical for multi-client support - mbedtls uses the transport ID
       * (derived from this address) to distinguish between simultaneous DTLS sessions.
       * Without a unique transport ID per client, cookies and sessions get confused. */
      int dtls_ret = dtls_srtp_handshake(&pc->dtls_srtp, &pc->agent.selected_pair->remote->addr);
      if (dtls_ret == 0) {
        LOGD("DTLS-SRTP handshake done");

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
    case PEER_CONNECTION_COMPLETED:
      /* Drain all pending packets from the socket.
       * STUN consent requests arrive frequently (~16/sec) and we must respond
       * to all of them. agent_recv returns 0 for STUN (handled internally),
       * >0 for data packets, <0 when no more data is available. */
      while ((pc->agent_ret = agent_recv(&pc->agent, pc->agent_buf, sizeof(pc->agent_buf))) >= 0) {
        if (pc->agent_ret == 0) {
          /* STUN packet was handled internally, continue draining */
          continue;
        }

        LOGD("agent_recv %d", pc->agent_ret);

        if (rtcp_probe(pc->agent_buf, pc->agent_ret)) {
          LOGD("Got RTCP packet");
          dtls_srtp_decrypt_rtcp_packet(&pc->dtls_srtp, pc->agent_buf, &pc->agent_ret);
          peer_connection_incoming_rtcp(pc, pc->agent_buf, pc->agent_ret);

        } else if (dtls_srtp_probe(pc->agent_buf)) {
          int ret = dtls_srtp_read(&pc->dtls_srtp, pc->temp_buf, sizeof(pc->temp_buf));
          LOGD("Got DTLS data %d", ret);

          if (ret > 0) {
            sctp_incoming_data(&pc->sctp, (char*)pc->temp_buf, ret);
          }

        } else if (rtp_packet_validate(pc->agent_buf, pc->agent_ret)) {
          LOGD("Got RTP packet");

          dtls_srtp_decrypt_rtp_packet(&pc->dtls_srtp, pc->agent_buf, &pc->agent_ret);

          ssrc = rtp_get_ssrc(pc->agent_buf);
          if (ssrc == pc->remote_assrc) {
            rtp_decoder_decode(&pc->artp_decoder, pc->agent_buf, pc->agent_ret);
          } else if (ssrc == pc->remote_vssrc) {
            rtp_decoder_decode(&pc->vrtp_decoder, pc->agent_buf, pc->agent_ret);
          }

        } else {
          LOGW("Unknown data");
        }
      }

      if (CONFIG_KEEPALIVE_TIMEOUT > 0 && (ports_get_epoch_time() - pc->agent.binding_request_time) > CONFIG_KEEPALIVE_TIMEOUT) {
        LOGI("binding request timeout");
        STATE_CHANGED(pc, PEER_CONNECTION_CLOSED);
      }

      break;
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
  if (ice_candidate_from_description(&agent->remote_candidates[agent->remote_candidates_count], candidate, candidate + strlen(candidate)) != 0) {
    return -1;
  }
  LOGD("Add candidate: %s", candidate);
  agent->remote_candidates_count++;
  return 0;
}
