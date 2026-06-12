#include <stdarg.h>
#include <stdio.h>

#include "sdp.h"

int sdp_append(char* sdp, const char* format, ...) {
  va_list argptr;

  va_start(argptr, format);

  if (sdp[0] == '\0') {
    vsnprintf(sdp, CONFIG_SDP_BUFFER_SIZE, format, argptr);
  } else {
    vsnprintf(sdp + strlen(sdp), CONFIG_SDP_BUFFER_SIZE - strlen(sdp), format, argptr);
  }

  if (sdp[strlen(sdp) - 1] != '\n') {
    strcat(sdp, "\r\n");
  }

  va_end(argptr);
  return 0;
}

void sdp_reset(char* sdp) {
  memset(sdp, 0, CONFIG_SDP_BUFFER_SIZE);
}

void sdp_append_h264(char* sdp) {
  sdp_append(sdp, "m=video 9 UDP/TLS/RTP/SAVPF 96");
  sdp_append(sdp, "c=IN IP4 0.0.0.0");
  sdp_append(sdp, "a=rtcp-fb:96 nack");
  sdp_append(sdp, "a=rtcp-fb:96 nack pli");
  /* goog-remb + abs-send-time (id 3, == RTP_EXT_ID_ABS_SEND_TIME). Asks the
   * browser to run receive-side BWE and report it via RTCP AFB(REMB); the
   * abs-send-time header ext (stamped per packet in peer_connection_outgoing_rtp_packet)
   * is the per-packet send time its estimator needs. We deliberately do NOT
   * offer transport-cc, so the browser falls back to REMB (ratecore §0/D1). */
  sdp_append(sdp, "a=rtcp-fb:96 goog-remb");
  sdp_append(sdp, "a=extmap:3 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time");
  sdp_append(sdp, "a=extmap:4 http://www.webrtc.org/experiments/rtp-hdrext/abs-capture-time");
  sdp_append(sdp, "a=fmtp:96 profile-level-id=42e01f;level-asymmetry-allowed=1;packetization-mode=1");
  sdp_append(sdp, "a=rtpmap:96 H264/90000");
  sdp_append(sdp, "a=ssrc:1 cname:webrtc-h264");
  sdp_append(sdp, "a=sendrecv");
  sdp_append(sdp, "a=mid:video");
  sdp_append(sdp, "a=rtcp-mux");
}

/* Same as sdp_append_h264 but additionally offers RTX retransmissions
 * (RFC 4588): rtx/90000 with apt=96 on a second SSRC bound to the media SSRC
 * via ssrc-group:FID. Both Chrome and Firefox negotiate and use this by
 * default — their NACKs (which we now answer) drive loss repair in one RTT. */
void sdp_append_h264_rtx(char* sdp) {
  sdp_append(sdp, "m=video 9 UDP/TLS/RTP/SAVPF 96 97");
  sdp_append(sdp, "c=IN IP4 0.0.0.0");
  sdp_append(sdp, "a=rtcp-fb:96 nack");
  sdp_append(sdp, "a=rtcp-fb:96 nack pli");
  sdp_append(sdp, "a=rtcp-fb:96 goog-remb");
  sdp_append(sdp, "a=extmap:3 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time");
  sdp_append(sdp, "a=extmap:4 http://www.webrtc.org/experiments/rtp-hdrext/abs-capture-time");
  sdp_append(sdp, "a=fmtp:96 profile-level-id=42e01f;level-asymmetry-allowed=1;packetization-mode=1");
  sdp_append(sdp, "a=rtpmap:96 H264/90000");
  sdp_append(sdp, "a=rtpmap:97 rtx/90000");
  sdp_append(sdp, "a=fmtp:97 apt=96");
  sdp_append(sdp, "a=ssrc-group:FID 1 2");
  sdp_append(sdp, "a=ssrc:1 cname:webrtc-h264");
  sdp_append(sdp, "a=ssrc:2 cname:webrtc-h264");
  sdp_append(sdp, "a=sendrecv");
  sdp_append(sdp, "a=mid:video");
  sdp_append(sdp, "a=rtcp-mux");
}

/* Same as sdp_append_h264 but advertises RED (RFC 2198) + ULPFEC (RFC 5109)
 * and sends media RED-encapsulated. One m-line, same SSRC; the browser
 * de-REDs and uses the FEC packets for XOR recovery — the only FEC the
 * big three browsers all support receiving (flexfec is Chrome-only). */
void sdp_append_h264_fec(char* sdp) {
  sdp_append(sdp, "m=video 9 UDP/TLS/RTP/SAVPF 96 118 119");
  sdp_append(sdp, "c=IN IP4 0.0.0.0");
  sdp_append(sdp, "a=rtcp-fb:96 nack");
  sdp_append(sdp, "a=rtcp-fb:96 nack pli");
  sdp_append(sdp, "a=rtcp-fb:96 goog-remb");
  sdp_append(sdp, "a=extmap:3 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time");
  sdp_append(sdp, "a=extmap:4 http://www.webrtc.org/experiments/rtp-hdrext/abs-capture-time");
  sdp_append(sdp, "a=fmtp:96 profile-level-id=42e01f;level-asymmetry-allowed=1;packetization-mode=1");
  sdp_append(sdp, "a=rtpmap:96 H264/90000");
  sdp_append(sdp, "a=rtpmap:118 red/90000");
  sdp_append(sdp, "a=rtpmap:119 ulpfec/90000");
  sdp_append(sdp, "a=ssrc:1 cname:webrtc-h264");
  sdp_append(sdp, "a=sendrecv");
  sdp_append(sdp, "a=mid:video");
  sdp_append(sdp, "a=rtcp-mux");
}

void sdp_append_pcma(char* sdp) {
  sdp_append(sdp, "m=audio 9 UDP/TLS/RTP/SAVP 8");
  sdp_append(sdp, "c=IN IP4 0.0.0.0");
  sdp_append(sdp, "a=rtpmap:8 PCMA/8000");
  sdp_append(sdp, "a=ssrc:4 cname:webrtc-pcma");
  sdp_append(sdp, "a=sendrecv");
  sdp_append(sdp, "a=mid:audio");
  sdp_append(sdp, "a=rtcp-mux");
}

void sdp_append_pcmu(char* sdp) {
  sdp_append(sdp, "m=audio 9 UDP/TLS/RTP/SAVP 0");
  sdp_append(sdp, "c=IN IP4 0.0.0.0");
  sdp_append(sdp, "a=rtpmap:0 PCMU/8000");
  sdp_append(sdp, "a=ssrc:5 cname:webrtc-pcmu");
  sdp_append(sdp, "a=sendrecv");
  sdp_append(sdp, "a=mid:audio");
  sdp_append(sdp, "a=rtcp-mux");
}

void sdp_append_opus(char* sdp) {
  sdp_append(sdp, "m=audio 9 UDP/TLS/RTP/SAVP 111");
  sdp_append(sdp, "c=IN IP4 0.0.0.0");
  sdp_append(sdp, "a=rtpmap:111 opus/48000/2");
  sdp_append(sdp, "a=ssrc:6 cname:webrtc-opus");
  sdp_append(sdp, "a=sendrecv");
  sdp_append(sdp, "a=mid:audio");
  sdp_append(sdp, "a=rtcp-mux");
}

void sdp_append_datachannel(char* sdp) {
  sdp_append(sdp, "m=application 50712 UDP/DTLS/SCTP webrtc-datachannel");
  sdp_append(sdp, "c=IN IP4 0.0.0.0");
  sdp_append(sdp, "a=mid:datachannel");
  sdp_append(sdp, "a=sctp-port:5000");
  sdp_append(sdp, "a=max-message-size:262144");
}

void sdp_create(char* sdp, int b_video, int b_audio, int b_datachannel) {
  char bundle[64];
  sdp_append(sdp, "v=0");
  sdp_append(sdp, "o=- 1495799811084970 1495799811084970 IN IP4 0.0.0.0");
  sdp_append(sdp, "s=-");
  sdp_append(sdp, "t=0 0");
  sdp_append(sdp, "a=msid-semantic: iot");
#if ICE_LITE
  sdp_append(sdp, "a=ice-lite");
#endif
  memset(bundle, 0, sizeof(bundle));

  strcat(bundle, "a=group:BUNDLE");

  if (b_video) {
    strcat(bundle, " video");
  }

  if (b_audio) {
    strcat(bundle, " audio");
  }

  if (b_datachannel) {
    strcat(bundle, " datachannel");
  }

  sdp_append(sdp, bundle);
}
