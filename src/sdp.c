#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include "rtp.h"
#include "sdp.h"
#include "twcc.h"

/* transport-wide congestion control, offered on every media section: the
 * feedback request for the media payload type and the sequence-number
 * extension that feedback refers to. */
static void sdp_append_transport_cc(char* sdp, int pt) {
  sdp_append(sdp, "a=rtcp-fb:%d transport-cc", pt);
  sdp_append(sdp, "a=extmap:%d %s", RTP_EXT_ID_TRANSPORT_CC, TWCC_EXTMAP_URI);
}

int sdp_find_extmap_id(const char* sdp, const char* uri, uint8_t* id) {
  size_t uri_len = strlen(uri);
  const char* line = sdp;
  while (line && *line) {
    const char* eol = strstr(line, "\r\n");
    size_t len = eol ? (size_t)(eol - line) : strlen(line);
    if (len > 9 && strncmp(line, "a=extmap:", 9) == 0) {
      char* end = NULL;
      long v = strtol(line + 9, &end, 10);
      /* "a=extmap:<id>[/<direction>] <uri>[ <attributes>]" */
      const char* sp = memchr(line, ' ', len);
      if (end != line + 9 && v >= 1 && v <= 14 && sp) {
        const char* u = sp + 1;
        size_t rest = len - (size_t)(u - line);
        if (rest >= uri_len && strncmp(u, uri, uri_len) == 0 && (rest == uri_len || u[uri_len] == ' ')) {
          *id = (uint8_t)v;
          return 1;
        }
      }
    }
    line = eol ? eol + 2 : NULL;
  }
  return 0;
}

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
  sdp_append_transport_cc(sdp, 96);
  sdp_append(sdp, "a=extmap:4 http://www.webrtc.org/experiments/rtp-hdrext/abs-capture-time");
  sdp_append(sdp, "a=extmap:%d %s", RTP_EXT_ID_PLAYOUT_DELAY, RTP_PLAYOUT_DELAY_URI);
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
  sdp_append_transport_cc(sdp, 96);
  sdp_append(sdp, "a=extmap:4 http://www.webrtc.org/experiments/rtp-hdrext/abs-capture-time");
  sdp_append(sdp, "a=extmap:%d %s", RTP_EXT_ID_PLAYOUT_DELAY, RTP_PLAYOUT_DELAY_URI);
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
  sdp_append_transport_cc(sdp, 96);
  sdp_append(sdp, "a=extmap:4 http://www.webrtc.org/experiments/rtp-hdrext/abs-capture-time");
  sdp_append(sdp, "a=extmap:%d %s", RTP_EXT_ID_PLAYOUT_DELAY, RTP_PLAYOUT_DELAY_URI);
  sdp_append(sdp, "a=fmtp:96 profile-level-id=42e01f;level-asymmetry-allowed=1;packetization-mode=1");
  sdp_append(sdp, "a=rtpmap:96 H264/90000");
  sdp_append(sdp, "a=rtpmap:118 red/90000");
  sdp_append(sdp, "a=rtpmap:119 ulpfec/90000");
  sdp_append(sdp, "a=ssrc:1 cname:webrtc-h264");
  sdp_append(sdp, "a=sendrecv");
  sdp_append(sdp, "a=mid:video");
  sdp_append(sdp, "a=rtcp-mux");
}

/* H.265 video m-section (RFC 7798). Same feedback, extmaps and ssrc lines as
 * H.264 on PT_H265; `rtx` adds the RFC 4588 pair (apt=98) and `fec` adds
 * RED + ULPFEC. fmtp carries the RFC 7798 §7.1 receive parameters at their
 * defaults, spelled out the way Chromium offers them (level-id 93 = level 3.1,
 * profile-id 1 = Main, tier-flag 0 = Main tier, tx-mode SRST = single RTP
 * stream/single session); VPS/SPS/PPS travel in-band, so no sprop-* is sent. */
static void sdp_append_h265_section(char* sdp, int rtx, int fec) {
  const char* extra_pts = rtx ? " 97" : (fec ? " 118 119" : "");
  sdp_append(sdp, "m=video 9 UDP/TLS/RTP/SAVPF %d%s", PT_H265, extra_pts);
  sdp_append(sdp, "c=IN IP4 0.0.0.0");
  sdp_append(sdp, "a=rtcp-fb:%d nack", PT_H265);
  sdp_append(sdp, "a=rtcp-fb:%d nack pli", PT_H265);
  sdp_append_transport_cc(sdp, PT_H265);
  sdp_append(sdp, "a=extmap:4 http://www.webrtc.org/experiments/rtp-hdrext/abs-capture-time");
  sdp_append(sdp, "a=extmap:%d %s", RTP_EXT_ID_PLAYOUT_DELAY, RTP_PLAYOUT_DELAY_URI);
  sdp_append(sdp, "a=fmtp:%d level-id=93;profile-id=1;tier-flag=0;tx-mode=SRST", PT_H265);
  sdp_append(sdp, "a=rtpmap:%d H265/90000", PT_H265);
  if (rtx) {
    sdp_append(sdp, "a=rtpmap:%d rtx/90000", PT_RTX);
    sdp_append(sdp, "a=fmtp:%d apt=%d", PT_RTX, PT_H265);
    sdp_append(sdp, "a=ssrc-group:FID 1 2");
  }
  if (fec) {
    sdp_append(sdp, "a=rtpmap:%d red/90000", PT_RED);
    sdp_append(sdp, "a=rtpmap:%d ulpfec/90000", PT_ULPFEC);
  }
  sdp_append(sdp, "a=ssrc:1 cname:webrtc-h265");
  if (rtx) {
    sdp_append(sdp, "a=ssrc:2 cname:webrtc-h265");
  }
  sdp_append(sdp, "a=sendrecv");
  sdp_append(sdp, "a=mid:video");
  sdp_append(sdp, "a=rtcp-mux");
}

void sdp_append_h265(char* sdp) {
  sdp_append_h265_section(sdp, 0, 0);
}

void sdp_append_h265_rtx(char* sdp) {
  sdp_append_h265_section(sdp, 1, 0);
}

void sdp_append_h265_fec(char* sdp) {
  sdp_append_h265_section(sdp, 0, 1);
}

void sdp_append_pcma(char* sdp) {
  sdp_append(sdp, "m=audio 9 UDP/TLS/RTP/SAVP 8");
  sdp_append(sdp, "c=IN IP4 0.0.0.0");
  sdp_append(sdp, "a=rtpmap:8 PCMA/8000");
  sdp_append_transport_cc(sdp, 8);
  sdp_append(sdp, "a=ssrc:4 cname:webrtc-pcma");
  sdp_append(sdp, "a=sendrecv");
  sdp_append(sdp, "a=mid:audio");
  sdp_append(sdp, "a=rtcp-mux");
}

void sdp_append_pcmu(char* sdp) {
  sdp_append(sdp, "m=audio 9 UDP/TLS/RTP/SAVP 0");
  sdp_append(sdp, "c=IN IP4 0.0.0.0");
  sdp_append(sdp, "a=rtpmap:0 PCMU/8000");
  sdp_append_transport_cc(sdp, 0);
  sdp_append(sdp, "a=ssrc:5 cname:webrtc-pcmu");
  sdp_append(sdp, "a=sendrecv");
  sdp_append(sdp, "a=mid:audio");
  sdp_append(sdp, "a=rtcp-mux");
}

void sdp_append_opus(char* sdp) {
  sdp_append(sdp, "m=audio 9 UDP/TLS/RTP/SAVP 111");
  sdp_append(sdp, "c=IN IP4 0.0.0.0");
  sdp_append(sdp, "a=rtpmap:111 opus/48000/2");
  sdp_append_transport_cc(sdp, 111);
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
