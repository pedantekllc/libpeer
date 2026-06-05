#ifndef RTCP_H_
#define RTCP_H_

#include <stddef.h>
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

typedef enum RtcpType {

  RTCP_FIR = 192,
  RTCP_SR = 200,
  RTCP_RR = 201,
  RTCP_SDES = 202,
  RTCP_BYE = 203,
  RTCP_APP = 204,
  RTCP_RTPFB = 205,
  RTCP_PSFB = 206,
  RTCP_XR = 207,

} RtcpType;

typedef struct RtcpHeader {
#if __BYTE_ORDER == __BIG_ENDIAN
  uint16_t version : 2;
  uint16_t padding : 1;
  uint16_t rc : 5;
  uint16_t type : 8;
#elif __BYTE_ORDER == __LITTLE_ENDIAN
  uint16_t rc : 5;
  uint16_t padding : 1;
  uint16_t version : 2;
  uint16_t type : 8;
#endif
  uint16_t length : 16;

} RtcpHeader;

typedef struct RtcpReportBlock {
  uint32_t ssrc;
  uint32_t flcnpl;
  uint32_t ehsnr;
  uint32_t jitter;
  uint32_t lsr;
  uint32_t dlsr;

} RtcpReportBlock;

typedef struct RtcpRr {
  RtcpHeader header;
  uint32_t ssrc;
  RtcpReportBlock report_block[1];

} RtcpRr;

typedef struct RtcpFir {
  uint32_t ssrc;
  uint32_t seqnr;

} RtcpFir;

typedef struct RtcpFb {
  RtcpHeader header;
  uint32_t ssrc;
  uint32_t media;
  char fci[1];

} RtcpFb;

int rtcp_probe(uint8_t* packet, size_t size);

int rtcp_get_pli(uint8_t* packet, int len, uint32_t ssrc);

int rtcp_get_fir(uint8_t* packet, int len, int* seqnr);

RtcpRr rtcp_parse_rr(uint8_t* packet);

/* Parse a goog-remb RTCP PSFB (PT=206, fmt=15). `pkt` points at the RTCP
 * header; `len` is the bytes available from there. On a well-formed REMB,
 * writes the decoded bitrate (mantissa << exp) to *out_bps and returns 1.
 * Returns 0 if `pkt` is not a REMB or is truncated. Pure parser — golden
 * vector tested in test_rtp_ext.c. */
int rtcp_parse_remb(const uint8_t* pkt, size_t len, uint32_t* out_bps);

/* Build an RTCP Sender Report (PT=200, RFC 3550 §6.4.1) into `buf`.
 * `buf` must be at least 28 bytes.  Returns 28 (the fixed SR size).
 *
 * Parameters:
 *   ssrc          : sender SSRC of the media stream
 *   ntp_ts        : 64-bit NTP wall-clock timestamp (high32=seconds since 1900,
 *                   low32=fraction)  — call unix_ns_to_ntp() to produce this
 *   rtp_ts        : RTP timestamp a frame captured "now" would carry; MUST use
 *                   the SAME formula as the wire RTP timestamps so the browser's
 *                   RTP↔NTP mapping is correct: (mono_ns * 90000 / 1e9)
 *   packets_sent  : cumulative RTP packets sent for this SSRC
 *   octets_sent   : cumulative RTP payload octets sent for this SSRC
 *
 * The result is a plain (unencrypted) RTCP packet; caller must SRTP-protect it
 * via dtls_srtp_encrypt_rctp_packet() before sending.                          */
int rtcp_build_sr(uint8_t* buf, uint32_t ssrc, uint64_t ntp_ts, uint32_t rtp_ts,
                  uint32_t packets_sent, uint32_t octets_sent);

#endif  // RTCP_H_
