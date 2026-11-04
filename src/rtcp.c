#include <stdio.h>
#include <string.h>

#include "address.h"
#include "rtcp.h"
#include "rtp.h"

int rtcp_probe(uint8_t* packet, size_t size) {
  if (size < 8)
    return -1;

  RtpHeader* header = (RtpHeader*)packet;
  return ((header->type >= 64) && (header->type < 96));
}

int rtcp_get_pli(uint8_t* packet, int len, uint32_t ssrc) {
  if (packet == NULL || len != 12)
    return -1;

  memset(packet, 0, len);
  RtcpHeader* rtcp_header = (RtcpHeader*)packet;
  rtcp_header->version = 2;
  rtcp_header->type = RTCP_PSFB;
  rtcp_header->rc = 1;
  rtcp_header->length = htons((len / 4) - 1);
  memcpy(packet + 8, &ssrc, 4);

  return 12;
}

int rtcp_get_fir(uint8_t* packet, int len, int* seqnr) {
  if (packet == NULL || len != 20 || seqnr == NULL)
    return -1;

  memset(packet, 0, len);
  RtcpHeader* rtcp = (RtcpHeader*)packet;
  *seqnr = *seqnr + 1;
  if (*seqnr < 0 || *seqnr >= 256)
    *seqnr = 0;

  rtcp->version = 2;
  rtcp->type = RTCP_PSFB;
  rtcp->rc = 4;
  rtcp->length = htons((len / 4) - 1);
  RtcpFb* rtcp_fb = (RtcpFb*)rtcp;
  RtcpFir* fir = (RtcpFir*)rtcp_fb->fci;
  fir->seqnr = htonl(*seqnr << 24);

  return 20;
}

int rtcp_build_sr(uint8_t* buf, uint32_t ssrc, uint64_t ntp_ts, uint32_t rtp_ts,
                  uint32_t packets_sent, uint32_t octets_sent) {
  /* RFC 3550 §6.4.1 Sender Report layout (28 bytes, no report blocks):
   *   Byte  0    : V=2, P=0, RC=0          → 0x80
   *   Byte  1    : PT=200 (SR)
   *   Bytes 2-3  : length = 6 (28/4 - 1)
   *   Bytes 4-7  : sender SSRC
   *   Bytes 8-11 : NTP timestamp high 32 bits (seconds since 1900)
   *   Bytes 12-15: NTP timestamp low  32 bits (fraction)
   *   Bytes 16-19: RTP timestamp
   *   Bytes 20-23: sender packet count
   *   Bytes 24-27: sender octet count                                          */
  memset(buf, 0, 28);
  buf[0] = 0x80;                          /* V=2, P=0, RC=0 */
  buf[1] = 200;                           /* PT = SR */
  buf[2] = 0x00; buf[3] = 0x06;          /* length = 6 words */
  /* SSRC */
  buf[4]  = (uint8_t)((ssrc >> 24) & 0xFF);
  buf[5]  = (uint8_t)((ssrc >> 16) & 0xFF);
  buf[6]  = (uint8_t)((ssrc >>  8) & 0xFF);
  buf[7]  = (uint8_t)( ssrc        & 0xFF);
  /* NTP timestamp (64-bit) */
  buf[8]  = (uint8_t)((ntp_ts >> 56) & 0xFF);
  buf[9]  = (uint8_t)((ntp_ts >> 48) & 0xFF);
  buf[10] = (uint8_t)((ntp_ts >> 40) & 0xFF);
  buf[11] = (uint8_t)((ntp_ts >> 32) & 0xFF);
  buf[12] = (uint8_t)((ntp_ts >> 24) & 0xFF);
  buf[13] = (uint8_t)((ntp_ts >> 16) & 0xFF);
  buf[14] = (uint8_t)((ntp_ts >>  8) & 0xFF);
  buf[15] = (uint8_t)( ntp_ts        & 0xFF);
  /* RTP timestamp */
  buf[16] = (uint8_t)((rtp_ts >> 24) & 0xFF);
  buf[17] = (uint8_t)((rtp_ts >> 16) & 0xFF);
  buf[18] = (uint8_t)((rtp_ts >>  8) & 0xFF);
  buf[19] = (uint8_t)( rtp_ts        & 0xFF);
  /* Sender packet count */
  buf[20] = (uint8_t)((packets_sent >> 24) & 0xFF);
  buf[21] = (uint8_t)((packets_sent >> 16) & 0xFF);
  buf[22] = (uint8_t)((packets_sent >>  8) & 0xFF);
  buf[23] = (uint8_t)( packets_sent        & 0xFF);
  /* Sender octet count */
  buf[24] = (uint8_t)((octets_sent >> 24) & 0xFF);
  buf[25] = (uint8_t)((octets_sent >> 16) & 0xFF);
  buf[26] = (uint8_t)((octets_sent >>  8) & 0xFF);
  buf[27] = (uint8_t)( octets_sent        & 0xFF);
  return 28;
}
