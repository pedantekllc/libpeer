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

RtcpRr rtcp_parse_rr(uint8_t* packet) {
  RtcpRr rtcp_rr;
  memcpy(&rtcp_rr.header, packet, sizeof(rtcp_rr.header));
  memcpy(&rtcp_rr.report_block[0], packet + 8, 6 * sizeof(uint32_t));

  return rtcp_rr;
}

/* goog-remb PSFB layout (draft-alvestrand-rmcat-remb):
 *   [0..3]   RTCP header (V/P/FMT=15, PT=206, length)
 *   [4..7]   packet sender SSRC
 *   [8..11]  media source SSRC (0 for REMB)
 *   [12..15] 'R' 'E' 'M' 'B'
 *   [16]     Num SSRC
 *   [17..19] Exp (6 bits) | Mantissa (18 bits), big-endian
 *   [20..]   Num SSRC × feedback SSRC
 * bitrate = mantissa << exp. */
int rtcp_parse_remb(const uint8_t* pkt, size_t len, uint32_t* out_bps) {
  if (!pkt || !out_bps || len < 20)
    return 0;
  if (pkt[12] != 'R' || pkt[13] != 'E' || pkt[14] != 'M' || pkt[15] != 'B')
    return 0;
  uint8_t exp = (uint8_t)(pkt[17] >> 2);
  uint32_t mantissa = ((uint32_t)(pkt[17] & 0x03) << 16) |
                      ((uint32_t)pkt[18] << 8) |
                      (uint32_t)pkt[19];
  uint64_t bps = (exp < 47) ? ((uint64_t)mantissa << exp) : 0xFFFFFFFFULL;
  if (bps > 0xFFFFFFFFULL) bps = 0xFFFFFFFFULL;
  *out_bps = (uint32_t)bps;
  return 1;
}
