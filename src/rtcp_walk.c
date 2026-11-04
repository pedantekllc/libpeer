#include "rtcp_walk.h"

#include <string.h>

#define RTCP_PT_SR 200
#define RTCP_PT_RR 201
#define RTCP_PT_RTPFB 205
#define RTCP_PT_PSFB 206

#define RTCP_COMMON_HEADER 4u
#define RTCP_RR_FIXED 8u /* header + sender ssrc */
#define RTCP_REPORT_BLOCK 24u
#define RTCP_FB_FIXED 12u /* header + sender ssrc + media ssrc */

static uint32_t be32(const uint8_t* p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

static void parse_report(const uint8_t* p, rtcp_report* r) {
  r->ssrc = be32(p);
  r->fraction_lost = p[4];
  r->cum_lost = be32(p + 4) & 0x00FFFFFFu;
  r->ext_highest_seq = be32(p + 8);
  r->jitter = be32(p + 12);
  r->lsr = be32(p + 16);
  r->dlsr = be32(p + 20);
}

rtcp_walk_result rtcp_walk(const uint8_t* buf, size_t len, const rtcp_walk_ops* ops, void* ctx) {
  rtcp_walk_result res = {0, RTCP_WALK_OK};
  size_t pos = 0;

  while (pos < len) {
    size_t left = len - pos;
    if (left < RTCP_COMMON_HEADER) {
      res.status = RTCP_WALK_TRUNCATED_HEADER;
      return res;
    }
    const uint8_t* p = buf + pos;
    if ((p[0] >> 6) != 2) {
      res.status = RTCP_WALK_BAD_VERSION;
      return res;
    }
    unsigned count = p[0] & 0x1Fu;
    uint8_t type = p[1];
    size_t total = 4u * ((size_t)(((unsigned)p[2] << 8) | p[3]) + 1u);
    if (total > left) {
      res.status = RTCP_WALK_LENGTH_OVERRUN;
      return res;
    }

    switch (type) {
      case RTCP_PT_RR: {
        if (total < RTCP_RR_FIXED + (size_t)count * RTCP_REPORT_BLOCK) {
          res.status = RTCP_WALK_SHORT_BODY;
          return res;
        }
        if (ops && ops->receiver_report) {
          rtcp_report blocks[31];
          for (unsigned i = 0; i < count; i++)
            parse_report(p + RTCP_RR_FIXED + (size_t)i * RTCP_REPORT_BLOCK, &blocks[i]);
          ops->receiver_report(ctx, be32(p + 4), blocks, count);
        }
        break;
      }
      case RTCP_PT_RTPFB:
        if (total < RTCP_FB_FIXED) {
          res.status = RTCP_WALK_SHORT_BODY;
          return res;
        }
        if (ops && count == 1 && ops->nack)
          ops->nack(ctx, p, total);
        else if (ops && count == 15 && ops->twcc)
          ops->twcc(ctx, p, total);
        break;
      case RTCP_PT_PSFB:
        if (total < RTCP_FB_FIXED) {
          res.status = RTCP_WALK_SHORT_BODY;
          return res;
        }
        if (ops && (count == 1 || count == 4) && ops->keyframe_request)
          ops->keyframe_request(ctx);
        break;
      case RTCP_PT_SR:
        /* Sender info is 20 bytes after the ssrc; nothing is read from it, but a
         * packet too short for it is not an SR. */
        if (total < 28u) {
          res.status = RTCP_WALK_SHORT_BODY;
          return res;
        }
        break;
      default:
        /* SDES, BYE, APP, XR and unknown types are framed and skipped. */
        break;
    }
    res.packets++;
    pos += total;
  }
  return res;
}

void rtcp_sr_history_init(rtcp_sr_history* h) {
  memset(h, 0, sizeof(*h));
}

void rtcp_sr_history_add(rtcp_sr_history* h, uint64_t ntp, uint64_t sent_us) {
  h->slot[h->next].lsr = (uint32_t)(ntp >> 16);
  h->slot[h->next].sent_us = sent_us;
  h->next = (h->next + 1) % RTCP_SR_HISTORY_SLOTS;
  if (h->count < RTCP_SR_HISTORY_SLOTS) h->count++;
}

int rtcp_rtt_sample(const rtcp_sr_history* h, uint32_t lsr, uint32_t dlsr, uint64_t now_us, uint32_t* rtt_us) {
  if (lsr == 0) return 0;
  /* Newest first: the same LSR can recur only after 18 hours. */
  for (size_t i = 0; i < h->count; i++) {
    size_t idx = (h->next + RTCP_SR_HISTORY_SLOTS - 1 - i) % RTCP_SR_HISTORY_SLOTS;
    if (h->slot[idx].lsr != lsr) continue;
    int64_t elapsed = (int64_t)(now_us - h->slot[idx].sent_us);
    int64_t delay = (int64_t)((uint64_t)dlsr * 1000000u / 65536u);
    int64_t rtt = elapsed - delay;
    if (rtt < 1000) rtt = 1000;
    if (rtt > UINT32_MAX) rtt = UINT32_MAX;
    *rtt_us = (uint32_t)rtt;
    return 1;
  }
  return 0;
}
