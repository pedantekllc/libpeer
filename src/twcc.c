#include "twcc.h"

#include <stdlib.h>
#include <string.h>

/* ── RTP header extension ─────────────────────────────────────────────────── */

#define EXT_PROFILE_ONE_BYTE 0xBEDE
#define EXT_MAX_BLOCK_BYTES 60

static uint16_t be16(const uint8_t* p) {
  return (uint16_t)((p[0] << 8) | p[1]);
}

static void put_be16(uint8_t* p, uint16_t v) {
  p[0] = (uint8_t)(v >> 8);
  p[1] = (uint8_t)(v & 0xFF);
}

static void put_be32(uint8_t* p, uint32_t v) {
  p[0] = (uint8_t)(v >> 24);
  p[1] = (uint8_t)(v >> 16);
  p[2] = (uint8_t)(v >> 8);
  p[3] = (uint8_t)(v & 0xFF);
}

static uint32_t be32(const uint8_t* p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

/* Where the extension block of a packet sits: `hdr` = offset of the 0xBEDE
 * word, `end` = offset one past the block. Returns 1 for a well-formed
 * one-byte block, 0 for a packet with no extension, negative for a block this
 * layer cannot edit. */
static int ext_block(const uint8_t* pkt, size_t size, size_t* hdr, size_t* end) {
  if (size < 12)
    return TWCC_ERR_FORMAT;
  if (!(pkt[0] & 0x10))
    return 0;
  size_t h = 12 + 4u * (pkt[0] & 0x0F);
  if (size < h + 4)
    return TWCC_ERR_FORMAT;
  if (be16(pkt + h) != EXT_PROFILE_ONE_BYTE)
    return TWCC_ERR_FORMAT;
  size_t e = h + 4 + 4u * be16(pkt + h + 2);
  if (e > size)
    return TWCC_ERR_FORMAT;
  *hdr = h;
  *end = e;
  return 1;
}

int twcc_ext_find(const uint8_t* pkt, size_t size, uint8_t id, size_t* data_off, size_t* data_len) {
  size_t hdr = 0, end = 0;
  if (ext_block(pkt, size, &hdr, &end) != 1)
    return 0;
  size_t p = hdr + 4;
  while (p < end) {
    if (pkt[p] == 0) {
      p++;
      continue;
    }
    uint8_t eid = pkt[p] >> 4;
    if (eid == 15 || eid == 0)
      return 0; /* RFC 8285: id 15 is reserved and id 0 with a non-zero length is invalid; both end parsing */
    size_t len = (size_t)(pkt[p] & 0x0F) + 1;
    if (p + 1 + len > end)
      return 0;
    if (eid == id) {
      *data_off = p + 1;
      *data_len = len;
      return 1;
    }
    p += 1 + len;
  }
  return 0;
}

int twcc_ext_reserve(uint8_t* pkt, size_t* size, size_t cap, uint8_t id) {
  if (id < 1 || id > 14)
    return TWCC_ERR_RANGE;
  size_t off = 0, len = 0;
  if (twcc_ext_find(pkt, *size, id, &off, &len)) {
    if (len != 2)
      return TWCC_ERR_FORMAT;
    pkt[off] = 0;
    pkt[off + 1] = 0;
    return 0;
  }

  size_t hdr = 0, end = 0;
  int has = ext_block(pkt, *size, &hdr, &end);
  if (has < 0)
    return has;

  if (!has) {
    size_t payload = 12 + 4u * (pkt[0] & 0x0F);
    if (*size < payload)
      return TWCC_ERR_FORMAT;
    if (*size + 8 > cap)
      return TWCC_ERR_SPACE;
    memmove(pkt + payload + 8, pkt + payload, *size - payload);
    put_be16(pkt + payload, EXT_PROFILE_ONE_BYTE);
    put_be16(pkt + payload + 2, 1);
    pkt[payload + 4] = (uint8_t)((id << 4) | 1);
    pkt[payload + 5] = 0;
    pkt[payload + 6] = 0;
    pkt[payload + 7] = 0;
    pkt[0] |= 0x10;
    *size += 8;
    return 0;
  }

  /* Gather the existing elements without their padding bytes, append ours,
   * and rewrite the block padded to a word boundary. */
  uint8_t keep[EXT_MAX_BLOCK_BYTES];
  size_t klen = 0;
  size_t p = hdr + 4;
  while (p < end) {
    if (pkt[p] == 0) {
      p++;
      continue;
    }
    if ((pkt[p] >> 4) == 15 || (pkt[p] >> 4) == 0)
      break; /* same terminators as twcc_ext_find: what follows is not kept */
    size_t elen = 1 + (size_t)(pkt[p] & 0x0F) + 1;
    if (p + elen > end || klen + elen + 3 > sizeof(keep))
      return TWCC_ERR_FORMAT;
    memcpy(keep + klen, pkt + p, elen);
    klen += elen;
    p += elen;
  }
  keep[klen++] = (uint8_t)((id << 4) | 1);
  keep[klen++] = 0;
  keep[klen++] = 0;
  size_t new_data = (klen + 3) & ~(size_t)3;
  size_t old_data = end - (hdr + 4);
  if (new_data / 4 > 0xFFFF)
    return TWCC_ERR_RANGE;
  if (*size - old_data + new_data > cap)
    return TWCC_ERR_SPACE;
  memmove(pkt + hdr + 4 + new_data, pkt + end, *size - end);
  memcpy(pkt + hdr + 4, keep, klen);
  memset(pkt + hdr + 4 + klen, 0, new_data - klen);
  put_be16(pkt + hdr + 2, (uint16_t)(new_data / 4));
  *size = *size - old_data + new_data;
  return 0;
}

int twcc_ext_stamp(uint8_t* pkt, size_t size, uint8_t id, uint16_t seq) {
  size_t off = 0, len = 0;
  if (!twcc_ext_find(pkt, size, id, &off, &len) || len != 2)
    return 0;
  put_be16(pkt + off, seq);
  return 1;
}

size_t twcc_build_padding_packet(uint8_t* out, size_t cap, uint8_t pt, uint32_t ssrc, uint16_t seq, uint32_t rtp_ts, uint8_t ext_id) {
  if (cap < TWCC_PADDING_PACKET_SIZE || ext_id < 1 || ext_id > 14)
    return 0;
  memset(out, 0, TWCC_PADDING_PACKET_SIZE);
  out[0] = 0x80 | 0x20 | 0x10; /* V=2, P, X */
  out[1] = (uint8_t)(pt & 0x7F);
  put_be16(out + 2, seq);
  put_be32(out + 4, rtp_ts);
  put_be32(out + 8, ssrc);
  put_be16(out + 12, EXT_PROFILE_ONE_BYTE);
  put_be16(out + 14, 1);
  out[16] = (uint8_t)((ext_id << 4) | 1);
  out[TWCC_PADDING_PACKET_SIZE - 1] = 255;
  return TWCC_PADDING_PACKET_SIZE;
}

/* ── Feedback parse ───────────────────────────────────────────────────────── */

#define FMT_TCC 15
#define RTCP_RTPFB_TYPE 205
#define FIXED_BYTES 20

void twcc_feedback_free(twcc_feedback* fb) {
  free(fb->results);
  fb->results = NULL;
  fb->count = 0;
}

int twcc_parse(const uint8_t* pkt, size_t len, twcc_feedback* fb) {
  memset(fb, 0, sizeof(*fb));
  if (len < FIXED_BYTES || (pkt[0] >> 6) != 2 || (pkt[0] & 0x1F) != FMT_TCC || pkt[1] != RTCP_RTPFB_TYPE)
    return TWCC_ERR_FORMAT;
  size_t total = 4u * ((size_t)be16(pkt + 2) + 1);
  if (total > len || total < FIXED_BYTES)
    return TWCC_ERR_FORMAT;
  size_t end = total;
  if (pkt[0] & 0x20) {
    size_t pad = pkt[total - 1];
    if (pad == 0 || pad > total - FIXED_BYTES)
      return TWCC_ERR_FORMAT;
    end = total - pad;
  }

  size_t count = be16(pkt + 14);

  twcc_status* res = NULL;
  if (count > 0) {
    res = calloc(count, sizeof(*res));
    if (!res)
      return TWCC_ERR_NOMEM;
  }
  uint16_t base = be16(pkt + 12);
  int rc = TWCC_ERR_FORMAT;

  /* First pass: the status symbol of every packet, parked in recv_delta_us. */
  size_t pos = FIXED_BYTES, done = 0;
  while (done < count) {
    if (pos + 2 > end)
      goto fail;
    uint16_t w = be16(pkt + pos);
    pos += 2;
    if (!(w & 0x8000)) {
      uint8_t sym = (uint8_t)((w >> 13) & 3);
      size_t run = w & 0x1FFF;
      if (run > count - done)
        run = count - done;
      if (sym == 3 && run > 0) {
        rc = TWCC_ERR_RESERVED;
        goto fail;
      }
      for (size_t i = 0; i < run; i++)
        res[done + i].recv_delta_us = sym;
      done += run;
    } else if (w & 0x4000) {
      for (int i = 0; i < 7 && done < count; i++) {
        uint8_t sym = (uint8_t)((w >> (12 - 2 * i)) & 3);
        if (sym == 3) {
          rc = TWCC_ERR_RESERVED;
          goto fail;
        }
        res[done++].recv_delta_us = sym;
      }
    } else {
      for (int i = 0; i < 14 && done < count; i++)
        res[done++].recv_delta_us = (w >> (13 - i)) & 1;
    }
  }

  /* Second pass: the receive deltas of the received packets. */
  for (size_t i = 0; i < count; i++) {
    int sym = res[i].recv_delta_us;
    res[i].seq = (uint16_t)(base + i);
    res[i].recv_delta_us = 0;
    if (sym == 0)
      continue;
    res[i].received = 1;
    if (sym == 1) {
      if (pos + 1 > end)
        goto fail;
      res[i].recv_delta_us = (int32_t)pkt[pos] * TWCC_DELTA_TICK_US;
      pos += 1;
    } else {
      if (pos + 2 > end)
        goto fail;
      res[i].recv_delta_us = (int32_t)(int16_t)be16(pkt + pos) * TWCC_DELTA_TICK_US;
      pos += 2;
    }
  }

  fb->sender_ssrc = be32(pkt + 4);
  fb->media_ssrc = be32(pkt + 8);
  fb->base_seq = base;
  fb->ref_time = ((uint32_t)pkt[16] << 16) | ((uint32_t)pkt[17] << 8) | pkt[18];
  fb->fb_count = pkt[19];
  fb->count = count;
  fb->results = res;
  return 0;

fail:
  free(res);
  return rc;
}

/* ── Feedback encode ──────────────────────────────────────────────────────── */

/* The chunker is Pion's (interceptor pkg/twcc): symbols accumulate in one open
 * chunk; when the next symbol does not fit, the open chunk is flushed as a run
 * length, a full 14-symbol one-bit vector, or the first seven symbols as a
 * two-bit vector. */
#define SYM_NOT_RECEIVED 0
#define SYM_SMALL 1
#define SYM_LARGE 2
#define RUN_MAX 0x1FFF
#define ONE_BIT_CAP 14
#define TWO_BIT_CAP 7

typedef struct {
  uint8_t sym[RUN_MAX + 1];
  unsigned n;
  int has_large;
  int has_diff;
} open_chunk;

static int chunk_can_add(const open_chunk* c, uint8_t s) {
  if (c->n < TWO_BIT_CAP)
    return 1;
  if (c->n < ONE_BIT_CAP && !c->has_large && s != SYM_LARGE)
    return 1;
  if (c->n < RUN_MAX && !c->has_diff && s == c->sym[0])
    return 1;
  return 0;
}

static void chunk_add(open_chunk* c, uint8_t s) {
  c->sym[c->n++] = s;
  if (s == SYM_LARGE)
    c->has_large = 1;
  if (s != c->sym[0])
    c->has_diff = 1;
}

static uint16_t chunk_flush(open_chunk* c) {
  uint16_t w;
  if (!c->has_diff) {
    w = (uint16_t)(((unsigned)c->sym[0] << 13) | c->n);
    c->n = 0;
    c->has_large = 0;
    return w;
  }
  if (c->n == ONE_BIT_CAP) {
    w = 0x8000;
    for (unsigned i = 0; i < ONE_BIT_CAP; i++)
      w |= (uint16_t)((c->sym[i] & 1u) << (13 - i));
    c->n = 0;
    c->has_diff = 0;
    c->has_large = 0;
    return w;
  }
  unsigned take = c->n < TWO_BIT_CAP ? c->n : TWO_BIT_CAP;
  w = 0xC000;
  for (unsigned i = 0; i < take; i++)
    w |= (uint16_t)((unsigned)c->sym[i] << (12 - 2 * i));
  memmove(c->sym, c->sym + take, c->n - take);
  c->n -= take;
  c->has_diff = 0;
  c->has_large = 0;
  for (unsigned i = 0; i < c->n; i++) {
    if (c->sym[i] != c->sym[0])
      c->has_diff = 1;
    if (c->sym[i] == SYM_LARGE)
      c->has_large = 1;
  }
  return w;
}

int twcc_encode(const twcc_feedback* fb, uint8_t* out, size_t cap) {
  if (fb->count > TWCC_MAX_PACKETS || (fb->count > 0 && !fb->results) || fb->ref_time > 0xFFFFFF)
    return TWCC_ERR_RANGE;

  open_chunk* oc = calloc(1, sizeof(*oc));
  uint16_t* chunks = calloc(fb->count + 1, sizeof(*chunks));
  if (!oc || !chunks) {
    free(oc);
    free(chunks);
    return TWCC_ERR_NOMEM;
  }
  size_t nchunks = 0, delta_bytes = 0;
  int rc = 0;

  for (size_t i = 0; i < fb->count; i++) {
    const twcc_status* r = &fb->results[i];
    uint8_t sym = SYM_NOT_RECEIVED;
    if (r->received) {
      if (r->recv_delta_us % TWCC_DELTA_TICK_US != 0) {
        rc = TWCC_ERR_RANGE;
        goto done;
      }
      int32_t ticks = r->recv_delta_us / TWCC_DELTA_TICK_US;
      if (ticks < -32768 || ticks > 32767) {
        rc = TWCC_ERR_RANGE;
        goto done;
      }
      sym = (ticks >= 0 && ticks <= 255) ? SYM_SMALL : SYM_LARGE;
      delta_bytes += (sym == SYM_SMALL) ? 1 : 2;
    }
    if (!chunk_can_add(oc, sym))
      chunks[nchunks++] = chunk_flush(oc);
    chunk_add(oc, sym);
  }
  while (oc->n > 0)
    chunks[nchunks++] = chunk_flush(oc);

  size_t body = FIXED_BYTES + nchunks * 2 + delta_bytes;
  size_t total = (body + 3) & ~(size_t)3;
  if (total / 4 - 1 > 0xFFFF || nchunks > fb->count + 1) {
    rc = TWCC_ERR_RANGE;
    goto done;
  }
  if (total > cap) {
    rc = TWCC_ERR_SPACE;
    goto done;
  }

  memset(out, 0, total);
  out[0] = (uint8_t)(0x80 | (total != body ? 0x20 : 0) | FMT_TCC);
  out[1] = RTCP_RTPFB_TYPE;
  put_be16(out + 2, (uint16_t)(total / 4 - 1));
  put_be32(out + 4, fb->sender_ssrc);
  put_be32(out + 8, fb->media_ssrc);
  put_be16(out + 12, fb->base_seq);
  put_be16(out + 14, (uint16_t)fb->count);
  out[16] = (uint8_t)(fb->ref_time >> 16);
  out[17] = (uint8_t)(fb->ref_time >> 8);
  out[18] = (uint8_t)fb->ref_time;
  out[19] = fb->fb_count;
  size_t pos = FIXED_BYTES;
  for (size_t i = 0; i < nchunks; i++, pos += 2)
    put_be16(out + pos, chunks[i]);
  for (size_t i = 0; i < fb->count; i++) {
    const twcc_status* r = &fb->results[i];
    if (!r->received)
      continue;
    int32_t ticks = r->recv_delta_us / TWCC_DELTA_TICK_US;
    if (ticks >= 0 && ticks <= 255) {
      out[pos++] = (uint8_t)ticks;
    } else {
      put_be16(out + pos, (uint16_t)(int16_t)ticks);
      pos += 2;
    }
  }
  if (total != body)
    out[total - 1] = (uint8_t)(total - body);
  rc = (int)total;

done:
  free(oc);
  free(chunks);
  return rc;
}

/* ── Reference clock and arrivals ─────────────────────────────────────────────── */

/* libwebrtc TransportFeedbackAdapter::ProcessTransportFeedback: the offset
 * starts at the local clock when the first feedback arrives and advances by the
 * signed 24-bit change of the reference time; a step back larger than the offset
 * itself would make it negative, so the offset restarts at the local clock. */
int64_t twcc_ref_local_us(twcc_ref_clock* c, uint32_t ref_time, int64_t now_us) {
  ref_time &= 0xFFFFFF;
  if (!c->local_init) {
    c->offset_us = now_us;
    c->local_init = 1;
  } else {
    uint32_t diff = (ref_time - c->last_ref) & 0xFFFFFF;
    int64_t ticks = (diff >= 0x800000) ? (int64_t)diff - 0x1000000 : (int64_t)diff;
    int64_t delta_us = ticks * TWCC_REF_TICK_US;
    if (delta_us < -c->offset_us)
      c->offset_us = now_us;
    else
      c->offset_us += delta_us;
  }
  c->last_ref = ref_time;
  return c->offset_us;
}

int64_t twcc_ref_unwrap(twcc_ref_clock* c, uint32_t ref_time) {
  ref_time &= 0xFFFFFF;
  if (!c->init) {
    c->ref_ticks = ref_time;
    c->init = 1;
  } else {
    uint32_t diff = (ref_time - (uint32_t)(c->ref_ticks & 0xFFFFFF)) & 0xFFFFFF;
    c->ref_ticks += (diff >= 0x800000) ? (int64_t)diff - 0x1000000 : (int64_t)diff;
  }
  return c->ref_ticks * TWCC_REF_TICK_US;
}

size_t twcc_arrivals(const twcc_feedback* fb, int64_t ref_us, twcc_arrival* out, size_t cap) {
  size_t n = 0;
  int64_t t = ref_us;
  for (size_t i = 0; i < fb->count && n < cap; i++) {
    const twcc_status* r = &fb->results[i];
    if (r->received)
      t += r->recv_delta_us;
    out[n].seq = r->seq;
    out[n].received = r->received ? 1 : 0;
    out[n].recv_us = r->received ? t : 0;
    n++;
  }
  return n;
}
