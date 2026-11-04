#include "twcc_send.h"

#include <stdlib.h>
#include <string.h>

#include "twcc.h"

_Static_assert(TWCC_PROBE_PACKET_BYTES == TWCC_PADDING_PACKET_SIZE, "probe packet size follows the padding packet");

int twcc_sender_init(twcc_sender* s, uint8_t ext_id, size_t ring_cap) {
  memset(s, 0, sizeof(*s));
  s->ring = calloc(ring_cap, sizeof(*s->ring));
  if (!s->ring)
    return -1;
  s->ring_cap = ring_cap;
  s->ext_id = ext_id;
  return 0;
}

void twcc_sender_deinit(twcc_sender* s) {
  free(s->ring);
  memset(s, 0, sizeof(*s));
}

static void ring_push(twcc_sender* s, const twcc_sent_record* r) {
  if (s->ring_count == s->ring_cap) {
    s->ring[s->ring_head] = *r;
    s->ring_head = (s->ring_head + 1) % s->ring_cap;
    s->dropped++;
    return;
  }
  s->ring[(s->ring_head + s->ring_count) % s->ring_cap] = *r;
  s->ring_count++;
}

static int cluster_complete(const twcc_sender* s, uint64_t now_us) {
  if (s->padding_packets >= TWCC_PROBE_MAX_PADDING_PACKETS)
    return 1;
  return s->cluster_bytes >= s->cur.min_bytes && s->cluster_packets >= s->cur.min_packets &&
         now_us - s->start_us >= (uint64_t)s->cur.min_duration_ms * 1000u;
}

int twcc_sender_stamp(twcc_sender* s, uint8_t* pkt, size_t size, uint64_t now_us) {
  uint16_t seq = s->next_seq;
  if (!twcc_ext_stamp(pkt, size, s->ext_id, seq)) {
    s->unstamped++;
    return 0;
  }
  s->next_seq = (uint16_t)(seq + 1);

  int32_t cluster = TWCC_NO_CLUSTER;
  if (s->active && cluster_complete(s, now_us))
    s->active = 0;
  if (s->active) {
    cluster = s->cur.id;
    s->cluster_bytes += size;
    s->cluster_packets++;
    if (size >= 12 && (pkt[0] & 0x20))
      s->padding_packets++;
  }
  twcc_sent_record r = {.seq = seq, .size = (uint16_t)size, .send_us = now_us, .probe_cluster = cluster};
  ring_push(s, &r);
  return 1;
}

size_t twcc_sender_drain(twcc_sender* s, twcc_sent_record* out, size_t cap) {
  size_t n = s->ring_count < cap ? s->ring_count : cap;
  for (size_t i = 0; i < n; i++)
    out[i] = s->ring[(s->ring_head + i) % s->ring_cap];
  s->ring_head = (s->ring_head + n) % s->ring_cap;
  s->ring_count -= n;
  return n;
}

uint64_t twcc_sender_dropped(const twcc_sender* s) {
  return s->dropped;
}

static void event_push(twcc_sender* s, uint16_t id, twcc_probe_event_kind kind) {
  twcc_probe_event e = {id, kind};
  if (s->event_count == TWCC_PROBE_EVENT_CAP) {
    s->events[s->event_head] = e;
    s->event_head = (s->event_head + 1) % TWCC_PROBE_EVENT_CAP;
    s->events_lost++;
    return;
  }
  s->events[(s->event_head + s->event_count) % TWCC_PROBE_EVENT_CAP] = e;
  s->event_count++;
}

size_t twcc_sender_drain_probe_events(twcc_sender* s, twcc_probe_event* out, size_t cap) {
  size_t n = s->event_count < cap ? s->event_count : cap;
  for (size_t i = 0; i < n; i++)
    out[i] = s->events[(s->event_head + i) % TWCC_PROBE_EVENT_CAP];
  s->event_head = (s->event_head + n) % TWCC_PROBE_EVENT_CAP;
  s->event_count -= n;
  return n;
}

uint64_t twcc_sender_probe_events_lost(const twcc_sender* s) {
  return s->events_lost;
}

static void queue_drop_front(twcc_sender* s, twcc_probe_event_kind kind) {
  event_push(s, s->queue[0].id, kind);
  memmove(&s->queue[0], &s->queue[1], (TWCC_PROBE_QUEUE_SLOTS - 1) * sizeof(s->queue[0]));
  memmove(&s->queued_at_us[0], &s->queued_at_us[1], (TWCC_PROBE_QUEUE_SLOTS - 1) * sizeof(s->queued_at_us[0]));
  s->queue_len--;
}

static void queue_expire(twcc_sender* s, uint64_t now_us) {
  while (s->queue_len > 0 && now_us - s->queued_at_us[0] > TWCC_PROBE_TIMEOUT_US)
    queue_drop_front(s, TWCC_PROBE_EXPIRED);
}

void twcc_sender_probe_enqueue(twcc_sender* s, const twcc_probe_req* req, uint64_t now_us) {
  queue_expire(s, now_us);
  while (s->queue_len > 0 && s->queue_len + (s->active ? 1u : 0u) > TWCC_PROBE_MAX_PENDING)
    queue_drop_front(s, TWCC_PROBE_DROPPED_OLDEST);
  s->queue[s->queue_len] = *req;
  s->queued_at_us[s->queue_len] = now_us;
  s->queue_len++;
}

int twcc_sender_probe_pending(const twcc_sender* s) {
  return s->active || s->queue_len > 0;
}

void twcc_sender_probe_cancel(twcc_sender* s) {
  if (s->active) event_push(s, s->cur.id, TWCC_PROBE_CANCELLED);
  while (s->queue_len > 0)
    queue_drop_front(s, TWCC_PROBE_CANCELLED);
  s->active = 0;
}

static void start_next(twcc_sender* s, uint64_t now_us) {
  s->cur = s->queue[0];
  memmove(&s->queue[0], &s->queue[1], (TWCC_PROBE_QUEUE_SLOTS - 1) * sizeof(s->queue[0]));
  memmove(&s->queued_at_us[0], &s->queued_at_us[1], (TWCC_PROBE_QUEUE_SLOTS - 1) * sizeof(s->queued_at_us[0]));
  s->queue_len--;
  s->active = 1;
  s->start_us = now_us;
  s->origin_us = now_us;
  s->cluster_bytes = 0;
  s->padding_packets = 0;
  s->cluster_packets = 0;
}

twcc_probe_step twcc_sender_probe_step(twcc_sender* s, uint64_t now_us) {
  twcc_probe_step step = {0, 0};
  if (s->active && cluster_complete(s, now_us))
    s->active = 0;
  if (!s->active) {
    queue_expire(s, now_us);
    if (s->queue_len == 0)
      return step;
    start_next(s, now_us);
  }

  /* The ideal curve: bps/8 bytes per second since origin. A packet is due while
   * the bytes sent so far have not passed the curve. */
  uint64_t ideal = (uint64_t)s->cur.bps / 8u * (now_us - s->origin_us) / 1000000u;
  if (ideal > s->cluster_bytes + (uint64_t)s->cur.bps / 8u * TWCC_PROBE_MAX_LAG_US / 1000000u) {
    /* Too far behind: re-anchor so the shortfall is the tolerated lag. */
    uint64_t lag_bytes = (uint64_t)s->cur.bps / 8u * TWCC_PROBE_MAX_LAG_US / 1000000u;
    uint64_t want_us = (s->cluster_bytes + lag_bytes) * 1000000u / ((uint64_t)s->cur.bps / 8u);
    s->origin_us = now_us - want_us;
    ideal = s->cluster_bytes + lag_bytes;
  }
  uint32_t packets = 0;
  if (ideal >= s->cluster_bytes) {
    uint64_t due = (ideal - s->cluster_bytes) / TWCC_PROBE_PACKET_BYTES + 1;
    packets = due > TWCC_PROBE_STEP_MAX_PACKETS ? TWCC_PROBE_STEP_MAX_PACKETS : (uint32_t)due;
  }
  step.packets = packets;
  uint64_t after = s->cluster_bytes + (uint64_t)packets * TWCC_PROBE_PACKET_BYTES;
  step.wake_us = s->origin_us + after * 8u * 1000000u / s->cur.bps;
  if (step.wake_us <= now_us)
    step.wake_us = now_us + 1;
  return step;
}
