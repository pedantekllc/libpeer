/* rtx_history.c — the sent-packet history NACKs are answered from. Contract: rtx_history.h. */
#include "rtx_history.h"

#include <stdlib.h>
#include <string.h>

int rtx_history_init(rtx_history* h, unsigned initial, unsigned max) {
  memset(h, 0, sizeof(*h));
  h->slots = calloc(initial, sizeof(rtx_slot_t));
  if (!h->slots) return -1;
  h->cap = initial;
  h->max_cap = max;
  return 0;
}

void rtx_history_free(rtx_history* h) {
  free(h->slots);
  h->slots = NULL;
  h->cap = 0;
}

/* Double the ring. Every held packet keeps its own slot: two sequence numbers
 * distinct modulo the old size are distinct modulo the new one. */
static void grow(rtx_history* h) {
  unsigned cap = h->cap * 2;
  rtx_slot_t* slots = calloc(cap, sizeof(rtx_slot_t));
  if (!slots) return;
  for (unsigned i = 0; i < h->cap; i++) {
    const rtx_slot_t* s = &h->slots[i];
    if (s->len) slots[s->seq % cap] = *s;
  }
  free(h->slots);
  h->slots = slots;
  h->cap = cap;
}

void rtx_history_store(rtx_history* h, const uint8_t* pkt, size_t len) {
  if (!h->slots || len < 12 || len > RTX_SLOT_BYTES) return;
  h->frame_pkts++;
  while (h->frame_pkts * 2 > h->cap && h->cap < h->max_cap) {
    unsigned before = h->cap;
    grow(h);
    if (h->cap == before) break;
  }
  uint16_t seq = (uint16_t)((pkt[2] << 8) | pkt[3]);
  rtx_slot_t* slot = &h->slots[seq % h->cap];
  slot->seq = seq;
  slot->len = (uint16_t)len;
  slot->last_resend_ms = 0;
  memcpy(slot->data, pkt, len);
  if (pkt[1] & 0x80) h->frame_pkts = 0;
}

rtx_slot_t* rtx_history_find(rtx_history* h, uint16_t seq) {
  if (!h->slots) return NULL;
  rtx_slot_t* slot = &h->slots[seq % h->cap];
  return slot->len >= 12 && slot->seq == seq ? slot : NULL;
}
