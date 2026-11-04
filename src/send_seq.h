#ifndef SEND_SEQ_H_
#define SEND_SEQ_H_

/*
 * The RTP sequence space of one SSRC that two threads send on: the send worker
 * (media) and the probe thread (padding-only packets). The owner holds the
 * connection's send mutex around send_seq_write() and the transmit it belongs
 * to, so a packet's seq is drawn at the moment the packet is sent: no two
 * packets share a seq and the seq order is the wire order. Plain data, no lock
 * of its own.
 */

#include <stdint.h>

typedef struct {
  uint16_t next;
} send_seq;

/* Write the next seq into the RTP header at pkt[2..3] (big-endian) and advance.
 * `pkt` holds at least 4 bytes. */
static inline uint16_t send_seq_write(send_seq* s, uint8_t* pkt) {
  uint16_t seq = s->next++;
  pkt[2] = (uint8_t)(seq >> 8);
  pkt[3] = (uint8_t)(seq & 0xFF);
  return seq;
}

#endif  // SEND_SEQ_H_
