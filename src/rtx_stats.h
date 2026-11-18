#ifndef RTX_STATS_H_
#define RTX_STATS_H_

/*
 * Per-connection retransmission counters for one reporting window.
 *
 * Counts what the NACK path does: NACKed packets received, retransmits sent,
 * NACKs the history could no longer answer, NACKs the repeat guard dropped, PLIs
 * received, and how long a sent retransmit waited between its NACK arriving and
 * leaving the pacer (max and median over the window). Counters only; nothing
 * here changes what is sent.
 *
 * Pure: no lock, no clock, no I/O. The caller serialises every call and passes
 * the times in.
 */

#include <stdint.h>

#include "rtx_history.h"

#define RTX_STATS_WAIT_SAMPLES 512

typedef struct {
  uint32_t nacked;     /* packets named by received NACKs                       */
  uint32_t sent;       /* retransmits that left the pacer                       */
  uint32_t miss;       /* named packets the history no longer held              */
  uint32_t suppressed; /* named packets inside the repeat guard                 */
  uint32_t pli;        /* PLI / FIR received                                    */
  uint32_t wait_max_ms;
  uint32_t wait_p50_ms;
  uint32_t wait_n;     /* retransmits with a wait sample (the window's sent)    */
  uint32_t hist_oldest_ms; /* age of the oldest packet in the history; set by the connection */
} rtx_stats_snapshot;

typedef struct {
  uint32_t nacked, sent, miss, suppressed, pli;
  uint32_t wait_n;     /* sent retransmits whose wait was measured              */
  uint32_t wait_max_ms;
  uint16_t waits[RTX_STATS_WAIT_SAMPLES]; /* first samples of the window, ms, saturated */
} rtx_stats;

void rtx_stats_init(rtx_stats* s);
void rtx_stats_on_miss(rtx_stats* s);
void rtx_stats_on_pli(rtx_stats* s);
/* Answer one NACKed seq against the history and count it: nacked always, plus miss
 * (history no longer holds it) or suppressed (retransmitted less than `guard_ms`
 * ago). Returns the slot to retransmit, or NULL when nothing is to be sent. The
 * caller queues it, and stamps slot->last_resend_ms. */
rtx_slot_t* rtx_stats_on_nack_seq(rtx_stats* s, rtx_history* h, uint16_t seq, uint32_t now_ms,
                                  uint32_t guard_ms);

/* A retransmit left the pacer `wait_ms` after its NACK arrived. */
void rtx_stats_on_sent(rtx_stats* s, uint32_t wait_ms);

/* The window's counts; resets the window. */
rtx_stats_snapshot rtx_stats_drain(rtx_stats* s);

#endif /* RTX_STATS_H_ */
