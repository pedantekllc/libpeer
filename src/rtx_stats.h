#ifndef RTX_STATS_H_
#define RTX_STATS_H_

/*
 * Per-connection retransmission counters for one reporting window.
 *
 * Counts what the NACK path does: NACKed packets received, retransmits sent,
 * NACKs the history could no longer answer, NACKs the repeat guard dropped, PLIs
 * received, retransmits dropped for waiting too long, and how long a sent retransmit waited between its NACK arriving and
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
  uint32_t stale;      /* queued retransmits dropped unsent for waiting too long */
  uint32_t wait_max_ms;
  uint32_t wait_p50_ms;
  uint32_t wait_n;     /* retransmits with a wait sample (the window's sent)    */
  uint32_t hist_oldest_ms; /* age of the oldest packet in the history; set by the connection */
} rtx_stats_snapshot;

typedef struct {
  uint32_t nacked, sent, miss, suppressed, pli, stale;
  uint32_t wait_n;     /* sent retransmits whose wait was measured              */
  uint32_t wait_max_ms;
  uint16_t waits[RTX_STATS_WAIT_SAMPLES]; /* first samples of the window, ms, saturated */
} rtx_stats;

void rtx_stats_init(rtx_stats* s);
void rtx_stats_on_miss(rtx_stats* s);
void rtx_stats_on_pli(rtx_stats* s);
/* A NACKed packet was already queued or being sent: counted as suppressed. */
void rtx_stats_on_dup(rtx_stats* s);
/* `n` queued retransmits were dropped unsent for waiting longer than RTX_QUEUE_MAX_AGE_MS. */
void rtx_stats_on_stale(rtx_stats* s, uint32_t n);

/* The connection's round trip time: known, or not measured yet. */
typedef struct {
  int known;
  uint32_t ms; /* meaningful only when known */
} rtx_rtt;

/* The repeat guard: a packet is not retransmitted again until half a round trip after its
 * last send. The receiver repeats a NACK for a sequence one RTT after its last NACK for
 * it, and the copy leaves the pacer some time after that NACK arrived, so a guard of a
 * whole RTT from the send would still hold when the repeat arrives and the lost copy
 * would wait for the next one, about two RTTs. Half an RTT is the copy's own flight, the
 * time before which a repeat is not news. The RTT/2 clamped to [RTX_GUARD_MIN_MS,
 * RTX_GUARD_MAX_MS], or RTX_GUARD_FALLBACK_MS while the RTT is unknown. */
#define RTX_GUARD_MIN_MS 20u
#define RTX_GUARD_MAX_MS 125u
#define RTX_GUARD_FALLBACK_MS 100u
uint32_t rtx_guard_ms(rtx_rtt rtt);
/* Answer one NACKed seq against the history and count it: nacked always, plus miss
 * (history no longer holds it) or suppressed (retransmitted less than `guard_ms`
 * ago). Returns the slot to retransmit, or NULL when nothing is to be sent. The
 * caller queues it (rtx_queue.h) and stamps the slot when the packet is SENT
 * (rtx_history_mark_sent), so the guard counts from the last send. */
rtx_slot_t* rtx_stats_on_nack_seq(rtx_stats* s, rtx_history* h, uint16_t seq, uint32_t now_ms,
                                  uint32_t guard_ms);

/* A retransmit left the pacer `wait_ms` after its NACK arrived. */
void rtx_stats_on_sent(rtx_stats* s, uint32_t wait_ms);

/* The window's counts; resets the window. */
rtx_stats_snapshot rtx_stats_drain(rtx_stats* s);

#endif /* RTX_STATS_H_ */
