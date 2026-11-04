#ifndef TWCC_SEND_H_
#define TWCC_SEND_H_

/*
 * Sender side of transport-wide congestion control: the per-connection
 * transport-wide sequence counter, the ring of sent-packet records the
 * estimator drains, and the probe-cluster state machine.
 *
 * Pure data code with the clock as a parameter: no sockets, no threads, no
 * clock read. The owner serialises every call with one lock (the connection's
 * send mutex), so a record is appended at the same instant the packet is
 * stamped and tagged.
 */

#include <stddef.h>
#include <stdint.h>

/* probe_cluster of a packet that was sent while no probe cluster was active. */
#define TWCC_NO_CLUSTER (-1)

typedef struct {
  uint16_t seq;          /* transport-wide sequence number, wraps at 2^16 */
  uint16_t size;         /* RTP packet bytes before SRTP */
  uint64_t send_us;      /* sender monotonic clock at the stamping point */
  int32_t probe_cluster; /* cluster id, or TWCC_NO_CLUSTER */
} twcc_sent_record;

/* The reactor drains the ring every loop, so it only has to outlast a stalled
 * loop: 8192 records hold 250 ms of 275-byte padding packets at 60 Mbps (6.8k)
 * and more than 1 s of 1200-byte media at 60 Mbps (6.3k). */
#define TWCC_SENT_RING_CAP 8192

/* Padding-only packet size (twcc_build_padding_packet): 12 header + 8
 * extension + 255 padding. Kept equal to TWCC_PADDING_PACKET_SIZE in twcc.h. */
#define TWCC_PROBE_PACKET_BYTES 275u

/* A cluster ends after this many padding packets even when its bytes or
 * duration are not met. */
#define TWCC_PROBE_MAX_PADDING_PACKETS 8192u

/* The most packets one probe step hands out, and the lag behind the ideal
 * curve the pacer tolerates before it re-anchors instead of bursting. */
#define TWCC_PROBE_STEP_MAX_PACKETS 4u
#define TWCC_PROBE_MAX_LAG_US 20000u

/* libwebrtc BitrateProber: before a cluster is queued, queued clusters are
 * dropped oldest first while more than TWCC_PROBE_MAX_PENDING (active one
 * included) are pending, and any not started within TWCC_PROBE_TIMEOUT_US of
 * its request is dropped. The active cluster is never dropped by the cap, so
 * at most TWCC_PROBE_MAX_PENDING + 1 are pending after a queue. */
#define TWCC_PROBE_MAX_PENDING 5u
#define TWCC_PROBE_TIMEOUT_US 5000000u
#define TWCC_PROBE_QUEUE_SLOTS (TWCC_PROBE_MAX_PENDING + 1)

typedef struct {
  uint16_t id;
  uint32_t bps;
  uint32_t min_bytes;
  uint32_t min_packets; /* packets of any kind (media and padding) sent in the cluster */
  uint32_t min_duration_ms;
} twcc_probe_req;

/* Why a requested cluster will never produce sent records. */
typedef enum {
  TWCC_PROBE_DROPPED_OLDEST = 1, /* pushed out by newer requests */
  TWCC_PROBE_EXPIRED = 2,        /* not started within TWCC_PROBE_TIMEOUT_US */
  TWCC_PROBE_CANCELLED = 3       /* the connection was not up, or the sender was cancelled */
} twcc_probe_event_kind;

typedef struct {
  uint16_t id;
  twcc_probe_event_kind kind;
} twcc_probe_event;

#define TWCC_PROBE_EVENT_CAP 32

typedef struct {
  twcc_sent_record* ring;
  size_t ring_cap;
  size_t ring_head; /* index of the oldest record */
  size_t ring_count;
  uint64_t dropped; /* records overwritten before they were drained */

  uint8_t ext_id;
  uint16_t next_seq;
  uint32_t unstamped; /* packets that reached the stamp without the extension element */

  twcc_probe_req queue[TWCC_PROBE_QUEUE_SLOTS];
  uint64_t queued_at_us[TWCC_PROBE_QUEUE_SLOTS];
  size_t queue_len;
  twcc_probe_event events[TWCC_PROBE_EVENT_CAP];
  size_t event_head;
  size_t event_count;
  uint64_t events_lost; /* events overwritten before they were drained */
  int active;
  twcc_probe_req cur;
  uint64_t start_us;        /* when the active cluster began */
  uint64_t origin_us;       /* start of the cluster's ideal byte curve (re-anchored on lag) */
  uint64_t cluster_bytes;   /* media + padding sent since start */
  uint32_t padding_packets; /* padding packets sent since start */
  uint32_t cluster_packets; /* packets of any kind sent since start */
} twcc_sender;

/* Allocate the ring (`ring_cap` records) and set the extension id. Returns 0,
 * or -1 on allocation failure. */
int twcc_sender_init(twcc_sender* s, uint8_t ext_id, size_t ring_cap);
void twcc_sender_deinit(twcc_sender* s);

/* Stamp the next transport-wide seq into element ext_id of `pkt`, tag it with
 * the active cluster and append its record. Returns 1 when stamped, 0 when the
 * packet has no such element (counted in `unstamped`; no seq is consumed). A
 * packet with the RTP padding bit set counts toward the cluster's padding cap. */
int twcc_sender_stamp(twcc_sender* s, uint8_t* pkt, size_t size, uint64_t now_us);

/* Move up to `cap` oldest records into `out`, oldest first. Returns the count. */
size_t twcc_sender_drain(twcc_sender* s, twcc_sent_record* out, size_t cap);

/* Records overwritten before they were drained, since init. */
uint64_t twcc_sender_dropped(const twcc_sender* s);

/* Queue a cluster behind the ones already requested, at `now_us`. Queued
 * clusters that expired or exceed the pending cap are dropped first and
 * reported as events; the new request is always queued. */
void twcc_sender_probe_enqueue(twcc_sender* s, const twcc_probe_req* req, uint64_t now_us);

/* Drop the active cluster and every queued one, each reported as an event. */
void twcc_sender_probe_cancel(twcc_sender* s);

/* Move up to `cap` events into `out`, oldest first. Returns the count. A
 * cluster in an event produced no sent records after the event; one that was
 * active when cancelled may have produced some before it. */
size_t twcc_sender_drain_probe_events(twcc_sender* s, twcc_probe_event* out, size_t cap);

/* Events overwritten before they were drained, since init. */
uint64_t twcc_sender_probe_events_lost(const twcc_sender* s);

/* 1 while a cluster is active or queued. */
int twcc_sender_probe_pending(const twcc_sender* s);

typedef struct {
  uint32_t packets; /* padding packets to send now */
  uint64_t wake_us; /* clock time of the next step; 0 when nothing is active or queued */
} twcc_probe_step;

/* Advance the cluster schedule to `now_us` (BitrateProber semantics): start the
 * next queued cluster when none is active; drop queued clusters older than
 * TWCC_PROBE_TIMEOUT_US; end the active cluster once its min_bytes, min_packets
 * and min_duration are all met; otherwise hand out the padding packets
 * that fill the gap between the bytes already sent in the cluster (media
 * included) and the cluster's rate. */
twcc_probe_step twcc_sender_probe_step(twcc_sender* s, uint64_t now_us);

#endif  // TWCC_SEND_H_
