#ifndef MDNS_H_
#define MDNS_H_

#include <stdlib.h>
#include "address.h"

int mdns_resolve_addr(const char* hostname, Address* addr);

// Exposed for unit testing. Parses a received mDNS packet; returns 0 and fills
// `addr` when `buf` is a DNS response whose first answer matches `hostname`
// with a 4-byte (A-record) payload, non-zero otherwise (wrong host, not a
// response, bad length, too short).
int mdns_parse_answer(uint8_t* buf, int size, Address* addr, const char* hostname);

// Exposed for unit testing. Builds an mDNS query for `hostname` into `buf`;
// returns the encoded size, or -1 if `buf` is too small.
int mdns_build_query(const char* hostname, uint8_t* buf, int size);

// ── Async resolver ──────────────────────────────────────────────────────────
// Poll-driven .local resolution so ICE candidate parsing never blocks the
// signaling reactor: the synchronous mdns_resolve_addr() waits up to
// MDNS_TOTAL_TIMEOUT_MS per name, and off-LAN (viewer on cellular/another
// network) it ALWAYS times out — those stalls starve candidate processing for
// every connection on the reactor. State is module-global and unlocked: all
// three calls must come from the same thread (the reactor).

// Begin resolving `hostname`. Idempotent while a query for that name is
// pending or its result is cached. Returns 0 on success, -1 if the resolver
// socket cannot be opened or the pending table is full.
int mdns_async_request(const char* hostname);

// Pump the resolver: drain received answers (never blocks), re-send pending
// queries on their interval, expire finished entries. Cheap no-op while
// nothing is pending.
void mdns_async_poll(void);

// Result for `hostname`: 1 = resolved (`*addr` filled with the IP; port is
// untouched), 0 = still pending, -1 = failed/expired/never requested.
int mdns_async_lookup(const char* hostname, Address* addr);

#endif  // MDNS_H_
