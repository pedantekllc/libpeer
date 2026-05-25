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

#endif  // MDNS_H_
