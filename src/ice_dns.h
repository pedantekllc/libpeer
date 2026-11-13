#ifndef ICE_DNS_H_
#define ICE_DNS_H_

#include <stdbool.h>
#include <stdint.h>

#include "address.h"

/* Remembered addresses of the STUN/TURN servers named in ICE server URLs.
 *
 * Gathering must never wait on DNS: a lookup answers from this table and never
 * resolves. A background thread (ice_dns_start) resolves each watched name and
 * refreshes it on an interval; a refresh that fails keeps the last good
 * address. A name that has not resolved yet is its own state, so a caller
 * cannot mistake "no answer yet" for an address. */

typedef enum {
  ICE_DNS_NEVER_RESOLVED = 0, /* the name is unknown or its first resolve has not succeeded */
  ICE_DNS_RESOLVED            /* `addr` holds the last good address                          */
} IceDnsState;

typedef struct {
  IceDnsState state;
  Address addr; /* meaningful only when state == ICE_DNS_RESOLVED */
} IceDnsLookup;

typedef int (*IceDnsResolver)(const char* host, Address* addr); /* 0 on success */

/* After a success a name is resolved again after this long; after a failure it
 * is retried after the shorter interval. */
#define ICE_DNS_REFRESH_MS 300000u
#define ICE_DNS_RETRY_MS 5000u
#define ICE_DNS_MAX_HOSTS 8

/* Replace the resolver (tests); NULL restores ports_resolve_addr. */
void ice_dns_set_resolver(IceDnsResolver resolver);

/* Register `host` so it is resolved and kept fresh. Idempotent. */
void ice_dns_watch(const char* host);

/* Register the host of an ICE server URL ("stun:host:port", "turn:host:port").
 * stuns:/turns: URLs are not usable by libpeer and register nothing. */
void ice_dns_watch_url(const char* url);

/* The remembered address of `host`. Never resolves and never blocks on the
 * network; an unregistered name is registered and reads NEVER_RESOLVED. */
IceDnsLookup ice_dns_lookup(const char* host);

/* Resolve every watched name that is due at `now_ms`. This is the thread's one
 * step; tests call it directly with their own clock. */
void ice_dns_refresh_due(uint32_t now_ms);

/* Start/stop the background thread that calls ice_dns_refresh_due. */
void ice_dns_start(void);
void ice_dns_stop(void);

/* Forget every name (tests). */
void ice_dns_reset(void);

/* Split an ICE server URL into scheme/host/port. 0 on success. */
int ice_dns_parse_url(const char* url, bool* is_tls, char* host, size_t host_cap, int* port);

#endif /* ICE_DNS_H_ */
