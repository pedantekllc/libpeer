// Unit tests for mDNS answer parsing (mdns.c). These pin down the
// discrimination the hardened resolver relies on: a matching A-record
// response resolves, while unrelated LAN mDNS chatter (wrong hostname),
// non-responses, and malformed records are rejected — so noise can never be
// mistaken for the answer.

#include <arpa/inet.h>
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "address.h"
#include "mdns.h"

static int g_failures = 0;

#define CHECK(cond)                                          \
  do {                                                       \
    if (!(cond)) {                                           \
      printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
      g_failures++;                                          \
    }                                                        \
  } while (0)

// Build a minimal mDNS response for hostname "test.local" with a single A
// record. `qr_set` controls the response bit, `answer_len` the RDLENGTH, and
// `ip` the 4 payload bytes. Returns the total length written.
static int build_response(uint8_t* buf, int qr_set, uint16_t answer_len, const uint8_t ip[4]) {
  // "test.local" encoded as DNS labels: 4 t e s t 5 l o c a l 0
  static const uint8_t name[] = {4, 't', 'e', 's', 't', 5, 'l', 'o', 'c', 'a', 'l', 0};
  int o = 0;

  memset(buf, 0, 64);
  // DnsHeader is 12 bytes; parser only reads the flags field (offset 2..3) and
  // checks the top bit (QR). 0x84 high byte => QR=1 (response) + AA.
  if (qr_set) {
    buf[2] = 0x84;
  }
  o = 12;

  memcpy(buf + o, name, sizeof(name));
  o += sizeof(name);

  // Answer RR: type(2) class(2) ttl(4) rdlength(2) rdata(answer_len)
  buf[o++] = 0x00; buf[o++] = 0x01;                         // type A
  buf[o++] = 0x00; buf[o++] = 0x01;                         // class IN
  buf[o++] = 0x00; buf[o++] = 0x00; buf[o++] = 0x00; buf[o++] = 0x78;  // ttl 120
  buf[o++] = (uint8_t)(answer_len >> 8); buf[o++] = (uint8_t)(answer_len & 0xff);
  buf[o++] = ip[0]; buf[o++] = ip[1]; buf[o++] = ip[2]; buf[o++] = ip[3];

  return o;
}

static void test_valid_answer_resolves(void) {
  uint8_t buf[64];
  const uint8_t ip[4] = {192, 168, 1, 50};
  int len = build_response(buf, 1, 4, ip);

  Address addr;
  memset(&addr, 0, sizeof(addr));
  int r = mdns_parse_answer(buf, len, &addr, "test.local");
  CHECK(r == 0);

  addr_set_family(&addr, AF_INET);
  char s[ADDRSTRLEN];
  addr_to_string(&addr, s, sizeof(s));
  CHECK(strcmp(s, "192.168.1.50") == 0);
}

// The common LAN case: a response for some *other* device's .local name must
// be ignored, not mistaken for our answer.
static void test_wrong_hostname_rejected(void) {
  uint8_t buf[64];
  const uint8_t ip[4] = {192, 168, 1, 51};
  int len = build_response(buf, 1, 4, ip);

  Address addr;
  memset(&addr, 0, sizeof(addr));
  CHECK(mdns_parse_answer(buf, len, &addr, "other.local") != 0);
}

static void test_query_not_response_rejected(void) {
  uint8_t buf[64];
  const uint8_t ip[4] = {192, 168, 1, 52};
  int len = build_response(buf, 0 /* QR not set */, 4, ip);

  Address addr;
  memset(&addr, 0, sizeof(addr));
  CHECK(mdns_parse_answer(buf, len, &addr, "test.local") != 0);
}

static void test_bad_length_rejected(void) {
  uint8_t buf[64];
  const uint8_t ip[4] = {192, 168, 1, 53};
  int len = build_response(buf, 1, 16 /* not 4 => not an A record */, ip);

  Address addr;
  memset(&addr, 0, sizeof(addr));
  CHECK(mdns_parse_answer(buf, len, &addr, "test.local") != 0);
}

static void test_too_short_rejected(void) {
  uint8_t buf[4] = {0};
  Address addr;
  memset(&addr, 0, sizeof(addr));
  CHECK(mdns_parse_answer(buf, sizeof(buf), &addr, "test.local") != 0);
}

static void test_build_query_well_formed(void) {
  uint8_t buf[128];
  int n = mdns_build_query("test.local", buf, sizeof(buf));
  CHECK(n > 0);
  // Too-small buffer must be rejected, not overflowed.
  CHECK(mdns_build_query("test.local", buf, 4) == -1);
}

int main(void) {
  test_valid_answer_resolves();
  test_wrong_hostname_rejected();
  test_query_not_response_rejected();
  test_bad_length_rejected();
  test_too_short_rejected();
  test_build_query_well_formed();

  if (g_failures == 0) {
    printf("test_mdns: all checks passed\n");
  } else {
    printf("test_mdns: %d check(s) FAILED\n", g_failures);
  }
  return g_failures == 0 ? 0 : 1;
}
