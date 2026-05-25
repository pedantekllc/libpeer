#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <time.h>
#include <unistd.h>
#include "address.h"
#include "socket.h"
#include "utils.h"

#define MDNS_GROUP "224.0.0.251"
#define MDNS_PORT 5353

typedef struct DnsHeader {
  uint16_t id;
  uint16_t flags;
  uint16_t qestions;
  uint16_t answer_rrs;
  uint16_t authority_rrs;
  uint16_t additional_rrs;
} DnsHeader;

typedef struct DnsAnswer {
  uint16_t type;
  uint16_t class;
  uint32_t ttl;
  uint16_t length;
  uint8_t data[0];
} DnsAnswer;

typedef struct DnsQuery {
  uint16_t type;
  uint16_t class;
} DnsQuery;

static int mdns_add_hostname(const char* hostname, uint8_t* buf, int size) {
  const char *label, *dot;
  int len, offset;

  offset = 0;
  label = hostname;
  while (*label) {
    dot = strchr(label, '.');
    if (!dot) {
      dot = label + strlen(label);
    }
    len = dot - label;
    buf[offset++] = len;
    memcpy(buf + offset, label, len);
    offset += len;
    label = *dot ? dot + 1 : dot;
  }
  buf[offset++] = 0x00;
  return offset;
}
int mdns_parse_answer(uint8_t* buf, int size, Address* addr, const char* hostname) {
  int flags_qr, offset;
  DnsHeader* header;
  DnsAnswer* answer;
  uint8_t name[256];

  if (size < sizeof(DnsHeader)) {
    LOGE("response too short");
    return -1;
  }

  header = (DnsHeader*)buf;
  flags_qr = ntohs(header->flags) >> 15;
  if (flags_qr != 1) {
    LOGD("flag is not a DNS response");
    return -1;
  }

  buf += sizeof(DnsHeader);
  offset = mdns_add_hostname(hostname, name, sizeof(name));
  // compare hostname
  if (memcmp(buf, name, offset)) {
    LOGI("not a mDNS response");
    return -1;
  }

  answer = (DnsAnswer*)(buf + offset);
  LOGD("type: %" PRIu16 ", class: %" PRIu16 ", ttl: %" PRIu32 ", length: %" PRIu16 "", ntohs(answer->type), ntohs(answer->class), ntohl(answer->ttl), ntohs(answer->length));
  if (ntohs(answer->length) != 4) {
    LOGI("invalid length");
    return -1;
  }

  memcpy(&addr->sin.sin_addr, answer->data, 4);
  return 0;
}

int mdns_build_query(const char* hostname, uint8_t* buf, int size) {
  int total_size, offset;
  DnsHeader* dns_header;
  DnsQuery* dns_query;

  total_size = sizeof(DnsHeader) + strlen(hostname) + sizeof(DnsQuery) + 2;
  if (size < total_size) {
    printf("buf size is not enough");
    return -1;
  }

  memset(buf, 0, size);
  dns_header = (DnsHeader*)buf;
  dns_header->qestions = 0x0100;
  offset = sizeof(DnsHeader);

  // Append hostname to query
  offset += mdns_add_hostname(hostname, buf + offset, size - offset);

  dns_query = (DnsQuery*)(buf + offset);
  dns_query->type = 0x0100;
  dns_query->class = 0x0100;
  return total_size;
}

// Overall budget for resolving one .local name, and how often we re-send the
// query within it. A browser's mDNS responder can be slow to answer right
// after the device (or the phone) wakes, and on a busy LAN the answer can be
// lost or arrive behind unrelated mDNS chatter — so we keep listening (without
// a fixed packet budget) and re-query periodically until the deadline.
#define MDNS_TOTAL_TIMEOUT_MS 2000
#define MDNS_RESEND_INTERVAL_MS 250

static uint64_t mdns_now_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

int mdns_resolve_addr(const char* hostname, Address* addr) {
  Address mcast_addr = {0};
  UdpSocket udp_socket;
  uint8_t buf[256];
  char addr_string[ADDRSTRLEN];
  fd_set rfds;
  int size, ret;
  uint64_t deadline, next_send, now, wait_until, wait_ms;

  if (udp_socket_open(&udp_socket, AF_INET, MDNS_PORT) < 0) {
    LOGE("Failed to create socket");
    return 0;  // 0 == unresolved (callers treat non-zero as success)
  }

  addr_from_string(MDNS_GROUP, &mcast_addr);
  addr_set_port(&mcast_addr, MDNS_PORT);
  if (udp_socket_add_multicast_group(&udp_socket, &mcast_addr) < 0) {
    LOGE("Failed to add multicast group");
    udp_socket_close(&udp_socket);
    return 0;
  }

  deadline = mdns_now_ms() + MDNS_TOTAL_TIMEOUT_MS;
  next_send = 0;  // 0 forces an immediate first query below

  while ((now = mdns_now_ms()) < deadline) {
    // (Re)send the query periodically to survive multicast loss.
    if (now >= next_send) {
      size = mdns_build_query(hostname, buf, sizeof(buf));
      if (size > 0) {
        udp_socket_sendto(&udp_socket, &mcast_addr, buf, size);
      }
      next_send = now + MDNS_RESEND_INTERVAL_MS;
    }

    // Wait for a packet, but never past the next resend or the overall
    // deadline. Recompute the timeout each iteration rather than relying on
    // select() decrementing tv (Linux-only behaviour).
    wait_until = next_send < deadline ? next_send : deadline;
    wait_ms = wait_until > now ? wait_until - now : 0;

    FD_ZERO(&rfds);
    FD_SET(udp_socket.fd, &rfds);
    struct timeval tv = {(time_t)(wait_ms / 1000), (suseconds_t)((wait_ms % 1000) * 1000)};
    ret = select(udp_socket.fd + 1, &rfds, NULL, NULL, &tv);

    if (ret < 0) {
      LOGE("select error");
      break;
    }
    if (ret == 0 || !FD_ISSET(udp_socket.fd, &rfds)) {
      continue;  // slice timed out; loop re-checks deadline and re-sends
    }

    ret = udp_socket_recvfrom(&udp_socket, NULL, buf, sizeof(buf));
    if (ret > 0 && mdns_parse_answer(buf, ret, addr, hostname) == 0) {
      addr_set_family(addr, AF_INET);
      addr_to_string(addr, addr_string, sizeof(addr_string));
      LOGI("Resolved %s -> %s", hostname, addr_string);
      udp_socket_close(&udp_socket);
      return 1;
    }
    // Non-matching packet (other devices' mDNS chatter): ignore and keep
    // listening. Crucially we do NOT consume a fixed retry budget here, so
    // noise can't starve us out before the real answer arrives.
  }

  LOGI("Failed to resolve hostname %s", hostname);
  udp_socket_close(&udp_socket);
  return 0;
}
