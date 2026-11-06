#ifndef SOCKET_H_
#define SOCKET_H_

#include "address.h"

#include <stdatomic.h>
#include <stdint.h>

/* The densest UDP_PEAK_BIN_NS of sends since the last take: what actually reached the
 * socket, after every pacer and queue above it. Several threads send on one socket, so
 * the counters are atomic and a bin boundary may split a burst; it is a readout. */
#define UDP_PEAK_BIN_NS 10000000ull

typedef struct UdpSocket {
  int fd;
  Address bind_addr;
  atomic_ullong peak_bin;
  atomic_uint bin_pkts, bin_bytes, peak_pkts, peak_bytes;
} UdpSocket;

/* The densest bin since the last call, then reset. */
void udp_socket_take_peak(UdpSocket* udp_socket, uint32_t* pkts, uint32_t* bytes);

typedef struct TcpSocket {
  int fd;
  Address bind_addr;
} TcpSocket;

int udp_socket_open(UdpSocket* udp_socket, int family, int port);

/* As udp_socket_open, but the port may already be held by another process
 * (SO_REUSEPORT): for a well-known multicast port such as mDNS's 5353, which
 * the host's own resolver usually owns. */
int udp_socket_open_shared(UdpSocket* udp_socket, int family, int port);

/* Pin an already-open socket to a single interface via SO_BINDTODEVICE so all
 * traffic ingresses/egresses on that NIC regardless of the routing table.
 * ifname NULL/empty is a no-op (returns 0). On non-Linux platforms (no
 * SO_BINDTODEVICE) this is a no-op returning 0 — single-homed dev hosts don't
 * need it. Returns 0 on success/no-op, negative on a real bind failure (e.g.
 * missing CAP_NET_RAW). */
int udp_socket_bind_iface(UdpSocket* udp_socket, const char* ifname);

int udp_socket_bind(UdpSocket* udp_socket, int port);

void udp_socket_close(UdpSocket* udp_socket);

int udp_socket_sendto(UdpSocket* udp_socket, Address* bind_addr, const uint8_t* buf, int len);

int udp_socket_recvfrom(UdpSocket* udp_sock, Address* bind_addr, uint8_t* buf, int len);

int udp_socket_add_multicast_group(UdpSocket* udp_socket, Address* mcast_addr);

int tcp_socket_open(TcpSocket* tcp_socket, int family);

int tcp_socket_connect(TcpSocket* tcp_socket, Address* addr);

void tcp_socket_close(TcpSocket* tcp_socket);

int tcp_socket_send(TcpSocket* tcp_socket, const uint8_t* buf, int len);

int tcp_socket_recv(TcpSocket* tcp_socket, uint8_t* buf, int len);

#endif  // SOCKET_H_
