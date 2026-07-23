#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <unistd.h>

#include "agent.h"
#include "base64.h"
#include "ice.h"
#include "mdns.h"
#include "ports.h"
#include "socket.h"
#include "stun.h"
#include "utils.h"

#define AGENT_POLL_TIMEOUT 1
#define AGENT_CONNCHECK_MAX 100
#define AGENT_CONNCHECK_PERIOD 10
#define AGENT_MAX_INPROGRESS 5  // Parallel pair checking
// After the first pair succeeds, keep checking for up to this long if a
// strictly higher-priority pair is still in progress, so a direct (host/prflx)
// path can win over a relay that merely answered first. Bounded so a
// genuinely relay-only peer still connects promptly.
#define AGENT_PAIR_SETTLE_MS 150

void agent_clear_candidates(Agent* agent) {
  int i;
  agent->local_candidates_count = 0;
  agent->remote_candidates_count = 0;
  agent->candidate_pairs_num = 0;
  agent->first_success_time = 0;
  for (i = 0; i < AGENT_MAX_PENDING_MDNS; i++) {
    agent->pending_mdns[i].active = 0;
  }
  /* Fresh attempt: reset the Plane-A/Plane-B diagnostics (see agent.h). */
  agent->turn_alloc_ok = 0;
  agent->turn_alloc_rejected = 0;
  agent->mdns_resolved = 0;
  agent->mdns_queued = 0;
  agent->selected_remote_type = -1;
}

int agent_create(Agent* agent) {
  int ret;
  /* Use the configured fixed port (0 = ephemeral). */
  if ((ret = udp_socket_open(&agent->udp_sockets[0], AF_INET, agent->media_port)) < 0) {
    LOGE("Failed to create UDP socket.");
    return ret;
  }
  LOGI("create IPv4 UDP socket: %d (port %d)", agent->udp_sockets[0].fd,
       agent->udp_sockets[0].bind_addr.port);
  /* Pin to the chosen NIC so egress media follows the advertised candidate
   * (no-op when bind_iface is empty / on platforms without SO_BINDTODEVICE). */
  udp_socket_bind_iface(&agent->udp_sockets[0], agent->bind_iface);

#if CONFIG_IPV6
  if ((ret = udp_socket_open(&agent->udp_sockets[1], AF_INET6, 0)) < 0) {
    LOGE("Failed to create IPv6 UDP socket.");
    return ret;
  }
  LOGI("create IPv6 UDP socket: %d", agent->udp_sockets[1].fd);
  udp_socket_bind_iface(&agent->udp_sockets[1], agent->bind_iface);
#endif

  agent_clear_candidates(agent);
  memset(agent->remote_ufrag, 0, sizeof(agent->remote_ufrag));
  memset(agent->remote_upwd, 0, sizeof(agent->remote_upwd));
  return 0;
}

void agent_destroy(Agent* agent) {
  if (agent->udp_sockets[0].fd > 0) {
    udp_socket_close(&agent->udp_sockets[0]);
  }

#if CONFIG_IPV6
  if (agent->udp_sockets[1].fd > 0) {
    udp_socket_close(&agent->udp_sockets[1]);
  }
#endif
}

static int agent_socket_recv(Agent* agent, Address* addr, uint8_t* buf, int len) {
  int ret = -1;
  int i = 0;
  int maxfd = -1;
  fd_set rfds;
  struct timeval tv;
  int addr_type[] = { AF_INET,
#if CONFIG_IPV6
                      AF_INET6,
#endif
  };

  tv.tv_sec = 0;
  tv.tv_usec = AGENT_POLL_TIMEOUT * 1000;
  FD_ZERO(&rfds);

  for (i = 0; i < sizeof(addr_type) / sizeof(addr_type[0]); i++) {
    if (agent->udp_sockets[i].fd > maxfd) {
      maxfd = agent->udp_sockets[i].fd;
    }
    if (agent->udp_sockets[i].fd >= 0) {
      FD_SET(agent->udp_sockets[i].fd, &rfds);
    }
  }

  ret = select(maxfd + 1, &rfds, NULL, NULL, &tv);
  if (ret < 0) {
    LOGE("select error");
  } else if (ret == 0) {
    // timeout - return -1 to indicate no data available
    ret = -1;
  } else {
    for (i = 0; i < 2; i++) {
      if (FD_ISSET(agent->udp_sockets[i].fd, &rfds)) {
        memset(buf, 0, len);
        ret = udp_socket_recvfrom(&agent->udp_sockets[i], addr, buf, len);
        break;
      }
    }
  }

  return ret;
}

/* One request/response exchange for candidate gathering: send `req` to
 * `serv_addr` and wait up to AGENT_GATHER_TIMEOUT_MS for a datagram whose STUN
 * method matches `method`, re-sending the request every AGENT_GATHER_RESEND_MS
 * to ride out UDP loss.
 *
 * agent_socket_recv() waits at most AGENT_POLL_TIMEOUT (1 ms) per call, so
 * this loop provides the actual wait. It replaces a recv helper that gave up
 * on the FIRST 1 ms timeout — a server had to answer within ~1 ms of the
 * request, which only ever happens against localhost (e2e/CI). On real
 * hardware the STUN/TURN replies always arrived after that window, so devices
 * gathered no srflx/relay candidate at all, and the late replies then sat in
 * the socket buffer to be mis-read as the response of the NEXT exchange
 * ("Invalid TURN Binding Response"). Non-matching datagrams are drained and
 * discarded here instead of aborting the exchange.
 *
 * Gathering runs on the signaling reactor, so the wait is deliberately
 * bounded: worst case (server unreachable) is AGENT_GATHER_TIMEOUT_MS per
 * exchange, ≤3 exchanges per peer connection. */
#define AGENT_GATHER_TIMEOUT_MS 500
#define AGENT_GATHER_RESEND_MS 150

static int agent_socket_send(Agent* agent, Address* addr, const uint8_t* buf, int len);

static int agent_gather_exchange(Agent* agent, Address* serv_addr, StunMessage* req,
                                 StunMessage* resp, uint16_t method) {
  uint32_t now = ports_get_epoch_time();
  uint32_t deadline = now + AGENT_GATHER_TIMEOUT_MS;
  uint32_t next_send = now;
  int ret;

  while ((now = ports_get_epoch_time()) < deadline) {
    if (now >= next_send) {
      if (agent_socket_send(agent, serv_addr, req->buf, req->size) == -1) {
        LOGE("gather: failed to send request (method 0x%04x)", method);
        return -1;
      }
      next_send = now + AGENT_GATHER_RESEND_MS;
    }
    ret = agent_socket_recv(agent, NULL, resp->buf, sizeof(resp->buf));
    if (ret > 0) {
      stun_parse_msg_buf(resp);
      if (resp->stunmethod == method) {
        return ret;
      }
      LOGD("gather: discarding non-matching datagram (method 0x%04x, want 0x%04x)",
           resp->stunmethod, method);
    }
  }
  return -1;
}

static int agent_socket_send(Agent* agent, Address* addr, const uint8_t* buf, int len) {
  switch (addr->family) {
    case AF_INET6:
      return udp_socket_sendto(&agent->udp_sockets[1], addr, buf, len);
    case AF_INET:
    default:
      return udp_socket_sendto(&agent->udp_sockets[0], addr, buf, len);
  }
  return -1;
}

static int agent_create_host_addr(Agent* agent) {
  int i, j;
  /* When the agent is pinned to an interface, gather the host candidate from
   * exactly that NIC (its name is also an exact-match prefix for
   * ports_get_host_addr). Otherwise fall back to the legacy compile-time
   * prefix list / first-interface behaviour. */
  const char* legacy_prefx[] = {CONFIG_IFACE_PREFIX};
  const char* pinned_prefx[] = {agent->bind_iface};
  const char** iface_prefx = (agent->bind_iface[0] != '\0') ? pinned_prefx : legacy_prefx;
  const int iface_prefx_count = (agent->bind_iface[0] != '\0')
                                    ? (int)(sizeof(pinned_prefx) / sizeof(pinned_prefx[0]))
                                    : (int)(sizeof(legacy_prefx) / sizeof(legacy_prefx[0]));
  IceCandidate* ice_candidate;
  int addr_type[] = { AF_INET,
#if CONFIG_IPV6
                      AF_INET6,
#endif
  };

  for (i = 0; i < sizeof(addr_type) / sizeof(addr_type[0]); i++) {
    for (j = 0; j < iface_prefx_count; j++) {
      ice_candidate = agent->local_candidates + agent->local_candidates_count;
      // only copy port and family to addr of ice candidate
      ice_candidate_create(ice_candidate, agent->local_candidates_count, ICE_CANDIDATE_TYPE_HOST,
                           &agent->udp_sockets[i].bind_addr);
      // if resolve host addr, add to local candidate
      if (ports_get_host_addr(&ice_candidate->addr, iface_prefx[j])) {
        agent->local_candidates_count++;
      }
    }
  }

  return 0;
}

static int agent_create_stun_addr(Agent* agent, Address* serv_addr) {
  int ret = -1;
  Address bind_addr;
  StunMessage send_msg;
  StunMessage recv_msg;
  memset(&send_msg, 0, sizeof(send_msg));
  memset(&recv_msg, 0, sizeof(recv_msg));

  stun_msg_create(&send_msg, STUN_CLASS_REQUEST | STUN_METHOD_BINDING);

  ret = agent_gather_exchange(agent, serv_addr, &send_msg, &recv_msg, STUN_METHOD_BINDING);
  if (ret <= 0) {
    LOGW("STUN gather: no Binding Response — srflx candidate unavailable");
    return -1;
  }

  memcpy(&bind_addr, &recv_msg.mapped_addr, sizeof(Address));
  IceCandidate* ice_candidate = agent->local_candidates + agent->local_candidates_count++;
  ice_candidate_create(ice_candidate, agent->local_candidates_count, ICE_CANDIDATE_TYPE_SRFLX, &bind_addr);
  return ret;
}

static int agent_create_turn_addr(Agent* agent, Address* serv_addr, const char* username, const char* credential) {
  int ret = -1;
  uint32_t attr = ntohl(0x11000000);
  Address turn_addr;
  StunMessage send_msg;
  StunMessage recv_msg;
  memset(&recv_msg, 0, sizeof(recv_msg));
  memset(&send_msg, 0, sizeof(send_msg));
  stun_msg_create(&send_msg, STUN_METHOD_ALLOCATE);
  stun_msg_write_attr(&send_msg, STUN_ATTR_TYPE_REQUESTED_TRANSPORT, sizeof(attr), (char*)&attr);  // UDP
  stun_msg_write_attr(&send_msg, STUN_ATTR_TYPE_USERNAME, strlen(username), (char*)username);

  ret = agent_gather_exchange(agent, serv_addr, &send_msg, &recv_msg, STUN_METHOD_ALLOCATE);
  if (ret <= 0) {
    LOGW("TURN gather: no Allocate reply — relay candidate unavailable");
    return -1;
  }

  if (recv_msg.stunclass == STUN_CLASS_ERROR) {
    /* Expected first reply: the 401 challenge carrying realm+nonce for the
     * authenticated retry (long-term credential mechanism). */
    if (recv_msg.nonce[0] == '\0' || recv_msg.realm[0] == '\0') {
      LOGW("TURN gather: Allocate error without realm/nonce challenge");
      return -1;
    }
    memset(&send_msg, 0, sizeof(send_msg));
    stun_msg_create(&send_msg, STUN_METHOD_ALLOCATE);
    stun_msg_write_attr(&send_msg, STUN_ATTR_TYPE_REQUESTED_TRANSPORT, sizeof(attr), (char*)&attr);  // UDP
    stun_msg_write_attr(&send_msg, STUN_ATTR_TYPE_USERNAME, strlen(username), (char*)username);
    stun_msg_write_attr(&send_msg, STUN_ATTR_TYPE_NONCE, strlen(recv_msg.nonce), recv_msg.nonce);
    stun_msg_write_attr(&send_msg, STUN_ATTR_TYPE_REALM, strlen(recv_msg.realm), recv_msg.realm);
    stun_msg_finish(&send_msg, STUN_CREDENTIAL_LONG_TERM, credential, strlen(credential));

    memset(&recv_msg, 0, sizeof(recv_msg));
    ret = agent_gather_exchange(agent, serv_addr, &send_msg, &recv_msg, STUN_METHOD_ALLOCATE);
    if (ret <= 0) {
      LOGW("TURN gather: no authenticated Allocate reply");
      return -1;
    }
    if (recv_msg.stunclass != STUN_CLASS_RESPONSE) {
      LOGW("TURN gather: authenticated Allocate rejected (class=0x%04x)", recv_msg.stunclass);
      agent->turn_alloc_rejected++;
      return -1;
    }
  } else if (recv_msg.stunclass != STUN_CLASS_RESPONSE) {
    LOGW("TURN gather: unexpected Allocate reply (class=0x%04x)", recv_msg.stunclass);
    return -1;
  }

  memcpy(&turn_addr, &recv_msg.relayed_addr, sizeof(Address));
  IceCandidate* ice_candidate = agent->local_candidates + agent->local_candidates_count++;
  ice_candidate_create(ice_candidate, agent->local_candidates_count, ICE_CANDIDATE_TYPE_RELAY, &turn_addr);
  agent->turn_alloc_ok++;
  return ret;
}

void agent_gather_candidate(Agent* agent, const char* urls, const char* username, const char* credential) {
  char* pos;
  int port;
  char hostname[64];
  char addr_string[ADDRSTRLEN];
  int i;
  int addr_type[1] = {AF_INET};  // ipv6 no need stun
  Address resolved_addr;
  memset(hostname, 0, sizeof(hostname));

  if (urls == NULL) {
    agent_create_host_addr(agent);
    return;
  }

  // urls is "scheme:host:port" (scheme = stun | turn | stuns | turns). Scan for
  // the scheme delimiter instead of assuming a 5-char scheme: "turns:"/"stuns:"
  // are 6 chars, and the old fixed `urls + 5` slice mis-parsed them into
  // "Cannot parse port" failures on every gather.
  const char* host = strchr(urls, ':');
  if (host == NULL) {
    LOGE("Invalid URL");
    return;
  }
  host++;

  if ((pos = strstr(host, ":")) == NULL) {
    LOGE("Invalid URL");
    return;
  }

  port = atoi(pos + 1);
  if (port <= 0) {
    LOGE("Cannot parse port");
    return;
  }

  snprintf(hostname, pos - host + 1, "%s", host);

  for (i = 0; i < sizeof(addr_type) / sizeof(addr_type[0]); i++) {
    if (ports_resolve_addr(hostname, &resolved_addr) == 0) {
      addr_set_port(&resolved_addr, port);
      addr_to_string(&resolved_addr, addr_string, sizeof(addr_string));
      LOGI("Resolved stun/turn server %s:%d", addr_string, port);

      if (strncmp(urls, "stun:", 5) == 0) {
        LOGD("Create stun addr");
        agent_create_stun_addr(agent, &resolved_addr);
      } else if (strncmp(urls, "turn:", 5) == 0) {
        LOGD("Create turn addr");
        agent_create_turn_addr(agent, &resolved_addr, username, credential);
      } else {
        /* stuns:/turns: — TLS transports libpeer does not implement; skip
         * cleanly rather than mis-driving them over plain UDP. */
        LOGD("Skipping unsupported ICE server scheme: %s", urls);
      }
    }
  }
}

void agent_create_ice_credential(Agent* agent) {
  memset(agent->local_ufrag, 0, sizeof(agent->local_ufrag));
  memset(agent->local_upwd, 0, sizeof(agent->local_upwd));

  utils_random_string(agent->local_ufrag, 4);
  utils_random_string(agent->local_upwd, 24);
}

void agent_get_local_description(Agent* agent, char* description, int length) {
  for (int i = 0; i < agent->local_candidates_count; i++) {
    ice_candidate_to_description(&agent->local_candidates[i], description + strlen(description), length - strlen(description));
  }

  // remove last \n
  description[strlen(description)] = '\0';
  LOGD("local description:\n%s", description);
}

int agent_send(Agent* agent, const uint8_t* buf, int len) {
  return agent_socket_send(agent, &agent->nominated_pair->remote->addr, buf, len);
}

static void agent_create_binding_response(Agent* agent, StunMessage* msg, Address* addr) {
  int size = 0;
  char username[584];
  char mapped_address[32];
  uint8_t mask[16];
  StunHeader* header;
  stun_msg_create(msg, STUN_CLASS_RESPONSE | STUN_METHOD_BINDING);
  header = (StunHeader*)msg->buf;
  memcpy(header->transaction_id, agent->transaction_id, sizeof(header->transaction_id));
  snprintf(username, sizeof(username), "%s:%s", agent->local_ufrag, agent->remote_ufrag);
  *((uint32_t*)mask) = htonl(MAGIC_COOKIE);
  memcpy(mask + 4, agent->transaction_id, sizeof(agent->transaction_id));
  size = stun_set_mapped_address(mapped_address, mask, addr);
  stun_msg_write_attr(msg, STUN_ATTR_TYPE_XOR_MAPPED_ADDRESS, size, mapped_address);
  stun_msg_write_attr(msg, STUN_ATTR_TYPE_USERNAME, strlen(username), username);
  stun_msg_finish(msg, STUN_CREDENTIAL_SHORT_TERM, agent->local_upwd, strlen(agent->local_upwd));
}

static void agent_create_binding_request(Agent* agent, StunMessage* msg) {
  uint64_t tie_breaker = 0;  // always be controlled
  // send binding request
  stun_msg_create(msg, STUN_CLASS_REQUEST | STUN_METHOD_BINDING);
  char username[584];
  memset(username, 0, sizeof(username));
  snprintf(username, sizeof(username), "%s:%s", agent->remote_ufrag, agent->local_ufrag);
  stun_msg_write_attr(msg, STUN_ATTR_TYPE_USERNAME, strlen(username), username);
  stun_msg_write_attr(msg, STUN_ATTR_TYPE_PRIORITY, 4, (char*)&agent->nominated_pair->priority);
  if (agent->mode == AGENT_MODE_CONTROLLING) {
    stun_msg_write_attr(msg, STUN_ATTR_TYPE_USE_CANDIDATE, 0, NULL);
    stun_msg_write_attr(msg, STUN_ATTR_TYPE_ICE_CONTROLLING, 8, (char*)&tie_breaker);
  } else {
    stun_msg_write_attr(msg, STUN_ATTR_TYPE_ICE_CONTROLLED, 8, (char*)&tie_breaker);
  }
  stun_msg_finish(msg, STUN_CREDENTIAL_SHORT_TERM, agent->remote_upwd, strlen(agent->remote_upwd));
}

/* Pair one late-arriving remote candidate against every same-family local
 * candidate. Append-only (same discipline as agent_add_prflx_candidate):
 * existing pairs and the selected/nominated_pair pointers into the array are
 * untouched, so this is safe while connectivity checks are in flight. New
 * pairs start FROZEN and are picked up by the normal check pump. */
void agent_pair_remote_candidate(Agent* agent, IceCandidate* remote) {
  int i;
  for (i = 0; i < agent->local_candidates_count; i++) {
    if (agent->local_candidates[i].addr.family != remote->addr.family) {
      continue;
    }
    if (agent->candidate_pairs_num >= AGENT_MAX_CANDIDATE_PAIRS) {
      LOGW("Cannot pair remote candidate: candidate pair table full");
      return;
    }
    IceCandidatePair* pair = &agent->candidate_pairs[agent->candidate_pairs_num];
    pair->local = &agent->local_candidates[i];
    pair->remote = remote;
    pair->priority = (uint64_t)agent->local_candidates[i].priority + (uint64_t)remote->priority;
    pair->state = ICE_CANDIDATE_STATE_FROZEN;
    pair->conncheck = 0;
    agent->candidate_pairs_num++;
  }
}

void agent_queue_mdns_candidate(Agent* agent, const IceCandidate* candidate, const char* hostname) {
  int i;
  for (i = 0; i < AGENT_MAX_PENDING_MDNS; i++) {
    if (agent->pending_mdns[i].active && strcmp(agent->pending_mdns[i].hostname, hostname) == 0) {
      return;  /* already pending on this agent */
    }
  }
  for (i = 0; i < AGENT_MAX_PENDING_MDNS; i++) {
    AgentPendingMdns* p = &agent->pending_mdns[i];
    if (p->active) {
      continue;
    }
    if (mdns_async_request(hostname) != 0) {
      return;
    }
    p->active = 1;
    snprintf(p->hostname, sizeof(p->hostname), "%s", hostname);
    p->candidate = *candidate;
    agent->mdns_queued++;
    LOGD("Queued mDNS candidate for async resolve: %s", hostname);
    return;
  }
  LOGW("Pending mDNS table full; dropping candidate %s", hostname);
}

void agent_poll_mdns_candidates(Agent* agent) {
  int i, j, state;
  Address resolved;
  char addr_string[ADDRSTRLEN];
  int has_active = 0;

  for (i = 0; i < AGENT_MAX_PENDING_MDNS; i++) {
    if (agent->pending_mdns[i].active) {
      has_active = 1;
      break;
    }
  }
  if (!has_active) {
    return;
  }

  mdns_async_poll();

  for (i = 0; i < AGENT_MAX_PENDING_MDNS; i++) {
    AgentPendingMdns* p = &agent->pending_mdns[i];
    if (!p->active) {
      continue;
    }
    state = mdns_async_lookup(p->hostname, &resolved);
    if (state == 0) {
      continue;  /* still resolving */
    }
    p->active = 0;
    if (state < 0) {
      LOGD("mDNS candidate %s did not resolve; dropped (prflx still covers the direct path)", p->hostname);
      continue;
    }

    /* Fill in the resolved IP; port/priority/foundation were parsed up-front. */
    p->candidate.addr.sin.sin_addr = resolved.sin.sin_addr;
    addr_set_family(&p->candidate.addr, AF_INET);

    if (agent->remote_candidates_count >= AGENT_MAX_CANDIDATES) {
      LOGW("Remote candidate table full; dropping resolved %s", p->hostname);
      continue;
    }
    for (j = 0; j < agent->remote_candidates_count; j++) {
      if (strcmp(agent->remote_candidates[j].foundation, p->candidate.foundation) == 0) {
        break;
      }
    }
    if (j != agent->remote_candidates_count) {
      continue;  /* duplicate of an already-known candidate */
    }

    IceCandidate* rc = &agent->remote_candidates[agent->remote_candidates_count++];
    *rc = p->candidate;
    agent_pair_remote_candidate(agent, rc);
    addr_to_string(&rc->addr, addr_string, sizeof(addr_string));
    agent->mdns_resolved++;
    LOGI("mDNS candidate resolved and paired: %s -> %s:%d", p->hostname, addr_string, rc->addr.port);
  }
}

int agent_add_prflx_candidate(Agent* agent, Address* addr) {
  int i;
  char addr_string[ADDRSTRLEN];

  // Already known (host/srflx/relay/prflx)? Nothing to learn.
  for (i = 0; i < agent->remote_candidates_count; i++) {
    if (addr_equal(&agent->remote_candidates[i].addr, addr)) {
      return i;
    }
  }

  if (agent->remote_candidates_count >= AGENT_MAX_CANDIDATES) {
    LOGW("Cannot learn peer-reflexive candidate: remote candidate table full");
    return -1;
  }

  IceCandidate* prflx = &agent->remote_candidates[agent->remote_candidates_count];
  int prflx_idx = agent->remote_candidates_count;
  ice_candidate_create(prflx, prflx_idx, ICE_CANDIDATE_TYPE_PRFLX, addr);
  agent->remote_candidates_count++;

  addr_to_string(addr, addr_string, sizeof(addr_string));
  LOGI("Learned peer-reflexive candidate %s:%d (slot %d)", addr_string, addr->port, prflx_idx);

  // Pair it with every same-family local candidate and prime each pair for an
  // immediate triggered check (INPROGRESS). The validated inbound request is
  // itself proof the remote can reach us, so we confirm the reverse direction
  // right away rather than waiting for the frozen-pair pump. Appending leaves
  // existing pairs (and the selected/nominated_pair pointers into the array)
  // untouched.
  for (i = 0; i < agent->local_candidates_count; i++) {
    if (agent->local_candidates[i].addr.family != prflx->addr.family) {
      continue;
    }
    if (agent->candidate_pairs_num >= AGENT_MAX_CANDIDATE_PAIRS) {
      LOGW("Cannot add peer-reflexive pair: candidate pair table full");
      break;
    }
    IceCandidatePair* pair = &agent->candidate_pairs[agent->candidate_pairs_num];
    pair->local = &agent->local_candidates[i];
    pair->remote = prflx;
    pair->priority = (uint64_t)agent->local_candidates[i].priority + (uint64_t)prflx->priority;
    pair->state = ICE_CANDIDATE_STATE_INPROGRESS;
    pair->conncheck = 0;
    agent->candidate_pairs_num++;
  }

  return prflx_idx;
}

void agent_process_stun_request(Agent* agent, StunMessage* stun_msg, Address* addr) {
  StunMessage msg;
  StunHeader* header;
  switch (stun_msg->stunmethod) {
    case STUN_METHOD_BINDING:
      if (stun_msg_is_valid(stun_msg->buf, stun_msg->size, agent->local_upwd) == 0) {
        header = (StunHeader*)stun_msg->buf;
        memcpy(agent->transaction_id, header->transaction_id, sizeof(header->transaction_id));
        agent_create_binding_response(agent, &msg, addr);
        agent_socket_send(agent, addr, msg.buf, msg.size);
        agent->binding_request_time = ports_get_epoch_time();
        // Browsers hide their host candidate behind an mDNS .local name in the
        // SDP, but their connectivity checks still arrive from the real
        // address. Learn it as a peer-reflexive candidate so we can establish a
        // direct path without resolving mDNS at all.
        agent_add_prflx_candidate(agent, addr);
        /* RFC 8445 §7.3.1.4 triggered check: when we are CONTROLLING and ICE
         * has already been nominated (nominated_pair != NULL), the remote peer
         * may still be in the CHECKING state and has not yet received our
         * USE_CANDIDATE STUN request (race: our ICE completed before the
         * remote started its checks).  Send a triggered binding REQUEST to
         * the incoming address so the browser can complete its ICE nomination
         * and advance from CHECKING → CONNECTED.  Without this, the browser
         * times out in CHECKING (~15 s) and the WebRTC connection never opens. */
        if (agent->mode == AGENT_MODE_CONTROLLING && agent->nominated_pair != NULL) {
          StunMessage req;
          memset(&req, 0, sizeof(req));
          /* Temporarily point nominated_pair to the peer-reflexive entry so
           * agent_create_binding_request() uses the right priority value.
           * The message is sent directly to addr, not via the pair's remote. */
          IceCandidatePair* saved_nom = agent->nominated_pair;
          agent_create_binding_request(agent, &req);
          agent->nominated_pair = saved_nom;
          agent_socket_send(agent, addr, req.buf, req.size);
          {
            char trig_addr[ADDRSTRLEN];
            addr_to_string(addr, trig_addr, sizeof(trig_addr));
            LOGD("Sent triggered USE_CANDIDATE check to %s:%u", trig_addr, addr->port);
          }
        }
      }
      break;
    default:
      break;
  }
}

void agent_process_stun_response(Agent* agent, StunMessage* stun_msg, Address* from_addr) {
  int i;
  switch (stun_msg->stunmethod) {
    case STUN_METHOD_BINDING:
      if (stun_msg_is_valid(stun_msg->buf, stun_msg->size, agent->remote_upwd) == 0) {
        // Find the pair that matches this response's source address
        for (i = 0; i < agent->candidate_pairs_num; i++) {
          if (agent->candidate_pairs[i].state == ICE_CANDIDATE_STATE_INPROGRESS &&
              addr_equal(&agent->candidate_pairs[i].remote->addr, from_addr)) {
            agent->candidate_pairs[i].state = ICE_CANDIDATE_STATE_SUCCEEDED;
            LOGI("STUN response matched pair %d", i);
            return;
          }
        }
        // Fallback to nominated_pair for backwards compatibility
        if (agent->nominated_pair) {
          agent->nominated_pair->state = ICE_CANDIDATE_STATE_SUCCEEDED;
        }
      }
      break;
    default:
      break;
  }
}

int agent_recv(Agent* agent, uint8_t* buf, int len) {
  int ret = -1;
  StunMessage stun_msg;
  Address addr;
  if ((ret = agent_socket_recv(agent, &addr, buf, len)) > 0 && stun_probe(buf, len) == 0) {
    if ((size_t)ret > sizeof(stun_msg.buf)) {
      /* Oversized STUN datagram: a legitimate STUN message never approaches
       * STUN_ATTR_BUF_SIZE. Drop it rather than truncating into
       * stun_msg.buf, which would corrupt the attribute TLV stream and let
       * stun_parse_msg_buf() walk past the buffer. Treat as consumed (like
       * any other STUN packet) so callers don't mistake the raw bytes for
       * a DTLS record. */
      LOGW("Dropping oversized STUN datagram (%d bytes > %zu byte buffer)", ret, sizeof(stun_msg.buf));
      return 0;
    }
    memcpy(stun_msg.buf, buf, ret);
    stun_msg.size = ret;
    stun_parse_msg_buf(&stun_msg);
    switch (stun_msg.stunclass) {
      case STUN_CLASS_REQUEST:
        agent_process_stun_request(agent, &stun_msg, &addr);
        break;
      case STUN_CLASS_RESPONSE:
        agent_process_stun_response(agent, &stun_msg, &addr);
        break;
      case STUN_CLASS_ERROR:
        break;
      default:
        break;
    }
    ret = 0;
  }
  return ret;
}

void agent_set_remote_description(Agent* agent, char* description) {
  /*
  a=ice-ufrag:Iexb
  a=ice-pwd:IexbSoY7JulyMbjKwISsG9
  a=candidate:1 1 UDP 1 36.231.28.50 38143 typ srflx
  */
  int i;

  LOGD("Set remote description:\n%s", description);

  char* line_start = description;
  char* line_end = NULL;

  while ((line_end = strstr(line_start, "\r\n")) != NULL) {
    if (strncmp(line_start, "a=ice-ufrag:", strlen("a=ice-ufrag:")) == 0) {
      strncpy(agent->remote_ufrag, line_start + strlen("a=ice-ufrag:"), line_end - line_start - strlen("a=ice-ufrag:"));

    } else if (strncmp(line_start, "a=ice-pwd:", strlen("a=ice-pwd:")) == 0) {
      strncpy(agent->remote_upwd, line_start + strlen("a=ice-pwd:"), line_end - line_start - strlen("a=ice-pwd:"));

    } else if (strncmp(line_start, "a=candidate:", strlen("a=candidate:")) == 0) {
      char mdns_hostname[128];
      int parsed;
      if (agent->remote_candidates_count >= AGENT_MAX_CANDIDATES) {
        LOGW("Remote candidate table full; ignoring further SDP candidates");
        line_start = line_end + 2;
        continue;
      }
      parsed = ice_candidate_from_description(&agent->remote_candidates[agent->remote_candidates_count],
                                              line_start, line_end, mdns_hostname, sizeof(mdns_hostname));
      if (parsed == 1) {
        /* .local candidate: park it for async mDNS resolution (it is promoted
         * into the table + paired by agent_poll_mdns_candidates on resolve). */
        agent_queue_mdns_candidate(agent, &agent->remote_candidates[agent->remote_candidates_count], mdns_hostname);
      } else if (parsed == 0) {
        for (i = 0; i < agent->remote_candidates_count; i++) {
          if (strcmp(agent->remote_candidates[i].foundation, agent->remote_candidates[agent->remote_candidates_count].foundation) == 0) {
            break;
          }
        }
        if (i == agent->remote_candidates_count) {
          agent->remote_candidates_count++;
        }
      }
    }

    line_start = line_end + 2;
  }

  LOGD("remote ufrag: %s", agent->remote_ufrag);
  LOGD("remote upwd: %s", agent->remote_upwd);
}

// Comparator for sorting candidate pairs by priority (highest first)
static int compare_pairs_by_priority(const void* a, const void* b) {
  const IceCandidatePair* pa = (const IceCandidatePair*)a;
  const IceCandidatePair* pb = (const IceCandidatePair*)b;
  // Higher priority first
  if (pb->priority > pa->priority) return 1;
  if (pb->priority < pa->priority) return -1;
  return 0;
}

void agent_update_candidate_pairs(Agent* agent) {
  int i, j;
  // Please set gather candidates before set remote description
  LOGI("Updating candidate pairs: local=%d, remote=%d", agent->local_candidates_count, agent->remote_candidates_count);
  for (i = 0; i < agent->local_candidates_count; i++) {
    for (j = 0; j < agent->remote_candidates_count; j++) {
      if (agent->local_candidates[i].addr.family == agent->remote_candidates[j].addr.family) {
        agent->candidate_pairs[agent->candidate_pairs_num].local = &agent->local_candidates[i];
        agent->candidate_pairs[agent->candidate_pairs_num].remote = &agent->remote_candidates[j];
        agent->candidate_pairs[agent->candidate_pairs_num].priority = agent->local_candidates[i].priority + agent->remote_candidates[j].priority;
        agent->candidate_pairs[agent->candidate_pairs_num].state = ICE_CANDIDATE_STATE_FROZEN;
        agent->candidate_pairs_num++;
      }
    }
  }

  // Sort by priority (highest first) - RFC 5245 optimization
  if (agent->candidate_pairs_num > 1) {
    qsort(agent->candidate_pairs, agent->candidate_pairs_num,
          sizeof(IceCandidatePair), compare_pairs_by_priority);
    LOGD("Sorted %d candidate pairs by priority", agent->candidate_pairs_num);
  }

  LOGI("Created %d candidate pairs", agent->candidate_pairs_num);
}

// Send binding request to a specific pair
static void agent_send_binding_to_pair(Agent* agent, IceCandidatePair* pair) {
  char addr_string[ADDRSTRLEN];
  StunMessage msg;
  memset(&msg, 0, sizeof(msg));

  // Temporarily set nominated_pair for the binding request creation
  IceCandidatePair* saved = agent->nominated_pair;
  agent->nominated_pair = pair;
  agent_create_binding_request(agent, &msg);
  agent->nominated_pair = saved;

  addr_to_string(&pair->remote->addr, addr_string, sizeof(addr_string));
  LOGD("send binding request to %s:%d (priority: %llu)",
       addr_string, pair->remote->addr.port, (unsigned long long)pair->priority);
  agent_socket_send(agent, &pair->remote->addr, msg.buf, msg.size);
}

IceCandidatePair* agent_best_succeeded_pair(Agent* agent) {
  IceCandidatePair* best = NULL;
  for (int i = 0; i < agent->candidate_pairs_num; i++) {
    if (agent->candidate_pairs[i].state == ICE_CANDIDATE_STATE_SUCCEEDED &&
        (best == NULL || agent->candidate_pairs[i].priority > best->priority)) {
      best = &agent->candidate_pairs[i];
    }
  }
  return best;
}

// True if any pair with priority strictly greater than `threshold` is still
// being checked — i.e. a better path might yet succeed.
static int agent_higher_priority_pending(Agent* agent, uint64_t threshold) {
  for (int i = 0; i < agent->candidate_pairs_num; i++) {
    if (agent->candidate_pairs[i].state == ICE_CANDIDATE_STATE_INPROGRESS &&
        agent->candidate_pairs[i].priority > threshold) {
      return 1;
    }
  }
  return 0;
}

int agent_connectivity_check(Agent* agent) {
  uint8_t buf[1400];
  int i;
  int inprogress_count = 0;
  int recv_count = 0;

  // Send binding requests to all in-progress pairs
  for (i = 0; i < agent->candidate_pairs_num; i++) {
    if (agent->candidate_pairs[i].state == ICE_CANDIDATE_STATE_INPROGRESS) {
      inprogress_count++;
      // Send on first check (conncheck==0) and every PERIOD thereafter
      if (agent->candidate_pairs[i].conncheck % AGENT_CONNCHECK_PERIOD == 0) {
        agent_send_binding_to_pair(agent, &agent->candidate_pairs[i]);
      }
      agent->candidate_pairs[i].conncheck++;  // Increment AFTER the send decision
    }
  }

  // Drain pending packets first so responses can flip pairs to SUCCEEDED
  // before we evaluate which pair to commit to.
  while (recv_count < 10 && agent_recv(agent, buf, sizeof(buf)) > 0) {
    recv_count++;
  }

  // Prefer the highest-priority succeeded pair, not whichever happened to
  // succeed first or sits earliest in the (partially unsorted) array. Relay
  // has the lowest priority, so any direct host/prflx/srflx success wins.
  IceCandidatePair* best = agent_best_succeeded_pair(agent);
  if (best != NULL) {
    if (agent->first_success_time == 0) {
      agent->first_success_time = ports_get_epoch_time();
    }
    agent->selected_pair = best;
    agent->nominated_pair = best;

    // Settle window: if a strictly higher-priority pair is still in progress
    // (e.g. the direct path while a relay answered first), don't commit yet —
    // give it a bounded chance to win so we keep media off the relay.
    if (agent_higher_priority_pending(agent, best->priority) &&
        (uint32_t)(ports_get_epoch_time() - agent->first_success_time) < AGENT_PAIR_SETTLE_MS) {
      return -1;
    }

    agent->selected_remote_type = (int)best->remote->type;
    LOGI("Selected pair (priority: %llu, remote candidate type: %d)",
         (unsigned long long)best->priority, best->remote->type);
    return 0;
  }

  if (inprogress_count == 0) {
    LOGI("No pairs in progress - total pairs=%d", agent->candidate_pairs_num);
  }
  return -1;
}

int agent_select_candidate_pair(Agent* agent) {
  int i;
  int inprogress_count = 0;
  int succeeded_count = 0;

  // First pass: count in-progress pairs and time out stale ones. We do NOT
  // commit on the first success here — selection happens after the second
  // pass (below) so a higher-priority pair still has a chance to start and be
  // preferred over a relay that answered first.
  for (i = 0; i < agent->candidate_pairs_num; i++) {
    if (agent->candidate_pairs[i].state == ICE_CANDIDATE_STATE_SUCCEEDED) {
      succeeded_count++;
    } else if (agent->candidate_pairs[i].state == ICE_CANDIDATE_STATE_INPROGRESS) {
      inprogress_count++;
      // Check for timeout (conncheck is incremented in agent_connectivity_check)
      if (agent->candidate_pairs[i].conncheck >= AGENT_CONNCHECK_MAX) {
        agent->candidate_pairs[i].state = ICE_CANDIDATE_STATE_FAILED;
        inprogress_count--;
        LOGD("Pair %d failed after %d checks", i, AGENT_CONNCHECK_MAX);
      }
    }
  }

  // Second pass: start frozen pairs if we have room (parallel checking). Kept
  // running even after a pair has succeeded so a higher-priority (direct) pair
  // still gets started and a chance to win the settle window.
  for (i = 0; i < agent->candidate_pairs_num && inprogress_count < AGENT_MAX_INPROGRESS; i++) {
    if (agent->candidate_pairs[i].state == ICE_CANDIDATE_STATE_FROZEN) {
      agent->candidate_pairs[i].conncheck = 0;
      agent->candidate_pairs[i].state = ICE_CANDIDATE_STATE_INPROGRESS;
      if (agent->nominated_pair == NULL) {
        agent->nominated_pair = &agent->candidate_pairs[i];
      }
      inprogress_count++;
      LOGD("Started pair %d (priority: %llu)", i, (unsigned long long)agent->candidate_pairs[i].priority);
    }
  }

  // Provisionally track the best succeeded pair so outbound checks/sends use
  // it; the actual commit to CONNECTED is gated by agent_connectivity_check.
  IceCandidatePair* best = agent_best_succeeded_pair(agent);
  if (best != NULL) {
    agent->selected_pair = best;
    agent->nominated_pair = best;
  }

  // Return 0 while there's still something to evaluate, -1 only when every
  // pair has failed (no successes and nothing in progress).
  return (succeeded_count > 0 || inprogress_count > 0) ? 0 : -1;
}
