#ifndef DTLS_SRTP_H_
#define DTLS_SRTP_H_

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/pk.h>
#include <mbedtls/ssl.h>
#include <mbedtls/ssl_cookie.h>
#include <mbedtls/timing.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/x509_csr.h>

#include <srtp2/srtp.h>

#include "address.h"

/* Non-blocking, step-wise DTLS handshake sentinel.
 *
 * dtls_srtp_handshake() (and the internal dtls_srtp_do_handshake /
 * dtls_srtp_handshake_server / dtls_srtp_handshake_client helpers) drive AT
 * MOST ONE mbedtls_ssl_handshake() call per invocation. When that single step
 * returns MBEDTLS_ERR_SSL_WANT_READ/WANT_WRITE and the handshake's wall-clock
 * deadline (DTLS_HANDSHAKE_TIMEOUT_S, dtls_srtp.c) has not yet expired, these
 * functions return DTLS_SRTP_HS_WANT instead of looping internally.
 *
 * Contract for callers (peer_connection.c's PEER_CONNECTION_CONNECTED case):
 *   0                  -> handshake complete, proceed to COMPLETED.
 *   DTLS_SRTP_HS_WANT  -> in progress; stay in the same state and call again
 *                         on a later peer_connection_loop() tick. Do NOT
 *                         treat this as success or failure.
 *   anything else (<0) -> real failure (including MBEDTLS_ERR_SSL_TIMEOUT
 *                         once the deadline has passed) -> FAILED.
 *
 * Value 1 is used because it is unambiguous against both success (0) and
 * every mbedtls error code (always negative). */
#define DTLS_SRTP_HS_WANT 1

/* dtls_srtp_handshake_server()'s per-attempt sub-state: whether the next step
 * must (re)issue mbedtls_ssl_session_reset()+set_client_transport_id() before
 * stepping (a fresh handshake, or immediately after a HelloVerifyRequest
 * round), or whether it should just keep stepping the in-flight handshake. */
typedef enum DtlsHandshakeSubState {
  DTLS_HS_SUB_NEED_RESET = 0,
  DTLS_HS_SUB_STEPPING,
} DtlsHandshakeSubState;

#define SRTP_MASTER_KEY_LENGTH 16
#define SRTP_MASTER_SALT_LENGTH 14
#define DTLS_SRTP_KEY_MATERIAL_LENGTH 60
#define DTLS_SRTP_FINGERPRINT_LENGTH 160

typedef enum DtlsSrtpRole {

  DTLS_SRTP_ROLE_CLIENT,
  DTLS_SRTP_ROLE_SERVER

} DtlsSrtpRole;

typedef enum DtlsSrtpState {

  DTLS_SRTP_STATE_INIT,
  DTLS_SRTP_STATE_HANDSHAKE,
  DTLS_SRTP_STATE_CONNECTED

} DtlsSrtpState;

typedef struct DtlsSrtp {
  // MbedTLS - per-connection SSL context and config
  mbedtls_ssl_context ssl;
  mbedtls_ssl_config conf;
  mbedtls_ssl_cookie_ctx cookie_ctx;
  mbedtls_timing_delay_context timer;  // Per-connection timer for DTLS handshake
  // NOTE: Certificate, private key, entropy, and ctr_drbg are now shared globally
  // to work around Firefox bug with multiple certs using same CN.
  // See: https://bugzilla.mozilla.org/show_bug.cgi?id=1397177

  // SRTP
  srtp_policy_t remote_policy;
  srtp_policy_t local_policy;
  srtp_t srtp_in;
  srtp_t srtp_out;
  unsigned char remote_policy_key[SRTP_MASTER_KEY_LENGTH + SRTP_MASTER_SALT_LENGTH];
  unsigned char local_policy_key[SRTP_MASTER_KEY_LENGTH + SRTP_MASTER_SALT_LENGTH];

  int (*udp_send)(void* ctx, const unsigned char* buf, size_t len);
  int (*udp_recv)(void* ctx, unsigned char* buf, size_t len);

  Address* remote_addr;

  DtlsSrtpRole role;
  DtlsSrtpState state;

  char local_fingerprint[DTLS_SRTP_FINGERPRINT_LENGTH];
  char remote_fingerprint[DTLS_SRTP_FINGERPRINT_LENGTH];
  char actual_remote_fingerprint[DTLS_SRTP_FINGERPRINT_LENGTH];

  void* user_data;

  /* ── Step-wise / non-blocking handshake state (see DTLS_SRTP_HS_WANT above
   * and dtls_srtp_do_handshake in dtls_srtp.c). All persistent ACROSS calls
   * so the reactor can drive one mbedtls step per peer_connection_loop()
   * tick without losing the wall-clock deadline or redoing one-time setup.
   * Reset to a fresh-handshake state in dtls_srtp_init(). */
  struct timespec hs_deadline;      /* wall-clock deadline; set ONCE per handshake attempt */
  int hs_initialized;                /* 0/1: has the one-time mbedtls_ssl_set_bio/timer/
                                       * export-keys-cb setup + hs_deadline been done yet
                                       * for the CURRENT handshake attempt? */
  DtlsHandshakeSubState hs_substate; /* server role: NEED_RESET vs STEPPING (HelloVerify) */

  /* mbedtls's ssl_context is NOT thread-safe (MBEDTLS_THREADING_C is disabled
   * in third_party/mbedtls/include/mbedtls/mbedtls_config.h). usrsctp's internal
   * timer thread can call our conn_output → dtls_srtp_write at the same time the
   * pc_task thread runs dtls_srtp_read on the same `ssl` context. Without this
   * mutex, concurrent ssl_read/ssl_write corrupt mbedtls's state machine
   * silently — outbound DATA chunks get queued but never crypted to the wire
   * (4MB sndbuf fills, no packets cross), even though small handshake messages
   * sent from a single thread still work. Locking around every ssl_read/write
   * eliminates the race. */
  pthread_mutex_t ssl_mutex;

} DtlsSrtp;

/**
 * Initialize the shared DTLS certificate.
 * Must be called once at application startup before any PeerConnections.
 * The certificate is shared across all connections to work around Firefox
 * bug with multiple certs using the same Common Name.
 */
int dtls_srtp_init_cert(void);

/**
 * Get the shared certificate fingerprint (for SDP generation).
 * Returns pointer to static fingerprint string, or NULL if not initialized.
 */
const char* dtls_srtp_get_fingerprint(void);

int dtls_srtp_init(DtlsSrtp* dtls_srtp, DtlsSrtpRole role, void* user_data);

void dtls_srtp_deinit(DtlsSrtp* dtls_srtp);

int dtls_srtp_handshake(DtlsSrtp* dtls_srtp, Address* addr);

void dtls_srtp_reset_session(DtlsSrtp* dtls_srtp);

int dtls_srtp_write(DtlsSrtp* dtls_srtp, const uint8_t* buf, size_t len);

int dtls_srtp_read(DtlsSrtp* dtls_srtp, uint8_t* buf, size_t len);

/* Re-send the server's last DTLS handshake flight (CCS+Finished). Used to
 * recover from a lost final flight when a peer keeps retransmitting its own
 * flight after we've completed. See dtls_srtp.c for the RFC 6347 §4.2.4 note. */
int dtls_srtp_resend(DtlsSrtp* dtls_srtp);

void dtls_srtp_sctp_to_dtls(DtlsSrtp* dtls_srtp, uint8_t* packet, int bytes);

int dtls_srtp_probe(uint8_t* buf);

void dtls_srtp_decrypt_rtp_packet(DtlsSrtp* dtls_srtp, uint8_t* packet, int* bytes);

void dtls_srtp_decrypt_rtcp_packet(DtlsSrtp* dtls_srtp, uint8_t* packet, int* bytes);

void dtls_srtp_encrypt_rtp_packet(DtlsSrtp* dtls_srtp, uint8_t* packet, int* bytes);

void dtls_srtp_encrypt_rctp_packet(DtlsSrtp* dtls_srtp, uint8_t* packet, int* bytes);

#endif  // DTLS_SRTP_H_
