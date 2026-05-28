#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "address.h"
#include "config.h"
#include "dtls_srtp.h"
#if CONFIG_MBEDTLS_DEBUG
#include "mbedtls/debug.h"
#endif
#include "mbedtls/sha256.h"
#include "mbedtls/ssl.h"
#include "ports.h"
#include "socket.h"
#include "utils.h"

/*
 * Shared DTLS certificate storage.
 *
 * Firefox has a bug where it cannot validate multiple DTLS certificates with
 * the same Common Name (CN) but different public keys from the same browser.
 * See: https://bugzilla.mozilla.org/show_bug.cgi?id=1397177
 *
 * Two mitigations:
 * 1. Share ONE certificate across all PeerConnections within a process.
 * 2. Use a random CN per process so different devices don't collide.
 *
 * Each connection still has its own SSL context and unique SRTP session keys
 * (derived during each DTLS handshake), so there is no security impact.
 */
static struct {
  int initialized;
  mbedtls_x509_crt cert;
  mbedtls_pk_context pkey;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
  char fingerprint[DTLS_SRTP_FINGERPRINT_LENGTH];
} g_shared_cert = {0};

/* Forward declaration for fingerprint computation */
static void dtls_srtp_x509_digest(const mbedtls_x509_crt* crt, char* buf);

/**
 * Initialize the shared DTLS certificate.
 * Call this once at application startup before any PeerConnections are created.
 * Thread-safe: uses simple flag check (ok for init-once pattern).
 */
int dtls_srtp_init_cert(void) {
  int ret;
  mbedtls_x509write_cert crt;
  unsigned char* cert_buf = NULL;
#if CONFIG_MBEDTLS_2_X
  mbedtls_mpi serial;
#else
  const char* serial = "peer";
#endif
  const char* pers = "dtls_srtp_shared";

  if (g_shared_cert.initialized) {
    LOGD("Shared DTLS certificate already initialized");
    return 0;
  }

  LOGI("Initializing shared DTLS certificate...");

  cert_buf = (unsigned char*)malloc(RSA_KEY_LENGTH * 2);
  if (cert_buf == NULL) {
    LOGE("malloc failed");
    return -1;
  }

  /* Initialize mbedtls structures for shared cert */
  mbedtls_x509_crt_init(&g_shared_cert.cert);
  mbedtls_pk_init(&g_shared_cert.pkey);
  mbedtls_entropy_init(&g_shared_cert.entropy);
  mbedtls_ctr_drbg_init(&g_shared_cert.ctr_drbg);

  mbedtls_ctr_drbg_seed(&g_shared_cert.ctr_drbg, mbedtls_entropy_func,
                        &g_shared_cert.entropy, (const unsigned char*)pers, strlen(pers));

#if CONFIG_DTLS_USE_ECDSA
  mbedtls_pk_setup(&g_shared_cert.pkey, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
  mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(g_shared_cert.pkey),
                      mbedtls_ctr_drbg_random, &g_shared_cert.ctr_drbg);
#else
  mbedtls_pk_setup(&g_shared_cert.pkey, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
  mbedtls_rsa_gen_key(mbedtls_pk_rsa(g_shared_cert.pkey), mbedtls_ctr_drbg_random,
                      &g_shared_cert.ctr_drbg, RSA_KEY_LENGTH, 65537);
#endif

  mbedtls_x509write_crt_init(&crt);
  mbedtls_x509write_crt_set_subject_key(&crt, &g_shared_cert.pkey);
  mbedtls_x509write_crt_set_version(&crt, MBEDTLS_X509_CRT_VERSION_3);
  mbedtls_x509write_crt_set_md_alg(&crt, MBEDTLS_MD_SHA256);
  mbedtls_x509write_crt_set_subject_key(&crt, &g_shared_cert.pkey);
  mbedtls_x509write_crt_set_issuer_key(&crt, &g_shared_cert.pkey);

  /* Use a unique CN per process to work around Firefox bug 1397177.
   * Firefox rejects multiple DTLS certs with the same CN but different keys. */
  unsigned char cn_rand[8];
  mbedtls_ctr_drbg_random(&g_shared_cert.ctr_drbg, cn_rand, sizeof(cn_rand));
  char cn_name[64];
  snprintf(cn_name, sizeof(cn_name), "CN=%02x%02x%02x%02x%02x%02x%02x%02x",
           cn_rand[0], cn_rand[1], cn_rand[2], cn_rand[3],
           cn_rand[4], cn_rand[5], cn_rand[6], cn_rand[7]);
  mbedtls_x509write_crt_set_subject_name(&crt, cn_name);
  mbedtls_x509write_crt_set_issuer_name(&crt, cn_name);

#if CONFIG_MBEDTLS_2_X
  mbedtls_mpi_init(&serial);
  mbedtls_mpi_fill_random(&serial, 16, mbedtls_ctr_drbg_random, &g_shared_cert.ctr_drbg);
  ret = mbedtls_x509write_crt_set_serial(&crt, &serial);
  if (ret < 0) {
    LOGE("mbedtls_x509write_crt_set_serial failed -0x%.4x", (unsigned int)-ret);
  }
#else
  mbedtls_x509write_crt_set_serial_raw(&crt, (unsigned char*)serial, strlen(serial));
#endif

  mbedtls_x509write_crt_set_validity(&crt, "20180101000000", "20280101000000");

  ret = mbedtls_x509write_crt_pem(&crt, cert_buf, 2 * RSA_KEY_LENGTH,
                                   mbedtls_ctr_drbg_random, &g_shared_cert.ctr_drbg);
  if (ret < 0) {
    LOGE("mbedtls_x509write_crt_pem failed -0x%.4x", (unsigned int)-ret);
    free(cert_buf);
    return ret;
  }

  mbedtls_x509_crt_parse(&g_shared_cert.cert, cert_buf, 2 * RSA_KEY_LENGTH);
  mbedtls_x509write_crt_free(&crt);
  free(cert_buf);

  /* Compute fingerprint once */
  dtls_srtp_x509_digest(&g_shared_cert.cert, g_shared_cert.fingerprint);

  g_shared_cert.initialized = 1;
  LOGI("Shared DTLS certificate initialized. Fingerprint: %s", g_shared_cert.fingerprint);

  return 0;
}

/**
 * Get the shared certificate fingerprint (for SDP generation).
 * Returns pointer to static fingerprint string, or NULL if not initialized.
 */
const char* dtls_srtp_get_fingerprint(void) {
  if (!g_shared_cert.initialized) {
    return NULL;
  }
  return g_shared_cert.fingerprint;
}

int dtls_srtp_udp_send(void* ctx, const uint8_t* buf, size_t len) {
  DtlsSrtp* dtls_srtp = (DtlsSrtp*)ctx;
  UdpSocket* udp_socket = (UdpSocket*)dtls_srtp->user_data;

  int ret = udp_socket_sendto(udp_socket, dtls_srtp->remote_addr, buf, len);

  LOGD("dtls_srtp_udp_send (%d)", ret);

  return ret;
}

int dtls_srtp_udp_recv(void* ctx, uint8_t* buf, size_t len) {
  DtlsSrtp* dtls_srtp = (DtlsSrtp*)ctx;
  UdpSocket* udp_socket = (UdpSocket*)dtls_srtp->user_data;

  int ret;

  while ((ret = udp_socket_recvfrom(udp_socket, &udp_socket->bind_addr, buf, len)) <= 0) {
    ports_sleep_ms(1);
  }

  LOGD("dtls_srtp_udp_recv (%d)", ret);

  return ret;
}

static void dtls_srtp_x509_digest(const mbedtls_x509_crt* crt, char* buf) {
  int i;
  unsigned char digest[32];

  mbedtls_sha256_context sha256_ctx;
  mbedtls_sha256_init(&sha256_ctx);
  mbedtls_sha256_starts(&sha256_ctx, 0);
  mbedtls_sha256_update(&sha256_ctx, crt->raw.p, crt->raw.len);
  mbedtls_sha256_finish(&sha256_ctx, (unsigned char*)digest);
  mbedtls_sha256_free(&sha256_ctx);

  for (i = 0; i < 32; i++) {
    snprintf(buf, 4, "%.2X:", digest[i]);
    buf += 3;
  }

  *(--buf) = '\0';
}

// Do not verify CA
static int dtls_srtp_cert_verify(void* data, mbedtls_x509_crt* crt, int depth, uint32_t* flags) {
  *flags &= ~(MBEDTLS_X509_BADCERT_NOT_TRUSTED | MBEDTLS_X509_BADCERT_CN_MISMATCH | MBEDTLS_X509_BADCERT_BAD_KEY);
  return 0;
}

/* NOTE: dtls_srtp_selfsign_cert was removed.
 * Certificate generation is now done once via dtls_srtp_init_cert() and shared
 * across all connections. This works around Firefox bug 1397177. */

#if CONFIG_MBEDTLS_DEBUG
static void dtls_srtp_debug(void* ctx, int level, const char* file, int line, const char* str) {
  LOGD("%s:%04d: %s", file, line, str);
}
#endif

int dtls_srtp_init(DtlsSrtp* dtls_srtp, DtlsSrtpRole role, void* user_data) {
  static const mbedtls_ssl_srtp_profile default_profiles[] = {
      MBEDTLS_TLS_SRTP_AES128_CM_HMAC_SHA1_80,
      MBEDTLS_TLS_SRTP_AES128_CM_HMAC_SHA1_32,
      MBEDTLS_TLS_SRTP_NULL_HMAC_SHA1_80,
      MBEDTLS_TLS_SRTP_NULL_HMAC_SHA1_32,
      MBEDTLS_TLS_SRTP_UNSET};

  /* Ensure shared certificate is initialized */
  if (!g_shared_cert.initialized) {
    LOGE("Shared DTLS certificate not initialized! Call dtls_srtp_init_cert() first.");
    return -1;
  }

  dtls_srtp->role = role;
  dtls_srtp->state = DTLS_SRTP_STATE_INIT;
  dtls_srtp->user_data = user_data;
  dtls_srtp->udp_send = dtls_srtp_udp_send;
  dtls_srtp->udp_recv = dtls_srtp_udp_recv;
  pthread_mutex_init(&dtls_srtp->ssl_mutex, NULL);

  /* Initialize per-connection mbedtls structures (SSL context, config, etc.)
   * but NOT cert/pkey/entropy/ctr_drbg - those are shared */
  mbedtls_ssl_config_init(&dtls_srtp->conf);
  mbedtls_ssl_init(&dtls_srtp->ssl);

  /* Copy shared fingerprint to this connection's local_fingerprint */
  memcpy(dtls_srtp->local_fingerprint, g_shared_cert.fingerprint, DTLS_SRTP_FINGERPRINT_LENGTH);
  LOGD("Using shared certificate fingerprint: %s", dtls_srtp->local_fingerprint);

  /* IMPORTANT: mbedtls_ssl_config_defaults MUST be called FIRST, before other
   * mbedtls_ssl_conf_* functions. It sets default values which would overwrite
   * any previously configured settings. */
  if (dtls_srtp->role == DTLS_SRTP_ROLE_SERVER) {
    mbedtls_ssl_config_defaults(&dtls_srtp->conf,
                                MBEDTLS_SSL_IS_SERVER,
                                MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                                MBEDTLS_SSL_PRESET_DEFAULT);

    mbedtls_ssl_cookie_init(&dtls_srtp->cookie_ctx);
    mbedtls_ssl_cookie_setup(&dtls_srtp->cookie_ctx, mbedtls_ctr_drbg_random, &g_shared_cert.ctr_drbg);
    mbedtls_ssl_conf_dtls_cookies(&dtls_srtp->conf, mbedtls_ssl_cookie_write, mbedtls_ssl_cookie_check, &dtls_srtp->cookie_ctx);
  } else {
    mbedtls_ssl_config_defaults(&dtls_srtp->conf,
                                MBEDTLS_SSL_IS_CLIENT,
                                MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                                MBEDTLS_SSL_PRESET_DEFAULT);
  }

  /* Now configure SSL options AFTER defaults are set */
#if CONFIG_MBEDTLS_DEBUG
  mbedtls_debug_set_threshold(CONFIG_MBEDTLS_DEBUG);
  mbedtls_ssl_conf_dbg(&dtls_srtp->conf, dtls_srtp_debug, NULL);
#endif

  mbedtls_ssl_conf_verify(&dtls_srtp->conf, dtls_srtp_cert_verify, NULL);
  mbedtls_ssl_conf_authmode(&dtls_srtp->conf, MBEDTLS_SSL_VERIFY_REQUIRED);
  /* Use the shared certificate and private key for all connections */
  mbedtls_ssl_conf_ca_chain(&dtls_srtp->conf, &g_shared_cert.cert, NULL);
  mbedtls_ssl_conf_own_cert(&dtls_srtp->conf, &g_shared_cert.cert, &g_shared_cert.pkey);
  mbedtls_ssl_conf_rng(&dtls_srtp->conf, mbedtls_ctr_drbg_random, &g_shared_cert.ctr_drbg);
  mbedtls_ssl_conf_read_timeout(&dtls_srtp->conf, 1000);

  /* Configure DTLS-SRTP specific options */
  mbedtls_ssl_conf_dtls_srtp_protection_profiles(&dtls_srtp->conf, default_profiles);
  mbedtls_ssl_conf_srtp_mki_value_supported(&dtls_srtp->conf, MBEDTLS_SSL_DTLS_SRTP_MKI_UNSUPPORTED);
  mbedtls_ssl_conf_cert_req_ca_list(&dtls_srtp->conf, MBEDTLS_SSL_CERT_REQ_CA_LIST_DISABLED);

  /* Disable session resumption/tickets to prevent cross-connection confusion.
   * Each WebRTC connection should use a fresh DTLS handshake. */
#if defined(MBEDTLS_SSL_SESSION_TICKETS) && defined(MBEDTLS_SSL_SRV_C)
  /* For server: don't issue session tickets */
  mbedtls_ssl_conf_session_tickets_cb(&dtls_srtp->conf, NULL, NULL, NULL);
#endif

  /* Finally, set up the SSL context with the configured options */
  mbedtls_ssl_setup(&dtls_srtp->ssl, &dtls_srtp->conf);

  return 0;
}

void dtls_srtp_deinit(DtlsSrtp* dtls_srtp) {
  /* Free per-connection SSL context and config */
  mbedtls_ssl_free(&dtls_srtp->ssl);
  mbedtls_ssl_config_free(&dtls_srtp->conf);
  pthread_mutex_destroy(&dtls_srtp->ssl_mutex);

  /* NOTE: We do NOT free cert, pkey, entropy, or ctr_drbg here because
   * they are part of the shared g_shared_cert structure, not per-connection.
   * The shared certificate persists for the lifetime of the application. */

  if (dtls_srtp->role == DTLS_SRTP_ROLE_SERVER) {
    mbedtls_ssl_cookie_free(&dtls_srtp->cookie_ctx);
  }

  if (dtls_srtp->state == DTLS_SRTP_STATE_CONNECTED) {
    srtp_dealloc(dtls_srtp->srtp_in);
    srtp_dealloc(dtls_srtp->srtp_out);
  }
}

static int dtls_srtp_key_derivation(DtlsSrtp* dtls_srtp, const unsigned char* master_secret, size_t secret_len, const unsigned char* randbytes, size_t randbytes_len, mbedtls_tls_prf_types tls_prf_type) {
  int ret;
  const char* dtls_srtp_label = "EXTRACTOR-dtls_srtp";
  uint8_t key_material[DTLS_SRTP_KEY_MATERIAL_LENGTH];
  // Export keying material
  if ((ret = mbedtls_ssl_tls_prf(tls_prf_type, master_secret, secret_len, dtls_srtp_label,
                                 randbytes, randbytes_len, key_material, sizeof(key_material))) != 0) {
    LOGE("mbedtls_ssl_tls_prf failed(%d)", ret);
    return ret;
  }

#if 0
  int i, j;
  printf("    DTLS-SRTP key material is:");
  for (j = 0; j < sizeof(key_material); j++) {
    if (j % 8 == 0) {
      printf("\n    ");
    }
    printf("%02x ", key_material[j]);
  }
  printf("\n");

  /* produce a less readable output used to perform automatic checks
   * - compare client and server output
   * - interop test with openssl which client produces this kind of output
   */
  printf("    Keying material: ");
  for (j = 0; j < sizeof(key_material); j++) {
    printf("%02X", key_material[j]);
  }
  printf("\n");
#endif

  const uint8_t* client_key = key_material;
  const uint8_t* server_key = client_key + SRTP_MASTER_KEY_LENGTH;
  const uint8_t* client_salt = server_key + SRTP_MASTER_KEY_LENGTH;
  const uint8_t* server_salt = client_salt + SRTP_MASTER_SALT_LENGTH;
  uint8_t *local_key, *remote_key, *local_salt, *remote_salt;
  if (dtls_srtp->role == DTLS_SRTP_ROLE_SERVER) {
    local_key = server_key;
    local_salt = server_salt;
    remote_key = client_key;
    remote_salt = client_salt;
  } else {
    local_key = client_key;
    local_salt = client_salt;
    remote_key = server_key;
    remote_salt = server_salt;
  }
  // derive inbounds keys

  memset(&dtls_srtp->remote_policy, 0, sizeof(dtls_srtp->remote_policy));

  srtp_crypto_policy_set_rtp_default(&dtls_srtp->remote_policy.rtp);
  srtp_crypto_policy_set_rtcp_default(&dtls_srtp->remote_policy.rtcp);

  memcpy(dtls_srtp->remote_policy_key, remote_key, SRTP_MASTER_KEY_LENGTH);
  memcpy(dtls_srtp->remote_policy_key + SRTP_MASTER_KEY_LENGTH, remote_salt, SRTP_MASTER_SALT_LENGTH);

  dtls_srtp->remote_policy.ssrc.type = ssrc_any_inbound;
  dtls_srtp->remote_policy.key = dtls_srtp->remote_policy_key;
  dtls_srtp->remote_policy.next = NULL;

  if (srtp_create(&dtls_srtp->srtp_in, &dtls_srtp->remote_policy) != srtp_err_status_ok) {
    LOGD("Error creating inbound SRTP session for component");
    return -1;
  }

  LOGI("Created inbound SRTP session");

  // derive outbounds keys
  memset(&dtls_srtp->local_policy, 0, sizeof(dtls_srtp->local_policy));

  srtp_crypto_policy_set_rtp_default(&dtls_srtp->local_policy.rtp);
  srtp_crypto_policy_set_rtcp_default(&dtls_srtp->local_policy.rtcp);

  memcpy(dtls_srtp->local_policy_key, local_key, SRTP_MASTER_KEY_LENGTH);
  memcpy(dtls_srtp->local_policy_key + SRTP_MASTER_KEY_LENGTH, local_salt, SRTP_MASTER_SALT_LENGTH);

  dtls_srtp->local_policy.ssrc.type = ssrc_any_outbound;
  dtls_srtp->local_policy.key = dtls_srtp->local_policy_key;
  dtls_srtp->local_policy.next = NULL;

  if (srtp_create(&dtls_srtp->srtp_out, &dtls_srtp->local_policy) != srtp_err_status_ok) {
    LOGE("Error creating outbound SRTP session");
    return -1;
  }

  LOGI("Created outbound SRTP session");
  dtls_srtp->state = DTLS_SRTP_STATE_CONNECTED;
  return 0;
}

#if CONFIG_MBEDTLS_2_X
static int dtls_srtp_key_derivation_cb(void* context,
                                       const unsigned char* ms,
                                       const unsigned char* kb,
                                       size_t maclen,
                                       size_t keylen,
                                       size_t ivlen,
                                       const unsigned char client_random[32],
                                       const unsigned char server_random[32],
                                       mbedtls_tls_prf_types tls_prf_type) {
#else
static void dtls_srtp_key_derivation_cb(void* context,
                                        mbedtls_ssl_key_export_type secret_type,
                                        const unsigned char* secret,
                                        size_t secret_len,
                                        const unsigned char client_random[32],
                                        const unsigned char server_random[32],
                                        mbedtls_tls_prf_types tls_prf_type) {
#endif
  DtlsSrtp* dtls_srtp = (DtlsSrtp*)context;

  unsigned char master_secret[48];
  unsigned char randbytes[64];

  memcpy(randbytes, client_random, 32);
  memcpy(randbytes + 32, server_random, 32);

#if CONFIG_MBEDTLS_2_X
  memcpy(master_secret, ms, sizeof(master_secret));
  return dtls_srtp_key_derivation(dtls_srtp, master_secret, sizeof(master_secret), randbytes, sizeof(randbytes), tls_prf_type);
#else
  memcpy(master_secret, secret, sizeof(master_secret));
  dtls_srtp_key_derivation(dtls_srtp, master_secret, sizeof(master_secret), randbytes, sizeof(randbytes), tls_prf_type);
#endif
}

static int dtls_srtp_do_handshake(DtlsSrtp* dtls_srtp) {
  int ret;

  // Use per-connection timer instead of static to support multiple simultaneous handshakes
  mbedtls_ssl_set_timer_cb(&dtls_srtp->ssl, &dtls_srtp->timer, mbedtls_timing_set_delay, mbedtls_timing_get_delay);

#if CONFIG_MBEDTLS_2_X
  mbedtls_ssl_conf_export_keys_ext_cb(&dtls_srtp->conf, dtls_srtp_key_derivation_cb, dtls_srtp);
#else
  mbedtls_ssl_set_export_keys_cb(&dtls_srtp->ssl, dtls_srtp_key_derivation_cb, dtls_srtp);
#endif

  mbedtls_ssl_set_bio(&dtls_srtp->ssl, dtls_srtp, dtls_srtp->udp_send, dtls_srtp->udp_recv, NULL);

  do {
    ret = mbedtls_ssl_handshake(&dtls_srtp->ssl);

  } while (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE);

  return ret;
}

static int dtls_srtp_handshake_server(DtlsSrtp* dtls_srtp) {
  int ret;

  /* Verify we're using the shared certificate */
  if (strncmp(dtls_srtp->local_fingerprint, g_shared_cert.fingerprint, DTLS_SRTP_FINGERPRINT_LENGTH) != 0) {
    LOGE("CERTIFICATE MISMATCH! Connection: %s, Shared: %s", dtls_srtp->local_fingerprint, g_shared_cert.fingerprint);
  }

  while (1) {
    // Use actual client address with port for transport ID to distinguish between multiple clients.
    // Including the port is critical when multiple clients connect from the same IP address.
    char client_addr_str[ADDRSTRLEN + 10];  // IP + ":port"
    int addr_len = 0;
    if (dtls_srtp->remote_addr) {
      addr_to_string_with_port(dtls_srtp->remote_addr, client_addr_str, sizeof(client_addr_str));
      addr_len = strlen(client_addr_str);
    } else {
      // Fallback if no address set yet
      strcpy(client_addr_str, "unknown");
      addr_len = 7;
    }
    LOGD("DTLS handshake with client: %s", client_addr_str);

    mbedtls_ssl_session_reset(&dtls_srtp->ssl);

    mbedtls_ssl_set_client_transport_id(&dtls_srtp->ssl, (unsigned char*)client_addr_str, addr_len);

    ret = dtls_srtp_do_handshake(dtls_srtp);

    if (ret == MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED) {
      LOGD("DTLS hello verification requested");

    } else if (ret != 0) {
      LOGE("failed! mbedtls_ssl_handshake returned -0x%.4x", (unsigned int)-ret);

      break;

    } else {
      break;
    }
  }

  LOGD("DTLS server handshake done");

  return ret;
}

static int dtls_srtp_handshake_client(DtlsSrtp* dtls_srtp) {
  int ret;

  ret = dtls_srtp_do_handshake(dtls_srtp);
  if (ret != 0) {
    LOGE("failed! mbedtls_ssl_handshake returned -0x%.4x\n\n", (unsigned int)-ret);
  }

  LOGD("DTLS client handshake done");

  return ret;
}

int dtls_srtp_handshake(DtlsSrtp* dtls_srtp, Address* addr) {
  int ret;
  dtls_srtp->remote_addr = addr;

  if (dtls_srtp->role == DTLS_SRTP_ROLE_SERVER) {
    ret = dtls_srtp_handshake_server(dtls_srtp);
  } else {
    ret = dtls_srtp_handshake_client(dtls_srtp);
  }

  const mbedtls_x509_crt* remote_crt;
  if ((remote_crt = mbedtls_ssl_get_peer_cert(&dtls_srtp->ssl)) != NULL) {
    dtls_srtp_x509_digest(remote_crt, dtls_srtp->actual_remote_fingerprint);

    if (strncmp(dtls_srtp->remote_fingerprint, dtls_srtp->actual_remote_fingerprint, DTLS_SRTP_FINGERPRINT_LENGTH) != 0) {
      LOGE("Actual and Expected Fingerprint mismatch: %s %s",
           dtls_srtp->remote_fingerprint,
           dtls_srtp->actual_remote_fingerprint);
      return -1;
    }

  } else {
    LOGE("no remote fingerprint");
    return -1;
  }

  mbedtls_dtls_srtp_info dtls_srtp_negotiation_result;
  mbedtls_ssl_get_dtls_srtp_negotiation_result(&dtls_srtp->ssl, &dtls_srtp_negotiation_result);

  /* Log the negotiated DTLS cipher right after the handshake finishes (the
   * later ssl_session_reset path clears this). */
  {
    const char* suite = mbedtls_ssl_get_ciphersuite(&dtls_srtp->ssl);
    LOGI("DTLS negotiated cipher: %s", suite ? suite : "(unknown)");
  }

  return ret;
}

void dtls_srtp_reset_session(DtlsSrtp* dtls_srtp) {
  if (dtls_srtp->state == DTLS_SRTP_STATE_CONNECTED) {
    srtp_dealloc(dtls_srtp->srtp_in);
    srtp_dealloc(dtls_srtp->srtp_out);
    mbedtls_ssl_session_reset(&dtls_srtp->ssl);
  }

  dtls_srtp->state = DTLS_SRTP_STATE_INIT;
}

int dtls_srtp_write(DtlsSrtp* dtls_srtp, const unsigned char* buf, size_t len) {
  int ret;

  /* See ssl_mutex comment in dtls_srtp.h — mbedtls's ssl_context is not
   * thread-safe in this build, so all access is serialized. Without this,
   * usrsctp's timer thread (calling us via sctp_outgoing_data_cb to emit
   * DATA chunks) races pc_task (calling dtls_srtp_read) on the same ssl
   * ctx. */
  pthread_mutex_lock(&dtls_srtp->ssl_mutex);
  do {
    ret = mbedtls_ssl_write(&dtls_srtp->ssl, buf, len);
  } while (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE);
  pthread_mutex_unlock(&dtls_srtp->ssl_mutex);

  /* Anything but a positive byte count is a real failure to encrypt+send.
   * The caller (sctp_outgoing_data_cb on the data-channel path) used to
   * discard this return value, masking DTLS-level failures as silent data
   * loss; surface it loudly. */
  if (ret <= 0) {
    LOGE("dtls_srtp_write: mbedtls_ssl_write returned %d (0x%04x) for %zu bytes",
         ret, (unsigned)(ret < 0 ? -ret : 0), len);
  }
  return ret;
}

int dtls_srtp_read(DtlsSrtp* dtls_srtp, unsigned char* buf, size_t len) {
  int ret;

  memset(buf, 0, len);

  pthread_mutex_lock(&dtls_srtp->ssl_mutex);
  /* Only loop on WANT_WRITE (mbedtls wants to push out an internal record).
   * WANT_READ means "no more bytes available from BIO recv right now" — at
   * steady-state that's the normal exit when we've consumed the cached wire
   * packet, so we must not spin (BIO recv would just keep returning WANT_READ
   * because the dispatch loop hasn't fed us a fresh packet yet). The outer
   * dispatch in peer_connection_loop is the natural retry: it iterates per
   * agent_recv packet and calls dtls_srtp_read fresh each time. */
  do {
    ret = mbedtls_ssl_read(&dtls_srtp->ssl, buf, len);
  } while (ret == MBEDTLS_ERR_SSL_WANT_WRITE);
  pthread_mutex_unlock(&dtls_srtp->ssl_mutex);

  /* Normal end-of-data: BIO had no more bytes to give. Caller treats 0
   * as "no plaintext extracted this call" and moves on. */
  if (ret == MBEDTLS_ERR_SSL_WANT_READ) return 0;

  /* Anything else negative is an actual decrypt/protocol failure. The
   * dispatch loop checks `ret > 0` and silently skips otherwise, so log
   * it here or the failure mode (corrupt record, bad MAC, TIMEOUT from a
   * misbehaving BIO recv) is invisible. */
  if (ret < 0) {
    LOGE("dtls_srtp_read: mbedtls_ssl_read returned %d (0x%04x)",
         ret, (unsigned)(-ret));
  }
  return ret;
}

int dtls_srtp_probe(uint8_t* buf) {
  if (buf == NULL)
    return 0;

  LOGD("DTLS content type: %d", buf[0]);
  // only handle application data
  return (buf[0] == 0x17);
}

void dtls_srtp_decrypt_rtp_packet(DtlsSrtp* dtls_srtp, uint8_t* packet, int* bytes) {
  srtp_unprotect(dtls_srtp->srtp_in, packet, bytes);
}

void dtls_srtp_decrypt_rtcp_packet(DtlsSrtp* dtls_srtp, uint8_t* packet, int* bytes) {
  srtp_unprotect_rtcp(dtls_srtp->srtp_in, packet, bytes);
}

void dtls_srtp_encrypt_rtp_packet(DtlsSrtp* dtls_srtp, uint8_t* packet, int* bytes) {
  srtp_protect(dtls_srtp->srtp_out, packet, bytes);
}

void dtls_srtp_encrypt_rctp_packet(DtlsSrtp* dtls_srtp, uint8_t* packet, int* bytes) {
  srtp_protect_rtcp(dtls_srtp->srtp_out, packet, bytes);
}
