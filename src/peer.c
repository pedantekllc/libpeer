#include <srtp2/srtp.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "dtls_srtp.h"
#include "peer.h"
#include "sctp.h"
#include "utils.h"

int peer_init() {
  if (srtp_init() != srtp_err_status_ok) {
    LOGE("libsrtp init failed");
    return -1;
  }
  sctp_usrsctp_init();

  /* Initialize shared DTLS certificate once at startup.
   * This certificate is shared across all PeerConnections to work around
   * Firefox bug 1397177 (cannot validate multiple certs with same CN). */
  if (dtls_srtp_init_cert() != 0) {
    LOGE("Failed to initialize shared DTLS certificate");
    return -1;
  }

  return 0;
}

void peer_deinit() {
  srtp_shutdown();
  sctp_usrsctp_deinit();
}
