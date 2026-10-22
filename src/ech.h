#ifndef WARPQ_ECH_H
#define WARPQ_ECH_H

#include <stddef.h>

#define ECH_DEFAULT_FRONT "cloudflare-ech.com"

/* TLS 1.3 with Encrypted Client Hello, for the API calls.
 *
 * The ECH key comes from the HTTPS DNS record of `front`, an ECH-enabled name
 * on the same CDN, and the addresses to dial from resolving that same `front`.
 * The wire then shows front's addresses and its public name as the outer SNI,
 * while `name` -- the real server -- travels only inside the encrypted inner
 * ClientHello. The
 * certificate is checked against `name`, and a handshake the server did not
 * accept ECH on is never used: if it rejects the key, the retry key it hands
 * back is tried once, and failing that the call fails.
 *
 * Built only with WARPQ_ECH (wolfSSL); otherwise ech_connect() fails. */

typedef struct ech_conn ech_conn;

ech_conn *ech_connect(const char *front, const char *name, int port);
int ech_write(ech_conn *conn, const void *buf, size_t len);
/* bytes read, 0 once the peer is done, -1 on error */
int ech_read(ech_conn *conn, void *buf, size_t len);
void ech_close(ech_conn *conn);

const char *ech_error(void);

#endif
