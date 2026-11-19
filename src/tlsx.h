#ifndef WARPQ_TLSX_H
#define WARPQ_TLSX_H

#include <stddef.h>
#include <stdint.h>

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/pk.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>

#define TLS_WANT_IO (-2)

enum { TLS_CIPHER_AUTO, TLS_CIPHER_CHACHA, TLS_CIPHER_AES };
void tls_prefer_cipher(int preference);
int tls_global_init(void);

typedef struct {
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context drbg;
	mbedtls_ssl_context ssl;
	mbedtls_ssl_config conf;
	mbedtls_x509_crt ca;
	mbedtls_x509_crt cert;
	mbedtls_pk_context key;
	const char *alpn_list[2];
	int fd;
	int have_cert;
	/* TLS 1.3 application traffic secrets, kept from the handshake only
	 * until tls_offload() has handed them over */
	unsigned char secret_tx[48];
	unsigned char secret_rx[48];
	size_t secret_len;
	/* directions the kernel's TLS layer (kTLS) now carries; see tls_offload */
	int ktls_tx;
	int ktls_rx;
	/* warpq's own record layer, for what the kernel would not take */
	struct tls_records *own;
} tls_conn;

int identity_generate(uint8_t **key_der, size_t *key_len,
		      uint8_t **spki, size_t *spki_len);
int identity_spki(const uint8_t *key_der, size_t key_len,
		  uint8_t **spki, size_t *spki_len);

int tls_client(tls_conn *conn, const char *host, int port, const char *sni,
	       const char *alpn, const uint8_t *key_der, size_t key_len,
	       const uint8_t *pin_spki, size_t pin_len, unsigned mark);

int tls_set_nonblocking(tls_conn *conn);

/* Who carries the record layer after the handshake: the kernel if it will,
 * else warpq's own (ChaCha20-Poly1305 only), else mbedTLS. */
enum { TLS_ENGINE_AUTO, TLS_ENGINE_WARPQ, TLS_ENGINE_MBEDTLS };
int tls_offload(tls_conn *conn, int engine);
const char *tls_engine(const tls_conn *conn);

int tls_read(tls_conn *conn, void *buf, size_t len);
int tls_write(tls_conn *conn, const void *buf, size_t len);
void tls_close(tls_conn *conn);

const char *tls_error(void);
const char *tls_ciphersuite(const tls_conn *conn);

#endif
