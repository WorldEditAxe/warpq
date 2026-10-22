#include "tlsx.h"

#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/x509_csr.h>
#include <psa/crypto.h>

#include "route.h"
#include "util.h"

/* one per worker thread: every worker calls fail() on its own errors */
static __thread char error_buf[256];
static int cipher_preference = TLS_CIPHER_AUTO;

void tls_prefer_cipher(int preference)
{
	cipher_preference = preference;
}

/* TLS 1.3 runs on PSA crypto, whose key store and RNG are process-wide.
 * Left alone, mbedTLS initialises them lazily from inside the first
 * ClientHello -- and with several workers handshaking at once that happens
 * on several threads together, which corrupts the TLS contexts: a worker
 * either deadlocks on its DRBG mutex or crashes through a mangled
 * ssl->conf. Call this once before any thread starts a handshake. */
int tls_global_init(void)
{
	psa_status_t status = psa_crypto_init();

	if (status != PSA_SUCCESS) {
		snprintf(error_buf, sizeof(error_buf),
			 "failed to initialise PSA crypto: %d", (int)status);
		return -1;
	}
	return 0;
}

const char *tls_error(void)
{
	return error_buf;
}

const char *tls_ciphersuite(const tls_conn *conn)
{
	const char *name = mbedtls_ssl_get_ciphersuite(&conn->ssl);

	return name ? name : "unknown";
}

static int fail(const char *what, int code)
{
	char detail[128] = "";

	if (code)
		mbedtls_strerror(code, detail, sizeof(detail));
	snprintf(error_buf, sizeof(error_buf), "%s%s%s", what, code ? ": " : "", detail);
	return -1;
}

static const char *CA_PATHS[] = {
	"/etc/ssl/certs/ca-certificates.crt",
	"/etc/ssl/cert.pem",
	"/etc/pki/tls/certs/ca-bundle.crt",
	NULL
};

static int rng_init(tls_conn *conn)
{
	static const char personal[] = "warpq";
	int rc;

	mbedtls_entropy_init(&conn->entropy);
	mbedtls_ctr_drbg_init(&conn->drbg);
	rc = mbedtls_ctr_drbg_seed(&conn->drbg, mbedtls_entropy_func, &conn->entropy,
				   (const unsigned char *)personal, sizeof(personal) - 1);
	return rc ? fail("failed to seed RNG", rc) : 0;
}

int identity_generate(uint8_t **key_der, size_t *key_len, uint8_t **spki, size_t *spki_len)
{
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context drbg;
	mbedtls_pk_context pk;
	unsigned char buf[1024];
	int rc, len;

	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&drbg);
	mbedtls_pk_init(&pk);
	*key_der = *spki = NULL;

	rc = mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &entropy,
				   (const unsigned char *)"warpq-key", 9);
	if (rc)
		goto error;
	rc = mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
	if (rc)
		goto error;
	rc = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(pk),
				 mbedtls_ctr_drbg_random, &drbg);
	if (rc)
		goto error;

	len = mbedtls_pk_write_key_der(&pk, buf, sizeof(buf));
	if (len < 0) {
		rc = len;
		goto error;
	}
	*key_len = (size_t)len;
	*key_der = malloc(*key_len);
	if (!*key_der)
		goto nomem;
	memcpy(*key_der, buf + sizeof(buf) - *key_len, *key_len);

	len = mbedtls_pk_write_pubkey_der(&pk, buf, sizeof(buf));
	if (len < 0) {
		rc = len;
		goto error;
	}
	*spki_len = (size_t)len;
	*spki = malloc(*spki_len);
	if (!*spki)
		goto nomem;
	memcpy(*spki, buf + sizeof(buf) - *spki_len, *spki_len);

	mbedtls_pk_free(&pk);
	mbedtls_ctr_drbg_free(&drbg);
	mbedtls_entropy_free(&entropy);
	return 0;

nomem:
	rc = 0;
	free(*key_der);
	*key_der = NULL;
error:
	mbedtls_pk_free(&pk);
	mbedtls_ctr_drbg_free(&drbg);
	mbedtls_entropy_free(&entropy);
	return fail("failed to generate device key", rc);
}

int identity_spki(const uint8_t *key_der, size_t key_len, uint8_t **spki, size_t *spki_len)
{
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context drbg;
	mbedtls_pk_context pk;
	unsigned char buf[512];
	int rc, len;

	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&drbg);
	mbedtls_pk_init(&pk);

	rc = mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &entropy,
				   (const unsigned char *)"warpq-spki", 10);
	if (!rc)
		rc = mbedtls_pk_parse_key(&pk, key_der, key_len, NULL, 0,
					  mbedtls_ctr_drbg_random, &drbg);
	if (rc) {
		mbedtls_pk_free(&pk);
		mbedtls_ctr_drbg_free(&drbg);
		mbedtls_entropy_free(&entropy);
		return fail("failed to parse device key", rc);
	}

	len = mbedtls_pk_write_pubkey_der(&pk, buf, sizeof(buf));
	*spki_len = len > 0 ? (size_t)len : 0;
	*spki = *spki_len ? malloc(*spki_len) : NULL;
	if (*spki)
		memcpy(*spki, buf + sizeof(buf) - *spki_len, *spki_len);

	mbedtls_pk_free(&pk);
	mbedtls_ctr_drbg_free(&drbg);
	mbedtls_entropy_free(&entropy);
	return *spki ? 0 : fail("failed to export public key", len < 0 ? len : 0);
}

static int make_cert(tls_conn *conn, unsigned char *out, size_t out_len, int *cert_len)
{
	mbedtls_x509write_cert crt;
	unsigned char serial[] = { 1 };
	char not_before[16], not_after[16];
	int rc;

	mbedtls_x509write_crt_init(&crt);
	x509_time(not_before, sizeof(not_before), -3600);
	x509_time(not_after, sizeof(not_after), 365 * 24 * 3600);

	mbedtls_x509write_crt_set_version(&crt, MBEDTLS_X509_CRT_VERSION_3);
	mbedtls_x509write_crt_set_md_alg(&crt, MBEDTLS_MD_SHA256);
	mbedtls_x509write_crt_set_subject_key(&crt, &conn->key);
	mbedtls_x509write_crt_set_issuer_key(&crt, &conn->key);
	rc = mbedtls_x509write_crt_set_subject_name(&crt, "CN=warpq");
	if (!rc)
		rc = mbedtls_x509write_crt_set_issuer_name(&crt, "CN=warpq");
	if (!rc)
		rc = mbedtls_x509write_crt_set_serial_raw(&crt, serial, sizeof(serial));
	if (!rc)
		rc = mbedtls_x509write_crt_set_validity(&crt, not_before, not_after);
	if (!rc) {
		rc = mbedtls_x509write_crt_der(&crt, out, out_len,
					       mbedtls_ctr_drbg_random, &conn->drbg);
		if (rc > 0) {
			*cert_len = rc;
			rc = 0;
		}
	}

	mbedtls_x509write_crt_free(&crt);
	return rc ? fail("failed to build device certificate", rc) : 0;
}

static int tcp_connect(const char *host, int port, unsigned mark)
{
	struct addrinfo hints, *list, *entry;
	char service[8];
	int fd = -1;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	snprintf(service, sizeof(service), "%d", port);
	if (getaddrinfo(host, service, &hints, &list))
		return fail("failed to resolve endpoint", 0);

	for (entry = list; entry; entry = entry->ai_next) {
		fd = socket(entry->ai_family, entry->ai_socktype | SOCK_CLOEXEC, 0);
		if (fd < 0)
			continue;
		if (mark)
			route_mark_socket(fd, mark);
		{
			int on = 1;
			setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));
		}
		if (!connect(fd, entry->ai_addr, entry->ai_addrlen))
			break;
		close(fd);
		fd = -1;
	}
	freeaddrinfo(list);
	if (fd < 0)
		return fail("failed to connect", 0);
	return fd;
}

static int load_ca(tls_conn *conn)
{
	int i;

	for (i = 0; CA_PATHS[i]; i++)
		if (mbedtls_x509_crt_parse_file(&conn->ca, CA_PATHS[i]) >= 0)
			return 0;
	return fail("no system CA bundle found", 0);
}

static int check_pin(tls_conn *conn, const uint8_t *pin, size_t pin_len)
{
	const mbedtls_x509_crt *peer = mbedtls_ssl_get_peer_cert(&conn->ssl);
	unsigned char buf[512];
	int len;

	if (!peer)
		return fail("endpoint sent no certificate", 0);
	len = mbedtls_pk_write_pubkey_der((mbedtls_pk_context *)&peer->pk, buf, sizeof(buf));
	if (len < 0)
		return fail("failed to read endpoint public key", len);
	if ((size_t)len != pin_len || memcmp(buf + sizeof(buf) - len, pin, pin_len))
		return fail("endpoint public key does not match the pinned key", 0);
	return 0;
}

int tls_client(tls_conn *conn, const char *host, int port, const char *sni,
	       const char *alpn, const uint8_t *key_der, size_t key_len,
	       const uint8_t *pin_spki, size_t pin_len, unsigned mark)
{
	static const uint16_t groups[] = { MBEDTLS_SSL_IANA_TLS_GROUP_SECP256R1, 0 };
	static const int chacha_only[] = {
		MBEDTLS_TLS1_3_CHACHA20_POLY1305_SHA256,
		0
	};
	static const int aes_only[] = {
		MBEDTLS_TLS1_3_AES_128_GCM_SHA256,
		MBEDTLS_TLS1_3_AES_256_GCM_SHA384,
		0
	};
	unsigned char cert_der[1024];
	int cert_len = 0;
	int rc;

	memset(conn, 0, sizeof(*conn));
	conn->fd = -1;
	mbedtls_ssl_init(&conn->ssl);
	mbedtls_ssl_config_init(&conn->conf);
	mbedtls_x509_crt_init(&conn->ca);
	mbedtls_x509_crt_init(&conn->cert);
	mbedtls_pk_init(&conn->key);

	if (rng_init(conn))
		return -1;

	rc = mbedtls_ssl_config_defaults(&conn->conf, MBEDTLS_SSL_IS_CLIENT,
					 MBEDTLS_SSL_TRANSPORT_STREAM,
					 MBEDTLS_SSL_PRESET_DEFAULT);
	if (rc)
		return fail("failed to set up TLS", rc);
	mbedtls_ssl_conf_rng(&conn->conf, mbedtls_ctr_drbg_random, &conn->drbg);
	mbedtls_ssl_conf_groups(&conn->conf, groups);
	if (pin_spki && cipher_preference != TLS_CIPHER_AUTO)
		mbedtls_ssl_conf_ciphersuites(&conn->conf,
			cipher_preference == TLS_CIPHER_CHACHA ? chacha_only : aes_only);

	conn->alpn_list[0] = alpn;
	conn->alpn_list[1] = NULL;
	rc = mbedtls_ssl_conf_alpn_protocols(&conn->conf, conn->alpn_list);
	if (rc)
		return fail("failed to set ALPN", rc);

	if (pin_spki) {
		mbedtls_ssl_conf_authmode(&conn->conf, MBEDTLS_SSL_VERIFY_NONE);
		mbedtls_ssl_conf_min_tls_version(&conn->conf, MBEDTLS_SSL_VERSION_TLS1_3);
	} else {
		if (load_ca(conn))
			return -1;
		mbedtls_ssl_conf_authmode(&conn->conf, MBEDTLS_SSL_VERIFY_REQUIRED);
		mbedtls_ssl_conf_ca_chain(&conn->conf, &conn->ca, NULL);
	}

	if (key_der) {
		rc = mbedtls_pk_parse_key(&conn->key, key_der, key_len, NULL, 0,
					  mbedtls_ctr_drbg_random, &conn->drbg);
		if (rc)
			return fail("failed to parse device key", rc);
		if (make_cert(conn, cert_der, sizeof(cert_der), &cert_len))
			return -1;
		rc = mbedtls_x509_crt_parse_der(&conn->cert,
						cert_der + sizeof(cert_der) - cert_len,
						(size_t)cert_len);
		if (!rc)
			rc = mbedtls_ssl_conf_own_cert(&conn->conf, &conn->cert, &conn->key);
		if (rc)
			return fail("failed to install device certificate", rc);
		conn->have_cert = 1;
	}

	rc = mbedtls_ssl_setup(&conn->ssl, &conn->conf);
	if (rc)
		return fail("failed to set up TLS session", rc);
	rc = mbedtls_ssl_set_hostname(&conn->ssl, sni);
	if (rc)
		return fail("failed to set SNI", rc);

	conn->fd = tcp_connect(host, port, mark);
	if (conn->fd < 0)
		return -1;
	mbedtls_ssl_set_bio(&conn->ssl, &conn->fd, mbedtls_net_send, mbedtls_net_recv, NULL);

	while ((rc = mbedtls_ssl_handshake(&conn->ssl)) != 0) {
		if (rc != MBEDTLS_ERR_SSL_WANT_READ && rc != MBEDTLS_ERR_SSL_WANT_WRITE)
			return fail("TLS handshake failed", rc);
	}

	if (pin_spki && check_pin(conn, pin_spki, pin_len))
		return -1;
	return 0;
}

int tls_set_nonblocking(tls_conn *conn)
{
	mbedtls_net_context net = { conn->fd };

	return mbedtls_net_set_nonblock(&net) ? fail("failed to set non-blocking", 0) : 0;
}

int tls_read(tls_conn *conn, void *buf, size_t len)
{
	int rc = mbedtls_ssl_read(&conn->ssl, buf, len);

	if (rc == MBEDTLS_ERR_SSL_WANT_READ || rc == MBEDTLS_ERR_SSL_WANT_WRITE)
		return TLS_WANT_IO;
	if (rc == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
		return 0;
	if (rc < 0)
		return fail("TLS read failed", rc);
	return rc;
}

int tls_write(tls_conn *conn, const void *buf, size_t len)
{
	int rc = mbedtls_ssl_write(&conn->ssl, buf, len);

	if (rc == MBEDTLS_ERR_SSL_WANT_READ || rc == MBEDTLS_ERR_SSL_WANT_WRITE)
		return TLS_WANT_IO;
	if (rc < 0)
		return fail("TLS write failed", rc);
	return rc;
}

void tls_close(tls_conn *conn)
{
	if (conn->fd >= 0) {
		mbedtls_ssl_close_notify(&conn->ssl);
		close(conn->fd);
		conn->fd = -1;
	}
	mbedtls_ssl_free(&conn->ssl);
	mbedtls_ssl_config_free(&conn->conf);
	mbedtls_x509_crt_free(&conn->ca);
	mbedtls_x509_crt_free(&conn->cert);
	mbedtls_pk_free(&conn->key);
	mbedtls_ctr_drbg_free(&conn->drbg);
	mbedtls_entropy_free(&conn->entropy);
}
