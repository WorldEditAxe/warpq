#include "tlsx.h"

#include <errno.h>
#include <linux/tls.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <mbedtls/error.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/platform_util.h>
#include <mbedtls/x509_csr.h>
#include <psa/crypto.h>

#include "aead.h"
#include "route.h"
#include "util.h"

#ifndef TCP_ULP
#define TCP_ULP 31
#endif
#ifndef SOL_TLS
#define SOL_TLS 282
#endif

#define RECORD_ALERT 21
#define RECORD_HANDSHAKE 22
#define RECORD_APPLICATION_DATA 23

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

	aead_init();
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

/* Keep the TLS 1.3 application traffic secrets so tls_offload() can hand the
 * record layer over once the handshake is done. */
static void export_keys(void *arg, mbedtls_ssl_key_export_type type,
			const unsigned char *secret, size_t secret_len,
			const unsigned char client_random[32],
			const unsigned char server_random[32],
			mbedtls_tls_prf_types prf)
{
	tls_conn *conn = arg;

	(void)client_random;
	(void)server_random;
	(void)prf;
	if (secret_len > sizeof(conn->secret_tx))
		return;
	if (type == MBEDTLS_SSL_KEY_EXPORT_TLS1_3_CLIENT_APPLICATION_TRAFFIC_SECRET)
		memcpy(conn->secret_tx, secret, secret_len);
	else if (type == MBEDTLS_SSL_KEY_EXPORT_TLS1_3_SERVER_APPLICATION_TRAFFIC_SECRET)
		memcpy(conn->secret_rx, secret, secret_len);
	else
		return;
	conn->secret_len = secret_len;
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
	mbedtls_ssl_set_export_keys_cb(&conn->ssl, export_keys, conn);
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

/* HKDF-Expand-Label(secret, label, "", out_len) from RFC 8446 7.1. */
static int expand_label(const mbedtls_md_info_t *md, const unsigned char *secret,
			size_t secret_len, const char *label,
			unsigned char *out, size_t out_len)
{
	unsigned char info[2 + 1 + 6 + 8 + 1];
	size_t label_len = strlen(label), n = 0;

	info[n++] = (unsigned char)(out_len >> 8);
	info[n++] = (unsigned char)out_len;
	info[n++] = (unsigned char)(6 + label_len);
	memcpy(info + n, "tls13 ", 6);
	n += 6;
	memcpy(info + n, label, label_len);
	n += label_len;
	info[n++] = 0;
	return mbedtls_hkdf_expand(md, secret, secret_len, info, n, out, out_len);
}

/* Fill the kernel's crypto_info for one direction. Returns its size, or 0 if
 * the suite is not one kTLS takes. */
static size_t ktls_info(int suite, const unsigned char *secret, size_t secret_len,
			const unsigned char seq[8], void *out)
{
	const mbedtls_md_info_t *md;
	unsigned char key[32], iv[12];
	size_t key_len, size;

	switch (suite) {
	case MBEDTLS_TLS1_3_AES_128_GCM_SHA256:
		md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
		key_len = 16;
		break;
	case MBEDTLS_TLS1_3_AES_256_GCM_SHA384:
		md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA384);
		key_len = 32;
		break;
#ifdef TLS_CIPHER_CHACHA20_POLY1305
	case MBEDTLS_TLS1_3_CHACHA20_POLY1305_SHA256:
		md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
		key_len = 32;
		break;
#endif
	default:
		return 0;
	}
	if (!md || mbedtls_md_get_size(md) != secret_len ||
	    expand_label(md, secret, secret_len, "key", key, key_len) ||
	    expand_label(md, secret, secret_len, "iv", iv, sizeof(iv)))
		return 0;

	/* TLS 1.3 has no explicit nonce: the kernel splits the 12-byte IV
	 * into a 4-byte salt and an 8-byte iv for GCM, and takes it whole for
	 * ChaCha20-Poly1305. */
	if (suite == MBEDTLS_TLS1_3_AES_128_GCM_SHA256) {
		struct tls12_crypto_info_aes_gcm_128 *ci = out;

		memset(ci, 0, sizeof(*ci));
		ci->info.version = TLS_1_3_VERSION;
		ci->info.cipher_type = TLS_CIPHER_AES_GCM_128;
		memcpy(ci->salt, iv, 4);
		memcpy(ci->iv, iv + 4, 8);
		memcpy(ci->key, key, 16);
		memcpy(ci->rec_seq, seq, 8);
		size = sizeof(*ci);
	} else if (suite == MBEDTLS_TLS1_3_AES_256_GCM_SHA384) {
		struct tls12_crypto_info_aes_gcm_256 *ci = out;

		memset(ci, 0, sizeof(*ci));
		ci->info.version = TLS_1_3_VERSION;
		ci->info.cipher_type = TLS_CIPHER_AES_GCM_256;
		memcpy(ci->salt, iv, 4);
		memcpy(ci->iv, iv + 4, 8);
		memcpy(ci->key, key, 32);
		memcpy(ci->rec_seq, seq, 8);
		size = sizeof(*ci);
	} else {
#ifdef TLS_CIPHER_CHACHA20_POLY1305
		struct tls12_crypto_info_chacha20_poly1305 *ci = out;

		memset(ci, 0, sizeof(*ci));
		ci->info.version = TLS_1_3_VERSION;
		ci->info.cipher_type = TLS_CIPHER_CHACHA20_POLY1305;
		memcpy(ci->iv, iv, 12);
		memcpy(ci->key, key, 32);
		memcpy(ci->rec_seq, seq, 8);
		size = sizeof(*ci);
#else
		size = 0;
#endif
	}
	mbedtls_platform_zeroize(key, sizeof(key));
	mbedtls_platform_zeroize(iv, sizeof(iv));
	return size;
}

/* warpq's own TLS 1.3 record layer, for ChaCha20-Poly1305 when the kernel
 * will not take it.
 *
 * Next to mbedTLS it does the cipher with aead.c (SIMD ChaCha20, 64-bit
 * Poly1305: two to three times the speed), decrypts straight into the
 * caller's buffer, and moves up to 64 KiB of records per recv() or send()
 * where mbedTLS makes two reads per record and one write per record. */
#define OWN_RECORD 16384                         /* most plaintext per record */
#define OWN_OVERHEAD (5 + 1 + AEAD_TAG_LEN)      /* header, content type, tag */
#define OWN_MAX_CIPHERTEXT (OWN_RECORD + 256)    /* RFC 8446 5.2 */
#define OWN_IN (64 * 1024 + 5 + OWN_MAX_CIPHERTEXT)
#define OWN_OUT (4 * (OWN_RECORD + OWN_OVERHEAD))

struct own_dir {
	unsigned char key[AEAD_KEY_LEN];
	unsigned char iv[AEAD_NONCE_LEN];
	uint64_t seq;
};

struct tls_records {
	struct own_dir rx, tx;
	int rx_on, tx_on;
	int eof;                /* close_notify seen, data before it returned */
	size_t in_len;          /* received, not yet decrypted */
	size_t out_off, out_len;/* sealed records, and how far they are sent */
	size_t out_taken;       /* plaintext those records hold */
	unsigned char in[OWN_IN];
	unsigned char out[OWN_OUT];
};

static int own_dir_init(struct own_dir *d, const unsigned char *secret,
			size_t secret_len, const unsigned char seq[8])
{
	const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
	int i;

	if (!md || mbedtls_md_get_size(md) != secret_len ||
	    expand_label(md, secret, secret_len, "key", d->key, sizeof(d->key)) ||
	    expand_label(md, secret, secret_len, "iv", d->iv, sizeof(d->iv)))
		return -1;
	d->seq = 0;
	for (i = 0; i < 8; i++)
		d->seq = (d->seq << 8) | seq[i];
	return 0;
}

/* RFC 8446 5.3: the IV with the record number XORed into its tail */
static void own_nonce(struct own_dir *d, unsigned char nonce[AEAD_NONCE_LEN])
{
	int i;

	memcpy(nonce, d->iv, AEAD_NONCE_LEN);
	for (i = 0; i < 8; i++)
		nonce[4 + i] ^= (unsigned char)(d->seq >> (56 - 8 * i));
	d->seq++;
}

static void own_setup(tls_conn *conn, int rx, int tx,
		      const unsigned char rx_seq[8], const unsigned char tx_seq[8])
{
	struct tls_records *own = calloc(1, sizeof(*own));

	if (!own)
		return;
	if ((rx && own_dir_init(&own->rx, conn->secret_rx, conn->secret_len, rx_seq)) ||
	    (tx && own_dir_init(&own->tx, conn->secret_tx, conn->secret_len, tx_seq))) {
		mbedtls_platform_zeroize(own, sizeof(*own));
		free(own);
		return;
	}
	own->rx_on = rx;
	own->tx_on = tx;
	conn->own = own;
}

/* Hand the record layer over once the handshake is done.
 *
 * mbedTLS's ChaCha20-Poly1305 and AES-GCM are portable C -- one 16-byte block
 * per call for GCM -- and on the tunnel's hot path they are most of what the
 * TLS thread does. The kernel's TLS layer (kTLS) carries hand-tuned versions
 * for every CPU we build for (NEON on ARM, assembly on MIPS, AVX on x86) and
 * decrypts straight into our buffer, with whole runs of records per
 * recvmsg(). Without it (no kmod-tls on OpenWrt, say), a ChaCha20-Poly1305
 * connection moves to warpq's own record layer above instead. mbedTLS keeps
 * the handshake and the certificate pin either way; only the symmetric
 * record layer moves.
 *
 * Best effort: whatever is not handed over stays with mbedTLS. Each
 * direction goes on its own, receive first, so a kernel that takes only one
 * still works. Returns 1 if anything moved. */
int tls_offload(tls_conn *conn, int engine)
{
	union {
		struct tls12_crypto_info_aes_gcm_128 gcm128;
		struct tls12_crypto_info_aes_gcm_256 gcm256;
#ifdef TLS_CIPHER_CHACHA20_POLY1305
		struct tls12_crypto_info_chacha20_poly1305 chacha;
#endif
	} info;
	int suite = mbedtls_ssl_get_ciphersuite_id_from_ssl(&conn->ssl);
	/* The record sequence numbers carry on from wherever mbedTLS left them
	 * (for receive, past any records it has already taken). */
	const unsigned char *rx_seq = conn->ssl.MBEDTLS_PRIVATE(in_ctr);
	const unsigned char *tx_seq = conn->ssl.MBEDTLS_PRIVATE(cur_out_ctr);
	size_t size;

	if (engine == TLS_ENGINE_MBEDTLS || !conn->secret_len ||
	    mbedtls_ssl_get_version_number(&conn->ssl) != MBEDTLS_SSL_VERSION_TLS1_3 ||
	    /* mbedTLS must not be holding bytes it has already pulled off the
	     * socket: those would never reach the new record layer. It reads
	     * exactly one record at a time, so right after the handshake it
	     * holds none. */
	    mbedtls_ssl_check_pending(&conn->ssl) ||
	    mbedtls_ssl_get_bytes_avail(&conn->ssl))
		goto done;

	if (engine == TLS_ENGINE_AUTO &&
	    !setsockopt(conn->fd, SOL_TCP, TCP_ULP, "tls", sizeof("tls"))) {
		size = ktls_info(suite, conn->secret_rx, conn->secret_len, rx_seq, &info);
		if (size && !setsockopt(conn->fd, SOL_TLS, TLS_RX, &info, (socklen_t)size)) {
			conn->ktls_rx = 1;
			size = ktls_info(suite, conn->secret_tx, conn->secret_len,
					 tx_seq, &info);
			if (size && !setsockopt(conn->fd, SOL_TLS, TLS_TX, &info,
						(socklen_t)size))
				conn->ktls_tx = 1;
		}
		mbedtls_platform_zeroize(&info, sizeof(info));
	}
	if (suite == MBEDTLS_TLS1_3_CHACHA20_POLY1305_SHA256 &&
	    (!conn->ktls_rx || !conn->ktls_tx))
		own_setup(conn, !conn->ktls_rx, !conn->ktls_tx, rx_seq, tx_seq);
done:
	mbedtls_platform_zeroize(conn->secret_tx, sizeof(conn->secret_tx));
	mbedtls_platform_zeroize(conn->secret_rx, sizeof(conn->secret_rx));
	conn->secret_len = 0;
	return conn->ktls_rx || conn->own;
}

/* "kernel TLS", "warpq ChaCha20/AVX2", "mbedTLS", or one per direction */
const char *tls_engine(const tls_conn *conn)
{
	static __thread char name[96];
	char own[32];
	const char *rx, *tx;

	snprintf(own, sizeof(own), "warpq ChaCha20/%s", aead_impl());
	rx = conn->ktls_rx ? "kernel TLS" : conn->own && conn->own->rx_on ? own : "mbedTLS";
	tx = conn->ktls_tx ? "kernel TLS" : conn->own && conn->own->tx_on ? own : "mbedTLS";
	if (!strcmp(rx, tx))
		snprintf(name, sizeof(name), "%s", rx);
	else
		snprintf(name, sizeof(name), "%s receive, %s send", rx, tx);
	return name;
}

/* Does a handshake record hold a KeyUpdate? NewSessionTicket and the rest
 * can be dropped, but a KeyUpdate changes the receive key under the kernel,
 * which cannot follow it on older kernels. */
static int has_key_update(const unsigned char *p, size_t len)
{
	while (len >= 4) {
		size_t body = ((size_t)p[1] << 16) | ((size_t)p[2] << 8) | p[3];

		if (p[0] == 24)
			return 1;
		if (body > len - 4)
			break;
		p += 4 + body;
		len -= 4 + body;
	}
	return 0;
}

static int ktls_read(tls_conn *conn, void *buf, size_t len)
{
	for (;;) {
		union {
			struct cmsghdr align;
			char buf[CMSG_SPACE(sizeof(unsigned char))];
		} control;
		struct iovec iov;
		struct msghdr msg;
		struct cmsghdr *cmsg;
		unsigned char type = RECORD_APPLICATION_DATA;
		ssize_t n;

		iov.iov_base = buf;
		iov.iov_len = len;
		memset(&msg, 0, sizeof(msg));
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_control = control.buf;
		msg.msg_controllen = sizeof(control.buf);
		n = recvmsg(conn->fd, &msg, 0);
		if (n < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
				return TLS_WANT_IO;
			snprintf(error_buf, sizeof(error_buf),
				 "TLS read failed (kernel): %s", strerror(errno));
			return -1;
		}
		if (n == 0)
			return 0;
		cmsg = CMSG_FIRSTHDR(&msg);
		if (cmsg && cmsg->cmsg_level == SOL_TLS &&
		    cmsg->cmsg_type == TLS_GET_RECORD_TYPE)
			type = *(unsigned char *)CMSG_DATA(cmsg);
		if (type == RECORD_APPLICATION_DATA)
			return (int)n;
		if (type == RECORD_ALERT) {
			const unsigned char *alert = buf;

			if (n >= 2 && alert[1] == 0)    /* close_notify */
				return 0;
			snprintf(error_buf, sizeof(error_buf),
				 "TLS alert from peer: %d", n >= 2 ? alert[1] : -1);
			return -1;
		}
		if (type == RECORD_HANDSHAKE && !has_key_update(buf, (size_t)n))
			continue;   /* NewSessionTicket: nothing to do */
		return fail(type == RECORD_HANDSHAKE ?
			    "peer sent a TLS KeyUpdate (reconnecting)" :
			    "unexpected TLS record from peer", 0);
	}
}

static int own_read(tls_conn *conn, unsigned char *buf, size_t len)
{
	struct tls_records *own = conn->own;
	size_t got = 0, pos = 0;
	int rc = 0;

	if (own->eof)
		return 0;
	for (;;) {
		/* every whole record buffered, while the plaintext fits */
		while (!own->eof && own->in_len - pos >= 5) {
			unsigned char *rec = own->in + pos, nonce[AEAD_NONCE_LEN];
			size_t clen = ((size_t)rec[3] << 8) | rec[4], inner, n;
			int type;

			if (rec[0] != RECORD_APPLICATION_DATA ||
			    clen <= AEAD_TAG_LEN || clen > OWN_MAX_CIPHERTEXT) {
				rc = fail("unexpected TLS record from peer", 0);
				goto out;
			}
			if (own->in_len - pos < 5 + clen)
				break;
			inner = clen - AEAD_TAG_LEN;
			if (inner > len - got) {
				if (!got)
					rc = fail("TLS read buffer too small", 0);
				goto out;
			}
			own_nonce(&own->rx, nonce);
			if (aead_open(own->rx.key, nonce, rec, 5, rec + 5, inner,
				      buf + got, rec + 5 + inner)) {
				rc = fail("TLS record failed authentication", 0);
				goto out;
			}
			pos += 5 + clen;

			/* TLSInnerPlaintext: content, type, zero padding */
			for (n = inner; n && !buf[got + n - 1]; n--)
				;
			if (!n) {
				rc = fail("unexpected TLS record from peer", 0);
				goto out;
			}
			type = buf[got + --n];
			if (type == RECORD_APPLICATION_DATA) {
				got += n;
			} else if (type == RECORD_ALERT && n >= 2 && buf[got + 1] == 0) {
				own->eof = 1;   /* close_notify */
			} else if (type == RECORD_ALERT) {
				snprintf(error_buf, sizeof(error_buf),
					 "TLS alert from peer: %d", n >= 2 ? buf[got + 1] : -1);
				rc = -1;
				goto out;
			} else if (type == RECORD_HANDSHAKE &&
				   !has_key_update(buf + got, n)) {
				;       /* NewSessionTicket: nothing to do */
			} else {
				rc = fail(type == RECORD_HANDSHAKE ?
					  "peer sent a TLS KeyUpdate (reconnecting)" :
					  "unexpected TLS record from peer", 0);
				goto out;
			}
		}
		if (got || own->eof)
			break;
		if (pos) {
			memmove(own->in, own->in + pos, own->in_len - pos);
			own->in_len -= pos;
			pos = 0;
		}
		{
			ssize_t n = recv(conn->fd, own->in + own->in_len,
					 OWN_IN - own->in_len, 0);

			if (n < 0) {
				if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
					return TLS_WANT_IO;
				snprintf(error_buf, sizeof(error_buf),
					 "TLS read failed: %s", strerror(errno));
				return -1;
			}
			if (n == 0)
				return 0;
			own->in_len += (size_t)n;
		}
	}
out:
	if (pos) {
		memmove(own->in, own->in + pos, own->in_len - pos);
		own->in_len -= pos;
	}
	return rc ? rc : (int)got;
}

/* Seal one record of type `type` holding len bytes of buf at own->out +
 * own->out_len. The caller has checked it fits. */
static void own_seal(struct tls_records *own, int type,
		     const unsigned char *buf, size_t len)
{
	unsigned char *rec = own->out + own->out_len, nonce[AEAD_NONCE_LEN];
	size_t clen = len + 1 + AEAD_TAG_LEN;

	rec[0] = RECORD_APPLICATION_DATA;
	rec[1] = 3;
	rec[2] = 3;
	rec[3] = (unsigned char)(clen >> 8);
	rec[4] = (unsigned char)clen;
	memcpy(rec + 5, buf, len);
	rec[5 + len] = (unsigned char)type;
	own_nonce(&own->tx, nonce);
	aead_seal(own->tx.key, nonce, rec, 5, rec + 5, len + 1, rec + 5,
		  rec + 5 + len + 1);
	own->out_len += 5 + clen;
}

/* Same contract as mbedtls_ssl_write: after TLS_WANT_IO, call again with the
 * same data; the count comes back once the records holding it are sent. */
static int own_write(tls_conn *conn, const unsigned char *buf, size_t len)
{
	struct tls_records *own = conn->own;

	if (!own->out_len) {
		size_t taken = 0;

		while (taken < len &&
		       OWN_OUT - own->out_len >= OWN_RECORD + OWN_OVERHEAD) {
			size_t n = len - taken < OWN_RECORD ? len - taken : OWN_RECORD;

			own_seal(own, RECORD_APPLICATION_DATA, buf + taken, n);
			taken += n;
		}
		own->out_off = 0;
		own->out_taken = taken;
	}
	while (own->out_off < own->out_len) {
		ssize_t n = send(conn->fd, own->out + own->out_off,
				 own->out_len - own->out_off, MSG_NOSIGNAL);

		if (n < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
				return TLS_WANT_IO;
			snprintf(error_buf, sizeof(error_buf),
				 "TLS write failed: %s", strerror(errno));
			return -1;
		}
		own->out_off += (size_t)n;
	}
	own->out_len = 0;
	return (int)own->out_taken;
}

int tls_read(tls_conn *conn, void *buf, size_t len)
{
	int rc;

	if (conn->ktls_rx)
		return ktls_read(conn, buf, len);
	if (conn->own && conn->own->rx_on)
		return own_read(conn, buf, len);
	rc = mbedtls_ssl_read(&conn->ssl, buf, len);

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
	int rc;

	if (conn->ktls_tx) {
		ssize_t n = send(conn->fd, buf, len, MSG_NOSIGNAL);

		if (n >= 0)
			return (int)n;
		if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
			return TLS_WANT_IO;
		snprintf(error_buf, sizeof(error_buf),
			 "TLS write failed (kernel): %s", strerror(errno));
		return -1;
	}
	if (conn->own && conn->own->tx_on)
		return own_write(conn, buf, len);
	rc = mbedtls_ssl_write(&conn->ssl, buf, len);

	if (rc == MBEDTLS_ERR_SSL_WANT_READ || rc == MBEDTLS_ERR_SSL_WANT_WRITE)
		return TLS_WANT_IO;
	if (rc < 0)
		return fail("TLS write failed", rc);
	return rc;
}

void tls_close(tls_conn *conn)
{
	if (conn->fd >= 0) {
		/* With kTLS sending, mbedTLS's record state is stale: let the
		 * kernel's stream end without a close_notify rather than send one
		 * under the wrong sequence number. Our own layer sends its own,
		 * unless a record is still half sent. */
		if (conn->own && conn->own->tx_on) {
			static const unsigned char close_notify[2] = { 1, 0 };
			struct tls_records *own = conn->own;

			if (!own->out_len) {
				own_seal(own, RECORD_ALERT, close_notify, sizeof(close_notify));
				(void)!send(conn->fd, own->out, own->out_len, MSG_NOSIGNAL);
			}
		} else if (!conn->ktls_tx) {
			mbedtls_ssl_close_notify(&conn->ssl);
		}
		close(conn->fd);
		conn->fd = -1;
	}
	if (conn->own) {
		mbedtls_platform_zeroize(conn->own, sizeof(*conn->own));
		free(conn->own);
		conn->own = NULL;
	}
	mbedtls_ssl_free(&conn->ssl);
	mbedtls_ssl_config_free(&conn->conf);
	mbedtls_x509_crt_free(&conn->ca);
	mbedtls_x509_crt_free(&conn->cert);
	mbedtls_pk_free(&conn->key);
	mbedtls_ctr_drbg_free(&conn->drbg);
	mbedtls_entropy_free(&conn->entropy);
}
