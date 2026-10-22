#include "ech.h"

#include <stdio.h>
#include <string.h>

/* one per thread, like tlsx.c; registration runs on the main thread */
static __thread char error_buf[256];

const char *ech_error(void)
{
	return error_buf;
}

static int fail(const char *fmt, const char *detail)
{
	snprintf(error_buf, sizeof(error_buf), fmt, detail ? detail : "");
	return -1;
}

#ifndef WARPQ_ECH

/* mbedTLS has no ECH, so the default build ships these stubs. The caller
 * (api.c) treats a NULL return as "ECH not available" and, in secure mode,
 * falls back to a connection with no SNI. Build with -DWARPQ_ECH against
 * wolfSSL to get the real thing. */

ech_conn *ech_connect(const char *front, const char *name, int port)
{
	(void)front;
	(void)name;
	(void)port;
	fail("this build has no ECH support%s", NULL);
	return NULL;
}

int ech_write(ech_conn *conn, const void *buf, size_t len)
{
	(void)conn;
	(void)buf;
	(void)len;
	return -1;
}

int ech_read(ech_conn *conn, void *buf, size_t len)
{
	(void)conn;
	(void)buf;
	(void)len;
	return -1;
}

void ech_close(ech_conn *conn)
{
	(void)conn;
}

#else /* WARPQ_ECH */

#include <netdb.h>
#include <stdlib.h>
#include <unistd.h>

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>

#include <arpa/nameser.h>
#include <resolv.h>

#ifndef SOCK_CLOEXEC
#define SOCK_CLOEXEC 0
#endif

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

/* RFC 9460 SVCB/HTTPS wire format. The HPKE public key and the public name
 * that becomes the outer SNI live in the ECHConfigList, which Cloudflare
 * publishes in the HTTPS resource record (type 65) of the ECH-enabled front
 * name under SvcParamKey 5. The record's TargetName is never compressed. */
#define RRTYPE_HTTPS   65
#define SVCPARAM_ECH   5

static const char *CA_PATHS[] = {
	"/etc/ssl/certs/ca-certificates.crt",
	"/etc/ssl/cert.pem",
	"/etc/pki/tls/certs/ca-bundle.crt",
	NULL
};

struct ech_conn {
	WOLFSSL_CTX *ctx;
	WOLFSSL *ssl;
	int fd;
};

/* Read the ECHConfigList of `name` out of its HTTPS DNS record. Returns the
 * number of bytes written to `out`, or -1 if the record or the key is absent.
 * Only SvcParamKey 5 is extracted; the addresses to dial are resolved
 * separately, and both resolve to the same CDN front, so they agree. */
static int fetch_ech_config(const char *name, unsigned char *out, size_t out_cap)
{
	unsigned char answer[4096];
	int answer_len, i;
	const unsigned char *p, *end;
	unsigned qd, an;

	if (res_init())
		return fail("DNS resolver init failed%s", NULL);

	answer_len = res_query(name, ns_c_in, RRTYPE_HTTPS, answer, sizeof(answer));
	if (answer_len < (int)NS_HFIXEDSZ)
		return fail("no HTTPS record for the ECH front%s", NULL);

	qd = (unsigned)((answer[4] << 8) | answer[5]);
	an = (unsigned)((answer[6] << 8) | answer[7]);
	p = answer + NS_HFIXEDSZ;
	end = answer + answer_len;

	/* skip the question section: each entry is a name then QTYPE+QCLASS */
	for (i = 0; i < (int)qd; i++) {
		int n = dn_skipname(p, end);

		if (n < 0 || p + n + 4 > end)
			return fail("malformed DNS response%s", NULL);
		p += n + 4;
	}

	for (i = 0; i < (int)an; i++) {
		int n = dn_skipname(p, end);
		unsigned type, rdlen;
		const unsigned char *rdata;

		if (n < 0 || p + n + 10 > end)
			return fail("malformed DNS answer%s", NULL);
		p += n;
		type = (unsigned)((p[0] << 8) | p[1]);
		rdlen = (unsigned)((p[8] << 8) | p[9]);
		p += 10;
		if (p + rdlen > end)
			return fail("malformed DNS answer%s", NULL);
		rdata = p;
		p += rdlen;

		if (type != RRTYPE_HTTPS)
			continue;

		/* SVCB RDATA: SvcPriority(2) then an uncompressed TargetName then
		 * the SvcParams, each of them key(2) length(2) value(length). */
		{
			const unsigned char *q = rdata, *rend = rdata + rdlen;

			if (q + 2 > rend)
				continue;
			q += 2;                       /* SvcPriority */
			while (q < rend && *q)        /* TargetName labels */
				q += *q + 1;
			if (q >= rend)
				continue;
			q += 1;                       /* root label */

			while (q + 4 <= rend) {
				unsigned key = (unsigned)((q[0] << 8) | q[1]);
				unsigned len = (unsigned)((q[2] << 8) | q[3]);

				q += 4;
				if (q + len > rend)
					break;
				if (key == SVCPARAM_ECH) {
					if (len == 0 || len > out_cap)
						return fail("ECH config does not fit%s", NULL);
					memcpy(out, q, len);
					return (int)len;
				}
				q += len;
			}
		}
	}
	return fail("the HTTPS record carries no ECH config%s", NULL);
}

static int tcp_connect(const char *host, int port)
{
	struct addrinfo hints, *list, *entry;
	char service[8];
	int fd = -1;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	snprintf(service, sizeof(service), "%d", port);
	if (getaddrinfo(host, service, &hints, &list))
		return fail("failed to resolve the ECH front%s", NULL);

	for (entry = list; entry; entry = entry->ai_next) {
		fd = socket(entry->ai_family, entry->ai_socktype | SOCK_CLOEXEC, 0);
		if (fd < 0)
			continue;
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
		return fail("failed to connect to the ECH front%s", NULL);
	return fd;
}

static int load_ca(WOLFSSL_CTX *ctx)
{
	int i;

	for (i = 0; CA_PATHS[i]; i++)
		if (wolfSSL_CTX_load_verify_locations(ctx, CA_PATHS[i], NULL)
		    == WOLFSSL_SUCCESS)
			return 0;
	return fail("no system CA bundle found%s", NULL);
}

/* One handshake attempt with a given ECHConfigList. On success the connection
 * is live in *conn and ECH was accepted. If the server rejected ECH it hands
 * back a fresh config in `retry`/`retry_len` and this returns 1 so the caller
 * can try exactly once more; any other failure returns -1. */
static int attempt(ech_conn *conn, const char *front, const char *name, int port,
		   const unsigned char *config, int config_len,
		   unsigned char *retry, word32 *retry_len)
{
	int rc;

	conn->ctx = NULL;
	conn->ssl = NULL;
	conn->fd = -1;

	conn->ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
	if (!conn->ctx)
		return fail("failed to set up TLS%s", NULL);
	if (load_ca(conn->ctx))
		return -1;
	wolfSSL_CTX_set_verify(conn->ctx, WOLFSSL_VERIFY_PEER, NULL);

	conn->ssl = wolfSSL_new(conn->ctx);
	if (!conn->ssl)
		return fail("failed to set up TLS session%s", NULL);

	/* The real server name travels only in the encrypted inner ClientHello
	 * and is what the certificate is checked against; the public name from
	 * the ECH config is what appears on the wire as the outer SNI. */
	if (wolfSSL_SetEchConfigs(conn->ssl, config, (word32)config_len)
	    != WOLFSSL_SUCCESS)
		return fail("failed to load the ECH config%s", NULL);
	if (wolfSSL_UseSNI(conn->ssl, WOLFSSL_SNI_HOST_NAME, name,
			   (unsigned short)strlen(name)) != WOLFSSL_SUCCESS)
		return fail("failed to set the inner server name%s", NULL);
	if (wolfSSL_check_domain_name(conn->ssl, name) != WOLFSSL_SUCCESS)
		return fail("failed to pin the certificate name%s", NULL);

	conn->fd = tcp_connect(front, port);
	if (conn->fd < 0)
		return -1;
	if (wolfSSL_set_fd(conn->ssl, conn->fd) != WOLFSSL_SUCCESS)
		return fail("failed to attach the socket%s", NULL);

	if (wolfSSL_connect(conn->ssl) == WOLFSSL_SUCCESS) {
		if (wolfSSL_GetEchStatus(conn->ssl) == WOLFSSL_ECH_STATUS_ACCEPTED)
			return 0;
		return fail("the server did not accept ECH%s", NULL);
	}

	rc = wolfSSL_get_error(conn->ssl, 0);
	if (rc == ECH_REQUIRED_E && retry && retry_len) {
		/* ECH was offered but rejected; the server supplied a new config
		 * for one retry (RFC 9460 / the ECH draft's retry flow). */
		word32 cap = *retry_len;

		*retry_len = 0;
		if (wolfSSL_GetEchRetryConfigs(conn->ssl, retry, &cap)
		    == WOLFSSL_SUCCESS && cap > 0) {
			*retry_len = cap;
			return 1;
		}
	}
	{
		char detail[80];

		wolfSSL_ERR_error_string((unsigned long)rc, detail);
		return fail("ECH handshake failed: %s", detail);
	}
}

ech_conn *ech_connect(const char *front, const char *name, int port)
{
	unsigned char config[1024], retry[1024];
	word32 retry_len = sizeof(retry);
	int config_len, rc;
	ech_conn *conn;

	if (!front || !*front)
		front = ECH_DEFAULT_FRONT;

	if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
		fail("failed to initialise wolfSSL%s", NULL);
		return NULL;
	}

	config_len = fetch_ech_config(front, config, sizeof(config));
	if (config_len < 0)
		return NULL;

	conn = calloc(1, sizeof(*conn));
	if (!conn) {
		fail("out of memory%s", NULL);
		return NULL;
	}

	rc = attempt(conn, front, name, port, config, config_len, retry, &retry_len);
	if (rc == 1) {
		/* rejected with a retry config: tear down and try once more */
		ech_close(conn);
		conn = calloc(1, sizeof(*conn));
		if (!conn) {
			fail("out of memory%s", NULL);
			return NULL;
		}
		rc = attempt(conn, front, name, port,
			     retry, (int)retry_len, NULL, NULL);
	}
	if (rc != 0) {
		ech_close(conn);
		return NULL;
	}
	return conn;
}

int ech_write(ech_conn *conn, const void *buf, size_t len)
{
	int rc = wolfSSL_write(conn->ssl, buf, (int)len);

	if (rc <= 0)
		return fail("TLS write failed%s", NULL);
	return rc;
}

int ech_read(ech_conn *conn, void *buf, size_t len)
{
	int rc = wolfSSL_read(conn->ssl, buf, (int)len);

	if (rc > 0)
		return rc;
	if (rc == 0 ||
	    wolfSSL_get_error(conn->ssl, rc) == WOLFSSL_ERROR_ZERO_RETURN)
		return 0;
	return fail("TLS read failed%s", NULL);
}

void ech_close(ech_conn *conn)
{
	if (!conn)
		return;
	if (conn->ssl) {
		wolfSSL_shutdown(conn->ssl);
		wolfSSL_free(conn->ssl);
	}
	if (conn->fd >= 0)
		close(conn->fd);
	if (conn->ctx)
		wolfSSL_CTX_free(conn->ctx);
	free(conn);
}

#endif /* WARPQ_ECH */
