#include "api.h"

#include <stdio.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>

#include "ech.h"
#include "tlsx.h"
#include "util.h"

#define API_HOST "api.cloudflareclient.com"
#define API_VERSION "v0a4471"
#define CLIENT_VERSION "a-6.35-4471"
#define USER_AGENT "WARP for Android"

static char error_buf[512];
static int secure_mode;

void api_secure_mode(int on)
{
	secure_mode = on;
}

const char *api_error(void)
{
	return error_buf;
}

static int fail(const char *fmt, const char *detail)
{
	snprintf(error_buf, sizeof(error_buf), fmt, detail ? detail : "");
	return -1;
}

/* The API is reached over one of three TLS handshakes. By default the SNI is
 * the API host, in the clear. In secure mode the server name is hidden: ECH
 * carries it encrypted, and failing that the handshake sends no SNI at all,
 * which the API's own addresses answer with their default certificate. The
 * three share this wrapper so the HTTP code below need not know which ran. */
struct api_conn {
	int is_ech;
	tls_conn tls;
	ech_conn *ech;
};

static int conn_open(struct api_conn *c)
{
	memset(c, 0, sizeof(*c));

	if (secure_mode) {
		c->ech = ech_connect(ECH_DEFAULT_FRONT, API_HOST, 443);
		if (c->ech) {
			c->is_ech = 1;
			return 0;
		}
		/* secure, but ECH is unavailable: hide the name by sending none */
		if (tls_client(&c->tls, API_HOST, 443, NULL, "http/1.1",
			       NULL, 0, NULL, 0, 0))
			return fail("%s", tls_error());
		return 0;
	}

	if (tls_client(&c->tls, API_HOST, 443, API_HOST, "http/1.1",
		       NULL, 0, NULL, 0, 0))
		return fail("%s", tls_error());
	return 0;
}

static int conn_write(struct api_conn *c, const void *buf, size_t len)
{
	return c->is_ech ? ech_write(c->ech, buf, len)
			 : tls_write(&c->tls, buf, len);
}

static int conn_read(struct api_conn *c, void *buf, size_t len)
{
	return c->is_ech ? ech_read(c->ech, buf, len)
			 : tls_read(&c->tls, buf, len);
}

static const char *conn_error(struct api_conn *c)
{
	return c->is_ech ? ech_error() : tls_error();
}

static void conn_close(struct api_conn *c)
{
	if (c->is_ech)
		ech_close(c->ech);
	else
		tls_close(&c->tls);
}

static int http_request(const char *method, const char *path, const char *bearer,
			const char *body, char **response)
{
	struct api_conn conn;
	char head[1024];
	size_t head_len;
	char *buffer = NULL;
	size_t size = 0, cap = 0;
	const char *separator, *payload;
	int status = -1;

	*response = NULL;
	if (conn_open(&conn))
		return -1;

	head_len = (size_t)snprintf(head, sizeof(head),
		"%s %s HTTP/1.1\r\nHost: " API_HOST "\r\nUser-Agent: " USER_AGENT "\r\n"
		"CF-Client-Version: " CLIENT_VERSION "\r\nAccept: application/json\r\n"
		"Connection: close\r\n", method, path);
	if (bearer)
		head_len += (size_t)snprintf(head + head_len, sizeof(head) - head_len,
					     "Authorization: Bearer %s\r\n", bearer);
	if (body)
		head_len += (size_t)snprintf(head + head_len, sizeof(head) - head_len,
					     "Content-Type: application/json; charset=UTF-8\r\n"
					     "Content-Length: %zu\r\n", strlen(body));
	head_len += (size_t)snprintf(head + head_len, sizeof(head) - head_len, "\r\n");

	if (conn_write(&conn, head, head_len) < 0 ||
	    (body && conn_write(&conn, body, strlen(body)) < 0)) {
		int rc = fail("%s", conn_error(&conn));

		conn_close(&conn);
		return rc;
	}

	for (;;) {
		int n;

		if (size + 4096 > cap) {
			char *grown = realloc(buffer, cap + 16384);

			if (!grown) {
				free(buffer);
				conn_close(&conn);
				return fail("out of memory%s", NULL);
			}
			buffer = grown;
			cap += 16384;
		}
		n = conn_read(&conn, buffer + size, cap - size - 1);
		if (n == TLS_WANT_IO)
			continue;
		if (n <= 0)
			break;
		size += (size_t)n;
	}
	conn_close(&conn);

	if (!buffer)
		return fail("empty response from API%s", NULL);
	buffer[size] = 0;

	if (sscanf(buffer, "HTTP/1.%*d %d", &status) != 1) {
		free(buffer);
		return fail("malformed HTTP response%s", NULL);
	}
	separator = strstr(buffer, "\r\n\r\n");
	if (!separator) {
		free(buffer);
		return fail("malformed HTTP response%s", NULL);
	}
	payload = separator + 4;

	if (strcasestr(buffer, "\r\nTransfer-Encoding: chunked")) {
		char *out = malloc(size + 1);
		size_t o = 0;

		if (!out) {
			free(buffer);
			return fail("out of memory%s", NULL);
		}
		while (*payload) {
			unsigned long chunk = strtoul(payload, NULL, 16);
			const char *data = strstr(payload, "\r\n");

			if (!data || !chunk)
				break;
			data += 2;
			if (data + chunk > buffer + size)
				break;
			memcpy(out + o, data, chunk);
			o += chunk;
			payload = data + chunk + 2;
		}
		out[o] = 0;
		free(buffer);
		*response = out;
	} else {
		*response = strdup(payload);
		free(buffer);
		if (!*response)
			return fail("out of memory%s", NULL);
	}
	return status;
}

static json *api_call(const char *method, const char *path, const char *bearer, const char *body)
{
	char *response = NULL;
	int status = http_request(method, path, bearer, body, &response);
	json *parsed;

	if (status < 0) {
		free(response);
		return NULL;
	}
	if (status < 200 || status >= 300) {
		snprintf(error_buf, sizeof(error_buf), "API returned HTTP %d: %s",
			 status, response ? response : "");
		free(response);
		return NULL;
	}
	if (!response || !*response) {
		free(response);
		return json_parse("{}");
	}
	parsed = json_parse(response);
	if (!parsed)
		snprintf(error_buf, sizeof(error_buf), "API returned invalid JSON: %s", response);
	free(response);
	return parsed;
}

static void strip_port(char *out, size_t out_len, const char *addr)
{
	const char *end;

	if (!addr) {
		out[0] = 0;
		return;
	}
	if (*addr == '[') {
		addr++;
		end = strchr(addr, ']');
	} else {
		end = strrchr(addr, ':');
	}
	if (!end)
		end = addr + strlen(addr);
	snprintf(out, out_len, "%.*s", (int)(end - addr), addr);
}

static int parse_peer_key(const char *value, uint8_t **spki, size_t *spki_len)
{
	const char *begin = strstr(value, "-----BEGIN PUBLIC KEY-----");
	const char *end;

	if (begin) {
		begin += strlen("-----BEGIN PUBLIC KEY-----");
		end = strstr(begin, "-----END PUBLIC KEY-----");
	} else {
		begin = value;
		end = value + strlen(value);
	}
	if (!end)
		return fail("malformed endpoint public key%s", NULL);
	*spki = b64_decode(begin, (size_t)(end - begin), spki_len);
	return *spki ? 0 : fail("malformed endpoint public key%s", NULL);
}

int api_register(warp_config *config, const char *device_name, const char *model, const char *locale)
{
	uint8_t random[32];
	char wg_key_raw[32];
	char serial[17];
	char tos[40];
	char body[1024];
	char path[128];
	char name_escaped[128];
	char *wg_key;
	json *account = NULL, *enrolled = NULL;
	const char *id, *token, *peer_key;
	FILE *urandom;

	memset(config, 0, sizeof(*config));

	urandom = fopen("/dev/urandom", "rb");
	if (!urandom || fread(random, 1, sizeof(random), urandom) != sizeof(random)) {
		if (urandom)
			fclose(urandom);
		return fail("failed to read /dev/urandom%s", NULL);
	}
	memcpy(wg_key_raw, random, 32);
	hex_encode(random, 8, serial);
	fclose(urandom);

	wg_key = b64_encode((const uint8_t *)wg_key_raw, sizeof(wg_key_raw));
	if (!wg_key)
		return fail("out of memory%s", NULL);
	cf_time(tos, sizeof(tos));
	snprintf(body, sizeof(body),
		 "{\"key\":\"%s\",\"install_id\":\"\",\"fcm_token\":\"\",\"tos\":\"%s\","
		 "\"model\":\"%s\",\"serial_number\":\"%s\",\"os_version\":\"\","
		 "\"key_type\":\"curve25519\",\"tunnel_type\":\"wireguard\",\"locale\":\"%s\"}",
		 wg_key, tos, model, serial, locale);
	free(wg_key);

	snprintf(path, sizeof(path), "/%s/reg", API_VERSION);
	account = api_call("POST", path, NULL, body);
	if (!account)
		return -1;

	id = json_str(account, "id");
	token = json_str(account, "token");
	if (!id || !token) {
		json_free(account);
		return fail("registration response was missing id or token%s", NULL);
	}
	snprintf(config->id, sizeof(config->id), "%s", id);
	snprintf(config->token, sizeof(config->token), "%s", token);
	json_free(account);

	if (identity_generate(&config->key_der, &config->key_len,
			      &config->spki, &config->spki_len))
		return fail("%s", tls_error());
	{
		char *spki_b64 = b64_encode(config->spki, config->spki_len);

		if (!spki_b64)
			return fail("out of memory%s", NULL);
		if (device_name && *device_name)
			snprintf(body, sizeof(body),
				 "{\"key\":\"%s\",\"key_type\":\"secp256r1\","
				 "\"tunnel_type\":\"masque\",\"name\":\"%s\"}",
				 spki_b64, json_escape(device_name, name_escaped, sizeof(name_escaped)));
		else
			snprintf(body, sizeof(body),
				 "{\"key\":\"%s\",\"key_type\":\"secp256r1\",\"tunnel_type\":\"masque\"}",
				 spki_b64);
		free(spki_b64);
	}
	free(config->spki);
	config->spki = NULL;
	config->spki_len = 0;

	snprintf(path, sizeof(path), "/%s/reg/%s", API_VERSION, config->id);
	enrolled = api_call("PATCH", path, config->token, body);
	if (!enrolled)
		return -1;

	peer_key = json_str(enrolled, "config/peers/0/public_key");
	if (!peer_key) {
		json_free(enrolled);
		return fail("enrollment response had no peer key%s", NULL);
	}
	if (parse_peer_key(peer_key, &config->spki, &config->spki_len)) {
		json_free(enrolled);
		return -1;
	}
	strip_port(config->endpoint_v4, sizeof(config->endpoint_v4),
		   json_str(enrolled, "config/peers/0/endpoint/v4"));
	strip_port(config->endpoint_v6, sizeof(config->endpoint_v6),
		   json_str(enrolled, "config/peers/0/endpoint/v6"));
	snprintf(config->ipv4, sizeof(config->ipv4), "%s",
		 json_str(enrolled, "config/interface/addresses/v4") ?: "");
	snprintf(config->ipv6, sizeof(config->ipv6), "%s",
		 json_str(enrolled, "config/interface/addresses/v6") ?: "");
	json_free(enrolled);
	return 0;
}

static void read_account(json *node, warp_account *account)
{
	memset(account, 0, sizeof(*account));
	snprintf(account->account_type, sizeof(account->account_type), "%s",
		 json_str(node, "account_type") ?: "unknown");
	snprintf(account->role, sizeof(account->role), "%s", json_str(node, "role") ?: "");
	snprintf(account->license, sizeof(account->license), "%s", json_str(node, "license") ?: "");
	account->warp_plus = json_bool(node, "warp_plus");
	account->premium_data = json_num(node, "premium_data");
	account->quota = json_num(node, "quota");
}

int api_account(const warp_config *config, warp_account *account)
{
	char path[160];
	json *node;

	snprintf(path, sizeof(path), "/%s/reg/%s/account", API_VERSION, config->id);
	node = api_call("GET", path, config->token, NULL);
	if (!node)
		return -1;
	read_account(node, account);
	json_free(node);
	return 0;
}

int api_set_license(const warp_config *config, const char *license, warp_account *account)
{
	char path[160], body[192], escaped[96];
	json *node;

	snprintf(path, sizeof(path), "/%s/reg/%s/account", API_VERSION, config->id);
	snprintf(body, sizeof(body), "{\"license\":\"%s\"}",
		 json_escape(license, escaped, sizeof(escaped)));
	node = api_call("PUT", path, config->token, body);
	if (!node)
		return -1;
	read_account(node, account);
	json_free(node);
	if (!account->account_type[0] || !strcmp(account->account_type, "unknown"))
		return api_account(config, account);
	return 0;
}

int api_clear_license(const warp_config *config)
{
	char path[160];
	json *node;

	snprintf(path, sizeof(path), "/%s/reg/%s/account", API_VERSION, config->id);
	node = api_call("DELETE", path, config->token, NULL);
	if (!node)
		return -1;
	json_free(node);
	return 0;
}

int config_save(const warp_config *config, const char *path)
{
	char *key_b64 = b64_encode(config->key_der, config->key_len);
	char *spki_b64 = b64_encode(config->spki, config->spki_len);
	FILE *file;

	if (!key_b64 || !spki_b64) {
		free(key_b64);
		free(spki_b64);
		return fail("out of memory%s", NULL);
	}
	file = fopen(path, "w");
	if (!file) {
		free(key_b64);
		free(spki_b64);
		return fail("failed to write %s", path);
	}
	fchmod(fileno(file), 0600);
	fprintf(file,
		"{\n  \"private_key\": \"%s\",\n  \"endpoint_v4\": \"%s\",\n"
		"  \"endpoint_v6\": \"%s\",\n  \"endpoint_pub_key\": \"%s\",\n"
		"  \"id\": \"%s\",\n  \"access_token\": \"%s\",\n"
		"  \"ipv4\": \"%s\",\n  \"ipv6\": \"%s\"\n}\n",
		key_b64, config->endpoint_v4, config->endpoint_v6, spki_b64,
		config->id, config->token, config->ipv4, config->ipv6);
	fclose(file);
	free(key_b64);
	free(spki_b64);
	return 0;
}

int config_load(warp_config *config, const char *path)
{
	char *text;
	long size;
	FILE *file = fopen(path, "r");
	json *node;
	const char *value;

	memset(config, 0, sizeof(*config));
	if (!file)
		return fail("failed to read %s", path);
	fseek(file, 0, SEEK_END);
	size = ftell(file);
	fseek(file, 0, SEEK_SET);
	text = malloc((size_t)size + 1);
	if (!text || fread(text, 1, (size_t)size, file) != (size_t)size) {
		free(text);
		fclose(file);
		return fail("failed to read %s", path);
	}
	text[size] = 0;
	fclose(file);

	node = json_parse(text);
	free(text);
	if (!node)
		return fail("%s is not valid JSON", path);

#define COPY(field, name)                                                      \
	do {                                                                   \
		value = json_str(node, name);                                  \
		if (!value) {                                                  \
			json_free(node);                                       \
			return fail("config is missing " name "%s", NULL);     \
		}                                                              \
		snprintf(config->field, sizeof(config->field), "%s", value);   \
	} while (0)

	COPY(endpoint_v4, "endpoint_v4");
	COPY(id, "id");
	COPY(token, "access_token");
	COPY(ipv4, "ipv4");
#undef COPY
	snprintf(config->endpoint_v6, sizeof(config->endpoint_v6), "%s",
		 json_str(node, "endpoint_v6") ?: "");
	snprintf(config->ipv6, sizeof(config->ipv6), "%s", json_str(node, "ipv6") ?: "");

	value = json_str(node, "private_key");
	if (value)
		config->key_der = b64_decode(value, strlen(value), &config->key_len);
	value = json_str(node, "endpoint_pub_key");
	if (value)
		config->spki = b64_decode(value, strlen(value), &config->spki_len);
	json_free(node);

	if (!config->key_der || !config->spki)
		return fail("config is missing the device or endpoint key%s", NULL);
	return 0;
}

void config_free(warp_config *config)
{
	free(config->key_der);
	free(config->spki);
	config->key_der = NULL;
	config->spki = NULL;
}
