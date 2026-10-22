#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static const char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

char *b64_encode(const uint8_t *data, size_t len)
{
	size_t out_len = ((len + 2) / 3) * 4;
	char *out = malloc(out_len + 1);
	size_t i, o = 0;

	if (!out)
		return NULL;
	for (i = 0; i < len; i += 3) {
		uint32_t n = (uint32_t)data[i] << 16;
		if (i + 1 < len)
			n |= (uint32_t)data[i + 1] << 8;
		if (i + 2 < len)
			n |= data[i + 2];
		out[o++] = B64[(n >> 18) & 63];
		out[o++] = B64[(n >> 12) & 63];
		out[o++] = (i + 1 < len) ? B64[(n >> 6) & 63] : '=';
		out[o++] = (i + 2 < len) ? B64[n & 63] : '=';
	}
	out[o] = 0;
	return out;
}

static int b64_value(char c)
{
	if (c >= 'A' && c <= 'Z')
		return c - 'A';
	if (c >= 'a' && c <= 'z')
		return c - 'a' + 26;
	if (c >= '0' && c <= '9')
		return c - '0' + 52;
	if (c == '+')
		return 62;
	if (c == '/')
		return 63;
	return -1;
}

uint8_t *b64_decode(const char *text, size_t len, size_t *out_len)
{
	uint8_t *out = malloc(len / 4 * 3 + 4);
	uint32_t acc = 0;
	int bits = 0;
	size_t i, o = 0;

	if (!out)
		return NULL;
	for (i = 0; i < len; i++) {
		int v = b64_value(text[i]);
		if (v < 0)
			continue;
		acc = (acc << 6) | (uint32_t)v;
		bits += 6;
		if (bits >= 8) {
			bits -= 8;
			out[o++] = (uint8_t)(acc >> bits);
		}
	}
	*out_len = o;
	return out;
}

void hex_encode(const uint8_t *data, size_t len, char *out)
{
	static const char digits[] = "0123456789abcdef";
	size_t i;

	for (i = 0; i < len; i++) {
		out[i * 2] = digits[data[i] >> 4];
		out[i * 2 + 1] = digits[data[i] & 15];
	}
	out[len * 2] = 0;
}

void cf_time(char *out, size_t out_len)
{
	time_t now = time(NULL);
	struct tm tm;

	gmtime_r(&now, &tm);
	snprintf(out, out_len, "%04d-%02d-%02dT%02d:%02d:%02d.000+00:00",
		 tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
		 tm.tm_hour, tm.tm_min, tm.tm_sec);
}

void x509_time(char *out, size_t out_len, long offset_secs)
{
	time_t when = time(NULL) + offset_secs;
	struct tm tm;

	gmtime_r(&when, &tm);
	snprintf(out, out_len, "%04d%02d%02d%02d%02d%02d",
		 tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
		 tm.tm_hour, tm.tm_min, tm.tm_sec);
}

struct parser {
	const char *p;
};

static json *parse_value(struct parser *ps);

static void skip_ws(struct parser *ps)
{
	while (*ps->p == ' ' || *ps->p == '\t' || *ps->p == '\n' || *ps->p == '\r')
		ps->p++;
}

static char *parse_string(struct parser *ps)
{
	const char *start;
	char *out;
	size_t o = 0;

	if (*ps->p != '"')
		return NULL;
	ps->p++;
	start = ps->p;
	out = malloc(strlen(start) + 1);
	if (!out)
		return NULL;

	while (*ps->p && *ps->p != '"') {
		if (*ps->p == '\\') {
			ps->p++;
			switch (*ps->p) {
			case 'n': out[o++] = '\n'; break;
			case 'r': out[o++] = '\r'; break;
			case 't': out[o++] = '\t'; break;
			case 'b': out[o++] = '\b'; break;
			case 'f': out[o++] = '\f'; break;
			case 'u': {
				unsigned code = 0;
				int i;
				for (i = 1; i <= 4 && ps->p[i]; i++) {
					char c = ps->p[i];
					code <<= 4;
					if (c >= '0' && c <= '9')
						code |= (unsigned)(c - '0');
					else if (c >= 'a' && c <= 'f')
						code |= (unsigned)(c - 'a' + 10);
					else if (c >= 'A' && c <= 'F')
						code |= (unsigned)(c - 'A' + 10);
				}
				ps->p += 4;
				if (code < 0x80) {
					out[o++] = (char)code;
				} else if (code < 0x800) {
					out[o++] = (char)(0xc0 | (code >> 6));
					out[o++] = (char)(0x80 | (code & 0x3f));
				} else {
					out[o++] = (char)(0xe0 | (code >> 12));
					out[o++] = (char)(0x80 | ((code >> 6) & 0x3f));
					out[o++] = (char)(0x80 | (code & 0x3f));
				}
				break;
			}
			default: out[o++] = *ps->p; break;
			}
			if (*ps->p)
				ps->p++;
		} else {
			out[o++] = *ps->p++;
		}
	}
	if (*ps->p == '"')
		ps->p++;
	out[o] = 0;
	return out;
}

static json *node_new(int type)
{
	json *node = calloc(1, sizeof(*node));

	if (node)
		node->type = type;
	return node;
}

static json *parse_container(struct parser *ps, int type)
{
	json *node = node_new(type);
	json *tail = NULL;
	char close = (type == JSON_OBJ) ? '}' : ']';

	if (!node)
		return NULL;
	ps->p++;
	skip_ws(ps);
	if (*ps->p == close) {
		ps->p++;
		return node;
	}

	for (;;) {
		json *item;
		char *key = NULL;

		skip_ws(ps);
		if (type == JSON_OBJ) {
			key = parse_string(ps);
			skip_ws(ps);
			if (*ps->p != ':') {
				free(key);
				json_free(node);
				return NULL;
			}
			ps->p++;
		}
		item = parse_value(ps);
		if (!item) {
			free(key);
			json_free(node);
			return NULL;
		}
		item->key = key;
		if (tail)
			tail->next = item;
		else
			node->child = item;
		tail = item;

		skip_ws(ps);
		if (*ps->p == ',') {
			ps->p++;
			continue;
		}
		if (*ps->p == close) {
			ps->p++;
			return node;
		}
		json_free(node);
		return NULL;
	}
}

static json *parse_value(struct parser *ps)
{
	json *node;

	skip_ws(ps);
	switch (*ps->p) {
	case '{':
		return parse_container(ps, JSON_OBJ);
	case '[':
		return parse_container(ps, JSON_ARR);
	case '"':
		node = node_new(JSON_STR);
		if (!node)
			return NULL;
		node->str = parse_string(ps);
		return node;
	case 't':
		ps->p += 4;
		node = node_new(JSON_BOOL);
		if (node)
			node->boolean = 1;
		return node;
	case 'f':
		ps->p += 5;
		return node_new(JSON_BOOL);
	case 'n':
		ps->p += 4;
		return node_new(JSON_NULL);
	default: {
		char *end;
		long long value = strtoll(ps->p, &end, 10);

		if (end == ps->p)
			return NULL;
		ps->p = end;
		if (*ps->p == '.') {
			ps->p++;
			while (*ps->p >= '0' && *ps->p <= '9')
				ps->p++;
		}
		node = node_new(JSON_NUM);
		if (node)
			node->num = value;
		return node;
	}
	}
}

json *json_parse(const char *text)
{
	struct parser ps = { text };

	return parse_value(&ps);
}

void json_free(json *node)
{
	while (node) {
		json *next = node->next;

		json_free(node->child);
		free(node->key);
		free(node->str);
		free(node);
		node = next;
	}
}

json *json_get(json *node, const char *path)
{
	char part[64];

	while (node && *path) {
		size_t len = 0;
		json *child;

		while (*path == '/')
			path++;
		while (path[len] && path[len] != '/' && len < sizeof(part) - 1)
			len++;
		if (!len)
			break;
		memcpy(part, path, len);
		part[len] = 0;
		path += len;

		if (node->type == JSON_ARR) {
			long index = strtol(part, NULL, 10);
			child = node->child;
			while (child && index-- > 0)
				child = child->next;
		} else if (node->type == JSON_OBJ) {
			for (child = node->child; child; child = child->next)
				if (child->key && !strcmp(child->key, part))
					break;
		} else {
			return NULL;
		}
		node = child;
	}
	return node;
}

const char *json_str(json *node, const char *path)
{
	json *found = json_get(node, path);

	return (found && found->type == JSON_STR) ? found->str : NULL;
}

long long json_num(json *node, const char *path)
{
	json *found = json_get(node, path);

	return (found && found->type == JSON_NUM) ? found->num : 0;
}

int json_bool(json *node, const char *path)
{
	json *found = json_get(node, path);

	return (found && found->type == JSON_BOOL) ? found->boolean : 0;
}

char *json_escape(const char *in, char *out, size_t out_len)
{
	size_t o = 0;

	for (; *in && o + 7 < out_len; in++) {
		switch (*in) {
		case '"':  out[o++] = '\\'; out[o++] = '"'; break;
		case '\\': out[o++] = '\\'; out[o++] = '\\'; break;
		case '\n': out[o++] = '\\'; out[o++] = 'n'; break;
		case '\r': out[o++] = '\\'; out[o++] = 'r'; break;
		case '\t': out[o++] = '\\'; out[o++] = 't'; break;
		default:
			if ((unsigned char)*in < 0x20)
				o += (size_t)snprintf(out + o, out_len - o, "\\u%04x", *in);
			else
				out[o++] = *in;
		}
	}
	out[o] = 0;
	return out;
}
