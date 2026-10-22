#ifndef WARPQ_UTIL_H
#define WARPQ_UTIL_H

#include <stddef.h>
#include <stdint.h>

char *b64_encode(const uint8_t *data, size_t len);
uint8_t *b64_decode(const char *text, size_t len, size_t *out_len);
void hex_encode(const uint8_t *data, size_t len, char *out);

void cf_time(char *out, size_t out_len);
void x509_time(char *out, size_t out_len, long offset_secs);

enum { JSON_NULL, JSON_BOOL, JSON_NUM, JSON_STR, JSON_ARR, JSON_OBJ };

typedef struct json {
	int type;
	char *key;
	char *str;
	long long num;
	int boolean;
	struct json *child;
	struct json *next;
} json;

json *json_parse(const char *text);
void json_free(json *node);
json *json_get(json *node, const char *path);
const char *json_str(json *node, const char *path);
long long json_num(json *node, const char *path);
int json_bool(json *node, const char *path);
char *json_escape(const char *in, char *out, size_t out_len);

#endif
