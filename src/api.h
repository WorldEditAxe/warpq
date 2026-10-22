#ifndef WARPQ_API_H
#define WARPQ_API_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
	uint8_t *key_der;
	size_t key_len;
	uint8_t *spki;
	size_t spki_len;
	char endpoint_v4[64];
	char endpoint_v6[64];
	char id[64];
	char token[128];
	char ipv4[64];
	char ipv6[64];
} warp_config;

typedef struct {
	char account_type[32];
	char role[32];
	char license[64];
	int warp_plus;
	long long premium_data;
	long long quota;
} warp_account;

int config_load(warp_config *config, const char *path);
int config_save(const warp_config *config, const char *path);
void config_free(warp_config *config);

/* Secure mode hides the API server name on the wire: the call first tries
 * TLS Encrypted Client Hello, and if this build or the network cannot do ECH
 * it sends no SNI at all. Off by default, where the SNI is the API host. */
void api_secure_mode(int on);

int api_register(warp_config *config, const char *device_name,
		 const char *model, const char *locale);
int api_account(const warp_config *config, warp_account *account);
int api_set_license(const warp_config *config, const char *license, warp_account *account);
int api_clear_license(const warp_config *config);

const char *api_error(void);

#endif
