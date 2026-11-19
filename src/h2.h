#ifndef WARPQ_H2_H
#define WARPQ_H2_H

#include <signal.h>
#include <stddef.h>

#include "api.h"
#include "ctl.h"

typedef struct {
	int port;
	int mtu;
	int use_ipv6;
	unsigned mark;
	int ctl_fd;
	size_t vnet_hdr_len;   /* virtio header on the TUN fd; 0 when absent */
	int secure;            /* hide the endpoint name: send no SNI (see h2.c) */
	const char *sni;       /* SNI to send instead; overrides secure when set */
	int tls_engine;        /* TLS_ENGINE_*: who takes the record layer (tls_offload) */
} tunnel_opts;

int h2_run(const warp_config *config, int tun_fd, const tunnel_opts *opts,
	   volatile sig_atomic_t *stop, struct warp_status *status);
const char *h2_error(void);

#endif
