#ifndef WARPQ_CTL_H
#define WARPQ_CTL_H

#include <time.h>

#define CTL_DEFAULT_PATH "/var/run/warpq.sock"

struct warp_status {
	char iface[32];
	char ipv4[64];
	char ipv6[64];
	char endpoint[80];
	char cipher[48];
	int connected;
	int routed;
	time_t started;
	unsigned long long rx_packets;
	unsigned long long rx_bytes;
	unsigned long long tx_packets;
	unsigned long long tx_bytes;
	unsigned reconnects;
};

int ctl_listen(const char *path);
int ctl_serve(int listen_fd, const struct warp_status *status);
void ctl_shutdown(int listen_fd, const char *path);

int ctl_request(const char *path, const char *command);

const char *ctl_error(void);

#endif
