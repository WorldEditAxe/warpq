#include "ctl.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

static char error_buf[160];

const char *ctl_error(void)
{
	return error_buf;
}

static int fail(const char *what)
{
	snprintf(error_buf, sizeof(error_buf), "%s: %s", what, strerror(errno));
	return -1;
}

static int bind_path(int fd, const char *path)
{
	struct sockaddr_un addr;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	if (strlen(path) >= sizeof(addr.sun_path)) {
		snprintf(error_buf, sizeof(error_buf), "socket path too long: %s", path);
		return -1;
	}
	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);
	return bind(fd, (struct sockaddr *)&addr, sizeof(addr));
}

int ctl_listen(const char *path)
{
	int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);

	if (fd < 0)
		return fail("control socket");
	unlink(path);
	if (bind_path(fd, path) < 0) {
		close(fd);
		return fail("failed to bind control socket");
	}
	chmod(path, 0600);
	if (listen(fd, 4) < 0) {
		close(fd);
		unlink(path);
		return fail("failed to listen on control socket");
	}
	return fd;
}

void ctl_shutdown(int listen_fd, const char *path)
{
	if (listen_fd >= 0)
		close(listen_fd);
	if (path)
		unlink(path);
}

static void format_text(const struct warp_status *s, char *out, size_t out_len)
{
	snprintf(out, out_len,
		 "state: %s\n"
		 "transport: masque/http2\n"
		 "interface: %s\n"
		 "ipv4: %s\n"
		 "ipv6: %s\n"
		 "endpoint: %s\n"
		 "cipher: %s\n"
		 "routed: %s\n"
		 "uptime: %lld\n"
		 "rx: %llu packets %llu bytes\n"
		 "tx: %llu packets %llu bytes\n"
		 "reconnects: %u\n",
		 s->connected ? "connected" : "connecting",
		 s->iface, s->ipv4, s->ipv6, s->endpoint,
		 s->cipher[0] ? s->cipher : "-",
		 s->routed ? "yes" : "no",
		 s->started ? (long long)(time(NULL) - s->started) : 0LL,
		 s->rx_packets, s->rx_bytes, s->tx_packets, s->tx_bytes,
		 s->reconnects);
}

static void format_json(const struct warp_status *s, char *out, size_t out_len)
{
	snprintf(out, out_len,
		 "{\"state\":\"%s\",\"transport\":\"masque/http2\",\"interface\":\"%s\","
		 "\"ipv4\":\"%s\",\"ipv6\":\"%s\",\"endpoint\":\"%s\",\"cipher\":\"%s\",\"routed\":%s,"
		 "\"uptime\":%lld,\"rx_packets\":%llu,\"rx_bytes\":%llu,"
		 "\"tx_packets\":%llu,\"tx_bytes\":%llu,\"reconnects\":%u}\n",
		 s->connected ? "connected" : "connecting",
		 s->iface, s->ipv4, s->ipv6, s->endpoint,
		 s->cipher[0] ? s->cipher : "-",
		 s->routed ? "true" : "false",
		 s->started ? (long long)(time(NULL) - s->started) : 0LL,
		 s->rx_packets, s->rx_bytes, s->tx_packets, s->tx_bytes,
		 s->reconnects);
}

int ctl_serve(int listen_fd, const struct warp_status *status)
{
	char request[64];
	char reply[768];
	int client = accept(listen_fd, NULL, NULL);
	ssize_t n;
	int stop = 0;

	if (client < 0)
		return 0;

	n = read(client, request, sizeof(request) - 1);
	if (n <= 0) {
		close(client);
		return 0;
	}
	request[n] = 0;
	while (n > 0 && (request[n - 1] == '\n' || request[n - 1] == '\r'))
		request[--n] = 0;

	if (!strcmp(request, "status")) {
		format_text(status, reply, sizeof(reply));
	} else if (!strcmp(request, "status.json")) {
		format_json(status, reply, sizeof(reply));
	} else if (!strcmp(request, "stop")) {
		snprintf(reply, sizeof(reply), "stopping\n");
		stop = 1;
	} else if (!strcmp(request, "ping")) {
		snprintf(reply, sizeof(reply), "pong\n");
	} else {
		snprintf(reply, sizeof(reply),
			 "unknown command; try status, status.json, ping or stop\n");
	}

	{
		size_t len = strlen(reply);
		ssize_t written = write(client, reply, len);

		(void)written;
	}
	close(client);
	return stop;
}

int ctl_request(const char *path, const char *command)
{
	struct sockaddr_un addr;
	char reply[1024];
	int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	ssize_t n;

	if (fd < 0)
		return fail("control socket");

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);
	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		close(fd);
		snprintf(error_buf, sizeof(error_buf),
			 "no daemon listening on %s (%s)", path, strerror(errno));
		return -1;
	}
	if (write(fd, command, strlen(command)) < 0 || shutdown(fd, SHUT_WR) < 0) {
		close(fd);
		return fail("failed to send command");
	}
	while ((n = read(fd, reply, sizeof(reply) - 1)) > 0) {
		reply[n] = 0;
		fputs(reply, stdout);
	}
	close(fd);
	return 0;
}
