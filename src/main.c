#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "api.h"
#include "ctl.h"
#include "h2.h"
#include "route.h"
#include "tlsx.h"
#include "tun.h"

static const char USAGE[] =
"warpq - minimal Cloudflare WARP MASQUE client\n"
"\n"
"USAGE:\n"
"  warpq register [-c FILE] [-n NAME] [--secure]\n"
"                                        register a free WARP account for MASQUE\n"
"  warpq up [-c FILE] [OPTIONS] [--secure]\n"
"                                        bring the tunnel up on a TUN device\n"
"  warpq account [-c FILE]               show account type, WARP+ status and quota\n"
"  warpq license [-c FILE] KEY           bind a WARP+ license key to this device\n"
"  warpq license [-c FILE] --clear       unbind the license key\n"
"  warpq status [-s SOCK] [-j]           query the running daemon\n"
"  warpq stop [-s SOCK]                  ask the running daemon to exit\n"
"\n"
"OPTIONS (up):\n"
"  -i IFACE     TUN interface name (default: warp0)\n"
"  -m MTU       tunnel MTU (default: 1280)\n"
"  -p PORT      MASQUE endpoint port (default: 443)\n"
"  -6           reach the endpoint over IPv6\n"
"  --no-route   do not touch routing; only create and address the interface\n"
"  --no-addr    do not assign addresses or bring the link up (implies --no-route)\n"
"  -s SOCK      control socket path (default: " CTL_DEFAULT_PATH ")\n"
"  --no-ctl     do not create a control socket\n"
"  -t N         tunnel workers, one TLS session and TUN queue each\n"
"               (default: one per CPU core, max 8)\n"
"  --cipher C   restrict the TLS AEAD: auto (default), chacha or aes.\n"
"               the endpoint picks chacha unless only aes is offered\n"
"\n"
"COMMON:\n"
"  -c FILE      config file (default: /etc/warpq.json)\n"
"  --secure     hide the server name on the wire. For registration and other\n"
"               API calls: try TLS ECH, else send no SNI. For 'up': send no\n"
"               SNI on the tunnel (the endpoint ignores it and is pinned by\n"
"               key, so the endpoint name never appears in the clear)\n";

static volatile sig_atomic_t stop_requested;

static void on_signal(int signum)
{
	(void)signum;
	stop_requested = 1;
}

static const char *option(int argc, char **argv, const char *name, const char *fallback)
{
	int i;

	for (i = 1; i < argc - 1; i++)
		if (!strcmp(argv[i], name))
			return argv[i + 1];
	return fallback;
}

static int flag(int argc, char **argv, const char *name)
{
	int i;

	for (i = 1; i < argc; i++)
		if (!strcmp(argv[i], name))
			return 1;
	return 0;
}

static void human_bytes(long long value, char *out, size_t out_len)
{
	static const char *UNITS[] = { "B", "KiB", "MiB", "GiB", "TiB" };
	int unit = 0;
	long long whole = value, fraction = 0;

	while (whole >= 1024 && unit < 4) {
		fraction = (whole % 1024) * 100 / 1024;
		whole /= 1024;
		unit++;
	}
	snprintf(out, out_len, "%lld.%02lld %s", whole, fraction, UNITS[unit]);
}

static void print_account(const warp_account *account)
{
	char premium[32], quota[32];

	human_bytes(account->premium_data, premium, sizeof(premium));
	human_bytes(account->quota, quota, sizeof(quota));
	printf("account type  %s\n", account->account_type);
	printf("warp+         %s\n", account->warp_plus ? "yes" : "no");
	if (account->role[0])
		printf("role          %s\n", account->role);
	printf("premium data  %s\n", premium);
	printf("quota         %s\n", quota);
	if (account->license[0])
		printf("license       %s\n", account->license);
}

static int cmd_register(const char *path, const char *name)
{
	warp_config config;

	if (!access(path, F_OK)) {
		fprintf(stderr, "error: %s already exists; delete it to register a new account\n", path);
		return 1;
	}
	if (api_register(&config, name, "PC", "en_US")) {
		fprintf(stderr, "error: %s\n", api_error());
		return 1;
	}
	if (config_save(&config, path)) {
		fprintf(stderr, "error: %s\n", api_error());
		config_free(&config);
		return 1;
	}
	printf("registered device %s\n", config.id);
	printf("  endpoint  %s / %s\n", config.endpoint_v4, config.endpoint_v6);
	printf("  addresses %s / %s\n", config.ipv4, config.ipv6);
	printf("  saved to  %s\n", path);
	config_free(&config);
	return 0;
}

static int cmd_account(const char *path)
{
	warp_config config;
	warp_account account;
	int rc;

	if (config_load(&config, path)) {
		fprintf(stderr, "error: %s\n", api_error());
		return 1;
	}
	rc = api_account(&config, &account);
	config_free(&config);
	if (rc) {
		fprintf(stderr, "error: %s\n", api_error());
		return 1;
	}
	print_account(&account);
	return 0;
}

static int cmd_license(const char *path, const char *key, int clear)
{
	warp_config config;
	warp_account account;
	int rc;

	if (config_load(&config, path)) {
		fprintf(stderr, "error: %s\n", api_error());
		return 1;
	}
	if (clear) {
		rc = api_clear_license(&config);
		if (!rc) {
			printf("license unbound\n");
			rc = api_account(&config, &account);
		}
	} else if (key) {
		rc = api_set_license(&config, key, &account);
		if (!rc)
			printf("license applied\n");
	} else {
		fprintf(stderr, "usage: warpq license [-c FILE] KEY | --clear\n");
		config_free(&config);
		return 1;
	}
	config_free(&config);
	if (rc) {
		fprintf(stderr, "error: %s\n", api_error());
		return 1;
	}
	print_account(&account);
	return 0;
}

/* One worker: its own TUN queue, its own TLS connection to the endpoint, its
 * own HTTP/2 session. Workers share nothing but the status counters (atomic)
 * and the stop flag, so they scale across cores without locking. A single TLS
 * connection could not be split this way -- record sequence numbers make it
 * strictly ordered -- which is why each worker dials its own. */
struct worker {
	pthread_t thread;
	const warp_config *config;
	int tun_fd;
	tunnel_opts opts;
	volatile sig_atomic_t *stop;
	struct warp_status *status;
	int index;
};

#define MAX_WORKERS 8

static void *worker_main(void *arg)
{
	struct worker *w = arg;

	while (!*w->stop) {
		if (h2_run(w->config, w->tun_fd, &w->opts, w->stop, w->status) &&
		    !*w->stop)
			fprintf(stderr, "worker %d down: %s\n", w->index, h2_error());
		if (!*w->stop) {
			__atomic_fetch_add(&w->status->reconnects, 1, __ATOMIC_RELAXED);
			sleep(1);
		}
	}
	return NULL;
}

/* Two by default. Each extra worker adds a TLS session, which lifts aggregate
 * throughput when several flows are in the air but costs a single flow some
 * speed -- a flow is hashed to one TUN queue, so it can only ever use one
 * worker, and the idle ones still cost cache and scheduling. Measured on a
 * 4-core ipq40xx: one worker 29.6 Mbit/s single / 34.4 aggregate, two 29.4 /
 * 51.8, four 23.2 / 58.1. Two is the point where aggregate improves without
 * the single-flow loss. Raise it with -t if the traffic is mostly parallel. */
static int default_workers(void)
{
	long n = sysconf(_SC_NPROCESSORS_ONLN);

	if (n < 2)
		return 1;
	return 2;
}

static int cmd_up(const char *path, const char *iface, int mtu, int port,
		  int use_ipv6, int addressed, int routed, const char *ctl_path,
		  const char *cipher, int workers, int secure)
{
	warp_config config;
	struct warp_status status;
	struct worker pool[MAX_WORKERS];
	char name[32];
	int tun_fd, ctl_fd = -1, have_v6 = 0, rc = 0;
	int started = 0, i;
	size_t vnet_hdr_len = 0;

	if (workers < 1)
		workers = 1;
	if (workers > MAX_WORKERS)
		workers = MAX_WORKERS;

	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);
	signal(SIGPIPE, SIG_IGN);

	if (!strcmp(cipher, "chacha"))
		tls_prefer_cipher(TLS_CIPHER_CHACHA);
	else if (!strcmp(cipher, "aes"))
		tls_prefer_cipher(TLS_CIPHER_AES);

	if (config_load(&config, path)) {
		fprintf(stderr, "error: %s\n", api_error());
		return 1;
	}
	if (tls_global_init()) {
		fprintf(stderr, "error: %s\n", tls_error());
		config_free(&config);
		return 1;
	}

	snprintf(name, sizeof(name), "%s", iface);
	/* With more than one worker the device needs IFF_MULTI_QUEUE so each
	 * worker can hold its own queue; the kernel hashes flows across them. */
	/* Always take a multi-queue device: it carries the virtio header that
	 * lets inbound segments be coalesced, and extra queues can be attached
	 * later without recreating it. */
	tun_fd = tun_open_queue(name, sizeof(name), &vnet_hdr_len);
	if (tun_fd < 0) {
		fprintf(stderr, "error: %s\n", tun_error());
		config_free(&config);
		return 1;
	}
	tun_nonblocking(tun_fd);

	if (addressed) {
		if (tun_set_mtu(name, mtu) ||
		    (config.ipv4[0] && tun_set_ipv4(name, config.ipv4)) ||
		    tun_set_up(name)) {
			fprintf(stderr, "error: %s\n", tun_error());
			rc = 1;
			goto cleanup;
		}
		if (config.ipv6[0] && !tun_set_ipv6(name, config.ipv6))
			have_v6 = 1;
	}
	fprintf(stderr, "interface %s up: %s / %s\n", name, config.ipv4, config.ipv6);

	if (routed) {
		int index = tun_index(name);

		if (index < 0 || route_install((unsigned)index, 1, have_v6)) {
			fprintf(stderr, "error: %s\n",
				index < 0 ? tun_error() : route_error());
			rc = 1;
			routed = 0;
			goto cleanup;
		}
		fprintf(stderr, "routing all traffic via %s (table %u, fwmark %#x)\n",
			name, WARPQ_TABLE, WARPQ_MARK);
	}

	memset(&status, 0, sizeof(status));
	snprintf(status.iface, sizeof(status.iface), "%s", name);
	snprintf(status.ipv4, sizeof(status.ipv4), "%s", config.ipv4);
	snprintf(status.ipv6, sizeof(status.ipv6), "%s", config.ipv6);
	snprintf(status.endpoint, sizeof(status.endpoint), "%s:%d",
		 use_ipv6 && config.endpoint_v6[0] ? config.endpoint_v6 : config.endpoint_v4,
		 port);
	status.routed = routed;
	status.started = time(NULL);

	if (ctl_path) {
		ctl_fd = ctl_listen(ctl_path);
		if (ctl_fd < 0) {
			fprintf(stderr, "error: %s\n", ctl_error());
			rc = 1;
			goto cleanup;
		}
		fprintf(stderr, "control socket at %s\n", ctl_path);
	}

	memset(pool, 0, sizeof(pool));
	for (i = 0; i < workers; i++) {
		pool[i].config = &config;
		pool[i].stop = &stop_requested;
		pool[i].status = &status;
		pool[i].index = i;
		pool[i].opts.port = port;
		pool[i].opts.mtu = mtu;
		pool[i].opts.use_ipv6 = use_ipv6;
		pool[i].opts.mark = routed ? WARPQ_MARK : 0;
		pool[i].opts.vnet_hdr_len = vnet_hdr_len;
		pool[i].opts.secure = secure;
		/* Only worker 0 answers the control socket; the others must not
		 * poll the same listening fd or they would race on accept(). */
		pool[i].opts.ctl_fd = i == 0 ? ctl_fd : -1;

		if (i == 0) {
			pool[i].tun_fd = tun_fd;
		} else {
			char queue_name[32];

			snprintf(queue_name, sizeof(queue_name), "%s", name);
			size_t queue_vnet = 0;

			pool[i].tun_fd = tun_open_queue(queue_name, sizeof(queue_name),
							vnet_hdr_len ? &queue_vnet : NULL);
			if (pool[i].tun_fd < 0) {
				fprintf(stderr, "warning: only %d worker(s): %s\n",
					i, tun_error());
				break;
			}
			tun_nonblocking(pool[i].tun_fd);
		}
	}
	workers = i ? i : 1;

	/* Worker 0 runs on this thread so signals keep landing here. */
	for (i = 1; i < workers; i++) {
		if (pthread_create(&pool[i].thread, NULL, worker_main, &pool[i])) {
			fprintf(stderr, "warning: could not start worker %d\n", i);
			close(pool[i].tun_fd);
			pool[i].tun_fd = -1;
			break;
		}
		started++;
	}
	fprintf(stderr, "tunnel workers: %d (one TLS session per worker), "
		"inbound coalescing %s\n",
		started + 1, vnet_hdr_len ? "on" : "off");

	worker_main(&pool[0]);

	for (i = 1; i <= started; i++)
		pthread_join(pool[i].thread, NULL);
	for (i = 1; i < workers; i++)
		if (pool[i].tun_fd >= 0)
			close(pool[i].tun_fd);

	fprintf(stderr, "shutting down\n");
cleanup:
	if (ctl_fd >= 0)
		ctl_shutdown(ctl_fd, ctl_path);
	if (routed)
		route_remove();
	close(tun_fd);
	config_free(&config);
	return rc;
}

int main(int argc, char **argv)
{
	const char *path = option(argc, argv, "-c", "/etc/warpq.json");
	const char *command = argc > 1 ? argv[1] : "";

	api_secure_mode(flag(argc, argv, "--secure"));

	if (!strcmp(command, "register"))
		return cmd_register(path, option(argc, argv, "-n", ""));
	if (!strcmp(command, "account"))
		return cmd_account(path);
	if (!strcmp(command, "license")) {
		const char *key = NULL;
		int i;

		for (i = 2; i < argc; i++) {
			if (argv[i][0] == '-') {
				if (!strcmp(argv[i], "-c"))
					i++;
				continue;
			}
			key = argv[i];
			break;
		}
		return cmd_license(path, key, flag(argc, argv, "--clear"));
	}
	if (!strcmp(command, "up")) {
		int addressed = !flag(argc, argv, "--no-addr");

		return cmd_up(path,
			      option(argc, argv, "-i", "warp0"),
			      atoi(option(argc, argv, "-m", "1280")),
			      atoi(option(argc, argv, "-p", "443")),
			      flag(argc, argv, "-6"),
			      addressed,
			      addressed && !flag(argc, argv, "--no-route"),
			      flag(argc, argv, "--no-ctl") ? NULL :
				      option(argc, argv, "-s", CTL_DEFAULT_PATH),
			      option(argc, argv, "--cipher", "auto"),
			      atoi(option(argc, argv, "-t", "0")) > 0
				      ? atoi(option(argc, argv, "-t", "0"))
				      : default_workers(),
			      flag(argc, argv, "--secure"));
	}
	if (!strcmp(command, "status"))
		return ctl_request(option(argc, argv, "-s", CTL_DEFAULT_PATH),
				   flag(argc, argv, "-j") ? "status.json" : "status") ?
		       (fprintf(stderr, "error: %s\n", ctl_error()), 1) : 0;
	if (!strcmp(command, "stop"))
		return ctl_request(option(argc, argv, "-s", CTL_DEFAULT_PATH), "stop") ?
		       (fprintf(stderr, "error: %s\n", ctl_error()), 1) : 0;

	fputs(USAGE, stdout);
	return 0;
}
