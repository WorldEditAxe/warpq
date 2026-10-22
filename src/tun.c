#include "tun.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/virtio_net.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

struct in6_ifreq_compat {
	struct in6_addr addr;
	unsigned int prefixlen;
	int ifindex;
};

static char error_buf[128];

const char *tun_error(void)
{
	return error_buf;
}

static int fail(const char *what)
{
	snprintf(error_buf, sizeof(error_buf), "%s: %s", what, strerror(errno));
	return -1;
}

static int ctl(int family, unsigned long request, struct ifreq *ifr, const char *what)
{
	int fd = socket(family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	int rc;

	if (fd < 0)
		return fail(what);
	rc = ioctl(fd, request, ifr);
	close(fd);
	return rc < 0 ? fail(what) : 0;
}

static int tun_open_flags(char *name, size_t name_len, short extra)
{
	struct ifreq ifr;
	int fd = open("/dev/net/tun", O_RDWR | O_CLOEXEC);

	if (fd < 0)
		return fail("failed to open /dev/net/tun");

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = (short)(IFF_TUN | IFF_NO_PI | extra);
	snprintf(ifr.ifr_name, IFNAMSIZ, "%s", name);
	if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
		close(fd);
		return fail("failed to create TUN device");
	}
	snprintf(name, name_len, "%s", ifr.ifr_name);
	return fd;
}

int tun_open(char *name, size_t name_len)
{
	return tun_open_flags(name, name_len, 0);
}

int tun_open_queue(char *name, size_t name_len, size_t *vnet_hdr_len)
{
	int fd;

	if (vnet_hdr_len) {
		unsigned size = (unsigned)sizeof(struct virtio_net_hdr);

		fd = tun_open_flags(name, name_len, IFF_MULTI_QUEUE | IFF_VNET_HDR);
		if (fd >= 0) {
			if (!ioctl(fd, TUNSETVNETHDRSZ, &size)) {
				*vnet_hdr_len = size;
				return fd;
			}
			close(fd);
		}
		*vnet_hdr_len = 0;
	}
	return tun_open_flags(name, name_len, IFF_MULTI_QUEUE);
}

int tun_nonblocking(int fd)
{
	int flags = fcntl(fd, F_GETFL);

	if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
		return fail("failed to set non-blocking");
	return 0;
}

int tun_set_mtu(const char *name, int mtu)
{
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name, IFNAMSIZ, "%s", name);
	ifr.ifr_mtu = mtu;
	return ctl(AF_INET, SIOCSIFMTU, &ifr, "failed to set MTU");
}

int tun_set_ipv4(const char *name, const char *addr)
{
	struct sockaddr_in sin;
	struct ifreq ifr;

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	if (inet_pton(AF_INET, addr, &sin.sin_addr) != 1) {
		snprintf(error_buf, sizeof(error_buf), "bad IPv4 address %s", addr);
		return -1;
	}

	memset(&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name, IFNAMSIZ, "%s", name);
	memcpy(&ifr.ifr_addr, &sin, sizeof(sin));
	if (ctl(AF_INET, SIOCSIFADDR, &ifr, "failed to set IPv4 address"))
		return -1;

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = 0xffffffffu;
	memset(&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name, IFNAMSIZ, "%s", name);
	memcpy(&ifr.ifr_addr, &sin, sizeof(sin));
	return ctl(AF_INET, SIOCSIFNETMASK, &ifr, "failed to set IPv4 netmask");
}

int tun_set_ipv6(const char *name, const char *addr)
{
	struct in6_ifreq_compat req;
	int index = tun_index(name);
	int fd, rc;

	if (index < 0)
		return -1;
	memset(&req, 0, sizeof(req));
	if (inet_pton(AF_INET6, addr, &req.addr) != 1) {
		snprintf(error_buf, sizeof(error_buf), "bad IPv6 address %s", addr);
		return -1;
	}
	req.prefixlen = 128;
	req.ifindex = index;

	fd = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return fail("failed to open IPv6 socket");
	rc = ioctl(fd, SIOCSIFADDR, &req);
	close(fd);
	return rc < 0 ? fail("failed to set IPv6 address") : 0;
}

int tun_set_up(const char *name)
{
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name, IFNAMSIZ, "%s", name);
	if (ctl(AF_INET, SIOCGIFFLAGS, &ifr, "failed to read interface flags"))
		return -1;
	ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
	return ctl(AF_INET, SIOCSIFFLAGS, &ifr, "failed to bring interface up");
}

int tun_index(const char *name)
{
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name, IFNAMSIZ, "%s", name);
	if (ctl(AF_INET, SIOCGIFINDEX, &ifr, "failed to read interface index"))
		return -1;
	return ifr.ifr_ifindex;
}
