#include "route.h"

#include <errno.h>
#include <ifaddrs.h>
#include <linux/fib_rules.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define PRIORITY_BYPASS   32763u
#define PRIORITY_SUPPRESS 32764u
#define PRIORITY_TUNNEL   32765u

#define MAX_BYPASS 48

static char error_buf[128];
static unsigned installed_ifindex;
static int installed_v4, installed_v6;

/* Traffic pinned to the main table ahead of the tunnel: from a local address
 * outside the tunnel, or to a private or link-local destination. */
struct bypass {
	unsigned char family;
	unsigned char to;        /* match the destination rather than the source */
	unsigned char prefix_len;
	unsigned char addr[16];
};
static struct bypass bypasses[MAX_BYPASS];
static int bypass_count;

/* Never carried through the tunnel, as the official client excludes them by
 * default: RFC 1918, shared address space (100.64.0.0/10, also Tailscale's
 * range), link-local and IPv6 unique-local. */
static const struct {
	unsigned char family;
	unsigned char prefix_len;
	unsigned char addr[16];
} PRIVATE_RANGES[] = {
	{ AF_INET, 8, { 10 } },
	{ AF_INET, 12, { 172, 16 } },
	{ AF_INET, 16, { 192, 168 } },
	{ AF_INET, 10, { 100, 64 } },
	{ AF_INET, 16, { 169, 254 } },
	{ AF_INET6, 7, { 0xfc } },
	{ AF_INET6, 10, { 0xfe, 0x80 } },
};

const char *route_error(void)
{
	return error_buf;
}

static int fail(const char *what)
{
	snprintf(error_buf, sizeof(error_buf), "%s: %s", what, strerror(errno));
	return -1;
}

struct request {
	struct nlmsghdr hdr;
	union {
		struct rtmsg route;
		struct fib_rule_hdr rule;
	} body;
	char attrs[256];
};

static void put_attr(struct request *req, unsigned short type, const void *data, size_t len)
{
	struct rtattr *attr = (struct rtattr *)((char *)req + NLMSG_ALIGN(req->hdr.nlmsg_len));

	attr->rta_type = type;
	attr->rta_len = (unsigned short)RTA_LENGTH(len);
	memcpy(RTA_DATA(attr), data, len);
	req->hdr.nlmsg_len = NLMSG_ALIGN(req->hdr.nlmsg_len) + (unsigned)RTA_ALIGN(attr->rta_len);
}

static int talk(struct request *req)
{
	char buf[4096];
	struct nlmsghdr *reply = (struct nlmsghdr *)buf;
	int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
	ssize_t n;

	if (fd < 0)
		return fail("netlink socket");
	if (send(fd, req, req->hdr.nlmsg_len, 0) < 0) {
		close(fd);
		return fail("netlink send");
	}
	n = recv(fd, buf, sizeof(buf), 0);
	close(fd);
	if (n < 0)
		return fail("netlink recv");
	if ((size_t)n >= sizeof(struct nlmsghdr) + sizeof(int) && reply->nlmsg_type == NLMSG_ERROR) {
		int code = *(int *)NLMSG_DATA(reply);

		if (code) {
			errno = -code;
			return fail("netlink request rejected");
		}
	}
	return 0;
}

static int default_route(int add, unsigned char family, unsigned ifindex)
{
	struct request req;
	unsigned table = WARPQ_TABLE;

	memset(&req, 0, sizeof(req));
	req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	req.hdr.nlmsg_type = add ? RTM_NEWROUTE : RTM_DELROUTE;
	req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK |
			      (add ? (NLM_F_CREATE | NLM_F_EXCL) : 0);
	req.hdr.nlmsg_seq = 1;
	req.body.route.rtm_family = family;
	req.body.route.rtm_table = RT_TABLE_UNSPEC;
	req.body.route.rtm_protocol = RTPROT_BOOT;
	req.body.route.rtm_scope = add ? RT_SCOPE_LINK : RT_SCOPE_NOWHERE;
	req.body.route.rtm_type = add ? RTN_UNICAST : RTN_UNSPEC;
	put_attr(&req, RTA_TABLE, &table, sizeof(table));
	put_attr(&req, RTA_OIF, &ifindex, sizeof(ifindex));
	return talk(&req);
}

static int rule(int add, unsigned char family, int invert, unsigned priority, unsigned table)
{
	struct request req;
	unsigned mark = WARPQ_MARK;
	unsigned suppress = 0;

	memset(&req, 0, sizeof(req));
	req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct fib_rule_hdr));
	req.hdr.nlmsg_type = add ? RTM_NEWRULE : RTM_DELRULE;
	req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK |
			      (add ? (NLM_F_CREATE | NLM_F_EXCL) : 0);
	req.hdr.nlmsg_seq = 1;
	req.body.rule.family = family;
	req.body.rule.table = table < 256 ? (unsigned char)table : 0;
	req.body.rule.action = FR_ACT_TO_TBL;
	req.body.rule.flags = invert ? FIB_RULE_INVERT : 0;
	put_attr(&req, FRA_PRIORITY, &priority, sizeof(priority));
	put_attr(&req, FRA_TABLE, &table, sizeof(table));
	if (invert)
		put_attr(&req, FRA_FWMARK, &mark, sizeof(mark));
	else
		put_attr(&req, FRA_SUPPRESS_PREFIXLEN, &suppress, sizeof(suppress));
	return talk(&req);
}

/* Replies on connections that came in over the LAN or WAN carry that
 * interface's address as their source. Without a source rule their only route
 * back is the main table's default, which suppress_prefixlength 0 skips, so
 * they would be sent into the tunnel -- an SSH session to this host goes dead
 * the moment the tunnel comes up. Traffic this host originates is unaffected:
 * its source is not chosen until the lookup, which lands on the tunnel.
 * Destination rules keep private networks off the tunnel in both directions,
 * including ones reached through a gateway rather than a connected route. */
static int bypass_rule(int add, const struct bypass *b)
{
	struct request req;
	unsigned priority = PRIORITY_BYPASS;
	unsigned table = RT_TABLE_MAIN;
	size_t len = b->family == AF_INET ? 4 : 16;

	memset(&req, 0, sizeof(req));
	req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct fib_rule_hdr));
	req.hdr.nlmsg_type = add ? RTM_NEWRULE : RTM_DELRULE;
	req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK |
			      (add ? (NLM_F_CREATE | NLM_F_EXCL) : 0);
	req.hdr.nlmsg_seq = 1;
	req.body.rule.family = b->family;
	if (b->to)
		req.body.rule.dst_len = b->prefix_len;
	else
		req.body.rule.src_len = b->prefix_len;
	req.body.rule.table = RT_TABLE_MAIN;
	req.body.rule.action = FR_ACT_TO_TBL;
	put_attr(&req, FRA_PRIORITY, &priority, sizeof(priority));
	put_attr(&req, FRA_TABLE, &table, sizeof(table));
	put_attr(&req, b->to ? FRA_DST : FRA_SRC, b->addr, len);
	return talk(&req);
}

/* The private ranges, then every address on an interface other than the
 * tunnel, loopback excluded and IPv6 link-local too (fe80::/10 is above). */
static void collect_bypasses(unsigned ifindex, int ipv4, int ipv6)
{
	struct ifaddrs *list, *ifa;
	size_t i;

	memset(bypasses, 0, sizeof(bypasses));
	bypass_count = 0;
	for (i = 0; i < sizeof(PRIVATE_RANGES) / sizeof(PRIVATE_RANGES[0]); i++) {
		struct bypass *b = &bypasses[bypass_count];

		if (PRIVATE_RANGES[i].family == AF_INET ? !ipv4 : !ipv6)
			continue;
		b->family = PRIVATE_RANGES[i].family;
		b->to = 1;
		b->prefix_len = PRIVATE_RANGES[i].prefix_len;
		memcpy(b->addr, PRIVATE_RANGES[i].addr, sizeof(b->addr));
		bypass_count++;
	}

	if (getifaddrs(&list))
		return;
	for (ifa = list; ifa && bypass_count < MAX_BYPASS; ifa = ifa->ifa_next) {
		struct bypass *src = &bypasses[bypass_count];

		if (!ifa->ifa_addr || (ifa->ifa_flags & IFF_LOOPBACK) ||
		    if_nametoindex(ifa->ifa_name) == ifindex)
			continue;
		if (ifa->ifa_addr->sa_family == AF_INET && ipv4) {
			src->family = AF_INET;
			src->prefix_len = 32;
			memcpy(src->addr, &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr, 4);
		} else if (ifa->ifa_addr->sa_family == AF_INET6 && ipv6) {
			const struct in6_addr *a = &((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr;

			if (IN6_IS_ADDR_LINKLOCAL(a) || IN6_IS_ADDR_LOOPBACK(a))
				continue;
			src->family = AF_INET6;
			src->prefix_len = 128;
			memcpy(src->addr, a, 16);
		} else {
			continue;
		}
		bypass_count++;
	}
	freeifaddrs(list);
}

int route_install(unsigned ifindex, int ipv4, int ipv6)
{
	unsigned char families[2];
	int count = 0, i;

	if (ipv4)
		families[count++] = AF_INET;
	if (ipv6)
		families[count++] = AF_INET6;

	installed_ifindex = ifindex;
	installed_v4 = ipv4;
	installed_v6 = ipv6;

	for (i = 0; i < count; i++) {
		unsigned char family = families[i];

		rule(0, family, 0, PRIORITY_SUPPRESS, RT_TABLE_MAIN);
		rule(0, family, 1, PRIORITY_TUNNEL, WARPQ_TABLE);

		if (default_route(1, family, ifindex))
			return -1;
		if (rule(1, family, 0, PRIORITY_SUPPRESS, RT_TABLE_MAIN))
			return -1;
		if (rule(1, family, 1, PRIORITY_TUNNEL, WARPQ_TABLE))
			return -1;
	}

	collect_bypasses(ifindex, ipv4, ipv6);
	for (i = 0; i < bypass_count; i++) {
		bypass_rule(0, &bypasses[i]);
		if (bypass_rule(1, &bypasses[i]))
			return -1;
	}
	return 0;
}

void route_remove(void)
{
	unsigned char families[2];
	int count = 0, i;

	if (installed_v4)
		families[count++] = AF_INET;
	if (installed_v6)
		families[count++] = AF_INET6;

	for (i = 0; i < count; i++) {
		rule(0, families[i], 0, PRIORITY_SUPPRESS, RT_TABLE_MAIN);
		rule(0, families[i], 1, PRIORITY_TUNNEL, WARPQ_TABLE);
		default_route(0, families[i], installed_ifindex);
	}
	for (i = 0; i < bypass_count; i++)
		bypass_rule(0, &bypasses[i]);
	bypass_count = 0;
	installed_v4 = installed_v6 = 0;
}

int route_mark_socket(int fd, unsigned mark)
{
	if (setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) < 0)
		return fail("failed to set SO_MARK");
	return 0;
}
