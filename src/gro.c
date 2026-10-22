#include "gro.h"

#include <linux/virtio_net.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <unistd.h>

#define MAX_HDR 80         /* IPv6 40 + TCP with options 60, clamped below */
#define MAX_COALESCED 65535

struct gro {
	int tun_fd;
	size_t vnet_hdr_len;
	size_t mtu;

	/* the run currently being built */
	int open;
	uint8_t hdr[MAX_HDR];
	size_t hdr_len;          /* network + transport header bytes */
	size_t ip_hdr_len;
	int is_v6;
	uint32_t next_seq;       /* host order */
	uint16_t seg_size;       /* payload length of the first segment */
	int segments;

	uint8_t *payload;
	size_t payload_len;
	size_t payload_cap;

	uint8_t *out;            /* vnet hdr + headers + payload */
	size_t out_cap;
};

static uint16_t rd16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static uint32_t rd32(const uint8_t *p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
	       ((uint32_t)p[2] << 8) | p[3];
}
static void wr16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }

/* The IPv4 header checksum covers the header only, and the kernel does not
 * recompute it for us -- VIRTIO_NET_HDR_F_NEEDS_CSUM only ever refers to the
 * transport checksum. Growing the total-length field means redoing this. */
static void ipv4_fix_checksum(uint8_t *ip, size_t ip_hdr_len)
{
	uint32_t sum = 0;
	size_t i;

	ip[10] = ip[11] = 0;
	for (i = 0; i < ip_hdr_len; i += 2)
		sum += rd16(ip + i);
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	wr16(ip + 10, (uint16_t)~sum);
}

struct gro *gro_new(int tun_fd, size_t vnet_hdr_len, size_t mtu)
{
	struct gro *g = calloc(1, sizeof(*g));

	if (!g)
		return NULL;
	g->tun_fd = tun_fd;
	g->vnet_hdr_len = vnet_hdr_len;
	g->mtu = mtu;
	g->payload_cap = MAX_COALESCED;
	g->out_cap = MAX_COALESCED + MAX_HDR + 32;
	g->payload = malloc(g->payload_cap);
	g->out = malloc(g->out_cap);
	if (!g->payload || !g->out) {
		gro_free(g);
		return NULL;
	}
	return g;
}

void gro_free(struct gro *g)
{
	if (!g)
		return;
	free(g->payload);
	free(g->out);
	free(g);
}

/* Write one packet through untouched, prefixing an empty virtio header when
 * the device expects one. */
static int write_plain(struct gro *g, const uint8_t *packet, size_t len)
{
	if (!g->vnet_hdr_len) {
		ssize_t n = write(g->tun_fd, packet, len);

		return n < 0 ? -1 : 0;
	}
	{
		uint8_t vnet[sizeof(struct virtio_net_hdr)];
		struct iovec iov[2];
		ssize_t n;

		memset(vnet, 0, sizeof(vnet));
		iov[0].iov_base = vnet;
		iov[0].iov_len = g->vnet_hdr_len;
		iov[1].iov_base = (void *)(uintptr_t)packet;
		iov[1].iov_len = len;
		n = writev(g->tun_fd, iov, 2);
		return n < 0 ? -1 : 0;
	}
}

/* Sum used for the TCP pseudo-header. The kernel finishes the checksum when
 * VIRTIO_NET_HDR_F_NEEDS_CSUM is set, but it expects the pseudo-header sum to
 * already be sitting in the checksum field. */
static uint16_t pseudo_sum(const uint8_t *hdr, size_t ip_hdr_len, int is_v6,
			   size_t tcp_len)
{
	uint32_t sum = 0;
	size_t i;

	if (is_v6) {
		for (i = 8; i < 40; i += 2)
			sum += rd16(hdr + i);
		sum += (uint32_t)(tcp_len >> 16) & 0xffff;
		sum += (uint32_t)tcp_len & 0xffff;
		sum += 6; /* next header: TCP */
	} else {
		for (i = 12; i < 20; i += 2)
			sum += rd16(hdr + i);
		sum += 6;
		sum += (uint32_t)tcp_len;
	}
	(void)ip_hdr_len;
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return (uint16_t)sum;
}

static int emit(struct gro *g)
{
	uint8_t *out = g->out;
	struct virtio_net_hdr vh;
	size_t total, tcp_len;

	if (!g->open)
		return 0;

	tcp_len = (g->hdr_len - g->ip_hdr_len) + g->payload_len;
	total = g->hdr_len + g->payload_len;

	memset(&vh, 0, sizeof(vh));
	if (g->segments > 1) {
		vh.flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
		vh.gso_type = g->is_v6 ? VIRTIO_NET_HDR_GSO_TCPV6
				       : VIRTIO_NET_HDR_GSO_TCPV4;
		vh.gso_size = g->seg_size;
		vh.hdr_len = (uint16_t)g->hdr_len;
		vh.csum_start = (uint16_t)g->ip_hdr_len;
		vh.csum_offset = 16; /* offset of the checksum within the TCP header */
	}

	memcpy(out, &vh, sizeof(vh));
	memcpy(out + g->vnet_hdr_len, g->hdr, g->hdr_len);
	memcpy(out + g->vnet_hdr_len + g->hdr_len, g->payload, g->payload_len);

	{
		uint8_t *ip = out + g->vnet_hdr_len;

		if (g->is_v6) {
			wr16(ip + 4, (uint16_t)(total - 40));
		} else {
			wr16(ip + 2, (uint16_t)total);
			ipv4_fix_checksum(ip, g->ip_hdr_len);
		}
		if (g->segments > 1) {
			uint8_t *tcp = ip + g->ip_hdr_len;
			uint16_t ps = pseudo_sum(ip, g->ip_hdr_len, g->is_v6, tcp_len);

			wr16(tcp + 16, ps);
		}
	}

	g->open = 0;
	g->payload_len = 0;
	g->segments = 0;

	{
		ssize_t n = write(g->tun_fd, out, g->vnet_hdr_len + total);

		return n < 0 ? -1 : 0;
	}
}

int gro_flush(struct gro *g)
{
	return emit(g);
}

/* Describe an inbound packet enough to decide whether it can extend the run. */
struct parsed {
	int ok;
	int is_v6;
	size_t ip_hdr_len;
	size_t tcp_hdr_len;
	size_t hdr_len;
	uint32_t seq;
	size_t payload_len;
	uint8_t flags;
};

static struct parsed parse(const uint8_t *p, size_t len)
{
	struct parsed r;
	size_t total;

	memset(&r, 0, sizeof(r));
	if (len < 40)
		return r;

	if ((p[0] >> 4) == 4) {
		r.ip_hdr_len = (size_t)(p[0] & 0x0f) * 4;
		if (r.ip_hdr_len < 20 || len < r.ip_hdr_len + 20)
			return r;
		if (p[9] != 6)
			return r;                       /* not TCP */
		if (rd16(p + 6) & 0x3fff)
			return r;                       /* fragment */
		total = rd16(p + 2);
		if (total > len)
			return r;
		r.is_v6 = 0;
	} else if ((p[0] >> 4) == 6) {
		if (len < 40 + 20 || p[6] != 6)
			return r;                       /* no extension headers, TCP only */
		r.ip_hdr_len = 40;
		total = 40 + (size_t)rd16(p + 4);
		if (total > len)
			return r;
		r.is_v6 = 1;
	} else {
		return r;
	}

	{
		const uint8_t *tcp = p + r.ip_hdr_len;

		r.tcp_hdr_len = (size_t)(tcp[12] >> 4) * 4;
		if (r.tcp_hdr_len < 20 || r.ip_hdr_len + r.tcp_hdr_len > total)
			return r;
		r.flags = tcp[13];
		r.seq = rd32(tcp + 4);
	}
	r.hdr_len = r.ip_hdr_len + r.tcp_hdr_len;
	if (r.hdr_len > MAX_HDR)
		return r;
	r.payload_len = total - r.hdr_len;
	r.ok = 1;
	return r;
}

/* Two packets belong to the same run when their headers match byte for byte
 * apart from the fields that legitimately move between segments. */
static int same_flow(const struct gro *g, const uint8_t *p, const struct parsed *q)
{
	if (!g->open || g->is_v6 != q->is_v6 || g->hdr_len != q->hdr_len)
		return 0;
	if (q->is_v6) {
		if (memcmp(g->hdr + 8, p + 8, 32))          /* addresses */
			return 0;
	} else {
		if (memcmp(g->hdr + 12, p + 12, 8))         /* addresses */
			return 0;
	}
	/* ports */
	return !memcmp(g->hdr + g->ip_hdr_len, p + q->ip_hdr_len, 4);
}

int gro_push(struct gro *g, const uint8_t *packet, size_t len)
{
	struct parsed q;

	if (!g->vnet_hdr_len)
		return write_plain(g, packet, len);

	q = parse(packet, len);

	/* Anything not a plain TCP data segment goes straight out, after the run
	 * in progress so ordering within the flow is preserved. */
	if (!q.ok || !q.payload_len ||
	    (q.flags & 0x07) ||                      /* FIN, SYN, RST */
	    (q.flags & 0x20)) {                      /* URG */
		if (emit(g))
			return -1;
		return write_plain(g, packet, len);
	}

	if (g->open) {
		int joinable = same_flow(g, packet, &q) &&
			       q.seq == g->next_seq &&
			       q.payload_len <= g->seg_size &&
			       g->payload_len + q.payload_len <= g->payload_cap;

		if (!joinable) {
			if (emit(g))
				return -1;
		} else {
			memcpy(g->payload + g->payload_len,
			       packet + q.hdr_len, q.payload_len);
			g->payload_len += q.payload_len;
			g->next_seq += (uint32_t)q.payload_len;
			g->segments++;
			/* A short segment ends the run: nothing may follow it. */
			if (q.payload_len < g->seg_size)
				return emit(g);
			return 0;
		}
	}

	/* start a new run */
	memcpy(g->hdr, packet, q.hdr_len);
	g->hdr_len = q.hdr_len;
	g->ip_hdr_len = q.ip_hdr_len;
	g->is_v6 = q.is_v6;
	g->seg_size = (uint16_t)q.payload_len;
	g->next_seq = q.seq + (uint32_t)q.payload_len;
	memcpy(g->payload, packet + q.hdr_len, q.payload_len);
	g->payload_len = q.payload_len;
	g->segments = 1;
	g->open = 1;
	return 0;
}
