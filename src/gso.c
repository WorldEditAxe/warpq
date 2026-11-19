#include "gso.h"

#include <linux/virtio_net.h>
#include <string.h>

#define TCP_FIN 0x01
#define TCP_PSH 0x08
#define TCP_CWR 0x80

static uint16_t rd16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static uint32_t rd32(const uint8_t *p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
	       ((uint32_t)p[2] << 8) | p[3];
}
static void wr16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static void wr32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v >> 24);
	p[1] = (uint8_t)(v >> 16);
	p[2] = (uint8_t)(v >> 8);
	p[3] = (uint8_t)v;
}

/* Internet checksum arithmetic in native byte order (RFC 1071 1.2.B): words
 * are summed as they sit in memory and the result is stored the same way,
 * which comes out right on either endianness and lets the loop read 32 bits
 * at a time. */
static uint64_t sum_bytes(uint64_t sum, const uint8_t *p, size_t len)
{
	while (len >= 4) {
		uint32_t w;

		memcpy(&w, p, 4);
		sum += w;
		p += 4;
		len -= 4;
	}
	if (len >= 2) {
		uint16_t w;

		memcpy(&w, p, 2);
		sum += w;
		p += 2;
		len -= 2;
	}
	if (len) {
		uint8_t last[2] = { p[0], 0 };
		uint16_t w;

		memcpy(&w, last, 2);
		sum += w;
	}
	return sum;
}

/* A 16-bit value given in host order, summed as the two bytes it would be
 * on the wire. */
static uint64_t sum_be16(uint64_t sum, uint16_t v)
{
	uint8_t b[2];
	uint16_t w;

	wr16(b, v);
	memcpy(&w, b, 2);
	return sum + w;
}

static void put_csum(uint8_t *field, uint64_t sum)
{
	uint16_t folded;

	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	folded = (uint16_t)~sum;
	/* 0 and 0xffff are the same sum; UDP reserves 0 for "none" */
	if (!folded)
		folded = 0xffff;
	memcpy(field, &folded, 2);
}

/* Finish a CHECKSUM_PARTIAL packet: the kernel put the pseudo-header sum in
 * the field and left the rest of [start, end) to us. */
static int finish_csum(uint8_t *pkt, size_t len, size_t start, size_t offset)
{
	if (start >= len || offset + 2 > len - start)
		return -1;
	put_csum(pkt + start + offset, sum_bytes(0, pkt + start, len - start));
	return 0;
}

static int split_tcp(uint8_t *pkt, size_t len, size_t thoff, size_t mss,
		     uint8_t *scratch, size_t scratch_len,
		     gso_emit_fn emit, void *arg)
{
	int v6 = (pkt[0] >> 4) == 6;
	size_t hlen, payload, off;
	uint32_t seq;
	uint16_t id;
	uint8_t flags;
	unsigned i;

	if ((!v6 && (pkt[0] >> 4) != 4) || thoff < (v6 ? 40u : 20u) ||
	    thoff + 20 > len)
		return 0;
	hlen = thoff + (size_t)(pkt[thoff + 12] >> 4) * 4;
	if (hlen < thoff + 20 || hlen > len || !mss || hlen + mss > scratch_len)
		return 0;

	payload = len - hlen;
	seq = rd32(pkt + thoff + 4);
	flags = pkt[thoff + 13];
	id = v6 ? 0 : rd16(pkt + 4);

	for (off = 0, i = 0; off < payload; off += mss, i++) {
		size_t n = payload - off < mss ? payload - off : mss;
		size_t total = hlen + n;
		uint8_t *seg = scratch, *tcp = scratch + thoff;
		uint8_t seg_flags = flags;
		uint64_t sum;

		memcpy(seg, pkt, hlen);
		memcpy(seg + hlen, pkt + hlen + off, n);

		if (v6) {
			wr16(seg + 4, (uint16_t)(total - 40));
			sum = sum_bytes(0, seg + 8, 32);            /* addresses */
		} else {
			wr16(seg + 2, (uint16_t)total);
			wr16(seg + 4, (uint16_t)(id + i));
			seg[10] = seg[11] = 0;
			put_csum(seg + 10, sum_bytes(0, seg, (size_t)(seg[0] & 0x0f) * 4));
			sum = sum_bytes(0, seg + 12, 8);            /* addresses */
		}

		/* FIN and PSH belong to the last segment, CWR to the first */
		if (off + n < payload)
			seg_flags &= (uint8_t)~(TCP_FIN | TCP_PSH);
		if (i)
			seg_flags &= (uint8_t)~TCP_CWR;
		wr32(tcp + 4, seq + (uint32_t)off);
		tcp[13] = seg_flags;
		tcp[16] = tcp[17] = 0;
		sum = sum_be16(sum, 6);                             /* protocol */
		sum = sum_be16(sum, (uint16_t)(total - thoff));     /* TCP length */
		put_csum(tcp + 16, sum_bytes(sum, tcp, total - thoff));

		if (emit(arg, seg, total))
			return -1;
	}
	return 0;
}

int gso_split(uint8_t *frame, size_t len, size_t vnet_hdr_len,
	      uint8_t *scratch, size_t scratch_len, gso_emit_fn emit, void *arg)
{
	struct virtio_net_hdr vh;
	uint8_t *pkt = frame + vnet_hdr_len;
	size_t plen;

	if (len < vnet_hdr_len + 20 || vnet_hdr_len < sizeof(vh))
		return 0;
	memcpy(&vh, frame, sizeof(vh));
	plen = len - vnet_hdr_len;

	switch (vh.gso_type & ~VIRTIO_NET_HDR_GSO_ECN) {
	case VIRTIO_NET_HDR_GSO_NONE:
		if ((vh.flags & VIRTIO_NET_HDR_F_NEEDS_CSUM) &&
		    finish_csum(pkt, plen, vh.csum_start, vh.csum_offset))
			return 0;
		return emit(arg, pkt, plen);
	case VIRTIO_NET_HDR_GSO_TCPV4:
	case VIRTIO_NET_HDR_GSO_TCPV6:
		return split_tcp(pkt, plen, vh.csum_start, vh.gso_size,
				 scratch, scratch_len, emit, arg);
	default:
		return 0;   /* not asked for (no UDP segmentation offload) */
	}
}
