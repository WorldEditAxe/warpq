#ifndef WARPQ_GRO_H
#define WARPQ_GRO_H

#include <stddef.h>
#include <stdint.h>

/* Inbound coalescing for the TUN device.
 *
 * Packets arrive from the tunnel one capsule at a time, and writing each one
 * to the TUN fd makes the kernel carry a separate skb through conntrack, NAT,
 * routing and the bridge -- the single largest cost in the datapath. With
 * IFF_VNET_HDR the kernel accepts one oversized TCP segment plus a virtio
 * header describing how to split it, so a run of consecutive segments from the
 * same flow crosses all of that once instead of dozens of times.
 *
 * Non-TCP traffic, and anything that cannot be joined to the run in progress,
 * is written straight through, so correctness never depends on coalescing. */

struct gro;

/* vnet_hdr_len is 0 when the device has no virtio header, in which case every
 * packet is written through untouched. */
struct gro *gro_new(int tun_fd, size_t vnet_hdr_len, size_t mtu);
void gro_free(struct gro *g);

/* Queue one inner IP packet. Returns -1 only on a write error. */
int gro_push(struct gro *g, const uint8_t *packet, size_t len);

/* Emit whatever is still held. Call once per batch of capsules. */
int gro_flush(struct gro *g);

#endif
