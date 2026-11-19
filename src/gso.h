#ifndef WARPQ_GSO_H
#define WARPQ_GSO_H

#include <stddef.h>
#include <stdint.h>

/* Outbound segmentation for the TUN device -- the mirror of gro.h.
 *
 * With TSO turned on for the device (see tun_open_queue), the kernel hands
 * over a TCP flow's data as segments of up to 64 KiB plus a virtio header
 * saying how to cut them, instead of one MTU-sized packet per read(). That is
 * one read and one wakeup of the TLS thread per 64 KiB rather than per 1.2
 * KiB, and the TLS thread gets enough at once to fill whole records. The
 * endpoint still wants plain IP packets, so they are cut back to size here,
 * with the checksums the kernel left for us to finish. */

/* Called once per finished IP packet. Returns -1 to stop. */
typedef int (*gso_emit_fn)(void *arg, const uint8_t *packet, size_t len);

/* frame/len is what one read() on a TUN fd with a vnet_hdr_len-byte virtio
 * header returned. scratch must hold one finished packet (an MTU's worth).
 * Malformed frames are dropped. Returns -1 only if emit did. */
int gso_split(uint8_t *frame, size_t len, size_t vnet_hdr_len,
	      uint8_t *scratch, size_t scratch_len, gso_emit_fn emit, void *arg);

#endif
