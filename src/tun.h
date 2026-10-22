#ifndef WARPQ_TUN_H
#define WARPQ_TUN_H

#include <stddef.h>

int tun_open(char *name, size_t name_len);
/* Open one queue of a multi-queue TUN device. The first call creates the
 * device, every later call with the same name attaches another queue to it.
 * The kernel hashes flows across the queues, so a packet's flow always comes
 * back out of the same queue and per-flow ordering is kept. */
/* vnet_hdr_len, when not NULL, asks for IFF_VNET_HDR and reports the virtio
 * header size the device ended up using -- 0 if the kernel would not give it,
 * in which case packets are written one at a time as before. */
int tun_open_queue(char *name, size_t name_len, size_t *vnet_hdr_len);
int tun_set_mtu(const char *name, int mtu);
int tun_set_ipv4(const char *name, const char *addr);
int tun_set_ipv6(const char *name, const char *addr);
int tun_set_up(const char *name);
int tun_index(const char *name);
int tun_nonblocking(int fd);
const char *tun_error(void);

#endif
