#ifndef WARPQ_ROUTE_H
#define WARPQ_ROUTE_H

#define WARPQ_MARK  0x77617271u
#define WARPQ_TABLE 30561u

int route_mark_socket(int fd, unsigned mark);
int route_install(unsigned ifindex, int ipv4, int ipv6);
void route_remove(void);
const char *route_error(void);

#endif
