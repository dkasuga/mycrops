#ifndef _UDP_H_
#define _UDP_H_

#include <stddef.h>
#include <stdint.h>
#include "net.h"
#include "ip.h"

extern ssize_t
udp_tx (struct netif *iface, uint16_t sport, uint8_t *buf, size_t len, ip_addr_t *peer, uint16_t port);

extern int
udp_socket_open (void);
extern int
udp_socket_close (int soc);
extern int
udp_socket_bind (int soc, ip_addr_t addr, uint16_t port);
extern ssize_t
udp_socket_recvfrom (int soc, uint8_t *buf, size_t size, ip_addr_t *peer, uint16_t *port, int timeout);
extern ssize_t
udp_socket_sendto (int soc, uint8_t *buf, size_t len, ip_addr_t *peer, uint16_t port);

extern int
udp_init (void);

#endif
