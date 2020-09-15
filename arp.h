#ifdef _ARP_H_
#define _ARP_H_

#include <stdio.h>
#include "net.h"
#include "ip.h"

#define ARP_RESOLVE_ERROR -1
#define ARP_RESOLVE_QUERY  0
#define ARP_RESOLVE_FOUND  1

extern int 
arp_init(void);

extern int
arp_resolve(struct netif *netif, const ip_addr_t *pa, uint8_t *ha);

#endif
