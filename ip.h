#ifndef IP_H
#define IP_H

#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include "net.h"

#define IP_VERSION_IPV4 4

#define IP_ADDR_LEN 4
#define IP_ADDR_STR_LEN 16 /* "ddd.ddd.ddd.ddd\0" */

typedef uint32_t ip_addr_t;

struct netif_ip {
    struct netif netif;
    ip_addr_t unicast;
    ip_addr_t netmask;
    ip_addr_t network;
    ip_addr_t broadcast;
    ip_addr_t gateway;
};

extern int
ip_addr_pton (const char *p, ip_addr_t *n);
extern char *
ip_addr_ntop (const ip_addr_t *n, char *p, size_t size);

#endif
