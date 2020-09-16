#ifndef IP_H
#define IP_H

#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include "net.h"

#define IP_VERSION_IPV4 4

#define IP_PROTOCOL_ICMP 1
#define IP_PROTOCOL_TCP 6
#define IP_PROTOCOL_UDP 17
#define IP_PROTOCOL_RAW 255

#define IP_HDR_SIZE_MIN 20
#define IP_HDR_SIZE_MAX 60

#define IP_PAYLOAD_SIZE_MAX (65535 - IP_HDR_SIZE_MIN)

#define IP_ADDR_LEN 4
#define IP_ADDR_STR_LEN 16 /* "ddd.ddd.ddd.ddd\0" */

typedef uint32_t ip_addr_t;

struct ip_hdr {
    uint8_t vhl;
    uint8_t tos;
    uint16_t len;
    uint16_t id;
    uint16_t offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t sum;
    ip_addr_t src;
    ip_addr_t dst;
    uint8_t options[0];
};

struct netif_ip {
    struct netif netif;
    ip_addr_t unicast;
    ip_addr_t netmask;
    ip_addr_t network;
    ip_addr_t broadcast;
    ip_addr_t gateway;
};

extern const ip_addr_t IP_ADDR_ANY;
extern const ip_addr_t IP_ADDR_BROADCAST;

extern int
ip_addr_pton (const char *p, ip_addr_t *n);
extern char *
ip_addr_ntop (const ip_addr_t *n, char *p, size_t size);

extern struct netif *
ip_netif_alloc (const char *addr, const char *netmask);
extern struct netif *
ip_netif_register (struct netdev *dev, const char *addr, const char *netmask);
extern int
ip_add_protocol (uint8_t protocol, void (*handler)(uint8_t *, size_t, ip_addr_t *, ip_addr_t *, struct netif *));
extern int
ip_init (void);

#endif
