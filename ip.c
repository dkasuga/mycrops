#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <limits.h>
#include <pthread.h>
#include "util.h"
#include "arp.h"
#include "ip.h"

// ipv4 or ipv6
struct ip_protocol {
    struct ip_protocol *next;
    uint8_t type;
    void (*handler)(uint8_t *payload, size_t len, ip_addr_t *src, ip_addr_t *dst, struct netif *netif);
};

static void
ip_rx (uint8_t *dgram, size_t dlen, struct netdev *dev);

static struct ip_protocol *protocols;

const ip_addr_t IP_ADDR_ANY = 0x00000000;
const ip_addr_t IP_ADDR_BROADCAST = 0xffffffff;

int
ip_addr_pton (const char *p, ip_addr_t *n) {
    char *sp, *ep;
    int idx;
    long ret;

    sp = (char *)p;
    for (idx = 0; idx < 4; idx++) {
        ret = strtol(sp, &ep, 10);
        if (ret < 0 || ret > 255) {
            return -1;
        }
        if (ep == sp) {
            return -1;
        }
        if ((idx == 3 && *ep != '\0') || (idx != 3 && *ep != '.')) {
            return -1;
        }
        ((uint8_t *)n)[idx] = ret;
        sp = ep + 1;
    }
    return 0;
}

char *
ip_addr_ntop (const ip_addr_t *n, char *p, size_t size) {
    uint8_t *ptr;

    ptr = (uint8_t *)n;
    snprintf(p, size, "%d.%d.%d.%d",
        ptr[0], ptr[1], ptr[2], ptr[3]);
    return p;
}

void
ip_dump (struct netif *netif, uint8_t *packet, size_t plen) {
    struct netif_ip *iface;
    char addr[IP_ADDR_STR_LEN];
    struct ip_hdr *hdr;
    uint8_t hl;
    uint16_t offset;

    iface = (struct netif_ip *)netif;
    fprintf(stderr, " dev: %s (%s)\n", netif->dev->name, ip_addr_ntop(&iface->unicast, addr, sizeof(addr)));
    hdr = (struct ip_hdr *)packet;
    hl = hdr->vhl & 0x0f;
    fprintf(stderr, "      vhl: %02x [v: %u, hl: %u (%u)]\n", hdr->vhl, (hdr->vhl & 0xf0) >> 4, hl, hl << 2);
    fprintf(stderr, "      tos: %02x\n", hdr->tos);
    fprintf(stderr, "      len: %u\n", ntoh16(hdr->len));
    fprintf(stderr, "       id: %u\n", ntoh16(hdr->id));
    offset = ntoh16(hdr->offset);
    fprintf(stderr, "   offset: 0x%04x [flags=%x, offset=%u]\n", offset, (offset & 0xe000) >> 13, offset & 0x1fff);
    fprintf(stderr, "      ttl: %u\n", hdr->ttl);
    fprintf(stderr, " protocol: %u\n", hdr->protocol);
    fprintf(stderr, "      sum: 0x%04x\n", ntoh16(hdr->sum));
    fprintf(stderr, "      src: %s\n", ip_addr_ntop(&hdr->src, addr, sizeof(addr)));
    fprintf(stderr, "      dst: %s\n", ip_addr_ntop(&hdr->dst, addr, sizeof(addr)));
    hexdump(stderr, packet, plen);
}

/*
 * IP INTERFACE
 * */
struct netif *
ip_netif_alloc(const char *addr, const char *netmask) {
    struct netif_ip *iface;

    if (!addr || !netmask) {
        return NULL;
    }
    iface = malloc(sizeof(struct netif_ip));
    if (!iface) {
        return NULL;
    }
    ((struct netif *)iface)->next = NULL;
    ((struct netif *)iface)->family = NETIF_FAMILY_IPV4;
    ((struct netif *)iface)->dev = NULL;
    if(ip_addr_pton(addr, &iface->unicast) == -1){
        free(iface);
        return NULL;
    }
    if(ip_addr_pton(netmask, &iface->netmask) == -1) {
        free(iface);
        return NULL;
    }
    /* your code here: ネットワークアドレスを計算で求めて iface->network に設定 */
    iface->network = iface->unicast & iface->netmask;
    
    /* your code here: ネットワークのブロードキャストアドレスを計算で求めて iface->broadcast に設定 */
    iface->broadcast = iface->network | ~iface->netmask;

    return (struct netif *)iface;
}

struct netif *
ip_netif_register (struct netdev *dev, const char *addr, const char *netmask) {
    struct netif *netif;

    netif = ip_netif_alloc(addr, netmask);
    if(!netif) {
        return NULL;
    }
    if(netdev_add_netif(dev, netif) == -1) {
        free(netif);
        return NULL;
    }
    return netif;
}

/*
 * IP CORE
 */

static void
ip_rx (uint8_t *dgram, size_t dlen, struct netdev *dev){
    struct ip_hdr *hdr;
    uint16_t hlen, offset;
    struct netif_ip *iface;
    uint8_t *payload;
    size_t plen;
    struct ip_protocol *protocol;

    // data gramの長さは少なくともip_hdr以上
    if (dlen < sizeof(struct ip_hdr)) {
        return;
    }
    hdr = (struct ip_hdr *)dgram;
    /* your code here: IPヘッダの検証 */
    /* 1. IPバージョンの検証*/
    if((hdr->vhl >> 4) != IP_VERSION_IPV4){
        return;
    }
    /* 2. ヘッダ長を検証（hlen に格納）*/
    hlen = (hdr->vhl & 0x0f) << 2; // hlenはbyteでの長さ 32bitは4byte IHLは32bit単位で大きさが格納されている
    if(hlen > dlen) {
        return;
    }
    /* 3. パケットのトータル長を検証 */
    if(ntoh16(hdr->len) > dlen){
        return;
    }
    /* 4. TTLの検証 */
    if(!hdr->ttl){
        return;
    }


    if(cksum16((uint16_t *)hdr, hlen, 0) != 0) {
        fprintf(stderr, "ip checksum error.\n");
        return;
    }
    iface = (struct netif_ip *)netdev_get_netif(dev, NETIF_FAMILY_IPV4);
    if (!iface){
        fprintf(stderr, "ip unknown interface.\n");
        return;
    }
    // 自分のところに届いたものかどうか
    if(hdr->dst != iface->unicast) {
        if(hdr->dst != iface->broadcast && hdr->dst != IP_ADDR_BROADCAST){ // broadcastできたもの
            return;
        }
    }
#ifdef DEBUG
    fprintf(stderr, ">>> ip_rx <<<\n");
    ip_dump((struct netif *)iface, dgram, dlen);
#endif

    // CHECK: よくわかっていない
    offset = ntoh16(hdr->offset);
    if(offset & 0x2000 || offset & 0x1fff){
        // fragments does not support
        return;
    }
    /* your code here: payload と plen に正しく値を設定*/
    payload = (uint8_t *)hdr + hlen;
    plen = (size_t)(ntoh16(hdr->len) - hlen);

    for(protocol = protocols; protocol; protocol=protocol->next) {
        if(protocol->type == hdr->protocol) {
            protocol->handler(payload, plen, &hdr->src, &hdr->dst, (struct netif *)iface);
            break;
        }
    }
}

int
ip_add_protocol (uint8_t type, void (*handler)(uint8_t *payload, size_t len, ip_addr_t *src, ip_addr_t *dst, struct netif *netif)){
    struct ip_protocol *p;

    for(p=protocols; p; p=p->next){
        if(p->type == type){ // 既存
            return -1;
        }
    }
    p = malloc(sizeof(struct ip_protocol));
    if(!p){
        return -1;
    }
    p->next = protocols;
    p->type = type;
    p->handler = handler;
    protocols = p;
    return 0;
}

int
ip_init (void) {
    netdev_proto_register(NETDEV_PROTO_IP, ip_rx);
    return 0;
}
