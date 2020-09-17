#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <limits.h>
#include <pthread.h>
#include "util.h"
#include "arp.h"
#include "ip.h"

#define IP_ROUTE_TABLE_SIZE 8

// ipv4 or ipv6
struct ip_protocol {
    struct ip_protocol *next;
    uint8_t type;
    void (*handler)(uint8_t *payload, size_t len, ip_addr_t *src, ip_addr_t *dst, struct netif *netif);
};

struct ip_route {
    uint8_t used;
    ip_addr_t network;
    ip_addr_t netmask;
    ip_addr_t nexthop;
    struct netif_ip *iface;
};

static struct ip_route route_table[IP_ROUTE_TABLE_SIZE];

static void
ip_rx (uint8_t *dgram, size_t dlen, struct netdev *dev);

static struct ip_protocol *protocols;

const ip_addr_t IP_ADDR_ANY = 0x00000000;
const ip_addr_t IP_ADDR_BROADCAST = 0xffffffff;

/*
 * IP ROUTING
 */

static int
ip_route_add (ip_addr_t network, ip_addr_t netmask, ip_addr_t nexthop, struct netif_ip *iface){
    struct ip_route *route;

    for(route = route_table; route < array_tailof(route_table); route++){
        if(!route->used){
            route->used = 1;
            route->network = network;
            route->netmask = netmask;
            route->nexthop = nexthop;
            route->iface = iface;
            return 0;
        }
    }
    return -1;
}

static int
ip_route_del (struct netif_ip *iface){
    struct ip_route *route;

    for(route = route_table; route < array_tailof(route_table); route++){
        if(route->used){
            if(route->iface == iface){
                route->used = 0;
                route->network = IP_ADDR_ANY;
                route->netmask = IP_ADDR_ANY;
                route->nexthop = IP_ADDR_ANY;
                route->iface = NULL;
            }
        }
    }
    return 0;
}

static struct ip_route *
ip_route_lookup (const struct netif_ip *iface, const ip_addr_t *dst){
    struct ip_route *route, *candidate = NULL;

    for(route = route_table; route < array_tailof(route_table); route++){
        if(route->used && (*dst & route->netmask) == route->network && (!iface || route->iface == iface)) { // ifaceが設定されていない場合もある
            if(!candidate || ntoh32(candidate->netmask) < ntoh32(route->netmask)){ // longest match
                candidate = route;
            }
        }
    }
    return candidate;
}

int
ip_set_default_gateway (struct netif_ip *iface, const char *gateway){
    ip_addr_t gw;

    if(ip_addr_pton(gateway, &gw) == -1){
        return -1;
    }
    if(ip_route_add(IP_ADDR_ANY, IP_ADDR_ANY, gw, iface) == -1){
        return -1;
    }
    return 0;
}

struct netif *
ip_netif_by_addr (const ip_addr_t *addr){
    struct netdev *dev;
    struct netif *entry;

    for(dev = netdev_root(); dev; dev=dev->next){
        for(entry = dev->ifs; entry; entry = entry->next){
            if(entry->family == NETIF_FAMILY_IPV4 && ((struct netif_ip *)entry)->unicast == *addr){
                return entry;
            }
        }
    }
    return NULL;
}

// ルーティングテーブルから
struct netif *
ip_netif_by_peer(const ip_addr_t *peer){
    struct ip_route *route;

    route = ip_route_lookup(NULL, peer);
    if(!route) {
        return NULL;
    }
    return (struct netif *)route->iface;
}

static int
ip_tx_netdev (struct netif_ip *iface, uint8_t *packet, size_t plen, const ip_addr_t *nexthop){
    ssize_t ret;
    uint8_t ha[128] = {};
    struct netif *netif;

    netif = &iface->netif;
    if(!(netif->dev->flags & NETDEV_FLAG_NOARP)){ // CHECK ?? 
        if(*nexthop == iface->broadcast || *nexthop == IP_ADDR_BROADCAST){
            memcpy(ha, netif->dev->broadcast, netif->dev->alen); // BROADCASTのMACアドレス？
        } else {
            ret = arp_resolve(netif, nexthop, (void *)ha); // haにnexthopのMACアドレスを入れる
            if(ret != ARP_RESOLVE_FOUND){
                return ret;
            }
        }
    }
    if(netif->dev->ops->tx(netif->dev, ETHERNET_TYPE_IP, packet, plen, (void *)ha) != (ssize_t)plen) {
        return -1;
    }
    return 1;
}

static int
ip_tx_core(struct netif_ip *iface, uint8_t protocol, const uint8_t *buf, size_t len, const ip_addr_t *src, const ip_addr_t *dst, const ip_addr_t *nexthop, uint16_t id, uint16_t offset){
    uint8_t packet[4096];
    struct ip_hdr *hdr;
    uint16_t hlen;

    hdr = (struct ip_hdr *)packet;

    /* your code here: IPヘッダの生成 */
    hlen = sizeof(struct ip_hdr); // これでいいのか？ optionの考慮は？
    hdr->vhl = (IP_VERSION_IPV4 << 4) | (hlen >> 2);
    hdr->tos = 0;// ??
    hdr->len = hton16(hlen + (uint16_t)len);
    hdr->id = hton16(id);
    hdr->offset = hton16(offset);
    hdr->ttl = 0xff;// ?? Thus, the maximum time to live is 255 seconds or 4.25 minutes. 

    hdr->protocol = protocol;
    hdr->sum = 0;
    hdr->src = src ? *src : iface->unicast;
    hdr->dst = *dst;
    hdr->sum = cksum16((uint16_t *)hdr, hlen, 0);
    memcpy(hdr + 1, buf, len);
#ifdef DEBUG
    fprintf(stderr, ">>> ip_tx_core <<<\n");
    ip_dump((struct netif *)iface, (uint8_t *)packet, hlen + len);
#endif
    return ip_tx_netdev(iface, packet, hlen+len, nexthop);
}

static uint16_t
ip_generate_id (void) {
    static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
    static uint16_t id = 128;
    uint16_t ret;

    pthread_mutex_lock(&mutex);
    ret = id++;
    pthread_mutex_unlock(&mutex);
    return ret;
}
ssize_t
ip_tx(struct netif *netif, uint8_t protocol, const uint8_t *buf, size_t len, const ip_addr_t *dst){
    struct ip_route *route;
    struct netif_ip *iface;
    const ip_addr_t *nexthop = NULL, *src = NULL;
    uint16_t id;

    route = ip_route_lookup(NULL, dst);
    if(!route) {
        fprintf(stderr, "ip no route to host.\n");
        return -1;
    }
    if(netif) {
        // origin source address
        src = &((struct netif_ip *)netif)->unicast;
    }
    iface = route->iface;
    // CHECK:
    // mtu: maximum transmission unit: ノードが隣接したネットワークへ，一回の通信で転送可能な最大のデータグラムサイズ
    if (len > (size_t)(((struct netif *)iface)->dev->mtu - IP_HDR_SIZE_MIN)) {
        // flagmentation does not support
        return -1;
    }
    nexthop = route->nexthop ? &route->nexthop : dst;
    id = ip_generate_id(); // 固有のid
    if (ip_tx_core(iface, protocol, buf, len, src, dst, nexthop, id, 0) == -1){
        return -1;
    }
    return len;
}

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

    // 直結のルートを自動生成
    if(ip_route_add(iface->network, iface->netmask, IP_ADDR_ANY, iface) == -1){
        free(iface);
        return NULL;
    }

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
    offset = ntoh16(hdr->offset); // fragmentsの16bit全体
    if(offset & 0x2000 || offset & 0x1fff){ // 0x2000は前から3bit目
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


