#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include "net.h"
#include "arp.h"
#include "util.h"

#define ARP_HRD_ETHERNET 0x0001

#define ARP_OP_REQUEST 1
#define ARP_OP_REPLY   2

#define ARP_TABLE_SIZE 4096
#define ARP_TABLE_TIMEOUT_SEC 300

struct arp_hdr {
    uint16_t hrd;
    uint16_t pro;
    uint8_t hln;
    uint8_t pln;
    uint16_t op;
};

struct arp_ethernet {
    struct arp_hdr hdr;
    uint8_t sha[ETHERNET_ADDR_LEN];
    ip_addr_t spa; // typedef ip_addr_t uint32_t
    uint8_t tha[ETHERNET_ADDR_LEN];
    ip_addr_t tpa; // typedef ip_addr_t uint32_t
} __attribute__ ((packed)); // 上のようにするとコンパイラに怒られるかもしれないのでこれで避ける

// arp tableに登録するentry
struct arp_entry {
    unsigned char used;
    ip_addr_t pa;
    uint8_t ha[ETHERNET_ADDR_LEN];
    time_t timestamp;
};

static struct arp_entry arp_table[ARP_TABLE_SIZE];
static time_t timestamp;
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

// なぜわざわざ？そのままではだめなのか？
static char *
arp_opcode_ntop (uint16_t opcode){
    switch (ntoh16(opcode)) {
        case ARP_OP_REQUEST:
            return "REQUEST";
        case ARP_OP_REPLY:
            return "REPLY";
    }
    return "UNKNOWN";
}

void 
arp_dump (uint8_t *packet, size_t plen) {
    struct arp_ethernet *message;
    char addr[128];


    message = (struct arp_ethernet *)packet;
    fprintf(stderr, " hrd: 0x%04x\n", ntoh16(message->hdr.hrd));
    fprintf(stderr, " pro: 0x%04x\n", ntoh16(message->hdr.pro));
    fprintf(stderr, " hln: %u\n", message->hdr.hln);
    fprintf(stderr, " pln: %u\n", message->hdr.pln);
    fprintf(stderr, "  op: %u (%s)\n", ntoh16(message->hdr.op), arp_opcode_ntop(message->hdr.op));
    fprintf(stderr, " sha: %s\n", ethernet_addr_ntop(message->sha, addr, sizeof(addr)));
    fprintf(stderr, " spa: %s\n", ip_addr_ntop(&message->spa, addr, sizeof(addr)));
    fprintf(stderr, " tha: %s\n", ethernet_addr_ntop(message->tha, addr, sizeof(addr)));
    fprintf(stderr, " tpa: %s\n", ip_addr_ntop(&message->tpa, addr, sizeof(addr)));
    hexdump(stderr, packet, plen);
}

// 登録されているかどうかを線形探索
static struct arp_entry *
arp_table_select (const ip_addr_t *pa){
    struct arp_entry *entry;

    for(entry = arp_table; entry < array_tailof(arp_table); entry++){
        if(entry->used && entry->pa == *pa){
            return entry;
        }
    }
    return NULL;
}

// 既に存在するentryを更新 (IP addressで検索してMACアドレスを更新)
static int 
arp_table_update (const ip_addr_t *pa, const uint8_t *ha) {
    struct arp_entry *entry;

    entry = arp_table_select(pa);
    if(!entry) {
        return -1;
    }

    memcpy(entry->ha, ha, ETHERNET_ADDR_LEN);
    time(&entry->timestamp);
    return 0;
}

// 前から見ていって空のentryを返す
static struct arp_entry *
arp_table_freespace(void) {
    struct arp_entry *entry;

    for (entry = arp_table; entry < array_tailof(arp_table); entry++){
        if(!entry->used){
            return entry;
        }
    }
    return NULL;
}

// 空のentryに新規に登録
static int
arp_table_insert (const ip_addr_t *pa, const uint8_t *ha) {
    struct arp_entry *entry;

    entry = arp_table_freespace();
    if(!entry) {
        return -1;
    }
    entry->used = 1;
    entry->pa = *pa; // uint32_tの塊1つなので，この代入が可能
    memcpy(entry->ha, ha, ETHERNET_ADDR_LEN); //uint8_tの配列なので，memcpyで
    time(&entry->timestamp);
    return 0;
}

static void
arp_entry_clear (struct arp_entry *entry) {
    entry->used = 0;
    entry->pa = 0;
    memset(entry->ha, 0, ETHERNET_ADDR_LEN);
    entry->timestamp = 0;
}

static void
arp_table_patrol(void) {
    struct arp_entry *entry;

    for(entry = arp_table; entry < array_tailof(arp_table); entry++){
        if(entry->used && timestamp - entry->timestamp > ARP_TABLE_TIMEOUT_SEC){
            arp_entry_clear(entry);
        }
    }
}

// このIPアドレスに対応するMACアドレスはなんですか
static int
arp_send_request(struct netif *netif, const ip_addr_t *tpa){
    struct arp_ethernet request;
    
    if(!tpa) {
        return -1;
    }
    request.hdr.hrd = hton16(ARP_HRD_ETHERNET);
    request.hdr.pro = hton16(ETHERNET_TYPE_IP);
    request.hdr.hln = ETHERNET_ADDR_LEN;
    request.hdr.pln = IP_ADDR_LEN;
    request.hdr.op = hton16(ARP_OP_REQUST);
    memcpy(request.sha, netif->dev->addr, ETHERNET_ADDR_LEN);
    request.spa = ((struct netif_ip *)netif)->unicast;
    memset(request.tha, 0, ETHERNET_ADDR_LEN);
    request.tpa = *tpa;
#ifdef DEBUG
    fprintf(stderr, ">>> arp_send_request <<<\n");
    arp_dump((uint8_t *)&request, sizeof(request));
#endif 
    if(netif->dev->ops->tx(netif->dev, ETHERNET_TYPE_ARP, (uint8_t *)&request, sizeof(request), ETHERNET_ADDR_BROADCAST) == -1){
        return -1;
    }
    return 0;
}


// IPアドレスに対応するMACアドレスを教える
static int
arp_send_reply (struct netif *netif, const uint8_t *tha, const ip_addr_t *tpa, const uint8_t *dst){
    struct arp_ethernet reply;

    if(!tha || !tpa){
        return -1;
    }

    reply.hdr.hrd = hton16(ARP_HRD_ETHERNET);
    reply.hdr.pro = hton16(ETHERNET_TYPE_IP);
    reply.hdr.hln = ETHERNET_ADDR_LEN;
    reply.hdr.pln = IP_ADDR_LEN;
    reply.hdr.op = hton16(ARP_OP_REPLY);
    memcpy(reply.sha, netif->dev->addr, ETHERNET_ADDR_LEN);
    reply.spa = ((struct netif_ip *)netif)->unicast;
    memcpy(reply.tha, tha, ETHERNET_ADDR_LEN);
    reply.tpa = *tpa;
#ifdef DEBUG
    fprintf(stderr, ">>> arp_send_reply <<<\n");
    arp_dump((uint8_t *)&reply, sizeof(reply));
#endif
    if (netif->dev->ops->tx(netif->dev, ETHERNET_TYPE_ARP, (uint8_t *)&reply, sizeof(reply), dst) < 0){
        return -1;
    }
    return 0;
}

static void
arp_rx (uint8_t *packet, size_t plen, struct netdev *dev){
    struct arp_ethernet *message;
    time_t now;
    int merge = 0;
    struct netif *netif;

    if(plen < sizeof(struct arp_ethernet)) {
        return;
    }
    message = (struct arp_ethernet *)packet;
    /* your code here: ヘッダの検証　*/
    if(!message->hdr->hrd) { // ?Do I have the hardware type in ar$hrd?
        return;
    }
#ifdef DEBUG
    fprintf(stderr, ">>> arp_rx <<<\n");
    arp_dump(packet, plen);
#endif
    pthread_mutex_lock(&mutex);
    time(&now);
    if (now - timestamp > 10) {
        timestamp = now;
        arp_table_patrol();
    }
    /* 
        If the pair <protocol type, sender protocol address> is
        already in my translation table, update the sender
        hardware address field of the entry with the new
        information in the packet and set Merge_flag to true.
    */
    merge = (arp_table_update(&message->spa, message->sha) == 0) ? 1 : 0; // == 0ならmerge

    pthread_mutex_unlock(&mutex);
    netif = netdev_get_netif(dev, NETIF_FAMILY_IPV4);
    if (netif && ((struct netif_ip *)netif)->unicast == message->tpa) {
        /*
          If Merge_flag is false, add the triplet <protocol type,
          sender protocol address, sender hardware address> to
          the translation table.
        */
        if (!merge) {
            pthread_mutex_lock(&mutex);
            /* your code here: ARPテーブルへのinsert */
            arp_table_insert(&message->spa, message->sha);
            pthread_mutex_unlock(&mutex);
        }

        /*
            Send the packet to the (new) target hardware address on
            the same hardware on which the request was received.
        */
        if (ntoh16(message->hdr.op) == ARP_OP_REQUEST) { // requestじゃないことなんてあるのか？
            /* your code here: ARPリプライの送信 */
            arp_send_reply(netif, message->sha, &message->spa, &message->spa);
        }
    }
    return;
}









