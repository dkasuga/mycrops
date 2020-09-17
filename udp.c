#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <limits.h>
#include <pthread.h>
#include "util.h"
#include "arp.h"
#include "ip.h"
#include "icmp.h"

struct udp_hdr {
    uint16_t sport;
    uint16_t dport;
    uint16_t len;
    uint16_t cksum;
};

struct pseudo_hdr {
    uint32_t src;
    uint32_t dst;
    uint8_t zero;
    uint8_t protocol;
    uint16_t len;
};



void
udp_dump(uint8_t *packet, size_t plen){ // arp_dumpを参考に
    struct udp_hdr *hdr;

    hdr = (struct udp_hdr *)packet;
    fprintf(stderr, "sport: %u\n", ntoh16(hdr->sport)); // 符号なし10進数に変換
    fprintf(stderr, "dport: %u\n", ntoh16(hdr->dport));
    fprintf(stderr, "len: %u\n", ntoh16(hdr->len));
    fprintf(stderr, "cksum: 0x%04x\n", ntoh16(hdr->cksum)); // 16進数のまま
    hexdump(stderr, packet, plen);
}

static void
udp_rx(uint8_t *packet, size_t plen, ip_addr_t *src, ip_addr_t *dst, struct netif *netif){
    struct udp_hdr *hdr;
    struct pseudo_hdr phdr;
    uint16_t psum;
    
    // UDPパケットの検証
    if(plen < sizeof(struct udp_hdr)){
        return;
    }
    hdr = (struct udp_hdr *)packet;

    phdr.src = *src; //ip_addr_tの中身はnetwork byteorderにしておく
    phdr.dst = *dst;
    phdr.zero = 0;
    phdr.protocol = IP_PROTOCOL_UDP;
    phdr.len = hton16((uint16_t)plen);

    // チェックサムの検証
    if(hdr->cksum){ // チェックサムに0が設定されていたら検証スキップ
        psum = ~cksum16((uint16_t *)&phdr, sizeof(struct pseudo_hdr), 0);
        if(cksum16((uint16_t *)hdr, plen, psum) != 0){
                fprintf(stderr, "udp checksum error.\n");
                return;
            }
    }

    // udp_dump()を呼び出してパケットの内容を出力
#ifdef DEBUG
    fprintf(stderr, ">>> udp_rx <<<\n");
    udp_dump(packet, plen);
#endif

    return;
}

int
udp_init(void){
    ip_add_protocol(IP_PROTOCOL_UDP, udp_rx);
    return 0;
}

