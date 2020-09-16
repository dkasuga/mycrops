#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "util.h"
#include "net.h"
#include "ip.h"
#include "icmp.h"

struct icmp_hdr {
    uint8_t type;
    uint8_t code;
    uint16_t sum;
    uint32_t spec;
};

struct icmp_echo {
    uint8_t type;
    uint8_t code;
    uint16_t sum;
    uint16_t id;
    uint16_t seq;
};

#define ICMP_BUFSIZ IP_PAYLOAD_SIZE_MAX

static char *
icmp_type_ntoa(uint8_t type){
    switch (type) {
        case ICMP_TYPE_ECHOREPLY:
            return "Echo Reply";
        case ICMP_TYPE_DEST_UNREACH:
            return "Destination Unreachable";
        case ICMP_TYPE_SOURCE_QUENCH:
            return "Source Quench";
        case ICMP_TYPE_REDIRECT:
            return "Redirect";
        case ICMP_TYPE_ECHO:
            return "Echo";
        case ICMP_TYPE_TIME_EXCEEDED:
            return "Time Exceeded";
        case ICMP_TYPE_PARAM_PROBLEM:
            return "Parameter Problem";
        case ICMP_TYPE_TIMESTAMP:
            return "Timestamp";
        case ICMP_TYPE_TIMESTAMPREPLY:
            return "timestamp Reply";
        case ICMP_TYPE_INFO_REQUEST:
            return "Information Request";
        case ICMP_TYPE_INFO_REPLY:
            return "Information Reply";
    }
    return "UNKNOWN";
}

void
icmp_dump(struct netif *netif, ip_addr_t *src, ip_addr_t *dst, uint8_t *packet, size_t plen){
    struct netif_ip *iface;
    char addr[IP_ADDR_STR_LEN];
    struct icmp_hdr *hdr;
    struct icmp_echo *echo;

    iface = (struct netif_ip *)netif;
    fprintf(stderr, "   dev: %s (%s)\n", netif->dev->name, ip_addr_ntop(&iface->unicast, addr, sizeof(addr)));
    fprintf(stderr, "   src: %s\n", src ? ip_addr_ntop(src, addr, sizeof(addr)) : "(self)");
    fprintf(stderr, "   dst: %s\n", ip_addr_ntop(dst, addr, sizeof(addr)));
    hdr = (struct icmp_hdr *)packet;
    fprintf(stderr, "  type: %u (%s)\n", hdr->type, icmp_type_ntoa(hdr->type));
    fprintf(stderr, "  code: %u\n", hdr->code);
    fprintf(stderr, "   sum: 0x%04x\n", ntoh16(hdr->sum));
    switch (hdr->type) {
    case ICMP_TYPE_ECHOREPLY:
    case ICMP_TYPE_ECHO:
        echo = (struct icmp_echo *)hdr;
        fprintf(stderr, "    id: %u\n", ntoh16(echo->id));
        fprintf(stderr, "   seq: %u\n", ntoh16(echo->seq));
        break;
    default:
        fprintf(stderr, "  spec: 0x%08x\n", ntoh32(hdr->spec));
        break;
    }
    hexdump(stderr, packet, plen);
}

static void
icmp_rx(uint8_t *packet, size_t plen, ip_addr_t *src, ip_addr_t *dst, struct netif *netif){
    struct icmp_hdr *hdr;

    (void)dst;
    if(plen < sizeof(struct icmp_hdr)){
        return;
    }
    hdr = (struct icmp_hdr *)packet;
    /* your code here: ICMPヘッダの検証（チェックサムの検証）*/
    /* The checksum is the 16-bit ones's complement of the one's
      complement sum of the ICMP message starting with the ICMP Type. */
    // icmpのcheksumの範囲はmessage全体
    if(cksum16((uint16_t *)hdr, plen, 0) != 0){
        fprintf(stderr, "icmp checksum error.\n");
        return;
    }

#ifdef DEBUG
    fprintf(stderr, ">>> icmp_rx <<<\n");
    icmp_dump(netif, src, dst, packet, plen);
#endif
    switch(hdr->type){
        case ICMP_TYPE_ECHO:
            /* your code here: icmp_tx を使って EchoReply を送信 */
            icmp_tx(netif, ICMP_TYPE_ECHOREPLY, hdr->code, hdr->spec, (uint8_t *)(hdr+1), plen - sizeof(struct icmp_hdr), src);
            break;
    }
}

int
icmp_tx (struct netif *netif, uint8_t type, uint8_t code, uint32_t spec, uint8_t *data, size_t len, ip_addr_t *dst){
    uint8_t buf[ICMP_BUFSIZ];
    struct icmp_hdr *hdr;
    size_t msg_len;

    hdr = (struct icmp_hdr *)buf;
    hdr->type = type;
    hdr->code = code;
    hdr->sum = 0;
    hdr->spec = spec;
    memcpy(hdr+1, data, len);
    msg_len = sizeof(struct icmp_hdr) + len;
    hdr->sum = cksum16((uint16_t *)hdr, msg_len, 0); //msg_lenではなくsizeof(struct icmp_hdr)では？
#ifdef DEBUG
    fprintf(stderr, ">>> icmp_tx <<<\n");
    icmp_dump(netif, NULL, dst, (uint8_t *)hdr, msg_len);
#endif
    return ip_tx(netif, IP_PROTOCOL_ICMP, (uint8_t *)hdr, msg_len, dst);
}

int
icmp_init (void){
    ip_add_protocol(IP_PROTOCOL_ICMP, icmp_rx);
    return 0;
}
