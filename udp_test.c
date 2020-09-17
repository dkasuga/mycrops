#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include "raw.h"
#include "ethernet.h"
#include "net.h"
#include "arp.h"
#include "ip.h"
#include "icmp.h"
#include "udp.h"
#include "util.h"

volatile sig_atomic_t terminate;

static void
on_signal (int s) {
    terminate = 1;
}

static void
init(void){
    ethernet_init();
    arp_init();
    ip_init();
    icmp_init();
    udp_init();
}

static int
setup (char *ifname, char *hwaddr, char *ipaddr, char *netmask){
    struct netdev *dev;
    struct netif *netif;

    init();
    dev = netdev_alloc(NETDEV_TYPE_ETHERNET);
    if(!dev){
        return -1;
    }
    strncpy(dev->name, ifname, sizeof(dev->name)-1);
    if(hwaddr){
        ethernet_addr_pton(hwaddr, dev->addr);
    }
    if(dev->ops->open(dev, RAWDEV_TYPE_TAP) == -1){
        return -1;
    }
    netif = ip_netif_register(dev, ipaddr, netmask);
    if(!netif){
        fprintf(stderr, "ip_netif_register(): error\n");
        return -1;
    }
    dev->ops->run(dev);
    return 0;
}

int
main (int argc, char *argv[]){
    char *ifname, *hwaddr = NULL, *ipaddr, *netmask;
    int soc = -1, ret;
    uint8_t buf[65535];
    ip_addr_t peer_addr;
    uint16_t port, peer_port;
    char addr[IP_ADDR_STR_LEN];

    signal(SIGINT, on_signal);
    switch(argc){
        case 6:
            hwaddr = argv[2];
            // fall through
        case 5:
            ifname = argv[1];
            ipaddr = argv[argc-3];
            netmask = argv[argc-2];
            port = hton16(strtol(argv[argc-1], NULL, 10));
            break;
        default:
            fprintf(stderr, "usage: %s interface [mac_address] ip_address netmask port\n", argv[0]);
            return -1;
    }
    if(setup(ifname, hwaddr, ipaddr, netmask) == -1){
        fprintf(stderr, "setup failure\n");
        return -1;
    }

    soc = udp_socket_open();
    if(soc == -1){
        return -1;
    }
    if(udp_socket_bind(soc, IP_ADDR_ANY, port) == -1){ // IP_ADDR_ANYをipaddrにしても
        udp_socket_close(soc);
        return -1;
    }
    fprintf(stderr, "running...\n");
    while(!terminate){
        ret = udp_socket_recvfrom(soc, buf, sizeof(buf), &peer_addr, &peer_port, 1);
        if(ret <= 0){
            if (ret == -ETIMEDOUT){
                continue;
            }
            break;
        }
        fprintf(stderr, "receive %d bytes message from %s:%d\n", ret, ip_addr_ntop(&peer_addr, addr, sizeof(addr)), ntoh16(peer_port));
        hexdump(stderr, buf, ret);
        udp_socket_sendto(soc, buf, ret, &peer_addr, peer_port);
    }
    udp_socket_close(soc);

    return 0;
}

