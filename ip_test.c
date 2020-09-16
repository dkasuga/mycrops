#include <stdio.h>
#include <string.h>
#include <signal.h>
#include "raw.h"
#include "net.h"
#include "ethernet.h"
#include "arp.h"
#include "ip.h"

static void
dummy_handler(uint8_t *packet, size_t plen, ip_addr_t *src, ip_addr_t *dst, struct netif *netif){
    char addr1[IP_ADDR_STR_LEN];
    char addr2[IP_ADDR_STR_LEN];

    (void)packet;
    fprintf(stderr, "### ICMP Message Receive ###\n");
    fprintf(stderr, "%s => %s (%zd bytes) via %s\n", ip_addr_ntop(src, addr1, sizeof(addr1)), ip_addr_ntop(dst, addr2, sizeof(addr2)), plen, netif->dev->name);
}

static int
setup(void){
    ethernet_init();
    arp_init();
    ip_init();
    ip_add_protocol(IP_PROTOCOL_ICMP, dummy_handler);
    return 0;
}

int
main(int argc, char *argv[]){
    char *ifname, *hwaddr = NULL, *ipaddr, *netmask;
    sigset_t sigset;
    int signo;
    struct netdev *dev;
    struct netif *netif;

    switch(argc){
        case 5:
            hwaddr = argv[2];
            /* fall through */
        case 4:
            ifname = argv[1];
            ipaddr = argv[argc-2];
            netmask = argv[argc-1];
            break;
        default:
            fprintf(stderr, "usage: %s interface [mac_address] ip_address netmask\n", argv[0]);
            return -1;
    }

    sigemptyset(&sigset);
    sigaddset(&sigset, SIGINT);
    sigprocmask(SIG_BLOCK, &sigset, NULL);
    setup();
    dev = netdev_alloc(NETDEV_TYPE_ETHERNET);
    if(!dev){
        return -1;
    }
    strncpy(dev->name, ifname, sizeof(dev->name) - 1);
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
    fprintf(stderr, "running...\n");
    while(1){
        sigwait(&sigset, &signo);
        if(signo == SIGINT){
            break;
        }
    }
    dev->ops->close(dev);
    return 0;
}
