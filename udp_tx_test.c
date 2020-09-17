#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include "util.h"
#include "raw.h"
#include "net.h"
#include "ethernet.h"
#include "arp.h"
#include "ip.h"
#include "icmp.h"
#include "udp.h"

volatile sig_atomic_t terminate;

static void
on_signal (int s) {
    (void)s;
    terminate = 1;
}

static int
setup (void) {
    ethernet_init();
    arp_init();
    ip_init();
    icmp_init();
    udp_init();
    return 0;
}

int
main (int argc, char *argv[]) {
    char *ifname, *hwaddr = NULL, *ipaddr, *netmask;
    uint16_t port, peer_port;
    ip_addr_t peer;
    struct netdev *dev;
    struct netif *netif;
    uint8_t data[] = "hoge\n";

    switch (argc) {
    case 8:
        hwaddr = argv[2];
        /* fall through */
    case 7:
        ifname = argv[1];
        ipaddr = argv[argc-5];
        netmask = argv[argc-4];
        port = hton16(strtol(argv[argc-3], NULL, 10));
        ip_addr_pton(argv[argc-2], &peer);
        peer_port = hton16(strtol(argv[argc-1], NULL, 10));
        break;
    default:
        fprintf(stderr, "usage: %s interface [mac_address] ip_address netmask port peer_address peer_port\n", argv[0]);
        return -1;
    }
    signal(SIGINT, on_signal);
    setup();
    dev = netdev_alloc(NETDEV_TYPE_ETHERNET);
    if (!dev) {
        return -1;
    }
    strncpy(dev->name, ifname, sizeof(dev->name) -1);
    if (hwaddr) {
        ethernet_addr_pton(hwaddr, dev->addr);
    }
    if (dev->ops->open(dev, RAWDEV_TYPE_TAP) == -1) {
        return -1;
    }
    netif = ip_netif_register(dev, ipaddr, netmask);
    if (!netif) {
        fprintf(stderr, "ip_netif_register(): error\n");
        return -1;
    }
    dev->ops->run(dev);
    fprintf(stderr, "running...\n");
    while (!terminate) {
        udp_tx(netif, port, data, sizeof(data), &peer, peer_port);
        sleep(1);
    }
    dev->ops->close(dev);
    return 0;
}
