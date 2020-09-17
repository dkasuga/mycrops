#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/time.h>
#include "util.h"
#include "udp.h"

#define UDP_CB_TABLE_SIZE 16
#define UDP_SOURCE_PORT_MIN 49152
#define UDP_SOURCE_PORT_MAX 65535

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

struct udp_queue_hdr {
    ip_addr_t addr;
    uint16_t port;
    uint16_t len;
    uint8_t data[0];
};

struct udp_cb {
    int used;
    struct netif *iface;
    uint16_t port;
    struct queue_head queue;
    pthread_cond_t cond;
};

static struct udp_cb cb_table[UDP_CB_TABLE_SIZE];
static pthread_mutex_t mutex;

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

ssize_t 
udp_tx (struct netif *iface, uint16_t sport, uint8_t *buf, size_t len, ip_addr_t *peer, uint16_t port){
    char packet[65536];
    ssize_t ret;
    struct udp_hdr *hdr;
    struct pseudo_hdr phdr;
    uint16_t psum;

    // チェックサム計算のために擬似ヘッダを用意
    phdr.src = ((struct netif_ip *)iface)->unicast;
    phdr.dst = *peer;
    phdr.zero = 0;
    phdr.protocol = IP_PROTOCOL_UDP;
    phdr.len = hton16(sizeof(struct udp_hdr) + len);

     /* your code here: */                                                              
     /* 1. バッファ（packet）に対してUDPデータグラムを構築（ヘッダ生成＋データコピー）*/
    hdr = (struct udp_hdr *)packet;
    hdr->sport = sport;
    hdr->dport = port;
    hdr->len = hton16(sizeof(struct udp_hdr) + len);
    psum = ~cksum16((uint16_t *)&phdr, sizeof(struct pseudo_hdr), 0);

    memcpy(hdr+1, buf, len);
    hdr->cksum = cksum16((uint16_t *)hdr, sizeof(struct udp_hdr)+len, psum); //0
     
     /* 2. UDPデータグラムをダンプ出力                                                 */
#ifdef DEBUG
    fprintf(stderr, ">>> udp_tx <<<\n");
    udp_dump((uint8_t *)packet, sizeof(struct udp_hdr) + len);
#endif
     /* 3. ip_tx() を呼び出してUDPデータグラムを送信（戻り値をretに格納）                */
    ret = ip_tx(iface, IP_PROTOCOL_UDP, packet, sizeof(struct udp_hdr) + len, peer);

    return ret;
}

static void
udp_rx(uint8_t *packet, size_t plen, ip_addr_t *src, ip_addr_t *dst, struct netif *netif){
    struct udp_hdr *hdr;
    struct pseudo_hdr phdr;
    uint16_t psum;

    struct udp_cb *cb;
    void *data;
    struct udp_queue_hdr *queue_hdr;
    
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
    pthread_mutex_lock(&mutex);
    // 宛先のアドレス(iface)+ポート(hdr->dport)に対応するコントロールブロックを探す
    for(cb=cb_table; cb<array_tailof(cb_table); cb++){
        if(cb->used && (!cb->iface || cb->iface == netif) && cb->port == hdr->dport){
            data = malloc(sizeof(struct udp_queue_hdr) + (plen - sizeof(struct udp_hdr)));
            if(!data){
                pthread_mutex_unlock(&mutex);
                return;
            }
            // コントロールブロックのキューにエントリを追加
            // queue_hdrとdataをまとめてつっこむ
            queue_hdr = data;
            queue_hdr->addr = *src;
            queue_hdr->port = hdr->sport;
            queue_hdr->len = plen - sizeof(struct udp_hdr);
            memcpy(queue_hdr + 1, hdr+1, plen-sizeof(struct udp_hdr)); // dataをコピー
            queue_push(&cb->queue, data, sizeof(struct udp_queue_hdr) + (plen - sizeof(struct udp_hdr)));
            // キューの状態に変化があったことを通知(pthread_cond_waitで待機しているスレッドを起床させる)
            pthread_cond_broadcast(&cb->cond);
            pthread_mutex_unlock(&mutex);
            return;
        }
    }
    pthread_mutex_unlock(&mutex);
    // icmp_send_destination_unreachable(); // 対応するIPアドレス/portが見つからないよ
    return;
}

int
udp_socket_open(void){
    struct udp_cb *cb;

    pthread_mutex_lock(&mutex);
    for(cb = cb_table; cb < array_tailof(cb_table); cb++){
        if(!cb->used){ //どれか空いているcbを見つける
            cb->used = 1;
            pthread_mutex_unlock(&mutex);
            return array_offset(cb_table, cb);
        }
    }
    pthread_mutex_unlock(&mutex);
    return -1;
}

int
udp_socket_close (int soc){
    struct udp_cb *cb;
    struct queue_entry *entry;

    if(soc < 0 || soc >= UDP_CB_TABLE_SIZE) {
        return -1;
    }

    pthread_mutex_lock(&mutex);
    cb = &cb_table[soc];
    if (!cb->used) {
        pthread_mutex_unlock(&mutex);
        return -1;
    }
    cb->used = 0;
    cb->iface = NULL;
    cb->port = 0;
    while((entry = queue_pop(&cb->queue)) != NULL){
        free(entry->data);
        free(entry);
    }
    cb->queue.next = cb->queue.tail = NULL;
    pthread_mutex_unlock(&mutex);
    return 0;
}

int
udp_socket_bind(int soc, ip_addr_t addr, uint16_t port){
    struct udp_cb *cb, *tmp;
    struct netif *iface = NULL;

    if (soc < 0 || soc >= UDP_CB_TABLE_SIZE){
        return -1;
    }
    pthread_mutex_lock(&mutex);
    cb = &cb_table[soc];
    if(!cb->used){
        pthread_mutex_unlock(&mutex);
        return -1;
    }
     /* addrが0(IP_ADDR_ANY)の場合はすべてのアドレスのポートにbindすることになるので特定のインタフェースに紐づけない */
    if(addr){
        iface = ip_netif_by_addr(&addr);
        if(!iface){
            pthread_mutex_unlock(&mutex);
            return -1;
        }
    }

    // アドレスにbind可能かどうか調べる
    for(tmp = cb_table; tmp < array_tailof(cb_table); tmp++){
         /*
         * (!iface || !tmp->iface || tmp->iface == iface)
         *
         * !iface               ... 全てのアドレスにbindしたい
         * !tmp->iface          ... 全てのアドレスにbind済み
         * !tmp->iface == iface ... bindしたいアドレスにbind済み
         *
         */
        if(tmp->used && tmp != cb && (!iface || !tmp->iface || tmp->iface == iface) && tmp->port == port){
            pthread_mutex_unlock(&mutex);
            return -1;
        }
    }
    cb->iface = iface;
    cb->port = port;
    pthread_mutex_unlock(&mutex);
    return 0;
}

ssize_t
udp_socket_recvfrom(int soc, uint8_t *buf, size_t size, ip_addr_t *peer, uint16_t *port, int timeout){
    struct udp_cb *cb;
    struct queue_entry *entry;
    struct timeval tv;
    struct timespec ts;
    int ret = 0;
    ssize_t len;
    struct udp_queue_hdr *queue_hdr;

    if(soc < 0 || soc >= UDP_CB_TABLE_SIZE){
        return -1;
    }
    pthread_mutex_lock(&mutex);
    cb = &cb_table[soc];
    if(!cb->used){
        pthread_mutex_unlock(&mutex);
        return -1;
    }
    // コントロールブロックのキューからエントリを取り出す
    gettimeofday(&tv, NULL);
    // clock_gettime(CLOCK_REALTIME, &ts);
    
    while((entry = queue_pop(&cb->queue)) == NULL && ret != ETIMEDOUT){
        /* キューにエントリがなかったらpthread_cond_waitで待機する（pthread_cond_broadcastで起こされるのを待つ） */
        if(timeout != -1){
            ts.tv_sec = tv.tv_sec+timeout;
            ts.tv_nsec = tv.tv_usec * 1000; // microsec -> nanosec
            ret = pthread_cond_timedwait(&cb->cond, &mutex, &ts);
        } else{
            ret = pthread_cond_wait(&cb->cond, &mutex);
        }
    }
    pthread_mutex_unlock(&mutex);
    if (ret == ETIMEDOUT){
        return -ETIMEDOUT;
    }
    // キューエントリのヘッダから送信元の情報を取り出す
    queue_hdr = (struct udp_queue_hdr *)entry->data;
    if(peer){
        *peer = queue_hdr->addr;
    }
    if(port){
        *port = queue_hdr->port;
    }
    // アプリケーションのバッファに受信データをコピー
    len = MIN(size, queue_hdr->len); // どれだけデータをとりだしたいか？
    memcpy(buf, queue_hdr + 1, len);
    free(entry->data);
    free(entry);
    return len;
}

ssize_t
udp_socket_sendto (int soc, uint8_t *buf, size_t len, ip_addr_t *peer, uint16_t port){
    struct udp_cb *cb, *tmp;
    struct netif *iface;
    uint32_t p;
    uint16_t sport;

    if(soc < 0 || soc >= UDP_CB_TABLE_SIZE){
        return -1;
    }
    pthread_mutex_lock(&mutex);
    cb = &cb_table[soc];
    if (!cb->used){
        pthread_mutex_unlock(&mutex);
        return -1;
    }
    iface = cb->iface;
    if (!iface){
        /* 特定のアドレスにbindされていなかったらpeerのアドレスに到達できるインタフェースを取得 */
        iface = ip_netif_by_peer(peer);
        if(!iface){
            pthread_mutex_unlock(&mutex);
            return -1;
        }
    }
    if (!cb->port) {
        // 特定のポートにbindされていなかったら未使用のポートを使う
        // エフェメラルポート？
        for(p = UDP_SOURCE_PORT_MIN; p <= UDP_SOURCE_PORT_MAX; p++){
            for(tmp = cb_table; tmp < array_tailof(cb_table); tmp++){
                // すべてのアドレスのポートにbindされているものを考慮する
                if(tmp->port == hton16((uint16_t)p) && (!tmp->iface || tmp->iface == iface)){
                    break;
                }
            }
            // どこにもひっかからなかったら最後まで到達している
            if(tmp == array_tailof(cb_table)){
                // 使用可能なポートを発見
                cb->port = hton16((uint16_t)p);
                break;
            }
        }
        if(!cb->port){
            //使用可能なポートがなかった
            pthread_mutex_unlock(&mutex);
            return -1;
        }
    }
    sport = cb->port;
    pthread_mutex_unlock(&mutex);
    return udp_tx(iface, sport, buf, len, peer, port);
}

int
udp_init(void){
    struct udp_cb *cb;

    for(cb = cb_table; cb<array_tailof(cb_table); cb++){
        pthread_cond_init(&cb->cond, NULL);
    }
    pthread_mutex_init(&mutex, NULL);
    if(ip_add_protocol(IP_PROTOCOL_UDP, udp_rx) == -1){
        return -1;
    }
    return 0;
}

