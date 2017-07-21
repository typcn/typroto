//
//  socks.c
//  typroto
//
//  Created by TYPCN on 2016/6/4.
//
//

#include "socks.h"
#include <stdlib.h>
#include <sodium.h>

// TODO: Add O(1) sock map type
// Current only support very simple fd id based map

struct Socket *_temp_skt_map[1024];

const struct Socket *tp_get_sock_by_id(int fd){
    return _temp_skt_map[fd];
}

void tp_add_sock(int fd, struct Socket * skt){
    _temp_skt_map[fd] = skt;
}

void tp_remove_sock(int fd){
    struct Socket *skt = _temp_skt_map[fd];
    if(skt){
        tp_send_queue_destroy(skt->sendqueue);
        tp_recv_queue_destroy(skt->recvqueue);
        free(skt->addr);
        sodium_free(skt->transfer_key);
        free(skt);
    }
}