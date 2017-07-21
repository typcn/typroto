//
//  socks.h
//  typroto
//
//  Created by TYPCN on 2016/6/4.
//
//

#ifndef socks_h
#define socks_h


#ifdef _WIN32
#include <winsock2.h>
#else
#include <sys/socket.h>
#endif
#include "queue.h"
#include "typroto.h"

struct Socket {
    int fd;

    struct sockaddr *addr;
    socklen_t sockaddr_len;
    
    uint8_t *transfer_key;
    uint32_t packet_size;

    struct SendQueue *sendqueue;
    struct RecvQueue *recvqueue;
    
    event_cb_t evt;
    void *evt_userdata;
};

#ifdef __cplusplus
extern "C" {
#endif

const struct Socket *tp_get_sock_by_id(int fd);
void tp_add_sock(int fd, struct Socket * skt);
void tp_remove_sock(int fd);

#ifdef __cplusplus
}
#endif

#endif /* socks_h */
