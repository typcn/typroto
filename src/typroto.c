
#include <string.h>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <netdb.h>
#endif
#include <sys/time.h>
#include <errno.h>
#include <pthread.h>
#include <sodium.h>
#include <unistd.h>
#include "typroto.h"
#include "common.h"
#include "packet.h"
#include "socks.h"
#include "handshake.h"

int tp_init(){
    int rv = sodium_init();
    printd("libsodium init returned with %d\n",rv);
    if(rv == -1){
        return -1;
    }
    printd("chacha20-poly1305 tag size %d\n",PKT_TAG_SIZE);
    printd("chacha20-poly1305 nonce size %d\n",PKT_NONCE_SIZE);
    printd("chacha20-poly1305 key size %d\n",crypto_aead_chacha20poly1305_KEYBYTES);
    return 0;
}

int tp_socket(int af){
    int fd = socket(af, SOCK_DGRAM, IPPROTO_UDP);
    return fd;
}

static void tp_default_event_callback(int fd, int code, const char* msg,const struct sockaddr* addr, socklen_t addrlen, void *userdata){
    return;
}

int tp_connect(int sockfd, int pktSize, const char *key, const struct sockaddr *addr, socklen_t addrlen){
    uint8_t *rsa_privkey_buf = sodium_malloc(8192);
    uint8_t *data_buf = malloc(pktSize);
    int rsa_privkey_len = tp_build_handshake_packet(rsa_privkey_buf, data_buf, pktSize, key);
    sendto(sockfd, data_buf, pktSize, 0, addr, addrlen);
    
    ssize_t recvlen = recvfrom(sockfd, data_buf, pktSize, 0, NULL, NULL);
    if(recvlen < 1){
        return -1;
    }
    
    uint8_t *transKey = sodium_malloc(crypto_aead_chacha20poly1305_KEYBYTES);
    
    int rv = tp_handshake_response_decrypt(transKey, rsa_privkey_buf, rsa_privkey_len, data_buf, recvlen, key);
    if(rv != 0){
        return rv;
    }
    
    sodium_mprotect_readwrite(rsa_privkey_buf);
    sodium_free(rsa_privkey_buf);
    free(data_buf);
    
    struct sockaddr *paddr = malloc(addrlen);
    memcpy(paddr, addr, addrlen);
    
    int sktSize = sizeof(struct Socket);
    struct Socket *skt = malloc(sktSize);
    memset(skt, 0, sizeof(sktSize));
    skt->fd = sockfd;
    skt->addr = paddr;
    skt->sockaddr_len = addrlen;
    skt->transfer_key = transKey;
    skt->packet_size = pktSize;
    skt->sendqueue = tp_send_queue_create(skt);
    skt->recvqueue = tp_recv_queue_create(skt);
    skt->evt = tp_default_event_callback;
    tp_add_sock(sockfd, skt);
    return 0;
}

int tp_listen(int sockfd, const struct sockaddr *addr, socklen_t addrlen){
    int rv = bind(sockfd, addr, addrlen);
    printd("bind() returned %d\n",rv);
    return rv;
}

int tp_accept(int sockfd, int pktSize, const char *key, struct sockaddr *addr, socklen_t *addrlen){
    uint8_t data_buf[pktSize];
    ssize_t recvlen = recvfrom(sockfd, data_buf, pktSize, 0, addr, addrlen);
    if(recvlen < 1){
        return -1;
    }
    uint8_t resp_buf[pktSize];
    uint8_t *transKey = sodium_malloc(crypto_aead_chacha20poly1305_KEYBYTES);
    int rv = tp_build_handshake_packet_response(transKey, resp_buf, pktSize, data_buf, recvlen, key);
    if(rv != 0){
        return rv;
    }
    rv = sendto(sockfd, resp_buf, pktSize, 0, addr, *addrlen);
    printd("Sent server hello with rv %d, errno %d\n",rv,errno);
    
    struct sockaddr *paddr = malloc(*addrlen);
    memcpy(paddr, addr, *addrlen);
    
    int sktSize = sizeof(struct Socket);
    struct Socket *skt = malloc(sktSize);
    memset(skt, 0, sizeof(sktSize));
    skt->fd = sockfd;
    skt->addr = paddr;
    skt->sockaddr_len = *addrlen;
    skt->transfer_key = transKey;
    skt->packet_size = pktSize;
    skt->sendqueue = tp_send_queue_create(skt);
    skt->recvqueue = tp_recv_queue_create(skt);
    skt->evt = tp_default_event_callback;
    tp_add_sock(sockfd, skt);
    return 0;
}

int tp_send(int sockfd, uint8_t *buf, size_t len){
    const struct Socket* skt = tp_get_sock_by_id(sockfd);
    if(!skt){
        return -1;
    }
    struct SendQueue *q = skt->sendqueue;
    pthread_mutex_lock(&q->lock);
start_send:;

    bool is_full = (q->write_offset - q->sent_offset >= TP_SEND_BUFFER_SIZE);
    uint64_t write_offset = q->write_offset;
    if(!is_full){
        q->write_offset++;
    }else{
        printv("Blocking at %ld\n",time(NULL));
        q->nobufs_wait = true;
    }
    
    if(q->idle_wait){
        pthread_cond_signal(&q->idle_cond);
    }
    
    if(is_full){
        pthread_cond_wait(&q->nobufs_cond, &q->lock);
        q->nobufs_wait = false;
        goto start_send;
    }

    
    int boxSize = sizeof(struct Box);
    struct Box *box = malloc(boxSize);
    box->packet_id = q->last_packet_id++;
    box->payload = buf;
    box->payload_length = len;
    
    int idx = write_offset % TP_SEND_BUFFER_SIZE;
    q->boxes[idx] = box;

    pthread_mutex_unlock(&q->lock);
    return 0;
}

int tp_set_recv_callback(int sockfd, recv_cb_t cb, void *userdata){
    const struct Socket* skt = tp_get_sock_by_id(sockfd);
    if(!skt){
        return -1;
    }
    skt->recvqueue->callback = cb;
    skt->recvqueue->callback_userdata = userdata;
    return 0;
}

int tp_set_event_callback(int sockfd, event_cb_t cb, void *userdata){
    struct Socket* skt = (struct Socket*)tp_get_sock_by_id(sockfd);
    if(!skt){
        return -1;
    }
    skt->evt = cb;
    skt->evt_userdata = userdata;
    return 0;
}

int tp_shutdown(int sockfd){
    close(sockfd);
    tp_remove_sock(sockfd);
    return 0;
}