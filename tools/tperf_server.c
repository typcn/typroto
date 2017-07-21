//
//  tperf_server.c
//  typroto
//
//  Created by TYPCN on 2016/6/8.
//
//

#include <pthread.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>

#include "../src/typroto.h"
#include "../src/socks.h"

int msgtime = 0;
int reverse_started = 0;
int speed_limit = 0;

void recvcb(int fd, const uint8_t *buf, uint32_t len, const struct sockaddr* addr, socklen_t addrlen, void *userdata){
    // const struct sockaddr_in *iaddr = (const struct sockaddr_in *)addr;
    //printf("[Fd %d] Got a packet from %s:%d : %s\n",fd, inet_ntoa(iaddr->sin_addr), ntohs(iaddr->sin_port),  buf);
    msgtime = time(NULL);
    if(len == 4){
        speed_limit = *(int *)buf;
    }
}

void evtcb(int fd, int code, const char* msg,const struct sockaddr* addr, socklen_t addrlen, void *userdata){
    const struct sockaddr_in *iaddr = (const struct sockaddr_in *)addr;
    printf("[Fd %d] Event %d from %s:%d : %s\n",fd, code , inet_ntoa(iaddr->sin_addr), ntohs(iaddr->sin_port),  msg);
}

void printHex(int x, uint8_t *buf){
    int i;
    for (i = 0; i < x; i++)
    {
        if (i > 0) printf(":");
        printf("%02X", buf[i]);
    }
    printf("\n");
}

char *paddings = "                                                                            ";

void print_padding(int width, char *fmt, ...){
    char *txt = NULL;
    va_list arglist;
    va_start(arglist, fmt);
    vasprintf(&txt, fmt, arglist);
    va_end(arglist);
    int len = strlen(txt);
    int padding = width - len;
    char padstr[100];
    memset(padstr, 0, 100);
    memcpy(padstr, paddings, padding);
    fprintf(stderr,"%s%s",txt,padstr);
}

void *print_stats(void *skt_p){
    const struct Socket *skt = (const struct Socket *)skt_p;
    struct SendQueue *sq = skt->sendqueue;
    struct RecvQueue *rq = skt->recvqueue;
    int psize = skt->packet_size;
    uint64_t send_last_user_byte = 0;
    uint64_t send_last_real_byte = 0;
    uint64_t recv_last_user_byte = 0;
    uint64_t recv_last_real_byte = 0;
    while (1) {
        sleep(1);
        // Print send bytes
        fprintf(stderr, "Send --- ");
        uint64_t spus = (sq->packet_num - sq->packet_resend) * psize;
        uint64_t sprs = sq->packet_num * psize;
        print_padding(20, "User: %lluKB", spus / 1024);
        print_padding(20, "Real: %lluKB", sprs / 1024);
        print_padding(20, "Rsnd: %lluKB", (sq->packet_resend * psize) / 1024);
        // Print send packets
        fprintf(stderr,"| PKTS --- ");
        print_padding(20, "User: %llu", sq->packet_num - sq->packet_resend);
        print_padding(20, "Real: %llu", sq->packet_num);
        print_padding(20, "Rsnd: %llu", sq->packet_resend);
        
        // Print send speed
        fprintf(stderr,"| ");
        print_padding(20, "U: %lluKB/s", (spus - send_last_user_byte) / 1024);
        print_padding(20, "R: %lluKB/s", (sprs - send_last_real_byte) / 1024);
        
        // Print recv bytes
        fprintf(stderr,"\nRecv --- ");
        print_padding(20, "User: %lluKB", rq->user_bytes / 1024);
        print_padding(20, "Real: %lluKB", rq->real_bytes / 1024);
        print_padding(20, "Ovhd: %lluKB", (rq->real_bytes - rq->user_bytes) / 1024);
        
        // Print recv packets
        fprintf(stderr,"| PKTS --- ");
        print_padding(20, "All : %llu", rq->packet_num);
        print_padding(20, "Dups: %llu", rq->packet_dup);
        print_padding(20, "Drop: %llu", rq->packet_dropped);
        
        // Print recv speed
        fprintf(stderr,"| ");
        print_padding(20, "U: %lluKB/s", (rq->user_bytes - recv_last_user_byte) / 1024);
        print_padding(20, "R: %lluKB/s", (rq->real_bytes - recv_last_real_byte) / 1024);
        
        fprintf(stderr,"\n");
        
        send_last_user_byte = spus;
        send_last_real_byte = sprs;
        recv_last_user_byte = rq->user_bytes;
        recv_last_real_byte = rq->real_bytes;
    }
    return NULL;
}


void *reverse_sending(void *skt_p){
    const struct Socket *skt = (const struct Socket *)skt_p;
    int fd = skt->fd;
    int psize = skt->packet_size;
    while (1) {
        uint8_t *buf = malloc(psize - PROTOCOL_ABYTE);
        int r = tp_send(fd, buf, psize - PROTOCOL_ABYTE);
        if(r){
            free(buf);
        }
    }
    return NULL;
}

int main(int argc, char *argv[]){
    int rv = tp_init();
    if(rv != 0){
        printf("Failed to init typroto\n");
        return -1;
    }
    if(argc < 5){
        printf("Usage: ./tperf_server bind_ip bind_port packet_size password\n");
        return -1;
    }
    
slisten: sleep(1);


    int fd = tp_socket(AF_INET);
    printf("[Server] Got fd %d, Ready to listen %s:%s\n",fd, argv[1], argv[2]);

    struct sockaddr_in addr;
    socklen_t slen = sizeof(addr);
    memset((void *) &addr, 0, slen);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(atoi(argv[2]));
    inet_aton(argv[1], &addr.sin_addr);
    tp_listen(fd, (const struct sockaddr*)&addr, slen);
    
    int psize = atoi(argv[3]);
    char *password = argv[4];
    
    struct sockaddr_in incoming_addr;
    socklen_t alen = sizeof(incoming_addr);
acceptc:

    rv = tp_accept(fd, psize, password, (struct sockaddr *)&incoming_addr,&alen);
    if(rv != 0){
        if(errno == EAGAIN){
            goto acceptc;
        }
        printf("[Server] Invalid packet from %s:%d, Code %d\n",
               inet_ntoa(incoming_addr.sin_addr), ntohs(incoming_addr.sin_port), rv);
        goto acceptc;
    }
    msgtime = time(NULL);
    tp_set_recv_callback(fd, recvcb, NULL);
    tp_set_event_callback(fd, evtcb, NULL);
    printf("[Server] Accepted a connection from %s:%d\n",
           inet_ntoa(incoming_addr.sin_addr), ntohs(incoming_addr.sin_port));
    const struct Socket *skt = tp_get_sock_by_id(fd);
    printf("[Server] Size per packet: %d Transfer Key: ",skt->packet_size);
    printHex(32,skt->transfer_key);

    pthread_t stats_t;
    pthread_create(&stats_t, NULL, print_stats, (void *)skt);
    
    pthread_t rsend_t;

    while (1) {
        if(time(NULL) - msgtime > 5){
            printf("[Server] Client timeout\n");
            if(reverse_started){
                pthread_cancel(rsend_t);
            }
            reverse_started = 0;
            speed_limit = 0;
            pthread_cancel(stats_t);
            tp_shutdown(fd);
            goto slisten;
        }else if(!reverse_started && speed_limit > 0){
            skt->sendqueue->speed_limit = speed_limit;
            pthread_create(&rsend_t, NULL, reverse_sending, (void *)skt);
            reverse_started = 1;
        }
        sleep(1);
    }
    return 0;
}