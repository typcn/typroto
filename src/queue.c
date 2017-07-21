//
//  queue.c
//  typroto
//
//  Created by TYPCN on 2016/6/4.
//
//

#include "queue.h"
#include "packet.h"
#include <stdlib.h>
#include <math.h>
#include <sys/param.h>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <unistd.h>
#include <netinet/in.h>
#endif
#include "rqutils.h"

void *tp_send_loop();
void *tp_recv_loop();

#define send_event(code,msg) q->skt->evt(sockfd,code,msg,addr,alen,q->skt->evt_userdata)

struct SendQueue *tp_send_queue_create(const struct Socket *skt){
    int size = sizeof(struct SendQueue);
    struct SendQueue *q = malloc(size);
    memset(q, 0, size);
    q->skt = skt;
    q->write_offset = 1;
    q->last_packet_id = 1;
    q->packet_num = 1;
    q->window_size = TP_INIT_WINDOW_SIZE;
    q->resend_delay = TP_INIT_RESEND_DELAY;
    q->speed_limit = 50000;
    q->max_resend_timeout = 1000;
    pthread_mutex_init(&q->lock,NULL);
    pthread_spin_init(&q->ack_lock, PTHREAD_PROCESS_PRIVATE);
    pthread_cond_init(&q->idle_cond, NULL);
    pthread_cond_init(&q->nobufs_cond, NULL);
    pthread_create(&q->thread, NULL, tp_send_loop, (void *)q);
    return q;
}
struct RecvQueue *tp_recv_queue_create(const struct Socket *skt){
    int size = sizeof(struct RecvQueue);
    struct RecvQueue *q = malloc(size);
    memset(q, 0, size);
    q->skt = skt;
    q->real_bytes = skt->packet_size; // 1 Handshake packet
    q->packet_num = 1;
    q->sack_send_delay = TP_SACK_SEND_DELAY;
    q->sack_threshold = TP_SACK_THRESHOLD;
    q->ack_send_delay = TP_ACK_SEND_DELAY;
    //pthread_spin_init(&q->lock, PTHREAD_PROCESS_PRIVATE);
    pthread_create(&q->thread, NULL, tp_recv_loop, (void *)q);
    return q;
}

void *tp_send_loop(void *queue){
    struct SendQueue *q = (struct SendQueue *)queue;
    int psize = q->skt->packet_size;
    int sockfd = q->skt->fd;
    const struct sockaddr *addr = q->skt->addr;
    socklen_t alen = q->skt->sockaddr_len;
    int rv = 0;
    pthread_mutex_t *lock = &q->lock;
    pthread_spinlock_t *ack_lock = &q->ack_lock;
    
    pthread_cond_t *idle_cond = &q->idle_cond;
    
    uint64_t ts_ignore_until = 0;
    int resends_since_last_ack = 0;
    
    int us_factor = 1000*1000;
    
    while (!q->stopping) {
        pthread_spin_lock(ack_lock);
        uint64_t last_ack = q->last_ack_id;
        bool ack_reset_perform = q->ack_reset_perform;
        if(ack_reset_perform){
            q->ack_reset_perform = false;
        }
        pthread_spin_unlock(ack_lock);
        
        pthread_mutex_lock(lock);
        uint64_t last_write = q->write_offset;
        uint64_t last_sent = q->sent_offset;
        bool is_buf_full = q->nobufs_wait;
        last_sent = tr_procACK(q, last_sent, last_ack, is_buf_full);
        q->sent_offset = last_sent;
        pthread_mutex_unlock(lock);
        
        int pkt_end = MIN(last_write, last_sent + q->window_size);
        int pkt_sent_this_cycle = 0;
        
        last_sent++;
        
        printv("Sending %llu to %d\n", last_sent, pkt_end);
    
        for (uint64_t i = last_sent; i < pkt_end; i++) {
            int idx = i % TP_SEND_BUFFER_SIZE;
            uint64_t current = get_clock_ms();
            
            if(current - q->sent_ts[idx] < (q->resend_delay + TP_ACK_SEND_DELAY) && i > ts_ignore_until){
                printv("resend delay %d preventing packet %llu sending.\n",q->resend_delay, i);
                continue;
            }
            
            pthread_spin_lock(ack_lock);
            bool sack_reset = q->sack_reset_perform;
            bool ack_pres = q->last_ack_id > i+1;
            int sack_id = i - q->last_sack_id;
            bool sack_prevent = false;
            if(sack_id < TP_SACK_BUFFER_SIZE){
                sack_prevent = BITTEST(q->sack_bitmap, sack_id);
            }
            if(sack_reset){
                q->sack_reset_perform = false;
            }
            pthread_spin_unlock(ack_lock);
    
            if(sack_prevent){
                printv("SACK ID %d preventing packet %llu sending\n",sack_id,i);
                continue;
            }else if(q->sent_ts[idx] > 0){
                resends_since_last_ack++;
                q->packet_resend++;
                printv("Resending %llu\n", i);
            }
            
            if(!q->boxes[idx]){
                printv("Box of %llu is empty\n", i);
                continue;
            }
            
            q->packet_num++;
            q->boxes[idx]->timestamp = time(NULL);
            
            if(i+1 == pkt_end){
                q->boxes[idx]->type = PT_DATA_NEED_ACK;
            }else{
                q->boxes[idx]->type = PT_DATA;
            }
    
            uint8_t buf[psize];
            rv = tp_packet_encrypt(q->boxes[idx], buf, psize, q->skt->transfer_key);
            if(rv != 0){
                send_event(rv, "packet encrypt failed");
                goto breakout;
            }
            rv = sendto(sockfd, buf, psize, 0, addr, alen);
            if(rv < 0){
                send_event(errno, "sendto() failed");
                goto breakout;
            }
            
            pkt_sent_this_cycle++;

            printv("send() %llu returned %d with errno %d\n", i ,rv,errno);
            q->sent_ts[idx] = current;

            if(ack_pres){
                goto breakout;
            }else if(sack_reset){
                pthread_spin_lock(ack_lock);
                q->sack_reset_perform = false;
                ts_ignore_until = q->last_sack_id + q->last_sack_length;
                pthread_spin_unlock(ack_lock);
                printv("Ignore timeout until packet %llu , last_sent %llu\n",ts_ignore_until,i);
                goto breakout;
            }
        }
        
        if(ts_ignore_until > 0){
            ts_ignore_until = 0;
        }
        
        if(ack_reset_perform){
            resends_since_last_ack = 0;
        }
        
        if(resends_since_last_ack > q->max_resend_timeout){
            send_event(-2002, "no ack");
            printf("WARNING: NO ACKS AFTER %d Resends, is remote down? \n",resends_since_last_ack);
            sleep(1);
        }
    
        if(last_write  - last_sent > 1){
            usleep((us_factor / q->speed_limit) * (pkt_end - last_sent));
            continue;
        }
        
        pthread_mutex_lock(lock);
        q->idle_wait = true;
        pthread_cond_wait(idle_cond, lock);
        q->idle_wait = false;
        pthread_mutex_unlock(lock);
    breakout:;
    }
    printd("Sending fd %d thread exiting\n",sockfd);
    return NULL;
}

void *tp_recv_loop(void *queue){
    struct RecvQueue *q = (struct RecvQueue *)queue;
    const struct Socket *skt = q->skt;
    struct SendQueue *sq = skt->sendqueue;
    
    int psize = skt->packet_size;
    int sockfd = skt->fd;
    
    struct sockaddr *addr;

    if(skt->addr->sa_family == AF_INET){
        struct sockaddr_in incoming_addr;
        addr = (struct sockaddr*)&incoming_addr;
    }else{
        struct sockaddr_in6 incoming_addr;
        addr = (struct sockaddr*)&incoming_addr;
    }
    
    socklen_t alen = skt->sockaddr_len;
    uint8_t buf[psize];
    struct Packet outpkt;

    uint32_t boxSize = sizeof(struct Box);
    
    while (1) {
        if(!q->callback){
            sleep(1);
            continue;
        }
        int rsize = recvfrom(sockfd, buf, psize, 0, addr, &alen);
        if(errno == EBADF){
            printd("Fd %d was closed , thread exiting\n",sockfd);
            break;
        }
        if(errno == ETIMEDOUT || errno == EAGAIN){
            continue;
        }else if(rsize < psize){
            if(rsize < 0){
                send_event(errno, "recvfrom() failed");
            }else{
                send_event(-2001, "invalid packet size");
            }
            continue;
        }
        
#if ENABLE_RANDOM_PACKET_LOSS > 0
        if(((float)rand() / (float)RAND_MAX) * 100 < ENABLE_RANDOM_PACKET_LOSS){
            continue;
        }
#endif
        q->real_bytes += rsize;
        
        struct Box *outbox = malloc(boxSize);
        outpkt.box = outbox;
        // TODO: Anti nonce reuse , request missing packet, verify overflow
    
        int e = tp_packet_decrypt(&outpkt, buf, rsize, skt->transfer_key);
        if(e != 0){
            send_event(e, "packet decrypt failed");
            free(outbox);
            continue;
        }
        
        q->packet_num++;
        
        if(outbox->type == PT_ACK){
            uint64_t ackid = *(uint64_t *)outbox->payload;
            pthread_spin_lock(&sq->ack_lock);
            if(ackid > sq->last_ack_id){
                sq->last_ack_id = ackid;
                sq->ack_reset_perform = true;
            }
            pthread_spin_unlock(&sq->ack_lock);
            printv("Got ACK from %llu to %llu\n",ackid, *(uint64_t *)outbox->payload);
            free(outbox->payload);
            free(outbox);
            continue;
        }else if(outbox->type == PT_SACK){
            uint64_t sackid = *(uint64_t *)outbox->payload;
            int sack_len = *(int *)(outbox->payload + 8);
            pthread_spin_lock(&sq->ack_lock);
            // Prevent SACK packet delay
            if(sackid > sq->last_ack_id){
                sq->sack_reset_perform = true;
                sq->last_ack_id = sackid - 1;
                sq->last_sack_id = sackid;
                sq->last_sack_length = sack_len;
                memcpy(sq->sack_bitmap, outbox->payload + 12, outbox->payload_length - 12);
                printv("Got SACK packet with ID %llu\n",sackid);
            }
            pthread_spin_unlock(&sq->ack_lock);
            free(outbox->payload);
            free(outbox);
            continue;
        }
    
        printv("LastRecv: %llu, LastComplete: %llu\n",q->last_received_id, q->last_completed_id);

        if(q->last_received_id - q->last_completed_id >= TP_RECV_BUFFER_SIZE // Check is write to a in use slot
            && outbox->packet_id > q->last_received_id){ // Check is bigger than last recv ( need write to end )
            q->packet_dropped++;
            free(outbox->payload);
            free(outbox);
            printd("WARNING: Packet dropped because buffer full %llu\n",q->packet_dropped);
            continue;
        }else if(outbox->packet_id <= q->last_completed_id){
            q->packet_dup++;
            printd("WARNING: Received a ACKed packet %llu\n",outbox->packet_id);
            free(outbox->payload);
            free(outbox);
            tr_sendACK(q, false);
            continue;
        }
        
        int insert_position = outbox->packet_id % TP_RECV_BUFFER_SIZE;
        
        if(q->boxes[insert_position]){
            printv("Received DUP packet %llu %p, box pos %d\n", outbox->packet_id, q->boxes[insert_position], insert_position);
            q->packet_dup++;
            free(outbox->payload);
            free(outbox);
            tr_sendSACK(q, q->last_completed_id + 1,  q->last_received_id - 1);
            continue;
        }
        
        q->user_bytes += outbox->payload_length;

        printv("Insert pos %d %p , packet id %llu\n",insert_position, outbox, outbox->packet_id);
        q->boxes[insert_position] = outbox;
        
        if(outbox->packet_id > q->last_received_id){
            q->last_received_id = outbox->packet_id;
        }

        uint64_t target_id = q->last_completed_id + 1;
        uint64_t end_id = q->last_received_id + 1;
        for (int i = target_id; i < end_id; i++) {
            int key = i % TP_RECV_BUFFER_SIZE;
            struct Box *box = q->boxes[key];
            if(!box){
                break;
            }
            q->callback(sockfd, box->payload, box->payload_length, addr, alen, q->callback_userdata);
            if(box->payload_length > 0 && box->payload){
                free(box->payload);
            }
            free(box);
            printv("Box: %d %p was freed, pos %d\n",i,box, key);
            q->boxes[key] = NULL;
            printv("Box: %d %p was freed, pos %d\n",i,box, key);
            q->last_completed_id = i;
        }
        
        target_id = q->last_completed_id;
    
        if(end_id - target_id > q->sack_threshold){
            tr_sendSACK(q, target_id + 1, end_id - 1);
        }
        
        if(outbox->type == PT_DATA_NEED_ACK || outbox->packet_id == q->last_sack_sent){
            tr_sendACK(q, true);
        }else{
            tr_sendACK(q, false);
        }
    }
    return NULL;
}

int tp_send_queue_destroy(struct SendQueue *q){
    q->stopping = true;
    pthread_cond_signal(&q->idle_cond);
    pthread_cond_signal(&q->nobufs_cond);
    pthread_join(q->thread, NULL);
    pthread_mutex_destroy(&q->lock);
    pthread_spin_destroy(&q->ack_lock);
    pthread_cond_destroy(&q->idle_cond);
    pthread_cond_destroy(&q->nobufs_cond);
    for (int i = 0; i < TP_SEND_BUFFER_SIZE; i++) {
        struct Box *box = q->boxes[i];
        if(!box){
            continue;
        }
        if(box->payload_length > 0 && box->payload){
            free(box->payload);
        }
        free(box);
        q->boxes[i] = NULL;
    }
    free(q);
    return 0;
}
int tp_recv_queue_destroy(struct RecvQueue *q){
    pthread_cancel(q->thread);
    for (int i = 0; i < TP_RECV_BUFFER_SIZE; i++) {
        struct Box *box = q->boxes[i];
        if(!box){
            continue;
        }
        if(box->payload_length > 0 && box->payload){
            free(box->payload);
        }
        free(box);
        q->boxes[i] = NULL;
    }
    free(q);
    return 0;
}