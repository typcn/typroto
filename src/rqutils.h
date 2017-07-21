//
//  rqutils.h
//  typroto
//
//  Created by TYPCN on 2016/6/7.
//
//

#ifndef rqutils_h
#define rqutils_h

#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/time.h>
#include "queue.h"

#define BITMASK(b) (1 << ((b) % CHAR_BIT))
#define BITSLOT(b) ((b) / CHAR_BIT)
#define BITSET(a, b) ((a)[BITSLOT(b)] |= BITMASK(b))
#define BITCLEAR(a, b) ((a)[BITSLOT(b)] &= ~BITMASK(b))
#define BITTEST(a, b) ((a)[BITSLOT(b)] & BITMASK(b))
#define BITNSLOTS(nb) ((nb + CHAR_BIT - 1) / CHAR_BIT)

#ifdef _WIN32
/* Macros for min/max.  */
#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX(a,b) (((a)>(b))?(a):(b))
#endif

inline static uint64_t get_clock_ms(){
    struct timeval now;
    gettimeofday(&now, NULL);
    return (now.tv_sec * 1000LL) + now.tv_usec / 1000;
}

inline static void tr_send_control_packet(const struct Socket *skt, struct Box *box, int repeat){
    for (int i = 0; i < repeat; i++) {
        uint8_t buf[skt->packet_size];
        int rv = tp_packet_encrypt(box, buf, skt->packet_size, skt->transfer_key);
        if(rv != 0){
            printd("Packet encrypt failed with rv %d",rv);
            return;
        }
        sendto(skt->fd, buf, skt->packet_size, 0, skt->addr, skt->sockaddr_len);
    }
}

inline static void tr_sendACK(struct RecvQueue *q, bool force){
    uint64_t current = get_clock_ms();
    // printv("Current time %llu , last ack %llu\n",current, q->last_ack_time);
    if(current - q->last_ack_time > q->ack_send_delay || force){
        struct Box box;
        box.packet_id = 0;
        box.timestamp = time(NULL);
        box.type = PT_ACK;
        box.payload = (uint8_t *)&q->last_completed_id;
        box.payload_length = 8;
        tr_send_control_packet(q->skt, &box, TP_ACK_REPEAT_COUNT);
        printv("Sending ACK with ID %llu\n",*(uint64_t *)box.payload);
        q->last_ack_time = current;
    }
}

inline static void tr_sendSACK(struct RecvQueue *q, uint64_t missing_pkt_id, uint64_t end_pkt_id){
    uint64_t current = get_clock_ms();
    // printv("Current time %llu , last sack %llu\n",current, q->last_sack_time);
    if(current - q->last_sack_time > q->sack_send_delay){
        q->last_sack_sent = missing_pkt_id;
        
        int max_body = q->skt->packet_size - PROTOCOL_ABYTE;
    
        int start_bit = 12 * CHAR_BIT;
        int max_slot = (max_body - 12) * CHAR_BIT;
        int ack_length = MIN(end_pkt_id - missing_pkt_id, max_slot);
        
        uint8_t arr[max_body];
        memset(arr, 0, max_body);
        memcpy(arr, &missing_pkt_id, 8);
        memcpy(arr + 8, &ack_length, 4);
        
        int b;
        for (int i = 0; i < ack_length; i++) {
            int idx = (missing_pkt_id + i) % TP_SEND_BUFFER_SIZE;
            if(q->boxes[idx]){
                b = i + start_bit;
                BITSET(arr, b);
            }
        }

        struct Box box;
        box.packet_id = 0;
        box.timestamp = time(NULL);
        box.type = PT_SACK;
        box.payload = arr;
        box.payload_length = max_body;
        tr_send_control_packet(q->skt, &box, TP_SACK_REPEAT_COUNT);
        q->last_sack_time = current;
    }
}

inline static uint64_t tr_procACK(struct SendQueue *q, uint64_t sent_offset, uint64_t last_ack, bool isBufFull){
    if(last_ack > sent_offset){
        for (uint64_t i = sent_offset; i < last_ack; i++) {
            int idx = i % TP_SEND_BUFFER_SIZE;
            struct Box *b = q->boxes[idx];
            if(!b){
                continue;
            }
            if(b->payload_length && b->payload){
                free(b->payload);
            }
            free(b);
            q->boxes[idx] = NULL;
            q->sent_ts[idx] = 0;
        }
        if(isBufFull){
            pthread_cond_signal(&q->nobufs_cond);
        }
    }
    return last_ack;
}

#endif /* rqutils_h */
