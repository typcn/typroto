//
//  queue.h
//  typroto
//
//  Created by TYPCN on 2016/6/4.
//
//

#ifndef queue_h
#define queue_h

#include <pthread.h>
#include <time.h>
#include "box.h"
#include "packet.h"
#include "socks.h"
#include "common.h"
#include "spinlock.h"
#include "typroto.h"

struct SendQueue {
    const struct Socket* skt;
    
    // Some firewall may drop packet with same content, and may identify this is an rudp protocol
    // So just save the raw box, if packet got dropped , encrypt it with different nonce then resend
    struct Box *boxes[TP_SEND_BUFFER_SIZE]; // Same position should never writed before sent
    uint64_t sent_ts[TP_SEND_BUFFER_SIZE];
    
    pthread_t thread;
    pthread_mutex_t lock;
    pthread_spinlock_t ack_lock;
    
    pthread_cond_t idle_cond;
    pthread_cond_t nobufs_cond;
    
    bool idle_wait;
    bool nobufs_wait;
    
    // These 2 numbers need lock for r/w
    uint64_t sent_offset; // Incr on every packet sent, reset to 0 on reach int64 max (TODO)
    uint64_t write_offset;
    
    // These 5 values need ack_lock for r/w
    uint64_t last_ack_id;
    uint64_t last_sack_id;
    int last_sack_length;
    uint8_t sack_bitmap[TP_SACK_BUFFER_SIZE];
    bool ack_reset_perform;
    bool sack_reset_perform;
    
    // These 1 number should only read/write on same thread
    uint64_t last_packet_id;
    
    bool stopping;

    // Options - You can change it via user interface ot others
    int window_size;
    int resend_delay;
    int speed_limit; // Packet per second
    int max_resend_timeout; // How many resends without ACK cause timeout
    
    // Stats - Read it may cause race cond and got invalid value, and do not write it
    uint64_t packet_num; // Packets transmitted include resends
    uint64_t packet_resend; // Resend packets
};

struct RecvQueue {
    const struct Socket* skt;
    recv_cb_t callback;
    void *callback_userdata;
    
    struct Box *boxes[TP_RECV_BUFFER_SIZE];
    
    pthread_t thread;
    
    // These numbers should only read/write on receiving thread
    uint64_t last_received_id;
    uint64_t last_completed_id;
    uint64_t last_ack_time;
    uint64_t last_sack_time;
    uint64_t last_sack_sent;
    
    // Options - You can change it via user interface ot others
    int sack_send_delay;
    int sack_threshold;
    int ack_send_delay;
    
    
    // Stats - Read it may cause race cond , and do not write it
    uint64_t user_bytes; // Bytes of payload received and not dropped
    uint64_t real_bytes; // Bytes include header / tag / invalid packets
    uint64_t packet_num; // Packets received
    uint64_t packet_dup; // Duplicate packets
    uint64_t packet_dropped; // Dropped packets due buffer full, if > 0 you need adjust recv buffer size
};


// These functions should never fail, except memory alloc failed / thread create failed, just let it crash...
struct SendQueue *tp_send_queue_create(const struct Socket *skt);
struct RecvQueue *tp_recv_queue_create(const struct Socket *skt);


int tp_send_queue_destroy(struct SendQueue *q);
int tp_recv_queue_destroy(struct RecvQueue *q);


#endif /* queue_h */
