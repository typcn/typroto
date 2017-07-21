//
//  common.h
//  typroto
//
//  Created by TYPCN on 2016/6/3.
//
//

#ifndef common_h
#define common_h
#define TYPROTO

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define __FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)


// The buffer size is in "packet", not in bytes
// To control the packet size , look at the pktSize param of connect() and accept()
#define TP_SEND_BUFFER_SIZE 2048
#define TP_RECV_BUFFER_SIZE 2048 // Set a larger value if you have enough memory

// Receive timeout ( seconds )
#define TP_RECV_TIMEOUT 2

// ACK Delay in ms , Be careful: ACK Packet is also padded to full size ( = pktSize )
// Send timeout will be set to ACK_DELAY + f(NETWORK_DELAY)
// Set a lager value for downloading / mobile device
#define TP_ACK_SEND_DELAY 100
// Repeat send x times ACK packet
#define TP_ACK_REPEAT_COUNT 2

// If last received id - last free id > sack threshold , an SACK packet will be sent
#define TP_SACK_THRESHOLD 10
// Min delay between two SACK packets
#define TP_SACK_SEND_DELAY 100
// Repeat send x times SACK packet
#define TP_SACK_REPEAT_COUNT 1
// never > mtu 1500, 2048 is safe
#define TP_SACK_BUFFER_SIZE 2048

#define TP_INIT_WINDOW_SIZE 500

#define TP_INIT_RESEND_DELAY 250

// Enable it will log every packet send , recv , ack , free
#define ENABLE_VERBOSE_LOGGING 0
// Enable random packet loss , Percent
#define ENABLE_RANDOM_PACKET_LOSS 0

#ifdef DEBUG
#define printd(fmt, ...) printf("[TYProto][%s-%d] " fmt, __FILENAME__, __LINE__, __VA_ARGS__)
#else
#define printd(fmt, ...)
#endif

#if ENABLE_VERBOSE_LOGGING == 1
#define printv(fmt, ...) printf("[TYProto][%s-%d] " fmt, __FILENAME__, __LINE__, __VA_ARGS__)
#else
#define printv(fmt, ...)
#endif

// Add some random packet drop, percent , 1-100.  comment to disable
// #define ENABLE_PACKET_DROP 10

// Enable it to allow read RSA KEY from file , will decrease security, only for very low performance devices
// #define TP_RSA_LOAD_FROM_FILE 1

#ifndef CHAR_BIT
#define CHAR_BIT 8
#endif

#endif /* common_h */
