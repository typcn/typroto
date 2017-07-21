//
//  box.h
//  typroto
//
//  Created by TYPCN on 2016/6/3.
//
//

#ifndef box_h
#define box_h
#include "common.h"

#define PT_CLIENT_HELLO 1
#define PT_SERVER_HELLO 2
#define PT_DATA 3
#define PT_DATA_NEED_ACK 4
#define PT_ACK 11
#define PT_SACK 12

#define TP_SEC_HEADER_SIZE 15

struct Box {
    uint8_t type;
    uint32_t timestamp;
    uint64_t packet_id;
    uint16_t payload_length;
    uint8_t *payload;
    // Padding will removed
};

enum _BOX_ERROR
{
    B_SUCCESS = 0,
    B_INVALID_INPUT = -1,
    B_BUFFER_TOO_SMALL = -2,
};

typedef enum _BOX_ERROR BOX_ERROR;

BOX_ERROR tp_box_data_build(struct Box *inbox, uint8_t *buf, uint32_t buflen);
BOX_ERROR tp_box_data_open(struct Box *outbox, uint8_t *buf, uint32_t buflen);


#endif /* box_h */
