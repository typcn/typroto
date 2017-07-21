//
//  box.c
//  typroto
//
//  Created by TYPCN on 2016/6/3.
//
//

#include "box.h"
#include "common.h"
#include <stdlib.h>

BOX_ERROR tp_box_data_build(struct Box *inbox, uint8_t *buf, uint32_t buflen){
    if(buflen - TP_SEC_HEADER_SIZE < inbox->payload_length){
        printd("Buffer length %d too short, at least need %d\n",buflen, inbox->payload_length + TP_SEC_HEADER_SIZE);
        return B_BUFFER_TOO_SMALL;
    }
    buf[0] = inbox->type;
    memcpy(buf+1, &inbox->timestamp, 4);
    memcpy(buf+5, &inbox->packet_id, 8);
    memcpy(buf+13, &inbox->payload_length, 2);
    
    if(inbox->payload_length > 0){
        memcpy(buf + TP_SEC_HEADER_SIZE, inbox->payload, inbox->payload_length);
    }
    
    uint64_t offset = TP_SEC_HEADER_SIZE + inbox->payload_length;
    
    memset(buf + offset, 0, buflen - offset);

    return B_SUCCESS;
}

BOX_ERROR tp_box_data_open(struct Box *outbox, uint8_t *buf, uint32_t buflen){
    if(buflen < 15){
        printd("Invalid buffer length %d\n",buflen);
        return B_BUFFER_TOO_SMALL;
    }
    outbox->type = buf[0];
    memcpy(&outbox->timestamp, buf+1, 4);
    memcpy(&outbox->packet_id, buf+5, 8);
    memcpy(&outbox->payload_length, buf+13, 2);
    
    if(outbox->payload_length > 0){
        outbox->payload = malloc(outbox->payload_length);
        memcpy(outbox->payload, buf + TP_SEC_HEADER_SIZE, outbox->payload_length);
    }
    
    return B_SUCCESS;
}