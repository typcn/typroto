//
//  packet.c
//  typroto
//
//  Created by TYPCN on 2016/6/3.
//
//

#include "packet.h"
#include "common.h"
#include <sodium.h>
#include <time.h>

PKT_ERROR tp_packet_encrypt(struct Box *inbox, uint8_t *buf, uint32_t buflen, const uint8_t *key){
    uint32_t inbox_min_size = TP_SEC_HEADER_SIZE + inbox->payload_length;
    uint32_t pkt_min_size = inbox_min_size + PKT_NONCE_SIZE + PKT_TAG_SIZE;
    if(buflen < pkt_min_size){
        printd("Buffer length %d not enough, at least %d needed\n", buflen, pkt_min_size);
        return P_BUFFER_TOO_SMALL;
    }
    uint32_t inbox_max_size = buflen - PKT_NONCE_SIZE - PKT_TAG_SIZE;
    uint8_t box_buf[inbox_max_size];
    BOX_ERROR box_rv = tp_box_data_build(inbox, box_buf, inbox_max_size);
    if(box_rv != B_SUCCESS){
        printd("Box build failed with error %d\n",box_rv);
        return P_BOX_BUILD_FAILED;
    }
    
    uint8_t cipher[inbox_max_size];
    uint8_t tag[PKT_TAG_SIZE];
    uint8_t nonce[PKT_NONCE_SIZE];
    
    randombytes_buf(nonce, PKT_NONCE_SIZE);
    
    uint64_t taglen = PKT_TAG_SIZE;
    int crypt_rv = crypto_aead_chacha20poly1305_encrypt_detached(cipher, tag, (unsigned long long *)&taglen, box_buf, inbox_max_size, NULL, 0, NULL, nonce, key);
    if(crypt_rv != 0){
        printd("Crypt function failed with error %d\n",crypt_rv);
        return P_ENCRYPT_FAILED;
    }
    
    memcpy(buf, nonce, PKT_NONCE_SIZE);
    memcpy(buf + PKT_NONCE_SIZE, cipher, inbox_max_size);
    memcpy(buf + PKT_NONCE_SIZE + inbox_max_size, tag, PKT_TAG_SIZE);
    return P_SUCCESS;
}

PKT_ERROR tp_packet_decrypt(struct Packet *outpkt, uint8_t *buf, uint32_t buflen, const uint8_t *key){
    uint32_t pos_tag_start = buflen - PKT_TAG_SIZE;
    if(buflen < PKT_NONCE_SIZE + PKT_TAG_SIZE + 2){
        printd("Invalid inbound packet: Buffer length %d too small\n",buflen);
        return P_BUFFER_TOO_SMALL;
    }
    outpkt->tag = (uint8_t *)(buf + pos_tag_start);
    outpkt->nonce = (uint8_t *)buf;
    outpkt->secret_box = (uint8_t *)(buf + PKT_NONCE_SIZE);
    outpkt->secret_box_len = buflen - PKT_NONCE_SIZE - PKT_TAG_SIZE;
    
    // An UDP packet generally not more than 20000
    if(outpkt->secret_box_len > 20000){
        printd("Invalid inbound packet: Buffer length %d invalid\n",buflen);
        return P_BUFFER_TOO_SMALL;
    }
    
    uint8_t box_data[outpkt->secret_box_len];
    int decrypt_rv = crypto_aead_chacha20poly1305_decrypt_detached(box_data, NULL, outpkt->secret_box, outpkt->secret_box_len, outpkt->tag, NULL, 0, outpkt->nonce, key);
    
    if(decrypt_rv == -1){
        printd("Tag not valid for packet %p , len %d\n",buf, buflen);
        return P_INCORRECT_TAG;
    }else if(decrypt_rv != 0){
        printd("Decrypt function failed with error %d\n",decrypt_rv);
        return P_DECRYPT_FAILED;
    }else if(!outpkt->box){
        printd("API MISUSE: Box of %p is not allocated\n",outpkt);
    }
    
    BOX_ERROR openbox_rv = tp_box_data_open(outpkt->box, box_data, outpkt->secret_box_len);
    if(openbox_rv != B_SUCCESS){
        printd("Box open failed with error %d\n",openbox_rv);
        return  P_BOX_OPEN_FAILED;
    }
    
    if(abs((int)(time(NULL) - outpkt->box->timestamp)) > 30){
        printd("Possible replay attack! PktTime: %d, CurrentTime: %ld\n",outpkt->box->timestamp,time(NULL));
        free(outpkt->box->payload);
        return P_TIMESTAMP_MISMATCH;
    }
    
    return P_SUCCESS;
}