//
//  packet.h
//  typroto
//
//  Created by TYPCN on 2016/6/3.
//
//

#ifndef packet_h
#define packet_h



#include "box.h"

#define PKT_TAG_SIZE crypto_aead_chacha20poly1305_ABYTES
#define PKT_NONCE_SIZE crypto_aead_chacha20poly1305_NPUBBYTES

struct Packet {
    uint8_t *nonce;
    uint8_t *secret_box;
    uint8_t *tag;
    
    // Box may not always exists ( eg: encrypt & send ), you must alloc it before call decrypt function
    struct Box *box;
    uint32_t secret_box_len;
};

enum _PKT_ERROR
{
    P_TIMESTAMP_MISMATCH = 1,
    P_SUCCESS = 0,
    P_ENCRYPT_FAILED = -1,
    P_BUFFER_TOO_SMALL = -2,
    P_BOX_BUILD_FAILED = -3,
    P_BOX_OPEN_FAILED = -4,
    P_DECRYPT_FAILED = -5,
    P_INCORRECT_TAG = -6,
};

typedef enum _PKT_ERROR PKT_ERROR;

PKT_ERROR tp_packet_encrypt(struct Box *inbox, uint8_t *buf, uint32_t buflen, const uint8_t *key);
PKT_ERROR tp_packet_decrypt(struct Packet *outpkt, uint8_t *buf, uint32_t buflen, const uint8_t *key);

#endif /* packet_h */
