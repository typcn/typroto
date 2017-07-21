//
//  handshake.c
//  typroto
//
//  Created by TYPCN on 2016/6/4.
//
//

#include "handshake.h"
#include "totp.h"
#include "packet.h"
#include "common.h"
#include <string.h>
#include <openssl/hmac.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/rand.h>
#include <sodium.h>

void tp_calc_encrypt_key(const char *psk, uint8_t *buf){
    char totpkey[9];
    totp((uint8_t *)psk, strlen(psk), 30, 8, NULL, totpkey, 9);
    totpkey[8] = '\0';
    
    uint32_t hs_key_len;
    HMAC(EVP_sha256(), totpkey, 8, (uint8_t *)psk, strlen(psk), buf, &hs_key_len);
    if(hs_key_len != 32){
        printd("Key size %d may not suitable for encrypt\n",hs_key_len);
    }
}

int read_file(const char* name, uint8_t *buf, int *size){
    int rv = -1;
    FILE *file;
    file = fopen(name, "r");
    if (file) {
        uint32_t datasize;
        int len = fread(&datasize, 1, 4, file);
        if(len == 4){
            int len = fread(buf, 1, datasize, file);
            if(len == datasize){
                *size = len;
                rv = 0;
            }
        }
        fclose(file);
    }
    return rv;
}

int tp_build_handshake_packet(uint8_t *keybuf, uint8_t *databuf, uint32_t buflen, const char *psk){
    
    int status = -1;
    
#ifdef TP_RSA_LOAD_FROM_FILE
    printf("WARNING: RSA KEY WILL BE LOADED FROM FILE, PLEASE KEEP IT SAFE, AND CHANGE IT DAILY\n");
    uint8_t *private_key = malloc(8192);
    int private_key_length = 0;
    int rfrv = read_file("rsa_priv", private_key, &private_key_length);
    if(rfrv == -1){
        printf("You don't have rsa_priv, generate it with gen_key .\n");
        exit(-1);
    }
    sodium_mprotect_readwrite(keybuf);
    memcpy(keybuf, private_key, private_key_length);
    sodium_mprotect_noaccess(keybuf);
    free(private_key);
    
    uint8_t *public_key = malloc(8192);
    int public_key_length = 0;
    rfrv = read_file("rsa_pub", public_key, &public_key_length);
    if(rfrv == -1){
        printf("You don't have rsa_pub, generate it with gen_key .\n");
        exit(-1);
    }
    
#else
    // Generate RSA Keypair
    printd("Generating %d bit RSA keypair, this may take a while\n", TP_RSA_KEY_BITS);
    
    if(RAND_status() != 1){
        printd("OpenSSL rand status: %d , do you have /dev/urandom ?\n", RAND_status());
    }
    
    RSA *rsa_o = RSA_new();
    BIGNUM *big_number = BN_new();
    BN_set_word(big_number , RSA_F4);
    int ret = RSA_generate_key_ex(rsa_o, TP_RSA_KEY_BITS, big_number, NULL);
    if(ret != 1){
        printd("RSA keypair generate failed with ret %d\n",ret);
        goto cleanup;
    }
    
    // Save private key
    
    uint8_t *private_key = NULL;
    int private_key_length = i2d_RSAPrivateKey(rsa_o, &private_key);
    sodium_mprotect_readwrite(keybuf);
    memcpy(keybuf, private_key, private_key_length);
    sodium_mprotect_noaccess(keybuf);
    sodium_memzero(private_key, private_key_length);
    free(private_key);
    
    // Save public key
    
    uint8_t *public_key = NULL;
    int public_key_length = i2d_RSAPublicKey(rsa_o, &public_key);
#endif

    // Generate secret box
    
    struct Box inbox;
    inbox.packet_id = 0;
    inbox.type = PT_CLIENT_HELLO;
    inbox.timestamp = time(NULL);
    inbox.payload = public_key;
    inbox.payload_length = public_key_length;
    
    // Generate handshake encrypt key
    
    uint8_t hs_encrypt_key[EVP_MAX_MD_SIZE];
    tp_calc_encrypt_key(psk, hs_encrypt_key);

    // Encrypt packet
    
    int rv = tp_packet_encrypt(&inbox, databuf, buflen, hs_encrypt_key);
    sodium_memzero(public_key, public_key_length);
    free(public_key);

    if(rv != P_SUCCESS){
        printd("Packet encrypt failed, buflen: %d\n",buflen);
        goto cleanup;
    }
    status = private_key_length;
    
cleanup:
#ifndef TP_RSA_LOAD_FROM_FILE
    RSA_free(rsa_o);
    BN_free(big_number);
#endif
    return status;
}

int tp_build_handshake_packet_response(uint8_t *outkeybuf,uint8_t *respbuf, uint32_t rbuflen, uint8_t *databuf, uint32_t buflen, const char *psk){

    // Decrypt handshake request

    struct Box box;
    struct Packet pkt;
    pkt.box = &box;
    
    uint8_t hs_encrypt_key[EVP_MAX_MD_SIZE];
    tp_calc_encrypt_key(psk, hs_encrypt_key);
    
    int rv = tp_packet_decrypt(&pkt, databuf, buflen, hs_encrypt_key);
    if(rv != P_SUCCESS){
        printd("Packet decrypt failed, rv: %d\n",rv);
        return rv;
    }
    
    if(box.type != PT_CLIENT_HELLO || box.packet_id != 0){
        printd("Incorrect packet id %lld type %d for handshake\n",box.packet_id, box.type);
        return -1001;
    }
    
    int status = -1;
    
    // Decode RSA public key
    
    const unsigned char *pkptr = box.payload;
    
    RSA *r = d2i_RSAPublicKey(NULL, &pkptr, box.payload_length);
    free(box.payload);
    if(!r){
        printd("Failed to decode rsa public key %d\n",box.payload_length);
        return -1002;
    }
    
    randombytes_buf(outkeybuf, 32);
    
    int to_size = RSA_size(r);
    uint8_t target[to_size];
    
    int ret = RSA_public_encrypt(32, outkeybuf, target, r, RSA_PKCS1_PADDING);
    if(ret < 0){
        printd("RSA encrypt failed with ret %d\n",ret);
        status = -1003;
        goto cleanup;
    }
    
    printd("size: %d to_size:%d\n",ret,to_size);
    
    // Generate secret box
    
    struct Box inbox;
    inbox.packet_id = 0;
    inbox.type = PT_SERVER_HELLO;
    inbox.timestamp = time(NULL);
    inbox.payload = target;
    inbox.payload_length = ret;
    
    // Encrypt packet
    
    rv = tp_packet_encrypt(&inbox, respbuf, rbuflen, hs_encrypt_key);
    if(rv != P_SUCCESS){
        printd("Packet encrypt failed, buflen: %d\n",buflen);
        status = -1004;
        goto cleanup;
    }
    status = 0;

cleanup:
    RSA_free(r);
    return status;
}

int tp_handshake_response_decrypt(uint8_t *outkeybuf, uint8_t *inkeybuf, uint32_t inkeylen, uint8_t *inbuf, uint32_t inlen, const char *psk){
    // Decrypt handshake response
    
    struct Box box;
    struct Packet pkt;
    pkt.box = &box;
    
    uint8_t hs_encrypt_key[EVP_MAX_MD_SIZE];
    tp_calc_encrypt_key(psk, hs_encrypt_key);
    
    int rv = tp_packet_decrypt(&pkt, inbuf, inlen, hs_encrypt_key);
    if(rv != P_SUCCESS){
        printd("Packet decrypt failed, rv: %d\n",rv);
        return rv;
    }
    
    if(box.type != PT_SERVER_HELLO || box.packet_id != 0){
        printd("Incorrect packet id %lld type %d for handshake\n",box.packet_id, box.type);
        return -1101;
    }
    
    // Decode RSA private key
    sodium_mprotect_readonly(inkeybuf);
    const unsigned char *ibptr = inkeybuf;
    RSA *r = d2i_RSAPrivateKey(NULL, &ibptr, inkeylen);
    if(!r){
        printd("Failed to decode rsa private key %d",inkeylen);
        return -1102;
    }
    
    int status = -1;
    
    int ret = RSA_private_decrypt(box.payload_length, box.payload, outkeybuf, r, RSA_PKCS1_PADDING);
    free(box.payload);
    if(ret < 0){
        printd("RSA decrypt failed with ret %d\n",ret);
        status = -1103;
        goto cleanup;
    }else if(ret != 32){
        printd("Key size %d may not suitable for encrypt\n",ret);
    }
    
    status = 0;
cleanup:
    RSA_free(r);
    sodium_mprotect_noaccess(inkeybuf);
    return status;
}