//
//  test_pkt.c
//  typroto
//
//  Created by TYPCN on 2016/6/3.
//
//


#include "../src/typroto.h"
#include "../src/packet.h"
#include "../src/box.h"
#include <sodium.h>
#include <time.h>
#include <string.h>
#include <assert.h>
#include <sys/resource.h>

void test(){
    unsigned char key[crypto_aead_chacha20poly1305_KEYBYTES];
    randombytes_buf(key, sizeof key);
    
    unsigned char *c = (unsigned char *)"Hello world";
    
    struct Box inbox;
    inbox.packet_id = 1;
    inbox.timestamp = time(NULL);
    inbox.type = 1;
    inbox.payload = c;
    inbox.payload_length = 11;
    
    uint8_t *inbuf = malloc(1400);
    
    printf("Start encrypt packet\n");
    
    int rv = tp_packet_encrypt(&inbox, inbuf, 1400, key);
    assert(rv == 0);
    
    printf("Packet encrypted\n");
    
    struct Box outbox;
    
    struct Packet outpkt;
    outpkt.box = &outbox;
    
    rv = tp_packet_decrypt(&outpkt, inbuf, 1400, key);
    assert(rv == 0);
    
    printf("Decrypted packet: %s\n",outpkt.box->payload);
    assert(memcmp(outpkt.box->payload, c, 11) == 0);
    free(outpkt.box->payload);
    free(inbuf);
}

int main(){
    int rv = tp_init();
    if(rv != 0){
        printf("Failed to init typroto\n");
        return -1;
    }
    struct rusage* memory = malloc(sizeof(struct rusage));
    getrusage(RUSAGE_SELF, memory);
    long init_memory = memory->ru_maxrss;
    for (int i = 0; i < 10000; i++) {
        test();
    }
    getrusage(RUSAGE_SELF, memory);
    if(memory->ru_maxrss - init_memory > 120000){
        printf("Possible memory leak detected: init usage: %ld after: %ld\n",init_memory,memory->ru_maxrss);
        return -1;
    }
    return 0;
}