//
//  test_hs.c
//  typroto
//
//  Created by TYPCN on 2016/6/4.
//
//


#include "../src/typroto.h"
#include "../src/packet.h"
#include "../src/box.h"
#include "../src/handshake.h"
#include <sodium.h>
#include <time.h>
#include <string.h>
#include <assert.h>
#include <sys/resource.h>
#include <openssl/err.h>
#include <openssl/evp.h>

void test(){
    const char *psk = "123456";
    
    void *kb = sodium_malloc(8192);
    void *hsp = malloc(1400);
    int klen = tp_build_handshake_packet(kb, hsp, 1400, psk);
    assert(klen > 0);
    
    
    void *skb = malloc(32);
    void *rsp = malloc(1400);
    int rv = tp_build_handshake_packet_response(skb, rsp, 1400, hsp, 1400, psk);
    assert(rv == 0);

    void *outskb = malloc(32);
    rv = tp_handshake_response_decrypt(outskb, kb, klen, rsp, 1400, psk);
    assert(rv == 0);
    
    assert(sodium_memcmp(skb, outskb, 32) == 0);
    
    sodium_mprotect_readwrite(kb);
    sodium_free(kb);
    free(hsp);
    free(rsp);
    free(skb);
    free(outskb);
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
    for (int i = 0; i < 10; i++) {
        test();
    }
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
    ERR_remove_state(0);
    EVP_cleanup();
    getrusage(RUSAGE_SELF, memory);
    if(memory->ru_maxrss - init_memory > 600000){ // There are some leaks by openssl
        printf("Possible memory leak detected: init usage: %ld after: %ld\n",init_memory,memory->ru_maxrss);
        return -1;
    }
    return 0;
}