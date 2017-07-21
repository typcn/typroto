//
//  gen_key.c
//  typroto
//
//  Created by TYPCN on 2016/6/8.
//
//

#include <stdio.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/rand.h>
#include <stdint.h>
#include <stdlib.h>

int write_file(const char* name, const uint8_t *buf, uint32_t size){
    int rv = -1;
    FILE *file;
    file = fopen(name, "w");
    if (file) {
        fwrite(&size, 4, 1, file);
        fwrite(buf, size, 1, file);
        rv = 0;
        fclose(file);
    }
    return rv;
}


int main(int argc, char *argv[]){
    if(argc < 2){
        printf("Usage: ./gen_key LENGTH_BITS\n");
        return -1;
    }
    int kb = atoi(argv[1]);
    if(kb < 1024){
        printf("At least 1024 bits\n");
        return -1;
    }else if(kb < 4096){
        printf("We suggest you use > 4096 bits key\n");
    }
    
    printf("Generating %d bits RSA keypair\n",kb);

    RSA *rsa_o = RSA_new();
    BIGNUM *big_number = BN_new();
    BN_set_word(big_number , RSA_F4);
    int ret = RSA_generate_key_ex(rsa_o, kb, big_number, NULL);
    if(ret != 1){
        printf("RSA keypair generate failed with ret %d\n",ret);
        return -1;
    }
    
    uint8_t *private_key = NULL;
    int private_key_length = i2d_RSAPrivateKey(rsa_o, &private_key);
    write_file("rsa_priv", private_key, private_key_length);
    
    uint8_t *public_key = NULL;
    int public_key_length = i2d_RSAPublicKey(rsa_o, &public_key);
    write_file("rsa_pub", public_key, public_key_length);
}