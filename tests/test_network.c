
#include <pthread.h>
#include <stdlib.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#include <string.h>
#include "../src/typroto.h"
#include "../src/socks.h"

#define TEST_BIND_TO "127.0.0.1"
#define TEST_PORT 29910

void printHex(int x, uint8_t *buf){
    int i;
    for (i = 0; i < x; i++)
    {
        if (i > 0) printf(":");
        printf("%02X", buf[i]);
    }
    printf("\n");
}

void recvcb(int fd, const uint8_t *buf, uint32_t len, const struct sockaddr* addr, socklen_t addrlen, void *userdata){
    const struct sockaddr_in *iaddr = (const struct sockaddr_in *)addr;
    printf("[Fd %d] Got a packet from %s:%d : %s\n",fd, inet_ntoa(iaddr->sin_addr), ntohs(iaddr->sin_port),  buf);
}

void evtcb(int fd, int code, const char* msg,const struct sockaddr* addr, socklen_t addrlen, void *userdata){
    const struct sockaddr_in *iaddr = (const struct sockaddr_in *)addr;
    printf("[Fd %d] Event %d from %s:%d : %s\n",fd, code , inet_ntoa(iaddr->sin_addr), ntohs(iaddr->sin_port),  msg);
}


void *client(){
    struct sockaddr_in addr;
    socklen_t slen = sizeof(addr);
    memset((void *) &addr, 0, slen);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(TEST_PORT);
    inet_aton(TEST_BIND_TO, &addr.sin_addr);
    
    int fd = tp_socket(AF_INET);
    printf("[Client] Got fd %d, Ready to connect %s:%d\n",fd, TEST_BIND_TO,TEST_PORT);
    int rv = tp_connect(fd, 1400, "123456", (const struct sockaddr*)&addr, slen);
    printf("[Client] connect() returned %d\n",rv);
    tp_set_recv_callback(fd, recvcb, NULL);
    tp_set_event_callback(fd, evtcb, NULL);
    
    const struct Socket *skt = tp_get_sock_by_id(fd);
    printf("[Client] Size per packet: %d Transfer Key: ",skt->packet_size);
    printHex(32,skt->transfer_key);

    char *c = "Hello world packet from client";
    uint8_t *data_to_send = malloc(strlen(c));
    memcpy(data_to_send, c, strlen(c));
    tp_send(fd, data_to_send, strlen(c));
    sleep(5);
    tp_shutdown(fd);
    return NULL;
}

void *server(){
    int fd = tp_socket(AF_INET);
    printf("[Server] Got fd %d, Ready to listen %s:%d\n",fd, TEST_BIND_TO,TEST_PORT);
    struct sockaddr_in addr;
    socklen_t slen = sizeof(addr);
    memset((void *) &addr, 0, slen);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(TEST_PORT);
    inet_aton(TEST_BIND_TO, &addr.sin_addr);
    
    tp_listen(fd, (const struct sockaddr*)&addr, slen);
    for (int i = 0;i < 100;i++) {
        struct sockaddr_in incoming_addr;
        socklen_t slen = sizeof(incoming_addr);
        int rv = tp_accept(fd, 1400, "123456", (struct sockaddr *)&incoming_addr,&slen);
        if(rv != 0){
            printf("[Server] Invalid packet from %s:%d, Code %d\n",
                                inet_ntoa(incoming_addr.sin_addr), ntohs(incoming_addr.sin_port), rv);
            continue;
        }
        tp_set_recv_callback(fd, recvcb, NULL);
        tp_set_event_callback(fd, evtcb, NULL);
        printf("[Server] Accepted a connection from %s:%d\n",
               inet_ntoa(incoming_addr.sin_addr), ntohs(incoming_addr.sin_port));
        const struct Socket *skt = tp_get_sock_by_id(fd);
        printf("[Server] Size per packet: %d Transfer Key: ",skt->packet_size);
        printHex(32,skt->transfer_key);
        
        char *c = "Hello world packet from server";
        uint8_t *data_to_send = malloc(strlen(c));
        memcpy(data_to_send, c, strlen(c));
        tp_send(fd, data_to_send, strlen(c));
        sleep(5);
        tp_shutdown(fd);
        return NULL;
    }
    printf("[Server] Unable to get connection");
    exit(-1);
    return NULL;
}

int main(int argc, char *argv[]){
    printf("Starting TYProto test\n");
    int rv = tp_init();
    if(rv != 0){
        printf("Failed to init typroto\n");
        return -1;
    }
    pthread_t server_t;
    pthread_create(&server_t, NULL, server, NULL);
    sleep(1);
    pthread_t client_t;
    pthread_create(&client_t, NULL, client, NULL);
    pthread_join(server_t, NULL);
}