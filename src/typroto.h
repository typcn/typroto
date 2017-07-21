//
//  typroto.h
//  typroto
//
//  Created by TYPCN on 2016/6/3.
//
//

#ifndef typroto_h
#define typroto_h
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#endif
#include <stdint.h>

// 1 type + 4 timestamp + 8 packetid + 2 payload length + 8 nonce + 16 tag
#define PROTOCOL_ABYTE 39

#ifdef __cplusplus
extern "C" {
#endif

    /** @brief Init typroto
     *
     *  @return 0 for success
     */
    int tp_init();

    /** @brief Create fd
     *
     *  @return fd
     */
    int tp_socket(int af);
    
    /** @brief Connect to server
     *
     *  @param sockfd fd
     *  @param pktSize size per packet ( all packets will be padding to this size to avoid detection )
     *  @param key Pre-shared key
     *  @param addr Server addr
     *  @param addrlen Server addr len
     *  @return 0 for success
     */
    int tp_connect(int sockfd, int pktSize, const char *key, const struct sockaddr *addr, socklen_t addrlen);

    /** @brief Listen to address
     *
     *  @param sockfd fd
     *  @param addr Server addr
     *  @param addrlen Server addr len
     *  @return same as bind()
     */
    int tp_listen(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
    
    /** @brief Waiting for a incoming connection
     *
     *  Return value can be PKT_ERROR and :
     *  -1001 (Incorrect type )
     *  -1002 (Fail to decode public key)
     *  -1003 (Fail to encrypt key)
     *  -1004 (Fail to build packet)
     *
     *  @param sockfd fd
     *  @param pktSize Paket Size , need to same as client
     *  @param key Pre-shared key
     *  @param addr Incoming client addr ( writeable )
     *  @param addrlen Addr len  ( writeable )
     *  @return 0 for success
     */
    int tp_accept(int sockfd, int pktSize, const char *key, struct sockaddr *addr, socklen_t *addrlen);
    
    /** @brief Send some data
     *
     *  Push the packet to queue , and waiting for send.
     *  If return value is 0 , the buf will be freed after ACK
     *
     *  Will block on buffer full
     *
     *  @param sockfd fd
     *  @param buf Buffer to send
     *  @param len Buffer length ( must < pktSize - PROTOCOL_ABYTE )
     *  @return 0 for success, -1 Invalid fd
     */
    int tp_send(int sockfd, uint8_t *buf, size_t len);
    
    
    // Not need to say
    typedef void (*recv_cb_t)(int fd, const uint8_t *buf, uint32_t len, const struct sockaddr* addr, socklen_t addrlen, void *userdata);
    
    int tp_set_recv_callback(int sockfd, recv_cb_t cb, void *userdata);
    
    
    /** @brief Event callback function
     *
     *  Code can be PKT_ERROR, errno and:
     *  -2001 Invalid packet size
     *  -2002 Long time no ACK
     *
     *  @param fd FD
     *  @param code Error code
     *  @param addr Incoming client addr
     *  @param addrlen Addr len
     */
    typedef void (*event_cb_t)(int fd, int code, const char* msg,const struct sockaddr* addr, socklen_t addrlen, void *userdata);
    
    int tp_set_event_callback(int sockfd, event_cb_t cb, void *userdata);
    
    int tp_shutdown(int sockfd);
#ifdef __cplusplus
}
#endif

#endif /* typroto_h */
