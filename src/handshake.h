//
//  handshake.h
//  typroto
//
//  Created by TYPCN on 2016/6/4.
//
//

#ifndef handshake_h
#define handshake_h

#include "common.h"

#define TP_RSA_KEY_BITS 4096

/** @brief Calc encryption key for handshake packet
 *
 *  @param psk The pre-shared key
 *  @param buf Key buffer ( 32 bytes )
 */
void tp_calc_encrypt_key(const char *psk, uint8_t *buf);

/** @brief Build a handshake request
 *
 *  This function should never fail, if -1 is returned , please build with debug mode and watch logs
 *
 *  @param keybuf Output private key buffer, the buffer must be allocated with sodium_malloc
 *  @param databuf Output packet data buffer
 *  @param buflen Length of output packet buffer
 *  @return size of private key , -1 for fail
 */
int tp_build_handshake_packet(uint8_t *keybuf, uint8_t *databuf, uint32_t buflen, const char *psk);

/** @brief Decode handshake request and build a reply
 *
 *  If return value is not 0 , free your all buf , and do not reply anything to client
 *  Error codes may in enum PKT_ERROR
 *
 *  @param outkeybuf New symmetry key output buffer ( 32 bytes )
 *  @param respbuf Output response packet buffer
 *  @param rbuflen Length of response buffer
 *  @param databuf Input packet data buffer
 *  @param buflen Length of input packet buffer
 *  @return 0 for success , other for fail
 */
int tp_build_handshake_packet_response(uint8_t *outkeybuf, uint8_t *respbuf, uint32_t rbuflen, uint8_t *databuf, uint32_t buflen, const char *psk);

/** @brief Decrypt a handshake response
 *
 *  @param outkeybuf New symmetry key output buffer ( 32 byte )
 *  @param inkeybuf Keybuf of build_handshake_packet
 *  @param inkeylen Return value of build_handshake_packet
 *  @param inbuf Input data
 *  @param inlen Input data length
 *  @return 0 for success , other for fail
 */
int tp_handshake_response_decrypt(uint8_t *outkeybuf, uint8_t *inkeybuf, uint32_t inkeylen,uint8_t *inbuf, uint32_t inlen, const char *psk);

#endif /* handshake_h */
