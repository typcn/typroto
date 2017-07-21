//
//  totp.h
//  typroto
//
//  Created by TYPCN on 2016/6/3.
//
//

#ifndef totp_h
#define totp_h

#include "common.h"


void hotp(const unsigned char *key, size_t keylen, uint64_t counter, int ndigits, char *buf10, char *buf16, size_t buflen);

void totp(const unsigned char *key, size_t keylen, int timeStep,  int ndigits, char *buf10, char *buf16, size_t buflen);

#endif /* totp_h */
