//
//  lea.h
//  LEA_HASH
//
//  Created by Siwoo on 2022/01/06.
//

#ifndef lea_h
#define lea_h

#include <stdio.h>
#include <string.h>
#include "common_typedef.h"



void ROUND_KEY_GEN_128(u32 *mk, u32 *rk);
void ROUND_KEY_GEN_256(u32 *mk, u32 *rk);
void LEA_ENC(u32 *INPUT, u32 *rk, u32 *OUTPUT);
void LEA_tandm_init_key(u32 *Front, u32 *back, u32 *key);
void tandm_lea(unsigned char *msg, unsigned long long msgLen, u32 *output_HASH);

#endif /* lea_h */

