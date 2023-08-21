//
//  cham.h
//  CHAM_HASH
//
//  Created by Siwoo on 2022/01/06.
//

#ifndef cham_h
#define cham_h

#include <stdio.h>
#include <string.h>
#include "common_typedef.h"

//CHAM-128-256
#define KEY_SIZE 256
#define WORD_SIZE 32
#define ROUND_LOOP 120


void CHAM_ROUND_KEY_GEN(u32 *mk, u32 *rk);
void CHAM_ENC(u32 *INPUT, u32 *roundkey, u32 *OUTPUT);
void CHAM_tandm_init_key(u32 *Front, u32 *back, u32 *key);
void tandm_cham_ref(char *msg, u32 *output_HASH);
void tandm_cham(unsigned char *msg, unsigned long long msgLen, u32 *output_HASH);
#endif /* cham_h */
