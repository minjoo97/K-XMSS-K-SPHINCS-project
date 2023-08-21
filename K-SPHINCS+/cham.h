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

#define sphincs_CHAM_OUTPUT_BYTES 32
#define sphincs_CHAM_BLOCK_BYTES 16

typedef struct chamctx{
    
}chamctx;

u32 ROL(u32 x, u8 n);
u32 ROR(u32 x, u8 n);

void ROUND_KEY_GEN(u32 *mk, u32 *rk);
void ENC(u32 *INPUT, u32 *roundkey, u32 *OUTPUT);
void tandm_init_key(u32 *Front, u32 *back, u32 *key);
void tandm_cham(unsigned char *msg, size_t msgLen, u8 *output);

void sphincs_CHAM_mgf1(
    unsigned char *out, unsigned long outlen,
                         unsigned char *input_plus_four_bytes, unsigned long inlen);

#endif /* cham_h */
