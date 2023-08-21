//
//  cham.c
//  CHAM_HASH
//
//  Created by Siwoo on 2022/01/06.
//

#include "cham.h"

u32 CHAM_Rotation_L(u32 x, u8 n) { return (x<<n | x>>(32-n)); }
u32 CHAM_Rotation_R(u32 x, u8 n) { return (x>>n | x<<(32-n)); }

void CHAM_ROUND_KEY_GEN(u32 *mk, u32 *rk){
    for(int i=0; i<KEY_SIZE/WORD_SIZE; i++){
        rk[i] = mk[i] ^ CHAM_Rotation_L(mk[i], 1) ^ CHAM_Rotation_L(mk[i], 8);
        rk[(i+KEY_SIZE/WORD_SIZE)^1] = mk[i] ^ CHAM_Rotation_L(mk[i], 1) ^ CHAM_Rotation_L(mk[i], 11);
    }
}

void CHAM_ENC(u32 *INPUT, u32 *roundkey, u32 *OUTPUT){
    u32 temp;
    for(int i=0; i<4; i++) OUTPUT[i] = INPUT[i];
    
    for(int i=0; i<ROUND_LOOP; i++){
        if(i%2==0){
            temp = CHAM_Rotation_L((OUTPUT[0]^i) + (CHAM_Rotation_L(OUTPUT[1], 1) ^ roundkey[i%(2*KEY_SIZE/WORD_SIZE)]), 8);
            OUTPUT[0] = OUTPUT[1];
            OUTPUT[1] = OUTPUT[2];
            OUTPUT[2] = OUTPUT[3];
            OUTPUT[3] = temp;
        }
        else {
            temp = CHAM_Rotation_L((OUTPUT[0]^i) + (CHAM_Rotation_L(OUTPUT[1], 8) ^ roundkey[i%(2*KEY_SIZE/WORD_SIZE)]), 1);
            OUTPUT[0] = OUTPUT[1];
            OUTPUT[1] = OUTPUT[2];
            OUTPUT[2] = OUTPUT[3];
            OUTPUT[3] = temp;
        }
    }
}

void CHAM_tandm_init_key(u32 *Front, u32 *back, u32 *key){
    key[0] = Front[0];
    key[1] = Front[1];
    key[2] = Front[2];
    key[3] = Front[3];
    key[4] = back[0];
    key[5] = back[1];
    key[6] = back[2];
    key[7] = back[3];
}
void tandm_cham_ref(char *msg, u32 *output_HASH){

//void tandm_cham(char *msg, unsigned long long msgLen, u32 *output_HASH){
    //u32 msgLen = (u32)strlen(msg); //msg len byte
    unsigned long long msgLen = 32;
    printf("\nmsgLen = %d\n", msgLen);
    
    u32 loop_len = msgLen / 16;
    printf("loop_len = %d\n", loop_len);
    
    u32 key[8] = {0x0,};
    u32 roundkey[16] = {0x0,};
    u32 H[4] = {0x1A2A3A4A, 0x1B2B3B4B, 0x1C2C3C4C, 0x1D2D3D4D};
    u32 W[4] = {0x0,};
    u32 G[4] = {0x12312312, 0x29292031, 0x28940321, 0x2AFC2D3A};
    u32 temp[4] = {0x0, };
    
    temp[0] = (u32)msg[0]|((u32)msg[1]<<8)|((u32)msg[2]<<16)|((u32)msg[3]<<24);
    temp[1] = (u32)msg[4]|((u32)msg[5]<<8)|((u32)msg[6]<<16)|((u32)msg[7]<<24);
    temp[2] = (u32)msg[8]|((u32)msg[9]<<8)|((u32)msg[10]<<16)|((u32)msg[11]<<24);
    temp[3] = (u32)msg[12]|((u32)msg[13]<<8)|((u32)msg[14]<<16)|((u32)msg[15]<<24);
    
    for(int loop=1; loop<loop_len+1; loop++){
        CHAM_tandm_init_key(G, temp, key);
        CHAM_ROUND_KEY_GEN(key, roundkey);
        CHAM_ENC(H, roundkey, W);
        CHAM_tandm_init_key(temp, W, key);
        CHAM_ROUND_KEY_GEN(key, roundkey);
        CHAM_ENC(G, roundkey, temp);
        H[0] ^= W[0]; H[1] ^= W[1]; H[2] ^= W[2]; H[3] ^= W[3];
        G[0] ^= temp[0]; G[1] ^= temp[1]; G[2] ^= temp[2]; G[3] ^= temp[3];
        
        if(loop!=loop_len){
            temp[0] = (u32)msg[loop*16]|((u32)msg[loop*16+1]<<8)|((u32)msg[loop*16+2]<<16)|((u32)msg[loop*16+3]<<24);
            temp[1] = (u32)msg[loop*16+4]|((u32)msg[loop*16+5]<<8)|((u32)msg[loop*16+6]<<16)|((u32)msg[loop*16+7]<<24);
            temp[2] = (u32)msg[loop*16+8]|((u32)msg[loop*16+9]<<8)|((u32)msg[loop*16+10]<<16)|((u32)msg[loop*16+11]<<24);
            temp[3] = (u32)msg[loop*16+12]|((u32)msg[loop*16+13]<<8)|((u32)msg[loop*16+14]<<16)|((u32)msg[loop*16+15]<<24);
        }
    }
    
    output_HASH[0] = H[0];
    output_HASH[1] = H[1];
    output_HASH[2] = H[2];
    output_HASH[3] = H[3];
    output_HASH[4] = G[0];
    output_HASH[5] = G[1];
    output_HASH[6] = G[2];
    output_HASH[7] = G[3];
    
}

void tandm_cham(unsigned char *msg, unsigned long long msgLen, u32 *output_HASH){
    //printf("\nmsgLen = %lld\n", msgLen);
    
   // printf("Cham in : ");
   // for(int i = 0; i<msgLen; i++) printf("%02X ", msg[i]);
   // printf("\n");
    
    
    u32 loop_len = msgLen / 16;
   // printf("loop_len = %d\n", loop_len);
    
    u32 key[8] = {0x0,};
    u32 roundkey[16] = {0x0,};
    u32 H[4] = {0x1A2A3A4A, 0x1B2B3B4B, 0x1C2C3C4C, 0x1D2D3D4D};
    u32 W[4] = {0x0,};
    u32 G[4] = {0x12312312, 0x29292031, 0x28940321, 0x2AFC2D3A};
    u32 temp[4] = {0x0, };
    
    temp[0] = (u32)msg[0]|((u32)msg[1]<<8)|((u32)msg[2]<<16)|((u32)msg[3]<<24);
    temp[1] = (u32)msg[4]|((u32)msg[5]<<8)|((u32)msg[6]<<16)|((u32)msg[7]<<24);
    temp[2] = (u32)msg[8]|((u32)msg[9]<<8)|((u32)msg[10]<<16)|((u32)msg[11]<<24);
    temp[3] = (u32)msg[12]|((u32)msg[13]<<8)|((u32)msg[14]<<16)|((u32)msg[15]<<24);
    
    for(int loop=1; loop<loop_len+1; loop++){
        CHAM_tandm_init_key(G, temp, key);
        CHAM_ROUND_KEY_GEN(key, roundkey);
        CHAM_ENC(H, roundkey, W);
        CHAM_tandm_init_key(temp, W, key);
        CHAM_ROUND_KEY_GEN(key, roundkey);
        CHAM_ENC(G, roundkey, temp);
        H[0] ^= W[0]; H[1] ^= W[1]; H[2] ^= W[2]; H[3] ^= W[3];
        G[0] ^= temp[0]; G[1] ^= temp[1]; G[2] ^= temp[2]; G[3] ^= temp[3];
        
        if(loop!=loop_len){
            temp[0] = (u32)msg[loop*16]|((u32)msg[loop*16+1]<<8)|((u32)msg[loop*16+2]<<16)|((u32)msg[loop*16+3]<<24);
            temp[1] = (u32)msg[loop*16+4]|((u32)msg[loop*16+5]<<8)|((u32)msg[loop*16+6]<<16)|((u32)msg[loop*16+7]<<24);
            temp[2] = (u32)msg[loop*16+8]|((u32)msg[loop*16+9]<<8)|((u32)msg[loop*16+10]<<16)|((u32)msg[loop*16+11]<<24);
            temp[3] = (u32)msg[loop*16+12]|((u32)msg[loop*16+13]<<8)|((u32)msg[loop*16+14]<<16)|((u32)msg[loop*16+15]<<24);
        }
    }
    
    output_HASH[0] = H[0];
    output_HASH[1] = H[1];
    output_HASH[2] = H[2];
    output_HASH[3] = H[3];
    output_HASH[4] = G[0];
    output_HASH[5] = G[1];
    output_HASH[6] = G[2];
    output_HASH[7] = G[3];
    
}
