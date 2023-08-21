//
//  lea.c
//  LEA_HASH
//
//  Created by Siwoo on 2022/01/06.
//

#include "lea.h"

u32 key_constant[8] = { 0xc3efe9db, 0x44626b02, 0x79e27c8a,
                        0x78df30ec, 0x715ea49e, 0xc785da0a,
                        0xe04ef22a, 0xe5c40957 };



u32 LEA_Rotation_L(u32 x, u8 n) { return (x<<n | x>>(32-n)); }
u32 LEA_Rotation_R(u32 x, u8 n) { return (x>>n | x<<(32-n)); }

void ROUND_KEY_GEN_128(u32 *mk, u32 *rk){
    u32 temp[4] = {0x00,};
    u8 i;

    for(i=0; i<4; i++) { temp[i] = mk[i]; }

    for(i=0; i<24; i++){
        temp[0] = LEA_Rotation_L((temp[0]+LEA_Rotation_L(key_constant[i%4], i+0)), 1);
        temp[1] = LEA_Rotation_L((temp[1]+LEA_Rotation_L(key_constant[i%4], i+1)), 3);
        temp[2] = LEA_Rotation_L((temp[2]+LEA_Rotation_L(key_constant[i%4], i+2)), 6);
        temp[3] = LEA_Rotation_L((temp[3]+LEA_Rotation_L(key_constant[i%4], i+3)), 11);
        rk[i*6] = temp[0];
        rk[i*6+1] = temp[1];
        rk[i*6+2] = temp[2];
        rk[i*6+3] = temp[1];
        rk[i*6+4] = temp[3];
        rk[i*6+5] = temp[1];
    }
}

void ROUND_KEY_GEN_256(u32 *mk, u32 *rk){
    u32 temp[8] = {0x00,};
    u8 i;

    for(i=0; i<8; i++) { temp[i] = mk[i]; }

    for(i=0; i<32; i++){
        temp[(6*i)%8] = LEA_Rotation_L((temp[(6*i)%8]+LEA_Rotation_L(key_constant[i%8], i+0)), 1);
        temp[(6*i+1)%8] = LEA_Rotation_L((temp[(6*i+1)%8]+LEA_Rotation_L(key_constant[i%8], i+1)), 3);
        temp[(6*i+2)%8] = LEA_Rotation_L((temp[(6*i+2)%8]+LEA_Rotation_L(key_constant[i%8], i+2)), 6);
        temp[(6*i+3)%8] = LEA_Rotation_L((temp[(6*i+3)%8]+LEA_Rotation_L(key_constant[i%8], i+3)), 11);
        temp[(6*i+4)%8] = LEA_Rotation_L((temp[(6*i+4)%8]+LEA_Rotation_L(key_constant[i%8], i+4)), 13);
        temp[(6*i+5)%8] = LEA_Rotation_L((temp[(6*i+5)%8]+LEA_Rotation_L(key_constant[i%8], i+5)), 17);
        
        rk[i*6] = temp[(6*i)%8];
        rk[i*6+1] = temp[(6*i+1)%8];
        rk[i*6+2] = temp[(6*i+2)%8];
        rk[i*6+3] = temp[(6*i+3)%8];
        rk[i*6+4] = temp[(6*i+4)%8];
        rk[i*6+5] = temp[(6*i+5)%8];
    }
}

void LEA_ENC(u32 *INPUT, u32 *rk, u32 *OUTPUT){
    u8 i;
    u32 temp;
    
    for(i=0; i<4; i++) OUTPUT[i] = INPUT[i];
    
    for(i=0; i<32; i++){
        temp = OUTPUT[0];
        OUTPUT[0] = LEA_Rotation_L(((OUTPUT[0]^rk[i*6])+(OUTPUT[1]^rk[(i*6)+1])), 9);
        OUTPUT[1] = LEA_Rotation_R(((OUTPUT[1]^rk[(i*6)+2])+(OUTPUT[2]^rk[(i*6)+3])), 5);
        OUTPUT[2] = LEA_Rotation_R(((OUTPUT[2]^rk[(i*6)+4])+(OUTPUT[3]^rk[(i*6)+5])), 3);
        OUTPUT[3] = temp;
    }
}

void LEA_tandm_init_key(u32 *Front, u32 *back, u32 *key){
    key[0] = Front[0];
    key[1] = Front[1];
    key[2] = Front[2];
    key[3] = Front[3];
    key[4] = back[0];
    key[5] = back[1];
    key[6] = back[2];
    key[7] = back[3];
}

void tandm_lea(unsigned char *msg, unsigned long long msgLen, u32 *output_HASH){
   // u32 msgLen = (u32)strlen(msg); //msg len byte
  //  printf("\nmsgLen = %d\n", msgLen);

//    printf("LEA in : ");
//    for(int i = 0; i<msgLen; i++) printf("%02X ", msg[i]);
//    printf("\n");
    
    u32 loop_len = msgLen / 16;
//    printf("loop_len = %d\n", loop_len);
    
    u32 key[8] = {0x0,};
    u32 roundkey[192] = {0x0,};
    u32 H[4] = {0x1A2A3A4A, 0x1B2B3B4B, 0x1C2C3C4C, 0x1D2D3D4D};
    u32 W[4] = {0x0,};
    u32 G[4] = {0x12312312, 0x29292031, 0x28940321, 0x2AFC2D3A};
    u32 temp[4] = {0x0, };
    
    temp[0] = (u32)msg[0]|((u32)msg[1]<<8)|((u32)msg[2]<<16)|((u32)msg[3]<<24);
    temp[1] = (u32)msg[4]|((u32)msg[5]<<8)|((u32)msg[6]<<16)|((u32)msg[7]<<24);
    temp[2] = (u32)msg[8]|((u32)msg[9]<<8)|((u32)msg[10]<<16)|((u32)msg[11]<<24);
    temp[3] = (u32)msg[12]|((u32)msg[13]<<8)|((u32)msg[14]<<16)|((u32)msg[15]<<24);
    
    for(int loop=1; loop<loop_len+1; loop++){
        LEA_tandm_init_key(G, temp, key);
        ROUND_KEY_GEN_256(key, roundkey);
        LEA_ENC(H, roundkey, W);
        LEA_tandm_init_key(temp, W, key);
        ROUND_KEY_GEN_256(key, roundkey);
        LEA_ENC(G, roundkey, temp);
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

