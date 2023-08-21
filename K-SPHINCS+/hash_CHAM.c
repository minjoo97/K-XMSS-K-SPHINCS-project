#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#include "address.h"
#include "cham.h"
#include "hash.h"
#include "params.h"
#include "utils.h"

#include "hash_state.h"

#include <stddef.h>
#include <stdint.h>

void sphincs_CHAM_initialize_hash_function(
        hash_state *hash_state_seeded,
        const unsigned char *pub_seed, const unsigned char *sk_seed){
    (void)hash_state_seeded;
    (void)pub_seed;
    (void)sk_seed;
}

void sphincs_CHAM_destroy_hash_function(hash_state *hash_state_seeded){
    (void)hash_state_seeded;
}

//sphincs_CHAM_haraka_S_inc_absorb(s_inc, sk_prf, sphincs_CHAM_N, hash_state_seeded);

void sphincs_CHAM_prf_addr(
        unsigned char *out, const unsigned char *key, const uint32_t addr[8],
        const hash_state *hash_state_seeded){
    unsigned char buf[sphincs_CHAM_N+sphincs_CHAM_ADDR_BYTES];
    /* Since sphincs_CHAM_N may be smaller than 32, we need a temporary buffer. */

    memcpy(buf, key, sphincs_CHAM_N);
    sphincs_CHAM_addr_to_bytes(buf+sphincs_CHAM_N, addr);

    tandm_cham(buf, (sphincs_CHAM_N+sphincs_CHAM_ADDR_BYTES), out);

}

void sphincs_CHAM_gen_message_random(
        unsigned char *R,
        const unsigned char *sk_prf, const unsigned char *optrand,
        const unsigned char *m, size_t mlen,
        const hash_state *hash_state_seeded){
    unsigned char buf[sphincs_CHAM_N*2+mlen];
    memcpy(buf, sk_prf, sphincs_CHAM_N);
    memcpy(buf+sphincs_CHAM_N, optrand, sphincs_CHAM_N);
    memcpy(buf+sphincs_CHAM_N*2, m, mlen);
    tandm_cham(buf, (sphincs_CHAM_N*2+mlen), R);

}

void sphincs_CHAM_hash_message(
        unsigned char *digest, uint64_t *tree, uint32_t *leaf_idx,
        const unsigned char *R, const unsigned char *pk,
        const unsigned char *m, size_t mlen,
        const hash_state *hash_state_seeded){

#define sphincs_CHAM_TREE_BITS (sphincs_CHAM_TREE_HEIGHT * (sphincs_CHAM_D - 1))
#define sphincs_CHAM_TREE_BYTES ((sphincs_CHAM_TREE_BITS + 7) / 8)
#define sphincs_CHAM_LEAF_BITS sphincs_CHAM_TREE_HEIGHT
#define sphincs_CHAM_LEAF_BYTES ((sphincs_CHAM_LEAF_BITS + 7) / 8)
#define sphincs_CHAM_DGST_BYTES (sphincs_CHAM_FORS_MSG_BYTES + sphincs_CHAM_TREE_BYTES + sphincs_CHAM_LEAF_BYTES)
    
    unsigned char seed[sphincs_CHAM_OUTPUT_BYTES + 4];
    
#define sphincs_CHAM_INBLOCKS (((sphincs_CHAM_N + sphincs_CHAM_PK_BYTES + sphincs_CHAM_BLOCK_BYTES - 1) & \
        -sphincs_CHAM_BLOCK_BYTES) / sphincs_CHAM_BLOCK_BYTES)
    unsigned char inbuf[sphincs_CHAM_N+sphincs_CHAM_PK_BYTES+mlen];
    
    unsigned char buf[sphincs_CHAM_DGST_BYTES];
    unsigned char *bufp = buf;

    memcpy(inbuf, R, sphincs_CHAM_N);
    memcpy(inbuf + sphincs_CHAM_N, pk, sphincs_CHAM_PK_BYTES);
    
    if (sphincs_CHAM_N + sphincs_CHAM_PK_BYTES + mlen < sphincs_CHAM_INBLOCKS * sphincs_CHAM_BLOCK_BYTES){
        memcpy(inbuf + sphincs_CHAM_N + sphincs_CHAM_PK_BYTES, m, mlen);
        tandm_cham(inbuf, sphincs_CHAM_N + sphincs_CHAM_PK_BYTES + mlen, seed);
    }
    else {
        memcpy(inbuf + sphincs_CHAM_N + sphincs_CHAM_PK_BYTES, m,
               sphincs_CHAM_INBLOCKS * sphincs_CHAM_BLOCK_BYTES - sphincs_CHAM_N - sphincs_CHAM_PK_BYTES);
        m += sphincs_CHAM_INBLOCKS * sphincs_CHAM_BLOCK_BYTES - sphincs_CHAM_N - sphincs_CHAM_PK_BYTES;
        mlen -= sphincs_CHAM_INBLOCKS * sphincs_CHAM_BLOCK_BYTES - sphincs_CHAM_N - sphincs_CHAM_PK_BYTES;
        
        unsigned char temp[sphincs_CHAM_INBLOCKS+mlen];
        memcpy(temp, inbuf, sphincs_CHAM_INBLOCKS);
        memcpy(temp+sphincs_CHAM_INBLOCKS, m, mlen);
        
        tandm_cham(temp, sphincs_CHAM_INBLOCKS+mlen, seed);
    }
    sphincs_CHAM_mgf1(bufp, sphincs_CHAM_DGST_BYTES, seed, sphincs_CHAM_OUTPUT_BYTES);
    
    memcpy(digest, bufp, sphincs_CHAM_FORS_MSG_BYTES);
    bufp += sphincs_CHAM_FORS_MSG_BYTES;

    *tree = sphincs_CHAM_bytes_to_ull(bufp, sphincs_CHAM_TREE_BYTES);
    *tree &= (~(uint64_t)0) >> (64 - sphincs_CHAM_TREE_BITS);
    bufp += sphincs_CHAM_TREE_BYTES;

    *leaf_idx = (uint32_t)sphincs_CHAM_bytes_to_ull(
            bufp, sphincs_CHAM_LEAF_BYTES);
    *leaf_idx &= (~(uint32_t)0) >> (32 - sphincs_CHAM_LEAF_BITS);
}


