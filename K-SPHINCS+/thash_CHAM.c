//
// Created by Siwoo on 2022/01/12.
//
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "address.h"
#include "params.h"
#include "thash.h"
#include "cham.h"

static void sphincs_CHAM_thash(
        unsigned char *out, unsigned char *buf,
        const unsigned char *in, unsigned int inblocks,
        const unsigned char *pub_seed, uint32_t addr[8]) {

    memcpy(buf, pub_seed, sphincs_CHAM_N);
    sphincs_CHAM_addr_to_bytes(buf + sphincs_CHAM_N, addr);
    memcpy(buf + sphincs_CHAM_N + sphincs_CHAM_ADDR_BYTES, in, inblocks * sphincs_CHAM_N);
    
    tandm_cham(buf, (sphincs_CHAM_N + sphincs_CHAM_ADDR_BYTES + inblocks * sphincs_CHAM_N), out);
    
}

void sphincs_CHAM_thash_1(
        unsigned char *out, const unsigned char *in,
        const unsigned char *pub_seed, uint32_t addr[8],
        const hash_state *hash_state_seeded){

    unsigned char buf[sphincs_CHAM_N + sphincs_CHAM_ADDR_BYTES + 1 * sphincs_CHAM_N];
    sphincs_CHAM_thash(
            out, buf, in, 1, pub_seed, addr);

    (void)hash_state_seeded;  /* Avoid unused parameter warning. */
}

void sphincs_CHAM_thash_2(
        unsigned char *out, const unsigned char *in,
        const unsigned char *pub_seed, uint32_t addr[8],
        const hash_state *hash_state_seeded){

    unsigned char buf[sphincs_CHAM_N + sphincs_CHAM_ADDR_BYTES + 2 * sphincs_CHAM_N];
    sphincs_CHAM_thash(
            out, buf, in, 2, pub_seed, addr);

    (void)hash_state_seeded;  /* Avoid unused parameter warning. */
}

void sphincs_CHAM_thash_WOTS_LEN(
        unsigned char *out, const unsigned char *in,
        const unsigned char *pub_seed, uint32_t addr[8],
        const hash_state *hash_state_seeded){

    unsigned char buf[sphincs_CHAM_N + sphincs_CHAM_ADDR_BYTES + sphincs_CHAM_WOTS_LEN * sphincs_CHAM_N];
    sphincs_CHAM_thash(
            out, buf, in, sphincs_CHAM_WOTS_LEN, pub_seed, addr);

    (void)hash_state_seeded;  /* Avoid unused parameter warning. */
}

void sphincs_CHAM_thash_FORS_TREES(
        unsigned char *out, const unsigned char *in,
        const unsigned char *pub_seed, uint32_t addr[8],
        const hash_state *hash_state_seeded){

    unsigned char buf[sphincs_CHAM_N + sphincs_CHAM_ADDR_BYTES + sphincs_CHAM_FORS_TREES * sphincs_CHAM_N];
    sphincs_CHAM_thash(
            out, buf, in, sphincs_CHAM_FORS_TREES, pub_seed, addr);

    (void)hash_state_seeded;  /* Avoid unused parameter warning. */
}
