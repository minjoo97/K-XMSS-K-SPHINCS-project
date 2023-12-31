#include <stdint.h>
#include <string.h>

#include "address.h"
#include "hash.h"
#include "hash_state.h"
#include "params.h"
#include "thash.h"
#include "utils.h"
#include "wots.h"

// TODO clarify address expectations, and make them more uniform.
// TODO i.e. do we expect types to be set already?
// TODO and do we expect modifications or copies?

/**
 * Computes the starting value for a chain, i.e. the secret key.
 * Expects the address to be complete up to the chain address.
 */
static void wots_gen_sk(unsigned char *sk, const unsigned char *sk_seed,
                        uint32_t wots_addr[8],
                        const hash_state *hash_state_seeded) {
    /* Make sure that the hash address is actually zeroed. */
    sphincs_CHAM_set_hash_addr(wots_addr, 0);

    /* Generate sk element. */
    sphincs_CHAM_prf_addr(sk, sk_seed, wots_addr, hash_state_seeded);
}

/**
 * Computes the chaining function.
 * out and in have to be n-byte arrays.
 *
 * Interprets in as start-th value of the chain.
 * addr has to contain the address of the chain.
 */
static void gen_chain(unsigned char *out, const unsigned char *in,
                      unsigned int start, unsigned int steps,
                      const unsigned char *pub_seed, uint32_t addr[8],
                      const hash_state *hash_state_seeded) {
    uint32_t i;

    /* Initialize out with the value at position 'start'. */
    memcpy(out, in, sphincs_CHAM_N);

    /* Iterate 'steps' calls to the hash function. */
    for (i = start; i < (start + steps) && i < sphincs_CHAM_WOTS_W; i++) {
        sphincs_CHAM_set_hash_addr(addr, i);
        sphincs_CHAM_thash_1(
            out, out, pub_seed, addr, hash_state_seeded);
    }
}

/**
 * base_w algorithm as described in draft.
 * Interprets an array of bytes as integers in base w.
 * This only works when log_w is a divisor of 8.
 */
static void base_w(unsigned int *output, const size_t out_len,
                   const unsigned char *input) {
    size_t in = 0;
    size_t out = 0;
    unsigned char total = 0;
    unsigned int bits = 0;
    size_t consumed;

    for (consumed = 0; consumed < out_len; consumed++) {
        if (bits == 0) {
            total = input[in];
            in++;
            bits += 8;
        }
        bits -= sphincs_CHAM_WOTS_LOGW;
        output[out] = (unsigned int)((total >> bits) & (sphincs_CHAM_WOTS_W - 1));
        out++;
    }
}

/* Computes the WOTS+ checksum over a message (in base_w). */
static void wots_checksum(unsigned int *csum_base_w,
                          const unsigned int *msg_base_w) {
    unsigned int csum = 0;
    unsigned char csum_bytes[(sphincs_CHAM_WOTS_LEN2 * sphincs_CHAM_WOTS_LOGW + 7) / 8];
    unsigned int i;

    /* Compute checksum. */
    for (i = 0; i < sphincs_CHAM_WOTS_LEN1; i++) {
        csum += sphincs_CHAM_WOTS_W - 1 - msg_base_w[i];
    }

    /* Convert checksum to base_w. */
    /* Make sure expected empty zero bits are the least significant bits. */
    csum = csum << (8 - ((sphincs_CHAM_WOTS_LEN2 * sphincs_CHAM_WOTS_LOGW) % 8));
    sphincs_CHAM_ull_to_bytes(
        csum_bytes, sizeof(csum_bytes), csum);
    base_w(csum_base_w, sphincs_CHAM_WOTS_LEN2, csum_bytes);
}

/* Takes a message and derives the matching chain lengths. */
static void chain_lengths(unsigned int *lengths, const unsigned char *msg) {
    base_w(lengths, sphincs_CHAM_WOTS_LEN1, msg);
    wots_checksum(lengths + sphincs_CHAM_WOTS_LEN1, lengths);
}

/**
 * WOTS key generation. Takes a 32 byte sk_seed, expands it to WOTS private key
 * elements and computes the corresponding public key.
 * It requires the seed pub_seed (used to generate bitmasks and hash keys)
 * and the address of this WOTS key pair.
 *
 * Writes the computed public key to 'pk'.
 */
void sphincs_CHAM_wots_gen_pk(
    unsigned char *pk, const unsigned char *sk_seed,
    const unsigned char *pub_seed, uint32_t addr[8],
    const hash_state *hash_state_seeded) {
    uint32_t i;

    for (i = 0; i < sphincs_CHAM_WOTS_LEN; i++) {
        sphincs_CHAM_set_chain_addr(addr, i);
        wots_gen_sk(pk + i * sphincs_CHAM_N, sk_seed, addr, hash_state_seeded);
        gen_chain(pk + i * sphincs_CHAM_N, pk + i * sphincs_CHAM_N,
                  0, sphincs_CHAM_WOTS_W - 1, pub_seed, addr, hash_state_seeded);
    }
}

/**
 * Takes a n-byte message and the 32-byte sk_see to compute a signature 'sig'.
 */
void sphincs_CHAM_wots_sign(
    unsigned char *sig, const unsigned char *msg,
    const unsigned char *sk_seed, const unsigned char *pub_seed,
    uint32_t addr[8], const hash_state *hash_state_seeded) {
    unsigned int lengths[sphincs_CHAM_WOTS_LEN];
    uint32_t i;

    chain_lengths(lengths, msg);

    for (i = 0; i < sphincs_CHAM_WOTS_LEN; i++) {
        sphincs_CHAM_set_chain_addr(addr, i);
        wots_gen_sk(sig + i * sphincs_CHAM_N, sk_seed, addr, hash_state_seeded);
        gen_chain(sig + i * sphincs_CHAM_N, sig + i * sphincs_CHAM_N, 0, lengths[i], pub_seed, addr, hash_state_seeded);
    }
}

/**
 * Takes a WOTS signature and an n-byte message, computes a WOTS public key.
 *
 * Writes the computed public key to 'pk'.
 */
void sphincs_CHAM_wots_pk_from_sig(
    unsigned char *pk,
    const unsigned char *sig, const unsigned char *msg,
    const unsigned char *pub_seed, uint32_t addr[8],
    const hash_state *hash_state_seeded) {
    unsigned int lengths[sphincs_CHAM_WOTS_LEN];
    uint32_t i;

    chain_lengths(lengths, msg);

    for (i = 0; i < sphincs_CHAM_WOTS_LEN; i++) {
        sphincs_CHAM_set_chain_addr(addr, i);
        gen_chain(pk + i * sphincs_CHAM_N, sig + i * sphincs_CHAM_N,
                  lengths[i], sphincs_CHAM_WOTS_W - 1 - lengths[i], pub_seed, addr,
                  hash_state_seeded);
    }
}
