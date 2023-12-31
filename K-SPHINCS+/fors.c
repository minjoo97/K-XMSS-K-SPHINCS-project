#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "address.h"
#include "fors.h"
#include "hash.h"
#include "hash_state.h"
#include "thash.h"
#include "utils.h"

static void fors_gen_sk(unsigned char *sk, const unsigned char *sk_seed,
                        uint32_t fors_leaf_addr[8], const hash_state *hash_state_seeded) {
    sphincs_CHAM_prf_addr(
        sk, sk_seed, fors_leaf_addr, hash_state_seeded);
}

static void fors_sk_to_leaf(unsigned char *leaf, const unsigned char *sk,
                            const unsigned char *pub_seed,
                            uint32_t fors_leaf_addr[8],
                            const hash_state *hash_state_seeded) {
    sphincs_CHAM_thash_1(
        leaf, sk, pub_seed, fors_leaf_addr, hash_state_seeded);
}

static void fors_gen_leaf(unsigned char *leaf, const unsigned char *sk_seed,
                          const unsigned char *pub_seed,
                          uint32_t addr_idx, const uint32_t fors_tree_addr[8],
                          const hash_state *hash_state_seeded) {
    uint32_t fors_leaf_addr[8] = {0};

    /* Only copy the parts that must be kept in fors_leaf_addr. */
    sphincs_CHAM_copy_keypair_addr(
        fors_leaf_addr, fors_tree_addr);
    sphincs_CHAM_set_type(
        fors_leaf_addr, sphincs_CHAM_ADDR_TYPE_FORSTREE);
    sphincs_CHAM_set_tree_index(
        fors_leaf_addr, addr_idx);

    fors_gen_sk(leaf, sk_seed, fors_leaf_addr, hash_state_seeded);
    fors_sk_to_leaf(leaf, leaf, pub_seed, fors_leaf_addr, hash_state_seeded);
}

/**
 * Interprets m as sphincs_CHAM_FORS_HEIGHT-bit unsigned integers.
 * Assumes m contains at least sphincs_CHAM_FORS_HEIGHT * sphincs_CHAM_FORS_TREES bits.
 * Assumes indices has space for sphincs_CHAM_FORS_TREES integers.
 */
static void message_to_indices(uint32_t *indices, const unsigned char *m) {
    unsigned int i, j;
    unsigned int offset = 0;

    for (i = 0; i < sphincs_CHAM_FORS_TREES; i++) {
        indices[i] = 0;
        for (j = 0; j < sphincs_CHAM_FORS_HEIGHT; j++) {
            indices[i] ^= (((uint32_t)m[offset >> 3] >> (offset & 0x7)) & 0x1) << j;
            offset++;
        }
    }
}

/**
 * Signs a message m, deriving the secret key from sk_seed and the FTS address.
 * Assumes m contains at least sphincs_CHAM_FORS_HEIGHT * sphincs_CHAM_FORS_TREES bits.
 */
void sphincs_CHAM_fors_sign(
    unsigned char *sig, unsigned char *pk,
    const unsigned char *m,
    const unsigned char *sk_seed, const unsigned char *pub_seed,
    const uint32_t fors_addr[8], const hash_state *hash_state_seeded) {
    uint32_t indices[sphincs_CHAM_FORS_TREES];
    unsigned char roots[sphincs_CHAM_FORS_TREES * sphincs_CHAM_N];
    uint32_t fors_tree_addr[8] = {0};
    uint32_t fors_pk_addr[8] = {0};
    uint32_t idx_offset;
    unsigned int i;

    sphincs_CHAM_copy_keypair_addr(
        fors_tree_addr, fors_addr);
    sphincs_CHAM_copy_keypair_addr(
        fors_pk_addr, fors_addr);

    sphincs_CHAM_set_type(
        fors_tree_addr, sphincs_CHAM_ADDR_TYPE_FORSTREE);
    sphincs_CHAM_set_type(
        fors_pk_addr, sphincs_CHAM_ADDR_TYPE_FORSPK);

    message_to_indices(indices, m);

    for (i = 0; i < sphincs_CHAM_FORS_TREES; i++) {
        idx_offset = i * (1 << sphincs_CHAM_FORS_HEIGHT);

        sphincs_CHAM_set_tree_height(
            fors_tree_addr, 0);
        sphincs_CHAM_set_tree_index(
            fors_tree_addr, indices[i] + idx_offset);

        /* Include the secret key part that produces the selected leaf node. */
        fors_gen_sk(sig, sk_seed, fors_tree_addr, hash_state_seeded);
        sig += sphincs_CHAM_N;

        /* Compute the authentication path for this leaf node. */
        sphincs_CHAM_treehash_FORS_HEIGHT(
            roots + i * sphincs_CHAM_N, sig, sk_seed, pub_seed,
            indices[i], idx_offset, fors_gen_leaf, fors_tree_addr,
            hash_state_seeded);
        sig += sphincs_CHAM_N * sphincs_CHAM_FORS_HEIGHT;
    }

    /* Hash horizontally across all tree roots to derive the public key. */
    sphincs_CHAM_thash_FORS_TREES(
        pk, roots, pub_seed, fors_pk_addr, hash_state_seeded);
}

/**
 * Derives the FORS public key from a signature.
 * This can be used for verification by comparing to a known public key, or to
 * subsequently verify a signature on the derived public key. The latter is the
 * typical use-case when used as an FTS below an OTS in a hypertree.
 * Assumes m contains at least sphincs_CHAM_FORS_HEIGHT * sphincs_CHAM_FORS_TREES bits.
 */
void sphincs_CHAM_fors_pk_from_sig(
    unsigned char *pk,
    const unsigned char *sig, const unsigned char *m,
    const unsigned char *pub_seed, const uint32_t fors_addr[8],
    const hash_state *hash_state_seeded) {
    uint32_t indices[sphincs_CHAM_FORS_TREES];
    unsigned char roots[sphincs_CHAM_FORS_TREES * sphincs_CHAM_N];
    unsigned char leaf[sphincs_CHAM_N];
    uint32_t fors_tree_addr[8] = {0};
    uint32_t fors_pk_addr[8] = {0};
    uint32_t idx_offset;
    unsigned int i;

    sphincs_CHAM_copy_keypair_addr(fors_tree_addr, fors_addr);
    sphincs_CHAM_copy_keypair_addr(fors_pk_addr, fors_addr);

    sphincs_CHAM_set_type(fors_tree_addr, sphincs_CHAM_ADDR_TYPE_FORSTREE);
    sphincs_CHAM_set_type(fors_pk_addr, sphincs_CHAM_ADDR_TYPE_FORSPK);

    message_to_indices(indices, m);

    for (i = 0; i < sphincs_CHAM_FORS_TREES; i++) {
        idx_offset = i * (1 << sphincs_CHAM_FORS_HEIGHT);

        sphincs_CHAM_set_tree_height(fors_tree_addr, 0);
        sphincs_CHAM_set_tree_index(fors_tree_addr, indices[i] + idx_offset);

        /* Derive the leaf from the included secret key part. */
        fors_sk_to_leaf(leaf, sig, pub_seed, fors_tree_addr, hash_state_seeded);
        sig += sphincs_CHAM_N;

        /* Derive the corresponding root node of this tree. */
        sphincs_CHAM_compute_root(roots + i * sphincs_CHAM_N, leaf, indices[i], idx_offset, sig,
                sphincs_CHAM_FORS_HEIGHT, pub_seed, fors_tree_addr, hash_state_seeded);
        sig += sphincs_CHAM_N * sphincs_CHAM_FORS_HEIGHT;
    }

    /* Hash horizontally across all tree roots to derive the public key. */
    sphincs_CHAM_thash_FORS_TREES(pk, roots, pub_seed, fors_pk_addr, hash_state_seeded);
}
