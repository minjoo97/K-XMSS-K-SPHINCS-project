#ifndef sphincs_CHAM_ADDRESS_H
#define sphincs_CHAM_ADDRESS_H

#include <stdint.h>

#define sphincs_CHAM_ADDR_TYPE_WOTS 0
#define sphincs_CHAM_ADDR_TYPE_WOTSPK 1
#define sphincs_CHAM_ADDR_TYPE_HASHTREE 2
#define sphincs_CHAM_ADDR_TYPE_FORSTREE 3
#define sphincs_CHAM_ADDR_TYPE_FORSPK 4

void sphincs_CHAM_addr_to_bytes(
    unsigned char *bytes, const uint32_t addr[8]);

void sphincs_CHAM_set_layer_addr(
    uint32_t addr[8], uint32_t layer);

void sphincs_CHAM_set_tree_addr(
    uint32_t addr[8], uint64_t tree);

void sphincs_CHAM_set_type(
    uint32_t addr[8], uint32_t type);

/* Copies the layer and tree part of one address into the other */
void sphincs_CHAM_copy_subtree_addr(
    uint32_t out[8], const uint32_t in[8]);

/* These functions are used for WOTS and FORS addresses. */

void sphincs_CHAM_set_keypair_addr(
    uint32_t addr[8], uint32_t keypair);

void sphincs_CHAM_set_chain_addr(
    uint32_t addr[8], uint32_t chain);

void sphincs_CHAM_set_hash_addr(
    uint32_t addr[8], uint32_t hash);

void sphincs_CHAM_copy_keypair_addr(
    uint32_t out[8], const uint32_t in[8]);

/* These functions are used for all hash tree addresses (including FORS). */

void sphincs_CHAM_set_tree_height(
    uint32_t addr[8], uint32_t tree_height);

void sphincs_CHAM_set_tree_index(
    uint32_t addr[8], uint32_t tree_index);

#endif
