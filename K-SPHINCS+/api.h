#ifndef sphincs_CHAM_API_H
#define sphincs_CHAM_API_H

#include <stddef.h>
#include <stdint.h>



#define sphincs_CHAM_CRYPTO_ALGNAME "SPHINCS+"

#define sphincs_CHAM_CRYPTO_SECRETKEYBYTES 128
#define sphincs_CHAM_CRYPTO_PUBLICKEYBYTES 64
#define sphincs_CHAM_CRYPTO_BYTES 49856
#define sphincs_CHAM_CRYPTO_SEEDBYTES 96


/*
 * Returns the length of a secret key, in bytes
 */
size_t sphincs_CHAM_crypto_sign_secretkeybytes(void);

/*
 * Returns the length of a public key, in bytes
 */
size_t sphincs_CHAM_crypto_sign_publickeybytes(void);

/*
 * Returns the length of a signature, in bytes
 */
size_t sphincs_CHAM_crypto_sign_bytes(void);

/*
 * Returns the length of the seed required to generate a key pair, in bytes
 */
size_t sphincs_CHAM_crypto_sign_seedbytes(void);

/*
 * Generates a SPHINCS+ key pair given a seed.
 * Format sk: [SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [root || PUB_SEED]
 */
int sphincs_CHAM_crypto_sign_seed_keypair(
    uint8_t *pk, uint8_t *sk, const uint8_t *seed);

/*
 * Generates a SPHINCS+ key pair.
 * Format sk: [SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [root || PUB_SEED]
 */
int sphincs_CHAM_crypto_sign_keypair(
    uint8_t *pk, uint8_t *sk);

/**
 * Returns an array containing a detached signature.
 */
int sphincs_CHAM_crypto_sign_signature(
    uint8_t *sig, size_t *siglen,
    const uint8_t *m, size_t mlen, const uint8_t *sk);

/**
 * Verifies a detached signature and message under a given public key.
 */
int sphincs_CHAM_crypto_sign_verify(
    const uint8_t *sig, size_t siglen,
    const uint8_t *m, size_t mlen, const uint8_t *pk);

/**
 * Returns an array containing the signature followed by the message.
 */
int sphincs_CHAM_crypto_sign(
    uint8_t *sm, size_t *smlen,
    const uint8_t *m, size_t mlen, const uint8_t *sk);

/**
 * Verifies a given signature-message pair under a given public key.
 */
int sphincs_CHAM_crypto_sign_open(
    uint8_t *m, size_t *mlen,
    const uint8_t *sm, size_t smlen, const uint8_t *pk);

#endif
