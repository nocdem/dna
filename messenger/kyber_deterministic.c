/*
 * Deterministic Kyber512 key generation for QGP
 *
 * This implements deterministic keypair generation from a 32-byte seed
 * by replacing randombytes() calls with seed-derived values.
 *
 */

#include "kyber_deterministic.h"
#include <string.h>

// Include Kyber internals from vendored implementation
#include "crypto/kyber512/params.h"
#include "crypto/kyber512/kem.h"
#include "crypto/kyber512/indcpa.h"
#include "crypto/kyber512/symmetric.h"
#include "crypto/kyber512/poly_kyber.h"
#include "crypto/kyber512/polyvec.h"
#include "crypto/kyber512/ntt_kyber.h"

// Use vendored Kyber's gen_matrix function
#define gen_a(A,B)  gen_matrix(A,B,0)

/*************************************************
* Name:        pack_pk_local
*
* Description: Serialize the public key
**************************************************/
static void pack_pk_local(uint8_t r[KYBER_INDCPA_PUBLICKEYBYTES],
                          polyvec *pk,
                          const uint8_t seed[KYBER_SYMBYTES])
{
    size_t i;
    polyvec_tobytes(r, pk);
    for(i=0; i<KYBER_SYMBYTES; i++)
        r[i+KYBER_POLYVECBYTES] = seed[i];
}

/*************************************************
* Name:        pack_sk_local
*
* Description: Serialize the secret key
**************************************************/
static void pack_sk_local(uint8_t r[KYBER_INDCPA_SECRETKEYBYTES], polyvec *sk)
{
    polyvec_tobytes(r, sk);
}

/*************************************************
* Name:        indcpa_keypair_derand
*
* Description: Deterministic version of indcpa_keypair that uses
*              a provided seed instead of randombytes()
*
* Arguments:   - uint8_t *pk: pointer to output public key
*              - uint8_t *sk: pointer to output private key
*              - const uint8_t *seed: 32-byte seed for deterministic generation
**************************************************/
static void indcpa_keypair_derand(uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                                   uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES],
                                   const uint8_t *seed)
{
    unsigned int i;
    uint8_t buf[2*KYBER_SYMBYTES];
    const uint8_t *publicseed = buf;
    const uint8_t *noiseseed = buf+KYBER_SYMBYTES;
    uint8_t nonce = 0;
    polyvec a[KYBER_K], e, pkpv, skpv;

    // CRITICAL CHANGE: Use provided seed instead of randombytes()
    memcpy(buf, seed, KYBER_SYMBYTES);
    hash_g(buf, buf, KYBER_SYMBYTES);

    gen_a(a, publicseed);

    for(i=0; i<KYBER_K; i++)
        poly_getnoise_eta1(&skpv.vec[i], noiseseed, nonce++);
    for(i=0; i<KYBER_K; i++)
        poly_getnoise_eta1(&e.vec[i], noiseseed, nonce++);

    polyvec_ntt(&skpv);
    polyvec_ntt(&e);

    // matrix-vector multiplication
    for(i=0; i<KYBER_K; i++) {
        polyvec_pointwise_acc_montgomery(&pkpv.vec[i], &a[i], &skpv);
        poly_tomont(&pkpv.vec[i]);
    }

    polyvec_add(&pkpv, &pkpv, &e);
    polyvec_reduce(&pkpv);

    pack_sk_local(sk, &skpv);
    pack_pk_local(pk, &pkpv, publicseed);
}

/*************************************************
* Name:        crypto_kem_keypair_derand
*
* Description: Deterministic Kyber512 keypair generation from seed
*
* Arguments:   - unsigned char *pk: pointer to output public key
*              - unsigned char *sk: pointer to output private key
*              - const uint8_t *seed: 32-byte seed for deterministic generation
*
* Returns 0 (success)
**************************************************/
int crypto_kem_keypair_derand(unsigned char *pk, unsigned char *sk, const uint8_t *seed)
{
    size_t i;
    uint8_t z_seed[KYBER_SYMBYTES];

    // Generate deterministic keypair from seed
    indcpa_keypair_derand(pk, sk, seed);

    // Copy public key to secret key structure
    for(i=0; i<KYBER_INDCPA_PUBLICKEYBYTES; i++)
        sk[i+KYBER_INDCPA_SECRETKEYBYTES] = pk[i];

    // Hash of public key
    hash_h(sk+KYBER_SECRETKEYBYTES-2*KYBER_SYMBYTES, pk, KYBER_PUBLICKEYBYTES);

    // CRITICAL CHANGE: Use seed-derived z value instead of random
    // Hash the seed to get z (pseudo-random output on reject)
    hash_h(z_seed, seed, KYBER_SYMBYTES);
    memcpy(sk+KYBER_SECRETKEYBYTES-KYBER_SYMBYTES, z_seed, KYBER_SYMBYTES);

    return 0;
}
