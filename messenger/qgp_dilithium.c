#include "qgp_dilithium.h"
#include "crypto/dilithium/api.h"
#include "crypto/dilithium/params.h"
#include "crypto/dilithium/sign.h"
#include "crypto/dilithium/packing.h"
#include "crypto/dilithium/polyvec.h"
#include "crypto/dilithium/poly.h"
#include "crypto/dilithium/fips202.h"
#include <string.h>
#include <stdio.h>

// QGP Dilithium3 API
// Wrapper for vendored pq-crystals/dilithium reference implementation
// FIPS 204 compliant - ML-DSA-65 (NIST Level 3 security)

int qgp_dilithium3_keypair(uint8_t *pk, uint8_t *sk)
{
    if (!pk || !sk) {
        return -1;
    }

    // Call upstream Dilithium3 keypair generation
    // Context is NULL for pure Dilithium (no pre-hash)
    return pqcrystals_dilithium3_ref_keypair(pk, sk);
}

int qgp_dilithium3_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed)
{
    if (!pk || !sk || !seed) {
        return -1;
    }

    // Deterministic key generation from seed
    // This mirrors crypto_sign_keypair() but uses user-provided seed
    uint8_t seedbuf[2*SEEDBYTES + CRHBYTES];
    uint8_t tr[TRBYTES];
    const uint8_t *rho, *rhoprime, *key;
    polyvecl mat[K];
    polyvecl s1, s1hat;
    polyveck s2, t1, t0;

    // Use provided seed instead of randombytes()
    memcpy(seedbuf, seed, SEEDBYTES);
    seedbuf[SEEDBYTES+0] = K;
    seedbuf[SEEDBYTES+1] = L;
    shake256(seedbuf, 2*SEEDBYTES + CRHBYTES, seedbuf, SEEDBYTES+2);
    rho = seedbuf;
    rhoprime = rho + SEEDBYTES;
    key = rhoprime + CRHBYTES;

    // Expand matrix
    polyvec_matrix_expand(mat, rho);

    // Sample short vectors s1 and s2
    polyvecl_uniform_eta(&s1, rhoprime, 0);
    polyveck_uniform_eta(&s2, rhoprime, L);

    // Matrix-vector multiplication
    s1hat = s1;
    polyvecl_ntt(&s1hat);
    polyvec_matrix_pointwise_montgomery(&t1, mat, &s1hat);
    polyveck_reduce(&t1);
    polyveck_invntt_tomont(&t1);

    // Add error vector s2
    polyveck_add(&t1, &t1, &s2);

    // Extract t1 and write public key
    polyveck_caddq(&t1);
    polyveck_power2round(&t1, &t0, &t1);
    pack_pk(pk, rho, &t1);

    // Compute H(rho, t1) and write secret key
    shake256(tr, TRBYTES, pk, CRYPTO_PUBLICKEYBYTES);
    pack_sk(sk, rho, tr, key, &t0, &s1, &s2);

    return 0;
}

int qgp_dilithium3_signature(uint8_t *sig, size_t *siglen,
                              const uint8_t *m, size_t mlen,
                              const uint8_t *sk)
{
    if (!sig || !siglen || !m || !sk) {
        return -1;
    }

    // Call upstream Dilithium3 detached signature
    // Context (ctx) is NULL and ctxlen is 0 for pure Dilithium
    return pqcrystals_dilithium3_ref_signature(sig, siglen, m, mlen, NULL, 0, sk);
}

int qgp_dilithium3_verify(const uint8_t *sig, size_t siglen,
                           const uint8_t *m, size_t mlen,
                           const uint8_t *pk)
{
    if (!sig || !m || !pk) {
        return -1;
    }

    // Call upstream Dilithium3 signature verification
    // Context (ctx) is NULL and ctxlen is 0 for pure Dilithium
    return pqcrystals_dilithium3_ref_verify(sig, siglen, m, mlen, NULL, 0, pk);
}
