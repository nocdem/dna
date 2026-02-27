#ifndef QGP_DILITHIUM_H
#define QGP_DILITHIUM_H

#include <stdint.h>
#include <stddef.h>

// QGP DSA-87 API (ML-DSA-87)
// Wrapper for vendored pq-crystals/dilithium reference implementation
// FIPS 204 compliant - ML-DSA-87 (NIST Level 5 / Category 5 security)

// DSA-87 key and signature sizes (FIPS 204 / ML-DSA-87)
#define QGP_DSA87_PUBLICKEYBYTES  2592
#define QGP_DSA87_SECRETKEYBYTES  4896
#define QGP_DSA87_SIGNATURE_BYTES 4627

// Key generation
// Generates a DSA-87 keypair
// pk: output public key buffer (must be QGP_DSA87_PUBLICKEYBYTES - 2592 bytes)
// sk: output secret key buffer (must be QGP_DSA87_SECRETKEYBYTES - 4896 bytes)
// Returns 0 on success, -1 on failure
int qgp_dsa87_keypair(uint8_t *pk, uint8_t *sk);

// Deterministic key generation from seed
// Generates a DSA-87 keypair deterministically from a seed
// pk: output public key buffer (must be QGP_DSA87_PUBLICKEYBYTES - 2592 bytes)
// sk: output secret key buffer (must be QGP_DSA87_SECRETKEYBYTES - 4896 bytes)
// seed: input seed (must be 32 bytes)
// Returns 0 on success, -1 on failure
int qgp_dsa87_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed);

// Signing (detached signature)
// sig: output signature buffer (must be QGP_DSA87_SIGNATURE_BYTES)
// siglen: output signature length (will be <= QGP_DSA87_SIGNATURE_BYTES)
// m: message to sign
// mlen: message length
// sk: secret key (must be QGP_DSA87_SECRETKEYBYTES)
// Returns 0 on success, -1 on failure
int qgp_dsa87_sign(uint8_t *sig, size_t *siglen,
                   const uint8_t *m, size_t mlen,
                   const uint8_t *sk);

// Verification (detached signature)
// sig: signature to verify
// siglen: signature length
// m: message to verify
// mlen: message length
// pk: public key (must be QGP_DSA87_PUBLICKEYBYTES)
// Returns 0 if signature is valid, -1 if invalid
int qgp_dsa87_verify(const uint8_t *sig, size_t siglen,
                     const uint8_t *m, size_t mlen,
                     const uint8_t *pk);

#endif
