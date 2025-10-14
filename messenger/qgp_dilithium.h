#ifndef QGP_DILITHIUM_H
#define QGP_DILITHIUM_H

#include <stdint.h>
#include <stddef.h>

// QGP Dilithium3 API
// Wrapper for vendored pq-crystals/dilithium reference implementation
// FIPS 204 compliant - ML-DSA-65 (NIST Level 3 security)

// Dilithium3 key and signature sizes (FIPS 204 / ML-DSA-65)
#define QGP_DILITHIUM3_PUBLICKEYBYTES  1952
#define QGP_DILITHIUM3_SECRETKEYBYTES  4032
#define QGP_DILITHIUM3_BYTES           3309

// Key generation
// Generates a Dilithium3 keypair
// pk: output public key buffer (must be QGP_DILITHIUM3_PUBLICKEYBYTES)
// sk: output secret key buffer (must be QGP_DILITHIUM3_SECRETKEYBYTES)
// Returns 0 on success, -1 on failure
int qgp_dilithium3_keypair(uint8_t *pk, uint8_t *sk);

// Deterministic key generation from seed
// Generates a Dilithium3 keypair deterministically from a seed
// pk: output public key buffer (must be QGP_DILITHIUM3_PUBLICKEYBYTES)
// sk: output secret key buffer (must be QGP_DILITHIUM3_SECRETKEYBYTES)
// seed: input seed (must be 32 bytes)
// Returns 0 on success, -1 on failure
int qgp_dilithium3_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed);

// Signing (detached signature)
// sig: output signature buffer (must be QGP_DILITHIUM3_BYTES)
// siglen: output signature length (will be <= QGP_DILITHIUM3_BYTES)
// m: message to sign
// mlen: message length
// sk: secret key (must be QGP_DILITHIUM3_SECRETKEYBYTES)
// Returns 0 on success, -1 on failure
int qgp_dilithium3_signature(uint8_t *sig, size_t *siglen,
                              const uint8_t *m, size_t mlen,
                              const uint8_t *sk);

// Verification (detached signature)
// sig: signature to verify
// siglen: signature length
// m: message to verify
// mlen: message length
// pk: public key (must be QGP_DILITHIUM3_PUBLICKEYBYTES)
// Returns 0 if signature is valid, -1 if invalid
int qgp_dilithium3_verify(const uint8_t *sig, size_t siglen,
                           const uint8_t *m, size_t mlen,
                           const uint8_t *pk);

#endif
