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

// Largest FIPS 204 context string (ctx is length-prefixed by one byte)
#define QGP_DSA87_CTX_MAX_BYTES 255

// Signing with a FIPS 204 context string (detached signature)
// The library forms pre = 0 || ctxlen || ctx and passes it alongside m
// (shared/crypto/sign/dsa/sign.c:279-295; verify :439-458). ctx is NOT
// part of the message and must never be prepended to it by the caller.
// ctx: context string, may be NULL only when ctxlen == 0
// ctxlen: context length, at most QGP_DSA87_CTX_MAX_BYTES
// Other arguments as qgp_dsa87_sign.
// Returns 0 on success, -1 on failure (NULL argument, ctx too long)
int qgp_dsa87_sign_ctx(uint8_t *sig, size_t *siglen,
                       const uint8_t *m, size_t mlen,
                       const uint8_t *ctx, size_t ctxlen,
                       const uint8_t *sk);

// Verification with a FIPS 204 context string (detached signature)
// A signature made under one ctx never verifies under another ctx, nor
// under qgp_dsa87_verify (which is ctx = empty). There is no fallback.
// ctx: context string, may be NULL only when ctxlen == 0
// ctxlen: context length, at most QGP_DSA87_CTX_MAX_BYTES
// Other arguments as qgp_dsa87_verify.
// Returns 0 if signature is valid, -1 if invalid or arguments rejected
int qgp_dsa87_verify_ctx(const uint8_t *sig, size_t siglen,
                         const uint8_t *m, size_t mlen,
                         const uint8_t *ctx, size_t ctxlen,
                         const uint8_t *pk);

#endif
