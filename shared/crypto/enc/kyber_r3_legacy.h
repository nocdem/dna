#ifndef KYBER_R3_LEGACY_H
#define KYBER_R3_LEGACY_H

#include <stdint.h>
#include <stddef.h>

/**
 * Kyber round-3 (pre-FIPS-203) — LEGACY, kept only so that keys/ciphertexts/
 * DHT blobs produced before the ML-KEM migration remain readable and, during
 * Faz 1-2, sendable to old peers. Transplanted verbatim from commit
 * c86cad72 shared/crypto/enc/kem/kem.c (crypto_kem_keypair :26-36,
 * crypto_kem_enc :53-77, crypto_kem_dec :96-129) and
 * shared/crypto/enc/kyber_deterministic.c (indcpa_keypair_derand :61-97,
 * crypto_kem_keypair_derand :110-131), re-implemented on top of the new
 * std@d5b791c ML-KEM K-PKE layer in shared/crypto/enc/kem/ — the matrix
 * generation, noise sampling, NTT and packing are the SAME functions the
 * new ML-KEM path calls; only the FO wrapper (final KDF: SHAKE256 over
 * K'||H(c) instead of ML-KEM's bare G output) and the keygen G-input
 * (G(d), 32 bytes, instead of ML-KEM's G(d||k), 33 bytes) differ from
 * ML-KEM — that IS round-3's definition relative to FIPS 203. See
 * docs/plans/2026-09-23-mlkem-fips203-migration-design.md §2 (F1-F6, F4:
 * decap ret value = SHAKE256(z||H(c)), not FIPS 203's J(z||c)) and §4.4.
 *
 * Proof this is behaviour-preserving: messenger/tests/test_kyber1024.c
 * checks this path against messenger/tests/fixtures/kyber_r3_legacy_kat.h,
 * a KAT captured from the pre-port binary at commit c86cad72.
 *
 * Removal: Faz 3 (docs/plans/decisions/2026-09-23-kem-mlkem-migration.md,
 * operator decision K5 — "1 yıla kadar bekleyebilir").
 */

#define KYBER_R3_PUBLICKEYBYTES     1568
#define KYBER_R3_SECRETKEYBYTES     3168
#define KYBER_R3_CIPHERTEXTBYTES    1568
#define KYBER_R3_SHAREDSECRETBYTES  32

/**
 * Generate a round-3 keypair from fresh randomness (qgp_randombytes).
 * Equivalent to c86cad72 kem/kem.c crypto_kem_keypair.
 */
int kyber_r3_keypair(uint8_t pk[KYBER_R3_PUBLICKEYBYTES],
                     uint8_t sk[KYBER_R3_SECRETKEYBYTES]);

/**
 * Generate a round-3 keypair deterministically from a 32-byte seed.
 * Equivalent to c86cad72 kyber_deterministic.c crypto_kem_keypair_derand
 * (G(seed) over 32 bytes; z = SHA3-256(seed) — NOT FIPS 203's (d,z) pair).
 */
int kyber_r3_keypair_derand(uint8_t pk[KYBER_R3_PUBLICKEYBYTES],
                            uint8_t sk[KYBER_R3_SECRETKEYBYTES],
                            const uint8_t seed[32]);

/**
 * Encapsulate against a round-3 public key.
 * Equivalent to c86cad72 kem/kem.c crypto_kem_enc.
 */
int kyber_r3_encapsulate(uint8_t ct[KYBER_R3_CIPHERTEXTBYTES],
                         uint8_t ss[KYBER_R3_SHAREDSECRETBYTES],
                         const uint8_t pk[KYBER_R3_PUBLICKEYBYTES]);

/**
 * Decapsulate a round-3 ciphertext.
 * Equivalent to c86cad72 kem/kem.c crypto_kem_dec (implicit rejection:
 * ss = SHAKE256(z||H(ct)) on failure — round-3's rejection KDF, distinct
 * from FIPS 203's J(z||ct)).
 */
int kyber_r3_decapsulate(uint8_t ss[KYBER_R3_SHAREDSECRETBYTES],
                         const uint8_t ct[KYBER_R3_CIPHERTEXTBYTES],
                         const uint8_t sk[KYBER_R3_SECRETKEYBYTES]);

#endif /* KYBER_R3_LEGACY_H */
