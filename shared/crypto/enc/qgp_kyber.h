#ifndef QGP_KYBER_H
#define QGP_KYBER_H

#include <stdint.h>
#include <stddef.h>

/**
 * KEM-1024 Key Encapsulation Mechanism — Kyber1024 round-3 — LEGACY.
 *
 * This is the ROUND-3 (pre-FIPS-203) API, kept only for backward
 * compatibility: reading keys/ciphertexts/DHT blobs produced before the
 * ML-KEM migration, and — during Faz 1-2 — sending to peers who have not
 * yet published an ML-KEM key. Routes to shared/crypto/enc/kyber_r3_legacy.h
 * (kyber_r3_*), which is a verbatim transplant of this API's old direct
 * implementation (commit c86cad72).
 *
 * The FIPS-203-conformant ML-KEM-1024 API is
 * shared/crypto/enc/qgp_mlkem.h (qgp_mlkem1024_*) — new code uses that,
 * not this. See docs/plans/decisions/2026-09-23-kem-mlkem-migration.md and
 * docs/plans/2026-09-23-mlkem-fips203-migration-design.md for the phased
 * rollout and the exact differences between the two (F1-F6).
 *
 * Two concrete divergences from ML-KEM (both verified in this tree, both
 * preserved unchanged from before this port):
 *   1. FINAL KDF. The shared secret is SHAKE256(K' || H(c)) — FIPS 203
 *      removed that step (the shared secret is K' straight out of G).
 *   2. KEYGEN DOMAIN SEPARATION. G is fed 32 bytes (G(d)). FIPS 203 feeds
 *      G(d || k), i.e. 33 bytes including the parameter-set byte.
 * Consequence: shared secrets DIFFER from ML-KEM for the same inputs; this
 * path will NOT interoperate with a FIPS 203 peer. Round-3 Kyber1024 is not
 * broken — it is the well-analysed scheme ML-KEM was standardised FROM.
 */

#define QGP_KEM1024_PUBLICKEYBYTES     1568
#define QGP_KEM1024_SECRETKEYBYTES     3168
#define QGP_KEM1024_CIPHERTEXTBYTES    1568
#define QGP_KEM1024_SHAREDSECRET_BYTES 32

/**
 * Generate KEM-1024 (round-3, legacy) keypair
 *
 * @param pk Output public key (1568 bytes)
 * @param sk Output secret key (3168 bytes)
 * @return 0 on success, -1 on error
 */
int qgp_kem1024_keypair(uint8_t *pk, uint8_t *sk);

/**
 * Encapsulation: Generate shared secret and ciphertext (round-3, legacy)
 *
 * @param ct Output ciphertext (1568 bytes)
 * @param ss Output shared secret (32 bytes)
 * @param pk Input public key (1568 bytes)
 * @return 0 on success, -1 on error
 */
int qgp_kem1024_encapsulate(uint8_t *ct, uint8_t *ss, const uint8_t *pk);

/**
 * Decapsulation: Recover shared secret from ciphertext (round-3, legacy)
 *
 * @param ss Output shared secret (32 bytes)
 * @param ct Input ciphertext (1568 bytes)
 * @param sk Input secret key (3168 bytes)
 * @return 0 on success, -1 on error
 */
int qgp_kem1024_decapsulate(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

#endif /* QGP_KYBER_H */
