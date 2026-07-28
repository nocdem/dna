#ifndef QGP_KYBER_H
#define QGP_KYBER_H

#include <stdint.h>
#include <stddef.h>

/**
 * KEM-1024 Key Encapsulation Mechanism — Kyber1024 (round-3 / v3.x)
 *
 * Reference: pq-crystals/kyber, round-3 specification.
 * Security level: NIST Level 5 / Category 5 (256-bit post-quantum security).
 *
 * ⚠ THIS IS **NOT** ML-KEM-1024 AND **NOT** FIPS 203 (corrected 2026-07-28; the
 * header previously claimed both, and that claim was false — it had been carried
 * into the READMEs and the shipped protocol docs).
 *
 * The vendored code is round-3 Kyber, the direct predecessor of ML-KEM. Two
 * concrete divergences, both verified in this tree:
 *
 *   1. FINAL KDF. Here the shared secret is SHAKE256(K' ‖ H(c)) —
 *      `enc/kem/kem.c:73-75` hashes the ciphertext into `kr` and then calls
 *      `kdf(ss, kr, 2*KYBER_SYMBYTES)`. FIPS 203 REMOVED that step: in ML-KEM the
 *      shared secret is K' straight out of G, with no post-hash.
 *   2. KEYGEN DOMAIN SEPARATION. Here G is fed 32 bytes —
 *      `enc/kem/indcpa.c:231-232`, `hash_g(buf, buf, KYBER_SYMBYTES)`. FIPS 203
 *      keygen feeds G(d ‖ k), i.e. 33 bytes including the parameter-set byte.
 *
 * Consequences of the difference, so nobody has to re-derive them:
 *   - Shared secrets DIFFER from ML-KEM for the same inputs. This implementation
 *     will NOT interoperate with a FIPS 203 peer, and changing it would break
 *     every stored ciphertext and every deployed peer — so this is a documentation
 *     fix, NOT a call to "upgrade" the algorithm. Migrating to ML-KEM is a
 *     separate, breaking decision.
 *   - Round-3 Kyber1024 is not broken; it is the well-analysed scheme ML-KEM was
 *     standardised FROM. The defect being corrected here is the false compliance
 *     claim, not the cryptography.
 *
 * Note the asymmetry inside this repo: the signature side DID receive its
 * FIPS-204 alignment (`shared/crypto/sign/dsa/sign.c:34-36` appends the K and L
 * parameter bytes before the SHAKE256 expansion), while this KEM did not. That
 * asymmetry — one primitive updated, the other not, both banner-labelled
 * "FIPS-2xx compliant" — is what exposed the wrong label.
 *
 * The name ML-KEM-1024 still appears in older comments, size tables and docs
 * elsewhere in the tree as a synonym for Kyber1024. Those are inaccurate for the
 * same reason; THIS header is the authoritative statement of what the code is.
 */

#define QGP_KEM1024_PUBLICKEYBYTES     1568
#define QGP_KEM1024_SECRETKEYBYTES     3168
#define QGP_KEM1024_CIPHERTEXTBYTES    1568
#define QGP_KEM1024_SHAREDSECRET_BYTES 32

/**
 * Generate KEM-1024 keypair
 *
 * @param pk Output public key (1568 bytes)
 * @param sk Output secret key (3168 bytes)
 * @return 0 on success, -1 on error
 */
int qgp_kem1024_keypair(uint8_t *pk, uint8_t *sk);

/**
 * Encapsulation: Generate shared secret and ciphertext
 *
 * @param ct Output ciphertext (1568 bytes)
 * @param ss Output shared secret (32 bytes)
 * @param pk Input public key (1568 bytes)
 * @return 0 on success, -1 on error
 */
int qgp_kem1024_encapsulate(uint8_t *ct, uint8_t *ss, const uint8_t *pk);

/**
 * Decapsulation: Recover shared secret from ciphertext
 *
 * @param ss Output shared secret (32 bytes)
 * @param ct Input ciphertext (1568 bytes)
 * @param sk Input secret key (3168 bytes)
 * @return 0 on success, -1 on error
 */
int qgp_kem1024_decapsulate(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

#endif /* QGP_KYBER_H */
