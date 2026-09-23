#ifndef QGP_MLKEM_H
#define QGP_MLKEM_H

#include <stdint.h>
#include <stddef.h>

/**
 * ML-KEM-1024 Key Encapsulation Mechanism — FIPS 203 (2024-08-13).
 *
 * Reference: pq-crystals/kyber, `standard` branch @
 * d5b791c0c601b543233daccbae2845c6197a9e77 (shared/crypto/enc/kem/,
 * KYBER_K=4). Claim: FIPS 203 input-output conformant (Appendix C,
 * fips203.txt:2421-2427 — "a conforming implementation need only match the
 * input-output behavior of these three algorithms"), proven by the KATs in
 * messenger/tests/test_mlkem1024.c against
 * messenger/tests/fixtures/mlkem/ — NIST ACVP-Server @975de31 (FIPS 203
 * final; PIN.md §1) + CCTV@4448f20 (draft-era: encaps/decaps/modulus/strcmp
 * only, PIN.md §2). NOT claimed: FIPS
 * 140-3 module validation, or an approved RBG — (d,z) seeds come from a
 * BIP39 master seed via SHAKE256, not an approved DRBG (fips203.txt:1080-
 * 1081; docs/plans/2026-09-23-mlkem-fips203-migration-design.md §3).
 *
 * Distinct from the legacy round-3 API (crypto/enc/qgp_kyber.h /
 * kyber_r3_legacy.h) — same K-PKE core, different FO wrapper and keygen
 * domain separation. See the migration design doc §2 for the exact
 * differences (F1-F6) and docs/plans/decisions/2026-09-23-kem-mlkem-
 * migration.md for the phased rollout (Faz 0 = this port, behaviour of
 * every EXISTING caller unchanged; nothing calls this header yet).
 */

#define QGP_MLKEM1024_PUBLICKEYBYTES     1568
#define QGP_MLKEM1024_SECRETKEYBYTES     3168
#define QGP_MLKEM1024_CIPHERTEXTBYTES    1568
#define QGP_MLKEM1024_SHAREDSECRET_BYTES 32
#define QGP_MLKEM1024_COINS_BYTES        64   /* d || z, FIPS 203 Alg 16 KeyGen_internal */

/**
 * Generate an ML-KEM-1024 keypair from fresh randomness (qgp_randombytes,
 * return value CHECKED — unlike upstream crypto_kem_keypair's own call to
 * randombytes(), kem.c:50-57, which ignores it). Draws 64 bytes of coins,
 * calls qgp_mlkem1024_keypair_derand, zeroes the coins afterward.
 */
int qgp_mlkem1024_keypair(uint8_t *ek, uint8_t *dk);

/**
 * Generate an ML-KEM-1024 keypair deterministically from a 64-byte coins
 * buffer, coins = d(32) || z(32). Upstream crypto_kem_keypair_derand — FIPS
 * 203 Algorithm 16, KeyGen_internal(d, z).
 *
 * @param coins Input 64-byte seed, d(32) || z(32) (QGP_MLKEM1024_COINS_BYTES)
 */
int qgp_mlkem1024_keypair_derand(uint8_t *ek, uint8_t *dk, const uint8_t *coins);

/**
 * FIPS 203 §7.2 encapsulation key check (fips203.txt:2035-2050): reject an
 * ek whose 12-bit-packed polynomial coefficients (ek[0:1536], the packed
 * t-hat vector) are not all < q=3329. (Length is checked by contract — this
 * API takes a fixed QGP_MLKEM1024_PUBLICKEYBYTES-sized buffer.)
 *
 * @param ek Input encapsulation key (QGP_MLKEM1024_PUBLICKEYBYTES bytes)
 * @return 0 if ek passes the check, -1 if it does not.
 */
int qgp_mlkem1024_ek_check(const uint8_t *ek);

/**
 * Encapsulate against an ML-KEM-1024 encapsulation key, with fresh
 * randomness (qgp_randombytes, return value CHECKED — unlike upstream
 * crypto_kem_enc's own call to randombytes(), kem.c:113-121, which ignores
 * it; the drawn message is zeroed afterward). Runs qgp_mlkem1024_ek_check
 * first; on failure returns -1 and writes nothing to ct/ss.
 *
 * @param ct Output ciphertext (QGP_MLKEM1024_CIPHERTEXTBYTES bytes)
 * @param ss Output shared secret (QGP_MLKEM1024_SHAREDSECRET_BYTES bytes)
 * @param ek Input encapsulation key (QGP_MLKEM1024_PUBLICKEYBYTES bytes)
 */
int qgp_mlkem1024_encapsulate(uint8_t *ct, uint8_t *ss, const uint8_t *ek);

/**
 * Encapsulate deterministically from a 32-byte message m (KAT entry point).
 * Runs qgp_mlkem1024_ek_check first, then upstream crypto_kem_enc_derand.
 *
 * @param m Input 32-byte message (the FIPS 203 encaps randomness)
 */
int qgp_mlkem1024_encapsulate_derand(uint8_t *ct, uint8_t *ss, const uint8_t *ek,
                                     const uint8_t *m);

/**
 * Decapsulate an ML-KEM-1024 ciphertext. Runs the FIPS 203 §7.3 checks
 * first (fips203.txt:2080-2100): ct/dk length are by contract; the hash
 * check sha3_256(dk[384k:768k+32)) == dk[768k+32:768k+64) (k=4:
 * sha3_256(dk[1536:3104)) == dk[3104:3136)) is performed in constant time
 * (upstream verify()) on EVERY call, per fips203.txt:2099-2100 ("ciphertext
 * checking shall be performed with every execution"). On failure returns -1
 * WITHOUT decapsulating.
 *
 * @param ss Output shared secret (QGP_MLKEM1024_SHAREDSECRET_BYTES bytes)
 * @param ct Input ciphertext (QGP_MLKEM1024_CIPHERTEXTBYTES bytes)
 * @param dk Input decapsulation key (QGP_MLKEM1024_SECRETKEYBYTES bytes)
 */
int qgp_mlkem1024_decapsulate(uint8_t *ss, const uint8_t *ct, const uint8_t *dk);

#endif /* QGP_MLKEM_H */
