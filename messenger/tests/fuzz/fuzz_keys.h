/**
 * @file fuzz_keys.h
 * @brief Deterministic REAL key material for the fuzz harnesses.
 *
 * Unlike fuzz_common.h (fake byte patterns that no algorithm accepts), these
 * are genuine keypairs derived from a fixed per-identity seed through the
 * derand entry points of the shared crypto:
 *   ML-DSA-87   qgp_dsa87_keypair_derand        (crypto/sign/qgp_dilithium.h:29)
 *   Kyber r3    kyber_r3_keypair_derand         (crypto/enc/kyber_r3_legacy.h:49)
 *   ML-KEM-1024 qgp_mlkem1024_keypair_derand    (crypto/enc/qgp_mlkem.h:52)
 *   fingerprint SHA3-512(ML-DSA-87 pubkey)      (dna_api.c dna_verify_seal_authorship)
 *
 * A harness that builds a valid envelope around fuzzed bytes (so the bytes
 * reach code behind a decapsulation or a signature check) needs keys the
 * decoder will accept; the seed generator needs the SAME keys so its seeds
 * decrypt / verify inside the harness. Same tag = same keys, every run.
 *
 * NOT secret, NOT for anything but fuzzing.
 */

#ifndef FUZZ_KEYS_H
#define FUZZ_KEYS_H

#include <stdint.h>
#include <stddef.h>

#define FUZZ_SIGN_PK_BYTES   2592   /* QGP_DSA87_PUBLICKEYBYTES */
#define FUZZ_SIGN_SK_BYTES   4896   /* QGP_DSA87_SECRETKEYBYTES */
#define FUZZ_KEM_PK_BYTES    1568   /* Kyber r3 and ML-KEM-1024 */
#define FUZZ_KEM_SK_BYTES    3168   /* Kyber r3 and ML-KEM-1024 */

/* Identity tags used by the harnesses and the seed generator */
#define FUZZ_ID_SELF     1   /* the local user (recipient / list owner) */
#define FUZZ_ID_CONTACT  2   /* the other party of a salt agreement */

typedef struct {
    uint8_t sign_pk[FUZZ_SIGN_PK_BYTES];
    uint8_t sign_sk[FUZZ_SIGN_SK_BYTES];
    uint8_t kyber_pk[FUZZ_KEM_PK_BYTES];   /* round-3 (legacy) */
    uint8_t kyber_sk[FUZZ_KEM_SK_BYTES];
    uint8_t mlkem_pk[FUZZ_KEM_PK_BYTES];   /* ML-KEM-1024 */
    uint8_t mlkem_sk[FUZZ_KEM_SK_BYTES];
    uint8_t fp[64];                        /* SHA3-512(sign_pk) */
    char    fp_hex[129];                   /* lowercase hex + NUL */
} fuzz_identity_t;

/**
 * Derive the identity for `tag` (FUZZ_ID_*). Deterministic.
 * @return 0 on success, -1 if any derivation failed
 */
int fuzz_identity_derive(fuzz_identity_t *id, uint8_t tag);

#endif /* FUZZ_KEYS_H */
