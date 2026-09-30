/**
 * @file fuzz_keys.c
 * @brief Deterministic REAL key material for the fuzz harnesses (fuzz_keys.h).
 */

#include "fuzz_keys.h"

#include <string.h>

#include "crypto/sign/qgp_dilithium.h"
#include "crypto/enc/kyber_r3_legacy.h"
#include "crypto/enc/qgp_mlkem.h"
#include "crypto/hash/qgp_sha3.h"

/* Lowercase hex, as qgp_fp_raw_to_hex (crypto/utils/qgp_fingerprint.h:31)
 * and dna_verify_seal_authorship (dna_api.c) write it. Local so the wasm32
 * fuzz build does not have to compile qgp_fingerprint.c. */
static void to_hex(const uint8_t *raw, size_t len, char *out) {
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[2 * i]     = digits[raw[i] >> 4];
        out[2 * i + 1] = digits[raw[i] & 0x0F];
    }
    out[2 * len] = '\0';
}

/* Seed bytes: tag in every byte, mixed with the position and a per-key
 * domain byte so the three keypairs of one identity are unrelated. */
static void fill_seed(uint8_t *seed, size_t len, uint8_t tag, uint8_t domain) {
    for (size_t i = 0; i < len; i++) {
        seed[i] = (uint8_t)((tag * 0x3B) ^ (domain * 0x5D) ^ (uint8_t)(i * 7));
    }
}

int fuzz_identity_derive(fuzz_identity_t *id, uint8_t tag) {
    if (!id) {
        return -1;
    }
    memset(id, 0, sizeof(*id));

    uint8_t sign_seed[32];
    uint8_t kyber_seed[32];
    uint8_t mlkem_coins[QGP_MLKEM1024_COINS_BYTES];
    fill_seed(sign_seed, sizeof(sign_seed), tag, 1);
    fill_seed(kyber_seed, sizeof(kyber_seed), tag, 2);
    fill_seed(mlkem_coins, sizeof(mlkem_coins), tag, 3);

    if (qgp_dsa87_keypair_derand(id->sign_pk, id->sign_sk, sign_seed) != 0) {
        return -1;
    }
    if (kyber_r3_keypair_derand(id->kyber_pk, id->kyber_sk, kyber_seed) != 0) {
        return -1;
    }
    if (qgp_mlkem1024_keypair_derand(id->mlkem_pk, id->mlkem_sk, mlkem_coins) != 0) {
        return -1;
    }
    if (qgp_sha3_512(id->sign_pk, sizeof(id->sign_pk), id->fp) != 0) {
        return -1;
    }
    to_hex(id->fp, sizeof(id->fp), id->fp_hex);
    return 0;
}
