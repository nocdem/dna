/**
 * @file nullifier.c
 * @brief Shared nullifier derivation (v0.8.0)
 *
 * Extracted from wallet.c so that both the wallet (receiver) and
 * the validator (consensus) can compute the same nullifier for a
 * given UTXO output.
 *
 * Nullifier = SHA3-512(owner_fingerprint || nullifier_seed)
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dnac/dnac.h"
#include <string.h>
#include <openssl/evp.h>

#include "crypto/utils/qgp_log.h"

#define LOG_TAG "NULLIFIER_DERIVE"

/**
 * @brief Derive a nullifier from owner fingerprint and seed
 *
 * This is the canonical nullifier derivation used by both wallets
 * and validators. Must produce identical results on both sides.
 *
 * @param owner_fp Owner's identity fingerprint
 * @param seed 32-byte random seed from TX output
 * @param nullifier_out Output buffer (DNAC_NULLIFIER_SIZE = 64 bytes)
 * @return 0 on success, -1 on error
 */
int dnac_derive_nullifier(const char *owner_fp,
                           const uint8_t *seed,
                           uint8_t *nullifier_out) {
    if (!owner_fp || !seed || !nullifier_out) return -1;

    uint8_t data[256];
    size_t offset = 0;

    size_t fp_len = strlen(owner_fp);
    if (fp_len > 192) fp_len = 192;  /* Safety bound */

    memcpy(data, owner_fp, fp_len);
    offset = fp_len;

    memcpy(data + offset, seed, 32);
    offset += 32;

    /* SHA3-512 */
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) return -1;

    if (EVP_DigestInit_ex(mdctx, EVP_sha3_512(), NULL) != 1 ||
        EVP_DigestUpdate(mdctx, data, offset) != 1 ||
        EVP_DigestFinal_ex(mdctx, nullifier_out, NULL) != 1) {
        EVP_MD_CTX_free(mdctx);
        return -1;
    }

    EVP_MD_CTX_free(mdctx);
    return 0;
}
