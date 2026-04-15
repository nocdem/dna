/**
 * @file block.c
 * @brief DNAC block header hashing and link verification.
 *
 * Implements the client-side block hash used by dnac to anchor Merkle proofs.
 * Deterministic preimage (little-endian integer encoding):
 *
 *   SHA3-512(
 *     height(8 LE) ||
 *     prev_block_hash(64) ||
 *     state_root(64) ||
 *     tx_root(64) ||
 *     tx_count(4 LE) ||
 *     timestamp(8 LE) ||
 *     proposer_id(32)
 *     [ IF is_genesis: chain_def fields appended — see below ]
 *   )
 *
 * Genesis-only extension (appended only when block->is_genesis == true):
 *
 *   chain_name(32) ||
 *   protocol_version(4 LE) ||
 *   parent_chain_id(64) ||
 *   genesis_message(64) ||
 *   witness_count(4 LE) ||
 *   max_active_witnesses(4 LE) ||
 *   witness_pubkeys[0..witness_count-1] (witness_count * 2592) ||
 *   block_interval_sec(4 LE) ||
 *   max_txs_per_block(4 LE) ||
 *   view_change_timeout_ms(4 LE) ||
 *   token_symbol(8) ||
 *   token_decimals(1) ||
 *   initial_supply_raw(8 LE) ||
 *   native_token_id(64) ||
 *   fee_recipient(32)
 *
 * `is_genesis` itself is NOT part of the preimage — the presence of chain_def
 * bytes IS the commitment. Only `witness_count` pubkeys are hashed (empty
 * slots in the compile-time-capped array are excluded).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dnac/block.h"

#include <string.h>

#include <openssl/evp.h>

#include "crypto/utils/qgp_log.h"

#define LOG_TAG "DNAC_BLOCK"

/* ============================================================================
 * Little-endian integer encoding helpers
 * ========================================================================== */

static inline void enc_u32_le(uint32_t v, uint8_t out[4]) {
    out[0] = (uint8_t)(v & 0xff);
    out[1] = (uint8_t)((v >> 8) & 0xff);
    out[2] = (uint8_t)((v >> 16) & 0xff);
    out[3] = (uint8_t)((v >> 24) & 0xff);
}

static inline void enc_u64_le(uint64_t v, uint8_t out[8]) {
    for (int i = 0; i < 8; i++) {
        out[i] = (uint8_t)((v >> (i * 8)) & 0xff);
    }
}

/* ============================================================================
 * Block hash
 * ========================================================================== */

int dnac_block_compute_hash(dnac_block_t *block) {
    if (!block) return -1;

    /* Guard against a corrupted chain_def that would walk past the
     * compile-time-capped witness_pubkeys array. */
    if (block->is_genesis &&
        block->chain_def.witness_count > DNAC_MAX_WITNESSES_COMPILE_CAP) {
        QGP_LOG_ERROR(LOG_TAG,
                      "genesis witness_count %u exceeds compile cap %u",
                      block->chain_def.witness_count,
                      (unsigned)DNAC_MAX_WITNESSES_COMPILE_CAP);
        return -1;
    }

    EVP_MD_CTX *md = EVP_MD_CTX_new();
    if (!md) return -1;
    if (EVP_DigestInit_ex(md, EVP_sha3_512(), NULL) != 1) {
        EVP_MD_CTX_free(md);
        return -1;
    }

#define UPD(ptr, len) do { \
    if (EVP_DigestUpdate(md, (ptr), (len)) != 1) { \
        EVP_MD_CTX_free(md); \
        return -1; \
    } \
} while (0)

    /* Standard header (unchanged for non-genesis blocks). */
    uint8_t height_le[8];
    enc_u64_le(block->block_height, height_le);
    UPD(height_le, 8);

    UPD(block->prev_block_hash, DNAC_BLOCK_HASH_SIZE);
    UPD(block->state_root, DNAC_BLOCK_HASH_SIZE);
    UPD(block->tx_root, DNAC_BLOCK_HASH_SIZE);

    uint8_t tx_count_le[4];
    enc_u32_le(block->tx_count, tx_count_le);
    UPD(tx_count_le, 4);

    uint8_t timestamp_le[8];
    enc_u64_le(block->timestamp, timestamp_le);
    UPD(timestamp_le, 8);

    UPD(block->proposer_id, DNAC_BLOCK_PROPOSER_SIZE);

    /* Genesis-only chain_def fields — see file header for the exact order. */
    if (block->is_genesis) {
        const dnac_chain_definition_t *cd = &block->chain_def;

        UPD(cd->chain_name, DNAC_CHAIN_NAME_LEN);

        uint8_t pv_le[4];
        enc_u32_le(cd->protocol_version, pv_le);
        UPD(pv_le, 4);

        UPD(cd->parent_chain_id, DNAC_BLOCK_HASH_SIZE);
        UPD(cd->genesis_message, DNAC_GENESIS_MESSAGE_LEN);

        uint8_t wc_le[4];
        enc_u32_le(cd->witness_count, wc_le);
        UPD(wc_le, 4);

        uint8_t maw_le[4];
        enc_u32_le(cd->max_active_witnesses, maw_le);
        UPD(maw_le, 4);

        /* Only witness_count pubkeys hashed — empty slots excluded. */
        for (uint32_t i = 0; i < cd->witness_count; i++) {
            UPD(cd->witness_pubkeys[i], DNAC_PUBKEY_SIZE);
        }

        uint8_t bis_le[4], mtb_le[4], vct_le[4];
        enc_u32_le(cd->block_interval_sec, bis_le);
        enc_u32_le(cd->max_txs_per_block, mtb_le);
        enc_u32_le(cd->view_change_timeout_ms, vct_le);
        UPD(bis_le, 4);
        UPD(mtb_le, 4);
        UPD(vct_le, 4);

        UPD(cd->token_symbol, DNAC_TOKEN_SYMBOL_LEN);
        UPD(&cd->token_decimals, 1);

        uint8_t isr_le[8];
        enc_u64_le(cd->initial_supply_raw, isr_le);
        UPD(isr_le, 8);

        UPD(cd->native_token_id, DNAC_TOKEN_ID_SIZE);
        UPD(cd->fee_recipient, DNAC_FEE_RECIPIENT_SIZE);
    }

    uint8_t tmp[DNAC_BLOCK_HASH_SIZE];
    unsigned int hash_len = 0;
    int ok = EVP_DigestFinal_ex(md, tmp, &hash_len);
    EVP_MD_CTX_free(md);
    if (ok != 1 || hash_len != DNAC_BLOCK_HASH_SIZE) return -1;
    memcpy(block->block_hash, tmp, DNAC_BLOCK_HASH_SIZE);
    return 0;

#undef UPD
}

/* ============================================================================
 * Genesis construction helper
 * ========================================================================== */

int dnac_block_set_genesis_def(dnac_block_t *block,
                                const dnac_chain_definition_t *chain_def) {
    if (!block || !chain_def) return -1;
    if (chain_def->witness_count > DNAC_MAX_WITNESSES_COMPILE_CAP) {
        QGP_LOG_ERROR(LOG_TAG,
                      "chain_def witness_count %u exceeds compile cap %u",
                      chain_def->witness_count,
                      (unsigned)DNAC_MAX_WITNESSES_COMPILE_CAP);
        return -1;
    }
    block->is_genesis = true;
    memcpy(&block->chain_def, chain_def, sizeof(*chain_def));
    return 0;
}

