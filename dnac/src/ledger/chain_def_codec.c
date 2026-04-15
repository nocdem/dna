/**
 * @file chain_def_codec.c
 * @brief Deterministic encode/decode for dnac_chain_definition_t.
 *
 * Byte format matches the genesis-preimage sub-sequence used by
 * dnac_block_compute_hash (see dnac/src/transaction/block.c). Changes
 * here MUST be mirrored there or block hashes will diverge.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dnac/chain_def_codec.h"
#include "dnac/block.h"
#include "dnac/dnac.h"

#include <stdint.h>
#include <string.h>

/* ============================================================================
 * Little-endian integer encoding helpers (match block.c)
 * ========================================================================== */

static inline void enc_u32_le(uint32_t v, uint8_t out[4]) {
    out[0] = (uint8_t)(v & 0xff);
    out[1] = (uint8_t)((v >> 8) & 0xff);
    out[2] = (uint8_t)((v >> 16) & 0xff);
    out[3] = (uint8_t)((v >> 24) & 0xff);
}

static inline uint32_t dec_u32_le(const uint8_t in[4]) {
    return ((uint32_t)in[0])
         | ((uint32_t)in[1] << 8)
         | ((uint32_t)in[2] << 16)
         | ((uint32_t)in[3] << 24);
}

static inline void enc_u64_le(uint64_t v, uint8_t out[8]) {
    for (int i = 0; i < 8; i++) {
        out[i] = (uint8_t)((v >> (i * 8)) & 0xff);
    }
}

static inline uint64_t dec_u64_le(const uint8_t in[8]) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) {
        v |= ((uint64_t)in[i]) << (i * 8);
    }
    return v;
}

/* ============================================================================
 * Fixed (non-witness) bytes in the encoded chain_def
 *
 *   chain_name(32) + protocol_version(4) + parent_chain_id(64) +
 *   genesis_message(64) + witness_count(4) + max_active_witnesses(4) +
 *   block_interval_sec(4) + max_txs_per_block(4) +
 *   view_change_timeout_ms(4) + token_symbol(8) + token_decimals(1) +
 *   initial_supply_raw(8) + native_token_id(64) + fee_recipient(32)
 *   = 297 bytes
 * ========================================================================== */
#define CD_FIXED_BYTES  (DNAC_CHAIN_NAME_LEN           \
                       + 4                              \
                       + DNAC_BLOCK_HASH_SIZE           \
                       + DNAC_GENESIS_MESSAGE_LEN       \
                       + 4 + 4                          \
                       + 4 + 4 + 4                      \
                       + DNAC_TOKEN_SYMBOL_LEN          \
                       + 1                              \
                       + 8                              \
                       + DNAC_TOKEN_ID_SIZE             \
                       + DNAC_FEE_RECIPIENT_SIZE)

/* ============================================================================
 * Size helpers
 * ========================================================================== */

size_t dnac_chain_def_max_size(void) {
    return CD_FIXED_BYTES
         + ((size_t)DNAC_MAX_WITNESSES_COMPILE_CAP * DNAC_PUBKEY_SIZE);
}

size_t dnac_chain_def_encoded_size(const dnac_chain_definition_t *cd) {
    if (!cd) return 0;
    if (cd->witness_count > DNAC_MAX_WITNESSES_COMPILE_CAP) return 0;
    return CD_FIXED_BYTES + ((size_t)cd->witness_count * DNAC_PUBKEY_SIZE);
}

/* ============================================================================
 * Encode
 * ========================================================================== */

int dnac_chain_def_encode(const dnac_chain_definition_t *cd,
                           uint8_t *out, size_t cap, size_t *len) {
    if (!cd || !out || !len) return -1;
    if (cd->witness_count > DNAC_MAX_WITNESSES_COMPILE_CAP) return -1;

    size_t need = dnac_chain_def_encoded_size(cd);
    if (need == 0 || cap < need) return -1;

    uint8_t *p = out;

    /* chain_name(32) */
    memcpy(p, cd->chain_name, DNAC_CHAIN_NAME_LEN);
    p += DNAC_CHAIN_NAME_LEN;

    /* protocol_version(4 LE) */
    enc_u32_le(cd->protocol_version, p);
    p += 4;

    /* parent_chain_id(64) */
    memcpy(p, cd->parent_chain_id, DNAC_BLOCK_HASH_SIZE);
    p += DNAC_BLOCK_HASH_SIZE;

    /* genesis_message(64) */
    memcpy(p, cd->genesis_message, DNAC_GENESIS_MESSAGE_LEN);
    p += DNAC_GENESIS_MESSAGE_LEN;

    /* witness_count(4 LE) */
    enc_u32_le(cd->witness_count, p);
    p += 4;

    /* max_active_witnesses(4 LE) */
    enc_u32_le(cd->max_active_witnesses, p);
    p += 4;

    /* witness_pubkeys[0..witness_count-1] */
    for (uint32_t i = 0; i < cd->witness_count; i++) {
        memcpy(p, cd->witness_pubkeys[i], DNAC_PUBKEY_SIZE);
        p += DNAC_PUBKEY_SIZE;
    }

    /* block_interval_sec(4 LE) */
    enc_u32_le(cd->block_interval_sec, p);
    p += 4;

    /* max_txs_per_block(4 LE) */
    enc_u32_le(cd->max_txs_per_block, p);
    p += 4;

    /* view_change_timeout_ms(4 LE) */
    enc_u32_le(cd->view_change_timeout_ms, p);
    p += 4;

    /* token_symbol(8) */
    memcpy(p, cd->token_symbol, DNAC_TOKEN_SYMBOL_LEN);
    p += DNAC_TOKEN_SYMBOL_LEN;

    /* token_decimals(1) */
    *p++ = cd->token_decimals;

    /* initial_supply_raw(8 LE) */
    enc_u64_le(cd->initial_supply_raw, p);
    p += 8;

    /* native_token_id(64) */
    memcpy(p, cd->native_token_id, DNAC_TOKEN_ID_SIZE);
    p += DNAC_TOKEN_ID_SIZE;

    /* fee_recipient(32) */
    memcpy(p, cd->fee_recipient, DNAC_FEE_RECIPIENT_SIZE);
    p += DNAC_FEE_RECIPIENT_SIZE;

    *len = (size_t)(p - out);
    return (*len == need) ? 0 : -1;
}

/* ============================================================================
 * Decode
 * ========================================================================== */

int dnac_chain_def_decode(const uint8_t *bytes, size_t len,
                           dnac_chain_definition_t *cd_out) {
    if (!bytes || !cd_out) return -1;
    if (len < CD_FIXED_BYTES) return -1;

    const uint8_t *p = bytes;
    const uint8_t *end = bytes + len;

    /* chain_name(32) */
    memcpy(cd_out->chain_name, p, DNAC_CHAIN_NAME_LEN);
    p += DNAC_CHAIN_NAME_LEN;

    /* protocol_version(4 LE) */
    cd_out->protocol_version = dec_u32_le(p);
    p += 4;

    /* parent_chain_id(64) */
    memcpy(cd_out->parent_chain_id, p, DNAC_BLOCK_HASH_SIZE);
    p += DNAC_BLOCK_HASH_SIZE;

    /* genesis_message(64) */
    memcpy(cd_out->genesis_message, p, DNAC_GENESIS_MESSAGE_LEN);
    p += DNAC_GENESIS_MESSAGE_LEN;

    /* witness_count(4 LE) */
    uint32_t witness_count = dec_u32_le(p);
    p += 4;
    if (witness_count > DNAC_MAX_WITNESSES_COMPILE_CAP) return -1;
    cd_out->witness_count = witness_count;

    /* max_active_witnesses(4 LE) */
    cd_out->max_active_witnesses = dec_u32_le(p);
    p += 4;

    /* Validate total input length now that witness_count is known. */
    size_t expected = CD_FIXED_BYTES
                    + ((size_t)witness_count * DNAC_PUBKEY_SIZE);
    if (len != expected) return -1;

    /* witness_pubkeys[0..witness_count-1] */
    for (uint32_t i = 0; i < witness_count; i++) {
        if ((size_t)(end - p) < DNAC_PUBKEY_SIZE) return -1;
        memcpy(cd_out->witness_pubkeys[i], p, DNAC_PUBKEY_SIZE);
        p += DNAC_PUBKEY_SIZE;
    }

    /* block_interval_sec(4 LE) */
    cd_out->block_interval_sec = dec_u32_le(p);
    p += 4;

    /* max_txs_per_block(4 LE) */
    cd_out->max_txs_per_block = dec_u32_le(p);
    p += 4;

    /* view_change_timeout_ms(4 LE) */
    cd_out->view_change_timeout_ms = dec_u32_le(p);
    p += 4;

    /* token_symbol(8) */
    memcpy(cd_out->token_symbol, p, DNAC_TOKEN_SYMBOL_LEN);
    p += DNAC_TOKEN_SYMBOL_LEN;

    /* token_decimals(1) */
    cd_out->token_decimals = *p++;

    /* initial_supply_raw(8 LE) */
    cd_out->initial_supply_raw = dec_u64_le(p);
    p += 8;

    /* native_token_id(64) */
    memcpy(cd_out->native_token_id, p, DNAC_TOKEN_ID_SIZE);
    p += DNAC_TOKEN_ID_SIZE;

    /* fee_recipient(32) */
    memcpy(cd_out->fee_recipient, p, DNAC_FEE_RECIPIENT_SIZE);
    p += DNAC_FEE_RECIPIENT_SIZE;

    if (p != end) return -1;
    return 0;
}
