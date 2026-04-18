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

/* Big-endian u16 (for initial_validators[].commission_bps; wire-stable). */
static inline void enc_u16_be(uint16_t v, uint8_t out[2]) {
    out[0] = (uint8_t)((v >> 8) & 0xff);
    out[1] = (uint8_t)(v & 0xff);
}

static inline uint16_t dec_u16_be(const uint8_t in[2]) {
    return (uint16_t)(((uint16_t)in[0] << 8) | (uint16_t)in[1]);
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

/* Phase 12 Task 56 — initial_validator trailer.
 *
 * Appended after fee_recipient:
 *   initial_validator_count(1) || count × (
 *     pubkey(2592) || unstake_destination_fp(129) ||
 *     commission_bps(2 BE) || endpoint(128) )
 *
 * Per-entry size = 2592 + 129 + 2 + 128 = 2851 bytes.
 * Full 129-byte fp + 128-byte endpoint buffers participate in the hash
 * (including post-NUL padding) — prevents malleability where mutating
 * padding leaves the decoded string unchanged but alters the chain_id. */
#define CD_IV_ENTRY_BYTES   (DNAC_PUBKEY_SIZE                        \
                           + DNAC_FINGERPRINT_SIZE                   \
                           + 2                                       \
                           + DNAC_INITIAL_VALIDATOR_ENDPOINT_LEN)
#define CD_IV_TRAILER_BYTES(n)  (1 + ((size_t)(n) * CD_IV_ENTRY_BYTES))

/* ============================================================================
 * Size helpers
 * ========================================================================== */

size_t dnac_chain_def_max_size(void) {
    return CD_FIXED_BYTES
         + ((size_t)DNAC_MAX_WITNESSES_COMPILE_CAP * DNAC_PUBKEY_SIZE)
         + CD_IV_TRAILER_BYTES(DNAC_COMMITTEE_SIZE);
}

size_t dnac_chain_def_encoded_size(const dnac_chain_definition_t *cd) {
    if (!cd) return 0;
    if (cd->witness_count > DNAC_MAX_WITNESSES_COMPILE_CAP) return 0;
    if (cd->initial_validator_count > DNAC_COMMITTEE_SIZE) return 0;
    return CD_FIXED_BYTES
         + ((size_t)cd->witness_count * DNAC_PUBKEY_SIZE)
         + CD_IV_TRAILER_BYTES(cd->initial_validator_count);
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

    /* initial_validator_count(1) */
    *p++ = cd->initial_validator_count;

    /* initial_validators[0..count-1] — full fixed-size buffers participate
     * in the hash (design §5.2 canonicality; prevents post-NUL malleability). */
    for (uint8_t i = 0; i < cd->initial_validator_count; i++) {
        const dnac_chain_initial_validator_t *iv = &cd->initial_validators[i];

        memcpy(p, iv->pubkey, DNAC_PUBKEY_SIZE);
        p += DNAC_PUBKEY_SIZE;

        memcpy(p, iv->unstake_destination_fp, DNAC_FINGERPRINT_SIZE);
        p += DNAC_FINGERPRINT_SIZE;

        enc_u16_be(iv->commission_bps, p);
        p += 2;

        memcpy(p, iv->endpoint, DNAC_INITIAL_VALIDATOR_ENDPOINT_LEN);
        p += DNAC_INITIAL_VALIDATOR_ENDPOINT_LEN;
    }

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

    /* Full-length validation happens after we read initial_validator_count
     * below; a simple lower-bound check lets us proceed safely through the
     * witness_pubkeys + tail fields first. */
    size_t min_expected_pre_iv = CD_FIXED_BYTES
                                + ((size_t)witness_count * DNAC_PUBKEY_SIZE);
    if (len < min_expected_pre_iv + 1 /* initial_validator_count byte */) return -1;

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

    /* initial_validator_count(1) */
    if ((size_t)(end - p) < 1) return -1;
    uint8_t iv_count = *p++;
    if (iv_count > DNAC_COMMITTEE_SIZE) return -1;
    cd_out->initial_validator_count = iv_count;

    /* Validate the exact byte count now that initial_validator_count is known. */
    size_t expected = CD_FIXED_BYTES
                    + ((size_t)witness_count * DNAC_PUBKEY_SIZE)
                    + CD_IV_TRAILER_BYTES(iv_count);
    if (len != expected) return -1;

    /* initial_validators[0..count-1] */
    for (uint8_t i = 0; i < iv_count; i++) {
        dnac_chain_initial_validator_t *iv = &cd_out->initial_validators[i];

        if ((size_t)(end - p) < DNAC_PUBKEY_SIZE) return -1;
        memcpy(iv->pubkey, p, DNAC_PUBKEY_SIZE);
        p += DNAC_PUBKEY_SIZE;

        if ((size_t)(end - p) < DNAC_FINGERPRINT_SIZE) return -1;
        memcpy(iv->unstake_destination_fp, p, DNAC_FINGERPRINT_SIZE);
        p += DNAC_FINGERPRINT_SIZE;

        if ((size_t)(end - p) < 2) return -1;
        iv->commission_bps = dec_u16_be(p);
        p += 2;

        if ((size_t)(end - p) < DNAC_INITIAL_VALIDATOR_ENDPOINT_LEN) return -1;
        memcpy(iv->endpoint, p, DNAC_INITIAL_VALIDATOR_ENDPOINT_LEN);
        p += DNAC_INITIAL_VALIDATOR_ENDPOINT_LEN;
    }

    if (p != end) return -1;
    return 0;
}
