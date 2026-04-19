/**
 * @file nodus_witness_genesis_seed.c
 * @brief Phase 12 Task 57 — seed validator_tree + reward_tree on genesis.
 *
 * Parses the initial_validators[] trailer appended to the genesis chain_def
 * blob (Task 56) inline — no libdna linkage required. Layout is pinned:
 *
 *   chain_def_blob ::=
 *     chain_name(32) || protocol_version(4) || parent_chain_id(64) ||
 *     genesis_message(64) || witness_count(4) || max_active_witnesses(4) ||
 *     witness_pubkeys[witness_count x 2592] ||
 *     block_interval_sec(4) || max_txs_per_block(4) || view_change_timeout_ms(4) ||
 *     token_symbol(8) || token_decimals(1) || initial_supply_raw(8) ||
 *     native_token_id(64) || fee_recipient(32) ||
 *     initial_validator_count(1) ||
 *     count x (
 *       pubkey(2592) ||
 *       unstake_destination_fp(129) ||
 *       commission_bps(2 BE) ||
 *       endpoint(128)
 *     )
 */

#include "witness/nodus_witness_genesis_seed.h"
#include "witness/nodus_witness.h"
#include "witness/nodus_witness_validator.h"
#include "witness/nodus_witness_reward.h"

#include "dnac/dnac.h"
#include "dnac/validator.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define LOG_TAG "WITNESS_GENESIS_SEED"

/* Sizes matching Task 56 canonical chain_def_codec.c layout. */
#define CD_FIXED_BYTES  (32 + 4 + 64 + 64 + 4 + 4 + 4 + 4 + 4 + 8 + 1 + 8 + 64 + 32)  /* = 297 */
#define IV_ENTRY_BYTES  (DNAC_PUBKEY_SIZE + DNAC_FINGERPRINT_SIZE + 2 + 128)          /* = 2851 */

int nodus_witness_genesis_seed_validators(nodus_witness_t *w,
                                            const uint8_t *cd_blob,
                                            size_t cd_blob_len) {
    if (!w) return -1;
    if (!cd_blob || cd_blob_len == 0) return 0;

    if (cd_blob_len < CD_FIXED_BYTES) {
        fprintf(stderr, "%s: cd_blob too short (%zu < %d)\n",
                LOG_TAG, cd_blob_len, CD_FIXED_BYTES);
        return -1;
    }

    /* witness_count is a little-endian u32 at offset 164
     * (chain_name(32) + protocol_version(4) + parent_chain_id(64) +
     *  genesis_message(64)). */
    const uint8_t *p_wc = cd_blob + 32 + 4 + 64 + 64;
    uint32_t witness_count = (uint32_t)p_wc[0]
                           | ((uint32_t)p_wc[1] << 8)
                           | ((uint32_t)p_wc[2] << 16)
                           | ((uint32_t)p_wc[3] << 24);
    if (witness_count > 21) {
        fprintf(stderr, "%s: witness_count %u out of range\n",
                LOG_TAG, witness_count);
        return -1;
    }

    size_t iv_count_off = CD_FIXED_BYTES
                        + (size_t)witness_count * DNAC_PUBKEY_SIZE;
    if (cd_blob_len < iv_count_off + 1) {
        return 0;  /* legacy blob without Task-56 trailer */
    }

    uint8_t iv_count = cd_blob[iv_count_off];
    if (iv_count == 0) return 0;
    if (iv_count > DNAC_COMMITTEE_SIZE) {
        fprintf(stderr, "%s: initial_validator_count %u > committee cap %u\n",
                LOG_TAG, (unsigned)iv_count, (unsigned)DNAC_COMMITTEE_SIZE);
        return -1;
    }

    size_t need = iv_count_off + 1 + (size_t)iv_count * IV_ENTRY_BYTES;
    if (cd_blob_len < need) {
        fprintf(stderr, "%s: cd_blob truncated: need %zu got %zu\n",
                LOG_TAG, need, cd_blob_len);
        return -1;
    }

    const uint8_t *p = cd_blob + iv_count_off + 1;

    for (uint8_t i = 0; i < iv_count; i++) {
        const uint8_t *iv_pubkey = p;
        p += DNAC_PUBKEY_SIZE;

        const uint8_t *iv_fp = p;
        p += DNAC_FINGERPRINT_SIZE;

        uint16_t commission_bps = (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
        p += 2;

        /* endpoint(128) skipped — discovery hint, not persisted on validator row. */
        p += 128;

        dnac_validator_record_t v;
        memset(&v, 0, sizeof(v));
        memcpy(v.pubkey, iv_pubkey, DNAC_PUBKEY_SIZE);
        v.self_stake                  = DNAC_SELF_STAKE_AMOUNT;
        v.total_delegated             = 0;
        v.external_delegated          = 0;
        v.commission_bps              = commission_bps;
        v.pending_commission_bps      = 0;
        v.pending_effective_block     = 0;
        v.status                      = DNAC_VALIDATOR_ACTIVE;
        v.active_since_block          = 1ULL;
        v.unstake_commit_block        = 0;
        memcpy(v.unstake_destination_fp, iv_fp, DNAC_FINGERPRINT_SIZE);
        v.last_validator_update_block = 0;
        v.consecutive_missed_epochs   = 0;
        v.last_signed_block           = 0;

        int rc = nodus_validator_insert(w, &v);
        if (rc != 0) {
            fprintf(stderr, "%s: validator_insert [%u] failed rc=%d\n",
                    LOG_TAG, (unsigned)i, rc);
            return -1;
        }

        dnac_reward_record_t r;
        memset(&r, 0, sizeof(r));
        memcpy(r.validator_pubkey, iv_pubkey, DNAC_PUBKEY_SIZE);
        r.last_update_block = 1ULL;

        rc = nodus_reward_upsert(w, &r);
        if (rc != 0) {
            fprintf(stderr, "%s: reward_upsert [%u] failed rc=%d\n",
                    LOG_TAG, (unsigned)i, rc);
            return -1;
        }
    }

    if (!w->db) {
        fprintf(stderr, "%s: witness db handle NULL\n", LOG_TAG);
        return -1;
    }
    char sql[192];
    snprintf(sql, sizeof(sql),
             "UPDATE validator_stats SET value = %u WHERE key = 'active_count'",
             (unsigned)iv_count);
    char *errmsg = NULL;
    if (sqlite3_exec(w->db, sql, NULL, NULL, &errmsg) != SQLITE_OK) {
        fprintf(stderr, "%s: validator_stats update failed: %s\n",
                LOG_TAG, errmsg ? errmsg : "(unknown)");
        if (errmsg) sqlite3_free(errmsg);
        return -1;
    }

    fprintf(stderr, "%s: seeded %u initial validators + rewards\n",
            LOG_TAG, (unsigned)iv_count);
    return 0;
}

int nodus_witness_parse_cd_supply(const uint8_t *cd_blob, size_t cd_blob_len,
                                    uint64_t *initial_supply_raw_out,
                                    uint8_t  *initial_validator_count_out) {
    if (!cd_blob || cd_blob_len == 0 ||
        !initial_supply_raw_out || !initial_validator_count_out) {
        return -1;
    }
    if (cd_blob_len < CD_FIXED_BYTES) return -1;

    /* witness_count is u32 LE at offset 164 (chain_name 32 + protocol_version 4
     * + parent_chain_id 64 + genesis_message 64). */
    const uint8_t *p_wc = cd_blob + 32 + 4 + 64 + 64;
    uint32_t witness_count = (uint32_t)p_wc[0]
                           | ((uint32_t)p_wc[1] << 8)
                           | ((uint32_t)p_wc[2] << 16)
                           | ((uint32_t)p_wc[3] << 24);
    if (witness_count > 21) return -1;

    /* initial_supply_raw is u64 LE at offset
     *   32 + 4 + 64 + 64 + 4 + 4 + witness_count*PUBKEY + 4 + 4 + 4 + 8 + 1
     * = 193 + witness_count * DNAC_PUBKEY_SIZE. */
    size_t isr_off = 193 + (size_t)witness_count * DNAC_PUBKEY_SIZE;
    if (cd_blob_len < isr_off + 8) return -1;
    const uint8_t *p = cd_blob + isr_off;
    uint64_t supply = 0;
    for (int i = 0; i < 8; i++) supply |= ((uint64_t)p[i]) << (i * 8);

    /* initial_validator_count is u8 at CD_FIXED_BYTES + witness_count * PUBKEY
     * (same offset the seeder uses). */
    size_t iv_count_off = CD_FIXED_BYTES
                        + (size_t)witness_count * DNAC_PUBKEY_SIZE;
    if (cd_blob_len < iv_count_off + 1) {
        /* Legacy blob without trailer — report count=0 but supply is valid. */
        *initial_supply_raw_out = supply;
        *initial_validator_count_out = 0;
        return 0;
    }
    *initial_supply_raw_out = supply;
    *initial_validator_count_out = cd_blob[iv_count_off];
    return 0;
}
