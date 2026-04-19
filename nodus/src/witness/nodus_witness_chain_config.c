/**
 * @file nodus_witness_chain_config.c
 * @brief Hard-Fork v1 -- witness-side chain_config implementation.
 *
 * Self-contained: no dependencies on libdna / dnac symbols. All tx_data
 * parsing is done inline so the nodus standalone build (which links only
 * libnodus.a) can resolve every reference.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "nodus/nodus_chain_config.h"
#include "nodus/nodus_types.h"        /* NODUS_TREE_TAG_CHAIN_CONFIG */

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_committee.h"
#include "witness/nodus_witness_merkle.h"

#include "protocol/nodus_tier3.h"     /* NODUS_T3_NULLIFIER_LEN etc. */

#include "crypto/sign/qgp_dilithium.h"
#include "crypto/hash/qgp_sha3.h"
#include "crypto/utils/qgp_log.h"

#include <openssl/evp.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LOG_TAG "CHAIN_CONFIG"

/* CHAIN_CONFIG TX constants -- mirror of dnac/include/dnac/transaction.h
 * and dnac/include/dnac/dnac.h. Duplicated here so the nodus standalone
 * build does not need to link libdna. If any constant drifts between
 * the client and witness, chain_config TXs get silent consensus
 * divergence -- so all values are pinned by static_assert below. */
#define CC_PUBKEY_SIZE              2592
#define CC_SIGNATURE_SIZE           4627
#define CC_TX_HASH_SIZE             64
#define CC_COMMITTEE_SIZE           7
#define CC_MIN_SIGS                 5
#define CC_MAX_SIGS                 CC_COMMITTEE_SIZE
#define CC_PURPOSE_TAG_LEN          16
#define CC_TX_TYPE                  10    /* DNAC_TX_CHAIN_CONFIG */
#define CC_PARAM_MAX_ID             3
#define CC_PARAM_MAX_TXS            1
#define CC_PARAM_BLOCK_INTERVAL     2
#define CC_PARAM_INFLATION_START    3
#define CC_MAX_TXS_HARD_CAP         10ULL
#define CC_MIN_BLOCK_INTERVAL_SEC   1ULL
#define CC_MAX_BLOCK_INTERVAL_SEC   15ULL
#define CC_MAX_INFLATION_START      281474976710656ULL  /* 2^48 */

static const uint8_t CC_PURPOSE_TAG[CC_PURPOSE_TAG_LEN] = {
    'D','N','A','C','_','C','C','_','v','1',0,0,0,0,0,0
};

/* Wire-format constants from dnac/src/transaction/serialize.c layout. */
#define CC_TX_HEADER_SIZE    (1 + 1 + 8 + CC_TX_HASH_SIZE)  /* 74 */
#define CC_NULLIFIER_LEN     NODUS_T3_NULLIFIER_LEN          /* 64 */
#define CC_TOKEN_ID_LEN      64
#define CC_FINGERPRINT_LEN   129
#define CC_SEED_LEN          32

/* Parsed chain_config fields (mirror of dnac_tx_chain_config_fields_t). */
typedef struct {
    uint8_t  param_id;
    uint64_t new_value;
    uint64_t effective_block_height;
    uint64_t proposal_nonce;
    uint64_t signed_at_block;
    uint64_t valid_before_block;
    uint8_t  committee_sig_count;
    uint8_t  witness_ids[CC_COMMITTEE_SIZE][32];
    uint8_t  signatures[CC_COMMITTEE_SIZE][CC_SIGNATURE_SIZE];
} cc_fields_t;

static void be64_into(uint64_t v, uint8_t out[8]) {
    for (int i = 7; i >= 0; i--) { out[i] = (uint8_t)(v & 0xff); v >>= 8; }
}

static uint64_t be64_from(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | (uint64_t)p[i];
    return v;
}

/* ============================================================================
 * Schema migration
 * ========================================================================== */

int nodus_chain_config_db_migrate(nodus_witness_t *w) {
    if (!w || !w->db) return -1;

    static const char *const stmts[] = {
        "CREATE TABLE IF NOT EXISTS chain_config_history ("
        "    param_id          INTEGER NOT NULL,"
        "    new_value         INTEGER NOT NULL,"
        "    effective_block   INTEGER NOT NULL,"
        "    commit_block      INTEGER NOT NULL,"
        "    tx_hash           BLOB    NOT NULL,"
        "    proposal_nonce    INTEGER NOT NULL,"
        "    created_at_unix   INTEGER NOT NULL,"
        "    PRIMARY KEY (param_id, effective_block)"
        ")",
        "CREATE INDEX IF NOT EXISTS idx_chain_config_active "
        "ON chain_config_history (param_id, effective_block)"
    };

    for (size_t i = 0; i < sizeof(stmts) / sizeof(stmts[0]); i++) {
        char *err = NULL;
        int rc = sqlite3_exec(w->db, stmts[i], NULL, NULL, &err);
        if (rc != SQLITE_OK) {
            fprintf(stderr,
                    "MIGRATION FAILURE: chain_config migration stmt[%zu] "
                    "sqlite error %d: %s\n",
                    i, rc, err ? err : "(null)");
            if (err) sqlite3_free(err);
            abort();
        }
        if (err) sqlite3_free(err);
    }
    return 0;
}

/* ============================================================================
 * Active-override lookup
 * ========================================================================== */

/* Cache warm-up (CC-OPS-004 / Q16). Pulls every row from
 * chain_config_history grouped by param_id, sorted ascending by
 * effective_block so lookup can walk backwards for latest-effective-wins.
 * Called on first get_u64 after cache_warm == false. */
static int cc_cache_warm_from_db(nodus_witness_t *w) {
    if (!w || !w->db) return -1;

    /* Clear counts */
    for (int i = 0; i < 4; i++) w->chain_config_cache_count[i] = 0;

    const char *sql =
        "SELECT param_id, new_value, effective_block "
        "FROM chain_config_history "
        "ORDER BY param_id ASC, effective_block ASC";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(w->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        QGP_LOG_WARN(LOG_TAG, "cache warm: prepare failed: %s",
                     sqlite3_errmsg(w->db));
        return -1;
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        int param_id = sqlite3_column_int(stmt, 0);
        if (param_id < 0 || param_id >= 4) continue;  /* defense */
        int slot = w->chain_config_cache_count[param_id];
        if (slot >= 64) continue;  /* cache full — unlikely */
        w->chain_config_cache[param_id][slot].new_value =
            (uint64_t)sqlite3_column_int64(stmt, 1);
        w->chain_config_cache[param_id][slot].effective_block =
            (uint64_t)sqlite3_column_int64(stmt, 2);
        w->chain_config_cache_count[param_id] = slot + 1;
    }
    sqlite3_finalize(stmt);
    w->chain_config_cache_warm = true;
    return 0;
}

uint64_t nodus_chain_config_get_u64(nodus_witness_t *w,
                                     uint8_t param_id,
                                     uint64_t current_block,
                                     uint64_t default_value) {
    if (!w || !w->db) return default_value;
    if (param_id >= 4) return default_value;  /* defense */

    /* Cache warm-up if needed (CC-OPS-004 / Q16). */
    if (!w->chain_config_cache_warm) {
        if (cc_cache_warm_from_db(w) != 0) {
            /* Warm-up failed — fall through to DB-direct lookup below
             * so we never return a WRONG value due to cache miss. */
        }
    }

    /* Fast path: walk cache backwards (rows sorted by effective_block
     * ascending), first row with effective_block <= current_block wins. */
    if (w->chain_config_cache_warm) {
        int n = w->chain_config_cache_count[param_id];
        for (int i = n - 1; i >= 0; i--) {
            if (w->chain_config_cache[param_id][i].effective_block
                <= current_block) {
                return w->chain_config_cache[param_id][i].new_value;
            }
        }
        /* No row active at current_block — return default. */
        return default_value;
    }

    /* Cache warm-up failed — fall back to direct DB lookup so we never
     * return wrong value because of transient cache failure. */
    const char *sql =
        "SELECT new_value FROM chain_config_history "
        "WHERE param_id = ? AND effective_block <= ? "
        "ORDER BY effective_block DESC LIMIT 1";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(w->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        QGP_LOG_WARN(LOG_TAG, "get_u64 prepare failed: %s",
                     sqlite3_errmsg(w->db));
        return default_value;
    }
    sqlite3_bind_int(stmt, 1, (int)param_id);
    sqlite3_bind_int64(stmt, 2, (sqlite3_int64)current_block);

    uint64_t out = default_value;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        out = (uint64_t)sqlite3_column_int64(stmt, 0);
    }
    sqlite3_finalize(stmt);
    return out;
}

/* ============================================================================
 * Merkle helpers (local RFC6962, 0x00 leaf / 0x01 inner tags)
 * ========================================================================== */

static int cc_leaf_hash(const uint8_t *raw, size_t len, uint8_t out[64]) {
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    if (!md) return -1;
    const uint8_t tag = 0x00;
    if (EVP_DigestInit_ex(md, EVP_sha3_512(), NULL) != 1 ||
        EVP_DigestUpdate(md, &tag, 1) != 1 ||
        EVP_DigestUpdate(md, raw, len) != 1 ||
        EVP_DigestFinal_ex(md, out, NULL) != 1) {
        EVP_MD_CTX_free(md);
        return -1;
    }
    EVP_MD_CTX_free(md);
    return 0;
}

static int cc_inner_hash(const uint8_t l[64], const uint8_t r[64],
                          uint8_t out[64]) {
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    if (!md) return -1;
    const uint8_t tag = 0x01;
    if (EVP_DigestInit_ex(md, EVP_sha3_512(), NULL) != 1 ||
        EVP_DigestUpdate(md, &tag, 1) != 1 ||
        EVP_DigestUpdate(md, l, 64) != 1 ||
        EVP_DigestUpdate(md, r, 64) != 1 ||
        EVP_DigestFinal_ex(md, out, NULL) != 1) {
        EVP_MD_CTX_free(md);
        return -1;
    }
    EVP_MD_CTX_free(md);
    return 0;
}

static int merkle_root_from_leaves(uint8_t (*leaves)[64], size_t n,
                                    uint8_t out[64]) {
    if (n == 0) return -1;
    if (n == 1) { memcpy(out, leaves[0], 64); return 0; }
    size_t k = 1;
    while (k * 2 < n) k *= 2;
    uint8_t left[64], right[64];
    if (merkle_root_from_leaves(leaves, k, left) != 0) return -1;
    if (merkle_root_from_leaves(leaves + k, n - k, right) != 0) return -1;
    return cc_inner_hash(left, right, out);
}

int nodus_chain_config_compute_root(nodus_witness_t *w, uint8_t out_root[64]) {
    if (!w || !w->db || !out_root) return -1;

    const char *sql =
        "SELECT param_id, new_value, effective_block, commit_block, "
        "       proposal_nonce "
        "FROM chain_config_history "
        "ORDER BY effective_block ASC, param_id ASC, "
        "         commit_block ASC, proposal_nonce ASC";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(w->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "compute_root prepare failed: %s",
                      sqlite3_errmsg(w->db));
        return -1;
    }

    size_t cap = 16;
    size_t n = 0;
    uint8_t (*leaves)[64] = malloc(cap * 64);
    if (!leaves) { sqlite3_finalize(stmt); return -1; }

    int rc;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (n == cap) {
            size_t new_cap = cap * 2;
            uint8_t (*tmp)[64] = realloc(leaves, new_cap * 64);
            if (!tmp) { free(leaves); sqlite3_finalize(stmt); return -1; }
            leaves = tmp;
            cap = new_cap;
        }
        uint8_t  param_id        = (uint8_t)sqlite3_column_int(stmt, 0);
        uint64_t new_value       = (uint64_t)sqlite3_column_int64(stmt, 1);
        uint64_t effective_block = (uint64_t)sqlite3_column_int64(stmt, 2);
        uint64_t commit_block    = (uint64_t)sqlite3_column_int64(stmt, 3);
        uint64_t proposal_nonce  = (uint64_t)sqlite3_column_int64(stmt, 4);

        uint8_t raw[1 + 8 + 8 + 8 + 8];
        raw[0] = param_id;
        be64_into(new_value,       raw + 1);
        be64_into(effective_block, raw + 9);
        be64_into(commit_block,    raw + 17);
        be64_into(proposal_nonce,  raw + 25);

        if (cc_leaf_hash(raw, sizeof(raw), leaves[n]) != 0) {
            free(leaves);
            sqlite3_finalize(stmt);
            return -1;
        }
        n++;
    }
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "compute_root step failed rc=%d", rc);
        free(leaves);
        return -1;
    }

    int result;
    if (n == 0) {
        nodus_merkle_empty_root(NODUS_TREE_TAG_CHAIN_CONFIG, out_root);
        result = 0;
    } else {
        result = merkle_root_from_leaves(leaves, n, out_root);
    }
    free(leaves);
    return result;
}

/* ============================================================================
 * TX-parse helpers
 * ========================================================================== */

/* Walk tx_data past inputs/outputs/witnesses/signers to position `off` at
 * the start of the appended CHAIN_CONFIG fields. Returns 0 on success,
 * -1 on truncated / malformed input. The walk mirrors dnac/src/transaction
 * /serialize.c exactly -- a drift here is a silent consensus break. */
static int find_cc_appended_offset(const uint8_t *tx_data, uint32_t tx_len,
                                    size_t *off_out) {
    if (!tx_data || !off_out) return -1;
    if (tx_len < CC_TX_HEADER_SIZE + 1) return -1;
    size_t off = CC_TX_HEADER_SIZE;  /* past version+type+timestamp+tx_hash */

    /* inputs */
    if (off >= tx_len) return -1;
    uint8_t input_count = tx_data[off++];
    const size_t input_size = CC_NULLIFIER_LEN + 8 + CC_TOKEN_ID_LEN;
    if ((size_t)input_count * input_size > tx_len - off) return -1;
    off += (size_t)input_count * input_size;

    /* outputs (variable memo) */
    if (off >= tx_len) return -1;
    uint8_t output_count = tx_data[off++];
    for (int i = 0; i < output_count; i++) {
        /* version(1) + fp(129) + amount(8) + token_id(64) + seed(32) + memo_len(1) */
        if (off + 1 + CC_FINGERPRINT_LEN + 8 + CC_TOKEN_ID_LEN + CC_SEED_LEN + 1 > tx_len)
            return -1;
        off += 1 + CC_FINGERPRINT_LEN + 8 + CC_TOKEN_ID_LEN + CC_SEED_LEN;
        uint8_t memo_len = tx_data[off++];
        if (memo_len > tx_len - off) return -1;
        off += memo_len;
    }

    /* witnesses */
    if (off >= tx_len) return -1;
    uint8_t witness_count = tx_data[off++];
    const size_t witness_size = 32 + CC_SIGNATURE_SIZE + 8 + CC_PUBKEY_SIZE;
    if ((size_t)witness_count * witness_size > tx_len - off) return -1;
    off += (size_t)witness_count * witness_size;

    /* signers */
    if (off >= tx_len) return -1;
    uint8_t signer_count = tx_data[off++];
    if (signer_count == 0) return -1;
    const size_t signer_size = CC_PUBKEY_SIZE + CC_SIGNATURE_SIZE;
    if ((size_t)signer_count * signer_size > tx_len - off) return -1;
    off += (size_t)signer_count * signer_size;

    *off_out = off;
    return 0;
}

/* Parse the CHAIN_CONFIG appended fields starting at `off`. Validates
 * that committee_sig_count is within [MIN, MAX] and that the byte-range
 * fits in tx_len. Returns 0 on success. */
static int parse_cc_fields(const uint8_t *tx_data, uint32_t tx_len, size_t off,
                            cc_fields_t *out) {
    const size_t fixed_len = 1 + 8 + 8 + 8 + 8 + 8 + 1;  /* 42 */
    if (off + fixed_len > tx_len) return -1;

    out->param_id               = tx_data[off];                    off += 1;
    out->new_value              = be64_from(tx_data + off);        off += 8;
    out->effective_block_height = be64_from(tx_data + off);        off += 8;
    out->proposal_nonce         = be64_from(tx_data + off);        off += 8;
    out->signed_at_block        = be64_from(tx_data + off);        off += 8;
    out->valid_before_block     = be64_from(tx_data + off);        off += 8;
    out->committee_sig_count    = tx_data[off];                    off += 1;

    if (out->committee_sig_count > CC_MAX_SIGS) return -1;
    const size_t per_vote = 32 + CC_SIGNATURE_SIZE;
    size_t votes_total = (size_t)out->committee_sig_count * per_vote;
    if (off + votes_total > tx_len) return -1;

    for (uint8_t i = 0; i < out->committee_sig_count; i++) {
        memcpy(out->witness_ids[i], tx_data + off, 32);   off += 32;
        memcpy(out->signatures[i],  tx_data + off, CC_SIGNATURE_SIZE);
        off += CC_SIGNATURE_SIZE;
    }
    return 0;
}

/* Client-side local rule subset (mirror of dnac_tx_verify_chain_config_rules
 * in dnac/src/transaction/verify.c). Returns 0 on success. */
static int verify_cc_local_rules(const cc_fields_t *cc) {
    if (cc->param_id < 1 || cc->param_id > CC_PARAM_MAX_ID) return -1;

    switch (cc->param_id) {
        case CC_PARAM_MAX_TXS:
            if (cc->new_value < 1ULL || cc->new_value > CC_MAX_TXS_HARD_CAP)
                return -1;
            break;
        case CC_PARAM_BLOCK_INTERVAL:
            if (cc->new_value < CC_MIN_BLOCK_INTERVAL_SEC ||
                cc->new_value > CC_MAX_BLOCK_INTERVAL_SEC) return -1;
            break;
        case CC_PARAM_INFLATION_START:
            if (cc->new_value > CC_MAX_INFLATION_START) return -1;
            break;
        default:
            return -1;
    }

    if (cc->signed_at_block == 0) return -1;
    if (cc->valid_before_block <= cc->effective_block_height) return -1;
    if (cc->valid_before_block <= cc->signed_at_block) return -1;
    if (cc->committee_sig_count < CC_MIN_SIGS ||
        cc->committee_sig_count > CC_MAX_SIGS) return -1;

    /* pairwise-distinct witness_ids */
    for (uint8_t i = 0; i < cc->committee_sig_count; i++) {
        for (uint8_t j = (uint8_t)(i + 1); j < cc->committee_sig_count; j++) {
            if (memcmp(cc->witness_ids[i], cc->witness_ids[j], 32) == 0)
                return -1;
        }
    }
    return 0;
}

/* ============================================================================
 * Apply
 * ========================================================================== */

/* ============================================================================
 * Vote primitives (Stage C — public API, pure functions)
 * ========================================================================== */

int nodus_chain_config_derive_witness_id(const uint8_t pubkey[NODUS_CC_PUBKEY_SIZE],
                                          uint8_t out_witness_id[NODUS_CC_WITNESS_ID_SIZE]) {
    if (!pubkey || !out_witness_id) return -1;
    uint8_t full[64];
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    if (!md) return -1;
    if (EVP_DigestInit_ex(md, EVP_sha3_512(), NULL) != 1 ||
        EVP_DigestUpdate(md, pubkey, NODUS_CC_PUBKEY_SIZE) != 1 ||
        EVP_DigestFinal_ex(md, full, NULL) != 1) {
        EVP_MD_CTX_free(md);
        return -1;
    }
    EVP_MD_CTX_free(md);
    memcpy(out_witness_id, full, NODUS_CC_WITNESS_ID_SIZE);
    return 0;
}

int nodus_chain_config_compute_digest(const uint8_t chain_id[32],
                                       uint8_t  param_id,
                                       uint64_t new_value,
                                       uint64_t effective_block_height,
                                       uint64_t proposal_nonce,
                                       uint64_t signed_at_block,
                                       uint64_t valid_before_block,
                                       uint8_t  out_digest[NODUS_CC_DIGEST_SIZE]) {
    if (!chain_id || !out_digest) return -1;
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    if (!md) return -1;
    uint8_t u64_be[8];
    int ok =
        EVP_DigestInit_ex(md, EVP_sha3_512(), NULL) == 1 &&
        EVP_DigestUpdate(md, CC_PURPOSE_TAG, CC_PURPOSE_TAG_LEN) == 1 &&
        EVP_DigestUpdate(md, chain_id, 32) == 1 &&
        EVP_DigestUpdate(md, &param_id, 1) == 1;
    if (ok) { be64_into(new_value, u64_be);
              ok &= EVP_DigestUpdate(md, u64_be, 8) == 1; }
    if (ok) { be64_into(effective_block_height, u64_be);
              ok &= EVP_DigestUpdate(md, u64_be, 8) == 1; }
    if (ok) { be64_into(proposal_nonce, u64_be);
              ok &= EVP_DigestUpdate(md, u64_be, 8) == 1; }
    if (ok) { be64_into(signed_at_block, u64_be);
              ok &= EVP_DigestUpdate(md, u64_be, 8) == 1; }
    if (ok) { be64_into(valid_before_block, u64_be);
              ok &= EVP_DigestUpdate(md, u64_be, 8) == 1; }
    ok &= EVP_DigestFinal_ex(md, out_digest, NULL) == 1;
    EVP_MD_CTX_free(md);
    return ok ? 0 : -1;
}

int nodus_chain_config_sign_vote(const uint8_t pubkey[NODUS_CC_PUBKEY_SIZE],
                                  const uint8_t seckey[NODUS_CC_SECKEY_SIZE],
                                  const uint8_t digest[NODUS_CC_DIGEST_SIZE],
                                  uint8_t out_witness_id[NODUS_CC_WITNESS_ID_SIZE],
                                  uint8_t out_signature[NODUS_CC_SIG_SIZE]) {
    if (!pubkey || !seckey || !digest || !out_witness_id || !out_signature)
        return -1;
    if (nodus_chain_config_derive_witness_id(pubkey, out_witness_id) != 0)
        return -1;
    size_t siglen = 0;
    if (qgp_dsa87_sign(out_signature, &siglen,
                        digest, NODUS_CC_DIGEST_SIZE, seckey) != 0) {
        return -1;
    }
    /* Dilithium5 signatures are fixed-length; any deviation indicates a
     * corrupt key or library bug — bail rather than ship a short sig. */
    if (siglen != NODUS_CC_SIG_SIZE) return -1;
    return 0;
}

int nodus_chain_config_verify_vote(const uint8_t pubkey[NODUS_CC_PUBKEY_SIZE],
                                    const uint8_t digest[NODUS_CC_DIGEST_SIZE],
                                    const uint8_t signature[NODUS_CC_SIG_SIZE]) {
    if (!pubkey || !digest || !signature) return -1;
    if (qgp_dsa87_verify(signature, NODUS_CC_SIG_SIZE,
                          digest, NODUS_CC_DIGEST_SIZE, pubkey) != 0) {
        return -1;
    }
    return 0;
}

/* Internal wrapper so the apply function's call site stays compact;
 * delegates to the public primitive so the formula is single-sourced. */
static int compute_proposal_digest(const uint8_t chain_id[32],
                                    const cc_fields_t *cc,
                                    uint8_t digest[64]) {
    return nodus_chain_config_compute_digest(chain_id,
                                              cc->param_id,
                                              cc->new_value,
                                              cc->effective_block_height,
                                              cc->proposal_nonce,
                                              cc->signed_at_block,
                                              cc->valid_before_block,
                                              digest);
}

/* Internal alias kept for readability at the apply call site. */
static int derive_witness_id(const uint8_t pubkey[CC_PUBKEY_SIZE],
                              uint8_t out_id[32]) {
    return nodus_chain_config_derive_witness_id(pubkey, out_id);
}

/* Per-param grace minimum (Q4 Option B, CC-GOV-004 mitigation). */
static uint64_t grace_period_for_param(uint8_t param_id) {
    switch (param_id) {
        case CC_PARAM_BLOCK_INTERVAL:
        case CC_PARAM_INFLATION_START:
            return 12ULL * (uint64_t)DNAC_EPOCH_LENGTH;
        case CC_PARAM_MAX_TXS:
        default:
            return (uint64_t)DNAC_EPOCH_LENGTH;
    }
}

int nodus_chain_config_apply(nodus_witness_t *w,
                              const uint8_t *tx_data,
                              uint32_t tx_len,
                              uint64_t block_height) {
    if (!w || !w->db || !tx_data) {
        QGP_LOG_ERROR(LOG_TAG, "apply: invalid args");
        return -1;
    }
    if (tx_len < CC_TX_HEADER_SIZE) {
        QGP_LOG_ERROR(LOG_TAG, "apply: tx_len < header");
        return -1;
    }

    /* Header sanity. tx_data[0]=version, tx_data[1]=type, tx_data[2..9]=timestamp,
     * tx_data[10..73]=tx_hash. */
    if (tx_data[1] != CC_TX_TYPE) {
        QGP_LOG_ERROR(LOG_TAG, "apply: type_byte=%u != CHAIN_CONFIG(10)",
                      (unsigned)tx_data[1]);
        return -1;
    }
    const uint8_t *tx_hash = tx_data + 10;

    /* Walk past inputs/outputs/witnesses/signers to reach appended section. */
    size_t off = 0;
    if (find_cc_appended_offset(tx_data, tx_len, &off) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "apply: malformed tx (offset walk)");
        return -1;
    }

    cc_fields_t cc;
    if (parse_cc_fields(tx_data, tx_len, off, &cc) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "apply: malformed appended fields");
        return -1;
    }

    /* Local rules (match client-side verify). */
    if (verify_cc_local_rules(&cc) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "apply: local rule violation");
        return -1;
    }

    /* Freshness (CC-G). */
    if (block_height > cc.valid_before_block) {
        QGP_LOG_ERROR(LOG_TAG,
                      "apply: stale -- commit=%llu > valid_before=%llu",
                      (unsigned long long)block_height,
                      (unsigned long long)cc.valid_before_block);
        return -1;
    }

    /* Grace (CC-C, Q4 Option B per-param tier). */
    uint64_t grace = grace_period_for_param(cc.param_id);
    if (cc.effective_block_height < block_height + grace) {
        QGP_LOG_ERROR(LOG_TAG,
                      "apply: grace -- effective=%llu < commit=%llu + grace=%llu",
                      (unsigned long long)cc.effective_block_height,
                      (unsigned long long)block_height,
                      (unsigned long long)grace);
        return -1;
    }

    /* Committee lookup at commit_block - 1. */
    nodus_committee_member_t committee[CC_COMMITTEE_SIZE];
    int committee_count = 0;
    uint64_t lookup_height = (block_height == 0) ? 0 : block_height - 1;
    if (nodus_committee_get_for_block(w, lookup_height, committee,
                                       CC_COMMITTEE_SIZE,
                                       &committee_count) != 0 ||
        committee_count == 0) {
        QGP_LOG_ERROR(LOG_TAG,
                      "apply: committee lookup failed at height=%llu",
                      (unsigned long long)lookup_height);
        return -1;
    }

    uint8_t committee_ids[CC_COMMITTEE_SIZE][32];
    for (int i = 0; i < committee_count; i++) {
        if (derive_witness_id(committee[i].pubkey, committee_ids[i]) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "apply: derive_witness_id failed i=%d", i);
            return -1;
        }
    }

    /* Compute proposal digest committee members signed. Uses w->chain_id
     * (witness local truth), not any client-supplied chain_id. */
    uint8_t digest[64];
    if (compute_proposal_digest(w->chain_id, &cc, digest) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "apply: digest compute failed");
        return -1;
    }

    /* Verify each vote. */
    int verified = 0;
    for (uint8_t v = 0; v < cc.committee_sig_count; v++) {
        int match = -1;
        for (int c = 0; c < committee_count; c++) {
            if (memcmp(cc.witness_ids[v], committee_ids[c], 32) == 0) {
                match = c;
                break;
            }
        }
        if (match < 0) {
            QGP_LOG_ERROR(LOG_TAG,
                          "apply: vote[%u] witness_id not in current committee",
                          (unsigned)v);
            return -1;
        }
        if (qgp_dsa87_verify(cc.signatures[v], CC_SIGNATURE_SIZE,
                              digest, sizeof(digest),
                              committee[match].pubkey) != 0) {
            QGP_LOG_ERROR(LOG_TAG,
                          "apply: vote[%u] Dilithium5 verify failed",
                          (unsigned)v);
            return -1;
        }
        verified++;
    }
    if (verified < CC_MIN_SIGS) {
        QGP_LOG_ERROR(LOG_TAG, "apply: verified=%d < min=%d",
                      verified, CC_MIN_SIGS);
        return -1;
    }

    /* Monotonicity for INFLATION_START_BLOCK (Q5 / CC-GOV-001). */
    if (cc.param_id == CC_PARAM_INFLATION_START) {
        const char *exists_sql =
            "SELECT new_value FROM chain_config_history "
            "WHERE param_id = ? AND new_value > 0 "
            "ORDER BY commit_block DESC LIMIT 1";
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(w->db, exists_sql, -1, &st, NULL) == SQLITE_OK) {
            sqlite3_bind_int(st, 1, CC_PARAM_INFLATION_START);
            if (sqlite3_step(st) == SQLITE_ROW) {
                if (cc.new_value == 0) {
                    QGP_LOG_ERROR(LOG_TAG,
                                  "apply: INFLATION_START_BLOCK monotonicity -- "
                                  "cannot disable once enabled");
                    sqlite3_finalize(st);
                    return -1;
                }
                if (cc.new_value > block_height) {
                    QGP_LOG_ERROR(LOG_TAG,
                                  "apply: INFLATION_START_BLOCK monotonicity -- "
                                  "cannot move start_block forward past current_block");
                    sqlite3_finalize(st);
                    return -1;
                }
            }
            sqlite3_finalize(st);
        }
    }

    /* INSERT row; PK conflict = replay reject. */
    const char *ins_sql =
        "INSERT INTO chain_config_history "
        "(param_id, new_value, effective_block, commit_block, tx_hash, "
        " proposal_nonce, created_at_unix) "
        "VALUES (?, ?, ?, ?, ?, ?, strftime('%s','now'))";
    sqlite3_stmt *ins = NULL;
    if (sqlite3_prepare_v2(w->db, ins_sql, -1, &ins, NULL) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "apply: insert prepare failed: %s",
                      sqlite3_errmsg(w->db));
        return -1;
    }
    sqlite3_bind_int  (ins, 1, (int)cc.param_id);
    sqlite3_bind_int64(ins, 2, (sqlite3_int64)cc.new_value);
    sqlite3_bind_int64(ins, 3, (sqlite3_int64)cc.effective_block_height);
    sqlite3_bind_int64(ins, 4, (sqlite3_int64)block_height);
    sqlite3_bind_blob (ins, 5, tx_hash, CC_TX_HASH_SIZE, SQLITE_TRANSIENT);
    sqlite3_bind_int64(ins, 6, (sqlite3_int64)cc.proposal_nonce);

    int srv = sqlite3_step(ins);
    sqlite3_finalize(ins);
    if (srv != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "apply: insert failed rc=%d", srv);
        return -1;
    }

    /* CC-OPS-004 / Q16 — invalidate cache BEFORE outer transaction
     * commits. Rationale: if outer tx rolls back after this point the
     * cache being stale (flag=false) just means next lookup re-warms
     * from DB, which will NOT have the rolled-back row. Cache coherence
     * preserved in both commit and rollback paths. */
    w->chain_config_cache_warm = false;

    QGP_LOG_WARN(LOG_TAG,
                 "CHAIN_CONFIG_PROPOSAL committed: param_id=%u new_value=%llu "
                 "effective=%llu commit=%llu nonce=%016llx",
                 (unsigned)cc.param_id,
                 (unsigned long long)cc.new_value,
                 (unsigned long long)cc.effective_block_height,
                 (unsigned long long)block_height,
                 (unsigned long long)cc.proposal_nonce);

    return 0;
}
