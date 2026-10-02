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
#include "dnac/chain_config_wire.h"   /* shared CHAIN_CONFIG extension codec */
#include "dnac/ledger_ids.h"          /* DNA_MAX_ACTIVE_VALIDATORS, dna_bft_quorum,
                                       * DNA_DOMAIN_SYSTEM                    */
#include "dnac/dnac.h"                /* DNAC_CFG_* governance param ids      */
#include "dnac/env_wire.h"            /* dna_env_view_t, DNA_ENV_MAX_TOTAL_LEN */
#include "dnac/env_preflight.h"       /* dna_env_preflight_status_t           */
#include "dnac/res_meter.h"           /* dna_ck_add_u64                       */

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_committee.h"
#include "witness/nodus_witness_merkle.h"
#include "witness/nodus_witness_runtime.h"    /* NODUS_RT_AUTHKIND_DSA87_CC_V1,
                                               * DNA_SYSRULE_CHAIN_CONFIG,
                                               * nodus_rt_committee_set_hash,
                                               * nodus_rt_cc_approval_digest   */
#include "witness/nodus_witness_v2_env.h"     /* block_ctx_build, env_preflight_batch */
#include "witness/nodus_witness_v2_produce.h" /* nodus_witness_v2_tip_height          */
#include "witness/nodus_witness_v2_claims.h"  /* nodus_witness_v2_chain_id            */
#include "witness/nodus_witness_v2_apply.h"   /* nodus_v2_epoch_for_height            */

#include "protocol/nodus_tier3.h"     /* cc_appr_{req,rsp} (channel 0x71) */
#include "protocol/nodus_cbor.h"      /* the dnac_cc_collect reply          */
#include "witness/nodus_witness_p2p.h" /* the 0x71 reply path (P2P-PORT F5) */
#include "witness/nodus_witness_host.h" /* identity, find_session_conn */
#include "transport/nodus_tcp.h"      /* nodus_tcp_send (the 4001 reply)  */
#include "nodus/nodus.h"              /* NODUS_CC_COLLECT_ST_* (the wire's
                                       * status values, shared with the
                                       * client SDK's decoder)             */

#include "crypto/sign/qgp_dilithium.h"
#include "crypto/hash/qgp_sha3.h"
#include "crypto/utils/qgp_log.h"

#include <openssl/evp.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LOG_TAG "CHAIN_CONFIG"

/* CHAIN_CONFIG constants -- mirror of dnac/include/dnac/dnac.h. If any
 * constant drifts between the client and witness, chain_config votes get
 * silent consensus divergence -- so all values are pinned by
 * static_assert below. (The legacy tx-apply's wire sizes left with
 * nodus_chain_config_apply — HF-4 review L1 F1.) */

/* DNA's initial seat count / minimum-seats policy. NOT the size of the
 * committee that governs a given height — that comes from chain state via
 * nodus_committee_get_for_block. */
#define CC_COMMITTEE_SIZE           7
/* This release's active-validator ceiling (shared/dnac/ledger_ids.h). */
#define CC_MAX_ACTIVE               DNA_MAX_ACTIVE_VALIDATORS

#define CC_PURPOSE_TAG_LEN          16
#define CC_PARAM_MAX_ID            13
#define CC_PARAM_MAX_TXS            1
#define CC_PARAM_BLOCK_INTERVAL     2
#define CC_PARAM_INFLATION_START    3
#define CC_PARAM_TARGET_ACTIVE      4     /* S3 — DNAC_CFG_TARGET_ACTIVE_COUNT */
#define CC_PARAM_GAS_PRICE          5     /* HF-1 — DNAC_CFG_GAS_PRICE_RAW_PER_UNIT */
#define CC_PARAM_TOKEN_CREATE_FEE   6     /* W-C — DNAC_CFG_TOKEN_CREATE_FEE_RAW */
#define CC_PARAM_HF2_ACTIVE         7     /* HF-2 — DNAC_CFG_HF2_ACTIVE */
#define CC_PARAM_HF3_ACTIVE         8     /* HF-3 — DNAC_CFG_HF3_ACTIVE */
#define CC_PARAM_RULESET_GEN2       9     /* HF-4 — DNAC_CFG_RULESET_GEN2 */
#define CC_PARAM_NAME_PRICE_3P      10    /* HF-4 — DNAC_CFG_NAME_PRICE_3P */
#define CC_PARAM_NAME_PRICE_4P      11    /* HF-4 — DNAC_CFG_NAME_PRICE_4P */
#define CC_PARAM_NAME_PRICE_5P      12    /* HF-4 — DNAC_CFG_NAME_PRICE_5P */
#define CC_PARAM_NAME_PRICE_6P      13    /* HF-4 — DNAC_CFG_NAME_PRICE_6P */
/* Number of per-param cache rows dimensions: param ids are 1..CC_PARAM_MAX_ID
 * and index 0 is unused, so the arrays are CC_PARAM_MAX_ID + 1 wide.
 * HF-4 grew it 9 -> 14 (design 2026-10-02-onchain-names-design.md rev 4
 * §1.1): without the slots nodus_chain_config_get_u64 answers -1 for ids
 * 9-13 and every read of them would FAULT on every node. */
#define CC_PARAM_SLOTS              (CC_PARAM_MAX_ID + 1)
/* CC_MAX_TXS_HARD_CAP RETIRED (R3 W4-C delta 2) with CC_PARAM_MAX_TXS —
 * no live consumer; the id space stays 1..CC_PARAM_MAX_ID unchanged. */
/* CC_MIN/MAX_BLOCK_INTERVAL_SEC removed (0.20.3) with their one consumer,
 * scalar_rules' id-2 range check: id 2 is not read by the running
 * consensus and is refused before any bound is looked at. The parameter's
 * [1, 15] definition stays in dnac.h (DNAC_CFG_MIN/MAX_BLOCK_INTERVAL_SEC)
 * for a consensus that reads it. */
/* CC_MAX_INFLATION_START RETIRED (tokenomics-v3 P2, P2-4) with
 * CC_PARAM_INFLATION_START — no live consumer. */
#define CC_MIN_TARGET_ACTIVE        ((uint64_t)CC_COMMITTEE_SIZE)
#define CC_MAX_TARGET_ACTIVE        ((uint64_t)CC_MAX_ACTIVE)
/* HF-1 GAS_PRICE_RAW_PER_UNIT ceiling (decision 2026-09-25-gas-price.md,
 * "HF-1 O4": 1 000 000 raw/unit). The floor is 0, and 0 is legal: a vote
 * for 0 switches the price rule off again. */
#define CC_MAX_GAS_PRICE            1000000ULL
/* Final pre-testnet wipe W-C TOKEN_CREATE_FEE_RAW range (decision
 * 2026-09-28-token-create-fee-governance.md; range proposed in design
 * 2026-09-28-final-wipe-package-design.md §1 W-C): [1 NODUS, 10M NODUS]. */
#define CC_MIN_TOKEN_CREATE_FEE     100000000ULL
#define CC_MAX_TOKEN_CREATE_FEE     1000000000000000ULL
/* HF-2 HF2_ACTIVE value domain (design 2026-09-30-gov-weight-netzero-
 * design.md rev 2): exactly 1 — a one-way switch, no "off" vote. */
#define CC_HF2_ACTIVE_ON            1ULL
/* HF-3 HF3_ACTIVE value domain (design 2026-10-01-hf3-comet-block-bounds-
 * design.md rev 3 §0): exactly 1 — the HF-2 one-way switch shape. */
#define CC_HF3_ACTIVE_ON            1ULL
/* HF-4 NAME_REGISTER price range (params 10-13; design 2026-10-02-
 * onchain-names-design.md rev 4 §2 Price): [1 NODUS, 10M NODUS]. */
#define CC_MIN_NAME_PRICE           100000000ULL
#define CC_MAX_NAME_PRICE           1000000000000000ULL

static const uint8_t CC_PURPOSE_TAG[CC_PURPOSE_TAG_LEN] = {
    'D','N','A','C','_','C','C','_','v','1',0,0,0,0,0,0
};

/* Pin the nodus-local CC_* mirror macros against the shared wire constants
 * — drift between libnodus and libdna would silently break consensus. */
_Static_assert(CC_MAX_ACTIVE == DNAC_CC_WIRE_MAX_SLOTS,
               "CC_MAX_ACTIVE drift vs shared wire slot cap");
_Static_assert(CC_COMMITTEE_SIZE == DNAC_COMMITTEE_SIZE,
               "CC_COMMITTEE_SIZE drift vs dnac initial seat count");
_Static_assert(CC_PARAM_MAX_ID == DNAC_CFG_PARAM_MAX_ID,
               "CC_PARAM_MAX_ID drift vs dnac param allowlist");
_Static_assert(CC_PARAM_TARGET_ACTIVE == DNAC_CFG_TARGET_ACTIVE_COUNT,
               "CC_PARAM_TARGET_ACTIVE drift vs dnac param id");
_Static_assert(CC_MIN_TARGET_ACTIVE == DNAC_CFG_MIN_TARGET_ACTIVE,
               "TARGET_ACTIVE_COUNT floor drift vs dnac");
_Static_assert(CC_MAX_TARGET_ACTIVE == DNAC_CFG_MAX_TARGET_ACTIVE,
               "TARGET_ACTIVE_COUNT ceiling drift vs dnac");
_Static_assert(CC_PARAM_GAS_PRICE == DNAC_CFG_GAS_PRICE_RAW_PER_UNIT,
               "CC_PARAM_GAS_PRICE drift vs dnac param id");
_Static_assert(CC_MAX_GAS_PRICE == DNAC_CFG_MAX_GAS_PRICE,
               "GAS_PRICE_RAW_PER_UNIT ceiling drift vs dnac");
_Static_assert(CC_PARAM_TOKEN_CREATE_FEE == DNAC_CFG_TOKEN_CREATE_FEE_RAW,
               "CC_PARAM_TOKEN_CREATE_FEE drift vs dnac param id");
_Static_assert(CC_MIN_TOKEN_CREATE_FEE == DNAC_CFG_MIN_TOKEN_CREATE_FEE,
               "TOKEN_CREATE_FEE_RAW floor drift vs dnac");
_Static_assert(CC_MAX_TOKEN_CREATE_FEE == DNAC_CFG_MAX_TOKEN_CREATE_FEE,
               "TOKEN_CREATE_FEE_RAW ceiling drift vs dnac");
_Static_assert(CC_PARAM_HF2_ACTIVE == DNAC_CFG_HF2_ACTIVE,
               "CC_PARAM_HF2_ACTIVE drift vs dnac param id");
_Static_assert(CC_HF2_ACTIVE_ON == DNAC_CFG_HF2_ACTIVE_ON,
               "HF2_ACTIVE value drift vs dnac");
_Static_assert(CC_PARAM_HF3_ACTIVE == DNAC_CFG_HF3_ACTIVE,
               "CC_PARAM_HF3_ACTIVE drift vs dnac param id");
_Static_assert(CC_HF3_ACTIVE_ON == DNAC_CFG_HF3_ACTIVE_ON,
               "HF3_ACTIVE value drift vs dnac");
_Static_assert(CC_PARAM_RULESET_GEN2 == DNAC_CFG_RULESET_GEN2,
               "CC_PARAM_RULESET_GEN2 drift vs dnac param id");
_Static_assert(CC_PARAM_NAME_PRICE_3P == DNAC_CFG_NAME_PRICE_3P &&
               CC_PARAM_NAME_PRICE_4P == DNAC_CFG_NAME_PRICE_4P &&
               CC_PARAM_NAME_PRICE_5P == DNAC_CFG_NAME_PRICE_5P &&
               CC_PARAM_NAME_PRICE_6P == DNAC_CFG_NAME_PRICE_6P,
               "CC_PARAM_NAME_PRICE_* drift vs dnac param ids");
_Static_assert(CC_MIN_NAME_PRICE == DNAC_CFG_MIN_NAME_PRICE &&
               CC_MAX_NAME_PRICE == DNAC_CFG_MAX_NAME_PRICE,
               "NAME_PRICE range drift vs dnac");
/* nodus_chain_config.h keeps this as a bare literal so it stays free of
 * shared/ includes — pin it here, the one TU that sees both. */
_Static_assert(NODUS_CC_RATE_LIMIT_MAX_PROPOSERS == CC_MAX_ACTIVE,
               "rate-limit slot count drift vs active-validator ceiling");

static void be64_into(uint64_t v, uint8_t out[8]) {
    for (int i = 7; i >= 0; i--) { out[i] = (uint8_t)(v & 0xff); v >>= 8; }
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

/* Rows the lookup cache holds per param — DERIVED from the array itself
 * (nodus_witness.h, `chain_config_cache[DNAC_CFG_PARAM_MAX_ID + 1][64]`,
 * whose second dimension is a bare literal with no named constant), so
 * this bound can never disagree with the storage it guards. */
#define CC_CACHE_ROWS                                                     \
    ((int)(sizeof(((nodus_witness_t *)0)->chain_config_cache[0]) /       \
           sizeof(((nodus_witness_t *)0)->chain_config_cache[0][0])))

/* Cache warm-up (CC-OPS-004 / Q16). Pulls every row from
 * chain_config_history grouped by param_id, sorted ascending by
 * effective_block so lookup can walk backwards for latest-effective-wins.
 * Called on first get_u64 after cache_warm == false. */
static int cc_cache_warm_from_db(nodus_witness_t *w) {
    if (!w || !w->db) return -1;

    /* Clear counts */
    for (int i = 0; i < CC_PARAM_SLOTS; i++) w->chain_config_cache_count[i] = 0;

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

    /* rc carries the step result out of the loop — same shape as
     * nodus_chain_config_compute_root below (:293). Without it a mid-scan
     * SQLITE_IOERR / SQLITE_CORRUPT truncated the cache and the function
     * still marked it warm, so nodus_chain_config_get_u64 served a PARTIAL
     * override set as authoritative (:184-195) — fee and block-time
     * parameters silently diverging between nodes, which is a consensus
     * split with no Byzantine actor. */
    int rc;
    int overflow_param = -1;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        int param_id = sqlite3_column_int(stmt, 0);
        if (param_id < 0 || param_id >= CC_PARAM_SLOTS) continue;  /* defense */
        int slot = w->chain_config_cache_count[param_id];
        if (slot >= CC_CACHE_ROWS) {
            /* nodus/BUGS.md "chain_config cache keeps only the OLDEST 64
             * rows": this used to `continue`, and because the scan is
             * ORDER BY effective_block ASC the rows it dropped were the
             * NEWEST — the warm cache then answered the last cached row's
             * value forever while the DB fallback answered the real
             * latest row (cache != DB, chain-split class). A param that
             * outgrows the cache is not cached at all: stop here and stay
             * cold (below). */
            overflow_param = param_id;
            break;
        }
        w->chain_config_cache[param_id][slot].new_value =
            (uint64_t)sqlite3_column_int64(stmt, 1);
        w->chain_config_cache[param_id][slot].effective_block =
            (uint64_t)sqlite3_column_int64(stmt, 2);
        w->chain_config_cache_count[param_id] = slot + 1;
    }
    sqlite3_finalize(stmt);

    if (overflow_param >= 0) {
        /* Discard the fill exactly as the mid-scan fault path below does
         * and stay COLD: every lookup then takes the DB-direct fallback in
         * nodus_chain_config_get_u64, which answers the same question with
         * the same three outcomes over ALL rows. The cost is speed (one
         * scan attempt + one indexed SELECT per lookup), never an answer.
         * Logged once per process — the attempt repeats on every lookup
         * while cold, and the condition cannot clear (history rows are
         * never deleted). */
        static int cc_overflow_logged = 0;
        for (int i = 0; i < CC_PARAM_SLOTS; i++)
            w->chain_config_cache_count[i] = 0;
        w->chain_config_cache_warm = false;
        if (!cc_overflow_logged) {
            cc_overflow_logged = 1;
            QGP_LOG_WARN(LOG_TAG, "cache warm: param %d has more than %d "
                         "chain_config_history rows — lookup cache "
                         "DISABLED, every lookup reads the database",
                         overflow_param, CC_CACHE_ROWS);
        }
        return -1;
    }

    if (rc != SQLITE_DONE) {
        /* Discard the partial fill and stay COLD, so every lookup goes
         * through the DB-direct fallback below instead of being answered
         * from a truncated override set.
         *
         * ⚠ HISTORY, so the next reader does not re-derive it. An earlier
         * version of this comment claimed staying cold "costs speed, not
         * correctness". That was FALSE, and a later revision recorded the
         * reason as a KNOWN REMAINING HOLE: the fallback was itself
         * FAIL-OPEN — a prepare failure returned default_value and a
         * failed step left `out == default_value`, because the function
         * returned uint64_t and had no error channel. A caller could not
         * tell "no override exists" from "the table is unreadable", so
         * under an IOERR/CORRUPT fault one node used the DEFAULT fee /
         * block-interval / inflation-start while healthy peers used the
         * override.
         *
         * CLOSED (O15J Block 2, A2): nodus_chain_config_get_u64 is now
         * three-valued (0 present / 1 genuinely absent / -1 cannot
         * determine) and every production caller fails closed on -1.
         * Staying cold here is now what it always claimed to be: a cost
         * in speed, because the fallback answers the same question with
         * the same three outcomes. */
        for (int i = 0; i < CC_PARAM_SLOTS; i++)
            w->chain_config_cache_count[i] = 0;
        w->chain_config_cache_warm = false;
        QGP_LOG_ERROR(LOG_TAG, "cache warm: step failed rc=%d — discarding "
                      "partial chain_config cache, staying cold", rc);
        return -1;
    }

    w->chain_config_cache_warm = true;
    return 0;
}

/* Does a schema object named `chain_config_history` exist at all?
 *
 *   1  it exists, 0  it genuinely does not, -1  sqlite_master itself is
 *   unreadable (a real DB fault).
 *
 * Why this probe exists: on a live node the table is created on EVERY
 * database open (nodus_witness_db.c:1926, reached from nodus_witness.c:356
 * and the joining-node path nodus_witness_bootstrap.c:992), so "the table
 * is missing" is only reachable on a hand-rolled unit fixture that never
 * ran the migration. A fixture holds no governance rows, which is exactly
 * "no override is active" — answering 1 (absent) there keeps every such
 * fixture working, while an unreadable table on a real node still faults.
 * Same shape and same rationale as the sqlite_master probe in
 * nodus_committee_get_for_block (nodus_witness_committee.c).
 *
 * DELIBERATE DEVIATION from that precedent: it filters `type='table'`;
 * this one matches on NAME ALONE. The only structural way to inject a
 * mid-scan step fault into this table (the poisoned-VIEW trick used by
 * test_merkle_scan_fail_close.c) replaces it with a VIEW of the same
 * name — a type='table' filter would classify that fixture as ABSENT and
 * make the fault untestable. Matching by name is also the more
 * conservative reading: any object of that name means reads of it are
 * meaningful, so a failure to read one is a fault. */
static int cc_history_exists(nodus_witness_t *w) {
    sqlite3_stmt *pr = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT 1 FROM sqlite_master WHERE name='chain_config_history'",
            -1, &pr, NULL) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "sqlite_master probe prepare failed: %s",
                      sqlite3_errmsg(w->db));
        return -1;
    }
    int rc = sqlite3_step(pr);
    sqlite3_finalize(pr);
    if (rc == SQLITE_ROW)  return 1;
    if (rc == SQLITE_DONE) return 0;
    QGP_LOG_ERROR(LOG_TAG, "sqlite_master probe step failed rc=%d: %s",
                  rc, sqlite3_errmsg(w->db));
    return -1;
}

int nodus_chain_config_get_u64(nodus_witness_t *w,
                                uint8_t param_id,
                                uint64_t current_block,
                                uint64_t default_value,
                                uint64_t *value_out) {
    if (!w || !value_out) return -1;
    /* No open DB is not "no override" — it is "this node cannot answer".
     * Every consensus path holds an open handle long before it gets here. */
    if (!w->db) return -1;
    /* An out-of-range param id is a CALLER bug, not chain state. Returning
     * the default would let a typo'd id silently read as "unconfigured". */
    if (param_id >= CC_PARAM_SLOTS) return -1;

    /* Cache warm-up if needed (CC-OPS-004 / Q16). A failure here is not
     * yet an answer: the DB-direct fallback below re-asks the same
     * question and produces the same three outcomes. */
    if (!w->chain_config_cache_warm) {
        (void)cc_cache_warm_from_db(w);
    }

    /* Fast path: walk cache backwards (rows sorted by effective_block
     * ascending), first row with effective_block <= current_block wins.
     * The cache is only ever marked warm after a COMPLETE scan that
     * cached EVERY row of every param: cc_cache_warm_from_db discards
     * the fill and stays cold both on a mid-scan fault and when any
     * param has more rows than the cache holds (CC_CACHE_ROWS). So when
     * warm, the cache holds exactly the rows the fallback's SELECT
     * reads, and a hit here and the fallback below answer identically. */
    if (w->chain_config_cache_warm) {
        w->chain_config_cache_hits++;
        int n = w->chain_config_cache_count[param_id];
        for (int i = n - 1; i >= 0; i--) {
            if (w->chain_config_cache[param_id][i].effective_block
                <= current_block) {
                *value_out = w->chain_config_cache[param_id][i].new_value;
                return 0;
            }
        }
        *value_out = default_value;
        return 1;                       /* genuinely no active override */
    }
    w->chain_config_cache_misses++;

    /* Cache warm-up failed (or the table does not exist) — fall back to a
     * direct DB lookup rather than trusting a cache we could not fill.
     * Every exit below is one of the three contract values; none of them
     * substitutes a value for a failure. */
    int have = cc_history_exists(w);
    if (have < 0) return -1;            /* cannot even ask               */
    if (have == 0) {                    /* pre-migration fixture: no rows */
        *value_out = default_value;
        return 1;
    }

    const char *sql =
        "SELECT new_value FROM chain_config_history "
        "WHERE param_id = ? AND effective_block <= ? "
        "ORDER BY effective_block DESC LIMIT 1";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(w->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "get_u64 prepare failed (param %u): %s",
                      (unsigned)param_id, sqlite3_errmsg(w->db));
        return -1;
    }
    sqlite3_bind_int(stmt, 1, (int)param_id);
    sqlite3_bind_int64(stmt, 2, (sqlite3_int64)current_block);

    int rc = sqlite3_step(stmt);
    int ret;
    if (rc == SQLITE_ROW) {
        *value_out = (uint64_t)sqlite3_column_int64(stmt, 0);
        ret = 0;
    } else if (rc == SQLITE_DONE) {
        *value_out = default_value;
        ret = 1;
    } else {
        QGP_LOG_ERROR(LOG_TAG, "get_u64 step failed rc=%d (param %u): %s — "
                      "the active override cannot be determined", rc,
                      (unsigned)param_id, sqlite3_errmsg(w->db));
        ret = -1;
    }
    sqlite3_finalize(stmt);
    return ret;
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
        /* 2026-07-31: empty_root is three-valued now — the sentinel it
         * writes on digest failure is 64 zeros, which would otherwise
         * travel into state_root as a real chain_config_root. */
        result = nodus_merkle_empty_root(NODUS_TREE_TAG_CHAIN_CONFIG,
                                         out_root);
    } else {
        result = merkle_root_from_leaves(leaves, n, out_root);
    }
    free(leaves);
    return result;
}

/* The SCALAR half of the CHAIN_CONFIG local rules — param allowlist +
 * per-param value bounds + the signing/validity window shape. Exported
 * (nodus_chain_config.h) so the Ledger V2 native SYSTEM runtime
 * (nodus_witness_rt_native.c) consumes the SAME authority instead of a
 * drift-prone mirror. */
int nodus_chain_config_scalar_rules(uint8_t param_id, uint64_t new_value,
                                    uint64_t signed_at_block,
                                    uint64_t valid_before_block,
                                    uint64_t effective_block_height,
                                    uint64_t proposal_nonce) {
    if (param_id < 1 || param_id > CC_PARAM_MAX_ID) return -1;
    /* 0.20.3 (decision file 2026-09-23-height-activated-upgrades-before-
     * testnet.md item 1): a proposal for a parameter the RUNNING consensus
     * does not read is refused. The list is dnac.h's
     * dnac_cfg_param_read_by_consensus — the same predicate the client
     * mirror (verify.c) consumes, so the two sides cannot drift. The
     * switch below holds the bounds of the ids ON the list. Why the
     * others are off it (their former cases were unreachable after this
     * gate and were removed — no dead code):
     *   id 1 MAX_TXS_PER_BLOCK — RETIRED (R3 W4-C delta 2, operator
     *        "kaldır" 2026-09-18; atlas-dec-5b7568512b95e6d2e671c4eaad2c1879
     *        rev 1): a block's capacity is bytes and units only.
     *   id 2 BLOCK_INTERVAL_SEC — NOT READ (0.20.3; decision
     *        2026-09-23-height-activated-upgrades-before-testnet.md item 1):
     *        the Comet lane's block pace is a compile-time node setting
     *        (nodus_witness_cmt_node.c: param 2 "has NO effect on this lane
     *        and is not read"). NOT retired — a consensus that reads it
     *        puts it back on the list. Committed id-2 rows stay readable
     *        (nodus_chain_config_get_u64 and the merkle root never call
     *        this function).
     *   id 3 INFLATION_START_BLOCK — RETIRED (tokenomics-v3 P2, P2-4:
     *        "INFLATION_START parametresi (id 3) emekli"; no per-block
     *        mint remains). */
    if (!dnac_cfg_param_read_by_consensus(param_id)) return -1;

    switch (param_id) {
        case CC_PARAM_TARGET_ACTIVE:
            if (new_value < CC_MIN_TARGET_ACTIVE ||
                new_value > CC_MAX_TARGET_ACTIVE) return -1;
            break;
        case CC_PARAM_GAS_PRICE:
            /* HF-1: [0, CC_MAX_GAS_PRICE]. The lower bound is 0 and needs
             * no test on an unsigned value — 0 is LEGAL (it switches the
             * price rule off again, decision 2026-09-25-gas-price.md). */
            if (new_value > CC_MAX_GAS_PRICE) return -1;
            break;
        case CC_PARAM_TOKEN_CREATE_FEE:
            /* W-C: [CC_MIN_TOKEN_CREATE_FEE, CC_MAX_TOKEN_CREATE_FEE].
             * Unlike the gas price there is no "off" value: token
             * creation always costs at least one NODUS. */
            if (new_value < CC_MIN_TOKEN_CREATE_FEE ||
                new_value > CC_MAX_TOKEN_CREATE_FEE) return -1;
            break;
        case CC_PARAM_HF2_ACTIVE:
            /* HF-2: EXACTLY 1. A one-way switch — 0 would be an "off"
             * vote, which the design does not have (rev 2: H is voted
             * once, the old rules hold below H, the new ones from H). */
            if (new_value != CC_HF2_ACTIVE_ON) return -1;
            break;
        case CC_PARAM_HF3_ACTIVE:
            /* HF-3: EXACTLY 1, the HF-2 shape above — a one-way switch,
             * no "off" vote (design 2026-10-01-hf3-comet-block-bounds-
             * design.md §0). */
            if (new_value != CC_HF3_ACTIVE_ON) return -1;
            break;
        case CC_PARAM_RULESET_GEN2:
            /* HF-4 (design 2026-10-02-onchain-names-design.md rev 4
             * §1.2): EXACTLY the compiled vote literal D2 — the vote names
             * its target generation (tuples + switch procedure). A binary
             * whose generation 2 differs refuses here, at the vote block.
             * Pure: the literal, never a hash. The single-use / HF-2 /
             * epoch-boundary rules need chain state and live in
             * nodus_chain_config_stateful_rules. */
            if (new_value != (uint64_t)DNAC_CFG_RULESET_GEN2_D2) return -1;
            break;
        case CC_PARAM_NAME_PRICE_3P:
        case CC_PARAM_NAME_PRICE_4P:
        case CC_PARAM_NAME_PRICE_5P:
        case CC_PARAM_NAME_PRICE_6P:
            /* HF-4 (design §2 Price): [10^8, 10^15] raw. Votable only
             * while generation 2 judges the vote — a stateful rule
             * (nodus_chain_config_stateful_rules), not this one. */
            if (new_value < CC_MIN_NAME_PRICE ||
                new_value > CC_MAX_NAME_PRICE) return -1;
            break;
        default:
            return -1;
    }

    if (signed_at_block == 0) return -1;
    if (valid_before_block <= effective_block_height) return -1;
    if (valid_before_block <= signed_at_block) return -1;
    /* The int64 bound (decision 2026-09-30-chain-config-int64-bounds.md,
     * red-team CC-1/CC-2): chain_config_history stores these columns as
     * SQLite int64. The V2 writer (nodus_witness_rt_native.c, the
     * chain_config_history INSERT) casts each u64 to sqlite3_int64, so a
     * value >= 2^63 is stored NEGATIVE; the reader (rtn_sys_cc_fetch's
     * `pn >= 0` / the effective_block key) then treats the row as
     * corrupt and fails closed as a NODE fault — every validator at
     * once, on a value any committee seat could have proposed. A value
     * above INT64_MAX is therefore refused HERE, as a deterministic
     * verdict every node reaches from the same bytes. With the window
     * rule above, valid_before <= INT64_MAX also bounds signed_at and
     * effective to < INT64_MAX; each is still tested on its own so the
     * rule does not depend on the order of these lines. */
    if (proposal_nonce         > (uint64_t)INT64_MAX) return -1;
    if (signed_at_block        > (uint64_t)INT64_MAX) return -1;
    if (valid_before_block     > (uint64_t)INT64_MAX) return -1;
    if (effective_block_height > (uint64_t)INT64_MAX) return -1;
    return 0;
}

/* Per-param grace minimum, exported for the same single-authority
 * reason. */
uint64_t nodus_chain_config_grace_for_param(uint8_t param_id) {
    switch (param_id) {
        case CC_PARAM_TARGET_ACTIVE:
            return (uint64_t)DNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS;
        case CC_PARAM_BLOCK_INTERVAL:
            /* NOT READ by the running consensus (0.20.3) — `scalar_rules`
             * refuses id 2 before any caller reaches a grace check; the
             * id-1/id-3 treatment below makes the gap test unsatisfiable
             * by construction for a caller that reaches this function
             * directly. A consensus that reads the block interval
             * restores its SAFETY class here together with its entry in
             * dnac_cfg_param_read_by_consensus. */
            return (uint64_t)-1;
        case CC_PARAM_INFLATION_START:
            /* RETIRED (tokenomics-v3 P2, P2-4) — the id-1 treatment
             * below, verbatim in intent: `scalar_rules` refuses id 3
             * before any caller reaches a grace check; UINT64_MAX makes
             * the gap test unsatisfiable by construction for a caller
             * that reaches this function directly. */
            return (uint64_t)-1;
        case CC_PARAM_MAX_TXS:
            /* RETIRED (R3 W4-C delta 2) — `scalar_rules` above already
             * refuses id 1 with -1 before any caller reaches a grace
             * check, so this is defense in depth: UINT64_MAX makes the
             * "effective gap >= this many blocks" test unsatisfiable by
             * construction, never merely a long wait, for a caller that
             * somehow reaches this function directly with the retired
             * id. */
            return (uint64_t)-1;
        case CC_PARAM_HF3_ACTIVE:
            /* HF-3 — ERGONOMIC, HF-2's class (design 2026-10-01-hf3-
             * comet-block-bounds-design.md §0: "an explicit case, not the
             * default: branch"). Its OWN return, not a fall-through into
             * default:, so a later change to the default class cannot
             * move this switch's grace. */
            return (uint64_t)DNAC_CHAIN_CONFIG_GRACE_ERGONOMIC_BLOCKS;
        case CC_PARAM_RULESET_GEN2:
            /* HF-4 — ERGONOMIC (decision 2026-10-02-onchain-names.md item
             * 17: "Param 9 bekleme süresi ERGONOMIC 720 blok"). Its own
             * return, the HF-3 shape: never the default: branch. */
            return (uint64_t)DNAC_CHAIN_CONFIG_GRACE_ERGONOMIC_BLOCKS;
        case CC_PARAM_NAME_PRICE_3P:
        case CC_PARAM_NAME_PRICE_4P:
        case CC_PARAM_NAME_PRICE_5P:
        case CC_PARAM_NAME_PRICE_6P:
            /* HF-4 — ERGONOMIC (decision item 17: "10–13 de ERGONOMIC"). */
            return (uint64_t)DNAC_CHAIN_CONFIG_GRACE_ERGONOMIC_BLOCKS;
        case CC_PARAM_GAS_PRICE:
            /* HF-1 — ERGONOMIC by decision (2026-09-25-gas-price.md,
             * detail decision 3: "bekleme süresi 720 blok"). Named
             * explicitly rather than left to `default:`. */
        case CC_PARAM_TOKEN_CREATE_FEE:
            /* W-C — ERGONOMIC by decision (2026-09-28-token-create-fee-
             * governance.md, operator "Tamam yap": "bekleme ERGONOMIC
             * 720 blok"). Named explicitly as well. */
        case CC_PARAM_HF2_ACTIVE:
            /* HF-2 — ERGONOMIC, the HF-1 class (dispatch of the HF-2
             * package; the activation procedure is DEPLOY_RUNBOOK §2.2:
             * the whole fleet is on the new binary BEFORE the vote, so
             * the grace only has to cover the vote-to-H window). */
        default:
            return (uint64_t)DNAC_CHAIN_CONFIG_GRACE_ERGONOMIC_BLOCKS;
    }
}

/* HF-4 — the STATEFUL half of the CHAIN_CONFIG rules (contract:
 * nodus_chain_config.h). Pure over the facts its callers derive; the
 * SYSTEM CHAIN_CONFIG exec (nodus_witness_rt_native.c) passes the
 * engine-filled ctx facts and its own runtime's generation, the 0x71
 * approval responder (cc_appr_rules_chain_config below) derives the same
 * three facts at its candidate height — so the two sites cannot fork. */
int nodus_chain_config_stateful_rules(uint8_t param_id,
                                      uint64_t effective_block_height,
                                      uint8_t hf2_active,
                                      uint8_t ruleset_gen2_voted,
                                      uint32_t judging_generation) {
    switch (param_id) {
        case CC_PARAM_RULESET_GEN2: {
            /* (a) single use: any committed param-9 row — at any
             * effective height, the far-future one included (design §1.2:
             * "a far-future effective retires param 9 for good") —
             * refuses every further vote. */
            if (ruleset_gen2_voted) return -1;
            /* (b) HF-2 must be active at the vote height: the switch
             * leaves CORE's root unchanged at H-1, which phase 9 accepts
             * only while HF-2 is on (HF-2 has no off vote, so on at the
             * vote height means on at H-1). */
            if (!hf2_active) return -1;
            /* (c) H-1 must not be an epoch boundary (the
             * nodus_witness_v2_epoch_boundary_apply gate: height != 0 and
             * height % DNAC_EPOCH_LENGTH == 0). */
            if (effective_block_height == 0) return -1;
            {
                uint64_t h1 = effective_block_height - 1u;
                if (h1 != 0 && (h1 % (uint64_t)DNAC_EPOCH_LENGTH) == 0)
                    return -1;
            }
            return 0;
        }
        case CC_PARAM_NAME_PRICE_3P:
        case CC_PARAM_NAME_PRICE_4P:
        case CC_PARAM_NAME_PRICE_5P:
        case CC_PARAM_NAME_PRICE_6P:
            /* votable only once generation 2 judges the vote (design
             * §1.2 / §2: "refused unless the judging runtime is
             * gen >= 2"); a synthetic or unresolved runtime reads 0 here */
            if (judging_generation < NODUS_RT_GEN_2) return -1;
            return 0;
        case CC_PARAM_MAX_TXS:
        case CC_PARAM_BLOCK_INTERVAL:
        case CC_PARAM_INFLATION_START:
        case CC_PARAM_TARGET_ACTIVE:
        case CC_PARAM_GAS_PRICE:
        case CC_PARAM_TOKEN_CREATE_FEE:
        case CC_PARAM_HF2_ACTIVE:
        case CC_PARAM_HF3_ACTIVE:
            /* no stateful rule — the scalar rules decide these alone */
            return 0;
        default:
            return -1;                   /* unknown id: fail closed      */
    }
}

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

/* ============================================================================
 * Stage C.3 — per-proposer rate-limit (CC-OPS-003 / Q15)
 *
 * Linear-scan over an active-set-sized slot array. Lookup is
 * O(NODUS_CC_RATE_LIMIT_MAX_PROPOSERS) worst case — 128 memcmp of 32 bytes
 * since S3 (was 7) — still fine for the handler hot path and avoids a
 * hash-table dependency. The scan is over a fixed-size array in index
 * order, so it is order-deterministic regardless of insertion history.
 * ========================================================================== */

int nodus_cc_rate_limit_check(nodus_cc_rate_limit_table_t *t,
                               const uint8_t sender_id[NODUS_CC_WITNESS_ID_SIZE],
                               uint64_t now_ms,
                               uint64_t *elapsed_ms_out) {
    if (!t || !sender_id) return -1;

    for (uint32_t i = 0; i < NODUS_CC_RATE_LIMIT_MAX_PROPOSERS; i++) {
        const nodus_cc_rate_limit_slot_t *s = &t->slots[i];
        if (!s->in_use) continue;
        if (memcmp(s->witness_id, sender_id,
                    NODUS_CC_WITNESS_ID_SIZE) != 0) continue;

        /* Clock-skew defense: if now_ms < last_accepted_ms, treat as zero
         * elapsed (aggressive) rather than wrap to huge elapsed (permissive).
         * nodus_time_now_ms() is the WALL clock (CLOCK_REALTIME), not a
         * monotonic one: it can step back (NTP, an operator), and this
         * branch is what keeps such a step from opening the cooldown. */
        uint64_t elapsed = (now_ms >= s->last_accepted_ms)
                            ? (now_ms - s->last_accepted_ms) : 0;

        if (elapsed < NODUS_CC_RATE_LIMIT_WINDOW_MS) {
            if (elapsed_ms_out) *elapsed_ms_out = elapsed;
            return -1;
        }
        /* Cooldown elapsed — allow. */
        return 0;
    }
    /* Sender not yet tracked — allow. */
    return 0;
}

void nodus_cc_rate_limit_record(nodus_cc_rate_limit_table_t *t,
                                 const uint8_t sender_id[NODUS_CC_WITNESS_ID_SIZE],
                                 uint64_t now_ms) {
    if (!t || !sender_id) return;

    int free_slot = -1;
    int oldest_slot = 0;
    uint64_t oldest_ms = UINT64_MAX;

    for (uint32_t i = 0; i < NODUS_CC_RATE_LIMIT_MAX_PROPOSERS; i++) {
        nodus_cc_rate_limit_slot_t *s = &t->slots[i];
        if (s->in_use && memcmp(s->witness_id, sender_id,
                                  NODUS_CC_WITNESS_ID_SIZE) == 0) {
            s->last_accepted_ms = now_ms;
            return;
        }
        if (!s->in_use && free_slot < 0) free_slot = (int)i;
        if (s->in_use && s->last_accepted_ms < oldest_ms) {
            oldest_ms = s->last_accepted_ms;
            oldest_slot = (int)i;
        }
    }

    /* Claim free slot first; else evict oldest (LRU). Eviction only
     * happens if a non-committee sender ever slips past the dispatch
     * guard — in the normal 7-committee case we have exactly enough
     * slots and no eviction ever occurs. */
    int target = (free_slot >= 0) ? free_slot : oldest_slot;
    nodus_cc_rate_limit_slot_t *s = &t->slots[target];
    memcpy(s->witness_id, sender_id, NODUS_CC_WITNESS_ID_SIZE);
    s->last_accepted_ms = now_ms;
    s->in_use = true;
}

/* ============================================================================
 * D-16 rev 7 (W4-CC) — SYSTEM-governance approval-collection RPC
 * server-side handler (verbs 40-41), replacing the retired Stage C.2
 * vote-collect pair (14-15).
 * ============================================================================ */

/* Mirror of nodus_witness_rt_native.c's RTN_CC_CALL_LEN (internal
 * linkage there, in a file this package does not touch, so it cannot be
 * pinned by a _Static_assert from here): the v2 CHAIN_CONFIG call is
 * EXACTLY param_id(1) || new_value_BE(8) || effective_BE(8) ||
 * nonce_BE(8) || signed_at_BE(8) || valid_before_BE(8) = 41 bytes
 * (nodus_witness_rt_native.c:2692-2709 rtn_cc_parse — the SAME layout
 * nodus-cli.c's shared cc_appr_build_pass1 builds, :901-906). A width
 * change to either site must update this mirror by hand. */
#define CC_APPR_CHAIN_CONFIG_CALL_LEN  41u

typedef struct {
    uint8_t  param_id;
    uint64_t new_value, effective, nonce, signed_at, valid_before;
} cc_appr_cc_call_t;

static uint64_t cc_appr_get64(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | p[i];
    return v;
}

static void cc_appr_parse_cc_call(const uint8_t *p, cc_appr_cc_call_t *c) {
    c->param_id     = p[0];
    c->new_value    = cc_appr_get64(p + 1);
    c->effective    = cc_appr_get64(p + 9);
    c->nonce        = cc_appr_get64(p + 17);
    c->signed_at    = cc_appr_get64(p + 25);
    c->valid_before = cc_appr_get64(p + 33);
}

/* Per-op approval rule: applies EXACTLY the checks
 * nodus_rt_system_exec's CHAIN_CONFIG branch applies at exec time
 * (nodus_witness_rt_native.c:3755-3819), at the CANDIDATE height `h`
 * (tip+1, the same candidate the responder's preflight used) instead of
 * the eventual commit height — a proposal approved now may commit at a
 * different height, and every one of these gates is re-checked there by
 * the same exec function; this is a pre-signature sanity gate, not a
 * second authority. Quorum/signer checks are NOT here: those are the
 * chain's own auth-hook verdict once the envelope is assembled, and
 * this handler contributes exactly one seat's worth of evidence toward
 * them. @return 0 accept; -1/-2 reject — `reason` is always filled. */
static int cc_appr_rules_chain_config(nodus_witness_t *w,
                                     const uint8_t *call, uint32_t call_len,
                                     uint64_t h, char *reason,
                                     size_t reason_size) {
    if (call_len != CC_APPR_CHAIN_CONFIG_CALL_LEN) {
        snprintf(reason, reason_size, "CHAIN_CONFIG call length mismatch");
        return -1;
    }
    cc_appr_cc_call_t c;
    cc_appr_parse_cc_call(call, &c);

    /* the SAME scalar authority the legacy apply and the V2 exec hook
     * both consume — id 1 (MAX_TXS_PER_BLOCK), since tokenomics-v3 P2
     * id 3 (INFLATION_START_BLOCK) and, since 0.20.3, id 2
     * (BLOCK_INTERVAL_SEC — not read by the running consensus) are
     * refused here exactly as they are everywhere else: a seat never
     * signs an approval for them. */
    if (nodus_chain_config_scalar_rules(c.param_id, c.new_value,
                                        c.signed_at, c.valid_before,
                                        c.effective, c.nonce) != 0) {
        snprintf(reason, reason_size, "scalar rules rejected");
        return -1;
    }
    /* O15F D2 — the V2-lane TARGET_ACTIVE_COUNT ceiling
     * NODUS_V2_ACTIVE_SET_MAX, the same narrowing nodus_rt_system_exec
     * applies beyond scalar_rules' wider [7..128]. tokenomics-v3 P3-7:
     * the ceiling is 32 (was 30), so the governed range on this lane is
     * [7, 32] (decision file §3 2026-09-24 "P3 soruları" (4)). */
    if (c.param_id == DNAC_CFG_TARGET_ACTIVE_COUNT &&
        c.new_value > NODUS_V2_ACTIVE_SET_MAX) {
        snprintf(reason, reason_size,
                 "TARGET_ACTIVE_COUNT exceeds the V2 active-set ceiling");
        return -1;
    }
    /* freshness (CC-G) */
    if (h > c.valid_before) {
        snprintf(reason, reason_size, "valid_before has already passed");
        return -1;
    }
    /* per-param grace (CC-C) */
    {
        uint64_t floor_h;
        if (dna_ck_add_u64(h, nodus_chain_config_grace_for_param(c.param_id),
                           &floor_h) != 0) {
            snprintf(reason, reason_size, "grace floor overflowed");
            return -1;
        }
        if (c.effective < floor_h) {
            snprintf(reason, reason_size, "effective is below the grace floor");
            return -1;
        }
    }
    /* HF-4 (design 2026-10-02-onchain-names-design.md rev 4 §1.2): the
     * STATEFUL rules, through the ONE authority the exec applies, over
     * the same three facts the engine hands the exec — derived here at
     * the candidate height h with the engine's read discipline (an
     * unanswerable read refuses, never defaults):
     *   - HF-2 at h: chain_config param 7 (exec: ctx.hf2_active);
     *   - "any param-9 row": param 9 at INT64_MAX — every committed
     *     effective is <= INT64_MAX by the scalar rules' int64 bound, and
     *     the DB path binds an int64 (exec: ctx.ruleset_gen2_voted);
     *   - the judging generation: the runtime the committed SYSTEM
     *     manifest resolves — the registry after the tip names the
     *     generation that judges tip + 1 = h (exec: rt->generation). */
    {
        uint64_t v7 = 0, v9 = 0;
        int r7 = nodus_chain_config_get_u64(w, (uint8_t)CC_PARAM_HF2_ACTIVE,
                                            h, 0ULL, &v7);
        int r9 = nodus_chain_config_get_u64(w, (uint8_t)CC_PARAM_RULESET_GEN2,
                                            (uint64_t)INT64_MAX, 0ULL, &v9);
        const nodus_domain_runtime_t *sys_rt = NULL;
        if (r7 < 0 || r9 < 0 ||
            (v7 != 0ULL && v7 != CC_HF2_ACTIVE_ON)) {
            snprintf(reason, reason_size,
                     "chain_config state unreadable on this node");
            return -2;
        }
        if (nodus_witness_v2_runtime_for(w, DNA_DOMAIN_SYSTEM, 1,
                                         &sys_rt) != 0 || !sys_rt) {
            snprintf(reason, reason_size,
                     "the SYSTEM runtime does not resolve on this node");
            return -2;
        }
        if (nodus_chain_config_stateful_rules(
                c.param_id, c.effective,
                (uint8_t)(v7 == CC_HF2_ACTIVE_ON ? 1u : 0u),
                (uint8_t)(r9 == 0 ? 1u : 0u),
                sys_rt->generation) != 0) {
            snprintf(reason, reason_size, "stateful rules rejected");
            return -1;
        }
    }
    /* tokenomics-v3 P2 (P2-4): the INFLATION_START_BLOCK monotonicity
     * check that stood here left with parameter id 3 — the scalar rules
     * above refuse id 3, so no id-3 proposal reaches this line, and the
     * exec hook it mirrored (the SYSTEM adapter's retired op 3) is gone
     * with it. */
    return 0;
}

typedef int (*cc_appr_rule_fn)(nodus_witness_t *w, const uint8_t *call,
                               uint32_t call_len, uint64_t h,
                               char *reason, size_t reason_size);

typedef struct {
    uint32_t         domain_id;
    uint32_t         runtime_op;
    uint32_t         call_len;
    cc_appr_rule_fn  rule;
} cc_appr_table_row_t;

/* The APPROVAL TABLE (D-16 rev 7 (4)): the SYSTEM governance ops whose
 * authority rule is committee approval. Today exactly CHAIN_CONFIG; a
 * future domain-registration op is a NEW ROW here, never a new verb
 * pair (that is the whole reason this is a table and not a hardcoded
 * single check). */
static const cc_appr_table_row_t CC_APPR_TABLE[] = {
    { DNA_DOMAIN_SYSTEM, DNA_SYSRULE_CHAIN_CONFIG,
      CC_APPR_CHAIN_CONFIG_CALL_LEN, cc_appr_rules_chain_config },
};
#define CC_APPR_TABLE_LEN \
    (sizeof(CC_APPR_TABLE) / sizeof(CC_APPR_TABLE[0]))

/* Send the reply on channel 0x71 to the peer that asked (P2P-PORT F5: the
 * secret connection authenticates it — the tier-3 envelope and its 0x03
 * signature this used to build are deleted). */
static int cc_appr_send(nodus_witness_t *w, const char *peer_id,
                        const nodus_t3_cc_appr_rsp_t *rsp) {
    uint8_t *buf = malloc(NODUS_T3_CC_APPR_RSP_MAX + 256u);
    if (!buf) return -1;
    size_t len = 0;
    int rc = nodus_t3_cc_appr_rsp_encode(rsp, buf, NODUS_T3_CC_APPR_RSP_MAX + 256u,
                                         &len);
    if (rc == 0 && !nodus_witness_p2p_send(w->p2p, peer_id, NODUS_P2P_CH_CC_APPR,
                                           buf, len))
        rc = -1;
    free(buf);
    return rc;
}

/* Fill a refusal (never a signature — the caller's `rsp` is zeroed) and
 * report it as one. */
static int cc_appr_refuse(nodus_t3_cc_appr_rsp_t *rsp, const char *reason) {
    rsp->ok = false;
    snprintf(rsp->reason, sizeof(rsp->reason), "%s", reason ? reason : "fault");
    return 0;
}

/* The governing committee at the local tip and every member's SHA3-512
 * fingerprint, resolved ONE way for both users — the 0x71 responder below
 * and the node-side approval collection (decision 2026-09-26-cc-approval-
 * via-own-node.md (3): "the node resolves the committee at its tip").
 * The ENGINE's own expression is nodus_committee_get_for_block at H-1
 * with H the EXECUTION height; the candidate is H = tip+1, so H-1 = tip
 * (matches the offline CLI builder's own committee query). The caller
 * frees `*cm_out` and `*fps_out`. @return 0; -1 a fault (nothing to
 * free). */
static int cc_appr_resolve(nodus_witness_t *w, uint64_t *tip_out,
                           nodus_committee_member_t **cm_out, int *n_out,
                           uint8_t (**fps_out)[64]) {
    uint64_t tip = 0;
    nodus_committee_member_t *committee = NULL;
    int cm_count = 0;

    *cm_out = NULL;
    *fps_out = NULL;
    *n_out = 0;
    if (nodus_witness_v2_tip_height(w, &tip) != 0) return -1;
    if (nodus_committee_get_for_block_alloc(w, tip, &committee, &cm_count) != 0 ||
        cm_count < 1) {
        free(committee);
        return -1;
    }
    uint8_t (*fps)[64] = malloc((size_t)cm_count * 64);
    if (!fps) {
        free(committee);
        return -1;
    }
    for (int i = 0; i < cm_count; i++) {
        if (qgp_sha3_512(committee[i].pubkey, NODUS_CC_PUBKEY_SIZE, fps[i]) != 0) {
            free(fps);
            free(committee);
            return -1;
        }
    }
    *tip_out = tip;
    *cm_out = committee;
    *n_out = cm_count;
    *fps_out = fps;
    return 0;
}

/* The verdict itself (nodus_witness_cc_appr_answer below adds the request
 * identity to every answer it will send). */
static int cc_appr_verdict(nodus_witness_t *w,
                           const uint8_t peer_wid[NODUS_CC_WITNESS_ID_SIZE],
                           bool requester_bonded,
                           const nodus_t3_cc_appr_req_t *req,
                           nodus_t3_cc_appr_rsp_t *rsp_out) {
    nodus_t3_cc_appr_rsp_t *rsp = rsp_out;
    memset(rsp, 0, sizeof(*rsp));

    /* (i) refuse unless this is a version-3 chain. */
    if (!w->v2_successor) {
        return cc_appr_refuse(rsp, "this node is not on a version-3 chain");
    }

    /* The former tier-3 header frame gate (`wh.cid == w->v2_chain32`) is
     * gone with the envelope: the requester's connection could only be
     * established with THIS chain's id (the secret connection's N9 check
     * and NodeInfo CompatibleWith, p2p-port design §3), and the approval
     * digest below binds this chain regardless (the header comment). */

    /* (v) per-proposer rate limit — unchanged (nodus_cc_rate_limit_check
     * / _record), keyed on `peer_wid`: the requesting connection's
     * AUTHENTICATED identity (SHA3-512 of the key its secret connection
     * verified), never a decoded field.
     * ORCHESTRATOR correction (W4-CC ORC-7): checked HERE, before the
     * preflight — the retired handler ran it "before the expensive
     * digest + Dilithium5 sign so a hostile proposer cannot burn CPU by
     * spamming", and this handler's expensive work now starts one step
     * earlier, at the engine seam's decode + SHA3 over an envelope of up
     * to DNA_ENV_MAX_TOTAL_LEN. The check itself has no side effect; the
     * slot is recorded below, after the bonded gate (red-team H1). */
    uint64_t now_ms = nodus_time_now_ms();
    uint64_t elapsed_ms = 0;
    if (nodus_cc_rate_limit_check(&w->cc_rate_limit, peer_wid,
                                  now_ms, &elapsed_ms) != 0) {
        w->cc_rate_limit.rate_limited_count++;
        char rl_reason[128];
        snprintf(rl_reason, sizeof(rl_reason),
                 "rate-limited (cooldown %ums, elapsed %llums)",
                 (unsigned)NODUS_CC_RATE_LIMIT_WINDOW_MS,
                 (unsigned long long)elapsed_ms);
        return cc_appr_refuse(rsp, rl_reason);
    }

    /* (v-a) the BONDED gate, before any DB work (red-team H1). Only a
     * committee seat may make this node sign (decision
     * 2026-09-26-cc-approval-via-own-node.md (5)), and every seat of the
     * committee at the tip is in the p2p host's in-memory bonded set
     * (ACTIVE ∪ ELIGIBLE ∪ the committees at tip ± 1,
     * nodus_witness_p2p_refresh_bonded). A requester outside it is
     * DROPPED: no reply, no committee resolution, nothing recorded, and
     * NOT stopped — the set is refreshed once per poll and can be one
     * poll stale for a seat that just bonded (fix proposals 2026-09-27
     * "REVISED" H1). No reference counterpart: channel 0x71 is nodus's
     * own (R-P2P-5). The rate limit above cannot hold it back: a
     * requester is recorded only after this gate. */
    if (!requester_bonded) {
        QGP_LOG_DEBUG(LOG_TAG, "0x71 approval request from a requester "
                      "outside the bonded set — dropped, no reply");
        return NODUS_CC_APPR_DROPPED;
    }

    /* (v-b) RECORD the attempt: every bonded request that passed the
     * check above holds the requester's slot for the whole cooldown
     * window, whatever the verdict below — a seat that floods invalid
     * envelopes is throttled like one that floods valid ones (red-team
     * H1; previously only a SENT approval was recorded). The requesting
     * CLI waits the window out before its round 2 (nodus-cli.c). The
     * table has NODUS_CC_RATE_LIMIT_MAX_PROPOSERS = 128 slots (pinned to
     * the active-validator ceiling above); a bonded set larger than that
     * evicts the least recently recorded (nodus_cc_rate_limit_record). */
    nodus_cc_rate_limit_record(&w->cc_rate_limit, peer_wid, now_ms);

    /* (vi) resolve the governing committee at the tip (cc_appr_resolve —
     * the same resolution the node-side collection uses; the committee
     * itself is epoch-cached, nodus_witness_committee.c). Resolved HERE,
     * before the preflight, because the requester gate below needs it. */
    uint64_t tip = 0;
    nodus_committee_member_t *committee = NULL;
    int cm_count = 0;
    uint8_t (*fps)[64] = NULL;
    if (cc_appr_resolve(w, &tip, &committee, &cm_count, &fps) != 0) {
        return cc_appr_refuse(rsp, "fault");
    }

    /* (vi-a) the REQUESTER must be a seat of that committee (decision
     * 2026-09-26-cc-approval-via-own-node.md (5): "Only validators can
     * make a validator sign an approval"). `peer_wid` is the first 32
     * bytes of SHA3-512(the requester's AUTHENTICATED key) — the p2p
     * host's derivation (nodus_witness_p2p.c peer_wid) and
     * nodus_chain_config_derive_witness_id's — so it is compared with the
     * same 32 bytes of each seat's fingerprint. Cheap and BEFORE the
     * preflight: a non-seat never costs this node a decode, a digest or a
     * signature. Its attempt is already recorded (v-b). */
    {
        bool requester_is_seat = false;
        for (int i = 0; i < cm_count; i++) {
            if (memcmp(fps[i], peer_wid, NODUS_CC_WITNESS_ID_SIZE) == 0) {
                requester_is_seat = true;
                break;
            }
        }
        if (!requester_is_seat) {
            free(fps); free(committee);
            return cc_appr_refuse(rsp, "requester is not a committee seat");
        }
    }

    /* (ii) decode `e` with the ENGINE'S OWN preflight seam — never a
     * private decoder. This is the SAME two-call sequence CheckTx uses
     * (nodus_witness_cmt_app.c:276-305 nodus_cmt_app_entry_identity):
     * nodus_witness_v2_block_ctx_build for the committed ruleset table,
     * then nodus_witness_v2_env_preflight_batch for the candidate
     * height's structural preflight. dna_env_preflight (which this
     * seam calls) does NOT validate signatures — env_preflight.h:57-63
     * says so explicitly — so it succeeds on a zero-filled auth blob
     * exactly as the proposer's own pass-1 build does
     * (nodus-cli.c:944-946), which is what makes it usable BEFORE
     * anyone has signed. The candidate height is the resolved tip + 1. */
    uint64_t h = tip + 1;

    nodus_witness_v2_block_ctx_t *bctx = calloc(1, sizeof(*bctx));
    dna_env_preflight_t          *pf   = calloc(1, sizeof(*pf));
    if (!bctx || !pf) {
        free(bctx); free(pf); free(fps); free(committee);
        return cc_appr_refuse(rsp, "fault");
    }
    int bcrc = nodus_witness_v2_block_ctx_build(w, h, bctx);
    if (bcrc != 0) {
        free(bctx); free(pf); free(fps); free(committee);
        return cc_appr_refuse(rsp, bcrc == -1 ? "SYSTEM is not ACTIVE"
                                              : "fault");
    }
    nodus_v2_envelope_t env;
    env.env_bytes = req->e;
    env.env_len   = req->e_len;
    size_t                     fail_idx = 0;
    dna_env_preflight_status_t pf_status = DNA_ENV_PF_OK;
    nodus_v2_env_status_t pbrc = nodus_witness_v2_env_preflight_batch(
        w, h, bctx->rulesets, bctx->n_rulesets, &env, 1, pf,
        &fail_idx, &pf_status);
    free(bctx);
    if (pbrc != NODUS_V2_ENV_OK) {
        free(pf); free(fps); free(committee);
        return cc_appr_refuse(rsp, "the envelope failed preflight");
    }

    /* (iii) the APPROVAL TABLE: exactly one leg, matching a row, under
     * auth_kind 2, fee 0. */
    const dna_env_view_t *v = &pf->view;
    if (v->leg_count != 1 || v->fee_amount != 0 ||
        v->leg[0].auth_kind != NODUS_RT_AUTHKIND_DSA87_CC_V1) {
        free(pf); free(fps); free(committee);
        return cc_appr_refuse(rsp,
                              "not a single-leg auth_kind-2 zero-fee envelope");
    }
    const cc_appr_table_row_t *row = NULL;
    for (size_t i = 0; i < CC_APPR_TABLE_LEN; i++) {
        if (CC_APPR_TABLE[i].domain_id == v->leg[0].domain_id &&
            CC_APPR_TABLE[i].runtime_op == v->leg[0].runtime_op) {
            row = &CC_APPR_TABLE[i];
            break;
        }
    }
    if (!row || v->leg[0].call_len != row->call_len) {
        free(pf); free(fps); free(committee);
        return cc_appr_refuse(rsp, "operation is not in the approval table");
    }

    /* (iv) the op's own rules, at the SAME candidate height `h`. */
    char reason[128];
    reason[0] = '\0';
    int rulerc = row->rule(w, v->buf + v->call_off[0], v->leg[0].call_len,
                          h, reason, sizeof(reason));
    if (rulerc != 0) {
        free(pf); free(fps); free(committee);
        return cc_appr_refuse(rsp, reason);
    }

    /* (v) the per-proposer rate limit was checked and recorded above,
     * before the preflight (ORC-7, red-team H1). (vi) the committee was
     * resolved above, before the requester gate. */

    /* find this node's own seat by direct pubkey comparison against the
     * resolved snapshot — the same comparison the offline CLI builder
     * uses to find ITS signers' seats (nodus-cli.c:1898-1900). */
    int seat = -1;
    for (int i = 0; i < cm_count; i++) {
        if (memcmp(committee[i].pubkey, w->host->identity->pk.bytes,
                   NODUS_CC_PUBKEY_SIZE) == 0) {
            seat = i;
            break;
        }
    }
    if (seat < 0) {
        free(fps); free(committee); free(pf);
        return cc_appr_refuse(rsp, "not a committee seat");
    }

    /* (vii) the resolved-set hash + epoch + the digest ITSELF, computed
     * from the seam-derived leg auth_digest — never a digest this node
     * did not compute. */
    uint8_t set_hash[64];
    if (nodus_rt_committee_set_hash((const uint8_t (*)[64])fps,
                                    (uint32_t)cm_count, set_hash) != 0) {
        free(fps); free(committee); free(pf);
        return cc_appr_refuse(rsp, "fault");
    }
    uint64_t epoch = nodus_v2_epoch_for_height(tip);

    uint8_t adigest[64];
    if (nodus_rt_cc_approval_digest(pf->auth_digest[0], set_hash, epoch,
                                    (uint16_t)seat, adigest) != 0) {
        free(fps); free(committee); free(pf);
        return cc_appr_refuse(rsp, "fault");
    }

    uint8_t scratch_witness_id[NODUS_CC_WITNESS_ID_SIZE];
    if (nodus_chain_config_sign_vote(w->host->identity->pk.bytes,
                                     w->host->identity->sk.bytes,
                                     adigest, scratch_witness_id,
                                     rsp->sig) != 0) {
        memset(rsp->sig, 0, sizeof(rsp->sig));
        free(fps); free(committee); free(pf);
        return cc_appr_refuse(rsp, "sign failed");
    }

    rsp->ok    = true;
    rsp->seat  = (uint16_t)seat;
    memcpy(rsp->set_hash, set_hash, 64);
    rsp->epoch = epoch;

    QGP_LOG_INFO(LOG_TAG,
        "CC_APPR_SIGNED domain=%u op=%u seat=%d epoch=%llu",
        (unsigned)v->leg[0].domain_id, (unsigned)v->leg[0].runtime_op,
        seat, (unsigned long long)epoch);

    free(fps);
    free(committee);
    free(pf);
    return 1;
}

int nodus_witness_cc_appr_answer(nodus_witness_t *w,
                                 const uint8_t peer_wid[NODUS_CC_WITNESS_ID_SIZE],
                                 bool requester_bonded,
                                 const nodus_t3_cc_appr_req_t *req,
                                 nodus_t3_cc_appr_rsp_t *rsp_out) {
    if (!w || !peer_wid || !req || !rsp_out ||
        (req->e == NULL && req->e_len != 0)) return -1;
    int arc = cc_appr_verdict(w, peer_wid, requester_bonded, req, rsp_out);

    /* Every answer that will be SENT — the signed approval and every
     * refusal — names the request it answers (decision
     * 2026-09-27-p2p-fix-2.md (2); nodus_tier3.h `rq`): SHA3-512 of the
     * envelope bytes asked about, the same bytes the collector hashed
     * (nodus_witness_cc_collect_start). Hashed only here, after the
     * verdict: a DROPPED request (outside the bonded set) costs no hash,
     * and the rate-limit check still precedes every expensive step. */
    if (arc < 0 || arc == NODUS_CC_APPR_DROPPED) return arc;
    /* an empty `e` is hashed as the empty string (qgp_sha3_512 refuses a
     * NULL pointer even at length 0) */
    static const uint8_t no_bytes[1] = { 0 };
    if (qgp_sha3_512(req->e != NULL ? req->e : no_bytes, req->e_len,
                     rsp_out->rq) != 0) {
        memset(rsp_out, 0, sizeof(*rsp_out));
        return -1;
    }
    return arc;
}

int nodus_witness_handle_cc_appr_req(nodus_witness_t *w,
                                     const char *peer_id,
                                     const uint8_t peer_wid[NODUS_CC_WITNESS_ID_SIZE],
                                     const void *ireq) {
    if (!w || !peer_id || !peer_wid || !ireq) return -1;

    nodus_t3_cc_appr_rsp_t rsp;
    /* The bonded set is the p2p host's, in memory (a bsearch); the
     * verdict takes the answer as an argument so it stays callable
     * without a host (test_cc_appr). */
    bool bonded = nodus_witness_p2p_is_bonded(w->p2p, peer_id);
    int arc = nodus_witness_cc_appr_answer(w, peer_wid, bonded,
                                           (const nodus_t3_cc_appr_req_t *)ireq,
                                           &rsp);
    if (arc < 0) return -1;
    if (arc == NODUS_CC_APPR_DROPPED) return 0;           /* no reply */

    /* The rate-limit slot was recorded inside the verdict, on the
     * attempt (red-team H1) — it no longer waits for a sent approval
     * (the former ORC-11 placement): a refused attempt holds the slot
     * too, and the requesting CLI waits the window out before its round
     * 2 whatever it was answered (nodus-cli.c). */
    return cc_appr_send(w, peer_id, &rsp);
}

/* ============================================================================
 * The node-side approval collection (`dnac_cc_collect`, decision
 * docs/plans/decisions/2026-09-26-cc-approval-via-own-node.md): the
 * proposer's CLI hands its OWN node the pre-auth envelope over 4001; the
 * node asks every other committee seat on channel 0x71 over the 4004
 * connections it already holds, and answers the CLI with one result per
 * seat. Tooling, not consensus: nothing here feeds a block, a vote or the
 * state root — each approval is verified by the SYSTEM runtime at
 * execution, exactly as before (decision "Consequences").
 *
 * Bounded: ONE collection at a time per node (a second request is
 * refused "busy"); every seat is asked at most once; the collection ends
 * when every asked seat answered or NODUS_CC_COLLECT_DEADLINE_MS after it
 * began, whichever is first; the state is freed when it ends (and when
 * the p2p host is freed, with no reply).
 * ========================================================================== */

/* Internal only — a seat that was sent the request and has not answered
 * yet. Never on the wire: at the end it becomes
 * NODUS_CC_COLLECT_ST_NO_ANSWER. */
#define CC_COLLECT_ST_ASKED  0xFFu

/* The client SDK must wait past the node's own deadline, or a slow seat
 * turns every collection into a client timeout. */
_Static_assert(NODUS_DNAC_CC_COLLECT_TIMEOUT_MS > NODUS_CC_COLLECT_DEADLINE_MS,
               "the client's dnac_cc_collect wait must exceed the node's "
               "collection deadline");
/* The client decodes at most NODUS_T3_MAX_WITNESSES entries; a reply
 * carries one per seat but self, and a committee never exceeds the
 * active-validator ceiling. */
_Static_assert(DNA_MAX_ACTIVE_VALIDATORS <= NODUS_T3_MAX_WITNESSES,
               "a dnac_cc_collect reply must fit the client's result");

typedef struct {
    uint16_t                seat;
    uint8_t                 status;          /* NODUS_CC_COLLECT_ST_* */
    char                    peer_id[CMT_P2P_ID_CAP];
    nodus_t3_cc_appr_rsp_t  rsp;             /* status ANSWERED only  */
} cc_collect_seat_t;

struct nodus_cc_collect {
    /* The requesting 4001 session, by IDENTITY + SESSION TOKEN — never a
     * connection pointer (decision (4)): looked up again at reply time. */
    uint8_t             requester_pk[NODUS_PK_BYTES];
    uint8_t             token[NODUS_SESSION_TOKEN_LEN];
    uint32_t            txn_id;
    int64_t             deadline_ms;         /* monotonic, ms         */
    /* The request identity every answer must carry: SHA3-512 of the
     * envelope sent (nodus_tier3.h `rq`; decision 2026-09-27-p2p-fix-2.md
     * (2)). */
    uint8_t             rq[NODUS_T3_CC_APPR_RQ_BYTES];
    int                 n_seats;             /* every seat but self   */
    int                 n_waiting;           /* status ASKED          */
    cc_collect_seat_t  *seats;
};

/* The requesting session, if it is still authenticated as the same
 * identity in the same session (its token) — asked of the host
 * (nodus_witness_host.h find_session_conn). @return its connection, or
 * NULL (gone / re-authenticated / never existed). */
static struct nodus_tcp_conn *cc_collect_session_conn(nodus_witness_t *w,
                                                      const nodus_cc_collect_t *c) {
    if (!w->host || !w->host->find_session_conn) return NULL;
    return w->host->find_session_conn(w->host->ctx, c->requester_pk,
                                      c->token);
}

/* The reply: {"t": txn, "y": "r", "q": "dnac_cc_collect", "r": {"res":
 * [entry...]}} — the dnac_* response header (nodus_witness_handlers.c
 * enc_dnac_response) — one entry per seat other than this node's own,
 * ascending seat order:
 *   {"i": seat, "st": status, "ok": bool}                  not answered
 *   {"i", "st", "ok": false, "r": reason}                   refused
 *   {"i", "st", "ok": true, "rs": the responder's own seat,
 *    "s": signature, "sh": set hash, "ep": epoch}            approved
 * @return the encoded length, or 0 on overflow. */
static size_t cc_collect_encode_reply(const nodus_cc_collect_t *c,
                                      uint8_t *buf, size_t cap) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    cbor_encode_map(&enc, 4);
    cbor_encode_cstr(&enc, "t");  cbor_encode_uint(&enc, c->txn_id);
    cbor_encode_cstr(&enc, "y");  cbor_encode_cstr(&enc, "r");
    cbor_encode_cstr(&enc, "q");  cbor_encode_cstr(&enc, "dnac_cc_collect");
    cbor_encode_cstr(&enc, "r");
    cbor_encode_map(&enc, 1);
    cbor_encode_cstr(&enc, "res");
    cbor_encode_array(&enc, (size_t)c->n_seats);
    for (int i = 0; i < c->n_seats; i++) {
        const cc_collect_seat_t *s = &c->seats[i];
        bool answered = s->status == NODUS_CC_COLLECT_ST_ANSWERED;
        bool ok = answered && s->rsp.ok;
        cbor_encode_map(&enc, ok ? 7u : (answered ? 4u : 3u));
        cbor_encode_cstr(&enc, "i");  cbor_encode_uint(&enc, s->seat);
        cbor_encode_cstr(&enc, "st"); cbor_encode_uint(&enc, s->status);
        cbor_encode_cstr(&enc, "ok"); cbor_encode_bool(&enc, ok);
        if (ok) {
            cbor_encode_cstr(&enc, "rs"); cbor_encode_uint(&enc, s->rsp.seat);
            cbor_encode_cstr(&enc, "s");
            cbor_encode_bstr(&enc, s->rsp.sig, NODUS_SIG_BYTES);
            cbor_encode_cstr(&enc, "sh");
            cbor_encode_bstr(&enc, s->rsp.set_hash, 64);
            cbor_encode_cstr(&enc, "ep"); cbor_encode_uint(&enc, s->rsp.epoch);
        } else if (answered) {
            cbor_encode_cstr(&enc, "r");  cbor_encode_cstr(&enc, s->rsp.reason);
        }
    }
    return cbor_encoder_len(&enc);
}

static void cc_collect_free(nodus_cc_collect_t *c) {
    if (!c) return;
    free(c->seats);
    free(c);
}

/* End the pending collection: every seat still ASKED becomes NO_ANSWER,
 * the reply goes to the requesting session if it is still there
 * (decision (4)), and the state is freed. */
static void cc_collect_finish(nodus_witness_t *w) {
    nodus_cc_collect_t *c = w->cc_collect;
    if (!c) return;
    w->cc_collect = NULL;

    int n_ok = 0;
    for (int i = 0; i < c->n_seats; i++) {
        if (c->seats[i].status == CC_COLLECT_ST_ASKED)
            c->seats[i].status = NODUS_CC_COLLECT_ST_NO_ANSWER;
        if (c->seats[i].status == NODUS_CC_COLLECT_ST_ANSWERED &&
            c->seats[i].rsp.ok)
            n_ok++;
    }

    struct nodus_tcp_conn *conn = cc_collect_session_conn(w, c);
    if (!conn) {
        QGP_LOG_WARN(LOG_TAG, "CC_COLLECT_DONE approved=%d/%d — the "
                     "requesting session is gone, reply dropped",
                     n_ok, c->n_seats);
        cc_collect_free(c);
        return;
    }
    /* Worst case per entry: the signature, the set hash, the key strings
     * and the CBOR headers, or a <=128-character reason. */
    size_t cap = 256 + (size_t)c->n_seats * (NODUS_SIG_BYTES + 64 + 256);
    uint8_t *buf = malloc(cap);
    size_t len = buf ? cc_collect_encode_reply(c, buf, cap) : 0;
    if (len == 0 || nodus_tcp_send(conn, buf, len) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "CC_COLLECT_DONE approved=%d/%d — the reply "
                      "could not be sent", n_ok, c->n_seats);
    } else {
        QGP_LOG_INFO(LOG_TAG, "CC_COLLECT_DONE approved=%d/%d", n_ok,
                     c->n_seats);
    }
    free(buf);
    cc_collect_free(c);
}

int nodus_witness_cc_collect_start(nodus_witness_t *w,
                                   const uint8_t requester_pk[NODUS_PK_BYTES],
                                   const uint8_t token[NODUS_SESSION_TOKEN_LEN],
                                   uint32_t txn_id,
                                   const uint8_t *e, size_t e_len,
                                   int64_t now_ms,
                                   char *err, size_t err_size) {
    if (!w || !w->host || !requester_pk || !token || !e || !err ||
        err_size == 0)
        return -1;
    err[0] = '\0';

    /* Decision (2): served ONLY to a session authenticated with THIS
     * node's own identity key — the proposer is this node's seat. */
    if (memcmp(requester_pk, w->host->identity->pk.bytes, NODUS_PK_BYTES) != 0) {
        snprintf(err, err_size, "dnac_cc_collect is served only to this "
                                "node's own identity");
        return -1;
    }
    if (e_len == 0 || e_len > NODUS_T3_CC_APPR_E_MAX) {
        snprintf(err, err_size, "envelope length out of range");
        return -1;
    }
    if (w->cc_collect) {
        snprintf(err, err_size, "busy: an approval collection is pending");
        return -1;
    }
    if (!w->v2_successor) {
        snprintf(err, err_size, "this node is not on a version-3 chain");
        return -1;
    }

    uint64_t tip = 0;
    nodus_committee_member_t *committee = NULL;
    int cm_count = 0;
    uint8_t (*fps)[64] = NULL;
    if (cc_appr_resolve(w, &tip, &committee, &cm_count, &fps) != 0) {
        snprintf(err, err_size, "committee resolution failed");
        return -1;
    }
    free(fps);                     /* the seats' IDs derive from the keys */

    int self_seat = -1;
    for (int i = 0; i < cm_count; i++) {
        if (memcmp(committee[i].pubkey, w->host->identity->pk.bytes,
                   NODUS_CC_PUBKEY_SIZE) == 0) {
            self_seat = i;
            break;
        }
    }
    if (self_seat < 0) {
        free(committee);
        snprintf(err, err_size, "this node is not a committee seat");
        return -1;
    }

    nodus_cc_collect_t *c = calloc(1, sizeof(*c));
    uint8_t *msg = malloc(e_len + 256u);
    if (c) c->seats = calloc((size_t)cm_count, sizeof(*c->seats));
    size_t msg_len = 0;
    nodus_t3_cc_appr_req_t req = { .e = e, .e_len = e_len };
    if (!c || !c->seats || !msg ||
        nodus_t3_cc_appr_req_encode(&req, msg, e_len + 256u, &msg_len) != 0 ||
        qgp_sha3_512(e, e_len, c->rq) != 0) {
        free(msg);
        cc_collect_free(c);
        free(committee);
        snprintf(err, err_size, "fault");
        return -1;
    }
    memcpy(c->requester_pk, requester_pk, NODUS_PK_BYTES);
    memcpy(c->token, token, NODUS_SESSION_TOKEN_LEN);
    c->txn_id = txn_id;
    c->deadline_ms = now_ms + (int64_t)NODUS_CC_COLLECT_DEADLINE_MS;

    /* Every seat but self, ascending (committee resolution order): over
     * the EXISTING 4004 connection to that seat's p2p ID (decision (3)),
     * or "not connected". No new connection is ever dialed here. */
    for (int i = 0; i < cm_count; i++) {
        if (i == self_seat) continue;
        cc_collect_seat_t *s = &c->seats[c->n_seats++];
        s->seat = (uint16_t)i;
        if (cmt_p2p_pubkey_to_id(committee[i].pubkey, s->peer_id) != CMT_OK) {
            s->status = NODUS_CC_COLLECT_ST_SEND_FAILED;
        } else if (!nodus_witness_p2p_has_peer(w->p2p, s->peer_id)) {
            s->status = NODUS_CC_COLLECT_ST_NOT_CONNECTED;
        } else if (!nodus_witness_p2p_send(w->p2p, s->peer_id,
                                           NODUS_P2P_CH_CC_APPR, msg, msg_len)) {
            s->status = NODUS_CC_COLLECT_ST_SEND_FAILED;
        } else {
            s->status = CC_COLLECT_ST_ASKED;
            c->n_waiting++;
        }
    }
    free(msg);
    free(committee);

    QGP_LOG_INFO(LOG_TAG, "CC_COLLECT_START seats=%d asked=%d tip=%llu",
                 c->n_seats, c->n_waiting, (unsigned long long)tip);
    w->cc_collect = c;
    if (c->n_waiting == 0) {
        cc_collect_finish(w);      /* nothing to wait for: answer at once */
    }
    return 0;
}

bool nodus_witness_cc_collect_on_rsp(nodus_witness_t *w, const char *peer_id,
                                     const nodus_t3_cc_appr_rsp_t *rsp) {
    if (!w || !peer_id || !rsp || !w->cc_collect) return false;
    nodus_cc_collect_t *c = w->cc_collect;
    /* An answer to ANOTHER request (a late one to an earlier collection
     * whose envelope differed) is not an answer to this one, whoever sent
     * it — decision 2026-09-27-p2p-fix-2.md (2). Refusals carry `rq` too.
     * No reference counterpart: channel 0x71 is nodus's own (R-P2P-5). */
    if (memcmp(rsp->rq, c->rq, NODUS_T3_CC_APPR_RQ_BYTES) != 0) return false;
    for (int i = 0; i < c->n_seats; i++) {
        cc_collect_seat_t *s = &c->seats[i];
        if (s->status != CC_COLLECT_ST_ASKED ||
            strcmp(s->peer_id, peer_id) != 0)
            continue;
        s->rsp = *rsp;
        s->status = NODUS_CC_COLLECT_ST_ANSWERED;
        if (--c->n_waiting == 0) {
            cc_collect_finish(w);
        }
        return true;
    }
    return false;          /* not a peer this collection is waiting on */
}

void nodus_witness_cc_collect_tick(nodus_witness_t *w, int64_t now_ms) {
    if (!w || !w->cc_collect) return;
    if (now_ms >= w->cc_collect->deadline_ms) {
        cc_collect_finish(w);
    }
}

void nodus_witness_cc_collect_abort(nodus_witness_t *w) {
    if (!w || !w->cc_collect) return;
    cc_collect_free(w->cc_collect);
    w->cc_collect = NULL;
}

/* Q17 / CC-OPS-005 — observability dump. Single-line structured log
 * so external scrapers / grafana agents can tail journalctl. */
void nodus_chain_config_log_stats(nodus_witness_t *w) {
    if (!w) return;
    QGP_LOG_INFO(LOG_TAG,
        "CHAIN_CONFIG_STATS committed=%llu rejected=%llu "
        "cache_hits=%llu cache_misses=%llu rate_limited=%llu",
        (unsigned long long)w->chain_config_proposals_committed,
        (unsigned long long)w->chain_config_proposals_rejected,
        (unsigned long long)w->chain_config_cache_hits,
        (unsigned long long)w->chain_config_cache_misses,
        (unsigned long long)w->cc_rate_limit.rate_limited_count);
}

/* HF-4 review (L1 F1): nodus_chain_config_apply — the legacy CHAIN_CONFIG
 * tx apply, with its private parse / rule / digest helpers — is DELETED:
 * it had no caller in nodus/src or in any test since R3 W4 closed the
 * legacy lane. The ONE apply path is the SYSTEM CHAIN_CONFIG runtime
 * (nodus_witness_rt_native.c), which judges through
 * nodus_chain_config_scalar_rules + nodus_chain_config_stateful_rules. */
