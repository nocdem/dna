/**
 * @file nodus_witness_v2_apply.c
 * @brief Ledger V2 Season 5 — atomic global-block apply engine, V2
 *        genesis and the V2 supply gate (INACTIVE). Contract:
 *        nodus_witness_v2_apply.h.
 *
 * @file nodus_witness_v2_apply.c
 */

#include "witness/nodus_witness_v2_apply.h"
#include "witness/nodus_witness_v2_schema.h"
#include "witness/nodus_witness_v2_claims.h"
#include "witness/nodus_witness_domreg.h"
#include "witness/nodus_witness_roots_v2.h"
#include "witness/nodus_witness_db.h"
#include "nodus/nodus_chain_config.h"

#include "dnac/dnac.h"                 /* DNAC_CFG_* */
#include "crypto/utils/qgp_log.h"

#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>

#define LOG_TAG "W_V2APPLY"

#define MAX_OPS 16      /* engine array bound; the GLOBAL tx cap (<= 10)
                         * is enforced separately from chain config      */

static int exec_sql(nodus_witness_t *w, const char *sql) {
    char *err = NULL;
    if (sqlite3_exec(w->db, sql, NULL, NULL, &err) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "SQL failed: %s", err ? err : "?");
        sqlite3_free(err);
        return -1;
    }
    return 0;
}

/* Sum one u64 aggregate; fail-closed (D1: DB error is never a value). */
static int sum_q(nodus_witness_t *w, const char *sql, uint64_t *out) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db, sql, -1, &st, NULL) != SQLITE_OK)
        return -1;
    int rc = sqlite3_step(st);
    if (rc != SQLITE_ROW) { sqlite3_finalize(st); return -1; }
    sqlite3_int64 v = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    if (v < 0) return -1;
    *out = (uint64_t)v;
    return 0;
}

/* ── V2 supply gate ─────────────────────────────────────────────────── */

int nodus_witness_v2_supply_check(nodus_witness_t *w) {
    if (!w || !w->db) return -1;

    /* C3 stop: NO shielded pool state may exist. A table that looks like
     * pool state is unknown supply — fail closed. */
    {
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(w->db,
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND "
                "(LOWER(name) LIKE '%shielded%' OR "
                " LOWER(name) LIKE 'pool_%')", -1, &st, NULL) != SQLITE_OK)
            return -1;
        int rc = sqlite3_step(st);
        int n = (rc == SQLITE_ROW) ? sqlite3_column_int(st, 0) : -1;
        sqlite3_finalize(st);
        if (n != 0) {
            QGP_LOG_ERROR(LOG_TAG,
                "SUPPLY V2: shielded/pool state table present (%d) — "
                "C3 is inactive, rejecting", n);
            return -1;
        }
    }

    nodus_witness_supply_t sup;
    memset(&sup, 0, sizeof(sup));
    int sup_rc = nodus_witness_supply_get(w, &sup);
    if (sup_rc < 0) return -1;           /* DB error is never a value     */
    if (sup_rc == 1) return 0;           /* honest pre-genesis            */

    uint64_t expected = sup.genesis_supply;
    if (sup.total_minted > UINT64_MAX - expected) return -1;
    expected += sup.total_minted;
    if (sup.total_burned > expected) return -1;   /* underflow            */
    expected -= sup.total_burned;

    uint64_t utxo = 0, bonds = 0, delegated = 0, pool = 0, unclaimed = 0;
    /* the production helper OWNS the native-token representation rule —
     * one authority, never a parallel SQL mirror */
    if (nodus_witness_utxo_sum_by_token(w, NULL, &utxo) != 0) return -1;
    if (sum_q(w, "SELECT COALESCE(SUM(self_stake),0) FROM validators",
              &bonds) != 0) return -1;
    if (sum_q(w, "SELECT COALESCE(SUM(total_delegated),0) FROM validators",
              &delegated) != 0) return -1;
    if (sum_q(w, "SELECT COALESCE(SUM(epoch_pool_accum),0) FROM epoch_state",
              &pool) != 0) return -1;
    /* S6: the ONE generic unclaimed-distribution owner (absent table =
     * honest pre-S6 zero; DB fault fails the gate). */
    if (nodus_witness_v2_unclaimed_total(w, &unclaimed) != 0) return -1;

    const uint64_t shielded = 0;         /* FIXED until C3 — see above    */

    uint64_t observed = utxo;
    if (bonds > UINT64_MAX - observed) return -1;
    observed += bonds;
    if (delegated > UINT64_MAX - observed) return -1;
    observed += delegated;
    if (pool > UINT64_MAX - observed) return -1;
    observed += pool;
    if (unclaimed > UINT64_MAX - observed) return -1;
    observed += unclaimed;
    if (shielded > UINT64_MAX - observed) return -1;
    observed += shielded;

    if (expected != observed) {
        QGP_LOG_ERROR(LOG_TAG,
            "SUPPLY V2 VIOLATION: expected=%llu observed=%llu "
            "(utxo=%llu bonds=%llu delegated=%llu pool=%llu "
            "unclaimed=%llu shielded=0)",
            (unsigned long long)expected, (unsigned long long)observed,
            (unsigned long long)utxo, (unsigned long long)bonds,
            (unsigned long long)delegated, (unsigned long long)pool,
            (unsigned long long)unclaimed);
        return -1;
    }
    return 0;
}

/* ── DomainHead persistence ─────────────────────────────────────────── */

static int head_store(nodus_witness_t *w, const dna_v2_domain_head_t *h) {
    uint8_t enc[DNA_V2_DOMHEAD_ENC_LEN];
    if (dna_v2_domain_head_encode(h, enc) != 0) return -1;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "INSERT OR REPLACE INTO v2_domain_heads "
            "(domain_id, head, domain_height, last_updated_global) "
            "VALUES (?1, ?2, ?3, ?4)", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)h->domain_id);
    sqlite3_bind_blob(st, 2, enc, DNA_V2_DOMHEAD_ENC_LEN, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 3, (sqlite3_int64)h->domain_height);
    sqlite3_bind_int64(st, 4, (sqlite3_int64)h->last_updated_global_height);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

/* Decode the 89-byte canonical head blob (layout: ledger_roots_v2.h). */
static void head_decode(const uint8_t enc[DNA_V2_DOMHEAD_ENC_LEN],
                        dna_v2_domain_head_t *h) {
    memset(h, 0, sizeof(*h));
    h->domain_id = ((uint32_t)enc[0] << 24) | ((uint32_t)enc[1] << 16) |
                   ((uint32_t)enc[2] << 8) | enc[3];
    memcpy(h->domain_state_root, enc + 4, 64);
    for (int i = 0; i < 8; i++)
        h->domain_height = (h->domain_height << 8) | enc[68 + i];
    for (int i = 0; i < 8; i++)
        h->last_updated_global_height =
            (h->last_updated_global_height << 8) | enc[76 + i];
    h->ruleset_version = ((uint32_t)enc[84] << 24) |
                         ((uint32_t)enc[85] << 16) |
                         ((uint32_t)enc[86] << 8) | enc[87];
    h->status = enc[88];
}

/* 0 found (validated blob + mirror agreement), 1 absent, -1 fault. */
static int head_load(nodus_witness_t *w, uint32_t domain_id,
                     dna_v2_domain_head_t *out) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT head, domain_height, last_updated_global "
            "FROM v2_domain_heads WHERE domain_id = ?1", -1, &st, NULL)
        != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)domain_id);
    int rc = sqlite3_step(st);
    if (rc == SQLITE_DONE) { sqlite3_finalize(st); return 1; }
    int out_rc = -1;
    if (rc == SQLITE_ROW &&
        sqlite3_column_bytes(st, 0) == DNA_V2_DOMHEAD_ENC_LEN) {
        dna_v2_domain_head_t h;
        head_decode(sqlite3_column_blob(st, 0), &h);
        uint64_t mh = (uint64_t)sqlite3_column_int64(st, 1);
        uint64_t ml = (uint64_t)sqlite3_column_int64(st, 2);
        if (h.domain_id == domain_id && h.domain_height == mh &&
            h.last_updated_global_height == ml) {
            *out = h;
            out_rc = 0;
        }
    }
    sqlite3_finalize(st);
    return out_rc;
}

/* Latest committed update hash for a domain (genesis sentinel if none). */
static int prev_update_hash(nodus_witness_t *w, uint32_t domain_id,
                            uint8_t out[64]) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT upd_hash FROM v2_domain_updates WHERE domain_id = ?1 "
            "ORDER BY global_height DESC LIMIT 1", -1, &st, NULL)
        != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)domain_id);
    int rc = sqlite3_step(st);
    int out_rc = -1;
    if (rc == SQLITE_ROW) {
        if (sqlite3_column_bytes(st, 0) == 64) {
            memcpy(out, sqlite3_column_blob(st, 0), 64);
            out_rc = 0;
        }
    } else if (rc == SQLITE_DONE) {
        out_rc = dna_dupd_prev_genesis(out);
    }
    sqlite3_finalize(st);
    return out_rc;
}

/* Compute a domain's CURRENT state root (S5 supports domains 0 and 1). */
static int domain_root_now(nodus_witness_t *w, uint32_t domain_id,
                           uint8_t out[64]) {
    if (domain_id == DNA_DOMAIN_SYSTEM)
        return nodus_witness_system_root_v2(w, out);
    if (domain_id == DNA_DOMAIN_CORE)
        return nodus_witness_core_root_v2(w, out);
    return -1;
}

/* ── V2 genesis ─────────────────────────────────────────────────────── */

int nodus_witness_v2_genesis(nodus_witness_t *w,
                             const uint8_t genesis_block_id[64],
                             const uint8_t vset_hash[64],
                             uint64_t epoch) {
    return nodus_witness_v2_genesis_ex(w, genesis_block_id, vset_hash,
                                       epoch, NULL, 0);
}

int nodus_witness_v2_genesis_ex(nodus_witness_t *w,
                                const uint8_t genesis_block_id[64],
                                const uint8_t vset_hash[64],
                                uint64_t epoch,
                                const uint8_t *manifest_bytes,
                                size_t manifest_len) {
    if (!w || !w->db || !genesis_block_id || !vset_hash) return -1;
    if ((manifest_bytes == NULL) != (manifest_len == 0)) return -1;
    uint32_t ver = 0;
    if (nodus_witness_db_schema_version(w, &ver) != 0 ||
        ver != NODUS_V2_SCHEMA_VERSION_S6)
        return -1;

    /* Idempotency: a committed height-0 row decides. */
    {
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(w->db,
                "SELECT block_id FROM v2_blocks WHERE global_height = 0",
                -1, &st, NULL) != SQLITE_OK)
            return -1;
        int rc = sqlite3_step(st);
        if (rc == SQLITE_ROW) {
            int same = (sqlite3_column_bytes(st, 0) == 64 &&
                        memcmp(sqlite3_column_blob(st, 0),
                               genesis_block_id, 64) == 0);
            sqlite3_finalize(st);
            return same ? 0 : -2;
        }
        sqlite3_finalize(st);
        if (rc != SQLITE_DONE) return -1;
    }

    if (exec_sql(w, "BEGIN IMMEDIATE") != 0) return -1;
    int ok = 0;
    do {
        /* Registry with REAL payload-root manifests (cycle break). */
        if (nodus_witness_domreg_init_genesis(w) != 0) break;

        /* S6: commit the canonical genesis manifest (seq 0, height 0)
         * BEFORE the root computation — the SYSTEM head root below then
         * commits the REAL manifest_root. NON-CIRCULAR by construction:
         * the manifest commits the DomainManifest hashes, whose
         * genesis_state_root legs are the RUNTIME-OWNED payload roots
         * ("DNA.SYSPAYL.v1" — no registry/manifest leg), so
         *   payload → DomainManifest hash → GenesisManifest hash →
         *   manifest_root → FINAL system root
         * stays a DAG with no fixed point. */
        if (manifest_bytes &&
            nodus_witness_v2_manifest_commit(w, manifest_bytes,
                                             manifest_len, 0, 0) != 0)
            break;

        /* Final genesis heads: SYSTEM = FULL 8-leg root (registry rows
         * now exist), CORE = core root. Registry record status feeds the
         * head status byte (S5 definition of the S2 placeholder field). */
        uint8_t sys_root[64], core_root[64];
        if (nodus_witness_system_root_v2(w, sys_root) != 0) break;
        if (nodus_witness_core_root_v2(w, core_root) != 0) break;

        dna_domreg_record_t rec;
        dna_v2_domain_head_t heads[2];
        memset(heads, 0, sizeof(heads));
        if (nodus_witness_domreg_get(w, DNA_DOMAIN_SYSTEM, &rec, NULL,
                                     NULL) != 0) break;
        heads[0].domain_id = DNA_DOMAIN_SYSTEM;
        memcpy(heads[0].domain_state_root, sys_root, 64);
        heads[0].ruleset_version = 1;
        heads[0].status = rec.status;
        if (nodus_witness_domreg_get(w, DNA_DOMAIN_CORE, &rec, NULL,
                                     NULL) != 0) break;
        heads[1].domain_id = DNA_DOMAIN_CORE;
        memcpy(heads[1].domain_state_root, core_root, 64);
        heads[1].ruleset_version = 1;
        heads[1].status = rec.status;

        if (head_store(w, &heads[0]) != 0) break;
        if (head_store(w, &heads[1]) != 0) break;

        uint8_t domains_root[64], global_root[64];
        if (dna_v2_domains_root(heads, 2, domains_root) != 0) break;
        if (dna_v2_global_root(domains_root, global_root) != 0) break;

        uint8_t tx_root[64], dupd_root[64];
        if (dna_v2_tx_batch_root(NULL, 0, tx_root) != 0) break;
        if (dna_v2_domain_updates_root(NULL, 0, dupd_root) != 0) break;

        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(w->db,
                "INSERT INTO v2_blocks (global_height, block_id, "
                "prev_block_id, epoch, tx_root, domain_updates_root, "
                "domains_root, system_root, core_root, global_root, "
                "vset_hash, tx_count, qc) "
                "VALUES (0,?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,0,NULL)",
                -1, &st, NULL) != SQLITE_OK)
            break;
        uint8_t zero64[64];
        memset(zero64, 0, sizeof(zero64));
        sqlite3_bind_blob(st, 1, genesis_block_id, 64, SQLITE_TRANSIENT);
        sqlite3_bind_blob(st, 2, zero64, 64, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 3, (sqlite3_int64)epoch);
        sqlite3_bind_blob(st, 4, tx_root, 64, SQLITE_TRANSIENT);
        sqlite3_bind_blob(st, 5, dupd_root, 64, SQLITE_TRANSIENT);
        sqlite3_bind_blob(st, 6, domains_root, 64, SQLITE_TRANSIENT);
        sqlite3_bind_blob(st, 7, sys_root, 64, SQLITE_TRANSIENT);
        sqlite3_bind_blob(st, 8, core_root, 64, SQLITE_TRANSIENT);
        sqlite3_bind_blob(st, 9, global_root, 64, SQLITE_TRANSIENT);
        sqlite3_bind_blob(st, 10, vset_hash, 64, SQLITE_TRANSIENT);
        int rc = sqlite3_step(st);
        sqlite3_finalize(st);
        if (rc != SQLITE_DONE) break;

        /* Root-history genesis rows (upd_hash = the genesis linkage
         * sentinel — no DomainUpdate exists for height 0). */
        uint8_t sentinel[64];
        if (dna_dupd_prev_genesis(sentinel) != 0) break;
        int hist_ok = 1;
        for (int i = 0; i < 2 && hist_ok; i++) {
            sqlite3_stmt *hs = NULL;
            if (sqlite3_prepare_v2(w->db,
                    "INSERT INTO v2_root_history (domain_id, "
                    "domain_height, global_height, state_root, upd_hash, "
                    "ruleset_version, ruleset_hash) "
                    "VALUES (?1, 0, 0, ?2, ?3, 1, ?4)", -1, &hs, NULL)
                != SQLITE_OK) { hist_ok = 0; break; }
            dna_domain_manifest_t man;
            if (nodus_witness_domreg_get(w, heads[i].domain_id, NULL,
                                         &man, NULL) != 0) {
                sqlite3_finalize(hs); hist_ok = 0; break;
            }
            sqlite3_bind_int64(hs, 1, (sqlite3_int64)heads[i].domain_id);
            sqlite3_bind_blob(hs, 2, heads[i].domain_state_root, 64,
                              SQLITE_TRANSIENT);
            sqlite3_bind_blob(hs, 3, sentinel, 64, SQLITE_TRANSIENT);
            sqlite3_bind_blob(hs, 4, man.ruleset_hash, 64,
                              SQLITE_TRANSIENT);
            if (sqlite3_step(hs) != SQLITE_DONE) hist_ok = 0;
            sqlite3_finalize(hs);
        }
        if (!hist_ok) break;

        if (nodus_witness_v2_supply_check(w) != 0) break;
        ok = 1;
    } while (0);

    if (!ok) { (void)exec_sql(w, "ROLLBACK"); return -1; }
    if (exec_sql(w, "COMMIT") != 0) {
        (void)exec_sql(w, "ROLLBACK");
        return -1;
    }
    return 0;
}

/* ── Apply ──────────────────────────────────────────────────────────── */

typedef struct {
    uint32_t domain_id;
    uint8_t  tx_ids[MAX_OPS][64];       /* local order                   */
    uint32_t n_tx;
    uint32_t res_cost;                  /* checked accumulation          */
    int      touched;
} dom_acc_t;

static dom_acc_t *acc_for(dom_acc_t *acc, size_t n, uint32_t id) {
    for (size_t i = 0; i < n; i++)
        if (acc[i].domain_id == id) return &acc[i];
    return NULL;
}

#define FAIL_POINT(pt) \
    do { if (blk->fail_at == (pt)) goto fail; } while (0)

int nodus_witness_v2_apply_block(nodus_witness_t *w, nodus_v2_block_t *blk) {
    if (!w || !w->db || !blk || (blk->n_ops > 0 && !blk->ops)) return -1;
    if (blk->n_ops > MAX_OPS) return -1;

    uint32_t ver = 0;
    if (nodus_witness_db_schema_version(w, &ver) != 0 ||
        ver != NODUS_V2_SCHEMA_VERSION_S6)
        return -1;

    /* ── 0. replay / linkage (read-only, pre-transaction) ───────────── */
    {
        sqlite3_stmt *st = NULL;
        /* same height? */
        if (sqlite3_prepare_v2(w->db,
                "SELECT block_id FROM v2_blocks WHERE global_height = ?1",
                -1, &st, NULL) != SQLITE_OK)
            return -1;
        sqlite3_bind_int64(st, 1, (sqlite3_int64)blk->global_height);
        int rc = sqlite3_step(st);
        if (rc == SQLITE_ROW) {
            int same = (sqlite3_column_bytes(st, 0) == 64 &&
                        memcmp(sqlite3_column_blob(st, 0), blk->block_id,
                               64) == 0);
            sqlite3_finalize(st);
            return same ? 1 : -1;       /* idempotent / conflicting      */
        }
        sqlite3_finalize(st);
        if (rc != SQLITE_DONE) return -1;

        /* same BlockID at another height? */
        if (sqlite3_prepare_v2(w->db,
                "SELECT 1 FROM v2_blocks WHERE block_id = ?1", -1, &st,
                NULL) != SQLITE_OK)
            return -1;
        sqlite3_bind_blob(st, 1, blk->block_id, 64, SQLITE_TRANSIENT);
        rc = sqlite3_step(st);
        sqlite3_finalize(st);
        if (rc == SQLITE_ROW) return -1;
        if (rc != SQLITE_DONE) return -1;

        /* height continuity + prev linkage */
        uint64_t maxh = 0;
        if (sum_q(w, "SELECT COALESCE(MAX(global_height),0) FROM v2_blocks",
                  &maxh) != 0)
            return -1;
        uint64_t rows = 0;
        if (sum_q(w, "SELECT COUNT(*) FROM v2_blocks", &rows) != 0)
            return -1;
        if (rows == 0) return -1;       /* genesis must exist first      */
        if (blk->global_height != maxh + 1) return -1;   /* gap/behind   */

        if (sqlite3_prepare_v2(w->db,
                "SELECT block_id FROM v2_blocks WHERE global_height = ?1",
                -1, &st, NULL) != SQLITE_OK)
            return -1;
        sqlite3_bind_int64(st, 1, (sqlite3_int64)maxh);
        rc = sqlite3_step(st);
        int prev_ok = (rc == SQLITE_ROW &&
                       sqlite3_column_bytes(st, 0) == 64 &&
                       memcmp(sqlite3_column_blob(st, 0),
                              blk->prev_block_id, 64) == 0);
        sqlite3_finalize(st);
        if (!prev_ok) return -1;
    }

    /* ── op classification + resource pre-scan (no mutation yet) ────── */
    dom_acc_t acc[2] = {
        { .domain_id = DNA_DOMAIN_SYSTEM },
        { .domain_id = DNA_DOMAIN_CORE }
    };
    uint8_t claim_nuls[MAX_OPS][64];
    /* duplicate tx_id in the block */
    for (size_t i = 0; i < blk->n_ops; i++)
        for (size_t j = i + 1; j < blk->n_ops; j++)
            if (memcmp(blk->ops[i].tx_id, blk->ops[j].tx_id, 64) == 0)
                return -1;

    uint64_t global_cost = 0;
    for (size_t i = 0; i < blk->n_ops; i++) {
        const nodus_v2_op_t *op = &blk->ops[i];
        if (op->touched_n == 0 || op->touched_n > DNA_TOUCHED_MAX)
            return -1;
        for (uint16_t t = 0; t < op->touched_n; t++) {
            if (t > 0 && op->touched[t - 1] >= op->touched[t]) return -1;
            dom_acc_t *a = acc_for(acc, 2, op->touched[t]);
            if (!a) return -1;          /* S5 engine: domains {0,1} only */
            a->touched = 1;
            if (a->n_tx >= MAX_OPS) return -1;
            memcpy(a->tx_ids[a->n_tx++], op->tx_id, 64);
            /* the ONE canonical cross-domain rule: cost charged to EVERY
             * touched domain */
            uint64_t nc = (uint64_t)a->res_cost + op->verify_cost;
            if (nc > UINT32_MAX) return -1;
            a->res_cost = (uint32_t)nc;
        }
        if (op->verify_cost > UINT64_MAX - global_cost) return -1;
        global_cost += op->verify_cost;
    }

    /* global caps: MAX_TXS chain-config param + the verify budget */
    {
        uint64_t cap = nodus_chain_config_get_u64(w,
            DNAC_CFG_MAX_TXS_PER_BLOCK, blk->global_height,
            DNAC_CFG_MAX_TXS_HARD_CAP);
        if (cap == 0 || cap > DNAC_CFG_MAX_TXS_HARD_CAP)
            cap = DNAC_CFG_MAX_TXS_HARD_CAP;
        if ((uint64_t)blk->n_ops > cap) return -1;
        if (global_cost > NODUS_V2_GLOBAL_VERIFY_BUDGET) return -1;
    }

    /* per-domain quotas from the ACTIVE registry manifests (0 = the
     * global cap/budget governs — enforced just above, never
     * "unlimited") */
    for (int d = 0; d < 2; d++) {
        if (!acc[d].touched) continue;
        dna_domain_manifest_t man;
        if (nodus_witness_domreg_get(w, acc[d].domain_id, NULL, &man,
                                     NULL) != 0)
            return -1;
        if (man.quota_tx_per_block != 0 &&
            acc[d].n_tx > (uint32_t)man.quota_tx_per_block)
            return -1;
        if (man.quota_verify_cost != 0 &&
            acc[d].res_cost > man.quota_verify_cost)
            return -1;
    }

    /* ── S6 claims: bounds + in-block duplicate nullifiers (pre-txn,
     * read-only). The nullifier is a pure function of the claim's
     * committed leaf context, so the duplicate scan needs no DB. ────── */
    if (blk->n_claims > 0) {
        if (!blk->claims || blk->n_claims > MAX_OPS) return -1;
        for (size_t i = 0; i < blk->n_claims; i++) {
            const dna_claim_t *c = &blk->claims[i];
            if (dna_claim_validate(c) != 0) return -1;
            if (dna_claim_nullifier(c->chain_id, c->manifest_seq,
                                    c->source_id, c->source_id_len,
                                    claim_nuls[i]) != 0)
                return -1;
            for (size_t j = 0; j < i; j++)
                if (memcmp(claim_nuls[i], claim_nuls[j], 64) == 0) {
                    QGP_LOG_ERROR(LOG_TAG,
                        "duplicate claim in one block — rejected");
                    return -1;
                }
        }
        /* A claim IS a DNA_CORE state transition (new output +
         * claims_root move) — the block declares CORE touched by
         * carrying claims at all. */
        acc[1].touched = 1;
    }

    /* pre-block heads (also the pre-state for the untouched guard) */
    dna_v2_domain_head_t head[2];
    for (int d = 0; d < 2; d++)
        if (head_load(w, acc[d].domain_id, &head[d]) != 0) return -1;

    /* ── 1. THE transaction ─────────────────────────────────────────── */
    if (exec_sql(w, "BEGIN IMMEDIATE") != 0) return -1;
    FAIL_POINT(V2AP_FAIL_AFTER_BEGIN);

    /* 2. supply gate (pre-apply) */
    if (nodus_witness_v2_supply_check(w) != 0) goto fail;

    /* 4-6. op execution in the canonical phase order */
    for (size_t i = 0; i < blk->n_ops; i++) {   /* SYSTEM-local          */
        const nodus_v2_op_t *op = &blk->ops[i];
        if (op->touched_n == 1 && op->touched[0] == DNA_DOMAIN_SYSTEM &&
            op->sql && exec_sql(w, op->sql) != 0)
            goto fail;
    }
    FAIL_POINT(V2AP_FAIL_AFTER_SYSTEM);
    for (size_t i = 0; i < blk->n_ops; i++) {   /* cross-domain          */
        const nodus_v2_op_t *op = &blk->ops[i];
        if (op->touched_n > 1 && op->sql && exec_sql(w, op->sql) != 0)
            goto fail;
    }
    FAIL_POINT(V2AP_FAIL_AFTER_CROSS);
    for (int d = 0; d < 2; d++) {               /* domain-local, id ASC  */
        for (size_t i = 0; i < blk->n_ops; i++) {
            const nodus_v2_op_t *op = &blk->ops[i];
            if (op->touched_n == 1 &&
                op->touched[0] == acc[d].domain_id &&
                acc[d].domain_id != DNA_DOMAIN_SYSTEM &&
                op->sql && exec_sql(w, op->sql) != 0)
                goto fail;
        }
        if (blk->fail_at == V2AP_FAIL_AFTER_DOMAIN_BATCH &&
            blk->fail_domain_batch == acc[d].domain_id)
            goto fail;
    }
    FAIL_POINT(V2AP_FAIL_AFTER_UTXO);

    /* 6b. S6 generic claims — DNA_CORE transitions inside THE txn.
     * Sequential processing makes intra-block accounting exact: a later
     * claim's remaining-value check sees every earlier decrement. */
    for (size_t i = 0; i < blk->n_claims; i++) {
        const dna_claim_t *c = &blk->claims[i];
        uint64_t converted = 0;
        uint8_t nul[64];
        if (nodus_witness_v2_claim_admit(w, c, blk->global_height,
                                         &converted, nul) != 0)
            goto fail;
        if (memcmp(nul, claim_nuls[i], 64) != 0) goto fail;
        if (nodus_witness_v2_claim_spend_insert(w, c, nul, converted,
                                                blk->global_height) != 0)
            goto fail;
        if (blk->fail_at == V2AP_FAIL_AFTER_CLAIM_SPEND &&
            blk->fail_claim_index == (uint32_t)i)
            goto fail;
        if (nodus_witness_v2_claim_utxo_create(w, c, nul, converted,
                                               blk->global_height) != 0)
            goto fail;
        if (blk->fail_at == V2AP_FAIL_AFTER_CLAIM_UTXO &&
            blk->fail_claim_index == (uint32_t)i)
            goto fail;
        if (nodus_witness_v2_claim_state_update(w, c->manifest_seq,
                                                converted) != 0)
            goto fail;
        if (blk->fail_at == V2AP_FAIL_AFTER_CLAIM_STATE &&
            blk->fail_claim_index == (uint32_t)i)
            goto fail;
    }

    /* 7. supply gate (post-stage) */
    if (nodus_witness_v2_supply_check(w) != 0) goto fail;
    FAIL_POINT(V2AP_FAIL_AFTER_SUPPLY_MUT);

    /* 8. domain roots + untouched-domain guard */
    uint8_t root_now[2][64];
    for (int d = 0; d < 2; d++) {
        if (domain_root_now(w, acc[d].domain_id, root_now[d]) != 0)
            goto fail;
        if (!acc[d].touched &&
            memcmp(root_now[d], head[d].domain_state_root, 64) != 0) {
            QGP_LOG_ERROR(LOG_TAG,
                "domain %u mutated without being declared touched",
                acc[d].domain_id);
            goto fail;
        }
    }
    FAIL_POINT(V2AP_FAIL_AFTER_DOMAIN_ROOTS);

    /* 9. DomainUpdates (touched only; a DECLARED no-op — post == pre —
     * rejects: no fake empty updates) */
    dna_domain_update_t upd[2];
    uint8_t upd_hash[2][64];
    size_t n_upd = 0;
    dna_domain_update_t upd_sorted[2];
    for (int d = 0; d < 2; d++) {
        if (!acc[d].touched) continue;
        if (memcmp(root_now[d], head[d].domain_state_root, 64) == 0)
            goto fail;                   /* declared but changed nothing */
        dna_domain_manifest_t man;
        if (nodus_witness_domreg_get(w, acc[d].domain_id, NULL, &man,
                                     NULL) != 0)
            goto fail;
        memset(&upd[d], 0, sizeof(upd[d]));
        upd[d].update_version = DNA_DUPD_VERSION;
        upd[d].domain_id = acc[d].domain_id;
        upd[d].old_height = head[d].domain_height;
        upd[d].new_height = head[d].domain_height + 1;
        upd[d].global_height = blk->global_height;
        memcpy(upd[d].pre_root, head[d].domain_state_root, 64);
        memcpy(upd[d].post_root, root_now[d], 64);
        if (dna_v2_tx_batch_root(acc[d].tx_ids, acc[d].n_tx,
                                 upd[d].tx_batch_root) != 0)
            goto fail;
        upd[d].ruleset_version = man.ruleset_version;
        memcpy(upd[d].ruleset_hash, man.ruleset_hash, 64);
        upd[d].res_tx_count = acc[d].n_tx;
        upd[d].res_verify_cost = acc[d].res_cost;
        if (prev_update_hash(w, acc[d].domain_id,
                             upd[d].prev_update_hash) != 0)
            goto fail;
        if (dna_dupd_hash(&upd[d], upd_hash[d]) != 0) goto fail;

        uint8_t enc[DNA_DUPD_ENC_LEN];
        if (dna_dupd_encode(&upd[d], enc) != 0) goto fail;
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(w->db,
                "INSERT INTO v2_domain_updates (global_height, domain_id, "
                "upd, upd_hash) VALUES (?1, ?2, ?3, ?4)", -1, &st, NULL)
            != SQLITE_OK)
            goto fail;
        sqlite3_bind_int64(st, 1, (sqlite3_int64)blk->global_height);
        sqlite3_bind_int64(st, 2, (sqlite3_int64)acc[d].domain_id);
        sqlite3_bind_blob(st, 3, enc, DNA_DUPD_ENC_LEN, SQLITE_TRANSIENT);
        sqlite3_bind_blob(st, 4, upd_hash[d], 64, SQLITE_TRANSIENT);
        int rc = sqlite3_step(st);
        sqlite3_finalize(st);
        if (rc != SQLITE_DONE) goto fail;
        upd_sorted[n_upd++] = upd[d];    /* d ascends ⇒ already sorted   */
    }
    FAIL_POINT(V2AP_FAIL_AFTER_UPDATES);

    /* 10. heads */
    dna_v2_domain_head_t newhead[2];
    for (int d = 0; d < 2; d++) {
        newhead[d] = head[d];
        if (acc[d].touched) {
            memcpy(newhead[d].domain_state_root, root_now[d], 64);
            newhead[d].domain_height = head[d].domain_height + 1;
            newhead[d].last_updated_global_height = blk->global_height;
            dna_domreg_record_t rec;
            if (nodus_witness_domreg_get(w, acc[d].domain_id, &rec, NULL,
                                         NULL) != 0)
                goto fail;
            newhead[d].status = rec.status;
            if (head_store(w, &newhead[d]) != 0) goto fail;
        }
    }
    FAIL_POINT(V2AP_FAIL_AFTER_HEADS);

    /* 11. root history (touched only) */
    for (int d = 0; d < 2; d++) {
        if (!acc[d].touched) continue;
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(w->db,
                "INSERT INTO v2_root_history (domain_id, domain_height, "
                "global_height, state_root, upd_hash, ruleset_version, "
                "ruleset_hash) VALUES (?1,?2,?3,?4,?5,?6,?7)", -1, &st,
                NULL) != SQLITE_OK)
            goto fail;
        sqlite3_bind_int64(st, 1, (sqlite3_int64)acc[d].domain_id);
        sqlite3_bind_int64(st, 2, (sqlite3_int64)newhead[d].domain_height);
        sqlite3_bind_int64(st, 3, (sqlite3_int64)blk->global_height);
        sqlite3_bind_blob(st, 4, newhead[d].domain_state_root, 64,
                          SQLITE_TRANSIENT);
        sqlite3_bind_blob(st, 5, upd_hash[d], 64, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 6, (sqlite3_int64)upd[d].ruleset_version);
        sqlite3_bind_blob(st, 7, upd[d].ruleset_hash, 64,
                          SQLITE_TRANSIENT);
        int rc = sqlite3_step(st);
        sqlite3_finalize(st);
        if (rc != SQLITE_DONE) goto fail;
    }
    FAIL_POINT(V2AP_FAIL_AFTER_HISTORY);

    /* 12. transaction indices (global order = the phase order above) */
    {
        uint32_t gidx = 0;
        for (int phase = 0; phase < 3 /* sys, cross, local */; phase++) {
            for (size_t i = 0; i < blk->n_ops; i++) {
                const nodus_v2_op_t *op = &blk->ops[i];
                int is_sys = (op->touched_n == 1 &&
                              op->touched[0] == DNA_DOMAIN_SYSTEM);
                int is_cross = (op->touched_n > 1);
                int in_phase = (phase == 0 && is_sys) ||
                               (phase == 1 && is_cross) ||
                               (phase == 2 && !is_sys && !is_cross);
                if (!in_phase) continue;

                uint8_t tl[2 + 4 * DNA_TOUCHED_MAX];
                size_t tw = 0;
                if (dna_touched_encode(op->touched, op->touched_n, tl,
                                       sizeof(tl), &tw) != 0)
                    goto fail;
                uint32_t owner = (op->touched_n == 1)
                                     ? op->touched[0] : DNA_TX_OWNER_NONE;
                sqlite3_stmt *st = NULL;
                if (sqlite3_prepare_v2(w->db,
                        "INSERT INTO v2_tx_index (global_height, "
                        "global_index, tx_id, owner_domain, touched, "
                        "wire_version) VALUES (?1,?2,?3,?4,?5,3)",
                        -1, &st, NULL) != SQLITE_OK)
                    goto fail;
                sqlite3_bind_int64(st, 1,
                                   (sqlite3_int64)blk->global_height);
                sqlite3_bind_int64(st, 2, (sqlite3_int64)gidx);
                sqlite3_bind_blob(st, 3, op->tx_id, 64, SQLITE_TRANSIENT);
                sqlite3_bind_int64(st, 4, (sqlite3_int64)owner);
                sqlite3_bind_blob(st, 5, tl, (int)tw, SQLITE_TRANSIENT);
                int rc = sqlite3_step(st);
                sqlite3_finalize(st);
                if (rc != SQLITE_DONE) goto fail;   /* dup tx_id, etc.  */
                gidx++;

                /* deterministic local index per touched domain */
                for (uint16_t t = 0; t < op->touched_n; t++) {
                    dom_acc_t *a = acc_for(acc, 2, op->touched[t]);
                    dna_v2_domain_head_t *nh = NULL;
                    for (int d = 0; d < 2; d++)
                        if (acc[d].domain_id == op->touched[t])
                            nh = &newhead[d];
                    if (!a || !nh) goto fail;
                    uint32_t lidx = 0;
                    for (uint32_t k = 0; k < a->n_tx; k++)
                        if (memcmp(a->tx_ids[k], op->tx_id, 64) == 0) {
                            lidx = k;
                            break;
                        }
                    sqlite3_stmt *ls = NULL;
                    if (sqlite3_prepare_v2(w->db,
                            "INSERT INTO v2_tx_local_index (tx_id, "
                            "domain_id, domain_height, local_index) "
                            "VALUES (?1,?2,?3,?4)", -1, &ls, NULL)
                        != SQLITE_OK)
                        goto fail;
                    sqlite3_bind_blob(ls, 1, op->tx_id, 64,
                                      SQLITE_TRANSIENT);
                    sqlite3_bind_int64(ls, 2,
                                       (sqlite3_int64)op->touched[t]);
                    sqlite3_bind_int64(ls, 3,
                                       (sqlite3_int64)nh->domain_height);
                    sqlite3_bind_int64(ls, 4, (sqlite3_int64)lidx);
                    rc = sqlite3_step(ls);
                    sqlite3_finalize(ls);
                    if (rc != SQLITE_DONE) goto fail;
                }
            }
        }
    }
    FAIL_POINT(V2AP_FAIL_AFTER_TX_INDEX);

    /* 13. block-level roots + expectation compare + metadata */
    {
        uint8_t all_ids[MAX_OPS][64];
        uint32_t n_all = 0;
        /* global order again (phase order) */
        for (int phase = 0; phase < 3; phase++)
            for (size_t i = 0; i < blk->n_ops; i++) {
                const nodus_v2_op_t *op = &blk->ops[i];
                int is_sys = (op->touched_n == 1 &&
                              op->touched[0] == DNA_DOMAIN_SYSTEM);
                int is_cross = (op->touched_n > 1);
                int in_phase = (phase == 0 && is_sys) ||
                               (phase == 1 && is_cross) ||
                               (phase == 2 && !is_sys && !is_cross);
                if (in_phase)
                    memcpy(all_ids[n_all++], op->tx_id, 64);
            }
        if (dna_v2_tx_batch_root(all_ids, n_all, blk->out_tx_root) != 0)
            goto fail;
        if (dna_v2_domain_updates_root(upd_sorted, n_upd,
                                       blk->out_dupd_root) != 0)
            goto fail;
        if (dna_v2_domains_root(newhead, 2, blk->out_domains_root) != 0)
            goto fail;
        if (dna_v2_global_root(blk->out_domains_root,
                               blk->out_global_root) != 0)
            goto fail;

        if (blk->expect_tx_root &&
            memcmp(blk->expect_tx_root, blk->out_tx_root, 64) != 0)
            goto fail;
        if (blk->expect_dupd_root &&
            memcmp(blk->expect_dupd_root, blk->out_dupd_root, 64) != 0)
            goto fail;
        if (blk->expect_domains_root &&
            memcmp(blk->expect_domains_root, blk->out_domains_root, 64)
                != 0)
            goto fail;
        if (blk->expect_global_root &&
            memcmp(blk->expect_global_root, blk->out_global_root, 64) != 0)
            goto fail;

        uint8_t sys_r[64], core_r[64];
        memcpy(sys_r, newhead[0].domain_state_root, 64);
        memcpy(core_r, newhead[1].domain_state_root, 64);

        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(w->db,
                "INSERT INTO v2_blocks (global_height, block_id, "
                "prev_block_id, epoch, tx_root, domain_updates_root, "
                "domains_root, system_root, core_root, global_root, "
                "vset_hash, tx_count, qc) "
                "VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,NULL)",
                -1, &st, NULL) != SQLITE_OK)
            goto fail;
        sqlite3_bind_int64(st, 1, (sqlite3_int64)blk->global_height);
        sqlite3_bind_blob(st, 2, blk->block_id, 64, SQLITE_TRANSIENT);
        sqlite3_bind_blob(st, 3, blk->prev_block_id, 64, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 4, (sqlite3_int64)blk->epoch);
        sqlite3_bind_blob(st, 5, blk->out_tx_root, 64, SQLITE_TRANSIENT);
        sqlite3_bind_blob(st, 6, blk->out_dupd_root, 64, SQLITE_TRANSIENT);
        sqlite3_bind_blob(st, 7, blk->out_domains_root, 64,
                          SQLITE_TRANSIENT);
        sqlite3_bind_blob(st, 8, sys_r, 64, SQLITE_TRANSIENT);
        sqlite3_bind_blob(st, 9, core_r, 64, SQLITE_TRANSIENT);
        sqlite3_bind_blob(st, 10, blk->out_global_root, 64,
                          SQLITE_TRANSIENT);
        sqlite3_bind_blob(st, 11, blk->vset_hash, 64, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 12, (sqlite3_int64)n_all);
        int rc = sqlite3_step(st);
        sqlite3_finalize(st);
        if (rc != SQLITE_DONE) goto fail;
    }
    FAIL_POINT(V2AP_FAIL_AFTER_BLOCK_META);

    /* 14. supply gate (pre-commit) */
    if (nodus_witness_v2_supply_check(w) != 0) goto fail;
    FAIL_POINT(V2AP_FAIL_BEFORE_COMMIT);

    /* 15. COMMIT (or the simulated commit failure) */
    if (blk->fail_at == V2AP_FAIL_COMMIT) goto fail;
    if (exec_sql(w, "COMMIT") != 0) {
        (void)exec_sql(w, "ROLLBACK");
        return -1;
    }
    if (blk->fail_at == V2AP_FAIL_AFTER_COMMIT)
        return 2;                        /* committed; pre-cache window  */
    return 0;

fail:
    (void)exec_sql(w, "ROLLBACK");
    return -1;
}
