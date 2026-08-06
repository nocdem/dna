/**
 * Nodus — Ledger V2 Season 2: witness-side V2 root loaders (INACTIVE).
 *
 * See nodus_witness_roots_v2.h. Every reader follows the fail-closed
 * shape of nodus_chain_config_compute_root: the step loop's final rc is
 * checked against SQLITE_DONE, a malformed row fails the computation,
 * and no leg is ever replaced by a sentinel.
 *
 * @file nodus_witness_roots_v2.c
 */

#include "witness/nodus_witness_roots_v2.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_merkle.h"
#include "witness/nodus_witness_vset.h"
#include "witness/nodus_witness_domreg.h"
#include "witness/nodus_witness_v2_claims.h"
#include "witness/nodus_witness_v2_pools.h"
#include "nodus/nodus_chain_config.h"
#include "crypto/utils/qgp_log.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LOG_TAG "ROOTS-V2"

/* ── token_root ─────────────────────────────────────────────────────── */

int nodus_witness_token_root_v2(nodus_witness_t *w, uint8_t out[64]) {
    if (!w || !w->db || !out) return -1;

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT token_id, name, symbol, decimals, supply, creator_fp, "
        "flags, block_height FROM tokens ORDER BY token_id ASC",
        -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "token scan prepare failed: %s",
                      sqlite3_errmsg(w->db));
        return -1;
    }

    size_t cap = 4, n = 0;
    dna_v2_token_leaf_t *leaves = calloc(cap, sizeof(*leaves));
    char **owned = calloc(cap * 3, sizeof(char *)); /* name/symbol/fp per row */
    if (!leaves || !owned) {
        free(leaves); free(owned); sqlite3_finalize(stmt);
        return -1;
    }
    int fail = 0;

    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (n >= cap) {
            size_t nc = cap * 2;
            dna_v2_token_leaf_t *nl = realloc(leaves, nc * sizeof(*nl));
            if (nl) leaves = nl;
            char **no = nl ? realloc(owned, nc * 3 * sizeof(char *)) : NULL;
            if (no) owned = no;
            if (!nl || !no) {
                /* OOM: free every strdup'd string before the containers
                 * (leak found by the S2 isolation verifier). */
                for (size_t i = 0; i < n * 3; i++) free(owned[i]);
                free(owned);
                free(leaves);
                sqlite3_finalize(stmt);
                return -1;
            }
            memset(owned + cap * 3, 0, (nc - cap) * 3 * sizeof(char *));
            cap = nc;
        }
        const void *tid = sqlite3_column_blob(stmt, 0);
        int tid_len     = sqlite3_column_bytes(stmt, 0);
        const unsigned char *name   = sqlite3_column_text(stmt, 1);
        const unsigned char *symbol = sqlite3_column_text(stmt, 2);
        const unsigned char *cfp    = sqlite3_column_text(stmt, 5);
        if (!tid || tid_len != DNA_V2_TOKEN_ID_LEN ||
            !name || !symbol || !cfp) {
            /* Malformed row = corruption: FAIL the root, never skip. */
            QGP_LOG_ERROR(LOG_TAG, "token row %zu malformed — failing root", n);
            fail = 1;
            break;
        }
        dna_v2_token_leaf_t *L = &leaves[n];
        memcpy(L->token_id, tid, DNA_V2_TOKEN_ID_LEN);
        owned[n * 3 + 0] = strdup((const char *)name);
        owned[n * 3 + 1] = strdup((const char *)symbol);
        owned[n * 3 + 2] = strdup((const char *)cfp);
        if (!owned[n * 3] || !owned[n * 3 + 1] || !owned[n * 3 + 2]) {
            fail = 1;
            n++;             /* count the row so its strings get freed */
            break;
        }
        L->name           = owned[n * 3 + 0];
        L->name_len       = strlen(L->name);
        L->symbol         = owned[n * 3 + 1];
        L->symbol_len     = strlen(L->symbol);
        L->creator_fp     = owned[n * 3 + 2];
        L->creator_fp_len = strlen(L->creator_fp);
        /* Range-check before the u8 narrowing: an out-of-range column is
         * corruption and FAILS the root (S2 verifier finding — silent
         * truncation would hash a value the row does not hold). */
        int dec = sqlite3_column_int(stmt, 3);
        int flg = sqlite3_column_int(stmt, 6);
        if (dec < 0 || dec > 255 || flg < 0 || flg > 255) {
            QGP_LOG_ERROR(LOG_TAG, "token row %zu out-of-range "
                          "decimals/flags — failing root", n);
            fail = 1;
            n++;             /* count the row so its strings get freed */
            break;
        }
        L->decimals     = (uint8_t)dec;
        L->supply       = (uint64_t)sqlite3_column_int64(stmt, 4);
        L->flags        = (uint8_t)flg;
        L->block_height = (uint64_t)sqlite3_column_int64(stmt, 7);
        n++;
    }
    /* Fail-close: a mid-scan error must not truncate to a "valid" root. */
    if (!fail && rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "token scan aborted mid-stream (rc=%d) — "
                      "failing root", rc);
        fail = 1;
    }
    sqlite3_finalize(stmt);

    int ret = -1;
    if (!fail)
        ret = dna_v2_token_root(leaves, n, out);
    for (size_t i = 0; i < n; i++) {
        free(owned[i * 3 + 0]);
        free(owned[i * 3 + 1]);
        free(owned[i * 3 + 2]);
    }
    free(owned);
    free(leaves);
    return ret;
}

/* ── epoch_state_root_v2 (supply counters relocated out) ────────────── */

int nodus_witness_epoch_root_v2(nodus_witness_t *w, uint8_t out[64]) {
    if (!w || !w->db || !out) return -1;

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT epoch_start_height, epoch_pool_accum, snapshot_hash "
        "FROM epoch_state ORDER BY epoch_start_height ASC",
        -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        /* The epoch_state table is created lazily; on a fresh DB the
         * prepare fails with "no such table" — that is the honest EMPTY
         * state (pre-genesis), not a fault. Distinguish it via
         * sqlite_master — and FAIL CLOSED if the probe itself errors
         * (S2 verifier finding: a probe fault must never be reported as
         * pre-genesis; "a DB failure is never a value"). */
        sqlite3_stmt *chk = NULL;
        if (sqlite3_prepare_v2(w->db,
                "SELECT 1 FROM sqlite_master WHERE type='table' "
                "AND name='epoch_state'", -1, &chk, NULL) != SQLITE_OK) {
            QGP_LOG_ERROR(LOG_TAG, "epoch table probe failed: %s",
                          sqlite3_errmsg(w->db));
            return -1;                       /* probe fault ≠ empty */
        }
        int step = sqlite3_step(chk);
        sqlite3_finalize(chk);
        if (step == SQLITE_DONE)             /* table genuinely absent */
            return dna_v2_empty_root(DNA_V2_EMPTY_EPOCH_V2, out);
        if (step != SQLITE_ROW) {
            QGP_LOG_ERROR(LOG_TAG, "epoch table probe step failed (rc=%d)",
                          step);
            return -1;                       /* probe fault ≠ empty */
        }
        /* Table exists but the scan prepare failed: real error. */
        QGP_LOG_ERROR(LOG_TAG, "epoch scan prepare failed: %s",
                      sqlite3_errmsg(w->db));
        return -1;
    }

    size_t cap = 4, n = 0;
    uint64_t *starts = malloc(cap * sizeof(uint64_t));
    uint8_t (*hashes)[64] = malloc(cap * sizeof(*hashes));
    if (!starts || !hashes) {
        free(starts); free(hashes); sqlite3_finalize(stmt);
        return -1;
    }
    int fail = 0;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (n >= cap) {
            size_t nc = cap * 2;
            uint64_t *ns = realloc(starts, nc * sizeof(uint64_t));
            uint8_t (*nh)[64] = realloc(hashes, nc * sizeof(*nh));
            if (!ns || !nh) {
                free(ns ? ns : starts);
                free(nh ? nh : hashes);
                sqlite3_finalize(stmt);
                return -1;
            }
            starts = ns; hashes = nh; cap = nc;
        }
        const void *snap = sqlite3_column_blob(stmt, 2);
        int snap_len     = sqlite3_column_bytes(stmt, 2);
        if (!snap || snap_len != 64) {
            /* Always written full-length (nodus_witness_epoch.c) — a NULL
             * or short blob is corruption. FAIL, never substitute. */
            QGP_LOG_ERROR(LOG_TAG, "epoch row %zu snapshot malformed — "
                          "failing root", n);
            fail = 1;
            break;
        }
        starts[n] = (uint64_t)sqlite3_column_int64(stmt, 0);
        if (dna_v2_epoch_leaf_hash(starts[n],
                                   (uint64_t)sqlite3_column_int64(stmt, 1),
                                   (const uint8_t *)snap, hashes[n]) != 0) {
            fail = 1;
            break;
        }
        n++;
    }
    if (!fail && rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "epoch scan aborted mid-stream (rc=%d) — "
                      "failing root", rc);
        fail = 1;
    }
    sqlite3_finalize(stmt);

    int ret = -1;
    if (!fail)
        ret = dna_v2_epoch_root(starts, hashes, n, out);
    free(starts);
    free(hashes);
    return ret;
}

/* ── supply_root ────────────────────────────────────────────────────── */

int nodus_witness_supply_root_v2(nodus_witness_t *w, uint8_t out[64]) {
    if (!w || !out) return -1;
    nodus_witness_supply_t sup;
    memset(&sup, 0, sizeof(sup));
    int rc = nodus_witness_supply_get(w, &sup);
    if (rc < 0) {
        /* Three-valued read (D1): a DB error is NOT pre-genesis. */
        QGP_LOG_ERROR(LOG_TAG, "supply_get DB error — failing supply_root");
        return -1;
    }
    /* rc == 1: row genuinely absent (pre-genesis) — zeros are the honest
     * values; `sup` is already zeroed. */
    return dna_v2_supply_root(sup.genesis_supply, sup.total_minted,
                              sup.total_burned, out);
}

/* ── Composition ────────────────────────────────────────────────────── */

int nodus_witness_system_payload_root_v2(nodus_witness_t *w,
                                         uint8_t out[64]) {
    if (!w || !out) return -1;
    uint8_t validator_root[64], delegation_root[64], epoch_v2[64];
    uint8_t chain_config_root[64], vset[64];
    if (nodus_witness_merkle_compute_validator_root(w, validator_root) != 0)
        return -1;
    if (nodus_witness_merkle_compute_delegation_root(w, delegation_root) != 0)
        return -1;
    if (nodus_witness_epoch_root_v2(w, epoch_v2) != 0)
        return -1;
    if (nodus_chain_config_compute_root(w, chain_config_root) != 0)
        return -1;
    if (nodus_witness_vset_root(w, vset) != 0)
        return -1;
    return dna_v2_system_payload_root(validator_root, delegation_root,
                                      epoch_v2, chain_config_root, vset,
                                      out);
}

int nodus_witness_system_root_v2(nodus_witness_t *w, uint8_t out[64]) {
    if (!w || !out) return -1;
    uint8_t validator_root[64], delegation_root[64], epoch_v2[64];
    uint8_t chain_config_root[64], vset[64], domreg[64], manifest[64];
    if (nodus_witness_merkle_compute_validator_root(w, validator_root) != 0)
        return -1;
    if (nodus_witness_merkle_compute_delegation_root(w, delegation_root) != 0)
        return -1;
    if (nodus_witness_epoch_root_v2(w, epoch_v2) != 0)
        return -1;
    if (nodus_chain_config_compute_root(w, chain_config_root) != 0)
        return -1;
    /* S3: the real validator-set leg. An EMPTY validator_set_snapshots
     * table yields the SAME tagged empty root the S2 placeholder emitted
     * (nodus_witness_vset_root → dna_v2_vset_root n==0 → DNA_V2_EMPTY_VSET),
     * so a pre-snapshot chain's system_state_root is byte-unchanged. */
    if (nodus_witness_vset_root(w, vset) != 0)
        return -1;
    /* S4: the domain-registry leg is REAL — nodus_witness_domreg_root
     * over the domain_registry table. An empty table (every pre-V2 chain)
     * returns exactly the DNA_V2_EMPTY_DOMREG tagged root the S2
     * placeholder returned, so this root is byte-unchanged for every
     * pre-registry chain. */
    if (nodus_witness_domreg_root(w, domreg) != 0)
        return -1;
    /* S6: the manifest leg is REAL — nodus_witness_manifest_root_v2
     * over the v2_manifests table. An absent (pre-S6) or empty table
     * returns exactly the DNA_V2_EMPTY_MANIFEST tagged root the S2
     * placeholder returned, so this root is byte-unchanged for every
     * pre-manifest chain. */
    if (nodus_witness_manifest_root_v2(w, manifest) != 0)
        return -1;
    /* GENERICITY CORRECTION (locked): the native supply_root is NOT a
     * SYSTEM leg — issuance belongs to the DNA_CORE runtime and is
     * committed by ITS state root below. */
    return dna_v2_system_root(validator_root, delegation_root, epoch_v2,
                              chain_config_root, vset, domreg, manifest,
                              out);
}

int nodus_witness_core_root_v2(nodus_witness_t *w, uint8_t out[64]) {
    if (!w || !out) return -1;
    uint8_t utxo_root[64], token_root[64], pools[64], claims[64], names[64];
    uint8_t supply[64];
    if (nodus_witness_merkle_compute_utxo_root(w, utxo_root) != 0)
        return -1;
    if (nodus_witness_token_root_v2(w, token_root) != 0)
        return -1;
    /* S7: the pools leg is REAL — nodus_witness_pools_root_v2 over the
     * v2_pools rows OWNED BY THIS DOMAIN (each runtime commits the pool
     * state of its own domain; a foreign domain's pool can never enter
     * this root). An absent table (pre-S7 DB) or a zero-pool domain
     * reproduces the frozen S2 tagged-empty root byte-identically. */
    if (nodus_witness_pools_root_v2(w, DNA_DOMAIN_CORE, pools) != 0)
        return -1;
    /* S6: the claims leg is REAL — nodus_witness_claims_root_v2 over
     * the v2_claims_spent rows TARGETING THIS DOMAIN (each runtime owns
     * the claims commitment of its own domain — this is the CORE
     * runtime's root, so it covers CORE-targeted claims only).
     * Absent/empty tables reproduce the S2 tagged-empty root
     * byte-identically (pre-S6 chains unchanged). */
    if (nodus_witness_claims_root_v2(w, DNA_DOMAIN_CORE, claims) != 0)
        return -1;
    if (dna_v2_empty_root(DNA_V2_EMPTY_NAMES, names) != 0)
        return -1;
    /* Native issuance (genesis/minted/burned) is the CORE runtime's OWN
     * asset commitment — the supply leg lives HERE (locked ownership). */
    if (nodus_witness_supply_root_v2(w, supply) != 0)
        return -1;
    return dna_v2_core_root(utxo_root, token_root, pools, claims, names,
                            supply, out);
}

/* Decode the 89-byte canonical head blob (layout: ledger_roots_v2.h). */
static void head_blob_decode(const uint8_t enc[DNA_V2_DOMHEAD_ENC_LEN],
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

int nodus_witness_global_root_v2(nodus_witness_t *w,
                                 uint8_t out_global[64],
                                 uint8_t out_domains[64],
                                 uint8_t out_system[64],
                                 uint8_t out_core[64]) {
    if (!w || !out_global) return -1;
    uint8_t sys[64], core[64], domains[64];
    if (nodus_witness_system_root_v2(w, sys) != 0) return -1;
    if (nodus_witness_core_root_v2(w, core) != 0) return -1;

    /* When S5 head persistence exists (v2_domain_heads with rows), the
     * COMMITTED heads are the authority — ANY registered domain count,
     * never a fixed two. The pre-S5 fixture composition below survives
     * only for head-less databases (byte-identical to the frozen S2
     * KATs). Probe fault ≠ empty: fail closed. */
    int have_heads = 0;
    {
        sqlite3_stmt *chk = NULL;
        if (sqlite3_prepare_v2(w->db,
                "SELECT 1 FROM sqlite_master WHERE type='table' AND "
                "name='v2_domain_heads'", -1, &chk, NULL) != SQLITE_OK)
            return -1;
        int rc = sqlite3_step(chk);
        sqlite3_finalize(chk);
        if (rc == SQLITE_ROW) {
            sqlite3_stmt *cnt = NULL;
            if (sqlite3_prepare_v2(w->db,
                    "SELECT COUNT(*) FROM v2_domain_heads", -1, &cnt,
                    NULL) != SQLITE_OK)
                return -1;
            rc = sqlite3_step(cnt);
            if (rc != SQLITE_ROW) { sqlite3_finalize(cnt); return -1; }
            have_heads = sqlite3_column_int64(cnt, 0) > 0;
            sqlite3_finalize(cnt);
        } else if (rc != SQLITE_DONE) {
            return -1;
        }
    }

    if (have_heads) {
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(w->db,
                "SELECT head FROM v2_domain_heads ORDER BY domain_id ASC",
                -1, &st, NULL) != SQLITE_OK)
            return -1;
        size_t cap = 4, n = 0;
        dna_v2_domain_head_t *heads = malloc(cap * sizeof(*heads));
        if (!heads) { sqlite3_finalize(st); return -1; }
        int rc, fail = 0;
        while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
            if (n >= cap) {
                size_t nc = cap * 2;
                dna_v2_domain_head_t *nh =
                    realloc(heads, nc * sizeof(*nh));
                if (!nh) { free(heads); sqlite3_finalize(st); return -1; }
                heads = nh; cap = nc;
            }
            if (sqlite3_column_bytes(st, 0) != DNA_V2_DOMHEAD_ENC_LEN) {
                fail = 1;
                break;
            }
            head_blob_decode(sqlite3_column_blob(st, 0), &heads[n]);
            n++;
        }
        if (!fail && rc != SQLITE_DONE) fail = 1;
        sqlite3_finalize(st);
        int ret = -1;
        if (!fail && dna_v2_domains_root(heads, n, domains) == 0 &&
            dna_v2_global_root(domains, out_global) == 0)
            ret = 0;
        free(heads);
        if (ret != 0) return -1;
    } else {
        /* Pre-S5 fixture composition (frozen S2 KAT behavior). */
        dna_v2_domain_head_t heads[2];
        memset(heads, 0, sizeof(heads));
        heads[0].domain_id = DNA_DOMAIN_SYSTEM;
        memcpy(heads[0].domain_state_root, sys, 64);
        heads[0].ruleset_version = 1;
        heads[1].domain_id = DNA_DOMAIN_CORE;
        memcpy(heads[1].domain_state_root, core, 64);
        heads[1].ruleset_version = 1;
        if (dna_v2_domains_root(heads, 2, domains) != 0) return -1;
        if (dna_v2_global_root(domains, out_global) != 0) return -1;
    }

    if (out_domains) memcpy(out_domains, domains, 64);
    if (out_system)  memcpy(out_system, sys, 64);
    if (out_core)    memcpy(out_core, core, 64);
    return 0;
}
