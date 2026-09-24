/**
 * Nodus — Ledger V2 Season 6: witness-side manifest persistence, real
 * manifest_root / per-domain claims_root legs, distribution accounting,
 * generic runtime resolution, the generic claim pipeline, and the
 * NATIVE SYSTEM/CORE runtime-hook implementations (INACTIVE).
 * Contract: nodus_witness_v2_claims.h / nodus_witness_runtime.h.
 *
 * Every reader follows the fail-closed shape of
 * nodus_chain_config_compute_root: the step loop's final rc is checked
 * against SQLITE_DONE, a malformed row fails the computation, and no leg
 * is ever replaced by a sentinel. An absent S6 table is distinguished
 * from a fault via sqlite_master (the epoch_state probe pattern) — a
 * probe fault is never reported as "empty".
 *
 * @file nodus_witness_v2_claims.c
 */

#include "witness/nodus_witness_v2_claims.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_domreg.h"
#include "witness/nodus_witness_roots_v2.h"
#include "witness/nodus_witness_v2_pools.h"
#include "witness/nodus_witness_v2_gen.h"   /* the version-3 chain's
                                             * identity lives in its
                                             * stored genesis document
                                             * (nodus_witness_v2_gen.h:786) */
#include "witness/nodus_witness_cmt_store.h" /* W4-S: the genesisDoc row,
                                              * probed by the supply gate */

#include "dnac/domain_wire.h"
#include "crypto/hash/qgp_sha3.h"
#include "crypto/sign/qgp_dilithium.h"
#include "crypto/utils/qgp_log.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LOG_TAG "W_V2CLAIMS"

/* 1 = table exists, 0 = not, -1 = fault (probe fault ≠ empty). */
static int table_exists(nodus_witness_t *w, const char *name) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, name, -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc == SQLITE_ROW) return 1;
    return rc == SQLITE_DONE ? 0 : -1;
}

/* 1 = utxo_set has a domain_id column, 0 = not, -1 = fault. */
static int utxo_has_domain_col(nodus_witness_t *w) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db, "PRAGMA table_info(utxo_set)", -1, &st,
                           NULL) != SQLITE_OK)
        return -1;
    int found = 0, rc;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        const unsigned char *name = sqlite3_column_text(st, 1);
        if (name && strcmp((const char *)name, "domain_id") == 0) found = 1;
    }
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) return -1;
    return found;
}

/* ── manifest_root ──────────────────────────────────────────────────── */

int nodus_witness_manifest_root_v2(nodus_witness_t *w, uint8_t out[64]) {
    if (!w || !w->db || !out) return -1;

    int has = table_exists(w, "v2_manifests");
    if (has < 0) return -1;
    if (has == 0)                       /* pre-S6 DB: honest empty leg   */
        return dna_v2_empty_root(DNA_V2_EMPTY_MANIFEST, out);

    sqlite3_stmt *st = NULL;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT manifest_hash FROM v2_manifests "
        "ORDER BY manifest_hash ASC", -1, &st, NULL);
    if (rc != SQLITE_OK) return -1;

    size_t cap = 4, n = 0;
    uint8_t (*hashes)[64] = malloc(cap * sizeof(*hashes));
    if (!hashes) { sqlite3_finalize(st); return -1; }
    int fail = 0;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        if (n >= cap) {
            size_t nc = cap * 2;
            uint8_t (*nh)[64] = realloc(hashes, nc * sizeof(*nh));
            if (!nh) { free(hashes); sqlite3_finalize(st); return -1; }
            hashes = nh; cap = nc;
        }
        const void *h = sqlite3_column_blob(st, 0);
        if (!h || sqlite3_column_bytes(st, 0) != 64) {
            QGP_LOG_ERROR(LOG_TAG,
                          "manifest row %zu malformed — failing root", n);
            fail = 1;
            break;
        }
        memcpy(hashes[n], h, 64);
        n++;
    }
    if (!fail && rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "manifest scan aborted mid-stream (rc=%d) "
                      "— failing root", rc);
        fail = 1;
    }
    sqlite3_finalize(st);

    int ret = -1;
    if (!fail)
        ret = dna_v2_manifest_root(hashes, n, out);
    free(hashes);
    return ret;
}

/* ── claims_root (per target domain — the runtime owns its claims) ──── */

int nodus_witness_claims_root_v2(nodus_witness_t *w, uint32_t domain_id,
                                 uint8_t out[64]) {
    if (!w || !w->db || !out) return -1;

    int has = table_exists(w, "v2_claims_spent");
    if (has < 0) return -1;
    if (has == 0)                       /* pre-S6 DB: honest empty leg   */
        return dna_v2_empty_root(DNA_V2_EMPTY_CLAIMS, out);

    sqlite3_stmt *st = NULL;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT nullifier, manifest_hash, leaf_index, amount, "
        "claimed_height FROM v2_claims_spent "
        "WHERE target_domain_id = ?1 ORDER BY nullifier ASC",
        -1, &st, NULL);
    if (rc != SQLITE_OK) return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)domain_id);

    size_t cap = 4, n = 0;
    dna_claims_entry_t *entries = malloc(cap * sizeof(*entries));
    if (!entries) { sqlite3_finalize(st); return -1; }
    int fail = 0;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        if (n >= cap) {
            size_t nc = cap * 2;
            dna_claims_entry_t *ne = realloc(entries, nc * sizeof(*ne));
            if (!ne) { free(entries); sqlite3_finalize(st); return -1; }
            entries = ne; cap = nc;
        }
        const void *nul = sqlite3_column_blob(st, 0);
        const void *mh  = sqlite3_column_blob(st, 1);
        sqlite3_int64 idx = sqlite3_column_int64(st, 2);
        sqlite3_int64 amt = sqlite3_column_int64(st, 3);
        sqlite3_int64 hgt = sqlite3_column_int64(st, 4);
        if (!nul || sqlite3_column_bytes(st, 0) != 64 ||
            !mh || sqlite3_column_bytes(st, 1) != 64 ||
            idx < 0 || amt < 1 || hgt < 0) {
            QGP_LOG_ERROR(LOG_TAG,
                          "claim row %zu malformed — failing root", n);
            fail = 1;
            break;
        }
        memcpy(entries[n].nullifier, nul, 64);
        memcpy(entries[n].manifest_hash, mh, 64);
        entries[n].target_domain_id = domain_id;
        entries[n].leaf_index = (uint64_t)idx;
        entries[n].amount = (uint64_t)amt;
        entries[n].claimed_height = (uint64_t)hgt;
        n++;
    }
    if (!fail && rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "claims scan aborted mid-stream (rc=%d) — "
                      "failing root", rc);
        fail = 1;
    }
    sqlite3_finalize(st);

    int ret = -1;
    if (!fail)
        ret = dna_claims_root(entries, n, out);
    free(entries);
    return ret;
}

/* ── chain id ───────────────────────────────────────────────────────── */

int nodus_witness_v2_chain_id(nodus_witness_t *w,
                              uint8_t out[DNA_CHAIN_ID_LEN]) {
    if (!w || !w->db || !out) return -1;
    /* ── THE CHAIN'S IDENTITY IS ITS STORED GENESIS DOCUMENT ──────────
     *
     * D-19 rev 6 withdrew the genesis block, so the cometbft genesis
     * writes no `v2_blocks` row of any height
     * (nodus_witness_v2_genesis_cmt, nodus_witness_v2_apply.h) and the
     * chain's identity is the hash of its stored genesis DOCUMENT
     * (D-18 rev 4). `nodus_witness_v2_gen_stored_chain_id` reads exactly
     * that, from `cmt_state`'s "genesisDoc" row. Every consumer of this
     * function — the batch preflight (nodus_witness_v2_env.c), claim
     * admission (below), the apply engine's block-start snapshot — reads
     * the one identity.
     *
     * tokenomics-v3 P4 (OBLIGATION atlas-dec-71525f3b): the branch that
     * answered from a committed HEIGHT-0 v2_blocks row
     * (dna_bh2_derive_chain_id over the version-2 genesis BlockID) is
     * deleted with the version-2 genesis that wrote that row
     * (nodus_witness_v2_genesis_ex) — nothing writes one any more.
     *
     * An absent document is a failure: a chain with no stored genesis
     * document has no identity to bind anything to. */
    return nodus_witness_v2_gen_stored_chain_id(w, out);
}

/* ── generic runtime resolution (registry → tuple → compiled table) ─── */

int nodus_witness_v2_runtime_for(nodus_witness_t *w, uint32_t domain_id,
                                 int require_active,
                                 const nodus_domain_runtime_t **out) {
    if (!w || !out) return -1;
    *out = NULL;

    dna_domreg_record_t rec;
    dna_domain_manifest_t man;
    if (nodus_witness_domreg_get(w, domain_id, &rec, &man, NULL) != 0)
        return -1;                      /* unknown domain OR fault       */
    if (require_active && rec.status != DNA_DOMST_ACTIVE)
        return -1;                      /* inactive target fails closed  */

    const nodus_domain_runtime_t *table = w->v2_runtime_table;
    size_t n = w->v2_runtime_table_n;
    if (!table)
        table = nodus_runtime_builtin_table(&n);

    const nodus_domain_runtime_t *rt = nodus_runtime_lookup_in(
        table, n, domain_id, man.runtime_kind, man.runtime_abi,
        man.ruleset_version, man.ruleset_hash);
    if (!rt) return -1;                 /* tuple not carried — fail-close */
    *out = rt;
    return 0;
}

/* ── manifest persistence ───────────────────────────────────────────── */

int nodus_witness_v2_manifest_commit(nodus_witness_t *w,
                                     const uint8_t *bytes, size_t len,
                                     uint32_t manifest_seq,
                                     uint64_t committed_height) {
    if (!w || !w->db || !bytes || len == 0) return -1;

    dna_gman_t m;
    if (dna_gman_decode(bytes, len, &m) != 0) return -1;

    /* The committed domain set must EXACTLY match the domain registry. */
    {
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(w->db,
                "SELECT COUNT(*) FROM domain_registry", -1, &st, NULL)
            != SQLITE_OK)
            return -1;
        int rc = sqlite3_step(st);
        sqlite3_int64 cnt = (rc == SQLITE_ROW)
                                ? sqlite3_column_int64(st, 0) : -1;
        sqlite3_finalize(st);
        if (cnt < 0 || (uint64_t)cnt != (uint64_t)m.domain_count) {
            QGP_LOG_ERROR(LOG_TAG, "manifest domain count %u != registry "
                          "count %lld", m.domain_count, (long long)cnt);
            return -1;
        }
    }
    for (uint16_t i = 0; i < m.domain_count; i++) {
        dna_domain_manifest_t dm;
        if (nodus_witness_domreg_get(w, m.domains[i].domain_id, NULL,
                                     &dm, NULL) != 0)
            return -1;
        uint8_t h[64];
        if (dna_domman_hash(&dm, h) != 0) return -1;
        if (memcmp(h, m.domains[i].manifest_hash, 64) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "manifest domain %u hash mismatch "
                          "against registry", m.domains[i].domain_id);
            return -1;
        }
    }

    /* Genesis-supply cross-check (three-valued read honored). */
    {
        nodus_witness_supply_t sup;
        memset(&sup, 0, sizeof(sup));
        int rc = nodus_witness_supply_get(w, &sup);
        if (rc < 0) return -1;          /* DB error is never a value     */
        if (m.genesis_supply_raw != sup.genesis_supply) {
            QGP_LOG_ERROR(LOG_TAG, "manifest genesis supply %llu != "
                          "supply_tracking %llu",
                          (unsigned long long)m.genesis_supply_raw,
                          (unsigned long long)sup.genesis_supply);
            return -1;
        }
    }

    /* Distribution target: explicit, registered, ACTIVE, runtime-backed,
     * asset accepted by the TARGET runtime. The generic layer never
     * assumes a target — every leg fails closed. */
    if (m.dist_present == 1) {
        int in_set = 0;
        for (uint16_t i = 0; i < m.domain_count; i++)
            if (m.domains[i].domain_id == m.target_domain_id) in_set = 1;
        if (!in_set) {
            QGP_LOG_ERROR(LOG_TAG, "distribution target domain %u not in "
                          "the manifest domain set", m.target_domain_id);
            return -1;
        }
        const nodus_domain_runtime_t *rt = NULL;
        if (nodus_witness_v2_runtime_for(w, m.target_domain_id, 1, &rt)
            != 0) {
            QGP_LOG_ERROR(LOG_TAG, "distribution target domain %u has no "
                          "resolvable ACTIVE runtime", m.target_domain_id);
            return -1;
        }
        if (!rt->asset_check || !rt->claim_apply) {
            QGP_LOG_ERROR(LOG_TAG, "target runtime %u cannot accept "
                          "distribution claims", m.target_domain_id);
            return -1;
        }
        if (rt->asset_check(rt, m.target_asset_ref, m.target_asset_len)
            != 0) {
            QGP_LOG_ERROR(LOG_TAG, "target runtime %u rejected the "
                          "committed asset reference", m.target_domain_id);
            return -1;
        }
    }

    uint8_t mh[64];
    if (dna_gman_hash(&m, mh) != 0) return -1;

    /* Duplicate identity rejects via the UNIQUE manifest_hash (and the
     * PK on the internal locator). */
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "INSERT INTO v2_manifests (manifest_seq, manifest_hash, "
            "manifest, committed_height) VALUES (?1, ?2, ?3, ?4)",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)manifest_seq);
    sqlite3_bind_blob(st, 2, mh, 64, SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 3, bytes, (int)len, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 4, (sqlite3_int64)committed_height);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) return -1;

    if (m.dist_present == 1) {
        if (sqlite3_prepare_v2(w->db,
                "INSERT INTO v2_dist_state (manifest_hash, "
                "target_domain_id, target_asset_ref, remaining) "
                "VALUES (?1, ?2, ?3, ?4)", -1, &st, NULL) != SQLITE_OK)
            return -1;
        sqlite3_bind_blob(st, 1, mh, 64, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 2, (sqlite3_int64)m.target_domain_id);
        sqlite3_bind_blob(st, 3, m.target_asset_ref, m.target_asset_len,
                          SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 4, (sqlite3_int64)m.total_claimable);
        rc = sqlite3_step(st);
        sqlite3_finalize(st);
        if (rc != SQLITE_DONE) return -1;
    }
    return 0;
}

static int manifest_row_decode(sqlite3_stmt *st, dna_gman_t *out) {
    const void *bytes = sqlite3_column_blob(st, 0);
    int blen = sqlite3_column_bytes(st, 0);
    const void *sh = sqlite3_column_blob(st, 1);
    if (bytes && blen > 0 && sh && sqlite3_column_bytes(st, 1) == 64 &&
        dna_gman_decode(bytes, (size_t)blen, out) == 0) {
        uint8_t h[64];
        if (dna_gman_hash(out, h) == 0 && memcmp(h, sh, 64) == 0)
            return 0;                    /* stored bytes re-hash verified */
    }
    return -1;
}

int nodus_witness_v2_manifest_load(nodus_witness_t *w,
                                   uint32_t manifest_seq,
                                   dna_gman_t *out) {
    if (!w || !w->db || !out) return -1;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT manifest, manifest_hash FROM v2_manifests "
            "WHERE manifest_seq = ?1", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)manifest_seq);
    int rc = sqlite3_step(st);
    if (rc == SQLITE_DONE) { sqlite3_finalize(st); return 1; }
    int ret = (rc == SQLITE_ROW) ? manifest_row_decode(st, out) : -1;
    sqlite3_finalize(st);
    return ret;
}

int nodus_witness_v2_manifest_load_by_hash(nodus_witness_t *w,
                                           const uint8_t hash[64],
                                           dna_gman_t *out) {
    if (!w || !w->db || !hash || !out) return -1;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT manifest, manifest_hash FROM v2_manifests "
            "WHERE manifest_hash = ?1", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_blob(st, 1, hash, 64, SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);
    if (rc == SQLITE_DONE) { sqlite3_finalize(st); return 1; }
    int ret = (rc == SQLITE_ROW) ? manifest_row_decode(st, out) : -1;
    sqlite3_finalize(st);
    return ret;
}

/* ── unclaimed-distribution total (per target domain + asset) ───────── */

int nodus_witness_v2_unclaimed_total(nodus_witness_t *w,
                                     uint32_t target_domain_id,
                                     const uint8_t *target_asset_ref,
                                     uint16_t target_asset_len,
                                     uint64_t *out) {
    if (!w || !w->db || !target_asset_ref || target_asset_len == 0 ||
        !out)
        return -1;

    int has = table_exists(w, "v2_dist_state");
    if (has < 0) return -1;
    if (has == 0) { *out = 0; return 0; }   /* honest pre-S6 zero        */

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT remaining FROM v2_dist_state "
            "WHERE target_domain_id = ?1 AND target_asset_ref = ?2 "
            "ORDER BY manifest_hash", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)target_domain_id);
    sqlite3_bind_blob(st, 2, target_asset_ref, target_asset_len,
                      SQLITE_TRANSIENT);
    uint64_t sum = 0;
    int rc;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        sqlite3_int64 v = sqlite3_column_int64(st, 0);
        if (v < 0) { sqlite3_finalize(st); return -1; }
        if ((uint64_t)v > UINT64_MAX - sum) {       /* checked add       */
            sqlite3_finalize(st);
            return -1;
        }
        sum += (uint64_t)v;
    }
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) return -1;   /* mid-scan fault ≠ a value      */
    *out = sum;
    return 0;
}

/* ── spent-claim lookup — O15K V-3 ──────────────────────────────────── */

/* THE ONE place `v2_claims_spent` is asked "does this nullifier have a
 * row?". It used to be open-coded inside the admission verifier below and
 * nowhere else, which is exactly how V-3 happened: a claim's commit wrote
 * THIS table (nodus_witness_v2_claim_spend_insert) while every "is this
 * pooled entry decided?" question walked the LEGACY `nullifiers` table,
 * whose only writer is the legacy commit path a successor commit
 * bypasses. Two writers, two readers, no overlap — so a committed claim
 * read as live demand forever and drove a view change every T against a
 * healthy leader. One helper, two callers, no drift; the same argument
 * that keeps bft_p3_entry_finished in one place.
 *
 * ⚠ TRI-STATE, AND IT MUST STAY ONE. Do NOT "simplify" this to a bool.
 * The same fact serves two questions whose SAFE answers point in OPPOSITE
 * directions, so the mapping of a fault cannot live here — it belongs to
 * each caller:
 *
 *   caller                              question              maps -1 to
 *   ─────────────────────────────────── ───────────────────── ──────────
 *   admission (nodus_witness_v2_claim_  "may I ADMIT this?"   SPENT →
 *   admit, step 9)                                            reject
 *   reaper (nodus_witness_mempool_      "may I DELETE this?"  NOT SPENT
 *   evict_committed, nodus_witness.c)                         → keep
 *
 * A bool return would silently hand ONE of those two the dangerous
 * direction: either admitting a possible double-spend, or deleting a
 * client's pending work with no error anywhere.
 *
 * Deterministic and node-local: the answer is a function of the nullifier
 * bytes and this node's committed state — no clock, no message, no
 * iteration order.
 *
 * @return 1 spent (a row exists) / 0 not spent (no row) / -1 FAULT (the
 *         query could not be prepared or stepped — this node does not
 *         know; absence of the table is a fault, never "not spent").
 */
int nodus_witness_v2_claim_nullifier_spent(nodus_witness_t *w,
                                           const uint8_t nullifier[64]) {
    if (!w || !w->db || !nullifier) return -1;

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT 1 FROM v2_claims_spent WHERE nullifier = ?1",
            -1, &st, NULL) != SQLITE_OK)
        return -1;                          /* absent/corrupt table = fault */
    sqlite3_bind_blob(st, 1, nullifier, 64, SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);

    if (rc == SQLITE_ROW)  return 1;
    if (rc == SQLITE_DONE) return 0;
    return -1;                              /* mid-step fault ≠ a value     */
}

/* ── claim pipeline ─────────────────────────────────────────────────── */

int nodus_witness_v2_claim_admit(nodus_witness_t *w,
                                 const dna_claim_t *c,
                                 uint64_t global_height,
                                 nodus_v2_claim_admit_t *out) {
    /* Cannot even attempt a determination: -2, never -1 (a caller-
     * contract violation is not a fact about the claim). */
    if (!w || !w->db || !c || !out) return -2;
    memset(out, 0, sizeof(*out));

    /* 1. structural validation — pure function of the claim's own
     * bytes; every honest node reaches the SAME answer. VERDICT. */
    if (dna_claim_validate(c) != 0) return -1;

    /* 2. chain binding: reading THIS node's own chain id is a local DB
     * read (NODE-LOCAL, "chain id unreadable"); once known, comparing it
     * to the claim's is a deterministic VERDICT. */
    uint8_t chain_id[DNA_CHAIN_ID_LEN];
    if (nodus_witness_v2_chain_id(w, chain_id) != 0) return -2;
    if (memcmp(chain_id, c->chain_id, DNA_CHAIN_ID_LEN) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "claim chain_id mismatch — cross-chain "
                      "replay rejected");
        return -1;
    }

    /* 3. committed manifest BY HASH (the committed identity).
     * nodus_witness_v2_manifest_load_by_hash's OWN contract already
     * splits this: 0 found, 1 absent (deterministic — the claim names a
     * manifest this chain never committed, every honest node agrees),
     * -1 fault (a local prepare/step error, or a stored row that no
     * longer re-hashes to its own claimed identity — local corruption,
     * never a network-wide fact). */
    dna_gman_t m;
    int mrc = nodus_witness_v2_manifest_load_by_hash(w, c->manifest_hash,
                                                     &m);
    if (mrc < 0) return -2;             /* NODE-LOCAL: read/corruption   */
    if (mrc > 0) return -1;             /* VERDICT: not committed here   */
    if (m.dist_present != 1) return -1; /* no distribution to claim from */
    if (c->auth_mode != m.auth_mode) return -1;

    /* 4. height window (early and late both reject; v1 post-deadline
     *    policy RETAIN: nothing but the reject happens) */
    if (global_height < m.claim_start_height ||
        global_height > m.claim_end_height)
        return -1;

    /* 5. leaf membership */
    if (c->leaf_index >= m.leaf_count) return -1;
    dna_dist_leaf_t leaf;
    memset(&leaf, 0, sizeof(leaf));
    leaf.leaf_version = DNA_DIST_VERSION;
    leaf.source_id_len = c->source_id_len;
    memcpy(leaf.source_id, c->source_id, c->source_id_len);
    leaf.source_amount = c->source_amount;
    memcpy(leaf.dest_binding, c->dest_binding, 64);
    uint8_t leaf_hash[64];
    /* SHA3 backend: a total function of already-validated bytes — a
     * nonzero return here is an environment/allocation fault, never a
     * data-dependent answer. NODE-LOCAL. */
    if (dna_dist_leaf_hash(&leaf, leaf_hash) != 0) return -2;
    if (dna_dist_proof_verify(m.snapshot_root, leaf_hash, c->leaf_index,
                              m.leaf_count, c->siblings,
                              c->n_siblings) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "claim Merkle proof invalid");
        return -1;
    }

    /* 6. converted amount from COMMITTED parameters only */
    uint64_t converted = 0;
    if (dna_dist_converted(c->source_amount, m.conv_numerator,
                           m.conv_denominator, m.rounding_mode,
                           &converted) != 0)
        return -1;

    /* 7. DNA-native authorization (the only v1 mode; anything else was
     *    already rejected by validate + the manifest match above) */
    {
        uint8_t pk_hash[64];
        /* SHA3 backend — NODE-LOCAL, same reasoning as the leaf hash
         * above. */
        if (qgp_sha3_512(c->pubkey, DNA_CLAIM_PUBKEY_LEN, pk_hash) != 0)
            return -2;
        if (memcmp(pk_hash, c->dest_binding, 64) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "claim key does not bind to the "
                          "leaf destination — substitution rejected");
            return -1;
        }
        uint8_t pre[DNA_CLAIM_PREIMAGE_MAX];
        size_t pre_len = 0;
        /* dna_claim_preimage fails only on NULL arguments or on a claim
         * dna_claim_validate refuses (shared/dnac/manifest_wire.c) — and
         * step 1 already passed validate on this very claim. Reaching
         * this branch is a broken invariant, never a fact about the
         * claim: -2 under the header contract (TV3-P0, verifier N6). */
        if (dna_claim_preimage(c, pre, &pre_len) != 0) return -2;
        if (qgp_dsa87_verify(c->signature, DNA_CLAIM_SIG_LEN,
                             pre, pre_len, c->pubkey) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "claim signature invalid");
            return -1;
        }
    }

    /* 8. TARGET runtime: registered, ACTIVE, locally compiled, claim
     *    hooks present, committed asset accepted. The generic engine
     *    NEVER picks a domain — the committed manifest names it.
     *    nodus_witness_v2_runtime_for conflates THREE things under one
     *    -1 — an unknown/inactive registry entry (deterministic registry
     *    state) OR a local registry read fault OR this build's compiled
     *    runtime table lacking the exact tuple (deterministic ACROSS a
     *    consistent fleet, but indistinguishable here from the read
     *    fault it shares a return code with). Per the DB-failure-is-
     *    never-a-value rule, a conflated code that MAY be a local fault
     *    is never asserted as a VERDICT: NODE-LOCAL, -2. */
    const nodus_domain_runtime_t *rt = NULL;
    if (nodus_witness_v2_runtime_for(w, m.target_domain_id, 1, &rt) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "claim target domain %u has no resolvable "
                      "ACTIVE runtime (runtime table resolution fault, "
                      "possibly conflated with a local read — honest "
                      "label) — refusing to vote", m.target_domain_id);
        return -2;
    }
    /* Both of the following are properties of THIS BUILD's compiled
     * runtime table for a target that manifest_commit already verified
     * to be hook-backed and asset-accepting at commit time — the same
     * class as the resolution miss above, so the same code: NODE-LOCAL
     * / broken invariant, -2, never a claim verdict (TV3-P0, verifier
     * N6; header contract in nodus_witness_v2_claims.h). */
    if (!rt->asset_check || !rt->claim_apply) return -2;
    if (rt->asset_check(rt, m.target_asset_ref, m.target_asset_len) != 0)
        return -2;

    /* 9. nullifier from the COMMITTED context — already spent rejects.
     * Derivation is a SHA3 backend call: NODE-LOCAL on failure. */
    uint8_t nul[64];
    if (dna_claim_nullifier(c->chain_id, c->manifest_hash,
                            m.target_domain_id, m.target_asset_ref,
                            m.target_asset_len, leaf_hash, nul) != 0)
        return -2;
    /* O15K V-3's tri-state (1 spent / 0 not spent / -1 FAULT) is now
     * mapped to the finer tri-state THIS function returns: spent is a
     * VERDICT every honest node with the same committed set reaches
     * (-1); a read fault is NODE-LOCAL (-2) — TV3-P0 item 2 replaces the
     * old "FAULT maps to SPENT" collapse the comment used to describe,
     * which hid a local read fault inside an ordinary claim refusal. */
    {
        int nsp = nodus_witness_v2_claim_nullifier_spent(w, nul);
        if (nsp < 0) return -2;   /* NODE-LOCAL: spent-set read fault    */
        if (nsp > 0) return -1;   /* VERDICT: already claimed            */
    }

    /* 10. the distribution must cover it — a claim can never mint.
     * The row's ABSENCE here is itself an invariant break (step 3 above
     * already required `m.dist_present == 1`, and manifest_commit seeds
     * this table whenever that holds), so — like a genuine sqlite
     * prepare/step fault or a negative stored value — it is NODE-LOCAL,
     * never a verdict about this claim. Only the remaining-cover
     * COMPARISON itself, once the row is known good, is the
     * deterministic VERDICT. */
    {
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(w->db,
                "SELECT remaining FROM v2_dist_state "
                "WHERE manifest_hash = ?1", -1, &st, NULL) != SQLITE_OK)
            return -2;
        sqlite3_bind_blob(st, 1, c->manifest_hash, 64, SQLITE_TRANSIENT);
        int rc = sqlite3_step(st);
        sqlite3_int64 rem = (rc == SQLITE_ROW)
                                ? sqlite3_column_int64(st, 0) : -1;
        sqlite3_finalize(st);
        if (rc != SQLITE_ROW || rem < 0) return -2;
        if ((uint64_t)rem < converted) {
            QGP_LOG_ERROR(LOG_TAG, "claim exceeds remaining distribution "
                          "value — rejected (never mints)");
            return -1;
        }
    }

    out->converted = converted;
    memcpy(out->nullifier, nul, 64);
    memcpy(out->manifest_hash, c->manifest_hash, 64);
    out->target_domain_id = m.target_domain_id;
    out->target_asset_len = m.target_asset_len;
    memcpy(out->target_asset_ref, m.target_asset_ref, m.target_asset_len);
    out->rt = rt;
    return 0;
}

int nodus_witness_v2_claim_output_create(nodus_witness_t *w,
                                         const dna_claim_t *c,
                                         const nodus_v2_claim_admit_t *a,
                                         uint64_t global_height,
                                         uint8_t out_output_id[64]) {
    /* EXECUTE stage: ADMIT already settled the verdict for this claim,
     * so every failure here — a broken precondition ADMIT was supposed
     * to guarantee, or the runtime hook's own storage/backend fault — is
     * NODE-LOCAL. -2, never -1 (header contract, TV3-P0 item 2). */
    if (!w || !w->db || !c || !a || !a->rt || !a->rt->claim_apply ||
        !out_output_id || a->converted == 0)
        return -2;
    nodus_rt_claim_t rc_ctx;
    memset(&rc_ctx, 0, sizeof(rc_ctx));
    rc_ctx.nullifier = a->nullifier;
    rc_ctx.dest_binding = c->dest_binding;
    rc_ctx.amount = a->converted;
    rc_ctx.asset_ref = a->target_asset_ref;
    rc_ctx.asset_ref_len = a->target_asset_len;
    rc_ctx.global_height = global_height;
    return a->rt->claim_apply(a->rt, w, &rc_ctx, out_output_id) == 0
               ? 0 : -2;
}

int nodus_witness_v2_claim_spend_insert(nodus_witness_t *w,
                                        const dna_claim_t *c,
                                        const nodus_v2_claim_admit_t *a,
                                        const uint8_t output_id[64],
                                        uint64_t global_height) {
    /* EXECUTE stage — see the header contract: -2, never -1. */
    if (!w || !w->db || !c || !a || !output_id || a->converted == 0)
        return -2;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "INSERT INTO v2_claims_spent (nullifier, manifest_hash, "
            "target_domain_id, target_asset_ref, leaf_index, amount, "
            "claimed_height, output_id) "
            "VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)", -1, &st, NULL)
        != SQLITE_OK)
        return -2;
    sqlite3_bind_blob(st, 1, a->nullifier, 64, SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 2, a->manifest_hash, 64, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 3, (sqlite3_int64)a->target_domain_id);
    sqlite3_bind_blob(st, 4, a->target_asset_ref, a->target_asset_len,
                      SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 5, (sqlite3_int64)c->leaf_index);
    sqlite3_bind_int64(st, 6, (sqlite3_int64)a->converted);
    sqlite3_bind_int64(st, 7, (sqlite3_int64)global_height);
    sqlite3_bind_blob(st, 8, output_id, 64, SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    /* A PK collision here means the in-block duplicate-nullifier check
     * upstream was bypassed — a broken invariant, not a fact about this
     * claim (the comment used to read "dup nullifier = PK constraint"
     * as if that were an ordinary rejection path). */
    return rc == SQLITE_DONE ? 0 : -2;
}

int nodus_witness_v2_claim_state_update(nodus_witness_t *w,
                                        const uint8_t manifest_hash[64],
                                        uint64_t converted) {
    /* EXECUTE stage — see the header contract: -2, never -1. */
    if (!w || !w->db || !manifest_hash || converted == 0) return -2;

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT remaining FROM v2_dist_state WHERE manifest_hash = ?1",
            -1, &st, NULL) != SQLITE_OK)
        return -2;
    sqlite3_bind_blob(st, 1, manifest_hash, 64, SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);
    sqlite3_int64 rem = (rc == SQLITE_ROW) ? sqlite3_column_int64(st, 0)
                                           : -1;
    sqlite3_finalize(st);
    if (rc != SQLITE_ROW || rem < 0) return -2;
    /* ADMIT's own step 10 already verified `rem >= converted` moments
     * earlier in this SAME sequential apply (no other claim's write can
     * have run in between) — reaching underflow here is a broken
     * invariant, not a new fact. */
    if ((uint64_t)rem < converted) return -2;

    if (sqlite3_prepare_v2(w->db,
            "UPDATE v2_dist_state SET remaining = ?1 "
            "WHERE manifest_hash = ?2", -1, &st, NULL) != SQLITE_OK)
        return -2;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)((uint64_t)rem - converted));
    sqlite3_bind_blob(st, 2, manifest_hash, 64, SQLITE_TRANSIENT);
    rc = sqlite3_step(st);
    int changed = sqlite3_changes(w->db);
    sqlite3_finalize(st);
    return (rc == SQLITE_DONE && changed == 1) ? 0 : -2;
}

/* ═════════════════════════════════════════════════════════════════════
 * NATIVE runtime-hook implementations (nodus_witness_runtime.h table).
 *
 * These are the ONLY places that know the concrete SYSTEM/CORE state
 * composition. The generic executor dispatches through the hook table;
 * it holds no per-domain branch. Allowed concrete behavior: SYSTEM is
 * the mandatory protocol domain; the native DNA_CORE runtime implements
 * UTXO / token / DNAC supply rules inside its own module.
 * ═══════════════════════════════════════════════════════════════════ */

int nodus_rt_system_state_root(const nodus_domain_runtime_t *rt,
                               struct nodus_witness *w, uint8_t out[64]) {
    (void)rt;
    return nodus_witness_system_root_v2((nodus_witness_t *)w, out);
}

/* The activation payload root — the S5 genesis cycle break: SYSTEM's
 * registry-committed genesis_state_root is this payload composition
 * (no registry/manifest container legs), never the full state root. */
int nodus_rt_system_payload_root(const nodus_domain_runtime_t *rt,
                                 struct nodus_witness *w, uint8_t out[64]) {
    (void)rt;
    return nodus_witness_system_payload_root_v2((nodus_witness_t *)w, out);
}

int nodus_rt_core_state_root(const nodus_domain_runtime_t *rt,
                             struct nodus_witness *w, uint8_t out[64]) {
    (void)rt;
    return nodus_witness_core_root_v2((nodus_witness_t *)w, out);
}

/* The CORE asset namespace IS the existing 64-byte token_id namespace.
 * v1 accepts ONLY the native DNAC id (64 zero bytes): a non-native
 * token distribution is a FUTURE versioned mode — fail-closed today. */
int nodus_rt_core_asset_check(const nodus_domain_runtime_t *rt,
                              const uint8_t *asset_ref, uint16_t len) {
    (void)rt;
    if (!asset_ref || len != 64) return -1;
    for (uint16_t i = 0; i < len; i++)
        if (asset_ref[i] != 0) return -1;
    return 0;
}

int nodus_rt_core_claim_apply(const nodus_domain_runtime_t *rt,
                              struct nodus_witness *wv,
                              const nodus_rt_claim_t *claim,
                              uint8_t out_output_id[64]) {
    nodus_witness_t *w = (nodus_witness_t *)wv;
    if (!rt || !w || !w->db || !claim || !claim->nullifier ||
        !claim->dest_binding || !out_output_id || claim->amount == 0)
        return -1;
    /* the runtime re-validates ITS asset — never trusts the caller */
    if (nodus_rt_core_asset_check(rt, claim->asset_ref,
                                  claim->asset_ref_len) != 0)
        return -1;

    uint8_t utxo_id[64];
    if (dna_claim_utxo_id(claim->nullifier, utxo_id) != 0) return -1;

    /* owner = the 128-char lowercase-hex form of dest_binding — the
     * existing DNA fingerprint discipline (wallet.c: exactly 128
     * lowercase hex chars). */
    char owner[129];
    static const char hexd[] = "0123456789abcdef";
    for (int i = 0; i < 64; i++) {
        owner[i * 2]     = hexd[claim->dest_binding[i] >> 4];
        owner[i * 2 + 1] = hexd[claim->dest_binding[i] & 0x0f];
    }
    owner[128] = '\0';

    /* STRICT insert (the stock helper's INSERT OR IGNORE would silently
     * swallow a duplicate output). created_at is pinned to 0: a claim
     * output is a deterministic consensus artifact — a wall-clock byte
     * here would be node-divergent state. domain_id is written
     * EXPLICITLY by this runtime for ITS OWN domain — no schema default
     * exists. */
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "INSERT INTO utxo_set (nullifier, owner, amount, token_id, "
            "tx_hash, output_index, block_height, created_at, "
            "unlock_block, domain_id) "
            "VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6, 0, 0, ?7)",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    static const uint8_t native_token[64] = {0};
    sqlite3_bind_blob(st, 1, utxo_id, 64, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, owner, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 3, (sqlite3_int64)claim->amount);
    sqlite3_bind_blob(st, 4, native_token, 64, SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 5, claim->nullifier, 64, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 6, (sqlite3_int64)claim->global_height);
    sqlite3_bind_int64(st, 7, (sqlite3_int64)rt->domain_id);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) return -1;
    memcpy(out_output_id, utxo_id, 64);
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

/**
 * The DNAC conservation invariant — owned by the CORE runtime (DNAC is
 * CORE's native asset; this equation is NOT a universal rule for other
 * domains, and the generic gate never applies it to them):
 *
 *   genesis + minted − burned ==
 *       Σ utxo (native, CORE-owned) + Σ self_stake + Σ delegated
 *     + reward_pool + Σ accrued (tokenomics-v3 P2 — the reserve plus
 *       every fee, and the per-recipient accrual; the O15J Σ epoch_pool
 *       term is gone with the per-block mint)
 *     + unclaimed CORE-native distribution
 *     + Σ balance of THIS domain's pools configured for the native
 *       asset (S7 — real committed pool balances; the previous
 *       "shielded ≡ 0, no pool table may exist" placeholder is
 *       replaced. Foreign-ASSET pools of this domain and every
 *       foreign-DOMAIN pool are excluded: their value is another
 *       asset's/runtime's conservation, never summed here. Pool
 *       commitments and nullifiers do not themselves move supply;
 *       admission is still C3-rejected, so live pool balances remain
 *       zero until then.)
 *
 * Foreign-domain rows in utxo_set FAIL the invariant (fail-closed): the
 * v1 UTXO table is this runtime's domain-local state; another runtime's
 * value must live in its own namespace, never silently summed here.
 */
#ifdef NODUS_V2_TEST_SUPPLY
/* Definition and setter exist ONLY in the two test binaries that
 * compile this TU with NODUS_V2_TEST_SUPPLY. See the block inside
 * nodus_rt_core_invariant below for the full rationale, and
 * test_v2_supply_linked for the `nm` proof of absence. */
static int g_v2_supply_test_bypass = 0;

void nodus_witness_v2_supply_test_bypass(int on) {
    g_v2_supply_test_bypass = on ? 1 : 0;
}
#endif

int nodus_rt_core_invariant(const nodus_domain_runtime_t *rt,
                            struct nodus_witness *wv) {
    nodus_witness_t *w = (nodus_witness_t *)wv;
    if (!rt || !w || !w->db) return -1;

    /* Ownership guard: every utxo_set row must belong to THIS domain
     * (when the domain column exists — a pre-S5 DB is all-CORE by the
     * legacy definition). A foreign row is unknown value: fail closed,
     * never sum it. */
    {
        int has = utxo_has_domain_col(w);
        if (has < 0) return -1;
        if (has == 1) {
            char sql[128];
            snprintf(sql, sizeof(sql),
                     "SELECT COUNT(*) FROM utxo_set WHERE domain_id != %u",
                     rt->domain_id);
            uint64_t foreign = 0;
            if (sum_q(w, sql, &foreign) != 0) return -1;
            if (foreign != 0) {
                QGP_LOG_ERROR(LOG_TAG, "CORE INVARIANT: %llu utxo rows "
                              "owned by a foreign domain — rejecting",
                              (unsigned long long)foreign);
                return -1;
            }
        }
    }

#ifdef NODUS_V2_TEST_SUPPLY
    /* ── O15J — TEST-ONLY conservation bypass ─────────────────────────
     * Engine-level tests (test_v2_apply, test_v2_exec — R2-F5 corrected
     * the count; test_v2_claims never arms it and was dropped back to a
     * plain registration) exercise the apply engine's EFFECT PLUMBING
     * with synthetic
     * envelopes that create value from nothing (env_core_utxo_create).
     * No genesis seeding can balance that — conjured value is exactly
     * what the conservation equation exists to forbid — so those tests
     * cannot run against a live invariant, and before L2-F1 they only
     * passed because an absent supply_tracking row SKIPPED the equation
     * outright. That escape hatch was also the CRITICAL production hole.
     *
     * This replaces it with one that CANNOT EXIST IN PRODUCTION: the
     * flag and its setter are compiled only when NODUS_V2_TEST_SUPPLY is
     * defined, which happens for those two test targets and nowhere
     * else. libnodus is STATIC and this TU is compiled INTO each of
     * those binaries, so the definition exists in no shipped artefact —
     * the same arrangement, and the same reasoning, as the
     * NODUS_V2_TEST_AUTHORITY gate fixture (CMakeLists.txt:882-906).
     * test_v2_supply_linked proves the absence with `nm` rather than
     * arguing it from this comment.
     *
     * Process-global rather than per-handle: these tests are
     * single-threaded and drive one chain at a time. A per-handle flag
     * would need a field in the PRODUCTION struct, which is strictly
     * weaker — this way production has no flag to set. */
    if (g_v2_supply_test_bypass) return 0;
#endif

    nodus_witness_supply_t sup;
    memset(&sup, 0, sizeof(sup));
    int sup_rc = nodus_witness_supply_get(w, &sup);
    if (sup_rc < 0) return -1;           /* DB error is never a value     */
    if (sup_rc == 1) {
        /* ── O15J L2-F1 (CRITICAL) ────────────────────────────────────
         * An absent supply_tracking row used to be an unconditional
         * `return 0` — the whole conservation invariant SKIPPED, not
         * failed, for the LIFE of the chain. Nothing else catches it
         * either: the manifest cross-check reads the same absent row as
         * 0 and compares it to a manifest genesis_supply of 0, so a
         * chain born without the row passes both gates permanently
         * (nodus_witness_v2_claims.c manifest_commit, the
         * "Genesis-supply cross-check" block above).
         *
         * "Pre-genesis" is only honest BEFORE a genesis exists. Once a
         * V2 genesis is committed, the row's absence is not an empty
         * state — it is a broken one, and the only safe answer is to
         * fail closed.
         *
         * R3-W4-S (D-17 rev 11 (11)): a version-3 (cometbft) chain NEVER
         * writes a height-0 v2_blocks row — its genesis is a STORED
         * DOCUMENT in cmt_state under NODUS_V2_GEN_GENESIS_DOC_KEY
         * ("genesisDoc", D-18), and that document is the probe.
         * tokenomics-v3 P4: the height-0-row probe that decided for the
         * version-2 genesis (nodus_witness_v2_genesis_ex) is deleted with
         * it — nothing writes that row any more.
         *
         * Deliberately SCOPED so the legitimate pre-genesis `return 0` is
         * not weakened:
         *   - no v2_blocks table at all  → never had a V2 genesis → 0
         *   - no cmt_state table (below S14) → genuinely pre-genesis → 0
         *   - cmt_state present but no stored genesisDoc → the
         *     ceremony's own scratch database before the document is
         *     written → 0 (still honest pre-genesis)
         *   - a stored genesisDoc present → a genesis EXISTS → -1
         *   - any probe fault      → -1, never a value (the probe-fault
         *     discipline this file's header states). */
        int has_v2 = table_exists(w, "v2_blocks");
        if (has_v2 < 0) return -1;
        if (has_v2 == 0) return 0;       /* honest pre-genesis            */

        int genesis_exists = 0;
        {
            /* Probe the Comet stores (D-19 rev 6) for a stored genesis
             * document before declaring pre-genesis. */
            int has_cmt = table_exists(w, "cmt_state");
            if (has_cmt < 0) return -1;
            if (has_cmt == 1) {
                nodus_cmt_store_t s;
                if (nodus_cmt_store_init(&s, w->db, false) != CMT_OK)
                    return -1;
                const uint8_t *val = NULL;
                size_t vlen = 0;
                int doc_rc = nodus_cmt_store_get(&s, /*state_table=*/true,
                        NODUS_V2_GEN_GENESIS_DOC_KEY, &val, &vlen);
                /* vlen == 0 (or no value): S14 tables exist, no document
                 * stored yet — the ceremony's own scratch database:
                 * still honest pre-genesis. val && vlen > 0: a
                 * version-3 genesis IS stored. Evaluated BEFORE the
                 * release: `val` points into the store's own copy
                 * buffer and is indeterminate once the store is
                 * released (nodus_witness_cmt_store.h:495-497). */
                int doc_present = (doc_rc == CMT_OK && val != NULL &&
                                   vlen > 0);
                nodus_cmt_store_release(&s);
                if (doc_rc != CMT_OK) return -1;
                genesis_exists = doc_present;
            }
            /* has_cmt == 0: below S14, no Comet stores at all — still
             * honest pre-genesis, genesis_exists stays false. */
        }
        if (!genesis_exists) return 0;   /* pre-genesis, still honest */

        QGP_LOG_ERROR(LOG_TAG, "%s",
            "CORE INVARIANT: supply_tracking row is ABSENT on a chain "
            "that has a committed V2 genesis — the conservation "
            "invariant cannot be evaluated, refusing (fail closed)");
        return -1;
    }

    uint64_t expected = sup.genesis_supply;
    if (sup.total_minted > UINT64_MAX - expected) return -1;
    expected += sup.total_minted;
    if (sup.total_burned > expected) return -1;   /* underflow            */
    expected -= sup.total_burned;

    /* tokenomics-v3 P2 (design §7 P2-2): the equation is
     *   genesis + minted − burned
     *     == utxo + bonds + delegated + reward_pool + accrued
     *        + unclaimed + shielded
     * The O15J `epoch_state.epoch_pool_accum` term is GONE with the
     * per-block mint that filled it (nothing writes epoch_state any
     * more), and total_minted is never written (decision §1 "Yeni token
     * basılmayacak") — it stays in the LHS as a term that is always 0.
     * The reward pool (supply_tracking.reward_pool, read with the row
     * above) holds the undistributed reserve plus every fee; `accrued`
     * (Σ v2_reward_accrual.amount) holds what the distribution credited
     * and the payday has not yet paid. The two move value between each
     * other and utxo_set only, so the equation closes at every step. */
    uint64_t utxo = 0, bonds = 0, delegated = 0, accrued = 0, unclaimed = 0;
    const uint64_t pool = sup.reward_pool;
    /* the production helper OWNS the native-token representation rule —
     * one authority, never a parallel SQL mirror */
    if (nodus_witness_utxo_sum_by_token(w, NULL, &utxo) != 0) return -1;
    if (sum_q(w, "SELECT COALESCE(SUM(self_stake),0) FROM validators",
              &bonds) != 0) return -1;
    if (sum_q(w, "SELECT COALESCE(SUM(total_delegated),0) FROM validators",
              &delegated) != 0) return -1;
    if (sum_q(w, "SELECT COALESCE(SUM(amount),0) FROM v2_reward_accrual",
              &accrued) != 0) return -1;
    /* Unclaimed distribution value TARGETING THIS RUNTIME'S NATIVE
     * ASSET only — a distribution targeting another domain/asset is
     * that runtime's invariant, never summed here. */
    static const uint8_t native_token[64] = {0};
    if (nodus_witness_v2_unclaimed_total(w, rt->domain_id, native_token,
                                         64, &unclaimed) != 0)
        return -1;

    /* S7: the REAL committed pool bucket — Σ balance over THIS domain's
     * pools configured for the native asset (checked add inside; absent
     * v2_pools table = honest pre-S7 zero; DB fault = -1, never a
     * value). */
    uint64_t shielded = 0;
    if (nodus_witness_v2_pool_balance_total(w, rt->domain_id,
                                            native_token, 64,
                                            &shielded) != 0)
        return -1;

    uint64_t observed = utxo;
    if (bonds > UINT64_MAX - observed) return -1;
    observed += bonds;
    if (delegated > UINT64_MAX - observed) return -1;
    observed += delegated;
    if (pool > UINT64_MAX - observed) return -1;
    observed += pool;
    if (accrued > UINT64_MAX - observed) return -1;
    observed += accrued;
    if (unclaimed > UINT64_MAX - observed) return -1;
    observed += unclaimed;
    if (shielded > UINT64_MAX - observed) return -1;
    observed += shielded;

    if (expected != observed) {
        QGP_LOG_ERROR(LOG_TAG,
            "CORE INVARIANT VIOLATION: expected=%llu observed=%llu "
            "(utxo=%llu bonds=%llu delegated=%llu reward_pool=%llu "
            "accrued=%llu unclaimed=%llu shielded=%llu)",
            (unsigned long long)expected, (unsigned long long)observed,
            (unsigned long long)utxo, (unsigned long long)bonds,
            (unsigned long long)delegated, (unsigned long long)pool,
            (unsigned long long)accrued, (unsigned long long)unclaimed,
            (unsigned long long)shielded);
        return -1;
    }
    return 0;
}
