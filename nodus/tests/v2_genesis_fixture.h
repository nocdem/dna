/**
 * @file nodus/tests/v2_genesis_fixture.h
 * @brief Ledger V2 — version-3 genesis fixtures + the cometbft-lane host
 *        for tests.
 *
 * This header exists separately from v2_exec_fixture.h because the tests
 * that need genesis are not the same set as the tests that need the
 * scripted execution runtimes, and pulling the whole exec fixture into
 * them would collide with their own local helpers.
 *
 * tokenomics-v3 P4 (second half): the version-2 engine genesis
 * (nodus_witness_v2_genesis_ex) and the legacy block lane are DELETED
 * (OBLIGATION atlas-dec-71525f3b), and with them this header's
 * version-2 fixture (v2x_genesis_min, v2x_seed_authority[_fill],
 * v2x_block_id_at). What lives here now:
 *   v2x_db_digest — the canonical whole-database oracle.
 *   TIER A, v2x_chain_open & co. — a REAL version-3 chain: the
 *     ceremony's derivation + the production open path. For tests that
 *     need no genesis rows of their own.
 *   TIER B, v2x_seed_prepare / v2x_seed_rows / v2x_seed_genesis — a
 *     SEEDED version-3 genesis: the derivation's own steps (pre-genesis
 *     S16 database, v2_successor, the econ band, the committee and its
 *     snapshots, the registry, nodus_witness_v2_genesis_cmt, the stored
 *     document, the production reopen) around rows the TEST writes —
 *     genesis states a version-3 config cannot express (sub-10M or zero
 *     stakes, other than 7 validators, genesis UTXOs / delegations,
 *     reward reserves). Every such row is written BEFORE the genesis is
 *     committed; after it, nothing may touch a root leg except a block.
 *     It ends with the derivation's own ledger post-conditions
 *     (v2x_seed_postconditions); a test whose genesis is deliberately
 *     not a real one names each departure (V2X_SEED_NOT_REAL_*).
 *   THE HOST, v2x_cmt_apply & co. — every block through the engine's
 *     one production lane (`blk->cmt.on`): BEGIN IMMEDIATE, the Comet
 *     block-store record, the engine, COMMIT on 0 / ROLLBACK on a FAULT,
 *     with the per-item verdict helpers (v2x_cmt_apply_ok,
 *     v2x_cmt_refused[_probe], v2x_cmt_fault, v2x_cmt_injected).
 *
 * HOW IT CAN LIE — where a green here is not a green on a real node:
 *   TIER B genesis
 *   - It is not the ceremony: no allocation document, no derive_v3
 *     plan. A TEST-SEEDED committee has no document plan, so the
 *     "bonds == plan" post-condition is checked only when the committee
 *     IS the document's (v2x_seed_rows wrote it).
 *   - The default manifest (v2x_seed_manifest) commits NO claim
 *     distribution; derive_v3 always commits one. The reserve check
 *     then only proves "no distribution, no v2_dist_state row".
 *   - The opt-outs (V2X_SEED_NOT_REAL_*: spendable genesis UTXOs,
 *     non-ACTIVE rows with active_count over the bonded statuses, a
 *     malformed row) are states derive_v3 refuses; a test carrying one
 *     proves nothing about a chain a ceremony produced.
 *   - Genesis delegations and a non-zero reward pool (test_v2_econ,
 *     the delegation-cap bench) are rows derive_v3 never writes and no
 *     post-condition names.
 *   THE HOST
 *   - The block-store record (v2x_cmt_store_block: a real
 *     cmt_state_make_block block, its hash and part set) is written
 *     INSIDE the block's own transaction, where a node has it in the
 *     Comet store before FinalizeBlock runs; its Data is EMPTY — the
 *     envelopes the engine applies are handed in beside it, never
 *     decoded from it. A height the store refuses is handed a
 *     (chain, height)-derived identity instead (v2x_cmt_probe_ids).
 *   - One process-global results array (v2x_res) serves every block
 *     that brings none; two live blocks must not share it.
 *   - No updateState, no ValidatorUpdates diff and no Commit/app-hash
 *     round trip: the engine's rc and per-item codes are the whole
 *     observation.
 *   - Under NODUS_V2_TEST_SUPPLY (test_v2_apply, test_v2_exec) the
 *     seeded genesis re-arms the conservation bypass on success;
 *     v2x_seed_genesis disarms it for its own gate and post-conditions,
 *     but every block after it runs with the equation OFF until the
 *     test disarms it again.
 *
 * Copyright (c) 2026 nocdem — SPDX-License-Identifier: MIT
 */

#ifndef NODUS_TESTS_V2_GENESIS_FIXTURE_H
#define NODUS_TESTS_V2_GENESIS_FIXTURE_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>

#include "crypto/hash/qgp_sha3.h"

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"   /* O15J L2-F1 — supply_init */
#include "witness/nodus_witness_v2_claims.h" /* O15J — test supply bypass */
#include "witness/nodus_witness_domreg.h"
#include "witness/nodus_witness_v2_apply.h"
#include "witness/nodus_witness_vset.h"
#include "witness/nodus_witness_validator.h"
#include "witness/nodus_witness_v2_epoch.h"
#include "dnac/vset_wire.h"
#include "dnac/domain_wire.h"
#include "dnac/manifest_wire.h"
#include "dnac/ledger_ids.h"


/* ── O14 §13: canonical LOGICAL whole-database digest ────────────────
 * Source-locked from the shipped helper (test_v2_apply.c:171) and
 * EXTENDED in one respect: that version filters `name NOT LIKE
 * 'sqlite_%'`, which drops **sqlite_sequence** — the AUTOINCREMENT
 * counter table. Those counters are exactly the kind of "sequence or
 * counter that affects deterministic replay" a side-effect oracle must
 * cover: the legacy `blocks` table is AUTOINCREMENT, so a rolled-back
 * insert that nonetheless advanced the counter would be invisible to a
 * digest that skips it.
 *
 * Covers every user table in sqlite_master (block metadata, v2_blocks,
 * domain heads/updates/history, validators, snapshots, epoch state,
 * staking/delegation, chain config, utxo_set, supply, pools, claims,
 * tx/intent indices) plus sqlite_sequence, each row ordered, each
 * column's storage type and bytes hashed. NOT a raw file hash — the
 * SQLite file image is not a deterministic representation of logical
 * state (free-page layout and vacuum state move without it). */
static int v2x_db_digest(nodus_witness_t *w, uint8_t out[64]) {
    if (!w || !w->db || !out) return -1;
    sqlite3_stmt *ts = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT name FROM sqlite_master WHERE type='table' "
            "  AND name NOT LIKE 'sqlite_%' "
            "UNION ALL "
            "SELECT name FROM sqlite_master WHERE type='table' "
            "  AND name = 'sqlite_sequence' "
            "ORDER BY 1", -1, &ts, NULL) != SQLITE_OK)
        return -1;

    uint8_t *buf = NULL;
    size_t len = 0, cap = 0;
    int rc, ret = -1;
#define V2XD_PUT(p, n) do {                                              \
        if (len + (n) > cap) {                                           \
            size_t nc = (cap ? cap * 2 : 4096);                          \
            while (nc < len + (n)) nc *= 2;                              \
            uint8_t *nb = (uint8_t *)realloc(buf, nc);                   \
            if (!nb) goto done;                                          \
            buf = nb; cap = nc;                                          \
        }                                                                \
        memcpy(buf + len, (p), (n)); len += (n);                         \
    } while (0)

    while ((rc = sqlite3_step(ts)) == SQLITE_ROW) {
        const char *name = (const char *)sqlite3_column_text(ts, 0);
        if (!name) goto done;
        V2XD_PUT(name, strlen(name) + 1);
        char sql[256];
        snprintf(sql, sizeof(sql), "SELECT * FROM \"%s\" ORDER BY rowid",
                 name);
        sqlite3_stmt *rs = NULL;
        if (sqlite3_prepare_v2(w->db, sql, -1, &rs, NULL) != SQLITE_OK)
            goto done;
        int rrc;
        while ((rrc = sqlite3_step(rs)) == SQLITE_ROW) {
            int nc = sqlite3_column_count(rs);
            for (int c = 0; c < nc; c++) {
                uint8_t t = (uint8_t)sqlite3_column_type(rs, c);
                V2XD_PUT(&t, 1);
                if (t == SQLITE_NULL) continue;
                const void *b = sqlite3_column_blob(rs, c);
                int bl = sqlite3_column_bytes(rs, c);
                uint32_t bl32 = (uint32_t)bl;
                V2XD_PUT(&bl32, 4);
                if (bl > 0 && b) V2XD_PUT(b, (size_t)bl);
            }
        }
        sqlite3_finalize(rs);
        if (rrc != SQLITE_DONE) goto done;
    }
    if (rc != SQLITE_DONE) goto done;
    ret = qgp_sha3_512(buf ? buf : (const uint8_t *)"", len, out) == 0
              ? 0 : -1;
done:
#undef V2XD_PUT
    sqlite3_finalize(ts);
    free(buf);
    return ret;
}

/* ══════════════════════════════════════════════════════════════════════
 * THE VERSION-3 FIXTURE (tokenomics-v3 P4)
 *
 * A chain built the way a real one is: a version-3 config →
 * nodus_witness_v2_gen_derive_v3 (the derivation `nodus-server
 * --derive-v2-genesis` runs, which seeds the validators, the
 * validator_stats.active_count row, supply_tracking, the econ band, the
 * epoch-0/E validator-set snapshots, runs the engine genesis
 * nodus_witness_v2_genesis_cmt — manifest, domain heads, the epoch-0
 * balance copy — and stores the genesis document) → reopened through the
 * PRODUCTION open path (nodus_witness_create_chain_db, whose post-open
 * gate recognises a version-3 chain from its stored document and sets
 * v2_successor / v2_chain32 itself — ASSERTED here, never assigned).
 *
 * WHY IT EXISTS. It is the chain shape that runs: a stored document, no
 * height-0 v2_blocks row, active_count as the derivation writes it, the
 * ceremony's distribution. (The version-2 fixture it replaced built
 * none of that, and is deleted with the version-2 genesis.)
 *
 * THE COMPOSITION, and why it is the only one: gen_plan_build admits
 * exactly DNAC_COMMITTEE_SIZE validators, each bonding exactly
 * DNAC_SELF_STAKE_AMOUNT with a payout fingerprint that derives from its
 * payout key, and Rule P.2 (Σ allocations + Σ self_stake +
 * reward_pool_initial == total_supply_raw). The validators are
 * deterministic SYNTHETIC byte patterns (no signature is ever verified
 * against them here), varied by `salt` so two chains can differ; the one
 * allocation (source_id 0x30…, the remainder of the supply) is bound to
 * SHA3-512 of a synthetic owner key; no reward reserve. The same shape
 * test_v2_gen.c / test_v2_committee_seed.c derive from.
 *
 * Everything is v2x_-prefixed so no includer's own helpers collide.
 * ══════════════════════════════════════════════════════════════════════ */

#include "witness/nodus_witness_v2_gen.h"
#include "witness/nodus_witness_emission.h"   /* DNAC_BLOCKS_PER_YEAR,
                                               * DNAC_DECIMAL_UNIT       */
#include "dnac/dnac.h"

#define V2X_GENESIS_TIME_MS  1700000000000ULL

typedef struct {
    nodus_v2_gen_config_t *cfg;       /* ~255 KB — heap, never stack    */
    nodus_v2_gen_alloc_t  *allocs;
} v2x_cfgbox_t;

static void v2x_cfg_free(v2x_cfgbox_t *b) {
    if (!b) return;
    free(b->cfg);
    free(b->allocs);
    b->cfg = NULL;
    b->allocs = NULL;
}

/** A complete, derivable version-3 config (see the banner). 0 / -1. */
static int v2x_cfg_make(v2x_cfgbox_t *b, uint8_t salt) {
    static const char hexd[] = "0123456789abcdef";
    if (!b) return -1;
    memset(b, 0, sizeof(*b));
    b->cfg    = (nodus_v2_gen_config_t *)calloc(1, sizeof(*b->cfg));
    b->allocs = (nodus_v2_gen_alloc_t *)calloc(1, sizeof(*b->allocs));
    if (!b->cfg || !b->allocs) { v2x_cfg_free(b); return -1; }

    nodus_v2_gen_config_t *c = b->cfg;
    c->config_version        = NODUS_V2_GEN_CONFIG_VERSION_V3;
    c->total_supply_raw      = DNAC_DEFAULT_TOTAL_SUPPLY;
    c->epoch_length          = (uint64_t)DNAC_EPOCH_LENGTH;
    c->blocks_per_year       = (uint64_t)DNAC_BLOCKS_PER_YEAR;
    c->decimal_unit          = (uint64_t)DNAC_DECIMAL_UNIT;
    c->inflation_start_block = 0ULL;          /* retired: only 0 is legal */
    c->claim_start_height    = 0;
    c->claim_end_height      = UINT64_MAX;
    c->n_validators          = (uint16_t)DNAC_COMMITTEE_SIZE;
    for (uint16_t i = 0; i < c->n_validators; i++) {
        nodus_v2_gen_validator_t *v = &c->validators[i];
        uint8_t d[64];
        for (size_t k = 0; k < DNAC_PUBKEY_SIZE; k++) {
            v->pubkey[k] = (uint8_t)(0x11 * (i + 1) + (k & 0x3F) + salt);
            v->unstake_destination_pubkey[k] = (uint8_t)(v->pubkey[k] ^ 0x5A);
        }
        if (qgp_sha3_512(v->unstake_destination_pubkey, DNAC_PUBKEY_SIZE,
                         d) != 0) {
            v2x_cfg_free(b);
            return -1;
        }
        for (int k = 0; k < 64; k++) {
            v->unstake_destination_fp[2 * k]     = (uint8_t)hexd[d[k] >> 4];
            v->unstake_destination_fp[2 * k + 1] = (uint8_t)hexd[d[k] & 0xF];
        }
        v->unstake_destination_fp[128] = 0;
        v->self_stake     = DNAC_SELF_STAKE_AMOUNT;
        v->commission_bps = (uint16_t)(100 * (i + 1));
    }
    {
        nodus_v2_gen_alloc_t *a = &b->allocs[0];
        uint8_t owner[DNAC_PUBKEY_SIZE];
        memset(a->source_id, 0, sizeof(a->source_id));
        a->source_id[0] = 0x30;
        for (size_t k = 0; k < sizeof(owner); k++)
            owner[k] = (uint8_t)(0xA0 + (k & 0x1F) + salt);
        if (qgp_sha3_512(owner, sizeof(owner), a->dest_binding) != 0) {
            v2x_cfg_free(b);
            return -1;
        }
        a->amount = DNAC_DEFAULT_TOTAL_SUPPLY -
                    (uint64_t)DNAC_COMMITTEE_SIZE * DNAC_SELF_STAKE_AMOUNT;
    }
    c->n_allocs = 1;
    c->allocs   = b->allocs;

    if (nodus_witness_v2_gen_v3_defaults(c) != 0) {
        v2x_cfg_free(b);
        return -1;
    }
    c->reward_pool_initial = 0;     /* the allocation carries the supply */
    c->genesis_time_ms     = V2X_GENESIS_TIME_MS;
    c->initial_height      = 1;
    if (nodus_witness_v2_gen_v3_fill_comet_rows(c) != 0) {
        v2x_cfg_free(b);
        return -1;
    }
    return 0;
}

typedef struct {
    nodus_witness_t *w;               /* multi-MB — heap, never stack   */
    v2x_cfgbox_t     box;             /* the config the chain came from */
    char             dir[128];
    uint8_t          chain32[NODUS_V2_GEN_CHAIN_ID_LEN];
} v2x_chain_t;

static void v2x_chain_close(v2x_chain_t *c) {
    if (!c) return;
    if (c->w) {
        if (c->w->db) sqlite3_close(c->w->db);
        free(c->w);
        c->w = NULL;
    }
    v2x_cfg_free(&c->box);
    if (c->dir[0]) {
        char cmd[200];
        snprintf(cmd, sizeof(cmd), "rm -rf '%s'", c->dir);
        if (system(cmd) != 0) { /* best effort */ }
        c->dir[0] = 0;
    }
}

/**
 * Derive a version-3 chain from `box` (taken over: closed with the
 * chain) into a fresh mkdtemp directory tagged `tag`, and reopen it
 * through the production open path. On any failure everything built so
 * far is released and -1 is returned.
 */
static int v2x_chain_open_cfg(v2x_chain_t *c, const char *tag,
                              v2x_cfgbox_t *box) {
    if (!c || !tag || !box || !box->cfg) return -1;
    memset(c, 0, sizeof(*c));
    c->box = *box;
    memset(box, 0, sizeof(*box));
    snprintf(c->dir, sizeof(c->dir), "/tmp/v2x_%s_XXXXXX", tag);
    if (!mkdtemp(c->dir)) {
        c->dir[0] = 0;
        v2x_chain_close(c);
        return -1;
    }
    if (nodus_witness_v2_gen_derive_v3(c->dir, c->box.cfg, c->chain32) != 0) {
        v2x_chain_close(c);
        return -1;
    }
    c->w = (nodus_witness_t *)calloc(1, sizeof(*c->w));
    if (!c->w) { v2x_chain_close(c); return -1; }
    /* the live constructor's cache sentinel (nodus_witness.h) */
    c->w->cached_committee_epoch_start = UINT64_MAX;
    snprintf(c->w->data_path, sizeof(c->w->data_path), "%s", c->dir);
    /* The file is named witness_<chain_id[0..15] hex>.db, so reopening by
     * the first 16 bytes of the derived id opens exactly that file. */
    if (nodus_witness_create_chain_db(c->w, c->chain32) != 0) {
        v2x_chain_close(c);
        return -1;
    }
    /* ASSERTED, never assigned: the post-open gate sets both from the
     * stored document. A gate that stopped recognising the chain must
     * fail the fixture, not route the test through another lane. */
    if (!c->w->v2_successor ||
        memcmp(c->w->v2_chain32, c->chain32, sizeof(c->chain32)) != 0) {
        fprintf(stderr, "v2x_chain_open: the production open path did not "
                        "recognise the derived version-3 chain\n");
        v2x_chain_close(c);
        return -1;
    }
    return 0;
}

/** v2x_cfg_make(salt) + v2x_chain_open_cfg. 0 / -1. */
static int v2x_chain_open(v2x_chain_t *c, const char *tag, uint8_t salt) {
    v2x_cfgbox_t box;
    if (v2x_cfg_make(&box, salt) != 0) return -1;
    if (v2x_chain_open_cfg(c, tag, &box) != 0) {
        v2x_cfg_free(&box);            /* no-op if it was taken over     */
        return -1;
    }
#ifdef NODUS_V2_TEST_SUPPLY
    /* O15J — the engine-level targets that drive synthetic value-creating
     * envelopes arm the test-only conservation bypass on every chain they
     * open (CMakeLists.txt register_witness_test_supply_bypass); the
     * symbol does not exist in any other build. */
    nodus_witness_v2_supply_test_bypass(1);
#endif
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════
 * THE SEEDED VERSION-3 GENESIS (tokenomics-v3 P4, engine half)
 *
 * WHAT IT IS. The version-3 derivation's own steps
 * (nodus_witness_v2_gen_derive_v3, steps 4-10), run in the SAME order,
 * with ONE seam: between the database preparation (step 4 — create,
 * v2_successor before any validator row, the live rung S16, the
 * chain-config table, the economic band gen_seed_state commits) and the
 * authority + engine genesis (steps 6-7 — the epoch-0/E snapshots, the
 * registry, the manifest, nodus_witness_v2_genesis_cmt with its supply
 * gate and the epoch-0 balance copy), the TEST seeds the genesis rows a
 * version-3 config cannot express: bonds other than
 * DNAC_SELF_STAKE_AMOUNT, other than 7 validators, real ML-DSA-87
 * validator keys, UTXOs present at genesis, genesis delegations,
 * synthetic domains. Then the document is stored and the database is
 * REOPENED through the production open path, whose post-open gate must
 * recognise it as a version-3 chain (asserted, never assigned).
 *
 * WHY THE SEAM IS THERE AND NOT AFTER THE DERIVATION. The engine genesis
 * commits one activation DomainHead per ACTIVE domain over the rows that
 * exist at that moment. A row written into a root leg afterwards
 * (validators, utxo_set, snapshots, delegations, supply, chain config)
 * moves the live root away from the committed head, and the first block
 * dies at phase 8's untouched-domain guard — so "seed after derivation"
 * cannot produce a chain the engine will run. Seeding BEFORE the engine
 * genesis is the one place where every committed genesis value (heads,
 * root history, supply gate, snapshots 0/E, copy(0)) is computed by the
 * production code over the seeded rows, exactly as a real genesis
 * computes them over the ceremony's rows.
 *
 * THE INVARIANTS A REAL GENESIS KEEPS, and who keeps them here:
 *   - validator_stats.active_count == the bonded rows (ACTIVE, ELIGIBLE,
 *     RETIRING — the counter's D-11 meaning): written by v2x_seed_rows
 *     from the rows (gen_seed_state writes n_validators, and every
 *     genesis row is ACTIVE);
 *   - the supply equation closes: nodus_witness_v2_genesis_cmt runs the
 *     supply gate and REFUSES otherwise; an absent supply row is created
 *     from the seeded rows (Rule P.2 by construction);
 *   - snapshots 0/E: nodus_witness_vset_commit_genesis over the seeded
 *     validators, unless the test committed its own;
 *   - copy(0): nodus_witness_v2_genesis_cmt writes it from the seeded
 *     validators and delegations.
 * A test that seeds NO validator gets the document's own seven (the rows
 * gen_seed_state writes for the v2x_cfg_make config), bonds included in
 * the supply — a real genesis always has its committee.
 *
 * WHAT IT IS NOT, stated so no reader mistakes it: the stored document
 * is the v2x_cfg_make config (salt-varied) completed with THIS ledger's
 * genesis root as app_hash — it carries the chain's identity and chain
 * parameters (payout interval, reward divisor), but its validator and
 * allocation lists are the synthetic ceremony's, not the seeded rows. The
 * ledger tests never run InitChain (the one reader that compares the
 * document's validators with the ledger, nodus_witness_cmt_app.c), and
 * the database file keeps the name the test opened it under instead of
 * being renamed to the chain id. Tests that need the ceremony's exact
 * chain use v2x_chain_open above.
 * ══════════════════════════════════════════════════════════════════════ */

#include "witness/nodus_witness_v2_schema.h"
#include "witness/nodus_witness_cmt_store.h"
#include "nodus/nodus_chain_config.h"

static int v2x_sql(sqlite3 *db, const char *sql) {
    char *err = NULL;
    if (sqlite3_exec(db, sql, NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr, "v2x_sql: %s: %s\n", sql, err ? err : "?");
        sqlite3_free(err);
        return -1;
    }
    return 0;
}

static int v2x_count(sqlite3 *db, const char *sql, sqlite3_int64 *out) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    int rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) *out = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return rc == SQLITE_ROW ? 0 : -1;
}

/* ── NOT-A-REAL-GENESIS opt-outs (P4 fix round) ──────────────────────
 * v2x_seed_genesis runs the version-3 derivation's own ledger
 * post-conditions (nodus_witness_v2_gen.c, nodus_witness_v2_gen_derive_v3
 * step 10 (a)/(d)) on every seeded genesis. A test whose genesis state is
 * deliberately NOT one a real ceremony can produce names each departure
 * with one of these flags, set through v2x_seed_not_real() right before
 * the genesis, next to a comment "not a real genesis: <why>". The flags
 * are ONE-SHOT: v2x_seed_genesis clears them whatever its outcome (the
 * g_v2x_hash_override pattern).
 *
 * Always enforced, no flag: no block row; a committed claim distribution
 * holds exactly its total_claimable (and no distribution means no
 * v2_dist_state row); a committee that IS the document's carries exactly
 * the document's bonds; the supply equation balances. */
#define V2X_SEED_NOT_REAL_UTXOS     0x01u  /* spendable UTXOs at genesis
                                            * (derive_v3: none)          */
#define V2X_SEED_NOT_REAL_STATUSES  0x02u  /* non-ACTIVE validator rows
                                            * (derive_v3 writes only
                                            * ACTIVE); active_count then
                                            * counts the BONDED statuses
                                            * instead of every row       */
#define V2X_SEED_NOT_REAL_MALFORMED 0x04u  /* a validator row that is NOT
                                            * writable-shaped (derive_v3
                                            * refuses it, L2-F4)         */
static unsigned g_v2x_seed_not_real = 0;

static void v2x_seed_not_real(unsigned flags) {
    g_v2x_seed_not_real |= flags;
}

/**
 * Step 4 of the derivation: open `w` (data_path already set by the
 * caller) under the file id `file16`, which must be a PRE-GENESIS
 * database; mark it a Ledger V2 successor BEFORE any validator row
 * exists (the vset writer guard is gated on it); migrate to the live
 * rung S16; create the chain-config table; commit the economic band
 * exactly as gen_seed_state does (tx_hash = the document's source
 * commit). The test seeds its genesis rows after this and then calls
 * v2x_seed_genesis with the SAME salt. 0 / -1.
 */
static int v2x_seed_prepare(nodus_witness_t *w, const uint8_t file16[16],
                            uint8_t salt) {
    if (!w || !w->data_path[0] || !file16) return -1;
    w->cached_committee_epoch_start = UINT64_MAX;
    if (nodus_witness_create_chain_db(w, file16) != 0) return -1;
    if (w->v2_successor) {
        fprintf(stderr, "v2x_seed_prepare: the database is already a "
                        "version-3 chain\n");
        return -1;
    }
    w->v2_successor = 1;
    if (nodus_witness_db_migrate_v2s16(w) != 0) return -1;
    if (nodus_chain_config_db_migrate(w) != 0) return -1;

    v2x_cfgbox_t box;
    uint8_t src[NODUS_V2_GEN_SRCCOMMIT_LEN];
    if (v2x_cfg_make(&box, salt) != 0) return -1;
    if (nodus_witness_v2_gen_v3_source_commit(box.cfg, src) != 0) {
        v2x_cfg_free(&box);
        return -1;
    }
    const unsigned params[3] = { NODUS_CC_ECON_BLOCKS_PER_YEAR,
                                 NODUS_CC_ECON_DECIMAL_UNIT,
                                 NODUS_CC_ECON_EPOCH_LENGTH };
    const uint64_t vals[3] = { box.cfg->blocks_per_year,
                               box.cfg->decimal_unit,
                               box.cfg->epoch_length };
    v2x_cfg_free(&box);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "INSERT INTO chain_config_history (param_id, new_value, "
            "effective_block, commit_block, tx_hash, proposal_nonce, "
            "created_at_unix) VALUES (?1, ?2, ?3, 0, ?4, 0, 0)",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    for (int i = 0; i < 3; i++) {
        sqlite3_reset(st);
        sqlite3_clear_bindings(st);
        sqlite3_bind_int64(st, 1, (sqlite3_int64)params[i]);
        sqlite3_bind_int64(st, 2, (sqlite3_int64)vals[i]);
        sqlite3_bind_int64(st, 3,
                           (sqlite3_int64)NODUS_CC_ECON_EFFECTIVE_BLOCK);
        sqlite3_bind_blob(st, 4, src, sizeof(src), SQLITE_TRANSIENT);
        if (sqlite3_step(st) != SQLITE_DONE) {
            sqlite3_finalize(st);
            return -1;
        }
    }
    sqlite3_finalize(st);
    w->chain_config_cache_warm = false;
    return 0;
}

/**
 * The rows of a genesis the test did NOT seed, and the authority over
 * them (the derivation's step 5 remainder + step 6's snapshots): the
 * document's own seven validators if there is none,
 * validator_stats.active_count, the supply row if absent, the epoch-0/E
 * snapshots if absent. Idempotent — v2x_seed_genesis calls it again. A
 * test that captures payload roots BEFORE the registry commits them
 * calls this first (the validator and snapshot legs are part of the
 * SYSTEM payload root). 0 / -1.
 */
static int v2x_seed_rows(nodus_witness_t *w, uint8_t salt) {
    if (!w || !w->db || !w->v2_successor) return -1;

    v2x_cfgbox_t box;
    if (v2x_cfg_make(&box, salt) != 0) return -1;
    nodus_v2_gen_config_t *cfg = box.cfg;
    uint8_t src[NODUS_V2_GEN_SRCCOMMIT_LEN];
    int ok = -1;
    do {
        if (nodus_witness_v2_gen_v3_source_commit(cfg, src) != 0) break;

        /* ── 5. the committee, when the test seeded none ─────────────
         * gen_seed_state's writer, field for field, over the
         * document's own validators, in pubkey-ascending order (the
         * order gen_plan_build's val_idx gives the seeder). */
        sqlite3_int64 n_val = -1;
        int seeded_committee = 0;
        if (v2x_count(w->db, "SELECT COUNT(*) FROM validators",
                      &n_val) != 0) break;
        if (n_val == 0) {
            uint16_t order[NODUS_V2_GEN_MAX_VALIDATORS];
            uint16_t i, j;
            for (i = 0; i < cfg->n_validators; i++) order[i] = i;
            for (i = 1; i < cfg->n_validators; i++)
                for (j = i; j > 0 &&
                     memcmp(cfg->validators[order[j]].pubkey,
                            cfg->validators[order[j - 1]].pubkey,
                            DNAC_PUBKEY_SIZE) < 0; j--) {
                    uint16_t t = order[j];
                    order[j] = order[j - 1];
                    order[j - 1] = t;
                }
            for (i = 0; i < cfg->n_validators; i++) {
                const nodus_v2_gen_validator_t *v =
                    &cfg->validators[order[i]];
                dnac_validator_record_t rec;
                memset(&rec, 0, sizeof(rec));
                memcpy(rec.pubkey, v->pubkey, DNAC_PUBKEY_SIZE);
                memcpy(rec.unstake_destination_pubkey,
                       v->unstake_destination_pubkey, DNAC_PUBKEY_SIZE);
                memcpy(rec.unstake_destination_fp, v->unstake_destination_fp,
                       DNAC_FINGERPRINT_SIZE);
                rec.self_stake         = v->self_stake;
                rec.commission_bps     = v->commission_bps;
                rec.status             = DNAC_VALIDATOR_ACTIVE;
                rec.active_since_block = 1ULL;
                if (nodus_validator_insert(w, &rec) != 0) break;
            }
            if (i != cfg->n_validators) break;
            seeded_committee = 1;
        }

        /* validator_stats.active_count — the row create_chain_db seeds
         * at 0; gen_seed_state writes n_validators (every row a genesis
         * writes is ACTIVE), and so does this fixture: every validator
         * row, which on an all-ACTIVE genesis is the same number.
         * A genesis that seeds NON-ACTIVE rows is not a real one and
         * must say so (V2X_SEED_NOT_REAL_STATUSES); it then gets the
         * counter's own invariant (D-11; the STAKE writer
         * nodus_witness_rt_native.c and the boundary's graduation /
         * Rule N decrements) — every BONDED row not yet graduated and
         * not auto-retired: ACTIVE, ELIGIBLE, RETIRING. Without the flag
         * such a genesis is refused here, loudly. */
        {
            sqlite3_int64 n_act = -1, n_rows = -1, n_nonact = -1;
            char sql[200];
            if (v2x_count(w->db, "SELECT COUNT(*) FROM validators",
                          &n_rows) != 0) break;
            snprintf(sql, sizeof(sql), "SELECT COUNT(*) FROM validators "
                     "WHERE status != %d", (int)DNAC_VALIDATOR_ACTIVE);
            if (v2x_count(w->db, sql, &n_nonact) != 0) break;
            if (n_nonact != 0 &&
                !(g_v2x_seed_not_real & V2X_SEED_NOT_REAL_STATUSES)) {
                fprintf(stderr, "v2x_seed_rows: %lld non-ACTIVE validator "
                        "rows but no V2X_SEED_NOT_REAL_STATUSES — a real "
                        "genesis writes only ACTIVE rows\n",
                        (long long)n_nonact);
                break;
            }
            snprintf(sql, sizeof(sql), "SELECT COUNT(*) FROM validators "
                     "WHERE status IN (%d, %d, %d)",
                     (int)DNAC_VALIDATOR_ACTIVE,
                     (int)DNAC_VALIDATOR_ELIGIBLE,
                     (int)DNAC_VALIDATOR_RETIRING);
            if (g_v2x_seed_not_real & V2X_SEED_NOT_REAL_STATUSES) {
                if (v2x_count(w->db, sql, &n_act) != 0) break;
            } else {
                n_act = n_rows;
            }
            snprintf(sql, sizeof(sql),
                     "UPDATE validator_stats SET value = %lld "
                     "WHERE key = 'active_count'", (long long)n_act);
            if (v2x_sql(w->db, sql) != 0) break;
            if (sqlite3_changes(w->db) != 1) break;
        }

        /* supply_tracking. Absent: created with genesis_supply = the
         * equation's right-hand side over the seeded rows (UTXOs of the
         * native token + bonds + delegated; no reserve) — Rule P.2 by
         * construction. Present AND the committee was added above: its
         * bonds join the supply the test declared, which a real genesis
         * supply always includes. The engine genesis's supply gate
         * decides whether the result closes. */
        {
            nodus_witness_supply_t sup;
            memset(&sup, 0, sizeof(sup));
            int src_rc = nodus_witness_supply_get(w, &sup);
            sqlite3_int64 bonds = 0, deleg = 0;
            uint64_t utxo = 0;
            if (src_rc < 0) break;
            if (v2x_count(w->db, "SELECT COALESCE(SUM(self_stake),0) "
                          "FROM validators", &bonds) != 0) break;
            if (v2x_count(w->db, "SELECT COALESCE(SUM(total_delegated),0) "
                          "FROM validators", &deleg) != 0) break;
            if (nodus_witness_utxo_sum_by_token(w, NULL, &utxo) != 0) break;
            if (src_rc == 1) {
                uint64_t total = utxo + (uint64_t)bonds + (uint64_t)deleg;
                if (nodus_witness_supply_init(w, total, 0, src) != 0) break;
            } else if (seeded_committee) {
                char sql[256];
                snprintf(sql, sizeof(sql),
                         "UPDATE supply_tracking SET genesis_supply = "
                         "genesis_supply + %lld, current_supply = "
                         "current_supply + %lld WHERE id = 1",
                         (long long)bonds, (long long)bonds);
                if (v2x_sql(w->db, sql) != 0) break;
            }
        }

        /* ── 6. the committed authority: snapshots 0 and E ─────────── */
        {
            sqlite3_int64 n_snap = -1;
            if (v2x_count(w->db, "SELECT COUNT(*) FROM "
                          "validator_set_snapshots", &n_snap) != 0) break;
            if (n_snap == 0 &&
                nodus_witness_vset_commit_genesis(w, 1) != 0) break;
        }
        ok = 0;
    } while (0);
    v2x_cfg_free(&box);
    return ok;
}

/**
 * The genesis manifest a seeded genesis commits when the test brings
 * none: an ABSENT-distribution GenesisManifest over the registry's
 * committed SYSTEM/CORE manifest hashes and the committed genesis supply
 * (the ceremony's manifest additionally carries the allocation
 * distribution — v2x_chain_open is that chain). Runs the registry
 * genesis first (idempotent; the engine genesis re-runs it and
 * byte-compares). 0 / -1.
 */
static int v2x_seed_manifest(nodus_witness_t *w, uint8_t *out, size_t cap,
                             size_t *out_len) {
    dna_domain_manifest_t dm;
    uint8_t sys_h[64], core_h[64];
    nodus_witness_supply_t sup;
    dna_gman_t m;
    if (!w || !w->db || !out || !out_len) return -1;
    if (nodus_witness_domreg_init_genesis(w) != 0) return -1;
    if (nodus_witness_domreg_get(w, DNA_DOMAIN_SYSTEM, NULL, &dm,
                                 NULL) != 0) return -1;
    if (dna_domman_hash(&dm, sys_h) != 0) return -1;
    if (nodus_witness_domreg_get(w, DNA_DOMAIN_CORE, NULL, &dm,
                                 NULL) != 0) return -1;
    if (dna_domman_hash(&dm, core_h) != 0) return -1;
    memset(&sup, 0, sizeof(sup));
    if (nodus_witness_supply_get(w, &sup) != 0) return -1;
    memset(&m, 0, sizeof(m));
    m.manifest_version   = DNA_GMAN_VERSION;
    m.genesis_supply_raw = sup.genesis_supply;
    m.domain_count       = 2;
    m.domains[0].domain_id = DNA_DOMAIN_SYSTEM;
    memcpy(m.domains[0].manifest_hash, sys_h, 64);
    m.domains[1].domain_id = DNA_DOMAIN_CORE;
    memcpy(m.domains[1].manifest_hash, core_h, 64);
    m.dist_present = 0;
    return dna_gman_encode(&m, out, cap, out_len) == 0 ? 0 : -1;
}

/** The committed epoch-0 authority's set hash (the engine genesis's
 *  `vset_hash` assertion must equal it). 0 / -1. */
static int v2x_seed_vset_hash(nodus_witness_t *w,
                              uint8_t out[DNA_VSET_HASH_LEN]) {
    dna_vset_snapshot_t *s0 = NULL;
    uint32_t sn = 0, sq = 0;
    if (nodus_witness_v2_epoch_authority_for_height(w, 0, &s0, &sn, &sq)
            != 0 || !s0) {
        dna_vset_free(&s0);
        return -1;
    }
    int hrc = dna_vset_hash(s0, out);
    dna_vset_free(&s0);
    return hrc == 0 ? 0 : -1;
}

/**
 * The version-3 derivation's ledger post-conditions
 * (nodus_witness_v2_gen.c, nodus_witness_v2_gen_derive_v3 step 10 (a)
 * and (d)), run by v2x_seed_genesis on the reopened chain:
 *   (a) no block row, of any height;
 *   (d1) no spendable UTXO — unless V2X_SEED_NOT_REAL_UTXOS;
 *   (d2) the claim reserve: a committed distribution holds exactly its
 *        total_claimable; no distribution, no v2_dist_state row. (The
 *        derivation always commits one; the default seeded manifest,
 *        v2x_seed_manifest, commits none — a banner item.)
 *   (d3) the bonds: when the committee IS the document's (every one of
 *        its validators present and no other row), Σ self_stake equals
 *        the document's Σ self_stake. A test-seeded committee has no
 *        document plan to compare against — a banner item;
 *   (d4) every validator row writable-shaped
 *        (nodus_witness_v2_epoch_val_rec_ok) — unless
 *        V2X_SEED_NOT_REAL_MALFORMED;
 *   (d5) the supply equation balances (nodus_witness_v2_supply_check);
 *   and validator_stats.active_count is what v2x_seed_rows wrote: every
 *   row, or — under V2X_SEED_NOT_REAL_STATUSES — the bonded statuses.
 * 0 / -1 (the failing condition printed).
 */
static int v2x_seed_postconditions(nodus_witness_t *w,
                                   const nodus_v2_gen_config_t *cfg,
                                   const uint8_t *mbytes, size_t mlen,
                                   unsigned not_real) {
    sqlite3_int64 n = -1;
    if (v2x_count(w->db, "SELECT COUNT(*) FROM v2_blocks", &n) != 0 ||
        n != 0) {
        fprintf(stderr, "v2x_seed_genesis: (a) %lld block rows after the "
                "genesis\n", (long long)n);
        return -1;
    }
    if (!(not_real & V2X_SEED_NOT_REAL_UTXOS)) {
        if (v2x_count(w->db, "SELECT COUNT(*) FROM utxo_set", &n) != 0 ||
            n != 0) {
            fprintf(stderr, "v2x_seed_genesis: (d1) %lld spendable UTXOs at "
                    "genesis and no V2X_SEED_NOT_REAL_UTXOS\n",
                    (long long)n);
            return -1;
        }
    }
    {
        dna_gman_t m;
        memset(&m, 0, sizeof(m));
        if (dna_gman_decode(mbytes, mlen, &m) != 0) {
            fprintf(stderr, "v2x_seed_genesis: (d2) the committed manifest "
                    "does not decode\n");
            return -1;
        }
        if (m.dist_present) {
            if (v2x_count(w->db, "SELECT COALESCE(SUM(remaining), -1) FROM "
                          "v2_dist_state", &n) != 0 ||
                n < 0 || (uint64_t)n != m.total_claimable) {
                fprintf(stderr, "v2x_seed_genesis: (d2) claim reserve %lld "
                        "!= claimable %llu\n", (long long)n,
                        (unsigned long long)m.total_claimable);
                return -1;
            }
        } else if (v2x_count(w->db, "SELECT COUNT(*) FROM v2_dist_state",
                             &n) != 0 || n != 0) {
            fprintf(stderr, "v2x_seed_genesis: (d2) %lld distribution rows "
                    "without a committed distribution\n", (long long)n);
            return -1;
        }
    }
    {
        sqlite3_int64 n_rows = -1, bonded = -1;
        if (v2x_count(w->db, "SELECT COUNT(*) FROM validators",
                      &n_rows) != 0 ||
            v2x_count(w->db, "SELECT COALESCE(SUM(self_stake), 0) FROM "
                      "validators", &bonded) != 0)
            return -1;
        int doc_committee = (n_rows == (sqlite3_int64)cfg->n_validators);
        uint64_t plan = 0;
        for (uint16_t i = 0; i < cfg->n_validators && doc_committee; i++) {
            dnac_validator_record_t got;
            if (nodus_validator_get(w, cfg->validators[i].pubkey, &got) != 0)
                doc_committee = 0;
            plan += cfg->validators[i].self_stake;
        }
        if (doc_committee && (uint64_t)bonded != plan) {
            fprintf(stderr, "v2x_seed_genesis: (d3) the document's committee "
                    "carries self-stake %lld, the document says %llu\n",
                    (long long)bonded, (unsigned long long)plan);
            return -1;
        }
        if (!(not_real & V2X_SEED_NOT_REAL_MALFORMED) && n_rows > 0) {
            dnac_validator_record_t *recs =
                calloc((size_t)n_rows, sizeof(*recs));
            int got_n = 0, total = 0, bad = -1;
            if (recs &&
                nodus_validator_list_paged(w, -1, 0, (int)n_rows, recs,
                                           &got_n, &total) == 0 &&
                got_n == (int)n_rows && total == (int)n_rows) {
                bad = 0;
                for (int i = 0; i < got_n && !bad; i++)
                    if (!nodus_witness_v2_epoch_val_rec_ok(&recs[i])) bad = 1;
            }
            free(recs);
            if (bad != 0) {
                fprintf(stderr, "v2x_seed_genesis: (d4) a committed validator "
                        "row is not writable-shaped (or unreadable) and no "
                        "V2X_SEED_NOT_REAL_MALFORMED\n");
                return -1;
            }
        }
        sqlite3_int64 n_act = -1, want = n_rows;
        if (not_real & V2X_SEED_NOT_REAL_STATUSES) {
            char sql[200];
            snprintf(sql, sizeof(sql), "SELECT COUNT(*) FROM validators "
                     "WHERE status IN (%d, %d, %d)",
                     (int)DNAC_VALIDATOR_ACTIVE,
                     (int)DNAC_VALIDATOR_ELIGIBLE,
                     (int)DNAC_VALIDATOR_RETIRING);
            if (v2x_count(w->db, sql, &want) != 0) return -1;
        }
        if (v2x_count(w->db, "SELECT value FROM validator_stats WHERE "
                      "key = 'active_count'", &n_act) != 0 ||
            n_act != want) {
            fprintf(stderr, "v2x_seed_genesis: active_count %lld, expected "
                    "%lld\n", (long long)n_act, (long long)want);
            return -1;
        }
    }
    if (nodus_witness_v2_supply_check(w) != 0) {
        fprintf(stderr, "v2x_seed_genesis: (d5) the supply equation does not "
                "balance on the seeded chain\n");
        return -1;
    }
    return 0;
}

/**
 * The derivation's steps 6-10 over the rows the test seeded since
 * v2x_seed_prepare: v2x_seed_rows (idempotent), the registry, the
 * manifest (`mbytes` NULL = v2x_seed_manifest; otherwise the caller's
 * canonical GenesisManifest bytes), the engine genesis
 * nodus_witness_v2_genesis_cmt, the completed document (app_hash = the
 * engine's genesis root) stored under genesisDoc, and the reopen through
 * the production open path. `out_chain32` (may be NULL) receives the
 * chain id the post-open gate derived. 0 / -1.
 */
static int v2x_seed_genesis(nodus_witness_t *w, const uint8_t file16[16],
                            uint8_t salt, const uint8_t *mbytes_in,
                            size_t mlen_in, uint8_t out_chain32[32]) {
    const unsigned not_real = g_v2x_seed_not_real;
    g_v2x_seed_not_real = 0;                  /* one-shot, every outcome */
    if (!w || !w->db || !file16) return -1;
    if (!w->v2_successor) return -1;          /* v2x_seed_prepare first */
#ifdef NODUS_V2_TEST_SUPPLY
    /* P4 fix round: the engine genesis's own supply gate and the
     * post-conditions below run against the LIVE equation. An earlier
     * seeded genesis in the same process left the test bypass armed,
     * which made both vacuous for every later fixture. Re-armed at the
     * end, as before. */
    nodus_witness_v2_supply_test_bypass(0);
#endif
    g_v2x_seed_not_real = not_real;           /* v2x_seed_rows reads it */
    int rows_rc = v2x_seed_rows(w, salt);
    g_v2x_seed_not_real = 0;
    if (rows_rc != 0) return -1;

    v2x_cfgbox_t box;
    if (v2x_cfg_make(&box, salt) != 0) return -1;
    nodus_v2_gen_config_t *cfg = box.cfg;
    uint8_t *doc = NULL;
    size_t doc_len = 0;
    int ok = -1;
    do {
        if (nodus_witness_domreg_init_genesis(w) != 0) break;

        uint8_t mdefault[8192];
        const uint8_t *mbytes = mbytes_in;
        size_t mlen = mlen_in;
        if (!mbytes) {
            if (v2x_seed_manifest(w, mdefault, sizeof(mdefault), &mlen)
                    != 0) break;
            mbytes = mdefault;
        }

        uint8_t vsh[DNA_VSET_HASH_LEN];
        if (v2x_seed_vset_hash(w, vsh) != 0) break;

        /* ── 7. THE ENGINE GENESIS ─────────────────────────────────── */
        uint8_t global_root[64];
        if (nodus_witness_v2_genesis_cmt(w, vsh, mbytes, mlen,
                                         global_root) != 0) {
            fprintf(stderr, "v2x_seed_genesis: nodus_witness_v2_genesis_cmt "
                            "refused the seeded genesis\n");
            break;
        }

        /* ── 8-9. complete and store the document ──────────────────── */
        memcpy(cfg->app_hash, global_root, NODUS_V2_GEN_APP_HASH_LEN);
        memset(cfg->chain_id, 0, NODUS_V2_GEN_CHAIN_ID_LEN);
        if (nodus_witness_v2_gen_chain_id(cfg, cfg->chain_id) != 0) break;
        if (nodus_witness_v2_gen_v3_encode(cfg, &doc, &doc_len) != 0) break;
        {
            nodus_cmt_store_t s;
            if (nodus_cmt_store_init(&s, w->db, false) != CMT_OK) break;
            int srv = nodus_cmt_store_set(&s, /*state_table=*/true,
                                          NODUS_V2_GEN_GENESIS_DOC_KEY,
                                          doc, doc_len);
            nodus_cmt_store_release(&s);
            if (srv != CMT_OK) break;
        }

        /* ── 10. the production open path decides what this is ────── */
        sqlite3_close(w->db);
        w->db = NULL;
        w->chain_config_cache_warm = false;
        w->cached_committee_epoch_start = UINT64_MAX;
        if (nodus_witness_create_chain_db(w, file16) != 0) break;
        if (!w->v2_successor ||
            memcmp(w->v2_chain32, cfg->chain_id,
                   NODUS_V2_GEN_CHAIN_ID_LEN) != 0) {
            fprintf(stderr, "v2x_seed_genesis: the production open path "
                            "did not recognise the seeded version-3 "
                            "chain\n");
            break;
        }
        if (out_chain32)
            memcpy(out_chain32, w->v2_chain32, NODUS_V2_GEN_CHAIN_ID_LEN);

        /* ── the derivation's post-conditions (P4 fix round) ──────────
         * nodus_witness_v2_gen_derive_v3 step 10 (a) and (d), on the
         * REOPENED chain. Where a seeded genesis is legitimately not a
         * real one the caller said so (V2X_SEED_NOT_REAL_*). */
        if (v2x_seed_postconditions(w, cfg, mbytes, mlen, not_real) != 0)
            break;
        ok = 0;
    } while (0);
    free(doc);
    v2x_cfg_free(&box);
#ifdef NODUS_V2_TEST_SUPPLY
    if (ok == 0) nodus_witness_v2_supply_test_bypass(1);
#endif
    return ok;
}

/* ══════════════════════════════════════════════════════════════════════
 * THE COMETBFT-LANE BLOCK FIXTURE (tokenomics-v3 P4, engine half)
 *
 * nodus_witness_v2_apply_block has ONE production caller,
 * nodus_cmt_app_finalize_block (nodus_witness_cmt_app.c), and it always
 * applies in the cometbft lane. v2x_cmt_apply is that caller's shape for
 * a test, field for field:
 *   cmt.on = true;
 *   cmt.block_hash      the request's Hash (64 bytes, CMT_TMHASH_SIZE) —
 *                       the hash of the block the host just saved to the
 *                       block store (v2x_cmt_store_block, above);
 *   cmt.validators_hash the request's NextValidatorsHash, from that
 *                       block's header;
 *   proposer_id         the request's proposer address, from that header;
 *   timestamp           the request's time (seconds), from that header;
 *   cmt.results         a results array sized for every item;
 *   cmt.votes_*         the test's own (decided_last_commit; empty is the
 *                       legal initial-height shape);
 *   epoch / envs / claims / fail_* — the test's own block fields, as the
 *                       app fills them.
 * A height the block store cannot record (a gap, a stale height, height
 * 0 — the linkage fault probes) and a block whose hash the test set
 * itself get a deterministic per-(chain, height) identity instead
 * (v2x_cmt_probe_ids); the engine refuses them either way.
 * The TEST IS THE HOST (nodus_witness_cmt_host.c apply_verified_block):
 * BEGIN IMMEDIATE, the block-store record, the engine, then COMMIT when
 * it returns 0 and ROLLBACK otherwise — the engine opens, commits and
 * rolls back nothing in this lane.
 *
 * THE LANE'S TRUTH TABLE (nodus_witness_v2_apply_block):
 *   0                        the block committed; each item's verdict is
 *                            in cmt.results[i].code (nodus_v2_tx_code_t);
 *                            a refused item left no state behind (its
 *                            SAVEPOINT was rolled back) and the others
 *                            committed around it;
 *   NODUS_V2_INTERNAL_FAULT  every block-level refusal (a decided block
 *                            is never refused — the wrapper folds every
 *                            body class into this one); the host rolled
 *                            the whole block back.
 * There is no idempotent-replay rc 1, no post-commit rc 2 and no
 * block-level verdict in this lane.
 * ══════════════════════════════════════════════════════════════════════ */

/** A fixture-level error (not an engine return code). */
#define V2X_CMT_FIXTURE_ERR  (-100)
/* One-shot block-hash override for the next v2x_cmt_host call (the
 * duplicate-identity probe, v2x_cmt_fault_with_hash). */
static const uint8_t *g_v2x_hash_override;
/** Results array the helper lends a block that brought none. */
#define V2X_RES_MAX          4096u
static nodus_v2_tx_result_t v2x_res[V2X_RES_MAX];

/* ── THE HOST'S BLOCK-STORE RECORD ─────────────────────────────────────
 * A node's consensus driver saves the decided block to the Comet block
 * store (cometbft finalizeCommit → blockStore.SaveBlock, this port's
 * nodus_cmt_bs_save_block) BEFORE the application's FinalizeBlock runs,
 * and the ledger READS that store: on a version-3 chain the epoch
 * boundary's committee seed is the BlockMeta at the lookback height
 * (nodus_witness_committee.c v2_seed_block_id — height, chain id and
 * the block hash that v2_blocks.block_id must equal). So the fixture
 * saves one for every block it hands the engine, built the way
 * test_v2_committee_seed.c's commit_block1 builds one: a real
 * cmt_block_t made by cmt_state_make_block from the chain's OWN stored
 * genesis document (read through the canonical-strict reader, as
 * nodus_cmt_node_init does), hashed, cut into its part set and saved
 * with a zero-signature seen commit (save_block verifies no
 * signature). What it is NOT: a replay of consensus — every block is made
 * from the GENESIS state, with the timestamp rule's genesis branch
 * (initial_height is set to the block's own height on a private copy of
 * the state), an empty Data section (the ledger reads none of it) and an
 * empty LastCommit. Only the three fields the ledger checks are the
 * point, and they are the real ones.
 *
 * The record is written INSIDE the host's transaction, so a FAULT rolls
 * it back with the block. A height that is not the store's next
 * contiguous height (the gap / stale / height-0 fault probes) gets no
 * record — the store itself refuses one (save_block's contiguity rule),
 * and consensus could never have decided such a block. */

#include "witness/nodus_witness_cmt_store.h"
#include "dnac/cmt_genesis.h"
#include "dnac/cmt_state.h"
#include "dnac/cmt_block.h"
#include "dnac/cmt_part_set.h"

/* One-entry cache of the genesis cmt_state, keyed by the chain id: twin
 * fixtures of one chain share it, a different chain rebuilds it. */
typedef struct {
    int                        valid;
    uint8_t                    chain32[32];
    cmt_genesis_doc_t          doc;
    cmt_genesis_validator_t    gvals[NODUS_V2_GEN_MAX_VALIDATORS];
    cmt_state_storage_t        stor;
    cmt_state_t                state;
    cmt_valset_scratch_t       vscratch;
    uint8_t                    proposer[32];
} v2x_cmt_gen_t;
static v2x_cmt_gen_t *g_v2x_cmt_gen;

static const v2x_cmt_gen_t *v2x_cmt_genesis_state(nodus_witness_t *w) {
    if (!g_v2x_cmt_gen) {
        g_v2x_cmt_gen = (v2x_cmt_gen_t *)calloc(1, sizeof(*g_v2x_cmt_gen));
        if (!g_v2x_cmt_gen) return NULL;
    }
    v2x_cmt_gen_t *g = g_v2x_cmt_gen;
    if (g->valid && memcmp(g->chain32, w->v2_chain32, 32) == 0) return g;
    memset(g, 0, sizeof(*g));

    nodus_v2_gen_config_t *cfg =
        (nodus_v2_gen_config_t *)calloc(1, sizeof(*cfg));
    nodus_v2_gen_alloc_t  *allocs = NULL;
    int ok = -1;
    if (!cfg) return NULL;
    do {
        uint8_t digest[64];
        if (nodus_witness_v2_gen_stored_doc(w, cfg, &allocs) != 0) break;
        if (nodus_witness_v2_gen_to_cmt_doc(cfg, &g->doc, g->gvals,
                                            NODUS_V2_GEN_MAX_VALIDATORS)
                != 0) break;
        if (cmt_state_init(&g->state, &g->stor) != CMT_OK) break;
        if (cmt_state_make_genesis(&g->doc, NULL, NULL, &g->vscratch,
                                   &g->state) != CMT_OK) break;
        /* the proposer: the document's first validator's address
         * (SHA3-512(pubkey)[0..31], vset_wire.h) */
        if (qgp_sha3_512(cfg->validators[0].pubkey, DNAC_PUBKEY_SIZE,
                         digest) != 0) break;
        memcpy(g->proposer, digest, 32);
        memcpy(g->chain32, w->v2_chain32, 32);
        g->valid = 1;
        ok = 0;
    } while (0);
    free(allocs);
    free(cfg);
    return ok == 0 ? g : NULL;
}

/**
 * Save the host's block-store record for height `h` inside the open
 * transaction, and report the fields FinalizeBlock's request carries
 * from it. @return 0 saved / 1 not the store's next contiguous height
 * (nothing saved) / -1 fault.
 */
static int v2x_cmt_store_block(nodus_witness_t *w, uint64_t h,
                               uint8_t hash[64], uint8_t next_vals[64],
                               uint8_t proposer[32], uint64_t *seconds) {
    nodus_cmt_store_t s;
    int ret = -1;
    if (nodus_cmt_store_init(&s, w->db, false) != CMT_OK) return -1;
    if (s.base > 0 && (int64_t)h != s.height + 1) {
        nodus_cmt_store_release(&s);
        return 1;
    }
    if (s.base == 0 && h != 1) {
        nodus_cmt_store_release(&s);
        return 1;
    }

    const v2x_cmt_gen_t *g = v2x_cmt_genesis_state(w);
    cmt_state_block_scratch_t *bscratch =
        (cmt_state_block_scratch_t *)calloc(1, sizeof(*bscratch));
    cmt_block_t *blk = (cmt_block_t *)calloc(1, sizeof(*blk));
    const size_t parts_cap = 8;
    const size_t part_scratch_cap = parts_cap * CMT_BLOCK_PART_SIZE_BYTES;
    cmt_part_t *parts = (cmt_part_t *)calloc(parts_cap, sizeof(*parts));
    uint8_t *part_scratch = (uint8_t *)malloc(part_scratch_cap);
    uint8_t meta_scratch[4096];
    do {
        if (!g || !bscratch || !blk || !parts || !part_scratch) break;
        cmt_state_t st = g->state;          /* shares g's storage       */
        st.initial_height = (int64_t)h;     /* the genesis-time branch  */
        cmt_data_t data;
        cmt_commit_t last_commit;
        memset(&data, 0, sizeof(data));
        memset(&last_commit, 0, sizeof(last_commit));
        last_commit.height = (int64_t)h - 1;
        if (cmt_state_make_block(&st, (int64_t)h, &data, &last_commit, NULL,
                                 g->proposer, sizeof(g->proposer),
                                 bscratch, blk) != CMT_OK) break;
        cmt_block_id_t bid;
        memset(&bid, 0, sizeof(bid));
        if (cmt_block_hash(blk, bid.hash) != CMT_OK) break;
        bid.hash_len = CMT_TMHASH_SIZE;
        cmt_part_set_t ps;
        if (cmt_block_make_part_set(blk, CMT_BLOCK_PART_SIZE_BYTES,
                                    part_scratch, part_scratch_cap,
                                    parts, parts_cap, &ps) != CMT_OK) break;
        if (cmt_part_set_header(&ps, &bid.part_set_header) != CMT_OK) break;
        cmt_commit_t seen;
        memset(&seen, 0, sizeof(seen));
        seen.height = (int64_t)h;
        seen.round = 0;
        seen.block_id = bid;
        if (nodus_cmt_bs_save_block(&s, blk, &ps, &seen, meta_scratch,
                                    sizeof(meta_scratch)) != CMT_OK) break;
        memset(hash, 0, 64);
        memcpy(hash, bid.hash, bid.hash_len);
        memset(next_vals, 0, 64);
        memcpy(next_vals, blk->header.next_validators_hash,
               blk->header.next_validators_hash_len > 64
                   ? 64 : blk->header.next_validators_hash_len);
        memset(proposer, 0, 32);
        memcpy(proposer, blk->header.proposer_address,
               blk->header.proposer_address_len > 32
                   ? 32 : blk->header.proposer_address_len);
        *seconds = (uint64_t)blk->header.time.seconds;
        ret = 0;
    } while (0);
    free(part_scratch);
    free(parts);
    free(blk);
    free(bscratch);
    nodus_cmt_store_release(&s);
    return ret;
}

/* The identity a height the store refuses to record is handed with:
 * deterministic per (chain, height), 64 bytes — the Comet hash width
 * (CMT_TMHASH_SIZE) — so no two such probes collide with each other or
 * with a real block hash. */
static void v2x_cmt_probe_ids(const nodus_witness_t *w, nodus_v2_block_t *b) {
    static const uint8_t zero[64];
    uint8_t pre[64];
    size_t n = 0;
    if (memcmp(b->cmt.block_hash, zero, 64) == 0) {
        memcpy(pre, "V2X.CMT.HASH.v1", 15);
        n = 15;
        memcpy(pre + n, w->v2_chain32, 32);
        n += 32;
        for (int i = 0; i < 8; i++)
            pre[n++] = (uint8_t)(b->global_height >> (56 - 8 * i));
        (void)qgp_sha3_512(pre, n, b->cmt.block_hash);
    }
    if (memcmp(b->cmt.validators_hash, zero, 64) == 0) {
        memcpy(pre, "V2X.CMT.VALS.v1", 15);
        n = 15;
        memcpy(pre + n, w->v2_chain32, 32);
        n += 32;
        (void)qgp_sha3_512(pre, n, b->cmt.validators_hash);
    }
}

/**
 * The host around one FinalizeBlock: BEGIN IMMEDIATE, the block-store
 * record, the engine, then COMMIT on 0 — or, with `keep_open`, return 0
 * with the transaction STILL OPEN for the caller to inspect and close
 * (v2x_cmt_refused_probe). A nonzero engine rc is always rolled back.
 */
static int v2x_cmt_host(nodus_witness_t *w, nodus_v2_block_t *b,
                        int keep_open) {
    if (!w || !w->db || !b) return V2X_CMT_FIXTURE_ERR;
    if (!w->v2_successor) {
        fprintf(stderr, "v2x_cmt_apply: not a version-3 chain\n");
        return V2X_CMT_FIXTURE_ERR;
    }
    b->cmt.on = true;
    if (!b->cmt.results) {
        if (b->n_envs + b->n_claims > V2X_RES_MAX) return V2X_CMT_FIXTURE_ERR;
        b->cmt.results = v2x_res;
        b->cmt.results_cap = V2X_RES_MAX;
    }
    if (sqlite3_exec(w->db, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK)
        return V2X_CMT_FIXTURE_ERR;
    {
        /* The host: the decided block's store record first, then the
         * request fields FinalizeBlock copies from it (hash, next
         * validators hash, proposer, time) — ALWAYS the host's, never a
         * value left in `b` by an earlier apply. Only the one
         * duplicate-identity probe hands its own hash in
         * (v2x_cmt_fault_with_hash); it gets no record. */
        int src = 1;
        memset(b->cmt.block_hash, 0, sizeof(b->cmt.block_hash));
        memset(b->cmt.validators_hash, 0, sizeof(b->cmt.validators_hash));
        if (g_v2x_hash_override) {
            memcpy(b->cmt.block_hash, g_v2x_hash_override, 64);
            g_v2x_hash_override = NULL;
        } else {
            uint8_t hash[64], nvh[64], prop[32];
            uint64_t secs = 0;
            src = v2x_cmt_store_block(w, b->global_height, hash, nvh, prop,
                                      &secs);
            if (src < 0) {
                (void)sqlite3_exec(w->db, "ROLLBACK", NULL, NULL, NULL);
                return V2X_CMT_FIXTURE_ERR;
            }
            if (src == 0) {
                memcpy(b->cmt.block_hash, hash, 64);
                memcpy(b->cmt.validators_hash, nvh, 64);
                memcpy(b->proposer_id, prop, 32);
                b->timestamp = secs;
            }
        }
        if (src != 0) v2x_cmt_probe_ids(w, b);
    }
    int rc = nodus_witness_v2_apply_block(w, b);
    if (rc == 0) {
        if (keep_open) return 0;        /* the caller closes it          */
        if (sqlite3_exec(w->db, "COMMIT", NULL, NULL, NULL) != SQLITE_OK) {
            (void)sqlite3_exec(w->db, "ROLLBACK", NULL, NULL, NULL);
            return V2X_CMT_FIXTURE_ERR;
        }
        return 0;
    }
    (void)sqlite3_exec(w->db, "ROLLBACK", NULL, NULL, NULL);
    if (b->out_reason[0])
        fprintf(stderr, "v2x_cmt_apply: height %llu rc %d: %s\n",
                (unsigned long long)b->global_height, rc, b->out_reason);
    return rc;
}

/**
 * Apply `b` through the cometbft lane with the test as the host.
 * @return 0 (committed; per-item codes in b->cmt.results) /
 *         NODUS_V2_INTERNAL_FAULT (rolled back) / V2X_CMT_FIXTURE_ERR.
 */
static int v2x_cmt_apply(nodus_witness_t *w, nodus_v2_block_t *b) {
    return v2x_cmt_host(w, b, 0);
}

/**
 * The cometbft-lane statement of "the block applied": it committed AND
 * every item it carries applied (code 0). 0 / -1.
 */
static int v2x_cmt_apply_ok(nodus_witness_t *w, nodus_v2_block_t *b) {
    int rc = v2x_cmt_apply(w, b);
    if (rc != 0) return -1;
    for (size_t i = 0; i < b->n_envs + b->n_claims; i++) {
        if (b->cmt.results[i].code != NODUS_V2_TX_OK) {
            fprintf(stderr, "v2x_cmt_apply_ok: height %llu item %zu "
                    "refused with code %u\n",
                    (unsigned long long)b->global_height, i,
                    (unsigned)b->cmt.results[i].code);
            return -1;
        }
    }
    return 0;
}

/* The tables EVERY committed block writes whatever its items did: the
 * block row, the claim count and bytes (phase 12c, every claim the
 * block carries), the out-of-root attendance credit of
 * decided_last_commit, and the host's block-store record
 * (cmt_blockstore, v2x_cmt_store_block). Everything else is ledger state
 * an item can move. (The P4 fix round deleted `v2_tx_bytes`.) */
static int v2x_is_block_bookkeeping(const char *name) {
    static const char *const t[] = { "v2_blocks",
                                     "v2_claim_counts", "v2_claim_bytes",
                                     "v2_attendance", "cmt_blockstore" };
    for (size_t i = 0; i < sizeof(t) / sizeof(t[0]); i++)
        if (strcmp(name, t[i]) == 0) return 1;
    return 0;
}

/** v2x_db_digest over every table EXCEPT the per-block bookkeeping. */
static int v2x_ledger_digest(nodus_witness_t *w, uint8_t out[64]) {
    if (!w || !w->db || !out) return -1;
    sqlite3_stmt *ts = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT name FROM sqlite_master WHERE type='table' "
            "  AND name NOT LIKE 'sqlite_%' "
            "UNION ALL "
            "SELECT name FROM sqlite_master WHERE type='table' "
            "  AND name = 'sqlite_sequence' "
            "ORDER BY 1", -1, &ts, NULL) != SQLITE_OK)
        return -1;
    uint8_t *buf = NULL;
    size_t len = 0, cap = 0;
    int rc, ret = -1;
#define V2XL_PUT(p, n) do {                                              \
        if (len + (n) > cap) {                                           \
            size_t nc = (cap ? cap * 2 : 4096);                          \
            while (nc < len + (n)) nc *= 2;                              \
            uint8_t *nb = (uint8_t *)realloc(buf, nc);                   \
            if (!nb) goto done;                                          \
            buf = nb; cap = nc;                                          \
        }                                                                \
        memcpy(buf + len, (p), (n)); len += (n);                         \
    } while (0)
    while ((rc = sqlite3_step(ts)) == SQLITE_ROW) {
        const char *name = (const char *)sqlite3_column_text(ts, 0);
        if (!name) goto done;
        if (v2x_is_block_bookkeeping(name)) continue;
        V2XL_PUT(name, strlen(name) + 1);
        char sql[256];
        snprintf(sql, sizeof(sql), "SELECT * FROM \"%s\" ORDER BY rowid",
                 name);
        sqlite3_stmt *rs = NULL;
        if (sqlite3_prepare_v2(w->db, sql, -1, &rs, NULL) != SQLITE_OK)
            goto done;
        int rrc;
        while ((rrc = sqlite3_step(rs)) == SQLITE_ROW) {
            int nc = sqlite3_column_count(rs);
            for (int c = 0; c < nc; c++) {
                uint8_t t = (uint8_t)sqlite3_column_type(rs, c);
                V2XL_PUT(&t, 1);
                if (t == SQLITE_NULL) continue;
                const void *bl = sqlite3_column_blob(rs, c);
                int bn = sqlite3_column_bytes(rs, c);
                uint32_t bn32 = (uint32_t)bn;
                V2XL_PUT(&bn32, 4);
                if (bn > 0 && bl) V2XL_PUT(bl, (size_t)bn);
            }
        }
        sqlite3_finalize(rs);
        if (rrc != SQLITE_DONE) goto done;
    }
    if (rc != SQLITE_DONE) goto done;
    ret = qgp_sha3_512(buf ? buf : (const uint8_t *)"", len, out) == 0
              ? 0 : -1;
done:
#undef V2XL_PUT
    sqlite3_finalize(ts);
    free(buf);
    return ret;
}

/**
 * The cometbft-lane statement of "the block's items were refused and
 * nothing they did survives": the block COMMITTED, EVERY item it carries
 * got a nonzero code, and the ledger (every table but the per-block
 * bookkeeping above) is byte-identical to its state before the block.
 * `code_out` (may be NULL) receives item `idx`'s code. Valid for a block
 * that crosses no epoch boundary (a boundary moves the ledger by
 * itself). 0 / -1.
 */
static int v2x_cmt_refused(nodus_witness_t *w, nodus_v2_block_t *b,
                           size_t idx, uint32_t *code_out) {
    uint8_t d0[64], d1[64];
    if (v2x_ledger_digest(w, d0) != 0) return -1;
    if (v2x_cmt_apply(w, b) != 0) return -1;
    if (idx >= b->n_envs + b->n_claims) return -1;
    for (size_t i = 0; i < b->n_envs + b->n_claims; i++)
        if (b->cmt.results[i].code == NODUS_V2_TX_OK) return -1;
    if (code_out) *code_out = b->cmt.results[idx].code;
    if (v2x_ledger_digest(w, d1) != 0) return -1;
    return memcmp(d0, d1, 64) == 0 ? 0 : -1;
}

/**
 * The cometbft-lane statement of a NODE FAULT: the engine returned
 * NODUS_V2_INTERNAL_FAULT, the host rolled back, and the WHOLE database
 * (v2x_db_digest, sqlite_sequence included) is byte-identical. 0 / -1.
 */
static int v2x_cmt_fault(nodus_witness_t *w, nodus_v2_block_t *b) {
    uint8_t d0[64], d1[64];
    if (v2x_db_digest(w, d0) != 0) return -1;
    if (v2x_cmt_apply(w, b) != NODUS_V2_INTERNAL_FAULT) return -1;
    if (v2x_db_digest(w, d1) != 0) return -1;
    return memcmp(d0, d1, 64) == 0 ? 0 : -1;
}

/**
 * Where a fault-injection point (nodus_v2_apply_fail_t) sits on the
 * cometbft lane's path through nodus_witness_v2_apply.c:
 *    1  an ITEM-stage point — inside one item's execution (the envelope
 *       leg points 29-33 / 37 / 38 in exec_one_env, the claim stages
 *       16-18 in claim_execute_one): it refuses THAT item (code EXEC /
 *       CLAIM) and the block applies around it;
 *    0  a BLOCK-stage point — on the lane's own path after the items
 *       (BEGIN, the post-stage supply gate, roots, updates, heads,
 *       history, the index, the envelope/claim bytes, the block row,
 *       before the host's commit) or inside the epoch boundary: a node
 *       FAULT the host rolls back;
 *   -1  a point only the deleted legacy lane had (its phase order, its
 *       pre-BEGIN batch stage, its engine-owned COMMIT, its post-commit
 *       window, the in-block pool batches, its header/BlockID build) —
 *       it never fires in this lane, so a test that injects it tests
 *       nothing.
 */
static int v2x_cmt_fail_class(nodus_v2_apply_fail_t pt) {
    switch ((int)pt) {
    case V2AP_FAIL_AFTER_CLAIM_OUTPUT:
    case V2AP_FAIL_AFTER_CLAIM_SPEND:
    case V2AP_FAIL_AFTER_CLAIM_STATE:
    case V2AP_FAIL_AFTER_READ_PLAN:
    case V2AP_FAIL_AFTER_READS:
    case V2AP_FAIL_AFTER_EXEC_HOOK:
    case V2AP_FAIL_AFTER_EFFECT_DECODE:
    case V2AP_FAIL_AFTER_EFFECT_CHARGE:
    case V2AP_FAIL_AFTER_EFFECT_APPLY:
    case V2AP_FAIL_AFTER_LEG_APPLY:
        return 1;
    case V2AP_FAIL_AFTER_BEGIN:
    case V2AP_FAIL_AFTER_SUPPLY_MUT:
    case V2AP_FAIL_AFTER_DOMAIN_ROOTS:
    case V2AP_FAIL_AFTER_UPDATES:
    case V2AP_FAIL_AFTER_HEADS:
    case V2AP_FAIL_AFTER_HISTORY:
    case V2AP_FAIL_AFTER_TX_INDEX:
    case V2AP_FAIL_AFTER_BLOCK_META:
    case V2AP_FAIL_BEFORE_COMMIT:
    case V2AP_FAIL_AFTER_CLAIM_BYTES:
    /* the epoch-boundary stages (nodus_witness_v2_epoch.c) */
    case V2AP_FAIL_AFTER_EPOCH_COMMISSIONS:
    case V2AP_FAIL_AFTER_FIRST_GRAD_RELEASE:
    case V2AP_FAIL_AFTER_FIRST_GRAD_APPLIED:
    case V2AP_FAIL_AFTER_GRAD_BATCH:
    case V2AP_FAIL_AFTER_BOUNDARY_FLIPS:
    case V2AP_FAIL_AFTER_SNAPSHOT_BUILD:
    case V2AP_FAIL_AFTER_SNAPSHOT_PERSIST:
    case V2AP_FAIL_AFTER_ATTENDANCE_DIGEST:
    case V2AP_FAIL_AFTER_ATTENDANCE_RESET:
    case V2AP_FAIL_AFTER_DIST_ACCRUED:
    case V2AP_FAIL_AFTER_DIST_APPLIED:
    case V2AP_FAIL_AFTER_PAYDAY_EMITTED:
    case V2AP_FAIL_AFTER_PAYDAY_APPLIED:
    case V2AP_FAIL_AFTER_BALANCE_COPY:
    case V2AP_FAIL_AFTER_FIRST_GRAD_DELEG_RELEASE:
        return 0;
    default:
        break;
    }
    return -1;
}

/**
 * Apply `b` carrying an injected fault point (b->fail_at) and prove the
 * cometbft lane's class for that point (v2x_cmt_fail_class): an ITEM
 * point refuses every item with the ledger byte-identical
 * (v2x_cmt_refused_probe — the height stays free); a BLOCK point is a
 * FAULT with the whole database byte-identical (v2x_cmt_fault). A
 * legacy-only point is a test error here. 0 / -1.
 */
static int v2x_cmt_refused_probe(nodus_witness_t *w, nodus_v2_block_t *b,
                                 size_t idx, uint32_t *code_out);
static int v2x_reason_is(const nodus_v2_block_t *b, const char *cls,
                         const char *why);

static int v2x_cmt_injected(nodus_witness_t *w, nodus_v2_block_t *b) {
    int cls = v2x_cmt_fail_class(b->fail_at);
    if (cls < 0) {
        fprintf(stderr, "v2x_cmt_injected: fault point %d never fires in "
                "the cometbft lane\n", (int)b->fail_at);
        return -1;
    }
    if (cls == 0) {
        if (v2x_cmt_fault(w, b) != 0) return -1;
        /* and it was THE INJECTION that refused the block, not some
         * other check: a FAIL_POINT labels itself a VERDICT naming the
         * point (apply.c FAIL_POINT); an epoch-boundary stage aborts the
         * boundary, which phase 6e reports as a node FAULT. */
        if ((b->fail_at >= V2AP_FAIL_AFTER_EPOCH_COMMISSIONS &&
             b->fail_at <= V2AP_FAIL_AFTER_SNAPSHOT_PERSIST) ||
            b->fail_at >= V2AP_FAIL_AFTER_ATTENDANCE_DIGEST)
            return v2x_reason_is(b, "FAULT: ", "phase 6e");
        return v2x_reason_is(b, "VERDICT: ", "fault-injection point");
    }
    return v2x_cmt_refused_probe(w, b, 0, NULL);
}

/**
 * v2x_cmt_fault for a block handed a caller-chosen block hash (the
 * duplicate-identity probe: a hash already committed at another
 * height). No block-store record is written for it. 0 / -1.
 */
static int v2x_cmt_fault_with_hash(nodus_witness_t *w, nodus_v2_block_t *b,
                                   const uint8_t hash[64]) {
    g_v2x_hash_override = hash;
    int rc = v2x_cmt_fault(w, b);
    g_v2x_hash_override = NULL;
    return rc;
}

/* The refusal CLASS the engine body labelled a block-level refusal with,
 * before the wrapper folded it into NODUS_V2_INTERNAL_FAULT. */
#define V2X_VERDICT "VERDICT: "      /* a deterministic judgement      */
#define V2X_FAULT   "FAULT: "        /* this node could not compute    */
#define V2X_DEFER   "DEFER: "        /* predecessor state absent here  */

/**
 * `b->out_reason` starts with the class prefix `cls` (V2X_VERDICT /
 * V2X_FAULT / V2X_DEFER — the engine's V2AP_* macros, apply.c) and, when
 * `why` is non-NULL, contains `why`. The wrapper's fold made every
 * block-level refusal one return code; this is what still tells a
 * judgement from a node fault from a deferral, and which check fired.
 * 0 / -1 (the reason printed).
 */
static int v2x_reason_is(const nodus_v2_block_t *b, const char *cls,
                         const char *why) {
    if (!b || !cls) return -1;
    if (strncmp(b->out_reason, cls, strlen(cls)) != 0 ||
        (why && strstr(b->out_reason, why) == NULL)) {
        fprintf(stderr, "v2x_reason_is: wanted \"%s...%s\", the engine "
                "said \"%s\"\n", cls, why ? why : "",
                b->out_reason);
        return -1;
    }
    return 0;
}

/** v2x_cmt_fault AND the refusal's class + reason (v2x_reason_is). */
static int v2x_cmt_fault_why(nodus_witness_t *w, nodus_v2_block_t *b,
                             const char *cls, const char *why) {
    if (v2x_cmt_fault(w, b) != 0) return -1;
    return v2x_reason_is(b, cls, why);
}

/** v2x_cmt_fault_with_hash AND the refusal's class + reason. */
static int v2x_cmt_fault_with_hash_why(nodus_witness_t *w,
                                       nodus_v2_block_t *b,
                                       const uint8_t hash[64],
                                       const char *cls, const char *why) {
    if (v2x_cmt_fault_with_hash(w, b, hash) != 0) return -1;
    return v2x_reason_is(b, cls, why);
}

/**
 * v2x_cmt_refused as a PROBE that leaves the height free: the engine
 * applies `b` in the host's transaction and returns 0 (the block would
 * commit), EVERY item carries a nonzero code, and the ledger — read
 * INSIDE that transaction, after the engine — is byte-identical to its
 * state before the block. Then, instead of committing, the host rolls
 * the block back, and the whole database (v2x_db_digest) is checked
 * byte-identical too, so the test's next block can take the same height
 * — the shape of the many one-refusal-then-retry sequences the legacy
 * lane's all-or-nothing verdict allowed. What the engine did is the same
 * either way; only the host's final decision differs, and it is a test
 * probe's decision, not a node's. `code_out` (may be NULL) receives item
 * `idx`'s code. 0 / -1 (the reason printed).
 */
static int v2x_cmt_refused_probe(nodus_witness_t *w, nodus_v2_block_t *b,
                                 size_t idx, uint32_t *code_out) {
    uint8_t d0[64], d1[64], l0[64], l1[64];
    int ok = -1;
    if (v2x_db_digest(w, d0) != 0 || v2x_ledger_digest(w, l0) != 0)
        return -1;
    int rc = v2x_cmt_host(w, b, 1);
    if (rc != 0) {
        fprintf(stderr, "v2x_cmt_refused_probe: height %llu: the engine "
                "returned %d, not an item refusal in an applied block\n",
                (unsigned long long)b->global_height, rc);
        return -1;
    }
    do {
        if (idx >= b->n_envs + b->n_claims) break;
        size_t i;
        for (i = 0; i < b->n_envs + b->n_claims; i++)
            if (b->cmt.results[i].code == NODUS_V2_TX_OK) break;
        if (i != b->n_envs + b->n_claims) {
            fprintf(stderr, "v2x_cmt_refused_probe: height %llu item %zu "
                    "APPLIED (code 0)\n",
                    (unsigned long long)b->global_height, i);
            break;
        }
        if (code_out) *code_out = b->cmt.results[idx].code;
        if (v2x_ledger_digest(w, l1) != 0) break;
        if (memcmp(l0, l1, 64) != 0) {
            fprintf(stderr, "v2x_cmt_refused_probe: height %llu: a "
                    "refused item moved the ledger\n",
                    (unsigned long long)b->global_height);
            break;
        }
        ok = 0;
    } while (0);
    (void)sqlite3_exec(w->db, "ROLLBACK", NULL, NULL, NULL);
    if (v2x_db_digest(w, d1) != 0 || memcmp(d0, d1, 64) != 0) return -1;
    return ok;
}

#endif /* NODUS_TESTS_V2_GENESIS_FIXTURE_H */
