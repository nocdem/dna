/**
 * @file nodus/tests/v2_genesis_fixture.h
 * @brief Ledger V2 O14 — canonical minimal V2 genesis for tests.
 *
 * The apply engine now DERIVES the genesis BlockID
 * (dna_bh2_genesis_block_id), and that preimage takes the canonical
 * GenesisManifest bytes as an EXPLICIT input (shared/dnac/block_v2.h).
 * A genesis with no manifest therefore has no defined identity and the
 * engine refuses it, so every fixture must hand it real manifest bytes.
 *
 * This header exists separately from v2_exec_fixture.h because the tests
 * that need genesis are not the same set as the tests that need the
 * scripted execution runtimes, and pulling the whole exec fixture into
 * them would collide with their own local helpers.
 *
 * ⚠ TWO FIXTURES LIVE HERE (tokenomics-v3 P4).
 *   v2x_genesis_min & co. (below) — the VERSION-2 engine genesis
 *     (nodus_witness_v2_genesis_ex) over hand-seeded state, driven through
 *     the legacy (non-cmt) block lane. It is NOT the chain a node runs:
 *     no stored genesis document, a height-0 v2_blocks row,
 *     validator_stats.active_count left at 0. It stays because the
 *     ledger-engine tests that still use it (test_v2_apply, _claims,
 *     _econ, _epoch, _exec, _native, _pools, _schema,
 *     _deleg_cap_bench, _committee_seed §7, and test_cmt_app's
 *     chain_id row-branch case) drive the legacy block lane and/or seed
 *     genesis states a version-3 config cannot express (sub-10M or zero
 *     stakes, other than 7 validators, genesis UTXOs / delegations, zero
 *     supply). Some of them could move to the fixture below; P4 did not
 *     reach them. Its removal is the open half of OBLIGATION
 *     atlas-dec-71525f3b (see the P4 report).
 *   v2x_chain_open & co. (at the end) — a REAL version-3 chain: the
 *     ceremony's derivation + the production open path. New tests use
 *     this one.
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

/**
 * Commit a minimal, absent-distribution V2 genesis over the REAL
 * registry domain-manifest hashes and report the ENGINE-DERIVED genesis
 * BlockID.
 *
 * The genesis header binds the engine's own derived global root, which a
 * fixture cannot know before genesis runs — so this commits in leader
 * mode (assertion omitted) and reads the committed identity back. That
 * IS the O14 contract: the engine derives, the caller observes. A test
 * that wants to ASSERT a genesis id calls nodus_witness_v2_genesis_ex
 * directly with a non-NULL first argument.
 *
 * `genesis_supply_raw` is read back from supply_tracking so the manifest
 * can never disagree with whatever supply the fixture seeded.
 *
 * @param out_gid   receives the 64-byte derived genesis BlockID (may be NULL)
 * @param out_chain receives the 32-byte derived chain id (may be NULL)
 * @return 0 / -1.
 */
/* `fill` seeds the filler validator's pubkey. Varying it produces a
 * DIFFERENT committed validator set, hence a different vset hash, hence
 * a different genesis BlockID and chain id — which is the semantically
 * honest way for a fixture to be "another chain" now that genesis must
 * bind the committed authority (O14 review R1-F2). Call this BEFORE
 * v2x_genesis_min to choose the set; v2x_genesis_min's own call then
 * skips, because snapshots already exist. */
static int v2x_seed_authority_fill(nodus_witness_t *w, uint8_t fill) {
    if (!w || !w->db) return -1;

    /* ── O14 PRECONDITION, and it must come FIRST ─────────────────────
     * A V2 chain needs COMMITTED validator authority from genesis
     * onward: the apply engine resolves the governing snapshot for every
     * block (pre-BEGIN, block-start) and an absent snapshot is a node
     * FAULT, never a fallback to some current set — the O12 resolver
     * contract.
     *
     * ORDERING IS LOAD-BEARING. `nodus_witness_domreg_init_genesis`
     * commits each domain's `genesis_state_root`, and genesis_ex RE-RUNS
     * it and BYTE-COMPARES, so consensus state must not move in between
     * (the same hazard test_v2_claims.c:651-653 documents). The
     * validator rows and snapshots feed the SYSTEM payload root, so they
     * must exist BEFORE the registry commits it — otherwise genesis
     * fails its own idempotency check.
     *
     * Skipped when the fixture already seeded its own set, since
     * re-running the genesis hook over those would conflict. */
    {
        sqlite3_stmt *st = NULL;
        sqlite3_int64 n_snap = -1;
        if (sqlite3_prepare_v2(w->db,
                "SELECT COUNT(*) FROM validator_set_snapshots", -1, &st,
                NULL) != SQLITE_OK)
            return -1;
        if (sqlite3_step(st) == SQLITE_ROW)
            n_snap = sqlite3_column_int64(st, 0);
        sqlite3_finalize(st);
        if (n_snap < 0) return -1;

        if (n_snap == 0) {
            /* The snapshot builder reads the validators table, so it
             * needs at least one row to produce a non-empty set. These
             * are deterministic filler keys: this helper's snapshots
             * exist to give the engine an AUTHORITY to resolve, not to
             * verify signatures — QC verification is exercised against
             * real ML-DSA-87 keys in test_v2_qc_authority. */
            sqlite3_int64 n_val = -1;
            if (sqlite3_prepare_v2(w->db,
                    "SELECT COUNT(*) FROM validators", -1, &st, NULL)
                != SQLITE_OK)
                return -1;
            if (sqlite3_step(st) == SQLITE_ROW)
                n_val = sqlite3_column_int64(st, 0);
            sqlite3_finalize(st);
            if (n_val < 0) return -1;

            if (n_val == 0) {
                dnac_validator_record_t v;
                memset(&v, 0, sizeof(v));
                for (size_t i = 0; i < sizeof(v.pubkey); i++)
                    v.pubkey[i] = (uint8_t)(fill + (i & 0x3F));
                /* self_stake MUST be 0 here: the CORE supply invariant
                 * counts Σself_stake, so a bonded filler validator would
                 * silently unbalance every fixture that seeded its own
                 * supply. This row exists to give the snapshot builder an
                 * ACTIVE member, not to model stake. */
                v.self_stake         = 0;
                v.status             = DNAC_VALIDATOR_ACTIVE;
                v.active_since_block = 1;
                /* The fingerprint is 128 lowercase hex chars + NUL — the
                 * validator merkle leaf loader fails CLOSED on a
                 * malformed row, which would take the SYSTEM payload
                 * root (and therefore genesis) down with it. */
                memset(v.unstake_destination_fp, '5',
                       sizeof(v.unstake_destination_fp));
                v.unstake_destination_fp[128] = '\0';
                if (nodus_validator_insert(w, &v) != 0) return -1;
            }
            /* The argument is the BLOCK HEIGHT, not a count: the hook
             * no-ops unless it equals VSET_GENESIS_BLOCK_HEIGHT (1 —
             * blocks.height is AUTOINCREMENT, so legacy genesis is 1). */
            if (nodus_witness_vset_commit_genesis(w, 1) != 0) return -1;
        }
    }

    return 0;
}

/** The ordinary set: one filler validator, deterministic pubkey. */
static int v2x_seed_authority(nodus_witness_t *w) {
    return v2x_seed_authority_fill(w, 0x40);
}

/**
 * Commit a minimal, absent-distribution V2 genesis over the REAL
 * registry domain-manifest hashes and report the ENGINE-DERIVED genesis
 * BlockID. Calls v2x_seed_authority() first (idempotent), so a fixture
 * that does not care about root-capture ordering gets the precondition
 * for free; a fixture that captures payload roots BEFORE genesis must
 * call v2x_seed_authority() itself before capturing, since seeding the
 * validator set moves the SYSTEM payload root.
 *
 * Commits in leader mode (assertion omitted) and reads the committed
 * identity back — the engine derives, the caller observes.
 */
/* tokenomics-v3 P2 — the O15J "OPT-IN inflation switch"
 * (v2x_inflation_off / v2x_seed_inflation_off) that stood here is
 * DELETED. It existed because the O15J per-block mint made every block
 * touch CORE and SYSTEM; the mint is gone (decision file §1 "Yeni token
 * basılmayacak") and parameter id 3 it seeded is retired, so EVERY
 * fixture chain is quiet now and the switch had nothing left to switch. */

static int v2x_genesis_min(nodus_witness_t *w, const uint8_t vset[64],
                           uint8_t out_gid[64], uint8_t out_chain[32]) {
    if (!w || !w->db || !vset) return -1;

    if (v2x_seed_authority(w) != 0) return -1;
    if (nodus_witness_domreg_init_genesis(w) != 0) return -1;

    dna_domain_manifest_t dm;
    uint8_t sys_h[64], core_h[64];
    if (nodus_witness_domreg_get(w, DNA_DOMAIN_SYSTEM, NULL, &dm, NULL) != 0)
        return -1;
    if (dna_domman_hash(&dm, sys_h) != 0) return -1;
    if (nodus_witness_domreg_get(w, DNA_DOMAIN_CORE, NULL, &dm, NULL) != 0)
        return -1;
    if (dna_domman_hash(&dm, core_h) != 0) return -1;

    /* O15J L2-F1 — the supply row must EXIST before a V2 genesis is
     * committed. It used to be legitimate for this fixture to leave it
     * absent: nodus_rt_core_invariant returned 0 unconditionally on
     * `sup_rc == 1`, so the conservation equation was SKIPPED (not
     * satisfied) and the COALESCE below read the absence as 0. That is
     * the CRITICAL hole the red-team found — an absent row disables the
     * invariant for the LIFE of the chain — and the invariant now fails
     * closed once a committed V2 genesis exists.
     *
     * The fixture's intent is unchanged: these are ZERO-supply chains
     * (the validator rows deliberately carry self_stake = 0, see the
     * comment above), so a row holding genesis_supply = 0 expresses
     * exactly what the fixture always meant, and the equation now
     * genuinely evaluates: 0 == 0. supply_init carries its own
     * already-initialized probe, so a test that seeded its own supply
     * first keeps that value. */
    {
        uint8_t zero_hash[64];
        memset(zero_hash, 0, sizeof(zero_hash));
        /* -2 == "already initialized" (nodus_witness_db.c:952) — a test
         * that seeded its own supply BEFORE calling the fixture keeps
         * that value, and that is the expected path, not an error.
         * Anything else is a genuine failure. */
        /* tokenomics-v3 P2: a zero-supply chain reserves no reward pool
         * either — the distribution pays nothing on these fixtures unless
         * a test seeds its own supply row (with a pool) first. */
        int srv = nodus_witness_supply_init(w, 0, 0, zero_hash);
        if (srv != 0 && srv != -2) return -1;
    }

#ifdef NODUS_V2_TEST_SUPPLY
    /* O15J — the three engine-level targets that drive synthetic
     * value-creating envelopes arm the test-only conservation bypass
     * here, so no per-test edit is needed and every other consumer of
     * this fixture keeps the live invariant. The symbol does not exist
     * outside those targets (CMakeLists.txt register_witness_test_supply_bypass). */
    nodus_witness_v2_supply_test_bypass(1);
#endif

    uint64_t supply = 0;
    {
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(w->db,
                "SELECT COALESCE(genesis_supply,0) FROM supply_tracking "
                "WHERE id = 1", -1, &st, NULL) != SQLITE_OK)
            return -1;
        if (sqlite3_step(st) == SQLITE_ROW)
            supply = (uint64_t)sqlite3_column_int64(st, 0);
        sqlite3_finalize(st);
    }

    dna_gman_t m;
    memset(&m, 0, sizeof(m));
    m.manifest_version   = DNA_GMAN_VERSION;
    m.genesis_supply_raw = supply;
    m.domain_count       = 2;
    m.domains[0].domain_id = DNA_DOMAIN_SYSTEM;
    memcpy(m.domains[0].manifest_hash, sys_h, 64);
    m.domains[1].domain_id = DNA_DOMAIN_CORE;
    memcpy(m.domains[1].manifest_hash, core_h, 64);
    m.dist_present = 0;

    uint8_t mbytes[8192];
    size_t mlen = 0;
    if (dna_gman_encode(&m, mbytes, sizeof(mbytes), &mlen) != 0) return -1;

    /* O14 PRECONDITION: a V2 chain needs COMMITTED validator authority
     * from genesis onward. The apply engine resolves the governing
     * snapshot for every block (pre-BEGIN, block-start) and an absent
     * snapshot is a node FAULT, never a fallback to some current set —
     * that is the O12 resolver contract. Seed the genesis snapshots here
     * so fixtures get the precondition without each restating it.
     *
     * Ordering matters and is not cosmetic: validator_set_snapshots
     * feeds the vset leg of system_state_root, so the rows must exist
     * BEFORE genesis computes the SYSTEM head root. Seeding afterwards
     * is an out-of-band SYSTEM mutation and the untouched-domain guard
     * rejects the first driven block.
     *
     * Seeded only when the fixture has not already done it itself —
     * some fixtures seed their own validator set and snapshots, and
     * re-running the genesis hook over those would conflict. */
    {
        sqlite3_stmt *st = NULL;
        sqlite3_int64 n_snap = -1;
        if (sqlite3_prepare_v2(w->db,
                "SELECT COUNT(*) FROM validator_set_snapshots", -1, &st,
                NULL) != SQLITE_OK)
            return -1;
        if (sqlite3_step(st) == SQLITE_ROW)
            n_snap = sqlite3_column_int64(st, 0);
        sqlite3_finalize(st);
        if (n_snap < 0) return -1;
        if (n_snap == 0 && nodus_witness_vset_commit_genesis(w, 1) != 0)
            return -1;
    }

    /* O14 review R1-F2: genesis binds validator_set_hash into the chain
     * identity, and the engine now requires it to EQUAL the committed
     * epoch-0 authority — otherwise it would be the one header field
     * with two authoritative producers. So the fixture must hand over
     * the COMMITTED hash, not an arbitrary one. `vset` is therefore
     * advisory: it is used only when no snapshot is committed. */
    uint8_t vsh[DNA_VSET_HASH_LEN];
    memcpy(vsh, vset, DNA_VSET_HASH_LEN);
    {
        dna_vset_snapshot_t *s0 = NULL;
        uint32_t sn = 0, sq = 0;
        if (nodus_witness_v2_epoch_authority_for_height(w, 0, &s0, &sn,
                                                        &sq) == 0 && s0) {
            int hrc = dna_vset_hash(s0, vsh);
            dna_vset_free(&s0);
            if (hrc != 0) return -1;
        } else {
            dna_vset_free(&s0);
        }
    }

    if (nodus_witness_v2_genesis_ex(w, NULL, vsh, 0, mbytes, mlen) != 0)
        return -1;

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT block_id FROM v2_blocks WHERE global_height = 0",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    int ok = 0;
    if (sqlite3_step(st) == SQLITE_ROW &&
        sqlite3_column_bytes(st, 0) == 64) {
        const uint8_t *bid = (const uint8_t *)sqlite3_column_blob(st, 0);
        if (out_gid)   memcpy(out_gid, bid, 64);
        if (out_chain) memcpy(out_chain, bid, 32);   /* chain = id[0..31] */
        ok = 1;
    }
    sqlite3_finalize(st);
    return ok ? 0 : -1;
}

/**
 * Read the ENGINE-DERIVED BlockID committed at `height`.
 *
 * O14 tests need this constantly: since no caller chooses an id any
 * more, the only way to assert one (expect_block_id) is to read the one
 * the engine actually derived.
 *
 * @return 0 with `out` filled / -1 if no such row or it is malformed.
 */
static int v2x_block_id_at(nodus_witness_t *w, uint64_t height,
                           uint8_t out[64]) {
    if (!w || !w->db || !out) return -1;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT block_id FROM v2_blocks WHERE global_height = ?1",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)height);
    int ok = 0;
    if (sqlite3_step(st) == SQLITE_ROW &&
        sqlite3_column_bytes(st, 0) == 64) {
        memcpy(out, sqlite3_column_blob(st, 0), 64);
        ok = 1;
    }
    sqlite3_finalize(st);
    return ok ? 0 : -1;
}

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
 * WHY IT EXISTS. v2x_genesis_min above builds a chain the real genesis
 * never builds (no stored document, a height-0 v2_blocks row,
 * active_count left at 0, a zero-supply manifest with no distribution).
 * Files converted to this fixture test the chain shape that runs.
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
    return 0;
}

#endif /* NODUS_TESTS_V2_GENESIS_FIXTURE_H */
