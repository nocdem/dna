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
/* ── O15J Faz 2 — OPT-IN inflation switch ─────────────────────────────
 *
 * The V1 economics port makes every block mint, and a mint moves both
 * supply_tracking (a CORE root leg) and epoch_state (a SYSTEM leg), so
 * every block now legitimately touches both domains.
 *
 * Several tests built on this fixture predate economics and pin
 * orthogonal properties — touch isolation ("SYSTEM advanced while
 * untouched"), pool-root stability, per-block DomainUpdate counts,
 * metering arithmetic, a supply composition with total_minted == 0.
 * Rewriting those assertions to accept the new movement would delete the
 * property each one exists to protect.
 *
 * A test that needs a quiet chain sets this to 1 BEFORE its first
 * v2x_genesis_min call. It is deliberately OPT-IN, not the default:
 * forcing the row on every fixture changes the committed genesis root
 * (chain_config_history is a SYSTEM leg) and broke five tests that were
 * previously green — measured, not assumed.
 *
 * `static` in a header is correct here: every test is a single TU, so
 * each gets its own copy and no test can affect another. */
static int v2x_inflation_off = 0;

/* Seed the inflation-OFF chain-config row. Idempotent.
 *
 * chain_config_history is a SYSTEM root leg, so this MOVES the SYSTEM
 * payload root — exactly like v2x_seed_authority, and with the same
 * consequence: a fixture that CAPTURES payload roots before genesis must
 * call this itself before capturing, or its captured root will not match
 * the committed one. (Measured: calling it only from inside
 * v2x_genesis_min made test_v2_apply fail its own
 * "SYSTEM gsr != payload root" assertion.)
 *
 * The warm chain-config cache is cleared explicitly: this raw INSERT
 * bypasses the mutate path that would invalidate it, and without that
 * get_u64 keeps serving the 1ULL default and the seed does nothing. */
static int v2x_seed_inflation_off(nodus_witness_t *w) {
    if (!w || !w->db) return -1;
    char cc[320];
    snprintf(cc, sizeof(cc),
        "INSERT OR REPLACE INTO chain_config_history (param_id,"
        " new_value, effective_block, commit_block, tx_hash,"
        " proposal_nonce, created_at_unix)"
        " VALUES (%d, 0, 0, 0, zeroblob(64), 0, 0)",
        (int)DNAC_CFG_INFLATION_START_BLOCK);
    char *cerr = NULL;
    if (sqlite3_exec(w->db, cc, NULL, NULL, &cerr) != SQLITE_OK) {
        if (cerr) sqlite3_free(cerr);
        return -1;
    }
    w->chain_config_cache_warm = false;
    return 0;
}

static int v2x_genesis_min(nodus_witness_t *w, const uint8_t vset[64],
                           uint8_t out_gid[64], uint8_t out_chain[32]) {
    if (!w || !w->db || !vset) return -1;

    if (v2x_inflation_off && v2x_seed_inflation_off(w) != 0) return -1;

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
        int srv = nodus_witness_supply_init(w, 0, zero_hash);
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

#endif /* NODUS_TESTS_V2_GENESIS_FIXTURE_H */
