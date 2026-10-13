/**
 * @file nodus/tests/test_hf6_power.c
 * @brief HF-6 slice 5b — THE ONE voting-power helper of a validator-set
 *        snapshot (nodus_witness_vset_powers) and its ratio seam
 *        (nodus_witness_power_cap_bps_for_epoch).
 *
 * Design docs/plans/2026-10-03-hf5-validator-owner-stake-design.md rev 6
 * §5 ("Güç tavanı — tek fonksiyon": v1 snapshot → uncapped, v2 → capped;
 * the three examples), §8 (param 20 POWER_CAP_BPS, default 3000, range
 * [500, 3000]); decisions docs/plans/decisions/2026-10-08-kurultay-14-
 * hf6-summary.md K1 / K2 / K5; plan tasks/hf6-slice5-plan.md §2 "5b".
 *
 * ── WHAT IT PROVES ──────────────────────────────────────────────────────
 *  1. With no param-20 row the ratio is the compiled
 *     DNAC_HF6_POWER_CAP_BPS_DEFAULT (3000) for any epoch start, and a
 *     NULL output / witness is refused. (The default's range is pinned at
 *     compile time by a _Static_assert in nodus_witness_vset.c — this
 *     binary would not link without it.)
 *  2. The design's twin vectors through the helper on hand-built
 *     RULESET-2 snapshots, amounts as raw stake (whole × 10^8):
 *     [88,2×6] → [5,2×6]; [45,45,10] → [10,10,10]; [10]×7 → unchanged —
 *     the values power_cap.h derives step by step and
 *     nodus/tests/test_power_cap.c pins against the independent oracle.
 *     Output is in the snapshot's own entry order (the 88 placed last
 *     still yields 5 there); a sub-coin remainder is floored before the
 *     cap (88×10^8 + 10^8−1 counts as 88).
 *  3. A RULESET-1 snapshot is the identity total_stake / 10^8 — the
 *     pre-slice-5 derivation every consumer used — including the same
 *     [88,2×6] vector (NOT capped) and a zero-power entry (10^8 − 1 raw
 *     → 0, returned as 0, not refused).
 *  4. Fail-closed: a ruleset-2 entry below one whole coin → -1 with the
 *     output untouched; ruleset 0 and ruleset 3 → -1; NULL witness /
 *     snapshot / output → -1.
 *  5. HF-6 slice 8a — the ratio is chain_config param 20 read at the
 *     snapshot's EPOCH START: a row of 500 effective at 10E answers 500
 *     at 10E and 11E and the default at 10E - 1; a row effective at
 *     12E + 1 does NOT count for the snapshot starting at 12E (it answers
 *     from 13E); the helper's output for a ruleset-2 snapshot at 10E
 *     equals dna_power_cap_counted at 500 (and differs from the 3000
 *     answer — non-vacuous); a stored 499, 3001 or a value stored
 *     negative (2^63) answers -1 with the output untouched and every
 *     ruleset-2 power computation over that epoch refuses, while a
 *     ruleset-1 snapshot (which never reads the ratio) is unaffected; no
 *     open DB answers -1, never the default.
 *
 * ── WHAT IT DOES NOT PROVE (the consumers — where they are covered) ────
 * The consumers on a STORED RULESET-2 snapshot (slice 5c made the store /
 * read path accept both rulesets):
 *   - the reward shares (Σcounted denominator, raw inner split — K2):
 *     test_hf6_readers case E5 ([60M, 10M × 6] → [25714285, 10M × 6]
 *     through nodus_witness_v2_settlement_apply);
 *   - the storage report weight (F1 on counted powers): test_storage_b2
 *     case E (engine_v2_power);
 *   - the Comet boundary diff, OLD side only: test_cmt_app
 *     val_updates_v2_old_side. The NEW side (snapshot(H) governs block H,
 *     and the engine's per-block phase 0a still hashes the governing
 *     snapshot with the ruleset-1-only codec) and Rule N's verdict (its
 *     preview is built ruleset 1 until slice 5d, and the verdict function
 *     is file-static) are NOT covered before slice 5d; stated, not faked.
 * Each consumer is a one-line call of this helper; its ruleset-1 identity
 * is covered by that consumer's existing fixtures (test_v2_epoch,
 * test_v2_econ, test_storage_*, test_cmt_app) staying byte-identical, and
 * the committee cache's by test_committee_cache.
 *
 * ── WHAT IT REQUIRES ────────────────────────────────────────────────────
 * Compile flags: none beyond a default nodus build (registered with the
 * other HF-6 tests under NODUS_EVM_ENABLED; the helper itself does not
 * need the EVM runtime). Environment: none.
 *
 * ── WHAT IT LEAVES BEHIND ───────────────────────────────────────────────
 * One /tmp/test_hf6_power_* directory (a chain DB the witness handle
 * owns — the ratio is a chain-config read since HF-6 slice 8a), removed
 * at the end (left behind when a CHECK aborts).
 *
 * ── HOW IT CAN LIE ──────────────────────────────────────────────────────
 *  - The expected vectors are design §5's own examples (reproduced in
 *    power_cap.h and pinned by test_power_cap against the oracle), not a
 *    new independent oracle run.
 *  - Case 5 writes the param-20 rows straight into chain_config_history
 *    (the test_hf4_params.c direct_insert device), not through a voted
 *    CHAIN_CONFIG envelope: it proves the read, its key and its range
 *    check, not the vote (test_hf4_params.c covers the vote's rules) nor
 *    the frozen-ratio timing at a real boundary (the grace >= epoch
 *    premise is a _Static_assert in nodus_witness_vset.c).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_vset.h"
#include "witness/nodus_witness_emission.h"   /* DNAC_DECIMAL_UNIT */

#include "dnac/dnac.h"
#include "dnac/power_cap.h"
#include "dnac/vset_wire.h"

#include <dirent.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static int g_checks = 0;

#define CHECK(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK fail at %s:%d: %s\n", \
                __FILE__, __LINE__, #cond); \
        exit(1); \
    } \
    g_checks++; \
} while (0)

#define U DNAC_DECIMAL_UNIT

static void rmrf(const char *path) {
    DIR *d = opendir(path);
    if (d) {
        struct dirent *ent;
        while ((ent = readdir(d)) != NULL) {
            if (strcmp(ent->d_name, ".") == 0 ||
                strcmp(ent->d_name, "..") == 0) continue;
            char child[1024];
            snprintf(child, sizeof(child), "%s/%s", path, ent->d_name);
            struct stat st;
            if (lstat(child, &st) == 0) {
                if (S_ISDIR(st.st_mode)) rmrf(child);
                else (void)unlink(child);
            }
        }
        closedir(d);
        (void)rmdir(path);
    } else {
        (void)unlink(path);
    }
}

/* A hand-built snapshot: entry i gets raw total_stake[i], a distinct
 * pubkey / validator_id / owner_fp (byte i + 1 so none is all-zero), and
 * self_bond = total (the helper never reads it). */
static dna_vset_snapshot_t *mk_snap(uint32_t ruleset, uint64_t epoch,
                                    const uint64_t *raw, uint16_t n) {
    dna_vset_snapshot_t *s = dna_vset_alloc(n);
    CHECK(s != NULL);
    s->epoch = epoch;
    s->selection_ruleset = ruleset;
    for (uint16_t i = 0; i < n; i++) {
        dna_vset_entry_t *e = &s->entries[i];
        memset(e->pubkey, (int)(i + 1), DNA_VSET_PUBKEY_LEN);
        e->total_stake = raw[i];
        e->self_bond   = raw[i];
        e->commission_bps = 500;
        if (ruleset == DNA_VSET_RULESET_TOPN_V2) {
            memset(e->validator_id, (int)(0x40 + i), DNA_VSET_VALIDATOR_ID_LEN);
            memset(e->owner_fp, (int)(0x80 + i), DNA_VSET_OWNER_FP_LEN);
        }
    }
    return s;
}

/* Run the helper over (ruleset, raw[]) and compare with expect[]. */
static void expect_powers(nodus_witness_t *w, uint32_t ruleset,
                          const uint64_t *raw, uint16_t n,
                          const uint64_t *expect) {
    dna_vset_snapshot_t *s = mk_snap(ruleset, 6 * (uint64_t)DNAC_EPOCH_LENGTH,
                                     raw, n);
    uint64_t out[DNA_MAX_ACTIVE_VALIDATORS];
    memset(out, 0xA5, sizeof(out));
    CHECK(nodus_witness_vset_powers(w, s, out) == 0);
    for (uint16_t i = 0; i < n; i++) CHECK(out[i] == expect[i]);
    /* the snapshot itself is never modified: total_stake stays raw */
    for (uint16_t i = 0; i < n; i++) CHECK(s->entries[i].total_stake == raw[i]);
    dna_vset_free(&s);
}

/* The helper refuses and leaves `out` untouched. */
static void expect_refused(nodus_witness_t *w, dna_vset_snapshot_t *s) {
    uint64_t out[DNA_MAX_ACTIVE_VALIDATORS];
    memset(out, 0xA5, sizeof(out));
    CHECK(nodus_witness_vset_powers(w, s, out) == -1);
    for (size_t i = 0; i < DNA_MAX_ACTIVE_VALIDATORS; i++)
        CHECK(out[i] == 0xA5A5A5A5A5A5A5A5ULL);
}

/* HF-6 slice 8a: one chain_config_history row written straight into the
 * table (the test_hf4_params.c device) — how a row the scalar rule never
 * admits can exist at all (a corrupt / foreign DB); the cache is dropped
 * so the next read sees it. */
static void direct_insert(nodus_witness_t *w, uint8_t param, uint64_t value,
                          uint64_t effective) {
    uint8_t tx_hash[64];
    memset(tx_hash, (int)(effective & 0xFF), sizeof(tx_hash));
    sqlite3_stmt *st = NULL;
    CHECK(sqlite3_prepare_v2(w->db,
              "INSERT INTO chain_config_history (param_id, new_value, "
              "effective_block, commit_block, tx_hash, proposal_nonce, "
              "created_at_unix) VALUES (?1, ?2, ?3, 1, ?4, 1, 0)",
              -1, &st, NULL) == SQLITE_OK);
    sqlite3_bind_int(st, 1, param);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)value);
    sqlite3_bind_int64(st, 3, (sqlite3_int64)effective);
    sqlite3_bind_blob(st, 4, tx_hash, 64, SQLITE_TRANSIENT);
    CHECK(sqlite3_step(st) == SQLITE_DONE);
    sqlite3_finalize(st);
    w->chain_config_cache_warm = false;
}

int main(void) {
    char data_path[] = "/tmp/test_hf6_power_XXXXXX";
    CHECK(mkdtemp(data_path) != NULL);

    static nodus_witness_t w;   /* multi-MB — static storage, not stack */
    memset(&w, 0, sizeof(w));
    snprintf(w.data_path, sizeof(w.data_path), "%s", data_path);
    w.cached_committee_epoch_start = UINT64_MAX;
    uint8_t chain_id[16];
    memset(chain_id, 0xC5, sizeof(chain_id));
    CHECK(nodus_witness_create_chain_db(&w, chain_id) == 0);

    /* ── 1. the ratio seam ─────────────────────────────────────────── */
    printf("  (1) POWER_CAP_BPS with no row = compiled default\n");
    {
        uint32_t r = 0;
        CHECK(DNAC_HF6_POWER_CAP_BPS_DEFAULT == 3000u);
        CHECK(nodus_witness_power_cap_bps_for_epoch(&w, 0, &r) == 0);
        CHECK(r == DNAC_HF6_POWER_CAP_BPS_DEFAULT);
        r = 0;
        CHECK(nodus_witness_power_cap_bps_for_epoch(
                  &w, 7 * (uint64_t)DNAC_EPOCH_LENGTH, &r) == 0);
        CHECK(r == DNAC_HF6_POWER_CAP_BPS_DEFAULT);
        CHECK(r >= DNA_POWER_CAP_BPS_MIN && r <= DNA_POWER_CAP_BPS_MAX);
        CHECK(nodus_witness_power_cap_bps_for_epoch(&w, 0, NULL) == -1);
        CHECK(nodus_witness_power_cap_bps_for_epoch(NULL, 0, &r) == -1);
    }

    /* ── 2. the design §5 twin vectors, ruleset 2 ──────────────────── */
    printf("  (2) ruleset 2: §5 vectors through the helper (capped)\n");
    {
        const uint64_t a_raw[7] = { 88 * U, 2 * U, 2 * U, 2 * U, 2 * U,
                                    2 * U, 2 * U };
        const uint64_t a_exp[7] = { 5, 2, 2, 2, 2, 2, 2 };
        expect_powers(&w, DNA_VSET_RULESET_TOPN_V2, a_raw, 7, a_exp);

        /* caller order: the 88 placed LAST still gets 5 there */
        const uint64_t a2_raw[7] = { 2 * U, 2 * U, 2 * U, 2 * U, 2 * U,
                                     2 * U, 88 * U };
        const uint64_t a2_exp[7] = { 2, 2, 2, 2, 2, 2, 5 };
        expect_powers(&w, DNA_VSET_RULESET_TOPN_V2, a2_raw, 7, a2_exp);

        /* a sub-coin remainder is floored before the cap */
        const uint64_t a3_raw[7] = { 88 * U + (U - 1), 2 * U, 2 * U, 2 * U,
                                     2 * U, 2 * U, 2 * U + (U - 1) };
        expect_powers(&w, DNA_VSET_RULESET_TOPN_V2, a3_raw, 7, a_exp);

        const uint64_t b_raw[3] = { 45 * U, 45 * U, 10 * U };
        const uint64_t b_exp[3] = { 10, 10, 10 };
        expect_powers(&w, DNA_VSET_RULESET_TOPN_V2, b_raw, 3, b_exp);

        const uint64_t c_raw[7] = { 10 * U, 10 * U, 10 * U, 10 * U, 10 * U,
                                    10 * U, 10 * U };
        const uint64_t c_exp[7] = { 10, 10, 10, 10, 10, 10, 10 };
        expect_powers(&w, DNA_VSET_RULESET_TOPN_V2, c_raw, 7, c_exp);

        /* the helper is exactly dna_power_cap_counted at the seam's ratio
         * over p = total / 10^8 and the entries' validator_ids */
        dna_vset_snapshot_t *s = mk_snap(DNA_VSET_RULESET_TOPN_V2, 0,
                                         a_raw, 7);
        uint64_t p[7], direct[7], via[7];
        uint8_t ids[7][64];
        for (int i = 0; i < 7; i++) {
            p[i] = a_raw[i] / U;
            memcpy(ids[i], s->entries[i].validator_id, 64);
        }
        CHECK(dna_power_cap_counted(p, (const uint8_t (*)[64])ids, 7,
                                    DNAC_HF6_POWER_CAP_BPS_DEFAULT,
                                    direct) == 0);
        CHECK(nodus_witness_vset_powers(&w, s, via) == 0);
        CHECK(memcmp(direct, via, sizeof(via)) == 0);
        dna_vset_free(&s);
    }

    /* ── 3. ruleset 1: the identity total / 10^8, zero allowed ──────── */
    printf("  (3) ruleset 1: identity, uncapped, zero allowed\n");
    {
        const uint64_t a_raw[7] = { 88 * U, 2 * U, 2 * U, 2 * U, 2 * U,
                                    2 * U, 2 * U };
        const uint64_t a_exp[7] = { 88, 2, 2, 2, 2, 2, 2 };
        expect_powers(&w, DNA_VSET_RULESET_TOPN_V1, a_raw, 7, a_exp);

        const uint64_t z_raw[4] = { 10 * U + (U - 1), U - 1, 0, 3 * U };
        const uint64_t z_exp[4] = { 10, 0, 0, 3 };
        expect_powers(&w, DNA_VSET_RULESET_TOPN_V1, z_raw, 4, z_exp);
    }

    /* ── 4. fail-closed ─────────────────────────────────────────────── */
    printf("  (4) refusals: ruleset-2 zero power, unknown ruleset, NULLs\n");
    {
        const uint64_t z_raw[3] = { 10 * U, U - 1, 10 * U };
        dna_vset_snapshot_t *s = mk_snap(DNA_VSET_RULESET_TOPN_V2, 0,
                                         z_raw, 3);
        expect_refused(&w, s);                 /* p_1 == 0 under v2     */
        s->entries[1].total_stake = 0;
        expect_refused(&w, s);
        dna_vset_free(&s);

        const uint64_t ok_raw[2] = { 10 * U, 10 * U };
        s = mk_snap(DNA_VSET_RULESET_TOPN_V1, 0, ok_raw, 2);
        s->selection_ruleset = DNA_VSET_RULESET_INVALID;
        expect_refused(&w, s);
        s->selection_ruleset = 3u;
        expect_refused(&w, s);

        uint64_t out[DNA_MAX_ACTIVE_VALIDATORS];
        s->selection_ruleset = DNA_VSET_RULESET_TOPN_V1;
        CHECK(nodus_witness_vset_powers(NULL, s, out) == -1);
        CHECK(nodus_witness_vset_powers(&w, NULL, out) == -1);
        CHECK(nodus_witness_vset_powers(&w, s, NULL) == -1);
        dna_vset_free(&s);
    }

    /* ── 5. HF-6 slice 8a: the ratio is chain_config param 20 at the
     *       snapshot's EPOCH START ─────────────────────────────────── */
    printf("  (5) POWER_CAP_BPS = param 20 at the epoch start; "
           "out-of-range rows refused\n");
    {
        const uint64_t E = (uint64_t)DNAC_EPOCH_LENGTH;
        uint32_t r = 0;
        /* a committed 500 effective at 10E governs the snapshot whose
         * epoch start is 10E, and every later one until the next row */
        direct_insert(&w, 20, 500u, 10 * E);
        CHECK(nodus_witness_power_cap_bps_for_epoch(&w, 10 * E - 1, &r) == 0
              && r == DNAC_HF6_POWER_CAP_BPS_DEFAULT);
        CHECK(nodus_witness_power_cap_bps_for_epoch(&w, 10 * E, &r) == 0 &&
              r == 500u);
        CHECK(nodus_witness_power_cap_bps_for_epoch(&w, 11 * E, &r) == 0 &&
              r == 500u);
        /* the epoch-start key: a row effective at epoch_start + 1 does NOT
         * count for that snapshot (it governs the next one) */
        direct_insert(&w, 20, 1000u, 12 * E + 1);
        CHECK(nodus_witness_power_cap_bps_for_epoch(&w, 12 * E, &r) == 0 &&
              r == 500u);
        CHECK(nodus_witness_power_cap_bps_for_epoch(&w, 13 * E, &r) == 0 &&
              r == 1000u);
        /* the helper applies THAT ratio: equal to the water-fill at 500 */
        {
            const uint64_t a_raw[7] = { 88 * U, 2 * U, 2 * U, 2 * U, 2 * U,
                                        2 * U, 2 * U };
            dna_vset_snapshot_t *s = mk_snap(DNA_VSET_RULESET_TOPN_V2,
                                             10 * E, a_raw, 7);
            uint64_t p[7], direct[7], via[7], dflt[7];
            uint8_t ids[7][64];
            for (int i = 0; i < 7; i++) {
                p[i] = a_raw[i] / U;
                memcpy(ids[i], s->entries[i].validator_id, 64);
            }
            CHECK(dna_power_cap_counted(p, (const uint8_t (*)[64])ids, 7,
                                        500u, direct) == 0);
            CHECK(dna_power_cap_counted(p, (const uint8_t (*)[64])ids, 7,
                                        DNAC_HF6_POWER_CAP_BPS_DEFAULT,
                                        dflt) == 0);
            CHECK(nodus_witness_vset_powers(&w, s, via) == 0);
            CHECK(memcmp(direct, via, sizeof(via)) == 0);
            /* non-vacuity: the 500 answer differs from the 3000 one here */
            CHECK(memcmp(direct, dflt, sizeof(dflt)) != 0);
            dna_vset_free(&s);
        }
        /* a stored value the scalar rule never admits (this node's
         * storage disagreeing with every writer) is a refusal, never the
         * default and never a clamp: 499, 3001, and a value stored
         * NEGATIVE (2^63 through the int64 cast) */
        direct_insert(&w, 20, 499u, 14 * E);
        r = 777;
        CHECK(nodus_witness_power_cap_bps_for_epoch(&w, 14 * E, &r) == -1);
        CHECK(r == 777);                         /* untouched on -1      */
        {
            const uint64_t c_raw[7] = { 10 * U, 10 * U, 10 * U, 10 * U,
                                        10 * U, 10 * U, 10 * U };
            dna_vset_snapshot_t *s = mk_snap(DNA_VSET_RULESET_TOPN_V2,
                                             14 * E, c_raw, 7);
            expect_refused(&w, s);               /* every consumer faults */
            /* a ruleset-1 snapshot never reads the ratio */
            s->selection_ruleset = DNA_VSET_RULESET_TOPN_V1;
            uint64_t out[DNA_MAX_ACTIVE_VALIDATORS];
            CHECK(nodus_witness_vset_powers(&w, s, out) == 0);
            dna_vset_free(&s);
        }
        direct_insert(&w, 20, 3001u, 15 * E);
        CHECK(nodus_witness_power_cap_bps_for_epoch(&w, 15 * E, &r) == -1);
        direct_insert(&w, 20, (uint64_t)INT64_MAX + 1u, 16 * E);
        CHECK(nodus_witness_power_cap_bps_for_epoch(&w, 16 * E, &r) == -1);
        /* a legal row after them answers again */
        direct_insert(&w, 20, 3000u, 17 * E);
        CHECK(nodus_witness_power_cap_bps_for_epoch(&w, 17 * E, &r) == 0 &&
              r == 3000u);
        /* no open database: "cannot determine", never the default */
        {
            sqlite3 *keep = w.db;
            w.db = NULL;
            w.chain_config_cache_warm = false;
            CHECK(nodus_witness_power_cap_bps_for_epoch(&w, 0, &r) == -1);
            w.db = keep;
        }
    }

    sqlite3_close(w.db);
    w.db = NULL;
    rmrf(data_path);

    printf("test_hf6_power: %d checks OK\n", g_checks);
    return 0;
}
