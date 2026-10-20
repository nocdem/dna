/**
 * @file nodus/tests/test_hf7_wiring.c
 * @brief HF-7 P1c-1 — the HF-7 roots wired into the witness: SYSTEM v6,
 *        segment leaf v2, DomainHead v2 head-authoritative, GLOBAL v2.
 *
 * Normative bytes: docs/plans/2026-09-11-nodus-ledger-snapshot-design.md
 * §8.9 S1-S8 (APPROVED 2026-10-15). Wiring: §10.2 item 8, §10.3 (the
 * A−1/A/A+1 matrix), §10.9, §10.11; decisions/2026-10-20-kurultay-27-hf7-
 * p1-summary.md items 7-8; decisions/2026-10-15-kurultay-24-summary.md
 * item 7. The pure functions themselves are pinned against the oracle KAT
 * in test_roots_hf7 — this file proves the WIRING.
 *
 * ── WHAT IT PROVES ──────────────────────────────────────────────────────
 *  A. LEGS (a fresh chain DB migrated to S19, rows written by hand):
 *   A1. nodus_witness_bcopy_root == dna_v2_bcopy_root over the same rows in
 *       the S1 key order (rows inserted out of order); kind 2 and a
 *       negative amount are FAULTS (-1), never cast.
 *   A2. nodus_witness_vstat_hash == dna_v2_vstat_hash(active_count); the
 *       absent row and a negative value are FAULTS.
 *   A3. nodus_witness_stmem_root == dna_v2_stmem_root over the S3 order.
 *   A4. nodus_witness_storage_segments_root_v2 == dna_v2_segments_root_v2
 *       over (k, Root(k), published_height), != the v1 segments root over
 *       the same rows; the empty table is the shared empty root in both.
 *   A5. nodus_witness_replay_root: the empty relation is
 *       DNA_V2_EMPTY_REPLAY (the A−1 value); three rows inserted out of
 *       order == dna_v2_replay_root over the tx_id order.
 *  B. ENGINE (test_hf6_migrate's seeded fixture: HF-2 on, param 9 at 3,
 *     EVM at 5, the HF-6 edge at block 7; idle blocks):
 *   B1. GENERATION 4 BYTE-IDENTICAL: at block E−1 (generation 4) every
 *       head's last_upd_hash column is NULL (never written), the committed
 *       global root equals dna_v2_global_root(dna_v2_domains_root(heads
 *       decoded from the 89-byte rows)) — the pre-HF-7 formula, recomputed
 *       outside the engine — and the SYSTEM head equals the v5 composition.
 *   B2. THE SEED: outside a transaction it refuses; inside one it fills
 *       EVERY head with today's history query (latest update hash, or the
 *       genesis sentinel for a domain with no update — at least one such
 *       domain exists here and is checked); a second run is idempotent; a
 *       head carrying a different value is a fault.
 *   B3. THE MIRROR FAULT: under generation ROOTS (a scripted copy of the
 *       compiled table whose generation-4 SYSTEM / CORE entries name
 *       generation NODUS_RT_GEN_ROOTS — the exact tuples, so the committed
 *       registry resolves onto them) the boundary block E (SYSTEM touched
 *       by the boundary) with SYSTEM's head-height history row tampered is
 *       a node FAULT naming the mirror; restored, block E commits.
 *   B4. Block E under ROOTS: the SYSTEM head root == dna_v2_system_root_v6
 *       over the twelve legs the test reads itself, != v5; the touched
 *       SYSTEM head's column == block E's SYSTEM update hash; every
 *       untouched head's column is unchanged from the seed; the committed
 *       global root == dna_v2_global_root_v2(dna_v2_domains_root_v2(heads,
 *       columns), DNA_V2_EMPTY_REPLAY) and == nodus_witness_global_root_v2.
 *   B5. GLOBAL v2 with a NON-EMPTY replay relation: three rows written by
 *       hand (expiry far above the next height) → block E+1's committed
 *       root == GLOBAL v2 over the S7 root of those rows, != the
 *       empty-relation composition.
 *   B6. nodus_witness_v2_head_last_upd directly: OK with the head's value;
 *       the mirror row tampered → NODUS_V2_LUH_MIRROR; the mirror row
 *       deleted (the restore case) → OK, the head's value stands; the
 *       column NULL → NODUS_V2_LUH_UNSEEDED.
 *
 * ── WHAT IT REQUIRES ────────────────────────────────────────────────────
 * Compile flags: NODUS_EVM_ENABLED (generation 4 exists only there; the
 * target is registered only in that configuration); DNAC_EPOCH_LENGTH > 8
 * (checked) — the default 720 makes B run E + 1 = 721 idle blocks.
 * Environment: none.
 *
 * ── WHAT IT LEAVES BEHIND ───────────────────────────────────────────────
 * One /tmp/test_hf7_wiring_* directory per fixture, removed at its end
 * (left behind when a CHECK aborts).
 *
 * ── HOW IT CAN LIE ──────────────────────────────────────────────────────
 *  - Generation ROOTS is reached by a SCRIPTED table swapped in between
 *    blocks E−1 and E, NOT by the HF-7 edge (written when P1d did not
 *    exist; the edge, its seeding call site and the A−1 timing are
 *    test_hf7_edge.c's since P1d): they are not exercised here — only that, once the registry resolves to ROOTS,
 *    phases 8-13 compose as §8.9 says. The seed is called by the test.
 *  - The "new domain under ROOTS" lifecycle case (head_activate storing
 *    the sentinel) is NOT exercised: no domain activates after the switch
 *    in this fixture, and a ROOTS genesis is impossible while the genesis
 *    registry is generation 1. Covered by reading only.
 *  - The replay rows of B5 are written by hand (the relation's writer is
 *    package P1c-2). Their expiry is far above E+1, so a prune "expiry <=
 *    H" leaves them; any other P1c-2 consistency rule over the relation is
 *    not modelled.
 *  - B1 pins generation 4 against a RECOMPUTATION with the pre-HF-7
 *    functions, not against a literal recorded before the change: no
 *    engine-level literal root existed to pin. The pure v1 functions keep
 *    their literal KATs in test_roots_v2.
 *  - The legs in B4 are read with the same loaders the engine uses; A1-A5
 *    prove those loaders against the pure functions over hand-built rows.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_v2_apply.h"
#include "witness/nodus_witness_v2_claims.h"
#include "witness/nodus_witness_v2_storage.h"
#include "witness/nodus_witness_v2_schema.h"
#include "witness/nodus_witness_merkle.h"
#include "witness/nodus_witness_vset.h"
#include "witness/nodus_witness_domreg.h"
#include "witness/nodus_witness_roots_v2.h"
#include "witness/nodus_witness_runtime.h"
#include "nodus/nodus_chain_config.h"

#include "dnac/dnac.h"
#include "dnac/ledger_ids.h"
#include "dnac/ledger_roots_v2.h"
#include "dnac/domain_wire.h"
#include "crypto/hash/qgp_sha3.h"

#include "v2_genesis_fixture.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <unistd.h>

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, \
                (msg)); \
        return 1; \
    } \
    g_checks++; \
} while (0)

static int g_checks = 0;

#define E_LEN     ((uint64_t)DNAC_EPOCH_LENGTH)
#define MAXH      16u

/* ══ shared helpers ═══════════════════════════════════════════════════ */

typedef struct {
    nodus_witness_t *w;
    char             dir[128];
    uint8_t          chain16[16];
} fixture_t;

static void fx_close(fixture_t *fx) {
    if (!fx->w) return;
    if (fx->w->db) sqlite3_close(fx->w->db);
    free(fx->w);
    fx->w = NULL;
    char cmd[200];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", fx->dir);
    if (system(cmd) != 0) { /* best effort */ }
}

static int run_sql(sqlite3 *db, const char *sql) {
    char *err = NULL;
    if (sqlite3_exec(db, sql, NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr, "SQL failed (%s): %s\n", sql, err ? err : "?");
        sqlite3_free(err);
        return -1;
    }
    return 0;
}

static int count_q(nodus_witness_t *w, const char *sql, sqlite3_int64 *n) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    int rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) *n = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return rc == SQLITE_ROW ? 0 : -1;
}

static int fxd_open(fixture_t *fx, const char *tag) {
    memset(fx, 0, sizeof(*fx));
    fx->w = calloc(1, sizeof(*fx->w));      /* multi-MB — ALWAYS heap */
    if (!fx->w) return -1;
    snprintf(fx->dir, sizeof(fx->dir), "/tmp/test_hf7_wiring_%s_XXXXXX",
             tag);
    if (!mkdtemp(fx->dir)) { free(fx->w); fx->w = NULL; return -1; }
    snprintf(fx->w->data_path, sizeof(fx->w->data_path), "%s", fx->dir);
    memset(fx->chain16, 0x7A, sizeof(fx->chain16));
    if (nodus_witness_create_chain_db(fx->w, fx->chain16) != 0) return -1;
    /* the S9 … S19 ladder: v2_replay exists from S19 (test_v2_schema
     * "0->19") */
    return nodus_witness_db_migrate_v2s19(fx->w);
}

/* ══ A. the legs ══════════════════════════════════════════════════════ */

static int put_bcopy(nodus_witness_t *w, uint64_t es, uint8_t vfill,
                     uint8_t ofill, int64_t kind, int64_t amount) {
    uint8_t v[64], o[64];
    memset(v, vfill, 64);
    memset(o, ofill, 64);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "INSERT INTO v2_balance_copy (epoch_start, validator_fp, "
            "owner_fp, kind, amount) VALUES (?1, ?2, ?3, ?4, ?5)", -1, &st,
            NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)es);
    sqlite3_bind_blob(st, 2, v, 64, SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 3, o, 64, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 4, (sqlite3_int64)kind);
    sqlite3_bind_int64(st, 5, (sqlite3_int64)amount);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

static void bc_row(dna_v2_bcopy_row_t *r, uint64_t es, uint8_t vfill,
                   uint8_t ofill, uint64_t kind, uint64_t amount) {
    memset(r, 0, sizeof(*r));
    r->epoch_start = es;
    memset(r->validator_fp, vfill, 64);
    memset(r->owner_fp, ofill, 64);
    r->kind = kind;
    r->amount = amount;
}

static int t_legs_bcopy_vstat(void) {
    fixture_t fx;
    CHECK(fxd_open(&fx, "bcopy") == 0, "chain DB");
    uint8_t got[64], want[64];

    CHECK(run_sql(fx.w->db, "DELETE FROM v2_balance_copy") == 0, "clean");
    CHECK(nodus_witness_bcopy_root(fx.w, got) == 0 &&
          dna_v2_empty_root(DNA_V2_EMPTY_BCOPY, want) == 0 &&
          memcmp(got, want, 64) == 0, "A1 empty table = NDS.E.BCOPY.v1");

    /* inserted OUT of key order on purpose */
    CHECK(put_bcopy(fx.w, 720, 0x22, 0x11, 1, 5) == 0 &&
          put_bcopy(fx.w, 0, 0x22, 0x11, 0, 7) == 0 &&
          put_bcopy(fx.w, 720, 0x11, 0x33, 0, 9) == 0 &&
          put_bcopy(fx.w, 0, 0x11, 0x11, 1, 3) == 0 &&
          put_bcopy(fx.w, 720, 0x22, 0x11, 0, 4) == 0, "five rows");
    dna_v2_bcopy_row_t r[5];
    bc_row(&r[0], 0, 0x11, 0x11, 1, 3);
    bc_row(&r[1], 0, 0x22, 0x11, 0, 7);
    bc_row(&r[2], 720, 0x11, 0x33, 0, 9);
    bc_row(&r[3], 720, 0x22, 0x11, 0, 4);
    bc_row(&r[4], 720, 0x22, 0x11, 1, 5);
    CHECK(dna_v2_bcopy_root(r, 5, want) == 0 &&
          nodus_witness_bcopy_root(fx.w, got) == 0 &&
          memcmp(got, want, 64) == 0,
          "A1 bcopy_root == dna_v2_bcopy_root over the S1 key order");

    CHECK(put_bcopy(fx.w, 1440, 0x44, 0x44, 2, 1) == 0, "kind 2 row");
    CHECK(nodus_witness_bcopy_root(fx.w, got) == -1, "A1 kind 2 = FAULT");
    CHECK(run_sql(fx.w->db, "DELETE FROM v2_balance_copy WHERE kind = 2")
          == 0, "drop it");
    CHECK(put_bcopy(fx.w, 1440, 0x44, 0x44, 0, -1) == 0, "negative amount");
    CHECK(nodus_witness_bcopy_root(fx.w, got) == -1,
          "A1 negative amount = FAULT, never cast");

    /* S2 */
    CHECK(run_sql(fx.w->db, "INSERT OR REPLACE INTO validator_stats (key, "
                  "value) VALUES ('active_count', 7)") == 0, "active 7");
    uint64_t seven = 7;
    CHECK(dna_v2_vstat_hash(&seven, want) == 0 &&
          nodus_witness_vstat_hash(fx.w, got) == 0 &&
          memcmp(got, want, 64) == 0, "A2 vstat == dna_v2_vstat_hash(7)");
    CHECK(run_sql(fx.w->db, "UPDATE validator_stats SET value = -1 WHERE "
                  "key = 'active_count'") == 0, "negative");
    CHECK(nodus_witness_vstat_hash(fx.w, got) == -1, "A2 negative = FAULT");
    CHECK(run_sql(fx.w->db, "DELETE FROM validator_stats WHERE key = "
                  "'active_count'") == 0, "absent");
    CHECK(nodus_witness_vstat_hash(fx.w, got) == -1,
          "A2 absent row = FAULT (S2: mandatory)");
    fx_close(&fx);
    return 0;
}

static int put_mem(nodus_witness_t *w, uint64_t es, uint8_t fill,
                   uint64_t fs, uint64_t gu) {
    uint8_t fp[64];
    memset(fp, fill, 64);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "INSERT INTO v2_storage_set_members (epoch_start, node_fp, "
            "fail_streak, grace_until) VALUES (?1, ?2, ?3, ?4)", -1, &st,
            NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)es);
    sqlite3_bind_blob(st, 2, fp, 64, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 3, (sqlite3_int64)fs);
    sqlite3_bind_int64(st, 4, (sqlite3_int64)gu);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

static int put_seg(nodus_witness_t *w, uint64_t k, uint8_t fill,
                   uint64_t ph) {
    uint8_t root[64];
    memset(root, fill, 64);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "INSERT INTO v2_storage_segments (k, root, published_height) "
            "VALUES (?1, ?2, ?3)", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)k);
    sqlite3_bind_blob(st, 2, root, 64, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 3, (sqlite3_int64)ph);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

static int t_legs_stmem_segments(void) {
    fixture_t fx;
    CHECK(fxd_open(&fx, "stmem") == 0, "chain DB");
    uint8_t got[64], want[64], v1[64];

    CHECK(nodus_witness_stmem_root(fx.w, got) == 0 &&
          dna_v2_empty_root(DNA_V2_EMPTY_STMEM, want) == 0 &&
          memcmp(got, want, 64) == 0, "A3 empty = NDS.E.STMEM.v1");
    CHECK(put_mem(fx.w, 1440, 0x05, 0, 0) == 0 &&
          put_mem(fx.w, 720, 0x09, 4294967295ull, 2160) == 0 &&
          put_mem(fx.w, 720, 0x03, 2, 0) == 0, "three members");
    dna_v2_stmem_row_t m[3];
    memset(m, 0, sizeof(m));
    m[0].epoch_start = 720;  memset(m[0].node_fp, 0x03, 64);
    m[0].fail_streak = 2;    m[0].grace_until = 0;
    m[1].epoch_start = 720;  memset(m[1].node_fp, 0x09, 64);
    m[1].fail_streak = 4294967295ull; m[1].grace_until = 2160;
    m[2].epoch_start = 1440; memset(m[2].node_fp, 0x05, 64);
    CHECK(dna_v2_stmem_root(m, 3, want) == 0 &&
          nodus_witness_stmem_root(fx.w, got) == 0 &&
          memcmp(got, want, 64) == 0,
          "A3 stmem_root == dna_v2_stmem_root over the S3 key order");

    /* S5 */
    CHECK(nodus_witness_storage_segments_root_v2(fx.w, got) == 0 &&
          nodus_witness_storage_segments_root(fx.w, v1) == 0 &&
          dna_v2_empty_root(DNA_V2_EMPTY_STORAGE_SEGS, want) == 0 &&
          memcmp(got, want, 64) == 0 && memcmp(v1, want, 64) == 0,
          "A4 empty: v2 == v1 == NDS.E.STSEG.v1 (S5: empty unchanged)");
    CHECK(put_seg(fx.w, 2, 0xB2, 34560) == 0 &&
          put_seg(fx.w, 1, 0xB1, 17280) == 0 &&
          put_seg(fx.w, 3, 0xB3, 51840) == 0, "three segments");
    uint64_t ks[3] = { 1, 2, 3 }, phs[3] = { 17280, 34560, 51840 };
    uint8_t rs[3][64];
    memset(rs[0], 0xB1, 64);
    memset(rs[1], 0xB2, 64);
    memset(rs[2], 0xB3, 64);
    CHECK(dna_v2_segments_root_v2(ks, (const uint8_t (*)[64])rs, phs, 3,
                                  want) == 0 &&
          nodus_witness_storage_segments_root_v2(fx.w, got) == 0 &&
          memcmp(got, want, 64) == 0,
          "A4 segments v2 == dna_v2_segments_root_v2(k, root, published)");
    CHECK(nodus_witness_storage_segments_root(fx.w, v1) == 0 &&
          memcmp(v1, got, 64) != 0,
          "A4 the v2 leaf moves the root over the same rows (re-tag)");
    fx_close(&fx);
    return 0;
}

static int put_replay(nodus_witness_t *w, uint8_t txf, uint8_t inf,
                      uint64_t expiry) {
    uint8_t tx[64], in[64];
    memset(tx, txf, 64);
    memset(in, inf, 64);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "INSERT INTO v2_replay (tx_id, intent_id, expiry_height) "
            "VALUES (?1, ?2, ?3)", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_blob(st, 1, tx, 64, SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 2, in, 64, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 3, (sqlite3_int64)expiry);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

/* the three rows B5 / A5 use, in tx_id order */
static void replay_rows(dna_v2_replay_row_t r[3], uint64_t base) {
    memset(r, 0, 3 * sizeof(*r));
    memset(r[0].tx_id, 0x31, 64); memset(r[0].intent_id, 0x93, 64);
    r[0].expiry_height = base + 600;
    memset(r[1].tx_id, 0x52, 64); memset(r[1].intent_id, 0x71, 64);
    r[1].expiry_height = base + 650;
    memset(r[2].tx_id, 0x7F, 64); memset(r[2].intent_id, 0x15, 64);
    r[2].expiry_height = base + 700;
}

static int put_replay_rows(nodus_witness_t *w, uint64_t base) {
    /* inserted OUT of tx_id order on purpose */
    return (put_replay(w, 0x7F, 0x15, base + 700) == 0 &&
            put_replay(w, 0x31, 0x93, base + 600) == 0 &&
            put_replay(w, 0x52, 0x71, base + 650) == 0) ? 0 : -1;
}

static int t_legs_replay(void) {
    fixture_t fx;
    CHECK(fxd_open(&fx, "replay") == 0, "chain DB (S19)");
    uint8_t got[64], want[64];
    CHECK(nodus_witness_replay_root(fx.w, got) == 0 &&
          dna_v2_empty_root(DNA_V2_EMPTY_REPLAY, want) == 0 &&
          memcmp(got, want, 64) == 0,
          "A5 empty relation = NDS.E.REPLAY.v1 (the A-1 value)");
    CHECK(put_replay_rows(fx.w, 1000) == 0, "three rows");
    dna_v2_replay_row_t r[3];
    replay_rows(r, 1000);
    CHECK(dna_v2_replay_root(r, 3, want) == 0 &&
          nodus_witness_replay_root(fx.w, got) == 0 &&
          memcmp(got, want, 64) == 0,
          "A5 replay_root == dna_v2_replay_root over the tx_id order");
    fx_close(&fx);
    return 0;
}

/* ══ B. the engine ═══════════════════════════════════════════════════ */

#define H9   3u
#define HE   5u
#define HS   8u      /* param 18 effective: the HF-6 edge runs in HS-1 */

static int cc_row(nodus_witness_t *w, unsigned param, uint64_t value,
                  uint64_t effective, uint64_t nonce) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "INSERT INTO chain_config_history (param_id, new_value, "
            "effective_block, commit_block, tx_hash, proposal_nonce, "
            "created_at_unix) VALUES (?1, ?2, ?3, 0, zeroblob(64), ?4, 0)",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)param);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)value);
    sqlite3_bind_int64(st, 3, (sqlite3_int64)effective);
    sqlite3_bind_int64(st, 4, (sqlite3_int64)nonce);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    w->chain_config_cache_warm = false;
    return rc == SQLITE_DONE ? 0 : -1;
}

/* test_hf6_migrate fxe_open's shape */
static int fxe_open(fixture_t *fx, const char *tag) {
    memset(fx, 0, sizeof(*fx));
    fx->w = calloc(1, sizeof(*fx->w));
    if (!fx->w) return -1;
    snprintf(fx->dir, sizeof(fx->dir), "/tmp/test_hf7_wiring_%s_XXXXXX",
             tag);
    if (!mkdtemp(fx->dir)) { free(fx->w); fx->w = NULL; return -1; }
    snprintf(fx->w->data_path, sizeof(fx->w->data_path), "%s", fx->dir);
    memset(fx->chain16, 0x47, sizeof(fx->chain16));
    if (v2x_seed_prepare(fx->w, fx->chain16, 0) != 0) return -1;
    if (cc_row(fx->w, DNAC_CFG_HF2_ACTIVE, DNAC_CFG_HF2_ACTIVE_ON, 1, 11)
        != 0 ||
        cc_row(fx->w, DNAC_CFG_RULESET_GEN2,
               (uint64_t)DNAC_CFG_RULESET_GEN2_D2, H9, 12) != 0 ||
        cc_row(fx->w, DNAC_CFG_EVM_ACTIVE, (uint64_t)DNAC_CFG_EVM_ACTIVE_D,
               HE, 14) != 0 ||
        cc_row(fx->w, DNAC_CFG_RULESET_GEN_ROLES,
               (uint64_t)DNAC_CFG_RULESET_GEN_ROLES_D, HS, 13) != 0)
        return -1;
    return v2x_seed_genesis(fx->w, fx->chain16, 0, NULL, 0, NULL);
}

static void mk_block(nodus_v2_block_t *b, uint64_t h) {
    memset(b, 0, sizeof(*b));
    b->global_height = h;
    b->epoch = nodus_v2_epoch_for_height(h);
    b->envs = NULL;
    b->n_envs = 0;
}

static int run_from_to(fixture_t *fx, uint64_t first, uint64_t last) {
    nodus_v2_block_t b;
    for (uint64_t h = first; h <= last; h++) {
        mk_block(&b, h);
        if (v2x_cmt_apply_ok(fx->w, &b) != 0) return -1;
    }
    return 0;
}

/* The ROOTS-generation test table: the compiled table, copied, with the
 * generation-4 SYSTEM and CORE entries renamed generation ROOTS. The
 * registry resolves by EXACT tuple (nodus_witness_v2_runtime_for), so the
 * committed generation-4 manifests land on these entries. */
static nodus_domain_runtime_t *g_t5 = NULL;

static int roots_table_install(nodus_witness_t *w) {
    size_t n = 0;
    const nodus_domain_runtime_t *all = nodus_runtime_all_table(&n);
    if (!all || n == 0) return -1;
    free(g_t5);
    g_t5 = malloc(n * sizeof(*g_t5));
    if (!g_t5) return -1;
    memcpy(g_t5, all, n * sizeof(*g_t5));
    int renamed = 0;
    for (size_t i = 0; i < n; i++)
        if (g_t5[i].generation == NODUS_RT_GEN_STORAGE &&
            (g_t5[i].domain_id == DNA_DOMAIN_SYSTEM ||
             g_t5[i].domain_id == DNA_DOMAIN_CORE)) {
            g_t5[i].generation = NODUS_RT_GEN_ROOTS;
            renamed++;
        }
    if (renamed != 2) return -1;
    w->v2_runtime_table = g_t5;
    w->v2_runtime_table_n = n;
    return 0;
}

static void head_dec(const uint8_t *e, dna_v2_domain_head_t *h) {
    memset(h, 0, sizeof(*h));
    h->domain_id = ((uint32_t)e[0] << 24) | ((uint32_t)e[1] << 16) |
                   ((uint32_t)e[2] << 8) | e[3];
    memcpy(h->domain_state_root, e + 4, 64);
    for (int i = 0; i < 8; i++)
        h->domain_height = (h->domain_height << 8) | e[68 + i];
    for (int i = 0; i < 8; i++)
        h->last_updated_global_height =
            (h->last_updated_global_height << 8) | e[76 + i];
    h->ruleset_version = ((uint32_t)e[84] << 24) | ((uint32_t)e[85] << 16) |
                         ((uint32_t)e[86] << 8) | e[87];
    h->status = e[88];
}

/* every head row, domain_id ASC; lstate[i]: 0 NULL, 1 a 64-byte value,
 * 2 anything else. @return the count, or -1. */
static int heads_read(nodus_witness_t *w, dna_v2_domain_head_t *h,
                      uint8_t (*luh)[64], int *lstate) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT head, last_upd_hash, typeof(last_upd_hash) FROM "
            "v2_domain_heads ORDER BY domain_id ASC", -1, &st, NULL)
        != SQLITE_OK)
        return -1;
    int n = 0, bad = 0;
    while (sqlite3_step(st) == SQLITE_ROW) {
        if (n >= (int)MAXH ||
            sqlite3_column_bytes(st, 0) != DNA_V2_DOMHEAD_ENC_LEN) {
            bad = 1;
            break;
        }
        head_dec(sqlite3_column_blob(st, 0), &h[n]);
        const char *t = (const char *)sqlite3_column_text(st, 2);
        memset(luh[n], 0, 64);
        if (t && strcmp(t, "null") == 0) {
            lstate[n] = 0;
        } else if (t && strcmp(t, "blob") == 0 &&
                   sqlite3_column_bytes(st, 1) == 64) {
            memcpy(luh[n], sqlite3_column_blob(st, 1), 64);
            lstate[n] = 1;
        } else {
            lstate[n] = 2;
        }
        n++;
    }
    sqlite3_finalize(st);
    return bad ? -1 : n;
}

static int tip_global(nodus_witness_t *w, uint64_t h, uint8_t out[64]) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db, "SELECT global_root FROM v2_blocks WHERE "
                           "global_height = ?1", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)h);
    int ok = sqlite3_step(st) == SQLITE_ROW &&
             sqlite3_column_bytes(st, 0) == 64;
    if (ok) memcpy(out, sqlite3_column_blob(st, 0), 64);
    sqlite3_finalize(st);
    return ok ? 0 : -1;
}

/* the update hash of domain `d` committed at global height `h` */
static int upd_at(nodus_witness_t *w, uint32_t d, uint64_t h,
                  uint8_t out[64]) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db, "SELECT upd_hash FROM v2_domain_updates "
                           "WHERE domain_id = ?1 AND global_height = ?2",
                           -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)d);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)h);
    int ok = sqlite3_step(st) == SQLITE_ROW &&
             sqlite3_column_bytes(st, 0) == 64;
    if (ok) memcpy(out, sqlite3_column_blob(st, 0), 64);
    sqlite3_finalize(st);
    return ok ? 0 : 1;
}

/* today's history query, written out by the test */
static int latest_upd(nodus_witness_t *w, uint32_t d, uint8_t out[64]) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db, "SELECT upd_hash FROM v2_domain_updates "
                           "WHERE domain_id = ?1 ORDER BY global_height "
                           "DESC LIMIT 1", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)d);
    int rc = sqlite3_step(st);
    int ret = -1;
    if (rc == SQLITE_ROW && sqlite3_column_bytes(st, 0) == 64) {
        memcpy(out, sqlite3_column_blob(st, 0), 64);
        ret = 0;
    } else if (rc == SQLITE_DONE) {
        ret = dna_dupd_prev_genesis(out) == 0 ? 1 : -1;
    }
    sqlite3_finalize(st);
    return ret;
}

/* the SYSTEM head's committed state root */
static int sys_head_root(nodus_witness_t *w, uint8_t out[64]) {
    dna_v2_domain_head_t h[MAXH];
    uint8_t l[MAXH][64];
    int s[MAXH];
    int n = heads_read(w, h, l, s);
    if (n < 1 || h[0].domain_id != DNA_DOMAIN_SYSTEM) return -1;
    memcpy(out, h[0].domain_state_root, 64);
    return 0;
}

/* the mirror row upd_hash of (domain, height) — save / overwrite */
static int mirror_get(nodus_witness_t *w, uint32_t d, uint64_t dh,
                      uint8_t out[64]) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db, "SELECT upd_hash FROM v2_root_history "
                           "WHERE domain_id = ?1 AND domain_height = ?2",
                           -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)d);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)dh);
    int ok = sqlite3_step(st) == SQLITE_ROW &&
             sqlite3_column_bytes(st, 0) == 64;
    if (ok) memcpy(out, sqlite3_column_blob(st, 0), 64);
    sqlite3_finalize(st);
    return ok ? 0 : -1;
}

static int mirror_set(nodus_witness_t *w, uint32_t d, uint64_t dh,
                      const uint8_t v[64]) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db, "UPDATE v2_root_history SET upd_hash = ?3 "
                           "WHERE domain_id = ?1 AND domain_height = ?2",
                           -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)d);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)dh);
    sqlite3_bind_blob(st, 3, v, 64, SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);
    int ch = sqlite3_changes(w->db);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE && ch == 1 ? 0 : -1;
}

/* SYSTEM v6 from the twelve legs, each read by the test itself */
static int sys_v6_from_legs(nodus_witness_t *w, uint8_t out[64]) {
    uint8_t va[64], de[64], cc[64], vs[64], dr[64], ma[64], at[64], tr[64];
    uint8_t sto[64], bc[64], vt[64], sm[64];
    if (nodus_witness_merkle_compute_validator_root_v2(w, va) != 0 ||
        nodus_witness_merkle_compute_delegation_root_v2(w, de) != 0 ||
        nodus_chain_config_compute_root(w, cc) != 0 ||
        nodus_witness_vset_root(w, vs) != 0 ||
        nodus_witness_domreg_root(w, dr) != 0 ||
        nodus_witness_manifest_root_v2(w, ma) != 0 ||
        nodus_witness_attendance_root(w, at) != 0 ||
        nodus_witness_treasury_root_v2(w, tr) != 0 ||
        nodus_witness_storage_root_segv2(w, sto) != 0 ||
        nodus_witness_bcopy_root(w, bc) != 0 ||
        nodus_witness_vstat_hash(w, vt) != 0 ||
        nodus_witness_stmem_root(w, sm) != 0)
        return -1;
    return dna_v2_system_root_v6(va, de, cc, vs, dr, ma, at, tr, sto, bc, vt,
                                 sm, out);
}

static int t_engine_roots(void) {
    fixture_t fx;
    nodus_v2_block_t b;
    CHECK(E_LEN > HS, "no epoch boundary among heights 1..HS");
    CHECK(fxe_open(&fx, "eng") == 0, "seeded chain (HF-6 edge at HS-1)");
    CHECK(run_from_to(&fx, 1, E_LEN - 1u) == 0,
          "idle blocks 1..E-1 under generations 1..4");

    dna_v2_domain_head_t h[MAXH];
    uint8_t l[MAXH][64], seeded[MAXH][64];
    int s[MAXH];
    int n = heads_read(fx.w, h, l, s);
    CHECK(n >= 2 && h[0].domain_id == DNA_DOMAIN_SYSTEM, "heads");

    /* ── B1. generation 4 byte-identical ── */
    {
        const nodus_domain_runtime_t *rs = NULL;
        CHECK(nodus_witness_v2_runtime_for(fx.w, DNA_DOMAIN_SYSTEM, 1, &rs)
                  == 0 && rs && rs->generation == NODUS_RT_GEN_STORAGE,
              "B1 SYSTEM resolves generation 4 at E-1");
        for (int i = 0; i < n; i++)
            CHECK(s[i] == 0, "B1 generation 4 never writes last_upd_hash");
        uint8_t d1[64], g1[64], committed[64], sysr[64], v5[64];
        CHECK(dna_v2_domains_root(h, (size_t)n, d1) == 0 &&
              dna_v2_global_root(d1, g1) == 0 &&
              tip_global(fx.w, E_LEN - 1u, committed) == 0 &&
              memcmp(g1, committed, 64) == 0,
              "B1 committed E-1 root == the pre-HF-7 formula over the "
              "89-byte heads");
        CHECK(sys_head_root(fx.w, sysr) == 0 &&
              nodus_witness_system_root_v5(fx.w, v5) == 0 &&
              memcmp(sysr, v5, 64) == 0, "B1 SYSTEM head == v5");
        uint8_t fresh[64];
        CHECK(nodus_witness_global_root_v2(fx.w, fresh, NULL, NULL, NULL)
                  == 0 && memcmp(fresh, committed, 64) == 0,
              "B1 nodus_witness_global_root_v2 keeps the old bytes");
    }

    /* ── switch the registry's resolution to generation ROOTS ── */
    CHECK(roots_table_install(fx.w) == 0, "ROOTS test table");
    {
        const nodus_domain_runtime_t *rs = NULL;
        CHECK(nodus_witness_v2_runtime_for(fx.w, DNA_DOMAIN_SYSTEM, 1, &rs)
                  == 0 && rs && rs->generation == NODUS_RT_GEN_ROOTS,
              "SYSTEM now resolves generation ROOTS");
    }

    /* ── B2. the seed ── */
    CHECK(nodus_witness_v2_domain_heads_seed_last_upd(fx.w) == -1,
          "B2 the seed refuses outside a transaction");
    CHECK(run_sql(fx.w->db, "BEGIN IMMEDIATE") == 0, "begin");
    CHECK(nodus_witness_v2_domain_heads_seed_last_upd(fx.w) == 0,
          "B2 the seed fills every head");
    CHECK(nodus_witness_v2_domain_heads_seed_last_upd(fx.w) == 0,
          "B2 a second seed is idempotent");
    CHECK(run_sql(fx.w->db, "COMMIT") == 0, "commit");
    n = heads_read(fx.w, h, l, s);
    CHECK(n >= 2, "heads after the seed");
    int never = 0;
    for (int i = 0; i < n; i++) {
        uint8_t want[64];
        int q = latest_upd(fx.w, h[i].domain_id, want);
        CHECK(q >= 0 && s[i] == 1 && memcmp(l[i], want, 64) == 0,
              "B2 every head == today's history query");
        if (q == 1) never++;
        memcpy(seeded[i], l[i], 64);
    }
    CHECK(never >= 1, "B2 at least one never-updated domain carries the "
          "genesis sentinel");
    {
        /* a different value already present = fault (rolled back) */
        CHECK(run_sql(fx.w->db, "BEGIN IMMEDIATE") == 0 &&
              run_sql(fx.w->db, "UPDATE v2_domain_heads SET last_upd_hash "
                      "= zeroblob(64) WHERE domain_id = 0") == 0, "tamper");
        CHECK(nodus_witness_v2_domain_heads_seed_last_upd(fx.w) == -1,
              "B2 a head carrying a different value is a fault");
        CHECK(run_sql(fx.w->db, "ROLLBACK") == 0, "rollback");
    }

    /* ── B3. the mirror FAULT at block E (SYSTEM touched by the
     *        boundary) ── */
    uint8_t keep[64], bad[64];
    memset(bad, 0xEE, 64);
    CHECK(mirror_get(fx.w, DNA_DOMAIN_SYSTEM, h[0].domain_height, keep) == 0
          && memcmp(keep, l[0], 64) == 0,
          "SYSTEM's head-height history row mirrors its column");
    CHECK(mirror_set(fx.w, DNA_DOMAIN_SYSTEM, h[0].domain_height, bad) == 0,
          "tamper the mirror");
    mk_block(&b, E_LEN);
    CHECK(v2x_cmt_fault_why(fx.w, &b, V2X_FAULT,
                            "disagrees with its history mirror") == 0,
          "B3 a disagreeing mirror row stops the node");
    CHECK(mirror_set(fx.w, DNA_DOMAIN_SYSTEM, h[0].domain_height, keep) == 0,
          "restore the mirror");

    /* ── B4. block E under ROOTS ── */
    mk_block(&b, E_LEN);
    CHECK(v2x_cmt_apply_ok(fx.w, &b) == 0, "B4 block E commits under ROOTS");
    {
        uint8_t sysr[64], v6[64], v5[64], u[64];
        CHECK(sys_head_root(fx.w, sysr) == 0 &&
              sys_v6_from_legs(fx.w, v6) == 0 && memcmp(sysr, v6, 64) == 0,
              "B4 SYSTEM head == dna_v2_system_root_v6 over the 12 legs");
        CHECK(nodus_witness_system_root_v5(fx.w, v5) == 0 &&
              memcmp(v5, v6, 64) != 0, "B4 v6 != v5");
        dna_v2_domain_head_t h2[MAXH];
        uint8_t l2[MAXH][64];
        int s2[MAXH];
        int n2 = heads_read(fx.w, h2, l2, s2);
        CHECK(n2 == n, "same head set");
        int touched = 0, untouched = 0;
        for (int i = 0; i < n2; i++) {
            CHECK(s2[i] == 1, "B4 every head carries a 64-byte column");
            int q = upd_at(fx.w, h2[i].domain_id, E_LEN, u);
            CHECK(q >= 0, "update read");
            if (q == 0) {
                CHECK(memcmp(l2[i], u, 64) == 0,
                      "B4 a touched head's column == block E's update hash");
                touched++;
            } else {
                CHECK(memcmp(l2[i], seeded[i], 64) == 0,
                      "B4 an untouched head's column is unchanged");
                untouched++;
            }
        }
        CHECK(touched >= 1 && untouched >= 1,
              "B4 both the touched and the untouched case occurred");
        uint8_t d2[64], empty[64], g2[64], committed[64], fresh[64];
        CHECK(dna_v2_domains_root_v2(h2, (const uint8_t (*)[64])l2,
                                     (size_t)n2, d2) == 0 &&
              dna_v2_empty_root(DNA_V2_EMPTY_REPLAY, empty) == 0 &&
              dna_v2_global_root_v2(d2, empty, g2) == 0 &&
              tip_global(fx.w, E_LEN, committed) == 0 &&
              memcmp(g2, committed, 64) == 0,
              "B4 committed E root == GLOBAL v2(DomainHead v2, empty S7)");
        CHECK(nodus_witness_global_root_v2(fx.w, fresh, NULL, NULL, NULL)
                  == 0 && memcmp(fresh, committed, 64) == 0,
              "B4 nodus_witness_global_root_v2 == committed under ROOTS");
        uint8_t v1d[64], v1g[64];
        CHECK(dna_v2_domains_root(h2, (size_t)n2, v1d) == 0 &&
              dna_v2_global_root(v1d, v1g) == 0 &&
              memcmp(v1g, committed, 64) != 0,
              "B4 the old composition no longer matches");
    }

    /* ── B5. GLOBAL v2 over a non-empty replay relation ── */
    CHECK(put_replay_rows(fx.w, E_LEN) == 0, "three replay rows by hand");
    mk_block(&b, E_LEN + 1u);
    CHECK(v2x_cmt_apply_ok(fx.w, &b) == 0, "B5 block E+1 commits");
    {
        dna_v2_domain_head_t h3[MAXH];
        uint8_t l3[MAXH][64];
        int s3[MAXH];
        int n3 = heads_read(fx.w, h3, l3, s3);
        dna_v2_replay_row_t r[3];
        replay_rows(r, E_LEN);
        uint8_t d3[64], rr[64], g3[64], empty[64], g0[64], committed[64];
        CHECK(n3 >= 2 &&
              dna_v2_domains_root_v2(h3, (const uint8_t (*)[64])l3,
                                     (size_t)n3, d3) == 0 &&
              dna_v2_replay_root(r, 3, rr) == 0 &&
              dna_v2_global_root_v2(d3, rr, g3) == 0 &&
              tip_global(fx.w, E_LEN + 1u, committed) == 0 &&
              memcmp(g3, committed, 64) == 0,
              "B5 committed E+1 root == GLOBAL v2 over the S7 root of the "
              "relation");
        CHECK(dna_v2_empty_root(DNA_V2_EMPTY_REPLAY, empty) == 0 &&
              dna_v2_global_root_v2(d3, empty, g0) == 0 &&
              memcmp(g0, committed, 64) != 0,
              "B5 the replay leg moves the root");
    }

    /* ── B6. the head-authoritative read directly ── */
    {
        n = heads_read(fx.w, h, l, s);
        uint8_t got[64], save[64];
        CHECK(n >= 1 &&
              nodus_witness_v2_head_last_upd(fx.w, DNA_DOMAIN_SYSTEM, got)
                  == NODUS_V2_LUH_OK && memcmp(got, l[0], 64) == 0,
              "B6 OK: the head's value");
        CHECK(mirror_get(fx.w, DNA_DOMAIN_SYSTEM, h[0].domain_height, save)
                  == 0 &&
              mirror_set(fx.w, DNA_DOMAIN_SYSTEM, h[0].domain_height, bad)
                  == 0, "tamper the mirror");
        CHECK(nodus_witness_v2_head_last_upd(fx.w, DNA_DOMAIN_SYSTEM, got)
                  == NODUS_V2_LUH_MIRROR, "B6 a disagreeing mirror");
        sqlite3_stmt *st = NULL;
        CHECK(sqlite3_prepare_v2(fx.w->db, "DELETE FROM v2_root_history "
                                 "WHERE domain_id = ?1 AND domain_height = "
                                 "?2", -1, &st, NULL) == SQLITE_OK,
              "prepare");
        sqlite3_bind_int64(st, 1, (sqlite3_int64)DNA_DOMAIN_SYSTEM);
        sqlite3_bind_int64(st, 2, (sqlite3_int64)h[0].domain_height);
        int drc = sqlite3_step(st);
        sqlite3_finalize(st);
        CHECK(drc == SQLITE_DONE, "delete the mirror row");
        memset(got, 0, 64);
        CHECK(nodus_witness_v2_head_last_upd(fx.w, DNA_DOMAIN_SYSTEM, got)
                  == NODUS_V2_LUH_OK && memcmp(got, l[0], 64) == 0,
              "B6 an ABSENT mirror row: the head's value stands");
        CHECK(run_sql(fx.w->db, "UPDATE v2_domain_heads SET last_upd_hash = "
                      "NULL WHERE domain_id = 0") == 0, "column NULL");
        CHECK(nodus_witness_v2_head_last_upd(fx.w, DNA_DOMAIN_SYSTEM, got)
                  == NODUS_V2_LUH_UNSEEDED, "B6 an unseeded column");
    }

    fx.w->v2_runtime_table = NULL;
    fx.w->v2_runtime_table_n = 0;
    fx_close(&fx);
    free(g_t5);
    g_t5 = NULL;
    return 0;
}

int main(void) {
    static const struct {
        const char *name;
        int (*fn)(void);
    } cases[] = {
        { "legs_bcopy_vstat",       t_legs_bcopy_vstat },
        { "legs_stmem_segments",    t_legs_stmem_segments },
        { "legs_replay",            t_legs_replay },
        { "engine_roots_gen5",      t_engine_roots },
    };
    size_t failed = 0, n = sizeof(cases) / sizeof(cases[0]);
    for (size_t i = 0; i < n; i++) {
        int rc = cases[i].fn();
        fprintf(stderr, "[%s] %s\n", rc == 0 ? "PASS" : "FAIL",
                cases[i].name);
        if (rc != 0) failed++;
    }
    fprintf(stderr, "test_hf7_wiring: %zu/%zu cases passed, %d checks\n",
            n - failed, n, g_checks);
    return failed == 0 ? 0 : 1;
}
