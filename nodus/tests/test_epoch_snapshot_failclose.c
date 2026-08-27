/**
 * @file nodus/tests/test_epoch_snapshot_failclose.c
 * @brief O15J Block 2 / A1 — nodus_witness_epoch_snapshot_apply must HALT
 *        on a DB fault, and must NOT halt on a genuine absence.
 *
 * ── WHAT WAS WRONG ────────────────────────────────────────────────────
 * The function read three inputs and, for each one, substituted a
 * legitimate-looking value on failure and still returned 0:
 *
 *   LEG 1  `if (rc != 0 || committee_count == 0) committee_count = 0;`
 *          — an unreadable committee was hashed as "empty chain".
 *   LEG 2  `if (vrc != 0) { memset(&v, 0, ...); }` — an unreadable
 *          `validators` row was hashed as an all-zero validator.
 *   LEG 3  `if (lrc != 0) dcount = 0;` — a failed delegation scan was
 *          hashed as "this validator has no delegators".
 *
 * The blob those three feed is SHA3-512'd into epoch_state.snapshot_hash,
 * which is scanned into the epoch_state leaves of state_root. So one
 * node's transient SQLITE_IOERR committed a state_root no peer could
 * reproduce — a chain split with no Byzantine actor — and the function
 * reported success while doing it.
 *
 * ── WHAT THIS FILE PINS ───────────────────────────────────────────────
 * For each leg, BOTH sides of the distinction the fix is made of:
 *   FAULT  -> snapshot_apply returns -1 and the stored row is not moved.
 *   ABSENT -> snapshot_apply returns 0 and produces the SAME bytes it
 *             always did. Absent must never start failing: a chain with
 *             no validators must still serialize the canonical empty
 *             snapshot, and a committee member whose `validators` row is
 *             genuinely gone must still be zero-filled.
 *
 * ── ISOLATING ONE LEG AT A TIME (this is the anti-vacuity design) ─────
 * All three legs defend the same end property ("a fault must not become a
 * committed snapshot_hash"), so a test that only asserted "some fault =>
 * -1" would let a mutant that reverts ONE leg survive: another leg would
 * catch the same poison. Every subtest below therefore scopes its poison
 * so that exactly ONE leg can observe it, and asserts the OTHER legs'
 * inputs are still healthy at the same time:
 *
 *   LEG 1  poisons a validator that is NOT in the committee, with the
 *          committee cache COLD. nodus_validator_top_n scans the whole
 *          bonded set (so it hits the poison and fails closed —
 *          nodus_witness_validator.c), while leg 2 only ever reads the
 *          seven MEMBERS and so cannot see it.
 *   LEG 2  poisons a MEMBER, with the committee cache WARM. The subtest
 *          asserts nodus_committee_get_for_block_alloc still returns 0
 *          under that exact poison, so a -1 out of snapshot_apply can
 *          only have come from leg 2.
 *   LEG 3  poisons `delegations` only. The subtest asserts both the
 *          committee lookup and a direct nodus_validator_get still
 *          succeed, so only leg 3 can be responsible.
 *
 * ── FAULT INJECTION IS STRUCTURAL, NOT TIMED ──────────────────────────
 * Same technique as test_merkle_scan_fail_close.c and
 * test_chain_config_cache_failclose.c: the table under test is replaced
 * by a VIEW over a raw table, and the flagged row projects
 * abs(-9223372036854775808), which SQLite raises as "integer overflow"
 * when that row is evaluated. No sleeps, no timing, no randomness —
 * flaky tests are forbidden project-wide.
 *
 * FIXTURE: nodus_witness_t is multi-MB — calloc, never the stack.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_epoch.h"
#include "witness/nodus_witness_committee.h"
#include "witness/nodus_witness_validator.h"
#include "witness/nodus_witness_delegation.h"

#include "dnac/dnac.h"
#include "dnac/validator.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define TEST(name) do { printf("  %-62s", name); } while (0)
#define PASS()     do { printf("PASS\n"); passed++; } while (0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while (0)

static int passed = 0;
static int failed = 0;

/* Raises SQLITE_ERROR ("integer overflow") when the row is evaluated. */
#define OVERFLOW_EXPR "abs(-9223372036854775808)"

/* Nine bonded validators, strictly descending stake, so the top-7
 * committee is V0..V6 and V7/V8 are OUTSIDE it. The gap is what lets a
 * poison be visible to nodus_validator_top_n (leg 1) and invisible to the
 * per-member nodus_validator_get loop (leg 2). */
#define N_VALS          9
#define N_MEMBERS       DNAC_COMMITTEE_SIZE      /* 7 */
#define OUTSIDER_IDX    8                        /* lowest stake         */
#define MEMBER_IDX      0                        /* highest stake        */

/* Two delegations, both to V0, so leg 3 has rows to scan. */
#define N_DELS          2
#define DEL_AMOUNT      1000ULL

/* Canonical blob field widths (nodus_witness_epoch.h). */
#define VAL_ENTRY_LEN   (DNAC_PUBKEY_SIZE + 8 + 8 + 2 + 1)   /* 2611 */
#define DEL_ENTRY_LEN   (DNAC_PUBKEY_SIZE + DNAC_PUBKEY_SIZE + 8) /* 5192 */

/* An epoch start inside the bootstrap window (e_start < E + 1), so the
 * committee comes from nodus_committee_bootstrap_for_epoch and needs no
 * `blocks` history — the same height the pre-existing
 * test_epoch_snapshot.c smoke uses. */
#define EPOCH_H         ((uint64_t)DNAC_EPOCH_LENGTH)

/* ── fixture ──────────────────────────────────────────────────────────── */

typedef struct {
    nodus_witness_t *w;
    char             dir[80];
    uint8_t          pk[N_VALS][DNAC_PUBKEY_SIZE];
    uint8_t          dpk[N_DELS][DNAC_PUBKEY_SIZE];
} fx_t;

static int exec_sql(nodus_witness_t *w, const char *sql) {
    char *err = NULL;
    if (sqlite3_exec(w->db, sql, NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr, "sql error: %s\n  in: %s\n", err ? err : "?", sql);
        sqlite3_free(err);
        return -1;
    }
    return 0;
}

static void fx_free(fx_t *fx) {
    if (!fx->w) return;
    if (fx->w->db) sqlite3_close(fx->w->db);
    free(fx->w);
    fx->w = NULL;
}

/* Bring up a full-schema chain DB. nodus_witness_create_chain_db runs
 * WITNESS_DB_SCHEMA plus the whole migration chain, so `validators`,
 * `delegations`, `epoch_state`, `validator_set_snapshots` and
 * `chain_config_history` all exist — which is exactly the state every
 * real node is in from its first open (nodus_witness.c, and the joining
 * node path nodus_witness_bootstrap.c). */
static int fx_up(fx_t *fx, const char *tag, int seed_validators,
                 int seed_delegations) {
    memset(fx, 0, sizeof(*fx));
    fx->w = calloc(1, sizeof(*fx->w));
    if (!fx->w) return -1;

    /* The live constructor's cache sentinel: a zeroed struct would read
     * as a CACHED EMPTY committee for epoch 0 and every committee lookup
     * below would be vacuous. */
    fx->w->cached_committee_epoch_start = UINT64_MAX;

    snprintf(fx->dir, sizeof(fx->dir), "/tmp/test_epoch_fc_%s_XXXXXX", tag);
    if (!mkdtemp(fx->dir)) { free(fx->w); fx->w = NULL; return -1; }
    snprintf(fx->w->data_path, sizeof(fx->w->data_path), "%s", fx->dir);

    uint8_t chain_id[16];
    memset(chain_id, 0xE7, sizeof(chain_id));
    if (nodus_witness_create_chain_db(fx->w, chain_id) != 0) return -1;
    if (!fx->w->db) return -1;

    for (int i = 0; i < N_VALS; i++)
        memset(fx->pk[i], (uint8_t)(0x10 + i), DNAC_PUBKEY_SIZE);
    for (int i = 0; i < N_DELS; i++)
        memset(fx->dpk[i], (uint8_t)(0xA0 + i), DNAC_PUBKEY_SIZE);

    if (!seed_validators) return 0;

    for (int i = 0; i < N_VALS; i++) {
        dnac_validator_record_t v;
        memset(&v, 0, sizeof(v));
        memcpy(v.pubkey, fx->pk[i], DNAC_PUBKEY_SIZE);
        /* strictly descending, so the ranking is total and the tiebreak
         * sort never runs — which keeps WHICH seven are members a fact of
         * the fixture rather than of a hash. */
        v.self_stake         = 1000000ULL - (uint64_t)i * 1000ULL;
        v.total_delegated    = (i == MEMBER_IDX && seed_delegations)
                                   ? DEL_AMOUNT * N_DELS : 0;
        v.external_delegated = v.total_delegated;
        v.commission_bps     = (uint16_t)(100 + i);
        v.status             = DNAC_VALIDATOR_ACTIVE;
        v.active_since_block = 1;   /* constitutional seed set: tenured */
        memset(v.unstake_destination_fp, 'f',
               sizeof(v.unstake_destination_fp) - 1);
        if (nodus_validator_insert(fx->w, &v) != 0) return -1;
    }

    if (!seed_delegations) return 0;

    for (int i = 0; i < N_DELS; i++) {
        dnac_delegation_record_t d;
        memset(&d, 0, sizeof(d));
        memcpy(d.delegator_pubkey, fx->dpk[i], DNAC_PUBKEY_SIZE);
        memcpy(d.validator_pubkey, fx->pk[MEMBER_IDX], DNAC_PUBKEY_SIZE);
        d.amount             = DEL_AMOUNT;
        d.delegated_at_block = 1;
        if (nodus_delegation_insert(fx->w, &d) != 0) return -1;
    }
    return 0;
}

/* Replace `validators` with a VIEW over the original rows in which the
 * row whose pubkey blob equals `poison_pk` projects the overflow
 * expression as self_stake. Every column keeps its name, so both
 * nodus_validator_top_n and nodus_validator_get bind and read exactly as
 * they do in production. */
static int poison_validators(fx_t *fx, const uint8_t *poison_pk) {
    if (exec_sql(fx->w, "ALTER TABLE validators RENAME TO validators_raw;")
        != 0) return -1;
    if (exec_sql(fx->w,
        "ALTER TABLE validators_raw ADD COLUMN bad INTEGER NOT NULL "
        "DEFAULT 0;") != 0) return -1;

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(fx->w->db,
            "UPDATE validators_raw SET bad = 1 WHERE pubkey = ?",
            -1, &st, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_blob(st, 1, poison_pk, DNAC_PUBKEY_SIZE, SQLITE_STATIC);
    int rc = sqlite3_step(st);
    int changed = sqlite3_changes(fx->w->db);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE || changed != 1) return -1;

    return exec_sql(fx->w,
        "CREATE VIEW validators AS SELECT pubkey_hash, pubkey,"
        "  CASE WHEN bad = 1 THEN " OVERFLOW_EXPR " ELSE self_stake END"
        "    AS self_stake,"
        "  total_delegated, external_delegated, commission_bps,"
        "  pending_commission_bps, pending_effective_block, status,"
        "  active_since_block, unstake_commit_block,"
        "  unstake_destination_fp, unstake_destination_pubkey,"
        "  last_validator_update_block, consecutive_missed_epochs,"
        "  last_signed_block, signed_blocks_this_epoch"
        " FROM validators_raw;");
}

/* Same trick for `delegations`: every row's amount raises. */
static int poison_delegations(fx_t *fx) {
    if (exec_sql(fx->w, "ALTER TABLE delegations RENAME TO delegations_raw;")
        != 0) return -1;
    return exec_sql(fx->w,
        "CREATE VIEW delegations AS SELECT delegator_hash, validator_hash,"
        "  delegator_pubkey, validator_pubkey,"
        "  " OVERFLOW_EXPR " AS amount, delegated_at_block"
        " FROM delegations_raw;");
}

/* Warm the per-epoch committee cache from the healthy tables, and report
 * how many members it holds. */
static int warm_committee(fx_t *fx, int *count_out) {
    nodus_committee_member_t *m = NULL;
    int n = 0;
    if (nodus_committee_get_for_block_alloc(fx->w, EPOCH_H, &m, &n) != 0)
        return -1;
    free(m);
    *count_out = n;
    return 0;
}

/* ── blob readers ─────────────────────────────────────────────────────── */

static uint16_t be16(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}
static uint32_t be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  |  (uint32_t)p[3];
}
static uint64_t be64(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | p[i];
    return v;
}

/* Locate the member entry whose pubkey matches, and hand back a pointer
 * to its 19 non-pubkey bytes (self_stake .. status). */
static const uint8_t *member_tail(const nodus_epoch_state_t *e,
                                  const uint8_t *pk) {
    if (!e->snapshot_blob || e->snapshot_blob_len < 2) return NULL;
    uint16_t n = be16(e->snapshot_blob);
    for (uint16_t i = 0; i < n; i++) {
        const uint8_t *ent = e->snapshot_blob + 2 + (size_t)i * VAL_ENTRY_LEN;
        if (memcmp(ent, pk, DNAC_PUBKEY_SIZE) == 0)
            return ent + DNAC_PUBKEY_SIZE;
    }
    return NULL;
}

static uint32_t blob_del_count(const nodus_epoch_state_t *e) {
    if (!e->snapshot_blob || e->snapshot_blob_len < 2) return UINT32_MAX;
    uint16_t n = be16(e->snapshot_blob);
    size_t off = 2 + (size_t)n * VAL_ENTRY_LEN;
    if (e->snapshot_blob_len < off + 4) return UINT32_MAX;
    return be32(e->snapshot_blob + off);
}

/* ═══════════════════════════════════════════════════════════════════════
 * LEG 1 — the committee lookup
 * ═════════════════════════════════════════════════════════════════════ */

/* ABSENT: a chain with no validators at all. The committee accessor
 * SUCCEEDS with zero members, which is not a fault, and the canonical
 * empty snapshot (u16 0 || u32 0 = 6 bytes) must still be written.
 *
 * KILLED BY: turning leg 1 into `if (rc != 0 || committee_count == 0)
 * return -1;` — the over-broad fail-close that would stop a pre-genesis
 * or freshly-bootstrapped node from ever sealing its first epoch. */
static void t_leg1_absent_empty_chain_still_serializes(void) {
    TEST("leg 1 ABSENT: empty chain still writes the 6-byte empty snapshot");
    fx_t fx;
    if (fx_up(&fx, "l1abs", 0, 0) != 0) { FAIL("fixture"); fx_free(&fx); return; }

    if (nodus_witness_epoch_snapshot_apply(fx.w, EPOCH_H) != 0) {
        FAIL("empty chain was treated as a fault");
        goto done;
    }
    nodus_epoch_state_t e;
    memset(&e, 0, sizeof(e));
    if (nodus_witness_epoch_get(fx.w, EPOCH_H, &e) != 0) {
        FAIL("no epoch_state row written");
        goto done;
    }
    if (e.snapshot_blob_len != 6) {
        FAIL("empty snapshot is not the canonical 6 bytes");
        nodus_witness_epoch_free(&e);
        goto done;
    }
    for (size_t i = 0; i < 6; i++) {
        if (e.snapshot_blob[i] != 0) {
            FAIL("empty snapshot body is not all zero");
            nodus_witness_epoch_free(&e);
            goto done;
        }
    }
    nodus_witness_epoch_free(&e);
    PASS();
done:
    fx_free(&fx);
}

/* FAULT: the committee cannot be determined.
 *
 * The cache is COLD and a NON-MEMBER validator row is poisoned.
 * nodus_validator_top_n scans the whole bonded set, hits the poisoned
 * row and fails closed (nodus_witness_validator.c), so
 * nodus_committee_get_for_block_alloc returns -1 — asserted directly
 * below, which is the precondition that makes this a LEG 1 test.
 *
 * KILLED BY: restoring `if (rc != 0 || committee_count == 0) {
 * committee_count = 0; }`. With that line back the function hashes the
 * canonical EMPTY snapshot and returns 0 — the exact silent divergence
 * this leg exists to stop. Nothing else in the function would catch it:
 * with committee_count forced to 0 neither the leg-2 loop nor the leg-3
 * loop executes at all, so this single mutant is killed by this single
 * assertion. */
static void t_leg1_fault_halts(void) {
    TEST("leg 1 FAULT: unreadable committee halts, never 'empty chain'");
    fx_t fx;
    nodus_committee_member_t *m = NULL;
    int n = 0, pn = 0, g = 0;
    if (fx_up(&fx, "l1flt", 1, 1) != 0) { FAIL("fixture"); fx_free(&fx); return; }

    /* Non-vacuity: healthy, cold, the same call SUCCEEDS with a full
     * committee — so the -1 below cannot come from the fixture. */
    if (warm_committee(&fx, &n) != 0 || n != N_MEMBERS) {
        FAIL("healthy committee lookup did not produce N_MEMBERS");
        goto done;
    }

    if (poison_validators(&fx, fx.pk[OUTSIDER_IDX]) != 0) {
        FAIL("poison");
        goto done;
    }
    /* Cold again, so the poisoned scan really runs. */
    fx.w->cached_committee_epoch_start = UINT64_MAX;
    fx.w->cached_committee_count = 0;

    if (nodus_committee_get_for_block_alloc(fx.w, EPOCH_H, &m, &pn) != -1) {
        free(m);
        FAIL("precondition: poisoned committee lookup did not fail");
        goto done;
    }

    fx.w->cached_committee_epoch_start = UINT64_MAX;
    fx.w->cached_committee_count = 0;
    if (nodus_witness_epoch_snapshot_apply(fx.w, EPOCH_H) != -1) {
        FAIL("a DB fault became a committed empty snapshot");
        goto done;
    }
    /* And it left no row behind to be hashed into state_root. */
    nodus_epoch_state_t e;
    memset(&e, 0, sizeof(e));
    g = nodus_witness_epoch_get(fx.w, EPOCH_H, &e);
    if (g == 0) {
        nodus_witness_epoch_free(&e);
        FAIL("a snapshot row was written despite the fault");
        goto done;
    }
    PASS();
done:
    fx_free(&fx);
}

/* ═══════════════════════════════════════════════════════════════════════
 * LEG 2 — the per-member `validators` row
 * ═════════════════════════════════════════════════════════════════════ */

/* ABSENT: a committee member whose `validators` row is genuinely gone
 * (nodus_validator_get returns 1). The historical zero-fill MUST survive
 * — this is reachable and deterministic since S3, where the committee can
 * be served from a committed validator_set_snapshots row whose member no
 * longer has a live `validators` row, and every node replaying that chain
 * sees the same absence.
 *
 * Two assertions, killing two different mutants:
 *   - `== 0`: kills `if (vrc != 0) return -1;` (over-broad fail-close).
 *   - the tail bytes: kills any mutant that drops the member, carries a
 *     neighbour's record, or leaves `v` uninitialised — the pubkey must
 *     be preserved and every other field must be exactly zero. This is
 *     also the assertion that makes ABSENT and FAULT observably
 *     DIFFERENT rather than merely differently-returning. */
static void t_leg2_absent_zero_fills(void) {
    TEST("leg 2 ABSENT: missing validators row is zero-filled, not a fault");
    fx_t fx;
    const uint8_t *tail_b = NULL, *tail_a = NULL;
    size_t len_before = 0;
    int n = 0;
    if (fx_up(&fx, "l2abs", 1, 0) != 0) { FAIL("fixture"); fx_free(&fx); return; }

    if (warm_committee(&fx, &n) != 0 || n != N_MEMBERS) {
        FAIL("healthy committee lookup did not produce N_MEMBERS");
        goto done;
    }

    /* Baseline with the row PRESENT: the member's tail is non-zero. */
    if (nodus_witness_epoch_snapshot_apply(fx.w, EPOCH_H) != 0) {
        FAIL("healthy snapshot_apply failed");
        goto done;
    }
    nodus_epoch_state_t before;
    memset(&before, 0, sizeof(before));
    if (nodus_witness_epoch_get(fx.w, EPOCH_H, &before) != 0) {
        FAIL("no baseline row");
        goto done;
    }
    tail_b = member_tail(&before, fx.pk[MEMBER_IDX]);
    if (!tail_b || be64(tail_b) == 0) {
        FAIL("baseline member carries no self_stake — fixture is vacuous");
        nodus_witness_epoch_free(&before);
        goto done;
    }
    uint8_t hash_before[NODUS_EPOCH_SNAPSHOT_HASH_LEN];
    memcpy(hash_before, before.snapshot_hash, sizeof(hash_before));
    len_before = before.snapshot_blob_len;
    nodus_witness_epoch_free(&before);

    /* Now delete that member's row. The committee is cached, so the SET
     * is unchanged — only the per-member read goes absent. */
    {
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(fx.w->db,
                "DELETE FROM validators WHERE pubkey = ?", -1, &st, NULL)
            != SQLITE_OK) { FAIL("delete prepare"); goto done; }
        sqlite3_bind_blob(st, 1, fx.pk[MEMBER_IDX], DNAC_PUBKEY_SIZE,
                          SQLITE_STATIC);
        int rc = sqlite3_step(st);
        int ch = sqlite3_changes(fx.w->db);
        sqlite3_finalize(st);
        if (rc != SQLITE_DONE || ch != 1) { FAIL("delete"); goto done; }
    }

    /* Precondition: the read really is ABSENT (1), not a fault. */
    dnac_validator_record_t probe;
    if (nodus_validator_get(fx.w, fx.pk[MEMBER_IDX], &probe) != 1) {
        FAIL("precondition: deleted row did not read as absent");
        goto done;
    }

    if (nodus_witness_epoch_snapshot_apply(fx.w, EPOCH_H) != 0) {
        FAIL("a genuinely absent row was treated as a fault");
        goto done;
    }
    nodus_epoch_state_t after;
    memset(&after, 0, sizeof(after));
    if (nodus_witness_epoch_get(fx.w, EPOCH_H, &after) != 0) {
        FAIL("no row after the absent-member apply");
        goto done;
    }
    if (after.snapshot_blob_len != len_before) {
        FAIL("the absent member changed the blob LENGTH");
        nodus_witness_epoch_free(&after);
        goto done;
    }
    tail_a = member_tail(&after, fx.pk[MEMBER_IDX]);
    if (!tail_a) {
        FAIL("the absent member's pubkey was not carried into the blob");
        nodus_witness_epoch_free(&after);
        goto done;
    }
    for (int i = 0; i < 19; i++) {   /* 8 + 8 + 2 + 1 */
        if (tail_a[i] != 0) {
            FAIL("the absent member was not zero-filled");
            nodus_witness_epoch_free(&after);
            goto done;
        }
    }
    /* Observable: absence changes the committed hash. It is a different
     * chain state, and it is supposed to be. */
    if (memcmp(hash_before, after.snapshot_hash, sizeof(hash_before)) == 0) {
        FAIL("zero-filling a member did not change snapshot_hash");
        nodus_witness_epoch_free(&after);
        goto done;
    }
    nodus_witness_epoch_free(&after);
    PASS();
done:
    fx_free(&fx);
}

/* FAULT: a committee member's `validators` row is unreadable.
 *
 * The committee cache is WARM and the poisoned row belongs to a MEMBER,
 * so the subtest asserts nodus_committee_get_for_block_alloc still
 * returns 0 under this exact poison. Leg 1 therefore cannot fire and a -1
 * out of snapshot_apply can only be leg 2's.
 *
 * KILLED BY: restoring `if (vrc != 0) { memset(&v, 0, ...); ... }`. With
 * that line back the fault is zero-filled and the function returns 0,
 * committing a snapshot_hash that is byte-identical to the ABSENT case
 * above and reproducible on no peer. No other guard in the function
 * covers it, so this single mutant dies to this single assertion. */
static void t_leg2_fault_halts(void) {
    TEST("leg 2 FAULT: unreadable validators row halts, never zero-fill");
    fx_t fx;
    nodus_committee_member_t *m = NULL;
    int n = 0, cn = 0;
    if (fx_up(&fx, "l2flt", 1, 0) != 0) { FAIL("fixture"); fx_free(&fx); return; }

    if (warm_committee(&fx, &n) != 0 || n != N_MEMBERS) {
        FAIL("healthy committee lookup did not produce N_MEMBERS");
        goto done;
    }
    /* Non-vacuity: healthy apply succeeds on this exact fixture. */
    if (nodus_witness_epoch_snapshot_apply(fx.w, EPOCH_H) != 0) {
        FAIL("healthy snapshot_apply failed");
        goto done;
    }
    nodus_epoch_state_t before;
    memset(&before, 0, sizeof(before));
    if (nodus_witness_epoch_get(fx.w, EPOCH_H, &before) != 0) {
        FAIL("no baseline row");
        goto done;
    }
    uint8_t hash_before[NODUS_EPOCH_SNAPSHOT_HASH_LEN];
    memcpy(hash_before, before.snapshot_hash, sizeof(hash_before));
    nodus_witness_epoch_free(&before);

    if (poison_validators(&fx, fx.pk[MEMBER_IDX]) != 0) {
        FAIL("poison");
        goto done;
    }

    /* Precondition A — leg 1 is NOT the one firing: the committee is
     * served from the warm cache and still answers 0. */
    if (nodus_committee_get_for_block_alloc(fx.w, EPOCH_H, &m, &cn) != 0 ||
        cn != N_MEMBERS) {
        free(m);
        FAIL("precondition: committee lookup no longer clean under poison");
        goto done;
    }
    free(m);

    /* Precondition B — the per-member read really is a FAULT (-1), which
     * is what distinguishes this from the ABSENT subtest above. */
    dnac_validator_record_t probe;
    if (nodus_validator_get(fx.w, fx.pk[MEMBER_IDX], &probe) != -1) {
        FAIL("precondition: poisoned row did not read as a fault");
        goto done;
    }

    if (nodus_witness_epoch_snapshot_apply(fx.w, EPOCH_H) != -1) {
        FAIL("a DB fault became a zero-filled validator record");
        goto done;
    }
    /* The previously committed row must be untouched — a halted apply
     * must not have half-written the epoch. */
    nodus_epoch_state_t after;
    memset(&after, 0, sizeof(after));
    if (nodus_witness_epoch_get(fx.w, EPOCH_H, &after) != 0) {
        FAIL("baseline row disappeared");
        goto done;
    }
    if (memcmp(hash_before, after.snapshot_hash, sizeof(hash_before)) != 0) {
        FAIL("the halted apply still moved snapshot_hash");
        nodus_witness_epoch_free(&after);
        goto done;
    }
    nodus_witness_epoch_free(&after);
    PASS();
done:
    fx_free(&fx);
}

/* ═══════════════════════════════════════════════════════════════════════
 * LEG 3 — the per-member delegation scan
 * ═════════════════════════════════════════════════════════════════════ */

/* ABSENT: a validator with no delegators. nodus_delegation_list_by_validator
 * reports that as rc 0 with count 0 — there is no separate "absent" code
 * on this path — so the empty list must still serialize.
 *
 * KILLED BY: `if (lrc != 0 || dcount == 0) return -1;`, i.e. mistaking an
 * empty delegator set for a fault. Every validator on a fresh chain has
 * one. */
static void t_leg3_absent_empty_deleg_set(void) {
    TEST("leg 3 ABSENT: a validator with no delegators still serializes");
    fx_t fx;
    if (fx_up(&fx, "l3abs", 1, 0) != 0) { FAIL("fixture"); fx_free(&fx); return; }

    if (nodus_witness_epoch_snapshot_apply(fx.w, EPOCH_H) != 0) {
        FAIL("an empty delegation set was treated as a fault");
        goto done;
    }
    nodus_epoch_state_t e;
    memset(&e, 0, sizeof(e));
    if (nodus_witness_epoch_get(fx.w, EPOCH_H, &e) != 0) {
        FAIL("no row");
        goto done;
    }
    if (blob_del_count(&e) != 0) {
        FAIL("delegation_count is not 0 on a chain with no delegations");
        nodus_witness_epoch_free(&e);
        goto done;
    }
    if (e.snapshot_blob_len != 2 + (size_t)N_MEMBERS * VAL_ENTRY_LEN + 4) {
        FAIL("unexpected blob length for a no-delegation chain");
        nodus_witness_epoch_free(&e);
        goto done;
    }
    nodus_witness_epoch_free(&e);
    PASS();
done:
    fx_free(&fx);
}

/* FAULT: the delegation scan for a member fails mid-stream.
 *
 * Only `delegations` is poisoned. The subtest asserts BOTH the committee
 * lookup and a direct nodus_validator_get are still clean, so legs 1 and
 * 2 are excluded by construction and a -1 can only be leg 3's.
 *
 * KILLED BY: restoring `if (lrc != 0) dcount = 0;`. The function then
 * returns 0 having written a blob whose delegation_count is 0 instead of
 * N_DELS — which is also why the non-vacuity twin asserts the healthy
 * count is exactly N_DELS: a mutant that silently dropped delegations on
 * the SUCCESS path would show up there rather than passing quietly. */
static void t_leg3_fault_halts(void) {
    TEST("leg 3 FAULT: a failed delegation scan halts, never 'no delegators'");
    fx_t fx;
    nodus_committee_member_t *m = NULL;
    dnac_delegation_record_t dbuf[8];
    int n = 0, cn = 0, dn = 0;
    if (fx_up(&fx, "l3flt", 1, 1) != 0) { FAIL("fixture"); fx_free(&fx); return; }

    if (warm_committee(&fx, &n) != 0 || n != N_MEMBERS) {
        FAIL("healthy committee lookup did not produce N_MEMBERS");
        goto done;
    }
    /* Non-vacuity: the healthy scan really does find the delegations. */
    if (nodus_witness_epoch_snapshot_apply(fx.w, EPOCH_H) != 0) {
        FAIL("healthy snapshot_apply failed");
        goto done;
    }
    nodus_epoch_state_t before;
    memset(&before, 0, sizeof(before));
    if (nodus_witness_epoch_get(fx.w, EPOCH_H, &before) != 0) {
        FAIL("no baseline row");
        goto done;
    }
    if (blob_del_count(&before) != (uint32_t)N_DELS) {
        FAIL("healthy blob does not carry N_DELS delegations");
        nodus_witness_epoch_free(&before);
        goto done;
    }
    uint8_t hash_before[NODUS_EPOCH_SNAPSHOT_HASH_LEN];
    memcpy(hash_before, before.snapshot_hash, sizeof(hash_before));
    nodus_witness_epoch_free(&before);

    if (poison_delegations(&fx) != 0) { FAIL("poison"); goto done; }

    /* Preconditions — legs 1 and 2 are untouched by this poison. */
    if (nodus_committee_get_for_block_alloc(fx.w, EPOCH_H, &m, &cn) != 0 ||
        cn != N_MEMBERS) {
        free(m);
        FAIL("precondition: committee lookup not clean under deleg poison");
        goto done;
    }
    free(m);
    dnac_validator_record_t probe;
    if (nodus_validator_get(fx.w, fx.pk[MEMBER_IDX], &probe) != 0) {
        FAIL("precondition: validators read not clean under deleg poison");
        goto done;
    }
    /* And the delegation scan itself really faults. */
    if (nodus_delegation_list_by_validator(fx.w, fx.pk[MEMBER_IDX], dbuf,
                                           8, &dn) == 0) {
        FAIL("precondition: poisoned delegation scan reported success");
        goto done;
    }

    if (nodus_witness_epoch_snapshot_apply(fx.w, EPOCH_H) != -1) {
        FAIL("a failed delegation scan became 'this validator has none'");
        goto done;
    }
    nodus_epoch_state_t after;
    memset(&after, 0, sizeof(after));
    if (nodus_witness_epoch_get(fx.w, EPOCH_H, &after) != 0) {
        FAIL("baseline row disappeared");
        goto done;
    }
    if (memcmp(hash_before, after.snapshot_hash, sizeof(hash_before)) != 0) {
        FAIL("the halted apply still moved snapshot_hash");
        nodus_witness_epoch_free(&after);
        goto done;
    }
    nodus_witness_epoch_free(&after);
    PASS();
done:
    fx_free(&fx);
}

int main(void) {
    printf("\nO15J A1 — epoch snapshot: a DB fault must HALT, not become a "
           "value\n");
    printf("======================================================="
           "=======================\n\n");

    t_leg1_absent_empty_chain_still_serializes();
    t_leg1_fault_halts();
    t_leg2_absent_zero_fills();
    t_leg2_fault_halts();
    t_leg3_absent_empty_deleg_set();
    t_leg3_fault_halts();

    printf("\n======================================================="
           "=======================\n");
    printf("Results: %d passed, %d failed\n\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
