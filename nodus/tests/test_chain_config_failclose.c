/**
 * @file nodus/tests/test_chain_config_failclose.c
 * @brief O15J Block 2 / A2 — nodus_chain_config_get_u64 must distinguish
 *        "no override is active" from "I cannot read the overrides", and
 *        its consensus consumers must fail closed on the second.
 *
 * ── WHAT WAS WRONG ────────────────────────────────────────────────────
 * The function returned `uint64_t` and had NO error channel. A prepare
 * failure returned `default_value`, and a failed step left `out ==
 * default_value` because sqlite3_step's result was only compared against
 * SQLITE_ROW. So under an IOERR/CORRUPT class fault a node used the
 * DEFAULT fee / block-interval / inflation-start / seat-count while its
 * healthy peers used the governance-voted override — a consensus split
 * with no Byzantine actor. The source named it in its own words as a
 * "KNOWN REMAINING HOLE".
 *
 * ── WHAT THIS FILE PINS ───────────────────────────────────────────────
 *   1. ABSENT is not a fault, in all three of its forms — empty table,
 *      no row at or below the queried height, and a fixture that never
 *      ran the migration. This is the pin that keeps a pre-genesis and a
 *      freshly-bootstrapping node starting; getting it wrong reproduces
 *      the v0.18.19 near-miss where a new hard -1 would have bricked
 *      every joining node during its bootstrap window.
 *   2. FAULT is -1 and leaves the caller's value UNTOUCHED.
 *   3. A fault is scoped to the param that faulted — an over-broad
 *      fail-close would take a whole cluster down on one bad row.
 *   4. The consumers fail closed rather than selecting a committee,
 *      sizing a snapshot or minting on a guessed parameter.
 *
 * ── FAULT INJECTION IS STRUCTURAL, NOT TIMED ──────────────────────────
 * chain_config_history is replaced by a VIEW whose flagged row projects
 * abs(-9223372036854775808) — SQLite raises "integer overflow" when that
 * row is evaluated. Same technique as test_chain_config_cache_failclose.c
 * and test_merkle_scan_fail_close.c. No sleeps, no timing, no randomness.
 *
 * NOTE for whoever maintains the sqlite_master probe in
 * nodus_witness_chain_config.c: it matches on NAME ALONE, deliberately.
 * If it ever grows a `type='table'` filter, every fixture below turns
 * into "absent" and this whole file goes vacuously green.
 *
 * FIXTURE: nodus_witness_t is multi-MB — calloc, never the stack.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "nodus/nodus_chain_config.h"

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_committee.h"
#include "witness/nodus_witness_validator.h"
#include "witness/nodus_witness_vset.h"
#include "witness/nodus_witness_v2_econ.h"

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

#define OVERFLOW_EXPR "abs(-9223372036854775808)"

#define P_TXS   ((uint8_t)DNAC_CFG_MAX_TXS_PER_BLOCK)      /* 1 */
#define P_INFL  ((uint8_t)DNAC_CFG_INFLATION_START_BLOCK)  /* 3 */
#define P_TAC   ((uint8_t)DNAC_CFG_TARGET_ACTIVE_COUNT)    /* 4 */

/* A sentinel the callee must never write over on a fault. */
#define UNTOUCHED 0x5A5A5A5A5A5A5A5AULL

/* Nine bonded validators: enough that a TARGET_ACTIVE_COUNT override of 9
 * produces a visibly different committee size than the default 7, which
 * is what makes the consumer twins non-vacuous. */
#define N_VALS   9

typedef struct {
    nodus_witness_t *w;
    char             dir[80];
    uint8_t          pk[N_VALS][DNAC_PUBKEY_SIZE];
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

/* Full-schema chain DB: WITNESS_DB_SCHEMA plus the whole migration chain,
 * which is where chain_config_history is created — on EVERY open, for
 * every node including a joining one. That is the property the ABSENT
 * cases below depend on. */
static int fx_up(fx_t *fx, const char *tag, int seed_validators) {
    memset(fx, 0, sizeof(*fx));
    fx->w = calloc(1, sizeof(*fx->w));
    if (!fx->w) return -1;
    fx->w->cached_committee_epoch_start = UINT64_MAX;

    snprintf(fx->dir, sizeof(fx->dir), "/tmp/test_cc_fc_%s_XXXXXX", tag);
    if (!mkdtemp(fx->dir)) { free(fx->w); fx->w = NULL; return -1; }
    snprintf(fx->w->data_path, sizeof(fx->w->data_path), "%s", fx->dir);

    uint8_t chain_id[16];
    memset(chain_id, 0xC3, sizeof(chain_id));
    if (nodus_witness_create_chain_db(fx->w, chain_id) != 0) return -1;
    if (!fx->w->db) return -1;

    for (int i = 0; i < N_VALS; i++)
        memset(fx->pk[i], (uint8_t)(0x20 + i), DNAC_PUBKEY_SIZE);

    if (!seed_validators) return 0;

    for (int i = 0; i < N_VALS; i++) {
        dnac_validator_record_t v;
        memset(&v, 0, sizeof(v));
        memcpy(v.pubkey, fx->pk[i], DNAC_PUBKEY_SIZE);
        v.self_stake         = 1000000ULL - (uint64_t)i * 1000ULL;
        v.commission_bps     = (uint16_t)(200 + i);
        v.status             = DNAC_VALIDATOR_ACTIVE;
        v.active_since_block = 1;
        memset(v.unstake_destination_fp, 'f',
               sizeof(v.unstake_destination_fp) - 1);
        if (nodus_validator_insert(fx->w, &v) != 0) return -1;
    }
    return 0;
}

/* Replace chain_config_history with a VIEW over cch_raw, carrying exactly
 * one governance row. `poison` selects whether THAT row raises when it is
 * evaluated. The real (empty) table created by the migration is renamed
 * out of the way, so the object the production code opens is the view. */
static int cc_view(fx_t *fx, uint8_t param_id, uint64_t value,
                   uint64_t effective_block, int poison) {
    if (exec_sql(fx->w,
        "ALTER TABLE chain_config_history RENAME TO cch_raw;") != 0)
        return -1;
    if (exec_sql(fx->w,
        "ALTER TABLE cch_raw ADD COLUMN bad INTEGER NOT NULL DEFAULT 0;")
        != 0) return -1;

    char sql[512];
    snprintf(sql, sizeof(sql),
        "INSERT INTO cch_raw (param_id, new_value, effective_block,"
        " commit_block, tx_hash, proposal_nonce, created_at_unix, bad)"
        " VALUES (%u, %llu, %llu, 1, x'00', 1, 0, %d);",
        (unsigned)param_id, (unsigned long long)value,
        (unsigned long long)effective_block, poison ? 1 : 0);
    if (exec_sql(fx->w, sql) != 0) return -1;

    if (exec_sql(fx->w,
        "CREATE VIEW chain_config_history AS SELECT param_id,"
        "  CASE WHEN bad = 1 THEN " OVERFLOW_EXPR " ELSE new_value END"
        "    AS new_value,"
        "  effective_block, commit_block, tx_hash, proposal_nonce,"
        "  created_at_unix FROM cch_raw;") != 0) return -1;

    /* Any earlier lookup may have warmed the cache over the old table. */
    fx->w->chain_config_cache_warm = false;
    for (int i = 0; i <= DNAC_CFG_PARAM_MAX_ID; i++)
        fx->w->chain_config_cache_count[i] = 0;
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════
 * 1 — the three-valued contract itself
 * ═════════════════════════════════════════════════════════════════════ */

/* ABSENT, form (a): the migrated table exists and is EMPTY — the state of
 * every chain in production today, and of every node that has just
 * bootstrapped its DB.
 *
 * KILLED BY: any mutant that collapses absent into the fault code (return
 * -1 on SQLITE_DONE, or dropping the `ret = 1` arm). That mutant is the
 * v0.18.19 bricking class: with the consumers below failing closed on -1,
 * it would stop every node on a chain with no governance rows — i.e. all
 * of them — from selecting a committee or minting a block. */
static void t_absent_empty_table(void) {
    TEST("ABSENT: empty migrated table answers 1 + default, never a fault");
    fx_t fx;
    if (fx_up(&fx, "abs_empty", 0) != 0) { FAIL("fixture"); fx_free(&fx); return; }

    uint64_t v = UNTOUCHED;
    int rc = nodus_chain_config_get_u64(fx.w, P_TXS, 1000, 42ULL, &v);
    if (rc != 1) { FAIL("empty table did not answer ABSENT"); goto done; }
    if (v != 42ULL) { FAIL("absent did not yield default_value"); goto done; }

    /* And again from the WARM cache — a hit and a miss must give the same
     * answer, rc included (root CLAUDE.md's cache rule). */
    if (!fx.w->chain_config_cache_warm) {
        FAIL("an empty table should still warm the cache");
        goto done;
    }
    v = UNTOUCHED;
    rc = nodus_chain_config_get_u64(fx.w, P_TXS, 1000, 42ULL, &v);
    if (rc != 1 || v != 42ULL) {
        FAIL("warm-cache answer differs from the cold one");
        goto done;
    }
    PASS();
done:
    fx_free(&fx);
}

/* ABSENT, form (b): the table does not exist at all — a hand-rolled unit
 * fixture that never ran nodus_chain_config_db_migrate. A schema object
 * that is absent holds no governance rows, so this is "no override", not
 * "unreadable".
 *
 * KILLED BY: removing the sqlite_master probe from the DB-direct
 * fallback, which turns a missing table into a prepare failure and hence
 * -1. Same bricking class as above, one layer down. */
static void t_absent_missing_table(void) {
    TEST("ABSENT: a missing chain_config_history is absent, not a fault");
    fx_t fx;
    uint64_t v = UNTOUCHED;
    int rc;
    if (fx_up(&fx, "abs_notbl", 0) != 0) { FAIL("fixture"); fx_free(&fx); return; }

    if (exec_sql(fx.w, "DROP TABLE chain_config_history;") != 0) {
        FAIL("drop");
        goto done;
    }
    fx.w->chain_config_cache_warm = false;

    rc = nodus_chain_config_get_u64(fx.w, P_TXS, 1000, 9ULL, &v);
    if (rc != 1) { FAIL("missing table did not answer ABSENT"); goto done; }
    if (v != 9ULL) { FAIL("absent did not yield default_value"); goto done; }
    PASS();
done:
    fx_free(&fx);
}

/* ABSENT, form (c): rows exist but none is effective at the queried
 * height. Semantics unchanged from before A2 — and asserting rc == 1 here
 * is what makes "not yet active" distinguishable from "unreadable".
 *
 * KILLED BY: a mutant that returns 0 for the not-yet-effective case (it
 * would claim an override is active when it is not) or -1 (bricking). */
static void t_absent_row_not_yet_effective(void) {
    TEST("ABSENT: a row below its effective_block is absent, not active");
    fx_t fx;
    uint64_t v = UNTOUCHED;
    if (fx_up(&fx, "abs_early", 0) != 0) { FAIL("fixture"); fx_free(&fx); return; }
    if (cc_view(&fx, P_TXS, 5ULL, 1000ULL, 0) != 0) { FAIL("view"); goto done; }

    if (nodus_chain_config_get_u64(fx.w, P_TXS, 999, 10ULL, &v) != 1 ||
        v != 10ULL) {
        FAIL("before the effective height should be ABSENT + default");
        goto done;
    }
    v = UNTOUCHED;
    if (nodus_chain_config_get_u64(fx.w, P_TXS, 1000, 10ULL, &v) != 0 ||
        v != 5ULL) {
        FAIL("at the effective height should be PRESENT + override");
        goto done;
    }
    PASS();
done:
    fx_free(&fx);
}

/* FAULT: the row for the queried param cannot be read.
 *
 * KILLED BY: restoring either fail-open exit — `return default_value` on
 * the prepare failure, or initialising `out = default_value` and only
 * overwriting on SQLITE_ROW. Both make this call return the default,
 * which the ABSENT subtests above show is a legitimate answer, so the
 * node would proceed on a value its peers do not share. The `v ==
 * UNTOUCHED` assertion additionally kills a mutant that returns -1 but
 * still writes the default through the out-parameter — a caller that
 * ignored the rc would then silently keep the old behaviour. */
static void t_fault_returns_minus_one(void) {
    TEST("FAULT: an unreadable row is -1 and leaves *value_out untouched");
    fx_t fx;
    uint64_t v = UNTOUCHED;
    if (fx_up(&fx, "flt", 0) != 0) { FAIL("fixture"); fx_free(&fx); return; }

    /* Non-vacuity twin FIRST: the identical row, poison off, is served. */
    if (cc_view(&fx, P_TXS, 5ULL, 1ULL, 0) != 0) { FAIL("view"); goto done; }
    if (nodus_chain_config_get_u64(fx.w, P_TXS, 1000, 42ULL, &v) != 0 ||
        v != 5ULL) {
        FAIL("healthy view did not serve the override — fixture is vacuous");
        goto done;
    }
    fx_free(&fx);

    /* Same row, poison ON. */
    if (fx_up(&fx, "flt2", 0) != 0) { FAIL("fixture"); fx_free(&fx); return; }
    if (cc_view(&fx, P_TXS, 5ULL, 1ULL, 1) != 0) { FAIL("view"); goto done; }
    v = UNTOUCHED;
    if (nodus_chain_config_get_u64(fx.w, P_TXS, 1000, 42ULL, &v) != -1) {
        FAIL("an unreadable override did not report a fault");
        goto done;
    }
    if (v != UNTOUCHED) {
        FAIL("*value_out was written on the fault path");
        goto done;
    }
    /* The cache must not have latched: a second call re-asks and faults
     * again rather than answering from a partial fill. */
    if (fx.w->chain_config_cache_warm) {
        FAIL("cache marked warm after a failed scan");
        goto done;
    }
    v = UNTOUCHED;
    if (nodus_chain_config_get_u64(fx.w, P_TXS, 1000, 42ULL, &v) != -1 ||
        v != UNTOUCHED) {
        FAIL("second lookup diverged from the first");
        goto done;
    }
    PASS();
done:
    fx_free(&fx);
}

/* A fault must be SCOPED to the param that faulted. One unreadable
 * governance row must not take every parameter — and therefore the whole
 * node — offline.
 *
 * KILLED BY: an over-broad fail-close, e.g. propagating
 * cc_cache_warm_from_db's -1 straight out of get_u64 instead of falling
 * through to the DB-direct lookup. That mutant passes every FAULT
 * assertion in this file and fails only here. */
static void t_fault_is_param_scoped(void) {
    TEST("SCOPE: a poisoned param does not fault an unrelated param");
    fx_t fx;
    uint64_t v = UNTOUCHED;
    if (fx_up(&fx, "scope", 0) != 0) { FAIL("fixture"); fx_free(&fx); return; }

    /* Two rows: param 1 healthy, param 4 poisoned. The warm scan reads
     * BOTH and therefore fails, so every lookup goes DB-direct. */
    if (exec_sql(fx.w,
        "ALTER TABLE chain_config_history RENAME TO cch_raw;") != 0 ||
        exec_sql(fx.w,
        "ALTER TABLE cch_raw ADD COLUMN bad INTEGER NOT NULL DEFAULT 0;")
        != 0 ||
        exec_sql(fx.w,
        "INSERT INTO cch_raw (param_id, new_value, effective_block,"
        " commit_block, tx_hash, proposal_nonce, created_at_unix, bad)"
        " VALUES (1, 5, 1, 1, x'00', 1, 0, 0);") != 0 ||
        exec_sql(fx.w,
        "INSERT INTO cch_raw (param_id, new_value, effective_block,"
        " commit_block, tx_hash, proposal_nonce, created_at_unix, bad)"
        " VALUES (4, 21, 1, 1, x'00', 2, 0, 1);") != 0 ||
        exec_sql(fx.w,
        "CREATE VIEW chain_config_history AS SELECT param_id,"
        "  CASE WHEN bad = 1 THEN " OVERFLOW_EXPR " ELSE new_value END"
        "    AS new_value,"
        "  effective_block, commit_block, tx_hash, proposal_nonce,"
        "  created_at_unix FROM cch_raw;") != 0) {
        FAIL("fixture");
        goto done;
    }
    fx.w->chain_config_cache_warm = false;

    if (nodus_chain_config_get_u64(fx.w, P_TAC, 1000, 7ULL, &v) != -1) {
        FAIL("the poisoned param did not fault");
        goto done;
    }
    v = UNTOUCHED;
    if (nodus_chain_config_get_u64(fx.w, P_TXS, 1000, 42ULL, &v) != 0 ||
        v != 5ULL) {
        FAIL("a healthy param was collateral damage of another's fault");
        goto done;
    }
    PASS();
done:
    fx_free(&fx);
}

/* An out-of-range param id is a CALLER bug, and the contract's answer for
 * "I cannot tell you" is -1. It used to return default_value, which is
 * the same answer as "this param has no override" — so a typo'd id read
 * as unconfigured chain state.
 *
 * KILLED BY: restoring `if (param_id >= CC_PARAM_SLOTS) return
 * default_value;`. */
static void t_out_of_range_param_is_a_fault(void) {
    TEST("out-of-range param id is a fault, not 'unconfigured'");
    fx_t fx;
    if (fx_up(&fx, "range", 0) != 0) { FAIL("fixture"); fx_free(&fx); return; }

    uint64_t v = UNTOUCHED;
    if (nodus_chain_config_get_u64(fx.w,
            (uint8_t)(DNAC_CFG_PARAM_MAX_ID + 1), 999, 1234ULL, &v) != -1) {
        FAIL("out-of-range id did not fault");
        goto done;
    }
    if (v != UNTOUCHED) { FAIL("*value_out written on a fault"); goto done; }

    /* Non-vacuity: the LAST in-range id is still perfectly readable, so
     * the guard moved rather than swallowing the whole allowlist. */
    v = UNTOUCHED;
    if (nodus_chain_config_get_u64(fx.w, (uint8_t)DNAC_CFG_PARAM_MAX_ID,
                                   999, 1234ULL, &v) != 1 || v != 1234ULL) {
        FAIL("the last in-range param id stopped working");
        goto done;
    }
    PASS();
done:
    fx_free(&fx);
}

/* ═══════════════════════════════════════════════════════════════════════
 * 2 — the consumers
 * ═════════════════════════════════════════════════════════════════════ */

/* CONSUMER: the committee selector. TARGET_ACTIVE_COUNT decides how many
 * seats the epoch has; a node that cannot read it cannot know the
 * committee, and a committee is what authorises votes and what
 * snapshot_hash is built from.
 *
 * Non-vacuity twin: the SAME row, poison off, must change the committee
 * size from the default 7 to 9 — proving the override is genuinely being
 * read and that the -1 below is the poison talking, not the fixture.
 *
 * KILLED BY: reverting committee_target_for_epoch to return the clamped
 * default on rc < 0. The committee then comes back with 7 members and
 * rc 0 — a well-formed answer no peer would agree with. */
static void t_committee_fails_closed(void) {
    TEST("consumer: committee selection halts on an unreadable seat count");
    fx_t fx;

    /* Twin: healthy override of 9 seats. */
    if (fx_up(&fx, "cmt_ok", 1) != 0) { FAIL("fixture"); fx_free(&fx); return; }
    if (cc_view(&fx, P_TAC, (uint64_t)N_VALS, 0ULL, 0) != 0) {
        FAIL("view"); goto done;
    }
    {
        nodus_committee_member_t *m = NULL;
        int n = 0;
        if (nodus_committee_get_for_block_alloc(fx.w, 0, &m, &n) != 0) {
            FAIL("healthy committee lookup failed");
            goto done;
        }
        free(m);
        if (n != N_VALS) {
            FAIL("the seat-count override was not applied — twin is vacuous");
            goto done;
        }
    }
    fx_free(&fx);

    /* Same row, poisoned. */
    if (fx_up(&fx, "cmt_bad", 1) != 0) { FAIL("fixture"); fx_free(&fx); return; }
    if (cc_view(&fx, P_TAC, (uint64_t)N_VALS, 0ULL, 1) != 0) {
        FAIL("view"); goto done;
    }
    {
        nodus_committee_member_t *m = NULL;
        int n = 0;
        int rc = nodus_committee_get_for_block_alloc(fx.w, 0, &m, &n);
        free(m);
        if (rc != -1) {
            FAIL("a guessed seat count produced a committee anyway");
            goto done;
        }
    }
    PASS();
done:
    fx_free(&fx);
}

/* CONSUMER: the validator-set snapshot builder, which must agree with the
 * committee selector about how many seats an epoch has.
 *
 * ⚠ HONEST LIMIT OF THIS ASSERTION — stated so nobody reads it as more
 * than it is. vset_target_for_epoch and committee_target_for_epoch read
 * the SAME param at the SAME key, and vset_build_and_store calls
 * nodus_witness_vset_build_for_epoch, which computes the committee
 * DIRECTLY (nodus_witness_vset.h says why). So a mutant that reverts ONLY
 * vset_target_for_epoch's guard SURVIVES this test: the read one layer
 * down still fails and the -1 still appears. What this assertion kills is
 * the COMPOUND mutant (both guards reverted) and any regression that
 * makes commit_genesis succeed under an unreadable parameter.
 *
 * The vset guard is not therefore redundant: the two reads are two
 * separate SQLite calls, so a transient fault can hit the first and miss
 * the second. It is simply not independently killable by a DB-fault test,
 * and saying so is better than implying coverage that does not exist. */
static void t_vset_fails_closed(void) {
    TEST("consumer: genesis vset snapshot halts on an unreadable seat count");
    fx_t fx;

    /* Twin: healthy. commit_genesis must seed both epoch rows. */
    if (fx_up(&fx, "vs_ok", 1) != 0) { FAIL("fixture"); fx_free(&fx); return; }
    if (cc_view(&fx, P_TAC, (uint64_t)N_VALS, 0ULL, 0) != 0) {
        FAIL("view"); goto done;
    }
    if (nodus_witness_vset_commit_genesis(fx.w, 1) != 0) {
        FAIL("healthy commit_genesis failed — twin is vacuous");
        goto done;
    }
    {
        /* And it really used the override: 9 seats, not the default 7. */
        dna_vset_snapshot_t *snap = NULL;
        if (nodus_witness_vset_get(fx.w, 0, &snap, NULL) != 0 || !snap) {
            FAIL("no genesis snapshot row");
            goto done;
        }
        int ac = (int)snap->active_count;
        dna_vset_free(&snap);
        if (ac != N_VALS) {
            FAIL("the snapshot ignored the seat-count override");
            goto done;
        }
    }
    fx_free(&fx);

    /* Same row, poisoned. */
    if (fx_up(&fx, "vs_bad", 1) != 0) { FAIL("fixture"); fx_free(&fx); return; }
    if (cc_view(&fx, P_TAC, (uint64_t)N_VALS, 0ULL, 1) != 0) {
        FAIL("view"); goto done;
    }
    if (nodus_witness_vset_commit_genesis(fx.w, 1) != -1) {
        FAIL("a snapshot was sized from a guessed seat count");
        goto done;
    }
    {
        dna_vset_snapshot_t *snap = NULL;
        int g = nodus_witness_vset_get(fx.w, 0, &snap, NULL);
        if (g == 0) {
            dna_vset_free(&snap);
            FAIL("a snapshot row was written despite the fault");
            goto done;
        }
    }
    PASS();
done:
    fx_free(&fx);
}

/* CONSUMER: the V2 emission gate. This is the exact parameter
 * nodus_witness_chain_config.c named in its KNOWN REMAINING HOLE note —
 * inflation-start — and the exact place the tree's comments claimed a
 * 1ULL default made a fetch failure safe.
 *
 * The twin is the same row with the poison off, carrying the explicit 0
 * that disables emission: the healthy read returns rc 0 with value 0, so
 * emission_apply returns 0 having minted nothing. That proves the read
 * path works AND that "explicit 0 disables emission" still holds — the
 * behaviour the substituted default could never honour on a fault.
 *
 * KILLED BY: reverting to the unchecked read. inflation_start then takes
 * the 1ULL default, emission becomes non-zero, and the function walks on
 * into the supply path instead of returning -2 — a node minting on a
 * schedule its peers do not share. */
static void t_emission_fails_closed(void) {
    TEST("consumer: V2 emission halts on an unreadable inflation-start");
    fx_t fx;

    /* Twin: healthy explicit 0 => emission off, rc 0, nothing minted. */
    if (fx_up(&fx, "em_ok", 1) != 0) { FAIL("fixture"); fx_free(&fx); return; }
    if (cc_view(&fx, P_INFL, 0ULL, 0ULL, 0) != 0) { FAIL("view"); goto done; }
    {
        uint64_t minted = UNTOUCHED;
        if (nodus_witness_v2_emission_apply(fx.w, 5, &minted) != 0) {
            FAIL("healthy emission gate did not succeed — twin is vacuous");
            goto done;
        }
        if (minted != 0) {
            FAIL("an explicit inflation-start of 0 still minted");
            goto done;
        }
    }
    fx_free(&fx);

    /* Same row, poisoned. */
    if (fx_up(&fx, "em_bad", 1) != 0) { FAIL("fixture"); fx_free(&fx); return; }
    if (cc_view(&fx, P_INFL, 0ULL, 0ULL, 1) != 0) { FAIL("view"); goto done; }
    {
        uint64_t minted = UNTOUCHED;
        if (nodus_witness_v2_emission_apply(fx.w, 5, &minted) != -2) {
            FAIL("emission proceeded on a guessed inflation schedule");
            goto done;
        }
    }
    PASS();
done:
    fx_free(&fx);
}

int main(void) {
    printf("\nO15J A2 — chain_config: ABSENT is not a FAULT, and a FAULT "
           "halts\n");
    printf("======================================================="
           "=======================\n\n");

    t_absent_empty_table();
    t_absent_missing_table();
    t_absent_row_not_yet_effective();
    t_fault_returns_minus_one();
    t_fault_is_param_scoped();
    t_out_of_range_param_is_a_fault();
    t_committee_fails_closed();
    t_vset_fails_closed();
    t_emission_fails_closed();

    printf("\n======================================================="
           "=======================\n");
    printf("Results: %d passed, %d failed\n\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
