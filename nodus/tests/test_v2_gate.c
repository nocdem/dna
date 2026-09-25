/**
 * @file nodus/tests/test_v2_gate.c
 * @brief O15B — the activation gate and the network result algebra.
 *
 * ── WHAT THIS TEST IS FOR ─────────────────────────────────────────────
 * The claim that makes the Ledger V2 network surface safe is narrow and
 * checkable:
 *
 *   1. The gate stays SHUT on a database that is not a Ledger V2 chain,
 *      and no input reaches it that could change that.
 *   2. Ingress-arming (the gate's own arm/disarm/is_armed mechanism, NOT
 *      the deleted block-ingress path below) is unreachable unless the
 *      gate opened.
 *   3. NOT_ACTIVE, INTERNAL_FAULT and NOT_YET_LINKABLE never blame a
 *      peer, per the result-algebra predicates.
 *
 * R3 W4-D — the closed consensus lane's deletion removes this file's
 * OWN "ingress reachability" half: claims 2 and 3 as originally written
 * here asserted a V2 frame reaching nodus_witness_v2_ingress_block (the
 * old-lane block-ingress entry point, deleted with
 * nodus_witness_v2_ingress.c) produces NOT_ACTIVE with no side effect.
 * That entry point no longer exists on the version-3 lane — Comet block
 * application does not go through it — so those two cases are deleted,
 * not rewritten onto a substitute; see the register for what remains
 * (the gate's own arm/disarm mechanism, and the result-algebra
 * predicates on the enum values directly, which need no live call to
 * assert).
 *
 * ⚠ WHAT NO_AUTHORITY MEANS SINCE O15J Faz 3 ──────────────────────────
 * The activation ceremony is GONE, and with it the reading of
 * NO_AUTHORITY this file was written under ("this binary has no
 * activation authority compiled in"). Authority is now a property of the
 * DATABASE: a chain whose committed height-0 genesis manifest carries the
 * pure-V2 source tag IS its own authority, and such a chain opens the
 * gate in an ORDINARY build.
 *
 * Every fixture here is a bare `nodus_witness_create_chain_db` database —
 * NOT a pure-V2 chain — so every "the gate is shut" assertion below still
 * holds, but it now means "this database is not a V2 chain", not "this
 * software cannot activate V2 at all".
 *
 * The other half of the contract — that a REAL pure-V2 chain DOES open
 * the gate and DOES arm, in a build carrying no authority macro at all —
 * is `test_v2_gate_pure.c`. It must never be merged into this file: this
 * target compiles the synthetic-authority fixture in, and a test that can
 * grant itself authority cannot prove authority is derived.
 *
 * ── ON THE TEST-ONLY AUTHORITY FIXTURE ────────────────────────────────
 * `nodus_witness_v2_gate_test_arm()` exists only under
 * NODUS_V2_TEST_AUTHORITY, which CMake defines on test targets that
 * compile the gate TU in, and on no library or server target.
 * `test_v2_gate_linked` proves its absence from the shipped binaries with
 * `nm`. Using it here is what lets the ARMED paths be exercised on a
 * database that could never open the gate on its own merits.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <unistd.h>

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_v2_gate.h"
#include "witness/nodus_witness_v2_preflight.h"
#include "witness/nodus_witness_v2_result.h"
/* R3 W4-D — nodus_witness_v2_ingress.h (file deleted; ingress_block /
 * _queue_stats / _queue_clear were this file's only users here),
 * nodus_witness_v2_sync2.h (its sync-range/restart-check symbols this
 * file called are all deleted with the old-lane half of that file),
 * nodus_witness_v2_schema.h (nodus_witness_db_migrate_v2s9, used only by
 * the deleted restart-integrity case), dnac/blockmsg_v2.h and
 * v2_genesis_fixture.h (make_frame / db_digest, both deleted — their
 * only callers were the two deleted ingress-block cases) are DROPPED
 * with the closed consensus lane. */

static int checks;
#define CHECK(c, msg)                                                     \
    do {                                                                  \
        if (!(c)) {                                                       \
            printf("CHECK failed at %s:%d: %s\n", __FILE__, __LINE__,      \
                   msg);                                                  \
            exit(1);                                                      \
        }                                                                 \
        checks++;                                                         \
    } while (0)

typedef struct {
    char             dir[256];
    nodus_witness_t *w;
} fx_t;

static int fx_open(fx_t *f, const char *tag) {
    snprintf(f->dir, sizeof(f->dir), "/tmp/test_v2_gate_%s_XXXXXX", tag);
    if (!mkdtemp(f->dir)) return -1;
    f->w = calloc(1, sizeof(*f->w));    /* multi-MB — never on the stack */
    if (!f->w) return -1;
    snprintf(f->w->data_path, sizeof(f->w->data_path), "%s", f->dir);
    uint8_t chain_id16[16];
    memset(chain_id16, 0x3c, sizeof(chain_id16));
    if (nodus_witness_create_chain_db(f->w, chain_id16) != 0) return -1;
    return 0;
}

static void fx_close(fx_t *f) {
    if (f->w) {
        if (f->w->db) sqlite3_close(f->w->db);
        free(f->w);
        f->w = NULL;
    }
}

/* R3 W4-D — db_digest (the whole-database FNV digest oracle wrapper) and
 * make_frame (the structurally-valid-but-meaningless BlockMessage v1
 * builder) are DELETED: their only callers were the cases that used to
 * occupy slots 5 and 11, both deleted with the closed consensus lane
 * (nodus_witness_v2_ingress_block, their common subject, is gone). */

int main(void) {
    printf("=== O15B — activation gate, ingress reachability, result algebra ===\n");

    /* ── 1. THE GATE IS CLOSED, AND CLOSED FOR THE RIGHT REASON ────────
     * NO_AUTHORITY, not NOT_READY: the distinction is what tells an
     * operator "this database is not a Ledger V2 chain, so nothing here
     * could ever activate" apart from "this is a V2 chain but it is not
     * ready yet". This fixture is a bare chain database with no committed
     * genesis manifest, so the first is the correct answer. */
    {
        fx_t f = {0};
        CHECK(fx_open(&f, "closed") == 0, "fixture open");
        CHECK(nodus_witness_v2_gate_state(f.w) == NODUS_V2_GATE_NO_AUTHORITY,
              "a database that is not a Ledger V2 chain must report "
              "NO_AUTHORITY");
        CHECK(nodus_witness_v2_activation_permitted(f.w) == 0,
              "activation must not be permitted");
        CHECK(strcmp(nodus_witness_v2_gate_state_name(
                         NODUS_V2_GATE_NO_AUTHORITY), "NO_AUTHORITY") == 0,
              "state name is stable");
        fx_close(&f);
    }

    /* ── 2. A NULL / DATABASE-LESS HANDLE IS A FAULT, NOT A STATE ──────
     * "We could not tell" must never be reported as "not ready": the two
     * call for different operator responses, and only one of them is a
     * bug. */
    {
        CHECK(nodus_witness_v2_gate_state(NULL) == NODUS_V2_GATE_FAULT,
              "NULL handle is a FAULT");
        CHECK(nodus_witness_v2_activation_permitted(NULL) == 0,
              "NULL handle never permits activation");
    }

    /* ── 3. THE PREFLIGHT IS NOT READY ON A FRESH DATABASE ─────────────
     * O15C: issue 12 is RETIRED (the V2 attendance writer exists in this
     * build), so the standing unconditional issue is gone — but a fresh
     * database is still blocked by real findings (schema, genesis), and
     * the retired id must never reappear. */
    {
        fx_t f = {0};
        CHECK(fx_open(&f, "pf") == 0, "fixture open");
        nodus_v2_preflight_report_t rep;
        CHECK(nodus_witness_v2_preflight(f.w, &rep) == 0, "preflight ran");
        CHECK(rep.ready == 0, "a fresh database must not be ready");
        int saw_rule_n = 0;
        for (size_t i = 0; i < rep.n_issues; i++)
            if (rep.issues[i] == NODUS_V2_PF_RULE_N_ATTENDANCE_SOURCE_ABSENT)
                saw_rule_n = 1;
        CHECK(!saw_rule_n,
              "retired issue 12 must never be raised again");
        fx_close(&f);
    }

    /* ── 4. INGRESS CANNOT BE ARMED WHILE THE GATE IS SHUT ─────────────
     * And a refused arm leaves the node UNARMED — there is no partial
     * arming, so a failed attempt cannot leave a half-open door. */
    {
        fx_t f = {0};
        CHECK(fx_open(&f, "arm") == 0, "fixture open");
        CHECK(nodus_witness_v2_ingress_is_armed(f.w) == 0,
              "a fresh node starts UNARMED");
        CHECK(nodus_witness_v2_ingress_arm(f.w) != 0,
              "arming must be refused while the gate is shut");
        CHECK(nodus_witness_v2_ingress_is_armed(f.w) == 0,
              "a refused arm leaves the node UNARMED");
        fx_close(&f);
    }

    /* R3 W4-D — the case that used to occupy slot 5, "a V2 frame on a
     * production node: NOT_ACTIVE, and nothing else", is DELETED with
     * the closed consensus lane: it drove nodus_witness_v2_ingress_
     * block / _queue_stats, both defined only in the deleted
     * nodus_witness_v2_ingress.c. Every case number from here on is
     * renumbered down by one to close the gap. */

    /* ── 5. NOT_ACTIVE IS NOT ANY OTHER CLASS ─────────────────────────
     * The classifiers are the contract every network caller routes on, so
     * the separations are pinned by value rather than trusted. */
    {
        CHECK(NODUS_V2_NOT_ACTIVE == -6, "NOT_ACTIVE has its pinned value");
        CHECK(!nodus_v2_result_is_accepted(NODUS_V2_NOT_ACTIVE),
              "NOT_ACTIVE is not an acceptance");
        CHECK(!nodus_v2_result_is_verdict(NODUS_V2_NOT_ACTIVE),
              "NOT_ACTIVE IS NOT A VERDICT");
        CHECK(!nodus_v2_result_is_undecided(NODUS_V2_NOT_ACTIVE),
              "NOT_ACTIVE is not 'tried and could not decide'");
        CHECK(nodus_v2_result_is_not_active(NODUS_V2_NOT_ACTIVE),
              "NOT_ACTIVE has its own predicate");
        /* The values O15A pinned must not have moved. */
        CHECK(NODUS_V2_ACCEPTED == 0 && NODUS_V2_IDEMPOTENT_REPLAY == 1 &&
              NODUS_V2_ACCEPTED_PRECACHE == 2 &&
              NODUS_V2_CONSENSUS_INVALID == -1 &&
              NODUS_V2_INTERNAL_FAULT == -2 &&
              NODUS_V2_NOT_YET_LINKABLE == -3 &&
              NODUS_V2_RETIRED_VERSION == -4 &&
              NODUS_V2_UNSUPPORTED_VERSION == -5,
              "the O15A result values are UNMOVED");
    }

    /* ── 6. WHO MAY BE BLAMED — the single peer-policy predicate ───────
     * The three "never blame" rows of the ingress table are the point of
     * the whole algebra, so they are asserted directly. */
    {
        CHECK(nodus_v2_result_blames_peer(NODUS_V2_CONSENSUS_INVALID),
              "a deterministic verdict may be held against a peer");
        CHECK(nodus_v2_result_blames_peer(NODUS_V2_RETIRED_VERSION),
              "a retired version is a verdict");
        CHECK(nodus_v2_result_blames_peer(NODUS_V2_UNSUPPORTED_VERSION),
              "an unsupported version is a verdict");
        CHECK(!nodus_v2_result_blames_peer(NODUS_V2_NOT_YET_LINKABLE),
              "A PEER IS NEVER BLAMED FOR OUR OWN LAG");
        CHECK(!nodus_v2_result_blames_peer(NODUS_V2_INTERNAL_FAULT),
              "A PEER IS NEVER BLAMED FOR OUR OWN FAULT");
        CHECK(!nodus_v2_result_blames_peer(NODUS_V2_NOT_ACTIVE),
              "A PEER IS NEVER BLAMED FOR OUR OWN INACTIVITY");
        CHECK(!nodus_v2_result_blames_peer(NODUS_V2_ACCEPTED),
              "an accepted block blames nobody");
    }

    /* R3 W4-D — the cases that used to occupy slots 8 and 9, "sync and
     * restart are gated too" and "an incompatible peer is never worth
     * syncing from", are DELETED with the closed consensus lane: both
     * drove nodus_witness_v2_sync_plan_range / _apply_range / _restart_
     * check / _peer_compatible, all defined only in the old-lane half of
     * nodus_witness_v2_sync2.c, itself deleted this delta (verbs 20-23
     * and the restart integrity check). Every case number from here on
     * is renumbered down by two to close the gap. */

#ifdef NODUS_V2_TEST_AUTHORITY
    /* ── 7. THE ARMED PATH ON A DATABASE THAT COULD NEVER OPEN ────────
     *
     * This fixture is NOT a Ledger V2 chain, so the only way it reaches
     * the armed ingress/queue/sync code is the synthetic fixture — and
     * without this section that code would ship unexercised on this
     * database shape, which is its own hazard. The fixture grants exactly
     * the authority half and nothing more, and the two halves of the gate
     * stay separately controllable so a test cannot silently conflate
     * them.
     *
     * A chain that opens the gate on its OWN committed authority is a
     * different test entirely (test_v2_gate_pure.c) — and it must stay
     * different, because it is only meaningful in a build where this
     * fixture does not exist.
     */
    {
        fx_t f = {0};
        CHECK(fx_open(&f, "armed") == 0, "fixture open");

        /* Authority alone is NOT enough — readiness is still evaluated for
         * real, and this bare fixture database has genuine blocking
         * findings (no V2 schema, no committed genesis). */
        nodus_witness_v2_gate_test_arm(f.w, 0);
        CHECK(nodus_witness_v2_gate_state(f.w) == NODUS_V2_GATE_NOT_READY,
              "authority WITHOUT readiness is NOT_READY, not OPEN");
        CHECK(nodus_witness_v2_ingress_arm(f.w) != 0,
              "authority alone must not permit arming");

        /* Both halves — the only configuration that can arm. */
        nodus_witness_v2_gate_test_arm(f.w, 1);
        CHECK(nodus_witness_v2_gate_state(f.w) == NODUS_V2_GATE_OPEN,
              "authority AND readiness is OPEN");
        CHECK(nodus_witness_v2_ingress_arm(f.w) == 0, "arming succeeds");
        CHECK(nodus_witness_v2_ingress_is_armed(f.w) == 1, "node is armed");

        /* ISSUE 13 IS NOW A REAL COMPUTED CHECK. With the readiness half
         * forced, the preflight sees an ARMED node whose authority is
         * synthetic — the state that must never occur — and says so.
         * O15A could not raise this at all; it argued from a structural
         * claim that O15B's own code retired. */
        nodus_witness_v2_gate_test_arm(f.w, 0);      /* readiness back on */
        nodus_v2_preflight_report_t rep;
        CHECK(nodus_witness_v2_preflight(f.w, &rep) == 0, "preflight ran");
        int saw_ingress = 0;
        for (size_t i = 0; i < rep.n_issues; i++)
            if (rep.issues[i] == NODUS_V2_PF_INGRESS_ENABLED) saw_ingress = 1;
        CHECK(saw_ingress,
              "ISSUE 13 MUST BE RAISED when ingress is armed and the gate "
              "is not open");
        CHECK(rep.ready == 0, "and the report is not ready");

        /* Disarm clears it — the check tracks the ACTUAL state, it is not
         * a latch that stays set once tripped. */
        nodus_witness_v2_ingress_disarm(f.w);
        CHECK(nodus_witness_v2_preflight(f.w, &rep) == 0, "preflight ran");
        saw_ingress = 0;
        for (size_t i = 0; i < rep.n_issues; i++)
            if (rep.issues[i] == NODUS_V2_PF_INGRESS_ENABLED) saw_ingress = 1;
        CHECK(!saw_ingress, "issue 13 clears when ingress is disarmed");

        nodus_witness_v2_gate_test_clear(f.w);
        CHECK(nodus_witness_v2_gate_state(f.w) == NODUS_V2_GATE_NO_AUTHORITY,
              "clearing the fixture restores the DERIVED state — and for "
              "this database that is NO_AUTHORITY, because it is not a "
              "Ledger V2 chain");
        CHECK(nodus_witness_v2_ingress_is_armed(f.w) == 0,
              "clearing the fixture disarms");
        fx_close(&f);
    }

    /* R3 W4-D — the case that used to occupy slot 11, "an armed node
     * still refuses a malformed frame", is DELETED with the closed
     * consensus lane: it drove nodus_witness_v2_ingress_block, defined
     * only in the deleted nodus_witness_v2_ingress.c. */
#endif /* NODUS_V2_TEST_AUTHORITY */

#ifdef NODUS_V2_TEST_AUTHORITY
    /* R3 W4-D — the case that used to occupy slot 12, "restart
     * integrity — the armed path", is DELETED with the closed consensus
     * lane: it drove nodus_witness_v2_sync_restart_check, deleted this
     * delta once its production callers were confirmed gone (register
     * R3-W4-D-10). Every case number from here on is renumbered down by
     * one. */

    /* ── 8. THE WITNESS UTXO READ FAILS CLOSED ON A MALFORMED ROW ────
     *
     * Also added from the mutation campaign: nothing exercised the
     * negative-height guard, so a mutant that let a negative stored
     * `unlock_block` wrap to a huge u64 survived. A wrapped value reads as
     * "unlocked long ago", which is the WRONG direction — it is exactly
     * the coin consensus refuses. */
    {
        fx_t f = {0};
        CHECK(fx_open(&f, "utxoneg") == 0, "fixture open");

        static const char *OWNER =
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        sqlite3_stmt *st = NULL;
        const char *sql =
            "INSERT INTO utxo_set (nullifier, owner, amount, token_id, "
            " tx_hash, output_index, block_height, created_at, unlock_block) "
            /* -5, NOT -1.
             *
             * The mutation campaign killed an earlier version of this test
             * for being a tautology: with -1, the guard's UINT64_MAX and
             * the unguarded `(uint64_t)ub` produce the SAME value, so
             * deleting the guard changed nothing observable. -5 casts to
             * 0xFFFF...FB, which differs from UINT64_MAX — so the
             * assertion below can only pass if the guard actually ran. */
            "VALUES (?1, ?2, 100, ?3, ?4, 0, 1, 0, -5)";
        if (sqlite3_prepare_v2(f.w->db, sql, -1, &st, NULL) == SQLITE_OK) {
            uint8_t nf[64], tok[64], txh[64];
            memset(nf, 0x21, sizeof(nf));
            memset(tok, 0, sizeof(tok));
            memset(txh, 0x22, sizeof(txh));
            sqlite3_bind_blob(st, 1, nf, 64, SQLITE_STATIC);
            sqlite3_bind_text(st, 2, OWNER, -1, SQLITE_STATIC);
            sqlite3_bind_blob(st, 3, tok, 64, SQLITE_STATIC);
            sqlite3_bind_blob(st, 4, txh, 64, SQLITE_STATIC);
            int rc = sqlite3_step(st);
            sqlite3_finalize(st);
            CHECK(rc == SQLITE_DONE, "planted a NEGATIVE unlock_block row");

            nodus_witness_utxo_entry_t rows[4];
            int n = 0;
            CHECK(nodus_witness_utxo_by_owner(f.w, OWNER, rows, 4, &n) == 0,
                  "the query succeeds");
            CHECK(n == 1, "one row returned");
            CHECK(rows[0].unlock_block == UINT64_MAX,
                  "A NEGATIVE STORED HEIGHT READS AS LOCKED-FOREVER — it "
                  "must never wrap to a huge value that reads as spendable");
        } else {
            CHECK(0, "could not prepare the utxo_set insert");
        }
        fx_close(&f);
    }
#endif /* NODUS_V2_TEST_AUTHORITY */

    printf("test_v2_gate: ALL %d checks passed\n", checks);
    return 0;
}
