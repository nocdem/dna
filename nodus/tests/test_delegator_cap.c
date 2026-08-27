/**
 * Nodus — the per-validator delegator CAP, LEGACY lane (O15J Block 2)
 *
 * THE BUG THIS PINS. nodus_witness_epoch.c serializes at most
 * NODUS_EPOCH_MAX_DELEGS_PER_VAL delegators per committee member into the
 * epoch snapshot blob, while writing that validator's FULL
 * total_delegated. Nothing bounded the underlying row count, so a
 * validator with more delegators than the blob can carry had its whole
 * delegated figure hashed into the snapshot while only a SUBSET of its
 * delegators appeared in it. Settlement divides by the full figure, the
 * excluded delegators are never paid, and their share falls into the
 * inner-dust burn — permanently.
 *
 * Worse, WHICH delegators were dropped was not even stable: the
 * truncating query (nodus_witness_delegation.c delegation_list_by_hash,
 * "... WHERE %s = ? LIMIT ?") has NO ORDER BY, and the caller's qsort
 * runs AFTER the LIMIT — it orders the survivors, not the selection. Two
 * witnesses whose tables hold the same logical rows in a different
 * physical order would pick different subsets → different snapshot blob
 * → different snapshot_hash → different state_root.
 *
 * THE FIX UNDER TEST. The cap is enforced at ADMISSION, so the snapshot
 * can never be ASKED to truncate. This file covers the LEGACY lane
 * (apply_delegate, nodus_witness_bft.c). The Ledger V2 lane
 * (rtn_delegate_exec) is covered by test_delegator_cap() in
 * test_v2_native.c, which owns the envelope fixture.
 *
 * Cases:
 *   L1  one BELOW the cap  → a NEW delegator is admitted (lands ON it)
 *   L2  AT the cap         → a NEW delegator is REJECTED
 *   L3  AT the cap         → an EXISTING delegator may still TOP UP
 *   L4  count unreadable   → REJECTED (fail-closed, never "0 ⇒ admit")
 *   L5  far below the cap  → unaffected (the gate is not a blanket no)
 *   L6  the SNAPSHOT property: the bound the snapshot passes to
 *       list_by_validator can no longer discard a row
 *   L7  the same bound DOES discard a row once the gate is bypassed —
 *       so L6 is not passing vacuously, and this is what an already
 *       over-cap chain still does
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_delegation.h"
#include "witness/nodus_witness_validator.h"
#include "witness/nodus_witness_bft_internal.h"

#include "dnac/dnac.h"
#include "dnac/transaction.h"
#include "dnac/validator.h"
#include "nodus/nodus_types.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <sqlite3.h>

#define TEST(name) do { printf("  %-58s", name); } while (0)
#define PASS()     do { printf("PASS\n"); passed++; } while (0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while (0)

static int passed = 0;
static int failed = 0;

/* The cap under test, read from its ONE authority
 * (nodus_witness_delegation.h). Deliberately NOT a literal 64 here: a
 * private copy in the test would keep passing after the production
 * constant drifted, which is the exact failure mode — two unrelated 64s
 * — that produced this bug. */
#define CAP NODUS_MAX_DELEGATORS_PER_VALIDATOR

/* ── fixture ────────────────────────────────────────────────────────── */

/* Only the two tables apply_delegate touches. The DDL is copied from the
 * production schema as it appears in the existing witness tests
 * (test_commit_wrappers.c), so the CRUD helpers bind real columns. */
static const char *SCHEMA =
    "CREATE TABLE validators ("
    "  pubkey_hash BLOB PRIMARY KEY,"
    "  pubkey BLOB NOT NULL,"
    "  self_stake INTEGER NOT NULL,"
    "  total_delegated INTEGER NOT NULL DEFAULT 0,"
    "  external_delegated INTEGER NOT NULL DEFAULT 0,"
    "  commission_bps INTEGER NOT NULL,"
    "  pending_commission_bps INTEGER NOT NULL DEFAULT 0,"
    "  pending_effective_block INTEGER NOT NULL DEFAULT 0,"
    "  status INTEGER NOT NULL,"
    "  active_since_block INTEGER NOT NULL,"
    "  unstake_commit_block INTEGER NOT NULL DEFAULT 0,"
    "  unstake_destination_fp TEXT NOT NULL,"
    "  unstake_destination_pubkey BLOB NOT NULL,"
    "  last_validator_update_block INTEGER NOT NULL DEFAULT 0,"
    "  consecutive_missed_epochs INTEGER NOT NULL DEFAULT 0,"
    "  last_signed_block INTEGER NOT NULL DEFAULT 0,"
    "  signed_blocks_this_epoch INTEGER NOT NULL DEFAULT 0"
    ");"
    "CREATE TABLE delegations ("
    "  delegator_hash BLOB,"
    "  validator_hash BLOB,"
    "  delegator_pubkey BLOB NOT NULL,"
    "  validator_pubkey BLOB NOT NULL,"
    "  amount INTEGER NOT NULL,"
    "  delegated_at_block INTEGER NOT NULL,"
    "  PRIMARY KEY (delegator_hash, validator_hash)"
    ");"
    "CREATE INDEX idx_delegator ON delegations (delegator_hash);"
    "CREATE INDEX idx_validator ON delegations (validator_hash);";

static int setup(nodus_witness_t *w) {
    memset(w, 0, sizeof(*w));
    if (sqlite3_open(":memory:", &w->db) != SQLITE_OK) return -1;
    char *err = NULL;
    if (sqlite3_exec(w->db, SCHEMA, NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr, "schema failed: %s\n", err ? err : "(null)");
        if (err) sqlite3_free(err);
        sqlite3_close(w->db);
        w->db = NULL;
        return -1;
    }
    return 0;
}

static void teardown(nodus_witness_t *w) {
    if (w->db) sqlite3_close(w->db);
    w->db = NULL;
}

/* A distinct synthetic Dilithium-shaped pubkey per index.
 *
 * These are NOT real keys and never need to be: apply_delegate verifies
 * no signature (signature verification happens before it, in the verify
 * layer), and the cap's only input is COUNT(*) over validator_hash — a
 * property of the ROWS. 64+ real Dilithium5 keypairs would add minutes
 * of keygen to prove nothing extra. Index 0 is reserved for the target
 * validator so it can never collide with a delegator. */
static void synth_pubkey(uint8_t out[DNAC_PUBKEY_SIZE], uint32_t idx) {
    memset(out, 0, DNAC_PUBKEY_SIZE);
    out[0] = 0xD0;
    out[1] = (uint8_t)(idx >> 24);
    out[2] = (uint8_t)(idx >> 16);
    out[3] = (uint8_t)(idx >> 8);
    out[4] = (uint8_t)idx;
}

/* Insert an ACTIVE, bonded validator — the only status class
 * apply_delegate accepts alongside ELIGIBLE. */
static int add_validator(nodus_witness_t *w, const uint8_t *pk) {
    dnac_validator_record_t v;
    memset(&v, 0, sizeof(v));
    memcpy(v.pubkey, pk, DNAC_PUBKEY_SIZE);
    v.self_stake         = 10000000ULL;
    v.commission_bps     = 500;
    v.status             = (uint8_t)DNAC_VALIDATOR_ACTIVE;
    v.active_since_block = 1;
    memset(v.unstake_destination_fp, 'a', DNAC_FINGERPRINT_SIZE - 1);
    v.unstake_destination_fp[DNAC_FINGERPRINT_SIZE - 1] = '\0';
    return nodus_validator_insert(w, &v);
}

/* Seed `n` delegation rows against `vpk`, delegators indexed 1..n. */
static int seed_delegators(nodus_witness_t *w, const uint8_t *vpk, int n,
                           uint64_t amount) {
    for (int i = 1; i <= n; i++) {
        dnac_delegation_record_t d;
        memset(&d, 0, sizeof(d));
        synth_pubkey(d.delegator_pubkey, (uint32_t)i);
        memcpy(d.validator_pubkey, vpk, DNAC_PUBKEY_SIZE);
        d.amount             = amount;
        d.delegated_at_block = 1;
        if (nodus_delegation_insert(w, &d) != 0) return -1;
    }
    return 0;
}

static int count_for(nodus_witness_t *w, const uint8_t *vpk) {
    int n = -1;
    if (nodus_delegation_count_by_validator(w, vpk, &n) != 0) return -1;
    return n;
}

/* ── the synthetic DELEGATE transaction ─────────────────────────────
 *
 * Layout walked by compute_appended_fields_offset / sum_native_dnac_in_out
 * (nodus_witness_bft.c):
 *
 *   header(DNAC_TX_HEADER_SIZE=82)
 *   input_count u8 = 1, then 1 x ( nullifier(64) ‖ amount(u64 HOST) ‖
 *                                  token_id(64) )
 *   output_count u8 = 1, then 1 x ( version(1) ‖ fp(129) ‖
 *                                   amount(u64 HOST) ‖ token_id(64) ‖
 *                                   seed(32) ‖ memo_len u8 = 0 )
 *   witness_count u8 = 0
 *   signer_count  u8 = 1, then 1 x ( pubkey(2592) ‖ signature(4627) )
 *   APPENDED: validator_pubkey(2592) ‖ delegation_amount(u64 BE)
 *
 * The two amount fields are read with memcpy into a uint64_t, i.e. HOST
 * byte order, while the appended delegation_amount is parsed BIG-endian
 * byte by byte. That asymmetry is in the production parsers; this builder
 * reproduces it rather than "fixing" it, or the consistency rule
 *   Σnative_in == Σnative_out + committed_fee + delegation_amount
 * would not balance and every case would reject for the wrong reason.
 *
 * The signature bytes are arbitrary: apply_delegate never verifies them.
 */
#define TX_IN_SIZE   (NODUS_T3_NULLIFIER_LEN + 8 + 64)
#define TX_OUT_SIZE  (1 + 129 + 8 + 64 + 32 + 1)
#define TX_SGN_SIZE  (DNAC_PUBKEY_SIZE + DNAC_SIGNATURE_SIZE)
#define TX_TOTAL     (DNAC_TX_HEADER_SIZE + 1 + TX_IN_SIZE + \
                      1 + TX_OUT_SIZE + 1 + 1 + TX_SGN_SIZE + \
                      DNAC_PUBKEY_SIZE + 8)

static uint32_t build_delegate_tx(uint8_t *dst,
                                  const uint8_t *delegator_pk,
                                  const uint8_t *validator_pk,
                                  uint64_t amount,
                                  uint64_t fee,
                                  uint64_t change) {
    memset(dst, 0, TX_TOTAL);
    size_t off = DNAC_TX_HEADER_SIZE;

    /* inputs: one native-DNAC input worth amount + fee + change */
    dst[off++] = 1;
    off += NODUS_T3_NULLIFIER_LEN;              /* nullifier, any bytes  */
    uint64_t in_amt = amount + fee + change;
    memcpy(dst + off, &in_amt, 8);              /* HOST order, as parsed */
    off += 8;
    off += 64;                                  /* token_id = native (0) */

    /* outputs: one native change output */
    dst[off++] = 1;
    off += 1 + 129;                             /* version + fingerprint */
    memcpy(dst + off, &change, 8);              /* HOST order            */
    off += 8;
    off += 64 + 32;                             /* token_id + seed       */
    dst[off++] = 0;                             /* memo_len              */

    dst[off++] = 0;                             /* witness_count         */
    dst[off++] = 1;                             /* signer_count          */
    memcpy(dst + off, delegator_pk, DNAC_PUBKEY_SIZE);
    off += TX_SGN_SIZE;                         /* pubkey ‖ signature    */

    /* appended type-specific fields */
    memcpy(dst + off, validator_pk, DNAC_PUBKEY_SIZE);
    off += DNAC_PUBKEY_SIZE;
    for (int i = 0; i < 8; i++)                 /* BIG endian, as parsed */
        dst[off + i] = (uint8_t)(amount >> (56 - 8 * i));
    off += 8;

    return (uint32_t)off;
}

#define DLG_AMT   400000ULL
#define DLG_FEE   1000ULL
#define DLG_CHG   50000ULL

/* Drive one DELEGATE through the legacy apply. Returns apply_delegate's
 * verdict: 0 admitted, -1 rejected. */
static int do_delegate(nodus_witness_t *w, uint32_t delegator_idx,
                       const uint8_t *vpk, uint64_t height) {
    static uint8_t tx[TX_TOTAL];
    uint8_t dpk[DNAC_PUBKEY_SIZE];
    synth_pubkey(dpk, delegator_idx);
    uint32_t len = build_delegate_tx(tx, dpk, vpk, DLG_AMT, DLG_FEE,
                                     DLG_CHG);
    return apply_delegate(w, tx, len, height, DLG_FEE);
}

/* ── L1: one BELOW the cap, a NEW delegator lands exactly ON it ─────── */
static void test_at_cap_admits(void) {
    static nodus_witness_t w;   /* multi-MB — static storage, not stack */
    TEST("L1 a new delegator landing ON the cap is admitted");
    if (setup(&w) != 0) { FAIL("setup"); return; }

    uint8_t vpk[DNAC_PUBKEY_SIZE];
    synth_pubkey(vpk, 0);
    if (add_validator(&w, vpk) != 0) { FAIL("validator"); goto out; }
    if (seed_delegators(&w, vpk, CAP - 1, 1000) != 0) {
        FAIL("seed"); goto out;
    }
    if (count_for(&w, vpk) != CAP - 1) { FAIL("fixture count"); goto out; }

    /* delegator index CAP is new — it takes the validator to exactly CAP */
    if (do_delegate(&w, (uint32_t)CAP, vpk, 10) != 0) {
        FAIL("a delegation landing on the cap must be admitted");
        goto out;
    }
    if (count_for(&w, vpk) != CAP) { FAIL("row not written"); goto out; }
    PASS();
out:
    teardown(&w);
}

/* ── L2: AT the cap, a NEW delegator is rejected ────────────────────── */
static void test_one_over_rejects(void) {
    static nodus_witness_t w;
    TEST("L2 a new delegator PAST the cap is rejected");
    if (setup(&w) != 0) { FAIL("setup"); return; }

    uint8_t vpk[DNAC_PUBKEY_SIZE];
    synth_pubkey(vpk, 0);
    if (add_validator(&w, vpk) != 0) { FAIL("validator"); goto out; }
    if (seed_delegators(&w, vpk, CAP, 1000) != 0) { FAIL("seed"); goto out; }
    if (count_for(&w, vpk) != CAP) { FAIL("fixture count"); goto out; }

    uint64_t tot_before = 0;
    {
        dnac_validator_record_t v;
        if (nodus_validator_get(&w, vpk, &v) != 0) { FAIL("get"); goto out; }
        tot_before = v.total_delegated;
    }

    if (do_delegate(&w, (uint32_t)CAP + 1, vpk, 11) != -1) {
        FAIL("a delegation past the cap must be REJECTED");
        goto out;
    }
    if (count_for(&w, vpk) != CAP) {
        FAIL("the rejected delegation still wrote a row"); goto out;
    }
    /* the reject happens BEFORE any mutation — the validator totals must
     * not have moved either, or a refused TX would still inflate the
     * denominator settlement divides by */
    {
        dnac_validator_record_t v;
        if (nodus_validator_get(&w, vpk, &v) != 0) { FAIL("get"); goto out; }
        if (v.total_delegated != tot_before) {
            FAIL("the rejected delegation moved total_delegated");
            goto out;
        }
    }
    PASS();
out:
    teardown(&w);
}

/* ── L3: AT the cap, an EXISTING delegator may still top up ─────────── */
static void test_topup_at_cap_admits(void) {
    static nodus_witness_t w;
    TEST("L3 an existing delegator may top up AT the cap");
    if (setup(&w) != 0) { FAIL("setup"); return; }

    uint8_t vpk[DNAC_PUBKEY_SIZE];
    synth_pubkey(vpk, 0);
    if (add_validator(&w, vpk) != 0) { FAIL("validator"); goto out; }
    if (seed_delegators(&w, vpk, CAP, 1000) != 0) { FAIL("seed"); goto out; }

    /* delegator 1 is one of the seeded CAP rows: a top-up adds no NEW
     * delegator, so the count cannot move and the snapshot still holds
     * everyone. A gate that looked only at the count would wrongly
     * freeze every existing position the moment a validator filled. */
    if (do_delegate(&w, 1, vpk, 12) != 0) {
        FAIL("a top-up at the cap must be admitted"); goto out;
    }
    if (count_for(&w, vpk) != CAP) {
        FAIL("a top-up must not change the row count"); goto out;
    }
    {
        uint8_t dpk[DNAC_PUBKEY_SIZE];
        dnac_delegation_record_t d;
        synth_pubkey(dpk, 1);
        if (nodus_delegation_get(&w, dpk, vpk, &d) != 0) {
            FAIL("row"); goto out;
        }
        if (d.amount != 1000 + DLG_AMT) {
            FAIL("the top-up did not sum into the existing row"); goto out;
        }
    }
    PASS();
out:
    teardown(&w);
}

/* ── L4: an unreadable count REJECTS — it is never read as zero ─────── */
static void test_count_failure_rejects(void) {
    static nodus_witness_t w;
    TEST("L4 an unreadable delegator count is fail-closed");
    if (setup(&w) != 0) { FAIL("setup"); return; }

    uint8_t vpk[DNAC_PUBKEY_SIZE];
    synth_pubkey(vpk, 0);
    if (add_validator(&w, vpk) != 0) { FAIL("validator"); goto out; }

    /* Drop the table the count reads. nodus_delegation_count_by_validator
     * now fails at prepare. The validator has ZERO delegators, so a gate
     * that treated the failure as "count = 0" would sail straight past
     * the cap and ADMIT — this case is what distinguishes fail-closed
     * from fail-open, and it must reject. */
    char *err = NULL;
    if (sqlite3_exec(w.db, "DROP TABLE delegations", NULL, NULL, &err)
            != SQLITE_OK) {
        FAIL("drop"); if (err) sqlite3_free(err); goto out;
    }
    if (do_delegate(&w, 7, vpk, 13) != -1) {
        FAIL("an unreadable count must REJECT, not admit"); goto out;
    }
    PASS();
out:
    teardown(&w);
}

/* ── L5: below the cap the gate is inert ────────────────────────────── */
static void test_below_cap_unaffected(void) {
    static nodus_witness_t w;
    TEST("L5 delegations far below the cap are unaffected");
    if (setup(&w) != 0) { FAIL("setup"); return; }

    uint8_t vpk[DNAC_PUBKEY_SIZE];
    synth_pubkey(vpk, 0);
    if (add_validator(&w, vpk) != 0) { FAIL("validator"); goto out; }

    for (uint32_t i = 1; i <= 5; i++) {
        if (do_delegate(&w, i, vpk, 14) != 0) {
            FAIL("an ordinary delegation must be admitted"); goto out;
        }
    }
    if (count_for(&w, vpk) != 5) { FAIL("count"); goto out; }
    {
        dnac_validator_record_t v;
        if (nodus_validator_get(&w, vpk, &v) != 0) { FAIL("get"); goto out; }
        if (v.total_delegated != 5 * DLG_AMT ||
            v.external_delegated != 5 * DLG_AMT) {
            FAIL("validator totals"); goto out;
        }
    }
    PASS();
out:
    teardown(&w);
}

/* ── L6: THE SNAPSHOT PROPERTY ──────────────────────────────────────
 *
 * This is what the whole cap exists for. nodus_witness_epoch_snapshot_apply
 * calls nodus_delegation_list_by_validator with a bound of
 * NODUS_EPOCH_MAX_DELEGS_PER_VAL — an ALIAS of the admission cap — and
 * that call is its ONLY delegation input. Drive a validator as hard as
 * admission allows, then run the snapshot's own query at the snapshot's
 * own bound and show it returns EVERY row: nothing was discarded, so the
 * absent ORDER BY has no set left to choose from and the blob's
 * delegator list matches the total_delegated hashed beside it.
 */
static void test_snapshot_cannot_truncate(void) {
    static nodus_witness_t w;
    TEST("L6 the snapshot's bounded query can no longer truncate");
    if (setup(&w) != 0) { FAIL("setup"); return; }

    uint8_t vpk[DNAC_PUBKEY_SIZE];
    synth_pubkey(vpk, 0);
    if (add_validator(&w, vpk) != 0) { FAIL("validator"); goto out; }

    /* push through the front door until admission refuses */
    int admitted = 0;
    for (uint32_t i = 1; i <= (uint32_t)CAP + 16; i++) {
        if (do_delegate(&w, i, vpk, 20) == 0) admitted++;
    }
    if (admitted != CAP) {
        FAIL("admission let through something other than exactly CAP");
        goto out;
    }
    if (count_for(&w, vpk) != CAP) { FAIL("row count"); goto out; }

    /* the snapshot's own call, at the snapshot's own bound */
    dnac_delegation_record_t *dels =
        malloc((size_t)CAP * sizeof(*dels));
    if (!dels) { FAIL("alloc"); goto out; }
    int listed = 0;
    int lrc = nodus_delegation_list_by_validator(&w, vpk, dels, CAP,
                                                 &listed);
    if (lrc != 0 || listed != CAP) {
        free(dels);
        FAIL("the snapshot query did not return every row");
        goto out;
    }

    /* every returned delegator is distinct — a truncated set that
     * happened to be the right SIZE would still be wrong */
    int dup = 0;
    for (int a = 0; a < listed && !dup; a++)
        for (int b = a + 1; b < listed; b++)
            if (memcmp(dels[a].delegator_pubkey, dels[b].delegator_pubkey,
                       DNAC_PUBKEY_SIZE) == 0) { dup = 1; break; }
    free(dels);
    if (dup) { FAIL("duplicate delegator in the snapshot set"); goto out; }
    PASS();
out:
    teardown(&w);
}

/* ── L7: the truncation is REAL, and admission is what prevents it ──
 *
 * L6 on its own could pass vacuously — if the snapshot's bound were
 * enormous, "nothing was discarded" would be true for a reason that has
 * nothing to do with the cap. This case removes that doubt by putting
 * the table into the state admission now forbids, BYPASSING the gate
 * with a direct insert, and showing the snapshot query then silently
 * drops a row. It is the negative image of L6: the loss is genuine, the
 * bound is genuinely CAP, and the ONLY thing standing between the chain
 * and that loss is the admission gate L1-L2 pin.
 *
 * It doubles as the executable statement of what happens to a chain
 * that ALREADY carried an over-cap validator before the gate existed:
 * admission cannot retroactively remove delegators, so that validator
 * keeps its rows and keeps truncating. Unreachable on a chain capped
 * from genesis; the devnet is being reset, so it cannot arise there.
 */
static void test_truncation_is_real_without_the_cap(void) {
    static nodus_witness_t w;
    TEST("L7 without the gate the snapshot DOES lose a delegator");
    if (setup(&w) != 0) { FAIL("setup"); return; }

    uint8_t vpk[DNAC_PUBKEY_SIZE];
    synth_pubkey(vpk, 0);
    if (add_validator(&w, vpk) != 0) { FAIL("validator"); goto out; }

    /* CAP + 1 rows written straight to the table — the pre-fix chain
     * state, reachable only by bypassing apply_delegate entirely. */
    if (seed_delegators(&w, vpk, CAP + 1, 1000) != 0) {
        FAIL("seed"); goto out;
    }
    if (count_for(&w, vpk) != CAP + 1) { FAIL("fixture count"); goto out; }

    dnac_delegation_record_t *dels = malloc((size_t)CAP * sizeof(*dels));
    if (!dels) { FAIL("alloc"); goto out; }
    int listed = 0;
    int lrc = nodus_delegation_list_by_validator(&w, vpk, dels, CAP,
                                                 &listed);
    free(dels);
    if (lrc != 0) { FAIL("list"); goto out; }
    if (listed != CAP) {
        FAIL("expected the bound to clamp the result to exactly CAP");
        goto out;
    }
    /* CAP + 1 rows exist, CAP came back: one delegator was dropped and
     * the query reported success. That is the loss the cap prevents. */
    PASS();
out:
    teardown(&w);
}

int main(void) {
    printf("\nNodus per-validator delegator cap — LEGACY lane\n");
    printf("================================================\n");

    test_at_cap_admits();
    test_one_over_rejects();
    test_topup_at_cap_admits();
    test_count_failure_rejects();
    test_below_cap_unaffected();
    test_snapshot_cannot_truncate();
    test_truncation_is_real_without_the_cap();

    printf("------------------------------------------------\n");
    printf("passed: %d  failed: %d\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
