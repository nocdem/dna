/**
 * Nodus — O15O Faz 7 — the delegation LIMIT truncates against a TOTAL ORDER
 *
 * WHAT THIS PROVES.
 *   delegation_list_by_hash (nodus_witness_delegation.c) is the ONLY way
 *   the epoch snapshot reads a validator's delegators
 *   (nodus_witness_epoch.c:418), and it caps the result with a LIMIT.
 *   Before this phase the query carried NO `ORDER BY`, so when the
 *   filtered set was larger than the bound, the rows that SURVIVED were
 *   whichever ones SQLite's scan reached first — index-scan order, which
 *   is to say the order the rows happened to be WRITTEN. Two witnesses
 *   holding the same logical rows in a different physical order keep
 *   different subsets.
 *
 *   The property that would be false if any assertion here failed: the
 *   set of rows that survives the truncation is a function of the ROWS
 *   ALONE, and not of the order in which they were inserted. Its two
 *   halves are asserted separately, because they fail separately:
 *
 *     - DETERMINISM. The same rows inserted in two DIFFERENT orders, read
 *       at the same bound, yield the IDENTICAL surviving set — position
 *       for position, not merely as a set. This is the chain-split half:
 *       a differing delegator list is a differing snapshot blob, hence a
 *       differing snapshot_hash, hence a differing state_root.
 *     - CORRECTNESS. That set is the one the total order names — the
 *       memcmp-smallest `max_entries` pubkeys — computed HERE by sorting
 *       the fixture's own keys, independently of anything the database
 *       says. "Both runs agreed" is not enough on its own: two runs of a
 *       broken query can agree by luck of layout.
 *
 *   The order key is the pubkey column the WHERE clause does NOT pin, so
 *   the shared implementation is parameterised on it exactly as it is on
 *   the filter column. Both directions are covered: §1 filters on the
 *   validator and orders by delegator_pubkey (the LIVE consumer's call),
 *   §2 filters on the delegator and orders by validator_pubkey (the
 *   transpose, which pins that the parameterisation is real and not a
 *   constant wearing a parameter's clothes).
 *
 *   ⚠ WHY A TEST FOR AN UNREACHABLE PATH. In production the per-validator
 *   delegator cap (NODUS_MAX_DELEGATORS_PER_VALIDATOR, enforced at
 *   admission in both lanes) keeps the filtered set at or below the bound
 *   the snapshot passes, so the LIMIT never truncates and the ORDER BY
 *   changes no output. This file therefore inserts rows DIRECTLY through
 *   the CRUD writer, bypassing admission, because its subject is exactly
 *   the world where that cap is lifted, raised, or already violated by an
 *   inherited chain — see the RESIDUAL paragraph in nodus_witness_epoch.c.
 *   Reaching the LIMIT is the whole point, and a run that did not reach
 *   it would prove nothing at all (see HOW IT CAN LIE).
 *
 * WHAT IT REQUIRES.
 *   Compile flags: NONE beyond a default nodus build. Registered through
 *   register_witness_test, which supplies NODUS_WITNESS_INTERNAL_API (the
 *   file defines it too, matching test_delegator_cap.c). No
 *   QGP_FAULT_INJECT, no O15H_DIAG, no NODUS_V2_* gate macro. Nothing
 *   here reads DNAC_EPOCH_LENGTH or any other tunable constant, so the
 *   assertions hold identically at production and harness parameters.
 *   Environment: NONE. No STAGEF_*, no NODUS_FAULT_*, no network, no node
 *   directories, no pre-exported variable — and not even a writable /tmp,
 *   because every fixture is an `:memory:` database.
 *
 * WHAT IT LEAVES BEHIND.
 *   Nothing. Each leg opens its own `:memory:` SQLite database — a fresh
 *   one per leg, which is also how the second insertion order gets a
 *   genuinely different physical layout rather than a re-used rowid
 *   sequence — and closes it in teardown. No files, no directories, no
 *   processes, no arm files. Every heap allocation is freed on every
 *   path.
 *
 * HOW IT CAN LIE.
 *   - THE VACUITY TRAP, and it is this file's central one: if the bound
 *     is at or above the number of rows present, NO truncation happens,
 *     every row comes back, and the leg passes IDENTICALLY with or
 *     without the ORDER BY. It would prove nothing while printing PASS.
 *     Every leg therefore asserts BOTH halves of the control explicitly —
 *     that more rows exist than the bound (counted through the production
 *     COUNT(*) helper, not assumed from the seed loop) and that the result
 *     came back at exactly the bound.
 *   - THE COINCIDING-ORDER TRAP. If an insertion order's first
 *     `max_entries` rows happened to BE the total order's first
 *     `max_entries`, then rowid order and sorted order coincide and that
 *     leg passes without the fix. Both insertion orders below are chosen
 *     so their prefixes differ from the sorted prefix, and — rather than
 *     leaving that to the reader to verify — each leg ASSERTS that the
 *     surviving set differs from the first `max_entries` rows it
 *     inserted. That assertion is what proves the ORDER BY changed the
 *     answer.
 *   - A GUARD DEAD IN BOTH DIRECTIONS. A query that returned a fixed set
 *     regardless of input would satisfy the determinism half. The
 *     independently computed expected set is what excludes it, and the
 *     ascending-order assertion is what excludes a DESC that would still
 *     be perfectly deterministic.
 *   - THE KEYS ARE SYNTHETIC, NOT REAL ML-DSA-87 PUBKEYS. That is sound
 *     here because the query orders BYTES: nothing in the path parses,
 *     verifies or interprets a key, and 16 real keypairs would add keygen
 *     time to prove nothing extra. It does mean this file would not
 *     notice an ordering rule that became key-semantic rather than
 *     byte-wise.
 *   - IT PINS THE QUERY, NOT THE SETTLEMENT. Nothing here runs
 *     nodus_witness_epoch_snapshot_apply or pays anyone. That the
 *     snapshot consumes this order correctly is argued in that file's
 *     docblock and covered by test_delegator_cap L6/L7; this file proves
 *     only that the order exists and is total.
 *   - THE SCHEMA IS A COPY. The DDL below is copied from the production
 *     WITNESS_DB_SCHEMA (nodus_witness.c:189-199), INCLUDING BOTH
 *     INDEXES, because the unfixed scan order is index-scan order and a
 *     fixture without them would not model the shape the bug lived in. A
 *     future production schema change would not reach this copy; that is
 *     the standing cost of the in-memory fixture pattern this suite uses
 *     everywhere.
 *   - THERE IS NO SKIP PATH. Every leg runs unconditionally; nothing here
 *     can decline to run and still report success.
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_delegation.h"

#include "dnac/dnac.h"
#include "dnac/validator.h"
#include "nodus/nodus_types.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sqlite3.h>

#define TEST(name) do { printf("  %-62s", name); } while (0)
#define PASS()     do { printf("PASS\n"); passed++; } while (0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while (0)

static int passed = 0;
static int failed = 0;

/* Eight rows against one pivot, read three at a time.
 *
 * The two numbers are chosen for one reason: N_ROWS must EXCEED LIMIT or
 * the LIMIT is never reached and this whole file measures nothing. The
 * gap is asserted at runtime in every leg rather than trusted here. */
#define N_ROWS  8
#define LIMIT   3

/* Index 0 is the PIVOT — the validator in §1, the delegator in §2 — so it
 * can never collide with one of the eight counterparties. */
#define PIVOT_IDX 0

/* Which side of the pair the WHERE clause pins, and therefore which side
 * must carry the total order. */
typedef enum {
    BY_VALIDATOR,   /* pin validator_hash → order by delegator_pubkey */
    BY_DELEGATOR    /* pin delegator_hash → order by validator_pubkey */
} lens_t;

/* ── fixture ────────────────────────────────────────────────────────── */

/* Copied from the production schema (nodus_witness.c:189-199), both
 * indexes included: without them the unfixed query would not take the
 * index-scan path the defect lives on. */
static const char *SCHEMA =
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

/* nodus_witness_t is multi-MB — heap, never the stack (repo discipline,
 * feedback_heap_alloc_test_fixture). Returns NULL on failure. */
static nodus_witness_t *fixture(void) {
    nodus_witness_t *w = calloc(1, sizeof(*w));
    if (!w) return NULL;
    if (sqlite3_open(":memory:", &w->db) != SQLITE_OK) {
        if (w->db) sqlite3_close(w->db);
        free(w);
        return NULL;
    }
    char *err = NULL;
    if (sqlite3_exec(w->db, SCHEMA, NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr, "schema failed: %s\n", err ? err : "(null)");
        if (err) sqlite3_free(err);
        sqlite3_close(w->db);
        free(w);
        return NULL;
    }
    return w;
}

/* A bare CRUD fixture never ran nodus_witness_open, so it must not be
 * handed to nodus_witness_close: the database handle is the only resource
 * it owns. Same teardown shape as test_delegator_cap.c. */
static void fixture_free(nodus_witness_t *w) {
    if (!w) return;
    if (w->db) sqlite3_close(w->db);
    free(w);
}

/* A distinct synthetic Dilithium-shaped pubkey per index, big-endian in
 * bytes 1..4 so the memcmp order of the keys matches the index order.
 *
 * Nothing in the path under test parses a key — the query orders raw
 * BLOB bytes — so real ML-DSA-87 keypairs would cost keygen time and buy
 * nothing. The expectations below are still derived by SORTING these
 * keys rather than by assuming that index order is byte order, so this
 * layout is a readability convenience and not a load-bearing assumption.
 * Shape copied from synth_pubkey in test_delegator_cap.c. */
static void synth_pubkey(uint8_t out[DNAC_PUBKEY_SIZE], uint32_t idx) {
    memset(out, 0, DNAC_PUBKEY_SIZE);
    out[0] = 0xD0;
    out[1] = (uint8_t)(idx >> 24);
    out[2] = (uint8_t)(idx >> 16);
    out[3] = (uint8_t)(idx >> 8);
    out[4] = (uint8_t)idx;
}

/* The half of the pair that VARIES across a result set: the one the
 * WHERE clause did not pin, and therefore the one that carries the
 * order. */
static const uint8_t *varying(const dnac_delegation_record_t *r,
                              lens_t lens) {
    return (lens == BY_VALIDATOR) ? r->delegator_pubkey
                                  : r->validator_pubkey;
}

static int pubkey_cmp(const void *a, const void *b) {
    return memcmp(a, b, DNAC_PUBKEY_SIZE);
}

/* ── one leg ────────────────────────────────────────────────────────── */

/* Seed the eight rows in `order` and read back at most LIMIT of them
 * through the PRODUCTION accessor, on a database of this leg's own.
 *
 * `order` is the INSERTION order, and it is the only thing that differs
 * between the two legs of a section — same rows, same amounts, same
 * pivot. A fresh `:memory:` database per leg is what makes the physical
 * layout genuinely follow it: rowids start from 1 again, so leg B's
 * rowid order really is leg B's insertion order and not a continuation
 * of leg A's.
 *
 * @return 0 on success, -1 on any fixture or accessor failure.
 */
static int run_leg(lens_t lens, const uint32_t *order,
                   dnac_delegation_record_t *got, int *got_n,
                   int *total_rows) {
    nodus_witness_t *w = fixture();
    if (!w) return -1;

    uint8_t pivot[DNAC_PUBKEY_SIZE];
    synth_pubkey(pivot, PIVOT_IDX);

    int rc = -1;

    for (int i = 0; i < N_ROWS; i++) {
        dnac_delegation_record_t d;
        memset(&d, 0, sizeof(d));
        if (lens == BY_VALIDATOR) {
            synth_pubkey(d.delegator_pubkey, order[i]);
            memcpy(d.validator_pubkey, pivot, DNAC_PUBKEY_SIZE);
        } else {
            memcpy(d.delegator_pubkey, pivot, DNAC_PUBKEY_SIZE);
            synth_pubkey(d.validator_pubkey, order[i]);
        }
        /* The amount is a function of the ROW, never of its insertion
         * position, so the two legs seed byte-identical row sets. */
        d.amount             = 1000ULL + (uint64_t)order[i];
        d.delegated_at_block = 1;
        if (nodus_delegation_insert(w, &d) != 0) goto out;
    }

    /* Counted through the production COUNT(*) helper rather than assumed
     * from the loop above: the anti-vacuity control must measure what the
     * database actually holds. */
    *total_rows = -1;
    if (lens == BY_VALIDATOR) {
        if (nodus_delegation_count_by_validator(w, pivot, total_rows) != 0)
            goto out;
    } else {
        if (nodus_delegation_count_by_delegator(w, pivot, total_rows) != 0)
            goto out;
    }

    *got_n = -1;
    if (lens == BY_VALIDATOR) {
        if (nodus_delegation_list_by_validator(w, pivot, got, LIMIT,
                                               got_n) != 0)
            goto out;
    } else {
        if (nodus_delegation_list_by_delegator(w, pivot, got, LIMIT,
                                               got_n) != 0)
            goto out;
    }

    rc = 0;
out:
    fixture_free(w);
    return rc;
}

/* The set the TOTAL ORDER names, computed here and not asked of the
 * database: sort the eight counterparty keys by memcmp and keep the
 * first LIMIT. Without this the file could only prove that two runs
 * agreed, which a broken query can also do. */
static void expected_prefix(uint8_t out[LIMIT][DNAC_PUBKEY_SIZE]) {
    static uint8_t all[N_ROWS][DNAC_PUBKEY_SIZE];
    for (int i = 0; i < N_ROWS; i++)
        synth_pubkey(all[i], (uint32_t)(i + 1));   /* 1..N_ROWS */
    qsort(all, N_ROWS, DNAC_PUBKEY_SIZE, pubkey_cmp);
    for (int i = 0; i < LIMIT; i++)
        memcpy(out[i], all[i], DNAC_PUBKEY_SIZE);
}

/* ── the section body, shared by both lenses ────────────────────────── */

/* Two insertion orders. NEITHER begins with the sorted prefix {1,2,3} —
 * A starts {3,1,4}, B starts {8,5,2} — so on a build without the ORDER BY
 * each leg returns its OWN first three and the two disagree. That is the
 * discriminator; it is not left to inspection, because every leg asserts
 * that its result differs from its own first three. */
static const uint32_t ORDER_A[N_ROWS] = { 3, 1, 4, 8, 6, 2, 7, 5 };
static const uint32_t ORDER_B[N_ROWS] = { 8, 5, 2, 7, 1, 4, 3, 6 };

/* Assert everything one leg can be asked on its own. Returns 0 if the leg
 * holds, -1 with a FAIL already reported otherwise. */
static int check_leg(lens_t lens, const char *leg_name,
                     const uint32_t *order,
                     const dnac_delegation_record_t *got, int got_n,
                     int total_rows,
                     uint8_t expect[LIMIT][DNAC_PUBKEY_SIZE]) {
    char msg[192];

    /* ── ANTI-VACUITY, half 1: more rows exist than the bound. If this
     * ever fails the LIMIT was never reached and nothing below means
     * anything, whatever it prints. */
    if (total_rows != N_ROWS || total_rows <= LIMIT) {
        snprintf(msg, sizeof(msg),
                 "%s: the table holds %d rows, needed more than the bound "
                 "of %d — the LIMIT was never reached and this leg would "
                 "pass without the fix", leg_name, total_rows, LIMIT);
        FAIL(msg);
        return -1;
    }

    /* ── ANTI-VACUITY, half 2: the read really was truncated. */
    if (got_n != LIMIT) {
        snprintf(msg, sizeof(msg),
                 "%s: the read returned %d rows, expected exactly the "
                 "bound %d — no truncation, so no truncation SET to be "
                 "right or wrong about", leg_name, got_n, LIMIT);
        FAIL(msg);
        return -1;
    }

    /* ── CORRECTNESS: the survivors are the ones the total order names,
     * position for position. The ORDER BY fixes the output sequence as
     * well as the selection, so this is asserted positionally — which
     * also pins the direction, since a DESC would be equally
     * deterministic and equally wrong. */
    for (int i = 0; i < LIMIT; i++) {
        if (memcmp(varying(&got[i], lens), expect[i],
                   DNAC_PUBKEY_SIZE) != 0) {
            snprintf(msg, sizeof(msg),
                     "%s: row %d is not the one the total order names "
                     "(marker 0x%02X%02X, expected 0x%02X%02X)",
                     leg_name, i,
                     varying(&got[i], lens)[3], varying(&got[i], lens)[4],
                     expect[i][3], expect[i][4]);
            FAIL(msg);
            return -1;
        }
    }

    /* ── ASCENDING, asserted directly rather than inferred from the
     * expectation above: it is the one property a reader can check by eye
     * against the query text. */
    for (int i = 1; i < LIMIT; i++) {
        if (memcmp(varying(&got[i - 1], lens), varying(&got[i], lens),
                   DNAC_PUBKEY_SIZE) >= 0) {
            snprintf(msg, sizeof(msg),
                     "%s: rows %d and %d are not in ascending byte order",
                     leg_name, i - 1, i);
            FAIL(msg);
            return -1;
        }
    }

    /* ── THE SHARP CONTROL: the surviving set is NOT the first LIMIT rows
     * inserted. This is the assertion that proves the ORDER BY CHANGED
     * the answer here rather than agreeing with the old behaviour by
     * luck of layout — and it holds on its own terms, without depending
     * on what an unordered query would have returned.
     *
     * For the reader wondering why the unordered query returned exactly
     * the first-inserted rows: that is the OBSERVED behaviour, not a
     * contract. SQLite appends the rowid to an index key, so entries
     * sharing one indexed value come back in rowid order, which on a
     * fresh table follows the insert. The assertion above does not rest
     * on that; it rests on the sorted expectation. */
    {
        int same_as_inserted = 1;
        for (int i = 0; i < LIMIT && same_as_inserted; i++) {
            uint8_t ins[DNAC_PUBKEY_SIZE];
            synth_pubkey(ins, order[i]);
            if (memcmp(varying(&got[i], lens), ins, DNAC_PUBKEY_SIZE) != 0)
                same_as_inserted = 0;
        }
        if (same_as_inserted) {
            snprintf(msg, sizeof(msg),
                     "%s: the result IS the first %d rows inserted — "
                     "insertion order and sorted order coincide here, so "
                     "this leg cannot tell the fix from its absence",
                     leg_name, LIMIT);
            FAIL(msg);
            return -1;
        }
    }

    return 0;
}

/* One lens, both insertion orders, every assertion. */
static void section(lens_t lens, const char *title) {
    dnac_delegation_record_t *a = NULL, *b = NULL;
    int a_n = 0, b_n = 0, a_total = 0, b_total = 0;
    uint8_t expect[LIMIT][DNAC_PUBKEY_SIZE];

    TEST(title);

    a = malloc((size_t)LIMIT * sizeof(*a));
    b = malloc((size_t)LIMIT * sizeof(*b));
    if (!a || !b) { FAIL("alloc"); goto out; }

    expected_prefix(expect);

    if (run_leg(lens, ORDER_A, a, &a_n, &a_total) != 0) {
        FAIL("leg A: fixture or accessor failed");
        goto out;
    }
    if (run_leg(lens, ORDER_B, b, &b_n, &b_total) != 0) {
        FAIL("leg B: fixture or accessor failed");
        goto out;
    }

    if (check_leg(lens, "leg A", ORDER_A, a, a_n, a_total, expect) != 0)
        goto out;
    if (check_leg(lens, "leg B", ORDER_B, b, b_n, b_total, expect) != 0)
        goto out;

    /* ── DETERMINISM: the two legs agree position for position. Each leg
     * has already been proven individually correct, so this is strictly
     * redundant — and it is kept anyway, because it is the property the
     * chain depends on stated in its own terms, and it is what would
     * still fail if BOTH expectations above were ever weakened together.
     * The whole record is compared, not just the ordering key: the amount
     * is a function of the row, so a leg that returned the right keys
     * carrying another row's payload is caught here. */
    for (int i = 0; i < LIMIT; i++) {
        if (memcmp(varying(&a[i], lens), varying(&b[i], lens),
                   DNAC_PUBKEY_SIZE) != 0) {
            FAIL("the two insertion orders kept DIFFERENT delegators — "
                 "the truncation set follows physical layout");
            goto out;
        }
        if (a[i].amount != b[i].amount) {
            char msg[192];
            snprintf(msg, sizeof(msg),
                     "row %d carries a different amount between the legs "
                     "(%llu vs %llu) — same key, other row's payload", i,
                     (unsigned long long)a[i].amount,
                     (unsigned long long)b[i].amount);
            FAIL(msg);
            goto out;
        }
    }

    PASS();
out:
    free(a);
    free(b);
}

int main(void) {
    printf("\nO15O Faz 7 — the delegation LIMIT truncates against a "
           "TOTAL ORDER\n");
    printf("======================================================"
           "============\n");
    printf("  %d rows per pivot, read at a bound of %d — the LIMIT is "
           "reached in every leg\n", N_ROWS, LIMIT);

    /* §1 — the LIVE consumer's direction: the epoch snapshot calls
     * nodus_delegation_list_by_validator (nodus_witness_epoch.c:418), so
     * this is the path whose truncation set decides who gets paid and
     * what snapshot_hash every node computes. */
    section(BY_VALIDATOR,
            "S1 by validator: order is delegator_pubkey, both legs agree");

    /* §2 — the transpose. It has no consensus consumer today, and it is
     * here because the implementation is SHARED and parameterised: if the
     * order column were hard-coded rather than passed alongside the
     * filter column, this section is what fails. */
    section(BY_DELEGATOR,
            "S2 by delegator: order is validator_pubkey, both legs agree");

    printf("------------------------------------------------------"
           "------------\n");
    printf("passed: %d  failed: %d\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
