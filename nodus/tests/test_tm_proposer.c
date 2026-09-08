/**
 * Nodus — Tendermint T1: proposer-selection KATs and DNA sequences.
 *
 * Covers nodus/src/bft/tendermint/tm_proposer.c, the C port of CometBFT's
 * weighted round-robin priority counter pinned at cometbft@709fd12b.
 *
 * ── WHAT WOULD BE FALSE IF THIS FILE FAILED ───────────────────────────
 *
 * §A  The counter reproduces proposer-selection.md's "Stable Set" table row
 *     by row (VP 1 / 3, sequence p2, p1, p2, p2). If it went red, DNA's
 *     proposer order would not be the reference order and a node built from
 *     the spec document would disagree with one built from this code — R1
 *     determinism across implementations, not just across runs.
 * §B  The CENTERING step exists and divides exactly. The "Validator Removal"
 *     table's sum is -2 over n = 2, so avg = -1; without the centering the
 *     final vector would be [-2, 0] instead of [-1, 1], which the literal
 *     below discriminates.
 * §B-2 The RESCALE branch exists and truncates. Every other vector in this
 *     file keeps diff <= 2P, so that branch never executed at all and its
 *     division was unmeasured; [5, -4] over weights [1, 1] forces
 *     diff 9 > 2P 4, ratio 3, and a result ([0, 0]) that the un-rescaled path
 *     cannot produce.
 * §C  The centering divides with EUCLIDEAN (floor) semantics, because
 *     computeAvgProposerPriority sums into math/big and calls Int.Div
 *     (go1.22.0 math/big/int.go:299-302, "Div implements Euclidean division
 *     (unlike Go)"). For the "New Validator" example the pinned CODE gives
 *     avg = -5 where the reference DOCUMENT's table says -4. THE DNA RULE IS
 *     THE PINNED CODE; the numbers here are hand-derived along the code path
 *     and are NOT produced by running tm_proposer.
 * §C-neg  The two divisions really are different. The same step is re-run
 *     inside this file with truncation and must reproduce the DOCUMENT's
 *     numbers and differ from §C's. If floor and truncation ever coincided
 *     here, §C would be measuring nothing.
 * §D  With DNA's weight 1 the counter degenerates to an exact round-robin in
 *     identity order: over 21 heights of a 7-member set each member proposes
 *     exactly 3 times, and proposer(h) = (h-1) mod 7. If it went red, block
 *     production would be unfair or, worse, not agreed.
 * §D-c proposer(h, r) is PATH-INDEPENDENT: Increment(r) from S_h equals r
 *     successive Increment(1) steps. DNA computes it the first way ALWAYS
 *     while CometBFT keeps the advanced set and moves by the delta
 *     (state.go:1081); at weight 1 the two coincide, and that equality is what
 *     lets a node that jumped rounds agree with one that walked them (DG-2).
 * §E  A set change CARRIES the counter (design §6.2, operator decision
 *     2026-09-08): survivors keep their accumulated priority and their
 *     relative order, joiners enter at -1.125*P' behind everybody. If it went
 *     red, a validator could jump the queue by leaving and rejoining.
 * §F  S_h crosses the WAL boundary INTACT: export/import carries the set, the
 *     priority vector AND the elected proposer index, so proposer(h, r) round-
 *     trips for every r, round 0 included. Round 0 is the one that needs the
 *     index — the election ends with A(prop) -= P, so the maximum of the
 *     exported vector is a DIFFERENT member than the one elected (genesis
 *     [-3,1,1,1]: elected v0, maximum v1). An out-of-range index is refused,
 *     never repaired by the findProposer fallback, which is gone.
 * §G  int64 is enough: over 10 000 heights of a 128-member set the
 *     accumulated priority never approaches TM_PRIO_ABS_BOUND, so CometBFT's
 *     saturating clip is unreachable and the module never has to refuse.
 * §H  dna_bft_f_plus_one is the "f+1" of the paper for a general n, and it is
 *     NOT n - quorum(n): at n = 9 it is 3, not 4.
 *
 * ── WHAT IT REQUIRES ──────────────────────────────────────────────────
 *
 * Nothing beyond a default build. No compile flags (register_witness_test's
 * NODUS_WITNESS_INTERNAL_API is not used by this file), no environment
 * variables, no files, no ports, no clock and no RNG — every input is a
 * literal, so a failure reproduces byte for byte on any machine.
 *
 * ── WHAT IT LEAVES BEHIND ─────────────────────────────────────────────
 *
 * Nothing. Every tm_proposer object is destroyed on every exit path.
 *
 * ── HOW IT COULD LIE ──────────────────────────────────────────────────
 *
 *  1. THE EXPECTATION COMES FROM THE CODE. If a table were produced by
 *     calling tm_proposer_at and then compared with itself, it would measure
 *     nothing at all. Every table in §A-§F is a LITERAL in this file: §A, §B
 *     and §C-neg are copied from proposer-selection.md, and §C, §D and §E are
 *     hand-derived along the pinned code path in the design document (§11.2).
 *     No expectation anywhere in this file is generated at run time.
 *  2. THE DIVISION SEMANTICS IS NOT EXERCISED. If every sum happened to
 *     divide exactly, floor and truncation would agree and §C would pass
 *     under either. §C-neg closes that by running BOTH and requiring them to
 *     DIFFER.
 *  3. THE BOUND CHECK NEVER RUNS. §G asserts not only that no call refused
 *     but that priorities were actually observed and stayed small; a run in
 *     which the loop did nothing would fail its own count assertion.
 *  4. A "SEQUENCE" OF LENGTH ZERO. Every sequence section asserts its
 *     expected length was consumed in full.
 */

#include "bft/tendermint/tm_core.h"
#include "bft/dna_consensus.h"
#include "dnac/ledger_ids.h"    /* dna_bft_f_plus_one, DNA_MAX_ACTIVE_VALIDATORS */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#define TEST(name) do { printf("  %-58s", name); } while (0)
#define PASS()     do { printf("PASS\n"); passed++; } while (0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while (0)

static int passed = 0;
static int failed = 0;

#define MAXV DNA_MAX_ACTIVE_VALIDATORS

static void mkid(uint8_t out[DNA_CONSENSUS_ID_LEN], uint8_t tag)
{
    memset(out, tag, DNA_CONSENSUS_ID_LEN);
}

/* Compares the exported priority vector against a literal. */
static int prio_eq(const tm_proposer_t *p, const int64_t *want, uint32_t n)
{
    dna_vset_t out;
    int64_t got[MAXV];
    uint32_t pidx = 0;

    memset(&out, 0, sizeof(out));
    if (tm_proposer_export(p, &out, got, MAXV, &pidx) != 0) return 0;
    if (out.n != n) return 0;
    if (pidx >= n) return 0;
    return memcmp(got, want, (size_t)n * sizeof(int64_t)) == 0;
}

/* Index of the proposer at round `r`, or MAXV+1 on error. */
static uint32_t prop_idx(const tm_proposer_t *p, uint32_t r,
                         const uint8_t (*ids)[DNA_CONSENSUS_ID_LEN], uint32_t n)
{
    uint8_t got[DNA_CONSENSUS_ID_LEN];
    uint32_t i;

    if (tm_proposer_at(p, r, got) != 0) return MAXV + 1u;
    for (i = 0; i < n; i++) {
        if (memcmp(ids[i], got, DNA_CONSENSUS_ID_LEN) == 0) return i;
    }
    return MAXV + 1u;
}

/* ── §A  proposer-selection.md "Stable Set" ──────────────────────────── */

static void test_a_stable_set(void)
{
    /* LITERAL, copied from proposer-selection.md's table (VP p1 = 1, p2 = 3,
     * priorities initialised to 0). Rows are read after each run:
     *   run 1  A(i)+=VP -> [1, 3];  A(p2)-=4 -> [ 1, -1]   proposer p2
     *   run 2  A(i)+=VP -> [2, 2];  A(p1)-=4 -> [-2,  2]   proposer p1 (tie, lower address)
     *   run 3  A(i)+=VP -> [-1,5];  A(p2)-=4 -> [-1,  1]   proposer p2
     *   run 4  A(i)+=VP -> [0, 4];  A(p2)-=4 -> [ 0,  0]   proposer p2
     * and the document's own summary of the emitted sequence is
     * "p2, p1, p2, p2". Every sum here is 0, so the centering divides
     * exactly and the rescale never triggers: this section isolates the
     * elect-and-push-back core from the two divisions. */
    static const int64_t want[4][2] = { { 1, -1 }, { -2, 2 }, { -1, 1 }, { 0, 0 } };
    static const uint32_t want_prop[4] = { 1, 0, 1, 1 };

    uint8_t ids[2][DNA_CONSENSUS_ID_LEN];
    int64_t weights[2] = { 1, 3 };
    int64_t start[2]   = { 0, 0 };
    dna_vset_t set;
    tm_proposer_t *p = NULL;
    int i;

    TEST("A stable set VP 1/3 -> p2,p1,p2,p2 with reference priorities");

    mkid(ids[0], 0x01);
    mkid(ids[1], 0x02);
    set.n = 2;
    set.ids = (const uint8_t (*)[DNA_CONSENSUS_ID_LEN])ids;
    set.weights = weights;

    /* The document's table starts from priorities [0, 0] with no election
     * behind it, so the imported proposer index is arbitrary; every row below
     * reads the index the FOLLOWING run elects, never this seed value. */
    if (tm_proposer_import(&p, &set, start, 0) != 0) { FAIL("import"); return; }

    for (i = 0; i < 4; i++) {
        if (tm_proposer_next_height(p, &set) != 0) {
            tm_proposer_destroy(p); FAIL("next_height refused"); return;
        }
        if (!prio_eq(p, want[i], 2)) {
            char buf[64];
            snprintf(buf, sizeof(buf), "run %d priorities", i + 1);
            tm_proposer_destroy(p); FAIL(buf); return;
        }
        if (prop_idx(p, 0, (const uint8_t (*)[DNA_CONSENSUS_ID_LEN])ids, 2) != want_prop[i]) {
            char buf[64];
            snprintf(buf, sizeof(buf), "run %d proposer", i + 1);
            tm_proposer_destroy(p); FAIL(buf); return;
        }
    }
    tm_proposer_destroy(p);
    PASS();
}

/* ── §B  proposer-selection.md "Validator Removal" ───────────────────── */

static void test_b_removal_centering(void)
{
    /* LITERAL from the document: set {p1:1, p2:2, p3:3} with priorities
     * p1 = 1, p2 = 2, p3 = -3 (sum 0), then p2 is removed.
     *   updateWithChangeSet: survivors keep A -> [1, -3], P' = 4
     *   centre: sum = -2, n = 2, avg = -1 (EXACT, no rounding question)
     *                                     -> [2, -2]      the document's "new step" row
     *   increment: [3, 1]; max = p1; A(p1) -= 4           -> [-1, 1]
     * The document's final row is exactly p1 = -1, p3 = 1.
     *
     * This section is the CENTERING's own witness: with the step removed the
     * run would be [1,-3] -> [2,0] -> A(p1)-=4 -> [-2, 0], which is not the
     * literal below. */
    static const int64_t want[2] = { -1, 1 };

    uint8_t ids3[3][DNA_CONSENSUS_ID_LEN];
    uint8_t ids2[2][DNA_CONSENSUS_ID_LEN];
    int64_t w3[3] = { 1, 2, 3 };
    int64_t w2[2] = { 1, 3 };
    int64_t start[3] = { 1, 2, -3 };
    dna_vset_t set3, set2;
    tm_proposer_t *p = NULL;

    TEST("B validator removal centers with avg = -1 (exact division)");

    mkid(ids3[0], 0x01); mkid(ids3[1], 0x02); mkid(ids3[2], 0x03);
    mkid(ids2[0], 0x01); mkid(ids2[1], 0x03);
    set3.n = 3; set3.ids = (const uint8_t (*)[DNA_CONSENSUS_ID_LEN])ids3; set3.weights = w3;
    set2.n = 2; set2.ids = (const uint8_t (*)[DNA_CONSENSUS_ID_LEN])ids2; set2.weights = w2;

    if (tm_proposer_import(&p, &set3, start, 0) != 0) { FAIL("import"); return; }
    if (tm_proposer_next_height(p, &set2) != 0) {
        tm_proposer_destroy(p); FAIL("next_height refused"); return;
    }
    if (!prio_eq(p, want, 2)) { tm_proposer_destroy(p); FAIL("priorities"); return; }
    if (prop_idx(p, 0, (const uint8_t (*)[DNA_CONSENSUS_ID_LEN])ids2, 2) != 0) {
        tm_proposer_destroy(p); FAIL("proposer should be p1"); return;
    }
    tm_proposer_destroy(p);
    PASS();
}

static void test_b2_forced_rescale(void)
{
    /* HAND-DERIVED (design §11.2, Codex mutation finding). No other vector in
     * this file ever drives `diff > 2P`, so the RESCALE branch of
     * IncrementProposerPriority was never executed at all — its truncating
     * division could have been anything.
     *
     *   weights [1, 1]  =>  P = 2, diffMax = 2P = 4
     *   imported priorities [5, -4]
     *   diff = 5 - (-4) = 9 > 4                        -> rescale fires
     *   ratio = ceil(9 / 4) = (9 + 4 - 1) / 4 = 3
     *   truncating divide: 5/3 = 1, -4/3 = -1          -> [ 1, -1]
     *   centre: sum = 0, avg = 0                       -> [ 1, -1]
     *   +VP                                            -> [ 2,  0]
     *   max = 2 -> p1;  A(p1) -= 2                     -> [ 0,  0]
     * proposer index 0. */
    static const int64_t want[2] = { 0, 0 };

    uint8_t ids[2][DNA_CONSENSUS_ID_LEN];
    int64_t weights[2] = { 1, 1 };
    int64_t start[2]   = { 5, -4 };
    dna_vset_t set;
    tm_proposer_t *p = NULL;

    TEST("B-2 forced rescale: diff 9 > 2P 4 -> ratio 3 -> [0,0], proposer p1");

    mkid(ids[0], 0x01);
    mkid(ids[1], 0x02);
    set.n = 2;
    set.ids = (const uint8_t (*)[DNA_CONSENSUS_ID_LEN])ids;
    set.weights = weights;

    if (tm_proposer_import(&p, &set, start, 0) != 0) { FAIL("import"); return; }
    if (tm_proposer_next_height(p, &set) != 0) {
        tm_proposer_destroy(p); FAIL("next_height refused"); return;
    }
    if (!prio_eq(p, want, 2)) { tm_proposer_destroy(p); FAIL("priorities"); return; }
    if (prop_idx(p, 0, (const uint8_t (*)[DNA_CONSENSUS_ID_LEN])ids, 2) != 0) {
        tm_proposer_destroy(p); FAIL("proposer should be p1"); return;
    }
    /* NON-VACUITY: without the rescale the same step would be
     * [5,-4] -> centre avg 0 -> [6,-3] -> max p1 -> [4,-3], which is not [0,0].
     * The literal above is only reachable through the rescale branch. */
    tm_proposer_destroy(p);
    PASS();
}

/* ── §C  "New Validator" ALONG THE PINNED CODE PATH ──────────────────── */

static void test_c_new_validator_floor(void)
{
    /* Set {p1:1, p2:3} with priorities p1 = 2, p2 = -2 (the document's "last
     * run" row); p3 joins with VP 8.
     *
     * HAND-DERIVED along the pinned code, NOT produced by this module:
     *   P' (updates applied, removals not) = 4 + 8 = 12
     *   A(p3) = -(12 + (12 >> 3)) = -13                    the document agrees
     *   rescale(2*12 = 24): diff = 2 - (-13) = 15 <= 24    no scaling
     *   centre: sum = 2 + (-2) + (-13) = -13, n = 3
     *           Int.Div is EUCLIDEAN -> floor(-13/3) = -5
     *           (the document's table writes -4, i.e. truncation — see §C-neg)
     *                                          -> [ 7,  3, -8]
     *   IncrementProposerPriority(1):
     *           rescale: diff = 15 <= 24                   no scaling
     *           centre:  sum = 2, floor(2/3) = 0           unchanged
     *           +VP                              -> [ 8,  6,  0]
     *           max = 8 -> p1;  A(p1) -= 12      -> [-4,  6,  0]
     *
     * The elected proposer, p1, is the same one the document names. The
     * NUMBERS are not, and the pinned code is the rule. */
    static const int64_t want[3] = { -4, 6, 0 };

    uint8_t ids2[2][DNA_CONSENSUS_ID_LEN];
    uint8_t ids3[3][DNA_CONSENSUS_ID_LEN];
    int64_t w2[2] = { 1, 3 };
    int64_t w3[3] = { 1, 3, 8 };
    int64_t start[2] = { 2, -2 };
    dna_vset_t set2, set3;
    tm_proposer_t *p = NULL;

    TEST("C new validator centers with FLOOR avg = -5 (pinned code)");

    mkid(ids2[0], 0x01); mkid(ids2[1], 0x02);
    mkid(ids3[0], 0x01); mkid(ids3[1], 0x02); mkid(ids3[2], 0x03);
    set2.n = 2; set2.ids = (const uint8_t (*)[DNA_CONSENSUS_ID_LEN])ids2; set2.weights = w2;
    set3.n = 3; set3.ids = (const uint8_t (*)[DNA_CONSENSUS_ID_LEN])ids3; set3.weights = w3;

    if (tm_proposer_import(&p, &set2, start, 0) != 0) { FAIL("import"); return; }
    if (tm_proposer_next_height(p, &set3) != 0) {
        tm_proposer_destroy(p); FAIL("next_height refused"); return;
    }
    if (!prio_eq(p, want, 3)) { tm_proposer_destroy(p); FAIL("priorities"); return; }
    if (prop_idx(p, 0, (const uint8_t (*)[DNA_CONSENSUS_ID_LEN])ids3, 3) != 0) {
        tm_proposer_destroy(p); FAIL("proposer should be p1"); return;
    }
    tm_proposer_destroy(p);
    PASS();
}

/* The reference DOCUMENT's algorithm, run here with TRUNCATING division —
 * the pseudocode of proposer-selection.md's "Proposer Priority Range"
 * section, one pass: scale, centre, increment, elect, push back. */
static void doc_path_one_run(int64_t *a, const int64_t *vp, uint32_t n, int64_t total)
{
    int64_t mx = a[0], mn = a[0], diff, threshold, scale, sum, avg;
    uint32_t i, best;

    for (i = 1; i < n; i++) { if (a[i] > mx) mx = a[i]; if (a[i] < mn) mn = a[i]; }
    diff = mx - mn;
    threshold = 2 * total;
    if (diff > threshold) {
        scale = diff / threshold;
        for (i = 0; i < n; i++) a[i] /= scale;
    }
    sum = 0;
    for (i = 0; i < n; i++) sum += a[i];
    avg = sum / (int64_t)n;                 /* C truncates toward zero, as the document did */
    for (i = 0; i < n; i++) a[i] -= avg;
    for (i = 0; i < n; i++) a[i] += vp[i];
    best = 0;
    for (i = 1; i < n; i++) if (a[i] > a[best]) best = i;
    a[best] -= total;
}

static void test_c_neg_truncation_differs(void)
{
    /* LITERAL, read off the document's own "New Validator" table:
     *   avg = -4  ->  [6, 2, -9]  ->  +VP  ->  [7, 5, -1]
     *   max = 7 -> p1;  A(p1) -= 12          ->  [-5, 5, -1]
     * which is the table's last row (p1 at -5, p3 at -1, p2 at 5).
     *
     * WHAT THIS IS AND IS NOT (label corrected after the Codex mutation
     * campaign): doc_path_one_run below is FIXTURE ARITHMETIC written in this
     * file. It touches no production code and therefore guards nothing on its
     * own — the production assertion is §C's literal vector, which is only
     * reachable through the floor path. This section exists solely to prove
     * that the two divisions DISAGREE on this input, so that §C's literal is
     * known to be measuring the semantics and not a coincidence. */
    static const int64_t doc_expect[3]  = { -5, 5, -1 };
    static const int64_t code_result[3] = { -4, 6,  0 };   /* the same literal as §C */

    int64_t a[3] = { 2, -2, -13 };
    int64_t vp[3] = { 1, 3, 8 };

    TEST("C-neg truncating division reproduces the DOC and differs from C");

    doc_path_one_run(a, vp, 3, 12);
    if (memcmp(a, doc_expect, sizeof(a)) != 0) { FAIL("doc path did not reproduce the table"); return; }
    if (memcmp(doc_expect, code_result, sizeof(doc_expect)) == 0) {
        FAIL("floor and truncation agree — C measures nothing");
        return;
    }
    PASS();
}

/* ── §D  DNA weight 1: exact round-robin ─────────────────────────────── */

static void test_d_dna_round_robin(void)
{
    /* LITERAL, hand-derived: for a 7-member weight-1 set the genesis state is
     *   penalty = -(7 + (7 >> 3)) = -7 for everyone, centre -> all 0,
     *   IncrementProposerPriority(1) -> all 1, tie -> lowest identity wins,
     *   A(v0) -= 7  =>  S_1 = [-6, 1, 1, 1, 1, 1, 1], proposer v0
     * and each further height moves the -P by one seat, so
     *   proposer(h) = (h - 1) mod 7
     * with S_7 = all zeros and S_8 = S_1. Over 21 heights every member
     * proposes exactly 3 times. */
    static const uint32_t want_seq[21] = {
        0, 1, 2, 3, 4, 5, 6,
        0, 1, 2, 3, 4, 5, 6,
        0, 1, 2, 3, 4, 5, 6
    };
    static const int64_t s1[7] = { -6, 1, 1, 1, 1, 1, 1 };
    static const int64_t s7[7] = {  0, 0, 0, 0, 0, 0, 0 };

    uint8_t ids[7][DNA_CONSENSUS_ID_LEN];
    dna_vset_t set;
    tm_proposer_t *p = NULL;
    uint32_t i, counts[7];
    int consumed = 0;

    TEST("D weight-1 n=7 is an exact round-robin over 21 heights");

    for (i = 0; i < 7; i++) mkid(ids[i], (uint8_t)(0x10 + i));
    set.n = 7;
    set.ids = (const uint8_t (*)[DNA_CONSENSUS_ID_LEN])ids;
    set.weights = NULL;

    if (tm_proposer_create(&p, &set) != 0) { FAIL("create"); return; }
    if (!prio_eq(p, s1, 7)) { tm_proposer_destroy(p); FAIL("S_1 vector"); return; }

    memset(counts, 0, sizeof(counts));
    for (i = 0; i < 21; i++) {
        uint32_t idx = prop_idx(p, 0, (const uint8_t (*)[DNA_CONSENSUS_ID_LEN])ids, 7);
        if (idx != want_seq[i]) {
            char buf[72];
            snprintf(buf, sizeof(buf), "height %u proposer %u want %u", i + 1u, idx, want_seq[i]);
            tm_proposer_destroy(p); FAIL(buf); return;
        }
        counts[idx]++;
        consumed++;
        if (i == 6 && !prio_eq(p, s7, 7)) { tm_proposer_destroy(p); FAIL("S_7 vector"); return; }
        if (i == 7 && !prio_eq(p, s1, 7)) { tm_proposer_destroy(p); FAIL("S_8 != S_1"); return; }
        if (tm_proposer_next_height(p, &set) != 0) {
            tm_proposer_destroy(p); FAIL("next_height refused"); return;
        }
    }
    if (consumed != 21) { tm_proposer_destroy(p); FAIL("sequence not consumed"); return; }
    for (i = 0; i < 7; i++) {
        if (counts[i] != 3) { tm_proposer_destroy(p); FAIL("unfair over 21 heights"); return; }
    }
    tm_proposer_destroy(p);
    PASS();
}

static void test_d_at_round_is_pure(void)
{
    /* tm_proposer_at works on a COPY (consensus/state.go:1071-1075), so `p`
     * must be byte-identical before and after, and the round sequence at S_1
     * must be r mod 7 — the same round-robin walked forward inside a height
     * rather than across heights. */
    uint8_t ids[7][DNA_CONSENSUS_ID_LEN];
    dna_vset_t set, exp_before, exp_after;
    int64_t before[MAXV], after[MAXV];
    tm_proposer_t *p = NULL;
    uint32_t i, pidx_before = 0, pidx_after = 0;

    TEST("D tm_proposer_at(r) = r mod 7 and leaves the object untouched");

    for (i = 0; i < 7; i++) mkid(ids[i], (uint8_t)(0x10 + i));
    set.n = 7;
    set.ids = (const uint8_t (*)[DNA_CONSENSUS_ID_LEN])ids;
    set.weights = NULL;

    if (tm_proposer_create(&p, &set) != 0) { FAIL("create"); return; }
    memset(&exp_before, 0, sizeof(exp_before));
    memset(&exp_after, 0, sizeof(exp_after));
    if (tm_proposer_export(p, &exp_before, before, MAXV, &pidx_before) != 0) {
        tm_proposer_destroy(p); FAIL("export"); return;
    }
    for (i = 0; i < 21; i++) {
        uint32_t idx = prop_idx(p, i, (const uint8_t (*)[DNA_CONSENSUS_ID_LEN])ids, 7);
        if (idx != (i % 7u)) {
            tm_proposer_destroy(p); FAIL("round proposer is not r mod 7"); return;
        }
    }
    if (tm_proposer_export(p, &exp_after, after, MAXV, &pidx_after) != 0) {
        tm_proposer_destroy(p); FAIL("export"); return;
    }
    if (memcmp(before, after, 7 * sizeof(int64_t)) != 0) {
        tm_proposer_destroy(p); FAIL("tm_proposer_at mutated the object"); return;
    }
    /* The stored proposer index is part of the object too — a copy-based
     * tm_proposer_at must not move it either. */
    if (pidx_before != pidx_after || pidx_before != 0u) {
        tm_proposer_destroy(p); FAIL("tm_proposer_at moved the proposer index"); return;
    }
    tm_proposer_destroy(p);
    PASS();
}

static void test_d_c_path_independence(void)
{
    uint8_t ids[7][DNA_CONSENSUS_ID_LEN];
    dna_vset_t set, exported;
    int64_t prio[MAXV];
    tm_proposer_t *p = NULL, *walked = NULL;
    uint32_t i, pidx = 0, direct, stepwise;

    /* DNA defines proposer(h, r) as Increment(r) from S_h, so the answer does
     * not depend on the route the node took (design §6.1, DG-2). CometBFT
     * keeps the ADVANCED set (state.go:1081) and moves by the delta, which for
     * weighted sets runs a different number of rescale/centre passes and can
     * in principle differ. At weight 1 the two coincide — the priority sum
     * stays 0 so centring subtracts nothing, and diff <= n <= 2P so rescaling
     * never fires — and that is what this pins: at(S, 2) must equal the round-0
     * proposer of a CLONE walked forward two heights one step at a time.
     *
     * The clone is built through export/import so it is a genuinely separate
     * object, not an alias whose mutation would make the comparison vacuous. */
    TEST("D-c at(S, 2) == two successive Increment(1) on an independent clone");

    for (i = 0; i < 7; i++) mkid(ids[i], (uint8_t)(0x10 + i));
    set.n = 7;
    set.ids = (const uint8_t (*)[DNA_CONSENSUS_ID_LEN])ids;
    set.weights = NULL;

    if (tm_proposer_create(&p, &set) != 0) { FAIL("create"); return; }
    memset(&exported, 0, sizeof(exported));
    if (tm_proposer_export(p, &exported, prio, MAXV, &pidx) != 0) {
        tm_proposer_destroy(p); FAIL("export"); return;
    }
    if (tm_proposer_import(&walked, &exported, prio, pidx) != 0) {
        tm_proposer_destroy(p); FAIL("import"); return;
    }
    if (tm_proposer_next_height(walked, &set) != 0 ||
        tm_proposer_next_height(walked, &set) != 0) {
        tm_proposer_destroy(p); tm_proposer_destroy(walked); FAIL("walk"); return;
    }

    direct   = prop_idx(p,      2, (const uint8_t (*)[DNA_CONSENSUS_ID_LEN])ids, 7);
    stepwise = prop_idx(walked, 0, (const uint8_t (*)[DNA_CONSENSUS_ID_LEN])ids, 7);
    if (direct > 6u || stepwise > 6u) {
        tm_proposer_destroy(p); tm_proposer_destroy(walked); FAIL("proposer_at"); return;
    }
    if (direct != stepwise) {
        tm_proposer_destroy(p); tm_proposer_destroy(walked);
        FAIL("Increment(2) and Increment(1) twice disagree"); return;
    }
    /* Non-vacuity: the answer must actually have MOVED from round 0, or the
     * two sides could agree by both being "the genesis proposer". */
    if (direct == prop_idx(p, 0, (const uint8_t (*)[DNA_CONSENSUS_ID_LEN])ids, 7)) {
        tm_proposer_destroy(p); tm_proposer_destroy(walked);
        FAIL("round 2 named the same member as round 0 — nothing was measured"); return;
    }
    tm_proposer_destroy(p);
    tm_proposer_destroy(walked);
    PASS();
}

/* ── §E  set change carries the counter ──────────────────────────────── */

static void test_e_set_change_carries(void)
{
    /* HAND-DERIVED literals (design §6.2: "apply the reference" — carry, do
     * NOT reset). Starting from the 7-member S_1 = [-6,1,1,1,1,1,1]:
     *
     * 7 -> 9 (v7, v8 join, weight 1):
     *   P' = 7 + 1 + 1 = 9,  penalty = -(9 + (9>>3)) = -10
     *   [-6,1,1,1,1,1,1,-10,-10]; rescale(18): diff 11 <= 18, none
     *   centre: sum = -20, floor(-20/9) = -3   -> [-3,4,4,4,4,4,4,-7,-7]
     *   increment: centre sum = 7, floor(7/9) = 0; +1 all
     *              -> [-2,5,5,5,5,5,5,-6,-6]; max 5, lowest id -> v1; -9
     *              -> [-2,-4,5,5,5,5,5,-6,-6]     proposer v1
     *   The queue order survived (v1 was next) and the joiners are behind.
     *
     * 9 -> 9 (unchanged): -> [-1,-3,-3,6,6,6,6,-5,-5]  proposer v2
     *
     * 9 -> 7 (v7, v8 leave):
     *   survivors keep A -> [-1,-3,-3,6,6,6,6]; rescale(14): diff 9, none
     *   centre: sum = 17, floor(17/7) = 2      -> [-3,-5,-5,4,4,4,4]
     *   increment: centre sum = 3, floor(3/7) = 0; +1 all
     *              -> [-2,-4,-4,5,5,5,5]; max 5, lowest id -> v3; -7
     *              -> [-2,-4,-4,-2,5,5,5]        proposer v3
     *   The survivors' relative order is unchanged. */
    static const int64_t want9a[9] = { -2, -4, 5, 5, 5, 5, 5, -6, -6 };
    static const int64_t want9b[9] = { -1, -3, -3, 6, 6, 6, 6, -5, -5 };
    static const int64_t want7[7]  = { -2, -4, -4, -2, 5, 5, 5 };

    uint8_t ids9[9][DNA_CONSENSUS_ID_LEN];
    uint8_t ids7[7][DNA_CONSENSUS_ID_LEN];
    dna_vset_t set7, set9;
    tm_proposer_t *p = NULL;
    uint32_t i;

    TEST("E 7->9->9->7 carries priorities, penalises joiners, keeps order");

    for (i = 0; i < 9; i++) mkid(ids9[i], (uint8_t)(0x10 + i));
    for (i = 0; i < 7; i++) mkid(ids7[i], (uint8_t)(0x10 + i));
    set7.n = 7; set7.ids = (const uint8_t (*)[DNA_CONSENSUS_ID_LEN])ids7; set7.weights = NULL;
    set9.n = 9; set9.ids = (const uint8_t (*)[DNA_CONSENSUS_ID_LEN])ids9; set9.weights = NULL;

    if (tm_proposer_create(&p, &set7) != 0) { FAIL("create"); return; }

    if (tm_proposer_next_height(p, &set9) != 0) { tm_proposer_destroy(p); FAIL("7->9"); return; }
    if (!prio_eq(p, want9a, 9)) { tm_proposer_destroy(p); FAIL("7->9 priorities"); return; }
    if (prop_idx(p, 0, (const uint8_t (*)[DNA_CONSENSUS_ID_LEN])ids9, 9) != 1) {
        tm_proposer_destroy(p); FAIL("7->9 proposer should be v1"); return;
    }

    if (tm_proposer_next_height(p, &set9) != 0) { tm_proposer_destroy(p); FAIL("9->9"); return; }
    if (!prio_eq(p, want9b, 9)) { tm_proposer_destroy(p); FAIL("9->9 priorities"); return; }
    if (prop_idx(p, 0, (const uint8_t (*)[DNA_CONSENSUS_ID_LEN])ids9, 9) != 2) {
        tm_proposer_destroy(p); FAIL("9->9 proposer should be v2"); return;
    }

    if (tm_proposer_next_height(p, &set7) != 0) { tm_proposer_destroy(p); FAIL("9->7"); return; }
    if (!prio_eq(p, want7, 7)) { tm_proposer_destroy(p); FAIL("9->7 priorities"); return; }
    if (prop_idx(p, 0, (const uint8_t (*)[DNA_CONSENSUS_ID_LEN])ids7, 7) != 3) {
        tm_proposer_destroy(p); FAIL("9->7 proposer should be v3"); return;
    }

    tm_proposer_destroy(p);
    PASS();
}

/* ── §F  export / import ─────────────────────────────────────────────── */

static void test_f_export_import(void)
{
    /* S_h is the TRIPLE (set, priority vector, elected proposer index), and an
     * imported object reproduces the original at EVERY round, 0 included.
     *
     * Round 0 is the interesting one and it is where the vector alone is not
     * enough: the election ends with A(prop) -= P, so the maximum of the
     * exported vector is NOT the member that was elected. For the 4-member
     * genesis state [-3, 1, 1, 1] the elected member is v0 while the maximum
     * (findProposer's answer, validator_set.go:351-359) is v1. This section
     * therefore asserts the ORIGINAL elects v0, the IMPORT elects v0 as well,
     * and it pins the literal 1 as the answer the discarded fallback WOULD
     * have given — so if the fallback ever creeps back in, the round-0 leg
     * goes red instead of quietly disagreeing with the original. */
    static const int64_t s1[4] = { -3, 1, 1, 1 };
    static const uint32_t ELECTED = 0u;        /* what the election chose */
    static const uint32_t VECTOR_MAX = 1u;     /* what a bare-vector fallback would choose */

    uint8_t ids[4][DNA_CONSENSUS_ID_LEN];
    dna_vset_t set, exported;
    int64_t prio[MAXV];
    tm_proposer_t *orig = NULL, *imp = NULL, *twin = NULL, *bad = NULL;
    uint32_t r, i, pidx = 0xFFFFFFFFu;
    int compared = 0;

    TEST("F export/import round-trips EVERY round, 0 included");

    for (i = 0; i < 4; i++) mkid(ids[i], (uint8_t)(0x20 + i));
    set.n = 4;
    set.ids = (const uint8_t (*)[DNA_CONSENSUS_ID_LEN])ids;
    set.weights = NULL;

    if (tm_proposer_create(&orig, &set) != 0) { FAIL("create"); return; }
    if (!prio_eq(orig, s1, 4)) { tm_proposer_destroy(orig); FAIL("S_1 vector"); return; }

    memset(&exported, 0, sizeof(exported));
    if (tm_proposer_export(orig, &exported, prio, MAXV, &pidx) != 0) {
        tm_proposer_destroy(orig); FAIL("export"); return;
    }
    if (exported.weights != NULL) {
        tm_proposer_destroy(orig); FAIL("weight-1 set exported weights"); return;
    }
    /* The index really is the ELECTED one and not the vector's maximum — if
     * these two coincided, the whole section would prove nothing. */
    if (pidx != ELECTED) {
        tm_proposer_destroy(orig); FAIL("exported index is not the elected member"); return;
    }
    if (ELECTED == VECTOR_MAX) {
        tm_proposer_destroy(orig);
        FAIL("fixture is vacuous: elected == vector max"); return;
    }

    if (tm_proposer_import(&imp, &exported, prio, pidx) != 0) {
        tm_proposer_destroy(orig); FAIL("import"); return;
    }
    if (tm_proposer_import(&twin, &exported, prio, pidx) != 0) {
        tm_proposer_destroy(orig); tm_proposer_destroy(imp); FAIL("twin import"); return;
    }

    /* the vector itself round-trips exactly */
    if (!prio_eq(imp, s1, 4)) {
        tm_proposer_destroy(orig); tm_proposer_destroy(imp); tm_proposer_destroy(twin);
        FAIL("imported vector differs"); return;
    }

    /* EVERY round agrees now, r = 0 first */
    for (r = 0; r <= 32; r++) {
        uint32_t a = prop_idx(orig, r, (const uint8_t (*)[DNA_CONSENSUS_ID_LEN])ids, 4);
        uint32_t b = prop_idx(imp,  r, (const uint8_t (*)[DNA_CONSENSUS_ID_LEN])ids, 4);
        uint32_t t = prop_idx(twin, r, (const uint8_t (*)[DNA_CONSENSUS_ID_LEN])ids, 4);
        if (a > 3u) {
            tm_proposer_destroy(orig); tm_proposer_destroy(imp); tm_proposer_destroy(twin);
            FAIL("proposer_at failed"); return;
        }
        if (a != b || b != t) {
            char buf[72];
            snprintf(buf, sizeof(buf), "round %u does not round-trip", r);
            tm_proposer_destroy(orig); tm_proposer_destroy(imp); tm_proposer_destroy(twin);
            FAIL(buf); return;
        }
        compared++;
    }
    if (compared != 33) {
        tm_proposer_destroy(orig); tm_proposer_destroy(imp); tm_proposer_destroy(twin);
        FAIL("no rounds compared"); return;
    }

    /* the round-0 answer is the ELECTED member on both sides */
    if (prop_idx(orig, 0, (const uint8_t (*)[DNA_CONSENSUS_ID_LEN])ids, 4) != ELECTED ||
        prop_idx(imp,  0, (const uint8_t (*)[DNA_CONSENSUS_ID_LEN])ids, 4) != ELECTED) {
        tm_proposer_destroy(orig); tm_proposer_destroy(imp); tm_proposer_destroy(twin);
        FAIL("round 0 is not the elected member"); return;
    }

    /* an out-of-range index is an error, never repaired by a fallback */
    if (tm_proposer_import(&bad, &exported, prio, 4u) == 0) {
        tm_proposer_destroy(bad);
        tm_proposer_destroy(orig); tm_proposer_destroy(imp); tm_proposer_destroy(twin);
        FAIL("import accepted proposer_idx == n"); return;
    }
    if (bad != NULL) {
        tm_proposer_destroy(orig); tm_proposer_destroy(imp); tm_proposer_destroy(twin);
        FAIL("failed import left an object behind"); return;
    }

    tm_proposer_destroy(orig);
    tm_proposer_destroy(imp);
    tm_proposer_destroy(twin);
    PASS();
}

/* ── §G  the int64 bound ─────────────────────────────────────────────── */

static void test_g_priority_bound(void)
{
    uint8_t (*ids)[DNA_CONSENSUS_ID_LEN];
    dna_vset_t set, out;
    int64_t *prio;
    tm_proposer_t *p = NULL;
    uint32_t h, i, r;
    int64_t worst = 0;
    long observed = 0;

    TEST("G n=128, 10000 heights x 64 rounds stays far inside 2^40");

    ids  = (uint8_t (*)[DNA_CONSENSUS_ID_LEN])calloc(MAXV, DNA_CONSENSUS_ID_LEN);
    prio = (int64_t *)calloc(MAXV, sizeof(int64_t));
    if (!ids || !prio) { free(ids); free(prio); FAIL("alloc"); return; }
    for (i = 0; i < (uint32_t)MAXV; i++) {
        memset(ids[i], 0, DNA_CONSENSUS_ID_LEN);
        ids[i][0] = (uint8_t)(i >> 8);
        ids[i][1] = (uint8_t)(i & 0xFFu);
    }
    set.n = MAXV;
    set.ids = (const uint8_t (*)[DNA_CONSENSUS_ID_LEN])ids;
    set.weights = NULL;

    if (tm_proposer_create(&p, &set) != 0) { free(ids); free(prio); FAIL("create"); return; }

    /* EVERY height is sampled (Codex mutation: sampling one height in a
     * thousand let a drift that reset itself between checkpoints go unseen),
     * and every round query is followed by a re-export so that a copy-based
     * tm_proposer_at that quietly mutated `p` would be caught here too. */
    for (h = 0; h < 10000u; h++) {
        uint32_t pidx = 0;
        if (tm_proposer_next_height(p, &set) != 0) {
            tm_proposer_destroy(p); free(ids); free(prio);
            FAIL("next_height refused — the bound was hit"); return;
        }
        memset(&out, 0, sizeof(out));
        if (tm_proposer_export(p, &out, prio, MAXV, &pidx) != 0) {
            tm_proposer_destroy(p); free(ids); free(prio); FAIL("export"); return;
        }
        if (pidx >= (uint32_t)MAXV) {
            tm_proposer_destroy(p); free(ids); free(prio);
            FAIL("proposer index out of range"); return;
        }
        for (i = 0; i < (uint32_t)MAXV; i++) {
            int64_t a = prio[i] < 0 ? -prio[i] : prio[i];
            if (a > worst) worst = a;
            observed++;
        }
        if ((h % 1000u) == 0u) {
            int64_t before[MAXV];
            dna_vset_t chk;
            uint32_t pidx2 = 0;
            memcpy(before, prio, (size_t)MAXV * sizeof(int64_t));
            for (r = 0; r < 64u; r++) {
                uint8_t got[DNA_CONSENSUS_ID_LEN];
                if (tm_proposer_at(p, r, got) != 0) {
                    tm_proposer_destroy(p); free(ids); free(prio);
                    FAIL("proposer_at refused — the bound was hit"); return;
                }
                memset(&chk, 0, sizeof(chk));
                if (tm_proposer_export(p, &chk, prio, MAXV, &pidx2) != 0) {
                    tm_proposer_destroy(p); free(ids); free(prio); FAIL("re-export"); return;
                }
                if (pidx2 != pidx ||
                    memcmp(before, prio, (size_t)MAXV * sizeof(int64_t)) != 0) {
                    tm_proposer_destroy(p); free(ids); free(prio);
                    FAIL("tm_proposer_at mutated the object"); return;
                }
            }
        }
    }
    tm_proposer_destroy(p);
    free(ids);
    free(prio);

    if (observed == 0) { FAIL("nothing was measured"); return; }
    if (worst >= TM_PRIO_ABS_BOUND) { FAIL("priority reached the refusal bound"); return; }
    /* The theoretical envelope for weight 1 is 2*P = 256; anything near it is
     * fine, anything near 2^40 would mean the counter is drifting. */
    if (worst > 4096) { FAIL("priority drifted far past 2*P"); return; }
    PASS();
}

/* ── §H  the f+1 threshold ───────────────────────────────────────────── */

static void test_h_f_plus_one(void)
{
    struct row { uint32_t n; uint32_t want; };
    static const struct row rows[] = {
        {   0,  1 },   /* never 0, same discipline as dna_bft_quorum */
        {   1,  1 },
        {   3,  1 },
        {   4,  2 },
        {   7,  3 },
        {   9,  3 },   /* NOT 4 — this is the D-6 distinction */
        {  10,  4 },
        {  30, 10 },
        { 128, 43 }
    };
    size_t i;

    TEST("H dna_bft_f_plus_one literals (n=9 gives 3, not 4)");

    for (i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
        if (dna_bft_f_plus_one(rows[i].n) != rows[i].want) {
            char buf[80];
            snprintf(buf, sizeof(buf), "n=%u got %u want %u",
                     rows[i].n, dna_bft_f_plus_one(rows[i].n), rows[i].want);
            FAIL(buf);
            return;
        }
    }
    /* f+1 is NOT n - quorum(n): at n = 9 that would be 9 - 7 = 2. The core
     * must never derive one from the other (DG-3). */
    if (dna_bft_f_plus_one(9) == 9u - dna_bft_quorum(9)) {
        FAIL("f+1 coincides with n - quorum — the distinction is untested");
        return;
    }
    PASS();
}

/* ── refusals ────────────────────────────────────────────────────────── */

static void test_i_refusals(void)
{
    uint8_t ids[3][DNA_CONSENSUS_ID_LEN];
    uint8_t bad[3][DNA_CONSENSUS_ID_LEN];
    dna_vset_t set;
    tm_proposer_t *p = NULL;
    int64_t w[3] = { 1, 0, 1 };

    TEST("I malformed sets are refused, not silently repaired");

    mkid(ids[0], 0x01); mkid(ids[1], 0x02); mkid(ids[2], 0x03);
    mkid(bad[0], 0x03); mkid(bad[1], 0x02); mkid(bad[2], 0x01);   /* descending */

    set.n = 0; set.ids = (const uint8_t (*)[DNA_CONSENSUS_ID_LEN])ids; set.weights = NULL;
    if (tm_proposer_create(&p, &set) == 0) { tm_proposer_destroy(p); FAIL("empty set accepted"); return; }

    set.n = 3; set.ids = (const uint8_t (*)[DNA_CONSENSUS_ID_LEN])bad; set.weights = NULL;
    if (tm_proposer_create(&p, &set) == 0) { tm_proposer_destroy(p); FAIL("unsorted set accepted"); return; }

    set.n = 3; set.ids = (const uint8_t (*)[DNA_CONSENSUS_ID_LEN])ids; set.weights = w;
    if (tm_proposer_create(&p, &set) == 0) { tm_proposer_destroy(p); FAIL("zero weight accepted"); return; }

    set.weights = NULL;
    if (tm_proposer_create(&p, &set) != 0) { FAIL("valid set refused"); return; }
    {
        dna_vset_t out;
        int64_t buf[MAXV];      /* full width: the buffer must survive even if a
                                 * future edit reorders the checks in export */
        uint32_t pidx = 0;
        memset(&out, 0, sizeof(out));
        if (tm_proposer_export(p, &out, buf, 1, &pidx) == 0) {
            tm_proposer_destroy(p); FAIL("export ignored the capacity"); return;
        }
        /* the proposer index is MANDATORY on export, not optional */
        if (tm_proposer_export(p, &out, buf, MAXV, NULL) == 0) {
            tm_proposer_destroy(p); FAIL("export accepted a NULL index out"); return;
        }
    }
    tm_proposer_destroy(p);
    PASS();
}

int main(void)
{
    printf("\nNodus Tendermint T1 — Proposer Selection\n");
    printf("==========================================\n\n");

    test_a_stable_set();
    test_b_removal_centering();
    test_b2_forced_rescale();
    test_c_new_validator_floor();
    test_c_neg_truncation_differs();
    test_d_dna_round_robin();
    test_d_at_round_is_pure();
    test_d_c_path_independence();
    test_e_set_change_carries();
    test_f_export_import();
    test_g_priority_bound();
    test_h_f_plus_one();
    test_i_refusals();

    printf("\n==========================================\n");
    printf("Results: %d passed, %d failed\n\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
