/**
 * @file test_mmcs_air.c
 * @brief P2b slice 1 — MMCS-verify control-AIR construction gate (TDD).
 *
 * Design contract: dnac/docs/plans/2026-07-28-p2b-mmcs-in-air-design.md v2
 * §0.5 "Constraint forms" (index binding user-locked A1: LSB-first, direction
 * bits as PUBLICS).
 *
 * ── HONEST LABEL (read this before believing the word "byte-match") ────────
 * This test does NOT byte-match anything against Plonky3 itself. It performs a
 * NATIVE REPLAY: it drives the SHIPPED, already-byte-matched primitives
 *   - `dnac_p2_mmcs_commit` / `_open_batch` / `_verify` (poseidon2_mmcs.c,
 *     byte-matched at P1b by tests/test_poseidon2_mmcs.c against real
 *     MerkleTreeMmcs vectors),
 *   - `dnac_p2_mmcs_hash_iter` / `_compress` (same file, same gate),
 *   - `poseidon2_air_generate_row` (byte-matched at FP1c.2 against the real
 *     generate_trace_rows),
 * and requires the AIR to accept exactly the trace that chain produces. The
 * byte-match is INHERITED from P1b/FP1c; what is proved HERE is that the AIR's
 * accepted language contains the native one (accepts) and excludes each
 * single-form deviation (negatives).
 *
 * (accept) For two configs x two indices: commit a deterministically filled
 *   batch (NO RNG — a fixed affine fill), open a row, require the NATIVE
 *   verifier to ACCEPT it, then build the AIR trace from that same opening and
 *   require `dnac_mmcs_air_eval_trace == 0`, with the leaf digest and every
 *   intermediate compression cross-checked against `dnac_p2_mmcs_hash_iter` /
 *   `dnac_p2_mmcs_compress` and the final digest against the committed root.
 *   Configs cover BOTH sponge residue classes: the pinned reference
 *   {2 mats, widths {8,5}, depth 4} (total_width 13, 4 leaf rows, partial final
 *   block) and {2 mats, widths {4,4}, depth 3} (total_width 8, 2 leaf rows,
 *   exact block boundary — no trailing permutation). Both indices are
 *   NON-PALINDROMIC at their depth (asserted in-test), so the A1 bit-order
 *   negatives are not vacuous.
 *
 * (reject) 22 negatives, at least one per §0.5 constraint form (plus one per
 *   constraint of the beyond-doc step-index mechanism, so none of those is a
 *   regression hole either), each flipping exactly ONE thing. Four of them pin
 *   an EXACT violation count, which is what proves they hit that form and only
 *   that form: the public root (1), the final-row threading (4), the terminal
 *   row rule (1) and `dir` off a compress row (1).
 *
 * Build (via Makefile):  ./build/test_mmcs_air        (no vector files)
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../field_goldilocks.h"
#include "../mmcs_air.h"
#include "../mmcs_air_table.h"
#include "../poseidon2_air_trace.h"
#include "../poseidon2_mmcs.h"

#define T_MAX_MATS  4
#define T_MAX_TOTAL 32
#define T_MAX_PUB   (MAIR_DIGEST_LANES + DNAC_P2B_MAX_DEPTH + T_MAX_TOTAL)

static int fails = 0;

/* ══════════════════════════ deterministic fixtures ═══════════════════════
 * No RNG anywhere (root CLAUDE.md: seeded/deterministic only). Cell (m, r, c)
 * is a fixed affine function of its coordinates, canonicalized into [0, p) by
 * `gold_fp_from_u64` so the MMCS's canonicality sweep (poseidon2_mmcs.c:
 * 557-562) is satisfied by construction.
 */
static uint64_t cell(size_t m, size_t r, size_t c) {
    const uint64_t x = (uint64_t)(m + 1) * UINT64_C(0x00000001ABCDEF01) +
                       (uint64_t)r * UINT64_C(0x0000000100000007) +
                       (uint64_t)c * UINT64_C(1315423911) +
                       UINT64_C(0x2026072900000000);
    return gold_fp_to_u64(gold_fp_from_u64(x));
}

typedef struct {
    uint64_t         elems[T_MAX_TOTAL]; /* opened rows, concatenated       */
    size_t           total;
    dnac_p2_digest_t sibs[DNAC_P2B_MAX_DEPTH];
    size_t           depth;
    dnac_p2_digest_t root;
} fixture_t;

/* Commit a batch, open `index`, require the NATIVE verifier to accept, and
 * hand back the opened stream + sibling path + root. */
static int make_fixture(const dnac_p2b_table_cfg_t *cfg, uint64_t index,
                        fixture_t *F) {
    const size_t nm = cfg->num_matrices;
    const size_t num_rows = (size_t)1u << cfg->depth;
    uint64_t       *mats[T_MAX_MATS] = {NULL};
    const uint64_t *cmats[T_MAX_MATS] = {NULL};
    const uint64_t *orows[T_MAX_MATS] = {NULL};
    dnac_p2_mmcs_tree_t *tree = NULL;
    dnac_p2_proof_t proof;
    int ok = 1;

    if (nm > T_MAX_MATS) return 0;
    memset(F, 0, sizeof(*F));
    F->depth = cfg->depth;

    for (size_t m = 0; m < nm && ok; m++) {
        mats[m] = (uint64_t *)malloc(num_rows * cfg->widths[m] * sizeof(uint64_t));
        if (!mats[m]) { ok = 0; break; }
        for (size_t r = 0; r < num_rows; r++)
            for (size_t c = 0; c < cfg->widths[m]; c++)
                mats[m][r * cfg->widths[m] + c] = cell(m, r, c);
        cmats[m] = mats[m];
    }

    if (ok && dnac_p2_mmcs_commit(cmats, cfg->widths, nm, num_rows, &F->root,
                                  &tree) != DNAC_P2M_OK)
        ok = 0;

    if (ok) {
        memset(&proof, 0, sizeof(proof));
        proof.siblings = F->sibs;
        if (dnac_p2_mmcs_open_batch(tree, index, orows, &proof) != DNAC_P2M_OK) ok = 0;
    }
    /* The native ACCEPT is the anchor: the AIR must accept the trace built
     * from an opening the shipped verifier itself accepts. */
    if (ok && dnac_p2_mmcs_verify(&F->root, orows, cfg->widths, nm, num_rows,
                                  index, &proof) != DNAC_P2M_OK)
        ok = 0;
    if (ok && (size_t)proof.depth != cfg->depth) ok = 0;

    if (ok) {
        size_t off = 0;
        for (size_t m = 0; m < nm; m++) {
            if (off + cfg->widths[m] > T_MAX_TOTAL) { ok = 0; break; }
            memcpy(F->elems + off, orows[m], cfg->widths[m] * sizeof(uint64_t));
            off += cfg->widths[m];
        }
        F->total = off;
    }

    dnac_p2_mmcs_tree_free(tree);
    for (size_t m = 0; m < nm; m++) free(mats[m]);
    return ok;
}

/* ══════════════════════════ honest trace builder ═════════════════════════
 * TEST-SIDE by design (slice 1 ships no prover): the constraint file must not
 * be able to "help" the witness it checks.
 */
typedef struct {
    const dnac_p2b_table_cfg_t *cfg;
    size_t    rows, leaf, total, depth, num_pub;
    uint64_t *trace; /* rows * MAIR_WIDTH                  */
    uint64_t *prep;  /* rows * DNAC_P2B_TABLE_COLS         */
    uint64_t *pub;   /* num_pub                            */
} built_t;

static void built_free(built_t *B) {
    free(B->trace);
    free(B->prep);
    free(B->pub);
    memset(B, 0, sizeof(*B));
}

static uint64_t *row_of(uint64_t *t, size_t r) { return t + r * MAIR_WIDTH; }

/* Regenerate the embedded block from whatever preimage its input columns hold
 * — so a tamper isolates the CONTROL pin instead of tripping the poseidon2
 * block's own constraints (the test_transcript_air.c:331-335 idiom). */
static void regen_perm(uint64_t *row) {
    uint64_t pre[MAIR_PERM_WIDTH];
    for (size_t i = 0; i < (size_t)MAIR_PERM_WIDTH; i++)
        pre[i] = row[mair_perm_in_off(i)];
    poseidon2_air_generate_row(pre, row + MAIR_PERM_OFF);
}

/**
 * Build the honest AIR trace for one opening.
 *
 * `sibs` and `claimed_root` are parameters (not read from the fixture) so a
 * negative can rebuild the chain honestly around ONE tampered sibling while
 * the public root stays the true one — the A1-F4 / root-equality attack shape.
 * Returns 0 if the replay disagrees with the native primitives.
 */
static int build_trace(built_t *B, const dnac_p2b_table_cfg_t *cfg,
                       uint64_t index, const uint64_t *elems,
                       const dnac_p2_digest_t *sibs,
                       const uint64_t claimed_root[MAIR_DIGEST_LANES]) {
    memset(B, 0, sizeof(*B));
    B->cfg = cfg;
    B->rows = dnac_p2b_table_rows(cfg);
    B->leaf = dnac_mmcs_air_leaf_rows(cfg);
    B->total = dnac_mmcs_air_total_width(cfg);
    B->depth = cfg->depth;
    B->num_pub = dnac_mmcs_air_num_publics(cfg);
    if (B->rows == 0 || B->leaf == 0 || B->total == 0 || B->num_pub == 0) return 0;

    B->trace = (uint64_t *)calloc(B->rows * MAIR_WIDTH, sizeof(uint64_t));
    B->prep = (uint64_t *)calloc(B->rows * DNAC_P2B_TABLE_COLS, sizeof(uint64_t));
    B->pub = (uint64_t *)calloc(B->num_pub, sizeof(uint64_t));
    if (!B->trace || !B->prep || !B->pub) { built_free(B); return 0; }

    if (dnac_p2b_table_generate(cfg, B->prep,
                                B->rows * (size_t)DNAC_P2B_TABLE_COLS) !=
        DNAC_P2B_TABLE_OK) {
        built_free(B);
        return 0;
    }

    size_t   r = 0;
    uint64_t state[MAIR_PERM_WIDTH];
    memset(state, 0, sizeof(state)); /* poseidon2_mmcs.c:49-50 — zero start */

    /* ── leaf-hash rows: PaddingFreeSponge OVERWRITE absorb, one row per
     * permutation (poseidon2_mmcs.c:53-68). ── */
    for (size_t blk = 0; blk < B->leaf; blk++) {
        const size_t k = (blk + 1 < B->leaf)
                             ? (size_t)MAIR_RATE
                             : B->total - (size_t)MAIR_RATE * (B->leaf - 1);
        for (size_t j = 0; j < k; j++) state[j] = elems[(size_t)MAIR_RATE * blk + j];
        uint64_t *row = row_of(B->trace, r);
        poseidon2_air_generate_row(state, row + MAIR_PERM_OFF);
        row[mair_pos_off(blk)] = 1;
        for (size_t j = 0; j < (size_t)MAIR_PERM_WIDTH; j++)
            state[j] = row[mair_perm_out_off(j)];
        r++;
    }

    uint64_t digest[MAIR_DIGEST_LANES];
    memcpy(digest, state, sizeof(digest));
    {   /* cross-check the leaf digest against the shipped sponge */
        uint64_t want[MAIR_DIGEST_LANES];
        dnac_p2_mmcs_hash_iter(elems, B->total, want);
        if (memcmp(want, digest, sizeof(want)) != 0) { built_free(B); return 0; }
    }

    /* ── compress rows: LSB-first walk (poseidon2_mmcs.c:581-590). ── */
    for (size_t l = 0; l < B->depth; l++) {
        const uint64_t bit = (index >> l) & 1u;
        uint64_t pre[MAIR_PERM_WIDTH];
        if (bit == 0) {
            memcpy(pre, digest, sizeof(digest));
            memcpy(pre + MAIR_DIGEST_LANES, sibs[l].lanes, sizeof(digest));
        } else {
            memcpy(pre, sibs[l].lanes, sizeof(digest));
            memcpy(pre + MAIR_DIGEST_LANES, digest, sizeof(digest));
        }
        uint64_t *row = row_of(B->trace, r);
        poseidon2_air_generate_row(pre, row + MAIR_PERM_OFF);
        row[MAIR_DIR_OFF] = bit;
        row[mair_pos_off(B->leaf + l)] = 1;

        uint64_t want[MAIR_DIGEST_LANES];
        if (bit == 0) dnac_p2_mmcs_compress(digest, sibs[l].lanes, want);
        else dnac_p2_mmcs_compress(sibs[l].lanes, digest, want);
        for (size_t j = 0; j < (size_t)MAIR_DIGEST_LANES; j++)
            digest[j] = row[mair_perm_out_off(j)];
        if (memcmp(want, digest, sizeof(want)) != 0) { built_free(B); return 0; }
        r++;
    }

    /* ── final row: receives the last compression's output; its block carries
     * a dummy witness (evaluated ungated). ── */
    {
        uint64_t pre[MAIR_PERM_WIDTH];
        memset(pre, 0, sizeof(pre));
        memcpy(pre, digest, sizeof(digest));
        uint64_t *row = row_of(B->trace, r);
        poseidon2_air_generate_row(pre, row + MAIR_PERM_OFF);
        row[mair_pos_off(B->leaf + B->depth)] = 1;
        r++;
    }

    /* ── padding rows: inert, but they still carry a VALID dummy permutation
     * because the embedded block is evaluated UNGATED. ── */
    {
        uint64_t z[MAIR_PERM_WIDTH];
        memset(z, 0, sizeof(z));
        while (r < B->rows) {
            poseidon2_air_generate_row(z, row_of(B->trace, r) + MAIR_PERM_OFF);
            r++;
        }
    }

    /* ── publics: [root 4][dir bits, LSB-first][opened rows flattened] ── */
    for (size_t j = 0; j < (size_t)MAIR_DIGEST_LANES; j++)
        B->pub[MAIR_PUB_ROOT_OFF + j] = claimed_root[j];
    for (size_t l = 0; l < B->depth; l++)
        B->pub[MAIR_PUB_DIR_OFF + l] = (index >> l) & 1u;
    for (size_t i = 0; i < B->total; i++)
        B->pub[dnac_mmcs_air_pub_opened_off(cfg) + i] = elems[i];

    return 1;
}

/* ═════════════════════════════ helpers/reporting ═════════════════════════ */

/* Evaluate a built trace (a plain call into the AIR evaluator — no dynamic
 * code of any kind). */
static int eval_built(const built_t *B) {
    return dnac_mmcs_air_eval_trace(B->trace, B->prep, B->rows, B->cfg, B->pub,
                                    B->num_pub);
}

static uint64_t *clone_trace(const built_t *B) {
    uint64_t *t = (uint64_t *)malloc(B->rows * MAIR_WIDTH * sizeof(uint64_t));
    if (t) memcpy(t, B->trace, B->rows * MAIR_WIDTH * sizeof(uint64_t));
    return t;
}

static uint64_t *clone_prep(const built_t *B) {
    const size_t n = B->rows * (size_t)DNAC_P2B_TABLE_COLS;
    uint64_t *t = (uint64_t *)malloc(n * sizeof(uint64_t));
    if (t) memcpy(t, B->prep, n * sizeof(uint64_t));
    return t;
}

static uint64_t *clone_pub(const built_t *B) {
    uint64_t *t = (uint64_t *)malloc(B->num_pub * sizeof(uint64_t));
    if (t) memcpy(t, B->pub, B->num_pub * sizeof(uint64_t));
    return t;
}

/* Reject with a violation count; `want_exact` > 0 additionally pins the count
 * (the isolated-count pattern — proves the negative hits THAT form and nothing
 * else). */
static void expect_reject(const char *name, const uint64_t *trace,
                          const uint64_t *prep, size_t rows,
                          const dnac_p2b_table_cfg_t *cfg, const uint64_t *pub,
                          size_t num_pub, int want_exact) {
    const int v = dnac_mmcs_air_eval_trace(trace, prep, rows, cfg, pub, num_pub);
    if (v < 1) {
        printf("  [reject] %-52s NOT caught — FAIL\n", name);
        fails++;
        return;
    }
    if (want_exact > 0 && v != want_exact) {
        printf("  [reject] %-52s caught but %d viol (want %d) — FAIL\n", name, v,
               want_exact);
        fails++;
        return;
    }
    printf("  [reject] %-52s caught (%d viol) — OK\n", name, v);
}

static void expect_bad_config(const char *name, int v) {
    if (v == MAIR_VIOL_BAD_CONFIG)
        printf("  [reject] %-52s fails closed — OK\n", name);
    else {
        printf("  [reject] %-52s returned %d — FAIL\n", name, v);
        fails++;
    }
}

/* Bit-reversal of `x` within `depth` bits — the naive-composition trap
 * (design §0.5 / G-DET-P2b-3: upstream's `2*acc + bit` composed against DNAC's
 * LSB-first walk yields exactly this). */
static uint64_t bitrev(uint64_t x, size_t depth) {
    uint64_t y = 0;
    for (size_t i = 0; i < depth; i++) y |= ((x >> i) & 1u) << (depth - 1 - i);
    return y;
}

/* Accept one (cfg, index) pair; optionally keep the built trace. */
static int accept_case(const dnac_p2b_table_cfg_t *cfg, uint64_t index,
                       const char *label, built_t *keep) {
    fixture_t *F = (fixture_t *)calloc(1, sizeof(fixture_t));
    built_t    B;
    int        ok = 1;

    if (!F) return 0;
    if (!make_fixture(cfg, index, F)) {
        printf("  [accept] %-20s native commit/open/verify        FAIL\n", label);
        fails++;
        free(F);
        return 0;
    }
    if (!build_trace(&B, cfg, index, F->elems, F->sibs, F->root.lanes)) {
        printf("  [accept] %-20s honest trace build               FAIL\n", label);
        fails++;
        free(F);
        return 0;
    }

    const int v = eval_built(&B);
    if (v != 0) {
        printf("  [accept] %-20s %2zu rows  %d viol — FAIL\n", label, B.rows, v);
        fails++;
        ok = 0;
    } else {
        printf("  [accept] %-20s idx %2" PRIu64 "  %2zu rows (%zu leaf + %zu "
               "compress + 1 final)  0 viol — OK\n",
               label, index, B.rows, B.leaf, B.depth);
    }

    if (keep && ok) *keep = B; /* ownership moves to the caller */
    else built_free(&B);
    free(F);
    return ok;
}

/* ═════════════════════════════════ main ══════════════════════════════════ */

/* Second config: total_width 8 => 8 % RATE == 0, the OTHER residue class (no
 * trailing permutation, poseidon2_mmcs.c:63), 2 leaf rows, depth 3. */
static const size_t CFG_B_WIDTHS[2] = {4, 4};
static const dnac_p2b_table_cfg_t CFG_B = {2, CFG_B_WIDTHS, 3};

int main(void) {
    printf("============================================================\n");
    printf("P2b slice 1 — MMCS-verify control-AIR  WIDTH=%zu (%zu control + %d perm)\n",
           (size_t)MAIR_WIDTH, (size_t)MAIR_PERM_OFF, P2AIR_NUM_COLS);
    printf("============================================================\n");

    const dnac_p2b_table_cfg_t *A = dnac_p2b_ref_cfg();

    /* ── Gate 0: layout binding contract ── */
    if (dnac_mmcs_air_layout_check())
        printf("  [accept] column-layout binding contract                     OK\n");
    else {
        printf("  [accept] column-layout binding contract                     FAIL\n");
        fails++;
    }

    /* ── Gate 0b: schedule/public helpers agree with the pinned reference ── */
    {
        const size_t leaf = dnac_mmcs_air_leaf_rows(A);
        const size_t total = dnac_mmcs_air_total_width(A);
        const size_t npub = dnac_mmcs_air_num_publics(A);
        const int good = (total == DNAC_P2B_REF_WIDTH_0 + DNAC_P2B_REF_WIDTH_1) &&
                         (leaf == 4) && (dnac_p2b_table_rows(A) == DNAC_P2B_REF_ROWS) &&
                         (dnac_mmcs_air_pub_opened_off(A) ==
                          (size_t)MAIR_DIGEST_LANES + DNAC_P2B_REF_DEPTH) &&
                         (npub == (size_t)MAIR_DIGEST_LANES + DNAC_P2B_REF_DEPTH + total);
        if (good)
            printf("  [accept] reference schedule: total_width %zu, %zu leaf rows, "
                   "%zu publics  OK\n", total, leaf, npub);
        else {
            printf("  [accept] reference schedule helpers                         FAIL\n");
            fails++;
        }
    }

    /* ── Gate 0c: config fail-close ── */
    {
        uint64_t dummy_main[MAIR_WIDTH];
        uint64_t dummy_prep[DNAC_P2B_TABLE_COLS] = {0, 0, 0};
        uint64_t dummy_pub[T_MAX_PUB];
        memset(dummy_main, 0, sizeof(dummy_main));
        memset(dummy_pub, 0, sizeof(dummy_pub));

        expect_bad_config("NULL config",
                          dnac_mmcs_air_eval_row(dummy_main, NULL, dummy_prep, NULL,
                                                 0, NULL, dummy_pub, 1));
        /* depth 0 is not a Merkle tree (mmcs_air_table.c:36). */
        {
            const dnac_p2b_table_cfg_t bad = {2, CFG_B_WIDTHS, 0};
            expect_bad_config("depth == 0",
                              dnac_mmcs_air_eval_row(dummy_main, NULL, dummy_prep,
                                                     NULL, 0, &bad, dummy_pub, 1));
        }
        /* Wrong public-value count. */
        expect_bad_config("num_publics != required",
                          dnac_mmcs_air_eval_row(dummy_main, NULL, dummy_prep, NULL,
                                                 0, A, dummy_pub, 1));
        /* A schedule too tall for the slice-1 step one-hot: width 248 => 62 leaf
         * rows, +4 compress +1 final => 67 steps > MAIR_MAX_STEPS. */
        {
            static const size_t wide[1] = {248};
            const dnac_p2b_table_cfg_t big = {1, wide, 4};
            expect_bad_config("schedule exceeds MAIR_MAX_STEPS",
                              dnac_mmcs_air_eval_row(dummy_main, NULL, dummy_prep,
                                                     NULL, 0, &big,
                                                     dummy_pub, T_MAX_PUB));
        }
        /* A schedule that leaves NO padding row: width 12 => 3 leaf + 4 compress
         * + 1 final = 8 = 2^3 exactly, so the last row would carry a row type
         * and the terminality boundary could never hold. Rejected up front. */
        {
            static const size_t exact[1] = {12};
            const dnac_p2b_table_cfg_t nopad = {1, exact, 4};
            expect_bad_config("schedule with no padding row",
                              dnac_mmcs_air_eval_row(dummy_main, NULL, dummy_prep,
                                                     NULL, 0, &nopad,
                                                     dummy_pub, T_MAX_PUB));
        }
        /* A next MAIN row without a next PREPROCESSED row is the PIN-2 shape
         * (batch_verify.c:696-707 zero-fills it) — rejected, never evaluated. */
        expect_bad_config("main_next without prep_next (PIN-2 shape)",
                          dnac_mmcs_air_eval_row(dummy_main, dummy_main, dummy_prep,
                                                 NULL, 0, A, dummy_pub,
                                                 dnac_mmcs_air_num_publics(A)));
    }

    /* ══ PHASE 1 — POSITIVE: native replay, both residue classes ══ */
    printf("------------------------------------------------------------\n");
    printf("Phase 1 — honest traces (native commit/open/verify replay)\n");
    printf("------------------------------------------------------------\n");

    /* Non-palindromic indices: the plain "wrong index" negative passes just as
     * happily with the bit order inverted, so A1 can only be guarded by an
     * index whose bit-reversal differs (design §0.5, round-1 A1-F7). */
    const uint64_t IDX_A = 3;  /* depth 4: 1100b LSB-first, bitrev = 12 */
    const uint64_t IDX_A2 = 5; /* depth 4: 1010b LSB-first, bitrev = 10 */
    const uint64_t IDX_B = 3;  /* depth 3: 110b  LSB-first, bitrev = 6  */
    const uint64_t IDX_B2 = 6; /* depth 3: 011b  LSB-first, bitrev = 3  */
    {
        const int np = (bitrev(IDX_A, 4) != IDX_A) && (bitrev(IDX_A2, 4) != IDX_A2) &&
                       (bitrev(IDX_B, 3) != IDX_B) && (bitrev(IDX_B2, 3) != IDX_B2);
        if (np)
            printf("  [accept] all four indices are NON-palindromic (A1 guard)     OK\n");
        else {
            printf("  [accept] index palindromicity precondition                  FAIL\n");
            fails++;
        }
    }

    built_t W;
    memset(&W, 0, sizeof(W));
    if (!accept_case(A, IDX_A, "ref {8,5} d4", &W)) return 1;
    accept_case(A, IDX_A2, "ref {8,5} d4", NULL);
    accept_case(&CFG_B, IDX_B, "alt {4,4} d3", NULL);
    accept_case(&CFG_B, IDX_B2, "alt {4,4} d3", NULL);

    /* ══ PHASE 2 — NEGATIVE ══
     * Workhorse: the reference config at the non-palindromic index 3. It has
     * 4 leaf rows (a PARTIAL final block), 4 compress rows with a mixed bit
     * pattern, one final row and 7 padding rows.
     */
    printf("------------------------------------------------------------\n");
    printf("Phase 2 — §0.5 constraint-form negatives\n");
    printf("------------------------------------------------------------\n");

    const size_t r_leaf0 = 0;
    const size_t r_leaf_last = W.leaf - 1;
    const size_t r_comp0 = W.leaf;      /* level 0 — index bit 0 == 1 */
    const size_t r_comp1 = W.leaf + 1;  /* level 1 — index bit 1 == 1 */
    const size_t r_comp_last = W.leaf + W.depth - 1;
    const size_t r_final = W.leaf + W.depth;

    /* N1 — flipped direction bit, with its PUBLIC bit flipped too so the A1
     * binding still holds: the placement pair (mmcs_air.c block I) is then the
     * only form left to reject it. */
    {
        uint64_t *t = clone_trace(&W);
        uint64_t *p = clone_pub(&W);
        row_of(t, r_comp0)[MAIR_DIR_OFF] ^= 1u;
        p[MAIR_PUB_DIR_OFF + 0] ^= 1u;
        expect_reject("N1 direction bit flipped (+ its public bit)", t, W.prep,
                      W.rows, W.cfg, p, W.num_pub, 0);
        free(t);
        free(p);
    }
    /* N2 — sibling and running hash SWAPPED inside a compress row's preimage
     * (poseidon2_mmcs.c:584-587 chooses the side by the bit; here the halves
     * are exchanged while the bit is unchanged). */
    {
        uint64_t *t = clone_trace(&W);
        uint64_t *row = row_of(t, r_comp1);
        for (size_t j = 0; j < (size_t)MAIR_DIGEST_LANES; j++) {
            const uint64_t tmp = row[mair_perm_in_off(j)];
            row[mair_perm_in_off(j)] = row[mair_perm_in_off(MAIR_DIGEST_LANES + j)];
            row[mair_perm_in_off(MAIR_DIGEST_LANES + j)] = tmp;
        }
        regen_perm(row);
        expect_reject("N2 sibling side swapped", t, W.prep, W.rows, W.cfg, W.pub,
                      W.num_pub, 0);
        free(t);
    }
    /* N3 — a TAMPERED SIBLING with the whole downstream chain rebuilt
     * honestly: every placement, every threading step holds; only the final
     * root no longer equals the public one (poseidon2_mmcs.c:593-594). */
    {
        fixture_t *F = (fixture_t *)calloc(1, sizeof(fixture_t));
        built_t    X;
        if (F && make_fixture(A, IDX_A, F)) {
            F->sibs[1].lanes[0] =
                gold_fp_to_u64(gold_fp_add(gold_fp_from_u64(F->sibs[1].lanes[0]),
                                           gold_fp_one()));
            if (build_trace(&X, A, IDX_A, F->elems, F->sibs, F->root.lanes)) {
                expect_reject("N3 tampered sibling, chain rebuilt (root equality)",
                              X.trace, X.prep, X.rows, X.cfg, X.pub, X.num_pub, 0);
                built_free(&X);
            } else {
                printf("  [reject] N3 rebuild                                    FAIL\n");
                fails++;
            }
        } else {
            printf("  [reject] N3 fixture                                        FAIL\n");
            fails++;
        }
        free(F);
    }
    /* N4 — wrong PUBLIC root. Isolated: exactly one lane differs, and only the
     * final row's root pin reads it. */
    {
        uint64_t *p = clone_pub(&W);
        p[MAIR_PUB_ROOT_OFF + 2] =
            gold_fp_to_u64(gold_fp_add(gold_fp_from_u64(p[MAIR_PUB_ROOT_OFF + 2]),
                                       gold_fp_one()));
        expect_reject("N4 wrong public root lane", W.trace, W.prep, W.rows, W.cfg,
                      p, W.num_pub, 1);
        free(p);
    }
    /* N5 — WRONG CLAIMED INDEX with a CORRECT walk: the trace's dir columns
     * (and therefore its siblings' sides) are index 3's, the public bits claim
     * index 5. Only the A1 binding can see it. */
    {
        uint64_t *p = clone_pub(&W);
        for (size_t l = 0; l < W.depth; l++)
            p[MAIR_PUB_DIR_OFF + l] = (IDX_A2 >> l) & 1u;
        expect_reject("N5 wrong claimed index, correct walk (A1)", W.trace, W.prep,
                      W.rows, W.cfg, p, W.num_pub, 0);
        free(p);
    }
    /* N6 — the same walk claimed under the BIT-REVERSED index: the exact
     * artefact a naive composition of upstream's `2*acc + bit` with DNAC's
     * LSB-first walk would produce (G-DET-P2b-3). Non-vacuous because index 3
     * is non-palindromic at depth 4 (bitrev(3) == 12). */
    {
        uint64_t *p = clone_pub(&W);
        const uint64_t rev = bitrev(IDX_A, W.depth);
        for (size_t l = 0; l < W.depth; l++)
            p[MAIR_PUB_DIR_OFF + l] = (rev >> l) & 1u;
        expect_reject("N6 bit-reversed index publics (composition trap)", W.trace,
                      W.prep, W.rows, W.cfg, p, W.num_pub, 0);
        free(p);
    }
    /* N7 — broken chaining: a compress row's RUNNING half no longer equals the
     * previous row's permutation output. */
    {
        uint64_t *t = clone_trace(&W);
        uint64_t *row = row_of(t, r_comp1);
        const size_t half = (W.pub[MAIR_PUB_DIR_OFF + 1] == 0) ? 0 : MAIR_DIGEST_LANES;
        row[mair_perm_in_off(half)] =
            gold_fp_to_u64(gold_fp_add(gold_fp_from_u64(row[mair_perm_in_off(half)]),
                                       gold_fp_one()));
        regen_perm(row);
        expect_reject("N7 running hash != previous output (chaining)", t, W.prep,
                      W.rows, W.cfg, W.pub, W.num_pub, 0);
        free(t);
    }
    /* N8 — non-boolean `dir` (P3rec air.rs:937 assert_bool). */
    {
        uint64_t *t = clone_trace(&W);
        row_of(t, r_comp0)[MAIR_DIR_OFF] = 2;
        expect_reject("N8 non-boolean dir", t, W.prep, W.rows, W.cfg, W.pub,
                      W.num_pub, 0);
        free(t);
    }
    /* N9 — leaf preimage tamper: an absorbed lane no longer equals its public
     * opened-row element (the A1-F2 pillar; without it the AIR proves only
     * that SOME leaf is in the tree). */
    {
        uint64_t *t = clone_trace(&W);
        uint64_t *row = row_of(t, r_leaf0);
        row[mair_perm_in_off(1)] =
            gold_fp_to_u64(gold_fp_add(gold_fp_from_u64(row[mair_perm_in_off(1)]),
                                       gold_fp_one()));
        regen_perm(row);
        expect_reject("N9 absorbed lane != its public (leaf preimage)", t, W.prep,
                      W.rows, W.cfg, W.pub, W.num_pub, 0);
        free(t);
    }
    /* N10 — the leaf sponge does NOT start at zero: a capacity lane of the
     * first leaf row is non-zero (poseidon2_mmcs.c:49-50 memset; round-1
     * A1-F3). */
    {
        uint64_t *t = clone_trace(&W);
        uint64_t *row = row_of(t, r_leaf0);
        row[mair_perm_in_off(MAIR_PERM_WIDTH - 1)] = 1;
        regen_perm(row);
        expect_reject("N10 leaf state not zero (capacity lane)", t, W.prep, W.rows,
                      W.cfg, W.pub, W.num_pub, 0);
        free(t);
    }
    /* N11 — the A1-F4 attack shape: GARBAGE the last compression (its sibling
     * half is free witness, so nothing else notices) while writing the TRUE
     * root straight into the final row. Only the final-row threading rejects
     * it. */
    {
        uint64_t *t = clone_trace(&W);
        uint64_t *row = row_of(t, r_comp_last);
        const size_t sib_half =
            (W.pub[MAIR_PUB_DIR_OFF + W.depth - 1] == 0) ? MAIR_DIGEST_LANES : 0;
        row[mair_perm_in_off(sib_half)] =
            gold_fp_to_u64(gold_fp_add(gold_fp_from_u64(row[mair_perm_in_off(sib_half)]),
                                       gold_fp_one()));
        regen_perm(row);
        expect_reject("N11 garbaged last compression, true root in final row", t,
                      W.prep, W.rows, W.cfg, W.pub, W.num_pub,
                      (int)MAIR_DIGEST_LANES);
        free(t);
    }
    /* N12 — TRUNCATED trace that ends at the final row (no padding row left).
     * Schedule conformance fires first: the row count is a pinned constant,
     * never a witnessed length (A1-F6). */
    expect_bad_config("N12 truncated trace (ends at the final row)",
                      dnac_mmcs_air_eval_trace(W.trace, W.prep, r_final + 1, W.cfg,
                                               W.pub, W.num_pub));
    /* N13 — TERMINALITY in isolation. Full-length trace, correct row count, and
     * the LAST row is turned into an OTHERWISE-VALID typed row: the table types
     * it `is_leaf`, it claims step 0, and its permutation preimage is a
     * perfectly legal first leaf block (the opened stream's first RATE
     * elements over a zero capacity). Every row-local form it touches is
     * SATISFIED, and no transition constrains it because it has no successor —
     * which is exactly the hole the boundary exists to close. The count is
     * therefore EXACTLY 1: this negative pins the terminal-row rule itself and
     * nothing else, so deleting that rule turns the suite red (the N20b
     * isolation pattern, test_transcript_air.c:878-888). */
    {
        uint64_t *t = clone_trace(&W);
        uint64_t *p = clone_prep(&W);
        const size_t last = W.rows - 1;
        const size_t k0 = (1 < W.leaf) ? (size_t)MAIR_RATE
                                       : W.total - (size_t)MAIR_RATE * (W.leaf - 1);
        uint64_t *row = row_of(t, last);
        p[last * DNAC_P2B_TABLE_COLS + DNAC_P2B_COL_IS_LEAF] = 1;
        row[mair_pos_off(0)] = 1;
        for (size_t j = 0; j < k0; j++)
            row[mair_perm_in_off(j)] = W.pub[dnac_mmcs_air_pub_opened_off(W.cfg) + j];
        for (size_t j = k0; j < (size_t)MAIR_PERM_WIDTH; j++)
            row[mair_perm_in_off(j)] = 0;
        regen_perm(row);
        expect_reject("N13 valid typed row with no successor (terminality)", t, p,
                      W.rows, W.cfg, W.pub, W.num_pub, 1);
        free(t);
        free(p);
    }
    /* N14 — n_rows != dnac_p2b_table_rows(cfg): fail-close, both directions. */
    expect_bad_config("N14 n_rows one short of the pinned schedule",
                      dnac_mmcs_air_eval_trace(W.trace, W.prep, W.rows - 1, W.cfg,
                                               W.pub, W.num_pub));
    /* N15 — the PIN-1 vacuity shape: an ALL-ZERO preprocessed table (every
     * gated constraint would evaluate 0 * (...) == 0). Reported truthfully. */
    {
        uint64_t *p = clone_prep(&W);
        memset(p, 0, W.rows * (size_t)DNAC_P2B_TABLE_COLS * sizeof(uint64_t));
        const int v = dnac_mmcs_air_eval_trace(W.trace, p, W.rows, W.cfg, W.pub,
                                               W.num_pub);
        if (v >= 1) {
            /* The step one-hot is bound to the preprocessed type indicator and
             * anchored at row 0, so an all-zero table is not merely vacuous —
             * it is UNSATISFIABLE for any trace claiming a step. That does NOT
             * replace PIN-1: a DIFFERENTLY-SHAPED but well-formed table (a
             * shorter walk, a different leaf count) is still only excluded by
             * pinning the table's root. */
            printf("  [reject] N15 all-zero preprocessed table (PIN-1 shape)      "
                   "caught (%d viol) — OK\n", v);
        } else {
            printf("  [reject] N15 all-zero preprocessed table (PIN-1 shape)      "
                   "NOT caught — FAIL\n");
            fails++;
        }
        free(p);
    }
    /* N16 — step one-hot broken (double bit). */
    {
        uint64_t *t = clone_trace(&W);
        row_of(t, r_leaf_last)[mair_pos_off(0)] = 1;
        expect_reject("N16 step one-hot double bit", t, W.prep, W.rows, W.cfg,
                      W.pub, W.num_pub, 0);
        free(t);
    }
    /* N17 — a step SKIPPED: the walk would drop a compress row's worth of
     * schedule while the preprocessed table still says `is_compress`. */
    {
        uint64_t *t = clone_trace(&W);
        uint64_t *row = row_of(t, r_comp1);
        row[mair_pos_off(W.leaf + 1)] = 0;
        row[mair_pos_off(W.leaf + 2)] = 1;
        expect_reject("N17 step index skipped (advance rule)", t, W.prep, W.rows,
                      W.cfg, W.pub, W.num_pub, 0);
        free(t);
    }
    /* N18 — position/type disagreement: a row the TABLE types as `is_compress`
     * claims a LEAF step (design §3 target 2: "the schedule says compress but
     * the main columns carry leaf-hash data"). */
    {
        uint64_t *t = clone_trace(&W);
        uint64_t *row = row_of(t, r_comp0);
        row[mair_pos_off(W.leaf)] = 0;
        row[mair_pos_off(0)] = 1;
        expect_reject("N18 compress row claiming a leaf step", t, W.prep, W.rows,
                      W.cfg, W.pub, W.num_pub, 0);
        free(t);
    }
    /* N19 — leaf state threading broken: a capacity lane is not carried from
     * one leaf permutation into the next (poseidon2_mmcs.c:55-59 — only the
     * absorbed rate slots are overwritten). */
    {
        uint64_t *t = clone_trace(&W);
        uint64_t *row = row_of(t, 1); /* second leaf row */
        row[mair_perm_in_off(MAIR_PERM_WIDTH - 1)] =
            gold_fp_to_u64(gold_fp_add(
                gold_fp_from_u64(row[mair_perm_in_off(MAIR_PERM_WIDTH - 1)]),
                gold_fp_one()));
        regen_perm(row);
        expect_reject("N19 leaf capacity not threaded", t, W.prep, W.rows, W.cfg,
                      W.pub, W.num_pub, 0);
        free(t);
    }

    /* N20 — an INTERIOR cell of the embedded poseidon2 block (G-SEC-P2b-1
     * rests on every compression being a real permutation; the block is
     * evaluated UNGATED on every row, so this is the form that carries it). */
    {
        uint64_t *t = clone_trace(&W);
        const size_t off = MAIR_PERM_OFF + p2air_beg_sbox_off(0, 0);
        uint64_t *row = row_of(t, r_comp0);
        row[off] = gold_fp_to_u64(
            gold_fp_add(gold_fp_from_u64(row[off]), gold_fp_one()));
        expect_reject("N20 poseidon2 block interior cell tamper", t, W.prep,
                      W.rows, W.cfg, W.pub, W.num_pub, 0);
        free(t);
    }
    /* N21 — `dir` non-zero on a NON-compress row (design §4.6 item 6: there is
     * exactly one direction bit per level and it lives on that level's compress
     * row). Isolated: nothing else on a leaf row reads `dir`. */
    {
        uint64_t *t = clone_trace(&W);
        row_of(t, r_leaf0)[MAIR_DIR_OFF] = 1;
        expect_reject("N21 dir set on a leaf row", t, W.prep, W.rows, W.cfg,
                      W.pub, W.num_pub, 1);
        free(t);
    }
    /* N22 — a NON-BOOLEAN step cell whose one-hot SUM is still 1 in the field
     * (2 + (p-1) == 1 mod p): the sum constraint alone cannot see it, so this
     * is the negative that keeps the per-cell booleanity rule alive. */
    {
        uint64_t *t = clone_trace(&W);
        uint64_t *row = row_of(t, 1); /* leaf block 1 */
        row[mair_pos_off(1)] = 2;
        row[mair_pos_off(2)] = GOLDILOCKS_P - 1u;
        expect_reject("N22 non-boolean step cell (sum preserved)", t, W.prep,
                      W.rows, W.cfg, W.pub, W.num_pub, 0);
        free(t);
    }

    built_free(&W);

    printf("------------------------------------------------------------\n");
    if (fails) {
        printf("P2b MMCS AIR: %d FAIL\n", fails);
        return 1;
    }
    printf("P2b MMCS AIR: 4 honest openings accepted (2 configs x 2 indices,\n"
           "  both sponge residue classes, native chain cross-checked) +\n"
           "  7 fail-close configs + 22 constraint-form negatives — PASS\n");
    return 0;
}
