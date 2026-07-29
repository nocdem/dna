/**
 * @file test_mmcs_mixed_air.c
 * @brief P2b slice 2 — mixed-height MMCS-verify control-AIR construction gate.
 *
 * Build spec: dnac/docs/plans/2026-07-29-p2b-slice2-mixed-mmcs-BUILDABLE.md.
 *
 * ── HONEST LABEL (read before believing "byte-match") ──────────────────────
 * This test does NOT byte-match against Plonky3 directly. It NATIVE-REPLAYS the
 * SHIPPED, already-byte-matched primitives:
 *   - `dnac_p2_mmcs_commit_mixed` / `_open_mixed` / `_verify_mixed`
 *     (poseidon2_mmcs.c, byte-matched at P1b/P2L-d against real MerkleTreeMmcs
 *     vectors),
 *   - `dnac_p2_mmcs_hash_iter` / `_compress` (same file, same gate),
 *   - `poseidon2_air_generate_row` (byte-matched at FP1c.2),
 * and requires the AIR to accept exactly the trace that chain produces, with the
 * leaf digest, EVERY intermediate compression AND the injected-group's
 * rows_digest cross-checked against the native primitives on the SAME inputs.
 * The byte-match is INHERITED; what is proved HERE is that the AIR's accepted
 * language contains the native one (accepts) and excludes each single-form
 * deviation (negatives).
 *
 * (accept) FOUR mixed shapes (REF {8,2}, WIDE {16,4,2} ×2 idx, MG {8,8,2},
 * INJ2 {8,2}w{1,6}) = 5 accept invocations, each committed with an affine fill
 *   (NO RNG), opened, NATIVE-verified, then AIR-checked at 0 violations:
 *   - REF   heights {8,2}   widths {1,1} salt 2 depth 3  (the pinned ref cfg):
 *           1 tallest-leaf row (partial block) + one inject block at level 1.
 *   - WIDE  heights {16,4,2} widths {1,1,1} salt 2 depth 4:
 *           TWO inject blocks, at levels 1 and 2.
 *   - MG    heights {8,8,2} widths {2,2,2} salt 2 depth 3:
 *           a TWO-MATRIX tallest group (concat 8 => 2 leaf rows, EXACT sponge
 *           boundary) + one inject block.
 *
 * (reject) the mandatory injection-specific negatives (N-order the point of the
 *   slice) + the leaf/compress/root/salt/chain forms + the cfg / shape gates.
 *
 * Build (via Makefile):  ./build/test_mmcs_mixed_air        (no vector files)
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
#include "../mmcs_mixed_air.h"
#include "../mmcs_mixed_air_table.h"
#include "../poseidon2_air_cols.h"
#include "../poseidon2_air_trace.h"
#include "../poseidon2_mmcs.h"

#define T_MAXM      8
#define T_MAXPHYS   16
#define T_MAXDEPTH  8
#define T_MAXROWS   128
#define T_MAXCONCAT 64
#define T_MAXPUB    64

static int fails = 0;

/* ══════════════════════════ deterministic fixtures ═══════════════════════
 * No RNG (root CLAUDE.md: seeded/deterministic only). Cell (m,r,c) is a fixed
 * affine function canonicalized into [0,p) so the MMCS canonicality sweep
 * (poseidon2_mmcs.c:476-477) holds by construction. */
static uint64_t cell(size_t m, size_t r, size_t c) {
    const uint64_t x = (uint64_t)(m + 1) * UINT64_C(0x00000001ABCDEF01) +
                       (uint64_t)r * UINT64_C(0x0000000100000007) +
                       (uint64_t)c * UINT64_C(1315423911) +
                       UINT64_C(0x2026072900000000);
    return gold_fp_to_u64(gold_fp_from_u64(x));
}

static size_t ilog2(size_t x) {
    size_t d = 0;
    while (x > 1) { x >>= 1; d++; }
    return d;
}
static size_t maxh_of(const dnac_p2c_mmix_table_cfg_t *c) {
    size_t m = 0;
    for (size_t i = 0; i < c->num_matrices; i++)
        if (c->heights[i] > m) m = c->heights[i];
    return m;
}
static int present(const dnac_p2c_mmix_table_cfg_t *c, size_t h) {
    for (size_t i = 0; i < c->num_matrices; i++)
        if (c->heights[i] == h) return 1;
    return 0;
}

typedef struct {
    size_t           nm, depth, max_h, salt;
    size_t           semw[T_MAXM], physw[T_MAXM], heights[T_MAXM];
    uint64_t         index;
    uint64_t         rows[T_MAXM][T_MAXPHYS]; /* copied physical opened rows */
    dnac_p2_digest_t sibs[T_MAXDEPTH];
    dnac_p2_digest_t root;
} fixt_t;

/* Commit a mixed batch, open `index`, require NATIVE verify to accept, and hand
 * back the opened PHYSICAL rows + sibling path + root. */
static int make_fixt(const dnac_p2c_mmix_table_cfg_t *cfg, uint64_t index,
                     fixt_t *F) {
    const size_t nm = cfg->num_matrices;
    uint64_t       *mats[T_MAXM] = {NULL};
    const uint64_t *cmats[T_MAXM] = {NULL};
    const uint64_t *orows[T_MAXM] = {NULL};
    dnac_p2_mmcs_tree_t *tree = NULL;
    dnac_p2_proof_t proof;
    int ok = 1;

    if (nm > T_MAXM) return 0;
    memset(F, 0, sizeof(*F));
    F->nm = nm;
    F->salt = cfg->salt_elems;
    F->max_h = maxh_of(cfg);
    F->depth = ilog2(F->max_h);
    F->index = index;

    for (size_t m = 0; m < nm; m++) {
        F->semw[m] = cfg->widths[m];
        F->physw[m] = cfg->widths[m] + cfg->salt_elems;
        F->heights[m] = cfg->heights[m];
        if (F->physw[m] > T_MAXPHYS) return 0;
    }

    for (size_t m = 0; m < nm && ok; m++) {
        mats[m] = (uint64_t *)malloc(F->heights[m] * F->physw[m] * sizeof(uint64_t));
        if (!mats[m]) { ok = 0; break; }
        for (size_t r = 0; r < F->heights[m]; r++)
            for (size_t c = 0; c < F->physw[m]; c++)
                mats[m][r * F->physw[m] + c] = cell(m, r, c);
        cmats[m] = mats[m];
    }

    if (ok && dnac_p2_mmcs_commit_mixed(cmats, F->physw, F->heights, nm, &F->root,
                                        &tree) != DNAC_P2M_OK)
        ok = 0;

    if (ok) {
        memset(&proof, 0, sizeof(proof));
        proof.siblings = F->sibs;
        if (dnac_p2_mmcs_open_mixed(tree, index, orows, &proof) != DNAC_P2M_OK)
            ok = 0;
    }
    /* The native ACCEPT is the anchor. */
    if (ok && dnac_p2_mmcs_verify_mixed(&F->root, orows, F->physw, F->heights, nm,
                                        index, &proof) != DNAC_P2M_OK)
        ok = 0;
    if (ok && (size_t)proof.depth != F->depth) ok = 0;

    if (ok)
        for (size_t m = 0; m < nm; m++)
            memcpy(F->rows[m], orows[m], F->physw[m] * sizeof(uint64_t));

    dnac_p2_mmcs_tree_free(tree);
    for (size_t m = 0; m < nm; m++) free(mats[m]);
    return ok;
}

/* ══════════════════════════ honest trace builder ═════════════════════════
 * TEST-SIDE by design (slice ships no prover). Replays dnac_p2_mmcs_verify_mixed
 * and fills leaf / compress / inject / final / pad rows. */
typedef struct {
    const dnac_p2c_mmix_table_cfg_t *cfg;
    size_t    rows, npub;
    uint64_t *trace; /* rows * MMIX_WIDTH               */
    uint64_t *prep;  /* rows * DNAC_P2C_MMIX_TABLE_COLS */
    uint64_t *pub;   /* npub                           */
} built_t;

static void built_free(built_t *B) {
    free(B->trace); free(B->prep); free(B->pub);
    memset(B, 0, sizeof(*B));
}
static uint64_t *row_of(uint64_t *t, size_t r) { return t + r * MMIX_WIDTH; }

/* Concatenate the PHYSICAL opened rows (data ‖ salt) of every matrix at height
 * `gh`, matrix order — matches p2m_group_row_concat (poseidon2_mmcs.c:296-310). */
static size_t group_concat(const fixt_t *F, size_t gh, uint64_t *out) {
    size_t off = 0;
    for (size_t m = 0; m < F->nm; m++)
        if (F->heights[m] == gh) {
            memcpy(out + off, F->rows[m], F->physw[m] * sizeof(uint64_t));
            off += F->physw[m];
        }
    return off;
}

/* PaddingFreeSponge over `concat`, one row per permutation; if `is_inject` set
 * RDIG = `running` on each row. Returns the squeezed digest. */
static void sponge_over(uint64_t *trace, size_t *rp, const uint64_t *concat,
                        size_t clen, int is_inject, const uint64_t *running,
                        uint64_t digest_out[MMIX_DIGEST_LANES]) {
    uint64_t state[MMIX_PERM_WIDTH];
    memset(state, 0, sizeof(state));
    const size_t lg =
        (clen % MMIX_RATE == 0) ? clen / MMIX_RATE : clen / MMIX_RATE + 1;
    for (size_t blk = 0; blk < lg; blk++) {
        const size_t k =
            (blk + 1 < lg) ? (size_t)MMIX_RATE : clen - (size_t)MMIX_RATE * (lg - 1);
        for (size_t j = 0; j < k; j++) state[j] = concat[(size_t)MMIX_RATE * blk + j];
        uint64_t *row = row_of(trace, *rp);
        poseidon2_air_generate_row(state, row + MMIX_PERM_OFF);
        if (is_inject)
            for (size_t j = 0; j < (size_t)MMIX_DIGEST_LANES; j++)
                row[mmix_rdig_off(j)] = running[j];
        for (size_t j = 0; j < (size_t)MMIX_PERM_WIDTH; j++)
            state[j] = row[mmix_perm_out_off(j)];
        (*rp)++;
    }
    for (size_t j = 0; j < (size_t)MMIX_DIGEST_LANES; j++) digest_out[j] = state[j];
}

static void emit_compress(uint64_t *trace, size_t *rp,
                          const uint64_t digest[MMIX_DIGEST_LANES],
                          const uint64_t sib[MMIX_DIGEST_LANES], int bit,
                          uint64_t out4[MMIX_DIGEST_LANES]) {
    uint64_t pre[MMIX_PERM_WIDTH];
    if (bit == 0) {
        memcpy(pre, digest, MMIX_DIGEST_LANES * sizeof(uint64_t));
        memcpy(pre + MMIX_DIGEST_LANES, sib, MMIX_DIGEST_LANES * sizeof(uint64_t));
    } else {
        memcpy(pre, sib, MMIX_DIGEST_LANES * sizeof(uint64_t));
        memcpy(pre + MMIX_DIGEST_LANES, digest, MMIX_DIGEST_LANES * sizeof(uint64_t));
    }
    uint64_t *row = row_of(trace, *rp);
    poseidon2_air_generate_row(pre, row + MMIX_PERM_OFF);
    row[MMIX_DIR_OFF] = (uint64_t)bit;
    for (size_t j = 0; j < (size_t)MMIX_DIGEST_LANES; j++)
        out4[j] = row[mmix_perm_out_off(j)];
    (*rp)++;
}

static void emit_inject_compress(uint64_t *trace, size_t *rp,
                                 const uint64_t running[MMIX_DIGEST_LANES],
                                 const uint64_t rows_digest[MMIX_DIGEST_LANES],
                                 uint64_t out4[MMIX_DIGEST_LANES]) {
    uint64_t pre[MMIX_PERM_WIDTH];
    memcpy(pre, running, MMIX_DIGEST_LANES * sizeof(uint64_t));
    memcpy(pre + MMIX_DIGEST_LANES, rows_digest, MMIX_DIGEST_LANES * sizeof(uint64_t));
    uint64_t *row = row_of(trace, *rp);
    poseidon2_air_generate_row(pre, row + MMIX_PERM_OFF);
    for (size_t j = 0; j < (size_t)MMIX_DIGEST_LANES; j++)
        row[mmix_rdig_off(j)] = running[j];
    for (size_t j = 0; j < (size_t)MMIX_DIGEST_LANES; j++)
        out4[j] = row[mmix_perm_out_off(j)];
    (*rp)++;
}

static void emit_final(uint64_t *trace, size_t *rp,
                       const uint64_t digest[MMIX_DIGEST_LANES]) {
    uint64_t pre[MMIX_PERM_WIDTH];
    memset(pre, 0, sizeof(pre));
    memcpy(pre, digest, MMIX_DIGEST_LANES * sizeof(uint64_t));
    poseidon2_air_generate_row(pre, row_of(trace, *rp) + MMIX_PERM_OFF);
    (*rp)++;
}

/* Regenerate the embedded block from whatever preimage its input cols hold — so
 * a control tamper isolates the CONTROL pin, not the poseidon2 block's own
 * constraints (the test_mmcs_air.c:175-180 idiom). */
static void regen_perm(uint64_t *row) {
    uint64_t pre[MMIX_PERM_WIDTH];
    for (size_t i = 0; i < (size_t)MMIX_PERM_WIDTH; i++)
        pre[i] = row[mmix_perm_in_off(i)];
    poseidon2_air_generate_row(pre, row + MMIX_PERM_OFF);
}

/* Build the honest AIR trace for one opening. `sibs`/`claimed_root` are
 * parameters (not read from F) so a negative can rebuild the chain honestly
 * around ONE tampered sibling while the public root stays true. Returns 0 if the
 * replay disagrees with the native primitives. */
static int build_trace(built_t *B, const dnac_p2c_mmix_table_cfg_t *cfg,
                       const fixt_t *F, const dnac_p2_digest_t *sibs,
                       const uint64_t claimed_root[MMIX_DIGEST_LANES]) {
    memset(B, 0, sizeof(*B));
    B->cfg = cfg;
    B->rows = dnac_p2c_mmix_table_rows(cfg);
    B->npub = dnac_mmix_air_num_publics(cfg);
    if (B->rows == 0 || B->npub == 0 || B->rows > T_MAXROWS) return 0;

    B->trace = (uint64_t *)calloc(B->rows * MMIX_WIDTH, sizeof(uint64_t));
    B->prep = (uint64_t *)calloc(B->rows * DNAC_P2C_MMIX_TABLE_COLS, sizeof(uint64_t));
    B->pub = (uint64_t *)calloc(B->npub, sizeof(uint64_t));
    if (!B->trace || !B->prep || !B->pub) { built_free(B); return 0; }

    if (dnac_p2c_mmix_table_generate(cfg, B->prep,
                                     B->rows * (size_t)DNAC_P2C_MMIX_TABLE_COLS) !=
        DNAC_P2C_MMIX_TABLE_OK) {
        built_free(B); return 0;
    }

    const size_t max_h = F->max_h;
    const size_t depth = F->depth;
    size_t r = 0;
    uint64_t digest[MMIX_DIGEST_LANES];
    uint64_t concat[T_MAXCONCAT];

    /* tallest-group leaf */
    size_t clen = group_concat(F, max_h, concat);
    sponge_over(B->trace, &r, concat, clen, 0, NULL, digest);
    {   uint64_t want[MMIX_DIGEST_LANES];
        dnac_p2_mmcs_hash_iter(concat, clen, want);
        if (memcmp(want, digest, sizeof(want)) != 0) { built_free(B); return 0; }
    }

    /* walk */
    for (size_t l = 0; l < depth; l++) {
        const uint64_t bit = (F->index >> l) & 1u;
        uint64_t nd[MMIX_DIGEST_LANES];
        emit_compress(B->trace, &r, digest, sibs[l].lanes, (int)bit, nd);
        {   uint64_t want[MMIX_DIGEST_LANES];
            if (bit == 0) dnac_p2_mmcs_compress(digest, sibs[l].lanes, want);
            else          dnac_p2_mmcs_compress(sibs[l].lanes, digest, want);
            if (memcmp(want, nd, sizeof(want)) != 0) { built_free(B); return 0; }
        }
        memcpy(digest, nd, sizeof(nd));

        const size_t cur = max_h >> (l + 1);
        if (present(cfg, cur)) {
            uint64_t running[MMIX_DIGEST_LANES];
            memcpy(running, digest, sizeof(running));
            uint64_t rows_digest[MMIX_DIGEST_LANES];
            const size_t gl = group_concat(F, cur, concat);
            sponge_over(B->trace, &r, concat, gl, 1, running, rows_digest);
            {   uint64_t want[MMIX_DIGEST_LANES];
                dnac_p2_mmcs_hash_iter(concat, gl, want);
                if (memcmp(want, rows_digest, sizeof(want)) != 0) {
                    built_free(B); return 0;
                }
            }
            uint64_t nd2[MMIX_DIGEST_LANES];
            emit_inject_compress(B->trace, &r, running, rows_digest, nd2);
            {   uint64_t want[MMIX_DIGEST_LANES];
                dnac_p2_mmcs_compress(running, rows_digest, want); /* running FIRST */
                if (memcmp(want, nd2, sizeof(want)) != 0) { built_free(B); return 0; }
            }
            memcpy(digest, nd2, sizeof(nd2));
        }
    }

    /* final digest must be the committed root (the native accepted it). */
    if (memcmp(digest, F->root.lanes, sizeof(digest)) != 0) { built_free(B); return 0; }
    emit_final(B->trace, &r, digest);

    /* padding rows: inert, but still a VALID dummy permutation (block ungated). */
    {   uint64_t z[MMIX_PERM_WIDTH];
        memset(z, 0, sizeof(z));
        while (r < B->rows) {
            poseidon2_air_generate_row(z, row_of(B->trace, r) + MMIX_PERM_OFF);
            r++;
        }
    }

    /* publics: [root 4][dir bits LSB-first][opened DATA rows per matrix]. */
    for (size_t j = 0; j < (size_t)MMIX_DIGEST_LANES; j++)
        B->pub[MMIX_PUB_ROOT_OFF + j] = claimed_root[j];
    for (size_t l = 0; l < depth; l++)
        B->pub[MMIX_PUB_DIR_OFF + l] = (F->index >> l) & 1u;
    {   const size_t oo = dnac_mmix_air_pub_opened_off(cfg);
        size_t off = 0;
        for (size_t m = 0; m < F->nm; m++) {
            for (size_t d = 0; d < F->semw[m]; d++)
                B->pub[oo + off + d] = F->rows[m][d]; /* data lanes only */
            off += F->semw[m];
        }
    }
    return 1;
}

/* ═════════════════════════════ helpers/reporting ═════════════════════════ */
static int eval_built(const built_t *B) {
    return dnac_mmix_air_eval_trace(B->trace, B->prep, B->rows, B->cfg, B->pub,
                                    B->npub);
}
static uint64_t *clone_u64(const uint64_t *src, size_t n) {
    uint64_t *t = (uint64_t *)malloc(n * sizeof(uint64_t));
    if (t) memcpy(t, src, n * sizeof(uint64_t));
    return t;
}
static uint64_t *clone_trace(const built_t *B) {
    return clone_u64(B->trace, B->rows * MMIX_WIDTH);
}
static uint64_t *clone_prep(const built_t *B) {
    return clone_u64(B->prep, B->rows * (size_t)DNAC_P2C_MMIX_TABLE_COLS);
}
static uint64_t *clone_pub(const built_t *B) { return clone_u64(B->pub, B->npub); }
static uint64_t bump(uint64_t x) {
    return gold_fp_to_u64(gold_fp_add(gold_fp_from_u64(x), gold_fp_one()));
}

static void expect_reject(const char *name, const uint64_t *trace,
                          const uint64_t *prep, size_t rows,
                          const dnac_p2c_mmix_table_cfg_t *cfg,
                          const uint64_t *pub, size_t npub, int want_exact) {
    const int v = dnac_mmix_air_eval_trace(trace, prep, rows, cfg, pub, npub);
    if (v < 1) {
        printf("  [reject] %-54s NOT caught — FAIL\n", name); fails++; return;
    }
    if (want_exact > 0 && v != want_exact) {
        printf("  [reject] %-54s caught but %d viol (want %d) — FAIL\n", name, v,
               want_exact); fails++; return;
    }
    printf("  [reject] %-54s caught (%d viol) — OK\n", name, v);
}
static void expect_bad(const char *name, int v) {
    if (v == MMIX_VIOL_BAD_CONFIG)
        printf("  [reject] %-54s fails closed — OK\n", name);
    else { printf("  [reject] %-54s returned %d — FAIL\n", name, v); fails++; }
}

/* Accept one (cfg, index); optionally keep the built trace/fixture. */
static int accept_case(const dnac_p2c_mmix_table_cfg_t *cfg, uint64_t index,
                       const char *label, built_t *keep, fixt_t *keepF) {
    fixt_t *F = (fixt_t *)calloc(1, sizeof(fixt_t));
    built_t B;
    int ok = 1;
    if (!F) return 0;
    if (!make_fixt(cfg, index, F)) {
        printf("  [accept] %-22s native commit/open/verify      FAIL\n", label);
        fails++; free(F); return 0;
    }
    if (!build_trace(&B, cfg, F, F->sibs, F->root.lanes)) {
        printf("  [accept] %-22s honest trace build             FAIL\n", label);
        fails++; free(F); return 0;
    }
    const int v = eval_built(&B);
    if (v != 0) {
        printf("  [accept] %-22s %2zu rows  %d viol — FAIL\n", label, B.rows, v);
        fails++; ok = 0;
    } else {
        printf("  [accept] %-22s idx %2" PRIu64 "  %2zu rows  0 viol — OK\n",
               label, index, B.rows);
    }
    if (keep && ok) { *keep = B; if (keepF) *keepF = *F; }
    else built_free(&B);
    free(F);
    return ok;
}

/* ═════════════════════════════════ configs ═══════════════════════════════ */
static const size_t REF_W[2] = {1, 1};
static const size_t REF_H[2] = {8, 2};
static const dnac_p2c_mmix_table_cfg_t CFG_REF = {2, REF_W, REF_H, 3, 2};

static const size_t WIDE_W[3] = {1, 1, 1};
static const size_t WIDE_H[3] = {16, 4, 2};
static const dnac_p2c_mmix_table_cfg_t CFG_WIDE = {3, WIDE_W, WIDE_H, 4, 2};

static const size_t MG_W[3] = {2, 2, 2};
static const size_t MG_H[3] = {8, 8, 2};
static const dnac_p2c_mmix_table_cfg_t CFG_MG = {3, MG_W, MG_H, 3, 2};

/* INJ2 — a WIDE inject group: h2 matrix width 6 + salt 2 => concat 8 => TWO
 * inject-leaf rows. Exercises the RDIG carry ACROSS multiple inject-leaf rows
 * (block K) and the inject-leaf within-group state threading (block L on
 * is_inject_leaf), which the 1-inject-leaf configs above never reach. */
static const size_t INJ2_W[2] = {1, 6};
static const size_t INJ2_H[2] = {8, 2};
static const dnac_p2c_mmix_table_cfg_t CFG_INJ2 = {2, INJ2_W, INJ2_H, 3, 2};

/* Locate the inject-compress row at Merkle level `l` in the prep table (its
 * is_inject_compress cell set + its lvl one-hot at `l`). SIZE_MAX if none. */
static size_t find_inject_compress_row(const built_t *B, size_t l) {
    for (size_t r = 0; r < B->rows; r++) {
        const uint64_t *row = B->prep + r * (size_t)DNAC_P2C_MMIX_TABLE_COLS;
        if (row[DNAC_P2C_MMIX_COL_IS_INJECT_COMPRESS] == 1 &&
            row[dnac_p2c_mmix_col_lvl(l)] == 1)
            return r;
    }
    return (size_t)-1;
}
static size_t find_compress_row(const built_t *B, size_t l) {
    for (size_t r = 0; r < B->rows; r++) {
        const uint64_t *row = B->prep + r * (size_t)DNAC_P2C_MMIX_TABLE_COLS;
        if (row[DNAC_P2C_MMIX_COL_IS_COMPRESS] == 1 &&
            row[dnac_p2c_mmix_col_lvl(l)] == 1)
            return r;
    }
    return (size_t)-1;
}

/* ═════════════════════════════════ main ══════════════════════════════════ */
int main(void) {
    printf("============================================================\n");
    printf("P2b slice 2 — mixed-height MMCS-verify control-AIR  WIDTH=%zu "
           "(%zu control + %d perm)\n",
           (size_t)MMIX_WIDTH, (size_t)MMIX_PERM_OFF, P2AIR_NUM_COLS);
    printf("============================================================\n");

    /* ── Gate 0: layout binding contract ── */
    if (dnac_mmix_air_layout_check())
        printf("  [accept] column-layout binding contract                       OK\n");
    else { printf("  [accept] column-layout binding contract                       FAIL\n"); fails++; }

    /* ── Gate 0b: helpers agree with the pinned reference + table module ── */
    {
        const dnac_p2c_mmix_table_cfg_t *R = dnac_p2c_mmix_ref_cfg();
        const size_t npub = dnac_mmix_air_num_publics(R);
        const size_t oo = dnac_mmix_air_pub_opened_off(R);
        const size_t topen = dnac_mmix_air_total_opened(R);
        const int good = (topen == (size_t)(REF_W[0] + REF_W[1])) &&
                         (oo == (size_t)MMIX_DIGEST_LANES + CFG_REF.depth) &&
                         (npub == oo + topen) &&
                         (dnac_p2c_mmix_table_rows(R) == DNAC_P2C_MMIX_REF_ROWS);
        if (good)
            printf("  [accept] reference publics: opened %zu, off %zu, npub %zu     OK\n",
                   topen, oo, npub);
        else { printf("  [accept] reference publics/helpers                            FAIL\n"); fails++; }
    }

    /* ── Gate 0c: eval-entry config fail-close ── */
    {
        uint64_t dmain[MMIX_WIDTH];
        uint64_t dprep[DNAC_P2C_MMIX_TABLE_COLS];
        uint64_t dpub[T_MAXPUB];
        memset(dmain, 0, sizeof(dmain));
        memset(dprep, 0, sizeof(dprep));
        memset(dpub, 0, sizeof(dpub));

        expect_bad("NULL config",
                   dnac_mmix_air_eval_row(dmain, NULL, dprep, NULL, 0, NULL,
                                          dpub, 1));
        { /* depth != log2(max_h): heights {8,2} but depth 2 */
            static const size_t w[2] = {1, 1};
            static const size_t h[2] = {8, 2};
            const dnac_p2c_mmix_table_cfg_t bad = {2, w, h, 2, 2};
            expect_bad("depth != log2(max_h)",
                       dnac_mmix_air_eval_row(dmain, NULL, dprep, NULL, 0, &bad,
                                              dpub, T_MAXPUB));
        }
        { /* non-power-of-two height */
            static const size_t w[2] = {1, 1};
            static const size_t h[2] = {8, 3};
            const dnac_p2c_mmix_table_cfg_t bad = {2, w, h, 3, 2};
            expect_bad("non-pow2 height",
                       dnac_mmix_air_eval_row(dmain, NULL, dprep, NULL, 0, &bad,
                                              dpub, T_MAXPUB));
        }
        { /* zero width */
            static const size_t w[2] = {0, 1};
            static const size_t h[2] = {8, 2};
            const dnac_p2c_mmix_table_cfg_t bad = {2, w, h, 3, 2};
            expect_bad("width == 0",
                       dnac_mmix_air_eval_row(dmain, NULL, dprep, NULL, 0, &bad,
                                              dpub, T_MAXPUB));
        }
        /* wrong public count */
        expect_bad("num_publics != required",
                   dnac_mmix_air_eval_row(dmain, NULL, dprep, NULL, 0, &CFG_REF,
                                          dpub, 1));
        /* main_next without prep_next == PIN-2 shape */
        expect_bad("main_next without prep_next (PIN-2 shape)",
                   dnac_mmix_air_eval_row(dmain, dmain, dprep, NULL, 0, &CFG_REF,
                                          dpub, dnac_mmix_air_num_publics(&CFG_REF)));
    }

    /* ══ PHASE 1 — POSITIVE: native replay ══ */
    printf("------------------------------------------------------------\n");
    printf("Phase 1 — honest traces (native commit/open/verify_mixed replay)\n");
    printf("------------------------------------------------------------\n");

    built_t W;   /* workhorse (CFG_WIDE) kept for negatives */
    memset(&W, 0, sizeof(W));

    accept_case(&CFG_REF, 3, "REF  {8,2}   d3", NULL, NULL);
    if (!accept_case(&CFG_WIDE, 3, "WIDE {16,4,2} d4", &W, NULL)) return 1;
    accept_case(&CFG_WIDE, 11, "WIDE {16,4,2} d4", NULL, NULL);
    accept_case(&CFG_MG, 5, "MG   {8,8,2} d3", NULL, NULL);
    accept_case(&CFG_INJ2, 5, "INJ2 {8,2}w{1,6} d3", NULL, NULL);

    /* ══ PHASE 2 — NEGATIVE ══
     * Workhorse W = CFG_WIDE idx 3. Schedule:
     *   0 leaf(h16) | 1 comp l0 | 2 comp l1(inj) | 3 inj-leaf(h4) | 4 inj-comp |
     *   5 comp l2(inj) | 6 inj-leaf(h2) | 7 inj-comp | 8 comp l3 | 9 final | 10..15 pad
     */
    printf("------------------------------------------------------------\n");
    printf("Phase 2 — constraint-form negatives (WIDE, two inject blocks)\n");
    printf("------------------------------------------------------------\n");

    const size_t ic1 = find_inject_compress_row(&W, 1); /* row 4 */
    const size_t ic2 = find_inject_compress_row(&W, 2); /* row 7 */
    const size_t comp2 = find_compress_row(&W, 2);      /* row 5 */
    if (ic1 == (size_t)-1 || ic2 == (size_t)-1 || comp2 == (size_t)-1) {
        printf("  [reject] inject-block row lookup                              FAIL\n");
        fails++;
    }

    /* N-order — THE POINT OF THE SLICE: inject-compress with SWAPPED combine
     * order C(rows_digest, running). Swap the inject-compress preimage halves
     * and regen: LEFT (block F, == RDIG) and RIGHT (block I, == prev output)
     * both reject. */
    {
        uint64_t *t = clone_trace(&W);
        uint64_t *row = row_of(t, ic1);
        for (size_t j = 0; j < (size_t)MMIX_DIGEST_LANES; j++) {
            const uint64_t tmp = row[mmix_perm_in_off(j)];
            row[mmix_perm_in_off(j)] = row[mmix_perm_in_off(MMIX_DIGEST_LANES + j)];
            row[mmix_perm_in_off(MMIX_DIGEST_LANES + j)] = tmp;
        }
        regen_perm(row);
        expect_reject("N-order inject-compress halves swapped (running<->rows)", t,
                      W.prep, W.rows, W.cfg, W.pub, W.npub, 0);
        free(t);
    }
    /* N-level — injection claimed at the WRONG level: relocate has_inject from
     * the true injecting compress (level 1, row 2) up to level 0's compress
     * (row 1) in the PREP. Block J (RDIG seed) then fires at row 1, forcing
     * RDIG(row 2) = out(row 1) which the honest trace does not satisfy. */
    {
        uint64_t *p = clone_prep(&W);
        p[find_compress_row(&W, 1) * DNAC_P2C_MMIX_TABLE_COLS +
          DNAC_P2C_MMIX_COL_HAS_INJECT] = 0;
        p[find_compress_row(&W, 0) * DNAC_P2C_MMIX_TABLE_COLS +
          DNAC_P2C_MMIX_COL_HAS_INJECT] = 1;
        expect_reject("N-level has_inject relocated to the wrong level", W.trace, p,
                      W.rows, W.cfg, W.pub, W.npub, 0);
        free(p);
    }
    /* N-index — a direction public bit in an inject group's REDUCED-INDEX SUFFIX
     * flipped, walk kept honest. Group h4 injects at level 1; its reduced index
     * is index>>2 = bits [2,3]. Flip public dir bit 2: block D at the level-2
     * compress (row 5, its dir col unchanged) rejects. */
    {
        uint64_t *p = clone_pub(&W);
        p[MMIX_PUB_DIR_OFF + 2] ^= 1u;
        expect_reject("N-index suffix dir public flipped (reduced-index bind)",
                      W.trace, W.prep, W.rows, W.cfg, p, W.npub, 0);
        free(p);
    }
    /* N-leaf — tamper the tallest group's absorbed DATA lane (leaf preimage) and
     * regen: the absorbed lane no longer equals its public opened element. */
    {
        uint64_t *t = clone_trace(&W);
        uint64_t *row = row_of(t, 0); /* first tallest-leaf row */
        row[mmix_perm_in_off(0)] = bump(row[mmix_perm_in_off(0)]);
        regen_perm(row);
        expect_reject("N-leaf tampered tallest-group data lane", t, W.prep, W.rows,
                      W.cfg, W.pub, W.npub, 0);
        free(t);
    }
    /* N-bit — non-boolean dir on a compress row. */
    {
        uint64_t *t = clone_trace(&W);
        row_of(t, find_compress_row(&W, 0))[MMIX_DIR_OFF] = 2;
        expect_reject("N-bit non-boolean dir", t, W.prep, W.rows, W.cfg, W.pub,
                      W.npub, 0);
        free(t);
    }
    /* N-bit2 — flip a compress dir COLUMN (not its public): block D (dir == pub)
     * rejects. Level-0 compress (row 1). */
    {
        uint64_t *t = clone_trace(&W);
        uint64_t *row = row_of(t, find_compress_row(&W, 0));
        row[MMIX_DIR_OFF] ^= 1u;
        regen_perm(row); /* keep the perm valid; only the control bit is wrong */
        expect_reject("N-bit2 dir column != its public bit", t, W.prep, W.rows,
                      W.cfg, W.pub, W.npub, 0);
        free(t);
    }
    /* N-root — wrong public root lane. Isolated: only the final row's root pin
     * reads it, one lane differs => exactly 1 violation. */
    {
        uint64_t *p = clone_pub(&W);
        p[MMIX_PUB_ROOT_OFF + 2] = bump(p[MMIX_PUB_ROOT_OFF + 2]);
        expect_reject("N-root wrong public root lane", W.trace, W.prep, W.rows,
                      W.cfg, p, W.npub, 1);
        free(p);
    }
    /* N-salt — tamper a SALT lane in the tallest leaf preimage and regen ONLY
     * that row (root public stays true). Salt is free witness, but the leaf
     * digest changes => the running-digest placement into the level-0 compress
     * no longer matches => caught downstream. */
    {
        uint64_t *t = clone_trace(&W);
        uint64_t *row = row_of(t, 0);
        /* tallest group h16 mat0: physical row = [data(1) ‖ salt(2)]; lane 1 is
         * the first salt element. */
        row[mmix_perm_in_off(1)] = bump(row[mmix_perm_in_off(1)]);
        regen_perm(row);
        expect_reject("N-salt tampered salt lane (leaf digest diverges)", t,
                      W.prep, W.rows, W.cfg, W.pub, W.npub, 0);
        free(t);
    }
    /* N-rdig — break the RDIG carry: bump an inject-leaf's RDIG lane. Block K
     * (carry) / block F (LEFT read) reject. */
    {
        uint64_t *t = clone_trace(&W);
        uint64_t *row = row_of(t, ic1 - 1); /* the inject-leaf feeding ic1 (row 3) */
        row[mmix_rdig_off(0)] = bump(row[mmix_rdig_off(0)]);
        expect_reject("N-rdig broken running-digest carry", t, W.prep, W.rows,
                      W.cfg, W.pub, W.npub, 0);
        free(t);
    }
    /* N-left — tamper the inject-compress LEFT input (block F: LEFT == RDIG). */
    {
        uint64_t *t = clone_trace(&W);
        uint64_t *row = row_of(t, ic1);
        row[mmix_perm_in_off(0)] = bump(row[mmix_perm_in_off(0)]);
        regen_perm(row);
        expect_reject("N-left inject-compress LEFT != carried digest", t, W.prep,
                      W.rows, W.cfg, W.pub, W.npub, 0);
        free(t);
    }
    /* N-zerostart — a capacity lane of the first tallest-leaf row is non-zero
     * (poseidon2_mmcs.c:49-50 zero start). */
    {
        uint64_t *t = clone_trace(&W);
        uint64_t *row = row_of(t, 0);
        row[mmix_perm_in_off(MMIX_PERM_WIDTH - 1)] = 1;
        regen_perm(row);
        expect_reject("N-zerostart leaf capacity lane nonzero", t, W.prep, W.rows,
                      W.cfg, W.pub, W.npub, 0);
        free(t);
    }
    /* N-perm — an INTERIOR cell of the embedded poseidon2 block (evaluated
     * ungated on every row; carries "every combination is a real permutation"). */
    {
        uint64_t *t = clone_trace(&W);
        const size_t off = MMIX_PERM_OFF + p2air_beg_sbox_off(0, 0);
        uint64_t *row = row_of(t, find_compress_row(&W, 0));
        row[off] = bump(row[off]);
        expect_reject("N-perm poseidon2 block interior cell tamper", t, W.prep,
                      W.rows, W.cfg, W.pub, W.npub, 0);
        free(t);
    }
    /* N-dirpad — dir non-zero on a NON-compress row (block B: (1-is_compress)·dir).
     * Put it on the tallest-leaf row 0. Isolated => exactly 1 violation. */
    {
        uint64_t *t = clone_trace(&W);
        row_of(t, 0)[MMIX_DIR_OFF] = 1;
        expect_reject("N-dirpad dir set on a leaf row", t, W.prep, W.rows, W.cfg,
                      W.pub, W.npub, 1);
        free(t);
    }
    /* N-final — garbage the last combination (its free sibling half) while the
     * TRUE root sits in the final row: block H (final threading) rejects. The
     * last level (l3) has no inject, so the predecessor of the final is the
     * level-3 compress (row 8); tamper its running-digest side and regen. */
    {
        uint64_t *t = clone_trace(&W);
        const size_t rc = find_compress_row(&W, W.cfg->depth - 1); /* row 8 */
        uint64_t *row = row_of(t, rc);
        /* level-3 bit of index 3 == 0 => running is LEFT, sibling is RIGHT; bump
         * a RIGHT (sibling) lane so the compress OUTPUT changes but placement
         * (running side) stays honest — only the threaded output into final is
         * wrong. */
        row[mmix_perm_in_off(MMIX_DIGEST_LANES)] =
            bump(row[mmix_perm_in_off(MMIX_DIGEST_LANES)]);
        regen_perm(row);
        expect_reject("N-final garbaged last compress, true root in final row", t,
                      W.prep, W.rows, W.cfg, W.pub, W.npub, 0);
        free(t);
    }
    /* N-thread — leaf state carry broken in a MULTI-BLOCK tallest group (MG):
     * a capacity lane of the SECOND tallest-leaf row is not the first's output. */
    {
        fixt_t *F = (fixt_t *)calloc(1, sizeof(fixt_t));
        built_t X;
        if (F && make_fixt(&CFG_MG, 5, F) &&
            build_trace(&X, &CFG_MG, F, F->sibs, F->root.lanes)) {
            uint64_t *row = row_of(X.trace, 1); /* 2nd tallest-leaf row */
            row[mmix_perm_in_off(MMIX_PERM_WIDTH - 1)] =
                bump(row[mmix_perm_in_off(MMIX_PERM_WIDTH - 1)]);
            regen_perm(row);
            expect_reject("N-thread multi-block leaf capacity not carried (MG)",
                          X.trace, X.prep, X.rows, X.cfg, X.pub, X.npub, 0);
            built_free(&X);
        } else {
            printf("  [reject] N-thread fixture/build                             FAIL\n");
            fails++;
        }
        free(F);
    }
    /* N-sched — n_rows one short of the pinned schedule: fail-close. */
    expect_bad("N-sched n_rows != table_rows",
               dnac_mmix_air_eval_trace(W.trace, W.prep, W.rows - 1, W.cfg, W.pub,
                                        W.npub));
    /* N-term — the last row is turned into a valid-looking FINAL row (typed) so
     * the trace no longer ends in padding: terminality fails closed. */
    {
        uint64_t *p = clone_prep(&W);
        const size_t last = W.rows - 1;
        p[last * DNAC_P2C_MMIX_TABLE_COLS + DNAC_P2C_MMIX_COL_IS_PAD] = 0;
        p[last * DNAC_P2C_MMIX_TABLE_COLS + DNAC_P2C_MMIX_COL_IS_FINAL] = 1;
        expect_bad("N-term last row not padding",
                   dnac_mmix_air_eval_trace(W.trace, p, W.rows, W.cfg, W.pub,
                                            W.npub));
        free(p);
    }
    /* N-canon — non-canonical public (p+1 aliases 1) fails closed (OBL-2). */
    {
        uint64_t *p = clone_pub(&W);
        p[MMIX_PUB_DIR_OFF + 0] = GOLDILOCKS_P + 1u;
        expect_bad("N-canon non-canonical public (p+1)",
                   dnac_mmix_air_eval_trace(W.trace, W.prep, W.rows, W.cfg, p,
                                            W.npub));
        free(p);
    }
    /* N-allzero — the PIN-1-MMIX vacuity shape: an ALL-ZERO preprocessed table.
     * With pos/type all zero, every pos-gated form is inert AND terminality
     * fails closed (last row is not is_pad==1). Reported truthfully: this does
     * NOT replace PIN-1 (a differently-shaped well-formed table is only excluded
     * by pinning the root). */
    {
        uint64_t *p = clone_prep(&W);
        memset(p, 0, W.rows * (size_t)DNAC_P2C_MMIX_TABLE_COLS * sizeof(uint64_t));
        const int v = dnac_mmix_air_eval_trace(W.trace, p, W.rows, W.cfg, W.pub,
                                               W.npub);
        if (v != 0)
            printf("  [reject] %-54s caught (%d) — OK\n",
                   "N-allzero all-zero preprocessed (PIN-1 shape)", v);
        else {
            printf("  [reject] %-54s NOT caught — FAIL\n",
                   "N-allzero all-zero preprocessed (PIN-1 shape)");
            fails++;
        }
        free(p);
    }

    built_free(&W);

    printf("------------------------------------------------------------\n");
    if (fails) { printf("P2b MIXED MMCS AIR: %d FAIL\n", fails); return 1; }
    printf("P2b MIXED MMCS AIR: 5 honest openings accepted (REF + WIDE x2 +\n"
           "  MG multi-matrix tallest group + INJ2 multi-row inject group,\n"
           "  native chain cross-checked) +\n"
           "  6 fail-close eval-entry gates + 19 constraint-form negatives\n"
           "  (N-order the load-bearing combine-order catch; 4 fail-close in\n"
           "  mechanism: N-sched / N-term / N-canon / N-allzero) — PASS\n");
    return 0;
}
