/**
 * @file logup.h
 * @brief LogUp lookup-argument gadget — port of Plonky3 p3-lookup LogUpGadget.
 *
 * Plonky3 commit pin: 82cfad73cd734d37a0d51953094f970c531817ec.
 *
 * P2L-a scope (P2-lookup design 2026-07-23 §4, v3 GREEN): the pure gadget —
 *   - β-combine of tuple elements (lookup/src/logup.rs:72-96),
 *   - numerator / common-denominator via prefix/suffix products, ONE
 *     ext-field inversion per (row, lookup) in trace generation
 *     (logup.rs:98-146, 427-536),
 *   - per-row transition + boundary (s[0] = 0) constraint residuals
 *     (logup.rs:158-265),
 *   - aux-trace generation `generate_permutation` (logup.rs:370-646),
 *   - `verify_global_sum` (logup.rs:314-324) and `constraint_degree`
 *     (logup.rs:339-367).
 * NOT in scope here: interaction/bus builder (P2L-b), batch-stark proof
 * shape/priming (P2L-c), prover/verifier/wire integration (P2L-d).
 *
 * Field choice (per DNAC v3 ZK design): Val = Goldilocks (gold_fp_t),
 * Challenge = Goldilocks² (gold_fp2_t). The two lookup challenges (α, β)
 * live in the EXTENSION field (G-SEC-L1; logup.rs:207-209 ExprEF).
 *
 * Determinism (G-DET-L1): the reference generates the aux trace with
 * chunked-parallel batch inversion (logup.rs:449, CHUNK_SIZE=1024) and a
 * three-phase parallel prefix sum (logup.rs:581-620). Field inverses are
 * unique values and field addition is exact/associative, so this SERIAL port
 * is byte-identical to the reference output. Plonky3's batch inversion
 * PANICS on a zero input (field/src/batch_inverse.rs:26); this port mirrors
 * that as the fail-close error DNAC_LOGUP_ERR_ZERO_DENOM.
 *
 * Next-row convention (PINNED, oracle-matched): next = (row + 1) % height —
 * the WRAP convention generate_permutation itself uses (logup.rs:474) and
 * the cyclic constraint-domain argument relies on (logup.rs:259-263).
 *
 * Bus names: a global lookup's bus name is a grouping/memo key ONLY. It is
 * NEVER observed into the Fiat-Shamir transcript (G-DET-L2; p3-lookup
 * types.rs:22, batch-stark transcript.rs:84-96) and is therefore NOT part of
 * this gadget's data model — grouping happens in the caller (P2L-b/d).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_LOGUP_H
#define DNAC_LOGUP_H

#include <stddef.h>
#include <stdint.h>

#include "field_goldilocks.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Error codes (all entry points fail-close; 0 = OK)
 * ========================================================================== */
#define DNAC_LOGUP_OK              0
#define DNAC_LOGUP_ERR_NULL       (-1) /* required pointer is NULL            */
#define DNAC_LOGUP_ERR_EXPR       (-2) /* malformed expression pool/reference */
#define DNAC_LOGUP_ERR_ZERO_DENOM (-3) /* α - combined == 0 (mirror of the
                                          Plonky3 batch-inversion panic,
                                          batch_inverse.rs:26)               */
#define DNAC_LOGUP_ERR_PARAM      (-4) /* duplicate aux column, challenge
                                          count, height 0, kind mismatch —
                                          mirrors logup.rs asserts 173-176,
                                          201-203, 239-241, 254-256, 383-401 */
#define DNAC_LOGUP_ERR_GLOBAL_SUM (-5) /* verify_global_sum: Σ != 0
                                          (logup.rs:317-321)                 */
#define DNAC_LOGUP_ERR_OOM        (-6) /* scratch allocation failed          */

/* ============================================================================
 * Expression pool
 *
 * A P2L-a lookup element / multiplicity is a small arithmetic expression over
 * the two-row window — the concrete subset of Plonky3 SymbolicExpression
 * (air/src/symbolic/expression.rs) that lookup interactions use: main /
 * preprocessed column references (current or next row), public values,
 * base-field constants, and add/sub/mul/neg. Selector leaves (IsFirstRow /
 * IsLastRow / IsTransition) and periodic columns are OUT of P2L-a scope.
 *
 * Nodes live in a flat pool; children MUST have a smaller pool index than
 * their parent (topological order). Evaluation is a single forward pass —
 * no recursion, no iteration-order dependence.
 * ========================================================================== */
typedef enum {
    DNAC_LOGUP_EXPR_CONST  = 0, /* cval                                     */
    DNAC_LOGUP_EXPR_MAIN   = 1, /* main[row + next][index]                  */
    DNAC_LOGUP_EXPR_PREP   = 2, /* preprocessed[row + next][index]          */
    DNAC_LOGUP_EXPR_PUBLIC = 3, /* publics[index] (degree 0, variable.rs:44)*/
    DNAC_LOGUP_EXPR_ADD    = 4, /* pool[x] + pool[y]                        */
    DNAC_LOGUP_EXPR_SUB    = 5, /* pool[x] - pool[y]                        */
    DNAC_LOGUP_EXPR_MUL    = 6, /* pool[x] * pool[y]                        */
    DNAC_LOGUP_EXPR_NEG    = 7  /* -pool[x]                                 */
} dnac_logup_expr_kind_t;

typedef struct {
    uint8_t   kind;  /* dnac_logup_expr_kind_t                              */
    uint8_t   next;  /* MAIN/PREP: 0 = current row, 1 = next row (offset)   */
    uint32_t  index; /* MAIN/PREP: column; PUBLIC: public-value index       */
    gold_fp_t cval;  /* CONST only                                          */
    int32_t   x;     /* ADD/SUB/MUL/NEG: child pool index (< own index)     */
    int32_t   y;     /* ADD/SUB/MUL: child pool index (< own index)         */
} dnac_logup_expr_t;

/* Evaluation context: the traces one instance evaluates over. All matrices
 * are row-major. prep may be NULL (then no PREP node is legal). */
typedef struct {
    const gold_fp_t *main;        /* [height][main_width]                   */
    uint32_t         main_width;
    const gold_fp_t *prep;        /* [height][prep_width] or NULL           */
    uint32_t         prep_width;
    const gold_fp_t *publics;     /* [num_publics] or NULL if 0             */
    uint32_t         num_publics;
    uint32_t         height;
    const dnac_logup_expr_t *pool;
    uint32_t         pool_len;
} dnac_logup_ctx_t;

/* One lookup argument (p3-lookup types.rs:28-37 Lookup<F>, concrete form).
 * `column` is the auxiliary column this lookup owns in the permutation
 * trace; challenge indices derive from it (α = challenges[2·column],
 * β = challenges[2·column + 1]; logup.rs:207-209, 421-425). */
typedef struct {
    int                     is_global;      /* 0 = Local, 1 = Global        */
    uint32_t                column;
    uint32_t                num_tuples;
    const uint32_t         *tuple_widths;   /* [num_tuples]                 */
    const int32_t *const   *tuple_elems;    /* [num_tuples][tuple_widths[t]]
                                               expression pool indices      */
    const int32_t          *multiplicities; /* [num_tuples] pool indices    */
} dnac_logup_lookup_t;

/* ============================================================================
 * Pool validation
 *
 * Checks every node: kind valid, children topologically ordered (child index
 * >= 0 and < own index), MAIN/PREP offset in {0,1} and column in range (PREP
 * additionally requires ctx->prep != NULL), PUBLIC index in range. All
 * public entry points below run this before touching the pool (fail-close).
 * ========================================================================== */
int dnac_logup_pool_validate(const dnac_logup_ctx_t *ctx);

/* Degree multiple of one pool expression, per the Plonky3 rules
 * (air/src/symbolic/expression.rs:43-49, variable.rs:37-47, mod.rs:124-183):
 * CONST/PUBLIC = 0, MAIN/PREP = 1, ADD/SUB = max, NEG = same, MUL = sum. */
int dnac_logup_expr_degree(const dnac_logup_ctx_t *ctx, int32_t idx,
                           uint32_t *out_degree);

/* ============================================================================
 * Sum terms — logup.rs:101-146 compute_combined_sum_terms (concrete ExprEF)
 *
 * Computes numerator / common_denominator of Σ m_i / (α − combined_i) where
 * combined_i = Horner-fold of tuple i's element VALUES with β
 * (elements[i][0]·β^{w-1} + … + elements[i][w-1]; logup.rs:88-93).
 * Prefix/suffix products; NO inversion here.
 *
 * n == 0 => (numerator, denominator) = (0, 1)  (logup.rs:113-114).
 * ========================================================================== */
int dnac_logup_sum_terms_fp2(
    const gold_fp2_t *const *elements,  /* [n][widths[i]] element values    */
    const uint32_t          *widths,    /* [n]                              */
    const gold_fp2_t        *mults,     /* [n] multiplicity values          */
    uint32_t                 n,
    gold_fp2_t               alpha,
    gold_fp2_t               beta,
    gold_fp2_t              *numerator,
    gold_fp2_t              *denominator);

/* ============================================================================
 * Aux-trace generation — logup.rs:362-703 generate_permutation (SERIAL)
 *
 * ⚠ ARITHMETIZATION CHANGED at Plonky3 v0.6.2 (S2'-c, 2026-07-27). This is a
 * RE-PORT, not a patch: the old scheme kept one exclusive running sum per
 * lookup and returned a cumulative sum per GLOBAL lookup. The new one is
 *
 *   aux width = num_lookups + 1                            (logup.rs:381-382)
 *     col 0      = ONE shared accumulator
 *     col c + 1  = lookup slot c's FRACTION column
 *
 *   frac_c[r]  = Σ_t m_t / (α − combined_t)   written directly (logup.rs:630)
 *   row_total[r] = Σ_c frac_c[r]
 *   acc[0] = 0,  acc[r] = Σ_{j<r} row_total[j]   EXCLUSIVE prefix sum
 *                                              (logup.rs:637-654, 690-700)
 *   terminal   = Σ_{all r} row_total[r]        ONE per AIR, not per lookup
 *                                              (logup.rs:685-688, 702)
 *
 * `terminal_out` receives that single value; it replaces the old
 * `cumulative_sums`/`num_globals` pair outright. NULL is legal only when
 * num_lookups == 0, which produces no aux trace and no terminal
 * (logup.rs:374-377).
 *
 * Fail-close checks (always on): num_challenges == 2·num_lookups
 * (logup.rs:384-389); **lookups[i].column == i** — the slot index must equal
 * the slice position (logup.rs:399-406). That last one REPLACES the old
 * unique-and-in-range pair check and is strictly stronger: upstream's own
 * reason is that a gap is "an out-of-bounds write on untrusted data", since
 * slot i writes column i+1 here while the constraint reads the column the
 * lookup names. Also height > 0.
 * ========================================================================== */
int dnac_logup_generate_permutation(
    const dnac_logup_ctx_t    *ctx,
    const dnac_logup_lookup_t *lookups,
    uint32_t                   num_lookups,
    const gold_fp2_t          *challenges,     /* [num_challenges]          */
    uint32_t                   num_challenges, /* == 2·num_lookups          */
    gold_fp2_t                *aux_out,        /* [height][num_lookups + 1] */
    gold_fp2_t                *terminal_out);  /* single per-AIR terminal   */

/* ============================================================================
 * Constraint residuals — SPLIT IN TWO at v0.6.2 (S2'-c, 2026-07-27).
 *
 * The old single `dnac_logup_eval_row` emitted a per-lookup running-sum stream
 * (first-row anchor + transition + optional last-row cumulative binding). The
 * new scheme separates the two jobs, because the accumulator is now SHARED:
 *
 *   eval_fraction     — ONE residual per lookup, per row, UNGATED
 *   eval_accumulator  — THREE residuals per row, over ALL lookups at once
 *
 * ── eval_fraction (logup.rs:175-246) ────────────────────────────────────────
 *   residual = U_c · f_c[r] − V_c        where f_c[r] = aux[row][column + 1]
 *
 * (V_c, U_c) = (numerator, common_denominator) from dnac_logup_sum_terms_fp2
 * over the row-resolved elements. Pinned on EVERY row with no selector —
 * upstream's reason (logup.rs:241-244): "The identity is cyclic in the trace
 * domain, so it does not need a transition gate. Forcing it on every row also
 * pins the last-row value used by the accumulator's terminal binding."
 * A valid witness yields zero on every row.
 * ========================================================================== */
int dnac_logup_eval_fraction(
    const dnac_logup_ctx_t    *ctx,
    const dnac_logup_lookup_t *lookup,
    const gold_fp2_t          *aux,            /* [height][aux_width]       */
    uint32_t                   aux_width,      /* == num_lookups + 1        */
    const gold_fp2_t          *challenges,
    uint32_t                   num_challenges, /* >= 2·(column+1),
                                                  logup.rs:215-218          */
    uint32_t                   row,
    gold_fp2_t                *residual);

/* ── eval_accumulator (logup.rs:258-302) ────────────────────────────────────
 * Emits the ordered assert_zero_ext stream for the SHARED accumulator at one
 * row, each entry multiplied by its row selector exactly as the reference
 * filtered builder does (air/src/filtered.rs:78-86: residual · condition):
 *
 *   residuals[0] = is_first_row  · acc_local                    (logup.rs:291)
 *   residuals[1] = is_transition · (acc_next − acc_local − row_sum)
 *                                                               (logup.rs:294-296)
 *   residuals[2] = is_last_row   · (terminal − acc_local − row_sum)
 *                                                               (logup.rs:299-301)
 *
 * with acc_local = aux[row][0], acc_next = aux[(row+1) % height][0] (WRAP),
 * and row_sum = Σ_c aux[row][c + 1] over every lookup slot (logup.rs:285-287).
 * `terminal` is the value the prover committed for this AIR — the same one
 * generate_permutation returned. Always exactly 3 residuals: the local/global
 * distinction is GONE from this layer, since one accumulator now covers both.
 * ========================================================================== */
int dnac_logup_eval_accumulator(
    const dnac_logup_ctx_t    *ctx,
    const dnac_logup_lookup_t *lookups,
    uint32_t                   num_lookups,
    const gold_fp2_t          *aux,            /* [height][aux_width]       */
    uint32_t                   aux_width,      /* == num_lookups + 1        */
    uint32_t                   row,
    gold_fp2_t                 terminal,
    gold_fp2_t                 residuals[3]);

/* ============================================================================
 * EF-window pool evaluation — P2L-d d2 (the verifier side at ζ)
 *
 * The batched verifier evaluates lookup element/multiplicity expressions
 * with Expr = the EXTENSION field over the opened two-row window
 * (VerifierConstraintFolderWithLookups, lookup/src/folder.rs:115-126:
 * main/prep windows are RowWindow::from_two_rows over the ζ / g·ζ opened
 * values). Variable leaves resolve to the opened fp2 values; constants and
 * public values are base elements promoted into the extension field.
 * Same topological pool, same node semantics as logup_pool_eval_row —
 * only the leaf domain changes (concrete row → OOD window).
 *
 * main_next / prep_next may be NULL ONLY if no expression references the
 * next row of that trace (fail-close ERR_EXPR otherwise). prep_local NULL
 * forbids PREP nodes; publics NULL forbids PUBLIC nodes.
 * ========================================================================== */
int dnac_logup_eval_pool_window(
    const dnac_logup_expr_t *pool, uint32_t pool_len,
    const gold_fp2_t *main_local, const gold_fp2_t *main_next,
    uint32_t          main_width,
    const gold_fp2_t *prep_local, const gold_fp2_t *prep_next,
    uint32_t          prep_width,
    const gold_fp_t  *publics, uint32_t num_publics,
    gold_fp2_t       *vals /* [pool_len] */);

/* ============================================================================
 * Cross-AIR terminal check — logup.rs:304-319 verify_terminal_sum
 *
 * Returns DNAC_LOGUP_OK iff Σ terminals == 0, else DNAC_LOGUP_ERR_GLOBAL_SUM.
 *
 * FLAT total over every AIR's committed terminal — and at v0.6.2 that is
 * CORRECT, where the old flat sum was not. The previous contract here warned
 * that the caller had to group per bus name (G-DET-L4 / red-team F3), because
 * a flat total let one bus's imbalance cancel another's. That hazard is now
 * closed one layer down, in the CHALLENGE DERIVATION rather than in the
 * gadget: every lookup slot gets a domain-separated denominator base
 * prefix[bus] = α + (bus+1)·β^W, so two different buses cannot produce
 * cancelling terms (challenges.rs:8-37 "Injectivity"; Kind::Local takes a
 * fresh bus id each while Kind::Global shares one by NAME,
 * transcript.rs:117-151). See dnac_logup_bus_derive in logup_bus.h.
 *
 * ⚠ The gadget itself still provides NO cross-bus protection — it consumes
 * whatever challenge array it is handed. Hand it colliding prefixes and the
 * hazard returns. The logup_bus KAT pins BOTH directions on purpose
 * (`cross_bus_cancel` vs `cross_bus_separated`).
 * ========================================================================== */
int dnac_logup_verify_terminal_sum(const gold_fp2_t *terminals, uint32_t n);

/* ============================================================================
 * Constraint degree — logup.rs:339-367 constraint_degree
 *
 * deg = max(1 + Σ_i deg(combined_i),
 *           max_i (deg(m_i) + Σ_j deg(combined_j) − deg(combined_i)))
 * where deg(combined_i) = max over the tuple's element degrees.
 * ========================================================================== */
int dnac_logup_constraint_degree(const dnac_logup_ctx_t    *ctx,
                                 const dnac_logup_lookup_t *lookup,
                                 uint32_t                  *out_degree);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_LOGUP_H */
