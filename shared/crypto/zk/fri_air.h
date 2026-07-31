/**
 * @file fri_air.h
 * @brief P2c slice 1 — the FRI FOLD-WALK control AIR: column layout, public
 *        layout and constraint evaluation (EVALUATION ONLY, no prover).
 *
 * Design contract: dnac/docs/plans/2026-07-29-p2c-fri-in-air-design.md
 * (local-only), §0.5 "Design — fri_air.{c,h}, the fold-walk control-AIR":
 *   Row schedule           :229-266   (delegated to fri_air_table.{c,h})
 *   Publics layout + gates  :268-290
 *   Field representation    :292-302   (W = 7, fp2 = [c0, c1])
 *   Columns                 :304-325
 *   Constraint forms C2-C6  :327-391
 *   Slice boundary          :393-403
 * Every "MUST" in §0.5 is discharged here as an EXPLICIT constraint; nothing is
 * left to trace-generation convention (the P2a-i3 lesson: "the doc says it" is
 * not "the code constrains it"). Each constraint block in fri_air.c cites the
 * §0.5 form it discharges and, where ported, the pinned upstream line the
 * design gives (P3rec b36339709a7a67ee9760fb578b3d4339fd983709,
 * `recursion/circuit/src/fri/verifier.rs` unless stated otherwise).
 *
 * ── What this AIR is ────────────────────────────────────────────────────────
 * One trace = ONE query's fold walk of `fri_verify_query`
 * (fri_verifier.c:507-618), under ONE pinned cfg:
 *
 *     [ lgmh-1 chain rows ]  x0-anchor accumulation, index bits MSB-first
 *     [ R      fold rows  ]  one per FRI phase, index bits LSB-first
 *     [ >=1    pad rows   ]  terminality; the FIRST of them carries C5
 *
 * exactly the schedule `dnac_p2c_table_generate` emits (fri_air_table.c:213-253
 * — the ONE schedule authority; this file never re-derives it, it reads the row
 * counts and the roll-in placement back OUT of the generator).
 *
 * ⚠ DOC-CITE BASELINE (FLEET 022 A1-F5): `design §0.5 :NNN` cites here and in
 * fri_air.c are against the doc AS OF 2026-07-29 implementation time; the doc
 * has since gained fold-record lines, so exact numbers drift a few lines while
 * every cited claim is intact (A1-verified). Resolve by the stable §/form
 * anchors (RESUME "CITATION BASELINE" practice).
 *
 * Row types, the pair gates, the step one-hot and the chain's G_j literals all
 * come from the PREPROCESSED window, never from witness columns (design §0.5
 * :247-262, the FLEET 020 A2-F5 fold). Their booleanity / exclusivity /
 * one-hotness is a TABLE-GENERATOR obligation under PIN-1-P2c — nothing on the
 * verify path checks preprocessed cells (batch_verify.c:722-727 hands the
 * window to `air_eval` raw) — so this evaluator never constrains them; it is
 * simply well defined for arbitrary prep values, read as field elements.
 * `dnac_p2c_table_validate` (fri_air_table.c:266-438) is what checks the
 * generator, and the root KAT is what freezes the pair.
 *
 * ⚠ PIN-1-P2c / PIN-2 ARE PREREQUISITES OF EVERY GUARANTEE BELOW:
 *   - PIN-1-P2c: the future P2c verify ENTRY must compare the decoded
 *     preprocessed root against DNAC_P2C_PREP_ROOT (`dnac_p2c_prep_root_check`,
 *     fri_air_table.h:468-483) and fail closed. Without it the selector cells
 *     are prover-supplied proof data (batch_prover.c:787-826 commits the
 *     PROVER's own table) and every gated constraint here is satisfiable with
 *     an all-zero table.
 *   - PIN-2: the P2c descriptor MUST set `prep_next = 1`. C3's chain transition
 *     reads the NEXT row's `g_pow2` literal. ⚠ Read fri_air_table.h:142-154
 *     (the O6-corrected paragraph) before assuming the P2b failure mode: at
 *     DNAC_P2C_TABLE_COLS == 73 a `prep_next = 0` descriptor does NOT get a
 *     silent all-zero next window — it trips the `pzeros[64]` capacity guard
 *     and returns DNAC_BV_ERR_SHAPE outright (batch_verify.c:696-701), so this
 *     table fails CLOSED harder than P2b's. The composition entry must still
 *     confirm the full prove/verify pipeline handles a 73-wide preprocessed
 *     matrix WITH prep_next = 1; this slice has no round-trip evidence.
 * Neither pin is enforced by THIS module: there is no P2c verify entry yet
 * (slice 1 is evaluation only). `dnac_fair_eval_row` takes the next-row
 * preprocessed window as a SEPARATE, REAL parameter — the shape a
 * `prep_next = 1` descriptor produces — and rejects a next-MAIN-without-
 * next-PREP call outright (gate G5).
 *
 * ── NO embedded permutation ─────────────────────────────────────────────────
 * Unlike P2a (WIDTH 281) and P2b (WIDTH 245), this AIR embeds NO poseidon2
 * block: the fold walk is HASH-FREE. That is the central cost win of the slice
 * boundary (design §0.5 :320-325). MMCS binding of the sibling cells happens at
 * COMPOSITION, not here (see "What slice 1 does NOT do" below).
 *
 * ── Public values (composition binds to THESE offsets) ──────────────────────
 *   [0, lgmh)                       index bits, LSB-first   FAIR_PUB_BITS_OFF
 *   [lgmh, lgmh + 2R)               betas, fp2 [c0,c1] per phase, transcript
 *                                   order                   dnac_fair_pub_beta_off
 *   [+2R, +2R+2)                    f_init                  dnac_fair_pub_finit_off
 *   [.., + 2*num_rollin)            roll-in values, HEIGHT-DESCENDING
 *                                                           dnac_fair_pub_ro_off
 *   [.., +2)                        final_poly[0]           dnac_fair_pub_final_off
 * total = `dnac_fair_num_publics(cfg)`; any other length fails closed (G6).
 *
 * Layout rationale, per region:
 *   - BITS are public and LSB-first: index binding form A1, user-locked
 *     2026-07-29 (design §0.4 :156-160). Bit i is bit i of the query index —
 *     the native's own order (`idx >>= log_arity` per phase,
 *     fri_verifier.c:558; `sample_bits(lgmh)` at :737). The chain reads them
 *     MSB-first and the walk LSB-first, so the OVERLAP [1, R-1] is read TWICE;
 *     that is a strength (it forces chain and walk onto ONE index), not a
 *     redundancy (design §0.5 C2 :331-338).
 *   - BETAS are public because slice 1 does not carry a transcript; the
 *     composition binds them to P2a sample lanes in F-S order (OBL-P2a-1).
 *     fp2 is TWO base lanes, c0 FIRST (duplex_challenger.c:134-140 <->
 *     P3rec circuit.rs:378-386).
 *   - F_INIT is public and IS READ by a constraint (the is_handoff boundary,
 *     C4). v1 of the design carried it in publics with NO constraint reading it
 *     — the FLEET 020 A2-F2 CRITICAL, the classic write-key/read-key hole.
 *   - ROLL-IN values sit one fp2 per cfg-pinned roll-in phase, in the cfg's
 *     STRICTLY DESCENDING height order, which is exactly the native's monotone
 *     consumption order (`ro_i` only advances, fri_verifier.c:600-605).
 *   - FINAL_POLY[0] is a single fp2 constant because log_final_poly_len == 0 is
 *     pinned (gate G2): the terminal Horner degenerates to `final_poly[0]` and
 *     is x-INDEPENDENT (fri_terminal_horner_eval, fri_verifier.c:122-142;
 *     upstream early-returns `coefficients[0]`, P3rec verifier.rs:847-849), so
 *     slice 1 needs NO terminal-x machinery.
 *
 * ── Native checks with NO in-AIR counterpart (design §0.6 ledger :204-218) ───
 *   OBL-1  circuit selected by a PINNED height, never a wire depth
 *          (mmcs_air.h:90-92) — DISCHARGED BY SHAPE here: lgmh, R, the roll-in
 *          set and every row count derive from the cfg alone (design §1 D-2);
 *          no wire field enters the schedule.
 *   OBL-2  canonicality — the eval entry REJECTS any public >= p (G6, the P2b
 *          A2-F1 precedent); the wire sweep stays a commitment-layer duty.
 *   OBL-3  index-domain circularity — non-circular here: the index domain is
 *          2^lgmh EXACTLY with lgmh cfg-pinned, and the bits are
 *          bool-constrained in-AIR (C2), so index < 2^lgmh by construction.
 *   OBL-4c PIN-1-P2c binds the TABLE, never the verifier's separate cfg
 *          ARGUMENT (wording corrected by FLEET 022 A1-F2). Under collision
 *          resistance the root DOES determine lgmh (g_pow2 is lgmh-injective),
 *          R and the roll-in set (they are table content, fri_air_table.c:
 *          190-198) — of the cfg scalars only num_queries escapes the table
 *          entirely. The residual: nothing ties the root-checked TABLE to the
 *          cfg STRUCT the eval entry receives; a mismatched pair leaves
 *          cfg-derived loop bounds (e.g. C4g's) aimed at the wrong publics.
 *          The COMPOSITION entry MUST pin the cfg scalars INDEPENDENTLY of
 *          DNAC_P2C_PREP_ROOT. What pins the publics shape TODAY is the
 *          `num_publics` fail-close at eval entry, not the table.
 *   OBL-P2c-3 (FLEET 022 A2-F8) ROW-0 SELECTOR. C3a — the SOLE anchor of the
 *          x0 chain — fires on the caller-supplied `is_first_row` flag, not on
 *          a preprocessed cell. The composition MUST wire the composed
 *          system's own first-row selector (stark_constraints.h is_first_row)
 *          to this flag; dropping it frees g[0] and with it the whole chain.
 *          (House pattern — mmcs_air.c/transcript_air.c do the same — but
 *          HERE the first-row form pins the arithmetic anchor, not a mere
 *          selector cell, so it is a named obligation, not just style.)
 *   OBL-P2c-4 (FLEET 022 A1-F3) FINAL-HEIGHT ROLL-IN IS ZERO. Both natives
 *          force a reduced opening at height == log_blowup to equal 0
 *          (fri_verifier.c:480-487; 82cfad73 fri/src/verifier.rs:647-651 —
 *          "f is constant, so ... must equal 0"). That rule lives in
 *          open_input, OUTSIDE this slice; this AIR accepts an arbitrary
 *          public in a final-height roll-in slot. ⚠ REVISED BY FLEET 029: the
 *          oi module's final-closeout is now CONDITIONAL (a height AT lb is
 *          OPTIONAL — real proofs have none; fri_oi_air_table.c:92-100), so
 *          the pin exists only when the oi cfg contains an lb group. The
 *          composition entry owns BOTH halves: (a) every fri_air roll-in
 *          height MUST appear in OI.H (lb is admissible here — final_h =
 *          lb + lfpl, fri_air_table.c:64/:89 — so this is a REAL check, not
 *          vacuously true), and (b) a cfg pair with a final-height roll-in is
 *          blessed only when the oi side carries the lb group whose C4b pins
 *          that slot to zero. Mirror text: fri_oi_air.h (cross-seam label).
 *   OBL-P2c-1 (FLEET 020 A2-F6, cross-seam) SHAPE PRECEDENCE. The native
 *          derives the round count and lgmh from the PROOF
 *          (fri_verifier.c:642-649) and rejects extra reduced openings only via
 *          :613-615; this AIR pins R structurally and has NO CELL for a round
 *          or a reduced opening the cfg does not name. The composition entry
 *          MUST therefore reject any proof whose round count != cfg R, and any
 *          reduced opening outside the cfg roll-in set, BEFORE selecting or
 *          attesting the circuit. Absence is a PRECONDITION here, not a check.
 *   OBL-P2c-2 (FLEET 020 A2-F7, cross-seam) QUERY MULTIPLICITY. One trace ==
 *          ONE query. The composed system MUST (a) ALIAS the SHARED
 *          Fiat-Shamir values across all Q traces and (b) feed each trace the
 *          transcript's OWN q-th index sample. Otherwise Q copies of ONE query
 *          collapse soundness from lb*Q + pow to ~lb + pow bits.
 *          ⚠ TEXT CORRECTED (multi-query slice). This obligation used to name
 *          the shared set as "beta / f_init / final_poly"; the design doc
 *          (dnac/docs/plans/2026-07-29-p2c-fri-in-air-design.md:218) said
 *          "beta / final_poly". BOTH were wrong. The shared set is
 *          {alpha, betas, final_poly}:
 *            alpha      fri_verifier.c:694  — sampled ONCE
 *            betas[r]   fri_verifier.c:707  — once per commit round
 *            final_poly fri_verifier.c:710-713 — observed once
 *          all three OUTSIDE the per-query loop that starts at
 *          fri_verifier.c:736. `f_init` is the OPPOSITE of shared: it is ro[0]
 *          of `fri_open_input`, run INSIDE that loop against the query's own
 *          index (:742), so aliasing it across queries would BE the collapse
 *          this obligation forbids — as would aliasing the roll-ins. The doc
 *          also omitted alpha, which is shared and does need the alias.
 *          ⚠ (b) IS ABOUT POSITION, NOT VALUE. ":737 samples a fresh index per
 *          query" does not mean the Q values must differ — two fresh samples
 *          may legitimately collide. What must not happen is Q consumers all
 *          reading the transcript's q = 0 export block.
 *          DISCHARGED by the composition entry (fri_statement.h): instance
 *          1 + 4q + slot consumes `index_bits[q]`, which IS the transcript
 *          instance's q-th exported bit block; the shared three are single
 *          statement fields with no per-query copy. Gate: N-QSEP / N-QSHARED /
 *          N-QINDEP in tests/test_fri_statement.c.
 *
 * ── What slice 1 does NOT do (design §0.5 :393-403) ─────────────────────────
 *   - No MMCS verify. The sibling column `s` is UNCONSTRAINED witness data
 *     until the composition binds it to P2b opened-row publics. Every soundness
 *     claim of this AIR is conditional on that seam.
 *   - No transcript binding (alpha is unused in slice 1 — it lives in
 *     open_input); betas / bits / f_init / final_poly arrive as PUBLICS.
 *   - No open_input, no per-height alpha accumulation, no 1/(z-x).
 *   - No multi-query stacking, no PoW rows.
 *   - No terminal-x (lfpl = 0 pinned), no arity != 2, no hiding salts.
 *
 * ⚠ COLUMN-COUNT (count-KAFADAN discipline, design §4 item 2 which
 * explicitly orders "exact column count ... re-counted at implementation"):
 * the design's §0.5 column list has THIRTEEN entries — b, g, g_sq, gb, f, s,
 * inv, beta, beta_sq, t1, t2, rterm, ro — of which five are 1 base lane
 * (b, g, g_sq, gb, inv) and eight are fp2 = 2 lanes each:
 *     5 * 1 + 8 * 2 = 21.
 * At implementation time the doc's summary said "20" (its 5th count-KAFADAN
 * instance); the doc has since been CORRECTED to 21 in both places (its §0.5
 * block and §4 item 2 record the history — FLEET 022 A1-F1 caught this
 * comment still quoting the superseded text). FAIR_NUM_COLS is DERIVED from
 * the last offset below so it can never drift from the list again.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_ZK_FRI_AIR_H
#define DNAC_ZK_FRI_AIR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "field_goldilocks.h" /* GOLDILOCKS_P — FAIR_NEG_HALF is derived from it */
#include "fri_air_table.h"    /* dnac_p2c_table_cfg_t + the row schedule    */

#ifdef __cplusplus
extern "C" {
#endif

/* ── Column layout (flat; offsets are the binding contract) ─────────────────
 *
 * ORDER IS THE DESIGN'S (§0.5 :306-318). fp2 quantities are TWO consecutive
 * base lanes [c0, c1] (design §1 D-5: one representation, no per-site choice).
 * The one base-field actor is x0 (column `g`); it enters fp2 expressions in the
 * c0 lane only (design §0.5 :296-302).
 */

/** b — the index bit this row consumes. Chain row j: b_{lgmh-1-j}. Fold row r:
 *  b_r. Boolean and bound to a public on every typed row (C2). */
#define FAIR_COL_B ((size_t)0)

/** g — the chain accumulator on chain rows; x0 of this phase on fold rows.
 *  Base field. The handoff copies the last chain value into fold row 0. */
#define FAIR_COL_G ((size_t)1)

/** g_sq — g*g. Degree-relief intermediate for the x0 recurrence (C4). */
#define FAIR_COL_G_SQ ((size_t)2)

/** gb — g * b' , the chain-transition intermediate (C3). Written on the row
 *  the product FEEDS (row j+1), pinned by row j's is_chainpair gate. */
#define FAIR_COL_GB ((size_t)3)

/** f[2] — the running folded evaluation (fp2). */
#define FAIR_COL_F ((size_t)4)

/** s[2] — the sibling evaluation (fp2). PRIVATE witness: proof data, never
 *  public, UNCONSTRAINED until the composition binds it to P2b. */
#define FAIR_COL_S ((size_t)6)

/** inv — witness for 1/x0, pinned by `g * inv = -1/2` (C4, the div form). */
#define FAIR_COL_INV ((size_t)8)

/** beta[2] — this phase's FRI challenge (fp2), bound to publics on fold rows. */
#define FAIR_COL_BETA ((size_t)9)

/** beta_sq[2] — beta^2 (fp2). beta^arity at arity 2 (fri_verifier.c:601-602). */
#define FAIR_COL_BETA_SQ ((size_t)11)

/** t1[2] — (1 - 2b) * (s - f), lanewise (fp2 scaled by a base scalar). */
#define FAIR_COL_T1 ((size_t)13)

/** t2[2] — (beta - x0) * t1 (fp2 product, W = 7). */
#define FAIR_COL_T2 ((size_t)15)

/** rterm[2] — beta_sq * ro (fp2). Degree-relief intermediate. */
#define FAIR_COL_RTERM ((size_t)17)

/** ro[2] — the roll-in value (fp2): bound to its public slot on is_rollin rows,
 *  forced to ZERO on every other fold row (C4). */
#define FAIR_COL_RO ((size_t)19)

/** Total control-AIR trace width == 21. DERIVED from the last block so it
 *  cannot drift from the column list (see the header's count correction).
 *  Far under DNAC_STARK_MAX_MAIN_WIDTH = 2560 (stark_constraints.h:243). */
#define FAIR_NUM_COLS (FAIR_COL_RO + (size_t)2)

/** fp2 lane count — [c0, c1], c0 first, everywhere (design §1 D-5). */
#define FAIR_EXT_LANES ((size_t)2)

/* ── Public-value layout ───────────────────────────────────────────────────
 * The bit region starts at 0; every other region's offset is a function of the
 * cfg (see the accessors below). */
#define FAIR_PUB_BITS_OFF ((size_t)0)

/* ── Field constants ──────────────────────────────────────────────────────── */

/**
 * NEG_HALF = -1/2 in Goldilocks.
 *
 * DERIVATION (no citation needed, it is arithmetic — but it is written out
 * because a wrong constant here would be silently satisfiable): p is ODD, so
 * (p-1)/2 is an integer, and
 *     2 * ((p-1)/2) = p - 1 == -1  (mod p),
 * hence (p-1)/2 == -1/2 (mod p). For Goldilocks p = 2^64 - 2^32 + 1 this is
 * 0x7FFFFFFF80000000. `dnac_fair_layout_check` re-derives the defining identity
 * 2*NEG_HALF + 1 == 0 (mod p) at runtime and fri_air.c pins it at COMPILE time
 * with a _Static_assert, so the literal cannot rot.
 *
 * Why this exact constant: the fold's `inv` witness ports upstream's
 * `inv = div(-1/2, x0)` (P3rec verifier.rs:619 via circuit_builder.rs:637-649,
 * where `div(lhs, rhs)` emits the constraint `rhs * out = lhs`). Because the
 * numerator is a NONZERO constant, `x0 * inv = -1/2` is UNSATISFIABLE at
 * x0 = 0 — division by zero is fail-close BY CONSTRUCTION (design §0.4
 * :143-149), which is also security goal G3.
 */
#define FAIR_NEG_HALF ((uint64_t)((GOLDILOCKS_P - UINT64_C(1)) / UINT64_C(2)))

/* ── Status / fail-close contract ─────────────────────────────────────────── */

/**
 * Fail-close sentinel: returned INSTEAD of a violation count when the config,
 * the public-value length, the row window or the preprocessed terminality is
 * out of contract. Strictly larger than any reachable PER-ROW violation count;
 * `dnac_fair_eval_trace` SATURATES at FAIR_VIOL_BAD_CONFIG - 1 rather than
 * overflowing, so a saturated count and the sentinel stay distinguishable.
 *
 * CALLER CONTRACT (identical to MAIR_VIOL_BAD_CONFIG, mmcs_air.h:184-193, which
 * inherits it from the P2a i3/A2-F5 contract, transcript_air.h:128-136): treat
 * ANY non-zero return as "invalid", and ONLY `== FAIR_VIOL_BAD_CONFIG` as "bad
 * config / out of contract".
 */
#define FAIR_VIOL_BAD_CONFIG 1000000

/**
 * The two DISTINGUISHED return values of the eval entries. Any other value is a
 * violation COUNT in [1, FAIR_VIOL_BAD_CONFIG - 1]; this enum exists so callers
 * can name the two ends without re-deriving the contract above. It deliberately
 * does NOT enumerate defect kinds: a constraint system reports "how many forms
 * were violated", not "which", and inventing a taxonomy here would imply a
 * precision the evaluator does not have.
 */
typedef enum {
    DNAC_FAIR_OK = 0,
    DNAC_FAIR_BAD_CONFIG = FAIR_VIOL_BAD_CONFIG
} dnac_fair_status_t;

/* ── Column accessors (P2AIR / MAIR accessor pattern) ──────────────────────── */

/** Lane `c` (0 = c0, 1 = c1) of the fp2 block starting at `off`. */
static inline size_t fair_ext_off(size_t off, size_t c) { return off + c; }

/* ── Public-layout helpers (pure functions of the pinned cfg) ─────────────── */

/**
 * First public index of the BETA region (== lgmh). Returns 0 for a config the
 * table module rejects — and 0 is unambiguously "reject" here, because a valid
 * cfg has lgmh >= DNAC_P2C_MIN_LGMH = 2. The same holds for every accessor
 * below (each is >= lgmh >= 2 on an accepted cfg).
 */
size_t dnac_fair_pub_beta_off(const dnac_p2c_table_cfg_t *cfg);

/** First public index of f_init (== lgmh + 2R). 0 on reject. */
size_t dnac_fair_pub_finit_off(const dnac_p2c_table_cfg_t *cfg);

/** First public index of the roll-in region (== lgmh + 2R + 2). The region is
 *  EMPTY when cfg->num_rollin == 0; the offset is still well defined. 0 on
 *  reject. */
size_t dnac_fair_pub_ro_off(const dnac_p2c_table_cfg_t *cfg);

/** First public index of final_poly[0] (== lgmh + 2R + 2 + 2*num_rollin).
 *  0 on reject. */
size_t dnac_fair_pub_final_off(const dnac_p2c_table_cfg_t *cfg);

/** Required public-value count (lgmh + 2R + 4 + 2*num_rollin). 0 on reject.
 *  This is what gate G6 compares `num_publics` against, EXACTLY. */
size_t dnac_fair_num_publics(const dnac_p2c_table_cfg_t *cfg);

/**
 * @brief Structural self-check of the column layout and the field constants.
 *
 * Verifies: no overlap and no gap across the 13 column blocks in the design's
 * order, FAIR_NUM_COLS consistent with the last block, the fp2 lane accessor
 * inside its block, the public regions disjoint and ordered on the pinned
 * reference cfg, and the NEG_HALF defining identity 2*NEG_HALF + 1 == 0 (mod p).
 *
 * @return true iff the layout is internally consistent.
 */
bool dnac_fair_layout_check(void);

/* ── Constraint evaluation ─────────────────────────────────────────────────── */

/**
 * @brief Evaluate every constraint anchored at ONE row.
 *
 * Evaluates the row-local constraints of the (`main_local`, `prep_local`) pair
 * plus the transition constraints into (`main_next`, `prep_next`). Pass
 * `main_next == prep_next == NULL` for the final trace row; a mixed
 * NULL/non-NULL pair is gate G5 and fails closed.
 *
 * ⚠ CONTRACT — `eval_row` STANDALONE IS STRICTLY WEAKER (the P2a i3/A2-F4
 * lesson, transcript_air.h:204-209; the same warning MAIR carries at
 * mmcs_air.h:245-252). Several transition constraints pin only PART of the next
 * row and rely on that row's OWN row-local block to pin the rest — e.g. the
 * is_handoff copy pins `g'` but the fold row's own `g * inv = -1/2` and
 * `g_sq = g*g` are row-local there; the is_fold transition pins `f'` but C5's
 * terminal equality is row-local on the padding row. A caller that evaluates
 * rows in isolation and never evaluates `next` as a `local` gets a WEAKER
 * system. Use `dnac_fair_eval_trace`, which evaluates every row both ways;
 * direct `eval_row` use is for NEGATIVE TESTS only.
 *
 * PRECONDITION: every MAIN column is a canonical Goldilocks u64 in [0, p).
 * Preprocessed cells are read as field elements and are NOT required to be
 * boolean (generator obligation under PIN-1-P2c). ⚠ PUBLICS are NOT a
 * precondition: they are checked canonical and any public >= p FAILS CLOSED
 * (gate G6 / OBL-2, the P2b red-verify A2-F1 shape — `fp()` aliases x and x+p
 * while every downstream u64 consumer of a public is representation-sensitive).
 *
 * @param main_local   FAIR_NUM_COLS columns.
 * @param main_next    FAIR_NUM_COLS columns, or NULL on the last row.
 * @param prep_local   DNAC_P2C_TABLE_COLS preprocessed cells of this row.
 * @param prep_next    DNAC_P2C_TABLE_COLS cells of the next row, or NULL.
 *                     REAL, never zero-filled: that is PIN-2 (`prep_next = 1`).
 * @param is_first_row non-zero on trace row 0 (C3's row-0 boundary anchor).
 * @param cfg          the pinned FRI cfg; NULL or any config the table module
 *                     rejects (gates G1/G2/G3/G7) is fail-close.
 * @param publics      `dnac_fair_num_publics(cfg)` canonical values.
 * @param num_publics  MUST equal `dnac_fair_num_publics(cfg)` (G6).
 * @return number of violated constraints (0 == valid), or FAIR_VIOL_BAD_CONFIG.
 */
int dnac_fair_eval_row(const uint64_t *main_local, const uint64_t *main_next,
                       const uint64_t *prep_local, const uint64_t *prep_next,
                       int is_first_row, const dnac_p2c_table_cfg_t *cfg,
                       const uint64_t *publics, size_t num_publics);

/**
 * @brief Evaluate the whole trace: every row local, every adjacent pair.
 *
 * Enforces, beyond the per-row forms, the two SHAPE gates (both fail-close,
 * both evaluated BEFORE any constraint):
 *   - G4a SCHEDULE CONFORMANCE: `n_rows` MUST equal `dnac_p2c_table_rows(cfg)`.
 *     The row count comes from the PINNED schedule, never from a witnessed
 *     length — otherwise a prover picks a shorter walk, i.e. a different
 *     statement (design §0.5 :280-283).
 *   - G4b TERMINALITY: the LAST row's preprocessed window MUST be a PADDING row
 *     (`is_pad == 1`, `is_chain == is_fold == 0`). The final trace row gets no
 *     transition constraints, so every effect a row pins on its SUCCESSOR is
 *     void there; requiring the last row to be padding makes "every typed row
 *     has a successor" structurally true, so no transition-anchored form — the
 *     chain multiply, the handoff, the x0 recurrence, the fold transition —
 *     can be skipped by ending the trace early (the P2a-i3 shipped-HIGH shape,
 *     transcript_air.c:444-460).
 *
 * ⚠ TWO DELIBERATE DIVERGENCES FROM `dnac_mmcs_air_eval_trace`, both stricter:
 *   1. P2b counted its terminality breach as ONE VIOLATION (mmcs_air.c:445-451);
 *      here it is a fail-close GATE. The P2c preprocessed table is generated
 *      and root-pinned as a whole, so a typed last row is not a "trace defect"
 *      a prover could argue about — it is an out-of-contract table.
 *   2. P2b's padding rows are ALL-ZERO, so it tested "no cell set". P2c padding
 *      rows carry `is_pad = 1` (fri_air_table.c:203-205) and the FIRST of them
 *      carries `is_terminal = 1`, which can be the LAST row when the pad block
 *      has length 1 (e.g. lgmh 5 / log_blowup 2: 4 + 3 + 1 = 8 rows exactly).
 *      So the gate checks the row TYPE, not "all cells zero".
 *
 * @param main_trace n_rows * FAIR_NUM_COLS canonical columns, row-major.
 * @param prep_table n_rows * DNAC_P2C_TABLE_COLS preprocessed cells, row-major
 *                   — the table PIN-1-P2c pins the root of.
 * @param n_rows     number of rows (>= 1).
 * @return total violated constraints (0 == valid), or FAIR_VIOL_BAD_CONFIG.
 */
int dnac_fair_eval_trace(const uint64_t *main_trace, const uint64_t *prep_table,
                         size_t n_rows, const dnac_p2c_table_cfg_t *cfg,
                         const uint64_t *publics, size_t num_publics);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ZK_FRI_AIR_H */
