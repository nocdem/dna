/**
 * @file transcript_air.h
 * @brief P2a — DuplexChallenger-as-a-control-AIR (transcript-in-AIR), column
 *        layout + constraint evaluation.
 *
 * Design contract: dnac/docs/plans/2026-07-28-p2a-transcript-in-air-design.md
 * **v2**, §0.5 "The state machine — CONSTRAINT FORMS". Every "MUST" in that
 * section is discharged here as an EXPLICIT constraint; nothing is left to
 * trace-generation convention (the vacuous-range lesson). Each constraint block
 * below cites (a) the §0.5 archetype it discharges and (b) the native
 * `duplex_challenger.c` line whose semantics it mirrors.
 *
 * ── What this AIR is ────────────────────────────────────────────────────────
 * One trace ROW = one transcript step of
 *   DuplexChallenger<Goldilocks, Poseidon2Goldilocks<8>, WIDTH=8, RATE=4>
 * (the SHIPPED native challenger, `duplex_challenger.{c,h}`, byte-matched to
 * Plonky3 @ 82cfad73 / v0.6.2 `11cc5849`). Semantic reference for the in-circuit
 * form: Plonky3-recursion @ b36339709a7a67ee9760fb578b3d4339fd983709 ("P3rec")
 * `recursion/src/challenger/circuit.rs` (observe :337-349, sample :351-364,
 * duplexing :94-155, sample_bits :388-407, check_pow_witness :409-430).
 *
 * ── Permutation delegation = INLINE embedding (design §0.5, user-locked) ────
 * A duplexing row carries the byte-matched 180-column `poseidon2_air` block in
 * its OWN row at TAIR_PERM_OFF, exactly as every shipped consumer does
 * (`conf_action_fold.c:133-185`, `conf_membership_air.h:70-71`). Binding is BY
 * COLUMN IDENTITY: the block's `inputs[8]` and final-round `post[8]` ARE the
 * cells the control constraints reference. No bus, no CTL, no multiplicity
 * accounting (design §0.5 F4 fold / G-SEC-P2a-4).
 *
 * The embedded block's own constraints are evaluated UNGATED on every row —
 * the shipped precedent (`conf_action_fold.c:133-134, :190-192` call
 * `dnac_poseidon2_fold_eval` unconditionally). Non-duplexing rows therefore
 * carry a valid dummy permutation witness (the honest builder fills
 * `poseidon2_air_generate_row` over an all-zero preimage). Ungated is STRICTER
 * than gated and removes a gate an adversary could otherwise aim at.
 *
 * ── Constraint degree ───────────────────────────────────────────────────────
 * Every control constraint here is degree <= 3, matching `poseidon2_air`'s max
 * degree 3 (SBOX_REGISTERS=1, `poseidon2_air.h:20`) so the whole AIR stays
 * inside the FRI log_blowup=2 (blowup 4) envelope. The one place upstream uses
 * an unbounded-degree construction — `assert_bits_canonical`'s running
 * `eq_prefix` product over 32 bits (`circuit_builder.rs:1135-1146`) — is a
 * circuit DAG there (each `mul` allocates a wire) and CANNOT be transcribed into
 * a row-AIR verbatim. It is realized here by this tree's own is-zero idiom
 * (`conf_action_fold.c:54-58`, `:260-265`) over the two witness columns
 * TAIR_CANON_ISZ / TAIR_CANON_INV. The equivalence holds exactly when
 * p-1 = [ones][trailing zeros] (upstream states this for its supported fields,
 * `circuit_builder.rs:1119-1121`); the evaluator CHECKS that shape at run time
 * and fail-closes if a future field breaks it. Labelled ADAPTATION.
 *
 * ── Scope (design §0.5 "Op-stream binding — honest scope split", F8) ────────
 * This AIR binds the stream SHAPE (instance boundary + reset, DS prefix,
 * transition legality, filler inertness/terminality, canonical bit exposure).
 * It does NOT bind WHICH ops the verifier issues — that is the pinned recursion
 * config plus the P2c/P2e composition wiring (G-DET-P2a-5). It also does not
 * cover fp2: the AIR sees only base ops, and the CONSUMER must bind each fp2
 * challenge to two consecutive base pops, c0 first (design §0.5 F13;
 * `duplex_challenger.c:134-140` <-> `circuit.rs:378-386`).
 *
 * ── P2a-i2 scope ────────────────────────────────────────────────────────────
 * AIR evaluation only. There is no prover for this AIR yet (the recursion
 * config is non-hiding, salt=0 — design §0.5 F5 fold); the honest trace builder
 * lives test-side in `tests/test_transcript_air.c`.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_ZK_TRANSCRIPT_AIR_H
#define DNAC_ZK_TRANSCRIPT_AIR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "duplex_challenger.h" /* DNAC_DUPLEX_WIDTH / _RATE / _DS_PREFIX */
#include "poseidon2_air_cols.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Instance dimensions (mirror the native challenger, never re-declared) ── */
#define TAIR_STATE_LANES DNAC_DUPLEX_WIDTH /* 8  — sponge_state[] */
#define TAIR_RATE        DNAC_DUPLEX_RATE  /* 4  — input_buffer[] */
#define TAIR_LEN_SLOTS   (TAIR_RATE + 1)   /* 5  — one-hot 0..RATE */
#define TAIR_PREFIX_SLOTS 5                /* one-hot DS-prefix progress 0..4 */
#define TAIR_BITS        64                /* sample_bits decomposition lanes */

/* ── Row-type selectors (design §0.5 "Row archetypes"), ONE-HOT incl. filler ─ */
#define TAIR_SEL_START      0 /* instance boundary: resets state/counters      */
#define TAIR_SEL_OBS        1 /* observe, input_len < 3 (no duplex)            */
#define TAIR_SEL_OBS_DUP    2 /* 4th observe + eager duplex, ONE row           */
#define TAIR_SEL_SAMPLE     3 /* pop only (buffer empty, output non-empty)     */
#define TAIR_SEL_SAMPLE_DUP 4 /* duplex then pop, ONE row                      */
#define TAIR_SEL_FILLER     5 /* inert padding; terminal once started          */
#define TAIR_NUM_SEL        6

/* ── Column layout (flat, padding-free; offsets are the binding contract) ─── */
#define TAIR_STATE_OFF     0                                        /*   0  8 */
#define TAIR_INBUF_OFF     (TAIR_STATE_OFF + TAIR_STATE_LANES)      /*   8  4 */
#define TAIR_ILFLAG_OFF    (TAIR_INBUF_OFF + TAIR_RATE)             /*  12  5 */
#define TAIR_OLFLAG_OFF    (TAIR_ILFLAG_OFF + TAIR_LEN_SLOTS)       /*  17  5 */
#define TAIR_SEL_OFF       (TAIR_OLFLAG_OFF + TAIR_LEN_SLOTS)       /*  22  6 */
#define TAIR_PREFIX_OFF    (TAIR_SEL_OFF + TAIR_NUM_SEL)            /*  28  5 */
#define TAIR_LANE_OFF      (TAIR_PREFIX_OFF + TAIR_PREFIX_SLOTS)    /*  33  1 */
#define TAIR_ISPOW_OFF     (TAIR_LANE_OFF + 1)                      /*  34  1 */
#define TAIR_CANON_ISZ_OFF (TAIR_ISPOW_OFF + 1)                     /*  35  1 */
#define TAIR_CANON_INV_OFF (TAIR_CANON_ISZ_OFF + 1)                 /*  36  1 */
#define TAIR_BIT_OFF       (TAIR_CANON_INV_OFF + 1)                 /*  37 64 */
#define TAIR_PERM_OFF      (TAIR_BIT_OFF + TAIR_BITS)               /* 101 180*/

/** Total control-AIR trace width. == 281.
 *  (Design §4.2 budgeted ~277 = 97 control + 180 perm; the four columns beyond
 *  that budget are the op payload lane, the PoW modifier, and the two
 *  canonicality-gadget witnesses — see §4 note in the report. Far under
 *  DNAC_PROVER_MAX_TRACE_WIDTH = 2560, `stark_prover.h`.) */
#define TAIR_WIDTH (TAIR_PERM_OFF + P2AIR_NUM_COLS)

/** Pinned upper bound on the AIR's exposed `num_bits` (design §0.5: "a
 *  pinned-config constant <= 32"). 32 == GOLDILOCKS_TWO_ADICITY, the same bound
 *  the FRI verifier enforces on lgmh (`fri_verifier.c` lgmh guard); stricter
 *  than the native `bits >= 64` abort (`duplex_challenger.c:145`) and than
 *  upstream's `<= 64` (`circuit.rs:395-401`), so the 64-bit parity gap between
 *  those two is unreachable here (design F12). */
#define TAIR_MAX_NUM_BITS 32

/** Fail-close sentinel: returned INSTEAD of a violation count when the config
 *  or the field shape is out of contract. Strictly larger than any reachable
 *  PER-ROW violation count, so a caller comparing `== 0` cannot be fooled.
 *  ⚠ NOT larger than every conceivable per-TRACE sum (i3/A2-F5 corrected an
 *  earlier over-claim here): `dnac_transcript_air_eval_trace` SATURATES at
 *  `TAIR_VIOL_BAD_CONFIG - 1` rather than overflowing, so a saturated count and
 *  the sentinel stay distinguishable, but a caller must treat any non-zero
 *  return as "invalid" and only `== TAIR_VIOL_BAD_CONFIG` as "bad config". */
#define TAIR_VIOL_BAD_CONFIG 1000000

/* ── Column accessors (P2AIR accessor pattern, `poseidon2_air_cols.h:77-107`) ─ */

/** sponge_state[i], i < TAIR_STATE_LANES — the sponge lanes AT ROW ENTRY. */
static inline size_t tair_state_off(size_t i) { return (size_t)TAIR_STATE_OFF + i; }

/** input_buffer[i], i < TAIR_RATE — pending absorb lanes at row entry
 *  (native field `dnac_duplex_t::input_buffer`, `duplex_challenger.h:92`). */
static inline size_t tair_inbuf_off(size_t i) { return (size_t)TAIR_INBUF_OFF + i; }

/** il_flag[i], i <= TAIR_RATE — ONE-HOT `input_len` at row entry. */
static inline size_t tair_il_off(size_t i) { return (size_t)TAIR_ILFLAG_OFF + i; }

/** ol_flag[i], i <= TAIR_RATE — ONE-HOT `output_len` at row entry. */
static inline size_t tair_ol_off(size_t i) { return (size_t)TAIR_OLFLAG_OFF + i; }

/** Row-type selector s, s < TAIR_NUM_SEL. */
static inline size_t tair_sel_off(size_t s) { return (size_t)TAIR_SEL_OFF + s; }

/** prefix_ctr[i], i < TAIR_PREFIX_SLOTS — ONE-HOT DS-prefix progress. */
static inline size_t tair_prefix_off(size_t i) { return (size_t)TAIR_PREFIX_OFF + i; }

/** bit[i], i < TAIR_BITS — LE bit decomposition of the sampled lane. */
static inline size_t tair_bit_off(size_t i) { return (size_t)TAIR_BIT_OFF + i; }

/** Embedded poseidon2_air block: permutation PRE-image lane i (i < 8). */
static inline size_t tair_perm_in_off(size_t i) {
    return (size_t)TAIR_PERM_OFF + p2air_input_off(i);
}

/** Embedded poseidon2_air block: permutation OUTPUT lane i (i < 8) — the final
 *  ending-round `post` columns (`poseidon2_air_trace.h:46-47`). */
static inline size_t tair_perm_out_off(size_t i) {
    return (size_t)TAIR_PERM_OFF +
           p2air_end_post_off(P2AIR_HALF_FULL_ROUNDS - 1, i);
}

/**
 * @brief Pinned AIR configuration (design G-DET-P2a-2: a recursion-config
 *        constant, never per-proof data).
 */
typedef struct {
    /** PoW grinding bits: on a row with `is_pow = 1`, the low `pow_bits` bits of
     *  the sampled challenge are constrained ZERO (design §0.5 check_pow_witness
     *  <-> `duplex_challenger.c:151-158`, `circuit.rs:409-430`). MUST be
     *  <= TAIR_MAX_NUM_BITS. The live shielded pin is 16
     *  (`shielded_fri_params.h` DNAC_SHIELDED_FRI_QUERY_POW_BITS); the recursion
     *  layer's own value is fixed by the recursion config, not by this file. */
    size_t pow_bits;
} dnac_tair_config_t;

/**
 * @brief Structural self-check of the column layout (no overlap, no gap,
 *        TAIR_WIDTH consistent, selector indices distinct and in range).
 * @return true iff the layout is internally consistent.
 */
bool dnac_transcript_air_layout_check(void);

/**
 * @brief Evaluate every constraint anchored at ONE row.
 *
 * Evaluates the row-local constraints of `local`, plus the transition
 * constraints from `local` to `next`. Pass `next == NULL` for the final trace
 * row (no transition is evaluated there — the trace MUST therefore end in a
 * filler row for the last real op's effect to be constrained; that rule is
 * ENFORCED by `dnac_transcript_air_eval_trace`, not here).
 *
 * ⚠ CONTRACT (i3/A2-F4): the transition constraints pin ONE slot of each
 * next-row one-hot group (e.g. `nil_[k] == 1`) and rely on `next`'s OWN
 * row-local block to force the group's other slots to zero. A caller that
 * evaluates rows in isolation and never evaluates `next` as a `local` gets a
 * WEAKER system. Use `dnac_transcript_air_eval_trace`, which evaluates every
 * row both ways; direct `eval_row` use is for negative tests only.
 *
 * PRECONDITION (same contract as `poseidon2_air_eval_row`): every column is a
 * canonical Goldilocks u64 in [0, p). Non-canonical cells alias; the bit
 * decomposition's own `< p` constraint is what pins the SAMPLED lane's
 * representative, and that one IS checked here.
 *
 * @param local        TAIR_WIDTH columns.
 * @param next         TAIR_WIDTH columns, or NULL on the last row.
 * @param is_first_row non-zero on trace row 0 (boundary: MUST be `sel_start`).
 * @param cfg          pinned config; NULL or pow_bits > TAIR_MAX_NUM_BITS is
 *                     fail-close.
 * @return number of violated constraints (0 == valid), or TAIR_VIOL_BAD_CONFIG.
 */
int dnac_transcript_air_eval_row(const uint64_t *local, const uint64_t *next,
                                 int is_first_row,
                                 const dnac_tair_config_t *cfg);

/**
 * @brief Evaluate the whole trace: every row local, every adjacent pair.
 *
 * Row 0 carries the boundary constraint; the last row is evaluated with
 * `next == NULL`.
 *
 * @param trace  n_rows * TAIR_WIDTH canonical columns, row-major.
 * @param n_rows number of rows (>= 1).
 * @param cfg    pinned config.
 * @return total violated constraints (0 == valid), or TAIR_VIOL_BAD_CONFIG.
 */
int dnac_transcript_air_eval_trace(const uint64_t *trace, size_t n_rows,
                                   const dnac_tair_config_t *cfg);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ZK_TRANSCRIPT_AIR_H */
