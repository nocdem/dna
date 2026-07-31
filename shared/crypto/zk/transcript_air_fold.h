/**
 * @file transcript_air_fold.h
 * @brief s1a — the P2a transcript control-AIR in VERIFIER-FOLD form (fp2
 *        alpha-fold over the opened trace window at zeta).
 *
 * Build spec (authoritative): dnac/docs/plans/2026-07-29-composition-s1a-fold-
 * evals-BUILDABLE.md (local-only) — §2 API contract, §3 transcription rules,
 * §4 equivalence tests, §5 prohibitions.
 *
 * ── What this module is, and what it is NOT ─────────────────────────────────
 * `transcript_air.{c,h}` is a CONCRETE-TRACE checker: `dnac_transcript_air_
 * eval_row` / `_eval_trace` walk u64 cells and COUNT violations. A batch-STARK
 * verifier instead evaluates the constraint polynomial ONCE at the out-of-domain
 * point zeta over the opened fp2 values, alpha-folding every constraint in the
 * SAME order the prover used (`dnac_stark_folder_t`, stark_constraints.h:262-283;
 * `dnac_stark_air_t`, :284-291). This module is that fold-form eval and NOTHING
 * else.
 *
 * NO NEW CONSTRAINT IS INVENTED HERE. The constraint SET is exactly the u64
 * evaluator's per-row + transition set, in the u64 EMISSION ORDER (the alpha-fold
 * is order-sensitive). Every block below cites the `transcript_air.c` line range
 * it transcribes. The one form that is not a line-for-line copy is the
 * TERMINALITY boundary — see "Terminality" below; it is the same rule, moved from
 * `eval_trace`'s trace-level gate into an explicit `is_last_row` constraint,
 * because a row-AIR has no trace-level hook.
 *
 * ── Selector mapping (spec §3.2) ────────────────────────────────────────────
 *   u64 `is_first_row` argument      -> `when(folder->is_first_row, ·)`
 *   u64 "only evaluated when next    -> every such residual is multiplied by
 *   exists" (everything after the        `folder->is_transition`
 *   `if (!next) return v;` at
 *   transcript_air.c:224)
 *   u64 `eval_trace` terminality     -> `when(folder->is_last_row, 1 - sel_filler)`
 *   (transcript_air.c:444-460)
 *
 * ⚠ DEGREE — READ BEFORE COMPOSING (s1b). `transcript_air.h:37-49` documents
 * "every control constraint is degree <= 3" for the u64 forms. That count does
 * NOT include a transition selector, because the u64 evaluator has none: it
 * simply skips the transition block on the last row. Upstream's symbolic builder
 * DOES count `is_transition` as a degree multiple (a `when_transition` wrapper is
 * a multiplication), so the transition-anchored forms of trace-degree 3 — e.g.
 * `s_obs · il[j] · (next_inbuf[j] - lane)` (transcript_air.c:274) — become
 * DEGREE 4 in this form. This is a consequence of the mandated selector mapping,
 * not a choice made here. The s1b composition entry MUST size `log_num_qc` for
 * the real max degree of the composed system; it is not this module's decision.
 *
 * ── Terminality (spec §3.2, G4b) ────────────────────────────────────────────
 * `dnac_transcript_air_eval_trace` (transcript_air.c:444-460) adds ONE violation
 * when the last trace row is not a filler row. That gate is what closes the P2a
 * i3 shipped-HIGH: the final row gets no transition constraints, so a trace
 * ending in a SAMPLING row leaves the popped challenge free. On a cyclic trace
 * domain the last row's "next" is row 0 and `is_transition` vanishes there, so
 * the gate MUST be carried as an explicit boundary constraint or it is lost.
 * Emitted LAST, mirroring the u64 order (eval_row's steps, then the trace-level
 * rule).
 *
 * ── s1b ENTRY duties — NOT carried here (spec §3.2) ─────────────────────────
 *   G4a  SCHEDULE CONFORMANCE (`n_rows`): the u64 `eval_trace` walks a concrete
 *        row count. A fold eval sees ONE window at zeta and has no row count; the
 *        trace height is pinned by the batch descriptor (`degree_bits`) at the
 *        composition entry.
 *   G6   PUBLICS CANONICALITY: unreachable from a folder —
 *        `folder->public_values` is already `gold_fp_t`, so the raw-u64 alias
 *        the u64 evaluator rejects (transcript_air.c, the `>= GOLDILOCKS_P`
 *        sweep) cannot be observed here. The entry checks it on the DECODED
 *        publics before they enter the folder.
 *   PIN  The pinned `dnac_tair_config_t` (pow_bits) AND the pinned
 *        `dnac_tair_script_t` are bound by the caller; this module fail-closes
 *        on an out-of-contract pair but does not KNOW the production values.
 *        PIN-1-P2a (`dnac_tair_prep_root_check` on the decoded preprocessed
 *        root) and OBL-P2a-T1/T2 are ENTRY duties — see transcript_air_table.h.
 *
 * ── s3a UPDATE (2026-07-30) ─────────────────────────────────────────────────
 * The AIR gained a preprocessed op-schedule table and public values. This module
 * follows: `dnac_transcript_air_fold_bind` now takes the script too, the eval
 * reads `folder->preprocessed_local` / `folder->public_values`, and block T
 * (CT-1..CT-4, transcript_air.c) is transcribed in the same position and order.
 * `folder->preprocessed_next` is NOT read — no CT-* form touches it.
 *
 * ── Binding contract (FLEET 034: CALLER-OWNED state, no module static) ──────
 * `dnac_stark_air_t::air_eval`'s SIGNATURE still carries no context, but
 * `dnac_stark_folder_t` now does — `folder->ctx`, copied verbatim from
 * `dnac_stark_air_t::ctx` by every glue that builds a folder. The cfg + script
 * snapshot is therefore a CALLER-OWNED `dnac_tair_fold_state_t`. Consequences,
 * stated rather than assumed:
 *   - N SIMULTANEOUS bindings are legal: two descriptors with two states may
 *     carry two DIFFERENT (cfg, script) pairs of THIS AIR in the same batch, and
 *     each eval sees only its own state. Before FLEET 034 the second bind
 *     silently overwrote the first.
 *   - ⚠ LIFETIME: the state object AND the script it names must outlive every
 *     `air_eval` call made under that binding — i.e. the whole
 *     `dnac_batch_verify` / `dnac_batch_prove` call. Nothing is copied.
 *   - Determinism is unaffected: the state is a pure function of the pinned cfg
 *     and script, never of wire data, a clock or an RNG. Two nodes binding the
 *     same pair emit the identical constraint stream. The move changed only
 *     WHERE the bytes live.
 *   - `folder->ctx == NULL`, an unbound state, or a REJECTED bind all make
 *     `air_eval` emit ONE unsatisfiable constraint (`assert_zero(1)`) instead of
 *     silently folding nothing. Fail-close, never fail-open. A rejected bind
 *     disarms BOTH the state (`bound`) and the descriptor (`ctx = NULL`), on
 *     entry — see the same note in mmcs_air_fold.h for why the state alone is
 *     not enough.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_ZK_TRANSCRIPT_AIR_FOLD_H
#define DNAC_ZK_TRANSCRIPT_AIR_FOLD_H

#include <stddef.h>

#include "stark_constraints.h" /* dnac_stark_air_t / dnac_stark_folder_t */
#include "transcript_air.h"    /* TAIR_* layout + dnac_tair_config_t      */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Fold steps contributed by the blocks whose count does NOT depend on the
 * script — transcript_air.c blocks A..L plus terminality:
 *   A  one-hots      28  (6 sel bool + 1 sum; 5x2 il/ol bool + 2 sums;
 *                         5 pc bool + 1 sum; A2 1; A3 2)
 *   C  row-0 boundary 1
 *   D  sample bits   69 + pow_bits  (64 bool + recomp + 3 canon + 1 low-sum
 *                                    + pow_bits PoW lanes)
 *   E  DS prefix      5
 *   T  table conform  9 + total_bits  (6 CT-1 + 1 CT-2 + 1 CT-3a + 1 CT-3b
 *                                     + one lane per exported bit for CT-4)
 *   F  sel_start     11
 *   G  prefix thread 10
 *   H  sel_obs       22
 *   I  sel_obs_dup   23
 *   J  sel_sample    23
 *   K  sel_sample_dup 39
 *   L  sel_filler    23
 *   M  terminality    1
 *   ------------------------------------------------------------------
 *   control total    264 + pow_bits + total_bits
 * plus block B, the INLINE 180-column Poseidon2 block folded UNGATED through the
 * shared `dnac_poseidon2_fold_eval` (transcript_air.c <-> the shipped fold
 * precedent conf_action_fold.c:133-185).
 *
 * ⚠ DERIVED, NOT ASSERTED. `tests/test_transcript_air_fold.c` T-CNT compares
 * `dnac_transcript_air_fold_control_steps` against the MEASURED
 * `folder.capture_len` on every row of every honest trace, and separately
 * MEASURES the Poseidon2 block's own step count by running
 * `dnac_poseidon2_fold_eval` on an isolated folder. Nothing here is a
 * hand-counted claim about code the test does not re-measure.
 */
#define TAIR_FOLD_SCRIPT_FREE_STEPS ((size_t)264)

/**
 * @brief Fold steps this AIR emits per row for (`cfg`, `sched`).
 * @return TAIR_FOLD_SCRIPT_FREE_STEPS + cfg->pow_bits +
 *         `dnac_tair_total_bits(sched)`, or 0 on a rejected pair.
 */
size_t dnac_transcript_air_fold_control_steps(const dnac_tair_config_t *cfg,
                                              const dnac_tair_script_t *sched);

/**
 * @brief The cfg + script snapshot `dnac_transcript_air_fold_eval` runs on — the
 *        object `dnac_stark_air_t::ctx` points at (FLEET 034).
 *
 * PUBLIC only so the caller can OWN the storage; the fields are this module's
 * business. Fill it ONLY through `dnac_transcript_air_fold_bind`. A zeroed state
 * is "unbound" and fails closed.
 */
typedef struct {
    int      bound;
    size_t   pow_bits;
    unsigned trailing; /**< trailing-zero run of p-1 (transcript_air.c:79-84) */
    /** s3a: the pinned schedule. The POINTER is retained — the script and the
     *  arrays it names must outlive every eval under this binding (header). */
    const dnac_tair_script_t *sched;
    size_t num_publics;
} dnac_tair_fold_state_t;

/**
 * @brief Bind the pinned cfg + script into `state` and fill the descriptor.
 *
 * @param cfg      pinned transcript-AIR config. `pow_bits > TAIR_MAX_NUM_BITS`
 *                 is rejected (the same gate as transcript_air.c), as is a
 *                 `pow_bits` that disagrees with the script's PoW ops. The field
 *                 shape the canonicality ADAPTATION depends on (p-1 ==
 *                 [ones][trailing zeros]) is re-checked here, once, instead of
 *                 per row.
 * @param sched    the pinned op script (`transcript_air_table.h`). The POINTER
 *                 is retained: the script and the arrays it names MUST outlive
 *                 every `air_eval` call made under this binding.
 * @param state    CALLER-OWNED storage for the snapshot; must outlive every
 *                 `air_eval` call made under this binding. Left UNBOUND
 *                 (`state->bound == 0`) on rejection, never partially armed.
 * @param out_air  filled on success with {TAIR_WIDTH,
 *                 dnac_tair_num_publics(sched), main_next = 1, air_eval,
 *                 ctx = state}. On FAILURE its `ctx` is set to NULL (DISARMED)
 *                 and its shape fields are left as the caller had them.
 * @return 0 on success, non-zero on a rejected pair / NULL argument
 *         (fail-close: a failed bind DISARMS both `state` and `out_air->ctx`,
 *         so no stale cfg can survive a rejected re-bind).
 */
int dnac_transcript_air_fold_bind(const dnac_tair_config_t *cfg,
                                  const dnac_tair_script_t *sched,
                                  dnac_tair_fold_state_t *state,
                                  dnac_stark_air_t *out_air);

/**
 * @brief The fold-form eval (the `dnac_stark_air_t::air_eval` callback).
 *
 * Exposed for the equivalence tests (and for a caller that already holds a
 * descriptor); production callers get it through `dnac_transcript_air_fold_bind`.
 * Reads its snapshot from `folder->ctx` (a `const dnac_tair_fold_state_t *`),
 * plus `folder->trace_local` / `trace_next` (TAIR_WIDTH each),
 * `folder->preprocessed_local` (>= TAIR_TBL_COLS) and `folder->public_values`,
 * and emits the constraint stream described above. Emits ONE unsatisfiable
 * constraint if `ctx` is NULL, the state is unbound, or the folder shape does
 * not match the binding.
 */
void dnac_transcript_air_fold_eval(dnac_stark_folder_t *folder);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ZK_TRANSCRIPT_AIR_FOLD_H */
