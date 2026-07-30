/**
 * @file mmcs_air_fold.h
 * @brief s1a — the P2b slice-1 (SAME-HEIGHT) MMCS-verify control AIR in
 *        VERIFIER-FOLD form (fp2 alpha-fold over the opened window at zeta).
 *
 * Build spec (authoritative): dnac/docs/plans/2026-07-29-composition-s1a-fold-
 * evals-BUILDABLE.md (local-only) — §2 API contract, §3 transcription rules,
 * §4 equivalence tests, §5 prohibitions.
 *
 * ── What this module is, and what it is NOT ─────────────────────────────────
 * `mmcs_air.{c,h}` is a CONCRETE-TRACE checker (`dnac_mmcs_air_eval_row` /
 * `_eval_trace` walk u64 cells and COUNT violations). A batch-STARK verifier
 * evaluates the constraint polynomial ONCE at zeta over the opened fp2 values,
 * alpha-folding every constraint in the prover's order (`dnac_stark_folder_t`,
 * stark_constraints.h:262-283; `dnac_stark_air_t`, :284-291). This module is
 * that fold-form eval and NOTHING else.
 *
 * NO NEW CONSTRAINT IS INVENTED HERE. The constraint SET is exactly the u64
 * evaluator's per-row + transition set, in the u64 EMISSION ORDER. Every block
 * cites the `mmcs_air.c` range it transcribes.
 *
 * ── The schedule has ONE authority, still ───────────────────────────────────
 * `mmcs_air.c`'s `mair_schedule` (:66-108) is static, so this module reads the
 * SAME schedule back out through the module's own PUBLIC accessors —
 * `dnac_mmcs_air_leaf_rows` / `_total_width` / `_pub_opened_off` /
 * `_num_publics` (mmcs_air.c:118-140), each of which internally runs
 * `mair_schedule` and returns 0 on a rejected config. Nothing about the row
 * schedule is re-derived here; a config the u64 module rejects is rejected here
 * too, by construction. The one derived quantity is the per-block absorb count,
 * which is `mair_absorb_count`'s formula (mmcs_air.c:110-114) over those same
 * scalars — needed because the leaf-absorb constraints are per-block.
 *
 * ── Selector mapping (spec §3.2) ────────────────────────────────────────────
 *   u64 `is_first_row` argument (mmcs_air.c:260) -> `when(is_first_row, ·)`
 *   everything after `if (!main_next) return v;`  -> multiplied by
 *   (mmcs_air.c:322)                                 `is_transition`
 *   u64 `eval_trace` TERMINALITY (mmcs_air.c:445-451: the last row's three
 *   preprocessed selectors must all be zero) -> `when(is_last_row, is_leaf +
 *   is_compress + is_final)`, the "typed-flag sum == 0" form the spec §3.2
 *   prescribes for this AIR. Emitted LAST, mirroring the u64 order.
 *
 * ⚠ DEGREE. mmcs_air.h:57-62 documents "degree <= 3", counting the placement
 * pair (`is_compress' · dir' · linear`) and the step advance (`pos · prep_sum ·
 * linear`) as the degree-3 forms. That count does NOT include a transition
 * selector — the u64 evaluator has none, it just skips the block on the last
 * row. Multiplying by `is_transition` (mandated by the selector mapping) makes
 * those two forms DEGREE 4 here. Consequence of the form, not a choice; the s1b
 * composition entry must size `log_num_qc` for the composed system's real max
 * degree.
 *
 * ── s1b ENTRY duties — NOT carried here (spec §3.2) ─────────────────────────
 *   G4a  SCHEDULE CONFORMANCE (`n_rows == dnac_p2b_table_rows(cfg)`,
 *        mmcs_air.c:408-413). A fold eval sees ONE window and has no row count;
 *        the trace height is pinned by the batch descriptor's `degree_bits`.
 *   G6   PUBLICS CANONICALITY (`publics[i] < GOLDILOCKS_P`, mmcs_air.c:187-196).
 *        Unreachable from a folder: `folder->public_values` is already
 *        `gold_fp_t`, so the raw-u64 alias the u64 entry rejects cannot be
 *        observed. The entry MUST check it on the DECODED publics — the
 *        red-verify A2-F1 finding does not disappear, it MOVES.
 *   PIN-1 / PIN-2 (mmcs_air.h:29-43) are unchanged and still un-enforced: the
 *        preprocessed root must be compared to DNAC_P2B_PREP_ROOT and the
 *        descriptor must set `prep_next = 1`, both at the composition entry.
 *        This module reads `folder->preprocessed_local/next` raw, exactly as the
 *        u64 reads its prep window raw.
 *   OBL-4 (mmcs_air.h:97-104) — PIN-1 binds the SCHEDULE, not the cfg. The cfg
 *        bound here must be pinned INDEPENDENTLY of the table root.
 *
 * ── Binding contract (spec §2) ──────────────────────────────────────────────
 * `air_eval` has no ctx parameter (stark_constraints.h:290) — shared surface
 * this slice may not change — so the cfg is bound into MODULE-STATIC state:
 *   - SINGLE-THREADED; one bound cfg at a time.
 *   - Bind BEFORE `dnac_batch_verify` / `dnac_batch_prove`; do not change the
 *     cfg for the duration of that call. The bound state holds a POINTER to the
 *     caller's cfg only indirectly (the derived scalars are copied), but the
 *     caller's `cfg->widths` array is NOT retained.
 *   - Pure function of the pinned cfg — no clock, no RNG, no wire data — so two
 *     nodes binding the same cfg emit the identical constraint stream.
 *   - Unbound (or after a REJECTED bind) `air_eval` emits ONE unsatisfiable
 *     constraint. Fail-close, never fail-open.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_ZK_MMCS_AIR_FOLD_H
#define DNAC_ZK_MMCS_AIR_FOLD_H

#include <stddef.h>

#include "mmcs_air.h"          /* MAIR_* layout + dnac_p2b_table_cfg_t helpers */
#include "stark_constraints.h" /* dnac_stark_air_t / dnac_stark_folder_t       */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Number of CONTROL fold steps this AIR emits per row (i.e. excluding
 *        the embedded 180-column Poseidon2 block, which is folded through the
 *        shared `dnac_poseidon2_fold_eval`).
 *
 * ⚠ DERIVED, NOT ASSERTED. `tests/test_mmcs_air_fold.c` T-CNT compares this
 * against the MEASURED `folder.capture_len` on every row of every honest trace,
 * with the Poseidon2 term measured separately by running the shared block fold
 * on an isolated folder. A wrong formula here turns that test red.
 *
 * Composition (u64 block -> count), mmcs_air.c blocks B..J + terminality:
 *   B  dir boolean + off-compress        :216-226      2
 *   C  step one-hot (2 per slot)         :228-255    2*MAIR_MAX_STEPS + 1
 *      + row-0 anchor                    :260          1
 *   D  leaf absorb (Σ absorb counts)     :262-290    total_width
 *      + first-block zero fill                       (PERM_WIDTH - absorb(0))
 *   E  index binding                     :292-308    depth
 *   F  final-row root equality           :310-320    DIGEST_LANES
 *   G  step advance + overflow guard     :330-339    MAIR_MAX_STEPS
 *   H  leaf state threading              :341-354    Σ_{blk=1..leaf-1}
 *                                                      (PERM_WIDTH - absorb(blk))
 *   I  placement pair                    :356-387    2 * DIGEST_LANES
 *   J  final-row threading               :389-397    DIGEST_LANES
 *   M  terminality (from eval_trace)     :445-451      1
 *
 * @return the count, or 0 for a config the schedule authority rejects.
 */
size_t dnac_mmcs_air_fold_control_steps(const dnac_p2b_table_cfg_t *cfg);

/**
 * @brief Bind the pinned opening shape to this module and fill the descriptor.
 *
 * @param cfg      the pinned same-height opening shape. Accepted iff the u64
 *                 module's schedule authority accepts it (see the header note).
 * @param out_air  filled on success with {MAIR_WIDTH,
 *                 dnac_mmcs_air_num_publics(cfg), main_next = 1, air_eval}.
 *                 UNTOUCHED on failure.
 * @return 0 on success, non-zero on a rejected cfg / NULL argument (a failed
 *         bind also DISARMS any previous binding).
 */
int dnac_mmcs_air_fold_bind(const dnac_p2b_table_cfg_t *cfg,
                            dnac_stark_air_t *out_air);

/**
 * @brief The fold-form eval (the `dnac_stark_air_t::air_eval` callback).
 *
 * Reads `folder->trace_local` / `trace_next` (MAIR_WIDTH each),
 * `folder->preprocessed_local` / `preprocessed_next` (>= DNAC_P2B_TABLE_COLS
 * cells each — a `prep_next = 1` descriptor's shape, PIN-2) and
 * `folder->public_values`. Emits ONE unsatisfiable constraint if the module is
 * unbound or the folder shape does not match the binding.
 */
void dnac_mmcs_air_fold_eval(dnac_stark_folder_t *folder);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ZK_MMCS_AIR_FOLD_H */
