/**
 * @file mmcs_mixed_air_fold.h
 * @brief s1a — the P2b slice-2 (MIXED-HEIGHT) MMCS-verify control AIR in
 *        VERIFIER-FOLD form (fp2 alpha-fold over the opened window at zeta).
 *
 * Build spec (authoritative): dnac/docs/plans/2026-07-29-composition-s1a-fold-
 * evals-BUILDABLE.md (local-only) — §2 API contract, §3 transcription rules,
 * §4 equivalence tests, §5 prohibitions.
 *
 * ── What this module is, and what it is NOT ─────────────────────────────────
 * `mmcs_mixed_air.{c,h}` is a CONCRETE-TRACE checker (`dnac_mmix_air_eval_row` /
 * `_eval_trace` walk u64 cells and COUNT violations). A batch-STARK verifier
 * evaluates the constraint polynomial ONCE at zeta over the opened fp2 values,
 * alpha-folding every constraint in the prover's order. This module is that
 * fold-form eval and NOTHING else.
 *
 * NO NEW CONSTRAINT IS INVENTED HERE. The constraint SET is exactly the u64
 * evaluator's per-row + transition set, in the u64 EMISSION ORDER. Every block
 * cites the `mmcs_mixed_air.c` range it transcribes.
 *
 * ── Where the schedule comes from (and the ONE duplication, declared) ───────
 * `mmcs_mixed_air.c`'s `mmix_build` (:81-190) is static. This module rebuilds
 * the SAME per-step map, but it does NOT re-derive the schedule ORDER by hand:
 * it decodes it out of the table module's own row decoder
 * `dnac_p2c_mmix_table_row` (mmcs_mixed_air_table.h:470-471), which is the
 * generator's decoded form and therefore the schedule authority PIN-1-MMIX pins.
 * Type / level / group / has_inject per scheduled step all come from there.
 *
 * ⚠ DECLARED DUPLICATION — two cfg-arithmetic helpers have no public accessor
 * and are re-derived here from the SAME cfg scalars the u64 module uses:
 *   - the per-group absorb concat `Σ_{m in group}(widths[m] + salt_elems)`
 *     (mmcs_mixed_air.c:128-133) and the per-block absorb count
 *     (mmcs_mixed_air.c:212-217);
 *   - the absorb-stream -> public-index map `mmix_stream_pub`
 *     (mmcs_mixed_air.c:196-208): per member matrix in MATRIX order,
 *     [data(widths[m]) ‖ salt(salt_elems)], with salt slots UNBOUND.
 * Both are cross-checked against the table module's own accessors
 * (`dnac_p2c_mmix_group_leaf_rows`, `_sched_rows`, `_num_groups`) and against
 * `dnac_mmix_air_num_publics`; any disagreement is a fail-close reject rather
 * than a guess (the mmcs_air.c:83-84 discipline). The equivalence test is what
 * proves the two derivations agree on real traces.
 *
 * ── Selector mapping (spec §3.2) ────────────────────────────────────────────
 *   u64 `is_first_row` argument      -> UNUSED, exactly as in the u64
 *                                       (mmcs_mixed_air.c:271: the row-0 anchor
 *                                       is PREPROCESSED here, pinned under
 *                                       PIN-1-MMIX). No boundary is emitted.
 *   everything after                 -> multiplied by `is_transition`
 *   `if (!main_next) return v;`
 *   (mmcs_mixed_air.c:379)
 *   u64 `eval_trace` TERMINALITY     -> `when(is_last_row, 1 - is_pad)`
 *   (mmcs_mixed_air.c:472-486)
 *
 * ⚠ TERMINALITY IS NARROWER THAN THE u64 GATE, BY SPEC. The u64 gate requires
 * `is_pad == 1` AND each of the five other primary type flags == 0 (six raw-cell
 * conditions, mmcs_mixed_air.c:479-485). Spec §3.2 prescribes ONE boundary
 * constraint per AIR, "mmix/oi: kendi is_pad'i" — so only `1 - is_pad == 0` is
 * carried. The residual five are the table generator's TYPE-EXCLUSIVITY
 * obligation (`DNAC_P2C_MMIX_DEFECT_TYPE_EXCLUSIVE`,
 * mmcs_mixed_air_table.h:324, checked by `dnac_p2c_mmix_table_validate`) under
 * PIN-1-MMIX — the same posture the whole AIR already takes toward preprocessed
 * cells (nothing on the verify path checks them; the root pin does). Stated
 * here rather than left implicit: without PIN-1-MMIX a table could set BOTH
 * `is_pad` and `is_final` on the last row and this boundary would not see it.
 *
 * ⚠ DEGREE. mmcs_mixed_air.h:69-74 documents "degree <= 3", the degree-3 forms
 * being the two halves of the running-digest placement pair. That count does NOT
 * include a transition selector — the u64 evaluator has none. Multiplying by
 * `is_transition` makes those two forms DEGREE 4 here. Consequence of the form,
 * not a choice; the s1b composition entry must size `log_num_qc` accordingly.
 *
 * ── s1b ENTRY duties — NOT carried here (spec §3.2) ─────────────────────────
 *   G4a  SCHEDULE CONFORMANCE (`n_rows == dnac_p2c_mmix_table_rows(cfg)`,
 *        mmcs_mixed_air.c:467-470) — a fold eval has no row count; the trace
 *        height is pinned by the batch descriptor's `degree_bits`.
 *   G6   PUBLICS CANONICALITY (mmcs_mixed_air.c:285-290) — unreachable from a
 *        folder (`folder->public_values` is already `gold_fp_t`). The entry MUST
 *        check it on the DECODED publics; OBL-2 does not disappear, it MOVES.
 *   PIN-1-MMIX / PIN-2 (mmcs_mixed_air.h:43-57) unchanged and still
 *        un-enforced; plus the whole OBL-1..OBL-9 ledger (mmcs_mixed_air.h:
 *        122-157), which this transcription neither discharges nor widens.
 *
 * ── Binding contract (spec §2) ──────────────────────────────────────────────
 * `air_eval` has no ctx parameter (stark_constraints.h:290), so the cfg is bound
 * into MODULE-STATIC state: SINGLE-THREADED, bound BEFORE
 * `dnac_batch_verify`/`_prove` and unchanged for that call, a pure function of
 * the pinned cfg (no clock / RNG / wire data), and unbound-or-rejected means
 * `air_eval` emits ONE unsatisfiable constraint. The cfg's `widths` / `heights`
 * arrays are NOT retained — every derived scalar is copied at bind time.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_ZK_MMCS_MIXED_AIR_FOLD_H
#define DNAC_ZK_MMCS_MIXED_AIR_FOLD_H

#include <stddef.h>

#include "mmcs_mixed_air.h"    /* MMIX_* layout + the cfg + public helpers */
#include "stark_constraints.h" /* dnac_stark_air_t / dnac_stark_folder_t   */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Number of CONTROL fold steps this AIR emits per row (i.e. excluding
 *        the embedded 180-column Poseidon2 block).
 *
 * ⚠ DERIVED, NOT ASSERTED. `tests/test_mmcs_mixed_air_fold.c` T-CNT compares
 * this against the MEASURED `folder.capture_len` on every row of every honest
 * trace, with the Poseidon2 term measured separately. A wrong formula here turns
 * that test red.
 *
 * Composition (u64 block -> count), mmcs_mixed_air.c blocks B..L + terminality:
 *   B  dir boolean + off-compress        :308-316    2
 *   C  (inject-)leaf absorb              :318-347    total_opened
 *                                                    + Σ_groups (PERM_WIDTH
 *                                                      - absorb(g, 0))
 *      (salt slots emit NOTHING — they are unbound witness, OBL-6)
 *   D  index binding                     :349-359    depth
 *   E  final-row root equality           :361-367    DIGEST_LANES
 *   F  inject-compress LEFT == RDIG      :369-377    DIGEST_LANES
 *   G  running-digest placement pair     :391-402    2 * DIGEST_LANES
 *   H  final-row threading               :404-409    DIGEST_LANES
 *   I  inject-compress RIGHT             :411-417    DIGEST_LANES
 *   J  RDIG seed                         :419-423    DIGEST_LANES
 *   K  RDIG carry                        :425-431    DIGEST_LANES
 *   L  (inject-)leaf state threading     :434-453    Σ_groups Σ_{b>=1}
 *                                                      (PERM_WIDTH - absorb(g,b))
 *   M  terminality (from eval_trace)     :472-486    1
 *
 * @return the count, or 0 for a config the table module rejects.
 */
size_t dnac_mmix_air_fold_control_steps(const dnac_p2c_mmix_table_cfg_t *cfg);

/**
 * @brief Bind the pinned mixed-height opening shape and fill the descriptor.
 *
 * @param cfg      the pinned shape. Accepted iff the table module accepts it AND
 *                 this module's re-derived absorb schedule agrees with the table
 *                 module's accessors (see the DECLARED DUPLICATION note).
 * @param out_air  filled on success with {MMIX_WIDTH,
 *                 dnac_mmix_air_num_publics(cfg), main_next = 1, air_eval}.
 *                 UNTOUCHED on failure.
 * @return 0 on success, non-zero on reject (a failed bind also DISARMS any
 *         previous binding).
 */
int dnac_mmix_air_fold_bind(const dnac_p2c_mmix_table_cfg_t *cfg,
                            dnac_stark_air_t *out_air);

/**
 * @brief The fold-form eval (the `dnac_stark_air_t::air_eval` callback).
 *
 * Reads `folder->trace_local` / `trace_next` (MMIX_WIDTH each),
 * `folder->preprocessed_local` / `preprocessed_next` (>= DNAC_P2C_MMIX_TABLE_COLS
 * cells each — a `prep_next = 1` descriptor's shape, PIN-2) and
 * `folder->public_values`. Emits ONE unsatisfiable constraint if the module is
 * unbound or the folder shape does not match the binding.
 */
void dnac_mmix_air_fold_eval(dnac_stark_folder_t *folder);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ZK_MMCS_MIXED_AIR_FOLD_H */
