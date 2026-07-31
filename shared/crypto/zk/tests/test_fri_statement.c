/**
 * @file test_fri_statement.c
 * @brief Composition s1b + s1c + s2 + s3b + MULTI-QUERY + COMMIT-ROUND +
 *        INPUT-BATCH replication — gate for the FRI-verify statement ENTRY
 *        (fri_statement.{c,h}).
 *
 * ── HOW THIS TEST REUSES THE SHIPPED GATES ──────────────────────────────────
 * The honest trace builders for all five participating AIRs already exist,
 * red-teamed, in tests/test_mmcs_mixed_air.c, tests/test_mmcs_air.c,
 * tests/test_fri_air.c, tests/test_fri_oi_air.c and tests/test_transcript_air.c.
 * This file INCLUDES all five translation units rather than copying any of them
 * (the s1a pattern, test_fri_air_fold.c:48-52) — a copy could drift, and the
 * claim under test is that the ENTRY accepts exactly the traces those gates
 * accept.
 *
 * Including five at once needs more than `#define main`: they share file-scope
 * identifiers (built_t, build_trace, fails, row_of, fp, wr2, tfp, tfp2, WIDE_H,
 * CFG_WIDE, CFG_Q0, ...). Each include is therefore wrapped in a rename block
 * that prefixes every shared name, and every rename is #undef'd afterwards. A
 * missed rename is a COMPILE error, never a silent aliasing — which is why this
 * is safe to do mechanically. The shipped files are NOT modified (whitelist).
 *
 * ── WHAT IS PROVED ──────────────────────────────────────────────────────────
 *   T-CONST  the pinned public-region arithmetic in fri_statement.h agrees with
 *            every module's own layout accessor, and the pinned table heights
 *            are powers of two with the degree_bits the entry derives.
 *   T-LQ     `log_num_qc` computed from the upstream symbolic rule, derived a
 *            SECOND time here from the rule's text, agrees with the module.
 *   T-REF    the pinned cfg set is re-derived FROM THE FIXTURE (prep_pair in
 *            tools/vectors/batch_proof.json) and compared constant by constant.
 *            This is the §2 "one real inner verification" claim, and it is the
 *            only thing that keeps the pins from being decoration. s1c adds the
 *            oi derivation: the DISTINCT reduced-opening heights and the
 *            per-height acc-row COUNT, measured by walking the same four nested
 *            loops the native walks (fri_verifier.c:207/400/436/469) over the
 *            fixture's opening rounds and query-0 input proof.
 *   T-PINKAT the composed preprocessed root, recomputed here through the
 *            SHIPPED prover pipeline, equals DNAC_P2S_PREP_ROOT.
 *   T-ALIAS  the entry's ALIASED publics equal, element for element, the
 *            publics each shipped builder wrote for its own honest trace —
 *            so no later gate can pass on a misalignment both sides share.
 *            Also pins the derived degree_bits / log_num_qc / prep_next.
 *   T-SRC    the SINGLE-SOURCE property of s1c, asserted directly: the fri
 *            instance's f_init publics and its roll-in publics are the very
 *            lanes the oi instance exports as its ro publics.
 *   N-PXBOUND ►► THE ACCEPTANCE CRITERION OF THE INPUT-BATCH SLICE, and the
 *            closure proof for fri_statement.h HONEST LABEL 3. Two directions,
 *            both on the ENTRY's own output vectors:
 *              (positive) EVERY acc row's p_x public in the oi instance IS its
 *              OWN batch's mmix instance's opened-row public, at the column the
 *              native's innermost loop index names. Swept over all TOTAL_ACC
 *              rows and required to have compared exactly that many, so it is
 *              non-vacuous. s2's T-SRC/px was this for batch 0 only.
 *              (perturbation) moving ONE mmix opened lane of batch b MUST move
 *              the corresponding oi acc row. Under the s2 shape a quotient or
 *              preprocessed lane moved NOTHING in oi (their p_x came from the
 *              deleted `px_rest`), which is exactly what this catches.
 *   N-BSEP   ►► THE BATCH-AXIS SEPARATION, the exact-set counterpart of N-QSEP
 *            and N-RSEP. Perturbing a lane of batch b's opened span must move
 *            ONLY {mmix[q][b], oi[q]} — never another batch's mmix instance,
 *            never another query's anything. A collapse that fed every batch
 *            batch 0's span would move batch 0's instance for a batch-1 lane,
 *            and the exact-set comparison fires.
 *   T-REF/px the fixture MEASUREMENT the p_x alias rests on: EVERY batch's
 *            per-height (matrices, points, columns) split and opened width,
 *            which must be the pinned per-batch ones EXACTLY. The three splits
 *            are NOT equal (the quotient batch is 1 point x 2 columns where the
 *            other two are 2 x 1), which is precisely why the entry cannot use
 *            the uniform group descriptor's column count for all of them.
 *   N-PIN×N  tampering ONE cell of ONE table moves the composed root and the
 *            entry rejects at step 2; run once per table, so the test names the
 *            table even though the single composed root cannot. ⚠ This is what
 *            keeps the B mmix tables discriminated even though they are
 *            BYTE-IDENTICAL to one another at this pin (their widths do not
 *            reach the schedule — fri_statement.h's honest note): the composed
 *            root commits the matrices separately and in order.
 *   N-PINMAP a reordered / absent / missing preprocessed map or commitment is
 *            rejected — the map is part of what the composed root means.
 *   N-CANON  a >= p statement lane, and a non-boolean index bit, are rejected
 *            at step 1; plus an ORDERING check proving step 1 precedes step 2.
 *   RT-1     four honest traces -> dnac_batch_prove -> the entry accepts, and
 *            (pin-independently) the entry's OWN descriptors + aliased publics
 *            are shown to verify against that real proof.
 *   N-PIN2   `prep_next = 0` rejected: the fri table at 73 > 64 and the oi table
 *            at 106 > 64 take the zero-window capacity route and fail SHAPE
 *            outright (batch_verify.c:696-706); the mmcs table at 3 columns
 *            takes the other documented route (window zeroed, constraint check
 *            fails). Driven one level down, because the entry hard-codes
 *            prep_next = 1.
 *   N-ALIAS  flipping one bit of the single shared index is rejected for EVERY
 *            bit — and once the pin is filled, rejected by the BATCH check,
 *            which is what proves the aliased publics really are consumed.
 *            s1c adds the RO-EXPORT leg: perturbing one ro_export lane is
 *            rejected, and it is rejected because it lands in the oi instance
 *            AND the fri instance at once (the alias is the only path either
 *            has to that value). The PX leg is now N-BSEP / N-PXBOUND above.
 *
 * ⚠ N-PXREST is GONE with the field it tested, exactly as N-BITSREST went with
 * `tair_bits_rest`: `px_rest` held the acc rows no commitment bound, and every
 * acc row is mmix-aliased now. Its claim is SUBSUMED by N-PXBOUND, which makes
 * the STRONGER statement about the same rows (they are bound, not merely read).
 *   N-CFG    a proof whose fri instance was built on a DIFFERENT cfg is
 *            rejected (OBL-P2c-1).
 *
 * ── s3b additions ───────────────────────────────────────────────────────────
 *   T-REF/tair the transcript cfg is DERIVED from the s1 statement constants
 *            (each field compared against the constant it must be) and the
 *            script the entry pins is compared OP FOR OP against
 *            `dnac_tair_ref_script` — one builder, two entry points, so "the
 *            REF pin" and "the statement pin" are the same authority. The pop
 *            SHAPE the aliases index into (2 alpha + 2R beta + Q query, every
 *            query pop exporting exactly lgmh bits) is re-derived by scanning.
 *   N-POWPIN the grinding width the preprocessed root CANNOT bind (FLEET 032
 *            #30). Both pinned widths are 0, so a compile-time mismatch is not
 *            constructible; the negative drives `dnac_p2s_check_tair_pow_pin`
 *            with a SYNTHETIC pow=1 and pow=16 script instead, and separately
 *            proves the two produce a BYTE-IDENTICAL table — which is exactly
 *            why the root cannot serve as this pin.
 *   T-SRC/beta + T-SRC/alpha  the fri betas and the oi alpha ARE transcript
 *            payload lanes, asserted on the entry's own output vectors. The
 *            statement holds each value once and holds no beta / alpha field.
 *   T-SRC/index the transcript's query-0 exported bits ARE `index_bits`, and
 *            are the very lanes the fri walk's bit publics carry.
 *   N-ALIAS/beta + /alpha  perturbing one payload lane moves the tair publics
 *            AND its ONE consumer's, and moves NO other consumer's — then the
 *            entry rejects.
 *   N-ALIAS/idx flipping an index bit reaches the TRANSCRIPT's exported-bit
 *            publics too, so the index cannot be one the transcript did not
 *            produce.
 *
 * ── MULTI-QUERY additions (OBL-P2c-2 discharged) ────────────────────────────
 *   T-MAP    the instance map (1 producer at index 0, then 1 + SLOTS*q + slot)
 *            and the flat publics layout, re-derived here from the header's own
 *            rule: every instance named exactly once, every decoder round-trips,
 *            out-of-range refused by every accessor, the Q copies of a slot the
 *            same shape, the regions an exact gap-free in-order partition, and
 *            the derived Q ceiling (32-1)/(B+R+2) respected.
 *   N-QSEP   ►► THE ACCEPTANCE CRITERION. Perturbing the transcript's q-th
 *            exported bit block (= `index_bits[q]`, the alias) must move query
 *            q's instances and NOT any other query's. Under the collapse this
 *            slice removes, flipping block 1 moves nothing downstream and
 *            flipping block 0 moves EVERY query — both are caught, because the
 *            assertion is the EXACT instance set, not "something moved".
 *   N-QSHARED the values the native samples/observes ONCE (alpha :694, the
 *            betas :707, final_poly :710-713, and the two commitment roots)
 *            reach EVERY query's consumer — one statement field, Q consumers.
 *   N-PZSHARED the same claim for the CLAIMED EVALUATIONS `pz_shared`, which
 *            used to sit inside the per-query region with no justification.
 *            Perturbing a lane must move EVERY query's oi instance; one query
 *            moving alone means the alias was not built. Swept over every lane.
 *   N-QINDEP a per-query value (`ro_export[q]`, `mmcs_opened[q]`, `z_pq[q]`)
 *            reaches ONLY query q's consumers. This subsumes the old
 *            N-ALIAS/ro, each of which was a pair of booleans and is now an
 *            exact set. Its `z` leg is the counterpart of N-PZSHARED: together
 *            they pin the split so it cannot regress in either direction.
 *            (`mmix_opened[q]`'s per-query claim is now the finer
 *            (query, batch) claim of N-BSEP, so it is not repeated there.)
 *   RT       the pinned script's Q indices are printed and required to DIFFER
 *            (a constant of this pin, not a probabilistic claim), and every
 *            query's four u64 evaluators must accept their own trace.
 *
 * ⚠ N-BITSREST is GONE with the field it tested: `tair_bits_rest` held the
 * exported bit blocks no consumer modelled, and all Q are consumed now.
 *
 * ⚠ PIN-STATE DISCIPLINE. Every check passes in BOTH pin states; only the
 * PIN-DEPENDENT expectations differ. With `DNAC_P2S_PREP_ROOT` at its
 * placeholder the entry rejects at step 2 and the pin-dependent checks assert
 * exactly that. Filling it flips them to their accept form and adds the
 * T-PINKAT lane comparisons and the N-ALIAS ERR_BATCH pins. Both states are run
 * GREEN; neither is a skip. (s1c RE-PINS: adding the oi table as a fourth
 * committed preprocessed matrix moves the composed root, so the constant is
 * back at its placeholder until `--print-roots` refills it.)
 *
 * ── HONEST LABEL — what RT-1's trace VALUES are, and are not ────────────────
 * The pinned cfg SET is derived from a real inner proof and T-REF proves it
 * (that is what §2 asks for). The trace VALUES are a different matter:
 *   - mmix / mmcs: REAL. Each builder commits its own batch, opens the index and
 *     requires the SHIPPED native verifier to accept before it emits a trace
 *     (test_mmcs_mixed_air.c:145-151, test_mmcs_air.c:128-133), so all B + R of
 *     those instances replay genuine Poseidon2 MMCS openings at the pinned
 *     shapes. ⚠ HONEST NOTE on the B mmix fixtures: the shipped builder fills
 *     every matrix cell from its own `cell(m, r, c)`, which sees the WIDTH but
 *     not the batch, so batches 0 and 2 — identical cfgs at this pin — commit
 *     the SAME tree and produce the SAME root and the SAME opened row, while
 *     batch 1 (width 2) differs. That is a property of the fixture, not of the
 *     mechanism: the statement carries a root and an opened span PER BATCH
 *     regardless, and N-BSEP proves each span reaches only its own instance.
 *     `stmt_from_traces` REPORTS which batch roots coincide rather than
 *     asserting they differ, because differing is not something this pin can
 *     honestly claim.
 *   - oi: NATIVE-FORMULA REPLAY. Its builder drives the exact field expressions
 *     of `fri_open_input` — x_h from the two-adic generator and the bit-reversed
 *     index, and ro += alpha_pow*(p_z - p_x)/(z - x) per acc row
 *     (test_fri_oi_air.c:10-23) — over ITS OWN deterministic z / p_z fixtures,
 *     at the pinned shape. So the ro EXPORTS RT-1 uses are genuine reduced
 *     openings of that fixture, not of prep_pair's data.
 *     s2 NARROWED this for the MAIN batch, and the INPUT-BATCH slice finishes
 *     it: NO acc row uses the builder's p_x fixture any more. The `g_px_ext`
 *     hook feeds EVERY row its own batch's mmix instance's REAL opened lanes
 *     (each of which came out of a genuine Poseidon2 MMCS opening, above), so
 *     the whole accumulation is over real opened values. The honest gap
 *     `px_rest` carried in the statement is gone from the trace too — there is
 *     no fixture branch left in `oi_px_from_mmix`.
 *   - fri: its SIBLINGS are still the shipped deterministic fixture, but its
 *     f_init and roll-in are OVERRIDDEN with the oi instance's exported ro
 *     (s1c) and — s3b — every BETA is overridden with the transcript's own
 *     round-r pop, so the walk is seeded by the open_input result AND folded
 *     with the challenger's own challenges. What remains fixture-derived is the
 *     sibling column, which needs dnac_fri_test_verify_capture plus
 *     batch_verify's opening-round assembly (batch_verify.c:302-499) replicated
 *     test-side. That replication is a fork of consensus logic into a test and
 *     is NOT done here.
 *     ⚠ MULTI-QUERY adds ONE more construction to that column: the LAST fold
 *     row's sibling of every query is SOLVED so all Q walks land on the ONE
 *     shared `final_poly0`. A real prover gets that for free (its queries are
 *     folds of one codeword); a fixture-sibling walk does not, and making
 *     `final_poly0` per-query instead would have DROPPED the constraint. The
 *     solve is an inversion of the shipped builder's own fold expression and it
 *     is self-checked — see `fri_solve_last_sib` and the q = 0 identity check
 *     in `traces_build`.
 *   - tair: REAL for the challenger, FIXTURE for what it observes. The trace is
 *     the shipped builder's, and its pops come from replaying the shipped
 *     `duplex_challenger.c`, so alpha / the betas / the query index are genuine
 *     Fiat-Shamir outputs of the pinned script. The OBSERVED lanes past the DS
 *     prefix are deterministic fixtures — ⚠ they are NOT aliased to the mmcs /
 *     mmix roots, so "the transcript absorbed the commitment this proof opens"
 *     is NOT closed here; that is the commit-round replication slice.
 * So RT-1 is: "the entry accepts an honest 1 + (B+R+2)*Q-instance proof over
 * the pinned cfgs, where query q's instances take their index publics from the
 * transcript's OWN q-th exported block, their fri walk seed / roll-in from
 * query q's oi ro export, and EVERY acc row's p_x from query q's own opening of
 * that row's batch, while the alpha, the betas and the final_poly every query
 * folds with are ONE transcript-produced set". It is NOT "the entry accepts
 * prep_pair's queries".
 * Reported as a delta against spec §4.
 *
 * Deterministic fixtures only — NO rand() (root CLAUDE.md).
 *
 * Usage: test_fri_statement [vector.json] [--print-roots]
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

/* ══════════════ the three shipped u64 gates, reused whole ═════════════════ */

#define main        p2s_mmix_main_unused
#define fails       p2s_mmix_fails
#define built_t     p2s_mmix_built_t
#define built_free  p2s_mmix_built_free
#define build_trace p2s_mmix_build_trace
#define row_of      p2s_mmix_row_of
#define cell        p2s_mmix_cell
#define regen_perm  p2s_mmix_regen_perm
#define eval_built  p2s_mmix_eval_built
#define clone_trace p2s_mmix_clone_trace
#define clone_prep  p2s_mmix_clone_prep
#define clone_pub   p2s_mmix_clone_pub
#define expect_reject p2s_mmix_expect_reject
#define accept_case p2s_mmix_accept_case
#define bump        p2s_mmix_bump
#define fixt_t      p2s_mmix_fixt_t
#define make_fixt   p2s_mmix_make_fixt
#include "test_mmcs_mixed_air.c"
#undef main
#undef fails
#undef built_t
#undef built_free
#undef build_trace
#undef row_of
#undef cell
#undef regen_perm
#undef eval_built
#undef clone_trace
#undef clone_prep
#undef clone_pub
#undef expect_reject
#undef accept_case
#undef bump
#undef fixt_t
#undef make_fixt

#define main        p2s_mmcs_main_unused
#define fails       p2s_mmcs_fails
#define built_t     p2s_mmcs_built_t
#define built_free  p2s_mmcs_built_free
#define build_trace p2s_mmcs_build_trace
#define row_of      p2s_mmcs_row_of
#define cell        p2s_mmcs_cell
#define regen_perm  p2s_mmcs_regen_perm
#define eval_built  p2s_mmcs_eval_built
#define clone_trace p2s_mmcs_clone_trace
#define clone_prep  p2s_mmcs_clone_prep
#define clone_pub   p2s_mmcs_clone_pub
#define expect_reject p2s_mmcs_expect_reject
#define expect_bad_config p2s_mmcs_expect_bad_config
#define accept_case p2s_mmcs_accept_case
#define fixture_t   p2s_mmcs_fixture_t
#define make_fixture p2s_mmcs_make_fixture
#include "test_mmcs_air.c"
#undef main
#undef fails
#undef built_t
#undef built_free
#undef build_trace
#undef row_of
#undef cell
#undef regen_perm
#undef eval_built
#undef clone_trace
#undef clone_prep
#undef clone_pub
#undef expect_reject
#undef expect_bad_config
#undef accept_case
#undef fixture_t
#undef make_fixture
/* T_MAX_PUB is a MACRO each shipped gate defines for itself, not a name that
 * needs prefixing — dropping the definition here lets the next include define
 * its own without a redefinition warning. */
#undef T_MAX_PUB

#define main        p2s_fri_main_unused
#define fails       p2s_fri_fails
#define built_t     p2s_fri_built_t
#define built_free  p2s_fri_built_free
#define build_trace p2s_fri_build_trace
#define row_of      p2s_fri_row_of
#define eval_built  p2s_fri_eval_built
#define expect_reject p2s_fri_expect_reject
#define expect_bad_config p2s_fri_expect_bad_config
#define accept_case p2s_fri_accept_case
#define fixture_t   p2s_fri_fixture_t
#define fill_fixture p2s_fri_fill_fixture
#define bump        p2s_fri_bump
#define check       p2s_fri_check
#include "test_fri_air.c"
#undef main
#undef fails
#undef built_t
#undef built_free
#undef build_trace
#undef row_of
#undef eval_built
#undef expect_reject
#undef expect_bad_config
#undef accept_case
#undef fixture_t
#undef fill_fixture
#undef bump
#undef check
/* Same story as above: T_MAX_PUB is per-gate, so drop the fri gate's before the
 * oi gate defines its own. */
#undef T_MAX_PUB

/* ⚠ The oi gate's own headers are pulled in HERE, BEFORE its rename block. That
 * block has to rename tokens as short as `u`, `fp` and `check` (the oi gate
 * collides with the fri gate on fp / wr2 / tfp / tfp2, with the mmix gate on
 * WIDE_H / CFG_WIDE, and with the fri gate again on CFG_Q0), and a macro that
 * short must not be allowed to reach into a header. Pre-including them makes
 * the include guards swallow the second inclusion inside the renamed region. */
#include "../fri_oi_air.h"
#include "../fri_oi_air_table.h"

#define main         p2s_oi_main_unused
#define fails        p2s_oi_fails
#define fp           p2s_oi_fp
#define u            p2s_oi_u
#define emb          p2s_oi_emb
#define wr2          p2s_oi_wr2
#define tfp          p2s_oi_tfp
#define tfp2         p2s_oi_tfp2
#define bump         p2s_oi_bump
#define rev_bits     p2s_oi_rev_bits
#define g_px_ext     p2s_oi_g_px_ext
#define g_alpha_ext  p2s_oi_g_alpha_ext
#define alpha_of     p2s_oi_alpha_of
#define built_t      p2s_oi_built_t
#define row_of       p2s_oi_row_of
#define built_free   p2s_oi_built_free
#define zoff_of      p2s_oi_zoff_of
#define px_of        p2s_oi_px_of
#define build_honest p2s_oi_build_honest
#define eval_b       p2s_oi_eval_b
#define expect_reject p2s_oi_expect_reject
#define expect_bad_config p2s_oi_expect_bad_config
#define check        p2s_oi_check
#define acc_row_for_height p2s_oi_acc_row_for_height
#define closeout_row_for_height p2s_oi_closeout_row_for_height
#define first_sq_row p2s_oi_first_sq_row
#define first_seed_row p2s_oi_first_seed_row
#define WIDE_H       p2s_oi_WIDE_H
#define CFG_WIDE     p2s_oi_CFG_WIDE
#define NOLB_H       p2s_oi_NOLB_H
#define CFG_NOLB     p2s_oi_CFG_NOLB
#define NOLB_MB_H    p2s_oi_NOLB_MB_H
#define CFG_NOLB_MB  p2s_oi_CFG_NOLB_MB
#define MB_H         p2s_oi_MB_H
#define CFG_MB       p2s_oi_CFG_MB
#define H33          p2s_oi_H33
#define CFG_LGMH33   p2s_oi_CFG_LGMH33
#define HQ0          p2s_oi_HQ0
#define CFG_Q0       p2s_oi_CFG_Q0
#define HF7          p2s_oi_HF7
#define CFG_F7       p2s_oi_CFG_F7
#define accept_case  p2s_oi_accept_case
#include "test_fri_oi_air.c"
#undef main
#undef fails
#undef fp
#undef u
#undef emb
#undef wr2
#undef tfp
#undef tfp2
#undef bump
#undef rev_bits
#undef g_px_ext
#undef g_alpha_ext
#undef alpha_of
#undef built_t
#undef row_of
#undef built_free
#undef zoff_of
#undef px_of
#undef build_honest
#undef eval_b
#undef expect_reject
#undef expect_bad_config
#undef check
#undef acc_row_for_height
#undef closeout_row_for_height
#undef first_sq_row
#undef first_seed_row
#undef WIDE_H
#undef CFG_WIDE
#undef NOLB_H
#undef CFG_NOLB
#undef NOLB_MB_H
#undef CFG_NOLB_MB
#undef MB_H
#undef CFG_MB
#undef H33
#undef CFG_LGMH33
#undef HQ0
#undef CFG_Q0
#undef HF7
#undef CFG_F7
#undef accept_case

/* ⚠ Same pre-include reason as the oi gate above: the transcript gate's rename
 * block covers names as short as `fadd` and as common as `built_t`, and a macro
 * that broad must not be allowed to reach into a header. */
#include "../duplex_challenger.h"
#include "../transcript_air.h"
#include "../transcript_air_table.h"

#define main                 p2s_tair_main_unused
#define fails                p2s_tair_fails
#define slurp                p2s_tair_slurp
#define find_key             p2s_tair_find_key
#define read_quoted          p2s_tair_read_quoted
#define read_quoted_u64      p2s_tair_read_quoted_u64
#define read_u64_array       p2s_tair_read_u64_array
#define read_bare_array      p2s_tair_read_bare_array
#define read_bare_u64        p2s_tair_read_bare_u64
#define read_dup_list        p2s_tair_read_dup_list
#define vec_op_t             p2s_tair_vec_op_t
#define vec_t                p2s_tair_vec_t
#define load_vector          p2s_tair_load_vector
#define built_t              p2s_tair_built_t
#define rebind_script        p2s_tair_rebind_script
#define row_of               p2s_tair_row_of
#define fadd                 p2s_tair_fadd
#define write_bits           p2s_tair_write_bits
#define write_pre            p2s_tair_write_pre
#define regen_perm           p2s_tair_regen_perm
#define set_perm_obs_dup     p2s_tair_set_perm_obs_dup
#define set_perm_sample_dup  p2s_tair_set_perm_sample_dup
#define script_of            p2s_tair_script_of
#define build_publics        p2s_tair_build_publics
#define build_trace          p2s_tair_build_trace
#define pow_bits_of          p2s_tair_pow_bits_of
#define find_row             p2s_tair_find_row
#define stash                p2s_tair_stash
#define clone_trace          p2s_tair_clone_trace
#define clone_buf            p2s_tair_clone_buf
#define expect_reject_ex     p2s_tair_expect_reject_ex
#define expect_reject        p2s_tair_expect_reject
#define expect_reject_pair   p2s_tair_expect_reject_pair
#define synth_t              p2s_tair_synth_t
#define mk_synth             p2s_tair_mk_synth
#define synth_prep           p2s_tair_synth_prep
#define mk_sample_pair       p2s_tair_mk_sample_pair
#include "test_transcript_air.c"
#undef main
#undef fails
#undef slurp
#undef find_key
#undef read_quoted
#undef read_quoted_u64
#undef read_u64_array
#undef read_bare_array
#undef read_bare_u64
#undef read_dup_list
#undef vec_op_t
#undef vec_t
#undef load_vector
#undef built_t
#undef rebind_script
#undef row_of
#undef fadd
#undef write_bits
#undef write_pre
#undef regen_perm
#undef set_perm_obs_dup
#undef set_perm_sample_dup
#undef script_of
#undef build_publics
#undef build_trace
#undef pow_bits_of
#undef find_row
#undef stash
#undef clone_trace
#undef clone_buf
#undef expect_reject_ex
#undef expect_reject
#undef expect_reject_pair
#undef synth_t
#undef mk_synth
#undef synth_prep
#undef mk_sample_pair

/* ══════════════════════════════ our own stack ════════════════════════════ */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../batch_prover.h"
#include "../fri_statement.h"
#include "../poseidon2_mmcs.h"
#include "../stark_prover.h" /* dnac_prover_coset_lde_bitrev (pin pipeline) */
#include "logup_test_util.h" /* jv_* JSON + load_file                      */

static int g_checks = 0;
static int g_fails = 0;

#define CHECK(cond, ...)                                                       \
    do {                                                                       \
        g_checks++;                                                            \
        if (!(cond)) {                                                         \
            g_fails++;                                                         \
            printf("  FAIL: ");                                                \
            printf(__VA_ARGS__);                                               \
            printf("\n");                                                      \
        }                                                                      \
    } while (0)

/* ══════════ ONE built descriptor set — the multi-query bookkeeping ═════════
 *
 * s3b's negatives each declared five publics arrays plus five more for the
 * perturbed side; at 1 + 4*Q instances that shape does not survive. Everything
 * the entry produces now lives in ONE object, and the ONLY question the
 * negatives ask — "did instance i's publics move?" — is one function.
 *
 * FLEET 034: the fold-state storage must outlive the `insts` it arms, which is
 * why it is a member here rather than an automatic at each call site. File
 * scope rather than automatics for the whole object: ~13 KB each and several
 * call sites sit inside loops. Two of them because the negatives build TWO
 * descriptor sets side by side and each set must own its own snapshots.
 */
typedef struct {
    dnac_batch_vinstance_t insts[DNAC_P2S_NUM_INSTANCES];
    gold_fp_t              pub[DNAC_P2S_TOTAL_PUBLICS];
    dnac_p2s_fold_states_t fs;
} p2s_set_t;

static p2s_set_t g_set_a;
static p2s_set_t g_set_b;

static dnac_p2s_status_t set_build(p2s_set_t *S,
                                   const dnac_p2s_statement_t *stmt)
{
    memset(&S->fs, 0, sizeof(S->fs));
    return dnac_p2_fri_statement_build_instances(stmt, S->insts, &S->fs,
                                                 S->pub);
}

/** Instance `i`'s publics inside a built set. */
static const gold_fp_t *set_pub(const p2s_set_t *S, uint32_t i)
{
    return S->pub + dnac_p2s_pub_off(i);
}

/** 1 iff instance `i`'s publics differ between the two sets. */
static int inst_moved(const p2s_set_t *A, const p2s_set_t *B, uint32_t i)
{
    const gold_fp_t *a = set_pub(A, i), *b = set_pub(B, i);
    for (size_t k = 0; k < dnac_p2s_num_publics(i); k++) {
        if (gold_fp_to_u64(a[k]) != gold_fp_to_u64(b[k])) return 1;
    }
    return 0;
}

/** Build both sets (honest + perturbed) or report a test defect. */
static int set_pair(const dnac_p2s_statement_t *good,
                    const dnac_p2s_statement_t *bad, const char *what)
{
    if (set_build(&g_set_a, good) != DNAC_P2S_OK ||
        set_build(&g_set_b, bad) != DNAC_P2S_OK) {
        CHECK(0, "%s: build_instances rejected a canonical perturbation", what);
        return 0;
    }
    return 1;
}

/** Human-readable instance name, for negatives that report per instance.
 *  Caller-supplied buffer: two names are routinely formatted into one message,
 *  and a shared static would make the first the second. */
static const char *inst_name_r(uint32_t i, char *buf, size_t n)
{
    const size_t b = dnac_p2s_inst_batch(i);
    const size_t r = dnac_p2s_inst_round(i);
    if (i == DNAC_P2S_INST_TAIR) {
        snprintf(buf, n, "tair");
    } else if (b != (size_t)-1) {
        snprintf(buf, n, "mmix%zu[q%zu]", b, dnac_p2s_inst_query(i));
    } else if (r != (size_t)-1) {
        snprintf(buf, n, "mmcs%zu[q%zu]", r, dnac_p2s_inst_query(i));
    } else if (i < DNAC_P2S_NUM_INSTANCES) {
        snprintf(buf, n, "%s[q%zu]",
                 dnac_p2s_inst_slot(i) == DNAC_P2S_SLOT_FRI ? "fri" : "oi",
                 dnac_p2s_inst_query(i));
    } else {
        snprintf(buf, n, "inst%u", i);
    }
    return buf;
}

/** Single-use convenience wrapper (never two per message). */
static const char *inst_name(uint32_t i)
{
    static char buf[32];
    return inst_name_r(i, buf, sizeof(buf));
}

/* ── The instance MASK vocabulary the multi-query negatives speak in ────────
 * DNAC_P2S_NUM_INSTANCES is 1 + SLOTS*Q and the Q ceiling is derived so that it
 * never exceeds the batch stack's 32, so a uint32_t mask always fits; the
 * static assert says so rather than leaving it to the reader. */
typedef char p2s_mask_fits_assert
    [(DNAC_P2S_NUM_INSTANCES <= 32) ? 1 : -1];

#define P2S_TMASK        (1u << DNAC_P2S_INST_TAIR)
#define P2S_IMASK(q, s)  (1u << DNAC_P2S_INST((q), (s)))

/** The set of instances whose publics differ between g_set_a and g_set_b. */
static uint32_t moved_mask(void)
{
    uint32_t m = 0;
    for (uint32_t i = 0; i < DNAC_P2S_NUM_INSTANCES; i++) {
        if (inst_moved(&g_set_a, &g_set_b, i)) m |= 1u << i;
    }
    return m;
}

static void mask_str(uint32_t m, char *buf, size_t n)
{
    size_t used = 0;
    char nm[32];
    buf[0] = '\0';
    for (uint32_t i = 0; i < DNAC_P2S_NUM_INSTANCES && used + 1 < n; i++) {
        int w;
        if (!(m & (1u << i))) continue;
        w = snprintf(buf + used, n - used, "%s%s", used ? "," : "",
                     inst_name_r(i, nm, sizeof(nm)));
        if (w < 0) break;
        used += (size_t)w;
    }
    if (used == 0) snprintf(buf, n, "(none)");
}

/**
 * The EXACT-SET assertion every multi-query negative is written in.
 *
 * "At least one instance moved" cannot distinguish a working alias from a
 * collapsed one — under the collapse the WRONG instances move, and they move.
 * Comparing the whole set is what makes N-QSEP / N-QSHARED / N-QINDEP three
 * different claims instead of three spellings of the same one, and it makes a
 * failure self-describing: the message names both sets.
 */
static void check_mask_v(uint32_t got, uint32_t want, const char *fmt,
                         va_list ap)
{
    char where[192], sg[256], sw[256];
    g_checks++;
    if (got == want) return;
    g_fails++;
    vsnprintf(where, sizeof(where), fmt, ap);
    mask_str(got, sg, sizeof(sg));
    mask_str(want, sw, sizeof(sw));
    printf("  FAIL: %s moved {%s}, expected {%s}\n", where, sg, sw);
}

static void check_mask(uint32_t got, uint32_t want, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    check_mask_v(got, want, fmt, ap);
    va_end(ap);
}

/* ══════════ s3b — the transcript instance's honest trace + its F-S values ═══
 *
 * The tair trace is built by the SHIPPED gate's builder (`p2s_tair_build_trace`,
 * tests/test_transcript_air.c:467) — not by a copy — but that builder is VECTOR
 * driven, and no shipped `transcript_trace_*.json` carries the pinned FRI-tail
 * op stream (they are 8-19 op scenarios; the pin is 31 ops). So the vector is
 * SYNTHESIZED here from the pinned SCRIPT by replaying the shipped
 * `duplex_challenger.c` and recording what it does.
 *
 * ⚠ HONEST LABEL — what that synthesis is and is not. The shipped gate's oracle
 * cross-check (build_trace's per-op `state`/`input`/`output` comparison against
 * the vector) compares the builder's replay against OUR replay of the SAME
 * shipped challenger, so for this vector it is self-consistent rather than an
 * independent oracle. The Rust-oracle pinning of the challenger lives in
 * test_transcript_air.c's own 8 scenarios and is not re-proved here. What IS
 * proved here is the composition claim: the challenger's OWN pops are the values
 * the other four instances consume.
 *
 * The observed lanes, in three groups (HONEST LABEL 6):
 *   - the first RATE observes MUST be the DS prefix (the AIR pins them,
 *     transcript_air.c:279);
 *   - the R commit-round digest blocks ARE `mmcs_root[r]` — the round
 *     replication slice's closure. They are fed in from `mmcs_probe_roots`
 *     BEFORE the challenger runs, so every challenge this transcript squeezes,
 *     including the query indices, is downstream of the real roots;
 *   - the final poly and the per-round log_arity keep a deterministic fixture.
 *     ⚠ Those two are still NOT aliased to anything, and `mmix_root` has no
 *     observe op at all (its batch is observed during priming, outside this
 *     script) — that is the residue label 6 still declares. Stated rather than
 *     implied.
 */
typedef struct {
    p2s_tair_vec_t   *V;
    p2s_tair_built_t *B;
    /** PER QUERY — the low lgmh bits of the q-th index sample. The multi-query
     *  slice's whole subject: query q's four instances are driven by index[q],
     *  and index[q] is read out of the transcript's q-th exported bit block. */
    uint64_t          index[DNAC_P2S_NUM_QUERIES];
    uint64_t          alpha[2];                 /* SHARED: first two pops    */
    uint64_t          beta[2 * DNAC_P2S_FRI_R]; /* SHARED: per round, c0/c1  */
    int               built;
} tair_run_t;

/** Deterministic stand-in for a non-DS observed lane. Canonical by reduction. */
static uint64_t tair_obs_fixture(size_t k)
{
    return gold_fp_to_u64(gold_fp_from_u64(k * UINT64_C(0x00000001DEADBE01) +
                                           UINT64_C(0x0F1E2D3C4B5A6978)));
}

/**
 * The ordinal -> op-index map, DERIVED HERE by scanning the script for non-PoW
 * sampling ops. fri_statement.c derives the same map with its own walk; the two
 * are independent implementations of the rule stated in
 * transcript_air_table.c:296-324, which is the point (a shared helper would
 * make T-SRC compare the entry against itself).
 */
static size_t tair_pop_op(const dnac_tair_script_t *s, size_t ordinal)
{
    size_t seen = 0;
    for (size_t k = 0; k < s->n_ops; k++) {
        if (s->ops[k].kind != DNAC_TAIR_OP_SAMPLE || s->ops[k].is_pow) continue;
        if (seen == ordinal) return k;
        seen++;
    }
    return (size_t)-1;
}

/** The OBSERVE half of the same map, likewise derived HERE by scanning. Used by
 *  the honest-trace synthesizer (to observe the round roots) and by N-OBSBIND /
 *  N-OBSDEAD; fri_statement.c has its own independent walk. */
static size_t tair_obs_op(const dnac_tair_script_t *s, size_t ordinal)
{
    size_t seen = 0;
    for (size_t k = 0; k < s->n_ops; k++) {
        if (s->ops[k].kind != DNAC_TAIR_OP_OBSERVE) continue;
        if (seen == ordinal) return k;
        seen++;
    }
    return (size_t)-1;
}

/**
 * The R commit-round Merkle ROOTS, probed BEFORE the transcript exists.
 *
 * ⚠ ORDERING, and why it is not circular. Closing HONEST LABEL 6 means the
 * transcript OBSERVES round r's root, so the roots must be known before the
 * challenger runs — but the query index comes OUT of that challenger. The knot
 * unties because a round's TREE is index-independent: the shipped builder fills
 * every cell from `cell(m, r, c)` (tests/test_mmcs_air.c:114-116), so the root
 * is a function of the cfg alone and opening at index 0 reveals it. What the
 * index selects is only the opened row and the sibling path.
 *
 * That independence is not assumed: `qtraces_build_head` re-derives each round's
 * root at the query's REAL index and requires it to equal the probe.
 */
static int mmcs_probe_roots(uint64_t roots[DNAC_P2S_FRI_R][MAIR_DIGEST_LANES])
{
    for (size_t r = 0; r < DNAC_P2S_FRI_R; r++) {
        const dnac_p2b_table_cfg_t *cfg = dnac_p2s_mmcs_cfg(r);
        p2s_mmcs_fixture_t F;
        if (cfg == NULL || !p2s_mmcs_make_fixture(cfg, 0, &F)) {
            CHECK(0, "tair: could not probe commit round %zu's root", r);
            return 0;
        }
        for (size_t k = 0; k < (size_t)MAIR_DIGEST_LANES; k++) {
            roots[r][k] = F.root.lanes[k];
        }
    }
    return 1;
}

/** Replay the pinned script through the shipped challenger and record the
 *  vector the shipped trace builder consumes.
 *
 *  `roots` supplies the OBSERVED lanes of each commit round's digest block —
 *  the HONEST LABEL 6 closure seen from the witness side. Every other non-DS
 *  observe (the final poly, the per-round log_arity) keeps the deterministic
 *  fixture, which is exactly the residue that label still declares open. */
static int tair_make_vector(p2s_tair_vec_t *V, const dnac_tair_script_t *s,
                            const uint64_t roots[DNAC_P2S_FRI_R]
                                                [MAIR_DIGEST_LANES])
{
    dnac_duplex_t ch;
    size_t dup_seen = 0, obs_seen = 0;

    memset(V, 0, sizeof(*V));
    snprintf(V->scenario, sizeof(V->scenario), "p2s_fri_tail");
    for (size_t j = 0; j < (size_t)TAIR_RATE; j++) {
        V->ds_prefix[j] = DNAC_DUPLEX_DS_PREFIX[j];
    }
    V->starts[0] = 0;
    V->n_starts = 1;
    if (s->n_ops > sizeof(V->ops) / sizeof(V->ops[0])) return 0;
    V->n_ops = s->n_ops;

    /* The builder itself calls dnac_duplex_init at the instance start, so the
     * replay starts from the same fresh state. */
    dnac_duplex_init(&ch);

    for (size_t k = 0; k < s->n_ops; k++) {
        const dnac_tair_op_t *op = &s->ops[k];
        p2s_tair_vec_op_t *o = &V->ops[k];
        int duplexes;

        o->dup_index = dup_seen;
        if (op->kind == DNAC_TAIR_OP_OBSERVE) {
            /* DS prefix, then the round digests (LABEL 6), then fixtures. The
             * digest ordinals are re-derived from the script here, exactly as
             * `fri_statement.c` derives them from its own walk — two
             * independent implementations of transcript_air_table.c:296-324. */
            size_t rd = (size_t)-1, rl = 0;
            uint64_t lane;
            for (size_t r = 0; r < DNAC_P2S_FRI_R; r++) {
                for (size_t i = 0; i < (size_t)DNAC_P2M_DIGEST_LANES; i++) {
                    if (obs_seen == DNAC_P2S_OBS_DIGEST(r, i)) { rd = r; rl = i; }
                }
            }
            lane = (obs_seen < (size_t)TAIR_RATE)
                       ? DNAC_DUPLEX_DS_PREFIX[obs_seen]
                       : (rd != (size_t)-1 ? roots[rd][rl]
                                           : tair_obs_fixture(k));
            snprintf(o->type, sizeof(o->type), "observe");
            o->lane = lane;
            /* The eager duplex fires when this lane FILLS the rate buffer
             * (duplex_challenger.c:112-114). */
            duplexes = (ch.input_len == (size_t)TAIR_RATE - 1);
            dnac_duplex_observe_fp(&ch, gold_fp_from_u64(lane));
            obs_seen++;
        } else {
            if (op->is_pow) {
                /* The pinned script has no PoW op (both widths are 0). A
                 * synthesizer that silently skipped one would make N-POWPIN's
                 * sibling checks vacuous, so fail loudly instead. */
                return 0;
            }
            snprintf(o->type, sizeof(o->type),
                     op->num_bits > 0 ? "sample_bits" : "sample");
            o->bits = (uint64_t)op->num_bits;
            duplexes = (ch.input_len > 0 || ch.output_len == 0);
            o->lane = gold_fp_to_u64(dnac_duplex_sample_fp(&ch));
        }
        if (duplexes) dup_seen++;
        o->n_dup = duplexes ? 1u : 0u;

        /* Post-op snapshot — build_trace compares its own replay against these
         * after every op, which is what keeps the two in lockstep. */
        for (size_t j = 0; j < (size_t)TAIR_STATE_LANES; j++) {
            o->state[j] = ch.sponge_state[j];
        }
        o->n_in = ch.input_len;
        o->n_out = ch.output_len;
        for (size_t j = 0; j < o->n_in; j++) o->input[j] = ch.input_buffer[j];
        for (size_t j = 0; j < o->n_out; j++) o->output[j] = ch.output_buffer[j];
    }
    for (size_t j = 0; j < (size_t)TAIR_STATE_LANES; j++) {
        V->final_state[j] = ch.sponge_state[j];
    }
    return 1;
}

static void tair_free(tair_run_t *T)
{
    if (T->B) {
        free(T->B->trace);
        free(T->B->prep);
        free(T->B->pub);
        free(T->B);
        T->B = NULL;
    }
    free(T->V);
    T->V = NULL;
    T->built = 0;
}

/** Build the tair honest trace at the PINNED script and extract the F-S values
 *  the other four instances are seeded from. */
static int tair_build(tair_run_t *T,
                      const uint64_t roots[DNAC_P2S_FRI_R][MAIR_DIGEST_LANES])
{
    const dnac_tair_script_t *s = dnac_p2s_tair_script();

    memset(T, 0, sizeof(*T));
    if (s == NULL) {
        CHECK(0, "tair: the pinned script does not build");
        return 0;
    }
    T->V = (p2s_tair_vec_t *)calloc(1, sizeof(p2s_tair_vec_t));
    T->B = (p2s_tair_built_t *)calloc(1, sizeof(p2s_tair_built_t));
    if (!T->V || !T->B) { tair_free(T); return 0; }
    /* The shipped builder writes into caller-owned buffers of exactly these
     * sizes (tests/test_transcript_air.c:877-879). */
    T->B->trace = (uint64_t *)calloc((size_t)128 * TAIR_WIDTH, sizeof(uint64_t));
    T->B->prep = (uint64_t *)calloc((size_t)128 * TAIR_TBL_COLS, sizeof(uint64_t));
    T->B->pub = (uint64_t *)calloc((size_t)512, sizeof(uint64_t));
    if (!T->B->trace || !T->B->prep || !T->B->pub) { tair_free(T); return 0; }

    if (!tair_make_vector(T->V, s, roots)) {
        CHECK(0, "tair: could not synthesize the vector for the pinned script");
        tair_free(T);
        return 0;
    }
    if (!p2s_tair_build_trace(T->V, T->B)) {
        CHECK(0, "tair: the shipped honest-trace builder rejected the pinned "
                 "script's vector");
        tair_free(T);
        return 0;
    }
    T->built = 1;

    /* The builder derived its OWN script from the vector; it must be the pinned
     * one op for op, or the publics the entry indexes are not the publics this
     * trace carries. */
    if (T->B->script.n_ops != s->n_ops) {
        CHECK(0, "tair: builder script has %zu ops, pinned has %zu",
              T->B->script.n_ops, s->n_ops);
        return 0;
    }
    for (size_t k = 0; k < s->n_ops; k++) {
        if (T->B->script.ops[k].kind != s->ops[k].kind ||
            T->B->script.ops[k].is_pow != s->ops[k].is_pow ||
            T->B->script.ops[k].pow_bits != s->ops[k].pow_bits ||
            T->B->script.ops[k].num_bits != s->ops[k].num_bits) {
            CHECK(0, "tair: builder script op %zu differs from the pinned one",
                  k);
            return 0;
        }
    }

    /* ── the F-S values, read out of the trace's own payload publics ── */
    {
        const size_t ka0 = tair_pop_op(s, 0), ka1 = tair_pop_op(s, 1);
        if (ka0 == (size_t)-1 || ka1 == (size_t)-1) {
            CHECK(0, "tair: the script has no alpha pops");
            return 0;
        }
        T->alpha[0] = T->B->pub[ka0];
        T->alpha[1] = T->B->pub[ka1];
    }
    for (size_t r = 0; r < DNAC_P2S_FRI_R; r++) {
        const size_t k0 = tair_pop_op(s, 2 + 2 * r);
        const size_t k1 = tair_pop_op(s, 2 + 2 * r + 1);
        if (k0 == (size_t)-1 || k1 == (size_t)-1) {
            CHECK(0, "tair: the script has no beta pops for round %zu", r);
            return 0;
        }
        T->beta[2 * r] = T->B->pub[k0];
        T->beta[2 * r + 1] = T->B->pub[k1];
    }
    /* EVERY query's index, not just query 0's (multi-query slice). Each block
     * is read out of the transcript's own exported-bit publics, so index[q] is
     * by construction "what the challenger squeezed on its q-th sample". */
    for (size_t q = 0; q < DNAC_P2S_NUM_QUERIES; q++) {
        const size_t kq = tair_pop_op(s, 2 + 2 * DNAC_P2S_FRI_R + q);
        size_t off;
        if (kq == (size_t)-1) {
            CHECK(0, "tair: the script has no query-%zu pop", q);
            return 0;
        }
        off = dnac_tair_op_bit_off(s, kq);
        if (off == (size_t)-1) {
            CHECK(0, "tair: query %zu exports no bits", q);
            return 0;
        }
        T->index[q] = 0;
        for (size_t l = 0; l < DNAC_P2S_LGMH; l++) {
            const uint64_t b = T->B->pub[off + l];
            if (b > 1) {
                CHECK(0, "tair: query %zu exported bit %zu is not boolean", q,
                      l);
                return 0;
            }
            T->index[q] |= b << l;
        }
        /* The exported bits must BE the low bits of the popped challenge —
         * otherwise the index that query's consumers walk is not the one the
         * transcript produced, and the whole alias is decoration. */
        if ((T->B->pub[kq] & ((UINT64_C(1) << DNAC_P2S_LGMH) - 1)) !=
            T->index[q]) {
            CHECK(0, "tair: query-%zu bits are not the low bits of its "
                     "challenge", q);
            return 0;
        }
    }
    return 1;
}

/* ══════════════════════ T-CONST / T-LQ — the pinned arithmetic ═══════════ */

static void t_const(void)
{
    const dnac_p2c_table_cfg_t      *fri = dnac_p2s_fri_cfg();
    const dnac_p2c_oi_table_cfg_t   *oi = dnac_p2s_oi_cfg();

    /* ── the B input-batch cfgs, per batch ───────────────────────────────────
     * The batch axis's own T-CONST: each batch's cfg must carry that batch's
     * pinned opened WIDTH, its accessors must agree with the per-batch pinned
     * arithmetic, the batch-independent parts (matrix count, heights, depth,
     * salt) must actually be batch-independent, and the Σ the flat publics
     * layout is built on must equal the actual sum. */
    {
        size_t sum_pub = 0, sum_opened = 0;
        CHECK(dnac_p2s_mmix_cfg(DNAC_P2S_OI_NUM_BATCHES) == NULL,
              "T-CONST: an out-of-range input batch returns a cfg");
        CHECK(dnac_p2s_mmix_opened_off(DNAC_P2S_OI_NUM_BATCHES) == (size_t)-1,
              "T-CONST: an out-of-range input batch returns an opened offset");
        for (size_t b = 0; b < DNAC_P2S_OI_NUM_BATCHES; b++) {
            const dnac_p2c_mmix_table_cfg_t *c = dnac_p2s_mmix_cfg(b);
            CHECK(c != NULL, "T-CONST: input batch %zu has no pinned cfg", b);
            if (!c) continue;
            CHECK(c->num_matrices == DNAC_P2S_MMIX_NUM_MATRICES &&
                      c->depth == DNAC_P2S_MMIX_DEPTH &&
                      c->salt_elems == DNAC_P2S_MMIX_SALT_ELEMS,
                  "T-CONST: batch %zu's batch-independent shape moved", b);
            CHECK(c->heights[0] == ((size_t)1u << DNAC_P2S_MMIX_LH0) &&
                      c->heights[1] == ((size_t)1u << DNAC_P2S_MMIX_LH1),
                  "T-CONST: batch %zu's heights are not the pinned ones", b);
            for (size_t m = 0; m < c->num_matrices; m++) {
                CHECK(c->widths[m] == DNAC_P2S_MMIX_BW(b),
                      "T-CONST: batch %zu matrix %zu width %zu != pinned %zu",
                      b, m, c->widths[m], (size_t)DNAC_P2S_MMIX_BW(b));
            }
            CHECK(dnac_mmix_air_total_opened(c) ==
                      DNAC_P2S_MMIX_TOTAL_OPENED(b),
                  "T-CONST: batch %zu total_opened %zu != pinned %zu", b,
                  dnac_mmix_air_total_opened(c),
                  (size_t)DNAC_P2S_MMIX_TOTAL_OPENED(b));
            CHECK(dnac_mmix_air_num_publics(c) == DNAC_P2S_MMIX_NUM_PUBLICS(b),
                  "T-CONST: batch %zu publics %zu != pinned %zu", b,
                  dnac_mmix_air_num_publics(c),
                  (size_t)DNAC_P2S_MMIX_NUM_PUBLICS(b));
            /* The opened spans are an exact, gap-free, in-order partition. */
            CHECK(dnac_p2s_mmix_opened_off(b) == sum_opened,
                  "T-CONST: batch %zu's opened span starts at %zu, expected "
                  "%zu", b, dnac_p2s_mmix_opened_off(b), sum_opened);
            /* The REAL (points, columns) split vs the uniform descriptor's
             * block size — HONEST LABEL 5's reconciliation, re-derived here. */
            CHECK(DNAC_P2S_OI_BNP(b) * DNAC_P2S_OI_BNC(b) ==
                      DNAC_P2S_OI_ACC_PER_BATCH,
                  "T-CONST: batch %zu's split %zu x %zu != ACC_PER_BATCH %zu",
                  b, (size_t)DNAC_P2S_OI_BNP(b), (size_t)DNAC_P2S_OI_BNC(b),
                  (size_t)DNAC_P2S_OI_ACC_PER_BATCH);
            /* ...and the column count IS the opened width (fri_verifier.c:333
             * pins them to each other; they are two constants here). */
            CHECK(DNAC_P2S_OI_BNC(b) == DNAC_P2S_MMIX_BW(b),
                  "T-CONST: batch %zu's column count %zu != its opened width "
                  "%zu", b, (size_t)DNAC_P2S_OI_BNC(b),
                  (size_t)DNAC_P2S_MMIX_BW(b));
            sum_pub += DNAC_P2S_MMIX_NUM_PUBLICS(b);
            sum_opened += DNAC_P2S_MMIX_TOTAL_OPENED(b);
        }
        CHECK(sum_opened == DNAC_P2S_MMIX_ALL_OPENED,
              "T-CONST: Σ opened %zu != DNAC_P2S_MMIX_ALL_OPENED %zu",
              sum_opened, (size_t)DNAC_P2S_MMIX_ALL_OPENED);
        CHECK(sum_pub == DNAC_P2S_MMIX_ALL_PUBLICS,
              "T-CONST: Σ mmix publics %zu != DNAC_P2S_MMIX_ALL_PUBLICS %zu",
              sum_pub, (size_t)DNAC_P2S_MMIX_ALL_PUBLICS);
        /* NON-VACUITY of the whole batch axis: if every batch had the same
         * opened width the alias would be indistinguishable from the uniform
         * one the s2 shape used, and N-PXBOUND's column arithmetic would never
         * be exercised. At this pin the quotient batch is 2 where the others
         * are 1. */
        {
            int any_differs = 0;
            for (size_t b = 1; b < DNAC_P2S_OI_NUM_BATCHES; b++) {
                if (DNAC_P2S_MMIX_BW(b) != DNAC_P2S_MMIX_BW(0)) any_differs = 1;
            }
            CHECK(any_differs,
                  "T-CONST: every input batch has the SAME opened width — the "
                  "per-batch column arithmetic is untested by this pin");
        }
    }
    /* ── the R commit-round cfgs, per round ──────────────────────────────────
     * The round axis's own T-CONST: each round's cfg must carry the depth the
     * fold walk gives it, its accessors must agree with the per-round pinned
     * arithmetic, and the closed-form Σ the flat publics layout is built on
     * must equal the actual sum. */
    {
        size_t sum_pub = 0, sum_depth = 0;
        CHECK(dnac_p2s_mmcs_cfg(DNAC_P2S_FRI_R) == NULL,
              "T-CONST: an out-of-range commit round returns a cfg");
        for (size_t r = 0; r < DNAC_P2S_FRI_R; r++) {
            const dnac_p2b_table_cfg_t *c = dnac_p2s_mmcs_cfg(r);
            CHECK(c != NULL, "T-CONST: commit round %zu has no pinned cfg", r);
            if (!c) continue;
            CHECK(c->depth == DNAC_P2S_MMCS_DEPTH(r),
                  "T-CONST: round %zu depth %zu != pinned %zu", r, c->depth,
                  (size_t)DNAC_P2S_MMCS_DEPTH(r));
            CHECK(c->widths[0] == DNAC_P2S_MMCS_TOTAL_WIDTH &&
                      dnac_mmcs_air_total_width(c) ==
                          DNAC_P2S_MMCS_TOTAL_WIDTH,
                  "T-CONST: round %zu leaf width is not the arity's", r);
            CHECK(dnac_mmcs_air_num_publics(c) == DNAC_P2S_MMCS_NUM_PUBLICS(r),
                  "T-CONST: round %zu publics %zu != pinned %zu", r,
                  dnac_mmcs_air_num_publics(c),
                  (size_t)DNAC_P2S_MMCS_NUM_PUBLICS(r));
            /* BIT_OFF + DEPTH == lgmh: round r's dir window is exactly the
             * index's remaining high bits (fri_verifier.c:557-558). */
            CHECK(DNAC_P2S_MMCS_BIT_OFF(r) + DNAC_P2S_MMCS_DEPTH(r) ==
                      DNAC_P2S_LGMH,
                  "T-CONST: round %zu's bit window does not end at lgmh", r);
            sum_pub += DNAC_P2S_MMCS_NUM_PUBLICS(r);
            sum_depth += DNAC_P2S_MMCS_DEPTH(r);
        }
        CHECK(sum_depth == DNAC_P2S_MMCS_SUM_DEPTHS,
              "T-CONST: Σ depth %zu != the closed form %zu", sum_depth,
              (size_t)DNAC_P2S_MMCS_SUM_DEPTHS);
        CHECK(sum_pub == DNAC_P2S_MMCS_ALL_PUBLICS,
              "T-CONST: Σ mmcs publics %zu != DNAC_P2S_MMCS_ALL_PUBLICS %zu",
              sum_pub, (size_t)DNAC_P2S_MMCS_ALL_PUBLICS);
        /* The LAST round must land on the walk's closing height
         * (fri_verifier.c:609-611) — the arity-equality assumption's visible
         * consequence, checked rather than left to HONEST LABEL 4's prose. */
        CHECK(DNAC_P2S_MMCS_DEPTH(DNAC_P2S_FRI_R - 1) ==
                  DNAC_P2S_LOG_BLOWUP + DNAC_P2S_LFPL,
              "T-CONST: the last round folds to %zu, not log_final_height %zu",
              (size_t)DNAC_P2S_MMCS_DEPTH(DNAC_P2S_FRI_R - 1),
              (size_t)(DNAC_P2S_LOG_BLOWUP + DNAC_P2S_LFPL));
    }
    CHECK(dnac_fair_num_publics(fri) == DNAC_P2S_FRI_NUM_PUBLICS,
          "T-CONST: fri publics %zu != pinned %zu", dnac_fair_num_publics(fri),
          (size_t)DNAC_P2S_FRI_NUM_PUBLICS);
    CHECK(dnac_foi_num_publics(oi) == DNAC_P2S_OI_NUM_PUBLICS,
          "T-CONST: oi publics %zu != pinned %zu", dnac_foi_num_publics(oi),
          (size_t)DNAC_P2S_OI_NUM_PUBLICS);
    CHECK(dnac_foi_total_acc(oi) == DNAC_P2S_OI_TOTAL_ACC,
          "T-CONST: oi total_acc %zu != pinned %zu", dnac_foi_total_acc(oi),
          (size_t)DNAC_P2S_OI_TOTAL_ACC);
    /* s2 — the p_x region is APPENDED after ro, so every earlier oi offset is
     * exactly what s1c had, and the region is one BASE lane per acc row. */
    CHECK(dnac_foi_pub_px_off(oi) ==
              dnac_foi_pub_ro_off(oi) + 2 * DNAC_P2S_OI_NUM_HEIGHTS,
          "T-CONST: oi px_off %zu is not ro_off + 2*num_heights",
          dnac_foi_pub_px_off(oi));
    CHECK(dnac_foi_num_publics(oi) ==
              dnac_foi_pub_px_off(oi) + DNAC_P2S_OI_TOTAL_ACC,
          "T-CONST: the oi p_x region is not total_acc lanes long");
    /* The per-batch partition of a group has to BE a partition — every acc row
     * belongs to exactly one batch's block, which is what makes the p_x walk
     * total. */
    CHECK(DNAC_P2S_OI_ACC_PER_BATCH * DNAC_P2S_OI_NUM_BATCHES ==
              DNAC_P2S_OI_ACC_PER_HEIGHT,
          "T-CONST: ACC_PER_BATCH * NUM_BATCHES != ACC_PER_HEIGHT");

    /* R and the roll-in slot: the fold-row count is the table module's, R is
     * this header's arithmetic. */
    CHECK(dnac_p2c_fold_rows(fri) == DNAC_P2S_FRI_R,
          "T-CONST: fri fold rows %zu != R %zu", dnac_p2c_fold_rows(fri),
          (size_t)DNAC_P2S_FRI_R);
    CHECK(fri->num_rollin == DNAC_P2S_NUM_ROLLIN &&
              fri->rollin_heights[0] == DNAC_P2S_ROLLIN_0,
          "T-CONST: fri roll-in set moved");

    /* Every pinned table height must be a power of two — otherwise it has no
     * degree_bits and the entry fails closed on SHAPE. */
    for (uint32_t i = 0; i < DNAC_P2S_NUM_INSTANCES; i++) {
        const size_t rows = dnac_p2s_prep_rows(i);
        CHECK(rows != 0 && (rows & (rows - 1)) == 0,
              "T-CONST: instance %u rows %zu is not a power of two", i, rows);
        CHECK(dnac_p2s_prep_cells(i) == rows * dnac_p2s_prep_cols(i),
              "T-CONST: instance %u cell count inconsistent", i);
    }
    /* Every mixed batch's depth must be log2 of its tallest matrix — checked
     * per batch above; restated here as the one-line invariant the alias shift
     * (lgmh - depth == 0) depends on. */
    CHECK(DNAC_P2S_MMIX_DEPTH == DNAC_P2S_MMIX_LH0 &&
              DNAC_P2S_MMIX_LH0 > DNAC_P2S_MMIX_LH1,
          "T-CONST: mmix depth/heights inconsistent");

    /* ── the oi cfg: shape, the DESCENDING height array, and the STATIC
     * cross-cfg consistency the entry checks at step 3a, re-derived here from
     * the two cfgs so the entry's copy is compared against something. ── */
    CHECK(oi->lgmh == DNAC_P2S_LGMH && oi->log_blowup == DNAC_P2S_LOG_BLOWUP &&
              oi->num_heights == DNAC_P2S_OI_NUM_HEIGHTS &&
              oi->num_queries == DNAC_P2S_NUM_QUERIES,
          "T-CONST: oi scalar cfg does not match the pinned FRI shape");
    CHECK(oi->heights[0].log_height == DNAC_P2S_OI_H0 &&
              oi->heights[1].log_height == DNAC_P2S_OI_H1 &&
              oi->heights[0].log_height > oi->heights[1].log_height,
          "T-CONST: oi height array is not the pinned descending {%zu, %zu}",
          (size_t)DNAC_P2S_OI_H0, (size_t)DNAC_P2S_OI_H1);
    CHECK(oi->heights[0].log_height == oi->lgmh,
          "T-CONST: OI.H[0] != lgmh, so ro_export[0] is not the walk's seed");
    for (size_t i = 0; i < DNAC_P2S_OI_NUM_HEIGHTS; i++) {
        CHECK(dnac_p2c_oi_acc_count(&oi->heights[i]) ==
                  DNAC_P2S_OI_ACC_PER_HEIGHT,
              "T-CONST: oi group %zu has %zu acc rows, pinned %zu", i,
              dnac_p2c_oi_acc_count(&oi->heights[i]),
              (size_t)DNAC_P2S_OI_ACC_PER_HEIGHT);
        /* The C4b / C5 zero rules are VACUOUS only while no group sits at lb;
         * the entry's step-3a check (b) depends on this staying true. */
        CHECK(oi->heights[i].log_height != oi->log_blowup,
              "T-CONST: oi group %zu IS at log_blowup — C4b/C5 are no longer "
              "vacuous and the roll-in obligation changes", i);
    }
    /* Step 3a (a): every fri roll-in height is an oi height other than index 0. */
    for (size_t k = 0; k < fri->num_rollin; k++) {
        size_t found = (size_t)-1;
        for (size_t i = 0; i < oi->num_heights; i++) {
            if (oi->heights[i].log_height == fri->rollin_heights[k]) found = i;
        }
        CHECK(found != (size_t)-1 && found != 0,
              "T-CONST: fri roll-in height %zu is not a non-seed OI height",
              fri->rollin_heights[k]);
    }
}

/* ═════════ T-MAP — the multi-query instance map and publics layout ════════
 *
 * The instance ORDER is interface (fri_statement.h): the pinned preprocessed
 * root commits to it, so a silent renumbering would void the pin without
 * moving a single table cell. Everything here is re-derived from the header's
 * own rule — 1 producer at index 0, then 1 + 4q + slot — and compared against
 * the module's decoders, so the two are independent.
 */
/* The preprocessed-table scratch helpers live with the pin pipeline further
 * down; T-MAP needs them to compare the commit rounds' table CONTENT. */
static int  p2s_alloc_tables(uint64_t *tab[DNAC_P2S_NUM_INSTANCES]);
static void p2s_free_tables(uint64_t *tab[DNAC_P2S_NUM_INSTANCES]);

static void t_map(void)
{
    size_t next = 0;
    size_t seen[DNAC_P2S_NUM_INSTANCES];

    /* The per-query block is B input batches + R commit rounds + fri + oi.
     * Written out here as `B + R + 2` so the map's claim is compared against
     * arithmetic this file does independently, not against DNAC_P2S_SLOTS. */
    CHECK(DNAC_P2S_SLOTS == DNAC_P2S_OI_NUM_BATCHES + DNAC_P2S_FRI_R + 2,
          "T-MAP: %u slots per query, the map says B + R + 2 = %zu",
          DNAC_P2S_SLOTS,
          (size_t)(DNAC_P2S_OI_NUM_BATCHES + DNAC_P2S_FRI_R + 2));
    CHECK(DNAC_P2S_NUM_INSTANCES ==
              1u + (DNAC_P2S_OI_NUM_BATCHES + DNAC_P2S_FRI_R + 2) *
                       DNAC_P2S_NUM_QUERIES,
          "T-MAP: %u instances, the map says 1 + (B+R+2)*Q = %zu",
          DNAC_P2S_NUM_INSTANCES,
          (size_t)(1u + (DNAC_P2S_OI_NUM_BATCHES + DNAC_P2S_FRI_R + 2) *
                            DNAC_P2S_NUM_QUERIES));
    CHECK(DNAC_P2S_INST_TAIR == 0,
          "T-MAP: the transcript instance is not index 0 — its index must be "
          "Q-, B- and R-independent");
    /* The input batches are CONTIGUOUS and ASCENDING from slot 0, the commit
     * rounds are the contiguous block after them, and fri / oi close the
     * query — the slot order the pin's table sequence depends on. */
    CHECK(DNAC_P2S_SLOT_MMIX(0) == 0 &&
              DNAC_P2S_SLOT_MMCS(0) ==
                  DNAC_P2S_SLOT_MMIX(DNAC_P2S_OI_NUM_BATCHES - 1) + 1 &&
              DNAC_P2S_SLOT_FRI ==
                  DNAC_P2S_SLOT_MMCS(DNAC_P2S_FRI_R - 1) + 1 &&
              DNAC_P2S_SLOT_OI == DNAC_P2S_SLOT_FRI + 1,
          "T-MAP: the slot blocks are not {mmix..}{mmcs..}{fri}{oi} in order");
    /* The two RANGE predicates must be disjoint and must not swallow the "no
     * slot" sentinel — the entry's decoders are built on exactly this. */
    for (uint32_t s = 0; s <= DNAC_P2S_SLOTS; s++) {
        const int is_b = DNAC_P2S_SLOT_IS_MMIX(s) ? 1 : 0;
        const int is_r = DNAC_P2S_SLOT_IS_MMCS(s) ? 1 : 0;
        CHECK(!(is_b && is_r),
              "T-MAP: slot %u decodes as BOTH a batch and a round", s);
        if (s == DNAC_P2S_SLOTS) {
            CHECK(!is_b && !is_r,
                  "T-MAP: the 'no slot' sentinel decodes as a batch or round");
        }
        if (is_b) {
            CHECK(DNAC_P2S_SLOT_BATCH(s) < DNAC_P2S_OI_NUM_BATCHES,
                  "T-MAP: slot %u decodes to batch %zu, out of range", s,
                  DNAC_P2S_SLOT_BATCH(s));
        }
    }
    /* The batch stack's cap, and the ceiling the entry static-asserts against.
     * With B + R + 2 = 8 consumers per query, Q = 3 is the largest this shape
     * admits: 1 + 8*3 = 25 <= 32, while 1 + 8*4 = 33 would not fit. */
    CHECK(DNAC_P2S_MAX_QUERIES == 3,
          "T-MAP: the derived Q ceiling is %zu, expected (32-1)/(B+R+2) = 3",
          (size_t)DNAC_P2S_MAX_QUERIES);
    CHECK(1u + DNAC_P2S_SLOTS * DNAC_P2S_MAX_QUERIES <=
                  DNAC_P2S_BATCH_MAX_INSTANCES &&
              1u + DNAC_P2S_SLOTS * (DNAC_P2S_MAX_QUERIES + 1) >
                  DNAC_P2S_BATCH_MAX_INSTANCES,
          "T-MAP: the Q ceiling is not the LARGEST Q that fits the cap");
    CHECK(DNAC_P2S_NUM_QUERIES <= DNAC_P2S_MAX_QUERIES &&
              DNAC_P2S_NUM_INSTANCES <= DNAC_P2S_BATCH_MAX_INSTANCES,
          "T-MAP: the pinned Q overruns the batch stack's instance cap");

    /* (q, slot) round-trips through the decoders, for EVERY instance. */
    CHECK(dnac_p2s_inst_slot(DNAC_P2S_INST_TAIR) == DNAC_P2S_SLOTS &&
              dnac_p2s_inst_query(DNAC_P2S_INST_TAIR) == (size_t)-1 &&
              dnac_p2s_inst_batch(DNAC_P2S_INST_TAIR) == (size_t)-1 &&
              dnac_p2s_inst_round(DNAC_P2S_INST_TAIR) == (size_t)-1,
          "T-MAP: the transcript instance reports a query/slot/batch/round");
    CHECK(dnac_p2s_inst_slot(DNAC_P2S_NUM_INSTANCES) == DNAC_P2S_SLOTS &&
              dnac_p2s_inst_query(DNAC_P2S_NUM_INSTANCES) == (size_t)-1 &&
              dnac_p2s_inst_batch(DNAC_P2S_NUM_INSTANCES) == (size_t)-1 &&
              dnac_p2s_inst_round(DNAC_P2S_NUM_INSTANCES) == (size_t)-1 &&
              dnac_p2s_num_publics(DNAC_P2S_NUM_INSTANCES) == 0 &&
              dnac_p2s_pub_off(DNAC_P2S_NUM_INSTANCES) == (size_t)-1 &&
              dnac_p2s_prep_rows(DNAC_P2S_NUM_INSTANCES) == 0 &&
              dnac_p2s_prep_cols(DNAC_P2S_NUM_INSTANCES) == 0,
          "T-MAP: an out-of-range instance is not refused by every accessor");

    for (uint32_t i = 0; i < DNAC_P2S_NUM_INSTANCES; i++) seen[i] = 0;
    for (size_t q = 0; q < DNAC_P2S_NUM_QUERIES; q++) {
        for (uint32_t s = 0; s < DNAC_P2S_SLOTS; s++) {
            const uint32_t i = DNAC_P2S_INST(q, s);
            CHECK(i > 0 && i < DNAC_P2S_NUM_INSTANCES,
                  "T-MAP: DNAC_P2S_INST(%zu,%u) = %u is out of range", q, s, i);
            if (i >= DNAC_P2S_NUM_INSTANCES) continue;
            seen[i]++;
            CHECK(dnac_p2s_inst_slot(i) == s && dnac_p2s_inst_query(i) == q,
                  "T-MAP: instance %u decodes to (q %zu, slot %u), built from "
                  "(q %zu, slot %u)", i, dnac_p2s_inst_query(i),
                  dnac_p2s_inst_slot(i), q, s);
        }
        /* The ROUND axis round-trips too, and ONLY the mmcs slots carry one:
         * a round decoded off mmix / fri / oi would silently point the cfg
         * lookup at the wrong table. */
        for (size_t r = 0; r < DNAC_P2S_FRI_R; r++) {
            const uint32_t i = DNAC_P2S_INST(q, DNAC_P2S_SLOT_MMCS(r));
            CHECK(dnac_p2s_inst_round(i) == r &&
                      dnac_p2s_inst_batch(i) == (size_t)-1,
                  "T-MAP: instance %u decodes to (round %zu, batch %zu), built "
                  "from round %zu", i, dnac_p2s_inst_round(i),
                  dnac_p2s_inst_batch(i), r);
        }
        /* And the BATCH axis, symmetrically: only the mmix slots carry one. */
        for (size_t b = 0; b < DNAC_P2S_OI_NUM_BATCHES; b++) {
            const uint32_t i = DNAC_P2S_INST(q, DNAC_P2S_SLOT_MMIX(b));
            CHECK(dnac_p2s_inst_batch(i) == b &&
                      dnac_p2s_inst_round(i) == (size_t)-1,
                  "T-MAP: instance %u decodes to (batch %zu, round %zu), built "
                  "from batch %zu", i, dnac_p2s_inst_batch(i),
                  dnac_p2s_inst_round(i), b);
        }
        CHECK(dnac_p2s_inst_round(DNAC_P2S_INST(q, DNAC_P2S_SLOT_FRI)) ==
                      (size_t)-1 &&
                  dnac_p2s_inst_round(DNAC_P2S_INST(q, DNAC_P2S_SLOT_OI)) ==
                      (size_t)-1 &&
                  dnac_p2s_inst_batch(DNAC_P2S_INST(q, DNAC_P2S_SLOT_FRI)) ==
                      (size_t)-1 &&
                  dnac_p2s_inst_batch(DNAC_P2S_INST(q, DNAC_P2S_SLOT_OI)) ==
                      (size_t)-1,
              "T-MAP: fri or oi of q%zu reports a commit round or input batch",
              q);
    }
    seen[DNAC_P2S_INST_TAIR]++;
    for (uint32_t i = 0; i < DNAC_P2S_NUM_INSTANCES; i++) {
        CHECK(seen[i] == 1, "T-MAP: instance %u is named %zu times by the map",
              i, seen[i]);
    }

    /* The Q copies of a slot are the SAME shape — the header's honest note. */
    for (uint32_t s = 0; s < DNAC_P2S_SLOTS; s++) {
        for (size_t q = 1; q < DNAC_P2S_NUM_QUERIES; q++) {
            CHECK(dnac_p2s_prep_rows(DNAC_P2S_INST(q, s)) ==
                          dnac_p2s_prep_rows(DNAC_P2S_INST(0, s)) &&
                      dnac_p2s_prep_cols(DNAC_P2S_INST(q, s)) ==
                          dnac_p2s_prep_cols(DNAC_P2S_INST(0, s)) &&
                      dnac_p2s_num_publics(DNAC_P2S_INST(q, s)) ==
                          dnac_p2s_num_publics(DNAC_P2S_INST(0, s)),
                  "T-MAP: slot %u's copy for query %zu has a different shape",
                  s, q);
        }
    }
    /* But the ROUNDS are NOT copies of one another — the other half of that
     * honest note, and the reason the pin had to be recomputed.
     *
     * ⚠ ROW COUNT DOES NOT DISTINGUISH THEM. Depths 4/3/2 schedule 6/5/4 rows
     * and the terminality reserve pads all three to 8, so comparing heights
     * would pass vacuously. What differs is the CONTENT (each round has its own
     * compress-row count), and that is what the composed pin commits to — so
     * the tables are compared BYTE FOR BYTE here. Publics still shrink strictly
     * with the depth, which is the other observable. */
    for (size_t r = 1; r < DNAC_P2S_FRI_R; r++) {
        const uint32_t a = DNAC_P2S_INST(0, DNAC_P2S_SLOT_MMCS(r - 1));
        const uint32_t b = DNAC_P2S_INST(0, DNAC_P2S_SLOT_MMCS(r));
        CHECK(dnac_p2s_num_publics(b) < dnac_p2s_num_publics(a),
              "T-MAP: round %zu does not have fewer publics than round %zu — "
              "the dir regions are not shrinking", r, r - 1);
    }
    /* The BATCHES are likewise not interchangeable, but the observable is
     * different and the difference is the honest point: their TABLES coincide
     * (their widths do not reach the schedule), so what separates them is the
     * PUBLIC count. Asserted here, and required to be non-vacuous — if every
     * batch had the same width the batch axis would carry nothing at all. */
    {
        int differs = 0;
        for (size_t b = 1; b < DNAC_P2S_OI_NUM_BATCHES; b++) {
            const uint32_t x = DNAC_P2S_INST(0, DNAC_P2S_SLOT_MMIX(0));
            const uint32_t y = DNAC_P2S_INST(0, DNAC_P2S_SLOT_MMIX(b));
            if (dnac_p2s_num_publics(y) != dnac_p2s_num_publics(x)) differs = 1;
        }
        CHECK(differs,
              "T-MAP: every input batch declares the SAME public count — the "
              "batch axis carries neither table content nor shape");
    }
    {
        uint64_t *tab[DNAC_P2S_NUM_INSTANCES] = { 0 };
        if (!p2s_alloc_tables(tab) ||
            dnac_p2_fri_statement_prep_tables(tab) != DNAC_P2S_OK) {
            CHECK(0, "T-MAP: could not generate the preprocessed tables");
        } else {
            for (size_t r = 1; r < DNAC_P2S_FRI_R; r++) {
                const uint32_t a = DNAC_P2S_INST(0, DNAC_P2S_SLOT_MMCS(r - 1));
                const uint32_t b = DNAC_P2S_INST(0, DNAC_P2S_SLOT_MMCS(r));
                const size_t na = dnac_p2s_prep_cells(a);
                CHECK(na == dnac_p2s_prep_cells(b) &&
                          memcmp(tab[a], tab[b], na * sizeof(uint64_t)) != 0,
                      "T-MAP: commit rounds %zu and %zu have BYTE-IDENTICAL "
                      "tables — the round axis carries no content", r - 1, r);
            }
            /* and the Q copies of ONE round ARE byte-identical, which is the
             * claim the header's honest note makes in the other direction. */
            for (size_t r = 0; DNAC_P2S_NUM_QUERIES > 1 &&
                               r < DNAC_P2S_FRI_R; r++) {
                const uint32_t a = DNAC_P2S_INST(0, DNAC_P2S_SLOT_MMCS(r));
                const uint32_t b = DNAC_P2S_INST(1, DNAC_P2S_SLOT_MMCS(r));
                const size_t na = dnac_p2s_prep_cells(a);
                CHECK(na == dnac_p2s_prep_cells(b) &&
                          memcmp(tab[a], tab[b], na * sizeof(uint64_t)) == 0,
                      "T-MAP: the two queries' round-%zu tables differ", r);
            }
        }
        p2s_free_tables(tab);
    }

    /* The flat publics block is an exact, gap-free, in-order PARTITION. */
    for (uint32_t i = 0; i < DNAC_P2S_NUM_INSTANCES; i++) {
        CHECK(dnac_p2s_pub_off(i) == next,
              "T-MAP: instance %u publics start at %zu, expected %zu", i,
              dnac_p2s_pub_off(i), next);
        CHECK(dnac_p2s_num_publics(i) != 0,
              "T-MAP: instance %u declares zero publics", i);
        next += dnac_p2s_num_publics(i);
    }
    CHECK(next == DNAC_P2S_TOTAL_PUBLICS,
          "T-MAP: the regions span %zu elements, DNAC_P2S_TOTAL_PUBLICS is %zu",
          next, (size_t)DNAC_P2S_TOTAL_PUBLICS);
    CHECK(DNAC_P2S_TOTAL_PUBLICS ==
              DNAC_P2S_TAIR_NUM_PUBLICS +
                  DNAC_P2S_NUM_QUERIES * DNAC_P2S_QUERY_PUBLICS,
          "T-MAP: TOTAL_PUBLICS is not TAIR + Q*QUERY_PUBLICS");
    CHECK(DNAC_P2S_QUERY_PUBLICS ==
              DNAC_P2S_MMIX_ALL_PUBLICS + DNAC_P2S_MMCS_ALL_PUBLICS +
                  DNAC_P2S_FRI_NUM_PUBLICS + DNAC_P2S_OI_NUM_PUBLICS,
          "T-MAP: QUERY_PUBLICS is not Σ mmix + Σ mmcs + fri + oi");

    /* ── T-QCAP — the SECOND instance ceiling, MEASURED and REPORTED.
     *
     * The batch stack's 32-instance cap is not the binding one: the outer
     * proof's QUOTIENT opening round is ONE FRI input batch carrying one matrix
     * per quotient chunk of every instance (batch_verify.c:373-374 with :579),
     * and `fri_open_input` caps a single input batch's matrices at FRI_MAX_RO
     * (fri_verifier.c:218 with :41). See the full chain in fri_statement.h.
     *
     * ASSERTED, since the FRI_MAX_RO 64 → 128 raise: the pinned shape must FIT.
     * If it ever stops fitting, RT-1's prove leg dies with a
     * DNAC_PROVER_ERR_VERIFY that names nothing, so the ceiling is checked
     * here — where the numbers are — rather than diagnosed later. The
     * log_num_qc leg is checked too, because the ceiling arithmetic is only
     * about the shape the entry actually builds. ── */
    {
        const size_t lq = dnac_p2s_log_num_qc(DNAC_P2S_MAX_SYMBOLIC_DEGREE, 0);
        const size_t maxn = DNAC_P2S_FRI_RO_MAX_INSTANCES(lq);
        const size_t qc = (size_t)DNAC_P2S_NUM_INSTANCES << lq;

        CHECK(lq != (size_t)-1 && lq == 2,
              "T-QCAP: log_num_qc is %zu, the ceiling arithmetic assumes the "
              "derived 2", lq);
        CHECK(DNAC_P2S_NUM_INSTANCES <= maxn,
              "T-QCAP: %u instances x %zu quotient chunks = %zu matrices in ONE "
              "FRI input batch, over the FRI_MAX_RO %zu cap (ceiling %zu) — no "
              "honest proof of this shape is producible",
              DNAC_P2S_NUM_INSTANCES, (size_t)1u << lq, qc,
              (size_t)DNAC_P2S_FRI_MAX_RO, maxn);
        /* The mirrored cap must be the one the verifier actually compiles. It
         * is file-private to fri_verifier.c, so this cannot be a compile-time
         * comparison — but a stale mirror would make the CHECK above pass while
         * the real walk rejects, which is the exact failure the raise was meant
         * to end. The honest rail: report both, so a drift is visible in the
         * log next to the number it would invalidate. */
        printf("  [t-qcap] quotient round: %u instances x %zu chunks = %zu "
               "matrices vs FRI_MAX_RO %zu (mirror) -> instance ceiling %zu, "
               "headroom %zu\n",
               DNAC_P2S_NUM_INSTANCES, (size_t)1u << lq, qc,
               (size_t)DNAC_P2S_FRI_MAX_RO, maxn,
               (DNAC_P2S_NUM_INSTANCES <= maxn)
                   ? maxn - DNAC_P2S_NUM_INSTANCES
                   : 0);
    }
}

/* ═══════════ T-REF/tair — the tair cfg + script come from the s1 pins ══════
 *
 * §2's claim, in two halves:
 *  (a) every `dnac_tair_fri_cfg_t` field is the STATEMENT constant, not a hand
 *      written number, and
 *  (b) the script the entry pins is what `dnac_tair_fri_build_script` produces
 *      — asserted by comparing it OP FOR OP against `dnac_tair_ref_script`,
 *      which expands the same builder. Equal scripts from two entry points is
 *      what makes "the REF pin" and "the statement pin" one authority.
 */
static void t_tair_ref(void)
{
    const dnac_tair_fri_cfg_t *c = dnac_p2s_tair_fri_cfg();
    const dnac_tair_script_t *s = dnac_p2s_tair_script();
    const dnac_fri_params_t *fp = dnac_p2s_fri_params();
    dnac_tair_op_t rops[TAIR_TBL_MAX_STEPS];
    size_t rstarts[TAIR_TBL_MAX_STARTS];
    dnac_tair_script_t rs;

    CHECK(s != NULL, "T-REF/tair: the pinned script does not build");
    if (!s) return;

    /* (a) — each field against the statement constant it must be. */
    CHECK(c->R == DNAC_P2S_FRI_R, "T-REF/tair: R %zu != DNAC_P2S_FRI_R %zu",
          c->R, (size_t)DNAC_P2S_FRI_R);
    CHECK(c->log_final_poly_len == DNAC_P2S_LFPL,
          "T-REF/tair: lfpl %zu != DNAC_P2S_LFPL", c->log_final_poly_len);
    CHECK(c->num_queries == DNAC_P2S_NUM_QUERIES,
          "T-REF/tair: Q %zu != DNAC_P2S_NUM_QUERIES", c->num_queries);
    CHECK(c->lgmh == DNAC_P2S_LGMH, "T-REF/tair: lgmh %zu != DNAC_P2S_LGMH",
          c->lgmh);
    /* and the two PoW widths against the OUTER params — the same equality the
     * entry's pin enforces, checked here from the cfg side. */
    CHECK(c->commit_pow_bits == fp->commit_proof_of_work_bits &&
              c->query_pow_bits == fp->query_proof_of_work_bits,
          "T-REF/tair: the script cfg's PoW widths are not the FRI params'");

    /* (b) — op-for-op against the module's own REF expansion. */
    if (dnac_tair_ref_script(rops, TAIR_TBL_MAX_STEPS, rstarts, &rs) !=
        DNAC_TAIR_TABLE_OK) {
        CHECK(0, "T-REF/tair: dnac_tair_ref_script failed");
    } else {
        size_t bad = 0;
        CHECK(s->n_ops == rs.n_ops,
              "T-REF/tair: %zu ops vs REF %zu", s->n_ops, rs.n_ops);
        for (size_t k = 0; k < s->n_ops && k < rs.n_ops; k++) {
            if (s->ops[k].kind != rs.ops[k].kind ||
                s->ops[k].is_pow != rs.ops[k].is_pow ||
                s->ops[k].pow_bits != rs.ops[k].pow_bits ||
                s->ops[k].num_bits != rs.ops[k].num_bits) {
                bad++;
            }
        }
        CHECK(bad == 0,
              "T-REF/tair: %zu ops differ from the REF script — the statement "
              "pin and the module pin are NOT the same authority", bad);
        CHECK(s->n_starts == rs.n_starts && s->n_starts == 1,
              "T-REF/tair: instance-start count moved");
    }

    /* The counts the statement struct and the entry index by. */
    CHECK(s->n_ops == DNAC_P2S_TAIR_NUM_OPS,
          "T-REF/tair: n_ops %zu != the header's arithmetic %zu", s->n_ops,
          (size_t)DNAC_P2S_TAIR_NUM_OPS);
    CHECK(dnac_tair_num_publics(s) == DNAC_P2S_TAIR_NUM_PUBLICS,
          "T-REF/tair: num_publics %zu != pinned %zu", dnac_tair_num_publics(s),
          (size_t)DNAC_P2S_TAIR_NUM_PUBLICS);
    CHECK(dnac_tair_total_bits(s) == DNAC_P2S_TAIR_TOTAL_BITS,
          "T-REF/tair: total_bits %zu != pinned %zu", dnac_tair_total_bits(s),
          (size_t)DNAC_P2S_TAIR_TOTAL_BITS);
    CHECK(dnac_p2s_prep_cols(DNAC_P2S_INST_TAIR) == (size_t)TAIR_TBL_COLS,
          "T-REF/tair: prep width is not TAIR_TBL_COLS");
    CHECK(dnac_p2s_prep_rows(DNAC_P2S_INST_TAIR) == dnac_tair_table_rows(s),
          "T-REF/tair: prep rows disagree with the script's padded height");

    /* The DS prefix the script's first ops carry is RATE long on both sides —
     * the assumption the vector synthesizer's "first RATE observes" rule and
     * the AIR's block E share. */
    CHECK((size_t)TAIR_RATE == (size_t)DNAC_DUPLEX_RATE,
          "T-REF/tair: TAIR_RATE != DNAC_DUPLEX_RATE");

    /* The pop shape the aliases index into: 2 alpha + 2R beta + Q query, and
     * every query pop exports exactly lgmh bits. Derived here by scanning, so
     * the entry's own walk is compared against something. */
    {
        size_t npop = 0;
        for (size_t k = 0; k < s->n_ops; k++) {
            if (s->ops[k].kind == DNAC_TAIR_OP_SAMPLE && !s->ops[k].is_pow) {
                npop++;
            }
        }
        CHECK(npop == 2 + 2 * DNAC_P2S_FRI_R + DNAC_P2S_NUM_QUERIES,
              "T-REF/tair: %zu non-PoW pops, expected %zu", npop,
              (size_t)(2 + 2 * DNAC_P2S_FRI_R + DNAC_P2S_NUM_QUERIES));
        for (size_t o = 0; o < 2 + 2 * DNAC_P2S_FRI_R; o++) {
            const size_t k = tair_pop_op(s, o);
            CHECK(k != (size_t)-1 && s->ops[k].num_bits == 0,
                  "T-REF/tair: alpha/beta pop %zu exports bits", o);
        }
        for (size_t q = 0; q < DNAC_P2S_NUM_QUERIES; q++) {
            const size_t k = tair_pop_op(s, 2 + 2 * DNAC_P2S_FRI_R + q);
            CHECK(k != (size_t)-1 && s->ops[k].num_bits == DNAC_P2S_LGMH,
                  "T-REF/tair: query pop %zu does not export lgmh bits", q);
        }
    }

    /* The pinned pair passes its own pow_bits pin (the positive leg; N-POWPIN
     * is the negative one). */
    CHECK(dnac_p2s_check_tair_pow_pin(s) == DNAC_P2S_OK,
          "T-REF/tair: the pinned script fails the pow_bits pin");
}

/* ═════════ N-POWPIN — FLEET 032 #30, the root does NOT bind pow_bits ═══════
 *
 * The pinned constants make both widths 0, so a MISMATCH cannot be built out of
 * them; the negative is therefore driven with a SYNTHETIC script, exactly as
 * spec §4 allows. Two halves:
 *   (a) a script that grinds where the params do not → the entry's pin REJECTS;
 *   (b) that same script produces the SAME preprocessed root as a script with a
 *       DIFFERENT non-zero width — which is why the root cannot be the pin and
 *       this separate check has to exist at all.
 */
static void t_powpin(void)
{
    dnac_tair_fri_cfg_t c = *dnac_p2s_tair_fri_cfg();
    dnac_tair_op_t ops1[TAIR_TBL_MAX_STEPS], ops16[TAIR_TBL_MAX_STEPS];
    size_t st1[TAIR_TBL_MAX_STARTS], st16[TAIR_TBL_MAX_STARTS];
    dnac_tair_script_t s1, s16;
    size_t got = 0;

    /* (a) the mismatch: the params grind 0 bits, this script grinds 1. */
    c.query_pow_bits = 1;
    if (dnac_tair_fri_build_script(&c, ops1, TAIR_TBL_MAX_STEPS, st1, &s1) !=
        DNAC_TAIR_TABLE_OK) {
        CHECK(0, "N-POWPIN: could not build the pow=1 script");
        return;
    }
    CHECK(dnac_tair_script_pow_bits(&s1, &got) == DNAC_TAIR_TABLE_OK &&
              got == 1,
          "N-POWPIN: the pow=1 script does not report width 1 (got %zu)", got);
    CHECK(got != dnac_p2s_fri_params()->query_proof_of_work_bits,
          "N-POWPIN: the synthetic script does not actually differ from the "
          "params — the negative would be vacuous");
    CHECK(dnac_p2s_check_tair_pow_pin(&s1) == DNAC_P2S_ERR_CFG,
          "N-POWPIN: a script grinding 1 bit was ACCEPTED against 0-bit params");

    /* and the NULL rail */
    CHECK(dnac_p2s_check_tair_pow_pin(NULL) == DNAC_P2S_ERR_NULL,
          "N-POWPIN: NULL script accepted");

    /* (b) the reason the root cannot do this job: 1-bit and 16-bit grinding
     * give BYTE-IDENTICAL tables (the table has no pow-width column —
     * transcript_air_table.h:162-173), so their roots are equal. */
    c.query_pow_bits = 16;
    if (dnac_tair_fri_build_script(&c, ops16, TAIR_TBL_MAX_STEPS, st16, &s16) !=
        DNAC_TAIR_TABLE_OK) {
        CHECK(0, "N-POWPIN: could not build the pow=16 script");
        return;
    }
    CHECK(dnac_p2s_check_tair_pow_pin(&s16) == DNAC_P2S_ERR_CFG,
          "N-POWPIN: a script grinding 16 bits was ACCEPTED against 0-bit "
          "params");
    {
        const size_t rows = dnac_tair_table_rows(&s1);
        const size_t cells = rows * (size_t)TAIR_TBL_COLS;
        uint64_t *t1 = (uint64_t *)calloc(cells, sizeof(uint64_t));
        uint64_t *t16 = (uint64_t *)calloc(cells, sizeof(uint64_t));
        if (!t1 || !t16 || rows == 0 ||
            dnac_tair_table_rows(&s16) != rows) {
            CHECK(0, "N-POWPIN: the two pow widths do not even share a height");
        } else if (dnac_tair_table_generate(&s1, t1, cells) !=
                       DNAC_TAIR_TABLE_OK ||
                   dnac_tair_table_generate(&s16, t16, cells) !=
                       DNAC_TAIR_TABLE_OK) {
            CHECK(0, "N-POWPIN: table generation failed");
        } else {
            CHECK(memcmp(t1, t16, cells * sizeof(uint64_t)) == 0,
                  "N-POWPIN: the 1-bit and 16-bit tables DIFFER — the premise "
                  "of the separate pow_bits pin has changed, re-derive it");
        }
        free(t1);
        free(t16);
    }
}

static void t_lq(void)
{
    /* The rule, transcribed a SECOND time from batch-stark/src/symbolic.rs
     * :70-78 so the module's implementation is compared against something and
     * not merely re-read:
     *     constraint_degree = max(max_degree + is_zk, 2)
     *     result            = log2_ceil(constraint_degree - 1)
     * For degree 4, is_zk 0: max(4,2) = 4, log2_ceil(3) = 2, so 4 chunks. */
    struct { size_t deg; int zk; size_t want; } v[] = {
        { 2, 0, 0 }, /* max(2,2)=2, log2_ceil(1)=0 -> 1 chunk  */
        { 3, 0, 1 }, /* log2_ceil(2)=1              -> 2 chunks */
        { 4, 0, 2 }, /* log2_ceil(3)=2              -> 4 chunks */
        { 5, 0, 2 }, /* log2_ceil(4)=2              -> 4 chunks */
        { 4, 1, 2 }, /* max(5,2)=5, log2_ceil(4)=2             */
        { 1, 0, 0 }, /* the .max(2) floor is what makes this 0 */
    };
    for (size_t i = 0; i < sizeof(v) / sizeof(v[0]); i++) {
        const size_t got = dnac_p2s_log_num_qc(v[i].deg, v[i].zk);
        CHECK(got == v[i].want,
              "T-LQ: log_num_qc(deg %zu, zk %d) = %zu, want %zu", v[i].deg,
              v[i].zk, got, v[i].want);
    }
    CHECK(dnac_p2s_log_num_qc(0, 0) == (size_t)-1, "T-LQ: degree 0 not refused");
    CHECK(dnac_p2s_log_num_qc(4, 2) == (size_t)-1, "T-LQ: is_zk 2 not refused");

    /* And the value the entry actually uses. */
    CHECK(dnac_p2s_log_num_qc(DNAC_P2S_MAX_SYMBOLIC_DEGREE, 0) == 2,
          "T-LQ: the pinned degree no longer yields log_num_qc 2");
}

/* ═══════════════ T-REF — re-derive the pins FROM THE FIXTURE ══════════════ */

/**
 * Re-derive every pinned cfg scalar from scenario `prep_pair` and compare.
 * This is the §2 claim: the pins describe ONE REAL inner FRI verification.
 * Derivations mirror fri_verifier.c:640-650 (lgmh / log_final_height),
 * :557 + :585-588 (commit-round depth) and :211-243 (batch heights).
 */
static void t_ref(const jv_t *doc)
{
    const jv_t *scen = jv_get(doc, "scenarios");
    const jv_t *s = NULL;
    if (!scen || scen->kind != JV_ARR) {
        CHECK(0, "T-REF: no scenarios array");
        return;
    }
    for (size_t i = 0; i < scen->n; i++) {
        const jv_t *nm = jv_get(scen->items[i], "name");
        if (nm && nm->kind == JV_STR && !strcmp(nm->str, "prep_pair")) {
            s = scen->items[i];
            break;
        }
    }
    if (!s) {
        CHECK(0, "T-REF: scenario prep_pair not found");
        return;
    }

    /* --- FRI params --- */
    {
        const jv_t *fp = jv_get(s, "fri_params");
        uint64_t lb = 0, lfpl = 0, mla = 0, nq = 0;
        CHECK(jv_u64(jv_get(fp, "log_blowup"), &lb) &&
                  lb == DNAC_P2S_LOG_BLOWUP,
              "T-REF: log_blowup %llu != pinned %zu", (unsigned long long)lb,
              (size_t)DNAC_P2S_LOG_BLOWUP);
        CHECK(jv_u64(jv_get(fp, "log_final_poly_len"), &lfpl) &&
                  lfpl == DNAC_P2S_LFPL,
              "T-REF: log_final_poly_len %llu != pinned %zu",
              (unsigned long long)lfpl, (size_t)DNAC_P2S_LFPL);
        CHECK(jv_u64(jv_get(fp, "max_log_arity"), &mla) &&
                  mla == DNAC_P2S_MAX_LOG_ARITY,
              "T-REF: max_log_arity %llu != pinned %zu",
              (unsigned long long)mla, (size_t)DNAC_P2S_MAX_LOG_ARITY);
        CHECK(jv_u64(jv_get(fp, "num_queries"), &nq) &&
                  nq == DNAC_P2S_NUM_QUERIES,
              "T-REF: num_queries %llu != pinned %zu", (unsigned long long)nq,
              (size_t)DNAC_P2S_NUM_QUERIES);
    }

    const jv_t *op = jv_get(jv_get(s, "proof_serde"), "opening_proof");
    const jv_t *qps = jv_get(op, "query_proofs");
    if (!qps || qps->kind != JV_ARR || qps->n == 0) {
        CHECK(0, "T-REF: no query_proofs");
        return;
    }
    const jv_t *q0 = qps->items[0];

    /* --- lgmh = sum(log_arity) + log_blowup + log_final_poly_len --- */
    const jv_t *cpo = jv_get(q0, "commit_phase_openings");
    if (!cpo || cpo->kind != JV_ARR) {
        CHECK(0, "T-REF: no commit_phase_openings");
        return;
    }
    {
        uint64_t sum_la = 0;
        for (size_t r = 0; r < cpo->n; r++) {
            uint64_t la = 0;
            if (!jv_u64(jv_get(cpo->items[r], "log_arity"), &la)) {
                CHECK(0, "T-REF: log_arity unreadable at round %zu", r);
                return;
            }
            sum_la += la;
        }
        const size_t lgmh = (size_t)sum_la + DNAC_P2S_LOG_BLOWUP +
                            DNAC_P2S_LFPL;
        CHECK(lgmh == DNAC_P2S_LGMH, "T-REF: derived lgmh %zu != pinned %zu",
              lgmh, (size_t)DNAC_P2S_LGMH);
        /* R is the commit-round count AND lgmh - lb - lfpl; both must agree. */
        CHECK(cpo->n == DNAC_P2S_FRI_R,
              "T-REF: %zu commit rounds != pinned R %zu", cpo->n,
              (size_t)DNAC_P2S_FRI_R);
    }

    /* --- EVERY commit round: leaf lanes = 2*arity, depth = lgmh - (r+1)*la ---
     * The round-replication slice's grounding. Until it, only round 0 was
     * measured, because only round 0 had an instance; now every round has one
     * and every round's SHAPE is compared against the pinned per-round macro.
     * The per-round `log_arity` check is also what keeps HONEST LABEL 4 honest:
     * the entry shifts by the PINNED `max_log_arity` each round, and this is
     * where the fixture is required to agree — for all R rounds, not just the
     * first. */
    if (cpo->n == DNAC_P2S_FRI_R) {
        for (size_t r = 0; r < DNAC_P2S_FRI_R; r++) {
            const jv_t *st = cpo->items[r];
            uint64_t la = 0;
            const jv_t *ipr = jv_get(st, "opening_proof");
            const jv_t *sv = jv_get(st, "sibling_values");
            CHECK(jv_u64(jv_get(st, "log_arity"), &la) &&
                      la == DNAC_P2S_MAX_LOG_ARITY,
                  "T-REF: round-%zu log_arity != pinned max_log_arity", r);
            CHECK(sv && sv->kind == JV_ARR &&
                      sv->n == ((size_t)1u << DNAC_P2S_MAX_LOG_ARITY) - 1,
                  "T-REF: round-%zu sibling count != arity-1", r);
            CHECK(ipr && ipr->kind == JV_ARR &&
                      ipr->n == DNAC_P2S_MMCS_DEPTH(r),
                  "T-REF: round-%zu opening depth %zu != pinned %zu", r,
                  ipr ? ipr->n : (size_t)0, (size_t)DNAC_P2S_MMCS_DEPTH(r));
        }
        printf("  [t-ref]  commit rounds: %zu, depths", cpo->n);
        for (size_t r = 0; r < DNAC_P2S_FRI_R; r++) {
            printf(" %zu", (size_t)DNAC_P2S_MMCS_DEPTH(r));
        }
        printf(" (one mmcs instance each, per query)\n");
    }
    /* The leaf is the arity fp2 evals BASE-flattened: 2 lanes each, the same
     * for every round because every round's arity is the pinned one. */
    CHECK(((size_t)2u << DNAC_P2S_MAX_LOG_ARITY) == DNAC_P2S_MMCS_TOTAL_WIDTH,
          "T-REF: 2*arity != pinned mmcs total width");

    /* --- EVERY input batch: matrix count, widths, heights, depth, mixedness ---
     * The input-batch replication slice's grounding. Until it, only batch 0 was
     * measured, because only batch 0 had an instance; now every batch has one
     * and every batch's SHAPE is compared against the per-batch pinned macros.
     * This is what says the quotient batch really is 2 lanes wide and the other
     * two really are 1 — the numbers the p_x column arithmetic stands on. */
    {
        const jv_t *ip = jv_get(q0, "input_proof");
        const jv_t *insts = jv_get(s, "instances");
        const size_t want_lh[DNAC_P2S_MMIX_NUM_MATRICES] = {
            DNAC_P2S_MMIX_LH0, DNAC_P2S_MMIX_LH1
        };
        if (!ip || ip->kind != JV_ARR || ip->n == 0) {
            CHECK(0, "T-REF: no input_proof");
            return;
        }
        CHECK(ip->n == DNAC_P2S_OI_NUM_BATCHES,
              "T-REF: %zu input batches != pinned B %zu", ip->n,
              (size_t)DNAC_P2S_OI_NUM_BATCHES);
        for (size_t b = 0; b < ip->n && b < DNAC_P2S_OI_NUM_BATCHES; b++) {
            const jv_t *ovs = jv_get(ip->items[b], "opened_values");
            const jv_t *opr = jv_get(ip->items[b], "opening_proof");
            CHECK(ovs && ovs->kind == JV_ARR &&
                      ovs->n == DNAC_P2S_MMIX_NUM_MATRICES,
                  "T-REF: batch-%zu has %zu matrices, pinned %zu", b,
                  ovs ? ovs->n : (size_t)0,
                  (size_t)DNAC_P2S_MMIX_NUM_MATRICES);
            CHECK(opr && opr->kind == JV_ARR && opr->n == DNAC_P2S_MMIX_DEPTH,
                  "T-REF: batch-%zu opening depth %zu != pinned %zu", b,
                  opr ? opr->n : (size_t)0, (size_t)DNAC_P2S_MMIX_DEPTH);
            if (ovs && ovs->kind == JV_ARR &&
                ovs->n == DNAC_P2S_MMIX_NUM_MATRICES) {
                for (size_t m = 0; m < ovs->n; m++) {
                    CHECK(ovs->items[m]->kind == JV_ARR &&
                              ovs->items[m]->n == DNAC_P2S_MMIX_BW(b),
                          "T-REF: batch-%zu matrix %zu width %zu != pinned %zu",
                          b, m, ovs->items[m]->n, (size_t)DNAC_P2S_MMIX_BW(b));
                }
            }
            printf("  [t-ref]  input batch %zu: %zu matrices, width %zu each, "
                   "depth %zu (one mmix instance, per query)\n", b,
                   (size_t)DNAC_P2S_MMIX_NUM_MATRICES,
                   (size_t)DNAC_P2S_MMIX_BW(b), (size_t)DNAC_P2S_MMIX_DEPTH);
        }
        /* heights: 2^(log_ext_degree_i + log_blowup), instance order. SHARED by
         * every batch — each opening round carries one matrix per inner
         * instance at that instance's log_ext_degree (batch_verify.c:549/:569/
         * :587), which is what makes ONE heights array serve all B cfgs. */
        CHECK(insts && insts->kind == JV_ARR &&
                  insts->n == DNAC_P2S_MMIX_NUM_MATRICES,
              "T-REF: instance count != pinned matrix count");
        if (insts && insts->kind == JV_ARR &&
            insts->n == DNAC_P2S_MMIX_NUM_MATRICES) {
            for (size_t i = 0; i < insts->n; i++) {
                uint64_t led = 0;
                CHECK(jv_u64(jv_get(insts->items[i], "log_ext_degree"), &led),
                      "T-REF: log_ext_degree unreadable");
                CHECK((size_t)led + DNAC_P2S_LOG_BLOWUP == want_lh[i],
                      "T-REF: matrix %zu log-height %zu != pinned %zu", i,
                      (size_t)led + DNAC_P2S_LOG_BLOWUP, want_lh[i]);
            }
            CHECK(want_lh[0] != want_lh[1],
                  "T-REF: the pinned batches are NOT mixed-height — the mmix "
                  "instances would be describing same-height openings");
        }
        /* The mixed batch's max log-height is what the reduced index shifts by,
         * and it must be lgmh for the alias `dir[l] = bits[l]` to hold. */
        CHECK(DNAC_P2S_MMIX_DEPTH == DNAC_P2S_LGMH,
              "T-REF: mmix depth != lgmh, the mmix alias shift is not 0");
    }

    /* The roll-in set: the reduced-opening heights strictly BELOW lgmh. Here
     * {5,4} -> height 4 rolls in at fold round 0 (fri_verifier.c:600-605). */
    CHECK(DNAC_P2S_NUM_ROLLIN == 1 && DNAC_P2S_ROLLIN_0 == DNAC_P2S_MMIX_LH1,
          "T-REF: the roll-in set does not match the sub-lgmh heights");

    /* ── oi: the DISTINCT reduced-opening heights and their acc-row COUNTS ────
     * MEASURED, by walking the same four nested loops `fri_open_input` walks:
     *   batch (fri_verifier.c:207) -> matrix (:400) -> point (:436)
     *   -> claimed eval (:469),
     * one ro accumulation step per innermost visit. The fixture gives all four:
     * the batch and matrix lists plus the per-matrix POINT count come from
     * `opening_rounds` (the round assembly batch_verify.c:545-602 performs) and
     * the per-matrix claimed-eval count is the WIDTH of that matrix's opened row
     * in query 0's input proof — the quantity fri_verifier.c:333 pins against
     * `num_claimed_evals`. Matrix log-height is the instance's log_ext_degree +
     * log_blowup, exactly as :423 computes it. */
    {
        const jv_t *ip = jv_get(q0, "input_proof");
        const jv_t *rounds = jv_get(s, "opening_rounds");
        const jv_t *insts = jv_get(s, "instances");
        size_t mh[8], macc[8], nmh = 0;
        int walked = 1;

        if (!ip || ip->kind != JV_ARR || !rounds || rounds->kind != JV_ARR ||
            !insts || insts->kind != JV_ARR || ip->n != rounds->n) {
            CHECK(0, "T-REF/oi: the fixture's batch/round arrays do not line up");
            walked = 0;
        }
        if (walked) {
            CHECK(ip->n == DNAC_P2S_OI_NUM_BATCHES,
                  "T-REF/oi: %zu input batches != the pinned num_batches %zu",
                  ip->n, (size_t)DNAC_P2S_OI_NUM_BATCHES);
        }
        for (size_t b = 0; walked && b < ip->n; b++) {
            const jv_t *mats = jv_get(rounds->items[b], "matrices");
            const jv_t *ov = jv_get(ip->items[b], "opened_values");
            if (!mats || mats->kind != JV_ARR || !ov || ov->kind != JV_ARR ||
                mats->n != ov->n) {
                CHECK(0, "T-REF/oi: batch %zu matrix lists disagree", b);
                walked = 0;
                break;
            }
            for (size_t m = 0; m < mats->n; m++) {
                uint64_t ii = 0, led = 0;
                const jv_t *pts = jv_get(mats->items[m], "points");
                size_t h, np, nc, k;
                if (!jv_u64(jv_get(mats->items[m], "instance"), &ii) ||
                    ii >= insts->n ||
                    !jv_u64(jv_get(insts->items[(size_t)ii], "log_ext_degree"),
                            &led) ||
                    !pts || pts->kind != JV_ARR ||
                    ov->items[m]->kind != JV_ARR) {
                    CHECK(0, "T-REF/oi: batch %zu matrix %zu unreadable", b, m);
                    walked = 0;
                    break;
                }
                h = (size_t)led + DNAC_P2S_LOG_BLOWUP;
                np = pts->n;
                nc = ov->items[m]->n;
                for (k = 0; k < nmh; k++) {
                    if (mh[k] == h) break;
                }
                if (k == nmh) {
                    if (nmh >= sizeof(mh) / sizeof(mh[0])) {
                        CHECK(0, "T-REF/oi: more heights than the probe holds");
                        walked = 0;
                        break;
                    }
                    mh[nmh] = h;
                    macc[nmh] = 0;
                    nmh++;
                }
                macc[k] += np * nc;
            }
        }
        if (walked) {
            /* sort DESCENDING by height — the native's own order
             * (fri_verifier.c:490-497), and the order the oi cfg pins. */
            for (size_t i = 0; i < nmh; i++) {
                size_t best = i;
                for (size_t j = i + 1; j < nmh; j++) {
                    if (mh[j] > mh[best]) best = j;
                }
                { size_t t = mh[i]; mh[i] = mh[best]; mh[best] = t; }
                { size_t t = macc[i]; macc[i] = macc[best]; macc[best] = t; }
            }
            CHECK(nmh == DNAC_P2S_OI_NUM_HEIGHTS,
                  "T-REF/oi: %zu distinct reduced-opening heights, pinned %zu",
                  nmh, (size_t)DNAC_P2S_OI_NUM_HEIGHTS);
            if (nmh == DNAC_P2S_OI_NUM_HEIGHTS) {
                const size_t want_h[DNAC_P2S_OI_NUM_HEIGHTS] = {
                    DNAC_P2S_OI_H0, DNAC_P2S_OI_H1
                };
                size_t total = 0;
                for (size_t i = 0; i < nmh; i++) {
                    CHECK(mh[i] == want_h[i],
                          "T-REF/oi: height[%zu] = %zu, pinned %zu", i, mh[i],
                          want_h[i]);
                    CHECK(macc[i] == DNAC_P2S_OI_ACC_PER_HEIGHT,
                          "T-REF/oi: height %zu accumulates %zu tuples, the "
                          "pinned group holds %zu",
                          mh[i], macc[i], (size_t)DNAC_P2S_OI_ACC_PER_HEIGHT);
                    total += macc[i];
                }
                CHECK(total == DNAC_P2S_OI_TOTAL_ACC,
                      "T-REF/oi: %zu acc rows measured, pinned %zu", total,
                      (size_t)DNAC_P2S_OI_TOTAL_ACC);
                /* The FLEET-029 shape: nothing at log_blowup. If a real proof
                 * ever had one, C4b/C5 would stop being vacuous and the pinned
                 * cfg would have to carry that group. */
                CHECK(mh[nmh - 1] > DNAC_P2S_LOG_BLOWUP,
                      "T-REF/oi: the fixture HAS a reduced opening at "
                      "log_blowup — the pinned lb-less cfg no longer describes "
                      "it");
                /* The seed: fri_verifier.c:524-527 requires ro[0].log_height ==
                 * lgmh, which is what makes ro_export[0] the walk's f_init. */
                CHECK(mh[0] == DNAC_P2S_LGMH,
                      "T-REF/oi: the tallest reduced opening is %zu, not lgmh",
                      mh[0]);
            }
            printf("  [t-ref]  oi: %zu heights, %zu acc rows total "
                   "(%zu batches x %zu tuples per height)\n",
                   nmh, (size_t)DNAC_P2S_OI_TOTAL_ACC,
                   (size_t)DNAC_P2S_OI_NUM_BATCHES,
                   (size_t)DNAC_P2S_OI_ACC_PER_HEIGHT /
                       DNAC_P2S_OI_NUM_BATCHES);
        }
    }

    /* ── T-REF/px: MEASURE EVERY batch's share of each height group ──────────
     * The p_x alias rests on one claim about this fixture PER BATCH: in the
     * schedule's BATCH-MAJOR order (fri_oi_air_table.h:104-114) each height
     * group is B consecutive blocks of DNAC_P2S_OI_ACC_PER_BATCH rows, block b
     * belonging to input batch b — the batch mmix instance
     * DNAC_P2S_SLOT_MMIX(b) describes. The batch index in that order IS the
     * native's batch loop index, i.e. the position in `input_proof`
     * (fri_verifier.c:207), so what has to be measured is EVERY batch's
     * per-height (matrices, points, columns) split.
     *
     * ⚠ This is where the "uniform (m,p,c) factorization is a LABEL" caveat
     * (fri_statement.h HONEST LABEL 5) STOPS being harmless: for the group
     * TOTAL only the product matters, but the p_x map indexes INSIDE a batch's
     * block, so each batch's split must be the PER-BATCH pinned one EXACTLY.
     * s2 only had to measure batch 0 because only batch 0 was aliased.
     *
     * ⚠ AND THE THREE SPLITS ARE NOT EQUAL — the quotient batch is 1 point x 2
     * columns where the other two are 2 x 1. The loop below therefore compares
     * each batch against DNAC_P2S_OI_BNP/_BNC(b), NOT against the descriptor's
     * uniform (2, 1), and separately asserts that at least two of them differ
     * so the per-batch machinery is not vacuously exercised. */
    {
        const jv_t *ip = jv_get(q0, "input_proof");
        const jv_t *rounds = jv_get(s, "opening_rounds");
        const jv_t *insts = jv_get(s, "instances");
        const size_t want_h[DNAC_P2S_OI_NUM_HEIGHTS] = { DNAC_P2S_OI_H0,
                                                         DNAC_P2S_OI_H1 };
        const size_t mmix_lh[DNAC_P2S_MMIX_NUM_MATRICES] = { DNAC_P2S_MMIX_LH0,
                                                             DNAC_P2S_MMIX_LH1 };
        int split_differs = 0;

        if (!ip || ip->kind != JV_ARR || ip->n != DNAC_P2S_OI_NUM_BATCHES ||
            !rounds || rounds->kind != JV_ARR ||
            rounds->n != DNAC_P2S_OI_NUM_BATCHES || !insts ||
            insts->kind != JV_ARR) {
            CHECK(0, "T-REF/px: the fixture's batch arrays are unusable");
        } else {
            for (size_t b = 0; b < DNAC_P2S_OI_NUM_BATCHES; b++) {
                const jv_t *matsb = jv_get(rounds->items[b], "matrices");
                const jv_t *ovb = jv_get(ip->items[b], "opened_values");
                if (!matsb || matsb->kind != JV_ARR || !ovb ||
                    ovb->kind != JV_ARR || matsb->n != ovb->n) {
                    CHECK(0, "T-REF/px: batch %zu's matrix lists disagree", b);
                    continue;
                }
                /* batch b must be an mmix batch: one matrix per pinned height,
                 * each at the pinned mmix log-height and batch b's width. */
                CHECK(matsb->n == DNAC_P2S_MMIX_NUM_MATRICES,
                      "T-REF/px: batch %zu has %zu matrices, mmix pins %zu", b,
                      matsb->n, (size_t)DNAC_P2S_MMIX_NUM_MATRICES);
                for (size_t i = 0; i < DNAC_P2S_OI_NUM_HEIGHTS; i++) {
                    size_t seen = 0, np = 0, nc = 0;
                    for (size_t m = 0; m < matsb->n; m++) {
                        uint64_t ii = 0, led = 0;
                        const jv_t *pts = jv_get(matsb->items[m], "points");
                        if (!jv_u64(jv_get(matsb->items[m], "instance"), &ii) ||
                            ii >= insts->n ||
                            !jv_u64(jv_get(insts->items[(size_t)ii],
                                           "log_ext_degree"), &led) ||
                            !pts || pts->kind != JV_ARR ||
                            ovb->items[m]->kind != JV_ARR) {
                            CHECK(0, "T-REF/px: batch %zu matrix %zu "
                                     "unreadable", b, m);
                            break;
                        }
                        if ((size_t)led + DNAC_P2S_LOG_BLOWUP != want_h[i]) {
                            continue;
                        }
                        seen++;
                        np = pts->n;
                        nc = ovb->items[m]->n;
                        /* the alias reads THIS matrix's opened row, so its
                         * position in batch b's flattening has to be the pinned
                         * one too. */
                        CHECK(m < DNAC_P2S_MMIX_NUM_MATRICES &&
                                  mmix_lh[m] == want_h[i] &&
                                  nc == DNAC_P2S_MMIX_BW(b),
                              "T-REF/px: height %zu maps to batch-%zu matrix "
                              "%zu (width %zu), which is not the pinned mmix "
                              "matrix", want_h[i], b, m, nc);
                    }
                    /* EXACTLY ONE matrix per (batch, height) — the map the
                     * entry's p2s_mmix_matrix_at_height fails closed on. */
                    CHECK(seen == DNAC_P2S_OI_NUM_MATRICES,
                          "T-REF/px: batch %zu has %zu matrices at height %zu, "
                          "the pinned group descriptor says %zu", b, seen,
                          want_h[i], (size_t)DNAC_P2S_OI_NUM_MATRICES);
                    /* THE PER-BATCH SPLIT, not the uniform descriptor's. */
                    CHECK(np == DNAC_P2S_OI_BNP(b),
                          "T-REF/px: batch %zu opens height %zu at %zu points, "
                          "pinned %zu", b, want_h[i], np,
                          (size_t)DNAC_P2S_OI_BNP(b));
                    CHECK(nc == DNAC_P2S_OI_BNC(b),
                          "T-REF/px: batch %zu's height-%zu row is %zu columns "
                          "wide, pinned %zu", b, want_h[i], nc,
                          (size_t)DNAC_P2S_OI_BNC(b));
                    CHECK(seen * np * nc == DNAC_P2S_OI_ACC_PER_BATCH,
                          "T-REF/px: batch %zu contributes %zu acc rows at "
                          "height %zu, the split assumes %zu", b,
                          seen * np * nc, want_h[i],
                          (size_t)DNAC_P2S_OI_ACC_PER_BATCH);
                    if (np != DNAC_P2S_OI_NUM_POINTS ||
                        nc != DNAC_P2S_OI_NUM_COLUMNS) {
                        split_differs = 1;
                    }
                    printf("  [t-ref]  px: batch %zu @ h=%zu -> %zu matrix x "
                           "%zu points x %zu cols = %zu acc rows "
                           "(mmix-aliased)\n",
                           b, want_h[i], seen, np, nc, seen * np * nc);
                }
            }
            /* NON-VACUITY: at least one batch's real split must differ from the
             * uniform group descriptor's, or the per-batch column arithmetic
             * would be indistinguishable from the s2 shape and this whole
             * measurement would prove nothing the descriptor did not already. */
            CHECK(split_differs,
                  "T-REF/px: every batch's (points, columns) split equals the "
                  "uniform descriptor's — the per-batch split is untested");
        }
    }
}

/* ════════════════ the preprocessed-commit pipeline (test-side) ════════════
 * The exact pipeline batch_prover.c:786-822 runs with is_zk = 0, kept here
 * rather than in the module so the verify surface does not link the prover
 * (fri_statement.h documents why). test_mmcs_air_table.c:72-95 precedent.
 */
static int p2s_commit_tables(const uint64_t *const *tables, uint64_t lanes[4])
{
    uint64_t *lde[DNAC_P2S_NUM_INSTANCES] = { 0 };
    const uint64_t *mats[DNAC_P2S_NUM_INSTANCES];
    size_t widths[DNAC_P2S_NUM_INSTANCES], heights[DNAC_P2S_NUM_INSTANCES];
    dnac_p2_digest_t root;
    int ok = 1;

    for (uint32_t i = 0; i < DNAC_P2S_NUM_INSTANCES && ok; i++) {
        const size_t rows = dnac_p2s_prep_rows(i);
        const size_t cols = dnac_p2s_prep_cols(i);
        const size_t lde_rows = rows << DNAC_P2S_LOG_BLOWUP;
        lde[i] = (uint64_t *)calloc(lde_rows * cols, sizeof(uint64_t));
        if (!lde[i]) { ok = 0; break; }
        if (dnac_prover_coset_lde_bitrev(tables[i], rows, cols,
                                        (unsigned)DNAC_P2S_LOG_BLOWUP,
                                        GOLDILOCKS_GENERATOR,
                                        lde[i]) != DNAC_PROVER_OK) {
            ok = 0;
            break;
        }
        mats[i] = lde[i];
        widths[i] = cols;
        heights[i] = lde_rows;
    }
    if (ok && dnac_p2_mmcs_commit_mixed(mats, widths, heights,
                                        DNAC_P2S_NUM_INSTANCES, &root,
                                        NULL) != DNAC_P2M_OK) {
        ok = 0;
    }
    if (ok) {
        for (size_t k = 0; k < 4; k++) lanes[k] = root.lanes[k];
    }
    for (uint32_t i = 0; i < DNAC_P2S_NUM_INSTANCES; i++) free(lde[i]);
    return ok;
}

/** Allocate + generate the three honest tables. Caller frees. */
static int p2s_alloc_tables(uint64_t *tab[DNAC_P2S_NUM_INSTANCES])
{
    for (uint32_t i = 0; i < DNAC_P2S_NUM_INSTANCES; i++) {
        const size_t cells = dnac_p2s_prep_cells(i);
        tab[i] = cells ? (uint64_t *)calloc(cells, sizeof(uint64_t)) : NULL;
        if (!tab[i]) return 0;
    }
    return dnac_p2_fri_statement_prep_tables(tab) == DNAC_P2S_OK;
}

static void p2s_free_tables(uint64_t *tab[DNAC_P2S_NUM_INSTANCES])
{
    for (uint32_t i = 0; i < DNAC_P2S_NUM_INSTANCES; i++) free(tab[i]);
}

static int p2s_honest_root(uint64_t lanes[4])
{
    uint64_t *tab[DNAC_P2S_NUM_INSTANCES] = { 0 };
    const uint64_t *ctab[DNAC_P2S_NUM_INSTANCES];
    int ok = p2s_alloc_tables(tab);
    if (ok) {
        for (uint32_t i = 0; i < DNAC_P2S_NUM_INSTANCES; i++) ctab[i] = tab[i];
        ok = p2s_commit_tables(ctab, lanes);
    }
    p2s_free_tables(tab);
    return ok;
}

static void t_pin_kat(void)
{
    static const uint64_t pinned[4] = DNAC_P2S_PREP_ROOT;
    uint64_t lanes[4] = { 0, 0, 0, 0 };

    if (!p2s_honest_root(lanes)) {
        CHECK(0, "T-PINKAT: the preprocessed commit pipeline failed");
        return;
    }
#if DNAC_P2S_PREP_ROOT_UNFILLED
    (void)pinned;
    printf("  [pin]    DNAC_P2S_PREP_ROOT is the UNFILLED placeholder — the "
           "comparator rejects everything (expected).\n");
    printf("           Run with --print-roots and paste the four lanes into "
           "fri_statement.h.\n");
#else
    for (size_t k = 0; k < 4; k++) {
        CHECK(lanes[k] == pinned[k],
              "T-PINKAT: lane %zu recomputed 0x%016llx != pinned 0x%016llx", k,
              (unsigned long long)lanes[k], (unsigned long long)pinned[k]);
    }
#endif
}

/* ═══════════════════════ the three honest traces ═════════════════════════ */

/** One query's honest traces — one per SLOT, so B of them for the mmix AIR and
 *  R for the mmcs AIR. */
typedef struct {
    /** PER INPUT BATCH. Batch b's fixture commits batch b's own cfg (its own
     *  opened WIDTH) and opens it at the query's index, exactly as the entry's
     *  alias says. */
    p2s_mmix_fixt_t     mmix_fx[DNAC_P2S_OI_NUM_BATCHES];
    p2s_mmix_built_t    mmix[DNAC_P2S_OI_NUM_BATCHES];
    /** PER COMMIT ROUND. Round r's fixture opens the round-r tree (its own
     *  depth) at the round-r folded index, exactly as the entry's alias says. */
    p2s_mmcs_fixture_t  mmcs_fx[DNAC_P2S_FRI_R];
    p2s_mmcs_built_t    mmcs[DNAC_P2S_FRI_R];
    p2s_fri_fixture_t   fri_fx;
    p2s_fri_built_t     fri;
    p2s_oi_built_t      oi;
    uint64_t            index; /* DERIVED from the transcript, not chosen */
    int                 built[DNAC_P2S_SLOTS];
} qtraces_t;

typedef struct {
    tair_run_t tair;
    int        tair_built;
    qtraces_t  q[DNAC_P2S_NUM_QUERIES];
    /** The fri cfg these traces were BUILT with. Normally the pinned one, but
     *  N-CFG deliberately builds on an ALTERNATIVE cfg, and a fri builder's
     *  publics buffer is `calloc(dnac_fair_num_publics(cfg))` — exactly that
     *  long (tests/test_fri_air.c:184,196). Reading it at the PINNED cfg's
     *  offsets when it was built with a shorter one is a HEAP OVERREAD, so the
     *  cfg has to travel with the traces rather than be re-derived. (Latent
     *  since the N-CFG leg was written: ALT drops the roll-in slots, so its
     *  final_off is 2 lanes lower than the pinned one and `stmt_from_traces`
     *  read 2 elements past the allocation. It only surfaced when the heap
     *  layout changed.) */
    const dnac_p2c_table_cfg_t *fri_cfg;
    /** The R commit-round roots, probed BEFORE the transcript so the challenger
     *  can OBSERVE them (HONEST LABEL 6). Shared across q by construction. */
    uint64_t mmcs_root[DNAC_P2S_FRI_R][MAIR_DIGEST_LANES];
} traces_t;

static void traces_free(traces_t *T)
{
    for (size_t q = 0; q < DNAC_P2S_NUM_QUERIES; q++) {
        qtraces_t *Q = &T->q[q];
        for (size_t b = 0; b < DNAC_P2S_OI_NUM_BATCHES; b++) {
            if (Q->built[DNAC_P2S_SLOT_MMIX(b)]) {
                p2s_mmix_built_free(&Q->mmix[b]);
            }
        }
        for (size_t r = 0; r < DNAC_P2S_FRI_R; r++) {
            if (Q->built[DNAC_P2S_SLOT_MMCS(r)]) {
                p2s_mmcs_built_free(&Q->mmcs[r]);
            }
        }
        if (Q->built[DNAC_P2S_SLOT_FRI]) p2s_fri_built_free(&Q->fri);
        if (Q->built[DNAC_P2S_SLOT_OI]) p2s_oi_built_free(&Q->oi);
        memset(Q->built, 0, sizeof(Q->built));
    }
    if (T->tair_built) tair_free(&T->tair);
    T->tair_built = 0;
}

/** Query q's oi instance exported ro for descending-height index `i`, as fp2. */
static gold_fp2_t oi_ro_export(const traces_t *T, size_t q, size_t i)
{
    const p2s_oi_built_t *B = &T->q[q].oi;
    return gold_fp2_new(gold_fp_from_u64(B->pub[B->pub_ro + 2 * i]),
                        gold_fp_from_u64(B->pub[B->pub_ro + 2 * i + 1]));
}

/**
 * INPUT-BATCH REPLICATION — the p_x lane every oi acc row must carry, in
 * SCHEDULE order. EVERY row, no fixture branch left.
 *
 * Derived HERE from the B mmix FIXTURES' opened rows and the pinned cfgs,
 * INDEPENDENTLY of fri_statement.c (which maps `stmt.mmix_opened`, the
 * flattened form, through `dnac_p2s_mmix_opened_off`). Feeding this into the oi
 * builder is what makes the honest oi trace's p_x column BE the mmix instances'
 * opened values; T-ALIAS then compares the two derivations element for element,
 * and N-PXBOUND asserts the alias on the entry's own output.
 *
 * ⚠ THE COLUMN INDEX IS PER BATCH, and that is the whole difficulty this slice
 * added. The native's p_x depends on the CLAIMED-EVAL ordinal, not on the
 * opening point (fri_verifier.c:469-471 with the point loop outside at :436),
 * so under batch-major emission block row `a` reads column `a % nc_b` — where
 * `nc_b` is batch b's OWN column count, which the uniform group descriptor does
 * not carry. Using `d->num_columns` here would read column 0 for both of the
 * quotient batch's rows.
 *
 * @return 0 if a (batch, height) pair does not name exactly one matrix — a test
 *         defect, reported by the caller rather than papered over.
 */
static int oi_px_from_mmix(const traces_t *T, size_t q,
                           uint64_t px[DNAC_P2S_OI_TOTAL_ACC])
{
    const dnac_p2c_oi_table_cfg_t *oc = dnac_p2s_oi_cfg();
    size_t g = 0;

    for (size_t i = 0; i < oc->num_heights; i++) {
        const dnac_p2c_oi_height_desc_t *d = &oc->heights[i];
        const size_t batch_sz =
            d->num_matrices * d->num_points * d->num_columns;
        const size_t want_h = (size_t)1u << d->log_height;

        for (size_t b = 0; b < d->num_batches; b++) {
            const dnac_p2c_mmix_table_cfg_t *mc = dnac_p2s_mmix_cfg(b);
            const size_t nc = DNAC_P2S_OI_BNC(b);
            size_t mi = (size_t)-1;

            if (mc == NULL || nc == 0) return 0;
            for (size_t m = 0; m < mc->num_matrices; m++) {
                if (mc->heights[m] == want_h) { mi = m; break; }
            }
            if (mi == (size_t)-1) return 0;
            for (size_t a = 0; a < batch_sz; a++, g++) {
                if (g >= DNAC_P2S_OI_TOTAL_ACC) return 0;
                /* batch b's tuple: matrix mi, column a % nc_b. Query q's OWN
                 * opened row of THAT batch. */
                px[g] = T->q[q].mmix_fx[b].rows[mi][a % nc];
            }
        }
    }
    return g == DNAC_P2S_OI_TOTAL_ACC;
}

/* ══════════ the SHARED terminal — solving the last sibling (multi-query) ═══
 *
 * `final_poly0` is a SHARED statement field: the native observes the final poly
 * ONCE, before the query loop (fri_verifier.c:710-713), and with
 * log_final_poly_len == 0 pinned it is a single fp2 CONSTANT, so EVERY query's
 * walk must land on the SAME value. That is a real constraint of the composed
 * system and the reason the field is not per-query.
 *
 * It is also the one place an honest 2-query witness does not fall out of the
 * shipped builders for free. Each query's walk starts at its OWN f_init (the oi
 * export for its OWN index) and folds over its OWN index bits, so the two
 * terminals differ. A REAL prover has no such problem — its queries are folds
 * of one codeword — but this gate's siblings are fixtures, not a codeword.
 *
 * The fri AIR leaves the sibling column FREE (fri_air.h "the sibling column `s`
 * is UNCONSTRAINED witness data until the composition binds it to P2b opened-
 * row publics"), and the fold is AFFINE in it. From the shipped builder's own
 * expression (tests/test_fri_air.c:288-306):
 *     t1  = (1 - 2b)*(s - f)
 *     t2  = (beta - x)*t1
 *     inv = NEG_HALF * x^-1
 *     f'  = f + b*(s - f) + inv*t2 + beta^2*ro
 *         = f + (s - f)*C + beta^2*ro,   C = b + inv*(beta - x)*(1 - 2b)
 * so for a target f' the last row's sibling is
 *     s = f + (f' - f - beta^2*ro) / C.
 * Solving the LAST fold row leaves every earlier row exactly as the shipped
 * builder produced it.
 *
 * ⚠ This is a WITNESS CONSTRUCTION, not a relaxation: the trace still has to
 * satisfy every fri constraint, and the shipped u64 evaluator + the batch proof
 * are what say it does. If the algebra here were wrong the walk would miss the
 * target, C5 would fire on the terminal public and RT-1 would fail loudly.
 */
static int fri_solve_last_sib(const p2s_fri_built_t *B,
                              const p2s_fri_fixture_t *F, gold_fp2_t target,
                              gold_fp2_t *out_sib)
{
    size_t r;
    const uint64_t *row;
    gold_fp_t x, one = gold_fp_one(), inv, sgn;
    uint64_t b;
    gold_fp2_t f, beta, ro, C, rhs;

    if (B->R == 0) return 0; /* no fold row to solve; B->R - 1 would wrap */
    r = B->R - 1;
    row = p2s_fri_row_of(B, B->n_chain + r);

    x = gold_fp_from_u64(row[FAIR_COL_G]);
    b = row[FAIR_COL_B];
    f = gold_fp2_new(gold_fp_from_u64(row[FAIR_COL_F]),
                     gold_fp_from_u64(row[FAIR_COL_F + 1]));
    beta = F->beta[r];
    ro = B->is_rollin[r] ? F->ro[B->rank[r]] : gold_fp2_zero();

    if (gold_fp_is_zero(x)) return 0;
    inv = gold_fp_mul(gold_fp_from_u64(FAIR_NEG_HALF), gold_fp_inv(x));
    sgn = gold_fp_sub(one, gold_fp_add(gold_fp_from_u64(b),
                                       gold_fp_from_u64(b)));
    /* C = b + inv*(beta - x)*(1 - 2b) */
    C = gold_fp2_mul(gold_fp2_sub(beta, gold_fp2_from_base(x)),
                     gold_fp2_from_base(gold_fp_mul(inv, sgn)));
    C = gold_fp2_add(C, gold_fp2_from_base(gold_fp_from_u64(b)));
    /* gold_fp2_inv returns 0 for 0 by contract, so a zero C would silently
     * DELETE the equation — refuse instead (beta == x for b == 0 is the only
     * way to reach it at the pinned shape). */
    if (gold_fp_is_zero(C.a) && gold_fp_is_zero(C.b)) return 0;

    rhs = gold_fp2_sub(gold_fp2_sub(target, f),
                       gold_fp2_mul(gold_fp2_mul(beta, beta), ro));
    *out_sib = gold_fp2_add(f, gold_fp2_mul(rhs, gold_fp2_inv(C)));
    return 1;
}

/** The mmix / mmcs / oi traces of ONE query. `fri` is built afterwards, in the
 *  second pass, because the SHARED terminal has to be fixed first. */
static int qtraces_build_head(traces_t *T, size_t q, uint64_t seed)
{
    qtraces_t *Q = &T->q[q];
    const uint64_t index = T->tair.index[q];

    Q->index = index;

    /* mmix, ONE PER INPUT BATCH — the builder commits batch b's own mixed batch
     * (at batch b's own opened WIDTH), opens it and requires the SHIPPED native
     * mixed verifier to accept (test_mmcs_mixed_air.c:145-151) before any trace
     * exists. The batch CONTENT is index-independent
     * (test_mmcs_mixed_air.c:129-133 fills every cell from `cell(m, r, c)`), so
     * every query commits the SAME tree per batch and each root is genuinely
     * shared across q — only the opened row and the sibling path move with q.
     * stmt_from_traces asserts that rather than assuming it. */
    for (size_t b = 0; b < DNAC_P2S_OI_NUM_BATCHES; b++) {
        const dnac_p2c_mmix_table_cfg_t *cfg = dnac_p2s_mmix_cfg(b);

        if (cfg == NULL) {
            printf("  [rt]     batch %zu has no pinned mmix cfg\n", b);
            return 0;
        }
        if (!p2s_mmix_make_fixt(cfg, index, &Q->mmix_fx[b])) {
            printf("  [rt]     q%zu mmix batch %zu fixture FAILED\n", q, b);
            return 0;
        }
        if (!p2s_mmix_build_trace(&Q->mmix[b], cfg, &Q->mmix_fx[b],
                                  Q->mmix_fx[b].sibs,
                                  Q->mmix_fx[b].root.lanes)) {
            printf("  [rt]     q%zu mmix batch %zu trace FAILED\n", q, b);
            return 0;
        }
        Q->built[DNAC_P2S_SLOT_MMIX(b)] = 1;
    }

    /* mmcs, ONE PER COMMIT ROUND — same anchoring through dnac_p2_mmcs_verify
     * (test_mmcs_air.c:128-133), at THIS round's cfg and THIS round's folded
     * index. The index a round sees is the start index shifted down once per
     * preceding round plus its own (fri_verifier.c:558), i.e. by
     * DNAC_P2S_MMCS_BIT_OFF(r) — the same expression the entry's dir alias
     * uses, written here from the other side. */
    for (size_t r = 0; r < DNAC_P2S_FRI_R; r++) {
        const dnac_p2b_table_cfg_t *cfg = dnac_p2s_mmcs_cfg(r);
        const uint64_t ridx = index >> DNAC_P2S_MMCS_BIT_OFF(r);

        if (cfg == NULL) {
            printf("  [rt]     round %zu has no pinned mmcs cfg\n", r);
            return 0;
        }
        if (!p2s_mmcs_make_fixture(cfg, ridx, &Q->mmcs_fx[r])) {
            printf("  [rt]     q%zu mmcs round %zu fixture FAILED\n", q, r);
            return 0;
        }
        /* LABEL 6's ordering premise, CHECKED not assumed: the root the
         * transcript already observed (probed at index 0) must be the root this
         * query's real opening produces. If a round's tree ever became
         * index-dependent, the transcript would have absorbed a root no walk
         * verifies against and the alias would be decoration. */
        {
            size_t bad = 0;
            for (size_t k = 0; k < (size_t)MAIR_DIGEST_LANES; k++) {
                if (Q->mmcs_fx[r].root.lanes[k] != T->mmcs_root[r][k]) bad++;
            }
            CHECK(bad == 0,
                  "RT: q%zu round %zu opens a root the transcript did not "
                  "observe (%zu lanes differ)", q, r, bad);
        }
        if (!p2s_mmcs_build_trace(&Q->mmcs[r], cfg, ridx, Q->mmcs_fx[r].elems,
                                  Q->mmcs_fx[r].sibs,
                                  Q->mmcs_fx[r].root.lanes)) {
            printf("  [rt]     q%zu mmcs round %zu trace FAILED\n", q, r);
            return 0;
        }
        Q->built[DNAC_P2S_SLOT_MMCS(r)] = 1;
    }

    /* oi — a NATIVE-FORMULA REPLAY of fri_open_input over the builder's own
     * deterministic z / p_z fixtures (test_fri_oi_air.c:10-23), at the pinned
     * cfg and at THIS query's index. Built BEFORE fri because fri consumes its
     * ro export, and AFTER the B mmix instances because EVERY acc row takes its
     * p_x from its own batch's mmix opening: the builder's `g_px_ext` hook is
     * pointed at that derivation for the duration of the build and cleared
     * immediately after, so the walk's reduced openings really are accumulated
     * over the MMCS-opened values of THIS query. */
    {
        uint64_t px[DNAC_P2S_OI_TOTAL_ACC];
        int ok;
        if (!oi_px_from_mmix(T, q, px)) {
            printf("  [rt]     q%zu p_x derivation FAILED (a (batch, height) "
                   "pair does not name exactly one mmix matrix)\n", q);
            return 0;
        }
        p2s_oi_g_px_ext = px;
        /* s3b — and its alpha is the TRANSCRIPT's first fp2 pop, injected the
         * same way. SHARED across q, exactly like the statement field: the
         * shipped fixture family cannot reach that value for any seed (both of
         * its lanes move together), which is why the hook exists; see
         * tests/test_fri_oi_air.c's `g_alpha_ext` comment. */
        p2s_oi_g_alpha_ext = T->tair.alpha;
        ok = p2s_oi_build_honest(&Q->oi, dnac_p2s_oi_cfg(), index, seed);
        p2s_oi_g_px_ext = NULL;
        p2s_oi_g_alpha_ext = NULL;
        if (!ok) {
            printf("  [rt]     q%zu oi trace FAILED\n", q);
            return 0;
        }
    }
    Q->built[DNAC_P2S_SLOT_OI] = 1;
    return 1;
}

/** Fill query q's fri FIXTURE: the shared betas, and this query's own f_init /
 *  roll-ins off its own oi export. The sibling column is left as
 *  `fill_fixture` produced it; the caller may then solve its last entry. */
static int qtraces_fri_fixture(traces_t *T, size_t q,
                               const dnac_p2c_table_cfg_t *fri_cfg,
                               uint64_t seed)
{
    qtraces_t *Q = &T->q[q];

    /* seed + q so the two queries' SIBLING columns genuinely differ; the
     * siblings are unconstrained witness here (fri_air.h), and a shared
     * fixture would make the two fri traces differ only in their bits. */
    p2s_fri_fill_fixture(&Q->fri_fx, seed + q);
    /* s3b — every beta is the TRANSCRIPT's round-r fp2 pop, and it is the SAME
     * pop for every query: the native samples beta once per round, outside the
     * query loop (fri_verifier.c:707 vs :736). `fixture_t` is CALLER-owned
     * (tests/test_fri_air.c:122-129 fills a struct the caller hands it, and
     * build_trace reads `F->beta[r]` at :268), so no hook is needed on this
     * side: overwriting after fill_fixture is the same move the f_init / ro
     * lines below already make. */
    for (size_t r = 0; r < dnac_p2c_fold_rows(fri_cfg) && r < DNAC_P2S_FRI_R;
         r++) {
        Q->fri_fx.beta[r] =
            gold_fp2_new(gold_fp_from_u64(T->tair.beta[2 * r]),
                         gold_fp_from_u64(T->tair.beta[2 * r + 1]));
    }
    /* PER-QUERY: f_init takes THIS query's height-lgmh export (oi index 0);
     * roll-in slot k takes THIS query's export of `rollin_heights[k]`, found by
     * height in the oi cfg — the same lookup fri_statement.c performs. */
    Q->fri_fx.f_init = oi_ro_export(T, q, 0);
    for (size_t k = 0; k < fri_cfg->num_rollin; k++) {
        const dnac_p2c_oi_table_cfg_t *oc = dnac_p2s_oi_cfg();
        size_t found = (size_t)-1;
        for (size_t i = 0; i < oc->num_heights; i++) {
            if (oc->heights[i].log_height == fri_cfg->rollin_heights[k]) {
                found = i;
            }
        }
        if (found == (size_t)-1 || found == 0) {
            printf("  [rt]     fri roll-in height %zu has no oi export\n",
                   fri_cfg->rollin_heights[k]);
            return 0;
        }
        Q->fri_fx.ro[k] = oi_ro_export(T, q, found);
    }
    return 1;
}

/**
 * Build every honest trace at the pinned cfgs, for ALL Q queries.
 *
 * The index each builder receives is exactly the alias map fri_statement.c
 * step 6 implements, from the other side, for that query:
 *   mmix[b] reduced index = index[q] >> (lgmh - depth) == index[q] (shift 0),
 *           the SAME for every batch because every batch's depth is lgmh
 *   mmcs  index[q] >> log_arity                      (fri_verifier.c:558)
 *   fri   the full index[q]
 *   oi    the full index[q] (its chain consumes all lgmh bits, MSB-first)
 * `fri_cfg` is a parameter so N-CFG can build the same batch on a DIFFERENT
 * fri cfg without duplicating any of this.
 *
 * ⚠ ORDER IS LOAD-BEARING (s1c + s3b + multi-query), and it is the SAME rule
 * every time: a value that is aliased must be produced BEFORE its consumers.
 *   1. tair FIRST — it produces every query's index, alpha and every beta.
 *   2. per query: the B mmix instances and the R mmcs ones on index[q]; oi with
 *      the shared alpha injected (g_alpha_ext) and EVERY acc row's p_x taken
 *      from THAT query's opening of THAT row's batch (g_px_ext).
 *   3. query 0's fri, which FIXES the shared terminal; then every query's fri
 *      with its last sibling solved against that terminal.
 * So each walk really is seeded by its own open_input result and driven by the
 * challenger's own challenges, and all Q land on ONE final_poly.
 */
static int traces_build(traces_t *T, const dnac_p2c_table_cfg_t *fri_cfg,
                        uint64_t seed)
{
    gold_fp2_t target;

    memset(T, 0, sizeof(*T));
    /* Recorded BEFORE anything is built: every later read of a fri builder's
     * publics must use THIS cfg's offsets, not the pinned cfg's. */
    T->fri_cfg = fri_cfg;

    /* 0. The commit-round ROOTS, before the transcript — LABEL 6's ordering
     * requirement (see mmcs_probe_roots). */
    if (!mmcs_probe_roots(T->mmcs_root)) return 0;

    /* tair — the SHIPPED gate's builder over a vector synthesized from the
     * pinned script, OBSERVING those roots. Everything below is seeded from its
     * result. */
    if (!tair_build(&T->tair, T->mmcs_root)) return 0;
    T->tair_built = 1;

    for (size_t q = 0; q < DNAC_P2S_NUM_QUERIES; q++) {
        if (!qtraces_build_head(T, q, seed)) return 0;
        if (!qtraces_fri_fixture(T, q, fri_cfg, seed)) return 0;
    }

    /* Query 0's walk defines the SHARED terminal. Building it first and taking
     * its natural output means query 0 needs no adjustment at all, and the
     * solve applied to it is a self-check rather than a change. */
    if (!p2s_fri_build_trace(&T->q[0].fri, fri_cfg, T->q[0].index,
                             &T->q[0].fri_fx, &V_HONEST)) {
        printf("  [rt]     q0 fri trace FAILED\n");
        return 0;
    }
    T->q[0].built[DNAC_P2S_SLOT_FRI] = 1;
    {
        const size_t fo = dnac_fair_pub_final_off(fri_cfg);
        target = gold_fp2_new(gold_fp_from_u64(T->q[0].fri.pub[fo]),
                              gold_fp_from_u64(T->q[0].fri.pub[fo + 1]));
    }

    /* SELF-CHECK of the inverse: solving query 0's last sibling against the
     * terminal query 0 ALREADY produced must give back the sibling it already
     * has. If the affine inversion above were wrong in any term, this fires
     * here rather than as an unexplained RT-1 failure. */
    {
        gold_fp2_t s;
        if (!fri_solve_last_sib(&T->q[0].fri, &T->q[0].fri_fx, target, &s)) {
            CHECK(0, "RT: the last-sibling solve is not applicable at the "
                     "pinned shape (x == 0 or a degenerate coefficient)");
            return 0;
        }
        CHECK(gold_fp_to_u64(s.a) ==
                      gold_fp_to_u64(T->q[0].fri_fx.sib[T->q[0].fri.R - 1].a) &&
                  gold_fp_to_u64(s.b) ==
                      gold_fp_to_u64(
                          T->q[0].fri_fx.sib[T->q[0].fri.R - 1].b),
              "RT: solving for the sibling that produced this terminal does "
              "not return that sibling — the affine inversion is wrong");
    }

    /* Every other query: solve its last sibling so its walk lands on the SAME
     * terminal, then rebuild. Rows before the last fold row are untouched. */
    for (size_t q = 1; q < DNAC_P2S_NUM_QUERIES; q++) {
        qtraces_t *Q = &T->q[q];
        gold_fp2_t s;

        if (!p2s_fri_build_trace(&Q->fri, fri_cfg, Q->index, &Q->fri_fx,
                                 &V_HONEST)) {
            printf("  [rt]     q%zu provisional fri trace FAILED\n", q);
            return 0;
        }
        if (!fri_solve_last_sib(&Q->fri, &Q->fri_fx, target, &s)) {
            CHECK(0, "RT: q%zu last-sibling solve not applicable", q);
            p2s_fri_built_free(&Q->fri);
            return 0;
        }
        Q->fri_fx.sib[Q->fri.R - 1] = s;
        p2s_fri_built_free(&Q->fri);
        if (!p2s_fri_build_trace(&Q->fri, fri_cfg, Q->index, &Q->fri_fx,
                                 &V_HONEST)) {
            printf("  [rt]     q%zu fri rebuild FAILED\n", q);
            return 0;
        }
        Q->built[DNAC_P2S_SLOT_FRI] = 1;
        {
            const size_t fo = dnac_fair_pub_final_off(fri_cfg);
            CHECK(Q->fri.pub[fo] == gold_fp_to_u64(target.a) &&
                      Q->fri.pub[fo + 1] == gold_fp_to_u64(target.b),
                  "RT: q%zu's walk does not land on the SHARED terminal", q);
        }
    }

    /* Each shipped u64 evaluator must accept its own trace — the anchor the
     * whole round-trip stands on. Per query, so a builder that silently
     * degraded for q > 0 cannot hide behind query 0. */
    for (size_t q = 0; q < DNAC_P2S_NUM_QUERIES; q++) {
        for (size_t b = 0; b < DNAC_P2S_OI_NUM_BATCHES; b++) {
            CHECK(p2s_mmix_eval_built(&T->q[q].mmix[b]) == 0,
                  "RT: the mmix u64 evaluator rejects q%zu batch %zu's honest "
                  "trace", q, b);
        }
        for (size_t r = 0; r < DNAC_P2S_FRI_R; r++) {
            CHECK(p2s_mmcs_eval_built(&T->q[q].mmcs[r]) == 0,
                  "RT: the mmcs u64 evaluator rejects q%zu round %zu's honest "
                  "trace", q, r);
        }
        CHECK(p2s_fri_eval_built(&T->q[q].fri) == 0,
              "RT: the fri u64 evaluator rejects q%zu's honest trace", q);
        CHECK(p2s_oi_eval_b(&T->q[q].oi) == 0,
              "RT: the oi u64 evaluator rejects q%zu's honest trace", q);
    }
    CHECK(dnac_transcript_air_eval_trace(
              T->tair.B->trace, T->tair.B->prep, T->tair.B->n_rows,
              dnac_p2s_tair_cfg(), dnac_p2s_tair_script(), T->tair.B->pub,
              T->tair.B->n_pub) == 0,
          "RT: the tair u64 evaluator rejects its own honest trace");
    return 1;
}

/** Fill the statement from every built trace. */
static void stmt_from_traces(dnac_p2s_statement_t *stmt, const traces_t *T)
{
    /* The cfg the TRACES were built with — see traces_t::fri_cfg. Using the
     * pinned cfg here would overread a shorter ALT publics buffer. */
    const dnac_p2c_table_cfg_t *fri = T->fri_cfg;
    const size_t final_off = dnac_fair_pub_final_off(fri);
    memset(stmt, 0, sizeof(*stmt));

    /* ── SHARED regions, filled ONCE ──────────────────────────────────────
     * Each is taken from query 0's builder and then REQUIRED to agree with
     * every other query's, because "shared" is a claim about the traces, not
     * just about the struct: a builder whose root or terminal moved with the
     * index would make the shared field unsatisfiable and the failure would
     * surface as an unexplained RT-1 reject instead of here. */
    /* PER INPUT BATCH, shared across q. Taken from query 0's batch-b fixture
     * and then required to agree with every other query's — batch b's tree
     * CONTENT is index-independent (test_mmcs_mixed_air.c:129-133), so only the
     * opened row and the path move with q. */
    for (size_t b = 0; b < DNAC_P2S_OI_NUM_BATCHES; b++) {
        for (size_t k = 0; k < (size_t)MMIX_DIGEST_LANES; k++) {
            stmt->mmix_root[b][k] = T->q[0].mmix_fx[b].root.lanes[k];
        }
    }
    /* ⚠ REPORTED, NOT ASSERTED — the honest counterpart of the mmcs
     * distinctness check below. Two batches with identical pinned cfgs commit
     * identical trees under the shipped builder's content function, so batches
     * 0 and 2 legitimately share a root at this pin. That does not weaken any
     * gate (the statement carries a root PER BATCH and N-BSEP works on the
     * per-batch opened spans), and asserting distinctness would be asserting a
     * fixture property this pin does not have. Printed so a reader of the log
     * knows which axis is degenerate. */
    for (size_t a = 0; a < DNAC_P2S_OI_NUM_BATCHES; a++) {
        for (size_t b = a + 1; b < DNAC_P2S_OI_NUM_BATCHES; b++) {
            int same = 1;
            for (size_t k = 0; k < (size_t)MMIX_DIGEST_LANES; k++) {
                if (stmt->mmix_root[a][k] != stmt->mmix_root[b][k]) same = 0;
            }
            if (same) {
                printf("  [rt]     note: input batches %zu and %zu share a root "
                       "(identical pinned cfgs; fixture property, see the "
                       "honest label)\n", a, b);
                /* ⚠ AND THEIR OPENED VALUES COINCIDE TOO — same widths, same
                 * heights, and the fixture's cell content is cell(m,r,c), a pure
                 * function of position (tests/test_mmcs_mixed_air.c:129-136).
                 * So N-PXBOUND's POSITIVE half cannot tell "batch %zu's p_x came
                 * from batch %zu" from "...came from batch %zu": the compared
                 * lanes are equal either way. The discrimination is carried by
                 * N-BSEP's PERTURBATION leg, which moves one batch's lane and
                 * requires exactly that batch's instances to follow. Stated here
                 * because the roots-degeneracy label alone does not cover it. */
                printf("  [rt]     note: ...so their OPENED VALUES coincide as "
                       "well — N-PXBOUND's positive half is value-degenerate "
                       "between them; N-BSEP's perturbation leg is what "
                       "discriminates\n");
            }
        }
    }
    /* PER ROUND, shared across q. Taken from query 0's round-r fixture and then
     * required to agree with every other query's — the round-r tree's CONTENT
     * is index-independent (test_mmcs_air.c:114-116 fills every cell from
     * `cell(m,r,c)`), so only the opened row and the path move with q. */
    for (size_t r = 0; r < DNAC_P2S_FRI_R; r++) {
        for (size_t k = 0; k < (size_t)MAIR_DIGEST_LANES; k++) {
            stmt->mmcs_root[r][k] = T->q[0].mmcs_fx[r].root.lanes[k];
        }
    }
    /* The R roots must be DISTINCT — the rounds are different trees (different
     * depths), so a collision would mean the round axis carries no information
     * and N-OBSBIND / N-RSEP would be measuring nothing. */
    for (size_t a = 0; a < DNAC_P2S_FRI_R; a++) {
        for (size_t b = a + 1; b < DNAC_P2S_FRI_R; b++) {
            int same = 1;
            for (size_t k = 0; k < (size_t)MAIR_DIGEST_LANES; k++) {
                if (stmt->mmcs_root[a][k] != stmt->mmcs_root[b][k]) same = 0;
            }
            CHECK(!same, "stmt: commit rounds %zu and %zu have the SAME root — "
                         "the round axis is degenerate", a, b);
        }
    }
    stmt->final_poly0[0] = T->q[0].fri.pub[final_off];
    stmt->final_poly0[1] = T->q[0].fri.pub[final_off + 1];
    for (size_t q = 1; q < DNAC_P2S_NUM_QUERIES; q++) {
        int same = 1;
        for (size_t b = 0; b < DNAC_P2S_OI_NUM_BATCHES; b++) {
            same = 1;
            for (size_t k = 0; k < (size_t)MMIX_DIGEST_LANES; k++) {
                if (T->q[q].mmix_fx[b].root.lanes[k] != stmt->mmix_root[b][k]) {
                    same = 0;
                }
            }
            CHECK(same, "stmt: q%zu commits a DIFFERENT batch-%zu mmix root — "
                        "the shared root field cannot describe both", q, b);
        }
        for (size_t r = 0; r < DNAC_P2S_FRI_R; r++) {
            same = 1;
            for (size_t k = 0; k < (size_t)MAIR_DIGEST_LANES; k++) {
                if (T->q[q].mmcs_fx[r].root.lanes[k] != stmt->mmcs_root[r][k]) {
                    same = 0;
                }
            }
            CHECK(same, "stmt: q%zu commits a DIFFERENT round-%zu mmcs root", q,
                  r);
        }
        CHECK(T->q[q].fri.pub[final_off] == stmt->final_poly0[0] &&
                  T->q[q].fri.pub[final_off + 1] == stmt->final_poly0[1],
              "stmt: q%zu's walk terminal is not the shared final_poly", q);
    }
    /* The CLAIMED EVALUATIONS. Taken from query 0's oi builder at the p_z half
     * of each acc row's four-lane block (z at 4a, p_z at 4a + 2), and then
     * REQUIRED to agree with every other query's — which is the claim the
     * shared region rests on, so it is asserted rather than assumed. The
     * builder emits `pz = tfp2(a_global + 3, 19)` for every row of the pinned
     * cfg (tests/test_fri_oi_air.c:265-266 with `cur_is_lb == 0` throughout,
     * because no pinned oi height sits at log_blowup — T-CONST guards that),
     * i.e. a pure function of the SCHEDULE ORDINAL, not of the query index.
     * If that ever stops holding, this fires here instead of surfacing as an
     * unexplained RT-1 rejection. */
    for (size_t a = 0; a < DNAC_P2S_OI_TOTAL_ACC; a++) {
        const p2s_oi_built_t *B0 = &T->q[0].oi;
        stmt->pz_shared[2 * a] = B0->pub[B0->pub_zpz + 4 * a + 2];
        stmt->pz_shared[2 * a + 1] = B0->pub[B0->pub_zpz + 4 * a + 3];
    }
    for (size_t q = 1; q < DNAC_P2S_NUM_QUERIES; q++) {
        const p2s_oi_built_t *B = &T->q[q].oi;
        size_t bad = 0;
        for (size_t a = 0; a < DNAC_P2S_OI_TOTAL_ACC; a++) {
            if (B->pub[B->pub_zpz + 4 * a + 2] != stmt->pz_shared[2 * a] ||
                B->pub[B->pub_zpz + 4 * a + 3] != stmt->pz_shared[2 * a + 1]) {
                bad++;
            }
        }
        CHECK(bad == 0,
              "stmt: q%zu's oi builder claims %zu DIFFERENT p_z value(s) — a "
              "shared claimed-evaluation region has no honest witness", q, bad);
    }
    /* s3b — the transcript payload, read straight off the tair builder's own
     * publics. This is the SINGLE source of the betas and alpha, so those two
     * have no statement field to fill any more, and no per-query copy either. */
    for (size_t k = 0; k < DNAC_P2S_TAIR_NUM_OPS; k++) {
        stmt->tair_payload[k] = T->tair.B->pub[k];
    }

    /* ── PER-QUERY regions ────────────────────────────────────────────────── */
    for (size_t q = 0; q < DNAC_P2S_NUM_QUERIES; q++) {
        const qtraces_t *Q = &T->q[q];
        const uint64_t index = Q->index;

        for (size_t l = 0; l < DNAC_P2S_LGMH; l++) {
            stmt->index_bits[q][l] = (index >> l) & 1u;
        }
        /* opened rows, taken from the SAME place each builder's publics take
         * them: the mixed fixture's per-matrix DATA lanes, and the same-height
         * fixture's concatenated element stream.
         *
         * ONE FLAT ROW per query, batch by batch. The batch's base is read from
         * the MODULE (`dnac_p2s_mmix_opened_off`) so the statement and the
         * entry cannot disagree about where a batch's span starts, and the
         * running offset is compared against it — a partition mismatch is a
         * test defect, reported here rather than surfacing as an RT-1 reject. */
        {
            size_t off = 0;
            for (size_t b = 0; b < DNAC_P2S_OI_NUM_BATCHES; b++) {
                CHECK(dnac_p2s_mmix_opened_off(b) == off,
                      "stmt: batch %zu's opened span starts at %zu, the module "
                      "says %zu", b, off, dnac_p2s_mmix_opened_off(b));
                for (size_t m = 0; m < Q->mmix_fx[b].nm; m++) {
                    for (size_t d = 0; d < Q->mmix_fx[b].semw[m]; d++) {
                        stmt->mmix_opened[q][off + d] = Q->mmix_fx[b].rows[m][d];
                    }
                    off += Q->mmix_fx[b].semw[m];
                }
            }
            CHECK(off == DNAC_P2S_MMIX_ALL_OPENED,
                  "stmt: the B opened spans cover %zu lanes, ALL_OPENED is %zu",
                  off, (size_t)DNAC_P2S_MMIX_ALL_OPENED);
        }
        for (size_t r = 0; r < DNAC_P2S_FRI_R; r++) {
            for (size_t c = 0; c < DNAC_P2S_MMCS_TOTAL_WIDTH; c++) {
                stmt->mmcs_opened[q][r][c] = Q->mmcs_fx[r].elems[c];
            }
        }
        /* oi regions, straight off the oi builder's publics — minus alpha,
         * which is the tair payload's now (s3b). `f_init` and the roll-ins
         * (s1c) are DELIBERATELY not read out of the fri builder: they have no
         * statement field, the oi export is their single source, and
         * traces_build already seeded the fri trace from it. */
        /* Only the z half of each acc row's block is per-query; the p_z half is
         * the shared region filled above. */
        for (size_t a = 0; a < DNAC_P2S_OI_TOTAL_ACC; a++) {
            stmt->z_pq[q][2 * a] = Q->oi.pub[Q->oi.pub_zpz + 4 * a];
            stmt->z_pq[q][2 * a + 1] = Q->oi.pub[Q->oi.pub_zpz + 4 * a + 1];
        }
        for (size_t i = 0; i < 2 * DNAC_P2S_OI_NUM_HEIGHTS; i++) {
            stmt->ro_export[q][i] = Q->oi.pub[Q->oi.pub_ro + i];
        }
        /* ⚠ NO p_x FIELD AT ALL any more (input-batch replication). Every acc
         * row's p_x is an alias of `mmix_opened[q]`, so there is nothing left
         * to copy out of the oi builder's publics — `px_rest`, which held the
         * rows the main batch did not cover, is gone with the seam it stood
         * for. T-ALIAS is what proves the entry reconstructs exactly the lanes
         * the builder wrote. */
    }
}

/**
 * T-ALIAS(positive): the entry's ALIASED publics must equal, element for
 * element, the publics each shipped builder wrote for its own trace. Without
 * this, RT-1 could pass on a misalignment that both sides shared.
 */
static void t_alias_positive(const dnac_p2s_statement_t *stmt, const traces_t *T)
{
    const p2s_set_t *S = &g_set_a;
    const gold_fp_t *pt;

    if (set_build(&g_set_a, stmt) != DNAC_P2S_OK) {
        CHECK(0, "T-ALIAS: build_instances rejected the honest statement");
        return;
    }
    pt = set_pub(S, DNAC_P2S_INST_TAIR);

    {
        size_t bad = 0;
        for (size_t i = 0; i < DNAC_P2S_TAIR_NUM_PUBLICS; i++) {
            if (gold_fp_to_u64(pt[i]) != T->tair.B->pub[i]) bad++;
        }
        CHECK(bad == 0, "T-ALIAS: %zu tair publics differ from the builder's",
              bad);
    }

    for (size_t q = 0; q < DNAC_P2S_NUM_QUERIES; q++) {
        const qtraces_t *Q = &T->q[q];
        const gold_fp_t *pf = set_pub(S, DNAC_P2S_INST(q, DNAC_P2S_SLOT_FRI));
        const gold_fp_t *po = set_pub(S, DNAC_P2S_INST(q, DNAC_P2S_SLOT_OI));
        size_t bad = 0;

        /* One comparison per INPUT BATCH: each batch's instance must match the
         * builder that opened THAT batch's tree at THAT batch's width. A single
         * batch-0 comparison would pass even if batches 1..B-1 were fed batch
         * 0's lanes, which is precisely the collapse N-BSEP forbids. */
        for (size_t b = 0; b < DNAC_P2S_OI_NUM_BATCHES; b++) {
            const gold_fp_t *pm =
                set_pub(S, DNAC_P2S_INST(q, DNAC_P2S_SLOT_MMIX(b)));
            bad = 0;
            for (size_t i = 0; i < DNAC_P2S_MMIX_NUM_PUBLICS(b); i++) {
                if (gold_fp_to_u64(pm[i]) != Q->mmix[b].pub[i]) bad++;
            }
            CHECK(bad == 0, "T-ALIAS: %zu mmix%zu[q%zu] publics differ from the "
                            "builder's", bad, b, q);
        }
        /* One comparison per COMMIT ROUND: each round's instance must match the
         * builder that opened THAT round's tree at THAT round's index. A single
         * round-0 comparison would pass even if rounds 1..R-1 were fed round
         * 0's lanes, which is precisely the collapse N-RSEP forbids. */
        for (size_t r = 0; r < DNAC_P2S_FRI_R; r++) {
            const gold_fp_t *pc =
                set_pub(S, DNAC_P2S_INST(q, DNAC_P2S_SLOT_MMCS(r)));
            bad = 0;
            for (size_t i = 0; i < DNAC_P2S_MMCS_NUM_PUBLICS(r); i++) {
                if (gold_fp_to_u64(pc[i]) != Q->mmcs[r].pub[i]) bad++;
            }
            CHECK(bad == 0, "T-ALIAS: %zu mmcs%zu[q%zu] publics differ from the "
                            "builder's", bad, r, q);
        }
        bad = 0;
        for (size_t i = 0; i < DNAC_P2S_FRI_NUM_PUBLICS; i++) {
            if (gold_fp_to_u64(pf[i]) != Q->fri.pub[i]) bad++;
        }
        CHECK(bad == 0, "T-ALIAS: %zu fri[q%zu] publics differ from the "
                        "builder's", bad, q);
        bad = 0;
        for (size_t i = 0; i < DNAC_P2S_OI_NUM_PUBLICS; i++) {
            if (gold_fp_to_u64(po[i]) != Q->oi.pub[i]) bad++;
        }
        CHECK(bad == 0, "T-ALIAS: %zu oi[q%zu] publics differ from the "
                        "builder's", bad, q);

        /* ── T-SRC: the s1c single-source property, asserted on the entry's OWN
         * output, PER QUERY. Query q's fri f_init region and its roll-in region
         * must BE query q's oi exported ro lanes — not merely equal to
         * something the statement also holds, since the statement no longer
         * holds them at all. ── */
        {
            const dnac_p2c_table_cfg_t    *fc = dnac_p2s_fri_cfg();
            const dnac_p2c_oi_table_cfg_t *oc = dnac_p2s_oi_cfg();
            const size_t finit_off = dnac_fair_pub_finit_off(fc);
            const size_t fro_off = dnac_fair_pub_ro_off(fc);
            const size_t oro_off = dnac_foi_pub_ro_off(oc);

            CHECK(gold_fp_to_u64(pf[finit_off]) ==
                          gold_fp_to_u64(po[oro_off]) &&
                      gold_fp_to_u64(pf[finit_off + 1]) ==
                          gold_fp_to_u64(po[oro_off + 1]),
                  "T-SRC: fri[q%zu] f_init is not q%zu's oi height-lgmh ro "
                  "export", q, q);
            for (size_t k = 0; k < fc->num_rollin; k++) {
                size_t i = (size_t)-1;
                for (size_t j = 0; j < oc->num_heights; j++) {
                    if (oc->heights[j].log_height == fc->rollin_heights[k]) {
                        i = j;
                    }
                }
                CHECK(i != (size_t)-1 && i != 0,
                      "T-SRC: roll-in %zu has no non-seed oi export", k);
                if (i == (size_t)-1) continue;
                CHECK(gold_fp_to_u64(pf[fro_off + 2 * k]) ==
                              gold_fp_to_u64(po[oro_off + 2 * i]) &&
                          gold_fp_to_u64(pf[fro_off + 2 * k + 1]) ==
                              gold_fp_to_u64(po[oro_off + 2 * i + 1]),
                      "T-SRC: fri[q%zu] roll-in slot %zu is not oi ro export "
                      "%zu", q, k, i);
            }
        }

        /* ── N-PXBOUND (positive half) — HONEST LABEL 3's CLOSURE PROOF.
         *
         * EVERY acc row's p_x public in the oi instance IS its OWN batch's mmix
         * instance's opened-row public, at the column the native's innermost
         * loop index names. Asserted on the ENTRY's own output vectors — not on
         * the statement, which holds those lanes exactly once (in
         * `mmix_opened[q]`) and holds no p_x field for any of them.
         *
         * s2's T-SRC/px was this restricted to batch 0 and required only
         * MAIN_ACC comparisons; the requirement is TOTAL_ACC now, and a
         * regression to the s2 shape would fail the count as well as the
         * comparisons. The column index is per batch (DNAC_P2S_OI_BNC), which
         * is what makes the quotient batch's SECOND acc row read its SECOND
         * claimed evaluation rather than duplicating the first. ── */
        {
            const dnac_p2c_oi_table_cfg_t *oc = dnac_p2s_oi_cfg();
            const size_t opx_off = dnac_foi_pub_px_off(oc);
            size_t g = 0, checked = 0;

            for (size_t i = 0; i < oc->num_heights; i++) {
                const dnac_p2c_oi_height_desc_t *d = &oc->heights[i];
                const size_t batch_sz =
                    d->num_matrices * d->num_points * d->num_columns;
                const size_t want_h = (size_t)1u << d->log_height;

                for (size_t b = 0; b < d->num_batches; b++) {
                    const dnac_p2c_mmix_table_cfg_t *mc = dnac_p2s_mmix_cfg(b);
                    const gold_fp_t *pm =
                        set_pub(S, DNAC_P2S_INST(q, DNAC_P2S_SLOT_MMIX(b)));
                    const size_t nc = DNAC_P2S_OI_BNC(b);
                    size_t mo_off, moff = 0, mi = (size_t)-1;

                    CHECK(mc != NULL, "N-PXBOUND: batch %zu has no cfg", b);
                    if (mc == NULL) { g += batch_sz; continue; }
                    mo_off = dnac_mmix_air_pub_opened_off(mc);
                    for (size_t m = 0; m < mc->num_matrices; m++) {
                        if (mc->heights[m] == want_h) { mi = m; break; }
                        moff += mc->widths[m];
                    }
                    CHECK(mi != (size_t)-1,
                          "N-PXBOUND: batch %zu has no matrix at oi height %zu",
                          b, d->log_height);
                    if (mi == (size_t)-1) { g += batch_sz; continue; }
                    CHECK(mc->widths[mi] == nc,
                          "N-PXBOUND: batch %zu's height-%zu matrix is %zu "
                          "columns wide, the pinned split says %zu", b,
                          d->log_height, mc->widths[mi], nc);
                    for (size_t a = 0; a < batch_sz; a++, g++) {
                        CHECK(gold_fp_to_u64(po[opx_off + g]) ==
                                  gold_fp_to_u64(pm[mo_off + moff + a % nc]),
                              "N-PXBOUND: oi[q%zu] acc row %zu (height %zu, "
                              "batch %zu, column %zu) is not the mmix%zu[q%zu] "
                              "opened lane", q, g, d->log_height, b, a % nc, b,
                              q);
                        checked++;
                    }
                }
            }
            /* Not vacuous, and not the s2 subset: EVERY acc row compared. */
            CHECK(checked == DNAC_P2S_OI_TOTAL_ACC,
                  "N-PXBOUND: compared %zu acc rows, expected all %zu — a "
                  "main-batch-only alias would report %zu",
                  checked, (size_t)DNAC_P2S_OI_TOTAL_ACC,
                  (size_t)(DNAC_P2S_OI_NUM_HEIGHTS *
                           DNAC_P2S_OI_ACC_PER_BATCH));
        }

        /* ── T-SRC/beta + T-SRC/alpha (s3b): query q's fri betas and oi alpha
         * ARE transcript payload lanes — the SAME lanes for every query, since
         * `tair_payload` has no per-query copy. The op indices are re-derived
         * here by scanning the script, independently of the entry's own
         * walk. ── */
        {
            const dnac_tair_script_t *ts = dnac_p2s_tair_script();
            const size_t beta_off = dnac_fair_pub_beta_off(dnac_p2s_fri_cfg());
            const size_t alpha_off = dnac_foi_pub_alpha_off(dnac_p2s_oi_cfg());
            const size_t ka0 = tair_pop_op(ts, 0), ka1 = tair_pop_op(ts, 1);

            CHECK(ka0 != (size_t)-1 && ka1 != (size_t)-1,
                  "T-SRC/alpha: the script has no alpha pops");
            if (ka0 != (size_t)-1 && ka1 != (size_t)-1) {
                CHECK(gold_fp_to_u64(po[alpha_off]) ==
                              gold_fp_to_u64(pt[ka0]) &&
                          gold_fp_to_u64(po[alpha_off + 1]) ==
                              gold_fp_to_u64(pt[ka1]),
                      "T-SRC/alpha: oi[q%zu]'s alpha publics are not the "
                      "transcript's first fp2 pop", q);
            }
            for (size_t r = 0; r < DNAC_P2S_FRI_R; r++) {
                const size_t k0 = tair_pop_op(ts, 2 + 2 * r);
                const size_t k1 = tair_pop_op(ts, 2 + 2 * r + 1);
                CHECK(k0 != (size_t)-1 && k1 != (size_t)-1,
                      "T-SRC/beta: no pops for round %zu", r);
                if (k0 == (size_t)-1 || k1 == (size_t)-1) continue;
                CHECK(gold_fp_to_u64(pf[beta_off + 2 * r]) ==
                              gold_fp_to_u64(pt[k0]) &&
                          gold_fp_to_u64(pf[beta_off + 2 * r + 1]) ==
                              gold_fp_to_u64(pt[k1]),
                      "T-SRC/beta: fri[q%zu] beta[%zu] is not the transcript's "
                      "round-%zu pop pair", q, r, r);
            }

            /* ── T-SRC/index, PER QUERY: the transcript's q-th exported bits
             * ARE the lanes query q's four consumers' bit / direction publics
             * were built from. This is the multi-query half of OBL-P2c-2 seen
             * from the alias side: query q reads the transcript's BLOCK q, not
             * block 0. ── */
            {
                const size_t kq = tair_pop_op(ts, 2 + 2 * DNAC_P2S_FRI_R + q);
                const size_t off = (kq == (size_t)-1)
                                       ? (size_t)-1
                                       : dnac_tair_op_bit_off(ts, kq);
                CHECK(off != (size_t)-1,
                      "T-SRC/index: query %zu exports no bits", q);
                if (off != (size_t)-1) {
                    for (size_t l = 0; l < DNAC_P2S_LGMH; l++) {
                        CHECK(gold_fp_to_u64(pt[off + l]) ==
                                  stmt->index_bits[q][l],
                              "T-SRC/index: tair bit %zu of block %zu is not "
                              "index_bits[%zu][%zu]", l, q, q, l);
                        CHECK(gold_fp_to_u64(
                                  pf[(size_t)FAIR_PUB_BITS_OFF + l]) ==
                                  gold_fp_to_u64(pt[off + l]),
                              "T-SRC/index: fri[q%zu]'s bit %zu is not the "
                              "transcript's q%zu exported bit", q, l, q);
                        CHECK(gold_fp_to_u64(
                                  po[(size_t)FOI_PUB_BITS_OFF + l]) ==
                                  gold_fp_to_u64(pt[off + l]),
                              "T-SRC/index: oi[q%zu]'s bit %zu is not the "
                              "transcript's q%zu exported bit", q, l, q);
                    }
                }
            }
        }
    }

    /* The descriptors the entry derived. Row counts are a property of the SLOT
     * (the Q copies of a table are identical), so they are checked per slot and
     * applied to every query's instance. */
    {
        /* The B input batches, then the R commit rounds, then fri and oi.
         * Every input batch is 16 rows: the mixed schedule sees a batch's width
         * only through `leaf_rows = ceil(concat / 4)` and every pinned width
         * (1 / 2 / 1) rounds to 1, so all three batches schedule the same rows.
         * Every commit round is 8 rows: depths 4/3/2 schedule 6/5/4 rows and
         * the TERMINALITY RESERVE (mmcs_air_table.h) pads each to the next
         * power of two ABOVE that, which is 8 for all three. Same height,
         * DIFFERENT content for the rounds — the table-content check below is
         * what carries the round distinctness; the batches carry theirs in the
         * CFG, not the table.
         * Hard-coded on purpose: deriving them from `dnac_p2s_prep_rows` would
         * compare the entry against itself. The assert pins the list LENGTH to
         * the pinned shape, so a change to B or R fails the build instead of
         * zero-filling a slot's expectation. */
        typedef char want_db_matches_slots
            [(DNAC_P2S_SLOTS == 8 && DNAC_P2S_FRI_R == 3 &&
              DNAC_P2S_OI_NUM_BATCHES == 3)
                 ? 1
                 : -1];
        static const uint32_t want_db[DNAC_P2S_SLOTS] = { 4, 4, 4, 3,
                                                          3, 3, 3, 5 };
        (void)sizeof(want_db_matches_slots);
        CHECK(S->insts[DNAC_P2S_INST_TAIR].degree_bits == 6,
              "T-ALIAS: tair degree_bits %u, expected 6",
              S->insts[DNAC_P2S_INST_TAIR].degree_bits);
        for (size_t q = 0; q < DNAC_P2S_NUM_QUERIES; q++) {
            for (uint32_t s = 0; s < DNAC_P2S_SLOTS; s++) {
                const uint32_t i = DNAC_P2S_INST(q, s);
                CHECK(S->insts[i].degree_bits == want_db[s],
                      "T-ALIAS: %s degree_bits %u, expected %u", inst_name(i),
                      S->insts[i].degree_bits, want_db[s]);
            }
        }
    }
    for (uint32_t i = 0; i < DNAC_P2S_NUM_INSTANCES; i++) {
        CHECK(S->insts[i].prep_next == 1, "T-ALIAS: %s prep_next != 1",
              inst_name(i));
        CHECK(S->insts[i].log_num_qc == 2, "T-ALIAS: %s log_num_qc != 2",
              inst_name(i));
        CHECK(S->insts[i].preprocessed_width == dnac_p2s_prep_cols(i),
              "T-ALIAS: %s preprocessed_width wrong", inst_name(i));
        CHECK(S->insts[i].num_lookups == 0, "T-ALIAS: %s declares lookups",
              inst_name(i));
        /* The descriptor's publics pointer must be its OWN slice of the flat
         * block — a shared or overlapping pointer would make two instances
         * evaluate the same publics, which is the failure mode this layout is
         * meant to make impossible. */
        CHECK(S->insts[i].public_values == S->pub + dnac_p2s_pub_off(i),
              "T-ALIAS: %s public_values is not its own region", inst_name(i));
        CHECK(S->insts[i].num_publics == dnac_p2s_num_publics(i),
              "T-ALIAS: %s num_publics disagrees with the layout", inst_name(i));
    }

    /* ── The MEASURED frame cost, so fri_statement.h's size note is a reading
     * and not an estimate. `dnac_p2_fri_statement_verify` keeps exactly these
     * three objects on its frame; the batch axis is the expensive one because
     * `dnac_mmix_fold_state_t` is by far the largest of the five states. ── */
    printf("  [size]   fold states %zu B (mmix %zu B each x %zu batches x %zu "
           "queries) + %u descriptors %zu B + publics %zu B = frame ~%zu B\n",
           sizeof(dnac_p2s_fold_states_t), sizeof(dnac_mmix_fold_state_t),
           (size_t)DNAC_P2S_OI_NUM_BATCHES, (size_t)DNAC_P2S_NUM_QUERIES,
           DNAC_P2S_NUM_INSTANCES,
           DNAC_P2S_NUM_INSTANCES * sizeof(dnac_batch_vinstance_t),
           DNAC_P2S_TOTAL_PUBLICS * sizeof(gold_fp_t),
           sizeof(dnac_p2s_fold_states_t) +
               DNAC_P2S_NUM_INSTANCES * sizeof(dnac_batch_vinstance_t) +
               DNAC_P2S_TOTAL_PUBLICS * sizeof(gold_fp_t));
}

/* ═════════════════════════════ prove + verify ════════════════════════════ */

/** Point `wits` at every instance's traces, in instance order. */
static void p2s_fill_witnesses(dnac_batch_pwitness_t *wits, const traces_t *T)
{
    memset(wits, 0, DNAC_P2S_NUM_INSTANCES * sizeof(*wits));
    wits[DNAC_P2S_INST_TAIR].main_trace = T->tair.B->trace;
    wits[DNAC_P2S_INST_TAIR].prep_trace = T->tair.B->prep;
    for (size_t q = 0; q < DNAC_P2S_NUM_QUERIES; q++) {
        const qtraces_t *Q = &T->q[q];
        for (size_t b = 0; b < DNAC_P2S_OI_NUM_BATCHES; b++) {
            const uint32_t i = DNAC_P2S_INST(q, DNAC_P2S_SLOT_MMIX(b));
            wits[i].main_trace = Q->mmix[b].trace;
            wits[i].prep_trace = Q->mmix[b].prep;
        }
        for (size_t r = 0; r < DNAC_P2S_FRI_R; r++) {
            const uint32_t i = DNAC_P2S_INST(q, DNAC_P2S_SLOT_MMCS(r));
            wits[i].main_trace = Q->mmcs[r].trace;
            wits[i].prep_trace = Q->mmcs[r].prep;
        }
        wits[DNAC_P2S_INST(q, DNAC_P2S_SLOT_FRI)].main_trace = Q->fri.trace;
        wits[DNAC_P2S_INST(q, DNAC_P2S_SLOT_FRI)].prep_trace = Q->fri.prep;
        wits[DNAC_P2S_INST(q, DNAC_P2S_SLOT_OI)].main_trace = Q->oi.trace;
        wits[DNAC_P2S_INST(q, DNAC_P2S_SLOT_OI)].prep_trace = Q->oi.prep;
    }
}

/** Prove every instance the entry describes. Caller frees *out_proof. */
static int p2s_prove(const dnac_p2s_statement_t *stmt, const traces_t *T,
                     dnac_batch_proof_t **out_proof)
{
    dnac_batch_pwitness_t wits[DNAC_P2S_NUM_INSTANCES];
    dnac_prover_status_t ps;

    *out_proof = NULL;
    if (set_build(&g_set_a, stmt) != DNAC_P2S_OK) return 0;
    p2s_fill_witnesses(wits, T);

    /* is_zk 0, no random codewords, no salt — the non-hiding recursion
     * envelope. dnac_batch_prove self-verifies before returning. */
    ps = dnac_batch_prove(g_set_a.insts, wits, DNAC_P2S_NUM_INSTANCES, 0,
                          dnac_p2s_fri_params(), 0, NULL, 0, NULL, 0, NULL, 0,
                          0, out_proof);
    if (ps != DNAC_PROVER_OK) {
        printf("  [rt]     dnac_batch_prove FAILED (%d)\n", (int)ps);
        return 0;
    }
    return 1;
}

/** Run the entry over a proven proof, with an optional commit override. */
static dnac_p2s_status_t p2s_run_entry(const dnac_p2s_statement_t *stmt,
                                       const dnac_batch_proof_t *proof,
                                       const gold_fp_t *prep_override,
                                       dnac_batch_verify_out_t *out)
{
    dnac_batch_vcommits_t commits;
    dnac_batch_vopened_t opened[DNAC_P2S_NUM_INSTANCES];
    uint32_t nprep = 0;
    const uint32_t *map = dnac_batch_proof_prep_map(proof, &nprep);

    dnac_batch_proof_commits(proof, &commits);
    if (prep_override) commits.preprocessed_commit = prep_override;
    for (uint32_t i = 0; i < DNAC_P2S_NUM_INSTANCES; i++) {
        opened[i] = *dnac_batch_proof_opened(proof, i);
    }
    return dnac_p2_fri_statement_verify(stmt, opened, &commits, map, nprep,
                                        dnac_batch_proof_fri(proof), out);
}

/* ═══════════════════════════════ RT-1 + negatives ════════════════════════ */
/* A zeroed proof surface, for the negatives that are decided BEFORE step 7
 * ever looks at a proof (steps 1 and 2). Non-NULL because the entry's NULL
 * rail is checked first; never dereferenced on those paths. */
typedef struct {
    dnac_batch_vopened_t  opened[DNAC_P2S_NUM_INSTANCES];
    dnac_batch_vcommits_t commits;
    dnac_fri_proof_t      fri;
    gold_fp_t             prep[4];
    uint32_t              map[DNAC_P2S_NUM_INSTANCES];
} stub_proof_t;

static void stub_init(stub_proof_t *S, const uint64_t root_lanes[4])
{
    memset(S, 0, sizeof(*S));
    for (size_t k = 0; k < 4; k++) {
        S->prep[k] = gold_fp_from_u64(root_lanes[k]);
    }
    S->commits.preprocessed_commit = S->prep;
    for (uint32_t i = 0; i < DNAC_P2S_NUM_INSTANCES; i++) S->map[i] = i;
}

static dnac_p2s_status_t stub_run(const dnac_p2s_statement_t *stmt,
                                 stub_proof_t *S)
{
    return dnac_p2_fri_statement_verify(stmt, S->opened, &S->commits, S->map,
                                        DNAC_P2S_NUM_INSTANCES, &S->fri, NULL);
}

/**
 * Everything that is decided in steps 1-2, i.e. everything that needs NO
 * proof. These are full-strength gates regardless of the prover blocker below.
 */
static void t_steps12_negatives(const dnac_p2s_statement_t *stmt,
                                const uint64_t honest_root[4])
{
    stub_proof_t S;

    /* ── the honest root: post-fill it must get PAST step 2; pre-fill the
     * placeholder rejects it, which is the documented pre-fill state. ── */
    stub_init(&S, honest_root);
    {
        const dnac_p2s_status_t st = stub_run(stmt, &S);
#if DNAC_P2S_PREP_ROOT_UNFILLED
        CHECK(st == DNAC_P2S_ERR_PREP_ROOT,
              "step2: the UNFILLED placeholder must reject the honest root "
              "too, got %d", (int)st);
#else
        CHECK(st != DNAC_P2S_ERR_PREP_ROOT,
              "step2: the honest root was rejected by the pin");
        /* It must then die further down — the proof surface is all zeros. */
        CHECK(st != DNAC_P2S_OK, "step2: an all-zero proof was ACCEPTED");
#endif
    }

    /* ── N-PIN×4: one tampered cell per table. The single composed root cannot
     * name the guilty table, so the discrimination lives here: one run per
     * table, and the test knows which one it touched. ── */
    {
        for (uint32_t t = 0; t < DNAC_P2S_NUM_INSTANCES; t++) {
            uint64_t *tab[DNAC_P2S_NUM_INSTANCES] = { 0 };
            const uint64_t *ctab[DNAC_P2S_NUM_INSTANCES];
            uint64_t lanes[4];
            int moved = 0;
            if (!p2s_alloc_tables(tab)) {
                CHECK(0, "N-PIN[%s]: table generate failed", inst_name(t));
                p2s_free_tables(tab);
                continue;
            }
            tab[t][dnac_p2s_prep_cells(t) - 1] += 1u; /* ONE cell */
            for (uint32_t i = 0; i < DNAC_P2S_NUM_INSTANCES; i++) {
                ctab[i] = tab[i];
            }
            if (!p2s_commit_tables(ctab, lanes)) {
                CHECK(0, "N-PIN[%s]: commit failed", inst_name(t));
                p2s_free_tables(tab);
                continue;
            }
            for (size_t k = 0; k < 4; k++) {
                if (lanes[k] != honest_root[k]) moved = 1;
            }
            /* Without this the negative would be vacuous — and with Q copies
             * of every slot's table in the set this is the check that says the
             * copies are committed SEPARATELY: tampering query 1's fri table
             * has to move the root even though query 0's is untouched. */
            CHECK(moved,
                  "N-PIN[%s]: a tampered table gives the SAME composed root",
                  inst_name(t));
            stub_init(&S, lanes);
            CHECK(stub_run(stmt, &S) == DNAC_P2S_ERR_PREP_ROOT,
                  "N-PIN[%s]: a tampered-table root was not rejected at step 2",
                  inst_name(t));
            p2s_free_tables(tab);
        }
    }

    /* ── N-PINMAP: the map is part of what the composed root means ── */
    {
        uint32_t swapped[DNAC_P2S_NUM_INSTANCES];
        for (uint32_t i = 0; i < DNAC_P2S_NUM_INSTANCES; i++) swapped[i] = i;
        swapped[0] = 1;
        swapped[1] = 0;
        stub_init(&S, honest_root);
        CHECK(dnac_p2_fri_statement_verify(stmt, S.opened, &S.commits, swapped,
                                           DNAC_P2S_NUM_INSTANCES, &S.fri,
                                           NULL) == DNAC_P2S_ERR_PREP_ROOT,
              "N-PINMAP: a reordered preprocessed map was accepted");
        CHECK(dnac_p2_fri_statement_verify(stmt, S.opened, &S.commits, NULL, 0,
                                           &S.fri,
                                           NULL) == DNAC_P2S_ERR_PREP_ROOT,
              "N-PINMAP: an absent preprocessed map was accepted");
        S.commits.preprocessed_commit = NULL;
        CHECK(stub_run(stmt, &S) == DNAC_P2S_ERR_PREP_ROOT,
              "N-PINMAP: a missing preprocessed commitment was accepted");
    }

    /* ── N-CANON: step 1 runs BEFORE the pin, so these hold in either pin
     * state — which is exactly the ordering the spec makes binding. ── */
    {
        dnac_p2s_statement_t bad;
        stub_init(&S, honest_root);

        bad = *stmt;
        bad.tair_payload[0] = GOLDILOCKS_P;
        CHECK(stub_run(&bad, &S) == DNAC_P2S_ERR_CANON,
              "N-CANON: a payload lane == p was not rejected at step 1");

        /* the lane the fri betas are aliased from — the s3b region, spanned by
         * step 1 exactly like every other, and kept spanned by the struct's
         * sizeof static-assert in fri_statement.c */
        bad = *stmt;
        bad.tair_payload[DNAC_P2S_TAIR_NUM_OPS - 1] = UINT64_MAX;
        CHECK(stub_run(&bad, &S) == DNAC_P2S_ERR_CANON,
              "N-CANON: the last payload lane was not rejected");

        /* EVERY batch's root — the span grew by an axis exactly as the round
         * one did, and a loop that stopped at batch 0 would leave batches
         * 1..B-1 unchecked while the struct's sizeof assert still passed. */
        for (size_t b = 0; b < DNAC_P2S_OI_NUM_BATCHES; b++) {
            bad = *stmt;
            bad.mmix_root[b][MMIX_DIGEST_LANES - 1] = UINT64_MAX;
            CHECK(stub_run(&bad, &S) == DNAC_P2S_ERR_CANON,
                  "N-CANON: a non-canonical batch-%zu mmix root lane was not "
                  "rejected", b);
        }

        /* EVERY round's root — the span grew by an axis, and a loop that
         * stopped at round 0 would leave rounds 1..R-1 unchecked while the
         * struct's sizeof assert still passed. Last lane of each, so an
         * off-by-one in the flat span shows up here. */
        for (size_t r = 0; r < DNAC_P2S_FRI_R; r++) {
            bad = *stmt;
            bad.mmcs_root[r][MAIR_DIGEST_LANES - 1] = GOLDILOCKS_P;
            CHECK(stub_run(&bad, &S) == DNAC_P2S_ERR_CANON,
                  "N-CANON: a non-canonical round-%zu mmcs root lane was not "
                  "rejected", r);
        }

        bad = *stmt;
        bad.final_poly0[1] = GOLDILOCKS_P;
        CHECK(stub_run(&bad, &S) == DNAC_P2S_ERR_CANON,
              "N-CANON: a non-canonical final_poly lane was not rejected");

        /* the SHARED claimed-evaluation region — both ends, so an off-by-one
         * in step 1's span shows up here rather than as a downstream surprise */
        bad = *stmt;
        bad.pz_shared[0] = GOLDILOCKS_P;
        CHECK(stub_run(&bad, &S) == DNAC_P2S_ERR_CANON,
              "N-CANON: a non-canonical pz_shared lane was not rejected");

        bad = *stmt;
        bad.pz_shared[2 * DNAC_P2S_OI_TOTAL_ACC - 1] = UINT64_MAX;
        CHECK(stub_run(&bad, &S) == DNAC_P2S_ERR_CANON,
              "N-CANON: the LAST pz_shared lane was not rejected");

        /* Every PER-QUERY region, for EVERY query. The multi-query slice turned
         * five flat regions into Q rows each, and step 1's span must cover all
         * of them — a loop that stopped at q = 0 would leave query 1's lanes
         * unchecked and the sizeof static-assert in fri_statement.c would not
         * notice, because the struct size is right either way. Each lane picked
         * is the LAST of its row, so an off-by-one in the span shows up here. */
        for (size_t q = 0; q < DNAC_P2S_NUM_QUERIES; q++) {
            for (size_t r = 0; r < DNAC_P2S_FRI_R; r++) {
                bad = *stmt;
                bad.mmcs_opened[q][r][DNAC_P2S_MMCS_TOTAL_WIDTH - 1] =
                    GOLDILOCKS_P + 1;
                CHECK(stub_run(&bad, &S) == DNAC_P2S_ERR_CANON,
                      "N-CANON: q%zu round %zu's non-canonical mmcs opened "
                      "lane was not rejected", q, r);
            }

            /* The LAST lane of EVERY batch's span, so an off-by-one in either
             * the flat canonicality span or `dnac_p2s_mmix_opened_off` shows up
             * here rather than downstream. */
            for (size_t b = 0; b < DNAC_P2S_OI_NUM_BATCHES; b++) {
                const size_t last = dnac_p2s_mmix_opened_off(b) +
                                    DNAC_P2S_MMIX_TOTAL_OPENED(b) - 1;
                bad = *stmt;
                bad.mmix_opened[q][last] = GOLDILOCKS_P;
                CHECK(stub_run(&bad, &S) == DNAC_P2S_ERR_CANON,
                      "N-CANON: q%zu batch %zu's non-canonical mmix opened "
                      "lane (%zu) was not rejected", q, b, last);
            }

            bad = *stmt;
            bad.z_pq[q][2 * DNAC_P2S_OI_TOTAL_ACC - 1] = UINT64_MAX;
            CHECK(stub_run(&bad, &S) == DNAC_P2S_ERR_CANON,
                  "N-CANON: q%zu's non-canonical z lane was not rejected", q);

            bad = *stmt;
            bad.ro_export[q][2 * DNAC_P2S_OI_NUM_HEIGHTS - 1] = GOLDILOCKS_P;
            CHECK(stub_run(&bad, &S) == DNAC_P2S_ERR_CANON,
                  "N-CANON: q%zu's non-canonical ro_export lane was not "
                  "rejected", q);

            /* the boolean rail on the entry's own construction input */
            bad = *stmt;
            bad.index_bits[q][0] = 2;
            CHECK(stub_run(&bad, &S) == DNAC_P2S_ERR_CANON,
                  "N-CANON: q%zu's non-boolean index bit was not rejected", q);

            bad = *stmt;
            bad.index_bits[q][DNAC_P2S_LGMH - 1] = GOLDILOCKS_P;
            CHECK(stub_run(&bad, &S) == DNAC_P2S_ERR_CANON,
                  "N-CANON: q%zu's non-canonical index bit was not rejected",
                  q);
        }

        /* ORDERING: a statement that is BOTH non-canonical and paired with a
         * bad root must report CANON, proving step 1 precedes step 2. */
        bad = *stmt;
        bad.tair_payload[0] = GOLDILOCKS_P;
        S.prep[0] = gold_fp_from_u64(honest_root[0] ^ 1u);
        CHECK(stub_run(&bad, &S) == DNAC_P2S_ERR_CANON,
              "N-CANON: step 1 does not precede step 2");
    }

    /* ── the NULL rail ── */
    {
        stub_init(&S, honest_root);
        CHECK(dnac_p2_fri_statement_verify(NULL, S.opened, &S.commits, S.map,
                                           DNAC_P2S_NUM_INSTANCES, &S.fri,
                                           NULL) == DNAC_P2S_ERR_NULL,
              "NULL: a NULL statement was accepted");
        CHECK(dnac_p2_fri_statement_verify(stmt, NULL, &S.commits, S.map,
                                           DNAC_P2S_NUM_INSTANCES, &S.fri,
                                           NULL) == DNAC_P2S_ERR_NULL,
              "NULL: NULL opened values were accepted");
        CHECK(dnac_p2_fri_statement_verify(stmt, S.opened, &S.commits, S.map,
                                           DNAC_P2S_NUM_INSTANCES, NULL,
                                           NULL) == DNAC_P2S_ERR_NULL,
              "NULL: a NULL fri proof was accepted");
    }
}
/* ═══════════════════ RT-1 + the proof-driven negatives ═══════════════════
 *
 * These need a REAL 3-instance proof. That became possible when the batched
 * prover's preprocessed-window cap was lifted: `bp_quotient_values` used to
 * keep its windows in fixed `gold_fp2_t pl[64], pn[64]` stack arrays and reject
 * `pw > 64` outright, which made the P2b/P2c control AIRs (mmix 136 columns,
 * fri 73) unprovable. They are heap-sized by `pw` now — same values, same
 * order, storage only. The verifier never had the limit on the path that
 * matters (batch_verify.c:696-706 caps at 64 only when `prep_next == 0`, and
 * the entry pins `prep_next = 1`), so this closed a prover/verifier asymmetry.
 *
 * PIN-STATE DISCIPLINE: while `DNAC_P2S_PREP_ROOT` is the placeholder, only the
 * PIN-DEPENDENT expectations change — every check still passes, asserting the
 * documented placeholder behaviour. Filling the pin flips those same checks to
 * their accept form; nothing else moves.
 */
/* Defined below; declared here because rt1_and_proof_negatives drives them and
 * `t_query_alias` must be reachable on the prove-failure path too. */
static void t_query_alias(const dnac_p2s_statement_t *stmt,
                          const dnac_batch_proof_t *proof);
static void t_ncfg(void);

/**
 * Run the entry on a perturbed statement and require it to REJECT — and, once
 * the pin is filled, to reject with the BATCH status, which is the form that
 * proves the perturbed publics actually reach the constraint system rather
 * than merely being written into a buffer.
 *
 * Skips silently when `proof` is NULL. That is the one deliberate skip in this
 * file and it is bounded: `t_query_alias`'s mask half runs either way, so the
 * alias SHAPE is still asserted; only the "and the batch notices" half needs a
 * proof. See t_query_alias's nullable note for why that path exists.
 */
static void expect_entry_reject(const dnac_p2s_statement_t *bad,
                                const dnac_batch_proof_t *proof,
                                const char *fmt, ...)
{
    char where[192];
    dnac_p2s_status_t st;
    va_list ap;

    /* The skip is deliberate (see the header comment) but must NEVER be
     * SILENT: it does not increment `g_checks`, so a prover that stopped
     * producing proofs would SHRINK the reported check count instead of
     * failing, and a before/after count comparison would read the shrink as
     * "fewer tests" rather than "the prover broke". Announce it.
     * (FLEET 035 verifier finding.) */
    if (!proof) {
        va_start(ap, fmt);
        vsnprintf(where, sizeof(where), fmt, ap);
        va_end(ap);
        printf("  [skip]   %s: no proof (prover blocked) — batch leg NOT run\n",
               where);
        return;
    }
    va_start(ap, fmt);
    vsnprintf(where, sizeof(where), fmt, ap);
    va_end(ap);

    st = p2s_run_entry(bad, proof, NULL, NULL);
    CHECK(st != DNAC_P2S_OK, "%s: perturbation was ACCEPTED", where);
#if !DNAC_P2S_PREP_ROOT_UNFILLED
    CHECK(st == DNAC_P2S_ERR_BATCH,
          "%s: rejected as %d, want the BATCH check (the publics must actually "
          "reach the constraint system)", where, (int)st);
#endif
}

static void rt1_and_proof_negatives(const dnac_p2s_statement_t *stmt,
                                    const traces_t *T,
                                    const uint64_t honest_root[4])
{
    dnac_batch_proof_t *proof = NULL;
    dnac_batch_vcommits_t cm;
    dnac_batch_vopened_t opened[DNAC_P2S_NUM_INSTANCES];
    uint32_t nprep = 0;
    const uint32_t *map = NULL;

    printf("  [rt]     preprocessed widths: tair %zu, mmix %zu, mmcs %zu, "
           "fri %zu, oi %zu (the batch_prover.c pw cap is lifted)\n",
           dnac_p2s_prep_cols(DNAC_P2S_INST_TAIR),
           dnac_p2s_prep_cols(DNAC_P2S_INST(0, DNAC_P2S_SLOT_MMIX(0))),
           dnac_p2s_prep_cols(DNAC_P2S_INST(0, DNAC_P2S_SLOT_MMCS(0))),
           dnac_p2s_prep_cols(DNAC_P2S_INST(0, DNAC_P2S_SLOT_FRI)),
           dnac_p2s_prep_cols(DNAC_P2S_INST(0, DNAC_P2S_SLOT_OI)));

    if (!p2s_prove(stmt, T, &proof)) {
        /* If this fires, check T-QCAP FIRST: the quotient round puts one matrix
         * per quotient chunk of every instance into ONE FRI input batch
         * (batch_verify.c:373-374 with :579), and exceeding FRI_MAX_RO makes
         * the prover's own self-verify (batch_prover.c:1639-1646) reject with a
         * status that names nothing. That was the FLEET 037 blocker, closed by
         * the 64 → 128 raise. */
        CHECK(0, "RT-1: dnac_batch_prove could not prove the %u-instance set "
                 "(quotient round %zu matrices vs FRI_MAX_RO %zu — check "
                 "T-QCAP)",
              DNAC_P2S_NUM_INSTANCES,
              (size_t)DNAC_P2S_NUM_INSTANCES
                  << dnac_p2s_log_num_qc(DNAC_P2S_MAX_SYMBOLIC_DEGREE, 0),
              (size_t)DNAC_P2S_FRI_MAX_RO);
        /* ⚠ NO SILENT SKIP. A prove failure is exactly what a BROKEN alias
         * produces — query q's honest trace then contradicts the publics the
         * entry hands it — so returning here would suppress the very checks
         * that name the cause. The proof-free half of the alias evidence runs
         * regardless (FLEET 028 verifier M1). */
        t_query_alias(stmt, NULL);
        t_ncfg();
        return;
    }
    printf("  [rt]     dnac_batch_prove OK — %u instances (1 transcript + "
           "%zu queries x (%zu input batches + %zu commit rounds + fri + oi)), "
           "is_zk 0\n",
           DNAC_P2S_NUM_INSTANCES, (size_t)DNAC_P2S_NUM_QUERIES,
           (size_t)DNAC_P2S_OI_NUM_BATCHES, (size_t)DNAC_P2S_FRI_R);

    map = dnac_batch_proof_prep_map(proof, &nprep);
    dnac_batch_proof_commits(proof, &cm);
    for (uint32_t i = 0; i < DNAC_P2S_NUM_INSTANCES; i++) {
        opened[i] = *dnac_batch_proof_opened(proof, i);
    }

    /* The prover's own preprocessed map must be the order the pin commits to —
     * otherwise the pin would be comparing against a differently-ordered tree. */
    CHECK(nprep == DNAC_P2S_NUM_INSTANCES, "RT-1: %u preprocessed matrices",
          nprep);
    if (nprep == DNAC_P2S_NUM_INSTANCES) {
        for (uint32_t m = 0; m < nprep; m++) {
            CHECK(map[m] == m, "RT-1: prover prep_map[%u] = %u", m, map[m]);
        }
    }

    /* What the pin pins IS what the prover commits. */
    CHECK(cm.preprocessed_commit != NULL,
          "RT-1: the proof carries no preprocessed commitment");
    if (cm.preprocessed_commit) {
        size_t bad = 0;
        for (size_t k = 0; k < 4; k++) {
            if (gold_fp_to_u64(cm.preprocessed_commit[k]) != honest_root[k]) {
                bad++;
            }
        }
        CHECK(bad == 0,
              "RT-1: the proof's preprocessed root differs from the recomputed "
              "pipeline root in %zu lane(s)", bad);
    }

    /* ── steps 3-7, pin aside: the instances the ENTRY builds, verified
     * directly. Pin-independent, so it is a full-strength gate in either pin
     * state, and it is what proves the entry's descriptors + aliased publics
     * are not merely self-consistent but actually satisfied by a real proof. ── */
    {
        dnac_batch_verify_status_t bs;
        CHECK(set_build(&g_set_a, stmt) == DNAC_P2S_OK,
              "RT-1: build_instances rejected the honest statement");
        bs = dnac_batch_verify(g_set_a.insts, opened, DNAC_P2S_NUM_INSTANCES, 0,
                               &cm, map, nprep, dnac_p2s_fri_params(), 0, 0,
                               dnac_batch_proof_fri(proof), NULL, NULL);
        CHECK(bs == DNAC_BV_OK,
              "RT-1: the entry's own instances do NOT verify (batch %d)",
              (int)bs);
        if (bs == DNAC_BV_OK) {
            printf("  [rt]     steps 3-7 verify GREEN (entry-built "
                   "descriptors + aliased publics)\n");
        }
    }

    /* ── RT-1 proper, through the ENTRY ── */
    {
        dnac_batch_verify_out_t out;
        const dnac_p2s_status_t st = p2s_run_entry(stmt, proof, NULL, &out);
#if DNAC_P2S_PREP_ROOT_UNFILLED
        CHECK(st == DNAC_P2S_ERR_PREP_ROOT,
              "RT-1: with the pin unfilled the entry must reject at step 2, "
              "got %d", (int)st);
        printf("  [rt]     entry rejects on the UNFILLED pin (expected; fill "
               "it with --print-roots and RT-1 becomes an accept)\n");
#else
        CHECK(st == DNAC_P2S_OK,
              "RT-1: the entry rejected an honest proof (%d)", (int)st);
        if (st == DNAC_P2S_OK) {
            printf("  [rt]     RT-1 honest round-trip OK\n");
        }
#endif
    }

    /* ── N-PIN2: `prep_next = 0`. The entry HARD-CODES 1, so the descriptor
     * cannot be built through it; this drives dnac_batch_verify directly, which
     * is the reachable evidence class the fri table's width gives — at 73 > 64
     * the zero-window capacity guard rejects on SHAPE outright
     * (batch_verify.c:696-706), rather than substituting an all-zero window. ── */
    {
        /* Driven per SLOT, on query 0's instance — the Q copies have identical
         * widths (T-MAP asserts that), so one per slot is the full evidence. */
        const uint32_t fri_i = DNAC_P2S_INST(0, DNAC_P2S_SLOT_FRI);
        const uint32_t oi_i = DNAC_P2S_INST(0, DNAC_P2S_SLOT_OI);
        const uint32_t mmcs_i = DNAC_P2S_INST(0, DNAC_P2S_SLOT_MMCS(0));
        dnac_batch_verify_status_t bs;

        if (set_build(&g_set_a, stmt) == DNAC_P2S_OK) {
            CHECK(dnac_p2s_prep_cols(fri_i) > 64,
                  "N-PIN2: the fri preprocessed width is no longer > 64, so "
                  "the SHAPE route this negative relies on has moved");
            g_set_a.insts[fri_i].prep_next = 0;
            bs = dnac_batch_verify(g_set_a.insts, opened,
                                   DNAC_P2S_NUM_INSTANCES, 0, &cm, map, nprep,
                                   dnac_p2s_fri_params(), 0, 0,
                                   dnac_batch_proof_fri(proof), NULL, NULL);
            CHECK(bs == DNAC_BV_ERR_SHAPE,
                  "N-PIN2: prep_next = 0 gave %d, want DNAC_BV_ERR_SHAPE",
                  (int)bs);

            /* The oi table is 106 columns, so it takes the SAME capacity route
             * as fri — pinned separately because a future width change could
             * move it to the other one silently. */
            if (set_build(&g_set_a, stmt) == DNAC_P2S_OK) {
                CHECK(dnac_p2s_prep_cols(oi_i) > 64,
                      "N-PIN2: the oi preprocessed width is no longer > 64");
                g_set_a.insts[oi_i].prep_next = 0;
                bs = dnac_batch_verify(g_set_a.insts, opened,
                                       DNAC_P2S_NUM_INSTANCES, 0, &cm, map,
                                       nprep, dnac_p2s_fri_params(), 0, 0,
                                       dnac_batch_proof_fri(proof), NULL, NULL);
                CHECK(bs == DNAC_BV_ERR_SHAPE,
                      "N-PIN2: oi prep_next = 0 gave %d, want "
                      "DNAC_BV_ERR_SHAPE", (int)bs);
            }

            /* The mmcs table is 3 columns, UNDER the zero-window capacity, so
             * flipping ITS prep_next takes the other documented route: the
             * window is silently zeroed and the AIR's gated forms then fail the
             * constraint check instead of the shape check. Both are rejects;
             * pinning which one keeps the two routes distinguishable. */
            if (set_build(&g_set_a, stmt) == DNAC_P2S_OK) {
                CHECK(dnac_p2s_prep_cols(mmcs_i) <= 64,
                      "N-PIN2: the mmcs width moved above the zero-window cap");
                g_set_a.insts[mmcs_i].prep_next = 0;
                bs = dnac_batch_verify(g_set_a.insts, opened,
                                       DNAC_P2S_NUM_INSTANCES, 0, &cm, map,
                                       nprep, dnac_p2s_fri_params(), 0, 0,
                                       dnac_batch_proof_fri(proof), NULL, NULL);
                CHECK(bs != DNAC_BV_OK,
                      "N-PIN2: mmcs prep_next = 0 was ACCEPTED");
            }
        }
    }

    t_query_alias(stmt, proof);
    t_ncfg();
    dnac_batch_proof_free(proof);
}

/* ══════════════════════════════════════════════════════════════════════════
 * N-QSEP / N-QSHARED / N-QINDEP / N-ALIAS — ONE mechanism, three claims.
 *
 * Every one of these perturbs exactly ONE statement lane, rebuilds the
 * descriptors, and asserts the EXACT SET of instances whose publics moved.
 * An exact set (rather than "at least one moved") is what makes the three
 * claims separable:
 *
 *   N-QSEP    query separation — the acceptance criterion of the multi-query
 *             slice. Perturbing the transcript's q-th exported bit block must
 *             move query q's four instances and NOT any other query's. If the
 *             Q consumers had collapsed onto export block 0, flipping block 1
 *             would move NOTHING downstream and flipping block 0 would move
 *             EVERY query — either way the expected set is wrong and this
 *             fires.
 *   N-QSHARED the shared Fiat-Shamir values reach BOTH queries.
 *   N-QINDEP  a per-query value reaches ONLY its own query.
 *
 * Then the entry itself is required to reject — post-fill with the BATCH
 * status, which is what proves the publics really do reach the constraint
 * system rather than merely being written.
 *
 * ⚠ `proof` IS NULLABLE, deliberately. The mask half needs no proof at all: it
 * is a statement about `build_instances`. Keeping it runnable with a NULL proof
 * means a prover blockage — which is exactly what a BROKEN alias causes, since
 * query q's honest trace then contradicts the publics it is given — cannot
 * silently skip the very evidence that would name the cause (the FLEET 028
 * verifier M1 no-silent-escape discipline). With a NULL proof the reject legs
 * are skipped and the mask legs still run.
 */
static void t_query_alias(const dnac_p2s_statement_t *stmt,
                          const dnac_batch_proof_t *proof)
{
    /* ── N-QSEP + N-RSEP/dir: flip ONE bit of ONE query's index. ────────────
     * Expected set, DERIVED (not listed): the transcript instance, because the
     * bit IS its q-th exported public; plus query q's mmix / fri / oi, whose
     * bit regions are the whole index; plus EXACTLY THOSE commit rounds whose
     * dir window contains bit l. `verify_query` shifts the index down by
     * log_arity once per round before that round's MMCS walk
     * (fri_verifier.c:558 with :585-588), so round r reads bits from
     * BIT_OFF(r) = (r+1)*log_arity upward: bit 0 reaches NO round, bit 1 only
     * round 0, and only the top bit reaches all R. NOTHING of any other query.
     *
     * That per-round subset IS the dir-axis half of N-RSEP: a collapse that
     * fed every round round 0's window would move all R rounds for bit 1 and
     * none for the top bits, and the exact-set comparison fires either way.
     * The `hit`/`miss` tallies below make the non-vacuity explicit — if every
     * bit reached every round the claim would be empty. */
    {
        size_t partial = 0;
        for (size_t qq = 0; qq < DNAC_P2S_NUM_QUERIES; qq++) {
            for (size_t l = 0; l < DNAC_P2S_LGMH; l++) {
                dnac_p2s_statement_t bad = *stmt;
                uint32_t want;
                size_t hit = 0;

                bad.index_bits[qq][l] ^= 1u;
                if (!set_pair(stmt, &bad, "N-QSEP")) continue;

                want = P2S_TMASK | P2S_IMASK(qq, DNAC_P2S_SLOT_FRI) |
                       P2S_IMASK(qq, DNAC_P2S_SLOT_OI);
                /* EVERY input batch of this query: their dir regions are the
                 * whole index (depth == lgmh for every batch), so a bit reaches
                 * all B — unlike the commit rounds, whose windows are proper
                 * suffixes. */
                for (size_t b = 0; b < DNAC_P2S_OI_NUM_BATCHES; b++) {
                    want |= P2S_IMASK(qq, DNAC_P2S_SLOT_MMIX(b));
                }
                for (size_t r = 0; r < DNAC_P2S_FRI_R; r++) {
                    if (l >= DNAC_P2S_MMCS_BIT_OFF(r) &&
                        l < DNAC_P2S_MMCS_BIT_OFF(r) +
                                DNAC_P2S_MMCS_DEPTH(r)) {
                        want |= P2S_IMASK(qq, DNAC_P2S_SLOT_MMCS(r));
                        hit++;
                    }
                }
                if (hit > 0 && hit < DNAC_P2S_FRI_R) partial++;
                check_mask(moved_mask(), want, "N-QSEP: index_bits[q%zu][%zu]",
                           qq, l);
                expect_entry_reject(&bad, proof,
                                    "N-QSEP: index_bits[q%zu][%zu]", qq, l);
            }
        }
        CHECK(partial > 0,
              "N-RSEP/dir: no index bit reaches a PROPER SUBSET of the commit "
              "rounds — the round windows are not separated and the exact-set "
              "check above is vacuous on the round axis");
    }

    /* ── N-RSEP/opened: round r's LEAF reaches ONLY (query, round). ──────────
     * The acceptance criterion of the round axis on the data side. Round r's
     * opened leaf is `mmcs_opened[q][r]`, and nothing else in the composition
     * reads it — not the other rounds of the same query (they open different
     * trees at different depths, fri_verifier.c:557-558), not the same round of
     * another query (that query opens the same tree at ITS index), and not the
     * fri instance (HONEST LABEL 9: the leaf/fold seam is still open, so a
     * move here reaching fri would mean an alias nobody built). ── */
    for (size_t qq = 0; qq < DNAC_P2S_NUM_QUERIES; qq++) {
        for (size_t r = 0; r < DNAC_P2S_FRI_R; r++) {
            for (size_t c = 0; c < DNAC_P2S_MMCS_TOTAL_WIDTH; c++) {
                dnac_p2s_statement_t bad = *stmt;
                bad.mmcs_opened[qq][r][c] = gold_fp_to_u64(gold_fp_add(
                    gold_fp_from_u64(bad.mmcs_opened[qq][r][c]),
                    gold_fp_one()));
                if (!set_pair(stmt, &bad, "N-RSEP/opened")) continue;
                check_mask(moved_mask(),
                           P2S_IMASK(qq, DNAC_P2S_SLOT_MMCS(r)),
                           "N-RSEP/opened: mmcs_opened[q%zu][r%zu][%zu]", qq, r,
                           c);
                expect_entry_reject(&bad, proof,
                                    "N-RSEP/opened: mmcs_opened[q%zu][r%zu]"
                                    "[%zu]", qq, r, c);
            }
        }
    }

    /* ── N-QSHARED: the values the native samples/observes ONCE reach EVERY
     * query's consumer. A per-query copy of any of them would let two queries
     * be folded with two different challenges, which is the other half of the
     * OBL-P2c-2 shape. ── */
    {
        const dnac_tair_script_t *ts = dnac_p2s_tair_script();
        uint32_t all_oi = 0, all_fri = 0;

        for (size_t q = 0; q < DNAC_P2S_NUM_QUERIES; q++) {
            all_oi |= P2S_IMASK(q, DNAC_P2S_SLOT_OI);
            all_fri |= P2S_IMASK(q, DNAC_P2S_SLOT_FRI);
        }

        /* alpha (fri_verifier.c:694) -> EVERY oi instance, and the transcript
         * whose payload lane it is. betas (:707) -> EVERY fri instance. */
        {
            struct { size_t ord; const char *what; uint32_t extra; } legs[] = {
                { 0, "alpha.c0", 0 },
                { 1, "alpha.c1", 0 },
                { 2, "beta[0].c0", 1 },
                { 3, "beta[0].c1", 1 },
                { 2 + 2 * (DNAC_P2S_FRI_R - 1), "beta[R-1].c0", 1 },
            };
            for (size_t e = 0; e < sizeof(legs) / sizeof(legs[0]); e++) {
                const size_t k = tair_pop_op(ts, legs[e].ord);
                dnac_p2s_statement_t bad = *stmt;

                if (k == (size_t)-1 || k >= DNAC_P2S_TAIR_NUM_OPS) {
                    CHECK(0, "N-QSHARED/%s: no such pop in the pinned script",
                          legs[e].what);
                    continue;
                }
                bad.tair_payload[k] = gold_fp_to_u64(gold_fp_add(
                    gold_fp_from_u64(bad.tair_payload[k]), gold_fp_one()));
                if (!set_pair(stmt, &bad, "N-QSHARED")) continue;
                check_mask(moved_mask(),
                           P2S_TMASK | (legs[e].extra ? all_fri : all_oi),
                           "N-QSHARED: tair_payload[%s]", legs[e].what);
                expect_entry_reject(&bad, proof, "N-QSHARED: tair_payload[%s]",
                                    legs[e].what);
            }
        }

        /* final_poly0 -> EVERY fri instance, and NOTHING else.
         * ⚠ HONEST LABEL: NOT the transcript, and the contrast with N-OBSBIND
         * below is the point. The native observes the final poly
         * (fri_verifier.c:710-713) and the pinned script HAS those observe ops,
         * but their payload lanes are still deterministic fixtures rather than
         * aliases of this field — residue (b) of fri_statement.h HONEST LABEL
         * 6, which the commit digests no longer share. So this negative pins
         * "shared across queries"; N-OBSBIND is what pins "transcript-bound",
         * and it does so for the digests only. */
        for (size_t j = 0; j < 2; j++) {
            dnac_p2s_statement_t bad = *stmt;
            bad.final_poly0[j] = gold_fp_to_u64(gold_fp_add(
                gold_fp_from_u64(bad.final_poly0[j]), gold_fp_one()));
            if (!set_pair(stmt, &bad, "N-QSHARED")) continue;
            check_mask(moved_mask(), all_fri, "N-QSHARED: final_poly0[%zu]", j);
            expect_entry_reject(&bad, proof, "N-QSHARED: final_poly0[%zu]", j);
        }

        /* ── N-PZSHARED: the CLAIMED EVALUATIONS -> EVERY query's oi instance,
         * and nothing else.
         *
         * This is the acceptance criterion of the p_z split. `p_z` used to live
         * inside the per-query `zpz[q]` region with no reason given, which let
         * two queries name two different claimed evaluations for the same
         * opening — a freedom the native does not have (fri_verifier.c:470
         * reads them through `commitments`, and :743 passes the query loop the
         * SAME pointer every iteration). If the alias were not built, only ONE
         * query's oi instance would move here and the exact-set check fires.
         *
         * SWEPT over every lane, not sampled: the mask half is pure
         * `build_instances` and costs nothing, and a region-walk off-by-one
         * would move a NEIGHBOURING row rather than none at all — which only a
         * full sweep with an exact expected set catches. The expensive
         * entry-reject leg stays on the two ENDS, the same split the z leg
         * below uses. ── */
        for (size_t i = 0; i < 2 * DNAC_P2S_OI_TOTAL_ACC; i++) {
            dnac_p2s_statement_t bad = *stmt;
            bad.pz_shared[i] = gold_fp_to_u64(gold_fp_add(
                gold_fp_from_u64(bad.pz_shared[i]), gold_fp_one()));
            if (!set_pair(stmt, &bad, "N-PZSHARED")) continue;
            check_mask(moved_mask(), all_oi, "N-PZSHARED: pz_shared[%zu]", i);
            if (i == 0 || i == 2 * DNAC_P2S_OI_TOTAL_ACC - 1) {
                expect_entry_reject(&bad, proof, "N-PZSHARED: pz_shared[%zu]",
                                    i);
            }
        }

        /* The commitment roots -> every instance of their own slot, and nothing
         * else. One commitment, Q openings — and, since the input-batch slice,
         * B such statements rather than one. The expected set is
         * {mmix[q][b] : all q} for the perturbed batch and NOTHING of any other
         * batch: a collapse that fed every batch batch 0's root would move all
         * B for a batch-0 lane and none for the others. That is the SHARED-axis
         * half of N-BSEP, and it is why this loop is over b as well as k. */
        for (size_t b = 0; b < DNAC_P2S_OI_NUM_BATCHES; b++) {
            uint32_t all_b = 0;
            for (size_t q = 0; q < DNAC_P2S_NUM_QUERIES; q++) {
                all_b |= P2S_IMASK(q, DNAC_P2S_SLOT_MMIX(b));
            }
            for (size_t k = 0; k < (size_t)MMIX_DIGEST_LANES; k++) {
                dnac_p2s_statement_t bad = *stmt;
                bad.mmix_root[b][k] = gold_fp_to_u64(gold_fp_add(
                    gold_fp_from_u64(bad.mmix_root[b][k]), gold_fp_one()));
                if (!set_pair(stmt, &bad, "N-QSHARED")) continue;
                check_mask(moved_mask(), all_b,
                           "N-QSHARED: mmix_root[b%zu][%zu]", b, k);
                expect_entry_reject(&bad, proof,
                                    "N-QSHARED: mmix_root[b%zu][%zu]", b, k);
            }
        }
        /* ── N-OBSBIND — HONEST LABEL 6's ACCEPTANCE CRITERION, and the round
         * axis's shared-value leg in one.
         *
         * `mmcs_root[r]` has TWO consumers by construction: every query's
         * round-r MMCS instance (shared across q — one commitment, Q openings)
         * AND the transcript instance's round-r digest observe lanes, which is
         * what makes "the challenger absorbed the root this walk verifies
         * against" true rather than merely plausible (fri_verifier.c:702 vs
         * :585). So the expected set is {tair} ∪ {mmcs[q][r] : all q}, and
         * NOTHING of any other round.
         *
         * Before the alias existed the tair bit of that set was absent — the
         * transcript observed a deterministic fixture instead — so this leg is
         * the one that goes RED without it. The per-round disjointness is the
         * other half: a root that reached rounds it does not belong to would
         * mean the digest ordinal map picked the wrong observe block. ── */
        for (size_t r = 0; r < DNAC_P2S_FRI_R; r++) {
            uint32_t all_r = 0;
            for (size_t q = 0; q < DNAC_P2S_NUM_QUERIES; q++) {
                all_r |= P2S_IMASK(q, DNAC_P2S_SLOT_MMCS(r));
            }
            for (size_t k = 0; k < (size_t)MAIR_DIGEST_LANES; k++) {
                dnac_p2s_statement_t bad = *stmt;
                bad.mmcs_root[r][k] = gold_fp_to_u64(gold_fp_add(
                    gold_fp_from_u64(bad.mmcs_root[r][k]), gold_fp_one()));
                if (!set_pair(stmt, &bad, "N-OBSBIND")) continue;
                check_mask(moved_mask(), P2S_TMASK | all_r,
                           "N-OBSBIND: mmcs_root[r%zu][%zu]", r, k);
                expect_entry_reject(&bad, proof,
                                    "N-OBSBIND: mmcs_root[r%zu][%zu]", r, k);
            }
        }

        /* ── N-OBSDEAD — the other side of the same closure. Once the digest
         * lanes are sourced from `mmcs_root[r]`, the `tair_payload` lanes at
         * those op indices are read by NOTHING: the entry overwrites them. That
         * is stated in the field comment; this asserts it, so "dead" is a
         * measured property and not a promise. Expected set: the EMPTY set. ── */
        for (size_t r = 0; r < DNAC_P2S_FRI_R; r++) {
            for (size_t i = 0; i < (size_t)DNAC_P2M_DIGEST_LANES; i++) {
                const size_t k = tair_obs_op(ts, DNAC_P2S_OBS_DIGEST(r, i));
                dnac_p2s_statement_t bad = *stmt;
                if (k == (size_t)-1 || k >= DNAC_P2S_TAIR_NUM_OPS) {
                    CHECK(0, "N-OBSDEAD: no observe op for round %zu lane %zu",
                          r, i);
                    continue;
                }
                bad.tair_payload[k] = gold_fp_to_u64(gold_fp_add(
                    gold_fp_from_u64(bad.tair_payload[k]), gold_fp_one()));
                if (!set_pair(stmt, &bad, "N-OBSDEAD")) continue;
                check_mask(moved_mask(), 0u,
                           "N-OBSDEAD: tair_payload[digest r%zu lane %zu]", r,
                           i);
            }
        }
    }

    /* ── N-QINDEP: a PER-QUERY lane reaches ONLY its own query's consumers.
     * This is the leg that would fire if a per-query region had been aliased
     * across q (the collapse), and it also carries the older single-query
     * claim it subsumes: the ro-export two-consumer property (s1c), now stated
     * as an exact instance set instead of a pair of booleans.
     * ⚠ The p_x legs that used to live here — the s2 alias (N-ALIAS/px) and the
     * `px_rest` honest label (N-PXREST) — have MOVED, not been dropped: they
     * are the (query, batch) claims of N-BSEP / N-PXBOUND below, which is a
     * strictly finer statement than "reaches only query qq". ── */
    for (size_t qq = 0; qq < DNAC_P2S_NUM_QUERIES; qq++) {
        const uint32_t m_fri = P2S_IMASK(qq, DNAC_P2S_SLOT_FRI);
        const uint32_t m_oi = P2S_IMASK(qq, DNAC_P2S_SLOT_OI);

        /* ro_export (s1c): the seed lane feeds fri's f_init, a roll-in height's
         * lane feeds that roll-in slot — and BOTH feed the oi ro publics. Every
         * pinned height is either the seed or a roll-in, so EVERY lane must
         * reach fri; a future cfg exporting a height fri neither seeds from nor
         * rolls in would be reported here rather than silently becoming a
         * one-sided alias. */
        for (size_t i = 0; i < 2 * DNAC_P2S_OI_NUM_HEIGHTS; i++) {
            dnac_p2s_statement_t bad = *stmt;
            bad.ro_export[qq][i] = gold_fp_to_u64(gold_fp_add(
                gold_fp_from_u64(bad.ro_export[qq][i]), gold_fp_one()));
            if (!set_pair(stmt, &bad, "N-QINDEP/ro")) continue;
            check_mask(moved_mask(), m_fri | m_oi,
                       "N-QINDEP/ro: ro_export[q%zu][%zu]", qq, i);
            expect_entry_reject(&bad, proof,
                                "N-QINDEP/ro: ro_export[q%zu][%zu]", qq, i);
        }

        /* ── N-BSEP + N-PXBOUND(perturbation) — ►► THE ACCEPTANCE CRITERION OF
         * THE INPUT-BATCH SLICE, on the data side. ONE perturbation, TWO
         * claims, because they are two facets of the same alias:
         *
         *   N-BSEP    (exact set) a lane of BATCH b's opened span reaches
         *             {mmix[qq][b], oi[qq]} and NOTHING else — not another
         *             batch's mmix instance (each has its own span), not
         *             another query's anything (the row is per query).
         *             Under a collapse that fed every batch batch 0's span, a
         *             batch-1 lane would move mmix[qq][0] instead of
         *             mmix[qq][1], and the exact set fires.
         *   N-PXBOUND (the closure) the `oi` bit of that set is not incidental:
         *             it is the p_x alias, and BEFORE this slice it was ABSENT
         *             for b > 0 — the quotient and preprocessed rows came from
         *             the deleted `px_rest`, so perturbing their opened lanes
         *             moved oi not at all. The `m_oi` bit going missing is
         *             therefore exactly the RED signal of a regression to the
         *             s2 shape, and it is asserted for EVERY batch.
         *
         * Plus the containment leg: inside the oi vector the move must land
         * ONLY in the p_x region, and only at the acc rows belonging to batch
         * b — anywhere else would mean the region walk mis-partitioned. ── */
        for (size_t b = 0; b < DNAC_P2S_OI_NUM_BATCHES; b++) {
            const uint32_t m_mmix_b = P2S_IMASK(qq, DNAC_P2S_SLOT_MMIX(b));
            const size_t base = dnac_p2s_mmix_opened_off(b);

            CHECK(base != (size_t)-1, "N-BSEP: batch %zu has no opened offset",
                  b);
            if (base == (size_t)-1) continue;
            for (size_t c = 0; c < DNAC_P2S_MMIX_TOTAL_OPENED(b); c++) {
                dnac_p2s_statement_t bad = *stmt;
                const size_t opx = dnac_foi_pub_px_off(dnac_p2s_oi_cfg());
                const gold_fp_t *ao, *bo;
                int outside_px = 0, px_moved = 0;

                bad.mmix_opened[qq][base + c] =
                    gold_fp_to_u64(gold_fp_add(
                        gold_fp_from_u64(bad.mmix_opened[qq][base + c]),
                        gold_fp_one()));
                if (!set_pair(stmt, &bad, "N-BSEP")) continue;
                check_mask(moved_mask(), m_mmix_b | m_oi,
                           "N-BSEP: mmix_opened[q%zu] batch %zu lane %zu "
                           "(flat %zu)", qq, b, c, base + c);

                ao = set_pub(&g_set_a, DNAC_P2S_INST(qq, DNAC_P2S_SLOT_OI));
                bo = set_pub(&g_set_b, DNAC_P2S_INST(qq, DNAC_P2S_SLOT_OI));
                for (size_t k = 0; k < opx; k++) {
                    if (gold_fp_to_u64(ao[k]) != gold_fp_to_u64(bo[k])) {
                        outside_px = 1;
                    }
                }
                for (size_t k = opx; k < DNAC_P2S_OI_NUM_PUBLICS; k++) {
                    if (gold_fp_to_u64(ao[k]) != gold_fp_to_u64(bo[k])) {
                        px_moved = 1;
                    }
                }
                CHECK(!outside_px,
                      "N-BSEP: mmix_opened[q%zu] batch %zu lane %zu moved an "
                      "oi public OUTSIDE the p_x region", qq, b, c);
                /* THE CLOSURE ASSERTION, stated on its own so a failure names
                 * it rather than hiding inside the mask message. */
                CHECK(px_moved,
                      "N-PXBOUND: mmix_opened[q%zu] batch %zu lane %zu reaches "
                      "NO oi p_x public — batch %zu's acc rows are not bound to "
                      "its opening (the pre-slice `px_rest` shape)", qq, b, c,
                      b);
                expect_entry_reject(&bad, proof,
                                    "N-BSEP: mmix_opened[q%zu] batch %zu lane "
                                    "%zu", qq, b, c);
            }
        }

        /* mmcs_opened's per-query claim is now the (query, round) claim of
         * N-RSEP/opened above, and mmix_opened's is the (query, batch) claim of
         * N-BSEP — the same perturbations with finer expected sets, so neither
         * is repeated here. */

        /* z — the OPENING POINTS. One consumer, this query's oi instance: this
         * is the half of the old `zpz` region that legitimately stays per-query
         * (HONEST LABEL 8 — the shipped builder ties z to x, and x moves with
         * the index). Its counterpart p_z is now SHARED and is pinned by
         * N-PZSHARED; keeping both checks means the split cannot silently
         * regress in either direction — a per-query p_z would fail N-PZSHARED,
         * and a shared z would fail here.
         *
         * SWEPT for the mask, entry-rejected at the two ENDS: 2*total_acc lanes
         * x Q full batch verifications buy nothing the exact-set mask does not
         * already say, and the ends are what a region-walk off-by-one moves. */
        {
            for (size_t i = 0; i < 2 * DNAC_P2S_OI_TOTAL_ACC; i++) {
                dnac_p2s_statement_t bad = *stmt;
                bad.z_pq[qq][i] = gold_fp_to_u64(gold_fp_add(
                    gold_fp_from_u64(bad.z_pq[qq][i]), gold_fp_one()));
                if (!set_pair(stmt, &bad, "N-QINDEP/z")) continue;
                check_mask(moved_mask(), m_oi, "N-QINDEP/z: z_pq[q%zu][%zu]",
                           qq, i);
                if (i == 0 || i == 2 * DNAC_P2S_OI_TOTAL_ACC - 1) {
                    expect_entry_reject(&bad, proof,
                                        "N-QINDEP/z: z_pq[q%zu][%zu]", qq, i);
                }
            }
        }
    }

}

/* ── N-CFG (OBL-P2c-1): a proof whose fri instances were built on a DIFFERENT
 * cfg. The entry always rebuilds from the PINNED cfg, so the shapes cannot line
 * up. Self-contained (it builds its own traces, statement and proof), which is
 * why it takes nothing. ── */
static void t_ncfg(void)
{
    {
        static const dnac_p2c_table_cfg_t ALT = {
            DNAC_P2S_LGMH, DNAC_P2S_LOG_BLOWUP, DNAC_P2S_LFPL,
            DNAC_P2S_MAX_LOG_ARITY, 0, NULL, DNAC_P2S_NUM_QUERIES
        };
        traces_t AT;
        dnac_p2s_statement_t astmt;
        dnac_batch_proof_t *aproof = NULL;

        CHECK(dnac_fair_num_publics(&ALT) != DNAC_P2S_FRI_NUM_PUBLICS,
              "N-CFG: the alternative cfg has the SAME public count — the "
              "negative would not be testing a shape mismatch");

        if (!traces_build(&AT, &ALT, 11)) {
            /* A builder failure is a TEST defect, not an acceptable outcome:
             * it would silently skip OBL-P2c-1's negative (FLEET 028 verifier
             * M1 — no silent escape paths). */
            CHECK(0, "N-CFG: alternative-cfg traces not buildable (test bug)");
        } else {
            dnac_batch_pwitness_t wits[DNAC_P2S_NUM_INSTANCES];
            /* [Q][anp]: the alternative cfg is bound into EVERY query's fri
             * slot, so the mismatch is not one instance against Q-1 correct
             * ones — the statement's rebuild from the PINNED cfg has to
             * disagree with all of them. `static` because they must outlive
             * `dnac_batch_prove`. */
            static gold_fp_t alt_pub[DNAC_P2S_NUM_QUERIES][256];
            static dnac_fair_fold_state_t alt_state[DNAC_P2S_NUM_QUERIES];
            const size_t anp = dnac_fair_num_publics(&ALT);
            dnac_stark_air_t alt_air[DNAC_P2S_NUM_QUERIES];
            int ok = 1;

            stmt_from_traces(&astmt, &AT);
            if (set_build(&g_set_a, &astmt) != DNAC_P2S_OK) {
                CHECK(0, "N-CFG: build_instances failed");
                ok = 0;
            }
            if (ok && anp > sizeof(alt_pub[0]) / sizeof(alt_pub[0][0])) {
                CHECK(0, "N-CFG: alternative publics too wide");
                ok = 0;
            }
            /* FLEET 034: each alternative binding gets its OWN caller-owned
             * state, so it neither disturbs the statement's fri bindings nor
             * the other query's (with the retired module static, these binds
             * CLOBBERED the ones `build_instances` had just armed — the alt cfg
             * leaked into the statement's instance and the negative was
             * measuring the wrong thing). */
            for (size_t q = 0; ok && q < DNAC_P2S_NUM_QUERIES; q++) {
                memset(&alt_air[q], 0, sizeof(alt_air[q]));
                memset(&alt_state[q], 0, sizeof(alt_state[q]));
                if (dnac_fair_fold_bind(&ALT, &alt_state[q], &alt_air[q]) !=
                    DNAC_FAIR_FOLD_OK) {
                    CHECK(0, "N-CFG: could not bind the alternative cfg for "
                             "query %zu", q);
                    ok = 0;
                }
            }
            if (ok) {
                size_t db = 0, v = 1;
                const size_t rows = dnac_p2c_table_rows(&ALT);
                while (v < rows) { v <<= 1; db++; }

                p2s_fill_witnesses(wits, &AT);
                for (size_t q = 0; q < DNAC_P2S_NUM_QUERIES; q++) {
                    const uint32_t fi = DNAC_P2S_INST(q, DNAC_P2S_SLOT_FRI);
                    for (size_t i = 0; i < anp; i++) {
                        alt_pub[q][i] = gold_fp_from_u64(AT.q[q].fri.pub[i]);
                    }
                    g_set_a.insts[fi].air = alt_air[q];
                    g_set_a.insts[fi].num_publics = (uint32_t)anp;
                    g_set_a.insts[fi].public_values = alt_pub[q];
                    g_set_a.insts[fi].degree_bits = (uint32_t)db;
                }

                if (dnac_batch_prove(g_set_a.insts, wits,
                                     DNAC_P2S_NUM_INSTANCES, 0,
                                     dnac_p2s_fri_params(), 0, NULL, 0, NULL, 0,
                                     NULL, 0, 0, &aproof) != DNAC_PROVER_OK) {
                    /* Recorded as an explicit CHECK so N-CFG can never end
                     * with zero assertions (FLEET 028 verifier M1). Honest
                     * label: unprovability blocks the mismatch UPSTREAM of the
                     * entry; the entry-reject leg below is the one that tests
                     * OBL-P2c-1 directly, and which leg runs is a runtime
                     * fact reported here, not adjudicated. */
                    CHECK(1, "N-CFG: wrong-cfg batch refused by the prover "
                             "(mismatch unreachable; entry leg not exercised)");
                } else {
                    const dnac_p2s_status_t st =
                        p2s_run_entry(&astmt, aproof, NULL, NULL);
                    CHECK(st != DNAC_P2S_OK,
                          "N-CFG: a proof over a DIFFERENT fri cfg was "
                          "ACCEPTED");
                    printf("  [n-cfg]  wrong-cfg proof rejected (status %d)\n",
                           (int)st);
                    dnac_batch_proof_free(aproof);
                }
            }
            traces_free(&AT);
        }
    }
}

static void rt1_and_negatives(void)
{
    traces_t T;
    dnac_p2s_statement_t stmt;
    uint64_t honest_root[4] = { 0, 0, 0, 0 };

    if (!traces_build(&T, dnac_p2s_fri_cfg(), 7)) {
        CHECK(0, "RT: could not build the %u honest traces",
              DNAC_P2S_NUM_INSTANCES);
        traces_free(&T);
        return;
    }
    for (size_t q = 0; q < DNAC_P2S_NUM_QUERIES; q++) {
        printf("  [rt]     transcript-derived query index[%zu] = %llu "
               "(0x%llx)\n", q, (unsigned long long)T.q[q].index,
               (unsigned long long)T.q[q].index);
    }
    /* The Q indices of the PINNED script are CONSTANTS of this composition —
     * the script is fixed and `duplex_challenger.c` is deterministic, so this
     * is an assertion about the pin, not a probabilistic one. Two equal indices
     * would still be a legitimate protocol outcome (fri_verifier.c:737 samples
     * freshly and may repeat) and would not invalidate N-QSEP, whose fields are
     * separate regardless — but it would mean the Q traces are identical, which
     * is exactly the situation this slice exists to distinguish from, so it is
     * reported rather than tolerated silently. */
    for (size_t a = 0; a < DNAC_P2S_NUM_QUERIES; a++) {
        for (size_t b = a + 1; b < DNAC_P2S_NUM_QUERIES; b++) {
            CHECK(T.q[a].index != T.q[b].index,
                  "RT: the pinned script's query indices %zu and %zu are BOTH "
                  "%llu — the Q traces would be identical", a, b,
                  (unsigned long long)T.q[a].index);
        }
    }
    stmt_from_traces(&stmt, &T);
    t_alias_positive(&stmt, &T);

    if (!p2s_honest_root(honest_root)) {
        CHECK(0, "RT: the preprocessed commit pipeline failed");
        traces_free(&T);
        return;
    }
    t_steps12_negatives(&stmt, honest_root);
    rt1_and_proof_negatives(&stmt, &T, honest_root);
    traces_free(&T);
}

int main(int argc, char **argv)
{
    const char *path = "tools/vectors/batch_proof.json";
    int print_roots = 0;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--print-roots")) print_roots = 1;
        else path = argv[i];
    }

    if (print_roots) {
        uint64_t lanes[4];
        uint64_t *tab[DNAC_P2S_NUM_INSTANCES] = { 0 };
        const uint64_t *ctab[DNAC_P2S_NUM_INSTANCES];
        int ok = p2s_alloc_tables(tab);

        printf("multi-query + round + input-batch replication composed "
               "preprocessed root — the PINNED cfg set\n(%u tables: tair, then "
               "{mmix[0..%zu], mmcs[0..%zu], fri, oi} per query, "
               "%zu queries),\n",
               DNAC_P2S_NUM_INSTANCES, (size_t)DNAC_P2S_OI_NUM_BATCHES - 1,
               (size_t)DNAC_P2S_FRI_R - 1, (size_t)DNAC_P2S_NUM_QUERIES);
        printf("pipeline = batch_prover.c:786-822 with is_zk = 0, blowup %zu\n\n",
               (size_t)DNAC_P2S_LOG_BLOWUP);
        for (uint32_t i = 0; i < DNAC_P2S_NUM_INSTANCES; i++) {
            printf("  instance %2u %-10s: %zu rows x %zu cols -> lde %zu rows\n",
                   i, inst_name(i), dnac_p2s_prep_rows(i),
                   dnac_p2s_prep_cols(i),
                   dnac_p2s_prep_rows(i) << DNAC_P2S_LOG_BLOWUP);
        }
        if (ok) {
            for (uint32_t i = 0; i < DNAC_P2S_NUM_INSTANCES; i++) {
                ctab[i] = tab[i];
            }
            ok = p2s_commit_tables(ctab, lanes);
        }
        if (!ok) {
            printf("\nFAILED to compute the root\n");
            p2s_free_tables(tab);
            return 1;
        }
        printf("\nPaste into fri_statement.h:\n\n");
        for (size_t k = 0; k < 4; k++) {
            printf("#define DNAC_P2S_PREP_ROOT_LANE%zu UINT64_C(0x%016llx)\n", k,
                   (unsigned long long)lanes[k]);
        }
        printf("\n");
        p2s_free_tables(tab);
        return 0;
    }

    printf("=== s1b + s1c + s2 + s3b + MULTI-QUERY + ROUND + INPUT-BATCH "
           "REPLICATION — FRI-verify statement ENTRY (%u instances) ===\n\n",
           DNAC_P2S_NUM_INSTANCES);

    printf("T-CONST / T-LQ — the pinned arithmetic vs the module accessors\n");
    t_const();
    t_lq();

    printf("\nT-MAP — the multi-query instance map + the flat publics layout\n");
    t_map();

    printf("\nT-REF/tair — the transcript cfg + script derived from the s1 "
           "pins\n");
    t_tair_ref();

    printf("\nN-POWPIN — the grinding width the preprocessed root cannot bind\n");
    t_powpin();

    printf("\nT-REF — the pinned cfg set re-derived from the fixture\n");
    {
        size_t len = 0;
        char *buf = load_file(path, &len);
        if (!buf) {
            CHECK(0, "T-REF: cannot load %s", path);
        } else {
            jp_t p = { buf, 0, len };
            jv_t *doc = jp_value(&p);
            if (!doc) {
                CHECK(0, "T-REF: JSON parse failed for %s", path);
            } else {
                printf("  loaded %s (%zu bytes)\n", path, len);
                t_ref(doc);
                jv_free(doc);
            }
            free(buf);
        }
    }

    printf("\nT-PINKAT — the composed preprocessed root\n");
    t_pin_kat();

    printf("\nT-ALIAS + steps 1-2 negatives + RT-1\n");
    rt1_and_negatives();

    printf("\n=== %d checks, %d failures ===\n", g_checks, g_fails);
    if (p2s_mmix_fails || p2s_mmcs_fails || p2s_fri_fails || p2s_oi_fails ||
        p2s_tair_fails) {
        printf("NOTE: a shipped gate's own counter is non-zero "
               "(mmix %d, mmcs %d, fri %d, oi %d, tair %d) — its cross-checks "
               "fired\n",
               p2s_mmix_fails, p2s_mmcs_fails, p2s_fri_fails, p2s_oi_fails,
               p2s_tair_fails);
        return 1;
    }
    return g_fails ? 1 : 0;
}
