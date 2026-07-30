/**
 * @file test_fri_statement.c
 * @brief Composition s1b + s1c + s2 + s3b — gate for the FRI-verify statement
 *        ENTRY (fri_statement.{c,h}).
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
 *   T-SRC/px the same property one seam down (s2): every MAIN-batch acc row's
 *            p_x public in the oi instance IS the mmix instance's opened-row
 *            public for that height. Asserted on the entry's two output
 *            vectors, and required to have compared MAIN_ACC rows (non-vacuous).
 *   T-REF/px the fixture MEASUREMENT the s2 alias rests on: batch 0's per-height
 *            (matrices, points, columns) split, which must be the pinned one
 *            EXACTLY — the quotient batch's is NOT, which is why only batch 0
 *            may be aliased.
 *   N-PIN×4  tampering ONE cell of ONE table moves the composed root and the
 *            entry rejects at step 2; run once per table, so the test names the
 *            table even though the single composed root cannot.
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
 *            has to that value). s2 adds the PX leg: perturbing one
 *            `mmix_opened` lane lands in the mmix publics AND the oi p_x
 *            publics together, and NOWHERE ELSE in the oi vector.
 *   N-PXREST the honest label under test: `px_rest` IS read (perturbing a lane
 *            reaches the oi p_x publics and the entry rejects) and reaches ONLY
 *            oi — i.e. it is exactly the still-unbound remainder the header
 *            says it is, neither dead nor commitment-bound.
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
 *   N-BITSREST queries 1..Q-1's bits ARE read (they reach the tair publics) but
 *            reach ONLY tair — the honest label that no consumer models a
 *            second query yet (OBL-P2c-2), pinned from both sides.
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
 *     (test_mmcs_mixed_air.c:145-151, test_mmcs_air.c:128-133), so those two
 *     instances replay genuine Poseidon2 MMCS openings at the pinned shapes.
 *   - oi: NATIVE-FORMULA REPLAY. Its builder drives the exact field expressions
 *     of `fri_open_input` — x_h from the two-adic generator and the bit-reversed
 *     index, and ro += alpha_pow*(p_z - p_x)/(z - x) per acc row
 *     (test_fri_oi_air.c:10-23) — over ITS OWN deterministic z / p_z fixtures,
 *     at the pinned shape. So the ro EXPORTS RT-1 uses are genuine reduced
 *     openings of that fixture, not of prep_pair's data.
 *     s2 NARROWS this: the MAIN batch's acc rows no longer use the builder's
 *     p_x fixture — the `g_px_ext` hook feeds them the mmix instance's REAL
 *     opened lanes (which came out of a genuine Poseidon2 MMCS opening, above),
 *     so for those rows the accumulation is over real opened values. The
 *     quotient / preprocessed batches' rows keep the fixture, which is the same
 *     honest gap `px_rest` carries in the statement.
 *   - fri: its SIBLINGS are still the shipped deterministic fixture, but its
 *     f_init and roll-in are OVERRIDDEN with the oi instance's exported ro
 *     (s1c) and — s3b — every BETA is overridden with the transcript's own
 *     round-r pop, so the walk is seeded by the open_input result AND folded
 *     with the challenger's own challenges. What remains fixture-derived is the
 *     sibling column, which needs dnac_fri_test_verify_capture plus
 *     batch_verify's opening-round assembly (batch_verify.c:302-499) replicated
 *     test-side. That replication is a fork of consensus logic into a test and
 *     is NOT done here.
 *   - tair: REAL for the challenger, FIXTURE for what it observes. The trace is
 *     the shipped builder's, and its pops come from replaying the shipped
 *     `duplex_challenger.c`, so alpha / the betas / the query index are genuine
 *     Fiat-Shamir outputs of the pinned script. The OBSERVED lanes past the DS
 *     prefix are deterministic fixtures — ⚠ they are NOT aliased to the mmcs /
 *     mmix roots, so "the transcript absorbed the commitment this proof opens"
 *     is NOT closed here; that is the commit-round replication slice.
 * So RT-1 is: "the entry accepts an honest 5-instance proof over the pinned
 * cfgs, with every instance's index publics aliased from ONE transcript-produced
 * index, the fri walk's seed / roll-in aliased from the oi ro export, the fri
 * betas and the oi alpha aliased from the transcript payload, and the main
 * batch's p_x aliased from the mmix opening". It is NOT "the entry accepts
 * prep_pair's query 0". Reported as a delta against spec §4.
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
 * The observed lanes: the first RATE observes MUST be the DS prefix (the AIR
 * pins them, transcript_air.c:279); every later observe is a deterministic
 * fixture. Those later observes stand for the commit-phase digests, the final
 * poly and the per-round log_arity — ⚠ they are NOT aliased to `mmcs_root` /
 * `mmix_root`, so "the transcript observed the commitment this proof opens" is
 * NOT closed by this slice. It belongs to the commit-round replication slice,
 * with the rest of the round-1..R-1 seam. Stated rather than implied.
 */
typedef struct {
    p2s_tair_vec_t   *V;
    p2s_tair_built_t *B;
    uint64_t          index;                    /* query 0, low lgmh bits    */
    uint64_t          alpha[2];                 /* the first two pops        */
    uint64_t          beta[2 * DNAC_P2S_FRI_R]; /* per round, c0 then c1     */
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

/** Replay the pinned script through the shipped challenger and record the
 *  vector the shipped trace builder consumes. */
static int tair_make_vector(p2s_tair_vec_t *V, const dnac_tair_script_t *s)
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
            const uint64_t lane = (obs_seen < (size_t)TAIR_RATE)
                                      ? DNAC_DUPLEX_DS_PREFIX[obs_seen]
                                      : tair_obs_fixture(k);
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
static int tair_build(tair_run_t *T)
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

    if (!tair_make_vector(T->V, s)) {
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
    {
        const size_t kq = tair_pop_op(s, 2 + 2 * DNAC_P2S_FRI_R);
        size_t off;
        if (kq == (size_t)-1) {
            CHECK(0, "tair: the script has no query-0 pop");
            return 0;
        }
        off = dnac_tair_op_bit_off(s, kq);
        if (off == (size_t)-1) {
            CHECK(0, "tair: query 0 exports no bits");
            return 0;
        }
        T->index = 0;
        for (size_t l = 0; l < DNAC_P2S_LGMH; l++) {
            const uint64_t b = T->B->pub[off + l];
            if (b > 1) {
                CHECK(0, "tair: exported bit %zu is not boolean", l);
                return 0;
            }
            T->index |= b << l;
        }
        /* The exported bits must BE the low bits of the popped challenge —
         * otherwise the index the four consumers walk is not the one the
         * transcript produced, and the whole alias is decoration. */
        if ((T->B->pub[kq] & ((UINT64_C(1) << DNAC_P2S_LGMH) - 1)) != T->index) {
            CHECK(0, "tair: query-0 bits are not the low bits of its challenge");
            return 0;
        }
    }
    return 1;
}

/* ══════════════════════ T-CONST / T-LQ — the pinned arithmetic ═══════════ */

static void t_const(void)
{
    const dnac_p2c_mmix_table_cfg_t *mmix = dnac_p2s_mmix_cfg();
    const dnac_p2b_table_cfg_t      *mmcs = dnac_p2s_mmcs_cfg();
    const dnac_p2c_table_cfg_t      *fri = dnac_p2s_fri_cfg();
    const dnac_p2c_oi_table_cfg_t   *oi = dnac_p2s_oi_cfg();

    /* Each module's accessor vs this header's region arithmetic — two
     * independent derivations of the same number (count-KAFADAN discipline). */
    CHECK(dnac_mmix_air_num_publics(mmix) == DNAC_P2S_MMIX_NUM_PUBLICS,
          "T-CONST: mmix publics %zu != pinned %zu",
          dnac_mmix_air_num_publics(mmix), (size_t)DNAC_P2S_MMIX_NUM_PUBLICS);
    CHECK(dnac_mmcs_air_num_publics(mmcs) == DNAC_P2S_MMCS_NUM_PUBLICS,
          "T-CONST: mmcs publics %zu != pinned %zu",
          dnac_mmcs_air_num_publics(mmcs), (size_t)DNAC_P2S_MMCS_NUM_PUBLICS);
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
    /* The s2 main/rest partition of a group has to BE a partition. */
    CHECK(DNAC_P2S_OI_ACC_PER_BATCH * DNAC_P2S_OI_NUM_BATCHES ==
              DNAC_P2S_OI_ACC_PER_HEIGHT,
          "T-CONST: ACC_PER_BATCH * NUM_BATCHES != ACC_PER_HEIGHT");
    CHECK(DNAC_P2S_OI_MAIN_ACC + DNAC_P2S_OI_PX_REST == DNAC_P2S_OI_TOTAL_ACC,
          "T-CONST: MAIN_ACC + PX_REST != TOTAL_ACC");

    CHECK(dnac_mmcs_air_total_width(mmcs) == DNAC_P2S_MMCS_TOTAL_WIDTH,
          "T-CONST: mmcs total_width %zu != pinned %zu",
          dnac_mmcs_air_total_width(mmcs), (size_t)DNAC_P2S_MMCS_TOTAL_WIDTH);
    CHECK(dnac_mmix_air_total_opened(mmix) == DNAC_P2S_MMIX_TOTAL_OPENED,
          "T-CONST: mmix total_opened %zu != pinned %zu",
          dnac_mmix_air_total_opened(mmix), (size_t)DNAC_P2S_MMIX_TOTAL_OPENED);

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
    /* The mixed batch's depth must be log2 of its tallest matrix. */
    CHECK(mmix->depth == DNAC_P2S_MMIX_LH0 &&
              mmix->heights[0] == ((size_t)1u << DNAC_P2S_MMIX_LH0) &&
              mmix->heights[1] == ((size_t)1u << DNAC_P2S_MMIX_LH1),
          "T-CONST: mmix depth/heights inconsistent");
    CHECK(mmcs->depth == DNAC_P2S_MMCS_DEPTH &&
              mmcs->widths[0] == DNAC_P2S_MMCS_TOTAL_WIDTH,
          "T-CONST: mmcs depth/width inconsistent");

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

    /* --- commit round 0: leaf lanes = 2*arity, depth = lgmh - log_arity --- */
    {
        const jv_t *st0 = cpo->items[0];
        uint64_t la = 0;
        const jv_t *ipr = jv_get(st0, "opening_proof");
        const jv_t *sv = jv_get(st0, "sibling_values");
        CHECK(jv_u64(jv_get(st0, "log_arity"), &la) &&
                  la == DNAC_P2S_MAX_LOG_ARITY,
              "T-REF: round-0 log_arity != pinned max_log_arity");
        CHECK(sv && sv->kind == JV_ARR &&
                  sv->n == ((size_t)1u << DNAC_P2S_MAX_LOG_ARITY) - 1,
              "T-REF: round-0 sibling count != arity-1");
        CHECK(ipr && ipr->kind == JV_ARR && ipr->n == DNAC_P2S_MMCS_DEPTH,
              "T-REF: round-0 opening depth %zu != pinned %zu",
              ipr ? ipr->n : (size_t)0, (size_t)DNAC_P2S_MMCS_DEPTH);
        /* The leaf is the arity fp2 evals BASE-flattened: 2 lanes each. */
        CHECK(((size_t)2u << DNAC_P2S_MAX_LOG_ARITY) ==
                  DNAC_P2S_MMCS_TOTAL_WIDTH,
              "T-REF: 2*arity != pinned mmcs total width");
    }

    /* --- input batch 0 (the inner MAIN round): widths, heights, depth --- */
    {
        const jv_t *ip = jv_get(q0, "input_proof");
        if (!ip || ip->kind != JV_ARR || ip->n == 0) {
            CHECK(0, "T-REF: no input_proof");
            return;
        }
        const jv_t *b0 = ip->items[0];
        const jv_t *ovs = jv_get(b0, "opened_values");
        const jv_t *opr = jv_get(b0, "opening_proof");
        CHECK(ovs && ovs->kind == JV_ARR &&
                  ovs->n == DNAC_P2S_MMIX_NUM_MATRICES,
              "T-REF: batch-0 has %zu matrices, pinned %zu",
              ovs ? ovs->n : (size_t)0, (size_t)DNAC_P2S_MMIX_NUM_MATRICES);
        CHECK(opr && opr->kind == JV_ARR && opr->n == DNAC_P2S_MMIX_DEPTH,
              "T-REF: batch-0 opening depth %zu != pinned %zu",
              opr ? opr->n : (size_t)0, (size_t)DNAC_P2S_MMIX_DEPTH);
        if (ovs && ovs->kind == JV_ARR &&
            ovs->n == DNAC_P2S_MMIX_NUM_MATRICES) {
            const size_t want_w[DNAC_P2S_MMIX_NUM_MATRICES] = {
                DNAC_P2S_MMIX_W0, DNAC_P2S_MMIX_W1
            };
            for (size_t m = 0; m < ovs->n; m++) {
                CHECK(ovs->items[m]->kind == JV_ARR &&
                          ovs->items[m]->n == want_w[m],
                      "T-REF: batch-0 matrix %zu width %zu != pinned %zu", m,
                      ovs->items[m]->n, want_w[m]);
            }
        }
        /* heights: 2^(log_ext_degree_i + log_blowup), instance order. */
        const jv_t *insts = jv_get(s, "instances");
        const size_t want_lh[DNAC_P2S_MMIX_NUM_MATRICES] = {
            DNAC_P2S_MMIX_LH0, DNAC_P2S_MMIX_LH1
        };
        CHECK(insts && insts->kind == JV_ARR &&
                  insts->n == DNAC_P2S_MMIX_NUM_MATRICES,
              "T-REF: instance count != pinned matrix count");
        if (insts && insts->kind == JV_ARR &&
            insts->n == DNAC_P2S_MMIX_NUM_MATRICES) {
            int mixed = 0;
            for (size_t i = 0; i < insts->n; i++) {
                uint64_t led = 0;
                CHECK(jv_u64(jv_get(insts->items[i], "log_ext_degree"), &led),
                      "T-REF: log_ext_degree unreadable");
                CHECK((size_t)led + DNAC_P2S_LOG_BLOWUP == want_lh[i],
                      "T-REF: matrix %zu log-height %zu != pinned %zu", i,
                      (size_t)led + DNAC_P2S_LOG_BLOWUP, want_lh[i]);
                if (i > 0 && led != 0) mixed = 1;
            }
            (void)mixed;
            CHECK(want_lh[0] != want_lh[1],
                  "T-REF: the pinned batch is NOT mixed-height — the mmix "
                  "instance would be describing a same-height opening");
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

    /* ── T-REF/px (s2): MEASURE the MAIN batch's share of each height group ──
     * The s2 p_x alias rests on ONE claim about this fixture: in the schedule's
     * BATCH-MAJOR order (fri_oi_air_table.h:104-114) the FIRST
     * DNAC_P2S_OI_ACC_PER_BATCH rows of every height group belong to input
     * batch 0, the MAIN round — the batch the mmix instance describes. The
     * batch index in that order IS the native's batch loop index, i.e. the
     * position in `input_proof` (fri_verifier.c:207), so what has to be
     * measured is batch 0's per-height (matrices, points, columns) split.
     *
     * ⚠ This is where the "uniform (m,p,c) factorization is a LABEL" caveat
     * (fri_statement.h) STOPS being harmless: for the group TOTAL only the
     * product matters, but the p_x map indexes INSIDE the main batch's block,
     * so the main batch's split must be the pinned one EXACTLY. It is measured
     * here, not assumed — the quotient batch's split (1 point x 2 columns) is
     * NOT the pinned (2 x 1), which is precisely why only batch 0 may be
     * aliased. */
    {
        const jv_t *ip = jv_get(q0, "input_proof");
        const jv_t *rounds = jv_get(s, "opening_rounds");
        const jv_t *insts = jv_get(s, "instances");
        const size_t want_h[DNAC_P2S_OI_NUM_HEIGHTS] = { DNAC_P2S_OI_H0,
                                                         DNAC_P2S_OI_H1 };
        const size_t want_w[DNAC_P2S_MMIX_NUM_MATRICES] = { DNAC_P2S_MMIX_W0,
                                                            DNAC_P2S_MMIX_W1 };
        const size_t mmix_lh[DNAC_P2S_MMIX_NUM_MATRICES] = { DNAC_P2S_MMIX_LH0,
                                                             DNAC_P2S_MMIX_LH1 };

        if (!ip || ip->kind != JV_ARR || ip->n == 0 || !rounds ||
            rounds->kind != JV_ARR || !insts || insts->kind != JV_ARR) {
            CHECK(0, "T-REF/px: the fixture's batch arrays are unusable");
        } else {
            const jv_t *mats0 = jv_get(rounds->items[0], "matrices");
            const jv_t *ov0 = jv_get(ip->items[0], "opened_values");
            if (!mats0 || mats0->kind != JV_ARR || !ov0 ||
                ov0->kind != JV_ARR || mats0->n != ov0->n) {
                CHECK(0, "T-REF/px: batch 0's matrix lists disagree");
            } else {
                /* batch 0 must be the mmix batch: one matrix per pinned height,
                 * each at the pinned mmix log-height and opened width. */
                CHECK(mats0->n == DNAC_P2S_MMIX_NUM_MATRICES,
                      "T-REF/px: batch 0 has %zu matrices, mmix pins %zu",
                      mats0->n, (size_t)DNAC_P2S_MMIX_NUM_MATRICES);
                for (size_t i = 0; i < DNAC_P2S_OI_NUM_HEIGHTS; i++) {
                    size_t seen = 0, np = 0, nc = 0;
                    for (size_t m = 0; m < mats0->n; m++) {
                        uint64_t ii = 0, led = 0;
                        const jv_t *pts = jv_get(mats0->items[m], "points");
                        if (!jv_u64(jv_get(mats0->items[m], "instance"), &ii) ||
                            ii >= insts->n ||
                            !jv_u64(jv_get(insts->items[(size_t)ii],
                                           "log_ext_degree"), &led) ||
                            !pts || pts->kind != JV_ARR ||
                            ov0->items[m]->kind != JV_ARR) {
                            CHECK(0, "T-REF/px: batch 0 matrix %zu unreadable",
                                  m);
                            break;
                        }
                        if ((size_t)led + DNAC_P2S_LOG_BLOWUP != want_h[i]) {
                            continue;
                        }
                        seen++;
                        np = pts->n;
                        nc = ov0->items[m]->n;
                        /* the alias reads THIS matrix's opened row, so its
                         * position in the mmix flattening has to be the pinned
                         * one too. */
                        CHECK(m < DNAC_P2S_MMIX_NUM_MATRICES &&
                                  mmix_lh[m] == want_h[i] &&
                                  nc == want_w[m],
                              "T-REF/px: height %zu maps to batch-0 matrix %zu "
                              "(width %zu), which is not the pinned mmix "
                              "matrix", want_h[i], m, nc);
                    }
                    /* EXACTLY ONE main-batch matrix per height — the map the
                     * entry's p2s_mmix_matrix_at_height fails closed on. */
                    CHECK(seen == DNAC_P2S_OI_NUM_MATRICES,
                          "T-REF/px: batch 0 has %zu matrices at height %zu, "
                          "the pinned group descriptor says %zu", seen,
                          want_h[i], (size_t)DNAC_P2S_OI_NUM_MATRICES);
                    CHECK(np == DNAC_P2S_OI_NUM_POINTS,
                          "T-REF/px: batch 0 opens height %zu at %zu points, "
                          "pinned %zu", want_h[i], np,
                          (size_t)DNAC_P2S_OI_NUM_POINTS);
                    CHECK(nc == DNAC_P2S_OI_NUM_COLUMNS,
                          "T-REF/px: batch 0's height-%zu row is %zu columns "
                          "wide, pinned %zu", want_h[i], nc,
                          (size_t)DNAC_P2S_OI_NUM_COLUMNS);
                    CHECK(seen * np * nc == DNAC_P2S_OI_ACC_PER_BATCH,
                          "T-REF/px: batch 0 contributes %zu acc rows at height "
                          "%zu, the s2 split assumes %zu", seen * np * nc,
                          want_h[i], (size_t)DNAC_P2S_OI_ACC_PER_BATCH);
                    printf("  [t-ref]  px: batch 0 @ h=%zu -> %zu matrix x "
                           "%zu points x %zu cols = %zu acc rows (MAIN, "
                           "mmix-aliased)\n",
                           want_h[i], seen, np, nc, seen * np * nc);
                }
            }
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

typedef struct {
    p2s_mmix_fixt_t     mmix_fx;
    p2s_mmix_built_t    mmix;
    p2s_mmcs_fixture_t  mmcs_fx;
    p2s_mmcs_built_t    mmcs;
    p2s_fri_fixture_t   fri_fx;
    p2s_fri_built_t     fri;
    p2s_oi_built_t      oi;
    tair_run_t          tair;
    uint64_t            index; /* s3b: DERIVED from the transcript, not chosen */
    int                 built[DNAC_P2S_NUM_INSTANCES];
} traces_t;

static void traces_free(traces_t *T)
{
    if (T->built[DNAC_P2S_INST_MMIX]) p2s_mmix_built_free(&T->mmix);
    if (T->built[DNAC_P2S_INST_MMCS]) p2s_mmcs_built_free(&T->mmcs);
    if (T->built[DNAC_P2S_INST_FRI]) p2s_fri_built_free(&T->fri);
    if (T->built[DNAC_P2S_INST_OI]) p2s_oi_built_free(&T->oi);
    if (T->built[DNAC_P2S_INST_TAIR]) tair_free(&T->tair);
    memset(T->built, 0, sizeof(T->built));
}

/** The oi instance's exported ro for descending-height index `i`, as fp2. */
static gold_fp2_t oi_ro_export(const traces_t *T, size_t i)
{
    return gold_fp2_new(gold_fp_from_u64(T->oi.pub[T->oi.pub_ro + 2 * i]),
                        gold_fp_from_u64(T->oi.pub[T->oi.pub_ro + 2 * i + 1]));
}

/**
 * s2 — the p_x lane every oi acc row must carry, in SCHEDULE order.
 *
 * Derived HERE from the mmix FIXTURE's opened rows and the two pinned cfgs,
 * INDEPENDENTLY of fri_statement.c (which maps `stmt.mmix_opened`, the flattened
 * form). Feeding this into the oi builder is what makes the honest oi trace's
 * p_x column BE the mmix instance's opened value; T-ALIAS then compares the two
 * derivations element for element, and T-SRC/px asserts the alias on the
 * entry's own output.
 *
 * Non-main rows keep the shipped gate's own deterministic fixture value, so
 * they are exactly what the builder would have produced on its own — the
 * statement reads them back out of the builder's publics (stmt_from_traces).
 */
static void oi_px_from_mmix(const traces_t *T,
                            uint64_t px[DNAC_P2S_OI_TOTAL_ACC])
{
    const dnac_p2c_mmix_table_cfg_t *mc = dnac_p2s_mmix_cfg();
    const dnac_p2c_oi_table_cfg_t   *oc = dnac_p2s_oi_cfg();
    size_t g = 0;

    for (size_t i = 0; i < oc->num_heights; i++) {
        const dnac_p2c_oi_height_desc_t *d = &oc->heights[i];
        const size_t n_acc = d->num_batches * d->num_matrices * d->num_points *
                             d->num_columns;
        const size_t batch_sz =
            d->num_matrices * d->num_points * d->num_columns;
        const size_t want_h = (size_t)1u << d->log_height;
        size_t mi = (size_t)-1;

        for (size_t m = 0; m < mc->num_matrices; m++) {
            if (mc->heights[m] == want_h) { mi = m; break; }
        }
        for (size_t a = 0; a < n_acc && g < DNAC_P2S_OI_TOTAL_ACC; a++, g++) {
            if (a < batch_sz && mi != (size_t)-1) {
                /* the MAIN batch's tuple: matrix mi, column a % num_columns
                 * (the p_x of native fri_verifier.c:471 depends on the column,
                 * not on the opening point). */
                px[g] = T->mmix_fx.rows[mi][a % d->num_columns];
            } else {
                px[g] = p2s_oi_u(p2s_oi_tfp(g + 2, 17));
            }
        }
    }
}

/**
 * Build the four honest traces at the pinned cfgs for ONE shared index.
 *
 * The index each builder receives is exactly the alias map fri_statement.c
 * step 6 implements, from the other side:
 *   mmix  reduced index = index >> (lgmh - depth)  == index  (shift 0)
 *   mmcs  index >> log_arity                       (fri_verifier.c:558)
 *   fri   the full index
 *   oi    the full index (its chain consumes all lgmh bits, MSB-first)
 * `fri_cfg` is a parameter so N-CFG can build the same batch on a DIFFERENT
 * fri cfg without duplicating any of this.
 *
 * ⚠ ORDER IS LOAD-BEARING (s1c + s3b), and it is the SAME rule twice: a value
 * that is aliased must be produced BEFORE its consumers are built.
 *   1. tair first — it produces the index, alpha and every beta.
 *   2. mmix / mmcs on that index; oi with alpha injected (g_alpha_ext) and its
 *      p_x taken from the mmix opening (g_px_ext).
 *   3. fri last, with the betas from tair and f_init / roll-ins from the oi
 *      export written into its fixture.
 * So the walk really is seeded by the open_input result AND driven by the
 * challenger's own challenges, rather than by fixture values the entry happens
 * to copy into two instances.
 */
static int traces_build(traces_t *T, const dnac_p2c_table_cfg_t *fri_cfg,
                        uint64_t seed)
{
    uint64_t index;

    memset(T, 0, sizeof(*T));

    /* tair — the SHIPPED gate's builder over a vector synthesized from the
     * pinned script. Everything below is seeded from its result. */
    if (!tair_build(&T->tair)) return 0;
    T->built[DNAC_P2S_INST_TAIR] = 1;
    index = T->tair.index;
    T->index = index;

    /* mmix — the builder commits its own mixed batch, opens it and requires the
     * SHIPPED native mixed verifier to accept (test_mmcs_mixed_air.c:145-151)
     * before any trace exists. */
    if (!p2s_mmix_make_fixt(dnac_p2s_mmix_cfg(), index, &T->mmix_fx)) {
        printf("  [rt]     mmix fixture FAILED\n");
        return 0;
    }
    if (!p2s_mmix_build_trace(&T->mmix, dnac_p2s_mmix_cfg(), &T->mmix_fx,
                              T->mmix_fx.sibs, T->mmix_fx.root.lanes)) {
        printf("  [rt]     mmix trace FAILED\n");
        return 0;
    }
    T->built[DNAC_P2S_INST_MMIX] = 1;

    /* mmcs — same anchoring through dnac_p2_mmcs_verify
     * (test_mmcs_air.c:128-133). */
    if (!p2s_mmcs_make_fixture(dnac_p2s_mmcs_cfg(),
                               index >> DNAC_P2S_MAX_LOG_ARITY,
                               &T->mmcs_fx)) {
        printf("  [rt]     mmcs fixture FAILED\n");
        return 0;
    }
    if (!p2s_mmcs_build_trace(&T->mmcs, dnac_p2s_mmcs_cfg(),
                              index >> DNAC_P2S_MAX_LOG_ARITY,
                              T->mmcs_fx.elems, T->mmcs_fx.sibs,
                              T->mmcs_fx.root.lanes)) {
        printf("  [rt]     mmcs trace FAILED\n");
        return 0;
    }
    T->built[DNAC_P2S_INST_MMCS] = 1;

    /* oi — a NATIVE-FORMULA REPLAY of fri_open_input over the builder's own
     * deterministic z / p_z fixtures (test_fri_oi_air.c:10-23), at the pinned
     * cfg. Built BEFORE fri because fri consumes its ro export, and AFTER mmix
     * because (s2) the MAIN batch's acc rows take their p_x from the mmix
     * opening: the builder's `g_px_ext` hook is pointed at that derivation for
     * the duration of the build and cleared immediately after, so the walk's
     * reduced openings really are accumulated over the MMCS-opened values. */
    {
        uint64_t px[DNAC_P2S_OI_TOTAL_ACC];
        int ok;
        oi_px_from_mmix(T, px);
        p2s_oi_g_px_ext = px;
        /* s3b — and its alpha is the TRANSCRIPT's first fp2 pop, injected the
         * same way. The shipped fixture family cannot reach that value for any
         * seed (both of its lanes move together), which is exactly why the hook
         * exists; see tests/test_fri_oi_air.c's `g_alpha_ext` comment. */
        p2s_oi_g_alpha_ext = T->tair.alpha;
        ok = p2s_oi_build_honest(&T->oi, dnac_p2s_oi_cfg(), index, seed);
        p2s_oi_g_px_ext = NULL;
        p2s_oi_g_alpha_ext = NULL;
        if (!ok) {
            printf("  [rt]     oi trace FAILED\n");
            return 0;
        }
    }
    T->built[DNAC_P2S_INST_OI] = 1;

    /* fri — betas / siblings are FIXTURE-DERIVED (see the file header's honest
     * label), but f_init and every roll-in are OVERRIDDEN with the oi export
     * BEFORE the trace is built. f_init takes the height-lgmh export (oi index
     * 0); roll-in slot k takes the export of `rollin_heights[k]`, found by
     * height in the oi cfg — the same lookup fri_statement.c performs. */
    p2s_fri_fill_fixture(&T->fri_fx, seed);
    /* s3b — every beta is the TRANSCRIPT's round-r fp2 pop. `fixture_t` is
     * CALLER-owned (tests/test_fri_air.c:122-129 fills a struct the caller
     * hands it, and build_trace reads `F->beta[r]` at :268), so no hook is
     * needed on this side: overwriting after fill_fixture is the same move the
     * f_init / ro lines below already make. */
    for (size_t r = 0; r < dnac_p2c_fold_rows(fri_cfg) && r < DNAC_P2S_FRI_R;
         r++) {
        T->fri_fx.beta[r] = gold_fp2_new(gold_fp_from_u64(T->tair.beta[2 * r]),
                                         gold_fp_from_u64(T->tair.beta[2 * r + 1]));
    }
    T->fri_fx.f_init = oi_ro_export(T, 0);
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
        T->fri_fx.ro[k] = oi_ro_export(T, found);
    }
    if (!p2s_fri_build_trace(&T->fri, fri_cfg, index, &T->fri_fx, &V_HONEST)) {
        printf("  [rt]     fri trace FAILED\n");
        return 0;
    }
    T->built[DNAC_P2S_INST_FRI] = 1;

    /* Each shipped u64 evaluator must accept its own trace — the anchor the
     * whole round-trip stands on. */
    CHECK(p2s_mmix_eval_built(&T->mmix) == 0,
          "RT: the mmix u64 evaluator rejects its own honest trace");
    CHECK(p2s_mmcs_eval_built(&T->mmcs) == 0,
          "RT: the mmcs u64 evaluator rejects its own honest trace");
    CHECK(p2s_fri_eval_built(&T->fri) == 0,
          "RT: the fri u64 evaluator rejects its own honest trace");
    CHECK(p2s_oi_eval_b(&T->oi) == 0,
          "RT: the oi u64 evaluator rejects its own honest trace");
    CHECK(dnac_transcript_air_eval_trace(
              T->tair.B->trace, T->tair.B->prep, T->tair.B->n_rows,
              dnac_p2s_tair_cfg(), dnac_p2s_tair_script(), T->tair.B->pub,
              T->tair.B->n_pub) == 0,
          "RT: the tair u64 evaluator rejects its own honest trace");
    return 1;
}

/** Fill the statement from the three built traces. */
static void stmt_from_traces(dnac_p2s_statement_t *stmt, const traces_t *T)
{
    const dnac_p2c_table_cfg_t *fri = dnac_p2s_fri_cfg();
    const uint64_t index = T->index;
    memset(stmt, 0, sizeof(*stmt));

    for (size_t l = 0; l < DNAC_P2S_LGMH; l++) {
        stmt->index_bits[l] = (index >> l) & 1u;
    }
    for (size_t k = 0; k < (size_t)MMIX_DIGEST_LANES; k++) {
        stmt->mmix_root[k] = T->mmix_fx.root.lanes[k];
    }
    for (size_t k = 0; k < (size_t)MAIR_DIGEST_LANES; k++) {
        stmt->mmcs_root[k] = T->mmcs_fx.root.lanes[k];
    }
    /* opened rows, taken from the SAME place each builder's publics take them:
     * the mixed fixture's per-matrix DATA lanes, and the same-height fixture's
     * concatenated element stream. */
    {
        size_t off = 0;
        for (size_t m = 0; m < T->mmix_fx.nm; m++) {
            for (size_t d = 0; d < T->mmix_fx.semw[m]; d++) {
                stmt->mmix_opened[off + d] = T->mmix_fx.rows[m][d];
            }
            off += T->mmix_fx.semw[m];
        }
    }
    for (size_t c = 0; c < DNAC_P2S_MMCS_TOTAL_WIDTH; c++) {
        stmt->mmcs_opened[c] = T->mmcs_fx.elems[c];
    }
    /* s3b — the transcript payload, read straight off the tair builder's own
     * publics. This is the SINGLE source of the betas and alpha, so those two
     * have no statement field to fill any more (below). */
    {
        const dnac_tair_script_t *ts = dnac_p2s_tair_script();
        size_t rest = 0;
        for (size_t k = 0; k < DNAC_P2S_TAIR_NUM_OPS; k++) {
            stmt->tair_payload[k] = T->tair.B->pub[k];
        }
        /* and the bit blocks of queries 1..Q-1, in script order */
        for (size_t q = 1; q < DNAC_P2S_NUM_QUERIES; q++) {
            const size_t kq = tair_pop_op(ts, 2 + 2 * DNAC_P2S_FRI_R + q);
            size_t off;
            if (kq == (size_t)-1) {
                CHECK(0, "stmt: query %zu has no pop", q);
                break;
            }
            off = dnac_tair_op_bit_off(ts, kq);
            if (off == (size_t)-1) {
                CHECK(0, "stmt: query %zu exports no bits", q);
                break;
            }
            for (size_t l = 0; l < DNAC_P2S_LGMH; l++) {
                if (rest < DNAC_P2S_TAIR_BITS_REST) {
                    stmt->tair_bits_rest[rest++] = T->tair.B->pub[off + l];
                }
            }
        }
    }
    /* fri regions, read back out of the builder's own publics so the statement
     * and the trace cannot disagree by construction. `f_init` and the roll-ins
     * (s1c) and now `betas` (s3b) are DELIBERATELY not read here — they have no
     * statement field any more; the oi export and the tair payload are their
     * single sources, and traces_build already seeded the fri trace from both. */
    {
        const size_t final_off = dnac_fair_pub_final_off(fri);
        stmt->final_poly0[0] = T->fri.pub[final_off];
        stmt->final_poly0[1] = T->fri.pub[final_off + 1];
    }
    /* oi regions, likewise straight off the oi builder's publics — minus alpha,
     * which is the tair payload's now (s3b). */
    {
        for (size_t i = 0; i < 4 * DNAC_P2S_OI_TOTAL_ACC; i++) {
            stmt->zpz[i] = T->oi.pub[T->oi.pub_zpz + i];
        }
        for (size_t i = 0; i < 2 * DNAC_P2S_OI_NUM_HEIGHTS; i++) {
            stmt->ro_export[i] = T->oi.pub[T->oi.pub_ro + i];
        }
        /* s2 — px_rest carries ONLY the acc rows the main batch does not cover.
         * The main-batch rows have NO statement field: the entry aliases them
         * off mmix_opened, which is the whole point of the slice. Walked in the
         * same schedule order the entry walks. */
        {
            const dnac_p2c_oi_table_cfg_t *oc = dnac_p2s_oi_cfg();
            size_t g = 0, rest = 0;
            for (size_t i = 0; i < oc->num_heights; i++) {
                const dnac_p2c_oi_height_desc_t *d = &oc->heights[i];
                const size_t n_acc = d->num_batches * d->num_matrices *
                                     d->num_points * d->num_columns;
                const size_t batch_sz =
                    d->num_matrices * d->num_points * d->num_columns;
                for (size_t a = 0; a < n_acc; a++, g++) {
                    if (a < batch_sz) continue;
                    if (rest < DNAC_P2S_OI_PX_REST) {
                        stmt->px_rest[rest++] = T->oi.pub[T->oi.pub_px + g];
                    }
                }
            }
        }
    }
}

/**
 * T-ALIAS(positive): the entry's ALIASED publics must equal, element for
 * element, the publics each shipped builder wrote for its own trace. Without
 * this, RT-1 could pass on a misalignment that both sides shared.
 */
static void t_alias_positive(const dnac_p2s_statement_t *stmt, const traces_t *T)
{
    dnac_batch_vinstance_t insts[DNAC_P2S_NUM_INSTANCES];
    gold_fp_t pm[DNAC_P2S_MMIX_NUM_PUBLICS];
    gold_fp_t pc[DNAC_P2S_MMCS_NUM_PUBLICS];
    gold_fp_t pf[DNAC_P2S_FRI_NUM_PUBLICS];
    gold_fp_t po[DNAC_P2S_OI_NUM_PUBLICS];
    gold_fp_t pt[DNAC_P2S_TAIR_NUM_PUBLICS];
    size_t bad = 0;

    if (dnac_p2_fri_statement_build_instances(stmt, insts, pm, pc, pf, po,
                                              pt) != DNAC_P2S_OK) {
        CHECK(0, "T-ALIAS: build_instances rejected the honest statement");
        return;
    }
    for (size_t i = 0; i < DNAC_P2S_MMIX_NUM_PUBLICS; i++) {
        if (gold_fp_to_u64(pm[i]) != T->mmix.pub[i]) bad++;
    }
    CHECK(bad == 0, "T-ALIAS: %zu mmix publics differ from the builder's", bad);
    bad = 0;
    for (size_t i = 0; i < DNAC_P2S_MMCS_NUM_PUBLICS; i++) {
        if (gold_fp_to_u64(pc[i]) != T->mmcs.pub[i]) bad++;
    }
    CHECK(bad == 0, "T-ALIAS: %zu mmcs publics differ from the builder's", bad);
    bad = 0;
    for (size_t i = 0; i < DNAC_P2S_FRI_NUM_PUBLICS; i++) {
        if (gold_fp_to_u64(pf[i]) != T->fri.pub[i]) bad++;
    }
    CHECK(bad == 0, "T-ALIAS: %zu fri publics differ from the builder's", bad);
    bad = 0;
    for (size_t i = 0; i < DNAC_P2S_OI_NUM_PUBLICS; i++) {
        if (gold_fp_to_u64(po[i]) != T->oi.pub[i]) bad++;
    }
    CHECK(bad == 0, "T-ALIAS: %zu oi publics differ from the builder's", bad);
    bad = 0;
    for (size_t i = 0; i < DNAC_P2S_TAIR_NUM_PUBLICS; i++) {
        if (gold_fp_to_u64(pt[i]) != T->tair.B->pub[i]) bad++;
    }
    CHECK(bad == 0, "T-ALIAS: %zu tair publics differ from the builder's", bad);

    /* ── T-SRC: the s1c single-source property, asserted on the entry's OWN
     * output. The fri instance's f_init region and its roll-in region must BE
     * the oi instance's exported ro lanes — not merely equal to something the
     * statement also holds, since the statement no longer holds them at all. ── */
    {
        const dnac_p2c_table_cfg_t    *fc = dnac_p2s_fri_cfg();
        const dnac_p2c_oi_table_cfg_t *oc = dnac_p2s_oi_cfg();
        const size_t finit_off = dnac_fair_pub_finit_off(fc);
        const size_t fro_off = dnac_fair_pub_ro_off(fc);
        const size_t oro_off = dnac_foi_pub_ro_off(oc);

        CHECK(gold_fp_to_u64(pf[finit_off]) == gold_fp_to_u64(po[oro_off]) &&
                  gold_fp_to_u64(pf[finit_off + 1]) ==
                      gold_fp_to_u64(po[oro_off + 1]),
              "T-SRC: fri f_init is not the oi height-lgmh ro export");
        for (size_t k = 0; k < fc->num_rollin; k++) {
            size_t i = (size_t)-1;
            for (size_t j = 0; j < oc->num_heights; j++) {
                if (oc->heights[j].log_height == fc->rollin_heights[k]) i = j;
            }
            CHECK(i != (size_t)-1 && i != 0,
                  "T-SRC: roll-in %zu has no non-seed oi export", k);
            if (i == (size_t)-1) continue;
            CHECK(gold_fp_to_u64(pf[fro_off + 2 * k]) ==
                          gold_fp_to_u64(po[oro_off + 2 * i]) &&
                      gold_fp_to_u64(pf[fro_off + 2 * k + 1]) ==
                          gold_fp_to_u64(po[oro_off + 2 * i + 1]),
                  "T-SRC: fri roll-in slot %zu is not oi ro export %zu", k, i);
        }
    }

    /* ── T-SRC/px (s2): the MAIN batch's p_x publics ARE the mmix instance's
     * opened-row publics. Asserted on the ENTRY's own two output vectors — not
     * on the statement, which holds those lanes exactly once (in mmix_opened)
     * and holds no p_x field for them at all. This is the same two-consumer
     * shape T-SRC asserts for ro_export, one seam further down. ── */
    {
        const dnac_p2c_mmix_table_cfg_t *mc = dnac_p2s_mmix_cfg();
        const dnac_p2c_oi_table_cfg_t   *oc = dnac_p2s_oi_cfg();
        const size_t mo_off = dnac_mmix_air_pub_opened_off(mc);
        const size_t opx_off = dnac_foi_pub_px_off(oc);
        size_t g = 0, checked = 0;

        for (size_t i = 0; i < oc->num_heights; i++) {
            const dnac_p2c_oi_height_desc_t *d = &oc->heights[i];
            const size_t n_acc = d->num_batches * d->num_matrices *
                                 d->num_points * d->num_columns;
            const size_t batch_sz =
                d->num_matrices * d->num_points * d->num_columns;
            const size_t want_h = (size_t)1u << d->log_height;
            size_t moff = 0, mi = (size_t)-1;

            for (size_t m = 0; m < mc->num_matrices; m++) {
                if (mc->heights[m] == want_h) { mi = m; break; }
                moff += mc->widths[m];
            }
            CHECK(mi != (size_t)-1,
                  "T-SRC/px: oi height %zu has no mmix matrix", d->log_height);
            for (size_t a = 0; a < n_acc; a++, g++) {
                if (mi == (size_t)-1 || a >= batch_sz) continue;
                CHECK(gold_fp_to_u64(po[opx_off + g]) ==
                          gold_fp_to_u64(pm[mo_off + moff + a % d->num_columns]),
                      "T-SRC/px: oi acc row %zu (height %zu, main batch) is not "
                      "the mmix opened lane", g, d->log_height);
                checked++;
            }
        }
        /* Not vacuous: the loop must actually have compared MAIN_ACC rows. */
        CHECK(checked == DNAC_P2S_OI_MAIN_ACC,
              "T-SRC/px: compared %zu main-batch rows, expected %zu", checked,
              (size_t)DNAC_P2S_OI_MAIN_ACC);
    }

    /* ── T-SRC/beta + T-SRC/alpha (s3b): the fri betas and the oi alpha ARE
     * transcript payload lanes. Asserted on the ENTRY's own three output
     * vectors — the statement holds each of these values exactly once, in
     * `tair_payload`, and holds no beta or alpha field at all. The op indices
     * are re-derived here by scanning the script, independently of the entry's
     * own walk. ── */
    {
        const dnac_tair_script_t *ts = dnac_p2s_tair_script();
        const size_t beta_off = dnac_fair_pub_beta_off(dnac_p2s_fri_cfg());
        const size_t alpha_off = dnac_foi_pub_alpha_off(dnac_p2s_oi_cfg());
        const size_t ka0 = tair_pop_op(ts, 0), ka1 = tair_pop_op(ts, 1);

        CHECK(ka0 != (size_t)-1 && ka1 != (size_t)-1,
              "T-SRC/alpha: the script has no alpha pops");
        if (ka0 != (size_t)-1 && ka1 != (size_t)-1) {
            CHECK(gold_fp_to_u64(po[alpha_off]) == gold_fp_to_u64(pt[ka0]) &&
                      gold_fp_to_u64(po[alpha_off + 1]) ==
                          gold_fp_to_u64(pt[ka1]),
                  "T-SRC/alpha: the oi alpha publics are not the transcript's "
                  "first fp2 pop");
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
                  "T-SRC/beta: fri beta[%zu] is not the transcript's round-%zu "
                  "pop pair", r, r);
        }

        /* ── T-SRC/index: the transcript's query-0 exported bits ARE the lanes
         * the four consumers' bit / direction publics were built from. Compared
         * against `index_bits` — the entry's single construction input — and
         * then, one step further, against the fri instance's own bit region, so
         * the chain transcript -> statement -> consumer is closed on the
         * entry's output rather than on its input. ── */
        {
            const size_t kq = tair_pop_op(ts, 2 + 2 * DNAC_P2S_FRI_R);
            const size_t off = (kq == (size_t)-1)
                                   ? (size_t)-1
                                   : dnac_tair_op_bit_off(ts, kq);
            CHECK(off != (size_t)-1, "T-SRC/index: query 0 exports no bits");
            if (off != (size_t)-1) {
                for (size_t l = 0; l < DNAC_P2S_LGMH; l++) {
                    CHECK(gold_fp_to_u64(pt[off + l]) == stmt->index_bits[l],
                          "T-SRC/index: tair bit %zu is not index_bits[%zu]", l,
                          l);
                    CHECK(gold_fp_to_u64(pf[(size_t)FAIR_PUB_BITS_OFF + l]) ==
                              gold_fp_to_u64(pt[off + l]),
                          "T-SRC/index: the fri walk's bit %zu is not the "
                          "transcript's exported bit", l);
                }
            }
        }
    }

    /* The descriptors the entry derived. */
    CHECK(insts[DNAC_P2S_INST_MMIX].degree_bits == 4 &&
              insts[DNAC_P2S_INST_MMCS].degree_bits == 3 &&
              insts[DNAC_P2S_INST_FRI].degree_bits == 3 &&
              insts[DNAC_P2S_INST_OI].degree_bits == 5 &&
              insts[DNAC_P2S_INST_TAIR].degree_bits == 6,
          "T-ALIAS: degree_bits (%u,%u,%u,%u,%u) not the table row counts",
          insts[DNAC_P2S_INST_MMIX].degree_bits,
          insts[DNAC_P2S_INST_MMCS].degree_bits,
          insts[DNAC_P2S_INST_FRI].degree_bits,
          insts[DNAC_P2S_INST_OI].degree_bits,
          insts[DNAC_P2S_INST_TAIR].degree_bits);
    for (uint32_t i = 0; i < DNAC_P2S_NUM_INSTANCES; i++) {
        CHECK(insts[i].prep_next == 1, "T-ALIAS: inst %u prep_next != 1", i);
        CHECK(insts[i].log_num_qc == 2, "T-ALIAS: inst %u log_num_qc != 2", i);
        CHECK(insts[i].preprocessed_width == dnac_p2s_prep_cols(i),
              "T-ALIAS: inst %u preprocessed_width wrong", i);
        CHECK(insts[i].num_lookups == 0, "T-ALIAS: inst %u declares lookups", i);
    }
}

/* ═════════════════════════════ prove + verify ════════════════════════════ */

/** Prove the three instances the entry describes. Caller frees *out_proof. */
static int p2s_prove(const dnac_p2s_statement_t *stmt, const traces_t *T,
                     dnac_batch_proof_t **out_proof)
{
    dnac_batch_vinstance_t insts[DNAC_P2S_NUM_INSTANCES];
    dnac_batch_pwitness_t wits[DNAC_P2S_NUM_INSTANCES];
    gold_fp_t pm[DNAC_P2S_MMIX_NUM_PUBLICS];
    gold_fp_t pc[DNAC_P2S_MMCS_NUM_PUBLICS];
    gold_fp_t pf[DNAC_P2S_FRI_NUM_PUBLICS];
    gold_fp_t po[DNAC_P2S_OI_NUM_PUBLICS];
    gold_fp_t pt[DNAC_P2S_TAIR_NUM_PUBLICS];
    dnac_prover_status_t ps;

    *out_proof = NULL;
    if (dnac_p2_fri_statement_build_instances(stmt, insts, pm, pc, pf, po,
                                              pt) != DNAC_P2S_OK) {
        return 0;
    }
    memset(wits, 0, sizeof(wits));
    wits[DNAC_P2S_INST_MMIX].main_trace = T->mmix.trace;
    wits[DNAC_P2S_INST_MMIX].prep_trace = T->mmix.prep;
    wits[DNAC_P2S_INST_MMCS].main_trace = T->mmcs.trace;
    wits[DNAC_P2S_INST_MMCS].prep_trace = T->mmcs.prep;
    wits[DNAC_P2S_INST_FRI].main_trace = T->fri.trace;
    wits[DNAC_P2S_INST_FRI].prep_trace = T->fri.prep;
    wits[DNAC_P2S_INST_OI].main_trace = T->oi.trace;
    wits[DNAC_P2S_INST_OI].prep_trace = T->oi.prep;
    wits[DNAC_P2S_INST_TAIR].main_trace = T->tair.B->trace;
    wits[DNAC_P2S_INST_TAIR].prep_trace = T->tair.B->prep;

    /* is_zk 0, no random codewords, no salt — the non-hiding recursion
     * envelope. dnac_batch_prove self-verifies before returning. */
    ps = dnac_batch_prove(insts, wits, DNAC_P2S_NUM_INSTANCES, 0,
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
        static const char *const names[DNAC_P2S_NUM_INSTANCES] = { "mmix",
                                                                   "mmcs",
                                                                   "fri",
                                                                   "oi",
                                                                   "tair" };
        for (uint32_t t = 0; t < DNAC_P2S_NUM_INSTANCES; t++) {
            uint64_t *tab[DNAC_P2S_NUM_INSTANCES] = { 0 };
            const uint64_t *ctab[DNAC_P2S_NUM_INSTANCES];
            uint64_t lanes[4];
            int moved = 0;
            if (!p2s_alloc_tables(tab)) {
                CHECK(0, "N-PIN[%s]: table generate failed", names[t]);
                p2s_free_tables(tab);
                continue;
            }
            tab[t][dnac_p2s_prep_cells(t) - 1] += 1u; /* ONE cell */
            for (uint32_t i = 0; i < DNAC_P2S_NUM_INSTANCES; i++) {
                ctab[i] = tab[i];
            }
            if (!p2s_commit_tables(ctab, lanes)) {
                CHECK(0, "N-PIN[%s]: commit failed", names[t]);
                p2s_free_tables(tab);
                continue;
            }
            for (size_t k = 0; k < 4; k++) {
                if (lanes[k] != honest_root[k]) moved = 1;
            }
            /* Without this the negative would be vacuous. */
            CHECK(moved,
                  "N-PIN[%s]: a tampered table gives the SAME composed root",
                  names[t]);
            stub_init(&S, lanes);
            CHECK(stub_run(stmt, &S) == DNAC_P2S_ERR_PREP_ROOT,
                  "N-PIN[%s]: a tampered-table root was not rejected at step 2",
                  names[t]);
            p2s_free_tables(tab);
        }
    }

    /* ── N-PINMAP: the map is part of what the composed root means ── */
    {
        const uint32_t swapped[DNAC_P2S_NUM_INSTANCES] = { 1, 0, 2, 3, 4 };
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

        bad = *stmt;
        bad.tair_bits_rest[DNAC_P2S_TAIR_BITS_REST - 1] = GOLDILOCKS_P;
        CHECK(stub_run(&bad, &S) == DNAC_P2S_ERR_CANON,
              "N-CANON: a non-canonical tair_bits_rest lane was not rejected");

        /* the boolean rail on the OTHER queries' exported bits */
        bad = *stmt;
        bad.tair_bits_rest[0] = 2;
        CHECK(stub_run(&bad, &S) == DNAC_P2S_ERR_CANON,
              "N-CANON: a non-boolean tair_bits_rest lane was not rejected");

        bad = *stmt;
        bad.mmix_root[3] = UINT64_MAX;
        CHECK(stub_run(&bad, &S) == DNAC_P2S_ERR_CANON,
              "N-CANON: a non-canonical mmix root lane was not rejected");

        bad = *stmt;
        bad.mmcs_opened[0] = GOLDILOCKS_P + 1;
        CHECK(stub_run(&bad, &S) == DNAC_P2S_ERR_CANON,
              "N-CANON: a non-canonical mmcs opened lane was not rejected");

        bad = *stmt;
        bad.final_poly0[1] = GOLDILOCKS_P;
        CHECK(stub_run(&bad, &S) == DNAC_P2S_ERR_CANON,
              "N-CANON: a non-canonical final_poly lane was not rejected");

        /* the s1c regions — every one of them is spanned by step 1, which the
         * struct's sizeof static-assert (fri_statement.c) keeps true as the
         * struct grows. */
        bad = *stmt;
        bad.zpz[4 * DNAC_P2S_OI_TOTAL_ACC - 1] = UINT64_MAX;
        CHECK(stub_run(&bad, &S) == DNAC_P2S_ERR_CANON,
              "N-CANON: a non-canonical z/p_z lane was not rejected");

        bad = *stmt;
        bad.ro_export[2 * DNAC_P2S_OI_NUM_HEIGHTS - 1] = GOLDILOCKS_P;
        CHECK(stub_run(&bad, &S) == DNAC_P2S_ERR_CANON,
              "N-CANON: a non-canonical ro_export lane was not rejected");

        /* the s2 region — the sizeof static-assert in fri_statement.c is what
         * keeps step 1 from forgetting it, and this is the runtime witness. */
        bad = *stmt;
        bad.px_rest[DNAC_P2S_OI_PX_REST - 1] = UINT64_MAX;
        CHECK(stub_run(&bad, &S) == DNAC_P2S_ERR_CANON,
              "N-CANON: a non-canonical px_rest lane was not rejected");

        /* the boolean rail on the entry's own construction input */
        bad = *stmt;
        bad.index_bits[0] = 2;
        CHECK(stub_run(&bad, &S) == DNAC_P2S_ERR_CANON,
              "N-CANON: a non-boolean index bit was not rejected");

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
static void rt1_and_proof_negatives(const dnac_p2s_statement_t *stmt,
                                    const traces_t *T,
                                    const uint64_t honest_root[4])
{
    dnac_batch_proof_t *proof = NULL;
    dnac_batch_vcommits_t cm;
    dnac_batch_vopened_t opened[DNAC_P2S_NUM_INSTANCES];
    uint32_t nprep = 0;
    const uint32_t *map = NULL;

    printf("  [rt]     preprocessed widths: mmix %zu, mmcs %zu, fri %zu, "
           "oi %zu, tair %zu (the batch_prover.c pw cap is lifted)\n",
           dnac_p2s_prep_cols(DNAC_P2S_INST_MMIX),
           dnac_p2s_prep_cols(DNAC_P2S_INST_MMCS),
           dnac_p2s_prep_cols(DNAC_P2S_INST_FRI),
           dnac_p2s_prep_cols(DNAC_P2S_INST_OI),
           dnac_p2s_prep_cols(DNAC_P2S_INST_TAIR));

    if (!p2s_prove(stmt, T, &proof)) {
        CHECK(0, "RT-1: dnac_batch_prove could not prove the 4-instance set");
        return;
    }
    printf("  [rt]     dnac_batch_prove OK — %u instances, is_zk 0\n",
           DNAC_P2S_NUM_INSTANCES);

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
        dnac_batch_vinstance_t insts[DNAC_P2S_NUM_INSTANCES];
        gold_fp_t pm[DNAC_P2S_MMIX_NUM_PUBLICS];
        gold_fp_t pc[DNAC_P2S_MMCS_NUM_PUBLICS];
        gold_fp_t pf[DNAC_P2S_FRI_NUM_PUBLICS];
        gold_fp_t po[DNAC_P2S_OI_NUM_PUBLICS];
    gold_fp_t pt[DNAC_P2S_TAIR_NUM_PUBLICS];
        dnac_batch_verify_status_t bs;
        CHECK(dnac_p2_fri_statement_build_instances(stmt, insts, pm, pc, pf, po,
                                                    pt) == DNAC_P2S_OK,
              "RT-1: build_instances rejected the honest statement");
        bs = dnac_batch_verify(insts, opened, DNAC_P2S_NUM_INSTANCES, 0, &cm,
                               map, nprep, dnac_p2s_fri_params(), 0, 0,
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
        dnac_batch_vinstance_t insts[DNAC_P2S_NUM_INSTANCES];
        gold_fp_t pm[DNAC_P2S_MMIX_NUM_PUBLICS];
        gold_fp_t pc[DNAC_P2S_MMCS_NUM_PUBLICS];
        gold_fp_t pf[DNAC_P2S_FRI_NUM_PUBLICS];
        gold_fp_t po[DNAC_P2S_OI_NUM_PUBLICS];
    gold_fp_t pt[DNAC_P2S_TAIR_NUM_PUBLICS];
        if (dnac_p2_fri_statement_build_instances(stmt, insts, pm, pc, pf, po,
                                                  pt) == DNAC_P2S_OK) {
            dnac_batch_verify_status_t bs;
            CHECK(dnac_p2s_prep_cols(DNAC_P2S_INST_FRI) > 64,
                  "N-PIN2: the fri preprocessed width is no longer > 64, so "
                  "the SHAPE route this negative relies on has moved");
            insts[DNAC_P2S_INST_FRI].prep_next = 0;
            bs = dnac_batch_verify(insts, opened, DNAC_P2S_NUM_INSTANCES, 0,
                                   &cm, map, nprep, dnac_p2s_fri_params(), 0, 0,
                                   dnac_batch_proof_fri(proof), NULL, NULL);
            CHECK(bs == DNAC_BV_ERR_SHAPE,
                  "N-PIN2: prep_next = 0 gave %d, want DNAC_BV_ERR_SHAPE",
                  (int)bs);

            /* The oi table is 106 columns, so it takes the SAME capacity route
             * as fri — pinned separately because a future width change could
             * move it to the other one silently. */
            if (dnac_p2_fri_statement_build_instances(stmt, insts, pm, pc, pf,
                                                      po, pt) == DNAC_P2S_OK) {
                CHECK(dnac_p2s_prep_cols(DNAC_P2S_INST_OI) > 64,
                      "N-PIN2: the oi preprocessed width is no longer > 64");
                insts[DNAC_P2S_INST_OI].prep_next = 0;
                bs = dnac_batch_verify(insts, opened, DNAC_P2S_NUM_INSTANCES, 0,
                                       &cm, map, nprep, dnac_p2s_fri_params(),
                                       0, 0, dnac_batch_proof_fri(proof), NULL,
                                       NULL);
                CHECK(bs == DNAC_BV_ERR_SHAPE,
                      "N-PIN2: oi prep_next = 0 gave %d, want "
                      "DNAC_BV_ERR_SHAPE", (int)bs);
            }

            /* The mmcs table is 3 columns, UNDER the zero-window capacity, so
             * flipping ITS prep_next takes the other documented route: the
             * window is silently zeroed and the AIR's gated forms then fail the
             * constraint check instead of the shape check. Both are rejects;
             * pinning which one keeps the two routes distinguishable. */
            if (dnac_p2_fri_statement_build_instances(stmt, insts, pm, pc, pf,
                                                      po, pt) == DNAC_P2S_OK) {
                CHECK(dnac_p2s_prep_cols(DNAC_P2S_INST_MMCS) <= 64,
                      "N-PIN2: the mmcs width moved above the zero-window cap");
                insts[DNAC_P2S_INST_MMCS].prep_next = 0;
                bs = dnac_batch_verify(insts, opened, DNAC_P2S_NUM_INSTANCES, 0,
                                       &cm, map, nprep, dnac_p2s_fri_params(),
                                       0, 0, dnac_batch_proof_fri(proof), NULL,
                                       NULL);
                CHECK(bs != DNAC_BV_OK,
                      "N-PIN2: mmcs prep_next = 0 was ACCEPTED");
            }
        }
    }

    /* ── N-ALIAS, batch-driven: flip ONE bit of the single shared index. The
     * entry BUILDS every instance's bit publics from it, so the flip lands in
     * the fri bits AND (for l >= max_log_arity) the mmcs dir AND the mmix dir
     * at once — it cannot be confined to one instance, which is the property
     * the aliasing buys. Post-fill the rejection is the batch's own OOD/FRI
     * check, which is the form that proves the publics really are consumed. ── */
    for (size_t l = 0; l < DNAC_P2S_LGMH; l++) {
        dnac_p2s_statement_t bad = *stmt;
        dnac_p2s_status_t st;
        bad.index_bits[l] ^= 1u;
        st = p2s_run_entry(&bad, proof, NULL, NULL);
        CHECK(st != DNAC_P2S_OK, "N-ALIAS: flipping index bit %zu was ACCEPTED",
              l);
#if !DNAC_P2S_PREP_ROOT_UNFILLED
        CHECK(st == DNAC_P2S_ERR_BATCH,
              "N-ALIAS: bit %zu rejected as %d, want the BATCH check (the "
              "publics must actually reach the constraint system)", l, (int)st);
#endif
    }

    /* ── N-ALIAS / RO-EXPORT (s1c): perturb ONE ro_export lane. There is no
     * second field to perturb — the statement holds this value once — so the
     * entry writes the changed lane into the oi instance's ro publics AND (for
     * the seed lane, into f_init; for a roll-in height, into that slot) the fri
     * instance's, and the batch check sees both move together. That both
     * instances are affected is shown DIRECTLY on the entry's own output, not
     * inferred: build the descriptors for the perturbed statement and count how
     * many of the two publics vectors changed. ── */
    for (size_t i = 0; i < 2 * DNAC_P2S_OI_NUM_HEIGHTS; i++) {
        dnac_p2s_statement_t bad = *stmt;
        dnac_p2s_status_t st;
        bad.ro_export[i] =
            gold_fp_to_u64(gold_fp_add(gold_fp_from_u64(bad.ro_export[i]),
                                       gold_fp_one()));

        /* (a) the two-consumer property, on the entry's construction. */
        {
            dnac_batch_vinstance_t i0[DNAC_P2S_NUM_INSTANCES];
            dnac_batch_vinstance_t i1[DNAC_P2S_NUM_INSTANCES];
            gold_fp_t am[DNAC_P2S_MMIX_NUM_PUBLICS], bm[DNAC_P2S_MMIX_NUM_PUBLICS];
            gold_fp_t ac[DNAC_P2S_MMCS_NUM_PUBLICS], bc[DNAC_P2S_MMCS_NUM_PUBLICS];
            gold_fp_t af[DNAC_P2S_FRI_NUM_PUBLICS], bf[DNAC_P2S_FRI_NUM_PUBLICS];
            gold_fp_t ao[DNAC_P2S_OI_NUM_PUBLICS], bo[DNAC_P2S_OI_NUM_PUBLICS];
            gold_fp_t at[DNAC_P2S_TAIR_NUM_PUBLICS], bt[DNAC_P2S_TAIR_NUM_PUBLICS];
            int fri_moved = 0, oi_moved = 0;
            if (dnac_p2_fri_statement_build_instances(stmt, i0, am, ac, af, ao,
                                                      at) == DNAC_P2S_OK &&
                dnac_p2_fri_statement_build_instances(&bad, i1, bm, bc, bf, bo,
                                                      bt) == DNAC_P2S_OK) {
                for (size_t k = 0; k < DNAC_P2S_FRI_NUM_PUBLICS; k++) {
                    if (gold_fp_to_u64(af[k]) != gold_fp_to_u64(bf[k])) {
                        fri_moved = 1;
                    }
                }
                for (size_t k = 0; k < DNAC_P2S_OI_NUM_PUBLICS; k++) {
                    if (gold_fp_to_u64(ao[k]) != gold_fp_to_u64(bo[k])) {
                        oi_moved = 1;
                    }
                }
            } else {
                CHECK(0, "N-ALIAS/ro: build_instances rejected a canonical "
                         "perturbation (lane %zu)", i);
            }
            CHECK(oi_moved,
                  "N-ALIAS/ro: lane %zu does not reach the oi publics", i);
            /* Every pinned height is either the seed (index 0 -> f_init) or a
             * roll-in height, so EVERY export lane must reach fri too. If a
             * future cfg exported a height fri neither seeds from nor rolls in,
             * this is the check that would report it rather than let the alias
             * silently become one-sided. */
            CHECK(fri_moved,
                  "N-ALIAS/ro: lane %zu does not reach the fri publics — the "
                  "export is no longer single-source for both consumers", i);
        }

        /* (b) and the entry rejects it. */
        st = p2s_run_entry(&bad, proof, NULL, NULL);
        CHECK(st != DNAC_P2S_OK,
              "N-ALIAS/ro: perturbing ro_export lane %zu was ACCEPTED", i);
#if !DNAC_P2S_PREP_ROOT_UNFILLED
        CHECK(st == DNAC_P2S_ERR_BATCH,
              "N-ALIAS/ro: lane %zu rejected as %d, want the BATCH check", i,
              (int)st);
#endif
    }

    /* ── N-ALIAS / beta + alpha (s3b): perturb ONE transcript payload lane that
     * a consumer is aliased from. The statement holds it ONCE, so the entry
     * writes the changed value into the tair instance's payload publics AND
     * into the consumer's — they move TOGETHER, which is the property the alias
     * buys and the thing a "the transcript said X but the walk used Y" attack
     * would have to break. Shown on the entry's own construction, then the
     * entry is required to reject. ── */
    {
        const dnac_tair_script_t *ts = dnac_p2s_tair_script();
        struct { size_t ord; const char *what; int fri_leg; } legs[] = {
            { 0, "alpha.c0", 0 },
            { 1, "alpha.c1", 0 },
            { 2, "beta[0].c0", 1 },
            { 3, "beta[0].c1", 1 },
            { 2 + 2 * (DNAC_P2S_FRI_R - 1), "beta[R-1].c0", 1 },
        };
        for (size_t e = 0; e < sizeof(legs) / sizeof(legs[0]); e++) {
            const size_t k = tair_pop_op(ts, legs[e].ord);
            dnac_p2s_statement_t bad = *stmt;
            dnac_p2s_status_t st;
            int tair_moved = 0, fri_moved = 0, oi_moved = 0;

            if (k == (size_t)-1 || k >= DNAC_P2S_TAIR_NUM_OPS) {
                CHECK(0, "N-ALIAS/%s: no such pop in the pinned script",
                      legs[e].what);
                continue;
            }
            bad.tair_payload[k] = gold_fp_to_u64(gold_fp_add(
                gold_fp_from_u64(bad.tair_payload[k]), gold_fp_one()));

            {
                dnac_batch_vinstance_t i0[DNAC_P2S_NUM_INSTANCES];
                dnac_batch_vinstance_t i1[DNAC_P2S_NUM_INSTANCES];
                gold_fp_t am[DNAC_P2S_MMIX_NUM_PUBLICS], bm[DNAC_P2S_MMIX_NUM_PUBLICS];
                gold_fp_t ac[DNAC_P2S_MMCS_NUM_PUBLICS], bc[DNAC_P2S_MMCS_NUM_PUBLICS];
                gold_fp_t af[DNAC_P2S_FRI_NUM_PUBLICS], bf[DNAC_P2S_FRI_NUM_PUBLICS];
                gold_fp_t ao[DNAC_P2S_OI_NUM_PUBLICS], bo[DNAC_P2S_OI_NUM_PUBLICS];
                gold_fp_t at[DNAC_P2S_TAIR_NUM_PUBLICS], bt[DNAC_P2S_TAIR_NUM_PUBLICS];
                if (dnac_p2_fri_statement_build_instances(stmt, i0, am, ac, af,
                                                          ao, at) ==
                        DNAC_P2S_OK &&
                    dnac_p2_fri_statement_build_instances(&bad, i1, bm, bc, bf,
                                                          bo, bt) ==
                        DNAC_P2S_OK) {
                    for (size_t j = 0; j < DNAC_P2S_TAIR_NUM_PUBLICS; j++) {
                        if (gold_fp_to_u64(at[j]) != gold_fp_to_u64(bt[j])) {
                            tair_moved = 1;
                        }
                    }
                    for (size_t j = 0; j < DNAC_P2S_FRI_NUM_PUBLICS; j++) {
                        if (gold_fp_to_u64(af[j]) != gold_fp_to_u64(bf[j])) {
                            fri_moved = 1;
                        }
                    }
                    for (size_t j = 0; j < DNAC_P2S_OI_NUM_PUBLICS; j++) {
                        if (gold_fp_to_u64(ao[j]) != gold_fp_to_u64(bo[j])) {
                            oi_moved = 1;
                        }
                    }
                } else {
                    CHECK(0, "N-ALIAS/%s: build_instances rejected a canonical "
                             "perturbation", legs[e].what);
                }
                CHECK(tair_moved,
                      "N-ALIAS/%s: the lane does not reach the tair publics",
                      legs[e].what);
                if (legs[e].fri_leg) {
                    CHECK(fri_moved,
                          "N-ALIAS/%s: the lane does not reach the fri betas — "
                          "the beta alias is broken", legs[e].what);
                    CHECK(!oi_moved,
                          "N-ALIAS/%s: a beta lane reached the oi publics",
                          legs[e].what);
                } else {
                    CHECK(oi_moved,
                          "N-ALIAS/%s: the lane does not reach the oi alpha — "
                          "the alpha alias is broken", legs[e].what);
                    CHECK(!fri_moved,
                          "N-ALIAS/%s: an alpha lane reached the fri publics",
                          legs[e].what);
                }
            }

            st = p2s_run_entry(&bad, proof, NULL, NULL);
            CHECK(st != DNAC_P2S_OK, "N-ALIAS/%s: perturbation was ACCEPTED",
                  legs[e].what);
#if !DNAC_P2S_PREP_ROOT_UNFILLED
            CHECK(st == DNAC_P2S_ERR_BATCH,
                  "N-ALIAS/%s: rejected as %d, want the BATCH check",
                  legs[e].what, (int)st);
#endif
        }
    }

    /* ── N-ALIAS / idx (s3b): the index bits now have FIVE consumers. The bit
     * flip loop above already proves the four AIR-side ones move; this asserts
     * the TRANSCRIPT side moves with them, i.e. that the entry cannot be handed
     * an index the transcript did not produce. ── */
    for (size_t l = 0; l < DNAC_P2S_LGMH; l++) {
        dnac_p2s_statement_t bad = *stmt;
        dnac_batch_vinstance_t i0[DNAC_P2S_NUM_INSTANCES];
        dnac_batch_vinstance_t i1[DNAC_P2S_NUM_INSTANCES];
        gold_fp_t am[DNAC_P2S_MMIX_NUM_PUBLICS], bm[DNAC_P2S_MMIX_NUM_PUBLICS];
        gold_fp_t ac[DNAC_P2S_MMCS_NUM_PUBLICS], bc[DNAC_P2S_MMCS_NUM_PUBLICS];
        gold_fp_t af[DNAC_P2S_FRI_NUM_PUBLICS], bf[DNAC_P2S_FRI_NUM_PUBLICS];
        gold_fp_t ao[DNAC_P2S_OI_NUM_PUBLICS], bo[DNAC_P2S_OI_NUM_PUBLICS];
        gold_fp_t at[DNAC_P2S_TAIR_NUM_PUBLICS], bt[DNAC_P2S_TAIR_NUM_PUBLICS];
        int tair_moved = 0;

        bad.index_bits[l] ^= 1u;
        if (dnac_p2_fri_statement_build_instances(stmt, i0, am, ac, af, ao,
                                                  at) == DNAC_P2S_OK &&
            dnac_p2_fri_statement_build_instances(&bad, i1, bm, bc, bf, bo,
                                                  bt) == DNAC_P2S_OK) {
            for (size_t j = 0; j < DNAC_P2S_TAIR_NUM_PUBLICS; j++) {
                if (gold_fp_to_u64(at[j]) != gold_fp_to_u64(bt[j])) {
                    tair_moved = 1;
                }
            }
        } else {
            CHECK(0, "N-ALIAS/idx: build_instances rejected bit %zu", l);
        }
        CHECK(tair_moved,
              "N-ALIAS/idx: flipping index bit %zu does not reach the tair "
              "exported-bit publics — the index is not transcript-bound", l);
    }

    /* ── N-BITSREST: the honest label on the OTHER queries' bits — they ARE
     * read (they reach the tair publics) but reach ONLY tair, because no
     * consumer models query 1 yet. Same two-sided pinning as N-PXREST. ── */
    for (size_t i = 0; i < DNAC_P2S_TAIR_BITS_REST; i++) {
        dnac_p2s_statement_t bad = *stmt;
        dnac_batch_vinstance_t i0[DNAC_P2S_NUM_INSTANCES];
        dnac_batch_vinstance_t i1[DNAC_P2S_NUM_INSTANCES];
        gold_fp_t am[DNAC_P2S_MMIX_NUM_PUBLICS], bm[DNAC_P2S_MMIX_NUM_PUBLICS];
        gold_fp_t ac[DNAC_P2S_MMCS_NUM_PUBLICS], bc[DNAC_P2S_MMCS_NUM_PUBLICS];
        gold_fp_t af[DNAC_P2S_FRI_NUM_PUBLICS], bf[DNAC_P2S_FRI_NUM_PUBLICS];
        gold_fp_t ao[DNAC_P2S_OI_NUM_PUBLICS], bo[DNAC_P2S_OI_NUM_PUBLICS];
        gold_fp_t at[DNAC_P2S_TAIR_NUM_PUBLICS], bt[DNAC_P2S_TAIR_NUM_PUBLICS];
        int tair_moved = 0, other_moved = 0;
        dnac_p2s_status_t st;

        bad.tair_bits_rest[i] ^= 1u;
        if (dnac_p2_fri_statement_build_instances(stmt, i0, am, ac, af, ao,
                                                  at) == DNAC_P2S_OK &&
            dnac_p2_fri_statement_build_instances(&bad, i1, bm, bc, bf, bo,
                                                  bt) == DNAC_P2S_OK) {
            for (size_t j = 0; j < DNAC_P2S_TAIR_NUM_PUBLICS; j++) {
                if (gold_fp_to_u64(at[j]) != gold_fp_to_u64(bt[j])) {
                    tair_moved = 1;
                }
            }
            for (size_t j = 0; j < DNAC_P2S_FRI_NUM_PUBLICS; j++) {
                if (gold_fp_to_u64(af[j]) != gold_fp_to_u64(bf[j])) {
                    other_moved = 1;
                }
            }
            for (size_t j = 0; j < DNAC_P2S_OI_NUM_PUBLICS; j++) {
                if (gold_fp_to_u64(ao[j]) != gold_fp_to_u64(bo[j])) {
                    other_moved = 1;
                }
            }
        } else {
            CHECK(0, "N-BITSREST: build_instances rejected lane %zu", i);
        }
        CHECK(tair_moved, "N-BITSREST: lane %zu is never read", i);
        CHECK(!other_moved,
              "N-BITSREST: lane %zu reached a CONSUMER's publics — query 1 is "
              "documented as unconsumed in this slice", i);

        st = p2s_run_entry(&bad, proof, NULL, NULL);
        CHECK(st != DNAC_P2S_OK,
              "N-BITSREST: flipping bit %zu was ACCEPTED", i);
#if !DNAC_P2S_PREP_ROOT_UNFILLED
        CHECK(st == DNAC_P2S_ERR_BATCH,
              "N-BITSREST: lane %zu rejected as %d, want the BATCH check", i,
              (int)st);
#endif
    }

    /* ── N-ALIAS / px (s2): perturb ONE `mmix_opened` lane. It is the mmix
     * instance's opened-row public AND — for every acc row of the MAIN batch at
     * that matrix's height — the oi instance's p_x public. There is no second
     * field to disagree with, so the two move TOGETHER; that is what the p_x
     * <-> MMCS seam being closed for those rows means, and it is shown on the
     * entry's own construction rather than inferred from a reject. ── */
    for (size_t c = 0; c < DNAC_P2S_MMIX_TOTAL_OPENED; c++) {
        dnac_p2s_statement_t bad = *stmt;
        dnac_p2s_status_t st;
        bad.mmix_opened[c] =
            gold_fp_to_u64(gold_fp_add(gold_fp_from_u64(bad.mmix_opened[c]),
                                       gold_fp_one()));

        {
            dnac_batch_vinstance_t i0[DNAC_P2S_NUM_INSTANCES];
            dnac_batch_vinstance_t i1[DNAC_P2S_NUM_INSTANCES];
            gold_fp_t am[DNAC_P2S_MMIX_NUM_PUBLICS], bm[DNAC_P2S_MMIX_NUM_PUBLICS];
            gold_fp_t ac[DNAC_P2S_MMCS_NUM_PUBLICS], bc[DNAC_P2S_MMCS_NUM_PUBLICS];
            gold_fp_t af[DNAC_P2S_FRI_NUM_PUBLICS], bf[DNAC_P2S_FRI_NUM_PUBLICS];
            gold_fp_t ao[DNAC_P2S_OI_NUM_PUBLICS], bo[DNAC_P2S_OI_NUM_PUBLICS];
            gold_fp_t at[DNAC_P2S_TAIR_NUM_PUBLICS], bt[DNAC_P2S_TAIR_NUM_PUBLICS];
            const size_t opx = dnac_foi_pub_px_off(dnac_p2s_oi_cfg());
            int mmix_moved = 0, oi_px_moved = 0, oi_other_moved = 0;

            if (dnac_p2_fri_statement_build_instances(stmt, i0, am, ac, af, ao,
                                                      at) == DNAC_P2S_OK &&
                dnac_p2_fri_statement_build_instances(&bad, i1, bm, bc, bf, bo,
                                                      bt) == DNAC_P2S_OK) {
                for (size_t k = 0; k < DNAC_P2S_MMIX_NUM_PUBLICS; k++) {
                    if (gold_fp_to_u64(am[k]) != gold_fp_to_u64(bm[k])) {
                        mmix_moved = 1;
                    }
                }
                for (size_t k = 0; k < DNAC_P2S_OI_NUM_PUBLICS; k++) {
                    if (gold_fp_to_u64(ao[k]) == gold_fp_to_u64(bo[k])) continue;
                    if (k >= opx) oi_px_moved = 1;
                    else oi_other_moved = 1;
                }
            } else {
                CHECK(0, "N-ALIAS/px: build_instances rejected a canonical "
                         "perturbation (lane %zu)", c);
            }
            CHECK(mmix_moved,
                  "N-ALIAS/px: lane %zu does not reach the mmix publics", c);
            CHECK(oi_px_moved,
                  "N-ALIAS/px: lane %zu does not reach the oi p_x publics — "
                  "the main-batch rows are no longer MMCS-aliased", c);
            /* It must land ONLY in the p_x region of the oi publics; anywhere
             * else would mean the region walk mis-partitioned. */
            CHECK(!oi_other_moved,
                  "N-ALIAS/px: lane %zu moved an oi public OUTSIDE the p_x "
                  "region", c);
        }

        st = p2s_run_entry(&bad, proof, NULL, NULL);
        CHECK(st != DNAC_P2S_OK,
              "N-ALIAS/px: perturbing mmix_opened lane %zu was ACCEPTED", c);
#if !DNAC_P2S_PREP_ROOT_UNFILLED
        CHECK(st == DNAC_P2S_ERR_BATCH,
              "N-ALIAS/px: lane %zu rejected as %d, want the BATCH check", c,
              (int)st);
#endif
    }

    /* ── N-PXREST (s2): the honest label under test. `px_rest` IS consumed —
     * perturbing a lane reaches the oi p_x publics and the entry rejects — but
     * it reaches ONLY oi, which is exactly the seam that is still open (no
     * commitment binds it). Pinning both halves keeps the label from drifting
     * into either "unused" or "bound". ── */
    for (size_t i = 0; i < DNAC_P2S_OI_PX_REST; i++) {
        dnac_p2s_statement_t bad = *stmt;
        dnac_p2s_status_t st;
        bad.px_rest[i] =
            gold_fp_to_u64(gold_fp_add(gold_fp_from_u64(bad.px_rest[i]),
                                       gold_fp_one()));
        {
            dnac_batch_vinstance_t i0[DNAC_P2S_NUM_INSTANCES];
            dnac_batch_vinstance_t i1[DNAC_P2S_NUM_INSTANCES];
            gold_fp_t am[DNAC_P2S_MMIX_NUM_PUBLICS], bm[DNAC_P2S_MMIX_NUM_PUBLICS];
            gold_fp_t ac[DNAC_P2S_MMCS_NUM_PUBLICS], bc[DNAC_P2S_MMCS_NUM_PUBLICS];
            gold_fp_t af[DNAC_P2S_FRI_NUM_PUBLICS], bf[DNAC_P2S_FRI_NUM_PUBLICS];
            gold_fp_t ao[DNAC_P2S_OI_NUM_PUBLICS], bo[DNAC_P2S_OI_NUM_PUBLICS];
            gold_fp_t at[DNAC_P2S_TAIR_NUM_PUBLICS], bt[DNAC_P2S_TAIR_NUM_PUBLICS];
            const size_t opx = dnac_foi_pub_px_off(dnac_p2s_oi_cfg());
            int oi_px_moved = 0, mmix_moved = 0;
            if (dnac_p2_fri_statement_build_instances(stmt, i0, am, ac, af, ao,
                                                      at) == DNAC_P2S_OK &&
                dnac_p2_fri_statement_build_instances(&bad, i1, bm, bc, bf, bo,
                                                      bt) == DNAC_P2S_OK) {
                for (size_t k = opx; k < DNAC_P2S_OI_NUM_PUBLICS; k++) {
                    if (gold_fp_to_u64(ao[k]) != gold_fp_to_u64(bo[k])) {
                        oi_px_moved = 1;
                    }
                }
                for (size_t k = 0; k < DNAC_P2S_MMIX_NUM_PUBLICS; k++) {
                    if (gold_fp_to_u64(am[k]) != gold_fp_to_u64(bm[k])) {
                        mmix_moved = 1;
                    }
                }
            } else {
                CHECK(0, "N-PXREST: build_instances rejected lane %zu", i);
            }
            CHECK(oi_px_moved, "N-PXREST: lane %zu is never read", i);
            CHECK(!mmix_moved,
                  "N-PXREST: lane %zu reached the mmix publics — it is NOT the "
                  "unbound remainder this field is documented to be", i);
        }
        st = p2s_run_entry(&bad, proof, NULL, NULL);
        CHECK(st != DNAC_P2S_OK,
              "N-PXREST: perturbing px_rest lane %zu was ACCEPTED", i);
#if !DNAC_P2S_PREP_ROOT_UNFILLED
        CHECK(st == DNAC_P2S_ERR_BATCH,
              "N-PXREST: lane %zu rejected as %d, want the BATCH check", i,
              (int)st);
#endif
    }

    /* ── N-CFG (OBL-P2c-1): a proof whose fri instance was built on a
     * DIFFERENT cfg. The entry always rebuilds from the PINNED cfg, so the
     * shapes cannot line up. ── */
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
            dnac_batch_vinstance_t insts[DNAC_P2S_NUM_INSTANCES];
            dnac_batch_pwitness_t wits[DNAC_P2S_NUM_INSTANCES];
            gold_fp_t pm[DNAC_P2S_MMIX_NUM_PUBLICS];
            gold_fp_t pc[DNAC_P2S_MMCS_NUM_PUBLICS];
            gold_fp_t pf[DNAC_P2S_FRI_NUM_PUBLICS];
            gold_fp_t po[DNAC_P2S_OI_NUM_PUBLICS];
    gold_fp_t pt[DNAC_P2S_TAIR_NUM_PUBLICS];
            static gold_fp_t alt_pub[256];
            const size_t anp = dnac_fair_num_publics(&ALT);
            dnac_stark_air_t alt_air;
            int ok = 1;

            stmt_from_traces(&astmt, &AT);
            if (dnac_p2_fri_statement_build_instances(&astmt, insts, pm, pc, pf,
                                                      po, pt) != DNAC_P2S_OK) {
                CHECK(0, "N-CFG: build_instances failed");
                ok = 0;
            }
            memset(&alt_air, 0, sizeof(alt_air));
            if (ok && dnac_fair_fold_bind(&ALT, &alt_air) !=
                          DNAC_FAIR_FOLD_OK) {
                CHECK(0, "N-CFG: could not bind the alternative cfg");
                ok = 0;
            }
            if (ok && anp > sizeof(alt_pub) / sizeof(alt_pub[0])) {
                CHECK(0, "N-CFG: alternative publics too wide");
                ok = 0;
            }
            if (ok) {
                size_t db = 0, v = 1;
                const size_t rows = dnac_p2c_table_rows(&ALT);
                while (v < rows) { v <<= 1; db++; }
                for (size_t i = 0; i < anp; i++) {
                    alt_pub[i] = gold_fp_from_u64(AT.fri.pub[i]);
                }
                insts[DNAC_P2S_INST_FRI].air = alt_air;
                insts[DNAC_P2S_INST_FRI].num_publics = (uint32_t)anp;
                insts[DNAC_P2S_INST_FRI].public_values = alt_pub;
                insts[DNAC_P2S_INST_FRI].degree_bits = (uint32_t)db;

                memset(wits, 0, sizeof(wits));
                wits[DNAC_P2S_INST_MMIX].main_trace = AT.mmix.trace;
                wits[DNAC_P2S_INST_MMIX].prep_trace = AT.mmix.prep;
                wits[DNAC_P2S_INST_MMCS].main_trace = AT.mmcs.trace;
                wits[DNAC_P2S_INST_MMCS].prep_trace = AT.mmcs.prep;
                wits[DNAC_P2S_INST_FRI].main_trace = AT.fri.trace;
                wits[DNAC_P2S_INST_FRI].prep_trace = AT.fri.prep;
                wits[DNAC_P2S_INST_OI].main_trace = AT.oi.trace;
                wits[DNAC_P2S_INST_OI].prep_trace = AT.oi.prep;

                if (dnac_batch_prove(insts, wits, DNAC_P2S_NUM_INSTANCES, 0,
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

    dnac_batch_proof_free(proof);
}

static void rt1_and_negatives(void)
{
    traces_t T;
    dnac_p2s_statement_t stmt;
    uint64_t honest_root[4] = { 0, 0, 0, 0 };

    if (!traces_build(&T, dnac_p2s_fri_cfg(), 7)) {
        CHECK(0, "RT: could not build the five honest traces");
        traces_free(&T);
        return;
    }
    printf("  [rt]     transcript-derived query index = %llu (0x%llx)\n",
           (unsigned long long)T.index, (unsigned long long)T.index);
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

        printf("s3b composed preprocessed root — the PINNED cfg set "
               "(5 tables: mmix, mmcs, fri, oi, tair),\n");
        printf("pipeline = batch_prover.c:786-822 with is_zk = 0, blowup %zu\n\n",
               (size_t)DNAC_P2S_LOG_BLOWUP);
        for (uint32_t i = 0; i < DNAC_P2S_NUM_INSTANCES; i++) {
            printf("  instance %u: %zu rows x %zu cols -> lde %zu rows\n", i,
                   dnac_p2s_prep_rows(i), dnac_p2s_prep_cols(i),
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

    printf("=== s1b + s1c + s2 + s3b — FRI-verify statement ENTRY "
           "(5 instances) ===\n\n");

    printf("T-CONST / T-LQ — the pinned arithmetic vs the module accessors\n");
    t_const();
    t_lq();

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
