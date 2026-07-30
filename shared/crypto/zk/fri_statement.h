/**
 * @file fri_statement.h
 * @brief Composition s1b — the FRI-verify statement ENTRY: ONE verify call that
 *        binds the s1a fold AIRs into a single batched STARK instance set and
 *        ENFORCES the pin class the per-module slices deferred.
 *
 * s1a shipped five fold-form evaluators, each with its OWN reference cfg, and
 * those cfgs were mutually INCONSISTENT (fri lgmh 13 vs oi lgmh 4). This module
 * fixes ONE consistent statement: a single query index, a single inner FRI
 * verification shape, and one pinned cfg per participating AIR. The entry only
 * ever CONSTRUCTS and REJECTS — it introduces no constraint and no column.
 *
 * ── FIVE instances (s3b — the composition map is complete) ───────────────────
 *   idx 0  mmix  mixed-height input-batch MMCS verify   (inner input batch 0)
 *   idx 1  mmcs  same-height binary MMCS verify         (inner commit round 0)
 *   idx 2  fri   the fold-walk control AIR
 *   idx 3  oi    the reduced-opening accumulation AIR   (open_input)
 *   idx 4  tair  the DuplexChallenger control AIR       (the Fiat-Shamir tail)
 * The instance ORDER is part of the interface: the pinned preprocessed root
 * below is a commitment over the five tables IN THIS ORDER, so the entry
 * rejects any other `prep_matrix_to_instance`.
 *
 * ── WHAT s3b CLOSES: the challenge <-> Fiat-Shamir transcript seam ───────────
 * s1c closed ro_export; s2 closed the main batch's p_x; this closes the last
 * one the earlier slices declared open by name: alpha, the betas and the query
 * INDEX were plain statement inputs, unbound to any transcript. They are now BY
 * CONSTRUCTION the transcript instance's own publics — the statement carries ONE
 * `tair_payload` region (the observed/popped lane of every script op) and the
 * entry aliases it into both consumers,
 *   oi.alpha     := payload[first two non-PoW pops]   (fri_verifier.c:694)
 *   fri.betas[r] := payload[the round-r pop pair]     (fri_verifier.c:707)
 * while the ONE `index_bits` region is written into the tair instance's
 * exported-bit block for query 0 AS WELL AS into the four consumers' bit /
 * direction regions, so the index the transcript PRODUCES and the index the
 * four AIRs CONSUME are the same lanes. The `betas` and `alpha` statement
 * fields are GONE; the struct shrank again.
 *
 * ── WHAT s1c CLOSES: the ro-export <-> f_init / roll-in seam ─────────────────
 * s1b had no oi instance, so the fri walk's seed and roll-in publics were plain
 * statement inputs — nothing recomputed them. They are now BY CONSTRUCTION the
 * open_input instance's exported reduced openings: the statement carries ONE
 * `ro_export` region and the entry aliases it into BOTH consumers,
 *   fri.f_init      := ro_export[height == lgmh]  (native ro[0] -> folded_eval,
 *                                                  fri_verifier.c:524-527)
 *   fri.rollins[i]  := ro_export[height == the i-th roll-in height]
 *                                                 (fri_verifier.c:600-605)
 *   oi.ro publics   := the SAME ro_export lanes    (fri_oi_air.h:69,79-82)
 * so the two instances cannot be given different values for the same reduced
 * opening — there is no second field to disagree with. The `f_init` and
 * `rollins` statement fields of s1b are GONE; the struct shrank.
 *
 * The oi cfg's participation was blocked in s1b by a COMPLETENESS defect in the
 * oi module (its table required the lowest scheduled height to be log_blowup,
 * while the native runs that zero-test CONDITIONALLY, fri_verifier.c:482-487,
 * and a real proof has no matrix at height 2^log_blowup). FLEET 029 repaired
 * that — a height AT log_blowup is now OPTIONAL (fri_oi_air_table.h:366-372) —
 * which is what makes an oi cfg derivable from the REF proof at all.
 *
 * ⚠ HONEST LABELS — the seams that are still open:
 *   1. The transcript instance covers the FRI TAIL ONLY. The batch-STARK
 *      PRIMING ops (`dnac_batch_observe_main` and friends) are NOT in the
 *      pinned script — `dnac_tair_fri_build_script` starts at the DS prefix and
 *      ends at the query samples (transcript_air_table.h "SCOPE, honestly
 *      labelled") — so `zeta` / `z` are still plain statement inputs, popped by
 *      a transcript this instance does not model. Prepending the priming ops is
 *      a later slice; alpha, the betas and the query index ARE bound here.
 *   2. Commit rounds 1..R-1 are NOT replicated (one mmcs instance, round 0
 *      only), and only ONE query is CONSUMED (OBL-P2c-2) even though the script
 *      samples Q of them — hence `tair_bits_rest`. Both are later slices.
 *   3. The `p_x` <-> MMCS opened-row seam is PARTIALLY closed (s2). `p_x` is no
 *      longer free oi witness — C3g binds every acc row's `p_x` to its own
 *      public (fri_oi_air.h) — and this entry sources the MAIN input batch's
 *      acc rows from `stmt.mmix_opened`, i.e. from the SAME lanes the mmix
 *      instance's opened-row publics are built from. For those rows the two
 *      instances cannot be given different opened values, exactly as `ro_export`
 *      does for the fri seed. The QUOTIENT and PREPROCESSED batches' rows come
 *      from `stmt.px_rest`, an honest statement input (see its field comment):
 *      inside the mechanism, but not yet bound to a commitment. Closing them
 *      needs the input-batch REPLICATION slice (one mmix instance per input
 *      batch), which is the same slice the commit-round replication belongs to.
 *   4. ARITY-EQUALITY ASSUMPTION (FLEET 028 verifier M2): the mmcs dir alias
 *      shifts by the PINNED `max_log_arity`, while the native shifts by the
 *      proof's ACTUAL round-0 `log_arity` (`fri_verifier.c:558`). The two
 *      coincide because the pinned shape has every log_arity == mla == 1; the
 *      entry itself does not bind a proof's round-0 arity — that equality is
 *      asserted TEST-side (T-REF) and becomes an entry duty when arities are
 *      ever unpinned (round replication slice).
 *   5. OI GROUP SHAPE — the (matrices, points, columns) factorization of a
 *      height group is a LABEL, not a measurement (see the cfg derivation
 *      below). Only the group's acc-row TOTAL and its boundary are load-bearing
 *      here, and both are measured.
 *   6. THE TRANSCRIPT'S OBSERVED LANES ARE NOT BOUND TO THIS PROOF (s3b; the
 *      FLEET 033 verifier's CLAIM-7 note — these two labels existed only in the
 *      TEST file's header, which is the wrong place for a seam a consensus
 *      caller must know about). The script's OBSERVE ops carry the commit
 *      digests and the final-poly / log-arity lanes, and this entry sources
 *      them from `stmt.tair_payload` WITHOUT aliasing them to `mmcs_root` /
 *      `mmix_root` or to the proof's own commitments. So "the transcript
 *      absorbed THIS proof" is NOT established: what is bound is that the
 *      challenges the four consumers use are the ones THIS transcript squeezed
 *      from whatever it observed. Closing it belongs to the commit-round
 *      replication slice, which is where the per-round digests become instance
 *      publics in the first place.
 *   7. RT-1's transcript vector is SELF-CONSISTENT, not an independent oracle:
 *      the test builds it by replaying the shipped `duplex_challenger.c` and
 *      checks it against its own replay of that same challenger. The Rust-oracle
 *      pinning for the transcript lives in `tests/test_transcript_air.c`'s 8
 *      dump-transcript-trace scenarios, not here.
 *
 * ── The pinned cfg set (DERIVED from a real inner proof, then FROZEN) ────────
 * Source: scenario `prep_pair` of `tools/vectors/batch_proof.json` — the
 * smallest shipped batch fixture that has BOTH >= 1 commit round AND a
 * mixed-height input batch. It is loaded by `tests/test_batch_verify.c:327` and
 * gated there by `dnac_batch_verify`. Its measured shape (query 0):
 *
 *   fri_params        log_blowup 2, log_final_poly_len 0, max_log_arity 1,
 *                     num_queries 2, both PoW bit counts 0
 *   commit rounds     3, each log_arity 1, sibling counts 1,
 *                     opening depths 4 / 3 / 2
 *   instances         log_ext_degree 3 and 2, main width 1 each
 *   input batch 0     2 matrices, opened widths {1,1}, opening depth 5
 *                     (main round: LDE heights 2^5 and 2^4 -> MIXED)
 *
 * From those, exactly as `fri_verifier.c:640-650` derives them:
 *   lgmh = sum(log_arity) + log_blowup + log_final_poly_len = 3 + 2 + 0 = 5
 *   R    = lgmh - log_blowup - log_final_poly_len            = 3
 *   reduced-opening heights = {log_ext_degree_i + log_blowup} = {5, 4};
 *     height 5 SEEDS the walk (fri_verifier.c:524-527) and height 4 = lgmh-1
 *     ROLLS IN at fold round 0 (fri_verifier.c:600-605) -> rollin set {4}
 *   commit round 0 leaf = arity fp2 evals BASE-flattened = 2*arity = 4 lanes,
 *     at depth log_folded_height = lgmh - 1 = 4 (fri_verifier.c:557, :585-588)
 *   input batch 0 depth = log2(max height) = 5 (mmcs_mixed_air_table.h:361-368)
 *
 * ── The oi (open_input) cfg — DERIVED THE SAME WAY, from the same proof ──────
 * `fri_open_input` accumulates one reduced opening PER DISTINCT log-height over
 * every input batch (fri_verifier.c:207-478), so the oi cfg is a property of the
 * WHOLE input side of that proof, not of batch 0:
 *   lgmh / log_blowup   the same 5 / 2
 *   H (descending)      the distinct heights {5, 4} — NO height at log_blowup,
 *                       which is what FLEET 029 made expressible
 *   acc rows per height MEASURED: for each height h, the number of
 *                       (batch, matrix at h, opening point, claimed eval)
 *                       tuples the native visits — the four nested loops at
 *                       fri_verifier.c:207 / :400 / :436 / :469. prep_pair has
 *                       three input batches (main, quotient, preprocessed —
 *                       batch_verify.c:545-602 with is_zk 0 and no lookups) and
 *                       each contributes exactly 2 tuples at each height:
 *                         main         1 matrix x 2 points (zeta, zeta_next)
 *                                                  x 1 claimed eval  = 2
 *                         quotient     1 chunk   x 1 point (zeta)
 *                                                  x 2 lanes         = 2
 *                         preprocessed 1 matrix x 2 points x 1 eval   = 2
 *                       => 6 acc rows per height, 12 in total.
 *
 * ⚠ HONEST LABEL — THE GROUP DESCRIPTOR IS A FACTORIZATION, NOT A SHAPE.
 * `dnac_p2c_oi_height_desc_t` describes a group as a UNIFORM product
 * (num_batches x num_matrices x num_points x num_columns). The real batches are
 * NOT uniform in the (points, columns) split — the quotient batch is 1x2 where
 * the other two are 2x1 — so the pinned (3, 1, 2, 1) reproduces the correct
 * PER-BATCH count (2), the correct group TOTAL (6) and the correct group
 * boundary, and mislabels only the internal split. That split carries no
 * semantics here: `num_matrices*num_points*num_columns` is read ONLY as
 * `batch_sz` for the C5 per-batch lb-zero rule (fri_oi_air.c:164-176), which is
 * gated on `cur_is_lb` and therefore never fires for a cfg with no height at
 * log_blowup. What DOES carry semantics — the total and the per-acc-row public
 * slot ORDER — is pinned by the schedule and proved by the test's native replay.
 *
 * `tests/test_fri_statement.c` re-derives every one of those numbers from the
 * fixture JSON and compares them against the constants below, so the pin cannot
 * drift from the proof it claims to describe.
 *
 * ⚠ The cfg scalars are pinned INDEPENDENTLY of the preprocessed root — that is
 * OBL-4c / OBL-4-MMIX (fri_air_table.h:140-148): a root binds table CONTENT,
 * never the verifier's separate cfg ARGUMENT, so a root-checked table paired
 * with a mismatched cfg would aim cfg-derived loop bounds at the wrong publics.
 * Both are checked, from two independent sources.
 *
 * ⚠ MECHANISM PIN, NOT PRODUCTION. Neither the cfg set nor `dnac_p2s_fri_params`
 * is a security parameter choice: `prep_pair` is a 2-query toy fixture. This
 * slice proves the pin class can be established and that it binds. The
 * production re-pin (real recursion shape, real query count) is P2e.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_ZK_FRI_STATEMENT_H
#define DNAC_ZK_FRI_STATEMENT_H

#include <stddef.h>
#include <stdint.h>

#include "batch_verify.h"        /* dnac_batch_v{instance,opened,commits}_t   */
#include "fri_air_fold.h"       /* dnac_fair_fold_bind + the fri publics      */
#include "fri_air_table.h"      /* dnac_p2c_table_cfg_t                       */
#include "fri_oi_air_fold.h"    /* dnac_foi_fold_bind + the oi publics        */
#include "fri_oi_air_table.h"   /* dnac_p2c_oi_table_cfg_t                    */
#include "mmcs_air_fold.h"      /* dnac_mmcs_air_fold_bind                    */
#include "mmcs_air_table.h"     /* dnac_p2b_table_cfg_t                       */
#include "mmcs_mixed_air_fold.h" /* dnac_mmix_air_fold_bind                   */
#include "mmcs_mixed_air_table.h" /* dnac_p2c_mmix_table_cfg_t                */
#include "transcript_air_fold.h"  /* dnac_transcript_air_fold_bind            */
#include "transcript_air_table.h" /* dnac_tair_script_t + the script builder  */

#ifdef __cplusplus
extern "C" {
#endif

/* ── Instance indices (the ORDER the pinned prep root commits to) ─────────── */
#define DNAC_P2S_INST_MMIX ((uint32_t)0)
#define DNAC_P2S_INST_MMCS ((uint32_t)1)
#define DNAC_P2S_INST_FRI  ((uint32_t)2)
#define DNAC_P2S_INST_OI   ((uint32_t)3)
#define DNAC_P2S_INST_TAIR ((uint32_t)4)
#define DNAC_P2S_NUM_INSTANCES ((uint32_t)5)

/* ── The inner FRI shape (see the header derivation) ─────────────────────── */
#define DNAC_P2S_LGMH           ((size_t)5)
#define DNAC_P2S_LOG_BLOWUP     ((size_t)2)
#define DNAC_P2S_LFPL           ((size_t)0)
#define DNAC_P2S_MAX_LOG_ARITY   ((size_t)1)
#define DNAC_P2S_NUM_QUERIES     ((size_t)2)

/** The grinding widths of the OUTER FRI params. SINGLE-SOURCED here because
 *  three consumers must agree on them: `dnac_p2s_fri_params()`, the transcript
 *  script the entry builds, and the `pow_bits` PIN that compares the two
 *  (see `dnac_p2s_check_tair_pow_pin` — OBL-P2a-T1's second half). */
#define DNAC_P2S_COMMIT_POW_BITS ((size_t)0)
#define DNAC_P2S_QUERY_POW_BITS  ((size_t)0)

/** Fold rounds R = lgmh - log_blowup - log_final_poly_len (fri_verifier.c
 *  :640-650 with :609-611 closing the walk at log_final_height). DERIVED. */
#define DNAC_P2S_FRI_R (DNAC_P2S_LGMH - DNAC_P2S_LOG_BLOWUP - DNAC_P2S_LFPL)

/** The roll-in set: the ONE reduced opening below lgmh, at lgmh-1. */
#define DNAC_P2S_NUM_ROLLIN ((size_t)1)
#define DNAC_P2S_ROLLIN_0   (DNAC_P2S_LGMH - 1)

/* ── mmcs (commit round 0) ───────────────────────────────────────────────── */
/** Leaf lanes = the arity fp2 evals BASE-flattened, [c0,c1] x arity
 *  (fri_verifier.c:564-568 via extension_mmcs.rs:77-95). DERIVED from arity. */
#define DNAC_P2S_MMCS_TOTAL_WIDTH ((size_t)2 << DNAC_P2S_MAX_LOG_ARITY)
/** depth = log_folded_height at round 0 = lgmh - log_arity (fri_verifier.c
 *  :557, the height passed to the MMCS at :585-588). */
#define DNAC_P2S_MMCS_DEPTH (DNAC_P2S_LGMH - DNAC_P2S_MAX_LOG_ARITY)

/* ── mmix (input batch 0 = the inner MAIN round) ─────────────────────────── */
#define DNAC_P2S_MMIX_NUM_MATRICES ((size_t)2)
/** Per-matrix opened widths — the inner instances' main widths, straight off
 *  the fixture (both 1). A proof-shape scalar: nothing derives it. */
#define DNAC_P2S_MMIX_W0 ((size_t)1)
#define DNAC_P2S_MMIX_W1 ((size_t)1)
#define DNAC_P2S_MMIX_TOTAL_OPENED (DNAC_P2S_MMIX_W0 + DNAC_P2S_MMIX_W1)
/** Per-matrix heights: 2^(log_ext_degree_i + log_blowup) for the two inner
 *  instances (log_ext_degree 3 and 2). */
#define DNAC_P2S_MMIX_LH0 ((size_t)5)
#define DNAC_P2S_MMIX_LH1 ((size_t)4)
/** depth == log2(max height) == the tallest matrix's log-height. */
#define DNAC_P2S_MMIX_DEPTH DNAC_P2S_MMIX_LH0
/** Non-hiding recursion envelope (G-DET-3, user-locked at P2a): no leaf salt.
 *  Matches the fixture, whose input openings carry salt_elems 0
 *  (tests/batch_test_util.h:231-232). */
#define DNAC_P2S_MMIX_SALT_ELEMS ((size_t)0)

/* ── oi (open_input: the WHOLE input side, all three inner batches) ──────────
 * The distinct reduced-opening heights, STRICTLY DESCENDING, heights[0] == lgmh
 * (fri_oi_air_table.h:362-364). NO height at log_blowup — that is the FLEET 029
 * shape and it is what makes C4b/C5 vacuous here (fri_oi_air_table.h:366-372). */
#define DNAC_P2S_OI_NUM_HEIGHTS ((size_t)2)
#define DNAC_P2S_OI_H0 DNAC_P2S_LGMH
#define DNAC_P2S_OI_H1 ((size_t)4)

/* The group descriptor. See the header's HONEST LABEL: only the PRODUCT (the
 * group's acc-row count) and the group boundary are load-bearing; the (m,p,c)
 * split is a label, unread for a group that is not the log_blowup group. */
#define DNAC_P2S_OI_NUM_BATCHES  ((size_t)3) /* main / quotient / preprocessed */
#define DNAC_P2S_OI_NUM_MATRICES ((size_t)1) /* per batch, at each height      */
#define DNAC_P2S_OI_NUM_POINTS   ((size_t)2)
#define DNAC_P2S_OI_NUM_COLUMNS  ((size_t)1)

/** Acc rows per height group = the four-loop tuple count (fri_verifier.c:207 /
 *  :400 / :436 / :469). Both pinned heights have the same shape here. */
#define DNAC_P2S_OI_ACC_PER_HEIGHT                                            \
    (DNAC_P2S_OI_NUM_BATCHES * DNAC_P2S_OI_NUM_MATRICES *                     \
     DNAC_P2S_OI_NUM_POINTS * DNAC_P2S_OI_NUM_COLUMNS)
/** Σ over the height groups — the length of the z / p_z public region. */
#define DNAC_P2S_OI_TOTAL_ACC                                                 \
    (DNAC_P2S_OI_ACC_PER_HEIGHT * DNAC_P2S_OI_NUM_HEIGHTS)

/* ── s2: the MAIN input batch's share of each height group ───────────────────
 * The oi schedule emits a group's acc rows BATCH-MAJOR (batch -> matrix ->
 * point -> column, fri_oi_air_table.h:104-114, the native's own nesting at
 * fri_verifier.c:207/400/436/469), and the batch index IS the native's batch
 * loop index, i.e. the position in `qp->input_proof`. Input batch 0 is the
 * inner MAIN round — the batch the mmix instance describes (see the mmix block
 * above, and T-REF in tests/test_fri_statement.c, which MEASURES the fixture's
 * per-batch per-height shape rather than assuming it).
 * So the FIRST `DNAC_P2S_OI_ACC_PER_BATCH` acc rows of every height group are
 * the main batch's, and their `p_x` is that height's mmix opened lane. */
#define DNAC_P2S_OI_ACC_PER_BATCH                                             \
    (DNAC_P2S_OI_NUM_MATRICES * DNAC_P2S_OI_NUM_POINTS *                      \
     DNAC_P2S_OI_NUM_COLUMNS)
/** Acc rows whose p_x is MMCS-bound by aliasing (main batch, every height). */
#define DNAC_P2S_OI_MAIN_ACC                                                  \
    (DNAC_P2S_OI_NUM_HEIGHTS * DNAC_P2S_OI_ACC_PER_BATCH)
/** Acc rows whose p_x still comes from the statement (quotient + preprocessed
 *  batches). Length of `dnac_p2s_statement_t::px_rest`. */
#define DNAC_P2S_OI_PX_REST                                                   \
    (DNAC_P2S_OI_TOTAL_ACC - DNAC_P2S_OI_MAIN_ACC)

/* ── tair (the transcript instance — s3b) ────────────────────────────────────
 * The FRI-tail cfg is DERIVED from the statement constants above, never written
 * out: `dnac_p2s_tair_fri_cfg()` fills `dnac_tair_fri_cfg_t` from R / lfpl / Q /
 * lgmh / the two PoW widths, and the script is then EXPANDED from it by the
 * shipped `dnac_tair_fri_build_script` (transcript_air_table.c:268-341) — the
 * same authority `dnac_tair_ref_script` uses, so "the REF script" and "the
 * statement script" cannot be two different things. The test asserts they are
 * op-for-op equal at this pin.
 *
 * The op COUNT is mirrored here as a compile-time expression only because the
 * statement struct needs a fixed array bound; it is the same sum
 * `dnac_tair_fri_num_ops` computes, and the entry COMPARES the two and fails
 * closed on any disagreement (the count-KAFADAN discipline, exactly as
 * DNAC_P2S_FRI_NUM_PUBLICS is compared against `dnac_fair_num_publics`).
 *
 *   ops = RATE (DS prefix)            transcript_air_table.c:297
 *       + 2 (alpha, an fp2 pop)                            :299-300
 *       + R * (DIGEST_LANES + powops(commit) + 2)          :302-310
 *       + (2 << lfpl) (final poly)                         :313-314
 *       + R (per-round log_arity)                          :317
 *       + powops(query)                                    :319-322
 *       + Q (one index sample per query)                   :324
 * where powops(bits) is 2 for a non-zero width and 0 for zero — the ZERO-OP
 * `check_witness` branch (duplex_challenger.c:153-155). */
#define DNAC_P2S_TAIR_POW_OPS(bits) ((bits) != 0 ? (size_t)2 : (size_t)0)

#define DNAC_P2S_TAIR_NUM_OPS                                                 \
    ((size_t)DNAC_DUPLEX_RATE + (size_t)2 +                                   \
     DNAC_P2S_FRI_R * ((size_t)DNAC_P2M_DIGEST_LANES +                        \
                       DNAC_P2S_TAIR_POW_OPS(DNAC_P2S_COMMIT_POW_BITS) +      \
                       (size_t)2) +                                           \
     ((size_t)2 << DNAC_P2S_LFPL) + DNAC_P2S_FRI_R +                          \
     DNAC_P2S_TAIR_POW_OPS(DNAC_P2S_QUERY_POW_BITS) + DNAC_P2S_NUM_QUERIES)

/** Exported index bits: one query sample per query, each exporting lgmh lanes
 *  (transcript_air_table.c:324). */
#define DNAC_P2S_TAIR_TOTAL_BITS (DNAC_P2S_NUM_QUERIES * DNAC_P2S_LGMH)

/** The bit lanes of queries 1..Q-1 — the ones NO other instance consumes in
 *  this slice (only query 0's index is modelled, OBL-P2c-2). Honest statement
 *  input until the multi-query slice; see `tair_bits_rest`. */
#define DNAC_P2S_TAIR_BITS_REST (DNAC_P2S_TAIR_TOTAL_BITS - DNAC_P2S_LGMH)

/** `dnac_tair_num_publics` = payload ‖ exported bits. Compared against the
 *  module accessor by the entry. */
#define DNAC_P2S_TAIR_NUM_PUBLICS                                             \
    (DNAC_P2S_TAIR_NUM_OPS + DNAC_P2S_TAIR_TOTAL_BITS)

/* ── Public-value counts, DERIVED from each AIR's documented layout ──────────
 * fri  (fri_air.h): bits[lgmh] ‖ beta[2R] ‖ f_init[2] ‖ ro[2*num_rollin] ‖
 *                   final[2]
 * mmcs (mmcs_air.h:181-182 + :227-231): root[4] ‖ dir[depth] ‖ opened[total]
 * mmix (mmcs_mixed_air.h:99-104):        root[4] ‖ dir[depth] ‖ opened[total]
 * oi   (fri_oi_air.h public layout): bits[lgmh] ‖ alpha[2] ‖
 *                            (z,p_z)[4*total_acc] ‖ ro[2*num_heights] ‖
 *                            p_x[total_acc]   (the s2 region, APPENDED LAST)
 * The entry compares each against the module accessor and fails closed on any
 * disagreement, so these cannot drift (the count-KAFADAN discipline). */
#define DNAC_P2S_FRI_NUM_PUBLICS                                              \
    (DNAC_P2S_LGMH + 2 * DNAC_P2S_FRI_R + 2 + 2 * DNAC_P2S_NUM_ROLLIN + 2)
#define DNAC_P2S_MMCS_NUM_PUBLICS                                             \
    ((size_t)MAIR_DIGEST_LANES + DNAC_P2S_MMCS_DEPTH +                        \
     DNAC_P2S_MMCS_TOTAL_WIDTH)
#define DNAC_P2S_MMIX_NUM_PUBLICS                                             \
    ((size_t)MMIX_DIGEST_LANES + DNAC_P2S_MMIX_DEPTH +                        \
     DNAC_P2S_MMIX_TOTAL_OPENED)
#define DNAC_P2S_OI_NUM_PUBLICS                                               \
    (DNAC_P2S_LGMH + 2 + 4 * DNAC_P2S_OI_TOTAL_ACC +                          \
     2 * DNAC_P2S_OI_NUM_HEIGHTS + DNAC_P2S_OI_TOTAL_ACC)

/** Widest of the five, for callers sizing one scratch buffer. */
#define DNAC_P2S_MAX_NUM_PUBLICS DNAC_P2S_OI_NUM_PUBLICS

/* ── Max SYMBOLIC constraint degree over the five fold AIRs ─────────────────
 * Not computable at runtime (C has no symbolic builder), so it is a CITED
 * module property, and `log_num_qc` is DERIVED from it by the upstream rule —
 * never written as a number. Each fold header states its own max degree, and
 * each says the same thing: the mandated `is_transition` selector factor
 * (transcription rule §3.2) lifts its degree-3 transition forms to 4.
 *   fri_air_fold.h:39-48   C3b / C3c / C4k / C4l  -> 4
 *   mmcs_air_fold.h:42-49  the two placement forms -> 4
 *   mmcs_mixed_air_fold.h:66-69  likewise          -> 4
 *   fri_oi_air_fold.h:43-48      C1b / C2b-sq      -> 4  (the u64 degree table
 *                                fri_oi_air.c:25-51 tops out at 3 in-AIR)
 *   transcript_air_fold.h:36-45  the transition-anchored forms -> 4 (its own
 *                                note names the same is_transition lift, and
 *                                its INLINE Poseidon2 block folds through the
 *                                shared gadget the two MMCS AIRs already embed
 *                                at this same degree)
 * If any of the five were actually HIGHER, the quotient would be undersized
 * and the honest round-trip would fail — RT-1 in test_fri_statement.c is the
 * evidence, not this comment. */
#define DNAC_P2S_MAX_SYMBOLIC_DEGREE ((size_t)4)

/* ── PIN: the composed preprocessed root ────────────────────────────────────
 * In DNAC the preprocessed commitment is PROVER-SUPPLIED PROOF DATA — the
 * prover commits its own tables and exports the lanes (batch_prover.c:818-825)
 * and `dnac_batch_verify` checks only their PRESENCE against the declared
 * matrix count. Nothing else in the tree compares that root to a pinned value,
 * so an all-zero selector table would satisfy every gated constraint of all
 * four AIRs vacuously. Upstream has no such hole: its preprocessed commitment
 * lives verifier-side in `CommonData` (full argument at mmcs_air_table.h:73-100).
 *
 * ⚠ ONE pin, not five — a CORRECTED DEVIATION from spec §2/§3.2, which asked
 * for one constant per table. `batch_prover.c:786-822` commits ALL preprocessed
 * matrices in ONE `dnac_p2_mmcs_commit_mixed` call, so a batched proof carries a
 * SINGLE 4-lane preprocessed root
 * (`dnac_batch_vcommits_t::preprocessed_commit`) and no per-table root exists
 * anywhere in it. Five constants would have had nothing to compare against.
 * The composed root binds all five tables jointly — tampering ANY cell of ANY
 * of them moves it — which is the property the pin needs; what it cannot do is
 * NAME the guilty table. The per-table discrimination spec §4's N-PIN×N asks
 * for therefore lives in the test, which tampers one table at a time and knows
 * which one it touched.
 *
 * ⚠ RE-PINNED AT s3b. Adding the TRANSCRIPT table as a fifth committed matrix
 * CHANGED the composed root; the s1c/s2 value is void and the constant below is
 * back at its {0,0,0,0} PLACEHOLDER. While it is, the comparator rejects
 * everything (see DNAC_P2S_PREP_ROOT_UNFILLED) and the pin-dependent checks in
 * tests/test_fri_statement.c assert exactly that; `--print-roots` refills it and
 * T-PINKAT then recomputes the root through the real pipeline and compares.
 *
 * DERIVATION (exactly the pipeline batch_prover.c:786-822 runs, is_zk = 0):
 *   for i in (mmix, mmcs, fri, oi, tair):             // prep_map order
 *       table_i = <table module>_generate(PINNED CFG_i)      // rows_i x COLS_i
 *       lde_i   = dnac_prover_coset_lde_bitrev(table_i, rows_i, COLS_i,
 *                     DNAC_P2S_LOG_BLOWUP, GOLDILOCKS_GENERATOR, ·)
 *   root = dnac_p2_mmcs_commit_mixed({lde_0..lde_4}, {COLS_i},
 *                                    {rows_i << lb}, 5, ·, NULL)
 * `dnac_p2_fri_statement_prep_tables` + the test's commit half ARE that
 * pipeline, so the pin is filled and re-checked by running code, never
 * transcribed by hand.
 *
 * The blowup is the OUTER `dnac_p2s_fri_params()->log_blowup`, because that is
 * what the prover commits the preprocessed matrices at. It coincides with the
 * per-module pins' DNAC_P2{B,C}_PREP_LOG_BLOWUP (both 2); the two are
 * independent quantities that happen to agree, so this uses its own constant.
 *
 * salt_elems = 0 is MANDATORY: salted + preprocessed is fail-closed at
 * batch_prover.c:604-612 (the guard inside `if (salt_elems > 0)`; citation
 * corrected — FLEET 028 verifier L3). */
#define DNAC_P2S_PREP_ROOT_LANE0 UINT64_C(0x0d61c566c046f50b)
#define DNAC_P2S_PREP_ROOT_LANE1 UINT64_C(0x6c028d283562f043)
#define DNAC_P2S_PREP_ROOT_LANE2 UINT64_C(0x5fc153486979664d)
#define DNAC_P2S_PREP_ROOT_LANE3 UINT64_C(0xba116b402a5fe146)

#define DNAC_P2S_PREP_ROOT                                                    \
    {                                                                         \
        DNAC_P2S_PREP_ROOT_LANE0, DNAC_P2S_PREP_ROOT_LANE1,                   \
        DNAC_P2S_PREP_ROOT_LANE2, DNAC_P2S_PREP_ROOT_LANE3                    \
    }

/** 1 while the pin above is still the unfilled placeholder. While it is, the
 *  comparator rejects EVERYTHING — a placeholder that accepted an all-zero
 *  root would be strictly worse than no pin, because a zero commitment is
 *  exactly what an adversary supplying an all-zero table would present
 *  (fri_air_table.h:398-401 precedent). Fill it with `--print-roots`. */
#define DNAC_P2S_PREP_ROOT_UNFILLED                                           \
    (DNAC_P2S_PREP_ROOT_LANE0 == 0 && DNAC_P2S_PREP_ROOT_LANE1 == 0 &&        \
     DNAC_P2S_PREP_ROOT_LANE2 == 0 && DNAC_P2S_PREP_ROOT_LANE3 == 0)

/* ── Status ─────────────────────────────────────────────────────────────── */
typedef enum {
    DNAC_P2S_OK = 0,
    DNAC_P2S_ERR_NULL = -1,      /**< required pointer missing               */
    DNAC_P2S_ERR_CANON = -2,     /**< G6: a statement value >= p, or an
                                      index bit outside {0,1}                */
    DNAC_P2S_ERR_PREP_ROOT = -3, /**< the pin comparison failed (incl. the
                                      unfilled-placeholder reject) or the
                                      preprocessed matrix map is not
                                      exactly {mmix, mmcs, fri, oi}          */
    DNAC_P2S_ERR_CFG = -4,       /**< a fold bind rejected the pinned cfg, a
                                      module accessor disagreed with the
                                      pinned public/geometry constants, or the
                                      STATIC cross-cfg consistency check
                                      (fri roll-in set vs OI.H) failed        */
    DNAC_P2S_ERR_SHAPE = -5,     /**< a pinned table height is not a power of
                                      two / does not fit a degree_bits        */
    DNAC_P2S_ERR_BATCH = -6      /**< dnac_batch_verify rejected; see `out`   */
} dnac_p2s_status_t;

/* ── The statement ──────────────────────────────────────────────────────────
 * Every field is a RAW canonical-candidate lane: step 1 is the ONE place their
 * canonicality is established, which is what lets the fold AIRs take
 * `gold_fp_t` publics (the s1a headers each defer exactly this).
 *
 * Region sizes are the PINNED cfg's, so they are compile-time — there is no
 * caller-supplied length to disagree with, and with it no length-mismatch
 * class. fp2 quantities are TWO consecutive lanes [c0, c1], c0 first, the
 * convention the fold modules use throughout. */
typedef struct {
    /** The ONE shared query index, LSB-first: bit l is index_bits[l].
     *  Every instance's direction/bit publics are ALIASES of this (step 6), so
     *  their agreement is true by construction rather than by a check. */
    uint64_t index_bits[DNAC_P2S_LGMH];

    /** s3b — the transcript instance's PAYLOAD publics, one lane per script op
     *  in script order: the OBSERVED value on an observe row, the POPPED
     *  challenge on a sampling row (transcript_air_table.h "PUBLIC-VALUE
     *  LAYOUT"). This is the SINGLE SOURCE of every Fiat-Shamir value the other
     *  instances consume — see the header's s3b block:
     *      fri.betas[r] := payload[the (2 + 2r)-th / (3 + 2r)-th non-PoW pop]
     *      oi.alpha     := payload[the first two non-PoW pops]
     *  so the `betas` and `alpha` statement fields of s1b/s1c are GONE, exactly
     *  as `f_init` / `rollins` went at s1c. There is no second field for a
     *  challenge to disagree with. */
    uint64_t tair_payload[DNAC_P2S_TAIR_NUM_OPS];
    /** s3b — the exported index bits of queries 1..Q-1, in script order.
     *
     *  ⚠ HONEST LABEL. Query 0's bits are NOT here: they are `index_bits`
     *  above, which the entry writes into BOTH the tair instance's exported-bit
     *  region and the four consumers' bit/direction regions — that alias is the
     *  seam this slice closes. The remaining queries have no consumer yet (only
     *  ONE query is modelled, OBL-P2c-2), so their lanes are a plain statement
     *  input until the multi-query slice replicates the consumers. */
    uint64_t tair_bits_rest[DNAC_P2S_TAIR_BITS_REST];

    /* fri regions (fri_air.h public layout).
     * ⚠ `f_init`, `rollins` (s1c) and now `betas` (s3b) are NOT fields — they
     * are DERIVED from `ro_export` / `tair_payload`. Adding any of them back
     * would re-open the very disagreement those slices removed. */
    uint64_t final_poly0[2];               /**< the walk's terminal, fp2   */

    /* oi regions (fri_oi_air.h:64-71 public layout).
     * ⚠ `alpha` is NOT a field either (s3b) — see `tair_payload`. */
    /** Per acc row, in SCHEDULE order (height-descending, then batch-major):
     *  z at 4*a, p_z at 4*a + 2, each fp2. */
    uint64_t zpz[4 * DNAC_P2S_OI_TOTAL_ACC];
    /** The exported reduced openings, ONE fp2 per height, DESCENDING — the
     *  SINGLE source of the fri walk's seed and roll-ins as well as the oi
     *  instance's own ro publics (fri_verifier.c:490-497 writes them in this
     *  order; fri_oi_air.h:79-82 exports them in it). */
    uint64_t ro_export[2 * DNAC_P2S_OI_NUM_HEIGHTS];
    /** s2 — the p_x of every acc row the MAIN batch does NOT cover, i.e. the
     *  quotient and preprocessed batches' rows, in schedule order (height
     *  descending, then batch-major, main batch's rows skipped).
     *
     *  ⚠ HONEST LABEL. The main batch's rows need no field here: the entry
     *  aliases them off `mmix_opened`, so they are MMCS-bound by construction.
     *  These are not — they are a statement input, exactly the trust level
     *  `p_x` had in s1c when it was a free witness. What CHANGED is that they
     *  are now inside the mechanism (a public C3g pins the trace column to)
     *  rather than outside it, so closing them is a matter of replacing this
     *  field with a second/third mmix instance when input-batch replication
     *  lands — not of adding a constraint. */
    uint64_t px_rest[DNAC_P2S_OI_PX_REST];

    /* inner commitment roots (4 lanes each) */
    uint64_t mmix_root[MMIX_DIGEST_LANES];
    uint64_t mmcs_root[MAIR_DIGEST_LANES];

    /* inner opened rows, concatenated in matrix order */
    uint64_t mmix_opened[DNAC_P2S_MMIX_TOTAL_OPENED];
    uint64_t mmcs_opened[DNAC_P2S_MMCS_TOTAL_WIDTH];
} dnac_p2s_statement_t;

/* ── Pinned-cfg accessors (the dnac_p2b_ref_cfg pattern,
 *    mmcs_air_table.h:232 — one definition, no caller re-declaration) ────── */
const dnac_p2c_mmix_table_cfg_t *dnac_p2s_mmix_cfg(void);
const dnac_p2b_table_cfg_t      *dnac_p2s_mmcs_cfg(void);
const dnac_p2c_table_cfg_t      *dnac_p2s_fri_cfg(void);
const dnac_p2c_oi_table_cfg_t   *dnac_p2s_oi_cfg(void);

/** The transcript AIR's own config (its `pow_bits`). DERIVED from the two
 *  DNAC_P2S_*_POW_BITS widths, and cross-checked against the script by
 *  `dnac_p2s_check_tair_pow_pin`. */
const dnac_tair_config_t *dnac_p2s_tair_cfg(void);

/** The FRI-tail scalars the pinned transcript script is expanded from, filled
 *  from the statement constants (R / lfpl / Q / lgmh / the PoW widths). */
const dnac_tair_fri_cfg_t *dnac_p2s_tair_fri_cfg(void);

/**
 * @brief The PINNED transcript op script, expanded once from
 *        `dnac_p2s_tair_fri_cfg()` by `dnac_tair_fri_build_script`.
 *
 * NULL if the shipped builder rejects the derived cfg (fail-close). The script
 * and the arrays it names have static storage duration, so the pointer is
 * valid for the life of the process — which is what lets the fold bind retain
 * it (transcript_air_fold.h:155-166).
 *
 * ⚠ SINGLE-THREADED, like every other binding in this composition: the script
 * is expanded on first use into module-static storage. The expansion is a pure
 * function of compile-time constants — no wire data, no clock, no RNG — so two
 * nodes always obtain the identical script.
 */
const dnac_tair_script_t *dnac_p2s_tair_script(void);

/**
 * @brief The `pow_bits` PIN — OBL-P2a-T1's second half (FLEET 032 #30).
 *
 * The preprocessed root does NOT bind the grinding width: the table's columns
 * are TYPE(6) + IS_POW(1) + POS(64) and the generator branches on zero-vs-
 * non-zero only, so a 1-bit script and a 16-bit script produce a BYTE-IDENTICAL
 * table and the SAME root (transcript_air_table.h:162-173). The width is what
 * the AIR turns into "the low `pow_bits` of the challenge are zero"
 * (transcript_air.c:262-263), so an entry that pins only the root could be
 * handed a 1-bit script where 16 were intended.
 *
 * This compares the width `s` actually carries (`dnac_tair_script_pow_bits`,
 * which itself fails closed when two PoW ops disagree) against the widths of
 * `dnac_p2s_fri_params()`, and rejects on ANY difference — including the case
 * where the params name two DIFFERENT non-zero widths, which one
 * `dnac_tair_config_t::pow_bits` cannot represent at all.
 *
 * Exposed because the pinned constants make both widths 0, so a compile-time
 * mismatch cannot be constructed: N-POWPIN drives this function with a
 * SYNTHETIC non-zero-PoW script instead.
 *
 * @return DNAC_P2S_OK on agreement, DNAC_P2S_ERR_CFG otherwise (or on NULL).
 */
dnac_p2s_status_t dnac_p2s_check_tair_pow_pin(const dnac_tair_script_t *s);

/** The OUTER FRI parameters the composed recursion proof is verified under.
 *  MECHANISM pin (see the header's production caveat): these size the proof,
 *  they do not choose a security level. */
const dnac_fri_params_t *dnac_p2s_fri_params(void);

/**
 * @brief Build the four batch descriptors from the statement — steps 3-6.
 *
 * Exposed because the TEST must prove the SAME instances the entry verifies:
 * were the test to assemble its own publics, a bug in the entry's aliasing
 * would be faithfully mirrored on both sides and RT-1 would pass regardless.
 * With one builder, RT-1 is a statement about the entry's own construction.
 *
 * Fills, per instance: the fold `air` descriptor (via the module's bind),
 * `preprocessed_width`, `prep_next = 1` (PIN-2, hard-coded — see the entry),
 * `degree_bits` from the table's own row count, `log_num_qc` from the upstream
 * symbolic rule, and `public_values` / `num_publics` pointing at the caller's
 * buffers, which this function fills.
 *
 * ⚠ Leaves the module-static fold bindings ARMED on success — the four fold
 * modules bind MODULE-STATICALLY (fri_air_fold.h:130-146) and `insts[].air`
 * only carries the callback, so the caller MUST run its prove/verify before
 * binding anything else. A rejected call disarms them (each bind clears its
 * own state on entry).
 *
 * @param stmt      the statement; publics are built from it, nothing is read
 *                  from any proof.
 * @param insts     [DNAC_P2S_NUM_INSTANCES], filled on success.
 * @param pub_mmix  >= DNAC_P2S_MMIX_NUM_PUBLICS elements; must outlive `insts`.
 * @param pub_mmcs  >= DNAC_P2S_MMCS_NUM_PUBLICS elements; must outlive `insts`.
 * @param pub_fri   >= DNAC_P2S_FRI_NUM_PUBLICS  elements; must outlive `insts`.
 * @param pub_oi    >= DNAC_P2S_OI_NUM_PUBLICS   elements; must outlive `insts`.
 * @param pub_tair  >= DNAC_P2S_TAIR_NUM_PUBLICS elements; must outlive `insts`.
 * @return DNAC_P2S_OK, or the first failing step's status.
 */
dnac_p2s_status_t dnac_p2_fri_statement_build_instances(
    const dnac_p2s_statement_t *stmt,
    dnac_batch_vinstance_t     *insts,
    gold_fp_t                  *pub_mmix,
    gold_fp_t                  *pub_mmcs,
    gold_fp_t                  *pub_fri,
    gold_fp_t                  *pub_oi,
    gold_fp_t                  *pub_tair);

/**
 * @brief Verify a composed FRI-verify statement.
 *
 * The steps, in this order, every one of them fail-close:
 *   1. G6 canonicality over the WHOLE statement (< p, and the index bits
 *      boolean) — before anything is derived from it.
 *   2. the preprocessed root pin + the preprocessed matrix map.
 *   3a. the STATIC cross-cfg consistency of the five pinned cfgs — no witness,
 *      no proof, pure constants (see `p2s_check_static_consistency` in the .c):
 *        (a) every fri roll-in height is an OI height OTHER than lgmh,
 *        (b) a fri roll-in AT the final height requires an OI group at
 *            log_blowup (fri_oi_air.h:90-99 hands this obligation to the
 *            composition entry explicitly),
 *        (c) OI.H[0] == lgmh == fri.lgmh, and the two cfgs agree on log_blowup,
 *        (d) s3b: the script's op count / public count match the pinned
 *            arithmetic, its non-PoW pop sequence has the alpha + 2R beta + Q
 *            query shape the aliases index into, each query sample exports
 *            exactly lgmh bits, and the `pow_bits` PIN holds
 *            (`dnac_p2s_check_tair_pow_pin`).
 *   3b. the five cfgs bound; a cfg is never read out of the proof (OBL-P2c-1).
 *   4. each `degree_bits` from `<module>_table_rows(cfg)`.
 *   5. `log_num_qc` from the upstream symbolic rule.
 *   6. every instance's publics assembled from the ONE `index_bits`, the ONE
 *      `ro_export`, the ONE `mmix_opened` (whose main-batch lanes are the s2
 *      source of the oi p_x publics), the ONE `tair_payload` (the s3b source of
 *      the fri betas and the oi alpha) and the statement's own regions
 *      (aliasing, not checking).
 *   7. `dnac_batch_verify` with is_zk = 0, num_random_codewords = 0,
 *      salt_elems = 0 and the pinned outer FRI params.
 * Steps 3-6 are `dnac_p2_fri_statement_build_instances`.
 *
 * @param stmt                     the statement.
 * @param opened                   [DNAC_P2S_NUM_INSTANCES] unmerged opened
 *                                 values, in the instance order above.
 * @param commits                  the batch commitments; `preprocessed_commit`
 *                                 is REQUIRED and is what the pin compares.
 * @param prep_matrix_to_instance  MUST be exactly {0, 1, 2, 3, 4}.
 * @param num_prep_matrices        MUST be DNAC_P2S_NUM_INSTANCES.
 * @param fri_proof                the FRI opening proof.
 * @param out                      optional batch diagnostics (nullable).
 * @return DNAC_P2S_OK on acceptance, else the first failing step's status.
 */
dnac_p2s_status_t dnac_p2_fri_statement_verify(
    const dnac_p2s_statement_t   *stmt,
    const dnac_batch_vopened_t   *opened,
    const dnac_batch_vcommits_t  *commits,
    const uint32_t               *prep_matrix_to_instance,
    uint32_t                      num_prep_matrices,
    const dnac_fri_proof_t       *fri_proof,
    dnac_batch_verify_out_t      *out);

/**
 * @brief Generate the five honest preprocessed tables for the pinned cfgs, in
 *        the instance order the pin commits to.
 *
 * Sizes: `out[i]` needs `dnac_p2s_prep_cells(i)` cells. Exposed so the
 * `--print-roots` pin-fill path and the pin negatives can generate, tamper one
 * cell, and re-commit — and so the ORDER lives in one place.
 *
 * ⚠ The LDE + Merkle-commit half of the pin pipeline is deliberately NOT here.
 * `dnac_prover_coset_lde_bitrev` lives in stark_prover.c, so exposing a
 * root-recomputing entry from this module would put the whole PROVER stack on
 * the link line of every consumer of the VERIFY entry — nodus links the verify
 * stack. The verify path compares the proof's root against the CONSTANT and
 * never runs an LDE, so the pipeline belongs to the test, exactly as
 * `mmcs_air_table.c` keeps only the comparator and `test_mmcs_air_table.c:72-95`
 * carries `p2b_commit_table`.
 */
dnac_p2s_status_t dnac_p2_fri_statement_prep_tables(uint64_t *const *out);

/** Preprocessed cell count (rows * cols) for instance `i`. 0 if `i` is out of
 *  range or the pinned cfg is rejected by its table module. */
size_t dnac_p2s_prep_cells(uint32_t instance);

/** Preprocessed width (columns) for instance `i`. 0 if `i` is out of range. */
size_t dnac_p2s_prep_cols(uint32_t instance);

/** Preprocessed row count for instance `i`. 0 if `i` is out of range or the
 *  pinned cfg is rejected. */
size_t dnac_p2s_prep_rows(uint32_t instance);

/**
 * @brief `log_num_qc` for a max symbolic constraint degree, by the upstream
 *        rule — exposed so the test can derive it independently.
 *
 * Plonky3 v0.6.2 `batch-stark/src/symbolic.rs:70-78`
 * (`get_log_num_quotient_chunks`, the function batch_verify.h:126 names as the
 * source of this field):
 *     max_degree        = max(air.max_constraint_degree(), lookup degrees)
 *     constraint_degree = max(max_degree + is_zk, 2)
 *     result            = log2_ceil(constraint_degree - 1)
 * The five fold AIRs declare no lookups, so the lookup term is 0 and drops out
 * (`.unwrap_or(0)` at symbolic.rs:75).
 *
 * @return the chunk-count exponent, or SIZE_MAX on a degenerate input.
 */
size_t dnac_p2s_log_num_qc(size_t max_symbolic_degree, int is_zk);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ZK_FRI_STATEMENT_H */
