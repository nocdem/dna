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
 * ── 1 + 4*Q instances (the MULTI-QUERY slice — OBL-P2c-2 discharged) ─────────
 *   idx 0                tair  the DuplexChallenger control AIR (the F-S tail)
 *   idx 1 + 4q + 0       mmix  mixed-height input-batch MMCS verify, QUERY q
 *   idx 1 + 4q + 1       mmcs  same-height binary MMCS verify (round 0), q
 *   idx 1 + 4q + 2       fri   the fold-walk control AIR,               q
 *   idx 1 + 4q + 3       oi    the reduced-opening accumulation AIR,    q
 * i.e. `DNAC_P2S_INST(q, DNAC_P2S_SLOT_*)`, with q < DNAC_P2S_NUM_QUERIES.
 *
 * ⚠ THE INSTANCE ORDER IS PART OF THE INTERFACE. The pinned preprocessed root
 * below is a commitment over the tables IN THIS ORDER, so the entry rejects any
 * other `prep_matrix_to_instance`. WHY this order, and not the s3b order with
 * the extra queries appended:
 *   - the transcript is the ONE SHARED producer and every query's four
 *     consumers read from it. At index 0 its position is INDEPENDENT of Q, so
 *     raising Q APPENDS instances instead of renumbering the producer (in the
 *     s3b order, tair sat at 4 and would have had to move to 4*Q).
 *   - a query's four consumers are CONTIGUOUS, so "the instances of query q" is
 *     one arithmetic expression and every per-query walk — in the entry, in the
 *     prep-table generator and in the gate — is a single nested loop rather
 *     than a lookup table.
 *   - inside a query the s1b..s3b slot order (mmix, mmcs, fri, oi) is kept, so
 *     the per-slot cfg / table / publics code is unchanged apart from its index.
 *
 * ⚠ HONEST NOTE — the Q copies of a slot's preprocessed table are BYTE-
 * IDENTICAL. The pinned cfgs are per-SLOT, not per-query (a table encodes the
 * AIR's SCHEDULE, and every query runs the same schedule; `num_queries` is a
 * fail-close sanity rail that never enters a table — fri_air_table.h:215-217,
 * fri_oi_air_table.h:225-226). So the composed root commits Q copies of each of
 * the four, which is redundancy, not a defect: what differs per query is the
 * MAIN trace and the PUBLICS, and those are what the aliases below partition.
 *
 * ── WHAT THE MULTI-QUERY SLICE CLOSES: OBL-P2c-2 (fri_air.h:163-169) ─────────
 * Until now the statement consumed exactly ONE of the Q query indices the
 * pinned script samples; the rest were the honest `tair_bits_rest` input with no
 * consumer. Q copies of one query is worth `lb + pow` bits of soundness, not
 * `lb*Q + pow`. Now every query has its own four instances, and the split
 * between what is SHARED and what is PER-QUERY is the native's own:
 *
 *   SHARED (sampled/observed ONCE, OUTSIDE the per-query loop at
 *   fri_verifier.c:736) — ONE statement field, aliased into all Q consumers:
 *     oi[q].alpha     := tair_payload[first two non-PoW pops]        (:694)
 *     fri[q].betas[r] := tair_payload[the round-r pop pair]          (:707)
 *     fri[q].final    := final_poly0  (observed once at :710-713; a single fp2
 *                        because log_final_poly_len == 0 is pinned)
 *     oi[q].p_z       := pz_shared    (the CLAIMED EVALUATIONS: :470 reads them
 *                        through `commitments`, which :743 passes unchanged on
 *                        every iteration of the query loop)
 *     mmix[q].root / mmcs[q].root := the ONE commitment each
 *
 *   PER-QUERY (produced INSIDE that loop) — one field PER QUERY, never aliased
 *   across q, because aliasing them is exactly the collapse OBL-P2c-2 forbids:
 *     index_bits[q]   the q-th index, and it is the tair instance's OWN q-th
 *                     exported bit block (:737 samples a FRESH index per query)
 *     ro_export[q]    the q-th `fri_open_input` result (:742), which is where
 *                     fri[q].f_init and its roll-ins come from
 *     mmix_opened[q] / mmcs_opened[q]   the rows opened AT the q-th index
 *     px_rest[q]      the q-th query's remaining opened values (:471 reads p_x
 *                     out of `qp->input_proof`, which IS the q-th query proof)
 *     z_pq[q]         the q-th query's opening points — HONEST LABEL 8: the
 *                     native's z does NOT move with q either, this one does
 *                     only because the shipped honest-trace builder ties z to x
 *
 * ⚠ "Q DISTINCT indices" is about POSITION, not VALUE. The native samples
 * freshly per query (:737) and two samples may legitimately land on the same
 * index; what must not happen is Q consumers all reading the transcript's q = 0
 * export block. That is what the per-query alias establishes by construction.
 * (The pinned script is a fixed pin, so its Q indices are constants of this
 * composition — the gate reports them and requires them to differ, which is an
 * assertion about THIS pin, not a probabilistic claim.)
 *
 * ── WHAT s3b CLOSED: the challenge <-> Fiat-Shamir transcript seam ───────────
 * s1c closed ro_export; s2 closed the main batch's p_x; s3b closed the last one
 * the earlier slices declared open by name: alpha, the betas and the query
 * INDEX were plain statement inputs, unbound to any transcript. They are BY
 * CONSTRUCTION the transcript instance's own publics — the statement carries ONE
 * `tair_payload` region (the observed/popped lane of every script op) and the
 * entry aliases it into its consumers. The `betas` and `alpha` statement fields
 * are GONE; the struct shrank.
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
 *   2. Commit rounds 1..R-1 are NOT replicated (one mmcs instance per query,
 *      round 0 only). ⚠ The other half of this label — "only ONE query is
 *      CONSUMED (OBL-P2c-2)" — is CLOSED by the multi-query slice: all Q are
 *      consumed now and `tair_bits_rest` is gone. Round replication remains.
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
 *   8. THE OPENING POINT `z` IS STILL PER-QUERY. WHAT ITS CLAIMED EVALUATION
 *      `p_z` USED TO BE IS FIXED.
 *
 *      In the native BOTH halves of an acc row's opening claim are query-
 *      invariant: `fri_open_input` receives `commitments` as an argument and the
 *      query loop passes the SAME pointer on every iteration (fri_verifier.c
 *      :743), so `cw = &commitments[batch]` (:209), `mo = &cw->matrices[m]`
 *      (:401) and `pt = &mo->points[point]` (:437) reach the same objects for
 *      every q — and from `pt` come BOTH `pt->point` (the opening point z, used
 *      at :464) and `pt->claimed_evals[j]` (p_z, :470). Only the OTHER two
 *      quantities move: `x` is derived from `index` (:425-430) and `p_at_x`
 *      comes from `qp->input_proof` (:471), i.e. from the q-th query proof.
 *
 *      ⚠ WHAT THE FIRST VERSION OF THIS LABEL MISSED. It kept ONE region,
 *      `zpz[q]`, carrying z at 4a and p_z at 4a+2, and justified the whole
 *      region with the builder argument in (b) below. That argument is about
 *      `z` ALONE. `p_z` was per-query as collateral damage, with NO reason
 *      given — an unjustified freedom that let two queries name two different
 *      claimed evaluations for the same opening. The region is now SPLIT:
 *        `pz_shared[2*TOTAL_ACC]` — ONE region, aliased into every oi instance,
 *                                   which is what the native says it is;
 *        `z_pq[q][2*TOTAL_ACC]`   — still per-query, for the reason below.
 *      Gate: N-PZSHARED (perturbing a `pz_shared` lane must move EVERY query's
 *      oi instance) and N-QINDEP/z (perturbing `z_pq[q]` must move ONLY q's).
 *
 *      WHY `z` STAYS PER-QUERY — the (b) argument, which is valid for z only:
 *      the shipped oi honest-trace builder derives z AS x + zoff
 *      (tests/test_fri_oi_air.c:262-263, chosen so that z - x is a fixed
 *      invertible fixture), and x IS query-dependent, so with two different
 *      indices it emits two different z. A shared z region would have no honest
 *      witness, and forcing one means a builder hook — a change to a file this
 *      slice does not own. `p_z` has no such obstacle: the same builder emits
 *      `pz = cur_is_lb ? emb(px) : tfp2(a_global + 3, 19)` (:265-266) and the
 *      pinned cfg takes the second branch on every row (heights {5, 4} vs
 *      log_blowup 2), so p_z is a pure function of the schedule ordinal and a
 *      shared region HAS a witness — which RT-1 now demonstrates by construction.
 *
 *      WHAT REMAINS OPEN, by name: a per-query z still admits a statement whose
 *      two queries name two DIFFERENT opening points. It costs nothing that was
 *      previously held — z / zeta were ALREADY unbound plain statement inputs
 *      (label 1: the priming ops are not in the pinned script, so nothing
 *      recomputes zeta), so a shared z would be one unbound value instead of Q,
 *      not a binding. Closing it is the PRIMING-TRANSCRIPT slice's job (label 1),
 *      where zeta becomes a transcript public and the alias becomes available;
 *      it is NOT achievable by re-shaping this field alone.
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

/* ── The inner FRI shape (see the header derivation) ─────────────────────── */
#define DNAC_P2S_LGMH           ((size_t)5)
#define DNAC_P2S_LOG_BLOWUP     ((size_t)2)
#define DNAC_P2S_LFPL           ((size_t)0)
#define DNAC_P2S_MAX_LOG_ARITY   ((size_t)1)
#define DNAC_P2S_NUM_QUERIES     ((size_t)2)

/* ── Instance indices (the ORDER the pinned prep root commits to) ─────────────
 * See the file header's instance map for why the transcript sits at 0 and each
 * query's four consumers are contiguous. Nothing below is a written-out number:
 * the instance COUNT is derived from the slot count and Q. */

/** Slot of a consumer inside its query's block. */
#define DNAC_P2S_SLOT_MMIX ((uint32_t)0)
#define DNAC_P2S_SLOT_MMCS ((uint32_t)1)
#define DNAC_P2S_SLOT_FRI  ((uint32_t)2)
#define DNAC_P2S_SLOT_OI   ((uint32_t)3)
/** Consumers per query. Also the value `dnac_p2s_inst_slot` returns for the
 *  transcript instance and for an out-of-range index (i.e. "no slot"). */
#define DNAC_P2S_SLOTS     ((uint32_t)4)

/** The ONE shared producer. Q-independent by construction (see the map). */
#define DNAC_P2S_INST_TAIR ((uint32_t)0)

/** Instance index of query `q`'s consumer in slot `slot`. */
#define DNAC_P2S_INST(q, slot)                                                \
    ((uint32_t)(1u + DNAC_P2S_SLOTS * (uint32_t)(q) + (uint32_t)(slot)))

/** DERIVED — 1 producer + 4 consumers per query. Never written as a number. */
#define DNAC_P2S_NUM_INSTANCES                                                \
    ((uint32_t)(1u + DNAC_P2S_SLOTS * (uint32_t)DNAC_P2S_NUM_QUERIES))

/** MIRROR of the batch stack's instance cap, with its citation: `dnac_batch_
 *  verify` rejects `num_instances > BV_MAX_INSTANCES` (batch_verify.c:20 and
 *  :86) and `dnac_batch_prove` (batch_prover.c:555) rejects
 *  `> BP_MAX_INSTANCES` at batch_prover.c:572 (the constant is :22; the two
 *  helpers `dnac_batch_prove_num_draws` :210 and `_num_salt_draws` :247 carry
 *  the same bound but are NOT the prove entry — FLEET 035 verifier, citation
 *  corrected); both are 32 and NEITHER is exported by a header, so this is an
 *  honest duplicate rather than a shared constant. It exists only to DERIVE the
 *  Q ceiling below; the compile-time assert in fri_statement.c is what turns a
 *  Q past that ceiling into a build failure instead of a runtime reject. */
#define DNAC_P2S_BATCH_MAX_INSTANCES ((uint32_t)32)

/** The largest Q this composition shape can carry: (cap - 1 producer) / 4. */
#define DNAC_P2S_MAX_QUERIES                                                  \
    ((size_t)((DNAC_P2S_BATCH_MAX_INSTANCES - 1u) / DNAC_P2S_SLOTS))

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
 *  (transcript_air_table.c:324). EVERY one of them now has a consumer — query
 *  q's block IS `index_bits[q]` — so the `tair_bits_rest` field and its
 *  DNAC_P2S_TAIR_BITS_REST length that stood for the unconsumed remainder are
 *  GONE (multi-query slice; OBL-P2c-2). */
#define DNAC_P2S_TAIR_TOTAL_BITS (DNAC_P2S_NUM_QUERIES * DNAC_P2S_LGMH)

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

/** Widest of the five AIRs, for callers sizing one scratch buffer. */
#define DNAC_P2S_MAX_NUM_PUBLICS DNAC_P2S_OI_NUM_PUBLICS

/* ── The FLAT publics block (multi-query slice) ───────────────────────────────
 * s3b handed `build_instances` five separate `gold_fp_t *`, one per AIR. With
 * 1 + 4*Q instances that parameter list is neither writable nor Q-independent,
 * so the instances' publics now live CONTIGUOUSLY in ONE caller-owned block, in
 * INSTANCE ORDER: the tair region first, then query 0's four, then query 1's,
 * and so on. `dnac_p2s_pub_off` is the ONLY thing that knows the layout, so a
 * caller never computes an offset and the entry never hard-codes one. */
#define DNAC_P2S_QUERY_PUBLICS                                                \
    (DNAC_P2S_MMIX_NUM_PUBLICS + DNAC_P2S_MMCS_NUM_PUBLICS +                  \
     DNAC_P2S_FRI_NUM_PUBLICS + DNAC_P2S_OI_NUM_PUBLICS)

#define DNAC_P2S_TOTAL_PUBLICS                                                \
    (DNAC_P2S_TAIR_NUM_PUBLICS +                                              \
     DNAC_P2S_NUM_QUERIES * DNAC_P2S_QUERY_PUBLICS)

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
 * ⚠ ONE pin, not one per table — a CORRECTED DEVIATION from spec §2/§3.2, which
 * asked for one constant per table. `batch_prover.c:786-822` commits ALL
 * preprocessed matrices in ONE `dnac_p2_mmcs_commit_mixed` call, so a batched
 * proof carries a SINGLE 4-lane preprocessed root
 * (`dnac_batch_vcommits_t::preprocessed_commit`) and no per-table root exists
 * anywhere in it. Per-table constants would have had nothing to compare against.
 * The composed root binds all the tables jointly — tampering ANY cell of ANY
 * of them moves it — which is the property the pin needs; what it cannot do is
 * NAME the guilty table. The per-table discrimination spec §4's N-PIN×N asks
 * for therefore lives in the test, which tampers one table at a time and knows
 * which one it touched.
 *
 * ⚠ RE-PINNED AT THE MULTI-QUERY SLICE. The instance set went from 5 matrices
 * to 1 + 4*Q in a NEW order (transcript first, then each query's four), and both
 * the count and the order feed the mixed commit — so the s3b value is void and
 * the constant below is back at its {0,0,0,0} PLACEHOLDER. While it is, the
 * comparator rejects everything (see DNAC_P2S_PREP_ROOT_UNFILLED) and the
 * pin-dependent checks in tests/test_fri_statement.c assert exactly that;
 * `--print-roots` refills it and T-PINKAT then recomputes the root through the
 * real pipeline and compares.
 *
 * DERIVATION (exactly the pipeline batch_prover.c:786-822 runs, is_zk = 0):
 *   for i in 0 .. DNAC_P2S_NUM_INSTANCES-1:           // prep_map order
 *       table_i = <table module for the slot of i>_generate(PINNED CFG)
 *       lde_i   = dnac_prover_coset_lde_bitrev(table_i, rows_i, COLS_i,
 *                     DNAC_P2S_LOG_BLOWUP, GOLDILOCKS_GENERATOR, ·)
 *   root = dnac_p2_mmcs_commit_mixed({lde_i}, {COLS_i}, {rows_i << lb},
 *                                    DNAC_P2S_NUM_INSTANCES, ·, NULL)
 * The Q copies of a slot's table are byte-identical (see the file header's
 * honest note); the root still MOVES when any single cell of any single copy is
 * tampered, which is what the pin needs and what N-PIN asserts per instance.
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
#define DNAC_P2S_PREP_ROOT_LANE0 UINT64_C(0x2a3d33b3147d5931)
#define DNAC_P2S_PREP_ROOT_LANE1 UINT64_C(0xcd89ac43548b337c)
#define DNAC_P2S_PREP_ROOT_LANE2 UINT64_C(0x79258c2d74edf477)
#define DNAC_P2S_PREP_ROOT_LANE3 UINT64_C(0xce9bfc860f64c3d9)

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
                                      preprocessed matrix map is not the
                                      identity over DNAC_P2S_NUM_INSTANCES   */
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
    /** PER-QUERY. Query q's index, LSB-first: bit l is index_bits[q][l]. Every
     *  instance of query q takes its direction/bit publics as ALIASES of THIS
     *  row (step 6), and the row is ALSO the transcript instance's own q-th
     *  exported bit block — so "the index the transcript produced" and "the
     *  index query q's four AIRs walk" are the same lanes by construction.
     *
     *  ⚠ NEVER aliased ACROSS q. Q consumers reading row 0 is exactly the
     *  soundness collapse OBL-P2c-2 names (fri_air.h): the native samples a
     *  FRESH index per query at fri_verifier.c:737. */
    uint64_t index_bits[DNAC_P2S_NUM_QUERIES][DNAC_P2S_LGMH];

    /** SHARED — the transcript instance's PAYLOAD publics, one lane per script
     *  op in script order: the OBSERVED value on an observe row, the POPPED
     *  challenge on a sampling row (transcript_air_table.h "PUBLIC-VALUE
     *  LAYOUT"). This is the SINGLE SOURCE of every Fiat-Shamir value the other
     *  instances consume, and every consumer of every query reads the SAME
     *  lanes — which is correct, because the native samples them ONCE, outside
     *  the query loop:
     *      fri[q].betas[r] := payload[the (2+2r)-th/(3+2r)-th non-PoW pop] :707
     *      oi[q].alpha     := payload[the first two non-PoW pops]          :694
     *  so the `betas` and `alpha` statement fields of s1b/s1c are GONE, exactly
     *  as `f_init` / `rollins` went at s1c. There is no second field for a
     *  challenge to disagree with — and no per-query copy either, so two
     *  queries cannot be folded with two different betas.
     *
     *  ⚠ The exported index bits of the tair instance are NOT here: they are
     *  `index_bits` above. `tair_bits_rest`, which held the queries no consumer
     *  modelled, is GONE — all Q are consumed now. */
    uint64_t tair_payload[DNAC_P2S_TAIR_NUM_OPS];

    /* fri regions (fri_air.h public layout).
     * ⚠ `f_init`, `rollins` (s1c) and `betas` (s3b) are NOT fields — they are
     * DERIVED from `ro_export[q]` / `tair_payload`. Adding any of them back
     * would re-open the very disagreement those slices removed. */
    /** SHARED — the walk's terminal, fp2. A single fp2 because
     *  log_final_poly_len == 0 is pinned (fri_air.h:105-106), and SHARED across
     *  q because the native observes the final poly once, before the query loop
     *  (fri_verifier.c:710-713). */
    uint64_t final_poly0[2];

    /** SHARED — the CLAIMED EVALUATION p_z of each acc row, in the SAME
     *  SCHEDULE order as `z_pq`: row a is the fp2 at 2*a, 2*a + 1. ONE region,
     *  aliased into every query's oi instance — the `ro_export` / `tair_payload`
     *  pattern, so two queries cannot name two different claimed evaluations
     *  for the same opening.
     *
     *  Native: `p_at_z = pt->claimed_evals[j]` (fri_verifier.c:470) where `pt`
     *  reaches back to `commitments[batch]` (:401 `mo = &cw->matrices[m]`, :437
     *  `pt = &mo->points[point]`, :209 `cw = &commitments[batch]`), and
     *  `commitments` is the SAME pointer on every iteration of the query loop
     *  (:743). Its partner `p_at_x` (:471) comes from `qp->input_proof` and IS
     *  per-query — that one is `mmix_opened[q]` / `px_rest[q]`.
     *
     *  ⚠ THE HONEST WITNESS FOR A SHARED REGION EXISTS ONLY WHILE NO OI HEIGHT
     *  GROUP SITS AT log_blowup. The shipped builder emits
     *  `pz = cur_is_lb ? emb(px) : tfp2(a_global + 3, 19)`
     *  (tests/test_fri_oi_air.c:265-266): the lb branch makes p_z a copy of p_x,
     *  which IS query-dependent, while the pinned cfg's heights {5, 4} against
     *  log_blowup 2 take the other branch on every row — a pure function of the
     *  schedule ordinal. T-CONST already fails closed if any pinned oi group
     *  ever moves to log_blowup (it guards C4b/C5 vacuity); that same check is
     *  now also what protects this region's witness. */
    uint64_t pz_shared[2 * DNAC_P2S_OI_TOTAL_ACC];

    /* oi regions (fri_oi_air.h:64-71 public layout).
     * ⚠ `alpha` is NOT a field either (s3b) — see `tair_payload`. */
    /** PER-QUERY. The OPENING POINT z of each acc row, in SCHEDULE order
     *  (height-descending, then batch-major): row a is the fp2 at 2*a, 2*a + 1.
     *
     *  ⚠ Per-query is WEAKER than the native, which takes z from
     *  `commitments[batch]` — a `fri_open_input` argument that does not move
     *  across the query loop (fri_verifier.c:743 passes the same pointer; :401
     *  and :437 reach z through it). See HONEST LABEL 8: this region stays
     *  per-query because the shipped honest-trace builder derives z as x + zoff
     *  and x IS query-dependent, so a shared region would have no witness. */
    uint64_t z_pq[DNAC_P2S_NUM_QUERIES][2 * DNAC_P2S_OI_TOTAL_ACC];
    /** PER-QUERY. Query q's exported reduced openings, ONE fp2 per height,
     *  DESCENDING — the SINGLE source of that query's fri walk seed and
     *  roll-ins as well as its oi instance's own ro publics
     *  (fri_verifier.c:490-497 writes them in this order; fri_oi_air.h:79-82
     *  exports them in it).
     *  ⚠ NEVER aliased across q: `fri_open_input` runs INSIDE the per-query
     *  loop, against that query's index (fri_verifier.c:742). */
    uint64_t ro_export[DNAC_P2S_NUM_QUERIES][2 * DNAC_P2S_OI_NUM_HEIGHTS];
    /** PER-QUERY. s2 — the p_x of every acc row the MAIN batch does NOT cover,
     *  i.e. the quotient and preprocessed batches' rows, in schedule order
     *  (height descending, then batch-major, main batch's rows skipped).
     *
     *  ⚠ HONEST LABEL. The main batch's rows need no field here: the entry
     *  aliases them off `mmix_opened[q]`, so they are MMCS-bound by
     *  construction. These are not — they are a statement input, exactly the
     *  trust level `p_x` had in s1c when it was a free witness. What CHANGED is
     *  that they are now inside the mechanism (a public C3g pins the trace
     *  column to) rather than outside it, so closing them is a matter of
     *  replacing this field with a second/third mmix instance when input-batch
     *  replication lands — not of adding a constraint. Per-query because p_x is
     *  an OPENED value: it is read at the query's own index
     *  (fri_verifier.c:469-476). */
    uint64_t px_rest[DNAC_P2S_NUM_QUERIES][DNAC_P2S_OI_PX_REST];

    /* SHARED inner commitment roots (4 lanes each). One commitment, opened at Q
     * different indices — the root is what every query's opening is checked
     * against, so a per-query root would let two queries open two trees. */
    uint64_t mmix_root[MMIX_DIGEST_LANES];
    uint64_t mmcs_root[MAIR_DIGEST_LANES];

    /* PER-QUERY inner opened rows, concatenated in matrix order. These ARE the
     * query-dependent half of an MMCS opening: same tree, same root, different
     * leaf. */
    uint64_t mmix_opened[DNAC_P2S_NUM_QUERIES][DNAC_P2S_MMIX_TOTAL_OPENED];
    uint64_t mmcs_opened[DNAC_P2S_NUM_QUERIES][DNAC_P2S_MMCS_TOTAL_WIDTH];
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

/** One query's four consumer snapshots. */
typedef struct {
    dnac_mmix_fold_state_t mmix;
    dnac_mair_fold_state_t mmcs;
    dnac_fair_fold_state_t fri;
    dnac_foi_fold_state_t  oi;
} dnac_p2s_query_fold_states_t;

/**
 * @brief Storage for every instance's fold-state snapshot (FLEET 034, grown to
 *        1 + 4*Q by the multi-query slice).
 *
 * The fold modules keep NO module-static binding: `<module>_fold_bind` fills a
 * CALLER-OWNED state and points the descriptor's `ctx` at it
 * (stark_constraints.h:299-311). That is precisely what makes Q instances of
 * the SAME AIR possible: each gets its own snapshot, so query 1's bind cannot
 * clobber query 0's. This block is all of them, in instance order, so a caller
 * declares ONE object instead of 1 + 4*Q.
 *
 * Contents are this file's business — declare it, pass it, do not read it.
 *
 * ⚠ SIZE. ~11.3 KB at Q = 2 (5.8 KB at Q = 1, and it grows by ~5.6 KB per
 * query — `dnac_mmix_fold_state_t` alone is 4 KB). `dnac_p2_fri_statement_
 * verify` keeps one on its own FRAME, deliberately: a file-scope object would
 * make the entry non-reentrant and give back exactly the shared-binding hazard
 * FLEET 034 removed, and a heap object would add an allocation-failure path to
 * a function whose whole contract is "construct and reject". A caller that
 * cannot afford ~15 KB of frame (that block plus the descriptors and the
 * publics) should drive `dnac_p2_fri_statement_build_instances` with storage of
 * its own lifetime instead — which is why that entry point is exposed.
 */
typedef struct {
    dnac_tair_fold_state_t       tair;
    dnac_p2s_query_fold_states_t q[DNAC_P2S_NUM_QUERIES];
} dnac_p2s_fold_states_t;

/** Public-value count for instance `i`. 0 if `i` is out of range. */
size_t dnac_p2s_num_publics(uint32_t instance);

/** Start of instance `i`'s region inside the flat publics block, in elements.
 *  SIZE_MAX if `i` is out of range. The regions are contiguous, in instance
 *  order, and together span exactly DNAC_P2S_TOTAL_PUBLICS. */
size_t dnac_p2s_pub_off(uint32_t instance);

/** The per-query SLOT of instance `i`, or DNAC_P2S_SLOTS for the transcript
 *  instance and for an out-of-range index ("no slot"). */
uint32_t dnac_p2s_inst_slot(uint32_t instance);

/** The QUERY instance `i` belongs to. SIZE_MAX for the transcript instance and
 *  for an out-of-range index. */
size_t dnac_p2s_inst_query(uint32_t instance);

/**
 * @brief Build every batch descriptor from the statement — steps 3-6.
 *
 * Exposed because the TEST must prove the SAME instances the entry verifies:
 * were the test to assemble its own publics, a bug in the entry's aliasing
 * would be faithfully mirrored on both sides and RT-1 would pass regardless.
 * With one builder, RT-1 is a statement about the entry's own construction.
 *
 * Fills, per instance: the fold `air` descriptor (via the module's bind,
 * including its `ctx` into `states`), `preprocessed_width`, `prep_next = 1`
 * (PIN-2, hard-coded — see the entry), `degree_bits` from the table's own row
 * count, `log_num_qc` from the upstream symbolic rule, and `public_values` /
 * `num_publics` pointing INTO `pub`, which this function fills.
 *
 * ⚠ On success the descriptors' `ctx` fields point INTO `states` and their
 * `public_values` INTO `pub`, which is why both carry the must-outlive rule.
 *
 * ⚠ On FAILURE — stated exactly, because the useful property is about `insts`,
 * not about `states`. Once `insts` is non-NULL it is ZEROED before anything
 * else, so EVERY failure path below leaves every descriptor with
 * `ctx == NULL` AND `air_eval == NULL`: a caller that ignores the return code
 * cannot evaluate a stale cfg's constraint system, because it cannot evaluate
 * at all. Additionally, each bind that actually RAN disarmed its own state and
 * its own descriptor on entry. States belonging to binds that were never
 * reached (an early step-3a reject, or a later query's binds after an earlier
 * query failed) are left exactly as the caller supplied them — which is why
 * `dnac_p2_fri_statement_verify` zero-initialises the block, and why callers
 * should too.
 *
 * @param stmt      the statement; publics are built from it, nothing is read
 *                  from any proof.
 * @param insts     [DNAC_P2S_NUM_INSTANCES], filled on success.
 * @param states    the fold-state snapshots; must outlive `insts`.
 * @param pub       >= DNAC_P2S_TOTAL_PUBLICS elements; must outlive `insts`.
 *                  Sliced by `dnac_p2s_pub_off` / `dnac_p2s_num_publics`.
 * @return DNAC_P2S_OK, or the first failing step's status.
 */
dnac_p2s_status_t dnac_p2_fri_statement_build_instances(
    const dnac_p2s_statement_t *stmt,
    dnac_batch_vinstance_t     *insts,
    dnac_p2s_fold_states_t     *states,
    gold_fp_t                  *pub);

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
 *   3b. every cfg bound; a cfg is never read out of the proof (OBL-P2c-1).
 *   4. each `degree_bits` from `<module>_table_rows(cfg)`.
 *   5. `log_num_qc` from the upstream symbolic rule.
 *   6. every instance's publics assembled from the statement's regions by
 *      ALIASING, not checking:
 *        - SHARED into every query: the ONE `tair_payload` (the s3b source of
 *          every fri instance's betas and every oi instance's alpha), the ONE
 *          `final_poly0`, the ONE `mmix_root` / `mmcs_root`;
 *        - PER QUERY q: `index_bits[q]` into the tair instance's q-th exported
 *          bit block AND into query q's four bit/direction regions;
 *          `ro_export[q]` into fri[q]'s f_init + roll-ins and oi[q]'s ro;
 *          `mmix_opened[q]` into mmix[q]'s opened row AND (s2) into oi[q]'s
 *          main-batch p_x publics; `mmcs_opened[q]`, `zpz[q]`, `px_rest[q]`.
 *   7. `dnac_batch_verify` with is_zk = 0, num_random_codewords = 0,
 *      salt_elems = 0 and the pinned outer FRI params.
 * Steps 3-6 are `dnac_p2_fri_statement_build_instances`.
 *
 * @param stmt                     the statement.
 * @param opened                   [DNAC_P2S_NUM_INSTANCES] unmerged opened
 *                                 values, in the instance order above.
 * @param commits                  the batch commitments; `preprocessed_commit`
 *                                 is REQUIRED and is what the pin compares.
 * @param prep_matrix_to_instance  MUST be the identity {0, 1, ..., N-1}.
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
 * @brief Generate the honest preprocessed table of every instance, in the
 *        instance order the pin commits to.
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
