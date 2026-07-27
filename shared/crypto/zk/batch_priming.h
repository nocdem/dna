/**
 * @file batch_priming.h
 * @brief Batch-STARK transcript priming + proof-shape checks — port of
 *        Plonky3 batch-stark BatchTranscript / verifier shape validation.
 *
 * Plonky3 commit pin: 82cfad73cd734d37a0d51953094f970c531817ec.
 *
 * P2L-c scope (P2-lookup design 2026-07-23 §4, v3 GREEN; round-2 N1 order):
 * the FULL batched Fiat-Shamir priming order over the P1 DuplexChallenger —
 *
 *   observe_instance_count(n)                      (transcript.rs:27-29)
 *   per-instance observe_instance_binding(
 *       log_ext_degree, log_degree, width,
 *       num_quotient_chunks)                       (transcript.rs:32-43)
 *   observe main commit + per-instance publics     (transcript.rs:46-54)
 *   observe preprocessed widths + optional commit  (transcript.rs:57-68;
 *                                                   AFTER main — N3/F2: the
 *                                                   v3 uni-stark order had
 *                                                   preprocessed FIRST)
 *   sample per-instance (α,β) with the per-bus
 *   memo (locals fresh; globals shared by name)    (transcript.rs:74-102,
 *                                                   via the P2L-b assigner)
 *   observe permutation commit + every
 *   cumulative_sum, then sample constraint-alpha   (transcript.rs:106-119)
 *   observe quotient commit                        (transcript.rs:122-124)
 *   observe random commit iff is_zk                (transcript.rs:127-129)
 *   sample ζ                                       (transcript.rs:132-134)
 *
 * — exactly the verifier's call sequence (verifier/mod.rs:143-300), which
 * the prover mirrors (prover.rs:200-447).
 *
 * Observe granularity (challenger/src/lib.rs):
 *   - usize v  → observe_base_as_algebra_element::<Goldilocks²>(v) =
 *                TWO base observes (v, 0)               (:141-147, :106-108)
 *   - fp2      → its 2 basis coefficients, c0 first     (:106-108)
 *   - commit   → 4 digest lanes                         (P1 pin)
 *   - sample fp2 → 2 base samples, c0 first             (P1a pin)
 *
 * Proof shape (proof.rs:12-55 BatchProof + the verifier checks): see
 * dnac_batch_proof_shape_check below. This stage is IN-MEMORY shape only —
 * the DZKF v4 wire codec, the FRI opening rounds and the prover/verifier
 * cutover are P2L-d (design §4; N2 pins the opening-round order there).
 * The existing v3 uni-stark priming (stark_priming.{c,h}) is UNTOUCHED and
 * stays live until the P2L-d cutover (F2: the two orders do NOT byte-match).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_BATCH_PRIMING_H
#define DNAC_BATCH_PRIMING_H

#include <stddef.h>
#include <stdint.h>

#include "duplex_challenger.h"
#include "logup_bus.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Error codes (fail-close; 0 = OK). */
#define DNAC_BATCH_OK        0
#define DNAC_BATCH_ERR_NULL  (-1) /* required pointer is NULL               */
#define DNAC_BATCH_ERR_SHAPE (-2) /* proof-shape check failed (mirrors a
                                     verifier InvalidProofShapeError)       */
#define DNAC_BATCH_ERR_PARAM (-3) /* inconsistent inputs (binding arithmetic,
                                     commit/flag mismatches)                */
#define DNAC_BATCH_ERR_OOM   (-4) /* scratch allocation failed              */

/* Per-instance transcript binding (transcript.rs:32-43; the verifier feeds
 * ext_db, base_db = ext_db − is_zk, width, num_quotient_chunks —
 * verifier/mod.rs:269-274). */
typedef struct {
    uint32_t log_ext_degree;      /* proof degree_bits[i] (incl. is_zk +1)  */
    uint32_t log_degree;          /* base; MUST == log_ext_degree − is_zk   */
    uint32_t width;               /* main trace width                       */
    uint32_t num_quotient_chunks; /* incl. the ZK doubling                  */
} dnac_batch_binding_t;

/* ============================================================================
 * Phase primitives (each mirrors one BatchTranscript method; the KAT
 * snapshots the duplex between calls)
 * ========================================================================== */

/* observe_usize (transcript.rs:136-140): two base observes (v, 0). */
void dnac_batch_observe_usize(dnac_duplex_t *ch, uint64_t v);

/* Observe a 4-lane commitment digest (P1 digest-observe pin). */
void dnac_batch_observe_commit(dnac_duplex_t *ch, const gold_fp_t commit[4]);

/* observe_instance_count + per-instance bindings
 * (transcript.rs:27-43; verifier/mod.rs:144, 269-274). */
int dnac_batch_observe_count_and_bindings(dnac_duplex_t            *ch,
                                          const dnac_batch_binding_t *bindings,
                                          uint32_t                   num_instances);

/* observe_main (transcript.rs:46-54): main commit, then every instance's
 * public values in order (each one base observe). */
int dnac_batch_observe_main(dnac_duplex_t          *ch,
                            const gold_fp_t         main_commit[4],
                            const gold_fp_t *const *public_values,
                            const uint32_t         *num_publics,
                            uint32_t                num_instances);

/* observe_preprocessed (transcript.rs:57-68): every width as usize, then the
 * optional global preprocessed commit. */
int dnac_batch_observe_preprocessed(dnac_duplex_t   *ch,
                                    const uint32_t  *preprocessed_widths,
                                    uint32_t         num_instances,
                                    const gold_fp_t *preprocessed_commit /* or NULL */);

/* sample_perm_challenges (transcript.rs:100-171).
 *
 * ⚠ SQUEEZE COUNT CHANGED at v0.6.2 (S2'-c): this samples exactly TWO fp2 —
 * one (alpha, beta) pair for the WHOLE batch — where it used to sample one
 * pair per local lookup and per first-occurrence bus name. Per-bus separation
 * now comes from the derivation prefix[i] = alpha + (i+1)·beta^W
 * (dnac_logup_bus_derive_challenges), not from extra draws. A batch with NO
 * lookups anywhere squeezes NOTHING (transcript.rs:106-110).
 * This is transcript-visible: every challenge sampled afterwards moves.
 *
 * @param max_message_width  W, the widest payload tuple in the batch (>= 1) —
 *   fixes where the bus offset sits. Not derivable from the bus views.
 * out_challenges[i] must hold 2·(num_locals+num_globals) of instance i; pass
 * NULL for instances with no lookups. */
int dnac_batch_sample_perm_challenges(dnac_duplex_t              *ch,
                                      const dnac_logup_bus_view_t *views,
                                      uint32_t                    num_instances,
                                      uint32_t                    max_message_width,
                                      gold_fp2_t *const          *out_challenges);

/* observe_perm_and_sample_alpha (transcript.rs:175-188): iff the permutation
 * commit is present, observe it and then each AIR's committed lookup TERMINAL
 * (2 coefficients each); then sample constraint-alpha.
 * ⚠ S2'-c: this observed every CUMULATIVE SUM before v0.6.2. An instance with
 * no lookups has no terminal and contributes nothing (upstream `flatten()`).
 * With no permutation commit nothing is observed, alpha is still sampled. */
int dnac_batch_observe_perm_and_sample_alpha(
    dnac_duplex_t               *ch,
    const gold_fp_t             *permutation_commit /* 4 lanes or NULL */,
    const dnac_logup_bus_view_t *views,
    const gold_fp2_t            *terminals,      /* [i] — one per AIR       */
    uint32_t                     num_instances,
    gold_fp2_t                  *out_alpha);

/* sample_zeta (transcript.rs:132-134). */
gold_fp2_t dnac_batch_sample_zeta(dnac_duplex_t *ch);

/* ============================================================================
 * Composed priming run — the full N1 order with fail-close consistency
 * checks (verifier/mod.rs:74-84 random-vs-ZK, :96-104 degree arithmetic,
 * :282-286 permutation-commit-vs-lookups)
 * ========================================================================== */
typedef struct {
    uint32_t                     num_instances;
    int                          is_zk;
    const dnac_batch_binding_t  *bindings;            /* [n]                */
    const gold_fp_t *const     *public_values;        /* [n][num_publics[i]]*/
    const uint32_t              *num_publics;         /* [n]                */
    const uint32_t              *preprocessed_widths; /* [n]                */
    const dnac_logup_bus_view_t *views;               /* [n]                */
    uint32_t                     max_message_width;   /* W >= 1 (S2'-c): the
                                                         widest payload tuple
                                                         in the batch; fixes
                                                         the bus offset beta^W
                                                         (challenges.rs:52-57).
                                                         Ignored when no
                                                         instance has lookups. */
    const gold_fp2_t            *terminals;           /* [n] — ONE per AIR
                                                         (S2'-c); entry i is
                                                         read only when
                                                         instance i has >= 1
                                                         lookup             */
    const gold_fp_t             *main_commit;         /* 4 lanes            */
    const gold_fp_t             *preprocessed_commit; /* 4 lanes or NULL    */
    const gold_fp_t             *permutation_commit;  /* 4 lanes or NULL    */
    const gold_fp_t             *quotient_commit;     /* 4 lanes            */
    const gold_fp_t             *random_commit;       /* 4 lanes or NULL    */
} dnac_batch_priming_input_t;

/* Runs the full verifier-order priming on a caller-initialized duplex
 * (production: dnac_duplex_init_default). Outputs the per-instance flat
 * (α,β) arrays (out_perm_challenges[i], 2·num_lookups_i elements; NULL
 * allowed for lookup-free instances), constraint-alpha, and ζ. */
int dnac_batch_priming_run(dnac_duplex_t                    *ch,
                           const dnac_batch_priming_input_t *in,
                           gold_fp2_t *const                *out_perm_challenges,
                           gold_fp2_t                       *out_alpha,
                           gold_fp2_t                       *out_zeta);

/* ============================================================================
 * BatchProof shape check (in-memory; mirrors the verifier's structural
 * validation — each check cites its verifier/mod.rs line)
 * ========================================================================== */
typedef struct {
    uint32_t trace_local_len;        /* == width (:162-169)                 */
    uint32_t trace_next_len;         /* width iff main_next_used else 0
                                        (:170-180)                          */
    uint32_t preprocessed_local_len; /* prep width or 0 (:211-231)          */
    uint32_t preprocessed_next_len;
    uint32_t num_quotient_chunks;    /* == binding (:183-191)               */
    uint32_t quotient_chunk_dim;     /* == 2 = Challenge DIMENSION (:193-199)*/
    uint32_t permutation_local_len;  /* == aux_width·2; aux_width (S2'-c,
                                        v0.6.2 verifier/mod.rs) is
                                        num_lookups + 1 when the AIR declares
                                        any lookup, else 0 — col 0 is the ONE
                                        shared accumulator and lookup c owns
                                        fraction column c+1. Was max(column)+1
                                        over the lookups at 82cfad73.        */
    uint32_t permutation_next_len;   /* == permutation_local (:482-484)     */
    uint32_t random_len;             /* 2 iff is_zk else 0 (:74-84,:201-209)*/
    /* LookupTerminal presence (S2'-c, v0.6.2): must equal (num_lookups > 0)
     * — upstream's TerminalPresenceMismatch.
     *
     * The v3-era (name, aux_column) metadata list is GONE. v0.6.2 deleted
     * that entire cross-check from the verifier: bus names and aux columns
     * stopped being proof data, so there is nothing left to compare against.
     * Only the Option discriminant is still checked. */
    int                   has_terminal;
    int                   main_next_used;
    int                   prep_next_used;
} dnac_batch_instance_shape_t;

int dnac_batch_proof_shape_check(const dnac_batch_instance_shape_t *shapes,
                                 const dnac_batch_binding_t        *bindings,
                                 const dnac_logup_bus_view_t       *views,
                                 const uint32_t                    *preprocessed_widths,
                                 uint32_t                           num_instances,
                                 int                                is_zk,
                                 int                                has_permutation_commit,
                                 int                                has_random_commit);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_BATCH_PRIMING_H */
