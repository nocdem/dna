/**
 * @file batch_verify.c
 * @brief Batched STARK verify — Plonky3 batch-stark `verify_batch` mirror
 *        (P2L-d d2). See batch_verify.h for the pipeline map; every step
 *        below cites its verifier/mod.rs (or data.rs / folder.rs /
 *        two_adic_pcs.rs / hiding_pcs.rs) lines at 82cfad73.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include "batch_verify.h"

#include <stdlib.h>
#include <string.h>

#include "transcript.h"

/* Fixed caps (fail-close; generous for the K=4 recursion batches). */
#define BV_MAX_INSTANCES ((uint32_t)32)
#define BV_MAX_TUPLES    ((uint32_t)16)
#define BV_MAX_TUPLE_W   ((uint32_t)16)

/* ζ_next(i) = ζ · two_adic_generator(base_db) — the BASE trace domain's
 * next_point (verifier/mod.rs:306-310, :341-343; the stark_priming.c:86-94
 * precedent). */
static gold_fp2_t bv_zeta_next(gold_fp2_t zeta, uint32_t base_db)
{
    return gold_fp2_mul(
        zeta, gold_fp2_from_base(gold_fp_two_adic_generator((unsigned)base_db)));
}

/* Recompose one EF element from its two base-flattened opened columns:
 * chunk = [v0, v1] (each an EF evaluation) → v0 + v1·X
 * (from_ext_basis_coefficients over the [1, X] basis, verifier/mod.rs:543-559;
 * same form as the quotient-chunk recompose, uni-stark verifier.rs:87-95). */
static gold_fp2_t bv_recompose_ef(gold_fp2_t v0, gold_fp2_t v1)
{
    const gold_fp2_t x = gold_fp2_new(gold_fp_zero(), gold_fp_one());
    return gold_fp2_add(v0, gold_fp2_mul(v1, x));
}

/* One assembled point slot: where its merged evals live in the arena. */
typedef struct {
    dnac_fri_opening_point_t *pt;      /* target point                     */
    const gold_fp2_t         *base;    /* unmerged evals                   */
    uint32_t                  base_len;
} bv_point_fill_t;

/* Aux width (v0.6.2 batch-stark/src/verifier/mod.rs:512-516):
 *
 *     num_lookups + 1   when the AIR declares any lookup
 *     0                 otherwise
 *
 * Column 0 is the ONE shared accumulator and lookup slot c owns fraction
 * column c + 1 (lookup/src/logup.rs:226-229, 381-382); zero lookups means no
 * permutation trace at all (logup.rs:374-377).
 *
 * At 82cfad73 this was `max(lookup.column) + 1` (old verifier/mod.rs:524-529),
 * i.e. num_lookups with NO accumulator column — off by exactly the column that
 * now carries the accumulator. */
static uint32_t bv_aux_width(const dnac_batch_vinstance_t *inst)
{
    if (inst->num_lookups == 0) return 0;
    return inst->num_lookups + 1u;
}

dnac_batch_verify_status_t dnac_batch_verify(
    const dnac_batch_vinstance_t     *insts,
    const dnac_batch_vopened_t       *opened,
    uint32_t                          num_instances,
    int                               is_zk,
    const dnac_batch_vcommits_t      *commits,
    const uint32_t                   *prep_matrix_to_instance,
    uint32_t                          num_prep_matrices,
    const dnac_fri_params_t          *fri_params,
    uint32_t                          num_random_codewords,
    size_t                            salt_elems,
    const dnac_fri_proof_t           *fri_proof,
    const dnac_batch_rand_openings_t *rand_openings,
    dnac_batch_verify_out_t          *out)
{
    if (!insts || !opened || !commits || !fri_params || !fri_proof) {
        return DNAC_BV_ERR_NULL;
    }
    if (num_instances == 0 || num_instances > BV_MAX_INSTANCES) {
        return DNAC_BV_ERR_PARAM;
    }
    if (is_zk != 0 && is_zk != 1) return DNAC_BV_ERR_PARAM;
    if (!commits->main_commit || !commits->quotient_commit) {
        return DNAC_BV_ERR_NULL;
    }
    /* Hiding randomization exists only in the is_zk configuration: a non-ZK
     * caller that names a nonzero count has mis-described its own instance
     * (fail-close rather than silently ignore it). */
    if (is_zk == 0 && num_random_codewords != 0) return DNAC_BV_ERR_PARAM;
    const uint32_t n = num_instances;

    /* ---- 0. SALT_ELEMS pin (G-SEC-P1-6) ----------------------------------
     * Every input-batch opening AND every commit-phase step must declare
     * exactly the caller's salt count. The salted leaf is row ‖ salts hashed
     * as one flat stream (hiding_mmcs.rs:169-170 assembled by
     * fri_verifier.c), so the salt count is part of the preimage LENGTH and
     * must be protocol-fixed, not read from the proof.
     * A mismatch would usually fail the FRI verify anyway (the committed leaf
     * hash differs), but "usually" is not a pin; this fail-closes it up front.
     * This check MOVED here from shielded_verify.c in S2'-d — it used to guard
     * only the shielded entry, leaving every other consumer of the same
     * decode -> dnac_batch_verify pair (P2 recursion) with no salt pin at
     * all. See batch_verify.h for the full rationale. */
    for (size_t q = 0; q < fri_proof->num_query_proofs; q++) {
        const dnac_fri_query_proof_t *qp = &fri_proof->query_proofs[q];
        for (size_t b = 0; b < qp->num_input_batches; b++) {
            if (qp->input_proof[b].salt_elems != salt_elems) {
                return DNAC_BV_ERR_SHAPE;
            }
        }
        for (size_t r = 0; r < qp->num_commit_phase_openings; r++) {
            if (qp->commit_phase_openings[r].salt_elems != salt_elems) {
                return DNAC_BV_ERR_SHAPE;
            }
        }
    }

    /* ---- 1. random-vs-ZK (:74-84) + rand-openings presence ---- */
    if ((commits->random_commit != NULL) != (is_zk == 1)) {
        return DNAC_BV_ERR_RANDOMIZATION;
    }
    for (uint32_t i = 0; i < n; i++) {
        if ((opened[i].random != NULL) != (is_zk == 1)) {
            return DNAC_BV_ERR_RANDOMIZATION;
        }
        /* random opened len == DIMENSION == 2 iff ZK (:201-209). */
        if (is_zk == 1 && opened[i].random_len != 2) {
            return DNAC_BV_ERR_RANDOMIZATION;
        }
    }
    if ((rand_openings != NULL) != (is_zk == 1)) return DNAC_BV_ERR_PARAM;

    /* Permutation commit present iff any instance has lookups (:282-286). */
    int any_lookups = 0;
    for (uint32_t i = 0; i < n; i++) {
        if (insts[i].num_lookups > 0) any_lookups = 1;
    }
    if ((commits->permutation_commit != NULL) != (any_lookups != 0)) {
        return DNAC_BV_ERR_SHAPE;
    }
    /* Preprocessed commit present iff prep matrices declared (:410-471). */
    if ((commits->preprocessed_commit != NULL) != (num_prep_matrices > 0)) {
        return DNAC_BV_ERR_SHAPE;
    }
    if (num_prep_matrices > 0 && !prep_matrix_to_instance) {
        return DNAC_BV_ERR_NULL;
    }

    /* ---- 2. per-instance derived values + shape validation ---- */
    dnac_batch_binding_t        bindings[BV_MAX_INSTANCES];
    dnac_batch_instance_shape_t shapes[BV_MAX_INSTANCES];
    dnac_logup_bus_view_t       views[BV_MAX_INSTANCES];
    uint32_t                    pre_widths[BV_MAX_INSTANCES];
    const gold_fp_t            *pubs[BV_MAX_INSTANCES];
    uint32_t                    npubs[BV_MAX_INSTANCES];
    gold_fp2_t                  terminals[BV_MAX_INSTANCES];
    const dnac_logup_lookup_t  *lookup_ptrs[BV_MAX_INSTANCES];
    uint32_t                    lookup_counts[BV_MAX_INSTANCES];

    for (uint32_t i = 0; i < n; i++) {
        const dnac_batch_vinstance_t *di = &insts[i];
        const dnac_batch_vopened_t   *oi = &opened[i];
        /* validate_degree_bits (:96-104): base = ext − is_zk, no underflow. */
        if (di->degree_bits < (uint32_t)is_zk || di->degree_bits >= 64) {
            return DNAC_BV_ERR_SHAPE;
        }
        if (di->air.main_width == 0 ||
            di->air.main_width > DNAC_STARK_MAX_MAIN_WIDTH) {
            return DNAC_BV_ERR_SHAPE;
        }
        /* num_qc = 1 << (log_num_qc + is_zk) (checked_log_size_sum, :132-140). */
        if (di->log_num_qc + (uint32_t)is_zk >= 32) return DNAC_BV_ERR_SHAPE;
        const uint32_t exp_qc = 1u << (di->log_num_qc + (uint32_t)is_zk);
        /* prep declaration consistency: width > 0 iff instance appears in
         * matrix_to_instance (:410-445). */
        int in_map = 0;
        for (uint32_t m = 0; m < num_prep_matrices; m++) {
            if (prep_matrix_to_instance[m] == i) in_map = 1;
        }
        if ((di->preprocessed_width > 0) != (in_map != 0)) {
            return DNAC_BV_ERR_SHAPE;
        }
        /* view vs lookups consistency (locals first, types.rs:59-89). */
        if (di->view.num_locals + di->view.num_globals != di->num_lookups) {
            return DNAC_BV_ERR_PARAM;
        }
        /* TerminalPresenceMismatch (v0.6.2 verifier/mod.rs): one terminal iff
         * the AIR declares any lookup, none otherwise. This is the whole of
         * what survived the old global_lookup_data metadata cross-check —
         * bus names and aux columns are no longer proof data. */
        if ((oi->has_terminal != 0) != (di->num_lookups > 0)) {
            return DNAC_BV_ERR_SHAPE;
        }

        bindings[i].log_ext_degree = di->degree_bits;
        bindings[i].log_degree = di->degree_bits - (uint32_t)is_zk;
        bindings[i].width = (uint32_t)di->air.main_width;
        bindings[i].num_quotient_chunks = exp_qc;

        shapes[i].trace_local_len = oi->trace_local_len;
        shapes[i].trace_next_len = oi->trace_next_len;
        shapes[i].preprocessed_local_len = oi->preprocessed_local_len;
        shapes[i].preprocessed_next_len = oi->preprocessed_next_len;
        shapes[i].num_quotient_chunks = oi->num_quotient_chunks;
        shapes[i].quotient_chunk_dim = 2; /* stride-2 API; wire dim check = d4 */
        shapes[i].permutation_local_len = oi->permutation_len;
        shapes[i].permutation_next_len = oi->permutation_len;
        shapes[i].random_len = oi->random_len;
        shapes[i].has_terminal = oi->has_terminal;
        shapes[i].main_next_used = di->air.main_next;
        shapes[i].prep_next_used = di->prep_next;

        views[i] = di->view;
        pre_widths[i] = di->preprocessed_width;
        pubs[i] = di->public_values;
        npubs[i] = di->num_publics;
        /* Absent terminal contributes ZERO to the cross-AIR sum — upstream's
         * `lookup_terminals.iter().flatten()` skips a None. Forced here rather
         * than trusted from the caller: a struct built in memory (not via the
         * decoder, which zeroes it) could carry a stale value behind
         * has_terminal == 0 and poison the flat sum. */
        terminals[i] = oi->has_terminal ? oi->terminal : gold_fp2_zero();
        lookup_ptrs[i] = di->lookups;
        lookup_counts[i] = di->num_lookups;

        /* pointer/len coherence (fail-close before any use). */
        if (!oi->trace_local ||
            (oi->trace_next_len > 0 && !oi->trace_next) ||
            (oi->preprocessed_local_len > 0 && !oi->preprocessed_local) ||
            (oi->preprocessed_next_len > 0 && !oi->preprocessed_next) ||
            (oi->num_quotient_chunks > 0 && !oi->quotient_chunks) ||
            (oi->permutation_len > 0 &&
             (!oi->permutation_local || !oi->permutation_next)) ||
            (di->num_lookups > 0 && !di->lookups)) {
            return DNAC_BV_ERR_NULL;
        }
        /* permutation opened lens == aux_width · DIMENSION
         * (v0.6.2 verifier/mod.rs:518-526; the ":524-541" this used to cite is
         * the superseded 82cfad73 location). */
        if (oi->permutation_len != bv_aux_width(di) * 2u) {
            return DNAC_BV_ERR_SHAPE;
        }
    }

    /* The structural gates the reference runs at :146-267. */
    if (dnac_batch_proof_shape_check(shapes, bindings, views, pre_widths, n,
                                     is_zk, any_lookups,
                                     is_zk) != DNAC_BATCH_OK) {
        return DNAC_BV_ERR_SHAPE;
    }

    /* ---- 2b. LogUp multiplicity height bound (S2'-d2) --------------------
     * Sum_i w_i·h_i < p, where w_i is the AIR's total count_weight and h_i its
     * BASE trace height. Upstream v0.6.2 runs this inside verify_batch
     * (verifier/mod.rs:146-149, "Soundness: bound LogUp multiplicities so none
     * wraps modulo p"), immediately before observe_instance_count — i.e. before
     * ANY transcript work, which is where it sits here too.
     *
     * WHY IT MATTERS (lookup/src/types.rs:222-232): a provided entry's
     * multiplicity equals how many queries hit it, and counted honestly that
     * never exceeds Sum w_i·h_i. Holding the sum below p is what rules out a
     * multiplicity WRAPPING modulo p — a wrap would let a prover forge
     * multiplicities and break the lookup argument.
     *
     * DNAC has had the checker since P2L-b but called it ONLY from tests, with
     * logup_bus.h calling it an offline "parameter-freeze" precondition. That
     * was a deviation: upstream enforces it on the verify path, so a config that
     * never went through a freeze step was unprotected.
     *
     * Heights are the BASE trace heights (upstream maps base_degree_bits ->
     * 1 << b); bindings[i].log_degree is exactly base = ext - is_zk.
     *
     * Only GLOBAL weights are summed, which matches upstream summing over ALL
     * lookups: intra-AIR lookups always carry count_weight 0 (types.rs:45-51),
     * and logup_bus.c enforces that rather than assuming it. */
    {
        uint32_t heights[BV_MAX_INSTANCES];
        for (uint32_t i = 0; i < n; i++) {
            if (bindings[i].log_degree >= 32) return DNAC_BV_ERR_SHAPE;
            heights[i] = 1u << bindings[i].log_degree;
        }
        const int hb = dnac_logup_bus_check_height_bound(views, heights, n);
        if (hb == DNAC_LOGUP_ERR_HEIGHT_BOUND) {
            return DNAC_BV_ERR_HEIGHT_BOUND;
        }
        if (hb != DNAC_LOGUP_OK) {
            /* Missing global_count_weights on an instance that declares
             * globals: the caller cannot state its lookups without stating
             * their weights, so this fail-closes rather than skipping the
             * bound. See logup_bus.h — the field is REQUIRED on this path. */
            return DNAC_BV_ERR_NULL;
        }
    }

    /* ---- 3. full batched priming (:143-300) ---- */
    uint32_t total_ch = 0;
    for (uint32_t i = 0; i < n; i++) total_ch += 2u * insts[i].num_lookups;
    gold_fp2_t *ch_flat = NULL;
    gold_fp2_t *ch_ptrs_storage[BV_MAX_INSTANCES];
    gold_fp2_t **ch_ptrs = ch_ptrs_storage;
    if (total_ch > 0) {
        ch_flat = (gold_fp2_t *)calloc(total_ch, sizeof(gold_fp2_t));
        if (!ch_flat) return DNAC_BV_ERR_OOM;
    }
    {
        uint32_t off = 0;
        for (uint32_t i = 0; i < n; i++) {
            ch_ptrs[i] = insts[i].num_lookups > 0 ? ch_flat + off : NULL;
            off += 2u * insts[i].num_lookups;
        }
    }

    dnac_duplex_t duplex;
    dnac_duplex_init_default(&duplex);
    gold_fp2_t alpha, zeta;
    {
        dnac_batch_priming_input_t pin;
        memset(&pin, 0, sizeof(pin));
        pin.num_instances = n;
        pin.is_zk = is_zk;
        pin.bindings = bindings;
        pin.public_values = pubs;
        pin.num_publics = npubs;
        pin.preprocessed_widths = pre_widths;
        pin.views = views;
        /* W = β's bus-offset power. Derived from the LOOKUPS, not the bus view
         * (which carries no tuple widths), through the same shared helper the
         * prover uses — the two sides must agree or the transcript forks. */
        pin.max_message_width = dnac_logup_bus_max_message_width(
            lookup_ptrs, lookup_counts, n);
        pin.terminals = terminals;
        pin.main_commit = commits->main_commit;
        pin.preprocessed_commit = commits->preprocessed_commit;
        pin.permutation_commit = commits->permutation_commit;
        pin.quotient_commit = commits->quotient_commit;
        pin.random_commit = commits->random_commit;
        if (dnac_batch_priming_run(&duplex, &pin, ch_ptrs, &alpha, &zeta) !=
            DNAC_BATCH_OK) {
            free(ch_flat);
            return DNAC_BV_ERR_SHAPE;
        }
    }
    if (out) {
        out->alpha = alpha;
        out->zeta = zeta;
        out->fri_status = DNAC_FRI_OK;
        out->bad_instance = 0;
        out->terminal_sum = gold_fp2_zero();
    }

    /* ---- 4. opening-round assembly (N2 order, :302-499) ----
     * Every matrix opens on a domain with log_size = degree_bits[i]:
     * random/main/permutation on the EXT trace domain (:316-356, :474-499);
     * quotient chunks on the randomized chunk domains, size
     * ((2^(ext_db+lq)) / 2^(lq+is_zk)) << is_zk = 2^ext_db (:360-385);
     * preprocessed on 2^meta_db = 2^ext_db (:447). */
    gold_fp2_t zeta_nexts[BV_MAX_INSTANCES];
    for (uint32_t i = 0; i < n; i++) {
        zeta_nexts[i] = bv_zeta_next(zeta, bindings[i].log_degree);
    }

    uint32_t num_perm_mats = 0;
    for (uint32_t i = 0; i < n; i++) {
        if (insts[i].num_lookups > 0) num_perm_mats++;
    }
    uint32_t total_qc = 0;
    for (uint32_t i = 0; i < n; i++) total_qc += opened[i].num_quotient_chunks;

    const uint32_t num_rounds = (is_zk ? 1u : 0u) + 1u /* main */ + 1u /* qc */ +
                                (num_prep_matrices > 0 ? 1u : 0u) +
                                (any_lookups ? 1u : 0u);
    const uint32_t total_mats = (is_zk ? n : 0u) + n + total_qc +
                                num_prep_matrices + num_perm_mats;

    /* Count points + merged eval lanes. */
    uint32_t total_points = 0;
    {
        if (is_zk) total_points += n;                       /* random @ ζ    */
        for (uint32_t i = 0; i < n; i++) {                  /* main          */
            total_points += insts[i].air.main_next ? 2u : 1u;
        }
        total_points += total_qc;                           /* quotient @ ζ  */
        for (uint32_t m = 0; m < num_prep_matrices; m++) {  /* preprocessed  */
            uint32_t ii = prep_matrix_to_instance[m];
            if (ii >= n) { free(ch_flat); return DNAC_BV_ERR_SHAPE; }
            total_points += insts[ii].prep_next ? 2u : 1u;
        }
        total_points += num_perm_mats * 2u;                 /* permutation   */
    }
    if (is_zk && rand_openings->num_entries != total_points) {
        /* zip_eq structure mirror (hiding_pcs.rs:386-395). */
        free(ch_flat);
        return DNAC_BV_ERR_SHAPE;
    }

    dnac_fri_commitment_with_opening_points_t coms[5];
    dnac_fri_matrix_openings_t *mats = (dnac_fri_matrix_openings_t *)calloc(
        total_mats, sizeof(dnac_fri_matrix_openings_t));
    dnac_fri_opening_point_t *pts = (dnac_fri_opening_point_t *)calloc(
        total_points, sizeof(dnac_fri_opening_point_t));
    if (!mats || !pts) {
        free(mats); free(pts); free(ch_flat);
        return DNAC_BV_ERR_OOM;
    }

    /* Merged-evals arena: base lens + rand tails.
     *
     * ⚠ RAND-TAIL PIN (S2'-d, 2026-07-27). This pass is also where every
     * `rand_openings->lens[k]` is CHECKED, because it is the one walk that
     * visits every entry exactly once, in assembly order, knowing which round
     * each belongs to. Until now only two facts were enforced —
     * `num_entries == total_points` above, and `== 0` on preprocessed entries
     * — so on every other point the tail length was wire data compared against
     * nothing, and `num_claimed_evals = BASE_LEN + tail` handed the prover the
     * row boundaries of a flat, separator-free MMCS leaf. See batch_verify.h
     * for the repartition attack this closes and for the note that upstream
     * does NOT make this check.
     *
     *   non-preprocessed point -> tail MUST equal num_random_codewords
     *   preprocessed point     -> tail MUST be 0 (hiding_pcs.rs:343-348,
     *                             split 0 at PREPROCESSED_TRACE_IDX)
     *
     * BV_TAIL yields the tail of entry `re` and advances, or jumps to
     * rand_shape on any deviation. Non-ZK never consumes an entry. */
    size_t eval_lanes = 0;
    {
        uint32_t re = 0; /* rand entry cursor (assembly point order) */
        uint32_t tl;     /* tail of the entry BV_TAIL just consumed */
        /* helper macro-free double pass: first count, then fill below. */
#define BV_TAIL(EXPECT)                                                       \
        do {                                                                  \
            tl = 0u;                                                          \
            if (is_zk) {                                                      \
                if (rand_openings->lens[re] != (EXPECT)) goto rand_shape;     \
                tl = rand_openings->lens[re++];                               \
            }                                                                 \
        } while (0)

        if (is_zk) {
            for (uint32_t i = 0; i < n; i++) {
                BV_TAIL(num_random_codewords);
                eval_lanes += opened[i].random_len + tl;
            }
        }
        for (uint32_t i = 0; i < n; i++) {
            BV_TAIL(num_random_codewords);
            eval_lanes += opened[i].trace_local_len + tl;
            if (insts[i].air.main_next) {
                BV_TAIL(num_random_codewords);
                eval_lanes += opened[i].trace_next_len + tl;
            }
        }
        for (uint32_t i = 0; i < n; i++) {
            for (uint32_t c = 0; c < opened[i].num_quotient_chunks; c++) {
                BV_TAIL(num_random_codewords);
                eval_lanes += 2u + tl;
            }
        }
        for (uint32_t m = 0; m < num_prep_matrices; m++) {
            uint32_t ii = prep_matrix_to_instance[m];
            BV_TAIL(0u);
            eval_lanes += opened[ii].preprocessed_local_len;
            if (insts[ii].prep_next) {
                BV_TAIL(0u);
                eval_lanes += opened[ii].preprocessed_next_len;
            }
        }
        for (uint32_t i = 0; i < n; i++) {
            if (insts[i].num_lookups == 0) continue;
            BV_TAIL(num_random_codewords);
            eval_lanes += opened[i].permutation_len + tl;
            BV_TAIL(num_random_codewords);
            eval_lanes += opened[i].permutation_len + tl;
        }
#undef BV_TAIL
        if (0) {
rand_shape:
            free(mats); free(pts); free(ch_flat);
            return DNAC_BV_ERR_SHAPE;
        }
    }
    gold_fp2_t *evals = (gold_fp2_t *)calloc(
        eval_lanes ? eval_lanes : 1, sizeof(gold_fp2_t));
    if (!evals) {
        free(mats); free(pts); free(ch_flat);
        return DNAC_BV_ERR_OOM;
    }

    /* Fill pass. */
    {
        uint32_t mi = 0, pi = 0, re = 0;
        size_t ei = 0;
        uint32_t ri = 0;

        /* one point: copy base evals + optional rand tail into the arena. */
#define BV_EMIT_POINT(POINT_VAL, BASE, BASE_LEN)                              \
        do {                                                                  \
            const uint32_t rl =                                               \
                is_zk ? rand_openings->lens[re] : 0u;                         \
            gold_fp2_t *dst = evals + ei;                                     \
            for (uint32_t k = 0; k < (BASE_LEN); k++) dst[k] = (BASE)[k];     \
            if (rl > 0) {                                                     \
                const gold_fp2_t *rv = rand_openings->vals[re];               \
                for (uint32_t k = 0; k < rl; k++) dst[(BASE_LEN) + k] = rv[k];\
            }                                                                 \
            if (is_zk) re++;                                                  \
            pts[pi].point = (POINT_VAL);                                      \
            pts[pi].claimed_evals = dst;                                      \
            pts[pi].num_claimed_evals = (BASE_LEN) + rl;                      \
            ei += (BASE_LEN) + rl;                                            \
            pi++;                                                             \
        } while (0)

#define BV_MAT(NPTS, LOGSZ)                                                   \
        do {                                                                  \
            mats[mi].domain.shift = gold_fp_one();                            \
            mats[mi].domain.shift_inverse = gold_fp_one();                    \
            mats[mi].domain.log_size = (LOGSZ);                               \
            mats[mi].points = &pts[pi];                                       \
            mats[mi].num_points = (NPTS);                                     \
            mi++;                                                             \
        } while (0)

        if (is_zk) { /* Round 0: random @ ζ (:316-329) */
            dnac_fri_matrix_openings_t *first = &mats[mi];
            for (uint32_t i = 0; i < n; i++) {
                BV_MAT(1u, (size_t)bindings[i].log_ext_degree);
                BV_EMIT_POINT(zeta, opened[i].random, opened[i].random_len);
            }
            for (uint32_t k = 0; k < 4; k++) {
                coms[ri].commitment.lanes[k] =
                    gold_fp_to_u64(commits->random_commit[k]);
            }
            coms[ri].matrices = first;
            coms[ri].num_matrices = n;
            ri++;
        }
        { /* Round 1: main (:331-356) */
            dnac_fri_matrix_openings_t *first = &mats[mi];
            for (uint32_t i = 0; i < n; i++) {
                const uint32_t np = insts[i].air.main_next ? 2u : 1u;
                BV_MAT(np, (size_t)bindings[i].log_ext_degree);
                BV_EMIT_POINT(zeta, opened[i].trace_local,
                              opened[i].trace_local_len);
                if (np == 2u) {
                    BV_EMIT_POINT(zeta_nexts[i], opened[i].trace_next,
                                  opened[i].trace_next_len);
                }
            }
            for (uint32_t k = 0; k < 4; k++) {
                coms[ri].commitment.lanes[k] =
                    gold_fp_to_u64(commits->main_commit[k]);
            }
            coms[ri].matrices = first;
            coms[ri].num_matrices = n;
            ri++;
        }
        { /* Round 2: quotient chunks, each @ ζ (:358-406) */
            dnac_fri_matrix_openings_t *first = &mats[mi];
            for (uint32_t i = 0; i < n; i++) {
                for (uint32_t c = 0; c < opened[i].num_quotient_chunks; c++) {
                    BV_MAT(1u, (size_t)bindings[i].log_ext_degree);
                    BV_EMIT_POINT(zeta, opened[i].quotient_chunks + (size_t)c * 2u,
                                  2u);
                }
            }
            for (uint32_t k = 0; k < 4; k++) {
                coms[ri].commitment.lanes[k] =
                    gold_fp_to_u64(commits->quotient_commit[k]);
            }
            coms[ri].matrices = first;
            coms[ri].num_matrices = total_qc;
            ri++;
        }
        if (num_prep_matrices > 0) { /* Round 3: preprocessed (:410-471) */
            dnac_fri_matrix_openings_t *first = &mats[mi];
            for (uint32_t m = 0; m < num_prep_matrices; m++) {
                const uint32_t ii = prep_matrix_to_instance[m];
                const uint32_t np = insts[ii].prep_next ? 2u : 1u;
                BV_MAT(np, (size_t)bindings[ii].log_ext_degree);
                BV_EMIT_POINT(zeta, opened[ii].preprocessed_local,
                              opened[ii].preprocessed_local_len);
                if (np == 2u) {
                    BV_EMIT_POINT(zeta_nexts[ii], opened[ii].preprocessed_next,
                                  opened[ii].preprocessed_next_len);
                }
            }
            for (uint32_t k = 0; k < 4; k++) {
                coms[ri].commitment.lanes[k] =
                    gold_fp_to_u64(commits->preprocessed_commit[k]);
            }
            coms[ri].matrices = first;
            coms[ri].num_matrices = num_prep_matrices;
            ri++;
        }
        if (any_lookups) { /* Round 4: permutation @ ζ AND g·ζ (:474-499) */
            dnac_fri_matrix_openings_t *first = &mats[mi];
            for (uint32_t i = 0; i < n; i++) {
                if (insts[i].num_lookups == 0) continue;
                BV_MAT(2u, (size_t)bindings[i].log_ext_degree);
                BV_EMIT_POINT(zeta, opened[i].permutation_local,
                              opened[i].permutation_len);
                BV_EMIT_POINT(zeta_nexts[i], opened[i].permutation_next,
                              opened[i].permutation_len);
            }
            for (uint32_t k = 0; k < 4; k++) {
                coms[ri].commitment.lanes[k] =
                    gold_fp_to_u64(commits->permutation_commit[k]);
            }
            coms[ri].matrices = first;
            coms[ri].num_matrices = num_perm_mats;
            ri++;
        }
#undef BV_EMIT_POINT
#undef BV_MAT
        if (ri != num_rounds || mi != total_mats || pi != total_points ||
            ei != eval_lanes) {
            free(evals); free(mats); free(pts); free(ch_flat);
            return DNAC_BV_ERR_SHAPE;
        }
    }

    /* ---- 5+6. PCS observe (two_adic_pcs.rs:687-693) + FRI verify ---- */
    {
        dnac_transcript_t *t = dnac_transcript_init_from_duplex(&duplex);
        if (!t) {
            free(evals); free(mats); free(pts); free(ch_flat);
            return DNAC_BV_ERR_OOM;
        }
        for (uint32_t r = 0; r < num_rounds; r++) {
            for (size_t m = 0; m < coms[r].num_matrices; m++) {
                const dnac_fri_matrix_openings_t *mo = &coms[r].matrices[m];
                for (size_t p = 0; p < mo->num_points; p++) {
                    for (size_t k = 0; k < mo->points[p].num_claimed_evals; k++) {
                        dnac_transcript_observe_fp2(
                            t, mo->points[p].claimed_evals[k]);
                    }
                }
            }
        }
        dnac_fri_status_t fs =
            dnac_fri_verify(fri_params, fri_proof, t, coms, num_rounds);
        dnac_transcript_free(t);
        if (fs != DNAC_FRI_OK) {
            if (out) out->fri_status = fs;
            free(evals); free(mats); free(pts); free(ch_flat);
            return DNAC_BV_ERR_FRI;
        }
    }
    free(evals); free(mats); free(pts);

    /* ---- 7. per-instance constraint check at ζ (:507-621) ---- */
    for (uint32_t i = 0; i < n; i++) {
        const dnac_batch_vinstance_t *di = &insts[i];
        const dnac_batch_vopened_t   *oi = &opened[i];

        gold_fp2_t quotient;
        if (dnac_stark_recompose_quotient_nchunk(
                zeta, di->degree_bits, di->log_num_qc, (size_t)is_zk,
                oi->quotient_chunks, oi->num_quotient_chunks, 2,
                &quotient) != DNAC_STARK_VERIFY_OK) {
            free(ch_flat);
            return DNAC_BV_ERR_SHAPE;
        }

        const dnac_stark_selectors_t sels =
            dnac_stark_selectors_at_point(zeta, bindings[i].log_degree);

        /* OodPointInDomain (S2'-d2) — upstream v0.6.2 puts this at the TOP of
         * verify_constraints_with_lookups (batch-stark/src/verifier/data.rs),
         * i.e. before any selector is consumed, and so does this. See
         * DNAC_BV_ERR_OOD_POINT_IN_DOMAIN in batch_verify.h for why the C form
         * is a fail-OPEN rather than upstream's panic. */
        if (dnac_stark_zeta_in_domain(&sels)) {
            if (out) out->bad_instance = i;
            free(ch_flat);
            return DNAC_BV_ERR_OOD_POINT_IN_DOMAIN;
        }

        /* zero-windows (:563-581). */
        gold_fp2_t tzeros[DNAC_STARK_MAX_MAIN_WIDTH];
        const gold_fp2_t *tn = oi->trace_next;
        if (!di->air.main_next) {
            for (size_t k = 0; k < di->air.main_width; k++) {
                tzeros[k] = gold_fp2_zero();
            }
            tn = tzeros;
        }
        gold_fp2_t pzeros[64];
        const gold_fp2_t *pn = oi->preprocessed_next;
        if (di->preprocessed_width > 0 && !di->prep_next) {
            if (di->preprocessed_width > 64) {
                free(ch_flat);
                return DNAC_BV_ERR_SHAPE;
            }
            for (uint32_t k = 0; k < di->preprocessed_width; k++) {
                pzeros[k] = gold_fp2_zero();
            }
            pn = pzeros;
        }

        dnac_stark_folder_t folder;
        folder.trace_local = oi->trace_local;
        folder.trace_next = tn;
        folder.main_width = di->air.main_width;
        folder.public_values = di->public_values;
        folder.num_public_values = di->num_publics;
        folder.is_first_row = sels.is_first_row;
        folder.is_last_row = sels.is_last_row;
        folder.is_transition = sels.is_transition;
        dnac_stark_fold_init(&folder.fold, alpha);
        folder.capture = NULL;
        folder.capture_cap = 0;
        folder.capture_len = 0;
        folder.preprocessed_local = oi->preprocessed_local;
        folder.preprocessed_next = pn;
        folder.prep_width = di->preprocessed_width;

        /* air.eval FIRST (protocol.rs:64-81). */
        di->air.air_eval(&folder);

        /* Then the lookup constraints, in lookup order — ONE fold stream,
         * acc = acc·α + x (folder.rs:169-181). */
        if (di->num_lookups > 0) {
            const uint32_t aux_w = bv_aux_width(di);
            /* Recompose the permutation window at ζ into EF columns
             * (:543-559). */
            gold_fp2_t perm_loc[64], perm_nxt[64];
            if (aux_w > 64) { free(ch_flat); return DNAC_BV_ERR_SHAPE; }
            for (uint32_t c = 0; c < aux_w; c++) {
                perm_loc[c] = bv_recompose_ef(oi->permutation_local[2u * c],
                                              oi->permutation_local[2u * c + 1u]);
                perm_nxt[c] = bv_recompose_ef(oi->permutation_next[2u * c],
                                              oi->permutation_next[2u * c + 1u]);
            }
            /* Evaluate the expression pool over the EF window
             * (folder.rs:115-126 two-row window; leaves = opened values). */
            gold_fp2_t *pv = NULL;
            if (di->pool_len > 0) {
                pv = (gold_fp2_t *)calloc(di->pool_len, sizeof(gold_fp2_t));
                if (!pv) { free(ch_flat); return DNAC_BV_ERR_OOM; }
                if (dnac_logup_eval_pool_window(
                        di->pool, di->pool_len, oi->trace_local, tn,
                        (uint32_t)di->air.main_width, oi->preprocessed_local,
                        pn, di->preprocessed_width, di->public_values,
                        di->num_publics, pv) != DNAC_LOGUP_OK) {
                    free(pv); free(ch_flat);
                    return DNAC_BV_ERR_SHAPE;
                }
            }
            /* PASS 1 — one UNGATED fraction residual per lookup, in lookup
             * order (protocol.rs:76-78 driving logup.rs:245). */
            for (uint32_t l = 0; l < di->num_lookups; l++) {
                const dnac_logup_lookup_t *lk = &di->lookups[l];
                const uint32_t col = lk->column;
                /* col indexes both the challenge pair (2·col, 2·col+1,
                 * logup.rs:221-223) and fraction column col+1 of an aux_w =
                 * num_lookups+1 wide trace — so col must be < num_lookups. */
                if (col >= di->num_lookups) {
                    free(pv); free(ch_flat);
                    return DNAC_BV_ERR_SHAPE;
                }
                const gold_fp2_t la = ch_ptrs[i][2u * col];
                const gold_fp2_t lb = ch_ptrs[i][2u * col + 1u];
                /* Row-resolved tuple element / multiplicity values. */
                if (lk->num_tuples > BV_MAX_TUPLES) {
                    free(pv); free(ch_flat);
                    return DNAC_BV_ERR_SHAPE;
                }
                gold_fp2_t elem_store[BV_MAX_TUPLES][BV_MAX_TUPLE_W];
                const gold_fp2_t *elem_ptrs[BV_MAX_TUPLES];
                gold_fp2_t mults[BV_MAX_TUPLES];
                for (uint32_t tt = 0; tt < lk->num_tuples; tt++) {
                    const uint32_t w = lk->tuple_widths[tt];
                    if (w > BV_MAX_TUPLE_W) {
                        free(pv); free(ch_flat);
                        return DNAC_BV_ERR_SHAPE;
                    }
                    for (uint32_t e = 0; e < w; e++) {
                        const int32_t idx = lk->tuple_elems[tt][e];
                        if (idx < 0 || (uint32_t)idx >= di->pool_len) {
                            free(pv); free(ch_flat);
                            return DNAC_BV_ERR_SHAPE;
                        }
                        elem_store[tt][e] = pv[idx];
                    }
                    elem_ptrs[tt] = elem_store[tt];
                    const int32_t midx = lk->multiplicities[tt];
                    if (midx < 0 || (uint32_t)midx >= di->pool_len) {
                        free(pv); free(ch_flat);
                        return DNAC_BV_ERR_SHAPE;
                    }
                    mults[tt] = pv[midx];
                }
                gold_fp2_t num, den;
                if (dnac_logup_sum_terms_fp2(elem_ptrs, lk->tuple_widths, mults,
                                             lk->num_tuples, la, lb, &num,
                                             &den) != DNAC_LOGUP_OK) {
                    free(pv); free(ch_flat);
                    return DNAC_BV_ERR_SHAPE;
                }
                /* U·f − V, pinned on EVERY row with NO selector (logup.rs:245).
                 * Upstream's reason (logup.rs:241-244): the identity is cyclic
                 * in the trace domain so it needs no transition gate, and
                 * forcing it everywhere pins the last-row value the
                 * accumulator's terminal binding then consumes.
                 * Fraction column is col + 1 — column 0 is the shared
                 * accumulator (logup.rs:226-229). */
                const gold_fp2_t frac = perm_loc[col + 1u];
                dnac_stark_fold_assert_zero(
                    &folder.fold,
                    gold_fp2_sub(gold_fp2_mul(den, frac), num));
            }
            free(pv);

            /* PASS 2 — ONE accumulator block for the whole AIR
             * (protocol.rs:81 driving logup.rs:291-301), selector-multiplied
             * per air/src/filtered.rs:78-86. The per-lookup running sums of
             * the 82cfad73 scheme are gone: one shared accumulator covers
             * local and global alike, and the is_global branch with it.
             *
             *   [0] is_first_row  · acc_local
             *   [1] is_transition · (acc_next − acc_local − row_sum)
             *   [2] is_last_row   · (terminal − acc_local − row_sum)
             *
             * row_sum = Σ_c f_c over every lookup's fraction column at this
             * row (logup.rs:285-287). */
            const gold_fp2_t acc_loc = perm_loc[0];
            const gold_fp2_t acc_nxt = perm_nxt[0];
            gold_fp2_t row_sum = gold_fp2_zero();
            for (uint32_t l = 0; l < di->num_lookups; l++) {
                row_sum = gold_fp2_add(row_sum,
                                       perm_loc[di->lookups[l].column + 1u]);
            }
            dnac_stark_fold_assert_zero(
                &folder.fold, gold_fp2_mul(sels.is_first_row, acc_loc));
            dnac_stark_fold_assert_zero(
                &folder.fold,
                gold_fp2_mul(sels.is_transition,
                             gold_fp2_sub(gold_fp2_sub(acc_nxt, acc_loc),
                                          row_sum)));
            /* The terminal is the value this AIR committed — presence already
             * gated against num_lookups > 0 above, so it is live here. */
            dnac_stark_fold_assert_zero(
                &folder.fold,
                gold_fp2_mul(sels.is_last_row,
                             gold_fp2_sub(gold_fp2_sub(oi->terminal, acc_loc),
                                          row_sum)));
        }

        /* final: acc · inv_vanishing == quotient (data.rs:99-103). */
        if (dnac_stark_final_check(folder.fold.acc, sels.inv_vanishing,
                                   quotient) != DNAC_STARK_VERIFY_OK) {
            if (out) out->bad_instance = i;
            free(ch_flat);
            return DNAC_BV_ERR_OOD;
        }
    }
    free(ch_flat);

    /* ---- 8. cross-AIR terminal sum (v0.6.2 verifier/mod.rs) ----
     * A FLAT total over every AIR's one committed terminal, replacing the
     * per-bus HashMap grouping of 82cfad73. Sound at v0.6.2 because bus
     * separation moved into the challenge derivation: each slot's denominator
     * base is prefix[bus] = α + (bus+1)·β^W, one power above every payload
     * term, so two different buses cannot produce cancelling contributions
     * (challenges.rs:19-23). Absent terminals were forced to zero above and
     * so contribute nothing, matching upstream's `.flatten()`. */
    if (dnac_logup_verify_terminal_sum(terminals, n) != DNAC_LOGUP_OK) {
        if (out) {
            gold_fp2_t s = gold_fp2_zero();
            for (uint32_t i = 0; i < n; i++) s = gold_fp2_add(s, terminals[i]);
            out->terminal_sum = s;
        }
        return DNAC_BV_ERR_LOOKUP_SUM;
    }

    return DNAC_BV_OK; /* verifier/mod.rs:645 Ok(()) */
}
