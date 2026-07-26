/**
 * @file batch_priming.c
 * @brief Batch-STARK transcript priming + proof-shape checks — port of
 *        Plonky3 batch-stark BatchTranscript / verifier shape validation.
 *
 * Plonky3 commit pin: 82cfad73cd734d37a0d51953094f970c531817ec.
 * See batch_priming.h for the order and granularity pins (P2L-c).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>
#include <string.h>

#include "batch_priming.h"

/* ============================================================================
 * Phase primitives
 * ========================================================================== */

void dnac_batch_observe_usize(dnac_duplex_t *ch, uint64_t v)
{
    /* observe_base_as_algebra_element::<Goldilocks²>(from_usize(v)) =
     * observe_algebra_element(EF::from(v)) = the 2 basis coefficients (v, 0)
     * (challenger/src/lib.rs:141-147 via :106-108; transcript.rs:136-140). */
    dnac_duplex_observe_fp(ch, gold_fp_from_u64(v));
    dnac_duplex_observe_fp(ch, gold_fp_zero());
}

void dnac_batch_observe_commit(dnac_duplex_t *ch, const gold_fp_t commit[4])
{
    /* A commitment digest = 4 Goldilocks lanes observed in order (the P1
     * digest-observe pin; Hash<Goldilocks,Goldilocks,4>). */
    for (unsigned i = 0; i < 4; i++) {
        dnac_duplex_observe_fp(ch, commit[i]);
    }
}

int dnac_batch_observe_count_and_bindings(dnac_duplex_t              *ch,
                                          const dnac_batch_binding_t *bindings,
                                          uint32_t                    num_instances)
{
    if (!ch || (num_instances > 0 && !bindings)) {
        return DNAC_BATCH_ERR_NULL;
    }
    /* observe_instance_count (transcript.rs:27-29; verifier/mod.rs:144). */
    dnac_batch_observe_usize(ch, num_instances);
    /* Per-instance binding (transcript.rs:32-43; verifier/mod.rs:269-274):
     * log_ext_degree, log_degree, width, num_quotient_chunks — each a usize
     * observe. */
    for (uint32_t i = 0; i < num_instances; i++) {
        dnac_batch_observe_usize(ch, bindings[i].log_ext_degree);
        dnac_batch_observe_usize(ch, bindings[i].log_degree);
        dnac_batch_observe_usize(ch, bindings[i].width);
        dnac_batch_observe_usize(ch, bindings[i].num_quotient_chunks);
    }
    return DNAC_BATCH_OK;
}

int dnac_batch_observe_main(dnac_duplex_t          *ch,
                            const gold_fp_t         main_commit[4],
                            const gold_fp_t *const *public_values,
                            const uint32_t         *num_publics,
                            uint32_t                num_instances)
{
    if (!ch || !main_commit ||
        (num_instances > 0 && (!public_values || !num_publics))) {
        return DNAC_BATCH_ERR_NULL;
    }
    /* observe_main (transcript.rs:46-54): commit, then observe_slice of each
     * instance's public values. */
    dnac_batch_observe_commit(ch, main_commit);
    for (uint32_t i = 0; i < num_instances; i++) {
        if (num_publics[i] > 0 && !public_values[i]) {
            return DNAC_BATCH_ERR_NULL;
        }
        for (uint32_t j = 0; j < num_publics[i]; j++) {
            dnac_duplex_observe_fp(ch, public_values[i][j]);
        }
    }
    return DNAC_BATCH_OK;
}

int dnac_batch_observe_preprocessed(dnac_duplex_t   *ch,
                                    const uint32_t  *preprocessed_widths,
                                    uint32_t         num_instances,
                                    const gold_fp_t *preprocessed_commit)
{
    if (!ch || (num_instances > 0 && !preprocessed_widths)) {
        return DNAC_BATCH_ERR_NULL;
    }
    /* observe_preprocessed (transcript.rs:57-68): every width as usize, then
     * the optional global commit. */
    for (uint32_t i = 0; i < num_instances; i++) {
        dnac_batch_observe_usize(ch, preprocessed_widths[i]);
    }
    if (preprocessed_commit) {
        dnac_batch_observe_commit(ch, preprocessed_commit);
    }
    return DNAC_BATCH_OK;
}

int dnac_batch_sample_perm_challenges(dnac_duplex_t               *ch,
                                      const dnac_logup_bus_view_t *views,
                                      uint32_t                     num_instances,
                                      gold_fp2_t *const           *out_challenges)
{
    if (!ch || (num_instances > 0 && (!views || !out_challenges))) {
        return DNAC_BATCH_ERR_NULL;
    }

    /* Count the fresh pairs the memo walk will need: one per local lookup +
     * one per FIRST-occurrence bus name (transcript.rs:92-98). Pre-sampling
     * exactly that many pairs in draw order is byte-identical to the
     * reference's lazy sampling: no observes happen inside the phase, so the
     * challenger produces the same sample stream. */
    uint32_t total_globals = 0, fresh = 0;
    for (uint32_t i = 0; i < num_instances; i++) {
        if (views[i].num_globals > 0 && !views[i].global_bus_names) {
            return DNAC_BATCH_ERR_NULL;
        }
        fresh += views[i].num_locals;
        total_globals += views[i].num_globals;
    }
    const char **seen = (const char **)malloc(
        sizeof(const char *) * (total_globals ? total_globals : 1));
    if (!seen) {
        return DNAC_BATCH_ERR_OOM;
    }
    uint32_t num_seen = 0;
    for (uint32_t i = 0; i < num_instances; i++) {
        for (uint32_t g = 0; g < views[i].num_globals; g++) {
            const char *name = views[i].global_bus_names[g];
            if (!name) {
                free((void *)seen);
                return DNAC_BATCH_ERR_NULL;
            }
            int found = 0;
            for (uint32_t m = 0; m < num_seen; m++) {
                if (strcmp(seen[m], name) == 0) {
                    found = 1;
                    break;
                }
            }
            if (!found) {
                seen[num_seen++] = name;
            }
        }
    }
    fresh += num_seen;
    free((void *)seen);

    /* Sample the draw stream: `fresh` pairs, 2 fp2 each (sample_n_challenges,
     * transcript.rs:142-146; each fp2 = 2 base samples c0-first, P1a pin). */
    gold_fp2_t *draws =
        (gold_fp2_t *)malloc(sizeof(gold_fp2_t) * 2u * (fresh ? fresh : 1));
    if (!draws) {
        return DNAC_BATCH_ERR_OOM;
    }
    for (uint32_t d = 0; d < 2u * fresh; d++) {
        draws[d] = dnac_duplex_sample_fp2(ch);
    }

    uint32_t used = 0;
    int rc = dnac_logup_bus_assign_challenges(views, num_instances, draws,
                                              fresh, out_challenges, &used);
    free(draws);
    if (rc != DNAC_LOGUP_OK) {
        return DNAC_BATCH_ERR_PARAM;
    }
    if (used != fresh) {
        /* The pre-count and the memo walk MUST agree — divergence would mean
         * a draw-stream desync against the reference. Fail-close. */
        return DNAC_BATCH_ERR_PARAM;
    }
    return DNAC_BATCH_OK;
}

int dnac_batch_observe_perm_and_sample_alpha(
    dnac_duplex_t               *ch,
    const gold_fp_t             *permutation_commit,
    const dnac_logup_bus_view_t *views,
    const gold_fp2_t *const    *cumulative_sums,
    uint32_t                     num_instances,
    gold_fp2_t                  *out_alpha)
{
    if (!ch || !out_alpha || (num_instances > 0 && !views)) {
        return DNAC_BATCH_ERR_NULL;
    }
    /* transcript.rs:106-119: iff the permutation commit exists, observe it
     * and then every cumulative sum (flattened instance order, global-lookup
     * order; observe_algebra_element = 2 coefficients). Alpha is sampled
     * either way. */
    if (permutation_commit) {
        dnac_batch_observe_commit(ch, permutation_commit);
        for (uint32_t i = 0; i < num_instances; i++) {
            if (views[i].num_globals == 0) {
                continue;
            }
            if (!cumulative_sums || !cumulative_sums[i]) {
                return DNAC_BATCH_ERR_NULL;
            }
            for (uint32_t g = 0; g < views[i].num_globals; g++) {
                dnac_duplex_observe_fp2(ch, cumulative_sums[i][g]);
            }
        }
    }
    *out_alpha = dnac_duplex_sample_fp2(ch);
    return DNAC_BATCH_OK;
}

gold_fp2_t dnac_batch_sample_zeta(dnac_duplex_t *ch)
{
    /* transcript.rs:132-134. */
    return dnac_duplex_sample_fp2(ch);
}

/* ============================================================================
 * Composed priming run
 * ========================================================================== */

int dnac_batch_priming_run(dnac_duplex_t                    *ch,
                           const dnac_batch_priming_input_t *in,
                           gold_fp2_t *const                *out_perm_challenges,
                           gold_fp2_t                       *out_alpha,
                           gold_fp2_t                       *out_zeta)
{
    if (!ch || !in || !out_alpha || !out_zeta || !in->main_commit ||
        !in->quotient_commit) {
        return DNAC_BATCH_ERR_NULL;
    }
    const uint32_t n = in->num_instances;
    if (n > 0 && (!in->bindings || !in->public_values || !in->num_publics ||
                  !in->preprocessed_widths || !in->views)) {
        return DNAC_BATCH_ERR_NULL;
    }

    /* Fail-close consistency (always on):
     * - binding arithmetic: log_ext_degree == log_degree + is_zk
     *   (validate_degree_bits mirror, verifier/mod.rs:96-104),
     * - random commit present iff is_zk (verifier/mod.rs:74-84),
     * - permutation commit present iff any instance declares lookups
     *   (verifier/mod.rs:282-286). */
    int any_lookups = 0;
    for (uint32_t i = 0; i < n; i++) {
        if (in->bindings[i].log_ext_degree !=
            in->bindings[i].log_degree + (uint32_t)(in->is_zk ? 1 : 0)) {
            return DNAC_BATCH_ERR_PARAM;
        }
        if (in->bindings[i].num_quotient_chunks == 0) {
            return DNAC_BATCH_ERR_PARAM;
        }
        if (in->views[i].num_locals + in->views[i].num_globals > 0) {
            any_lookups = 1;
        }
    }
    if ((in->random_commit != NULL) != (in->is_zk != 0)) {
        return DNAC_BATCH_ERR_PARAM;
    }
    if ((in->permutation_commit != NULL) != any_lookups) {
        return DNAC_BATCH_ERR_PARAM;
    }

    int rc = dnac_batch_observe_count_and_bindings(ch, in->bindings, n);
    if (rc != DNAC_BATCH_OK) {
        return rc;
    }
    rc = dnac_batch_observe_main(ch, in->main_commit, in->public_values,
                                 in->num_publics, n);
    if (rc != DNAC_BATCH_OK) {
        return rc;
    }
    rc = dnac_batch_observe_preprocessed(ch, in->preprocessed_widths, n,
                                         in->preprocessed_commit);
    if (rc != DNAC_BATCH_OK) {
        return rc;
    }
    rc = dnac_batch_sample_perm_challenges(ch, in->views, n,
                                           out_perm_challenges);
    if (rc != DNAC_BATCH_OK) {
        return rc;
    }
    rc = dnac_batch_observe_perm_and_sample_alpha(
        ch, in->permutation_commit, in->views, in->cumulative_sums, n,
        out_alpha);
    if (rc != DNAC_BATCH_OK) {
        return rc;
    }
    dnac_batch_observe_commit(ch, in->quotient_commit);
    if (in->random_commit) {
        dnac_batch_observe_commit(ch, in->random_commit);
    }
    *out_zeta = dnac_batch_sample_zeta(ch);
    return DNAC_BATCH_OK;
}

/* ============================================================================
 * BatchProof shape check
 * ========================================================================== */

int dnac_batch_proof_shape_check(const dnac_batch_instance_shape_t *shapes,
                                 const dnac_batch_binding_t        *bindings,
                                 const dnac_logup_bus_view_t       *views,
                                 const uint32_t                    *preprocessed_widths,
                                 uint32_t                           num_instances,
                                 int                                is_zk,
                                 int                                has_permutation_commit,
                                 int                                has_random_commit)
{
    if (num_instances > 0 &&
        (!shapes || !bindings || !views || !preprocessed_widths)) {
        return DNAC_BATCH_ERR_NULL;
    }

    /* Random commitment present iff ZK (verifier/mod.rs:74-84). */
    if ((has_random_commit != 0) != (is_zk != 0)) {
        return DNAC_BATCH_ERR_SHAPE;
    }
    /* Permutation commitment present iff any instance declares lookups
     * (verifier/mod.rs:282-286). */
    int any_lookups = 0;
    for (uint32_t i = 0; i < num_instances; i++) {
        if (views[i].num_locals + views[i].num_globals > 0) {
            any_lookups = 1;
        }
    }
    if ((has_permutation_commit != 0) != any_lookups) {
        return DNAC_BATCH_ERR_SHAPE;
    }

    for (uint32_t i = 0; i < num_instances; i++) {
        const dnac_batch_instance_shape_t *s = &shapes[i];
        const uint32_t width = bindings[i].width;
        const uint32_t aux_width = views[i].num_locals + views[i].num_globals;

        /* trace_local width (verifier/mod.rs:162-169); trace_next iff the
         * AIR reads the next row (:170-180). */
        if (s->trace_local_len != width) {
            return DNAC_BATCH_ERR_SHAPE;
        }
        if (s->main_next_used ? (s->trace_next_len != width)
                              : (s->trace_next_len != 0)) {
            return DNAC_BATCH_ERR_SHAPE;
        }

        /* Quotient chunk count == the transcript binding (:183-191), each
         * chunk of Challenge DIMENSION == 2 coefficients (:193-199). */
        if (s->num_quotient_chunks != bindings[i].num_quotient_chunks ||
            s->quotient_chunk_dim != 2u) {
            return DNAC_BATCH_ERR_SHAPE;
        }

        /* Random opened values: 2 coefficients iff ZK (:201-209). */
        if (s->random_len != (is_zk ? 2u : 0u)) {
            return DNAC_BATCH_ERR_SHAPE;
        }

        /* Preprocessed lens vs the CommonData width (:211-231). */
        const uint32_t pw = preprocessed_widths[i];
        if (pw == 0) {
            if (s->preprocessed_local_len != 0 || s->preprocessed_next_len != 0) {
                return DNAC_BATCH_ERR_SHAPE;
            }
        } else if (s->prep_next_used) {
            if (s->preprocessed_local_len != pw || s->preprocessed_next_len != pw) {
                return DNAC_BATCH_ERR_SHAPE;
            }
        } else if (s->preprocessed_local_len != pw ||
                   s->preprocessed_next_len != 0) {
            return DNAC_BATCH_ERR_SHAPE;
        }

        /* Permutation opened lens: local == next (:482-484), both ==
         * aux_width · DIMENSION (:524-541). */
        if (s->permutation_local_len != s->permutation_next_len ||
            s->permutation_local_len != aux_width * 2u) {
            return DNAC_BATCH_ERR_SHAPE;
        }

        /* global_lookup_data metadata: entry count == global count
         * (:240-249); (name, aux_column) equal the expected list in order
         * (:250-267) with locals-first columns (types.rs:59-89) so global g
         * sits at column num_locals + g. */
        if (s->num_global_entries != views[i].num_globals) {
            return DNAC_BATCH_ERR_SHAPE;
        }
        if (views[i].num_globals > 0 &&
            (!s->entry_names || !s->entry_aux_columns)) {
            return DNAC_BATCH_ERR_NULL;
        }
        for (uint32_t g = 0; g < views[i].num_globals; g++) {
            if (!s->entry_names[g] ||
                strcmp(s->entry_names[g], views[i].global_bus_names[g]) != 0 ||
                s->entry_aux_columns[g] != views[i].num_locals + g) {
                return DNAC_BATCH_ERR_SHAPE;
            }
        }
    }
    return DNAC_BATCH_OK;
}
