/**
 * @file logup_bus.h
 * @brief LogUp interaction/bus layer — port of Plonky3 p3-lookup builder/bus
 *        + the batch-stark per-bus challenge memo and global-sum grouping.
 *
 * Plonky3 commit pin: 82cfad73cd734d37a0d51953094f970c531817ec.
 *
 * P2L-b scope (P2-lookup design 2026-07-23 §4, v3 GREEN):
 *   - interaction recording (lookup/src/builder.rs:59-94 InteractionBuilder:
 *     push_interaction / push_local_interaction; signed counts, count_weight),
 *   - column assignment (lookup/src/types.rs:59-89 from_interactions:
 *     locals FIRST, then globals, each in push order; a global interaction
 *     becomes a single-tuple lookup),
 *   - per-bus challenge assignment (batch-stark/src/transcript.rs:74-102
 *     sample_perm_challenges: globals sharing a bus name share ONE (α,β)
 *     pair memoized at first occurrence — instance order, then column
 *     order; locals always draw fresh),
 *   - per-bus global-sum verification (batch-stark/src/verifier/mod.rs:
 *     623-643: cumulative sums grouped BY BUS NAME, each group must sum to
 *     zero — G-DET-L4/G-SEC-L3/L4; a flat cross-bus total is the F3
 *     soundness hole and is NOT what this layer does),
 *   - the height-bound OFFLINE precondition Σ count_weight·height < p
 *     (builder.rs:33-38 doc contract; red-team F4: count_weight is stored
 *     and NEVER computed anywhere in Plonky3 82cfad73 — the runtime
 *     verifier will NOT catch a violation, so configs must be checked with
 *     dnac_logup_bus_check_height_bound at parameter-freeze time).
 * NOT in scope here: the batch-stark proof shape / transcript priming order
 * (P2L-c), prover/verifier/wire integration (P2L-d).
 *
 * Bus conventions (lookup/src/bus.rs): LookupBus query = +count, weight 1;
 * LookupBus table entry = −count, weight 0 (bus.rs:46-76).
 * PermutationCheckBus send = +count, receive = −count, both weight 1
 * (bus.rs:106-140).
 *
 * Bus names are grouping/memo keys ONLY — never observed into the
 * Fiat-Shamir transcript (G-DET-L2/F5). The grouping key and the
 * challenge-memo key are the SAME string by construction (round-2 N4).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_LOGUP_BUS_H
#define DNAC_LOGUP_BUS_H

#include <stddef.h>
#include <stdint.h>

#include "logup.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Additional error code (extends the DNAC_LOGUP_* set in logup.h). */
#define DNAC_LOGUP_ERR_HEIGHT_BOUND (-7) /* Σ weight·height >= p (F4
                                            offline precondition violated) */

/* ============================================================================
 * Bus view — the per-instance shape the bus-level operations need
 *
 * Column order is ALWAYS locals first, then globals (types.rs:59-89), so an
 * instance is fully described for challenge assignment / grouping by its
 * local count plus the ordered global bus names (+ weights for the height
 * bound). A view can be built by hand or taken from a finalized lookup set.
 * ========================================================================== */
typedef struct {
    uint32_t             num_locals;
    uint32_t             num_globals;
    const char *const   *global_bus_names;     /* [num_globals], column order */
    const uint32_t      *global_count_weights; /* [num_globals]; may be NULL
                                                  if only used for challenge
                                                  assignment / grouping      */
} dnac_logup_bus_view_t;

/* ============================================================================
 * Interaction recording builder (builder.rs InteractionBuilder, concrete)
 *
 * Records interactions in push order; finalize performs the from_interactions
 * column assignment. Expression operands are indices into the SAME expression
 * pool the resulting lookups will be evaluated against (logup.h pool).
 * ========================================================================== */
typedef struct dnac_logup_builder dnac_logup_builder_t;

dnac_logup_builder_t *dnac_logup_builder_new(void);
void dnac_logup_builder_free(dnac_logup_builder_t *b);

/* One global (cross-AIR) message on a named bus (builder.rs:68-74).
 * bus_name is copied. count is a SIGNED multiplicity expression
 * (+send/−receive per bus.rs). count_weight: 1 query / 0 table entry. */
int dnac_logup_push_interaction(dnac_logup_builder_t *b,
                                const char           *bus_name,
                                const int32_t        *fields,
                                uint32_t              num_fields,
                                int32_t               count,
                                uint32_t              count_weight);

/* One intra-AIR lookup, all (fields, count) tuples in one call
 * (builder.rs:80-83). Collapses into ONE running-sum column. */
int dnac_logup_push_local_interaction(dnac_logup_builder_t *b,
                                      const uint32_t       *tuple_widths,
                                      const int32_t *const *tuple_elems,
                                      const int32_t        *multiplicities,
                                      uint32_t              num_tuples);

/* ============================================================================
 * Finalized lookup set (types.rs:59-89 from_interactions)
 *
 * lookups[i] has column == i; order = locals (push order) then globals
 * (push order). A global lookup has exactly ONE tuple (the interaction's
 * fields) and one multiplicity (the signed count). All storage is owned by
 * the set; the builder may be freed independently afterwards.
 * ========================================================================== */
typedef struct {
    dnac_logup_lookup_t  *lookups;       /* [num_lookups]                   */
    const char *const    *bus_names;     /* [num_lookups]; NULL for locals  */
    const uint32_t       *count_weights; /* [num_lookups]; 0 for locals     */
    uint32_t              num_lookups;
    uint32_t              num_locals;
    uint32_t              num_globals;
    dnac_logup_bus_view_t view;          /* prebuilt bus view over the set  */
} dnac_logup_lookup_set_t;

int dnac_logup_builder_finalize(dnac_logup_builder_t     *b,
                                dnac_logup_lookup_set_t **out);
void dnac_logup_lookup_set_free(dnac_logup_lookup_set_t *s);

/* ============================================================================
 * Per-bus challenge assignment (transcript.rs:74-102 sample_perm_challenges)
 *
 * draws = the ordered fresh (α,β) pair stream (2 fp2 per pair; at P2L-c the
 * pairs come from the DuplexChallenger in exactly this order — one
 * sample_algebra_element per element). Assignment walks instances in order
 * and each instance's lookups in column order:
 *   - local lookup      → consume the next fresh pair,
 *   - global lookup     → memo by bus name: first occurrence consumes the
 *                         next fresh pair; later occurrences (any instance)
 *                         REUSE it (transcript.rs:92-98).
 * out_challenges[i] must hold 2·(num_locals+num_globals) of instance i —
 * the flat per-instance array indexed challenges[2·column] the gadget
 * expects. Fail-close if the draw stream is exhausted.
 * ========================================================================== */
int dnac_logup_bus_assign_challenges(
    const dnac_logup_bus_view_t *views,
    uint32_t                     num_instances,
    const gold_fp2_t            *draws,          /* [2*num_draw_pairs]      */
    uint32_t                     num_draw_pairs,
    gold_fp2_t *const           *out_challenges, /* [i][2*num_lookups_i]    */
    uint32_t                    *out_draw_pairs_used);

/* ============================================================================
 * Per-bus global-sum verification (verifier/mod.rs:623-643)
 *
 * cum_sums[i] = instance i's cumulative sums in GLOBAL-lookup order (the
 * dnac_logup_generate_permutation output order). Groups sums BY BUS NAME
 * (first-occurrence order — verdict identical to the reference's HashMap
 * iteration since the check is a conjunction, G-DET-L4) and requires EACH
 * group to sum to zero via dnac_logup_verify_global_sum.
 *
 * Returns DNAC_LOGUP_OK iff every bus group balances;
 * DNAC_LOGUP_ERR_GLOBAL_SUM otherwise, with *out_failed_bus (optional) set
 * to the first failing bus name in first-occurrence order.
 * ========================================================================== */
int dnac_logup_bus_verify_global_sums(
    const dnac_logup_bus_view_t *views,
    uint32_t                     num_instances,
    const gold_fp2_t *const    *cum_sums,        /* [i][num_globals_i]      */
    const char                 **out_failed_bus);

/* ============================================================================
 * Height-bound offline precondition (builder.rs:33-38; red-team F4)
 *
 * Checks Σ over all GLOBAL interactions of count_weight · height(instance)
 * < p (Goldilocks). Overflow-safe accumulation (each u32·u32 product fits
 * u64; the running sum fail-closes the moment it reaches p). This is a
 * CONFIG-TIME check — the runtime verifier does NOT enforce it (F4), so a
 * parameter freeze MUST call this. Views must carry global_count_weights.
 * ========================================================================== */
int dnac_logup_bus_check_height_bound(const dnac_logup_bus_view_t *views,
                                      const uint32_t              *heights,
                                      uint32_t                     num_instances);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_LOGUP_BUS_H */
