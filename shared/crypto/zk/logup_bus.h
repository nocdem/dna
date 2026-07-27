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
 *   - single-pair challenge DERIVATION (batch-stark/src/transcript.rs:
 *     118-155 sample_perm_challenges at v0.6.2: ONE (α,β) pair is squeezed
 *     for the WHOLE batch — "two draws, not two per bus" — and buses are
 *     separated by prefix[bus] = α + (bus+1)·β^W instead of by extra draws.
 *     Bus ids: locals take a fresh id each, globals share one by NAME),
 *   - the FLAT cross-AIR terminal-sum check (one committed terminal per AIR;
 *     Σ terminals == 0),
 *
 *   ⚠ THE F3 FRAMING INVERTED AT v0.6.2 (S2'-c, 2026-07-27) — this header
 *   previously said the opposite, so read it deliberately. Under 82cfad73 a
 *   flat cross-bus total WAS the soundness hole and the check had to group by
 *   bus name (old verifier/mod.rs:623-643, G-DET-L4/G-SEC-L3/L4). At v0.6.2
 *   the flat total is the CORRECT and only check, because the separation moved
 *   DOWN into the challenge derivation: the bus offset sits at β^W, one power
 *   above every payload term, so two different buses cannot produce cancelling
 *   contributions (lookup/src/challenges.rs:19-23). The grouping entry point
 *   dnac_logup_bus_verify_global_sums is DELETED rather than kept as dead code
 *   implying a protection that now lives elsewhere. The KAT pins both
 *   directions (cross_bus_cancel / cross_bus_separated).
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
 * Single-pair bus challenge DERIVATION
 *   (transcript.rs:100-171 sample_perm_challenges + challenges.rs:39-74)
 *
 * ⚠ REPLACES dnac_logup_bus_assign_challenges (S2'-c, 2026-07-27). The old
 * scheme SAMPLED one fresh (α,β) pair per local lookup and per distinct bus
 * name — 2·num_buses squeezes. v0.6.2 draws ONE pair for the whole batch
 * ("This is the only lookup squeeze: two draws, not two per bus",
 * transcript.rs:112-115) and separates buses by DERIVATION instead:
 *
 *   γ           = β^W                      (W = max_message_width)
 *   prefix[i]   = α + (i + 1)·γ            (challenges.rs:56-66)
 *   denominator = prefix[bus] − Σ_k β^k·payload_k
 *
 * Injectivity, upstream's own argument (challenges.rs:19-23): payload terms
 * occupy β^0..β^(W−1) and the bus offset sits at β^W, one power above every
 * payload term, so two messages collide only when bus AND payload agree.
 * This is what makes the FLAT cross-AIR terminal sum sound and retires the
 * per-bus grouping DNAC used to do (see dnac_logup_verify_terminal_sum).
 *
 * BUS IDs (transcript.rs:117-151): walk instances in order, each instance's
 * lookups in column order (locals first, then globals — see the bus view):
 *   - Kind::Local  → a FRESH id each, so nothing else can cancel it,
 *   - Kind::Global → shared by bus NAME across all instances, so senders and
 *                    receivers cancel in the terminal sum.
 *
 * out_challenges[i] receives instance i's flat per-lookup array in column
 * order, laid out exactly as the gadget indexes it (transcript.rs:156-169):
 *
 *   [ prefix[bus_0], β, prefix[bus_1], β, ... ]
 *
 * i.e. the DENOMINATOR BASE takes α's slot. The gadget computes
 * `base − combined`, so passing prefix[bus] yields the separated denominator
 * with no gadget change.
 *
 * @param max_message_width  W — the widest payload tuple in the WHOLE batch,
 *   minimum 1. It cannot be derived from the bus view (which carries no tuple
 *   widths), so the caller must supply it; upstream computes it in the same
 *   pass that assigns bus ids (transcript.rs:132-135). W == 0 is rejected:
 *   the bus offset would land on β^0 and collide with payloads
 *   (challenges.rs:51-54).
 * @param out_num_buses  optional — the number of distinct bus ids assigned.
 * ========================================================================== */
int dnac_logup_bus_derive_challenges(
    const dnac_logup_bus_view_t *views,
    uint32_t                     num_instances,
    gold_fp2_t                   alpha,
    gold_fp2_t                   beta,
    uint32_t                     max_message_width,
    gold_fp2_t *const           *out_challenges, /* [i][2*num_lookups_i]    */
    uint32_t                    *out_num_buses);

/* ============================================================================
 * W = max_message_width — the widest payload tuple in the WHOLE batch
 *
 * Upstream computes this in the same pass that assigns bus ids
 * (transcript.rs:118-135): `max_message_width` starts at **1** and is maxed
 * over `tuple.len()` for EVERY tuple of EVERY lookup of EVERY instance.
 * The floor of 1 is upstream's, not a DNAC choice, and it is what keeps a
 * lookup-free or empty-tuple batch off the rejected W == 0 path.
 *
 * Shared by both sides on purpose: the prover and the verifier must derive
 * γ = β^W from ONE definition or they desynchronize the transcript. Same
 * discipline as num_random_codewords (S2'-d).
 *
 * lookups[i] may be NULL iff num_lookups[i] == 0.
 * ========================================================================== */
uint32_t dnac_logup_bus_max_message_width(
    const dnac_logup_lookup_t *const *lookups,
    const uint32_t                   *num_lookups,
    uint32_t                          num_instances);

/* NOTE: dnac_logup_bus_verify_global_sums is GONE (S2'-c). Per-bus grouping of
 * cumulative sums no longer exists as a concept: there are no per-lookup
 * cumulative sums, only ONE terminal per AIR, and the cross-AIR check is the
 * flat dnac_logup_verify_terminal_sum. Keeping a grouping entry point would
 * have been dead code implying a protection that now lives elsewhere. */

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
