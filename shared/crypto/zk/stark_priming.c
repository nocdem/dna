/**
 * @file stark_priming.c
 * @brief STARK/PCS transcript-priming helper — implementation.
 *
 * Mirror of Plonky3 `p3_uni_stark::verify` front-half (commit 82cfad73):
 *   uni-stark/src/verifier.rs:360-391 + :398 + fri/src/two_adic_pcs.rs:687-693.
 * See stark_priming.h for the full source map. Transcript priming ONLY — no
 * constraint check, no quotient recomposition, no FRI.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include "stark_priming.h"

#include <assert.h>
#include <stddef.h>
#include <stdint.h>

#include "field_goldilocks.h"
#include "poseidon2_mmcs.h" /* dnac_p2_digest_t — P1c Poseidon2 cutover */
#include "transcript.h"

dnac_stark_priming_status_t dnac_stark_prime_transcript(
    dnac_transcript_t                *transcript,
    const dnac_stark_priming_input_t *input,
    dnac_stark_priming_out_t         *out) {
    /* P1e-E (S8-MED1): ALWAYS-ON fail-close (survives -DNDEBUG) — the caller
     * rejects on any non-OK status. */
    if (transcript == NULL || input == NULL || out == NULL)
        return DNAC_STARK_PRIMING_ERR_NULL;

    /* is_zk is a single config bit (config.rs:43 -> 0 or 1). 0 = TwoAdicFriPcs
     * (v3.0 transparent); 1 = HidingFriPcs (sandbox confidential, M1/M2). Any
     * other value is a malformed instance. */
    if (input->is_zk > 1) {
        return DNAC_STARK_PRIMING_ERR_ZK_UNSUPPORTED;
    }

    /* base_degree_bits is DERIVED (verifier.rs:52), never wire-trusted. */
    const size_t base_degree_bits = input->degree_bits - input->is_zk;
    const size_t preprocessed_width = input->preprocessed_width;

    /* (1)-(3) instance scalars as base-field elements (verifier.rs:361-363).
     * Val::from_usize(x) → canonical Goldilocks → 8 little-endian bytes. */
    dnac_transcript_observe_fp(transcript, gold_fp_from_u64((uint64_t)input->degree_bits));
    dnac_transcript_observe_fp(transcript, gold_fp_from_u64((uint64_t)base_degree_bits));
    dnac_transcript_observe_fp(transcript, gold_fp_from_u64((uint64_t)preprocessed_width));

    /* (4) trace commitment — MerkleCap cap_height=0 ⇒ one 4-lane digest,
     * observed lane-by-lane as field elements (CanObserve<MerkleCap<F,[F;4]>>,
     * duplex_challenger.rs:186-210 — P1c granularity flip, same ORDER). */
    dnac_transcript_observe_digest(transcript, &input->trace_commit);

    /* (5) preprocessed commitment iff width>0 (verifier.rs:370-372).
     * Not executed for the DNAC range_air / FibonacciAir (width 0). */
    if (preprocessed_width > 0) {
        if (input->preprocessed_commit == NULL)
            return DNAC_STARK_PRIMING_ERR_NULL; /* P1e-E: always-on fail-close */
        dnac_transcript_observe_digest(transcript, input->preprocessed_commit);
    }

    /* (6) public values — base field, fixed AIR order (verifier.rs:373). */
    for (size_t i = 0; i < input->num_public_values; ++i) {
        dnac_transcript_observe_fp(transcript, input->public_values[i]);
    }

    /* (7) sample STARK alpha — constraint combiner (verifier.rs:379). It must be
     * drawn here to advance the transcript even though FRI never uses it. */
    out->alpha = dnac_transcript_sample_fp2(transcript);

    /* (8) quotient_chunks commitment (verifier.rs:380). */
    dnac_transcript_observe_digest(transcript, &input->quotient_commit);

    /* (9) is_zk: observe the random commitment AFTER quotient_chunks, BEFORE
     * zeta (verifier.rs:383-385). is_zk==0 skips (no random branch). */
    if (input->is_zk != 0) {
        if (input->random_commit == NULL)
            return DNAC_STARK_PRIMING_ERR_NULL; /* P1e-E: always-on fail-close */
        dnac_transcript_observe_digest(transcript, input->random_commit);
    }

    /* (10) sample zeta — out-of-domain point (verifier.rs:391). */
    out->zeta = dnac_transcript_sample_fp2(transcript);

    /* (11) zeta_next = init_trace_domain.next_point(zeta)
     *               = zeta · two_adic_generator(base_degree_bits)
     * (verifier.rs:398; domain.rs:169-170; coset.rs:92). The generator belongs to
     * the trace subgroup of order 2^base_degree_bits — NOT the quotient/LDE
     * domain. zeta/zeta_next are verifier-DERIVED; a wire-supplied z is never
     * trusted (design § 5 note C, Security-G3). */
    out->zeta_next = gold_fp2_mul(
        out->zeta,
        gold_fp2_from_base(gold_fp_two_adic_generator((unsigned)base_degree_bits)));
    out->base_degree_bits = base_degree_bits;

    /* (12) PCS observe opened values (two_adic_pcs.rs:687-693), in coms_to_verify
     * order (verifier.rs:403-458). For is_zk==1 the RANDOM round is FIRST
     * (verifier.rs:403-411): random_local @ zeta over the trace domain, before
     * trace_local. Then trace_local @ zeta, trace_next @ zeta_next, each quotient
     * chunk @ zeta, then preprocessed. Only the eval VECTORS are observed; the
     * opening coordinate z is never observed (it is bound `_`). */
    if (input->is_zk != 0) {
        if (input->random_local == NULL)
            return DNAC_STARK_PRIMING_ERR_NULL; /* P1e-E: always-on fail-close */
        for (size_t i = 0; i < input->random_local_len; ++i) {
            dnac_transcript_observe_fp2(transcript, input->random_local[i]);
        }
    }
    for (size_t i = 0; i < input->trace_local_len; ++i) {
        dnac_transcript_observe_fp2(transcript, input->trace_local[i]);
    }
    if (input->trace_next != NULL) {
        for (size_t i = 0; i < input->trace_next_len; ++i) {
            dnac_transcript_observe_fp2(transcript, input->trace_next[i]);
        }
    }
    for (size_t c = 0; c < input->num_quotient_chunks; ++c) {
        for (size_t i = 0; i < input->quotient_chunk_lens[c]; ++i) {
            dnac_transcript_observe_fp2(transcript, input->quotient_chunks[c][i]);
        }
    }
    if (preprocessed_width > 0) {
        for (size_t i = 0; i < input->preprocessed_local_len; ++i) {
            dnac_transcript_observe_fp2(transcript, input->preprocessed_local[i]);
        }
        if (input->preprocessed_next != NULL) {
            for (size_t i = 0; i < input->preprocessed_next_len; ++i) {
                dnac_transcript_observe_fp2(transcript, input->preprocessed_next[i]);
            }
        }
    }

    /* Transcript is now at the verify_fri-entry "milestone-0 seed". */
    return DNAC_STARK_PRIMING_OK;
}
