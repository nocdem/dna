/**
 * @file shielded_verify.c
 * @brief Phase-C C2.1 — consensus shielded-statement verify (see header).
 *
 * Grounding map (KAFADAN YASAK — every constant cites its source):
 *   - 43-public layout ......... conf_action_agg_fold.h:115-127 (CONF_AGGZK_PUB_*)
 *   - proof shape (3 coms: random/trace/quotient, widths 6/2322/6, num_qc=8)
 *     ........................... stark_prover_agg.c build_coms():433-476 +
 *                                 A_* pins :34-45 (A_CW=6, A_RAND_W=W+4,
 *                                 A_NUM_QC=8 MEASURED oracle STOP gate)
 *   - priming order ............ stark_priming.h:80-116 (dnac_stark_priming_input_t)
 *   - pinned params/height ..... shielded_fri_params.h:68-93
 *   - sighash_v4 ............... dnac_tx_shielded_sighash, serialize.c:673-707
 *                                 (LINKED, not re-implemented — G-DET-2)
 *   - tx_binding map ........... conf_txbind_map, conf_txbind.h:45-56
 *   - N-chunk constraint check . stark_constraints.h:288-312 + the AIR
 *                                 descriptor DNAC_CONF_ACTION_AGG_FOLD_AIR
 *   - self-verify template ..... stark_prover_agg.c:478-523 (the struct-level
 *                                 FRI + N-chunk sequence this mirrors, with the
 *                                 publics recomputed from the WIRE instead of
 *                                 read from the prover struct)
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include "shielded_verify.h"

#include <string.h>

#include "conf_action_agg_fold.h"
#include "conf_txbind.h"
#include "field_goldilocks.h"
#include "fri_proof_codec.h"
#include "shielded_fri_params.h"
#include "stark_constraints.h"
#include "stark_priming.h"
#include "transcript.h"

/* ── Pinned aggregate proof shape (verifier-side consensus constants). ──
 * These MUST equal the prover's A_* pins (stark_prover_agg.c:34-45); the
 * accept-KAT (a real production proof through this entry) is the byte-level
 * cross-check that the two sets agree. */
#define SV_W ((size_t)CONF_AGGZK_WIDTH)      /* 2318 — main trace width        */
#define SV_NUM_RANDOM ((size_t)4)            /* A_NUM_RANDOM: randomize_trace
                                              * appends 4 random columns       */
#define SV_TRACE_OPEN_W (SV_W + SV_NUM_RANDOM) /* 2322 — committed/opened width */
#define SV_CHUNK_W ((size_t)2 + SV_NUM_RANDOM) /* 6 — quotient chunk / random
                                              * poly width (A_CW)              */
#define SV_NUM_QC ((size_t)8)                /* MEASURED (oracle STOP gate)    */
#define SV_LOG_NUM_QC ((size_t)2)            /* A_LOG_NUM_QC                   */
#define SV_NUM_PUBLICS ((size_t)CONF_AGGZK_NUM_PUBLICS) /* 43                  */

/* num_qc == 1 << (log_num_qc + is_zk) — verifier.rs:294-296 invariant. */
_Static_assert(SV_NUM_QC ==
                   ((size_t)1 << (SV_LOG_NUM_QC + DNAC_SHIELDED_IS_ZK)),
               "num_qc / log_num_qc / is_zk inconsistent");
/* Wire struct lane counts must match the AIR public layout. */
_Static_assert(DNAC_SHIELDED_LANES == CONF_AGGZK_MEMB_LANES &&
                   DNAC_SHIELDED_MAX_INPUTS == CONF_AGGZK_MAX_INPUTS &&
                   DNAC_SHIELDED_MAX_OUTPUTS == CONF_AGGZK_MAX_OUTPUTS,
               "wire shielded-field shape != AIR public shape");

static int fp2_eq(gold_fp2_t a, gold_fp2_t b) {
    return gold_fp_to_u64(a.a) == gold_fp_to_u64(b.a) &&
           gold_fp_to_u64(a.b) == gold_fp_to_u64(b.b);
}

/* Recompute the 43 publics from the WIRE fields (never from the proof).
 * Layout = CONF_AGGZK_PUB_* (conf_action_agg_fold.h:115-127), value source =
 * the wire struct whose slots the caller has already canonicalized. Unused
 * slots are zero on the wire (checked) and zero in the publics (the prover
 * zero-fills them the same way, stark_prover_agg.c:243-244,349-352). */
static void sv_build_publics(const dnac_tx_shielded_fields_t *sf,
                             const uint64_t txbind[CONF_TXBIND_LANES],
                             gold_fp_t out[SV_NUM_PUBLICS]) {
    for (unsigned j = 0; j < DNAC_SHIELDED_LANES; j++)
        out[CONF_AGGZK_PUB_ANCHOR + j] = gold_fp_from_u64(sf->anchor[j]);
    out[CONF_AGGZK_PUB_NUMIN] = gold_fp_from_u64((uint64_t)sf->num_input);
    for (unsigned s = 0; s < DNAC_SHIELDED_MAX_INPUTS; s++)
        for (unsigned j = 0; j < DNAC_SHIELDED_LANES; j++)
            out[CONF_AGGZK_PUB_NFSLOT + s * 4 + j] =
                gold_fp_from_u64(sf->nf_set[s][j]);
    out[CONF_AGGZK_PUB_NUMOUT] = gold_fp_from_u64((uint64_t)sf->num_output);
    for (unsigned s = 0; s < DNAC_SHIELDED_MAX_OUTPUTS; s++)
        for (unsigned j = 0; j < DNAC_SHIELDED_LANES; j++)
            out[CONF_AGGZK_PUB_OCOMMIT + s * 4 + j] =
                gold_fp_from_u64(sf->output_commit[s][j]);
    out[CONF_AGGZK_PUB_FEE] = gold_fp_from_u64(sf->fee);
    for (unsigned j = 0; j < CONF_TXBIND_LANES; j++)
        out[CONF_AGGZK_PUB_TXBIND + j] = gold_fp_from_u64(txbind[j]);
}

dnac_shielded_verify_status_t dnac_shielded_verify_statement(
    const dnac_tx_shielded_fields_t *sf,
    const uint8_t                    chain_id[32],
    uint64_t                         committed_fee) {
    if (sf == NULL || chain_id == NULL || sf->fri_proof == NULL ||
        sf->fri_proof_len == 0) {
        return DNAC_SHIELDED_VERIFY_ERR_NULL;
    }
    /* Oversize fail-close (design §0: never assume the transport cap, never
     * crash/OOM). The codec's own cap is the wire bound; anything above it can
     * be rejected without touching the blob. */
    if (sf->fri_proof_len > DNAC_FRI_WIRE_MAX_TOTAL_LEN) {
        return DNAC_SHIELDED_VERIFY_ERR_OVERSIZE;
    }

    /* ── 1. Wire canonicalization (DET-S5-3 / G-DET-5 / G-SEC-2 / G-SEC-6) ── */
    /* num_input in [1, MAX]: GAP-1 proves any INPUT row forces num_input >= 1
     * (conf_action_agg_fold constraint set); a 0-input statement has no
     * membership anchor and no spend — fail-close. num_output in [0, MAX]
     * (an all-fee spend has no OUTPUT block; the prover emits num_output=0,
     * stark_prover_agg.c:343-353). */
    if (sf->num_input < 1 || sf->num_input > DNAC_SHIELDED_MAX_INPUTS ||
        sf->num_output > DNAC_SHIELDED_MAX_OUTPUTS) {
        return DNAC_SHIELDED_VERIFY_ERR_COUNT;
    }
    for (unsigned s = 0; s < DNAC_SHIELDED_MAX_INPUTS; s++)
        for (unsigned j = 0; j < DNAC_SHIELDED_LANES; j++) {
            if (sf->nf_set[s][j] >= GOLDILOCKS_P)
                return DNAC_SHIELDED_VERIFY_ERR_NONCANONICAL;
            if (s >= sf->num_input && sf->nf_set[s][j] != 0)
                return DNAC_SHIELDED_VERIFY_ERR_SLOT_NONZERO;
        }
    for (unsigned s = 0; s < DNAC_SHIELDED_MAX_OUTPUTS; s++)
        for (unsigned j = 0; j < DNAC_SHIELDED_LANES; j++) {
            if (sf->output_commit[s][j] >= GOLDILOCKS_P)
                return DNAC_SHIELDED_VERIFY_ERR_NONCANONICAL;
            if (s >= sf->num_output && sf->output_commit[s][j] != 0)
                return DNAC_SHIELDED_VERIFY_ERR_SLOT_NONZERO;
        }
    for (unsigned j = 0; j < DNAC_SHIELDED_LANES; j++) {
        if (sf->anchor[j] >= GOLDILOCKS_P ||
            sf->tx_binding[j] >= GOLDILOCKS_P)
            return DNAC_SHIELDED_VERIFY_ERR_NONCANONICAL;
    }
    if (sf->fee >= GOLDILOCKS_P) return DNAC_SHIELDED_VERIFY_ERR_NONCANONICAL;
    /* Single fee authority (D7.2): the header committed_fee the fee-pool logic
     * reads MUST equal the balance-bound shielded fee public. */
    if (sf->fee != committed_fee) return DNAC_SHIELDED_VERIFY_ERR_FEE;

    /* ── 2. Statement binding (G-SEC-3): sighash_v4 -> txbind map -> wire ── */
    uint8_t  sighash[CONF_TXBIND_SIGHASH_LEN];
    uint64_t txbind[CONF_TXBIND_LANES];
    if (dnac_tx_shielded_sighash(sf, chain_id, sighash) != 0) {
        return DNAC_SHIELDED_VERIFY_ERR_TXBIND;
    }
    if (!conf_txbind_map(sighash, txbind)) {
        /* < 4 canonical groups in the digest (prob << 2^-100) — fail-close,
         * never reduce-mod-p (conf_txbind.h:12). */
        return DNAC_SHIELDED_VERIFY_ERR_TXBIND;
    }
    for (unsigned j = 0; j < CONF_TXBIND_LANES; j++) {
        if (txbind[j] != sf->tx_binding[j])
            return DNAC_SHIELDED_VERIFY_ERR_TXBIND;
    }

    /* ── 3. The 43 publics, recomputed from the WIRE (G-SEC-1/2). ── */
    gold_fp_t publics[SV_NUM_PUBLICS];
    sv_build_publics(sf, txbind, publics);

    /* ── 4. Decode the proof blob (canonicality of every proof field is
     *       enforced by the codec — NONCANONICAL/TRUNCATED/... all reject). ── */
    dnac_fri_wire_package_t *pkg = NULL;
    if (dnac_fri_proof_decode(sf->fri_proof, sf->fri_proof_len, &pkg) !=
        DNAC_FRI_CODEC_OK) {
        return DNAC_SHIELDED_VERIFY_ERR_DECODE;
    }

    dnac_shielded_verify_status_t rc = DNAC_SHIELDED_VERIFY_ERR_SHAPE;
    dnac_transcript_t            *vt = NULL;

    /* ── 5. Shape pin: exactly the aggregate proof's commitment layout
     *       (build_coms, stark_prover_agg.c:433-476):
     *         com[0] random   — 1 matrix, 1 point (zeta),        6 evals
     *         com[1] trace    — 1 matrix, 2 points (zeta, next), 2322 evals
     *         com[2] quotient — 8 matrices, 1 point (zeta) each, 6 evals
     *       every committed domain log_size == the pinned height 11. ── */
    size_t num_coms = 0;
    const dnac_fri_commitment_with_opening_points_t *coms =
        dnac_fri_wire_commitments(pkg, &num_coms);
    if (coms == NULL || num_coms != 3) goto out;
    if (coms[0].num_matrices != 1 || coms[1].num_matrices != 1 ||
        coms[2].num_matrices != SV_NUM_QC)
        goto out;
    const dnac_fri_matrix_openings_t *rand_mx = &coms[0].matrices[0];
    const dnac_fri_matrix_openings_t *trace_mx = &coms[1].matrices[0];
    if (rand_mx->num_points != 1 || trace_mx->num_points != 2) goto out;
    if (rand_mx->points[0].num_claimed_evals != SV_CHUNK_W ||
        trace_mx->points[0].num_claimed_evals != SV_TRACE_OPEN_W ||
        trace_mx->points[1].num_claimed_evals != SV_TRACE_OPEN_W)
        goto out;
    for (size_t k = 0; k < SV_NUM_QC; k++) {
        const dnac_fri_matrix_openings_t *m = &coms[2].matrices[k];
        if (m->num_points != 1 ||
            m->points[0].num_claimed_evals != SV_CHUNK_W)
            goto out;
        if (m->domain.log_size != DNAC_SHIELDED_COMMITTED_LOG_HEIGHT) {
            rc = DNAC_SHIELDED_VERIFY_ERR_HEIGHT;
            goto out;
        }
    }
    if (rand_mx->domain.log_size != DNAC_SHIELDED_COMMITTED_LOG_HEIGHT ||
        trace_mx->domain.log_size != DNAC_SHIELDED_COMMITTED_LOG_HEIGHT) {
        /* The pinned entry re-checks this (max over all matrices); pinning it
         * here too keeps the priming input trustworthy (G-SEC-4). */
        rc = DNAC_SHIELDED_VERIFY_ERR_HEIGHT;
        goto out;
    }

    /* ── 6. Prime a FRESH transcript from decoded opened values + recomputed
     *       publics; SAMPLE zeta/zeta_next (H2/H3 closed on this path). ── */
    {
        const gold_fp2_t *qc_ptr[SV_NUM_QC];
        size_t            qc_len[SV_NUM_QC];
        for (size_t k = 0; k < SV_NUM_QC; k++) {
            qc_ptr[k] = coms[2].matrices[k].points[0].claimed_evals;
            qc_len[k] = SV_CHUNK_W;
        }
        dnac_stark_priming_input_t pin;
        memset(&pin, 0, sizeof(pin));
        pin.degree_bits = DNAC_SHIELDED_COMMITTED_LOG_HEIGHT; /* == decoded, pinned */
        pin.is_zk = DNAC_SHIELDED_IS_ZK; /* config constant, NEVER wire-read
                                          * (stark_priming.h:72-78)            */
        pin.preprocessed_width = 0;
        pin.trace_commit = coms[1].commitment;
        pin.quotient_commit = coms[2].commitment;
        pin.random_commit = &coms[0].commitment;
        pin.random_local = rand_mx->points[0].claimed_evals;
        pin.random_local_len = SV_CHUNK_W;
        pin.public_values = publics;
        pin.num_public_values = SV_NUM_PUBLICS;
        pin.trace_local = trace_mx->points[0].claimed_evals;
        pin.trace_local_len = SV_TRACE_OPEN_W;
        pin.trace_next = trace_mx->points[1].claimed_evals;
        pin.trace_next_len = SV_TRACE_OPEN_W;
        pin.quotient_chunks = qc_ptr;
        pin.quotient_chunk_lens = qc_len;
        pin.num_quotient_chunks = SV_NUM_QC;

        vt = dnac_transcript_init_default();
        if (vt == NULL) {
            rc = DNAC_SHIELDED_VERIFY_ERR_PRIMING;
            goto out;
        }
        dnac_stark_priming_out_t pout;
        memset(&pout, 0, sizeof(pout));
        if (dnac_stark_prime_transcript(vt, &pin, &pout) !=
            DNAC_STARK_PRIMING_OK) {
            rc = DNAC_SHIELDED_VERIFY_ERR_PRIMING;
            goto out;
        }

        /* ── 7. Wire opening coordinates MUST equal the SAMPLED points
         *       (G-DET-4 / G-SEC-5; closes H2 — the pinned FRI entry verifies
         *       at the wire coordinates, so they must BE the derived ones). ── */
        if (!fp2_eq(rand_mx->points[0].point, pout.zeta) ||
            !fp2_eq(trace_mx->points[0].point, pout.zeta) ||
            !fp2_eq(trace_mx->points[1].point, pout.zeta_next)) {
            rc = DNAC_SHIELDED_VERIFY_ERR_OPENING_POINT;
            goto out;
        }
        for (size_t k = 0; k < SV_NUM_QC; k++) {
            if (!fp2_eq(coms[2].matrices[k].points[0].point, pout.zeta)) {
                rc = DNAC_SHIELDED_VERIFY_ERR_OPENING_POINT;
                goto out;
            }
        }

        /* ── 8. Pinned FRI/PCS verify on the wire bytes (params equality +
         *       pinned-param substitution + height pin + query PoW). ── */
        dnac_fri_status_t fs = DNAC_FRI_ERR_INVALID_POW_WITNESS;
        if (dnac_fri_verify_wire_shielded(sf->fri_proof, sf->fri_proof_len, vt,
                                          &fs) != DNAC_FRI_CODEC_OK ||
            fs != DNAC_FRI_OK) {
            rc = DNAC_SHIELDED_VERIFY_ERR_FRI;
            goto out;
        }

        /* ── 9. CRIT-1: the N-chunk AIR constraint check — recomputed publics
         *       + decoded openings at the SAMPLED zeta/alpha. FRI_OK alone is
         *       soundness-vacuous; BOTH must pass (self-verify template,
         *       stark_prover_agg.c:508-521). Only the first SV_W of the 2322
         *       opened trace columns are AIR columns (the +4 random tail is
         *       ignored, ditto the chunk tails via stride). ── */
        gold_fp2_t chunks[SV_NUM_QC * 2];
        for (size_t k = 0; k < SV_NUM_QC; k++) {
            chunks[k * 2 + 0] = qc_ptr[k][0];
            chunks[k * 2 + 1] = qc_ptr[k][1];
        }
        if (dnac_stark_verify_constraints_nchunk(
                &DNAC_CONF_ACTION_AGG_FOLD_AIR,
                trace_mx->points[0].claimed_evals, SV_W,
                trace_mx->points[1].claimed_evals, SV_W,
                publics, SV_NUM_PUBLICS,
                pout.zeta, DNAC_SHIELDED_COMMITTED_LOG_HEIGHT, SV_LOG_NUM_QC,
                DNAC_SHIELDED_IS_ZK, pout.alpha,
                chunks, SV_NUM_QC, 2) != DNAC_STARK_VERIFY_OK) {
            rc = DNAC_SHIELDED_VERIFY_ERR_CONSTRAINTS;
            goto out;
        }
    }

    rc = DNAC_SHIELDED_VERIFY_OK;

out:
    if (vt) dnac_transcript_free(vt);
    dnac_fri_wire_free(pkg);
    return rc;
}
