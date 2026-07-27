/**
 * @file shielded_verify.c
 * @brief Phase-C C2.1 — consensus shielded-statement verify (see header).
 *
 * d4.c-3 (2026-07-26): re-based onto the DZKF v4 BATCHED wire + dnac_batch_verify
 * (the v3 single-instance uni-stark path is retired). Steps 1-3 (wire
 * canonicalization, sighash_v4 -> txbind, publics recompute) are UNCHANGED; the
 * proof is decoded as a 1-instance batched proof and verified by dnac_batch_verify
 * (which does the FRI verify AND the N-chunk constraint check AND — vacuously
 * here — the per-bus lookup sums). The v3 wire opening-coordinate check
 * (H2/G-SEC-5) is GONE by construction: the v4 wire carries NO opening points,
 * so the verifier samples ζ itself and assembles the N2 rounds — a wire-chosen
 * opening point can no longer exist. The publics-from-wire binding is now
 * enforced by Fiat-Shamir divergence inside dnac_batch_verify (recomputed
 * publics feed the priming → a tampered statement yields a different ζ/α → the
 * committed openings no longer match → FRI reject).
 *
 * Grounding map (KAFADAN YASAK):
 *   - 43-public layout ......... conf_action_agg_fold.h (CONF_AGGZK_PUB_*)
 *   - batched proof shape (1 inst, is_zk=1, trace 2318, num_qc=8, random 2)
 *     ........................... stark_prover_agg.c agg_fill_vinstance + the
 *                                 batch_shielded_agg oracle (num_qc STOP gate)
 *   - pinned params/height/salt  shielded_fri_params.h
 *   - sighash_v4 ............... dnac_tx_shielded_sighash, serialize.c (LINKED)
 *   - tx_binding map ........... conf_txbind_map, conf_txbind.h
 *   - batched verify ........... dnac_batch_verify (batch_verify.h) — the FRI +
 *                                 N-chunk constraint + per-bus sum, 1:1 with
 *                                 Plonky3 batch-stark verify_batch (82cfad73)
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include "shielded_verify.h"

#include <string.h>

#include "batch_verify.h"
#include "conf_action_agg_fold.h"
#include "conf_txbind.h"
#include "field_goldilocks.h"
#include "fri_proof_codec.h"
#include "shielded_fri_params.h"

/* ── Pinned aggregate proof shape (verifier-side consensus constants). ── */
#define SV_W ((size_t)CONF_AGGZK_WIDTH)                 /* 2318 — AIR trace width */
#define SV_NUM_QC ((size_t)8)                           /* MEASURED (STOP gate)   */
#define SV_LOG_NUM_QC ((size_t)2)                       /* A_LOG_NUM_QC           */
#define SV_NUM_PUBLICS ((size_t)CONF_AGGZK_NUM_PUBLICS) /* 43                     */
#define SV_RANDOM_LEN ((size_t)2)                       /* is_zk random opened    */

/* num_qc == 1 << (log_num_qc + is_zk) — verifier.rs:294-296 invariant. */
_Static_assert(SV_NUM_QC ==
                   ((size_t)1 << (SV_LOG_NUM_QC + DNAC_SHIELDED_IS_ZK)),
               "num_qc / log_num_qc / is_zk inconsistent");
/* Wire struct lane counts must match the AIR public layout. */
_Static_assert(DNAC_SHIELDED_LANES == CONF_AGGZK_MEMB_LANES &&
                   DNAC_SHIELDED_MAX_INPUTS == CONF_AGGZK_MAX_INPUTS &&
                   DNAC_SHIELDED_MAX_OUTPUTS == CONF_AGGZK_MAX_OUTPUTS,
               "wire shielded-field shape != AIR public shape");

/* Recompute the 43 publics from the WIRE fields (never from the proof).
 * Layout = CONF_AGGZK_PUB_* (conf_action_agg_fold.h), value source = the wire
 * struct whose slots the caller has already canonicalized. Unused slots are
 * zero on the wire (checked) and zero in the publics (the prover zero-fills them
 * the same way, agg_zk_generate). */
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
     * crash/OOM). */
    if (sf->fri_proof_len > DNAC_FRI_WIRE_MAX_TOTAL_LEN) {
        return DNAC_SHIELDED_VERIFY_ERR_OVERSIZE;
    }

    /* ── 1. Wire canonicalization (DET-S5-3 / G-DET-5 / G-SEC-2 / G-SEC-6) ── */
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
    /* Single fee authority (D7.2). */
    if (sf->fee != committed_fee) return DNAC_SHIELDED_VERIFY_ERR_FEE;

    /* ── 2. Statement binding (G-SEC-3): sighash_v4 -> txbind map -> wire ── */
    uint8_t  sighash[CONF_TXBIND_SIGHASH_LEN];
    uint64_t txbind[CONF_TXBIND_LANES];
    if (dnac_tx_shielded_sighash(sf, chain_id, sighash) != 0) {
        return DNAC_SHIELDED_VERIFY_ERR_TXBIND;
    }
    if (!conf_txbind_map(sighash, txbind)) {
        return DNAC_SHIELDED_VERIFY_ERR_TXBIND;
    }
    for (unsigned j = 0; j < CONF_TXBIND_LANES; j++) {
        if (txbind[j] != sf->tx_binding[j])
            return DNAC_SHIELDED_VERIFY_ERR_TXBIND;
    }

    /* ── 3. The 43 publics, recomputed from the WIRE (G-SEC-1/2). ── */
    gold_fp_t publics[SV_NUM_PUBLICS];
    sv_build_publics(sf, txbind, publics);

    /* ── 4. Decode the DZKF v4 batched proof blob (canonicality of every field
     *       is enforced by the codec — NONCANONICAL/TRUNCATED/... all reject;
     *       v3 buffers reject on VERSION). ── */
    dnac_batch_wire_package_t *pkg = NULL;
    if (dnac_batch_wire_decode(sf->fri_proof, sf->fri_proof_len, &pkg) !=
        DNAC_FRI_CODEC_OK) {
        return DNAC_SHIELDED_VERIFY_ERR_DECODE;
    }

    dnac_shielded_verify_status_t rc = DNAC_SHIELDED_VERIFY_ERR_SHAPE;

    /* ── 5. Structural pins (fail-close). The wire has no opening points and no
     *       degree/height field — the verifier PINS is_zk / height / num_qc /
     *       params, so a mismatched-height proof fails the FRI verify below. ── */
    if (dnac_batch_wire_is_zk(pkg) != DNAC_SHIELDED_IS_ZK ||
        dnac_batch_wire_num_instances(pkg) != 1) {
        goto out;
    }

    /* Param equality (tamper-detect) then SUBSTITUTE the pinned params — the
     * verify runs on the canonical consensus params, never the wire's. */
    const dnac_fri_params_t *wp = dnac_batch_wire_params(pkg);
    if (wp == NULL) goto out;
    if (wp->log_blowup != DNAC_SHIELDED_FRI_LOG_BLOWUP ||
        wp->log_final_poly_len != DNAC_SHIELDED_FRI_LOG_FINAL_POLY_LEN ||
        wp->max_log_arity != DNAC_SHIELDED_FRI_MAX_LOG_ARITY ||
        wp->num_queries != DNAC_SHIELDED_FRI_NUM_QUERIES ||
        wp->commit_proof_of_work_bits != DNAC_SHIELDED_FRI_COMMIT_POW_BITS ||
        wp->query_proof_of_work_bits != DNAC_SHIELDED_FRI_QUERY_POW_BITS) {
        rc = DNAC_SHIELDED_VERIFY_ERR_FRI;
        goto out;
    }
    dnac_fri_params_t pinned;
    memset(&pinned, 0, sizeof(pinned));
    pinned.log_blowup = DNAC_SHIELDED_FRI_LOG_BLOWUP;
    pinned.log_final_poly_len = DNAC_SHIELDED_FRI_LOG_FINAL_POLY_LEN;
    pinned.max_log_arity = DNAC_SHIELDED_FRI_MAX_LOG_ARITY;
    pinned.num_queries = DNAC_SHIELDED_FRI_NUM_QUERIES;
    pinned.commit_proof_of_work_bits = DNAC_SHIELDED_FRI_COMMIT_POW_BITS;
    pinned.query_proof_of_work_bits = DNAC_SHIELDED_FRI_QUERY_POW_BITS;

    /* Opened-value shape pin (v4: trace 2318 — the 4 zk codewords live in the
     * rand-openings, NOT the 2322-wide v3 opened trace). */
    const dnac_batch_vopened_t *opened = dnac_batch_wire_opened(pkg);
    if (opened == NULL) goto out;
    if (opened->trace_local_len != SV_W || opened->trace_next_len != SV_W ||
        opened->num_quotient_chunks != SV_NUM_QC ||
        opened->random_len != SV_RANDOM_LEN ||
        opened->preprocessed_local != NULL || opened->preprocessed_next != NULL ||
        opened->permutation_len != 0 || opened->has_terminal != 0) {
        goto out;
    }

    const dnac_fri_proof_t *proof = dnac_batch_wire_proof(pkg);
    if (proof == NULL) goto out;

    /* ── 6. Build the pinned 1-instance aggregate descriptor + the recomputed
     *       publics, and run the batched verify. degree_bits is PINNED to 11
     *       (the committed is_zk ext domain, C1 fixed H=1024); a proof at any
     *       other height fails the FRI verify (its query depths / opened counts
     *       won't match). dnac_batch_verify does the FRI verify AND the N-chunk
     *       AIR constraint check (CRIT-1: the ONLY step binding publics to the
     *       trace) AND the per-bus lookup sums (vacuous — no lookups). ── */
    {
        dnac_batch_vinstance_t vi;
        memset(&vi, 0, sizeof(vi));
        vi.air = DNAC_CONF_ACTION_AGG_FOLD_AIR;
        vi.preprocessed_width = 0;
        vi.prep_next = 0;
        vi.pool = NULL;
        vi.pool_len = 0;
        vi.lookups = NULL;
        vi.num_lookups = 0;
        vi.degree_bits = (uint32_t)DNAC_SHIELDED_COMMITTED_LOG_HEIGHT; /* 11 */
        vi.log_num_qc = (uint32_t)SV_LOG_NUM_QC;                       /* 2  */
        vi.public_values = publics;
        vi.num_publics = (uint32_t)SV_NUM_PUBLICS;

        dnac_batch_verify_out_t vo;
        memset(&vo, 0, sizeof(vo));
        /* The two hiding-preimage pins are STATED here and enforced inside
         * dnac_batch_verify (S2'-d, 2026-07-27). The salt pin used to be a
         * private check in this file, and the random-tail count was pinned
         * nowhere at all; both now travel with the instance so that the second
         * consumer of the decode → batch-verify pair (P2 recursion) cannot
         * inherit an unpinned leaf preimage length. See batch_verify.h. */
        dnac_batch_verify_status_t bst = dnac_batch_verify(
            &vi, opened, 1, DNAC_SHIELDED_IS_ZK, dnac_batch_wire_commits(pkg),
            NULL, 0, &pinned,
            (uint32_t)DNAC_SHIELDED_NUM_RANDOM, DNAC_SHIELDED_SALT_ELEMS,
            proof, dnac_batch_wire_rand_openings(pkg), &vo);
        switch (bst) {
        case DNAC_BV_OK:
            rc = DNAC_SHIELDED_VERIFY_OK;
            break;
        case DNAC_BV_ERR_FRI:
            rc = DNAC_SHIELDED_VERIFY_ERR_FRI;
            break;
        case DNAC_BV_ERR_OOD:
        case DNAC_BV_ERR_LOOKUP_SUM: /* no lookups — cannot fire, map defensively */
            rc = DNAC_SHIELDED_VERIFY_ERR_CONSTRAINTS;
            break;
        default: /* SHAPE / RANDOMIZATION / PARAM / OOM / NULL */
            rc = DNAC_SHIELDED_VERIFY_ERR_SHAPE;
            break;
        }
    }

out:
    dnac_batch_wire_free(pkg);
    return rc;
}
