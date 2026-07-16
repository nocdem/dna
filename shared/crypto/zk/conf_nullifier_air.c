/**
 * @file conf_nullifier_air.c
 * @brief Dual-mode C4 nullifier-PRF AIR — is_zk=0 construction gate.
 *
 * See conf_nullifier_air.h for the construction + grounding. Construction-gate
 * style: generate an honest witness, eval returns the count of violated
 * constraints (0 == valid nullifier witness).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include "conf_nullifier_air.h"

#include <string.h>

#include "field_goldilocks.h"
#include "poseidon2_air.h"       /* poseidon2_air_eval_row */
#include "poseidon2_air_cols.h"
#include "poseidon2_air_trace.h" /* poseidon2_air_generate_row */
#include "shielded_domsep.h"     /* DNAC_DOMSEP_RHO / DNAC_DOMSEP_NF */

static uint64_t sp_out(const uint64_t *blk, size_t k) {
    return blk[p2air_end_post_off(P2AIR_HALF_FULL_ROUNDS - 1, k)];
}

/* One fixed-length PaddingFreeSponge<8,4,4> over in[8] (== S0 note_sponge_hash8),
 * emitting both permutation blocks and the 4-lane digest. block1 absorbs in[0..4]
 * with zero capacity; block2 absorbs in[4..8] with block1's capacity carry. */
static void sponge8_blocks(const uint64_t in[8], uint64_t *blk1, uint64_t *blk2,
                           uint64_t out[CONF_NF_LANES]) {
    uint64_t in1[8] = {in[0], in[1], in[2], in[3], 0, 0, 0, 0};
    poseidon2_air_generate_row(in1, blk1);
    uint64_t s1[8];
    for (int k = 0; k < 8; k++) s1[k] = sp_out(blk1, (size_t)k);

    uint64_t in2[8] = {in[4], in[5], in[6], in[7], s1[4], s1[5], s1[6], s1[7]};
    poseidon2_air_generate_row(in2, blk2);
    for (int k = 0; k < CONF_NF_LANES; k++) out[k] = sp_out(blk2, (size_t)k);
}

bool conf_nullifier_air_generate(const uint64_t cm[CONF_NF_LANES], uint64_t pos,
                                 uint64_t nk, uint64_t *trace_out,
                                 uint64_t nf_out[CONF_NF_LANES]) {
    if (!cm || !trace_out || !nf_out) return false;
    for (size_t i = 0; i < CONF_NF_WIDTH; i++) trace_out[i] = 0;

    for (int j = 0; j < CONF_NF_LANES; j++) trace_out[CONF_NF_CM_OFF + j] = cm[j];
    trace_out[CONF_NF_POS_OFF] = pos;
    trace_out[CONF_NF_NK_OFF] = nk;

    /* ρ = CRH(cm, pos): preimage [cm0..3, pos, DOMSEP_RHO, 0, 0]. */
    uint64_t rho_in[8] = {cm[0], cm[1], cm[2], cm[3], pos, DNAC_DOMSEP_RHO, 0, 0};
    uint64_t rho[CONF_NF_LANES];
    sponge8_blocks(rho_in, trace_out + CONF_NF_RHO1_OFF, trace_out + CONF_NF_RHO2_OFF,
                   rho);

    /* nf = PRF(nk, ρ): preimage [nk, ρ0..3, DOMSEP_NF, 0, 0]. */
    uint64_t nf_in[8] = {nk, rho[0], rho[1], rho[2], rho[3], DNAC_DOMSEP_NF, 0, 0};
    uint64_t nf[CONF_NF_LANES];
    sponge8_blocks(nf_in, trace_out + CONF_NF_NF1_OFF, trace_out + CONF_NF_NF2_OFF, nf);

    for (int j = 0; j < CONF_NF_LANES; j++) {
        trace_out[CONF_NF_NF_OFF + j] = nf[j];
        nf_out[j] = nf[j];
    }
    return true;
}

int conf_nullifier_air_eval(const uint64_t *trace, const uint64_t cm[CONF_NF_LANES],
                            uint64_t pos, const uint64_t nf[CONF_NF_LANES]) {
    if (!trace || !cm || !nf) return 1;
    int viol = 0;

    const uint64_t *rho1 = trace + CONF_NF_RHO1_OFF;
    const uint64_t *rho2 = trace + CONF_NF_RHO2_OFF;
    const uint64_t *nf1 = trace + CONF_NF_NF1_OFF;
    const uint64_t *nf2 = trace + CONF_NF_NF2_OFF;

    /* All four permutations internally consistent. */
    viol += poseidon2_air_eval_row(rho1);
    viol += poseidon2_air_eval_row(rho2);
    viol += poseidon2_air_eval_row(nf1);
    viol += poseidon2_air_eval_row(nf2);

    /* ── ρ = CRH(cm, pos) ──────────────────────────────────────────────────
     * G2 (red-team MF-1): the ρ-input MUST read the frozen-carry TRACE CELLS
     * (CONF_NF_CM_OFF / CONF_NF_POS_OFF), not the eval params directly — those
     * cells are what S4 wires to the C1 cm_carry/pos_carry, so a cell-only pin
     * would let a prover spend note A while nullifying note B (Faerie-Gold). Two
     * constraints per lane: RHO input == cell, AND cell == public value.
     * G1: absorb-pad + capacity-carry pins. */
    for (size_t j = 0; j < CONF_NF_LANES; j++) {
        if (rho1[p2air_input_off(j)] != trace[CONF_NF_CM_OFF + j]) viol++; /* input==cell */
        if (trace[CONF_NF_CM_OFF + j] != cm[j]) viol++;                    /* cell==public */
    }
    for (size_t k = 4; k < 8; k++)
        if (rho1[p2air_input_off(k)] != 0) viol++;          /* zero-cap IV */
    if (rho2[p2air_input_off(0)] != trace[CONF_NF_POS_OFF]) viol++;        /* input==cell */
    if (trace[CONF_NF_POS_OFF] != pos) viol++;                            /* cell==public */
    if (rho2[p2air_input_off(1)] != DNAC_DOMSEP_RHO) viol++;
    if (rho2[p2air_input_off(2)] != 0) viol++;
    if (rho2[p2air_input_off(3)] != 0) viol++;
    for (size_t k = 4; k < 8; k++)
        if (rho2[p2air_input_off(k)] != sp_out(rho1, k)) viol++; /* capacity carry */

    /* ρ = RHO2.out[0..4]. */
    uint64_t rho[CONF_NF_LANES];
    for (size_t j = 0; j < CONF_NF_LANES; j++) rho[j] = sp_out(rho2, j);

    /* ── nf = PRF(nk, ρ) ───────────────────────────────────────────────────
     * NF1.in[0] == nk (the SAME nk cell); NF1.in[1..4] == ρ[0..3]; NF2.in[0] ==
     * ρ[3]; NF2.in[1] == DOMSEP_NF; pads + capacity carry. */
    if (nf1[p2air_input_off(0)] != trace[CONF_NF_NK_OFF]) viol++;
    if (nf1[p2air_input_off(1)] != rho[0]) viol++;
    if (nf1[p2air_input_off(2)] != rho[1]) viol++;
    if (nf1[p2air_input_off(3)] != rho[2]) viol++;
    for (size_t k = 4; k < 8; k++)
        if (nf1[p2air_input_off(k)] != 0) viol++;           /* zero-cap IV */
    if (nf2[p2air_input_off(0)] != rho[3]) viol++;
    if (nf2[p2air_input_off(1)] != DNAC_DOMSEP_NF) viol++;
    if (nf2[p2air_input_off(2)] != 0) viol++;
    if (nf2[p2air_input_off(3)] != 0) viol++;
    for (size_t k = 4; k < 8; k++)
        if (nf2[p2air_input_off(k)] != sp_out(nf1, k)) viol++; /* capacity carry */

    /* G4 nf single-source: the public NF column == NF2.out[0..4], and it equals
     * the verifier-supplied public nf. The global shielded-nullifier-set double-
     * spend check+insert is owned by parent §1.8 / S4 (seen_shielded_nf, tag 0x08)
     * — NOT C6 (C6 is the transparent turnstile only; red-team MF-2 / dm-c4 G3). */
    for (size_t j = 0; j < CONF_NF_LANES; j++) {
        if (trace[CONF_NF_NF_OFF + j] != sp_out(nf2, j)) viol++;
        if (trace[CONF_NF_NF_OFF + j] != nf[j]) viol++;
    }
    return viol;
}
