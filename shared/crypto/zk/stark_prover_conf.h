/**
 * @file stark_prover_conf.h
 * @brief B1 Stage-2 — pure-C prover for the COMBINED confidential AIR
 *        (conf_root layout, width 614, is_zk=1, num_qc=8, 17 publics).
 *
 * The conf-AIR sibling of `dnac_prover_prove` (stark_prover_prove.h, the P1
 * RangeProofAir assembler): same S1→S12 pipeline over the SAME parametric
 * stage library (stark_prover.h), with the conf-specific pieces swapped in:
 *
 *   S1  trace       = conf_root_air_generate (the BUILT Stage-1 generator)
 *   S6  quotient    = the conf constraint set evaluated domain-wide by
 *                     REUSING dnac_conf_root_fold_air_eval (conf_root_fold.c)
 *                     row-by-row — ONE emission source for prover + verifier,
 *                     mirroring Plonky3's one Air::eval driven by both folders
 *   publics (17)    = [commitment_root(4), c_claimed(4), c_fee(4), hash_id,
 *                     tx_binding(4)] — root/c_claimed/c_fee read from the
 *                     built trace; tx_binding caller-supplied (conf_txbind map)
 *
 * Shape (grounded, Plonky3 82cfad73; empirically confirmed by the oracle's
 * measured num_qc=8 STOP gate on conf_root_air_zk{,_h16}.json):
 *   base_db = log2(height); degree_bits = base_db+1; log_max_height = base_db+3
 *   num_qc = 8 (log_num_qc = 2; degree-3 AIR at is_zk=1) — HEIGHT-INDEPENDENT
 *   q_size = 2^(degree_bits + log_num_qc) = 8·height = lde_h
 *   next_step (trace row step on the quotient domain) = 2^(is_zk+log_num_qc) = 8
 *
 * Draws (SmallRng consumption order, D1-B; hiding not soundness):
 *   trace (614+8)·h = 622h @ 0 ‖ codeword 8·4·h = 32h @ 622h ‖
 *   blinding 7·6·h = 42h @ 654h ‖ R 2h·6 = 12h @ 696h  — total 708h.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_ZK_STARK_PROVER_CONF_H
#define DNAC_ZK_STARK_PROVER_CONF_H

#include <stddef.h>
#include <stdint.h>

#include "conf_root_fold.h"
#include "fri_verifier.h"
#include "stark_prover.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Total SmallRng draws for an is_zk=1 combined-conf-AIR instance. */
#define DNAC_CONF_PROVER_TOTAL_DRAWS(height) ((size_t)708 * (size_t)(height))

/**
 * A conf prove request. `outputs[0..n_out)` (< 2^52 each), `fee` (< 2^52);
 * claimed = Σ outputs + fee is derived (must be < 2^62). `blind` = 2·height
 * canonical witness blinding lanes (2 per row incl. padding, the Stage-1
 * conf_commit convention). `tx_binding` = 4 canonical elements from the
 * conf_txbind rejection map (FS public #13..16). `draws` = the SmallRng-order
 * random stream (KAT: oracle dump; production: OS entropy).
 */
typedef struct {
    const uint64_t *outputs;
    size_t          n_out;
    uint64_t        fee;
    const uint64_t *blind;       /* 2*height canonical values */
    size_t          height;      /* power of two, n_out+2 <= height <= 2^11 */
    uint64_t        tx_binding[4];
    const uint64_t *draws;
    size_t          num_draws;   /* must equal DNAC_CONF_PROVER_TOTAL_DRAWS */
    /* M3b salted-leaf hiding: a fresh-SmallRng(1) salt sequence (both the
     * input-mmcs stream A and the FRI-mmcs stream B slice this ONE buffer from
     * their own offsets; design §3a). NULL -> unsalted (plain leaves). Length
     * must be >= DNAC_CONF_PROVER_SALT_DRAWS(height). */
    const uint64_t *salt_draws;
    size_t          num_salt_draws;
} dnac_conf_prover_instance_t;

/** SALT_ELEMS for the M3b hiding MMCS (Goldilocks 64-bit x 2 = 128-bit). */
#define C_SALT_ELEMS 2u

/** Salt draws needed: input stream A = 160h (trace 16h + quotient 128h +
 *  random 16h) is the max; the FRI stream B (< 2*sum of layer heights <
 *  2*lde_h) reuses the SAME buffer from position 0. lde_h = 8h. */
#define DNAC_CONF_PROVER_SALT_DRAWS(height) ((size_t)160 * (size_t)(height))

/** Opaque produced proof; free with dnac_conf_prover_proof_free. */
typedef struct dnac_conf_prover_proof_s dnac_conf_prover_proof_t;

/**
 * Prove a combined-conf-AIR instance and SELF-VERIFY (priming with the 17
 * publics + zeta cross-check + dnac_fri_verify == DNAC_FRI_OK + the N-chunk
 * constraint check dnac_stark_verify_constraints_nchunk == OK). Fail-close on
 * any inconsistency.
 */
dnac_prover_status_t dnac_conf_prover_prove(
    const dnac_conf_prover_instance_t *inst,
    dnac_conf_prover_proof_t         **out_proof);

/**
 * PRODUCTION entry point (G2): fills BOTH secret streams from OS entropy and
 * proves a GENUINELY SALTED (M3b leaf-hiding) proof —
 *   - the is_zk codeword/blinding stream (`draws`, 708h), AND
 *   - the salted-leaf MMCS salt stream (`salt_draws`, 160h)
 * via dnac_zk_fill_draws (rejection-sampled canonical Goldilocks, fail-close).
 * Same instance fields as dnac_conf_prover_prove EXCEPT `draws`/`num_draws` AND
 * `salt_draws`/`num_salt_draws` are IGNORED (filled internally). Use this in a
 * wallet — it delivers BOTH the is_zk randomization AND the leaf-salt hiding
 * that keeps the committed trace rows (confidential amounts/blinds) hidden at
 * the FRI query openings. Use dnac_conf_prover_prove with fixed streams only for
 * byte-stable KATs. Returns DNAC_PROVER_ERR_PARAM if the instance shape is
 * invalid or entropy fails (fail-close — never a partial or non-hiding proof).
 */
dnac_prover_status_t dnac_conf_prover_prove_production(
    const dnac_conf_prover_instance_t *inst,
    dnac_conf_prover_proof_t         **out_proof);

/** Re-verify (priming + FRI + N-chunk constraint check). */
dnac_fri_status_t dnac_conf_prover_proof_verify(const dnac_conf_prover_proof_t *p);

/** Cross-check accessors (byte-match vs the reference Plonky3 proof). */
void dnac_conf_prover_proof_zeta(const dnac_conf_prover_proof_t *p,
                                 gold_fp2_t *zeta, gold_fp2_t *zeta_next);
void dnac_conf_prover_proof_roots(const dnac_conf_prover_proof_t *p,
                                  uint8_t trace_root[DNAC_MERKLE_DIGEST_BYTES],
                                  uint8_t quot_root[DNAC_MERKLE_DIGEST_BYTES],
                                  uint8_t rand_root[DNAC_MERKLE_DIGEST_BYTES]);
const gold_fp2_t *dnac_conf_prover_proof_final_poly(
    const dnac_conf_prover_proof_t *p, size_t *out_len);
/** The 17 public values (base field, §4b flat order), borrowed. */
const gold_fp_t *dnac_conf_prover_proof_publics(const dnac_conf_prover_proof_t *p,
                                                size_t *out_n);

void dnac_conf_prover_proof_free(dnac_conf_prover_proof_t *p);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ZK_STARK_PROVER_CONF_H */
