/**
 * @file stark_prover_agg.h
 * @brief Dual-mode S4b.4 — pure-C prover for the AGGREGATE Action AIR
 *        (ConfActionAggAir ZK layout, width CONF_AGGZK_WIDTH = 2378 at the S8
 *        Gate 2 depth D=24, is_zk=1, num_qc=8, 45 publics).
 *
 * The aggregate sibling of dnac_action_prover_prove (stark_prover_action.h):
 * the SAME S1→S12 pipeline over the parametric stage library (stark_prover.h),
 * with the aggregate-specific pieces swapped in:
 *
 *   S1  trace     = the CONF_AGGZK_WIDTH-wide ZK trace (C1 scatter + membership walk +
 *                   nullifier sponge + is_zero SELECTOR columns + S4c output
 *                   routing/fee-acc), byte-matching Rust generate_conf_action_agg_trace
 *   S6  quotient  = the aggregate constraint set evaluated domain-wide by
 *                   REUSING dnac_conf_action_agg_fold_air_eval row-by-row (with
 *                   the 45 public values) — ONE emission source prover+verifier
 *   publics       = anchor[4] || num_input || nf_slot[MI][4] || num_output ||
 *                   output_commit[MO][4] || fee || boundary_in || boundary_out
 *                   || tx_binding[4]  (45, S4c + S8 Gate 2)
 *
 * Draw layout (SmallRng order, D1-B): trace (W+8)·h @0 ‖ codeword 32h ‖
 *   blinding 42h ‖ R 12h  — total (W+94)h = 2472h at W = CONF_AGGZK_WIDTH =
 *   2378 (D=24). Only the trace section grows vs C1; symbolic in A_W so it
 *   tracks the width.
 *
 * SALT (P4): optional M3b leaf-salt hiding — set instance.salt_draws (>= 160h) to
 * emit a SALTED proof (MerkleTreeHidingMmcs, SALT_ELEMS=2); NULL => unsalted,
 * byte-identical to before. KAT (fixed SmallRng seed) validates the salted verify
 * plumbing byte-matches; PRODUCTION hiding needs OS-entropy salts (zk_entropy).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_ZK_STARK_PROVER_AGG_H
#define DNAC_ZK_STARK_PROVER_AGG_H

#include <stddef.h>
#include <stdint.h>

#include "conf_action_agg_fold.h"
#include "conf_action_air.h"
#include "fri_proof_codec.h"
#include "fri_verifier.h"
#include "stark_prover.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Total SmallRng draws for an is_zk=1 aggregate instance: trace (W+8)h ‖
 *  codeword 32h ‖ blinding 42h ‖ R 12h = (W+94)h. W = CONF_AGGZK_WIDTH = 2378
 *  (D=24), so 2472h; symbolic so it tracks any future width change. */
#define DNAC_AGG_PROVER_TOTAL_DRAWS(height) \
    ((size_t)(CONF_AGGZK_WIDTH + 94) * (size_t)(height))

/** P4: M3b salt draws for the INPUT MMCS (stream A) — WIDTH-INDEPENDENT (per
 *  Merkle row, SALT_ELEMS=2 over lde_h=8h rows): trace 16h + quotient 8*16h +
 *  random 16h = 160h. This is stream A ONLY. WIDTH-INDEPENDENT (same at W=2378). */
#define DNAC_AGG_PROVER_SALT_DRAWS(height) ((size_t)160 * (size_t)(height))

/** P1e-HIGH1: M3b salt draws for the FRI-challenge MMCS (stream B) — a SEPARATE
 *  stream from A. The commit-phase consumes Σ(layer rows)·SALT_ELEMS < lde_h·SE =
 *  8h·2 = 16h draws (Σ rows < ro_len = lde_h). In Plonky3 the FRI mmcs is an
 *  INDEPENDENT hiding-mmcs (make_salted_zk_config: HidingChallengeMmcs over a
 *  CLONED rng, hiding_mmcs.rs:84-89) — production MUST give stream B its own
 *  entropy, never an alias of stream A (which would reveal an unopened trace
 *  leaf's salt via a FRI-layer opening). KAT byte-match is preserved by leaving
 *  instance.fri_salt_draws NULL (the plumbing then falls back to salt_draws@0,
 *  reproducing the oracle's same-seed clone). */
#define DNAC_AGG_PROVER_FRI_SALT_DRAWS(height) ((size_t)16 * (size_t)(height))

/**
 * An aggregate prove request — one shielded action's notes + the INPUT notes'
 * Merkle-membership siblings. Same conserving/range preconditions as the C1
 * instance; INPUT notes are addressed to Poseidon2(ak,nk) (condition-3) and must
 * be members of ONE tree at ONE anchor (the generator computes it).
 *
 * ZERO INPUT notes is a LEGAL instance (S8 Gate 2 SHIELD case): with no
 * INPUT-role block the generator emits num_input == 0, an all-zero anchor and
 * all-zero nf slots, and never dereferences memb_siblings — which is exactly the
 * statement dnac_shielded_verify_statement requires for num_input == 0.
 */
typedef struct {
    const uint64_t *value;      /* num_notes note values (< 2^52) */
    const uint64_t *addr;       /* num_notes * 4 recipient addresses */
    const uint64_t *rcm;        /* num_notes * 2 commitment randomness */
    const uint8_t  *roles;      /* num_notes role tags (CONF_ACTION_ROLE_*) */
    const uint64_t *pos;        /* num_notes tree positions */
    const uint64_t *nk;         /* num_notes × 4 nullifier-key lanes [blk*4+lane] (F3) */
    const uint64_t *ak;         /* num_notes × 4 spend-authority lanes [blk*4+lane] (F3) */
    size_t          num_notes;  /* real note-blocks; num_notes+1 <= H/K */
    const uint64_t *memb_siblings; /* num_notes * D * 4 (INPUT blocks consumed) */
    uint64_t        boundary_in;  /* S8 Gate 2 TRANSPARENT leg IN  (public @
                                   * CONF_AGGZK_PUB_BIN). MUST be < 2^63 — the
                                   * frozen B2 range the consensus entry enforces
                                   * (DNAC_SHIELDED_VERIFY_ERR_BOUNDARY); the
                                   * generator fail-closes on a larger value so a
                                   * prover cannot emit an unverifiable proof. */
    uint64_t        boundary_out; /* S8 Gate 2 TRANSPARENT leg OUT (public @
                                   * CONF_AGGZK_PUB_BOUT). Same < 2^63 bound. */
    uint64_t        fee;        /* S8 Gate 2: the committed fee (public @
                                 * CONF_AGGZK_PUB_FEE). The fee LEFT the balance
                                 * AIR (IS_FEE is pinned ZERO), so it can no
                                 * longer be derived from a FEE-role note block
                                 * or from the FEE_ACC column — both are now
                                 * identically zero. It is supplied here and is
                                 * FS/sighash-bound ONLY, exactly like
                                 * tx_binding: the consensus entry recomputes
                                 * the SAME value from the wire (sf->fee, which
                                 * it also pins == the header committed_fee), so
                                 * a prover that supplies a different fee
                                 * produces a proof whose publics cannot match
                                 * the verifier's and is rejected. */
    const uint64_t *tx_binding; /* 4 canonical lanes; FS-observed statement binding.
                                 * Production = conf_txbind_map(sighash_v5) (the
                                 * shared dnac_sighash_v5 codec → 4 lanes; the
                                 * consensus entry recomputes it from the wire).
                                 * NULL => zero. */
    const uint64_t *salt_draws; /* P4: M3b INPUT-mmcs salt stream A, or NULL
                                 * (unsalted). If set, num_salt_draws >=
                                 * DNAC_AGG_PROVER_SALT_DRAWS(h). */
    size_t          num_salt_draws;
    const uint64_t *fri_salt_draws; /* P1e-HIGH1: FRI-mmcs salt stream B (>=
                                 * DNAC_AGG_PROVER_FRI_SALT_DRAWS(h)). NULL =>
                                 * fall back to salt_draws@0 (KAT clone-seed
                                 * parity). Production MUST set this to an
                                 * INDEPENDENT entropy region. */
    size_t          num_fri_salt_draws;
    unsigned        log_height; /* height = 2^log_height, in [LOG_K, 10] */
    const uint64_t *draws;
    size_t          num_draws;  /* must equal DNAC_AGG_PROVER_TOTAL_DRAWS */
} dnac_agg_prover_instance_t;

/** Opaque produced proof; free with dnac_agg_prover_proof_free. */
typedef struct dnac_agg_prover_proof_s dnac_agg_prover_proof_t;

/**
 * Prove an aggregate instance and SELF-VERIFY (priming with the 45 publics +
 * zeta cross-check + dnac_fri_verify == DNAC_FRI_OK + the N-chunk constraint
 * check == OK). Fail-close on any inconsistency.
 */
dnac_prover_status_t dnac_agg_prover_prove(
    const dnac_agg_prover_instance_t *inst,
    dnac_agg_prover_proof_t         **out_proof);

/** Re-verify (priming + FRI + N-chunk constraint check). */
dnac_fri_status_t dnac_agg_prover_proof_verify(const dnac_agg_prover_proof_t *p);

/**
 * Phase-P PRODUCTION entry: prove at the PINNED shielded FRI params
 * (shielded_fri_params.h: num_queries=100, log_final_poly_len=0, query_pow=16
 * -> 216-bit conjectured soundness) with OS-entropy draws AND leaf salts
 * (genuinely salted/hiding, M3b mandatory — mirror of
 * dnac_conf_prover_prove_production). Requires inst->log_height ==
 * DNAC_SHIELDED_BASE_LOG_HEIGHT (the C1 fixed H=1024 pin; any other height is
 * rejected by the shielded verifier's committed-height pin). inst->draws /
 * salt_draws are ignored and filled internally (zeroized before free).
 * Self-verifies like dnac_agg_prover_prove.
 */
dnac_prover_status_t dnac_agg_prover_prove_production(
    const dnac_agg_prover_instance_t *inst,
    dnac_agg_prover_proof_t         **out_proof);

/**
 * Phase-P gate: serialize the proof (params + proof + commitments, wire v2
 * with M3b salt blocks) and verify the BYTES through the pinned consensus
 * entry dnac_fri_verify_wire_shielded, on a freshly primed transcript (same
 * priming as the struct self-verify). Success == DNAC_FRI_CODEC_OK AND
 * *out_fri_status == DNAC_FRI_OK.
 *
 * A TEST-params proof (dnac_agg_prover_prove) FAILS this with
 * DNAC_FRI_CODEC_ERR_SHIELDED_PARAM_MISMATCH — that rejection is itself a
 * KAT (the param pin bites). NOTE (honest scope): the transcript here is
 * primed from the prover's own statement; the consensus caller must instead
 * recompute the publics from the TX wire (Phase C, roadmap S6/C2). This gate
 * proves params/height/PoW/salt survive the wire — not statement recompute.
 */
dnac_fri_codec_status_t dnac_agg_prover_wire_selfcheck_shielded(
    const dnac_agg_prover_proof_t *p,
    dnac_fri_status_t             *out_fri_status);

/** Cross-check accessors (byte-match vs the reference Plonky3 proof). */
void dnac_agg_prover_proof_zeta(const dnac_agg_prover_proof_t *p,
                                gold_fp2_t *zeta, gold_fp2_t *zeta_next);
void dnac_agg_prover_proof_roots(const dnac_agg_prover_proof_t *p,
                                 dnac_p2_digest_t *trace_root,
                                 dnac_p2_digest_t *quot_root,
                                 dnac_p2_digest_t *rand_root);
const gold_fp2_t *dnac_agg_prover_proof_final_poly(
    const dnac_agg_prover_proof_t *p, size_t *out_len);
/** The computed public values (anchor[4] || num_input || nf_slot[M][4]). */
const gold_fp_t *dnac_agg_prover_proof_publics(const dnac_agg_prover_proof_t *p,
                                               size_t *out_len);

void dnac_agg_prover_proof_free(dnac_agg_prover_proof_t *p);

#ifdef DNAC_ZK_ENABLE_TEST_WIRE
/* ── C2.1 KAT-only exports (M5-gated like dnac_fri_verify_wire: only the zk
 * standalone Makefile defines DNAC_ZK_ENABLE_TEST_WIRE — absent from
 * libnodus/libdna, `nm`-provable). ── */

/** Serialize a produced aggregate proof to the DZKF wire bytes the consensus
 *  verify consumes (priming + zeta cross-check, NO verify — the KAT feeds the
 *  bytes to dnac_shielded_verify_statement). Caller frees *out_buf. */
dnac_fri_codec_status_t dnac_agg_prover_proof_wire_encode_testonly(
    const dnac_agg_prover_proof_t *p, uint8_t **out_buf, size_t *out_len);

/** CRIT-1 isolating forge: a production-params proof with an HONEST transcript
 *  over FORGED publics (quotient built from the TRUE trace publics). FRI
 *  accepts it; only the N-chunk constraint check rejects it. Self-verify is
 *  skipped (it would — correctly — fail). NEVER a production entry. */
dnac_prover_status_t dnac_agg_prover_prove_production_forged_publics_testonly(
    const dnac_agg_prover_instance_t *inst,
    const uint64_t                    forged_publics[CONF_AGGZK_NUM_PUBLICS],
    dnac_agg_prover_proof_t         **out_proof);

/** d4.c KAT-only: run the aggregate S1 generator (agg_zk_generate) to produce
 *  the RAW CONF_AGGZK_WIDTH-wide base trace (PRE-randomization, row-major
 *  canonical u64) + the 45 public values, so the batched-prover KAT
 *  (test_batch_shielded_agg) can feed the SAME witness to dnac_batch_prove as a
 *  1-instance is_zk=1 batch. trace_out = [(1<<log_height)*CONF_AGGZK_WIDTH],
 *  pub_out = [CONF_AGGZK_NUM_PUBLICS]. Returns 0 on an inconsistent instance
 *  (non-conserving / OOB / out-of-range boundary / NULL siblings on an INPUT
 *  block), 1 on success. NOT a production entry — the re-based prover calls
 *  agg_zk_generate directly at d4.c-2. */
int dnac_agg_zk_generate_trace_testonly(
    unsigned log_height, const dnac_agg_prover_instance_t *inst,
    uint64_t *trace_out, gold_fp_t *pub_out);
#endif /* DNAC_ZK_ENABLE_TEST_WIRE */

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ZK_STARK_PROVER_AGG_H */
