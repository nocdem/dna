/**
 * @file shielded_fri_params.h
 * @brief Consensus-constant FRI/STARK parameters for the shielded pool (S0/C5).
 *
 * EXISTENTIAL SOUNDNESS BACKSTOP. Per dm-c6/parent §3.2 (E2), STARK-constraint +
 * DEEP-FRI soundness is the SOLE barrier against an in-pool mint (the shielded
 * pool has no cleartext value ground-truth). Therefore the FRI parameters that
 * fix the security level MUST be prover-independent consensus constants — a
 * verifier that reads them from the wire lets an attacker down-tune the level
 * (log_blowup=0 → ~0-bit low-degree test) and forge a false proof → mint
 * (parent RT-8 / dm-c5 C5a′).
 *
 * ── Pinned set (grounded, NOT invented) ────────────────────────────────────
 * The shielded proof is is_zk=1 (M3b salted hiding). The grounded production
 * params for a zk proof are Plonky3 `FriParameters::new_benchmark_zk`
 * (fri/src/config.rs:102-113 @ 82cfad73):
 *     log_blowup               = 2
 *     log_final_poly_len       = 0
 *     max_log_arity            = 1   (binary folding)
 *     num_queries              = 100
 *     commit_proof_of_work_bits= 0
 *     query_proof_of_work_bits = 16
 * Conjectured soundness (config.rs:42-43, ethSTARK eprint 2021/582):
 *     log_blowup·num_queries + query_proof_of_work_bits = 2·100 + 16 = 216 bits.
 * Only query_pow counts toward soundness (config.rs:43); commit_pow does NOT
 * (dm-c5 C5b′). 216 ≫ the 128-bit target. These are copied from config.rs, not
 * chosen (KAFADAN YASAK).
 *
 * ── Soundness POSTURE: CONJECTURED (decision 2026-07-23, user) ─────────────
 * The 216 above is the CONJECTURED bound, and Plonky3 flags the gap itself:
 * "Certain users may instead want to look at proven soundness, a more complex
 * calculation which isn't currently supported by this crate" (config.rs:40-41
 * @ 82cfad73). DNAC ships on the conjectured bound, after option B (a
 * Goldilocks³ substrate re-port to reach proven-128) and option C (declare an
 * explicit ~80-bit proven bar) were rejected. What that posture costs:
 *
 * (a) The PROVEN floor for THIS pin set is ~87 bits, not 216 — and raising
 *     num_queries does NOT lift it, because the binding term is
 *     query-INDEPENDENT: the proven bound carries an additive commit-phase term
 *       (m+½)^7·n² / (2·ρ^{3/2}·|F|).
 *     Here |F| is the FRI CHALLENGE field = Goldilocks² ≈ 2^128
 *     (fri_verifier.h:52), ρ = 1/4 = 2^-log_blowup, and n = the committed
 *     codeword length = 2^13 (DNAC_SHIELDED_COMMITTED_LOG_HEIGHT = 11, the
 *     height the verifier pins at shielded_verify.c:243, + log_blowup = 2; the
 *     prover's global max height agrees — batch_prover.c:630 computes
 *     log_gmh = ext_db + lb). At the optimal m=3 that term ALONE evaluates to
 *     ≈2^-87, so proven soundness cannot exceed ~87 bits at ANY query count;
 *     reaching proven-128 needs |F| ≳ 2^170. (For contrast, the per-query proven
 *     yield — 0.778 bit at blowup 2 / m=3 — would give ~94 bits at 100 queries
 *     + 16 pow. It is the additive floor, not the query count, that binds.)
 *     ⇒ Real security for this pin set sits between ~87 (proven) and 216
 *     (conjectured); ~87 is the conservative hedge. A property of the
 *     Goldilocks-class substrate, not a DNAC-specific defect.
 *
 * (b) Be precise about WHICH number the Nov-2025 result attacks. 216 is the
 *     UP-TO-CAPACITY yield (the full log_blowup per query) — and it is exactly
 *     the up-to-capacity conjecture family that was DISPROVED near capacity
 *     (Crites-Stewart 2025/2046; Diamond-Gruen 2025/2010), over large prime
 *     fields INCLUDING Goldilocks scale and for every rate ρ ∈ (0,1/2);
 *     Goldilocks is NOT exempt. What survives: the break is confined to within
 *     O(1/log n) BELOW capacity (δ → 1−ρ) and does NOT reach the Johnson radius
 *     1−√ρ (SoK 2026/1367; 2026/858 Chai-Fan; 2026/861). So the honest reading
 *     is NOT "216 is untouched" — it is: the capacity-lens headline lost its
 *     aggressive discount, the Johnson-lens proven floor (~87) is unaffected,
 *     and the residual risk lives in the gap between the two.
 *
 * (c) UPGRADE TRIGGER — RE-OPEN this pin set if ANY of:
 *       1. a correlated-agreement / list-decodability break is shown AT or
 *          BELOW the Johnson radius 1−√ρ (not merely near capacity) — that
 *          voids the conjectured basis itself;
 *       2. a concrete attack below 2^128 work against blowup-2 Goldilocks FRI
 *          is published;
 *       3. DNAC comes to require PROVEN 128 (regulatory / external audit),
 *          which needs |F| ≳ 2^170, i.e. a Goldilocks³ substrate re-port.
 *
 * ── Provenance of the numbers above (read this before quoting them) ────────
 * Derivation, formula and citations:
 * dnac/docs/plans/2026-07-23-fri-soundness-grounding-note.md (local-only,
 * gitignored). The three grades are NOT interchangeable:
 *   · RE-CHECKABLE IN THIS TREE — the config.rs quote / params / conjectured
 *     formula, the Goldilocks² challenge field, the height pins, and the
 *     n = 2^13 arithmetic. Open the cited lines and confirm them.
 *   · DERIVED (grounding-note §6; the author's own arithmetic, self-cross-
 *     checked against ethSTARK's published provable counts, and NOT part of the
 *     note's 3-vote round) — the ~87-bit floor, 0.778 b/q, ≳2^170, 2^244. Sound
 *     arithmetic on a formula this tree cannot re-derive: engineering-grade,
 *     not audited.
 *   · NOT VERIFIABLE OFFLINE — the attribution of the additive term to ethSTARK
 *     2021/582 Thm 3 / Eq. 10 and BCIKS 2020/654 Thm 7.2, and every Nov-2025 /
 *     2026 eprint claim in (b). The note's adversarial record (100 agents,
 *     3-vote, 21/25 confirmed 3-0) covers its PRE-§6 material — it does NOT
 *     cover §6, so do not quote that credential in support of the §6 numbers.
 *     The note lists a third Nov-2025 reference (arXiv 2604.09724) whose
 *     identifier encodes 2026-04 and thus contradicts its own dating; dropped
 *     here rather than propagated.
 * ⚠ None of the above substitutes for an external cryptographic review, which
 * is the right instrument before this pin set gates real value.
 *
 * ── Trace-height pin (dm-c5 C5e) ───────────────────────────────────────────
 * FRI-param pinning is necessary but INSUFFICIENT: the round count / lgmh is a
 * PROOF field bound to the statement only via the largest committed matrix
 * domain height. That height comes from the STARK caller, not the FRI params, so
 * it MUST ALSO be pinned. C1 pins the shielded AIR trace to a FIXED power-of-two
 * physical height H = 1024 = 2^10 (STARK_PROVER_MAX_HEIGHT, stark_prover.h:69 ==
 * SUM_BALANCE_MAX_OUTPUTS, sum_balance.h:83; the 8-in/8-out cap = 19 blocks ×
 * K=32 = 608 ≤ 1024, padded up). Variable note count is carried by IS_REAL
 * padding INSIDE this fixed height.
 *
 * ⚠ is_zk COMMITTED-DOMAIN DOUBLING (red-team S0-H1 fix, was WRONG). The shielded
 * proof is is_zk=1, and the is_zk hiding transform commits the trace/quotient/
 * random matrices at a domain of `base_degree_bits + 1`, NOT the physical
 * base_degree_bits. This is NOT "FRI-internal only" — it is the COMMITTED opening-
 * point domain the verifier reads. Grounded to the REAL Plonky3 is_zk proofs:
 * tools/vectors/conf_root_air_zk.json (`base_degree_bits:3 → degree_bits:4`) and
 * conf_root_air_zk_h16.json (`4 → 5`); the C prover matches (stark_prover_prove.c
 * is_zk path). So a physical H=2^10 shielded trace commits a main-trace domain of
 * log_size == 11 = base(10) + is_zk(1). The verifier pins THAT (== 11) and rejects
 * any other height. Pinning 10 (the physical base) would reject every honest
 * proof and let a smaller H=512 (base 9 → committed 10) trace pass.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_ZK_SHIELDED_FRI_PARAMS_H
#define DNAC_ZK_SHIELDED_FRI_PARAMS_H

#include <stdbool.h>
#include <stddef.h>

#include "fri_verifier.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Pinned scalar values (see file header for grounding to config.rs:102-113). */
#define DNAC_SHIELDED_FRI_LOG_BLOWUP           ((size_t)2)
#define DNAC_SHIELDED_FRI_LOG_FINAL_POLY_LEN   ((size_t)0)
#define DNAC_SHIELDED_FRI_MAX_LOG_ARITY        ((size_t)1)
#define DNAC_SHIELDED_FRI_NUM_QUERIES          ((size_t)100)
#define DNAC_SHIELDED_FRI_COMMIT_POW_BITS      ((size_t)0)
#define DNAC_SHIELDED_FRI_QUERY_POW_BITS       ((size_t)16)

/* Conjectured soundness bits = log_blowup·num_queries + query_pow (config.rs:43).
 * commit_pow is NOT credited (dm-c5 C5b′). */
#define DNAC_SHIELDED_FRI_SOUNDNESS_BITS       ((size_t)216)

/* Minimum acceptable soundness target (policy floor; the pinned set clears it).
 * 128 = the project's PQ security target. Read against the CONJECTURED bound
 * above (216 ≥ 128); the PROVEN floor for this pin set is ~87 and is NOT
 * reachable to 128 over Goldilocks² — see POSTURE section (a) in the header. */
#define DNAC_SHIELDED_FRI_SOUNDNESS_TARGET     ((size_t)128)

/* is_zk hiding is ON for every shielded proof (M3b salted). */
#define DNAC_SHIELDED_IS_ZK                    ((size_t)1)

/* G-SEC-P1-6 (P1c, 2026-07-22): the hiding-MMCS salt count is a CONSENSUS
 * CONSTANT, never proof data — in Plonky3 SALT_ELEMS is a const generic
 * (hiding_mmcs.rs:39-51). Under the Poseidon2 PaddingFreeSponge leaf hash a
 * wire-controlled preimage length is the documented overwrite-mode collision
 * construction (sponge.rs:27-30,36-88), so the verifier REJECTS any decoded
 * salt_elems (every batch opening AND every commit-phase step) != this pin,
 * fail-close. Mirrors the prover's A_SALT_ELEMS (stark_prover_agg.c CT-asserts
 * the equality).
 *
 * ⚠ ENFORCER CORRECTED (S2'-d, 2026-07-27). This comment named
 * `dnac_fri_verify_wire_shielded`, a function DELETED at d4.d with the v3 wire.
 * The pin is enforced by `sv_salt_elems_pinned` in shielded_verify.c. Note the
 * scope limit that rename exposes: the check lives in the SHIELDED entry only —
 * neither the decoder nor `dnac_batch_verify` enforces it, so any second
 * consumer of the v4 decode → batch-verify pair (P2 recursion) inherits a
 * wire-chosen salt count with no pin. Tracked in FLEET 005.
 *
 * ⚠ AND the companion half of this preimage length — the opened ROW width — is
 * NOT pinned at all in the is_zk path. See the corrected comment in
 * fri_verifier.c; closing it is the remainder of S2'-d. */
#define DNAC_SHIELDED_SALT_ELEMS               ((size_t)2)

/* Pinned PHYSICAL shielded-AIR trace height, log2 (C1 fixed H=1024=2^10). This is
 * the base_degree_bits, NOT what the verifier sees on the wire. */
#define DNAC_SHIELDED_BASE_LOG_HEIGHT          ((size_t)10)

/* Pinned COMMITTED main-trace domain height the verifier reads = base + is_zk
 * doubling (see header). == 11. THIS is the value the height guard compares
 * against; grounded to conf_root_air_zk.json base_degree_bits+1. */
#define DNAC_SHIELDED_COMMITTED_LOG_HEIGHT \
    (DNAC_SHIELDED_BASE_LOG_HEIGHT + DNAC_SHIELDED_IS_ZK)

/**
 * @brief The consensus-constant shielded FRI parameters. The verifier uses THIS,
 *        never the wire-decoded params, for every shielded proof.
 */
const dnac_fri_params_t *dnac_shielded_fri_params(void);

/**
 * @brief Exact field-by-field equality of two param sets (all six scalars).
 *        Used to REJECT a shielded proof whose embedded wire params differ from
 *        the pinned set (tamper detection; the pinned set is what actually
 *        verifies, this makes a mismatch an explicit reject not a silent ignore).
 */
bool dnac_fri_params_eq(const dnac_fri_params_t *a, const dnac_fri_params_t *b);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ZK_SHIELDED_FRI_PARAMS_H */
