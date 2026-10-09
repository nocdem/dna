/**
 * @file shared/dnac/power_cap.h
 * @brief HF-6 slice 5a — the water-fill power cap, ONE pure function
 *        (INERT: no consensus path calls it yet).
 *
 * Governing record: design docs/plans/2026-10-03-hf5-validator-owner-stake
 * -design.md rev 6 §5 "Güç tavanı — tek fonksiyon (K1, K2, K5)";
 * decisions docs/plans/decisions/2026-10-08-kurultay-14-hf6-summary.md
 * item 1 (formula), K1 (the cap is a SHARE limit on COUNTED power, the old
 * max(floor(P×r), floor(P/n)) is gone), K2 (reward denominator Σcounted —
 * a consumer concern, not this function's), K5 (ratio range [500, 3000]).
 *
 * ── Rule (§5) ──────────────────────────────────────────────────────────
 *   Input: scalar arrays, not structs. p_i = total_stake_i /
 *   DNAC_DECIMAL_UNIT (the caller divides; every p_i ≥ 1, set non-empty),
 *   validator_id_i (64 bytes, tie-break only), ratio_bps.
 *   Sort p DESC, ties validator_id ASC (memcmp). r′ = max(ratio_bps,
 *   ⌈10000/n⌉). For k = 0, 1, …:
 *       S_k = Σ_{i>k} p_i,   c_k = floor(r′·S_k / (10000 − r′·k));
 *   stop at the first k with p_{k+1} ≤ c_k; counted_i = min(p_i, c_k).
 *
 * ── Index convention (derived from the §5 examples, stated here) ───────
 *   §5's indices are 1-BASED over the sorted order p_1 ≥ p_2 ≥ … ≥ p_n:
 *   k = number of leading entries already capped; S_k = p_{k+1} + … + p_n
 *   (the uncapped tail, INCLUDING p_{k+1}); the stop test is on p_{k+1},
 *   the largest uncapped entry. In the 0-based array q[] used in the code:
 *       S_k = q[k] + … + q[n−1];  stop when q[k] ≤ c_k.
 *   It is the water-fill fixed point: with the k capped entries at c the
 *   counted total is k·c + S_k, and "c's share ≤ r′" is
 *   c·10000 ≤ r′·(k·c + S_k)  ⇔  c·(10000 − r′·k) ≤ r′·S_k.
 *
 *   The three §5 examples (all reproduced, ratio 3000):
 *     [88,2,2,2,2,2,2] → r′=3000; k=0 S=100 c=30 (88>30); k=1 S=12
 *                        c=⌊36000/7000⌋=5, 2≤5 stop → [5,2,2,2,2,2,2]
 *     [45,45,10]       → r′=⌈10000/3⌉=3334; k=0 S=100 c=33; k=1 S=55
 *                        c=⌊183370/6666⌋=27; k=2 S=10 c=⌊33340/3332⌋=10,
 *                        10≤10 stop → [10,10,10]
 *     [10]×7           → r′=3000; k=0 S=70 c=21, 10≤21 stop → unchanged
 *   The other reading (0-based, S_k EXCLUDING q[k]) gives [4,2,…] for the
 *   first and never stops on the second; [10]×7 does not separate the two
 *   readings. Independent oracle: shared/dnac/tests/power_cap_oracle.py.
 *
 * ── Guarantees ─────────────────────────────────────────────────────────
 *   - Termination (k < n): r′·n ≥ 10000, so for the first k with
 *     r′·(k+1) ≥ 10000 (at the latest k = n−1) the denominator
 *     d = 10000 − r′·k satisfies 0 < d ≤ r′, hence c_k ≥ S_k ≥ q[k] and the
 *     walk stops there. Every k the walk reaches before that has
 *     r′·k < 10000, i.e. d > 0. The "d ≤ 0" and "walked past n" -1 paths
 *     are therefore UNREACHABLE for valid input; they stay as fail-closed
 *     guards.
 *   - counted_i ≥ 1: at the stop c_k ≥ q[k] ≥ 1 and every p_i ≥ 1. The
 *     explicit c < 1 guard is likewise unreachable.
 *   - No counted share exceeds r′: capped entries satisfy c·d ≤ r′·S_k
 *     (floor), uncapped entries are ≤ c. The promise is "no share exceeds
 *     r′" — for n ≤ 3 r′ is the average (100% / 50% / 33.34%), not the ratio.
 *   - Overflow: §5 bounds 10000·Σp < 2.4·10^17 for 128 × UINT64_MAX/10^8;
 *     every sum/product here is still CHECKED (dna_ck_*_u64,
 *     shared/dnac/res_meter.h) and an overflow returns -1 — inputs outside
 *     the §5 precondition fail closed instead of wrapping.
 *
 * ── Determinism ────────────────────────────────────────────────────────
 *   Integer only, no float, no clock, no randomness. The walk order is the
 *   total order (p DESC, validator_id ASC); an exact duplicate (same p AND
 *   same id) is interchangeable, and in fact equal p always yield equal
 *   counted (counted_i = min(p_i, c)), so the tie-break fixes the walk but
 *   can never change an output. The function sorts an internal index
 *   array; the caller's arrays are never reordered and counted_out is in
 *   the CALLER'S input order.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef SHARED_DNAC_POWER_CAP_H
#define SHARED_DNAC_POWER_CAP_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** POWER_CAP_BPS legal range (K5, design §5): [500, 3000] bps. */
#define DNA_POWER_CAP_BPS_MIN 500u
#define DNA_POWER_CAP_BPS_MAX 3000u

/**
 * Water-fill counted power (design §5).
 *
 * @param p            n powers (whole coins), each ≥ 1, caller order.
 * @param validator_id n 64-byte ids, same order as p (tie-break only).
 * @param n            1 .. DNA_MAX_ACTIVE_VALIDATORS (128).
 * @param ratio_bps    DNA_POWER_CAP_BPS_MIN .. DNA_POWER_CAP_BPS_MAX.
 * @param counted_out  n outputs, written in the caller's order ONLY on
 *                     success; untouched on -1.
 * @return 0 on success; -1 on a NULL argument, n == 0,
 *         n > DNA_MAX_ACTIVE_VALIDATORS, ratio outside [500, 3000], any
 *         p_i == 0, u64 overflow, or a denominator ≤ 0.
 */
int dna_power_cap_counted(const uint64_t *p,
                          const uint8_t (*validator_id)[64],
                          uint32_t n,
                          uint32_t ratio_bps,
                          uint64_t *counted_out);

#ifdef __cplusplus
}
#endif

#endif /* SHARED_DNAC_POWER_CAP_H */
