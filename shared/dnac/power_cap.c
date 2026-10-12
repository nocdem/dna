/**
 * @file shared/dnac/power_cap.c
 * @brief HF-6 slice 5a — water-fill power cap (contract: power_cap.h;
 *        design 2026-10-03-hf5-validator-owner-stake rev 6 §5, decisions
 *        Kurultay #14 K1, K2, K5). INERT: no consensus path calls it.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "power_cap.h"

#include <string.h>

#include "ledger_ids.h"   /* DNA_MAX_ACTIVE_VALIDATORS */
#include "res_meter.h"    /* dna_ck_add_u64 / dna_ck_mul_u64 / dna_ck_sub_u64 */

/** 1 iff entry a precedes entry b in the walk order: p DESC, then
 *  validator_id ASC (memcmp). Exact duplicates compare equal (0). */
static int pc_before(const uint64_t *p, const uint8_t (*vid)[64],
                     uint32_t a, uint32_t b) {
    if (p[a] != p[b]) return p[a] > p[b];
    return memcmp(vid[a], vid[b], 64) < 0;
}

int dna_power_cap_counted(const uint64_t *p,
                          const uint8_t (*validator_id)[64],
                          uint32_t n,
                          uint32_t ratio_bps,
                          uint64_t *counted_out) {
    uint32_t idx[DNA_MAX_ACTIVE_VALIDATORS];
    uint64_t out[DNA_MAX_ACTIVE_VALIDATORS];
    uint64_t total = 0;

    if (!p || !validator_id || !counted_out) return -1;
    if (n == 0 || n > DNA_MAX_ACTIVE_VALIDATORS) return -1;
    if (ratio_bps < DNA_POWER_CAP_BPS_MIN ||
        ratio_bps > DNA_POWER_CAP_BPS_MAX) return -1;

    for (uint32_t i = 0; i < n; i++) {
        if (p[i] == 0) return -1;
        if (dna_ck_add_u64(total, p[i], &total) != 0) return -1;
        idx[i] = i;
    }

    /* Insertion sort on the index array (n ≤ 128). Stable; with the total
     * order of pc_before only exact duplicates keep input order, and
     * those are interchangeable (equal p ⇒ equal counted). */
    for (uint32_t i = 1; i < n; i++) {
        uint32_t cur = idx[i];
        uint32_t j = i;
        while (j > 0 && pc_before(p, validator_id, cur, idx[j - 1])) {
            idx[j] = idx[j - 1];
            j--;
        }
        idx[j] = cur;
    }

    /* r′ = max(ratio, ⌈10000/n⌉); n ≥ 1 so this cannot overflow. */
    uint64_t r_prime = (10000u + n - 1u) / n;
    if (r_prime < ratio_bps) r_prime = ratio_bps;

    /* Walk (header "Index convention"): S_k = q[k] + … + q[n−1];
     * c_k = ⌊r′·S_k / (10000 − r′·k)⌋; stop when q[k] ≤ c_k. */
    uint64_t s_k = total;
    uint64_t cap = 0;
    int stopped = 0;
    for (uint32_t k = 0; k < n; k++) {
        uint64_t rk, den, num;
        if (dna_ck_mul_u64(r_prime, k, &rk) != 0) return -1;
        if (rk >= 10000u) return -1;            /* unreachable (header) */
        den = 10000u - rk;
        if (dna_ck_mul_u64(r_prime, s_k, &num) != 0) return -1;
        uint64_t c_k = num / den;
        uint64_t q_k = p[idx[k]];
        if (q_k <= c_k) {
            cap = c_k;
            stopped = 1;
            break;
        }
        if (dna_ck_sub_u64(s_k, q_k, &s_k) != 0) return -1;
    }
    if (!stopped) return -1;                    /* unreachable (header) */
    if (cap < 1) return -1;                     /* unreachable (header) */

    for (uint32_t i = 0; i < n; i++)
        out[i] = p[i] < cap ? p[i] : cap;
    memcpy(counted_out, out, (size_t)n * sizeof(uint64_t));
    return 0;
}
