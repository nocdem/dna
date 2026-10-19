/**
 * @file shared/dht2/dht2_place.c
 * @brief DHT v2 — nearest_R and eligible. See dht2_place.h.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dht2/dht2_place.h"

#include <string.h>

/* Compare XOR distances d(a) = a ⊕ key and d(b) = b ⊕ key as big-endian
 * 512-bit numbers. */
static int xor_cmp(const uint8_t *key, const uint8_t *a, const uint8_t *b)
{
    size_t k;

    for (k = 0; k < DHT2_HASH_LEN; k++) {
        uint8_t da = (uint8_t)(a[k] ^ key[k]);
        uint8_t db = (uint8_t)(b[k] ^ key[k]);

        if (da != db) {
            return (da < db) ? -1 : 1;
        }
    }
    return 0;
}

int dht2_nearest_r(const uint8_t key[DHT2_HASH_LEN],
                   const uint8_t (*set)[DHT2_FP_LEN], size_t n,
                   size_t *out_idx)
{
    size_t have = 0;
    size_t i, j;

    if (key == NULL || (set == NULL && n != 0) ||
        (out_idx == NULL && n != 0)) {
        return -1;
    }
    /* A repeated fp would make two members equidistant: refuse the set
     * (D1 claims no ties). O(n²) over a set of at most a few hundred
     * registry rows. */
    for (i = 0; i < n; i++) {
        for (j = i + 1; j < n; j++) {
            if (memcmp(set[i], set[j], DHT2_FP_LEN) == 0) {
                return -1;
            }
        }
    }
    /* Keep the R nearest in out_idx, sorted nearest first (insertion). */
    for (i = 0; i < n; i++) {
        size_t pos = have;

        while (pos > 0 && xor_cmp(key, set[i], set[out_idx[pos - 1]]) < 0) {
            pos--;
        }
        if (pos >= DHT2_R) {
            continue;
        }
        if (have < DHT2_R) {
            have++;
        }
        for (j = have - 1; j > pos; j--) {
            out_idx[j] = out_idx[j - 1];
        }
        out_idx[pos] = i;
    }
    return (int)have;
}

static int in_nearest(const uint8_t *key, const uint8_t (*set)[DHT2_FP_LEN],
                      size_t n, const uint8_t *fp)
{
    size_t idx[DHT2_R];
    int    m, k;

    m = dht2_nearest_r(key, set, n, idx);
    if (m < 0) {
        return -1;
    }
    for (k = 0; k < m; k++) {
        if (memcmp(set[idx[k]], fp, DHT2_FP_LEN) == 0) {
            return 1;
        }
    }
    return 0;
}

int dht2_eligible(const uint8_t key[DHT2_HASH_LEN],
                  const uint8_t (*s0)[DHT2_FP_LEN], size_t n0,
                  const uint8_t (*s1)[DHT2_FP_LEN], size_t n1,
                  const uint8_t fp[DHT2_FP_LEN])
{
    int a, b;

    if (key == NULL || fp == NULL) {
        return -1;
    }
    a = in_nearest(key, s0, n0, fp);
    b = in_nearest(key, s1, n1, fp);
    if (a < 0 || b < 0) {
        return -1;
    }
    return (a || b) ? 1 : 0;
}
