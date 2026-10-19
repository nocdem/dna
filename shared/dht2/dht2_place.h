/**
 * @file shared/dht2/dht2_place.h
 * @brief DHT v2 — placement: nearest_R by XOR and the one eligibility rule.
 *
 * Design rev 5 §2 "Placement (4f, R = 4)" and "One eligibility function":
 * a record is held by the R = 4 members of S(H) nearest its placement key
 * by XOR (libp2p-specs 78e75c6f kad-dht/README.md:175 — the k closest
 * peers hold a value, the design's citation; R = 4 is ours, scope 4f);
 * fewer than R members → all of them.
 * NAMED DEVIATION — the distance: kad-dht/README.md:51 defines it as
 * XOR(sha256(key1), sha256(key2)). Here both sides are ALREADY SHA3-512
 * outputs (a placement key is an address or an inbox id; a member is a
 * node fp = SHA3-512 of its key), so the raw 64 bytes are XORed with no
 * further hashing, compared as 512-bit big-endian numbers.
 * Sets larger than DHT2_SET_MAX (256, the registry bound of design §13
 * row 13) are refused, which bounds the O(n²) duplicate scan.
 *   eligible(key) = nearest_R(key, S(H)) ∪ nearest_R(key, S(H − E)).
 * §9 D1: holders are a pure function of (key, set); XOR over DISTINCT fps
 * never ties (x ↦ x ⊕ key is a bijection), so the result order is total.
 * A set with a repeated fp is refused rather than tie-broken.
 *
 * No heap, no clock, no randomness, no global state.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef SHARED_DHT2_PLACE_H
#define SHARED_DHT2_PLACE_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include "dht2/dht2_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The min(R, n) members of `set` (n fps of 64 B, any order) nearest `key`
 * by XOR distance, compared as 512-bit big-endian numbers, nearest first.
 * `out_idx` receives indices into `set` (capacity ≥ min(R, n)).
 * @return the number written (0 for an empty set), or -1 on a NULL
 *         argument, n > DHT2_SET_MAX, or a repeated fp in `set`.
 */
int dht2_nearest_r(const uint8_t key[DHT2_HASH_LEN],
                   const uint8_t (*set)[DHT2_FP_LEN], size_t n,
                   size_t *out_idx);

/** eligible(key) membership: is `fp` in nearest_R(key, s0) ∪
 *  nearest_R(key, s1)? `s1` may be empty (n1 = 0). @return 1 yes, 0 no,
 *  -1 on a bad argument, a set over DHT2_SET_MAX, or a repeated fp. */
int dht2_eligible(const uint8_t key[DHT2_HASH_LEN],
                  const uint8_t (*s0)[DHT2_FP_LEN], size_t n0,
                  const uint8_t (*s1)[DHT2_FP_LEN], size_t n1,
                  const uint8_t fp[DHT2_FP_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* SHARED_DHT2_PLACE_H */
