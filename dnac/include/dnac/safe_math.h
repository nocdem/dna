/**
 * @file safe_math.h
 * @brief Safe integer arithmetic for DNAC
 *
 * Uses compiler builtins (__builtin_*_overflow) to detect
 * integer overflow in uint64_t amount arithmetic.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef DNAC_SAFE_MATH_H
#define DNAC_SAFE_MATH_H

#include <stdint.h>

/**
 * Safe addition: *result = a + b
 * @return 0 on success, -1 on overflow
 */
static inline int safe_add_u64(uint64_t a, uint64_t b, uint64_t *result) {
    if (__builtin_add_overflow(a, b, result)) return -1;
    return 0;
}

/**
 * Safe multiplication: *result = a * b
 * @return 0 on success, -1 on overflow
 */
static inline int safe_mul_u64(uint64_t a, uint64_t b, uint64_t *result) {
    if (__builtin_mul_overflow(a, b, result)) return -1;
    return 0;
}

#endif /* DNAC_SAFE_MATH_H */
