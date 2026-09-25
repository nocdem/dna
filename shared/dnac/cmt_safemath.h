/**
 * @file shared/dnac/cmt_safemath.h
 * @brief cometbft @709fd12b `libs/math/safemath.go` ported to C.
 *
 * ═══ ACTIVATION: INACTIVE ═══════════════════════════════════════════════
 * Wave R1-A of the cometbft → C consensus port. Additive only.
 * ════════════════════════════════════════════════════════════════════════
 *
 * Five overflow-checked conversions. In the reference three of them PANIC
 * on overflow (`SafeAddInt32`, `SafeSubInt32`, `SafeConvertInt32` —
 * safemath.go:16, :18, :27, :29, :38, :40) and two RETURN AN ERROR
 * (`SafeConvertUint8`, `SafeConvertInt8` — :49, :51, :60, :62). Under the
 * APPROVED substitution a panic becomes an error return, so all five have
 * the same shape here; which of them panicked in Go is recorded on each
 * function so the difference is not lost.
 *
 * The overflow verdict is REJECT, not FAULT: it is a deterministic
 * property of the two inputs, so every honest node reaches it on the same
 * values. It never means "this process is unwell".
 *
 * ── One C-specific difference in HOW the check is made ─────────────────
 * The reference tests `a > math.MaxInt32-b` in int32 arithmetic. In C the
 * same expression can itself overflow, which is undefined behaviour, so
 * every comparison below is evaluated in int64_t. The PREDICATE is
 * identical — the operands simply never wrap while it is being computed.
 *
 * ── Determinism ────────────────────────────────────────────────────────
 * Pure integer functions. No clock, no allocation, no global state.
 *
 * ── Zero consumers today ───────────────────────────────────────────────
 * `SafeConvertInt8` (:58-65) has no caller inside the ported set, and
 * `SafeConvertInt32`'s only reference caller is state/store.go:570, which
 * is outside the 33 ported files. Both are ported anyway ("the reference
 * in everything") and are recorded as dead C until a later wave calls them.
 *
 * Reference @709fd12b: libs/math/safemath.go, 65 lines,
 * be592544331912400aecaee1ccdc8834afdf8508857d32d475e3f6bfaf3b33d2.
 * Governing records: umbrella rev 3 (atlas-dec-d5e766defde138eb6dd02e5b81e735a8),
 * INVARIANT (atlas-dec-7495d3372e004b24b4f6cc7bff5caf07).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef SHARED_DNAC_CMT_SAFEMATH_H
#define SHARED_DNAC_CMT_SAFEMATH_H

#include <stdint.h>

#include "cmt_tmhash.h"   /* CMT_OK / CMT_REJECT / CMT_FAULT */

#ifdef __cplusplus
extern "C" {
#endif

/** cometbft@709fd12b libs/math/safemath.go:14-21 — `SafeAddInt32()`.
 *  The reference PANICS with ErrOverflowInt32 (:16, :18).
 *  @return CMT_OK, CMT_REJECT on overflow, CMT_FAULT if out is NULL. */
int cmt_safe_add_int32(int32_t a, int32_t b, int32_t *out);

/** cometbft@709fd12b libs/math/safemath.go:25-32 — `SafeSubInt32()`.
 *  The reference PANICS with ErrOverflowInt32 (:27, :29). */
int cmt_safe_sub_int32(int32_t a, int32_t b, int32_t *out);

/** cometbft@709fd12b libs/math/safemath.go:36-43 — `SafeConvertInt32()`.
 *  The reference PANICS with ErrOverflowInt32 (:38, :40). */
int cmt_safe_convert_int32(int64_t a, int32_t *out);

/** cometbft@709fd12b libs/math/safemath.go:47-54 — `SafeConvertUint8()`.
 *  The reference RETURNS ErrOverflowUint8 (:49, :51). Note the asymmetric
 *  bounds it uses: `a > MaxUint8` and `a < 0` — not `a < MinUint8`. */
int cmt_safe_convert_uint8(int64_t a, uint8_t *out);

/** cometbft@709fd12b libs/math/safemath.go:58-65 — `SafeConvertInt8()`.
 *  The reference RETURNS ErrOverflowInt8 (:60, :62). */
int cmt_safe_convert_int8(int64_t a, int8_t *out);

#ifdef __cplusplus
}
#endif

#endif /* SHARED_DNAC_CMT_SAFEMATH_H */
