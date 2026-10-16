/**
 * @file shared/dnac/cmt_fraction.h
 * @brief cometbft @v0.38.26 `libs/math/fraction.go` ported to C — the
 *        `Fraction` type, and only the type.
 *
 * ═══ STATUS: NO PRODUCTION CALLER ═══════════════════════════════════════
 * Its consumers are the light-client verification functions:
 * `cmt_verify_commit_light_trusting*` (cmt_validation.h, types/validation.go
 * :126-193), their `cmt_validator_set_*` method forms (validator_set.go
 * :780-797) and cmt_light_verifier.h (light/verifier.go). None of them is
 * called by a node today; they exist for the bandwidth / storage light
 * client (docs/plans/2026-10-16-bandwidth-role-design.md §1 B9).
 * ════════════════════════════════════════════════════════════════════════
 *
 * ── WHAT IS PORTED ─────────────────────────────────────────────────────
 * `type Fraction struct` (fraction.go:11-18): a numerator and a
 * denominator, both uint64. The reference's own doc comment says
 * "Fraction must be positive"; the TYPE does not enforce that and neither
 * does this one — the functions that take a Fraction check what they
 * need (validation.go:162 refuses a zero Denominator; light/verifier.go
 * :197-204 `ValidateTrustLevel` checks the [1/3, 1] range).
 *
 * ── taşınmadı (not ported), with the reason ────────────────────────────
 *   · fraction.go:20-22 `String()`       — display only; the ported code
 *       uses it only inside error text (light/verifier.go:201), and this
 *       port's errors carry no text.
 *   · fraction.go:24-48 `ParseFraction()` — parses a config string
 *       ("1/3"); no ported function calls it. The light client's CONFIG
 *       is not ported. NOTE: it is the only place the reference bounds
 *       both fields to MaxInt64 (:44-46); a Fraction built any other way
 *       is not bounded, which is why the Trusting family's
 *       `int64(trustLevel.Numerator)` conversion (validation.go:170) is
 *       ported as a bit-reinterpreting cast, not assumed in range.
 *
 * ── Determinism ────────────────────────────────────────────────────────
 * A plain value type. No function, no clock, no randomness.
 *
 * Reference @v0.38.26: libs/math/fraction.go.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef SHARED_DNAC_CMT_FRACTION_H
#define SHARED_DNAC_CMT_FRACTION_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** cometbft@v0.38.26 libs/math/fraction.go:11-18 — `type Fraction`.
 *  "Fraction defined in terms of a numerator divided by a denominator in
 *  uint64 format. Fraction must be positive." (:11-12) */
typedef struct {
    /** fraction.go:14-15 — "The portion of the denominator in the
     *  faction, e.g. 2 in 2/3." */
    uint64_t numerator;
    /** fraction.go:16-17 — "The value by which the numerator is divided,
     *  e.g. 3 in 2/3." */
    uint64_t denominator;
} cmt_fraction_t;

#ifdef __cplusplus
}
#endif

#endif /* SHARED_DNAC_CMT_FRACTION_H */
