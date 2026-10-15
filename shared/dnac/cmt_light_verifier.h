/**
 * @file shared/dnac/cmt_light_verifier.h
 * @brief cometbft @v0.38.26 `light/verifier.go` ported to C — verifying a
 *        new header against a trusted one WITHOUT executing blocks — plus
 *        the `types.SignedHeader` type it needs (types/light.go:117-162)
 *        and the three typed errors it returns (light/errors.go:11-41).
 *
 * ═══ STATUS: NO PRODUCTION CALLER ═══════════════════════════════════════
 * Ported 2026-10-16 for the bandwidth and storage roles, which become
 * LIGHT CLIENTS (no block execution, no EVM) so that they can run on
 * Windows: docs/plans/2026-10-16-bandwidth-role-design.md §1 B9 and its
 * "Storage" bullet; decision
 * docs/plans/decisions/2026-10-16-relay-port-4003-bandwidth-role.md.
 * Nothing in a node calls this file yet. It sits in nodus's COMMON
 * (non-WIN32) source list next to cmt_validation.c so that it compiles
 * on Windows.
 * ════════════════════════════════════════════════════════════════════════
 *
 * ── WHAT THIS FILE DECIDES ─────────────────────────────────────────────
 * Whether a light client may move its trust from a header it already
 * trusts (height X) to a new header (height Y), given the validator set
 * that signed the new header:
 *   · ADJACENT (Y = X+1, verifier.go:93-132): the new header's
 *     ValidatorsHash must equal the trusted header's NextValidatorsHash,
 *     and more than 2/3 of the new set must have signed it;
 *   · NON-ADJACENT (verifier.go:32-79, "skipping" verification): at least
 *     `trust_level` (default 1/3) of the TRUSTED set must have signed the
 *     new header, and more than 2/3 of the new set too;
 *   · in both, the trusted header must not have expired (trusting period)
 *     and the new header must be well formed, later than the trusted one
 *     and not from further in the future than `max_clock_drift`.
 * And, separately, whether an OLDER header is the parent of a trusted one
 * (`VerifyBackwards`, verifier.go:212-245).
 *
 * ── THE CLOCK ──────────────────────────────────────────────────────────
 * NO FUNCTION HERE READS A CLOCK. The reference passes `now` and every
 * duration (`trustingPeriod`, `maxClockDrift`) as PARAMETERS
 * (verifier.go:37-39, :97-99, :140-142, :157-158, :207), and so does this
 * port: `now` is a `cmt_time_t`, a duration is int64 nanoseconds — Go's
 * `time.Duration` is an int64 nanosecond count, and the port already
 * represents durations that way (cmt_config.h, cmt_params.h:127). Time
 * arithmetic uses cmt_time_add_ns / cmt_time_after / cmt_time_before
 * (cmt_time.h). This verifier is NOT on any consensus path: it decides
 * what ONE light client believes, never what a block contains.
 *
 * ── DEVIATIONS, each forced by a port type ─────────────────────────────
 *  · `block_protocol` is a PARAMETER of `cmt_signed_header_validate_basic`,
 *    `cmt_light_verify_backwards` and every entry point that reaches
 *    `cmt_header_validate_basic` (non-adjacent, adjacent, verify). The
 *    value Version.Block must equal — the host's, normally
 *    CMT_BLOCK_PROTOCOL. It is a parameter because `version.BlockProtocol`
 *    is a build-time constant of the reference binary and a chain
 *    parameter here (the same wording as cmt_block.h:403-406).
 *  · Go's typed error VALUES become CMT_REJECT plus the optional
 *    `cmt_light_error_t` out-parameter, the pattern cmt_validation.h set
 *    with `cmt_vs_error_t` (cmt_validation.h:71-73). The three named
 *    error types of light/errors.go that verifier.go returns —
 *    ErrOldHeaderExpired, ErrNewValSetCantBeTrusted, ErrInvalidHeader —
 *    are carried with their payloads; every unnamed `errors.New` /
 *    `fmt.Errorf` is CMT_REJECT with code CMT_LIGHT_ERR_NONE. Error TEXT
 *    is not carried.
 *  · A Go nil-pointer DEREFERENCE (a panic) is CMT_FAULT: an argument
 *    pointer, the trusted header's or the untrusted header's embedded
 *    `*Header` read at verifier.go:42 / :101 / :145 / :208 / :226 before
 *    any validation. A nil `*Header` / `*Commit` INSIDE a SignedHeader
 *    that `SignedHeader.ValidateBasic` itself tests (light.go:135-140) is
 *    CMT_REJECT, because there the reference RETURNS an error and those
 *    are optional proto fields a peer can leave out — the reason
 *    deviation register R1B-10 uses for NULL → FAULT ("cannot arrive from
 *    the wire") does not hold for them.
 *  · `untrustedVals.Hash()` (verifier.go:183) needs leaf scratch in this
 *    port (`cmt_validator_set_hash`, cmt_validator_set.h:700-723); it is
 *    heap-allocated inside the verifier and freed before return, as
 *    `cmt_validator_set_verify_commit_extended` does. So the non-adjacent,
 *    adjacent and verify entry points ALLOCATE; nothing else here does.
 *
 * ── Determinism ────────────────────────────────────────────────────────
 * Every function is a pure function of its arguments. No clock, no
 * randomness, no map, no floating point. Signatures are visited in
 * commit-list order (cmt_verify_commit_single). Two light clients given
 * the same headers, sets, `now` and parameters reach the same verdict.
 *
 * ── taşınmadı (not ported), with the reason ────────────────────────────
 *  light/errors.go
 *   · :19-21, :29-31, :39-41 the three `Error()` methods — display only.
 *   · :43-121, everything else (ErrFailedHeaderCrossReferencing,
 *     ErrVerificationFailed, ErrLightClientAttack, ErrNoWitnesses,
 *     ErrConflictingHeaders, ErrProposerPrioritiesDiverge, errBadWitness,
 *     errNoDivergence) — none is returned by verifier.go; their producers
 *     are light/client.go and light/detector.go, which are not ported.
 *  types/light.go
 *   · :123-126 `IsEmpty`, :164-226 `String` / `StringIndented` /
 *     `ToProto` / `SignedHeaderFromProto`, and the `LightBlock` type with
 *     its methods (:12-111) — verifier.go calls none of them.
 *
 * Reference @v0.38.26 (SHA-256 verified before use):
 *   light/verifier.go 245 lines
 *     24c785164d16144ebaf26a29cbddf34a74aae42059690e96868916879923eca3
 *   light/errors.go   121 lines
 *     51e459b8405150021692a1867bce0e345eeff1a9baf12b24e756fc10f9c38dd3
 *   types/light.go    226 lines
 *     513cfd434dadf086a27daaa29a35a3014a356d684dbd89b0f931e6c0c5ea157d
 * Governing records: pin decision
 * docs/plans/decisions/2026-09-30-cometbft-pin-v0.38.26.md; the bandwidth
 * role decision above.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef SHARED_DNAC_CMT_LIGHT_VERIFIER_H
#define SHARED_DNAC_CMT_LIGHT_VERIFIER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "cmt_tmhash.h"          /* CMT_OK / CMT_REJECT / CMT_FAULT       */
#include "cmt_time.h"            /* cmt_time_t                            */
#include "cmt_block.h"           /* cmt_header_t, cmt_commit_t            */
#include "cmt_validator_set.h"   /* cmt_validator_set_t, cmt_vs_error_t   */
#include "cmt_fraction.h"        /* cmt_fraction_t                        */

#ifdef __cplusplus
extern "C" {
#endif

/* ══ types/light.go — SignedHeader ════════════════════════════════════ */

/**
 * cometbft@v0.38.26 types/light.go:116-121 — `type SignedHeader struct`:
 * "a header along with the commits that prove it". Both members are
 * POINTERS in the reference (`*Header` embedded, `Commit *Commit`) and
 * may be nil; so they are here, and neither is owned.
 */
typedef struct {
    const cmt_header_t *header;   /* light.go:118 `*Header` (embedded) */
    const cmt_commit_t *commit;   /* light.go:120 `Commit *Commit`     */
} cmt_signed_header_t;

/**
 * cometbft@v0.38.26 types/light.go:128-162 —
 * `(sh SignedHeader) ValidateBasic(chainID)`.
 *
 * In the reference's order: a header is present (:135-137) and a commit
 * is present (:138-140) — both CMT_REJECT, see the file header —; the
 * header passes `Header.ValidateBasic` (:142-144) and the commit
 * `Commit.ValidateBasic` (:145-147); the header's ChainID equals
 * `chain_id` (:149-151); the commit's height equals the header's
 * (:154-156); and the header's hash equals the commit's BlockID hash
 * (:157-159). "This does not actually check the cryptographic
 * signatures." (:131)
 *
 * The hash comparison is Go's `bytes.Equal(sh.Hash(), Commit.BlockID.Hash)`.
 * `Header.Hash()` returns nil for an empty ValidatorsHash (block.go:446-
 * 448; CMT_HASH_NIL in cmt_header_hash), which `Header.ValidateBasic`
 * permits; `bytes.Equal(nil, x)` is true exactly when x is empty, and that
 * is what is reproduced.
 *
 * @param block_protocol the value Version.Block must equal — the host's,
 *        normally CMT_BLOCK_PROTOCOL. It is a parameter because
 *        `version.BlockProtocol` is a build-time constant of the reference
 *        binary and a chain parameter here.
 * @return CMT_OK, CMT_REJECT; CMT_FAULT on a NULL `sh` (the reference
 *         takes it by value), a NULL `chain_id` with a non-zero length, or
 *         a hash backend failure.
 */
int cmt_signed_header_validate_basic(const cmt_signed_header_t *sh,
                                     const uint8_t *chain_id,
                                     size_t chain_id_len,
                                     uint64_t block_protocol);

/* ══ light/errors.go — the three typed errors verifier.go returns ════ */

#define CMT_LIGHT_ERR_NONE                         0
/** light/errors.go:11-17 — `ErrOldHeaderExpired{At, Now}`: "the old
 *  (trusted) header has expired according to the given trustingPeriod and
 *  current time. If so, the light client must be reset subjectively." */
#define CMT_LIGHT_ERR_OLD_HEADER_EXPIRED           1
/** light/errors.go:23-27 — `ErrNewValSetCantBeTrusted{Reason}`: "the new
 *  validator set cannot be trusted because < 1/3rd (+trustLevel+) of the
 *  old validator set has signed." Reason is an
 *  ErrNotEnoughVotingPowerSigned. */
#define CMT_LIGHT_ERR_NEW_VAL_SET_CANT_BE_TRUSTED  2
/** light/errors.go:33-37 — `ErrInvalidHeader{Reason}`: "the header either
 *  failed the basic validation or commit is not signed by 2/3+." */
#define CMT_LIGHT_ERR_INVALID_HEADER               3

/**
 * The reference's typed error values, as one out-parameter (the
 * `cmt_vs_error_t` pattern, cmt_validator_set.h:289-308). On CMT_OK and
 * on CMT_FAULT `code` is CMT_LIGHT_ERR_NONE. On CMT_REJECT:
 *   · CMT_LIGHT_ERR_OLD_HEADER_EXPIRED — `at` (= trusted time +
 *     trustingPeriod) and `now`, errors.go:15-16 (verifier.go:47, :106);
 *   · CMT_LIGHT_ERR_NEW_VAL_SET_CANT_BE_TRUSTED — `reason` is the
 *     ErrNotEnoughVotingPowerSigned {got, needed} (errors.go:26;
 *     verifier.go:61-62);
 *   · CMT_LIGHT_ERR_INVALID_HEADER — the wrapper of errors.go:36. Its
 *     `Reason` is an arbitrary error in Go; when that error is an
 *     ErrNotEnoughVotingPowerSigned (verifier.go:73-76, :126-129)
 *     `reason` carries it, otherwise `reason.code` is CMT_VS_ERR_NONE;
 *   · CMT_LIGHT_ERR_NONE — an unnamed error the reference does NOT wrap:
 *     the adjacency checks (verifier.go:43, :102), the NextValidatorsHash
 *     mismatch (:117-122), a Trusting rejection that is not a voting-power
 *     shortfall (`default: return e`, :63-64), and ValidateTrustLevel
 *     (:201).
 */
typedef struct {
    int            code;     /* CMT_LIGHT_ERR_*                          */
    cmt_time_t     at;       /* errors.go:15 — OLD_HEADER_EXPIRED only   */
    cmt_time_t     now;      /* errors.go:16 — OLD_HEADER_EXPIRED only   */
    cmt_vs_error_t reason;   /* errors.go:26, :36 — see above            */
} cmt_light_error_t;

/* ══ light/verifier.go ════════════════════════════════════════════════ */

/** cometbft@v0.38.26 light/verifier.go:13-17 — `DefaultTrustLevel`:
 *  "new header can be trusted if at least one correct validator signed
 *  it." — 1/3. */
#define CMT_LIGHT_DEFAULT_TRUST_LEVEL_NUMERATOR    1u
#define CMT_LIGHT_DEFAULT_TRUST_LEVEL_DENOMINATOR  3u
/** The same value as a `cmt_fraction_t` compound literal. */
#define CMT_LIGHT_DEFAULT_TRUST_LEVEL \
    ((cmt_fraction_t){ CMT_LIGHT_DEFAULT_TRUST_LEVEL_NUMERATOR, \
                       CMT_LIGHT_DEFAULT_TRUST_LEVEL_DENOMINATOR })

/**
 * cometbft@v0.38.26 light/verifier.go:19-79 — `VerifyNonAdjacent()`.
 *
 * In the reference's order:
 *   a) the heights must NOT be adjacent (:42-44, unnamed error);
 *   b) the trusted header must not have expired (:46-48 →
 *      OLD_HEADER_EXPIRED, `at` = trusted time + trusting_period);
 *   c) the untrusted header must pass verifyNewHeaderAndVals (:50-55 →
 *      INVALID_HEADER): SignedHeader.ValidateBasic against the TRUSTED
 *      header's chain id, a greater height, a strictly later time, a time
 *      strictly before `now + max_clock_drift`, and a ValidatorsHash equal
 *      to `untrusted_vals`' hash;
 *   d) at least `trust_level` of `trusted_vals` signed the untrusted
 *      commit (:57-66, `VerifyCommitLightTrusting`) — a voting-power
 *      shortfall is NEW_VAL_SET_CANT_BE_TRUSTED, any other rejection is
 *      returned unwrapped (`default: return e`, :63-64);
 *   e) more than 2/3 of `untrusted_vals` signed it (:68-76,
 *      `VerifyCommitLight` → INVALID_HEADER). "this should always be the
 *      last check because untrustedVals can be intentionally made very
 *      large to DOS the light client" (:70-72).
 * `trust_level` is NOT range-checked here; see
 * `cmt_light_validate_trust_level`.
 *
 * @param trusted_vals the set at height X or X+1 (:34). NOT const: its
 *        TotalVotingPower cache may be written, as in the reference.
 * @param untrusted_vals the set at height Y (:36). NOT const, same reason.
 * @param trusting_period, max_clock_drift nanoseconds (Go time.Duration).
 * @param now the caller's current time; never read from a clock here.
 * @param block_protocol the value Version.Block must equal — the host's,
 *        normally CMT_BLOCK_PROTOCOL. It is a parameter because
 *        `version.BlockProtocol` is a build-time constant of the reference
 *        binary and a chain parameter here.
 * @param err may be NULL; see `cmt_light_error_t`.
 * @return CMT_OK, CMT_REJECT; CMT_FAULT on a NULL argument, a NULL
 *         embedded header in either SignedHeader (the reference
 *         dereferences both at :42), or an allocation / backend failure.
 */
int cmt_light_verify_non_adjacent(const cmt_signed_header_t *trusted_header,
                                  cmt_validator_set_t *trusted_vals,
                                  const cmt_signed_header_t *untrusted_header,
                                  cmt_validator_set_t *untrusted_vals,
                                  int64_t trusting_period,
                                  cmt_time_t now,
                                  int64_t max_clock_drift,
                                  cmt_fraction_t trust_level,
                                  uint64_t block_protocol,
                                  cmt_light_error_t *err);

/**
 * cometbft@v0.38.26 light/verifier.go:81-132 — `VerifyAdjacent()`.
 *
 * In the reference's order:
 *   a) the heights MUST be adjacent (:101-103, unnamed error);
 *   b) the trusted header must not have expired (:105-107);
 *   c) verifyNewHeaderAndVals (:109-114 → INVALID_HEADER), as in
 *      `cmt_light_verify_non_adjacent` step c;
 *   d) the untrusted ValidatorsHash must equal the trusted
 *      NextValidatorsHash (:116-123 — an UNNAMED error, not wrapped in
 *      ErrInvalidHeader);
 *   e) more than 2/3 of `untrusted_vals` signed it (:125-129 →
 *      INVALID_HEADER).
 * `trusted_vals` is not a parameter — the reference does not take one.
 *
 * @param block_protocol the value Version.Block must equal — the host's,
 *        normally CMT_BLOCK_PROTOCOL. It is a parameter because
 *        `version.BlockProtocol` is a build-time constant of the reference
 *        binary and a chain parameter here.
 * @return CMT_OK, CMT_REJECT, CMT_FAULT (as for non-adjacent; the
 *         reference dereferences both headers at :101).
 */
int cmt_light_verify_adjacent(const cmt_signed_header_t *trusted_header,
                              const cmt_signed_header_t *untrusted_header,
                              cmt_validator_set_t *untrusted_vals,
                              int64_t trusting_period,
                              cmt_time_t now,
                              int64_t max_clock_drift,
                              uint64_t block_protocol,
                              cmt_light_error_t *err);

/**
 * cometbft@v0.38.26 light/verifier.go:134-151 — `Verify()`: "combines
 * both VerifyAdjacent and VerifyNonAdjacent functions". Non-adjacent when
 * `untrusted height != trusted height + 1` (:145-148), adjacent otherwise
 * (:150) — in which case `trusted_vals` and `trust_level` are unused, as
 * in the reference.
 *
 * @param block_protocol the value Version.Block must equal — the host's,
 *        normally CMT_BLOCK_PROTOCOL. It is a parameter because
 *        `version.BlockProtocol` is a build-time constant of the reference
 *        binary and a chain parameter here.
 * @return what the chosen function returns; CMT_FAULT on a NULL header.
 */
int cmt_light_verify(const cmt_signed_header_t *trusted_header,
                     cmt_validator_set_t *trusted_vals,
                     const cmt_signed_header_t *untrusted_header,
                     cmt_validator_set_t *untrusted_vals,
                     int64_t trusting_period,
                     cmt_time_t now,
                     int64_t max_clock_drift,
                     cmt_fraction_t trust_level,
                     uint64_t block_protocol,
                     cmt_light_error_t *err);

/**
 * cometbft@v0.38.26 light/verifier.go:194-204 — `ValidateTrustLevel()`:
 * "checks that trustLevel is within the allowed range [1/3, 1] … 1/3 is
 * the minimum amount of trust needed which does not break the security
 * model." Rejects `Numerator*3 < Denominator` (:198), `Numerator >
 * Denominator` (:199) and `Denominator == 0` (:200). The multiplication
 * is uint64 and WRAPS, in Go and in C alike — reproduced, not "fixed".
 * @return CMT_OK or CMT_REJECT.
 */
int cmt_light_validate_trust_level(cmt_fraction_t lvl);

/**
 * cometbft@v0.38.26 light/verifier.go:206-210 — `HeaderExpired()`:
 * `!(h.Time + trustingPeriod).After(now)` — so a header whose expiry
 * EQUALS `now` has expired.
 * @param out receives the verdict.
 * @return CMT_OK; CMT_FAULT on NULL `h`, `h->header` (the reference
 *         dereferences it at :208) or `out`.
 */
int cmt_light_header_expired(const cmt_signed_header_t *h,
                             int64_t trusting_period, cmt_time_t now,
                             bool *out);

/**
 * cometbft@v0.38.26 light/verifier.go:212-245 — `VerifyBackwards()`:
 * "verifies an untrusted header with a height one less than that of an
 * adjacent trusted header". Every failure is INVALID_HEADER (:220):
 * `Header.ValidateBasic` (:222-224), same ChainID (:226-228), a strictly
 * EARLIER time (:230-235), and the untrusted header's hash equal to the
 * trusted header's LastBlockID hash (:237-242, `bytes.Equal` — a nil
 * hash equals an empty one, as in `cmt_signed_header_validate_basic`).
 * NOTE: the height relation is NOT checked here, by the reference either.
 *
 * @param block_protocol the value Version.Block must equal — the host's,
 *        normally CMT_BLOCK_PROTOCOL. It is a parameter because
 *        `version.BlockProtocol` is a build-time constant of the reference
 *        binary and a chain parameter here.
 * @return CMT_OK, CMT_REJECT; CMT_FAULT on a NULL header or a hash
 *         backend failure.
 */
int cmt_light_verify_backwards(const cmt_header_t *untrusted_header,
                               const cmt_header_t *trusted_header,
                               uint64_t block_protocol,
                               cmt_light_error_t *err);

#ifdef __cplusplus
}
#endif

#endif /* SHARED_DNAC_CMT_LIGHT_VERIFIER_H */
