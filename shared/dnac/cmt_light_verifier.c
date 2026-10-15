/**
 * @file shared/dnac/cmt_light_verifier.c
 * @brief cometbft @v0.38.26 `light/verifier.go` (+ types/light.go
 *        SignedHeader.ValidateBasic) in C — see cmt_light_verifier.h for
 *        the contract, the deviations and the taşınmadı list.
 *
 * NOTHING HERE READS A CLOCK, DRAWS RANDOMNESS OR ITERATES A MAP. The one
 * allocation is the leaf scratch of `untrustedVals.Hash()` in
 * verify_new_header_and_vals, freed before it returns.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dnac/cmt_light_verifier.h"
#include "dnac/cmt_validation.h"   /* cmt_verify_commit_light_trusting */
#include "dnac/cmt_merkle.h"       /* cmt_merkle_item_t                */

#include <stdlib.h>
#include <string.h>

/* ══════════════════════════════════════════════════════════════════════
 * C-only helpers
 * ══════════════════════════════════════════════════════════════════════ */

/* Go `bytes.Equal(a, b)`: equal lengths and equal bytes; a nil slice and
 * an empty one are equal. */
static bool go_bytes_equal(const uint8_t *a, size_t a_len,
                           const uint8_t *b, size_t b_len)
{
    if (a_len != b_len) {
        return false;
    }
    if (a_len == 0u) {
        return true;
    }
    return memcmp(a, b, a_len) == 0;
}

/* Go's `h + 1` on an int64 height, which WRAPS on overflow by
 * specification; carried in uint64 because C signed overflow is
 * undefined — the pattern of cmt_validation.c's go_add_i64. */
static int64_t go_add_one_i64(int64_t h)
{
    return (int64_t)((uint64_t)h + 1u);
}

/* Clear the optional error out-parameter so a caller can never read a
 * payload left over from an earlier call. */
static void light_err_none(cmt_light_error_t *err)
{
    if (err != NULL) {
        memset(err, 0, sizeof(*err));
        err->code        = CMT_LIGHT_ERR_NONE;
        err->at          = CMT_TIME_ZERO;
        err->now         = CMT_TIME_ZERO;
        err->reason.code = CMT_VS_ERR_NONE;
    }
}

/* `ErrInvalidHeader{Reason}` (errors.go:35-37). `reason` is the wrapped
 * error's ErrNotEnoughVotingPowerSigned payload when it is one, else
 * NULL (code CMT_VS_ERR_NONE). */
static void light_err_invalid_header(cmt_light_error_t *err,
                                     const cmt_vs_error_t *reason)
{
    if (err != NULL) {
        err->code = CMT_LIGHT_ERR_INVALID_HEADER;
        if (reason != NULL) {
            err->reason = *reason;
        } else {
            err->reason.code   = CMT_VS_ERR_NONE;
            err->reason.got    = 0;
            err->reason.needed = 0;
        }
    }
}

/* ══ types/light.go — SignedHeader.ValidateBasic ══════════════════════ */

/* cometbft@v0.38.26 types/light.go:128-162 —
 * (sh SignedHeader) ValidateBasic(chainID) */
int cmt_signed_header_validate_basic(const cmt_signed_header_t *sh,
                                     const uint8_t *chain_id,
                                     size_t chain_id_len,
                                     uint64_t block_protocol)
{
    uint8_t hhash[CMT_TMHASH_SIZE];
    size_t  hhash_len;
    int     rc;

    if (sh == NULL) {
        return CMT_FAULT;   /* the reference takes SignedHeader by value */
    }
    if (chain_id == NULL && chain_id_len != 0u) {
        return CMT_FAULT;
    }
    if (sh->header == NULL) {
        return CMT_REJECT;                 /* :135-137 "missing header" */
    }
    if (sh->commit == NULL) {
        return CMT_REJECT;                 /* :138-140 "missing commit" */
    }

    rc = cmt_header_validate_basic(sh->header, block_protocol);
    if (rc != CMT_OK) {
        return rc;                         /* :142-144 "invalid header" */
    }
    rc = cmt_commit_validate_basic(sh->commit);
    if (rc != CMT_OK) {
        return rc;                         /* :145-147 "invalid commit" */
    }

    if (!go_bytes_equal(sh->header->chain_id, sh->header->chain_id_len,
                        chain_id, chain_id_len)) {
        return CMT_REJECT;   /* :149-151 "header belongs to another chain" */
    }

    /* :153-156 — "Make sure the header is consistent with the commit." */
    if (sh->commit->height != sh->header->height) {
        return CMT_REJECT;   /* :154-156 "header and commit height mismatch" */
    }

    /* :157 — `sh.Hash()`; nil (CMT_HASH_NIL) is the empty slice. */
    rc = cmt_header_hash(sh->header, hhash);
    if (rc == CMT_HASH_NIL) {
        hhash_len = 0u;
    } else if (rc == CMT_OK) {
        hhash_len = sizeof(hhash);
    } else {
        return rc;
    }
    if (!go_bytes_equal(hhash, hhash_len, sh->commit->block_id.hash,
                        sh->commit->block_id.hash_len)) {
        return CMT_REJECT;   /* :157-159 "commit signs block %X, header is block %X" */
    }
    return CMT_OK;                                               /* :161 */
}

/* ══ light/verifier.go ════════════════════════════════════════════════ */

/* cometbft@v0.38.26 light/verifier.go:206-210 — HeaderExpired() */
int cmt_light_header_expired(const cmt_signed_header_t *h,
                             int64_t trusting_period, cmt_time_t now,
                             bool *out)
{
    cmt_time_t expiration_time;

    if (h == NULL || h->header == NULL || out == NULL) {
        return CMT_FAULT;   /* :208 dereferences the embedded *Header */
    }
    expiration_time = cmt_time_add_ns(h->header->time,
                                      trusting_period);          /* :208 */
    *out = !cmt_time_after(expiration_time, now);                /* :209 */
    return CMT_OK;
}

/* cometbft@v0.38.26 light/verifier.go:153-192 — verifyNewHeaderAndVals().
 * Every rejection here is an unnamed error that the two callers wrap in
 * ErrInvalidHeader (:54, :113). */
static int verify_new_header_and_vals(const cmt_signed_header_t *untrusted_header,
                                      cmt_validator_set_t *untrusted_vals,
                                      const cmt_signed_header_t *trusted_header,
                                      cmt_time_t now,
                                      int64_t max_clock_drift,
                                      uint64_t block_protocol)
{
    uint8_t           *scratch = NULL;
    cmt_merkle_item_t *items   = NULL;
    uint8_t            vals_hash[CMT_TMHASH_SIZE];
    size_t             n;
    int                rc;

    /* :160-162 — `untrustedHeader.ValidateBasic(trustedHeader.ChainID)`. */
    rc = cmt_signed_header_validate_basic(untrusted_header,
                                          trusted_header->header->chain_id,
                                          trusted_header->header->chain_id_len,
                                          block_protocol);
    if (rc != CMT_OK) {
        return rc;
    }
    /* From here on the untrusted header and commit are both present. */

    if (untrusted_header->header->height <= trusted_header->header->height) {
        return CMT_REJECT;   /* :164-168 "expected new header height %d to be greater" */
    }

    if (!cmt_time_after(untrusted_header->header->time,
                        trusted_header->header->time)) {
        return CMT_REJECT;   /* :170-174 "to be after old header time" */
    }

    if (!cmt_time_before(untrusted_header->header->time,
                         cmt_time_add_ns(now, max_clock_drift))) {
        return CMT_REJECT;   /* :176-181 "new header has a time from the future" */
    }

    /* :183 — `untrustedVals.Hash()`. A nil set panics in the reference
     * (validator_set.go:377 reads vals.Validators): FAULT. The port's
     * hash needs leaf scratch, sized as nodus_witness_storage_segment.c
     * sizes it. A member without a key PANICS in the reference
     * (validator.go:119-122, Validator.Bytes); `cmt_validator_set_hash`
     * already returns that as CMT_REJECT (cmt_validator_set.h:717-718)
     * and it is passed through as such. */
    if (untrusted_vals == NULL) {
        return CMT_FAULT;
    }
    n = untrusted_vals->validators_len;
    if (n > (size_t)CMT_VALSET_MAX) {
        return CMT_FAULT;   /* the type's own invariant, not an input */
    }
    if (n != 0u) {
        scratch = malloc(n * (size_t)CMT_VALIDATOR_BYTES_MAX);
        items   = calloc(n, sizeof(*items));
        if (scratch == NULL || items == NULL) {
            free(scratch);
            free(items);
            return CMT_FAULT;
        }
    }
    rc = cmt_validator_set_hash(untrusted_vals, scratch,
                                n * (size_t)CMT_VALIDATOR_BYTES_MAX,
                                items, n, vals_hash);
    free(scratch);
    free(items);
    if (rc != CMT_OK) {
        return rc;
    }
    if (!go_bytes_equal(untrusted_header->header->validators_hash,
                        untrusted_header->header->validators_hash_len,
                        vals_hash, sizeof(vals_hash))) {
        return CMT_REJECT;   /* :183-189 "expected new header validators (%X) to match those that were supplied" */
    }
    return CMT_OK;                                               /* :191 */
}

/* cometbft@v0.38.26 light/verifier.go:19-79 — VerifyNonAdjacent() */
int cmt_light_verify_non_adjacent(const cmt_signed_header_t *trusted_header,
                                  cmt_validator_set_t *trusted_vals,
                                  const cmt_signed_header_t *untrusted_header,
                                  cmt_validator_set_t *untrusted_vals,
                                  int64_t trusting_period,
                                  cmt_time_t now,
                                  int64_t max_clock_drift,
                                  cmt_fraction_t trust_level,
                                  uint64_t block_protocol,
                                  cmt_light_error_t *err)
{
    cmt_vs_error_t vs_err;
    bool           expired;
    int            rc;

    light_err_none(err);

    if (trusted_header == NULL || untrusted_header == NULL ||
        trusted_header->header == NULL || untrusted_header->header == NULL) {
        return CMT_FAULT;   /* :42 dereferences both embedded *Headers */
    }

    if (untrusted_header->header->height ==
        go_add_one_i64(trusted_header->header->height)) {
        return CMT_REJECT;   /* :42-44 "headers must be non adjacent in height" */
    }

    rc = cmt_light_header_expired(trusted_header, trusting_period, now,
                                  &expired);                     /* :46 */
    if (rc != CMT_OK) {
        return rc;
    }
    if (expired) {
        if (err != NULL) {                                       /* :47 */
            err->code = CMT_LIGHT_ERR_OLD_HEADER_EXPIRED;
            err->at   = cmt_time_add_ns(trusted_header->header->time,
                                        trusting_period);
            err->now  = now;
        }
        return CMT_REJECT;
    }

    rc = verify_new_header_and_vals(untrusted_header, untrusted_vals,
                                    trusted_header, now, max_clock_drift,
                                    block_protocol);          /* :50-53 */
    if (rc == CMT_REJECT) {
        light_err_invalid_header(err, NULL);                     /* :54 */
        return CMT_REJECT;
    }
    if (rc != CMT_OK) {
        return rc;
    }

    /* :57-58 — "Ensure that +`trustLevel` (default 1/3) or more of last
     * trusted validators signed correctly." */
    rc = cmt_validator_set_verify_commit_light_trusting(
            trusted_vals, trusted_header->header->chain_id,
            trusted_header->header->chain_id_len, untrusted_header->commit,
            trust_level, &vs_err);
    if (rc == CMT_REJECT) {
        if (vs_err.code == CMT_VS_ERR_NOT_ENOUGH_VOTING_POWER_SIGNED) {
            if (err != NULL) {                                /* :61-62 */
                err->code   = CMT_LIGHT_ERR_NEW_VAL_SET_CANT_BE_TRUSTED;
                err->reason = vs_err;
            }
        }
        /* else :63-64 `default: return e` — unwrapped, code NONE. */
        return CMT_REJECT;
    }
    if (rc != CMT_OK) {
        return rc;
    }

    /* :68-76 — "Ensure that +2/3 of new validators signed correctly.
     * NOTE: this should always be the last check because untrustedVals
     * can be intentionally made very large to DOS the light client." */
    rc = cmt_validator_set_verify_commit_light(
            untrusted_vals, trusted_header->header->chain_id,
            trusted_header->header->chain_id_len,
            &untrusted_header->commit->block_id,
            untrusted_header->header->height, untrusted_header->commit,
            &vs_err);
    if (rc == CMT_REJECT) {
        light_err_invalid_header(err, &vs_err);                  /* :75 */
        return CMT_REJECT;
    }
    if (rc != CMT_OK) {
        return rc;
    }
    return CMT_OK;                                               /* :78 */
}

/* cometbft@v0.38.26 light/verifier.go:81-132 — VerifyAdjacent() */
int cmt_light_verify_adjacent(const cmt_signed_header_t *trusted_header,
                              const cmt_signed_header_t *untrusted_header,
                              cmt_validator_set_t *untrusted_vals,
                              int64_t trusting_period,
                              cmt_time_t now,
                              int64_t max_clock_drift,
                              uint64_t block_protocol,
                              cmt_light_error_t *err)
{
    cmt_vs_error_t vs_err;
    bool           expired;
    int            rc;

    light_err_none(err);

    if (trusted_header == NULL || untrusted_header == NULL ||
        trusted_header->header == NULL || untrusted_header->header == NULL) {
        return CMT_FAULT;   /* :101 dereferences both embedded *Headers */
    }

    if (untrusted_header->header->height !=
        go_add_one_i64(trusted_header->header->height)) {
        return CMT_REJECT;   /* :101-103 "headers must be adjacent in height" */
    }

    rc = cmt_light_header_expired(trusted_header, trusting_period, now,
                                  &expired);                    /* :105 */
    if (rc != CMT_OK) {
        return rc;
    }
    if (expired) {
        if (err != NULL) {                                      /* :106 */
            err->code = CMT_LIGHT_ERR_OLD_HEADER_EXPIRED;
            err->at   = cmt_time_add_ns(trusted_header->header->time,
                                        trusting_period);
            err->now  = now;
        }
        return CMT_REJECT;
    }

    rc = verify_new_header_and_vals(untrusted_header, untrusted_vals,
                                    trusted_header, now, max_clock_drift,
                                    block_protocol);        /* :109-112 */
    if (rc == CMT_REJECT) {
        light_err_invalid_header(err, NULL);                    /* :113 */
        return CMT_REJECT;
    }
    if (rc != CMT_OK) {
        return rc;
    }

    /* :116-123 — "Check the validator hashes are the same". An UNNAMED
     * error: the reference does not wrap it in ErrInvalidHeader. */
    if (!go_bytes_equal(untrusted_header->header->validators_hash,
                        untrusted_header->header->validators_hash_len,
                        trusted_header->header->next_validators_hash,
                        trusted_header->header->next_validators_hash_len)) {
        return CMT_REJECT;   /* :118-122 "expected old header next validators (%X) to match those from new header (%X)" */
    }

    /* :125-129 — "Ensure that +2/3 of new validators signed correctly." */
    rc = cmt_validator_set_verify_commit_light(
            untrusted_vals, trusted_header->header->chain_id,
            trusted_header->header->chain_id_len,
            &untrusted_header->commit->block_id,
            untrusted_header->header->height, untrusted_header->commit,
            &vs_err);
    if (rc == CMT_REJECT) {
        light_err_invalid_header(err, &vs_err);                 /* :128 */
        return CMT_REJECT;
    }
    if (rc != CMT_OK) {
        return rc;
    }
    return CMT_OK;                                              /* :131 */
}

/* cometbft@v0.38.26 light/verifier.go:134-151 — Verify() */
int cmt_light_verify(const cmt_signed_header_t *trusted_header,
                     cmt_validator_set_t *trusted_vals,
                     const cmt_signed_header_t *untrusted_header,
                     cmt_validator_set_t *untrusted_vals,
                     int64_t trusting_period,
                     cmt_time_t now,
                     int64_t max_clock_drift,
                     cmt_fraction_t trust_level,
                     uint64_t block_protocol,
                     cmt_light_error_t *err)
{
    light_err_none(err);

    if (trusted_header == NULL || untrusted_header == NULL ||
        trusted_header->header == NULL || untrusted_header->header == NULL) {
        return CMT_FAULT;   /* :145 dereferences both embedded *Headers */
    }
    if (untrusted_header->header->height !=
        go_add_one_i64(trusted_header->header->height)) {      /* :145 */
        return cmt_light_verify_non_adjacent(trusted_header, trusted_vals,
                                             untrusted_header,
                                             untrusted_vals,
                                             trusting_period, now,
                                             max_clock_drift, trust_level,
                                             block_protocol,
                                             err);          /* :146-147 */
    }
    return cmt_light_verify_adjacent(trusted_header, untrusted_header,
                                     untrusted_vals, trusting_period, now,
                                     max_clock_drift, block_protocol,
                                     err);                      /* :150 */
}

/* cometbft@v0.38.26 light/verifier.go:194-204 — ValidateTrustLevel() */
int cmt_light_validate_trust_level(cmt_fraction_t lvl)
{
    /* uint64 arithmetic in both languages: `Numerator*3` wraps alike. */
    if (lvl.numerator * 3u < lvl.denominator ||                 /* :198 */
        lvl.numerator > lvl.denominator ||                      /* :199 */
        lvl.denominator == 0u) {                                /* :200 */
        return CMT_REJECT;   /* :201 "trustLevel must be within [1/3, 1]" */
    }
    return CMT_OK;                                              /* :203 */
}

/* cometbft@v0.38.26 light/verifier.go:212-245 — VerifyBackwards() */
int cmt_light_verify_backwards(const cmt_header_t *untrusted_header,
                               const cmt_header_t *trusted_header,
                               uint64_t block_protocol,
                               cmt_light_error_t *err)
{
    uint8_t uhash[CMT_TMHASH_SIZE];
    size_t  uhash_len;
    int     rc;

    light_err_none(err);

    if (untrusted_header == NULL || trusted_header == NULL) {
        return CMT_FAULT;   /* :222 / :226 dereference both headers */
    }

    rc = cmt_header_validate_basic(untrusted_header, block_protocol);
    if (rc == CMT_REJECT) {
        light_err_invalid_header(err, NULL);                /* :222-224 */
        return CMT_REJECT;
    }
    if (rc != CMT_OK) {
        return rc;
    }

    if (!go_bytes_equal(untrusted_header->chain_id,
                        untrusted_header->chain_id_len,
                        trusted_header->chain_id,
                        trusted_header->chain_id_len)) {
        light_err_invalid_header(err, NULL);   /* :226-228 "header belongs to another chain" */
        return CMT_REJECT;
    }

    if (!cmt_time_before(untrusted_header->time, trusted_header->time)) {
        light_err_invalid_header(err, NULL);   /* :230-235 "expected older header time" */
        return CMT_REJECT;
    }

    /* :237 — `untrustedHeader.Hash()`; nil (CMT_HASH_NIL) is the empty
     * slice, as in cmt_signed_header_validate_basic. */
    rc = cmt_header_hash(untrusted_header, uhash);
    if (rc == CMT_HASH_NIL) {
        uhash_len = 0u;
    } else if (rc == CMT_OK) {
        uhash_len = sizeof(uhash);
    } else {
        return rc;
    }
    if (!go_bytes_equal(uhash, uhash_len,
                        trusted_header->last_block_id.hash,
                        trusted_header->last_block_id.hash_len)) {
        light_err_invalid_header(err, NULL);   /* :237-242 "older header hash %X does not match" */
        return CMT_REJECT;
    }
    return CMT_OK;                                              /* :244 */
}
