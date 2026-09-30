/**
 * @file shared/dnac/cmt_validation.c
 * @brief cometbft @v0.38.26 `types/validation.go` in C — see
 *        cmt_validation.h for the contract, the substitutions, the
 *        collapsed error list and the taşınmadı list.
 *
 * NOTHING HERE READS A CLOCK, DRAWS RANDOMNESS, ITERATES A MAP OR
 * ALLOCATES.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dnac/cmt_validation.h"
#include "dnac/cmt_vote.h"     /* CMT_VOTE_SIGN_BYTES_MAX               */

#include "crypto/sign/qgp_dilithium.h"

#include <string.h>

/* ══════════════════════════════════════════════════════════════════════
 * The two closures of validation.go:40/:43 and :102/:105, written out.
 * ══════════════════════════════════════════════════════════════════════ */

/* `ignoreSig` — true when this entry is skipped without being verified. */
static bool sig_ignored(cmt_commit_sig_policy_t policy,
                        const cmt_commit_sig_t *cs)
{
    if (policy == CMT_SIG_POLICY_COMMIT) {
        /* :40 — ignore all ABSENT signatures. */
        return cs->block_id_flag == (int32_t)CMT_BLOCK_ID_FLAG_ABSENT;
    }
    /* :102 — ignore everything that is not FOR THE BLOCK. */
    return cs->block_id_flag != (int32_t)CMT_BLOCK_ID_FLAG_COMMIT;
}

/* `countSig` — true when this entry's voting power joins the tally. */
static bool sig_counted(cmt_commit_sig_policy_t policy,
                        const cmt_commit_sig_t *cs)
{
    if (policy == CMT_SIG_POLICY_COMMIT) {
        /* :43 — only the signatures that are FOR THE BLOCK count. A NIL
         * entry reaches here (it was not ignored) and is verified, but it
         * does not count. */
        return cs->block_id_flag == (int32_t)CMT_BLOCK_ID_FLAG_COMMIT;
    }
    return true;                                                 /* :105 */
}

/* Go's `talliedVotingPower += p`, which WRAPS on overflow by
 * specification. C signed overflow is undefined, so the sum is carried in
 * uint64 and converted back — the pattern cmt_validator_set.c already uses
 * for every place the reference relies on Go's wrap.
 *
 * On any reachable path the sum cannot overflow at all: the set's total is
 * capped at MaxTotalVotingPower = MaxInt64/8 by updateTotalVotingPower
 * (validator_set.go:319-321), each member's power is non-negative
 * (processChanges refuses a negative one, :436-438), and the tally is a
 * sub-sum of that total. The wrap-safe form is used anyway, because the
 * reference's CONTRACT at :331 — "both commit and validator set should
 * have passed validate basic" — is a caller obligation and not something
 * this function verifies. */
static int64_t go_add_i64(int64_t a, int64_t b)
{
    return (int64_t)((uint64_t)a + (uint64_t)b);
}

/* Clear the optional error out-parameter so a caller can never read a
 * payload left over from an earlier call. */
static void err_none(cmt_vs_error_t *err)
{
    if (err != NULL) {
        err->code   = CMT_VS_ERR_NONE;
        err->got    = 0;
        err->needed = 0;
    }
}

/* ══ shouldBatchVerify ════════════════════════════════════════════════ */

/* cometbft@v0.38.26 types/validation.go:15-19 — shouldBatchVerify().
 * FALSE for every key in this port; see cmt_validation.h for why this is a
 * fact about the crypto layer and not a shortcut. */
bool cmt_should_batch_verify(const cmt_validator_set_t *vals,
                             const cmt_commit_t *commit)
{
    (void)vals;     /* :17 would ask batch.SupportsBatchVerifier(...)     */
    (void)commit;   /* :16 would compare against batchVerifyThreshold     */
    return false;
}

/* ══ verifyBasicValsAndCommit ═════════════════════════════════════════ */

/* cometbft@v0.38.26 types/validation.go:413-436 —
 * verifyBasicValsAndCommit() */
int cmt_verify_basic_vals_and_commit(const cmt_validator_set_t *vals,
                                     const cmt_commit_t *commit,
                                     int64_t height,
                                     const cmt_block_id_t *block_id)
{
    if (vals == NULL) {
        return CMT_FAULT;                        /* :414-416; R1B-10     */
    }
    if (commit == NULL) {
        return CMT_FAULT;                        /* :418-420; R1B-10     */
    }
    if (block_id == NULL) {
        /* The reference takes BlockID by VALUE, so it has no nil case
         * here. A NULL pointer is this representation's own error. */
        return CMT_FAULT;
    }
    if (cmt_validator_set_size(vals) != cmt_commit_size(commit)) {
        return CMT_REJECT;      /* :422-424 ErrInvalidCommitSignatures   */
    }
    if (height != commit->height) {
        return CMT_REJECT;      /* :427-429 ErrInvalidCommitHeight       */
    }
    if (!cmt_block_id_equals(block_id, &commit->block_id)) {
        return CMT_REJECT;      /* :430-433 "wrong block ID"             */
    }
    return CMT_OK;                                               /* :435 */
}

/* ══ verifyCommitSingle ═══════════════════════════════════════════════ */

/* cometbft@v0.38.26 types/validation.go:332-411 — verifyCommitSingle().
 * Every `:NNN` in this body is a v0.38.26 line. The one change against
 * 709fd12b is CSA-2026-001 ("Tachyon", v0.38.21) at :362-365. */
int cmt_verify_commit_single(const uint8_t *chain_id, size_t chain_id_len,
                             cmt_validator_set_t *vals,
                             const cmt_commit_t *commit,
                             int64_t voting_power_needed,
                             cmt_commit_sig_policy_t policy,
                             bool count_all_signatures,
                             bool look_up_by_index,
                             cmt_vs_error_t *err)
{
    /* :345 `seenVals map[int32]int`. A map is forbidden in a consensus
     * path (nothing here iterates it, but the port keeps none anyway):
     * the validator index is already a dense small integer, so the map
     * becomes an array holding the FIRST signature index seen for each
     * validator, or -1. */
    int32_t seen[CMT_VALSET_MAX];
    uint8_t sb[CMT_VOTE_SIGN_BYTES_MAX];
    int64_t tallied = 0;                                         /* :346 */
    size_t  n;
    size_t  i;
    int     rc;

    err_none(err);

    if (vals == NULL || commit == NULL) {
        return CMT_FAULT;
    }
    if (chain_id == NULL && chain_id_len != 0u) {
        return CMT_FAULT;
    }
    n = cmt_commit_size(commit);
    if (n != 0u && commit->signatures == NULL) {
        return CMT_FAULT;
    }
    if (vals->validators_len > (size_t)CMT_VALSET_MAX) {
        return CMT_FAULT;   /* the type's own invariant, not an input    */
    }
    if (vals->validators_len != 0u && vals->validators == NULL) {
        return CMT_FAULT;
    }
    for (i = 0; i < (size_t)CMT_VALSET_MAX; i++) {
        seen[i] = -1;
    }

    for (i = 0; i < n; i++) {                                 /* :349-404 */
        const cmt_commit_sig_t *cs  = &commit->signatures[i];
        const cmt_validator_t  *val = NULL;
        int32_t                 val_idx;
        size_t                  sb_len;

        if (sig_ignored(policy, cs)) {
            continue;                                         /* :350-352 */
        }
        if (cmt_commit_sig_validate_basic(cs) != CMT_OK) {
            return CMT_REJECT;   /* :354-356 "invalid signatures from"   */
        }

        if (look_up_by_index) {
            /* :361 `val = vals.Validators[idx]`. Go bounds-checks this
             * and panics; C does not, so the check is explicit (INVARIANT
             * atlas-dec-7495d3372e004b24b4f6cc7bff5caf07). It cannot fire
             * on the path from cmt_verify_commit, where :422 has already
             * made the two counts equal — but this function is callable
             * on its own, and an out-of-range index is then a property of
             * the arguments, hence REJECT and not FAULT. */
            if (i >= vals->validators_len) {
                return CMT_REJECT;
            }
            val = &vals->validators[i];
            /* :362-365 — CSA-2026-001 "Tachyon" (v0.38.21). The address a
             * CommitSig names must be the address of the validator at its
             * index. CanonicalVote does not contain the address, so the
             * signature alone cannot bind it; before this check a commit
             * could carry validator i's valid signature under validator
             * j's address, and MedianTime (state/state.go:281), which
             * looks signers up BY ADDRESS, then weighted i's timestamp
             * with j's power. The address is carried by the commit, so
             * a mismatch is a property of peer input: REJECT. */
            if (cs->validator_address_len != val->address_len ||
                (val->address_len != 0u &&
                 memcmp(cs->validator_address, val->address,
                        val->address_len) != 0)) {
                return CMT_REJECT;      /* "validator address mismatch" */
            }
        } else {
            /* :367 — by ADDRESS. Reachable only from the Trusting family,
             * where the set need not correspond to the commit. */
            rc = cmt_validator_set_get_by_address(vals,
                                                  cs->validator_address,
                                                  cs->validator_address_len,
                                                  &val_idx, NULL);
            if (rc != CMT_OK) {
                return rc;
            }
            if (val_idx < 0) {
                continue;   /* :371-373 the signature belongs to nobody  */
            }
            if ((size_t)val_idx >= vals->validators_len) {
                return CMT_FAULT;   /* the accessor's own invariant      */
            }
            /* :377-381 — "the same validator doesn't commit twice". */
            if (seen[val_idx] >= 0) {
                return CMT_REJECT;                /* :379 "double vote"  */
            }
            seen[val_idx] = (int32_t)i;                          /* :381 */
            val = &vals->validators[val_idx];
        }

        if (!val->pub_key.present) {
            return CMT_REJECT;      /* :384-386 "has a nil PubKey"       */
        }

        /* :388 — the bytes THIS validator signed. They differ between
         * entries only in the timestamp and the flag-derived BlockID. */
        rc = cmt_commit_vote_sign_bytes(commit, chain_id, chain_id_len,
                                        (int32_t)i, sb, sizeof(sb),
                                        &sb_len);
        if (rc != CMT_OK) {
            return rc;
        }
        /* INVARIANT atlas-dec-7495d3372e004b24b4f6cc7bff5caf07, as in
         * cmt_vote_verify: the verifier reads `signature_len` bytes out of
         * a fixed array, so the struct's own length is checked against
         * that array first. Go's Signature is a slice and carries its own
         * bound. */
        if (cs->signature_len > sizeof(cs->signature)) {
            return CMT_FAULT;
        }
        if (qgp_dsa87_verify(cs->signature, cs->signature_len,
                             sb, sb_len, val->pub_key.key) != 0) {
            return CMT_REJECT;              /* :390-392 "wrong signature" */
        }

        if (sig_counted(policy, cs)) {
            tallied = go_add_i64(tallied, val->voting_power);     /* :397 */
        }
        /* :401-403 — the early exit, which cmt_verify_commit disables. */
        if (!count_all_signatures && tallied > voting_power_needed) {
            return CMT_OK;
        }
    }

    if (tallied <= voting_power_needed) {                        /* :406 */
        if (err != NULL) {
            err->code   = CMT_VS_ERR_NOT_ENOUGH_VOTING_POWER_SIGNED;
            err->got    = tallied;                               /* :407 */
            err->needed = voting_power_needed;                   /* :407 */
        }
        return CMT_REJECT;
    }
    return CMT_OK;                                               /* :410 */
}

/* ══ VerifyCommit ═════════════════════════════════════════════════════ */

/* cometbft@v0.38.26 types/validation.go:28-54 — VerifyCommit() */
int cmt_verify_commit(const uint8_t *chain_id, size_t chain_id_len,
                      cmt_validator_set_t *vals,
                      const cmt_block_id_t *block_id,
                      int64_t height,
                      const cmt_commit_t *commit,
                      cmt_vs_error_t *err)
{
    int64_t total;
    int64_t needed;
    int     rc;

    err_none(err);

    rc = cmt_verify_basic_vals_and_commit(vals, commit, height, block_id);
    if (rc != CMT_OK) {
        return rc;                                            /* :31-33  */
    }
    /* :37 — `vals.TotalVotingPower() * 2 / 3`. The doubling is safe
     * because a successful TotalVotingPower guarantees
     * total <= MaxTotalVotingPower = MaxInt64/8 (validator_set.go:27,
     * :319-321); see cmt_validation.h. */
    rc = cmt_validator_set_total_voting_power(vals, &total);
    if (rc != CMT_OK) {
        return rc;
    }
    if (total > (int64_t)CMT_MAX_TOTAL_VOTING_POWER || total < 0) {
        /* Unreachable after the call above, which refuses exactly this.
         * Kept so the multiplication below is guarded by a check a reader
         * can see, rather than by a fact stated in a comment. */
        return CMT_FAULT;
    }
    needed = total * 2 / 3;

    if (cmt_should_batch_verify(vals, commit)) {
        /* :46-49 — the batch path. UNREACHABLE: there is no ML-DSA-87
         * batch verifier, so the predicate above is false for every key
         * here and verifyCommitBatch (:215-323) is not ported. See
         * cmt_validation.h's taşınmadı list. */
        return CMT_FAULT;
    }
    /* :52-53 — single verification, with countAllSignatures TRUE and
     * lookUpByIndex TRUE. */
    return cmt_verify_commit_single(chain_id, chain_id_len, vals, commit,
                                    needed, CMT_SIG_POLICY_COMMIT,
                                    true, true, err);
}

/* ══ VerifyCommitLight family ═════════════════════════════════════════ */

/* cometbft@v0.38.26 types/validation.go:85-116 —
 * verifyCommitLightInternal() */
static int verify_commit_light_internal(const uint8_t *chain_id,
                                        size_t chain_id_len,
                                        cmt_validator_set_t *vals,
                                        const cmt_block_id_t *block_id,
                                        int64_t height,
                                        const cmt_commit_t *commit,
                                        bool count_all_signatures,
                                        cmt_vs_error_t *err)
{
    int64_t total;
    int64_t needed;
    int     rc;

    err_none(err);

    rc = cmt_verify_basic_vals_and_commit(vals, commit, height, block_id);
    if (rc != CMT_OK) {
        return rc;                                            /* :94-96  */
    }
    /* :99 — `vals.TotalVotingPower() * 2 / 3`, guarded exactly as
     * cmt_verify_commit's :37 is (MaxTotalVotingPower = MaxInt64/8,
     * validator_set.go:27, :319-321). */
    rc = cmt_validator_set_total_voting_power(vals, &total);
    if (rc != CMT_OK) {
        return rc;
    }
    if (total > (int64_t)CMT_MAX_TOTAL_VOTING_POWER || total < 0) {
        return CMT_FAULT;                /* unreachable; see cmt_verify_commit */
    }
    needed = total * 2 / 3;

    if (cmt_should_batch_verify(vals, commit)) {
        /* :108-111 — the batch path. UNREACHABLE for the reason given at
         * cmt_verify_commit's :46-49 site. */
        return CMT_FAULT;
    }
    /* :114-115 — single verification with the light pair (:102, :105),
     * the caller's countAllSignatures, and lookUpByIndex TRUE. */
    return cmt_verify_commit_single(chain_id, chain_id_len, vals, commit,
                                    needed, CMT_SIG_POLICY_LIGHT,
                                    count_all_signatures, true, err);
}

/* cometbft@v0.38.26 types/validation.go:62-70 — VerifyCommitLight() */
int cmt_verify_commit_light(const uint8_t *chain_id, size_t chain_id_len,
                            cmt_validator_set_t *vals,
                            const cmt_block_id_t *block_id,
                            int64_t height,
                            const cmt_commit_t *commit,
                            cmt_vs_error_t *err)
{
    return verify_commit_light_internal(chain_id, chain_id_len, vals,
                                        block_id, height, commit,
                                        false, err);                  /* :69 */
}

/* cometbft@v0.38.26 types/validation.go:75-83 —
 * VerifyCommitLightAllSignatures() */
int cmt_verify_commit_light_all_signatures(const uint8_t *chain_id,
                                           size_t chain_id_len,
                                           cmt_validator_set_t *vals,
                                           const cmt_block_id_t *block_id,
                                           int64_t height,
                                           const cmt_commit_t *commit,
                                           cmt_vs_error_t *err)
{
    return verify_commit_light_internal(chain_id, chain_id_len, vals,
                                        block_id, height, commit,
                                        true, err);                   /* :82 */
}
