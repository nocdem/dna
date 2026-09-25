/**
 * @file shared/dnac/cmt_validation.c
 * @brief cometbft @709fd12b `types/validation.go` in C — see
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
 * The two closures of validation.go:39/:42 and :101/:104, written out.
 * ══════════════════════════════════════════════════════════════════════ */

/* `ignoreSig` — true when this entry is skipped without being verified. */
static bool sig_ignored(cmt_commit_sig_policy_t policy,
                        const cmt_commit_sig_t *cs)
{
    if (policy == CMT_SIG_POLICY_COMMIT) {
        /* :39 — ignore all ABSENT signatures. */
        return cs->block_id_flag == (int32_t)CMT_BLOCK_ID_FLAG_ABSENT;
    }
    /* :101 — ignore everything that is not FOR THE BLOCK. */
    return cs->block_id_flag != (int32_t)CMT_BLOCK_ID_FLAG_COMMIT;
}

/* `countSig` — true when this entry's voting power joins the tally. */
static bool sig_counted(cmt_commit_sig_policy_t policy,
                        const cmt_commit_sig_t *cs)
{
    if (policy == CMT_SIG_POLICY_COMMIT) {
        /* :42 — only the signatures that are FOR THE BLOCK count. A NIL
         * entry reaches here (it was not ignored) and is verified, but it
         * does not count. */
        return cs->block_id_flag == (int32_t)CMT_BLOCK_ID_FLAG_COMMIT;
    }
    return true;                                                 /* :104 */
}

/* Go's `talliedVotingPower += p`, which WRAPS on overflow by
 * specification. C signed overflow is undefined, so the sum is carried in
 * uint64 and converted back — the pattern cmt_validator_set.c already uses
 * for every place the reference relies on Go's wrap.
 *
 * On any reachable path the sum cannot overflow at all: the set's total is
 * capped at MaxTotalVotingPower = MaxInt64/8 by updateTotalVotingPower
 * (validator_set.go:319-324), each member's power is non-negative
 * (processChanges refuses a negative one, :425-427), and the tally is a
 * sub-sum of that total. The wrap-safe form is used anyway, because the
 * reference's CONTRACT at :326 — "both commit and validator set should
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

/* cometbft@709fd12b types/validation.go:14-18 — shouldBatchVerify().
 * FALSE for every key in this port; see cmt_validation.h for why this is a
 * fact about the crypto layer and not a shortcut. */
bool cmt_should_batch_verify(const cmt_validator_set_t *vals,
                             const cmt_commit_t *commit)
{
    (void)vals;     /* :16 would ask batch.SupportsBatchVerifier(...)     */
    (void)commit;   /* :15 would compare against batchVerifyThreshold     */
    return false;
}

/* ══ verifyBasicValsAndCommit ═════════════════════════════════════════ */

/* cometbft@709fd12b types/validation.go:404-427 —
 * verifyBasicValsAndCommit() */
int cmt_verify_basic_vals_and_commit(const cmt_validator_set_t *vals,
                                     const cmt_commit_t *commit,
                                     int64_t height,
                                     const cmt_block_id_t *block_id)
{
    if (vals == NULL) {
        return CMT_FAULT;                        /* :405-407; R1B-10     */
    }
    if (commit == NULL) {
        return CMT_FAULT;                        /* :409-411; R1B-10     */
    }
    if (block_id == NULL) {
        /* The reference takes BlockID by VALUE, so it has no nil case
         * here. A NULL pointer is this representation's own error. */
        return CMT_FAULT;
    }
    if (cmt_validator_set_size(vals) != cmt_commit_size(commit)) {
        return CMT_REJECT;      /* :413-415 ErrInvalidCommitSignatures   */
    }
    if (height != commit->height) {
        return CMT_REJECT;      /* :418-420 ErrInvalidCommitHeight       */
    }
    if (!cmt_block_id_equals(block_id, &commit->block_id)) {
        return CMT_REJECT;      /* :421-424 "wrong block ID"             */
    }
    return CMT_OK;                                               /* :426 */
}

/* ══ verifyCommitSingle ═══════════════════════════════════════════════ */

/* cometbft@709fd12b types/validation.go:327-402 — verifyCommitSingle() */
int cmt_verify_commit_single(const uint8_t *chain_id, size_t chain_id_len,
                             cmt_validator_set_t *vals,
                             const cmt_commit_t *commit,
                             int64_t voting_power_needed,
                             cmt_commit_sig_policy_t policy,
                             bool count_all_signatures,
                             bool look_up_by_index,
                             cmt_vs_error_t *err)
{
    /* :340 `seenVals map[int32]int`. A map is forbidden in a consensus
     * path (nothing here iterates it, but the port keeps none anyway):
     * the validator index is already a dense small integer, so the map
     * becomes an array holding the FIRST signature index seen for each
     * validator, or -1. */
    int32_t seen[CMT_VALSET_MAX];
    uint8_t sb[CMT_VOTE_SIGN_BYTES_MAX];
    int64_t tallied = 0;                                         /* :341 */
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

    for (i = 0; i < n; i++) {                                 /* :344-395 */
        const cmt_commit_sig_t *cs  = &commit->signatures[i];
        const cmt_validator_t  *val = NULL;
        int32_t                 val_idx;
        size_t                  sb_len;

        if (sig_ignored(policy, cs)) {
            continue;                                         /* :345-347 */
        }
        if (cmt_commit_sig_validate_basic(cs) != CMT_OK) {
            return CMT_REJECT;   /* :349-351 "invalid signatures from"   */
        }

        if (look_up_by_index) {
            /* :356 `val = vals.Validators[idx]`. Go bounds-checks this
             * and panics; C does not, so the check is explicit (INVARIANT
             * atlas-dec-7495d3372e004b24b4f6cc7bff5caf07). It cannot fire
             * on the path from cmt_verify_commit, where :413 has already
             * made the two counts equal — but this function is callable
             * on its own, and an out-of-range index is then a property of
             * the arguments, hence REJECT and not FAULT. */
            if (i >= vals->validators_len) {
                return CMT_REJECT;
            }
            val = &vals->validators[i];
        } else {
            /* :358 — by ADDRESS. Reachable only from the Trusting family,
             * where the set need not correspond to the commit. */
            rc = cmt_validator_set_get_by_address(vals,
                                                  cs->validator_address,
                                                  cs->validator_address_len,
                                                  &val_idx, NULL);
            if (rc != CMT_OK) {
                return rc;
            }
            if (val_idx < 0) {
                continue;   /* :362-364 the signature belongs to nobody  */
            }
            if ((size_t)val_idx >= vals->validators_len) {
                return CMT_FAULT;   /* the accessor's own invariant      */
            }
            /* :368-372 — "the same validator doesn't commit twice". */
            if (seen[val_idx] >= 0) {
                return CMT_REJECT;                /* :370 "double vote"  */
            }
            seen[val_idx] = (int32_t)i;                          /* :372 */
            val = &vals->validators[val_idx];
        }

        if (!val->pub_key.present) {
            return CMT_REJECT;      /* :375-377 "has a nil PubKey"       */
        }

        /* :379 — the bytes THIS validator signed. They differ between
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
            return CMT_REJECT;              /* :381-383 "wrong signature" */
        }

        if (sig_counted(policy, cs)) {
            tallied = go_add_i64(tallied, val->voting_power);     /* :388 */
        }
        /* :392-394 — the early exit, which cmt_verify_commit disables. */
        if (!count_all_signatures && tallied > voting_power_needed) {
            return CMT_OK;
        }
    }

    if (tallied <= voting_power_needed) {                        /* :397 */
        if (err != NULL) {
            err->code   = CMT_VS_ERR_NOT_ENOUGH_VOTING_POWER_SIGNED;
            err->got    = tallied;                               /* :398 */
            err->needed = voting_power_needed;                   /* :398 */
        }
        return CMT_REJECT;
    }
    return CMT_OK;                                               /* :401 */
}

/* ══ VerifyCommit ═════════════════════════════════════════════════════ */

/* cometbft@709fd12b types/validation.go:27-53 — VerifyCommit() */
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
        return rc;                                            /* :30-32  */
    }
    /* :36 — `vals.TotalVotingPower() * 2 / 3`. The doubling is safe
     * because a successful TotalVotingPower guarantees
     * total <= MaxTotalVotingPower = MaxInt64/8 (validator_set.go:27,
     * :319-324); see cmt_validation.h. */
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
        /* :45-48 — the batch path. UNREACHABLE: there is no ML-DSA-87
         * batch verifier, so the predicate above is false for every key
         * here and verifyCommitBatch (:214-318) is not ported. See
         * cmt_validation.h's taşınmadı list. */
        return CMT_FAULT;
    }
    /* :51-52 — single verification, with countAllSignatures TRUE and
     * lookUpByIndex TRUE. */
    return cmt_verify_commit_single(chain_id, chain_id_len, vals, commit,
                                    needed, CMT_SIG_POLICY_COMMIT,
                                    true, true, err);
}
