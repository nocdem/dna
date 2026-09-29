/**
 * Nodus — cometbft @709fd12b C port, wave R1-D: `types/validation.go`
 * (INACTIVE layer).
 *
 * ── WHAT IT PROVES ─────────────────────────────────────────────────────
 * That a commit is accepted exactly when more than two thirds of the
 * validator set's voting power really signed it, with REAL ML-DSA-87
 * signatures over the bytes `Commit.VoteSignBytes` produces. If this file
 * failed, one of these would be false:
 *   · a commit in which all four validators (powers 40/30/20/10) signed
 *     for the block verifies, and the threshold is `total * 2 / 3` = 66
 *     compared STRICTLY (`got <= needed` rejects, validation.go:397) — so
 *     100 passes and 66 would not;
 *   · a set size that does not match the signature count is refused in
 *     BOTH directions (:413-415), a wrong height (:418-420) and a wrong
 *     BlockID (:421-424) are refused;
 *   · an ABSENT entry is IGNORED — skipped without being verified
 *     (:39, :345-347) — so the remaining 90 still passes;
 *   · a NIL entry is VERIFIED BUT NOT COUNTED (:42, :387): making the
 *     40-power validator vote nil drops the tally to 60, which is at or
 *     below 66, and the rejection carries got = 60 and needed = 66 in the
 *     `ErrNotEnoughVotingPowerSigned` out-parameter;
 *   · a wrong signature is refused even when it sits AFTER the point where
 *     two thirds was already reached — `countAllSignatures` is true
 *     (:52), and this is the assertion that would fail first if someone
 *     "optimised" the loop with an early exit;
 *   · a validator whose public key is absent is refused (:375-377);
 *   · the `lookUpByIndex == false` branch, which only the out-of-scope
 *     Trusting family reaches, SKIPS a signature belonging to nobody
 *     (:362-364) and REFUSES a validator who signed twice (:368-372);
 *   · CSA-2026-001 "Tachyon" (cometbft@v0.38.26 validation.go:362-365):
 *     on the index path a CommitSig that keeps its own valid signature
 *     but names ANOTHER validator's address is refused — without the check
 *     t_tachyon's commit verifies and moves MedianTime by 1000 s with 30%
 *     of the power (project-authored case; upstream ships none);
 *   · `shouldBatchVerify` is false, so the batch path is never taken;
 *   · `ValidatorSet.VerifyCommit` (validator_set.go:698-702) answers
 *     identically to `types.VerifyCommit` — it is the same call.
 *
 * ── WHAT IT REQUIRES ───────────────────────────────────────────────────
 * A default build. No compile flags, no environment variables, no network,
 * no files, no clock. Keys come from `qgp_dsa87_keypair_derand` with fixed
 * seeds, so the test draws no randomness of its own and the derived
 * addresses are reproducible. Safe under `ctest -j`. One malloc, for the
 * validator-set change scratch, which is over a megabyte and must never be
 * a stack object (cmt_validator_set.h:241-245).
 *
 * ── WHAT IT LEAVES BEHIND ──────────────────────────────────────────────
 * Nothing. No files, no directories, no processes, no global state beyond
 * the file-scope fixtures, which are freed in main.
 *
 * ── HOW IT CAN LIE ─────────────────────────────────────────────────────
 *  1. ML-DSA-87 signing is HEDGED — signing the same message twice gives
 *     different bytes — so no signature is ever frozen or compared for
 *     equality here. Every real-key assertion is on a VERIFY OUTCOME.
 *  2. There is no frozen vector for the sign bytes in this file: it trusts
 *     `cmt_commit_vote_sign_bytes`, which test_cmt_block.c pins against
 *     the oracle. If that function were wrong in a way that was
 *     SELF-CONSISTENT between signing and verifying, every check here
 *     would still pass. This file proves the VERIFICATION LOGIC, not the
 *     preimage.
 *  3. The set is built with four validators. Nothing here exercises the
 *     128-validator capacity bound, and a green says nothing about it.
 *  4. `CMT_SIG_POLICY_LIGHT` is exercised only through the internal
 *     function; no in-scope caller passes it, so a green does not mean the
 *     light-client semantics are reachable — they are deliberately not.
 *  5. The tests below re-sign whenever a signed field changes. If a future
 *     edit forgot to re-sign, the affected case would fail for the WRONG
 *     reason (a stale signature rather than the property under test) and
 *     would still look like a red. Read the failure, do not assume.
 *
 * ── REFERENCE CASES PORTED (types/validation_test.go, UNPINNED) ────────
 * From `TestValidatorSet_VerifyCommit_All` (:17-155), the rows that do not
 * need the light family: "wrong signature (#0)" (:48, as a wrong chain
 * id), "wrong block ID" (:49), "wrong height" (:50), "wrong set size: 4 vs
 * 3" and "1 vs 2" (:52-53), and the four "insufficient voting power" rows
 * (:55-58) in the nil / absent / mixed shapes. From
 * `TestValidatorSet_VerifyCommit_CheckAllSignatures` (:157-183), the
 * property that a bad signature after the threshold still refuses.
 * NOT ported, because their subjects are YOK: `VerifyCommitLight*`
 * (:185-214) and every `VerifyCommitLightTrusting*` row (:216-310).
 *
 * @file test_cmt_validation.c
 */

#include "dnac/cmt_validation.h"
#include "dnac/cmt_validator_set.h"
#include "dnac/cmt_state.h"      /* cmt_state_median_time — t_tachyon */
#include "dnac/cmt_block.h"
#include "dnac/cmt_vote.h"
#include "dnac/cmt_pb.h"

#include "crypto/sign/qgp_dilithium.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, (msg)); \
        return 1; \
    } \
} while (0)

static int g_checks = 0;
#define OK() do { g_checks++; } while (0)

#define NVALS 4

/* ══ fixtures ═════════════════════════════════════════════════════════ */

static uint8_t  g_pk[NVALS][QGP_DSA87_PUBLICKEYBYTES];
static uint8_t  g_sk[NVALS][QGP_DSA87_SECRETKEYBYTES];
/* The powers as BUILT. `cmt_validator_set_new` sorts the set by voting
 * power DESCENDING (validator_set.go:851-856, :674), so the set's index i
 * is NOT the build index — `g_key_of_index` below records the mapping. */
static const int64_t g_power[NVALS] = { 10, 20, 30, 40 };

static cmt_validator_t        g_storage[NVALS];
static cmt_validator_set_t    g_vs;
static cmt_valset_scratch_t  *g_scratch;
static int                    g_key_of_index[NVALS];
static uint8_t                g_chain[32];

static cmt_commit_sig_t       g_sigs[NVALS + 1];
static cmt_commit_t           g_commit;

#define HEIGHT 100
#define ROUND  0

static void pat(uint8_t *dst, size_t n, uint8_t seed)
{
    size_t i;

    for (i = 0; i < n; i++) {
        dst[i] = (uint8_t)((seed + 7u * (unsigned)i) & 0xFFu);
    }
}

static void make_block_id(cmt_block_id_t *bid, uint8_t seed)
{
    cmt_pb_block_id_init(bid);
    pat(bid->hash, 64, seed);
    bid->hash_len                 = 64u;
    bid->part_set_header.total    = 1000u;
    pat(bid->part_set_header.hash, 64, (uint8_t)(seed + 1u));
    bid->part_set_header.hash_len = 64u;
}

/* Build the four keys and the set, then learn which key sits at which
 * index of the SORTED set by matching addresses. */
static int build_set(void)
{
    cmt_validator_t     list[NVALS];
    cmt_pb_public_key_t pk;
    uint8_t             seed[32];
    int                 i;
    int                 j;

    for (i = 0; i < NVALS; i++) {
        memset(seed, (uint8_t)(0x01 + i), sizeof(seed));
        if (qgp_dsa87_keypair_derand(g_pk[i], g_sk[i], seed) != 0) {
            fprintf(stderr, "keypair %d failed\n", i);
            return 1;
        }
        memset(&pk, 0, sizeof(pk));
        pk.present = true;
        memcpy(pk.key, g_pk[i], QGP_DSA87_PUBLICKEYBYTES);
        if (cmt_validator_new(&pk, g_power[i], &list[i]) != CMT_OK) {
            fprintf(stderr, "NewValidator %d failed\n", i);
            return 1;
        }
    }
    if (cmt_validator_set_init(&g_vs, g_storage, NVALS) != CMT_OK ||
        cmt_validator_set_new(&g_vs, list, NVALS, g_scratch) != CMT_OK) {
        fprintf(stderr, "NewValidatorSet failed\n");
        return 1;
    }
    for (i = 0; i < NVALS; i++) {
        g_key_of_index[i] = -1;
        for (j = 0; j < NVALS; j++) {
            uint8_t addr[32];

            if (cmt_pubkey_address(g_pk[j], addr) != CMT_OK) {
                return 1;
            }
            if (g_vs.validators[i].address_len == 32u &&
                memcmp(g_vs.validators[i].address, addr, 32) == 0) {
                g_key_of_index[i] = j;
                break;
            }
        }
        if (g_key_of_index[i] < 0) {
            fprintf(stderr, "index %d matched no key\n", i);
            return 1;
        }
    }
    return 0;
}

/* Fill every field of entry `i` EXCEPT the signature.
 *
 * ⚠ `i` MUST be below NVALS for any flag other than ABSENT: the non-absent
 * path reads `g_vs.validators[i]`, and the set has exactly NVALS members.
 * The ABSENT path returns before that read, which is why t_basic may use
 * index NVALS with it. t_guards, which needs a non-absent entry at NVALS,
 * fills it by hand instead. */
static void set_entry(size_t i, int32_t flag)
{
    cmt_commit_sig_t *cs = &g_sigs[i];

    memset(cs, 0, sizeof(*cs));
    if (flag == (int32_t)CMT_BLOCK_ID_FLAG_ABSENT) {
        cmt_new_commit_sig_absent(cs);
        return;
    }
    cs->block_id_flag = flag;
    memcpy(cs->validator_address, g_vs.validators[i].address, 32);
    cs->validator_address_len = 32u;
    cs->timestamp.seconds     = 1700000000 + (int64_t)i;
    cs->timestamp.nanos       = 0;
}

/* Sign entry `i` with the key that belongs to the validator AT THAT INDEX,
 * over the bytes `Commit.VoteSignBytes(chainID, i)` produces — the bytes
 * validation.go:379 hands to the verifier. Every field that enters those
 * bytes must already be set. */
static int sign_entry(size_t i, const uint8_t *chain, size_t chain_len)
{
    uint8_t sb[CMT_VOTE_SIGN_BYTES_MAX];
    size_t  sb_len;
    size_t  siglen;

    if (cmt_commit_vote_sign_bytes(&g_commit, chain, chain_len, (int32_t)i,
                                   sb, sizeof(sb), &sb_len) != CMT_OK) {
        fprintf(stderr, "sign bytes %zu failed\n", i);
        return 1;
    }
    if (qgp_dsa87_sign(g_sigs[i].signature, &siglen, sb, sb_len,
                       g_sk[g_key_of_index[i]]) != 0) {
        fprintf(stderr, "sign %zu failed\n", i);
        return 1;
    }
    g_sigs[i].signature_len = siglen;
    return 0;
}

/* The all-COMMIT commit: every validator signed for the block. */
static int make_good_commit(void)
{
    size_t i;

    cmt_pb_commit_init(&g_commit);
    g_commit.height     = HEIGHT;
    g_commit.round      = ROUND;
    make_block_id(&g_commit.block_id, 0x11);
    g_commit.signatures     = g_sigs;
    g_commit.signatures_cap = NVALS + 1;
    g_commit.signatures_len = NVALS;

    for (i = 0; i < NVALS; i++) {
        set_entry(i, (int32_t)CMT_BLOCK_ID_FLAG_COMMIT);
    }
    for (i = 0; i < NVALS; i++) {
        if (sign_entry(i, g_chain, sizeof(g_chain)) != 0) {
            return 1;
        }
    }
    return 0;
}

/* ══ 1. the happy path, and the threshold itself ══════════════════════ */

static int t_good(void)
{
    cmt_vs_error_t err;
    int64_t        total;

    if (make_good_commit() != 0) return 1;

    CHECK(cmt_validator_set_total_voting_power(&g_vs, &total) == CMT_OK &&
          total == 100, "the four powers sum to 100"); OK();
    CHECK(total * 2 / 3 == 66,
          "so the threshold is 66 — and 66 itself would NOT pass"); OK();

    err.code = 0x5A5A;   /* poison, to prove err is always written */
    CHECK(cmt_verify_commit(g_chain, sizeof(g_chain), &g_vs,
                            &g_commit.block_id, HEIGHT, &g_commit,
                            &err) == CMT_OK,
          "a fully signed commit verifies"); OK();
    CHECK(err.code == CMT_VS_ERR_NONE,
          "and the error out-parameter is cleared, never left stale"); OK();

    /* The NULL err out-parameter is legal. */
    CHECK(cmt_verify_commit(g_chain, sizeof(g_chain), &g_vs,
                            &g_commit.block_id, HEIGHT, &g_commit,
                            NULL) == CMT_OK, "err may be NULL"); OK();

    /* The ValidatorSet method is the same call (validator_set.go:701). */
    CHECK(cmt_validator_set_verify_commit(&g_vs, g_chain, sizeof(g_chain),
                                          &g_commit.block_id, HEIGHT,
                                          &g_commit, NULL) == CMT_OK,
          "ValidatorSet.VerifyCommit delegates to it"); OK();

    /* Batch verification is not available for this key type. */
    CHECK(!cmt_should_batch_verify(&g_vs, &g_commit),
          "shouldBatchVerify is false — no ML-DSA-87 batch verifier"); OK();
    return 0;
}

/* ══ 2. verifyBasicValsAndCommit — the four argument checks ═══════════ */

static int t_basic(void)
{
    cmt_block_id_t other;

    if (make_good_commit() != 0) return 1;

    /* :413-415 — set size vs signature count, BOTH directions. */
    g_commit.signatures_len = NVALS + 1;
    set_entry(NVALS, (int32_t)CMT_BLOCK_ID_FLAG_ABSENT);
    CHECK(cmt_verify_commit(g_chain, sizeof(g_chain), &g_vs,
                            &g_commit.block_id, HEIGHT, &g_commit,
                            NULL) == CMT_REJECT,
          "5 signatures for 4 validators is refused"); OK();
    g_commit.signatures_len = NVALS - 1;
    CHECK(cmt_verify_commit(g_chain, sizeof(g_chain), &g_vs,
                            &g_commit.block_id, HEIGHT, &g_commit,
                            NULL) == CMT_REJECT,
          "3 signatures for 4 validators is refused"); OK();
    g_commit.signatures_len = NVALS;

    /* :418-420 — the height. */
    CHECK(cmt_verify_commit(g_chain, sizeof(g_chain), &g_vs,
                            &g_commit.block_id, HEIGHT - 1, &g_commit,
                            NULL) == CMT_REJECT,
          "a commit for another height is refused"); OK();

    /* :421-424 — the BlockID. */
    make_block_id(&other, 0x77);
    CHECK(cmt_verify_commit(g_chain, sizeof(g_chain), &g_vs, &other,
                            HEIGHT, &g_commit, NULL) == CMT_REJECT,
          "a commit for another block is refused"); OK();

    /* The replay barrier: the same commit on another chain does not
     * verify, because the chain id is inside the signed bytes. */
    {
        uint8_t alt[32];

        memcpy(alt, g_chain, sizeof(alt));
        alt[0] = (uint8_t)(alt[0] ^ 0x01u);
        CHECK(cmt_verify_commit(alt, sizeof(alt), &g_vs,
                                &g_commit.block_id, HEIGHT, &g_commit,
                                NULL) == CMT_REJECT,
              "the same commit does not verify on another chain"); OK();
    }

    /* NULL arguments are FAULTs, not verdicts (R1B-10). */
    CHECK(cmt_verify_basic_vals_and_commit(NULL, &g_commit, HEIGHT,
                                           &g_commit.block_id) == CMT_FAULT,
          "NULL set"); OK();
    CHECK(cmt_verify_basic_vals_and_commit(&g_vs, NULL, HEIGHT,
                                           &g_commit.block_id) == CMT_FAULT,
          "NULL commit"); OK();
    CHECK(cmt_verify_basic_vals_and_commit(&g_vs, &g_commit, HEIGHT,
                                           NULL) == CMT_FAULT,
          "NULL block id"); OK();
    CHECK(cmt_verify_basic_vals_and_commit(&g_vs, &g_commit, HEIGHT,
                                           &g_commit.block_id) == CMT_OK,
          "and the good arguments pass"); OK();
    return 0;
}

/* ══ 3. ABSENT is ignored; NIL is verified but not counted ════════════ */

static int t_absent_and_nil(void)
{
    cmt_vs_error_t err;
    size_t         idx_of_40 = 0;
    size_t         idx_of_10 = 0;
    size_t         i;

    /* Find the indices of the strongest and weakest validators; the set is
     * sorted by power descending, but the test does not assume it. */
    for (i = 0; i < NVALS; i++) {
        if (g_vs.validators[i].voting_power == 40) idx_of_40 = i;
        if (g_vs.validators[i].voting_power == 10) idx_of_10 = i;
    }

    /* ── ABSENT: skipped entirely (:39, :345-347). ── */
    if (make_good_commit() != 0) return 1;
    set_entry(idx_of_10, (int32_t)CMT_BLOCK_ID_FLAG_ABSENT);
    CHECK(cmt_verify_commit(g_chain, sizeof(g_chain), &g_vs,
                            &g_commit.block_id, HEIGHT, &g_commit,
                            &err) == CMT_OK,
          "one absent validator: 90 of 100 still exceeds 66"); OK();

    /* An ABSENT entry is never verified, so it does not even need to be
     * well-formed in the way a signed one does — the ignore test at :345
     * runs BEFORE CommitSig.ValidateBasic at :349. */
    CHECK(g_sigs[idx_of_10].signature_len == 0u &&
          g_sigs[idx_of_10].validator_address_len == 0u,
          "and an absent entry carries no address and no signature"); OK();

    /* ── NIL: verified, but NOT counted (:42, :387). ── */
    if (make_good_commit() != 0) return 1;
    set_entry(idx_of_40, (int32_t)CMT_BLOCK_ID_FLAG_NIL);
    if (sign_entry(idx_of_40, g_chain, sizeof(g_chain)) != 0) return 1;

    err.code = CMT_VS_ERR_NONE;
    CHECK(cmt_verify_commit(g_chain, sizeof(g_chain), &g_vs,
                            &g_commit.block_id, HEIGHT, &g_commit,
                            &err) == CMT_REJECT,
          "the 40-power validator voting nil drops the tally to 60"); OK();
    CHECK(err.code == CMT_VS_ERR_NOT_ENOUGH_VOTING_POWER_SIGNED,
          "and the reason is ErrNotEnoughVotingPowerSigned"); OK();
    CHECK(err.got == 60 && err.needed == 66,
          "carrying got = 60 and needed = 66"); OK();
    CHECK(cmt_is_err_not_enough_voting_power_signed(&err),
          "which the reference's own type test recognises"); OK();

    /* THE POINT OF THE NIL CASE: that signature WAS verified. Corrupt it
     * and the verdict changes from "not enough power" to "bad signature" —
     * so a forged nil vote cannot hide behind not being counted. */
    g_sigs[idx_of_40].signature[0] =
        (uint8_t)(g_sigs[idx_of_40].signature[0] ^ 0x01u);
    err.code = CMT_VS_ERR_NONE;
    CHECK(cmt_verify_commit(g_chain, sizeof(g_chain), &g_vs,
                            &g_commit.block_id, HEIGHT, &g_commit,
                            &err) == CMT_REJECT,
          "a forged NIL signature is refused"); OK();
    CHECK(err.code == CMT_VS_ERR_NONE,
          "and NOT as a voting-power failure — the nil entry is verified");
    OK();

    /* Everyone nil: tally 0. */
    if (make_good_commit() != 0) return 1;
    for (i = 0; i < NVALS; i++) {
        set_entry(i, (int32_t)CMT_BLOCK_ID_FLAG_NIL);
    }
    for (i = 0; i < NVALS; i++) {
        if (sign_entry(i, g_chain, sizeof(g_chain)) != 0) return 1;
    }
    err.code = CMT_VS_ERR_NONE;
    CHECK(cmt_verify_commit(g_chain, sizeof(g_chain), &g_vs,
                            &g_commit.block_id, HEIGHT, &g_commit,
                            &err) == CMT_REJECT,
          "all nil: nothing counts"); OK();
    CHECK(err.got == 0 && err.needed == 66, "got 0, needed 66"); OK();

    /* Everyone absent: tally 0, and nothing is verified at all. */
    if (make_good_commit() != 0) return 1;
    for (i = 0; i < NVALS; i++) {
        set_entry(i, (int32_t)CMT_BLOCK_ID_FLAG_ABSENT);
    }
    err.code = CMT_VS_ERR_NONE;
    CHECK(cmt_verify_commit(g_chain, sizeof(g_chain), &g_vs,
                            &g_commit.block_id, HEIGHT, &g_commit,
                            &err) == CMT_REJECT,
          "all absent: nothing counts"); OK();
    CHECK(err.got == 0 && err.needed == 66, "got 0, needed 66"); OK();
    return 0;
}

/* ══ 4. every signature is checked — the countAllSignatures property ══ */

static int t_check_all_signatures(void)
{
    size_t i;
    size_t last = 0;
    size_t idx_of_10 = 0;

    for (i = 0; i < NVALS; i++) {
        if (g_vs.validators[i].voting_power == 10) idx_of_10 = i;
    }
    last = NVALS - 1;

    /* Corrupt the WEAKEST validator's signature. By the time the loop
     * reaches it, the tally from the others is 90, already past 66 — so an
     * implementation with an early exit would ACCEPT this commit. The
     * reference does not (validation.go:52 passes countAllSignatures =
     * true, and :392 is the branch that is thereby disabled). */
    if (make_good_commit() != 0) return 1;
    g_sigs[idx_of_10].signature[0] =
        (uint8_t)(g_sigs[idx_of_10].signature[0] ^ 0x01u);
    CHECK(cmt_verify_commit(g_chain, sizeof(g_chain), &g_vs,
                            &g_commit.block_id, HEIGHT, &g_commit,
                            NULL) == CMT_REJECT,
          "a bad signature AFTER 2/3 is reached still refuses"); OK();

    /* The same commit with the early exit ENABLED accepts it — which is
     * what the internal function does when countAllSignatures is false,
     * and exactly why VerifyCommit does not pass false. */
    CHECK(cmt_verify_commit_single(g_chain, sizeof(g_chain), &g_vs,
                                   &g_commit, 66,
                                   CMT_SIG_POLICY_COMMIT,
                                   false, true, NULL) == CMT_OK,
          "with countAllSignatures FALSE the same commit passes — the two "
          "differ, and VerifyCommit takes the strict one"); OK();

    /* A corrupted signature at the LAST index, truncated to zero length,
     * is refused by CommitSig.ValidateBasic before the verifier
     * (:349-351). */
    if (make_good_commit() != 0) return 1;
    g_sigs[last].signature_len = 0u;
    CHECK(cmt_verify_commit(g_chain, sizeof(g_chain), &g_vs,
                            &g_commit.block_id, HEIGHT, &g_commit,
                            NULL) == CMT_REJECT,
          "an empty signature on a non-absent entry is refused"); OK();

    /* An over-long signature length is refused the same way. */
    if (make_good_commit() != 0) return 1;
    g_sigs[0].signature_len = (size_t)CMT_MAX_SIGNATURE_SIZE + 1u;
    CHECK(cmt_verify_commit(g_chain, sizeof(g_chain), &g_vs,
                            &g_commit.block_id, HEIGHT, &g_commit,
                            NULL) == CMT_REJECT,
          "an over-long signature length is refused, never read"); OK();

    /* A validator with no public key (:375-377). */
    if (make_good_commit() != 0) return 1;
    g_vs.validators[0].pub_key.present = false;
    CHECK(cmt_verify_commit(g_chain, sizeof(g_chain), &g_vs,
                            &g_commit.block_id, HEIGHT, &g_commit,
                            NULL) == CMT_REJECT,
          "a validator with a nil PubKey is refused"); OK();
    g_vs.validators[0].pub_key.present = true;
    CHECK(cmt_verify_commit(g_chain, sizeof(g_chain), &g_vs,
                            &g_commit.block_id, HEIGHT, &g_commit,
                            NULL) == CMT_OK, "restored"); OK();
    return 0;
}

/* ══ 5. the address-lookup branch (lookUpByIndex == false) ════════════ */

static int t_by_address(void)
{
    cmt_vs_error_t err;
    size_t         idx_of_40 = 0;
    size_t         i;

    for (i = 0; i < NVALS; i++) {
        if (g_vs.validators[i].voting_power == 40) idx_of_40 = i;
    }

    /* The branch is only reachable from the out-of-scope Trusting family,
     * so it is exercised here through the internal function directly. With
     * addresses that match their indices it agrees with the index branch. */
    if (make_good_commit() != 0) return 1;
    CHECK(cmt_verify_commit_single(g_chain, sizeof(g_chain), &g_vs,
                                   &g_commit, 66, CMT_SIG_POLICY_COMMIT,
                                   true, false, NULL) == CMT_OK,
          "by address, a well-formed commit verifies"); OK();

    /* :362-364 — a signature belonging to nobody in the set is SKIPPED,
     * not refused. Removing the 40-power validator's contribution drops
     * the tally to 60, which is how the skip becomes observable. */
    if (make_good_commit() != 0) return 1;
    pat(g_sigs[idx_of_40].validator_address, 32, 0xEE);   /* a stranger */
    err.code = CMT_VS_ERR_NONE;
    CHECK(cmt_verify_commit_single(g_chain, sizeof(g_chain), &g_vs,
                                   &g_commit, 66, CMT_SIG_POLICY_COMMIT,
                                   true, false, &err) == CMT_REJECT,
          "an unknown address is skipped, so its power never counts"); OK();
    CHECK(err.code == CMT_VS_ERR_NOT_ENOUGH_VOTING_POWER_SIGNED &&
          err.got == 60 && err.needed == 66,
          "got 60 — skipped, not rejected outright"); OK();

    /* :368-372 — the same validator twice is a DOUBLE VOTE and refuses.
     * The check sits before the signature is verified, so the second
     * entry's signature does not need to be valid for this to fire. */
    if (make_good_commit() != 0) return 1;
    memcpy(g_sigs[1].validator_address, g_sigs[0].validator_address, 32);
    CHECK(cmt_verify_commit_single(g_chain, sizeof(g_chain), &g_vs,
                                   &g_commit, 66, CMT_SIG_POLICY_COMMIT,
                                   true, false, &err) == CMT_REJECT,
          "the same validator signing twice is refused"); OK();
    CHECK(err.code == CMT_VS_ERR_NONE,
          "as a double vote, not as insufficient power"); OK();

    /* ⚠ AND SINCE cometbft v0.38.21 THE INDEX BRANCH REFUSES IT TOO.
     *
     * `CanonicalVote` (proto/tendermint/types/canonical.proto:30-37) has
     * SIX fields — type, height, round, block_id, timestamp, chain_id —
     * and ValidatorAddress is NOT among them, so the address is not inside
     * the bytes anybody signed. Up to 709fd12b the index branch never read
     * it, and this very commit was ACCEPTED. CSA-2026-001 "Tachyon"
     * (cometbft@v0.38.26 types/validation.go:362-365) makes the index
     * branch compare it with the address of the validator at that index;
     * entry 1 now names validator 0, so it is refused before its
     * signature is even looked at. */
    CHECK(cmt_verify_commit_single(g_chain, sizeof(g_chain), &g_vs,
                                   &g_commit, 66, CMT_SIG_POLICY_COMMIT,
                                   true, true, &err) == CMT_REJECT,
          "by index the same commit is REFUSED: the address must match "
          "the validator at the index (Tachyon)"); OK();
    CHECK(err.code == CMT_VS_ERR_NONE,
          "as an address mismatch, not as insufficient power"); OK();

    /* CMT_SIG_POLICY_LIGHT: ignore everything that is not COMMIT, and
     * count everything that survives. With all four COMMIT the two
     * policies agree; with one NIL they do not, because LIGHT ignores the
     * nil entry (never verifying it) where COMMIT verifies it. */
    if (make_good_commit() != 0) return 1;
    set_entry(idx_of_40, (int32_t)CMT_BLOCK_ID_FLAG_NIL);
    if (sign_entry(idx_of_40, g_chain, sizeof(g_chain)) != 0) return 1;
    g_sigs[idx_of_40].signature[0] =
        (uint8_t)(g_sigs[idx_of_40].signature[0] ^ 0x01u);
    CHECK(cmt_verify_commit_single(g_chain, sizeof(g_chain), &g_vs,
                                   &g_commit, 66, CMT_SIG_POLICY_COMMIT,
                                   true, true, NULL) == CMT_REJECT,
          "COMMIT policy verifies the forged nil entry and refuses"); OK();
    CHECK(cmt_verify_commit_single(g_chain, sizeof(g_chain), &g_vs,
                                   &g_commit, 59, CMT_SIG_POLICY_LIGHT,
                                   true, true, NULL) == CMT_OK,
          "LIGHT policy ignores it entirely — which is why VerifyCommit "
          "does not use that policy"); OK();
    return 0;
}

/* ══ 5b. CSA-2026-001 "Tachyon": the address must match the index ═════
 *
 * PROJECT-AUTHORED, not an upstream vector: the v0.38.21..v0.38.26 test
 * diff carries no case for this check (types/validation_test.go changed
 * only in formatting). It pins cometbft@v0.38.26
 * types/validation.go:362-365 by constructing the attack the advisory
 * describes, with REAL signatures:
 *   · validators 40 and 30 stamp T; validators 20 and 10 (30 of 100, less
 *     than a third) stamp T+1000 s. Honestly the weighted median is T.
 *   · the two minority entries keep their OWN valid signatures but name
 *     the 40-power validator's ADDRESS. CanonicalVote does not contain the
 *     address, so every signature still verifies.
 *   · MedianTime (state/state.go:282) looks signers up by address, so it
 *     now weighs each minority stamp at 40 and the median jumps to T+1000.
 * Without the check (709fd12b) `cmt_verify_commit` ACCEPTED this commit;
 * with it VerifyCommit and VerifyCommitLightAllSignatures refuse it.
 * VerifyCommitLight exits at 2/3 before the forged entries and accepts
 * it, as the reference's does; a second arrangement puts the forgery
 * before the 2/3 point and shows the light path refusing it there. */
static int t_tachyon(void)
{
    const int64_t base = 1700000000;
    size_t        idx[4] = { 0, 0, 0, 0 };   /* by power: 40, 30, 20, 10 */
    cmt_time_t    median;
    size_t        i;

    for (i = 0; i < NVALS; i++) {
        switch (g_vs.validators[i].voting_power) {
        case 40: idx[0] = i; break;
        case 30: idx[1] = i; break;
        case 20: idx[2] = i; break;
        default: idx[3] = i; break;
        }
    }

    cmt_pb_commit_init(&g_commit);
    g_commit.height     = HEIGHT;
    g_commit.round      = ROUND;
    make_block_id(&g_commit.block_id, 0x11);
    g_commit.signatures     = g_sigs;
    g_commit.signatures_cap = NVALS + 1;
    g_commit.signatures_len = NVALS;
    for (i = 0; i < NVALS; i++) {
        set_entry(i, (int32_t)CMT_BLOCK_ID_FLAG_COMMIT);
        g_sigs[i].timestamp.seconds = base;
    }
    g_sigs[idx[2]].timestamp.seconds = base + 1000;
    g_sigs[idx[3]].timestamp.seconds = base + 1000;
    for (i = 0; i < NVALS; i++) {
        if (sign_entry(i, g_chain, sizeof(g_chain)) != 0) return 1;
    }

    CHECK(cmt_verify_commit(g_chain, sizeof(g_chain), &g_vs,
                            &g_commit.block_id, HEIGHT, &g_commit,
                            NULL) == CMT_OK,
          "the honest commit verifies"); OK();
    CHECK(cmt_state_median_time(&g_commit, &g_vs, &median) == CMT_OK &&
          median.seconds == base && median.nanos == 0,
          "and its weighted median is T"); OK();

    /* The forgery: the minority keeps its signatures, borrows an address. */
    memcpy(g_sigs[idx[2]].validator_address,
           g_vs.validators[idx[0]].address, 32);
    memcpy(g_sigs[idx[3]].validator_address,
           g_vs.validators[idx[0]].address, 32);

    CHECK(cmt_state_median_time(&g_commit, &g_vs, &median) == CMT_OK &&
          median.seconds == base + 1000,
          "MedianTime alone would move to T+1000 — the damage the check "
          "prevents"); OK();
    CHECK(cmt_verify_commit(g_chain, sizeof(g_chain), &g_vs,
                            &g_commit.block_id, HEIGHT, &g_commit,
                            NULL) == CMT_REJECT,
          "VerifyCommit refuses the borrowed address (validation.go:362)");
    OK();
    /* ⚠ VerifyCommitLight ACCEPTS this commit, in the reference too. It
     * stops as soon as the tally exceeds 2/3 (countAllSignatures false,
     * cometbft@v0.38.26 validation.go:401-403). The set is ordered by
     * power descending, so the 40 and 30 entries come first, 70 > 66,
     * and the loop returns before it ever reaches the two borrowed
     * addresses at the 20 and 10 indices. That early exit is exactly why
     * v0.38.22 made block sync run the FULL check as well (#5663). */
    CHECK(idx[0] < idx[2] && idx[1] < idx[2] && idx[0] < idx[3] &&
          idx[1] < idx[3],
          "precondition: the two honest heavy entries precede the forged "
          "ones"); OK();
    CHECK(cmt_verify_commit_light(g_chain, sizeof(g_chain), &g_vs,
                                  &g_commit.block_id, HEIGHT, &g_commit,
                                  NULL) == CMT_OK,
          "VerifyCommitLight exits at 2/3 before the forged entries");
    OK();
    CHECK(cmt_verify_commit_light_all_signatures(
              g_chain, sizeof(g_chain), &g_vs, &g_commit.block_id, HEIGHT,
              &g_commit, NULL) == CMT_REJECT,
          "VerifyCommitLightAllSignatures visits them and refuses"); OK();

    /* The light path IS covered when the borrowed address sits BEFORE the
     * 2/3 point: the 30-power entry names the 40's address. After the 40
     * the tally is 40 <= 66, so the light loop reaches index idx[1] and
     * the Tachyon check (:362-365) refuses it. */
    memcpy(g_sigs[idx[2]].validator_address,
           g_vs.validators[idx[2]].address, 32);
    memcpy(g_sigs[idx[3]].validator_address,
           g_vs.validators[idx[3]].address, 32);
    memcpy(g_sigs[idx[1]].validator_address,
           g_vs.validators[idx[0]].address, 32);
    CHECK(cmt_verify_commit_light(g_chain, sizeof(g_chain), &g_vs,
                                  &g_commit.block_id, HEIGHT, &g_commit,
                                  NULL) == CMT_REJECT,
          "VerifyCommitLight refuses a borrowed address it reaches"); OK();
    memcpy(g_sigs[idx[1]].validator_address,
           g_vs.validators[idx[1]].address, 32);

    /* Only the address was wrong: restoring it restores the verdict. */
    memcpy(g_sigs[idx[2]].validator_address,
           g_vs.validators[idx[2]].address, 32);
    memcpy(g_sigs[idx[3]].validator_address,
           g_vs.validators[idx[3]].address, 32);
    CHECK(cmt_verify_commit(g_chain, sizeof(g_chain), &g_vs,
                            &g_commit.block_id, HEIGHT, &g_commit,
                            NULL) == CMT_OK,
          "restored addresses verify again"); OK();

    /* An ABSENT entry carries no address and is ignored before the check
     * (:350-352), so it can never trip it. */
    set_entry(idx[3], (int32_t)CMT_BLOCK_ID_FLAG_ABSENT);
    CHECK(cmt_verify_commit(g_chain, sizeof(g_chain), &g_vs,
                            &g_commit.block_id, HEIGHT, &g_commit,
                            NULL) == CMT_OK,
          "an absent entry is not address-checked"); OK();
    return 0;
}

/* ══ 5c. VerifyCommitExtended — cometbft@v0.38.26
 *       types/validator_set_test.go:1649-1740 TestVerifyCommitExtended
 *
 * The four upstream cases, on this file's real ML-DSA-87 keys:
 *   · "happy path": every entry COMMIT with a signed extension → OK;
 *   · "invalid signature": entry 1's extension signature replaced → the
 *     commit is refused (upstream: "invalid vote extension signature
 *     (val #1)");
 *   · "nil extended commit": an error upstream; FAULT here (R1B-10 — a
 *     NULL pointer cannot come off the wire in C);
 *   · "allows absent and nil votes": one NIL and one ABSENT entry, neither
 *     carrying extension data, pass (VerifyExtension's early return,
 *     v0.38.26 vote.go:268-270).
 * The function is new in v0.38.22, so there is no 709fd12b behaviour to
 * be RED against; these cases pin the port against upstream's own. */
static cmt_extended_commit_sig_t g_esigs[NVALS];
static cmt_commit_sig_t          g_tosigs[NVALS];
static uint8_t                   g_ext_scratch[256];

/* Turn g_commit into an extended commit whose COMMIT entries carry the
 * extension "ext-<i>" signed by the validator at index i. */
static int make_ext_commit(cmt_extended_commit_t *ec, uint8_t ext[][8])
{
    size_t i;

    memset(ec, 0, sizeof(*ec));
    ec->height                  = g_commit.height;
    ec->round                   = g_commit.round;
    ec->block_id                = g_commit.block_id;
    ec->extended_signatures     = g_esigs;
    ec->extended_signatures_cap = NVALS;
    ec->extended_signatures_len = NVALS;
    for (i = 0; i < NVALS; i++) {
        cmt_vote_t vote;
        size_t     sb_len;
        size_t     siglen;

        memset(&g_esigs[i], 0, sizeof(g_esigs[i]));
        g_esigs[i].commit_sig = g_sigs[i];
        if (g_sigs[i].block_id_flag != (int32_t)CMT_BLOCK_ID_FLAG_COMMIT) {
            continue;          /* absent / nil: no extension data at all */
        }
        memcpy(ext[i], "ext-", 4);
        ext[i][4] = (uint8_t)('0' + i);
        g_esigs[i].extension.data = ext[i];
        g_esigs[i].extension.len  = 5u;
        if (cmt_extended_commit_get_extended_vote(ec, (int32_t)i, &vote) !=
                CMT_OK ||
            cmt_vote_extension_sign_bytes(g_chain, sizeof(g_chain), &vote,
                                          g_ext_scratch,
                                          sizeof(g_ext_scratch),
                                          &sb_len) != CMT_OK ||
            qgp_dsa87_sign(g_esigs[i].extension_signature, &siglen,
                           g_ext_scratch, sb_len,
                           g_sk[g_key_of_index[i]]) != 0) {
            fprintf(stderr, "extension %zu could not be signed\n", i);
            return 1;
        }
        g_esigs[i].extension_signature_len = siglen;
    }
    return 0;
}

static int t_verify_commit_extended(void)
{
    cmt_extended_commit_t ec;
    uint8_t               ext[NVALS][8];
    size_t                idx_of_10 = 0;
    size_t                idx_of_20 = 0;
    size_t                i;

    for (i = 0; i < NVALS; i++) {
        if (g_vs.validators[i].voting_power == 10) idx_of_10 = i;
        if (g_vs.validators[i].voting_power == 20) idx_of_20 = i;
    }

    /* "happy path" */
    if (make_good_commit() != 0) return 1;
    if (make_ext_commit(&ec, ext) != 0) return 1;
    CHECK(cmt_validator_set_verify_commit_extended(
              &g_vs, g_chain, sizeof(g_chain), &g_commit.block_id, HEIGHT,
              &ec, g_tosigs, NVALS, g_ext_scratch,
              sizeof(g_ext_scratch)) == CMT_OK,
          "a fully signed extended commit verifies"); OK();

    /* "invalid signature" — entry 1's extension signature is garbage. */
    g_esigs[1].extension_signature[0] =
        (uint8_t)(g_esigs[1].extension_signature[0] ^ 0x01u);
    CHECK(cmt_validator_set_verify_commit_extended(
              &g_vs, g_chain, sizeof(g_chain), &g_commit.block_id, HEIGHT,
              &ec, g_tosigs, NVALS, g_ext_scratch,
              sizeof(g_ext_scratch)) == CMT_REJECT,
          "a bad extension signature is refused"); OK();
    g_esigs[1].extension_signature[0] =
        (uint8_t)(g_esigs[1].extension_signature[0] ^ 0x01u);

    /* EnsureExtensions(true) runs first: a COMMIT entry with no
     * extension signature is refused before anything is verified. */
    {
        size_t saved = g_esigs[2].extension_signature_len;

        g_esigs[2].extension_signature_len = 0u;
        CHECK(cmt_validator_set_verify_commit_extended(
                  &g_vs, g_chain, sizeof(g_chain), &g_commit.block_id,
                  HEIGHT, &ec, g_tosigs, NVALS, g_ext_scratch,
                  sizeof(g_ext_scratch)) == CMT_REJECT,
              "a COMMIT entry without an extension signature is refused");
        OK();
        g_esigs[2].extension_signature_len = saved;
    }

    /* The regular commit is verified too: a bad PRECOMMIT signature. */
    g_esigs[0].commit_sig.signature[0] =
        (uint8_t)(g_esigs[0].commit_sig.signature[0] ^ 0x01u);
    CHECK(cmt_validator_set_verify_commit_extended(
              &g_vs, g_chain, sizeof(g_chain), &g_commit.block_id, HEIGHT,
              &ec, g_tosigs, NVALS, g_ext_scratch,
              sizeof(g_ext_scratch)) == CMT_REJECT,
          "a bad commit signature is refused by the VerifyCommit step");
    OK();
    g_esigs[0].commit_sig.signature[0] =
        (uint8_t)(g_esigs[0].commit_sig.signature[0] ^ 0x01u);

    /* "nil extended commit" */
    CHECK(cmt_validator_set_verify_commit_extended(
              &g_vs, g_chain, sizeof(g_chain), &g_commit.block_id, HEIGHT,
              NULL, g_tosigs, NVALS, g_ext_scratch,
              sizeof(g_ext_scratch)) == CMT_FAULT,
          "a NULL extended commit is a FAULT (R1B-10)"); OK();

    /* "allows absent and nil votes in extended commit": the 20-power
     * validator votes NIL, the 10-power one is ABSENT; 70 of 100 still
     * exceeds 66. Neither carries extension data. */
    if (make_good_commit() != 0) return 1;
    set_entry(idx_of_20, (int32_t)CMT_BLOCK_ID_FLAG_NIL);
    if (sign_entry(idx_of_20, g_chain, sizeof(g_chain)) != 0) return 1;
    set_entry(idx_of_10, (int32_t)CMT_BLOCK_ID_FLAG_ABSENT);
    if (make_ext_commit(&ec, ext) != 0) return 1;
    CHECK(g_esigs[idx_of_20].extension.len == 0u &&
          g_esigs[idx_of_20].extension_signature_len == 0u &&
          g_esigs[idx_of_10].extension.len == 0u &&
          g_esigs[idx_of_10].extension_signature_len == 0u,
          "the nil and absent entries carry no extension data"); OK();
    CHECK(cmt_validator_set_verify_commit_extended(
              &g_vs, g_chain, sizeof(g_chain), &g_commit.block_id, HEIGHT,
              &ec, g_tosigs, NVALS, g_ext_scratch,
              sizeof(g_ext_scratch)) == CMT_OK,
          "absent and nil entries pass"); OK();
    return 0;
}

/* ══ 6. NULL and shape guards on the internal function ════════════════ */

static int t_guards(void)
{
    if (make_good_commit() != 0) return 1;

    CHECK(cmt_verify_commit_single(g_chain, sizeof(g_chain), NULL,
                                   &g_commit, 66, CMT_SIG_POLICY_COMMIT,
                                   true, true, NULL) == CMT_FAULT,
          "NULL set"); OK();
    CHECK(cmt_verify_commit_single(g_chain, sizeof(g_chain), &g_vs,
                                   NULL, 66, CMT_SIG_POLICY_COMMIT,
                                   true, true, NULL) == CMT_FAULT,
          "NULL commit"); OK();

    /* More signatures than validators, called directly: the index branch
     * cannot index the set and REJECTS rather than reading past it
     * (INVARIANT atlas-dec-7495d3372e004b24b4f6cc7bff5caf07). VerifyCommit
     * never reaches this, because :413 refuses the mismatch first. */
    g_commit.signatures_len = NVALS + 1;
    /* ⚠ Hand-filled, NOT through set_entry: that helper copies the address
     * of `g_vs.validators[i]`, and there is no validator at index NVALS —
     * reading one would run 2.6 KB past g_storage. The entry only has to
     * pass CommitSig.ValidateBasic (32-byte address, non-empty signature)
     * so that the loop reaches the index check that is under test. */
    memset(&g_sigs[NVALS], 0, sizeof(g_sigs[NVALS]));
    g_sigs[NVALS].block_id_flag = (int32_t)CMT_BLOCK_ID_FLAG_COMMIT;
    pat(g_sigs[NVALS].validator_address, 32, 0xC3);
    g_sigs[NVALS].validator_address_len = 32u;
    g_sigs[NVALS].timestamp.seconds     = 1700000000;
    g_sigs[NVALS].signature_len         = 64u;
    CHECK(cmt_verify_commit_single(g_chain, sizeof(g_chain), &g_vs,
                                   &g_commit, 66, CMT_SIG_POLICY_COMMIT,
                                   true, true, NULL) == CMT_REJECT,
          "an index past the set is refused, never read"); OK();
    g_commit.signatures_len = NVALS;

    /* A NULL signature array with a non-zero count. */
    g_commit.signatures = NULL;
    CHECK(cmt_verify_commit_single(g_chain, sizeof(g_chain), &g_vs,
                                   &g_commit, 66, CMT_SIG_POLICY_COMMIT,
                                   true, true, NULL) == CMT_FAULT,
          "a NULL signature list with a non-zero count is a FAULT"); OK();
    g_commit.signatures = g_sigs;
    return 0;
}

int main(void)
{
    int rc = 1;

    g_scratch = (cmt_valset_scratch_t *)malloc(sizeof(*g_scratch));
    if (g_scratch == NULL) {
        fprintf(stderr, "scratch allocation failed\n");
        return 1;
    }
    pat(g_chain, sizeof(g_chain), 0x50);

    if (build_set() != 0) goto out;
    if (t_good() != 0) goto out;
    if (t_basic() != 0) goto out;
    if (t_absent_and_nil() != 0) goto out;
    if (t_check_all_signatures() != 0) goto out;
    if (t_by_address() != 0) goto out;
    if (t_tachyon() != 0) goto out;
    if (t_verify_commit_extended() != 0) goto out;
    if (t_guards() != 0) goto out;

    printf("test_cmt_validation: %d checks OK\n", g_checks);
    rc = 0;
out:
    free(g_scratch);
    return rc;
}
