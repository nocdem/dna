/**
 * @file shared/dnac/cmt_validation.h
 * @brief cometbft @v0.38.26 `types/validation.go` ported to C — verifying
 *        that more than 2/3 of a validator set signed a commit.
 *
 * ═══ ACTIVATION: INACTIVE ═══════════════════════════════════════════════
 * Wave R1-D of the cometbft → C consensus port. No consensus path calls
 * anything here yet; the module is additive only. The live witness BFT,
 * QC V2 and the T3 wave-1 modules are byte-identically untouched.
 * ════════════════════════════════════════════════════════════════════════
 *
 * ── WHAT THIS FILE DECIDES ─────────────────────────────────────────────
 * Whether a block's LastCommit is a valid commit for a given height and
 * BlockID under a given validator set. It is the check that makes a chain
 * a CHAIN: a block whose LastCommit does not carry more than two thirds of
 * the previous set's voting power is not a continuation of anything.
 *
 * ── EVERY SIGNATURE IS CHECKED, AND THAT IS DELIBERATE ─────────────────
 * `VerifyCommit` passes `countAllSignatures = true` (validation.go:53), so
 * it does NOT stop at the first 2/3 it reaches. The reference's own
 * comment (:23-27) gives the reason: an application's incentive logic sees
 * WHICH validators signed, so a commit that includes a bad signature after
 * the threshold must still be refused. A port that exited early would
 * accept commits the reference rejects — the exact shape of a chain split.
 *
 * ── BATCH VERIFICATION IS UNREACHABLE HERE ─────────────────────────────
 * `shouldBatchVerify` (:15-19) requires `batch.SupportsBatchVerifier` for
 * the proposer's key type (crypto/crypto.go:44-54, crypto/batch). There is
 * no ML-DSA-87 batch verifier — the port map records this at ~954 — so the
 * predicate is FALSE for every key this chain has, and `verifyCommitBatch`
 * (:215-323) has no reachable call site. The predicate is ported as a
 * function that returns false with the citation, and the batch routine is
 * NOT ported: see the taşınmadı list.
 *
 * ── THE LIGHT FAMILY: `VerifyCommitLight` IS PORTED, Trusting IS NOT ──
 * `VerifyCommitLight` / `VerifyCommitLightAllSignatures` /
 * `verifyCommitLightInternal` (:62-116) are PORTED (blocksync port,
 * 2026-09-29), for their then caller `blocksync/reactor.go:496` @709fd12b
 * and the operator's answer in
 * docs/plans/decisions/2026-09-29-blocksync-before-testnet.md ("follow
 * the reference — port VerifyCommitLight"). The v0.38.26 pin moved that
 * caller to the FULL check: block sync now verifies the first block with
 * the SECOND block's LastCommit through `cmt_verify_commit`
 * (v0.38.26 reactor.go:580-585, "Fully verify second.LastCommit";
 * cmt_bsync_reactor.c process_first), so the light pair has NO
 * production caller today — only its tests. The wrappers at
 * `validator_set.go:763-775` are ported with them
 * (cmt_validator_set.h). `VerifyCommitLightTrusting*` (:126-193) stay YOK
 * by the port map's REV 3/3.1 scope rule (map ~892, ~950): their callers
 * are `light/` and the evidence pool, which this port does not build.
 *
 * `verifyCommitSingle` keeps BOTH of its lookup branches and both of its
 * predicate parameters, because they are that function's parameters and
 * dropping them would be a different function. `look_up_by_index = true`
 * is reachable from `cmt_verify_commit` (:52-53, CMT_SIG_POLICY_COMMIT)
 * and from `cmt_verify_commit_light*` (:114-115, CMT_SIG_POLICY_LIGHT);
 * the address branch is reachable only from the Trusting family, and it
 * is ported — with its double-vote check — so that the row is complete
 * and testable.
 *
 * ── Substitutions, and nothing else ────────────────────────────────────
 *  · signature ML-DSA-87 via `qgp_dsa87_verify`, exactly as `cmt_vote_verify`
 *    (cmt_vote.c) does it, in place of `val.PubKey.VerifySignature` (:390);
 *  · `tmhash.Size` 32 → CMT_TMHASH_SIZE 64 at :198 — but that row,
 *    `ValidateHash` (:197-205), is ALREADY PORTED, as `cmt_validate_hash`
 *    (cmt_part_set.h:128). It is NOT duplicated here; it lives there
 *    because `part_set.go:140` calls it and putting it in cmt_block.h
 *    would have made two headers include each other.
 *  · Go's `errors` values become CMT_REJECT plus, for the one error that
 *    carries numbers, the `cmt_vs_error_t` out-parameter
 *    (cmt_validator_set.h:289-293);
 *  · a Go index panic becomes an explicit bounds check (INVARIANT
 *    atlas-dec-7495d3372e004b24b4f6cc7bff5caf07);
 *  · `seenVals`, a Go map, becomes a fixed array indexed by validator
 *    index — no map is iterated anywhere in this file.
 *
 * ── WHICH ERROR TYPES ARE COLLAPSED INTO CMT_REJECT ────────────────────
 * The reference distinguishes them by Go type; this port distinguishes
 * only "the input is bad". The full list, so nothing is hidden:
 *   · `ErrInvalidCommitSignatures{Expected, Actual}` (:423;
 *     types/errors.go:12-15, :30-35) — set size ≠ signature count;
 *   · `ErrInvalidCommitHeight{Expected, Actual}` (:428;
 *     types/errors.go:5-9, :20-25) — wrong height;
 *   · the unnamed `fmt.Errorf` at :431-432 — wrong BlockID;
 *   · the unnamed `fmt.Errorf`s at :355 (a CommitSig that fails
 *     ValidateBasic), :379 (a double vote in the address branch), :385 (a
 *     validator with a nil PubKey) and :391 (a wrong signature).
 * ONLY `ErrNotEnoughVotingPowerSigned{Got, Needed}` (:407;
 * validator_set.go:855-860) survives as a value, because its two numbers
 * are the answer to "how far short was it" and no return code can carry
 * them. It reaches the caller through the optional `err` out-parameter.
 *
 * ── Determinism ────────────────────────────────────────────────────────
 * Every function here is a pure function of its arguments and the set it
 * is given. No clock is read, no randomness is drawn, no map is iterated,
 * no floating point is used, and no allocation is made. Signatures are
 * visited in VALIDATOR-INDEX order — the order the list is built in
 * (D-19 rev 6 item 4; types/vote_set.go:649-658) — and the verdict does
 * not depend on when a check happens to fail, because every non-ignored
 * signature is verified before the tally is compared. Two nodes given the
 * same commit and the same set reach the same verdict.
 *
 * ── taşınmadı (not ported), with the reason ────────────────────────────
 *   · :126-193 `VerifyCommitLightTrusting`,
 *              `VerifyCommitLightTrustingAllSignatures`,
 *              `verifyCommitLightTrustingInternal`
 *                                  — YOK, scope rule (light client /
 *       evidence pool); see above. `verifyCommitLightTrusting`
 *       additionally needs `cmtmath.Fraction` and a trust level, which no
 *       in-scope caller supplies.
 *   (:62-116, the `VerifyCommitLight` trio, were on this list until the
 *   blocksync port; they are ported below.)
 *   · :197-205 `ValidateHash`       — ALREADY PORTED as `cmt_validate_hash`
 *       (cmt_part_set.h:128). Not duplicated; see above.
 *   · :215-323 `verifyCommitBatch`  — taşınmadı: ULAŞILMAZ (v0.38.21
 *       added the Tachyon address check at :250-253 to it — not
 *       ported with it, for the same reason). There is no
 *       ML-DSA-87 batch verifier (crypto/crypto.go:44-54; crypto/batch;
 *       port map ~954), so `shouldBatchVerify` is false for every key here
 *       and this routine has no reachable caller. Writing it would mean
 *       inventing a batch API the crypto layer does not have — the
 *       definition of kafadan. `cmt_should_batch_verify` below records the
 *       predicate and its answer.
 *   · :13 `batchVerifyThreshold`    — a constant used only by the batch
 *       routine and by `shouldBatchVerify`'s first conjunct; the predicate
 *       below is false on the SECOND conjunct regardless, so the constant
 *       has no behavioural role here. Cited, not defined.
 *
 * Reference @v0.38.26 (SHA-256 verified before use):
 *   types/validation.go 436 lines
 *     195fdda35aebc7ba584a7312e321373859866369d56bd67c676ceff78c70d67d
 *   types/errors.go      41 lines
 *     017c05d95f906d3dc0ceddb51e29618136ea66085ef36f41493fc64b26cfe50c
 *   crypto/crypto.go     54 lines
 *     60a32ee2c8f9a1090968ff9fcd3410f0099d21da8c7625b1b03f23d2647a1ceb
 * Governing records: umbrella rev 3 (atlas-dec-d5e766defde138eb6dd02e5b81e735a8),
 * D-19 rev 6 item 4 (atlas-dec-d106407a31d7d16d49d51990b75c36c6),
 * K-1 rev 2 (atlas-dec-3ba8153088b0d60c63083028023b61be),
 * INVARIANT (atlas-dec-7495d3372e004b24b4f6cc7bff5caf07),
 * pin rev 4 (atlas-dec-483ec17cbb352ef0ec2267ccd953339c).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef SHARED_DNAC_CMT_VALIDATION_H
#define SHARED_DNAC_CMT_VALIDATION_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "cmt_tmhash.h"
#include "cmt_block.h"          /* cmt_block_id_t, cmt_commit_t          */
#include "cmt_validator_set.h"  /* cmt_validator_set_t, cmt_vs_error_t   */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The reference's two closure PAIRS, as one enumerated policy.
 *
 * `verifyCommitSingle` takes `ignoreSig` and `countSig` as function values
 * (:337-338). Every call site in the pinned tree passes one of exactly two
 * pairs, so they are enumerated here rather than made function pointers:
 * an enum keeps the call direct (no indirect call in a consensus path) and
 * makes the two policies readable side by side. The SEMANTICS are the
 * reference's, line for line.
 */
typedef enum {
    /**
     * validation.go:40, :43 — `VerifyCommit`'s pair.
     *   ignore: `BlockIDFlag == BlockIDFlagAbsent`  (:40)
     *   count : `BlockIDFlag == BlockIDFlagCommit`  (:43)
     * So an ABSENT entry is skipped entirely; a NIL entry IS VERIFIED but
     * does NOT count toward the tally; only a COMMIT entry counts. That
     * middle case is the one worth remembering: a validator who signed for
     * nil has still signed something, and a forged nil signature must be
     * caught even though it never adds power.
     */
    CMT_SIG_POLICY_COMMIT = 0,
    /**
     * validation.go:102, :105 — the light family's pair.
     *   ignore: `BlockIDFlag != BlockIDFlagCommit`  (:102)
     *   count : always true                         (:105)
     * Passed by `cmt_verify_commit_light` and
     * `cmt_verify_commit_light_all_signatures` (:110, :114-115), which have
     * NO production caller since the v0.38.26 pin: block sync, their
     * caller @709fd12b (reactor.go:496), now calls the full
     * `cmt_verify_commit` (v0.38.26 reactor.go:580-585). A NIL entry is
     * IGNORED here — not verified — which is the light path's difference
     * from CMT_SIG_POLICY_COMMIT.
     */
    CMT_SIG_POLICY_LIGHT = 1
} cmt_commit_sig_policy_t;

/**
 * cometbft@v0.38.26 types/validation.go:15-19 — `shouldBatchVerify()`.
 *
 * ALWAYS FALSE IN THIS PORT, and not because of a shortcut. The second
 * conjunct is `batch.SupportsBatchVerifier(vals.GetProposer().PubKey)`,
 * and the batch package has no ML-DSA-87 implementation to support
 * (crypto/crypto.go:44-54 defines the `BatchVerifier` interface; the port
 * map records the absence at ~954). The first conjunct
 * (`len(commit.Signatures) >= batchVerifyThreshold`, :16) and the third
 * (`vals.AllKeysHaveSameType()`, :18) are therefore never decisive.
 *
 * It is ported as a real function rather than deleted so that
 * `cmt_verify_commit` can make the reference's branch (:46-49) visible and
 * so that a future key type with a batch verifier changes ONE function.
 *
 * @return false, always.
 */
bool cmt_should_batch_verify(const cmt_validator_set_t *vals,
                             const cmt_commit_t *commit);

/**
 * cometbft@v0.38.26 types/validation.go:413-436 —
 * `verifyBasicValsAndCommit()`.
 *
 * Four checks in the reference's order: a non-NULL set (:414-416), a
 * non-NULL commit (:418-420), `vals.Size() == len(commit.Signatures)`
 * (:422-424), `height == commit.Height` (:427-429) and
 * `blockID.Equals(commit.BlockID)` (:430-433).
 *
 * NOTE on the two NULL cases: the reference returns an ERROR for them, not
 * a panic — so a literal reading would make them CMT_REJECT. They are
 * CMT_FAULT here, per deviation register R1B-10, because in C a NULL
 * pointer is a programming error and cannot arrive from the wire: a
 * decoded commit is a struct, not a pointer a peer chose. Treating it as
 * REJECT would let an internal bug be reported as a peer's invalid input,
 * which is the confusion the FAULT code exists to prevent.
 *
 * @return CMT_OK, CMT_REJECT (see the collapsed error list in the file
 *         header), CMT_FAULT on a NULL argument.
 */
int cmt_verify_basic_vals_and_commit(const cmt_validator_set_t *vals,
                                     const cmt_commit_t *commit,
                                     int64_t height,
                                     const cmt_block_id_t *block_id);

/**
 * cometbft@v0.38.26 types/validation.go:332-411 — `verifyCommitSingle()`.
 * (The `:NNN` citations in THIS comment are v0.38.26 lines.)
 *
 * The signature-checking loop itself. Exposed rather than kept private
 * because it is the function the reference exposes to its own callers
 * through six wrappers, and because its `look_up_by_index = false` branch
 * is otherwise untestable.
 *
 * CSA-2026-001 "Tachyon" (v0.38.21, :362-365): on the index path the
 * CommitSig's `validator_address` must EQUAL the address of the validator
 * at that index, or the commit is refused (CMT_REJECT). The address is not
 * inside CanonicalVote, so before this check a commit could pair validator
 * i's valid signature with validator j's address, and MedianTime — which
 * looks signers up by ADDRESS — weighted i's vote stamp with j's power.
 * The same check at :250-253 inside `verifyCommitBatch` is not ported, for
 * the reason in the taşınmadı list (the batch path is unreachable).
 *
 * CONTRACT (the reference's own, :331): both the commit and the validator
 * set must already have passed ValidateBasic. This function does not
 * re-check the set.
 *
 * @param vals NOT const — `TotalVotingPower` is not read here, but
 *        `GetByAddress` and the index accessor are, and the type's
 *        proposer/total cache makes a const set awkward at every call
 *        site; the set is not modified.
 * @param voting_power_needed the threshold, already computed by the caller
 *        (the reference computes it in each wrapper, :37 / :99 / :174).
 * @param count_all_signatures when false, the loop returns as soon as the
 *        tally EXCEEDS the threshold (:401-403). `cmt_verify_commit`
 *        passes true; see "EVERY SIGNATURE IS CHECKED" in the header.
 * @param look_up_by_index true takes the validator at the signature's own
 *        index (:361) and requires the addresses to match (:362-365);
 *        false looks it up BY ADDRESS (:367), skips a signature belonging
 *        to nobody in the set (:371-373) and refuses a validator who
 *        appears twice (:377-381). Only true is reachable from
 *        `cmt_verify_commit` and the `VerifyCommitLight` pair.
 * @param err may be NULL. On CMT_REJECT it receives
 *        `ErrNotEnoughVotingPowerSigned` with `got`/`needed` when that is
 *        the reason, and `CMT_VS_ERR_NONE` for every other rejection — so
 *        a caller can never read a stale payload.
 * @return CMT_OK, CMT_REJECT, CMT_FAULT.
 */
int cmt_verify_commit_single(const uint8_t *chain_id, size_t chain_id_len,
                             cmt_validator_set_t *vals,
                             const cmt_commit_t *commit,
                             int64_t voting_power_needed,
                             cmt_commit_sig_policy_t policy,
                             bool count_all_signatures,
                             bool look_up_by_index,
                             cmt_vs_error_t *err);

/**
 * cometbft@v0.38.26 types/validation.go:28-54 — `VerifyCommit()`.
 *
 * "Verifies +2/3 of the set had signed the given commit." The threshold is
 * `vals.TotalVotingPower() * 2 / 3` (:37) and the comparison is STRICTLY
 * GREATER (`got <= needed` rejects, :406) — so it is more than two thirds,
 * not at least two thirds. With a total of 100 the threshold is 66 and 67
 * is required; with a total of 3 the threshold is 2 and 3 is required.
 *
 * The reference's own note at :35-36 about the multiplication: the total
 * is capped at `MaxTotalVotingPower = MaxInt64 / 8`
 * (validator_set.go:27), so `total * 2` cannot overflow. That is not
 * assumed here — `cmt_validator_set_total_voting_power` reaches
 * `updateTotalVotingPower`, which refuses a total above the cap
 * (validator_set.go:319-321, CMT_FAULT per deviation register R1C-4), so
 * on any path that returns CMT_OK the bound HOLDS and the doubling is
 * provably safe.
 *
 * @param vals NOT const: `TotalVotingPower()` writes the set's lazily
 *        recomputed cache, exactly as the reference's does
 *        (validator_set.go:341-348).
 * @param err may be NULL; see `cmt_verify_commit_single`.
 * @return CMT_OK, CMT_REJECT, CMT_FAULT.
 */
int cmt_verify_commit(const uint8_t *chain_id, size_t chain_id_len,
                      cmt_validator_set_t *vals,
                      const cmt_block_id_t *block_id,
                      int64_t height,
                      const cmt_commit_t *commit,
                      cmt_vs_error_t *err);

/**
 * cometbft@v0.38.26 types/validation.go:58-70 — `VerifyCommitLight()`.
 *
 * "Verifies +2/3 of the set had signed the given commit. This method is
 * primarily used by the light client and does NOT check all the
 * signatures." (:58-61). It is `verifyCommitLightInternal(..., false)`
 * (:69): the SAME basic checks as `VerifyCommit` (:94-96 →
 * verifyBasicValsAndCommit), the same threshold `total * 2 / 3` compared
 * strictly (:99, :406), but
 *   · only entries FOR THE BLOCK are looked at — ABSENT and NIL are both
 *     ignored without being verified (:102), and every looked-at entry
 *     counts (:105);
 *   · the loop RETURNS as soon as the tally exceeds the threshold
 *     (countAllSignatures false, :401-403), so a bad signature AFTER that
 *     point is not seen. That is the reference's light semantics — the
 *     one block sync used @709fd12b (blocksync/reactor.go:496); since the
 *     v0.38.26 pin block sync uses the full `cmt_verify_commit` and this
 *     function has no production caller. Two nodes given the
 *     same commit and set reach the same verdict, because entries are
 *     visited in validator-index order (:349) and the exit point is a
 *     function of that order only.
 *
 * @param vals NOT const: TotalVotingPower writes the set's cache.
 * @param err may be NULL; see `cmt_verify_commit_single`.
 * @return CMT_OK, CMT_REJECT, CMT_FAULT.
 */
int cmt_verify_commit_light(const uint8_t *chain_id, size_t chain_id_len,
                            cmt_validator_set_t *vals,
                            const cmt_block_id_t *block_id,
                            int64_t height,
                            const cmt_commit_t *commit,
                            cmt_vs_error_t *err);

/**
 * cometbft@v0.38.26 types/validation.go:72-83 —
 * `VerifyCommitLightAllSignatures()`: `verifyCommitLightInternal(...,
 * true)` (:82) — the light ignore/count pair of `cmt_verify_commit_light`
 * with EVERY commit-flagged signature verified before the tally is
 * compared.
 * @return CMT_OK, CMT_REJECT, CMT_FAULT.
 */
int cmt_verify_commit_light_all_signatures(const uint8_t *chain_id,
                                           size_t chain_id_len,
                                           cmt_validator_set_t *vals,
                                           const cmt_block_id_t *block_id,
                                           int64_t height,
                                           const cmt_commit_t *commit,
                                           cmt_vs_error_t *err);

#ifdef __cplusplus
}
#endif

#endif /* SHARED_DNAC_CMT_VALIDATION_H */
