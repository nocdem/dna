/**
 * @file shared/dnac/cmt_vote.h
 * @brief cometbft @709fd12b `types/vote.go` ported to C.
 *
 * ═══ ACTIVATION: INACTIVE ═══════════════════════════════════════════════
 * Wave R1-B of the cometbft → C consensus port. Additive only; nothing in
 * the running chain calls anything here. The live witness BFT, QC V2 and
 * the T3 wave-1 modules (tm_commit, tm_vote, tm_wal) are byte-identically
 * untouched — in particular this file does NOT replace `tm_vote.{h,c}`,
 * which stays exactly as it is.
 * ════════════════════════════════════════════════════════════════════════
 *
 * A vote is what a validator signs, and cmt_canonical decides what the
 * signature covers. This file is the domain object around that: how a vote
 * becomes a CommitSig, what makes it well-formed, and how its signature is
 * checked.
 *
 * ── Domain ↔ wire ──────────────────────────────────────────────────────
 * `types.Vote` (vote.go:64-75) is FIELD-IDENTICAL to R1-A's
 * `cmt_pb_vote_t` — ten fields, same order, same types — so the domain
 * type is a typedef of the wire type and `_to_proto` is the identity, as
 * R1-A did for `cmt_proof_t`. `VoteFromProto` is the identity plus the
 * BlockID conversion.
 *
 * NOTE reference asymmetry (vote.go:77-80 versus :82): the comment says
 * "No validation is performed on the resulting vote", but the very first
 * statement calls `BlockIDFromProto`, which DOES validate (block.go:1548).
 * So a VoteFromProto with a malformed BlockID fails while one with a
 * malformed signature succeeds. Ported as-is; the map records the same
 * asymmetry in its REV 3 table.
 *
 * ── Substitutions, and nothing else ────────────────────────────────────
 * 1. Signature verification is ML-DSA-87 (`qgp_dsa87_verify`,
 *    shared/crypto/sign/qgp_dilithium.h:49-51) in place of the
 *    reference's `pubKey.VerifySignature`. It takes the SIGN BYTES —
 *    the output of cmt_vote_sign_bytes, i.e. cmt_pb_marshal_delimited over
 *    the CanonicalVote — as the message.
 * 2. `crypto.AddressSize` 20 → 32 at vote.go:303-305;
 *    `MaxSignatureSize` 64 → 4627 at :316 and :339.
 * 3. `pubKey.Address()` — see cmt_pubkey_address below; it is the
 *    reference's own construction under the approved substitutions and is
 *    the function this tree already uses.
 * 4. panic → error return; caller-provided buffers for the sign bytes.
 * 5. `PrivValidator.SignVote` (:418) is HOST, reached through the
 *    `cmt_sign_vote_fn` callback declared below.
 *
 * ── Determinism ────────────────────────────────────────────────────────
 * Pure functions of their arguments — except `cmt_sign_and_check_vote`,
 * which calls the host's signer and, at :451, ADOPTS THE TIMESTAMP THE
 * SIGNER RETURNED. That is the reference's single clock-touching path for
 * a vote and the only one the APPROVED clock POLICY
 * (atlas-dec-4ac0423068085c100fdfa3e264ca16bc) permits. No function in
 * this file reads a clock itself.
 *
 * ── taşınmadı (not ported), with the reason ────────────────────────────
 *   · `ErrVoteConflictingVotes.Error` (:39-41),
 *     `ErrVoteExtensionInvalid.Error` (:55-57), `Vote.String` (:190-217) —
 *     display only.
 *   · The nine package-level `errors.New` values (:22-32) — the port has
 *     no error objects; each check names its reference error in a comment
 *     and returns CMT_REJECT.
 *
 * Reference @709fd12b (SHA-256 verified against tasks/comet-port-map.md
 * before use):
 *   types/vote.go             454 lines dd978df4530187c34902fad06ba1f7065896ece92b68d07d3a9bfc55ddb82e0f
 *   types/signed_msg_type.go   28 lines 17cc106f41d16e8f17f6152ddd73df607b02957557df4356c8f74b9750cd3a52
 *   types/signable.go          23 lines cd1dfb0b42c1b1e12e6b2f489fec2eb476d7c75c6aa395247f22e3be025011bd
 *   crypto/crypto.go           54 lines 60a32ee2c8f9a1090968ff9fcd3410f0099d21da8c7625b1b03f23d2647a1ceb
 *   crypto/ed25519/ed25519.go 228 lines d426c56a6ebc2ad3da5c83a1d0cc8d28c44fece62e4cc308d6e0d2d5f536b92b
 *     ⚠ crypto/ed25519/ed25519.go is NOT in the map's pin table; its
 *       SHA-256 was computed here. It is opened for ONE line range
 *       (:156-161, `Address()`), which is the concrete implementation of
 *       the `crypto.PubKey.Address()` interface method vote.go:220 calls.
 * Governing records: umbrella rev 3 (atlas-dec-d5e766defde138eb6dd02e5b81e735a8),
 * D-19 rev 6 (atlas-dec-d106407a31d7d16d49d51990b75c36c6),
 * K-1 rev 2 (atlas-dec-3ba8153088b0d60c63083028023b61be),
 * K-2 (atlas-dec-7fde65722d68b32eca08be61fbcb47ac),
 * INVARIANT (atlas-dec-7495d3372e004b24b4f6cc7bff5caf07),
 * clock POLICY (atlas-dec-4ac0423068085c100fdfa3e264ca16bc).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef SHARED_DNAC_CMT_VOTE_H
#define SHARED_DNAC_CMT_VOTE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "cmt_pb.h"
#include "cmt_block.h"       /* BlockID, CommitSig, ExtendedCommitSig     */
#include "cmt_canonical.h"

#include "crypto/sign/qgp_dilithium.h"

#ifdef __cplusplus
extern "C" {
#endif

/** cometbft@709fd12b types/vote.go:64-75 — `type Vote struct`.
 *  Field-identical to cmt_pb_vote_t; see the header. */
typedef cmt_pb_vote_t cmt_vote_t;

/**
 * The buffer a vote's sign bytes always fit in. Derived from the widest
 * CanonicalVote plus its MarshalDelimited prefix:
 *   type 1+10, height 1+8 (sfixed64), round 1+8, block_id 1+2+140,
 *   timestamp 1+1+17, chain_id 1+1+32 = 215; prefix uvarint(215) = 2.
 * 256 rounds that up. A vote EXTENSION is not in these bytes.
 */
#define CMT_VOTE_SIGN_BYTES_MAX 256

/** cometbft@709fd12b types/signed_msg_type.go:6-13 — `IsVoteTypeValid()`.
 *  Only PREVOTE and PRECOMMIT; PROPOSAL and UNKNOWN are not vote types. */
bool cmt_is_vote_type_valid(int32_t t);

/**
 * cometbft@709fd12b crypto/ed25519/ed25519.go:156-161 —
 * `(pubKey PubKey) Address()`, the concrete implementation of the
 * `crypto.PubKey.Address()` that vote.go:220 compares against a vote's
 * ValidatorAddress. The reference computes `tmhash.SumTruncated(pubKey)`:
 * the first `crypto.AddressSize` bytes of the key's hash
 * (crypto/tmhash/hash.go:74-77; crypto/crypto.go:8-11).
 *
 * DNA: the first CMT_ADDRESS_SIZE (32) bytes of SHA3-512(pubkey) — THE
 * SAME CONSTRUCTION under the approved digest and width substitutions, and
 * the same function this tree already uses to turn a Dilithium public key
 * into a witness id: `nodus_chain_config_derive_witness_id`
 * (nodus/src/witness/nodus_witness_chain_config.c:637-652, declared at
 * nodus/include/nodus/nodus_chain_config.h:319-326 — "first 32 bytes of
 * SHA3-512(pubkey)"). It is REPRODUCED rather than called, because
 * shared/dnac must not depend on nodus/; the bytes are identical. Nothing
 * about the derivation is invented here.
 *
 * SINCE WAVE R1-D THIS IS A ONE-LINE DELEGATE to `cmt_address_hash`
 * (cmt_tmhash.h), which is `crypto.AddressHash` (crypto/crypto.go:18-20) —
 * the function the reference's `Address()` methods actually call. There is
 * now exactly ONE truncation in the tree and two typed wrappers over it,
 * this one and `cmt_pub_key_address` (cmt_validator_set.h). The R1-B note
 * that cmt_tmhash.h contradicted this is RESOLVED: that header's claim was
 * wrong and R1-D corrected it in place.
 *
 * @return CMT_OK, CMT_FAULT on NULL or a hash backend failure.
 */
int cmt_pubkey_address(const uint8_t pubkey[CMT_PB_PUBKEY_LEN],
                       uint8_t out[CMT_ADDRESS_SIZE]);

/** cometbft@709fd12b types/vote.go:34-37 — `type ErrVoteConflictingVotes`.
 *  The two votes only; the reference's `Error()` string (:39-41) is not
 *  ported. The votes are REFERENCED, not copied, as the Go struct's
 *  pointers are. */
typedef struct {
    const cmt_vote_t *vote_a;   /* vote.go:35 */
    const cmt_vote_t *vote_b;   /* vote.go:36 */
} cmt_err_vote_conflicting_votes_t;

/** cometbft@709fd12b types/vote.go:43-48 — `NewConflictingVoteError()`.
 *  @return CMT_OK, CMT_FAULT on NULL. */
int cmt_new_conflicting_vote_error(const cmt_vote_t *vote1,
                                   const cmt_vote_t *vote2,
                                   cmt_err_vote_conflicting_votes_t *out);

/** cometbft@709fd12b types/vote.go:81-99 — `VoteFromProto()`.
 *  The identity plus BlockIDFromProto (:82), which validates — see the
 *  asymmetry note in the header. */
int cmt_vote_from_proto(const cmt_pb_vote_t *pv, cmt_vote_t *out);

/** cometbft@709fd12b types/vote.go:371-390 — `(vote *Vote) ToProto()`.
 *  The identity; a NULL receiver is the reference's nil (:374-376). */
int cmt_vote_to_proto(const cmt_vote_t *vote, cmt_pb_vote_t *out);

/**
 * cometbft@709fd12b types/vote.go:392-406 — `VotesToProto()`.
 * ToProto over a list of POINTERS, and a NULL element is DROPPED rather
 * than emitted (:400-403 — the reference's own comment says protobuf
 * crashes on a nil element of a repeated field). `*out_len` is therefore
 * at most `n`. A NULL `votes` is the reference's nil slice (:393-395) and
 * yields `*out_len == 0`.
 *
 * NOTE: the pinned tree contains NO caller of this function — grep
 * `VotesToProto` finds only its definition. It is ported because it is a
 * KODEK row of vote.go, and because the nil-dropping IS behaviour.
 * @param out caller storage of `cap` elements; may be NULL only when
 *        `cap` is 0, since a list of nothing but NULL elements writes
 *        nothing and the reference returns an empty slice for it.
 * @return CMT_OK; CMT_REJECT when `cap` cannot hold the survivors;
 *         CMT_FAULT on a NULL `out_len`, or a NULL `out` with a non-zero
 *         `cap`.
 */
int cmt_votes_to_proto(const cmt_vote_t *const *votes, size_t n,
                       cmt_pb_vote_t *out, size_t cap, size_t *out_len);

/**
 * cometbft@709fd12b types/vote.go:101-123 — `(vote *Vote) CommitSig()`.
 * A complete BlockID gives a COMMIT entry, a zero one a NIL entry, and a
 * NULL vote an ABSENT entry (:103-105).
 * @return CMT_OK; CMT_REJECT for a half-filled BlockID, where the
 *         reference panics (:113-115); CMT_FAULT on NULL `out`.
 */
int cmt_vote_commit_sig(const cmt_vote_t *vote, cmt_commit_sig_t *out);

/** cometbft@709fd12b types/vote.go:125-138 —
 *  `(vote *Vote) ExtendedCommitSig()`. CommitSig plus the two extension
 *  fields; a NULL vote gives an ABSENT entry (:129-131). */
int cmt_vote_extended_commit_sig(const cmt_vote_t *vote,
                                 cmt_extended_commit_sig_t *out);

/**
 * cometbft@709fd12b types/vote.go:140-156 — `VoteSignBytes()`.
 * CanonicalizeVote, then MarshalDelimited (uvarint length ‖ message).
 * THESE ARE THE BYTES A VALIDATOR SIGNS.
 * @param cap at least CMT_VOTE_SIGN_BYTES_MAX.
 * @return CMT_OK; CMT_REJECT where the reference panics on a marshal
 *         failure (:151-153) or if it does not fit; CMT_FAULT on NULL.
 */
int cmt_vote_sign_bytes(const uint8_t *chain_id, size_t chain_id_len,
                        const cmt_pb_vote_t *vote,
                        uint8_t *out, size_t cap, size_t *out_len);

/**
 * cometbft@709fd12b types/vote.go:158-171 — `VoteExtensionSignBytes()`.
 * The same shape over a CanonicalVoteExtension. The extension is
 * application data of unbounded length, so there is no fixed maximum:
 * `cap` must be at least 64 + 11 + the extension's length. A transient
 * buffer of that size is allocated for the message body, because
 * cmt_pb_marshal_delimited copies and must not be given overlapping
 * ranges.
 * @return CMT_OK, CMT_REJECT, CMT_FAULT on NULL or allocation failure.
 */
int cmt_vote_extension_sign_bytes(const uint8_t *chain_id,
                                  size_t chain_id_len,
                                  const cmt_pb_vote_t *vote,
                                  uint8_t *out, size_t cap, size_t *out_len);

/** cometbft@709fd12b types/vote.go:173-176 — `(vote *Vote) Copy()`.
 *  A struct copy, as the reference's is: the extension DESCRIPTOR is
 *  copied and its bytes are SHARED, exactly as Go's `[]byte` header is
 *  copied and its backing array shared. */
int cmt_vote_copy(const cmt_vote_t *vote, cmt_vote_t *out);

/**
 * cometbft@709fd12b types/vote.go:219-236 — `verifyAndReturnProto()` and
 * `(vote *Vote) Verify()`, which are one function once the returned proto
 * is the vote itself.
 *
 * Two checks in the reference's order: the public key's address equals the
 * vote's ValidatorAddress (:220-222), then the signature verifies over the
 * vote's sign bytes (:224-226).
 * @return CMT_OK; CMT_REJECT for a wrong address
 *         (ErrVoteInvalidValidatorAddress) or a bad signature
 *         (ErrVoteInvalidSignature); CMT_FAULT on NULL, a backend
 *         failure, or a `signature_len` larger than the array it names
 *         (INVARIANT atlas-dec-7495d3372e004b24b4f6cc7bff5caf07 — Go's
 *         Signature is a slice and carries its own bound; here it does
 *         not, so the length is checked before the verifier reads it).
 */
int cmt_vote_verify(const uint8_t *chain_id, size_t chain_id_len,
                    const cmt_vote_t *vote,
                    const uint8_t pubkey[CMT_PB_PUBKEY_LEN]);

/**
 * cometbft@709fd12b types/vote.go:238-259 — `VerifyVoteAndExtension()`.
 * Verify, then — for a NON-NIL PRECOMMIT ONLY (:248) — the extension
 * signature must be present (:249-251) and must verify (:253-256).
 * @param scratch a buffer for the extension sign bytes;
 *        `scratch_cap` must cover 64 + 11 + the extension's length.
 * @return CMT_OK, CMT_REJECT, CMT_FAULT on NULL, a backend failure, or an
 *         `extension_signature_len` larger than the array it names
 *         (same INVARIANT as cmt_vote_verify).
 */
int cmt_vote_verify_vote_and_extension(const uint8_t *chain_id,
                                       size_t chain_id_len,
                                       const cmt_vote_t *vote,
                                       const uint8_t pubkey[CMT_PB_PUBKEY_LEN],
                                       uint8_t *scratch, size_t scratch_cap);

/**
 * cometbft@709fd12b types/vote.go:261-273 — `VerifyExtension()`.
 * The extension signature ALONE. A prevote or a nil precommit is accepted
 * without any check at all (:264-266) — that early return is the
 * reference's, and it means this function proves NOTHING about a nil vote.
 * @return CMT_OK, CMT_REJECT, CMT_FAULT on NULL, a backend failure, or an
 *         `extension_signature_len` larger than the array it names
 *         (same INVARIANT as cmt_vote_verify).
 */
int cmt_vote_verify_extension(const uint8_t *chain_id, size_t chain_id_len,
                              const cmt_vote_t *vote,
                              const uint8_t pubkey[CMT_PB_PUBKEY_LEN],
                              uint8_t *scratch, size_t scratch_cap);

/**
 * cometbft@709fd12b types/vote.go:275-353 — `(vote *Vote) ValidateBasic()`.
 * Eleven checks in the reference's order, ending in the two extension
 * rules: a vote that is not a non-nil precommit may carry NEITHER an
 * extension NOR an extension signature (:323-333), and one that is may
 * carry an extension signature of at most CMT_MAX_SIGNATURE_SIZE and may
 * not carry an extension without one (:335-350).
 * @return CMT_OK, CMT_REJECT, CMT_FAULT on NULL.
 */
int cmt_vote_validate_basic(const cmt_vote_t *vote);

/** cometbft@709fd12b types/vote.go:355-369 — `(vote *Vote) EnsureExtension()`.
 *  A non-nil precommit MUST carry an extension signature; anything else
 *  passes.
 *  @return CMT_OK, CMT_REJECT (ErrVoteExtensionAbsent), CMT_FAULT. */
int cmt_vote_ensure_extension(const cmt_vote_t *vote);

/**
 * cometbft@709fd12b types/priv_validator.go — `PrivValidator.SignVote`, the
 * host call vote.go:418 makes. HOST, not ported.
 *
 * SHAPE. The dispatch for this wave suggested a plain byte-signer
 * `(ctx, sign_bytes, len, sig)`. That shape CANNOT express this call
 * site: `SignAndCheckVote` reads back THREE things the signer writes into
 * the vote — `v.Signature` (:423), `v.ExtensionSignature` (:432, :448)
 * and `v.Timestamp` (:451, the rule the dispatch names as PORT). A byte
 * signer leaves :451 a no-op and gives the extension signature no path at
 * all. This typedef therefore mirrors the reference's interface instead,
 * and the departure is recorded in the wave's report.
 *
 * The host computes the sign bytes itself with cmt_vote_sign_bytes (and
 * cmt_vote_extension_sign_bytes when extensions are enabled), signs them,
 * and writes the results back into `*v`. It MAY replace `v->timestamp`,
 * which is the reference's own behaviour and the ONLY clock read in a
 * vote's life (clock POLICY atlas-dec-4ac0423068085c100fdfa3e264ca16bc).
 *
 * @return CMT_OK on success; any other value is passed through as the
 *         reference passes its error through.
 */
typedef int (*cmt_sign_vote_fn)(void *ctx, const uint8_t *chain_id,
                                size_t chain_id_len, cmt_pb_vote_t *v);

/**
 * cometbft@709fd12b types/vote.go:408-454 — `SignAndCheckVote()`.
 *
 * Signs `vote` through the host callback and then checks that what came
 * back makes sense. The reference's two-value return is split: `*out`
 * carries its bool ("is this error recoverable"), and the return code
 * carries its error.
 *
 * @param recoverable receives the reference's first return value: true for
 *        a signer failure (:419-422 — "failing to sign a vote has always
 *        been a recoverable error"), false for every malformed-vote case
 *        (:428, :437, :445), and TRUE on success (:453 `return true, nil`)
 *        — the reference's literal value, meaningless without an error.
 * @return CMT_OK, CMT_REJECT (see `*recoverable`), CMT_FAULT on NULL, or
 *         whatever the signer returned when the signer failed.
 */
int cmt_sign_and_check_vote(cmt_vote_t *vote, cmt_sign_vote_fn sign,
                            void *ctx,
                            const uint8_t *chain_id, size_t chain_id_len,
                            bool extensions_enabled, bool *recoverable);

#ifdef __cplusplus
}
#endif

#endif /* SHARED_DNAC_CMT_VOTE_H */
