/**
 * @file shared/dnac/cmt_canonical.h
 * @brief cometbft @709fd12b `types/canonical.go` ported to C — the shapes
 *        that get SIGNED.
 *
 * ═══ ACTIVATION: INACTIVE ═══════════════════════════════════════════════
 * Wave R1-B of the cometbft → C consensus port. Additive only; nothing in
 * the running chain calls anything here.
 * ════════════════════════════════════════════════════════════════════════
 *
 * A validator never signs a Vote or a Proposal. It signs the CANONICAL
 * form: the same facts with the fields that differ between validators
 * removed (ValidatorAddress and ValidatorIndex are NOT in a CanonicalVote,
 * canonical.go:54-56), with the chain id added so a signature cannot be
 * replayed on another chain, and with height and round re-typed as
 * SFIXED64 so their encoding has a fixed width. These five functions
 * therefore decide what a signature covers. D-19 rev 6 item 10, APPROVED
 * (atlas-dec-d106407a31d7d16d49d51990b75c36c6), makes them normative.
 *
 * The canonical structs themselves are R1-A's `cmt_pb_canonical_*_t`; this
 * module only fills them, exactly as the reference's functions do, and the
 * bytes come from cmt_pb's marshal (K-1 rev 2 rule e).
 *
 * ── Substitutions ──────────────────────────────────────────────────────
 * Only the sizes (32-byte chain id, 64-byte hashes) and panic → error
 * return. `CanonicalizeBlockID` PANICS in the reference when
 * `BlockIDFromProto` fails (:20-22); here that is CMT_REJECT.
 *
 * ── Determinism ────────────────────────────────────────────────────────
 * Pure functions of their arguments. No clock (the timestamp arrives as a
 * value from the vote or the proposal), no randomness, no map.
 *
 * ── taşınmadı (not ported), with the reason ────────────────────────────
 *   · `CanonicalTime` (:81-86) — it renders a time as an RFC3339Nano
 *     STRING and its only callers are the String methods of Vote,
 *     Proposal and CommitSig. Display only; the map's REV 3 table
 *     re-labels it YOK for that reason.
 *   · `TimeFormat` (:13) — the format string CanonicalTime uses.
 *
 * Reference @709fd12b: types/canonical.go, 86 lines,
 * 868e059415a616344f955c4539f9e0e30f38d24341e531563b8e38283f1edc33.
 * Governing records: umbrella rev 3 (atlas-dec-d5e766defde138eb6dd02e5b81e735a8),
 * K-1 rev 2 (atlas-dec-3ba8153088b0d60c63083028023b61be),
 * D-19 rev 6 (atlas-dec-d106407a31d7d16d49d51990b75c36c6).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef SHARED_DNAC_CMT_CANONICAL_H
#define SHARED_DNAC_CMT_CANONICAL_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "cmt_pb.h"
#include "cmt_block.h"   /* cmt_block_id_from_proto, cmt_block_id_is_zero */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * cometbft@709fd12b types/canonical.go:18-34 — `CanonicalizeBlockID()`.
 *
 * The reference returns a POINTER, and returns nil for a zero BlockID
 * (:24-25); that nil is why a nil vote's sign bytes carry NO block id
 * field at all (K-1 rev 2 rule e). Here `*has` is that pointer's
 * presence: false means the enclosing CanonicalVote / CanonicalProposal
 * must leave `has_block_id` false.
 *
 * NOTE reference detail (:28): the hash copied into the result comes from
 * the ARGUMENT `bid`, not from the `rbid` that BlockIDFromProto produced.
 * The two are equal, because BlockIDFromProto copies the hash through;
 * the argument is used here for the same reason.
 *
 * @return CMT_OK; CMT_REJECT where the reference panics because
 *         BlockIDFromProto failed (:20-22); CMT_FAULT on NULL.
 */
int cmt_canonicalize_block_id(const cmt_pb_block_id_t *bid, bool *has,
                              cmt_pb_canonical_block_id_t *out);

/** cometbft@709fd12b types/canonical.go:37-39 —
 *  `CanonicalizePartSetHeader()`. A Go type conversion between two
 *  identically shaped messages, i.e. the identity here.
 *  @return CMT_OK, CMT_FAULT on NULL. */
int cmt_canonicalize_part_set_header(const cmt_pb_part_set_header_t *psh,
                                     cmt_pb_canonical_part_set_header_t *out);

/**
 * cometbft@709fd12b types/canonical.go:42-52 — `CanonicalizeProposal()`.
 * Type is forced to PROPOSAL (:44); Height and Round are re-typed to
 * sfixed64 (:45-46) and POLRound widens from int32 to INT64 (:47), which
 * is why CanonicalProposal's field 4 is an int64 varint while Proposal's
 * is an int32 one.
 * @return CMT_OK, CMT_REJECT, CMT_FAULT on NULL or an over-long chain id.
 */
int cmt_canonicalize_proposal(const uint8_t *chain_id, size_t chain_id_len,
                              const cmt_pb_proposal_t *p,
                              cmt_pb_canonical_proposal_t *out);

/**
 * cometbft@709fd12b types/canonical.go:57-66 — `CanonicalizeVote()`.
 * Keeps the vote's OWN type (:59 — unlike the proposal's, which is
 * forced), drops ValidatorAddress, ValidatorIndex and everything about
 * extensions (:54-56), and adds the chain id.
 * @return CMT_OK, CMT_REJECT, CMT_FAULT on NULL or an over-long chain id.
 */
int cmt_canonicalize_vote(const uint8_t *chain_id, size_t chain_id_len,
                          const cmt_pb_vote_t *vote,
                          cmt_pb_canonical_vote_t *out);

/**
 * cometbft@709fd12b types/canonical.go:71-78 —
 * `CanonicalizeVoteExtension()`. Four fields and NO timestamp and NO type:
 * an extension signature covers the extension, the height, the round and
 * the chain id, and nothing else.
 *
 * The extension bytes are NOT copied: `out->extension` points at the
 * vote's, exactly as the reference's slice does (:73).
 * @return CMT_OK, CMT_REJECT, CMT_FAULT on NULL or an over-long chain id.
 */
int cmt_canonicalize_vote_extension(const uint8_t *chain_id,
                                    size_t chain_id_len,
                                    const cmt_pb_vote_t *vote,
                                    cmt_pb_canonical_vote_extension_t *out);

#ifdef __cplusplus
}
#endif

#endif /* SHARED_DNAC_CMT_CANONICAL_H */
