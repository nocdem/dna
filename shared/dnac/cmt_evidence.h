/**
 * @file shared/dnac/cmt_evidence.h
 * @brief cometbft @709fd12b `types/evidence.go` ported to C — the
 *        duplicate-vote evidence domain and the evidence list.
 *
 * ═══ ACTIVATION: INACTIVE ═══════════════════════════════════════════════
 * Wave R1-D of the cometbft → C consensus port. No consensus path calls
 * anything here yet; the module is additive only. The live witness BFT,
 * QC V2 and the T3 wave-1 modules are byte-identically untouched.
 * ════════════════════════════════════════════════════════════════════════
 *
 * ── ONE BRANCH, AND THE REASON ─────────────────────────────────────────
 * The reference's `Evidence` is an interface with two implementations. Only
 * `DuplicateVoteEvidence` (evidence.go:35-43) is in scope.
 * `LightClientAttackEvidence` (:204-442) is YOK by the port map's scope
 * rule (REV 3, "Kapsam kuralı"): its callers are `light/`, the evidence
 * pool and `blocksync/`, three packages this port does not build. R1-A's
 * wire wrapper already refuses branch 2 rather than skipping it
 * (cmt_pb.h:379-397), for the reason stated there — silently dropping a
 * branch would let two nodes that disagree about scope hash one list
 * differently.
 *
 * Because there is one branch, the Go interface disappears: what the
 * reference does through dynamic dispatch, this module does directly on
 * `cmt_duplicate_vote_evidence_t`. That is a REPRESENTATION change, not a
 * behavioural one — every function below performs the same steps on the
 * same bytes as the reference's method for that branch.
 *
 * ── TWO DIFFERENT BYTE STRINGS. DO NOT CONFUSE THEM ────────────────────
 * `DuplicateVoteEvidence.Bytes()` (evidence.go:95-103) marshals the BARE
 * `DuplicateVoteEvidence` message. The `Evidence` ONEOF WRAPPER
 * (`cmt_pb_evidence_t`) is what travels inside a block's EvidenceList. The
 * hash of a piece of evidence, and every leaf of `EvidenceList.Hash`, is
 * over the BARE message — never over the wrapper. cmt_pb.h:389-392 warns
 * about the same confusion.
 *
 * ── Domain ↔ wire ──────────────────────────────────────────────────────
 * `DuplicateVoteEvidence` (:35-43) is FIELD-IDENTICAL to R1-A's
 * `cmt_pb_duplicate_vote_evidence_t` — VoteA, VoteB, TotalVotingPower,
 * ValidatorPower, Timestamp, in that order — so the domain type is a
 * typedef of the wire type and `ToProto` is the identity, exactly as wave
 * R1-B did for `cmt_vote_t` and R1-A for `cmt_proof_t`. Go's two `*Vote`
 * pointers are the wire struct's `has_vote_a` / `has_vote_b` flags: a
 * false flag IS the reference's nil, and `ValidateBasic` refuses it
 * (:131-133) just as the reference does.
 *
 * ── Substitutions, and nothing else ────────────────────────────────────
 *  · hash SHA3-512 / 64 bytes (cmt_tmhash.h) at :107 — a FLAT hash of the
 *    bare marshal, NOT a Merkle root. `EvidenceList.Hash` (:450-461) is
 *    the Merkle root; the two are different functions and this module has
 *    both.
 *  · a Go panic becomes CMT_REJECT; a NULL pointer where the reference
 *    would nil-dereference becomes CMT_FAULT (deviation register R1B-10).
 *  · transient heap for the marshal buffers, freed on every path, failure
 *    reported as CMT_FAULT (deviation register R1B-11, operator-accepted
 *    2026-09-10). The evidence body is not bounded by a constant, because a
 *    vote extension is application data of unbounded length; the bound is
 *    computed per item by `cmt_dve_upper_bound` below.
 *
 * ── Determinism ────────────────────────────────────────────────────────
 * Every function here is a pure function of its arguments. No clock is
 * read, no randomness is drawn, no map is iterated, no floating point is
 * used. `cmt_evidence_list_hash` hashes the items in the order the caller
 * supplied — which for a block is the order they sit in the block — and
 * that is the reference's behaviour at :454-459. Two nodes holding the
 * same list produce the same root, byte for byte.
 *
 * ── taşınmadı (not ported), with the reason ────────────────────────────
 *   · :50-78  `NewDuplicateVoteEvidence` — YOK by the port map's REV 3.1
 *     override (map ~950): its callers are the evidence POOL, which is out
 *     of scope. It is the constructor that ORDERS a conflicting pair and
 *     reads TotalVotingPower from a validator set; if a later wave brings
 *     the evidence pool into scope, this is the row to port then.
 *   · :81-92  `DuplicateVoteEvidence.ABCI`, :483-489 `EvidenceList.ToABCI`
 *     — the ABCI application layer, which this chain does not have.
 *   · :116-118 `String`, :463-469 `EvidenceList.String` — display only.
 *   · :204-442 the whole `LightClientAttackEvidence` family, and the
 *     `:535-536` branch of `EvidenceFromProto` that decodes it — scope
 *     rule (light client); see "ONE BRANCH" above.
 *   · :542-545 `init` — registers the two types with cmtjson; this port has
 *     no JSON layer.
 *   · :550-563 `ErrInvalidEvidence` / `NewErrInvalidEvidence` — YOK by the
 *     REV 3.1 override (map ~950), same evidence-pool reason. It is a
 *     wrapper carrying an Evidence and a cause, and nothing in scope
 *     constructs one.
 *   · :586-637 `NewMockDuplicateVoteEvidence*`, `makeMockVote`,
 *     `randBlockID` — test helpers; `randBlockID` additionally draws
 *     randomness, which no ported body may do.
 *
 * Reference @709fd12b (SHA-256 verified before use):
 *   types/evidence.go 637 lines
 *     5a41f27f0de4a63412f7e8a64f288b81d8fa52502102ad5b111214211c091fde
 * Governing records: umbrella rev 3 (atlas-dec-d5e766defde138eb6dd02e5b81e735a8),
 * K-1 rev 2 (atlas-dec-3ba8153088b0d60c63083028023b61be),
 * K-2 (atlas-dec-7fde65722d68b32eca08be61fbcb47ac),
 * INVARIANT (atlas-dec-7495d3372e004b24b4f6cc7bff5caf07),
 * D-19 rev 6 item 8 (atlas-dec-d106407a31d7d16d49d51990b75c36c6),
 * pin rev 4 (atlas-dec-483ec17cbb352ef0ec2267ccd953339c).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef SHARED_DNAC_CMT_EVIDENCE_H
#define SHARED_DNAC_CMT_EVIDENCE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "cmt_tmhash.h"
#include "cmt_time.h"
#include "cmt_pb.h"
#include "cmt_block.h"   /* cmt_block_id_t, cmt_block_id_key             */
#include "cmt_vote.h"    /* cmt_vote_t, validate_basic, from_proto       */

#ifdef __cplusplus
extern "C" {
#endif

/** cometbft@709fd12b types/evidence.go:35-43 —
 *  `type DuplicateVoteEvidence struct`. Field-identical to
 *  cmt_pb_duplicate_vote_evidence_t; see the header. */
typedef cmt_pb_duplicate_vote_evidence_t cmt_duplicate_vote_evidence_t;

/**
 * The widest marshal a given `DuplicateVoteEvidence` can produce, so a
 * caller can size the buffer `cmt_dve_bytes` needs.
 *
 * It is a FUNCTION and not a constant because a vote may carry an
 * extension, which is application data of unbounded length
 * (CMT_MAX_VOTE_EXTENSION_SIZE bounds it at a megabyte, but a bound of two
 * megabytes per item is not a buffer anyone wants by default). The value
 * is an upper bound, not the exact length.
 *
 * @return 0 if `d` is NULL, otherwise the bound in bytes.
 */
size_t cmt_dve_upper_bound(const cmt_duplicate_vote_evidence_t *d);

/**
 * cometbft@709fd12b types/evidence.go:95-103 —
 * `(dve *DuplicateVoteEvidence) Bytes()`.
 *
 * `ToProto()` followed by `Marshal()` — of the BARE message, not of the
 * Evidence wrapper (see the header). The reference panics on a marshal
 * failure (:98-100); that is CMT_REJECT here.
 *
 * @param cap should be at least `cmt_dve_upper_bound(dve)`.
 * @return CMT_OK, CMT_REJECT (it does not fit, or a field will not
 *         encode), CMT_FAULT on NULL.
 */
int cmt_dve_bytes(const cmt_duplicate_vote_evidence_t *dve,
                  uint8_t *out, size_t cap, size_t *out_len);

/**
 * cometbft@709fd12b types/evidence.go:106-108 —
 * `(dve *DuplicateVoteEvidence) Hash()`.
 *
 * ⚠ `tmhash.Sum(dve.Bytes())` — a FLAT hash of the bare marshal. This is
 * NOT a Merkle root, and it is not what goes into the header: the header's
 * EvidenceHash is `cmt_evidence_list_hash` below, the Merkle root over
 * these same bare marshals as leaves. `Has` (:472-479) is what compares
 * these flat hashes.
 *
 * Allocates one transient buffer of `cmt_dve_upper_bound(dve)` bytes and
 * frees it on every path (R1B-11).
 * @return CMT_OK, CMT_REJECT, CMT_FAULT on NULL, allocation or hash
 *         backend failure.
 */
int cmt_dve_hash(const cmt_duplicate_vote_evidence_t *dve,
                 uint8_t out[CMT_TMHASH_SIZE]);

/**
 * cometbft@709fd12b types/evidence.go:111-113 —
 * `(dve *DuplicateVoteEvidence) Height()`. `dve.VoteA.Height`.
 * @return CMT_OK; CMT_FAULT on NULL, or when VoteA is absent — the
 *         reference would nil-dereference there and this port refuses to
 *         (deviation register R1B-10). A caller that has run
 *         `cmt_dve_validate_basic` cannot reach it.
 */
int cmt_dve_height(const cmt_duplicate_vote_evidence_t *dve, int64_t *out);

/** cometbft@709fd12b types/evidence.go:121-123 —
 *  `(dve *DuplicateVoteEvidence) Time()`. The evidence's own Timestamp,
 *  NOT either vote's. @return CMT_OK, CMT_FAULT on NULL. */
int cmt_dve_time(const cmt_duplicate_vote_evidence_t *dve, cmt_time_t *out);

/**
 * cometbft@709fd12b types/evidence.go:126-145 —
 * `(dve *DuplicateVoteEvidence) ValidateBasic()`.
 *
 * Four checks in the reference's order: both votes present (:131-133),
 * VoteA well-formed (:134-136), VoteB well-formed (:137-139), and the pair
 * strictly ORDERED — `strings.Compare(VoteA.BlockID.Key(),
 * VoteB.BlockID.Key()) >= 0` refuses (:140-143).
 *
 * That last check is the one worth stating plainly, because it is what
 * makes the evidence canonical: a conflicting pair has exactly ONE valid
 * presentation, the one whose VoteA has the lexicographically smaller
 * BlockID key. `>= 0` refuses both the wrong order AND two votes for the
 * SAME BlockID — which is not a conflict at all. `Key()` is
 * `cmt_block_id_key` (cmt_block.h:300), the hash bytes followed by the
 * marshalled PartSetHeader; Go's `strings.Compare` on those bytes is a
 * bytewise comparison in which a prefix sorts first, reproduced here as a
 * memcmp over the shorter length followed by a length comparison — the
 * same construction `cmt_validator_compare_proposer_priority` uses for
 * `bytes.Compare`.
 *
 * @return CMT_OK, CMT_REJECT, CMT_FAULT on NULL (the reference returns an
 *         error for a nil receiver at :127-129; in C a NULL pointer is a
 *         programming error and never a wire value — R1B-10).
 */
int cmt_dve_validate_basic(const cmt_duplicate_vote_evidence_t *dve);

/** cometbft@709fd12b types/evidence.go:148-159 —
 *  `(dve *DuplicateVoteEvidence) ToProto()`. The identity; see the header.
 *  @return CMT_OK, CMT_FAULT on NULL. */
int cmt_dve_to_proto(const cmt_duplicate_vote_evidence_t *dve,
                     cmt_pb_duplicate_vote_evidence_t *out);

/**
 * cometbft@709fd12b types/evidence.go:162-200 —
 * `DuplicateVoteEvidenceFromProto()`.
 *
 * Each PRESENT vote goes through `VoteFromProto` (:170, :182) — which
 * validates the BlockID even though its doc comment says it validates
 * nothing (the asymmetry cmt_vote.h records) — and then through
 * `Vote.ValidateBasic` (:174, :186). An ABSENT vote is left absent and is
 * NOT an error here; the whole is then `ValidateBasic`'d at :199, and that
 * is where a missing vote is refused. Ported in that order, so the error a
 * caller sees is the reference's.
 *
 * @return CMT_OK, CMT_REJECT, CMT_FAULT on NULL (:163-165 is an error in
 *         the reference; R1B-10).
 */
int cmt_dve_from_proto(const cmt_pb_duplicate_vote_evidence_t *pb,
                       cmt_duplicate_vote_evidence_t *out);

/* ── the Evidence wrapper (evidence.go:495-540) ─────────────────────── */

/**
 * cometbft@709fd12b types/evidence.go:495-523 — `EvidenceToProto()`,
 * restricted to its DuplicateVoteEvidence branch (:501-507).
 * The `LightClientAttackEvidence` branch (:509-518) and the `default`
 * "not recognized" arm (:520-521) are unreachable in C: the parameter has
 * one type. @return CMT_OK, CMT_FAULT on NULL.
 */
int cmt_evidence_to_proto(const cmt_duplicate_vote_evidence_t *dve,
                          cmt_pb_evidence_t *out);

/**
 * cometbft@709fd12b types/evidence.go:527-540 — `EvidenceFromProto()`,
 * DuplicateVoteEvidence branch only (:533-534).
 *
 * The reference switches on which oneof arm is set; here an item whose
 * `has_duplicate_vote_evidence` is false IS the reference's "evidence is
 * not recognized" (:537-538) — either no arm was set or the decoder met
 * branch 2, which cmt_pb refuses outright.
 *
 * @return CMT_OK; CMT_REJECT for an unrecognised branch or an item that
 *         fails `cmt_dve_from_proto`; CMT_FAULT on NULL (:528-530 is an
 *         error in the reference; R1B-10).
 */
int cmt_evidence_from_proto(const cmt_pb_evidence_t *ev,
                            cmt_duplicate_vote_evidence_t *out);

/* ── EvidenceList (evidence.go:446-479) ─────────────────────────────── */

/**
 * cometbft@709fd12b types/evidence.go:450-461 — `(evl EvidenceList) Hash()`.
 *
 * THE HEADER'S EvidenceHash (D-19 rev 6 item 8; block.go:1383 →
 * evidence.go:460). The Merkle root over each item's `Bytes()` — the BARE
 * DuplicateVoteEvidence marshal — in the order given. An EMPTY list is the
 * empty tree's root H(""), not a run of zero bytes.
 *
 * `cmt_evidence_data_hash` (cmt_block.h:710), which is
 * `EvidenceData.Hash` (block.go:1380-1386), DELEGATES to this function:
 * the reference's `EvidenceData.Hash` body is one call to
 * `EvidenceList.Hash`, and this file is that row's home. One
 * implementation, one set of bytes.
 *
 * The reference's own TODO at :456-457 ("we should change this to the
 * hash") is NOT acted on — the leaf is the marshal, as the pinned code
 * has it.
 *
 * @param items may be NULL only when `n` is 0.
 * @return CMT_OK; CMT_REJECT if an item is not a DuplicateVoteEvidence or
 *         will not marshal; CMT_FAULT on NULL `out`, allocation failure or
 *         a hash backend failure.
 */
int cmt_evidence_list_hash(const cmt_pb_evidence_t *items, size_t n,
                           uint8_t out[CMT_TMHASH_SIZE]);

/**
 * cometbft@709fd12b types/evidence.go:472-479 — `(evl EvidenceList) Has()`.
 * Compares `Hash()` — the FLAT per-item hash of :106-108 — of the needle
 * against each item's. It is a linear scan, as the reference's is.
 * @param out receives the answer; the return code reports only whether the
 *        question could be ANSWERED.
 * @return CMT_OK, CMT_REJECT (an item will not hash), CMT_FAULT.
 */
int cmt_evidence_list_has(const cmt_pb_evidence_t *items, size_t n,
                          const cmt_pb_evidence_t *ev, bool *out);

/* ── errors the reference carries as values ─────────────────────────── */

#define CMT_EV_ERR_NONE      0
/** cometbft@709fd12b types/evidence.go:566-569 — `ErrEvidenceOverflow`. */
#define CMT_EV_ERR_OVERFLOW  1

/**
 * The reference's `ErrEvidenceOverflow` value (:566-574). The 0/-1/-2
 * return contract cannot carry a payload, so the two numbers the error
 * carries live here — the same shape `cmt_vs_error_t`
 * (cmt_validator_set.h:289-293) uses for `ErrNotEnoughVotingPowerSigned`,
 * so the port has one way of doing this and not two.
 *
 * ZERO CONSUMERS in this wave: the reference's only producer is the
 * evidence pool's `MaxBytes` check, which is out of scope. Ported because
 * the port map marks :572 PORT and because the VALUE — max and got — is
 * what a caller would need.
 */
typedef struct {
    int     code;   /* CMT_EV_ERR_*        */
    int64_t max;    /* evidence.go:567     */
    int64_t got;    /* evidence.go:568     */
} cmt_ev_error_t;

/** cometbft@709fd12b types/evidence.go:572-574 —
 *  `NewErrEvidenceOverflow(max, got)`. A plain constructor, as the
 *  reference's is; it does not check that `got > max`.
 *  @return CMT_OK, CMT_FAULT on NULL. */
int cmt_new_err_evidence_overflow(int64_t max, int64_t got,
                                  cmt_ev_error_t *out);

#ifdef __cplusplus
}
#endif

#endif /* SHARED_DNAC_CMT_EVIDENCE_H */
