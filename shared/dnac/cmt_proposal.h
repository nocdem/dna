/**
 * @file shared/dnac/cmt_proposal.h
 * @brief cometbft @709fd12b `types/proposal.go` ported to C.
 *
 * ═══ ACTIVATION: INACTIVE ═══════════════════════════════════════════════
 * Wave R1-B of the cometbft → C consensus port. Additive only; nothing in
 * the running chain calls anything here.
 * ════════════════════════════════════════════════════════════════════════
 *
 * A Proposal names a block by its BlockID and, when POLRound >= 0, says
 * which earlier round locked it. It is signed separately from any vote,
 * over a CanonicalProposal (cmt_canonical), and its own bytes never carry
 * the block — under the un-parked chunking decision
 * (atlas-dec-6d35670369b69df4439cb720036fa2d7 rev 2) the block travels as
 * a PartSet.
 *
 * ── Domain ↔ wire ──────────────────────────────────────────────────────
 * `types.Proposal` (proposal.go:25-33) is FIELD-IDENTICAL to R1-A's
 * `cmt_pb_proposal_t` — seven fields, same order, same types, including
 * POLRound as an int32 — so the domain type is a typedef of the wire type
 * and `_to_proto` is the identity. `ProposalFromProto` is the identity
 * plus BlockIDFromProto and ValidateBasic (:160).
 *
 * ⚠ POLRound is int32 HERE and int64 in CanonicalProposal
 * (canonical.proto field 4); cmt_canonical widens it. The two encodings
 * differ, and only the canonical one is signed.
 *
 * ── Substitutions, and nothing else ────────────────────────────────────
 * 1. `MaxSignatureSize` 64 → 4627 at proposal.go:76-78.
 * 2. THE CLOCK. `NewProposal` (:44) calls `cmttime.Now()` — the second and
 *    last clock read in the reference's proposal/vote path. Under the
 *    APPROVED clock POLICY (atlas-dec-4ac0423068085c100fdfa3e264ca16bc)
 *    every clock read in a ported body goes through the host's single
 *    `now()` callback, so here the current time is a PARAMETER the host
 *    has already obtained. NOTHING IN THIS FILE READS A CLOCK.
 * 3. panic → error return (:113-115); caller-provided sign-bytes buffer.
 *
 * ── Determinism ────────────────────────────────────────────────────────
 * Every function here is a pure function of its arguments, the timestamp
 * included, because it arrives as a value.
 *
 * ── taşınmadı (not ported), with the reason ────────────────────────────
 *   · `(p *Proposal) String` (:92-100) — display only.
 *   · `ErrInvalidBlockPartSignature` / `ErrInvalidBlockPartHash` (:14-17)
 *     — two package-level error values with no consumer in this file; the
 *     port has no error objects.
 *
 * Reference @709fd12b: types/proposal.go, 161 lines,
 * 0b56660bee6071267b75c9dabe148036cb96c814f640f4e4323baa59af44eba0.
 * Governing records: umbrella rev 3 (atlas-dec-d5e766defde138eb6dd02e5b81e735a8),
 * D-19 rev 6 (atlas-dec-d106407a31d7d16d49d51990b75c36c6),
 * K-1 rev 2 (atlas-dec-3ba8153088b0d60c63083028023b61be),
 * chunking rev 2 (atlas-dec-6d35670369b69df4439cb720036fa2d7),
 * clock POLICY (atlas-dec-4ac0423068085c100fdfa3e264ca16bc).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef SHARED_DNAC_CMT_PROPOSAL_H
#define SHARED_DNAC_CMT_PROPOSAL_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "cmt_pb.h"
#include "cmt_time.h"
#include "cmt_block.h"
#include "cmt_canonical.h"

#ifdef __cplusplus
extern "C" {
#endif

/** cometbft@709fd12b types/proposal.go:25-33 — `type Proposal struct`.
 *  Field-identical to cmt_pb_proposal_t; see the header. */
typedef cmt_pb_proposal_t cmt_proposal_t;

/**
 * The buffer a proposal's sign bytes always fit in. Derived from the
 * widest CanonicalProposal plus its MarshalDelimited prefix:
 *   type 1+10, height 1+8 (sfixed64), round 1+8, pol_round 1+10 (int64),
 *   block_id 1+2+140, timestamp 1+1+17, chain_id 1+1+32 = 236;
 *   prefix uvarint(236) = 2. 256 rounds that up.
 */
#define CMT_PROPOSAL_SIGN_BYTES_MAX 256

/**
 * cometbft@709fd12b types/proposal.go:35-46 — `NewProposal()`.
 *
 * `pol_round` is -1 when there is no proof-of-lock round (:36).
 * The Type is forced to PROPOSAL (:39) and the Signature is left empty —
 * a fresh proposal is unsigned, which is why ValidateBasic would refuse it
 * until a signer has run.
 *
 * @param now the current time, ALREADY OBTAINED BY THE HOST from its one
 *        clock callback. The reference calls `cmttime.Now()` at :44; this
 *        port reads no clock (clock POLICY
 *        atlas-dec-4ac0423068085c100fdfa3e264ca16bc).
 * @return CMT_OK, CMT_FAULT on NULL.
 */
int cmt_new_proposal(int64_t height, int32_t round, int32_t pol_round,
                     const cmt_block_id_t *block_id, cmt_time_t now,
                     cmt_proposal_t *out);

/**
 * cometbft@709fd12b types/proposal.go:48-80 — `(p *Proposal) ValidateBasic()`.
 * Seven checks in the reference's order. Note :66-68: the BlockID must be
 * COMPLETE, not merely valid — a proposal for nothing is not a proposal.
 * The timestamp is deliberately not checked (:70).
 * @return CMT_OK, CMT_REJECT, CMT_FAULT on NULL.
 */
int cmt_proposal_validate_basic(const cmt_proposal_t *p);

/**
 * cometbft@709fd12b types/proposal.go:102-118 — `ProposalSignBytes()`.
 * CanonicalizeProposal, then MarshalDelimited. THESE ARE THE BYTES A
 * PROPOSER SIGNS.
 *
 * There is no `Proposal.Verify` in the reference: a proposal's signature
 * is checked at its call site (consensus/state.go's proposal handling)
 * against the proposer's key, so none is invented here.
 *
 * @param cap at least CMT_PROPOSAL_SIGN_BYTES_MAX.
 * @return CMT_OK; CMT_REJECT where the reference panics on a marshal
 *         failure (:113-115) or if it does not fit; CMT_FAULT on NULL.
 */
int cmt_proposal_sign_bytes(const uint8_t *chain_id, size_t chain_id_len,
                            const cmt_pb_proposal_t *p,
                            uint8_t *out, size_t cap, size_t *out_len);

/** cometbft@709fd12b types/proposal.go:120-136 — `(p *Proposal) ToProto()`.
 *  The identity; a NULL receiver yields the EMPTY proposal (:122-124) —
 *  note that is an empty message, not the nil that Vote.ToProto returns. */
int cmt_proposal_to_proto(const cmt_proposal_t *p, cmt_pb_proposal_t *out);

/** cometbft@709fd12b types/proposal.go:138-161 — `ProposalFromProto()`.
 *  BlockIDFromProto (:147) and then ValidateBasic (:160). */
int cmt_proposal_from_proto(const cmt_pb_proposal_t *pp,
                            cmt_proposal_t *out);

#ifdef __cplusplus
}
#endif

#endif /* SHARED_DNAC_CMT_PROPOSAL_H */
