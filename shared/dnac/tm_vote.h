/**
 * @file shared/dnac/tm_vote.h
 * @brief Tendermint T3 — vote signing preimage `nodus.vote.v1` (INACTIVE).
 *
 * The exact bytes a validator signs when it votes. Built here and nowhere
 * else, so the signer, the certificate verifier and the reactor decoder
 * cannot drift apart: a certificate entry (shared/dnac/tm_commit.h) is a
 * PRECOMMIT vote, and it is verified against the preimage this file builds.
 *
 * ═══ ACTIVATION: INACTIVE ═══════════════════════════════════════════════
 * No consensus path calls anything in this file. It is wave 1 of the T3
 * host integration: additive only. The live witness BFT path is untouched.
 * ════════════════════════════════════════════════════════════════════════
 *
 * ── TAG ────────────────────────────────────────────────────────────────
 *   "nodus.vote.v1"  (16 bytes, zero-padded)
 *
 * ── Signed preimage (EXACTLY 229 bytes; T2 wire design §4.1) ───────────
 *     off   0  16  tag         "nodus.vote.v1" + 3 x 0x00
 *     off  16   1  type        0x01 PREVOTE | 0x02 PRECOMMIT
 *     off  17  64  block_id    BlockID v4; nil vote = 64 x 0x00
 *     off  81  32  voter_id
 *     off 113   8  height      u64 BE
 *     off 121   4  round       u32 BE
 *     off 125   8  timestamp   u64 BE, ms since the Unix epoch, UTC
 *     off 133  32  chain_id    the V2 DERIVED chain id (T2 §4.11); the
 *                              legacy half-zero id is never valid here
 *     off 165  64  vset_hash   dna_vset_hash of the snapshot governing the
 *                              message's OWN height
 *     total 229
 *
 * Signature: ML-DSA-87 (Dilithium5), 4627 bytes.
 *
 * ── Why each extra field is bound ──────────────────────────────────────
 * voter_id makes a vote non-transferable between signers; vset_hash makes
 * it non-transferable between validator sets, so a signature gathered under
 * one set can never be replayed to satisfy a quorum under another; chain_id
 * makes it non-transferable between chains. The same reasoning as the
 * 216-byte QC V2 preimage (qc_v2.h:30-33).
 *
 * ── The timestamp (BFT-time) ───────────────────────────────────────────
 * The timestamp is the VOTE's own stamp, not the block's. It is the only
 * place in this design where a clock is read at all, and it is read by the
 * voter for its OWN vote only (dna_tm_vote_time). A RECEIVER NEVER
 * VALIDATES IT: the reference states the check "is handled elsewhere"
 * (types/vote.go:291), and that elsewhere is the deterministic median over
 * the committed certificate (tm_commit.h, dna_tm_commit_median_time), which
 * consumes signed data and no clock at all.
 *
 * Reference: CanonicalVote {Type, Height, Round, BlockID, Timestamp,
 * ChainID} — spec/core/data_structures.md:282; spec/consensus/signing.md:21-25;
 * spec/consensus/bft-time.md "Vote Time"; consensus/state.go:2416-2435 —
 * all at the pinned cometbft commit 709fd12b. Governing records: D-12
 * (atlas-dec-ae3830947ee947d1d9bea33ad259d70b), D-20
 * (atlas-dec-fb3ed0315ffbfd0459efa779a2e00c19).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef SHARED_DNAC_TM_VOTE_H
#define SHARED_DNAC_TM_VOTE_H

#include <stdint.h>

#include "ledger_ids.h"    /* DNA_CHAIN_ID_LEN                            */
#include "vset_wire.h"     /* DNA_VSET_HASH_LEN                           */

#ifdef __cplusplus
extern "C" {
#endif

/* ── Tag ────────────────────────────────────────────────────────────── */
#define DNA_TM_VOTE_TAG            "nodus.vote.v1"        /* 13 ASCII + 3 × 0x00 = 16 */
#define DNA_TM_VOTE_TAG_LEN        16

/** The signed preimage is a fixed 229 bytes. */
#define DNA_TM_VOTE_PREIMAGE_LEN   229

/* ── Vote type byte (D-12) ──────────────────────────────────────────────
 * These are the REFERENCE's SignedMsgType values (spec/consensus/signing.md
 * :21-25 @709fd12b: PrevoteType 0x01, PrecommitType 0x02, ProposalType 0x20).
 *
 * THEY ARE NOT THE T1 CORE ENUM'S VALUES. The core is
 * dna_cmsg_type_t { DNA_CMSG_PROPOSAL = 1, DNA_CMSG_PREVOTE = 2,
 * DNA_CMSG_PRECOMMIT = 3 } (nodus/src/bft/dna_consensus.h:27), which lives
 * under nodus and is deliberately NOT included from shared. D-12 requires
 * the host adapter to map enum ↔ wire byte in EXACTLY ONE table and to
 * reject every other byte at decode time; this header is the wire side of
 * that table. 0x20 (ProposalType) is reserved and MUST NOT appear in a
 * nodus.vote.v1 preimage — a PROPOSAL carries no inner vote signature. */
#define DNA_TM_VOTE_PREVOTE        0x01
#define DNA_TM_VOTE_PRECOMMIT      0x02

/* ── Field offsets (T2 §4.1) ────────────────────────────────────────── */
#define DNA_TM_VOTE_OFF_TYPE       16
#define DNA_TM_VOTE_OFF_BLOCK_ID   17
#define DNA_TM_VOTE_OFF_VOTER_ID   81
#define DNA_TM_VOTE_OFF_HEIGHT     113
#define DNA_TM_VOTE_OFF_ROUND      121
#define DNA_TM_VOTE_OFF_TIMESTAMP  125
#define DNA_TM_VOTE_OFF_CHAIN_ID   133
#define DNA_TM_VOTE_OFF_VSET_HASH  165

/* ── Field widths ───────────────────────────────────────────────────── */
#define DNA_TM_BLOCK_ID_LEN        64
#define DNA_TM_VOTER_ID_LEN        32

/**
 * Build the exact 229-byte preimage. type ∈ {1,2}; nil vote = block_id 64 × 0.
 *
 * Pure byte layout: it reads no clock, allocates nothing, and computes no
 * consensus value. The caller supplies every field, including the timestamp.
 *
 * @return 0 / -1 (NULL argument or type outside {1,2}).
 */
int dna_tm_vote_preimage(uint8_t type,
                         const uint8_t block_id[DNA_TM_BLOCK_ID_LEN],
                         const uint8_t voter_id[DNA_TM_VOTER_ID_LEN],
                         uint64_t height, uint32_t round, uint64_t timestamp_ms,
                         const uint8_t chain_id[DNA_CHAIN_ID_LEN],
                         const uint8_t vset_hash[DNA_VSET_HASH_LEN],
                         uint8_t out[DNA_TM_VOTE_PREIMAGE_LEN]);

/**
 * Own-vote stamping (T2 §4.1; consensus/state.go:2416-2435; bft-time.md "Vote Time").
 * have_ref = 1 → ts = max(now_ms, ref_time_ms + 1); have_ref = 0 → ts = now_ms.
 * ref = locked value's header time if locked, else the proposal's header time
 * (the HOST picks which; this function only does the arithmetic).
 *
 * THIS FUNCTION READS NO CLOCK. `now_ms` is the host's own clock reading,
 * passed in, and this is the ONE place a validator's clock reaches consensus
 * data (D-20; the narrowed CLAUDE.md determinism scope, 2026-09-09). The
 * arithmetic is pure, so two nodes given the same arguments always agree.
 *
 * ref_time_ms == UINT64_MAX is rejected UNCONDITIONALLY (also when
 * have_ref = 0): ref + 1 would wrap to 0 and silently stamp the vote with
 * the epoch instead of a time after the reference, and rejecting it in both
 * branches keeps the guard independent of the flag.
 *
 * @return 0 / -1 (NULL out, or ref_time_ms == UINT64_MAX).
 */
int dna_tm_vote_time(uint64_t now_ms, int have_ref, uint64_t ref_time_ms, uint64_t *out_ts_ms);

/**
 * Signer-rule helper (T2 §4.9 step 3): classify two 229-byte preimages.
 *
 * The reference's privval returns the STORED signature and the STORED
 * timestamp when a sign request differs from the last one only in the
 * timestamp field (privval/file.go:335-343). Class 1 is exactly that case;
 * class 2 is the "conflicting data" case that must be refused. The host
 * applies the rule — this function only classifies.
 *
 * @return 0 identical; 1 differ ONLY in off 125..132 (timestamp); 2 differ elsewhere; -1 NULL.
 */
int dna_tm_vote_preimage_diff_class(const uint8_t a[DNA_TM_VOTE_PREIMAGE_LEN],
                                    const uint8_t b[DNA_TM_VOTE_PREIMAGE_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* SHARED_DNAC_TM_VOTE_H */
