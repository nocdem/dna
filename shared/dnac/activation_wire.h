/**
 * @file shared/dnac/activation_wire.h
 * @brief Ledger V2 O15C — committed activation authority: canonical
 *        objects, digests and the type-15/16 transaction extension wire.
 *
 * O15C-A (approved design) defines the ONE committed authority that can
 * ever select Ledger V2: a quorum-scheduled, all-active-readiness
 * activation record committed under the legacy chain's state root
 * (activation_root, 6th leg, state_root v4). This header carries every
 * canonical byte layout of that mechanism, shared verbatim between
 * libdna (client encoder), libnodus (witness decoder/apply) and the
 * nodus-cli operator verb — drift between any two is a silent consensus
 * break, exactly the chain_config_wire.h discipline.
 *
 * ═══ Objects ══════════════════════════════════════════════════════════
 *
 * 1. ActivationTarget digest D (what the validators must be running):
 *      D = SHA3-512( "DNA.V2ACT.TGT.v1"
 *                    ‖ target_version   u32 BE  (= 1)
 *                    ‖ header_version   u8      (DNA_BH2_VERSION = 3)
 *                    ‖ schema_version   u32 BE  (v2 ladder, = 10)
 *                    ‖ runtime_count    u32 BE
 *                    ‖ per runtime, domain_id ASC:
 *                        domain_id       u32 BE
 *                        ruleset_version u32 BE
 *                        ruleset_hash    [64]   (RulesetDescriptor digest —
 *                                                already commits kind/abi/
 *                                                rule list/meter policy) )
 *    Two binaries deriving the same D structurally run the same V2
 *    semantics. All-zero D is INVALID everywhere (fail closed).
 *
 * 2. Schedule digest (what governance quorum signs, type-15 op SCHEDULE):
 *      SHA3-512( "DNA.V2ACT.SCH.v1" ‖ chain_id[32]
 *                ‖ record_version u32 BE (= 1) ‖ D[64]
 *                ‖ activation_height u64 BE (the ORIGINAL H_act)
 *                ‖ proposal_nonce u64 BE ‖ signed_at_block u64 BE
 *                ‖ valid_before_block u64 BE )
 *
 * 3. Cancel digest (type-15 op CANCEL):
 *      SHA3-512( "DNA.V2ACT.CXL.v1" ‖ chain_id[32]
 *                ‖ schedule_digest[64] ‖ proposal_nonce u64 BE
 *                ‖ signed_at_block u64 BE ‖ valid_before_block u64 BE )
 *
 * 4. Readiness signal preimage (what ONE validator signs, type 16):
 *      SHA3-512( "DNA.V2ACT.RDY.v1" ‖ signal_version u32 BE (= 1)
 *                ‖ chain_id[32] ‖ schedule_digest[64] ‖ D[64]
 *                ‖ voter_id[32] ‖ signal_epoch u64 BE )
 *    The signal binds the ORIGINAL activation height only THROUGH the
 *    schedule digest and deliberately does NOT bind the record's mutable
 *    (postponable) activation_height — otherwise every one-epoch
 *    postponement would void every stored signal and the postpone loop
 *    could never converge (O15C-A §D.2).
 *
 * 5. Terminal source commitment (the seam binding, O15C-B §1.3):
 *      source_tag    = "DNA.LEGACY.TERM.v1"                 (18 bytes)
 *      source_commit = legacy_chain_id[32]
 *                      ‖ terminal_block_id[64]  (legacy block hash @H_act)
 *                      ‖ terminal_state_root[64]
 *                      ‖ H_act u64 BE                       (168 bytes)
 *    Binds all four required facts: chain id, terminal BlockID, terminal
 *    state root, terminal height.
 *
 * ═══ TX extension wire (appended after the generic TX body) ═══════════
 *
 * type 15 (DNAC_TX_V2_SCHEDULE — op SCHEDULE and op CANCEL, one shape):
 *   record_version(u32 BE) ‖ op(u8: 1=SCHEDULE 2=CANCEL)
 *   ‖ target[64]  (op1: D; op2: the schedule_digest being cancelled)
 *   ‖ activation_height(u64 BE; MUST be 0 for op2)
 *   ‖ proposal_nonce(u64 BE) ‖ signed_at_block(u64 BE)
 *   ‖ valid_before_block(u64 BE) ‖ vote_count(u8)
 *   ‖ votes[vote_count] × { witness_id[32], signature[4627] }
 *   Fixed 102 bytes before votes[]; per-vote 4659 (the CC shapes).
 *
 * type 16 (DNAC_TX_V2_READY — exactly one validator's signal):
 *   signal_version(u32 BE) ‖ schedule_digest[64] ‖ target[64]
 *   ‖ voter_id[32] ‖ signal_epoch(u64 BE)
 *   ‖ pubkey[2592] ‖ signature[4627]      — fixed 7391 bytes total.
 *
 * Both sections enter the legacy tx-hash preimage verbatim (the
 * CHAIN_CONFIG precedent: votes included).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef SHARED_DNAC_ACTIVATION_WIRE_H
#define SHARED_DNAC_ACTIVATION_WIRE_H

#include <stdint.h>
#include <stddef.h>

#include "dnac/ledger_ids.h"    /* DNA_MAX_ACTIVE_VALIDATORS */

#ifdef __cplusplus
extern "C" {
#endif

/* ── Sizes and constants ─────────────────────────────────────────────── */

#define DNA_ACT_HASH_LEN            64
#define DNA_ACT_CHAIN_ID_LEN        32
#define DNA_ACT_VOTER_ID_LEN        32
#define DNA_ACT_PUBKEY_LEN          2592   /* ML-DSA-87 */
#define DNA_ACT_SIG_LEN             4627   /* ML-DSA-87 */

#define DNA_ACT_RECORD_VERSION      1u
#define DNA_ACT_SIGNAL_VERSION      1u
#define DNA_ACT_TARGET_VERSION      1u

/* Activation record states (0 = INVALID, fail closed everywhere). */
#define DNA_ACT_STATE_INVALID       0u
#define DNA_ACT_STATE_SCHEDULED     1u
#define DNA_ACT_STATE_READY         2u
#define DNA_ACT_STATE_ACTIVE        3u
#define DNA_ACT_STATE_CANCELLED     4u

/* type-15 ops. */
#define DNA_ACT_OP_SCHEDULE         1u
#define DNA_ACT_OP_CANCEL           2u

/* Bounded postponement: one epoch at a time, auto-cancel past the cap
 * (O15C-A §D.3 JUDGMENT backstop — kills immortal schedules). */
#define DNA_ACT_MAX_POSTPONES       8u

/* 16-byte domain tags (exact length, no padding). */
#define DNA_ACT_TAG_TARGET          "DNA.V2ACT.TGT.v1"
#define DNA_ACT_TAG_SCHEDULE        "DNA.V2ACT.SCH.v1"
#define DNA_ACT_TAG_CANCEL          "DNA.V2ACT.CXL.v1"
#define DNA_ACT_TAG_READY           "DNA.V2ACT.RDY.v1"
/* activation_root leaf domains (16 bytes each, exact). */
#define DNA_ACT_TAG_REC_LEAF        "DNA.V2ACTLEAF.v1"
#define DNA_ACT_TAG_RDY_LEAF        "DNA.V2ACTRDYL.v1"

/* Terminal source commitment (seam). */
#define DNA_ACT_SOURCE_TAG          "DNA.LEGACY.TERM.v1"
#define DNA_ACT_SOURCE_TAG_LEN      18
#define DNA_ACT_SOURCE_COMMIT_LEN   (32 + 64 + 64 + 8)   /* 168 */

/* ── type-15 extension ───────────────────────────────────────────────── */

#define DNA_ACT15_WIRE_FIXED_LEN    (4 + 1 + 64 + 8 + 8 + 8 + 8 + 1) /* 102 */
#define DNA_ACT15_WIRE_PER_VOTE     (DNA_ACT_VOTER_ID_LEN + DNA_ACT_SIG_LEN)
#define DNA_ACT15_WIRE_MAX_SLOTS    DNA_MAX_ACTIVE_VALIDATORS
#define DNA_ACT15_WIRE_MAX_LEN      (DNA_ACT15_WIRE_FIXED_LEN + \
                                     (size_t)DNA_ACT15_WIRE_MAX_SLOTS * \
                                     DNA_ACT15_WIRE_PER_VOTE)

typedef struct {
    uint8_t witness_id[DNA_ACT_VOTER_ID_LEN];
    uint8_t signature[DNA_ACT_SIG_LEN];
} dna_act_wire_vote_t;

/** Parsed / to-encode type-15 extension.
 *  ⚠ ~596 KiB at the slot cap — heap-allocate, never the stack. */
typedef struct {
    uint32_t record_version;
    uint8_t  op;                       /* DNA_ACT_OP_* */
    uint8_t  target[DNA_ACT_HASH_LEN]; /* op1: D; op2: schedule_digest */
    uint64_t activation_height;        /* op1: original H_act; op2: 0 */
    uint64_t proposal_nonce;
    uint64_t signed_at_block;
    uint64_t valid_before_block;
    uint8_t  vote_count;
    dna_act_wire_vote_t votes[DNA_ACT15_WIRE_MAX_SLOTS];
} dna_act15_wire_t;

size_t dna_act15_wire_encoded_size(const dna_act15_wire_t *f);
int dna_act15_wire_encode(const dna_act15_wire_t *f,
                          uint8_t *dst, size_t dst_cap, size_t *written);
/** Shape-only decode (count cap + exact byte availability). Semantic
 *  rules (op/version/quorum/windows) are layered by the witness. Unused
 *  trailing vote slots are zeroed. @return 0 / -1. */
int dna_act15_wire_decode(const uint8_t *src, size_t src_len,
                          dna_act15_wire_t *out, size_t *consumed);

/* ── type-16 extension ───────────────────────────────────────────────── */

#define DNA_ACT16_WIRE_LEN  (4 + 64 + 64 + DNA_ACT_VOTER_ID_LEN + 8 + \
                             DNA_ACT_PUBKEY_LEN + DNA_ACT_SIG_LEN)  /* 7391 */

typedef struct {
    uint32_t signal_version;
    uint8_t  schedule_digest[DNA_ACT_HASH_LEN];
    uint8_t  target[DNA_ACT_HASH_LEN];
    uint8_t  voter_id[DNA_ACT_VOTER_ID_LEN];
    uint64_t signal_epoch;             /* EPOCH START HEIGHT at submission */
    uint8_t  pubkey[DNA_ACT_PUBKEY_LEN];
    uint8_t  signature[DNA_ACT_SIG_LEN];
} dna_act16_wire_t;

int dna_act16_wire_encode(const dna_act16_wire_t *f,
                          uint8_t *dst, size_t dst_cap, size_t *written);
int dna_act16_wire_decode(const uint8_t *src, size_t src_len,
                          dna_act16_wire_t *out, size_t *consumed);

/* ── Digests (pure functions, SHA3-512) ──────────────────────────────── */

/** One (domain_id, ruleset_version, ruleset_hash) target row. */
typedef struct {
    uint32_t domain_id;
    uint32_t ruleset_version;
    uint8_t  ruleset_hash[DNA_ACT_HASH_LEN];
} dna_act_target_rt_t;

/** ActivationTarget digest D. `rts` MUST be strictly ascending by
 *  domain_id (rejected otherwise); n in [1, 16]. @return 0 / -1. */
int dna_act_target_digest(uint32_t target_version,
                          uint8_t  header_version,
                          uint32_t schema_version,
                          const dna_act_target_rt_t *rts, size_t n,
                          uint8_t out[DNA_ACT_HASH_LEN]);

int dna_act_sched_digest(const uint8_t chain_id[DNA_ACT_CHAIN_ID_LEN],
                         uint32_t record_version,
                         const uint8_t target[DNA_ACT_HASH_LEN],
                         uint64_t activation_height,
                         uint64_t proposal_nonce,
                         uint64_t signed_at_block,
                         uint64_t valid_before_block,
                         uint8_t out[DNA_ACT_HASH_LEN]);

int dna_act_cancel_digest(const uint8_t chain_id[DNA_ACT_CHAIN_ID_LEN],
                          const uint8_t schedule_digest[DNA_ACT_HASH_LEN],
                          uint64_t proposal_nonce,
                          uint64_t signed_at_block,
                          uint64_t valid_before_block,
                          uint8_t out[DNA_ACT_HASH_LEN]);

int dna_act_ready_digest(uint32_t signal_version,
                         const uint8_t chain_id[DNA_ACT_CHAIN_ID_LEN],
                         const uint8_t schedule_digest[DNA_ACT_HASH_LEN],
                         const uint8_t target[DNA_ACT_HASH_LEN],
                         const uint8_t voter_id[DNA_ACT_VOTER_ID_LEN],
                         uint64_t signal_epoch,
                         uint8_t out[DNA_ACT_HASH_LEN]);

/** Terminal source commitment bytes (168). @return 0 / -1. */
int dna_act_source_commit(const uint8_t legacy_chain_id[DNA_ACT_CHAIN_ID_LEN],
                          const uint8_t terminal_block_id[DNA_ACT_HASH_LEN],
                          const uint8_t terminal_state_root[DNA_ACT_HASH_LEN],
                          uint64_t terminal_height,
                          uint8_t out[DNA_ACT_SOURCE_COMMIT_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* SHARED_DNAC_ACTIVATION_WIRE_H */
