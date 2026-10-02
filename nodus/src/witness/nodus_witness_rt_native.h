/**
 * @file nodus_witness_rt_native.h
 * @brief READ-ONLY description of one committed native envelope leg —
 *        the effects the compiled SYSTEM / DNA_CORE runtime
 *        (nodus_witness_rt_native.c) derived for it, recomputed from the
 *        leg's own call bytes by the SAME static decoders and output-id
 *        derivations the exec hooks run.
 *
 * WHY THIS EXISTS (scan-v3, decision docs/plans/decisions/
 * 2026-09-28-scan-v3-query.md; design docs/plans/2026-09-28-scan-v3-
 * design.md, item 1): the `dnac_v3_block` client query reports what an
 * APPLIED item did — coins consumed, coins created, value burned, the
 * SYSTEM record written. Those layouts are consensus encodings that live
 * in exactly one file; a second decoder elsewhere would be a second
 * implementation able to drift. This entry point keeps every byte offset
 * and every preimage inside nodus_witness_rt_native.c.
 *
 * PURITY: no database, no clock, no RNG, no allocation, no global state.
 * It executes nothing and changes nothing — it only parses the call bytes
 * the exec hook parsed and recomputes the identities the exec hook
 * derived. It does NOT re-judge the leg (no ownership, balance, lock or
 * quorum check): it is meaningful ONLY for a leg of an envelope the chain
 * APPLIED (result code 0), which the caller must establish from the
 * stored FinalizeBlock response.
 *
 * @file nodus_witness_rt_native.h
 */

#ifndef NODUS_WITNESS_RT_NATIVE_H
#define NODUS_WITNESS_RT_NATIVE_H

#include <stdint.h>
#include <stddef.h>

#include "dnac/env_wire.h"
#include "witness/nodus_witness_runtime.h"   /* nodus_rt_auth_verdict_t */

#ifdef __cplusplus
extern "C" {
#endif

/** Inputs one CORE leg can consume: the SPEND/BURN/SYSFUND transfer
 *  section's in_count ceiling (RTN_SPEND_MAX_IN, the largest of the
 *  three parsers' bounds; TOKEN_CREATE's is 14). */
#define NODUS_RT_DESC_MAX_IN   15u
/** Coins one CORE leg can create: RTN_SPEND_MAX_OUT (16) wire outputs
 *  plus the SYSFUND UNDELEGATE release coin. */
#define NODUS_RT_DESC_MAX_OUT  17u

/** The SYSTEM record a leg writes (none for a CORE leg). */
typedef enum {
    NODUS_RT_DESC_REC_NONE             = 0,
    NODUS_RT_DESC_REC_STAKE            = 1,
    NODUS_RT_DESC_REC_DELEGATE         = 2,
    NODUS_RT_DESC_REC_UNSTAKE          = 3,
    NODUS_RT_DESC_REC_UNDELEGATE       = 4,
    NODUS_RT_DESC_REC_VALIDATOR_UPDATE = 5,
    NODUS_RT_DESC_REC_CHAIN_CONFIG     = 6
} nodus_rt_desc_rec_t;

/** One coin the leg created — exactly the utxo_set row fields the exec
 *  hook's CREATE effect carries (owner / amount / token / unlock) plus
 *  its identity (the utxo_set primary key). */
typedef struct {
    uint8_t  id[64];
    uint8_t  owner_hex[128];      /* 128 lowercase hex, NOT NUL-terminated */
    uint64_t amount;
    uint8_t  token_id[64];        /* all-zero = native                     */
    uint64_t unlock_block;        /* 0 unless the UNDELEGATE release       */
} nodus_rt_desc_coin_t;

typedef struct {
    uint32_t domain_id;
    uint32_t runtime_op;

    /* CORE effects, in CALL order (never re-sorted) */
    uint8_t  n_consumed;
    uint8_t  consumed[NODUS_RT_DESC_MAX_IN][64];
    uint8_t  n_created;
    nodus_rt_desc_coin_t created[NODUS_RT_DESC_MAX_OUT];
    uint64_t burned;              /* BURN's burn_amount; 0 otherwise       */
    /* HF-4 NAME_REGISTER (design §1.7): the registered name and the
     * price paid into the reward pool. The price is NEVER folded into
     * `burned` — nothing is destroyed (a consumer would show it as
     * "Burned"). name_len 0 = not a registration. */
    uint8_t  name_len;
    uint8_t  name[36];            /* name_len bytes, NOT NUL-terminated    */
    uint64_t name_price;

    /* SYSTEM record — only the fields its kind names are meaningful.
     * Fingerprints are the RAW SHA3-512 of the call-carried pubkey (the
     * identity the exec hook binds the row to). */
    nodus_rt_desc_rec_t rec;
    uint8_t  rec_validator_fp[64];   /* STAKE, DELEGATE, UNSTAKE,
                                      * UNDELEGATE, VALIDATOR_UPDATE     */
    uint8_t  rec_delegator_fp[64];   /* DELEGATE, UNDELEGATE             */
    uint8_t  rec_dest_fp[64];        /* STAKE: the unstake destination   */
    uint64_t rec_amount;             /* STAKE bond; DELEGATE/UNDELEGATE  */
    uint16_t rec_commission_bps;     /* STAKE, VALIDATOR_UPDATE          */
    uint8_t  cc_param_id;            /* CHAIN_CONFIG                     */
    uint64_t cc_new_value;
    uint64_t cc_effective;
} nodus_rt_leg_desc_t;

/**
 * Describe leg `leg_index` of the decoded envelope `env`.
 *
 * Per op, the decoder and derivation it reuses (all static in
 * nodus_witness_rt_native.c, the SAME calls the exec hooks make):
 *   CORE SPEND        rtn_spend_parse + rtn_out_ids
 *   CORE BURN         rtn_burn_parse  + rtn_out_ids (+ burn_amount)
 *   CORE TOKEN_CREATE rtn_tc_parse    + rtn_out_ids
 *   CORE SYSFUND      rtn_sysfund_shape + rtn_sysfund_parse + rtn_out_ids,
 *                     the sibling SYSTEM leg's rtn_sys_call_flow, and —
 *                     for an UNDELEGATE release — rtn_sysfund_release_coin
 *                     (the helper rtn_sysfund_exec itself calls)
 *   SYSTEM STAKE / DELEGATE / UNSTAKE / UNDELEGATE / VALIDATOR_UPDATE
 *                     rtn_sys_stake_shape + rtn_stake_parse /
 *                     rtn_deleg_parse / rtn_vupd_parse
 *   SYSTEM CHAIN_CONFIG rtn_cc_parse
 *
 * @param global_height the height the envelope was APPLIED at (the
 *        release coin's lock is derived from it, as in exec).
 * @param intent_id the envelope's committed intent identity (the release
 *        coin's identity preimage, as in exec); may be NULL only when no
 *        UNDELEGATE release can arise (it is checked where it is needed).
 * @return 0 described; -1 the leg names an op this file does not execute
 *         or its call bytes do not parse (for an APPLIED leg that means
 *         this build cannot describe what the chain did — the caller must
 *         fail, never answer partially); -2 a hash-backend fault.
 */
int nodus_rt_native_describe_leg(const dna_env_view_t *env,
                                 uint16_t leg_index,
                                 uint64_t global_height,
                                 const uint8_t *intent_id,
                                 nodus_rt_leg_desc_t *out);

/**
 * HF-4 (design docs/plans/2026-10-02-onchain-names-design.md rev 4 §2
 * "Same owner, two names pending") — the CheckTx-only synthetic OWNER
 * conflict key of a CORE NAME_REGISTER leg: the CORE adapter's read-only
 * OWNER op id and the leg's owner (the verified verdict's signer_fp[0]).
 * The CheckTx dry run appends it to its conflict rows so one node's
 * mempool admits one registration per owner. Mempool only — it never
 * reaches consensus state or a result.
 * @return 0 key filled; 1 the leg is not a CORE NAME_REGISTER leg (no
 *         key); -1 bad arguments or an owner shape the exec refuses.
 */
int nodus_rt_core_name_owner_key(const dna_env_view_t *env,
                                 uint16_t leg_index,
                                 const nodus_rt_auth_verdict_t *verdict,
                                 uint32_t *op_id_out,
                                 uint8_t key_out[64]);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_RT_NATIVE_H */
