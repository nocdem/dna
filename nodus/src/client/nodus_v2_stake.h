/**
 * @file nodus/src/client/nodus_v2_stake.h
 * @brief The shared version-3 staking envelope builder — STAKE, DELEGATE,
 *        UNSTAKE, UNDELEGATE, STORAGE_REGISTER, STORAGE_EXIT — build + read
 *        back, no I/O.
 *
 * Governing records: docs/plans/decisions/2026-09-25-web-wallet-nodus-send-
 * transport.md ("İşlem kurucu": the wallet builds with the SAME C code
 * nodus-cli uses — no JS rewrite; applied here to the staking envelopes as
 * it was to the SPEND in nodus_v2_spend.h) and docs/plans/decisions/
 * 2026-09-28-treasury-pools-and-exact-self-stake.md (the bond is EXACTLY
 * DNAC_SELF_STAKE_AMOUNT; self-delegation is allowed).
 *
 * WHAT IT IS: the body of nodus-cli `v2-envelope stake|delegate`
 * (cmd_v2_stake), moved out unchanged in behaviour, plus the UNDELEGATE
 * sibling nodus-cli had no builder for, and the UNSTAKE sibling
 * (`v2-envelope unstake`). Pure functions over caller-supplied
 * inputs — the listed coins, the committed tip, the gas price, the chain
 * id, the ruleset identity and the signing key. It opens no socket, reads
 * no clock, touches no database and draws NO randomness: the only output
 * record it writes (the funding change) is seeded deterministically,
 * seed = SHA3-512(the selected nullifiers, ascending)[0..31], exactly as
 * cmd_v2_stake did. qgp_dsa87_sign is HEDGED (see nodus_v2_spend.h), so two
 * builds from identical inputs differ in their signature bytes and wire_id
 * only; intent_id and every byte outside the two auth blobs are identical.
 *
 * THE CHAIN IS THE SPECIFICATION (nodus/src/witness/nodus_witness_rt_native.c):
 *   leg0 SYSTEM record leg (rtn_sys_stake_shape — leg 0 of exactly two):
 *     STAKE      (op 1) staker_pk[2592] ‖ commission u16 BE ‖ bond u64 BE
 *                       ‖ unstake_dest_fp[64 raw]            = 2666 bytes
 *                       (rtn_stake_parse)
 *     DELEGATE   (op 2) delegator_pk[2592] ‖ validator_pk[2592]
 *                       ‖ amount u64 BE                      = 5192 bytes
 *     UNSTAKE    (op 3) validator_pk[2592]                   = 2592 bytes
 *                       (RTN_SYS_UNSTAKE_CALL_LEN, rtn_sys_call_identity:
 *                       the call IS the validator key, and the signer
 *                       must be that key — rtn_sys_stake_auth)
 *     UNDELEGATE (op 4) the DELEGATE layout (rtn_deleg_parse,
 *                       RTN_SYS_UNDELEGATE_CALL_LEN)
 *     STORAGE_REGISTER (op 7) node_pk[2592] ‖ bond u64 BE
 *                       ‖ payee_fp[64 raw]                   = 2664 bytes
 *                       (RTN_SYS_STREG_CALL_LEN, rtn_streg_parse; bytes doc
 *                       docs/plans/2026-10-04-storage-reward-bytes.md item 5)
 *     STORAGE_EXIT     (op 8) node_pk[2592]                  = 2592 bytes
 *                       (RTN_SYS_STEXIT_CALL_LEN; rtn_sys_call_identity:
 *                       the call IS the node key, the signer must be it)
 *     Both storage ops exist only under the GEN_STORAGE rule set
 *     (rtn_gen_storage): the caller passes that generation's tuples.
 *   leg1 CORE SYSFUND (op 7) = a SPEND transfer section (rtn_sysfund_parse):
 *     in_count ‖ nullifiers ascending ‖ out_count (0/1) ‖ native change.
 *   Conservation (rtn_sysfund_exec): Σnative_in == Σchange + fee + lock,
 *   where rtn_sys_call_flow derives lock = bond (STAKE, STORAGE_REGISTER) /
 *   amount (DELEGATE) / 0 (UNSTAKE, UNDELEGATE, STORAGE_EXIT). STORAGE_EXIT
 *   moves no value in its block: the exec marks the row EXITING
 *   (rtn_storage_exit_exec) and the storage boundary releases the bond as
 *   one UTXO to payee_fp locked DNAC_STORAGE_EXIT_LOCK_EPOCHS epochs
 *   (nodus_witness_v2_storage.c step 3). UNDELEGATE's funding leg pays the
 *   FEE ONLY; its principal comes back as a release coin the CHAIN creates
 *   in the same block (rtn_sysfund_release_coin), LOCKED until L(h) +
 *   DNAC_UNDELEGATE_LOCK_EPOCHS · E — this builder writes no release output.
 *   UNSTAKE's funding leg pays the FEE ONLY too (lock 0, release 0): the
 *   exec only moves the row to RETIRING (rtn_unstake_exec); the bond is
 *   released at the epoch-boundary graduation (nodus_witness_v2_epoch.c
 *   v2ep_graduate), locked DNAC_VALIDATOR_UNBOND_EPOCHS epochs, to the row's
 *   unstake_destination_fp, and every delegation the validator still holds
 *   is returned to its delegator at the same boundary, locked
 *   DNAC_UNDELEGATE_LOCK_EPOCHS epochs (v2ep_release_delegations — the
 *   "no delegators" Rule A is gone, tokenomics-v3 P3-4).
 *
 * WHAT THE BUILDER DECIDES vs WHAT THE CHAIN DECIDES: the builder refuses
 * only what the call bytes alone decide (the same checks cmd_v2_stake made
 * before any I/O):
 *   STAKE      bond == DNAC_SELF_STAKE_AMOUNT (rtn_stake_exec, W-B);
 *              commission_bps <= DNAC_COMMISSION_BPS_MAX (P3-8)
 *   DELEGATE /
 *   UNDELEGATE 1 <= amount <= DNAC_DEFAULT_TOTAL_SUPPLY
 *   UNSTAKE    nothing — the call is the signer's own key; `amount`,
 *              `commission_bps`, `dest_fp` and `validator_pk` are ignored
 *   STORAGE_REGISTER
 *              bond == DNAC_STORAGE_STAKE_MIN and payee (`dest_fp`) ==
 *              SHA3-512(pk) (rtn_storage_register_exec: the payee is the
 *              node's own fingerprint until HF-5 re-keys it)
 *   STORAGE_EXIT
 *              nothing — the UNSTAKE shape (call = the node key)
 * Everything that needs committed state is the chain's, at CheckTx:
 * DELEGATE — a bonded target, DNAC_MIN_DELEGATION for a NEW row, the
 * per-validator delegator cap; UNDELEGATE — the row exists, amount <= its
 * amount, a partial withdrawal leaves 0 or >= DNAC_MIN_DELEGATION
 * (rtn_undelegate_exec); UNSTAKE — the validator row exists and is ACTIVE
 * or ELIGIBLE (a repeated UNSTAKE finds it RETIRING and is rejected,
 * rtn_unstake_exec); STORAGE_REGISTER — no ACTIVE / EXITING row for the
 * node, fewer than NODUS_STORAGE_SET_MAX live rows; STORAGE_EXIT — the row
 * exists and is ACTIVE (rtn_storage_register_exec / _exit_exec).
 *
 * RULESET IDENTITY: leg0 is built against the SYSTEM ruleset tuple and leg1
 * against the CORE one; both hashes enter the digests the signature covers
 * (shared/dnac/env_preflight.c, dna_env_call_commit). A node-linked caller
 * (nodus-cli) fills nodus_v2_stake_ruleset_t from the compiled table; a
 * caller that cannot link the witness (the browser module) calls
 * nodus_v2_stake_ruleset_from_pins, which reads both tuples from the
 * GENERATED nodus_ruleset_pins.h (the "Yol 2" addendum of the decision
 * above, extended to the SYSTEM tuple by the same mechanism — ctest
 * test_ruleset_pins byte-compares the header with the node's table).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef NODUS_V2_STAKE_H
#define NODUS_V2_STAKE_H

#include <stdint.h>
#include <stddef.h>

#include "nodus/nodus_v2_spend.h"   /* rc values, widths, sign_one_key */

#ifdef __cplusplus
extern "C" {
#endif

/** The fixed declarations cmd_v2_stake used (right-sizing them like the
 *  SPEND builder is separate work, decision 2026-09-25-gas-price.md detail
 *  2): the envelope's unit ceiling — also what the gas-price fee is
 *  computed from — and each leg's effect declaration. */
#define NODUS_V2_STAKE_UNITS              400000u
#define NODUS_V2_STAKE_SYS_EFFECTS        8u
#define NODUS_V2_STAKE_SYS_EFFECT_BYTES   16384u
#define NODUS_V2_STAKE_FUND_EFFECTS       40u
#define NODUS_V2_STAKE_FUND_EFFECT_BYTES  16384u

/** SYSTEM call lengths (rtn_stake_parse / rtn_deleg_parse /
 *  RTN_SYS_UNSTAKE_CALL_LEN / RTN_SYS_STREG_CALL_LEN /
 *  RTN_SYS_STEXIT_CALL_LEN). */
#define NODUS_V2_STAKE_CALL_LEN           2666u
#define NODUS_V2_DELEG_CALL_LEN           5192u
#define NODUS_V2_UNSTAKE_CALL_LEN         2592u
#define NODUS_V2_STREG_CALL_LEN           2664u
#define NODUS_V2_STEXIT_CALL_LEN          2592u

/** Refusals of this module beyond the shared nodus_v2_spend_rc_t values it
 *  also returns (ERR_ARG, ERR_ALLOC, ERR_OVERFLOW, ERR_INPUT_SUM,
 *  ERR_INSUFFICIENT, ERR_GAS_OVERFLOW, ERR_HASH, ERR_ENCODE,
 *  ERR_PREFLIGHT1, ERR_SIGN, ERR_PREFLIGHT2, ERR_EXPIRY, ERR_DECODE). */
typedef enum {
    NODUS_V2_STAKE_ERR_BOND       = -40,  /* STAKE bond != the self-bond   */
    NODUS_V2_STAKE_ERR_COMMISSION = -41,  /* > DNAC_COMMISSION_BPS_MAX     */
    NODUS_V2_STAKE_ERR_AMOUNT     = -42,  /* outside 1..total supply       */
    NODUS_V2_STAKE_ERR_OP         = -43,  /* not STAKE/DELEGATE/UNSTAKE/
                                           * UNDELEGATE/STORAGE_REGISTER/
                                           * STORAGE_EXIT                 */
    NODUS_V2_STAKE_ERR_STORAGE_BOND = -44,  /* STORAGE_REGISTER bond !=
                                             * DNAC_STORAGE_STAKE_MIN     */
    NODUS_V2_STAKE_ERR_PAYEE      = -45   /* STORAGE_REGISTER payee !=
                                           * SHA3-512(pk) (until HF-5)    */
} nodus_v2_stake_rc_t;

/** Which SYSTEM record leg — the value IS the runtime_op on the wire
 *  (nodus_witness_runtime.h DNA_SYSRULE_*). */
typedef enum {
    NODUS_V2_STAKE_OP_STAKE            = 1,
    NODUS_V2_STAKE_OP_DELEGATE         = 2,
    NODUS_V2_STAKE_OP_UNSTAKE          = 3,
    NODUS_V2_STAKE_OP_UNDELEGATE       = 4,
    NODUS_V2_STAKE_OP_STORAGE_REGISTER = 7,
    NODUS_V2_STAKE_OP_STORAGE_EXIT     = 8
} nodus_v2_stake_op_t;

/** The two ruleset tuples a staking envelope is built against. */
typedef struct {
    uint32_t sys_ruleset_version;
    uint8_t  sys_ruleset_hash[DNA_ENV_RULESET_HASH_LEN];
    uint32_t core_ruleset_version;
    uint8_t  core_ruleset_hash[DNA_ENV_RULESET_HASH_LEN];
} nodus_v2_stake_ruleset_t;

/** One coin as the node lists it (dnac_utxo row). The builder itself
 *  skips a zero amount, a non-native token and a coin still locked at the
 *  tip (unlock_block > tip) — cmd_v2_stake's filter. */
typedef struct {
    uint8_t  nul[64];
    uint64_t amount;
    uint8_t  token[64];       /* all-zero = native */
    uint64_t unlock_block;
} nodus_v2_stake_coin_t;

typedef struct {
    const nodus_v2_stake_ruleset_t *rs;
    nodus_v2_stake_op_t op;
    const uint8_t *chain32;          /* DNA_CHAIN_ID_LEN bytes              */
    uint64_t       tip;              /* committed tip (>= 1)                */
    uint64_t       expiry_height;    /* (tip, tip + NODUS_CMT_APP_MAX_
                                      * EXPIRY_AHEAD]                       */
    const uint8_t *pk;               /* ML-DSA-87 pk 2592 B: the record
                                      * identity (staker / delegator /
                                      * the retiring validator / the
                                      * storage node), the signer of both
                                      * legs and the owner of every
                                      * funding coin                        */
    const uint8_t *sk;               /* 4896 B                              */
    uint64_t       amount;           /* STAKE / STORAGE_REGISTER: the bond;
                                      * DELEGATE / UNDELEGATE: the amount;
                                      * UNSTAKE / STORAGE_EXIT: ignored     */
    uint32_t       commission_bps;   /* STAKE only                          */
    const uint8_t *dest_fp;          /* STAKE: the unstake destination;
                                      * STORAGE_REGISTER: the payee_fp
                                      * (must be SHA3-512(pk)); 64 raw B    */
    const uint8_t *validator_pk;     /* DELEGATE / UNDELEGATE: 2592 B       */
    uint64_t       gas_price;        /* 0 = rule off (the flat floor)       */
    const nodus_v2_stake_coin_t *coins;
    int            n_coins;
} nodus_v2_stake_req_t;

/** Fill `out` with the SYSTEM and CORE tuples of the generated
 *  nodus_ruleset_pins.h. @return NODUS_V2_SPEND_OK / _ERR_ARG. */
int nodus_v2_stake_ruleset_from_pins(nodus_v2_stake_ruleset_t *out);

/** HF-4 — the same for pinned generation `generation` (the one whose
 *  tuple equals the node's dnac_ruleset_info answer;
 *  nodus_v2_stake_ruleset_from_pins above is generation 1, kept for the
 *  web wallet's WASM module). @return NODUS_V2_SPEND_OK / _ERR_ARG. */
int nodus_v2_stake_ruleset_from_pins_gen(uint32_t generation,
                                         nodus_v2_stake_ruleset_t *out);

/** Which numbers a refusal carries (for the caller's message). */
typedef struct {
    uint64_t fee;        /* the fee in force when it stopped              */
    uint64_t need;        /* lock + fee the funding had to cover           */
    uint64_t sum_in;      /* what the selected coins summed to             */
    int      n_in;
    uint64_t units, gas_price;
    int      leg;         /* signing: the failing leg                      */
} nodus_v2_stake_err_t;

/** A staking envelope read back from its bytes (self-consistent decode:
 *  this module's layout, checked against the chain's parsers' widths). */
typedef struct {
    uint32_t op;                         /* DNA_SYSRULE_*                   */
    uint64_t expiry_height, fee, units;
    uint32_t sys_ruleset_version, core_ruleset_version;
    uint8_t  identity_pk[2592];          /* staker / delegator / the
                                          * retiring validator (UNSTAKE) /
                                          * the storage node (ops 7, 8)     */
    uint8_t  validator_pk[2592];         /* DELEGATE / UNDELEGATE; zero
                                          * for every other op              */
    uint64_t amount;                     /* bond / amount; 0 for UNSTAKE
                                          * and STORAGE_EXIT                */
    uint32_t commission_bps;             /* STAKE                           */
    uint8_t  dest_fp[64];                /* STAKE: unstake destination;
                                          * STORAGE_REGISTER: payee_fp      */
    int      n_in;
    uint8_t  in_nul[NODUS_V2_SPEND_MAX_IN][64];
    int      n_out;                      /* 0 or 1                          */
    char     change_owner[129];
    uint64_t change_amount;
    uint8_t  change_id[64];              /* SHA3-512(owner ‖ seed)          */
} nodus_v2_stake_decoded_t;

typedef struct {
    uint8_t                 *env;        /* heap; nodus_v2_stake_built_free */
    size_t                   env_len;
    uint8_t                  wire_id[64];
    uint8_t                  intent_id[64];
    uint64_t                 fee, sum_in, change;
    int                      n_in;
    nodus_v2_stake_decoded_t dec;        /* read back from `env`           */
} nodus_v2_stake_built_t;

/**
 * Build, sign and self-check ONE two-leg staking envelope, then decode it
 * back and refuse if any decoded field differs from the request.
 *   fee    = max(DNAC_MIN_FEE_RAW, NODUS_W_BASE_TX_FEE), raised to
 *            NODUS_V2_STAKE_UNITS × gas_price when that is larger;
 *   need   = lock + fee (lock = amount for STAKE / DELEGATE /
 *            STORAGE_REGISTER, 0 for UNSTAKE / UNDELEGATE / STORAGE_EXIT);
 *   inputs = eligible coins ascending by nullifier, taken until their sum
 *            covers `need`, at most NODUS_V2_SPEND_MAX_IN;
 *   change = sum − need, one native output to the signer when > 0.
 * @return NODUS_V2_SPEND_OK or a refusal (`err` may be NULL).
 */
int nodus_v2_stake_build(const nodus_v2_stake_req_t *req,
                         nodus_v2_stake_built_t *out,
                         nodus_v2_stake_err_t *err);

/** Decode a two-leg staking envelope built by this module. Refuses any
 *  other shape (leg count, domains, ops, access modes, auth kind / length,
 *  effect declarations, call lengths, input order, change owner hex, a
 *  non-native or zero change, an auth blob not carrying exactly one signer
 *  whose key is the record identity, a STORAGE_REGISTER whose payee_fp is
 *  not SHA3-512 of the node key — the pre-HF-5 exec rule).
 *  @return NODUS_V2_SPEND_OK / _ERR_ARG / _ERR_ALLOC / _ERR_DECODE /
 *  _ERR_HASH. */
int nodus_v2_stake_decode(const uint8_t *env, size_t env_len,
                          nodus_v2_stake_decoded_t *out);

/** Free what nodus_v2_stake_build allocated inside `b`. NULL-safe. */
void nodus_v2_stake_built_free(nodus_v2_stake_built_t *b);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_V2_STAKE_H */
