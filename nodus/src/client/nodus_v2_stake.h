/**
 * @file nodus/src/client/nodus_v2_stake.h
 * @brief The shared version-3 staking envelope builder — STAKE, DELEGATE,
 *        UNSTAKE, UNDELEGATE, VALIDATOR_UPDATE (generation 4), ROTATE,
 *        STORAGE_REGISTER, STORAGE_EXIT — build + read back, no I/O.
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
 *     STORAGE_REGISTER / STORAGE_EXIT (ops 7 / 8): generation 4 only, see
 *                       "HF-6 6f-1 — GENERATION-AWARE" below.
 *   leg1 CORE SYSFUND (op 7) = a SPEND transfer section (rtn_sysfund_parse):
 *     in_count ‖ nullifiers ascending ‖ out_count (0/1) ‖ native change.
 *   Conservation (rtn_sysfund_exec): Σnative_in == Σchange + fee + lock,
 *   where rtn_sys_call_flow derives lock = bond (STAKE, STORAGE_REGISTER) /
 *   amount (DELEGATE) / 0 (UNSTAKE, UNDELEGATE, STORAGE_EXIT). STORAGE_EXIT
 *   moves no value in its block: the exec marks the row EXITING
 *   (rtn_storage_exit_exec) and the storage boundary releases the bond as
 *   one UTXO to the row's owner locked DNAC_STORAGE_EXIT_LOCK_EPOCHS
 *   epochs (nodus_witness_v2_storage.c step 3). UNDELEGATE's funding leg pays the
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
 *   STORAGE_REGISTER / STORAGE_EXIT: see the generation-4 block below
 * Everything that needs committed state is the chain's, at CheckTx:
 * DELEGATE — a bonded target, DNAC_MIN_DELEGATION for a NEW row, the
 * per-validator delegator cap; UNDELEGATE — the row exists, amount <= its
 * amount, a partial withdrawal leaves 0 or >= DNAC_MIN_DELEGATION
 * (rtn_undelegate_exec); UNSTAKE — the validator row exists and is ACTIVE
 * or ELIGIBLE (a repeated UNSTAKE finds it RETIRING and is rejected,
 * rtn_unstake_exec); STORAGE_REGISTER — the bond EXACTLY the STORAGE_BOND
 * in force, the node consent valid (op 3) and unexpired, no ACTIVE /
 * EXITING row for the node, a RELEASED row only past the re-registration
 * line, fewer than NODUS_STORAGE_SET_MAX live rows; STORAGE_EXIT — the row
 * exists, is ACTIVE and its owner signs (rtn_storage_register_exec /
 * _exit_exec).
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
 * HF-6 6f-1 — GENERATION-AWARE (design docs/plans/2026-10-03-hf5-validator-
 * owner-stake-design.md rev 6 §2: "STAKE/DELEGATE istemci kodlayıcısı
 * generation'a duyarlı olur"). The request names the rule-set generation
 * it builds for (`generation`; 0 — every caller before 6f-1, which
 * memsets the request — reads as "below the HF-6 generation"):
 *   below NODUS_RT_GEN_STORAGE: every path above, byte-identical;
 *   NODUS_RT_GEN_STORAGE and later (the HF-6 generation 4):
 *     STAKE  (op 1)  owner_fp[64] ‖ consensus_pk[2592] ‖ consent_sig[4627]
 *                    ‖ consent_expiry u64 ‖ commission u16 ‖ bond u64
 *                    = 7301 bytes (rtn_stake2_parse); lock = bond
 *     ROTATE (op 10) validator_id[64] ‖ new_pk[2592] ‖ consent_sig[4627]
 *                    ‖ consent_expiry u64 = 7291 bytes (rtn_rotate2_parse);
 *                    fee-only funding (khan decision A4, rtn_sys_call_flow)
 *     STORAGE_REGISTER (op 7, HF-6 slice 6b — design rev 6 §11.3)
 *                    owner_fp[64] ‖ node_pk[2592] ‖ consent_sig[4627]
 *                    ‖ consent_expiry u64 ‖ bond u64 = 7299 bytes
 *                    (rtn_streg2_parse); lock = bond. `consensus_pk` is
 *                    the NODE key, `consent_sig` its op-3 consent
 *     STORAGE_EXIT     (op 8, design rev 6 §11.5) node_fp[64] = 64 bytes
 *                    (rtn_stexit2_parse; `node_fp`); fee-only funding.
 *                    The chain checks the signer against the ROW's owner
 *     The OWNER is the signer of both legs (kind 1: owner_fp = SHA3-512 of
 *     the signing key — rtn_sys_owner_auth) and owns the funding coins; the
 *     node's consent (signature + expiry) is an INPUT, produced by the
 *     node's key elsewhere (nodus-cli `validator consent`).
 *   HF-6 slice 7b — ops 2-5 at generation 4 (design rev 6 §2, K7; the
 *   chain's rtn_deleg_parse_v2 / rtn_unstake_parse_v2 / rtn_vupd_parse_v2,
 *   flow rtn_sys_call_flow's generation-4 arms):
 *     DELEGATE   (op 2) delegator_fp[64] ‖ validator_id[64] ‖ amount u64
 *                       = 136 bytes; lock = amount
 *     UNDELEGATE (op 4) the same 136 bytes; fee-only funding, the chain
 *                       releases `amount` to delegator_fp
 *                       (rtn_sysfund_release_coin, generation-4 arm)
 *     UNSTAKE    (op 3) validator_id[64] = 64 bytes; fee-only
 *     VALIDATOR_UPDATE (op 5) validator_id[64] ‖ commission u16 = 66
 *                       bytes; fee-only. Op 5 exists in this module ONLY
 *                       at generation 4: its legacy 2594-byte layout was
 *                       never built here, so below generation 4 it is
 *                       refused (ERR_GEN).
 *     delegator_fp = SHA3-512 of the signing key (kind 1: the delegator IS
 *     the signer — rtn_delegate2_exec / rtn_undelegate2_exec bind the
 *     call's delegator_fp to the verdict); UNSTAKE and VALIDATOR_UPDATE are
 *     authorized by the ROW's owner_fp (rtn_unstake2_exec / rtn_vupd2_exec),
 *     which the bytes do not carry — the chain decides. Below generation 4
 *     ops 2-4 keep the legacy pubkey layouts above, byte-identical. A
 *     kind-3 (multisig) owner or delegator: see "KIND-3 OWNER" below.
 *     The storage ops exist ONLY at generation 4 (the chain owns
 *     them nowhere else) and have no other layout: below it they are
 *     refused (ERR_GEN). The builder refuses for STORAGE_REGISTER only
 *     what the call bytes decide — a bond outside [1, INT64_MAX]
 *     (ERR_STORAGE_BOND); the EXACT value is chain state (the STORAGE_BOND
 *     in force, rtn_storage_bond_at), checked by the chain.
 *   KIND-3 OWNER (decision docs/plans/decisions/2026-09-29-general-
 *   multisig.md, addendum "çok bacaklı ortak imza dosyası v2", 2026-10-13;
 *   design rev 6 §1.3): every generation-4 layout above may be owned by an
 *   M-of-N multisig address. The request then carries the DESCRIPTOR
 *   (req->msig_desc) and the final signer count K (req->msig_signers); the
 *   owner / delegator / change owner is the address SHA3-512(descriptor)
 *   (shared/dnac/msig_wire.h — computed here with qgp_sha3_512, the
 *   descriptor codec is NOT linked: the web wallet's native vector
 *   compiles this file without it), both legs carry auth_kind 3 =
 *   K zero signer slots ‖ dcount 1 ‖ dlen u16 BE ‖ descriptor (the chain's
 *   rtn_auth_msig layout, the nodus_v2_msig_unsigned_auth shape), and the
 *   envelope is returned UNSIGNED with its two leg auth digests
 *   (nodus_v2_stake_built_t.leg_digest): the co-signers sign them through
 *   the v2 export / signature files of nodus_v2_msig.h. The chain's rule
 *   (rtn_sys_owner_auth kind 3): one descriptor, >= M of its keys signed,
 *   no foreign signer, its address == the owner; the funding coins are the
 *   address's (rtn_input_owned). Legacy layouts have no kind-3 form
 *   (ERR_GEN).
 *   This module never calls the consent codec (shared/dnac/valbind_wire.c):
 *   the web wallet's WASM module and native vector compile this file
 *   without it. Signing, verifying and the validator_id derivation are the
 *   caller's (nodus-cli links the codec); only its WIDTHS are used here.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef NODUS_V2_STAKE_H
#define NODUS_V2_STAKE_H

#include <stdint.h>
#include <stddef.h>

#include "nodus/nodus_v2_spend.h"   /* rc values, widths, sign_one_key */
#include "dnac/valbind_wire.h"      /* HF-6 consent WIDTHS only — no call */
#include "dnac/msig_wire.h"         /* kind-3 descriptor WIDTHS only — no
                                     * call (see "KIND-3 OWNER")          */

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
 *  RTN_SYS_UNSTAKE_CALL_LEN). */
#define NODUS_V2_STAKE_CALL_LEN           2666u
#define NODUS_V2_DELEG_CALL_LEN           5192u
#define NODUS_V2_UNSTAKE_CALL_LEN         2592u
/** HF-6 generation-4 call lengths (design rev 6 §2, K7; Kurultay #16 —
 *  RTN_SYS_STAKE_V2_CALL_LEN / RTN_SYS_ROTATE_V2_CALL_LEN /
 *  RTN_SYS_STREG2_CALL_LEN / RTN_SYS_STEXIT2_CALL_LEN). */
#define NODUS_V2_STAKE2_CALL_LEN          7301u
#define NODUS_V2_ROTATE_CALL_LEN          7291u
#define NODUS_V2_STREG_CALL_LEN           7299u
#define NODUS_V2_STEXIT_CALL_LEN          64u
/** HF-6 slice 7b — the generation-4 calls of ops 2-5 (design rev 6 §2,
 *  K7; RTN_SYS_DELEGATE_V2_CALL_LEN / RTN_SYS_UNSTAKE_V2_CALL_LEN /
 *  RTN_SYS_VUPD_V2_CALL_LEN). */
#define NODUS_V2_DELEG2_CALL_LEN          136u
#define NODUS_V2_UNSTAKE2_CALL_LEN        64u
#define NODUS_V2_VUPD2_CALL_LEN           66u

/** Refusals of this module beyond the shared nodus_v2_spend_rc_t values it
 *  also returns (ERR_ARG, ERR_ALLOC, ERR_OVERFLOW, ERR_INPUT_SUM,
 *  ERR_INSUFFICIENT, ERR_GAS_OVERFLOW, ERR_HASH, ERR_ENCODE,
 *  ERR_PREFLIGHT1, ERR_SIGN, ERR_PREFLIGHT2, ERR_EXPIRY, ERR_DECODE). */
typedef enum {
    NODUS_V2_STAKE_ERR_BOND       = -40,  /* STAKE bond != the self-bond   */
    NODUS_V2_STAKE_ERR_COMMISSION = -41,  /* > DNAC_COMMISSION_BPS_MAX     */
    NODUS_V2_STAKE_ERR_AMOUNT     = -42,  /* outside 1..total supply       */
    NODUS_V2_STAKE_ERR_OP         = -43,  /* not STAKE/DELEGATE/UNSTAKE/
                                           * UNDELEGATE/VALIDATOR_UPDATE/
                                           * STORAGE_REGISTER/
                                           * STORAGE_EXIT/ROTATE          */
    NODUS_V2_STAKE_ERR_STORAGE_BOND = -44,  /* STORAGE_REGISTER bond
                                             * outside [1, INT64_MAX] (the
                                             * exact STORAGE_BOND is the
                                             * chain's)                   */
    /* -45 was NODUS_V2_STAKE_ERR_PAYEE (the storage-reward-v1 "payee ==
     * node fp" rule), retired by HF-6 slice 6b: the value is not reused */
    NODUS_V2_STAKE_ERR_GEN        = -46   /* the op has no layout this
                                           * module builds at the request's
                                           * generation: ROTATE,
                                           * VALIDATOR_UPDATE and the
                                           * storage ops below the HF-6
                                           * generation (HF-6 slice 7b:
                                           * DELEGATE / UNSTAKE /
                                           * UNDELEGATE are built at it)  */
} nodus_v2_stake_rc_t;

/** Which SYSTEM record leg — the value IS the runtime_op on the wire
 *  (nodus_witness_runtime.h DNA_SYSRULE_*). */
typedef enum {
    NODUS_V2_STAKE_OP_STAKE            = 1,
    NODUS_V2_STAKE_OP_DELEGATE         = 2,
    NODUS_V2_STAKE_OP_UNSTAKE          = 3,
    NODUS_V2_STAKE_OP_UNDELEGATE       = 4,
    NODUS_V2_STAKE_OP_VALIDATOR_UPDATE = 5,  /* HF-6 generation 4 only
                                              * (slice 7b)              */
    NODUS_V2_STAKE_OP_STORAGE_REGISTER = 7,
    NODUS_V2_STAKE_OP_STORAGE_EXIT     = 8,
    NODUS_V2_STAKE_OP_ROTATE           = 10  /* HF-6 generation 4 only */
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
                                      * the retiring validator; at
                                      * generation 4 the OWNER), the signer
                                      * of both legs and the owner of every
                                      * funding coin                        */
    const uint8_t *sk;               /* 4896 B                              */
    uint64_t       amount;           /* STAKE / STORAGE_REGISTER: the bond;
                                      * DELEGATE / UNDELEGATE: the amount;
                                      * UNSTAKE / STORAGE_EXIT / ROTATE /
                                      * VALIDATOR_UPDATE: ignored           */
    uint32_t       commission_bps;   /* STAKE; VALIDATOR_UPDATE (gen 4):
                                      * the new commission                  */
    const uint8_t *dest_fp;          /* legacy STAKE: the unstake
                                      * destination; 64 raw B               */
    const uint8_t *validator_pk;     /* DELEGATE / UNDELEGATE below gen 4:
                                      * 2592 B (unused at gen 4)            */
    uint64_t       gas_price;        /* 0 = rule off (the flat floor)       */
    const nodus_v2_stake_coin_t *coins;
    int            n_coins;
    /* ── HF-6 6f-1 (zero in every older caller) ─────────────────────── */
    uint32_t       generation;       /* the rule-set generation `rs` is;
                                      * >= NODUS_RT_GEN_STORAGE selects the
                                      * generation-4 STAKE / ROTATE layouts
                                      * and admits the storage ops          */
    const uint8_t *consensus_pk;     /* gen-4 STAKE: the node's consensus
                                      * key; ROTATE: the NEW key;
                                      * STORAGE_REGISTER: the storage NODE
                                      * key (2592 B)                        */
    const uint8_t *consent_sig;      /* gen-4 STAKE / ROTATE /
                                      * STORAGE_REGISTER: the node's
                                      * consent, DNA_VALBIND_SIG_LEN B      */
    uint64_t       consent_expiry;   /* gen-4 STAKE / ROTATE /
                                      * STORAGE_REGISTER                    */
    const uint8_t *validator_id;     /* ROTATE; HF-6 slice 7b, gen 4:
                                      * DELEGATE / UNDELEGATE (the target)
                                      * and UNSTAKE / VALIDATOR_UPDATE (the
                                      * validator) — 64 B, never all zero   */
    /* ── HF-6 slice 6b (zero in every older caller) ─────────────────── */
    const uint8_t *node_fp;          /* STORAGE_EXIT: the registry key
                                      * SHA3-512(node_pk) (64 raw B)        */
    /* ── HF-6 kind-3 owner (zero in every older caller — "KIND-3 OWNER"
     *    above) ──────────────────────────────────────────────────────── */
    const uint8_t *msig_desc;        /* non-NULL: the owner / delegator is
                                      * the multisig address SHA3-512(this
                                      * descriptor); `pk` / `sk` are then
                                      * unused (may be NULL) and the
                                      * envelope is built UNSIGNED          */
    size_t         msig_desc_len;    /* DNA_MSIG_DESC_LEN(N), 2 <= N <= 7    */
    uint32_t       msig_signers;     /* K, M <= K <= N: the FINAL signer
                                      * count (auth_len is signed, so K is
                                      * fixed here)                         */
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
                                          * retiring validator (UNSTAKE);
                                          * generation 4: the owner (the
                                          * one signer)                     */
    uint8_t  validator_pk[2592];         /* legacy DELEGATE / UNDELEGATE;
                                          * zero for every other layout     */
    uint64_t amount;                     /* bond / amount; 0 for UNSTAKE,
                                          * ROTATE, STORAGE_EXIT and
                                          * VALIDATOR_UPDATE                */
    uint32_t commission_bps;             /* STAKE; VALIDATOR_UPDATE         */
    uint8_t  dest_fp[64];                /* legacy STAKE: unstake
                                          * destination                     */
    int      n_in;
    uint8_t  in_nul[NODUS_V2_SPEND_MAX_IN][64];
    int      n_out;                      /* 0 or 1                          */
    char     change_owner[129];
    uint64_t change_amount;
    uint8_t  change_id[64];              /* SHA3-512(owner ‖ seed)          */
    /* ── HF-6 6f-1 / 6b / 7b: the generation-4 STAKE (7301 B) / ROTATE
     *    (7291 B) / STORAGE_REGISTER (7299 B) / STORAGE_EXIT (64 B) /
     *    DELEGATE and UNDELEGATE (136 B) / UNSTAKE (64 B) /
     *    VALIDATOR_UPDATE (66 B) — all zero for every other layout.
     *    identity_pk above is then the single signer of both legs (the
     *    owner / delegator), read from the auth blob: those calls carry no
     *    key. ────────────────────────────────────────────────────────── */
    int      gen4;                       /* 1 = a generation-4 layout       */
    uint8_t  owner_fp[64];               /* STAKE / STORAGE_REGISTER: the
                                          * call's owner_fp; DELEGATE /
                                          * UNDELEGATE: the call's
                                          * delegator_fp (both ==
                                          * SHA3-512(identity_pk), checked);
                                          * ROTATE / STORAGE_EXIT / UNSTAKE /
                                          * VALIDATOR_UPDATE:
                                          * SHA3-512(identity_pk)           */
    uint8_t  consensus_pk[2592];         /* STAKE: consensus_pk; ROTATE:
                                          * new_pk; STORAGE_REGISTER:
                                          * node_pk                         */
    uint8_t  consent_sig[DNA_VALBIND_SIG_LEN];
    uint64_t consent_expiry;
    uint8_t  validator_id[64];           /* ROTATE; gen-4 DELEGATE /
                                          * UNDELEGATE / UNSTAKE /
                                          * VALIDATOR_UPDATE                */
    uint8_t  node_fp[64];                /* STORAGE_REGISTER: SHA3-512(
                                          * node_pk); STORAGE_EXIT: the
                                          * call                            */
    /* ── HF-6 kind-3 owner ("KIND-3 OWNER" above) ───────────────────── */
    uint8_t  auth_kind;                  /* 1 (NODUS_RT_AUTHKIND_DSA87_
                                          * MULTI_V1) or 3 (_MSIG_V1); the
                                          * same on both legs               */
    uint32_t msig_signers;               /* kind 3: K (slots per leg)       */
    uint8_t  msig_m, msig_n;             /* kind 3: the descriptor header's
                                          * M and N (its full validation —
                                          * tag, key order — is the msig
                                          * library's / the chain's)        */
    uint8_t  msig_addr[64];              /* kind 3: SHA3-512(descriptor) —
                                          * then also owner_fp; identity_pk
                                          * is all zero (no single signer)  */
} nodus_v2_stake_decoded_t;

typedef struct {
    uint8_t                 *env;        /* heap; nodus_v2_stake_built_free */
    size_t                   env_len;
    uint8_t                  wire_id[64];/* kind 3: all zero — the unsigned
                                          * envelope has no final wire_id
                                          * (msig combine prints it)        */
    uint8_t                  intent_id[64];
    uint64_t                 fee, sum_in, change;
    int                      n_in;
    nodus_v2_stake_decoded_t dec;        /* read back from `env`           */
    /* ── HF-6 kind-3 owner ──────────────────────────────────────────── */
    uint8_t                  auth_kind;  /* 1 = signed (kind 1); 3 = the
                                          * UNSIGNED kind-3 envelope        */
    uint8_t                  leg_digest[2][64]; /* kind 3: the pass-1 leg
                                          * auth digests of leg 0 (SYSTEM)
                                          * and leg 1 (CORE SYSFUND) — what
                                          * every co-signer signs           */
} nodus_v2_stake_built_t;

/**
 * Build, sign and self-check ONE two-leg staking envelope, then decode it
 * back and refuse if any decoded field differs from the request.
 *   fee    = max(DNAC_MIN_FEE_RAW, NODUS_W_BASE_TX_FEE), raised to
 *            NODUS_V2_STAKE_UNITS × gas_price when that is larger;
 *   need   = lock + fee (lock = amount for STAKE / DELEGATE /
 *            STORAGE_REGISTER, 0 for UNSTAKE / UNDELEGATE / STORAGE_EXIT /
 *            ROTATE / VALIDATOR_UPDATE);
 *   gen-4 DELEGATE / UNDELEGATE / UNSTAKE / VALIDATOR_UPDATE (HF-6 slice
 *            7b): validator_id present and not all zero (ERR_ARG — no
 *            legal validator_id is, rtn_val2_rec_ok / rtn_vupd_parse_v2);
 *            DELEGATE / UNDELEGATE 1 <= amount <= total supply
 *            (ERR_AMOUNT); VALIDATOR_UPDATE commission <=
 *            DNAC_COMMISSION_BPS_MAX (ERR_COMMISSION, rtn_vupd_parse_v2);
 *            the funding of a gen-4 DELEGATE takes up to
 *            NODUS_V2_SPEND_MAX_IN inputs (the CORE leg is never name-gated
 *            at generation 4 — rtn_sysfund_name_gate, decision D3);
 *   gen-4 STAKE / ROTATE (generation >= NODUS_RT_GEN_STORAGE): owner_fp =
 *            SHA3-512(pk); the builder refuses only what the call bytes
 *            decide — STAKE: commission <= DNAC_COMMISSION_BPS_MAX, 1 <=
 *            bond <= INT64_MAX (ERR_BOND; STAKE_MIN is the chain's —
 *            chain_config param 19, dnac_fee_info "stake_min"); ROTATE:
 *            a non-zero
 *            validator_id; STAKE / ROTATE / STORAGE_REGISTER: consensus_pk
 *            and consent_sig present; STORAGE_REGISTER: 1 <= bond <=
 *            INT64_MAX (ERR_STORAGE_BOND; the exact STORAGE_BOND is the
 *            chain's); STORAGE_EXIT: node_fp present. It does NOT verify
 *            the consent nor its expiry window (the codec is not linked
 *            here — the caller does both);
 *   inputs = eligible coins ascending by nullifier, taken until their sum
 *            covers `need`, at most NODUS_V2_SPEND_MAX_IN;
 *   change = sum − need, one native output to the signer when > 0.
 * KIND-3 OWNER (req->msig_desc non-NULL): only the generation-4 layouts
 * (else ERR_GEN); the descriptor's length must be DNA_MSIG_DESC_LEN(N)
 * with 2 <= N <= DNA_MSIG_MAX_N and 1 <= M <= N read from its header, and
 * M <= K <= N (else ERR_ARG — the tag and the key order are not checked
 * here: the chain refuses a malformed descriptor, and nodus_v2_msig_
 * review2 checks it before anyone signs); the owner, the delegator and the
 * change owner are SHA3-512(descriptor); both legs are auth_kind 3 with K
 * zero slots; NOTHING is signed: the envelope is encoded, preflighted once
 * (pass 1) and returned with out->leg_digest[0..1] = its leg auth digests,
 * out->auth_kind = 3 and out->wire_id all zero.
 * @return NODUS_V2_SPEND_OK or a refusal (`err` may be NULL).
 */
int nodus_v2_stake_build(const nodus_v2_stake_req_t *req,
                         nodus_v2_stake_built_t *out,
                         nodus_v2_stake_err_t *err);

/** Decode a two-leg staking envelope built by this module. Refuses any
 *  other shape (leg count, domains, ops, access modes, auth kind / length,
 *  effect declarations, call lengths, input order, change owner hex, a
 *  non-native or zero change, an auth blob not carrying exactly one signer
 *  whose key is the record identity). HF-6 6f-1 / 6b: op 1 with a
 *  7301-byte call, op 10 (7291 bytes), op 7 (7299 bytes) and op 8 (64
 *  bytes) are the generation-4 layouts; their record identity is the one
 *  signer of both legs, and a STAKE or STORAGE_REGISTER whose owner_fp is
 *  not SHA3-512 of that signer is refused (kind 1: the owner IS the
 *  signer; kind 3 below). HF-6 slice 7b: ops 2 / 4
 *  with a 136-byte call, op 3 with a 64-byte call and op 5 (66 bytes — the
 *  only op-5 layout this module reads) are the generation-4 layouts; a
 *  DELEGATE / UNDELEGATE whose delegator_fp is not SHA3-512 of the signer
 *  is refused, an all-zero validator_id or a VALIDATOR_UPDATE commission
 *  above DNAC_COMMISSION_BPS_MAX too (the chain's decoder rules).
 *  KIND-3 OWNER: both legs auth_kind 3, a generation-4 layout only; each
 *  blob is K slots (1 <= K <= NODUS_RT_AUTH_MAX_SIGNERS) ‖ dcount 1 ‖ dlen
 *  ‖ ONE descriptor of exactly DNA_MSIG_DESC_LEN(N) bytes (2 <= N <=
 *  DNA_MSIG_MAX_N, 1 <= M <= K <= N from its header); the two legs carry
 *  the same K, the same descriptor bytes and the same public key in every
 *  slot (the signature bytes differ per leg; all-zero slots — the
 *  unsigned export — are accepted). The record identity is the address
 *  SHA3-512(descriptor): a STAKE / STORAGE_REGISTER owner_fp or a DELEGATE /
 *  UNDELEGATE delegator_fp that is not it is refused.
 *  @return NODUS_V2_SPEND_OK / _ERR_ARG / _ERR_ALLOC / _ERR_DECODE /
 *  _ERR_HASH. */
int nodus_v2_stake_decode(const uint8_t *env, size_t env_len,
                          nodus_v2_stake_decoded_t *out);

/** Free what nodus_v2_stake_build allocated inside `b`. NULL-safe. */
void nodus_v2_stake_built_free(nodus_v2_stake_built_t *b);

/* ── HF-6 6f-1: the node-consent CONTAINER ──────────────────────────────
 * How a node's consent travels from the node's machine (nodus-cli
 * `validator consent`, which builds the §6.1 message and signs it through
 * shared/dnac/valbind_wire.c) to the owner's (`v2-envelope stake2 |
 * rotate`). A local text file, NOT a wire format and not signed: every
 * field is re-checked by the reader, which rebuilds the message with the
 * codec and verifies the signature before building. Exactly these lines,
 * in this order, each ending in '\n', lowercase hex, nothing else:
 *   nodus-valbind-consent v1
 *   op <1 | 2 | 3>                   DNA_VALBIND_OP_STAKE / _ROTATE /
 *                                    _STORAGE_REGISTER (HF-6 6b)
 *   chain_id <64 hex>                the v2 chain id (32 B)
 *   subject <128 hex>                STAKE / STORAGE_REGISTER: 64 × 00;
 *                                    ROTATE: validator_id
 *   owner <128 hex>                  owner_fp
 *   consensus_pk <5184 hex>          the consenting key (STORAGE_REGISTER:
 *                                    the storage node key)
 *   expiry <decimal u64>
 *   sig <9254 hex>                   DNA_VALBIND_SIG_LEN bytes
 * The parser also applies the op/subject rule of the codec (STAKE and
 * STORAGE_REGISTER zero, ROTATE non-zero) so a container that can never
 * verify is refused early; it does not verify the signature (that is the
 * codec's, at the reader). */
#define NODUS_V2_CONSENT_MAGIC  "nodus-valbind-consent v1"

typedef struct {
    uint8_t  op;                    /* 1 STAKE / 2 ROTATE / 3 STORAGE_REG */
    uint8_t  chain32[DNA_VALBIND_CHAIN_LEN];
    uint8_t  subject[DNA_VALBIND_SUBJECT_LEN];
    uint8_t  owner_fp[DNA_VALBIND_OWNER_FP_LEN];
    uint8_t  consensus_pk[DNA_VALBIND_PUBKEY_LEN];
    uint64_t expiry;
    uint8_t  sig[DNA_VALBIND_SIG_LEN];
} nodus_v2_consent_t;

/** Encode `c` (format above). *text_out is heap, NUL-terminated, *len_out
 *  excludes the NUL. Refuses an op outside {1, 2, 3} or a subject breaking
 *  the op rule. @return NODUS_V2_SPEND_OK / _ERR_ARG / _ERR_ALLOC. */
int nodus_v2_consent_text_encode(const nodus_v2_consent_t *c,
                                 char **text_out, size_t *len_out);

/** Parse exactly the format above from `len` bytes (need not be
 *  NUL-terminated). @return NODUS_V2_SPEND_OK / _ERR_ARG (NULL) /
 *  _ERR_DECODE (anything else: magic, a missing / reordered / extra line,
 *  a wrong hex width, an uppercase or non-hex digit, a non-decimal or
 *  overflowing expiry, an op outside {1, 2, 3}, the op/subject rule). On a
 *  refusal `c` is zeroed. */
int nodus_v2_consent_text_parse(const char *text, size_t len,
                                nodus_v2_consent_t *c);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_V2_STAKE_H */
