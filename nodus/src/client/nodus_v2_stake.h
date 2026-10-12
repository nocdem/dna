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
 *     node's key elsewhere (nodus-cli `validator consent`). DELEGATE,
 *     UNSTAKE and UNDELEGATE have generation-4 layouts (136 / 64 / 136
 *     bytes) this module does not build yet: refused (ERR_GEN), never
 *     emitted in the legacy layout the generation-4 chain refuses by
 *     length. The storage ops exist ONLY at generation 4 (the chain owns
 *     them nowhere else) and have no other layout: below it they are
 *     refused (ERR_GEN). The builder refuses for STORAGE_REGISTER only
 *     what the call bytes decide — a bond outside [1, INT64_MAX]
 *     (ERR_STORAGE_BOND); the EXACT value is chain state (the STORAGE_BOND
 *     in force, rtn_storage_bond_at), checked by the chain.
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
    NODUS_V2_STAKE_ERR_STORAGE_BOND = -44,  /* STORAGE_REGISTER bond
                                             * outside [1, INT64_MAX] (the
                                             * exact STORAGE_BOND is the
                                             * chain's)                   */
    /* -45 was NODUS_V2_STAKE_ERR_PAYEE (the storage-reward-v1 "payee ==
     * node fp" rule), retired by HF-6 slice 6b: the value is not reused */
    NODUS_V2_STAKE_ERR_GEN        = -46   /* the op has no layout this
                                           * module builds at the request's
                                           * generation: ROTATE and the
                                           * storage ops below the HF-6
                                           * generation; DELEGATE /
                                           * UNSTAKE / UNDELEGATE at it   */
} nodus_v2_stake_rc_t;

/** Which SYSTEM record leg — the value IS the runtime_op on the wire
 *  (nodus_witness_runtime.h DNA_SYSRULE_*). */
typedef enum {
    NODUS_V2_STAKE_OP_STAKE            = 1,
    NODUS_V2_STAKE_OP_DELEGATE         = 2,
    NODUS_V2_STAKE_OP_UNSTAKE          = 3,
    NODUS_V2_STAKE_OP_UNDELEGATE       = 4,
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
                                      * UNSTAKE / STORAGE_EXIT / ROTATE:
                                      * ignored                             */
    uint32_t       commission_bps;   /* STAKE only                          */
    const uint8_t *dest_fp;          /* legacy STAKE: the unstake
                                      * destination; 64 raw B               */
    const uint8_t *validator_pk;     /* DELEGATE / UNDELEGATE: 2592 B       */
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
    const uint8_t *validator_id;     /* ROTATE: the validator (64 B)        */
    /* ── HF-6 slice 6b (zero in every older caller) ─────────────────── */
    const uint8_t *node_fp;          /* STORAGE_EXIT: the registry key
                                      * SHA3-512(node_pk) (64 raw B)        */
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
    uint8_t  validator_pk[2592];         /* DELEGATE / UNDELEGATE; zero
                                          * for every other op              */
    uint64_t amount;                     /* bond / amount; 0 for UNSTAKE,
                                          * ROTATE and STORAGE_EXIT         */
    uint32_t commission_bps;             /* STAKE                           */
    uint8_t  dest_fp[64];                /* legacy STAKE: unstake
                                          * destination                     */
    int      n_in;
    uint8_t  in_nul[NODUS_V2_SPEND_MAX_IN][64];
    int      n_out;                      /* 0 or 1                          */
    char     change_owner[129];
    uint64_t change_amount;
    uint8_t  change_id[64];              /* SHA3-512(owner ‖ seed)          */
    /* ── HF-6 6f-1 / 6b: the generation-4 STAKE (7301 B) / ROTATE (7291
     *    B) / STORAGE_REGISTER (7299 B) / STORAGE_EXIT (64 B) — all zero
     *    for every other layout. identity_pk above is then the single
     *    signer of both legs (the owner), read from the auth blob: those
     *    calls carry no owner key. ───────────────────────────────────── */
    int      gen4;                       /* 1 = a generation-4 layout       */
    uint8_t  owner_fp[64];               /* STAKE / STORAGE_REGISTER: the
                                          * call's owner_fp (==
                                          * SHA3-512(identity_pk), checked);
                                          * ROTATE / STORAGE_EXIT:
                                          * SHA3-512(identity_pk)           */
    uint8_t  consensus_pk[2592];         /* STAKE: consensus_pk; ROTATE:
                                          * new_pk; STORAGE_REGISTER:
                                          * node_pk                         */
    uint8_t  consent_sig[DNA_VALBIND_SIG_LEN];
    uint64_t consent_expiry;
    uint8_t  validator_id[64];           /* ROTATE                          */
    uint8_t  node_fp[64];                /* STORAGE_REGISTER: SHA3-512(
                                          * node_pk); STORAGE_EXIT: the
                                          * call                            */
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
 *            STORAGE_REGISTER, 0 for UNSTAKE / UNDELEGATE / STORAGE_EXIT /
 *            ROTATE);
 *   gen-4 STAKE / ROTATE (generation >= NODUS_RT_GEN_STORAGE): owner_fp =
 *            SHA3-512(pk); the builder refuses only what the call bytes
 *            decide — STAKE: commission <= DNAC_COMMISSION_BPS_MAX, 1 <=
 *            bond <= INT64_MAX (ERR_BOND; STAKE_MIN is the chain's — a
 *            chain_config value from slice 8); ROTATE: a non-zero
 *            validator_id; STAKE / ROTATE / STORAGE_REGISTER: consensus_pk
 *            and consent_sig present; STORAGE_REGISTER: 1 <= bond <=
 *            INT64_MAX (ERR_STORAGE_BOND; the exact STORAGE_BOND is the
 *            chain's); STORAGE_EXIT: node_fp present. It does NOT verify
 *            the consent nor its expiry window (the codec is not linked
 *            here — the caller does both);
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
 *  whose key is the record identity). HF-6 6f-1 / 6b: op 1 with a
 *  7301-byte call, op 10 (7291 bytes), op 7 (7299 bytes) and op 8 (64
 *  bytes) are the generation-4 layouts; their record identity is the one
 *  signer of both legs, and a STAKE or STORAGE_REGISTER whose owner_fp is
 *  not SHA3-512 of that signer is refused (kind 1: the owner IS the
 *  signer — the only shape this module builds).
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
