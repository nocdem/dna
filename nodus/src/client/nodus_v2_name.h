/**
 * @file nodus/src/client/nodus_v2_name.h
 * @brief The shared CORE NAME_REGISTER envelope builder (HF-4 on-chain
 *        names) — normalise, price, build + read back, no I/O.
 *
 * Governing records: docs/plans/decisions/2026-10-02-onchain-names.md
 * (items 2-6, 10, 11, 16: first come wins, one name per ID, permanent;
 * 3-36 of a-z0-9, an all-hex name of 8+ characters is never a name; the
 * price by length is the chain's — read from the node's dnac_fee_info, never
 * compiled into a client) with design docs/plans/2026-10-02-onchain-names-
 * design.md rev 4 §2, and docs/plans/decisions/2026-09-25-web-wallet-nodus-
 * send-transport.md ("İşlem kurucu": the wallet builds with the SAME C code
 * nodus-cli uses — applied here to the name registration as it was to the
 * SPEND and the staking envelopes).
 *
 * WHAT IT IS: the body of nodus-cli `name register` (cmd_name_register),
 * moved out unchanged in behaviour: the coin filter (zero / non-native /
 * locked at tip + 1 skipped), largest-first selection (nodus_v2_spend_
 * sort_coins + nodus_v2_spend_pick) capped at NODUS_V2_NAME_MAX_IN inputs,
 * the call layout, the exact effect declaration, the units ceiling
 * (nodus_v2_spend_ceiling, reads = inputs + pool + NAME + OWNER), the
 * gas-price fixed point (at most 8 passes) and the one-key two-pass
 * signature. Pure functions over caller-supplied inputs — the listed coins,
 * the committed tip, the expiry, the gas price, the price, the chain id, the
 * ruleset identity and the signing key. It opens no socket, reads no clock,
 * touches no database and calls no global RNG: the change output's seed
 * comes from the caller's `rand` callback (32 bytes per pass that writes a
 * change output — exactly where cmd_name_register drew nodus_random).
 * qgp_dsa87_sign is HEDGED (nodus_v2_spend.h), so two builds from identical
 * inputs differ in their signature bytes and wire_id only.
 *
 * WHAT THE BUILDER DECIDES vs WHAT THE CHAIN DECIDES: the builder refuses a
 * name outside dnac_name_bytes_ok, a zero price, a fixed fee below the
 * floor or below units × gas price, and funding it cannot cover from at
 * most NODUS_V2_NAME_MAX_IN eligible coins. "Taken", "this ID already
 * holds a name", the price in force at the block height and the generation
 * the node runs need committed state: the CALLER asks the node first
 * (nodus-cli cmd_name_register, web wallet nsw_name_build) and the chain
 * decides again at CheckTx / FinalizeBlock (nodus_witness_rt_native.c op 8).
 *
 * THE CHAIN IS THE SPECIFICATION (nodus_witness_rt_native.c, CORE op 8
 * DNA_CORERULE_NAME_REGISTER, generation 2 only, one CORE leg):
 *   call = name_len u8 ‖ name ‖ price u64 BE ‖ in_count u8 ‖ nullifiers
 *          (strictly ascending) ‖ out_count u8 ‖ out_count × 232-byte
 *          native output records (this builder: 0 or 1, the change)
 * Owner: auth_kind 1 with one signer (nodus_v2_name_build), or — from the
 * HF-8 activation height — auth_kind 3, a satisfied vault whose address
 * becomes the owner and whose own coins alone pay (nodus_v2_name_msig_
 * build below; rt_native.c rtn_name_owner_of / rtn_name_exec).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef NODUS_V2_NAME_H
#define NODUS_V2_NAME_H

#include <stdint.h>
#include <stddef.h>

#include "nodus/nodus_v2_spend.h"   /* rc values, ruleset id, rand fn     */
#include "dnac/dnac.h"              /* DNAC_NAME_MAX_LEN, the byte rule    */
#include "client/nodus_v2_msig.h"   /* HF-8: the vault flow's export type,
                                     * rc values and leg / digest helpers  */

#ifdef __cplusplus
extern "C" {
#endif

/** The NAME_REGISTER call's input ceiling (rt_native.c RTN_NAME_MAX_IN:
 *  the 16-read budget minus the pool, NAME and OWNER reads). */
#define NODUS_V2_NAME_MAX_IN    13u
/** The outputs THIS builder emits: the native change only. */
#define NODUS_V2_NAME_MAX_OUTS  1u
/** The largest call this builder writes. */
#define NODUS_V2_NAME_CALL_MAX  (1u + DNAC_NAME_MAX_LEN + 8u + 1u + \
                                 NODUS_V2_NAME_MAX_IN * 64u + 1u + \
                                 NODUS_V2_NAME_MAX_OUTS * NODUS_V2_SPEND_OUT_LEN)
/** The fee-fixed-point pass limit cmd_name_register had (pass >= 7). */
#define NODUS_V2_NAME_MAX_PASSES 8

/** Refusals of this module beyond the shared nodus_v2_spend_rc_t values it
 *  also returns (ERR_ARG, ERR_ALLOC, ERR_OVERFLOW, ERR_MAX_INPUTS,
 *  ERR_INPUT_SUM, ERR_INSUFFICIENT, ERR_METER, ERR_GAS_OVERFLOW,
 *  ERR_FEE_BELOW_GAS, ERR_FEE_UNSETTLED, ERR_RANDOM, ERR_HASH, ERR_ENCODE,
 *  ERR_PREFLIGHT1, ERR_SIGN, ERR_PREFLIGHT2, ERR_EXPIRY, ERR_DECODE). */
typedef enum {
    NODUS_V2_NAME_ERR_NAME      = -50,  /* outside dnac_name_bytes_ok     */
    NODUS_V2_NAME_ERR_PRICE     = -51,  /* price 0                        */
    NODUS_V2_NAME_ERR_FEE_FLOOR = -52   /* a fixed fee below the floor    */
} nodus_v2_name_rc_t;

/** What a person typed -> the chain name it denotes: ASCII-only
 *  lower-casing (A-Z -> a-z; a locale tolower maps 'I' to 'ı' under tr_TR,
 *  design §2), then the consensus byte rule dnac_name_bytes_ok.
 *  @return 0 (`out` = the name, NUL-terminated) / -1 (not a name). */
int nodus_v2_name_normalize(const char *in, char out[DNAC_NAME_MAX_LEN + 1]);

/** The price of a name of `name_len` bytes from the node's tier list
 *  (nodus_dnac_name_prices_t.price: 3, 4, 5, 6+ characters).
 *  @return 0 (*out set) / -1 (`name_len` outside 3..DNAC_NAME_MAX_LEN). */
int nodus_v2_name_price_for(const uint64_t price[4], size_t name_len,
                            uint64_t *out);

/** The EXACT (res_max_effects, res_max_effect_bytes) of one CORE
 *  NAME_REGISTER leg — rtn_name_exec's effect list: n_out UTXO CREATEs
 *  (key 64, value 284), ONE NAME CREATE (key name_len, value 72), ONE pool
 *  SET (key 1, value 8), n_in DELETEs (key 64, value 0):
 *    effects = n_in + n_out + 2
 *    bytes   = 23 + 84·effects + n_out·(64 + 284) + (name_len + 72)
 *              + (1 + 8) + n_in·64 */
void nodus_v2_name_effect_decl(uint32_t n_in, uint32_t n_out,
                               uint32_t name_len, uint32_t *effects_out,
                               uint32_t *bytes_out);

/** One coin as the node lists it (dnac_utxo row). The builder itself skips
 *  a zero amount, a non-native token and a coin still locked at tip + 1
 *  (unlock_block > tip) — cmd_name_register's filter. */
typedef struct {
    uint8_t  nul[64];
    uint64_t amount;
    uint8_t  token[64];       /* all-zero = native */
    uint64_t unlock_block;
} nodus_v2_name_coin_t;

typedef struct {
    const nodus_v2_ruleset_id_t *rs;  /* the CORE tuple of the generation
                                       * the node runs (>= 2) and that
                                       * generation's SYSTEM meter policy  */
    const uint8_t *chain32;           /* DNA_CHAIN_ID_LEN bytes            */
    uint64_t       tip;               /* committed tip (>= 1)              */
    uint64_t       expiry_height;     /* (tip, tip + NODUS_CMT_APP_MAX_
                                       * EXPIRY_AHEAD]                     */
    const uint8_t *pk;                /* ML-DSA-87 pk 2592 B: the OWNER of
                                       * the name, the signer and the owner
                                       * of every input                    */
    const uint8_t *sk;                /* 4896 B                            */
    const char    *name;              /* already normalised (lower-case,
                                       * dnac_name_bytes_ok)               */
    uint64_t       price;             /* the node's price for the length   */
    uint64_t       fee;               /* fee_fixed only: the fixed fee;
                                       * otherwise ignored — the build
                                       * starts at the floor max(DNAC_MIN_
                                       * FEE_RAW, NODUS_W_BASE_TX_FEE)     */
    int            fee_fixed;         /* 1 = never raised; refused when
                                       * below the floor or units × gas    */
    uint64_t       gas_price;         /* 0 = the rule is off               */
    const nodus_v2_name_coin_t *coins;
    int            n_coins;
    nodus_v2_rand_fn rand;            /* the change seed — never a global
                                       * RNG                               */
    void            *rand_ctx;
} nodus_v2_name_req_t;

/** Which numbers a refusal carries (for the caller's message). */
typedef struct {
    uint64_t fee;         /* the fee in force when it stopped              */
    uint64_t price;
    uint64_t floor;       /* the fee floor                                 */
    uint64_t units, gas_price, required;   /* required = units × gas_price */
    int      n_eligible;  /* coins that passed the filter                  */
    int      n_in;
    int      pass;
    int      leg;         /* signing: the failing leg                      */
} nodus_v2_name_err_t;

/** A NAME_REGISTER envelope read back from its bytes (self-consistent
 *  decode: this module's layout, checked against the chain's widths). */
typedef struct {
    char     name[DNAC_NAME_MAX_LEN + 1];
    uint64_t price;
    uint64_t expiry_height, fee, units;
    uint32_t core_ruleset_version;
    uint32_t effects, effect_bytes;      /* the leg's declaration          */
    uint8_t  owner_pk[2592];             /* the one signer                 */
    int      n_in;
    uint8_t  in_nul[NODUS_V2_NAME_MAX_IN][64];
    int      n_out;                      /* 0 or 1                         */
    char     change_owner[129];
    uint64_t change_amount;
    uint8_t  change_id[64];              /* SHA3-512(owner ‖ seed)         */
} nodus_v2_name_decoded_t;

typedef struct {
    uint8_t                *env;         /* heap; nodus_v2_name_built_free */
    size_t                  env_len;
    uint8_t                 wire_id[64];
    uint8_t                 intent_id[64];
    uint64_t                fee, price, sum_in, change, units;
    int                     n_in;
    int                     passes;      /* fee fixed-point passes used    */
    nodus_v2_name_decoded_t dec;         /* read back from `env`           */
} nodus_v2_name_built_t;

/**
 * Build, sign and self-check ONE single-leg CORE NAME_REGISTER envelope,
 * then decode it back and refuse if any decoded field differs from the
 * request. Per pass: inputs = eligible coins largest first (equal amounts
 * by nullifier), taken until they cover price + fee, at most
 * NODUS_V2_NAME_MAX_IN; change = sum − price − fee, one native output to
 * the signer when > 0 (its seed from `rand`); units = the ceiling of THIS
 * envelope; when gas_price > 0 and units × gas_price > fee the fee is
 * raised to it (refused instead when fee_fixed) and the pass repeats.
 * @return NODUS_V2_SPEND_OK or a refusal (`err` may be NULL).
 */
int nodus_v2_name_build(const nodus_v2_name_req_t *req,
                        nodus_v2_name_built_t *out,
                        nodus_v2_name_err_t *err);

/** Decode a single-leg NAME_REGISTER envelope built by this module. Refuses
 *  any other shape (leg count, domain, op, access mode, auth kind / length,
 *  an auth blob not carrying exactly one signer, call length, a name
 *  outside dnac_name_bytes_ok, a zero price, input count / order, more than
 *  one output, change owner hex, a non-native or zero change, an effect
 *  declaration other than nodus_v2_name_effect_decl's).
 *  @return NODUS_V2_SPEND_OK / _ERR_ARG / _ERR_ALLOC / _ERR_DECODE /
 *  _ERR_HASH. */
int nodus_v2_name_decode(const uint8_t *env, size_t env_len,
                         nodus_v2_name_decoded_t *out);

/** Free what nodus_v2_name_build allocated inside `b`. NULL-safe. */
void nodus_v2_name_built_free(nodus_v2_name_built_t *b);

/* ══ HF-8 — a NAME_REGISTER by a multisig vault ═════════════════════════
 * Decision docs/plans/decisions/2026-10-21-hf8-activation.md, amendment
 * 2026-10-21 (operator "ekle.": from the param-17 height a NAME_REGISTER
 * may be authorised by a satisfied M-of-N multisig, the name's owner = the
 * vault address; operator "Yalnız kasanın parası": the chain refuses it
 * unless EVERY input is owned by the vault). The chain side is
 * nodus_witness_rt_native.c rtn_name_owner_of / rtn_name_exec.
 *
 * The flow is the vault SPEND's v1 flow (client/nodus_v2_msig.h): this
 * builder writes the UNSIGNED single-leg envelope (auth_kind 3, K zero
 * signer slots, ONE descriptor — nodus_v2_msig_unsigned_auth) and returns
 * its pass-1 leg digest; the export / signature texts are the v1 formats
 * (nodus_v2_msig_export_encode / _sig_encode); each co-signer reads it
 * back with nodus_v2_name_msig_review (NOT nodus_v2_msig_review, whose
 * SPEND read-back would misread a name call) and checks every input
 * against the vault's coins on its own node, exactly as for a vault SPEND;
 * the combine is nodus_v2_msig_combine_op(…, DNA_CORERULE_NAME_REGISTER,
 * …). What the builder does not know: whether param 17 is in force at the
 * block height (the caller asks dnac_fee_info first; the chain decides),
 * whether the name or the vault is already named, the price in force. */

/** One vault NAME_REGISTER request. Every coin named is spent (the chain
 *  checks that each is the vault's: present, unlocked, native, owner ==
 *  the vault address); the change, if any, returns to the vault. */
typedef struct {
    const nodus_v2_ruleset_id_t *rs;  /* the CORE tuple of the generation
                                       * the node runs (>= 2) + its SYSTEM
                                       * meter policy                      */
    const uint8_t *chain32;           /* DNA_CHAIN_ID_LEN bytes            */
    uint64_t       tip;               /* committed tip (>= 1); the digest
                                       * is preflighted at tip + 1         */
    uint64_t       expiry_height;     /* (tip, tip + NODUS_V2_MSIG_EXPIRY_
                                       * AHEAD] — the co-signer window     */
    const uint8_t *desc;              /* the vault's descriptor            */
    size_t         desc_len;
    uint32_t       signers;           /* K (M <= K <= N); 0 = M            */
    const char    *name;              /* already normalised                */
    uint64_t       price;             /* the node's price for the length   */
    const nodus_v2_coin_t *coins;     /* 1..NODUS_V2_NAME_MAX_IN native
                                       * coins of the vault, any order     */
    int            n_coins;
    uint64_t       fee;               /* fee_fixed only                    */
    int            fee_fixed;         /* 1 = never raised                  */
    uint64_t       gas_price;         /* 0 = the rule is off               */
    nodus_v2_rand_fn rand;            /* the change seed                   */
    void            *rand_ctx;
} nodus_v2_name_msig_req_t;

typedef struct {
    uint8_t  *env;                    /* heap; nodus_v2_name_msig_built_free*/
    size_t    env_len;
    uint8_t   digest[64];             /* the leg auth digest to sign       */
    uint8_t   intent_id[64];
    uint8_t   addr[64];               /* the vault address = the owner     */
    uint8_t   m, n;
    uint32_t  signers;                /* K                                 */
    int       n_in, n_out;
    uint64_t  sum_in, fee, price, change, units;
    int       passes;
} nodus_v2_name_msig_built_t;

/**
 * Build the UNSIGNED single-leg CORE NAME_REGISTER of the vault: call =
 * name_len ‖ name ‖ price ‖ in_count ‖ the coins' nullifiers ascending ‖
 * out_count ‖ (the change to the vault address when > 0); auth_kind 3
 * with K zero slots and the descriptor; the effect declaration
 * nodus_v2_name_effect_decl; units = nodus_v2_spend_ceiling over THIS
 * envelope with reads = inputs + pool + NAME + OWNER; the fee starts at
 * the floor max(DNAC_MIN_FEE_RAW, NODUS_W_BASE_TX_FEE) and is raised to
 * units × gas_price when that is larger (refused instead when fee_fixed;
 * at most NODUS_V2_NAME_MAX_PASSES passes). The digest is the pass-1
 * preflight's leg auth digest at tip + 1.
 * @return NODUS_V2_SPEND_OK / _ERR_ARG / _ERR_ALLOC / _ERR_HASH /
 *         _ERR_EXPIRY / _ERR_INPUT_SUM / _ERR_INSUFFICIENT / _ERR_METER /
 *         _ERR_GAS_OVERFLOW / _ERR_FEE_BELOW_GAS / _ERR_FEE_UNSETTLED /
 *         _ERR_RANDOM / _ERR_ENCODE / _ERR_PREFLIGHT1 /
 *         NODUS_V2_NAME_ERR_NAME / _PRICE / _FEE_FLOOR /
 *         NODUS_V2_MSIG_ERR_DESC / _SIGNERS / _COIN (zero / duplicate).
 */
int nodus_v2_name_msig_build(const nodus_v2_name_msig_req_t *req,
                             nodus_v2_name_msig_built_t *out,
                             nodus_v2_name_err_t *err);

/** Free what nodus_v2_name_msig_build allocated inside `b`. NULL-safe. */
void nodus_v2_name_msig_built_free(nodus_v2_name_msig_built_t *b);

/** What a co-signer of a vault name registration is shown — every field
 *  READ BACK from the export's envelope bytes. */
typedef struct {
    uint8_t  addr[64];                /* the vault = the name's owner      */
    uint8_t  m, n;
    uint32_t signers;
    uint64_t tip, expiry_height, fee, units;
    char     name[DNAC_NAME_MAX_LEN + 1];
    uint64_t price;
    int      n_in;
    uint8_t  in_nul[NODUS_V2_NAME_MAX_IN][64];
    int      n_out;                   /* 0 or 1                            */
    uint64_t change_amount;           /* to the vault                      */
    uint8_t  digest[64];
    uint8_t  intent_id[64];
} nodus_v2_name_msig_review_t;

/**
 * The checks a co-signer makes on a vault name export before signing, in
 * order: the leg (nodus_v2_msig_leg_open_op, NAME_REGISTER — kind 3, K
 * slots, ONE descriptor); `signer_pk` (NULL = skip) is one of the
 * descriptor's keys (ERR_NOT_MEMBER); the digest re-derives
 * (nodus_v2_msig_digest) and EQUALS the exported one (ERR_DIGEST); the
 * expiry is not 0 and not beyond the export's tip +
 * NODUS_V2_MSIG_EXPIRY_AHEAD (ERR_EXPIRY); the call parses exactly (a name
 * dnac_name_bytes_ok accepts, a non-zero price, 1..NODUS_V2_NAME_MAX_IN
 * strictly ascending nullifiers, at most one output) and its one output,
 * if any, is a non-zero NATIVE change owned by the vault address (else
 * ERR_CALL — the HF-6 D2 rule of review2: nothing leaves the vault but the
 * price and the fee); the effect declaration is nodus_v2_name_effect_decl's
 * (ERR_CALL). Like nodus_v2_msig_review it does NOT prove the inputs are
 * the vault's coins (the descriptor is outside the signed context): the
 * caller checks every input against the vault's coin set on its own node
 * (nodus-cli `msig sign`, dnac_msig_utxo "nul") — and the chain refuses a
 * kind-3 registration with any non-vault input. `pf` is heap scratch.
 * @return NODUS_V2_SPEND_OK / _ERR_ARG / _ERR_ALLOC / _ERR_HASH /
 *         NODUS_V2_SPEND_ERR_PREFLIGHT1 / NODUS_V2_MSIG_ERR_SHAPE / _DESC /
 *         _NOT_MEMBER / _DIGEST / _EXPIRY / _CALL.
 */
int nodus_v2_name_msig_review(const nodus_v2_msig_export_t *x,
                              uint32_t core_version,
                              const uint8_t core_hash[DNA_ENV_RULESET_HASH_LEN],
                              const uint8_t *signer_pk,
                              dna_env_preflight_t *pf,
                              nodus_v2_name_msig_review_t *out);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_V2_NAME_H */
