/**
 * @file nodus/include/nodus/nodus_v2_spend.h
 * @brief The shared version-3 CORE SPEND builder — plan + build, no I/O.
 *
 * Governing records: docs/plans/2026-09-25-web-wallet-nodus-send-design.md
 * package (c2) (§0a.3, §1.3) and docs/plans/decisions/2026-09-25-web-wallet-
 * nodus-send-transport.md ("İşlem kurucu": the browser builds its SPEND with
 * the SAME C code `nodus-cli v2-envelope spend` uses, compiled to WASM — no
 * JS rewrite). This module is that code, moved out of nodus/tools/nodus-cli.c
 * unchanged in behaviour; nodus-cli now calls it.
 *
 * WHAT IT IS: pure functions over caller-supplied inputs — a coin list, the
 * recipient, the amount, the gas price, the chain id, the committed tip, the
 * ruleset identity, the signing key and a randomness source. It opens no
 * socket, reads no clock, touches no database and calls no global RNG: every
 * random byte (output seeds) comes from the caller's `rand` callback. The ONE
 * exception is outside this module's reach: qgp_dsa87_sign is HEDGED
 * (shared/crypto/sign/dsa/config.h DILITHIUM_RANDOMIZED_SIGNING,
 * dsa/sign.c randombytes) — so two builds from identical inputs carry
 * different signature bytes and therefore different wire_ids, while their
 * intent_id (authorization-independent, env_preflight.h) and every byte
 * outside the auth blob are identical.
 *
 * THE CHAIN IS THE SPECIFICATION (nodus/src/witness/nodus_witness_rt_native.c):
 * SPEND call v1 = in_count u8 (1..15) ‖ nullifiers strictly ascending ‖
 * out_count u8 ‖ out_count × 232-byte output records (rtn_xfer_section_parse,
 * rtn_spend_parse); exec rtn_xfer_exec. Widths are restated here with that
 * citation (the codec is file-local there).
 *
 * RULESET IDENTITY: the caller supplies it (nodus_v2_ruleset_id_t). A node-
 * linked caller (nodus-cli) fills it from the compiled table
 * (nodus_runtime_builtin_table); a caller that cannot link the witness (the
 * browser module) fills it with nodus_v2_ruleset_from_pins — the GENERATED
 * nodus_ruleset_pins.h (decision above, addendum 2026-09-29 "Yol 2"), whose
 * SYSTEM meter policy is rebuilt and checked against its pinned digest.
 *
 * EXTENSION: the staking builder (nodus/src/client/nodus_v2_stake.{c,h},
 * 2026-09-30) reuses nodus_v2_xfer_out_put (the SYSFUND funding leg IS a
 * transfer section), nodus_v2_env_sign_one_key (the two-pass signature,
 * any number of legs signed by one key), nodus_v2_spend_ceiling (the units
 * ceiling, with its own read count) and the pins header, which now also
 * carries the SYSTEM ruleset tuple. Genesis claims are built in the web
 * wallet module (web-wallet/crypto/nodus-send-wasm.c) and nodus-cli.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef NODUS_V2_SPEND_H
#define NODUS_V2_SPEND_H

#include <stdint.h>
#include <stddef.h>

#include "dnac/env_wire.h"
#include "dnac/env_preflight.h"
#include "dnac/res_meter.h"
#include "dnac/ledger_ids.h"

#ifdef __cplusplus
extern "C" {
#endif

/* SPEND transfer-section wire widths (nodus_witness_rt_native.c:
 * RTN_SPEND_MAX_IN = 15, RTN_SPEND_OUT_LEN = 232 = fp128 + amount8 +
 * token64 + seed32). */
#define NODUS_V2_SPEND_MAX_IN    15u
#define NODUS_V2_SPEND_OUT_LEN   232u
/* The outputs THIS builder emits: recipient + token change + native change. */
#define NODUS_V2_SPEND_MAX_OUTS  3u

/** Return codes. 0 = OK; NODUS_V2_SPEND_NONE_ELIGIBLE is a non-error
 *  answer of nodus_v2_spend_plan; every other value is a refusal. */
typedef enum {
    NODUS_V2_SPEND_OK               = 0,
    NODUS_V2_SPEND_NONE_ELIGIBLE    = 1,   /* count_all: no coin qualifies  */
    NODUS_V2_SPEND_ERR_ARG          = -1,  /* NULL / out-of-range argument  */
    NODUS_V2_SPEND_ERR_ALLOC        = -2,
    NODUS_V2_SPEND_ERR_OVERFLOW     = -3,  /* amount + fee overflows u64    */
    NODUS_V2_SPEND_ERR_NO_COIN_ALL  = -4,  /* amount_all: no coin above fee */
    NODUS_V2_SPEND_ERR_MAX_INPUTS   = -5,  /* > NODUS_V2_SPEND_MAX_IN needed */
    NODUS_V2_SPEND_ERR_INPUT_SUM    = -6,  /* selected input sum overflows  */
    NODUS_V2_SPEND_ERR_INSUFFICIENT = -7,
    NODUS_V2_SPEND_ERR_METER        = -8,  /* the metering plan refused     */
    NODUS_V2_SPEND_ERR_GAS_OVERFLOW = -9,  /* units × gas_price overflows   */
    NODUS_V2_SPEND_ERR_FEE_BELOW_GAS= -10, /* a fixed fee under the gas fee */
    NODUS_V2_SPEND_ERR_FEE_UNSETTLED= -11, /* fixed point did not converge  */
    NODUS_V2_SPEND_ERR_RANDOM       = -12, /* the rand callback failed      */
    NODUS_V2_SPEND_ERR_SHARD_DRAWS  = -13, /* no seed landed in the shard   */
    NODUS_V2_SPEND_ERR_HASH         = -14, /* SHA3 backend failure          */
    NODUS_V2_SPEND_ERR_UNITS_OVER_FEE = -15, /* built units × price > fee   */
    NODUS_V2_SPEND_ERR_ENCODE       = -16,
    NODUS_V2_SPEND_ERR_PREFLIGHT1   = -17, /* pass-1 preflight refused      */
    NODUS_V2_SPEND_ERR_SIGN         = -18,
    NODUS_V2_SPEND_ERR_PREFLIGHT2   = -19, /* pass-2 self-check refused     */
    NODUS_V2_SPEND_ERR_EXPIRY       = -20, /* expiry outside the window     */
    NODUS_V2_SPEND_ERR_DECODE       = -21, /* read-back refused the bytes   */
    NODUS_V2_SPEND_ERR_PINS         = -22, /* pins policy != pinned digest  */
    NODUS_V2_SPEND_ERR_DUP_OUTPUT   = -23  /* two outputs derived one id    */
} nodus_v2_spend_rc_t;

/** Coin-selection direction. Only today's nodus-cli rule exists: largest
 *  amount first, equal amounts by nullifier ascending. Smallest-first is a
 *  PROPOSAL (docs/plans/decisions/2026-09-25-spend-inputs-64-smallest-
 *  first.md item 1; design §5 item 13 — the operator's decision) and is
 *  refused until that decision is taken. */
typedef enum {
    NODUS_V2_SPEND_ORDER_LARGEST_FIRST = 0
} nodus_v2_spend_order_t;

/** One listed coin. `nul` MUST stay the first member: nodus_v2_nul_cmp
 *  orders both a bare 64-byte nullifier array and a coin array by it. */
typedef struct {
    uint8_t  nul[64];
    uint64_t amount;
    uint8_t  kind;      /* 0 native · 1 the requested token · 2 any other */
    uint8_t  used;
} nodus_v2_coin_t;

/** One planned spend: indices into the SORTED coin array. */
typedef struct {
    int      idx[NODUS_V2_SPEND_MAX_IN];
    int      n_in;
    uint64_t native_in, token_in;
    uint64_t native_change, token_change;
} nodus_v2_spend_plan_t;

/** The ruleset identity a CORE SPEND leg is built against, and the BLOCK
 *  metering policy (the SYSTEM runtime's) its units are priced under. */
typedef struct {
    uint32_t                  core_ruleset_version;
    uint8_t                   core_ruleset_hash[DNA_ENV_RULESET_HASH_LEN];
    const dna_meter_policy_t *meter_policy;
} nodus_v2_ruleset_id_t;

/** Caller-supplied randomness: fill `len` bytes, return 0 / nonzero. */
typedef int (*nodus_v2_rand_fn)(void *ctx, uint8_t *buf, size_t len);

/** Which numbers a refusal carries (for the caller's message). */
typedef struct {
    long          k;         /* 0-based spend index (plan / build)          */
    uint64_t      fee;       /* the fee in force when it stopped            */
    uint64_t      units;     /* the largest planned / the built units       */
    uint64_t      required;  /* units × gas_price                           */
    int           pass;      /* fixed-point pass                            */
    int           n_in, n_out;
    int           leg;       /* nodus_v2_env_sign_one_key: failing leg      */
    unsigned long draws;     /* shard seed draws                            */
} nodus_v2_spend_err_t;

/* ── building blocks (also used by nodus-cli stake / token-create / msig) */

/** Ascending by the first 64 bytes (a nullifier). qsort comparator. */
int nodus_v2_nul_cmp(const void *a, const void *b);

/** Sort `coins` in place in the selection order. 0 / NODUS_V2_SPEND_ERR_ARG. */
int nodus_v2_spend_sort_coins(nodus_v2_coin_t *coins, int n_coins,
                              nodus_v2_spend_order_t order);

/** Append unused coins of `kind`, in array order, to plan->idx until their
 *  sum reaches `need`. @return 0 covered · -1 not enough coins of this kind
 *  · -2 would need more than NODUS_V2_SPEND_MAX_IN inputs in total · -3 the
 *  input sum overflows u64. */
int nodus_v2_spend_pick(const nodus_v2_coin_t *coins, int n_coins,
                        uint8_t kind, uint64_t need,
                        nodus_v2_spend_plan_t *plan, uint64_t *sum_out);

/** Write ONE 232-byte transfer-section output record: owner (128 lowercase
 *  hex chars), amount u64 BE, token id (NULL = native, all-zero), seed. */
void nodus_v2_xfer_out_put(uint8_t *rec, const char *owner_hex128,
                           uint64_t amount, const uint8_t *token64,
                           const uint8_t seed32[32]);

/** The EXACT (res_max_effects, res_max_effect_bytes) of one CORE SPEND leg
 *  with n_in inputs and n_out outputs: effects = n_in + n_out + 1,
 *  bytes = 116 + 148·n_in + 432·n_out. */
void nodus_v2_spend_effect_decl(uint32_t n_in, uint32_t n_out,
                                uint32_t *effects_out, uint32_t *bytes_out);

/** The smallest res_max_total_units the chain accepts for THIS envelope and
 *  never exhausts executing it: static_units (dna_meter_plan_build under
 *  `pol`) + n_reads × w_read. Overwrites env_in->res_max_total_units
 *  (provisionally). @return 0 / -1. */
int nodus_v2_spend_ceiling(dna_env_in_t *env_in, const dna_meter_policy_t *pol,
                           uint32_t n_reads, uint64_t *ceiling_out);

/** The units a single-signer CORE SPEND of this SHAPE declares, before its
 *  coins are fixed (a zero-filled call of the same lengths). @return 0 / -1. */
int nodus_v2_spend_units_for_shape(uint32_t core_ruleset_version,
                                   const dna_meter_policy_t *pol,
                                   uint32_t alen, int n_in, int n_out,
                                   uint64_t *units_out);

/** The two-pass build of an envelope every leg of which is authorised by
 *  ONE kind-1 signer (count 1 ‖ pk ‖ sig over that leg's auth_digest):
 *  encode with zero-filled auth blobs, preflight at tip + 1, sign, re-encode,
 *  re-preflight (self-check). `auths[L]` is leg L's buffer (the SAME pointer
 *  as legs[L].auth_data), 1 + NODUS_RT_AUTH_SIGNER_LEN bytes. `pk` 2592 B,
 *  `sk` 4896 B. On OK *env_out is heap (caller frees) and `pf` holds the
 *  pass-2 commitments. `err` (may be NULL) receives the failing leg.
 *  @return NODUS_V2_SPEND_OK / _ERR_ALLOC / _ERR_ENCODE / _ERR_PREFLIGHT1 /
 *  _ERR_SIGN / _ERR_PREFLIGHT2. */
int nodus_v2_env_sign_one_key(const dna_env_in_t *env_in,
                              uint8_t *const *auths,
                              const dna_env_leg_ctx_t *lctx,
                              const uint8_t chain32[DNA_CHAIN_ID_LEN],
                              uint64_t tip, const uint8_t *pk,
                              const uint8_t *sk, uint8_t **env_out,
                              size_t *env_len_out, dna_env_preflight_t *pf,
                              nodus_v2_spend_err_t *err);

/* ── the ruleset identity from the generated pins header ───────────── */

/** Fill `out` from nodus_ruleset_pins.h: the CORE tuple, and the SYSTEM
 *  meter policy rebuilt into `policy_storage` (dna_meter_op_set + seal) and
 *  REFUSED unless its dna_meter_policy_digest equals the pinned digest.
 *  out->meter_policy points into policy_storage.
 *  @return NODUS_V2_SPEND_OK / _ERR_ARG / _ERR_PINS. */
int nodus_v2_ruleset_from_pins(nodus_v2_ruleset_id_t *out,
                               dna_meter_policy_t *policy_storage);

/* HF-4 (design docs/plans/2026-10-02-onchain-names-design.md rev 4 §1.6
 * — pins header v2 with every generation). A client asks the node
 * (dnac_ruleset_info), finds the pinned generation whose (SYSTEM, CORE)
 * tuple EQUALS the answer — never by height — and builds with it; no
 * match means the client is out of date (fail closed).
 * nodus_v2_ruleset_from_pins above is generation 1 (kept for the web
 * wallet's WASM module until it migrates to the _gen form). */

/** Number of generations nodus_ruleset_pins.h carries (1..count). */
uint32_t nodus_v2_pins_generation_count(void);

/** One pinned generation's (SYSTEM, CORE) tuples; any out may be NULL.
 *  @return NODUS_V2_SPEND_OK / _ERR_ARG (unknown generation). */
int nodus_v2_pins_tuples(uint32_t generation, uint32_t *sys_version,
                         uint8_t sys_hash[64], uint32_t *core_version,
                         uint8_t core_hash[64]);

/** nodus_v2_ruleset_from_pins for generation `generation`.
 *  @return NODUS_V2_SPEND_OK / _ERR_ARG / _ERR_PINS. */
int nodus_v2_ruleset_from_pins_gen(uint32_t generation,
                                   nodus_v2_ruleset_id_t *out,
                                   dna_meter_policy_t *policy_storage);

/* ── plan ───────────────────────────────────────────────────────────── */

typedef struct {
    const nodus_v2_ruleset_id_t *rs;
    nodus_v2_spend_order_t       order;
    int      is_native;      /* 1 native · 0 the coins' kind-1 token        */
    uint64_t amount;         /* ignored under amount_all                    */
    int      amount_all;     /* each spend: ONE native coin minus the fee   */
    uint64_t fee;            /* the starting fee (the floor, or a fixed fee)*/
    int      fee_fixed;      /* 1 = never raised; refused when too low      */
    uint64_t gas_price;      /* 0 = the rule is off                         */
    long     count;          /* spends to plan (ignored under count_all)    */
    int      count_all;      /* one spend per eligible coin (amount_all)    */
} nodus_v2_spend_plan_req_t;

/**
 * Plan `count` INDEPENDENT spends with DISJOINT input sets from `coins`
 * (sorted in place by req->order first; the plans index the sorted array),
 * under the bounded gas-price fixed point: plan at the current fee, price
 * the largest shape, raise the fee and re-plan from scratch if needed (at
 * most 8 passes). gas_price 0: one pass. `coins[].kind` must be set by the
 * caller; `used` is overwritten.
 * @param plans_out  heap array (caller frees) of *count_out plans
 * @param fee_out    the ONE fee every planned spend pays
 * @return NODUS_V2_SPEND_OK, NODUS_V2_SPEND_NONE_ELIGIBLE (count_all and no
 *         coin qualifies; nothing allocated), or a refusal with `err` set.
 */
int nodus_v2_spend_plan(const nodus_v2_spend_plan_req_t *req,
                        nodus_v2_coin_t *coins, int n_coins,
                        nodus_v2_spend_plan_t **plans_out, long *count_out,
                        uint64_t *fee_out, nodus_v2_spend_err_t *err);

/* ── build + read-back ──────────────────────────────────────────────── */

/** A CORE SPEND envelope read back from its bytes (self-consistent decode:
 *  this module's layout, not the chain's rtn_xfer_section_parse). */
typedef struct {
    uint64_t expiry_height;
    uint64_t fee;
    uint64_t units;                    /* res_max_total_units              */
    uint32_t ruleset_version;
    uint32_t effects, effect_bytes;    /* the leg's declaration            */
    int      n_in;
    uint8_t  in_nul[NODUS_V2_SPEND_MAX_IN][64];
    int      n_out;                    /* out[0] = recipient, then change  */
    char     out_owner[NODUS_V2_SPEND_MAX_OUTS][129];
    uint64_t out_amount[NODUS_V2_SPEND_MAX_OUTS];
    uint8_t  out_token[NODUS_V2_SPEND_MAX_OUTS][64];
    uint8_t  out_id[NODUS_V2_SPEND_MAX_OUTS][64]; /* SHA3-512(owner‖seed)  */
} nodus_v2_spend_decoded_t;

/** Decode a one-leg CORE SPEND envelope built by this module. Refuses any
 *  other shape (leg count, domain, op, access mode, lengths, input order,
 *  owner hex, zero amount, more than NODUS_V2_SPEND_MAX_OUTS outputs).
 *  @return NODUS_V2_SPEND_OK / _ERR_ARG / _ERR_DECODE / _ERR_HASH. */
int nodus_v2_spend_decode(const uint8_t *env, size_t env_len,
                          nodus_v2_spend_decoded_t *out);

typedef struct {
    const nodus_v2_ruleset_id_t *rs;
    const uint8_t *chain32;          /* DNA_CHAIN_ID_LEN bytes              */
    uint64_t       tip;              /* committed tip (>= 1); preflight at
                                      * tip + 1                             */
    uint64_t       expiry_height;    /* (tip, tip + NODUS_CMT_APP_MAX_EXPIRY_
                                      * AHEAD]; signed, fixed before signing*/
    const uint8_t *pk;               /* sender ML-DSA-87 pk, 2592 B: signer
                                      * and owner of every input            */
    const uint8_t *sk;               /* 4896 B                              */
    const uint8_t *to_fp;            /* recipient fingerprint, 64 raw bytes */
    const uint8_t *token;            /* NULL = native; else 64-byte id      */
    uint64_t       amount;           /* ignored under amount_all            */
    int            amount_all;       /* send = the plan's native_in − fee   */
    uint64_t       fee;              /* the plan's fee                      */
    uint64_t       gas_price;        /* 0 = rule off                        */
    const nodus_v2_coin_t       *coins;  /* the array the plan indexes      */
    const nodus_v2_spend_plan_t *plan;
    nodus_v2_rand_fn rand;           /* output seeds — never a global RNG   */
    void            *rand_ctx;
    uint64_t       shard_m, shard_i; /* shard_m <= 1: no constraint; else
                                      * every output id's first 8 bytes (BE)
                                      * mod shard_m == shard_i, by re-drawing
                                      * its seed (at most 64·m + 64 draws)  */
} nodus_v2_spend_build_req_t;

typedef struct {
    uint8_t                 *env;    /* heap; nodus_v2_spend_built_free     */
    size_t                   env_len;
    uint8_t                  wire_id[64];
    uint8_t                  intent_id[64];
    nodus_v2_spend_decoded_t dec;    /* read back from `env`                */
} nodus_v2_spend_built_t;

/**
 * Build, sign and self-check ONE CORE SPEND envelope from one plan, then
 * decode it back and refuse if the decoded fields differ from the request.
 * @return NODUS_V2_SPEND_OK or a refusal (`err` may be NULL).
 */
int nodus_v2_spend_build(const nodus_v2_spend_build_req_t *req,
                         nodus_v2_spend_built_t *out,
                         nodus_v2_spend_err_t *err);

/** Free what nodus_v2_spend_build allocated inside `b`. NULL-safe. */
void nodus_v2_spend_built_free(nodus_v2_spend_built_t *b);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_V2_SPEND_H */
