/**
 * @file nodus/src/client/nodus_v2_spend.c
 * @brief The shared version-3 CORE SPEND builder (package (c2)) — see
 *        nodus/include/nodus/nodus_v2_spend.h for the contract.
 *
 * Moved out of nodus/tools/nodus-cli.c (`v2-envelope spend`: the
 * T6_SPEND_* widths, t6_coin_t, t6_nul_cmp, t6_xfer_out_put,
 * t6_env_sign_one_key, t6_spend_plan_t, t6_coin_cmp, t6_spend_pick,
 * t6_spend_effect_decl, t6_spend_ceiling, t6_spend_units_for_shape, and the
 * plan / build loops of cmd_v2_spend). The arithmetic, the selection order,
 * the call layout, the leg header and the order of random draws are the
 * CLI's, unchanged; what changed is the surface: no printing (every refusal
 * is a code plus the numbers in nodus_v2_spend_err_t, the CLI prints), no
 * network, and the randomness source and the ruleset identity are inputs.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "nodus/nodus_v2_spend.h"
#include "nodus/nodus_ruleset_pins.h"
#include "nodus/nodus_types.h"             /* NODUS_CMT_APP_MAX_EXPIRY_AHEAD */
#include "witness/nodus_witness_runtime.h" /* NODUS_RT_* auth / record widths,
                                            * DNA_CORERULE_SPEND — header
                                            * constants only, no witness link */
#include "dnac/effect_wire.h"
#include "crypto/hash/qgp_sha3.h"
#include "crypto/sign/qgp_dilithium.h"
#include "crypto/utils/qgp_fingerprint.h"

#include <stdlib.h>
#include <string.h>

#include "crypto/utils/qgp_safe_string.h"   /* Phase 03: unsafe-string poison guard */

/* ML-DSA-87 sizes the kind-1 auth blob carries (pk ‖ sig, the
 * NODUS_RT_AUTH_SIGNER_LEN split). */
#define V2S_PK_LEN   2592u
#define V2S_SIG_LEN  4627u
_Static_assert(V2S_PK_LEN + V2S_SIG_LEN == NODUS_RT_AUTH_SIGNER_LEN,
               "the kind-1 signer record is pk ‖ sig");

/* One single-signer kind-1 auth blob: count u8 = 1 ‖ pk ‖ sig. */
#define V2S_AUTH_LEN (1u + NODUS_RT_AUTH_SIGNER_LEN)

/* The largest shape this builder can emit (15 inputs, 3 outputs) stays
 * inside the metering plan's declaration caps (res_meter.h:
 * res_max_effects <= DNA_EFFECT_MAX_COUNT, res_max_effect_bytes <=
 * DNA_EFFECT_MAX_TOTAL_LEN). */
_Static_assert(NODUS_V2_SPEND_MAX_IN + NODUS_V2_SPEND_MAX_OUTS + 1u <=
                   (unsigned)DNA_EFFECT_MAX_COUNT,
               "SPEND effect count exceeds the effect codec cap");
_Static_assert((unsigned)DNA_EFFECT_FIXED_HEAD +
                   (unsigned)DNA_EFFECT_RECORD_LEN *
                       (NODUS_V2_SPEND_MAX_IN + NODUS_V2_SPEND_MAX_OUTS + 1u) +
                   NODUS_V2_SPEND_MAX_OUTS * (64u + NODUS_RT_CORE_UTXO_REC_LEN) +
                   (1u + 8u) + NODUS_V2_SPEND_MAX_IN * 64u <=
                   DNA_EFFECT_MAX_TOTAL_LEN,
               "SPEND result length exceeds the effect codec cap");

static void err_reset(nodus_v2_spend_err_t *err) {
    if (err) memset(err, 0, sizeof(*err));
}

/* ── building blocks ────────────────────────────────────────────────── */

int nodus_v2_nul_cmp(const void *a, const void *b) {
    return memcmp(a, b, 64);
}

/* Largest amount first; equal amounts by nullifier ascending — a TOTAL
 * order (nullifiers are distinct rows), so the selection is a pure
 * function of the listing whatever order the server returned it in. */
static int coin_cmp_largest_first(const void *a, const void *b) {
    const nodus_v2_coin_t *x = (const nodus_v2_coin_t *)a;
    const nodus_v2_coin_t *y = (const nodus_v2_coin_t *)b;
    if (x->amount != y->amount) return x->amount > y->amount ? -1 : 1;
    return memcmp(x->nul, y->nul, 64);
}

int nodus_v2_spend_sort_coins(nodus_v2_coin_t *coins, int n_coins,
                              nodus_v2_spend_order_t order) {
    if (n_coins < 0 || (n_coins > 0 && !coins))
        return NODUS_V2_SPEND_ERR_ARG;
    if (order != NODUS_V2_SPEND_ORDER_LARGEST_FIRST)
        return NODUS_V2_SPEND_ERR_ARG;          /* see the enum's comment */
    if (n_coins > 1)
        qsort(coins, (size_t)n_coins, sizeof(*coins), coin_cmp_largest_first);
    return NODUS_V2_SPEND_OK;
}

int nodus_v2_spend_pick(const nodus_v2_coin_t *coins, int n_coins,
                        uint8_t kind, uint64_t need,
                        nodus_v2_spend_plan_t *plan, uint64_t *sum_out) {
    uint64_t sum = 0;
    for (int i = 0; i < n_coins && sum < need; i++) {
        if (coins[i].used || coins[i].kind != kind) continue;
        if (plan->n_in >= (int)NODUS_V2_SPEND_MAX_IN) return -2;
        if (sum > UINT64_MAX - coins[i].amount) return -3;
        plan->idx[plan->n_in++] = i;
        sum += coins[i].amount;
    }
    *sum_out = sum;
    return sum >= need ? 0 : -1;
}

/* Output record layout (NODUS_V2_SPEND_OUT_LEN = 232 bytes):
 *   [0..127]   owner fingerprint, 128 lowercase-hex chars (NOT raw — the
 *              chain checks rtn_hex_lower_ok)
 *   [128..135] amount u64 BE (>= 1)
 *   [136..199] token id, 64 bytes (NULL = all-zero = native)
 *   [200..231] seed, 32 bytes — output id = SHA3-512(owner_hex ‖ seed)
 *              (rtn_out_ids) */
void nodus_v2_xfer_out_put(uint8_t *rec, const char *owner_hex128,
                           uint64_t amount, const uint8_t *token64,
                           const uint8_t seed32[32]) {
    memcpy(rec, owner_hex128, 128);
    for (int i = 0; i < 8; i++)
        rec[128 + i] = (uint8_t)(amount >> (56 - 8 * i));
    if (token64) memcpy(rec + 136, token64, 64);
    else         memset(rec + 136, 0, 64);
    memcpy(rec + 200, seed32, 32);
}

/* The EXACT per-leg effect declaration (res_max_effects,
 * res_max_effect_bytes) of ONE CORE SPEND leg with n_in inputs and
 * n_out outputs — what the chain's SPEND executor emits and what the
 * meter charges, not a ceiling guess:
 *
 * EFFECTS (rtn_xfer_exec, nodus_witness_rt_native.c:1639-1771; the
 * result is built at :1727-1767; SPEND = burn_amount 0, is_burn false):
 *   - n_out CREATEs, one per output (:1734-1741): key 64 (the output
 *     nullifier), value RTN_UTXO_REC_LEN = 284 (:1010; set by
 *     rtn_utxo_create_eff :1563-1564; exported as
 *     NODUS_RT_CORE_UTXO_REC_LEN, nodus_witness_runtime.h);
 *   - exactly ONE reward-pool SET (:1752-1757, rtn_supply_add_eff
 *     :1598-1599): key 1 (the selector), value 8 (the counter). It is
 *     emitted UNCONDITIONALLY for a SPEND — there is no fee == 0 branch,
 *     and a fee below DNAC_MIN_FEE_RAW / NODUS_W_BASE_TX_FEE is refused
 *     before it (:1698-1700), so fee > 0 is not a term here;
 *   - n_in DELETEs, one per input (:1758-1764, rtn_utxo_delete_eff
 *     :1617-1618): key 64 (the input nullifier), value 0.
 *   The burned-counter SET (:1746-1751) is BURN-only.
 * (Line numbers as cited when this lived in nodus-cli.c; they are not
 * re-verified by the move.)
 *
 * BYTES = the canonical encoded result length — res_meter.h "effect
 * bytes" is the full effect_wire encoding, and dna_meter_charge_effects
 * recomputes it as head + count × record + Σ key_len + Σ value_len
 * (res_meter.c). effect_wire.h layout: DNA_EFFECT_FIXED_HEAD 23,
 * DNA_EFFECT_RECORD_LEN 84 per effect, then every key and value blob with
 * no padding. So:
 *   effects = n_in + n_out + 1
 *   bytes   = 23 + 84·effects + n_out·(64 + 284) + (1 + 8) + n_in·64
 *           = 116 + 148·n_in + 432·n_out
 * e.g. 1-in/1-out: 3 effects, 696 bytes. Every term is a fixed-size
 * field, so the bound is EXACT, never short. The charge gate rejects
 * only actual > declared (res_meter.c): exact equality passes, an
 * under-declaration fails the transaction at charge time (after CheckTx
 * admitted it). test_v2_native.c test_spend_effect_decl restates this
 * formula independently and pins it against the real runtime (hook-level
 * equality, block-level: the exact declaration commits, one effect or one
 * byte short rejects). */
void nodus_v2_spend_effect_decl(uint32_t n_in, uint32_t n_out,
                                uint32_t *effects_out, uint32_t *bytes_out) {
    const uint32_t effects = n_in + n_out + 1u;
    *effects_out = effects;
    *bytes_out = (uint32_t)DNA_EFFECT_FIXED_HEAD +
                 (uint32_t)DNA_EFFECT_RECORD_LEN * effects +
                 n_out * (64u + NODUS_RT_CORE_UTXO_REC_LEN) +
                 (1u + 8u) +
                 n_in * 64u;
}

/* The smallest res_max_total_units the chain will accept for THIS
 * envelope AND never exhaust while executing it:
 *   ceiling = static_units(envelope) + n_reads × w_read
 * static_units is computed by the metering module itself
 * (dna_meter_plan_build, shared/dnac/res_meter.c — w_base + Σ w_op +
 * w_callbyte·call_len + w_authbyte·auth_len + w_effect·res_max_effects +
 * w_effectbyte·res_max_effect_bytes) under the BLOCK policy, which is the
 * SYSTEM runtime's compiled meter_policy (nodus_witness_v2_apply.c
 * `ctx->policy = sys->rt->meter_policy`), so no weight is restated here.
 * Execution charges the fixed part (≤ static), the actual effect count
 * and bytes (≤ the declared per-leg ceilings — res_meter.h "Declared
 * per-leg ceilings gate it"), and ONE w_read per mediated read (charged
 * against the SAME global ceiling — res_meter.c meter_charge "consumed
 * never crosses the reserved ceiling"); a SPEND makes in_count + 1 reads
 * (nodus_witness_rt_native.c). The read term is added explicitly rather
 * than trusting the effect-byte slack to absorb it. */
int nodus_v2_spend_ceiling(dna_env_in_t *env_in, const dna_meter_policy_t *pol,
                           uint32_t n_reads, uint64_t *ceiling_out) {
    size_t len = 0, used = 0;
    if (!env_in || !pol || !ceiling_out ||
        dna_env_encoded_size(env_in->legs, env_in->leg_count, &len) != 0)
        return -1;
    uint8_t *buf = malloc(len);
    dna_meter_plan_t *plan = calloc(1, sizeof(*plan));
    dna_env_view_t *view = calloc(1, sizeof(*view));
    int rc = -1;
    /* provisional: plan_build only checks static_total <= this value */
    env_in->res_max_total_units = UINT64_MAX;
    if (buf && plan && view &&
        dna_env_encode(env_in, buf, len, &used) == 0 && used == len &&
        dna_env_decode(buf, len, view) == 0 &&
        dna_meter_plan_build(pol, view, plan) == DNA_METER_OK &&
        (plan->w_read == 0 || n_reads <= UINT64_MAX / plan->w_read) &&
        plan->static_total <= UINT64_MAX - (uint64_t)n_reads * plan->w_read) {
        *ceiling_out = plan->static_total + (uint64_t)n_reads * plan->w_read;
        rc = 0;
    }
    free(view);
    free(plan);
    free(buf);
    return rc;
}

/* HF-1 — the res_max_total_units a CORE SPEND envelope of THIS SHAPE
 * (n_in inputs, n_out outputs) will declare, computed BEFORE its coins
 * are fixed, so the gas-price fee can be known while planning.
 *
 * The ceiling nodus_v2_spend_ceiling derives is a function of the
 * envelope's LENGTHS and DECLARATIONS only — call_len = 2 + 64·n_in +
 * 232·n_out, auth_len, the leg's exact effect declaration and the
 * fixed-width header fields (expiry, fee and units are u64s whatever
 * their value) — never of the nullifier, owner, amount or seed bytes. So
 * a zero-filled call of the same shape prices exactly what the real build
 * prices; the build re-derives its own units and checks them against the
 * planned fee anyway. */
int nodus_v2_spend_units_for_shape(uint32_t core_ruleset_version,
                                   const dna_meter_policy_t *pol,
                                   uint32_t alen, int n_in, int n_out,
                                   uint64_t *units_out) {
    if (n_in < 1 || n_in > (int)NODUS_V2_SPEND_MAX_IN ||
        n_out < 1 || n_out > (int)NODUS_V2_SPEND_MAX_OUTS)
        return -1;
    size_t call_len = 2 + (size_t)n_in * 64 +
                      (size_t)n_out * NODUS_V2_SPEND_OUT_LEN;
    uint8_t *call = calloc(1, call_len);
    uint8_t *auth = calloc(1, alen);
    int rc = -1;
    if (call && auth) {
        call[0] = (uint8_t)n_in;
        call[1 + (size_t)n_in * 64] = (uint8_t)n_out;
        dna_env_leg_in_t leg;
        memset(&leg, 0, sizeof(leg));
        leg.hdr.domain_id       = DNA_DOMAIN_CORE;
        leg.hdr.runtime_op      = DNA_CORERULE_SPEND;
        leg.hdr.ruleset_version = core_ruleset_version;
        leg.hdr.access_mode     = DNA_ENV_ACCESS_INVOKE;
        leg.hdr.auth_kind       = NODUS_RT_AUTHKIND_DSA87_MULTI_V1;
        leg.hdr.call_len        = (uint32_t)call_len;
        leg.hdr.auth_len        = alen;
        nodus_v2_spend_effect_decl((uint32_t)n_in, (uint32_t)n_out,
                                   &leg.hdr.res_max_effects,
                                   &leg.hdr.res_max_effect_bytes);
        leg.call_data = call;
        leg.auth_data = auth;
        dna_env_in_t env_in;
        memset(&env_in, 0, sizeof(env_in));
        env_in.leg_count = 1;
        env_in.legs      = &leg;
        rc = nodus_v2_spend_ceiling(&env_in, pol, (uint32_t)n_in + 1u,
                                    units_out);
    }
    free(auth);
    free(call);
    return rc;
}

/* Encode with each leg's auth blob zero-filled at its FINAL length
 * (auth_len is committed, so the digest cannot depend on the signature
 * bytes), preflight at tip + 1 to derive every auth_digest, sign,
 * re-encode (same lengths ⇒ same digests), re-preflight as a self-check. */
int nodus_v2_env_sign_one_key(const dna_env_in_t *env_in,
                              uint8_t *const *auths,
                              const dna_env_leg_ctx_t *lctx,
                              const uint8_t chain32[DNA_CHAIN_ID_LEN],
                              uint64_t tip, const uint8_t *pk,
                              const uint8_t *sk, uint8_t **env_out,
                              size_t *env_len_out, dna_env_preflight_t *pf,
                              nodus_v2_spend_err_t *err) {
    if (!env_in || !auths || !lctx || !chain32 || !pk || !sk || !env_out ||
        !env_len_out || !pf)
        return NODUS_V2_SPEND_ERR_ARG;
    *env_out = NULL;
    *env_len_out = 0;
    size_t env_len = 0;
    if (dna_env_encoded_size(env_in->legs, env_in->leg_count, &env_len) != 0)
        return NODUS_V2_SPEND_ERR_ENCODE;
    uint8_t *env_bytes = malloc(env_len);
    if (!env_bytes) return NODUS_V2_SPEND_ERR_ALLOC;

    int rc = NODUS_V2_SPEND_ERR_ENCODE;
    size_t used = 0;
    if (dna_env_encode(env_in, env_bytes, env_len, &used) != 0 ||
        used != env_len) goto fail;
    if (dna_env_preflight(env_bytes, env_len, chain32, tip + 1, lctx,
                          env_in->leg_count, pf) != DNA_ENV_PF_OK) {
        rc = NODUS_V2_SPEND_ERR_PREFLIGHT1;
        goto fail;
    }

    for (uint16_t L = 0; L < env_in->leg_count; L++) {
        uint8_t *ab = auths[L];
        ab[0] = 1;
        memcpy(ab + 1, pk, V2S_PK_LEN);
        size_t sl = 0;
        if (qgp_dsa87_sign(ab + 1 + V2S_PK_LEN, &sl, pf->auth_digest[L],
                           64, sk) != 0 ||
            sl != V2S_SIG_LEN) {
            if (err) err->leg = (int)L;
            rc = NODUS_V2_SPEND_ERR_SIGN;
            goto fail;
        }
    }

    rc = NODUS_V2_SPEND_ERR_ENCODE;
    if (dna_env_encode(env_in, env_bytes, env_len, &used) != 0 ||
        used != env_len) goto fail;
    if (dna_env_preflight(env_bytes, env_len, chain32, tip + 1, lctx,
                          env_in->leg_count, pf) != DNA_ENV_PF_OK) {
        rc = NODUS_V2_SPEND_ERR_PREFLIGHT2;
        goto fail;
    }
    *env_out = env_bytes;
    *env_len_out = env_len;
    return NODUS_V2_SPEND_OK;

fail:
    free(env_bytes);
    return rc;
}

/* ── the ruleset identity from the generated pins header ───────────── */

/* HF-4 (design docs/plans/2026-10-02-onchain-names-design.md rev 4 §1.6
 * — pins header v2): one generation's pinned values. Generation 1 is the
 * unprefixed NODUS_PIN_* set, generation g > 1 the NODUS_PIN_G<g>_* set;
 * the policy SHAPE (seven scalar weights + the byte bound) is the same
 * layout in every generation. */
typedef struct {
    uint32_t       core_version;
    const uint8_t *core_hash;
    uint32_t       sys_version;
    const uint8_t *sys_hash;
    uint32_t       pol_version;
    uint64_t       w[7];                /* base callbyte authbyte effect
                                         * effectbyte read write          */
    uint64_t       max_env_bytes;
    uint32_t       n_ops;
    const uint32_t *ops;
    const uint64_t *wts;
    const uint8_t  *digest;
} pins_gen_t;

static const uint8_t PG1_CORE[64] = NODUS_PIN_CORE_RULESET_HASH_INIT;
static const uint8_t PG1_SYS[64]  = NODUS_PIN_SYS_RULESET_HASH_INIT;
static const uint32_t PG1_OPS[NODUS_PIN_SYS_METER_OP_COUNT] =
    NODUS_PIN_SYS_METER_OPS_INIT;
static const uint64_t PG1_WTS[NODUS_PIN_SYS_METER_OP_COUNT] =
    NODUS_PIN_SYS_METER_OP_WEIGHTS_INIT;
static const uint8_t PG1_DIG[64] = NODUS_PIN_SYS_METER_POLICY_DIGEST_INIT;
static const uint8_t PG2_CORE[64] = NODUS_PIN_G2_CORE_RULESET_HASH_INIT;
static const uint8_t PG2_SYS[64]  = NODUS_PIN_G2_SYS_RULESET_HASH_INIT;
static const uint32_t PG2_OPS[NODUS_PIN_G2_SYS_METER_OP_COUNT] =
    NODUS_PIN_G2_SYS_METER_OPS_INIT;
static const uint64_t PG2_WTS[NODUS_PIN_G2_SYS_METER_OP_COUNT] =
    NODUS_PIN_G2_SYS_METER_OP_WEIGHTS_INIT;
static const uint8_t PG2_DIG[64] = NODUS_PIN_G2_SYS_METER_POLICY_DIGEST_INIT;
static const uint8_t PG3_CORE[64] = NODUS_PIN_G3_CORE_RULESET_HASH_INIT;
static const uint8_t PG3_SYS[64]  = NODUS_PIN_G3_SYS_RULESET_HASH_INIT;
static const uint32_t PG3_OPS[NODUS_PIN_G3_SYS_METER_OP_COUNT] =
    NODUS_PIN_G3_SYS_METER_OPS_INIT;
static const uint64_t PG3_WTS[NODUS_PIN_G3_SYS_METER_OP_COUNT] =
    NODUS_PIN_G3_SYS_METER_OP_WEIGHTS_INIT;
static const uint8_t PG3_DIG[64] = NODUS_PIN_G3_SYS_METER_POLICY_DIGEST_INIT;

static const pins_gen_t PINS_GEN[] = {
    { NODUS_PIN_CORE_RULESET_VERSION, PG1_CORE,
      NODUS_PIN_SYS_RULESET_VERSION, PG1_SYS,
      NODUS_PIN_SYS_METER_POLICY_VERSION,
      { NODUS_PIN_SYS_METER_W_BASE, NODUS_PIN_SYS_METER_W_CALLBYTE,
        NODUS_PIN_SYS_METER_W_AUTHBYTE, NODUS_PIN_SYS_METER_W_EFFECT,
        NODUS_PIN_SYS_METER_W_EFFECTBYTE, NODUS_PIN_SYS_METER_W_READ,
        NODUS_PIN_SYS_METER_W_WRITE },
      NODUS_PIN_SYS_METER_MAX_BLOCK_ENV_BYTES,
      NODUS_PIN_SYS_METER_OP_COUNT, PG1_OPS, PG1_WTS, PG1_DIG },
    { NODUS_PIN_G2_CORE_RULESET_VERSION, PG2_CORE,
      NODUS_PIN_G2_SYS_RULESET_VERSION, PG2_SYS,
      NODUS_PIN_G2_SYS_METER_POLICY_VERSION,
      { NODUS_PIN_G2_SYS_METER_W_BASE, NODUS_PIN_G2_SYS_METER_W_CALLBYTE,
        NODUS_PIN_G2_SYS_METER_W_AUTHBYTE, NODUS_PIN_G2_SYS_METER_W_EFFECT,
        NODUS_PIN_G2_SYS_METER_W_EFFECTBYTE, NODUS_PIN_G2_SYS_METER_W_READ,
        NODUS_PIN_G2_SYS_METER_W_WRITE },
      NODUS_PIN_G2_SYS_METER_MAX_BLOCK_ENV_BYTES,
      NODUS_PIN_G2_SYS_METER_OP_COUNT, PG2_OPS, PG2_WTS, PG2_DIG },
    { NODUS_PIN_G3_CORE_RULESET_VERSION, PG3_CORE,
      NODUS_PIN_G3_SYS_RULESET_VERSION, PG3_SYS,
      NODUS_PIN_G3_SYS_METER_POLICY_VERSION,
      { NODUS_PIN_G3_SYS_METER_W_BASE, NODUS_PIN_G3_SYS_METER_W_CALLBYTE,
        NODUS_PIN_G3_SYS_METER_W_AUTHBYTE, NODUS_PIN_G3_SYS_METER_W_EFFECT,
        NODUS_PIN_G3_SYS_METER_W_EFFECTBYTE, NODUS_PIN_G3_SYS_METER_W_READ,
        NODUS_PIN_G3_SYS_METER_W_WRITE },
      NODUS_PIN_G3_SYS_METER_MAX_BLOCK_ENV_BYTES,
      NODUS_PIN_G3_SYS_METER_OP_COUNT, PG3_OPS, PG3_WTS, PG3_DIG },
};
_Static_assert(sizeof(PINS_GEN) / sizeof(PINS_GEN[0]) == NODUS_PIN_GEN_COUNT,
               "one pins entry per generation in nodus_ruleset_pins.h");
_Static_assert(NODUS_PIN_CORE_DOMAIN_ID == DNA_DOMAIN_CORE,
               "the pinned CORE tuple is domain 1");

uint32_t nodus_v2_pins_generation_count(void) {
    return (uint32_t)NODUS_PIN_GEN_COUNT;
}

int nodus_v2_pins_tuples(uint32_t generation, uint32_t *sys_version,
                         uint8_t sys_hash[64], uint32_t *core_version,
                         uint8_t core_hash[64]) {
    if (generation < 1 || generation > NODUS_PIN_GEN_COUNT)
        return NODUS_V2_SPEND_ERR_ARG;
    const pins_gen_t *g = &PINS_GEN[generation - 1u];
    if (sys_version) *sys_version = g->sys_version;
    if (sys_hash) memcpy(sys_hash, g->sys_hash, 64);
    if (core_version) *core_version = g->core_version;
    if (core_hash) memcpy(core_hash, g->core_hash, 64);
    return NODUS_V2_SPEND_OK;
}

int nodus_v2_ruleset_from_pins_gen(uint32_t generation,
                                   nodus_v2_ruleset_id_t *out,
                                   dna_meter_policy_t *policy_storage) {
    if (!out || !policy_storage || generation < 1 ||
        generation > NODUS_PIN_GEN_COUNT)
        return NODUS_V2_SPEND_ERR_ARG;
    const pins_gen_t *g = &PINS_GEN[generation - 1u];
    memset(out, 0, sizeof(*out));
    memset(policy_storage, 0, sizeof(*policy_storage));

    dna_meter_policy_t *p = policy_storage;
    p->policy_version      = g->pol_version;
    p->w_base              = g->w[0];
    p->w_callbyte          = g->w[1];
    p->w_authbyte          = g->w[2];
    p->w_effect            = g->w[3];
    p->w_effectbyte        = g->w[4];
    p->w_read              = g->w[5];
    p->w_write             = g->w[6];
    p->max_block_env_bytes = g->max_env_bytes;
    for (uint32_t i = 0; i < g->n_ops; i++)
        if (dna_meter_op_set(p, g->ops[i], g->wts[i]) != 0)
            return NODUS_V2_SPEND_ERR_PINS;
    uint8_t got[64];
    if (dna_meter_policy_seal(p) != 0 ||
        dna_meter_policy_digest(p, got) != 0 ||
        memcmp(got, g->digest, 64) != 0) {
        memset(policy_storage, 0, sizeof(*policy_storage));
        return NODUS_V2_SPEND_ERR_PINS;
    }
    out->core_ruleset_version = g->core_version;
    memcpy(out->core_ruleset_hash, g->core_hash, 64);
    out->meter_policy = p;
    return NODUS_V2_SPEND_OK;
}

int nodus_v2_ruleset_from_pins(nodus_v2_ruleset_id_t *out,
                               dna_meter_policy_t *policy_storage) {
    return nodus_v2_ruleset_from_pins_gen(1, out, policy_storage);
}

/* ── plan ───────────────────────────────────────────────────────────── */

int nodus_v2_spend_plan(const nodus_v2_spend_plan_req_t *req,
                        nodus_v2_coin_t *coins, int n_coins,
                        nodus_v2_spend_plan_t **plans_out, long *count_out,
                        uint64_t *fee_out, nodus_v2_spend_err_t *err) {
    err_reset(err);
    if (!req || !req->rs || !req->rs->meter_policy || !plans_out ||
        !count_out || !fee_out || n_coins < 0 || (n_coins > 0 && !coins) ||
        (req->count_all && !req->amount_all) ||
        (req->amount_all && !req->is_native) ||
        (!req->count_all && req->count < 1) ||
        (!req->amount_all && req->amount == 0))
        return NODUS_V2_SPEND_ERR_ARG;
    *plans_out = NULL;
    *count_out = 0;
    *fee_out = 0;
    if (nodus_v2_spend_sort_coins(coins, n_coins, req->order) != 0)
        return NODUS_V2_SPEND_ERR_ARG;

    const int is_native = req->is_native;
    const int amount_all = req->amount_all;
    const uint64_t amount = req->amount;
    const uint64_t gas_price = req->gas_price;
    uint64_t fee = req->fee;
    long count = req->count;
    nodus_v2_spend_plan_t *plans = NULL;
    int rc;

    /* The chain requires fee >= max(floor, units × gas_price) for a
     * non-SYSTEM envelope (nodus_witness_v2_apply.c env_gas_price_check).
     * `units` depends on the envelope's SHAPE, the shape on the coin
     * selection, and the selection on the fee — so the fee is found by a
     * bounded fixed point: plan at the current fee, price the largest
     * shape the batch uses, and if that needs more, raise the fee to it
     * and plan again from scratch. One fee for the whole batch.
     * gas_price 0 (the rule is off): ONE pass, nothing is priced. A fixed
     * fee is never raised: below what the plan needs, it is refused. */
    for (int pass = 0; ; pass++) {
        uint64_t native_need = fee;
        if (is_native) {
            if (amount > UINT64_MAX - fee) {
                rc = NODUS_V2_SPEND_ERR_OVERFLOW;
                goto fail;
            }
            native_need = amount + fee;
        }
        for (int i = 0; i < n_coins; i++) coins[i].used = 0;
        free(plans);
        plans = NULL;

        /* amount_all: an eligible coin is native and can pay the fee with
         * at least 1 raw left for the output (a zero-value output is a
         * deterministic reject). count_all = every eligible coin. */
        if (req->count_all) {
            long n_elig = 0;
            for (int i = 0; i < n_coins; i++)
                if (coins[i].kind == 0 && coins[i].amount > fee) n_elig++;
            if (n_elig == 0) {
                *fee_out = fee;
                return NODUS_V2_SPEND_NONE_ELIGIBLE;
            }
            count = n_elig;
        }
        *count_out = count;

        plans = calloc((size_t)count, sizeof(*plans));
        if (!plans) { rc = NODUS_V2_SPEND_ERR_ALLOC; goto fail; }
        for (long k = 0; k < count; k++) {
            nodus_v2_spend_plan_t *p = &plans[k];
            int prc = 0;
            if (amount_all) {
                /* largest unused eligible coin first (the sort order) */
                int pick = -1;
                for (int i = 0; i < n_coins; i++)
                    if (!coins[i].used && coins[i].kind == 0 &&
                        coins[i].amount > fee) { pick = i; break; }
                if (pick < 0) {
                    if (err) { err->k = k; err->fee = fee; }
                    rc = NODUS_V2_SPEND_ERR_NO_COIN_ALL;
                    goto fail;
                }
                p->idx[p->n_in++] = pick;
                p->native_in      = coins[pick].amount;
                p->native_change  = 0;
                coins[pick].used  = 1;
                continue;
            }
            if (!is_native) {
                prc = nodus_v2_spend_pick(coins, n_coins, 1, amount, p,
                                          &p->token_in);
                if (prc == 0) p->token_change = p->token_in - amount;
            }
            if (prc == 0) {
                prc = nodus_v2_spend_pick(coins, n_coins, 0, native_need, p,
                                          &p->native_in);
                if (prc == 0) p->native_change = p->native_in - native_need;
            }
            if (prc != 0) {
                if (err) { err->k = k; err->fee = fee; }
                rc = prc == -2 ? NODUS_V2_SPEND_ERR_MAX_INPUTS
                   : prc == -3 ? NODUS_V2_SPEND_ERR_INPUT_SUM
                               : NODUS_V2_SPEND_ERR_INSUFFICIENT;
                goto fail;
            }
            for (int j = 0; j < p->n_in; j++) coins[p->idx[j]].used = 1;
        }

        if (gas_price == 0) break;          /* rule off: one pass */

        /* price the LARGEST shape this batch uses */
        uint64_t max_units = 0;
        for (long k = 0; k < count; k++) {
            const nodus_v2_spend_plan_t *p = &plans[k];
            int n_out = 1 + ((!is_native && p->token_change > 0) ? 1 : 0) +
                        (p->native_change > 0 ? 1 : 0);
            uint64_t u = 0;
            if (nodus_v2_spend_units_for_shape(req->rs->core_ruleset_version,
                                               req->rs->meter_policy,
                                               V2S_AUTH_LEN, p->n_in, n_out,
                                               &u) != 0) {
                if (err) { err->k = k; err->n_in = p->n_in; err->n_out = n_out; }
                rc = NODUS_V2_SPEND_ERR_METER;
                goto fail;
            }
            if (u > max_units) max_units = u;
        }
        if (max_units > UINT64_MAX / gas_price) {
            if (err) { err->units = max_units; err->fee = fee; }
            rc = NODUS_V2_SPEND_ERR_GAS_OVERFLOW;
            goto fail;
        }
        const uint64_t required = max_units * gas_price;
        if (required <= fee) break;         /* the plan's fee covers it */
        if (err) {
            err->units = max_units;
            err->required = required;
            err->fee = fee;
            err->pass = pass;
        }
        if (req->fee_fixed) { rc = NODUS_V2_SPEND_ERR_FEE_BELOW_GAS; goto fail; }
        if (pass >= 7)     { rc = NODUS_V2_SPEND_ERR_FEE_UNSETTLED; goto fail; }
        fee = required;                     /* re-plan at the higher fee */
    }

    err_reset(err);
    *plans_out = plans;
    *fee_out = fee;
    return NODUS_V2_SPEND_OK;

fail:
    free(plans);
    return rc;
}

/* ── read-back ──────────────────────────────────────────────────────── */

static int hex_lower_ok(const uint8_t *s, size_t n) {
    for (size_t i = 0; i < n; i++)
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f')))
            return 0;
    return 1;
}

int nodus_v2_spend_decode(const uint8_t *env, size_t env_len,
                          nodus_v2_spend_decoded_t *out) {
    if (!env || !out) return NODUS_V2_SPEND_ERR_ARG;
    memset(out, 0, sizeof(*out));
    dna_env_view_t *v = calloc(1, sizeof(*v));
    if (!v) return NODUS_V2_SPEND_ERR_ALLOC;
    int rc = NODUS_V2_SPEND_ERR_DECODE;
    if (dna_env_decode(env, env_len, v) != 0 || v->leg_count != 1 ||
        v->leg[0].domain_id != DNA_DOMAIN_CORE ||
        v->leg[0].runtime_op != DNA_CORERULE_SPEND ||
        v->leg[0].access_mode != DNA_ENV_ACCESS_INVOKE)
        goto done;

    /* call = in_count ‖ in_count × nullifier ‖ out_count ‖ records; no
     * byte is read before its length is proved against call_len */
    const uint8_t *c = v->buf + v->call_off[0];
    const size_t clen = v->leg[0].call_len;
    if (clen < 2 || c[0] < 1 || c[0] > NODUS_V2_SPEND_MAX_IN ||
        clen < 2 + (size_t)c[0] * 64)
        goto done;
    const int nin = c[0];
    const int nout = c[1 + (size_t)nin * 64];
    if (nout < 1 || nout > (int)NODUS_V2_SPEND_MAX_OUTS ||
        clen != 2 + (size_t)nin * 64 + (size_t)nout * NODUS_V2_SPEND_OUT_LEN)
        goto done;
    for (int i = 0; i < nin; i++) {
        memcpy(out->in_nul[i], c + 1 + (size_t)i * 64, 64);
        if (i > 0 && memcmp(out->in_nul[i - 1], out->in_nul[i], 64) >= 0)
            goto done;                       /* strictly ascending */
    }
    const uint8_t *recs = c + 2 + (size_t)nin * 64;
    for (int o = 0; o < nout; o++) {
        const uint8_t *r = recs + (size_t)o * NODUS_V2_SPEND_OUT_LEN;
        if (!hex_lower_ok(r, 128)) goto done;
        memcpy(out->out_owner[o], r, 128);
        out->out_owner[o][128] = '\0';
        uint64_t amt = 0;
        for (int b = 0; b < 8; b++) amt = (amt << 8) | r[128 + b];
        if (amt == 0) goto done;
        out->out_amount[o] = amt;
        memcpy(out->out_token[o], r + 136, 64);
        uint8_t pre[160];
        memcpy(pre, r, 128);
        memcpy(pre + 128, r + 200, 32);
        if (qgp_sha3_512(pre, sizeof(pre), out->out_id[o]) != 0) {
            rc = NODUS_V2_SPEND_ERR_HASH;
            goto done;
        }
    }
    out->n_in            = nin;
    out->n_out           = nout;
    out->expiry_height   = v->expiry_height;
    out->fee             = v->fee_amount;
    out->units           = v->res_max_total_units;
    out->ruleset_version = v->leg[0].ruleset_version;
    out->effects         = v->leg[0].res_max_effects;
    out->effect_bytes    = v->leg[0].res_max_effect_bytes;
    rc = NODUS_V2_SPEND_OK;
done:
    if (rc != NODUS_V2_SPEND_OK) memset(out, 0, sizeof(*out));
    free(v);
    return rc;
}

/* ── build ──────────────────────────────────────────────────────────── */

void nodus_v2_spend_built_free(nodus_v2_spend_built_t *b) {
    if (!b) return;
    free(b->env);
    b->env = NULL;
    b->env_len = 0;
}

int nodus_v2_spend_build(const nodus_v2_spend_build_req_t *req,
                         nodus_v2_spend_built_t *out,
                         nodus_v2_spend_err_t *err) {
    err_reset(err);
    if (!out) return NODUS_V2_SPEND_ERR_ARG;
    memset(out, 0, sizeof(*out));
    if (!req || !req->rs || !req->rs->meter_policy || !req->chain32 ||
        !req->pk || !req->sk || !req->to_fp || !req->coins || !req->plan ||
        !req->rand || req->plan->n_in < 1 ||
        req->plan->n_in > (int)NODUS_V2_SPEND_MAX_IN ||
        (req->amount_all && req->token))
        return NODUS_V2_SPEND_ERR_ARG;
    /* The mempool lifetime rule (decision 2026-09-25-mempool-policy.md 1,
     * nodus_types.h NODUS_CMT_APP_MAX_EXPIRY_AHEAD): CheckTx refuses expiry
     * 0 and anything past its tip + 100; the preflight refuses expiry below
     * the candidate tip + 1. A tip of 0 is refused too: the node-reported
     * height is FAIL-OPEN (0 on a read fault — note 2026-09-26 item 2), and
     * an expiry anchored on it would be dead on arrival. */
    if (req->tip == 0 || req->expiry_height <= req->tip ||
        req->expiry_height - req->tip > (uint64_t)NODUS_CMT_APP_MAX_EXPIRY_AHEAD)
        return NODUS_V2_SPEND_ERR_EXPIRY;

    const nodus_v2_spend_plan_t *p = req->plan;
    const int is_native = req->token == NULL;
    int rc = NODUS_V2_SPEND_ERR_ALLOC;
    uint8_t *call = malloc(2 + (size_t)NODUS_V2_SPEND_MAX_IN * 64 +
                           (size_t)NODUS_V2_SPEND_MAX_OUTS *
                               NODUS_V2_SPEND_OUT_LEN);
    uint8_t *auth = calloc(1, V2S_AUTH_LEN);
    dna_env_preflight_t *pf = calloc(1, sizeof(*pf));
    uint8_t *env_bytes = NULL;
    size_t env_len = 0;
    if (!call || !auth || !pf) goto done;

    /* sender fingerprint (the utxo owner form: 128 lowercase hex of
     * SHA3-512(pk)) — every change output's owner; recipient likewise */
    uint8_t sender_raw[64];
    char sender_fp[QGP_FP_HEX_BUFFER], to_fp[QGP_FP_HEX_BUFFER];
    if (qgp_sha3_512(req->pk, V2S_PK_LEN, sender_raw) != 0) {
        rc = NODUS_V2_SPEND_ERR_HASH;
        goto done;
    }
    qgp_fp_raw_to_hex(sender_raw, sender_fp);
    qgp_fp_raw_to_hex(req->to_fp, to_fp);

    /* inputs: strictly ascending nullifiers on the wire */
    uint8_t nulls[NODUS_V2_SPEND_MAX_IN][64];
    for (int j = 0; j < p->n_in; j++)
        memcpy(nulls[j], req->coins[p->idx[j]].nul, 64);
    qsort(nulls, (size_t)p->n_in, 64, nodus_v2_nul_cmp);

    size_t off = 0;
    call[off++] = (uint8_t)p->n_in;
    for (int j = 0; j < p->n_in; j++) { memcpy(call + off, nulls[j], 64); off += 64; }

    /* outputs: recipient first, then the change the plan leaves */
    const char    *o_owner[NODUS_V2_SPEND_MAX_OUTS];
    uint64_t       o_amt[NODUS_V2_SPEND_MAX_OUTS];
    const uint8_t *o_tok[NODUS_V2_SPEND_MAX_OUTS];
    int n_out = 0;
    /* amount_all: this plan's ONE coin minus the fee (> 0 — the planner
     * only picks coins above the fee) */
    if (req->amount_all && p->native_in <= req->fee) {
        rc = NODUS_V2_SPEND_ERR_ARG;
        goto done;
    }
    const uint64_t send_amt = req->amount_all ? p->native_in - req->fee
                                              : req->amount;
    if (send_amt == 0) { rc = NODUS_V2_SPEND_ERR_ARG; goto done; }
    o_owner[n_out] = to_fp; o_amt[n_out] = send_amt;
    o_tok[n_out] = is_native ? NULL : req->token; n_out++;
    if (!is_native && p->token_change > 0) {
        o_owner[n_out] = sender_fp; o_amt[n_out] = p->token_change;
        o_tok[n_out] = req->token; n_out++;
    }
    if (p->native_change > 0) {
        o_owner[n_out] = sender_fp; o_amt[n_out] = p->native_change;
        o_tok[n_out] = NULL; n_out++;
    }
    call[off++] = (uint8_t)n_out;
    uint8_t out_id[NODUS_V2_SPEND_MAX_OUTS][64];
    const uint64_t shard_m = req->shard_m;
    for (int o = 0; o < n_out; o++) {
        /* shard: re-draw the seed until the output id (= the new coin's
         * nullifier) lands in THIS shard — expected shard_m draws; the
         * bound only turns a broken random source into an error */
        const unsigned long max_draws = 64ul * (unsigned long)shard_m + 64ul;
        unsigned long draws = 0;
        for (;;) {
            uint8_t seed[32];
            if (req->rand(req->rand_ctx, seed, sizeof(seed)) != 0) {
                rc = NODUS_V2_SPEND_ERR_RANDOM;
                goto done;
            }
            nodus_v2_xfer_out_put(call + off, o_owner[o], o_amt[o], o_tok[o],
                                  seed);
            /* the output id the chain will derive (rtn_out_ids) */
            uint8_t pre[160];
            memcpy(pre, call + off, 128);
            memcpy(pre + 128, seed, 32);
            if (qgp_sha3_512(pre, sizeof(pre), out_id[o]) != 0) {
                rc = NODUS_V2_SPEND_ERR_HASH;
                goto done;
            }
            if (shard_m <= 1) break;
            uint64_t key = 0;
            for (int b = 0; b < 8; b++) key = (key << 8) | out_id[o][b];
            if (key % shard_m == req->shard_i) break;
            if (++draws >= max_draws) {
                if (err) err->draws = draws;
                rc = NODUS_V2_SPEND_ERR_SHARD_DRAWS;
                goto done;
            }
        }
        off += NODUS_V2_SPEND_OUT_LEN;
    }
    /* two outputs deriving one id is a deterministic chain reject
     * (rtn_out_ids) — only a broken random source gets here */
    for (int a = 0; a < n_out; a++)
        for (int b = a + 1; b < n_out; b++)
            if (memcmp(out_id[a], out_id[b], 64) == 0) {
                rc = NODUS_V2_SPEND_ERR_DUP_OUTPUT;
                goto done;
            }
    const uint32_t call_len = (uint32_t)off;

    dna_env_leg_in_t leg;
    memset(&leg, 0, sizeof(leg));
    leg.hdr.domain_id            = DNA_DOMAIN_CORE;
    leg.hdr.runtime_op           = DNA_CORERULE_SPEND;
    leg.hdr.ruleset_version      = req->rs->core_ruleset_version;
    leg.hdr.access_mode          = DNA_ENV_ACCESS_INVOKE;
    leg.hdr.auth_kind            = NODUS_RT_AUTHKIND_DSA87_MULTI_V1;
    leg.hdr.call_len             = call_len;
    leg.hdr.auth_len             = V2S_AUTH_LEN;
    /* the EXACT effects this leg emits — the units right-sized below price
     * exactly this declaration */
    nodus_v2_spend_effect_decl((uint32_t)p->n_in, (uint32_t)n_out,
                               &leg.hdr.res_max_effects,
                               &leg.hdr.res_max_effect_bytes);
    leg.call_data = call;
    leg.auth_data = auth;                    /* pass 1 needs a zero blob */

    dna_env_in_t env_in;
    memset(&env_in, 0, sizeof(env_in));
    env_in.expiry_height       = req->expiry_height;
    env_in.fee_amount          = req->fee;
    env_in.leg_count           = 1;
    env_in.legs                = &leg;

    uint64_t units = 0;                      /* reads: in_count + 1 */
    if (nodus_v2_spend_ceiling(&env_in, req->rs->meter_policy,
                               (uint32_t)p->n_in + 1u, &units) != 0) {
        rc = NODUS_V2_SPEND_ERR_METER;
        goto done;
    }
    env_in.res_max_total_units = units;
    /* the planner priced this shape already; an envelope whose own units
     * need more than the fee would be refused by every node (code 9).
     * Never true while gas_price 0. */
    if (req->gas_price != 0 &&
        (units > UINT64_MAX / req->gas_price ||
         units * req->gas_price > req->fee)) {
        if (err) { err->units = units; err->fee = req->fee; }
        rc = NODUS_V2_SPEND_ERR_UNITS_OVER_FEE;
        goto done;
    }

    dna_env_leg_ctx_t lctx;
    memset(&lctx, 0, sizeof(lctx));
    lctx.domain_id       = DNA_DOMAIN_CORE;
    lctx.ruleset_version = req->rs->core_ruleset_version;
    memcpy(lctx.ruleset_hash, req->rs->core_ruleset_hash, 64);

    uint8_t *auths[1] = { auth };
    rc = nodus_v2_env_sign_one_key(&env_in, auths, &lctx, req->chain32,
                                   req->tip, req->pk, req->sk, &env_bytes,
                                   &env_len, pf, err);
    if (rc != NODUS_V2_SPEND_OK) goto done;

    /* read back what was BUILT, and refuse if it is not what was asked */
    rc = nodus_v2_spend_decode(env_bytes, env_len, &out->dec);
    if (rc != NODUS_V2_SPEND_OK) goto done;
    rc = NODUS_V2_SPEND_ERR_DECODE;
    if (out->dec.n_in != p->n_in || out->dec.n_out != n_out ||
        out->dec.fee != req->fee || out->dec.units != units ||
        out->dec.expiry_height != req->expiry_height ||
        out->dec.ruleset_version != req->rs->core_ruleset_version ||
        memcmp(out->dec.in_nul, nulls, (size_t)p->n_in * 64) != 0)
        goto done;
    for (int o = 0; o < n_out; o++) {
        static const uint8_t zero64[64] = {0};
        const uint8_t *tok = o_tok[o] ? o_tok[o] : zero64;
        if (memcmp(out->dec.out_owner[o], o_owner[o], 128) != 0 ||
            out->dec.out_amount[o] != o_amt[o] ||
            memcmp(out->dec.out_token[o], tok, 64) != 0 ||
            memcmp(out->dec.out_id[o], out_id[o], 64) != 0)
            goto done;
    }

    memcpy(out->wire_id, pf->wire_id, 64);
    memcpy(out->intent_id, pf->intent_id, 64);
    out->env = env_bytes;
    out->env_len = env_len;
    env_bytes = NULL;
    rc = NODUS_V2_SPEND_OK;

done:
    if (rc != NODUS_V2_SPEND_OK) memset(&out->dec, 0, sizeof(out->dec));
    free(env_bytes);
    free(pf);
    free(auth);
    free(call);
    return rc;
}
