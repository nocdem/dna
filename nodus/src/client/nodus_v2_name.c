/**
 * @file nodus/src/client/nodus_v2_name.c
 * @brief The shared CORE NAME_REGISTER envelope builder (HF-4 on-chain
 *        names) — see nodus_v2_name.h for the contract.
 *
 * Moved out of nodus/tools/nodus-cli.c cmd_name_register (`name register`):
 * the ASCII-only lower-casing (t8_name_lower), the effect declaration
 * (t8_name_effect_decl), the price tier index, the coin filter, the
 * largest-first selection with its 13-input cap, the call layout, the leg
 * header, the units ceiling and the gas-price fixed point are the CLI's,
 * unchanged. What changed is the surface: no printing (a refusal is a code
 * plus the numbers in nodus_v2_name_err_t, the CLI prints), no network, the
 * ruleset identity and the change-seed source are inputs, and the built
 * bytes are decoded back and compared with the request before they are
 * returned.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "client/nodus_v2_name.h"
#include "nodus/nodus_types.h"             /* NODUS_W_BASE_TX_FEE,
                                            * NODUS_CMT_APP_MAX_EXPIRY_AHEAD */
#include "witness/nodus_witness_runtime.h" /* DNA_CORERULE_NAME_REGISTER,
                                            * NODUS_RT_AUTH*, NODUS_RT_CORE_
                                            * UTXO_REC_LEN — header constants
                                            * only, no witness link         */
#include "dnac/effect_wire.h"              /* DNA_EFFECT_FIXED_HEAD / _RECORD_LEN */
#include "dnac/msig_wire.h"                /* HF-8: descriptor parse, address */
#include "crypto/hash/qgp_sha3.h"
#include "crypto/utils/qgp_fingerprint.h"

#include <stdlib.h>
#include <string.h>

#include "crypto/utils/qgp_safe_string.h"   /* Phase 03: unsafe-string poison guard */

#define V2N_PK_LEN   2592u
#define V2N_AUTH_LEN (1u + NODUS_RT_AUTH_SIGNER_LEN)   /* count 1 ‖ pk ‖ sig */
#define V2N_FLOOR    (DNAC_MIN_FEE_RAW > NODUS_W_BASE_TX_FEE \
                          ? (uint64_t)DNAC_MIN_FEE_RAW       \
                          : (uint64_t)NODUS_W_BASE_TX_FEE)

_Static_assert(V2N_PK_LEN == DNAC_PUBKEY_SIZE, "ML-DSA-87 public key width");
_Static_assert(NODUS_V2_NAME_MAX_IN <= NODUS_V2_SPEND_MAX_IN,
               "the name input cap is inside the selection cap");
_Static_assert(DNAC_NAME_MAX_LEN < 256u, "name_len is one byte on the wire");

static void err_reset(nodus_v2_name_err_t *err) {
    if (err) memset(err, 0, sizeof(*err));
}

static int hex_lower_ok(const uint8_t *s, size_t n) {
    for (size_t i = 0; i < n; i++)
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f')))
            return 0;
    return 1;
}

static void put_u64(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (56 - 8 * i));
}

static uint64_t get_u64(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | p[i];
    return v;
}

/* ── the name, its price, its effect declaration ─────────────────── */

int nodus_v2_name_normalize(const char *in, char out[DNAC_NAME_MAX_LEN + 1]) {
    if (!in || !out) return -1;
    const size_t n = strnlen(in, DNAC_NAME_MAX_LEN + 1u);
    if (n > DNAC_NAME_MAX_LEN) return -1;
    for (size_t i = 0; i < n; i++) {
        const char c = in[i];
        out[i] = (c >= 'A' && c <= 'Z') ? (char)(c - 'A' + 'a') : c;
    }
    out[n] = '\0';
    return dnac_name_bytes_ok((const uint8_t *)out, n) ? 0 : -1;
}

int nodus_v2_name_price_for(const uint64_t price[4], size_t name_len,
                            uint64_t *out) {
    if (!price || !out || name_len < DNAC_NAME_MIN_LEN ||
        name_len > DNAC_NAME_MAX_LEN)
        return -1;
    *out = price[name_len >= 6 ? 3 : name_len - 3];
    return 0;
}

void nodus_v2_name_effect_decl(uint32_t n_in, uint32_t n_out,
                               uint32_t name_len, uint32_t *effects_out,
                               uint32_t *bytes_out) {
    const uint32_t effects = n_in + n_out + 2u;
    *effects_out = effects;
    *bytes_out = (uint32_t)DNA_EFFECT_FIXED_HEAD +
                 (uint32_t)DNA_EFFECT_RECORD_LEN * effects +
                 n_out * (64u + NODUS_RT_CORE_UTXO_REC_LEN) +
                 (name_len + 72u) + (1u + 8u) + n_in * 64u;
}

/* ── read-back ──────────────────────────────────────────────────────── */

/* The NAME_REGISTER call of leg 0 of `v` and its effect declaration, read
 * strictly into `out` (name, price, inputs, the 0 / 1 change): name_len ‖
 * name ‖ price ‖ in_count ‖ nullifiers ‖ out_count ‖ outs — every length
 * proved before the read it guards. The ONE call reader of this module
 * (nodus_v2_name_decode for the single-key envelope, nodus_v2_name_msig_
 * review for the vault's). @return NODUS_V2_SPEND_OK /
 * NODUS_V2_SPEND_ERR_DECODE (any shape refusal) / NODUS_V2_SPEND_ERR_HASH. */
static int v2n_call_read(const dna_env_view_t *v,
                         nodus_v2_name_decoded_t *out) {
    const uint8_t *c = v->buf + v->call_off[0];
    const size_t clen = v->leg[0].call_len;
    if (clen < 1) return NODUS_V2_SPEND_ERR_DECODE;
    const size_t nl = c[0];
    if (nl < DNAC_NAME_MIN_LEN || nl > DNAC_NAME_MAX_LEN ||
        clen < 1 + nl + 8 + 1)
        return NODUS_V2_SPEND_ERR_DECODE;
    if (!dnac_name_bytes_ok(c + 1, nl)) return NODUS_V2_SPEND_ERR_DECODE;
    memcpy(out->name, c + 1, nl);
    out->name[nl] = '\0';
    out->price = get_u64(c + 1 + nl);
    if (out->price == 0) return NODUS_V2_SPEND_ERR_DECODE;
    size_t off = 1 + nl + 8;
    const int nin = c[off++];
    if (nin < 1 || nin > (int)NODUS_V2_NAME_MAX_IN ||
        clen < off + (size_t)nin * 64 + 1)
        return NODUS_V2_SPEND_ERR_DECODE;
    for (int i = 0; i < nin; i++) {
        memcpy(out->in_nul[i], c + off, 64);
        off += 64;
        if (i > 0 && memcmp(out->in_nul[i - 1], out->in_nul[i], 64) >= 0)
            return NODUS_V2_SPEND_ERR_DECODE;    /* strictly ascending */
    }
    const int nout = c[off++];
    if (nout > (int)NODUS_V2_NAME_MAX_OUTS ||
        clen != off + (size_t)nout * NODUS_V2_SPEND_OUT_LEN)
        return NODUS_V2_SPEND_ERR_DECODE;
    if (nout == 1) {
        static const uint8_t zero64[64] = {0};
        const uint8_t *r = c + off;
        if (!hex_lower_ok(r, 128)) return NODUS_V2_SPEND_ERR_DECODE;
        memcpy(out->change_owner, r, 128);
        out->change_owner[128] = '\0';
        out->change_amount = get_u64(r + 128);
        if (out->change_amount == 0) return NODUS_V2_SPEND_ERR_DECODE;
        if (memcmp(r + 136, zero64, 64) != 0)
            return NODUS_V2_SPEND_ERR_DECODE;    /* native only */
        uint8_t pre[160];
        memcpy(pre, r, 128);
        memcpy(pre + 128, r + 200, 32);
        if (qgp_sha3_512(pre, sizeof(pre), out->change_id) != 0)
            return NODUS_V2_SPEND_ERR_HASH;
    }
    uint32_t eff = 0, effb = 0;
    nodus_v2_name_effect_decl((uint32_t)nin, (uint32_t)nout, (uint32_t)nl,
                              &eff, &effb);
    if (v->leg[0].res_max_effects != eff ||
        v->leg[0].res_max_effect_bytes != effb)
        return NODUS_V2_SPEND_ERR_DECODE;

    out->n_in                 = nin;
    out->n_out                = nout;
    out->effects              = eff;
    out->effect_bytes         = effb;
    out->expiry_height        = v->expiry_height;
    out->fee                  = v->fee_amount;
    out->units                = v->res_max_total_units;
    out->core_ruleset_version = v->leg[0].ruleset_version;
    return NODUS_V2_SPEND_OK;
}

int nodus_v2_name_decode(const uint8_t *env, size_t env_len,
                         nodus_v2_name_decoded_t *out) {
    if (!env || !out) return NODUS_V2_SPEND_ERR_ARG;
    memset(out, 0, sizeof(*out));
    dna_env_view_t *v = calloc(1, sizeof(*v));
    if (!v) return NODUS_V2_SPEND_ERR_ALLOC;
    int rc = NODUS_V2_SPEND_ERR_DECODE;
    if (dna_env_decode(env, env_len, v) != 0 || v->leg_count != 1)
        goto done;
    if (v->leg[0].domain_id != DNA_DOMAIN_CORE ||
        v->leg[0].runtime_op != DNA_CORERULE_NAME_REGISTER ||
        v->leg[0].access_mode != DNA_ENV_ACCESS_INVOKE ||
        v->leg[0].auth_kind != NODUS_RT_AUTHKIND_DSA87_MULTI_V1 ||
        v->leg[0].auth_len != V2N_AUTH_LEN)
        goto done;

    /* the auth blob: exactly one signer (the owner, rtn op 8) */
    const uint8_t *a = v->buf + v->auth_off[0];
    if (a[0] != 1) goto done;
    memcpy(out->owner_pk, a + 1, V2N_PK_LEN);

    rc = v2n_call_read(v, out);
done:
    if (rc != NODUS_V2_SPEND_OK) memset(out, 0, sizeof(*out));
    free(v);
    return rc;
}

/* ── build ──────────────────────────────────────────────────────────── */

void nodus_v2_name_built_free(nodus_v2_name_built_t *b) {
    if (!b) return;
    free(b->env);
    b->env = NULL;
    b->env_len = 0;
}

/* What the builder asked for — the read-back predicate's input. */
typedef struct {
    const nodus_v2_name_req_t *req;
    uint64_t       fee, units;
    int            n_in;
    const uint8_t (*nulls)[64];             /* ascending, as on the wire     */
    uint32_t       n_out;
    uint64_t       change;
    const char    *owner_fp;                /* 128 hex, the change's owner   */
    const uint8_t *change_seed;             /* 32 bytes (when n_out)         */
} v2n_rb_t;

/* THE read-back predicate: decode `env` and refuse unless it is what the
 * request asked for — name, price, fee, units, expiry, ruleset, the owner
 * key, the exact inputs, and the change output (owner, amount, id). It runs
 * on the UNSIGNED bytes before any signature (v2n_presign_check; the signer
 * hands over the pass-1 bytes with `count 1 ‖ pk` in the auth blob and a
 * zero signature, so the owner key IS compared pre-sign) and again on the
 * signed bytes: the same code in both runs. Only the signature itself is
 * not judged here. @return OK / _ERR_DECODE (mismatch) / the decoder's code. */
static int v2n_readback(const v2n_rb_t *rb, const uint8_t *env, size_t len,
                        nodus_v2_name_decoded_t *d) {
    const nodus_v2_name_req_t *req = rb->req;
    int rc = nodus_v2_name_decode(env, len, d);
    if (rc != NODUS_V2_SPEND_OK) return rc;
    if (strcmp(d->name, req->name) != 0 || d->price != req->price ||
        d->fee != rb->fee || d->units != rb->units ||
        d->expiry_height != req->expiry_height ||
        d->core_ruleset_version != req->rs->core_ruleset_version ||
        memcmp(d->owner_pk, req->pk, V2N_PK_LEN) != 0 ||
        d->n_in != rb->n_in ||
        memcmp(d->in_nul, rb->nulls, (size_t)rb->n_in * 64) != 0 ||
        d->n_out != (int)rb->n_out)
        return NODUS_V2_SPEND_ERR_DECODE;
    if (rb->n_out) {
        uint8_t pre[160], change_id[64];
        memcpy(pre, rb->owner_fp, 128);
        memcpy(pre + 128, rb->change_seed, 32);
        if (qgp_sha3_512(pre, sizeof(pre), change_id) != 0)
            return NODUS_V2_SPEND_ERR_HASH;
        if (memcmp(d->change_owner, rb->owner_fp, 128) != 0 ||
            d->change_amount != rb->change ||
            memcmp(d->change_id, change_id, 64) != 0)
            return NODUS_V2_SPEND_ERR_DECODE;
    }
    return NODUS_V2_SPEND_OK;
}

static int v2n_presign_check(const uint8_t *env, size_t len, void *ctx) {
    nodus_v2_name_decoded_t d;
    return v2n_readback((const v2n_rb_t *)ctx, env, len, &d) ==
                   NODUS_V2_SPEND_OK ? 0 : -1;
}

int nodus_v2_name_build(const nodus_v2_name_req_t *req,
                        nodus_v2_name_built_t *out,
                        nodus_v2_name_err_t *err) {
    err_reset(err);
    if (!out) return NODUS_V2_SPEND_ERR_ARG;
    memset(out, 0, sizeof(*out));
    if (!req || !req->rs || !req->rs->meter_policy || !req->chain32 ||
        !req->pk || !req->sk || !req->name || !req->rand ||
        req->n_coins < 0 || (req->n_coins > 0 && !req->coins))
        return NODUS_V2_SPEND_ERR_ARG;

    /* what the request alone decides */
    const size_t name_len = strnlen(req->name, DNAC_NAME_MAX_LEN + 1u);
    if (!dnac_name_bytes_ok((const uint8_t *)req->name, name_len))
        return NODUS_V2_NAME_ERR_NAME;
    if (req->price == 0) return NODUS_V2_NAME_ERR_PRICE;
    /* the mempool lifetime rule (decision 2026-09-25-mempool-policy.md 1);
     * a 0 tip is a FAIL-OPEN height read and is refused (CHECKTX-P1 r3) */
    if (req->tip == 0 || req->expiry_height <= req->tip ||
        req->expiry_height - req->tip > (uint64_t)NODUS_CMT_APP_MAX_EXPIRY_AHEAD)
        return NODUS_V2_SPEND_ERR_EXPIRY;
    uint64_t fee = V2N_FLOOR;
    if (req->fee_fixed) {
        if (req->fee < V2N_FLOOR) {
            if (err) { err->fee = req->fee; err->floor = V2N_FLOOR; }
            return NODUS_V2_NAME_ERR_FEE_FLOOR;
        }
        fee = req->fee;
    }

    int rc = NODUS_V2_SPEND_ERR_ALLOC;
    nodus_v2_coin_t *coins = NULL;
    uint8_t *call = NULL, *auth = NULL, *env_bytes = NULL;
    size_t env_len = 0;
    dna_env_preflight_t *pf = NULL;

    /* ── the eligible coins: native, non-zero, unlocked at tip + 1 ──── */
    int n_coins = 0;
    {
        static const uint8_t native_tok[64] = {0};
        coins = calloc((size_t)(req->n_coins > 0 ? req->n_coins : 1),
                       sizeof(*coins));
        if (!coins) goto done;
        for (int i = 0; i < req->n_coins; i++) {
            const nodus_v2_name_coin_t *e = &req->coins[i];
            if (e->amount == 0) continue;
            if (memcmp(e->token, native_tok, 64) != 0) continue;
            if (e->unlock_block >= req->tip + 1) continue;  /* locked at
                                                              * tip + 1  */
            nodus_v2_coin_t *c = &coins[n_coins++];
            memcpy(c->nul, e->nul, 64);
            c->amount = e->amount;
            c->kind = 0;
            c->used = 0;
        }
    }
    if (err) err->n_eligible = n_coins;
    if (nodus_v2_spend_sort_coins(coins, n_coins,
                                  NODUS_V2_SPEND_ORDER_LARGEST_FIRST) != 0) {
        rc = NODUS_V2_SPEND_ERR_ARG;
        goto done;
    }

    call = malloc(NODUS_V2_NAME_CALL_MAX);
    auth = calloc(1, V2N_AUTH_LEN);
    pf   = calloc(1, sizeof(*pf));
    if (!call || !auth || !pf) goto done;

    dna_env_leg_ctx_t lctx;
    memset(&lctx, 0, sizeof(lctx));
    lctx.domain_id       = DNA_DOMAIN_CORE;
    lctx.ruleset_version = req->rs->core_ruleset_version;
    memcpy(lctx.ruleset_hash, req->rs->core_ruleset_hash, 64);

    char owner_fp[QGP_FP_HEX_BUFFER];
    {
        uint8_t owner_raw[64];
        if (qgp_sha3_512(req->pk, V2N_PK_LEN, owner_raw) != 0) {
            rc = NODUS_V2_SPEND_ERR_HASH;
            goto done;
        }
        qgp_fp_raw_to_hex(owner_raw, owner_fp);
    }

    nodus_v2_spend_plan_t plan;
    uint8_t nulls[NODUS_V2_SPEND_MAX_IN][64];
    dna_env_leg_in_t leg;
    dna_env_in_t env_in;
    uint64_t units = 0, change = 0, need = 0;
    uint32_t n_out = 0;
    uint8_t change_seed[32];
    int pass;
    memset(change_seed, 0, sizeof(change_seed));
    for (pass = 0; ; pass++) {
        if (err) { err->fee = fee; err->price = req->price; err->pass = pass; }
        if (fee > UINT64_MAX - req->price) {
            rc = NODUS_V2_SPEND_ERR_OVERFLOW;
            goto done;
        }
        need = fee + req->price;
        memset(&plan, 0, sizeof(plan));
        for (int i = 0; i < n_coins; i++) coins[i].used = 0;
        int prc = nodus_v2_spend_pick(coins, n_coins, 0, need, &plan,
                                      &plan.native_in);
        if (prc == 0 && plan.n_in > (int)NODUS_V2_NAME_MAX_IN) prc = -2;
        if (prc != 0) {
            if (err) err->n_in = plan.n_in;
            rc = prc == -2 ? NODUS_V2_SPEND_ERR_MAX_INPUTS
               : prc == -3 ? NODUS_V2_SPEND_ERR_INPUT_SUM
               : NODUS_V2_SPEND_ERR_INSUFFICIENT;
            goto done;
        }
        change = plan.native_in - need;

        for (int j = 0; j < plan.n_in; j++)
            memcpy(nulls[j], coins[plan.idx[j]].nul, 64);
        qsort(nulls, (size_t)plan.n_in, 64, nodus_v2_nul_cmp);

        /* name_len ‖ name ‖ price u64 BE ‖ in_count ‖ nullifiers ‖
         * out_count ‖ the change record */
        size_t off = 0;
        call[off++] = (uint8_t)name_len;
        memcpy(call + off, req->name, name_len);     off += name_len;
        put_u64(call + off, req->price);             off += 8;
        call[off++] = (uint8_t)plan.n_in;
        for (int j = 0; j < plan.n_in; j++) {
            memcpy(call + off, nulls[j], 64);
            off += 64;
        }
        n_out = change > 0 ? 1u : 0u;
        call[off++] = (uint8_t)n_out;
        if (n_out) {
            if (req->rand(req->rand_ctx, change_seed, sizeof(change_seed))
                != 0) {
                rc = NODUS_V2_SPEND_ERR_RANDOM;
                goto done;
            }
            nodus_v2_xfer_out_put(call + off, owner_fp, change, NULL,
                                  change_seed);
            off += NODUS_V2_SPEND_OUT_LEN;
        }

        memset(&leg, 0, sizeof(leg));
        leg.hdr.domain_id       = DNA_DOMAIN_CORE;
        leg.hdr.runtime_op      = DNA_CORERULE_NAME_REGISTER;
        leg.hdr.ruleset_version = req->rs->core_ruleset_version;
        leg.hdr.access_mode     = DNA_ENV_ACCESS_INVOKE;
        leg.hdr.auth_kind       = NODUS_RT_AUTHKIND_DSA87_MULTI_V1;
        leg.hdr.call_len        = (uint32_t)off;
        leg.hdr.auth_len        = V2N_AUTH_LEN;
        nodus_v2_name_effect_decl((uint32_t)plan.n_in, n_out,
                                  (uint32_t)name_len,
                                  &leg.hdr.res_max_effects,
                                  &leg.hdr.res_max_effect_bytes);
        leg.call_data = call;
        memset(auth, 0, V2N_AUTH_LEN);
        leg.auth_data = auth;

        memset(&env_in, 0, sizeof(env_in));
        env_in.expiry_height = req->expiry_height;
        env_in.fee_amount    = fee;
        env_in.leg_count     = 1;
        env_in.legs          = &leg;
        /* reads: inputs + the pool + NAME + OWNER (read plan) */
        if (nodus_v2_spend_ceiling(&env_in, req->rs->meter_policy,
                                   (uint32_t)plan.n_in + 3u, &units) != 0) {
            rc = NODUS_V2_SPEND_ERR_METER;
            goto done;
        }
        env_in.res_max_total_units = units;
        if (err) { err->units = units; err->n_in = plan.n_in; }
        if (req->gas_price == 0) break;
        if (units > UINT64_MAX / req->gas_price) {
            if (err) err->gas_price = req->gas_price;
            rc = NODUS_V2_SPEND_ERR_GAS_OVERFLOW;
            goto done;
        }
        const uint64_t required = units * req->gas_price;
        if (required <= fee) break;
        if (err) { err->gas_price = req->gas_price; err->required = required; }
        if (req->fee_fixed) {
            rc = NODUS_V2_SPEND_ERR_FEE_BELOW_GAS;
            goto done;
        }
        if (pass >= NODUS_V2_NAME_MAX_PASSES - 1) {
            rc = NODUS_V2_SPEND_ERR_FEE_UNSETTLED;
            goto done;
        }
        fee = required;
    }

    v2n_rb_t rb;
    memset(&rb, 0, sizeof(rb));
    rb.req         = req;
    rb.fee         = fee;
    rb.units       = units;
    rb.n_in        = plan.n_in;
    rb.nulls       = (const uint8_t (*)[64])nulls;
    rb.n_out       = n_out;
    rb.change      = change;
    rb.owner_fp    = owner_fp;
    rb.change_seed = change_seed;
    {
        uint8_t *auths[1] = { auth };
        nodus_v2_spend_err_t se;
        memset(&se, 0, sizeof(se));
        /* "nothing is signed on a mismatch": v2n_readback runs on the
         * unsigned bytes first (a refusal is _ERR_PRESIGN_CHECK) */
        rc = nodus_v2_env_sign_one_key_checked(&env_in, auths, &lctx,
                                               req->chain32, req->tip,
                                               req->pk, req->sk, &env_bytes,
                                               &env_len, pf, &se,
                                               v2n_presign_check, &rb);
        if (rc != NODUS_V2_SPEND_OK) {
            if (err) err->leg = se.leg;
            goto done;
        }
    }

    /* ── read back what was BUILT, and refuse if it is not what was
     *    asked ─────────────────────────────────────────────────────── */
    rc = v2n_readback(&rb, env_bytes, env_len, &out->dec);
    if (rc != NODUS_V2_SPEND_OK) goto done;

    memcpy(out->wire_id, pf->wire_id, 64);
    memcpy(out->intent_id, pf->intent_id, 64);
    out->fee     = fee;
    out->price   = req->price;
    out->sum_in  = plan.native_in;
    out->change  = change;
    out->units   = units;
    out->n_in    = plan.n_in;
    out->passes  = pass + 1;
    out->env     = env_bytes;
    out->env_len = env_len;
    env_bytes = NULL;
    rc = NODUS_V2_SPEND_OK;

done:
    if (rc != NODUS_V2_SPEND_OK) memset(&out->dec, 0, sizeof(out->dec));
    /* a refused signed buffer and the auth blob that held its signature are
     * wiped before they are freed */
    if (env_bytes) memset(env_bytes, 0, env_len);
    free(env_bytes);
    free(pf);
    if (auth) memset(auth, 0, V2N_AUTH_LEN);
    free(auth);
    free(call);
    free(coins);
    return rc;
}

/* ══ HF-8 — the vault's NAME_REGISTER (contract: nodus_v2_name.h) ═════ */

void nodus_v2_name_msig_built_free(nodus_v2_name_msig_built_t *b) {
    if (!b) return;
    free(b->env);
    memset(b, 0, sizeof(*b));
}

int nodus_v2_name_msig_build(const nodus_v2_name_msig_req_t *req,
                             nodus_v2_name_msig_built_t *out,
                             nodus_v2_name_err_t *err) {
    err_reset(err);
    if (!out) return NODUS_V2_SPEND_ERR_ARG;
    memset(out, 0, sizeof(*out));
    if (!req || !req->rs || !req->rs->meter_policy || !req->chain32 ||
        !req->desc || !req->name || !req->rand || !req->coins ||
        req->n_coins < 1 || req->n_coins > (int)NODUS_V2_NAME_MAX_IN)
        return NODUS_V2_SPEND_ERR_ARG;

    /* what the request alone decides */
    const size_t name_len = strnlen(req->name, DNAC_NAME_MAX_LEN + 1u);
    if (!dnac_name_bytes_ok((const uint8_t *)req->name, name_len))
        return NODUS_V2_NAME_ERR_NAME;
    if (req->price == 0) return NODUS_V2_NAME_ERR_PRICE;
    /* the co-signer window (nodus_v2_msig_review's rule): a 0 tip is a
     * FAIL-OPEN height read; an expiry past tip + 90 is refused by every
     * co-signer's read-back, so it is refused here first */
    if (req->tip == 0 || req->expiry_height <= req->tip ||
        req->expiry_height - req->tip > (uint64_t)NODUS_V2_MSIG_EXPIRY_AHEAD)
        return NODUS_V2_SPEND_ERR_EXPIRY;

    uint8_t m = 0, n = 0;
    if (dna_msig_desc_parse(req->desc, req->desc_len, &m, &n, NULL) != 0)
        return NODUS_V2_MSIG_ERR_DESC;
    uint8_t addr[64];
    {
        const int arc = dna_msig_address(req->desc, req->desc_len, addr);
        if (arc == -2) return NODUS_V2_SPEND_ERR_HASH;
        if (arc != 0) return NODUS_V2_MSIG_ERR_DESC;
    }
    const uint32_t k = req->signers ? req->signers : m;
    if (k < m || k > n) return NODUS_V2_MSIG_ERR_SIGNERS;
    char addr_hex[QGP_FP_HEX_BUFFER];
    qgp_fp_raw_to_hex(addr, addr_hex);

    /* the coins: every one spent, ascending for the wire, no duplicate,
     * none zero (the chain checks that each is the vault's) */
    nodus_v2_coin_t ins[NODUS_V2_NAME_MAX_IN];
    const int n_in = req->n_coins;
    uint64_t sum_in = 0;
    memcpy(ins, req->coins, (size_t)n_in * sizeof(ins[0]));
    for (int i = 0; i < n_in; i++) {
        if (ins[i].amount == 0) return NODUS_V2_MSIG_ERR_COIN;
        if (sum_in > UINT64_MAX - ins[i].amount)
            return NODUS_V2_SPEND_ERR_INPUT_SUM;
        sum_in += ins[i].amount;
    }
    qsort(ins, (size_t)n_in, sizeof(ins[0]), nodus_v2_nul_cmp);
    for (int i = 1; i < n_in; i++)
        if (memcmp(ins[i - 1].nul, ins[i].nul, 64) == 0)
            return NODUS_V2_MSIG_ERR_COIN;

    uint64_t fee = V2N_FLOOR;
    if (req->fee_fixed) {
        if (req->fee < V2N_FLOOR) {
            if (err) { err->fee = req->fee; err->floor = V2N_FLOOR; }
            return NODUS_V2_NAME_ERR_FEE_FLOOR;
        }
        fee = req->fee;
    }

    const uint32_t alen = 1u + k * NODUS_RT_AUTH_SIGNER_LEN + 3u +
                          (uint32_t)req->desc_len;
    int rc = NODUS_V2_SPEND_ERR_ALLOC;
    uint8_t *call = malloc(NODUS_V2_NAME_CALL_MAX);
    uint8_t *auth = calloc(1, alen);
    dna_env_preflight_t *pf = calloc(1, sizeof(*pf));
    dna_env_view_t *v = calloc(1, sizeof(*v));
    nodus_v2_name_decoded_t *dec = calloc(1, sizeof(*dec));
    uint8_t *env_bytes = NULL;
    if (!call || !auth || !pf || !v || !dec) goto done;
    {
        size_t al = 0;
        rc = nodus_v2_msig_unsigned_auth(k, req->desc, req->desc_len, auth,
                                         alen, &al);
        if (rc != NODUS_V2_SPEND_OK || al != alen) {
            rc = NODUS_V2_SPEND_ERR_ARG;
            goto done;
        }
    }

    dna_env_leg_in_t leg;
    dna_env_in_t env_in;
    uint64_t units = 0, change = 0;
    uint32_t n_out = 0;
    uint8_t change_seed[32];
    int pass;
    memset(change_seed, 0, sizeof(change_seed));
    for (pass = 0; ; pass++) {
        if (err) {
            err->fee = fee; err->price = req->price; err->pass = pass;
            err->n_in = n_in; err->n_eligible = n_in;
        }
        if (req->price > sum_in || fee > sum_in - req->price) {
            rc = NODUS_V2_SPEND_ERR_INSUFFICIENT;
            goto done;
        }
        change = sum_in - req->price - fee;

        /* name_len ‖ name ‖ price u64 BE ‖ in_count ‖ nullifiers ‖
         * out_count ‖ the change record (to the VAULT) */
        size_t off = 0;
        call[off++] = (uint8_t)name_len;
        memcpy(call + off, req->name, name_len);     off += name_len;
        put_u64(call + off, req->price);             off += 8;
        call[off++] = (uint8_t)n_in;
        for (int j = 0; j < n_in; j++) {
            memcpy(call + off, ins[j].nul, 64);
            off += 64;
        }
        n_out = change > 0 ? 1u : 0u;
        call[off++] = (uint8_t)n_out;
        if (n_out) {
            if (req->rand(req->rand_ctx, change_seed, sizeof(change_seed))
                != 0) {
                rc = NODUS_V2_SPEND_ERR_RANDOM;
                goto done;
            }
            nodus_v2_xfer_out_put(call + off, addr_hex, change, NULL,
                                  change_seed);
            off += NODUS_V2_SPEND_OUT_LEN;
        }

        memset(&leg, 0, sizeof(leg));
        leg.hdr.domain_id       = DNA_DOMAIN_CORE;
        leg.hdr.runtime_op      = DNA_CORERULE_NAME_REGISTER;
        leg.hdr.ruleset_version = req->rs->core_ruleset_version;
        leg.hdr.access_mode     = DNA_ENV_ACCESS_INVOKE;
        leg.hdr.auth_kind       = NODUS_RT_AUTHKIND_DSA87_MSIG_V1;
        leg.hdr.call_len        = (uint32_t)off;
        leg.hdr.auth_len        = alen;
        nodus_v2_name_effect_decl((uint32_t)n_in, n_out, (uint32_t)name_len,
                                  &leg.hdr.res_max_effects,
                                  &leg.hdr.res_max_effect_bytes);
        leg.call_data = call;
        leg.auth_data = auth;

        memset(&env_in, 0, sizeof(env_in));
        env_in.expiry_height = req->expiry_height;
        env_in.fee_amount    = fee;
        env_in.leg_count     = 1;
        env_in.legs          = &leg;
        /* reads: inputs + the pool + NAME + OWNER (read plan) */
        if (nodus_v2_spend_ceiling(&env_in, req->rs->meter_policy,
                                   (uint32_t)n_in + 3u, &units) != 0) {
            rc = NODUS_V2_SPEND_ERR_METER;
            goto done;
        }
        env_in.res_max_total_units = units;
        if (err) err->units = units;
        if (req->gas_price == 0) break;
        if (units > UINT64_MAX / req->gas_price) {
            if (err) err->gas_price = req->gas_price;
            rc = NODUS_V2_SPEND_ERR_GAS_OVERFLOW;
            goto done;
        }
        const uint64_t required = units * req->gas_price;
        if (required <= fee) break;
        if (err) { err->gas_price = req->gas_price; err->required = required; }
        if (req->fee_fixed) {
            rc = NODUS_V2_SPEND_ERR_FEE_BELOW_GAS;
            goto done;
        }
        if (pass >= NODUS_V2_NAME_MAX_PASSES - 1) {
            rc = NODUS_V2_SPEND_ERR_FEE_UNSETTLED;
            goto done;
        }
        fee = required;
    }

    /* ── pass 1: the unsigned envelope and its leg digest ──────────────── */
    size_t env_len = 0, used = 0;
    rc = NODUS_V2_SPEND_ERR_ENCODE;
    if (dna_env_encoded_size(env_in.legs, env_in.leg_count, &env_len) != 0)
        goto done;
    env_bytes = malloc(env_len);
    if (!env_bytes) { rc = NODUS_V2_SPEND_ERR_ALLOC; goto done; }
    if (dna_env_encode(&env_in, env_bytes, env_len, &used) != 0 ||
        used != env_len)
        goto done;
    {
        nodus_v2_msig_export_t x;
        memset(&x, 0, sizeof(x));
        memcpy(x.chain32, req->chain32, DNA_CHAIN_ID_LEN);
        x.tip = req->tip;
        x.signers = k;
        x.env = env_bytes;
        x.env_len = env_len;
        rc = nodus_v2_msig_digest(&x, req->rs->core_ruleset_version,
                                  req->rs->core_ruleset_hash, pf);
        if (rc != NODUS_V2_SPEND_OK) goto done;
    }

    /* ── read back what was BUILT, and refuse if it is not what was
     *    asked (the single-key builder's discipline) ─────────────────── */
    rc = NODUS_V2_SPEND_ERR_DECODE;
    if (dna_env_decode(env_bytes, env_len, v) != 0 || v->leg_count != 1)
        goto done;
    {
        const int crc = v2n_call_read(v, dec);
        if (crc != NODUS_V2_SPEND_OK) { rc = crc; goto done; }
    }
    rc = NODUS_V2_SPEND_ERR_DECODE;
    if (strcmp(dec->name, req->name) != 0 || dec->price != req->price ||
        dec->fee != fee || dec->units != units ||
        dec->expiry_height != req->expiry_height ||
        dec->core_ruleset_version != req->rs->core_ruleset_version ||
        dec->n_in != n_in || dec->n_out != (int)n_out)
        goto done;
    for (int j = 0; j < n_in; j++)
        if (memcmp(dec->in_nul[j], ins[j].nul, 64) != 0) goto done;
    if (n_out &&
        (memcmp(dec->change_owner, addr_hex, 128) != 0 ||
         dec->change_amount != change))
        goto done;

    out->env       = env_bytes;
    env_bytes      = NULL;
    out->env_len   = env_len;
    memcpy(out->digest, pf->auth_digest[0], 64);
    memcpy(out->intent_id, pf->intent_id, 64);
    memcpy(out->addr, addr, 64);
    out->m         = m;
    out->n         = n;
    out->signers   = k;
    out->n_in      = n_in;
    out->n_out     = (int)n_out;
    out->sum_in    = sum_in;
    out->fee       = fee;
    out->price     = req->price;
    out->change    = change;
    out->units     = units;
    out->passes    = pass + 1;
    rc = NODUS_V2_SPEND_OK;

done:
    free(env_bytes);
    free(dec);
    free(v);
    free(pf);
    free(auth);
    free(call);
    return rc;
}

int nodus_v2_name_msig_review(const nodus_v2_msig_export_t *x,
                              uint32_t core_version,
                              const uint8_t core_hash[DNA_ENV_RULESET_HASH_LEN],
                              const uint8_t *signer_pk,
                              dna_env_preflight_t *pf,
                              nodus_v2_name_msig_review_t *out) {
    if (!out) return NODUS_V2_SPEND_ERR_ARG;
    memset(out, 0, sizeof(*out));
    if (!x || !x->env || !core_hash || !pf) return NODUS_V2_SPEND_ERR_ARG;
    dna_env_view_t *v = calloc(1, sizeof(*v));
    nodus_v2_name_decoded_t *dec = calloc(1, sizeof(*dec));
    int rc = NODUS_V2_SPEND_ERR_ALLOC;
    if (!v || !dec) goto done;
    nodus_v2_msig_leg_t leg;
    rc = nodus_v2_msig_leg_open_op(x, v, DNA_CORERULE_NAME_REGISTER, &leg);
    if (rc != NODUS_V2_SPEND_OK) goto done;
    if (signer_pk) {
        int member = 0;
        for (uint8_t i = 0; i < leg.n && !member; i++)
            if (memcmp(leg.keys + (size_t)i * V2N_PK_LEN, signer_pk,
                       V2N_PK_LEN) == 0)
                member = 1;
        if (!member) { rc = NODUS_V2_MSIG_ERR_NOT_MEMBER; goto done; }
    }
    /* never sign a digest you did not derive yourself */
    rc = nodus_v2_msig_digest(x, core_version, core_hash, pf);
    if (rc != NODUS_V2_SPEND_OK) goto done;
    if (memcmp(pf->auth_digest[0], x->digest, 64) != 0) {
        rc = NODUS_V2_MSIG_ERR_DIGEST;
        goto done;
    }
    if (v->expiry_height == 0 ||
        x->tip > UINT64_MAX - NODUS_V2_MSIG_EXPIRY_AHEAD ||
        v->expiry_height > x->tip + NODUS_V2_MSIG_EXPIRY_AHEAD) {
        rc = NODUS_V2_MSIG_ERR_EXPIRY;
        goto done;
    }
    {
        const int arc = dna_msig_address(leg.desc, leg.desc_len, out->addr);
        if (arc != 0) {
            rc = arc == -2 ? NODUS_V2_SPEND_ERR_HASH : NODUS_V2_MSIG_ERR_DESC;
            goto done;
        }
    }
    if (v->leg[0].access_mode != DNA_ENV_ACCESS_INVOKE) {
        rc = NODUS_V2_MSIG_ERR_CALL;
        goto done;
    }
    {
        const int crc = v2n_call_read(v, dec);
        if (crc == NODUS_V2_SPEND_ERR_HASH) { rc = crc; goto done; }
        if (crc != NODUS_V2_SPEND_OK) {
            rc = NODUS_V2_MSIG_ERR_CALL;
            goto done;
        }
    }
    /* nothing leaves the vault but the price and the fee: the one output,
     * if any, is the vault's own change (v2n_call_read proved it native
     * and non-zero) */
    if (dec->n_out == 1) {
        char ah[QGP_FP_HEX_BUFFER];
        qgp_fp_raw_to_hex(out->addr, ah);
        if (memcmp(dec->change_owner, ah, 128) != 0) {
            rc = NODUS_V2_MSIG_ERR_CALL;
            goto done;
        }
    }
    out->m             = leg.m;
    out->n             = leg.n;
    out->signers       = x->signers;
    out->tip           = x->tip;
    out->expiry_height = v->expiry_height;
    out->fee           = v->fee_amount;
    out->units         = v->res_max_total_units;
    memcpy(out->name, dec->name, sizeof(out->name));
    out->price         = dec->price;
    out->n_in          = dec->n_in;
    memcpy(out->in_nul, dec->in_nul, (size_t)dec->n_in * 64);
    out->n_out         = dec->n_out;
    out->change_amount = dec->change_amount;
    memcpy(out->digest, x->digest, 64);
    memcpy(out->intent_id, pf->intent_id, 64);
    rc = NODUS_V2_SPEND_OK;
done:
    if (rc != NODUS_V2_SPEND_OK) memset(out, 0, sizeof(*out));
    free(dec);
    free(v);
    return rc;
}
