/**
 * @file nodus/src/client/nodus_v2_evm.c
 * @brief The shared EVM envelope builder — contract: nodus_v2_evm.h.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "client/nodus_v2_evm.h"
#include "nodus/nodus_types.h"             /* NODUS_W_BASE_TX_FEE         */
#include "witness/nodus_witness_runtime.h" /* NODUS_RT_AUTH_* , EVM caps  —
                                            * header constants only       */
#include "dnac/dnac.h"                     /* DNAC_MIN_FEE_RAW            */
#include "dnac/effect_wire.h"              /* DNA_EFFECT_FIXED_HEAD / _LEN */
#include "crypto/hash/qgp_sha3.h"
#include "crypto/hash/keccak256.h"           /* nodus_v2_evm_create_address */

#include <stdlib.h>
#include <string.h>

#define V2E_PK_LEN   2592u
#define V2E_AUTH_LEN (1u + NODUS_RT_AUTH_SIGNER_LEN)   /* count 1 ‖ pk ‖ sig */
#define V2E_FEE_FLOOR (DNAC_MIN_FEE_RAW > NODUS_W_BASE_TX_FEE ? \
                       DNAC_MIN_FEE_RAW : NODUS_W_BASE_TX_FEE)
/* the CORE UTXO record a CREATE writes (rt_native.c RTN_UTXO_REC_LEN) */
#define V2E_UTXO_REC_LEN 284u
/* the EVM runtime's records (nodus_witness_rt_evm.h — not included: that
 * header is the EVM-enabled build's; restated with their citation) */
#define V2E_EVM_ACCT_LEN 148u   /* NODUS_RT_EVM_ACCT_LEN */
#define V2E_EVM_META_LEN 96u    /* NODUS_RT_EVM_META_LEN */

_Static_assert(DNA_EVMFUND_OUT_LEN == NODUS_V2_SPEND_OUT_LEN &&
               DNA_EVMFUND_MAX_IN == NODUS_V2_SPEND_MAX_IN,
               "the funding section is a SPEND transfer section");

int nodus_v2_evm_fund_decl(uint8_t role, uint32_t n_in, uint32_t n_out,
                           uint32_t *effects_out, uint32_t *bytes_out) {
    if (!effects_out || !bytes_out) return -1;
    if (role != DNA_EVMFUND_ROLE_FEE && role != DNA_EVMFUND_ROLE_DEPOSIT &&
        role != DNA_EVMFUND_ROLE_RELEASE)
        return -1;
    const uint32_t rel = (role == DNA_EVMFUND_ROLE_RELEASE) ? 1u : 0u;
    const uint32_t rsv = (role != DNA_EVMFUND_ROLE_FEE) ? 1u : 0u;
    const uint32_t effects = n_in + n_out + rel + 1u + rsv;
    *effects_out = effects;
    *bytes_out = (uint32_t)DNA_EFFECT_FIXED_HEAD +
                 (uint32_t)DNA_EFFECT_RECORD_LEN * effects +
                 (64u + V2E_UTXO_REC_LEN) * (n_out + rel) +
                 (1u + 8u) * (1u + rsv) +
                 64u * n_in;
    return 0;
}

int nodus_v2_evm_bridge_decl(uint32_t op, uint32_t *effects_out,
                             uint32_t *bytes_out) {
    if (!effects_out || !bytes_out) return -1;
    const uint32_t meta = 1u + V2E_EVM_META_LEN;
    switch (op) {
        case DNA_EVM_OP_DEPOSIT:
        case DNA_EVM_OP_WITHDRAW:
            *effects_out = 2;
            *bytes_out = (uint32_t)DNA_EFFECT_FIXED_HEAD +
                         2u * (uint32_t)DNA_EFFECT_RECORD_LEN +
                         (32u + V2E_EVM_ACCT_LEN) + meta;
            return 0;
        case DNA_EVM_OP_REDEEM:
            *effects_out = 2;
            *bytes_out = (uint32_t)DNA_EFFECT_FIXED_HEAD +
                         2u * (uint32_t)DNA_EFFECT_RECORD_LEN + 64u + meta;
            return 0;
        default:
            return -1;
    }
}

static int is_vm_op(uint32_t op) {
    return op == DNA_EVM_OP_CALL || op == DNA_EVM_OP_CREATE;
}

int nodus_v2_evm_min_units(const dna_meter_policy_t *pol,
                           uint32_t core_version, uint32_t op,
                           size_t evm_call_len, uint32_t effects,
                           uint32_t effect_bytes, uint64_t gas_limit,
                           int n_in, int n_out, uint64_t *out,
                           int *meter_status) {
    if (meter_status) *meter_status = 0;
    if (!pol || !out || n_in < 1 || n_in > (int)DNA_EVMFUND_MAX_IN ||
        n_out < 0 || n_out > (int)DNA_EVMFUND_MAX_OUT ||
        evm_call_len > DNA_ENV_MAX_TOTAL_LEN)
        return NODUS_V2_SPEND_ERR_ARG;
    const uint8_t role = dna_evmfund_role_for_op(op);
    if (role == 0) return NODUS_V2_EVM_ERR_OP;
    uint32_t feff = 0, fbytes = 0;
    if (nodus_v2_evm_fund_decl(role, (uint32_t)n_in, (uint32_t)n_out, &feff,
                               &fbytes) != 0)
        return NODUS_V2_SPEND_ERR_ARG;

    const size_t fcall_len = 4 + (size_t)n_in * 64 +
                             (size_t)n_out * DNA_EVMFUND_OUT_LEN;
    uint8_t *fcall = calloc(1, fcall_len);
    uint8_t *ecall = calloc(1, evm_call_len ? evm_call_len : 1);
    uint8_t *a0 = calloc(1, V2E_AUTH_LEN), *a1 = calloc(1, V2E_AUTH_LEN);
    dna_env_view_t *view = calloc(1, sizeof(*view));
    dna_meter_plan_t *plan = calloc(1, sizeof(*plan));
    uint8_t *buf = NULL;
    int rc = NODUS_V2_SPEND_ERR_ALLOC;
    if (!fcall || !ecall || !a0 || !a1 || !view || !plan) goto done;

    dna_env_leg_in_t legs[2];
    memset(legs, 0, sizeof(legs));
    legs[0].hdr.domain_id            = DNA_DOMAIN_CORE;
    legs[0].hdr.runtime_op           = DNA_EVMFUND_CORE_OP;
    legs[0].hdr.ruleset_version      = core_version;
    legs[0].hdr.access_mode          = DNA_ENV_ACCESS_INVOKE;
    legs[0].hdr.auth_kind            = NODUS_RT_AUTHKIND_DSA87_MULTI_V1;
    legs[0].hdr.call_len             = (uint32_t)fcall_len;
    legs[0].hdr.auth_len             = V2E_AUTH_LEN;
    legs[0].hdr.res_max_effects      = feff;
    legs[0].hdr.res_max_effect_bytes = fbytes;
    legs[0].call_data = fcall;
    legs[0].auth_data = a0;
    legs[1].hdr.domain_id            = DNA_DOMAIN_EVM;
    legs[1].hdr.runtime_op           = op;
    legs[1].hdr.ruleset_version      = 1;   /* fixed width: never priced */
    legs[1].hdr.access_mode          = DNA_ENV_ACCESS_INVOKE;
    legs[1].hdr.auth_kind            = NODUS_RT_AUTHKIND_DSA87_MULTI_V1;
    legs[1].hdr.call_len             = (uint32_t)evm_call_len;
    legs[1].hdr.auth_len             = V2E_AUTH_LEN;
    legs[1].hdr.res_max_effects      = effects;
    legs[1].hdr.res_max_effect_bytes = effect_bytes;
    legs[1].call_data = ecall;
    legs[1].auth_data = a1;
    dna_env_in_t env_in;
    memset(&env_in, 0, sizeof(env_in));
    env_in.res_max_total_units = UINT64_MAX;   /* provisional: the plan
                                                * only checks total <= it */
    env_in.leg_count = 2;
    env_in.legs = legs;
    size_t len = 0, used = 0;
    if (dna_env_encoded_size(legs, 2, &len) != 0) {
        rc = NODUS_V2_SPEND_ERR_ENCODE;
        goto done;
    }
    if (!(buf = malloc(len))) goto done;              /* ERR_ALLOC */
    if (dna_env_encode(&env_in, buf, len, &used) != 0 || used != len ||
        dna_env_decode(buf, len, view) != 0) {
        rc = NODUS_V2_SPEND_ERR_ENCODE;
        goto done;
    }
    /* the EVM leg (index 1) is the STREAMED leg: stream_leg = 1 + 1 */
    dna_meter_status_t ms = dna_meter_plan_build_ex(pol, view, 2, plan);
    if (meter_status) *meter_status = (int)ms;
    if (ms == DNA_METER_ERR_OP_WEIGHT) { rc = NODUS_V2_EVM_ERR_OP_WEIGHT; goto done; }
    if (ms != DNA_METER_OK) { rc = NODUS_V2_SPEND_ERR_METER; goto done; }

    const uint64_t reads = (uint64_t)dna_evmfund_reads(role, (uint8_t)n_in) +
                           (is_vm_op(op) ? 0u : NODUS_V2_EVM_BRIDGE_READS);
    uint64_t u = 0, t = 0;
    rc = NODUS_V2_SPEND_ERR_OVERFLOW;
    if (dna_ck_mul_u64(reads, plan->w_read, &t) != 0 ||
        dna_ck_add_u64(plan->static_total, t, &u) != 0)
        goto done;
    if (is_vm_op(op)) {
        if (dna_ck_mul_u64(gas_limit, DNA_METER_EVM_W_GAS, &t) != 0 ||
            dna_ck_add_u64(u, t, &u) != 0 ||
            dna_ck_add_u64(u, DNA_METER_EVM_FAIL_RESERVE, &u) != 0)
            goto done;
    }
    *out = u;
    rc = NODUS_V2_SPEND_OK;
done:
    free(buf);
    free(plan);
    free(view);
    free(a1);
    free(a0);
    free(ecall);
    free(fcall);
    return rc;
}

int nodus_v2_evm_ref_units(const dna_meter_policy_t *pol,
                           uint32_t core_version, uint32_t op,
                           uint32_t data_len, uint64_t gas_limit,
                           uint64_t *out) {
    if (!is_vm_op(op)) return NODUS_V2_EVM_ERR_OP;
    /* the call bytes' length with no access list: the fixed head
     * (CALL 81 / CREATE 49) ‖ n_acc u16 ‖ data_len u32 ‖ data */
    const size_t head = (op == DNA_EVM_OP_CALL) ? 81u : 49u;
    return nodus_v2_evm_min_units(pol, core_version, op,
                                  head + 2u + 4u + (size_t)data_len,
                                  NODUS_V2_EVM_DEF_EFFECTS,
                                  NODUS_V2_EVM_DEF_EFFECT_BYTES, gas_limit,
                                  1, 1, out, NULL);
}

void nodus_v2_evm_built_free(nodus_v2_evm_built_t *b) {
    if (!b) return;
    free(b->env);
    memset(b, 0, sizeof(*b));
}

int nodus_v2_evm_create_address(const uint8_t sender[32], uint64_t nonce,
                                uint8_t out[32]) {
    if (!sender || !out) return -1;
    /* rlp([sender_32, nonce]) (ethereum_rlp): the sender is a 32-byte
     * string (0x80 + 32), the nonce the minimal big-endian scalar (0 ->
     * the empty string 0x80, 1..0x7f -> itself, else 0x80 + n then n
     * bytes). The payload is at most 33 + 9 = 42 < 56 bytes: a one-byte
     * list header 0xc0 + payload length. */
    uint8_t buf[1 + 33 + 9];
    size_t p = 1;
    buf[p++] = (uint8_t)(0x80 + 32);
    memcpy(buf + p, sender, 32);
    p += 32;
    if (nonce == 0) {
        buf[p++] = 0x80;
    } else if (nonce < 0x80) {
        buf[p++] = (uint8_t)nonce;
    } else {
        uint8_t tmp[8];
        size_t n = 0;
        for (uint64_t v = nonce; v; v >>= 8) tmp[n++] = (uint8_t)(v & 0xff);
        buf[p++] = (uint8_t)(0x80 + n);
        for (size_t i = 0; i < n; i++) buf[p++] = tmp[n - 1 - i];
    }
    buf[0] = (uint8_t)(0xc0 + (p - 1));
    return keccak256(buf, p, out) == 0 ? 0 : -1;
}

static void fmt_hex(const uint8_t *in, size_t n, char *out) {
    static const char hx[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2 * i] = hx[in[i] >> 4];
        out[2 * i + 1] = hx[in[i] & 0x0F];
    }
    out[2 * n] = '\0';
}

int nodus_v2_evm_build(const nodus_v2_evm_req_t *req,
                       nodus_v2_evm_built_t *out, nodus_v2_evm_err_t *err) {
    nodus_v2_evm_err_t e_local;
    if (!err) err = &e_local;
    memset(err, 0, sizeof(*err));
    if (!out) return NODUS_V2_SPEND_ERR_ARG;
    memset(out, 0, sizeof(*out));
    if (!req || !req->rs || !req->rs->meter_policy || !req->evm_ruleset_hash ||
        !req->chain32 || !req->pk || !req->sk ||
        (req->n_coins > 0 && !req->coins) || req->n_coins < 0)
        return NODUS_V2_SPEND_ERR_ARG;

    dna_evm_call_t call = req->call;
    const uint32_t op = call.op;
    const uint8_t role = dna_evmfund_role_for_op(op);
    if (role == 0) return NODUS_V2_EVM_ERR_OP;
    const int is_vm = is_vm_op(op);
    uint32_t eff = 0, effb = 0;
    if (is_vm) {
        if (call.gas_limit == 0 || call.gas_limit > NODUS_RT_EVM_TX_GAS_CAP)
            return NODUS_V2_EVM_ERR_GAS;
        if (op == DNA_EVM_OP_CREATE && call.data_len == 0)
            return NODUS_V2_EVM_ERR_NO_CODE;
        if (req->effects == 0 && req->effect_bytes == 0) {
            eff = NODUS_V2_EVM_DEF_EFFECTS;
            effb = NODUS_V2_EVM_DEF_EFFECT_BYTES;
        } else if (req->effects < DNA_METER_EVM_FAIL_EFFECTS ||
                   req->effects > DNA_METER_STREAM_MAX_EFFECTS ||
                   req->effect_bytes < DNA_METER_EVM_FAIL_BYTES ||
                   req->effect_bytes > DNA_METER_STREAM_MAX_EFFECT_BYTES) {
            return NODUS_V2_EVM_ERR_DECL;
        } else {
            eff = req->effects;
            effb = req->effect_bytes;
        }
    } else {
        if (call.data_len || call.n_access || call.access_len)
            return NODUS_V2_EVM_ERR_BRIDGE_DATA;
        if (call.amount_raw == 0) return NODUS_V2_EVM_ERR_AMOUNT;
        if (nodus_v2_evm_bridge_decl(op, &eff, &effb) != 0)
            return NODUS_V2_EVM_ERR_OP;
    }
    if (req->n_coins < 1) return NODUS_V2_SPEND_ERR_INSUFFICIENT;

    /* the EVM leg's call bytes — the ONE codec */
    size_t ecall_len = 0, used = 0;
    if (dna_evm_call_encoded_size(&call, &ecall_len) != 0 ||
        ecall_len > DNA_ENV_MAX_TOTAL_LEN)
        return NODUS_V2_SPEND_ERR_ENCODE;
    uint8_t *ecall = malloc(ecall_len ? ecall_len : 1);
    if (!ecall) return NODUS_V2_SPEND_ERR_ALLOC;
    if (dna_evm_call_encode(&call, ecall, ecall_len, &used) != 0 ||
        used != ecall_len) {
        free(ecall);
        return NODUS_V2_SPEND_ERR_ENCODE;
    }

    int rc = NODUS_V2_SPEND_ERR_ALLOC;
    nodus_v2_coin_t *coins = NULL;
    uint8_t *fcall = NULL, *auth0 = NULL, *auth1 = NULL, *env_bytes = NULL;
    size_t env_len = 0;
    dna_env_preflight_t *pf = NULL;
    dna_env_view_t *v = NULL;
    uint8_t own_raw[64];
    char own_hex[129];
    /* declared before the first `goto done`: the error path reads fee and
     * units (done: err->fee / err->units), and a goto may not jump over
     * their initialisation (it did — GCC -Wmaybe-uninitialized, CI) */
    uint64_t units = req->units, fee = 0, sum_in = 0, change = 0;
    uint64_t final_min = 0;
    int n_in = 0, shape_in = 1, shape_out = 1, settled = 0;
    if (qgp_sha3_512(req->pk, V2E_PK_LEN, own_raw) != 0) {
        rc = NODUS_V2_SPEND_ERR_HASH;
        goto done;
    }
    fmt_hex(own_raw, 64, own_hex);

    /* ── coins: ascending by nullifier until lock + fee is covered; units
     *    → fee → selection → units, a fixed point over the funding shape */
    coins = calloc((size_t)req->n_coins, sizeof(*coins));
    if (!coins) goto done;
    memcpy(coins, req->coins, sizeof(*coins) * (size_t)req->n_coins);
    qsort(coins, (size_t)req->n_coins, sizeof(*coins), nodus_v2_nul_cmp);
    const uint64_t lock = (op == DNA_EVM_OP_DEPOSIT) ? call.amount_raw : 0;
    const uint32_t core_v = req->rs->core_ruleset_version;
    const dna_meter_policy_t *pol = req->rs->meter_policy;
    for (int pass = 0; pass < NODUS_V2_EVM_MAX_PASSES && !settled; pass++) {
        uint64_t min_u = 0;
        rc = nodus_v2_evm_min_units(pol, core_v, op, ecall_len, eff, effb,
                                    call.gas_limit, shape_in, shape_out,
                                    &min_u, &err->meter_status);
        if (rc != NODUS_V2_SPEND_OK) goto done;
        if (req->units == 0) {
            if (dna_ck_add_u64(min_u, req->evm_read_units, &min_u) != 0) {
                rc = NODUS_V2_SPEND_ERR_OVERFLOW;
                goto done;
            }
            if (units < min_u) units = min_u;
        }
        fee = V2E_FEE_FLOOR;
        if (req->gas_price != 0) {
            uint64_t g = 0;
            if (dna_ck_mul_u64(units, req->gas_price, &g) != 0) {
                rc = NODUS_V2_SPEND_ERR_GAS_OVERFLOW;
                goto done;
            }
            if (g > fee) fee = g;
        }
        uint64_t need = 0;
        if (dna_ck_add_u64(lock, fee, &need) != 0) {
            rc = NODUS_V2_SPEND_ERR_OVERFLOW;
            goto done;
        }
        err->need = need;
        n_in = 0;
        sum_in = 0;
        for (int i = 0; i < req->n_coins && sum_in < need &&
                        n_in < (int)DNA_EVMFUND_MAX_IN; i++) {
            if (dna_ck_add_u64(sum_in, coins[i].amount, &sum_in) != 0) {
                rc = NODUS_V2_SPEND_ERR_INPUT_SUM;
                goto done;
            }
            n_in++;
        }
        if (sum_in < need) {
            err->n_in = n_in;
            err->fee = fee;
            rc = (n_in >= (int)DNA_EVMFUND_MAX_IN &&
                  req->n_coins > (int)DNA_EVMFUND_MAX_IN)
                     ? NODUS_V2_SPEND_ERR_MAX_INPUTS
                     : NODUS_V2_SPEND_ERR_INSUFFICIENT;
            goto done;
        }
        change = sum_in - need;
        const int n_out = change > 0 ? 1 : 0;
        rc = nodus_v2_evm_min_units(pol, core_v, op, ecall_len, eff, effb,
                                    call.gas_limit, n_in, n_out, &final_min,
                                    &err->meter_status);
        if (rc != NODUS_V2_SPEND_OK) goto done;
        if (req->units == 0 &&
            dna_ck_add_u64(final_min, req->evm_read_units, &final_min) != 0) {
            rc = NODUS_V2_SPEND_ERR_OVERFLOW;
            goto done;
        }
        if (req->units != 0) {
            if (req->units < final_min) {
                err->units = req->units;
                err->min_units = final_min;
                rc = NODUS_V2_EVM_ERR_UNITS_LOW;
                goto done;
            }
            settled = 1;
        } else if (final_min <= units) {
            settled = 1;
        } else {
            units = final_min;
            shape_in = n_in;
            shape_out = n_out;
        }
    }
    if (!settled) {
        rc = NODUS_V2_SPEND_ERR_FEE_UNSETTLED;
        goto done;
    }

    /* ── the CORE EVMFUND call ── */
    const int n_out = change > 0 ? 1 : 0;
    for (int i = 0; i < n_in; i++) memcpy(out->in_nul[i], coins[i].nul, 64);
    uint8_t outrec[DNA_EVMFUND_OUT_LEN];
    if (n_out) {
        /* deterministic change seed = SHA3-512(input nullifiers)[0..32]
         * (nodus_v2_stake.c, the same rule) */
        uint8_t seed_full[64], pre[160];
        if (qgp_sha3_512((const uint8_t *)out->in_nul, (size_t)n_in * 64,
                         seed_full) != 0) {
            rc = NODUS_V2_SPEND_ERR_HASH;
            goto done;
        }
        nodus_v2_xfer_out_put(outrec, own_hex, change, NULL, seed_full);
        memcpy(pre, outrec, 128);
        memcpy(pre + 128, seed_full, 32);
        if (qgp_sha3_512(pre, sizeof(pre), out->change_id) != 0) {
            rc = NODUS_V2_SPEND_ERR_HASH;
            goto done;
        }
    }
    dna_evmfund_call_t fc;
    memset(&fc, 0, sizeof(fc));
    fc.role = role;
    fc.n_in = (uint8_t)n_in;
    fc.in_nul = (const uint8_t *)out->in_nul;
    fc.n_out = (uint8_t)n_out;
    fc.outs = n_out ? outrec : NULL;
    size_t fcall_len = 0;
    if (dna_evmfund_encoded_size(&fc, &fcall_len) != 0 ||
        !(fcall = malloc(fcall_len)) ||
        dna_evmfund_encode(&fc, fcall, fcall_len, &used) != 0 ||
        used != fcall_len) {
        rc = fcall ? NODUS_V2_SPEND_ERR_ENCODE : NODUS_V2_SPEND_ERR_ALLOC;
        goto done;
    }
    uint32_t feff = 0, fbytes = 0;
    if (nodus_v2_evm_fund_decl(role, (uint32_t)n_in, (uint32_t)n_out, &feff,
                               &fbytes) != 0) {
        rc = NODUS_V2_SPEND_ERR_ARG;
        goto done;
    }

    /* ── two legs, ascending by domain: CORE (1), EVM (2) ── */
    auth0 = calloc(1, V2E_AUTH_LEN);
    auth1 = calloc(1, V2E_AUTH_LEN);
    pf = calloc(1, sizeof(*pf));
    if (!auth0 || !auth1 || !pf) { rc = NODUS_V2_SPEND_ERR_ALLOC; goto done; }
    dna_env_leg_in_t legs[2];
    memset(legs, 0, sizeof(legs));
    legs[0].hdr.domain_id            = DNA_DOMAIN_CORE;
    legs[0].hdr.runtime_op           = DNA_EVMFUND_CORE_OP;
    legs[0].hdr.ruleset_version      = core_v;
    legs[0].hdr.access_mode          = DNA_ENV_ACCESS_INVOKE;
    legs[0].hdr.auth_kind            = NODUS_RT_AUTHKIND_DSA87_MULTI_V1;
    legs[0].hdr.call_len             = (uint32_t)fcall_len;
    legs[0].hdr.auth_len             = V2E_AUTH_LEN;
    legs[0].hdr.res_max_effects      = feff;
    legs[0].hdr.res_max_effect_bytes = fbytes;
    legs[0].call_data = fcall;
    legs[0].auth_data = auth0;
    legs[1].hdr.domain_id            = DNA_DOMAIN_EVM;
    legs[1].hdr.runtime_op           = op;
    legs[1].hdr.ruleset_version      = req->evm_ruleset_version;
    legs[1].hdr.access_mode          = DNA_ENV_ACCESS_INVOKE;
    legs[1].hdr.auth_kind            = NODUS_RT_AUTHKIND_DSA87_MULTI_V1;
    legs[1].hdr.call_len             = (uint32_t)ecall_len;
    legs[1].hdr.auth_len             = V2E_AUTH_LEN;
    legs[1].hdr.res_max_effects      = eff;
    legs[1].hdr.res_max_effect_bytes = effb;
    legs[1].call_data = ecall;
    legs[1].auth_data = auth1;

    dna_env_in_t env_in;
    memset(&env_in, 0, sizeof(env_in));
    env_in.expiry_height       = req->expiry_height;
    env_in.fee_amount          = fee;
    env_in.res_max_total_units = units;
    env_in.leg_count           = 2;
    env_in.legs                = legs;

    dna_env_leg_ctx_t lctx[2];
    memset(lctx, 0, sizeof(lctx));
    lctx[0].domain_id       = DNA_DOMAIN_CORE;
    lctx[0].ruleset_version = core_v;
    memcpy(lctx[0].ruleset_hash, req->rs->core_ruleset_hash, 64);
    lctx[1].domain_id       = DNA_DOMAIN_EVM;
    lctx[1].ruleset_version = req->evm_ruleset_version;
    memcpy(lctx[1].ruleset_hash, req->evm_ruleset_hash, 64);
    {
        uint8_t *auths[2] = { auth0, auth1 };
        nodus_v2_spend_err_t se;
        memset(&se, 0, sizeof(se));
        rc = nodus_v2_env_sign_one_key(&env_in, auths, lctx, req->chain32,
                                       req->tip, req->pk, req->sk,
                                       &env_bytes, &env_len, pf, &se);
        if (rc != NODUS_V2_SPEND_OK) {
            err->leg = se.leg;
            goto done;
        }
    }

    /* ── read back what was BUILT; refuse unless it is what was asked ── */
    v = calloc(1, sizeof(*v));
    if (!v) { rc = NODUS_V2_SPEND_ERR_ALLOC; goto done; }
    int ok = dna_env_decode(env_bytes, env_len, v) == 0 &&
             v->leg_count == 2 && v->expiry_height == req->expiry_height &&
             v->fee_amount == fee && v->res_max_total_units == units;
    for (int L = 0; ok && L < 2; L++) {
        const dna_env_leg_hdr_t *h = &v->leg[L];
        if (h->domain_id != legs[L].hdr.domain_id ||
            h->runtime_op != legs[L].hdr.runtime_op ||
            h->ruleset_version != legs[L].hdr.ruleset_version ||
            h->access_mode != DNA_ENV_ACCESS_INVOKE ||
            h->auth_kind != NODUS_RT_AUTHKIND_DSA87_MULTI_V1 ||
            h->auth_len != V2E_AUTH_LEN ||
            h->res_max_effects != legs[L].hdr.res_max_effects ||
            h->res_max_effect_bytes != legs[L].hdr.res_max_effect_bytes)
            ok = 0;
        else {
            const uint8_t *a = v->buf + v->auth_off[L];
            if (a[0] != 1 || memcmp(a + 1, req->pk, V2E_PK_LEN) != 0) ok = 0;
        }
    }
    dna_evmfund_call_t dfc;
    memset(&dfc, 0, sizeof(dfc));
    uint64_t in_sum = 0, d_change = 0;
    if (ok && (dna_evmfund_decode(v->buf + v->call_off[0], v->leg[0].call_len,
                                  &dfc) != 0 ||
               dfc.role != role || dfc.n_in != n_in || dfc.n_out != n_out))
        ok = 0;
    for (int i = 0; ok && i < dfc.n_in; i++) {
        int found = 0;
        for (int k = 0; k < req->n_coins && !found; k++)
            if (memcmp(req->coins[k].nul, dfc.in_nul + (size_t)i * 64,
                       64) == 0) {
                found = 1;
                if (dna_ck_add_u64(in_sum, req->coins[k].amount,
                                   &in_sum) != 0)
                    ok = 0;
            }
        if (!found) ok = 0;
    }
    if (ok && dfc.n_out == 1) {
        const uint8_t *r = dfc.outs;
        uint64_t amt = 0;
        for (int b = 0; b < 8; b++) amt = (amt << 8) | r[128 + b];
        uint8_t pre[160], id[64];
        memcpy(pre, r, 128);
        memcpy(pre + 128, r + 200, 32);
        if (memcmp(r, own_hex, 128) != 0 ||
            qgp_sha3_512(pre, sizeof(pre), id) != 0 ||
            memcmp(id, out->change_id, 64) != 0)
            ok = 0;
        d_change = amt;
    }
    {
        uint64_t rhs = 0;
        if (ok && (d_change != change || in_sum != sum_in ||
                   dna_ck_add_u64(fee, lock, &rhs) != 0 ||
                   dna_ck_add_u64(rhs, d_change, &rhs) != 0 ||
                   rhs != in_sum))
            ok = 0;
    }
    /* the EVM leg's bytes: decoded strictly and re-encoded byte for byte */
    if (ok) {
        const uint8_t *eb = v->buf + v->call_off[1];
        const size_t el = v->leg[1].call_len;
        uint8_t *re = malloc(el ? el : 1);
        size_t rl = 0;
        if (!re || el != ecall_len || memcmp(eb, ecall, el) != 0 ||
            dna_evm_call_decode(op, eb, el, &out->dec) != 0 ||
            dna_evm_call_encode(&out->dec, re, el, &rl) != 0 || rl != el ||
            memcmp(re, ecall, el) != 0)
            ok = 0;
        free(re);
    }
    if (!ok) {
        rc = NODUS_V2_EVM_ERR_MISMATCH;
        goto done;
    }
    /* `dec` points into v->buf, which IS env_bytes (a view borrows its
     * buffer — env_wire.h), and env_bytes moves into `out` below */
    out->env = env_bytes;                  /* ownership moves here */
    env_bytes = NULL;
    out->env_len = env_len;
    memcpy(out->wire_id, pf->wire_id, 64);
    memcpy(out->intent_id, pf->intent_id, 64);
    out->role = role;
    out->fee = fee;
    out->change = change;
    out->units = units;
    out->sum_in = sum_in;
    out->min_units = final_min;
    out->n_in = n_in;
    rc = NODUS_V2_SPEND_OK;

done:
    if (rc != NODUS_V2_SPEND_OK) {
        err->fee = err->fee ? err->fee : fee;
        err->units = err->units ? err->units : units;
        nodus_v2_evm_built_free(out);
    }
    free(v);
    free(env_bytes);
    free(pf);
    free(auth0);
    free(auth1);
    free(fcall);
    free(coins);
    free(ecall);
    return rc;
}
