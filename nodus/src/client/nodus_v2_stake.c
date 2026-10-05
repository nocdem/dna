/**
 * @file nodus/src/client/nodus_v2_stake.c
 * @brief The shared version-3 staking envelope builder (STAKE, DELEGATE,
 *        UNSTAKE, UNDELEGATE) — see nodus_v2_stake.h for the contract.
 *
 * Moved out of nodus/tools/nodus-cli.c cmd_v2_stake (`v2-envelope stake |
 * delegate`): the fee rule, the coin filter, the ascending-nullifier
 * selection, both call layouts, the deterministic change seed, the two leg
 * headers and the two-pass signature are the CLI's, unchanged. What changed
 * is the surface: no printing (a refusal is a code plus the numbers in
 * nodus_v2_stake_err_t, the CLI prints), no network, the ruleset identity
 * is an input, and the built bytes are decoded back and compared with the
 * request before they are returned. UNDELEGATE is new: the DELEGATE call
 * layout under runtime_op 4 with a fee-only funding leg
 * (nodus_witness_rt_native.c rtn_sys_call_flow: lock 0, release = amount).
 * UNSTAKE (op 3) is new too: call = the signer's own 2592-byte key
 * (RTN_SYS_UNSTAKE_CALL_LEN) with a fee-only funding leg (rtn_sys_call_flow:
 * lock 0, release 0).
 * STORAGE_REGISTER (op 7) and STORAGE_EXIT (op 8), storage reward v1
 * package B2b-CLI: REGISTER = the STAKE class (call node_pk ‖ bond ‖
 * payee_fp, RTN_SYS_STREG_CALL_LEN; lock = bond), EXIT = the UNSTAKE class
 * (call = the node key, RTN_SYS_STEXIT_CALL_LEN; fee-only funding).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "client/nodus_v2_stake.h"
#include "nodus/nodus_ruleset_pins.h"
#include "nodus/nodus_types.h"            /* NODUS_W_BASE_TX_FEE,
                                            * NODUS_CMT_APP_MAX_EXPIRY_AHEAD */
#include "witness/nodus_witness_runtime.h" /* DNA_SYSRULE_*, DNA_CORERULE_
                                            * SYSFUND, NODUS_RT_AUTH* — header
                                            * constants only, no witness link */
#include "dnac/dnac.h"                     /* DNAC_* amounts and bounds       */
#include "crypto/hash/qgp_sha3.h"
#include "crypto/utils/qgp_fingerprint.h"

#include <stdlib.h>
#include <string.h>

#include "crypto/utils/qgp_safe_string.h"   /* Phase 03: unsafe-string poison guard */

#define V2K_PK_LEN   2592u
#define V2K_AUTH_LEN (1u + NODUS_RT_AUTH_SIGNER_LEN)   /* count 1 ‖ pk ‖ sig */

_Static_assert(V2K_PK_LEN == DNAC_PUBKEY_SIZE, "ML-DSA-87 public key width");
_Static_assert(NODUS_V2_STAKE_CALL_LEN == DNAC_PUBKEY_SIZE + 2u + 8u + 64u,
               "STAKE call = pk ‖ commission u16 ‖ bond u64 ‖ dest_fp");
_Static_assert(NODUS_V2_DELEG_CALL_LEN == 2u * DNAC_PUBKEY_SIZE + 8u,
               "DELEGATE / UNDELEGATE call = pk ‖ pk ‖ amount u64");
_Static_assert(NODUS_V2_UNSTAKE_CALL_LEN == DNAC_PUBKEY_SIZE,
               "UNSTAKE call = the validator pk (RTN_SYS_UNSTAKE_CALL_LEN)");
_Static_assert(NODUS_V2_STREG_CALL_LEN == DNAC_PUBKEY_SIZE + 8u + 64u,
               "STORAGE_REGISTER call = node_pk ‖ bond u64 ‖ payee_fp "
               "(RTN_SYS_STREG_CALL_LEN, bytes doc item 5)");
_Static_assert(NODUS_V2_STEXIT_CALL_LEN == DNAC_PUBKEY_SIZE,
               "STORAGE_EXIT call = the node pk (RTN_SYS_STEXIT_CALL_LEN)");
_Static_assert((uint32_t)NODUS_V2_STAKE_OP_STAKE == DNA_SYSRULE_STAKE &&
               (uint32_t)NODUS_V2_STAKE_OP_DELEGATE == DNA_SYSRULE_DELEGATE &&
               (uint32_t)NODUS_V2_STAKE_OP_UNSTAKE == DNA_SYSRULE_UNSTAKE &&
               (uint32_t)NODUS_V2_STAKE_OP_UNDELEGATE == DNA_SYSRULE_UNDELEGATE &&
               (uint32_t)NODUS_V2_STAKE_OP_STORAGE_REGISTER ==
                   DNA_SYSRULE_STORAGE_REGISTER &&
               (uint32_t)NODUS_V2_STAKE_OP_STORAGE_EXIT ==
                   DNA_SYSRULE_STORAGE_EXIT,
               "the op enum is the wire runtime_op");

static void err_reset(nodus_v2_stake_err_t *err) {
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

/* ── the ruleset identity from the generated pins header ───────────── */

int nodus_v2_stake_ruleset_from_pins_gen(uint32_t generation,
                                         nodus_v2_stake_ruleset_t *out) {
    _Static_assert(NODUS_PIN_SYS_DOMAIN_ID == DNA_DOMAIN_SYSTEM,
                   "the pinned SYSTEM tuple is domain 0");
    _Static_assert(NODUS_PIN_CORE_DOMAIN_ID == DNA_DOMAIN_CORE,
                   "the pinned CORE tuple is domain 1");
    if (!out) return NODUS_V2_SPEND_ERR_ARG;
    memset(out, 0, sizeof(*out));
    /* HF-4: the ONE per-generation pins table (nodus_v2_spend.c) */
    return nodus_v2_pins_tuples(generation, &out->sys_ruleset_version,
                                out->sys_ruleset_hash,
                                &out->core_ruleset_version,
                                out->core_ruleset_hash);
}

int nodus_v2_stake_ruleset_from_pins(nodus_v2_stake_ruleset_t *out) {
    return nodus_v2_stake_ruleset_from_pins_gen(1, out);
}

/* ── read-back ──────────────────────────────────────────────────────── */

int nodus_v2_stake_decode(const uint8_t *env, size_t env_len,
                          nodus_v2_stake_decoded_t *out) {
    if (!env || !out) return NODUS_V2_SPEND_ERR_ARG;
    memset(out, 0, sizeof(*out));
    dna_env_view_t *v = calloc(1, sizeof(*v));
    if (!v) return NODUS_V2_SPEND_ERR_ALLOC;
    int rc = NODUS_V2_SPEND_ERR_DECODE;
    if (dna_env_decode(env, env_len, v) != 0 || v->leg_count != 2)
        goto done;
    const uint32_t op = v->leg[0].runtime_op;
    if (op != DNA_SYSRULE_STAKE && op != DNA_SYSRULE_DELEGATE &&
        op != DNA_SYSRULE_UNSTAKE && op != DNA_SYSRULE_UNDELEGATE &&
        op != DNA_SYSRULE_STORAGE_REGISTER && op != DNA_SYSRULE_STORAGE_EXIT)
        goto done;
    if (v->leg[0].domain_id != DNA_DOMAIN_SYSTEM ||
        v->leg[1].domain_id != DNA_DOMAIN_CORE ||
        v->leg[1].runtime_op != DNA_CORERULE_SYSFUND)
        goto done;
    for (int L = 0; L < 2; L++)
        if (v->leg[L].access_mode != DNA_ENV_ACCESS_INVOKE ||
            v->leg[L].auth_kind != NODUS_RT_AUTHKIND_DSA87_MULTI_V1 ||
            v->leg[L].auth_len != V2K_AUTH_LEN)
            goto done;
    if (v->leg[0].res_max_effects != NODUS_V2_STAKE_SYS_EFFECTS ||
        v->leg[0].res_max_effect_bytes != NODUS_V2_STAKE_SYS_EFFECT_BYTES ||
        v->leg[1].res_max_effects != NODUS_V2_STAKE_FUND_EFFECTS ||
        v->leg[1].res_max_effect_bytes != NODUS_V2_STAKE_FUND_EFFECT_BYTES)
        goto done;

    /* leg0 — the record call; its length is proved before any read */
    const uint8_t *s = v->buf + v->call_off[0];
    const size_t slen = v->leg[0].call_len;
    if (op == DNA_SYSRULE_STAKE) {
        if (slen != NODUS_V2_STAKE_CALL_LEN) goto done;
        memcpy(out->identity_pk, s, V2K_PK_LEN);
        out->commission_bps = ((uint32_t)s[V2K_PK_LEN] << 8) |
                              s[V2K_PK_LEN + 1];
        out->amount = get_u64(s + V2K_PK_LEN + 2);
        memcpy(out->dest_fp, s + V2K_PK_LEN + 10, 64);
    } else if (op == DNA_SYSRULE_UNSTAKE) {
        /* the call IS the validator key (rtn_sys_call_identity) */
        if (slen != NODUS_V2_UNSTAKE_CALL_LEN) goto done;
        memcpy(out->identity_pk, s, V2K_PK_LEN);
    } else if (op == DNA_SYSRULE_STORAGE_REGISTER) {
        /* node_pk ‖ bond u64 BE ‖ payee_fp (rtn_streg_parse) */
        if (slen != NODUS_V2_STREG_CALL_LEN) goto done;
        memcpy(out->identity_pk, s, V2K_PK_LEN);
        out->amount = get_u64(s + V2K_PK_LEN);
        memcpy(out->dest_fp, s + V2K_PK_LEN + 8, 64);
        /* the pre-HF-5 exec rule (rtn_storage_register_exec): payee_fp ==
         * SHA3-512(node_pk) — an envelope carrying any other payee is
         * not one this module builds */
        uint8_t node_fp[64];
        if (qgp_sha3_512(out->identity_pk, V2K_PK_LEN, node_fp) != 0) {
            rc = NODUS_V2_SPEND_ERR_HASH;
            goto done;
        }
        if (memcmp(node_fp, out->dest_fp, 64) != 0) goto done;
    } else if (op == DNA_SYSRULE_STORAGE_EXIT) {
        /* the call IS the node key (rtn_sys_call_identity) */
        if (slen != NODUS_V2_STEXIT_CALL_LEN) goto done;
        memcpy(out->identity_pk, s, V2K_PK_LEN);
    } else {
        if (slen != NODUS_V2_DELEG_CALL_LEN) goto done;
        memcpy(out->identity_pk, s, V2K_PK_LEN);
        memcpy(out->validator_pk, s + V2K_PK_LEN, V2K_PK_LEN);
        out->amount = get_u64(s + 2 * V2K_PK_LEN);
    }

    /* both auth blobs: exactly one signer, and it is the record identity
     * (rtn_sys_stake_auth binds leg0's signer to the call's identity; the
     * funding coins are the same key's) */
    for (int L = 0; L < 2; L++) {
        const uint8_t *a = v->buf + v->auth_off[L];
        if (a[0] != 1 || memcmp(a + 1, out->identity_pk, V2K_PK_LEN) != 0)
            goto done;
    }

    /* leg1 — in_count ‖ nullifiers ascending ‖ out_count (0/1) ‖ change */
    const uint8_t *c = v->buf + v->call_off[1];
    const size_t clen = v->leg[1].call_len;
    if (clen < 2 || c[0] < 1 || c[0] > NODUS_V2_SPEND_MAX_IN ||
        clen < 2 + (size_t)c[0] * 64)
        goto done;
    const int nin = c[0];
    const int nout = c[1 + (size_t)nin * 64];
    if (nout > 1 ||
        clen != 2 + (size_t)nin * 64 + (size_t)nout * NODUS_V2_SPEND_OUT_LEN)
        goto done;
    for (int i = 0; i < nin; i++) {
        memcpy(out->in_nul[i], c + 1 + (size_t)i * 64, 64);
        if (i > 0 && memcmp(out->in_nul[i - 1], out->in_nul[i], 64) >= 0)
            goto done;                           /* strictly ascending */
    }
    if (nout == 1) {
        static const uint8_t zero64[64] = {0};
        const uint8_t *r = c + 2 + (size_t)nin * 64;
        if (!hex_lower_ok(r, 128)) goto done;
        memcpy(out->change_owner, r, 128);
        out->change_owner[128] = '\0';
        out->change_amount = get_u64(r + 128);
        if (out->change_amount == 0) goto done;
        if (memcmp(r + 136, zero64, 64) != 0) goto done;   /* native only */
        uint8_t pre[160];
        memcpy(pre, r, 128);
        memcpy(pre + 128, r + 200, 32);
        if (qgp_sha3_512(pre, sizeof(pre), out->change_id) != 0) {
            rc = NODUS_V2_SPEND_ERR_HASH;
            goto done;
        }
    }
    out->op                   = op;
    out->n_in                 = nin;
    out->n_out                = nout;
    out->expiry_height        = v->expiry_height;
    out->fee                  = v->fee_amount;
    out->units                = v->res_max_total_units;
    out->sys_ruleset_version  = v->leg[0].ruleset_version;
    out->core_ruleset_version = v->leg[1].ruleset_version;
    rc = NODUS_V2_SPEND_OK;
done:
    if (rc != NODUS_V2_SPEND_OK) memset(out, 0, sizeof(*out));
    free(v);
    return rc;
}

/* ── build ──────────────────────────────────────────────────────────── */

void nodus_v2_stake_built_free(nodus_v2_stake_built_t *b) {
    if (!b) return;
    free(b->env);
    b->env = NULL;
    b->env_len = 0;
}

int nodus_v2_stake_build(const nodus_v2_stake_req_t *req,
                         nodus_v2_stake_built_t *out,
                         nodus_v2_stake_err_t *err) {
    err_reset(err);
    if (!out) return NODUS_V2_SPEND_ERR_ARG;
    memset(out, 0, sizeof(*out));
    if (!req || !req->rs || !req->chain32 || !req->pk || !req->sk ||
        req->n_coins < 0 || (req->n_coins > 0 && !req->coins))
        return NODUS_V2_SPEND_ERR_ARG;
    const nodus_v2_stake_op_t op = req->op;
    const int is_stake = op == NODUS_V2_STAKE_OP_STAKE;
    const int is_streg = op == NODUS_V2_STAKE_OP_STORAGE_REGISTER;
    const int is_stexit = op == NODUS_V2_STAKE_OP_STORAGE_EXIT;
    /* the call is the signer's own key alone (UNSTAKE / STORAGE_EXIT) */
    const int is_unstake = op == NODUS_V2_STAKE_OP_UNSTAKE || is_stexit;
    const int is_deleg = op == NODUS_V2_STAKE_OP_DELEGATE ||
                         op == NODUS_V2_STAKE_OP_UNDELEGATE;
    if (!is_stake && !is_streg && !is_unstake && !is_deleg)
        return NODUS_V2_STAKE_ERR_OP;
    if ((is_stake || is_streg) ? !req->dest_fp
                               : (is_deleg && !req->validator_pk))
        return NODUS_V2_SPEND_ERR_ARG;

    /* what the call bytes alone decide (cmd_v2_stake's pre-I/O checks) */
    if (is_streg) {
        /* storage reward v1 (rtn_storage_register_exec): EXACTLY the
         * storage bond, and the payee is the node's own fingerprint until
         * HF-5 re-keys it */
        if (req->amount != DNAC_STORAGE_STAKE_MIN)
            return NODUS_V2_STAKE_ERR_STORAGE_BOND;
        uint8_t node_fp[64];
        if (qgp_sha3_512(req->pk, V2K_PK_LEN, node_fp) != 0)
            return NODUS_V2_SPEND_ERR_HASH;
        if (memcmp(node_fp, req->dest_fp, 64) != 0)
            return NODUS_V2_STAKE_ERR_PAYEE;
    } else if (is_stake) {
        /* tokenomics-v3 P3-8 (rtn_stake_exec) — the u16 wire field alone
         * would admit values the chain refuses */
        if (req->commission_bps > (uint32_t)DNAC_COMMISSION_BPS_MAX)
            return NODUS_V2_STAKE_ERR_COMMISSION;
        /* final pre-testnet wipe W-B (rtn_stake_exec): EXACTLY the
         * self-bond */
        if (req->amount != DNAC_SELF_STAKE_AMOUNT)
            return NODUS_V2_STAKE_ERR_BOND;
    } else if (!is_unstake &&
               (req->amount < 1 || req->amount > DNAC_DEFAULT_TOTAL_SUPPLY)) {
        return NODUS_V2_STAKE_ERR_AMOUNT;          /* rtn_delegate_exec's
                                                    * scalar rule */
    }
    /* the mempool lifetime rule (decision 2026-09-25-mempool-policy.md 1);
     * a 0 tip is a FAIL-OPEN height read and is refused (CHECKTX-P1 r3) */
    if (req->tip == 0 || req->expiry_height <= req->tip ||
        req->expiry_height - req->tip > (uint64_t)NODUS_CMT_APP_MAX_EXPIRY_AHEAD)
        return NODUS_V2_SPEND_ERR_EXPIRY;

    /* ── fee: the floor, raised under HF-1 to units × gas_price ─────── */
    const uint64_t units = NODUS_V2_STAKE_UNITS;
    uint64_t fee = DNAC_MIN_FEE_RAW > NODUS_W_BASE_TX_FEE
                 ? DNAC_MIN_FEE_RAW : NODUS_W_BASE_TX_FEE;
    if (req->gas_price != 0) {
        if (units > UINT64_MAX / req->gas_price) {
            if (err) { err->units = units; err->gas_price = req->gas_price; }
            return NODUS_V2_SPEND_ERR_GAS_OVERFLOW;
        }
        const uint64_t required = units * req->gas_price;
        if (required > fee) fee = required;
    }

    /* ── need = lock + fee (rtn_sys_call_flow: UNSTAKE, UNDELEGATE and
     *    STORAGE_EXIT lock 0 — their funding leg pays the fee only) ──── */
    const uint64_t lock = (is_unstake || op == NODUS_V2_STAKE_OP_UNDELEGATE)
                        ? 0 : req->amount;
    if (lock > UINT64_MAX - fee) {
        if (err) err->fee = fee;
        return NODUS_V2_SPEND_ERR_OVERFLOW;
    }
    const uint64_t need = lock + fee;

    int rc = NODUS_V2_SPEND_ERR_ALLOC;
    nodus_v2_coin_t *coins = NULL;
    uint8_t *scall = NULL, *fcall = NULL, *auth0 = NULL, *auth1 = NULL;
    uint8_t *env_bytes = NULL;
    size_t env_len = 0;
    dna_env_preflight_t *pf = NULL;

    /* ── select: native, unlocked, ascending by nullifier, until the sum
     *    covers `need` (the order the database-backed builder's SELECT
     *    used; cmd_v2_stake kept it) ─────────────────────────────────── */
    uint8_t nulls[NODUS_V2_SPEND_MAX_IN][64];
    int n_in = 0;
    uint64_t sum_in = 0;
    {
        static const uint8_t native_tok[64] = {0};
        int n_coins = 0;
        coins = calloc((size_t)(req->n_coins > 0 ? req->n_coins : 1),
                       sizeof(*coins));
        if (!coins) goto done;
        for (int i = 0; i < req->n_coins; i++) {
            const nodus_v2_stake_coin_t *e = &req->coins[i];
            if (e->amount == 0) continue;
            if (memcmp(e->token, native_tok, 64) != 0) continue; /* non-native */
            if (e->unlock_block > req->tip) continue;            /* locked     */
            memcpy(coins[n_coins].nul, e->nul, 64);
            coins[n_coins].amount = e->amount;
            n_coins++;
        }
        qsort(coins, (size_t)n_coins, sizeof(*coins), nodus_v2_nul_cmp);
        for (int i = 0; i < n_coins && sum_in < need &&
                        n_in < (int)NODUS_V2_SPEND_MAX_IN; i++) {
            if (sum_in > UINT64_MAX - coins[i].amount) {
                rc = NODUS_V2_SPEND_ERR_INPUT_SUM;
                goto done;
            }
            memcpy(nulls[n_in], coins[i].nul, 64);
            sum_in += coins[i].amount;
            n_in++;
        }
    }
    if (n_in < 1 || sum_in < need) {
        if (err) {
            err->fee = fee; err->need = need; err->sum_in = sum_in;
            err->n_in = n_in;
        }
        rc = NODUS_V2_SPEND_ERR_INSUFFICIENT;
        goto done;
    }
    const uint64_t change = sum_in - need;

    /* ── leg0 — the SYSTEM record call ─────────────────────────────── */
    uint32_t scall_len;
    if (is_stake) {
        /* staker_pk ‖ commission u16 ‖ bond u64 ‖ dest_fp[64 RAW] */
        scall_len = NODUS_V2_STAKE_CALL_LEN;
        scall = calloc(1, scall_len);
        if (!scall) goto done;
        memcpy(scall, req->pk, V2K_PK_LEN);
        scall[V2K_PK_LEN]     = (uint8_t)(req->commission_bps >> 8);
        scall[V2K_PK_LEN + 1] = (uint8_t)req->commission_bps;
        put_u64(scall + V2K_PK_LEN + 2, req->amount);
        memcpy(scall + V2K_PK_LEN + 10, req->dest_fp, 64);
    } else if (is_streg) {
        /* node_pk ‖ bond u64 ‖ payee_fp[64 RAW] (rtn_streg_parse) */
        scall_len = NODUS_V2_STREG_CALL_LEN;
        scall = calloc(1, scall_len);
        if (!scall) goto done;
        memcpy(scall, req->pk, V2K_PK_LEN);
        put_u64(scall + V2K_PK_LEN, req->amount);
        memcpy(scall + V2K_PK_LEN + 8, req->dest_fp, 64);
    } else if (is_unstake) {
        /* validator_pk / node_pk — the signer itself
         * (RTN_SYS_UNSTAKE_CALL_LEN == RTN_SYS_STEXIT_CALL_LEN;
         * rtn_sys_stake_auth binds SHA3-512(call) to the signer) */
        _Static_assert(NODUS_V2_UNSTAKE_CALL_LEN == NODUS_V2_STEXIT_CALL_LEN,
                       "UNSTAKE and STORAGE_EXIT share the key-only call");
        scall_len = NODUS_V2_UNSTAKE_CALL_LEN;
        scall = calloc(1, scall_len);
        if (!scall) goto done;
        memcpy(scall, req->pk, V2K_PK_LEN);
    } else {
        /* delegator_pk (the signer) ‖ validator_pk ‖ amount u64 — one
         * layout for DELEGATE and UNDELEGATE (rtn_deleg_parse) */
        scall_len = NODUS_V2_DELEG_CALL_LEN;
        scall = calloc(1, scall_len);
        if (!scall) goto done;
        memcpy(scall, req->pk, V2K_PK_LEN);
        memcpy(scall + V2K_PK_LEN, req->validator_pk, V2K_PK_LEN);
        put_u64(scall + 2 * V2K_PK_LEN, req->amount);
    }

    /* ── leg1 — the CORE SYSFUND transfer section ──────────────────── */
    uint8_t signer_raw[64];
    char signer_fp[QGP_FP_HEX_BUFFER];
    if (qgp_sha3_512(req->pk, V2K_PK_LEN, signer_raw) != 0) {
        rc = NODUS_V2_SPEND_ERR_HASH;
        goto done;
    }
    qgp_fp_raw_to_hex(signer_raw, signer_fp);

    fcall = calloc(1, 2 + (size_t)NODUS_V2_SPEND_MAX_IN * 64 +
                          NODUS_V2_SPEND_OUT_LEN);
    if (!fcall) goto done;
    size_t off = 0;
    fcall[off++] = (uint8_t)n_in;
    for (int i = 0; i < n_in; i++) { memcpy(fcall + off, nulls[i], 64); off += 64; }
    const uint8_t out_count = change > 0 ? 1 : 0;
    fcall[off++] = out_count;
    uint8_t change_id[64];
    memset(change_id, 0, sizeof(change_id));
    if (out_count) {
        /* deterministic change seed = SHA3-512(input nullifiers)[0..31] —
         * unique per input set, so the derived output id never collides */
        uint8_t seed_full[64];
        if (qgp_sha3_512((const uint8_t *)nulls, (size_t)n_in * 64,
                         seed_full) != 0) {
            rc = NODUS_V2_SPEND_ERR_HASH;
            goto done;
        }
        nodus_v2_xfer_out_put(fcall + off, signer_fp, change, NULL /* native */,
                              seed_full);
        uint8_t pre[160];
        memcpy(pre, fcall + off, 128);
        memcpy(pre + 128, seed_full, 32);
        if (qgp_sha3_512(pre, sizeof(pre), change_id) != 0) {
            rc = NODUS_V2_SPEND_ERR_HASH;
            goto done;
        }
        off += NODUS_V2_SPEND_OUT_LEN;
    }
    const uint32_t fcall_len = (uint32_t)off;

    /* ── two legs, kind-1 single signer each ───────────────────────── */
    auth0 = calloc(1, V2K_AUTH_LEN);
    auth1 = calloc(1, V2K_AUTH_LEN);
    pf    = calloc(1, sizeof(*pf));
    if (!auth0 || !auth1 || !pf) goto done;

    dna_env_leg_in_t legs[2];
    memset(legs, 0, sizeof(legs));
    legs[0].hdr.domain_id            = DNA_DOMAIN_SYSTEM;
    legs[0].hdr.runtime_op           = (uint32_t)op;
    legs[0].hdr.ruleset_version      = req->rs->sys_ruleset_version;
    legs[0].hdr.access_mode          = DNA_ENV_ACCESS_INVOKE;
    legs[0].hdr.auth_kind            = NODUS_RT_AUTHKIND_DSA87_MULTI_V1;
    legs[0].hdr.call_len             = scall_len;
    legs[0].hdr.auth_len             = V2K_AUTH_LEN;
    legs[0].hdr.res_max_effects      = NODUS_V2_STAKE_SYS_EFFECTS;
    legs[0].hdr.res_max_effect_bytes = NODUS_V2_STAKE_SYS_EFFECT_BYTES;
    legs[0].call_data = scall;
    legs[0].auth_data = auth0;
    legs[1].hdr.domain_id            = DNA_DOMAIN_CORE;
    legs[1].hdr.runtime_op           = DNA_CORERULE_SYSFUND;
    legs[1].hdr.ruleset_version      = req->rs->core_ruleset_version;
    legs[1].hdr.access_mode          = DNA_ENV_ACCESS_INVOKE;
    legs[1].hdr.auth_kind            = NODUS_RT_AUTHKIND_DSA87_MULTI_V1;
    legs[1].hdr.call_len             = fcall_len;
    legs[1].hdr.auth_len             = V2K_AUTH_LEN;
    legs[1].hdr.res_max_effects      = NODUS_V2_STAKE_FUND_EFFECTS;
    legs[1].hdr.res_max_effect_bytes = NODUS_V2_STAKE_FUND_EFFECT_BYTES;
    legs[1].call_data = fcall;
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
    lctx[0].domain_id       = DNA_DOMAIN_SYSTEM;
    lctx[0].ruleset_version = req->rs->sys_ruleset_version;
    memcpy(lctx[0].ruleset_hash, req->rs->sys_ruleset_hash, 64);
    lctx[1].domain_id       = DNA_DOMAIN_CORE;
    lctx[1].ruleset_version = req->rs->core_ruleset_version;
    memcpy(lctx[1].ruleset_hash, req->rs->core_ruleset_hash, 64);

    /* one key signs BOTH legs: it is the record identity AND the owner of
     * the funding inputs */
    {
        uint8_t *auths[2] = { auth0, auth1 };
        nodus_v2_spend_err_t se;
        memset(&se, 0, sizeof(se));
        rc = nodus_v2_env_sign_one_key(&env_in, auths, lctx, req->chain32,
                                       req->tip, req->pk, req->sk,
                                       &env_bytes, &env_len, pf, &se);
        if (rc != NODUS_V2_SPEND_OK) {
            if (err) err->leg = se.leg;
            goto done;
        }
    }

    /* ── read back what was BUILT, and refuse if it is not what was
     *    asked ─────────────────────────────────────────────────────── */
    rc = nodus_v2_stake_decode(env_bytes, env_len, &out->dec);
    if (rc != NODUS_V2_SPEND_OK) goto done;
    rc = NODUS_V2_SPEND_ERR_DECODE;
    {
        const nodus_v2_stake_decoded_t *d = &out->dec;
        if (d->op != (uint32_t)op || d->fee != fee || d->units != units ||
            d->expiry_height != req->expiry_height ||
            d->sys_ruleset_version != req->rs->sys_ruleset_version ||
            d->core_ruleset_version != req->rs->core_ruleset_version ||
            memcmp(d->identity_pk, req->pk, V2K_PK_LEN) != 0 ||
            (!is_unstake && d->amount != req->amount) ||
            d->n_in != n_in ||
            memcmp(d->in_nul, nulls, (size_t)n_in * 64) != 0 ||
            d->n_out != (int)out_count)
            goto done;
        if (is_stake) {
            if (d->commission_bps != req->commission_bps ||
                memcmp(d->dest_fp, req->dest_fp, 64) != 0)
                goto done;
        } else if (is_streg) {
            if (memcmp(d->dest_fp, req->dest_fp, 64) != 0) goto done;
        } else if (is_unstake) {
            if (d->amount != 0) goto done;   /* the call carries none */
        } else if (memcmp(d->validator_pk, req->validator_pk,
                          V2K_PK_LEN) != 0) {
            goto done;
        }
        if (out_count &&
            (memcmp(d->change_owner, signer_fp, 128) != 0 ||
             d->change_amount != change ||
             memcmp(d->change_id, change_id, 64) != 0))
            goto done;
    }

    memcpy(out->wire_id, pf->wire_id, 64);
    memcpy(out->intent_id, pf->intent_id, 64);
    out->fee     = fee;
    out->sum_in  = sum_in;
    out->change  = change;
    out->n_in    = n_in;
    out->env     = env_bytes;
    out->env_len = env_len;
    env_bytes = NULL;
    rc = NODUS_V2_SPEND_OK;

done:
    if (rc != NODUS_V2_SPEND_OK) memset(&out->dec, 0, sizeof(out->dec));
    free(env_bytes);
    free(pf);
    free(auth0);
    free(auth1);
    free(fcall);
    free(scall);
    free(coins);
    return rc;
}
