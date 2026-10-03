/**
 * @file nodus/src/client/nodus_v2_msig.c
 * @brief The shared general-multisig client library — see
 *        nodus/src/client/nodus_v2_msig.h for the contract and the
 *        governing records.
 *
 * Every function here is the body of a nodus-cli `msig` step moved out of
 * nodus/tools/nodus-cli.c unchanged in behaviour (the comments name the
 * step each came from); the printing stayed in the CLI.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "client/nodus_v2_msig.h"
#include "nodus/nodus_types.h"             /* NODUS_W_BASE_TX_FEE           */
#include "witness/nodus_witness_runtime.h" /* NODUS_RT_AUTH* widths, kind 3,
                                            * DNA_CORERULE_SPEND — header
                                            * constants only, no witness link
                                            * (as nodus_v2_spend.c)         */
#include "dnac/dnac.h"                     /* DNAC_MIN_FEE_RAW              */
#include "dnac/env_wire.h"
#include "dnac/env_preflight.h"
#include "crypto/hash/qgp_sha3.h"
#include "crypto/sign/qgp_dilithium.h"
#include "crypto/utils/qgp_fingerprint.h"

#include <stdlib.h>
#include <string.h>

#include "crypto/utils/qgp_safe_string.h"   /* Phase 03: unsafe-string poison guard */

_Static_assert(NODUS_V2_MSIG_PK_LEN == DNA_MSIG_PUBKEY_LEN,
               "a descriptor key is an ML-DSA-87 public key");
_Static_assert(NODUS_V2_MSIG_PK_LEN + NODUS_V2_MSIG_SIG_LEN ==
               NODUS_RT_AUTH_SIGNER_LEN,
               "a signer slot is pk ‖ sig");
_Static_assert(NODUS_V2_MSIG_PK_LEN == QGP_DSA87_PUBLICKEYBYTES &&
               NODUS_V2_MSIG_SIG_LEN == QGP_DSA87_SIGNATURE_BYTES,
               "ML-DSA-87 sizes");

/* nodus-cli cmd_v2_spend_msig fee_floor. */
#define V2M_FLOOR (DNAC_MIN_FEE_RAW > NODUS_W_BASE_TX_FEE \
                   ? (uint64_t)DNAC_MIN_FEE_RAW            \
                   : (uint64_t)NODUS_W_BASE_TX_FEE)
/* The CLI's fixed-point pass limit (`pass >= 2` refuses). */
#define V2M_MAX_PASSES 3
/* The largest export text a reader accepts (nodus-cli msig_export_read:
 * hex doubles the envelope; a 1 MiB envelope is the chain's ceiling). */
#define V2M_EXPORT_TEXT_MAX (2u * (size_t)DNA_ENV_MAX_TOTAL_LEN + 4096u)

/* ── small helpers ──────────────────────────────────────────────────── */

static int v2m_pk_cmp(const void *a, const void *b) {
    return memcmp(a, b, NODUS_V2_MSIG_PK_LEN);
}

static int v2m_key_in(const uint8_t *keys, uint8_t n, const uint8_t *pk) {
    for (uint8_t i = 0; i < n; i++)
        if (memcmp(keys + (size_t)i * NODUS_V2_MSIG_PK_LEN, pk,
                   NODUS_V2_MSIG_PK_LEN) == 0)
            return 1;
    return 0;
}

static int v2m_hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

/* Exactly 2n LOWERCASE hex characters -> n bytes (nodus-cli t6_hex_exact). */
static int v2m_hex_exact(const char *hex, size_t hex_len, uint8_t *out,
                         size_t n) {
    if (hex_len != 2 * n) return -1;
    for (size_t i = 0; i < n; i++) {
        int hi = v2m_hexval(hex[2 * i]), lo = v2m_hexval(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)(hi << 4 | lo);
    }
    return 0;
}

static void v2m_put_hex(char *out, const uint8_t *in, size_t n) {
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2 * i]     = digits[in[i] >> 4];
        out[2 * i + 1] = digits[in[i] & 15];
    }
}

/* Decimal digits only, no leading zero, within u64. */
static int v2m_parse_u64(const char *s, size_t n, uint64_t *out) {
    if (n == 0 || n > 20 || (n > 1 && s[0] == '0')) return -1;
    uint64_t v = 0;
    for (size_t i = 0; i < n; i++) {
        if (s[i] < '0' || s[i] > '9') return -1;
        uint64_t d = (uint64_t)(s[i] - '0');
        if (v > (UINT64_MAX - d) / 10u) return -1;
        v = v * 10u + d;
    }
    *out = v;
    return 0;
}

static size_t v2m_fmt_u64(uint64_t v, char *out) {
    char tmp[21];
    size_t n = 0;
    do { tmp[n++] = (char)('0' + (v % 10u)); v /= 10u; } while (v);
    for (size_t i = 0; i < n; i++) out[i] = tmp[n - 1 - i];
    return n;
}

/* The value of the line "key value" (nodus-cli msig_kv: the first line in
 * `txt` that starts with "key "; the value runs to the newline or the end).
 * @return 0 (*val / *vlen set) / -1 (no such line). */
static int v2m_kv(const char *txt, size_t len, const char *key,
                  const char **val, size_t *vlen) {
    const size_t kl = strlen(key);
    size_t p = 0;
    while (p < len) {
        const char *line = txt + p;
        const char *nl = memchr(line, '\n', len - p);
        const size_t ll = nl ? (size_t)(nl - line) : len - p;
        if (ll > kl && memcmp(line, key, kl) == 0 && line[kl] == ' ') {
            *val = line + kl + 1;
            *vlen = ll - kl - 1;
            return 0;
        }
        if (!nl) break;
        p += ll + 1;
    }
    return -1;
}

static int v2m_kv_hex(const char *txt, size_t len, const char *key,
                      uint8_t *out, size_t n) {
    const char *v = NULL;
    size_t vl = 0;
    if (v2m_kv(txt, len, key, &v, &vl) != 0) return -1;
    return v2m_hex_exact(v, vl, out, n);
}

static int v2m_kv_u64(const char *txt, size_t len, const char *key,
                      uint64_t *out) {
    const char *v = NULL;
    size_t vl = 0;
    if (v2m_kv(txt, len, key, &v, &vl) != 0) return -1;
    return v2m_parse_u64(v, vl, out);
}

/* The text begins with "<magic>\n" (nodus-cli's strncmp on the file). */
static int v2m_magic(const char *txt, size_t len, const char *magic) {
    const size_t ml = strlen(magic);
    return len > ml && memcmp(txt, magic, ml) == 0 && txt[ml] == '\n';
}

/* ── 1. descriptor + address from keys ──────────────────────────────── */

int nodus_v2_msig_desc_from_keys(uint8_t m, uint8_t n, const uint8_t *keys,
                                 uint8_t *desc_out, size_t desc_cap,
                                 size_t *desc_len_out,
                                 uint8_t addr_out[DNA_MSIG_ADDR_LEN]) {
    if (!keys || !desc_out || !desc_len_out || !addr_out)
        return NODUS_V2_SPEND_ERR_ARG;
    if (n < DNA_MSIG_MIN_N || n > DNA_MSIG_MAX_N || m < 1 || m > n)
        return NODUS_V2_MSIG_ERR_DESC;
    uint8_t sorted[DNA_MSIG_MAX_N * DNA_MSIG_PUBKEY_LEN];
    memcpy(sorted, keys, (size_t)n * DNA_MSIG_PUBKEY_LEN);
    /* the one canonical order — the encoder refuses anything else
     * (nodus-cli cmd_msig_address) */
    qsort(sorted, (size_t)n, DNA_MSIG_PUBKEY_LEN, v2m_pk_cmp);
    size_t dl = 0;
    if (dna_msig_desc_encode(m, n, sorted, desc_out, desc_cap, &dl) != 0)
        return NODUS_V2_MSIG_ERR_DESC;  /* duplicate / zero key / capacity */
    int rc = dna_msig_address(desc_out, dl, addr_out);
    if (rc == -2) return NODUS_V2_SPEND_ERR_HASH;
    if (rc != 0) return NODUS_V2_MSIG_ERR_DESC;
    *desc_len_out = dl;
    return NODUS_V2_SPEND_OK;
}

/* ── 2. the unsigned vault SPEND ────────────────────────────────────── */

int nodus_v2_msig_unsigned_auth(uint32_t signers, const uint8_t *desc,
                                size_t desc_len, uint8_t *out, size_t cap,
                                size_t *len_out) {
    if (!desc || !out || !len_out || signers < 1 ||
        signers > NODUS_RT_AUTH_MAX_SIGNERS || desc_len == 0 ||
        desc_len > DNA_MSIG_MAX_DESC_LEN)
        return NODUS_V2_SPEND_ERR_ARG;
    const size_t need = 1u + (size_t)signers * NODUS_RT_AUTH_SIGNER_LEN +
                        3u + desc_len;
    if (cap < need) return NODUS_V2_SPEND_ERR_ARG;
    memset(out, 0, need);
    out[0] = (uint8_t)signers;
    uint8_t *t = out + 1 + (size_t)signers * NODUS_RT_AUTH_SIGNER_LEN;
    t[0] = 1;                                /* dcount: one descriptor   */
    t[1] = (uint8_t)(desc_len >> 8);
    t[2] = (uint8_t)desc_len;
    memcpy(t + 3, desc, desc_len);
    *len_out = need;
    return NODUS_V2_SPEND_OK;
}

void nodus_v2_msig_built_free(nodus_v2_msig_built_t *b) {
    if (!b) return;
    free(b->env);
    memset(b, 0, sizeof(*b));
}

int nodus_v2_msig_build(const nodus_v2_msig_build_req_t *req,
                        nodus_v2_msig_built_t *out,
                        nodus_v2_spend_err_t *err) {
    if (err) memset(err, 0, sizeof(*err));
    if (!out) return NODUS_V2_SPEND_ERR_ARG;
    memset(out, 0, sizeof(*out));
    if (!req || !req->rs || !req->rs->meter_policy || !req->chain32 ||
        !req->desc || !req->coins || !req->to_fp || !req->rand ||
        req->tip == 0 || req->amount == 0 || req->n_coins < 1 ||
        req->n_coins > (int)NODUS_V2_SPEND_MAX_IN)
        return NODUS_V2_SPEND_ERR_ARG;

    uint8_t m = 0, n = 0;
    if (dna_msig_desc_parse(req->desc, req->desc_len, &m, &n, NULL) != 0)
        return NODUS_V2_MSIG_ERR_DESC;
    uint8_t addr[DNA_MSIG_ADDR_LEN];
    int arc = dna_msig_address(req->desc, req->desc_len, addr);
    if (arc == -2) return NODUS_V2_SPEND_ERR_HASH;
    if (arc != 0) return NODUS_V2_MSIG_ERR_DESC;
    const uint32_t k = req->signers ? req->signers : m;
    if (k < m || k > n) return NODUS_V2_MSIG_ERR_SIGNERS;

    char addr_hex[QGP_FP_HEX_BUFFER], to_hex[QGP_FP_HEX_BUFFER];
    qgp_fp_raw_to_hex(addr, addr_hex);
    qgp_fp_raw_to_hex(req->to_fp, to_hex);

    /* inputs: strictly ascending for the wire, no duplicate, >= 1 each */
    nodus_v2_coin_t ins[NODUS_V2_SPEND_MAX_IN];
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

    uint64_t fee = req->fee;
    if (!req->fee_fixed) fee = V2M_FLOOR;
    if (fee < V2M_FLOOR) {
        if (err) err->fee = fee;
        return NODUS_V2_MSIG_ERR_FEE_FLOOR;
    }

    /* ── build (fee fixed-point, at most 3 passes) ────────────────────── */
    const uint32_t tail_len = 1u + 2u + (uint32_t)req->desc_len;
    const uint32_t alen = 1u + k * NODUS_RT_AUTH_SIGNER_LEN + tail_len;
    uint8_t *call = malloc(2 + (size_t)NODUS_V2_SPEND_MAX_IN * 64 +
                           (size_t)NODUS_V2_MSIG_BUILD_OUTS *
                               NODUS_V2_SPEND_OUT_LEN);
    uint8_t *auth = calloc(1, alen);
    dna_env_preflight_t *pf = calloc(1, sizeof(*pf));
    uint8_t *env_bytes = NULL;
    int rc = NODUS_V2_SPEND_ERR_ALLOC;
    if (!call || !auth || !pf) goto done;
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
    uint64_t change = 0, units = 0;
    int n_out = 0;
    for (int pass = 0; ; pass++) {
        if (req->amount > sum_in || fee > sum_in - req->amount) {
            if (err) { err->fee = fee; err->pass = pass; }
            rc = NODUS_V2_SPEND_ERR_INSUFFICIENT;
            goto done;
        }
        change = sum_in - req->amount - fee;
        size_t off = 0;
        call[off++] = (uint8_t)n_in;
        for (int i = 0; i < n_in; i++, off += 64)
            memcpy(call + off, ins[i].nul, 64);
        n_out = change > 0 ? 2 : 1;
        call[off++] = (uint8_t)n_out;
        for (int o = 0; o < n_out; o++) {
            uint8_t seed[32];
            if (req->rand(req->rand_ctx, seed, sizeof(seed)) != 0) {
                rc = NODUS_V2_SPEND_ERR_RANDOM;
                goto done;
            }
            nodus_v2_xfer_out_put(call + off, o == 0 ? to_hex : addr_hex,
                                  o == 0 ? req->amount : change, NULL, seed);
            off += NODUS_V2_SPEND_OUT_LEN;
        }
        memset(&leg, 0, sizeof(leg));
        leg.hdr.domain_id       = DNA_DOMAIN_CORE;
        leg.hdr.runtime_op      = DNA_CORERULE_SPEND;
        leg.hdr.ruleset_version = req->rs->core_ruleset_version;
        leg.hdr.access_mode     = DNA_ENV_ACCESS_INVOKE;
        leg.hdr.auth_kind       = NODUS_RT_AUTHKIND_DSA87_MSIG_V1;
        leg.hdr.call_len        = (uint32_t)off;
        leg.hdr.auth_len        = alen;
        nodus_v2_spend_effect_decl((uint32_t)n_in, (uint32_t)n_out,
                                   &leg.hdr.res_max_effects,
                                   &leg.hdr.res_max_effect_bytes);
        leg.call_data = call;
        leg.auth_data = auth;
        memset(&env_in, 0, sizeof(env_in));
        env_in.expiry_height = req->expiry_height;
        env_in.fee_amount    = fee;
        env_in.leg_count     = 1;
        env_in.legs          = &leg;
        if (nodus_v2_spend_ceiling(&env_in, req->rs->meter_policy,
                                   (uint32_t)n_in + 1u, &units) != 0) {
            rc = NODUS_V2_SPEND_ERR_METER;
            goto done;
        }
        env_in.res_max_total_units = units;
        uint64_t need = V2M_FLOOR;
        if (req->gas_price != 0) {
            if (units > UINT64_MAX / req->gas_price) {
                rc = NODUS_V2_SPEND_ERR_GAS_OVERFLOW;
                goto done;
            }
            if (units * req->gas_price > need) need = units * req->gas_price;
        }
        if (fee >= need) break;
        if (req->fee_fixed || pass >= V2M_MAX_PASSES - 1) {
            if (err) {
                err->fee = fee; err->units = units; err->required = need;
                err->pass = pass;
            }
            rc = NODUS_V2_SPEND_ERR_FEE_BELOW_GAS;
            goto done;
        }
        fee = need;
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
        x.env = env_bytes;
        x.env_len = env_len;
        rc = nodus_v2_msig_digest(&x, req->rs->core_ruleset_version,
                                  req->rs->core_ruleset_hash, pf);
        if (rc != NODUS_V2_SPEND_OK) goto done;
    }
    out->env = env_bytes;
    env_bytes = NULL;
    out->env_len = env_len;
    memcpy(out->digest, pf->auth_digest[0], 64);
    memcpy(out->intent_id, pf->intent_id, 64);
    memcpy(out->addr, addr, sizeof(addr));
    out->m = m;
    out->n = n;
    out->signers = k;
    out->n_in = n_in;
    out->n_out = n_out;
    out->sum_in = sum_in;
    out->fee = fee;
    out->change = change;
    out->units = units;
    rc = NODUS_V2_SPEND_OK;

done:
    free(env_bytes);
    free(call);
    free(auth);
    free(pf);
    return rc;
}

/* ── 3. the export text ─────────────────────────────────────────────── */

int nodus_v2_msig_export_encode(const uint8_t chain32[DNA_CHAIN_ID_LEN],
                                uint64_t tip, uint32_t signers,
                                const uint8_t digest[64], const uint8_t *env,
                                size_t env_len, char **text_out,
                                size_t *len_out) {
    if (!chain32 || !digest || !env || env_len == 0 || !text_out ||
        !len_out || env_len > DNA_ENV_MAX_TOTAL_LEN)
        return NODUS_V2_SPEND_ERR_ARG;
    *text_out = NULL;
    *len_out = 0;
    static const char magic[] = NODUS_V2_MSIG_EXPORT_MAGIC "\n";
    const size_t cap = sizeof(magic) + 9 + 2 * DNA_CHAIN_ID_LEN + 1 +
                       4 + 20 + 1 + 8 + 20 + 1 + 7 + 128 + 1 + 9 +
                       2 * env_len + 1 + 1;
    char *t = malloc(cap);
    if (!t) return NODUS_V2_SPEND_ERR_ALLOC;
    size_t p = 0;
    memcpy(t + p, magic, sizeof(magic) - 1);              p += sizeof(magic) - 1;
    memcpy(t + p, "chain_id ", 9);                        p += 9;
    v2m_put_hex(t + p, chain32, DNA_CHAIN_ID_LEN);        p += 2 * DNA_CHAIN_ID_LEN;
    t[p++] = '\n';
    memcpy(t + p, "tip ", 4);                             p += 4;
    p += v2m_fmt_u64(tip, t + p);
    t[p++] = '\n';
    memcpy(t + p, "signers ", 8);                         p += 8;
    p += v2m_fmt_u64(signers, t + p);
    t[p++] = '\n';
    memcpy(t + p, "digest ", 7);                          p += 7;
    v2m_put_hex(t + p, digest, 64);                       p += 128;
    t[p++] = '\n';
    memcpy(t + p, "envelope ", 9);                        p += 9;
    v2m_put_hex(t + p, env, env_len);                     p += 2 * env_len;
    t[p++] = '\n';
    t[p] = '\0';
    *text_out = t;
    *len_out = p;
    return NODUS_V2_SPEND_OK;
}

void nodus_v2_msig_export_free(nodus_v2_msig_export_t *x) {
    if (!x) return;
    free(x->env);
    x->env = NULL;
    x->env_len = 0;
}

int nodus_v2_msig_export_parse(const char *text, size_t len,
                               nodus_v2_msig_export_t *x) {
    if (!x) return NODUS_V2_SPEND_ERR_ARG;
    memset(x, 0, sizeof(*x));
    if (!text || len == 0 || len > V2M_EXPORT_TEXT_MAX)
        return NODUS_V2_SPEND_ERR_ARG;
    if (!v2m_magic(text, len, NODUS_V2_MSIG_EXPORT_MAGIC))
        return NODUS_V2_MSIG_ERR_FORMAT;
    uint64_t signers = 0;
    if (v2m_kv_hex(text, len, "chain_id", x->chain32, DNA_CHAIN_ID_LEN) != 0 ||
        v2m_kv_hex(text, len, "digest", x->digest, 64) != 0 ||
        v2m_kv_u64(text, len, "tip", &x->tip) != 0 ||
        v2m_kv_u64(text, len, "signers", &signers) != 0 ||
        signers > NODUS_RT_AUTH_MAX_SIGNERS)
        return NODUS_V2_MSIG_ERR_FORMAT;
    x->signers = (uint32_t)signers;
    const char *v = NULL;
    size_t vl = 0;
    if (v2m_kv(text, len, "envelope", &v, &vl) != 0 || vl == 0 || vl % 2 != 0)
        return NODUS_V2_MSIG_ERR_FORMAT;
    x->env_len = vl / 2;
    x->env = malloc(x->env_len);
    if (!x->env) { x->env_len = 0; return NODUS_V2_SPEND_ERR_ALLOC; }
    if (v2m_hex_exact(v, vl, x->env, x->env_len) != 0) {
        nodus_v2_msig_export_free(x);
        return NODUS_V2_MSIG_ERR_FORMAT;
    }
    return NODUS_V2_SPEND_OK;
}

/* ── 4. the kind-3 leg, the CORE version, the digest ────────────────── */

int nodus_v2_msig_leg_open(const nodus_v2_msig_export_t *x,
                           dna_env_view_t *v, nodus_v2_msig_leg_t *leg) {
    if (!x || !x->env || !v || !leg) return NODUS_V2_SPEND_ERR_ARG;
    memset(leg, 0, sizeof(*leg));
    if (dna_env_decode(x->env, x->env_len, v) != 0 || v->leg_count != 1 ||
        v->leg[0].domain_id != DNA_DOMAIN_CORE ||
        v->leg[0].runtime_op != DNA_CORERULE_SPEND ||
        v->leg[0].auth_kind != NODUS_RT_AUTHKIND_DSA87_MSIG_V1)
        return NODUS_V2_MSIG_ERR_SHAPE;
    const uint8_t *a = v->buf + v->auth_off[0];
    const uint32_t alen = v->leg[0].auth_len;
    const uint64_t off = 1u + (uint64_t)x->signers * NODUS_RT_AUTH_SIGNER_LEN;
    if (x->signers < 1 || x->signers > NODUS_RT_AUTH_MAX_SIGNERS ||
        (uint64_t)alen < off + 3u || a[0] != x->signers || a[off] != 1)
        return NODUS_V2_MSIG_ERR_SHAPE;
    const size_t dl = ((size_t)a[off + 1] << 8) | a[off + 2];
    if ((uint64_t)alen != off + 3u + dl ||
        dna_msig_desc_parse(a + off + 3, dl, &leg->m, &leg->n,
                            &leg->keys) != 0) {
        memset(leg, 0, sizeof(*leg));
        return NODUS_V2_MSIG_ERR_DESC;
    }
    leg->desc = a + off + 3;
    leg->desc_len = dl;
    return NODUS_V2_SPEND_OK;
}

int nodus_v2_msig_core_version(const uint8_t *env, size_t env_len,
                               uint32_t *version_out) {
    if (!env || !version_out) return NODUS_V2_SPEND_ERR_ARG;
    dna_env_view_t *v = calloc(1, sizeof(*v));
    if (!v) return NODUS_V2_SPEND_ERR_ALLOC;
    int rc = NODUS_V2_MSIG_ERR_RULESET;
    if (dna_env_decode(env, env_len, v) == 0)
        for (uint16_t l = 0; l < v->leg_count; l++)
            if (v->leg[l].domain_id == DNA_DOMAIN_CORE) {
                *version_out = v->leg[l].ruleset_version;
                rc = NODUS_V2_SPEND_OK;
                break;
            }
    free(v);
    return rc;
}

int nodus_v2_msig_digest(const nodus_v2_msig_export_t *x,
                         uint32_t core_version,
                         const uint8_t core_hash[DNA_ENV_RULESET_HASH_LEN],
                         dna_env_preflight_t *pf) {
    if (!x || !x->env || !core_hash || !pf || x->tip == UINT64_MAX)
        return NODUS_V2_SPEND_ERR_ARG;
    dna_env_leg_ctx_t lctx;
    memset(&lctx, 0, sizeof(lctx));
    lctx.domain_id       = DNA_DOMAIN_CORE;
    lctx.ruleset_version = core_version;
    memcpy(lctx.ruleset_hash, core_hash, DNA_ENV_RULESET_HASH_LEN);
    if (dna_env_preflight(x->env, x->env_len, x->chain32, x->tip + 1, &lctx,
                          1, pf) != DNA_ENV_PF_OK)
        return NODUS_V2_SPEND_ERR_PREFLIGHT1;
    return NODUS_V2_SPEND_OK;
}

/* ── 5. the co-signer's read-back ───────────────────────────────────── */

int nodus_v2_msig_review(const nodus_v2_msig_export_t *x,
                         uint32_t core_version,
                         const uint8_t core_hash[DNA_ENV_RULESET_HASH_LEN],
                         const uint8_t *signer_pk, dna_env_preflight_t *pf,
                         nodus_v2_msig_review_t *out) {
    if (!out) return NODUS_V2_SPEND_ERR_ARG;
    memset(out, 0, sizeof(*out));
    if (!x || !x->env || !core_hash || !pf) return NODUS_V2_SPEND_ERR_ARG;
    dna_env_view_t *v = calloc(1, sizeof(*v));
    if (!v) return NODUS_V2_SPEND_ERR_ALLOC;
    nodus_v2_msig_leg_t leg;
    int rc = nodus_v2_msig_leg_open(x, v, &leg);
    if (rc != NODUS_V2_SPEND_OK) goto done;
    if (signer_pk && !v2m_key_in(leg.keys, leg.n, signer_pk)) {
        rc = NODUS_V2_MSIG_ERR_NOT_MEMBER;
        goto done;
    }
    /* never sign a digest you did not derive yourself */
    rc = nodus_v2_msig_digest(x, core_version, core_hash, pf);
    if (rc != NODUS_V2_SPEND_OK) goto done;
    if (memcmp(pf->auth_digest[0], x->digest, 64) != 0) {
        rc = NODUS_V2_MSIG_ERR_DIGEST;
        goto done;
    }
    {
        int arc = dna_msig_address(leg.desc, leg.desc_len, out->addr);
        if (arc != 0) {
            rc = arc == -2 ? NODUS_V2_SPEND_ERR_HASH : NODUS_V2_MSIG_ERR_DESC;
            goto done;
        }
    }
    /* The SPEND call is nin u8 ‖ nin × nullifier[64] ‖ nout u8 ‖ nout ×
     * NODUS_V2_SPEND_OUT_LEN (the build above, and the chain's
     * rtn_spend_parse). Nothing is read before its length is proved
     * against the leg's own call_len: a short or inconsistent call is
     * REFUSED, never displayed. */
    const uint8_t *c = v->buf + v->call_off[0];
    const size_t clen = v->leg[0].call_len;
    if (clen < 2 || c[0] < 1 || c[0] > NODUS_V2_SPEND_MAX_IN ||
        clen < 2 + (size_t)c[0] * 64) {
        rc = NODUS_V2_MSIG_ERR_CALL;
        goto done;
    }
    const uint8_t nin = c[0];
    const uint8_t nout = c[1 + (size_t)nin * 64];
    const uint8_t *outs = c + 1 + (size_t)nin * 64 + 1;
    if (nout < 1 || nout > NODUS_V2_MSIG_MAX_OUTS ||
        clen != 2 + (size_t)nin * 64 + (size_t)nout * NODUS_V2_SPEND_OUT_LEN) {
        rc = NODUS_V2_MSIG_ERR_CALL;
        goto done;
    }
    for (uint8_t i = 0; i < nin; i++)
        memcpy(out->in_nul[i], c + 1 + (size_t)i * 64, 64);
    for (uint8_t o = 0; o < nout; o++) {
        const uint8_t *r = outs + (size_t)o * NODUS_V2_SPEND_OUT_LEN;
        for (int b = 0; b < 128; b++)
            if (v2m_hexval((char)r[b]) < 0) {
                rc = NODUS_V2_MSIG_ERR_CALL;
                goto done;
            }
        memcpy(out->out_owner[o], r, 128);
        out->out_owner[o][128] = '\0';
        uint64_t amt = 0;
        for (int b = 0; b < 8; b++) amt = (amt << 8) | r[128 + b];
        out->out_amount[o] = amt;
        memcpy(out->out_token[o], r + 136, 64);
    }
    out->m = leg.m;
    out->n = leg.n;
    out->signers = x->signers;
    out->tip = x->tip;
    out->expiry_height = v->expiry_height;
    out->fee = v->fee_amount;
    out->n_in = nin;
    out->n_out = nout;
    memcpy(out->digest, x->digest, 64);
    memcpy(out->intent_id, pf->intent_id, 64);
    rc = NODUS_V2_SPEND_OK;
done:
    if (rc != NODUS_V2_SPEND_OK) memset(out, 0, sizeof(*out));
    free(v);
    return rc;
}

/* ── 6. the signature text ──────────────────────────────────────────── */

int nodus_v2_msig_sig_encode(const uint8_t digest[64],
                             const uint8_t pk[NODUS_V2_MSIG_PK_LEN],
                             const uint8_t sig[NODUS_V2_MSIG_SIG_LEN],
                             char **text_out, size_t *len_out) {
    if (!digest || !pk || !sig || !text_out || !len_out)
        return NODUS_V2_SPEND_ERR_ARG;
    *text_out = NULL;
    *len_out = 0;
    static const char magic[] = NODUS_V2_MSIG_SIG_MAGIC "\n";
    const size_t cap = sizeof(magic) + 7 + 128 + 1 + 7 +
                       2 * NODUS_V2_MSIG_PK_LEN + 1 + 4 +
                       2 * NODUS_V2_MSIG_SIG_LEN + 1 + 1;
    char *t = malloc(cap);
    if (!t) return NODUS_V2_SPEND_ERR_ALLOC;
    size_t p = 0;
    memcpy(t + p, magic, sizeof(magic) - 1);              p += sizeof(magic) - 1;
    memcpy(t + p, "digest ", 7);                          p += 7;
    v2m_put_hex(t + p, digest, 64);                       p += 128;
    t[p++] = '\n';
    memcpy(t + p, "pubkey ", 7);                          p += 7;
    v2m_put_hex(t + p, pk, NODUS_V2_MSIG_PK_LEN);         p += 2 * NODUS_V2_MSIG_PK_LEN;
    t[p++] = '\n';
    memcpy(t + p, "sig ", 4);                             p += 4;
    v2m_put_hex(t + p, sig, NODUS_V2_MSIG_SIG_LEN);       p += 2 * NODUS_V2_MSIG_SIG_LEN;
    t[p++] = '\n';
    t[p] = '\0';
    *text_out = t;
    *len_out = p;
    return NODUS_V2_SPEND_OK;
}

int nodus_v2_msig_sig_parse(const char *text, size_t len, uint8_t digest[64],
                            uint8_t pk[NODUS_V2_MSIG_PK_LEN],
                            uint8_t sig[NODUS_V2_MSIG_SIG_LEN]) {
    if (!text || !digest || !pk || !sig || len == 0 ||
        len > NODUS_V2_MSIG_SIG_TEXT_MAX)
        return NODUS_V2_SPEND_ERR_ARG;
    if (!v2m_magic(text, len, NODUS_V2_MSIG_SIG_MAGIC) ||
        v2m_kv_hex(text, len, "digest", digest, 64) != 0 ||
        v2m_kv_hex(text, len, "pubkey", pk, NODUS_V2_MSIG_PK_LEN) != 0 ||
        v2m_kv_hex(text, len, "sig", sig, NODUS_V2_MSIG_SIG_LEN) != 0)
        return NODUS_V2_MSIG_ERR_FORMAT;
    return NODUS_V2_SPEND_OK;
}

/* ── 7. the combine ─────────────────────────────────────────────────── */

int nodus_v2_msig_sig_check(const nodus_v2_msig_export_t *x,
                            const nodus_v2_msig_leg_t *leg,
                            const uint8_t digest[64],
                            const uint8_t pk[NODUS_V2_MSIG_PK_LEN],
                            const uint8_t sig[NODUS_V2_MSIG_SIG_LEN]) {
    if (!x || !leg || !leg->keys || !digest || !pk || !sig)
        return NODUS_V2_SPEND_ERR_ARG;
    if (memcmp(digest, x->digest, 64) != 0)
        return NODUS_V2_MSIG_ERR_SIG_DIGEST;
    if (!v2m_key_in(leg->keys, leg->n, pk))
        return NODUS_V2_MSIG_ERR_NOT_MEMBER;
    if (qgp_dsa87_verify(sig, NODUS_V2_MSIG_SIG_LEN, x->digest, 64, pk) != 0)
        return NODUS_V2_MSIG_ERR_SIG;
    return NODUS_V2_SPEND_OK;
}

int nodus_v2_msig_assemble(nodus_v2_msig_export_t *x,
                           const dna_env_view_t *v,
                           const uint8_t (*pks)[NODUS_V2_MSIG_PK_LEN],
                           const uint8_t (*sigs)[NODUS_V2_MSIG_SIG_LEN],
                           int n_sig) {
    if (!x || !x->env || !v || !pks || !sigs || n_sig < 1 ||
        v->buf != x->env || v->leg_count != 1)
        return NODUS_V2_SPEND_ERR_ARG;
    if ((uint32_t)n_sig != x->signers) return NODUS_V2_MSIG_ERR_COUNT;
    /* ascending pubkey order (the ONE canonical signer encoding), no
     * duplicate key — selection sort over <= 15 entries (nodus-cli
     * cmd_msig_combine) */
    uint8_t *a = x->env + v->auth_off[0];
    for (int i = 0; i < n_sig; i++) {
        int best = -1;
        for (int j = 0; j < n_sig; j++) {
            int used = 0;
            for (int t = 0; t < i; t++)
                if (memcmp(a + 1 + (size_t)t * NODUS_RT_AUTH_SIGNER_LEN,
                           pks[j], NODUS_V2_MSIG_PK_LEN) == 0) used = 1;
            if (used) continue;
            if (best < 0 || memcmp(pks[j], pks[best], NODUS_V2_MSIG_PK_LEN) < 0)
                best = j;
        }
        if (best < 0) return NODUS_V2_MSIG_ERR_DUP_SIGNER;
        uint8_t *slot = a + 1 + (size_t)i * NODUS_RT_AUTH_SIGNER_LEN;
        memcpy(slot, pks[best], NODUS_V2_MSIG_PK_LEN);
        memcpy(slot + NODUS_V2_MSIG_PK_LEN, sigs[best], NODUS_V2_MSIG_SIG_LEN);
    }
    return NODUS_V2_SPEND_OK;
}

int nodus_v2_msig_combine(nodus_v2_msig_export_t *x, uint32_t core_version,
                          const uint8_t core_hash[DNA_ENV_RULESET_HASH_LEN],
                          const uint8_t (*digests)[64],
                          const uint8_t (*pks)[NODUS_V2_MSIG_PK_LEN],
                          const uint8_t (*sigs)[NODUS_V2_MSIG_SIG_LEN],
                          int n_sig, dna_env_preflight_t *pf,
                          int *bad_index) {
    if (bad_index) *bad_index = -1;
    if (!x || !x->env || !core_hash || !digests || !pks || !sigs || !pf ||
        n_sig < 1 || n_sig > (int)NODUS_RT_AUTH_MAX_SIGNERS)
        return NODUS_V2_SPEND_ERR_ARG;
    dna_env_view_t *v = calloc(1, sizeof(*v));
    if (!v) return NODUS_V2_SPEND_ERR_ALLOC;
    nodus_v2_msig_leg_t leg;
    int rc = nodus_v2_msig_leg_open(x, v, &leg);
    if (rc != NODUS_V2_SPEND_OK) goto done;
    if ((uint32_t)n_sig != x->signers) {
        rc = NODUS_V2_MSIG_ERR_COUNT;
        goto done;
    }
    rc = nodus_v2_msig_digest(x, core_version, core_hash, pf);
    if (rc != NODUS_V2_SPEND_OK) goto done;
    if (memcmp(pf->auth_digest[0], x->digest, 64) != 0) {
        rc = NODUS_V2_MSIG_ERR_DIGEST;
        goto done;
    }
    for (int i = 0; i < n_sig; i++) {
        rc = nodus_v2_msig_sig_check(x, &leg, digests[i], pks[i], sigs[i]);
        if (rc != NODUS_V2_SPEND_OK) {
            if (bad_index) *bad_index = i;
            goto done;
        }
    }
    rc = nodus_v2_msig_assemble(x, v, pks, sigs, n_sig);
    if (rc != NODUS_V2_SPEND_OK) goto done;
    /* pass-2 self-check: the signed envelope still preflights */
    rc = nodus_v2_msig_digest(x, core_version, core_hash, pf);
    if (rc == NODUS_V2_SPEND_ERR_PREFLIGHT1) rc = NODUS_V2_SPEND_ERR_PREFLIGHT2;
done:
    free(v);
    return rc;
}
