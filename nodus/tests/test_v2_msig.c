/**
 * @file nodus/tests/test_v2_msig.c
 * @brief The shared general-multisig client library (nodus/src/client/
 *        nodus_v2_msig.c) against the pre-move nodus-cli code, its own
 *        refusals, and the chain's auth hook.
 *
 * Governing records: docs/plans/decisions/2026-09-29-general-multisig.md
 * (M-of-N address, <= 7 keys per address, auth_kind 3, validity tip + 90)
 * with design docs/plans/2026-09-29-general-multisig-design.md §7 rev 2,
 * and docs/plans/decisions/2026-09-25-web-wallet-nodus-send-transport.md
 * ("İşlem kurucu": the wallet builds with the SAME C code as nodus-cli).
 *
 * ── WHAT THIS PROVES ────────────────────────────────────────────────────
 *  M0  Descriptor + address: nodus_v2_msig_desc_from_keys over the keys in
 *      a scrambled order yields EXACTLY the bytes of the pre-move
 *      `msig address` body restated here (qsort memcmp-ascending,
 *      dna_msig_desc_encode, dna_msig_address) — for 2-of-3 and 3-of-7 —
 *      and leaves the caller's buffer unchanged; a duplicate key, a zero
 *      key, N = 1, N = 8, M = 0 and M > N are refused.
 *  M1  The unsigned build: for the same descriptor, coins, recipient,
 *      amount, fee rule, gas price, K, chain id, tip, expiry and the same
 *      rand bytes, nodus_v2_msig_build's envelope, digest and intent_id
 *      equal BYTE FOR BYTE those of the pre-move `v2-envelope spend
 *      --msig` loop restated here (inputs ascending, out[0] recipient,
 *      out[1] change to the vault, the fee fixed point, the units ceiling
 *      with inputs + 1 reads, the pass-1 preflight digest) — with change
 *      (two outputs), without change (one output), at a gas price that
 *      raises the fee, and with K = N. The export TEXT equals the pre-move
 *      fprintf sequence (open_memstream) byte for byte.
 *  M2  Build refusals: fixed fee below the floor, fixed fee below
 *      units × gas price, inputs not covering amount + fee, a duplicate
 *      coin, a zero coin, K below M / above N, a failing rand; nothing is
 *      left allocated.
 *  M3  The export text: parse(encode(x)) == x; refused: another magic, a
 *      missing line, odd / uppercase envelope hex, a tip with trailing
 *      characters, a leading-zero tip, signers above 15.
 *  M4  The co-signer read-back: every field equals the request (vault
 *      address, M/N/K, expiry, fee, inputs ascending, recipient + amount,
 *      change + vault); REFUSED: a key outside the descriptor; an envelope
 *      byte changed inside the call (the amount), inside the fee, inside
 *      the expiry; the exported digest changed; the chain id changed; a
 *      tip past the expiry (expired); a descriptor swapped for another of
 *      the same length is NOT caught by the digest (it is not covered) —
 *      the review then names a DIFFERENT vault address, which is what a
 *      caller compares against the vault it expects (asserted).
 *  M5  The signature text round-trips; malformed texts are refused.
 *  M6  The combine: two of three members sign; nodus_v2_msig_combine
 *      writes them ascending by key; the chain's OWN auth hook
 *      (nodus_rt_auth_dsa87_v1, the compiled CORE runtime) reports the
 *      descriptor satisfied; refused: one signature for K = 2, a signature
 *      over another digest, a key outside the descriptor, a corrupted
 *      signature, the same key twice.
 *  M7  nodus_v2_msig_unsigned_auth writes count ‖ K × 7219 zero ‖ 1 ‖
 *      dlen BE ‖ descriptor, written out here by hand.
 *
 * ── WHAT IT REQUIRES ────────────────────────────────────────────────────
 * Compile flags: none beyond a default build. Environment: none. No
 * network, no database, no file. open_memstream (POSIX 2008, glibc).
 *
 * ── WHAT IT LEAVES BEHIND ───────────────────────────────────────────────
 * Nothing.
 *
 * ── HOW IT CAN LIE ──────────────────────────────────────────────────────
 *  1. The restatements of the pre-move nodus-cli code and the library were
 *     written by the same author on the same day; the restatement was
 *     copied from the pre-move source (git show 16b88ede:nodus/tools/
 *     nodus-cli.c, cmd_msig_address / cmd_v2_spend_msig), not captured
 *     from a running nodus-cli (that needs a node). No digest or intent_id
 *     is pinned as a literal: it would have to be produced by running a
 *     built binary, which the author was not allowed to do.
 *  2. The envelope is NOT run through the chain's CheckTx / FinalizeBlock
 *     here (no seeded chain): M6 runs only the auth hook. The Genesis
 *     Protocol harness / a live run exercises the spend itself.
 *  3. The Foundation 2-of-3 descriptor is NOT a fixture here (it is a
 *     local-only file); the web wallet's vault test checks the embedded
 *     copy against its documented address.
 *  4. Written, compiled, NOT RUN by its author (the BUILDER rule).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness_runtime.h"
#include "nodus/nodus_types.h"
#include "nodus/nodus_v2_spend.h"
#include "client/nodus_v2_msig.h"

#include "dnac/dnac.h"
#include "dnac/ledger_ids.h"
#include "dnac/env_wire.h"
#include "dnac/env_preflight.h"
#include "dnac/msig_wire.h"
#include "crypto/hash/qgp_sha3.h"
#include "crypto/sign/qgp_dilithium.h"
#include "crypto/utils/qgp_fingerprint.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(cond, msg) do {                                              \
    if (!(cond)) {                                                         \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, \
                (msg));                                                    \
        return 1;                                                          \
    }                                                                      \
    g_checks++;                                                            \
} while (0)

static int g_checks = 0;

#define MS_FLOOR  ((uint64_t)(DNAC_MIN_FEE_RAW > NODUS_W_BASE_TX_FEE \
                       ? DNAC_MIN_FEE_RAW : NODUS_W_BASE_TX_FEE))
#define MS_AHEAD  ((uint64_t)NODUS_CMT_APP_MAX_EXPIRY_AHEAD - 10u)
#define MS_TIP    1000u
#define MS_PK     2592u
#define MS_NKEYS  8

/* ══ fixed keys: seeds 0x11, 0x22, … ═════════════════════════════════ */

static uint8_t g_pk[MS_NKEYS][MS_PK], g_sk[MS_NKEYS][4896];

static int keys_init(void) {
    for (int i = 0; i < MS_NKEYS; i++) {
        uint8_t seed[32];
        memset(seed, 0x11 * (i + 1), sizeof(seed));
        if (qgp_dsa87_keypair_derand(g_pk[i], g_sk[i], seed) != 0) return -1;
    }
    return 0;
}

/* ══ the fixed rand: 0xA0, 0xA1, … across calls ══════════════════════ */

typedef struct { uint8_t next; int calls; int fail; } ms_rand_t;

static int ms_rand(void *ctx, uint8_t *buf, size_t len) {
    ms_rand_t *r = ctx;
    if (r->fail) return -1;
    for (size_t i = 0; i < len; i++) buf[i] = r->next++;
    r->calls++;
    return 0;
}

/* ══ the generation-1 ruleset: compiled table (nodus-cli's source) ═══ */

static const nodus_domain_runtime_t *g_core_rt;

static int table_rs(nodus_v2_ruleset_id_t *rs) {
    const nodus_domain_runtime_t *c =
        nodus_runtime_for_generation(NODUS_RT_GEN_1, DNA_DOMAIN_CORE);
    const nodus_domain_runtime_t *s =
        nodus_runtime_for_generation(NODUS_RT_GEN_1, DNA_DOMAIN_SYSTEM);
    if (!c || !s || !s->meter_policy) return -1;
    memset(rs, 0, sizeof(*rs));
    rs->core_ruleset_version = c->ruleset_version;
    memcpy(rs->core_ruleset_hash, c->ruleset_hash, 64);
    rs->meter_policy = s->meter_policy;
    g_core_rt = c;
    return 0;
}

/* ══ M0: the pre-move `msig address` body, restated ══════════════════ */

static int old_pk_cmp(const void *a, const void *b) {
    return memcmp(a, b, DNA_MSIG_PUBKEY_LEN);
}

static int old_desc(uint8_t m, uint8_t n, const uint8_t *keys_in,
                    uint8_t *desc, size_t *dl, uint8_t addr[64]) {
    uint8_t keys[DNA_MSIG_MAX_N * DNA_MSIG_PUBKEY_LEN];
    memcpy(keys, keys_in, (size_t)n * DNA_MSIG_PUBKEY_LEN);
    qsort(keys, (size_t)n, DNA_MSIG_PUBKEY_LEN, old_pk_cmp);
    if (dna_msig_desc_encode(m, n, keys, desc, DNA_MSIG_MAX_DESC_LEN, dl) != 0)
        return -1;
    return dna_msig_address(desc, *dl, addr);
}

/* the given key indices, contiguous */
static void pick_keys(const int *idx, int n, uint8_t *out) {
    for (int i = 0; i < n; i++)
        memcpy(out + (size_t)i * MS_PK, g_pk[idx[i]], MS_PK);
}

static int test_m0(void) {
    static const int ord3[3] = { 2, 0, 1 };
    static const int ord7[7] = { 6, 3, 0, 5, 1, 4, 2 };
    uint8_t keys[DNA_MSIG_MAX_N * MS_PK], copy[DNA_MSIG_MAX_N * MS_PK];
    uint8_t d_new[DNA_MSIG_MAX_DESC_LEN], d_old[DNA_MSIG_MAX_DESC_LEN];
    uint8_t a_new[64], a_old[64];
    size_t l_new = 0, l_old = 0;

    pick_keys(ord3, 3, keys);
    memcpy(copy, keys, 3 * MS_PK);
    CHECK(nodus_v2_msig_desc_from_keys(2, 3, keys, d_new, sizeof(d_new),
                                       &l_new, a_new) == NODUS_V2_SPEND_OK,
          "M0: 2-of-3 builds");
    CHECK(old_desc(2, 3, keys, d_old, &l_old, a_old) == 0, "M0: old 2-of-3");
    CHECK(l_new == l_old && l_new == DNA_MSIG_DESC_LEN(3) &&
          memcmp(d_new, d_old, l_new) == 0, "M0: 2-of-3 descriptor bytes");
    CHECK(memcmp(a_new, a_old, 64) == 0, "M0: 2-of-3 address");
    CHECK(memcmp(keys, copy, 3 * MS_PK) == 0, "M0: caller keys unchanged");

    pick_keys(ord7, 7, keys);
    CHECK(nodus_v2_msig_desc_from_keys(3, 7, keys, d_new, sizeof(d_new),
                                       &l_new, a_new) == NODUS_V2_SPEND_OK,
          "M0: 3-of-7 builds");
    CHECK(old_desc(3, 7, keys, d_old, &l_old, a_old) == 0, "M0: old 3-of-7");
    CHECK(l_new == l_old && memcmp(d_new, d_old, l_new) == 0 &&
          memcmp(a_new, a_old, 64) == 0, "M0: 3-of-7 bytes and address");

    /* refusals */
    static const int dup[3] = { 0, 1, 0 };
    pick_keys(dup, 3, keys);
    CHECK(nodus_v2_msig_desc_from_keys(2, 3, keys, d_new, sizeof(d_new),
                                       &l_new, a_new) == NODUS_V2_MSIG_ERR_DESC,
          "M0: duplicate key refused");
    pick_keys(ord3, 3, keys);
    memset(keys + MS_PK, 0, 32);
    CHECK(nodus_v2_msig_desc_from_keys(2, 3, keys, d_new, sizeof(d_new),
                                       &l_new, a_new) == NODUS_V2_MSIG_ERR_DESC,
          "M0: zero key refused");
    pick_keys(ord3, 3, keys);
    CHECK(nodus_v2_msig_desc_from_keys(1, 1, keys, d_new, sizeof(d_new),
                                       &l_new, a_new) == NODUS_V2_MSIG_ERR_DESC,
          "M0: N = 1 refused");
    CHECK(nodus_v2_msig_desc_from_keys(2, 8, keys, d_new, sizeof(d_new),
                                       &l_new, a_new) == NODUS_V2_MSIG_ERR_DESC,
          "M0: N = 8 refused");
    CHECK(nodus_v2_msig_desc_from_keys(0, 3, keys, d_new, sizeof(d_new),
                                       &l_new, a_new) == NODUS_V2_MSIG_ERR_DESC,
          "M0: M = 0 refused");
    CHECK(nodus_v2_msig_desc_from_keys(4, 3, keys, d_new, sizeof(d_new),
                                       &l_new, a_new) == NODUS_V2_MSIG_ERR_DESC,
          "M0: M > N refused");
    return 0;
}

/* ══ M1: the pre-move `v2-envelope spend --msig` loop, restated ══════ */

typedef struct {
    uint8_t *env;
    size_t   env_len;
    uint8_t  digest[64], intent_id[64];
    uint64_t fee, change, units;
} old_built_t;

static int old_build(const nodus_v2_ruleset_id_t *rs, const uint8_t *chain32,
                     uint64_t tip, const uint8_t *dbuf, size_t dlen,
                     const nodus_v2_coin_t *coins_in, int n_in,
                     const uint8_t to_raw[64], uint64_t amount, uint64_t fee,
                     int have_fee, uint64_t gas_price, long k_signers,
                     ms_rand_t *rnd, old_built_t *out) {
    memset(out, 0, sizeof(*out));
    uint8_t m = 0, n = 0, addr[64];
    if (dna_msig_desc_parse(dbuf, dlen, &m, &n, NULL) != 0 ||
        dna_msig_address(dbuf, dlen, addr) != 0)
        return -1;
    if (k_signers == 0) k_signers = m;
    if (k_signers < m || k_signers > n) return -1;
    char addr_hex[QGP_FP_HEX_BUFFER], to_fp[QGP_FP_HEX_BUFFER];
    qgp_fp_raw_to_hex(addr, addr_hex);
    qgp_fp_raw_to_hex(to_raw, to_fp);
    nodus_v2_coin_t ins[NODUS_V2_SPEND_MAX_IN];
    uint64_t sum_in = 0;
    for (int i = 0; i < n_in; i++) {
        ins[i] = coins_in[i];
        sum_in += ins[i].amount;
    }
    qsort(ins, (size_t)n_in, sizeof(ins[0]), nodus_v2_nul_cmp);
    const uint64_t fee_floor = MS_FLOOR;
    if (!have_fee) fee = fee_floor;
    if (fee < fee_floor) return -1;

    const uint32_t tail_len = 1u + 2u + (uint32_t)dlen;
    const uint32_t alen = 1u + (uint32_t)k_signers * NODUS_RT_AUTH_SIGNER_LEN +
                          tail_len;
    uint8_t *call = malloc(2 + (size_t)NODUS_V2_SPEND_MAX_IN * 64 +
                           2u * NODUS_V2_SPEND_OUT_LEN);
    uint8_t *auth = calloc(1, alen);
    dna_env_preflight_t *pf = calloc(1, sizeof(*pf));
    int rc = -1;
    if (!call || !auth || !pf) goto done;
    auth[0] = (uint8_t)k_signers;
    {
        uint8_t *t = auth + 1 + (size_t)k_signers * NODUS_RT_AUTH_SIGNER_LEN;
        t[0] = 1;
        t[1] = (uint8_t)(dlen >> 8);
        t[2] = (uint8_t)dlen;
        memcpy(t + 3, dbuf, dlen);
    }
    dna_env_leg_in_t leg;
    dna_env_in_t env_in;
    uint64_t change = 0, units = 0;
    for (int pass = 0; ; pass++) {
        if (amount > sum_in || fee > sum_in - amount) goto done;
        change = sum_in - amount - fee;
        size_t off = 0;
        call[off++] = (uint8_t)n_in;
        for (int i = 0; i < n_in; i++, off += 64)
            memcpy(call + off, ins[i].nul, 64);
        int n_out = change > 0 ? 2 : 1;
        call[off++] = (uint8_t)n_out;
        for (int o = 0; o < n_out; o++) {
            uint8_t seed[32];
            if (ms_rand(rnd, seed, sizeof(seed)) != 0) goto done;
            nodus_v2_xfer_out_put(call + off, o == 0 ? to_fp : addr_hex,
                                  o == 0 ? amount : change, NULL, seed);
            off += NODUS_V2_SPEND_OUT_LEN;
        }
        memset(&leg, 0, sizeof(leg));
        leg.hdr.domain_id       = DNA_DOMAIN_CORE;
        leg.hdr.runtime_op      = DNA_CORERULE_SPEND;
        leg.hdr.ruleset_version = rs->core_ruleset_version;
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
        env_in.expiry_height = tip + MS_AHEAD;          /* cli_env_expiry,
                                                         * no rule switch */
        env_in.fee_amount    = fee;
        env_in.leg_count     = 1;
        env_in.legs          = &leg;
        if (nodus_v2_spend_ceiling(&env_in, rs->meter_policy,
                                   (uint32_t)n_in + 1u, &units) != 0)
            goto done;
        env_in.res_max_total_units = units;
        uint64_t need = fee_floor;
        if (gas_price != 0) {
            if (units > UINT64_MAX / gas_price) goto done;
            if (units * gas_price > need) need = units * gas_price;
        }
        if (fee >= need) break;
        if (have_fee || pass >= 2) goto done;
        fee = need;
    }
    size_t env_len = 0, used = 0;
    if (dna_env_encoded_size(env_in.legs, env_in.leg_count, &env_len) != 0)
        goto done;
    out->env = malloc(env_len);
    if (!out->env || dna_env_encode(&env_in, out->env, env_len, &used) != 0 ||
        used != env_len)
        goto done;
    out->env_len = env_len;
    {
        dna_env_leg_ctx_t lctx;
        memset(&lctx, 0, sizeof(lctx));
        lctx.domain_id       = DNA_DOMAIN_CORE;
        lctx.ruleset_version = rs->core_ruleset_version;
        memcpy(lctx.ruleset_hash, rs->core_ruleset_hash, 64);
        if (dna_env_preflight(out->env, env_len, chain32, tip + 1, &lctx, 1,
                              pf) != DNA_ENV_PF_OK)
            goto done;
    }
    memcpy(out->digest, pf->auth_digest[0], 64);
    memcpy(out->intent_id, pf->intent_id, 64);
    out->fee = fee;
    out->change = change;
    out->units = units;
    rc = 0;
done:
    if (rc != 0) { free(out->env); out->env = NULL; }
    free(call);
    free(auth);
    free(pf);
    return rc;
}

static void old_hex_line(FILE *f, const char *key, const uint8_t *b,
                         size_t n) {
    fprintf(f, "%s ", key);
    for (size_t i = 0; i < n; i++) fprintf(f, "%02x", b[i]);
    fputc('\n', f);
}

/* the pre-move export writer, into memory */
static char *old_export_text(const uint8_t *chain32, uint64_t tip,
                             long k_signers, const uint8_t digest[64],
                             const uint8_t *env, size_t env_len,
                             size_t *len_out) {
    char *buf = NULL;
    size_t len = 0;
    FILE *f = open_memstream(&buf, &len);
    if (!f) return NULL;
    fprintf(f, "%s\n", "nodus-msig-export v1");
    old_hex_line(f, "chain_id", chain32, DNA_CHAIN_ID_LEN);
    fprintf(f, "tip %llu\n", (unsigned long long)tip);
    fprintf(f, "signers %ld\n", k_signers);
    old_hex_line(f, "digest", digest, 64);
    old_hex_line(f, "envelope", env, env_len);
    if (fclose(f) != 0) { free(buf); return NULL; }
    *len_out = len;
    return buf;
}

/* shared fixture: a 2-of-3 vault of keys 0, 1, 2 */
static uint8_t g_desc[DNA_MSIG_MAX_DESC_LEN], g_addr[64];
static size_t  g_desc_len;
static uint8_t g_chain[DNA_CHAIN_ID_LEN];
static uint8_t g_to[64];
static nodus_v2_coin_t g_coins[3];
static nodus_v2_ruleset_id_t g_rs;

static int fixture_init(void) {
    static const int ord[3] = { 1, 2, 0 };
    uint8_t keys[3 * MS_PK];
    pick_keys(ord, 3, keys);
    if (nodus_v2_msig_desc_from_keys(2, 3, keys, g_desc, sizeof(g_desc),
                                     &g_desc_len, g_addr) != NODUS_V2_SPEND_OK)
        return -1;
    memset(g_chain, 0xC4, sizeof(g_chain));
    memset(g_to, 0x5A, sizeof(g_to));
    memset(g_coins, 0, sizeof(g_coins));
    memset(g_coins[0].nul, 0x33, 64); g_coins[0].amount = 40000000000ULL;
    memset(g_coins[1].nul, 0x11, 64); g_coins[1].amount = 20000000000ULL;
    memset(g_coins[2].nul, 0x22, 64); g_coins[2].amount =  5000000000ULL;
    return table_rs(&g_rs);
}

static void base_req(nodus_v2_msig_build_req_t *r, ms_rand_t *rnd) {
    memset(r, 0, sizeof(*r));
    r->rs            = &g_rs;
    r->chain32       = g_chain;
    r->tip           = MS_TIP;
    r->expiry_height = MS_TIP + MS_AHEAD;
    r->desc          = g_desc;
    r->desc_len      = g_desc_len;
    r->coins         = g_coins;
    r->n_coins       = 3;
    r->to_fp         = g_to;
    r->amount        = 30000000000ULL;
    r->rand          = ms_rand;
    r->rand_ctx      = rnd;
}

/* One M1 case: library vs restated, envelope + digest + intent + text. */
static int m1_case(const char *what, uint64_t amount, int n_coins,
                   uint64_t gas_price, uint32_t k) {
    nodus_v2_msig_build_req_t req;
    ms_rand_t r_new = { 0xA0, 0, 0 }, r_old = { 0xA0, 0, 0 };
    base_req(&req, &r_new);
    req.amount = amount;
    req.n_coins = n_coins;
    req.gas_price = gas_price;
    req.signers = k;
    nodus_v2_msig_built_t b;
    nodus_v2_spend_err_t e;
    int rc = nodus_v2_msig_build(&req, &b, &e);
    CHECK(rc == NODUS_V2_SPEND_OK, what);
    old_built_t o;
    CHECK(old_build(&g_rs, g_chain, MS_TIP, g_desc, g_desc_len, g_coins,
                    n_coins, g_to, amount, 0, 0, gas_price, (long)k, &r_old,
                    &o) == 0, what);
    CHECK(b.env_len == o.env_len && memcmp(b.env, o.env, b.env_len) == 0,
          what);
    CHECK(memcmp(b.digest, o.digest, 64) == 0, what);
    CHECK(memcmp(b.intent_id, o.intent_id, 64) == 0, what);
    CHECK(b.fee == o.fee && b.change == o.change && b.units == o.units, what);
    CHECK(r_new.calls == r_old.calls, what);
    CHECK(memcmp(b.addr, g_addr, 64) == 0, what);
    CHECK(b.n_out == (b.change > 0 ? 2 : 1), what);
    {
        uint64_t need = MS_FLOOR;
        if (gas_price && b.units * gas_price > need) need = b.units * gas_price;
        CHECK(b.fee == need, what);
    }
    size_t tl_new = 0, tl_old = 0;
    char *t_new = NULL;
    CHECK(nodus_v2_msig_export_encode(g_chain, MS_TIP, b.signers, b.digest,
                                      b.env, b.env_len, &t_new, &tl_new) ==
          NODUS_V2_SPEND_OK, what);
    char *t_old = old_export_text(g_chain, MS_TIP,
                                  (long)(k ? k : 2u), o.digest, o.env,
                                  o.env_len, &tl_old);
    CHECK(t_old != NULL, what);
    CHECK(tl_new == tl_old && memcmp(t_new, t_old, tl_new) == 0, what);
    free(t_new);
    free(t_old);
    free(o.env);
    nodus_v2_msig_built_free(&b);
    return 0;
}

static int test_m1(void) {
    /* 30e9 of 65e9: change -> two outputs */
    if (m1_case("M1: with change", 30000000000ULL, 3, 0, 0)) return 1;
    /* exactly 20e9 + 5e9 - floor: no change -> one output */
    if (m1_case("M1: without change", 25000000000ULL - MS_FLOOR, 2, 0, 0))
        return 1;
    /* a gas price that lifts the fee above the floor */
    if (m1_case("M1: gas price pass", 30000000000ULL, 3, 100000ULL, 0))
        return 1;
    /* K = N */
    if (m1_case("M1: K = N", 30000000000ULL, 3, 0, 3)) return 1;
    return 0;
}

/* ══ M2: build refusals ═════════════════════════════════════════════ */

static int test_m2(void) {
    nodus_v2_msig_build_req_t req;
    nodus_v2_msig_built_t b;
    nodus_v2_spend_err_t e;
    ms_rand_t rnd = { 0xA0, 0, 0 };

    base_req(&req, &rnd);
    req.fee_fixed = 1; req.fee = MS_FLOOR - 1;
    CHECK(nodus_v2_msig_build(&req, &b, &e) == NODUS_V2_MSIG_ERR_FEE_FLOOR &&
          b.env == NULL, "M2: fixed fee below floor");

    base_req(&req, &rnd);
    req.fee_fixed = 1; req.fee = MS_FLOOR; req.gas_price = 1000000000ULL;
    CHECK(nodus_v2_msig_build(&req, &b, &e) == NODUS_V2_SPEND_ERR_FEE_BELOW_GAS &&
          b.env == NULL, "M2: fixed fee below gas");

    base_req(&req, &rnd);
    req.amount = 65000000000ULL;
    CHECK(nodus_v2_msig_build(&req, &b, &e) == NODUS_V2_SPEND_ERR_INSUFFICIENT,
          "M2: inputs do not cover amount + fee");

    nodus_v2_coin_t dup[2];
    memcpy(&dup[0], &g_coins[0], sizeof(dup[0]));
    memcpy(&dup[1], &g_coins[0], sizeof(dup[1]));
    base_req(&req, &rnd);
    req.coins = dup; req.n_coins = 2; req.amount = 1000;
    CHECK(nodus_v2_msig_build(&req, &b, &e) == NODUS_V2_MSIG_ERR_COIN,
          "M2: duplicate coin");

    nodus_v2_coin_t zero[1];
    memcpy(&zero[0], &g_coins[0], sizeof(zero[0]));
    zero[0].amount = 0;
    base_req(&req, &rnd);
    req.coins = zero; req.n_coins = 1; req.amount = 1;
    CHECK(nodus_v2_msig_build(&req, &b, &e) == NODUS_V2_MSIG_ERR_COIN,
          "M2: zero coin");

    base_req(&req, &rnd);
    req.signers = 1;
    CHECK(nodus_v2_msig_build(&req, &b, &e) == NODUS_V2_MSIG_ERR_SIGNERS,
          "M2: K below M");
    req.signers = 4;
    CHECK(nodus_v2_msig_build(&req, &b, &e) == NODUS_V2_MSIG_ERR_SIGNERS,
          "M2: K above N");

    ms_rand_t bad = { 0, 0, 1 };
    base_req(&req, &bad);
    CHECK(nodus_v2_msig_build(&req, &b, &e) == NODUS_V2_SPEND_ERR_RANDOM &&
          b.env == NULL, "M2: rand failure");

    base_req(&req, &rnd);
    req.tip = 0;
    CHECK(nodus_v2_msig_build(&req, &b, &e) == NODUS_V2_SPEND_ERR_ARG,
          "M2: tip 0");
    return 0;
}

/* ══ helpers for M3..M6: one built export ═══════════════════════════ */

static int make_export(uint32_t k, char **text, size_t *len,
                       nodus_v2_msig_built_t *b) {
    nodus_v2_msig_build_req_t req;
    nodus_v2_spend_err_t e;
    ms_rand_t rnd = { 0xA0, 0, 0 };
    base_req(&req, &rnd);
    req.signers = k;
    if (nodus_v2_msig_build(&req, b, &e) != NODUS_V2_SPEND_OK) return -1;
    return nodus_v2_msig_export_encode(g_chain, MS_TIP, b->signers, b->digest,
                                       b->env, b->env_len, text, len) ==
           NODUS_V2_SPEND_OK ? 0 : -1;
}

/* A copy of `t` with the first occurrence of `from` replaced by `to`
 * (same length). */
static char *text_swap(const char *t, size_t len, const char *from,
                       const char *to) {
    char *c = malloc(len + 1);
    if (!c) return NULL;
    memcpy(c, t, len);
    c[len] = '\0';
    char *p = strstr(c, from);
    if (!p || strlen(from) != strlen(to)) { free(c); return NULL; }
    memcpy(p, to, strlen(to));
    return c;
}

/* ══ M3: the export text ═════════════════════════════════════════════ */

static int test_m3(void) {
    char *t = NULL;
    size_t tl = 0;
    nodus_v2_msig_built_t b;
    CHECK(make_export(0, &t, &tl, &b) == 0, "M3: export");
    nodus_v2_msig_export_t x;
    CHECK(nodus_v2_msig_export_parse(t, tl, &x) == NODUS_V2_SPEND_OK,
          "M3: parse");
    CHECK(memcmp(x.chain32, g_chain, DNA_CHAIN_ID_LEN) == 0 &&
          x.tip == MS_TIP && x.signers == 2 &&
          memcmp(x.digest, b.digest, 64) == 0 && x.env_len == b.env_len &&
          memcmp(x.env, b.env, b.env_len) == 0, "M3: round trip");
    nodus_v2_msig_export_free(&x);

    char *bad;
    bad = text_swap(t, tl, "nodus-msig-export v1", "nodus-msig-exporT v1");
    CHECK(bad && nodus_v2_msig_export_parse(bad, tl, &x) ==
          NODUS_V2_MSIG_ERR_FORMAT && x.env == NULL, "M3: magic");
    free(bad);
    bad = text_swap(t, tl, "\ntip 1000\n", "\ntip 100a\n");
    CHECK(bad && nodus_v2_msig_export_parse(bad, tl, &x) ==
          NODUS_V2_MSIG_ERR_FORMAT, "M3: tip junk");
    free(bad);
    bad = text_swap(t, tl, "\ntip 1000\n", "\ntip 0100\n");
    CHECK(bad && nodus_v2_msig_export_parse(bad, tl, &x) ==
          NODUS_V2_MSIG_ERR_FORMAT, "M3: tip leading zero");
    free(bad);
    bad = text_swap(t, tl, "\nsigners 2\n", "\nsignerz 2\n");
    CHECK(bad && nodus_v2_msig_export_parse(bad, tl, &x) ==
          NODUS_V2_MSIG_ERR_FORMAT, "M3: missing signers");
    free(bad);
    bad = text_swap(t, tl, "\nenvelope 0", "\nenvelope A");
    CHECK(bad && nodus_v2_msig_export_parse(bad, tl, &x) ==
          NODUS_V2_MSIG_ERR_FORMAT && x.env == NULL, "M3: uppercase hex");
    free(bad);
    /* odd envelope hex: drop the final hex digit before the newline */
    {
        char *odd = malloc(tl);
        CHECK(odd != NULL, "M3: alloc");
        memcpy(odd, t, tl - 2);
        odd[tl - 2] = '\n';
        CHECK(nodus_v2_msig_export_parse(odd, tl - 1, &x) ==
              NODUS_V2_MSIG_ERR_FORMAT, "M3: odd hex");
        free(odd);
    }
    /* signers above 15 */
    nodus_v2_msig_built_free(&b);
    free(t);
    {
        char *t16 = NULL;
        size_t l16 = 0;
        static const uint8_t env1[1] = { 0 };
        uint8_t dg[64] = { 0 };
        CHECK(nodus_v2_msig_export_encode(g_chain, 5, 16, dg, env1, 1, &t16,
                                          &l16) == NODUS_V2_SPEND_OK,
              "M3: encode 16");
        CHECK(nodus_v2_msig_export_parse(t16, l16, &x) ==
              NODUS_V2_MSIG_ERR_FORMAT, "M3: signers 16 refused");
        free(t16);
    }
    return 0;
}

/* ══ M4: the co-signer's read-back ═══════════════════════════════════ */

static int review_text(const char *t, size_t tl, const uint8_t *pk,
                       nodus_v2_msig_review_t *rv) {
    nodus_v2_msig_export_t x;
    int rc = nodus_v2_msig_export_parse(t, tl, &x);
    if (rc != NODUS_V2_SPEND_OK) return rc;
    dna_env_preflight_t *pf = calloc(1, sizeof(*pf));
    if (!pf) { nodus_v2_msig_export_free(&x); return -999; }
    rc = nodus_v2_msig_review(&x, g_rs.core_ruleset_version,
                              g_rs.core_ruleset_hash, pk, pf, rv);
    free(pf);
    nodus_v2_msig_export_free(&x);
    return rc;
}

/* flip one byte of the envelope at byte offset `at` (hex position in the
 * text: after "envelope "). */
static char *flip_env_byte(const char *t, size_t tl, size_t at) {
    char *c = malloc(tl + 1);
    if (!c) return NULL;
    memcpy(c, t, tl);
    c[tl] = '\0';
    char *e = strstr(c, "\nenvelope ");
    if (!e) { free(c); return NULL; }
    char *h = e + 10 + 2 * at;
    *h = (*h == '0') ? '1' : '0';
    return c;
}

static int test_m4(void) {
    char *t = NULL;
    size_t tl = 0;
    nodus_v2_msig_built_t b;
    CHECK(make_export(0, &t, &tl, &b) == 0, "M4: export");
    nodus_v2_msig_review_t *rv = calloc(1, sizeof(*rv));
    CHECK(rv != NULL, "M4: alloc");

    CHECK(review_text(t, tl, g_pk[1], rv) == NODUS_V2_SPEND_OK, "M4: member");
    CHECK(memcmp(rv->addr, g_addr, 64) == 0 && rv->m == 2 && rv->n == 3 &&
          rv->signers == 2 && rv->tip == MS_TIP &&
          rv->expiry_height == MS_TIP + MS_AHEAD && rv->fee == b.fee &&
          rv->n_in == 3 && rv->n_out == 2, "M4: header fields");
    CHECK(memcmp(rv->in_nul[0], g_coins[1].nul, 64) == 0 &&
          memcmp(rv->in_nul[1], g_coins[2].nul, 64) == 0 &&
          memcmp(rv->in_nul[2], g_coins[0].nul, 64) == 0,
          "M4: inputs ascending");
    {
        char to_hex[QGP_FP_HEX_BUFFER], addr_hex[QGP_FP_HEX_BUFFER];
        static const uint8_t zero64[64] = { 0 };
        qgp_fp_raw_to_hex(g_to, to_hex);
        qgp_fp_raw_to_hex(g_addr, addr_hex);
        CHECK(strcmp(rv->out_owner[0], to_hex) == 0 &&
              rv->out_amount[0] == 30000000000ULL &&
              strcmp(rv->out_owner[1], addr_hex) == 0 &&
              rv->out_amount[1] == b.change &&
              memcmp(rv->out_token[0], zero64, 64) == 0 &&
              memcmp(rv->out_token[1], zero64, 64) == 0,
              "M4: outputs");
    }
    CHECK(memcmp(rv->digest, b.digest, 64) == 0 &&
          memcmp(rv->intent_id, b.intent_id, 64) == 0, "M4: ids");
    CHECK(review_text(t, tl, NULL, rv) == NODUS_V2_SPEND_OK,
          "M4: watch-only review (no key)");

    CHECK(review_text(t, tl, g_pk[5], rv) == NODUS_V2_MSIG_ERR_NOT_MEMBER,
          "M4: non-member key refused");

    /* the envelope's own layout (env_wire.h "Canonical wire layout"):
     * expiry_height u64 BE at 17..24, fee_amount u64 BE at 25..32 — the
     * low byte of each is changed; the call's first output amount is
     * located through a decode */
    char *bad;
    bad = flip_env_byte(t, tl, 32);
    CHECK(bad && review_text(bad, tl, g_pk[1], rv) != NODUS_V2_SPEND_OK,
          "M4: fee byte changed");
    free(bad);
    bad = flip_env_byte(t, tl, 24);
    CHECK(bad && review_text(bad, tl, g_pk[1], rv) != NODUS_V2_SPEND_OK,
          "M4: expiry byte changed");
    free(bad);
    {
        dna_env_view_t *v = calloc(1, sizeof(*v));
        CHECK(v && dna_env_decode(b.env, b.env_len, v) == 0, "M4: decode");
        /* out[0] amount: call + 1 + 3×64 + 1 + 128 + 7 (the low byte) */
        size_t at = v->call_off[0] + 1 + 3 * 64 + 1 + 128 + 7;
        free(v);
        bad = flip_env_byte(t, tl, at);
        CHECK(bad && review_text(bad, tl, g_pk[1], rv) ==
              NODUS_V2_MSIG_ERR_DIGEST, "M4: amount byte changed");
        free(bad);
    }
    {
        char hex[129];
        qgp_fp_raw_to_hex(b.digest, hex);
        char flipped[129];
        memcpy(flipped, hex, 129);
        flipped[0] = flipped[0] == '0' ? '1' : '0';
        bad = text_swap(t, tl, hex, flipped);
        CHECK(bad && review_text(bad, tl, g_pk[1], rv) ==
              NODUS_V2_MSIG_ERR_DIGEST, "M4: digest changed");
        free(bad);
    }
    {
        char from[80], to[80];
        memcpy(from, "chain_id c4c4", 13); from[13] = '\0';
        memcpy(to,   "chain_id c5c4", 13); to[13] = '\0';
        bad = text_swap(t, tl, from, to);
        CHECK(bad && review_text(bad, tl, g_pk[1], rv) != NODUS_V2_SPEND_OK,
              "M4: chain id changed");
        free(bad);
    }
    {
        /* a tip past the expiry: the envelope is expired at tip + 1 */
        char tipline[40];
        snprintf(tipline, sizeof(tipline), "\ntip %llu\n",
                 (unsigned long long)(MS_TIP + MS_AHEAD));
        nodus_v2_msig_export_t x;
        CHECK(nodus_v2_msig_export_parse(t, tl, &x) == NODUS_V2_SPEND_OK,
              "M4: parse for expiry");
        x.tip = MS_TIP + MS_AHEAD;            /* tip + 1 > expiry */
        dna_env_preflight_t *pf = calloc(1, sizeof(*pf));
        CHECK(pf != NULL, "M4: alloc");
        CHECK(nodus_v2_msig_review(&x, g_rs.core_ruleset_version,
                                   g_rs.core_ruleset_hash, g_pk[1], pf, rv) ==
              NODUS_V2_SPEND_ERR_PREFLIGHT1, "M4: expired refused");
        x.tip = MS_TIP + MS_AHEAD - 1;        /* tip + 1 == expiry: valid */
        CHECK(nodus_v2_msig_review(&x, g_rs.core_ruleset_version,
                                   g_rs.core_ruleset_hash, g_pk[1], pf, rv) ==
              NODUS_V2_SPEND_OK, "M4: last valid height accepted");
        free(pf);
        nodus_v2_msig_export_free(&x);
        (void)tipline;
    }
    {
        /* a descriptor of the same length (keys 0, 1, 3) swapped into the
         * auth blob: the digest does not cover it, so the review passes —
         * and reports ANOTHER address, which the caller compares */
        static const int ord[3] = { 0, 1, 3 };
        uint8_t keys[3 * MS_PK], d2[DNA_MSIG_MAX_DESC_LEN], a2[64];
        size_t l2 = 0;
        pick_keys(ord, 3, keys);
        CHECK(nodus_v2_msig_desc_from_keys(2, 3, keys, d2, sizeof(d2), &l2,
                                           a2) == NODUS_V2_SPEND_OK &&
              l2 == g_desc_len, "M4: second descriptor");
        nodus_v2_msig_export_t x;
        CHECK(nodus_v2_msig_export_parse(t, tl, &x) == NODUS_V2_SPEND_OK,
              "M4: parse for swap");
        dna_env_view_t *v = calloc(1, sizeof(*v));
        nodus_v2_msig_leg_t leg;
        CHECK(v && nodus_v2_msig_leg_open(&x, v, &leg) == NODUS_V2_SPEND_OK,
              "M4: leg");
        memcpy((uint8_t *)leg.desc, d2, l2);
        free(v);
        dna_env_preflight_t *pf = calloc(1, sizeof(*pf));
        CHECK(pf != NULL, "M4: alloc");
        CHECK(nodus_v2_msig_review(&x, g_rs.core_ruleset_version,
                                   g_rs.core_ruleset_hash, g_pk[1], pf, rv) ==
              NODUS_V2_SPEND_OK, "M4: swapped descriptor reviews");
        CHECK(memcmp(rv->addr, g_addr, 64) != 0 &&
              memcmp(rv->addr, a2, 64) == 0,
              "M4: swapped descriptor names ANOTHER vault");
        free(pf);
        nodus_v2_msig_export_free(&x);
    }
    free(rv);
    free(t);
    nodus_v2_msig_built_free(&b);
    return 0;
}

/* ══ M5: the signature text ══════════════════════════════════════════ */

static int test_m5(void) {
    uint8_t dg[64], sig[NODUS_V2_MSIG_SIG_LEN], pk2[MS_PK], dg2[64],
            sig2[NODUS_V2_MSIG_SIG_LEN];
    memset(dg, 0x7E, sizeof(dg));
    memset(sig, 0x3C, sizeof(sig));
    char *t = NULL;
    size_t tl = 0;
    CHECK(nodus_v2_msig_sig_encode(dg, g_pk[0], sig, &t, &tl) ==
          NODUS_V2_SPEND_OK, "M5: encode");
    CHECK(strncmp(t, "nodus-msig-sig v1\ndigest ", 25) == 0, "M5: magic");
    CHECK(nodus_v2_msig_sig_parse(t, tl, dg2, pk2, sig2) == NODUS_V2_SPEND_OK &&
          memcmp(dg, dg2, 64) == 0 && memcmp(pk2, g_pk[0], MS_PK) == 0 &&
          memcmp(sig, sig2, sizeof(sig)) == 0, "M5: round trip");
    char *bad = text_swap(t, tl, "nodus-msig-sig v1", "nodus-msig-sig v2");
    CHECK(bad && nodus_v2_msig_sig_parse(bad, tl, dg2, pk2, sig2) ==
          NODUS_V2_MSIG_ERR_FORMAT, "M5: wrong magic");
    free(bad);
    bad = text_swap(t, tl, "\nsig 3c", "\nsig 3C");
    CHECK(bad && nodus_v2_msig_sig_parse(bad, tl, dg2, pk2, sig2) ==
          NODUS_V2_MSIG_ERR_FORMAT, "M5: uppercase hex");
    free(bad);
    CHECK(nodus_v2_msig_sig_parse(t, tl - 3, dg2, pk2, sig2) ==
          NODUS_V2_MSIG_ERR_FORMAT, "M5: truncated");
    free(t);
    return 0;
}

/* ══ M6: the combine ═════════════════════════════════════════════════ */

static int sign_digest(int who, const uint8_t dg[64],
                       uint8_t sig[NODUS_V2_MSIG_SIG_LEN]) {
    size_t sl = 0;
    return qgp_dsa87_sign(sig, &sl, dg, 64, g_sk[who]) == 0 &&
           sl == NODUS_V2_MSIG_SIG_LEN ? 0 : -1;
}

static int combine_with(const char *t, size_t tl, const int *who, int n,
                        const uint8_t (*dgs)[64], int corrupt,
                        nodus_v2_msig_export_t *x, dna_env_preflight_t *pf,
                        int *bad) {
    static uint8_t pks[NODUS_RT_AUTH_MAX_SIGNERS][NODUS_V2_MSIG_PK_LEN];
    static uint8_t sigs[NODUS_RT_AUTH_MAX_SIGNERS][NODUS_V2_MSIG_SIG_LEN];
    if (nodus_v2_msig_export_parse(t, tl, x) != NODUS_V2_SPEND_OK) return -999;
    for (int i = 0; i < n; i++) {
        memcpy(pks[i], g_pk[who[i]], MS_PK);
        if (sign_digest(who[i], dgs[i], sigs[i]) != 0) return -998;
    }
    if (corrupt) sigs[0][100] ^= 0x01;
    return nodus_v2_msig_combine(x, g_rs.core_ruleset_version,
                                 g_rs.core_ruleset_hash, dgs,
                                 (const uint8_t (*)[NODUS_V2_MSIG_PK_LEN])pks,
                                 (const uint8_t (*)[NODUS_V2_MSIG_SIG_LEN])sigs,
                                 n, pf, bad);
}

static int test_m6(void) {
    char *t = NULL;
    size_t tl = 0;
    nodus_v2_msig_built_t b;
    CHECK(make_export(0, &t, &tl, &b) == 0, "M6: export");
    uint8_t dgs[4][64];
    for (int i = 0; i < 4; i++) memcpy(dgs[i], b.digest, 64);
    dna_env_preflight_t *pf = calloc(1, sizeof(*pf));
    CHECK(pf != NULL, "M6: alloc");
    nodus_v2_msig_export_t x;
    int bad = 0;

    static const int ok_who[2] = { 2, 0 };
    CHECK(combine_with(t, tl, ok_who, 2, (const uint8_t (*)[64])dgs, 0, &x,
                       pf, &bad) == NODUS_V2_SPEND_OK && bad == -1,
          "M6: two members combine");
    {
        dna_env_view_t *v = calloc(1, sizeof(*v));
        CHECK(v && dna_env_decode(x.env, x.env_len, v) == 0, "M6: decode");
        const uint8_t *a = x.env + v->auth_off[0];
        const uint8_t *s0 = a + 1, *s1 = a + 1 + NODUS_RT_AUTH_SIGNER_LEN;
        const uint8_t *lo = memcmp(g_pk[0], g_pk[2], MS_PK) < 0 ? g_pk[0] : g_pk[2];
        const uint8_t *hi = lo == g_pk[0] ? g_pk[2] : g_pk[0];
        CHECK(memcmp(s0, lo, MS_PK) == 0 && memcmp(s1, hi, MS_PK) == 0,
              "M6: signer slots ascending by key");
        nodus_rt_auth_verdict_t av;
        nodus_rt_exec_ctx_t ctx;
        memset(&ctx, 0, sizeof(ctx));
        memset(&av, 0, sizeof(av));
        ctx.chain_id = x.chain32;
        ctx.global_height = x.tip + 1;
        ctx.leg_auth_digest = x.digest;
        CHECK(nodus_rt_auth_dsa87_v1(g_core_rt, v, 0, &ctx, &av) == 0 &&
              av.n_msig == 1 && av.msig_satisfied[0],
              "M6: the chain's auth hook: descriptor satisfied");
        free(v);
    }
    nodus_v2_msig_export_free(&x);

    static const int one[1] = { 0 };
    CHECK(combine_with(t, tl, one, 1, (const uint8_t (*)[64])dgs, 0, &x, pf,
                       &bad) == NODUS_V2_MSIG_ERR_COUNT,
          "M6: one signature for K = 2");
    nodus_v2_msig_export_free(&x);

    uint8_t other[4][64];
    memcpy(other, dgs, sizeof(other));
    other[1][0] ^= 0xFF;
    CHECK(combine_with(t, tl, ok_who, 2, (const uint8_t (*)[64])other, 0, &x,
                       pf, &bad) == NODUS_V2_MSIG_ERR_SIG_DIGEST && bad == 1,
          "M6: a signature over another digest");
    nodus_v2_msig_export_free(&x);

    static const int outsider[2] = { 0, 4 };
    CHECK(combine_with(t, tl, outsider, 2, (const uint8_t (*)[64])dgs, 0, &x,
                       pf, &bad) == NODUS_V2_MSIG_ERR_NOT_MEMBER && bad == 1,
          "M6: a key outside the descriptor");
    nodus_v2_msig_export_free(&x);

    CHECK(combine_with(t, tl, ok_who, 2, (const uint8_t (*)[64])dgs, 1, &x,
                       pf, &bad) == NODUS_V2_MSIG_ERR_SIG && bad == 0,
          "M6: a corrupted signature");
    nodus_v2_msig_export_free(&x);

    static const int twice[2] = { 1, 1 };
    CHECK(combine_with(t, tl, twice, 2, (const uint8_t (*)[64])dgs, 0, &x,
                       pf, &bad) == NODUS_V2_MSIG_ERR_DUP_SIGNER,
          "M6: the same key twice");
    nodus_v2_msig_export_free(&x);

    free(pf);
    free(t);
    nodus_v2_msig_built_free(&b);
    return 0;
}

/* ══ M7: the unsigned auth blob, by hand ═════════════════════════════ */

static int test_m7(void) {
    const size_t need = 1u + 2u * NODUS_RT_AUTH_SIGNER_LEN + 3u + g_desc_len;
    uint8_t *a = malloc(need), *want = calloc(1, need);
    size_t al = 0;
    CHECK(a && want, "M7: alloc");
    want[0] = 2;
    want[1 + 2 * NODUS_RT_AUTH_SIGNER_LEN] = 1;
    want[2 + 2 * NODUS_RT_AUTH_SIGNER_LEN] = (uint8_t)(g_desc_len >> 8);
    want[3 + 2 * NODUS_RT_AUTH_SIGNER_LEN] = (uint8_t)(g_desc_len & 0xFF);
    memcpy(want + 4 + 2 * NODUS_RT_AUTH_SIGNER_LEN, g_desc, g_desc_len);
    CHECK(nodus_v2_msig_unsigned_auth(2, g_desc, g_desc_len, a, need, &al) ==
          NODUS_V2_SPEND_OK && al == need && memcmp(a, want, need) == 0,
          "M7: layout");
    CHECK(nodus_v2_msig_unsigned_auth(2, g_desc, g_desc_len, a, need - 1,
                                      &al) == NODUS_V2_SPEND_ERR_ARG,
          "M7: short buffer refused");
    CHECK(nodus_v2_msig_unsigned_auth(16, g_desc, g_desc_len, a, need, &al) ==
          NODUS_V2_SPEND_ERR_ARG, "M7: 16 signers refused");
    free(a);
    free(want);
    return 0;
}

int main(void) {
    if (keys_init() != 0) { fprintf(stderr, "key derivation failed\n"); return 1; }
    if (fixture_init() != 0) { fprintf(stderr, "fixture failed\n"); return 1; }
    if (test_m0() || test_m1() || test_m2() || test_m3() || test_m4() ||
        test_m5() || test_m6() || test_m7())
        return 1;
    printf("test_v2_msig: %d checks passed\n", g_checks);
    return 0;
}
