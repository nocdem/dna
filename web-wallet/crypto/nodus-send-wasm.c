/* NODUS send module — the C side of the web wallet's NODUS balance / send /
 * confirmation (package (c3) of docs/plans/2026-09-25-web-wallet-nodus-send-
 * design.md rev 2: §0a.3 "(c3)", §1.3, §1.4, §1.5).
 *
 * Governing records (docs/plans/decisions/):
 *   2026-09-25-web-wallet-nodus-send-transport.md — the browser opens its OWN
 *     tier-2 session over the node's WebSocket entry; the SPEND is built by the
 *     SAME C code nodus-cli uses (nodus/src/client/nodus_v2_spend.c), no JS
 *     rewrite; the session stays open until the wallet locks; ONE thread
 *     (Asyncify); the ruleset identity comes from the GENERATED
 *     nodus/include/nodus/nodus_ruleset_pins.h, whose policy digest this module
 *     recomputes before it builds anything (addendum 2026-09-29 "Yol 2"); a
 *     pinned client is ML-KEM-1024 only (addendum 2026-09-29).
 *   2026-09-23-web-wallet-mldsa-hedged-signing.md İSTİSNA 1 / İSTİSNA 2 — the
 *     NODUS secret key stays in this module's memory until lock; the module
 *     signs with its own copy of shared/crypto/sign (hedged, browser CSPRNG).
 *   2026-09-25-mempool-policy.md 1 + note 2026-09-26-note-to-web-wallet-
 *     session-expiry.md — expiry_height = tip + 90; tip 0 / unknown: no send.
 *   2026-09-25-gas-price.md — fee = max(floor, units x gas_price), gas_price
 *     from dnac_fee_info on the same session.
 *
 * WHAT IS HERE: small wrappers only. Every chain rule is the shared builder's
 * (nodus_v2_spend_plan / nodus_v2_spend_build), every network call is the
 * nodus client's (nodus/src/client/nodus_client.c, browser branches from
 * package (c1)). The request each wrapper fills is nodus-cli's
 * `v2-envelope spend` (nodus/tools/nodus-cli.c cmd_v2_spend) for one native
 * spend: fee floor max(DNAC_MIN_FEE_RAW, NODUS_W_BASE_TX_FEE), not fixed,
 * largest-first selection, count 1, no shard, expiry tip + 90.
 *
 * THREE BUILDS of this one file (web-wallet/scripts/build-nodus-send-wasm.sh,
 * build-nodus-send-native-vector.sh):
 *   shipped   emcc, -DNODUS_SEND_RELEASE           src/nodus/send.{js,wasm}
 *   test      emcc, -DNODUS_SEND_TEST_FIXED_RANDOM parity only, never shipped
 *   vector    cc,   -DNODUS_SEND_OFFLINE_ONLY -DNODUS_SEND_TEST_FIXED_RANDOM
 *             (no network code; web-wallet/crypto/nodus-send-native-vector.c)
 *
 * RANDOMNESS: every random byte of this module goes through ONE function,
 * qgp_platform_random (defined below; qgp_platform_linux.c is not linked):
 * nodus_random (nodus_sign.c) and qgp_randombytes (qgp_random.c) both call it,
 * so it covers the client nonce, the KEM encapsulation coins, the output
 * seeds and the hedged ML-DSA `rnd` (shared/crypto/sign/dsa/config.h
 * DILITHIUM_RANDOMIZED_SIGNING is unconditional; dsa/randombytes.h maps
 * randombytes to qgp_randombytes). Shipped build: getentropy(), which
 * Emscripten routes to the browser CSPRNG (emsdk 6.0.10:
 * system/lib/libc/musl/src/misc/getentropy.c:22 __wasi_random_get ->
 * src/lib/libwasi.js:629 random_get -> randomFill -> :618
 * crypto.getRandomValues). TEST builds: a caller-loaded byte buffer consumed
 * in order, failing when exhausted — no generator, so the native vector and
 * the test wasm fed the same bytes build the same envelope.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#if defined(NODUS_SEND_RELEASE) && defined(NODUS_SEND_TEST_FIXED_RANDOM)
#error "NODUS_SEND_TEST_FIXED_RANDOM fixes every random byte (signatures, output seeds, session nonces); it must never be compiled into the shipped module (NODUS_SEND_RELEASE)"
#endif
#if defined(NODUS_SEND_RELEASE) && defined(NODUS_SEND_OFFLINE_ONLY)
#error "NODUS_SEND_OFFLINE_ONLY is the native vector build, not the shipped module"
#endif
#if defined(NODUS_SEND_OFFLINE_ONLY) && !defined(NODUS_SEND_TEST_FIXED_RANDOM)
#error "the native vector is a TEST build: define NODUS_SEND_TEST_FIXED_RANDOM"
#endif
#if !defined(__EMSCRIPTEN__) && !defined(NODUS_SEND_OFFLINE_ONLY)
#error "the networked module is built with emcc only; the native build is NODUS_SEND_OFFLINE_ONLY"
#endif
#if defined(__EMSCRIPTEN__) && defined(NODUS_SEND_OFFLINE_ONLY)
#error "NODUS_SEND_OFFLINE_ONLY is the native vector build"
#endif
#if !defined(NODUS_SEND_RELEASE) && !defined(NODUS_SEND_TEST_FIXED_RANDOM)
#error "choose a build: NODUS_SEND_RELEASE (shipped) or NODUS_SEND_TEST_FIXED_RANDOM (parity)"
#endif

/* No header of its own: the browser reaches the nsw_* entry points through
 * the build script's EXPORTED_FUNCTIONS list, and the native vector
 * (nodus-send-native-vector.c) declares the few it calls. */

#include "nodus/nodus_v2_spend.h"
#include "nodus/nodus_types.h"              /* NODUS_CMT_APP_MAX_EXPIRY_AHEAD,
                                             * NODUS_W_BASE_TX_FEE           */
#include "dnac/dnac.h"                      /* DNAC_MIN_FEE_RAW              */
#include "crypto/hash/qgp_sha3.h"
#include "crypto/sign/qgp_dilithium.h"
#include "crypto/utils/qgp_fingerprint.h"
#include "crypto/utils/qgp_log.h"

#ifndef NODUS_SEND_OFFLINE_ONLY
#include "nodus/nodus.h"
#include "crypto/nodus_identity.h"
#include "crypto/nodus_sign.h"
#endif

#ifdef __EMSCRIPTEN__
#include <emscripten.h>
#include <unistd.h>                         /* getentropy                    */
#endif

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LOG_TAG "NODUS_SEND"

/* nodus/tools/nodus-cli.c CLI_ENV_EXPIRY_AHEAD: the mempool lifetime cap
 * (NODUS_CMT_APP_MAX_EXPIRY_AHEAD = 100, nodus_types.h) minus the 10-block
 * gossip margin; note 2026-09-26 item 1 "expiry_height = tip + 90". */
#define NSW_EXPIRY_AHEAD ((uint64_t)NODUS_CMT_APP_MAX_EXPIRY_AHEAD - 10u)
/* nodus-cli cmd_v2_spend fee_floor. */
#define NSW_FEE_FLOOR (DNAC_MIN_FEE_RAW > NODUS_W_BASE_TX_FEE ? \
                       DNAC_MIN_FEE_RAW : NODUS_W_BASE_TX_FEE)
/* One dnac_utxo answer carries at most this many coins. */
#define NSW_MAX_COINS  NODUS_DNAC_MAX_UTXO_RESULTS
/* Output seeds an offline build may be given: one per output. */
#define NSW_OUT_SEEDS_MAX (32u * NODUS_V2_SPEND_MAX_OUTS)
#define NSW_PK_LEN   QGP_DSA87_PUBLICKEYBYTES
#define NSW_SK_LEN   QGP_DSA87_SECRETKEYBYTES
#define NSW_U64_DEC  21                     /* 20 digits + NUL               */

/* ── memory hygiene ─────────────────────────────────────────────────── */

static void nsw_wipe(void *p, size_t n) {
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (n--) *v++ = 0;
}

/* The shared sources call qgp_secure_memzero (hkdf_sha3.c, qgp_mlkem.c,
 * nodus_identity.c, nodus_client.c); its definition lives in
 * qgp_platform_<os>.c, which this module does not link. */
void qgp_secure_memzero(void *ptr, size_t len) {
    if (ptr) nsw_wipe(ptr, len);
}

/* ── randomness (see the header comment) ────────────────────────────── */

#ifdef NODUS_SEND_TEST_FIXED_RANDOM
/* TEST: the bytes the next draws return, in order. Enough for one build:
 * 3 output seeds (96) + one hedged rnd (32), with room to spare. */
#define NSW_TEST_RANDOM_MAX 4096u
static uint8_t g_test_random[NSW_TEST_RANDOM_MAX];
static size_t  g_test_random_len, g_test_random_pos;

uint8_t *nsw_test_random_buf(void) { return g_test_random; }

int nsw_test_random_load(int len) {
    if (len < 0 || (size_t)len > NSW_TEST_RANDOM_MAX) return -1;
    g_test_random_len = (size_t)len;
    g_test_random_pos = 0;
    return 0;
}

int qgp_platform_random(uint8_t *buf, size_t len) {
    if (!buf || len == 0) return -1;
    if (len > g_test_random_len - g_test_random_pos) return -1;
    memcpy(buf, g_test_random + g_test_random_pos, len);
    g_test_random_pos += len;
    return 0;
}
#else
int qgp_platform_random(uint8_t *buf, size_t len) {
    if (!buf || len == 0) return -1;
    /* getentropy() refuses more than 256 bytes per call (musl
     * src/misc/getentropy.c: len > 256 -> EIO). */
    while (len > 0) {
        size_t n = len > 256 ? 256 : len;
        if (getentropy(buf, n) != 0) return -1;
        buf += n;
        len -= n;
    }
    return 0;
}
#endif

/* ── error text ─────────────────────────────────────────────────────── */

static char g_error[256];

const char *nsw_error(void) { return g_error; }

static int nsw_fail(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(g_error, sizeof(g_error), fmt, ap);
    va_end(ap);
    QGP_LOG_WARN(LOG_TAG, "%s", g_error);
    return -1;
}

/* ── strict text codecs (amounts and heights cross as decimal strings) ─ */

/* "0" or 1..20 digits without a leading zero, within u64. */
static int nsw_parse_u64(const char *s, uint64_t *out) {
    if (!s || !out) return -1;
    size_t n = strnlen(s, NSW_U64_DEC);
    if (n == 0 || n >= NSW_U64_DEC) return -1;
    if (n > 1 && s[0] == '0') return -1;
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

static void nsw_fmt_u64(uint64_t v, char out[NSW_U64_DEC]) {
    char tmp[NSW_U64_DEC];
    int n = 0;
    do { tmp[n++] = (char)('0' + (v % 10u)); v /= 10u; } while (v);
    for (int i = 0; i < n; i++) out[i] = tmp[n - 1 - i];
    out[n] = '\0';
}

/* Exactly 2*n lowercase hex characters (the wallet's own form). */
static int nsw_parse_hex(const char *s, uint8_t *out, size_t n) {
    if (!s || strnlen(s, 2 * n + 1) != 2 * n) return -1;
    for (size_t i = 0; i < n; i++) {
        int hi = s[2 * i], lo = s[2 * i + 1];
        int h = hi >= '0' && hi <= '9' ? hi - '0' : hi >= 'a' && hi <= 'f' ? hi - 'a' + 10 : -1;
        int l = lo >= '0' && lo <= '9' ? lo - '0' : lo >= 'a' && lo <= 'f' ? lo - 'a' + 10 : -1;
        if (h < 0 || l < 0) return -1;
        out[i] = (uint8_t)(h << 4 | l);
    }
    return 0;
}

static void nsw_fmt_hex(const uint8_t *in, size_t n, char *out) {
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2 * i]     = digits[in[i] >> 4];
        out[2 * i + 1] = digits[in[i] & 15];
    }
    out[2 * n] = '\0';
}

/* ── the seed the caller hands in (unlock / offline build) ──────────── */

static uint8_t g_seed[32];

uint8_t *nsw_seed_buf(void) { return g_seed; }

/* ── the candidate coins of the next build ──────────────────────────── */

static nodus_v2_coin_t g_req_coins[NSW_MAX_COINS];
static int g_req_n;

void nsw_req_reset(void) {
    memset(g_req_coins, 0, sizeof(g_req_coins));
    g_req_n = 0;
}

/* One candidate: a native coin (kind 0) the wallet may spend. A duplicate,
 * a zero amount or a full list is refused. */
int nsw_req_add_coin(const char *nullifier_hex, const char *amount_dec) {
    if (g_req_n >= (int)NSW_MAX_COINS)
        return nsw_fail("Too many coins for one transfer request.");
    nodus_v2_coin_t c;
    memset(&c, 0, sizeof(c));
    if (nsw_parse_hex(nullifier_hex, c.nul, sizeof(c.nul)) != 0 ||
        nsw_parse_u64(amount_dec, &c.amount) != 0 || c.amount == 0)
        return nsw_fail("Invalid coin in the transfer request.");
    for (int i = 0; i < g_req_n; i++)
        if (memcmp(g_req_coins[i].nul, c.nul, sizeof(c.nul)) == 0)
            return nsw_fail("The same coin was listed twice.");
    c.kind = 0;
    g_req_coins[g_req_n++] = c;
    return 0;
}

/* ── output seeds for an OFFLINE build (explicit, never drawn) ──────── */

static uint8_t g_out_seeds[NSW_OUT_SEEDS_MAX];
static size_t  g_out_seeds_len, g_out_seeds_pos;

uint8_t *nsw_out_seed_buf(void) { return g_out_seeds; }

int nsw_out_seed_load(int len) {
    if (len < 0 || (size_t)len > NSW_OUT_SEEDS_MAX || len % 32 != 0) return -1;
    g_out_seeds_len = (size_t)len;
    g_out_seeds_pos = 0;
    return 0;
}

static int nsw_rand_explicit(void *ctx, uint8_t *buf, size_t len) {
    (void)ctx;
    if (len > g_out_seeds_len - g_out_seeds_pos) return -1;
    memcpy(buf, g_out_seeds + g_out_seeds_pos, len);
    g_out_seeds_pos += len;
    return 0;
}

#ifndef NODUS_SEND_OFFLINE_ONLY
/* Online builds: the output seeds come from the CSPRNG — the same source
 * nodus-cli's cli_rand uses (nodus_random -> qgp_platform_random). */
static int nsw_rand_csprng(void *ctx, uint8_t *buf, size_t len) {
    (void)ctx;
    return qgp_platform_random(buf, len);
}
#endif

/* ── the last envelope built, and what was read back from its bytes ─── */

typedef struct {
    uint8_t *env;
    size_t   env_len;
    uint8_t  wire_id[64];
    uint8_t  intent_id[64];
    char     intent_hex[129], wire_hex[129], chain_hex[65];
    char     recipient[129];
    char     amount[NSW_U64_DEC], fee[NSW_U64_DEC], change[NSW_U64_DEC],
             expiry[NSW_U64_DEC];
    int      n_in;
    char     in_hex[NODUS_V2_SPEND_MAX_IN][129];
} nsw_built_t;

static nsw_built_t g_built;

static void nsw_built_clear(void) {
    if (g_built.env) {
        nsw_wipe(g_built.env, g_built.env_len);
        free(g_built.env);
    }
    memset(&g_built, 0, sizeof(g_built));
}

const uint8_t *nsw_built_env(void)  { return g_built.env; }
int nsw_built_env_len(void)         { return (int)g_built.env_len; }
const char *nsw_built_intent(void)  { return g_built.intent_hex; }
const char *nsw_built_wire(void)    { return g_built.wire_hex; }
const char *nsw_built_chain(void)   { return g_built.chain_hex; }
const char *nsw_built_recipient(void) { return g_built.recipient; }
const char *nsw_built_amount(void)  { return g_built.amount; }
const char *nsw_built_fee(void)     { return g_built.fee; }
const char *nsw_built_change(void)  { return g_built.change; }
const char *nsw_built_expiry(void)  { return g_built.expiry; }
int nsw_built_n_in(void)            { return g_built.n_in; }
const char *nsw_built_in(int i) {
    return (i >= 0 && i < g_built.n_in) ? g_built.in_hex[i] : "";
}

/* ── the build: nodus-cli's request for ONE native spend ────────────── */

/* The ruleset identity, rebuilt from the generated pins and REFUSED unless
 * the SYSTEM meter policy digest equals the pinned one
 * (nodus_v2_ruleset_from_pins, nodus_v2_spend.c). */
static int nsw_ruleset(nodus_v2_ruleset_id_t *rs, dna_meter_policy_t *pol) {
    int rc = nodus_v2_ruleset_from_pins(rs, pol);
    if (rc != NODUS_V2_SPEND_OK)
        return nsw_fail("This wallet's transfer rules do not match their "
                        "pinned digest; nothing was built (rc=%d).", rc);
    return 0;
}

static const char *nsw_spend_reason(int rc) {
    switch (rc) {
    case NODUS_V2_SPEND_ERR_INSUFFICIENT:  return "Insufficient NODUS balance.";
    case NODUS_V2_SPEND_ERR_MAX_INPUTS:    return "This amount needs more than 15 coins; send less or combine coins first.";
    case NODUS_V2_SPEND_ERR_OVERFLOW:      return "Amount is out of range.";
    case NODUS_V2_SPEND_ERR_INPUT_SUM:     return "Amount is out of range.";
    case NODUS_V2_SPEND_ERR_GAS_OVERFLOW:  return "The network fee is out of range.";
    case NODUS_V2_SPEND_ERR_FEE_UNSETTLED: return "The network fee could not be settled.";
    case NODUS_V2_SPEND_ERR_EXPIRY:        return "The current Nodus block height is unknown.";
    case NODUS_V2_SPEND_ERR_RANDOM:        return "Random number generation failed.";
    default:                               return "The transfer could not be built.";
    }
}

/*
 * Plan + build + sign + read back ONE native spend from g_req_coins.
 * `pk`/`sk`: the sender's ML-DSA-87 keys. `rand`: output seeds. The
 * hedged signature draws from qgp_platform_random inside qgp_dsa87_sign.
 * On success g_built holds the envelope and the fields DECODED FROM ITS
 * BYTES (nodus_v2_spend_built_t.dec, the builder's read-back), each checked
 * here against the request: out[0] = recipient/amount/native, every other
 * output = sender/native (their sum = change), inputs from the request,
 * inputs = amount + fee + change. The chain id is not a field of the
 * envelope: it is the one the pass-2 preflight bound into wire_id and
 * intent_id (nodus_v2_env_sign_one_key) — reported as the chain the bytes
 * were signed for (self-consistent, design §1.4 / RT1 L4 F7).
 */
static int nsw_build_core(const uint8_t *pk, const uint8_t *sk,
                          const uint8_t chain32[DNA_CHAIN_ID_LEN],
                          uint64_t tip, uint64_t gas_price,
                          const uint8_t to_raw[64], uint64_t amount,
                          uint64_t expiry, nodus_v2_rand_fn rand) {
    nsw_built_clear();
    if (tip == 0)
        return nsw_fail("The current Nodus block height is unknown. Nothing "
                        "was built.");
    if (tip > UINT64_MAX - NSW_EXPIRY_AHEAD || expiry != tip + NSW_EXPIRY_AHEAD)
        return nsw_fail("The transfer's validity must end at block tip + %u.",
                        (unsigned)NSW_EXPIRY_AHEAD);
    if (amount == 0) return nsw_fail("Enter an amount above zero.");
    if (g_req_n < 1) return nsw_fail("Insufficient NODUS balance.");

    nodus_v2_ruleset_id_t rs;
    dna_meter_policy_t pol;
    if (nsw_ruleset(&rs, &pol) != 0) return -1;

    /* the planner sorts in place: plan over a copy, the request stays */
    nodus_v2_coin_t coins[NSW_MAX_COINS];
    memcpy(coins, g_req_coins, sizeof(coins[0]) * (size_t)g_req_n);

    nodus_v2_spend_plan_req_t preq;
    memset(&preq, 0, sizeof(preq));
    preq.rs         = &rs;
    preq.order      = NODUS_V2_SPEND_ORDER_LARGEST_FIRST;
    preq.is_native  = 1;
    preq.amount     = amount;
    preq.fee        = NSW_FEE_FLOOR;
    preq.fee_fixed  = 0;
    preq.gas_price  = gas_price;
    preq.count      = 1;
    nodus_v2_spend_plan_t *plans = NULL;
    long count = 0;
    uint64_t fee = 0;
    nodus_v2_spend_err_t err;
    int rc = nodus_v2_spend_plan(&preq, coins, g_req_n, &plans, &count, &fee,
                                 &err);
    if (rc != NODUS_V2_SPEND_OK || count != 1 || !plans) {
        free(plans);
        return nsw_fail("%s (plan rc=%d)", nsw_spend_reason(rc), rc);
    }

    nodus_v2_spend_build_req_t breq;
    memset(&breq, 0, sizeof(breq));
    breq.rs            = &rs;
    breq.chain32       = chain32;
    breq.tip           = tip;
    breq.expiry_height = expiry;
    breq.pk            = pk;
    breq.sk            = sk;
    breq.to_fp         = to_raw;
    breq.token         = NULL;
    breq.amount        = amount;
    breq.fee           = fee;
    breq.gas_price     = gas_price;
    breq.coins         = coins;
    breq.plan          = &plans[0];
    breq.rand          = rand;
    breq.rand_ctx      = NULL;
    breq.shard_m       = 1;
    breq.shard_i       = 0;
    nodus_v2_spend_built_t built;
    memset(&built, 0, sizeof(built));
    rc = nodus_v2_spend_build(&breq, &built, &err);
    const uint64_t native_in = plans[0].native_in;
    free(plans);
    if (rc != NODUS_V2_SPEND_OK) {
        nodus_v2_spend_built_free(&built);
        return nsw_fail("%s (build rc=%d)", nsw_spend_reason(rc), rc);
    }

    /* ── check the read-back against the request (G1) ── */
    const nodus_v2_spend_decoded_t *d = &built.dec;
    static const uint8_t zero64[64] = {0};
    char to_hex[129], own_hex[129];
    uint8_t own_raw[64];
    nsw_fmt_hex(to_raw, 64, to_hex);
    if (qgp_sha3_512(pk, NSW_PK_LEN, own_raw) != 0) {
        nodus_v2_spend_built_free(&built);
        return nsw_fail("The transfer could not be built (hash).");
    }
    nsw_fmt_hex(own_raw, 64, own_hex);
    uint64_t change = 0;
    int ok = d->n_out >= 1 && d->n_in >= 1 &&
             d->n_in <= (int)NODUS_V2_SPEND_MAX_IN &&
             memcmp(d->out_owner[0], to_hex, 128) == 0 &&
             d->out_amount[0] == amount &&
             memcmp(d->out_token[0], zero64, 64) == 0 &&
             d->expiry_height == expiry;
    for (int o = 1; ok && o < d->n_out; o++) {
        if (memcmp(d->out_owner[o], own_hex, 128) != 0 ||
            memcmp(d->out_token[o], zero64, 64) != 0 ||
            d->out_amount[o] > UINT64_MAX - change)
            ok = 0;
        else
            change += d->out_amount[o];
    }
    uint64_t in_sum = 0;
    for (int i = 0; ok && i < d->n_in; i++) {
        int found = 0;
        for (int k = 0; k < g_req_n && !found; k++)
            if (memcmp(g_req_coins[k].nul, d->in_nul[i], 64) == 0) {
                found = 1;
                if (g_req_coins[k].amount > UINT64_MAX - in_sum) ok = 0;
                else in_sum += g_req_coins[k].amount;
            }
        if (!found) ok = 0;
    }
    if (ok && (in_sum != native_in || amount > UINT64_MAX - d->fee ||
               amount + d->fee > UINT64_MAX - change ||
               amount + d->fee + change != in_sum))
        ok = 0;
    if (!ok) {
        nodus_v2_spend_built_free(&built);
        return nsw_fail("The built transfer does not match the request; "
                        "nothing was signed for sending.");
    }

    g_built.env = built.env;                 /* ownership moves here */
    g_built.env_len = built.env_len;
    built.env = NULL;
    memcpy(g_built.wire_id, built.wire_id, 64);
    memcpy(g_built.intent_id, built.intent_id, 64);
    nsw_fmt_hex(built.intent_id, 64, g_built.intent_hex);
    nsw_fmt_hex(built.wire_id, 64, g_built.wire_hex);
    nsw_fmt_hex(chain32, DNA_CHAIN_ID_LEN, g_built.chain_hex);
    memcpy(g_built.recipient, d->out_owner[0], 128);
    g_built.recipient[128] = '\0';
    nsw_fmt_u64(d->out_amount[0], g_built.amount);
    nsw_fmt_u64(d->fee, g_built.fee);
    nsw_fmt_u64(change, g_built.change);
    nsw_fmt_u64(d->expiry_height, g_built.expiry);
    g_built.n_in = d->n_in;
    for (int i = 0; i < d->n_in; i++)
        nsw_fmt_hex(d->in_nul[i], 64, g_built.in_hex[i]);
    nodus_v2_spend_built_free(&built);
    return 0;
}

/*
 * OFFLINE build — no session, every input explicit: the identity from the
 * seed in nsw_seed_buf (wiped here), the candidate coins (nsw_req_*), the
 * output seeds (nsw_out_seed_*; exactly consumed in order), the chain id,
 * tip and gas price as a node would report them. For the parity checks of
 * design §2 test plan item 2: the native vector and every wasm build run
 * this same function. The hedged signature still draws from
 * qgp_platform_random (the CSPRNG in the shipped build; the loaded bytes
 * in a TEST build), so intent_id — which excludes the authorization bytes —
 * is comparable across all builds, wire_id and the envelope bytes only
 * across TEST builds fed the same bytes.
 */
int nsw_offline_build(const char *chain_hex, const char *tip_dec,
                      const char *gas_dec, const char *to_hex,
                      const char *amount_dec, const char *expiry_dec) {
    uint8_t chain32[DNA_CHAIN_ID_LEN], to_raw[64];
    uint64_t tip = 0, gas = 0, amount = 0, expiry = 0;
    if (nsw_parse_hex(chain_hex, chain32, sizeof(chain32)) != 0 ||
        nsw_parse_u64(tip_dec, &tip) != 0 ||
        nsw_parse_u64(gas_dec, &gas) != 0 ||
        qgp_fp_hex_to_raw(to_hex, to_raw) != 0 ||
        nsw_parse_u64(amount_dec, &amount) != 0 ||
        nsw_parse_u64(expiry_dec, &expiry) != 0) {
        nsw_wipe(g_seed, sizeof(g_seed));
        return nsw_fail("Invalid offline build input.");
    }
    uint8_t *pk = malloc(NSW_PK_LEN), *sk = malloc(NSW_SK_LEN);
    int rc = -1;
    if (!pk || !sk) {
        rc = nsw_fail("Out of memory.");
    } else if (qgp_dsa87_keypair_derand(pk, sk, g_seed) != 0) {
        /* the same derivation nodus_identity_from_seed runs first
         * (nodus/src/crypto/nodus_identity.c) */
        rc = nsw_fail("Key derivation failed.");
    } else {
        rc = nsw_build_core(pk, sk, chain32, tip, gas, to_raw, amount, expiry,
                            nsw_rand_explicit);
        if (rc == 0 && g_out_seeds_pos != g_out_seeds_len) {
            nsw_built_clear();
            rc = nsw_fail("The build used %u of the %u output seed bytes given.",
                          (unsigned)g_out_seeds_pos, (unsigned)g_out_seeds_len);
        }
    }
    nsw_wipe(g_seed, sizeof(g_seed));
    if (sk) { nsw_wipe(sk, NSW_SK_LEN); free(sk); }
    free(pk);
    nsw_wipe(g_out_seeds, sizeof(g_out_seeds));
    g_out_seeds_len = g_out_seeds_pos = 0;
    return rc;
}

#ifndef NODUS_SEND_OFFLINE_ONLY
/* ═══ the networked module (browser) ════════════════════════════════════ */

/* ── network configuration (from the wallet build, src/nodus/send-module.js
 *    NODUS_SEND_NETWORK — set before unlock, never after) ── */

#define NSW_MAX_PINS 64
static struct {
    uint8_t                 chain[DNA_CHAIN_ID_LEN];
    int                     has_chain;
    nodus_server_endpoint_t servers[NODUS_CLIENT_MAX_SERVERS];
    int                     n_servers;
    nodus_key_t             pins[NSW_MAX_PINS];   /* outlives the client:
                                                   * the config keeps the
                                                   * pointer (nodus.h)   */
    int                     n_pins;
} g_net;

/* ── session state ── */
static nodus_client_t   g_client;       /* static: large, and the pending
                                         * slots must outlive any wait     */
static nodus_identity_t g_id;
static int g_client_inited;             /* nodus_client_init succeeded     */
static int g_used;                      /* unlock ran once (success or not)*/
static int g_unlocked;                  /* session open + chain checked    */
static int g_locked;                    /* lock ran: terminal              */
static volatile int g_cancel;           /* cancel ran: terminal            */
static int g_busy;                      /* an async export is running      */
static uint8_t g_checked_server_pk[NODUS_PK_BYTES];
static char g_fp_hex[129];
static char g_chain_hex[65];

/* the last coin listing (buildAndSign may only use these coins) */
static struct {
    int      valid;
    uint64_t tip;
    int      n;
    uint8_t  nul[NSW_MAX_COINS][64];
    uint64_t amount[NSW_MAX_COINS];
    char     nul_hex[NSW_MAX_COINS][129];
    char     amount_dec[NSW_MAX_COINS][NSW_U64_DEC];
    char     tip_dec[NSW_U64_DEC];
    int      truncated;
} g_list;

static char g_bal_total[NSW_U64_DEC], g_bal_spendable[NSW_U64_DEC];
static char g_scan_tip[NSW_U64_DEC], g_scan_height[NSW_U64_DEC];
static int  g_scan_found;
static uint8_t *g_req_env;               /* submit's request bytes         */
static size_t   g_req_env_len;

const char *nsw_fingerprint(void)     { return g_fp_hex; }
const char *nsw_chain_hex(void)       { return g_chain_hex; }
const char *nsw_bal_total(void)       { return g_bal_total; }
const char *nsw_bal_spendable(void)   { return g_bal_spendable; }
const char *nsw_list_tip(void)        { return g_list.tip_dec; }
int nsw_list_truncated(void)          { return g_list.truncated; }
int nsw_list_count(void)              { return g_list.valid ? g_list.n : 0; }
const char *nsw_list_nul(int i) {
    return (g_list.valid && i >= 0 && i < g_list.n) ? g_list.nul_hex[i] : "";
}
const char *nsw_list_amount(int i) {
    return (g_list.valid && i >= 0 && i < g_list.n) ? g_list.amount_dec[i] : "";
}
const char *nsw_scan_tip(void)        { return g_scan_tip; }
const char *nsw_scan_height(void)     { return g_scan_height; }
int nsw_scan_found(void)              { return g_scan_found; }

int nsw_net_reset(void) {
    if (g_used) return nsw_fail("The network is fixed once the wallet connects.");
    memset(&g_net, 0, sizeof(g_net));
    return 0;
}

int nsw_net_set_chain(const char *chain_hex) {
    if (g_used) return nsw_fail("The network is fixed once the wallet connects.");
    if (nsw_parse_hex(chain_hex, g_net.chain, sizeof(g_net.chain)) != 0)
        return nsw_fail("Invalid chain id in the network settings.");
    g_net.has_chain = 1;
    return 0;
}

/* `ip`: IPv4 dotted quad — nodus_tcp_connect resolves with inet_pton
 * (AF_INET) and Emscripten's SOCKFS opens <scheme>://<ip>:<port>/. */
int nsw_net_add_endpoint(const char *ip, int port) {
    if (g_used) return nsw_fail("The network is fixed once the wallet connects.");
    if (g_net.n_servers >= NODUS_CLIENT_MAX_SERVERS)
        return nsw_fail("Too many Nodus endpoints in the network settings.");
    if (!ip || strnlen(ip, sizeof(g_net.servers[0].ip)) >= sizeof(g_net.servers[0].ip) ||
        ip[0] == '\0' || port < 1 || port > 65535)
        return nsw_fail("Invalid Nodus endpoint in the network settings.");
    nodus_server_endpoint_t *ep = &g_net.servers[g_net.n_servers++];
    memset(ep, 0, sizeof(*ep));
    memcpy(ep->ip, ip, strlen(ip));
    ep->port = (uint16_t)port;
    return 0;
}

/* One accepted server key: SHA3-512 of the server's ML-DSA-87 public key,
 * the value nodus_client_config_t.pinned_server_fps holds (nodus.h). */
int nsw_net_add_pin(const char *fp_hex) {
    if (g_used) return nsw_fail("The network is fixed once the wallet connects.");
    if (g_net.n_pins >= NSW_MAX_PINS)
        return nsw_fail("Too many server keys in the network settings.");
    nodus_key_t k;
    if (qgp_fp_hex_to_raw(fp_hex, k.bytes) != 0)
        return nsw_fail("Invalid server key in the network settings.");
    for (int i = 0; i < g_net.n_pins; i++)
        if (memcmp(g_net.pins[i].bytes, k.bytes, NODUS_KEY_BYTES) == 0)
            return nsw_fail("A server key is listed twice in the network settings.");
    g_net.pins[g_net.n_pins++] = k;
    return 0;
}

/* ── op bracket: one async export at a time, none after lock/cancel ── */

static int nsw_begin(void) {
    if (g_locked || g_cancel) return nsw_fail("Wallet is locked.");
    if (g_busy) return nsw_fail("Another Nodus operation is still running.");
    g_busy = 1;
    g_error[0] = '\0';
    return 0;
}

static int nsw_end(int rc) {
    g_busy = 0;
    if (g_locked || g_cancel) return nsw_fail("Wallet is locked.");
    return rc;
}

/* The node's chain id must be the configured one (design §3 A3: "chain id
 * pinned in the build -> a different chain id = refusal"). Remembers which
 * server key it checked, so a reconnect to another pinned server re-checks. */
static int nsw_check_chain(void) {
    bool has = false;
    uint8_t c[DNA_CHAIN_ID_LEN];
    int rc = nodus_client_dnac_chain_id32(&g_client, &has, c);
    if (rc != 0)
        return nsw_fail("Could not read the Nodus chain id (rc=%d).", rc);
    if (!has)
        return nsw_fail("This Nodus node does not serve the expected chain.");
    if (memcmp(c, g_net.chain, sizeof(c)) != 0)
        return nsw_fail("This Nodus node is on a different chain. Nothing "
                        "was done.");
    if (!g_client.has_server_dil_pk)
        return nsw_fail("The Nodus server key is unknown.");
    memcpy(g_checked_server_pk, g_client.server_dil_pk.bytes,
           sizeof(g_checked_server_pk));
    return 0;
}

static int nsw_session_ok(void) {
    if (!g_unlocked) return nsw_fail("Nodus connection is not ready.");
    if (!nodus_client_is_ready(&g_client))
        return nsw_fail("Nodus connection is not ready. Try again shortly.");
    if (!g_client.has_server_dil_pk ||
        memcmp(g_client.server_dil_pk.bytes, g_checked_server_pk,
               sizeof(g_checked_server_pk)) != 0)
        return nsw_check_chain();          /* reconnected to another server */
    return 0;
}

/* ── unlock: identity from the seed, pinned session, chain check ── */

int nsw_unlock(void) {
    if (nsw_begin() != 0) { nsw_wipe(g_seed, sizeof(g_seed)); return -1; }
    int rc = -1;
    if (g_used) {
        nsw_wipe(g_seed, sizeof(g_seed));
        return nsw_end(nsw_fail("This Nodus connection was already used."));
    }
    g_used = 1;
    if (!g_net.has_chain || g_net.n_servers < 1 || g_net.n_pins < 1) {
        nsw_wipe(g_seed, sizeof(g_seed));
        return nsw_end(nsw_fail("Nodus network settings are missing."));
    }
    {
        nodus_v2_ruleset_id_t rs;
        dna_meter_policy_t pol;
        if (nsw_ruleset(&rs, &pol) != 0) {
            nsw_wipe(g_seed, sizeof(g_seed));
            return nsw_end(-1);
        }
    }
    rc = nodus_identity_from_seed(g_seed, &g_id);
    nsw_wipe(g_seed, sizeof(g_seed));
    if (rc != 0) return nsw_end(nsw_fail("Nodus key derivation failed."));
    qgp_fp_raw_to_hex(g_id.node_id.bytes, g_fp_hex);
    nsw_fmt_hex(g_net.chain, sizeof(g_net.chain), g_chain_hex);

    nodus_client_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    memcpy(cfg.servers, g_net.servers, sizeof(cfg.servers));
    cfg.server_count           = g_net.n_servers;
    cfg.auto_reconnect         = true;   /* tick() runs the (pinned)
                                          * reconnect, nodus_client_tick */
    cfg.pinned_server_fps      = g_net.pins;
    cfg.pinned_server_fp_count = g_net.n_pins;
    if (nodus_client_init(&g_client, &cfg, &g_id) != 0)
        return nsw_end(nsw_fail("Nodus client setup failed."));
    g_client_inited = 1;
    if (g_cancel) return nsw_end(-1);
    if (nodus_client_connect(&g_client) != 0)
        return nsw_end(nsw_fail("Could not open a verified connection to any "
                                "Nodus node."));
    if (g_cancel) return nsw_end(-1);
    if (nsw_check_chain() != 0) return nsw_end(-1);
    g_unlocked = 1;
    return nsw_end(0);
}

/* ── balance: dnac_balance, the native row only ── */

int nsw_balance(void) {
    if (nsw_begin() != 0) return -1;
    if (nsw_session_ok() != 0) return nsw_end(-1);
    nodus_dnac_balance_result_t res;
    memset(&res, 0, sizeof(res));
    int rc = nodus_client_dnac_balance(&g_client, g_fp_hex, &res);
    if (rc != 0) return nsw_end(nsw_fail("Balance unavailable (rc=%d).", rc));
    static const uint8_t zero64[64] = {0};
    uint64_t total = 0, spendable = 0;      /* an empty "tk" is a real zero
                                             * (nodus.h dnac_balance)       */
    for (size_t i = 0; i < res.count; i++)
        if (memcmp(res.tokens[i].token_id, zero64, 64) == 0) {
            total = res.tokens[i].total;
            spendable = res.tokens[i].spendable;
        }
    nodus_client_free_balance_result(&res);
    if (spendable > total) return nsw_end(nsw_fail("Balance unavailable."));
    nsw_fmt_u64(total, g_bal_total);
    nsw_fmt_u64(spendable, g_bal_spendable);
    return nsw_end(0);
}

/* ── list: dnac_utxo — the coins a build may use ──
 * Kept: native (token id zero), amount > 0, unlock_block <= tip (the
 * nodus-cli filter, cmd_v2_spend). The tip is passed through as reported,
 * 0 included (the wallet refuses 0 — note 2026-09-26 item 2). A row owned
 * by someone else, or a repeated coin, makes the whole answer invalid. */

int nsw_list(void) {
    if (nsw_begin() != 0) return -1;
    memset(&g_list, 0, sizeof(g_list));
    if (nsw_session_ok() != 0) return nsw_end(-1);
    nodus_dnac_utxo_result_t res;
    memset(&res, 0, sizeof(res));
    int rc = nodus_client_dnac_utxo(&g_client, g_fp_hex,
                                    NODUS_DNAC_MAX_UTXO_RESULTS, &res);
    if (rc != 0) {
        nodus_client_free_utxo_result(&res);
        return nsw_end(nsw_fail("Your coin list could not be read (rc=%d).", rc));
    }
    static const uint8_t zero64[64] = {0};
    int bad = res.count < 0 || res.count > (int)NODUS_DNAC_MAX_UTXO_RESULTS ||
              (res.count > 0 && !res.entries);
    const uint64_t tip = res.block_height;
    for (int i = 0; !bad && i < res.count; i++) {
        const nodus_dnac_utxo_entry_t *e = &res.entries[i];
        if (strncmp(e->owner, g_fp_hex, 128) != 0) { bad = 1; break; }
        for (int k = 0; k < g_list.n; k++)
            if (memcmp(g_list.nul[k], e->nullifier, 64) == 0) bad = 1;
        if (bad) break;
        if (e->amount == 0 || memcmp(e->token_id, zero64, 64) != 0 ||
            e->unlock_block > tip)
            continue;
        memcpy(g_list.nul[g_list.n], e->nullifier, 64);
        g_list.amount[g_list.n] = e->amount;
        nsw_fmt_hex(e->nullifier, 64, g_list.nul_hex[g_list.n]);
        nsw_fmt_u64(e->amount, g_list.amount_dec[g_list.n]);
        g_list.n++;
    }
    g_list.truncated = res.count >= (int)NODUS_DNAC_MAX_UTXO_RESULTS;
    nodus_client_free_utxo_result(&res);
    if (bad) {
        memset(&g_list, 0, sizeof(g_list));
        return nsw_end(nsw_fail("The Nodus node returned an invalid coin list."));
    }
    g_list.tip = tip;
    nsw_fmt_u64(tip, g_list.tip_dec);
    g_list.valid = 1;
    return nsw_end(0);
}

/* ── buildAndSign: the candidates must come from the LAST listing ── */

int nsw_build_and_sign(const char *to_hex, const char *amount_dec,
                       const char *expiry_dec) {
    if (nsw_begin() != 0) return -1;
    nsw_built_clear();
    uint8_t to_raw[64];
    uint64_t amount = 0, expiry = 0;
    if (qgp_fp_hex_to_raw(to_hex, to_raw) != 0)
        return nsw_end(nsw_fail("Enter a Nodus address: 128 characters, 0-9 and a-f."));
    if (nsw_parse_u64(amount_dec, &amount) != 0 || amount == 0)
        return nsw_end(nsw_fail("Enter an amount above zero."));
    if (nsw_parse_u64(expiry_dec, &expiry) != 0)
        return nsw_end(nsw_fail("Invalid validity height."));
    if (!g_list.valid || g_list.tip == 0)
        return nsw_end(nsw_fail("The current Nodus block height is unknown. "
                                "Nothing was sent; try again later."));
    for (int i = 0; i < g_req_n; i++) {
        int found = 0;
        for (int k = 0; k < g_list.n && !found; k++)
            if (memcmp(g_list.nul[k], g_req_coins[i].nul, 64) == 0 &&
                g_list.amount[k] == g_req_coins[i].amount)
                found = 1;
        if (!found)
            return nsw_end(nsw_fail("The transfer request names a coin that "
                                    "is not in your current coin list."));
    }
    if (nsw_session_ok() != 0) return nsw_end(-1);
    /* signing: re-read the chain id on this session, whatever the cache */
    if (nsw_check_chain() != 0) return nsw_end(-1);
    nodus_dnac_fee_info_t fi;
    memset(&fi, 0, sizeof(fi));
    int rc = nodus_client_dnac_fee_info(&g_client, &fi);
    if (rc != 0)                             /* a failed query is not price 0
                                              * (nodus-cli cmd_v2_spend)     */
        return nsw_end(nsw_fail("The network fee is unknown (rc=%d). Nothing "
                                "was built.", rc));
    if (g_cancel) return nsw_end(-1);
    rc = nsw_build_core(g_id.pk.bytes, g_id.sk.bytes, g_net.chain, g_list.tip,
                        fi.gas_price, to_raw, amount, expiry, nsw_rand_csprng);
    return nsw_end(rc);
}

/* ── submit: only the envelope this module built last ── */

uint8_t *nsw_req_env_alloc(int len) {
    if (g_req_env) { nsw_wipe(g_req_env, g_req_env_len); free(g_req_env); }
    g_req_env = NULL;
    g_req_env_len = 0;
    if (len <= 0 || (size_t)len > (size_t)64 * 1024 * 1024) return NULL;
    g_req_env = malloc((size_t)len);
    if (g_req_env) g_req_env_len = (size_t)len;
    return g_req_env;
}

/* 0 = accepted by the node's mempool CheckTx, 1 = refused (message in
 * nsw_error), -1 = no answer (transport / RPC fault). The submission is
 * nodus-cli's t6_submit_on: tx_hash = wire_id, signed with nodus_sign. */
int nsw_submit(void) {
    if (nsw_begin() != 0) return -1;
    int rc;
    if (!g_req_env || !g_built.env || g_req_env_len != g_built.env_len ||
        memcmp(g_req_env, g_built.env, g_built.env_len) != 0) {
        rc = nsw_fail("Only the transfer shown for review can be sent.");
    } else if (nsw_session_ok() != 0) {
        rc = -1;
    } else {
        nodus_pubkey_t spk;
        nodus_sig_t ssig;
        memcpy(spk.bytes, g_id.pk.bytes, NODUS_PK_BYTES);
        if (nodus_sign(&ssig, g_built.wire_id, 64, &g_id.sk) != 0) {
            rc = nsw_fail("Signing the submission failed.");
        } else {
            nodus_dnac_spend_result_t sres;
            memset(&sres, 0, sizeof(sres));
            int src = nodus_client_dnac_spend(&g_client, g_built.wire_id,
                                              g_built.env,
                                              (uint32_t)g_built.env_len,
                                              &spk, &ssig, 0, &sres);
            if (src != 0)
                rc = nsw_fail("The Nodus node did not answer the submission "
                              "(rc=%d).", src);
            else if (sres.status != NODUS_DNAC_APPROVED) {
                nsw_fail("The Nodus network refused this transfer "
                         "(status %d).", (int)sres.status);
                rc = 1;
            } else
                rc = 0;
        }
    }
    if (g_req_env) { nsw_wipe(g_req_env, g_req_env_len); free(g_req_env); }
    g_req_env = NULL;
    g_req_env_len = 0;
    return nsw_end(rc);
}

/* ── scanConfirm: dnac_v3_block, fromHeight .. min(tip, toHeight) ──
 * Committed blocks are final (one block per height, no reorg in the
 * cometbft port), so a height read once without the intent never needs
 * reading again: a small memo keeps, per intent, the first height not yet
 * read in this session. A NOT_FOUND (or any error) at a height <= the tip
 * the node reported is a partial read -> the call fails; "not found" is
 * only ever the answer to a complete read. */

#define NSW_SCAN_MEMO 8
static struct { uint8_t intent[64]; uint64_t next; int used; } g_memo[NSW_SCAN_MEMO];
static int g_memo_rr;

static uint64_t *nsw_memo_slot(const uint8_t intent[64]) {
    for (int i = 0; i < NSW_SCAN_MEMO; i++)
        if (g_memo[i].used && memcmp(g_memo[i].intent, intent, 64) == 0)
            return &g_memo[i].next;
    int i = g_memo_rr;
    g_memo_rr = (g_memo_rr + 1) % NSW_SCAN_MEMO;
    memcpy(g_memo[i].intent, intent, 64);
    g_memo[i].next = 0;
    g_memo[i].used = 1;
    return &g_memo[i].next;
}

int nsw_scan(const char *intent_hex, const char *from_dec, const char *to_dec) {
    if (nsw_begin() != 0) return -1;
    g_scan_found = 0;
    g_scan_tip[0] = g_scan_height[0] = '\0';
    uint8_t intent[64];
    uint64_t from = 0, to = 0;
    if (nsw_parse_hex(intent_hex, intent, sizeof(intent)) != 0 ||
        nsw_parse_u64(from_dec, &from) != 0 ||
        nsw_parse_u64(to_dec, &to) != 0 || from == 0 || to < from ||
        to - from > (uint64_t)NODUS_CMT_APP_MAX_EXPIRY_AHEAD)
        return nsw_end(nsw_fail("Invalid transfer status request."));
    if (nsw_session_ok() != 0) return nsw_end(-1);
    bool has_tip = false;
    uint64_t tip = 0;
    int rc = nodus_client_dnac_supply_tip(&g_client, &has_tip, &tip);
    if (rc != 0 || !has_tip)
        return nsw_end(nsw_fail("The current Nodus block height is unknown "
                                "(rc=%d).", rc));
    uint64_t *next = nsw_memo_slot(intent);
    uint64_t h = *next > from ? *next : from;
    const uint64_t last = tip < to ? tip : to;
    for (; h <= last; h++) {
        uint32_t idx = 0;
        int found = 0;
        for (;;) {
            if (g_cancel) return nsw_end(-1);
            nodus_dnac_v3_block_result_t page;
            memset(&page, 0, sizeof(page));
            rc = nodus_client_dnac_v3_block(&g_client, h, idx, 0, &page);
            if (rc != 0)
                return nsw_end(nsw_fail("Block %llu could not be read "
                                        "(rc=%d).", (unsigned long long)h, rc));
            int bad = page.height != h;
            for (size_t i = 0; !bad && i < page.count; i++) {
                const nodus_dnac_v3_item_t *it = &page.items[i];
                if (it->kind == NODUS_DNAC_V3_KIND_ENVELOPE &&
                    it->has_intent_id && it->code == 0 &&
                    memcmp(it->intent_id, intent, 64) == 0)
                    found = 1;
            }
            int more = !bad && !found && page.has_next;
            uint32_t nidx = page.next_index;
            nodus_client_free_v3_block_result(&page);
            if (bad)
                return nsw_end(nsw_fail("Block %llu: the node answered "
                                        "another height.", (unsigned long long)h));
            if (!more) break;
            if (nidx <= idx)
                return nsw_end(nsw_fail("Block %llu: the node's paging does "
                                        "not advance.", (unsigned long long)h));
            idx = nidx;
        }
        if (found) {
            g_scan_found = 1;
            nsw_fmt_u64(h, g_scan_height);
            break;
        }
        *next = h + 1;                       /* read completely, not here */
    }
    nsw_fmt_u64(tip, g_scan_tip);
    return nsw_end(0);
}

/* ── tick: keepalive + the pinned reconnect (nodus_client_tick) ── */

int nsw_tick(void) {
    if (nsw_begin() != 0) return -1;
    if (!g_unlocked) return nsw_end(nsw_fail("Nodus connection is not ready."));
    nodus_client_tick(&g_client);
    nodus_client_state_t st = nodus_client_state(&g_client);
    /* RECONNECTING: the drop was seen and the next tick retries; the
     * operations refuse until READY (nsw_session_ok). */
    if (st != NODUS_CLIENT_READY && st != NODUS_CLIENT_RECONNECTING)
        return nsw_end(nsw_fail("Nodus connection lost."));
    return nsw_end(0);
}

/* ── cancel / lock: synchronous, never reach emscripten_sleep ── */

void nsw_cancel(void) {
    g_cancel = 1;
}

/* Close the session and wipe every secret this file holds. With an async
 * export suspended mid-wait (g_busy), nothing it may still hold is freed:
 * nodus_client_force_disconnect only closes the socket (SOCKFS closes the
 * WebSocket) and clears client->conn, which ends its wait loop on the next
 * wake-up (wait_response / do_connect_one). The JS side then zeroes the
 * whole linear memory and aborts the instance, so no wake-up resumes. */
void nsw_lock(void) {
    g_cancel = 1;
    g_locked = 1;
    if (g_client_inited) {
        if (g_busy) {
            nodus_client_force_disconnect(&g_client);
        } else {
            nodus_client_close(&g_client);
            g_client_inited = 0;
        }
        nsw_wipe(&g_client.identity, sizeof(g_client.identity));
    }
    nsw_wipe(&g_id, sizeof(g_id));
    nsw_wipe(g_seed, sizeof(g_seed));
    nsw_built_clear();
    if (g_req_env) { nsw_wipe(g_req_env, g_req_env_len); free(g_req_env); }
    g_req_env = NULL;
    g_req_env_len = 0;
    nsw_req_reset();
    memset(&g_list, 0, sizeof(g_list));
    g_unlocked = 0;
}
#endif /* !NODUS_SEND_OFFLINE_ONLY */
