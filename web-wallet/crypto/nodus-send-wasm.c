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
 *   2026-10-02-onchain-names.md (design docs/plans/2026-10-02-onchain-names-
 *     design.md rev 4 §1.6, §2 "Queries"/"Clients") — HF-4: every envelope is
 *     built for the pinned rule-set GENERATION whose (SYSTEM, CORE) tuple
 *     EQUALS the node's dnac_ruleset_info answer (never chosen by height; no
 *     match or an older node = nothing is built); a generation-1 envelope
 *     never expires past H-1 once a RULESET_GEN2 height H is committed
 *     (nodus-cli's cli_select_runtimes / cli_env_expiry). Chain names
 *     (dnac_name_lookup / dnac_name_of) resolve from ONE node's committed
 *     state (decision item 9, accepted risk); a name's non-NODUS address is
 *     read from the owner's signature-checked profile (the Messages profile
 *     reader, connect/nc_profile.c), never from an unsigned source.
 *
 * WHAT IS HERE: small wrappers only. Every chain rule is the shared builder's
 * (nodus_v2_spend_plan / nodus_v2_spend_build), every network call is the
 * nodus client's (nodus/src/client/nodus_client.c, browser branches from
 * package (c1)). The request each wrapper fills is nodus-cli's
 * `v2-envelope spend` (nodus/tools/nodus-cli.c cmd_v2_spend) for one native
 * spend: fee floor max(DNAC_MIN_FEE_RAW, NODUS_W_BASE_TX_FEE), not fixed,
 * largest-first selection, count 1, no shard, expiry tip + 90 (capped at
 * H-1 for a generation-1 envelope once a rule-set switch at H is
 * committed — nsw_expiry_for).
 * The GENESIS CLAIM (nsw_claim_*, 0.1.26) is nodus-cli's `v2-claim`
 * (cmd_v2_claim) for this wallet's one allocation, over the shared claim
 * codec shared/dnac/manifest_wire.c — see the section of that name.
 * STAKING (nsw_stake_*, nsw_validators, nsw_delegations, 0.1.29) is
 * nodus-cli's `v2-envelope stake | delegate | undelegate` over the shared
 * builder nodus/src/client/nodus_v2_stake.c — see "STAKING".
 * VAULTS (nsw_msig_*) are nodus-cli's `msig address`, `v2-envelope spend
 * --msig`, `msig sign` and `msig combine` over the shared library
 * nodus/src/client/nodus_v2_msig.c — see "VAULTS".
 * MESSAGES (nc_*, package NC-4b of docs/plans/2026-09-24-web-connect-design
 * .md rev 5 §1.1): the Nodus Connect thin core (web-wallet/connect/, its
 * JSON exports in connect/nc_wasm.c) is linked into this module and runs on
 * this file's session, op bracket and cancel flag — see "Messages host".
 * The offline (native vector) build has none of it.
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
#include "client/nodus_v2_stake.h"         /* the shared staking builder    */
#include "client/nodus_v2_name.h"          /* the shared name registration
                                             * builder (networked builds
                                             * only — see "CHAIN NAME
                                             * REGISTRATION")                */
#include "client/nodus_v2_msig.h"          /* the shared multisig library
                                             * (networked builds only — see
                                             * "VAULTS")                     */
#include "witness/nodus_witness_runtime.h"  /* NODUS_RT_GEN_2 — header
                                             * constants only, no witness
                                             * link (as nodus_v2_stake.c)    */
#include "nodus/nodus_types.h"             /* NODUS_CMT_APP_MAX_EXPIRY_AHEAD,
                                             * NODUS_W_BASE_TX_FEE,
                                             * NODUS_MAX_DELEGATORS_PER_VALIDATOR */
#include "dnac/dnac.h"                      /* DNAC_MIN_FEE_RAW              */
#include "dnac/manifest_wire.h"             /* genesis claim codec           */
#include "dnac/evm_call_wire.h"             /* EVM leg + EVMFUND call bytes  */
#include "client/nodus_v2_evm.h"           /* the shared EVM builder
                                             * (networked builds only — see
                                             * "SMART CONTRACTS")            */
#include "witness/nodus_witness_rt_evm.h"   /* NODUS_RT_EVM_* — header
                                             * constants only, no witness
                                             * link                          */
#include "evm/evm.h"                        /* EVM_MAX_INITCODE_SIZE — header
                                             * constant only, no engine link */
#include "crypto/hash/qgp_sha3.h"
#include "crypto/sign/qgp_dilithium.h"
#include "crypto/utils/qgp_fingerprint.h"
#include "crypto/utils/qgp_log.h"

#ifndef NODUS_SEND_OFFLINE_ONLY
#include "nodus/nodus.h"
#include "protocol/nodus_cbor.h"           /* §18 reads: args + reply JSON  */
#include "crypto/nodus_identity.h"
#include "crypto/nodus_sign.h"
#include "nc_core.h"                        /* Messages host (NC-4b)         */
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
    /* 0 = a SPEND (nsw_build_core); else the staking op (DNA_SYSRULE_*:
     * 1 STAKE, 2 DELEGATE, 4 UNDELEGATE — nsw_stake_core). For a staking
     * envelope `recipient` is the validator's fingerprint (DELEGATE /
     * UNDELEGATE) or this wallet's own (STAKE), `amount` the bond / the
     * delegated / withdrawn amount. */
    int      op;
    char     commission[NSW_U64_DEC];       /* STAKE only, basis points     */
    /* A chain-name registration (nsw_name_core): the name ("" for every
     * other envelope) and its price; `recipient` is this wallet's own
     * address (the owner), `amount` the price. */
    char     name[DNAC_NAME_MAX_LEN + 1];
    char     price[NSW_U64_DEC];
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
int nsw_built_op(void)              { return g_built.op; }
const char *nsw_built_commission(void) { return g_built.commission; }
const char *nsw_built_name(void)    { return g_built.name; }
const char *nsw_built_price(void)   { return g_built.price; }
const char *nsw_built_in(int i) {
    return (i >= 0 && i < g_built.n_in) ? g_built.in_hex[i] : "";
}

/* ── the build: nodus-cli's request for ONE native spend ────────────── */

/* HF-4 — the rule-set generation an envelope is built for, and the facts
 * its expiry is judged against (design rev 4 §1.6): `gen` the pinned
 * generation whose (SYSTEM, CORE) tuple equals the node's
 * dnac_ruleset_info answer, `h` that answer's "H" (the earliest committed
 * RULESET_GEN2 effective height, 0 = no vote), `ri_tip` that answer's own
 * tip. The OFFLINE builds (parity, no session) use NSW_GEN_OFFLINE:
 * generation 1, no vote — the envelope they always built. */
typedef struct {
    uint32_t gen;
    uint64_t h;
    uint64_t ri_tip;
} nsw_gen_t;

static const nsw_gen_t NSW_GEN_OFFLINE = { 1u, 0u, 0u };

/* The ruleset identity of generation `gen`, rebuilt from the generated pins
 * and REFUSED unless that generation's SYSTEM meter policy digest equals
 * the pinned one (nodus_v2_ruleset_from_pins_gen, nodus_v2_spend.c). */
static int nsw_ruleset(uint32_t gen, nodus_v2_ruleset_id_t *rs,
                       dna_meter_policy_t *pol) {
    int rc = nodus_v2_ruleset_from_pins_gen(gen, rs, pol);
    if (rc != NODUS_V2_SPEND_OK)
        return nsw_fail("This wallet's transfer rules do not match their "
                        "pinned digest; nothing was built (rc=%d).", rc);
    return 0;
}

/* The ONE expiry rule (nodus-cli cli_env_expiry): tip + NSW_EXPIRY_AHEAD,
 * and — for an envelope of rule-set generation 1 while a RULESET_GEN2
 * height H is committed — never past H-1: a generation-1 envelope must not
 * outlive the last generation-1 block. Validity is judged against the MORE
 * CONSERVATIVE tip: the larger of `tip` (the coin listing's) and the
 * ruleset answer's; if H-1 is not above it, no generation-1 expiry is valid
 * and nothing is built ("try again after H"). `tip` 0 (the node's read-error
 * answer) refuses. @return 0 (*out set) / -1 (reason in nsw_error). */
static int nsw_expiry_for(uint64_t tip, const nsw_gen_t *g, uint64_t *out) {
    if (tip == 0)
        return nsw_fail("The current Nodus block height is unknown. Nothing "
                        "was built.");
    if (tip > UINT64_MAX - NSW_EXPIRY_AHEAD)
        return nsw_fail("The current Nodus block height is out of range.");
    uint64_t e = tip + NSW_EXPIRY_AHEAD;
    const uint64_t hi = tip > g->ri_tip ? tip : g->ri_tip;
    if (g->gen == 1u && g->h != 0) {
        if (g->h - 1u <= hi)
            return nsw_fail("The Nodus network switches to new transaction "
                            "rules at block %llu, and a transaction built "
                            "now could not be included before it. Nothing "
                            "was built; try again after block %llu.",
                            (unsigned long long)g->h,
                            (unsigned long long)g->h);
        if (e > g->h - 1u) e = g->h - 1u;
    }
    *out = e;
    return 0;
}

/* `expiry` (the wallet's request) must be exactly the rule's value.
 * @return 0 / -1 (reason in nsw_error). */
static int nsw_expiry_check(uint64_t tip, const nsw_gen_t *g,
                            uint64_t expiry) {
    uint64_t want = 0;
    if (nsw_expiry_for(tip, g, &want) != 0) return -1;
    if (expiry != want)
        return nsw_fail("The transaction's validity must end at block %llu "
                        "under the network's current rules. Nothing was "
                        "built; prepare it again.",
                        (unsigned long long)want);
    return 0;
}

/* The pinned generation whose (SYSTEM, CORE) tuple EQUALS the given one —
 * all four fields — or 0 for none (nodus-cli cli_select_runtimes' loop over
 * the pins header, nodus_v2_pins_tuples). */
static uint32_t nsw_gen_match(uint32_t sys_version, const uint8_t sys_hash[64],
                              uint32_t core_version,
                              const uint8_t core_hash[64]) {
    for (uint32_t gen = 1; gen <= nodus_v2_pins_generation_count(); gen++) {
        uint32_t sv = 0, cv = 0;
        uint8_t sh[64], ch[64];
        if (nodus_v2_pins_tuples(gen, &sv, sh, &cv, ch) != NODUS_V2_SPEND_OK)
            continue;
        if (sv == sys_version && memcmp(sh, sys_hash, 64) == 0 &&
            cv == core_version && memcmp(ch, core_hash, 64) == 0)
            return gen;
    }
    return 0;
}

#ifdef NODUS_SEND_TEST_FIXED_RANDOM
/* TEST-only (parity build, never shipped — build-nodus-send-wasm.sh
 * exports_test): one pinned generation's tuple as
 * "<sys version>:<sys hash hex>:<core version>:<core hash hex>" ("" for an
 * unknown generation), and nsw_gen_match on such a text — so the
 * generation choice is pinned without a node. */
static char g_test_tuple[2 * NSW_U64_DEC + 2 * 128 + 4];

const char *nsw_test_pins_tuple(int gen) {
    uint32_t sv = 0, cv = 0;
    uint8_t sh[64], ch[64];
    char svd[NSW_U64_DEC], cvd[NSW_U64_DEC], shx[129], chx[129];
    g_test_tuple[0] = '\0';
    if (gen < 1 || nodus_v2_pins_tuples((uint32_t)gen, &sv, sh, &cv, ch) !=
                       NODUS_V2_SPEND_OK)
        return g_test_tuple;
    nsw_fmt_u64(sv, svd);
    nsw_fmt_u64(cv, cvd);
    nsw_fmt_hex(sh, 64, shx);
    nsw_fmt_hex(ch, 64, chx);
    snprintf(g_test_tuple, sizeof(g_test_tuple), "%s:%s:%s:%s", svd, shx, cvd,
             chx);
    return g_test_tuple;
}

int nsw_test_gen_match(const char *sv_dec, const char *sh_hex,
                       const char *cv_dec, const char *ch_hex) {
    uint64_t sv = 0, cv = 0;
    uint8_t sh[64], ch[64];
    if (nsw_parse_u64(sv_dec, &sv) != 0 || sv > UINT32_MAX ||
        nsw_parse_u64(cv_dec, &cv) != 0 || cv > UINT32_MAX ||
        nsw_parse_hex(sh_hex, sh, sizeof(sh)) != 0 ||
        nsw_parse_hex(ch_hex, ch, sizeof(ch)) != 0)
        return -1;
    return (int)nsw_gen_match((uint32_t)sv, sh, (uint32_t)cv, ch);
}
#endif

/* The chain-name byte rule (dnac/include/dnac/dnac.h dnac_name_bytes_ok —
 * the one the CORE op-8 parse and the queries use) on a NUL-terminated
 * string. Synchronous, no network: the JS mirror's shared test vectors
 * are checked against it. @return 1 legal / 0 refused. */
int nsw_name_ok(const char *name) {
    if (!name) return 0;
    size_t n = strnlen(name, DNAC_NAME_MAX_LEN + 1u);
    return dnac_name_bytes_ok((const uint8_t *)name, n) ? 1 : 0;
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
 * `g`: the rule-set generation the envelope is built for and its expiry
 * facts (HF-4, nsw_gen_t); `expiry` must equal nsw_expiry_for's value.
 */
static int nsw_build_core(const uint8_t *pk, const uint8_t *sk,
                          const uint8_t chain32[DNA_CHAIN_ID_LEN],
                          uint64_t tip, uint64_t gas_price,
                          const uint8_t to_raw[64], uint64_t amount,
                          uint64_t expiry, nodus_v2_rand_fn rand,
                          const nsw_gen_t *g) {
    nsw_built_clear();
    if (nsw_expiry_check(tip, g, expiry) != 0) return -1;
    if (amount == 0) return nsw_fail("Enter an amount above zero.");
    if (g_req_n < 1) return nsw_fail("Insufficient NODUS balance.");

    nodus_v2_ruleset_id_t rs;
    dna_meter_policy_t pol;
    if (nsw_ruleset(g->gen, &rs, &pol) != 0) return -1;

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
                            nsw_rand_explicit, &NSW_GEN_OFFLINE);
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

/* ═══ STAKING (0.1.29): STAKE / DELEGATE / UNDELEGATE ═══════════════════
 *
 * nodus-cli `v2-envelope stake | delegate | undelegate` (cmd_v2_stake) in
 * the browser: the envelope is built by the SAME shared builder
 * (nodus/src/client/nodus_v2_stake.c, nodus_v2_stake_build), over the
 * ruleset tuples of the generated pins header
 * (nodus_v2_stake_ruleset_from_pins — the SYSTEM tuple pinned by the same
 * "Yol 2" mechanism as the CORE one). The request this file fills is the
 * CLI's: the listed candidate coins, the tip, the gas price read on this
 * session, expiry = nsw_expiry_for (tip + 90, capped at H-1 for a
 * generation-1 envelope before a committed rule-set switch at H), the
 * staker / delegator = this wallet's key.
 * The builder draws no randomness (its one change output is seeded from
 * the input nullifiers); only the two hedged signatures draw from
 * qgp_platform_random. What the chain decides from its state (a bonded
 * target, the 100-NODUS minimum for a new delegation, the delegator cap,
 * an undelegation not above the row) is NOT re-decided here. */

/* The chain constants the wallet shows and pre-checks with, as decimal
 * strings (dnac/include/dnac/dnac.h) — one source, never restated in JS. */
static char g_const[NSW_U64_DEC];
static const char *nsw_const(uint64_t v) { nsw_fmt_u64(v, g_const); return g_const; }
const char *nsw_const_min_delegation(void)  { return nsw_const(DNAC_MIN_DELEGATION); }
const char *nsw_const_self_stake(void)      { return nsw_const(DNAC_SELF_STAKE_AMOUNT); }
const char *nsw_const_commission_max(void)  { return nsw_const(DNAC_COMMISSION_BPS_MAX); }
const char *nsw_const_undelegate_lock_epochs(void) {
    return nsw_const((uint64_t)DNAC_UNDELEGATE_LOCK_EPOCHS);
}
const char *nsw_const_epoch_length(void)    { return nsw_const((uint64_t)DNAC_EPOCH_LENGTH); }
/* The per-validator delegator cap the chain admits a NEW delegator under
 * (nodus/include/nodus/nodus_types.h NODUS_MAX_DELEGATORS_PER_VALIDATOR;
 * enforced in nodus_witness_rt_native.c rtn_delegate_exec) — shown as the
 * "N/<cap>" delegator slots of a validator row. */
const char *nsw_const_max_delegators(void) {
    return nsw_const((uint64_t)NODUS_MAX_DELEGATORS_PER_VALIDATOR);
}

static const char *nsw_stake_reason(int rc, int op) {
    switch (rc) {
    case NODUS_V2_SPEND_ERR_INSUFFICIENT:
        return op == NODUS_V2_STAKE_OP_UNDELEGATE
            ? "Not enough spendable NODUS to pay the network fee."
            : "Insufficient NODUS balance for this amount plus the network fee (at most 15 coins are used).";
    case NODUS_V2_STAKE_ERR_BOND:        return "A validator bond must be exactly 10,000,000 NODUS.";
    case NODUS_V2_STAKE_ERR_COMMISSION:  return "The commission is above the maximum (50%).";
    case NODUS_V2_STAKE_ERR_AMOUNT:      return "Amount is out of range.";
    case NODUS_V2_STAKE_ERR_OP:          return "Unknown staking action.";
    case NODUS_V2_SPEND_ERR_OVERFLOW:
    case NODUS_V2_SPEND_ERR_INPUT_SUM:   return "Amount is out of range.";
    case NODUS_V2_SPEND_ERR_GAS_OVERFLOW: return "The network fee is out of range.";
    case NODUS_V2_SPEND_ERR_EXPIRY:      return "The current Nodus block height is unknown.";
    default:                             return "The staking transaction could not be built.";
    }
}

/*
 * Build + sign + read back ONE staking envelope from g_req_coins.
 * `validator_pk` (2592 B): the DELEGATE / UNDELEGATE target, NULL for
 * STAKE (whose unstake destination is this wallet's own address). On
 * success g_built holds the envelope and the fields DECODED FROM ITS BYTES
 * (nodus_v2_stake_built_t.dec), each checked here against the request:
 * the op, the record identity = this key, the validator key / the bond,
 * commission and destination, every input from the request, and
 * Σinputs = lock + fee + change (lock = the amount for STAKE / DELEGATE,
 * 0 for UNDELEGATE — rtn_sys_call_flow), the change to this wallet.
 * Large structs are heap: this runs after every network wait of the
 * networked caller, never across one. `g`: as for nsw_build_core.
 */
static int nsw_stake_core(const uint8_t *pk, const uint8_t *sk,
                          const uint8_t chain32[DNA_CHAIN_ID_LEN],
                          uint64_t tip, uint64_t gas_price, int op,
                          const uint8_t *validator_pk, uint64_t amount,
                          uint32_t commission, uint64_t expiry,
                          const nsw_gen_t *g) {
    nsw_built_clear();
    if (op != NODUS_V2_STAKE_OP_STAKE && op != NODUS_V2_STAKE_OP_DELEGATE &&
        op != NODUS_V2_STAKE_OP_UNDELEGATE)
        return nsw_fail("Unknown staking action.");
    if ((op == NODUS_V2_STAKE_OP_STAKE) != (validator_pk == NULL))
        return nsw_fail("Invalid staking request.");
    if (nsw_expiry_check(tip, g, expiry) != 0) return -1;
    if (g_req_n < 1) return nsw_fail("Insufficient NODUS balance.");

    /* the pinned policy digest of the generation (fail-closed, as for a
     * send) and that generation's two ruleset tuples the legs are signed
     * against */
    {
        nodus_v2_ruleset_id_t rs;
        dna_meter_policy_t pol;
        if (nsw_ruleset(g->gen, &rs, &pol) != 0) return -1;
    }
    nodus_v2_stake_ruleset_t srs;
    if (nodus_v2_stake_ruleset_from_pins_gen(g->gen, &srs) != NODUS_V2_SPEND_OK)
        return nsw_fail("This wallet's staking rules could not be loaded.");

    uint8_t own_raw[64];
    char own_hex[129];
    if (qgp_sha3_512(pk, NSW_PK_LEN, own_raw) != 0)
        return nsw_fail("The staking transaction could not be built (hash).");
    nsw_fmt_hex(own_raw, 64, own_hex);

    nodus_v2_stake_coin_t *coins = calloc((size_t)g_req_n, sizeof(*coins));
    nodus_v2_stake_built_t *built = calloc(1, sizeof(*built));
    int rc = -1;
    if (!coins || !built) { rc = nsw_fail("Out of memory."); goto done; }
    for (int i = 0; i < g_req_n; i++) {        /* native, unlocked: g_list  */
        memcpy(coins[i].nul, g_req_coins[i].nul, 64);
        coins[i].amount = g_req_coins[i].amount;
    }

    nodus_v2_stake_req_t req;
    memset(&req, 0, sizeof(req));
    req.rs             = &srs;
    req.op             = (nodus_v2_stake_op_t)op;
    req.chain32        = chain32;
    req.tip            = tip;
    req.expiry_height  = expiry;
    req.pk             = pk;
    req.sk             = sk;
    req.amount         = amount;
    req.commission_bps = commission;
    req.dest_fp        = op == NODUS_V2_STAKE_OP_STAKE ? own_raw : NULL;
    req.validator_pk   = validator_pk;
    req.gas_price      = gas_price;
    req.coins          = coins;
    req.n_coins        = g_req_n;
    nodus_v2_stake_err_t err;
    int brc = nodus_v2_stake_build(&req, built, &err);
    if (brc != NODUS_V2_SPEND_OK) {
        rc = nsw_fail("%s (build rc=%d)", nsw_stake_reason(brc, op), brc);
        goto done;
    }

    /* ── check the read-back against the request (G1) ── */
    const nodus_v2_stake_decoded_t *d = &built->dec;
    const uint64_t lock = op == NODUS_V2_STAKE_OP_UNDELEGATE ? 0 : amount;
    int ok = d->op == (uint32_t)op &&
             memcmp(d->identity_pk, pk, NSW_PK_LEN) == 0 &&
             d->amount == amount && d->expiry_height == expiry &&
             d->fee == built->fee && d->n_in >= 1 &&
             d->n_in <= (int)NODUS_V2_SPEND_MAX_IN && d->n_out <= 1;
    if (ok && op == NODUS_V2_STAKE_OP_STAKE)
        ok = d->commission_bps == commission &&
             memcmp(d->dest_fp, own_raw, 64) == 0;
    else if (ok)
        ok = memcmp(d->validator_pk, validator_pk, NSW_PK_LEN) == 0;
    uint64_t change = 0;
    if (ok && d->n_out == 1) {
        ok = memcmp(d->change_owner, own_hex, 128) == 0;
        change = d->change_amount;
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
    if (ok && (lock > UINT64_MAX - d->fee ||
               lock + d->fee > UINT64_MAX - change ||
               lock + d->fee + change != in_sum || built->change != change))
        ok = 0;
    if (!ok) {
        rc = nsw_fail("The built staking transaction does not match the "
                      "request; nothing was signed for sending.");
        goto done;
    }

    g_built.env = built->env;                /* ownership moves here */
    g_built.env_len = built->env_len;
    built->env = NULL;
    memcpy(g_built.wire_id, built->wire_id, 64);
    memcpy(g_built.intent_id, built->intent_id, 64);
    nsw_fmt_hex(built->intent_id, 64, g_built.intent_hex);
    nsw_fmt_hex(built->wire_id, 64, g_built.wire_hex);
    nsw_fmt_hex(chain32, DNA_CHAIN_ID_LEN, g_built.chain_hex);
    if (op == NODUS_V2_STAKE_OP_STAKE) {
        memcpy(g_built.recipient, own_hex, 129);
        nsw_fmt_u64(d->commission_bps, g_built.commission);
    } else {
        uint8_t vfp[64];
        if (qgp_sha3_512(d->validator_pk, NSW_PK_LEN, vfp) != 0) {
            nsw_built_clear();
            rc = nsw_fail("The staking transaction could not be built (hash).");
            goto done;
        }
        nsw_fmt_hex(vfp, 64, g_built.recipient);
    }
    nsw_fmt_u64(d->amount, g_built.amount);
    nsw_fmt_u64(d->fee, g_built.fee);
    nsw_fmt_u64(change, g_built.change);
    nsw_fmt_u64(d->expiry_height, g_built.expiry);
    g_built.n_in = d->n_in;
    for (int i = 0; i < d->n_in; i++)
        nsw_fmt_hex(d->in_nul[i], 64, g_built.in_hex[i]);
    g_built.op = op;
    rc = 0;

done:
    if (built) {
        nodus_v2_stake_built_free(built);
        free(built);
    }
    free(coins);
    return rc;
}

/* OFFLINE staking build (parity, like nsw_offline_build): the identity
 * from nsw_seed_buf (wiped here), the candidate coins (nsw_req_*), the
 * chain id, tip and gas price as a node would report them, the validator's
 * public key as 5184 lowercase hex ("" for STAKE). No output seeds: the
 * builder draws none. */
int nsw_stake_offline_build(int op, const char *chain_hex, const char *tip_dec,
                            const char *gas_dec, const char *validator_hex,
                            const char *amount_dec, const char *commission_dec,
                            const char *expiry_dec) {
    uint8_t chain32[DNA_CHAIN_ID_LEN];
    uint64_t tip = 0, gas = 0, amount = 0, commission = 0, expiry = 0;
    uint8_t *vpk = NULL, *pk = NULL, *sk = NULL;
    int rc = -1;
    const int is_stake = op == NODUS_V2_STAKE_OP_STAKE;
    if (nsw_parse_hex(chain_hex, chain32, sizeof(chain32)) != 0 ||
        nsw_parse_u64(tip_dec, &tip) != 0 ||
        nsw_parse_u64(gas_dec, &gas) != 0 ||
        nsw_parse_u64(amount_dec, &amount) != 0 ||
        nsw_parse_u64(commission_dec, &commission) != 0 ||
        commission > 0xffffu ||
        nsw_parse_u64(expiry_dec, &expiry) != 0 ||
        !validator_hex || (is_stake && validator_hex[0] != '\0')) {
        rc = nsw_fail("Invalid offline staking input.");
        goto done;
    }
    if (!is_stake) {
        vpk = malloc(NSW_PK_LEN);
        if (!vpk) { rc = nsw_fail("Out of memory."); goto done; }
        if (nsw_parse_hex(validator_hex, vpk, NSW_PK_LEN) != 0) {
            rc = nsw_fail("Invalid offline staking input.");
            goto done;
        }
    }
    pk = malloc(NSW_PK_LEN);
    sk = malloc(NSW_SK_LEN);
    if (!pk || !sk)
        rc = nsw_fail("Out of memory.");
    else if (qgp_dsa87_keypair_derand(pk, sk, g_seed) != 0)
        rc = nsw_fail("Key derivation failed.");
    else
        rc = nsw_stake_core(pk, sk, chain32, tip, gas, op, vpk, amount,
                            (uint32_t)commission, expiry, &NSW_GEN_OFFLINE);
done:
    nsw_wipe(g_seed, sizeof(g_seed));
    if (sk) { nsw_wipe(sk, NSW_SK_LEN); free(sk); }
    free(pk);
    free(vpk);
    return rc;
}

/* ═══ GENESIS CLAIM ══════════════════════════════════════════════════════
 *
 * The claim of a genesis allocation, built the way nodus-cli `v2-claim`
 * builds it (nodus/tools/nodus-cli.c cmd_v2_claim, :2529-2849) with the
 * shared codec shared/dnac/manifest_wire.{h,c}:
 *   dna_gman_hash, dna_dist_leaf_hash, leaf selection by dest_binding
 *   (:2717), dna_dist_proof_build (:2732), dna_claim_preimage + ML-DSA-87
 *   (:2742-2747), dna_claim_encode (:2754), tx hash = SHA3-512(bytes)
 *   (:2759), dna_claim_nullifier (:2763).
 *
 * WHERE THE DATA COMES FROM: no node RPC serves a manifest, a leaf list or
 * a proof, so the manifest bytes, their hash and the leaf list are part of
 * the wallet build (src/nodus/send-module.js NODUS_CLAIM_DATA — the same
 * trust root as the pinned chain id). Nothing of it is trusted here: the
 * manifest must decode strictly and re-hash to the embedded hash, and the
 * leaves must rebuild the manifest's committed snapshot root (the check
 * cmd_v2_claim makes before any proof, :2650-2670). A mismatch refuses
 * every claim operation; sending is unaffected.
 *
 * ONE LEAF PER KEY: a key bound by more than one leaf is refused (the CLI
 * loops over every match, :2716; the wallet has no per-leaf spent state to
 * choose between them — see nsw_claim_status). */

#define NSW_CLAIM_MAX_LEAVES   256u
#define NSW_CLAIM_MANIFEST_MAX 8192u        /* > the largest valid v1 manifest
                                             * (64 domains: ~4.8 KB)        */

static struct {
    int             fixed;                  /* unlock ran: data is final    */
    int             has_manifest, sealed;
    dna_gman_t      m;
    uint8_t         hash[DNA_V2_ROOT_LEN];
    size_t          n;
    dna_dist_leaf_t leaves[NSW_CLAIM_MAX_LEAVES];
    uint8_t         leaf_hash[NSW_CLAIM_MAX_LEAVES][DNA_V2_ROOT_LEN];
} g_cd;

/* Lowercase hex of 1..cap bytes, any even length. */
static int nsw_parse_hex_var(const char *s, uint8_t *out, size_t cap,
                             size_t *len_out) {
    if (!s) return -1;
    size_t n = strnlen(s, 2 * cap + 1);
    if (n == 0 || n % 2 != 0 || n > 2 * cap) return -1;
    if (nsw_parse_hex(s, out, n / 2) != 0) return -1;
    *len_out = n / 2;
    return 0;
}

int nsw_claim_reset(void) {
    if (g_cd.fixed) return nsw_fail("The claim data is fixed once the wallet connects.");
    memset(&g_cd, 0, sizeof(g_cd));
    return 0;
}

/* The embedded manifest: strict decode (exact length, full validation —
 * dna_gman_decode), a distribution section in DNA-native auth, the native
 * coin as its target (CORE domain, 64 zero bytes: the only asset the v1
 * CORE runtime accepts, manifest_wire.h:113-117), at most
 * NSW_CLAIM_MAX_LEAVES leaves, and dna_gman_hash equal to the embedded
 * hash. */
int nsw_claim_set_manifest(const char *manifest_hex, const char *hash_hex) {
    if (g_cd.fixed) return nsw_fail("The claim data is fixed once the wallet connects.");
    g_cd.has_manifest = g_cd.sealed = 0;
    g_cd.n = 0;
    static uint8_t buf[NSW_CLAIM_MANIFEST_MAX];
    static const uint8_t zero64[64] = {0};
    uint8_t want[DNA_V2_ROOT_LEN], got[DNA_V2_ROOT_LEN];
    size_t len = 0;
    if (nsw_parse_hex_var(manifest_hex, buf, sizeof(buf), &len) != 0 ||
        nsw_parse_hex(hash_hex, want, sizeof(want)) != 0)
        return nsw_fail("Invalid claim data in this wallet build.");
    if (dna_gman_decode(buf, len, &g_cd.m) != 0)
        return nsw_fail("The claim data in this wallet build does not decode.");
    if (dna_gman_hash(&g_cd.m, got) != 0 || memcmp(got, want, sizeof(got)) != 0)
        return nsw_fail("The claim data in this wallet build does not match "
                        "its pinned hash.");
    if (g_cd.m.dist_present != 1 ||
        g_cd.m.auth_mode != DNA_CLAIMAUTH_DNA_NATIVE ||
        g_cd.m.target_domain_id != DNA_DOMAIN_CORE ||
        g_cd.m.target_asset_len != 64 ||
        memcmp(g_cd.m.target_asset_ref, zero64, 64) != 0 ||
        g_cd.m.leaf_count < 1 || g_cd.m.leaf_count > NSW_CLAIM_MAX_LEAVES)
        return nsw_fail("The claim data in this wallet build is not a NODUS "
                        "allocation list this wallet can claim from.");
    memcpy(g_cd.hash, got, sizeof(g_cd.hash));
    g_cd.has_manifest = 1;
    return 0;
}

/* One allocation, as the genesis config lists it (nodus-cli.c
 * claim_derive_config_leaves :2497-2511): source id, destination binding
 * (SHA3-512 of the owner's ML-DSA-87 public key), raw amount >= 1. */
int nsw_claim_add_leaf(const char *source_id_hex, const char *dest_hex,
                       const char *amount_dec) {
    if (g_cd.fixed) return nsw_fail("The claim data is fixed once the wallet connects.");
    if (!g_cd.has_manifest || g_cd.sealed)
        return nsw_fail("Invalid claim data in this wallet build.");
    if (g_cd.n >= g_cd.m.leaf_count)
        return nsw_fail("The claim data lists more allocations than its manifest.");
    dna_dist_leaf_t L;
    memset(&L, 0, sizeof(L));
    size_t sl = 0;
    L.leaf_version = DNA_DIST_VERSION;
    if (nsw_parse_hex_var(source_id_hex, L.source_id, DNA_DIST_SRCID_MAX, &sl) != 0 ||
        nsw_parse_hex(dest_hex, L.dest_binding, sizeof(L.dest_binding)) != 0 ||
        nsw_parse_u64(amount_dec, &L.source_amount) != 0 || L.source_amount < 1)
        return nsw_fail("Invalid allocation in the claim data.");
    L.source_id_len = (uint16_t)sl;
    g_cd.leaves[g_cd.n++] = L;
    return 0;
}

static int nsw_leaf_qcmp(const void *a, const void *b) {
    return dna_dist_leaf_cmp((const dna_dist_leaf_t *)a,
                             (const dna_dist_leaf_t *)b);
}

/* Canonical order (source_id ASC, duplicates refused — nodus-cli.c
 * :2513-2521), the leaf count, the committed snapshot root (:2650-2670) and
 * the converted total (dna_dist_check_totals) must all match the manifest. */
int nsw_claim_seal(void) {
    if (g_cd.fixed) return nsw_fail("The claim data is fixed once the wallet connects.");
    if (!g_cd.has_manifest || g_cd.sealed || g_cd.n != g_cd.m.leaf_count)
        return nsw_fail("The claim data does not list every allocation of its manifest.");
    qsort(g_cd.leaves, g_cd.n, sizeof(g_cd.leaves[0]), nsw_leaf_qcmp);
    for (size_t i = 1; i < g_cd.n; i++)
        if (dna_dist_leaf_cmp(&g_cd.leaves[i - 1], &g_cd.leaves[i]) >= 0)
            return nsw_fail("The claim data lists an allocation twice.");
    uint8_t root[DNA_V2_ROOT_LEN];
    if (dna_dist_snapshot_root(g_cd.leaves, g_cd.n, root) != 0 ||
        memcmp(root, g_cd.m.snapshot_root, sizeof(root)) != 0)
        return nsw_fail("The claim data does not rebuild its manifest's "
                        "committed allocation root.");
    if (dna_dist_check_totals(g_cd.leaves, g_cd.n, g_cd.m.conv_numerator,
                              g_cd.m.conv_denominator, g_cd.m.rounding_mode,
                              g_cd.m.total_claimable) != 0)
        return nsw_fail("The claim data's amounts do not add up to its "
                        "manifest's total.");
    for (size_t i = 0; i < g_cd.n; i++)
        if (dna_dist_leaf_hash(&g_cd.leaves[i], g_cd.leaf_hash[i]) != 0)
            return nsw_fail("The claim data could not be hashed.");
    g_cd.sealed = 1;
    return 0;
}

/* The leaf bound to `binding`: 1 = found (*idx), 0 = none, -1 = refused
 * (data not sealed, or more than one leaf). */
static int nsw_claim_find(const uint8_t binding[64], size_t *idx) {
    if (!g_cd.sealed) return nsw_fail("Claiming is not available in this wallet build.");
    int matches = 0;
    for (size_t i = 0; i < g_cd.n; i++)
        if (memcmp(g_cd.leaves[i].dest_binding, binding, 64) == 0) {
            if (matches++ == 0) *idx = i;
        }
    if (matches > 1)
        return nsw_fail("This wallet holds more than one allocation; the web "
                        "wallet claims one only. Use nodus-cli v2-claim.");
    return matches;
}

/* The committed-context identity of leaf `idx` on `chain32`: its nullifier
 * (dna_claim_nullifier, as cmd_v2_claim :2763 and admission step 9), the
 * coin a claim of it creates (dna_claim_utxo_id — the id dnac_v3_block
 * reports for an applied claim, nodus_witness_handlers.c:3304-3308), and
 * the converted amount (dna_dist_converted, admission step 6). */
static int nsw_claim_ids(size_t idx, const uint8_t chain32[DNA_CHAIN_ID_LEN],
                         uint8_t nul[64], uint8_t out_id[64], uint64_t *amount) {
    if (dna_claim_nullifier(chain32, g_cd.hash, g_cd.m.target_domain_id,
                            g_cd.m.target_asset_ref, g_cd.m.target_asset_len,
                            g_cd.leaf_hash[idx], nul) != 0 ||
        dna_claim_utxo_id(nul, out_id) != 0 ||
        dna_dist_converted(g_cd.leaves[idx].source_amount,
                           g_cd.m.conv_numerator, g_cd.m.conv_denominator,
                           g_cd.m.rounding_mode, amount) != 0)
        return nsw_fail("The claim identity could not be computed.");
    return 0;
}

/* The last claim built, and what was read back from its bytes. */
static struct {
    uint8_t *bytes;
    size_t   len;
    uint8_t  tx_hash[64];
    char     tx_hex[129], nul_hex[129], out_hex[129], recipient[129],
             chain_hex[65], amount[NSW_U64_DEC], leaf[NSW_U64_DEC];
} g_cb;

static void nsw_claim_built_clear(void) {
    if (g_cb.bytes) free(g_cb.bytes);       /* public bytes: no wipe needed */
    memset(&g_cb, 0, sizeof(g_cb));
}

const uint8_t *nsw_claim_built_bytes(void)  { return g_cb.bytes; }
int nsw_claim_built_len(void)               { return (int)g_cb.len; }
const char *nsw_claim_built_id(void)        { return g_cb.tx_hex; }
const char *nsw_claim_built_nullifier(void) { return g_cb.nul_hex; }
const char *nsw_claim_built_output(void)    { return g_cb.out_hex; }
const char *nsw_claim_built_recipient(void) { return g_cb.recipient; }
const char *nsw_claim_built_chain(void)     { return g_cb.chain_hex; }
const char *nsw_claim_built_amount(void)    { return g_cb.amount; }
const char *nsw_claim_built_leaf(void)      { return g_cb.leaf; }

/*
 * Build + sign + read back the claim of this key's leaf on `chain32`
 * (cmd_v2_claim :2720-2766, one leaf). The hedged ML-DSA-87 signature
 * draws its rnd from qgp_platform_random. The read-back decodes the bytes
 * (dna_claim_decode, strict) and re-runs, locally, the admission checks
 * that need no chain state (nodus_witness_v2_claims.c claim_admit steps
 * 1, 5, 7): every field equals the request, the key hashes to the leaf's
 * destination, the proof reaches the committed root, the signature
 * verifies. Only then is anything kept for review.
 */
static int nsw_claim_core(const uint8_t *pk, const uint8_t *sk,
                          const uint8_t chain32[DNA_CHAIN_ID_LEN]) {
    nsw_claim_built_clear();
    uint8_t own[64];
    size_t idx = 0;
    if (qgp_sha3_512(pk, NSW_PK_LEN, own) != 0)
        return nsw_fail("The claim could not be built (hash).");
    int found = nsw_claim_find(own, &idx);
    if (found < 0) return -1;
    if (found == 0) return nsw_fail("This wallet has no allocation to claim.");

    uint8_t nul[64], out_id[64];
    uint64_t amount = 0;
    if (nsw_claim_ids(idx, chain32, nul, out_id, &amount) != 0) return -1;

    dna_claim_t *c = calloc(1, sizeof(*c)), *d = calloc(1, sizeof(*d));
    uint8_t *bytes = malloc(DNA_CLAIM_MAX_WIRE);
    int rc = -1;
    if (!c || !d || !bytes) { rc = nsw_fail("Out of memory."); goto done; }

    const dna_dist_leaf_t *L = &g_cd.leaves[idx];
    c->claim_version = DNA_CLAIM_VERSION;
    memcpy(c->chain_id, chain32, DNA_CHAIN_ID_LEN);
    memcpy(c->manifest_hash, g_cd.hash, 64);
    c->leaf_index    = (uint64_t)idx;
    c->source_id_len = L->source_id_len;
    memcpy(c->source_id, L->source_id, L->source_id_len);
    c->source_amount = L->source_amount;
    memcpy(c->dest_binding, L->dest_binding, 64);
    c->auth_mode     = g_cd.m.auth_mode;
    memcpy(c->pubkey, pk, DNA_CLAIM_PUBKEY_LEN);
    if (dna_dist_proof_build((const uint8_t (*)[64])g_cd.leaf_hash, g_cd.n,
                             (uint64_t)idx, c->siblings, &c->n_siblings) != 0) {
        rc = nsw_fail("The claim proof could not be built.");
        goto done;
    }
    uint8_t pre[DNA_CLAIM_PREIMAGE_MAX];
    size_t pre_len = 0, sl = 0, blen = 0;
    if (dna_claim_preimage(c, pre, &pre_len) != 0) {
        rc = nsw_fail("The claim could not be built (preimage).");
        goto done;
    }
    if (qgp_dsa87_sign(c->signature, &sl, pre, pre_len, sk) != 0 ||
        sl != DNA_CLAIM_SIG_LEN) {
        rc = nsw_fail("Signing the claim failed.");
        goto done;
    }
    if (dna_claim_encode(c, bytes, DNA_CLAIM_MAX_WIRE, &blen) != 0) {
        rc = nsw_fail("The claim could not be encoded.");
        goto done;
    }

    /* ── read back from the bytes ── */
    uint8_t pk_hash[64], lh[64], dpre[DNA_CLAIM_PREIMAGE_MAX];
    size_t dpre_len = 0;
    dna_dist_leaf_t dl;
    memset(&dl, 0, sizeof(dl));
    int ok = dna_claim_decode(bytes, blen, d) == 0 &&
             d->claim_version == DNA_CLAIM_VERSION &&
             memcmp(d->chain_id, chain32, DNA_CHAIN_ID_LEN) == 0 &&
             memcmp(d->manifest_hash, g_cd.hash, 64) == 0 &&
             d->leaf_index == (uint64_t)idx &&
             d->source_id_len == L->source_id_len &&
             memcmp(d->source_id, L->source_id, L->source_id_len) == 0 &&
             d->source_amount == L->source_amount &&
             memcmp(d->dest_binding, own, 64) == 0 &&
             d->auth_mode == g_cd.m.auth_mode &&
             memcmp(d->pubkey, pk, DNA_CLAIM_PUBKEY_LEN) == 0 &&
             qgp_sha3_512(d->pubkey, DNA_CLAIM_PUBKEY_LEN, pk_hash) == 0 &&
             memcmp(pk_hash, d->dest_binding, 64) == 0;
    if (ok) {
        dl.leaf_version  = DNA_DIST_VERSION;
        dl.source_id_len = d->source_id_len;
        memcpy(dl.source_id, d->source_id, d->source_id_len);
        dl.source_amount = d->source_amount;
        memcpy(dl.dest_binding, d->dest_binding, 64);
        ok = dna_dist_leaf_hash(&dl, lh) == 0 &&
             memcmp(lh, g_cd.leaf_hash[idx], 64) == 0 &&
             dna_dist_proof_verify(g_cd.m.snapshot_root, lh, d->leaf_index,
                                   g_cd.m.leaf_count,
                                   (const uint8_t (*)[64])d->siblings,
                                   d->n_siblings) == 0 &&
             dna_claim_preimage(d, dpre, &dpre_len) == 0 &&
             qgp_dsa87_verify(d->signature, DNA_CLAIM_SIG_LEN, dpre, dpre_len,
                              d->pubkey) == 0;
    }
    if (!ok) {
        rc = nsw_fail("The built claim does not check out; nothing was "
                      "signed for sending.");
        goto done;
    }
    if (qgp_sha3_512(bytes, blen, g_cb.tx_hash) != 0) {
        rc = nsw_fail("The claim could not be built (hash).");
        goto done;
    }
    g_cb.bytes = bytes;                      /* ownership moves here */
    g_cb.len   = blen;
    bytes = NULL;
    nsw_fmt_hex(g_cb.tx_hash, 64, g_cb.tx_hex);
    nsw_fmt_hex(nul, 64, g_cb.nul_hex);
    nsw_fmt_hex(out_id, 64, g_cb.out_hex);
    nsw_fmt_hex(d->dest_binding, 64, g_cb.recipient);
    nsw_fmt_hex(d->chain_id, DNA_CHAIN_ID_LEN, g_cb.chain_hex);
    nsw_fmt_u64(amount, g_cb.amount);
    nsw_fmt_u64(d->leaf_index, g_cb.leaf);
    rc = 0;
done:
    free(bytes);
    free(c);
    free(d);
    return rc;
}

/* OFFLINE claim build: the identity from the seed in nsw_seed_buf (wiped
 * here), the chain id as a node would report it, the claim data loaded and
 * sealed above. For parity: the native vector and every wasm build run
 * this function (the signature rnd comes from qgp_platform_random — fixed
 * bytes in a TEST build, the CSPRNG in the shipped one). */
int nsw_claim_offline_build(const char *chain_hex) {
    uint8_t chain32[DNA_CHAIN_ID_LEN];
    if (nsw_parse_hex(chain_hex, chain32, sizeof(chain32)) != 0) {
        nsw_wipe(g_seed, sizeof(g_seed));
        return nsw_fail("Invalid offline claim input.");
    }
    uint8_t *pk = malloc(NSW_PK_LEN), *sk = malloc(NSW_SK_LEN);
    int rc;
    if (!pk || !sk)
        rc = nsw_fail("Out of memory.");
    else if (qgp_dsa87_keypair_derand(pk, sk, g_seed) != 0)
        rc = nsw_fail("Key derivation failed.");
    else
        rc = nsw_claim_core(pk, sk, chain32);
    nsw_wipe(g_seed, sizeof(g_seed));
    if (sk) { nsw_wipe(sk, NSW_SK_LEN); free(sk); }
    free(pk);
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
static int g_used;                      /* identify ran once (success or not)*/
static int g_identified;                /* identity derived, nothing sent  */
static int g_refused;                   /* a node served another chain:
                                         * final, connect never runs again */
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
 * server key it checked, so a reconnect to another pinned server re-checks.
 * @return 0; -1 = the answer could not be read (a transport fault: the
 *         connect step may try again); -2 = REFUSED — the node answered
 *         and does not serve the configured chain, or its key is unknown
 *         (nsw_connect makes that final). Every caller treats both as
 *         failure (`!= 0`); the reason is in nsw_error. */
static int nsw_check_chain(void) {
    bool has = false;
    uint8_t c[DNA_CHAIN_ID_LEN];
    int rc = nodus_client_dnac_chain_id32(&g_client, &has, c);
    if (rc != 0)
        return nsw_fail("Could not read the Nodus chain id (rc=%d).", rc);
    if (!has) {
        nsw_fail("This Nodus node does not serve the expected chain.");
        return -2;
    }
    if (memcmp(c, g_net.chain, sizeof(c)) != 0) {
        nsw_fail("This Nodus node is on a different chain. Nothing was done.");
        return -2;
    }
    if (!g_client.has_server_dil_pk) {
        nsw_fail("The Nodus server key is unknown.");
        return -2;
    }
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

/* HF-4 (design rev 4 §1.6; nodus-cli cli_select_runtimes): ask the node
 * which rule-set generation governs its tip + 1 and pick the PINNED
 * generation whose (SYSTEM, CORE) tuple EQUALS the answer — never by
 * height. A failed query FAILS CLOSED: an older node answers "unknown DNAC
 * method" as NODUS_ERR_PROTOCOL_ERROR (nodus_witness_handlers.c dispatch
 * default), the same code the client returns for an answer it cannot
 * decode (hf4_query), so the message names both. No matching generation =
 * this page's build is older than the network's rules. The answer's
 * structure lives on the C stack (its address is taken), not in the
 * Asyncify unwind buffer. @return 0 (*out set) / -1 (reason in nsw_error). */
static int nsw_select_generation(nsw_gen_t *out) {
    nodus_dnac_ruleset_info_t ri;
    memset(&ri, 0, sizeof(ri));
    int rc = nodus_client_dnac_ruleset_info(&g_client, &ri);
    if (rc != 0)
        return nsw_fail("This Nodus node did not say which transaction rules "
                        "it runs (an older node, or an unreadable answer; "
                        "rc=%d). Nothing was built.", rc);
    const uint32_t gen = nsw_gen_match(ri.sys_version, ri.sys_hash,
                                       ri.core_version, ri.core_hash);
    if (gen != 0) {
        out->gen = gen;
        out->h = ri.gen2_height;
        out->ri_tip = ri.tip;
        return 0;
    }
    return nsw_fail("This page is out of date: the Nodus network runs "
                    "transaction rules this page does not know (generation "
                    "%u). Reload the page. Nothing was built.",
                    (unsigned)ri.generation);
}

/* ── unlock = IDENTIFY (local) + CONNECT (network) ──
 *
 * States (one module instance, terminal at lock/cancel):
 *   fresh        nothing derived; nsw_identify or nsw_unlock may run once.
 *   identified   g_identified: the identity is derived from the seed, its
 *                fingerprint and the chain id are readable, nothing was
 *                sent. nc_host_identity() answers (the Messages keys, the
 *                history key, kept-profile checks); nc_host_client() does
 *                not, and every network export refuses (nsw_session_ok:
 *                !g_unlocked). nsw_connect may run, again after a failure.
 *   connected    g_unlocked: the pinned session is open and the node's
 *                chain id equals the configured one (nsw_check_chain).
 *                Only here does any export send.
 *   refused      g_refused: a node answered with another chain (or no
 *                server key); nsw_connect refuses from then on. The page
 *                locks.
 * nsw_lock wipes the identity and closes the client in every state (a
 * client exists only during / after a connect attempt that got as far as
 * nodus_client_init; a failed attempt closes it again). */

/* Identity from the seed; no client, no socket. Inside the op bracket. */
static int nsw_identify_core(void) {
    if (g_used) {
        nsw_wipe(g_seed, sizeof(g_seed));
        return nsw_fail("This Nodus connection was already used.");
    }
    g_used = 1;
    g_cd.fixed = 1;                         /* the claim data is final too  */
    if (!g_net.has_chain || g_net.n_servers < 1 || g_net.n_pins < 1) {
        nsw_wipe(g_seed, sizeof(g_seed));
        return nsw_fail("Nodus network settings are missing.");
    }
    /* every pinned generation must rebuild its pinned policy digest before
     * anything connects (HF-4: the build picks one of them later) */
    for (uint32_t gen = 1; gen <= nodus_v2_pins_generation_count(); gen++) {
        nodus_v2_ruleset_id_t rs;
        dna_meter_policy_t pol;
        if (nsw_ruleset(gen, &rs, &pol) != 0) {
            nsw_wipe(g_seed, sizeof(g_seed));
            return -1;
        }
    }
    int rc = nodus_identity_from_seed(g_seed, &g_id);
    nsw_wipe(g_seed, sizeof(g_seed));
    if (rc != 0) return nsw_fail("Nodus key derivation failed.");
    qgp_fp_raw_to_hex(g_id.node_id.bytes, g_fp_hex);
    nsw_fmt_hex(g_net.chain, sizeof(g_net.chain), g_chain_hex);
    g_identified = 1;
    return 0;
}

/* A failed connect attempt leaves no client behind: the next attempt
 * starts from nodus_client_init again. Never while lock/cancel ran (lock
 * owns the client then — nsw_lock). */
static void nsw_client_drop(void) {
    if (!g_client_inited || g_locked || g_cancel) return;
    nodus_client_close(&g_client);
    nsw_wipe(&g_client.identity, sizeof(g_client.identity));
    g_client_inited = 0;
}

/* The pinned session + the chain check. Inside the op bracket, identified.
 * @return 0 connected; -1 failed, nsw_connect may try again; -2 refused
 *         (final: g_refused). */
static int nsw_connect_core(void) {
    nodus_client_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    memcpy(cfg.servers, g_net.servers, sizeof(cfg.servers));
    cfg.server_count           = g_net.n_servers;
    cfg.auto_reconnect         = true;   /* tick() runs the (pinned)
                                          * reconnect, nodus_client_tick */
    cfg.pinned_server_fps      = g_net.pins;
    cfg.pinned_server_fp_count = g_net.n_pins;
    if (nodus_client_init(&g_client, &cfg, &g_id) != 0) {
        /* init copies the identity into the client before an allocation
         * that can fail (nodus_client.c nodus_client_init); with
         * g_client_inited still 0 neither nsw_client_drop nor nsw_lock
         * would wipe that copy */
        nsw_wipe(&g_client.identity, sizeof(g_client.identity));
        return nsw_fail("Nodus client setup failed.");
    }
    g_client_inited = 1;
    if (g_cancel) return -1;
    if (nodus_client_connect(&g_client) != 0) {
        nsw_client_drop();
        return nsw_fail("Could not open a verified connection to any "
                        "Nodus node.");
    }
    if (g_cancel) return -1;
    int rc = nsw_check_chain();
    if (rc != 0) {
        if (rc == -2) g_refused = 1;
        nsw_client_drop();                  /* the reason stays in g_error */
        return rc == -2 ? -2 : -1;
    }
    g_unlocked = 1;
    return 0;
}

/* IDENTIFY, then CONNECT, in one export: the wallet's original unlock,
 * unchanged for its callers (send-module.js unlock). -1 on any failure. */
int nsw_unlock(void) {
    if (nsw_begin() != 0) { nsw_wipe(g_seed, sizeof(g_seed)); return -1; }
    if (nsw_identify_core() != 0) return nsw_end(-1);
    return nsw_end(nsw_connect_core() == 0 ? 0 : -1);
}

/* IDENTIFY only: no client is created and nothing is sent. Afterwards
 * nsw_fingerprint / nsw_chain_hex answer and the Messages exports that
 * need only the identity run (nc_wasm.c). */
int nsw_identify(void) {
    if (nsw_begin() != 0) { nsw_wipe(g_seed, sizeof(g_seed)); return -1; }
    return nsw_end(nsw_identify_core());
}

/* CONNECT after nsw_identify: 0 connected (also when already connected);
 * -1 failed, may be called again; -2 refused — a node served another chain,
 * final for this module (the page locks it). */
int nsw_connect(void) {
    if (nsw_begin() != 0) return -1;
    if (!g_identified) return nsw_end(nsw_fail("The wallet identity is not ready."));
    if (g_refused) {
        nsw_fail("This Nodus node is on a different chain. Nothing was done.");
        return nsw_end(-2);
    }
    if (g_unlocked) return nsw_end(0);
    return nsw_end(nsw_connect_core());
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
    /* HF-4: the generation is chosen from the node's answer on THIS call,
     * never from an earlier nsw_ruleset_info */
    nsw_gen_t gen;
    if (nsw_select_generation(&gen) != 0) return nsw_end(-1);
    nodus_dnac_fee_info_t fi;
    memset(&fi, 0, sizeof(fi));
    int rc = nodus_client_dnac_fee_info(&g_client, &fi);
    if (rc != 0)                             /* a failed query is not price 0
                                              * (nodus-cli cmd_v2_spend)     */
        return nsw_end(nsw_fail("The network fee is unknown (rc=%d). Nothing "
                                "was built.", rc));
    if (g_cancel) return nsw_end(-1);
    rc = nsw_build_core(g_id.pk.bytes, g_id.sk.bytes, g_net.chain, g_list.tip,
                        fi.gas_price, to_raw, amount, expiry, nsw_rand_csprng,
                        &gen);
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

/* nodus-cli's t6_submit_on (nodus-cli.c:2323-2354) for claim bytes OR
 * envelope bytes: the transaction is keyed by `tx_hash` (the envelope's
 * wire_id; SHA3-512 of a claim's bytes), which is signed with nodus_sign.
 * The server routes claim bytes to the claim lane itself, with no wire
 * flag (nodus-cli.c:2280-2284; handle_dnac_spend hands the bytes to the
 * mempool CheckTx, nodus_witness_handlers.c:2303-2373).
 * @return the client's rc (0 = an answer; `*approved` says which), or -1
 *         with nsw_error set when the submission could not be signed. */
static int nsw_dnac_spend(const uint8_t tx_hash[64], const uint8_t *bytes,
                          size_t len, int *approved) {
    nodus_pubkey_t spk;
    nodus_sig_t ssig;
    *approved = 0;
    memcpy(spk.bytes, g_id.pk.bytes, NODUS_PK_BYTES);
    if (nodus_sign(&ssig, tx_hash, 64, &g_id.sk) != 0)
        return nsw_fail("Signing the submission failed.");
    nodus_dnac_spend_result_t sres;
    memset(&sres, 0, sizeof(sres));
    int src = nodus_client_dnac_spend(&g_client, tx_hash, bytes,
                                      (uint32_t)len, &spk, &ssig, 0, &sres);
    if (src < 0)                             /* not sent: session / memory */
        return nsw_fail("The submission could not be sent to the Nodus node.");
    if (src == 0) *approved = sres.status == NODUS_DNAC_APPROVED;
    return src;
}

static void nsw_req_env_free(void) {
    if (g_req_env) { nsw_wipe(g_req_env, g_req_env_len); free(g_req_env); }
    g_req_env = NULL;
    g_req_env_len = 0;
}

/* 0 = accepted by the node's mempool CheckTx, 1 = refused (message in
 * nsw_error), -1 = no answer (transport / RPC fault). */
int nsw_submit(void) {
    if (nsw_begin() != 0) return -1;
    int rc, approved = 0;
    if (!g_req_env || !g_built.env || g_req_env_len != g_built.env_len ||
        memcmp(g_req_env, g_built.env, g_built.env_len) != 0) {
        rc = nsw_fail("Only the transfer shown for review can be sent.");
    } else if (nsw_session_ok() != 0) {
        rc = -1;
    } else {
        int src = nsw_dnac_spend(g_built.wire_id, g_built.env,
                                 g_built.env_len, &approved);
        if (src < 0)
            rc = -1;
        else if (src == NODUS_ERR_PROTOCOL_ERROR)
            /* code 7 is BOTH the server's CheckTx refusal (handle_dnac_spend
             * answers it as an error reply with this code) AND the client's
             * "the reply could not be read / carried no status"
             * (nodus_client_dnac_spend) — the client does not tell them
             * apart, so the message names both. Outcome unchanged. */
            rc = nsw_fail("The Nodus node refused this transfer, or its "
                          "answer could not be read (code %d). Check the "
                          "activity before sending again.", src);
        else if (src != 0)
            rc = nsw_fail("The Nodus node did not answer the submission "
                          "(rc=%d).", src);
        else if (!approved) {
            nsw_fail("The Nodus network refused this transfer.");
            rc = 1;
        } else
            rc = 0;
    }
    nsw_req_env_free();
    return nsw_end(rc);
}

/* ── genesis claim: status, build, submit ── */

static struct {
    int  found;                              /* a leaf binds this wallet    */
    int  window;                             /* 0 open, 1 not yet, 2 closed */
    int  claimed;                            /* 0 no evidence, 1 claimed,
                                              * 2 unknown                   */
    char amount[NSW_U64_DEC], tip[NSW_U64_DEC], start[NSW_U64_DEC],
         end[NSW_U64_DEC], out_hex[129];
} g_cs;

int nsw_claim_found(void)            { return g_cs.found; }
int nsw_claim_window(void)           { return g_cs.window; }
int nsw_claim_claimed(void)          { return g_cs.claimed; }
const char *nsw_claim_amount(void)   { return g_cs.amount; }
const char *nsw_claim_tip(void)      { return g_cs.tip; }
const char *nsw_claim_start(void)    { return g_cs.start; }
const char *nsw_claim_end(void)      { return g_cs.end; }
const char *nsw_claim_output(void)   { return g_cs.out_hex; }

/* The node's committed tip, and the claim window for the next block
 * (admission step 4 reads the candidate height; nodus-cli passes tip + 1,
 * nodus-cli.c:2779/:2815): 0 open, 1 not yet open, 2 closed. */
static int nsw_claim_tip_window(uint64_t *tip, int *window) {
    bool has = false;
    int rc = nodus_client_dnac_supply_tip(&g_client, &has, tip);
    if (rc != 0 || !has || *tip == 0 || *tip == UINT64_MAX)
        return nsw_fail("The current Nodus block height is unknown (rc=%d).", rc);
    const uint64_t next = *tip + 1;
    *window = next < g_cd.m.claim_start_height ? 1
            : next > g_cd.m.claim_end_height   ? 2 : 0;
    return 0;
}

/*
 * Is there an allocation for this wallet, how much, and is it claimable?
 * "Claimed" is an INFERENCE from dnac_supply's "unclaimed" bucket (Σ
 * v2_dist_state.remaining of the native distributions,
 * nodus_witness_v2_claims.c:441-478): while this leaf is unclaimed its
 * manifest's remaining is >= the leaf's amount (a claim subtracts exactly
 * that, :785-814), so unclaimed < amount PROVES it was claimed — and only
 * the holder of this key can claim it (admission step 7). unclaimed >=
 * amount proves nothing (other leaves / manifests share the sum): "no
 * evidence", the node's admission decides. An older node without the
 * bucket keys: unknown. The dnac_nullifier RPC is NOT used: it reads the
 * legacy `nullifiers` table (nodus_witness_db.c:52-74), never
 * v2_claims_spent.
 */
int nsw_claim_status(void) {
    if (nsw_begin() != 0) return -1;
    memset(&g_cs, 0, sizeof(g_cs));
    if (nsw_session_ok() != 0) return nsw_end(-1);
    size_t idx = 0;
    /* node_id = SHA3-512(pk) (nodus_identity.c:206-207) — the address the
     * wallet shows, checked equal at unlock (src/nodus/client.js) */
    int found = nsw_claim_find(g_id.node_id.bytes, &idx);
    if (found < 0) return nsw_end(-1);
    if (found == 0) return nsw_end(0);
    uint8_t nul[64], out_id[64];
    uint64_t amount = 0, tip = 0;
    int window = 0;
    if (nsw_claim_ids(idx, g_net.chain, nul, out_id, &amount) != 0 ||
        nsw_claim_tip_window(&tip, &window) != 0)
        return nsw_end(-1);
    if (g_cancel) return nsw_end(-1);
    nodus_dnac_supply_buckets_t b;
    memset(&b, 0, sizeof(b));
    int rc = nodus_client_dnac_supply_buckets(&g_client, &b);
    if (rc != 0)
        return nsw_end(nsw_fail("The allocation state could not be read (rc=%d).", rc));
    g_cs.found   = 1;
    g_cs.window  = window;
    g_cs.claimed = !b.has ? 2 : b.unclaimed < amount ? 1 : 0;
    nsw_fmt_u64(amount, g_cs.amount);
    nsw_fmt_u64(tip, g_cs.tip);
    nsw_fmt_u64(g_cd.m.claim_start_height, g_cs.start);
    nsw_fmt_u64(g_cd.m.claim_end_height, g_cs.end);
    nsw_fmt_hex(out_id, 64, g_cs.out_hex);
    return nsw_end(0);
}

/* Build + sign the claim of this wallet's allocation for review. The chain
 * id is re-read on this session and the window re-checked first. */
int nsw_claim_build(void) {
    if (nsw_begin() != 0) return -1;
    nsw_claim_built_clear();
    if (nsw_session_ok() != 0 || nsw_check_chain() != 0) return nsw_end(-1);
    uint64_t tip = 0;
    int window = 0;
    if (nsw_claim_tip_window(&tip, &window) != 0) return nsw_end(-1);
    if (window == 1)
        return nsw_end(nsw_fail("Claiming has not opened yet (from block %llu).",
                                (unsigned long long)g_cd.m.claim_start_height));
    if (window == 2)
        return nsw_end(nsw_fail("The claim period ended at block %llu.",
                                (unsigned long long)g_cd.m.claim_end_height));
    if (g_cancel) return nsw_end(-1);
    return nsw_end(nsw_claim_core(g_id.pk.bytes, g_id.sk.bytes, g_net.chain));
}

/* 0 = accepted by the mempool CheckTx, 1 = the node answered with a
 * refusal (an error reply: handle_dnac_spend answers every CheckTx refusal
 * — an already-claimed allocation included — as an error, and
 * nodus_client_dnac_spend returns its code, nodus_client.c:2396), -1 = no
 * answer. Only the claim built last may be submitted, byte for byte. */
int nsw_claim_submit(void) {
    if (nsw_begin() != 0) return -1;
    int rc, approved = 0;
    if (!g_req_env || !g_cb.bytes || g_req_env_len != g_cb.len ||
        memcmp(g_req_env, g_cb.bytes, g_cb.len) != 0) {
        rc = nsw_fail("Only the claim shown for review can be sent.");
    } else if (nsw_session_ok() != 0) {
        rc = -1;
    } else {
        int src = nsw_dnac_spend(g_cb.tx_hash, g_cb.bytes, g_cb.len, &approved);
        if (src < 0)
            rc = -1;
        else if (src == NODUS_ERR_TIMEOUT || src > NODUS_ERR_CIRCUIT_CLOSED)
            rc = nsw_fail("The Nodus node did not answer the claim (rc=%d).", src);
        else if (src == NODUS_ERR_PROTOCOL_ERROR) {
            /* code 7 is BOTH the server's CheckTx refusal (an already-claimed
             * allocation included) AND the client's "the reply could not be
             * read / carried no status" (nodus_client_dnac_spend) — the
             * client does not tell them apart, so the message names both
             * instead of asserting a refusal. Outcome unchanged. */
            nsw_fail("The Nodus node refused this claim, or its answer could "
                     "not be read (code %d). If the allocation was claimed "
                     "before, it is already claimed: check the balance "
                     "before trying again.", src);
            rc = 1;
        } else if (src != 0) {
            nsw_fail("The Nodus node could not accept this claim (code %d).",
                     src);
            rc = 1;
        } else if (!approved) {
            nsw_fail("The Nodus network refused this claim.");
            rc = 1;
        } else
            rc = 0;
    }
    nsw_req_env_free();
    return nsw_end(rc);
}

/* ── scanConfirm: dnac_v3_block, fromHeight .. min(tip, toHeight) ──
 * `intent_hex` names what to look for: an applied envelope with that
 * intent_id, or an applied claim that created the coin with that id (a
 * claim's tracking id, nsw_claim_output). Both ids are SHA3-512 outputs
 * under different domain tags. Committed blocks are final (one block per height, no reorg in the
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
                /* an applied claim: its coin id is dna_claim_utxo_id of the
                 * claim's nullifier (nodus_witness_handlers.c:3304-3308) —
                 * the same for every signature variant, unlike its hash */
                if (it->kind == NODUS_DNAC_V3_KIND_CLAIM && it->code == 0 &&
                    it->has_effects)
                    for (uint8_t k = 0; k < it->n_created && k < NODUS_DNAC_V3_ITEM_MAX_OUT; k++)
                        if (memcmp(it->created[k].id, intent, 64) == 0)
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

/* ── staking: the validator list, this wallet's delegations, the build ──
 *
 * The validator listing is kept HERE: a DELEGATE / UNDELEGATE build names
 * its target by fingerprint and this module resolves it to the public key
 * from its own last listing, deriving every fingerprint itself
 * (SHA3-512(pubkey)) — JS never hands a 2592-byte key in, and a
 * fingerprint the node reported is never trusted as a key.
 * Page size: the server caps one answer at 256 rows
 * (nodus_witness_handlers.c DNAC_VALIDATOR_LIST_MAX_RESULTS). */

#define NSW_MAX_VALIDATORS 256
#define NSW_VAL_PAGE       256
#define NSW_MAX_DELEGATIONS NODUS_DNAC_MAX_DELEGATIONS_RESULTS

static struct {
    int      valid, n, truncated;
    uint8_t  pk[NSW_MAX_VALIDATORS][NSW_PK_LEN];
    char     fp_hex[NSW_MAX_VALIDATORS][129];
    char     self_dec[NSW_MAX_VALIDATORS][NSW_U64_DEC];
    char     deleg_dec[NSW_MAX_VALIDATORS][NSW_U64_DEC];
    int      commission[NSW_MAX_VALIDATORS];
    int      status[NSW_MAX_VALIDATORS];
    /* the reply's optional "dlg" (filled delegator slots); -1 = the node
     * predates the key (has_delegator_count 0) = unknown, never 0 */
    int      delegators[NSW_MAX_VALIDATORS];
} g_vals;

static struct {
    int      valid, n;
    char     fp_hex[NSW_MAX_DELEGATIONS][129];
    char     amount_dec[NSW_MAX_DELEGATIONS][NSW_U64_DEC];
    char     block_dec[NSW_MAX_DELEGATIONS][NSW_U64_DEC];
} g_dels;

int nsw_val_count(void)     { return g_vals.valid ? g_vals.n : 0; }
int nsw_val_truncated(void) { return g_vals.valid ? g_vals.truncated : 0; }
static int nsw_val_ok(int i) { return g_vals.valid && i >= 0 && i < g_vals.n; }
const char *nsw_val_fp(int i)        { return nsw_val_ok(i) ? g_vals.fp_hex[i] : ""; }
const char *nsw_val_self(int i)      { return nsw_val_ok(i) ? g_vals.self_dec[i] : ""; }
const char *nsw_val_delegated(int i) { return nsw_val_ok(i) ? g_vals.deleg_dec[i] : ""; }
int nsw_val_commission(int i)        { return nsw_val_ok(i) ? g_vals.commission[i] : -1; }
int nsw_val_status(int i)            { return nsw_val_ok(i) ? g_vals.status[i] : -1; }
/* -1: unknown (an older node's reply carries no count) */
int nsw_val_delegators(int i)        { return nsw_val_ok(i) ? g_vals.delegators[i] : -1; }

int nsw_del_count(void) { return g_dels.valid ? g_dels.n : 0; }
static int nsw_del_ok(int i) { return g_dels.valid && i >= 0 && i < g_dels.n; }
const char *nsw_del_fp(int i)     { return nsw_del_ok(i) ? g_dels.fp_hex[i] : ""; }
const char *nsw_del_amount(int i) { return nsw_del_ok(i) ? g_dels.amount_dec[i] : ""; }
const char *nsw_del_block(int i)  { return nsw_del_ok(i) ? g_dels.block_dec[i] : ""; }

/* Every page of dnac_validator_list (all statuses). An answer is refused
 * whole when a row has no key, a status outside 0..4
 * (dnac/validator.h dnac_validator_status_t), a commission above
 * DNAC_COMMISSION_BPS_MAX, or repeats a key; a page that returns nothing
 * before the reported total is an incomplete read (refused). More rows
 * than NSW_MAX_VALIDATORS: the first ones are kept and `truncated` set. */
int nsw_validators(void) {
    if (nsw_begin() != 0) return -1;
    g_vals.valid = 0;
    g_vals.n = 0;
    g_vals.truncated = 0;
    if (nsw_session_ok() != 0) return nsw_end(-1);
    static const uint8_t zero_pk[NSW_PK_LEN];
    int offset = 0, total = -1, pages = 0;
    for (;;) {
        if (g_cancel) return nsw_end(-1);
        nodus_dnac_validator_list_result_t page;
        memset(&page, 0, sizeof(page));
        int rc = nodus_client_dnac_validator_list(&g_client, -1, offset,
                                                  NSW_VAL_PAGE, &page);
        if (rc != 0) {
            nodus_client_free_validator_list_result(&page);
            g_vals.n = 0;
            return nsw_end(nsw_fail("The validator list could not be read (rc=%d).", rc));
        }
        int bad = page.count < 0 || page.count > NSW_VAL_PAGE ||
                  (page.count > 0 && !page.entries) || page.total < 0 ||
                  (total >= 0 && page.total != total);
        if (!bad) total = page.total;
        for (int i = 0; !bad && i < page.count; i++) {
            const nodus_dnac_validator_list_entry_t *e = &page.entries[i];
            if (memcmp(e->pubkey, zero_pk, NSW_PK_LEN) == 0 || e->status > 4 ||
                e->commission_bps > DNAC_COMMISSION_BPS_MAX ||
                (e->has_delegator_count && e->delegator_count > INT32_MAX)) { bad = 1; break; }
            if (g_vals.n >= NSW_MAX_VALIDATORS) { g_vals.truncated = 1; break; }
            uint8_t fp[64];
            char fp_hex[129];
            if (qgp_sha3_512(e->pubkey, NSW_PK_LEN, fp) != 0) { bad = 1; break; }
            nsw_fmt_hex(fp, 64, fp_hex);
            for (int k = 0; k < g_vals.n; k++)
                if (memcmp(g_vals.fp_hex[k], fp_hex, 128) == 0) bad = 1;
            if (bad) break;
            const int n = g_vals.n++;
            memcpy(g_vals.pk[n], e->pubkey, NSW_PK_LEN);
            memcpy(g_vals.fp_hex[n], fp_hex, sizeof(fp_hex));
            nsw_fmt_u64(e->self_stake, g_vals.self_dec[n]);
            nsw_fmt_u64(e->total_delegated, g_vals.deleg_dec[n]);
            g_vals.commission[n] = e->commission_bps;
            g_vals.status[n] = e->status;
            g_vals.delegators[n] = e->has_delegator_count
                                   ? (int)e->delegator_count : -1;
        }
        const int got = page.count;
        nodus_client_free_validator_list_result(&page);
        if (bad) {
            g_vals.n = 0;
            return nsw_end(nsw_fail("The Nodus node returned an invalid validator list."));
        }
        offset += got;
        if (g_vals.truncated || offset >= total) break;
        if (got == 0 || ++pages > NSW_MAX_VALIDATORS) {
            g_vals.n = 0;
            return nsw_end(nsw_fail("The validator list could not be read completely."));
        }
    }
    g_vals.valid = 1;
    return nsw_end(0);
}

/* dnac_delegations for this wallet's own key (the node checks it against
 * the session). A row whose validator fingerprint is not 128 lowercase hex,
 * a zero amount or a repeated validator makes the answer invalid. */
int nsw_delegations(void) {
    if (nsw_begin() != 0) return -1;
    g_dels.valid = 0;
    g_dels.n = 0;
    if (nsw_session_ok() != 0) return nsw_end(-1);
    nodus_dnac_delegations_result_t res;
    memset(&res, 0, sizeof(res));
    int rc = nodus_client_dnac_delegations(&g_client, g_id.pk.bytes,
                                           NODUS_PK_BYTES, NSW_MAX_DELEGATIONS,
                                           &res);
    if (rc != 0) {
        nodus_client_free_delegations_result(&res);
        return nsw_end(nsw_fail("Your delegations could not be read (rc=%d).", rc));
    }
    int bad = res.count < 0 || res.count > NSW_MAX_DELEGATIONS ||
              (res.count > 0 && !res.entries);
    uint8_t tmp[64];
    for (int i = 0; !bad && i < res.count; i++) {
        const nodus_dnac_delegation_entry_t *e = &res.entries[i];
        if (strnlen(e->validator_fp, sizeof(e->validator_fp)) != 128 ||
            nsw_parse_hex(e->validator_fp, tmp, sizeof(tmp)) != 0 ||
            e->amount == 0) { bad = 1; break; }
        for (int k = 0; k < g_dels.n; k++)
            if (memcmp(g_dels.fp_hex[k], e->validator_fp, 128) == 0) bad = 1;
        if (bad) break;
        const int n = g_dels.n++;
        memcpy(g_dels.fp_hex[n], e->validator_fp, 128);
        g_dels.fp_hex[n][128] = '\0';
        nsw_fmt_u64(e->amount, g_dels.amount_dec[n]);
        nsw_fmt_u64(e->delegated_at_block, g_dels.block_dec[n]);
    }
    nodus_client_free_delegations_result(&res);
    if (bad) {
        g_dels.n = 0;
        return nsw_end(nsw_fail("The Nodus node returned an invalid delegation list."));
    }
    g_dels.valid = 1;
    return nsw_end(0);
}

/* Build one staking envelope for review. `op`: 1 STAKE, 2 DELEGATE,
 * 4 UNDELEGATE. `validator_fp_hex`: the target, resolved to its key from
 * the last nsw_validators listing ("" for STAKE). The candidate coins must
 * come from the LAST nsw_list, and expiry must be nsw_expiry_for's value
 * for its tip — the same gates as nsw_build_and_sign, including the
 * rule-set generation chosen from the node's answer on this call. A DELEGATE target must be bonded and
 * seat-eligible in that listing (status ACTIVE 0 or ELIGIBLE 4 —
 * rtn_delegate_exec's target rule); an UNDELEGATE target may have any
 * status (rtn_undelegate_exec has no status gate). The submission is
 * nsw_submit (only the envelope built last). Locals stay small: the
 * network waits below run in THIS frame (Asyncify), the build in
 * nsw_stake_core after them. */
int nsw_stake_build(int op, const char *validator_fp_hex, const char *amount_dec,
                    const char *commission_dec, const char *expiry_dec) {
    if (nsw_begin() != 0) return -1;
    nsw_built_clear();
    uint64_t amount = 0, commission = 0, expiry = 0;
    int vi = -1;
    if (op != NODUS_V2_STAKE_OP_STAKE && op != NODUS_V2_STAKE_OP_DELEGATE &&
        op != NODUS_V2_STAKE_OP_UNDELEGATE)
        return nsw_end(nsw_fail("Unknown staking action."));
    if (nsw_parse_u64(amount_dec, &amount) != 0 || amount == 0)
        return nsw_end(nsw_fail("Enter an amount above zero."));
    if (nsw_parse_u64(commission_dec, &commission) != 0 || commission > 0xffffu)
        return nsw_end(nsw_fail("Invalid commission."));
    if (nsw_parse_u64(expiry_dec, &expiry) != 0)
        return nsw_end(nsw_fail("Invalid validity height."));
    if (!validator_fp_hex)
        return nsw_end(nsw_fail("Invalid staking request."));
    if (op == NODUS_V2_STAKE_OP_STAKE) {
        if (validator_fp_hex[0] != '\0')
            return nsw_end(nsw_fail("Invalid staking request."));
    } else {
        if (!g_vals.valid)
            return nsw_end(nsw_fail("Load the validator list first."));
        for (int i = 0; i < g_vals.n && vi < 0; i++)
            if (strnlen(validator_fp_hex, 129) == 128 &&
                memcmp(g_vals.fp_hex[i], validator_fp_hex, 128) == 0)
                vi = i;
        if (vi < 0)
            return nsw_end(nsw_fail("This validator is not in the current "
                                    "validator list."));
        if (op == NODUS_V2_STAKE_OP_DELEGATE &&
            g_vals.status[vi] != 0 && g_vals.status[vi] != 4)
            return nsw_end(nsw_fail("This validator does not accept "
                                    "delegations now."));
    }
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
            return nsw_end(nsw_fail("The request names a coin that is not in "
                                    "your current coin list."));
    }
    if (nsw_session_ok() != 0) return nsw_end(-1);
    if (nsw_check_chain() != 0) return nsw_end(-1);
    nsw_gen_t gen;                           /* HF-4, as nsw_build_and_sign */
    if (nsw_select_generation(&gen) != 0) return nsw_end(-1);
    nodus_dnac_fee_info_t fi;
    memset(&fi, 0, sizeof(fi));
    int rc = nodus_client_dnac_fee_info(&g_client, &fi);
    if (rc != 0)
        return nsw_end(nsw_fail("The network fee is unknown (rc=%d). Nothing "
                                "was built.", rc));
    if (g_cancel) return nsw_end(-1);
    /* the listing may have been replaced only by another export, and none
     * can run while this one does (nsw_begin) — vi still names the row */
    rc = nsw_stake_core(g_id.pk.bytes, g_id.sk.bytes, g_net.chain, g_list.tip,
                        fi.gas_price, op,
                        op == NODUS_V2_STAKE_OP_STAKE ? NULL : g_vals.pk[vi],
                        amount, (uint32_t)commission, expiry, &gen);
    return nsw_end(rc);
}

/* ── HF-4: rule-set generation, chain names, a name's coin address ──
 *
 * nsw_ruleset_info: the generation a build made now would use and the
 * facts its expiry is judged against (nsw_select_generation), for the
 * wallet to compute the expiry it requests (src/adapters/nodus.js
 * expiryHeightFor — the same rule as nsw_expiry_for). The builds do NOT
 * reuse this answer: each asks the node again.
 * nsw_name_lookup / nsw_name_of: dnac_name_lookup / dnac_name_of — ONE
 * node's committed state (decision 2026-10-02-onchain-names.md item 9,
 * accepted risk); the client's decoders refuse a malformed answer
 * (nodus_dnac_name_result_decode: a name outside dnac_name_bytes_ok, an
 * owner that is not 128 lowercase hex).
 * nsw_profile_address: the coin address the name's OWNER published in
 * its profile, read with the Messages profile reader (connect/nc_profile.c
 * nc_profile_read: the owner's row only, decoded, its ML-DSA-87 signature
 * verified and SHA3-512(signing key) == the owner) — never an unsigned
 * source. Only the read needs the session (nc_read_one uses the client and
 * the cancel flag, never the Messages keys), so it runs without Messages
 * being open. */

static struct {
    int  gen;
    char tip[NSW_U64_DEC], h[NSW_U64_DEC];
} g_ri;

int nsw_ri_gen(void)         { return g_ri.gen; }
const char *nsw_ri_tip(void) { return g_ri.tip; }
const char *nsw_ri_h(void)   { return g_ri.h; }

int nsw_ruleset_info(void) {
    if (nsw_begin() != 0) return -1;
    memset(&g_ri, 0, sizeof(g_ri));
    if (nsw_session_ok() != 0) return nsw_end(-1);
    nsw_gen_t gen;
    if (nsw_select_generation(&gen) != 0) return nsw_end(-1);
    g_ri.gen = (int)gen.gen;
    nsw_fmt_u64(gen.ri_tip, g_ri.tip);
    nsw_fmt_u64(gen.h, g_ri.h);
    return nsw_end(0);
}

static struct {
    int  found;
    char owner[129], name[DNAC_NAME_MAX_LEN + 1u];
    char registered[NSW_U64_DEC], committed[NSW_U64_DEC];
} g_nm;

int nsw_name_found(void)             { return g_nm.found; }
const char *nsw_name_owner(void)     { return g_nm.owner; }
const char *nsw_name_name(void)      { return g_nm.name; }
const char *nsw_name_registered(void) { return g_nm.registered; }
const char *nsw_name_committed(void) { return g_nm.committed; }

static void nsw_name_keep(const nodus_dnac_name_result_t *r) {
    g_nm.found = r->found ? 1 : 0;
    nsw_fmt_u64(r->committed_height, g_nm.committed);
    if (!r->found) return;
    memcpy(g_nm.owner, r->owner, sizeof(g_nm.owner));
    g_nm.owner[128] = '\0';
    memcpy(g_nm.name, r->name, sizeof(g_nm.name));
    g_nm.name[DNAC_NAME_MAX_LEN] = '\0';
    nsw_fmt_u64(r->registered_height, g_nm.registered);
}

/* `name`: already lower-case (the wallet maps A-Z with an ASCII-only table;
 * uppercase is refused here, as by the chain). */
int nsw_name_lookup(const char *name) {
    if (nsw_begin() != 0) return -1;
    memset(&g_nm, 0, sizeof(g_nm));
    if (!nsw_name_ok(name))
        return nsw_end(nsw_fail("Not a chain name: 3 to 36 letters a-z and "
                                "digits."));
    if (nsw_session_ok() != 0) return nsw_end(-1);
    nodus_dnac_name_result_t r;
    memset(&r, 0, sizeof(r));
    int rc = nodus_client_dnac_name_lookup(&g_client, name, &r);
    if (rc != 0)
        return nsw_end(nsw_fail("The chain name could not be looked up (an "
                                "older node, or no readable answer; rc=%d).",
                                rc));
    uint8_t tmp[64];
    if (r.found && nsw_parse_hex(r.owner, tmp, sizeof(tmp)) != 0)
        return nsw_end(nsw_fail("The Nodus node returned an invalid owner."));
    nsw_name_keep(&r);
    if (g_nm.found) memcpy(g_nm.name, name, strnlen(name, DNAC_NAME_MAX_LEN) + 1u);
    return nsw_end(0);
}

/* `owner_hex`: 128 lowercase hex. */
int nsw_name_of(const char *owner_hex) {
    if (nsw_begin() != 0) return -1;
    memset(&g_nm, 0, sizeof(g_nm));
    uint8_t tmp[64];
    if (nsw_parse_hex(owner_hex, tmp, sizeof(tmp)) != 0)
        return nsw_end(nsw_fail("Invalid Nodus address."));
    if (nsw_session_ok() != 0) return nsw_end(-1);
    nodus_dnac_name_result_t r;
    memset(&r, 0, sizeof(r));
    int rc = nodus_client_dnac_name_of(&g_client, owner_hex, &r);
    if (rc != 0)
        return nsw_end(nsw_fail("The chain name of this ID could not be read "
                                "(an older node, or no readable answer; "
                                "rc=%d).", rc));
    nsw_name_keep(&r);
    if (g_nm.found) memcpy(g_nm.owner, owner_hex, 129);
    return nsw_end(0);
}

static char g_paddr[129];

const char *nsw_profile_addr(void) { return g_paddr; }

/* The address for coin network `field` ("eth", "bsc", "sol" or "trx" — the
 * profile's wallet fields, messenger/dht/client/dna_profile.h dna_wallets_t)
 * in the signed profile of `owner_hex`. No fallback between fields: an
 * empty field is a refusal. The address text is the owner's own claim;
 * the coin's adapter checks its format before anything is built. */
int nsw_profile_address(const char *owner_hex, const char *field) {
    if (nsw_begin() != 0) return -1;
    g_paddr[0] = '\0';
    uint8_t tmp[64];
    if (nsw_parse_hex(owner_hex, tmp, sizeof(tmp)) != 0)
        return nsw_end(nsw_fail("Invalid Nodus address."));
    if (!field || (strcmp(field, "eth") != 0 && strcmp(field, "bsc") != 0 &&
                   strcmp(field, "sol") != 0 && strcmp(field, "trx") != 0))
        return nsw_end(nsw_fail("This network has no profile address field."));
    if (nsw_session_ok() != 0) return nsw_end(-1);
    nc_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.client = &g_client;
    ctx.keys = NULL;                         /* a read: no Messages key used */
    ctx.fresh = false;
    ctx.cancel = &g_cancel;
    nc_read_t raw;
    dna_unified_identity_t *id = NULL;
    nc_profile_read(&ctx, owner_hex, &raw, &id, NULL);
    int rc;
    if (raw.outcome != NC_FOUND || !id) {
        rc = nsw_fail("The profile of this name's owner could not be read, or "
                      "did not pass its signature check. Nothing was sent.");
    } else {
        const char *a = strcmp(field, "eth") == 0 ? id->wallets.eth
                      : strcmp(field, "bsc") == 0 ? id->wallets.bsc
                      : strcmp(field, "sol") == 0 ? id->wallets.sol
                      : id->wallets.trx;
        size_t n = strnlen(a, sizeof(id->wallets.eth));
        if (n == 0)
            rc = nsw_fail("The owner of this name has no address for this "
                          "network in their profile. Nothing was sent.");
        else if (n >= sizeof(g_paddr))
            rc = nsw_fail("The owner's profile address is too long.");
        else {
            memcpy(g_paddr, a, n);
            g_paddr[n] = '\0';
            rc = 0;
        }
    }
    dna_identity_free(id);
    nc_read_clear(&raw);
    return nsw_end(rc);
}

/* ═══ CHAIN NAME REGISTRATION (HF-4) ═════════════════════════════════════
 *
 * nodus-cli `name register` (cmd_name_register) in the browser: the
 * envelope is built by the SAME shared builder (nodus/src/client/
 * nodus_v2_name.c, nodus_v2_name_build) over the pinned generation whose
 * tuple equals the node's dnac_ruleset_info answer — generation 2 or later
 * only (CORE op 8 exists from generation 2; decision 2026-10-02-onchain-
 * names.md, design rev 4 §2). The request is the CLI's: the listed
 * candidate coins, the tip, the gas price read on this session, expiry =
 * nsw_expiry_for, the name (already lower-case: the wallet maps A-Z with
 * an ASCII-only table, src/nodus/names.js), the PRICE READ FROM THE NODE on
 * this call (dnac_fee_info "np" at tip + 1, nodus_client_dnac_name_prices
 * — never a compiled value, never a value JS hands in), the owner = this
 * wallet's key. Before building, the CLI's two state checks on the same
 * session: the name is not registered (dnac_name_lookup) and this ID holds
 * no name (dnac_name_of) — one node's committed state (decision item 9);
 * the chain decides both again when it runs the registration.
 *
 * NOT IN THE NATIVE VECTOR: this whole section is inside the networked
 * part (#ifndef NODUS_SEND_OFFLINE_ONLY), because the native vector's
 * build script (scripts/build-nodus-send-native-vector.sh) does not link
 * nodus_v2_name.c. The parity of a name build is TEST wasm against the
 * shipped wasm (nsw_name_offline_build, test/nodus-send-wasm.test.js) and
 * the nodus ctest test_v2_name_build against the pre-move nodus-cli bytes.
 */

static const char *nsw_name_reason(int rc) {
    switch (rc) {
    case NODUS_V2_SPEND_ERR_INSUFFICIENT:
        return "Not enough spendable NODUS for the name's price plus the network fee.";
    case NODUS_V2_SPEND_ERR_MAX_INPUTS:
        return "Paying for this name needs more than 13 of your coins. Send some NODUS to yourself to combine coins first, then try again.";
    case NODUS_V2_SPEND_ERR_OVERFLOW:
    case NODUS_V2_SPEND_ERR_INPUT_SUM:    return "Amount is out of range.";
    case NODUS_V2_SPEND_ERR_GAS_OVERFLOW: return "The network fee is out of range.";
    case NODUS_V2_SPEND_ERR_FEE_UNSETTLED: return "The network fee could not be settled.";
    case NODUS_V2_SPEND_ERR_EXPIRY:       return "The current Nodus block height is unknown.";
    case NODUS_V2_SPEND_ERR_RANDOM:       return "Random number generation failed.";
    case NODUS_V2_NAME_ERR_NAME:          return "Not a chain name: 3 to 36 letters a-z and digits.";
    case NODUS_V2_NAME_ERR_PRICE:         return "The Nodus network gave no price for this name.";
    default:                              return "The name registration could not be built.";
    }
}

/*
 * Build + sign + read back ONE registration of `name` from g_req_coins.
 * On success g_built holds the envelope and the fields DECODED FROM ITS
 * BYTES (nodus_v2_name_built_t.dec), each checked here against the
 * request: the name, the price, the owner key = this key, the expiry,
 * every input from the request, the change to this wallet, and
 * Σinputs = price + fee + change. Large structs are heap: this runs after
 * every network wait of the networked caller, never across one.
 * `g`: the generation (>= 2) and its expiry facts, as for nsw_build_core.
 */
static int nsw_name_core(const uint8_t *pk, const uint8_t *sk,
                         const uint8_t chain32[DNA_CHAIN_ID_LEN],
                         uint64_t tip, uint64_t gas_price, const char *name,
                         uint64_t price, uint64_t expiry,
                         nodus_v2_rand_fn rand, const nsw_gen_t *g) {
    nsw_built_clear();
    if (g->gen < NODUS_RT_GEN_2)
        return nsw_fail("Chain names are not open on this network yet.");
    if (!nsw_name_ok(name))
        return nsw_fail("Not a chain name: 3 to 36 letters a-z and digits.");
    if (nsw_expiry_check(tip, g, expiry) != 0) return -1;
    if (g_req_n < 1) return nsw_fail("Insufficient NODUS balance.");

    nodus_v2_ruleset_id_t rs;
    dna_meter_policy_t pol;
    if (nsw_ruleset(g->gen, &rs, &pol) != 0) return -1;

    uint8_t own_raw[64];
    char own_hex[129];
    if (qgp_sha3_512(pk, NSW_PK_LEN, own_raw) != 0)
        return nsw_fail("The name registration could not be built (hash).");
    nsw_fmt_hex(own_raw, 64, own_hex);

    nodus_v2_name_coin_t *coins = calloc((size_t)g_req_n, sizeof(*coins));
    nodus_v2_name_built_t *built = calloc(1, sizeof(*built));
    int rc = -1;
    if (!coins || !built) { rc = nsw_fail("Out of memory."); goto done; }
    for (int i = 0; i < g_req_n; i++) {      /* native, unlocked: g_list   */
        memcpy(coins[i].nul, g_req_coins[i].nul, 64);
        coins[i].amount = g_req_coins[i].amount;
    }

    nodus_v2_name_req_t req;
    memset(&req, 0, sizeof(req));
    req.rs            = &rs;
    req.chain32       = chain32;
    req.tip           = tip;
    req.expiry_height = expiry;
    req.pk            = pk;
    req.sk            = sk;
    req.name          = name;
    req.price         = price;
    req.fee_fixed     = 0;                   /* the floor, raised by gas  */
    req.gas_price     = gas_price;
    req.coins         = coins;
    req.n_coins       = g_req_n;
    req.rand          = rand;
    req.rand_ctx      = NULL;
    nodus_v2_name_err_t err;
    int brc = nodus_v2_name_build(&req, built, &err);
    if (brc != NODUS_V2_SPEND_OK) {
        rc = nsw_fail("%s (build rc=%d)", nsw_name_reason(brc), brc);
        goto done;
    }

    /* ── check the read-back against the request (G1) ── */
    const nodus_v2_name_decoded_t *d = &built->dec;
    int ok = strcmp(d->name, name) == 0 && d->price == price &&
             memcmp(d->owner_pk, pk, NSW_PK_LEN) == 0 &&
             d->expiry_height == expiry && d->fee == built->fee &&
             d->n_in >= 1 && d->n_in <= (int)NODUS_V2_NAME_MAX_IN &&
             d->n_out <= 1;
    uint64_t change = 0;
    if (ok && d->n_out == 1) {
        ok = memcmp(d->change_owner, own_hex, 128) == 0;
        change = d->change_amount;
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
    if (ok && (price > UINT64_MAX - d->fee ||
               price + d->fee > UINT64_MAX - change ||
               price + d->fee + change != in_sum || built->change != change))
        ok = 0;
    if (!ok) {
        rc = nsw_fail("The built name registration does not match the "
                      "request; nothing was signed for sending.");
        goto done;
    }

    g_built.env = built->env;                /* ownership moves here */
    g_built.env_len = built->env_len;
    built->env = NULL;
    memcpy(g_built.wire_id, built->wire_id, 64);
    memcpy(g_built.intent_id, built->intent_id, 64);
    nsw_fmt_hex(built->intent_id, 64, g_built.intent_hex);
    nsw_fmt_hex(built->wire_id, 64, g_built.wire_hex);
    nsw_fmt_hex(chain32, DNA_CHAIN_ID_LEN, g_built.chain_hex);
    memcpy(g_built.recipient, own_hex, 129);
    memcpy(g_built.name, d->name, sizeof(g_built.name));
    nsw_fmt_u64(d->price, g_built.price);
    nsw_fmt_u64(d->price, g_built.amount);
    nsw_fmt_u64(d->fee, g_built.fee);
    nsw_fmt_u64(change, g_built.change);
    nsw_fmt_u64(d->expiry_height, g_built.expiry);
    g_built.n_in = d->n_in;
    for (int i = 0; i < d->n_in; i++)
        nsw_fmt_hex(d->in_nul[i], 64, g_built.in_hex[i]);
    g_built.op = 0;
    rc = 0;

done:
    if (built) {
        nodus_v2_name_built_free(built);
        free(built);
    }
    free(coins);
    return rc;
}

/* OFFLINE name build (parity, like nsw_offline_build): the identity from
 * nsw_seed_buf (wiped here), the candidate coins (nsw_req_*), the change
 * seeds (nsw_out_seed_*; exactly consumed — one per fee pass that writes a
 * change), the pinned generation `gen` (>= 2), the chain id, tip, gas price
 * and price as a node would report them; no vote height, so the expiry is
 * tip + 90. */
int nsw_name_offline_build(int gen, const char *name, const char *chain_hex,
                           const char *tip_dec, const char *gas_dec,
                           const char *price_dec, const char *expiry_dec) {
    uint8_t chain32[DNA_CHAIN_ID_LEN];
    uint64_t tip = 0, gas = 0, price = 0, expiry = 0;
    uint8_t *pk = NULL, *sk = NULL;
    int rc = -1;
    if (gen < (int)NODUS_RT_GEN_2 ||
        (uint32_t)gen > nodus_v2_pins_generation_count() ||
        nsw_parse_hex(chain_hex, chain32, sizeof(chain32)) != 0 ||
        nsw_parse_u64(tip_dec, &tip) != 0 ||
        nsw_parse_u64(gas_dec, &gas) != 0 ||
        nsw_parse_u64(price_dec, &price) != 0 ||
        nsw_parse_u64(expiry_dec, &expiry) != 0) {
        rc = nsw_fail("Invalid offline name input.");
        goto done;
    }
    pk = malloc(NSW_PK_LEN);
    sk = malloc(NSW_SK_LEN);
    if (!pk || !sk) {
        rc = nsw_fail("Out of memory.");
    } else if (qgp_dsa87_keypair_derand(pk, sk, g_seed) != 0) {
        rc = nsw_fail("Key derivation failed.");
    } else {
        const nsw_gen_t g = { (uint32_t)gen, 0u, 0u };
        rc = nsw_name_core(pk, sk, chain32, tip, gas, name, price, expiry,
                           nsw_rand_explicit, &g);
        if (rc == 0 && g_out_seeds_pos != g_out_seeds_len) {
            nsw_built_clear();
            rc = nsw_fail("The build used %u of the %u output seed bytes given.",
                          (unsigned)g_out_seeds_pos, (unsigned)g_out_seeds_len);
        }
    }
done:
    nsw_wipe(g_seed, sizeof(g_seed));
    if (sk) { nsw_wipe(sk, NSW_SK_LEN); free(sk); }
    free(pk);
    nsw_wipe(g_out_seeds, sizeof(g_out_seeds));
    g_out_seeds_len = g_out_seeds_pos = 0;
    return rc;
}

/* ── the node's name prices (dnac_fee_info "np" / "ns"), for display ──
 * The four tier prices at tip + 1 (3, 4, 5, 6+ characters) and the
 * committed price changes scheduled above tip + 1. A price outside the
 * chain's range [DNAC_CFG_MIN_NAME_PRICE, DNAC_CFG_MAX_NAME_PRICE] or a
 * scheduled row for another parameter makes the answer invalid. The build
 * (nsw_name_build) reads the price again; this answer is only shown. */

static struct {
    int  valid, n_sched;
    char price[4][NSW_U64_DEC];
    int  sched_param[NODUS_DNAC_NAME_SCHED_MAX];
    char sched_value[NODUS_DNAC_NAME_SCHED_MAX][NSW_U64_DEC];
    char sched_effective[NODUS_DNAC_NAME_SCHED_MAX][NSW_U64_DEC];
} g_np;

static int nsw_np_ok(int i) { return g_np.valid && i >= 0 && i < g_np.n_sched; }
const char *nsw_np_price(int i) {
    return (g_np.valid && i >= 0 && i < 4) ? g_np.price[i] : "";
}
int nsw_np_sched_count(void)            { return g_np.valid ? g_np.n_sched : 0; }
int nsw_np_sched_param(int i)           { return nsw_np_ok(i) ? g_np.sched_param[i] : -1; }
const char *nsw_np_sched_value(int i)   { return nsw_np_ok(i) ? g_np.sched_value[i] : ""; }
const char *nsw_np_sched_effective(int i) {
    return nsw_np_ok(i) ? g_np.sched_effective[i] : "";
}

static int nsw_price_in_range(uint64_t p) {
    return p >= DNAC_CFG_MIN_NAME_PRICE && p <= DNAC_CFG_MAX_NAME_PRICE;
}

int nsw_name_prices(void) {
    if (nsw_begin() != 0) return -1;
    memset(&g_np, 0, sizeof(g_np));
    if (nsw_session_ok() != 0) return nsw_end(-1);
    nodus_dnac_name_prices_t np;
    memset(&np, 0, sizeof(np));
    int rc = nodus_client_dnac_name_prices(&g_client, &np);
    if (rc != 0)
        return nsw_end(nsw_fail("The Nodus node did not give name prices (an "
                                "older node, or no readable answer; rc=%d).",
                                rc));
    int bad = np.n_sched > NODUS_DNAC_NAME_SCHED_MAX;
    for (int i = 0; !bad && i < 4; i++)
        if (!nsw_price_in_range(np.price[i])) bad = 1;
    for (size_t i = 0; !bad && i < np.n_sched; i++)
        if (np.sched[i].param_id < DNAC_CFG_NAME_PRICE_3P ||
            np.sched[i].param_id > DNAC_CFG_NAME_PRICE_6P ||
            !nsw_price_in_range(np.sched[i].value))
            bad = 1;
    if (bad)
        return nsw_end(nsw_fail("The Nodus node returned invalid name prices."));
    for (int i = 0; i < 4; i++) nsw_fmt_u64(np.price[i], g_np.price[i]);
    for (size_t i = 0; i < np.n_sched; i++) {
        g_np.sched_param[i] = np.sched[i].param_id;
        nsw_fmt_u64(np.sched[i].value, g_np.sched_value[i]);
        nsw_fmt_u64(np.sched[i].effective, g_np.sched_effective[i]);
    }
    g_np.n_sched = (int)np.n_sched;
    g_np.valid = 1;
    return nsw_end(0);
}

/* Build one registration of `name` (lower-case) for review. The candidate
 * coins must come from the LAST nsw_list and `expiry_dec` must be
 * nsw_expiry_for's value for its tip — the gates of nsw_build_and_sign,
 * including the rule-set generation chosen from the node's answer on this
 * call (>= 2 required). Then, on this session and in the CLI's order: the
 * name is free, this ID holds no name, the price for its length (fail
 * closed: no price, no build), the gas price. The submission is nsw_submit
 * (only the envelope built last). Every network wait runs in THIS frame
 * (Asyncify); the build in nsw_name_core after them. */
int nsw_name_build(const char *name, const char *expiry_dec) {
    if (nsw_begin() != 0) return -1;
    nsw_built_clear();
    uint64_t expiry = 0;
    if (!nsw_name_ok(name))
        return nsw_end(nsw_fail("Not a chain name: 3 to 36 letters a-z and "
                                "digits."));
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
            return nsw_end(nsw_fail("The request names a coin that is not in "
                                    "your current coin list."));
    }
    if (nsw_session_ok() != 0) return nsw_end(-1);
    if (nsw_check_chain() != 0) return nsw_end(-1);
    nsw_gen_t gen;                           /* HF-4, as nsw_build_and_sign */
    if (nsw_select_generation(&gen) != 0) return nsw_end(-1);
    if (gen.gen < NODUS_RT_GEN_2)
        return nsw_end(gen.h != 0
            ? nsw_fail("Chain names open at block %llu, when the Nodus "
                       "network switches to its new rules. Nothing was "
                       "built.", (unsigned long long)gen.h)
            : nsw_fail("Chain names are not open on this network yet. "
                       "Nothing was built."));
    nodus_dnac_name_result_t r;
    memset(&r, 0, sizeof(r));
    int rc = nodus_client_dnac_name_lookup(&g_client, name, &r);
    if (rc != 0)
        return nsw_end(nsw_fail("Could not check whether the name is free "
                                "(rc=%d). Nothing was built.", rc));
    if (r.found)
        return nsw_end(nsw_fail("The name \"%s\" is already registered. "
                                "Nothing was built.", name));
    if (g_cancel) return nsw_end(-1);
    memset(&r, 0, sizeof(r));
    rc = nodus_client_dnac_name_of(&g_client, g_fp_hex, &r);
    if (rc != 0)
        return nsw_end(nsw_fail("Could not check whether this wallet already "
                                "has a name (rc=%d). Nothing was built.", rc));
    if (r.found)
        return nsw_end(nsw_fail("This wallet already has the chain name \"%s\"."
                                " Each ID can hold one name. Nothing was "
                                "built.", r.name));
    if (g_cancel) return nsw_end(-1);
    nodus_dnac_name_prices_t np;
    memset(&np, 0, sizeof(np));
    rc = nodus_client_dnac_name_prices(&g_client, &np);
    if (rc != 0)                             /* never a guessed price      */
        return nsw_end(nsw_fail("The Nodus node did not give the name price "
                                "(rc=%d). Nothing was built.", rc));
    uint64_t price = 0;
    if (nodus_v2_name_price_for(np.price, strlen(name), &price) != 0 ||
        !nsw_price_in_range(price))
        return nsw_end(nsw_fail("The Nodus node returned an invalid name "
                                "price. Nothing was built."));
    if (g_cancel) return nsw_end(-1);
    nodus_dnac_fee_info_t fi;
    memset(&fi, 0, sizeof(fi));
    rc = nodus_client_dnac_fee_info(&g_client, &fi);
    if (rc != 0)
        return nsw_end(nsw_fail("The network fee is unknown (rc=%d). Nothing "
                                "was built.", rc));
    if (g_cancel) return nsw_end(-1);
    rc = nsw_name_core(g_id.pk.bytes, g_id.sk.bytes, g_net.chain, g_list.tip,
                       fi.gas_price, name, price, expiry, nsw_rand_csprng,
                       &gen);
    return nsw_end(rc);
}

/* ═══ VAULTS — general multisig (M-of-N) ═════════════════════════════════
 *
 * Decision docs/plans/decisions/2026-09-29-general-multisig.md (M-of-N
 * address, at most 7 keys per address, auth_kind 3, validity tip + 90
 * blocks) with design docs/plans/2026-09-29-general-multisig-design.md §7
 * rev 2; operator 2026-10-03 (vaults in Nodus Connect: members by name,
 * the address computed here, members told by message, Foundation preset,
 * a vault listed only for its members). Every byte rule is the shared
 * library's (nodus/src/client/nodus_v2_msig.c — nodus-cli's `msig address`,
 * `v2-envelope spend --msig`, `msig sign`, `msig combine` moved out); the
 * descriptor codec and the address are shared/dnac/msig_wire.c. Nothing
 * here restates them.
 *
 * WHAT IS HERE (one vault "in use" at a time; JS switches with
 * nsw_msig_load):
 *   members    nsw_msig_member_add(fp) reads the member's SIGNED profile
 *              (connect/nc_profile.c nc_profile_read: signature checked,
 *              SHA3-512(dilithium_pubkey) == fp) and keeps the 2592-byte
 *              key HERE — JS never hands a public key in;
 *              nsw_msig_member_add_self adds this wallet's own key.
 *   create     nsw_msig_create(M) -> nodus_v2_msig_desc_from_keys.
 *   load       nsw_msig_load(descriptor hex) -> dna_msig_desc_parse +
 *              dna_msig_address; the member IDs are DERIVED here
 *              (SHA3-512 of each key), never taken from a message.
 *   balance    dnac_balance of the vault address (public, decision
 *              2026-09-28-scan-v3-query.md 3a).
 *   coins      NO node answers a coin list for an address without its
 *              session key (dnac_utxo is gated to the session's own
 *              fingerprint, C11; nodus-cli's `--msig` takes coins by
 *              hand for the same reason). The vault's coins are FOUND
 *              here by reading committed blocks (dnac_v3_block, public):
 *              a created coin whose owner is the vault, minus every coin
 *              a later item consumed — nsw_msig_scan, at most
 *              NSW_MS_SCAN_BLOCKS blocks per call, resumed by JS from the
 *              height it returns. Genesis outputs are not in any block:
 *              a vault funded at genesis (the Foundation vault) has coins
 *              this scan cannot find — the balance shows them, the build
 *              cannot use them (the page says so).
 *   build      nsw_msig_build(to, amount): the shared builder on coins of
 *              the scan (largest first, the fewest that cover amount +
 *              fee), K = M, expiry = nsw_expiry_for (tip + 90, the
 *              decision's window), the generation the node runs.
 *   transport  a proposal travels by Messages as the export's parts with
 *              the UNSIGNED auth blob left out (nsw_msig_prop_*): that
 *              blob is K zero slots + the descriptor, which every member
 *              already holds — nsw_msig_prop_in rebuilds it from the
 *              descriptor of the vault in use (nodus_v2_msig_unsigned_
 *              auth), so the export bytes are nodus-cli's again and the
 *              descriptor is the receiver's OWN copy. A stored Messages
 *              record holds at most 64 KiB (src/connect/store.js
 *              PLAINTEXT_MAX); a full export of a 7-key vault does not
 *              fit, its parts do.
 *   review     nsw_msig_review: nodus_v2_msig_review (shape, membership,
 *              the digest re-derived and EQUAL, the call's lengths) at the
 *              node's current tip; then EVERY coin it spends must be one
 *              of the vault's own coins this module holds (F1 — the only
 *              binding of a request to its vault: the descriptor it
 *              carries is rebuilt from the receiver's own code, so the
 *              address check below is a backstop), every output must be
 *              native NODUS, the expiry within the node's tip + 90 (F3),
 *              and "expired" = tip + 1 > expiry. Every field
 *              shown comes from the export bytes, never from a message's
 *              words.
 *   sign       nsw_msig_sign: only after a review in this module, not
 *              expired, by a member; signs the digest (hedged ML-DSA-87)
 *              and writes nodus-cli's signature text.
 *   combine    nsw_msig_sig_add (each signature checked on arrival:
 *              nodus_v2_msig_sig_check) and nsw_msig_submit
 *              (nodus_v2_msig_combine with the first K, then dnac_spend
 *              on this session). The chain's own auth hook is witness
 *              code this module cannot link (nodus-cli runs it locally);
 *              the node judges the authorization when the envelope
 *              arrives.
 */

#define NSW_MS_MAX_COINS   64
#define NSW_MS_MAX_EVENTS  32
#define NSW_MS_SCAN_BLOCKS 200u
#define NSW_MS_SCAN_PAGES  64u             /* pages of ONE block per read  */
#define NSW_MS_SCAN_ITEMS  4096u           /* items per scan call (F6)     */
#define NSW_MS_MAX_SIGS    ((int)NODUS_RT_AUTH_MAX_SIGNERS)
/* the auth-less envelope a proposal message carries (see "transport") */
#define NSW_MS_PREFIX_MAX  65536u

typedef struct {
    uint8_t  id[64];
    uint64_t amount, unlock, height;
} nsw_ms_coin_t;

typedef struct {
    uint64_t height;
    int      dir;                         /* 1 received, -1 sent (+ fee)  */
    uint64_t amount;
    char     id_hex[129];
} nsw_ms_event_t;

static struct {
    /* members collected for a new vault */
    int      n_keys;
    uint8_t  keys[DNA_MSIG_MAX_N][NSW_PK_LEN];
    /* the vault in use */
    int      has_desc;
    uint8_t  desc[DNA_MSIG_MAX_DESC_LEN];
    size_t   desc_len;
    char     desc_hex[2 * DNA_MSIG_MAX_DESC_LEN + 1];
    uint8_t  addr[64];
    char     addr_hex[129];
    uint8_t  m, n;
    char     member_fp[DNA_MSIG_MAX_N][129];
    char     bal_total[NSW_U64_DEC], bal_spendable[NSW_U64_DEC];
    /* its coins and the items of the last scan */
    int      n_coins, coins_full;
    nsw_ms_coin_t coins[NSW_MS_MAX_COINS];
    int      n_events;
    nsw_ms_event_t events[NSW_MS_MAX_EVENTS];
    char     scan_next[NSW_U64_DEC], scan_tip[NSW_U64_DEC];
    /* the payment request in use */
    int      has_export;
    nodus_v2_msig_export_t x;
    char     chain_hex[65], tip_dec[NSW_U64_DEC], signers_dec[NSW_U64_DEC],
             digest_hex[129];
    char    *prefix_hex;                  /* heap                          */
    char    *text;                        /* heap: export or signature text*/
    int      reviewed, expired;
    uint64_t now_tip;
    nodus_v2_msig_review_t rv;
    /* signatures collected for it */
    int      n_sigs;
    uint8_t  sig_dg[NSW_MS_MAX_SIGS][64];
    uint8_t  sig_pk[NSW_MS_MAX_SIGS][NSW_PK_LEN];
    uint8_t  sig_sig[NSW_MS_MAX_SIGS][QGP_DSA87_SIGNATURE_BYTES];
    char     sig_fp[NSW_MS_MAX_SIGS][129];
    /* the last submission */
    char     intent_hex[129], wire_hex[129];
} g_ms;

static char g_ms_num[NSW_U64_DEC];
static const char *nsw_ms_u64(uint64_t v) { nsw_fmt_u64(v, g_ms_num); return g_ms_num; }

static void nsw_ms_proposal_clear(void) {
    if (g_ms.x.env) nsw_wipe(g_ms.x.env, g_ms.x.env_len);
    nodus_v2_msig_export_free(&g_ms.x);
    memset(&g_ms.x, 0, sizeof(g_ms.x));
    free(g_ms.prefix_hex);
    g_ms.prefix_hex = NULL;
    free(g_ms.text);
    g_ms.text = NULL;
    g_ms.has_export = 0;
    g_ms.reviewed = g_ms.expired = 0;
    g_ms.now_tip = 0;
    memset(&g_ms.rv, 0, sizeof(g_ms.rv));
    g_ms.chain_hex[0] = g_ms.tip_dec[0] = g_ms.signers_dec[0] =
        g_ms.digest_hex[0] = '\0';
    g_ms.n_sigs = 0;
    nsw_wipe(g_ms.sig_sig, sizeof(g_ms.sig_sig));
    g_ms.intent_hex[0] = g_ms.wire_hex[0] = '\0';
}

static void nsw_msig_wipe(void) {
    nsw_ms_proposal_clear();
    memset(&g_ms, 0, sizeof(g_ms));
}

/* The vault in use := `desc` (validated). Everything tied to the previous
 * vault (coins, items, balance, request, signatures) is dropped. */
static int nsw_ms_set_desc(const uint8_t *desc, size_t len) {
    uint8_t m = 0, n = 0, addr[64];
    const uint8_t *keys = NULL;
    if (dna_msig_desc_parse(desc, len, &m, &n, &keys) != 0 ||
        dna_msig_address(desc, len, addr) != 0)
        return nsw_fail("This is not a valid vault.");
    nsw_ms_proposal_clear();
    memmove(g_ms.desc, desc, len);
    g_ms.desc_len = len;
    nsw_fmt_hex(g_ms.desc, len, g_ms.desc_hex);
    memcpy(g_ms.addr, addr, 64);
    qgp_fp_raw_to_hex(addr, g_ms.addr_hex);
    g_ms.m = m;
    g_ms.n = n;
    for (uint8_t i = 0; i < n; i++) {
        uint8_t fp[64];
        if (qgp_sha3_512(g_ms.desc + DNA_MSIG_HDR_LEN +
                             (size_t)i * DNA_MSIG_PUBKEY_LEN,
                         DNA_MSIG_PUBKEY_LEN, fp) != 0) {
            g_ms.has_desc = 0;
            return nsw_fail("This is not a valid vault.");
        }
        qgp_fp_raw_to_hex(fp, g_ms.member_fp[i]);
    }
    g_ms.bal_total[0] = g_ms.bal_spendable[0] = '\0';
    g_ms.n_coins = g_ms.coins_full = 0;
    g_ms.n_events = 0;
    g_ms.scan_next[0] = g_ms.scan_tip[0] = '\0';
    g_ms.has_desc = 1;
    return 0;
}

static int nsw_ms_key_in_desc(const uint8_t *pk) {
    if (!g_ms.has_desc) return 0;
    for (uint8_t i = 0; i < g_ms.n; i++)
        if (memcmp(g_ms.desc + DNA_MSIG_HDR_LEN +
                       (size_t)i * DNA_MSIG_PUBKEY_LEN,
                   pk, DNA_MSIG_PUBKEY_LEN) == 0)
            return 1;
    return 0;
}

static int nsw_ms_is_member(void) {
    return g_unlocked && !g_locked && nsw_ms_key_in_desc(g_id.pk.bytes);
}

/* ── members of a new vault ── */

void nsw_msig_member_reset(void) {
    g_ms.n_keys = 0;
    memset(g_ms.keys, 0, sizeof(g_ms.keys));
}

int nsw_msig_member_count(void) { return g_ms.n_keys; }

static int nsw_ms_member_put(const uint8_t *pk) {
    for (int i = 0; i < g_ms.n_keys; i++)
        if (memcmp(g_ms.keys[i], pk, NSW_PK_LEN) == 0)
            return nsw_fail("This person is already a member of the new "
                            "vault.");
    if (g_ms.n_keys >= (int)DNA_MSIG_MAX_N)
        return nsw_fail("A vault can have at most %u members.",
                        (unsigned)DNA_MSIG_MAX_N);
    memcpy(g_ms.keys[g_ms.n_keys++], pk, NSW_PK_LEN);
    return 0;
}

int nsw_msig_member_add_self(void) {
    if (!g_unlocked || g_locked) return nsw_fail("Nodus connection is not ready.");
    return nsw_ms_member_put(g_id.pk.bytes);
}

/* `fp_hex`: the member's ID. Its key comes from its signed profile. */
int nsw_msig_member_add(const char *fp_hex) {
    if (nsw_begin() != 0) return -1;
    uint8_t fp[64];
    if (nsw_parse_hex(fp_hex, fp, sizeof(fp)) != 0)
        return nsw_end(nsw_fail("Invalid Nodus ID."));
    if (nsw_session_ok() != 0) return nsw_end(-1);
    nc_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.client = &g_client;
    ctx.keys = NULL;                         /* a read: no Messages key used */
    ctx.fresh = false;
    ctx.cancel = &g_cancel;
    nc_read_t raw;
    dna_unified_identity_t *id = NULL;
    nc_profile_read(&ctx, fp_hex, &raw, &id, NULL);
    int rc;
    uint8_t check[64];
    if (raw.outcome != NC_FOUND || !id) {
        rc = nsw_fail("This person's account could not be read, or did not "
                      "pass its signature check. They were not added.");
    } else if (qgp_sha3_512(id->dilithium_pubkey, NSW_PK_LEN, check) != 0 ||
               memcmp(check, fp, 64) != 0) {
        rc = nsw_fail("This person's account does not belong to this ID. "
                      "They were not added.");
    } else {
        rc = nsw_ms_member_put(id->dilithium_pubkey);
    }
    dna_identity_free(id);
    nc_read_clear(&raw);
    return nsw_end(rc);
}

#ifdef NODUS_SEND_TEST_FIXED_RANDOM
/* TEST-only (parity build, never shipped — build-nodus-send-wasm.sh
 * exports_test): a member key given directly, so the descriptor parity
 * runs without a node. */
int nsw_test_msig_member_add_pk(const char *pk_hex) {
    uint8_t pk[NSW_PK_LEN];
    if (nsw_parse_hex(pk_hex, pk, sizeof(pk)) != 0) return nsw_fail("Invalid key.");
    return nsw_ms_member_put(pk);
}
#endif

/* ── create / load the vault in use ── */

int nsw_msig_create(int m) {
    if (g_ms.n_keys < (int)DNA_MSIG_MIN_N)
        return nsw_fail("A vault needs %u to %u members.",
                        (unsigned)DNA_MSIG_MIN_N, (unsigned)DNA_MSIG_MAX_N);
    if (m < 1 || m > g_ms.n_keys)
        return nsw_fail("The number of approvals must be between 1 and the "
                        "number of members.");
    static uint8_t desc[DNA_MSIG_MAX_DESC_LEN];
    uint8_t addr[64];
    size_t dl = 0;
    int rc = nodus_v2_msig_desc_from_keys((uint8_t)m, (uint8_t)g_ms.n_keys,
                                          &g_ms.keys[0][0], desc, sizeof(desc),
                                          &dl, addr);
    if (rc != NODUS_V2_SPEND_OK)
        return nsw_fail("These members cannot form a vault (rc=%d).", rc);
    return nsw_ms_set_desc(desc, dl);
}

int nsw_msig_load(const char *desc_hex) {
    size_t h = desc_hex ? strnlen(desc_hex, 2 * DNA_MSIG_MAX_DESC_LEN + 1) : 0;
    static uint8_t desc[DNA_MSIG_MAX_DESC_LEN];
    if (h == 0 || h > 2 * DNA_MSIG_MAX_DESC_LEN || (h & 1u) ||
        nsw_parse_hex(desc_hex, desc, h / 2) != 0)
        return nsw_fail("This is not a valid vault.");
    return nsw_ms_set_desc(desc, h / 2);
}

const char *nsw_msig_addr(void)     { return g_ms.has_desc ? g_ms.addr_hex : ""; }
const char *nsw_msig_desc_hex(void) { return g_ms.has_desc ? g_ms.desc_hex : ""; }
int nsw_msig_m(void)                { return g_ms.has_desc ? g_ms.m : 0; }
int nsw_msig_n(void)                { return g_ms.has_desc ? g_ms.n : 0; }
const char *nsw_msig_member(int i) {
    return (g_ms.has_desc && i >= 0 && i < g_ms.n) ? g_ms.member_fp[i] : "";
}
int nsw_msig_is_member(void)        { return nsw_ms_is_member(); }

/* ── balance: dnac_balance of the vault address, the native row ── */

int nsw_msig_balance(void) {
    if (nsw_begin() != 0) return -1;
    if (!g_ms.has_desc) return nsw_end(nsw_fail("No vault is open."));
    if (nsw_session_ok() != 0) return nsw_end(-1);
    nodus_dnac_balance_result_t res;
    memset(&res, 0, sizeof(res));
    int rc = nodus_client_dnac_balance(&g_client, g_ms.addr_hex, &res);
    if (rc != 0) return nsw_end(nsw_fail("The vault balance is unavailable (rc=%d).", rc));
    static const uint8_t zero64[64] = {0};
    uint64_t total = 0, spendable = 0;
    for (size_t i = 0; i < res.count; i++)
        if (memcmp(res.tokens[i].token_id, zero64, 64) == 0) {
            total = res.tokens[i].total;
            spendable = res.tokens[i].spendable;
        }
    nodus_client_free_balance_result(&res);
    if (spendable > total) return nsw_end(nsw_fail("The vault balance is unavailable."));
    nsw_fmt_u64(total, g_ms.bal_total);
    nsw_fmt_u64(spendable, g_ms.bal_spendable);
    return nsw_end(0);
}

const char *nsw_msig_bal_total(void)     { return g_ms.bal_total; }
const char *nsw_msig_bal_spendable(void) { return g_ms.bal_spendable; }

/* ── the vault's coins: JS hands back what an earlier scan found ── */

void nsw_msig_coins_reset(void) {
    g_ms.n_coins = g_ms.coins_full = 0;
    g_ms.n_events = 0;
}

int nsw_msig_coin_add(const char *id_hex, const char *amount_dec,
                      const char *unlock_dec, const char *height_dec) {
    nsw_ms_coin_t c;
    memset(&c, 0, sizeof(c));
    if (nsw_parse_hex(id_hex, c.id, sizeof(c.id)) != 0 ||
        nsw_parse_u64(amount_dec, &c.amount) != 0 || c.amount == 0 ||
        nsw_parse_u64(unlock_dec, &c.unlock) != 0 ||
        nsw_parse_u64(height_dec, &c.height) != 0)
        return nsw_fail("Invalid vault coin.");
    for (int i = 0; i < g_ms.n_coins; i++)
        if (memcmp(g_ms.coins[i].id, c.id, 64) == 0)
            return nsw_fail("The same vault coin was listed twice.");
    if (g_ms.n_coins >= NSW_MS_MAX_COINS) {
        g_ms.coins_full = 1;
        return nsw_fail("This vault has more coins than this page can hold.");
    }
    g_ms.coins[g_ms.n_coins++] = c;
    return 0;
}

static void nsw_ms_event(uint64_t h, const nodus_dnac_v3_item_t *it,
                         uint64_t in_sum, uint64_t out_sum) {
    if (g_ms.n_events >= NSW_MS_MAX_EVENTS) {
        memmove(&g_ms.events[0], &g_ms.events[1],
                sizeof(g_ms.events[0]) * (NSW_MS_MAX_EVENTS - 1));
        g_ms.n_events = NSW_MS_MAX_EVENTS - 1;
    }
    nsw_ms_event_t *e = &g_ms.events[g_ms.n_events++];
    memset(e, 0, sizeof(*e));
    e->height = h;
    e->dir = in_sum >= out_sum ? 1 : -1;
    e->amount = in_sum >= out_sum ? in_sum - out_sum : out_sum - in_sum;
    if (it->has_intent_id)          nsw_fmt_hex(it->intent_id, 64, e->id_hex);
    else if (it->has_wire_id)       nsw_fmt_hex(it->wire_id, 64, e->id_hex);
    else if (it->n_created > 0)     nsw_fmt_hex(it->created[0].id, 64, e->id_hex);
}

/* One applied item: coins it consumed leave the set, native coins it
 * created for the vault join it. */
static void nsw_ms_apply_item(uint64_t h, const nodus_dnac_v3_item_t *it) {
    static const uint8_t zero64[64] = {0};
    uint64_t in_sum = 0, out_sum = 0;
    int touched = 0;
    for (uint8_t k = 0; k < it->n_consumed && k < NODUS_DNAC_V3_ITEM_MAX_IN; k++)
        for (int c = 0; c < g_ms.n_coins; c++)
            if (memcmp(g_ms.coins[c].id, it->consumed[k], 64) == 0) {
                if (out_sum <= UINT64_MAX - g_ms.coins[c].amount)
                    out_sum += g_ms.coins[c].amount;
                g_ms.coins[c] = g_ms.coins[--g_ms.n_coins];
                touched = 1;
                break;
            }
    for (uint8_t k = 0; k < it->n_created && k < NODUS_DNAC_V3_ITEM_MAX_OUT; k++) {
        const nodus_dnac_v3_coin_t *cr = &it->created[k];
        if (strncmp(cr->owner, g_ms.addr_hex, 128) != 0) continue;
        touched = 1;
        if (memcmp(cr->token_id, zero64, 64) != 0 || cr->amount == 0) continue;
        /* F6: a coin id already held (a node repeating an item, or a page
         * read twice) is not added twice */
        int dup = 0;
        for (int c = 0; c < g_ms.n_coins && !dup; c++)
            if (memcmp(g_ms.coins[c].id, cr->id, 64) == 0) dup = 1;
        if (dup) continue;
        if (in_sum <= UINT64_MAX - cr->amount) in_sum += cr->amount;
        if (g_ms.n_coins >= NSW_MS_MAX_COINS) { g_ms.coins_full = 1; continue; }
        nsw_ms_coin_t *c = &g_ms.coins[g_ms.n_coins++];
        memcpy(c->id, cr->id, 64);
        c->amount = cr->amount;
        c->unlock = cr->unlock_block;
        c->height = h;
    }
    if (touched) nsw_ms_event(h, it, in_sum, out_sum);
}

/* Read committed blocks `from` .. min(tip, from + NSW_MS_SCAN_BLOCKS - 1)
 * completely (every page); nsw_msig_scan_next is the height to resume at.
 * A partial read fails: nothing past the last complete block counts. */
int nsw_msig_scan(const char *from_dec) {
    if (nsw_begin() != 0) return -1;
    uint64_t from = 0;
    if (!g_ms.has_desc) return nsw_end(nsw_fail("No vault is open."));
    if (nsw_parse_u64(from_dec, &from) != 0 || from == 0)
        return nsw_end(nsw_fail("Invalid block height."));
    if (nsw_session_ok() != 0) return nsw_end(-1);
    bool has_tip = false;
    uint64_t tip = 0;
    int rc = nodus_client_dnac_supply_tip(&g_client, &has_tip, &tip);
    if (rc != 0 || !has_tip || tip == 0)
        return nsw_end(nsw_fail("The current Nodus block height is unknown "
                                "(rc=%d).", rc));
    g_ms.n_events = 0;
    uint64_t last = from - 1;
    if (from <= tip) {
        last = tip;
        if (tip - from >= NSW_MS_SCAN_BLOCKS) last = from + NSW_MS_SCAN_BLOCKS - 1u;
    }
    /* F6: bounded work per call — at most NSW_MS_SCAN_PAGES pages of one
     * block (a node whose paging never ends is refused) and, across the
     * call, a stop after the block in which NSW_MS_SCAN_ITEMS items were
     * passed (the next call resumes after it) */
    uint64_t items = 0;
    for (uint64_t h = from; h <= last; h++) {
        uint32_t idx = 0, pages = 0;
        for (;;) {
            if (g_cancel) return nsw_end(-1);
            if (++pages > NSW_MS_SCAN_PAGES)
                return nsw_end(nsw_fail("Block %llu has more pages than this "
                                        "page reads.", (unsigned long long)h));
            nodus_dnac_v3_block_result_t page;
            memset(&page, 0, sizeof(page));
            rc = nodus_client_dnac_v3_block(&g_client, h, idx, 0, &page);
            if (rc != 0)
                return nsw_end(nsw_fail("Block %llu could not be read "
                                        "(rc=%d).", (unsigned long long)h, rc));
            int bad = page.height != h;
            items += page.count;
            for (size_t i = 0; !bad && i < page.count; i++) {
                const nodus_dnac_v3_item_t *it = &page.items[i];
                if (it->code == 0 && it->has_effects) nsw_ms_apply_item(h, it);
            }
            int more = !bad && page.has_next;
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
        if (items >= NSW_MS_SCAN_ITEMS) { last = h; break; }
    }
    nsw_fmt_u64(last + 1, g_ms.scan_next);
    nsw_fmt_u64(tip, g_ms.scan_tip);
    return nsw_end(0);
}

const char *nsw_msig_scan_next(void) { return g_ms.scan_next; }
const char *nsw_msig_scan_tip(void)  { return g_ms.scan_tip; }
int nsw_msig_coins_full(void)        { return g_ms.coins_full; }
int nsw_msig_coin_count(void)        { return g_ms.n_coins; }
static int nsw_ms_coin_ok(int i)     { return i >= 0 && i < g_ms.n_coins; }
const char *nsw_msig_coin_id(int i) {
    static char hex[129];
    hex[0] = '\0';
    if (nsw_ms_coin_ok(i)) nsw_fmt_hex(g_ms.coins[i].id, 64, hex);
    return hex;
}
const char *nsw_msig_coin_amount(int i) { return nsw_ms_coin_ok(i) ? nsw_ms_u64(g_ms.coins[i].amount) : ""; }
const char *nsw_msig_coin_unlock(int i) { return nsw_ms_coin_ok(i) ? nsw_ms_u64(g_ms.coins[i].unlock) : ""; }
const char *nsw_msig_coin_height(int i) { return nsw_ms_coin_ok(i) ? nsw_ms_u64(g_ms.coins[i].height) : ""; }
int nsw_msig_event_count(void)        { return g_ms.n_events; }
static int nsw_ms_ev_ok(int i)        { return i >= 0 && i < g_ms.n_events; }
const char *nsw_msig_event_height(int i) { return nsw_ms_ev_ok(i) ? nsw_ms_u64(g_ms.events[i].height) : ""; }
int nsw_msig_event_dir(int i)         { return nsw_ms_ev_ok(i) ? g_ms.events[i].dir : 0; }
const char *nsw_msig_event_amount(int i) { return nsw_ms_ev_ok(i) ? nsw_ms_u64(g_ms.events[i].amount) : ""; }
const char *nsw_msig_event_id(int i)  { return nsw_ms_ev_ok(i) ? g_ms.events[i].id_hex : ""; }

/* ── the payment request in use: its parts, its review ── */

/* After g_ms.x is set: the hex fields, the auth-less prefix, the export
 * text (nodus-cli's file, byte for byte). */
static int nsw_ms_export_fill(void) {
    dna_env_view_t *v = calloc(1, sizeof(*v));
    if (!v) return nsw_fail("Out of memory.");
    int ok = dna_env_decode(g_ms.x.env, g_ms.x.env_len, v) == 0 &&
             v->leg_count == 1 &&
             (size_t)v->auth_off[0] + v->leg[0].auth_len == g_ms.x.env_len;
    const size_t prefix_len = ok ? v->auth_off[0] : 0;
    free(v);
    if (!ok || prefix_len == 0 || prefix_len > NSW_MS_PREFIX_MAX)
        return nsw_fail("This payment request is damaged.");
    g_ms.prefix_hex = malloc(2 * prefix_len + 1);
    if (!g_ms.prefix_hex) return nsw_fail("Out of memory.");
    nsw_fmt_hex(g_ms.x.env, prefix_len, g_ms.prefix_hex);
    nsw_fmt_hex(g_ms.x.chain32, sizeof(g_ms.x.chain32), g_ms.chain_hex);
    nsw_fmt_u64(g_ms.x.tip, g_ms.tip_dec);
    nsw_fmt_u64(g_ms.x.signers, g_ms.signers_dec);
    nsw_fmt_hex(g_ms.x.digest, 64, g_ms.digest_hex);
    size_t tl = 0;
    if (nodus_v2_msig_export_encode(g_ms.x.chain32, g_ms.x.tip, g_ms.x.signers,
                                    g_ms.x.digest, g_ms.x.env, g_ms.x.env_len,
                                    &g_ms.text, &tl) != NODUS_V2_SPEND_OK)
        return nsw_fail("Out of memory.");
    g_ms.has_export = 1;
    return 0;
}

/* The CORE tuple of the pinned generation whose CORE version the request's
 * leg names (nodus-cli cli_core_runtime_for_env over the pins). */
static int nsw_ms_core_tuple(uint32_t *cv_out, uint8_t ch_out[64]) {
    uint32_t version = 0;
    if (nodus_v2_msig_core_version(g_ms.x.env, g_ms.x.env_len, &version) !=
        NODUS_V2_SPEND_OK)
        return nsw_fail("This payment request is damaged.");
    for (uint32_t gen = 1; gen <= nodus_v2_pins_generation_count(); gen++) {
        uint32_t sv = 0, cv = 0;
        uint8_t sh[64], ch[64];
        if (nodus_v2_pins_tuples(gen, &sv, sh, &cv, ch) != NODUS_V2_SPEND_OK)
            continue;
        if (cv == version) {
            *cv_out = cv;
            memcpy(ch_out, ch, 64);
            return 0;
        }
    }
    return nsw_fail("This payment request was made for transaction rules "
                    "this page does not know. Reload the page.");
}

/* F1: every coin a request spends must be one of the vault's OWN coins —
 * the set this module holds for the vault in use (found in its blocks, or
 * its genesis coins), loaded by JS from the vault's record before a review.
 * The request's descriptor cannot tell (the receiver rebuilds it from its
 * own vault code, and the digest does not cover it), so this is what binds
 * a request to the vault it is signed for. */
static int nsw_ms_inputs_owned(const nodus_v2_msig_review_t *rv) {
    for (int i = 0; i < rv->n_in; i++) {
        int found = 0;
        for (int c = 0; c < g_ms.n_coins && !found; c++)
            if (memcmp(g_ms.coins[c].id, rv->in_nul[i], 64) == 0) found = 1;
        if (!found) return 0;
    }
    return 1;
}

#define NSW_MS_NOT_OWNED "This request spends coins this vault does not " \
    "hold — do not approve it. Refresh the vault if you think this is wrong."

/* The co-signer's read-back at the node's tip `now_tip` (see "review"). */
static int nsw_ms_review_now(uint64_t now_tip) {
    g_ms.reviewed = g_ms.expired = 0;
    memset(&g_ms.rv, 0, sizeof(g_ms.rv));
    if (!g_ms.has_export) return nsw_fail("There is no payment request to review.");
    uint32_t cv = 0;
    uint8_t ch[64];
    if (nsw_ms_core_tuple(&cv, ch) != 0) return -1;
    dna_env_preflight_t *pf = calloc(1, sizeof(*pf));
    if (!pf) return nsw_fail("Out of memory.");
    const uint8_t *signer = nsw_ms_is_member() ? g_id.pk.bytes : NULL;
    int rc = nodus_v2_msig_review(&g_ms.x, cv, ch, signer, pf, &g_ms.rv);
    free(pf);
    switch (rc) {
    case NODUS_V2_SPEND_OK: break;
    case NODUS_V2_MSIG_ERR_DIGEST:
        return nsw_fail("This payment request does not match its own "
                        "contents. Do not approve it.");
    case NODUS_V2_SPEND_ERR_PREFLIGHT1:
        return nsw_fail("This payment request is for another network, has "
                        "expired, or uses transaction rules this page does "
                        "not know.");
    case NODUS_V2_MSIG_ERR_CALL:
        return nsw_fail("This payment request is damaged. Do not approve it.");
    case NODUS_V2_MSIG_ERR_EXPIRY:
        return nsw_fail("This payment request never expires, or stays valid "
                        "longer than any wallet makes one. Do not approve it.");
    default:
        return nsw_fail("This payment request is not a vault payment this "
                        "page can read (rc=%d).", rc);
    }
    if (memcmp(g_ms.rv.addr, g_ms.addr, 64) != 0) {
        memset(&g_ms.rv, 0, sizeof(g_ms.rv));
        return nsw_fail("This payment request spends from a different vault "
                        "than the one it was sent for. Do not approve it.");
    }
    if (!nsw_ms_inputs_owned(&g_ms.rv)) {
        memset(&g_ms.rv, 0, sizeof(g_ms.rv));
        return nsw_fail(NSW_MS_NOT_OWNED);
    }
    static const uint8_t zero64[64] = {0};
    for (int o = 0; o < g_ms.rv.n_out; o++)
        if (memcmp(g_ms.rv.out_token[o], zero64, 64) != 0) {
            memset(&g_ms.rv, 0, sizeof(g_ms.rv));
            return nsw_fail("This payment request moves a token this page "
                            "cannot show. Do not approve it.");
        }
    /* F3: the window is judged at the NODE's tip too, not only at the tip
     * the proposer wrote — nsw_expiry_for's tip + NSW_EXPIRY_AHEAD */
    if (now_tip > UINT64_MAX - NSW_EXPIRY_AHEAD ||
        g_ms.rv.expiry_height > now_tip + NSW_EXPIRY_AHEAD) {
        memset(&g_ms.rv, 0, sizeof(g_ms.rv));
        return nsw_fail("This payment request stays valid longer than any "
                        "wallet makes one. Do not approve it.");
    }
    g_ms.now_tip = now_tip;
    g_ms.expired = now_tip >= g_ms.rv.expiry_height;   /* tip + 1 > expiry */
    g_ms.reviewed = 1;
    return 0;
}

/* A request received by message: its parts + the vault in use's OWN
 * descriptor (see "transport"). */
int nsw_msig_prop_in(const char *chain_hex, const char *tip_dec,
                     const char *signers_dec, const char *digest_hex,
                     const char *prefix_hex) {
    nsw_ms_proposal_clear();
    if (!g_ms.has_desc) return nsw_fail("No vault is open.");
    uint8_t chain[DNA_CHAIN_ID_LEN], digest[64];
    uint64_t tip = 0, k = 0;
    size_t ph = prefix_hex ? strnlen(prefix_hex, 2 * NSW_MS_PREFIX_MAX + 1) : 0;
    if (nsw_parse_hex(chain_hex, chain, sizeof(chain)) != 0 ||
        nsw_parse_u64(tip_dec, &tip) != 0 || tip == 0 ||
        nsw_parse_u64(signers_dec, &k) != 0 || k < g_ms.m || k > g_ms.n ||
        nsw_parse_hex(digest_hex, digest, sizeof(digest)) != 0 ||
        ph == 0 || ph > 2 * NSW_MS_PREFIX_MAX || (ph & 1u))
        return nsw_fail("This payment request is damaged.");
    if (memcmp(chain, g_net.chain, sizeof(chain)) != 0)
        return nsw_fail("This payment request is for another network.");
    const size_t plen = ph / 2;
    const size_t alen = 1u + (size_t)k * NODUS_RT_AUTH_SIGNER_LEN + 3u +
                        g_ms.desc_len;
    uint8_t *env = malloc(plen + alen);
    if (!env) return nsw_fail("Out of memory.");
    size_t al = 0;
    if (nsw_parse_hex(prefix_hex, env, plen) != 0 ||
        nodus_v2_msig_unsigned_auth((uint32_t)k, g_ms.desc, g_ms.desc_len,
                                    env + plen, alen, &al) != NODUS_V2_SPEND_OK ||
        al != alen) {
        free(env);
        return nsw_fail("This payment request is damaged.");
    }
    memcpy(g_ms.x.chain32, chain, sizeof(chain));
    g_ms.x.tip = tip;
    g_ms.x.signers = (uint32_t)k;
    memcpy(g_ms.x.digest, digest, 64);
    g_ms.x.env = env;
    g_ms.x.env_len = plen + alen;
    if (nsw_ms_export_fill() != 0) {
        nsw_ms_proposal_clear();
        return -1;
    }
    /* the rebuilt auth blob must be the one the envelope's own header
     * declares (nsw_ms_export_fill checked the prefix length) */
    dna_env_view_t *v = calloc(1, sizeof(*v));
    nodus_v2_msig_leg_t leg;
    int ok = v && nodus_v2_msig_leg_open(&g_ms.x, v, &leg) == NODUS_V2_SPEND_OK;
    free(v);
    if (!ok) {
        nsw_ms_proposal_clear();
        return nsw_fail("This payment request is not for this vault.");
    }
    return 0;
}

const char *nsw_msig_prop_chain(void)   { return g_ms.has_export ? g_ms.chain_hex : ""; }
const char *nsw_msig_prop_tip(void)     { return g_ms.has_export ? g_ms.tip_dec : ""; }
const char *nsw_msig_prop_signers(void) { return g_ms.has_export ? g_ms.signers_dec : ""; }
const char *nsw_msig_prop_digest(void)  { return g_ms.has_export ? g_ms.digest_hex : ""; }
const char *nsw_msig_prop_env(void)     { return (g_ms.has_export && g_ms.prefix_hex) ? g_ms.prefix_hex : ""; }
/* nodus-cli's export text of the request in use, or the signature text of
 * the last nsw_msig_sign. */
const char *nsw_msig_text(void)         { return g_ms.text ? g_ms.text : ""; }

/* ── build: a new request from the vault's found coins ── */

int nsw_msig_build(const char *to_hex, const char *amount_dec) {
    if (nsw_begin() != 0) return -1;
    nsw_ms_proposal_clear();
    uint8_t to_raw[64];
    uint64_t amount = 0;
    if (!g_ms.has_desc) return nsw_end(nsw_fail("No vault is open."));
    if (qgp_fp_hex_to_raw(to_hex, to_raw) != 0)
        return nsw_end(nsw_fail("Enter a Nodus address: 128 characters, 0-9 and a-f."));
    if (nsw_parse_u64(amount_dec, &amount) != 0 || amount == 0)
        return nsw_end(nsw_fail("Enter an amount above zero."));
    if (!nsw_ms_is_member())
        return nsw_end(nsw_fail("Only a member of this vault can propose a "
                                "payment from it."));
    if (nsw_session_ok() != 0) return nsw_end(-1);
    if (nsw_check_chain() != 0) return nsw_end(-1);
    nsw_gen_t gen;
    if (nsw_select_generation(&gen) != 0) return nsw_end(-1);
    nodus_dnac_fee_info_t fi;
    memset(&fi, 0, sizeof(fi));
    int rc = nodus_client_dnac_fee_info(&g_client, &fi);
    if (rc != 0)
        return nsw_end(nsw_fail("The network fee is unknown (rc=%d). Nothing "
                                "was built.", rc));
    bool has_tip = false;
    uint64_t tip = 0;
    rc = nodus_client_dnac_supply_tip(&g_client, &has_tip, &tip);
    if (rc != 0 || !has_tip)
        return nsw_end(nsw_fail("The current Nodus block height is unknown "
                                "(rc=%d). Nothing was built.", rc));
    uint64_t expiry = 0;
    if (nsw_expiry_for(tip, &gen, &expiry) != 0) return nsw_end(-1);
    if (g_cancel) return nsw_end(-1);
    nodus_v2_ruleset_id_t rs;
    dna_meter_policy_t pol;
    if (nsw_ruleset(gen.gen, &rs, &pol) != 0) return nsw_end(-1);

    /* candidates: the found coins spendable in the next block (unlock <=
     * tip, the nsw_list filter), largest first (nodus-cli's only order) */
    nodus_v2_coin_t cand[NSW_MS_MAX_COINS];
    int n_cand = 0;
    for (int i = 0; i < g_ms.n_coins; i++) {
        if (g_ms.coins[i].unlock > tip) continue;
        memset(&cand[n_cand], 0, sizeof(cand[n_cand]));
        memcpy(cand[n_cand].nul, g_ms.coins[i].id, 64);
        cand[n_cand].amount = g_ms.coins[i].amount;
        n_cand++;
    }
    if (n_cand == 0 ||
        nodus_v2_spend_sort_coins(cand, n_cand,
                                  NODUS_V2_SPEND_ORDER_LARGEST_FIRST) != 0)
        return nsw_end(nsw_fail("This vault has no coins this page can use "
                                "yet. Nothing was built."));
    nodus_v2_msig_build_req_t req;
    nodus_v2_msig_built_t b;
    nodus_v2_spend_err_t e;
    memset(&b, 0, sizeof(b));
    rc = NODUS_V2_SPEND_ERR_INSUFFICIENT;
    uint64_t sum = 0;
    const int max_take = n_cand < (int)NODUS_V2_SPEND_MAX_IN
                       ? n_cand : (int)NODUS_V2_SPEND_MAX_IN;
    for (int take = 1; take <= max_take; take++) {
        if (sum > UINT64_MAX - cand[take - 1].amount) break;
        sum += cand[take - 1].amount;
        if (sum <= amount) continue;
        memset(&req, 0, sizeof(req));
        req.rs            = &rs;
        req.chain32       = g_net.chain;
        req.tip           = tip;
        req.expiry_height = expiry;
        req.desc          = g_ms.desc;
        req.desc_len      = g_ms.desc_len;
        req.coins         = cand;
        req.n_coins       = take;
        req.to_fp         = to_raw;
        req.amount        = amount;
        req.gas_price     = fi.gas_price;
        req.signers       = 0;                  /* K = M */
        req.rand          = nsw_rand_csprng;
        rc = nodus_v2_msig_build(&req, &b, &e);
        if (rc != NODUS_V2_SPEND_ERR_INSUFFICIENT) break;
    }
    if (rc == NODUS_V2_SPEND_ERR_INSUFFICIENT)
        return nsw_end(nsw_fail("This vault does not have enough coins this "
                                "page can use for that amount plus the "
                                "network fee. Nothing was built."));
    if (rc != NODUS_V2_SPEND_OK)
        return nsw_end(nsw_fail("The vault payment could not be built "
                                "(rc=%d). Nothing was built.", rc));
    memcpy(g_ms.x.chain32, g_net.chain, DNA_CHAIN_ID_LEN);
    g_ms.x.tip = tip;
    g_ms.x.signers = b.signers;
    memcpy(g_ms.x.digest, b.digest, 64);
    g_ms.x.env = b.env;                         /* ownership moves here */
    g_ms.x.env_len = b.env_len;
    b.env = NULL;
    nodus_v2_msig_built_free(&b);
    if (nsw_ms_export_fill() != 0 || nsw_ms_review_now(tip) != 0) {
        nsw_ms_proposal_clear();
        return nsw_end(-1);
    }
    return nsw_end(0);
}

/* ── review: at the node's current tip ── */

int nsw_msig_review(void) {
    if (nsw_begin() != 0) return -1;
    if (!g_ms.has_export) return nsw_end(nsw_fail("There is no payment request to review."));
    if (nsw_session_ok() != 0) return nsw_end(-1);
    bool has_tip = false;
    uint64_t tip = 0;
    int rc = nodus_client_dnac_supply_tip(&g_client, &has_tip, &tip);
    if (rc != 0 || !has_tip || tip == 0)
        return nsw_end(nsw_fail("The current Nodus block height is unknown "
                                "(rc=%d).", rc));
    return nsw_end(nsw_ms_review_now(tip));
}

int nsw_msig_rv_ok(void)                 { return g_ms.reviewed; }
int nsw_msig_rv_expired(void)            { return g_ms.reviewed ? g_ms.expired : 0; }
int nsw_msig_rv_member(void)             { return nsw_ms_is_member(); }
const char *nsw_msig_rv_vault(void)      { return g_ms.reviewed ? g_ms.addr_hex : ""; }
int nsw_msig_rv_m(void)                  { return g_ms.reviewed ? g_ms.rv.m : 0; }
int nsw_msig_rv_n(void)                  { return g_ms.reviewed ? g_ms.rv.n : 0; }
int nsw_msig_rv_k(void)                  { return g_ms.reviewed ? (int)g_ms.rv.signers : 0; }
const char *nsw_msig_rv_fee(void)        { return g_ms.reviewed ? nsw_ms_u64(g_ms.rv.fee) : ""; }
const char *nsw_msig_rv_expiry(void)     { return g_ms.reviewed ? nsw_ms_u64(g_ms.rv.expiry_height) : ""; }
const char *nsw_msig_rv_now(void)        { return g_ms.reviewed ? nsw_ms_u64(g_ms.now_tip) : ""; }
const char *nsw_msig_rv_intent(void) {
    static char hex[129];
    hex[0] = '\0';
    if (g_ms.reviewed) nsw_fmt_hex(g_ms.rv.intent_id, 64, hex);
    return hex;
}
int nsw_msig_rv_n_in(void)               { return g_ms.reviewed ? g_ms.rv.n_in : 0; }
const char *nsw_msig_rv_in(int i) {
    static char hex[129];
    hex[0] = '\0';
    if (g_ms.reviewed && i >= 0 && i < g_ms.rv.n_in)
        nsw_fmt_hex(g_ms.rv.in_nul[i], 64, hex);
    return hex;
}
int nsw_msig_rv_n_out(void)              { return g_ms.reviewed ? g_ms.rv.n_out : 0; }
static int nsw_ms_out_ok(int i)          { return g_ms.reviewed && i >= 0 && i < g_ms.rv.n_out; }
const char *nsw_msig_rv_out_owner(int i) { return nsw_ms_out_ok(i) ? g_ms.rv.out_owner[i] : ""; }
const char *nsw_msig_rv_out_amount(int i){ return nsw_ms_out_ok(i) ? nsw_ms_u64(g_ms.rv.out_amount[i]) : ""; }
/* 1 = this output returns to the vault itself (the change) */
int nsw_msig_rv_out_change(int i) {
    return nsw_ms_out_ok(i) && strncmp(g_ms.rv.out_owner[i], g_ms.addr_hex, 128) == 0;
}

/* ── sign: only what this module reviewed ── */

int nsw_msig_sign(void) {
    if (g_locked || g_cancel) return nsw_fail("Wallet is locked.");
    if (!g_ms.has_export || !g_ms.reviewed)
        return nsw_fail("Review the payment request first.");
    if (g_ms.expired)
        return nsw_fail("This payment request has expired. Ask for it to be "
                        "proposed again.");
    if (!nsw_ms_is_member())
        return nsw_fail("Only a member of this vault can approve its payments.");
    /* again, on the bytes about to be signed */
    nodus_v2_msig_review_t *again = calloc(1, sizeof(*again));
    dna_env_preflight_t *pf = calloc(1, sizeof(*pf));
    uint32_t cv = 0;
    uint8_t ch[64];
    int ok = again && pf && nsw_ms_core_tuple(&cv, ch) == 0 &&
             nodus_v2_msig_review(&g_ms.x, cv, ch, g_id.pk.bytes, pf, again) ==
                 NODUS_V2_SPEND_OK &&
             memcmp(again->digest, g_ms.rv.digest, 64) == 0 &&
             memcmp(again->addr, g_ms.addr, 64) == 0;
    /* F1 again, on the bytes about to be signed */
    const int owned = ok && nsw_ms_inputs_owned(again);
    free(again);
    free(pf);
    if (!ok) return nsw_fail("This payment request changed after it was "
                             "reviewed. Nothing was signed.");
    if (!owned) return nsw_fail(NSW_MS_NOT_OWNED);
    uint8_t sig[QGP_DSA87_SIGNATURE_BYTES];
    size_t sl = 0;
    if (qgp_dsa87_sign(sig, &sl, g_ms.x.digest, 64, g_id.sk.bytes) != 0 ||
        sl != sizeof(sig))
        return nsw_fail("Signing failed.");
    free(g_ms.text);
    g_ms.text = NULL;
    size_t tl = 0;
    int rc = nodus_v2_msig_sig_encode(g_ms.x.digest, g_id.pk.bytes, sig,
                                      &g_ms.text, &tl);
    nsw_wipe(sig, sizeof(sig));
    return rc == NODUS_V2_SPEND_OK ? 0 : nsw_fail("Out of memory.");
}

/* ── signatures: each checked on arrival ── */

void nsw_msig_sig_reset(void) {
    g_ms.n_sigs = 0;
    nsw_wipe(g_ms.sig_sig, sizeof(g_ms.sig_sig));
}

/* F2: an approval counts only once it is VERIFIED here, against the request
 * in use (digest equal, signer a member, ML-DSA-87 signature valid), and
 * only when it came from its own signer: `sender_hex` (the ID the Messages
 * item arrived from, or this wallet's own) must equal SHA3-512(its key).
 * Only verified approvals are kept, one per key — a forged approval for
 * key X is refused, it cannot shadow a later valid one from X. The cap
 * (NSW_MS_MAX_SIGS) applies to verified approvals only.
 * 0 = verified and kept, 1 = a verified approval from this key is already
 * held, -1 = refused (reason in nsw_error). */
int nsw_msig_sig_add(const char *text, const char *sender_hex) {
    if (!g_ms.has_export) return nsw_fail("There is no payment request.");
    uint8_t sender[64];
    if (nsw_parse_hex(sender_hex, sender, sizeof(sender)) != 0)
        return nsw_fail("This approval has no sender.");
    size_t len = text ? strnlen(text, NODUS_V2_MSIG_SIG_TEXT_MAX + 1) : 0;
    if (len == 0 || len > NODUS_V2_MSIG_SIG_TEXT_MAX)
        return nsw_fail("This approval is damaged.");
    static uint8_t dg[64], pk[NSW_PK_LEN], sig[QGP_DSA87_SIGNATURE_BYTES];
    if (nodus_v2_msig_sig_parse(text, len, dg, pk, sig) != NODUS_V2_SPEND_OK)
        return nsw_fail("This approval is damaged.");
    uint8_t fp[64];
    if (qgp_sha3_512(pk, NSW_PK_LEN, fp) != 0) return nsw_fail("Hash failure.");
    if (memcmp(fp, sender, 64) != 0)
        return nsw_fail("This approval was sent by someone other than the "
                        "member who signed it.");
    for (int i = 0; i < g_ms.n_sigs; i++)
        if (memcmp(g_ms.sig_pk[i], pk, NSW_PK_LEN) == 0) return 1;
    if (g_ms.n_sigs >= NSW_MS_MAX_SIGS) return nsw_fail("Too many approvals.");
    dna_env_view_t *v = calloc(1, sizeof(*v));
    nodus_v2_msig_leg_t leg;
    int rc = v ? nodus_v2_msig_leg_open(&g_ms.x, v, &leg) : NODUS_V2_SPEND_ERR_ALLOC;
    if (rc == NODUS_V2_SPEND_OK) rc = nodus_v2_msig_sig_check(&g_ms.x, &leg, dg, pk, sig);
    free(v);
    switch (rc) {
    case NODUS_V2_SPEND_OK: break;
    case NODUS_V2_MSIG_ERR_SIG_DIGEST:
        return nsw_fail("This approval is for a different payment.");
    case NODUS_V2_MSIG_ERR_NOT_MEMBER:
        return nsw_fail("This approval comes from someone who is not a "
                        "member of this vault.");
    case NODUS_V2_MSIG_ERR_SIG:
        return nsw_fail("This approval's signature is not valid.");
    default:
        return nsw_fail("This approval could not be checked (rc=%d).", rc);
    }
    const int i = g_ms.n_sigs;
    memcpy(g_ms.sig_dg[i], dg, 64);
    memcpy(g_ms.sig_pk[i], pk, NSW_PK_LEN);
    memcpy(g_ms.sig_sig[i], sig, sizeof(sig));
    qgp_fp_raw_to_hex(fp, g_ms.sig_fp[i]);
    g_ms.n_sigs++;
    return 0;
}

int nsw_msig_sig_count(void) { return g_ms.n_sigs; }
const char *nsw_msig_sig_signer(int i) {
    return (i >= 0 && i < g_ms.n_sigs) ? g_ms.sig_fp[i] : "";
}

/* ── submit: combine the first K approvals, then dnac_spend ──
 * 0 = accepted by the node's mempool CheckTx, 1 = refused (message in
 * nsw_error), -1 = not sent / no answer. */
int nsw_msig_submit(void) {
    if (nsw_begin() != 0) return -1;
    if (!g_ms.has_export || !g_ms.reviewed)
        return nsw_end(nsw_fail("Review the payment request first."));
    if (g_ms.expired)
        return nsw_end(nsw_fail("This payment request has expired. Ask for it "
                                "to be proposed again."));
    const int k = (int)g_ms.x.signers;
    if (g_ms.n_sigs < k)
        return nsw_end(nsw_fail("%d more approval(s) are needed.",
                                k - g_ms.n_sigs));
    uint32_t cv = 0;
    uint8_t ch[64];
    if (nsw_ms_core_tuple(&cv, ch) != 0) return nsw_end(-1);
    /* combine a COPY: a refusal leaves the request as it was */
    nodus_v2_msig_export_t xc = g_ms.x;
    xc.env = malloc(g_ms.x.env_len);
    dna_env_preflight_t *pf = calloc(1, sizeof(*pf));
    if (!xc.env || !pf) {
        free(xc.env);
        free(pf);
        return nsw_end(nsw_fail("Out of memory."));
    }
    memcpy(xc.env, g_ms.x.env, g_ms.x.env_len);
    int bad = -1;
    int rc = nodus_v2_msig_combine(
        &xc, cv, ch, (const uint8_t (*)[64])g_ms.sig_dg,
        (const uint8_t (*)[NODUS_V2_MSIG_PK_LEN])g_ms.sig_pk,
        (const uint8_t (*)[NODUS_V2_MSIG_SIG_LEN])g_ms.sig_sig, k, pf, &bad);
    if (rc != NODUS_V2_SPEND_OK) {
        rc = nsw_fail("The approvals could not be combined (rc=%d).", rc);
    } else if (nsw_session_ok() != 0) {
        rc = -1;
    } else {
        int approved = 0;
        nsw_fmt_hex(pf->intent_id, 64, g_ms.intent_hex);
        nsw_fmt_hex(pf->wire_id, 64, g_ms.wire_hex);
        int src = nsw_dnac_spend(pf->wire_id, xc.env, xc.env_len, &approved);
        if (src < 0)
            rc = -1;
        else if (src == NODUS_ERR_PROTOCOL_ERROR)
            rc = nsw_fail("The Nodus node refused this vault payment, or its "
                          "answer could not be read (code %d). Check the "
                          "vault history before sending again.", src);
        else if (src != 0)
            rc = nsw_fail("The Nodus node did not answer the submission "
                          "(rc=%d).", src);
        else if (!approved) {
            nsw_fail("The Nodus network refused this vault payment.");
            rc = 1;
        } else
            rc = 0;
    }
    nsw_wipe(xc.env, xc.env_len);
    free(xc.env);
    free(pf);
    return nsw_end(rc);
}

const char *nsw_msig_intent(void) { return g_ms.intent_hex; }
const char *nsw_msig_wire(void)   { return g_ms.wire_hex; }

#ifdef NODUS_SEND_TEST_FIXED_RANDOM
/* TEST-only (parity build, never shipped — build-nodus-send-wasm.sh
 * exports_test): the build and the read-back WITHOUT a node, so the vault
 * test (test/vaults.test.js) can pin them. The build is nsw_msig_build's
 * builder call with every network fact given (chain id, tip, gas price,
 * generation, expiry) and the output seeds from the test randomness
 * buffer; the read-back is nsw_ms_review_now at `now_dec`. */
int nsw_test_msig_build(const char *chain_hex, const char *tip_dec,
                        const char *gas_dec, int gen, const char *to_hex,
                        const char *amount_dec, const char *expiry_dec) {
    nsw_ms_proposal_clear();
    uint8_t chain[DNA_CHAIN_ID_LEN], to_raw[64];
    uint64_t tip = 0, gas = 0, amount = 0, expiry = 0;
    if (!g_ms.has_desc) return nsw_fail("No vault is open.");
    if (nsw_parse_hex(chain_hex, chain, sizeof(chain)) != 0 ||
        nsw_parse_u64(tip_dec, &tip) != 0 || tip == 0 ||
        nsw_parse_u64(gas_dec, &gas) != 0 || gen < 1 ||
        qgp_fp_hex_to_raw(to_hex, to_raw) != 0 ||
        nsw_parse_u64(amount_dec, &amount) != 0 || amount == 0 ||
        nsw_parse_u64(expiry_dec, &expiry) != 0)
        return nsw_fail("Invalid test build request.");
    nodus_v2_ruleset_id_t rs;
    dna_meter_policy_t pol;
    if (nsw_ruleset((uint32_t)gen, &rs, &pol) != 0) return -1;
    nodus_v2_coin_t cand[NSW_MS_MAX_COINS];
    for (int i = 0; i < g_ms.n_coins; i++) {
        memset(&cand[i], 0, sizeof(cand[i]));
        memcpy(cand[i].nul, g_ms.coins[i].id, 64);
        cand[i].amount = g_ms.coins[i].amount;
    }
    nodus_v2_msig_build_req_t req;
    memset(&req, 0, sizeof(req));
    req.rs = &rs;
    req.chain32 = chain;
    req.tip = tip;
    req.expiry_height = expiry;
    req.desc = g_ms.desc;
    req.desc_len = g_ms.desc_len;
    req.coins = cand;
    req.n_coins = g_ms.n_coins;
    req.to_fp = to_raw;
    req.amount = amount;
    req.gas_price = gas;
    req.rand = nsw_rand_csprng;            /* the test randomness buffer   */
    nodus_v2_msig_built_t b;
    nodus_v2_spend_err_t e;
    int rc = nodus_v2_msig_build(&req, &b, &e);
    if (rc != NODUS_V2_SPEND_OK) return nsw_fail("Test build refused (rc=%d).", rc);
    memcpy(g_ms.x.chain32, chain, sizeof(chain));
    g_ms.x.tip = tip;
    g_ms.x.signers = b.signers;
    memcpy(g_ms.x.digest, b.digest, 64);
    g_ms.x.env = b.env;
    g_ms.x.env_len = b.env_len;
    b.env = NULL;
    nodus_v2_msig_built_free(&b);
    if (nsw_ms_export_fill() != 0) { nsw_ms_proposal_clear(); return -1; }
    return 0;
}

/* One applied block item that consumed coin `id_hex` (and created nothing),
 * through the SAME bookkeeping a block read uses (nsw_ms_apply_item): a
 * genesis coin handed in by nsw_msig_coin_add leaves the set exactly like
 * a coin found in a block. */
int nsw_test_msig_consume(const char *id_hex, const char *height_dec) {
    static nodus_dnac_v3_item_t it;
    uint64_t h = 0;
    memset(&it, 0, sizeof(it));
    if (!g_ms.has_desc || nsw_parse_hex(id_hex, it.consumed[0], 64) != 0 ||
        nsw_parse_u64(height_dec, &h) != 0)
        return nsw_fail("Invalid test item.");
    it.kind = NODUS_DNAC_V3_KIND_ENVELOPE;
    it.code = 0;
    it.has_effects = true;
    it.has_intent_id = true;
    memset(it.intent_id, 0x77, 64);
    it.n_consumed = 1;
    g_ms.n_events = 0;
    nsw_ms_apply_item(h, &it);
    return 0;
}

/* A member identity from a 32-byte seed (the wallet's own derivation,
 * nodus_identity_from_seed), so the approval tests have real keys without
 * a node: its public key as hex, and nodus-cli's signature text over the
 * request in use's digest (hedged signature: the test randomness buffer
 * must hold 32 bytes per call). */
static char *g_test_out;

const char *nsw_test_msig_seed_pk(const char *seed_hex) {
    static nodus_identity_t id;
    uint8_t seed[32];
    free(g_test_out);
    g_test_out = NULL;
    if (nsw_parse_hex(seed_hex, seed, sizeof(seed)) != 0 ||
        nodus_identity_from_seed(seed, &id) != 0)
        return "";
    g_test_out = malloc(2 * NSW_PK_LEN + 1);
    if (!g_test_out) return "";
    nsw_fmt_hex(id.pk.bytes, NSW_PK_LEN, g_test_out);
    nsw_wipe(&id, sizeof(id));
    return g_test_out;
}

const char *nsw_test_msig_seed_sign(const char *seed_hex) {
    static nodus_identity_t id;
    uint8_t seed[32], sig[QGP_DSA87_SIGNATURE_BYTES];
    size_t sl = 0, tl = 0;
    free(g_test_out);
    g_test_out = NULL;
    if (!g_ms.has_export || nsw_parse_hex(seed_hex, seed, sizeof(seed)) != 0 ||
        nodus_identity_from_seed(seed, &id) != 0)
        return "";
    if (qgp_dsa87_sign(sig, &sl, g_ms.x.digest, 64, id.sk.bytes) != 0 ||
        sl != sizeof(sig) ||
        nodus_v2_msig_sig_encode(g_ms.x.digest, id.pk.bytes, sig, &g_test_out,
                                 &tl) != NODUS_V2_SPEND_OK)
        g_test_out = NULL;
    nsw_wipe(&id, sizeof(id));
    return g_test_out ? g_test_out : "";
}

int nsw_test_msig_review(const char *now_dec) {
    uint64_t now = 0;
    if (nsw_parse_u64(now_dec, &now) != 0) return nsw_fail("Invalid height.");
    return nsw_ms_review_now(now);
}
#endif

/* ═══ SMART CONTRACTS — the EVM domain (Nodus EVM) ════════════════════════
 *
 * Design docs/plans/2026-10-04-nodus-evm-chain-integration-design.md rev 3 §2
 * (envelope = [CORE EVMFUND leg, op 9] + [EVM leg, domain 2, ops 1-5];
 * EVM sender = SHA3-512(ML-DSA-87 pk)[0..32]; the fee is a CORE-funded
 * DECLARED ceiling: res_max_total_units >= static units + gas_limit × w_gas
 * + FAIL_RESERVE for CALL/CREATE, fee >= units × gas price), §5 (q = 10^10),
 * §16 (wallet). Decisions 2026-10-04-nodus-evm-kurultay-k1.md (operator 1, 3,
 * 4) and 2026-10-04-nodus-evm-kurultay-k2-summary.md (operator 2: one pending
 * EVM transaction per sender — the wallet's queue, src/evm/contract.js).
 *
 * The envelope is built by the SHARED builder nodus-cli `evm` uses
 * (nodus/src/client/nodus_v2_evm.c, Nodus EVM Faz 4 — this file's former
 * nsw_evm_core / nsw_evm_min_units moved there): a transfer section
 * funded by this wallet's listed coins (ascending by nullifier until the
 * sum covers lock + fee, change seeded from the input nullifiers), the
 * EXACT funding / bridge effect declarations and the per-role read count
 * of the node (CORE EVMFUND reads in_count + 1, + the reserve for DEPOSIT /
 * RELEASE), two kind-1 legs signed by this ONE key, then the bytes are
 * decoded back and compared with the request before anything is kept.
 * The call bytes are shared/dnac/evm_call_wire.c — the codec the node
 * itself decodes with.
 *
 * THE EVM LEG'S RULESET IDENTITY is the compiled EVM generation's
 * (nodus_witness_runtime.h NODUS_RT_EVM_RULESET_VERSION_GEVM /
 * NODUS_RT_EVM_RULESET_HASH_GEVM_INIT — the bytes the node's table pins);
 * the network setting (nsw_evm_net_set, src/nodus/send-module.js
 * NODUS_EVM_NETWORK) must equal it, or smart contracts stay off. The
 * rule-set generation is the node's answer (nsw_select_generation): the
 * EVM generation's pinned SYSTEM policy weighs CORE op 9
 * (nodus_ruleset_pins.h G3); an older generation does not, and the meter
 * plan refuses (DNA_METER_ERR_OP_WEIGHT) — fail closed, no default weight.
 * READS (design §18): nsw_evm_query — one evm_* request on this session,
 * the reply map as JSON (nodus_client_dnac_query_raw).
 * Networked builds only (not in the native vector). */

/* EVM op ids and widths: the shared codec restates the node's constants
 * (nodus_witness_rt_evm.h) — pinned equal here, where both are visible. */
_Static_assert(DNA_EVM_OP_CALL == NODUS_RT_EVM_CALL &&
               DNA_EVM_OP_CREATE == NODUS_RT_EVM_CREATE &&
               DNA_EVM_OP_DEPOSIT == NODUS_RT_EVM_DEPOSIT &&
               DNA_EVM_OP_WITHDRAW == NODUS_RT_EVM_WITHDRAW &&
               DNA_EVM_OP_REDEEM == NODUS_RT_EVM_REDEEM,
               "EVM runtime op ids");
_Static_assert(DNA_EVM_CALL_VER == NODUS_RT_EVM_CALL_VER, "EVM call ver");
_Static_assert(DNA_EVM_Q == NODUS_RT_EVM_Q, "wei per raw unit");
_Static_assert(DNA_EVM_MAX_INITCODE == EVM_MAX_INITCODE_SIZE,
               "the EIP-3860 initcode cap of the engine");
_Static_assert(DNA_EVMFUND_OUT_LEN == NODUS_V2_SPEND_OUT_LEN &&
               DNA_EVMFUND_MAX_IN == NODUS_V2_SPEND_MAX_IN,
               "the funding section is a transfer section");

#define NSW_EVM_ACCESS_MAX        16384u
#define NSW_EVM_DATA_MAX          ((uint32_t)DNA_ENV_MAX_TOTAL_LEN)

/* the EVM leg's ruleset identity (a network setting — see above; it must
 * equal the compiled EVM generation's) */
static struct {
    int      has;
    uint32_t version;
    uint8_t  hash[64];
} g_evm_rs;

static const uint8_t NSW_EVM_RS_HASH[64] = NODUS_RT_EVM_RULESET_HASH_GEVM_INIT;

/* the request: contract data / initcode, access list, declaration, and
 * the node's evm_estimate answer (ue at ge) the read units come from */
static struct {
    uint8_t *data;
    uint32_t data_len;
    uint8_t  access[NSW_EVM_ACCESS_MAX];
    size_t   access_len;
    uint16_t n_access;
    uint64_t n_access_keys;              /* storage keys over all entries */
    uint32_t effects, effect_bytes;      /* 0 = the builder's default */
    uint64_t est_units, est_gas;         /* 0 = none                   */
} g_evm_req;

/* what was read back from the last EVM envelope (valid only while it is
 * g_built's envelope — nsw_evm_built_ok) */
static struct {
    int      valid;
    uint8_t  intent[64];
    int      op;
    char     to[65], value[65], ticket[129], dest[129];
    char     gas[NSW_U64_DEC], nonce[NSW_U64_DEC], units[NSW_U64_DEC],
             amount[NSW_U64_DEC];
    char     created[65];                /* CREATE: the address it deploys */
    uint32_t data_len;
} g_evm_built;

static int nsw_evm_built_ok(void) {
    return g_evm_built.valid && g_built.env &&
           memcmp(g_evm_built.intent, g_built.intent_id, 64) == 0;
}
int nsw_evm_built_op(void)            { return nsw_evm_built_ok() ? g_evm_built.op : 0; }
const char *nsw_evm_built_to(void)    { return nsw_evm_built_ok() ? g_evm_built.to : ""; }
const char *nsw_evm_built_value(void) { return nsw_evm_built_ok() ? g_evm_built.value : ""; }
const char *nsw_evm_built_gas(void)   { return nsw_evm_built_ok() ? g_evm_built.gas : ""; }
const char *nsw_evm_built_nonce(void) { return nsw_evm_built_ok() ? g_evm_built.nonce : ""; }
const char *nsw_evm_built_units(void) { return nsw_evm_built_ok() ? g_evm_built.units : ""; }
const char *nsw_evm_built_amount(void){ return nsw_evm_built_ok() ? g_evm_built.amount : ""; }
const char *nsw_evm_built_dest(void)  { return nsw_evm_built_ok() ? g_evm_built.dest : ""; }
const char *nsw_evm_built_ticket(void){ return nsw_evm_built_ok() ? g_evm_built.ticket : ""; }
int nsw_evm_built_data_len(void) {
    return nsw_evm_built_ok() ? (int)g_evm_built.data_len : -1;
}
/* A CREATE: the 32-byte address (64 hex) it deploys to, derived from the
 * SIGNED envelope's EVM sender (SHA3-512(pk)[0..32]) and its read-back
 * nonce with the shared rule (nodus_v2_evm_create_address — the engine's
 * evm_compute_contract_address in 32-byte mode). A receipt's "cr" that
 * differs from it is the connected node's error, not this transaction's
 * contract (red-team 1 F11). "" for every other op. */
const char *nsw_evm_built_created(void) {
    return nsw_evm_built_ok() ? g_evm_built.created : "";
}

/* ── settings and request ── */

/* The EVM leg's ruleset identity: version (decimal) and its 64-byte hash
 * (128 lowercase hex). Set once, before unlock (like the network
 * settings). It must equal the compiled EVM generation's identity
 * (nodus_witness_runtime.h NODUS_RT_EVM_RULESET_*_GEVM) — a page whose
 * setting differs from the rules it was built with offers no smart
 * contracts. */
int nsw_evm_net_set(const char *version_dec, const char *hash_hex) {
    uint64_t v = 0;
    uint8_t h[64];
    if (g_used) return nsw_fail("Settings are fixed once the wallet is open.");
    if (nsw_parse_u64(version_dec, &v) != 0 || v == 0 || v > UINT32_MAX ||
        nsw_parse_hex(hash_hex, h, sizeof(h)) != 0)
        return nsw_fail("Invalid smart-contract network setting.");
    if (v != NODUS_RT_EVM_RULESET_VERSION_GEVM ||
        memcmp(h, NSW_EVM_RS_HASH, 64) != 0)
        return nsw_fail("The smart-contract setting does not match the "
                        "rules this page was built with.");
    g_evm_rs.version = (uint32_t)v;
    memcpy(g_evm_rs.hash, h, 64);
    g_evm_rs.has = 1;
    return 0;
}

int nsw_evm_available(void) { return g_evm_rs.has; }

/* The rule-set generation that carries the EVM (nodus_witness_runtime.h
 * NODUS_RT_GEN_EVM): a node whose dnac_ruleset_info names an older one has
 * not voted the EVM in (src/nodus/client.js hides the panel then). */
int nsw_evm_generation(void) { return (int)NODUS_RT_GEN_EVM; }

/* The node's evm_estimate answer for the NEXT CALL / CREATE build: its
 * `ue` and `ge` (decimal; "0", "0" = none). The build adds the read units
 * it implies (ue − the reference shape's units at ge, client/nodus_v2_evm.h
 * "UNITS") to the minimum of its own shape. The answer is ONE node's: a
 * ge outside 1..EVM_TX_GAS_CAP is refused here, and the read units it
 * implies are checked against the engine's read cap in nsw_evm_core
 * (red-team 1 F9 — refused, never clamped). `gu` ≤ ge is checked by the
 * caller, which holds the reply (src/evm/contract.js). */
int nsw_evm_set_estimate(const char *units_dec, const char *gas_dec) {
    uint64_t u = 0, g = 0;
    if (nsw_parse_u64(units_dec, &u) != 0 || nsw_parse_u64(gas_dec, &g) != 0 ||
        (u != 0 && (g == 0 || g > NODUS_RT_EVM_TX_GAS_CAP)))
        return nsw_fail("Invalid smart-contract estimate.");
    g_evm_req.est_units = u;
    g_evm_req.est_gas = g;
    return 0;
}

/* The contract data (CALL) or initcode (CREATE) of the next build: a
 * buffer of `len` bytes the caller fills; len 0 = none. NULL on refusal
 * (or for len 0). */
uint8_t *nsw_evm_data_alloc(int len) {
    if (g_evm_req.data) {
        nsw_wipe(g_evm_req.data, g_evm_req.data_len);
        free(g_evm_req.data);
    }
    g_evm_req.data = NULL;
    g_evm_req.data_len = 0;
    if (len <= 0 || (uint32_t)len > NSW_EVM_DATA_MAX) return NULL;
    g_evm_req.data = calloc(1, (size_t)len);
    if (g_evm_req.data) g_evm_req.data_len = (uint32_t)len;
    return g_evm_req.data;
}

void nsw_evm_access_reset(void) {
    memset(g_evm_req.access, 0, sizeof(g_evm_req.access));
    g_evm_req.access_len = 0;
    g_evm_req.n_access = 0;
    g_evm_req.n_access_keys = 0;
}

/* One access-list entry: a 32-byte address (64 hex) and its storage keys
 * as concatenated 64-hex words ("" for none). */
int nsw_evm_access_add(const char *addr_hex, const char *keys_hex) {
    uint8_t addr[32];
    static uint8_t keys[NSW_EVM_ACCESS_MAX];
    size_t klen = 0;
    if (nsw_parse_hex(addr_hex, addr, sizeof(addr)) != 0)
        return nsw_fail("Invalid address in the access list.");
    if (keys_hex && keys_hex[0] &&
        (nsw_parse_hex_var(keys_hex, keys, sizeof(keys), &klen) != 0 ||
         klen % 32 != 0 || klen / 32 > 0xFFFFu))
        return nsw_fail("Invalid storage key in the access list.");
    if (g_evm_req.n_access == 0xFFFFu ||
        dna_evm_access_put(g_evm_req.access, sizeof(g_evm_req.access),
                           &g_evm_req.access_len, addr, (uint16_t)(klen / 32),
                           keys) != 0)
        return nsw_fail("The access list is too long.");
    g_evm_req.n_access++;
    g_evm_req.n_access_keys += klen / 32;
    return 0;
}

/* The EVM leg's declared effect ceilings for CALL / CREATE (0, 0 = the
 * default). They must carry the fixed failure result and stay within the
 * streamed-leg caps (res_meter.h DNA_METER_EVM_FAIL_*, DNA_METER_STREAM_*);
 * every declared effect and byte is paid for in the fee ceiling. */
int nsw_evm_set_decl(int effects, int effect_bytes) {
    if (effects == 0 && effect_bytes == 0) {
        g_evm_req.effects = g_evm_req.effect_bytes = 0;
        return 0;
    }
    if (effects < (int)DNA_METER_EVM_FAIL_EFFECTS ||
        (uint32_t)effects > DNA_METER_STREAM_MAX_EFFECTS ||
        effect_bytes < (int)DNA_METER_EVM_FAIL_BYTES ||
        (uint32_t)effect_bytes > DNA_METER_STREAM_MAX_EFFECT_BYTES)
        return nsw_fail("Invalid effect ceiling for a smart-contract call.");
    g_evm_req.effects = (uint32_t)effects;
    g_evm_req.effect_bytes = (uint32_t)effect_bytes;
    return 0;
}

/* ── the build ── */

/*
 * Build + sign + read back ONE EVM envelope from g_req_coins through the
 * shared builder (nodus_v2_evm_build). `call`: the EVM leg (op and its
 * scalars; data and access list come from g_evm_req). `units_req`: the
 * declared unit ceiling — 0 = the smallest the node accepts for THIS
 * envelope's shape plus, for a CALL / CREATE, the read units the node's
 * evm_estimate implies (nsw_evm_set_estimate). `expiry` is checked by the
 * caller (nsw_expiry_check). On success g_built + g_evm_built hold the
 * envelope and the fields read back from its bytes. Large structs are
 * heap; this runs after every network wait.
 */
static int nsw_evm_core(const uint8_t *pk, const uint8_t *sk,
                        const uint8_t chain32[DNA_CHAIN_ID_LEN],
                        uint64_t tip, uint64_t gas_price,
                        const nodus_v2_ruleset_id_t *rs, uint32_t evm_version,
                        const uint8_t evm_hash[64], dna_evm_call_t *call,
                        uint64_t units_req, uint64_t expiry) {
    nsw_built_clear();
    memset(&g_evm_built, 0, sizeof(g_evm_built));
    const uint32_t op = call->op;
    const int is_vm = op == DNA_EVM_OP_CALL || op == DNA_EVM_OP_CREATE;
    if (is_vm) {
        call->data = g_evm_req.data;
        call->data_len = g_evm_req.data_len;
        call->access = g_evm_req.access_len ? g_evm_req.access : NULL;
        call->access_len = g_evm_req.access_len;
        call->n_access = g_evm_req.n_access;
    } else if (g_evm_req.data_len || g_evm_req.n_access) {
        return nsw_fail("Contract data was given for a transfer; nothing "
                        "was built.");
    }
    if (g_req_n < 1) return nsw_fail("Insufficient NODUS balance.");

    /* the read units of a CALL / CREATE: the node's evm_estimate `ue` minus
     * the reference shape's units at its `ge` (client/nodus_v2_evm.h
     * "UNITS") — the same function the node priced `ue` with. `ue` is ONE
     * node's answer, so it is REFUSED (never clamped — red-team 1 F9) unless
     *   0 <= ue − ref <= (EVM_READS_BASE + 2 × access-list keys) × w_read
     * — the engine's logical-read cap of one leg (nodus_witness_runtime.h
     * NODUS_RT_EVM_READS_BASE; nodus_witness_rt_evm.c fixes max_reads =
     * READS_BASE + 2 × n_access_keys), each read charged w_read of the
     * generation's SYSTEM policy (the node's estimate multiplies by the same
     * weight, nodus_witness_handlers.c evm_estimate). A node that answers
     * more reads than any leg may make is asking for a fee no execution can
     * use. */
    uint64_t read_units = 0;
    if (is_vm && units_req == 0 && g_evm_req.est_units != 0) {
        uint64_t ref = 0, cap_reads = 0, cap_units = 0;
        if (nodus_v2_evm_ref_units(rs->meter_policy, rs->core_ruleset_version,
                                   op, call->data_len, g_evm_req.est_gas,
                                   &ref) != NODUS_V2_SPEND_OK)
            return nsw_fail("Smart contracts are not available under the "
                            "network's current transaction rules. Nothing "
                            "was built.");
        if (g_evm_req.est_units < ref)
            return nsw_fail("The network's estimate for this transaction is "
                            "malformed (its resource ceiling is below the "
                            "smallest one possible). Nothing was built.");
        read_units = g_evm_req.est_units - ref;
        if (dna_ck_mul_u64(2u, g_evm_req.n_access_keys, &cap_reads) != 0 ||
            dna_ck_add_u64(NODUS_RT_EVM_READS_BASE, cap_reads,
                           &cap_reads) != 0 ||
            dna_ck_mul_u64(cap_reads, rs->meter_policy->w_read,
                           &cap_units) != 0 ||
            read_units > cap_units)
            return nsw_fail("The network's estimate for this transaction is "
                            "malformed (it asks for more reads than a "
                            "transaction may make). Nothing was built.");
    }

    nodus_v2_evm_req_t req;
    memset(&req, 0, sizeof(req));
    req.rs                  = rs;
    req.evm_ruleset_version = evm_version;
    req.evm_ruleset_hash    = evm_hash;
    req.chain32             = chain32;
    req.tip                 = tip;
    req.expiry_height       = expiry;
    req.gas_price           = gas_price;
    req.pk                  = pk;
    req.sk                  = sk;
    req.call                = *call;
    req.effects             = g_evm_req.effects;
    req.effect_bytes        = g_evm_req.effect_bytes;
    req.units               = units_req;
    req.evm_read_units      = read_units;
    req.coins               = g_req_coins;
    req.n_coins             = g_req_n;
    nodus_v2_evm_built_t *b = calloc(1, sizeof(*b));
    if (!b) return nsw_fail("Out of memory.");
    nodus_v2_evm_err_t err;
    int brc = nodus_v2_evm_build(&req, b, &err);
    if (brc != NODUS_V2_SPEND_OK) {
        int rc;
        switch (brc) {
        case NODUS_V2_EVM_ERR_GAS:
            rc = nsw_fail("The gas limit must be between 1 and %llu.",
                          (unsigned long long)NODUS_RT_EVM_TX_GAS_CAP);
            break;
        case NODUS_V2_EVM_ERR_NO_CODE:
            rc = nsw_fail("A contract deployment needs its bytecode.");
            break;
        case NODUS_V2_EVM_ERR_AMOUNT:
            rc = nsw_fail("Enter an amount above zero.");
            break;
        case NODUS_V2_EVM_ERR_BRIDGE_DATA:
            rc = nsw_fail("Contract data was given for a transfer; nothing "
                          "was built.");
            break;
        case NODUS_V2_EVM_ERR_DECL:
            rc = nsw_fail("Invalid effect ceiling for a smart-contract call.");
            break;
        case NODUS_V2_EVM_ERR_OP_WEIGHT:
            rc = nsw_fail("Smart contracts are not available under the "
                          "network's current transaction rules. Nothing was "
                          "built.");
            break;
        case NODUS_V2_SPEND_ERR_METER:
            rc = nsw_fail("The smart-contract transaction could not be priced "
                          "(meter %d).", err.meter_status);
            break;
        case NODUS_V2_EVM_ERR_UNITS_LOW:
            rc = nsw_fail("The declared resource ceiling %llu is below this "
                          "transaction's minimum of %llu. Nothing was built.",
                          (unsigned long long)err.units,
                          (unsigned long long)err.min_units);
            break;
        case NODUS_V2_SPEND_ERR_INSUFFICIENT:
            rc = nsw_fail("Insufficient NODUS balance.");
            break;
        case NODUS_V2_SPEND_ERR_MAX_INPUTS:
            rc = nsw_fail("This amount needs more than 15 coins; send less or "
                          "combine coins first.");
            break;
        case NODUS_V2_SPEND_ERR_OVERFLOW:
        case NODUS_V2_SPEND_ERR_INPUT_SUM:
            rc = nsw_fail("Amount is out of range.");
            break;
        case NODUS_V2_SPEND_ERR_GAS_OVERFLOW:
            rc = nsw_fail("The network fee is out of range.");
            break;
        case NODUS_V2_SPEND_ERR_FEE_UNSETTLED:
            rc = nsw_fail("The network fee could not be settled.");
            break;
        case NODUS_V2_SPEND_ERR_ENCODE:
            rc = nsw_fail("The smart-contract call could not be encoded.");
            break;
        case NODUS_V2_SPEND_ERR_SIGN:
        case NODUS_V2_SPEND_ERR_PREFLIGHT1:
        case NODUS_V2_SPEND_ERR_PREFLIGHT2:
            rc = nsw_fail("The transaction could not be signed (rc=%d, leg "
                          "%d).", brc, err.leg);
            break;
        case NODUS_V2_EVM_ERR_MISMATCH:
            rc = nsw_fail("The built transaction does not match the request; "
                          "nothing was signed for sending.");
            break;
        default:
            rc = nsw_fail("The smart-contract transaction could not be built "
                          "(rc=%d).", brc);
            break;
        }
        free(b);
        return rc;
    }

    /* ── keep what was BUILT (read back from its bytes by the builder) ── */
    const dna_evm_call_t *dec = &b->dec;
    uint8_t own_raw[64];
    char own_hex[129];
    if (qgp_sha3_512(pk, NSW_PK_LEN, own_raw) != 0) {
        nodus_v2_evm_built_free(b);
        free(b);
        return nsw_fail("The transaction could not be built (hash).");
    }
    nsw_fmt_hex(own_raw, 64, own_hex);
    g_built.env = b->env;                    /* ownership moves here */
    g_built.env_len = b->env_len;
    b->env = NULL;
    memcpy(g_built.wire_id, b->wire_id, 64);
    memcpy(g_built.intent_id, b->intent_id, 64);
    nsw_fmt_hex(b->intent_id, 64, g_built.intent_hex);
    nsw_fmt_hex(b->wire_id, 64, g_built.wire_hex);
    nsw_fmt_hex(chain32, DNA_CHAIN_ID_LEN, g_built.chain_hex);
    nsw_fmt_u64(b->fee, g_built.fee);
    nsw_fmt_u64(b->change, g_built.change);
    nsw_fmt_u64(expiry, g_built.expiry);
    g_built.n_in = b->n_in;
    for (int i = 0; i < b->n_in; i++)
        nsw_fmt_hex(b->in_nul[i], 64, g_built.in_hex[i]);
    g_built.op = 0;
    /* recipient: the fingerprint value leaves to (WITHDRAW / REDEEM), or
     * this wallet's own (DEPOSIT: the EVM address is derived from it);
     * "" for a contract call / deployment (its target is evm_built_to) */
    if (op == DNA_EVM_OP_WITHDRAW || op == DNA_EVM_OP_REDEEM)
        nsw_fmt_hex(dec->dest_fp, 64, g_built.recipient);
    else if (op == DNA_EVM_OP_DEPOSIT)
        memcpy(g_built.recipient, own_hex, 129);
    nsw_fmt_u64(is_vm ? 0 : dec->amount_raw, g_built.amount);

    memcpy(g_evm_built.intent, b->intent_id, 64);
    g_evm_built.op = (int)op;
    /* `dec` points into the envelope bytes, which g_built now owns */
    if (op == DNA_EVM_OP_CALL) nsw_fmt_hex(dec->to, 32, g_evm_built.to);
    if (is_vm) {
        nsw_fmt_hex(dec->value_wei, 32, g_evm_built.value);
        nsw_fmt_u64(dec->gas_limit, g_evm_built.gas);
        g_evm_built.data_len = dec->data_len;
    }
    if (op != DNA_EVM_OP_REDEEM) nsw_fmt_u64(dec->nonce, g_evm_built.nonce);
    if (op == DNA_EVM_OP_CREATE) {
        /* the EVM sender is SHA3-512(pk)[0..32] (design §2), the nonce the
         * one read back from the signed bytes */
        uint8_t created[32];
        if (nodus_v2_evm_create_address(own_raw, dec->nonce, created) != 0) {
            memset(&g_evm_built, 0, sizeof(g_evm_built));
            nsw_built_clear();
            nodus_v2_evm_built_free(b);
            free(b);
            return nsw_fail("The transaction could not be built (hash).");
        }
        nsw_fmt_hex(created, 32, g_evm_built.created);
    }
    if (!is_vm) nsw_fmt_u64(dec->amount_raw, g_evm_built.amount);
    if (op == DNA_EVM_OP_WITHDRAW || op == DNA_EVM_OP_REDEEM)
        nsw_fmt_hex(dec->dest_fp, 64, g_evm_built.dest);
    if (op == DNA_EVM_OP_REDEEM) nsw_fmt_hex(dec->ticket_id, 64, g_evm_built.ticket);
    nsw_fmt_u64(b->units, g_evm_built.units);
    g_evm_built.valid = 1;
    nodus_v2_evm_built_free(b);              /* env already moved: NULL  */
    free(b);
    return 0;
}
/* The networked build of every EVM op: the candidates must come from the
 * LAST listing; chain id, rule-set generation and gas price are read on
 * this session (as nsw_build_and_sign). */
static int nsw_evm_net(dna_evm_call_t *call, const char *units_dec,
                       const char *expiry_dec) {
    if (nsw_begin() != 0) return -1;
    nsw_built_clear();
    uint64_t units = 0, expiry = 0;
    if (nsw_parse_u64(units_dec, &units) != 0)
        return nsw_end(nsw_fail("Invalid resource ceiling."));
    if (nsw_parse_u64(expiry_dec, &expiry) != 0)
        return nsw_end(nsw_fail("Invalid validity height."));
    if (!g_evm_rs.has)
        return nsw_end(nsw_fail("Smart contracts are not available on this "
                                "network yet. Nothing was built."));
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
            return nsw_end(nsw_fail("The request names a coin that is not "
                                    "in your current coin list."));
    }
    if (nsw_session_ok() != 0) return nsw_end(-1);
    if (nsw_check_chain() != 0) return nsw_end(-1);
    nsw_gen_t gen;
    if (nsw_select_generation(&gen) != 0) return nsw_end(-1);
    nodus_dnac_fee_info_t fi;
    memset(&fi, 0, sizeof(fi));
    int rc = nodus_client_dnac_fee_info(&g_client, &fi);
    if (rc != 0)
        return nsw_end(nsw_fail("The network fee is unknown (rc=%d). Nothing "
                                "was built.", rc));
    if (g_cancel) return nsw_end(-1);
    if (nsw_expiry_check(g_list.tip, &gen, expiry) != 0) return nsw_end(-1);
    nodus_v2_ruleset_id_t rs;
    dna_meter_policy_t *pol = calloc(1, sizeof(*pol));
    if (!pol) return nsw_end(nsw_fail("Out of memory."));
    rc = nsw_ruleset(gen.gen, &rs, pol);
    if (rc == 0)
        rc = nsw_evm_core(g_id.pk.bytes, g_id.sk.bytes, g_net.chain,
                          g_list.tip, fi.gas_price, &rs, g_evm_rs.version,
                          g_evm_rs.hash, call, units, expiry);
    free(pol);
    return nsw_end(rc);
}

/* The five operations (design §2). value_hex: 64 lowercase hex (u256 wei,
 * big-endian); addresses 64 hex; fingerprints / ticket ids 128 hex;
 * amounts, gas, nonce, units and expiry decimal. */
int nsw_evm_call(const char *to_hex, const char *value_hex,
                 const char *gas_dec, const char *nonce_dec,
                 const char *units_dec, const char *expiry_dec) {
    dna_evm_call_t c;
    memset(&c, 0, sizeof(c));
    c.op = DNA_EVM_OP_CALL;
    if (nsw_parse_hex(to_hex, c.to, 32) != 0)
        return nsw_fail("Enter a contract address: 64 characters, 0-9 and a-f.");
    if (nsw_parse_hex(value_hex, c.value_wei, 32) != 0 ||
        nsw_parse_u64(gas_dec, &c.gas_limit) != 0 ||
        nsw_parse_u64(nonce_dec, &c.nonce) != 0)
        return nsw_fail("Invalid smart-contract call.");
    return nsw_evm_net(&c, units_dec, expiry_dec);
}

int nsw_evm_create(const char *value_hex, const char *gas_dec,
                   const char *nonce_dec, const char *units_dec,
                   const char *expiry_dec) {
    dna_evm_call_t c;
    memset(&c, 0, sizeof(c));
    c.op = DNA_EVM_OP_CREATE;
    if (nsw_parse_hex(value_hex, c.value_wei, 32) != 0 ||
        nsw_parse_u64(gas_dec, &c.gas_limit) != 0 ||
        nsw_parse_u64(nonce_dec, &c.nonce) != 0)
        return nsw_fail("Invalid contract deployment.");
    return nsw_evm_net(&c, units_dec, expiry_dec);
}

int nsw_evm_deposit(const char *amount_dec, const char *nonce_dec,
                    const char *units_dec, const char *expiry_dec) {
    dna_evm_call_t c;
    memset(&c, 0, sizeof(c));
    c.op = DNA_EVM_OP_DEPOSIT;
    if (nsw_parse_u64(amount_dec, &c.amount_raw) != 0 ||
        nsw_parse_u64(nonce_dec, &c.nonce) != 0)
        return nsw_fail("Invalid amount.");
    return nsw_evm_net(&c, units_dec, expiry_dec);
}

int nsw_evm_withdraw(const char *amount_dec, const char *nonce_dec,
                     const char *dest_hex, const char *units_dec,
                     const char *expiry_dec) {
    dna_evm_call_t c;
    memset(&c, 0, sizeof(c));
    c.op = DNA_EVM_OP_WITHDRAW;
    if (qgp_fp_hex_to_raw(dest_hex, c.dest_fp) != 0)
        return nsw_fail("Enter a Nodus address: 128 characters, 0-9 and a-f.");
    if (nsw_parse_u64(amount_dec, &c.amount_raw) != 0 ||
        nsw_parse_u64(nonce_dec, &c.nonce) != 0)
        return nsw_fail("Invalid amount.");
    return nsw_evm_net(&c, units_dec, expiry_dec);
}

int nsw_evm_redeem(const char *ticket_hex, const char *amount_dec,
                   const char *dest_hex, const char *units_dec,
                   const char *expiry_dec) {
    dna_evm_call_t c;
    memset(&c, 0, sizeof(c));
    c.op = DNA_EVM_OP_REDEEM;
    if (nsw_parse_hex(ticket_hex, c.ticket_id, 64) != 0)
        return nsw_fail("Invalid withdrawal ticket.");
    if (qgp_fp_hex_to_raw(dest_hex, c.dest_fp) != 0)
        return nsw_fail("Enter a Nodus address: 128 characters, 0-9 and a-f.");
    if (nsw_parse_u64(amount_dec, &c.amount_raw) != 0)
        return nsw_fail("Invalid amount.");
    return nsw_evm_net(&c, units_dec, expiry_dec);
}

/* ── the §18 reads (design docs/plans/2026-10-04-nodus-evm-chain-integration-
 *    design.md rev 3 §18): ONE evm_* request on this session, its reply
 *    map handed to JS as JSON (src/evm/rpc.js checks it) ─────────────────
 *
 * The request's arguments cross as TEXT in module memory (nsw_evm_query_buf
 * — call data can be far larger than a ccall string argument's stack copy):
 *   key=t:value[;key=t:value...]   key [a-z0-9]{1,4}; t "b" (value =
 *   lowercase hex bytes), "u" (value = a decimal u64) or "U" (value = 1..3
 *   decimal u64 joined by ",", each under the "u" rules → a CBOR array of
 *   uints; the evm_logs cursor "c" = [h, x, li], red-team 1 F4).
 * The reply map → JSON: unsigned integer → decimal string, byte string →
 * lowercase hex string, text → JSON string, bool, null, array, map →
 * object (text keys only). Nesting is bounded (NSW_EVM_JSON_DEPTH). */

#define NSW_EVM_QUERY_MAX   ((size_t)4 * 1024 * 1024)   /* args text     */
#define NSW_EVM_JSON_DEPTH  8
#define NSW_EVM_ARG_ARRAY_MAX 3                         /* "U" elements  */

static char  *g_eq_args;
static size_t g_eq_args_cap;
static char  *g_eq_json;

typedef struct { char *p; size_t len, cap; int bad; } nsw_jb_t;

static void nsw_jb_put(nsw_jb_t *b, const char *s, size_t n) {
    if (b->bad) return;
    if (b->len + n + 1 > b->cap) {
        size_t nc = b->cap ? b->cap : 1024;
        while (nc < b->len + n + 1) {
            if (nc > ((size_t)1 << 30)) { b->bad = 1; return; }
            nc *= 2;
        }
        char *g = realloc(b->p, nc);
        if (!g) { b->bad = 1; return; }
        b->p = g;
        b->cap = nc;
    }
    memcpy(b->p + b->len, s, n);
    b->len += n;
    b->p[b->len] = '\0';
}

static void nsw_jb_str(nsw_jb_t *b, const char *s, size_t n) {
    static const char hx[] = "0123456789abcdef";
    nsw_jb_put(b, "\"", 1);
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c == '"' || c == '\\') {
            char e[2] = { '\\', (char)c };
            nsw_jb_put(b, e, 2);
        } else if (c < 0x20 || c == 0x7f) {
            char e[6] = { '\\', 'u', '0', '0', hx[c >> 4], hx[c & 15] };
            nsw_jb_put(b, e, 6);
        } else {
            nsw_jb_put(b, (const char *)&c, 1);
        }
    }
    nsw_jb_put(b, "\"", 1);
}

/* One CBOR value at the decoder → JSON. @return 0 / -1. */
static int nsw_cbor_json(cbor_decoder_t *d, nsw_jb_t *b, int depth) {
    if (depth > NSW_EVM_JSON_DEPTH) return -1;
    cbor_item_t it = cbor_decode_next(d);
    if (d->error) return -1;
    const size_t left = d->pos < d->len ? d->len - d->pos : 0;
    switch (it.type) {
    case CBOR_ITEM_UINT: {
        char n[NSW_U64_DEC];
        nsw_fmt_u64(it.uint_val, n);
        nsw_jb_put(b, "\"", 1);
        nsw_jb_put(b, n, strlen(n));
        nsw_jb_put(b, "\"", 1);
        return 0;
    }
    case CBOR_ITEM_BSTR: {
        static const char hx[] = "0123456789abcdef";
        nsw_jb_put(b, "\"", 1);
        for (size_t i = 0; i < it.bstr.len; i++) {
            char e[2] = { hx[it.bstr.ptr[i] >> 4], hx[it.bstr.ptr[i] & 15] };
            nsw_jb_put(b, e, 2);
        }
        nsw_jb_put(b, "\"", 1);
        return 0;
    }
    case CBOR_ITEM_TSTR:
        nsw_jb_str(b, it.tstr.ptr, it.tstr.len);
        return 0;
    case CBOR_ITEM_BOOL:
        nsw_jb_put(b, it.bool_val ? "true" : "false", it.bool_val ? 4 : 5);
        return 0;
    case CBOR_ITEM_NULL:
        nsw_jb_put(b, "null", 4);
        return 0;
    case CBOR_ITEM_ARRAY:
        if (it.count > left) return -1;
        nsw_jb_put(b, "[", 1);
        for (size_t i = 0; i < it.count; i++) {
            if (i) nsw_jb_put(b, ",", 1);
            if (nsw_cbor_json(d, b, depth + 1) != 0) return -1;
        }
        nsw_jb_put(b, "]", 1);
        return 0;
    case CBOR_ITEM_MAP:
        if (it.count > left / 2) return -1;
        nsw_jb_put(b, "{", 1);
        for (size_t i = 0; i < it.count; i++) {
            cbor_item_t k = cbor_decode_next(d);
            if (d->error || k.type != CBOR_ITEM_TSTR) return -1;
            if (i) nsw_jb_put(b, ",", 1);
            nsw_jb_str(b, k.tstr.ptr, k.tstr.len);
            nsw_jb_put(b, ":", 1);
            if (nsw_cbor_json(d, b, depth + 1) != 0) return -1;
        }
        nsw_jb_put(b, "}", 1);
        return 0;
    default:
        return -1;
    }
}

/* A buffer of `len` bytes for the next query's argument text (the caller
 * writes UTF-8 into it; no terminator needed). NULL on refusal. */
char *nsw_evm_query_buf(int len) {
    if (len < 0 || (size_t)len > NSW_EVM_QUERY_MAX) return NULL;
    if ((size_t)len + 1 > g_eq_args_cap) {
        char *g = realloc(g_eq_args, (size_t)len + 1);
        if (!g) return NULL;
        g_eq_args = g;
        g_eq_args_cap = (size_t)len + 1;
    }
    return g_eq_args;
}

/* The JSON of the last successful nsw_evm_query ("" otherwise). */
const char *nsw_evm_query_json(void) { return g_eq_json ? g_eq_json : ""; }

static int nsw_evm_method_ok(const char *m) {
    static const char *const names[] = {
        "evm_account", "evm_code", "evm_storage", "evm_call", "evm_estimate",
        "evm_receipt", "evm_logs", "evm_ticket"
    };
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++)
        if (m && strcmp(m, names[i]) == 0) return 1;
    return 0;
}

/* The argument text (`len` bytes in the query buffer) → CBOR map entries.
 * @return the entry count, or -1. */
static long nsw_evm_args_cbor(size_t len, cbor_encoder_t *enc) {
    long n = 0;
    size_t i = 0;
    while (i < len) {
        size_t j = i;
        while (j < len && g_eq_args[j] != ';') j++;
        /* key=t:value */
        size_t k = i;
        while (k < j && g_eq_args[k] != '=') k++;
        if (k == i || k - i > 4 || k + 2 >= j || g_eq_args[k + 2] != ':')
            return -1;
        for (size_t q = i; q < k; q++) {
            char c = g_eq_args[q];
            if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'))) return -1;
        }
        const char t = g_eq_args[k + 1];
        const char *v = g_eq_args + k + 3;
        const size_t vl = j - (k + 3);
        cbor_encode_tstr(enc, g_eq_args + i, k - i);
        if (t == 'u') {
            char dec[NSW_U64_DEC];
            uint64_t u = 0;
            if (vl == 0 || vl >= sizeof(dec)) return -1;
            memcpy(dec, v, vl);
            dec[vl] = '\0';
            if (nsw_parse_u64(dec, &u) != 0) return -1;
            cbor_encode_uint(enc, u);
        } else if (t == 'U') {
            /* every element parsed before the array head (its count) */
            uint64_t el[NSW_EVM_ARG_ARRAY_MAX];
            size_t ne = 0, s = 0;
            for (;;) {
                size_t e = s;
                while (e < vl && v[e] != ',') e++;
                char dec[NSW_U64_DEC];
                if (ne == NSW_EVM_ARG_ARRAY_MAX || e == s ||
                    e - s >= sizeof(dec))
                    return -1;
                memcpy(dec, v + s, e - s);
                dec[e - s] = '\0';
                if (nsw_parse_u64(dec, &el[ne]) != 0) return -1;
                ne++;
                if (e == vl) break;
                s = e + 1;
            }
            cbor_encode_array(enc, ne);
            for (size_t q = 0; q < ne; q++) cbor_encode_uint(enc, el[q]);
        } else if (t == 'b') {
            if (vl % 2) return -1;
            uint8_t *raw = malloc(vl / 2 + 1);
            if (!raw) return -1;
            for (size_t q = 0; q < vl / 2; q++) {
                int h = v[2 * q], l = v[2 * q + 1];
                int hv = h >= '0' && h <= '9' ? h - '0' : h >= 'a' && h <= 'f' ? h - 'a' + 10 : -1;
                int lv = l >= '0' && l <= '9' ? l - '0' : l >= 'a' && l <= 'f' ? l - 'a' + 10 : -1;
                if (hv < 0 || lv < 0) { free(raw); return -1; }
                raw[q] = (uint8_t)(hv << 4 | lv);
            }
            cbor_encode_bstr(enc, raw, vl / 2);
            free(raw);
        } else {
            return -1;
        }
        n++;
        i = j + 1;
    }
    return enc->error ? -1 : n;
}

/* ONE §18 read: `method` (one of the eight evm_* names) with the argument
 * text the caller placed in nsw_evm_query_buf (`len` bytes). Waits on the
 * network (ccall { async: true }). @return 0 (nsw_evm_query_json) / -1. */
int nsw_evm_query(const char *method, int len) {
    if (nsw_begin() != 0) return -1;
    free(g_eq_json);
    g_eq_json = NULL;
    if (!nsw_evm_method_ok(method))
        return nsw_end(nsw_fail("Unknown smart-contract request."));
    if (len < 0 || (size_t)len > NSW_EVM_QUERY_MAX ||
        (len > 0 && (!g_eq_args || (size_t)len >= g_eq_args_cap)))
        return nsw_end(nsw_fail("Invalid smart-contract request."));
    if (nsw_session_ok() != 0) return nsw_end(-1);
    const size_t cap = (size_t)len + 1024;
    uint8_t *ab = malloc(cap);
    if (!ab) return nsw_end(nsw_fail("Out of memory."));
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, ab, cap);
    long n = nsw_evm_args_cbor((size_t)len, &enc);
    if (n < 0) {
        free(ab);
        return nsw_end(nsw_fail("Invalid smart-contract request."));
    }
    uint8_t *reply = NULL;
    size_t rlen = 0;
    int rc = nodus_client_dnac_query_raw(&g_client, method, ab,
                                         cbor_encoder_len(&enc), (size_t)n,
                                         &reply, &rlen);
    free(ab);
    if (g_cancel) { free(reply); return nsw_end(-1); }
    if (rc != 0) {
        free(reply);
        if (rc == NODUS_ERR_NOT_FOUND)
            return nsw_end(nsw_fail("Smart contracts are not active on this "
                                    "Nodus network yet."));
        if (rc == NODUS_ERR_RATE_LIMITED)
            return nsw_end(nsw_fail("The Nodus node is busy; try again in a "
                                    "moment."));
        return nsw_end(nsw_fail("The smart-contract request failed (an older "
                                "node, a refused request, or no readable "
                                "answer; rc=%d).", rc));
    }
    nsw_jb_t jb;
    memset(&jb, 0, sizeof(jb));
    cbor_decoder_t d;
    cbor_decoder_init(&d, reply, rlen);
    int jrc = nsw_cbor_json(&d, &jb, 0);
    free(reply);
    if (jrc != 0 || jb.bad || d.pos != rlen) {
        free(jb.p);
        return nsw_end(nsw_fail("The Nodus node's smart-contract answer is "
                                "malformed."));
    }
    g_eq_json = jb.p;
    return nsw_end(0);
}

#ifdef NODUS_SEND_TEST_FIXED_RANDOM
/* TEST-only (parity build, exports_test): the codec through the module,
 * and an offline EVM build. */

static char *g_test_evm_hex;

static const char *nsw_test_evm_keep(const uint8_t *b, size_t n) {
    free(g_test_evm_hex);
    g_test_evm_hex = malloc(2 * n + 1);
    if (!g_test_evm_hex) return "";
    nsw_fmt_hex(b, n, g_test_evm_hex);
    return g_test_evm_hex;
}

/* The §18 query argument text (`len` bytes in nsw_evm_query_buf) through
 * the parser nsw_evm_query uses → "<entry count>:<CBOR map entries hex>",
 * "" on refusal. */
const char *nsw_test_evm_args_hex(int len) {
    if (len < 0 || (size_t)len > NSW_EVM_QUERY_MAX ||
        (len > 0 && (!g_eq_args || (size_t)len >= g_eq_args_cap)))
        return "";
    const size_t cap = (size_t)len + 1024;
    uint8_t *ab = malloc(cap);
    if (!ab) return "";
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, ab, cap);
    long n = nsw_evm_args_cbor((size_t)len, &enc);
    const char *out = "";
    if (n >= 0) {
        const size_t w = cbor_encoder_len(&enc);
        char cnt[NSW_U64_DEC];
        nsw_fmt_u64((uint64_t)n, cnt);
        const size_t cl = strlen(cnt);
        free(g_test_evm_hex);
        g_test_evm_hex = malloc(cl + 1 + 2 * w + 1);
        if (g_test_evm_hex) {
            memcpy(g_test_evm_hex, cnt, cl);
            g_test_evm_hex[cl] = ':';
            nsw_fmt_hex(ab, w, g_test_evm_hex + cl + 1);
            out = g_test_evm_hex;
        }
    }
    free(ab);
    return out;
}

/* Encode an EVM call (data / access list from the request) → hex, "" on
 * refusal. Bridge fields are ignored by ops that do not carry them. */
const char *nsw_test_evm_call_hex(int op, const char *to_hex,
                                  const char *value_hex, const char *gas_dec,
                                  const char *nonce_dec, const char *amount_dec,
                                  const char *dest_hex, const char *ticket_hex) {
    dna_evm_call_t c;
    memset(&c, 0, sizeof(c));
    c.op = (uint32_t)op;
    if ((to_hex[0] && nsw_parse_hex(to_hex, c.to, 32) != 0) ||
        (value_hex[0] && nsw_parse_hex(value_hex, c.value_wei, 32) != 0) ||
        nsw_parse_u64(gas_dec, &c.gas_limit) != 0 ||
        nsw_parse_u64(nonce_dec, &c.nonce) != 0 ||
        nsw_parse_u64(amount_dec, &c.amount_raw) != 0 ||
        (dest_hex[0] && nsw_parse_hex(dest_hex, c.dest_fp, 64) != 0) ||
        (ticket_hex[0] && nsw_parse_hex(ticket_hex, c.ticket_id, 64) != 0))
        return "";
    c.data = g_evm_req.data;
    c.data_len = g_evm_req.data_len;
    c.access = g_evm_req.access_len ? g_evm_req.access : NULL;
    c.access_len = g_evm_req.access_len;
    c.n_access = g_evm_req.n_access;
    size_t n = 0, w = 0;
    if (dna_evm_call_encoded_size(&c, &n) != 0) return "";
    uint8_t *b = malloc(n ? n : 1);
    const char *out = "";
    if (b && dna_evm_call_encode(&c, b, n, &w) == 0 && w == n)
        out = nsw_test_evm_keep(b, n);
    free(b);
    return out;
}

/* Strict decode of `hex` as op `op`, then re-encode → hex ("" = refused). */
const char *nsw_test_evm_call_roundtrip(int op, const char *hex) {
    size_t n = strlen(hex);
    if (n % 2) return "";
    uint8_t *b = malloc(n / 2 + 1), *r = malloc(n / 2 + 1);
    const char *out = "";
    dna_evm_call_t c;
    size_t w = 0;
    if (b && r && (n == 0 || nsw_parse_hex(hex, b, n / 2) == 0) &&
        dna_evm_call_decode((uint32_t)op, b, n / 2, &c) == 0 &&
        dna_evm_call_encode(&c, r, n / 2, &w) == 0 && w == n / 2)
        out = nsw_test_evm_keep(r, w);
    free(b);
    free(r);
    return out;
}

/* Strict decode of an EVMFUND call, then re-encode → hex ("" = refused). */
const char *nsw_test_evmfund_roundtrip(const char *hex) {
    size_t n = strlen(hex);
    if (n % 2 || n == 0) return "";
    uint8_t *b = malloc(n / 2), *r = malloc(n / 2);
    const char *out = "";
    dna_evmfund_call_t c;
    size_t w = 0;
    if (b && r && nsw_parse_hex(hex, b, n / 2) == 0 &&
        dna_evmfund_decode(b, n / 2, &c) == 0 &&
        dna_evmfund_encode(&c, r, n / 2, &w) == 0 && w == n / 2)
        out = nsw_test_evm_keep(r, w);
    free(b);
    free(r);
    return out;
}

/* The shared CREATE-address rule (nodus_v2_evm_create_address) on a given
 * 32-byte sender (64 hex) and nonce (decimal) → 64 hex, "" on refusal.
 * The test pins it to the engine's oracle vectors. */
const char *nsw_test_evm_create_address(const char *sender_hex,
                                        const char *nonce_dec) {
    uint8_t sender[32], out[32];
    uint64_t nonce = 0;
    if (nsw_parse_hex(sender_hex, sender, sizeof(sender)) != 0 ||
        nsw_parse_u64(nonce_dec, &nonce) != 0 ||
        nodus_v2_evm_create_address(sender, nonce, out) != 0)
        return "";
    return nsw_test_evm_keep(out, sizeof(out));
}

/* Extra meter-policy op weights an offline EVM build adds on top of the
 * pinned generation's policy (none of 1-2 weighs CORE op 9). TEST input,
 * never a pin. */
#define NSW_TEST_EVM_OPS 8
static struct { uint32_t op; uint64_t w; } g_test_evm_ops[NSW_TEST_EVM_OPS];
static int g_test_evm_nops;

int nsw_test_evm_op_weight(int op, const char *w_dec) {
    uint64_t w = 0;
    if (op < 0 || op > (int)DNA_ENV_MAX_RUNTIME_OP ||
        g_test_evm_nops >= NSW_TEST_EVM_OPS || nsw_parse_u64(w_dec, &w) != 0)
        return -1;
    g_test_evm_ops[g_test_evm_nops].op = (uint32_t)op;
    g_test_evm_ops[g_test_evm_nops].w = w;
    g_test_evm_nops++;
    return 0;
}

/* OFFLINE EVM build: the identity from nsw_seed_buf (wiped), the
 * candidate coins (nsw_req_*), data / access list (nsw_evm_*), pinned
 * generation `gen` for the CORE tuple and the policy (plus the test op
 * weights), the CORE leg's version / hash and the EVM leg's version /
 * hash given EXPLICITLY (no pin exists), chain id, tip and gas price as a
 * node would report them; no vote height, so the expiry is tip + 90. */
int nsw_test_evm_build(int gen, int op, const char *chain_hex,
                       const char *tip_dec, const char *gas_price_dec,
                       const char *core_ver_dec, const char *core_hash_hex,
                       const char *evm_ver_dec, const char *evm_hash_hex,
                       const char *to_hex, const char *value_hex,
                       const char *gas_dec, const char *nonce_dec,
                       const char *amount_dec, const char *dest_hex,
                       const char *ticket_hex, const char *units_dec,
                       const char *expiry_dec) {
    uint8_t chain32[DNA_CHAIN_ID_LEN], evm_hash[64];
    uint64_t tip = 0, gp = 0, cv = 0, ev = 0, units = 0, expiry = 0;
    uint8_t *pk = NULL, *sk = NULL;
    dna_meter_policy_t *pol = calloc(1, sizeof(*pol));
    nodus_v2_ruleset_id_t rs;
    dna_evm_call_t c;
    memset(&c, 0, sizeof(c));
    c.op = (uint32_t)op;
    int rc = -1;
    if (!pol || gen < 1 || (uint32_t)gen > nodus_v2_pins_generation_count() ||
        nsw_parse_hex(chain_hex, chain32, sizeof(chain32)) != 0 ||
        nsw_parse_u64(tip_dec, &tip) != 0 ||
        nsw_parse_u64(gas_price_dec, &gp) != 0 ||
        nsw_parse_u64(core_ver_dec, &cv) != 0 || cv > UINT32_MAX ||
        nsw_parse_u64(evm_ver_dec, &ev) != 0 || ev > UINT32_MAX ||
        nsw_parse_hex(evm_hash_hex, evm_hash, 64) != 0 ||
        nsw_parse_u64(units_dec, &units) != 0 ||
        nsw_parse_u64(expiry_dec, &expiry) != 0 ||
        (to_hex[0] && nsw_parse_hex(to_hex, c.to, 32) != 0) ||
        (value_hex[0] && nsw_parse_hex(value_hex, c.value_wei, 32) != 0) ||
        nsw_parse_u64(gas_dec, &c.gas_limit) != 0 ||
        nsw_parse_u64(nonce_dec, &c.nonce) != 0 ||
        nsw_parse_u64(amount_dec, &c.amount_raw) != 0 ||
        (dest_hex[0] && nsw_parse_hex(dest_hex, c.dest_fp, 64) != 0) ||
        (ticket_hex[0] && nsw_parse_hex(ticket_hex, c.ticket_id, 64) != 0)) {
        rc = nsw_fail("Invalid offline EVM input.");
        goto done;
    }
    if (nsw_ruleset((uint32_t)gen, &rs, pol) != 0) goto done;
    for (int i = 0; i < g_test_evm_nops; i++)
        if (dna_meter_op_set(pol, g_test_evm_ops[i].op,
                             g_test_evm_ops[i].w) != 0) {
            rc = nsw_fail("Invalid test op weight.");
            goto done;
        }
    if (dna_meter_policy_seal(pol) != 0) {
        rc = nsw_fail("The test policy could not be sealed.");
        goto done;
    }
    rs.meter_policy = pol;
    rs.core_ruleset_version = (uint32_t)cv;
    if (nsw_parse_hex(core_hash_hex, rs.core_ruleset_hash, 64) != 0) {
        rc = nsw_fail("Invalid offline EVM input.");
        goto done;
    }
    {
        const nsw_gen_t g = { (uint32_t)gen, 0u, 0u };
        if (nsw_expiry_check(tip, &g, expiry) != 0) goto done;
    }
    pk = malloc(NSW_PK_LEN);
    sk = malloc(NSW_SK_LEN);
    if (!pk || !sk) {
        rc = nsw_fail("Out of memory.");
    } else if (qgp_dsa87_keypair_derand(pk, sk, g_seed) != 0) {
        rc = nsw_fail("Key derivation failed.");
    } else {
        rc = nsw_evm_core(pk, sk, chain32, tip, gp, &rs, (uint32_t)ev,
                          evm_hash, &c, units, expiry);
    }
done:
    nsw_wipe(g_seed, sizeof(g_seed));
    if (sk) { nsw_wipe(sk, NSW_SK_LEN); free(sk); }
    free(pk);
    free(pol);
    return rc;
}
#endif

/* ── Messages host (package NC-4b; nc_core.h "Host") ──
 * The Messages exports (web-wallet/connect/nc_wasm.c, linked into this
 * module) run on THIS session, inside THIS op bracket, stopped by THIS
 * cancel flag: one session per identity (nodus_auth.c:95-116), one Asyncify
 * suspension at a time. They never create a client. */

int nc_host_begin(void)            { return nsw_begin(); }
int nc_host_end(void)              { g_busy = 0; return (g_locked || g_cancel) ? 1 : 0; }
const char *nc_host_error(void)    { return g_error; }
/* The client only once CONNECTED (session open, chain checked). */
nodus_client_t *nc_host_client(void) {
    return (g_unlocked && !g_locked && !g_cancel) ? &g_client : NULL;
}
/* The identity already once IDENTIFIED (nsw_identify): the Messages keys,
 * the history key and the kept-profile checks need no network. */
const nodus_identity_t *nc_host_identity(void) {
    return (g_identified && !g_locked && !g_cancel) ? &g_id : NULL;
}
/* The wallet's own session check for a Messages export about to send:
 * connected, the client ready, and — after a reconnect to another pinned
 * server — that server's chain id checked again (nsw_session_ok). Inside
 * the op bracket (nc_begin); may wait on the network. 0, or -1 with the
 * reason in nc_host_error(). Declared in nc_core.h. */
int nc_host_session_ok(void) {
    return nsw_session_ok() == 0 ? 0 : -1;
}
volatile const int *nc_host_cancel(void) { return &g_cancel; }

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
    nsw_claim_built_clear();
    nsw_req_env_free();
    nsw_req_reset();
    memset(&g_list, 0, sizeof(g_list));
    g_vals.valid = 0; g_vals.n = 0;
    g_dels.valid = 0; g_dels.n = 0;
    memset(&g_ri, 0, sizeof(g_ri));
    memset(&g_nm, 0, sizeof(g_nm));
    memset(&g_np, 0, sizeof(g_np));
    nsw_wipe(g_paddr, sizeof(g_paddr));
    nsw_msig_wipe();                        /* vaults (VAULTS)              */
    if (g_busy) {                           /* smart contracts: the request */
        if (g_evm_req.data) nsw_wipe(g_evm_req.data, g_evm_req.data_len);
    } else {
        nsw_evm_data_alloc(0);
    }
    nsw_evm_access_reset();
    g_evm_req.est_units = g_evm_req.est_gas = 0;
    memset(&g_evm_built, 0, sizeof(g_evm_built));
    if (!g_busy) {                          /* smart contracts: the reads   */
        free(g_eq_json);
        g_eq_json = NULL;
    }
    nc_session_wipe();                      /* the Messages keys and caches */
    g_unlocked = 0;
    g_identified = 0;
}
#endif /* !NODUS_SEND_OFFLINE_ONLY */
