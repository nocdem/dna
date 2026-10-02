/**
 * @file nodus/tests/test_v2_name_build.c
 * @brief The shared NAME_REGISTER envelope builder (nodus/src/client/
 *        nodus_v2_name.c — HF-4 on-chain names) against the pre-move
 *        nodus-cli algorithm, a literal call fixture and the production
 *        engine.
 *
 * Governing records: docs/plans/decisions/2026-10-02-onchain-names.md
 * (items 2-6, 10, 11, 16; the price comes from the node, never compiled
 * into a client) with design docs/plans/2026-10-02-onchain-names-design.md
 * rev 4 §2, and docs/plans/decisions/2026-09-25-web-wallet-nodus-send-
 * transport.md ("İşlem kurucu": the wallet builds with the SAME C code as
 * nodus-cli).
 *
 * ── WHAT THIS PROVES ────────────────────────────────────────────────────
 *  N0  The helpers: nodus_v2_name_normalize lower-cases A-Z only and then
 *      applies dnac_name_bytes_ok (uppercase input accepted as its lower
 *      form; '-', a non-ASCII byte, 2 and 37 characters and an all-hex name
 *      of 8+ characters refused; a 4-letter all-hex word accepted);
 *      nodus_v2_name_price_for picks tier 3 / 4 / 5 / 6+ by length and
 *      refuses 2 and 37; nodus_v2_name_effect_decl equals two hand-computed
 *      literals.
 *  N1  THE FIXTURE — bytes the old inline code wrote. With a fixed key,
 *      three made-up coins (40, 20 and 5 x 10^9 raw, nullifiers 0x33..,
 *      0x11.., 0x22..), "punk" at price 5 x 10^10, gas price 0 and a rand
 *      that returns 0xA0, 0xA1, …, the library's CORE leg carries EXACTLY
 *      the call written out byte by byte below (name_len 04 ‖ "punk" ‖
 *      00 00 00 0b a4 3b 74 00 ‖ in 02 ‖ 0x11.. ‖ 0x33.. ‖ out 01 ‖ owner
 *      hex ‖ 00 00 00 02 53 fc a1 c0 ‖ 64 zero ‖ a0..bf) and the header
 *      numbers written out as literals (domain 1, op 8, the generation-2
 *      CORE version, access INVOKE, auth kind 1, auth_len 7220, 5 effects,
 *      1004 effect bytes, fee 10^6, expiry tip + 90). The owner hex is the
 *      only value derived at run time (SHA3-512 of the derived key).
 *  N2  nodus-cli equivalence. `name register` has no builder of its own any
 *      more: it calls nodus_v2_name_build. A restatement, in this file, of
 *      the pre-move cmd_name_register loop (filter, largest-first pick,
 *      13-input cap, ascending nullifiers, the call, the leg header, units
 *      = nodus_v2_spend_ceiling with inputs + 3 reads, the gas fixed point,
 *      one rand draw per pass that writes a change) signed with the same
 *      key yields, for the same rand sequence: the same envelope length,
 *      the same intent_id, the same fee / units / pass count and bytes
 *      identical outside the auth blob — at gas price 0 (one pass) and at a
 *      gas price that forces a second pass (two rand draws, fee = units x
 *      gas price).
 *  N3  Refusals: a name outside the rule, price 0, tip 0, an expiry beyond
 *      the window, a fixed fee below the floor, a fixed fee below units x
 *      gas price, no coin / only a locked / only a non-native / only a zero
 *      coin, a price that needs more than 13 inputs, a failing rand, and
 *      nothing is returned on a refusal. The decoder refuses a call whose
 *      name byte was changed to uppercase.
 *  N4  The engine: on a seeded generation-2 chain (HF-2 on from 1, param 9
 *      effective at 4, blocks 1-3 applied — test_hf4_names_engine.c's
 *      fixture) a library-built registration is ADMITTED by the CheckTx
 *      seam (nodus_witness_v2_env_dry_run: rc 0, code OK, the engine's
 *      wire_id / intent_id equal the builder's) and APPLIED in block 4:
 *      v2_names (punk, owner, 4), the reward pool up by exactly fee +
 *      price. The same request built with the browser's ruleset source
 *      (nodus_v2_ruleset_from_pins_gen(2)) gives the same intent_id.
 *
 * ── WHAT IT REQUIRES ────────────────────────────────────────────────────
 * Compile flags: none beyond a default build; DNAC_EPOCH_LENGTH > 8 (no
 * epoch boundary among heights 1..4 — checked). Environment: none. SQLite
 * >= 3.35.0 (the seeded genesis fixture).
 *
 * ── WHAT IT LEAVES BEHIND ───────────────────────────────────────────────
 * One /tmp/test_v2_name_build_XXXXXX directory, removed at the end; a
 * CHECK failure leaves it behind (this tree's fixture convention).
 *
 * ── HOW IT CAN LIE ──────────────────────────────────────────────────────
 *  1. N2's restatement and the library were moved/written by the same
 *     author on the same day; N1's literal bytes were derived by hand from
 *     the pre-move code, not captured from a running nodus-cli (that needs a
 *     node over the network). intent_id is NOT pinned as a literal: it
 *     would have to be produced by running a built binary, which the
 *     author was not allowed to do.
 *  2. The genesis is SEEDED with spendable UTXOs (V2X_SEED_NOT_REAL_UTXOS)
 *     — a state the real derivation never writes.
 *  3. The chain's gas price is 0 (the seeded document): N2's second pass
 *     proves the builder's arithmetic, not that a node demands that fee.
 *  4. The price is passed in (the compiled no-row default
 *     DNAC_NAME_PRICE_4P_DEFAULT, what dnac_fee_info answers with no price
 *     row); the RPC itself is not exercised here.
 *  5. Written, compiled, NOT RUN by its author (the BUILDER rule).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_v2_apply.h"
#include "witness/nodus_witness_v2_claims.h"    /* nodus_witness_v2_chain_id */
#include "witness/nodus_witness_v2_produce.h"   /* v2_tip_height             */
#include "witness/nodus_witness_runtime.h"
#include "nodus/nodus_types.h"
#include "nodus/nodus_chain_config.h"
#include "nodus/nodus_v2_spend.h"
#include "client/nodus_v2_name.h"

#include "dnac/dnac.h"
#include "dnac/ledger_ids.h"
#include "dnac/env_wire.h"
#include "crypto/hash/qgp_sha3.h"
#include "crypto/sign/qgp_dilithium.h"
#include "crypto/utils/qgp_fingerprint.h"

#include "v2_genesis_fixture.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <unistd.h>

#define CHECK(cond, msg) do {                                              \
    if (!(cond)) {                                                         \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, \
                (msg));                                                    \
        return 1;                                                          \
    }                                                                      \
    g_checks++;                                                            \
} while (0)

static int g_checks = 0;

#define NB_FLOOR   ((uint64_t)(DNAC_MIN_FEE_RAW > NODUS_W_BASE_TX_FEE \
                        ? DNAC_MIN_FEE_RAW : NODUS_W_BASE_TX_FEE))
#define NB_AHEAD   ((uint64_t)NODUS_CMT_APP_MAX_EXPIRY_AHEAD - 10u)
#define NB_AUTH    (1u + NODUS_RT_AUTH_SIGNER_LEN)
#define NB_P4      ((uint64_t)DNAC_NAME_PRICE_4P_DEFAULT)
#define NB_TIP     1000u

/* ══ the fixed key ═══════════════════════════════════════════════════ */

static uint8_t g_pk[2592], g_sk[4896];
static char    g_fp[QGP_FP_HEX_BUFFER];
static uint8_t g_fp_raw[64];

static int keys_init(void) {
    uint8_t seed[32];
    memset(seed, 0x4E, sizeof(seed));
    if (qgp_dsa87_keypair_derand(g_pk, g_sk, seed) != 0) return -1;
    if (qgp_sha3_512(g_pk, sizeof(g_pk), g_fp_raw) != 0) return -1;
    qgp_fp_raw_to_hex(g_fp_raw, g_fp);
    return 0;
}

/* ══ the fixed rand: 0xA0, 0xA1, … across calls; counts its draws ═══ */

typedef struct { uint8_t next; int calls; int fail; } nb_rand_t;

static int nb_rand(void *ctx, uint8_t *buf, size_t len) {
    nb_rand_t *r = ctx;
    if (r->fail) return -1;
    for (size_t i = 0; i < len; i++) buf[i] = r->next++;
    r->calls++;
    return 0;
}

/* ══ the generation-2 ruleset: compiled table (nodus-cli's source) ═══ */

static int table_rs(nodus_v2_ruleset_id_t *rs) {
    const nodus_domain_runtime_t *c =
        nodus_runtime_for_generation(NODUS_RT_GEN_2, DNA_DOMAIN_CORE);
    const nodus_domain_runtime_t *s =
        nodus_runtime_for_generation(NODUS_RT_GEN_2, DNA_DOMAIN_SYSTEM);
    if (!c || !s || !s->meter_policy) return -1;
    memset(rs, 0, sizeof(*rs));
    rs->core_ruleset_version = c->ruleset_version;
    memcpy(rs->core_ruleset_hash, c->ruleset_hash, 64);
    rs->meter_policy = s->meter_policy;
    return 0;
}

static void base_req(nodus_v2_name_req_t *r, const nodus_v2_ruleset_id_t *rs,
                     const uint8_t *chain32, uint64_t tip, const char *name,
                     uint64_t price, const nodus_v2_name_coin_t *coins,
                     int n_coins, nb_rand_t *rand_ctx) {
    memset(r, 0, sizeof(*r));
    r->rs            = rs;
    r->chain32       = chain32;
    r->tip           = tip;
    r->expiry_height = tip + NB_AHEAD;
    r->pk            = g_pk;
    r->sk            = g_sk;
    r->name          = name;
    r->price         = price;
    r->coins         = coins;
    r->n_coins       = n_coins;
    r->rand          = nb_rand;
    r->rand_ctx      = rand_ctx;
}

/* ── the pre-move cmd_name_register loop, restated ──────────────────── */

typedef struct {
    uint8_t *env;
    size_t   env_len;
    uint8_t  intent_id[64];
    uint64_t fee, units;
    int      passes;
    size_t   auth_off;       /* the auth blob's offset in env            */
} nb_old_t;

/* `coins`: the listed rows (filter applied here, as the CLI did). */
static int restate_old(const nodus_v2_ruleset_id_t *rs, const uint8_t *chain32,
                       uint64_t tip, const char *name, uint64_t price,
                       uint64_t gas_price, const nodus_v2_name_coin_t *rows,
                       int n_rows, nb_rand_t *rnd, nb_old_t *out) {
    static const uint8_t native_tok[64] = {0};
    static uint8_t call[NODUS_V2_NAME_CALL_MAX];
    static uint8_t auth[NB_AUTH];
    nodus_v2_coin_t coins[32];
    const size_t name_len = strlen(name);
    int n_coins = 0;
    memset(out, 0, sizeof(*out));
    for (int i = 0; i < n_rows && n_coins < 32; i++) {
        const nodus_v2_name_coin_t *e = &rows[i];
        if (e->amount == 0) continue;
        if (memcmp(e->token, native_tok, 64) != 0) continue;
        if (e->unlock_block >= tip + 1) continue;
        memset(&coins[n_coins], 0, sizeof(coins[n_coins]));
        memcpy(coins[n_coins].nul, e->nul, 64);
        coins[n_coins].amount = e->amount;
        n_coins++;
    }
    if (nodus_v2_spend_sort_coins(coins, n_coins,
                                  NODUS_V2_SPEND_ORDER_LARGEST_FIRST) != 0)
        return -1;

    nodus_v2_spend_plan_t plan;
    dna_env_leg_in_t leg;
    dna_env_in_t env_in;
    uint64_t fee = NB_FLOOR, units = 0, change = 0;
    int pass;
    for (pass = 0; ; pass++) {
        const uint64_t need = fee + price;
        memset(&plan, 0, sizeof(plan));
        for (int i = 0; i < n_coins; i++) coins[i].used = 0;
        if (nodus_v2_spend_pick(coins, n_coins, 0, need, &plan,
                                &plan.native_in) != 0 ||
            plan.n_in > 13)
            return -1;
        change = plan.native_in - need;
        uint8_t nulls[NODUS_V2_SPEND_MAX_IN][64];
        for (int j = 0; j < plan.n_in; j++)
            memcpy(nulls[j], coins[plan.idx[j]].nul, 64);
        qsort(nulls, (size_t)plan.n_in, 64, nodus_v2_nul_cmp);
        size_t off = 0;
        call[off++] = (uint8_t)name_len;
        memcpy(call + off, name, name_len);          off += name_len;
        for (int b = 0; b < 8; b++)
            call[off++] = (uint8_t)(price >> (56 - 8 * b));
        call[off++] = (uint8_t)plan.n_in;
        for (int j = 0; j < plan.n_in; j++) {
            memcpy(call + off, nulls[j], 64);
            off += 64;
        }
        const uint32_t n_out = change > 0 ? 1u : 0u;
        call[off++] = (uint8_t)n_out;
        if (n_out) {
            uint8_t seed[32];
            if (nb_rand(rnd, seed, sizeof(seed)) != 0) return -1;
            nodus_v2_xfer_out_put(call + off, g_fp, change, NULL, seed);
            off += NODUS_V2_SPEND_OUT_LEN;
        }
        memset(&leg, 0, sizeof(leg));
        leg.hdr.domain_id       = DNA_DOMAIN_CORE;
        leg.hdr.runtime_op      = DNA_CORERULE_NAME_REGISTER;
        leg.hdr.ruleset_version = rs->core_ruleset_version;
        leg.hdr.access_mode     = DNA_ENV_ACCESS_INVOKE;
        leg.hdr.auth_kind       = NODUS_RT_AUTHKIND_DSA87_MULTI_V1;
        leg.hdr.call_len        = (uint32_t)off;
        leg.hdr.auth_len        = NB_AUTH;
        /* t8_name_effect_decl, restated */
        leg.hdr.res_max_effects = (uint32_t)plan.n_in + n_out + 2u;
        leg.hdr.res_max_effect_bytes =
            23u + 84u * leg.hdr.res_max_effects + n_out * (64u + 284u) +
            ((uint32_t)name_len + 72u) + (1u + 8u) + (uint32_t)plan.n_in * 64u;
        leg.call_data = call;
        memset(auth, 0, sizeof(auth));
        leg.auth_data = auth;
        memset(&env_in, 0, sizeof(env_in));
        env_in.expiry_height = tip + NB_AHEAD;
        env_in.fee_amount    = fee;
        env_in.leg_count     = 1;
        env_in.legs          = &leg;
        if (nodus_v2_spend_ceiling(&env_in, rs->meter_policy,
                                   (uint32_t)plan.n_in + 3u, &units) != 0)
            return -1;
        env_in.res_max_total_units = units;
        if (gas_price == 0) break;
        const uint64_t required = units * gas_price;
        if (required <= fee) break;
        if (pass >= 7) return -1;
        fee = required;
    }
    /* cli_sign_one_key: the one-key two-pass signature */
    dna_env_leg_ctx_t lctx;
    memset(&lctx, 0, sizeof(lctx));
    lctx.domain_id       = DNA_DOMAIN_CORE;
    lctx.ruleset_version = rs->core_ruleset_version;
    memcpy(lctx.ruleset_hash, rs->core_ruleset_hash, 64);
    uint8_t *auths[1] = { auth };
    dna_env_preflight_t *pf = calloc(1, sizeof(*pf));
    dna_env_view_t *v = calloc(1, sizeof(*v));
    int ok = -1;
    if (pf && v &&
        nodus_v2_env_sign_one_key(&env_in, auths, &lctx, chain32, tip, g_pk,
                                  g_sk, &out->env, &out->env_len, pf, NULL)
            == NODUS_V2_SPEND_OK &&
        dna_env_decode(out->env, out->env_len, v) == 0) {
        memcpy(out->intent_id, pf->intent_id, 64);
        out->fee      = fee;
        out->units    = units;
        out->passes   = pass + 1;
        out->auth_off = v->auth_off[0];
        ok = 0;
    }
    free(v);
    free(pf);
    if (ok != 0) { free(out->env); out->env = NULL; }
    return ok;
}

/* the envelope's single CORE leg header and call, read through the codec */
static int leg_of(const uint8_t *env, size_t len, dna_env_view_t *v,
                  const uint8_t **call, size_t *call_len) {
    if (dna_env_decode(env, len, v) != 0 || v->leg_count != 1) return -1;
    *call = v->buf + v->call_off[0];
    *call_len = v->leg[0].call_len;
    return 0;
}

/* ══ N0 — the helpers ════════════════════════════════════════════════ */

static int t_helpers(void) {
    char out[DNAC_NAME_MAX_LEN + 1];
    CHECK(nodus_v2_name_normalize("PuNk", out) == 0 && strcmp(out, "punk") == 0,
          "A-Z is lower-cased");
    CHECK(nodus_v2_name_normalize("bios7", out) == 0 &&
          strcmp(out, "bios7") == 0, "a-z0-9 kept");
    CHECK(nodus_v2_name_normalize("cafe", out) == 0,
          "a 4-letter all-hex word is a name (item 11: 8+ only)");
    CHECK(nodus_v2_name_normalize("deadbeef", out) != 0,
          "an all-hex name of 8 characters is refused");
    CHECK(nodus_v2_name_normalize("deadbeefz", out) == 0,
          "9 characters with a non-hex letter is a name");
    CHECK(nodus_v2_name_normalize("ab", out) != 0, "2 characters refused");
    CHECK(nodus_v2_name_normalize("a-b", out) != 0, "'-' refused");
    CHECK(nodus_v2_name_normalize("p\xc4\xb1nk", out) != 0,
          "a non-ASCII byte refused (no locale lower-casing)");
    CHECK(nodus_v2_name_normalize("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", out)
              == 0, "36 characters accepted");
    CHECK(nodus_v2_name_normalize("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", out)
              != 0, "37 characters refused");

    const uint64_t tiers[4] = { 11, 22, 33, 44 };
    uint64_t p = 0;
    CHECK(nodus_v2_name_price_for(tiers, 3, &p) == 0 && p == 11, "3 -> tier 0");
    CHECK(nodus_v2_name_price_for(tiers, 4, &p) == 0 && p == 22, "4 -> tier 1");
    CHECK(nodus_v2_name_price_for(tiers, 5, &p) == 0 && p == 33, "5 -> tier 2");
    CHECK(nodus_v2_name_price_for(tiers, 6, &p) == 0 && p == 44, "6 -> 6+");
    CHECK(nodus_v2_name_price_for(tiers, 36, &p) == 0 && p == 44, "36 -> 6+");
    CHECK(nodus_v2_name_price_for(tiers, 2, &p) != 0, "2 refused");
    CHECK(nodus_v2_name_price_for(tiers, 37, &p) != 0, "37 refused");

    uint32_t e = 0, b = 0;
    nodus_v2_name_effect_decl(2, 1, 4, &e, &b);
    /* 23 + 84·5 + 348 + (4 + 72) + 9 + 128 */
    CHECK(e == 5 && b == 1004, "effect decl (2 in, 1 out, 4 bytes)");
    nodus_v2_name_effect_decl(1, 0, 3, &e, &b);
    /* 23 + 84·3 + 0 + (3 + 72) + 9 + 64 */
    CHECK(e == 3 && b == 423, "effect decl (1 in, 0 out, 3 bytes)");
    return 0;
}

/* ══ N1 + N2 — the literal fixture and the pre-move equivalence ══════ */

static void layout_coins(nodus_v2_name_coin_t c[3]) {
    memset(c, 0, 3 * sizeof(c[0]));
    memset(c[0].nul, 0x33, 64); c[0].amount = 40000000000ULL;
    memset(c[1].nul, 0x11, 64); c[1].amount = 20000000000ULL;
    memset(c[2].nul, 0x22, 64); c[2].amount =  5000000000ULL;
}

static int t_fixture(void) {
    nodus_v2_ruleset_id_t rs;
    CHECK(table_rs(&rs) == 0, "generation-2 ruleset (compiled table)");
    uint8_t chain32[DNA_CHAIN_ID_LEN];
    memset(chain32, 0x5C, sizeof(chain32));
    nodus_v2_name_coin_t coins[3];
    layout_coins(coins);

    nb_rand_t r = { 0xA0, 0, 0 };
    nodus_v2_name_req_t req;
    base_req(&req, &rs, chain32, NB_TIP, "punk", 50000000000ULL, coins, 3, &r);
    nodus_v2_name_built_t *b = calloc(1, sizeof(*b));
    dna_env_view_t *v = calloc(1, sizeof(*v));
    CHECK(b && v, "alloc");
    nodus_v2_name_err_t err;
    CHECK(nodus_v2_name_build(&req, b, &err) == NODUS_V2_SPEND_OK,
          "builds at gas price 0");
    CHECK(r.calls == 1, "one change seed drawn");

    /* N1 — the call, byte by byte */
    uint8_t want[NODUS_V2_NAME_CALL_MAX];
    size_t w = 0;
    want[w++] = 0x04;
    memcpy(want + w, "punk", 4); w += 4;
    static const uint8_t price_be[8] = { 0x00, 0x00, 0x00, 0x0b,
                                         0xa4, 0x3b, 0x74, 0x00 };
    memcpy(want + w, price_be, 8); w += 8;
    want[w++] = 0x02;
    memset(want + w, 0x11, 64); w += 64;            /* ascending: 0x11.. */
    memset(want + w, 0x33, 64); w += 64;            /*            0x33.. */
    want[w++] = 0x01;
    memcpy(want + w, g_fp, 128); w += 128;          /* owner hex         */
    /* change = 6·10^10 − 5·10^10 − 10^6 = 9 999 000 000 */
    static const uint8_t change_be[8] = { 0x00, 0x00, 0x00, 0x02,
                                          0x53, 0xfc, 0xa1, 0xc0 };
    memcpy(want + w, change_be, 8); w += 8;
    memset(want + w, 0, 64); w += 64;               /* native            */
    for (int i = 0; i < 32; i++) want[w++] = (uint8_t)(0xA0 + i);
    CHECK(NB_FLOOR == 1000000ULL, "the floor the literal assumes");
    CHECK(w == 1 + 4 + 8 + 1 + 128 + 1 + 232, "fixture length");

    const uint8_t *call = NULL;
    size_t call_len = 0;
    CHECK(leg_of(b->env, b->env_len, v, &call, &call_len) == 0, "decode");
    CHECK(call_len == w && memcmp(call, want, w) == 0,
          "the call is EXACTLY the fixture bytes");
    CHECK(v->leg[0].domain_id == 1 && v->leg[0].runtime_op == 8 &&
          v->leg[0].ruleset_version == rs.core_ruleset_version &&
          v->leg[0].access_mode == DNA_ENV_ACCESS_INVOKE &&
          v->leg[0].auth_kind == 1 && v->leg[0].auth_len == 7220 &&
          v->leg[0].res_max_effects == 5 &&
          v->leg[0].res_max_effect_bytes == 1004,
          "the leg header literals");
    CHECK(v->fee_amount == 1000000ULL && v->expiry_height == NB_TIP + 90,
          "fee = the floor, expiry = tip + 90");
    CHECK(b->fee == 1000000ULL && b->price == 50000000000ULL &&
          b->change == 9999000000ULL && b->n_in == 2 && b->passes == 1 &&
          b->sum_in == 60000000000ULL, "the built summary");
    CHECK(strcmp(b->dec.name, "punk") == 0 && b->dec.n_out == 1 &&
          memcmp(b->dec.change_owner, g_fp, 128) == 0 &&
          memcmp(b->dec.owner_pk, g_pk, sizeof(g_pk)) == 0,
          "the read-back");

    /* N2 — the restated pre-move loop, same rand sequence */
    nb_old_t old;
    r.next = 0xA0; r.calls = 0;
    CHECK(restate_old(&rs, chain32, NB_TIP, "punk", 50000000000ULL, 0, coins,
                      3, &r, &old) == 0, "the restated nodus-cli build");
    CHECK(old.env_len == b->env_len && old.fee == b->fee &&
          old.units == b->units && old.passes == b->passes,
          "same length, fee, units, passes");
    CHECK(memcmp(old.intent_id, b->intent_id, 64) == 0, "same intent_id");
    CHECK(old.auth_off == v->auth_off[0], "the auth blob at the same offset");
    CHECK(memcmp(old.env, b->env, old.auth_off) == 0 &&
          memcmp(old.env + old.auth_off + NB_AUTH,
                 b->env + old.auth_off + NB_AUTH,
                 old.env_len - old.auth_off - NB_AUTH) == 0,
          "byte-identical outside the auth blob");
    free(old.env);

    /* N2 — a gas price that forces a second pass */
    nodus_v2_name_built_free(b);
    r.next = 0xA0; r.calls = 0;
    base_req(&req, &rs, chain32, NB_TIP, "punk", 50000000000ULL, coins, 3, &r);
    req.gas_price = 1000000;   /* units × 10^6 is far above the floor */
    CHECK(nodus_v2_name_build(&req, b, &err) == NODUS_V2_SPEND_OK,
          "builds at gas price 10^6");
    CHECK(b->passes == 2 && r.calls == 2 && b->fee == b->units * 1000000ULL,
          "two passes, two seeds, fee = units x gas price");
    r.next = 0xA0; r.calls = 0;
    CHECK(restate_old(&rs, chain32, NB_TIP, "punk", 50000000000ULL, 1000000,
                      coins, 3, &r, &old) == 0, "the restated build (gas)");
    CHECK(old.env_len == b->env_len && old.fee == b->fee &&
          old.units == b->units && old.passes == 2 &&
          memcmp(old.intent_id, b->intent_id, 64) == 0,
          "the gas fixed point matches the pre-move loop");
    free(old.env);
    nodus_v2_name_built_free(b);
    free(b);
    free(v);
    return 0;
}

/* ══ N3 — refusals ═══════════════════════════════════════════════════ */

static int t_refusals(void) {
    nodus_v2_ruleset_id_t rs;
    CHECK(table_rs(&rs) == 0, "ruleset");
    uint8_t chain32[DNA_CHAIN_ID_LEN];
    memset(chain32, 0x5C, sizeof(chain32));
    nodus_v2_name_coin_t coins[3];
    layout_coins(coins);
    nodus_v2_name_built_t *b = calloc(1, sizeof(*b));
    CHECK(b != NULL, "alloc");
    nb_rand_t r = { 0xA0, 0, 0 };
    nodus_v2_name_req_t req;
    nodus_v2_name_err_t err;
#define REFUSE(code, what) do {                                            \
        int rc_ = nodus_v2_name_build(&req, b, &err);                      \
        CHECK(rc_ == (code) && b->env == NULL && b->env_len == 0, what);   \
    } while (0)

    base_req(&req, &rs, chain32, NB_TIP, "PUNK", 50000000000ULL, coins, 3, &r);
    REFUSE(NODUS_V2_NAME_ERR_NAME, "an uppercase name (not normalised)");
    base_req(&req, &rs, chain32, NB_TIP, "deadbeef", 1, coins, 3, &r);
    REFUSE(NODUS_V2_NAME_ERR_NAME, "an all-hex name of 8");
    base_req(&req, &rs, chain32, NB_TIP, "punk", 0, coins, 3, &r);
    REFUSE(NODUS_V2_NAME_ERR_PRICE, "price 0");
    base_req(&req, &rs, chain32, 0, "punk", 50000000000ULL, coins, 3, &r);
    req.expiry_height = NB_AHEAD;
    REFUSE(NODUS_V2_SPEND_ERR_EXPIRY, "tip 0");
    base_req(&req, &rs, chain32, NB_TIP, "punk", 50000000000ULL, coins, 3, &r);
    req.expiry_height = NB_TIP + NODUS_CMT_APP_MAX_EXPIRY_AHEAD + 1;
    REFUSE(NODUS_V2_SPEND_ERR_EXPIRY, "expiry beyond the window");
    base_req(&req, &rs, chain32, NB_TIP, "punk", 50000000000ULL, coins, 3, &r);
    req.fee_fixed = 1; req.fee = NB_FLOOR - 1;
    REFUSE(NODUS_V2_NAME_ERR_FEE_FLOOR, "a fixed fee below the floor");
    base_req(&req, &rs, chain32, NB_TIP, "punk", 50000000000ULL, coins, 3, &r);
    req.fee_fixed = 1; req.fee = NB_FLOOR; req.gas_price = 1000000;
    REFUSE(NODUS_V2_SPEND_ERR_FEE_BELOW_GAS, "a fixed fee below units x gas");
    base_req(&req, &rs, chain32, NB_TIP, "punk", 50000000000ULL, coins, 0, &r);
    REFUSE(NODUS_V2_SPEND_ERR_INSUFFICIENT, "no coin");
    {
        nodus_v2_name_coin_t one[1];
        memset(one, 0, sizeof(one));
        memset(one[0].nul, 0x44, 64);
        one[0].amount = 100000000000ULL;
        one[0].unlock_block = NB_TIP + 1;            /* locked at tip + 1 */
        base_req(&req, &rs, chain32, NB_TIP, "punk", 50000000000ULL, one, 1, &r);
        REFUSE(NODUS_V2_SPEND_ERR_INSUFFICIENT, "only a locked coin");
        one[0].unlock_block = 0;
        memset(one[0].token, 0x01, 64);
        base_req(&req, &rs, chain32, NB_TIP, "punk", 50000000000ULL, one, 1, &r);
        REFUSE(NODUS_V2_SPEND_ERR_INSUFFICIENT, "only a non-native coin");
        memset(one[0].token, 0, 64);
        one[0].amount = 0;
        base_req(&req, &rs, chain32, NB_TIP, "punk", 50000000000ULL, one, 1, &r);
        REFUSE(NODUS_V2_SPEND_ERR_INSUFFICIENT, "only a zero coin");
    }
    {
        /* 14 coins of 4·10^9: 5·10^10 + fee needs 13 — still allowed — so
         * ask for a 6+ name priced 5.5·10^10: 14 coins needed */
        nodus_v2_name_coin_t many[14];
        memset(many, 0, sizeof(many));
        for (int i = 0; i < 14; i++) {
            memset(many[i].nul, 0x50 + i, 64);
            many[i].amount = 4000000000ULL;
        }
        base_req(&req, &rs, chain32, NB_TIP, "punker", 55000000000ULL, many,
                 14, &r);
        REFUSE(NODUS_V2_SPEND_ERR_MAX_INPUTS, "more than 13 inputs needed");
    }
    base_req(&req, &rs, chain32, NB_TIP, "punk", 50000000000ULL, coins, 3, &r);
    r.fail = 1;
    REFUSE(NODUS_V2_SPEND_ERR_RANDOM, "a failing rand");
    r.fail = 0;
#undef REFUSE

    /* the decoder refuses an uppercase name byte */
    base_req(&req, &rs, chain32, NB_TIP, "punk", 50000000000ULL, coins, 3, &r);
    CHECK(nodus_v2_name_build(&req, b, &err) == NODUS_V2_SPEND_OK, "build");
    dna_env_view_t *v = calloc(1, sizeof(*v));
    nodus_v2_name_decoded_t *d = calloc(1, sizeof(*d));
    CHECK(v && d, "alloc");
    CHECK(dna_env_decode(b->env, b->env_len, v) == 0, "decode");
    b->env[v->call_off[0] + 1] = 'P';
    CHECK(nodus_v2_name_decode(b->env, b->env_len, d) ==
              NODUS_V2_SPEND_ERR_DECODE, "an uppercase name byte is refused");
    free(d);
    free(v);
    nodus_v2_name_built_free(b);
    free(b);
    return 0;
}

/* ══ N4 — the engine on a generation-2 chain ═════════════════════════ */

typedef struct {
    nodus_witness_t *w;
    char             dir[128];
    uint8_t          chain16[16];
    uint8_t          chain32[32];
    uint8_t          nul[64];
} nb_chain_t;

#define NB_CHG   700000000ULL
#define NB_COIN  (NB_P4 + NB_FLOOR + NB_CHG)

static void rmrf_dir(const char *dir) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", dir);
    if (system(cmd) != 0) { /* best effort */ }
}

static int cc_row(nodus_witness_t *w, unsigned param, uint64_t value,
                  uint64_t effective, uint64_t nonce) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "INSERT INTO chain_config_history (param_id, new_value, "
            "effective_block, commit_block, tx_hash, proposal_nonce, "
            "created_at_unix) VALUES (?1, ?2, ?3, 0, zeroblob(64), ?4, 0)",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)param);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)value);
    sqlite3_bind_int64(st, 3, (sqlite3_int64)effective);
    sqlite3_bind_int64(st, 4, (sqlite3_int64)nonce);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    w->chain_config_cache_warm = false;
    return rc == SQLITE_DONE ? 0 : -1;
}

static int seed_coin(nb_chain_t *c) {
    uint8_t pre[160];
    memcpy(pre, g_fp, 128);
    memset(pre + 128, 0xC7, 32);
    if (qgp_sha3_512(pre, sizeof(pre), c->nul) != 0) return -1;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(c->w->db,
            "INSERT INTO utxo_set (nullifier, owner, amount, token_id, "
            "tx_hash, output_index, block_height, created_at, "
            "unlock_block, domain_id) VALUES "
            "(?1, ?2, ?3, zeroblob(64), zeroblob(64), 0, 0, 0, 0, 1)",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_blob(st, 1, c->nul, 64, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, g_fp, 128, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 3, (sqlite3_int64)NB_COIN);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

/* HF-2 on from 1, param 9 (D2) effective h9, the coin — all BEFORE the
 * engine genesis (test_hf4_names_engine.c fx_open). */
static int chain_open(nb_chain_t *c, uint64_t h9) {
    memset(c, 0, sizeof(*c));
    c->w = calloc(1, sizeof(*c->w));
    if (!c->w) return -1;
    c->w->cached_committee_epoch_start = UINT64_MAX;
    snprintf(c->dir, sizeof(c->dir), "/tmp/test_v2_name_build_XXXXXX");
    if (!mkdtemp(c->dir)) return -1;
    snprintf(c->w->data_path, sizeof(c->w->data_path), "%s", c->dir);
    memset(c->chain16, 0x4D, sizeof(c->chain16));
    if (v2x_seed_prepare(c->w, c->chain16, 0) != 0) return -1;
    if (cc_row(c->w, DNAC_CFG_HF2_ACTIVE, DNAC_CFG_HF2_ACTIVE_ON, 1, 11) != 0)
        return -1;
    if (cc_row(c->w, DNAC_CFG_RULESET_GEN2,
               (uint64_t)DNAC_CFG_RULESET_GEN2_D2, h9, 12) != 0)
        return -1;
    if (seed_coin(c) != 0) return -1;
    v2x_seed_not_real(V2X_SEED_NOT_REAL_UTXOS);
    if (v2x_seed_genesis(c->w, c->chain16, 0, NULL, 0, NULL) != 0) return -1;
    return nodus_witness_v2_chain_id(c->w, c->chain32);
}

static void chain_close(nb_chain_t *c) {
    if (!c->w) return;
    if (c->w->db) sqlite3_close(c->w->db);
    free(c->w);
    c->w = NULL;
    rmrf_dir(c->dir);
}

static int apply_block(nb_chain_t *c, uint64_t h,
                       const nodus_v2_envelope_t *envs, size_t n,
                       uint32_t *code0) {
    nodus_v2_tx_result_t res[2];
    nodus_v2_block_t b;
    if (n > 2) return -1;
    memset(res, 0, sizeof(res));
    memset(&b, 0, sizeof(b));
    b.global_height = h;
    b.epoch = nodus_v2_epoch_for_height(h);
    b.envs = envs;
    b.n_envs = n;
    b.cmt.results = res;
    b.cmt.results_cap = 2;
    if (v2x_cmt_apply(c->w, &b) != 0) return -1;
    if (code0 && n > 0) *code0 = res[0].code;
    return 0;
}

static int q_u64(nodus_witness_t *w, const char *sql, uint64_t *out) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    int rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) *out = (uint64_t)sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return rc == SQLITE_ROW ? 0 : -1;
}

static int t_engine(void) {
    const uint64_t H = 4;
    nb_chain_t c;
    CHECK((uint64_t)DNAC_EPOCH_LENGTH > 8, "no epoch boundary among 1..4");
    CHECK(chain_open(&c, H) == 0, "seeded chain (HF-2 on, vote at 4, coin)");
    for (uint64_t h = 1; h < H; h++)
        CHECK(apply_block(&c, h, NULL, 0, NULL) == 0, "idle block");
    uint64_t tip = 0;
    CHECK(nodus_witness_v2_tip_height(c.w, &tip) == 0 && tip == H - 1,
          "tip = H - 1 (the switch committed)");

    nodus_v2_ruleset_id_t rs;
    CHECK(table_rs(&rs) == 0, "generation-2 ruleset (compiled table)");
    nodus_v2_name_coin_t coin;
    memset(&coin, 0, sizeof(coin));
    memcpy(coin.nul, c.nul, 64);
    coin.amount = NB_COIN;

    nb_rand_t r = { 0x30, 0, 0 };
    nodus_v2_name_req_t req;
    base_req(&req, &rs, c.chain32, tip, "punk", NB_P4, &coin, 1, &r);
    nodus_v2_name_built_t *b = calloc(1, sizeof(*b));
    nodus_v2_name_built_t *bp = calloc(1, sizeof(*bp));
    CHECK(b && bp, "alloc");
    nodus_v2_name_err_t err;
    CHECK(nodus_v2_name_build(&req, b, &err) == NODUS_V2_SPEND_OK,
          "the library builds 'punk'");
    CHECK(b->change == NB_CHG && b->fee == NB_FLOOR, "change and fee");

    /* the browser's ruleset source gives the same intent */
    {
        nodus_v2_ruleset_id_t prs;
        dna_meter_policy_t pol;
        CHECK(nodus_v2_ruleset_from_pins_gen(2, &prs, &pol) ==
                  NODUS_V2_SPEND_OK, "generation-2 pins");
        r.next = 0x30; r.calls = 0;
        base_req(&req, &prs, c.chain32, tip, "punk", NB_P4, &coin, 1, &r);
        CHECK(nodus_v2_name_build(&req, bp, &err) == NODUS_V2_SPEND_OK,
              "the pins-built twin");
        CHECK(memcmp(bp->intent_id, b->intent_id, 64) == 0 &&
              bp->env_len == b->env_len, "pins == compiled table");
        nodus_v2_name_built_free(bp);
    }

    /* CheckTx's seam admits it */
    {
        char reason[256];
        reason[0] = '\0';
        nodus_v2_env_dry_run_t *d = calloc(1, sizeof(*d));
        CHECK(d != NULL, "alloc");
        int rc = nodus_witness_v2_env_dry_run(c.w, b->env, b->env_len, NULL,
                                              d, reason, sizeof(reason));
        if (rc != 0 && reason[0])
            fprintf(stderr, "  (dry run rc %d: %s)\n", rc, reason);
        int ok = rc == 0 && d->code == NODUS_V2_TX_OK &&
                 memcmp(d->wire_id, b->wire_id, 64) == 0 &&
                 memcmp(d->intent_id, b->intent_id, 64) == 0;
        nodus_witness_v2_env_dry_run_free(d);
        free(d);
        CHECK(ok, "admitted; the engine derives the builder's ids");
    }

    /* and block H applies it */
    uint64_t pool0 = 0, pool1 = 0, nrows = 0;
    CHECK(q_u64(c.w, "SELECT reward_pool FROM supply_tracking WHERE id = 1",
                &pool0) == 0, "pool before");
    {
        nodus_v2_envelope_t env[1] = { { b->env, b->env_len } };
        uint32_t code = 0xFFFFFFFFu;
        CHECK(apply_block(&c, H, env, 1, &code) == 0, "block H");
        CHECK(code == NODUS_V2_TX_OK, "the registration applies");
    }
    CHECK(q_u64(c.w, "SELECT reward_pool FROM supply_tracking WHERE id = 1",
                &pool1) == 0 && pool1 == pool0 + NB_FLOOR + NB_P4,
          "the reward pool rose by exactly fee + price");
    CHECK(q_u64(c.w, "SELECT COUNT(*) FROM v2_names WHERE name = x'70756e6b'",
                &nrows) == 0 && nrows == 1, "v2_names holds 'punk'");
    {
        sqlite3_stmt *st = NULL;
        CHECK(sqlite3_prepare_v2(c.w->db, "SELECT owner, registered_height "
                                 "FROM v2_names WHERE name = x'70756e6b'",
                                 -1, &st, NULL) == SQLITE_OK, "prepare");
        int ok = sqlite3_step(st) == SQLITE_ROW &&
                 sqlite3_column_bytes(st, 0) == 64 &&
                 memcmp(sqlite3_column_blob(st, 0), g_fp_raw, 64) == 0 &&
                 (uint64_t)sqlite3_column_int64(st, 1) == H;
        sqlite3_finalize(st);
        CHECK(ok, "owner = this key, registered at H");
    }
    nodus_v2_name_built_free(b);
    free(b);
    free(bp);
    chain_close(&c);
    return 0;
}

int main(void) {
    static const struct {
        const char *name;
        int (*fn)(void);
    } cases[] = {
        { "helpers",          t_helpers },
        { "fixture_and_cli",  t_fixture },
        { "refusals",         t_refusals },
        { "engine_gen2",      t_engine },
    };
    size_t failed = 0, n = sizeof(cases) / sizeof(cases[0]);
    if (keys_init() != 0) {
        fprintf(stderr, "test_v2_name_build: key generation failed\n");
        return 1;
    }
    for (size_t i = 0; i < n; i++) {
        int rc = cases[i].fn();
        fprintf(stderr, "%-20s %s\n", cases[i].name, rc == 0 ? "ok" : "FAIL");
        if (rc != 0) failed++;
    }
    fprintf(stderr, "test_v2_name_build: %zu/%zu cases passed, %d checks\n",
            n - failed, n, g_checks);
    return failed ? 1 : 0;
}
