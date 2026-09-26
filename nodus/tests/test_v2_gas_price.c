/**
 * @file nodus/tests/test_v2_gas_price.c
 * @brief HF-1 — the gas price as a chain_config parameter (id 5,
 *        GAS_PRICE_RAW_PER_UNIT) and the engine's fee rule
 *        (`env_gas_price_check`, nodus_witness_v2_apply.c), driven over a
 *        REAL derived version-3 chain.
 *
 * Governing records: docs/plans/decisions/2026-09-25-gas-price.md (incl.
 * the 2026-09-26 detail decisions and "HF-1 O4": MAX 1 000 000 raw/unit)
 * and the design docs/plans/2026-09-26-hf1-gas-price-design.md (§2, D1-D4,
 * G1-G4).
 *
 * ── WHAT THIS PROVES ────────────────────────────────────────────────────
 *  1. t_scalar_rule_matrix — the ONE (param, value) authority,
 *     nodus_chain_config_scalar_rules, admits id 5 at 0, 1 and MAX and
 *     refuses MAX + 1; id 5's grace class is ERGONOMIC. False if the id
 *     were still outside the allowlist (the pre-HF-1 `default: -1`) or the
 *     ceiling were off by one.
 *  2. t_price_rule — on one chain:
 *     block 1 (no price row active, rule OFF) commits a SYSTEM-only
 *     governance envelope that sets price 121 from height 2, and a CORE
 *     envelope creating six zero-amount rows;
 *     cache ≡ DB: nodus_chain_config_get_u64 for id 5 answers, at every
 *     probed height, exactly what a direct SQL read of
 *     chain_config_history answers, warm and after a forced re-warm;
 *     the CheckTx dry run at tip + 1 = 2 refuses a spend paying one raw
 *     under units × price with item code 9 and admits the exactly-paying
 *     one;
 *     block 2 (price 121): an underpaying spend, a spend whose
 *     units × price overflows u64, a CORE envelope at fee 0 and a MIXED
 *     SYSTEM + CORE envelope underpaying are ALL refused with code 9,
 *     each reporting gas_wanted = gas_used = 0 (the refusal precedes the
 *     reservation), and the ledger is byte-identical afterwards
 *     (v2x_cmt_refused's digest oracle) — design G1;
 *     block 3: the exactly-paying spend APPLIES and a SYSTEM-only
 *     governance envelope at fee 0 APPLIES while the price is active —
 *     design G3 (a vote can always lower the price again); it sets 50
 *     from height 4;
 *     block 4 (price 50: 10 000 units × 50 = 500 000 < the 0.01 floor):
 *     a spend paying 999 999 is refused with code 9 (the floor is the
 *     lower bound of the requirement once the rule is on) and one paying
 *     exactly the floor applies.
 *  3. t_rule_off_is_inert (design D3, the part a unit test can reach) —
 *     twin chains (same derivation, same chain id): X has no id-5 row at
 *     all, Y has a price-0 row active. On both, a spend paying 3 raw —
 *     below any price and below the flat floor — is admitted by the dry
 *     run and APPLIES with the same code, gas_wanted and gas_used, and
 *     block 2's tx_root is identical on both chains.
 *  4. t_cache_capacity — 64 rows of one param: the cache warms and
 *     answers the 64th; 65 rows: the cache stays COLD and get_u64 answers
 *     the 65th (the DB fallback), before and after a forced re-warm
 *     (nodus/BUGS.md "chain_config cache keeps only the OLDEST 64 rows").
 *
 * A NOTE ON CASE 4's rows: they are written directly into
 * chain_config_history; no block is applied after them.
 *
 * ── WHAT IT REQUIRES ────────────────────────────────────────────────────
 * Compile flags: none beyond a default build (it assumes block heights
 * 1-4 do not cross an epoch boundary — true for any DNAC_EPOCH_LENGTH
 * above 4, including the harness's short-epoch 15). Environment: none.
 * SQLite >= 3.35.0 (inherited from nodus_witness_v2_gen_derive_v3).
 *
 * ── WHAT IT LEAVES BEHIND ───────────────────────────────────────────────
 * One `/tmp/v2x_gp_*` directory per chain, removed at close. A case that
 * aborts through CHECK leaves its directories behind (this tree's
 * fixture convention, test_cmt_app.c "FIXTURE LIFETIME").
 *
 * ── HOW IT CAN LIE ──────────────────────────────────────────────────────
 *  1. The runtime is the SCRIPTED table (v2_exec_fixture.h): it lets an
 *     envelope carry ANY fee and needs no signatures, which is what makes
 *     the fee rule isolatable — but its exec hooks enforce no flat fee
 *     floor and credit no fee anywhere. What is proven is the ENGINE's
 *     rule (the one helper both callers run), not the native CORE exec's
 *     unchanged floors (nodus_witness_rt_native.c).
 *  2. The scripted SYSTEM adapter does NOT invalidate the chain_config
 *     lookup cache when it inserts a row — the production adapter does
 *     (nodus_witness_rt_native.c, the `cc_row` branch of the SYSTEM
 *     mutate: `w->chain_config_cache_warm = false`). After every block
 *     that commits an id-5 row this file clears the flag itself, standing
 *     in for that one production line. Without it the cache would be
 *     stale BY THE FIXTURE, not by the code under test.
 *  3. D3 is only HALF provable here. The design's D3 is "a chain with no
 *     id-5 row behaves byte-identically to 0.19.79"; a unit test has no
 *     0.19.79 engine to compare against. What case 3 proves is that with
 *     the rule off nothing about the item changes between "no row" and
 *     "a price-0 row". The GLOBAL roots of X and Y are NOT compared: the
 *     price-0 row is itself committed state (chain_config_root is a
 *     SYSTEM leg, nodus_chain_config.h), so they differ by construction.
 *     The mixed-binary proof is the harness scenario (design §6).
 *  4. Written, compiled, NOT RUN by its author (the BUILDER rule): the
 *     first run is the ORCHESTRATOR's. The 10 000-unit ceiling of the
 *     scripted spend is the one test_cmt_app.c verifies for the same
 *     envelope shape (TEST_APP_ENV_CEILING); the six-row CREATE envelope
 *     declares the same ceiling and its static cost was estimated, not
 *     measured, at roughly 3 000 units (all weights 1,
 *     nodus_witness_runtime.c).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_v2_apply.h"
#include "witness/nodus_witness_v2_env.h"
#include "witness/nodus_witness_v2_produce.h"   /* v2_tip_height          */
#include "nodus/nodus_chain_config.h"
#include "nodus/nodus_types.h"                  /* NODUS_W_BASE_TX_FEE    */

#include "dnac/dnac.h"
#include "dnac/ledger_ids.h"

#include "v2_exec_fixture.h"
#include "v2_genesis_fixture.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>

#define CHECK(cond, msg) do {                                              \
    if (!(cond)) {                                                         \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, \
                (msg));                                                    \
        return 1;                                                          \
    }                                                                      \
    g_checks++;                                                            \
} while (0)

static int g_checks = 0;

#define GP_PARAM     ((uint8_t)DNAC_CFG_GAS_PRICE_RAW_PER_UNIT)
#define GP_UNITS     10000ULL   /* the scripted spend's declared ceiling —
                                 * test_cmt_app.c TEST_APP_ENV_CEILING   */
#define GP_PRICE     121ULL     /* the decision's initial price           */
#define GP_PRICE2    50ULL      /* 10 000 x 50 = 500 000 < the floor      */
#define GP_FLOOR     (DNAC_MIN_FEE_RAW > NODUS_W_BASE_TX_FEE \
                          ? DNAC_MIN_FEE_RAW : NODUS_W_BASE_TX_FEE)

_Static_assert(GP_UNITS * GP_PRICE > GP_FLOOR,
               "the price-121 cases need units x price above the floor");
_Static_assert(GP_UNITS * GP_PRICE2 < GP_FLOOR,
               "the price-50 cases need units x price below the floor");

/* ══ envelope builders (scripted runtime, v2_exec_fixture.h) ═════════ */

/** One CORE leg CREATEing a zero-amount row for each tag (ascending —
 *  the canonical effect order). Amount 0: the conservation invariant
 *  sums utxo_set amounts, so these rows move no value
 *  (test_cmt_app.c ckt_row_insert's reasoning). */
static int env_core_create(v2x_env_t *e, const uint8_t *tags, uint16_t n)
{
    uint8_t         keys[8][64];
    uint8_t         zero8[8];
    dna_effect_in_t effs[8];
    uint8_t         res[2048], call[2200];
    size_t          rl = 0;
    uint32_t        cl;
    v2x_leg_t       leg;

    if (n == 0 || n > 8) return -1;
    memset(zero8, 0, sizeof(zero8));
    memset(effs, 0, sizeof(effs));
    for (uint16_t i = 0; i < n; i++) {
        memset(keys[i], tags[i], 64);
        effs[i].hdr.op_id       = V2X_OP_UTXO;
        effs[i].hdr.effect_kind = DNA_EFFECT_CREATE;
        effs[i].hdr.precond_tag = DNA_EFFECT_PRE_ABSENT;
        effs[i].hdr.key_len     = 64;
        effs[i].hdr.value_len   = 8;
        effs[i].key             = keys[i];
        effs[i].value           = zero8;
    }
    if (v2x_effres(res, sizeof(res), effs, n, &rl) != 0) return -1;
    cl = v2x_script_build(call, sizeof(call), NULL, 0, res, rl);
    if (cl == 0) return -1;
    memset(&leg, 0, sizeof(leg));
    leg.domain_id        = DNA_DOMAIN_CORE;
    leg.runtime_op       = 1;
    leg.call             = call;
    leg.call_len         = cl;
    leg.max_effects      = n;
    leg.max_effect_bytes = 2048;
    return v2x_env_build_ex(e, GP_UNITS, 0, 0, &leg, 1);
}

/** The CORE leg of a scripted spend: DELETE row `tag` (PRE_EXISTS). */
static int spend_leg_call(uint8_t tag, uint8_t *call, size_t cap,
                          uint32_t *cl_out)
{
    uint8_t         key[64], res[512];
    size_t          rl = 0;
    dna_effect_in_t eff;

    memset(key, tag, sizeof(key));
    memset(&eff, 0, sizeof(eff));
    eff.hdr.op_id       = V2X_OP_UTXDEL;
    eff.hdr.effect_kind = DNA_EFFECT_DELETE;
    eff.hdr.precond_tag = DNA_EFFECT_PRE_EXISTS;
    eff.hdr.key_len     = 64;
    eff.key             = key;
    if (v2x_effres(res, sizeof(res), &eff, 1, &rl) != 0) return -1;
    *cl_out = v2x_script_build(call, cap, NULL, 0, res, rl);
    return *cl_out ? 0 : -1;
}

/** A one-leg CORE "spend" of row `tag` paying `fee`, declaring `units`. */
static int env_spend(v2x_env_t *e, uint8_t tag, uint64_t fee, uint64_t units)
{
    uint8_t   call[600];
    uint32_t  cl = 0;
    v2x_leg_t leg;

    if (spend_leg_call(tag, call, sizeof(call), &cl) != 0) return -1;
    memset(&leg, 0, sizeof(leg));
    leg.domain_id        = DNA_DOMAIN_CORE;
    leg.runtime_op       = 1;
    leg.call             = call;
    leg.call_len         = cl;
    leg.max_effects      = 4;
    leg.max_effect_bytes = 2048;
    return v2x_env_build_ex(e, units, 0, fee, &leg, 1);
}

/** The SYSTEM leg's call: CREATE chain_config_history (id 5, eff) = v. */
static int price_leg_call(uint64_t eff, uint64_t value, uint8_t *call,
                          size_t cap, uint32_t *cl_out)
{
    uint8_t key[12], val[8], res[512];
    size_t  rl = 0;

    v2x_put32(key, (uint32_t)GP_PARAM);
    v2x_put64(key + 4, eff);
    v2x_put64(val, value);
    if (v2x_eff1(res, sizeof(res), V2X_OP_CC, DNA_EFFECT_CREATE,
                 DNA_EFFECT_PRE_ABSENT, key, 12, val, 8, &rl) != 0)
        return -1;
    *cl_out = v2x_script_build(call, cap, NULL, 0, res, rl);
    return *cl_out ? 0 : -1;
}

/** A SYSTEM-ONLY governance envelope setting the price — fee `fee`. */
static int env_price(v2x_env_t *e, uint64_t eff, uint64_t value, uint64_t fee)
{
    uint8_t   call[600];
    uint32_t  cl = 0;
    v2x_leg_t leg;

    if (price_leg_call(eff, value, call, sizeof(call), &cl) != 0) return -1;
    memset(&leg, 0, sizeof(leg));
    leg.domain_id        = DNA_DOMAIN_SYSTEM;
    leg.runtime_op       = 1;
    leg.call             = call;
    leg.call_len         = cl;
    leg.max_effects      = 4;
    leg.max_effect_bytes = 2048;
    return v2x_env_build_ex(e, GP_UNITS, 0, fee, &leg, 1);
}

/** A MIXED envelope: a SYSTEM price leg + a CORE spend of row `tag`.
 *  One non-SYSTEM leg is enough to lose the governance exemption. */
static int env_mixed(v2x_env_t *e, uint64_t eff, uint8_t tag, uint64_t fee)
{
    uint8_t   scall[600], ccall[600];
    uint32_t  scl = 0, ccl = 0;
    v2x_leg_t legs[2];

    if (price_leg_call(eff, 7, scall, sizeof(scall), &scl) != 0 ||
        spend_leg_call(tag, ccall, sizeof(ccall), &ccl) != 0)
        return -1;
    memset(legs, 0, sizeof(legs));
    legs[0].domain_id        = DNA_DOMAIN_SYSTEM;
    legs[0].runtime_op       = 1;
    legs[0].call             = scall;
    legs[0].call_len         = scl;
    legs[0].max_effects      = 4;
    legs[0].max_effect_bytes = 2048;
    legs[1].domain_id        = DNA_DOMAIN_CORE;
    legs[1].runtime_op       = 1;
    legs[1].call             = ccall;
    legs[1].call_len         = ccl;
    legs[1].max_effects      = 4;
    legs[1].max_effect_bytes = 2048;
    return v2x_env_build_ex(e, GP_UNITS, 0, fee, legs, 2);
}

/* ══ chain helpers ═══════════════════════════════════════════════════ */

static void mk_block(nodus_v2_block_t *b, uint64_t h,
                     const nodus_v2_envelope_t *envs, size_t n)
{
    memset(b, 0, sizeof(*b));
    b->global_height = h;
    b->epoch         = nodus_v2_epoch_for_height(h);
    b->envs          = envs;
    b->n_envs        = n;
}

/** Does CORE row `tag` exist? 1 / 0 / -1. */
static int row_exists(nodus_witness_t *w, uint8_t tag)
{
    sqlite3_stmt *st = NULL;
    uint8_t       key[64];
    int           rc;

    memset(key, tag, sizeof(key));
    if (sqlite3_prepare_v2(w->db,
            "SELECT 1 FROM utxo_set WHERE nullifier = ?1 AND domain_id = ?2",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_blob(st, 1, key, 64, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)DNA_DOMAIN_CORE);
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_ROW ? 1 : (rc == SQLITE_DONE ? 0 : -1);
}

/** The id-5 value active at `h` by a DIRECT read of the table — the
 *  "DB" side of cache ≡ DB. 0 row found / 1 none (value = 0) / -1. */
static int price_sql(nodus_witness_t *w, uint64_t h, uint64_t *out)
{
    sqlite3_stmt *st = NULL;
    int           rc, ret = -1;

    *out = 0;
    if (sqlite3_prepare_v2(w->db,
            "SELECT new_value FROM chain_config_history "
            "WHERE param_id = ?1 AND effective_block <= ?2 "
            "ORDER BY effective_block DESC LIMIT 1", -1, &st, NULL)
        != SQLITE_OK)
        return -1;
    sqlite3_bind_int(st, 1, (int)GP_PARAM);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)h);
    rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) {
        *out = (uint64_t)sqlite3_column_int64(st, 0);
        ret = 0;
    } else if (rc == SQLITE_DONE) {
        ret = 1;
    }
    sqlite3_finalize(st);
    return ret;
}

/** The dry run CheckTx calls, on one envelope. Returns its rc; *code
 *  receives out->code. */
static int dry(nodus_witness_t *w, const v2x_env_t *e, uint32_t *code)
{
    char                    reason[256];
    nodus_v2_env_dry_run_t *d = calloc(1, sizeof(*d));   /* ~70 KB */
    int                     rc;

    if (!d) return -100;
    reason[0] = '\0';
    rc = nodus_witness_v2_env_dry_run(w, e->bytes, e->len, NULL, d, reason,
                                      sizeof(reason));
    *code = d->code;
    if (rc != 0 && reason[0])
        fprintf(stderr, "  (dry run rc %d: %s)\n", rc, reason);
    nodus_witness_v2_env_dry_run_free(d);
    free(d);
    return rc;
}

/** tx_root of the committed block at height h. 0 / -1. */
static int tx_root_at(nodus_witness_t *w, uint64_t h, uint8_t out[64])
{
    sqlite3_stmt *st = NULL;
    int           ret = -1;

    if (sqlite3_prepare_v2(w->db,
            "SELECT tx_root FROM v2_blocks WHERE global_height = ?1",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)h);
    if (sqlite3_step(st) == SQLITE_ROW && sqlite3_column_bytes(st, 0) == 64) {
        memcpy(out, sqlite3_column_blob(st, 0), 64);
        ret = 0;
    }
    sqlite3_finalize(st);
    return ret;
}

/* ══ 1. the scalar rule matrix ═══════════════════════════════════════ */

static int t_scalar_rule_matrix(void)
{
    /* signed_at 1, valid_before 1000 > effective 500 > signed_at: the
     * window shape is legal, so only the (param, value) half decides. */
    CHECK(nodus_chain_config_scalar_rules(GP_PARAM, 0, 1, 1000, 500) == 0,
          "value 0 is LEGAL (switches the rule off again)");
    CHECK(nodus_chain_config_scalar_rules(GP_PARAM, 1, 1, 1000, 500) == 0,
          "value 1 is legal");
    CHECK(nodus_chain_config_scalar_rules(GP_PARAM, DNAC_CFG_MAX_GAS_PRICE,
                                          1, 1000, 500) == 0,
          "value MAX (1 000 000) is legal");
    CHECK(nodus_chain_config_scalar_rules(GP_PARAM,
                                          DNAC_CFG_MAX_GAS_PRICE + 1,
                                          1, 1000, 500) != 0,
          "value MAX + 1 is refused");
    CHECK(DNAC_CFG_MAX_GAS_PRICE == 1000000ULL,
          "the ceiling is the O4-approved 1 000 000 raw/unit");
    CHECK(nodus_chain_config_grace_for_param(GP_PARAM) ==
              (uint64_t)DNAC_CHAIN_CONFIG_GRACE_ERGONOMIC_BLOCKS,
          "grace class ERGONOMIC (decision detail 3)");
    CHECK(nodus_chain_config_scalar_rules(
              (uint8_t)(DNAC_CFG_PARAM_MAX_ID + 1), 0, 1, 1000, 500) != 0,
          "the id after the last one stays refused");
    CHECK(DNAC_CFG_PARAM_MAX_ID == DNAC_CFG_GAS_PRICE_RAW_PER_UNIT,
          "id 5 is the allowlist's last id");
    return 0;
}

/* ══ 2. the rule: cache, dry run, apply ══════════════════════════════ */

static int t_price_rule(void)
{
    v2x_chain_t        c;
    v2x_env_t         *e = NULL;
    nodus_v2_block_t  *b = NULL;
    nodus_v2_envelope_t v[4];
    uint32_t           code = 0;
    uint64_t           tip = 0;
    static const uint8_t tags[6] = { 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6 };

    CHECK(v2x_chain_open(&c, "gp_rule", 0x31) == 0, "version-3 chain");
    CHECK(v2x_table_init(c.w) == 0, "the scripted runtime table");
    e = calloc(12, sizeof(*e));
    b = calloc(1, sizeof(*b));
    CHECK(e && b, "alloc");

    /* a chain with no id-5 row: the slot exists and answers "absent" */
    {
        uint64_t p = 99;
        CHECK(nodus_chain_config_get_u64(c.w, GP_PARAM, 1, 0, &p) == 1 &&
              p == 0, "no row: get_u64 answers ABSENT with the default 0 "
                      "(pre-HF-1 it answered -1: id >= CC_PARAM_SLOTS)");
    }

    /* ── block 1 (rule OFF): the price vote + the rows ─────────────── */
    CHECK(env_price(&e[0], 2, GP_PRICE, 0) == 0, "price 121 from height 2");
    CHECK(env_core_create(&e[1], tags, 6) == 0, "six zero-amount rows");
    v[0].env_bytes = e[0].bytes; v[0].env_len = e[0].len;
    v[1].env_bytes = e[1].bytes; v[1].env_len = e[1].len;
    mk_block(b, 1, v, 2);
    CHECK(v2x_cmt_apply_ok(c.w, b) == 0, "block 1 applies, both items");
    /* HOW IT CAN LIE 2: the production SYSTEM adapter's invalidation */
    c.w->chain_config_cache_warm = false;

    /* ── cache ≡ DB for id 5 ────────────────────────────────────────── */
    {
        static const uint64_t hs[] = { 0, 1, 2, 3, 1000 };
        for (int pass = 0; pass < 2; pass++) {
            for (size_t i = 0; i < sizeof(hs) / sizeof(hs[0]); i++) {
                uint64_t pc = 7, pd = 7;
                int rc_c = nodus_chain_config_get_u64(c.w, GP_PARAM, hs[i],
                                                      0, &pc);
                int rc_d = price_sql(c.w, hs[i], &pd);
                CHECK(rc_c >= 0 && rc_d >= 0, "both reads answer");
                CHECK(rc_c == rc_d && pc == pd,
                      "get_u64 (cache) == direct SQL (DB) at every height");
            }
            CHECK(c.w->chain_config_cache_warm &&
                  c.w->chain_config_cache_count[GP_PARAM] == 1,
                  "the cache is warm and holds the one id-5 row");
            c.w->chain_config_cache_warm = false;   /* 2nd pass: re-warm */
        }
    }
    {
        uint64_t p = 0;
        CHECK(nodus_chain_config_get_u64(c.w, GP_PARAM, 1, 0, &p) == 1 &&
              p == 0, "height 1: not yet effective");
        CHECK(nodus_chain_config_get_u64(c.w, GP_PARAM, 2, 0, &p) == 0 &&
              p == GP_PRICE, "height 2: 121");
    }

    /* ── the CheckTx dry run at tip + 1 = 2 ─────────────────────────── */
    CHECK(nodus_witness_v2_tip_height(c.w, &tip) == 0 && tip == 1, "tip 1");
    CHECK(env_spend(&e[2], 0xE1, GP_UNITS * GP_PRICE - 1, GP_UNITS) == 0,
          "a spend paying one raw under units x price");
    CHECK(env_spend(&e[3], 0xE2, GP_UNITS * GP_PRICE, GP_UNITS) == 0,
          "a spend paying exactly units x price");
    CHECK(dry(c.w, &e[2], &code) == -1 && code == NODUS_V2_TX_ERR_FEE,
          "dry run: the underpaying spend is refused with code 9");
    CHECK(dry(c.w, &e[3], &code) == 0 && code == NODUS_V2_TX_OK,
          "dry run: the exactly-paying spend is admitted");

    /* ── block 2 (price 121): four refusals, nothing moves ──────────── */
    CHECK(env_spend(&e[4], 0xE3, UINT64_MAX, UINT64_MAX / 2 + 1) == 0,
          "units x 121 overflows u64 — even a UINT64_MAX fee cannot pay");
    CHECK(env_spend(&e[5], 0xE4, 0, GP_UNITS) == 0, "a CORE spend at fee 0");
    CHECK(env_mixed(&e[6], 100, 0xE5, GP_UNITS * GP_PRICE - 1) == 0,
          "a SYSTEM + CORE envelope underpaying");
    v[0].env_bytes = e[2].bytes; v[0].env_len = e[2].len;
    v[1].env_bytes = e[4].bytes; v[1].env_len = e[4].len;
    v[2].env_bytes = e[5].bytes; v[2].env_len = e[5].len;
    v[3].env_bytes = e[6].bytes; v[3].env_len = e[6].len;
    mk_block(b, 2, v, 4);
    CHECK(v2x_cmt_refused(c.w, b, 0, &code) == 0,
          "block 2 commits, EVERY item refused, the ledger byte-identical");
    for (size_t i = 0; i < 4; i++) {
        CHECK(b->cmt.results[i].code == NODUS_V2_TX_ERR_FEE,
              "each refusal is code 9 (FEE)");
        CHECK(b->cmt.results[i].gas_wanted == 0 &&
              b->cmt.results[i].gas_used == 0,
              "and reserved nothing: gas_wanted = gas_used = 0");
    }
    CHECK(row_exists(c.w, 0xE1) == 1 && row_exists(c.w, 0xE3) == 1 &&
          row_exists(c.w, 0xE4) == 1 && row_exists(c.w, 0xE5) == 1,
          "no refused spend deleted its row");

    /* ── block 3: the paying spend + governance at fee 0 ────────────── */
    CHECK(env_price(&e[7], 4, GP_PRICE2, 0) == 0,
          "a SYSTEM-only governance envelope at fee 0: price 50 from 4");
    v[0].env_bytes = e[3].bytes; v[0].env_len = e[3].len;
    v[1].env_bytes = e[7].bytes; v[1].env_len = e[7].len;
    mk_block(b, 3, v, 2);
    CHECK(v2x_cmt_apply_ok(c.w, b) == 0,
          "block 3: the exactly-paying spend AND the fee-0 governance "
          "envelope both apply while the price is active (G3)");
    CHECK(b->cmt.results[0].gas_wanted > 0,
          "the paying spend reserved its units");
    CHECK(row_exists(c.w, 0xE2) == 0, "its row is spent");
    c.w->chain_config_cache_warm = false;         /* HOW IT CAN LIE 2 */

    /* ── block 4 (price 50): the floor is the lower bound ───────────── */
    CHECK(env_spend(&e[8], 0xE1, GP_FLOOR - 1, GP_UNITS) == 0,
          "a spend above units x 50 but one raw under the floor");
    CHECK(env_spend(&e[9], 0xE6, GP_FLOOR, GP_UNITS) == 0,
          "a spend paying exactly the floor");
    v[0].env_bytes = e[8].bytes; v[0].env_len = e[8].len;
    v[1].env_bytes = e[9].bytes; v[1].env_len = e[9].len;
    mk_block(b, 4, v, 2);
    CHECK(v2x_cmt_apply(c.w, b) == 0, "block 4 commits");
    CHECK(b->cmt.results[0].code == NODUS_V2_TX_ERR_FEE,
          "below max(units x price, floor): code 9");
    CHECK(b->cmt.results[1].code == NODUS_V2_TX_OK,
          "exactly the floor (>= units x 50): applied");
    CHECK(row_exists(c.w, 0xE1) == 1 && row_exists(c.w, 0xE6) == 0,
          "only the paying spend moved state");

    free(b);
    free(e);
    v2x_chain_close(&c);
    return 0;
}

/* ══ 3. D3: the rule off is inert ════════════════════════════════════ */

static int t_rule_off_is_inert(void)
{
    v2x_chain_t        x, y;
    v2x_env_t         *e = NULL;
    nodus_v2_block_t  *b = NULL;
    nodus_v2_envelope_t v[2];
    nodus_v2_tx_result_t rx, ry;
    uint8_t            txr_x[64], txr_y[64];
    uint32_t           code = 0;
    uint64_t           p = 0;
    static const uint8_t tag1[1] = { 0xD1 };

    CHECK(v2x_chain_open(&x, "gp_d3x", 0x32) == 0, "chain X");
    CHECK(v2x_chain_open(&y, "gp_d3y", 0x32) == 0, "chain Y");
    CHECK(memcmp(x.chain32, y.chain32, 32) == 0,
          "the twins are the SAME chain (same derivation, same id)");
    CHECK(v2x_table_init(x.w) == 0 && v2x_table_init(y.w) == 0,
          "the scripted runtime table on both");
    e = calloc(3, sizeof(*e));
    b = calloc(1, sizeof(*b));
    CHECK(e && b, "alloc");

    CHECK(env_core_create(&e[0], tag1, 1) == 0, "row 0xD1");
    CHECK(env_price(&e[1], 2, 0, 0) == 0, "a price-0 row from height 2");
    CHECK(env_spend(&e[2], 0xD1, 3, GP_UNITS) == 0,
          "a spend paying 3 raw — below any price, below the flat floor");

    /* block 1: X carries the row only; Y also commits price 0 */
    v[0].env_bytes = e[0].bytes; v[0].env_len = e[0].len;
    mk_block(b, 1, v, 1);
    CHECK(v2x_cmt_apply_ok(x.w, b) == 0, "X block 1");
    v[1].env_bytes = e[1].bytes; v[1].env_len = e[1].len;
    mk_block(b, 1, v, 2);
    CHECK(v2x_cmt_apply_ok(y.w, b) == 0, "Y block 1");
    y.w->chain_config_cache_warm = false;         /* HOW IT CAN LIE 2 */

    CHECK(nodus_chain_config_get_u64(x.w, GP_PARAM, 2, 0, &p) == 1 && p == 0,
          "X: no id-5 row at all (ABSENT, price 0)");
    CHECK(nodus_chain_config_get_u64(y.w, GP_PARAM, 2, 0, &p) == 0 && p == 0,
          "Y: an ACTIVE row whose value is 0");

    CHECK(dry(x.w, &e[2], &code) == 0 && code == NODUS_V2_TX_OK,
          "X: the dry run admits the 3-raw spend");
    CHECK(dry(y.w, &e[2], &code) == 0 && code == NODUS_V2_TX_OK,
          "Y: the dry run admits the 3-raw spend");

    /* block 2: the SAME bytes on both */
    v[0].env_bytes = e[2].bytes; v[0].env_len = e[2].len;
    mk_block(b, 2, v, 1);
    CHECK(v2x_cmt_apply_ok(x.w, b) == 0, "X block 2: the spend applies");
    rx = b->cmt.results[0];
    mk_block(b, 2, v, 1);
    CHECK(v2x_cmt_apply_ok(y.w, b) == 0, "Y block 2: the spend applies");
    ry = b->cmt.results[0];
    CHECK(rx.code == ry.code && rx.gas_wanted == ry.gas_wanted &&
          rx.gas_used == ry.gas_used && rx.gas_wanted > 0,
          "the same item result on both: code, gas_wanted, gas_used");
    CHECK(tx_root_at(x.w, 2, txr_x) == 0 && tx_root_at(y.w, 2, txr_y) == 0 &&
          memcmp(txr_x, txr_y, 64) == 0,
          "block 2's tx_root is identical on both chains");
    CHECK(row_exists(x.w, 0xD1) == 0 && row_exists(y.w, 0xD1) == 0,
          "the row is spent on both");

    free(b);
    free(e);
    v2x_chain_close(&y);
    v2x_chain_close(&x);
    return 0;
}

/* ══ 4. cache capacity: past the cache, cache ≡ DB still holds ═══════
 *
 * nodus/BUGS.md "chain_config cache keeps only the OLDEST 64 rows": the
 * warm scan used to SKIP rows past the per-param capacity, and since it
 * reads effective_block ASC the skipped rows were the NEWEST, so a warm
 * lookup answered the 64th row forever while the DB fallback answered
 * the real latest one. Fixed: a param that outgrows the cache leaves the
 * cache COLD and every lookup reads the database.
 *
 * Rows are inserted DIRECTLY into chain_config_history: this case
 * applies no block afterwards, so the root legs the direct write moves
 * are never checked (the engine's untouched-domain guard only runs when
 * a block is applied). Row k (1-based) has effective_block 10·k and
 * value k. The capacity is 64 — the second dimension of
 * nodus_witness.h `chain_config_cache[...][64]`.
 *
 * RED on the unfixed tree: with 65 rows the warm cache answered 64 at
 * height 10 000 and chain_config_cache_warm was true. */
static int insert_rows(nodus_witness_t *w, int n)
{
    sqlite3_stmt *st = NULL;
    uint8_t       txh[64];

    memset(txh, 0xC5, sizeof(txh));
    if (sqlite3_prepare_v2(w->db,
            "INSERT INTO chain_config_history (param_id, new_value, "
            "effective_block, commit_block, tx_hash, proposal_nonce, "
            "created_at_unix) VALUES (?1, ?2, ?3, 1, ?4, ?5, 0)",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    for (int k = 1; k <= n; k++) {
        sqlite3_reset(st);
        sqlite3_bind_int(st, 1, (int)GP_PARAM);
        sqlite3_bind_int64(st, 2, (sqlite3_int64)k);
        sqlite3_bind_int64(st, 3, (sqlite3_int64)(10 * k));
        sqlite3_bind_blob(st, 4, txh, 64, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 5, (sqlite3_int64)k);
        if (sqlite3_step(st) != SQLITE_DONE) {
            sqlite3_finalize(st);
            return -1;
        }
    }
    sqlite3_finalize(st);
    return 0;
}

static int cache_cap_case(int n_rows, int expect_warm)
{
    v2x_chain_t c;
    uint64_t    p = 0;
    char        tag[32];

    snprintf(tag, sizeof(tag), "gp_cap%d", n_rows);
    CHECK(v2x_chain_open(&c, tag, 0x33) == 0, "version-3 chain");
    CHECK(insert_rows(c.w, n_rows) == 0, "rows inserted");
    c.w->chain_config_cache_warm = false;

    for (int pass = 0; pass < 2; pass++) {
        CHECK(nodus_chain_config_get_u64(c.w, GP_PARAM, 10000, 0, &p) == 0 &&
              p == (uint64_t)n_rows,
              "after the last row's effective height: the LAST row's value");
        CHECK(nodus_chain_config_get_u64(c.w, GP_PARAM, 10 * 64, 0, &p) == 0 &&
              p == 64, "at row 64's effective height: 64");
        CHECK(nodus_chain_config_get_u64(c.w, GP_PARAM, 9, 0, &p) == 1 &&
              p == 0, "before the first row: absent");
        CHECK((c.w->chain_config_cache_warm ? 1 : 0) == expect_warm,
              expect_warm ? "64 rows fit: the cache is warm"
                          : "65 rows do not fit: the cache stays COLD");
        c.w->chain_config_cache_warm = false;      /* 2nd pass: re-warm */
    }
    v2x_chain_close(&c);
    return 0;
}

static int t_cache_capacity(void)
{
    if (cache_cap_case(64, 1) != 0) return 1;
    if (cache_cap_case(65, 0) != 0) return 1;
    return 0;
}

int main(void)
{
    static const struct {
        const char *name;
        int (*fn)(void);
    } cases[] = {
        { "scalar_rule_matrix", t_scalar_rule_matrix },
        { "price_rule",         t_price_rule },
        { "rule_off_is_inert",  t_rule_off_is_inert },
        { "cache_capacity",     t_cache_capacity },
    };
    size_t failed = 0, ncases = sizeof(cases) / sizeof(cases[0]);

    for (size_t i = 0; i < ncases; i++) {
        int rc = cases[i].fn();
        fprintf(stderr, "%-24s %s\n", cases[i].name, rc == 0 ? "ok" : "FAIL");
        if (rc != 0) failed++;
    }
    fprintf(stderr, "test_v2_gas_price: %zu/%zu cases passed, %d checks\n",
            ncases - failed, ncases, g_checks);
    return failed ? 1 : 0;
}
