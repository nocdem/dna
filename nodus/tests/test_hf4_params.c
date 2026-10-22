/**
 * @file nodus/tests/test_hf4_params.c
 * @brief HF-4 part A1 — chain_config params 9-13: the scalar rules, the
 *        grace classes, the ONE stateful-rule authority, the SYSTEM
 *        CHAIN_CONFIG exec hook that applies it, and the cache slots.
 *
 * Design docs/plans/2026-10-02-onchain-names-design.md rev 4 §1.2 / §2
 * Price; decision docs/plans/decisions/2026-10-02-onchain-names.md items
 * 6, 10, 16, 17.
 *
 * ── WHAT IT PROVES ──────────────────────────────────────────────────────
 *  1. ids: RULESET_GEN2 = 9, NAME_PRICE_3P..6P = 10..13 (MAX_ID 21 since
 *     Nodus EVM 14-15, storage reward v1 16 (RETIRED), HF-8 17 and HF-6
 *     18-21), all on the read list;
 *     D2 <= INT64_MAX; SWITCH_SPEC_VERSION 1.
 *  2. scalar rules: param 9 accepts EXACTLY D2 (D2 ± 1, UINT64_MAX
 *     refused; the shared window and int64 rules still apply); params
 *     10-13 accept [10^8, 10^15] inclusive, refuse one past either end;
 *     (param 16 retired, HF-8 param 17, HF-6 param 18: below).
 *  3. grace: 9-13 ERGONOMIC (decision item 17), HF-3's class.
 *  4. nodus_chain_config_stateful_rules — the full matrix: param 9
 *     refused when a param-9 row exists (single use), when HF-2 is off,
 *     when effective-1 is a nonzero epoch-length multiple, when effective
 *     is 0; accepted otherwise (effective 1 included: height 0 is not a
 *     boundary). Params 10-13 refused under generation 0/1, accepted
 *     under 2. Ids 1-8 no stateful rule; 0, 16, 24, 255 refused (22 is
 *     HF-7's RULESET_GEN_ROOTS since P1d — test_hf7_activation.c; 23 the
 *     ML-DSA-87 precompile vote — test_v2_evm.c section 15).
 *  5. the SYSTEM CHAIN_CONFIG exec hook (nodus_rt_system_exec) applies
 *     the SAME rules from the engine-filled ctx facts and its own
 *     runtime's generation: one accepted param-9 leg produces exactly one
 *     CREATE on the chain_config_history op; each stateful refusal is -1
 *     (a verdict, never a -2 fault); params 10-13 refused by the
 *     generation-1 SYSTEM runtime and by a NULL runtime, accepted by the
 *     generation-2 one; the read plan stays EMPTY for 9 and 10-13 (the
 *     single-use rule is an unmetered ctx fact, never a mediated read —
 *     R3-1 F1).
 *  6. cache slots: rows for 9-13 are readable through the three-valued
 *     accessor (no -1 from a missing slot), each in its own slot, and a
 *     far-future param-9 row (effective INT64_MAX - 1) is found by the
 *     engine's "any row" read at INT64_MAX.
 *
 *  HF-6 slice 8c — param 16 RULESET_GEN_STORAGE RETIRED, param 18
 *  RULESET_GEN_ROLES the generation-4 vote (design docs/plans/2026-10-03-
 *  hf5-validator-owner-stake-design.md rev 6 §8, §8.1; decision docs/
 *  plans/decisions/2026-10-09-kurultay-16-hf6-storage-summary.md item 1;
 *  name khan 2026-10-13), added to the sections above:
 *   1. id 16 stays 16 and is OFF the read list (the id-1 treatment); id
 *      18 = RULESET_GEN_ROLES is ON it; D4 <= INT64_MAX and distinct from
 *      D2 and the EVM D.
 *   2. param 16 refused by the scalar rules for EVERY probed value (0, 1,
 *      D2, D4, the EVM D, INT64_MAX, UINT64_MAX); param 18 accepts
 *      EXACTLY D4 (D4 ± 1, 0, D2, the EVM D, UINT64_MAX refused; the
 *      window rule binds); param 9 refuses D4.
 *   3. grace 16 UINT64_MAX (unsatisfiable, the id-1 shape), grace 18
 *      ERGONOMIC.
 *   4. stateful: 16 refused (-1, no case). 18 accepted ONLY with no
 *      param-18 row (a) AND no param-16 row (a') AND HF-2 on (b) AND
 *      judged under EXACTLY generation 3 (c: 0/1/2/4 refused) AND neither
 *      H-1 (d) nor H (e) an epoch boundary: effective 0, E, E+1, 2E,
 *      2E+1 refused, 1 and E+2 accepted. Each fact gates only its param:
 *      the param-16 fact gates 18 and nothing else, the param-18 fact
 *      does not gate 9 or 14, the param-9 fact does not gate 18. K10:
 *      rule (c) keeps the generation-4 edge out of the EVM edge's block.
 *   5. exec hook (EVM-enabled build): a param-18 leg refused (-1) by the
 *      generation-1, -2, -4 and NULL runtimes, accepted by generation 3
 *      (one CREATE keyed 18 ‖ effective); refused by either fact, by HF-2
 *      off and by an H or H-1 boundary; the param-9 fact does NOT gate
 *      it; the 18 fact does NOT gate a param-9 leg; a param-16 leg is
 *      refused by every runtime; the read plan is empty.
 *   6. slot 18 readable; a far-future param-18 row found at INT64_MAX;
 *      slot 16 still readable (the retired id's history is read).
 *
 *  HF-8 (design docs/plans/2026-10-07-delegate-name-required-design.md
 *  rev 2 §1 — param 17 DELEGATE_NAME_REQUIRED, the HF-2/HF-3 switch
 *  shape; Kurultay #11), added to the sections above:
 *   1. id 17 = DELEGATE_NAME_REQUIRED, on the read list (MAX_ID was 17
 *      until HF-6 slice 8a); its value literal is 1.
 *   2. param 17 accepts EXACTLY 1 (0, 2, UINT64_MAX refused; the window
 *      rule binds); id 18 refuses 1.
 *   3. grace 17 ERGONOMIC (its own case — HF-2/HF-3's class).
 *   4. stateful: param 17 refused under generation 0 / 1, accepted under
 *      2 and every later generation, whatever the HF-2 / single-use /
 *      boundary facts (NO single-use rule); the facts form agrees.
 *   6. slot 17 readable; a param-17 row lands in its own slot.
 *  (The CORE SYSFUND name gate it switches is test_v2_native.c §20.)
 *
 *  HF-6 slice 8a (design docs/plans/2026-10-03-hf5-validator-owner-stake-
 *  design.md rev 6 §8 — params 19 STAKE_MIN, 20 POWER_CAP_BPS, 21
 *  STORAGE_BOND; ranges from Kurultay #14 K5 / K9 and #16 khan decision 3;
 *  ERGONOMIC from #16 "4 ok"), added to the sections above:
 *   1. ids 19 / 20 / 21, all three on the read list; since HF-7 P1d
 *      22 RULESET_GEN_ROOTS on the list; since the ML-DSA-87 precompile
 *      MAX_ID = 23 (MLDSA_ACTIVE, on the list) and 24 is the first id past
 *      the end; the named bounds are the records' numbers.
 *   2. scalar: 19 refuses 10^13 - 1, accepts 10^13, 2·10^14 and
 *      INT64_MAX, refuses INT64_MAX + 1 and UINT64_MAX — with a valid
 *      window and nonce, so the refusal can only come from param 19's OWN
 *      upper check (the shared int64 tail never bounds new_value): a 19
 *      case written as "≥ MIN only" fails here. 20: 499 / 3001 refused,
 *      500 / 3000 accepted. 21: 10^13 - 1 / 10^14 + 1 refused, 10^13 /
 *      10^14 accepted. 18 refuses each neighbour's value, 22 (exactly D5)
 *      them and D4, 23 (exactly the ML-DSA literal) them and D5, 24 every
 *      value.
 *   3. grace 19-21 ERGONOMIC.
 *   4. stateful: 19-21 refused under generations 0-3, accepted under 4
 *      whatever the HF-2 / single-use / boundary facts; the facts form
 *      agrees.
 *   5. exec hook (EVM-enabled build): a 19 / 20 / 21 leg refused (-1) by
 *      the generation-1, -2, -3 (EVM) and NULL runtimes, accepted by
 *      generation 4 with exactly ONE CREATE keyed (param ‖ effective);
 *      the read plan is empty; the HF-2 / single-use facts do not gate
 *      them.
 *   6. slots 18-21 readable (no missing-slot -1); a 19 / 20 / 21 row each
 *      lands in its own slot (chain_config_cache_count[21] counted).
 *
 *  HOW IT CAN LIE (HF-6 8c): every "exactly D4" check here holds for any
 *  literal value (D4 is the hf6_vote_oracle.py literal); its correctness
 *  is test_hf4_table.c's KAT and the runtime selfcheck. Section 5's
 *  param-16 / param-18 half does not run in a build without
 *  NODUS_EVM_ENABLED. The same-block check is over the pure rule, not a
 *  block-level run (test_hf4_switch.c has the engine's edges).
 *
 * ── WHAT IT REQUIRES ────────────────────────────────────────────────────
 * Compile flags: none beyond a default build (the grace / epoch tests
 * read DNAC_CHAIN_CONFIG_GRACE_* and DNAC_EPOCH_LENGTH as compiled, so
 * the short-epoch harness build is also valid). Environment: none.
 *
 * ── WHAT IT LEAVES BEHIND ───────────────────────────────────────────────
 * One /tmp/test_hf4_params_XXXXXX directory, removed at the end (left
 * behind if a CHECK aborts).
 *
 * ── HOW IT CAN LIE ──────────────────────────────────────────────────────
 *  - DNAC_CFG_RULESET_GEN2_D2 is the oracle-filled literal (dnac.h, from
 *    shared/dnac/tests/hf4_oracle.py, commit 89f9da09); section 2 proves
 *    "exactly D2" against it by its neighbours (D2 ± 1, UINT64_MAX), not
 *    that the literal itself is right — test_hf4_table.c's selfcheck
 *    re-derivation is that check.
 *  - Section 5 fabricates the auth verdict (quorum met) so the hook
 *    reaches its stateful rules; whether the ENGINE fills ctx facts per
 *    item is test_hf4_switch.c's block-level case, not this file's.
 *  - The client mirror (dnac verify.c) is dnac/tests/test_chain_config_
 *    verify.c, not this file; the responder is test_cc_appr.c.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "nodus/nodus_chain_config.h"
#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_runtime.h"

#include "dnac/dnac.h"
#include "dnac/env_wire.h"
#include "dnac/effect_wire.h"
#include "dnac/domain_wire.h"
#include "dnac/ledger_ids.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <unistd.h>

#define CHECK(cond) do { \
    if (!(cond)) { fprintf(stderr, "CHECK fail at %s:%d: %s\n", \
        __FILE__, __LINE__, #cond); exit(1); } } while (0)

#define E_LEN   ((uint64_t)DNAC_EPOCH_LENGTH)
#define GRACE_E ((uint64_t)DNAC_CHAIN_CONFIG_GRACE_ERGONOMIC_BLOCKS)

/* ── 5. the exec hook harness ───────────────────────────────────────── */

#define CC_CALL_LEN 41u

typedef struct {
    uint8_t  call[CC_CALL_LEN];
    uint8_t  auth[1 + NODUS_RT_AUTH_SIGNER_LEN + 2];
    uint8_t *bytes;
    size_t   len;
    dna_env_view_t view;
} cc_leg_t;

static void put64(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (56 - 8 * i));
}

/* One encoded + decoded single-leg SYSTEM CHAIN_CONFIG envelope. The auth
 * bytes are a zero-filled kind-2 shape: the hook never parses them (the
 * verdict below is the authority), the codec bounds only the length. */
static void cc_leg_build(cc_leg_t *e, uint8_t param, uint64_t value,
                         uint64_t effective, uint64_t valid_before) {
    memset(e, 0, sizeof(*e));
    e->call[0] = param;
    put64(e->call + 1, value);
    put64(e->call + 9, effective);
    put64(e->call + 17, 7);                  /* nonce                    */
    put64(e->call + 25, 1);                  /* signed_at                */
    put64(e->call + 33, valid_before);

    dna_env_leg_in_t leg;
    memset(&leg, 0, sizeof(leg));
    leg.hdr.domain_id            = DNA_DOMAIN_SYSTEM;
    leg.hdr.runtime_op           = DNA_SYSRULE_CHAIN_CONFIG;
    leg.hdr.ruleset_version      = 6;
    leg.hdr.access_mode          = DNA_ENV_ACCESS_INVOKE;
    leg.hdr.auth_kind            = NODUS_RT_AUTHKIND_DSA87_CC_V1;
    leg.hdr.call_len             = CC_CALL_LEN;
    leg.hdr.auth_len             = (uint32_t)sizeof(e->auth);
    leg.hdr.res_max_effects      = 4;
    leg.hdr.res_max_effect_bytes = 4096;
    leg.call_data = e->call;
    leg.auth_data = e->auth;

    dna_env_in_t in;
    memset(&in, 0, sizeof(in));
    in.expiry_height       = 0;
    in.fee_amount          = 0;
    in.res_max_total_units = 200000;
    in.leg_count           = 1;
    in.legs                = &leg;

    CHECK(dna_env_encoded_size(&leg, 1, &e->len) == 0);
    e->bytes = malloc(e->len);
    CHECK(e->bytes != NULL);
    size_t used = 0;
    CHECK(dna_env_encode(&in, e->bytes, e->len, &used) == 0 &&
          used == e->len);
    CHECK(dna_env_decode(e->bytes, e->len, &e->view) == 0);
}

/* HF-6 slice 8c: the two generation-4 vote facts the next run_exec hands
 * the hook — "any param-16 row" (ctx.ruleset_gen_storage_voted, rule
 * (a')) and "any param-18 row" (ctx.ruleset_gen_roles_voted, rule (a));
 * 0 unless a section sets them. */
static uint8_t g_svoted = 0;
static uint8_t g_rvoted = 0;

/* The engine facts the hook receives. The verdict meets BOTH approval
 * rules (7 of 7 seats; power 7 of 7) so only the rule under test can
 * refuse. */
static int run_exec(const nodus_domain_runtime_t *rt, const cc_leg_t *e,
                    uint64_t height, uint8_t hf2, uint8_t voted,
                    dna_effect_view_t *ev_out) {
    static uint8_t chain_id[DNA_CHAIN_ID_LEN];
    static uint8_t intent[64], digest[64];
    nodus_rt_auth_verdict_t av;
    memset(&av, 0, sizeof(av));
    av.n_signers = 1;
    av.n_approvals = 7;
    av.committee_n = 7;
    av.approved_power = 7;
    av.committee_power = 7;
    memset(intent, 0x5C, sizeof(intent));

    nodus_rt_exec_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.chain_id           = chain_id;
    ctx.global_height      = height;
    ctx.epoch              = height / E_LEN;
    ctx.wire_id            = intent;
    ctx.intent_id          = intent;
    ctx.auth_context_commit = digest;
    ctx.leg_auth_digest    = digest;
    ctx.auth               = &av;
    ctx.token_create_fee   = DNAC_CFG_MIN_TOKEN_CREATE_FEE;
    ctx.hf2_active         = hf2;
    ctx.ruleset_gen2_voted = voted;
    ctx.ruleset_gen_storage_voted = g_svoted;
    ctx.ruleset_gen_roles_voted = g_rvoted;

    static uint8_t res[DNA_EFFECT_MAX_TOTAL_LEN];
    size_t rl = 0;
    int rc = nodus_rt_system_exec(rt, &e->view, 0, &ctx, NULL, 0, res,
                                  sizeof(res), &rl);
    if (rc == 0 && ev_out)
        CHECK(dna_effect_result_decode(res, rl, ev_out) == 0);
    return rc;
}

/* The read plan of a chain-config leg: EMPTY, whatever the param. */
static void check_no_reads(const nodus_domain_runtime_t *rt,
                           const cc_leg_t *e) {
    static uint8_t chain_id[DNA_CHAIN_ID_LEN], intent[64];
    nodus_rt_exec_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.chain_id = chain_id;
    ctx.intent_id = intent;
    ctx.global_height = 100;
    nodus_rt_read_req_t reqs[NODUS_RT_MAX_READS];
    uint16_t n = 0xFFFF;
    CHECK(nodus_rt_system_read_plan(rt, &e->view, 0, &ctx, reqs,
                                    NODUS_RT_MAX_READS, &n) == 0);
    CHECK(n == 0);
}

/* An effective height >= floor whose predecessor is NOT a boundary, and
 * one whose predecessor IS. */
static uint64_t eff_not_boundary(uint64_t floor_h) {
    uint64_t e = floor_h;
    while (((e - 1u) % E_LEN) == 0 && (e - 1u) != 0) e++;
    return e;
}
static uint64_t eff_boundary(uint64_t floor_h) {
    uint64_t k = (floor_h > 1u ? (floor_h - 1u) / E_LEN : 0u) + 1u;
    return k * E_LEN + 1u;               /* (k·E + 1) - 1 = k·E, k >= 1 */
}
/* HF-6 param 18: an effective height >= floor_h with NEITHER it NOR its
 * predecessor a boundary (rules (d) and (e)), and one that IS a boundary
 * itself (rule (e)) while its predecessor is not. */
static uint64_t eff_roles_ok(uint64_t floor_h) {
    uint64_t e = floor_h;
    while ((((e - 1u) % E_LEN) == 0 && (e - 1u) != 0) || (e % E_LEN) == 0)
        e++;
    return e;
}
static uint64_t eff_h_boundary(uint64_t floor_h) {
    uint64_t k = floor_h / E_LEN + 1u;
    return k * E_LEN;                    /* k >= 1: k·E, (k·E) - 1 is not */
}

/* ── 6. a migrated chain DB for the read side ───────────────────────── */

static void direct_insert(nodus_witness_t *w, uint8_t param, uint64_t value,
                          uint64_t effective) {
    uint8_t tx_hash[64];
    memset(tx_hash, param, sizeof(tx_hash));
    sqlite3_stmt *st = NULL;
    CHECK(sqlite3_prepare_v2(w->db,
              "INSERT INTO chain_config_history (param_id, new_value, "
              "effective_block, commit_block, tx_hash, proposal_nonce, "
              "created_at_unix) VALUES (?1, ?2, ?3, 1, ?4, 1, 0)",
              -1, &st, NULL) == SQLITE_OK);
    sqlite3_bind_int(st, 1, param);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)value);
    sqlite3_bind_int64(st, 3, (sqlite3_int64)effective);
    sqlite3_bind_blob(st, 4, tx_hash, 64, SQLITE_TRANSIENT);
    CHECK(sqlite3_step(st) == SQLITE_DONE);
    sqlite3_finalize(st);
    w->chain_config_cache_warm = false;
}

int main(void) {
    /* ── 1. ids and literals ──────────────────────────────────────── */
    CHECK(DNAC_CFG_RULESET_GEN2 == 9);
    CHECK(DNAC_CFG_NAME_PRICE_3P == 10 && DNAC_CFG_NAME_PRICE_4P == 11 &&
          DNAC_CFG_NAME_PRICE_5P == 12 && DNAC_CFG_NAME_PRICE_6P == 13);
    /* Nodus EVM (design 2026-10-04-nodus-evm-chain-integration-design.md §9) appends
     * params 14 EVM_ACTIVE and 15 EVM_BLOCK_GAS_LIMIT after HF-4's 9-13;
     * storage reward v1 appended 16 RULESET_GEN_STORAGE and HF-8 17
     * DELEGATE_NAME_REQUIRED (main merge order); HF-6 appends 18-21 and
     * RETIRES 16 (slice 8c — the id keeps its number and is never
     * reused). HF-4's own ids are unchanged and still read by
     * consensus. */
    CHECK(DNAC_CFG_RULESET_GEN_STORAGE == 16);
    CHECK(DNAC_CFG_DELEGATE_NAME_REQUIRED == 17);
    CHECK(DNAC_CFG_RULESET_GEN_ROLES == 18);
    CHECK(DNAC_CFG_STAKE_MIN == 19);
    CHECK(DNAC_CFG_POWER_CAP_BPS == 20);
    CHECK(DNAC_CFG_STORAGE_BOND == 21);
    /* HF-7 P1d appends 22 RULESET_GEN_ROOTS (its own rules:
     * test_hf7_activation.c), the ML-DSA-87 precompile 23 MLDSA_ACTIVE
     * (its own rules: test_v2_evm.c section 15); 24 is now the first id
     * past the end */
    CHECK(DNAC_CFG_RULESET_GEN_ROOTS == 22);
    CHECK(DNAC_CFG_MLDSA_ACTIVE == 23);
    CHECK(DNAC_CFG_PARAM_MAX_ID == 23);
    for (unsigned id = 9; id <= 23; id++)
        CHECK(dnac_cfg_param_read_by_consensus((uint8_t)id) ==
              (id != DNAC_CFG_RULESET_GEN_STORAGE));
    CHECK(!dnac_cfg_param_read_by_consensus(16));
    CHECK(dnac_cfg_param_read_by_consensus(18));
    CHECK(dnac_cfg_param_read_by_consensus(22));
    CHECK(dnac_cfg_param_read_by_consensus(23));
    CHECK(!dnac_cfg_param_read_by_consensus(24));
    /* the records' numbers (K9: 100k NODUS floor, default 2M; K5: [500,
     * 3000], default 3000; Kurultay #16 decision 3: [100k, 1M], 1M) */
    CHECK(DNAC_HF6_STAKE_MIN_MIN == 10000000000000ULL);
    CHECK(DNAC_HF6_STAKE_MIN_DEFAULT == 200000000000000ULL);
    CHECK(DNAC_CFG_MIN_POWER_CAP_BPS == 500u &&
          DNAC_CFG_MAX_POWER_CAP_BPS == 3000u &&
          DNAC_HF6_POWER_CAP_BPS_DEFAULT == 3000u);
    CHECK(DNAC_HF6_STORAGE_BOND_MIN == 10000000000000ULL &&
          DNAC_HF6_STORAGE_BOND_MAX == 100000000000000ULL &&
          DNAC_HF6_STORAGE_BOND_DEFAULT == 100000000000000ULL);
    CHECK(DNAC_CFG_DELEGATE_NAME_REQUIRED_ON == 1ULL);
    CHECK(DNAC_CFG_RULESET_GEN2_D2 <= (uint64_t)INT64_MAX);
    CHECK(DNAC_CFG_RULESET_GEN_ROLES_D <= (uint64_t)INT64_MAX);
    CHECK(DNAC_CFG_RULESET_GEN_ROLES_D != DNAC_CFG_RULESET_GEN2_D2);
    CHECK(DNAC_CFG_RULESET_GEN_ROLES_D != DNAC_CFG_EVM_ACTIVE_D);
    CHECK(DNAC_RULESET_SWITCH_SPEC_VERSION == 1u);

    /* ── 2. scalar rules (signed_at 1, valid_before 5000 > eff 4000) ─ */
    {
        const uint64_t D2 = (uint64_t)DNAC_CFG_RULESET_GEN2_D2;
        CHECK(nodus_chain_config_scalar_rules(9, D2, 1, 5000, 4000, 7) == 0);
        CHECK(nodus_chain_config_scalar_rules(9, D2 + 1u, 1, 5000, 4000,
                                              7) == -1);
        CHECK(nodus_chain_config_scalar_rules(9, D2 - 1u, 1, 5000, 4000,
                                              7) == -1);
        CHECK(nodus_chain_config_scalar_rules(9, UINT64_MAX, 1, 5000, 4000,
                                              7) == -1);
        /* the shared window / int64 rules still bind param 9 */
        CHECK(nodus_chain_config_scalar_rules(9, D2, 0, 5000, 4000, 7) == -1);
        CHECK(nodus_chain_config_scalar_rules(9, D2, 1, 4000, 4000, 7) == -1);
        CHECK(nodus_chain_config_scalar_rules(9, D2, 1, 5000, 4000,
                                              (uint64_t)INT64_MAX + 1u)
              == -1);
        for (uint8_t id = 10; id <= 13; id++) {
            CHECK(nodus_chain_config_scalar_rules(id, DNAC_CFG_MIN_NAME_PRICE,
                                                  1, 5000, 4000, 7) == 0);
            CHECK(nodus_chain_config_scalar_rules(id, DNAC_CFG_MAX_NAME_PRICE,
                                                  1, 5000, 4000, 7) == 0);
            CHECK(nodus_chain_config_scalar_rules(id,
                                                  DNAC_NAME_PRICE_4P_DEFAULT,
                                                  1, 5000, 4000, 7) == 0);
            CHECK(nodus_chain_config_scalar_rules(
                      id, DNAC_CFG_MIN_NAME_PRICE - 1u, 1, 5000, 4000, 7)
                  == -1);
            CHECK(nodus_chain_config_scalar_rules(
                      id, DNAC_CFG_MAX_NAME_PRICE + 1u, 1, 5000, 4000, 7)
                  == -1);
            CHECK(nodus_chain_config_scalar_rules(id, 0, 1, 5000, 4000, 7)
                  == -1);
        }
        /* HF-6 slice 8c: param 16 RETIRED — refused for EVERY value, the
         * id-1 treatment (the read-list gate refuses before any bound);
         * param 18 accepts EXACTLY D4 (the param-9 shape), refuses its
         * neighbours, 0, D2, the EVM D and UINT64_MAX; param 9 refuses
         * D4. */
        {
            const uint64_t D4 = (uint64_t)DNAC_CFG_RULESET_GEN_ROLES_D;
            const uint64_t ED = (uint64_t)DNAC_CFG_EVM_ACTIVE_D;
            const uint64_t any16[] = { 0, 1, D2, D4, ED, (uint64_t)INT64_MAX,
                                       UINT64_MAX };
            for (size_t k = 0; k < sizeof(any16) / sizeof(any16[0]); k++)
                CHECK(nodus_chain_config_scalar_rules(16, any16[k], 1, 5000,
                                                      4000, 7) == -1);
            CHECK(nodus_chain_config_scalar_rules(18, D4, 1, 5000, 4000, 7)
                  == 0);
            CHECK(nodus_chain_config_scalar_rules(18, D4 + 1u, 1, 5000,
                                                  4000, 7) == -1);
            CHECK(nodus_chain_config_scalar_rules(18, D4 - 1u, 1, 5000,
                                                  4000, 7) == -1);
            CHECK(nodus_chain_config_scalar_rules(18, 0, 1, 5000, 4000, 7)
                  == -1);
            CHECK(nodus_chain_config_scalar_rules(18, D2, 1, 5000, 4000, 7)
                  == -1);
            CHECK(nodus_chain_config_scalar_rules(18, ED, 1, 5000, 4000, 7)
                  == -1);
            CHECK(nodus_chain_config_scalar_rules(18, UINT64_MAX, 1, 5000,
                                                  4000, 7) == -1);
            CHECK(nodus_chain_config_scalar_rules(18, D4, 0, 5000, 4000, 7)
                  == -1);               /* the shared window rule binds */
            CHECK(nodus_chain_config_scalar_rules(18, D4, 1, 4000, 4000, 7)
                  == -1);
            /* and param 9 does not accept D4 */
            CHECK(nodus_chain_config_scalar_rules(9, D4, 1, 5000, 4000, 7)
                  == -1);
        }
        /* HF-8: param 17 accepts EXACTLY 1 — a one-way switch, no "off"
         * vote (the HF-2/HF-3 shape) */
        CHECK(nodus_chain_config_scalar_rules(17, 1, 1, 5000, 4000, 7) == 0);
        CHECK(nodus_chain_config_scalar_rules(17, 0, 1, 5000, 4000, 7)
              == -1);
        CHECK(nodus_chain_config_scalar_rules(17, 2, 1, 5000, 4000, 7)
              == -1);
        CHECK(nodus_chain_config_scalar_rules(17, UINT64_MAX, 1, 5000, 4000,
                                              7) == -1);
        CHECK(nodus_chain_config_scalar_rules(17, 1, 0, 5000, 4000, 7)
              == -1);                   /* the shared window rule binds */
        CHECK(nodus_chain_config_scalar_rules(17, 1, 1, 4000, 4000, 7)
              == -1);
        CHECK(nodus_chain_config_scalar_rules(18, 1, 1, 5000, 4000, 7)
              == -1);                   /* 18: exactly D4               */
        CHECK(nodus_chain_config_scalar_rules(18, DNAC_CFG_MIN_NAME_PRICE, 1,
                                              5000, 4000, 7) == -1);

        /* HF-6 slice 8a — param 19 STAKE_MIN [10^13, INT64_MAX]. The
         * window (signed_at 1, valid_before 5000 > effective 4000) and
         * the nonce (7) are valid in every probe, so a refusal of
         * INT64_MAX + 1 / UINT64_MAX can come only from param 19's OWN
         * upper check: the shared int64 tail bounds the nonce and the
         * three heights, never new_value. */
        {
            const uint64_t MN = (uint64_t)DNAC_HF6_STAKE_MIN_MIN;
            CHECK(nodus_chain_config_scalar_rules(19, MN - 1u, 1, 5000, 4000,
                                                  7) == -1);
            CHECK(nodus_chain_config_scalar_rules(19, MN, 1, 5000, 4000, 7)
                  == 0);
            CHECK(nodus_chain_config_scalar_rules(
                      19, (uint64_t)DNAC_HF6_STAKE_MIN_DEFAULT, 1, 5000, 4000,
                      7) == 0);
            CHECK(nodus_chain_config_scalar_rules(19, (uint64_t)INT64_MAX, 1,
                                                  5000, 4000, 7) == 0);
            CHECK(nodus_chain_config_scalar_rules(
                      19, (uint64_t)INT64_MAX + 1u, 1, 5000, 4000, 7) == -1);
            CHECK(nodus_chain_config_scalar_rules(19, UINT64_MAX, 1, 5000,
                                                  4000, 7) == -1);
            CHECK(nodus_chain_config_scalar_rules(19, 0, 1, 5000, 4000, 7)
                  == -1);
            CHECK(nodus_chain_config_scalar_rules(19, MN, 0, 5000, 4000, 7)
                  == -1);               /* the shared window rule binds */
        }
        /* param 20 POWER_CAP_BPS [500, 3000] */
        CHECK(nodus_chain_config_scalar_rules(20, 499, 1, 5000, 4000, 7)
              == -1);
        CHECK(nodus_chain_config_scalar_rules(20, 500, 1, 5000, 4000, 7) == 0);
        CHECK(nodus_chain_config_scalar_rules(20, 1500, 1, 5000, 4000, 7)
              == 0);
        CHECK(nodus_chain_config_scalar_rules(20, 3000, 1, 5000, 4000, 7)
              == 0);
        CHECK(nodus_chain_config_scalar_rules(20, 3001, 1, 5000, 4000, 7)
              == -1);
        CHECK(nodus_chain_config_scalar_rules(20, 0, 1, 5000, 4000, 7) == -1);
        CHECK(nodus_chain_config_scalar_rules(20, UINT64_MAX, 1, 5000, 4000,
                                              7) == -1);
        /* param 21 STORAGE_BOND [10^13, 10^14] */
        {
            const uint64_t BMIN = (uint64_t)DNAC_HF6_STORAGE_BOND_MIN;
            const uint64_t BMAX = (uint64_t)DNAC_HF6_STORAGE_BOND_MAX;
            CHECK(nodus_chain_config_scalar_rules(21, BMIN - 1u, 1, 5000,
                                                  4000, 7) == -1);
            CHECK(nodus_chain_config_scalar_rules(21, BMIN, 1, 5000, 4000, 7)
                  == 0);
            CHECK(nodus_chain_config_scalar_rules(21, BMAX, 1, 5000, 4000, 7)
                  == 0);
            CHECK(nodus_chain_config_scalar_rules(21, BMAX + 1u, 1, 5000,
                                                  4000, 7) == -1);
            CHECK(nodus_chain_config_scalar_rules(21, (uint64_t)INT64_MAX, 1,
                                                  5000, 4000, 7) == -1);
            CHECK(nodus_chain_config_scalar_rules(21, 0, 1, 5000, 4000, 7)
                  == -1);
        }
        /* 18 (exactly D4) refuses every value one of its neighbours
         * would accept; 22 (exactly D5, HF-7) refuses them and D4; 23
         * (exactly the ML-DSA-87 precompile literal) refuses them and D5;
         * 24 is past the end, whatever the value */
        CHECK(nodus_chain_config_scalar_rules(18, 500, 1, 5000, 4000, 7)
              == -1);
        CHECK(nodus_chain_config_scalar_rules(
                  18, (uint64_t)DNAC_HF6_STAKE_MIN_DEFAULT, 1, 5000, 4000, 7)
              == -1);
        CHECK(nodus_chain_config_scalar_rules(22, 500, 1, 5000, 4000, 7)
              == -1);
        CHECK(nodus_chain_config_scalar_rules(
                  22, (uint64_t)DNAC_CFG_RULESET_GEN_ROLES_D, 1, 5000, 4000,
                  7) == -1);
        CHECK(nodus_chain_config_scalar_rules(23, 500, 1, 5000, 4000, 7)
              == -1);
        CHECK(nodus_chain_config_scalar_rules(
                  23, (uint64_t)DNAC_CFG_RULESET_GEN_ROOTS_D, 1, 5000, 4000,
                  7) == -1);
        CHECK(nodus_chain_config_scalar_rules(
                  24, (uint64_t)DNAC_CFG_MLDSA_ACTIVE_D, 1, 5000, 4000, 7)
              == -1);
    }

    /* ── 3. grace: ERGONOMIC, HF-3's class (the EVM ids 14-15 are
     *       SAFETY, Nodus EVM's own) ──────────────────────────────── */
    for (uint8_t id = 9; id <= 13; id++) {
        CHECK(nodus_chain_config_grace_for_param(id) == GRACE_E);
        CHECK(nodus_chain_config_grace_for_param(id) ==
              nodus_chain_config_grace_for_param(DNAC_CFG_HF3_ACTIVE));
    }
    /* HF-6 slice 8c: RETIRED 16 answers UINT64_MAX — the id-1 / id-3
     * shape, an unsatisfiable gap — and 18 is ERGONOMIC (Kurultay #16
     * "4 ok"), param 9's class */
    CHECK(nodus_chain_config_grace_for_param(16) == UINT64_MAX);
    CHECK(nodus_chain_config_grace_for_param(16) ==
          nodus_chain_config_grace_for_param(DNAC_CFG_MAX_TXS_PER_BLOCK));
    CHECK(nodus_chain_config_grace_for_param(18) == GRACE_E);
    CHECK(nodus_chain_config_grace_for_param(18) ==
          nodus_chain_config_grace_for_param(DNAC_CFG_RULESET_GEN2));
    /* HF-8: param 17 ERGONOMIC — the HF-2/HF-3 class */
    CHECK(nodus_chain_config_grace_for_param(17) == GRACE_E);
    CHECK(nodus_chain_config_grace_for_param(17) ==
          nodus_chain_config_grace_for_param(DNAC_CFG_HF2_ACTIVE));
    /* HF-6 slice 8a: 19-21 ERGONOMIC (Kurultay #16 "4 ok") */
    for (uint8_t id = 19; id <= 21; id++)
        CHECK(nodus_chain_config_grace_for_param(id) == GRACE_E);

    /* ── 4. the stateful authority — full matrix ──────────────────── */
    {
        const uint64_t ok_eff = eff_not_boundary(E_LEN + 5u);
        CHECK(((ok_eff - 1u) % E_LEN) != 0);
        /* param 9: accepted only with no row, HF-2 on, non-boundary */
        CHECK(nodus_chain_config_stateful_rules(9, ok_eff, 1, 0, 1) == 0);
        CHECK(nodus_chain_config_stateful_rules(9, ok_eff, 1, 0, 2) == 0);
        CHECK(nodus_chain_config_stateful_rules(9, ok_eff, 1, 1, 1) == -1);
        CHECK(nodus_chain_config_stateful_rules(9, ok_eff, 0, 0, 1) == -1);
        CHECK(nodus_chain_config_stateful_rules(9, ok_eff, 0, 1, 1) == -1);
        CHECK(nodus_chain_config_stateful_rules(9, E_LEN + 1u, 1, 0, 1)
              == -1);                   /* H-1 = E   — a boundary        */
        CHECK(nodus_chain_config_stateful_rules(9, 2u * E_LEN + 1u, 1, 0, 1)
              == -1);                   /* H-1 = 2E  — a boundary        */
        CHECK(nodus_chain_config_stateful_rules(9, 1, 1, 0, 1) == 0);
                                        /* H-1 = 0   — genesis, not one  */
        CHECK(nodus_chain_config_stateful_rules(9, 0, 1, 0, 1) == -1);
        /* params 10-13: generation 2 judges, nothing else */
        for (uint8_t id = 10; id <= 13; id++) {
            CHECK(nodus_chain_config_stateful_rules(id, ok_eff, 1, 0, 0)
                  == -1);
            CHECK(nodus_chain_config_stateful_rules(id, ok_eff, 1, 0, 1)
                  == -1);
            CHECK(nodus_chain_config_stateful_rules(id, ok_eff, 1, 0, 2)
                  == 0);
            /* the param-9 facts do not gate the prices */
            CHECK(nodus_chain_config_stateful_rules(id, E_LEN + 1u, 0, 1, 2)
                  == 0);
        }
        /* ids 1-8: no stateful rule, whatever the facts */
        for (uint8_t id = 1; id <= 8; id++)
            CHECK(nodus_chain_config_stateful_rules(id, E_LEN + 1u, 0, 1, 0)
                  == 0);
        /* HF-6 slice 8c — RETIRED param 16: no stateful case left, -1
         * whatever the facts (the scalar rules refuse it first) */
        {
            nodus_cc_state_facts_t f;
            memset(&f, 0, sizeof(f));
            f.hf2_active = 1;
            f.judging_generation = NODUS_RT_GEN_STORAGE_BASE;
            CHECK(nodus_chain_config_stateful_rules_ex(16, ok_eff, &f) == -1);
            for (uint32_t g = 0; g <= NODUS_RT_GEN_STORAGE; g++)
                CHECK(nodus_chain_config_stateful_rules(16, ok_eff, 1, 0, g)
                      == -1);
        }
        /* HF-6 slice 8c — param 18 RULESET_GEN_ROLES: accepted ONLY with
         * no param-18 row (a), no param-16 row (a'), HF-2 on (b), judged
         * under EXACTLY generation 3 (c), and neither H-1 (d) nor H (e)
         * an epoch boundary. Each probe below breaks ONE clause of the
         * accepted baseline. */
        {
            const uint32_t GB = NODUS_RT_GEN_STORAGE_BASE;
            const uint64_t R = eff_roles_ok(E_LEN + 5u);
            CHECK(GB == NODUS_RT_GEN_EVM && GB == 3u);
            CHECK(((R - 1u) % E_LEN) != 0 && (R % E_LEN) != 0);
            nodus_cc_state_facts_t f;
            memset(&f, 0, sizeof(f));
            f.hf2_active = 1;
            f.judging_generation = GB;
            CHECK(nodus_chain_config_stateful_rules_ex(18, R, &f) == 0);
            /* (c) judged under exactly 3: 0 (synthetic), 1, 2, 4 refused */
            for (uint32_t g = 0; g <= NODUS_RT_GEN_STORAGE; g++) {
                f.judging_generation = g;
                CHECK(nodus_chain_config_stateful_rules_ex(18, R, &f) ==
                      (g == GB ? 0 : -1));
            }
            f.judging_generation = GB;
            /* (a) a param-18 row exists */
            f.ruleset_gen_roles_voted = 1;
            CHECK(nodus_chain_config_stateful_rules_ex(18, R, &f) == -1);
            f.ruleset_gen_roles_voted = 0;
            /* (a') a param-16 row exists — the K16 precondition */
            f.ruleset_gen_storage_voted = 1;
            CHECK(nodus_chain_config_stateful_rules_ex(18, R, &f) == -1);
            f.ruleset_gen_storage_voted = 0;
            /* (b) HF-2 off */
            f.hf2_active = 0;
            CHECK(nodus_chain_config_stateful_rules_ex(18, R, &f) == -1);
            f.hf2_active = 1;
            /* (d)(e) the heights: 0 refused; 1 accepted (H-1 = genesis,
             * not a boundary, and H = 1 is not one); E refused by (e);
             * E+1 refused by (d); E+2 accepted; 2E by (e); 2E+1 by (d) */
            CHECK(nodus_chain_config_stateful_rules_ex(18, 0, &f) == -1);
            CHECK(nodus_chain_config_stateful_rules_ex(18, 1, &f) == 0);
            CHECK(nodus_chain_config_stateful_rules_ex(18, E_LEN, &f) == -1);
            CHECK(nodus_chain_config_stateful_rules_ex(18, E_LEN + 1u, &f)
                  == -1);
            CHECK(nodus_chain_config_stateful_rules_ex(18, E_LEN + 2u, &f)
                  == 0);
            CHECK(nodus_chain_config_stateful_rules_ex(18, 2u * E_LEN, &f)
                  == -1);
            CHECK(nodus_chain_config_stateful_rules_ex(18, 2u * E_LEN + 1u,
                                                       &f) == -1);
            {
                const uint64_t hb = eff_h_boundary(R);  /* the next k·E */
                CHECK((hb % E_LEN) == 0 && ((hb - 1u) % E_LEN) != 0);
                CHECK(nodus_chain_config_stateful_rules_ex(18, hb, &f) == -1);
                CHECK(nodus_chain_config_stateful_rules_ex(18, hb + 2u, &f)
                      == 0);
            }
            /* the facts that are not 18's do not gate it */
            f.ruleset_gen2_voted = 1;
            f.evm_active_voted = 1;
            f.hf3_active = 1;
            f.gas_price_on = 1;
            CHECK(nodus_chain_config_stateful_rules_ex(18, R, &f) == 0);
            /* and 18's facts gate nothing but 18: param 9 (generation 1)
             * and param 14 (its own full fact set, generation 2) still
             * accept with both generation-4 vote facts set */
            {
                nodus_cc_state_facts_t g9;
                memset(&g9, 0, sizeof(g9));
                g9.hf2_active = 1;
                g9.judging_generation = NODUS_RT_GEN_1;
                g9.ruleset_gen_roles_voted = 1;
                g9.ruleset_gen_storage_voted = 1;
                CHECK(nodus_chain_config_stateful_rules_ex(9, ok_eff, &g9)
                      == 0);
                nodus_cc_state_facts_t g14;
                memset(&g14, 0, sizeof(g14));
                g14.hf2_active = 1;
                g14.hf3_active = 1;
                g14.gas_price_on = 1;
                g14.judging_generation = NODUS_RT_GEN_EVM_BASE;
                g14.chain_initial_height = 1;
                g14.ruleset_gen_roles_voted = 1;
                g14.ruleset_gen_storage_voted = 1;
                const uint64_t e14 =
                    eff_not_boundary(1u + NODUS_CC_EVM_BLOCKHASH_WINDOW +
                                     E_LEN);
                CHECK(nodus_chain_config_stateful_rules_ex(14, e14, &g14)
                      == 0);
            }
            /* the 5-argument form: its 4th argument is 18's own fact */
            CHECK(nodus_chain_config_stateful_rules(18, R, 1, 0, GB) == 0);
            CHECK(nodus_chain_config_stateful_rules(18, R, 1, 1, GB) == -1);
            CHECK(nodus_chain_config_stateful_rules(18, R, 0, 0, GB) == -1);
            CHECK(nodus_chain_config_stateful_rules(18, R, 1, 0,
                                                    NODUS_RT_GEN_STORAGE)
                  == -1);
        }
        /* K10 (decision 2026-10-05-storage-reward-is-for-archive.md), kept
         * for the param-18 vote: rule (c) keeps the generation-4 edge out
         * of the EVM edge's block. The EVM edge switches the registry at
         * the END of block He-1 (He = the EVM_ACTIVE row's effective
         * height), so every block up to and including He-1 is judged under
         * the EVM BASE generation and every block from He on under the EVM
         * generation. A param-18 vote whose edge block H-1 equals He-1
         * would have to be judged at or before He-1 — under the base — and
         * is refused whatever its effective height (H = He included); a
         * vote judged at the EVM generation sits at a height >= He and its
         * effective is >= that height + the grace, so its edge block lies
         * strictly above He-1. */
        {
            const uint64_t He = eff_roles_ok(4u * E_LEN + 7u);
            nodus_cc_state_facts_t f;
            memset(&f, 0, sizeof(f));
            f.hf2_active = 1;
            f.judging_generation = NODUS_RT_GEN_EVM_BASE;
            for (uint64_t hs = He - 1u; hs <= He + 1u; hs++) {
                if (((hs - 1u) % E_LEN) == 0 || (hs % E_LEN) == 0) continue;
                CHECK(nodus_chain_config_stateful_rules_ex(18, hs, &f) == -1);
            }
            /* the earliest vote the EVM generation judges is at He; its
             * edge block is at least He + grace - 1 > He - 1 */
            CHECK(He + nodus_chain_config_grace_for_param(18) - 1u > He - 1u);
            CHECK(nodus_chain_config_grace_for_param(18) >= 1u);
        }
        /* HF-8 — param 17: votable only while generation >= 2 judges the
         * vote (names exist); NO single-use rule and no HF-2 / boundary
         * rule — every other fact is ignored */
        CHECK(nodus_chain_config_stateful_rules(17, ok_eff, 1, 0, 0) == -1);
        CHECK(nodus_chain_config_stateful_rules(17, ok_eff, 1, 0, 1) == -1);
        CHECK(nodus_chain_config_stateful_rules(17, ok_eff, 1, 0, 2) == 0);
        CHECK(nodus_chain_config_stateful_rules(17, E_LEN + 1u, 0, 1, 2)
              == 0);
        {
            nodus_cc_state_facts_t f;
            memset(&f, 0, sizeof(f));
            f.judging_generation = NODUS_RT_GEN_1;
            CHECK(nodus_chain_config_stateful_rules_ex(17, ok_eff, &f)
                  == -1);
            f.judging_generation = NODUS_RT_GEN_2;
            CHECK(nodus_chain_config_stateful_rules_ex(17, ok_eff, &f) == 0);
            f.judging_generation = NODUS_RT_GEN_STORAGE_BASE;
            CHECK(nodus_chain_config_stateful_rules_ex(17, ok_eff, &f) == 0);
            f.judging_generation = NODUS_RT_GEN_STORAGE;
            f.ruleset_gen2_voted = 1;
            f.ruleset_gen_storage_voted = 1;
            f.ruleset_gen_roles_voted = 1;
            f.evm_active_voted = 1;
            CHECK(nodus_chain_config_stateful_rules_ex(17, ok_eff, &f) == 0);
        }
        /* HF-6 slice 8a — params 19-21: votable only while generation 4
         * judges the vote; no other fact read (no single-use rule) */
        for (uint8_t id = 19; id <= 21; id++) {
            for (uint32_t g = 0; g < NODUS_RT_GEN_STORAGE; g++)
                CHECK(nodus_chain_config_stateful_rules(id, ok_eff, 1, 0, g)
                      == -1);
            CHECK(nodus_chain_config_stateful_rules(id, ok_eff, 1, 0,
                                                    NODUS_RT_GEN_STORAGE)
                  == 0);
            /* the other facts do not gate them: HF-2 off, the single-use
             * fact set, H-1 an epoch boundary, effective 0 */
            CHECK(nodus_chain_config_stateful_rules(id, E_LEN + 1u, 0, 1,
                                                    NODUS_RT_GEN_STORAGE)
                  == 0);
            nodus_cc_state_facts_t f;
            memset(&f, 0, sizeof(f));
            f.judging_generation = NODUS_RT_GEN_STORAGE_BASE;
            CHECK(nodus_chain_config_stateful_rules_ex(id, ok_eff, &f) == -1);
            f.judging_generation = NODUS_RT_GEN_STORAGE;
            CHECK(nodus_chain_config_stateful_rules_ex(id, ok_eff, &f) == 0);
            f.ruleset_gen2_voted = 1;
            f.ruleset_gen_storage_voted = 1;
            f.ruleset_gen_roles_voted = 1;
            f.evm_active_voted = 1;
            CHECK(nodus_chain_config_stateful_rules_ex(id, 0, &f) == 0);
        }
        CHECK(nodus_chain_config_stateful_rules(0, ok_eff, 1, 0, 2) == -1);
        CHECK(nodus_chain_config_stateful_rules(16, ok_eff, 1, 0, 2) == -1);
        CHECK(nodus_chain_config_stateful_rules(18, ok_eff, 1, 0, 2) == -1);
        CHECK(nodus_chain_config_stateful_rules(18, ok_eff, 1, 0,
                                                NODUS_RT_GEN_STORAGE) == -1);
        /* HF-7 P1d: 22 is RULESET_GEN_ROOTS now (its stateful matrix is
         * test_hf7_activation.c); 23 is the ML-DSA-87 precompile vote
         * (test_v2_evm.c section 15); 24 is the first unknown id */
        CHECK(nodus_chain_config_stateful_rules(24, ok_eff, 1, 0,
                                                NODUS_RT_GEN_STORAGE) == -1);
        CHECK(nodus_chain_config_stateful_rules(255, ok_eff, 1, 0, 2) == -1);
    }

    /* ── 5. the exec hook applies the same rules ──────────────────── */
    {
        const nodus_domain_runtime_t *sys1 =
            nodus_runtime_for_generation(NODUS_RT_GEN_1, DNA_DOMAIN_SYSTEM);
        const nodus_domain_runtime_t *sys2 =
            nodus_runtime_for_generation(NODUS_RT_GEN_2, DNA_DOMAIN_SYSTEM);
        CHECK(sys1 && sys1->generation == NODUS_RT_GEN_1);
        CHECK(sys2 && sys2->generation == NODUS_RT_GEN_2);

        const uint64_t H = 100;
        const uint64_t ok_eff = eff_not_boundary(H + GRACE_E);
        const uint64_t bd_eff = eff_boundary(H + GRACE_E);
        cc_leg_t e9, e9b, p[4];
        dna_effect_view_t ev;

        cc_leg_build(&e9, 9, (uint64_t)DNAC_CFG_RULESET_GEN2_D2, ok_eff,
                     ok_eff + 1000u);
        cc_leg_build(&e9b, 9, (uint64_t)DNAC_CFG_RULESET_GEN2_D2, bd_eff,
                     bd_eff + 1000u);
        check_no_reads(sys1, &e9);
        check_no_reads(sys2, &e9);

        /* accepted: exactly ONE CREATE, keyed param 9 ‖ effective */
        memset(&ev, 0, sizeof(ev));
        CHECK(run_exec(sys1, &e9, H, 1, 0, &ev) == 0);
        CHECK(ev.effect_count == 1);
        CHECK(ev.eff[0].effect_kind == DNA_EFFECT_CREATE);
        CHECK(ev.eff[0].precond_tag == DNA_EFFECT_PRE_ABSENT);
        CHECK(ev.eff[0].key_len == 12);
        {
            const uint8_t *k = ev.buf + ev.key_off[0];
            uint8_t want[12] = { 0, 0, 0, 9 };
            put64(want + 4, ok_eff);
            CHECK(memcmp(k, want, 12) == 0);
        }
        /* each stateful rule refuses as a VERDICT (-1), never -2 */
        CHECK(run_exec(sys1, &e9, H, 1, 1, NULL) == -1);   /* (a) single use */
        CHECK(run_exec(sys1, &e9, H, 0, 0, NULL) == -1);   /* (b) HF-2 off   */
        CHECK(run_exec(sys1, &e9b, H, 1, 0, NULL) == -1);  /* (c) boundary   */

        /* params 10-13: refused by generation 1 (and a NULL runtime),
         * accepted by generation 2; the read plan stays empty */
        for (int k = 0; k < 4; k++) {
            cc_leg_build(&p[k], (uint8_t)(10 + k), DNAC_NAME_PRICE_5P_DEFAULT,
                         ok_eff, ok_eff + 1000u);
            check_no_reads(sys1, &p[k]);
            CHECK(run_exec(sys1, &p[k], H, 1, 0, NULL) == -1);
            CHECK(run_exec(NULL, &p[k], H, 1, 0, NULL) == -1);
            memset(&ev, 0, sizeof(ev));
            CHECK(run_exec(sys2, &p[k], H, 1, 0, &ev) == 0);
            CHECK(ev.effect_count == 1);
            free(p[k].bytes);
        }

        /* HF-6 slice 8c — a param-18 leg through the same hook: the hook
         * hands the stateful rules the param-18 fact (rule (a)), the
         * param-16 fact (rule (a')) — never the param-9 one — and its
         * own generation; the read plan stays empty (both facts are
         * unmetered). The generation-3 SYSTEM runtime (the only one that
         * accepts it) and generation 4 exist in an EVM-enabled build only
         * (K10). A param-16 leg is refused by every runtime (RETIRED: the
         * scalar rules refuse it before any fact is read). */
#ifdef NODUS_EVM_ENABLED
        {
            const nodus_domain_runtime_t *sysE =
                nodus_runtime_for_generation(NODUS_RT_GEN_STORAGE_BASE,
                                             DNA_DOMAIN_SYSTEM);
            const nodus_domain_runtime_t *sysS =
                nodus_runtime_for_generation(NODUS_RT_GEN_STORAGE,
                                             DNA_DOMAIN_SYSTEM);
            CHECK(sysE && sysE->generation == NODUS_RT_GEN_EVM);
            CHECK(sysS && sysS->generation == NODUS_RT_GEN_STORAGE);
            const uint64_t D4 = (uint64_t)DNAC_CFG_RULESET_GEN_ROLES_D;
            const uint64_t r_eff = eff_roles_ok(H + GRACE_E);
            const uint64_t rh_eff = eff_h_boundary(H + GRACE_E);
            cc_leg_t e18, e18b, e18h, e16;
            cc_leg_build(&e18, 18, D4, r_eff, r_eff + 1000u);
            cc_leg_build(&e18b, 18, D4, bd_eff, bd_eff + 1000u);
            cc_leg_build(&e18h, 18, D4, rh_eff, rh_eff + 1000u);
            check_no_reads(sysE, &e18);
            g_svoted = 0;
            g_rvoted = 0;
            CHECK(run_exec(sys1, &e18, H, 1, 0, NULL) == -1);  /* (c) gen 1 */
            CHECK(run_exec(sys2, &e18, H, 1, 0, NULL) == -1);  /* (c) gen 2 */
            CHECK(run_exec(sysS, &e18, H, 1, 0, NULL) == -1);  /* (c) gen 4 */
            CHECK(run_exec(NULL, &e18, H, 1, 0, NULL) == -1);  /* (c) NULL  */
            memset(&ev, 0, sizeof(ev));
            CHECK(run_exec(sysE, &e18, H, 1, 0, &ev) == 0);    /* gen 3    */
            CHECK(ev.effect_count == 1);
            CHECK(ev.eff[0].effect_kind == DNA_EFFECT_CREATE);
            CHECK(ev.eff[0].precond_tag == DNA_EFFECT_PRE_ABSENT);
            CHECK(ev.eff[0].key_len == 12);
            {
                const uint8_t *k = ev.buf + ev.key_off[0];
                uint8_t want[12] = { 0, 0, 0, 18 };
                put64(want + 4, r_eff);
                CHECK(memcmp(k, want, 12) == 0);
            }
            /* the param-9 fact does NOT gate param 18 … */
            CHECK(run_exec(sysE, &e18, H, 1, 1, NULL) == 0);
            CHECK(run_exec(sysE, &e18, H, 0, 0, NULL) == -1);  /* (b)      */
            CHECK(run_exec(sysE, &e18b, H, 1, 0, NULL) == -1); /* (d) H-1  */
            CHECK(run_exec(sysE, &e18h, H, 1, 0, NULL) == -1); /* (e) H    */
            g_rvoted = 1;
            CHECK(run_exec(sysE, &e18, H, 1, 0, NULL) == -1);  /* (a)      */
            /* … and the param-18 fact does NOT gate param 9 */
            CHECK(run_exec(sys1, &e9, H, 1, 0, NULL) == 0);
            g_rvoted = 0;
            g_svoted = 1;
            CHECK(run_exec(sysE, &e18, H, 1, 0, NULL) == -1);  /* (a')     */
            CHECK(run_exec(sys1, &e9, H, 1, 0, NULL) == 0);
            g_svoted = 0;
            /* a value other than D4 never reaches the stateful rules */
            {
                cc_leg_t ex;
                cc_leg_build(&ex, 18, D4 + 1u, r_eff, r_eff + 1000u);
                CHECK(run_exec(sysE, &ex, H, 1, 0, NULL) == -1);
                free(ex.bytes);
            }
            /* RETIRED param 16: refused by every runtime, for D4 too */
            cc_leg_build(&e16, 16, D4, ok_eff, ok_eff + 1000u);
            CHECK(run_exec(sys1, &e16, H, 1, 0, NULL) == -1);
            CHECK(run_exec(sys2, &e16, H, 1, 0, NULL) == -1);
            CHECK(run_exec(sysE, &e16, H, 1, 0, NULL) == -1);
            CHECK(run_exec(sysS, &e16, H, 1, 0, NULL) == -1);
            CHECK(run_exec(NULL, &e16, H, 1, 0, NULL) == -1);
            free(e18.bytes);
            free(e18b.bytes);
            free(e18h.bytes);
            free(e16.bytes);
        }
        /* HF-6 slice 8a — params 19-21 through the same hook: refused by
         * every generation below 4 and by a NULL runtime, accepted by the
         * generation-4 SYSTEM runtime with exactly ONE CREATE keyed
         * (param ‖ effective); the read plan stays empty; the HF-2 and
         * single-use facts do not gate them. */
        {
            const nodus_domain_runtime_t *sysE =
                nodus_runtime_for_generation(NODUS_RT_GEN_STORAGE_BASE,
                                             DNA_DOMAIN_SYSTEM);
            const nodus_domain_runtime_t *sysS =
                nodus_runtime_for_generation(NODUS_RT_GEN_STORAGE,
                                             DNA_DOMAIN_SYSTEM);
            CHECK(sysE && sysS);
            static const struct { uint8_t id; uint64_t v; } legs[3] = {
                { 19, 10000000000000ULL },          /* STAKE_MIN = 100k  */
                { 20, 500u },                       /* POWER_CAP_BPS     */
                { 21, 10000000000000ULL },          /* STORAGE_BOND 100k */
            };
            for (int k = 0; k < 3; k++) {
                cc_leg_t e;
                cc_leg_build(&e, legs[k].id, legs[k].v, ok_eff,
                             ok_eff + 1000u);
                check_no_reads(sysS, &e);
                g_svoted = 0;
                CHECK(run_exec(sys1, &e, H, 1, 0, NULL) == -1);  /* gen 1 */
                CHECK(run_exec(sys2, &e, H, 1, 0, NULL) == -1);  /* gen 2 */
                CHECK(run_exec(sysE, &e, H, 1, 0, NULL) == -1);  /* gen 3 */
                CHECK(run_exec(NULL, &e, H, 1, 0, NULL) == -1);  /* NULL  */
                memset(&ev, 0, sizeof(ev));
                CHECK(run_exec(sysS, &e, H, 1, 0, &ev) == 0);    /* gen 4 */
                CHECK(ev.effect_count == 1);
                CHECK(ev.eff[0].effect_kind == DNA_EFFECT_CREATE);
                CHECK(ev.eff[0].precond_tag == DNA_EFFECT_PRE_ABSENT);
                CHECK(ev.eff[0].key_len == 12);
                {
                    const uint8_t *kk = ev.buf + ev.key_off[0];
                    uint8_t want[12] = { 0, 0, 0, legs[k].id };
                    put64(want + 4, ok_eff);
                    CHECK(memcmp(kk, want, 12) == 0);
                }
                /* the facts do not gate them */
                g_svoted = 1;
                g_rvoted = 1;
                CHECK(run_exec(sysS, &e, H, 0, 1, NULL) == 0);
                g_svoted = 0;
                g_rvoted = 0;
                free(e.bytes);
            }
            /* an out-of-range value never reaches the stateful rules */
            {
                cc_leg_t e;
                cc_leg_build(&e, 19, (uint64_t)INT64_MAX + 1u, ok_eff,
                             ok_eff + 1000u);
                CHECK(run_exec(sysS, &e, H, 1, 0, NULL) == -1);
                free(e.bytes);
                cc_leg_build(&e, 20, 499u, ok_eff, ok_eff + 1000u);
                CHECK(run_exec(sysS, &e, H, 1, 0, NULL) == -1);
                free(e.bytes);
                cc_leg_build(&e, 21, (uint64_t)DNAC_HF6_STORAGE_BOND_MAX + 1u,
                             ok_eff, ok_eff + 1000u);
                CHECK(run_exec(sysS, &e, H, 1, 0, NULL) == -1);
                free(e.bytes);
                cc_leg_build(&e, 18, 500u, ok_eff, ok_eff + 1000u);
                CHECK(run_exec(sysS, &e, H, 1, 0, NULL) == -1);
                free(e.bytes);
            }
        }
#endif
        free(e9.bytes);
        free(e9b.bytes);
    }

    /* ── 6. the read side: slots for 9-13, far-future "any row" ───── */
    {
        char dir[64];
        nodus_witness_t *w = calloc(1, sizeof(*w));
        CHECK(w != NULL);
        snprintf(dir, sizeof(dir), "/tmp/test_hf4_params_XXXXXX");
        CHECK(mkdtemp(dir) != NULL);
        snprintf(w->data_path, sizeof(w->data_path), "%s", dir);
        uint8_t cid[16];
        memset(cid, 0xC4, sizeof(cid));
        CHECK(nodus_witness_create_chain_db(w, cid) == 0 && w->db);

        uint64_t v = 0;
        /* no row anywhere: genuinely absent, never a missing-slot -1
         * (Nodus EVM: slots 14-15; storage reward v1: slot 16 too —
         * RETIRED, still read) */
        for (uint8_t id = 9; id <= 22; id++) {   /* HF-8: slot 17 too;
                                                  * HF-6: 18-21; HF-7: 22 */
            CHECK(nodus_chain_config_get_u64(w, id, 1000, 77, &v) == 1);
            CHECK(v == 77);
        }
        CHECK(nodus_chain_config_get_u64(w, 9, (uint64_t)INT64_MAX, 0, &v)
              == 1);

        direct_insert(w, 11, DNAC_CFG_MIN_NAME_PRICE, 500);
        direct_insert(w, 9, (uint64_t)DNAC_CFG_RULESET_GEN2_D2,
                      (uint64_t)INT64_MAX - 1u);
        CHECK(nodus_chain_config_get_u64(w, 11, 499, 0, &v) == 1);
        CHECK(nodus_chain_config_get_u64(w, 11, 500, 0, &v) == 0 &&
              v == DNAC_CFG_MIN_NAME_PRICE);
        CHECK(w->chain_config_cache_warm);
        CHECK(w->chain_config_cache_count[11] == 1);
        CHECK(w->chain_config_cache_count[10] == 0);
        CHECK(w->chain_config_cache_count[12] == 0);
        /* the far-future vote: invisible at any real height, found by the
         * engine's single-use read (current_block INT64_MAX) — before and
         * after a re-warm of the cache */
        CHECK(nodus_chain_config_get_u64(w, 9, 1000000, 0, &v) == 1);
        CHECK(nodus_chain_config_get_u64(w, 9, (uint64_t)INT64_MAX, 0, &v)
              == 0 && v == (uint64_t)DNAC_CFG_RULESET_GEN2_D2);
        w->chain_config_cache_warm = false;
        CHECK(nodus_chain_config_get_u64(w, 9, (uint64_t)INT64_MAX, 0, &v)
              == 0);
        /* HF-6 slice 8c: a param-18 row lands in ITS slot and the
         * single-use read finds it the same way */
        CHECK(nodus_chain_config_get_u64(w, 18, (uint64_t)INT64_MAX, 0, &v)
              == 1);
        direct_insert(w, 18, (uint64_t)DNAC_CFG_RULESET_GEN_ROLES_D,
                      (uint64_t)INT64_MAX - 2u);
        CHECK(nodus_chain_config_get_u64(w, 18, 1000000, 0, &v) == 1);
        CHECK(nodus_chain_config_get_u64(w, 18, (uint64_t)INT64_MAX, 0, &v)
              == 0 && v == (uint64_t)DNAC_CFG_RULESET_GEN_ROLES_D);
        CHECK(w->chain_config_cache_count[18] == 1);
        CHECK(w->chain_config_cache_count[14] == 0);
        CHECK(w->chain_config_cache_count[9] == 1);
        /* RETIRED 16: its slot still exists — a row committed before the
         * retirement is found by the engine's "any param-16 row" read
         * (the param-18 rule (a')), in its own slot */
        CHECK(nodus_chain_config_get_u64(w, 16, (uint64_t)INT64_MAX, 0, &v)
              == 1);
        direct_insert(w, 16, 7u, 800);
        CHECK(nodus_chain_config_get_u64(w, 16, (uint64_t)INT64_MAX, 0, &v)
              == 0 && v == 7u);
        CHECK(w->chain_config_cache_count[16] == 1);
        CHECK(w->chain_config_cache_count[18] == 1);
        /* HF-8: a param-17 row lands in ITS slot; below its effective
         * height the switch reads absent (the engine's OFF), from it on 1 */
        CHECK(w->chain_config_cache_count[17] == 0);
        direct_insert(w, 17, DNAC_CFG_DELEGATE_NAME_REQUIRED_ON, 900);
        CHECK(nodus_chain_config_get_u64(w, 17, 899, 0, &v) == 1 && v == 0);
        CHECK(nodus_chain_config_get_u64(w, 17, 900, 0, &v) == 0 &&
              v == DNAC_CFG_DELEGATE_NAME_REQUIRED_ON);
        CHECK(w->chain_config_cache_count[17] == 1);
        CHECK(w->chain_config_cache_count[16] == 1);
        /* HF-6 slice 8a: a 19 / 20 / 21 row each lands in ITS slot and is
         * read at and above its effective height; slot 18 keeps its one
         * row */
        direct_insert(w, 19, (uint64_t)DNAC_HF6_STAKE_MIN_MIN, 950);
        direct_insert(w, 20, 500u, 960);
        direct_insert(w, 21, (uint64_t)DNAC_HF6_STORAGE_BOND_MIN, 970);
        CHECK(nodus_chain_config_get_u64(w, 19, 949,
                                         DNAC_HF6_STAKE_MIN_DEFAULT, &v) == 1
              && v == DNAC_HF6_STAKE_MIN_DEFAULT);
        CHECK(nodus_chain_config_get_u64(w, 19, 950, 0, &v) == 0 &&
              v == (uint64_t)DNAC_HF6_STAKE_MIN_MIN);
        CHECK(nodus_chain_config_get_u64(w, 20, 960, 0, &v) == 0 &&
              v == 500u);
        CHECK(nodus_chain_config_get_u64(w, 21, 969, 0, &v) == 1);
        CHECK(nodus_chain_config_get_u64(w, 21, 970, 0, &v) == 0 &&
              v == (uint64_t)DNAC_HF6_STORAGE_BOND_MIN);
        CHECK(w->chain_config_cache_warm);
        CHECK(w->chain_config_cache_count[18] == 1);
        CHECK(w->chain_config_cache_count[19] == 1);
        CHECK(w->chain_config_cache_count[20] == 1);
        CHECK(w->chain_config_cache_count[21] == 1);
        CHECK(w->chain_config_cache_count[17] == 1);

        sqlite3_close(w->db);
        free(w);
        char cmd[128];
        snprintf(cmd, sizeof(cmd), "rm -rf '%s'", dir);
        if (system(cmd) != 0) { /* best effort */ }
    }

    printf("test_hf4_params: ALL CHECKS PASSED\n");
    return 0;
}
