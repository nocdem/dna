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
 *  1. ids: RULESET_GEN2 = 9, NAME_PRICE_3P..6P = 10..13 (MAX_ID 16 since
 *     Nodus EVM 14-15 and storage reward v1 16), all on the read list;
 *     D2 <= INT64_MAX; SWITCH_SPEC_VERSION 1.
 *  2. scalar rules: param 9 accepts EXACTLY D2 (D2 ± 1, UINT64_MAX
 *     refused; the shared window and int64 rules still apply); params
 *     10-13 accept [10^8, 10^15] inclusive, refuse one past either end;
 *     (storage reward v1: param 16, below; id 17 refused).
 *  3. grace: 9-13 ERGONOMIC (decision item 17), HF-3's class.
 *  4. nodus_chain_config_stateful_rules — the full matrix: param 9
 *     refused when a param-9 row exists (single use), when HF-2 is off,
 *     when effective-1 is a nonzero epoch-length multiple, when effective
 *     is 0; accepted otherwise (effective 1 included: height 0 is not a
 *     boundary). Params 10-13 refused under generation 0/1, accepted
 *     under 2. Ids 1-8 no stateful rule; 0, 17, 255 refused.
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
 *  STORAGE REWARD v1 (decision docs/plans/decisions/2026-10-04-storage-
 *  reward-approved.md; design docs/plans/2026-10-04-storage-reward-v1-
 *  design.md rev 2.2 §6 — param 16 RULESET_GEN_STORAGE, "voted like
 *  RULESET_GEN2"; ids and generation in main merge order, Nodus EVM
 *  first), added to the sections above:
 *   1. id 16 = RULESET_GEN_STORAGE, MAX_ID = 16, on the read list; 17 not;
 *      its literal <= INT64_MAX and distinct from D2.
 *   2. param 16 accepts EXACTLY its literal (±1, D2, UINT64_MAX refused;
 *      the window rule binds); param 9 refuses the storage literal; id 17
 *      refused.
 *   3. grace 16 ERGONOMIC.
 *   4. stateful: param 16 refused unless EXACTLY the EVM generation
 *      (NODUS_RT_GEN_STORAGE_BASE) judges (rule d: 0/1/2 and GEN_STORAGE
 *      refused), accepted there with no row / HF-2 on / non-boundary;
 *      refused with a param-16 row (a), HF-2 off (b), boundary (c),
 *      effective 0; the facts form reads the param-16 fact for param 16
 *      only. K10 (decision 2026-10-05-storage-reward-is-for-archive.md):
 *      rule (d) keeps the storage edge out of the EVM edge's block — a
 *      storage vote judged under the EVM base (every block up to the EVM
 *      edge block) is refused whatever its effective height.
 *   5. exec hook (EVM-enabled build): a param-16 leg refused by the
 *      generation-1, -2, GEN_STORAGE and NULL runtimes, accepted by the
 *      EVM generation (one CREATE keyed 16 ‖ effective); the param-9 fact
 *      does NOT gate it, the param-16 fact does, and the param-16 fact
 *      does NOT gate a param-9 leg; the read plan is empty.
 *   6. slot 16 readable; a far-future param-16 row found at INT64_MAX.
 *  HOW IT CAN LIE (storage): every "exactly the literal" check on
 *  DNAC_CFG_RULESET_GEN_STORAGE_D here holds for any literal value — and
 *  the literal is the unfilled oracle placeholder 0 (STORAGE-ORACLE: NOT
 *  FILLED) until the oracle re-runs; its correctness is
 *  test_hf4_table.c's selfcheck re-derivation. Section 5's storage half
 *  does not run in a build without NODUS_EVM_ENABLED. The same-block
 *  check is over the pure rule, not a block-level run (test_hf4_switch.c
 *  has the engine's edges).
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

/* Storage reward v1: the param-14 single-use fact the next run_exec hands
 * the hook (ctx.ruleset_gen_storage_voted); 0 unless a section sets it. */
static uint8_t g_svoted = 0;

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
     * storage reward v1 appends 16 RULESET_GEN_STORAGE (main merge
     * order), now the last id; 17 is the first unknown id. HF-4's own
     * ids are unchanged and still read by consensus. */
    CHECK(DNAC_CFG_RULESET_GEN_STORAGE == 16);
    CHECK(DNAC_CFG_PARAM_MAX_ID == 16);
    for (unsigned id = 9; id <= 16; id++)
        CHECK(dnac_cfg_param_read_by_consensus((uint8_t)id));
    CHECK(!dnac_cfg_param_read_by_consensus(17));
    CHECK(DNAC_CFG_RULESET_GEN2_D2 <= (uint64_t)INT64_MAX);
    CHECK(DNAC_CFG_RULESET_GEN_STORAGE_D <= (uint64_t)INT64_MAX);
    CHECK(DNAC_CFG_RULESET_GEN_STORAGE_D != DNAC_CFG_RULESET_GEN2_D2);
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
        /* storage reward v1: param 16 accepts EXACTLY the storage vote
         * literal (the param-9 shape), refuses its neighbours, D2 and
         * UINT64_MAX; id 17 is unknown. (While the literal is the unfilled
         * oracle placeholder 0, DS - 1 wraps to UINT64_MAX — still
         * refused.) */
        {
            const uint64_t DS = (uint64_t)DNAC_CFG_RULESET_GEN_STORAGE_D;
            CHECK(nodus_chain_config_scalar_rules(16, DS, 1, 5000, 4000, 7)
                  == 0);
            CHECK(nodus_chain_config_scalar_rules(16, DS + 1u, 1, 5000,
                                                  4000, 7) == -1);
            CHECK(nodus_chain_config_scalar_rules(16, DS - 1u, 1, 5000,
                                                  4000, 7) == -1);
            CHECK(nodus_chain_config_scalar_rules(16, D2, 1, 5000, 4000, 7)
                  == -1);
            CHECK(nodus_chain_config_scalar_rules(16, UINT64_MAX, 1, 5000,
                                                  4000, 7) == -1);
            CHECK(nodus_chain_config_scalar_rules(16, DS, 0, 5000, 4000, 7)
                  == -1);               /* the shared window rule binds */
            /* and param 9 does not accept the storage literal */
            CHECK(nodus_chain_config_scalar_rules(9, DS, 1, 5000, 4000, 7)
                  == -1);
        }
        CHECK(nodus_chain_config_scalar_rules(17, DNAC_CFG_MIN_NAME_PRICE, 1,
                                              5000, 4000, 7) == -1);
    }

    /* ── 3. grace: ERGONOMIC, HF-3's class (16: param 9's class; the
     *       EVM ids 14-15 between them are SAFETY, Nodus EVM's own) ──── */
    for (uint8_t id = 9; id <= 16; id++) {
        if (id == DNAC_CFG_EVM_ACTIVE || id == DNAC_CFG_EVM_BLOCK_GAS_LIMIT)
            continue;
        CHECK(nodus_chain_config_grace_for_param(id) == GRACE_E);
        CHECK(nodus_chain_config_grace_for_param(id) ==
              nodus_chain_config_grace_for_param(DNAC_CFG_HF3_ACTIVE));
    }

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
        /* storage reward v1 — param 16: rule (d) EXACTLY the EVM
         * generation (NODUS_RT_GEN_STORAGE_BASE) judges, then param 9's
         * (a)-(c), (a) over the param-16 fact the caller hands in the same
         * argument slot */
        {
            const uint32_t GB = NODUS_RT_GEN_STORAGE_BASE;
            CHECK(GB == NODUS_RT_GEN_EVM);
            CHECK(nodus_chain_config_stateful_rules(16, ok_eff, 1, 0, 0)
                  == -1);
            CHECK(nodus_chain_config_stateful_rules(16, ok_eff, 1, 0, 1)
                  == -1);
            CHECK(nodus_chain_config_stateful_rules(16, ok_eff, 1, 0, 2)
                  == -1);               /* (d) the EVM base, not the EVM
                                         * generation                    */
            CHECK(nodus_chain_config_stateful_rules(16, ok_eff, 1, 0, GB)
                  == 0);
            CHECK(nodus_chain_config_stateful_rules(16, ok_eff, 1, 0,
                                                    NODUS_RT_GEN_STORAGE)
                  == -1);               /* (d) already switched          */
            CHECK(nodus_chain_config_stateful_rules(16, ok_eff, 1, 1, GB)
                  == -1);               /* (a) a param-16 row exists     */
            CHECK(nodus_chain_config_stateful_rules(16, ok_eff, 0, 0, GB)
                  == -1);               /* (b) HF-2 off                  */
            CHECK(nodus_chain_config_stateful_rules(16, E_LEN + 1u, 1, 0, GB)
                  == -1);               /* (c) H-1 = E                   */
            CHECK(nodus_chain_config_stateful_rules(16, 0, 1, 0, GB) == -1);
        }
        /* the facts form: the param-16 fact gates ONLY param 16, the
         * param-9 fact ONLY param 9 */
        {
            nodus_cc_state_facts_t f;
            memset(&f, 0, sizeof(f));
            f.hf2_active = 1;
            f.judging_generation = NODUS_RT_GEN_STORAGE_BASE;
            CHECK(nodus_chain_config_stateful_rules_ex(16, ok_eff, &f) == 0);
            f.ruleset_gen2_voted = 1;
            CHECK(nodus_chain_config_stateful_rules_ex(16, ok_eff, &f) == 0);
            f.ruleset_gen_storage_voted = 1;
            CHECK(nodus_chain_config_stateful_rules_ex(16, ok_eff, &f) == -1);
            f.ruleset_gen2_voted = 0;
            f.judging_generation = NODUS_RT_GEN_1;
            CHECK(nodus_chain_config_stateful_rules_ex(9, ok_eff, &f) == 0);
        }
        /* K10 (decision 2026-10-05-storage-reward-is-for-archive.md): rule
         * (d) keeps the storage edge out of the EVM edge's block. The EVM
         * edge switches the registry at the END of block He-1 (He = the
         * EVM_ACTIVE row's effective height), so every block up to and
         * including He-1 is judged under the EVM BASE generation and every
         * block from He on under the EVM generation. A storage vote whose
         * edge block Hs-1 equals He-1 would have to be judged at or before
         * He-1 — under the base — and is refused whatever its effective
         * height (Hs = He included); a vote judged at the EVM generation
         * sits at a height >= He and its effective is >= that height +
         * the grace, so its edge block lies strictly above He-1. */
        {
            const uint64_t He = eff_not_boundary(4u * E_LEN + 7u);
            for (uint64_t hs = He - 1u; hs <= He + 1u; hs++) {
                if (((hs - 1u) % E_LEN) == 0) continue;
                CHECK(nodus_chain_config_stateful_rules(
                          16, hs, 1, 0, NODUS_RT_GEN_EVM_BASE) == -1);
            }
            /* the earliest vote the EVM generation judges is at He; its
             * edge block is at least He + grace - 1 > He - 1 */
            CHECK(He + nodus_chain_config_grace_for_param(16) - 1u > He - 1u);
            CHECK(nodus_chain_config_grace_for_param(16) >= 1u);
        }
        CHECK(nodus_chain_config_stateful_rules(0, ok_eff, 1, 0, 2) == -1);
        CHECK(nodus_chain_config_stateful_rules(17, ok_eff, 1, 0, 2) == -1);
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

        /* storage reward v1 — a param-16 leg through the same hook: the
         * hook hands the stateful rules the PARAM-16 fact (never the
         * param-9 one) and its own generation; the read plan stays
         * empty (the fact is unmetered). The EVM generation's SYSTEM
         * runtime (the only one that accepts it) exists in an
         * EVM-enabled build only (K10: GEN_STORAGE is EVM-only too). */
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
            cc_leg_t e16, e16b;
            cc_leg_build(&e16, 16,
                         (uint64_t)DNAC_CFG_RULESET_GEN_STORAGE_D, ok_eff,
                         ok_eff + 1000u);
            cc_leg_build(&e16b, 16,
                         (uint64_t)DNAC_CFG_RULESET_GEN_STORAGE_D, bd_eff,
                         bd_eff + 1000u);
            check_no_reads(sysE, &e16);
            g_svoted = 0;
            CHECK(run_exec(sys1, &e16, H, 1, 0, NULL) == -1);  /* (d) gen 1 */
            CHECK(run_exec(sys2, &e16, H, 1, 0, NULL) == -1);  /* (d) gen 2 */
            CHECK(run_exec(sysS, &e16, H, 1, 0, NULL) == -1);  /* (d) gen 4 */
            CHECK(run_exec(NULL, &e16, H, 1, 0, NULL) == -1);  /* (d) NULL  */
            memset(&ev, 0, sizeof(ev));
            CHECK(run_exec(sysE, &e16, H, 1, 0, &ev) == 0);
            CHECK(ev.effect_count == 1);
            CHECK(ev.eff[0].effect_kind == DNA_EFFECT_CREATE);
            {
                const uint8_t *k = ev.buf + ev.key_off[0];
                uint8_t want[12] = { 0, 0, 0, 16 };
                put64(want + 4, ok_eff);
                CHECK(memcmp(k, want, 12) == 0);
            }
            /* the param-9 fact does NOT gate param 16 … */
            CHECK(run_exec(sysE, &e16, H, 1, 1, NULL) == 0);
            CHECK(run_exec(sysE, &e16, H, 0, 0, NULL) == -1);  /* (b)      */
            CHECK(run_exec(sysE, &e16b, H, 1, 0, NULL) == -1); /* (c)      */
            g_svoted = 1;
            CHECK(run_exec(sysE, &e16, H, 1, 0, NULL) == -1);  /* (a)      */
            /* … and the param-16 fact does NOT gate param 9 */
            CHECK(run_exec(sys1, &e9, H, 1, 0, NULL) == 0);
            g_svoted = 0;
            free(e16.bytes);
            free(e16b.bytes);
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
         * (Nodus EVM: slots 14-15; storage reward v1: slot 16 too) */
        for (uint8_t id = 9; id <= 16; id++) {
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
        /* storage reward v1: a param-16 row lands in ITS slot and the
         * single-use read finds it the same way */
        CHECK(nodus_chain_config_get_u64(w, 16, (uint64_t)INT64_MAX, 0, &v)
              == 1);
        direct_insert(w, 16, (uint64_t)DNAC_CFG_RULESET_GEN_STORAGE_D,
                      (uint64_t)INT64_MAX - 2u);
        CHECK(nodus_chain_config_get_u64(w, 16, 1000000, 0, &v) == 1);
        CHECK(nodus_chain_config_get_u64(w, 16, (uint64_t)INT64_MAX, 0, &v)
              == 0 && v == (uint64_t)DNAC_CFG_RULESET_GEN_STORAGE_D);
        CHECK(w->chain_config_cache_count[16] == 1);
        CHECK(w->chain_config_cache_count[14] == 0);
        CHECK(w->chain_config_cache_count[9] == 1);

        sqlite3_close(w->db);
        free(w);
        char cmd[128];
        snprintf(cmd, sizeof(cmd), "rm -rf '%s'", dir);
        if (system(cmd) != 0) { /* best effort */ }
    }

    printf("test_hf4_params: ALL CHECKS PASSED\n");
    return 0;
}
