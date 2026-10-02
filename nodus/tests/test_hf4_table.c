/**
 * @file nodus/tests/test_hf4_table.c
 * @brief HF-4 part A1 — the compiled rule-set GENERATION table, its
 *        selfcheck, the D2 vote digest, and generation 2's CORE rule 8
 *        refusal before its exec exists.
 *
 * Design docs/plans/2026-10-02-onchain-names-design.md rev 4 §1.1-§1.2;
 * decision docs/plans/decisions/2026-10-02-onchain-names.md items 12, 18.
 *
 * ── WHAT IT PROVES ──────────────────────────────────────────────────────
 *  1. Shape: 2 generations; the full table is generation-major (gen 1
 *     SYSTEM, gen 1 CORE, gen 2 SYSTEM, gen 2 CORE); generation ids are
 *     filled; nodus_runtime_builtin_table is EXACTLY generation 1 (the
 *     two entries every pre-HF-4 consumer saw — genesis seeding reads
 *     it); generation_table(0/3) and for_generation(3, ·) are NULL.
 *  2. Generation 1 is today's chain: SYSTEM v6 / CORE v4, rule lists
 *     {1..6} / {1..7}, type lists unchanged, the SYSTEM policy prices ops
 *     1..7 and NOT 8, CORE declares no policy.
 *  3. Generation 2: SYSTEM v7 (rules {1..6}, types {4,5,6,7,9,10}),
 *     CORE v5 (rules {1..8}, types {1,2,3,11,12,13}), same kind / abi /
 *     names / hooks / allowlists; its SYSTEM policy is shape v2 (seven
 *     weights 1, the 2 MiB max_block_env_bytes field KEPT — decision item
 *     12), prices ops 1..8 with weight 1 and nothing else.
 *  4. Exact-tuple lookup resolves each generation's tuple to its own
 *     entry, and a cross-generation mix (gen-2 version with gen-1 hash)
 *     to nothing.
 *  5. nodus_witness_runtime_selfcheck() == 0 — which re-derives every
 *     pinned ruleset_hash (both generations), both policy digests, and
 *     the D2 literal from the generation-2 pins through the C encoder.
 *     This is the NON-circular check: the pins are INDEPENDENT-oracle
 *     literals, the encoder is this build's.
 *  6. dna_ruleset_gen_digest: top bit always clear; generation, either
 *     hash and the switch spec version each move the value; NULL refused.
 *  7. CORE rule 8: owned by generation 2 only; the shared CORE read_plan
 *     and exec hooks REFUSE it as a verdict (-1), never a fault (-2), for
 *     a generation-1 or NULL runtime (its execution under generation 2:
 *     test_hf4_names.c).
 *
 * ── WHAT IT REQUIRES ────────────────────────────────────────────────────
 * Compile flags: none. Environment: none. No database.
 *
 * ── WHAT IT LEAVES BEHIND ───────────────────────────────────────────────
 * Nothing.
 *
 * ── HOW IT CAN LIE ──────────────────────────────────────────────────────
 *  - Section 5 checks the four oracle-filled literals (generation-2
 *    SYSTEM / CORE ruleset_hash and policy digest G1-G3 in
 *    nodus_witness_runtime.c, D2 in dnac.h — filled from
 *    shared/dnac/tests/hf4_oracle.py, commit 89f9da09). If one stops
 *    re-deriving, section 5 fails — that is the point: a table whose
 *    pins do not re-derive must not start.
 *  - Section 7 feeds the hooks a view with no call bytes, so its gen-2
 *    case proves only the parse refusal; the op-8 matrix is
 *    test_hf4_names.c.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness_runtime.h"
#include "dnac/dnac.h"
#include "dnac/domain_wire.h"
#include "dnac/res_meter.h"
#include "dnac/env_wire.h"
#include "dnac/ledger_ids.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(cond) do { \
    if (!(cond)) { fprintf(stderr, "CHECK fail at %s:%d: %s\n", \
        __FILE__, __LINE__, #cond); exit(1); } } while (0)

static int rules_are(const dna_ruleset_desc_t *d, uint32_t n_expected) {
    if (d->rule_count != n_expected) return 0;
    for (uint32_t i = 0; i < n_expected; i++)
        if (d->rule_ids[i] != i + 1u) return 0;
    return 1;
}

static int types_are(const dna_ruleset_desc_t *d, const uint8_t *t,
                     size_t n) {
    return d->tx_type_count == n && memcmp(d->tx_types, t, n) == 0;
}

static int priced(const dna_meter_policy_t *p, uint32_t op) {
    uint64_t w = 0;
    return dna_meter_op_weight(p, op, &w) == 0 && w == 1u;
}

int main(void) {
    static const uint8_t SYS_T[6]  = { 4, 5, 6, 7, 9, 10 };
    static const uint8_t CORE_T[6] = { 1, 2, 3, 11, 12, 13 };
    static const uint8_t zero64[64] = { 0 };

    /* ── 1. shape ──────────────────────────────────────────────────── */
    CHECK(nodus_runtime_generation_count() == 2);
    CHECK(NODUS_RT_GEN_MAX == NODUS_RT_GEN_2);
    size_t n_all = 0, n1 = 0, n2 = 0, nb = 0;
    const nodus_domain_runtime_t *all = nodus_runtime_all_table(&n_all);
    const nodus_domain_runtime_t *g1  =
        nodus_runtime_generation_table(NODUS_RT_GEN_1, &n1);
    const nodus_domain_runtime_t *g2  =
        nodus_runtime_generation_table(NODUS_RT_GEN_2, &n2);
    const nodus_domain_runtime_t *bt  = nodus_runtime_builtin_table(&nb);
    CHECK(all && n_all == 4);
    CHECK(g1 && n1 == 2 && g1 == &all[0]);
    CHECK(g2 && n2 == 2 && g2 == &all[2]);
    CHECK(bt == g1 && nb == 2);                  /* genesis generation */
    for (size_t i = 0; i < n_all; i++) {
        CHECK(all[i].generation == (uint32_t)(i / 2u) + 1u);
        CHECK(all[i].domain_id == ((i % 2u) == 0 ? DNA_DOMAIN_SYSTEM
                                                 : DNA_DOMAIN_CORE));
    }
    {
        size_t nz = 99;
        CHECK(nodus_runtime_generation_table(0, &nz) == NULL && nz == 0);
        CHECK(nodus_runtime_generation_table(3, &nz) == NULL && nz == 0);
        CHECK(nodus_runtime_for_generation(3, DNA_DOMAIN_SYSTEM) == NULL);
        CHECK(nodus_runtime_for_generation(1, 7) == NULL);
        CHECK(nodus_runtime_for_generation(2, DNA_DOMAIN_CORE) == &all[3]);
    }

    /* ── 2. generation 1 = today ───────────────────────────────────── */
    CHECK(g1[0].ruleset_version == 6 && g1[1].ruleset_version == 4);
    CHECK(rules_are(&g1[0].descriptor, 6));
    CHECK(rules_are(&g1[1].descriptor, 7));
    CHECK(types_are(&g1[0].descriptor, SYS_T, 6));
    CHECK(types_are(&g1[1].descriptor, CORE_T, 6));
    CHECK(g1[0].meter_policy != NULL && g1[1].meter_policy == NULL);
    for (uint32_t op = 1; op <= 7; op++)
        CHECK(priced(g1[0].meter_policy, op));
    {
        uint64_t w = 0;
        CHECK(dna_meter_op_weight(g1[0].meter_policy,
                                  DNA_CORERULE_NAME_REGISTER, &w) != 0);
    }
    CHECK(memcmp(g1[1].descriptor.meter_policy_digest, zero64, 64) == 0);

    /* ── 3. generation 2 ───────────────────────────────────────────── */
    CHECK(g2[0].ruleset_version == 7 && g2[1].ruleset_version == 5);
    CHECK(rules_are(&g2[0].descriptor, 6));
    CHECK(rules_are(&g2[1].descriptor, 8));
    CHECK(g2[1].descriptor.rule_ids[7] == DNA_CORERULE_NAME_REGISTER);
    CHECK(types_are(&g2[0].descriptor, SYS_T, 6));
    CHECK(types_are(&g2[1].descriptor, CORE_T, 6));
    for (int k = 0; k < 2; k++) {
        CHECK(g2[k].runtime_kind == g1[k].runtime_kind);
        CHECK(g2[k].runtime_abi == g1[k].runtime_abi);
        CHECK(memcmp(g2[k].descriptor.name, g1[k].descriptor.name,
                     DNA_DOM_NAME_LEN) == 0);
        CHECK(g2[k].allowed_auth_kinds == g1[k].allowed_auth_kinds);
        CHECK(g2[k].auth == g1[k].auth && g2[k].read_plan == g1[k].read_plan &&
              g2[k].exec == g1[k].exec && g2[k].adapter == g1[k].adapter &&
              g2[k].state_root == g1[k].state_root);
    }
    CHECK(g2[1].meter_policy == NULL);
    CHECK(memcmp(g2[1].descriptor.meter_policy_digest, zero64, 64) == 0);
    {
        const dna_meter_policy_t *p1 = g1[0].meter_policy;
        const dna_meter_policy_t *p2 = g2[0].meter_policy;
        CHECK(p2 != NULL && p2 != p1);
        CHECK(p2->policy_version == p1->policy_version);
        CHECK(p2->policy_version == DNA_METER_POLICY_VERSION);
        CHECK(p2->w_base == 1 && p2->w_callbyte == 1 && p2->w_authbyte == 1 &&
              p2->w_effect == 1 && p2->w_effectbyte == 1 && p2->w_read == 1 &&
              p2->w_write == 1);
        CHECK(p2->max_block_env_bytes == p1->max_block_env_bytes);
        CHECK(p2->max_block_env_bytes == 2u * DNA_ENV_MAX_TOTAL_LEN);
        for (uint32_t op = 0; op < DNA_METER_OP_SPACE; op++) {
            uint64_t w = 0;
            int has = dna_meter_op_weight(p2, op, &w) == 0;
            CHECK(has == (op >= 1u && op <= 8u));
            if (has) CHECK(w == 1u);
        }
        CHECK(memcmp(g1[0].descriptor.meter_policy_digest,
                     g2[0].descriptor.meter_policy_digest, 64) != 0);
    }

    /* ── 4. exact-tuple lookup over every generation ───────────────── */
    for (size_t i = 0; i < n_all; i++) {
        const nodus_domain_runtime_t *r = &all[i];
        CHECK(nodus_runtime_lookup(r->domain_id, r->runtime_kind,
                                   r->runtime_abi, r->ruleset_version,
                                   r->ruleset_hash) == r);
    }
    /* gen-2 version + gen-1 hash: no entry (fail-closed) */
    CHECK(nodus_runtime_lookup(DNA_DOMAIN_SYSTEM, g1[0].runtime_kind,
                               g1[0].runtime_abi, 7,
                               g1[0].ruleset_hash) == NULL);
    CHECK(nodus_runtime_lookup(DNA_DOMAIN_CORE, g1[1].runtime_kind,
                               g1[1].runtime_abi, 4,
                               g2[1].ruleset_hash) == NULL);

    /* ── 5. selfcheck: every pin re-derives (oracle vs encoder) ────── */
    CHECK(nodus_witness_runtime_selfcheck() == 0);

    /* ── 6. the D2 digest's properties ─────────────────────────────── */
    {
        uint8_t a[64], b[64];
        uint64_t d0 = 0, d = 0;
        memset(a, 0x11, sizeof(a));
        memset(b, 0x22, sizeof(b));
        CHECK(dna_ruleset_gen_digest(2, a, b, 1, &d0) == 0);
        CHECK(d0 <= (uint64_t)INT64_MAX);
        CHECK(dna_ruleset_gen_digest(2, a, b, 1, &d) == 0 && d == d0);
        CHECK(dna_ruleset_gen_digest(3, a, b, 1, &d) == 0 && d != d0);
        CHECK(dna_ruleset_gen_digest(2, a, b, 2, &d) == 0 && d != d0);
        CHECK(dna_ruleset_gen_digest(2, b, a, 1, &d) == 0 && d != d0);
        a[63] ^= 1u;
        CHECK(dna_ruleset_gen_digest(2, a, b, 1, &d) == 0 && d != d0);
        CHECK(dna_ruleset_gen_digest(2, NULL, b, 1, &d) == -1);
        CHECK(dna_ruleset_gen_digest(2, a, NULL, 1, &d) == -1);
        CHECK(dna_ruleset_gen_digest(2, a, b, 1, NULL) == -1);
        /* the compiled literal re-derives from the compiled gen-2 pins */
        CHECK(dna_ruleset_gen_digest(NODUS_RT_GEN_2, g2[0].ruleset_hash,
                                     g2[1].ruleset_hash,
                                     DNAC_RULESET_SWITCH_SPEC_VERSION,
                                     &d) == 0);
        CHECK(d == (uint64_t)DNAC_CFG_RULESET_GEN2_D2);
    }

    /* ── 7. CORE rule 8: owned by gen 2 only, refused as a verdict ─── */
    {
        int owned1 = 0, owned2 = 0;
        for (size_t i = 0; i < g1[1].descriptor.rule_count; i++)
            if (g1[1].descriptor.rule_ids[i] == DNA_CORERULE_NAME_REGISTER)
                owned1 = 1;
        for (size_t i = 0; i < g2[1].descriptor.rule_count; i++)
            if (g2[1].descriptor.rule_ids[i] == DNA_CORERULE_NAME_REGISTER)
                owned2 = 1;
        CHECK(!owned1 && owned2);

        dna_env_view_t v;
        memset(&v, 0, sizeof(v));
        v.leg_count = 1;
        v.leg[0].domain_id   = DNA_DOMAIN_CORE;
        v.leg[0].runtime_op  = DNA_CORERULE_NAME_REGISTER;
        v.leg[0].auth_kind   = NODUS_RT_AUTHKIND_DSA87_MULTI_V1;
        v.leg[0].access_mode = DNA_ENV_ACCESS_INVOKE;

        static uint8_t chain_id[DNA_CHAIN_ID_LEN], intent[64];
        nodus_rt_auth_verdict_t av;
        memset(&av, 0, sizeof(av));
        av.n_signers = 1;
        memset(av.signer_fp[0], 0x3C, 64);
        nodus_rt_exec_ctx_t ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.chain_id = chain_id;
        ctx.intent_id = intent;
        ctx.global_height = 10;
        ctx.auth = &av;

        /* A2: generation 2 EXECUTES op 8 (test_hf4_names.c); the shared
         * CORE hooks refuse it — as a verdict (-1), never a fault — for a
         * generation-1 runtime and for a NULL / synthetic one, whatever
         * the call bytes (this view carries none). */
        nodus_rt_read_req_t reqs[NODUS_RT_MAX_READS];
        uint16_t nr = 0;
        static uint8_t res[DNA_EFFECT_MAX_TOTAL_LEN];
        size_t rl = 0;
        CHECK(nodus_rt_core_read_plan(&g1[1], &v, 0, &ctx, reqs,
                                      NODUS_RT_MAX_READS, &nr) == -1);
        CHECK(nodus_rt_core_exec(&g1[1], &v, 0, &ctx, NULL, 0, res,
                                 sizeof(res), &rl) == -1);
        CHECK(nodus_rt_core_read_plan(NULL, &v, 0, &ctx, reqs,
                                      NODUS_RT_MAX_READS, &nr) == -1);
        CHECK(nodus_rt_core_exec(NULL, &v, 0, &ctx, NULL, 0, res,
                                 sizeof(res), &rl) == -1);
        /* and a gen-2 runtime with an empty call refuses at the parse */
        CHECK(nodus_rt_core_read_plan(&g2[1], &v, 0, &ctx, reqs,
                                      NODUS_RT_MAX_READS, &nr) == -1);
        CHECK(nodus_rt_core_exec(&g2[1], &v, 0, &ctx, NULL, 0, res,
                                 sizeof(res), &rl) == -1);
    }

    printf("test_hf4_table: ALL CHECKS PASSED\n");
    return 0;
}
