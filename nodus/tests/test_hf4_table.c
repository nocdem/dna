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
 *  1. Shape: 2 generations (3 in an EVM-enabled build — the Nodus EVM EVM
 *     generation follows, pinned by test_v2_evm.c); generations 1 and 2
 *     are generation-major (gen 1
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
 *  STORAGE REWARD v1 (decision docs/plans/decisions/2026-10-04-storage-
 *  reward-approved.md; design docs/plans/2026-10-04-storage-reward-v1-
 *  design.md rev 2.2 §6) — the table grows a third generation,
 *  GEN_STORAGE:
 *   1'. 3 generations, 6 entries, generation-major; GEN_STORAGE =
 *       generation 2 + 1 = NODUS_RT_GEN_MAX; generation_table(4) NULL.
 *   3b. GEN_STORAGE: SYSTEM v8 (rules {1..9}: ops 7/8/9 = STORAGE_
 *       REGISTER / EXIT / REPORT, owned by no earlier generation), CORE v6
 *       (rules {1..8}), types unchanged, same kind / abi / names / hooks /
 *       adapters / allowlists; policy v2 pricing ops 1..9 with weight 1.
 *       HF-6 slice 6a (design 2026-10-03-hf5-validator-owner-stake-
 *       design.md rev 6 §2, K7; khan A6): the generation-4 SYSTEM (still
 *       v9) also owns op 10 ROTATE_CONSENSUS_KEY — rules {1..10} — and
 *       its policy prices ops 1..10, i.e. exactly the EVM generation's op
 *       set plus 10 (owned by no earlier generation); CORE v7 unchanged.
 *   6'. (deleted in HF-6 slice 8c with param 16: the storage vote
 *       literal it re-derived no longer exists.)
 *   6''. HF-6 slice 8b (design 2026-10-03-hf5-validator-owner-stake-
 *       design.md rev 6 §8.1): dna_rolegen_vote_digest over the compiled
 *       generation-4 pins + the compiled owner + the nine named constants
 *       (the test's own array) == nodus_runtime_gen4_vote_digest ==
 *       DNAC_CFG_RULESET_GEN_ROLES_D, and — only under
 *       DNAC_HF6_FOUNDATION_OWNER_IS_DEFAULT — == 0x4dc61072d5982acd, the
 *       K8 value of shared/dnac/tests/hf6_vote_oracle.py; the harness test
 *       owner 2cca88c4…ee196b93 passed explicitly gives the oracle's
 *       --owner value 0x4fc24934a9155c64 in every build; the preimage is
 *       296 bytes for n = 9 (DNA_ROLEGEN_PREIMAGE_LEN, which the
 *       constructor checks before hashing); NULL pointers and n_consts >
 *       64 are refused; generation, base, either hash, the spec version,
 *       n_consts, one owner byte and each constant move the value.
 *       HOW IT CAN LIE: the KAT numbers come from the Python oracle; this
 *       section proves the C constructor agrees with it, not that §8.1 is
 *       the right layout (that is the crypto gate's, approved 2026-10-09).
 *       In a test build that overrides the owner (stagef_hf6_owner.sh) the
 *       K8 KAT line is compiled out; the triangle and the harness-owner
 *       KAT still run.
 *   8.  the storage ops are refused (-1, never -2) by the generation-1,
 *       generation-2 and NULL SYSTEM hooks (read_plan and exec); with no
 *       call bytes GEN_STORAGE refuses them too (op 9 unconditionally —
 *       package B2); the generation-2 and NULL CORE read_plan refuse a
 *       SYSFUND leg paired with a storage op.
 *  HOW IT CAN LIE (storage): the GEN_STORAGE pins are independent-oracle
 *  literals (shared/dnac/tests/storage_oracle.py, nodus_witness_runtime.c)
 *  and D4 is hf6_vote_oracle.py's (dnac.h); section 5 (selfcheck) and the
 *  6'' re-derivation prove the C encoders agree with those oracles, not
 *  that the PROVISIONAL generation number / op ids /
 *  versions (main merge order) are final. Section 8 feeds views without
 *  call bytes, so its GEN_STORAGE case proves only the parse / B2
 *  refusals; the register /
 *  exit execution matrix is test_storage_reg.c.
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
#include "dnac/power_cap.h"      /* HF-6 8b: D4 consts[3..4] */
#include "dnac/valbind_wire.h"   /* HF-6 8b: D4 consts[8]    */

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
    /* Nodus EVM: an EVM-enabled build (NODUS_EVM_ENABLED — the standalone
     * non-Windows nodus) carries a third generation, the EVM one: three
     * slots (SYSTEM, CORE, EVM) after generations 1 and 2, which stay
     * the four slots they were (test_v2_evm.c pins the third). Storage
     * reward v1 (K10, EVM-only too): a fourth, GEN_STORAGE, on the EVM
     * generation — two slots (SYSTEM, CORE; no EVM slot, EVM v1 is
     * unchanged). */
    CHECK(NODUS_RT_GEN_STORAGE == NODUS_RT_GEN_EVM + 1u);
    CHECK(NODUS_RT_GEN_STORAGE_BASE == NODUS_RT_GEN_EVM);
#ifdef NODUS_EVM_ENABLED
    CHECK(nodus_runtime_generation_count() == 4);
    CHECK(NODUS_RT_GEN_MAX == NODUS_RT_GEN_STORAGE);
    const size_t n_all_want = 9;
#else
    CHECK(nodus_runtime_generation_count() == 2);
    CHECK(NODUS_RT_GEN_MAX == NODUS_RT_GEN_2);
    const size_t n_all_want = 4;
#endif
    size_t n_all = 0, n1 = 0, n2 = 0, nb = 0;
    const nodus_domain_runtime_t *all = nodus_runtime_all_table(&n_all);
    const nodus_domain_runtime_t *g1  =
        nodus_runtime_generation_table(NODUS_RT_GEN_1, &n1);
    const nodus_domain_runtime_t *g2  =
        nodus_runtime_generation_table(NODUS_RT_GEN_2, &n2);
    const nodus_domain_runtime_t *bt  = nodus_runtime_builtin_table(&nb);
    CHECK(all && n_all == n_all_want);
    CHECK(g1 && n1 == 2 && g1 == &all[0]);
    CHECK(g2 && n2 == 2 && g2 == &all[2]);
#ifdef NODUS_EVM_ENABLED
    size_t nE = 0, nS = 0;
    const nodus_domain_runtime_t *gE  =
        nodus_runtime_generation_table(NODUS_RT_GEN_EVM, &nE);
    const nodus_domain_runtime_t *gS  =
        nodus_runtime_generation_table(NODUS_RT_GEN_STORAGE, &nS);
    CHECK(gE && nE == 3 && gE == &all[4]);
    CHECK(gS && nS == 2 && gS == &all[7]);
    CHECK(gS[0].domain_id == DNA_DOMAIN_SYSTEM &&
          gS[1].domain_id == DNA_DOMAIN_CORE);
    /* no EVM slot in GEN_STORAGE: the EVM domain's entry is the EVM
     * generation's */
    CHECK(nodus_runtime_for_generation(NODUS_RT_GEN_STORAGE,
                                       DNA_DOMAIN_EVM) == NULL);
    CHECK(nodus_runtime_for_generation(NODUS_RT_GEN_EVM,
                                       DNA_DOMAIN_EVM) == &all[6]);
#endif
    CHECK(bt == g1 && nb == 2);                  /* genesis generation */
    for (size_t i = 0; i < 4; i++) {             /* generations 1 and 2 */
        CHECK(all[i].generation == (uint32_t)(i / 2u) + 1u);
        CHECK(all[i].domain_id == ((i % 2u) == 0 ? DNA_DOMAIN_SYSTEM
                                                 : DNA_DOMAIN_CORE));
    }
    {
        size_t nz = 99;
        CHECK(nodus_runtime_generation_table(0, &nz) == NULL && nz == 0);
        CHECK(nodus_runtime_generation_table(NODUS_RT_GEN_MAX + 1u, &nz)
                  == NULL && nz == 0);
        CHECK(nodus_runtime_for_generation(NODUS_RT_GEN_MAX + 1u,
                                           DNA_DOMAIN_SYSTEM) == NULL);
        CHECK(nodus_runtime_for_generation(1, 7) == NULL);
        CHECK(nodus_runtime_for_generation(2, DNA_DOMAIN_CORE) == &all[3]);
        CHECK(nodus_runtime_for_generation(2, DNA_DOMAIN_EVM) == NULL);
#ifdef NODUS_EVM_ENABLED
        CHECK(nodus_runtime_for_generation(NODUS_RT_GEN_STORAGE,
                                           DNA_DOMAIN_SYSTEM) == &all[7]);
#else
        /* an EVM-off build carries no GEN_STORAGE (K10) */
        CHECK(nodus_runtime_for_generation(NODUS_RT_GEN_STORAGE,
                                           DNA_DOMAIN_SYSTEM) == NULL);
#endif
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

    /* ── 3b. storage reward v1 — GEN_STORAGE (EVM-enabled build, K10):
     *        SYSTEM v9 (rules {1..9} — the EVM generation's {1..6} + ops
     *        7..9 the storage ops, types unchanged), CORE v7 (the EVM
     *        generation's rules {1..9}, types unchanged), same kind / abi /
     *        names / hooks / adapters / allowlists / root and invariant
     *        hooks as the EVM generation; policy = the EVM generation's,
     *        shape v2, ops 1..9 weight 1 ─ */
    CHECK(DNA_SYSRULE_STORAGE_REGISTER == 7 && DNA_SYSRULE_STORAGE_EXIT == 8 &&
          DNA_SYSRULE_STORAGE_REPORT == 9);
    CHECK(DNA_SYSRULE_ROTATE_CONSENSUS_KEY == 10);   /* design §2, K7 */
#ifdef NODUS_EVM_ENABLED
    CHECK(gE[0].ruleset_version == 8 && gE[1].ruleset_version == 6);
    CHECK(gS[0].ruleset_version == 9 && gS[1].ruleset_version == 7);
    CHECK(rules_are(&gE[0].descriptor, 6));
    CHECK(rules_are(&gS[0].descriptor, 10));        /* HF-6 6a: + op 10 */
    CHECK(rules_are(&gE[1].descriptor, 9));
    CHECK(rules_are(&gS[1].descriptor, 9));
    CHECK(gS[1].descriptor.rule_ids[8] == DNA_CORERULE_EVMFUND);
    CHECK(types_are(&gS[0].descriptor, SYS_T, 6));
    CHECK(types_are(&gS[1].descriptor, CORE_T, 6));
    for (int k = 0; k < 2; k++) {
        CHECK(gS[k].generation == NODUS_RT_GEN_STORAGE);
        CHECK(gS[k].runtime_kind == gE[k].runtime_kind);
        CHECK(gS[k].runtime_abi == gE[k].runtime_abi);
        CHECK(memcmp(gS[k].descriptor.name, gE[k].descriptor.name,
                     DNA_DOM_NAME_LEN) == 0);
        /* HF-6 3c: generation 4's SYSTEM also admits kind 3 (an owner may be
         * a multisig address, design §1.3); CORE's allowlist is unchanged */
        CHECK(gS[k].allowed_auth_kinds ==
              (k == 0 ? (gE[k].allowed_auth_kinds |
                         NODUS_RT_AUTHKIND_BIT(NODUS_RT_AUTHKIND_DSA87_MSIG_V1))
                      : gE[k].allowed_auth_kinds));
        CHECK(gS[k].auth == gE[k].auth && gS[k].read_plan == gE[k].read_plan &&
              gS[k].exec == gE[k].exec && gS[k].adapter == gE[k].adapter &&
              gS[k].state_root == gE[k].state_root &&
              gS[k].invariant == gE[k].invariant &&
              gS[k].claim_apply == gE[k].claim_apply);
    }
    /* the storage ops and (HF-6 6a) ROTATE_CONSENSUS_KEY are owned by
     * GEN_STORAGE's SYSTEM only */
    for (uint32_t op = DNA_SYSRULE_STORAGE_REGISTER;
         op <= DNA_SYSRULE_ROTATE_CONSENSUS_KEY; op++) {
        int o1 = 0, o2 = 0, oE = 0, oS = 0;
        for (size_t i = 0; i < g1[0].descriptor.rule_count; i++)
            if (g1[0].descriptor.rule_ids[i] == op) o1 = 1;
        for (size_t i = 0; i < g2[0].descriptor.rule_count; i++)
            if (g2[0].descriptor.rule_ids[i] == op) o2 = 1;
        for (size_t i = 0; i < gE[0].descriptor.rule_count; i++)
            if (gE[0].descriptor.rule_ids[i] == op) oE = 1;
        for (size_t i = 0; i < gS[0].descriptor.rule_count; i++)
            if (gS[0].descriptor.rule_ids[i] == op) oS = 1;
        CHECK(!o1 && !o2 && !oE && oS);
    }
    CHECK(gS[1].meter_policy == NULL);
    CHECK(memcmp(gS[1].descriptor.meter_policy_digest, zero64, 64) == 0);
    {
        const dna_meter_policy_t *pE = gE[0].meter_policy;
        const dna_meter_policy_t *pS = gS[0].meter_policy;
        CHECK(pS != NULL && pS != pE);
        CHECK(pS->policy_version == DNA_METER_POLICY_VERSION);
        CHECK(pS->w_base == 1 && pS->w_callbyte == 1 && pS->w_authbyte == 1 &&
              pS->w_effect == 1 && pS->w_effectbyte == 1 && pS->w_read == 1 &&
              pS->w_write == 1);
        CHECK(pS->max_block_env_bytes == 2u * DNA_ENV_MAX_TOTAL_LEN);
        for (uint32_t op = 0; op < DNA_METER_OP_SPACE; op++) {
            uint64_t w = 0, wE = 0;
            int has = dna_meter_op_weight(pS, op, &w) == 0;
            int hasE = dna_meter_op_weight(pE, op, &wE) == 0;
            CHECK(has == (op >= 1u && op <= 10u));
            /* the EVM generation's op set plus op 10 (HF-6 6a) */
            CHECK(has == (hasE || op == DNA_SYSRULE_ROTATE_CONSENSUS_KEY));
            if (has) CHECK(w == 1u);
            if (hasE) CHECK(wE == 1u);
        }
    }
#endif

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
        /* (the storage-reward v1 RSGEN literal that re-derived here from
         * the GEN_STORAGE pins is deleted with param 16 — HF-6 slice 8c;
         * generation 4's vote value is 6'' below) */
    }

    /* ── 6''. HF-6 slice 8b: the generation-4 vote value D4 (design rev 6
     *        §8.1) — the constructor over the compiled pins, owner and the
     *        nine named constants re-derives the literal and the wrapper;
     *        the K8 number only where the owner is K8; the harness owner's
     *        number through an explicit owner argument; refusals; every
     *        input moves the value (EVM-enabled build: generation 4 exists
     *        only there) ─────────────────────────────────────────────── */
#ifdef NODUS_EVM_ENABLED
    {
        /* the test's OWN copy of the §8.1 constants, from the named macros
         * (not the runtime's static array) */
        uint64_t k[9] = {
            DNAC_HF6_STAKE_MIN_DEFAULT, DNAC_HF6_STAKE_MIN_MIN,
            DNAC_HF6_POWER_CAP_BPS_DEFAULT, DNA_POWER_CAP_BPS_MIN,
            DNA_POWER_CAP_BPS_MAX, DNAC_HF6_STORAGE_BOND_DEFAULT,
            DNAC_HF6_STORAGE_BOND_MIN, DNAC_HF6_STORAGE_BOND_MAX,
            DNA_VALBIND_MAX_EXPIRY_BLOCKS
        };
        /* §8.1's numbers, so a renamed or re-valued macro is caught here
         * and not only by the KAT */
        CHECK(k[0] == 200000000000000ULL && k[1] == 10000000000000ULL &&
              k[2] == 3000u && k[3] == 500u && k[4] == 3000u &&
              k[5] == 100000000000000ULL && k[6] == 10000000000000ULL &&
              k[7] == 100000000000000ULL && k[8] == 720u);
        uint8_t own[64];
        {
            static const uint8_t compiled_owner[] = DNAC_HF6_FOUNDATION_OWNER;
            _Static_assert(sizeof(compiled_owner) == 64,
                           "the compiled owner is 64 bytes");
            memcpy(own, compiled_owner, sizeof(own));
        }
        /* the preimage length: 296 bytes for n = 9 (design §8.1, khan
         * 2026-10-13); the constructor refuses to hash any other length */
        _Static_assert(DNA_ROLEGEN_PREIMAGE_LEN(9) == 296,
                       "D4 preimage is 296 bytes");
        CHECK(DNA_ROLEGEN_PREIMAGE_LEN(0) == 224);
        CHECK(DNAC_HF6_SWITCH_SPEC_VERSION == 1u);
        CHECK(NODUS_RT_GEN_STORAGE == 4u && NODUS_RT_GEN_STORAGE_BASE == 3u);

        uint64_t d0 = 0, d = 0, w = 0;
        CHECK(dna_rolegen_vote_digest(NODUS_RT_GEN_STORAGE,
                                      NODUS_RT_GEN_STORAGE_BASE,
                                      gS[0].ruleset_hash, gS[1].ruleset_hash,
                                      DNAC_HF6_SWITCH_SPEC_VERSION, own,
                                      k, 9, &d0) == 0);
        CHECK(d0 <= (uint64_t)INT64_MAX);
        /* triangle: constructor == wrapper == compiled literal */
        CHECK(nodus_runtime_gen4_vote_digest(&w) == 0 && w == d0);
        CHECK(d0 == (uint64_t)DNAC_CFG_RULESET_GEN_ROLES_D);
        CHECK(nodus_runtime_gen4_vote_digest(NULL) == -1);
#ifdef DNAC_HF6_FOUNDATION_OWNER_IS_DEFAULT
        /* KAT: owner K8 → D4 of shared/dnac/tests/hf6_vote_oracle.py
         * (hf6_vote_oracle_out.txt: 0x4dc61072d5982acd =
         * 5604184871704996557) */
        CHECK(d0 == 0x4dc61072d5982acdULL);
#endif
        /* KAT: the harness test owner (stagef_hf6_owner.sh's identity of
         * the 2026-10-12 rotation run, SHA3-512 of its nodus.pk
         * 2cca88c4…ee196b93) passed EXPLICITLY → the oracle's
         * `hf6_vote_oracle.py --owner 2cca88c4…ee196b93` value
         * 0x4fc24934a9155c64 (5747236565002050660). A KAT vector, not a
         * project fixture: no build carries this owner by default. */
        {
            static const uint8_t harness_owner[64] = {
                0x2c, 0xca, 0x88, 0xc4, 0x51, 0x7e, 0xc1, 0xb7,
                0x84, 0xaf, 0xfa, 0xc2, 0x5f, 0xc0, 0x03, 0x4a,
                0x7f, 0xaf, 0x2b, 0x22, 0xee, 0x99, 0x35, 0x19,
                0x7d, 0x1a, 0x59, 0xce, 0xaf, 0xae, 0xa1, 0xe9,
                0x61, 0x82, 0x11, 0x40, 0x05, 0x33, 0xd8, 0x33,
                0x2d, 0xde, 0x3c, 0xbb, 0xb6, 0xcd, 0x80, 0x91,
                0x4b, 0x3c, 0xa5, 0x03, 0xc4, 0x5a, 0x89, 0x15,
                0xbc, 0xd8, 0xd9, 0xf1, 0xee, 0x19, 0x6b, 0x93
            };
            CHECK(dna_rolegen_vote_digest(NODUS_RT_GEN_STORAGE,
                                          NODUS_RT_GEN_STORAGE_BASE,
                                          gS[0].ruleset_hash,
                                          gS[1].ruleset_hash,
                                          DNAC_HF6_SWITCH_SPEC_VERSION,
                                          harness_owner, k, 9, &d) == 0);
            CHECK(d == 0x4fc24934a9155c64ULL);
        }
        /* refusals: every pointer, n_consts > 64, NULL consts with n > 0 */
        CHECK(dna_rolegen_vote_digest(4, 3, NULL, gS[1].ruleset_hash, 1,
                                      own, k, 9, &d) == -1);
        CHECK(dna_rolegen_vote_digest(4, 3, gS[0].ruleset_hash, NULL, 1,
                                      own, k, 9, &d) == -1);
        CHECK(dna_rolegen_vote_digest(4, 3, gS[0].ruleset_hash,
                                      gS[1].ruleset_hash, 1, NULL, k, 9,
                                      &d) == -1);
        CHECK(dna_rolegen_vote_digest(4, 3, gS[0].ruleset_hash,
                                      gS[1].ruleset_hash, 1, own, k, 9,
                                      NULL) == -1);
        CHECK(dna_rolegen_vote_digest(4, 3, gS[0].ruleset_hash,
                                      gS[1].ruleset_hash, 1, own, NULL, 9,
                                      &d) == -1);
        {
            static uint64_t many[DNA_ROLEGEN_MAX_CONSTS + 1];
            CHECK(dna_rolegen_vote_digest(4, 3, gS[0].ruleset_hash,
                                          gS[1].ruleset_hash, 1, own, many,
                                          DNA_ROLEGEN_MAX_CONSTS + 1,
                                          &d) == -1);
            CHECK(dna_rolegen_vote_digest(4, 3, gS[0].ruleset_hash,
                                          gS[1].ruleset_hash, 1, own, many,
                                          DNA_ROLEGEN_MAX_CONSTS, &d) == 0);
        }
        /* every input moves the value */
        CHECK(dna_rolegen_vote_digest(5, 3, gS[0].ruleset_hash,
                                      gS[1].ruleset_hash, 1, own, k, 9,
                                      &d) == 0 && d != d0);
        CHECK(dna_rolegen_vote_digest(4, 2, gS[0].ruleset_hash,
                                      gS[1].ruleset_hash, 1, own, k, 9,
                                      &d) == 0 && d != d0);
        CHECK(dna_rolegen_vote_digest(4, 3, gS[1].ruleset_hash,
                                      gS[0].ruleset_hash, 1, own, k, 9,
                                      &d) == 0 && d != d0);
        CHECK(dna_rolegen_vote_digest(4, 3, gS[0].ruleset_hash,
                                      gS[1].ruleset_hash, 2, own, k, 9,
                                      &d) == 0 && d != d0);
        CHECK(dna_rolegen_vote_digest(4, 3, gS[0].ruleset_hash,
                                      gS[1].ruleset_hash, 1, own, k, 8,
                                      &d) == 0 && d != d0);
        own[63] ^= 1u;                      /* one owner byte */
        CHECK(dna_rolegen_vote_digest(4, 3, gS[0].ruleset_hash,
                                      gS[1].ruleset_hash, 1, own, k, 9,
                                      &d) == 0 && d != d0);
        own[63] ^= 1u;
        for (size_t i = 0; i < 9; i++) {    /* each constant */
            k[i] += 1u;
            CHECK(dna_rolegen_vote_digest(4, 3, gS[0].ruleset_hash,
                                          gS[1].ruleset_hash, 1, own, k, 9,
                                          &d) == 0 && d != d0);
            k[i] -= 1u;
        }
        /* restored inputs give the same value again */
        CHECK(dna_rolegen_vote_digest(4, 3, gS[0].ruleset_hash,
                                      gS[1].ruleset_hash, 1, own, k, 9,
                                      &d) == 0 && d == d0);
        /* distinct from every other vote value */
        CHECK(d0 != (uint64_t)DNAC_CFG_RULESET_GEN2_D2 &&
              d0 != (uint64_t)DNAC_CFG_EVM_ACTIVE_D);
    }
#endif

    /* ── 8. storage reward v1: the storage ops are refused as a VERDICT
     *       (-1), never a fault, by the SYSTEM hooks of generations 1, 2
     *       and the EVM one and a NULL runtime; with no call bytes
     *       GEN_STORAGE refuses them too; SYSFUND paired with a storage op
     *       is refused by the generation-2 and EVM-generation CORE hooks
     *       (EVM-enabled build: GEN_STORAGE exists only there) ──────── */
#ifdef NODUS_EVM_ENABLED
    {
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
        nodus_rt_read_req_t reqs[NODUS_RT_MAX_READS];
        uint16_t nr = 0;
        static uint8_t res[DNA_EFFECT_MAX_TOTAL_LEN];
        size_t rl = 0;

        for (uint32_t op = DNA_SYSRULE_STORAGE_REGISTER;
             op <= DNA_SYSRULE_STORAGE_REPORT; op++) {
            dna_env_view_t v;
            memset(&v, 0, sizeof(v));
            v.leg_count = 2;
            v.leg[0].domain_id   = DNA_DOMAIN_SYSTEM;
            v.leg[0].runtime_op  = op;
            v.leg[0].auth_kind   = NODUS_RT_AUTHKIND_DSA87_MULTI_V1;
            v.leg[0].access_mode = DNA_ENV_ACCESS_INVOKE;
            v.leg[1].domain_id   = DNA_DOMAIN_CORE;
            v.leg[1].runtime_op  = DNA_CORERULE_SYSFUND;
            v.leg[1].auth_kind   = NODUS_RT_AUTHKIND_DSA87_MULTI_V1;
            v.leg[1].access_mode = DNA_ENV_ACCESS_INVOKE;
            const nodus_domain_runtime_t *sys[4] = { &g1[0], &g2[0], &gE[0],
                                                     NULL };
            for (int s = 0; s < 4; s++) {
                CHECK(nodus_rt_system_read_plan(sys[s], &v, 0, &ctx, reqs,
                                                NODUS_RT_MAX_READS, &nr)
                      == -1);
                CHECK(nodus_rt_system_exec(sys[s], &v, 0, &ctx, NULL, 0,
                                           res, sizeof(res), &rl) == -1);
            }
            /* GEN_STORAGE: no call bytes → refused at the parse — a
             * verdict */
            CHECK(nodus_rt_system_read_plan(&gS[0], &v, 0, &ctx, reqs,
                                            NODUS_RT_MAX_READS, &nr) == -1);
            CHECK(nodus_rt_system_exec(&gS[0], &v, 0, &ctx, NULL, 0, res,
                                       sizeof(res), &rl) == -1);
            /* the CORE funding leg of a storage envelope: the
             * generation-2 and EVM-generation CORE refuse the pairing
             * (shape), as does a NULL runtime */
            CHECK(nodus_rt_core_read_plan(&g2[1], &v, 1, &ctx, reqs,
                                          NODUS_RT_MAX_READS, &nr) == -1);
            CHECK(nodus_rt_core_read_plan(&gE[1], &v, 1, &ctx, reqs,
                                          NODUS_RT_MAX_READS, &nr) == -1);
            CHECK(nodus_rt_core_read_plan(NULL, &v, 1, &ctx, reqs,
                                          NODUS_RT_MAX_READS, &nr) == -1);
        }
    }
#endif

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
