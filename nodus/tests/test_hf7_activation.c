/**
 * @file nodus/tests/test_hf7_activation.c
 * @brief HF-7 P1d — the generation-5 activation, pure half: the compiled
 *        generation 5 and its pins, the vote literal D5 and its selfcheck
 *        row, the param-22 vote rules, and the "pre-A envelopes are dead
 *        at A" invariant (half b: the EVM pair rule).
 *
 * Design docs/plans/2026-09-11-nodus-ledger-snapshot-design.md §10.2 items
 * 1-3, §10.9, §10.11 (khan decisions B — param 22 grace ERGONOMIC — and C —
 * the vote binds the 720-block expiry window only); decision docs/plans/
 * decisions/2026-10-20-kurultay-27-hf7-p1-summary.md items 1, 2, 10. The
 * engine half (the edge at the end of block A-1) is test_hf7_edge.c.
 *
 * ── WHAT IT PROVES ──────────────────────────────────────────────────────
 *  1. table: generation 5 is compiled — two slots (SYSTEM, CORE) right
 *     after GEN_STORAGE, no EVM slot; SYSTEM v11 / CORE v10, each the
 *     generation-4 descriptor with ONLY ruleset_version moved (rule list,
 *     type list, SYSTEM policy digest equal); same hooks, adapters,
 *     allowlists; NODUS_RT_GEN_MAX == NODUS_RT_GEN_ROOTS; the compiled
 *     ruleset hashes equal the INDEPENDENT oracle's R1 / R2 byte for byte
 *     (shared/dnac/tests/hf7_vote_oracle_out.txt), first and last bytes
 *     named so a transposed row is identified; the policy digest is the
 *     oracle's C1; selfcheck() == 0.
 *  2. (a) the literal: DNAC_CFG_RULESET_GEN_ROOTS_D == 0x6f4c60640dd57094
 *     == 8019891019285098644 (hf7_vote_oracle_out.txt "D5 = …", owner K8)
 *     where the build compiles K8; in every build the triangle
 *     dna_rolegen_vote_digest(5, 4, R1, R2, spec 1, owner, {720}) ==
 *     nodus_runtime_gen5_vote_digest == the literal; the preimage is 232
 *     bytes; D5 <= INT64_MAX and differs from D2 / EVM_ACTIVE / D4.
 *  3. (b) drift: what the selfcheck row compares can never accept a
 *     drifted generation 5 — a SYSTEM or CORE descriptor whose version
 *     stays at the generation-4 value (or moves to 12 / 11) does not
 *     hash to R1 / R2; the digest over generation-4 hashes, over a
 *     window of 721, of 100 (the node-local mempool window the khan kept
 *     OUT of the vote), with both {720, 100}, with spec version 2, with
 *     base 3, with one owner byte flipped — none equals D5.
 *  4. (c) vote rules: scalar — D5 accepted, D5 ± 1, 0, D4, D2 and
 *     UINT64_MAX refused; grace ERGONOMIC (== param 18's); stateful
 *     matrix — accepted only with HF-2 on, no param-22 row, judging
 *     generation EXACTLY 4, A-1 and A not epoch boundaries, A != 0;
 *     each single violation refused (generation 3, 5 and 0 too); the
 *     5-argument form agrees with the _ex form on the single-use fact.
 *  5. (e) summary item 1 half (b): a generation-4-signed EVM envelope
 *     [CORE EVMFUND (CORE v9), EVM DEPOSIT (EVM v2)] passes the pair rule
 *     and passes preflight against the generation-4 registry context, but
 *     preflight against the generation-5 context (CORE v10, EVM v2 — the
 *     EVM domain has no generation-5 entry) refuses it ERR_CTX_VERSION —
 *     at its CORE leg; a generation-4 SYSTEM leg (v10) is refused the same
 *     way against SYSTEM v11; the same EVM envelope rebuilt with CORE v10
 *     passes.
 *
 * ── WHAT IT REQUIRES ────────────────────────────────────────────────────
 * Compile flags: NODUS_EVM_ENABLED (generations 3-5 exist only there; the
 * target is registered only in that configuration). The K8 KAT lines are
 * compiled only under DNAC_HF6_FOUNDATION_OWNER_IS_DEFAULT. Environment:
 * none. No database.
 *
 * ── WHAT IT LEAVES BEHIND ───────────────────────────────────────────────
 * Nothing.
 *
 * ── HOW IT CAN LIE ──────────────────────────────────────────────────────
 *  - The R1 / R2 / C1 / D5 numbers come from the Python oracle; this test
 *    proves the C table and constructor agree with it, not that §10.2's
 *    layout is right (the ROLEGEN constructor's bytes are HF-6's approved
 *    crypto gate, reused).
 *  - Section 3 cannot hand the production selfcheck a drifted table (the
 *    table is compiled const data; no test hook exists and none is added):
 *    it proves that every quantity the selfcheck row COMPARES moves under
 *    a drift, not that the selfcheck function itself runs the comparison —
 *    that is the source read (nodus_witness_runtime.c, the D5 row).
 *  - Section 4 calls the rule functions with hand-set facts. Which facts
 *    the block path actually passes is the engine's: the SYSTEM
 *    CHAIN_CONFIG exec does NOT yet fill ruleset_gen_roots_voted (HF-7 P1d
 *    report), so on the block path the single-use rule (a) is enforced
 *    only by the 0x71 approval responder today.
 *  - Section 5 drives preflight directly with the context the engine
 *    builds from the registry; it does not apply a block (the engine
 *    half is test_hf7_edge.c and the P1e harness case).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness_runtime.h"
#include "nodus/nodus_chain_config.h"

#include "dnac/dnac.h"
#include "dnac/domain_wire.h"
#include "dnac/env_wire.h"
#include "dnac/env_preflight.h"
#include "dnac/ledger_ids.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(cond) do { \
    if (!(cond)) { fprintf(stderr, "CHECK fail at %s:%d: %s\n", \
        __FILE__, __LINE__, #cond); exit(1); } } while (0)

static int g_checks = 0;
#define OK() do { g_checks++; } while (0)

#define E_LEN   ((uint64_t)DNAC_EPOCH_LENGTH)
#define GRACE_E ((uint64_t)DNAC_CHAIN_CONFIG_GRACE_ERGONOMIC_BLOCKS)

/* ── the INDEPENDENT oracle's values (hf7_vote_oracle_out.txt) ───────── */
/* R1 = GEN_ROOTS SYSTEM v11 ruleset_hash */
static const uint8_t ORACLE_R1[64] = {
    0xbb, 0xd0, 0xa1, 0x8d, 0x8b, 0x78, 0x1d, 0x01,
    0x23, 0x19, 0x5e, 0x5a, 0xb4, 0x81, 0x70, 0x64,
    0xaf, 0xb8, 0x31, 0x7f, 0x12, 0x4f, 0xdb, 0xbf,
    0xbc, 0x71, 0x84, 0x22, 0x5b, 0xad, 0xd1, 0x6c,
    0xd3, 0x16, 0xdc, 0x16, 0x1f, 0x00, 0xe3, 0x8d,
    0x30, 0x73, 0x19, 0x0e, 0x71, 0xdb, 0xb0, 0xe4,
    0x9e, 0x32, 0x54, 0x64, 0x1d, 0x4f, 0x91, 0xbc,
    0x41, 0x6d, 0x06, 0x03, 0x76, 0x67, 0x1a, 0xe9
};
/* R2 = GEN_ROOTS CORE v10 ruleset_hash */
static const uint8_t ORACLE_R2[64] = {
    0xff, 0x06, 0xf6, 0x82, 0x7e, 0x66, 0xcc, 0xa2,
    0x0c, 0x45, 0x1b, 0x76, 0x45, 0x3d, 0xf0, 0xa4,
    0x6f, 0x2a, 0xdc, 0xf0, 0x3b, 0x9a, 0xa6, 0xed,
    0x66, 0xf5, 0x6c, 0xbd, 0x58, 0xf0, 0xb2, 0xe2,
    0xf4, 0x1e, 0x7f, 0x43, 0xcf, 0x89, 0xa7, 0x01,
    0xdd, 0x23, 0x13, 0xd3, 0x98, 0x13, 0x6e, 0xdf,
    0x52, 0x40, 0xd1, 0x85, 0xb5, 0x86, 0x25, 0x19,
    0x0c, 0x39, 0x76, 0x02, 0x38, 0xbb, 0xb8, 0x70
};
/* C1 = the SYSTEM meter-policy identity digest (ops 1..9 weight 1) */
static const uint8_t ORACLE_C1[64] = {
    0x0a, 0xa4, 0xc6, 0x90, 0xa0, 0x5a, 0xf8, 0x82,
    0x7a, 0x32, 0x29, 0x12, 0xa4, 0x02, 0xd8, 0x7b,
    0x26, 0x42, 0xc9, 0x9e, 0xdc, 0x1d, 0xb8, 0x3f,
    0x28, 0x71, 0xaf, 0x64, 0xda, 0x18, 0xc3, 0xf8,
    0xb7, 0x4a, 0x6e, 0x5c, 0x87, 0x0e, 0xdc, 0x34,
    0x50, 0xae, 0x04, 0x74, 0xa3, 0xc8, 0xd7, 0x27,
    0x9e, 0xfb, 0x88, 0x4d, 0xf8, 0xb2, 0x85, 0xc8,
    0x84, 0x8b, 0xef, 0xfb, 0x25, 0x92, 0x27, 0x66
};
#define ORACLE_D5      0x6f4c60640dd57094ULL
#define ORACLE_D5_DEC  8019891019285098644ULL

static int desc_same_but_version(const dna_ruleset_desc_t *a,
                                 const dna_ruleset_desc_t *b) {
    return a->descriptor_version == b->descriptor_version &&
           a->domain_id == b->domain_id &&
           memcmp(a->name, b->name, sizeof(a->name)) == 0 &&
           a->runtime_abi == b->runtime_abi &&
           a->rule_count == b->rule_count &&
           memcmp(a->rule_ids, b->rule_ids,
                  a->rule_count * sizeof(a->rule_ids[0])) == 0 &&
           a->tx_type_count == b->tx_type_count &&
           memcmp(a->tx_types, b->tx_types, a->tx_type_count) == 0 &&
           memcmp(a->meter_policy_digest, b->meter_policy_digest, 64) == 0;
}

/* ══ 1. the compiled generation 5 ═════════════════════════════════════ */
static void t_table(void) {
    CHECK(NODUS_RT_GEN_ROOTS == 5u &&
          NODUS_RT_GEN_ROOTS_BASE == NODUS_RT_GEN_STORAGE); OK();
    CHECK(NODUS_RT_GEN_MAX == NODUS_RT_GEN_ROOTS); OK();
    CHECK(nodus_runtime_generation_count() == 5u); OK();
    size_t n_all = 0, n5 = 0, n4 = 0;
    const nodus_domain_runtime_t *all = nodus_runtime_all_table(&n_all);
    const nodus_domain_runtime_t *g5 =
        nodus_runtime_generation_table(NODUS_RT_GEN_ROOTS, &n5);
    const nodus_domain_runtime_t *g4 =
        nodus_runtime_generation_table(NODUS_RT_GEN_STORAGE, &n4);
    CHECK(all && n_all == 11u); OK();
    CHECK(g4 && n4 == 2u && g4 == &all[7]); OK();
    CHECK(g5 && n5 == 2u && g5 == &all[9]); OK();
    CHECK(g5[0].domain_id == DNA_DOMAIN_SYSTEM &&
          g5[1].domain_id == DNA_DOMAIN_CORE); OK();
    CHECK(g5[0].generation == NODUS_RT_GEN_ROOTS &&
          g5[1].generation == NODUS_RT_GEN_ROOTS); OK();
    /* no EVM slot: the EVM domain keeps the EVM generation's entry */
    CHECK(nodus_runtime_for_generation(NODUS_RT_GEN_ROOTS,
                                       DNA_DOMAIN_EVM) == NULL); OK();
    CHECK(nodus_runtime_for_generation(NODUS_RT_GEN_EVM,
                                       DNA_DOMAIN_EVM) != NULL); OK();
    /* SYSTEM v11 / CORE v10 — generation 4's v10 / v9, version only */
    CHECK(g4[0].ruleset_version == 10u && g4[1].ruleset_version == 9u); OK();
    CHECK(g5[0].ruleset_version == 11u && g5[1].ruleset_version == 10u);
    OK();
    CHECK(g5[0].descriptor.ruleset_version == 11u &&
          g5[1].descriptor.ruleset_version == 10u); OK();
    CHECK(desc_same_but_version(&g5[0].descriptor, &g4[0].descriptor));
    OK();
    CHECK(desc_same_but_version(&g5[1].descriptor, &g4[1].descriptor));
    OK();
    for (int k = 0; k < 2; k++) {
        CHECK(g5[k].runtime_kind == g4[k].runtime_kind &&
              g5[k].runtime_abi == g4[k].runtime_abi &&
              g5[k].allowed_auth_kinds == g4[k].allowed_auth_kinds &&
              g5[k].admit == g4[k].admit && g5[k].tx_cost == g4[k].tx_cost &&
              g5[k].auth == g4[k].auth &&
              g5[k].read_plan == g4[k].read_plan &&
              g5[k].exec == g4[k].exec &&
              g5[k].state_root == g4[k].state_root &&
              g5[k].payload_root == g4[k].payload_root &&
              g5[k].asset_check == g4[k].asset_check &&
              g5[k].claim_apply == g4[k].claim_apply &&
              g5[k].invariant == g4[k].invariant &&
              g5[k].state_init == g4[k].state_init &&
              g5[k].adapter == g4[k].adapter);
        OK();
    }
    /* the SYSTEM policy: its OWN sealed object, digest = oracle C1 */
    CHECK(g5[0].meter_policy != NULL && g5[1].meter_policy == NULL); OK();
    CHECK(g5[0].meter_policy != g4[0].meter_policy); OK();
    CHECK(memcmp(g5[0].descriptor.meter_policy_digest, ORACLE_C1, 64) == 0);
    OK();
    /* the pins == the oracle's R1 / R2 — first and last byte named so a
     * transposed row of the C array is identified, then all 64 */
    CHECK(g5[0].ruleset_hash[0] == 0xbb && g5[0].ruleset_hash[63] == 0xe9);
    OK();
    CHECK(g5[1].ruleset_hash[0] == 0xff && g5[1].ruleset_hash[63] == 0x70);
    OK();
    CHECK(memcmp(g5[0].ruleset_hash, ORACLE_R1, 64) == 0); OK();
    CHECK(memcmp(g5[1].ruleset_hash, ORACLE_R2, 64) == 0); OK();
    /* and the C encoder re-derives them (the selfcheck's own test) */
    {
        uint8_t h[64];
        CHECK(dna_ruleset_desc_hash(&g5[0].descriptor, h) == 0 &&
              memcmp(h, ORACLE_R1, 64) == 0); OK();
        CHECK(dna_ruleset_desc_hash(&g5[1].descriptor, h) == 0 &&
              memcmp(h, ORACLE_R2, 64) == 0); OK();
    }
    /* exact-tuple lookup resolves each generation-5 tuple to its entry */
    CHECK(nodus_runtime_lookup(DNA_DOMAIN_SYSTEM, g5[0].runtime_kind,
                               g5[0].runtime_abi, 11, ORACLE_R1) == &g5[0]);
    OK();
    CHECK(nodus_runtime_lookup(DNA_DOMAIN_CORE, g5[1].runtime_kind,
                               g5[1].runtime_abi, 10, ORACLE_R2) == &g5[1]);
    OK();
    CHECK(nodus_witness_runtime_selfcheck() == 0); OK();
}

/* ══ 2. (a) the literal D5 ═════════════════════════════════════════════ */
static void t_literal(void) {
    static const uint8_t owner[] = DNAC_HF6_FOUNDATION_OWNER;
    _Static_assert(sizeof(owner) == 64, "the compiled owner is 64 bytes");
    const uint64_t k720[1] = { NODUS_RT_GEN5_VOTE_EXPIRY_WINDOW };
    CHECK(NODUS_RT_GEN5_VOTE_EXPIRY_WINDOW == 720u); OK();
    CHECK(DNAC_HF7_SWITCH_SPEC_VERSION == 1u); OK();
    _Static_assert(DNA_ROLEGEN_PREIMAGE_LEN(1) == 232,
                   "the D5 preimage is 232 bytes (hf7_vote_oracle_out.txt)");
    uint64_t d0 = 0, w = 0;
    CHECK(dna_rolegen_vote_digest(NODUS_RT_GEN_ROOTS, NODUS_RT_GEN_ROOTS_BASE,
                                  ORACLE_R1, ORACLE_R2,
                                  DNAC_HF7_SWITCH_SPEC_VERSION, owner, k720,
                                  1, &d0) == 0); OK();
    /* triangle: constructor == wrapper == compiled literal */
    CHECK(nodus_runtime_gen5_vote_digest(&w) == 0 && w == d0); OK();
    CHECK(d0 == (uint64_t)DNAC_CFG_RULESET_GEN_ROOTS_D); OK();
    CHECK(nodus_runtime_gen5_vote_digest(NULL) == -1); OK();
#ifdef DNAC_HF6_FOUNDATION_OWNER_IS_DEFAULT
    /* KAT: owner K8 → D5 of shared/dnac/tests/hf7_vote_oracle.py
     * (hf7_vote_oracle_out.txt: "D5 = 0x6f4c60640dd57094ULL",
     * "D5 (decimal) = 8019891019285098644") */
    CHECK(d0 == ORACLE_D5 && d0 == ORACLE_D5_DEC); OK();
    CHECK((uint64_t)DNAC_CFG_RULESET_GEN_ROOTS_D == ORACLE_D5); OK();
#endif
    CHECK(d0 <= (uint64_t)INT64_MAX); OK();
    CHECK(d0 != (uint64_t)DNAC_CFG_RULESET_GEN2_D2 &&
          d0 != (uint64_t)DNAC_CFG_EVM_ACTIVE_D &&
          d0 != (uint64_t)DNAC_CFG_RULESET_GEN_ROLES_D); OK();
    /* the generation-4 vote is unchanged by generation 5 */
    {
        uint64_t d4 = 0;
        CHECK(nodus_runtime_gen4_vote_digest(&d4) == 0 &&
              d4 == (uint64_t)DNAC_CFG_RULESET_GEN_ROLES_D); OK();
    }
}

/* ══ 3. (b) drift — every compared quantity moves ═══════════════════════ */
static void t_drift(void) {
    static const uint8_t owner_c[] = DNAC_HF6_FOUNDATION_OWNER;
    uint8_t owner[64];
    memcpy(owner, owner_c, 64);
    const nodus_domain_runtime_t *s5 =
        nodus_runtime_for_generation(NODUS_RT_GEN_ROOTS, DNA_DOMAIN_SYSTEM);
    const nodus_domain_runtime_t *c5 =
        nodus_runtime_for_generation(NODUS_RT_GEN_ROOTS, DNA_DOMAIN_CORE);
    const nodus_domain_runtime_t *s4 =
        nodus_runtime_for_generation(NODUS_RT_GEN_STORAGE, DNA_DOMAIN_SYSTEM);
    const nodus_domain_runtime_t *c4 =
        nodus_runtime_for_generation(NODUS_RT_GEN_STORAGE, DNA_DOMAIN_CORE);
    CHECK(s5 && c5 && s4 && c4); OK();
    /* a descriptor whose version did not move (or moved elsewhere) does
     * not hash to the pin — the selfcheck's re-derivation refuses it */
    {
        static const uint32_t vs[] = { 10u, 12u };
        static const uint32_t vc[] = { 9u, 11u };
        for (size_t i = 0; i < 2; i++) {
            dna_ruleset_desc_t d = s5->descriptor;
            uint8_t h[64];
            d.ruleset_version = vs[i];
            CHECK(dna_ruleset_desc_hash(&d, h) == 0 &&
                  memcmp(h, ORACLE_R1, 64) != 0); OK();
            d = c5->descriptor;
            d.ruleset_version = vc[i];
            CHECK(dna_ruleset_desc_hash(&d, h) == 0 &&
                  memcmp(h, ORACLE_R2, 64) != 0); OK();
        }
        /* generation 4's own descriptors give generation 4's pins, never
         * generation 5's */
        uint8_t h[64];
        CHECK(dna_ruleset_desc_hash(&s4->descriptor, h) == 0 &&
              memcmp(h, s4->ruleset_hash, 64) == 0 &&
              memcmp(h, ORACLE_R1, 64) != 0); OK();
    }
    /* the digest moves with every input the selfcheck row binds */
    const uint64_t k720[1] = { 720u };
    const uint64_t k721[1] = { 721u };
    const uint64_t k100[1] = { 100u };
    const uint64_t k2[2]   = { 720u, 100u };
    uint64_t d0 = 0, d = 0;
    CHECK(dna_rolegen_vote_digest(5, 4, s5->ruleset_hash, c5->ruleset_hash,
                                  1, owner, k720, 1, &d0) == 0 &&
          d0 == (uint64_t)DNAC_CFG_RULESET_GEN_ROOTS_D); OK();
    CHECK(dna_rolegen_vote_digest(5, 4, s4->ruleset_hash, c5->ruleset_hash,
                                  1, owner, k720, 1, &d) == 0 && d != d0);
    OK();
    CHECK(dna_rolegen_vote_digest(5, 4, s5->ruleset_hash, c4->ruleset_hash,
                                  1, owner, k720, 1, &d) == 0 && d != d0);
    OK();
    CHECK(dna_rolegen_vote_digest(5, 4, s5->ruleset_hash, c5->ruleset_hash,
                                  1, owner, k721, 1, &d) == 0 && d != d0);
    OK();
    /* khan decision C: the mempool window 100 is NOT in the vote — a D
     * that bound it (alone or beside 720) is a different value */
    CHECK(dna_rolegen_vote_digest(5, 4, s5->ruleset_hash, c5->ruleset_hash,
                                  1, owner, k100, 1, &d) == 0 && d != d0);
    OK();
    CHECK(dna_rolegen_vote_digest(5, 4, s5->ruleset_hash, c5->ruleset_hash,
                                  1, owner, k2, 2, &d) == 0 && d != d0);
    OK();
    CHECK(dna_rolegen_vote_digest(5, 4, s5->ruleset_hash, c5->ruleset_hash,
                                  2, owner, k720, 1, &d) == 0 && d != d0);
    OK();
    CHECK(dna_rolegen_vote_digest(5, 3, s5->ruleset_hash, c5->ruleset_hash,
                                  1, owner, k720, 1, &d) == 0 && d != d0);
    OK();
    CHECK(dna_rolegen_vote_digest(4, 4, s5->ruleset_hash, c5->ruleset_hash,
                                  1, owner, k720, 1, &d) == 0 && d != d0);
    OK();
    owner[0] ^= 1u;
    CHECK(dna_rolegen_vote_digest(5, 4, s5->ruleset_hash, c5->ruleset_hash,
                                  1, owner, k720, 1, &d) == 0 && d != d0);
    OK();
    owner[0] ^= 1u;
    CHECK(dna_rolegen_vote_digest(5, 4, s5->ruleset_hash, c5->ruleset_hash,
                                  1, owner, k720, 1, &d) == 0 && d == d0);
    OK();
}

/* ══ 4. (c) the param-22 vote rules ════════════════════════════════════ */

/* the smallest effective >= floor_h whose A-1 and A are both off an epoch
 * boundary */
static uint64_t eff_ok(uint64_t floor_h) {
    uint64_t e = floor_h;
    for (;;) {
        int b1 = ((e - 1u) != 0) && ((e - 1u) % E_LEN) == 0;
        int b0 = (e % E_LEN) == 0;
        if (!b1 && !b0) return e;
        e++;
    }
}

static void t_vote_rules(void) {
    const uint8_t P = (uint8_t)DNAC_CFG_RULESET_GEN_ROOTS;
    CHECK(P == 22u && DNAC_CFG_PARAM_MAX_ID == 22); OK();
    CHECK(dnac_cfg_param_read_by_consensus(P)); OK();
    /* scalar: exactly D5 */
    CHECK(nodus_chain_config_scalar_rules(
              P, (uint64_t)DNAC_CFG_RULESET_GEN_ROOTS_D, 1, 5000, 4000, 7)
          == 0); OK();
    {
        const uint64_t bad[] = {
            (uint64_t)DNAC_CFG_RULESET_GEN_ROOTS_D + 1u,
            (uint64_t)DNAC_CFG_RULESET_GEN_ROOTS_D - 1u, 0u,
            (uint64_t)DNAC_CFG_RULESET_GEN_ROLES_D,
            (uint64_t)DNAC_CFG_RULESET_GEN2_D2,
            (uint64_t)DNAC_CFG_EVM_ACTIVE_D, UINT64_MAX };
        for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
            CHECK(nodus_chain_config_scalar_rules(P, bad[i], 1, 5000, 4000,
                                                  7) == -1); OK();
        }
    }
    /* param 18 refuses D5 */
    CHECK(nodus_chain_config_scalar_rules(
              (uint8_t)DNAC_CFG_RULESET_GEN_ROLES,
              (uint64_t)DNAC_CFG_RULESET_GEN_ROOTS_D, 1, 5000, 4000, 7)
          == -1); OK();
    /* the window shape still applies */
    CHECK(nodus_chain_config_scalar_rules(
              P, (uint64_t)DNAC_CFG_RULESET_GEN_ROOTS_D, 0, 5000, 4000, 7)
          == -1); OK();
    /* grace: ERGONOMIC (khan decision B), param 18's class */
    CHECK(nodus_chain_config_grace_for_param(P) == GRACE_E); OK();
    CHECK(nodus_chain_config_grace_for_param(P) ==
          nodus_chain_config_grace_for_param(
              (uint8_t)DNAC_CFG_RULESET_GEN_ROLES)); OK();

    /* stateful matrix */
    const uint64_t ok_eff = eff_ok(1u + GRACE_E);
    nodus_cc_state_facts_t f;
    memset(&f, 0, sizeof(f));
    f.hf2_active = 1;
    f.judging_generation = NODUS_RT_GEN_ROOTS_BASE;
    CHECK(nodus_chain_config_stateful_rules_ex(P, ok_eff, &f) == 0); OK();
    /* (a) single use */
    f.ruleset_gen_roots_voted = 1;
    CHECK(nodus_chain_config_stateful_rules_ex(P, ok_eff, &f) == -1); OK();
    f.ruleset_gen_roots_voted = 0;
    /* the OTHER single-use facts do not gate param 22 */
    f.ruleset_gen_roles_voted = 1;
    f.ruleset_gen2_voted = 1;
    f.ruleset_gen_storage_voted = 1;
    f.evm_active_voted = 1;
    CHECK(nodus_chain_config_stateful_rules_ex(P, ok_eff, &f) == 0); OK();
    f.ruleset_gen_roles_voted = 0;
    f.ruleset_gen2_voted = 0;
    f.ruleset_gen_storage_voted = 0;
    f.evm_active_voted = 0;
    /* (b) HF-2 */
    f.hf2_active = 0;
    CHECK(nodus_chain_config_stateful_rules_ex(P, ok_eff, &f) == -1); OK();
    f.hf2_active = 1;
    /* (c) judged under EXACTLY generation 4 */
    {
        const uint32_t gens[] = { 0u, NODUS_RT_GEN_1, NODUS_RT_GEN_2,
                                  NODUS_RT_GEN_EVM, NODUS_RT_GEN_ROOTS, 6u };
        for (size_t i = 0; i < sizeof(gens) / sizeof(gens[0]); i++) {
            f.judging_generation = gens[i];
            CHECK(nodus_chain_config_stateful_rules_ex(P, ok_eff, &f) == -1);
            OK();
        }
        f.judging_generation = NODUS_RT_GEN_ROOTS_BASE;
    }
    /* (d) A == 0, A-1 a boundary */
    CHECK(nodus_chain_config_stateful_rules_ex(P, 0, &f) == -1); OK();
    {
        const uint64_t a1b = 2u * E_LEN + 1u;        /* A-1 = 2E */
        CHECK(((a1b - 1u) % E_LEN) == 0); OK();
        CHECK(nodus_chain_config_stateful_rules_ex(P, a1b, &f) == -1); OK();
        /* (e) A a boundary */
        const uint64_t ab = 3u * E_LEN;
        CHECK(nodus_chain_config_stateful_rules_ex(P, ab, &f) == -1); OK();
        /* A = 1: A-1 = 0 is not a boundary, A = 1 is not */
        if (E_LEN > 1u) {
            CHECK(nodus_chain_config_stateful_rules_ex(P, 1u, &f) == 0); OK();
        }
    }
    /* the 5-argument test form: its 4th argument is the single-use fact */
    CHECK(nodus_chain_config_stateful_rules(P, ok_eff, 1, 0,
                                            NODUS_RT_GEN_ROOTS_BASE) == 0);
    OK();
    CHECK(nodus_chain_config_stateful_rules(P, ok_eff, 1, 1,
                                            NODUS_RT_GEN_ROOTS_BASE) == -1);
    OK();
    CHECK(nodus_chain_config_stateful_rules(P, ok_eff, 0, 0,
                                            NODUS_RT_GEN_ROOTS_BASE) == -1);
    OK();
    /* param 18's rules are unchanged by the new fact */
    memset(&f, 0, sizeof(f));
    f.hf2_active = 1;
    f.judging_generation = NODUS_RT_GEN_STORAGE_BASE;
    f.ruleset_gen_roots_voted = 1;
    CHECK(nodus_chain_config_stateful_rules_ex(
              (uint8_t)DNAC_CFG_RULESET_GEN_ROLES, ok_eff, &f) == 0); OK();
}

/* ══ 5. (e) a generation-4-signed EVM envelope at A ════════════════════ */

static void put64(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (56 - 8 * i));
}

/* [CORE EVMFUND role DEPOSIT (CORE `core_v`), EVM DEPOSIT (EVM v2)] —
 * the shape nodus_rt_evm_pair_check requires; no signature (preflight
 * does not verify one). @return the encoded length, 0 on failure. */
static size_t evm_env(uint8_t *buf, size_t cap, uint32_t core_v) {
    static uint8_t ccall[2 + 1 + 64 + 1];
    ccall[0] = NODUS_RT_EVMFUND_CALL_VER;
    ccall[1] = NODUS_RT_EVMFUND_ROLE_DEPOSIT;
    ccall[2] = 1;                              /* in_count 1             */
    memset(ccall + 3, 0x5A, 64);               /* the nullifier          */
    ccall[3 + 64] = 0;                         /* out_count 0            */
    uint8_t dep[17];
    dep[0] = NODUS_RT_EVM_CALL_VER;
    put64(dep + 1, 5u);                        /* amount_raw             */
    put64(dep + 9, 0u);                        /* nonce                  */
    uint8_t a = 0;
    dna_env_leg_in_t legs[2];
    memset(legs, 0, sizeof(legs));
    legs[0].hdr.domain_id = DNA_DOMAIN_CORE;
    legs[0].hdr.runtime_op = DNA_CORERULE_EVMFUND;
    legs[0].hdr.ruleset_version = core_v;
    legs[0].hdr.access_mode = DNA_ENV_ACCESS_INVOKE;
    legs[0].hdr.auth_kind = 1;
    legs[0].hdr.call_len = (uint32_t)sizeof(ccall);
    legs[0].hdr.auth_len = 1;
    legs[0].call_data = ccall;
    legs[0].auth_data = &a;
    legs[1].hdr.domain_id = DNA_DOMAIN_EVM;
    legs[1].hdr.runtime_op = NODUS_RT_EVM_DEPOSIT;
    legs[1].hdr.ruleset_version = NODUS_RT_EVM_RULESET_VERSION_GEVM;
    legs[1].hdr.access_mode = DNA_ENV_ACCESS_INVOKE;
    legs[1].hdr.auth_kind = 1;
    legs[1].hdr.call_len = 17;
    legs[1].hdr.auth_len = 1;
    legs[1].call_data = dep;
    legs[1].auth_data = &a;
    dna_env_in_t in;
    memset(&in, 0, sizeof(in));
    in.res_max_total_units = 1;
    in.leg_count = 2;
    in.legs = legs;
    size_t used = 0;
    if (dna_env_encode(&in, buf, cap, &used) != 0) return 0;
    return used;
}

/* a one-leg SYSTEM envelope naming SYSTEM `sys_v` (CHAIN_CONFIG op) */
static size_t sys_env(uint8_t *buf, size_t cap, uint32_t sys_v) {
    static uint8_t call[41];
    memset(call, 0, sizeof(call));
    uint8_t a = 0;
    dna_env_leg_in_t leg;
    memset(&leg, 0, sizeof(leg));
    leg.hdr.domain_id = DNA_DOMAIN_SYSTEM;
    leg.hdr.runtime_op = DNA_SYSRULE_CHAIN_CONFIG;
    leg.hdr.ruleset_version = sys_v;
    leg.hdr.access_mode = DNA_ENV_ACCESS_INVOKE;
    leg.hdr.auth_kind = 1;
    leg.hdr.call_len = (uint32_t)sizeof(call);
    leg.hdr.auth_len = 1;
    leg.call_data = call;
    leg.auth_data = &a;
    dna_env_in_t in;
    memset(&in, 0, sizeof(in));
    in.res_max_total_units = 1;
    in.leg_count = 1;
    in.legs = &leg;
    size_t used = 0;
    if (dna_env_encode(&in, buf, cap, &used) != 0) return 0;
    return used;
}

/* the registry context of `gen` for `dom` (the engine's block-start
 * rulesets come from the committed manifests, which name exactly the
 * compiled entry's version + hash) */
static void ctx_of(dna_env_leg_ctx_t *c, const nodus_domain_runtime_t *rt) {
    memset(c, 0, sizeof(*c));
    c->domain_id = rt->domain_id;
    c->ruleset_version = rt->ruleset_version;
    memcpy(c->ruleset_hash, rt->ruleset_hash, sizeof(c->ruleset_hash));
}

static void t_evm_dead_at_a(void) {
    static uint8_t buf[4096];
    static const uint8_t chain[32] = { 0x42 };
    const nodus_domain_runtime_t *c4 =
        nodus_runtime_for_generation(NODUS_RT_GEN_STORAGE, DNA_DOMAIN_CORE);
    const nodus_domain_runtime_t *c5 =
        nodus_runtime_for_generation(NODUS_RT_GEN_ROOTS, DNA_DOMAIN_CORE);
    const nodus_domain_runtime_t *s4 =
        nodus_runtime_for_generation(NODUS_RT_GEN_STORAGE, DNA_DOMAIN_SYSTEM);
    const nodus_domain_runtime_t *s5 =
        nodus_runtime_for_generation(NODUS_RT_GEN_ROOTS, DNA_DOMAIN_SYSTEM);
    /* the EVM domain's ONE entry (the EVM generation's v2) — the registry
     * names it before AND after the generation-5 edge */
    const nodus_domain_runtime_t *ev =
        nodus_runtime_for_generation(NODUS_RT_GEN_EVM, DNA_DOMAIN_EVM);
    CHECK(c4 && c5 && s4 && s5 && ev); OK();
    CHECK(c4->ruleset_version == 9u && c5->ruleset_version == 10u); OK();
    CHECK(ev->ruleset_version == NODUS_RT_EVM_RULESET_VERSION_GEVM); OK();

    dna_env_preflight_t *pf = calloc(1, sizeof(*pf));
    CHECK(pf != NULL); OK();

    /* a generation-4-signed EVM envelope: CORE leg v9 */
    size_t len = evm_env(buf, sizeof(buf), c4->ruleset_version);
    CHECK(len > 0); OK();
    {
        dna_env_view_t v;
        CHECK(dna_env_decode(buf, len, &v) == 0 &&
              nodus_rt_evm_pair_check(&v) == 0); OK();   /* a valid pair */
    }
    dna_env_leg_ctx_t lc[2];
    /* under the generation-4 registry (blocks <= A-1): admitted */
    ctx_of(&lc[0], c4);
    ctx_of(&lc[1], ev);
    CHECK(dna_env_preflight(buf, len, chain, 100, lc, 2, pf) ==
          DNA_ENV_PF_OK); OK();
    /* under the generation-5 registry (block A on): dead at its CORE leg */
    ctx_of(&lc[0], c5);
    ctx_of(&lc[1], ev);
    CHECK(dna_env_preflight(buf, len, chain, 100, lc, 2, pf) ==
          DNA_ENV_PF_ERR_CTX_VERSION); OK();
    /* the EVM leg alone would still match (EVM v2 is unchanged): the
     * refusal is the CORE leg's — the pair rule is what kills it */
    CHECK(lc[1].ruleset_version == NODUS_RT_EVM_RULESET_VERSION_GEVM); OK();
    /* the same envelope rebuilt for generation 5 (CORE v10) passes */
    len = evm_env(buf, sizeof(buf), c5->ruleset_version);
    CHECK(len > 0); OK();
    CHECK(dna_env_preflight(buf, len, chain, 100, lc, 2, pf) ==
          DNA_ENV_PF_OK); OK();

    /* half (a), the same mechanism: a generation-4 SYSTEM leg (v10) */
    len = sys_env(buf, sizeof(buf), s4->ruleset_version);
    CHECK(len > 0); OK();
    ctx_of(&lc[0], s4);
    CHECK(dna_env_preflight(buf, len, chain, 100, lc, 1, pf) ==
          DNA_ENV_PF_OK); OK();
    ctx_of(&lc[0], s5);
    CHECK(dna_env_preflight(buf, len, chain, 100, lc, 1, pf) ==
          DNA_ENV_PF_ERR_CTX_VERSION); OK();
    free(pf);
}

int main(void) {
    t_table();
    t_literal();
    t_drift();
    t_vote_rules();
    t_evm_dead_at_a();
    fprintf(stderr, "test_hf7_activation: all sections passed, %d checks\n",
            g_checks);
    return 0;
}
