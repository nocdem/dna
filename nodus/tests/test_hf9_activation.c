/**
 * @file nodus/tests/test_hf9_activation.c
 * @brief HF-9 WP3, plan row T-12 — the generation-6 activation, pure half:
 *        the compiled generation 6 and its pins, the vote literal D6 and its
 *        selfcheck row, the param-24 (RULESET_GEN_TRIE) and param-25
 *        (STORAGE_COPIES) vote rules, and the "pre-A envelopes are dead at
 *        A" invariant (the EVM pair rule). The engine half (the edge at the
 *        end of block A-1) is test_hf9_edge.c.
 *
 * Plan docs/plans/approved/2026-11-04-hf9.md §7.1, §12 T-12, §15 AD-7 /
 * AD-12, §15a A8 / A9 / A15 / A16 / F-15 / F-17 / F-32 / F-33 / F-34;
 * decisions D18 ("Oylamalarda bir epoxa bir epok olsun o zaman." /
 * "diğer ayarları değiştirme."), D24 ("3, evet." — the D6 layout), D25
 * ("4.24." — param 24 grace SAFETY), docs/plans/decisions/2026-11-04-hf9-
 * scope.md.
 *
 * ── WHAT IT PROVES ──────────────────────────────────────────────────────
 *  1. table: generation 6 is compiled — two slots (SYSTEM, CORE) right
 *     after GEN_ROOTS (index 11-12), no EVM slot; SYSTEM v12 / CORE v11,
 *     each the generation-5 descriptor with ONLY ruleset_version moved
 *     (rule list, type list, SYSTEM policy digest equal); same hooks,
 *     adapters, allowlists; NODUS_RT_GEN_MAX == NODUS_RT_GEN_TRIE; the
 *     compiled ruleset hashes equal the INDEPENDENT oracle's values byte
 *     for byte (shared/dnac/tests/hf9_vote_oracle.py, run 2026-11-04;
 *     typed here as hex, first and last bytes named so a transposed row is
 *     identified); the policy digest is the oracle's control C1;
 *     selfcheck() == 0.
 *  2. the literal: DNAC_CFG_RULESET_GEN_TRIE_D == 0x1f12a7f0b824ae45 ==
 *     2239036617079959109 (oracle "D6 = …", owner K8) where the build
 *     compiles K8; in every build the triangle dna_rolegen_vote_digest(6,
 *     5, S, C, spec 1, owner, [1024, 4, 4, 16]) ==
 *     nodus_runtime_gen6_vote_digest == the literal; the preimage is 256
 *     bytes; D6 <= INT64_MAX and differs from D2 / EVM_ACTIVE / D4 / D5 /
 *     MLDSA; D4 and D5 are unchanged by generation 6 (the oracle's
 *     controls).
 *  3. drift: the quantities the selfcheck row compares cannot drift
 *     unseen — a descriptor whose version did not move (or moved to 13 /
 *     12) does not hash to the pin; the digest over generation-5 hashes,
 *     base 4, generation 5, spec 2, one owner byte flipped, and each of
 *     the four constants changed (cap, default, minimum, maximum), the
 *     constants reordered, three of them only, or a fifth appended — none
 *     equals D6.
 *  4. param 24: scalar — D6 accepted, D6 ± 1, 0, D2, EVM D, D4, D5, MLDSA
 *     D and UINT64_MAX refused, the window shape binds, params 9 / 18 / 22
 *     refuse D6; grace SAFETY (D25) = DNAC_CHAIN_CONFIG_GRACE_SAFETY_
 *     BLOCKS and, where the two constants differ, not param 22's
 *     ERGONOMIC; stateful matrix — accepted only with HF-2 on, no param-24
 *     row, judging generation EXACTLY 5, A-1 and A not epoch boundaries,
 *     A != 0; each single violation refused (generations 0-4 and 6
 *     too); the other single-use facts do not gate it; the 5-argument
 *     form agrees on the single-use fact; param 22's rules are unchanged
 *     by the new fact.
 *  5. param 25: scalar — [4, 16] inclusive, 0 / 3 / 17 / UINT64_MAX and
 *     D6 refused; no row reads as the default 4 (the chain_config reader's
 *     absent answer, a real database); a committed row is read back;
 *     grace — exactly DNAC_EPOCH_LENGTH (one epoch, D18), equal to the
 *     ERGONOMIC constant in this build, and every other parameter keeps
 *     its class (4 and 15 SAFETY; 24 SAFETY; the ERGONOMIC ones
 *     unchanged); stateful — refused under generations 0-5, accepted
 *     under 6, whatever the HF-2 / single-use / boundary facts; the
 *     param-24 fact does not gate it and it does not gate 24.
 *  6. (summary item 1 half b, the HF-7 mechanism again) a generation-5-
 *     signed EVM envelope [CORE EVMFUND (CORE v10), EVM DEPOSIT (EVM v2)]
 *     passes the pair rule and preflight against the generation-5
 *     registry context, but preflight against the generation-6 context
 *     (CORE v11, EVM v2 — the EVM domain has no generation-6 entry)
 *     refuses it ERR_CTX_VERSION at its CORE leg; a generation-5 SYSTEM
 *     leg (v11) is refused the same way against SYSTEM v12; the same EVM
 *     envelope rebuilt with CORE v11 passes.
 *
 * ── WHAT IT REQUIRES ────────────────────────────────────────────────────
 * Compile flags: NODUS_EVM_ENABLED (generations 3-6 exist only there; the
 * target is registered only in that configuration). The K8 KAT lines are
 * compiled only under DNAC_HF6_FOUNDATION_OWNER_IS_DEFAULT. Environment:
 * none. Section 5's reader check uses one scratch witness database under
 * /tmp. No fault injection.
 *
 * ── WHAT IT LEAVES BEHIND ───────────────────────────────────────────────
 * One /tmp/test_hf9_activation_XXXXXX directory, removed at the end (left
 * behind if a CHECK aborts).
 *
 * ── HOW IT CAN LIE ──────────────────────────────────────────────────────
 *  - The ruleset hashes, C1 and D6 are typed from the Python oracle's
 *    output. The oracle labels the generation-6 values SELF-CONSISTENT: its
 *    controls reproduce the pinned D4 / D5 / generation-4 / -5 hashes from
 *    the same layouts, and the generation-6 values rest on the plan's rule
 *    "only ruleset_version bumped (12 / 11)". This test proves the C table
 *    and constructor agree with the oracle, not that the layout is right
 *    (the ROLEGEN constructor's bytes are HF-6's approved crypto gate,
 *    reused; D6 is a fixed activation identifier, plan AD-7).
 *  - Section 3 cannot hand the production selfcheck a drifted table (the
 *    table is compiled const data; no test hook exists and none is added):
 *    it proves every quantity the selfcheck row COMPARES moves under a
 *    drift, not that the selfcheck function itself runs the comparison —
 *    that is the source read (nodus_witness_runtime.c, the D6 row).
 *  - Sections 4 and 5 call the rule functions with hand-set facts. Which
 *    facts the block path passes is the engine's: proven on the block path
 *    by test_hf9_edge.c (the param-24 single-use case), not here. The
 *    0x71 approval responder's own reads are test_cc_appr.c's shape and
 *    are not exercised here.
 *  - Section 5's grace equality with the ERGONOMIC constant holds in the
 *    build under test; in the short-epoch harness build both constants
 *    are overridden to 15 together (stagef README) — the test asserts the
 *    EPOCH_LENGTH identity, never a literal 720.
 *  - Section 6 drives preflight directly with the context the engine
 *    builds from the registry; it does not apply a block.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
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
#include <sqlite3.h>
#include <unistd.h>

#define CHECK(cond) do { \
    if (!(cond)) { fprintf(stderr, "CHECK fail at %s:%d: %s\n", \
        __FILE__, __LINE__, #cond); exit(1); } } while (0)

static int g_checks = 0;
#define OK() do { g_checks++; } while (0)

#define E_LEN   ((uint64_t)DNAC_EPOCH_LENGTH)
#define GRACE_E ((uint64_t)DNAC_CHAIN_CONFIG_GRACE_ERGONOMIC_BLOCKS)
#define GRACE_S ((uint64_t)DNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS)

/* ── the INDEPENDENT oracle's values (hf9_vote_oracle.py output) ─────── */
#define ORACLE_S6_HEX \
    "817ec157033afe44c88a3a01cab796380907f17aa50b55d607de10e620eb4e63" \
    "282aabad563ce4ff43b313de7d51579a76319d95f50c583c7d66bce221c5494f"
#define ORACLE_C6_HEX \
    "2b841a28beddfac9bcdedd4126149a60f1e9c7cfd896c19bd7df7212443a04af" \
    "f5b88a066e6ad6b9741a855656d23620049109f3a545c1ab4a9f30f2c0156b26"
#define ORACLE_C1_HEX \
    "0aa4c690a05af8827a322912a402d87b2642c99edc1db83f2871af64da18c3f8" \
    "b74a6e5c870edc3450ae0474a3c8d7279efb884df8b285c8848beffb25922766"
#define ORACLE_D6      0x1f12a7f0b824ae45ULL
#define ORACLE_D6_DEC  2239036617079959109ULL

static int nib(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

/* 128 lowercase hex digits -> 64 bytes */
static void unhex64(const char *h, uint8_t out[64]) {
    CHECK(strlen(h) == 128u);
    for (int i = 0; i < 64; i++) {
        int a = nib(h[2 * i]), b = nib(h[2 * i + 1]);
        CHECK(a >= 0 && b >= 0);
        out[i] = (uint8_t)(a << 4 | b);
    }
}

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

/* ══ 1. the compiled generation 6 ═════════════════════════════════════ */
static void t_table(void) {
    uint8_t S6[64], C6[64], C1[64];
    unhex64(ORACLE_S6_HEX, S6);
    unhex64(ORACLE_C6_HEX, C6);
    unhex64(ORACLE_C1_HEX, C1);
    CHECK(NODUS_RT_GEN_TRIE == 6u &&
          NODUS_RT_GEN_TRIE_BASE == NODUS_RT_GEN_ROOTS); OK();
    CHECK(NODUS_RT_GEN_MAX == NODUS_RT_GEN_TRIE); OK();
    CHECK(nodus_runtime_generation_count() == 6u); OK();
    size_t n_all = 0, n6 = 0, n5 = 0;
    const nodus_domain_runtime_t *all = nodus_runtime_all_table(&n_all);
    const nodus_domain_runtime_t *g6 =
        nodus_runtime_generation_table(NODUS_RT_GEN_TRIE, &n6);
    const nodus_domain_runtime_t *g5 =
        nodus_runtime_generation_table(NODUS_RT_GEN_ROOTS, &n5);
    CHECK(all && n_all == 13u); OK();
    CHECK(g5 && n5 == 2u && g5 == &all[9]); OK();
    CHECK(g6 && n6 == 2u && g6 == &all[11]); OK();
    CHECK(g6[0].domain_id == DNA_DOMAIN_SYSTEM &&
          g6[1].domain_id == DNA_DOMAIN_CORE); OK();
    CHECK(g6[0].generation == NODUS_RT_GEN_TRIE &&
          g6[1].generation == NODUS_RT_GEN_TRIE); OK();
    /* no EVM slot: the EVM domain keeps the EVM generation's entry */
    CHECK(nodus_runtime_for_generation(NODUS_RT_GEN_TRIE,
                                       DNA_DOMAIN_EVM) == NULL); OK();
    CHECK(nodus_runtime_for_generation(NODUS_RT_GEN_EVM,
                                       DNA_DOMAIN_EVM) != NULL); OK();
    /* SYSTEM v12 / CORE v11 — generation 5's v11 / v10, version only */
    CHECK(g5[0].ruleset_version == 11u && g5[1].ruleset_version == 10u); OK();
    CHECK(g6[0].ruleset_version == 12u && g6[1].ruleset_version == 11u);
    OK();
    CHECK(g6[0].descriptor.ruleset_version == 12u &&
          g6[1].descriptor.ruleset_version == 11u); OK();
    CHECK(desc_same_but_version(&g6[0].descriptor, &g5[0].descriptor)); OK();
    CHECK(desc_same_but_version(&g6[1].descriptor, &g5[1].descriptor)); OK();
    for (int k = 0; k < 2; k++) {
        CHECK(g6[k].runtime_kind == g5[k].runtime_kind &&
              g6[k].runtime_abi == g5[k].runtime_abi &&
              g6[k].allowed_auth_kinds == g5[k].allowed_auth_kinds &&
              g6[k].admit == g5[k].admit && g6[k].tx_cost == g5[k].tx_cost &&
              g6[k].auth == g5[k].auth &&
              g6[k].read_plan == g5[k].read_plan &&
              g6[k].exec == g5[k].exec &&
              g6[k].state_root == g5[k].state_root &&
              g6[k].payload_root == g5[k].payload_root &&
              g6[k].asset_check == g5[k].asset_check &&
              g6[k].claim_apply == g5[k].claim_apply &&
              g6[k].invariant == g5[k].invariant &&
              g6[k].state_init == g5[k].state_init &&
              g6[k].adapter == g5[k].adapter);
        OK();
    }
    /* the SYSTEM policy: its OWN sealed object, digest = oracle control C1 */
    CHECK(g6[0].meter_policy != NULL && g6[1].meter_policy == NULL); OK();
    CHECK(g6[0].meter_policy != g5[0].meter_policy); OK();
    CHECK(memcmp(g6[0].descriptor.meter_policy_digest, C1, 64) == 0); OK();
    /* the pins == the oracle's values — first and last byte named so a
     * transposed row of the C array is identified, then all 64 */
    CHECK(g6[0].ruleset_hash[0] == 0x81 && g6[0].ruleset_hash[63] == 0x4f);
    OK();
    CHECK(g6[1].ruleset_hash[0] == 0x2b && g6[1].ruleset_hash[63] == 0x26);
    OK();
    CHECK(memcmp(g6[0].ruleset_hash, S6, 64) == 0); OK();
    CHECK(memcmp(g6[1].ruleset_hash, C6, 64) == 0); OK();
    /* and the C encoder re-derives them (the selfcheck's own test) */
    {
        uint8_t h[64];
        CHECK(dna_ruleset_desc_hash(&g6[0].descriptor, h) == 0 &&
              memcmp(h, S6, 64) == 0); OK();
        CHECK(dna_ruleset_desc_hash(&g6[1].descriptor, h) == 0 &&
              memcmp(h, C6, 64) == 0); OK();
    }
    /* exact-tuple lookup resolves each generation-6 tuple to its entry,
     * and the generation-5 tuples still to theirs */
    CHECK(nodus_runtime_lookup(DNA_DOMAIN_SYSTEM, g6[0].runtime_kind,
                               g6[0].runtime_abi, 12, S6) == &g6[0]); OK();
    CHECK(nodus_runtime_lookup(DNA_DOMAIN_CORE, g6[1].runtime_kind,
                               g6[1].runtime_abi, 11, C6) == &g6[1]); OK();
    CHECK(nodus_runtime_lookup(DNA_DOMAIN_SYSTEM, g5[0].runtime_kind,
                               g5[0].runtime_abi, 11, g5[0].ruleset_hash)
          == &g5[0]); OK();
    CHECK(nodus_witness_runtime_selfcheck() == 0); OK();
}

/* ══ 2. the literal D6 ═════════════════════════════════════════════════ */
static void t_literal(void) {
    static const uint8_t owner[] = DNAC_HF6_FOUNDATION_OWNER;
    _Static_assert(sizeof(owner) == 64, "the compiled owner is 64 bytes");
    uint8_t S6[64], C6[64];
    unhex64(ORACLE_S6_HEX, S6);
    unhex64(ORACLE_C6_HEX, C6);
    const uint64_t consts[4] = { 1024u, 4u, 4u, 16u };
    CHECK(DNAC_HF9_MEMBER_CAP == 1024u &&
          DNAC_STORAGE_COPIES_DEFAULT == 4u &&
          DNAC_CFG_MIN_STORAGE_COPIES == 4u &&
          DNAC_CFG_MAX_STORAGE_COPIES == 16u); OK();
    CHECK(DNAC_HF9_SWITCH_SPEC_VERSION == 1u); OK();
    _Static_assert(DNA_ROLEGEN_PREIMAGE_LEN(4) == 256,
                   "the D6 preimage is 256 bytes (hf9_vote_oracle.py)");
    uint64_t d0 = 0, w = 0;
    CHECK(dna_rolegen_vote_digest(NODUS_RT_GEN_TRIE, NODUS_RT_GEN_TRIE_BASE,
                                  S6, C6, DNAC_HF9_SWITCH_SPEC_VERSION,
                                  owner, consts, 4, &d0) == 0); OK();
    /* triangle: constructor == wrapper == compiled literal */
    CHECK(nodus_runtime_gen6_vote_digest(&w) == 0 && w == d0); OK();
    CHECK(d0 == (uint64_t)DNAC_CFG_RULESET_GEN_TRIE_D); OK();
    CHECK(nodus_runtime_gen6_vote_digest(NULL) == -1); OK();
#ifdef DNAC_HF6_FOUNDATION_OWNER_IS_DEFAULT
    /* KAT: owner K8 -> D6 of shared/dnac/tests/hf9_vote_oracle.py ("D6 =
     * 0x1f12a7f0b824ae45ULL", "D6 (decimal) = 2239036617079959109") */
    CHECK(d0 == ORACLE_D6 && d0 == ORACLE_D6_DEC); OK();
    CHECK((uint64_t)DNAC_CFG_RULESET_GEN_TRIE_D == ORACLE_D6); OK();
#endif
    CHECK(d0 <= (uint64_t)INT64_MAX); OK();
    CHECK(d0 != (uint64_t)DNAC_CFG_RULESET_GEN2_D2 &&
          d0 != (uint64_t)DNAC_CFG_EVM_ACTIVE_D &&
          d0 != (uint64_t)DNAC_CFG_RULESET_GEN_ROLES_D &&
          d0 != (uint64_t)DNAC_CFG_RULESET_GEN_ROOTS_D &&
          d0 != (uint64_t)DNAC_CFG_MLDSA_ACTIVE_D); OK();
    /* the generation-4 and -5 votes are unchanged by generation 6 (the
     * oracle's controls D4 / D5) */
    {
        uint64_t d4 = 0, d5 = 0;
        CHECK(nodus_runtime_gen4_vote_digest(&d4) == 0 &&
              d4 == (uint64_t)DNAC_CFG_RULESET_GEN_ROLES_D); OK();
        CHECK(nodus_runtime_gen5_vote_digest(&d5) == 0 &&
              d5 == (uint64_t)DNAC_CFG_RULESET_GEN_ROOTS_D); OK();
    }
}

/* ══ 3. drift — every compared quantity moves ═══════════════════════════ */
static void t_drift(void) {
    static const uint8_t owner_c[] = DNAC_HF6_FOUNDATION_OWNER;
    uint8_t owner[64];
    memcpy(owner, owner_c, 64);
    const nodus_domain_runtime_t *s6 =
        nodus_runtime_for_generation(NODUS_RT_GEN_TRIE, DNA_DOMAIN_SYSTEM);
    const nodus_domain_runtime_t *c6 =
        nodus_runtime_for_generation(NODUS_RT_GEN_TRIE, DNA_DOMAIN_CORE);
    const nodus_domain_runtime_t *s5 =
        nodus_runtime_for_generation(NODUS_RT_GEN_ROOTS, DNA_DOMAIN_SYSTEM);
    const nodus_domain_runtime_t *c5 =
        nodus_runtime_for_generation(NODUS_RT_GEN_ROOTS, DNA_DOMAIN_CORE);
    CHECK(s6 && c6 && s5 && c5); OK();
    /* a descriptor whose version did not move (or moved elsewhere) does
     * not hash to the pin — the selfcheck's re-derivation refuses it */
    {
        static const uint32_t vs[] = { 11u, 13u };
        static const uint32_t vc[] = { 10u, 12u };
        uint8_t S6[64], C6[64];
        unhex64(ORACLE_S6_HEX, S6);
        unhex64(ORACLE_C6_HEX, C6);
        for (size_t i = 0; i < 2; i++) {
            dna_ruleset_desc_t d = s6->descriptor;
            uint8_t h[64];
            d.ruleset_version = vs[i];
            CHECK(dna_ruleset_desc_hash(&d, h) == 0 &&
                  memcmp(h, S6, 64) != 0); OK();
            d = c6->descriptor;
            d.ruleset_version = vc[i];
            CHECK(dna_ruleset_desc_hash(&d, h) == 0 &&
                  memcmp(h, C6, 64) != 0); OK();
        }
        /* generation 5's own descriptors give generation 5's pins, never
         * generation 6's */
        uint8_t h[64];
        CHECK(dna_ruleset_desc_hash(&s5->descriptor, h) == 0 &&
              memcmp(h, s5->ruleset_hash, 64) == 0 &&
              memcmp(h, S6, 64) != 0); OK();
    }
    /* the digest moves with every input the selfcheck row binds */
    const uint64_t k0[4] = { 1024u, 4u, 4u, 16u };
    uint64_t d0 = 0, d = 0;
    CHECK(dna_rolegen_vote_digest(6, 5, s6->ruleset_hash, c6->ruleset_hash,
                                  1, owner, k0, 4, &d0) == 0 &&
          d0 == (uint64_t)DNAC_CFG_RULESET_GEN_TRIE_D); OK();
    CHECK(dna_rolegen_vote_digest(6, 5, s5->ruleset_hash, c6->ruleset_hash,
                                  1, owner, k0, 4, &d) == 0 && d != d0); OK();
    CHECK(dna_rolegen_vote_digest(6, 5, s6->ruleset_hash, c5->ruleset_hash,
                                  1, owner, k0, 4, &d) == 0 && d != d0); OK();
    CHECK(dna_rolegen_vote_digest(6, 5, s6->ruleset_hash, c6->ruleset_hash,
                                  2, owner, k0, 4, &d) == 0 && d != d0); OK();
    CHECK(dna_rolegen_vote_digest(6, 4, s6->ruleset_hash, c6->ruleset_hash,
                                  1, owner, k0, 4, &d) == 0 && d != d0); OK();
    CHECK(dna_rolegen_vote_digest(5, 5, s6->ruleset_hash, c6->ruleset_hash,
                                  1, owner, k0, 4, &d) == 0 && d != d0); OK();
    /* each of the four constants, one at a time */
    {
        const uint64_t cap[4]  = { 2048u, 4u, 4u, 16u };
        const uint64_t cap1[4] = { 1025u, 4u, 4u, 16u };
        const uint64_t def[4]  = { 1024u, 5u, 4u, 16u };
        const uint64_t mn[4]   = { 1024u, 4u, 3u, 16u };
        const uint64_t mx[4]   = { 1024u, 4u, 4u, 17u };
        const uint64_t swp[4]  = { 1024u, 4u, 16u, 4u };   /* reordered */
        const uint64_t *v[] = { cap, cap1, def, mn, mx, swp };
        for (size_t i = 0; i < sizeof(v) / sizeof(v[0]); i++) {
            CHECK(dna_rolegen_vote_digest(6, 5, s6->ruleset_hash,
                                          c6->ruleset_hash, 1, owner, v[i],
                                          4, &d) == 0 && d != d0); OK();
        }
        /* three constants only, and a fifth appended */
        CHECK(dna_rolegen_vote_digest(6, 5, s6->ruleset_hash,
                                      c6->ruleset_hash, 1, owner, k0, 3,
                                      &d) == 0 && d != d0); OK();
        const uint64_t k5[5] = { 1024u, 4u, 4u, 16u, 0u };
        CHECK(dna_rolegen_vote_digest(6, 5, s6->ruleset_hash,
                                      c6->ruleset_hash, 1, owner, k5, 5,
                                      &d) == 0 && d != d0); OK();
    }
    owner[0] ^= 1u;
    CHECK(dna_rolegen_vote_digest(6, 5, s6->ruleset_hash, c6->ruleset_hash,
                                  1, owner, k0, 4, &d) == 0 && d != d0); OK();
    owner[0] ^= 1u;
    CHECK(dna_rolegen_vote_digest(6, 5, s6->ruleset_hash, c6->ruleset_hash,
                                  1, owner, k0, 4, &d) == 0 && d == d0); OK();
}

/* ══ 4. the param-24 vote rules ════════════════════════════════════════ */

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

static void t_param24(void) {
    const uint8_t P = (uint8_t)DNAC_CFG_RULESET_GEN_TRIE;
    CHECK(P == 24u && DNAC_CFG_PARAM_MAX_ID == 25); OK();
    CHECK(dnac_cfg_param_read_by_consensus(P)); OK();
    /* scalar: exactly D6 */
    CHECK(nodus_chain_config_scalar_rules(
              P, (uint64_t)DNAC_CFG_RULESET_GEN_TRIE_D, 1, 5000, 4000, 7)
          == 0); OK();
    {
        const uint64_t bad[] = {
            (uint64_t)DNAC_CFG_RULESET_GEN_TRIE_D + 1u,
            (uint64_t)DNAC_CFG_RULESET_GEN_TRIE_D - 1u, 0u,
            (uint64_t)DNAC_CFG_RULESET_GEN_ROOTS_D,
            (uint64_t)DNAC_CFG_RULESET_GEN_ROLES_D,
            (uint64_t)DNAC_CFG_RULESET_GEN2_D2,
            (uint64_t)DNAC_CFG_EVM_ACTIVE_D,
            (uint64_t)DNAC_CFG_MLDSA_ACTIVE_D, UINT64_MAX };
        for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
            CHECK(nodus_chain_config_scalar_rules(P, bad[i], 1, 5000, 4000,
                                                  7) == -1); OK();
        }
    }
    /* params 9 / 18 / 22 refuse D6 */
    {
        const uint8_t others[] = { (uint8_t)DNAC_CFG_RULESET_GEN2,
                                   (uint8_t)DNAC_CFG_RULESET_GEN_ROLES,
                                   (uint8_t)DNAC_CFG_RULESET_GEN_ROOTS };
        for (size_t i = 0; i < sizeof(others); i++) {
            CHECK(nodus_chain_config_scalar_rules(
                      others[i], (uint64_t)DNAC_CFG_RULESET_GEN_TRIE_D, 1,
                      5000, 4000, 7) == -1); OK();
        }
    }
    /* the window shape still applies */
    CHECK(nodus_chain_config_scalar_rules(
              P, (uint64_t)DNAC_CFG_RULESET_GEN_TRIE_D, 0, 5000, 4000, 7)
          == -1); OK();
    /* grace: SAFETY (D25 "4.24."), not param 22's ERGONOMIC */
    CHECK(nodus_chain_config_grace_for_param(P) == GRACE_S); OK();
    CHECK(nodus_chain_config_grace_for_param(P) ==
          nodus_chain_config_grace_for_param(
              (uint8_t)DNAC_CFG_EVM_ACTIVE)); OK();
    if (GRACE_S != GRACE_E) {
        CHECK(nodus_chain_config_grace_for_param(P) !=
              nodus_chain_config_grace_for_param(
                  (uint8_t)DNAC_CFG_RULESET_GEN_ROOTS)); OK();
    }

    /* stateful matrix */
    const uint64_t ok_eff = eff_ok(1u + GRACE_S);
    nodus_cc_state_facts_t f;
    memset(&f, 0, sizeof(f));
    f.hf2_active = 1;
    f.judging_generation = NODUS_RT_GEN_TRIE_BASE;
    CHECK(nodus_chain_config_stateful_rules_ex(P, ok_eff, &f) == 0); OK();
    /* (a) single use */
    f.ruleset_gen_trie_voted = 1;
    CHECK(nodus_chain_config_stateful_rules_ex(P, ok_eff, &f) == -1); OK();
    f.ruleset_gen_trie_voted = 0;
    /* the OTHER single-use facts do not gate param 24 */
    f.ruleset_gen_roots_voted = 1;
    f.ruleset_gen_roles_voted = 1;
    f.ruleset_gen2_voted = 1;
    f.ruleset_gen_storage_voted = 1;
    f.evm_active_voted = 1;
    f.mldsa_active_voted = 1;
    CHECK(nodus_chain_config_stateful_rules_ex(P, ok_eff, &f) == 0); OK();
    f.ruleset_gen_roots_voted = 0;
    f.ruleset_gen_roles_voted = 0;
    f.ruleset_gen2_voted = 0;
    f.ruleset_gen_storage_voted = 0;
    f.evm_active_voted = 0;
    f.mldsa_active_voted = 0;
    /* (b) HF-2 */
    f.hf2_active = 0;
    CHECK(nodus_chain_config_stateful_rules_ex(P, ok_eff, &f) == -1); OK();
    f.hf2_active = 1;
    /* (c) judged under EXACTLY generation 5 */
    {
        const uint32_t gens[] = { 0u, NODUS_RT_GEN_1, NODUS_RT_GEN_2,
                                  NODUS_RT_GEN_EVM, NODUS_RT_GEN_STORAGE,
                                  NODUS_RT_GEN_TRIE, 7u };
        for (size_t i = 0; i < sizeof(gens) / sizeof(gens[0]); i++) {
            f.judging_generation = gens[i];
            CHECK(nodus_chain_config_stateful_rules_ex(P, ok_eff, &f) == -1);
            OK();
        }
        f.judging_generation = NODUS_RT_GEN_TRIE_BASE;
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
        /* E+2: neither E+1 nor E+2 a boundary */
        CHECK(nodus_chain_config_stateful_rules_ex(P, E_LEN + 2u, &f) == 0);
        OK();
    }
    /* the 5-argument test form: its 4th argument is the single-use fact */
    CHECK(nodus_chain_config_stateful_rules(P, ok_eff, 1, 0,
                                            NODUS_RT_GEN_TRIE_BASE) == 0);
    OK();
    CHECK(nodus_chain_config_stateful_rules(P, ok_eff, 1, 1,
                                            NODUS_RT_GEN_TRIE_BASE) == -1);
    OK();
    CHECK(nodus_chain_config_stateful_rules(P, ok_eff, 0, 0,
                                            NODUS_RT_GEN_TRIE_BASE) == -1);
    OK();
    /* param 22's rules are unchanged by the new fact */
    memset(&f, 0, sizeof(f));
    f.hf2_active = 1;
    f.judging_generation = NODUS_RT_GEN_ROOTS_BASE;
    f.ruleset_gen_trie_voted = 1;
    CHECK(nodus_chain_config_stateful_rules_ex(
              (uint8_t)DNAC_CFG_RULESET_GEN_ROOTS, ok_eff, &f) == 0); OK();
}

/* ══ 5. param 25 — copies per segment ═════════════════════════════════ */

static void t_param25(void) {
    const uint8_t P = (uint8_t)DNAC_CFG_STORAGE_COPIES;
    CHECK(P == 25u && dnac_cfg_param_read_by_consensus(P)); OK();
    /* scalar: [4, 16] inclusive */
    {
        const struct { uint64_t v; int want; } c[] = {
            { 0, -1 }, { 3, -1 }, { 4, 0 }, { 5, 0 }, { 15, 0 }, { 16, 0 },
            { 17, -1 }, { 1024, -1 }, { UINT64_MAX, -1 },
            { (uint64_t)DNAC_CFG_RULESET_GEN_TRIE_D, -1 } };
        for (size_t i = 0; i < sizeof(c) / sizeof(c[0]); i++) {
            CHECK(nodus_chain_config_scalar_rules(P, c[i].v, 1, 5000, 4000,
                                                  7) == c[i].want); OK();
        }
    }
    /* the window shape still applies */
    CHECK(nodus_chain_config_scalar_rules(P, 4, 0, 5000, 4000, 7) == -1);
    OK();
    /* 24 refuses an in-range copy count */
    CHECK(nodus_chain_config_scalar_rules(
              (uint8_t)DNAC_CFG_RULESET_GEN_TRIE, 4, 1, 5000, 4000, 7) == -1);
    OK();

    /* grace: exactly ONE EPOCH (D18, A16, F-33); every other parameter
     * keeps its class ("diğer ayarları değiştirme.") */
    CHECK(nodus_chain_config_grace_for_param(P) == E_LEN); OK();
    /* in this build the ERGONOMIC constant equals the epoch length (the
     * harness overrides both to 15 together) */
    CHECK(nodus_chain_config_grace_for_param(P) == GRACE_E); OK();
    CHECK(nodus_chain_config_grace_for_param(
              (uint8_t)DNAC_CFG_TARGET_ACTIVE_COUNT) == GRACE_S); OK();
    CHECK(nodus_chain_config_grace_for_param(
              (uint8_t)DNAC_CFG_EVM_BLOCK_GAS_LIMIT) == GRACE_S); OK();
    CHECK(nodus_chain_config_grace_for_param(
              (uint8_t)DNAC_CFG_EVM_ACTIVE) == GRACE_S); OK();
    CHECK(nodus_chain_config_grace_for_param(
              (uint8_t)DNAC_CFG_RULESET_GEN_TRIE) == GRACE_S); OK();
    {
        const uint8_t ergo[] = {
            (uint8_t)DNAC_CFG_GAS_PRICE_RAW_PER_UNIT,
            (uint8_t)DNAC_CFG_TOKEN_CREATE_FEE_RAW,
            (uint8_t)DNAC_CFG_HF2_ACTIVE, (uint8_t)DNAC_CFG_HF3_ACTIVE,
            (uint8_t)DNAC_CFG_RULESET_GEN2,
            (uint8_t)DNAC_CFG_NAME_PRICE_3P, (uint8_t)DNAC_CFG_NAME_PRICE_6P,
            (uint8_t)DNAC_CFG_DELEGATE_NAME_REQUIRED,
            (uint8_t)DNAC_CFG_RULESET_GEN_ROLES,
            (uint8_t)DNAC_CFG_STAKE_MIN, (uint8_t)DNAC_CFG_POWER_CAP_BPS,
            (uint8_t)DNAC_CFG_STORAGE_BOND,
            (uint8_t)DNAC_CFG_RULESET_GEN_ROOTS,
            (uint8_t)DNAC_CFG_MLDSA_ACTIVE };
        for (size_t i = 0; i < sizeof(ergo); i++) {
            CHECK(nodus_chain_config_grace_for_param(ergo[i]) == GRACE_E);
            OK();
        }
    }

    /* stateful: votable only while generation >= 6 judges the vote */
    nodus_cc_state_facts_t f;
    const uint64_t any_eff = 5000;
    {
        const uint32_t refused[] = { 0u, NODUS_RT_GEN_1, NODUS_RT_GEN_2,
                                     NODUS_RT_GEN_EVM, NODUS_RT_GEN_STORAGE,
                                     NODUS_RT_GEN_ROOTS };
        for (size_t i = 0; i < sizeof(refused) / sizeof(refused[0]); i++) {
            memset(&f, 0, sizeof(f));
            f.hf2_active = 1;
            f.judging_generation = refused[i];
            CHECK(nodus_chain_config_stateful_rules_ex(P, any_eff, &f) == -1);
            OK();
        }
        const uint32_t legal[] = { NODUS_RT_GEN_TRIE, NODUS_RT_GEN_TRIE + 1u };
        for (size_t i = 0; i < sizeof(legal) / sizeof(legal[0]); i++) {
            memset(&f, 0, sizeof(f));
            f.judging_generation = legal[i];   /* HF-2 off, nothing voted */
            CHECK(nodus_chain_config_stateful_rules_ex(P, any_eff, &f) == 0);
            OK();
            /* no single-use, boundary or HF-2 rule: an ordinary re-votable
             * value (effective 0, A-1 and A on a boundary all fine) */
            f.ruleset_gen_trie_voted = 1;
            f.ruleset_gen_roots_voted = 1;
            CHECK(nodus_chain_config_stateful_rules_ex(P, 0, &f) == 0); OK();
            CHECK(nodus_chain_config_stateful_rules_ex(P, 2u * E_LEN, &f)
                  == 0); OK();
        }
    }
    /* the param-24 fact does not gate 25; the facts of 25 do not gate 24 */
    memset(&f, 0, sizeof(f));
    f.hf2_active = 1;
    f.judging_generation = NODUS_RT_GEN_TRIE;
    f.ruleset_gen_trie_voted = 1;
    CHECK(nodus_chain_config_stateful_rules_ex(P, any_eff, &f) == 0); OK();
    f.judging_generation = NODUS_RT_GEN_TRIE_BASE;
    f.ruleset_gen_trie_voted = 0;
    CHECK(nodus_chain_config_stateful_rules_ex(
              (uint8_t)DNAC_CFG_RULESET_GEN_TRIE, eff_ok(1u + GRACE_S), &f)
          == 0); OK();

    /* the reader: no row reads as the default 4, a committed row is read
     * back (the contract: 0 present / 1 absent with the caller's default /
     * -1 fault; a real scratch database) */
    {
        char dir[64];
        nodus_witness_t *w = calloc(1, sizeof(*w));
        CHECK(w != NULL); OK();
        snprintf(dir, sizeof(dir), "/tmp/test_hf9_activation_XXXXXX");
        CHECK(mkdtemp(dir) != NULL); OK();
        snprintf(w->data_path, sizeof(w->data_path), "%s", dir);
        uint8_t cid[16];
        memset(cid, 0xC9, sizeof(cid));
        CHECK(nodus_witness_create_chain_db(w, cid) == 0 && w->db); OK();
        uint64_t v = 0;
        CHECK(nodus_chain_config_get_u64(w, P, 1000,
                                         DNAC_STORAGE_COPIES_DEFAULT, &v)
              == 1 && v == DNAC_STORAGE_COPIES_DEFAULT && v == 4u); OK();
        CHECK(nodus_chain_config_get_u64(w, (uint8_t)DNAC_CFG_RULESET_GEN_TRIE,
                                         1000, 0, &v) == 1); OK();
        sqlite3_stmt *st = NULL;
        uint8_t txh[64];
        memset(txh, 0x25, sizeof(txh));
        CHECK(sqlite3_prepare_v2(w->db,
                  "INSERT INTO chain_config_history (param_id, new_value, "
                  "effective_block, commit_block, tx_hash, proposal_nonce, "
                  "created_at_unix) VALUES (25, 7, 500, 1, ?1, 1, 0)",
                  -1, &st, NULL) == SQLITE_OK); OK();
        CHECK(sqlite3_bind_blob(st, 1, txh, 64, SQLITE_TRANSIENT)
              == SQLITE_OK && sqlite3_step(st) == SQLITE_DONE); OK();
        sqlite3_finalize(st);
        w->chain_config_cache_warm = false;
        /* before its effective height: still the default; from it: 7 */
        CHECK(nodus_chain_config_get_u64(w, P, 499,
                                         DNAC_STORAGE_COPIES_DEFAULT, &v)
              == 1 && v == 4u); OK();
        CHECK(nodus_chain_config_get_u64(w, P, 500,
                                         DNAC_STORAGE_COPIES_DEFAULT, &v)
              == 0 && v == 7u); OK();
        CHECK(w->chain_config_cache_count[25] == 1 &&
              w->chain_config_cache_count[24] == 0); OK();
        sqlite3_close(w->db);
        free(w);
        char cmd[128];
        snprintf(cmd, sizeof(cmd), "rm -rf '%s'", dir);
        if (system(cmd) != 0) { /* best effort */ }
    }
}

/* ══ 6. a generation-5-signed EVM envelope at A ════════════════════════ */

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

/* the registry context of a generation for a domain (the engine's
 * block-start rulesets come from the committed manifests, which name
 * exactly the compiled entry's version + hash) */
static void ctx_of(dna_env_leg_ctx_t *c, const nodus_domain_runtime_t *rt) {
    memset(c, 0, sizeof(*c));
    c->domain_id = rt->domain_id;
    c->ruleset_version = rt->ruleset_version;
    memcpy(c->ruleset_hash, rt->ruleset_hash, sizeof(c->ruleset_hash));
}

static void t_evm_dead_at_a(void) {
    static uint8_t buf[4096];
    static const uint8_t chain[32] = { 0x42 };
    const nodus_domain_runtime_t *c5 =
        nodus_runtime_for_generation(NODUS_RT_GEN_ROOTS, DNA_DOMAIN_CORE);
    const nodus_domain_runtime_t *c6 =
        nodus_runtime_for_generation(NODUS_RT_GEN_TRIE, DNA_DOMAIN_CORE);
    const nodus_domain_runtime_t *s5 =
        nodus_runtime_for_generation(NODUS_RT_GEN_ROOTS, DNA_DOMAIN_SYSTEM);
    const nodus_domain_runtime_t *s6 =
        nodus_runtime_for_generation(NODUS_RT_GEN_TRIE, DNA_DOMAIN_SYSTEM);
    /* the EVM domain's ONE entry (the EVM generation's v2) — the registry
     * names it before AND after the generation-6 edge */
    const nodus_domain_runtime_t *ev =
        nodus_runtime_for_generation(NODUS_RT_GEN_EVM, DNA_DOMAIN_EVM);
    CHECK(c5 && c6 && s5 && s6 && ev); OK();
    CHECK(c5->ruleset_version == 10u && c6->ruleset_version == 11u); OK();
    CHECK(ev->ruleset_version == NODUS_RT_EVM_RULESET_VERSION_GEVM); OK();

    dna_env_preflight_t *pf = calloc(1, sizeof(*pf));
    CHECK(pf != NULL); OK();

    /* a generation-5-signed EVM envelope: CORE leg v10 */
    size_t len = evm_env(buf, sizeof(buf), c5->ruleset_version);
    CHECK(len > 0); OK();
    {
        dna_env_view_t v;
        CHECK(dna_env_decode(buf, len, &v) == 0 &&
              nodus_rt_evm_pair_check(&v) == 0); OK();   /* a valid pair */
    }
    dna_env_leg_ctx_t lc[2];
    /* under the generation-5 registry (blocks <= A-1): admitted */
    ctx_of(&lc[0], c5);
    ctx_of(&lc[1], ev);
    CHECK(dna_env_preflight(buf, len, chain, 100, lc, 2, pf) ==
          DNA_ENV_PF_OK); OK();
    /* under the generation-6 registry (block A on): dead at its CORE leg */
    ctx_of(&lc[0], c6);
    ctx_of(&lc[1], ev);
    CHECK(dna_env_preflight(buf, len, chain, 100, lc, 2, pf) ==
          DNA_ENV_PF_ERR_CTX_VERSION); OK();
    /* the EVM leg alone would still match (EVM v2 is unchanged): the
     * refusal is the CORE leg's — the pair rule is what kills it */
    CHECK(lc[1].ruleset_version == NODUS_RT_EVM_RULESET_VERSION_GEVM); OK();
    /* the same envelope rebuilt for generation 6 (CORE v11) passes */
    len = evm_env(buf, sizeof(buf), c6->ruleset_version);
    CHECK(len > 0); OK();
    CHECK(dna_env_preflight(buf, len, chain, 100, lc, 2, pf) ==
          DNA_ENV_PF_OK); OK();

    /* half (a), the same mechanism: a generation-5 SYSTEM leg (v11) */
    len = sys_env(buf, sizeof(buf), s5->ruleset_version);
    CHECK(len > 0); OK();
    ctx_of(&lc[0], s5);
    CHECK(dna_env_preflight(buf, len, chain, 100, lc, 1, pf) ==
          DNA_ENV_PF_OK); OK();
    ctx_of(&lc[0], s6);
    CHECK(dna_env_preflight(buf, len, chain, 100, lc, 1, pf) ==
          DNA_ENV_PF_ERR_CTX_VERSION); OK();
    free(pf);
}

int main(void) {
    t_table();
    t_literal();
    t_drift();
    t_param24();
    t_param25();
    t_evm_dead_at_a();
    fprintf(stderr, "test_hf9_activation: all sections passed, %d checks\n",
            g_checks);
    return 0;
}
