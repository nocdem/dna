/**
 * Nodus — Ledger V2 S4: NATIVE_BUILTIN runtime table tests (INACTIVE layer).
 *
 * Sections:
 *   1. Self-check: pinned digests == fresh C recomputation; table shape;
 *      S5 hooks absent; the checked-in descriptors' rule/type lists and
 *      both ruleset digests pinned against the INDEPENDENT python oracle
 *      (S9 W4 re-derivation — SYSTEM's digest MUST NOT move).
 *   2. Exact-tuple lookup: SYSTEM and DNA_CORE hit; then every axis
 *      mutated one at a time MUST miss — unknown domain, wrong kind,
 *      wrong ABI, wrong ruleset version, one-bit ruleset-hash flip.
 *   3. Admission: owned transparent types admit with pool 0; foreign type
 *      rejects; nonzero pool rejects; TYPES 11, 12 AND 13 REJECT with any
 *      pool value (the C3/activation hard stop).
 *   4. Cost declarations: pinned values; unowned type has NO cost. Since
 *      tx_cost is the only observable that separates "owned" from
 *      "rejected", it doubles as the ownership oracle for 11/12/13.
 *   5. Test-only THIRD runtime in a caller-supplied table: lookup_in hits
 *      it, the production table never contains it, and supporting it
 *      required zero changes to any consensus structure.
 *
 * @file test_domain_runtime.c
 */

#include "../src/witness/nodus_witness_runtime.h"
#include "../src/witness/nodus_witness_v2_adapter.h"

#include <stdio.h>
#include <string.h>

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, (msg)); \
        return 1; \
    } \
} while (0)

static int g_checks = 0;
#define OK() do { g_checks++; } while (0)

/* Ruleset digests as produced by the INDEPENDENT python3 oracle over the
 * "DNA.RULESET.v1" descriptor layout — never copied out of the C
 * encoder. selfcheck() already proves pinned-constant == fresh C
 * recomputation; these literals additionally pin BOTH against the
 * oracle, so a descriptor edit cannot silently move a digest by
 * re-deriving the constant from the same (possibly wrong) code.
 *
 * RE-DERIVED for the EXECUTION SEASON (RulesetDescriptor v2): the
 * descriptor now APPENDS the committed meter_policy_digest, so BOTH
 * digests move by construction. SYSTEM's commits its compiled metering
 * policy's identity digest (KAT_METPOL_SYSTEM below); CORE's commits
 * the all-zero "no policy declared" field. The S9 values
 * (f2dcdefa…4cce / e0a0bc43…7429) are DEAD. Oracle:
 * scratchpad exec_season_oracle.py. */
static const uint8_t KAT_RS_SYSTEM[DNA_DOM_HASH_LEN] = {
    /* CAPACITY SEASON re-derivation: SYSTEM ruleset_version 2 (call v2,
     * auth carrier v2) committing the POLICY V2 identity digest
     * (max_block_env_bytes appended). Oracle: scratchpad
     * capacity_season_oracle.py, control-legged against BOTH shipped
     * pins. The exec-season value 89362213…96c2 is DEAD. */
    0x9f, 0xc5, 0x39, 0x4e, 0x60, 0xe0, 0xd9, 0x80,
    0xae, 0xe5, 0x5b, 0x5a, 0xa7, 0x1c, 0x4f, 0x9c,
    0x84, 0xcd, 0x45, 0x1f, 0x08, 0xd2, 0x76, 0xcf,
    0xfe, 0x21, 0x29, 0xd1, 0xfc, 0x95, 0x7f, 0x6f,
    0x35, 0x40, 0xa0, 0x33, 0x6c, 0xc8, 0x0e, 0xc5,
    0x30, 0x98, 0xa8, 0x97, 0x40, 0x40, 0xad, 0x7f,
    0x40, 0x8b, 0xa5, 0x9d, 0x88, 0x5d, 0x17, 0xac,
    0xdd, 0x17, 0x13, 0x46, 0x8c, 0xce, 0x24, 0xbb
};
static const uint8_t KAT_RS_CORE[DNA_DOM_HASH_LEN] = {
    0xad, 0x98, 0xa0, 0x36, 0xca, 0x2e, 0x2d, 0x92,
    0xf1, 0x27, 0x42, 0x33, 0xd6, 0x65, 0x13, 0xbc,
    0x80, 0x01, 0xbc, 0xc6, 0x9d, 0xd8, 0xb8, 0x5a,
    0x6a, 0x2a, 0x05, 0x90, 0x1b, 0x83, 0xe0, 0x63,
    0x40, 0xd0, 0x25, 0x30, 0xad, 0x8b, 0x93, 0xe4,
    0x1b, 0xa4, 0x1b, 0x1e, 0xeb, 0xad, 0x2f, 0xcf,
    0x20, 0x2e, 0xd7, 0x50, 0x05, 0x07, 0x5b, 0xb8,
    0x73, 0xfe, 0x54, 0xe0, 0x88, 0xa8, 0xe6, 0xf3
};
/* The SYSTEM metering policy's IDENTITY digest ("DNA.METPOLID.v1",
 * POLICY VERSION 2 — capacity season: seven scalar weights = 1,
 * max_block_env_bytes = 2*2^20 appended after w_write, ops 1..6
 * authoritative with weight 1) — the value SYSTEM's descriptor commits.
 * Oracle-derived, like the two above; the v1 value fad572e9…0537 is
 * DEAD. */
static const uint8_t KAT_METPOL_SYSTEM[DNA_DOM_HASH_LEN] = {
    0xdf, 0xeb, 0xb8, 0x2a, 0x55, 0x2d, 0xcd, 0xb0,
    0xac, 0x4e, 0x25, 0x81, 0x5e, 0x41, 0x84, 0x82,
    0xf0, 0x27, 0xa3, 0xce, 0x0c, 0xc8, 0x81, 0x09,
    0xc0, 0x45, 0xb7, 0x43, 0x9a, 0x9d, 0xce, 0x49,
    0xe3, 0x7c, 0x65, 0xc4, 0x32, 0x0a, 0xdb, 0xcd,
    0xf9, 0xdd, 0xca, 0x01, 0xd2, 0xcf, 0x05, 0x6d,
    0x32, 0xbc, 0x9c, 0x20, 0xa1, 0x59, 0x0f, 0xe6,
    0x7b, 0x35, 0x78, 0x66, 0xee, 0x27, 0xc2, 0xde
};

/* The checked-in descriptors' committed lists (S9 W4 truth). */
static const uint8_t SYS_TYPES_EXP[6]  = { 4, 5, 6, 7, 9, 10 };
static const uint8_t CORE_TYPES_EXP[6] = { 1, 2, 3, 11, 12, 13 };

int main(void) {
    /* ── 1. self-check ──────────────────────────────────────────────── */
    CHECK(nodus_witness_runtime_selfcheck() == 0, "selfcheck failed"); OK();

    size_t n = 0;
    const nodus_domain_runtime_t *t = nodus_runtime_builtin_table(&n);
    CHECK(t && n == 2, "builtin table shape"); OK();
    CHECK(t[0].domain_id == DNA_DOMAIN_SYSTEM &&
          t[1].domain_id == DNA_DOMAIN_CORE, "builtin ids"); OK();
    /* native auth season: the production execution surface is REAL —
     * both entries carry the shared auth_kind-1 hook, their compiled
     * read_plan/exec pair and a selfcheck-passing compiled adapter
     * (the pre-migration all-NULL pin is retired with the migration) */
    CHECK(t[0].auth == nodus_rt_auth_dsa87_v1 &&
          t[1].auth == nodus_rt_auth_dsa87_v1,
          "shared auth_kind-1 hook missing"); OK();
    CHECK(t[0].read_plan == nodus_rt_system_read_plan &&
          t[0].exec == nodus_rt_system_exec &&
          t[0].adapter == &NODUS_RT_SYSTEM_ADAPTER,
          "SYSTEM execution surface"); OK();
    CHECK(t[1].read_plan == nodus_rt_core_read_plan &&
          t[1].exec == nodus_rt_core_exec &&
          t[1].adapter == &NODUS_RT_CORE_ADAPTER,
          "CORE execution surface"); OK();
    CHECK(nodus_adapter_selfcheck(t[0].adapter) == 0 &&
          nodus_adapter_selfcheck(t[1].adapter) == 0,
          "production adapters fail their selfcheck"); OK();
    /* metering-policy coupling: SYSTEM carries THE block policy, its
     * identity digest is descriptor-committed and oracle-pinned; CORE
     * declares none (all-zero digest, NULL policy) */
    {
        uint8_t zero[DNA_DOM_HASH_LEN] = { 0 };
        uint8_t pd[64];
        CHECK(t[0].meter_policy != NULL, "SYSTEM policy missing"); OK();
        CHECK(dna_meter_policy_check(t[0].meter_policy) == 0,
              "SYSTEM policy seal invalid"); OK();
        CHECK(dna_meter_policy_digest(t[0].meter_policy, pd) == 0 &&
              memcmp(pd, KAT_METPOL_SYSTEM, 64) == 0,
              "SYSTEM policy identity != oracle pin"); OK();
        CHECK(memcmp(t[0].descriptor.meter_policy_digest,
                     KAT_METPOL_SYSTEM, 64) == 0,
              "SYSTEM descriptor does not commit the policy identity");
        OK();
        CHECK(t[1].meter_policy == NULL &&
              memcmp(t[1].descriptor.meter_policy_digest, zero, 64) == 0,
              "CORE must declare no metering policy"); OK();
        /* the policy digest and the local seal are DIFFERENT values
         * (different tags): the seal stays a local checksum */
        CHECK(memcmp(t[0].meter_policy->seal, pd, 64) != 0,
              "seal and identity digest collided"); OK();
    }
    /* the REAL runtime boundary: every runtime owns its state root;
     * only claim-capable runtimes carry the claim hooks (SYSTEM is
     * never a distribution target; CORE is) */
    CHECK(t[0].state_root != NULL && t[1].state_root != NULL,
          "state_root hooks present"); OK();
    CHECK(t[0].asset_check == NULL && t[0].claim_apply == NULL &&
          t[0].invariant == NULL, "SYSTEM: no claim/asset hooks"); OK();
    CHECK(t[1].asset_check != NULL && t[1].claim_apply != NULL &&
          t[1].invariant != NULL, "CORE: claim + invariant hooks"); OK();

    const nodus_domain_runtime_t *sys = &t[0], *core = &t[1];

    /* descriptor lists — the digest commits these, so pin them directly */
    CHECK(sys->descriptor.rule_count == 6 &&
          sys->descriptor.tx_type_count == 6, "SYSTEM descriptor counts");
    OK();
    CHECK(memcmp(sys->descriptor.tx_types, SYS_TYPES_EXP,
                 sizeof(SYS_TYPES_EXP)) == 0,
          "SYSTEM type list changed — S9 W4 must not touch SYSTEM"); OK();
    /* S9 W4: CORE owns the two V3 boundary types as well */
    CHECK(core->descriptor.rule_count == 6 &&
          core->descriptor.tx_type_count == 6, "CORE descriptor counts");
    OK();
    CHECK(memcmp(core->descriptor.tx_types, CORE_TYPES_EXP,
                 sizeof(CORE_TYPES_EXP)) == 0,
          "CORE type list != {1,2,3,11,12,13}"); OK();
    /* ascending order is load-bearing: rt_owns_type breaks early on a
     * greater element, and dna_ruleset_desc_hash rejects a non-ascending
     * list outright */
    for (size_t i = 1; i < core->descriptor.tx_type_count; i++) {
        CHECK(core->descriptor.tx_types[i - 1] < core->descriptor.tx_types[i],
              "CORE type list not strictly ascending");
    }
    OK();

    /* digests against the INDEPENDENT oracle (selfcheck only proves
     * pinned == fresh-C; this proves both == the oracle) */
    CHECK(memcmp(sys->ruleset_hash, KAT_RS_SYSTEM, DNA_DOM_HASH_LEN) == 0,
          "SYSTEM ruleset digest != the execution-season v2 oracle value");
    OK();
    CHECK(memcmp(core->ruleset_hash, KAT_RS_CORE, DNA_DOM_HASH_LEN) == 0,
          "CORE ruleset digest != the execution-season v2 oracle value");
    OK();
    CHECK(memcmp(sys->ruleset_hash, core->ruleset_hash,
                 DNA_DOM_HASH_LEN) != 0, "the two digests collided"); OK();

    /* ── 2. exact lookup + per-axis refusal ─────────────────────────── */
    const nodus_domain_runtime_t *hit;
    hit = nodus_runtime_lookup(DNA_DOMAIN_SYSTEM, DNA_RUNTIME_NATIVE_BUILTIN,
                               NODUS_DOMAIN_RUNTIME_ABI_V1, 2,
                               sys->ruleset_hash);
    CHECK(hit == sys, "SYSTEM exact lookup (ruleset v2)"); OK();
    /* the RETIRED SYSTEM ruleset v1 resolves NOTHING — old CHAIN_CONFIG
     * call-v1 legs name it and die here, never get reinterpreted */
    CHECK(nodus_runtime_lookup(DNA_DOMAIN_SYSTEM, DNA_RUNTIME_NATIVE_BUILTIN,
                               NODUS_DOMAIN_RUNTIME_ABI_V1, 1,
                               sys->ruleset_hash) == NULL,
          "retired SYSTEM ruleset v1 resolved"); OK();
    hit = nodus_runtime_lookup(DNA_DOMAIN_CORE, DNA_RUNTIME_NATIVE_BUILTIN,
                               NODUS_DOMAIN_RUNTIME_ABI_V1, 1,
                               core->ruleset_hash);
    CHECK(hit == core, "CORE exact lookup"); OK();

    /* unknown domain */
    CHECK(nodus_runtime_lookup(7, DNA_RUNTIME_NATIVE_BUILTIN,
                               NODUS_DOMAIN_RUNTIME_ABI_V1, 1,
                               core->ruleset_hash) == NULL,
          "unknown domain hit"); OK();
    /* wrong runtime kind (unknown kind 2 and invalid 0) */
    CHECK(nodus_runtime_lookup(DNA_DOMAIN_CORE, 2,
                               NODUS_DOMAIN_RUNTIME_ABI_V1, 1,
                               core->ruleset_hash) == NULL,
          "wrong kind hit"); OK();
    CHECK(nodus_runtime_lookup(DNA_DOMAIN_CORE, DNA_RUNTIME_INVALID,
                               NODUS_DOMAIN_RUNTIME_ABI_V1, 1,
                               core->ruleset_hash) == NULL,
          "invalid kind hit"); OK();
    /* wrong ABI */
    CHECK(nodus_runtime_lookup(DNA_DOMAIN_CORE, DNA_RUNTIME_NATIVE_BUILTIN,
                               2, 1, core->ruleset_hash) == NULL,
          "wrong ABI hit"); OK();
    /* wrong ruleset version — no "closest", no "latest" */
    CHECK(nodus_runtime_lookup(DNA_DOMAIN_CORE, DNA_RUNTIME_NATIVE_BUILTIN,
                               NODUS_DOMAIN_RUNTIME_ABI_V1, 2,
                               core->ruleset_hash) == NULL,
          "wrong ruleset version hit"); OK();
    /* one-bit ruleset-hash mismatch */
    uint8_t flipped[DNA_DOM_HASH_LEN];
    memcpy(flipped, core->ruleset_hash, DNA_DOM_HASH_LEN);
    flipped[0] ^= 0x01;
    CHECK(nodus_runtime_lookup(DNA_DOMAIN_CORE, DNA_RUNTIME_NATIVE_BUILTIN,
                               NODUS_DOMAIN_RUNTIME_ABI_V1, 1,
                               flipped) == NULL,
          "one-bit hash mismatch hit"); OK();
    memcpy(flipped, core->ruleset_hash, DNA_DOM_HASH_LEN);
    flipped[DNA_DOM_HASH_LEN - 1] ^= 0x80;
    CHECK(nodus_runtime_lookup(DNA_DOMAIN_CORE, DNA_RUNTIME_NATIVE_BUILTIN,
                               NODUS_DOMAIN_RUNTIME_ABI_V1, 1,
                               flipped) == NULL,
          "last-bit hash mismatch hit"); OK();

    /* ── 3. admission ───────────────────────────────────────────────── */
    CHECK(core->admit(core, 1, DNA_POOL_NONE) == 0, "SPEND admit"); OK();
    CHECK(core->admit(core, 2, DNA_POOL_NONE) == 0, "BURN admit"); OK();
    CHECK(core->admit(core, 3, DNA_POOL_NONE) == 0, "TOKEN_CREATE admit");
    OK();
    CHECK(sys->admit(sys, 4, DNA_POOL_NONE) == 0, "STAKE admit"); OK();
    CHECK(sys->admit(sys, 10, DNA_POOL_NONE) == 0, "CHAIN_CONFIG admit");
    OK();

    /* foreign types reject (ownership is per-domain, never global) */
    CHECK(core->admit(core, 4, DNA_POOL_NONE) != 0,
          "CORE admits SYSTEM type"); OK();
    CHECK(sys->admit(sys, 1, DNA_POOL_NONE) != 0,
          "SYSTEM admits CORE type"); OK();
    /* unassigned + retired types reject everywhere (UNOWNED leg — 12/13
     * moved OUT of this group in S9 W4: they are owned and stopped) */
    CHECK(core->admit(core, 8, DNA_POOL_NONE) != 0, "retired 8 admitted");
    OK();
    CHECK(core->admit(core, 14, DNA_POOL_NONE) == -1, "type 14 admitted");
    OK();
    CHECK(core->admit(core, 14, DNAC_SHIELDED_POOL_V1) == -1,
          "type 14 admitted with pool"); OK();
    CHECK(sys->admit(sys, 0, DNA_POOL_NONE) != 0, "GENESIS via runtime");
    OK();

    /* pool rules: nonzero pool for a transparent type rejects */
    CHECK(core->admit(core, 1, DNAC_SHIELDED_POOL_V1) != 0,
          "SPEND with pool admitted"); OK();
    CHECK(sys->admit(sys, 4, 1) != 0, "STAKE with pool admitted"); OK();

    /* HARD STOP: 11, 12 and 13 are OWNED by CORE and reject with ANY pool
     * value. The pool leg must never become an accidental admit path —
     * all three carry DNAC_SHIELDED_POOL_V1 in the target design. */
    CHECK(core->admit(core, 11, DNAC_SHIELDED_POOL_V1) == -1,
          "TYPE 11 ADMITTED — C3 stop broken"); OK();
    CHECK(core->admit(core, 11, DNA_POOL_NONE) == -1,
          "TYPE 11 ADMITTED (pool 0) — C3 stop broken"); OK();
    CHECK(core->admit(core, 12, DNAC_SHIELDED_POOL_V1) == -1,
          "TYPE 12 ADMITTED — activation stop broken"); OK();
    CHECK(core->admit(core, 12, DNA_POOL_NONE) == -1,
          "TYPE 12 ADMITTED (pool 0) — activation stop broken"); OK();
    CHECK(core->admit(core, 13, DNAC_SHIELDED_POOL_V1) == -1,
          "TYPE 13 ADMITTED — activation stop broken"); OK();
    CHECK(core->admit(core, 13, DNA_POOL_NONE) == -1,
          "TYPE 13 ADMITTED (pool 0) — activation stop broken"); OK();
    /* an arbitrary junk pool id must not slip past either */
    CHECK(core->admit(core, 12, 0xFFFFFFFFu) == -1,
          "TYPE 12 ADMITTED (junk pool)"); OK();
    CHECK(core->admit(core, 13, 0xFFFFFFFFu) == -1,
          "TYPE 13 ADMITTED (junk pool)"); OK();

    /* ── 4. cost declarations ───────────────────────────────────────── */
    uint32_t cost = 0;
    CHECK(core->tx_cost(core, 1, &cost) == 0 && cost == 1, "SPEND cost");
    OK();
    CHECK(core->tx_cost(core, 3, &cost) == 0 && cost == 2, "TC cost"); OK();
    CHECK(core->tx_cost(core, 11, &cost) == 0 && cost == 100,
          "shielded declared cost"); OK();
    /* S9 W4 — declared-but-unreachable, same STARK batch-verify class as
     * 11; 12 carries one extra unit for its transparent signature leg */
    CHECK(core->tx_cost(core, 12, &cost) == 0 && cost == 101,
          "SHIELD declared cost"); OK();
    CHECK(core->tx_cost(core, 13, &cost) == 0 && cost == 100,
          "UNSHIELD declared cost"); OK();
    CHECK(sys->tx_cost(sys, 10, &cost) == 0 && cost == 2, "CC cost"); OK();
    CHECK(sys->tx_cost(sys, 4, &cost) == 0 && cost == 1, "STAKE cost"); OK();
    /* an unowned type has NO cost — fail-closed, no default. tx_cost is
     * therefore the ownership oracle: it is the ONLY hook that separates
     * "CORE owns this type" from "CORE rejects this type", since admit
     * returns -1 for owned-and-stopped and for unowned alike. */
    CHECK(core->tx_cost(core, 4, &cost) != 0, "foreign type cost"); OK();
    CHECK(core->tx_cost(core, 8, &cost) != 0, "retired type 8 cost"); OK();
    CHECK(core->tx_cost(core, 14, &cost) != 0,
          "type 14 costed — CORE must NOT own it"); OK();
    CHECK(sys->tx_cost(sys, 12, &cost) != 0,
          "SYSTEM costed type 12 — ownership is per-domain"); OK();

    /* ── 5. test-only third runtime (caller-supplied table) ─────────── */
    static const uint32_t T3_RULES[1] = { 1 };
    static const uint8_t T3_TYPES[2] = { 20, 21 };
    nodus_domain_runtime_t ext[3];
    memcpy(&ext[0], sys, sizeof(*sys));
    memcpy(&ext[1], core, sizeof(*core));
    memset(&ext[2], 0, sizeof(ext[2]));
    ext[2].domain_id = 7;
    ext[2].runtime_kind = DNA_RUNTIME_NATIVE_BUILTIN;
    ext[2].runtime_abi = NODUS_DOMAIN_RUNTIME_ABI_V1;
    ext[2].ruleset_version = 1;
    ext[2].descriptor.descriptor_version = DNA_RULESET_DESC_VERSION;
    ext[2].descriptor.domain_id = 7;
    memcpy(ext[2].descriptor.name, "TEST_DOMAIN", 11);
    ext[2].descriptor.runtime_abi = NODUS_DOMAIN_RUNTIME_ABI_V1;
    ext[2].descriptor.ruleset_version = 1;
    ext[2].descriptor.rule_count = 1;
    ext[2].descriptor.rule_ids = T3_RULES;
    ext[2].descriptor.tx_type_count = 2;
    ext[2].descriptor.tx_types = T3_TYPES;
    CHECK(dna_ruleset_desc_hash(&ext[2].descriptor,
                                ext[2].ruleset_hash) == 0,
          "third descriptor hash"); OK();
    ext[2].admit = ext[1].admit;          /* the shared ownership shape    */
    ext[2].tx_cost = ext[1].tx_cost;

    const nodus_domain_runtime_t *third =
        nodus_runtime_lookup_in(ext, 3, 7, DNA_RUNTIME_NATIVE_BUILTIN,
                                NODUS_DOMAIN_RUNTIME_ABI_V1, 1,
                                ext[2].ruleset_hash);
    CHECK(third == &ext[2], "third runtime lookup"); OK();
    CHECK(third->admit(third, 20, DNA_POOL_NONE) == 0,
          "third runtime admit own type"); OK();
    CHECK(third->admit(third, 1, DNA_POOL_NONE) != 0,
          "third runtime admits foreign type"); OK();

    /* the PRODUCTION table must never contain it */
    CHECK(nodus_runtime_lookup(7, DNA_RUNTIME_NATIVE_BUILTIN,
                               NODUS_DOMAIN_RUNTIME_ABI_V1, 1,
                               ext[2].ruleset_hash) == NULL,
          "test-only runtime leaked into production table"); OK();

    printf("test_domain_runtime: ALL %d checks passed\n", g_checks);
    return 0;
}
