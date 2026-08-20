/**
 * Nodus — Ledger V2 S4: NATIVE_BUILTIN runtime table tests (INACTIVE layer).
 *
 * Sections:
 *   1. Self-check: pinned digests == fresh C recomputation; table shape;
 *      S5 hooks absent; the checked-in descriptors' rule/type lists and
 *      both ruleset digests pinned against the INDEPENDENT python oracle
 *      (S9 W4 re-derivation — SYSTEM's digest MUST NOT move).
 *   2. Exact-tuple lookup: SYSTEM and DNA_CORE hit at the CURRENT
 *      ruleset version (O11: both are 3); then every axis mutated one at
 *      a time MUST miss — unknown domain, wrong kind, wrong ABI, EVERY
 *      retired ruleset version (v1 and v2, both domains), a future
 *      version, one-bit ruleset-hash flip.
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
    /* O15F re-derivation: SYSTEM ruleset_version 4 → 5. The V2-lane
     * CHAIN_CONFIG (runtime op 6) now narrows the accepted
     * TARGET_ACTIVE_COUNT range to [7..30] (reject 31), which changes the
     * accepted runtime-op-6 semantics; the version advances and the
     * digest moves by construction (the descriptor commits
     * ruleset_version; the rule list {1..6}, the type list
     * {4,5,6,7,9,10} and the meter-policy digest are all byte-identical
     * to v4 — the CC range is enforced in the HOOK, not the descriptor).
     * The retired SYSTEM v4 (like v1/v2/v3) resolves NOTHING. Oracle:
     * scratchpad o15f_ruleset_oracle.py, whose control legs reproduced
     * BOTH shipped pins (SYSTEM v4 4fe76fed…7736, CORE v3 ed4b1bcd…4437)
     * byte-exactly before this value was accepted. The O12 value
     * 4fe76fed…7736 is DEAD. */
    0x0e, 0xfc, 0x48, 0xbf, 0x13, 0xb8, 0xda, 0xd5,
    0x3f, 0x41, 0xb4, 0xe7, 0x62, 0x3c, 0xab, 0xed,
    0x26, 0x2d, 0x94, 0xb3, 0xbd, 0xae, 0x2a, 0x1a,
    0x07, 0xf7, 0xe0, 0xc9, 0x39, 0x4c, 0x9f, 0x6c,
    0xf4, 0xc5, 0x09, 0x6f, 0x98, 0x53, 0xd9, 0xf2,
    0xb7, 0xae, 0x8d, 0x08, 0x45, 0xea, 0xac, 0xdb,
    0xf6, 0xd8, 0x59, 0xdf, 0x34, 0xc5, 0xb3, 0xda,
    0xd1, 0x89, 0x6c, 0x16, 0xb3, 0xf9, 0xf3, 0x50
};
static const uint8_t KAT_RS_CORE[DNA_DOM_HASH_LEN] = {
    /* O11 — CORE ruleset_version 3: the rule list GREW to {1..7}
     * (DNA_CORERULE_SYSFUND, the staking funding/release leg) and that
     * op is executable. Same oracle + control legs as the SYSTEM pin;
     * the burn-season value 746f584a…67a1 is DEAD. */
    0xed, 0x4b, 0x1b, 0xcd, 0xf0, 0xe8, 0xf7, 0x8f,
    0x0b, 0x64, 0x98, 0x5e, 0x42, 0xd4, 0x1d, 0x51,
    0x81, 0xed, 0xd5, 0xd4, 0x85, 0x94, 0xbc, 0xeb,
    0x73, 0xbf, 0x5e, 0xfb, 0x6a, 0xda, 0x08, 0x38,
    0x8d, 0x6f, 0xb6, 0xba, 0x04, 0x92, 0xf8, 0xbd,
    0xca, 0x21, 0x2a, 0x5d, 0xda, 0x87, 0x79, 0xe7,
    0x45, 0x13, 0xc5, 0x21, 0x0b, 0xc4, 0xba, 0xa2,
    0xf7, 0x0b, 0xf3, 0x8c, 0xb2, 0x63, 0x44, 0x37
};
/* The SYSTEM metering policy's IDENTITY digest ("DNA.METPOLID.v1",
 * POLICY VERSION 2 — seven scalar weights = 1, max_block_env_bytes =
 * 2*2^20 after w_write, and — since O11 — ops 1..**7** authoritative
 * with weight 1, because DNA_CORERULE_SYSFUND must be priced) — the
 * value SYSTEM's descriptor commits. Oracle-derived, like the two
 * above; the capacity-season value dfebb82a…c2de is DEAD. */
static const uint8_t KAT_METPOL_SYSTEM[DNA_DOM_HASH_LEN] = {
    0x8d, 0x03, 0x8f, 0x1e, 0xc6, 0x08, 0xbe, 0x54,
    0x7b, 0xf9, 0x8a, 0xfe, 0x2d, 0xf0, 0x53, 0x2b,
    0x4a, 0x94, 0xa7, 0xa0, 0x42, 0xa9, 0xd9, 0xd8,
    0x6b, 0x7a, 0x0f, 0xb1, 0xab, 0x51, 0xed, 0xaf,
    0xbc, 0x43, 0x64, 0xdc, 0x38, 0x91, 0xc3, 0x6b,
    0xfb, 0xc4, 0x43, 0x32, 0x2f, 0x2a, 0x3b, 0x0b,
    0x44, 0xc8, 0x23, 0x16, 0xbd, 0x78, 0x42, 0xfd,
    0x7f, 0xfb, 0xec, 0x2d, 0x19, 0xf1, 0xf5, 0xcc
};

/* The RETIRED SYSTEM v4 ruleset digest (the O12 pin, 4fe76fed…7736),
 * kept ONLY so the retired-tuple lookup below proves the EXACT identity
 * an old committed v4 SYSTEM leg would name now resolves NOTHING — O15F
 * narrowed op-6 TARGET_ACTIVE to [7..30] and advanced SYSTEM to v5. This
 * is NOT a live pin: the compiled table never carries it. */
static const uint8_t RETIRED_RS_SYSTEM_V4[DNA_DOM_HASH_LEN] = {
    0x4f, 0xe7, 0x6f, 0xed, 0x43, 0xef, 0x37, 0x25,
    0x94, 0x71, 0x3e, 0x97, 0xf6, 0xff, 0xf4, 0x68,
    0x4d, 0xba, 0x3d, 0x37, 0x8c, 0xa2, 0x32, 0x01,
    0xfe, 0xd6, 0x31, 0x4b, 0x81, 0x47, 0xe1, 0xce,
    0x57, 0x1a, 0x4f, 0xec, 0xd8, 0x17, 0x0b, 0xfa,
    0xd5, 0x5c, 0xb6, 0x86, 0x16, 0x2e, 0xbb, 0x1d,
    0xf4, 0x62, 0xa4, 0xf2, 0x44, 0xbc, 0xf9, 0xc2,
    0x38, 0x87, 0xeb, 0x7d, 0x14, 0x7a, 0x77, 0x36
};

/* The checked-in descriptors' committed lists (S9 W4 truth; O11 did NOT
 * move either list — runtime_op and tx_type are different axes). */
static const uint8_t SYS_TYPES_EXP[6]  = { 4, 5, 6, 7, 9, 10 };
static const uint8_t CORE_TYPES_EXP[6] = { 1, 2, 3, 11, 12, 13 };
/* The CORE rule list the O11 digest commits: {1..7}, strictly ascending
 * (dna_ruleset_desc_hash refuses anything else). */
static const uint32_t CORE_RULES_EXP[7] = { 1, 2, 3, 4, 5, 6, 7 };
static const uint32_t SYS_RULES_EXP[6]  = { 1, 2, 3, 4, 5, 6 };
/* The compiled ruleset versions this build ships. */
#define SYS_RSV  5u    /* O15F: op 6 CHAIN_CONFIG TARGET_ACTIVE range [7..30] */
#define CORE_RSV 3u

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
          "SYSTEM type list changed — S9 W4 / O11 must not touch it");
    OK();
    CHECK(memcmp(sys->descriptor.rule_ids, SYS_RULES_EXP,
                 sizeof(SYS_RULES_EXP)) == 0,
          "SYSTEM rule list != {1..6} — O11 enables op 1, it adds none");
    OK();
    /* S9 W4: CORE owns the two V3 boundary types as well.
     * O11: CORE's RULE list grew to seven (DNA_CORERULE_SYSFUND); its
     * TYPE list did not move — the funding leg carries no legacy type. */
    CHECK(core->descriptor.rule_count == 7 &&
          core->descriptor.tx_type_count == 6, "CORE descriptor counts");
    OK();
    CHECK(memcmp(core->descriptor.rule_ids, CORE_RULES_EXP,
                 sizeof(CORE_RULES_EXP)) == 0,
          "CORE rule list != {1..7} (O11 appended SYSFUND)"); OK();
    CHECK(memcmp(core->descriptor.tx_types, CORE_TYPES_EXP,
                 sizeof(CORE_TYPES_EXP)) == 0,
          "CORE type list != {1,2,3,11,12,13}"); OK();
    /* the compiled versions the whole slice hangs from */
    CHECK(sys->ruleset_version == SYS_RSV &&
          sys->descriptor.ruleset_version == SYS_RSV,
          "SYSTEM ruleset_version != 5 (O15F)"); OK();
    CHECK(core->ruleset_version == CORE_RSV &&
          core->descriptor.ruleset_version == CORE_RSV,
          "CORE ruleset_version != 3 (O11)"); OK();
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
                               NODUS_DOMAIN_RUNTIME_ABI_V1, SYS_RSV,
                               sys->ruleset_hash);
    CHECK(hit == sys, "SYSTEM exact lookup (ruleset v5)"); OK();
    /* EVERY retired SYSTEM ruleset resolves NOTHING — a leg naming v1
     * (CHAIN_CONFIG call v1), v2 (call v2, STAKE not yet executable),
     * v3 (O11 stake lifecycle, VALIDATOR_UPDATE not yet executable) or
     * v4 (O12; CC TARGET_ACTIVE range not yet narrowed) dies here and is
     * never reinterpreted under the current rules */
    CHECK(nodus_runtime_lookup(DNA_DOMAIN_SYSTEM, DNA_RUNTIME_NATIVE_BUILTIN,
                               NODUS_DOMAIN_RUNTIME_ABI_V1, 1,
                               sys->ruleset_hash) == NULL,
          "retired SYSTEM ruleset v1 resolved"); OK();
    CHECK(nodus_runtime_lookup(DNA_DOMAIN_SYSTEM, DNA_RUNTIME_NATIVE_BUILTIN,
                               NODUS_DOMAIN_RUNTIME_ABI_V1, 2,
                               sys->ruleset_hash) == NULL,
          "retired SYSTEM ruleset v2 resolved (O11)"); OK();
    CHECK(nodus_runtime_lookup(DNA_DOMAIN_SYSTEM, DNA_RUNTIME_NATIVE_BUILTIN,
                               NODUS_DOMAIN_RUNTIME_ABI_V1, 3,
                               sys->ruleset_hash) == NULL,
          "retired SYSTEM ruleset v3 resolved (O12)"); OK();
    CHECK(nodus_runtime_lookup(DNA_DOMAIN_SYSTEM, DNA_RUNTIME_NATIVE_BUILTIN,
                               NODUS_DOMAIN_RUNTIME_ABI_V1, 4,
                               sys->ruleset_hash) == NULL,
          "retired SYSTEM ruleset v4 (version axis) resolved (O15F)"); OK();
    /* the LOAD-BEARING retired-v4 miss: the EXACT tuple an old committed
     * v4 SYSTEM leg names — version 4 AND its real O12 digest — resolves
     * NOTHING (the version-axis probe above passes vacuously because the
     * live hash moved to v5; this one names the true retired identity) */
    CHECK(nodus_runtime_lookup(DNA_DOMAIN_SYSTEM, DNA_RUNTIME_NATIVE_BUILTIN,
                               NODUS_DOMAIN_RUNTIME_ABI_V1, 4,
                               RETIRED_RS_SYSTEM_V4) == NULL,
          "retired SYSTEM ruleset v4 (exact tuple) resolved (O15F)"); OK();
    hit = nodus_runtime_lookup(DNA_DOMAIN_CORE, DNA_RUNTIME_NATIVE_BUILTIN,
                               NODUS_DOMAIN_RUNTIME_ABI_V1, CORE_RSV,
                               core->ruleset_hash);
    CHECK(hit == core, "CORE exact lookup (ruleset v3)"); OK();
    /* likewise for CORE: v1 (pre-burn) and v2 (pre-SYSFUND) are dead */
    CHECK(nodus_runtime_lookup(DNA_DOMAIN_CORE, DNA_RUNTIME_NATIVE_BUILTIN,
                               NODUS_DOMAIN_RUNTIME_ABI_V1, 1,
                               core->ruleset_hash) == NULL,
          "retired CORE ruleset v1 resolved"); OK();
    CHECK(nodus_runtime_lookup(DNA_DOMAIN_CORE, DNA_RUNTIME_NATIVE_BUILTIN,
                               NODUS_DOMAIN_RUNTIME_ABI_V1, 2,
                               core->ruleset_hash) == NULL,
          "retired CORE ruleset v2 resolved (O11)"); OK();

    /* unknown domain */
    CHECK(nodus_runtime_lookup(7, DNA_RUNTIME_NATIVE_BUILTIN,
                               NODUS_DOMAIN_RUNTIME_ABI_V1, CORE_RSV,
                               core->ruleset_hash) == NULL,
          "unknown domain hit"); OK();
    /* wrong runtime kind (unknown kind 2 and invalid 0) */
    CHECK(nodus_runtime_lookup(DNA_DOMAIN_CORE, 2,
                               NODUS_DOMAIN_RUNTIME_ABI_V1, CORE_RSV,
                               core->ruleset_hash) == NULL,
          "wrong kind hit"); OK();
    CHECK(nodus_runtime_lookup(DNA_DOMAIN_CORE, DNA_RUNTIME_INVALID,
                               NODUS_DOMAIN_RUNTIME_ABI_V1, CORE_RSV,
                               core->ruleset_hash) == NULL,
          "invalid kind hit"); OK();
    /* wrong ABI */
    CHECK(nodus_runtime_lookup(DNA_DOMAIN_CORE, DNA_RUNTIME_NATIVE_BUILTIN,
                               2, CORE_RSV, core->ruleset_hash) == NULL,
          "wrong ABI hit"); OK();
    /* wrong (future) ruleset version — no "closest", no "latest" */
    CHECK(nodus_runtime_lookup(DNA_DOMAIN_CORE, DNA_RUNTIME_NATIVE_BUILTIN,
                               NODUS_DOMAIN_RUNTIME_ABI_V1, CORE_RSV + 1,
                               core->ruleset_hash) == NULL,
          "wrong ruleset version hit"); OK();
    /* one-bit ruleset-hash mismatch */
    uint8_t flipped[DNA_DOM_HASH_LEN];
    memcpy(flipped, core->ruleset_hash, DNA_DOM_HASH_LEN);
    flipped[0] ^= 0x01;
    CHECK(nodus_runtime_lookup(DNA_DOMAIN_CORE, DNA_RUNTIME_NATIVE_BUILTIN,
                               NODUS_DOMAIN_RUNTIME_ABI_V1, CORE_RSV,
                               flipped) == NULL,
          "one-bit hash mismatch hit"); OK();
    memcpy(flipped, core->ruleset_hash, DNA_DOM_HASH_LEN);
    flipped[DNA_DOM_HASH_LEN - 1] ^= 0x80;
    CHECK(nodus_runtime_lookup(DNA_DOMAIN_CORE, DNA_RUNTIME_NATIVE_BUILTIN,
                               NODUS_DOMAIN_RUNTIME_ABI_V1, CORE_RSV,
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
