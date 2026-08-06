/**
 * Nodus — Ledger V2 S4: NATIVE_BUILTIN runtime table tests (INACTIVE layer).
 *
 * Sections:
 *   1. Self-check: pinned digests == fresh C recomputation; table shape;
 *      S5 hooks absent.
 *   2. Exact-tuple lookup: SYSTEM and DNA_CORE hit; then every axis
 *      mutated one at a time MUST miss — unknown domain, wrong kind,
 *      wrong ABI, wrong ruleset version, one-bit ruleset-hash flip.
 *   3. Admission: owned transparent types admit with pool 0; foreign type
 *      rejects; nonzero pool rejects; TYPE 11 REJECTS (C3 hard stop).
 *   4. Cost declarations: pinned values; unowned type has NO cost.
 *   5. Test-only THIRD runtime in a caller-supplied table: lookup_in hits
 *      it, the production table never contains it, and supporting it
 *      required zero changes to any consensus structure.
 *
 * @file test_domain_runtime.c
 */

#include "../src/witness/nodus_witness_runtime.h"

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

int main(void) {
    /* ── 1. self-check ──────────────────────────────────────────────── */
    CHECK(nodus_witness_runtime_selfcheck() == 0, "selfcheck failed"); OK();

    size_t n = 0;
    const nodus_domain_runtime_t *t = nodus_runtime_builtin_table(&n);
    CHECK(t && n == 2, "builtin table shape"); OK();
    CHECK(t[0].domain_id == DNA_DOMAIN_SYSTEM &&
          t[1].domain_id == DNA_DOMAIN_CORE, "builtin ids"); OK();
    CHECK(t[0].apply_reserved == NULL && t[1].apply_reserved == NULL,
          "S9 apply hook must stay NULL"); OK();
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

    /* ── 2. exact lookup + per-axis refusal ─────────────────────────── */
    const nodus_domain_runtime_t *hit;
    hit = nodus_runtime_lookup(DNA_DOMAIN_SYSTEM, DNA_RUNTIME_NATIVE_BUILTIN,
                               NODUS_DOMAIN_RUNTIME_ABI_V1, 1,
                               sys->ruleset_hash);
    CHECK(hit == sys, "SYSTEM exact lookup"); OK();
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
    /* unassigned + retired types reject everywhere */
    CHECK(core->admit(core, 8, DNA_POOL_NONE) != 0, "retired 8 admitted");
    OK();
    CHECK(core->admit(core, 12, DNA_POOL_NONE) != 0, "type 12 admitted");
    OK();
    CHECK(core->admit(core, 13, DNA_POOL_NONE) != 0, "type 13 admitted");
    OK();
    CHECK(core->admit(core, 14, DNA_POOL_NONE) != 0, "type 14 admitted");
    OK();
    CHECK(sys->admit(sys, 0, DNA_POOL_NONE) != 0, "GENESIS via runtime");
    OK();

    /* pool rules: nonzero pool for a transparent type rejects */
    CHECK(core->admit(core, 1, DNAC_SHIELDED_POOL_V1) != 0,
          "SPEND with pool admitted"); OK();
    CHECK(sys->admit(sys, 4, 1) != 0, "STAKE with pool admitted"); OK();

    /* C3 HARD STOP: type 11 rejects with ANY pool value */
    CHECK(core->admit(core, 11, DNAC_SHIELDED_POOL_V1) != 0,
          "TYPE 11 ADMITTED — C3 stop broken"); OK();
    CHECK(core->admit(core, 11, DNA_POOL_NONE) != 0,
          "TYPE 11 ADMITTED (pool 0) — C3 stop broken"); OK();

    /* ── 4. cost declarations ───────────────────────────────────────── */
    uint32_t cost = 0;
    CHECK(core->tx_cost(core, 1, &cost) == 0 && cost == 1, "SPEND cost");
    OK();
    CHECK(core->tx_cost(core, 3, &cost) == 0 && cost == 2, "TC cost"); OK();
    CHECK(core->tx_cost(core, 11, &cost) == 0 && cost == 100,
          "shielded declared cost"); OK();
    CHECK(sys->tx_cost(sys, 10, &cost) == 0 && cost == 2, "CC cost"); OK();
    CHECK(sys->tx_cost(sys, 4, &cost) == 0 && cost == 1, "STAKE cost"); OK();
    /* an unowned type has NO cost — fail-closed, no default */
    CHECK(core->tx_cost(core, 4, &cost) != 0, "foreign type cost"); OK();
    CHECK(core->tx_cost(core, 12, &cost) != 0, "type 12 cost"); OK();

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
