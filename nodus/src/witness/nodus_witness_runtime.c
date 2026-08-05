/**
 * @file nodus_witness_runtime.c
 * @brief Ledger V2 Season 4 — compiled NATIVE_BUILTIN runtime table
 *        implementation (INACTIVE).
 *
 * See nodus_witness_runtime.h. The pinned ruleset digests below were
 * produced by the INDEPENDENT python3 oracle (scratchpad s4_oracle.py,
 * KAT_RS_SYSTEM / KAT_RS_CORE) over the canonical descriptor layouts in
 * shared/dnac/domain_wire.h — and nodus_witness_runtime_selfcheck()
 * re-derives them through the C encoder on every run, so oracle, encoder
 * and table can never drift apart silently.
 *
 * @file nodus_witness_runtime.c
 */

#include "nodus_witness_runtime.h"

#include <string.h>

/* ── Checked-in canonical descriptors (pure data) ───────────────────── */

static const uint32_t SYS_RULES[6] = {
    DNA_SYSRULE_STAKE, DNA_SYSRULE_DELEGATE, DNA_SYSRULE_UNSTAKE,
    DNA_SYSRULE_UNDELEGATE, DNA_SYSRULE_VALIDATOR_UPDATE,
    DNA_SYSRULE_CHAIN_CONFIG
};
static const uint8_t SYS_TYPES[6] = { 4, 5, 6, 7, 9, 10 };

static const uint32_t CORE_RULES[4] = {
    DNA_CORERULE_SPEND, DNA_CORERULE_BURN, DNA_CORERULE_TOKEN_CREATE,
    DNA_CORERULE_SHIELDED_C3_REJECT
};
static const uint8_t CORE_TYPES[4] = { 1, 2, 3, 11 };

/* Pinned digests — python3 oracle KAT_RS_SYSTEM / KAT_RS_CORE. */
static const uint8_t SYS_RULESET_HASH[DNA_DOM_HASH_LEN] = {
    0xf2, 0xdc, 0xde, 0xfa, 0x62, 0x38, 0x38, 0xd5,
    0xe2, 0x3f, 0x71, 0xb6, 0x55, 0x72, 0xab, 0xb5,
    0x2b, 0xd3, 0xa1, 0x91, 0xfd, 0x30, 0x72, 0x77,
    0x7e, 0x4b, 0xdb, 0xef, 0x4b, 0xcd, 0xdc, 0x07,
    0x46, 0x0a, 0x9d, 0xe1, 0xf0, 0xeb, 0x2a, 0xba,
    0x21, 0xd2, 0x1f, 0xed, 0xdd, 0x4b, 0x2b, 0xcb,
    0xd2, 0xe7, 0x79, 0x00, 0xae, 0x8d, 0xb2, 0x71,
    0x26, 0x2c, 0xc8, 0x9e, 0x40, 0x13, 0x4c, 0xce
};
static const uint8_t CORE_RULESET_HASH[DNA_DOM_HASH_LEN] = {
    0x13, 0xbc, 0x5f, 0xa9, 0x69, 0x20, 0xf8, 0x8f,
    0xcd, 0x5d, 0x3d, 0xe8, 0xee, 0x2f, 0x37, 0xcd,
    0x20, 0xc5, 0xe7, 0xd0, 0x2d, 0x9d, 0x9c, 0xc5,
    0xed, 0xd8, 0x9a, 0x8e, 0xd3, 0x93, 0x2c, 0x04,
    0x72, 0x7c, 0x2f, 0xdb, 0xf3, 0xf2, 0x12, 0x95,
    0x8d, 0x62, 0x8b, 0xbe, 0xaf, 0x08, 0x06, 0xda,
    0x1c, 0xd6, 0x7c, 0xb7, 0xc2, 0xda, 0xc0, 0x64,
    0x1e, 0xb9, 0xbd, 0x56, 0x70, 0x66, 0x9a, 0xda
};

/* ── Function tables ────────────────────────────────────────────────── */

/* Both runtimes share one shape: a type is admissible iff the descriptor
 * owns it AND the pool rule for that type holds. The ONLY pool-carrying
 * type in this release is 11 (shielded, pool DNAC_SHIELDED_POOL_V1) —
 * and 11 is consensus-REJECTED until C3, enforced HERE as well as in the
 * legacy admission gate, so the C3 stop cannot be bypassed through the
 * new boundary. */
static int rt_owns_type(const nodus_domain_runtime_t *rt, uint8_t tx_type) {
    const dna_ruleset_desc_t *d = &rt->descriptor;
    for (size_t i = 0; i < d->tx_type_count; i++) {
        if (d->tx_types[i] == tx_type) return 1;
        if (d->tx_types[i] > tx_type) break;      /* ascending list        */
    }
    return 0;
}

static int rt_admit_common(const nodus_domain_runtime_t *rt,
                           uint8_t tx_type, uint32_t pool_id) {
    if (!rt || !rt_owns_type(rt, tx_type)) return -1;
    if (tx_type == 11) {
        /* C3 HARD STOP: type 11 stays consensus-rejected. The pool rule is
         * stated for completeness but unreachable past the stop. */
        (void)pool_id;
        return -1;
    }
    if (pool_id != DNA_POOL_NONE) return -1;      /* no other type pools   */
    return 0;
}

/* Deterministic work-unit declarations (S4 JUDGMENT values, pinned by
 * test_domain_runtime.c). Dominated by Dilithium5 verifies today. */
static int sys_cost(const nodus_domain_runtime_t *rt,
                    uint8_t tx_type, uint32_t *cost_out) {
    if (!rt || !cost_out || !rt_owns_type(rt, tx_type)) return -1;
    switch (tx_type) {
        case 10: *cost_out = 2; return 0;  /* CHAIN_CONFIG: quorum of sigs */
        default: *cost_out = 1; return 0;  /* STAKE/DELEGATE/UNSTAKE/...   */
    }
}

static int core_cost(const nodus_domain_runtime_t *rt,
                     uint8_t tx_type, uint32_t *cost_out) {
    if (!rt || !cost_out || !rt_owns_type(rt, tx_type)) return -1;
    switch (tx_type) {
        case 3:  *cost_out = 2;   return 0;   /* TOKEN_CREATE              */
        case 11: *cost_out = 100; return 0;   /* STARK batch verify class —
                                               * declared, unreachable
                                               * until C3 (admit rejects) */
        default: *cost_out = 1;   return 0;   /* SPEND / BURN              */
    }
}

/* ── The compiled production table (SYSTEM + DNA_CORE, ascending) ───── */

static const nodus_domain_runtime_t BUILTIN[] = {
    {
        .domain_id       = DNA_DOMAIN_SYSTEM,
        .runtime_kind    = DNA_RUNTIME_NATIVE_BUILTIN,
        .runtime_abi     = NODUS_DOMAIN_RUNTIME_ABI_V1,
        .ruleset_version = 1,
        .ruleset_hash    = { 0 },   /* set via memcpy-free static init below
                                     * is impossible for a named array —
                                     * selfcheck compares against the pinned
                                     * constant instead; lookup uses the
                                     * SYS_RULESET_HASH accessor path. */
        .descriptor = {
            .descriptor_version = DNA_RULESET_DESC_VERSION,
            .domain_id = DNA_DOMAIN_SYSTEM,
            .name = "SYSTEM",
            .runtime_abi = NODUS_DOMAIN_RUNTIME_ABI_V1,
            .ruleset_version = 1,
            .rule_count = 6, .rule_ids = SYS_RULES,
            .tx_type_count = 6, .tx_types = SYS_TYPES
        },
        .admit = rt_admit_common,
        .tx_cost = sys_cost,
        .apply_reserved = NULL,
        .root_reserved  = NULL
    },
    {
        .domain_id       = DNA_DOMAIN_CORE,
        .runtime_kind    = DNA_RUNTIME_NATIVE_BUILTIN,
        .runtime_abi     = NODUS_DOMAIN_RUNTIME_ABI_V1,
        .ruleset_version = 1,
        .ruleset_hash    = { 0 },
        .descriptor = {
            .descriptor_version = DNA_RULESET_DESC_VERSION,
            .domain_id = DNA_DOMAIN_CORE,
            .name = "DNA_CORE",
            .runtime_abi = NODUS_DOMAIN_RUNTIME_ABI_V1,
            .ruleset_version = 1,
            .rule_count = 4, .rule_ids = CORE_RULES,
            .tx_type_count = 4, .tx_types = CORE_TYPES
        },
        .admit = rt_admit_common,
        .tx_cost = core_cost,
        .apply_reserved = NULL,
        .root_reserved  = NULL
    }
};
#define BUILTIN_COUNT (sizeof(BUILTIN) / sizeof(BUILTIN[0]))

/* The pinned digest for each builtin slot (parallel to BUILTIN). */
static const uint8_t *builtin_pinned_hash(size_t i) {
    return i == 0 ? SYS_RULESET_HASH : CORE_RULESET_HASH;
}

/* A mutable mirror whose ruleset_hash fields are filled from the pinned
 * constants on first use — C's const-initializer rules cannot copy an
 * array into a designated initializer, and duplicating 64 hex bytes in two
 * places would invite drift. Everything except the hash bytes is copied
 * verbatim from BUILTIN. */
static nodus_domain_runtime_t g_table[BUILTIN_COUNT];
static int g_table_ready = 0;

static const nodus_domain_runtime_t *table_get(size_t *n_out) {
    if (!g_table_ready) {
        memcpy(g_table, BUILTIN, sizeof(BUILTIN));
        for (size_t i = 0; i < BUILTIN_COUNT; i++)
            memcpy(g_table[i].ruleset_hash, builtin_pinned_hash(i),
                   DNA_DOM_HASH_LEN);
        g_table_ready = 1;
    }
    if (n_out) *n_out = BUILTIN_COUNT;
    return g_table;
}

/* ── Lookup ─────────────────────────────────────────────────────────── */

const nodus_domain_runtime_t *
nodus_runtime_lookup_in(const nodus_domain_runtime_t *table, size_t n,
                        uint32_t domain_id, uint8_t runtime_kind,
                        uint32_t runtime_abi, uint32_t ruleset_version,
                        const uint8_t ruleset_hash[DNA_DOM_HASH_LEN]) {
    if (!table || !ruleset_hash) return NULL;
    for (size_t i = 0; i < n; i++) {
        const nodus_domain_runtime_t *rt = &table[i];
        if (rt->domain_id != domain_id) continue;
        if (rt->runtime_kind != runtime_kind) continue;
        if (rt->runtime_abi != runtime_abi) continue;
        if (rt->ruleset_version != ruleset_version) continue;
        if (memcmp(rt->ruleset_hash, ruleset_hash, DNA_DOM_HASH_LEN) != 0)
            continue;
        return rt;
    }
    return NULL;
}

const nodus_domain_runtime_t *
nodus_runtime_lookup(uint32_t domain_id, uint8_t runtime_kind,
                     uint32_t runtime_abi, uint32_t ruleset_version,
                     const uint8_t ruleset_hash[DNA_DOM_HASH_LEN]) {
    size_t n = 0;
    const nodus_domain_runtime_t *t = table_get(&n);
    return nodus_runtime_lookup_in(t, n, domain_id, runtime_kind,
                                   runtime_abi, ruleset_version,
                                   ruleset_hash);
}

const nodus_domain_runtime_t *nodus_runtime_builtin_table(size_t *n_out) {
    return table_get(n_out);
}

/* ── Self-check ─────────────────────────────────────────────────────── */

int nodus_witness_runtime_selfcheck(void) {
    size_t n = 0;
    const nodus_domain_runtime_t *t = table_get(&n);
    if (n != 2) return -1;
    if (t[0].domain_id != DNA_DOMAIN_SYSTEM ||
        t[1].domain_id != DNA_DOMAIN_CORE)
        return -1;

    for (size_t i = 0; i < n; i++) {
        const nodus_domain_runtime_t *rt = &t[i];
        if (rt->runtime_kind != DNA_RUNTIME_NATIVE_BUILTIN) return -1;
        if (!rt->admit || !rt->tx_cost) return -1;
        if (rt->apply_reserved || rt->root_reserved) return -1;   /* S4 */
        /* descriptor identity must equal the tuple identity */
        if (rt->descriptor.domain_id != rt->domain_id) return -1;
        if (rt->descriptor.runtime_abi != rt->runtime_abi) return -1;
        if (rt->descriptor.ruleset_version != rt->ruleset_version) return -1;
        /* pinned digest must equal a FRESH recomputation */
        uint8_t fresh[DNA_DOM_HASH_LEN];
        if (dna_ruleset_desc_hash(&rt->descriptor, fresh) != 0) return -1;
        if (memcmp(fresh, rt->ruleset_hash, DNA_DOM_HASH_LEN) != 0) return -1;
        if (memcmp(fresh, builtin_pinned_hash(i), DNA_DOM_HASH_LEN) != 0)
            return -1;
    }
    return 0;
}
