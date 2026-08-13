/**
 * @file nodus_witness_runtime.c
 * @brief Ledger V2 Season 4 — compiled NATIVE_BUILTIN runtime table
 *        implementation (INACTIVE).
 *
 * See nodus_witness_runtime.h. The pinned ruleset digests below were
 * produced by an INDEPENDENT python3 oracle over the canonical descriptor
 * layout in shared/dnac/domain_wire.h (execution season: scratchpad
 * exec_season_oracle.py over the v2 layout, which also derives the
 * SYSTEM meter-policy identity digest; earlier pins came from
 * s4_oracle.py / s9_w4_ruleset_oracle.py and are retired) — and
 * nodus_witness_runtime_selfcheck() re-derives them through the C encoder
 * on every run, so oracle, encoder and table can never drift apart
 * silently. The same literals are pinned again in
 * nodus/tests/test_domain_runtime.c (KAT_RS_SYSTEM / KAT_RS_CORE /
 * KAT_METPOL_SYSTEM).
 *
 * S9 (W4): DNA_CORE's descriptor OWNS tx types 12 (SHIELD) and 13
 * (UNSHIELD) alongside 11 (SHIELDED) so the domain boundary is
 * expressible — admission REJECTS all three unconditionally until the
 * single atomic C3 activation gate.
 *
 * @file nodus_witness_runtime.c
 */

#include "nodus_witness_runtime.h"
#include "nodus_witness_v2_adapter.h"   /* nodus_adapter_selfcheck — the
                                         * adapter contract is pure
                                         * compiled data + fn pointers,
                                         * so this module stays free of
                                         * witness/db dependencies       */

#include <string.h>

/* ── Checked-in canonical descriptors (pure data) ───────────────────── */

static const uint32_t SYS_RULES[6] = {
    DNA_SYSRULE_STAKE, DNA_SYSRULE_DELEGATE, DNA_SYSRULE_UNSTAKE,
    DNA_SYSRULE_UNDELEGATE, DNA_SYSRULE_VALIDATOR_UPDATE,
    DNA_SYSRULE_CHAIN_CONFIG
};
static const uint8_t SYS_TYPES[6] = { 4, 5, 6, 7, 9, 10 };

/* Ledger V2 S9 — rule ids for the V3 boundary types 12 (SHIELD) and 13
 * (UNSHIELD), continuing the DNA_CORERULE_* namespace and its strictly
 * ascending order (nodus_witness_runtime.h holds ids 1-4). Like
 * DNA_CORERULE_SHIELDED_C3_REJECT, each names the SHIPPED behavior rather
 * than the intended one: both types are owned so the domain boundary is
 * expressible, and both are REJECTED unconditionally until the single
 * atomic C3 activation flip. The descriptor digest commits the VALUES
 * (5, 6), never the declaration site. */
#define DNA_CORERULE_SHIELD_C3_REJECT   ((uint32_t)5)
#define DNA_CORERULE_UNSHIELD_C3_REJECT ((uint32_t)6)

static const uint32_t CORE_RULES[6] = {
    DNA_CORERULE_SPEND, DNA_CORERULE_BURN, DNA_CORERULE_TOKEN_CREATE,
    DNA_CORERULE_SHIELDED_C3_REJECT, DNA_CORERULE_SHIELD_C3_REJECT,
    DNA_CORERULE_UNSHIELD_C3_REJECT
};
/* ASCENDING is load-bearing twice over: rt_owns_type() stops at the first
 * greater element, and dna_ruleset_desc_hash() refuses a non-ascending
 * list outright (shared/dnac/domain_wire.c:207-208). */
static const uint8_t CORE_TYPES[6] = { 1, 2, 3, 11, 12, 13 };

/* ── The compiled SYSTEM metering policy (execution season) ───────────
 *
 * PLACEHOLDER ECONOMICS, JUDGMENT-labelled exactly like the S4 tx_cost
 * values: every scalar weight is 1 and runtime ops 1..6 (the union of
 * the two descriptors' rule-id ranges) are authoritative with weight 1.
 * The devnet reset repins real economics behind a new policy digest —
 * which re-derives the SYSTEM ruleset hash by construction, making any
 * price change a visible committed event.
 *
 * The identity digest below (SYS_METER_POLICY_DIGEST) was produced by an
 * INDEPENDENT python3 oracle (scratchpad exec_season_oracle.py) over the
 * canonical "DNA.METPOLID.v1" preimage, and selfcheck re-derives it
 * through the C serializer on every run. */
static dna_meter_policy_t g_sys_policy;
static int g_sys_policy_ready = 0;          /* 0 until built+sealed OK   */

static const uint8_t SYS_METER_POLICY_DIGEST[DNA_DOM_HASH_LEN] = {
    /* capacity season — policy v2 (max_block_env_bytes appended);
     * oracle: scratchpad capacity_season_oracle.py, whose control legs
     * reproduced BOTH shipped pins (old SYSTEM policy fad572e9… and
     * the S9→exec CORE ruleset hash) before this value was accepted.
     * The old v1 digest fad572e9…0537 is dead. */
    0xdf, 0xeb, 0xb8, 0x2a, 0x55, 0x2d, 0xcd, 0xb0,
    0xac, 0x4e, 0x25, 0x81, 0x5e, 0x41, 0x84, 0x82,
    0xf0, 0x27, 0xa3, 0xce, 0x0c, 0xc8, 0x81, 0x09,
    0xc0, 0x45, 0xb7, 0x43, 0x9a, 0x9d, 0xce, 0x49,
    0xe3, 0x7c, 0x65, 0xc4, 0x32, 0x0a, 0xdb, 0xcd,
    0xf9, 0xdd, 0xca, 0x01, 0xd2, 0xcf, 0x05, 0x6d,
    0x32, 0xbc, 0x9c, 0x20, 0xa1, 0x59, 0x0f, 0xe6,
    0x7b, 0x35, 0x78, 0x66, 0xee, 0x27, 0xc2, 0xde
};

static int sys_policy_build(dna_meter_policy_t *p) {
    memset(p, 0, sizeof(*p));
    p->policy_version = DNA_METER_POLICY_VERSION;   /* v2 — capacity season */
    p->w_base = 1; p->w_callbyte = 1; p->w_authbyte = 1;
    p->w_effect = 1; p->w_effectbyte = 1; p->w_read = 1; p->w_write = 1;
    /* The ABSOLUTE per-block V2 envelope byte bound (policy v2 field —
     * res_meter.h). 2 MiB = 2 * DNA_ENV_MAX_TOTAL_LEN: admits at least
     * TWO worst-case legal envelopes (813,904 B each — the derivation
     * pinned in nodus_witness_rt_native.c) per block while bounding a
     * full block's admitted envelope bytes to 2 MiB — a block can never
     * carry the 1 MiB envelope maximum repeatedly up to the 16-slot
     * batch/tx-count cap (16 MiB). JUDGMENT value, same placeholder
     * class as the weight-1 economics: the devnet reset repins real
     * economics behind a new policy digest. Raw wire-byte bound,
     * separate from the unit budget by construction. */
    p->max_block_env_bytes = 2u * DNA_ENV_MAX_TOTAL_LEN;
    for (uint32_t op = 1; op <= 6; op++)
        if (dna_meter_op_set(p, op, 1) != 0) return -1;
    return dna_meter_policy_seal(p);
}

/* Pinned digests — python3 oracle (scratchpad exec_season_oracle.py),
 * RE-DERIVED for the execution season: RulesetDescriptor v2 appends the
 * committed meter_policy_digest, so BOTH digests move by construction.
 * The S9 values (SYSTEM f2dcdefa…4cce / CORE e0a0bc43…7429) are dead.
 * SYSTEM's digest commits SYS_METER_POLICY_DIGEST; CORE's commits the
 * all-zero "no policy declared" field. */
static const uint8_t SYS_RULESET_HASH[DNA_DOM_HASH_LEN] = {
    /* capacity season — ruleset_version 2 (CHAIN_CONFIG call v2 +
     * auth carrier v2) committing the v2 policy digest above; same
     * oracle + control legs. The exec-season value 89362213…96c2 is
     * dead. (CORE moved later, in the burn season — see the CORE pin
     * below; SYSTEM is untouched by that season and this value
     * stands.) */
    0x9f, 0xc5, 0x39, 0x4e, 0x60, 0xe0, 0xd9, 0x80,
    0xae, 0xe5, 0x5b, 0x5a, 0xa7, 0x1c, 0x4f, 0x9c,
    0x84, 0xcd, 0x45, 0x1f, 0x08, 0xd2, 0x76, 0xcf,
    0xfe, 0x21, 0x29, 0xd1, 0xfc, 0x95, 0x7f, 0x6f,
    0x35, 0x40, 0xa0, 0x33, 0x6c, 0xc8, 0x0e, 0xc5,
    0x30, 0x98, 0xa8, 0x97, 0x40, 0x40, 0xad, 0x7f,
    0x40, 0x8b, 0xa5, 0x9d, 0x88, 0x5d, 0x17, 0xac,
    0xdd, 0x17, 0x13, 0x46, 0x8c, 0xce, 0x24, 0xbb
};
static const uint8_t CORE_RULESET_HASH[DNA_DOM_HASH_LEN] = {
    /* burn season — CORE ruleset_version 1 → 2: runtime ops 2 (BURN)
     * and 3 (TOKEN_CREATE) become EXECUTABLE (they were deterministic
     * rejects inside the hooks). Enabling a previously rejected op
     * changes the accepted runtime semantics, and no separate versioned
     * activation mechanism commits that change — the exact-tuple
     * identity IS the activation mechanism — so the version advances
     * and the digest moves by construction (the descriptor commits
     * ruleset_version; the rule/type lists and the zero policy digest
     * are byte-identical). The retired CORE v1 resolves NOTHING: v1
     * legs are never reinterpreted (the SYSTEM v1 retirement
     * precedent). Oracle: scratchpad burn_tc_season_oracle.py, whose
     * control legs reproduced BOTH shipped pins (SYSTEM v2 9fc5394e…
     * and the retired CORE v1 ad98a036…e6f3) before this value was
     * accepted; selfcheck re-derives it through the C encoder on every
     * run. */
    0x74, 0x6f, 0x58, 0x4a, 0xc0, 0x99, 0x64, 0x3d,
    0x63, 0x14, 0x6b, 0xad, 0x02, 0x9c, 0xf9, 0xfd,
    0xeb, 0x67, 0x9a, 0x83, 0x0d, 0x5a, 0x3f, 0x4f,
    0x2a, 0x32, 0x7c, 0x26, 0xf3, 0xca, 0x0f, 0x10,
    0x45, 0x76, 0x3f, 0x0e, 0xa9, 0x2d, 0x28, 0xaf,
    0xf6, 0xfc, 0xa5, 0xd4, 0xcd, 0x20, 0xa5, 0x21,
    0xb5, 0xa3, 0xac, 0xc6, 0x49, 0x15, 0xe1, 0xdd,
    0x9f, 0x35, 0xe2, 0x1a, 0x41, 0xce, 0x67, 0xa1
};

/* ── Function tables ────────────────────────────────────────────────── */

/* Both runtimes share one shape: a type is admissible iff the descriptor
 * owns it AND the pool rule for that type holds. The pool-carrying types
 * in this release are 11 (SHIELDED), 12 (SHIELD) and 13 (UNSHIELD), all
 * on pool DNAC_SHIELDED_POOL_V1 — and all three are consensus-REJECTED
 * until C3, enforced HERE as well as in the legacy admission gate, so the
 * stop cannot be bypassed through the new boundary. */
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
    if (tx_type == 11 || tx_type == 12 || tx_type == 13) {
        /* C3/ACTIVATION HARD STOP (S9 posture): the descriptor OWNS 11
         * SHIELDED, 12 SHIELD and 13 UNSHIELD so the domain boundary is
         * expressible and testable — but all three stay REJECTED
         * unconditionally until the single atomic activation gate flips
         * them together with the shielded apply case. The stop comes
         * BEFORE the pool rule precisely so that carrying the legitimate
         * DNAC_SHIELDED_POOL_V1 id can never become an admit path. */
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
        case 12: *cost_out = 101; return 0;   /* SHIELD: same STARK class
                                               * plus one unit for its
                                               * transparent Dilithium5
                                               * spend authority — declared,
                                               * unreachable until C3      */
        case 13: *cost_out = 100; return 0;   /* UNSHIELD: STARK class only
                                               * (authority is the proof,
                                               * no transparent signer) —
                                               * declared, unreachable      */
        default: *cost_out = 1;   return 0;   /* SPEND / BURN              */
    }
}

/* ── The compiled production table (SYSTEM + DNA_CORE, ascending) ───── */

static const nodus_domain_runtime_t BUILTIN[] = {
    {
        .domain_id       = DNA_DOMAIN_SYSTEM,
        .runtime_kind    = DNA_RUNTIME_NATIVE_BUILTIN,
        /* ruleset_version 2 — capacity season: the CHAIN_CONFIG call
         * format changed (v2 = proposal-only, 41 bytes; approval
         * evidence moved to auth_kind 2) and the committed meter policy
         * moved to policy v2 (max_block_env_bytes). The runtime-call
         * version axis IS the ruleset version (exact-tuple lookup), so
         * v1 legs resolve NOTHING — old bytes are never reinterpreted. */
        .runtime_abi     = NODUS_DOMAIN_RUNTIME_ABI_V1,
        .ruleset_version = 2,
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
            .ruleset_version = 2,
            .rule_count = 6, .rule_ids = SYS_RULES,
            .tx_type_count = 6, .tx_types = SYS_TYPES
        },
        .admit = rt_admit_common,
        .tx_cost = sys_cost,
        /* Native auth season: the REAL compiled execution surface.
         * read_plan/exec implement exactly DNA_SYSRULE_CHAIN_CONFIG;
         * every other owned runtime_op deterministically rejects inside
         * the hooks until its own migration slice. */
        .auth      = nodus_rt_auth_dsa87_v1,
        /* capacity season: SYSTEM legs may carry the ordinary submitter
         * scheme AND the committee-indexed carrier. */
        .allowed_auth_kinds =
            NODUS_RT_AUTHKIND_BIT(NODUS_RT_AUTHKIND_DSA87_MULTI_V1) |
            NODUS_RT_AUTHKIND_BIT(NODUS_RT_AUTHKIND_DSA87_CC_V1),
        .read_plan = nodus_rt_system_read_plan,
        .exec      = nodus_rt_system_exec,
        .state_root   = nodus_rt_system_state_root,
        .payload_root = nodus_rt_system_payload_root,  /* cycle break   */
        .asset_check = NULL,     /* SYSTEM is never a distribution target */
        .claim_apply = NULL,
        .invariant   = NULL,     /* SYSTEM declares no asset state        */
        .state_init  = NULL,     /* SYSTEM initializes no activation state*/
        .adapter     = &NODUS_RT_SYSTEM_ADAPTER,
        .meter_policy = NULL     /* &g_sys_policy — bound in table_get()
                                  * after the seal (array-field literals
                                  * cannot name it here; the descriptor's
                                  * meter_policy_digest is copied there
                                  * for the same reason as ruleset_hash) */
    },
    {
        .domain_id       = DNA_DOMAIN_CORE,
        .runtime_kind    = DNA_RUNTIME_NATIVE_BUILTIN,
        /* ruleset_version 2 — burn season: runtime ops 2 (BURN) and 3
         * (TOKEN_CREATE) became executable (they deterministically
         * rejected under v1). The runtime-op semantic axis IS the
         * ruleset version (exact-tuple lookup), so v1 legs resolve
         * NOTHING — old CORE envelopes are never reinterpreted. */
        .runtime_abi     = NODUS_DOMAIN_RUNTIME_ABI_V1,
        .ruleset_version = 2,
        .ruleset_hash    = { 0 },
        .descriptor = {
            .descriptor_version = DNA_RULESET_DESC_VERSION,
            .domain_id = DNA_DOMAIN_CORE,
            .name = "DNA_CORE",
            .runtime_abi = NODUS_DOMAIN_RUNTIME_ABI_V1,
            .ruleset_version = 2,
            .rule_count = 6, .rule_ids = CORE_RULES,
            .tx_type_count = 6, .tx_types = CORE_TYPES
        },
        .admit = rt_admit_common,
        .tx_cost = core_cost,
        /* Burn season: DNA_CORERULE_SPEND + DNA_CORERULE_BURN +
         * DNA_CORERULE_TOKEN_CREATE (ops 4..6 still reject inside the
         * hooks); shared auth implementation. */
        .auth      = nodus_rt_auth_dsa87_v1,
        /* capacity season: CORE consumes ordinary multi-signer
         * authorization ONLY — no CORE operation reads committee
         * approvals, so a CORE leg can never be made to carry (or a
         * block to pay for) a committee-approval blob. */
        .allowed_auth_kinds =
            NODUS_RT_AUTHKIND_BIT(NODUS_RT_AUTHKIND_DSA87_MULTI_V1),
        .read_plan = nodus_rt_core_read_plan,
        .exec      = nodus_rt_core_exec,
        .state_root   = nodus_rt_core_state_root,
        .payload_root = NULL,    /* generic: payload ≡ state root         */
        .asset_check = nodus_rt_core_asset_check,
        .claim_apply = nodus_rt_core_claim_apply,
        .invariant   = nodus_rt_core_invariant,
        .state_init  = nodus_rt_core_state_init,  /* S7: native pool     */
        .adapter     = &NODUS_RT_CORE_ADAPTER,
        .meter_policy = NULL     /* CORE declares no policy (zero digest)*/
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
        /* SYSTEM carries THE block metering policy: build + seal the
         * compiled policy and bind the descriptor-committed identity
         * digest. A build/seal failure leaves g_sys_policy_ready 0 and
         * meter_policy NULL — selfcheck and every engine consumer then
         * fail closed (an unsealed policy prices nothing). */
        g_sys_policy_ready = (sys_policy_build(&g_sys_policy) == 0);
        if (g_sys_policy_ready)
            g_table[0].meter_policy = &g_sys_policy;
        memcpy(g_table[0].descriptor.meter_policy_digest,
               SYS_METER_POLICY_DIGEST, DNA_DOM_HASH_LEN);
        /* CORE's descriptor keeps the all-zero "no policy" digest. */
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
        /* Native auth season: both production runtimes own executable
         * operations, so the FULL execution surface must be present and
         * healthy — a missing authorization/read/exec hook or a broken
         * compiled adapter is a broken table, never a soft skip. */
        if (!rt->auth || !rt->read_plan || !rt->exec) return -1;
        /* capacity season: the auth-kind allowlist is part of the
         * table's health — a runtime accepting no kind cannot authorize
         * anything (broken), and a bit naming an uncompiled kind would
         * admit legs the shared implementation must reject. The exact
         * configured shape is pinned below with the policy shape. */
        if (rt->allowed_auth_kinds == 0) return -1;
        if (rt->allowed_auth_kinds &
            ~(NODUS_RT_AUTHKIND_BIT(NODUS_RT_AUTHKIND_DSA87_MULTI_V1) |
              NODUS_RT_AUTHKIND_BIT(NODUS_RT_AUTHKIND_DSA87_CC_V1)))
            return -1;
        if (!rt->adapter) return -1;
        if (nodus_adapter_selfcheck(rt->adapter) != 0) return -1;
        if (!rt->state_root) return -1;                /* root is REAL   */
        /* claim-target capability is all-or-nothing */
        if ((rt->asset_check == NULL) != (rt->claim_apply == NULL))
            return -1;
        /* descriptor identity must equal the tuple identity */
        if (rt->descriptor.domain_id != rt->domain_id) return -1;
        if (rt->descriptor.runtime_abi != rt->runtime_abi) return -1;
        if (rt->descriptor.ruleset_version != rt->ruleset_version) return -1;
        /* metering-policy coupling: presence ⇔ non-zero committed
         * digest; a present policy passes its self-check AND its
         * identity digest equals the descriptor-committed one. */
        {
            uint8_t zero[DNA_DOM_HASH_LEN] = { 0 };
            int declared = memcmp(rt->descriptor.meter_policy_digest, zero,
                                  DNA_DOM_HASH_LEN) != 0;
            if (declared != (rt->meter_policy != NULL)) return -1;
            if (rt->meter_policy) {
                uint8_t pd[64];
                if (dna_meter_policy_check(rt->meter_policy) != 0) return -1;
                if (dna_meter_policy_digest(rt->meter_policy, pd) != 0)
                    return -1;
                if (memcmp(pd, rt->descriptor.meter_policy_digest, 64) != 0)
                    return -1;
            }
        }
        /* the exact configured policy shape: SYSTEM (the block-policy
         * authority) carries one, CORE none */
        if (i == 0 && (!g_sys_policy_ready || !rt->meter_policy)) return -1;
        if (i == 1 && rt->meter_policy) return -1;
        /* the exact configured auth-kind shape (header contract):
         * SYSTEM {1,2} — submitter + committee carrier; CORE {1} */
        if (i == 0 && rt->allowed_auth_kinds !=
                (NODUS_RT_AUTHKIND_BIT(NODUS_RT_AUTHKIND_DSA87_MULTI_V1) |
                 NODUS_RT_AUTHKIND_BIT(NODUS_RT_AUTHKIND_DSA87_CC_V1)))
            return -1;
        if (i == 1 && rt->allowed_auth_kinds !=
                NODUS_RT_AUTHKIND_BIT(NODUS_RT_AUTHKIND_DSA87_MULTI_V1))
            return -1;
        /* pinned digest must equal a FRESH recomputation */
        uint8_t fresh[DNA_DOM_HASH_LEN];
        if (dna_ruleset_desc_hash(&rt->descriptor, fresh) != 0) return -1;
        if (memcmp(fresh, rt->ruleset_hash, DNA_DOM_HASH_LEN) != 0) return -1;
        if (memcmp(fresh, builtin_pinned_hash(i), DNA_DOM_HASH_LEN) != 0)
            return -1;
    }
    return 0;
}
