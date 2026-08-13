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
 * O11 (stake lifecycle): BOTH rulesets advance 2 → 3. SYSTEM enables
 * runtime ops 1..4 (STAKE / DELEGATE / UNSTAKE / UNDELEGATE) and
 * re-prices its metering policy over ops 1..7; CORE APPENDS rule 7
 * (DNA_CORERULE_SYSFUND, the staking funding/release leg) and enables
 * it. The version advanced ONCE for the whole op set. Neither tx_type list
 * moves — runtime_op and tx_type are different axes. All three pinned
 * digests were re-derived by the O11 oracle (scratchpad
 * o11_season_oracle.py), whose control legs reproduced the shipped
 * capacity-season SYSTEM pin and burn-season CORE pin first.
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

/* O11 appends DNA_CORERULE_SYSFUND (7, declared in the header — both
 * domains' hooks name it): the CORE funding/release half of every SYSTEM
 * stake-lifecycle envelope. The tx_type list is UNCHANGED — runtime_op
 * and tx_type are different axes, and this op carries no legacy type of
 * its own (the staking types 4..7 are SYSTEM's). */
static const uint32_t CORE_RULES[7] = {
    DNA_CORERULE_SPEND, DNA_CORERULE_BURN, DNA_CORERULE_TOKEN_CREATE,
    DNA_CORERULE_SHIELDED_C3_REJECT, DNA_CORERULE_SHIELD_C3_REJECT,
    DNA_CORERULE_UNSHIELD_C3_REJECT, DNA_CORERULE_SYSFUND
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
    /* O11 — the policy SHAPE is unchanged (still v2, same seven scalar
     * weights, same max_block_env_bytes); the AUTHORITATIVE OP SET grew
     * to 1..7 because DNA_CORERULE_SYSFUND must be priced (an op with no
     * committed weight is an "absent op weight" reject at reservation,
     * nodus_witness_v2_apply.c). The identity digest commits w_op and the
     * presence bitmap, so it moves by construction. Oracle: scratchpad
     * o11_season_oracle.py, whose control legs reproduced the shipped
     * pins first; selfcheck re-derives this value through the C
     * serializer on every run. The capacity-season digest dfebb82a…c2de
     * and the v1 digest fad572e9…0537 are both dead. */
    0x8d, 0x03, 0x8f, 0x1e, 0xc6, 0x08, 0xbe, 0x54,
    0x7b, 0xf9, 0x8a, 0xfe, 0x2d, 0xf0, 0x53, 0x2b,
    0x4a, 0x94, 0xa7, 0xa0, 0x42, 0xa9, 0xd9, 0xd8,
    0x6b, 0x7a, 0x0f, 0xb1, 0xab, 0x51, 0xed, 0xaf,
    0xbc, 0x43, 0x64, 0xdc, 0x38, 0x91, 0xc3, 0x6b,
    0xfb, 0xc4, 0x43, 0x32, 0x2f, 0x2a, 0x3b, 0x0b,
    0x44, 0xc8, 0x23, 0x16, 0xbd, 0x78, 0x42, 0xfd,
    0x7f, 0xfb, 0xec, 0x2d, 0x19, 0xf1, 0xf5, 0xcc
};

static int sys_policy_build(dna_meter_policy_t *p) {
    memset(p, 0, sizeof(*p));
    p->policy_version = DNA_METER_POLICY_VERSION;   /* v2 — capacity season */
    p->w_base = 1; p->w_callbyte = 1; p->w_authbyte = 1;
    p->w_effect = 1; p->w_effectbyte = 1; p->w_read = 1; p->w_write = 1;
    /* The ABSOLUTE per-block V2 envelope byte bound (policy v2 field —
     * res_meter.h). 2 MiB = 2 * DNA_ENV_MAX_TOTAL_LEN: admits at least
     * TWO worst-case legal envelopes (819,098 B each since O11 — the
     * derivation pinned in nodus_witness_rt_native.c, "O11 capacity
     * derivation") per block while bounding a
     * full block's admitted envelope bytes to 2 MiB — a block can never
     * carry the 1 MiB envelope maximum repeatedly up to the 16-slot
     * batch/tx-count cap (16 MiB). JUDGMENT value, same placeholder
     * class as the weight-1 economics: the devnet reset repins real
     * economics behind a new policy digest. Raw wire-byte bound,
     * separate from the unit budget by construction. */
    p->max_block_env_bytes = 2u * DNA_ENV_MAX_TOTAL_LEN;
    /* O11: the authoritative op set is the UNION of the two descriptors'
     * rule-id ranges, which grew to 1..7 when DNA_CORERULE_SYSFUND was
     * appended to CORE_RULES. An op with no committed weight has NO
     * price at all (fail-closed: reservation rejects it), so a missing
     * row here would make every staking envelope unreservable. */
    for (uint32_t op = 1; op <= 7; op++)
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
    /* O11 — SYSTEM ruleset_version 2 → 3: runtime op 1
     * (DNA_SYSRULE_STAKE) becomes EXECUTABLE (it was a deterministic
     * reject inside the hooks), and the committed metering policy moved
     * with the op set above. Enabling a previously rejected op changes
     * the accepted runtime semantics, and no separate versioned
     * activation mechanism commits that change — the exact-tuple
     * identity IS the activation mechanism — so the version advances and
     * the digest moves by construction (the descriptor commits
     * ruleset_version AND meter_policy_digest; the rule list {1..6} and
     * the type list {4,5,6,7,9,10} are byte-identical, ops 2..5 are
     * still owned and still reject). The retired SYSTEM v2 resolves
     * NOTHING: v2 legs are never reinterpreted (the v1 retirement
     * precedent). Oracle: scratchpad o11_season_oracle.py, whose control
     * legs reproduced BOTH shipped pins (SYSTEM v2 9fc5394e…24bb and
     * CORE v2 746f584a…67a1) before these values were accepted;
     * selfcheck re-derives them through the C encoder on every run. */
    0xd0, 0x65, 0xe2, 0xe1, 0x71, 0x96, 0x02, 0x21,
    0xe3, 0xb7, 0x9a, 0xfd, 0xed, 0x78, 0xb8, 0x28,
    0x9b, 0x20, 0xcc, 0xf1, 0x83, 0xfb, 0x1c, 0x17,
    0x23, 0xb5, 0x8c, 0x35, 0x18, 0x0c, 0x69, 0x57,
    0xc1, 0xd9, 0x50, 0xe3, 0x77, 0x7b, 0x25, 0x14,
    0xf2, 0xb0, 0x10, 0x8d, 0xa6, 0xed, 0x9c, 0xee,
    0x69, 0xd9, 0xf7, 0x3e, 0x8c, 0xbf, 0x49, 0x66,
    0xc2, 0x66, 0x8f, 0xd9, 0x89, 0x86, 0x6d, 0x64
};
static const uint8_t CORE_RULESET_HASH[DNA_DOM_HASH_LEN] = {
    /* O11 — CORE ruleset_version 2 → 3: the rule list GREW to {1..7}
     * (DNA_CORERULE_SYSFUND appended) and op 7 became executable. Adding
     * an owned op changes the accepted runtime semantics exactly as
     * enabling one does, and the descriptor commits the rule list
     * itself, so the digest moves twice over. The tx_type list
     * {1,2,3,11,12,13} and the all-zero "no policy declared" digest are
     * byte-identical. The retired CORE v2 resolves NOTHING: v2 legs are
     * never reinterpreted. Same oracle + control legs as the SYSTEM pin
     * above; the burn-season value 746f584a…67a1 is dead. */
    0xed, 0x4b, 0x1b, 0xcd, 0xf0, 0xe8, 0xf7, 0x8f,
    0x0b, 0x64, 0x98, 0x5e, 0x42, 0xd4, 0x1d, 0x51,
    0x81, 0xed, 0xd5, 0xd4, 0x85, 0x94, 0xbc, 0xeb,
    0x73, 0xbf, 0x5e, 0xfb, 0x6a, 0xda, 0x08, 0x38,
    0x8d, 0x6f, 0xb6, 0xba, 0x04, 0x92, 0xf8, 0xbd,
    0xca, 0x21, 0x2a, 0x5d, 0xda, 0x87, 0x79, 0xe7,
    0x45, 0x13, 0xc5, 0x21, 0x0b, 0xc4, 0xba, 0xa2,
    0xf7, 0x0b, 0xf3, 0x8c, 0xb2, 0x63, 0x44, 0x37
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
        /* ruleset_version 3 — O11: the STAKE LIFECYCLE ruleset. Runtime
         * ops 1..4 (STAKE / DELEGATE / UNSTAKE / UNDELEGATE) are
         * EXECUTABLE under v3 — all four deterministically rejected
         * under v2 — and the committed metering policy gained op 7.
         * Enabling previously rejected ops changes the accepted
         * semantics of this ruleset and no separate versioned activation
         * mechanism exists (the exact-tuple identity IS the mechanism),
         * so the version advanced ONCE for the whole set: v3 has never
         * been a partial ruleset on any chain, exactly as CORE v2
         * covered BURN and TOKEN_CREATE together. Op 5
         * (VALIDATOR_UPDATE) still rejects inside the hooks and its
         * migration will advance the version again. The retired v2 (like
         * v1) resolves NOTHING: old SYSTEM legs are never
         * reinterpreted. */
        .runtime_abi     = NODUS_DOMAIN_RUNTIME_ABI_V1,
        .ruleset_version = 3,
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
            .ruleset_version = 3,
            .rule_count = 6, .rule_ids = SYS_RULES,
            .tx_type_count = 6, .tx_types = SYS_TYPES
        },
        .admit = rt_admit_common,
        .tx_cost = sys_cost,
        /* The REAL compiled execution surface. read_plan/exec implement
         * the whole O11 stake lifecycle (DNA_SYSRULE_STAKE / DELEGATE /
         * UNSTAKE / UNDELEGATE) plus DNA_SYSRULE_CHAIN_CONFIG; op 5
         * (VALIDATOR_UPDATE) deterministically rejects inside the hooks
         * until its own migration slice. */
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
        /* ruleset_version 3 — O11: the rule list GREW (op 7,
         * DNA_CORERULE_SYSFUND) and that op is executable. Adding an
         * owned op changes this ruleset's accepted semantics exactly as
         * enabling one does, and the exact-tuple identity IS the
         * activation mechanism, so the version advances. The retired v2
         * (like v1) resolves NOTHING — old CORE envelopes are never
         * reinterpreted. */
        .runtime_abi     = NODUS_DOMAIN_RUNTIME_ABI_V1,
        .ruleset_version = 3,
        .ruleset_hash    = { 0 },
        .descriptor = {
            .descriptor_version = DNA_RULESET_DESC_VERSION,
            .domain_id = DNA_DOMAIN_CORE,
            .name = "DNA_CORE",
            .runtime_abi = NODUS_DOMAIN_RUNTIME_ABI_V1,
            .ruleset_version = 3,
            .rule_count = 7, .rule_ids = CORE_RULES,
            .tx_type_count = 6, .tx_types = CORE_TYPES
        },
        .admit = rt_admit_common,
        .tx_cost = core_cost,
        /* O11: DNA_CORERULE_SPEND + DNA_CORERULE_BURN +
         * DNA_CORERULE_TOKEN_CREATE + DNA_CORERULE_SYSFUND (ops 4..6
         * still reject inside the hooks); shared auth implementation. */
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
