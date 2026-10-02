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
 * HF-4 (design docs/plans/2026-10-02-onchain-names-design.md rev 4 §1.1;
 * decision docs/plans/decisions/2026-10-02-onchain-names.md): the table is
 * an ordered list of rule-set GENERATIONS — generation 1 (SYSTEM v6 /
 * CORE v4 / policy 8f1f9cb2…, byte-identical to the pre-HF-4 table, the
 * one genesis seeds) and generation 2 (SYSTEM v7 / CORE v5, CORE rule 8
 * NAME_REGISTER, the policy pricing ops 1..8). The registry's committed
 * manifests choose the generation that judges a block (exact-tuple
 * lookup across every generation); the engine's phase 6b' moves the
 * registry from 1 to 2 at the end of block H-1 of the RULESET_GEN2 vote.
 * The generation-2 pins (G1-G3) are INDEPENDENT-oracle literals, filled
 * from shared/dnac/tests/hf4_oracle.py (commit 89f9da09, with D2 in
 * dnac.h); selfcheck re-derives them and the D2 vote literal on every
 * start.
 *
 * @file nodus_witness_runtime.c
 */

#include "nodus_witness_runtime.h"
#include "nodus_witness_v2_adapter.h"   /* nodus_adapter_selfcheck — the
                                         * adapter contract is pure
                                         * compiled data + fn pointers,
                                         * so this module stays free of
                                         * witness/db dependencies       */
#include "dnac/dnac.h"                  /* HF-4: DNAC_CFG_RULESET_GEN2_D2,
                                         * DNAC_RULESET_SWITCH_SPEC_VERSION */
#include "crypto/utils/qgp_log.h"

#include <string.h>

#define LOG_TAG "W_RUNTIME"

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
/* HF-4 (design docs/plans/2026-10-02-onchain-names-design.md rev 4
 * §1.1): generation 2's CORE (v5) owns rules {1..8} — generation 1's list
 * with DNA_CORERULE_NAME_REGISTER appended. Its tx_type list is the SAME
 * CORE_TYPES array below (op and tx_type are different axes). Generation
 * 2's SYSTEM (v7) reuses SYS_RULES / SYS_TYPES unchanged. */
static const uint32_t CORE_RULES_G2[8] = {
    DNA_CORERULE_SPEND, DNA_CORERULE_BURN, DNA_CORERULE_TOKEN_CREATE,
    DNA_CORERULE_SHIELDED_C3_REJECT, DNA_CORERULE_SHIELD_C3_REJECT,
    DNA_CORERULE_UNSHIELD_C3_REJECT, DNA_CORERULE_SYSFUND,
    DNA_CORERULE_NAME_REGISTER
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
 * canonical "NDS.METPOLID.v1" preimage, and selfcheck re-derives it
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
    0x8f, 0x1f, 0x9c, 0xb2, 0xa5, 0x32, 0xbb, 0x28,
    0x7f, 0xc0, 0xd5, 0xa1, 0xd6, 0x3d, 0xa2, 0xca,
    0xb5, 0xc4, 0x86, 0x1a, 0x53, 0xe3, 0x91, 0xc3,
    0xf5, 0xb4, 0xb7, 0xdb, 0xdd, 0x36, 0x49, 0x8b,
    0xd8, 0xca, 0x8b, 0x14, 0x50, 0x1d, 0x69, 0x54,
    0xfd, 0x5a, 0xc0, 0x6a, 0x5e, 0x3c, 0x12, 0xbd,
    0xf4, 0xaf, 0x05, 0x71, 0xf3, 0x31, 0xd4, 0xf5,
    0x29, 0x9d, 0xaf, 0x26, 0x68, 0x74, 0x6f, 0x32
};

/* HF-4 — generation 2's SYSTEM (v7) metering policy: the SAME shape v2
 * (seven scalar weights 1, the 2 MiB max_block_env_bytes field KEPT —
 * decision 2026-10-02-onchain-names.md item 12) with the authoritative op
 * set grown to 1..8 so generation 2's CORE rule 8 (NAME_REGISTER) has a
 * committed weight (1). The identity digest commits w_op and the presence
 * bitmap, so it differs from generation 1's by construction. The literal
 * comes from the INDEPENDENT oracle (shared/dnac/tests/hf4_oracle.py,
 * built on ruleset_desc_oracle.py's helpers; its control legs must first
 * reproduce SYSTEM v6, CORE v4 and 8f1f9cb2…) — never this build's
 * serializer. Selfcheck re-derives it on every start. */
static dna_meter_policy_t g_sys_policy_g2;
static int g_sys_policy_g2_ready = 0;

static const uint8_t SYS_METER_POLICY_DIGEST_G2[DNA_DOM_HASH_LEN] = {
    /* Generation-2 SYSTEM meter-policy identity digest ("NDS.METPOLID.v1",
     * ops 1..8 weight 1) — G1 of shared/dnac/tests/hf4_oracle.py, whose
     * control legs reproduced 8f1f9cb2…, SYSTEM v6 and CORE v4 first
     * (written by an agent that read no HF-4 C). */
    0x0c, 0x25, 0x1c, 0xa2, 0x92, 0x0d, 0x77, 0x88,
    0x2b, 0xca, 0xb2, 0x94, 0x31, 0x10, 0x52, 0xa0,
    0x68, 0x13, 0x62, 0xc5, 0x5b, 0x06, 0xf4, 0x17,
    0xf6, 0xaa, 0xda, 0x46, 0xfe, 0xb7, 0x55, 0xb3,
    0xab, 0x30, 0x47, 0x76, 0xed, 0x33, 0x53, 0x7a,
    0xe0, 0x7e, 0x73, 0xf7, 0x9a, 0x10, 0xda, 0x3d,
    0x3f, 0x4b, 0x78, 0x8b, 0xd5, 0x6e, 0x4c, 0x06,
    0xa7, 0x17, 0x2a, 0x6f, 0x19, 0xce, 0xec, 0x87
};

/* The highest authoritative runtime op of each generation's SYSTEM policy:
 * the union of that generation's two descriptors' rule-id ranges
 * (generation 1: CORE 1..7 / SYSTEM 1..6; generation 2: CORE 1..8). */
#define SYS_POLICY_MAX_OP_G1  7u
#define SYS_POLICY_MAX_OP_G2  8u

static int sys_policy_build(dna_meter_policy_t *p, uint32_t max_op) {
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
     * row here would make every staking envelope unreservable.
     * HF-4: `max_op` is the generation's own bound (SYS_POLICY_MAX_OP_*);
     * generation 1 passes 7, so its policy is byte-identical to the
     * pre-HF-4 one (pinned: SYS_METER_POLICY_DIGEST). */
    for (uint32_t op = 1; op <= max_op; op++)
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
    /* Final pre-testnet wipe, W-A (design 2026-09-28-final-wipe-package-
     * design.md §7 Fable F3): SYSTEM ruleset_version 5 → 6. The SYSTEM
     * runtime's committed state changed meaning — system_state_root
     * gained the treasury_root leg ("NDS.SYS.v4"), its genesis payload
     * root moved to "NDS.SYSPAYL.v3" (W-A also credited a genesis seat's
     * graduation refund to the Foundation pool — WITHDRAWN by general
     * multisig, decision 2026-09-29-general-multisig.md: every seat
     * releases a UTXO to its unstake destination again, a genesis seat's
     * being the Foundation multisig address; the descriptor preimage is
     * unaffected, so v6 stands);
     * and (W-B, same v6) STAKE accepts only a bond of EXACTLY
     * DNAC_SELF_STAKE_AMOUNT and DELEGATE accepts a validator delegating
     * to itself (Rule S removed); and (W-C, same v6) CHAIN_CONFIG
     * accepts param id 6 TOKEN_CREATE_FEE_RAW (hook-side scalar rules,
     * not the descriptor, so the pinned v6 digest below is unaffected) —
     * and the exact-tuple identity IS the activation mechanism, so the
     * version advances. The descriptor preimage differs from v5 ONLY in
     * the ruleset_version field (rule list {1..6}, type list
     * {4,5,6,7,9,10} and the meter-policy digest are byte-identical), so
     * the digest moves by construction.
     *
     * The v6 digest comes from the INDEPENDENT python3 ruleset oracle,
     * never from this build's own encoder; the same value is
     * nodus/tests/test_domain_runtime.c KAT_RS_SYSTEM, and
     * nodus_witness_runtime_selfcheck() re-derives it through the C
     * encoder on every start. The retired v5 value 701d7876…2d7e is
     * dead: old SYSTEM legs are never reinterpreted.
     *
     * HISTORY — O15F, SYSTEM ruleset_version 4 → 5: the V2-lane CHAIN_CONFIG
     * (runtime op 6) NARROWS the accepted TARGET_ACTIVE_COUNT range to
     * [7..30] (a proposal for 31 is a deterministic reject in
     * rtn_cc_exec). Narrowing the accepted runtime-op-6 semantics changes
     * this ruleset, and no separate versioned activation mechanism commits
     * that change — the exact-tuple identity IS the activation mechanism —
     * so the version advances and the digest moves by construction. The
     * descriptor commits ruleset_version; the rule list {1..6}, the type
     * list {4,5,6,7,9,10} and the meter-policy digest are all byte-
     * identical to v4 — the CC range is enforced in the HOOK, not the
     * descriptor, so the v5 preimage differs from v4 ONLY in the version
     * field. The retired SYSTEM v4 (like v3/v2/v1) resolves NOTHING: old
     * SYSTEM legs are never reinterpreted. Oracle: scratchpad
     * o15f_ruleset_oracle.py, whose control legs reproduced BOTH shipped
     * pins (SYSTEM v4 4fe76fed…7736 and CORE v3 ed4b1bcd…4437)
     * byte-exactly before this value was accepted; selfcheck re-derives
     * it through the C encoder on every run. */
    /* W-A PINNED (2026-09-29): SYSTEM v6 from the independent
     * shared/dnac/tests/ruleset_desc_oracle.py, whose control legs
     * reproduced SYSTEM v4 4fe76fed…7736, SYSTEM v5 0efc48bf…f350, CORE v3
     * ed4b1bcd…4437 and the meter-policy digest 8d038f1e…f5cc byte-exactly
     * first (written by an agent that did not read this build's C). */
    0xca, 0x05, 0xb4, 0xd9, 0x57, 0xd9, 0x0b, 0xab,
    0x1b, 0x7b, 0xe1, 0xf4, 0xb9, 0xac, 0x81, 0x44,
    0xc5, 0xdf, 0xa8, 0x7d, 0x4c, 0x88, 0x94, 0x8b,
    0x46, 0xad, 0xc7, 0x11, 0xd6, 0xde, 0x6c, 0x39,
    0x00, 0x3b, 0x33, 0x65, 0xfa, 0x01, 0xac, 0x28,
    0xef, 0x95, 0xce, 0x36, 0xf3, 0x77, 0xe1, 0x12,
    0xd1, 0xbd, 0xd3, 0x5b, 0x6a, 0x0b, 0xe6, 0xe5,
    0x72, 0x08, 0x32, 0x92, 0x1c, 0xdb, 0xef, 0xa3
};
static const uint8_t CORE_RULESET_HASH[DNA_DOM_HASH_LEN] = {
    /* Final pre-testnet wipe, W-C (design 2026-09-28-final-wipe-package-
     * design.md §1 W-C and §7 Fable F3): CORE ruleset_version 3 → 4. The
     * CORE TOKEN_CREATE fee rule changes meaning — rtn_tc_exec
     * (nodus_witness_rt_native.c) enforces fee >= ctx->token_create_fee,
     * the COMMITTED chain_config param 6 (TOKEN_CREATE_FEE_RAW, decision
     * 2026-09-28-token-create-fee-governance.md) active at the block's
     * height, read by the engine (nodus_witness_v2_apply.c
     * env_token_create_fee) instead of the compiled
     * NODUS_W_TOKEN_CREATE_FEE (still the no-row value). The exact-tuple
     * identity IS the activation mechanism, so the version advances. The
     * descriptor preimage differs from v3 ONLY in the
     * ruleset_version field (rule list {1..7}, type list
     * {1,2,3,11,12,13} and the all-zero "no policy declared" digest are
     * byte-identical), so the digest moves by construction.
     *
     * AND (general multisig, same v4 — ONE bump for the whole final-wipe
     * release, decision 2026-09-29-general-multisig.md "CORE 3→4 tek
     * artış"): CORE accepts auth_kind 3 (the M-of-N address scheme) and
     * every CORE op decides input ownership through the one predicate
     * that honours a satisfied multisig address
     * (nodus_witness_rt_native.c rtn_input_owned). The auth-kind
     * allowlist is NOT a descriptor field (rule list, type list and
     * meter-policy digest are), so the multisig change leaves the v4
     * preimage exactly the W-C one — the version field alone moved.
     *
     * The same value is nodus/tests/test_domain_runtime.c KAT_RS_CORE,
     * and nodus_witness_runtime_selfcheck() re-derives it through the C
     * encoder on every start. The retired v3 value 08a204d6…15dc (below,
     * in HISTORY) is dead: old CORE legs are never reinterpreted.
     * PINNED 2026-09-29 from shared/dnac/tests/ruleset_desc_oracle.py
     * (independent; control legs SYSTEM v4/v5, CORE v3 and the meter-policy
     * digest reproduced first). */
    0xb8, 0x7a, 0xab, 0xb8, 0x32, 0x4d, 0xc0, 0x5f,
    0xd0, 0x54, 0x46, 0x90, 0x18, 0x0c, 0xec, 0xe1,
    0x3b, 0x6e, 0x28, 0x60, 0x78, 0xdb, 0x99, 0x73,
    0x9c, 0xaa, 0x65, 0xf0, 0x06, 0xd0, 0xb1, 0xd1,
    0x41, 0x54, 0xed, 0x74, 0xea, 0xb7, 0x8c, 0xf4,
    0x8b, 0x7f, 0xc4, 0x18, 0xde, 0xdc, 0xad, 0x86,
    0x84, 0xa4, 0x85, 0x77, 0x9a, 0xac, 0xf2, 0xa0,
    0xa6, 0xae, 0x40, 0xe0, 0x0d, 0x81, 0x88, 0x52
    /* HISTORY — the retired CORE v3 digest, kept as the oracle's control
     * leg (NOT compiled):
     *   08a204d6 6357b75b d2ec0d45 310e7750 3cc3eed0 53f7249b 246671cf
     *   7c9b3631 1d51fac2 e406b158 a2a77afd 00658330 03171b57 6963a796
     *   3bb1c7c5 26a115dc
     * O11 — CORE ruleset_version 2 → 3: the rule list GREW to {1..7}
     * (DNA_CORERULE_SYSFUND appended) and op 7 became executable. Adding
     * an owned op changes the accepted runtime semantics exactly as
     * enabling one does, and the descriptor commits the rule list
     * itself, so the digest moves twice over. The tx_type list
     * {1,2,3,11,12,13} and the all-zero "no policy declared" digest are
     * byte-identical. The retired CORE v2 resolves NOTHING: v2 legs are
     * never reinterpreted. Same oracle + control legs as the SYSTEM pin
     * above; the burn-season value 746f584a…67a1 is dead. */
};

/* HF-4 — the GENERATION-2 pins (design docs/plans/2026-10-02-onchain-
 * names-design.md rev 4 §1.1). Both from the INDEPENDENT oracle
 * (shared/dnac/tests/hf4_oracle.py, on ruleset_desc_oracle.py's helpers — its
 * control legs reproduce SYSTEM v6 ca05b4d9…, CORE v4 b87aabb8… and the
 * policy 8f1f9cb2… first), never from this build's encoder. Preimages:
 *   SYSTEM v7: version 2, domain 0, "SYSTEM", abi 1, ruleset_version 7,
 *              rules {1..6}, types {4,5,6,7,9,10},
 *              meter_policy_digest = SYS_METER_POLICY_DIGEST_G2;
 *   CORE v5:   version 2, domain 1, "DNA_CORE", abi 1, ruleset_version 5,
 *              rules {1..8}, types {1,2,3,11,12,13},
 *              meter_policy_digest = 64 zero bytes.
 * Selfcheck re-derives both through the C encoder on every start, and
 * the D2 vote literal (dnac.h DNAC_CFG_RULESET_GEN2_D2) from them. */
static const uint8_t SYS_RULESET_HASH_G2[DNA_DOM_HASH_LEN] = {
    /* Generation-2 SYSTEM v7 ruleset_hash — G2 of hf4_oracle.py. */
    0x87, 0x80, 0xa3, 0xa9, 0x12, 0x90, 0x41, 0xe1,
    0x6d, 0xb2, 0x75, 0xfc, 0xa2, 0xe2, 0xbf, 0xb8,
    0xd2, 0x1a, 0xae, 0x33, 0x37, 0x1c, 0x0b, 0x4c,
    0xaf, 0xdb, 0xcb, 0x62, 0x31, 0x59, 0xea, 0xcb,
    0x74, 0x85, 0x41, 0x07, 0xfa, 0xd3, 0x50, 0x3e,
    0xe2, 0xe0, 0x18, 0xec, 0x25, 0x78, 0x37, 0x7a,
    0x63, 0x00, 0x1e, 0x51, 0x56, 0xa0, 0x7d, 0x38,
    0x6a, 0x7c, 0x7b, 0x55, 0x31, 0x1d, 0x14, 0xb4
};
static const uint8_t CORE_RULESET_HASH_G2[DNA_DOM_HASH_LEN] = {
    /* Generation-2 CORE v5 ruleset_hash — G3 of hf4_oracle.py. */
    0x20, 0xc7, 0x23, 0x5b, 0x13, 0xdb, 0x0f, 0x02,
    0x9a, 0x8c, 0x3b, 0xe0, 0x96, 0xe2, 0x44, 0x03,
    0xfd, 0x3a, 0x3e, 0x39, 0x3e, 0x9f, 0xf7, 0x23,
    0xe0, 0x67, 0x2a, 0x60, 0x27, 0x60, 0x1a, 0x35,
    0x05, 0x86, 0xdb, 0x18, 0x98, 0x5e, 0x7a, 0x6a,
    0xc7, 0x33, 0x65, 0xbe, 0x6c, 0xfe, 0x65, 0xf0,
    0xfb, 0x9a, 0xd5, 0x33, 0x57, 0xdb, 0x2d, 0x53,
    0x9a, 0x1c, 0x69, 0xd9, 0x3d, 0x81, 0xca, 0xe5
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
        /* ruleset_version 6 — final pre-testnet wipe, W-A (Fable F3):
         * the SYSTEM state root gained the treasury leg ("NDS.SYS.v4"),
         * the payload root moved to "NDS.SYSPAYL.v3" (the W-A genesis-
         * seat refund to the Foundation pool is withdrawn by general
         * multisig — a genesis seat releases a UTXO to its destination,
         * the Foundation multisig address) — see
         * SYS_RULESET_HASH above (its v6 digest is pinned from the
         * independent oracle). The preimage differs from v5 ONLY in this
         * field.
         *
         * HISTORY — ruleset_version 5 — O15F: the V2-lane CHAIN_CONFIG (runtime
         * op 6) now NARROWS the accepted TARGET_ACTIVE_COUNT range to
         * [7..30] (a proposal for 31 is a deterministic reject). That
         * changes the accepted runtime-op-6 semantics, and no separate
         * versioned activation mechanism exists (the exact-tuple identity
         * IS the mechanism), so the version advances and the digest moves
         * by construction. The rule list {1..6}, the type list
         * {4,5,6,7,9,10} and the meter-policy digest are all byte-
         * identical to v4 — the CC range is enforced in the HOOK
         * (rtn_cc_exec), not in this descriptor, so the v5 preimage
         * differs from v4 ONLY in the ruleset_version field. The retired
         * v4 (like v3/v2/v1) resolves NOTHING: old SYSTEM legs are never
         * reinterpreted. */
        .runtime_abi     = NODUS_DOMAIN_RUNTIME_ABI_V1,
        .ruleset_version = 6,
        .generation      = NODUS_RT_GEN_1,
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
            .ruleset_version = 6,
            .rule_count = 6, .rule_ids = SYS_RULES,
            .tx_type_count = 6, .tx_types = SYS_TYPES
        },
        .admit = rt_admit_common,
        .tx_cost = sys_cost,
        /* The REAL compiled execution surface. read_plan/exec implement
         * every owned SYSTEM op: the O11 stake lifecycle
         * (DNA_SYSRULE_STAKE / DELEGATE / UNSTAKE / UNDELEGATE), the O12
         * VALIDATOR_UPDATE (op 5) and DNA_SYSRULE_CHAIN_CONFIG. */
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
        /* ruleset_version 4 — final pre-testnet wipe: W-C (Fable F3) —
         * the TOKEN_CREATE fee floor is the governed chain_config param
         * 6 at the block's height (ctx->token_create_fee, engine-read) —
         * AND general multisig — auth_kind 3 accepted, one ownership
         * predicate (ONE bump for both). See CORE_RULESET_HASH above
         * (its v4 digest is pinned from the independent oracle). The
         * preimage differs
         * from v3 ONLY in this field.
         *
         * HISTORY — ruleset_version 3 — O11: the rule list GREW (op 7,
         * DNA_CORERULE_SYSFUND) and that op is executable. Adding an
         * owned op changes this ruleset's accepted semantics exactly as
         * enabling one does, and the exact-tuple identity IS the
         * activation mechanism, so the version advances. The retired v2
         * (like v1) resolves NOTHING — old CORE envelopes are never
         * reinterpreted. */
        .runtime_abi     = NODUS_DOMAIN_RUNTIME_ABI_V1,
        .ruleset_version = 4,
        .generation      = NODUS_RT_GEN_1,
        .ruleset_hash    = { 0 },
        .descriptor = {
            .descriptor_version = DNA_RULESET_DESC_VERSION,
            .domain_id = DNA_DOMAIN_CORE,
            .name = "DNA_CORE",
            .runtime_abi = NODUS_DOMAIN_RUNTIME_ABI_V1,
            .ruleset_version = 4,
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
         * authorization — no CORE operation reads committee approvals,
         * so a CORE leg can never be made to carry (or a block to pay
         * for) a committee-approval blob. General multisig (CORE v4,
         * decision 2026-09-29-general-multisig.md): CORE also accepts
         * auth_kind 3, the M-of-N address scheme — every CORE op decides
         * input ownership through the one predicate that reads it
         * (nodus_witness_rt_native.c rtn_input_owned). */
        .allowed_auth_kinds =
            NODUS_RT_AUTHKIND_BIT(NODUS_RT_AUTHKIND_DSA87_MULTI_V1) |
            NODUS_RT_AUTHKIND_BIT(NODUS_RT_AUTHKIND_DSA87_MSIG_V1),
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
    },
    /* ── HF-4 GENERATION 2 (design docs/plans/2026-10-02-onchain-names-
     * design.md rev 4 §1.1). Never seeded at genesis (domreg seeds
     * generation 1 only); it starts judging blocks when the engine's
     * phase 6b' rewrites the SYSTEM and CORE registry records at the end
     * of block H-1 (H = the committed chain_config param-9 row's
     * effective height). Same hooks, adapters, auth implementation and
     * allowlists as generation 1 — the generation differs ONLY in the
     * descriptor (version, CORE rule list, SYSTEM policy digest) and in
     * what the hooks do with rule 8 (refused until the op-8 package). */
    {
        .domain_id       = DNA_DOMAIN_SYSTEM,
        .runtime_kind    = DNA_RUNTIME_NATIVE_BUILTIN,
        /* ruleset_version 7 — bumped (rule list and type list unchanged)
         * so a generation-1 SYSTEM envelope fails preflight step 5
         * cheaply after the switch (shared/dnac/env_preflight.c), and
         * because the committed policy digest moved (op 8 priced). */
        .runtime_abi     = NODUS_DOMAIN_RUNTIME_ABI_V1,
        .ruleset_version = 7,
        .generation      = NODUS_RT_GEN_2,
        .ruleset_hash    = { 0 },   /* SYS_RULESET_HASH_G2 via table_get */
        .descriptor = {
            .descriptor_version = DNA_RULESET_DESC_VERSION,
            .domain_id = DNA_DOMAIN_SYSTEM,
            .name = "SYSTEM",
            .runtime_abi = NODUS_DOMAIN_RUNTIME_ABI_V1,
            .ruleset_version = 7,
            .rule_count = 6, .rule_ids = SYS_RULES,
            .tx_type_count = 6, .tx_types = SYS_TYPES
        },
        .admit = rt_admit_common,
        .tx_cost = sys_cost,
        .auth      = nodus_rt_auth_dsa87_v1,
        .allowed_auth_kinds =
            NODUS_RT_AUTHKIND_BIT(NODUS_RT_AUTHKIND_DSA87_MULTI_V1) |
            NODUS_RT_AUTHKIND_BIT(NODUS_RT_AUTHKIND_DSA87_CC_V1),
        .read_plan = nodus_rt_system_read_plan,
        .exec      = nodus_rt_system_exec,
        .state_root   = nodus_rt_system_state_root,
        .payload_root = nodus_rt_system_payload_root,
        .asset_check = NULL,
        .claim_apply = NULL,
        .invariant   = NULL,
        .state_init  = NULL,
        .adapter     = &NODUS_RT_SYSTEM_ADAPTER,
        .meter_policy = NULL     /* &g_sys_policy_g2 — bound in table_get */
    },
    {
        .domain_id       = DNA_DOMAIN_CORE,
        .runtime_kind    = DNA_RUNTIME_NATIVE_BUILTIN,
        /* ruleset_version 5 — the rule list GREW to {1..8}
         * (DNA_CORERULE_NAME_REGISTER appended); the tx_type list and the
         * all-zero "no policy declared" field are unchanged. */
        .runtime_abi     = NODUS_DOMAIN_RUNTIME_ABI_V1,
        .ruleset_version = 5,
        .generation      = NODUS_RT_GEN_2,
        .ruleset_hash    = { 0 },   /* CORE_RULESET_HASH_G2 via table_get */
        .descriptor = {
            .descriptor_version = DNA_RULESET_DESC_VERSION,
            .domain_id = DNA_DOMAIN_CORE,
            .name = "DNA_CORE",
            .runtime_abi = NODUS_DOMAIN_RUNTIME_ABI_V1,
            .ruleset_version = 5,
            .rule_count = 8, .rule_ids = CORE_RULES_G2,
            .tx_type_count = 6, .tx_types = CORE_TYPES
        },
        .admit = rt_admit_common,
        .tx_cost = core_cost,
        .auth      = nodus_rt_auth_dsa87_v1,
        .allowed_auth_kinds =
            NODUS_RT_AUTHKIND_BIT(NODUS_RT_AUTHKIND_DSA87_MULTI_V1) |
            NODUS_RT_AUTHKIND_BIT(NODUS_RT_AUTHKIND_DSA87_MSIG_V1),
        .read_plan = nodus_rt_core_read_plan,
        .exec      = nodus_rt_core_exec,
        .state_root   = nodus_rt_core_state_root,
        .payload_root = NULL,
        .asset_check = nodus_rt_core_asset_check,
        .claim_apply = nodus_rt_core_claim_apply,
        .invariant   = nodus_rt_core_invariant,
        .state_init  = nodus_rt_core_state_init,
        .adapter     = &NODUS_RT_CORE_ADAPTER,
        .meter_policy = NULL     /* CORE declares no policy (zero digest)*/
    }
};
#define BUILTIN_COUNT (sizeof(BUILTIN) / sizeof(BUILTIN[0]))
/* Two domains per generation, SYSTEM then CORE, generation-major — the
 * order selfcheck pins and nodus_runtime_generation_table slices by. */
#define BUILTIN_PER_GEN 2u
#define BUILTIN_GENS    ((uint32_t)(BUILTIN_COUNT / BUILTIN_PER_GEN))
_Static_assert(BUILTIN_COUNT % BUILTIN_PER_GEN == 0,
               "every generation carries exactly SYSTEM and CORE");
_Static_assert(BUILTIN_COUNT / BUILTIN_PER_GEN == NODUS_RT_GEN_MAX,
               "NODUS_RT_GEN_MAX names the newest compiled generation");

/* The pinned digest for each builtin slot (parallel to BUILTIN). */
static const uint8_t *const BUILTIN_PINNED_HASH[] = {
    SYS_RULESET_HASH, CORE_RULESET_HASH,          /* generation 1 */
    SYS_RULESET_HASH_G2, CORE_RULESET_HASH_G2     /* generation 2 */
};
_Static_assert(sizeof(BUILTIN_PINNED_HASH) / sizeof(BUILTIN_PINNED_HASH[0])
                   == BUILTIN_COUNT, "one pinned digest per builtin slot");

static const uint8_t *builtin_pinned_hash(size_t i) {
    return BUILTIN_PINNED_HASH[i];
}

/* The SYSTEM policy object, its pinned identity digest and its op bound,
 * per generation (index = generation - 1). */
static dna_meter_policy_t *const GEN_SYS_POLICY[] = {
    &g_sys_policy, &g_sys_policy_g2
};
static int *const GEN_SYS_POLICY_READY[] = {
    &g_sys_policy_ready, &g_sys_policy_g2_ready
};
static const uint8_t *const GEN_SYS_POLICY_DIGEST[] = {
    SYS_METER_POLICY_DIGEST, SYS_METER_POLICY_DIGEST_G2
};
static const uint32_t GEN_SYS_POLICY_MAX_OP[] = {
    SYS_POLICY_MAX_OP_G1, SYS_POLICY_MAX_OP_G2
};
_Static_assert(sizeof(GEN_SYS_POLICY_MAX_OP) /
                   sizeof(GEN_SYS_POLICY_MAX_OP[0]) == BUILTIN_GENS,
               "one SYSTEM policy per generation");

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
         * digest. A build/seal failure leaves the generation's ready flag
         * 0 and meter_policy NULL — selfcheck and every engine consumer
         * then fail closed (an unsealed policy prices nothing). HF-4: one
         * policy per generation, bound to that generation's SYSTEM slot
         * (slot BUILTIN_PER_GEN * (generation - 1)). */
        for (uint32_t g = 0; g < BUILTIN_GENS; g++) {
            size_t sys = (size_t)g * BUILTIN_PER_GEN;
            *GEN_SYS_POLICY_READY[g] =
                (sys_policy_build(GEN_SYS_POLICY[g],
                                  GEN_SYS_POLICY_MAX_OP[g]) == 0);
            if (*GEN_SYS_POLICY_READY[g])
                g_table[sys].meter_policy = GEN_SYS_POLICY[g];
            memcpy(g_table[sys].descriptor.meter_policy_digest,
                   GEN_SYS_POLICY_DIGEST[g], DNA_DOM_HASH_LEN);
        }
        /* CORE's descriptors keep the all-zero "no policy" digest. */
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

/* The genesis generation only (header contract) — the two entries every
 * pre-HF-4 consumer saw, in the same order. */
const nodus_domain_runtime_t *nodus_runtime_builtin_table(size_t *n_out) {
    return nodus_runtime_generation_table(NODUS_RT_GEN_1, n_out);
}

const nodus_domain_runtime_t *nodus_runtime_all_table(size_t *n_out) {
    return table_get(n_out);
}

uint32_t nodus_runtime_generation_count(void) {
    return BUILTIN_GENS;
}

const nodus_domain_runtime_t *
nodus_runtime_generation_table(uint32_t generation, size_t *n_out) {
    if (n_out) *n_out = 0;
    if (generation < NODUS_RT_GEN_1 || generation > BUILTIN_GENS)
        return NULL;
    const nodus_domain_runtime_t *t = table_get(NULL);
    if (n_out) *n_out = BUILTIN_PER_GEN;
    return &t[(size_t)(generation - 1u) * BUILTIN_PER_GEN];
}

const nodus_domain_runtime_t *
nodus_runtime_for_generation(uint32_t generation, uint32_t domain_id) {
    size_t n = 0;
    const nodus_domain_runtime_t *g =
        nodus_runtime_generation_table(generation, &n);
    for (size_t i = 0; g && i < n; i++)
        if (g[i].domain_id == domain_id) return &g[i];
    return NULL;
}

/* ── Self-check ─────────────────────────────────────────────────────── */

/* HF-4: one generation-list invariant failed — named, because a node that
 * refuses to start must say which pin is wrong (the oracle-filled ones
 * are the likely culprit after a table change). */
#define SC_FAIL(...)                                                    \
    do {                                                                \
        QGP_LOG_ERROR(LOG_TAG, __VA_ARGS__);                            \
        return -1;                                                      \
    } while (0)

int nodus_witness_runtime_selfcheck(void) {
    size_t n = 0;
    const nodus_domain_runtime_t *t = table_get(&n);
    /* HF-4 shape: generation-major, SYSTEM then CORE in each generation,
     * generation ids 1..BUILTIN_GENS with no gap. */
    if (n != BUILTIN_COUNT || n == 0 || n % BUILTIN_PER_GEN != 0)
        SC_FAIL("selfcheck: table holds %zu entries", n);
    for (size_t i = 0; i < n; i++) {
        uint32_t want_gen = (uint32_t)(i / BUILTIN_PER_GEN) + 1u;
        uint32_t want_dom = (i % BUILTIN_PER_GEN) == 0 ? DNA_DOMAIN_SYSTEM
                                                       : DNA_DOMAIN_CORE;
        if (t[i].generation != want_gen || t[i].domain_id != want_dom)
            SC_FAIL("selfcheck: slot %zu is (generation %u, domain %u), "
                    "expected (%u, %u)", i, (unsigned)t[i].generation,
                    (unsigned)t[i].domain_id, (unsigned)want_gen,
                    (unsigned)want_dom);
    }

    for (size_t i = 0; i < n; i++) {
        const nodus_domain_runtime_t *rt = &t[i];
        const int is_sys = (rt->domain_id == DNA_DOMAIN_SYSTEM);
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
              NODUS_RT_AUTHKIND_BIT(NODUS_RT_AUTHKIND_DSA87_CC_V1) |
              NODUS_RT_AUTHKIND_BIT(NODUS_RT_AUTHKIND_DSA87_MSIG_V1)))
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
         * authority) carries one — sealed, of ITS generation — CORE none */
        if (is_sys && (!*GEN_SYS_POLICY_READY[rt->generation - 1u] ||
                       rt->meter_policy !=
                           GEN_SYS_POLICY[rt->generation - 1u]))
            return -1;
        if (!is_sys && rt->meter_policy) return -1;
        /* the exact configured auth-kind shape (header contract):
         * SYSTEM {1,2} — submitter + committee carrier; CORE {1,3} —
         * submitter + general multisig (CORE v4). SYSTEM never carries
         * kind 3: its ops decide authority on exactly one signer. */
        if (is_sys && rt->allowed_auth_kinds !=
                (NODUS_RT_AUTHKIND_BIT(NODUS_RT_AUTHKIND_DSA87_MULTI_V1) |
                 NODUS_RT_AUTHKIND_BIT(NODUS_RT_AUTHKIND_DSA87_CC_V1)))
            return -1;
        if (!is_sys && rt->allowed_auth_kinds !=
                (NODUS_RT_AUTHKIND_BIT(NODUS_RT_AUTHKIND_DSA87_MULTI_V1) |
                 NODUS_RT_AUTHKIND_BIT(NODUS_RT_AUTHKIND_DSA87_MSIG_V1)))
            return -1;
        /* pinned digest must equal a FRESH recomputation */
        uint8_t fresh[DNA_DOM_HASH_LEN];
        if (dna_ruleset_desc_hash(&rt->descriptor, fresh) != 0) return -1;
        if (memcmp(fresh, rt->ruleset_hash, DNA_DOM_HASH_LEN) != 0)
            SC_FAIL("selfcheck: generation %u domain %u ruleset_hash does "
                    "not re-derive from its descriptor",
                    (unsigned)rt->generation, (unsigned)rt->domain_id);
        if (memcmp(fresh, builtin_pinned_hash(i), DNA_DOM_HASH_LEN) != 0)
            return -1;
    }

    /* ── HF-4 generation-list invariants (design §1.1) ─────────────── */

    /* exact-tuple uniqueness: one committed tuple resolves ONE entry */
    for (size_t i = 0; i < n; i++)
        for (size_t j = i + 1; j < n; j++)
            if (t[i].domain_id == t[j].domain_id &&
                t[i].runtime_kind == t[j].runtime_kind &&
                t[i].runtime_abi == t[j].runtime_abi &&
                t[i].ruleset_version == t[j].ruleset_version &&
                memcmp(t[i].ruleset_hash, t[j].ruleset_hash,
                       DNA_DOM_HASH_LEN) == 0)
                SC_FAIL("selfcheck: slots %zu and %zu carry the same "
                        "exact tuple", i, j);

    /* per domain: versions strictly increase with the generation, and
     * kind / abi never change (the switch copies them, §1.4) */
    for (size_t i = BUILTIN_PER_GEN; i < n; i++) {
        const nodus_domain_runtime_t *prev = &t[i - BUILTIN_PER_GEN];
        if (t[i].ruleset_version <= prev->ruleset_version)
            SC_FAIL("selfcheck: domain %u ruleset_version %u in generation "
                    "%u does not exceed %u", (unsigned)t[i].domain_id,
                    (unsigned)t[i].ruleset_version,
                    (unsigned)t[i].generation,
                    (unsigned)prev->ruleset_version);
        if (t[i].runtime_kind != prev->runtime_kind ||
            t[i].runtime_abi != prev->runtime_abi)
            SC_FAIL("selfcheck: domain %u changes runtime kind/abi in "
                    "generation %u", (unsigned)t[i].domain_id,
                    (unsigned)t[i].generation);
    }

    /* generation 1 is today's chain, byte-identical — never re-pinned:
     * SYSTEM v6 + policy 8f1f9cb2…, CORE v4 (the literals above) */
    if (t[0].ruleset_version != 6 || t[1].ruleset_version != 4 ||
        memcmp(t[0].ruleset_hash, SYS_RULESET_HASH, DNA_DOM_HASH_LEN) != 0 ||
        memcmp(t[1].ruleset_hash, CORE_RULESET_HASH, DNA_DOM_HASH_LEN) != 0 ||
        memcmp(t[0].descriptor.meter_policy_digest, SYS_METER_POLICY_DIGEST,
               DNA_DOM_HASH_LEN) != 0)
        SC_FAIL("selfcheck: generation 1 is not the genesis generation "
                "(SYSTEM v6 / CORE v4 / policy 8f1f9cb2...)");

    /* each generation's SYSTEM policy prices every rule id of that
     * generation's SYSTEM and CORE descriptors — an unpriced op is an
     * "absent op weight" refusal at reservation for every leg naming it */
    for (size_t g = 0; g < BUILTIN_GENS; g++) {
        const dna_meter_policy_t *p = t[g * BUILTIN_PER_GEN].meter_policy;
        for (size_t k = 0; k < BUILTIN_PER_GEN; k++) {
            const dna_ruleset_desc_t *d = &t[g * BUILTIN_PER_GEN + k].descriptor;
            for (size_t r = 0; r < d->rule_count; r++) {
                uint64_t w = 0;
                if (!p || dna_meter_op_weight(p, d->rule_ids[r], &w) != 0)
                    SC_FAIL("selfcheck: generation %zu's SYSTEM policy does "
                            "not price rule %u of domain %u", g + 1,
                            (unsigned)d->rule_ids[r], (unsigned)d->domain_id);
            }
        }
    }

    /* the compiled vote literal re-derives from the generation-2 pins
     * (dnac.h DNAC_CFG_RULESET_GEN2_D2 — no hashing in the vote path) */
    {
        const nodus_domain_runtime_t *s2 =
            nodus_runtime_for_generation(NODUS_RT_GEN_2, DNA_DOMAIN_SYSTEM);
        const nodus_domain_runtime_t *c2 =
            nodus_runtime_for_generation(NODUS_RT_GEN_2, DNA_DOMAIN_CORE);
        uint64_t d2 = 0;
        if (!s2 || !c2 ||
            dna_ruleset_gen_digest(NODUS_RT_GEN_2, s2->ruleset_hash,
                                   c2->ruleset_hash,
                                   DNAC_RULESET_SWITCH_SPEC_VERSION,
                                   &d2) != 0)
            SC_FAIL("selfcheck: the generation-2 vote digest could not be "
                    "derived");
        if (d2 != (uint64_t)DNAC_CFG_RULESET_GEN2_D2)
            SC_FAIL("selfcheck: the compiled D2 literal 0x%016llx does not "
                    "re-derive (0x%016llx) from the generation-2 pins",
                    (unsigned long long)DNAC_CFG_RULESET_GEN2_D2,
                    (unsigned long long)d2);
    }
    return 0;
}
