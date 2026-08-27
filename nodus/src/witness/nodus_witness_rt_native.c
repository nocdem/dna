/**
 * @file nodus_witness_rt_native.c
 * @brief Ledger V2 — native authorization + the first PRODUCTION
 *        SYSTEM/DNA_CORE runtime vertical slices (INACTIVE).
 *
 * ═══ ACTIVATION: INACTIVE ═══════════════════════════════════════════════
 * No live consensus path calls anything here. The compiled production
 * runtime table (nodus_witness_runtime.c) binds these hooks; only the
 * (still inactive) V2 apply engine invokes them, and only tests drive
 * that engine. Types 11/12/13 stay REJECT-unconditional and type 14
 * stays unassigned — nothing in this file touches shielded state.
 * ════════════════════════════════════════════════════════════════════════
 *
 * WHAT IS IMPLEMENTED (source-existing operations only — the burn season
 * added 3 and 4, O11 added 5-7, O12 S1 adds 8):
 *
 *   1. SYSTEM  / DNA_SYSRULE_CHAIN_CONFIG (runtime_op 6, legacy tx 10):
 *      the committee-voted consensus-parameter change. The SOURCE
 *      authority is preserved: quorum = dna_bft_quorum(committee at the
 *      signing height H-1), votes are ML-DSA-87 signatures over the ONE
 *      shipped proposal digest (nodus_chain_config_compute_digest),
 *      scalar rules / grace tiers come from the SAME exported helpers
 *      the legacy apply consumes (nodus_chain_config_scalar_rules /
 *      nodus_chain_config_grace_for_param), freshness and the
 *      INFLATION_START monotonicity rule are mirrored 1:1 from
 *      nodus_chain_config_apply (nodus_witness_chain_config.c:903).
 *
 *   2. DNA_CORE / DNA_CORERULE_SPEND (runtime_op 1, legacy tx 1): the
 *      canonical transparent DNAC UTXO transfer. Source semantics
 *      preserved: inputs exist+unspent (utxo_set row present), lock rule
 *      (unlock_block >= H rejects — the legacy "unlock > tip" gate,
 *      nodus_witness_verify.c:731), ownership = UTXO owner fingerprint
 *      is one of the VERIFIED signers (verify.c:740-751), output
 *      identity = SHA3-512(owner_fp_128 ‖ seed_32) (the shipped
 *      update_utxo_set derivation, nodus_witness_bft.c:852-860), fee =
 *      Σnative_in − Σnative_out, must equal the envelope's committed
 *      fee_amount and satisfy BOTH shipped floors (DNAC_MIN_FEE_RAW,
 *      verify.c:540; NODUS_W_BASE_TX_FEE, verify.c:833 — equal today,
 *      enforced as a conjunction so neither can silently drift), and the
 *      fee is BURNED exactly once into supply_tracking.total_burned
 *      (route_tx_fee → nodus_witness_supply_add_burned semantics).
 *
 *   3. DNA_CORE / DNA_CORERULE_BURN (runtime_op 2, legacy tx 2): the
 *      explicit native destruction. The legacy lane has NO type-2
 *      branch anywhere — verify runs the SAME SPEND balance path
 *      (nodus_witness_verify.c:791-866) and apply the SAME
 *      update_utxo_set + route_tx_fee (nodus_witness_bft.c:752-921),
 *      so a legacy "burn" IS a fee-shaped destruction into the ONE
 *      committed counter supply_tracking.total_burned. The V2 call
 *      splits the DECLARATION (explicit burn_amount, >= 1) from the
 *      fee while preserving the exact accounting bucket:
 *      Σnative_in == Σnative_out + fee + burn_amount, and
 *      total_burned += fee + burn_amount (one SET). Non-native tokens
 *      must balance exactly — an explicit TOKEN burn is inexpressible
 *      in the legacy lane (nothing ever decrements tokens.supply) and
 *      is fail-closed here, never invented.
 *
 *   4. DNA_CORE / DNA_CORERULE_TOKEN_CREATE (runtime_op 3, legacy
 *      tx 3): custom-token registration. Source semantics preserved:
 *      output[0] is the token genesis output and the registry commits
 *      exactly its (token_id, amount, fp) (nodus_witness_bft.c:
 *      2243-2281); the creation fee must meet the shipped
 *      NODUS_W_TOKEN_CREATE_FEE floor (verify.c:776-789) and equal
 *      what the native inputs release (the block-level supply
 *      invariant rule, enforced per transaction here); metadata bounds
 *      are the client builder's (token_create.c:52-56 — name 1..32,
 *      symbol 1..8, decimals <= 18; JUDGMENT: the legacy witness never
 *      checked them). Honest fail-closed divergences: duplicate
 *      token_id REJECTS (legacy INSERT OR IGNORE dropped it silently),
 *      the token id must not be the native all-zero id, funding inputs
 *      must be native, non-genesis outputs native-only, and the
 *      registry row's timestamp is written 0 (wall-clock audit column,
 *      EXCLUDED from the token merkle leaf — roots_v2.c:36-37). The
 *      token id itself stays an OPAQUE caller-chosen 64-byte value,
 *      exactly the legacy wire behavior (the client derives it from a
 *      wall clock CLIENT-side; consensus never re-derives it — chain
 *      binding rides the envelope identities, not the token id).
 *
 *   5. SYSTEM / DNA_SYSRULE_STAKE (runtime_op 1, legacy tx 4 — O11):
 *      validator registration. Source semantics preserved from
 *      apply_stake (nodus_witness_bft.c:1505-1620): bond >=
 *      DNAC_SELF_STAKE_AMOUNT (:1568), a new ACTIVE row with
 *      active_since = the executing height (:1583), the unstake
 *      destination fingerprint stored as 128 hex chars and the
 *      destination PUBKEY populated only when the fingerprint derives
 *      from the staker's own key (:1596-1600), every other column zero,
 *      validator_stats.active_count + 1 (:1610), and Rule I (one row per
 *      pubkey) as a mediated ABSENT read plus the CREATE/ABSENT
 *      precondition behind it. LABELED NARROWING: commission_bps <=
 *      DNAC_COMMISSION_BPS_MAX is now WITNESS-enforced — the legacy
 *      apply copied it unchecked and only the client lane bounded it.
 *
 *   6. DNA_CORE / DNA_CORERULE_SYSFUND (runtime_op 7 — O11): the
 *      funding/release half of every SYSTEM stake-lifecycle envelope.
 *      It carries NO amounts: the lock (STAKE bond / DELEGATE amount)
 *      and the release (UNDELEGATE amount) are derived from the SIBLING
 *      SYSTEM leg's call bytes, so record and funding cannot disagree
 *      and neither leg can be replayed against a different partner. It
 *      enforces the legacy consistency equation with the state amount
 *      named on the side it belongs to —
 *      Σnative_in == Σchange + fee + lock — and burns the fee and ONLY
 *      the fee (a lock MOVES value into a supply bucket the conservation
 *      equation already counts; a RELEASE is not netted against the
 *      funding inputs at all — see rtn_sysfund_exec). The release UTXO
 *      reproduces the shipped synthetic-UTXO derivation
 *      (emit_synthetic_utxo, bft.c:1720-1729): kind 0x01, output_index
 *      100, unlock 0, owner = the delegator's fingerprint. LABELED
 *      NARROWING: native-token-only on both sides (the legacy staking
 *      applies summed only native DNAC and silently ignored any other
 *      token riding along).
 *
 *   7. SYSTEM / DNA_SYSRULE_DELEGATE (2) · DNA_SYSRULE_UNSTAKE (3) ·
 *      DNA_SYSRULE_UNDELEGATE (4) (legacy tx 5/6/7 — O11 S2+S3): the
 *      rest of the stake lifecycle, each documented at its own executor
 *      (rtn_delegate_exec / rtn_unstake_exec / rtn_undelegate_exec) with
 *      the apply_* site it preserves. All five SYSTEM record ops (1-5)
 *      share the 2-leg envelope shape, the one-signer call-identity
 *      authority rule and the CORE funding leg; they differ only in which
 *      rows they read and which columns they move. Every
 *      validator/delegation row they write is built FROM the record the
 *      mediated read observed and bound to it by EXISTS_VHASH, so a
 *      transition can only change the columns it names.
 *
 *   8. SYSTEM / DNA_SYSRULE_VALIDATOR_UPDATE (runtime_op 5, legacy tx 9
 *      — O12 S1): the validator's own commission change. Source
 *      semantics preserved from apply_validator_update
 *      (nodus_witness_bft.c:1934-2003): the row must exist and be in an
 *      updatable status (ACTIVE / ELIGIBLE / RETIRING — UNSTAKED and
 *      AUTO_RETIRED have frozen stake, :1970-1976); an INCREASE is
 *      DEFERRED one full epoch of delegator notice
 *      (pending_commission_bps + pending_effective_block, :1978-1987);
 *      a DECREASE (or an equal value) takes effect immediately and
 *      CLEARS any stale pending entry (:1987-1992); and
 *      last_validator_update_block always records the executing height
 *      (Rule K cooldown, :1993). Nothing else moves — no stake, no
 *      delegation total, no counter, no supply, no snapshot. Its funding
 *      leg is FEE-ONLY (lock = release = 0, the UNSTAKE shape).
 *
 * Every OTHER runtime_op the two descriptors own is a DETERMINISTIC
 * REJECT in these hooks until its own migration slice — ownership is
 * expressible, execution is fail-closed. Today that is CORE 4..6 (the
 * three C3 boundary rules).
 *
 * ── The verified authorization boundary ───────────────────────────────
 * nodus_rt_auth_dsa87_v1 is the ONE compiled implementation of
 * auth_kind 1 (both production entries bind the same symbol — scheme
 * verification cannot fork per domain). It verifies every signature
 * against the ENGINE-derived leg auth_digest, which commits — through
 * auth_context_commit (env_wire.h) — the chain identity, expiry, fee,
 * resource ceilings, and every leg's domain / runtime_op / ruleset
 * identity / call bytes. Changing ANY of them invalidates every
 * signature; the signature bytes themselves are covered only by the
 * full-wire wire_id (non-circularity). The verdict is ENGINE-owned: the caller cannot
 * supply one (no envelope field exists), the runtime cannot declare one
 * (exec only READS ctx->auth), and authorization work is priced once by
 * w_authbyte at reservation (no second charge anywhere).
 *
 * ── Canonical call_data encodings (JUDGMENT, independently tested) ────
 * The envelope framing layer treats call_data as opaque; the layouts
 * below are THIS release's canonical operation encodings, built by the
 * repository's standard conventions (fixed-width big-endian, exact
 * lengths, strictly ascending iteration, fail-closed decode).
 *
 * SPEND call v1 (exact length = 2 + 64*in + 232*out):
 *   in_count  u8   1..15   ── 15, not the legacy 16: the read budget is
 *                             NODUS_RT_MAX_READS(16) = 15 input reads +
 *                             1 supply read (honest narrowing, labeled)
 *   in_count × nullifier[64]              STRICTLY ascending
 *   out_count u8   1..16   (NODUS_T3_MAX_TX_OUTPUTS)
 *   out_count × ( owner_fp[128]           lowercase hex, exactly 128
 *               ‖ amount u64 BE
 *               ‖ token_id[64]            all-zero = native DNAC
 *               ‖ seed[32] )
 *
 * BURN call v1 (exact length = 2 + 64*in + 232*out + 8 — burn season;
 * CORE ruleset_version 2 enables ops 2 and 3, see runtime.c):
 *   the SPEND transfer section (in_count 1..15, out_count 0..16 — a
 *   full-value burn creates nothing) ‖ burn_amount u64 BE (>= 1; a
 *   zero burn IS a SPEND and has exactly one canonical encoding)
 *
 * TOKEN_CREATE call v1 (exact length = 109-fixed-max + 64*in + 232*out
 * — burn season):
 *   token_id[64]  (the NEW token — never the all-zero native id)
 *   ‖ name_len u8 (1..32) ‖ name  (printable ASCII minus ':')
 *   ‖ sym_len  u8 (1..8)  ‖ sym   (same rule)
 *   ‖ decimals u8 (0..18)
 *   ‖ transfer section (in_count 1..14 — the read budget funds 14
 *     input reads + 1 supply read + 1 registry read; out_count 1..16,
 *     output[0] = the token genesis output, outputs[1..] native)
 *
 * SYSFUND call v1 (exact length = 2 + 64*in + 232*out — O11): EXACTLY
 * the SPEND transfer section, in_count 1..15, out_count 0..16 (a bond
 * that consumes the whole input set creates no change — the BURN
 * precedent), every output NATIVE. No amount field of its own.
 *
 * SYSTEM stake-lifecycle calls v1 (O11 — all BE, all exact-length; the
 * shared decoder block below the auth section holds the parsers, since
 * both domains' hooks consume them):
 *   STAKE      (op 1) staker_pubkey[2592] ‖ commission_bps u16
 *                     ‖ bond u64 ‖ unstake_destination_fp[64 raw] = 2666
 *   DELEGATE   (op 2) delegator_pubkey[2592] ‖ validator_pubkey[2592]
 *                     ‖ amount u64                                 = 5192
 *   UNSTAKE    (op 3) validator_pubkey[2592]                       = 2592
 *   UNDELEGATE (op 4) same layout as DELEGATE                      = 5192
 *   VALIDATOR_UPDATE (op 5, O12 S1)
 *                     identity_pubkey[2592] ‖ new_commission_bps u16
 *                                                                 = 2594
 * All five EXECUTE (S1 shipped op 1; S2+S3 the rest; O12 S1 op 5). The
 * CORE funding leg derives its lock/release from these same layouts,
 * through the same compiled parsers.
 *
 * ⚠ DELIBERATELY DROPPED on V2 — the legacy VALIDATOR_UPDATE wire also
 * carried `signed_at_block[8 BE]` after the bps field (bft.c:1913,
 * 1944). The witness NEVER read it: apply_validator_update decodes the
 * bps and states outright that signed_at_block is "a verify-time field
 * (freshness); not consumed here" (bft.c:1932, 1951). On V2 that role
 * belongs to the ENVELOPE — expiry_height is committed by
 * auth_context_commit and the committed-intent replay guard closes
 * re-submission — so carrying a second, runtime-owned freshness field
 * would be inventing a rule the source never enforced and giving one
 * intent many encodings. The call is 2594 bytes, exactly.
 *
 * CHAIN_CONFIG call v2 (exact length = 41 — capacity season; SYSTEM
 * ruleset_version IS the call-format version, the repository's
 * versioning axis for runtime-call semantics):
 *   param_id u8 ‖ new_value u64 ‖ effective u64 ‖ nonce u64
 *   ‖ signed_at u64 ‖ valid_before u64
 *   The call now carries ONLY the canonical proposal. Committee
 *   approval evidence — formerly vote_count(5..8) × (pubkey ‖ sig)
 *   INSIDE these call bytes, capped by the old 64 KiB envelope fit —
 *   moved into versioned AUTHORIZATION evidence: auth_kind 2
 *   (NODUS_RT_AUTHKIND_DSA87_CC_V1, nodus_witness_runtime.h), which
 *   references the ENGINE-resolved governing snapshot by index and so
 *   scales to the full release validator ceiling
 *   (DNA_MAX_ACTIVE_VALIDATORS) under the derived 1 MiB envelope bound.
 *   The v1 call format is RETIRED with SYSTEM ruleset v1 (no committed
 *   consumer exists — Ledger V2 is inactive); v1 bytes are never
 *   reinterpreted: a v1 leg names ruleset_version 1, which no compiled
 *   runtime resolves any more.
 *
 * ── Capacity derivation (the DNA_ENV_MAX_TOTAL_LEN proof) ─────────────
 * The _Static_asserts below pin the worst-case LEGAL envelope shapes
 * against the constants they derive from; the independent oracle
 * (shared/dnac/tests/env_wire_oracle.py) reproduces the same numbers:
 *   single leg, CHAIN_CONFIG carrying ALL 128 release-ceiling approvals:
 *     43 + 30 + 41 + (1 + 15×7219) + (2 + 128×4629) = 700,914
 *   plus a maximal 15-distinct-owner / 16-output SPEND leg (the largest
 *   legal multi-leg composition under the per-runtime auth-kind
 *   allowlists — CORE legs carry kind 1 only):
 *     + 30 + (2 + 15×64 + 16×232) + (1 + 15×7219) = 813,904
 *   both <= 1,048,576 = DNA_ENV_MAX_TOTAL_LEN = 2^20 (the smallest
 *   power of two containing the worst case).
 *
 * ── Honest divergences from the legacy lane (all fail-closed) ─────────
 *   - PER-TOKEN conservation: Σin == Σout per non-native token and
 *     Σnative_in == Σnative_out + fee. The legacy verify sums tokens
 *     blindly (verify.c:753-758 / 792); the block-level supply gate is
 *     what caught native imbalance there. Here no value can be created
 *     or destroyed per token, at the transaction boundary.
 *   - NO spent-nullifier audit insert: V2 replay protection is the
 *     UTXO row itself (spend deletes it; re-spend = missing input) plus
 *     the engine's derived-id replay matrix. The legacy `nullifiers`
 *     table stays a legacy-lane structure.
 *   - Duplicate output identity REJECTS (legacy utxo_add dropped the
 *     row silently); an output whose identity equals a still-live row
 *     (including one of this leg's own inputs) rejects via the
 *     CREATE/ABSENT precondition — canonical order applies CREATEs
 *     before DELETEs.
 *   - created_at / created_at_unix are written 0: deterministic lane,
 *     no wall clock (both columns are audit-only — neither enters the
 *     UTXO merkle leaf (nodus_witness_merkle.c:136) nor the
 *     chain-config leaf (nodus_witness_chain_config.c:389)).
 *   - supply_tracking.last_tx_hash is left unchanged (audit column;
 *     the typed effect carries no side-band audit payload).
 *   - a SYSTEM CHAIN_CONFIG leg requires envelope fee_amount == 0:
 *     the legacy lane funds its fee from CORE inputs inside the same
 *     transaction; a single-leg SYSTEM envelope has no funding leg, and
 *     inventing a SYSTEM fee sink would be inventing economics. The
 *     cross-domain fee leg is a later season.
 *
 * ── Purity ────────────────────────────────────────────────────────────
 * The auth/read_plan/exec hooks touch NO database, NO clock, NO RNG and
 * allocate NOTHING (a hook has no node-fault-free failure channel for
 * allocation; -2 is reserved for hash/crypto backend failure). The
 * compiled adapters at the bottom are the ONLY storage-touching code,
 * reached exclusively through the engine's mediated read / validated
 * effect paths, always scoped by the resolved runtime's own domain id.
 *
 * @file nodus_witness_rt_native.c
 */

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_runtime.h"
#include "witness/nodus_witness_v2_adapter.h"
#include "nodus/nodus_chain_config.h"

#include "dnac/dnac.h"                 /* DNAC_MIN_FEE_RAW, DNAC_CFG_*   */
#include "dnac/validator.h"            /* DNAC_VALIDATOR_ACTIVE (O11)    */
#include "dnac/ledger_ids.h"           /* dna_bft_quorum                 */
#include "dnac/effect_wire.h"
#include "dnac/res_meter.h"            /* dna_ck_add_u64                 */
#include "crypto/hash/qgp_sha3.h"
#include "crypto/sign/qgp_dilithium.h" /* qgp_dsa87_verify               */

#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>

/* ── Local wire helpers (BE, the shared/dnac discipline) ────────────── */
static uint64_t rtn_get64(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | p[i];
    return v;
}
static void rtn_put64(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (56 - 8 * i));
}
static void rtn_put32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);  p[3] = (uint8_t)v;
}

/* ══════════════════════════════════════════════════════════════════════
 * The shared authorization implementation — kinds 1 and 2
 * (contract: runtime.h; ONE compiled symbol for both production
 * entries, so scheme verification cannot fork per domain)
 * ════════════════════════════════════════════════════════════════════ */

/* The operation-shape bounds participate in the capacity derivation, so
 * they are defined HERE, ahead of the asserts that consume them (their
 * consumers live in the CORE/SYSTEM sections below). */
#define RTN_SPEND_MAX_IN      15u  /* NODUS_RT_MAX_READS - 1 supply read */
#define RTN_SPEND_MAX_OUT     16u  /* NODUS_T3_MAX_TX_OUTPUTS            */
#define RTN_SPEND_OUT_LEN     232u /* fp128 + amount8 + token64 + seed32 */
/* BURN call v1 = the SPEND transfer surface + one explicit trailing
 * burn_amount u64 (burn season). Same read budget, and out_count may be
 * 0 (a full-value burn creates nothing). */
#define RTN_BURN_MAX_IN       RTN_SPEND_MAX_IN
#define RTN_BURN_MAX_OUT      RTN_SPEND_MAX_OUT
/* TOKEN_CREATE call v1 (burn season): the read budget funds in_count
 * input reads + 1 supply read + 1 token-registry read, so the input
 * ceiling narrows to NODUS_RT_MAX_READS(16) − 2 = 14 (the SPEND 15-of-16
 * honest-narrowing precedent). Field bounds are the CLIENT builder's
 * rules (dnac/src/transaction/token_create.c:52-56 — the one shipped
 * producer; the legacy witness never checked them: JUDGMENT, fail-closed
 * direction). */
#define RTN_TC_MAX_IN         14u
#define RTN_TC_MAX_OUT        16u  /* NODUS_T3_MAX_TX_OUTPUTS            */
#define RTN_TC_NAME_MAX       32u
#define RTN_TC_SYM_MAX        8u
#define RTN_TC_DECIMALS_MAX   18u
/** CHAIN_CONFIG call v2: the canonical PROPOSAL, nothing else (header
 *  block — approval evidence lives in auth_kind 2). Exact length. */
#define RTN_CC_CALL_LEN  41u

/* Capacity-derivation pins (header block above). Every participating
 * bound enters BY MACRO — a drift in any of them re-derives, or breaks,
 * the envelope ceiling visibly (review finding: literals would go
 * drift-blind on the call-shape side). */
_Static_assert(NODUS_RT_AUTH_APPROVAL_LEN == 2u + (unsigned)NODUS_CC_SIG_SIZE,
               "kind-2 approval unit drifted");
_Static_assert((unsigned)DNA_ENV_FIXED_HEAD + DNA_ENV_LEG_HDR_LEN +
                   RTN_CC_CALL_LEN +
                   (1u + (unsigned)NODUS_RT_AUTH_MAX_SIGNERS *
                             NODUS_RT_AUTH_SIGNER_LEN) +
                   (2u + (unsigned)DNA_MAX_ACTIVE_VALIDATORS *
                             NODUS_RT_AUTH_APPROVAL_LEN) == 700914u,
               "worst-case single-leg CHAIN_CONFIG envelope drifted");
_Static_assert(700914u + DNA_ENV_LEG_HDR_LEN +
                   (2u + RTN_SPEND_MAX_IN * 64u +
                    RTN_SPEND_MAX_OUT * RTN_SPEND_OUT_LEN) +
                   (1u + (unsigned)NODUS_RT_AUTH_MAX_SIGNERS *
                             NODUS_RT_AUTH_SIGNER_LEN) == 813904u,
               "worst-case CC+SPEND two-leg envelope drifted");
/* Burn season: the worst CORE leg is now TOKEN_CREATE (its call is 43
 * bytes longer than the maximal SPEND call: 109 fixed + 14*64 + 16*232
 * = 4717 vs 4674), so the worst framing-legal envelope is CC + one
 * maximal TOKEN_CREATE leg. The BURN call (SPEND + 8) sits between the
 * two and is dominated. */
_Static_assert((64u + 1u + RTN_TC_NAME_MAX + 1u + RTN_TC_SYM_MAX + 1u +
                1u + RTN_TC_MAX_IN * 64u +
                1u + RTN_TC_MAX_OUT * RTN_SPEND_OUT_LEN) == 4717u,
               "maximal TOKEN_CREATE call drifted");
_Static_assert(700914u + DNA_ENV_LEG_HDR_LEN + 4717u +
                   (1u + (unsigned)NODUS_RT_AUTH_MAX_SIGNERS *
                             NODUS_RT_AUTH_SIGNER_LEN) == 813947u,
               "worst-case CC+TOKEN_CREATE two-leg envelope drifted");
/* "Worst case" means worst FRAMING-AND-ALLOWLIST-legal: an envelope the
 * pre-BEGIN admission scan and the authorization stage accept and the
 * block therefore RESERVES AND PAYS FOR, whether or not exec later
 * rejects it (the CC+TC pair above can never execute — fee rules are
 * mutually exclusive; the O11 stake shapes below verify their kind-2
 * signatures and die only at exec's own authority rule). Over-covering
 * is the conservative direction for an admission bound.
 *
 * O11: the CC-carrying shapes above are now DOMINATED — a SYSTEM
 * DELEGATE/UNDELEGATE leg carries a 5192-byte call under the same
 * maximal kind-2 blob (SYSTEM's allowlist permits carriage; the op's
 * exec rejects kind 2, AFTER the block already accounted for it). The
 * governing worst-case asserts live with the stake call macros below
 * (search: "O11 capacity derivation"); the two shapes here stay pinned
 * as identities because the oracle and test_v2_capacity re-derive both
 * as control legs. */
/* TOKEN_CREATE checks ONLY its own creation floor: that is sound iff the
 * creation fee dominates BOTH generic floors — pinned, not assumed. */
_Static_assert(NODUS_W_TOKEN_CREATE_FEE >= DNAC_MIN_FEE_RAW &&
                   NODUS_W_TOKEN_CREATE_FEE >= NODUS_W_BASE_TX_FEE,
               "the TOKEN_CREATE fee floor no longer dominates the "
               "generic fee floors — re-derive the rtn_tc_exec fee gate");

/* ── Capacity-season tags (each EXACTLY 16 bytes, zero-padded ASCII —
 *    the env_wire.c discipline; collision-scanned against the full
 *    "DNA.*" namespace, 64 tags at introduction time). ──────────────── */

/** "DNA.CCSET.v1" (12 chars) + 4 zero bytes — resolved-committee-set
 *  hash. */
static const uint8_t TAG_CCSET[16] = {
    'D','N','A','.','C','C','S','E','T','.','v','1', 0, 0, 0, 0
};
/** "DNA.CCAPPR.v1" (13 chars) + 3 zero bytes — committee approval
 *  digest. */
static const uint8_t TAG_CCAPPR[16] = {
    'D','N','A','.','C','C','A','P','P','R','.','v','1', 0, 0, 0
};

int nodus_rt_committee_set_hash(const uint8_t (*fps)[64], uint32_t count,
                                uint8_t out[64]) {
    if (!fps || !out) return -1;
    if (count == 0 || count > DNA_MAX_ACTIVE_VALIDATORS) return -1;
    /* preimage: tag(16) ‖ count u16 BE ‖ count × fp[64] — the fps in
     * COMMITTEE ORDER (the stake-ranked order the resolution returns),
     * so the hash commits both membership AND seat positions. Stack:
     * 18 + 128×64 = 8210 bytes max. */
    uint8_t pre[16 + 2 + (size_t)DNA_MAX_ACTIVE_VALIDATORS * 64];
    size_t off = 0;
    memcpy(pre + off, TAG_CCSET, 16); off += 16;
    pre[off++] = (uint8_t)(count >> 8);
    pre[off++] = (uint8_t)count;
    for (uint32_t i = 0; i < count; i++) {
        memcpy(pre + off, fps[i], 64);
        off += 64;
    }
    return qgp_sha3_512(pre, off, out) == 0 ? 0 : -1;
}

int nodus_rt_cc_approval_digest(const uint8_t leg_auth_digest[64],
                                const uint8_t set_hash[64],
                                uint64_t epoch, uint16_t index,
                                uint8_t out[64]) {
    if (!leg_auth_digest || !set_hash || !out) return -1;
    /* preimage: tag(16) ‖ leg_auth_digest(64) ‖ set_hash(64)
     * ‖ epoch u64 BE ‖ index u16 BE = 154 bytes. Binds everything the
     * submitter signature binds (through leg_auth_digest →
     * auth_context_commit: chain, domain, runtime_op, ruleset identity,
     * proposal call bytes, fee, expiry, resource ceilings) PLUS the
     * exact governing snapshot (set hash + epoch) and the signer's own
     * seat — a vote cannot be replayed against another committee,
     * another epoch, or from another seat. */
    uint8_t pre[16 + 64 + 64 + 8 + 2];
    size_t off = 0;
    memcpy(pre + off, TAG_CCAPPR, 16); off += 16;
    memcpy(pre + off, leg_auth_digest, 64); off += 64;
    memcpy(pre + off, set_hash, 64); off += 64;
    rtn_put64(pre + off, epoch); off += 8;
    pre[off++] = (uint8_t)(index >> 8);
    pre[off++] = (uint8_t)index;
    if (off != sizeof(pre)) return -1;   /* final-offset proof           */
    return qgp_sha3_512(pre, off, out) == 0 ? 0 : -1;
}

/**
 * Parse + verify the SUBMITTER section (the whole kind-1 body; kind 2's
 * leading section). Fills the verdict's signer fields.
 * @param exact  non-zero = the section must consume alen EXACTLY
 *               (kind 1); zero = a tail may follow (kind 2).
 * @return 0 with *consumed_out set / -1 reject / -2 node fault.
 */
static int rtn_auth_submitters(const uint8_t *a, uint32_t alen,
                               const uint8_t digest[64], int exact,
                               nodus_rt_auth_verdict_t *out,
                               uint64_t *consumed_out) {
    if (alen < 1) return -1;
    uint32_t n = a[0];
    if (n < 1 || n > NODUS_RT_AUTH_MAX_SIGNERS) return -1;
    /* checked framing arithmetic (mutation target: a truncating
     * multiply must break the LEGAL maximum shape, not overflow) */
    uint64_t body = 0, need = 0;
    if (dna_ck_mul_u64((uint64_t)n, NODUS_RT_AUTH_SIGNER_LEN, &body) != 0 ||
        dna_ck_add_u64(1u, body, &need) != 0)
        return -1;
    if (exact ? ((uint64_t)alen != need) : ((uint64_t)alen < need))
        return -1;
    const uint8_t *prev_pk = NULL;
    for (uint32_t i = 0; i < n; i++) {
        const uint8_t *pk  = a + 1 + (size_t)i * NODUS_RT_AUTH_SIGNER_LEN;
        const uint8_t *sig = pk + NODUS_CC_PUBKEY_SIZE;
        /* zero-pubkey reject (the verify.c:657 discipline: first 32
         * bytes all zero marks a null key) */
        int allz = 1;
        for (int k = 0; k < 32 && allz; k++)
            if (pk[k] != 0) allz = 0;
        if (allz) return -1;
        /* strictly ascending pubkeys: ONE canonical encoding per signer
         * set — duplicates and disorder both reject */
        if (prev_pk && memcmp(prev_pk, pk, NODUS_CC_PUBKEY_SIZE) >= 0)
            return -1;
        prev_pk = pk;
        if (qgp_dsa87_verify(sig, NODUS_CC_SIG_SIZE, digest, 64, pk) != 0)
            return -1;                   /* invalid signature: reject    */
        if (qgp_sha3_512(pk, NODUS_CC_PUBKEY_SIZE,
                         out->signer_fp[i]) != 0)
            return -2;                   /* hash backend: NODE fault     */
    }
    out->n_signers = (uint16_t)n;
    *consumed_out = need;
    return 0;
}

int nodus_rt_auth_dsa87_v1(const nodus_domain_runtime_t *rt,
                           const dna_env_view_t *env, uint16_t leg_index,
                           const nodus_rt_exec_ctx_t *ctx,
                           nodus_rt_auth_verdict_t *out) {
    (void)rt;
    if (!env || !ctx || !ctx->leg_auth_digest || !out) return -2;
    memset(out, 0, sizeof(*out));
    if (leg_index >= env->leg_count || !env->buf) return -2;

    const dna_env_leg_hdr_t *h = &env->leg[leg_index];
    const uint8_t *a = env->buf + env->auth_off[leg_index];
    uint32_t alen = h->auth_len;

    if (h->auth_kind == NODUS_RT_AUTHKIND_DSA87_MULTI_V1) {
        uint64_t consumed = 0;
        int rc = rtn_auth_submitters(a, alen, ctx->leg_auth_digest,
                                     /*exact=*/1, out, &consumed);
        if (rc != 0) { memset(out, 0, sizeof(*out)); return rc; }
        return 0;
    }

    if (h->auth_kind == NODUS_RT_AUTHKIND_DSA87_CC_V1) {
        /* the ENGINE-resolved governing snapshot is this kind's one
         * extra input; the engine provides it for every kind-2 leg, so
         * a missing view is a broken engine invariant on THIS node */
        const nodus_rt_committee_t *cm = ctx->committee;
        if (!cm) { memset(out, 0, sizeof(*out)); return -2; }
        if (cm->count == 0 || cm->count > DNA_MAX_ACTIVE_VALIDATORS ||
            !cm->pubkeys) {
            /* a chain with no committee cannot carry committee
             * evidence — deterministic reject, never a fault */
            memset(out, 0, sizeof(*out));
            return -1;
        }

        uint64_t consumed = 0;
        int rc = rtn_auth_submitters(a, alen, ctx->leg_auth_digest,
                                     /*exact=*/0, out, &consumed);
        if (rc != 0) { memset(out, 0, sizeof(*out)); return rc; }

        /* approval section: count u16 BE ‖ count × (idx u16 ‖ sig) —
         * EXACT framing, checked arithmetic throughout */
        if ((uint64_t)alen < consumed + 2) {
            memset(out, 0, sizeof(*out));
            return -1;
        }
        const uint8_t *ap = a + consumed;
        uint32_t ac = ((uint32_t)ap[0] << 8) | ap[1];
        if (ac < 1 || ac > cm->count) {
            memset(out, 0, sizeof(*out));
            return -1;                   /* more approvals than seats    */
        }
        uint64_t abody = 0, total = 0;
        if (dna_ck_mul_u64((uint64_t)ac, NODUS_RT_AUTH_APPROVAL_LEN,
                           &abody) != 0 ||
            dna_ck_add_u64(consumed + 2, abody, &total) != 0 ||
            (uint64_t)alen != total) {
            memset(out, 0, sizeof(*out));
            return -1;                   /* truncated / trailing bytes   */
        }
        int32_t prev_idx = -1;
        for (uint32_t v = 0; v < ac; v++) {
            const uint8_t *slot = ap + 2 +
                                  (size_t)v * NODUS_RT_AUTH_APPROVAL_LEN;
            uint16_t idx = (uint16_t)(((uint16_t)slot[0] << 8) | slot[1]);
            /* STRICTLY increasing seats: duplicates and disorder reject
             * — one-validator-one-vote is structural, not counted */
            if ((int32_t)idx <= prev_idx) {
                memset(out, 0, sizeof(*out));
                return -1;
            }
            prev_idx = (int32_t)idx;
            if ((uint32_t)idx >= cm->count) {
                memset(out, 0, sizeof(*out));
                return -1;               /* seat outside the snapshot    */
            }
            uint8_t adigest[64];
            if (nodus_rt_cc_approval_digest(ctx->leg_auth_digest,
                                            cm->set_hash, cm->epoch, idx,
                                            adigest) != 0) {
                memset(out, 0, sizeof(*out));
                return -2;               /* hash backend: NODE fault     */
            }
            /* the pubkey comes from the SNAPSHOT — the wire carries
             * only the seat index */
            const uint8_t *pk = cm->pubkeys +
                                (size_t)idx * NODUS_CC_PUBKEY_SIZE;
            if (qgp_dsa87_verify(slot + 2, NODUS_CC_SIG_SIZE, adigest,
                                 64, pk) != 0) {
                memset(out, 0, sizeof(*out));
                return -1;               /* invalid approval: reject     */
            }
        }
        out->n_approvals = (uint16_t)ac;
        out->committee_n = (uint16_t)cm->count;
        return 0;
    }

    return -1;                           /* unsupported scheme: reject   */
}

/* ══════════════════════════════════════════════════════════════════════
 * The SYSTEM validator-record CALL layer (O11; O12 S1 appends op 5) —
 * decoded by BOTH domains
 *
 * Placed AHEAD of the DNA_CORE section deliberately: the CORE funding op
 * DNA_CORERULE_SYSFUND carries NO amounts of its own — what a staking
 * envelope LOCKS or RELEASES is derived from the SIBLING SYSTEM leg's
 * CALL BYTES. Both hooks therefore decode these five layouts through the
 * SAME compiled parsers, so no second decoder exists that could disagree
 * with the first about what a record leg requested (the record leg and
 * the funding leg are one intent, split across two domains).
 *
 * All BE, all EXACT-LENGTH (a prefix is never accepted), all five bound
 * by DNAC_PUBKEY_SIZE so a key-size change re-derives them visibly.
 * ════════════════════════════════════════════════════════════════════ */

/** STAKE (op 1): staker_pubkey ‖ commission_bps u16 ‖ bond u64 ‖
 *  unstake_destination_fp[64 RAW SHA3-512 bytes]. */
#define RTN_SYS_STAKE_CALL_LEN       ((uint32_t)DNAC_PUBKEY_SIZE + 2u + 8u + 64u)
/** DELEGATE (op 2): delegator_pubkey ‖ validator_pubkey ‖ amount u64. */
#define RTN_SYS_DELEGATE_CALL_LEN    (2u * (uint32_t)DNAC_PUBKEY_SIZE + 8u)
/** UNSTAKE (op 3): validator_pubkey. */
#define RTN_SYS_UNSTAKE_CALL_LEN     ((uint32_t)DNAC_PUBKEY_SIZE)
/** UNDELEGATE (op 4): same shape as DELEGATE (a different rule reading
 *  the same three fields — one layout, two ops, never one "generic"
 *  op with a mode byte). */
#define RTN_SYS_UNDELEGATE_CALL_LEN  RTN_SYS_DELEGATE_CALL_LEN
/** VALIDATOR_UPDATE (op 5, O12 S1): identity_pubkey ‖
 *  new_commission_bps u16. The legacy wire's trailing signed_at_block[8]
 *  is DELIBERATELY DROPPED — see the "DELIBERATELY DROPPED" block in the
 *  file header for why (the witness never read it; the ENVELOPE owns
 *  freshness on V2). */
#define RTN_SYS_VUPD_CALL_LEN        ((uint32_t)DNAC_PUBKEY_SIZE + 2u)
_Static_assert(RTN_SYS_STAKE_CALL_LEN == 2666u,
               "STAKE call length drifted");
_Static_assert(RTN_SYS_DELEGATE_CALL_LEN == 5192u,
               "DELEGATE/UNDELEGATE call length drifted");
_Static_assert(RTN_SYS_UNSTAKE_CALL_LEN == 2592u,
               "UNSTAKE call length drifted");
_Static_assert(RTN_SYS_VUPD_CALL_LEN == 2594u,
               "VALIDATOR_UPDATE call length drifted");
_Static_assert(RTN_SYS_VUPD_CALL_LEN < RTN_SYS_DELEGATE_CALL_LEN,
               "VALIDATOR_UPDATE is no longer dominated by the DELEGATE "
               "call — re-derive the worst-case envelope asserts below");

/* ── O11 capacity derivation — the governing worst case ──────────────
 * Every bound enters BY MACRO (the capacity-season discipline). The
 * worst framing-and-allowlist-legal SINGLE leg is a SYSTEM DELEGATE /
 * UNDELEGATE leg (call 5192 — the longest call any compiled runtime
 * accepts) under the maximal kind-2 authorization blob (15-signer
 * submitter body + all 128 release-ceiling approvals — SYSTEM's
 * allowlist permits the CARRIAGE; the op's exec rejects kind 2 only
 * after admission and authorization already priced it). The worst
 * envelope pairs it with the largest CORE leg the same standard admits.
 * ⚠ That is TOKEN_CREATE (call 4717), NOT the SYSFUND sibling (4674):
 * the SYSFUND-sibling requirement lives in the read_plan/exec hooks
 * (rtn_sys_stake_shape), NOT in rt_admit_common — admission inspects
 * only (tx_type, pool), so a {DELEGATE(kind-2), TOKEN_CREATE(kind-1)}
 * envelope is admission-legal, PRICED at reservation, and dies only at
 * exec (O11 R1 review finding: the originally pinned SYSFUND pairing,
 * 819,055 B, is DOMINATED by the mixed shape below).
 * Re-derived independently by test_v2_capacity.c and
 * shared/dnac/tests/env_wire_oracle.py — all three must agree. */
_Static_assert((unsigned)DNA_ENV_FIXED_HEAD + DNA_ENV_LEG_HDR_LEN +
                   RTN_SYS_DELEGATE_CALL_LEN +
                   ((1u + (unsigned)NODUS_RT_AUTH_MAX_SIGNERS *
                              NODUS_RT_AUTH_SIGNER_LEN) +
                    (2u + (unsigned)DNA_MAX_ACTIVE_VALIDATORS *
                              NODUS_RT_AUTH_APPROVAL_LEN)) == 706065u,
               "worst-case single-leg stake-lifecycle envelope drifted");
_Static_assert((2u + RTN_SPEND_MAX_IN * 64u +
                RTN_SPEND_MAX_OUT * RTN_SPEND_OUT_LEN) == 4674u,
               "maximal SYSFUND/SPEND transfer-section call drifted");
_Static_assert(706065u + DNA_ENV_LEG_HDR_LEN + 4674u +
                   (1u + (unsigned)NODUS_RT_AUTH_MAX_SIGNERS *
                             NODUS_RT_AUTH_SIGNER_LEN) == 819055u,
               "DELEGATE+SYSFUND two-leg shape drifted (dominated)");
_Static_assert(706065u + DNA_ENV_LEG_HDR_LEN + 4717u +
                   (1u + (unsigned)NODUS_RT_AUTH_MAX_SIGNERS *
                             NODUS_RT_AUTH_SIGNER_LEN) == 819098u,
               "worst-case DELEGATE+TOKEN_CREATE two-leg envelope "
               "drifted");
_Static_assert(819098u > 819055u && 819098u > 813947u,
               "the mixed DELEGATE+TOKEN_CREATE shape no longer "
               "dominates — re-derive which pair governs the ceiling");
_Static_assert(819098u <= (unsigned)DNA_ENV_MAX_TOTAL_LEN,
               "envelope ceiling no longer contains the worst legal "
               "envelope — re-derive DNA_ENV_MAX_TOTAL_LEN");
_Static_assert(819098u > (unsigned)DNA_ENV_MAX_TOTAL_LEN / 2u,
               "the ceiling is no longer the SMALLEST containing power "
               "of two — re-derive DNA_ENV_MAX_TOTAL_LEN");

typedef struct {
    const uint8_t *staker_pubkey;        /* [DNAC_PUBKEY_SIZE]           */
    uint16_t       commission_bps;
    uint64_t       bond;
    const uint8_t *dest_fp;              /* [64] RAW fingerprint bytes   */
} rtn_stake_call_t;

typedef struct {
    const uint8_t *delegator_pubkey;     /* [DNAC_PUBKEY_SIZE]           */
    const uint8_t *validator_pubkey;     /* [DNAC_PUBKEY_SIZE]           */
    uint64_t       amount;
} rtn_deleg_call_t;

typedef struct {
    const uint8_t *validator_pubkey;     /* [DNAC_PUBKEY_SIZE]           */
    uint16_t       new_commission_bps;
} rtn_vupd_call_t;

static int rtn_stake_parse(const uint8_t *p, uint32_t len,
                           rtn_stake_call_t *c) {
    if (len != RTN_SYS_STAKE_CALL_LEN) return -1;
    c->staker_pubkey  = p;
    c->commission_bps = (uint16_t)(((uint16_t)p[DNAC_PUBKEY_SIZE] << 8) |
                                   p[DNAC_PUBKEY_SIZE + 1]);
    c->bond           = rtn_get64(p + DNAC_PUBKEY_SIZE + 2);
    c->dest_fp        = p + DNAC_PUBKEY_SIZE + 10;
    return 0;
}

static int rtn_deleg_parse(const uint8_t *p, uint32_t len,
                           rtn_deleg_call_t *c) {
    if (len != RTN_SYS_DELEGATE_CALL_LEN) return -1;
    c->delegator_pubkey = p;
    c->validator_pubkey = p + DNAC_PUBKEY_SIZE;
    c->amount           = rtn_get64(p + 2 * DNAC_PUBKEY_SIZE);
    return 0;
}

/**
 * VALIDATOR_UPDATE (op 5, O12 S1). Three rejects live in the DECODER
 * rather than in exec, so BOTH domains' hooks agree about a malformed
 * record call before either of them writes anything:
 *   - exact length (never a prefix, never the legacy 2602-byte form);
 *   - new_commission_bps <= DNAC_COMMISSION_BPS_MAX — the bound
 *     apply_validator_update itself enforces (bft.c:1953-1957), so this
 *     one is SOURCE-preserved rather than the labeled narrowing STAKE
 *     carries;
 *   - an all-zero identity pubkey: no ML-DSA-87 key hashes to the
 *     fingerprint of the zero key that any signer could produce, so an
 *     all-zero identity can only ever be a malformed call. Fail-closed at
 *     the decoder instead of relying on the authority gate's memcmp.
 * @return 0 / -1 deterministic reject.
 */
static int rtn_vupd_parse(const uint8_t *p, uint32_t len,
                          rtn_vupd_call_t *c) {
    static const uint8_t zero_pk[DNAC_PUBKEY_SIZE] = { 0 };
    if (len != RTN_SYS_VUPD_CALL_LEN) return -1;
    if (memcmp(p, zero_pk, DNAC_PUBKEY_SIZE) == 0) return -1;
    c->validator_pubkey    = p;
    c->new_commission_bps  = (uint16_t)(((uint16_t)p[DNAC_PUBKEY_SIZE] << 8) |
                                        p[DNAC_PUBKEY_SIZE + 1]);
    if (c->new_commission_bps > DNAC_COMMISSION_BPS_MAX) return -1;
    return 0;
}

/** The five runtime ops this layer decodes (SYS_RULES 1..5). O12 S1
 *  appends VALIDATOR_UPDATE: it is not a stake-lifecycle transition, but
 *  it IS a validator-record op and shares the family's whole envelope
 *  contract — the 2-leg shape, the one-signer call-identity authority
 *  rule and the CORE funding sibling (fee-only, lock = release = 0). The
 *  range check stays contiguous because the SYS_RULES ids are. */
static int rtn_sys_is_stake_op(uint32_t op) {
    return op >= DNA_SYSRULE_STAKE && op <= DNA_SYSRULE_VALIDATOR_UPDATE;
}

/**
 * The AUTHORIZING identity of one stake-lifecycle op, taken from its
 * CALL bytes — never from the envelope's authorization section. The call
 * is intent-committed (dna_env_call_commit → intent_leg_commit), so the
 * identity a row is written for is fixed BEFORE any witness signs; the
 * verdict only GATES it (see rtn_sys_stake_auth). Per legacy site:
 * STAKE signer[0] = staker (bft.c:1576), DELEGATE = delegator
 * (bft.c:1443), UNSTAKE = the validator itself (bft.c:1652),
 * UNDELEGATE = delegator (bft.c:1845), VALIDATOR_UPDATE = the validator
 * itself (bft.c:1939-1960 resolves the row by the SIGNER's pubkey — the
 * legacy wire had no identity field at all, so a V2 call that carries one
 * must bind it to the signer, which rtn_sys_stake_auth does).
 * @return 0 with *pk_out borrowed from the call / -1 reject.
 */
static int rtn_sys_call_identity(uint32_t op, const uint8_t *p,
                                 uint32_t len, const uint8_t **pk_out) {
    switch (op) {
    case DNA_SYSRULE_STAKE: {
        rtn_stake_call_t c;
        if (rtn_stake_parse(p, len, &c) != 0) return -1;
        *pk_out = c.staker_pubkey;
        return 0;
    }
    case DNA_SYSRULE_DELEGATE:
    case DNA_SYSRULE_UNDELEGATE: {
        rtn_deleg_call_t c;
        if (rtn_deleg_parse(p, len, &c) != 0) return -1;
        *pk_out = c.delegator_pubkey;
        return 0;
    }
    case DNA_SYSRULE_UNSTAKE:
        if (len != RTN_SYS_UNSTAKE_CALL_LEN) return -1;
        *pk_out = p;
        return 0;
    case DNA_SYSRULE_VALIDATOR_UPDATE: {
        rtn_vupd_call_t c;
        if (rtn_vupd_parse(p, len, &c) != 0) return -1;
        *pk_out = c.validator_pubkey;
        return 0;
    }
    default:
        return -1;
    }
}

/**
 * The value flow one stake-lifecycle op imposes on its CORE funding leg,
 * derived from the SYSTEM call bytes alone (design §4.3):
 *   STAKE       lock = bond      release = 0
 *   DELEGATE    lock = amount    release = 0
 *   UNSTAKE     lock = 0         release = 0  (fee-only funding; the
 *               principal is released at epoch-boundary graduation,
 *               bft.c:2404-2560 — a DEFERRED season, not silently
 *               reproduced here)
 *   UNDELEGATE  lock = 0         release = amount (immediate principal
 *               return, bft.c:1873-1877 — Rule O is client-lane only)
 *   VALIDATOR_UPDATE
 *               lock = 0         release = 0  (O12 S1: a commission
 *               change moves NO value at all — the funding leg exists
 *               only to pay the fee, exactly the UNSTAKE lock=0 side)
 * @return 0 / -1 (unparseable or foreign op).
 */
static int rtn_sys_call_flow(uint32_t op, const uint8_t *p, uint32_t len,
                             uint64_t *lock_out, uint64_t *release_out) {
    *lock_out = 0;
    *release_out = 0;
    switch (op) {
    case DNA_SYSRULE_STAKE: {
        rtn_stake_call_t c;
        if (rtn_stake_parse(p, len, &c) != 0) return -1;
        *lock_out = c.bond;
        return 0;
    }
    case DNA_SYSRULE_DELEGATE: {
        rtn_deleg_call_t c;
        if (rtn_deleg_parse(p, len, &c) != 0) return -1;
        *lock_out = c.amount;
        return 0;
    }
    case DNA_SYSRULE_UNSTAKE:
        return len == RTN_SYS_UNSTAKE_CALL_LEN ? 0 : -1;
    case DNA_SYSRULE_UNDELEGATE: {
        rtn_deleg_call_t c;
        if (rtn_deleg_parse(p, len, &c) != 0) return -1;
        *release_out = c.amount;
        return 0;
    }
    case DNA_SYSRULE_VALIDATOR_UPDATE: {
        rtn_vupd_call_t c;
        return rtn_vupd_parse(p, len, &c);   /* fee-only: both stay 0    */
    }
    default:
        return -1;
    }
}

/**
 * The tag-prefixed row key SHA3-512(tree_tag ‖ pubkey) — byte-identical
 * to nodus_merkle_leaf_key(tag, pubkey, DNAC_PUBKEY_SIZE, out), which is
 * what nodus_witness_validator.c compute_pubkey_hash and
 * nodus_witness_delegation.c delegation_row_hash both call. Reproduced
 * here for two reasons: a hook receives NO witness handle (and the
 * merkle module is a witness module), and nodus_merkle_leaf_key
 * ZERO-FILLS its output on a digest failure and returns void — a hook
 * must fail closed instead, never publish a substituted key.
 * @return 0 / -2 hash-backend NODE fault.
 */
static int rtn_tag_key(uint8_t tree_tag, const uint8_t *pubkey,
                       uint8_t out[64]) {
    uint8_t pre[1 + DNAC_PUBKEY_SIZE];
    pre[0] = tree_tag;
    memcpy(pre + 1, pubkey, DNAC_PUBKEY_SIZE);
    return qgp_sha3_512(pre, sizeof(pre), out) == 0 ? 0 : -2;
}

/**
 * The canonical 2-leg staking envelope shape, checked from the SYSTEM
 * side (design §4.1): leg0 = the SYSTEM record leg, leg1 = the CORE
 * DNA_CORERULE_SYSFUND funding leg. Single-leg forms and every other
 * sibling REJECT — a record without funding, or funding without a
 * record, is not expressible. Legs are strictly ascending by domain_id
 * (env_wire.h), and DNA_DOMAIN_SYSTEM < DNA_DOMAIN_CORE, so this is the
 * ONLY legal ordering.
 * @return 0 / -1 deterministic reject.
 */
static int rtn_sys_stake_shape(const dna_env_view_t *env,
                               uint16_t leg_index) {
    if (!rtn_sys_is_stake_op(env->leg[leg_index].runtime_op)) return -1;
    if (env->leg_count != 2 || leg_index != 0) return -1;
    if (env->leg[1].domain_id != DNA_DOMAIN_CORE) return -1;
    if (env->leg[1].runtime_op != DNA_CORERULE_SYSFUND) return -1;
    return 0;
}

/**
 * The authority rule EVERY stake-lifecycle op decides for itself
 * (runtime.h auth-kind-2 SCOPING NOTE): the leg must carry the ordinary
 * submitter scheme, the verdict must name EXACTLY ONE verified signer,
 * and that signer's fingerprint must equal SHA3-512 of the identity
 * pubkey the CALL carries. Consequences, both deliberate:
 *   - a kind-2 leg REJECTS here (SYSTEM's allowlist permits CARRIAGE;
 *     committee approval certifies no staking policy);
 *   - an extra-signer kind-1 twin REJECTS rather than writing a
 *     divergent row — the consensus row derives from call bytes only,
 *     so twin-stability is structural and this gate keeps the accepted
 *     witness set canonical too.
 * The identity comes from rtn_sys_call_identity, so the op → signer
 * mapping exists in exactly one place for all four operations.
 * @param fp_out receives SHA3-512(identity pubkey) (the caller reuses
 *        it — STAKE compares it against the destination fingerprint).
 * @return 0 / -1 verdict / -2 hash-backend NODE fault.
 */
static int rtn_sys_stake_auth(const dna_env_view_t *env, uint16_t leg_index,
                              const nodus_rt_exec_ctx_t *ctx,
                              uint8_t fp_out[64]) {
    const uint8_t *identity_pk = NULL;
    if (!ctx->auth) return -1;
    if (env->leg[leg_index].auth_kind != NODUS_RT_AUTHKIND_DSA87_MULTI_V1)
        return -1;
    if (ctx->auth->n_signers != 1) return -1;
    if (rtn_sys_call_identity(env->leg[leg_index].runtime_op,
                              env->buf + env->call_off[leg_index],
                              env->leg[leg_index].call_len,
                              &identity_pk) != 0)
        return -1;
    if (qgp_sha3_512(identity_pk, DNAC_PUBKEY_SIZE, fp_out) != 0)
        return -2;
    if (memcmp(fp_out, ctx->auth->signer_fp[0], 64) != 0) return -1;
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════
 * DNA_CORE — DNA_CORERULE_SPEND / DNA_CORERULE_BURN /
 *            DNA_CORERULE_TOKEN_CREATE (burn season) /
 *            DNA_CORERULE_SYSFUND (O11)
 * ════════════════════════════════════════════════════════════════════ */

/* Compiled CORE adapter op ids (this adapter's own namespace). */
#define RTN_CORE_OP_UTXO    1u   /* CREATE + mediated read: utxo_set row */
#define RTN_CORE_OP_UTXDEL  2u   /* DELETE: utxo_set row                 */
#define RTN_CORE_OP_SUPPLY  3u   /* SET + mediated read: burned counter  */
#define RTN_CORE_OP_TOKEN   4u   /* CREATE + mediated read: tokens row
                                  * (burn season — TOKEN_CREATE registry)*/

/* The canonical UTXO record value (exact 284 bytes):
 *   [0..127]   owner fingerprint, exactly 128 lowercase-hex chars
 *   [128..135] amount        u64 BE
 *   [136..199] token_id      64 B (all-zero = native DNAC)
 *   [200..263] tx_hash       64 B (V2: the engine-derived INTENT
 *                            identity ctx->intent_id — witness-stable
 *                            provenance; NEVER the full-wire wire_id)
 *   [264..267] output_index  u32 BE
 *   [268..275] block_height  u64 BE
 *   [276..283] unlock_block  u64 BE
 * Exactly the utxo_set columns the UTXO merkle leaf consumes
 * (nullifier ‖ owner ‖ amount ‖ token_id ‖ tx_hash ‖ output_index —
 * nodus_witness_merkle.c:136) plus the two spendability/provenance
 * columns; created_at is deliberately excluded (wall-clock audit). */
#define RTN_UTXO_REC_LEN      284u
/* O15J Faz 2 — the SAME length, exported so an engine-internal producer
 * of CORE UTXOs (the epoch settlement) can size its value buffer against
 * this runtime's own authority instead of a copied literal that could
 * drift out of step with the layout above. The assert is the anti-drift
 * proof: the two names can never disagree. */
_Static_assert(NODUS_RT_CORE_UTXO_REC_LEN == RTN_UTXO_REC_LEN,
               "the exported CORE UTXO record length must equal the "
               "adapter's own RTN_UTXO_REC_LEN");
#define RTN_UTXO_OWNER_OFF    0u
#define RTN_UTXO_AMOUNT_OFF   128u
#define RTN_UTXO_TOKEN_OFF    136u
#define RTN_UTXO_TXH_OFF      200u
#define RTN_UTXO_OIDX_OFF     264u
#define RTN_UTXO_BH_OFF       268u
#define RTN_UTXO_UNLOCK_OFF   276u

/* The supply selector key: byte 2 = total_burned (the ONE counter this
 * slice consumes; selector 1 = total_minted is reserved, unimplemented). */
#define RTN_SUPPLY_SEL_BURNED 2u

/* The canonical token-registry record value (exact 188 bytes — burn
 * season). Exactly the `tokens` columns the token merkle leaf consumes
 * (token_id ‖ name ‖ symbol ‖ decimals ‖ supply ‖ creator_fp ‖ flags ‖
 * block_height — nodus_witness_roots_v2.c:36-37); the wall-clock
 * `timestamp` column is deliberately EXCLUDED (audit-only; leaf-excluded)
 * and the adapter writes it 0 — deterministic lane, exactly the
 * created_at rule for utxo rows. Name/symbol are zero-padded to their
 * maxima so exactly ONE encoding exists per registry row (padding bytes
 * MUST be zero — validated on both build and fetch).
 *   [0..7]     supply        u64 BE (the registered initial supply)
 *   [8]        decimals      u8
 *   [9]        flags         u8     (0 this release — no flag semantics)
 *   [10..17]   block_height  u64 BE
 *   [18..145]  creator_fp    128 lowercase-hex chars
 *   [146]      name_len      u8     1..32
 *   [147..178] name          32 B, zero-padded past name_len
 *   [179]      symbol_len    u8     1..8
 *   [180..187] symbol        8 B, zero-padded past symbol_len
 *
 * ⚠ MIGRATION OBLIGATION (review round, MEDIUM — owned by the V2
 * ACTIVATION season, not this slice): the `tokens` table is shared with
 * the LIVE legacy lane, whose writer never enforced this slice's write
 * rules. A legacy chain can therefore hold (a) token UTXO value whose
 * id has NO registry row (the legacy memo parse was conditional,
 * bft.c:2254-2272 — registration silently skipped), (b) duplicate
 * registrations dropped by INSERT OR IGNORE while the second genesis
 * UTXO was still created, and (c) rows whose name/symbol exceed the
 * 32/8 bounds (the legacy memo carrier allowed up to ~253 bytes). Under
 * (a)/(b) the V2 registry-absent read cannot distinguish "never
 * registered" from "value already exists"; under (c)
 * rtn_core_token_fetch fails CLOSED (node fault) for that id. All
 * deterministic across nodes (no split; a liveness/griefing edge on
 * specific ids at worst). The activation/migration season must
 * reconcile the tokens table (register-or-quarantine orphaned token
 * value, bound legacy rows) BEFORE the V2 lane goes live. There is
 * also NO committed cross-check that a registered supply equals the
 * token's UTXO sum in EITHER lane (both supply gates are native-only);
 * the identity holds inductively through this slice's per-transaction
 * rules and any future token-moving op must preserve it explicitly. */
#define RTN_TOKEN_REC_LEN     188u
#define RTN_TOKEN_SUPPLY_OFF  0u
#define RTN_TOKEN_DEC_OFF     8u
#define RTN_TOKEN_FLAGS_OFF   9u
#define RTN_TOKEN_BH_OFF      10u
#define RTN_TOKEN_CFP_OFF     18u
#define RTN_TOKEN_NLEN_OFF    146u
#define RTN_TOKEN_NAME_OFF    147u
#define RTN_TOKEN_SLEN_OFF    179u
#define RTN_TOKEN_SYM_OFF     180u

/* SPEND call v1 bounds: RTN_SPEND_MAX_IN / _MAX_OUT / _OUT_LEN — defined
 * with the capacity-derivation asserts near the top of this file (they
 * participate in the envelope-ceiling arithmetic). */

typedef struct {
    uint8_t        in_count;
    uint8_t        out_count;
    const uint8_t *ins;      /* in_count  × 64                          */
    const uint8_t *outs;     /* out_count × RTN_SPEND_OUT_LEN           */
} rtn_spend_call_t;

static int rtn_hex_lower_ok(const uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; i++) {
        uint8_t c = p[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return 0;
    }
    return 1;
}

/* Parse + validate ONE transfer section (`in_count u8 ‖ nullifiers ‖
 * out_count u8 ‖ output records`) at p[0..len) — the surface SPEND,
 * BURN and TOKEN_CREATE share (burn season: factored out of the SPEND
 * parser byte-for-byte). Enforces strictly ascending inputs (canonical
 * form + free dedup), exactly-128 lowercase-hex owner fingerprints and
 * a non-zero amount — the transparent-leg §6 rule (tx_wire.h:
 * `amount u64 BE ≥1`): a zero-value output names dust the ledger would
 * carry forever (R2/R4 review convergence; the legacy lane had no floor
 * — honest, fail-closed divergence).
 * @param min_out 0 only for BURN (a full-value burn creates nothing).
 * @return consumed byte count (> 0), or 0 = deterministic reject. */
static size_t rtn_xfer_section_parse(const uint8_t *p, size_t len,
                                     uint8_t max_in, uint8_t max_out,
                                     uint8_t min_out,
                                     rtn_spend_call_t *c) {
    if (len < 2) return 0;
    uint8_t ic = p[0];
    if (ic < 1 || ic > max_in) return 0;
    size_t off = 1 + (size_t)ic * 64u;
    if (len < off + 1) return 0;
    uint8_t oc = p[off];
    if (oc < min_out || oc > max_out) return 0;
    size_t need = off + 1 + (size_t)oc * RTN_SPEND_OUT_LEN;
    if (len < need) return 0;
    c->in_count = ic;
    c->out_count = oc;
    c->ins = p + 1;
    c->outs = p + off + 1;
    for (uint8_t i = 1; i < ic; i++)
        if (memcmp(c->ins + (size_t)(i - 1) * 64,
                   c->ins + (size_t)i * 64, 64) >= 0)
            return 0;
    for (uint8_t o = 0; o < oc; o++) {
        const uint8_t *rec = c->outs + (size_t)o * RTN_SPEND_OUT_LEN;
        if (!rtn_hex_lower_ok(rec, 128)) return 0;
        if (rtn_get64(rec + 128) == 0) return 0;
    }
    return need;
}

/* Strict SPEND call parse — the ONE decoder both hooks consume.
 * @return 0 / -1 (deterministic reject). */
static int rtn_spend_parse(const dna_env_view_t *env, uint16_t leg,
                           rtn_spend_call_t *c) {
    const uint8_t *p = env->buf + env->call_off[leg];
    uint32_t len = env->leg[leg].call_len;
    size_t used = rtn_xfer_section_parse(p, len, RTN_SPEND_MAX_IN,
                                         RTN_SPEND_MAX_OUT, 1, c);
    if (used == 0 || used != (size_t)len)
        return -1;                       /* exact length, never a prefix */
    return 0;
}

/* Strict BURN call v1 parse (burn season): transfer section ‖ explicit
 * `burn_amount u64 BE` (>= 1 — a zero burn IS a SPEND and has exactly
 * one canonical encoding, the SPEND call). out_count 0 is legal: a
 * full-value burn creates nothing. @return 0 / -1. */
static int rtn_burn_parse(const dna_env_view_t *env, uint16_t leg,
                          rtn_spend_call_t *c, uint64_t *burn_out) {
    const uint8_t *p = env->buf + env->call_off[leg];
    uint32_t len = env->leg[leg].call_len;
    size_t used = rtn_xfer_section_parse(p, len, RTN_BURN_MAX_IN,
                                         RTN_BURN_MAX_OUT, 0, c);
    if (used == 0 || (size_t)len != used + 8)
        return -1;                       /* exact length, never a prefix */
    uint64_t b = rtn_get64(p + used);
    if (b == 0) return -1;
    *burn_out = b;
    return 0;
}

/* TOKEN_CREATE call v1 (burn season). */
typedef struct {
    const uint8_t *token_id;             /* [64] the NEW token id        */
    const uint8_t *name;                 /* name_len bytes               */
    const uint8_t *sym;                  /* sym_len bytes                */
    uint8_t  name_len, sym_len, decimals;
    rtn_spend_call_t xfer;               /* funding inputs + outputs     */
} rtn_tc_call_t;

/* Registry text rule: printable ASCII (0x20..0x7e) minus ':'. Grounded
 * two ways: the legacy carrier was the memo string "name:symbol:decimals"
 * parsed with strchr (nodus_witness_bft.c:2264-2272), so a ':' or NUL
 * inside either field was UNREPRESENTABLE; and the token merkle-leaf
 * loader reads both columns via strlen (nodus_witness_roots_v2.c:96-98),
 * so an embedded NUL would silently truncate what the root commits.
 * Restricting the remainder to printable ASCII is the fail-closed
 * narrowing (JUDGMENT — the legacy witness checked nothing else). */
static int rtn_tc_text_ok(const uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; i++)
        if (p[i] < 0x20 || p[i] > 0x7e || p[i] == ':')
            return 0;
    return 1;
}

/* Strict TOKEN_CREATE call v1 parse:
 *   token_id[64] ‖ name_len u8 (1..32) ‖ name ‖ sym_len u8 (1..8) ‖ sym
 *   ‖ decimals u8 (0..18) ‖ transfer section (in 1..14, out 1..16)
 * output[0] IS the token genesis output — the legacy apply registers
 * exactly output[0]'s (token_id, amount, fp) (nodus_witness_bft.c:
 * 2243-2281) — so its token_id must equal the declared new token, and
 * every OTHER output must be native change: a second output carrying
 * the new token would inflate the token's UTXO sum above the registered
 * supply, and any third token has no funding leg here (fail-closed —
 * the legacy verify summed tokens blindly, verify.c:753-758).
 * @return 0 / -1. */
static int rtn_tc_parse(const dna_env_view_t *env, uint16_t leg,
                        rtn_tc_call_t *t) {
    static const uint8_t native_tok[64] = { 0 };
    const uint8_t *p = env->buf + env->call_off[leg];
    uint32_t len = env->leg[leg].call_len;
    size_t off = 0;
    if (len < 64 + 2) return -1;
    t->token_id = p;
    off += 64;
    if (memcmp(t->token_id, native_tok, 64) == 0)
        return -1;                       /* the native id is not a token */
    uint8_t nl = p[off++];
    if (nl < 1 || nl > RTN_TC_NAME_MAX) return -1;
    if ((size_t)len < off + nl + 1) return -1;
    t->name = p + off;
    t->name_len = nl;
    off += nl;
    uint8_t sl = p[off++];
    if (sl < 1 || sl > RTN_TC_SYM_MAX) return -1;
    if ((size_t)len < off + sl + 1) return -1;
    t->sym = p + off;
    t->sym_len = sl;
    off += sl;
    t->decimals = p[off++];
    if (t->decimals > RTN_TC_DECIMALS_MAX) return -1;
    if (!rtn_tc_text_ok(t->name, nl) || !rtn_tc_text_ok(t->sym, sl))
        return -1;
    size_t used = rtn_xfer_section_parse(p + off, len - off,
                                         RTN_TC_MAX_IN, RTN_TC_MAX_OUT,
                                         1, &t->xfer);
    if (used == 0 || off + used != (size_t)len)
        return -1;                       /* exact length, never a prefix */
    const uint8_t *o0 = t->xfer.outs;
    if (memcmp(o0 + 136, t->token_id, 64) != 0)
        return -1;                       /* output[0] carries the token  */
    /* Registered supply is stored in an SQLite INTEGER column; a value
     * above INT64_MAX would round-trip negative and poison every later
     * read of the row (the fetch fails closed on negatives). Bound it
     * at the source — the S7 pool-balance INT64_MAX storage-bound
     * precedent. */
    if (rtn_get64(o0 + 128) > (uint64_t)INT64_MAX)
        return -1;
    for (uint8_t o = 1; o < t->xfer.out_count; o++) {
        const uint8_t *rec = t->xfer.outs + (size_t)o * RTN_SPEND_OUT_LEN;
        if (memcmp(rec + 136, native_tok, 64) != 0)
            return -1;                   /* change is native-only        */
    }
    return 0;
}

/* ── DNA_CORERULE_SYSFUND (O11) — the staking funding/release leg ────
 *
 * call v1 = EXACTLY the SPEND transfer section, and nothing else:
 *   in_count u8 1..15 ‖ nullifiers (strictly ascending)
 *   ‖ out_count u8 0..16 ‖ change outputs
 * out_count 0 is legal (a bond that consumes the whole input set creates
 * no change — the BURN precedent). There are NO amount fields: what this
 * leg locks or releases comes from the SIBLING SYSTEM leg's call bytes
 * (rtn_sys_call_flow), so the two legs cannot disagree about the amount
 * and neither leg can be replayed against a different partner.
 *
 * NATIVE-ONLY (LABELED NARROWING): every change output must carry the
 * all-zero native token id. The legacy staking applies were token-BLIND
 * — apply_stake / apply_delegate / apply_undelegate all derive their
 * amounts through sum_native_dnac_in_out (nodus_witness_bft.c:1391,
 * 1548) and simply ignore any other token that rode along, so a custom
 * token could enter or leave a staking transaction unaccounted. The four
 * staking identities are native-only by construction; carrying a foreign
 * token here is fail-closed rather than silently unbalanced. (Inputs are
 * checked in exec against the same rule, where the mediated read holds
 * the stored token id.)
 * @return 0 / -1 deterministic reject. */
static int rtn_sysfund_parse(const dna_env_view_t *env, uint16_t leg,
                             rtn_spend_call_t *c) {
    static const uint8_t native_tok[64] = { 0 };
    const uint8_t *p = env->buf + env->call_off[leg];
    uint32_t len = env->leg[leg].call_len;
    size_t used = rtn_xfer_section_parse(p, len, RTN_SPEND_MAX_IN,
                                         RTN_SPEND_MAX_OUT, 0, c);
    if (used == 0 || used != (size_t)len)
        return -1;                       /* exact length, never a prefix */
    for (uint8_t o = 0; o < c->out_count; o++)
        if (memcmp(c->outs + (size_t)o * RTN_SPEND_OUT_LEN + 136,
                   native_tok, 64) != 0)
            return -1;                   /* native-only (label above)    */
    return 0;
}

/* The canonical 2-leg staking envelope shape, checked from the CORE
 * side — the mirror of rtn_sys_stake_shape: leg1 is THIS leg, leg0 is a
 * SYSTEM validator-record leg (ops 1..5 — rtn_sys_is_stake_op; O12 S1
 * added VALIDATOR_UPDATE, whose flow is lock = release = 0, so this leg
 * degenerates to a pure fee payment there). @return 0 / -1. */
static int rtn_sysfund_shape(const dna_env_view_t *env, uint16_t leg_index) {
    if (env->leg_count != 2 || leg_index != 1) return -1;
    if (env->leg[0].domain_id != DNA_DOMAIN_SYSTEM) return -1;
    if (!rtn_sys_is_stake_op(env->leg[0].runtime_op)) return -1;
    return 0;
}

/* Emit the shared transfer-read prefix: one UTXO read per input (keys
 * already strictly ascending by the parse) then the ONE burned-counter
 * read — ascending (op_id, key), the engine's canonical order. */
static void rtn_xfer_reads(const rtn_spend_call_t *c,
                           nodus_rt_read_req_t *reqs_out) {
    for (uint8_t i = 0; i < c->in_count; i++) {
        memset(&reqs_out[i], 0, sizeof(reqs_out[i]));
        reqs_out[i].op_id = RTN_CORE_OP_UTXO;
        reqs_out[i].key_len = 64;
        memcpy(reqs_out[i].key, c->ins + (size_t)i * 64, 64);
    }
    memset(&reqs_out[c->in_count], 0, sizeof(reqs_out[0]));
    reqs_out[c->in_count].op_id = RTN_CORE_OP_SUPPLY;
    reqs_out[c->in_count].key_len = 1;
    reqs_out[c->in_count].key[0] = RTN_SUPPLY_SEL_BURNED;
}

int nodus_rt_core_read_plan(const nodus_domain_runtime_t *rt,
                            const dna_env_view_t *env, uint16_t leg_index,
                            const nodus_rt_exec_ctx_t *ctx,
                            nodus_rt_read_req_t *reqs_out,
                            uint16_t max_reqs, uint16_t *n_out) {
    (void)rt;
    if (!env || !ctx || !reqs_out || !n_out) return -2;
    if (leg_index >= env->leg_count) return -2;
    switch (env->leg[leg_index].runtime_op) {
    case DNA_CORERULE_SPEND: {
        rtn_spend_call_t c;
        if (rtn_spend_parse(env, leg_index, &c) != 0) return -1;
        uint16_t need = (uint16_t)(c.in_count + 1);
        if (need > max_reqs) return -1;
        rtn_xfer_reads(&c, reqs_out);
        *n_out = need;
        return 0;
    }
    case DNA_CORERULE_BURN: {
        rtn_spend_call_t c;
        uint64_t burn = 0;
        if (rtn_burn_parse(env, leg_index, &c, &burn) != 0) return -1;
        (void)burn;                      /* validated; consumed at exec  */
        uint16_t need = (uint16_t)(c.in_count + 1);
        if (need > max_reqs) return -1;
        rtn_xfer_reads(&c, reqs_out);
        *n_out = need;
        return 0;
    }
    case DNA_CORERULE_TOKEN_CREATE: {
        rtn_tc_call_t t;
        if (rtn_tc_parse(env, leg_index, &t) != 0) return -1;
        /* inputs + supply + the registry-uniqueness read (op 4 last —
         * ascending op_id keeps the canonical request order) */
        uint16_t need = (uint16_t)(t.xfer.in_count + 2);
        if (need > max_reqs) return -1;
        rtn_xfer_reads(&t.xfer, reqs_out);
        memset(&reqs_out[t.xfer.in_count + 1], 0, sizeof(reqs_out[0]));
        reqs_out[t.xfer.in_count + 1].op_id = RTN_CORE_OP_TOKEN;
        reqs_out[t.xfer.in_count + 1].key_len = 64;
        memcpy(reqs_out[t.xfer.in_count + 1].key, t.token_id, 64);
        *n_out = need;
        return 0;
    }
    case DNA_CORERULE_SYSFUND: {
        rtn_spend_call_t c;
        if (rtn_sysfund_shape(env, leg_index) != 0) return -1;
        if (rtn_sysfund_parse(env, leg_index, &c) != 0) return -1;
        /* the SPEND read shape exactly: one UTXO read per input plus the
         * ONE burned-counter read (the release UTXO is CREATED, never
         * read) */
        uint16_t need = (uint16_t)(c.in_count + 1);
        if (need > max_reqs) return -1;
        rtn_xfer_reads(&c, reqs_out);
        *n_out = need;
        return 0;
    }
    default:
        return -1;                       /* un-migrated op: fail closed  */
    }
}

/* One (token_id → in/out sums) accumulator slot. */
typedef struct {
    const uint8_t *token;                /* borrowed 64-byte id          */
    uint64_t in_sum, out_sum;
} rtn_tok_sum_t;

static int rtn_tok_add(rtn_tok_sum_t *t, size_t *n, size_t cap,
                       const uint8_t *token, uint64_t amount, int is_in) {
    for (size_t i = 0; i < *n; i++) {
        if (memcmp(t[i].token, token, 64) == 0) {
            uint64_t *s = is_in ? &t[i].in_sum : &t[i].out_sum;
            uint64_t nv;
            if (dna_ck_add_u64(*s, amount, &nv) != 0) return -1;
            *s = nv;
            return 0;
        }
    }
    if (*n >= cap) return -1;
    t[*n].token = token;
    t[*n].in_sum = is_in ? amount : 0;
    t[*n].out_sum = is_in ? 0 : amount;
    (*n)++;
    return 0;
}

/* The ONE raw-fingerprint → 128-char lowercase-hex conversion in this
 * file (the qgp_fp_raw_to_hex form the legacy lane writes into every
 * owner / fingerprint TEXT column, minus its NUL — these buffers are
 * fixed-width fields, never C strings). */
static void rtn_fp_hex(const uint8_t raw[64], uint8_t out[128]) {
    static const char hexd[] = "0123456789abcdef";
    for (int b = 0; b < 64; b++) {
        out[2 * b]     = (uint8_t)hexd[raw[b] >> 4];
        out[2 * b + 1] = (uint8_t)hexd[raw[b] & 0xF];
    }
}

/* lowercase-hex fingerprints of the VERIFIED signers (shared by every
 * CORE exec path — ownership binds to the engine verdict, never to
 * envelope bytes). */
static void rtn_signer_fps(const nodus_rt_exec_ctx_t *ctx,
                           uint8_t sfp[][128]) {
    for (uint16_t s = 0; s < ctx->auth->n_signers; s++)
        rtn_fp_hex(ctx->auth->signer_fp[s], sfp[s]);
}

/* Deterministic output identities — the SOURCE derivation
 * SHA3-512(fp_128hex ‖ seed_32) (the shipped update_utxo_set rule,
 * nodus_witness_bft.c:850-861) — plus the duplicate-identity reject
 * (fail-closed divergence: legacy utxo_add dropped duplicates silently).
 * Fills nul[o] per output and sorted[] (output indices ascending by id).
 * @return 0 / -1 duplicate / -2 hash backend fault. */
static int rtn_out_ids(const rtn_spend_call_t *c,
                       uint8_t nul[][64], uint8_t *sorted) {
    for (uint8_t o = 0; o < c->out_count; o++) {
        uint8_t pre[160];
        const uint8_t *rec = c->outs + (size_t)o * RTN_SPEND_OUT_LEN;
        memcpy(pre, rec, 128);                       /* fp (128 hex)     */
        memcpy(pre + 128, rec + 200, 32);            /* seed             */
        if (qgp_sha3_512(pre, sizeof(pre), nul[o]) != 0) return -2;
        sorted[o] = o;
    }
    for (uint8_t a = 1; a < c->out_count; a++) {     /* insertion sort   */
        uint8_t key = sorted[a];
        int b = a - 1;
        while (b >= 0 && memcmp(nul[sorted[b]], nul[key], 64) > 0) {
            sorted[b + 1] = sorted[b];
            b--;
        }
        sorted[b + 1] = key;
    }
    for (uint8_t a = 1; a < c->out_count; a++)
        if (memcmp(nul[sorted[a - 1]], nul[sorted[a]], 64) == 0)
            return -1;                   /* duplicate output identity    */
    return 0;
}

/* Append one canonical UTXO CREATE record/effect (shared builder). */
static void rtn_utxo_create_eff(dna_effect_in_t *eff, uint8_t *v,
                                const uint8_t *rec, uint8_t o,
                                const uint8_t *out_id,
                                const nodus_rt_exec_ctx_t *ctx) {
    memcpy(v + RTN_UTXO_OWNER_OFF, rec, 128);
    memcpy(v + RTN_UTXO_AMOUNT_OFF, rec + 128, 8);   /* already BE   */
    memcpy(v + RTN_UTXO_TOKEN_OFF, rec + 136, 64);
    /* PROVENANCE = the canonical INTENT identity (intent season):
     * this row is consensus state (the UTXO merkle leaf commits
     * tx_hash — nodus_witness_merkle.c:136), so two valid
     * authorization realizations of the same operation must write
     * byte-identical rows. The full-wire ctx->wire_id would differ
     * between them and fork the CORE state root. */
    memcpy(v + RTN_UTXO_TXH_OFF, ctx->intent_id, 64);
    rtn_put32(v + RTN_UTXO_OIDX_OFF, (uint32_t)o);
    rtn_put64(v + RTN_UTXO_BH_OFF, ctx->global_height);
    rtn_put64(v + RTN_UTXO_UNLOCK_OFF, 0);           /* legacy: all
                                      * non-UNSTAKE outputs unlocked */
    eff->hdr.op_id = RTN_CORE_OP_UTXO;
    eff->hdr.effect_kind = DNA_EFFECT_CREATE;
    eff->hdr.precond_tag = DNA_EFFECT_PRE_ABSENT;
    eff->hdr.key_len = 64;
    eff->hdr.value_len = RTN_UTXO_REC_LEN;
    eff->key = out_id;
    eff->value = v;
}

/* O15J Faz 2 — the SAME canonical CORE UTXO CREATE effect, built from
 * EXPLICIT fields instead of a spend leg's output record.
 *
 * The epoch settlement (nodus_witness_v2_econ.c) is an ENGINE-internal
 * producer of CORE UTXOs: it has no envelope, no leg and no intent_id, so
 * it cannot go through rtn_utxo_create_eff — but it must write rows that
 * are byte-identical in SHAPE to every other CORE UTXO, or the CORE state
 * root would depend on which producer wrote the row. Sharing this builder
 * (and the offsets above) is what makes that structural rather than
 * asserted: there is ONE encoder of the 284-byte record in the tree.
 *
 * Every field is the caller's, deliberately: settlement's tx_hash is the
 * V1 "settlement" digest and its unlock_block is 0, neither of which this
 * runtime can derive. What the runtime still OWNS is the op id, the kind,
 * the precondition and the two lengths — the parts a caller must not be
 * able to choose.
 *
 * `value` must be NODUS_RT_CORE_UTXO_REC_LEN bytes and must outlive the
 * effect (effect_wire.h LIFETIME RULE). `owner_fp_hex` is exactly 128
 * lowercase-hex chars, NOT NUL-terminated here.
 *
 * @return 0 / -1 on a NULL argument. */
int nodus_rt_core_utxo_create_eff(dna_effect_in_t *eff, uint8_t *value,
                                  const uint8_t nullifier[64],
                                  const char *owner_fp_hex,
                                  uint64_t amount,
                                  const uint8_t token_id[64],
                                  const uint8_t tx_hash[64],
                                  uint32_t output_index,
                                  uint64_t block_height,
                                  uint64_t unlock_block) {
    if (!eff || !value || !nullifier || !owner_fp_hex || !token_id ||
        !tx_hash)
        return -1;
    memset(eff, 0, sizeof(*eff));
    memcpy(value + RTN_UTXO_OWNER_OFF, owner_fp_hex, 128);
    rtn_put64(value + RTN_UTXO_AMOUNT_OFF, amount);
    memcpy(value + RTN_UTXO_TOKEN_OFF, token_id, 64);
    memcpy(value + RTN_UTXO_TXH_OFF, tx_hash, 64);
    rtn_put32(value + RTN_UTXO_OIDX_OFF, output_index);
    rtn_put64(value + RTN_UTXO_BH_OFF, block_height);
    rtn_put64(value + RTN_UTXO_UNLOCK_OFF, unlock_block);
    eff->hdr.op_id = RTN_CORE_OP_UTXO;
    eff->hdr.effect_kind = DNA_EFFECT_CREATE;
    eff->hdr.precond_tag = DNA_EFFECT_PRE_ABSENT;
    eff->hdr.key_len = 64;
    eff->hdr.value_len = RTN_UTXO_REC_LEN;
    eff->key = nullifier;
    eff->value = value;
    return 0;
}

/* Append the ONE burned-counter SET, bound to the observed pre-state
 * counter (EXISTS_VERSION). `burn_total` = everything this leg destroys
 * (SPEND: the fee; BURN: fee + explicit burn_amount — ONE counter, the
 * legacy accounting: route_tx_fee adds every destroyed value to
 * supply_tracking.total_burned regardless of tx_type,
 * nodus_witness_bft.c:731-733; no separate explicit-burn bucket exists
 * in committed state and inventing one would be a schema/protocol
 * change). @return 0 / -1 verdict / -2 fault. */
static int rtn_supply_burn_eff(dna_effect_in_t *eff, uint8_t supv[8],
                               const nodus_rt_read_res_t *r,
                               uint64_t burn_total) {
    if (!r->present) return -1;          /* no supply row: unfunded chain*/
    if (r->value_len != 8) return -2;
    uint64_t burned_old = rtn_get64(r->value);
    uint64_t burned_new;
    if (dna_ck_add_u64(burned_old, burn_total, &burned_new) != 0)
        return -1;
    rtn_put64(supv, burned_new);
    eff->hdr.op_id = RTN_CORE_OP_SUPPLY;
    eff->hdr.effect_kind = DNA_EFFECT_SET;
    eff->hdr.precond_tag = DNA_EFFECT_PRE_EXISTS_VERSION;
    eff->hdr.expected_version = burned_old;
    eff->hdr.key_len = 1;
    eff->hdr.value_len = 8;
    eff->key = (const uint8_t *)"\x02";
    eff->value = supv;
    return 0;
}

/* Append one input DELETE, bound by EXISTS_VHASH to the exact record
 * the mediated read observed — the read and the mutation cannot
 * disagree about the row. @return 0 / -2 fault. */
static int rtn_utxo_delete_eff(dna_effect_in_t *eff, uint8_t dvh[64],
                               const nodus_rt_read_res_t *r,
                               const uint8_t *key) {
    if (dna_effect_value_hash(r->value, RTN_UTXO_REC_LEN, dvh) != 0)
        return -2;
    eff->hdr.op_id = RTN_CORE_OP_UTXDEL;
    eff->hdr.effect_kind = DNA_EFFECT_DELETE;
    eff->hdr.precond_tag = DNA_EFFECT_PRE_EXISTS_VHASH;
    memcpy(eff->hdr.expected_vhash, dvh, 64);
    eff->hdr.key_len = 64;
    eff->hdr.value_len = 0;
    eff->key = key;
    eff->value = NULL;
    return 0;
}

/* The shared transparent-transfer executor — SPEND (burn_amount == 0)
 * and BURN (burn_amount >= 1, parsed from the call) differ ONLY in the
 * native conservation equation and the burned-counter delta:
 *   SPEND:  Σnative_in == Σnative_out + fee            ; burned += fee
 *   BURN:   Σnative_in == Σnative_out + fee + burn     ; burned += fee+burn
 * Every non-native token balances EXACTLY in both — an explicit token
 * burn is NOT expressible: the legacy lane cannot represent one either
 * (its verify sums tokens blindly, verify.c:753-758, and nothing ever
 * decrements tokens.supply — a token-value imbalance would break the
 * per-token registered-supply identity the registry commits), so V2
 * fails it closed rather than inventing token-supply mechanics.
 * @return 0 / -1 verdict / -2 node fault. */
static int rtn_xfer_exec(const rtn_spend_call_t *c, uint64_t burn_amount,
                         const dna_env_view_t *env,
                         const nodus_rt_exec_ctx_t *ctx,
                         const nodus_rt_read_res_t *reads, uint16_t n_reads,
                         uint8_t *res_out, size_t res_cap,
                         size_t *res_len_out) {
    if (!reads || n_reads != (uint16_t)(c->in_count + 1)) return -2;

    uint8_t sfp[NODUS_RT_AUTH_MAX_SIGNERS][128];
    rtn_signer_fps(ctx, sfp);

    static const uint8_t native_token[64] = { 0 };
    rtn_tok_sum_t toks[RTN_SPEND_MAX_IN + RTN_SPEND_MAX_OUT + 1];
    size_t n_toks = 0;
    memset(toks, 0, sizeof(toks));
    /* seed the native slot so a token-only flow still faces the native
     * fee equation below */
    toks[0].token = native_token;
    n_toks = 1;

    /* ── inputs: exist, unlocked, OWNED BY A VERIFIED SIGNER ────────── */
    for (uint8_t i = 0; i < c->in_count; i++) {
        const nodus_rt_read_res_t *r = &reads[i];
        if (!r->present) return -1;      /* missing OR already spent     */
        if (r->value_len != RTN_UTXO_REC_LEN) return -2;   /* own adapter
                                          * out of contract: node fault  */
        const uint8_t *rec = r->value;
        uint64_t unlock = rtn_get64(rec + RTN_UTXO_UNLOCK_OFF);
        if (unlock >= ctx->global_height) return -1;   /* locked (the
                                          * legacy unlock > tip gate)    */
        int owned = 0;
        for (uint16_t s = 0; s < ctx->auth->n_signers && !owned; s++)
            if (memcmp(rec + RTN_UTXO_OWNER_OFF, sfp[s], 128) == 0)
                owned = 1;
        if (!owned) return -1;           /* wrong owner                  */
        if (rtn_tok_add(toks, &n_toks,
                        sizeof(toks) / sizeof(toks[0]),
                        rec + RTN_UTXO_TOKEN_OFF,
                        rtn_get64(rec + RTN_UTXO_AMOUNT_OFF), 1) != 0)
            return -1;                   /* checked-add overflow         */
    }

    /* ── outputs ────────────────────────────────────────────────────── */
    for (uint8_t o = 0; o < c->out_count; o++) {
        const uint8_t *rec = c->outs + (size_t)o * RTN_SPEND_OUT_LEN;
        if (rtn_tok_add(toks, &n_toks,
                        sizeof(toks) / sizeof(toks[0]),
                        rec + 136, rtn_get64(rec + 128), 0) != 0)
            return -1;
    }

    /* ── conservation: native pays fee + burn, every token balances ─── */
    uint64_t fee = env->fee_amount;
    if (fee < DNAC_MIN_FEE_RAW || fee < NODUS_W_BASE_TX_FEE)
        return -1;                       /* BOTH shipped floors          */
    uint64_t destroyed;                  /* fee + explicit burn          */
    if (dna_ck_add_u64(fee, burn_amount, &destroyed) != 0) return -1;
    for (size_t t = 0; t < n_toks; t++) {
        if (memcmp(toks[t].token, native_token, 64) == 0) {
            uint64_t need;
            if (dna_ck_add_u64(toks[t].out_sum, destroyed, &need) != 0)
                return -1;
            if (toks[t].in_sum != need) return -1;   /* value mismatch /
                                          * fee != committed declaration */
        } else {
            if (toks[t].in_sum != toks[t].out_sum) return -1;
        }
    }

    /* ── deterministic output identities + duplicate reject ─────────── */
    uint8_t nul[RTN_SPEND_MAX_OUT][64];
    uint8_t sorted[RTN_SPEND_MAX_OUT];   /* output index, sorted by nul  */
    if (c->out_count > 0) {
        int rc = rtn_out_ids(c, nul, sorted);
        if (rc != 0) return rc;
    }

    /* ── canonical typed-effect result ──────────────────────────────── */
    dna_effect_in_t effs[RTN_SPEND_MAX_OUT + 1 + RTN_SPEND_MAX_IN];
    uint8_t crv[RTN_SPEND_MAX_OUT][RTN_UTXO_REC_LEN];
    uint8_t dvh[RTN_SPEND_MAX_IN][64];
    uint8_t supv[8];
    uint16_t ne = 0;
    memset(effs, 0, sizeof(effs));

    /* CREATEs first (kind 1), keys ascending */
    for (uint8_t a = 0; a < c->out_count; a++) {
        uint8_t o = sorted[a];
        rtn_utxo_create_eff(&effs[ne], crv[a],
                            c->outs + (size_t)o * RTN_SPEND_OUT_LEN, o,
                            nul[o], ctx);
        ne++;
    }
    /* the ONE burn (kind 2), bound to the observed pre-state counter */
    {
        int rc = rtn_supply_burn_eff(&effs[ne], supv, &reads[c->in_count],
                                     destroyed);
        if (rc != 0) return rc;
        ne++;
    }
    /* DELETEs last (kind 3), keys ascending (= input order) */
    for (uint8_t i = 0; i < c->in_count; i++) {
        if (rtn_utxo_delete_eff(&effs[ne], dvh[i], &reads[i],
                                c->ins + (size_t)i * 64) != 0)
            return -2;
        ne++;
    }

    if (dna_effect_result_encode(effs, ne, res_out, res_cap,
                                 res_len_out) != 0)
        return -2;                       /* unreachable for a leg this
                                          * function built: node fault   */
    return 0;
}

/* TOKEN_CREATE executor (burn season). Source semantics preserved:
 * inputs are the NATIVE fee payment (the client builder funds exactly
 * the creation fee from native UTXOs, dnac/src/transaction/
 * token_create.c:98-123 — a non-native input is fail-closed here,
 * where the legacy verify summed it blindly); output[0] is the token
 * genesis output whose (token_id, amount, fp) the registry commits
 * (nodus_witness_bft.c:2243-2281: supply = output[0].amount,
 * creator_fp = output[0].fp); the creation fee must meet the shipped
 * NODUS_W_TOKEN_CREATE_FEE floor (verify.c:776-789 checks BOTH
 * total_input and declared_fee against it) and — the block-level rule
 * the legacy supply invariant enforces (bft.c:998) — equal exactly what
 * the native inputs release: Σnative_in == Σnative_out + fee. Registry
 * uniqueness is a HARD reject (fail-closed divergence from the legacy
 * INSERT OR IGNORE, nodus_witness_db.c:1503 — silently dropping a
 * registration under an existing id is the duplicate-output bug class).
 * @return 0 / -1 verdict / -2 node fault. */
static int rtn_tc_exec(const rtn_tc_call_t *t,
                       const dna_env_view_t *env,
                       const nodus_rt_exec_ctx_t *ctx,
                       const nodus_rt_read_res_t *reads, uint16_t n_reads,
                       uint8_t *res_out, size_t res_cap,
                       size_t *res_len_out) {
    const rtn_spend_call_t *c = &t->xfer;
    if (!reads || n_reads != (uint16_t)(c->in_count + 2)) return -2;

    uint8_t sfp[NODUS_RT_AUTH_MAX_SIGNERS][128];
    rtn_signer_fps(ctx, sfp);

    static const uint8_t native_token[64] = { 0 };

    /* ── registry uniqueness: the token read MUST be absent ─────────── */
    {
        const nodus_rt_read_res_t *r = &reads[c->in_count + 1];
        if (r->present) return -1;       /* duplicate token id           */
    }

    /* ── inputs: exist, unlocked, owned, NATIVE-only ────────────────── */
    uint64_t native_in = 0;
    for (uint8_t i = 0; i < c->in_count; i++) {
        const nodus_rt_read_res_t *r = &reads[i];
        if (!r->present) return -1;      /* missing OR already spent     */
        if (r->value_len != RTN_UTXO_REC_LEN) return -2;
        const uint8_t *rec = r->value;
        uint64_t unlock = rtn_get64(rec + RTN_UTXO_UNLOCK_OFF);
        if (unlock >= ctx->global_height) return -1;
        int owned = 0;
        for (uint16_t s = 0; s < ctx->auth->n_signers && !owned; s++)
            if (memcmp(rec + RTN_UTXO_OWNER_OFF, sfp[s], 128) == 0)
                owned = 1;
        if (!owned) return -1;           /* wrong owner                  */
        if (memcmp(rec + RTN_UTXO_TOKEN_OFF, native_token, 64) != 0)
            return -1;                   /* fee funding is native-only   */
        if (dna_ck_add_u64(native_in,
                           rtn_get64(rec + RTN_UTXO_AMOUNT_OFF),
                           &native_in) != 0)
            return -1;
    }

    /* ── fee + conservation ─────────────────────────────────────────── */
    uint64_t fee = env->fee_amount;
    if (fee < NODUS_W_TOKEN_CREATE_FEE)
        return -1;                       /* the shipped creation floor —
                                          * itself far above the generic
                                          * DNAC_MIN_FEE_RAW /
                                          * NODUS_W_BASE_TX_FEE floors   */
    uint64_t native_out = 0;             /* outputs[1..] are native by
                                          * the parse; output[0] is the
                                          * new token's genesis supply   */
    for (uint8_t o = 1; o < c->out_count; o++) {
        const uint8_t *rec = c->outs + (size_t)o * RTN_SPEND_OUT_LEN;
        if (dna_ck_add_u64(native_out, rtn_get64(rec + 128),
                           &native_out) != 0)
            return -1;
    }
    {
        uint64_t need;
        if (dna_ck_add_u64(native_out, fee, &need) != 0) return -1;
        if (native_in != need) return -1;    /* fee != what inputs release.
                                          * FAIL-CLOSED NARROWING (review
                                          * round): legacy never enforced
                                          * this per transaction — its
                                          * verify checked only the two
                                          * fee floors, and only the
                                          * block-level native supply
                                          * gate caught the imbalance by
                                          * rejecting the WHOLE block.
                                          * Same accepted block set,
                                          * finer rejection granularity. */
    }

    /* ── output identities + duplicate reject (all outputs, token
     *    genesis included — the legacy update_utxo_set derives every
     *    output's identity the same way) ──────────────────────────── */
    uint8_t nul[RTN_SPEND_MAX_OUT][64];
    uint8_t sorted[RTN_SPEND_MAX_OUT];
    {
        int rc = rtn_out_ids(c, nul, sorted);
        if (rc != 0) return rc;
    }

    /* ── canonical typed-effect result ──────────────────────────────── */
    dna_effect_in_t effs[RTN_TC_MAX_OUT + 2 + RTN_TC_MAX_IN];
    uint8_t crv[RTN_TC_MAX_OUT][RTN_UTXO_REC_LEN];
    uint8_t tokv[RTN_TOKEN_REC_LEN];
    uint8_t dvh[RTN_TC_MAX_IN][64];
    uint8_t supv[8];
    uint16_t ne = 0;
    memset(effs, 0, sizeof(effs));
    memset(tokv, 0, sizeof(tokv));

    /* CREATEs first (kind 1): op 1 utxo rows (keys ascending), then the
     * op 4 registry row — ascending op_id inside the kind, the effect
     * codec's canonical order */
    for (uint8_t a = 0; a < c->out_count; a++) {
        uint8_t o = sorted[a];
        rtn_utxo_create_eff(&effs[ne], crv[a],
                            c->outs + (size_t)o * RTN_SPEND_OUT_LEN, o,
                            nul[o], ctx);
        ne++;
    }
    {
        const uint8_t *o0 = c->outs;     /* the token genesis output     */
        rtn_put64(tokv + RTN_TOKEN_SUPPLY_OFF, rtn_get64(o0 + 128));
        tokv[RTN_TOKEN_DEC_OFF] = t->decimals;
        tokv[RTN_TOKEN_FLAGS_OFF] = 0;   /* no flag semantics shipped    */
        rtn_put64(tokv + RTN_TOKEN_BH_OFF, ctx->global_height);
        memcpy(tokv + RTN_TOKEN_CFP_OFF, o0, 128);   /* creator = o0 fp  */
        tokv[RTN_TOKEN_NLEN_OFF] = t->name_len;
        memcpy(tokv + RTN_TOKEN_NAME_OFF, t->name, t->name_len);
        tokv[RTN_TOKEN_SLEN_OFF] = t->sym_len;
        memcpy(tokv + RTN_TOKEN_SYM_OFF, t->sym, t->sym_len);
        effs[ne].hdr.op_id = RTN_CORE_OP_TOKEN;
        effs[ne].hdr.effect_kind = DNA_EFFECT_CREATE;
        effs[ne].hdr.precond_tag = DNA_EFFECT_PRE_ABSENT;   /* uniqueness
                                          * re-checked at apply          */
        effs[ne].hdr.key_len = 64;
        effs[ne].hdr.value_len = RTN_TOKEN_REC_LEN;
        effs[ne].key = t->token_id;
        effs[ne].value = tokv;
        ne++;
    }
    /* the ONE fee burn (kind 2) */
    {
        int rc = rtn_supply_burn_eff(&effs[ne], supv, &reads[c->in_count],
                                     fee);
        if (rc != 0) return rc;
        ne++;
    }
    /* DELETEs last (kind 3) */
    for (uint8_t i = 0; i < c->in_count; i++) {
        if (rtn_utxo_delete_eff(&effs[ne], dvh[i], &reads[i],
                                c->ins + (size_t)i * 64) != 0)
            return -2;
        ne++;
    }

    if (dna_effect_result_encode(effs, ne, res_out, res_cap,
                                 res_len_out) != 0)
        return -2;
    return 0;
}

/* The release UTXO's provenance constants — the SOURCE synthetic-UTXO
 * derivation of the legacy UNDELEGATE payout (emit_synthetic_utxo,
 * nodus_witness_bft.c:1720-1729 + the call site at :1873-1877): kind
 * byte 0x01 = "principal", output_index 100 = the high base that can
 * never collide with a wire output index (which start at 0 and are
 * bounded by RTN_SPEND_MAX_OUT). */
#define RTN_SYSFUND_REL_KIND   ((uint8_t)0x01)
#define RTN_SYSFUND_REL_INDEX  ((uint32_t)100)
_Static_assert(RTN_SYSFUND_REL_INDEX >= RTN_SPEND_MAX_OUT,
               "the release output index can collide with a wire output");

/* The staking funding/release executor (O11) — the CORE half of every
 * SYSTEM stake-lifecycle envelope.
 *
 * It owns exactly the transparent value movement the legacy applies
 * performed through update_utxo_set + route_tx_fee, with the amounts
 * taken from the SIBLING SYSTEM leg instead of inferred:
 *
 *   Σnative_in == Σchange_out + fee + lock                 (checked u64)
 *
 * which is the legacy consistency equation with the state amount named
 * explicitly on the side it belongs to: apply_delegate enforces
 * in == out + fee + delegation_amount (bft.c:1397-1414), apply_stake
 * derives bond = in − out − fee and requires bond >= the self-bond floor
 * (bft.c:1548-1570), apply_undelegate emits the principal as a synthetic
 * UTXO outside the wire outputs (bft.c:1873-1877). Everything DESTROYED
 * is the fee and only the fee: a lock MOVES value into
 * validators.self_stake / delegations.amount (both supply buckets,
 * v2_claims.c:787), it is never burned.
 *
 * @return 0 / -1 verdict / -2 node fault. */
static int rtn_sysfund_exec(const rtn_spend_call_t *c,
                            const dna_env_view_t *env,
                            const nodus_rt_exec_ctx_t *ctx,
                            const nodus_rt_read_res_t *reads,
                            uint16_t n_reads,
                            uint8_t *res_out, size_t res_cap,
                            size_t *res_len_out) {
    if (!reads || n_reads != (uint16_t)(c->in_count + 1)) return -2;

    /* ── the SIBLING SYSTEM leg decides the flow, from CALL BYTES ───── */
    const uint8_t *spc = env->buf + env->call_off[0];
    uint32_t       spl = env->leg[0].call_len;
    uint64_t lock = 0, release = 0;
    if (rtn_sys_call_flow(env->leg[0].runtime_op, spc, spl, &lock,
                          &release) != 0)
        return -1;                       /* unparseable record leg       */

    uint8_t sfp[NODUS_RT_AUTH_MAX_SIGNERS][128];
    rtn_signer_fps(ctx, sfp);
    static const uint8_t native_token[64] = { 0 };

    /* ── inputs: exist, unlocked, OWNED BY A VERIFIED SIGNER, NATIVE ── */
    uint64_t native_in = 0;
    for (uint8_t i = 0; i < c->in_count; i++) {
        const nodus_rt_read_res_t *r = &reads[i];
        if (!r->present) return -1;      /* missing OR already spent     */
        if (r->value_len != RTN_UTXO_REC_LEN) return -2;   /* own adapter
                                          * out of contract: node fault  */
        const uint8_t *rec = r->value;
        uint64_t unlock = rtn_get64(rec + RTN_UTXO_UNLOCK_OFF);
        if (unlock >= ctx->global_height) return -1;   /* the legacy
                                          * unlock > tip gate, verbatim  */
        int owned = 0;
        for (uint16_t s = 0; s < ctx->auth->n_signers && !owned; s++)
            if (memcmp(rec + RTN_UTXO_OWNER_OFF, sfp[s], 128) == 0)
                owned = 1;
        if (!owned) return -1;           /* wrong owner                  */
        /* HONEST LABEL (O11 R2): the funding owners are THIS leg's
         * verified signers; the record identity is the SIBLING leg's.
         * Third-party funding (F funds X's bond/delegation) is therefore
         * expressible — as it already was on the legacy WITNESS surface
         * (multi-signer wire, inputs owned by ANY signer,
         * nodus_witness_verify.c CRITICAL-4 loop; only the CLIENT lane
         * pinned signer_count==1). X still signs the record leg and the
         * lock still binds to X's identity, so this widens who may PAY,
         * never who OWNS. */
        if (memcmp(rec + RTN_UTXO_TOKEN_OFF, native_token, 64) != 0)
            return -1;                   /* native-only (rtn_sysfund_parse
                                          * carries the same label)      */
        if (dna_ck_add_u64(native_in,
                           rtn_get64(rec + RTN_UTXO_AMOUNT_OFF),
                           &native_in) != 0)
            return -1;
    }

    /* ── fee floors (BOTH shipped, as a conjunction) ────────────────── */
    uint64_t fee = env->fee_amount;
    if (fee < DNAC_MIN_FEE_RAW || fee < NODUS_W_BASE_TX_FEE)
        return -1;

    /* ── conservation, checked u64 ──────────────────────────────────── */
    uint64_t change_out = 0;
    for (uint8_t o = 0; o < c->out_count; o++) {
        const uint8_t *rec = c->outs + (size_t)o * RTN_SPEND_OUT_LEN;
        if (dna_ck_add_u64(change_out, rtn_get64(rec + 128),
                           &change_out) != 0)
            return -1;
    }
    {
        /* Σnative_in == Σchange_out + fee + lock.
         *
         * `release` is DELIBERATELY ABSENT from this equation. A release
         * does not fund anything: it MOVES value out of the delegated
         * bucket into a brand-new UTXO, and BOTH sides of that move sit
         * outside the funding inputs — the SYSTEM leg decrements
         * validators.total_delegated by exactly the amount this leg
         * creates as the release UTXO. Netting it against the funding
         * inputs would count the released value twice in Σutxo and break
         * the CORE supply identity (v2_claims.c:787).
         *
         * Derivation, per op (matches the season design's supply map):
         *   STAKE/DELEGATE  Σutxo −(lock+fee), bucket +lock, burned +fee
         *   UNSTAKE         Σutxo −fee,                      burned +fee
         *   UNDELEGATE      Σutxo +(release−fee), delegated −release,
         *                                                    burned +fee
         * each of which is exactly this equation plus the SYSTEM leg's
         * bucket move. The legacy lane enforced the same thing implicitly:
         * apply_undelegate performs NO balance check of its own, the
         * generic update_utxo_set/route_tx_fee path balances
         * Σin == Σout + fee, and emit_synthetic_utxo's principal
         * (bft.c:1873-1877) is covered by the delegation-row decrement. */
        uint64_t rhs = 0;
        if (dna_ck_add_u64(change_out, fee, &rhs) != 0) return -1;
        if (dna_ck_add_u64(rhs, lock, &rhs) != 0) return -1;
        if (native_in != rhs) return -1; /* value mismatch / fee != the
                                          * committed declaration        */
    }

    /* ── the release UTXO (UNDELEGATE only) ─────────────────────────── */
    uint8_t rel_id[64];
    uint8_t rel_rec[RTN_SPEND_OUT_LEN];
    memset(rel_id, 0, sizeof(rel_id));
    memset(rel_rec, 0, sizeof(rel_rec));
    if (release > 0) {
        /* identity = SHA3-512(tx_hash ‖ kind ‖ u32be(index)) with
         * tx_hash = the canonical INTENT identity: this row is consensus
         * state (the UTXO merkle leaf commits tx_hash), so two valid
         * authorization realizations must derive the SAME nullifier. */
        uint8_t pre[64 + 1 + 4];
        memcpy(pre, ctx->intent_id, 64);
        pre[64] = RTN_SYSFUND_REL_KIND;
        rtn_put32(pre + 65, RTN_SYSFUND_REL_INDEX);
        if (qgp_sha3_512(pre, sizeof(pre), rel_id) != 0) return -2;
        /* owner = the DELEGATOR named in the SYSTEM call (bft.c:1873
         * pays signer_pubkey; here the call-carried identity, which the
         * SYSTEM leg's own auth gate binds to the verified signer) */
        rtn_deleg_call_t d;
        if (rtn_deleg_parse(spc, spl, &d) != 0) return -1;
        uint8_t ofp[64];
        if (qgp_sha3_512(d.delegator_pubkey, DNAC_PUBKEY_SIZE, ofp) != 0)
            return -2;
        rtn_fp_hex(ofp, rel_rec);                    /* owner fp (128)   */
        rtn_put64(rel_rec + 128, release);           /* amount           */
        /* token stays the 64 native zeros; the seed window is unused —
         * this row's identity is passed explicitly, not derived from a
         * seed (the synthetic-UTXO rule, not the wire-output rule) */
    }

    /* ── the CREATE run: change outputs AND the release UTXO ─────────
     * All of them are (DNA_EFFECT_CREATE, RTN_CORE_OP_UTXO) records, and
     * the effect codec orders records by (kind, op_id, key) STRICTLY
     * ascending (effect_wire.h "CANONICAL ORDER"). They are therefore
     * ONE key-sorted run, NOT "the change outputs, then the release":
     * the release id sorts wherever its bytes fall. The duplicate check
     * covers the release id too and returns a VERDICT — letting the
     * encoder catch it would surface an attacker-reachable collision as
     * a node fault (-2), which is the wrong class. */
    uint8_t        nul[RTN_SPEND_MAX_OUT + 1][64];
    const uint8_t *crec[RTN_SPEND_MAX_OUT + 1];
    uint8_t        cidx[RTN_SPEND_MAX_OUT + 1];
    uint8_t        order[RTN_SPEND_MAX_OUT + 1];
    uint8_t        nc = 0;
    for (uint8_t o = 0; o < c->out_count; o++) {
        const uint8_t *rec = c->outs + (size_t)o * RTN_SPEND_OUT_LEN;
        uint8_t pre[160];
        memcpy(pre, rec, 128);                       /* fp (128 hex)     */
        memcpy(pre + 128, rec + 200, 32);            /* seed             */
        if (qgp_sha3_512(pre, sizeof(pre), nul[nc]) != 0) return -2;
        crec[nc] = rec;
        cidx[nc] = o;
        order[nc] = nc;
        nc++;
    }
    if (release > 0) {
        memcpy(nul[nc], rel_id, 64);
        crec[nc] = rel_rec;
        cidx[nc] = (uint8_t)RTN_SYSFUND_REL_INDEX;
        order[nc] = nc;
        nc++;
    }
    for (uint8_t a = 1; a < nc; a++) {               /* insertion sort   */
        uint8_t key = order[a];
        int b = a - 1;
        while (b >= 0 && memcmp(nul[order[b]], nul[key], 64) > 0) {
            order[b + 1] = order[b];
            b--;
        }
        order[b + 1] = key;
    }
    for (uint8_t a = 1; a < nc; a++)
        if (memcmp(nul[order[a - 1]], nul[order[a]], 64) == 0)
            return -1;                   /* duplicate output identity    */

    /* ── canonical typed-effect result ──────────────────────────────── */
    dna_effect_in_t effs[RTN_SPEND_MAX_OUT + 2 + RTN_SPEND_MAX_IN];
    uint8_t crv[RTN_SPEND_MAX_OUT + 1][RTN_UTXO_REC_LEN];
    uint8_t dvh[RTN_SPEND_MAX_IN][64];
    uint8_t supv[8];
    uint16_t ne = 0;
    memset(effs, 0, sizeof(effs));

    for (uint8_t a = 0; a < nc; a++) {               /* CREATEs (kind 1) */
        uint8_t s = order[a];
        rtn_utxo_create_eff(&effs[ne], crv[a], crec[s], cidx[s],
                            nul[s], ctx);
        ne++;
    }
    /* the ONE burn (kind 2): the FEE ONLY. A locked bond is not
     * destroyed — it moves into a validator/delegation bucket the supply
     * equation already counts. */
    {
        int rc = rtn_supply_burn_eff(&effs[ne], supv, &reads[c->in_count],
                                     fee);
        if (rc != 0) return rc;
        ne++;
    }
    for (uint8_t i = 0; i < c->in_count; i++) {      /* DELETEs (kind 3) */
        if (rtn_utxo_delete_eff(&effs[ne], dvh[i], &reads[i],
                                c->ins + (size_t)i * 64) != 0)
            return -2;
        ne++;
    }

    if (dna_effect_result_encode(effs, ne, res_out, res_cap,
                                 res_len_out) != 0)
        return -2;                       /* unreachable for a leg this
                                          * function built: node fault   */
    return 0;
}

int nodus_rt_core_exec(const nodus_domain_runtime_t *rt,
                       const dna_env_view_t *env, uint16_t leg_index,
                       const nodus_rt_exec_ctx_t *ctx,
                       const nodus_rt_read_res_t *reads, uint16_t n_reads,
                       uint8_t *res_out, size_t res_cap,
                       size_t *res_len_out) {
    (void)rt;
    if (!env || !ctx || !ctx->intent_id || !res_out || !res_len_out)
        return -2;
    if (leg_index >= env->leg_count) return -2;

    /* The ENGINE-verified authorization verdict is the ONLY ownership
     * authority. A commitment without a verdict never reaches here —
     * the engine refuses to execute an unverified leg — and this hook
     * additionally fails closed on a missing/empty verdict. */
    if (!ctx->auth || ctx->auth->n_signers < 1 ||
        ctx->auth->n_signers > NODUS_RT_AUTH_MAX_SIGNERS)
        return -1;

    switch (env->leg[leg_index].runtime_op) {
    case DNA_CORERULE_SPEND: {
        rtn_spend_call_t c;
        if (rtn_spend_parse(env, leg_index, &c) != 0) return -1;
        return rtn_xfer_exec(&c, 0, env, ctx, reads, n_reads,
                             res_out, res_cap, res_len_out);
    }
    case DNA_CORERULE_BURN: {
        rtn_spend_call_t c;
        uint64_t burn = 0;
        if (rtn_burn_parse(env, leg_index, &c, &burn) != 0) return -1;
        return rtn_xfer_exec(&c, burn, env, ctx, reads, n_reads,
                             res_out, res_cap, res_len_out);
    }
    case DNA_CORERULE_TOKEN_CREATE: {
        rtn_tc_call_t t;
        if (rtn_tc_parse(env, leg_index, &t) != 0) return -1;
        return rtn_tc_exec(&t, env, ctx, reads, n_reads,
                           res_out, res_cap, res_len_out);
    }
    case DNA_CORERULE_SYSFUND: {
        rtn_spend_call_t c;
        if (rtn_sysfund_shape(env, leg_index) != 0) return -1;
        if (rtn_sysfund_parse(env, leg_index, &c) != 0) return -1;
        return rtn_sysfund_exec(&c, env, ctx, reads, n_reads,
                                res_out, res_cap, res_len_out);
    }
    default:
        return -1;                       /* un-migrated op: fail closed  */
    }
}

/* ── The compiled CORE storage adapter ──────────────────────────────── */

/* Build the canonical 284-byte record from one utxo_set row statement
 * positioned on a row (columns: owner, amount, token_id, tx_hash,
 * output_index, block_height, unlock_block). @return 0 / -1 malformed. */
static int rtn_core_row_record(sqlite3_stmt *st, uint8_t rec[RTN_UTXO_REC_LEN]) {
    const unsigned char *owner = sqlite3_column_text(st, 0);
    const uint8_t *token = sqlite3_column_blob(st, 2);
    const uint8_t *txh = sqlite3_column_blob(st, 3);
    if (!owner || strlen((const char *)owner) != 128) return -1;
    if (!token || sqlite3_column_bytes(st, 2) != 64) return -1;
    if (!txh || sqlite3_column_bytes(st, 3) != 64) return -1;
    /* a NEGATIVE stored integer is a malformed row: surfacing it as a
     * huge u64 would be a silent value (the "DB failure is never a
     * value" rule) — fail closed instead (R4 review) */
    sqlite3_int64 amount = sqlite3_column_int64(st, 1);
    sqlite3_int64 oidx   = sqlite3_column_int64(st, 4);
    sqlite3_int64 bh     = sqlite3_column_int64(st, 5);
    sqlite3_int64 unlock = sqlite3_column_int64(st, 6);
    if (amount < 0 || oidx < 0 || oidx > (sqlite3_int64)UINT32_MAX ||
        bh < 0 || unlock < 0)
        return -1;
    memcpy(rec + RTN_UTXO_OWNER_OFF, owner, 128);
    rtn_put64(rec + RTN_UTXO_AMOUNT_OFF, (uint64_t)amount);
    memcpy(rec + RTN_UTXO_TOKEN_OFF, token, 64);
    memcpy(rec + RTN_UTXO_TXH_OFF, txh, 64);
    rtn_put32(rec + RTN_UTXO_OIDX_OFF, (uint32_t)oidx);
    rtn_put64(rec + RTN_UTXO_BH_OFF, (uint64_t)bh);
    rtn_put64(rec + RTN_UTXO_UNLOCK_OFF, (uint64_t)unlock);
    return 0;
}

/* 0 = record built, 1 = absent, -1 = fault. */
static int rtn_core_utxo_fetch(nodus_witness_t *w, uint32_t dom,
                               const uint8_t *key, uint16_t key_len,
                               uint8_t rec[RTN_UTXO_REC_LEN]) {
    if (key_len != 64) return -1;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT owner, amount, token_id, tx_hash, output_index, "
            "block_height, unlock_block FROM utxo_set "
            "WHERE nullifier = ?1 AND domain_id = ?2", -1, &st, NULL)
        != SQLITE_OK)
        return -1;
    sqlite3_bind_blob(st, 1, key, 64, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)dom);
    int rc = sqlite3_step(st);
    int out;
    if (rc == SQLITE_ROW)
        out = rtn_core_row_record(st, rec) == 0 ? 0 : -1;
    else
        out = rc == SQLITE_DONE ? 1 : -1;
    sqlite3_finalize(st);
    return out;
}

/* Build the canonical 188-byte registry record from one tokens row.
 * Fail-closed on every malformed shape (the rtn_core_row_record rule:
 * a corrupt row is never surfaced as a value). The `tokens` table is
 * CORE-LOCAL LEGACY STATE with no domain_id column — it is reachable
 * only through THIS adapter, which only the compiled DNA_CORE runtime
 * entry binds, so the domain scope is the binding itself.
 * 0 = record built, 1 = absent, -1 = fault. */
static int rtn_core_token_fetch(nodus_witness_t *w, const uint8_t *key,
                                uint16_t key_len,
                                uint8_t rec[RTN_TOKEN_REC_LEN]) {
    if (key_len != 64) return -1;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT name, symbol, decimals, supply, creator_fp, flags, "
            "block_height FROM tokens WHERE token_id = ?1",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_blob(st, 1, key, 64, SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);
    if (rc == SQLITE_DONE) {
        sqlite3_finalize(st);
        return 1;
    }
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(st);
        return -1;
    }
    const unsigned char *name = sqlite3_column_text(st, 0);
    const unsigned char *sym  = sqlite3_column_text(st, 1);
    const unsigned char *cfp  = sqlite3_column_text(st, 4);
    size_t nl = name ? strlen((const char *)name) : 0;
    size_t sl = sym ? strlen((const char *)sym) : 0;
    sqlite3_int64 dec = sqlite3_column_int64(st, 2);
    sqlite3_int64 sup = sqlite3_column_int64(st, 3);
    sqlite3_int64 flg = sqlite3_column_int64(st, 5);
    sqlite3_int64 bh  = sqlite3_column_int64(st, 6);
    int out = -1;
    if (name && sym && cfp && strlen((const char *)cfp) == 128 &&
        nl >= 1 && nl <= RTN_TC_NAME_MAX &&
        sl >= 1 && sl <= RTN_TC_SYM_MAX &&
        dec >= 0 && dec <= 255 && flg >= 0 && flg <= 255 &&
        sup >= 0 && bh >= 0) {
        memset(rec, 0, RTN_TOKEN_REC_LEN);
        rtn_put64(rec + RTN_TOKEN_SUPPLY_OFF, (uint64_t)sup);
        rec[RTN_TOKEN_DEC_OFF] = (uint8_t)dec;
        rec[RTN_TOKEN_FLAGS_OFF] = (uint8_t)flg;
        rtn_put64(rec + RTN_TOKEN_BH_OFF, (uint64_t)bh);
        memcpy(rec + RTN_TOKEN_CFP_OFF, cfp, 128);
        rec[RTN_TOKEN_NLEN_OFF] = (uint8_t)nl;
        memcpy(rec + RTN_TOKEN_NAME_OFF, name, nl);
        rec[RTN_TOKEN_SLEN_OFF] = (uint8_t)sl;
        memcpy(rec + RTN_TOKEN_SYM_OFF, sym, sl);
        out = 0;
    }
    sqlite3_finalize(st);
    return out;
}

/* Validate one canonical 188-byte registry record on the MUTATE side:
 * exactly ONE encoding per row — lengths in range, zero padding
 * actually zero, canonical text, AND the numeric storage bounds
 * (supply/block_height fit the SQLite INTEGER column, decimals within
 * the client rule, flags 0 — no flag semantics shipped). The fetch
 * side (rtn_core_token_fetch) enforces the SHAPE bounds (lengths,
 * non-negative integers) but deliberately NOT the text canonicality —
 * legacy-lane rows never faced these write rules and must stay
 * readable (review round: the two validators are asymmetric BY
 * DESIGN, each honest about its own side). */
static int rtn_token_rec_ok(const uint8_t *v) {
    uint8_t nl = v[RTN_TOKEN_NLEN_OFF];
    uint8_t sl = v[RTN_TOKEN_SLEN_OFF];
    if (nl < 1 || nl > RTN_TC_NAME_MAX) return 0;
    if (sl < 1 || sl > RTN_TC_SYM_MAX) return 0;
    if (!rtn_tc_text_ok(v + RTN_TOKEN_NAME_OFF, nl) ||
        !rtn_tc_text_ok(v + RTN_TOKEN_SYM_OFF, sl))
        return 0;
    for (size_t i = RTN_TOKEN_NAME_OFF + nl;
         i < RTN_TOKEN_NAME_OFF + RTN_TC_NAME_MAX; i++)
        if (v[i] != 0) return 0;
    for (size_t i = RTN_TOKEN_SYM_OFF + sl; i < RTN_TOKEN_REC_LEN; i++)
        if (v[i] != 0) return 0;
    if (!rtn_hex_lower_ok(v + RTN_TOKEN_CFP_OFF, 128)) return 0;
    /* numeric storage bounds — a value above INT64_MAX would round-trip
     * negative through the INTEGER column and poison every later fetch
     * of the row (the parse-side gate is the first defense; this is the
     * mutate-side mirror the review round asked for) */
    if (rtn_get64(v + RTN_TOKEN_SUPPLY_OFF) > (uint64_t)INT64_MAX)
        return 0;
    if (rtn_get64(v + RTN_TOKEN_BH_OFF) > (uint64_t)INT64_MAX) return 0;
    if (v[RTN_TOKEN_DEC_OFF] > RTN_TC_DECIMALS_MAX) return 0;
    if (v[RTN_TOKEN_FLAGS_OFF] != 0) return 0;
    return 1;
}

/* 0 = value fetched, 1 = absent, -1 = fault. */
static int rtn_core_burned_fetch(nodus_witness_t *w, uint64_t *out) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT total_burned FROM supply_tracking WHERE id = 1",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    int rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) {
        sqlite3_int64 v = sqlite3_column_int64(st, 0);
        sqlite3_finalize(st);
        if (v < 0) return -1;
        *out = (uint64_t)v;
        return 0;
    }
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 1 : -1;
}

static nodus_adapter_status_t rtn_core_probe(
        const nodus_domain_adapter_t *ad, struct nodus_witness *wns,
        uint32_t dom, const nodus_adapter_op_t *op,
        const uint8_t *key, uint16_t key_len,
        nodus_adapter_row_facts_t *f) {
    (void)ad;
    nodus_witness_t *w = (nodus_witness_t *)wns;
    if (op->op_id == RTN_CORE_OP_UTXO || op->op_id == RTN_CORE_OP_UTXDEL) {
        uint8_t rec[RTN_UTXO_REC_LEN];
        int rc = rtn_core_utxo_fetch(w, dom, key, key_len, rec);
        if (rc < 0) return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        f->exists = (rc == 0);
        if (f->exists) {
            f->version = rtn_get64(rec + RTN_UTXO_AMOUNT_OFF);
            if (dna_effect_value_hash(rec, RTN_UTXO_REC_LEN,
                                      f->value_hash) != 0)
                return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        }
        return NODUS_ADAPTER_OK;
    }
    if (op->op_id == RTN_CORE_OP_SUPPLY) {
        if (key_len != 1 || key[0] != RTN_SUPPLY_SEL_BURNED)
            return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        uint64_t v = 0;
        int rc = rtn_core_burned_fetch(w, &v);
        if (rc < 0) return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        f->exists = (rc == 0);
        if (f->exists) {
            uint8_t vb[8];
            rtn_put64(vb, v);
            f->version = v;
            if (dna_effect_value_hash(vb, 8, f->value_hash) != 0)
                return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        }
        return NODUS_ADAPTER_OK;
    }
    if (op->op_id == RTN_CORE_OP_TOKEN) {
        uint8_t rec[RTN_TOKEN_REC_LEN];
        int rc = rtn_core_token_fetch(w, key, key_len, rec);
        if (rc < 0) return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        f->exists = (rc == 0);
        if (f->exists) {
            f->version = rtn_get64(rec + RTN_TOKEN_SUPPLY_OFF);
            if (dna_effect_value_hash(rec, RTN_TOKEN_REC_LEN,
                                      f->value_hash) != 0)
                return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        }
        return NODUS_ADAPTER_OK;
    }
    return NODUS_ADAPTER_ERR_STORAGE_FAULT;
}

static nodus_adapter_status_t rtn_core_read(
        const nodus_domain_adapter_t *ad, struct nodus_witness *wns,
        uint32_t dom, const nodus_adapter_op_t *op,
        const uint8_t *key, uint16_t key_len,
        int *present, uint8_t *value, uint32_t cap, uint32_t *vlen) {
    (void)ad;
    nodus_witness_t *w = (nodus_witness_t *)wns;
    *present = 0;
    *vlen = 0;
    if (op->op_id == RTN_CORE_OP_UTXO || op->op_id == RTN_CORE_OP_UTXDEL) {
        uint8_t rec[RTN_UTXO_REC_LEN];
        int rc = rtn_core_utxo_fetch(w, dom, key, key_len, rec);
        if (rc < 0) return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        if (rc == 1) return NODUS_ADAPTER_OK;        /* absent           */
        if (cap < RTN_UTXO_REC_LEN)
            return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        memcpy(value, rec, RTN_UTXO_REC_LEN);
        *present = 1;
        *vlen = RTN_UTXO_REC_LEN;
        return NODUS_ADAPTER_OK;
    }
    if (op->op_id == RTN_CORE_OP_SUPPLY) {
        if (key_len != 1 || key[0] != RTN_SUPPLY_SEL_BURNED)
            return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        uint64_t v = 0;
        int rc = rtn_core_burned_fetch(w, &v);
        if (rc < 0) return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        if (rc == 1) return NODUS_ADAPTER_OK;
        if (cap < 8) return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        rtn_put64(value, v);
        *present = 1;
        *vlen = 8;
        return NODUS_ADAPTER_OK;
    }
    if (op->op_id == RTN_CORE_OP_TOKEN) {
        uint8_t rec[RTN_TOKEN_REC_LEN];
        int rc = rtn_core_token_fetch(w, key, key_len, rec);
        if (rc < 0) return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        if (rc == 1) return NODUS_ADAPTER_OK;        /* absent           */
        if (cap < RTN_TOKEN_REC_LEN)
            return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        memcpy(value, rec, RTN_TOKEN_REC_LEN);
        *present = 1;
        *vlen = RTN_TOKEN_REC_LEN;
        return NODUS_ADAPTER_OK;
    }
    return NODUS_ADAPTER_ERR_STORAGE_FAULT;
}

static nodus_adapter_status_t rtn_core_mutate(
        const nodus_domain_adapter_t *ad, struct nodus_witness *wns,
        uint32_t dom, const nodus_adapter_op_t *op, uint8_t kind,
        const uint8_t *key, uint16_t key_len,
        const uint8_t *value, uint32_t value_len) {
    (void)ad;
    nodus_witness_t *w = (nodus_witness_t *)wns;
    sqlite3_stmt *st = NULL;
    if (op->op_id == RTN_CORE_OP_UTXO && kind == DNA_EFFECT_CREATE) {
        if (key_len != 64 || value_len != RTN_UTXO_REC_LEN || !value)
            return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        if (sqlite3_prepare_v2(w->db,
                "INSERT INTO utxo_set (nullifier, owner, amount, "
                "token_id, tx_hash, output_index, block_height, "
                "created_at, unlock_block, domain_id) "
                "VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0, ?8, ?9)",
                -1, &st, NULL) != SQLITE_OK)
            return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        sqlite3_bind_blob(st, 1, key, 64, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, (const char *)(value + RTN_UTXO_OWNER_OFF),
                          128, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 3,
            (sqlite3_int64)rtn_get64(value + RTN_UTXO_AMOUNT_OFF));
        sqlite3_bind_blob(st, 4, value + RTN_UTXO_TOKEN_OFF, 64,
                          SQLITE_TRANSIENT);
        sqlite3_bind_blob(st, 5, value + RTN_UTXO_TXH_OFF, 64,
                          SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 6, (sqlite3_int64)(
            ((uint32_t)value[RTN_UTXO_OIDX_OFF] << 24) |
            ((uint32_t)value[RTN_UTXO_OIDX_OFF + 1] << 16) |
            ((uint32_t)value[RTN_UTXO_OIDX_OFF + 2] << 8) |
            (uint32_t)value[RTN_UTXO_OIDX_OFF + 3]));
        sqlite3_bind_int64(st, 7,
            (sqlite3_int64)rtn_get64(value + RTN_UTXO_BH_OFF));
        sqlite3_bind_int64(st, 8,
            (sqlite3_int64)rtn_get64(value + RTN_UTXO_UNLOCK_OFF));
        sqlite3_bind_int64(st, 9, (sqlite3_int64)dom);
    } else if (op->op_id == RTN_CORE_OP_UTXDEL &&
               kind == DNA_EFFECT_DELETE) {
        if (key_len != 64) return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        if (sqlite3_prepare_v2(w->db,
                "DELETE FROM utxo_set WHERE nullifier = ?1 AND "
                "domain_id = ?2", -1, &st, NULL) != SQLITE_OK)
            return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        sqlite3_bind_blob(st, 1, key, 64, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 2, (sqlite3_int64)dom);
    } else if (op->op_id == RTN_CORE_OP_SUPPLY &&
               kind == DNA_EFFECT_SET) {
        if (key_len != 1 || key[0] != RTN_SUPPLY_SEL_BURNED ||
            value_len != 8 || !value)
            return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        /* absolute new counter; current_supply kept coherent by the
         * same derivation the legacy burn maintains (genesis + minted
         * − burned); last_tx_hash is audit-only and stays unchanged */
        if (sqlite3_prepare_v2(w->db,
                "UPDATE supply_tracking SET total_burned = ?1, "
                "current_supply = genesis_supply + total_minted - ?1, "
                "last_sequence = last_sequence + 1 WHERE id = 1",
                -1, &st, NULL) != SQLITE_OK)
            return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        sqlite3_bind_int64(st, 1, (sqlite3_int64)rtn_get64(value));
    } else if (op->op_id == RTN_CORE_OP_TOKEN &&
               kind == DNA_EFFECT_CREATE) {
        if (key_len != 64 || value_len != RTN_TOKEN_REC_LEN || !value ||
            !rtn_token_rec_ok(value))
            return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        /* STRICT insert — never the legacy INSERT OR IGNORE
         * (nodus_witness_db.c:1503): the ABSENT precondition already
         * ruled inside this transaction, so a conflicting row here is a
         * broken invariant on THIS node, never a silent drop.
         * timestamp is written 0: deterministic lane, audit-only column
         * EXCLUDED from the token merkle leaf
         * (nodus_witness_roots_v2.c:36-37). */
        if (sqlite3_prepare_v2(w->db,
                "INSERT INTO tokens (token_id, name, symbol, decimals, "
                "supply, creator_fp, flags, block_height, timestamp) "
                "VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0)",
                -1, &st, NULL) != SQLITE_OK)
            return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        sqlite3_bind_blob(st, 1, key, 64, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2,
                          (const char *)(value + RTN_TOKEN_NAME_OFF),
                          (int)value[RTN_TOKEN_NLEN_OFF],
                          SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 3,
                          (const char *)(value + RTN_TOKEN_SYM_OFF),
                          (int)value[RTN_TOKEN_SLEN_OFF],
                          SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 4, (sqlite3_int64)value[RTN_TOKEN_DEC_OFF]);
        sqlite3_bind_int64(st, 5,
            (sqlite3_int64)rtn_get64(value + RTN_TOKEN_SUPPLY_OFF));
        sqlite3_bind_text(st, 6,
                          (const char *)(value + RTN_TOKEN_CFP_OFF), 128,
                          SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 7,
                           (sqlite3_int64)value[RTN_TOKEN_FLAGS_OFF]);
        sqlite3_bind_int64(st, 8,
            (sqlite3_int64)rtn_get64(value + RTN_TOKEN_BH_OFF));
    } else {
        return NODUS_ADAPTER_ERR_STORAGE_FAULT;
    }
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) return NODUS_ADAPTER_ERR_STORAGE_FAULT;
    if (sqlite3_changes(w->db) != 1)
        return NODUS_ADAPTER_ERR_STORAGE_FAULT;
    return NODUS_ADAPTER_OK;
}

static const nodus_adapter_op_t RTN_CORE_OPS[4] = {
    { RTN_CORE_OP_UTXO,
      NODUS_ADAPTER_KIND_BIT(DNA_EFFECT_CREATE),
      NODUS_ADAPTER_PRECOND_BIT(DNA_EFFECT_PRE_ABSENT),
      64, 64, RTN_UTXO_REC_LEN, RTN_UTXO_REC_LEN },
    { RTN_CORE_OP_UTXDEL,
      NODUS_ADAPTER_KIND_BIT(DNA_EFFECT_DELETE),
      (uint8_t)(NODUS_ADAPTER_PRECOND_BIT(DNA_EFFECT_PRE_EXISTS) |
                NODUS_ADAPTER_PRECOND_BIT(DNA_EFFECT_PRE_EXISTS_VERSION) |
                NODUS_ADAPTER_PRECOND_BIT(DNA_EFFECT_PRE_EXISTS_VHASH)),
      64, 64, 0, 0 },
    { RTN_CORE_OP_SUPPLY,
      NODUS_ADAPTER_KIND_BIT(DNA_EFFECT_SET),
      (uint8_t)(NODUS_ADAPTER_PRECOND_BIT(DNA_EFFECT_PRE_EXISTS) |
                NODUS_ADAPTER_PRECOND_BIT(DNA_EFFECT_PRE_EXISTS_VERSION)),
      1, 1, 8, 8 },
    /* burn season — the TOKEN_CREATE registry row (tokens table) */
    { RTN_CORE_OP_TOKEN,
      NODUS_ADAPTER_KIND_BIT(DNA_EFFECT_CREATE),
      NODUS_ADAPTER_PRECOND_BIT(DNA_EFFECT_PRE_ABSENT),
      64, 64, RTN_TOKEN_REC_LEN, RTN_TOKEN_REC_LEN }
};

const nodus_domain_adapter_t NODUS_RT_CORE_ADAPTER = {
    .adapter_version = NODUS_DOMAIN_ADAPTER_V1,
    .ops = RTN_CORE_OPS,
    .n_ops = 4,
    .probe = rtn_core_probe,
    .mutate = rtn_core_mutate,
    .read = rtn_core_read
};

/* ══════════════════════════════════════════════════════════════════════
 * SYSTEM — DNA_SYSRULE_STAKE (O11) / DNA_SYSRULE_CHAIN_CONFIG
 * ════════════════════════════════════════════════════════════════════ */

#define RTN_SYS_OP_CC        1u  /* CREATE: chain_config_history row     */
/* op id 2 (the mediated committee witness-id read) is RETIRED with the
 * capacity season: committee membership and signatures verify at the
 * AUTHORIZATION boundary against the engine-resolved snapshot
 * (auth_kind 2), so the exec phase no longer reads the committee at
 * all. The id is not reused. */
#define RTN_SYS_OP_CCLATEST  3u  /* READ-ONLY: latest nonzero value      */
/* O11 — the stake-lifecycle rows. Ids are APPENDED strictly ascending;
 * 1 and 3 are frozen (an op id is part of every committed effect). */
#define RTN_SYS_OP_VAL       4u  /* CREATE|SET + read: validators row    */
#define RTN_SYS_OP_DELEG     5u  /* CREATE|SET|DELETE + read: delegation */
#define RTN_SYS_OP_DELEGCNT  6u  /* READ-ONLY: delegations by validator  */
#define RTN_SYS_OP_STATS     7u  /* SET + read: validator_stats counter  */

/* The canonical validator record (exact 5397 bytes — O11). It is
 * EXACTLY the sixteen columns the validator merkle leaf hashes, in leaf
 * order (nodus_witness_merkle.c:880-896 / load_validator_leaves), so the
 * mediated read serves precisely what the state root commits and nothing
 * else. The `pubkey_hash` PK is the effect KEY, not part of the value
 * (it is a pure function of the pubkey — rtn_tag_key).
 *   [0..2591]     pubkey                       DNAC_PUBKEY_SIZE
 *   [2592..2599]  self_stake                   u64 BE
 *   [2600..2607]  total_delegated              u64 BE
 *   [2608..2615]  external_delegated           u64 BE
 *   [2616..2617]  commission_bps               u16 BE
 *   [2618..2619]  pending_commission_bps       u16 BE
 *   [2620..2627]  pending_effective_block      u64 BE
 *   [2628]        status                       u8
 *   [2629..2636]  active_since_block           u64 BE
 *   [2637..2644]  unstake_commit_block         u64 BE
 *   [2645..2772]  unstake_destination_fp       128 B, the ZERO-PADDED
 *                 window the leaf hashes (merkle.c:975-1036) — NOT a C
 *                 string; a legacy row shorter than 128 chars pads with
 *                 zeros exactly as the leaf loader does
 *   [2773..5364]  unstake_destination_pubkey   DNAC_PUBKEY_SIZE
 *   [5365..5372]  last_validator_update_block  u64 BE
 *   [5373..5380]  consecutive_missed_epochs    u64 BE
 *   [5381..5388]  last_signed_block            u64 BE
 *   [5389..5396]  signed_blocks_this_epoch     u64 BE
 *
 * ⚠ SPEC NOTE: the O11 design doc §4.4 states this total as 5417. The
 * field list it enumerates (identical to the one above, and to the
 * merkle leaf) sums to 5397 — 2×2592 + 128 + 10×u64 + 2×u16 + 1×u8.
 * There is no sixteen-column layout that reaches 5417 and no consumer of
 * the stated total, so the LAYOUT is authoritative and the record is
 * 5397 bytes; padding twenty meaningless bytes to match the prose would
 * put un-derived bytes inside a hashed value. */
#define RTN_VAL_PK_OFF        0u
#define RTN_VAL_SELF_OFF      ((uint32_t)DNAC_PUBKEY_SIZE)
#define RTN_VAL_TOTDEL_OFF    (RTN_VAL_SELF_OFF + 8u)
#define RTN_VAL_EXTDEL_OFF    (RTN_VAL_TOTDEL_OFF + 8u)
#define RTN_VAL_COMM_OFF      (RTN_VAL_EXTDEL_OFF + 8u)
#define RTN_VAL_PCOMM_OFF     (RTN_VAL_COMM_OFF + 2u)
#define RTN_VAL_PEFF_OFF      (RTN_VAL_PCOMM_OFF + 2u)
#define RTN_VAL_STATUS_OFF    (RTN_VAL_PEFF_OFF + 8u)
#define RTN_VAL_SINCE_OFF     (RTN_VAL_STATUS_OFF + 1u)
#define RTN_VAL_UCOMMIT_OFF   (RTN_VAL_SINCE_OFF + 8u)
#define RTN_VAL_DFP_OFF       (RTN_VAL_UCOMMIT_OFF + 8u)
#define RTN_VAL_DFP_LEN       128u
#define RTN_VAL_DPK_OFF       (RTN_VAL_DFP_OFF + RTN_VAL_DFP_LEN)
#define RTN_VAL_LASTUPD_OFF   (RTN_VAL_DPK_OFF + (uint32_t)DNAC_PUBKEY_SIZE)
#define RTN_VAL_MISSED_OFF    (RTN_VAL_LASTUPD_OFF + 8u)
#define RTN_VAL_LSIGNED_OFF   (RTN_VAL_MISSED_OFF + 8u)
#define RTN_VAL_SIGNEP_OFF    (RTN_VAL_LSIGNED_OFF + 8u)
#define RTN_VAL_REC_LEN       (RTN_VAL_SIGNEP_OFF + 8u)
_Static_assert(RTN_VAL_REC_LEN == 5397u,
               "validator record layout drifted — re-derive from the "
               "merkle leaf column list");
_Static_assert(RTN_VAL_REC_LEN <= (uint32_t)DNA_EFFECT_MAX_VALUE_LEN,
               "validator record no longer fits one typed effect value");
#define RTN_VAL_KEY_LEN       64u   /* the validator-tree leaf key       */

/* The canonical delegation record (exact 5200 bytes — O11): exactly the
 * four columns the delegation merkle leaf hashes, in leaf order
 * (nodus_witness_merkle.c:1116-1119). The composite key is the PK pair,
 * not part of the value.
 *   [0..2591]     delegator_pubkey   DNAC_PUBKEY_SIZE
 *   [2592..5183]  validator_pubkey   DNAC_PUBKEY_SIZE
 *   [5184..5191]  amount             u64 BE
 *   [5192..5199]  delegated_at_block u64 BE */
#define RTN_DEL_DPK_OFF       0u
#define RTN_DEL_VPK_OFF       ((uint32_t)DNAC_PUBKEY_SIZE)
#define RTN_DEL_AMT_OFF       (2u * (uint32_t)DNAC_PUBKEY_SIZE)
#define RTN_DEL_AT_OFF        (RTN_DEL_AMT_OFF + 8u)
#define RTN_DEL_REC_LEN       (RTN_DEL_AT_OFF + 8u)
_Static_assert(RTN_DEL_REC_LEN == 5200u, "delegation record drifted");
_Static_assert(RTN_DEL_REC_LEN <= (uint32_t)DNA_EFFECT_MAX_VALUE_LEN,
               "delegation record no longer fits one typed effect value");
/** delegator_hash[64] ‖ validator_hash[64] — the delegations PK, in the
 *  same order the shipped table declares it (nodus_witness_delegation.c
 *  delegation_row_hash on each side). Exactly DNA_EFFECT_MAX_KEY_LEN. */
#define RTN_DEL_KEY_LEN       128u
_Static_assert(RTN_DEL_KEY_LEN <= (uint32_t)DNA_EFFECT_MAX_KEY_LEN,
               "delegation key no longer fits the effect codec");

/** validator_stats selector: 1 = 'active_count' (the ONE counter this
 *  slice consumes; the table is a key/value store, so the selector byte
 *  is the compiled name→key mapping and an unknown selector fails
 *  closed). */
#define RTN_STATS_SEL_ACTIVE  1u

/* CC row canonical value (exact 88 bytes):
 *   [0..7]   new_value       u64 BE
 *   [8..15]  commit_block    u64 BE (the executing global height)
 *   [16..23] proposal_nonce  u64 BE
 *   [24..87] tx_hash         64 B  (V2: the engine-derived INTENT
 *                            identity ctx->intent_id — witness-stable
 *                            provenance; NEVER the full-wire wire_id)
 * Exactly the columns the chain-config merkle leaf consumes
 * (param_id/new_value/effective/commit_block/nonce —
 * nodus_witness_chain_config.c:389) plus the provenance tx_hash (leaf-
 * excluded, but a consensus-owned row — intent keeps it twin-stable);
 * created_at_unix is written 0 (deterministic lane, audit-only). */
#define RTN_CC_VAL_LEN   88u
#define RTN_CC_KEY_LEN   12u     /* param_id u32 BE ‖ effective u64 BE  */

/* CHAIN_CONFIG call v2 exact length: RTN_CC_CALL_LEN — defined with the
 * capacity-derivation asserts near the top of this file. */

typedef struct {
    uint8_t  param_id;
    uint64_t new_value, effective, nonce, signed_at, valid_before;
} rtn_cc_call_t;

static int rtn_cc_parse(const dna_env_view_t *env, uint16_t leg,
                        rtn_cc_call_t *c) {
    const uint8_t *p = env->buf + env->call_off[leg];
    uint32_t len = env->leg[leg].call_len;
    if (len != RTN_CC_CALL_LEN) return -1;   /* exact, never a prefix    */
    c->param_id     = p[0];
    c->new_value    = rtn_get64(p + 1);
    c->effective    = rtn_get64(p + 9);
    c->nonce        = rtn_get64(p + 17);
    c->signed_at    = rtn_get64(p + 25);
    c->valid_before = rtn_get64(p + 33);
    return 0;
}

/* The delegations composite key: delegator_hash ‖ validator_hash, each
 * SHA3-512(NODUS_TREE_TAG_DELEGATION ‖ pubkey). BOTH halves use the
 * DELEGATION tag — nodus_witness_delegation.c delegation_row_hash
 * (:37-42) wraps nodus_merkle_leaf_key with that one tag for the
 * delegator side AND the validator side, which is why a validator's
 * delegations key half is NOT its validator-tree leaf key.
 * @return 0 / -2 hash-backend NODE fault. */
static int rtn_deleg_key(const uint8_t *dpk, const uint8_t *vpk,
                         uint8_t out[RTN_DEL_KEY_LEN]) {
    if (rtn_tag_key(NODUS_TREE_TAG_DELEGATION, dpk, out) != 0) return -2;
    if (rtn_tag_key(NODUS_TREE_TAG_DELEGATION, vpk, out + 64) != 0)
        return -2;
    return 0;
}

/* Checked add PLUS the SQLite INTEGER storage bound, as ONE verdict.
 * Every u64 column these ops write round-trips through an INTEGER
 * column, so a value above INT64_MAX would come back negative and
 * poison every later read; bounding it at the source keeps the
 * rejection a VERDICT instead of the mutate-side node fault
 * (the rtn_stake_exec / rtn_tc_parse precedent). @return 0 / -1. */
static int rtn_add_bounded(uint64_t a, uint64_t b, uint64_t *out) {
    if (dna_ck_add_u64(a, b, out) != 0) return -1;
    if (*out > (uint64_t)INT64_MAX) return -1;
    return 0;
}

/* Bind one SET to the EXACT record the mediated read observed: the new
 * value is built FROM that record by the caller, and the precondition is
 * that record's value hash, so (a) a transition can only change the
 * columns it explicitly writes and (b) the read and the mutation can
 * never disagree about the row (the rtn_utxo_delete_eff discipline,
 * generalized to the SYSTEM rows). @return 0 / -2 node fault. */
static int rtn_row_set_eff(dna_effect_in_t *eff, uint32_t op_id,
                           const nodus_rt_read_res_t *r, uint32_t rec_len,
                           const uint8_t *key, uint16_t key_len,
                           const uint8_t *newrec) {
    if (r->value_len != rec_len) return -2;
    if (dna_effect_value_hash(r->value, rec_len,
                              eff->hdr.expected_vhash) != 0)
        return -2;
    eff->hdr.op_id = op_id;
    eff->hdr.effect_kind = DNA_EFFECT_SET;
    eff->hdr.precond_tag = DNA_EFFECT_PRE_EXISTS_VHASH;
    eff->hdr.key_len = key_len;
    eff->hdr.value_len = rec_len;
    eff->key = key;
    eff->value = newrec;
    return 0;
}

/* The delegation-row DELETE, bound the same way (a fully drained
 * delegation is REMOVED — bft.c:1879-1881). @return 0 / -2. */
static int rtn_deleg_del_eff(dna_effect_in_t *eff,
                             const nodus_rt_read_res_t *r,
                             const uint8_t *key) {
    if (r->value_len != RTN_DEL_REC_LEN) return -2;
    if (dna_effect_value_hash(r->value, RTN_DEL_REC_LEN,
                              eff->hdr.expected_vhash) != 0)
        return -2;
    eff->hdr.op_id = RTN_SYS_OP_DELEG;
    eff->hdr.effect_kind = DNA_EFFECT_DELETE;
    eff->hdr.precond_tag = DNA_EFFECT_PRE_EXISTS_VHASH;
    eff->hdr.key_len = (uint16_t)RTN_DEL_KEY_LEN;
    eff->hdr.value_len = 0;
    eff->key = key;
    eff->value = NULL;
    return 0;
}

/* STAKE (O11) read plan: the validator row this operation creates (Rule
 * I — it must be ABSENT) and the active-validator counter it increments.
 * Ascending (op_id, key) by construction: op 4 before op 7. */
static int rtn_stake_read_plan(const dna_env_view_t *env,
                               uint16_t leg_index,
                               nodus_rt_read_req_t *reqs_out,
                               uint16_t max_reqs, uint16_t *n_out) {
    rtn_stake_call_t c;
    if (rtn_sys_stake_shape(env, leg_index) != 0) return -1;
    if (rtn_stake_parse(env->buf + env->call_off[leg_index],
                        env->leg[leg_index].call_len, &c) != 0)
        return -1;
    if (max_reqs < 2) return -1;
    memset(&reqs_out[0], 0, sizeof(reqs_out[0]));
    reqs_out[0].op_id = RTN_SYS_OP_VAL;
    reqs_out[0].key_len = (uint16_t)RTN_VAL_KEY_LEN;
    if (rtn_tag_key(NODUS_TREE_TAG_VALIDATOR, c.staker_pubkey,
                    reqs_out[0].key) != 0)
        return -2;                       /* hash backend: NODE fault     */
    memset(&reqs_out[1], 0, sizeof(reqs_out[1]));
    reqs_out[1].op_id = RTN_SYS_OP_STATS;
    reqs_out[1].key_len = 1;
    reqs_out[1].key[0] = RTN_STATS_SEL_ACTIVE;
    *n_out = 2;
    return 0;
}

/* DELEGATE / UNDELEGATE (O11) share ONE read plan: the target validator
 * row and the (delegator, validator) delegation row. Ascending
 * (op_id, key) by construction: op 4 before op 5. */
static int rtn_deleg_pair_read_plan(const dna_env_view_t *env,
                                    uint16_t leg_index,
                                    nodus_rt_read_req_t *reqs_out,
                                    uint16_t max_reqs, uint16_t *n_out) {
    rtn_deleg_call_t c;
    if (rtn_sys_stake_shape(env, leg_index) != 0) return -1;
    if (rtn_deleg_parse(env->buf + env->call_off[leg_index],
                        env->leg[leg_index].call_len, &c) != 0)
        return -1;
    if (max_reqs < 2) return -1;
    memset(&reqs_out[0], 0, sizeof(reqs_out[0]));
    reqs_out[0].op_id = RTN_SYS_OP_VAL;
    reqs_out[0].key_len = (uint16_t)RTN_VAL_KEY_LEN;
    if (rtn_tag_key(NODUS_TREE_TAG_VALIDATOR, c.validator_pubkey,
                    reqs_out[0].key) != 0)
        return -2;
    memset(&reqs_out[1], 0, sizeof(reqs_out[1]));
    reqs_out[1].op_id = RTN_SYS_OP_DELEG;
    reqs_out[1].key_len = (uint16_t)RTN_DEL_KEY_LEN;
    if (rtn_deleg_key(c.delegator_pubkey, c.validator_pubkey,
                      reqs_out[1].key) != 0)
        return -2;
    *n_out = 2;
    return 0;
}

/* UNSTAKE (O11) read plan: the validator's own row and Rule A's input —
 * how many delegations still reference it. Ascending: op 4 before op 6.
 * The two keys are DIFFERENT derivations of the same pubkey (validator
 * tree tag vs delegation row tag) — see rtn_deleg_key. */
static int rtn_unstake_read_plan(const dna_env_view_t *env,
                                 uint16_t leg_index,
                                 nodus_rt_read_req_t *reqs_out,
                                 uint16_t max_reqs, uint16_t *n_out) {
    const uint8_t *vpk = NULL;
    if (rtn_sys_stake_shape(env, leg_index) != 0) return -1;
    if (rtn_sys_call_identity(DNA_SYSRULE_UNSTAKE,
                              env->buf + env->call_off[leg_index],
                              env->leg[leg_index].call_len, &vpk) != 0)
        return -1;
    if (max_reqs < 2) return -1;
    memset(&reqs_out[0], 0, sizeof(reqs_out[0]));
    reqs_out[0].op_id = RTN_SYS_OP_VAL;
    reqs_out[0].key_len = (uint16_t)RTN_VAL_KEY_LEN;
    if (rtn_tag_key(NODUS_TREE_TAG_VALIDATOR, vpk, reqs_out[0].key) != 0)
        return -2;
    memset(&reqs_out[1], 0, sizeof(reqs_out[1]));
    reqs_out[1].op_id = RTN_SYS_OP_DELEGCNT;
    reqs_out[1].key_len = 64;
    if (rtn_tag_key(NODUS_TREE_TAG_DELEGATION, vpk, reqs_out[1].key) != 0)
        return -2;
    *n_out = 2;
    return 0;
}

/* VALIDATOR_UPDATE (O12 S1) read plan: ONE mediated read — the validator
 * row named by the call's identity pubkey. It is the only row this op
 * touches; nothing else is consulted (no counter, no delegation count, no
 * snapshot), because nothing else moves. */
static int rtn_vupd_read_plan(const dna_env_view_t *env,
                              uint16_t leg_index,
                              nodus_rt_read_req_t *reqs_out,
                              uint16_t max_reqs, uint16_t *n_out) {
    rtn_vupd_call_t c;
    if (rtn_sys_stake_shape(env, leg_index) != 0) return -1;
    if (rtn_vupd_parse(env->buf + env->call_off[leg_index],
                       env->leg[leg_index].call_len, &c) != 0)
        return -1;
    if (max_reqs < 1) return -1;
    memset(&reqs_out[0], 0, sizeof(reqs_out[0]));
    reqs_out[0].op_id = RTN_SYS_OP_VAL;
    reqs_out[0].key_len = (uint16_t)RTN_VAL_KEY_LEN;
    if (rtn_tag_key(NODUS_TREE_TAG_VALIDATOR, c.validator_pubkey,
                    reqs_out[0].key) != 0)
        return -2;                           /* hash backend: NODE fault */
    *n_out = 1;
    return 0;
}

int nodus_rt_system_read_plan(const nodus_domain_runtime_t *rt,
                              const dna_env_view_t *env, uint16_t leg_index,
                              const nodus_rt_exec_ctx_t *ctx,
                              nodus_rt_read_req_t *reqs_out,
                              uint16_t max_reqs, uint16_t *n_out) {
    (void)rt;
    if (!env || !ctx || !reqs_out || !n_out) return -2;
    if (leg_index >= env->leg_count) return -2;
    switch (env->leg[leg_index].runtime_op) {
    case DNA_SYSRULE_STAKE:
        return rtn_stake_read_plan(env, leg_index, reqs_out, max_reqs,
                                   n_out);
    case DNA_SYSRULE_DELEGATE:
    case DNA_SYSRULE_UNDELEGATE:
        return rtn_deleg_pair_read_plan(env, leg_index, reqs_out,
                                        max_reqs, n_out);
    case DNA_SYSRULE_UNSTAKE:
        return rtn_unstake_read_plan(env, leg_index, reqs_out, max_reqs,
                                     n_out);
    case DNA_SYSRULE_VALIDATOR_UPDATE:
        return rtn_vupd_read_plan(env, leg_index, reqs_out, max_reqs,
                                  n_out);
    case DNA_SYSRULE_CHAIN_CONFIG:
        break;                           /* falls through to the CC plan */
    default:
        return -1;                       /* un-migrated op: fail closed  */
    }
    rtn_cc_call_t c;
    if (rtn_cc_parse(env, leg_index, &c) != 0) return -1;
    if (ctx->global_height == 0) return -1;   /* no governing committee
                                          * below genesis                */
    /* capacity season: the committee is no longer a mediated read —
     * membership and approvals verified at the AUTH boundary against
     * the engine-resolved snapshot. The one remaining read is the
     * INFLATION_START monotonicity input. */
    uint16_t need = (uint16_t)(c.param_id == DNAC_CFG_INFLATION_START_BLOCK
                                   ? 1 : 0);
    if (need > max_reqs) return -1;
    if (need == 1) {
        memset(&reqs_out[0], 0, sizeof(reqs_out[0]));
        reqs_out[0].op_id = RTN_SYS_OP_CCLATEST;
        reqs_out[0].key_len = 1;
        reqs_out[0].key[0] = c.param_id;
    }
    *n_out = need;
    return 0;
}

/**
 * DNA_SYSRULE_STAKE (O11) — validator registration.
 *
 * Source semantics preserved from apply_stake (nodus_witness_bft.c:
 * 1505-1620): the bond is what the transaction actually locked and must
 * meet the self-bond floor DNAC_SELF_STAKE_AMOUNT (:1568); the new row
 * is created ACTIVE with active_since = the executing height (:1583-84);
 * the unstake destination fingerprint is stored as 128 hex chars
 * (:1595, qgp_fp_raw_to_hex) and the destination PUBKEY is populated
 * ONLY when the fingerprint derives from the staker's own key
 * (:1596-1600), staying all-zero otherwise; every remaining column is
 * zero; validator_stats.active_count is incremented by exactly one
 * (:1610). Rule I — one validator row per pubkey — is the INSERT's
 * primary key in the legacy lane (validator.c returns -2 on
 * SQLITE_CONSTRAINT, bft.c:1602 rejects); here it is the mediated read
 * (row must be ABSENT) AND the CREATE/ABSENT precondition behind it.
 *
 * The bond itself is not moved here: the CORE DNA_CORERULE_SYSFUND leg
 * consumes the inputs and derives its lock from THIS call's bond field,
 * which is why the sibling leg's call must parse before anything is
 * written (a record leg whose funding leg is malformed must not commit).
 *
 * @return 0 / -1 verdict / -2 node fault.
 */
static int rtn_stake_exec(const dna_env_view_t *env, uint16_t leg_index,
                          const nodus_rt_exec_ctx_t *ctx,
                          const nodus_rt_read_res_t *reads,
                          uint16_t n_reads,
                          uint8_t *res_out, size_t res_cap,
                          size_t *res_len_out) {
    rtn_stake_call_t c;
    if (rtn_sys_stake_shape(env, leg_index) != 0) return -1;
    if (rtn_stake_parse(env->buf + env->call_off[leg_index],
                        env->leg[leg_index].call_len, &c) != 0)
        return -1;

    /* ── authority: exactly one verified signer, and it is the staker ─ */
    uint8_t staker_fp[64];
    {
        int rc = rtn_sys_stake_auth(env, leg_index, ctx, staker_fp);
        if (rc != 0) return rc;
    }

    /* ── scalar rules ───────────────────────────────────────────────── */
    if (c.commission_bps > DNAC_COMMISSION_BPS_MAX)
        return -1;                       /* LABELED NARROWING: the legacy
                                          * apply_stake copied
                                          * commission_bps into the row
                                          * unchecked (bft.c:1541, 1581)
                                          * — the 0..10000 bound existed
                                          * only in the CLIENT lane
                                          * (dnac verify.c / transaction.h
                                          * :495). Witness-enforced here,
                                          * fail-closed direction.       */
    if (c.bond < DNAC_SELF_STAKE_AMOUNT)
        return -1;                       /* the self-bond floor (:1568)  */
    if (c.bond > (uint64_t)INT64_MAX)
        return -1;                       /* self_stake is stored in an
                                          * SQLite INTEGER column; a value
                                          * above INT64_MAX would
                                          * round-trip negative and poison
                                          * every later read of the row.
                                          * Bounded at the SOURCE so the
                                          * rejection is a VERDICT — the
                                          * mutate-side mirror in
                                          * rtn_val_rec_ok is a node-fault
                                          * class and must not be the
                                          * first line of defence (the
                                          * rtn_tc_parse precedent).      */

    /* ── mediated reads ─────────────────────────────────────────────── */
    if (n_reads != 2 || !reads) return -2;
    if (reads[0].present) return -1;     /* Rule I: this pubkey already
                                          * has a validator row — reject
                                          * whatever its status is, the
                                          * legacy INSERT would too      */
    if (!reads[1].present) return -1;    /* no active_count row: a chain
                                          * whose validator_stats seed is
                                          * missing cannot be counted     */
    if (reads[1].value_len != 8) return -2;   /* own adapter out of
                                          * contract: node fault         */
    uint64_t count_old = rtn_get64(reads[1].value);
    uint64_t count_new;
    if (dna_ck_add_u64(count_old, 1, &count_new) != 0) return -1;
    if (count_new > (uint64_t)INT64_MAX) return -1;   /* same storage
                                          * bound, same VERDICT class     */

    /* ── the SIBLING funding leg must be a well-formed SYSFUND call ─── */
    {
        rtn_spend_call_t fc;
        if (rtn_sysfund_parse(env, 1, &fc) != 0) return -1;
    }

    /* ── the canonical validator record ─────────────────────────────── */
    uint8_t key[RTN_VAL_KEY_LEN];
    uint8_t val[RTN_VAL_REC_LEN];
    if (rtn_tag_key(NODUS_TREE_TAG_VALIDATOR, c.staker_pubkey, key) != 0)
        return -2;
    memset(val, 0, sizeof(val));
    memcpy(val + RTN_VAL_PK_OFF, c.staker_pubkey, DNAC_PUBKEY_SIZE);
    rtn_put64(val + RTN_VAL_SELF_OFF, c.bond);
    /* total_delegated / external_delegated / pending_* / unstake_commit
     * / the Rule N counters all stay 0 — a fresh validator has no
     * delegation, no pending change and no attendance history */
    val[RTN_VAL_COMM_OFF]     = (uint8_t)(c.commission_bps >> 8);
    val[RTN_VAL_COMM_OFF + 1] = (uint8_t)c.commission_bps;
    val[RTN_VAL_STATUS_OFF]   = (uint8_t)DNAC_VALIDATOR_ACTIVE;
    rtn_put64(val + RTN_VAL_SINCE_OFF, ctx->global_height);
    rtn_fp_hex(c.dest_fp, val + RTN_VAL_DFP_OFF);
    if (memcmp(staker_fp, c.dest_fp, 64) == 0)
        memcpy(val + RTN_VAL_DPK_OFF, c.staker_pubkey, DNAC_PUBKEY_SIZE);
    /* else: all-zero destination pubkey, exactly bft.c:1596-1600 — the
     * post-cooldown payout then has no pre-verified key and the
     * graduation season must resolve one. `staker_fp` is SHA3-512 of the
     * staker pubkey, already derived by the authority gate. */

    /* ── effects: CREATE the row (kind 1), then SET the counter (kind
     *    2) — the effect codec's canonical order is kind-major, so this
     *    is the only legal sequence for this pair. ─────────────────── */
    uint8_t statk[1] = { (uint8_t)RTN_STATS_SEL_ACTIVE };
    uint8_t statv[8];
    rtn_put64(statv, count_new);
    dna_effect_in_t effs[2];
    memset(effs, 0, sizeof(effs));
    effs[0].hdr.op_id = RTN_SYS_OP_VAL;
    effs[0].hdr.effect_kind = DNA_EFFECT_CREATE;
    effs[0].hdr.precond_tag = DNA_EFFECT_PRE_ABSENT;   /* Rule I backstop*/
    effs[0].hdr.key_len = (uint16_t)RTN_VAL_KEY_LEN;
    effs[0].hdr.value_len = RTN_VAL_REC_LEN;
    effs[0].key = key;
    effs[0].value = val;
    effs[1].hdr.op_id = RTN_SYS_OP_STATS;
    effs[1].hdr.effect_kind = DNA_EFFECT_SET;
    effs[1].hdr.precond_tag = DNA_EFFECT_PRE_EXISTS_VERSION;
    effs[1].hdr.expected_version = count_old;   /* bound to the OBSERVED
                                          * counter — the supply-counter
                                          * pattern (rtn_supply_burn_eff)*/
    effs[1].hdr.key_len = 1;
    effs[1].hdr.value_len = 8;
    effs[1].key = statk;
    effs[1].value = statv;
    if (dna_effect_result_encode(effs, 2, res_out, res_cap,
                                 res_len_out) != 0)
        return -2;
    return 0;
}

/* O11 integration fix (ORCHESTRATOR, fault-class): the canonical
 * writable-shape rules, defined with the compiled adapter below. An exec
 * that REWRITES an observed row must decide the row's writability as a
 * VERDICT (-1): whether a committed row satisfies the V2 canonical shape
 * is a deterministic property of committed state — every honest node
 * sees the same row — so surfacing it only through the mutate side's
 * NODE-FAULT class (rtn_val_rec_ok inside rtn_sys_mutate →
 * ERR_STORAGE_FAULT → -2 "do not vote") would turn a legacy-malformed
 * row into a liveness stop an attacker can trigger by targeting it.
 * The mutate-side check remains as defence in depth; THIS check is the
 * first line, in the verdict class. A row that fails it is READ-legal
 * (roots still commit it) but WRITE-frozen for V2 until the activation
 * season's reconciliation (the migration-obligation block below). */
static int rtn_val_rec_ok(const uint8_t *v, const uint8_t *key);
static int rtn_del_rec_ok(const uint8_t *v, const uint8_t *key);

/**
 * DNA_SYSRULE_DELEGATE (O11) — bond someone else's stake to a validator.
 *
 * Source semantics preserved from apply_delegate (nodus_witness_bft.c:
 * 1336-1495): Rule S rejects self-delegation by comparing the two
 * pubkeys directly (:1356); the amount is EXPLICIT on the wire and must
 * be non-zero and within total supply (:1374-1383); the target must
 * exist and be BONDED — ACTIVE or ELIGIBLE, so a validator that merely
 * lost its seat stays delegatable while RETIRING / UNSTAKED /
 * AUTO_RETIRED do not (:1424-1434); an existing delegation is TOPPED UP
 * rather than replaced, with delegated_at_block REFRESHED to the
 * executing height (:1448-1470); and both validator totals rise by the
 * amount, external_delegated included, because Rule S makes every
 * delegation external (:1476-1486).
 *
 * HONEST LABEL (not a narrowing — a deliberate NON-adoption): the
 * client lane's 100-DNAC MIN_DELEGATION (dnac/src/transaction/verify.c)
 * is NOT enforced here. The witness minimum is 1 (:1374 rejects only
 * zero) and the shipped witness code is the authority for what the
 * chain accepts; importing a client-side floor would reject
 * transactions the live lane commits.
 *
 * @return 0 / -1 verdict / -2 node fault.
 */
static int rtn_delegate_exec(const dna_env_view_t *env, uint16_t leg_index,
                             const nodus_rt_exec_ctx_t *ctx,
                             const nodus_rt_read_res_t *reads,
                             uint16_t n_reads,
                             uint8_t *res_out, size_t res_cap,
                             size_t *res_len_out) {
    rtn_deleg_call_t c;
    uint8_t dfp[64];
    if (rtn_sys_stake_shape(env, leg_index) != 0) return -1;
    if (rtn_deleg_parse(env->buf + env->call_off[leg_index],
                        env->leg[leg_index].call_len, &c) != 0)
        return -1;
    {
        int rc = rtn_sys_stake_auth(env, leg_index, ctx, dfp);
        if (rc != 0) return rc;          /* identity = the delegator     */
    }

    /* ── scalar rules ───────────────────────────────────────────────── */
    if (memcmp(c.delegator_pubkey, c.validator_pubkey,
               DNAC_PUBKEY_SIZE) == 0)
        return -1;                       /* Rule S: no self-delegation   */
    if (c.amount < 1 || c.amount > DNAC_DEFAULT_TOTAL_SUPPLY)
        return -1;                       /* :1374-1383                   */

    /* ── mediated reads ─────────────────────────────────────────────── */
    if (n_reads != 2 || !reads) return -2;
    const nodus_rt_read_res_t *vr = &reads[0], *dr = &reads[1];
    if (!vr->present) return -1;         /* unknown validator            */
    if (vr->value_len != RTN_VAL_REC_LEN) return -2;
    if (memcmp(vr->value + RTN_VAL_PK_OFF, c.validator_pubkey,
               DNAC_PUBKEY_SIZE) != 0)
        return -2;                       /* the row this node served does
                                          * not match the key it was
                                          * fetched by: broken storage on
                                          * THIS node, never a verdict   */
    {
        uint8_t st = vr->value[RTN_VAL_STATUS_OFF];
        if (st != (uint8_t)DNAC_VALIDATOR_ACTIVE &&
            st != (uint8_t)DNAC_VALIDATOR_ELIGIBLE)
            return -1;                   /* not BONDED (:1429-1434)      */
    }
    {
        rtn_spend_call_t fc;
        if (rtn_sysfund_parse(env, 1, &fc) != 0) return -1;
    }

    uint8_t vkey[RTN_VAL_KEY_LEN], dkey[RTN_DEL_KEY_LEN];
    if (rtn_tag_key(NODUS_TREE_TAG_VALIDATOR, c.validator_pubkey,
                    vkey) != 0)
        return -2;
    if (rtn_deleg_key(c.delegator_pubkey, c.validator_pubkey, dkey) != 0)
        return -2;
    /* writable-shape VERDICT on every row this op rewrites (fault-class
     * block above): a legacy-malformed validator row is write-frozen */
    if (!rtn_val_rec_ok(vr->value, vkey)) return -1;
    if (dr->present) {
        if (dr->value_len != RTN_DEL_REC_LEN) return -2;
        if (!rtn_del_rec_ok(dr->value, dkey)) return -1;
    }

    /* ── validator totals: built FROM the observed record, so every
     *    other column is carried through byte-for-byte ──────────────── */
    uint8_t vnew[RTN_VAL_REC_LEN];
    memcpy(vnew, vr->value, RTN_VAL_REC_LEN);
    {
        uint64_t tot, ext;
        if (rtn_add_bounded(rtn_get64(vnew + RTN_VAL_TOTDEL_OFF),
                            c.amount, &tot) != 0)
            return -1;
        if (rtn_add_bounded(rtn_get64(vnew + RTN_VAL_EXTDEL_OFF),
                            c.amount, &ext) != 0)
            return -1;
        rtn_put64(vnew + RTN_VAL_TOTDEL_OFF, tot);
        rtn_put64(vnew + RTN_VAL_EXTDEL_OFF, ext);
    }

    /* ── the delegation row: top-up or create ───────────────────────── */
    uint8_t dnew[RTN_DEL_REC_LEN];
    int topup = dr->present ? 1 : 0;
    if (topup) {
        if (dr->value_len != RTN_DEL_REC_LEN) return -2;
        if (memcmp(dr->value + RTN_DEL_DPK_OFF, c.delegator_pubkey,
                   DNAC_PUBKEY_SIZE) != 0 ||
            memcmp(dr->value + RTN_DEL_VPK_OFF, c.validator_pubkey,
                   DNAC_PUBKEY_SIZE) != 0)
            return -2;                   /* key/row disagreement: fault  */
        memcpy(dnew, dr->value, RTN_DEL_REC_LEN);
        uint64_t amt;
        if (rtn_add_bounded(rtn_get64(dnew + RTN_DEL_AMT_OFF), c.amount,
                            &amt) != 0)
            return -1;
        rtn_put64(dnew + RTN_DEL_AMT_OFF, amt);
    } else {
        memset(dnew, 0, sizeof(dnew));
        memcpy(dnew + RTN_DEL_DPK_OFF, c.delegator_pubkey,
               DNAC_PUBKEY_SIZE);
        memcpy(dnew + RTN_DEL_VPK_OFF, c.validator_pubkey,
               DNAC_PUBKEY_SIZE);
        rtn_put64(dnew + RTN_DEL_AMT_OFF, c.amount);
    }
    /* delegated_at_block := the executing height on BOTH paths — the
     * top-up REFRESHES it (:1468), which is the legacy behavior and
     * imposes a fresh hold period on the whole position */
    rtn_put64(dnew + RTN_DEL_AT_OFF, ctx->global_height);

    /* ── effects (the codec's kind-major canonical order) ───────────── */
    dna_effect_in_t effs[2];
    memset(effs, 0, sizeof(effs));
    if (topup) {
        /* both SET (kind 2) ⇒ ordered by op id: validator, then row */
        if (rtn_row_set_eff(&effs[0], RTN_SYS_OP_VAL, vr,
                            RTN_VAL_REC_LEN, vkey,
                            (uint16_t)RTN_VAL_KEY_LEN, vnew) != 0)
            return -2;
        if (rtn_row_set_eff(&effs[1], RTN_SYS_OP_DELEG, dr,
                            RTN_DEL_REC_LEN, dkey,
                            (uint16_t)RTN_DEL_KEY_LEN, dnew) != 0)
            return -2;
    } else {
        /* CREATE (kind 1) sorts before SET (kind 2) regardless of op */
        effs[0].hdr.op_id = RTN_SYS_OP_DELEG;
        effs[0].hdr.effect_kind = DNA_EFFECT_CREATE;
        effs[0].hdr.precond_tag = DNA_EFFECT_PRE_ABSENT;
        effs[0].hdr.key_len = (uint16_t)RTN_DEL_KEY_LEN;
        effs[0].hdr.value_len = RTN_DEL_REC_LEN;
        effs[0].key = dkey;
        effs[0].value = dnew;
        if (rtn_row_set_eff(&effs[1], RTN_SYS_OP_VAL, vr,
                            RTN_VAL_REC_LEN, vkey,
                            (uint16_t)RTN_VAL_KEY_LEN, vnew) != 0)
            return -2;
    }
    if (dna_effect_result_encode(effs, 2, res_out, res_cap,
                                 res_len_out) != 0)
        return -2;
    return 0;
}

/**
 * DNA_SYSRULE_UNSTAKE (O11) — request retirement.
 *
 * Source semantics preserved from apply_unstake (nodus_witness_bft.c:
 * 1637-1694): the requester IS the validator; the row must exist and be
 * BONDED (ACTIVE or ELIGIBLE — a validator without a seat this epoch
 * must still be able to exit, :1661-1666); Rule A requires that NO
 * delegation still references it (:1670-1681); and exactly two columns
 * move — status := RETIRING and unstake_commit_block := the executing
 * height (:1683-1684).
 *
 * DEFERRED, and deliberately NOT reproduced here: the principal itself.
 * self_stake stays untouched and validator_stats.active_count is NOT
 * decremented — the legacy lane releases the bond and drops the counter
 * at the EPOCH BOUNDARY graduation (bft.c:2404-2560), which emits the
 * principal UTXO locked +17280 blocks to unstake_destination_fp. That
 * transition belongs to the epoch-transition season; inventing it here
 * would release value the chain has not yet agreed to release.
 *
 * @return 0 / -1 verdict / -2 node fault.
 */
static int rtn_unstake_exec(const dna_env_view_t *env, uint16_t leg_index,
                            const nodus_rt_exec_ctx_t *ctx,
                            const nodus_rt_read_res_t *reads,
                            uint16_t n_reads,
                            uint8_t *res_out, size_t res_cap,
                            size_t *res_len_out) {
    const uint8_t *vpk = NULL;
    uint8_t vfp[64];
    if (rtn_sys_stake_shape(env, leg_index) != 0) return -1;
    if (rtn_sys_call_identity(DNA_SYSRULE_UNSTAKE,
                              env->buf + env->call_off[leg_index],
                              env->leg[leg_index].call_len, &vpk) != 0)
        return -1;
    {
        int rc = rtn_sys_stake_auth(env, leg_index, ctx, vfp);
        if (rc != 0) return rc;          /* identity = the validator     */
    }

    if (n_reads != 2 || !reads) return -2;
    const nodus_rt_read_res_t *vr = &reads[0], *cr = &reads[1];
    if (!vr->present) return -1;         /* unknown validator            */
    if (vr->value_len != RTN_VAL_REC_LEN) return -2;
    if (memcmp(vr->value + RTN_VAL_PK_OFF, vpk, DNAC_PUBKEY_SIZE) != 0)
        return -2;
    {
        uint8_t st = vr->value[RTN_VAL_STATUS_OFF];
        if (st != (uint8_t)DNAC_VALIDATOR_ACTIVE &&
            st != (uint8_t)DNAC_VALIDATOR_ELIGIBLE)
            return -1;                   /* not BONDED — this also makes
                                          * a repeated UNSTAKE reject    */
    }
    /* the delegation COUNT always answers (0 is a VALUE, not absence),
     * so an absent result means the adapter broke its own contract */
    if (!cr->present || cr->value_len != 8) return -2;
    if (rtn_get64(cr->value) != 0) return -1;      /* Rule A            */
    {
        rtn_spend_call_t fc;
        if (rtn_sysfund_parse(env, 1, &fc) != 0) return -1;
    }

    uint8_t vkey[RTN_VAL_KEY_LEN], vnew[RTN_VAL_REC_LEN];
    if (rtn_tag_key(NODUS_TREE_TAG_VALIDATOR, vpk, vkey) != 0) return -2;
    /* writable-shape VERDICT (fault-class block above) */
    if (!rtn_val_rec_ok(vr->value, vkey)) return -1;
    memcpy(vnew, vr->value, RTN_VAL_REC_LEN);
    vnew[RTN_VAL_STATUS_OFF] = (uint8_t)DNAC_VALIDATOR_RETIRING;
    rtn_put64(vnew + RTN_VAL_UCOMMIT_OFF, ctx->global_height);

    dna_effect_in_t eff;
    memset(&eff, 0, sizeof(eff));
    if (rtn_row_set_eff(&eff, RTN_SYS_OP_VAL, vr, RTN_VAL_REC_LEN, vkey,
                        (uint16_t)RTN_VAL_KEY_LEN, vnew) != 0)
        return -2;
    if (dna_effect_result_encode(&eff, 1, res_out, res_cap,
                                 res_len_out) != 0)
        return -2;
    return 0;
}

/**
 * DNA_SYSRULE_UNDELEGATE (O11) — withdraw delegated principal.
 *
 * Source semantics preserved from apply_undelegate (nodus_witness_bft.c:
 * 1820-1908): the delegation must exist and 0 < amount <= its amount
 * (:1851-1858); the validator row must exist but its STATUS IS NOT
 * GATED — the legacy comment (:1818-1821) states the rule outright, so
 * delegators of a RETIRING / UNSTAKED / AUTO_RETIRED validator can
 * always pull their principal; a fully drained row is DELETED, a partial
 * one keeps everything except the reduced amount — delegated_at_block is
 * NOT refreshed on this path (:1883-1884 mutates only `d.amount` and
 * writes the record back); and both validator totals fall by the amount
 * with an explicit underflow reject (:1893-1897).
 *
 * The RELEASE is not built here: the CORE DNA_CORERULE_SYSFUND leg
 * creates the principal UTXO from the SAME call bytes
 * (rtn_sys_call_flow), and the value it creates is exactly the amount
 * this leg removes from the delegated bucket — which is why the funding
 * equation does not net a release against its inputs.
 *
 * STALE-COMMENT NOTE: apply_undelegate's own doc comment describes a
 * reward accumulator and TWO synthetic UTXOs. The CODE emits only the
 * principal (v0.16 push-settlement removed the accumulator); the code is
 * authoritative and the comment is stale.
 *
 * @return 0 / -1 verdict / -2 node fault.
 */
static int rtn_undelegate_exec(const dna_env_view_t *env,
                               uint16_t leg_index,
                               const nodus_rt_exec_ctx_t *ctx,
                               const nodus_rt_read_res_t *reads,
                               uint16_t n_reads,
                               uint8_t *res_out, size_t res_cap,
                               size_t *res_len_out) {
    rtn_deleg_call_t c;
    uint8_t dfp[64];
    if (rtn_sys_stake_shape(env, leg_index) != 0) return -1;
    if (rtn_deleg_parse(env->buf + env->call_off[leg_index],
                        env->leg[leg_index].call_len, &c) != 0)
        return -1;
    {
        int rc = rtn_sys_stake_auth(env, leg_index, ctx, dfp);
        if (rc != 0) return rc;          /* identity = the delegator     */
    }

    if (n_reads != 2 || !reads) return -2;
    const nodus_rt_read_res_t *vr = &reads[0], *dr = &reads[1];
    if (!dr->present) return -1;         /* unknown delegation           */
    if (dr->value_len != RTN_DEL_REC_LEN) return -2;
    if (memcmp(dr->value + RTN_DEL_DPK_OFF, c.delegator_pubkey,
               DNAC_PUBKEY_SIZE) != 0 ||
        memcmp(dr->value + RTN_DEL_VPK_OFF, c.validator_pubkey,
               DNAC_PUBKEY_SIZE) != 0)
        return -2;                       /* key/row disagreement: fault  */
    uint64_t have = rtn_get64(dr->value + RTN_DEL_AMT_OFF);
    if (c.amount < 1 || c.amount > have) return -1;   /* :1851-1858     */
    if (!vr->present) return -1;         /* the totals have no owner     */
    if (vr->value_len != RTN_VAL_REC_LEN) return -2;
    if (memcmp(vr->value + RTN_VAL_PK_OFF, c.validator_pubkey,
               DNAC_PUBKEY_SIZE) != 0)
        return -2;
    /* NO status gate here — see the header block (:1818-1821). */
    {
        rtn_spend_call_t fc;
        if (rtn_sysfund_parse(env, 1, &fc) != 0) return -1;
    }

    uint64_t tot = rtn_get64(vr->value + RTN_VAL_TOTDEL_OFF);
    uint64_t ext = rtn_get64(vr->value + RTN_VAL_EXTDEL_OFF);
    if (tot < c.amount || ext < c.amount)
        return -1;                       /* underflow (:1893-1897): the
                                          * totals and the row disagree —
                                          * malformed legacy state fails
                                          * closed, it is never repaired */

    uint8_t vkey[RTN_VAL_KEY_LEN], dkey[RTN_DEL_KEY_LEN];
    if (rtn_tag_key(NODUS_TREE_TAG_VALIDATOR, c.validator_pubkey,
                    vkey) != 0)
        return -2;
    if (rtn_deleg_key(c.delegator_pubkey, c.validator_pubkey, dkey) != 0)
        return -2;
    /* writable-shape VERDICT on both rewritten rows (fault-class block
     * above) — the delegation row is rewritten on the partial path and
     * deleted on the drain path; the gate applies to both (a DELETE of
     * a malformed row would still leave a rewritten validator row) */
    if (!rtn_val_rec_ok(vr->value, vkey)) return -1;
    if (!rtn_del_rec_ok(dr->value, dkey)) return -1;

    uint8_t vnew[RTN_VAL_REC_LEN];
    memcpy(vnew, vr->value, RTN_VAL_REC_LEN);
    rtn_put64(vnew + RTN_VAL_TOTDEL_OFF, tot - c.amount);
    rtn_put64(vnew + RTN_VAL_EXTDEL_OFF, ext - c.amount);

    dna_effect_in_t effs[2];
    uint8_t dnew[RTN_DEL_REC_LEN];
    memset(effs, 0, sizeof(effs));
    /* SET (kind 2) always precedes DELETE (kind 3); the partial path's
     * two SETs order by op id (4 before 5) */
    if (rtn_row_set_eff(&effs[0], RTN_SYS_OP_VAL, vr, RTN_VAL_REC_LEN,
                        vkey, (uint16_t)RTN_VAL_KEY_LEN, vnew) != 0)
        return -2;
    if (c.amount == have) {
        if (rtn_deleg_del_eff(&effs[1], dr, dkey) != 0) return -2;
    } else {
        memcpy(dnew, dr->value, RTN_DEL_REC_LEN);
        rtn_put64(dnew + RTN_DEL_AMT_OFF, have - c.amount);
        /* delegated_at_block is NOT touched — a partial withdrawal does
         * not restart the position's clock (:1883-1884) */
        if (rtn_row_set_eff(&effs[1], RTN_SYS_OP_DELEG, dr,
                            RTN_DEL_REC_LEN, dkey,
                            (uint16_t)RTN_DEL_KEY_LEN, dnew) != 0)
            return -2;
    }
    if (dna_effect_result_encode(effs, 2, res_out, res_cap,
                                 res_len_out) != 0)
        return -2;
    return 0;
}

/* The epoch length is a DIVISOR below and a summand above; a zero or
 * negative value would be a division fault, not a verdict. */
_Static_assert((uint64_t)DNAC_EPOCH_LENGTH > 0,
               "DNAC_EPOCH_LENGTH must be positive — the deferral "
               "boundary divides by it");

/**
 * DNA_SYSRULE_VALIDATOR_UPDATE (O12 S1) — a validator changes its own
 * commission.
 *
 * Source semantics preserved from apply_validator_update
 * (nodus_witness_bft.c:1934-2003):
 *   - the row must EXIST (:1959-1965 — a missing validator is a
 *     deterministic reject, never a create);
 *   - and be UPDATABLE: ACTIVE / ELIGIBLE / RETIRING (:1966-1976).
 *     ELIGIBLE is exactly what a seat-less validator tunes while trying
 *     to win a seat back and RETIRING keeps paying delegators through
 *     its cooldown; UNSTAKED / AUTO_RETIRED have frozen stake;
 *   - new > current is an INCREASE and is DEFERRED a full epoch of
 *     delegator notice: pending_commission_bps := new and
 *     pending_effective_block := max(next_epoch_boundary, H + epoch)
 *     (:1978-1987). The CURRENT rate does not move;
 *   - new <= current (a decrease, or an equal value) takes effect
 *     IMMEDIATELY and CLEARS any stale pending entry (:1987-1992). Equal
 *     deliberately falls through the decrease branch — that is the legacy
 *     behaviour and its only net effect is dropping a pending change
 *     (:1922-1924);
 *   - last_validator_update_block := H on BOTH paths (Rule K cooldown,
 *     :1993).
 *
 * NOTHING ELSE MOVES. status, self_stake, both delegation totals,
 * active_since / unstake_commit, the unstake destination pair and the
 * Rule N counters are all carried through from the record the mediated
 * read observed, and the SET is bound to that record by EXISTS_VHASH, so
 * the transition CANNOT change a column it does not name. There is no
 * supply movement, no validator_stats.active_count movement and no
 * snapshot / epoch interaction — a commission change is not a set change
 * (nodus_witness_vset.c owns membership, and it reads none of these
 * columns).
 *
 * The bps bound (:1953-1957) lives in rtn_vupd_parse, so the sibling
 * funding leg rejects a malformed record call through the same decoder.
 *
 * @return 0 / -1 verdict / -2 node fault.
 */
static int rtn_vupd_exec(const dna_env_view_t *env, uint16_t leg_index,
                         const nodus_rt_exec_ctx_t *ctx,
                         const nodus_rt_read_res_t *reads,
                         uint16_t n_reads,
                         uint8_t *res_out, size_t res_cap,
                         size_t *res_len_out) {
    rtn_vupd_call_t c;
    uint8_t vfp[64];
    if (rtn_sys_stake_shape(env, leg_index) != 0) return -1;
    if (rtn_vupd_parse(env->buf + env->call_off[leg_index],
                       env->leg[leg_index].call_len, &c) != 0)
        return -1;
    {
        int rc = rtn_sys_stake_auth(env, leg_index, ctx, vfp);
        if (rc != 0) return rc;          /* identity = the validator     */
    }

    uint64_t H = ctx->global_height;
    if (H > (uint64_t)INT64_MAX)
        return -1;                       /* last_validator_update_block is
                                          * an SQLite INTEGER column;
                                          * bounded at the SOURCE so the
                                          * rejection is a VERDICT, not
                                          * the mutate side's node-fault
                                          * class (rtn_stake_exec
                                          * precedent)                   */

    /* ── the one mediated read ──────────────────────────────────────── */
    if (n_reads != 1 || !reads) return -2;
    const nodus_rt_read_res_t *vr = &reads[0];
    if (!vr->present) return -1;         /* unknown validator (:1961-65) */
    if (vr->value_len != RTN_VAL_REC_LEN) return -2;
    if (memcmp(vr->value + RTN_VAL_PK_OFF, c.validator_pubkey,
               DNAC_PUBKEY_SIZE) != 0)
        return -2;                       /* the row this node served does
                                          * not match the key it was
                                          * fetched by: broken storage on
                                          * THIS node, never a verdict   */
    {
        uint8_t st = vr->value[RTN_VAL_STATUS_OFF];
        if (st != (uint8_t)DNAC_VALIDATOR_ACTIVE &&
            st != (uint8_t)DNAC_VALIDATOR_ELIGIBLE &&
            st != (uint8_t)DNAC_VALIDATOR_RETIRING)
            return -1;                   /* :1970-1976                   */
    }
    {
        rtn_spend_call_t fc;
        if (rtn_sysfund_parse(env, 1, &fc) != 0) return -1;
    }

    uint8_t vkey[RTN_VAL_KEY_LEN];
    if (rtn_tag_key(NODUS_TREE_TAG_VALIDATOR, c.validator_pubkey,
                    vkey) != 0)
        return -2;
    /* writable-shape VERDICT (the fault-class block above
     * rtn_delegate_exec): a legacy-malformed row is write-frozen */
    if (!rtn_val_rec_ok(vr->value, vkey)) return -1;

    /* ── the transition, built FROM the observed record ─────────────── */
    uint8_t vnew[RTN_VAL_REC_LEN];
    memcpy(vnew, vr->value, RTN_VAL_REC_LEN);
    uint32_t cur = ((uint32_t)vnew[RTN_VAL_COMM_OFF] << 8) |
                   vnew[RTN_VAL_COMM_OFF + 1];
    if ((uint32_t)c.new_commission_bps > cur) {
        uint64_t plus_epoch = 0, boundary = 0;
        if (rtn_add_bounded(H, (uint64_t)DNAC_EPOCH_LENGTH,
                            &plus_epoch) != 0)
            return -1;                   /* the storage bound again, as a
                                          * VERDICT                      */
        boundary = (H / (uint64_t)DNAC_EPOCH_LENGTH) *
                   (uint64_t)DNAC_EPOCH_LENGTH;   /* <= H: no overflow   */
        if (rtn_add_bounded(boundary, (uint64_t)DNAC_EPOCH_LENGTH,
                            &boundary) != 0)
            return -1;
        /* max(next_epoch_boundary, H + epoch), reproduced EXACTLY as
         * bft.c:1984-1986 writes it.
         * ⚠ ARITHMETIC NOTE (O12 S1, honest label): the boundary arm is
         * UNREACHABLE. boundary = floor(H/E)*E + E and floor(H/E)*E <= H,
         * so boundary <= H + E always, with equality exactly when H is a
         * multiple of E. The ternary therefore always selects H + E and
         * the two agree on an epoch boundary. It is preserved verbatim
         * anyway — the source is the authority, an "equivalent"
         * simplification here would be a semantic claim this slice has no
         * mandate to make, and if E ever becomes per-epoch state the two
         * expressions stop coinciding. */
        uint64_t peff = boundary > plus_epoch ? boundary : plus_epoch;
        vnew[RTN_VAL_PCOMM_OFF]     = (uint8_t)(c.new_commission_bps >> 8);
        vnew[RTN_VAL_PCOMM_OFF + 1] = (uint8_t)c.new_commission_bps;
        rtn_put64(vnew + RTN_VAL_PEFF_OFF, peff);
        /* commission_bps is deliberately NOT touched on this path */
    } else {
        vnew[RTN_VAL_COMM_OFF]      = (uint8_t)(c.new_commission_bps >> 8);
        vnew[RTN_VAL_COMM_OFF + 1]  = (uint8_t)c.new_commission_bps;
        vnew[RTN_VAL_PCOMM_OFF]     = 0;
        vnew[RTN_VAL_PCOMM_OFF + 1] = 0;
        rtn_put64(vnew + RTN_VAL_PEFF_OFF, 0);
    }
    rtn_put64(vnew + RTN_VAL_LASTUPD_OFF, H);      /* Rule K (:1993)     */

    dna_effect_in_t eff;
    memset(&eff, 0, sizeof(eff));
    if (rtn_row_set_eff(&eff, RTN_SYS_OP_VAL, vr, RTN_VAL_REC_LEN, vkey,
                        (uint16_t)RTN_VAL_KEY_LEN, vnew) != 0)
        return -2;
    if (dna_effect_result_encode(&eff, 1, res_out, res_cap,
                                 res_len_out) != 0)
        return -2;
    return 0;
}

int nodus_rt_system_exec(const nodus_domain_runtime_t *rt,
                         const dna_env_view_t *env, uint16_t leg_index,
                         const nodus_rt_exec_ctx_t *ctx,
                         const nodus_rt_read_res_t *reads, uint16_t n_reads,
                         uint8_t *res_out, size_t res_cap,
                         size_t *res_len_out) {
    (void)rt;
    if (!env || !ctx || !ctx->intent_id || !ctx->chain_id || !res_out ||
        !res_len_out)
        return -2;
    if (leg_index >= env->leg_count) return -2;
    switch (env->leg[leg_index].runtime_op) {
    case DNA_SYSRULE_STAKE:
        return rtn_stake_exec(env, leg_index, ctx, reads, n_reads,
                              res_out, res_cap, res_len_out);
    case DNA_SYSRULE_DELEGATE:
        return rtn_delegate_exec(env, leg_index, ctx, reads, n_reads,
                                 res_out, res_cap, res_len_out);
    case DNA_SYSRULE_UNSTAKE:
        return rtn_unstake_exec(env, leg_index, ctx, reads, n_reads,
                                res_out, res_cap, res_len_out);
    case DNA_SYSRULE_UNDELEGATE:
        return rtn_undelegate_exec(env, leg_index, ctx, reads, n_reads,
                                   res_out, res_cap, res_len_out);
    case DNA_SYSRULE_VALIDATOR_UPDATE:
        return rtn_vupd_exec(env, leg_index, ctx, reads, n_reads,
                             res_out, res_cap, res_len_out);
    case DNA_SYSRULE_CHAIN_CONFIG:
        break;                           /* falls through to CC exec     */
    default:
        return -1;                       /* un-migrated op: fail closed  */
    }

    rtn_cc_call_t c;
    if (rtn_cc_parse(env, leg_index, &c) != 0) return -1;
    if (!ctx->auth || ctx->auth->n_signers < 1) return -1;   /* verified
                                          * submitter authorization      */
    /* ── committee quorum — the SOURCE authority, from the ENGINE
     * verdict (capacity season): the auth boundary verified every
     * approval signature against the engine-resolved governing snapshot
     * (kind 2), counted the DISTINCT seats into n_approvals and
     * recorded the resolved committee size. No envelope byte, no
     * runtime and no caller supplies either number. A kind-1 leg
     * arrives here with n_approvals == 0 and fails exactly like an
     * under-quorum vote set. Exact quorum passes; quorum-1 fails. */
    if (ctx->auth->committee_n < 1) return -1;
    if ((uint32_t)ctx->auth->n_approvals <
        dna_bft_quorum((uint32_t)ctx->auth->committee_n))
        return -1;                       /* Rule CC-F quorum             */
    if (env->fee_amount != 0) return -1;      /* header block: no SYSTEM
                                          * fee sink exists this season  */

    uint64_t H = ctx->global_height;
    if (H == 0) return -1;

    /* the SAME scalar authority the legacy apply consumes */
    if (nodus_chain_config_scalar_rules(c.param_id, c.new_value,
                                        c.signed_at, c.valid_before,
                                        c.effective) != 0)
        return -1;
    /* O15F D2 — V2-lane TARGET_ACTIVE_COUNT range narrowing [7..30].
     * The shared scalar rule above admits [7..128]; a successor's active
     * set can never exceed NODUS_V2_ACTIVE_SET_MAX (30, the set-layer
     * invariant, nodus_witness.h), so a runtime-op-6 CC envelope raising
     * the target above 30 is a deterministic VERDICT reject. This exec
     * hook is PURE (no witness handle), so the bound is V2-lane-GLOBAL —
     * every production V2 chain is a successor, and a 30-bounded fixture
     * chain is strictly safer; the legacy CC apply path never enters this
     * hook and keeps [7..128]. The set-layer guards (D1: target clamp /
     * insert / resolve / seam) are the defense-in-depth backstop. */
    if (c.param_id == DNAC_CFG_TARGET_ACTIVE_COUNT &&
        c.new_value > NODUS_V2_ACTIVE_SET_MAX)
        return -1;
    /* freshness (CC-G) + per-param grace (CC-C), 1:1 from
     * nodus_chain_config_apply */
    if (H > c.valid_before) return -1;
    {
        uint64_t floor_h;
        if (dna_ck_add_u64(H, nodus_chain_config_grace_for_param(
                                  c.param_id), &floor_h) != 0)
            return -1;
        if (c.effective < floor_h) return -1;
    }

    uint16_t expect_reads =
        (uint16_t)(c.param_id == DNAC_CFG_INFLATION_START_BLOCK ? 1 : 0);
    if (n_reads != expect_reads) return -2;
    if (expect_reads > 0 && !reads) return -2;

    /* ── INFLATION_START monotonicity (Q5 / CC-GOV-001, 1:1) ────────── */
    if (c.param_id == DNAC_CFG_INFLATION_START_BLOCK) {
        const nodus_rt_read_res_t *mono = &reads[0];
        if (mono->present) {
            if (mono->value_len != 8) return -2;
            if (c.new_value == 0) return -1;   /* cannot disable         */
            if (c.new_value > H) return -1;    /* cannot move past now   */
        }
    }

    /* ── the ONE effect: CREATE the committed history row ───────────── */
    uint8_t key[RTN_CC_KEY_LEN], val[RTN_CC_VAL_LEN];
    rtn_put32(key, (uint32_t)c.param_id);
    rtn_put64(key + 4, c.effective);
    rtn_put64(val, c.new_value);
    rtn_put64(val + 8, H);
    rtn_put64(val + 16, c.nonce);
    /* PROVENANCE = the canonical INTENT identity (intent season): the
     * cc merkle leaf excludes tx_hash (audit column), but the row is a
     * consensus-owned record — two valid committee subsets approving the
     * same proposal must commit byte-identical rows. */
    memcpy(val + 24, ctx->intent_id, 64);

    dna_effect_in_t eff;
    memset(&eff, 0, sizeof(eff));
    eff.hdr.op_id = RTN_SYS_OP_CC;
    eff.hdr.effect_kind = DNA_EFFECT_CREATE;
    eff.hdr.precond_tag = DNA_EFFECT_PRE_ABSENT;   /* PK replay reject   */
    eff.hdr.key_len = RTN_CC_KEY_LEN;
    eff.hdr.value_len = RTN_CC_VAL_LEN;
    eff.key = key;
    eff.value = val;
    if (dna_effect_result_encode(&eff, 1, res_out, res_cap,
                                 res_len_out) != 0)
        return -2;
    return 0;
}

/* ── The compiled SYSTEM storage adapter ────────────────────────────── */

/* 0 = row found (val filled), 1 = absent, -1 = fault. */
static int rtn_sys_cc_fetch(nodus_witness_t *w, const uint8_t *key,
                            uint8_t val[RTN_CC_VAL_LEN]) {
    uint32_t param = ((uint32_t)key[0] << 24) | ((uint32_t)key[1] << 16) |
                     ((uint32_t)key[2] << 8) | key[3];
    uint64_t eff = rtn_get64(key + 4);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT new_value, commit_block, proposal_nonce, tx_hash "
            "FROM chain_config_history "
            "WHERE param_id = ?1 AND effective_block = ?2",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)param);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)eff);
    int rc = sqlite3_step(st);
    int out = -1;
    if (rc == SQLITE_ROW) {
        const uint8_t *txh = sqlite3_column_blob(st, 3);
        sqlite3_int64 nv = sqlite3_column_int64(st, 0);
        sqlite3_int64 cb = sqlite3_column_int64(st, 1);
        sqlite3_int64 pn = sqlite3_column_int64(st, 2);
        /* negative stored integers = malformed row, fail closed (the
         * rtn_core_row_record rule) */
        if (txh && sqlite3_column_bytes(st, 3) == 64 &&
            nv >= 0 && cb >= 0 && pn >= 0) {
            rtn_put64(val, (uint64_t)nv);
            rtn_put64(val + 8, (uint64_t)cb);
            rtn_put64(val + 16, (uint64_t)pn);
            memcpy(val + 24, txh, 64);
            out = 0;
        }
    } else if (rc == SQLITE_DONE) {
        out = 1;
    }
    sqlite3_finalize(st);
    return out;
}

/* ── O11 stake-lifecycle row access ──────────────────────────────────
 *
 * The validators / delegations / validator_stats tables are SYSTEM-LOCAL
 * LEGACY STATE with no domain_id column — they are reachable only
 * through THIS adapter, which only the compiled SYSTEM runtime entry
 * binds, so the domain scope IS the binding (the `tokens` precedent).
 *
 * ⚠ MIGRATION OBLIGATION (owned by the V2 ACTIVATION season, not this
 * slice — the tokens-table precedent): these three tables are shared
 * with the LIVE legacy lane, whose writers never faced this slice's
 * write rules. A legacy chain can hold rows the V2 mutate side would
 * refuse (a commission_bps above 10000 — apply_stake never bounded it;
 * an unstake_destination_fp that is not 128 lowercase hex — the genesis
 * seeder copies a chain_def iv_fp verbatim, genesis_seed.c:117). Such
 * rows still READ (the fetch side deliberately enforces only the SHAPE
 * bounds the merkle leaf loader enforces, so the mediated read can serve
 * exactly what the state root already commits) but cannot be rewritten
 * by a V2 effect. Single-lane cutover must reconcile them before
 * activation.
 * ⚠ (O11 R2 finding) The freeze notably reaches UNDELEGATE: a
 * delegator to a malformed-row validator cannot exit through V2 until
 * reconciliation, whereas the legacy lane guarantees the exit is never
 * blocked (bft.c:1816-1818). The reconciliation owner must repair such
 * rows BEFORE cutover precisely so that guarantee survives. */

/* Build the canonical 5397-byte validator record from one row statement.
 * Column order = the SELECT below = the merkle leaf order. Fail-closed
 * on every malformed shape, exactly the checks load_validator_leaves
 * makes before hashing (merkle.c:941-1056) — a corrupt row is never
 * surfaced as a value. @return 0 / -1 malformed. */
static int rtn_sys_val_row(sqlite3_stmt *st, uint8_t rec[RTN_VAL_REC_LEN]) {
    const uint8_t *pk  = sqlite3_column_blob(st, 0);
    const uint8_t *dpk = sqlite3_column_blob(st, 11);
    if (!pk || sqlite3_column_bytes(st, 0) != DNAC_PUBKEY_SIZE) return -1;
    if (!dpk || sqlite3_column_bytes(st, 11) != DNAC_PUBKEY_SIZE) return -1;
    /* the fingerprint window: a SQL NULL is refused (never a substituted
     * 128 zeros) and an over-long value is refused (never truncated
     * inside a hashed value) — merkle.c:1017-1034. An EMPTY or short
     * value is legal and zero-pads, exactly as the leaf loader does. */
    if (sqlite3_column_type(st, 10) == SQLITE_NULL) return -1;
    const char *fp = (const char *)sqlite3_column_text(st, 10);
    size_t fp_len = fp ? strlen(fp) : 0;
    if (fp_len > RTN_VAL_DFP_LEN) return -1;
    /* a NEGATIVE stored integer is a malformed row (the
     * rtn_core_row_record rule); the two bps columns and the status byte
     * additionally have to fit their wire widths */
    sqlite3_int64 self = sqlite3_column_int64(st, 1);
    sqlite3_int64 totd = sqlite3_column_int64(st, 2);
    sqlite3_int64 extd = sqlite3_column_int64(st, 3);
    sqlite3_int64 comm = sqlite3_column_int64(st, 4);
    sqlite3_int64 pcom = sqlite3_column_int64(st, 5);
    sqlite3_int64 peff = sqlite3_column_int64(st, 6);
    sqlite3_int64 stat = sqlite3_column_int64(st, 7);
    sqlite3_int64 sinc = sqlite3_column_int64(st, 8);
    sqlite3_int64 ucom = sqlite3_column_int64(st, 9);
    sqlite3_int64 lupd = sqlite3_column_int64(st, 12);
    sqlite3_int64 miss = sqlite3_column_int64(st, 13);
    sqlite3_int64 lsig = sqlite3_column_int64(st, 14);
    sqlite3_int64 sepo = sqlite3_column_int64(st, 15);
    if (self < 0 || totd < 0 || extd < 0 || peff < 0 || sinc < 0 ||
        ucom < 0 || lupd < 0 || miss < 0 || lsig < 0 || sepo < 0)
        return -1;
    if (comm < 0 || comm > UINT16_MAX || pcom < 0 || pcom > UINT16_MAX)
        return -1;
    if (stat < 0 || stat > UINT8_MAX) return -1;
    memset(rec, 0, RTN_VAL_REC_LEN);
    memcpy(rec + RTN_VAL_PK_OFF, pk, DNAC_PUBKEY_SIZE);
    rtn_put64(rec + RTN_VAL_SELF_OFF, (uint64_t)self);
    rtn_put64(rec + RTN_VAL_TOTDEL_OFF, (uint64_t)totd);
    rtn_put64(rec + RTN_VAL_EXTDEL_OFF, (uint64_t)extd);
    rec[RTN_VAL_COMM_OFF]      = (uint8_t)((uint64_t)comm >> 8);
    rec[RTN_VAL_COMM_OFF + 1]  = (uint8_t)comm;
    rec[RTN_VAL_PCOMM_OFF]     = (uint8_t)((uint64_t)pcom >> 8);
    rec[RTN_VAL_PCOMM_OFF + 1] = (uint8_t)pcom;
    rtn_put64(rec + RTN_VAL_PEFF_OFF, (uint64_t)peff);
    rec[RTN_VAL_STATUS_OFF] = (uint8_t)stat;
    rtn_put64(rec + RTN_VAL_SINCE_OFF, (uint64_t)sinc);
    rtn_put64(rec + RTN_VAL_UCOMMIT_OFF, (uint64_t)ucom);
    if (fp_len > 0) memcpy(rec + RTN_VAL_DFP_OFF, fp, fp_len);
    memcpy(rec + RTN_VAL_DPK_OFF, dpk, DNAC_PUBKEY_SIZE);
    rtn_put64(rec + RTN_VAL_LASTUPD_OFF, (uint64_t)lupd);
    rtn_put64(rec + RTN_VAL_MISSED_OFF, (uint64_t)miss);
    rtn_put64(rec + RTN_VAL_LSIGNED_OFF, (uint64_t)lsig);
    rtn_put64(rec + RTN_VAL_SIGNEP_OFF, (uint64_t)sepo);
    return 0;
}

/* 0 = record built, 1 = absent, -1 = fault. */
static int rtn_sys_val_fetch(nodus_witness_t *w, const uint8_t *key,
                             uint16_t key_len,
                             uint8_t rec[RTN_VAL_REC_LEN]) {
    if (key_len != RTN_VAL_KEY_LEN) return -1;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT pubkey, self_stake, total_delegated, "
            "external_delegated, commission_bps, pending_commission_bps, "
            "pending_effective_block, status, active_since_block, "
            "unstake_commit_block, unstake_destination_fp, "
            "unstake_destination_pubkey, last_validator_update_block, "
            "consecutive_missed_epochs, last_signed_block, "
            "signed_blocks_this_epoch FROM validators "
            "WHERE pubkey_hash = ?1", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_blob(st, 1, key, RTN_VAL_KEY_LEN, SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);
    int out;
    if (rc == SQLITE_ROW)
        out = rtn_sys_val_row(st, rec) == 0 ? 0 : -1;
    else
        out = rc == SQLITE_DONE ? 1 : -1;
    sqlite3_finalize(st);
    return out;
}

/* 0 = record built, 1 = absent, -1 = fault. */
static int rtn_sys_del_fetch(nodus_witness_t *w, const uint8_t *key,
                             uint16_t key_len,
                             uint8_t rec[RTN_DEL_REC_LEN]) {
    if (key_len != RTN_DEL_KEY_LEN) return -1;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT delegator_pubkey, validator_pubkey, amount, "
            "delegated_at_block FROM delegations "
            "WHERE delegator_hash = ?1 AND validator_hash = ?2",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_blob(st, 1, key, 64, SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 2, key + 64, 64, SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);
    int out = -1;
    if (rc == SQLITE_ROW) {
        const uint8_t *dpk = sqlite3_column_blob(st, 0);
        const uint8_t *vpk = sqlite3_column_blob(st, 1);
        sqlite3_int64 amt = sqlite3_column_int64(st, 2);
        sqlite3_int64 at  = sqlite3_column_int64(st, 3);
        if (dpk && sqlite3_column_bytes(st, 0) == DNAC_PUBKEY_SIZE &&
            vpk && sqlite3_column_bytes(st, 1) == DNAC_PUBKEY_SIZE &&
            amt >= 0 && at >= 0) {
            memset(rec, 0, RTN_DEL_REC_LEN);
            memcpy(rec + RTN_DEL_DPK_OFF, dpk, DNAC_PUBKEY_SIZE);
            memcpy(rec + RTN_DEL_VPK_OFF, vpk, DNAC_PUBKEY_SIZE);
            rtn_put64(rec + RTN_DEL_AMT_OFF, (uint64_t)amt);
            rtn_put64(rec + RTN_DEL_AT_OFF, (uint64_t)at);
            out = 0;
        }
    } else if (rc == SQLITE_DONE) {
        out = 1;
    }
    sqlite3_finalize(st);
    return out;
}

/* Rule-A input: how many delegations reference one validator. Mirrors
 * nodus_delegation_count_by_validator (delegation.c:297-330) but keyed
 * by the row hash directly — the hook has the hash, never the pubkey's
 * table row. A COUNT always yields exactly one row.
 * @return 0 with *out set / -1 fault. */
static int rtn_sys_delegcnt_fetch(nodus_witness_t *w, const uint8_t *key,
                                  uint16_t key_len, uint64_t *out) {
    if (key_len != 64) return -1;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT COUNT(*) FROM delegations WHERE validator_hash = ?1",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_blob(st, 1, key, 64, SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);
    int ret = -1;
    if (rc == SQLITE_ROW) {
        sqlite3_int64 n = sqlite3_column_int64(st, 0);
        if (n >= 0) { *out = (uint64_t)n; ret = 0; }
    }
    sqlite3_finalize(st);
    return ret;
}

/* 0 = value fetched, 1 = absent, -1 = fault. */
static int rtn_sys_stats_fetch(nodus_witness_t *w, const uint8_t *key,
                               uint16_t key_len, uint64_t *out) {
    if (key_len != 1 || key[0] != RTN_STATS_SEL_ACTIVE) return -1;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT value FROM validator_stats WHERE key = 'active_count'",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    int rc = sqlite3_step(st);
    int ret;
    if (rc == SQLITE_ROW) {
        sqlite3_int64 v = sqlite3_column_int64(st, 0);
        ret = v < 0 ? -1 : 0;            /* negative counter = malformed */
        if (ret == 0) *out = (uint64_t)v;
    } else {
        ret = rc == SQLITE_DONE ? 1 : -1;
    }
    sqlite3_finalize(st);
    return ret;
}

/* Validate one canonical validator record on the MUTATE side: exactly
 * ONE encoding per row, and the KEY and the VALUE cannot disagree (the
 * key is SHA3-512(tag ‖ pubkey) of the pubkey the record carries — so a
 * caller cannot file a validator's record under another's identity).
 * Numeric columns must fit the SQLite INTEGER storage bound, or they
 * would round-trip negative and poison every later fetch (the
 * rtn_token_rec_ok discipline). @return 1 ok / 0 reject. */
static int rtn_val_rec_ok(const uint8_t *v, const uint8_t *key) {
    static const uint32_t u64_offs[] = {
        RTN_VAL_SELF_OFF, RTN_VAL_TOTDEL_OFF, RTN_VAL_EXTDEL_OFF,
        RTN_VAL_PEFF_OFF, RTN_VAL_SINCE_OFF, RTN_VAL_UCOMMIT_OFF,
        RTN_VAL_LASTUPD_OFF, RTN_VAL_MISSED_OFF, RTN_VAL_LSIGNED_OFF,
        RTN_VAL_SIGNEP_OFF
    };
    uint8_t want[64];
    if (rtn_tag_key(NODUS_TREE_TAG_VALIDATOR, v + RTN_VAL_PK_OFF,
                    want) != 0)
        return 0;
    if (memcmp(want, key, 64) != 0) return 0;
    for (size_t i = 0; i < sizeof(u64_offs) / sizeof(u64_offs[0]); i++)
        if (rtn_get64(v + u64_offs[i]) > (uint64_t)INT64_MAX) return 0;
    if (!rtn_hex_lower_ok(v + RTN_VAL_DFP_OFF, RTN_VAL_DFP_LEN)) return 0;
    {
        uint32_t comm = ((uint32_t)v[RTN_VAL_COMM_OFF] << 8) |
                        v[RTN_VAL_COMM_OFF + 1];
        uint32_t pcom = ((uint32_t)v[RTN_VAL_PCOMM_OFF] << 8) |
                        v[RTN_VAL_PCOMM_OFF + 1];
        if (comm > DNAC_COMMISSION_BPS_MAX ||
            pcom > DNAC_COMMISSION_BPS_MAX)
            return 0;
    }
    if (v[RTN_VAL_STATUS_OFF] > (uint8_t)DNAC_VALIDATOR_ELIGIBLE)
        return 0;                        /* undefined lifecycle value    */
    return 1;
}

/* The delegation mirror of rtn_val_rec_ok: BOTH halves of the composite
 * key must be the tagged hashes of the two pubkeys the record carries.
 * @return 1 ok / 0 reject. */
static int rtn_del_rec_ok(const uint8_t *v, const uint8_t *key) {
    uint8_t want[64];
    if (rtn_tag_key(NODUS_TREE_TAG_DELEGATION, v + RTN_DEL_DPK_OFF,
                    want) != 0)
        return 0;
    if (memcmp(want, key, 64) != 0) return 0;
    if (rtn_tag_key(NODUS_TREE_TAG_DELEGATION, v + RTN_DEL_VPK_OFF,
                    want) != 0)
        return 0;
    if (memcmp(want, key + 64, 64) != 0) return 0;
    if (rtn_get64(v + RTN_DEL_AMT_OFF) > (uint64_t)INT64_MAX) return 0;
    if (rtn_get64(v + RTN_DEL_AT_OFF) > (uint64_t)INT64_MAX) return 0;
    return 1;
}

static nodus_adapter_status_t rtn_sys_probe(
        const nodus_domain_adapter_t *ad, struct nodus_witness *wns,
        uint32_t dom, const nodus_adapter_op_t *op,
        const uint8_t *key, uint16_t key_len,
        nodus_adapter_row_facts_t *f) {
    (void)ad; (void)dom;
    nodus_witness_t *w = (nodus_witness_t *)wns;
    if (op->op_id == RTN_SYS_OP_CC) {
        if (key_len != RTN_CC_KEY_LEN)
            return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        uint8_t val[RTN_CC_VAL_LEN];
        int rc = rtn_sys_cc_fetch(w, key, val);
        if (rc < 0) return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        f->exists = (rc == 0);
        if (f->exists) {
            f->version = rtn_get64(val);
            if (dna_effect_value_hash(val, RTN_CC_VAL_LEN,
                                      f->value_hash) != 0)
                return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        }
        return NODUS_ADAPTER_OK;
    }
    if (op->op_id == RTN_SYS_OP_VAL) {
        uint8_t rec[RTN_VAL_REC_LEN];
        int rc = rtn_sys_val_fetch(w, key, key_len, rec);
        if (rc < 0) return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        f->exists = (rc == 0);
        if (f->exists) {
            f->version = rtn_get64(rec + RTN_VAL_SELF_OFF);
            if (dna_effect_value_hash(rec, RTN_VAL_REC_LEN,
                                      f->value_hash) != 0)
                return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        }
        return NODUS_ADAPTER_OK;
    }
    if (op->op_id == RTN_SYS_OP_DELEG) {
        uint8_t rec[RTN_DEL_REC_LEN];
        int rc = rtn_sys_del_fetch(w, key, key_len, rec);
        if (rc < 0) return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        f->exists = (rc == 0);
        if (f->exists) {
            f->version = rtn_get64(rec + RTN_DEL_AMT_OFF);
            if (dna_effect_value_hash(rec, RTN_DEL_REC_LEN,
                                      f->value_hash) != 0)
                return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        }
        return NODUS_ADAPTER_OK;
    }
    if (op->op_id == RTN_SYS_OP_STATS) {
        uint64_t v = 0;
        int rc = rtn_sys_stats_fetch(w, key, key_len, &v);
        if (rc < 0) return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        f->exists = (rc == 0);
        if (f->exists) {
            uint8_t vb[8];
            rtn_put64(vb, v);
            f->version = v;
            if (dna_effect_value_hash(vb, 8, f->value_hash) != 0)
                return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        }
        return NODUS_ADAPTER_OK;
    }
    return NODUS_ADAPTER_ERR_STORAGE_FAULT;   /* read-only ops (3, 6)
                                          * have no probe surface        */
}

static nodus_adapter_status_t rtn_sys_read(
        const nodus_domain_adapter_t *ad, struct nodus_witness *wns,
        uint32_t dom, const nodus_adapter_op_t *op,
        const uint8_t *key, uint16_t key_len,
        int *present, uint8_t *value, uint32_t cap, uint32_t *vlen) {
    (void)ad; (void)dom;
    nodus_witness_t *w = (nodus_witness_t *)wns;
    *present = 0;
    *vlen = 0;
    if (op->op_id == RTN_SYS_OP_CC) {
        if (key_len != RTN_CC_KEY_LEN)
            return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        uint8_t val[RTN_CC_VAL_LEN];
        int rc = rtn_sys_cc_fetch(w, key, val);
        if (rc < 0) return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        if (rc == 1) return NODUS_ADAPTER_OK;
        if (cap < RTN_CC_VAL_LEN) return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        memcpy(value, val, RTN_CC_VAL_LEN);
        *present = 1;
        *vlen = RTN_CC_VAL_LEN;
        return NODUS_ADAPTER_OK;
    }
    if (op->op_id == RTN_SYS_OP_CCLATEST) {
        if (key_len != 1) return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(w->db,
                "SELECT new_value FROM chain_config_history "
                "WHERE param_id = ?1 AND new_value > 0 "
                "ORDER BY commit_block DESC LIMIT 1", -1, &st, NULL)
            != SQLITE_OK)
            return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        sqlite3_bind_int64(st, 1, (sqlite3_int64)key[0]);
        int rc = sqlite3_step(st);
        if (rc == SQLITE_ROW) {
            if (cap < 8) {
                sqlite3_finalize(st);
                return NODUS_ADAPTER_ERR_STORAGE_FAULT;
            }
            rtn_put64(value, (uint64_t)sqlite3_column_int64(st, 0));
            sqlite3_finalize(st);
            *present = 1;
            *vlen = 8;
            return NODUS_ADAPTER_OK;
        }
        sqlite3_finalize(st);
        return rc == SQLITE_DONE ? NODUS_ADAPTER_OK
                                 : NODUS_ADAPTER_ERR_STORAGE_FAULT;
    }
    if (op->op_id == RTN_SYS_OP_VAL) {
        uint8_t rec[RTN_VAL_REC_LEN];
        int rc = rtn_sys_val_fetch(w, key, key_len, rec);
        if (rc < 0) return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        if (rc == 1) return NODUS_ADAPTER_OK;        /* absent           */
        if (cap < RTN_VAL_REC_LEN)
            return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        memcpy(value, rec, RTN_VAL_REC_LEN);
        *present = 1;
        *vlen = RTN_VAL_REC_LEN;
        return NODUS_ADAPTER_OK;
    }
    if (op->op_id == RTN_SYS_OP_DELEG) {
        uint8_t rec[RTN_DEL_REC_LEN];
        int rc = rtn_sys_del_fetch(w, key, key_len, rec);
        if (rc < 0) return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        if (rc == 1) return NODUS_ADAPTER_OK;        /* absent           */
        if (cap < RTN_DEL_REC_LEN)
            return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        memcpy(value, rec, RTN_DEL_REC_LEN);
        *present = 1;
        *vlen = RTN_DEL_REC_LEN;
        return NODUS_ADAPTER_OK;
    }
    if (op->op_id == RTN_SYS_OP_DELEGCNT) {
        uint64_t n = 0;
        if (rtn_sys_delegcnt_fetch(w, key, key_len, &n) != 0)
            return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        if (cap < 8) return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        rtn_put64(value, n);
        *present = 1;                    /* a COUNT always answers — 0
                                          * delegations is a VALUE, not
                                          * an absent row                */
        *vlen = 8;
        return NODUS_ADAPTER_OK;
    }
    if (op->op_id == RTN_SYS_OP_STATS) {
        uint64_t v = 0;
        int rc = rtn_sys_stats_fetch(w, key, key_len, &v);
        if (rc < 0) return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        if (rc == 1) return NODUS_ADAPTER_OK;        /* absent           */
        if (cap < 8) return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        rtn_put64(value, v);
        *present = 1;
        *vlen = 8;
        return NODUS_ADAPTER_OK;
    }
    return NODUS_ADAPTER_ERR_STORAGE_FAULT;
}

/* Bind the fifteen mutable validator columns of an INSERT/UPDATE
 * statement starting at parameter `start`, in the order
 * nodus_witness_validator.c bind_validator_mutable_fields uses (the
 * schema's column order) — the record's own field order is the MERKLE
 * order, which differs only in that the key is not a value field. */
static void rtn_sys_val_bind(sqlite3_stmt *st, int start,
                             const uint8_t *v) {
    sqlite3_bind_int64(st, start + 0,
        (sqlite3_int64)rtn_get64(v + RTN_VAL_SELF_OFF));
    sqlite3_bind_int64(st, start + 1,
        (sqlite3_int64)rtn_get64(v + RTN_VAL_TOTDEL_OFF));
    sqlite3_bind_int64(st, start + 2,
        (sqlite3_int64)rtn_get64(v + RTN_VAL_EXTDEL_OFF));
    sqlite3_bind_int64(st, start + 3, (sqlite3_int64)(
        ((uint32_t)v[RTN_VAL_COMM_OFF] << 8) | v[RTN_VAL_COMM_OFF + 1]));
    sqlite3_bind_int64(st, start + 4, (sqlite3_int64)(
        ((uint32_t)v[RTN_VAL_PCOMM_OFF] << 8) | v[RTN_VAL_PCOMM_OFF + 1]));
    sqlite3_bind_int64(st, start + 5,
        (sqlite3_int64)rtn_get64(v + RTN_VAL_PEFF_OFF));
    sqlite3_bind_int64(st, start + 6,
        (sqlite3_int64)v[RTN_VAL_STATUS_OFF]);
    sqlite3_bind_int64(st, start + 7,
        (sqlite3_int64)rtn_get64(v + RTN_VAL_SINCE_OFF));
    sqlite3_bind_int64(st, start + 8,
        (sqlite3_int64)rtn_get64(v + RTN_VAL_UCOMMIT_OFF));
    /* the fingerprint column is TEXT: the V2 write side always produces
     * a full 128-char lowercase-hex window (rtn_val_rec_ok enforces it),
     * so the fixed length is bound explicitly — never strlen, which
     * would stop at a NUL a corrupt value could carry */
    sqlite3_bind_text(st, start + 9,
        (const char *)(v + RTN_VAL_DFP_OFF), (int)RTN_VAL_DFP_LEN,
        SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, start + 10, v + RTN_VAL_DPK_OFF,
                      DNAC_PUBKEY_SIZE, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, start + 11,
        (sqlite3_int64)rtn_get64(v + RTN_VAL_LASTUPD_OFF));
    sqlite3_bind_int64(st, start + 12,
        (sqlite3_int64)rtn_get64(v + RTN_VAL_MISSED_OFF));
    sqlite3_bind_int64(st, start + 13,
        (sqlite3_int64)rtn_get64(v + RTN_VAL_LSIGNED_OFF));
    sqlite3_bind_int64(st, start + 14,
        (sqlite3_int64)rtn_get64(v + RTN_VAL_SIGNEP_OFF));
}

static nodus_adapter_status_t rtn_sys_mutate(
        const nodus_domain_adapter_t *ad, struct nodus_witness *wns,
        uint32_t dom, const nodus_adapter_op_t *op, uint8_t kind,
        const uint8_t *key, uint16_t key_len,
        const uint8_t *value, uint32_t value_len) {
    (void)ad; (void)dom;
    nodus_witness_t *w = (nodus_witness_t *)wns;
    sqlite3_stmt *st = NULL;
    int cc_row = 0;                      /* invalidate the warm cc cache */
    if (op->op_id == RTN_SYS_OP_CC && kind == DNA_EFFECT_CREATE) {
        if (key_len != RTN_CC_KEY_LEN || value_len != RTN_CC_VAL_LEN ||
            !value)
            return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        if (sqlite3_prepare_v2(w->db,
                "INSERT INTO chain_config_history (param_id, new_value, "
                "effective_block, commit_block, tx_hash, proposal_nonce, "
                "created_at_unix) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0)",
                -1, &st, NULL) != SQLITE_OK)
            return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        sqlite3_bind_int64(st, 1, (sqlite3_int64)(
            ((uint32_t)key[0] << 24) | ((uint32_t)key[1] << 16) |
            ((uint32_t)key[2] << 8) | (uint32_t)key[3]));
        sqlite3_bind_int64(st, 2, (sqlite3_int64)rtn_get64(value));
        sqlite3_bind_int64(st, 3, (sqlite3_int64)rtn_get64(key + 4));
        sqlite3_bind_int64(st, 4, (sqlite3_int64)rtn_get64(value + 8));
        sqlite3_bind_blob(st, 5, value + 24, 64, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 6, (sqlite3_int64)rtn_get64(value + 16));
        cc_row = 1;
    } else if (op->op_id == RTN_SYS_OP_VAL && kind == DNA_EFFECT_CREATE) {
        if (key_len != RTN_VAL_KEY_LEN || value_len != RTN_VAL_REC_LEN ||
            !value || !rtn_val_rec_ok(value, key))
            return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        /* STRICT insert — the ABSENT precondition already ruled inside
         * this transaction, so a conflicting row here is a broken
         * invariant on THIS node, never a silent drop (the legacy lane
         * mapped the constraint to a -2 return, validator.c:183). */
        if (sqlite3_prepare_v2(w->db,
                "INSERT INTO validators (pubkey_hash, pubkey, "
                "self_stake, total_delegated, external_delegated, "
                "commission_bps, pending_commission_bps, "
                "pending_effective_block, status, active_since_block, "
                "unstake_commit_block, unstake_destination_fp, "
                "unstake_destination_pubkey, "
                "last_validator_update_block, consecutive_missed_epochs, "
                "last_signed_block, signed_blocks_this_epoch) "
                "VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, "
                "?12, ?13, ?14, ?15, ?16, ?17)",
                -1, &st, NULL) != SQLITE_OK)
            return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        sqlite3_bind_blob(st, 1, key, RTN_VAL_KEY_LEN, SQLITE_TRANSIENT);
        sqlite3_bind_blob(st, 2, value + RTN_VAL_PK_OFF, DNAC_PUBKEY_SIZE,
                          SQLITE_TRANSIENT);
        rtn_sys_val_bind(st, 3, value);
    } else if (op->op_id == RTN_SYS_OP_VAL && kind == DNA_EFFECT_SET) {
        if (key_len != RTN_VAL_KEY_LEN || value_len != RTN_VAL_REC_LEN ||
            !value || !rtn_val_rec_ok(value, key))
            return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        /* the pubkey is NOT updatable: it is what the key hashes, and
         * rtn_val_rec_ok already proved the two agree */
        if (sqlite3_prepare_v2(w->db,
                "UPDATE validators SET self_stake = ?1, "
                "total_delegated = ?2, external_delegated = ?3, "
                "commission_bps = ?4, pending_commission_bps = ?5, "
                "pending_effective_block = ?6, status = ?7, "
                "active_since_block = ?8, unstake_commit_block = ?9, "
                "unstake_destination_fp = ?10, "
                "unstake_destination_pubkey = ?11, "
                "last_validator_update_block = ?12, "
                "consecutive_missed_epochs = ?13, last_signed_block = ?14, "
                "signed_blocks_this_epoch = ?15 WHERE pubkey_hash = ?16",
                -1, &st, NULL) != SQLITE_OK)
            return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        rtn_sys_val_bind(st, 1, value);
        sqlite3_bind_blob(st, 16, key, RTN_VAL_KEY_LEN, SQLITE_TRANSIENT);
    } else if (op->op_id == RTN_SYS_OP_DELEG &&
               kind == DNA_EFFECT_CREATE) {
        if (key_len != RTN_DEL_KEY_LEN || value_len != RTN_DEL_REC_LEN ||
            !value || !rtn_del_rec_ok(value, key))
            return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        if (sqlite3_prepare_v2(w->db,
                "INSERT INTO delegations (delegator_hash, "
                "validator_hash, delegator_pubkey, validator_pubkey, "
                "amount, delegated_at_block) "
                "VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                -1, &st, NULL) != SQLITE_OK)
            return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        sqlite3_bind_blob(st, 1, key, 64, SQLITE_TRANSIENT);
        sqlite3_bind_blob(st, 2, key + 64, 64, SQLITE_TRANSIENT);
        sqlite3_bind_blob(st, 3, value + RTN_DEL_DPK_OFF, DNAC_PUBKEY_SIZE,
                          SQLITE_TRANSIENT);
        sqlite3_bind_blob(st, 4, value + RTN_DEL_VPK_OFF, DNAC_PUBKEY_SIZE,
                          SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 5,
            (sqlite3_int64)rtn_get64(value + RTN_DEL_AMT_OFF));
        sqlite3_bind_int64(st, 6,
            (sqlite3_int64)rtn_get64(value + RTN_DEL_AT_OFF));
    } else if (op->op_id == RTN_SYS_OP_DELEG && kind == DNA_EFFECT_SET) {
        if (key_len != RTN_DEL_KEY_LEN || value_len != RTN_DEL_REC_LEN ||
            !value || !rtn_del_rec_ok(value, key))
            return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        if (sqlite3_prepare_v2(w->db,
                "UPDATE delegations SET amount = ?1, "
                "delegated_at_block = ?2 "
                "WHERE delegator_hash = ?3 AND validator_hash = ?4",
                -1, &st, NULL) != SQLITE_OK)
            return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        sqlite3_bind_int64(st, 1,
            (sqlite3_int64)rtn_get64(value + RTN_DEL_AMT_OFF));
        sqlite3_bind_int64(st, 2,
            (sqlite3_int64)rtn_get64(value + RTN_DEL_AT_OFF));
        sqlite3_bind_blob(st, 3, key, 64, SQLITE_TRANSIENT);
        sqlite3_bind_blob(st, 4, key + 64, 64, SQLITE_TRANSIENT);
    } else if (op->op_id == RTN_SYS_OP_DELEG &&
               kind == DNA_EFFECT_DELETE) {
        if (key_len != RTN_DEL_KEY_LEN)
            return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        if (sqlite3_prepare_v2(w->db,
                "DELETE FROM delegations WHERE delegator_hash = ?1 AND "
                "validator_hash = ?2", -1, &st, NULL) != SQLITE_OK)
            return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        sqlite3_bind_blob(st, 1, key, 64, SQLITE_TRANSIENT);
        sqlite3_bind_blob(st, 2, key + 64, 64, SQLITE_TRANSIENT);
    } else if (op->op_id == RTN_SYS_OP_STATS && kind == DNA_EFFECT_SET) {
        if (key_len != 1 || key[0] != RTN_STATS_SEL_ACTIVE ||
            value_len != 8 || !value)
            return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        if (rtn_get64(value) > (uint64_t)INT64_MAX)
            return NODUS_ADAPTER_ERR_STORAGE_FAULT;   /* would round-trip
                                          * negative through the INTEGER
                                          * column and poison the fetch  */
        /* ABSOLUTE new counter, bound by the effect's EXISTS_VERSION
         * precondition to the value the mediated read observed — never
         * the legacy read-modify-write "value = value + 1"
         * (bft.c:1611), which is not expressible as a typed effect and
         * cannot be replay-checked. */
        if (sqlite3_prepare_v2(w->db,
                "UPDATE validator_stats SET value = ?1 "
                "WHERE key = 'active_count'", -1, &st, NULL) != SQLITE_OK)
            return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        sqlite3_bind_int64(st, 1, (sqlite3_int64)rtn_get64(value));
    } else {
        return NODUS_ADAPTER_ERR_STORAGE_FAULT;
    }
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) return NODUS_ADAPTER_ERR_STORAGE_FAULT;
    if (sqlite3_changes(w->db) != 1)
        return NODUS_ADAPTER_ERR_STORAGE_FAULT;
    /* the legacy apply's cache-coherence rule (CC-OPS-004 / Q16): a
     * committed row must invalidate the warm lookup cache BEFORE the
     * outer transaction commits; on rollback a cold cache merely
     * re-warms from the database, which will not hold the row */
    if (cc_row) w->chain_config_cache_warm = false;
    return NODUS_ADAPTER_OK;
}

static const nodus_adapter_op_t RTN_SYS_OPS[6] = {
    { RTN_SYS_OP_CC,
      NODUS_ADAPTER_KIND_BIT(DNA_EFFECT_CREATE),
      NODUS_ADAPTER_PRECOND_BIT(DNA_EFFECT_PRE_ABSENT),
      RTN_CC_KEY_LEN, RTN_CC_KEY_LEN, RTN_CC_VAL_LEN, RTN_CC_VAL_LEN },
    /* op 2 (committee read) RETIRED — capacity season; id not reused */
    { RTN_SYS_OP_CCLATEST,  0, 0, 1, 1, 0, 8 },
    /* O11 — the stake-lifecycle rows */
    { RTN_SYS_OP_VAL,
      (uint8_t)(NODUS_ADAPTER_KIND_BIT(DNA_EFFECT_CREATE) |
                NODUS_ADAPTER_KIND_BIT(DNA_EFFECT_SET)),
      (uint8_t)(NODUS_ADAPTER_PRECOND_BIT(DNA_EFFECT_PRE_ABSENT) |
                NODUS_ADAPTER_PRECOND_BIT(DNA_EFFECT_PRE_EXISTS_VHASH)),
      (uint16_t)RTN_VAL_KEY_LEN, (uint16_t)RTN_VAL_KEY_LEN,
      RTN_VAL_REC_LEN, RTN_VAL_REC_LEN },
    /* DELETE is allowed here and nowhere else in this table: a fully
     * drained delegation is REMOVED (bft.c:1880), so value_len_min must
     * be 0 for that kind to be shapeable at all (adapter selfcheck). */
    { RTN_SYS_OP_DELEG,
      (uint8_t)(NODUS_ADAPTER_KIND_BIT(DNA_EFFECT_CREATE) |
                NODUS_ADAPTER_KIND_BIT(DNA_EFFECT_SET) |
                NODUS_ADAPTER_KIND_BIT(DNA_EFFECT_DELETE)),
      (uint8_t)(NODUS_ADAPTER_PRECOND_BIT(DNA_EFFECT_PRE_ABSENT) |
                NODUS_ADAPTER_PRECOND_BIT(DNA_EFFECT_PRE_EXISTS_VHASH)),
      (uint16_t)RTN_DEL_KEY_LEN, (uint16_t)RTN_DEL_KEY_LEN,
      0, RTN_DEL_REC_LEN },
    { RTN_SYS_OP_DELEGCNT,  0, 0, 64, 64, 0, 8 },
    { RTN_SYS_OP_STATS,
      NODUS_ADAPTER_KIND_BIT(DNA_EFFECT_SET),
      NODUS_ADAPTER_PRECOND_BIT(DNA_EFFECT_PRE_EXISTS_VERSION),
      1, 1, 8, 8 }
};

const nodus_domain_adapter_t NODUS_RT_SYSTEM_ADAPTER = {
    .adapter_version = NODUS_DOMAIN_ADAPTER_V1,
    .ops = RTN_SYS_OPS,
    .n_ops = 6,
    .probe = rtn_sys_probe,
    .mutate = rtn_sys_mutate,
    .read = rtn_sys_read
};
