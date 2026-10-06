/**
 * @file nodus_witness_runtime.h
 * @brief Ledger V2 Season 4 — the compiled NATIVE_BUILTIN domain-runtime
 *        table and its fail-closed exact-tuple lookup (INACTIVE).
 *
 * A DomainManifest never causes code execution by itself: a validator may
 * claim support for a proposed ruleset ONLY when this locally compiled
 * table contains an entry whose FULL identity tuple
 *
 *     (domain_id, runtime_kind, runtime_abi, ruleset_version, ruleset_hash)
 *
 * matches the proposal exactly. There is no "closest version", no implicit
 * latest, no acceptance on a name or id alone — any mismatch on any axis
 * means the lookup returns NULL and the caller must refuse readiness,
 * admission and activation (fail-closed).
 *
 * `ruleset_hash` is the tagged SHA3-512 digest of a checked-in canonical
 * RulesetDescriptor (shared/dnac/domain_wire.h, tag "NDS.RULESET.v1") —
 * pure data, never compiler output, build paths or timestamps, so it is
 * byte-identical across compilers, operating systems and build trees.
 * The pinned digest literals in this table are verified against a fresh
 * recomputation by nodus_witness_runtime_selfcheck(); a drifted descriptor
 * is a hard startup/test failure, never a silent divergence.
 *
 * ACTIVATION: nothing in live consensus calls anything here. The builtin
 * table carries exactly SYSTEM and DNA_CORE; a test-only third runtime is
 * exercised through the *_in() variants over a caller-supplied table and
 * is NEVER part of this production table.
 *
 * S5/S6 boundary: the state_root / asset_check / claim_apply / invariant
 * hooks are the REAL native-runtime boundary the generic executor
 * dispatches through — it holds no per-domain branch of its own.
 *
 * EXECUTION boundary (Ledger V2 execution season): the old reserved
 * apply hook is REPLACED by the real typed pair below — read_plan (the
 * deterministic mediated-read request phase) and exec (native compiled
 * execution of one preflighted envelope leg, returning ONLY a canonical
 * "NDS.EFFRES.v1" typed-effect result). Both MUST stay NULL in the
 * compiled production table until the CORE/SYSTEM hook-migration season;
 * nodus_witness_runtime_selfcheck() enforces the shape. A runtime whose
 * exec is NULL cannot execute envelope legs at all — the engine fails
 * that leg closed (there is no fallback execution path of any kind).
 *
 * METERING authority (same season): a runtime MAY carry the exact
 * metering policy its descriptor commits (meter_policy_digest,
 * domain_wire.h). The SYSTEM entry — the mandatory protocol domain —
 * carries THE block metering policy: the engine's block-start snapshot
 * takes its pricing authority from the resolved SYSTEM runtime, verifies
 * the seal AND the descriptor-committed identity digest, and from
 * nothing else. Because the descriptor hash is matched five-axis-exactly
 * by every validator, two validators claiming the same SYSTEM ruleset
 * identity structurally cannot price differently.
 *
 * @file nodus_witness_runtime.h
 */

#ifndef NODUS_WITNESS_RUNTIME_H
#define NODUS_WITNESS_RUNTIME_H

#include <stdint.h>
#include <stddef.h>

#include "dnac/domain_wire.h"
#include "dnac/res_meter.h"     /* dna_meter_policy_t + the env/effect
                                 * codec views the execution hooks borrow */
#include "dnac/evm_call_wire.h" /* Nodus EVM: the ONE EVM call / EVMFUND codec */

#ifdef __cplusplus
extern "C" {
#endif

/** This release's native runtime ABI. */
#define NODUS_DOMAIN_RUNTIME_ABI_V1  ((uint32_t)1)
/** Nodus EVM (design docs/plans/2026-10-04-nodus-evm-chain-integration-design.md
 *  rev 3 §3): the runtime ABI with ENGINE-MEDIATED READS AT RUN TIME. An
 *  ABI-2 runtime has no read_plan and no exec; it executes a leg through
 *  `exec_evm`, pulling committed state through an engine-owned reader that
 *  charges every logical read before it happens. Only the EVM runtime
 *  (nodus_witness_rt_evm.c) speaks it; the compiled production table
 *  carries it as the generation-3 EVM slice (nodus_witness_runtime.c, the
 *  ABI-2 entries), which a chain resolves only after the EVM_ACTIVE vote
 *  (param 14) switches the rule-set generation. */
#define NODUS_DOMAIN_RUNTIME_ABI_V2  ((uint32_t)2)

/* Semantic rule identifiers named in the checked-in ruleset descriptors.
 * Opaque, stable, strictly-ascending per descriptor — bumping a domain's
 * semantics means a NEW ruleset_version + descriptor, never a re-use. */
#define DNA_SYSRULE_STAKE            ((uint32_t)1)
#define DNA_SYSRULE_DELEGATE         ((uint32_t)2)
#define DNA_SYSRULE_UNSTAKE          ((uint32_t)3)
#define DNA_SYSRULE_UNDELEGATE       ((uint32_t)4)
#define DNA_SYSRULE_VALIDATOR_UPDATE ((uint32_t)5)
#define DNA_SYSRULE_CHAIN_CONFIG     ((uint32_t)6)

#define DNA_CORERULE_SPEND           ((uint32_t)1)
#define DNA_CORERULE_BURN            ((uint32_t)2)
#define DNA_CORERULE_TOKEN_CREATE    ((uint32_t)3)
/** Type 11 admission stays consensus-REJECTED until C3 — the rule exists
 *  so the descriptor honestly names the shipped behavior. */
#define DNA_CORERULE_SHIELDED_C3_REJECT ((uint32_t)4)
/* Rule ids 5 and 6 (DNA_CORERULE_SHIELD_C3_REJECT /
 * DNA_CORERULE_UNSHIELD_C3_REJECT) are declared in
 * nodus_witness_runtime.c next to the descriptor that names them — the
 * digest commits the VALUES, never the declaration site. */
/** O11 — the staking-lifecycle FUNDING/RELEASE coupling leg: the CORE
 *  half of every SYSTEM stake-lifecycle envelope. It consumes the
 *  transparent inputs that fund a lock (STAKE bond / DELEGATE amount),
 *  pays the fee, and creates the release UTXO an UNDELEGATE returns —
 *  amounts are NEVER in its own call, they are derived from the SIBLING
 *  SYSTEM leg's call bytes, so record and funding cannot disagree. It is
 *  declared HERE (not in runtime.c) because both the CORE hook and the
 *  SYSTEM stake hooks name it when they check their sibling leg. */
#define DNA_CORERULE_SYSFUND         ((uint32_t)7)
/** HF-4 (design docs/plans/2026-10-02-onchain-names-design.md rev 4 §2):
 *  NAME_REGISTER — owned by the generation-2 CORE descriptor only (CORE
 *  v5, rules {1..8}). Generation 1 does not own it, so admission refuses
 *  op 8 there exactly as before HF-4 (nodus_witness_v2_apply.c
 *  env_admit_legs, rt_owns_runtime_op). Executed by the CORE hooks
 *  (nodus_witness_rt_native.c rtn_name_parse / rtn_name_exec), which
 *  refuse it under a generation-1 or NULL runtime as a deterministic
 *  verdict (-1), never a fault. */
#define DNA_CORERULE_NAME_REGISTER   ((uint32_t)8)
/** Nodus EVM (design docs/plans/2026-10-04-nodus-evm-chain-integration-design.md
 *  rev 3 §2, §5): EVMFUND — the CORE half of every EVM envelope, which is
 *  EXACTLY [CORE EVMFUND] + [EVM op]. Owned by the EVM generation's CORE
 *  descriptor only (NODUS_RT_GEN_EVM below); every older generation does
 *  not own it, so admission refuses op 9 there exactly as before. Its
 *  call carries NO amount and NO recipient — those come from the sibling
 *  EVM leg's call bytes (the SYSFUND discipline). Declared HERE because
 *  the CORE hook and the EVM hook both name it when they check their
 *  sibling (nodus_rt_evm_pair_check below). */
#define DNA_CORERULE_EVMFUND         ((uint32_t)9)

/** EVMFUND call: ver u8 ‖ role u8 ‖ the SYSFUND transfer section
 *  (in_count u8 1..15 ‖ nullifiers ‖ out_count u8 0..16 ‖ outputs). */
#define NODUS_RT_EVMFUND_CALL_VER     1u
/** role FEE (EVM CALL / CREATE): the inputs pay the envelope fee, to the
 *  reward pool; nothing is locked. */
#define NODUS_RT_EVMFUND_ROLE_FEE     1u
/** role DEPOSIT (EVM DEPOSIT): the inputs also LOCK the sibling's
 *  amount_raw into the CORE EVM reserve. */
#define NODUS_RT_EVMFUND_ROLE_DEPOSIT 2u
/** role RELEASE (EVM WITHDRAW / REDEEM): a UTXO of the sibling's
 *  amount_raw is created to the sibling's dest_fp and the reserve is
 *  debited by it. */
#define NODUS_RT_EVMFUND_ROLE_RELEASE 3u

/* ── Nodus EVM runtime ops (design §2) — the EVM descriptor's rule ids. Here,
 *    not only in nodus_witness_rt_evm.h, because the pure call-head
 *    decoder below (always compiled) and the CORE hook read them. ─────── */
#define NODUS_RT_EVM_CALL       1u
#define NODUS_RT_EVM_CREATE     2u
#define NODUS_RT_EVM_DEPOSIT    3u
#define NODUS_RT_EVM_WITHDRAW   4u
#define NODUS_RT_EVM_REDEEM     5u
/** The one call-bytes version this release decodes (design §2 `ver`). */
#define NODUS_RT_EVM_CALL_VER   1u
/** The block-gas share of one bridge op (design §8: "köprü op'ları sabit
 *  21 000 sayılır"). */
#define NODUS_RT_EVM_BRIDGE_GAS 21000u

/* ── HF-4 rule-set GENERATIONS (design §1.1) ───────────────────────────
 * The compiled table is an ordered list of generations since genesis:
 * generation → (SYSTEM tuple, CORE tuple, sealed SYSTEM meter policy).
 * Generation 1 is the genesis generation (SYSTEM v6 / CORE v4 / policy
 * 8f1f9cb2…), byte-identical to the pre-HF-4 table; generation 2 is
 * SYSTEM v7 / CORE v5. Every generation stays in every future binary
 * (replay from genesis). The registry's committed manifests decide which
 * generation judges a block (nodus_witness_v2_runtime_for — exact
 * tuple); the switch from 1 to 2 is phase 6b' of the engine. */
#define NODUS_RT_GEN_1               ((uint32_t)1)
#define NODUS_RT_GEN_2               ((uint32_t)2)
/** Nodus EVM (design §9): the EVM GENERATION — SYSTEM v8 (the policy pricing
 *  ops 1..9), CORE v6 (rule 9 EVMFUND, the reserved supply leaf and
 *  invariant), EVM v2 (the third domain, registered ACTIVE by phase 6b''
 *  at the end of block H-1 of the EVM_ACTIVE vote). The NEXT FREE number
 *  in this tree; ONE definition so a merge with another generation (HF-5)
 *  renumbers it here only — the D literal (dnac.h DNAC_CFG_EVM_ACTIVE_D)
 *  commits it and must be re-derived with it. */
#define NODUS_RT_GEN_EVM             ((uint32_t)3)
/** Nodus EVM Faz 4: the EVM generation's EVM-domain RULESET IDENTITY — the
 *  (version, hash) every EVM leg's call commitment binds (env_wire.h
 *  "ruleset_hash is CONTEXTUAL"). Header constants (no code), ONE
 *  definition: the compiled table's EVM entry and its pinned digest
 *  (nodus_witness_runtime.c EVM_RULESET_HASH_GEVM) initialise from them,
 *  and so does a client that cannot link the witness (the web wallet's
 *  send.wasm, nodus-send-wasm.c "SMART CONTRACTS"). The digest is
 *  re-derived from the descriptor by nodus_witness_runtime_selfcheck on
 *  every start of an EVM-enabled build, so a drift here refuses to start.
 *  Version 2 (Kurultay #9, docs/plans/decisions/2026-10-06-kurultay-9-
 *  evm-address-width-summary.md items 1-2): the bridge refuses a DEPOSIT /
 *  WITHDRAW sender that carries code, and the address width is committed
 *  in D — new semantics, so a new version (the rule above), never v1
 *  re-used. Digest: E4 of shared/dnac/tests/nodus_evm_activation_oracle.py
 *  — SELF-DERIVED. */
#define NODUS_RT_EVM_RULESET_VERSION_GEVM  2u
#define NODUS_RT_EVM_RULESET_HASH_GEVM_INIT { \
    0x6a, 0xf8, 0x34, 0x6d, 0x10, 0xc9, 0xce, 0x5c, \
    0xed, 0x25, 0xb6, 0x8e, 0x1d, 0xdd, 0x20, 0x1b, \
    0xe2, 0x05, 0xe0, 0xd7, 0xd4, 0x65, 0xe9, 0x04, \
    0x12, 0xf7, 0x89, 0x62, 0x20, 0x6e, 0x77, 0x5b, \
    0xf8, 0x5f, 0x6c, 0x1d, 0x71, 0xd4, 0xcf, 0x38, \
    0x33, 0x14, 0x88, 0x93, 0x97, 0x7d, 0xc8, 0x12, \
    0x6d, 0xfa, 0x01, 0xfc, 0xae, 0x2c, 0x83, 0xca, \
    0x6a, 0x06, 0xd7, 0x4c, 0x1b, 0xf4, 0x46, 0x5f  \
}
/** The generation the EVM generation is built on and switches FROM (its
 *  SYSTEM/CORE tuples are this one's plus the EVM changes). ONE definition;
 *  committed by the D literal; a vote is refused unless the registry is at
 *  this generation (nodus_chain_config_stateful_rules). */
#define NODUS_RT_GEN_EVM_BASE        NODUS_RT_GEN_2
/** The newest compiled generation. The EVM generation needs the EVM
 *  runtime, which only the standalone non-Windows nodus build compiles
 *  (nodus/CMakeLists.txt NODUS_EVM_ENABLED); every other build of this
 *  file (the messenger tree's libnodus, a Windows nodus) carries
 *  generations 1 and 2 only — a node of such a build fails closed at the
 *  EVM edge (the tuple is unknown), it never mis-executes. */
#ifdef NODUS_EVM_ENABLED
#define NODUS_RT_GEN_MAX             NODUS_RT_GEN_EVM
#else
#define NODUS_RT_GEN_MAX             NODUS_RT_GEN_2
#endif

struct nodus_domain_runtime;

/** Semantic admission for one (tx_type, pool_id) under this runtime.
 *  @return 0 admit, -1 reject (unknown type, illegal pool, C3 stop). */
typedef int (*nodus_rt_admit_fn)(const struct nodus_domain_runtime *rt,
                                 uint8_t tx_type, uint32_t pool_id);

/** Deterministic verification-cost declaration (work units) for one type.
 *  @return 0 with *cost_out set, -1 for a type this runtime does not own
 *  (fail-closed — an unknown type has NO cost, not a default one).
 *
 *  AUTHORITY NOTE (metering season): this hook is a per-tx-TYPE
 *  classification for the LEGACY pre-envelope admission surface
 *  (nodus_witness_domreg.c admission; the raw-SQL op scaffold that also
 *  consumed it is retired). It is NOT a price authority for the Ledger
 *  V2 envelope lane:
 *  envelope legs are keyed by runtime_op and priced EXCLUSIVELY by the
 *  engine-supplied block-start policy snapshot
 *  (shared/dnac/res_meter.h — dna_meter_policy_t.w_op), which this hook
 *  can neither feed nor override. The hook migration that retires this
 *  surface onto the envelope lane is a later season's work. */
typedef int (*nodus_rt_cost_fn)(const struct nodus_domain_runtime *rt,
                                uint8_t tx_type, uint32_t *cost_out);

/* The witness handle every stateful hook receives. Forward-declared so
 * this header stays witness-free; the hook implementations live in the
 * witness tree and cast/use it there. */
struct nodus_witness;

/* The compiled storage adapter a runtime MAY register (Ledger V2
 * typed-effect boundary, nodus_witness_v2_adapter.h). Forward-declared
 * for the same reason: this header describes the runtime's shape, never
 * the adapter's contents. */
struct nodus_domain_adapter;

/* ── The typed EXECUTION boundary (Ledger V2 execution season) ────────
 *
 * A runtime executes ONE preflighted envelope leg through the two hooks
 * below. Everything it may consume is handed to it explicitly; it
 * receives NO witness handle, NO database, NO clock, NO RNG — so the
 * only inputs a leg's execution can depend on are the envelope bytes,
 * the engine-derived context and the engine-mediated read results, all
 * of which are byte-identical on every honest node. */

/** Largest mediated-read request list one leg may emit — an engine
 *  array bound, not a priced policy; a plan exceeding it is rejected,
 *  never truncated. R3 W4-C: this used to be described as "mirroring"
 *  NODUS_V2_ENV_BATCH_MAX / MAX_OPS while all three happened to be 16;
 *  those two are now derived bounds (3 209 / 17 371, apply.h) and this
 *  one is its own number — the read budget that sized CORE SPEND at 15
 *  inputs + 1 supply read (nodus_witness_rt_native.c). */
#define NODUS_RT_MAX_READS 16

/** One typed mediated-read request: a compiled adapter operation id plus
 *  an opaque canonical key — NOTHING else can be asked for. */
typedef struct {
    uint32_t op_id;                       /* compiled adapter op          */
    uint16_t key_len;                     /* 1..DNA_EFFECT_MAX_KEY_LEN    */
    uint8_t  key[DNA_EFFECT_MAX_KEY_LEN];
} nodus_rt_read_req_t;

/** One bounded typed mediated-read result. `present` distinguishes a
 *  MISSING row (present == 0, value_len == 0 — a successful read of an
 *  absent key) from a present one; a storage/node FAULT never produces
 *  a result at all (the engine aborts its own operation instead — the
 *  fault-vs-verdict rule). */
typedef struct {
    uint8_t  present;                     /* 0 or 1                       */
    uint32_t value_len;                   /* 0..DNA_EFFECT_MAX_VALUE_LEN  */
    uint8_t  value[DNA_EFFECT_MAX_VALUE_LEN];
} nodus_rt_read_res_t;

/* ── The verified AUTHORIZATION boundary (native auth season) ─────────
 *
 * An authorization COMMITMENT (leg_auth_digest) is not a VERDICT. The
 * engine turns commitments into verdicts by invoking the resolved
 * runtime's `auth` hook BEFORE any execution or mutation; the verdict
 * it produces is ENGINE-OWNED, immutable for the rest of the block, and
 * handed back to read_plan/exec as `ctx->auth`. No envelope field, no
 * caller parameter and no runtime return value can substitute for it:
 * a leg whose auth hook did not return 0 never reaches execution.
 *
 * THREE supported schemes this release (capacity season; kind 3 —
 * general multisig, final pre-testnet wipe):
 *
 *   auth_kind 1 — NODUS_RT_AUTHKIND_DSA87_MULTI_V1: auth_data =
 *     signer_count u8 (1..NODUS_RT_AUTH_MAX_SIGNERS)
 *     ‖ signer_count × ( pubkey[2592] ‖ signature[4627] )
 *   with pubkeys STRICTLY ascending (memcmp — duplicates and disorder
 *   reject, so exactly ONE encoding exists per signer set), each
 *   signature an ML-DSA-87 signature over the 64-byte engine-derived
 *   leg auth_digest (env_wire.h "NDS.ENVAUTH.v1": binds chain identity,
 *   expiry, fee, resource ceilings, every leg's domain / runtime_op /
 *   ruleset identity / call bytes through auth_context_commit — so
 *   changing ANY of them invalidates every signature).
 *
 *   auth_kind 2 — NODUS_RT_AUTHKIND_DSA87_CC_V1 (the committee-indexed
 *   authorization CARRIER, capacity season): auth_data =
 *     the ENTIRE kind-1 body (the SUBMITTER section, same rules)
 *     ‖ approval_count u16 BE (1..committee_n)
 *     ‖ approval_count × ( snapshot_index u16 BE ‖ signature[4627] )
 *   Approvals reference the ENGINE-resolved governing committee snapshot
 *   by POSITION — the committee pubkeys are NEVER carried on the wire
 *   (they are already consensus state). Indices STRICTLY increasing
 *   (duplicates and disorder reject — one-validator-one-vote is
 *   structural), every index < committee count, count <= committee
 *   count, exact framing (checked length arithmetic — truncation and
 *   trailing bytes reject). Each approval signature is ML-DSA-87 over
 *   the engine-derived APPROVAL DIGEST (nodus_witness_rt_native.c
 *   "NDS.CCAPPR.v1": leg auth_digest ‖ resolved-set hash ‖ governing
 *   epoch ‖ signer index — so an approval binds everything the
 *   submitter signature binds PLUS the exact governing snapshot and the
 *   signer's own seat). QUORUM IS NOT DECIDED HERE: the hook verifies
 *   EVIDENCE and counts it into the verdict; the consuming runtime_op
 *   (CHAIN_CONFIG exec) compares against dna_bft_quorum(committee_n).
 *   SCOPING NOTE (capacity-season review finding, fail-closed today):
 *   the scheme is deliberately runtime_op-AGNOSTIC — a verdict says
 *   only "these seats signed THIS leg's digest", which binds the op but
 *   certifies no policy. Every FUTURE SYSTEM op migrated onto kind 2
 *   must decide its own authority rule in ITS exec (the CHAIN_CONFIG
 *   quorum gate is the precedent, not an inherited default). O11 is the
 *   first exercise of that rule: all four stake-lifecycle ops (1..4)
 *   decide their own authority (exactly ONE signer whose fingerprint
 *   equals SHA3-512 of the identity pubkey CARRIED IN THE CALL) and
 *   therefore REJECT a kind-2 leg at exec — carriage is permitted by the
 *   runtime's allowlist, authority is never inherited from it. Op 5
 *   still deterministically rejects before any verdict is consumed.
 *   COORDINATION NOTE (honest label): auth_len is bound by the leg
 *   auth_digest through AUTHCTX_BYTES, and kind-2 auth_len depends on
 *   the final (signer_count, approval_count) pair — so the exact
 *   signer/approval SET must be fixed before anyone signs; adding or
 *   dropping one approval afterwards invalidates every signature. Same
 *   property kind 1 already has for its signer set; it is the seam the
 *   intent-identity season inherits, not a soundness hole.
 *
 *   auth_kind 3 — NODUS_RT_AUTHKIND_DSA87_MSIG_V1 (general multisig,
 *   decision 2026-09-29-general-multisig.md, design §7 rev 2 — CORE
 *   only): auth_data =
 *     the ENTIRE kind-1 body (the signer section, same rules, same
 *     signatures over the SAME leg auth_digest — there is NO new
 *     signature preimage)
 *     ‖ dcount u8 (1 .. NODUS_RT_MSIG_MAX_DESC)
 *     ‖ dcount × ( dlen u16 BE ‖ descriptor[dlen] )
 *   Each descriptor is a shared/dnac/msig_wire.h descriptor ("NDS.MSIG.v1"
 *   ‖ M ‖ N ‖ N × pubkey, 2 <= N <= 7, 1 <= M <= N, keys strictly
 *   ascending, no zero key), dlen EXACTLY 18 + N × 2592; descriptors
 *   STRICTLY ascending by their ADDRESS SHA3-512(descriptor) (duplicates
 *   and disorder reject — one canonical encoding); the SUM of N over the
 *   leg's descriptors <= NODUS_RT_MSIG_MAX_KEYS (15, the signer ceiling
 *   — design F3.1, operator decision); the blob is consumed EXACTLY.
 *   The hook verifies the signers exactly as kind 1, then records EVERY
 *   carried descriptor's address in the verdict with a SATISFIED flag:
 *   satisfied iff at least M of the descriptor's keys are among the
 *   verified signer keys. The hook REJECTS NOTHING on satisfaction or use
 *   — whether an input is owned, and the "a carried descriptor no input
 *   uses" rule, are EXEC decisions (design F1.2; the CORE exec's one
 *   ownership predicate, nodus_witness_rt_native.c rtn_input_owned), so
 *   the descriptor bytes are always priced (w_authbyte) before any exec
 *   verdict. The descriptor bytes do NOT enter intent_id (they are
 *   authorization bytes) — auth_kind does (F1.4): the kind-1 and kind-3
 *   spellings of one transfer are two intents.
 *
 * Every other auth_kind value REJECTS (unsupported scheme, fail-closed),
 * and a runtime accepts only the kinds its allowed_auth_kinds mask
 * declares (table field below).
 * Verification work is priced by w_authbyte at reservation — the hook
 * charges nothing, so authorization is never charged twice. */
#define NODUS_RT_AUTHKIND_DSA87_MULTI_V1  ((uint8_t)1)
#define NODUS_RT_AUTHKIND_DSA87_CC_V1     ((uint8_t)2)
/** General multisig (decision 2026-09-29-general-multisig.md). NOTE the
 *  name: kind 1 is already "..._MULTI_V1" (many SIGNERS); this is the
 *  M-of-N ADDRESS scheme. */
#define NODUS_RT_AUTHKIND_DSA87_MSIG_V1   ((uint8_t)3)
/** DERIVED, not chosen: the largest signer cardinality any compiled
 *  runtime can legally require. CORE SPEND accepts up to 15 inputs
 *  (RTN_SPEND_MAX_IN, nodus_witness_rt_native.c — the mediated-read
 *  budget), and every input may be owned by a DISTINCT signer, so the
 *  scheme must represent 15; SYSTEM's operations need only an ordinary
 *  submitter (1). One signer covering several owned inputs needs no
 *  duplicate signature (ownership matches any verified fp), so 15 is
 *  the exact structural maximum, not a headroom guess. */
#define NODUS_RT_AUTH_MAX_SIGNERS         15
#define NODUS_RT_AUTH_SIGNER_LEN          (2592u + 4627u)   /* pk ‖ sig  */
/** One kind-2 approval: snapshot_index u16 BE ‖ ML-DSA-87 signature. */
#define NODUS_RT_AUTH_APPROVAL_LEN        (2u + 4627u)
/** auth_kind 3: the most descriptor KEYS one leg may carry (Σ N over its
 *  descriptors) — the signer ceiling, operator decision 2026-09-29
 *  (design §7 rev 2, F3.1: 15 descriptors × 15 keys would not fit the
 *  1 MiB envelope; bounding the SUM keeps the worst case derived —
 *  nodus_witness_rt_native.c capacity asserts). */
#define NODUS_RT_MSIG_MAX_KEYS            NODUS_RT_AUTH_MAX_SIGNERS
/** auth_kind 3: the most descriptors one leg may carry — DERIVED, not
 *  chosen: Σ N <= 15 with every N >= DNA_MSIG_MIN_N (2) gives at most
 *  floor(15 / 2) = 7 (msig_wire.h; pinned in rt_native.c). */
#define NODUS_RT_MSIG_MAX_DESC            7
/** Per-runtime auth-kind allowlist bits (allowed_auth_kinds). */
#define NODUS_RT_AUTHKIND_BIT(k)          ((uint32_t)1u << (k))

/** The ENGINE-resolved governing committee snapshot view handed to the
 *  authorization hook for kind-2 legs (ctx->committee). Engine-owned,
 *  borrowed for the call; built ONCE per block from
 *  nodus_committee_get_for_block at the governing height (H-1) — a
 *  transaction can neither carry nor select it. count == 0 means the
 *  chain has no committee (a deterministic parse-level REJECT for any
 *  kind-2 leg, never a fault). */
typedef struct {
    uint32_t count;                /* members; 0 = no committee          */
    uint64_t epoch;                /* nodus_v2_epoch_for_height(H-1)     */
    uint8_t  set_hash[64];         /* "NDS.CCSET.v1" resolved-set hash   */
    const uint8_t *pubkeys;        /* count × 2592, contiguous           */
    const uint8_t (*fps)[64];      /* count × SHA3-512(pubkey)           */
    /* HF-2 (GW-1): count × the member's VOTING POWER, in seat order —
     * floor(total_stake / DNAC_DECIMAL_UNIT), the SAME derivation the
     * block-commit validator set uses (nodus_witness_cmt_app.c, the
     * FinalizeBlock validator-update loop). Filled for every non-empty
     * view; the auth hook sums it into the verdict whether or not HF-2
     * is active, and the SYSTEM exec reads the sums only when it is. */
    const uint64_t *powers;
} nodus_rt_committee_t;

/** The engine-owned verdict of ONE leg's verified authorization. Only
 *  the engine writes it (through the resolved auth hook); runtimes read
 *  it through ctx->auth. Kind 1 leaves the approval AND multisig fields
 *  ZERO; kind 2 fills the approval fields from the verified committee
 *  evidence; kind 3 fills the multisig fields (F1.1: the verdict carries
 *  the multisig decision, so exec binds to the verdict and never to
 *  envelope bytes). */
typedef struct {
    uint16_t n_signers;                  /* 1..NODUS_RT_AUTH_MAX_SIGNERS */
    uint8_t  signer_fp[NODUS_RT_AUTH_MAX_SIGNERS][64]; /* SHA3-512(pk)   */
    /* capacity season — committee approval evidence (kind 2 only):      */
    uint16_t n_approvals;                /* verified DISTINCT approvals  */
    uint16_t committee_n;                /* resolved committee size the
                                          * approvals verified against   */
    /* general multisig (kind 3 only): EVERY carried descriptor, in wire
     * order (= strictly ascending address). 0 for kinds 1 and 2. */
    uint16_t n_msig;                     /* 0..NODUS_RT_MSIG_MAX_DESC    */
    uint8_t  msig_satisfied[NODUS_RT_MSIG_MAX_DESC];  /* 1 = >= M of its
                                          * keys are verified signers    */
    uint8_t  msig_addr[NODUS_RT_MSIG_MAX_DESC][64];   /* SHA3-512(desc)  */
    /* HF-2 (GW-1), kind 2 only — checked u64 sums over the committee
     * view's `powers`: the VERIFIED approving seats, and every seat (both
     * 0 when the sum is unweighable). 0 for kinds 1 and 3. Never hashed,
     * stored or put on a wire — the SYSTEM CHAIN_CONFIG exec's approval
     * rule reads them from HF-2 on. Placed LAST: the members above end at
     * 1 423 B, already padded to 1 424 = 8-aligned, so the two u64s grow
     * the struct by exactly 16 B (sizeof 1 440 — pinned in
     * nodus_witness_v2_apply.h, whose per-envelope scratch cost reads it). */
    uint64_t approved_power;
    uint64_t committee_power;
} nodus_rt_auth_verdict_t;

/** The engine-owned execution context for one leg. Every pointer is a
 *  BORROWED engine buffer, valid for the hook call only. All identity
 *  material is ENGINE-DERIVED (env_preflight.h): both identities and
 *  the two commitments are derived from the envelope bytes + chain
 *  identity + contextual rulesets — a runtime can bind to them but can
 *  never choose, return or override them (the effect/result codec
 *  cannot carry an identity, which is the point). `auth` is the
 *  ENGINE-owned VERIFIED verdict of this leg's authorization (native
 *  auth season): NULL only while the auth hook itself runs; non-NULL
 *  for read_plan/exec, whose ownership / authority decisions MUST bind
 *  to it and to nothing carried by the envelope bytes.
 *
 *  IDENTITY SELECTION RULE (intent season): `wire_id` is the FULL-WIRE
 *  identity (commits authorization bytes — different valid witnesses,
 *  different wire_id); `intent_id` is the canonical WITNESS-INDEPENDENT
 *  identity. Anything a runtime persists into CONSENSUS STATE (rows
 *  that feed a state root, provenance columns, replay-relevant records)
 *  MUST use intent_id; wire_id exists for wire/audit binding only. The
 *  former ambiguous `tx_id` member is deliberately RENAMED so no hook
 *  can select a provenance identity without naming its semantics. */
typedef struct {
    const uint8_t *chain_id;              /* [DNA_CHAIN_ID_LEN]           */
    uint64_t       global_height;         /* the block being applied      */
    uint64_t       epoch;                 /* DERIVED from global block
                                           * count — never wall clock     */
    const uint8_t *wire_id;               /* [64] engine-derived FULL-WIRE
                                           * identity (frozen tx_id
                                           * preimage)                    */
    const uint8_t *intent_id;             /* [64] engine-derived canonical
                                           * intent identity — the ONLY
                                           * identity consensus-state
                                           * provenance may commit        */
    const uint8_t *auth_context_commit;   /* [64] derived commitment      */
    const uint8_t *leg_auth_digest;       /* [64] this leg's derived
                                           * commitment                   */
    const nodus_rt_auth_verdict_t *auth;  /* engine-VERIFIED verdict      */
    /* capacity season: the ENGINE-resolved governing committee snapshot
     * view (type doc above). Non-NULL exactly while the AUTH hook of a
     * leg whose auth_kind needs it runs (kind 2); NULL everywhere else —
     * read_plan/exec consume committee FACTS only through the verdict
     * (n_approvals / committee_n, and since HF-2 approved_power /
     * committee_power), never the raw snapshot. */
    const nodus_rt_committee_t *committee;
    /* Final pre-testnet wipe W-C (decision 2026-09-28-token-create-fee-
     * governance.md): the COMMITTED chain_config param 6
     * (TOKEN_CREATE_FEE_RAW) active at `global_height`, read by the
     * ENGINE (nodus_witness_v2_apply.c env_token_create_fee — the gas
     * price's read discipline: a read fault is a node FAULT, never a
     * default) and handed in, because the hooks are pure and touch no
     * database. With no row active it is the compiled
     * NODUS_W_TOKEN_CREATE_FEE. Filled on every ctx the engine builds
     * (auth stage and read_plan/exec); the CORE TOKEN_CREATE exec is its
     * one consumer (rtn_tc_exec: fee >= this). A hook never chooses it. */
    uint64_t       token_create_fee;
    /* HF-2 (design docs/plans/2026-09-30-gov-weight-netzero-design.md
     * rev 2): 1 when the COMMITTED chain_config param 7 (HF2_ACTIVE) is
     * active at `global_height`, else 0. Read by the ENGINE with the same
     * discipline as token_create_fee (nodus_witness_v2_apply.c
     * env_hf2_active: a read fault is a node FAULT, never a default) and
     * filled on every ctx it builds. One consumer: the SYSTEM
     * CHAIN_CONFIG exec, which weighs approvals by voting power while it
     * is 1 and by seat count while it is 0. A hook never chooses it. */
    uint8_t        hf2_active;
    /* HF-4 (design docs/plans/2026-10-02-onchain-names-design.md rev 4
     * §1.2 rule (a)): 1 when ANY chain_config param-9 (RULESET_GEN2) row
     * exists, at any effective height, else 0. Filled by the ENGINE
     * (nodus_witness_v2_apply.c env_ruleset_gen2_voted) on every ctx it
     * builds, re-read per item so a row an earlier item of the SAME block
     * wrote counts; an unreadable answer is a node FAULT, never a
     * default. UNMETERED by design: it is not a mediated read, so the
     * CHAIN_CONFIG read plan stays empty and no committed block's
     * gas_used moves. One consumer: the SYSTEM CHAIN_CONFIG exec's
     * single-use rule (nodus_chain_config_stateful_rules). */
    uint8_t        ruleset_gen2_voted;
    /* HF-4 (design §2 Price): the four NAME_REGISTER price tiers at
     * `global_height` — [0] = chain_config param 10 (NAME_PRICE_3P) …
     * [3] = param 13 (NAME_PRICE_6P), each the committed row active at
     * that height or the compiled DNAC_NAME_PRICE_*_DEFAULT. RAW values:
     * the monotonic fold is dnac_name_price_for_len (dnac.h), applied by
     * the consumer. Filled by the ENGINE on every ctx it builds
     * (nodus_witness_v2_apply.c env_name_prices — an unreadable row is a
     * node FAULT, never a default). One consumer: the CORE NAME_REGISTER
     * exec. A hook never chooses it. */
    uint64_t       name_price[4];
    /* Nodus EVM (design §10): the block being applied's Comet header time in
     * SECONDS (`blk->timestamp`, nodus_witness_cmt_app.c FinalizeBlock)
     * and the EVM block gas limit in force at `global_height` (chain_config
     * param 15 EVM_BLOCK_GAS_LIMIT, nodus_witness_v2_evm_block_gas_limit
     * in nodus_witness_v2_apply.c). Filled by the ENGINE on the
     * execution ctx (exec_one_env); the authorization stage's ctx carries
     * the gas limit and block_time_s 0 (no auth hook reads either).
     * Consumed only by an ABI-2 runtime's block environment (TIMESTAMP /
     * GASLIMIT). A hook never chooses them. */
    uint64_t       block_time_s;
    uint64_t       evm_block_gas_limit;
    /* Nodus EVM activation (design §9): three more UNMETERED engine facts the
     * SYSTEM CHAIN_CONFIG exec's stateful rules read for the EVM_ACTIVE
     * vote (nodus_chain_config_stateful_rules_ex) — the HF-2 shape:
     *   hf3_active       1 when chain_config param 8 is active at
     *                    global_height (nodus_witness_v2_apply.c
     *                    env_hf3_active);
     *   gas_price_on     1 when a NON-ZERO param-5 (GAS_PRICE_RAW_PER_UNIT)
     *                    row is active at global_height;
     *   evm_active_voted 1 when ANY param-14 (EVM_ACTIVE) row exists, at
     *                    any effective height (the param-9 single-use read).
     * Filled by the engine on every ctx it builds; an unreadable answer is
     * a node FAULT, never a default. No other hook reads them. */
    uint8_t        hf3_active;
    uint8_t        gas_price_on;
    uint8_t        evm_active_voted;
    /* Red-team 1 F5: the chain's FIRST block height (the genesis document's
     * initial_height, completed 0 → 1 — nodus_witness_v2_chain_initial_
     * height, cached once per open), the fact the EVM_ACTIVE stateful rule
     * (g) reads. Filled by the engine like the three above; 0 = not
     * derived, which refuses the EVM_ACTIVE vote (fail closed). Read only
     * by the SYSTEM CHAIN_CONFIG exec. */
    uint64_t       chain_initial_height;
} nodus_rt_exec_ctx_t;

/* ── Nodus EVM: the runtime-ABI-2 execution boundary (design §3, §4, §7) ────
 *
 * VALUES PENDING THE MEASUREMENT GATE (design §8): the two gas bounds
 * below are compiled placeholders until the Faz 3 measurement derives
 * them; the activation package replaces the block limit by chain_config
 * param 15 (EVM_BLOCK_GAS_LIMIT). */
/** Largest gas_limit one EVM leg may declare (design §4 EVM_TX_GAS_CAP). */
#define NODUS_RT_EVM_TX_GAS_CAP          30000000ull
/** The block environment's GASLIMIT until param 15 exists. */
#define NODUS_RT_EVM_BLOCK_GAS_LIMIT     30000000ull
/** NODE-LOCAL, NOT a consensus value (design §18 rev 5, §8): the gas the
 *  §18 RPC simulations (evm_call / evm_estimate) of ONE node may spend per
 *  committed tip height — the budget resets when the tip moves; no clock.
 *  It never enters the activation digest's constant list (evm_act_consts,
 *  the D literal) and no block, vote or root reads it. A compiled
 *  placeholder pending the measurement gate. */
#define NODUS_RT_EVM_SIM_GAS_PER_HEIGHT  (2ull * NODUS_RT_EVM_TX_GAS_CAP)
/** Logical-read cap of one leg (design §3 EVM_MAX_READS):
 *  ceil(EVM_TX_GAS_CAP / 2100) + 2 × access-list keys + 2048. The engine
 *  evaluates it with the leg's own access-list key count. */
#define NODUS_RT_EVM_READS_BASE \
    ((NODUS_RT_EVM_TX_GAS_CAP + 2099ull) / 2100ull + 2048ull)
/** Read-byte cap of one leg (design §3 EVM_MAX_READ_BYTES) — a compiled
 *  placeholder pending the measurement gate. */
#define NODUS_RT_EVM_MAX_READ_BYTES      (32ull * 1024ull * 1024ull)

/** The reader op the ENGINE serves itself (never the runtime's adapter):
 *  BLOCKHASH(n), key = n as u64 BE. Window [H-256, H-1] of the block H
 *  being applied, from v2_blocks.block_id[0..32]; outside the window the
 *  answer is present = 0; a window height with no row is a node FAULT.
 *  Every other op id is a compiled adapter op of the leg's runtime and is
 *  served through nodus_witness_v2_read_one. */
#define NODUS_RT_V2_OP_BLOCKHASH         0x80000001u

/** Reader status: the deterministic host-work verdict (design §3 BUDGET). */
#define NODUS_RT_V2_READ_BUDGET          (-3)

/**
 * The engine-owned READER an ABI-2 runtime pulls committed state through.
 * Every logical (op, key) is charged ONCE per leg, BEFORE it is read
 * (design §3 I2): the first request charges w_read and caches the answer,
 * every repeat of the same (op, key) in the same leg is served from the
 * cache for free. The runtime never sees the witness handle, the database
 * or the meter.
 */
typedef struct nodus_rt_v2_reader {
    void *ctx;
    /** @return 0 with *res filled (present 0/1, a MISSING row is a
     *  successful read with present 0), NODUS_RT_V2_READ_BUDGET (-3, the
     *  deterministic budget verdict: the read count / byte caps or the
     *  leg's units are exhausted — nothing was read), or -2 node FAULT. */
    int (*read)(void *ctx, uint32_t op, const uint8_t *key, uint16_t key_len,
                nodus_rt_read_res_t *res);
    /** Declare the leg's EVM gas before anything executes (design §4
     *  pre-validation): gas_limit <= NODUS_RT_EVM_TX_GAS_CAP and
     *  res_max_total_units >= static units + gas_limit × w_gas +
     *  FAIL_RESERVE. Fixes the leg's read cap from `n_access_keys`.
     *  @return 0 accepted, -1 refused (deterministic), -2 fault. */
    int (*declare_gas)(void *ctx, uint64_t gas_limit, uint64_t n_access_keys);
} nodus_rt_v2_reader_t;

/** One EVM log of a successful leg, for the node-local log index (design
 *  §7). Every pointer is runtime-owned (released with the out). */
typedef struct {
    const uint8_t *addr;                  /* 32 bytes                     */
    uint8_t        n_topics;              /* 0..4                         */
    const uint8_t *topics;                /* n_topics × 32 bytes          */
    const uint8_t *data;
    uint32_t       data_len;
} nodus_rt_v2_log_t;

/**
 * What an ABI-2 leg hands back (design §4). Every pointer is
 * RUNTIME-OWNED and stays valid until `release(out)`; the engine calls
 * release exactly once whatever the leg's return code.
 *
 *   success == 1: `effects` is the leg's whole change set as ONE canonical
 *     stream — strictly ascending by (op_id, key) over the whole stream,
 *     every logical key once — which the engine applies in pages.
 *   success == 0: execution failed (REVERT / out of gas / any exceptional
 *     halt / BUDGET): only `fail_effects` (the fixed failure-result
 *     effects, sender nonce + 1) are applied.
 *   failable: 1 when a deterministic over-ceiling of the success stream
 *     takes the failure path (CALL / CREATE — the leg executed, so it is
 *     applied and pays); 0 when it is a refusal (-1) instead (the bridge
 *     ops, which execute no code — design §4).
 *   gas_limit / gas_used: EVM gas, the units the engine charges
 *     (× DNA_METER_EVM_W_GAS) — gas_used on success, gas_limit on the
 *     failure path. 0 / 0 for the bridge ops.
 *   receipt / fail_receipt: the canonical receipt encodings of the two
 *     outcomes (design §7); the engine hashes the one it applies into
 *     ExecTxResult.Data and keeps the bytes in its node-local index.
 */
typedef struct nodus_rt_v2_out {
    uint8_t                  success;
    uint8_t                  failable;
    const dna_effect_in_t   *effects;
    uint32_t                 n_effects;
    const dna_effect_in_t   *fail_effects;
    uint32_t                 n_fail_effects;
    uint64_t                 gas_limit;
    uint64_t                 gas_used;
    const uint8_t           *receipt;
    size_t                   receipt_len;
    const uint8_t           *fail_receipt;
    size_t                   fail_receipt_len;
    const nodus_rt_v2_log_t *logs;
    uint32_t                 n_logs;
    void                    *priv;
    void                   (*release)(struct nodus_rt_v2_out *out);
} nodus_rt_v2_out_t;

/**
 * Verified authorization of one leg. Parses the leg's auth_data under
 * its auth_kind, verifies every signature against the ENGINE-derived
 * ctx->leg_auth_digest, and fills the verdict. PURE: no witness, no
 * database, no clock, no RNG — the only inputs are the borrowed
 * envelope view and the engine context, so two nodes produce the same
 * verdict for the same bytes.
 * @return 0 verified (out filled); -1 deterministic REJECT (unsupported
 * scheme, malformed layout, zero/duplicate/disordered pubkey, any
 * signature invalid — out zeroed); -2 NODE FAULT (hash backend failure
 * — never converted into a verdict).
 */
typedef int (*nodus_rt_auth_fn)(const struct nodus_domain_runtime *rt,
                                const dna_env_view_t *env,
                                uint16_t leg_index,
                                const nodus_rt_exec_ctx_t *ctx,
                                nodus_rt_auth_verdict_t *out);

/**
 * Deterministic mediated-read REQUEST phase for one leg. Emits at most
 * `max_reqs` typed requests (strictly ascending by (op_id, key) under
 * the effect-wire key order — duplicates and disorder are engine
 * rejects). NULL = the runtime reads nothing. The request list must be
 * a pure function of (envelope bytes, leg, ctx) — it runs before any
 * storage is touched. @return 0 with *n_out set, -1 = this leg is not
 * plannable under the domain's rules (a deterministic VERDICT), -2 =
 * NODE FAULT (a hook-internal backend failure — the engine fails its
 * own operation, it never converts -2 into a verdict).
 */
typedef int (*nodus_rt_read_plan_fn)(const struct nodus_domain_runtime *rt,
                                     const dna_env_view_t *env,
                                     uint16_t leg_index,
                                     const nodus_rt_exec_ctx_t *ctx,
                                     nodus_rt_read_req_t *reqs_out,
                                     uint16_t max_reqs,
                                     uint16_t *n_out);

/**
 * Native compiled execution of one preflighted leg. Consumes the
 * borrowed envelope view, the engine context and the bounded mediated
 * read results; produces ONLY canonical "NDS.EFFRES.v1" result bytes in
 * the engine's buffer (strictly decoded and validated by the engine
 * before anything is charged or applied). It must not return SQL, a
 * domain id, weights, table names, roots, a transaction identity, or
 * callback addresses — the result codec cannot carry any of them, which
 * is the point. @return 0 with *res_len_out set, -1 = the leg is
 * rejected under the domain's rules (a deterministic VERDICT), -2 =
 * NODE FAULT (hook-internal backend failure — never a verdict).
 */
typedef int (*nodus_rt_exec_fn)(const struct nodus_domain_runtime *rt,
                                const dna_env_view_t *env,
                                uint16_t leg_index,
                                const nodus_rt_exec_ctx_t *ctx,
                                const nodus_rt_read_res_t *reads,
                                uint16_t n_reads,
                                uint8_t *res_out, size_t res_cap,
                                size_t *res_len_out);

/**
 * Nodus EVM — runtime-ABI-2 execution of one preflighted leg (design §3/§4).
 * Pure like exec: no witness, no database, no clock, no RNG — committed
 * state arrives ONLY through `reader`, every read engine-charged.
 * @return 0 with *out filled (an APPLIED outcome: success or the fixed
 * failure path), -1 the leg is refused BEFORE anything executed (call
 * decode, pre-validation, a bridge-op rule — the whole item rolls back,
 * nothing is paid), -2 node FAULT (a reader fault, an engine invariant —
 * never a verdict). On every return the engine calls out->release when it
 * is set.
 */
typedef int (*nodus_rt_exec_evm_fn)(const struct nodus_domain_runtime *rt,
                                    const dna_env_view_t *env,
                                    uint16_t leg_index,
                                    const nodus_rt_exec_ctx_t *ctx,
                                    const nodus_rt_v2_reader_t *reader,
                                    nodus_rt_v2_out_t *out);

/** Nodus EVM (design §8 "Recheck: VM YÜRÜTÜLMEZ"): the mempool CONFLICT KEYS
 *  of one ABI-2 leg — synthetic row identities, never the leg's effect
 *  rows. At most two; each (op_id, key) is in the runtime's own
 *  namespace and the dry run files it under the leg's domain. */
#define NODUS_RT_V2_MAX_KEYS     2u
#define NODUS_RT_V2_KEY_MAX_LEN  72u
typedef struct {
    uint8_t n;
    struct {
        uint32_t op_id;
        uint16_t key_len;
        uint8_t  key[NODUS_RT_V2_KEY_MAX_LEN];
    } k[NODUS_RT_V2_MAX_KEYS];
} nodus_rt_v2_keys_t;

/**
 * Nodus EVM — the ONE shared PRE-VALIDATION of a runtime-ABI-2 leg (design §4
 * "Ön doğrulama", §8 recheck): the call decode, the envelope pairing, the
 * gas declaration and every cheap state-dependent check (nonce == the
 * committed nonce, value <= balance, intrinsic gas, ticket present, …) —
 * NOTHING executes. exec_evm runs exactly this function first; CheckTx
 * (a NEW entry and its RECHECK alike — red-team 1 F1) runs only this.
 * Pure like exec_evm (reads only through
 * `reader`). `keys` (may be NULL) receives the leg's conflict keys.
 * @return 0 valid, -1 refused (deterministic), -2 node fault.
 */
typedef int (*nodus_rt_prevalidate_fn)(const struct nodus_domain_runtime *rt,
                                       const dna_env_view_t *env,
                                       uint16_t leg_index,
                                       const nodus_rt_exec_ctx_t *ctx,
                                       const nodus_rt_v2_reader_t *reader,
                                       nodus_rt_v2_keys_t *keys);

/** Domain state root — the runtime OWNS its state-root composition; the
 *  generic executor consumes the 64-byte result as an OPAQUE value.
 *  @return 0 with out_root filled, -1 fail-closed. */
typedef int (*nodus_rt_root_fn)(const struct nodus_domain_runtime *rt,
                                struct nodus_witness *w,
                                uint8_t out_root[64]);

/** One admitted distribution claim, as handed to the TARGET runtime.
 *  Every field is committed data — the generic engine derived it from
 *  the committed manifest + verified claim, never from a default. */
typedef struct {
    const uint8_t *nullifier;       /* [64] committed claim identity      */
    const uint8_t *dest_binding;    /* [64] SHA3-512(recipient pk)        */
    uint64_t       amount;          /* converted, target-domain units     */
    const uint8_t *asset_ref;       /* committed target_asset_ref         */
    uint16_t       asset_ref_len;
    uint64_t       global_height;
} nodus_rt_claim_t;

/** Validate one committed target_asset_ref for this runtime (pure —
 *  no state). Fail-closed: a runtime without this hook, or a ref it
 *  does not recognise, cannot be a distribution target. */
typedef int (*nodus_rt_asset_fn)(const struct nodus_domain_runtime *rt,
                                 const uint8_t *asset_ref, uint16_t len);

/** Apply one admitted claim INSIDE the caller's transaction: validate
 *  the asset/destination representation, create the DOMAIN-LOCAL output
 *  and return its deterministic 64-byte output identity. The generic
 *  engine never creates an output itself. @return 0 / -1. */
typedef int (*nodus_rt_claim_fn)(const struct nodus_domain_runtime *rt,
                                 struct nodus_witness *w,
                                 const nodus_rt_claim_t *claim,
                                 uint8_t out_output_id[64]);

/** Runtime-owned conservation/supply invariant over the runtime's OWN
 *  assets. The generic gate dispatches; it never sums heterogeneous
 *  domain assets into one equation. NULL = the runtime declares no
 *  asset state (e.g. SYSTEM). @return 0 holds / -1 violated or fault. */
typedef int (*nodus_rt_invariant_fn)(const struct nodus_domain_runtime *rt,
                                     struct nodus_witness *w);

/** OPTIONAL activation-time domain-state initialization (Ledger V2
 *  S7): runs INSIDE the caller's transaction BEFORE the activation
 *  state/payload roots are evaluated, both at V2 genesis (before the
 *  registry commits genesis_state_root) and inside the canonical
 *  activation constructor — so the committed genesis root and the
 *  activation comparison see the SAME initialized state. MUST be
 *  idempotent-or-conflict (an activation calls it after the genesis
 *  path already ran it). NULL = the runtime initializes no state. The
 *  CORE implementation creates the configured native shielded pool
 *  (nodus_witness_v2_pools.c). @return 0 / -1 (fail-closed). */
typedef int (*nodus_rt_state_init_fn)(const struct nodus_domain_runtime *rt,
                                      struct nodus_witness *w,
                                      uint64_t activation_global_height);

typedef struct nodus_domain_runtime {
    /* ── identity tuple (ALL five axes must match exactly) ──────────── */
    uint32_t domain_id;
    uint8_t  runtime_kind;               /* DNA_RUNTIME_NATIVE_BUILTIN    */
    uint32_t runtime_abi;                /* NODUS_DOMAIN_RUNTIME_ABI_V1   */
    uint32_t ruleset_version;
    uint8_t  ruleset_hash[DNA_DOM_HASH_LEN];  /* pinned descriptor digest */
    /* HF-4: the rule-set GENERATION this entry belongs to (NODUS_RT_GEN_*;
     * 1 = genesis). NOT an identity axis and not hashed anywhere — the
     * exact five-axis tuple above is what resolves a runtime; this field
     * says which compiled generation the resolved entry is. Synthetic
     * test runtimes leave it 0, which every "generation >= 2" gate reads
     * as "not generation 2" (the fail-closed direction). */
    uint32_t generation;
    /* ── checked-in canonical descriptor the digest is recomputed from ─ */
    dna_ruleset_desc_t descriptor;
    /* ── function table ─────────────────────────────────────────────── */
    nodus_rt_admit_fn admit;
    nodus_rt_cost_fn  tx_cost;
    /* The verified AUTHORIZATION boundary (native auth season). The
     * engine invokes it BEFORE any execution or mutation; a leg whose
     * auth hook is absent or does not return 0 fails closed. */
    nodus_rt_auth_fn      auth;
    /* Per-runtime auth-kind ALLOWLIST (capacity season): bit k set =
     * this runtime's legs may carry auth_kind k
     * (NODUS_RT_AUTHKIND_BIT). Enforced by the engine's pre-BEGIN
     * admission scan BEFORE any authorization work, so a runtime that
     * never consumes committee approvals (CORE) cannot be made to carry
     * — and its blocks cannot be made to pay for — a 128-approval blob:
     * the worst-case LEGAL envelope stays exactly the enumerated shapes
     * the DNA_ENV_MAX_TOTAL_LEN derivation contains. 0 is INVALID
     * (selfcheck rejects a runtime that accepts no kind). SYSTEM
     * declares {1,2}; CORE declares {1,3} (general multisig, CORE v4 —
     * pinned by nodus_witness_runtime_selfcheck). */
    uint32_t              allowed_auth_kinds;
    /* The typed EXECUTION boundary (header block above). Native auth
     * season installed the real hooks; the burn season completed the
     * transparent CORE set; O11 opened the staking lane. Executable
     * today — SYSTEM: the whole stake lifecycle DNA_SYSRULE_STAKE /
     * DELEGATE / UNSTAKE / UNDELEGATE (1..4) + DNA_SYSRULE_CHAIN_CONFIG;
     * DNA_CORE: DNA_CORERULE_SPEND + DNA_CORERULE_BURN +
     * DNA_CORERULE_TOKEN_CREATE + DNA_CORERULE_SYSFUND. Every other
     * owned runtime_op (SYSTEM 5, CORE 4..6) is a deterministic reject
     * inside the hooks until its own migration slice. NULL exec = this
     * runtime cannot execute envelope legs (engine fails the leg
     * closed); NULL read_plan = it reads nothing. */
    nodus_rt_read_plan_fn read_plan;
    nodus_rt_exec_fn      exec;
    /* Nodus EVM: the runtime-ABI-2 execution hook (typedef above). Present
     * exactly when runtime_abi == NODUS_DOMAIN_RUNTIME_ABI_V2, and then
     * read_plan and exec are NULL (nodus_runtime_hooks_check). NULL in
     * every ABI-1 entry — the generation-1/2 tables leave it zero. */
    nodus_rt_exec_evm_fn  exec_evm;
    /* Nodus EVM: the ABI-2 shared pre-validation (typedef above). Present
     * exactly when runtime_abi == NODUS_DOMAIN_RUNTIME_ABI_V2
     * (nodus_runtime_hooks_check); NULL in every ABI-1 entry. */
    nodus_rt_prevalidate_fn prevalidate_evm;
    nodus_rt_root_fn      state_root;    /* domain state root (S5/S6)     */
    /* OPTIONAL activation payload root: the value compared against the
     * registry-committed genesis_state_root when this domain's
     * DomainHead is created at ACTIVATION. NULL = the state root itself
     * (the generic case — a runtime whose state root contains no
     * self-referencing container legs). SYSTEM sets it to the
     * "NDS.SYSPAYL.v3" payload root (the S5 genesis cycle break; W-A
     * appended the treasury leg, nodus_witness_roots_v2.c) — the
     * ONE protocol-special composition, kept inside SYSTEM's runtime
     * entry so the generic engine never branches on a domain id. */
    nodus_rt_root_fn      payload_root;
    nodus_rt_asset_fn     asset_check;   /* NULL = never a claim target   */
    nodus_rt_claim_fn     claim_apply;   /* NULL = never a claim target   */
    nodus_rt_invariant_fn invariant;     /* NULL = no asset state         */
    nodus_rt_state_init_fn state_init;   /* NULL = no activation state    */
    /* Compiled storage adapter (Ledger V2 typed-effect boundary,
     * nodus_witness_v2_adapter.h). Registered HERE so an adapter resolves
     * only through the five-axis exact-tuple lookup — never through a
     * second caller-controlled path. Native auth season: BOTH production
     * entries carry their compiled adapter (selfcheck enforces presence
     * + adapter selfcheck, replacing the pre-migration all-NULL rule). */
    const struct nodus_domain_adapter *adapter;
    /* OPTIONAL committed metering policy (header block above). Presence
     * is COUPLED to the descriptor: meter_policy != NULL exactly when
     * descriptor.meter_policy_digest is non-zero, and the policy's
     * dna_meter_policy_digest MUST equal that committed digest —
     * selfcheck and the engine snapshot both enforce it. The SYSTEM
     * entry carries THE block policy; no caller and no envelope can
     * substitute another. */
    const dna_meter_policy_t *meter_policy;
} nodus_domain_runtime_t;

/**
 * Exact-tuple lookup in a caller-supplied table (test-extensibility
 * surface — a test-only third runtime lives in a TEST table, never in the
 * production one). Every axis must match byte-exactly; the first failure
 * axis is not reported — a miss is a miss (fail-closed).
 * @return the entry or NULL.
 */
const nodus_domain_runtime_t *
nodus_runtime_lookup_in(const nodus_domain_runtime_t *table, size_t n,
                        uint32_t domain_id, uint8_t runtime_kind,
                        uint32_t runtime_abi, uint32_t ruleset_version,
                        const uint8_t ruleset_hash[DNA_DOM_HASH_LEN]);

/** Exact-tuple lookup across EVERY compiled generation of the production
 *  table (HF-4: a tuple names at most one entry — selfcheck enforces
 *  exact-tuple uniqueness). @return the entry or NULL. */
const nodus_domain_runtime_t *
nodus_runtime_lookup(uint32_t domain_id, uint8_t runtime_kind,
                     uint32_t runtime_abi, uint32_t ruleset_version,
                     const uint8_t ruleset_hash[DNA_DOM_HASH_LEN]);

/** The GENESIS generation of the compiled production table (generation
 *  1: SYSTEM then DNA_CORE — exactly the two entries every pre-HF-4
 *  consumer saw). Genesis seeding, the pre-registry supply walk and the
 *  test fixtures read THIS; it is never a lookup surface for a committed
 *  tuple (use nodus_runtime_lookup / nodus_runtime_all_table, which see
 *  every generation). @param n_out receives the entry count (2). */
const nodus_domain_runtime_t *nodus_runtime_builtin_table(size_t *n_out);

/** HF-4: EVERY compiled entry of every generation, generation-major
 *  (generation 1 SYSTEM, generation 1 CORE, generation 2 SYSTEM, …) —
 *  the table exact-tuple resolution of a COMMITTED registry tuple walks
 *  (nodus_witness_v2_runtime_for with no test override).
 *  @param n_out receives the entry count. */
const nodus_domain_runtime_t *nodus_runtime_all_table(size_t *n_out);

/** HF-4: the number of compiled generations (generation ids are
 *  1..count, contiguous). */
uint32_t nodus_runtime_generation_count(void);

/** HF-4: one generation's contiguous slice of the production table
 *  (SYSTEM then DNA_CORE). @return NULL for an unknown generation. */
const nodus_domain_runtime_t *
nodus_runtime_generation_table(uint32_t generation, size_t *n_out);

/** HF-4: the (domain, generation) entry — the replacement for every
 *  "first entry whose domain matches" lookup. @return the entry or NULL. */
const nodus_domain_runtime_t *
nodus_runtime_for_generation(uint32_t generation, uint32_t domain_id);

/**
 * Self-check of the production table, fail-closed:
 *   - every entry's pinned ruleset_hash equals a FRESH
 *     dna_ruleset_desc_hash of its checked-in descriptor;
 *   - allowed_auth_kinds is non-zero, names only compiled kinds (1/2/3),
 *     and matches the configured shape exactly: SYSTEM {1,2}, CORE {1,3}
 *     (general multisig, CORE v4);
 *   - descriptor identity fields (domain_id / runtime_abi /
 *     ruleset_version) equal the entry's tuple fields;
 *   - runtime_kind is NATIVE_BUILTIN;
 *   - admit, tx_cost and state_root are present; auth, read_plan, exec
 *     and adapter are ALL PRESENT (native auth season: both production
 *     runtimes own executable operations, so a missing execution or
 *     authorization hook is a broken table) and the compiled adapter
 *     passes nodus_adapter_selfcheck; asset_check and claim_apply are
 *     present or absent
 *     TOGETHER (a runtime is a claim target only when it can both
 *     validate the asset and create the output);
 *   - metering-policy coupling: meter_policy present exactly when the
 *     descriptor's meter_policy_digest is non-zero; a present policy
 *     passes dna_meter_policy_check AND its dna_meter_policy_digest
 *     equals the descriptor-committed digest byte-exactly; the SYSTEM
 *     entry (the block-policy authority) carries one, DNA_CORE carries
 *     none — the exact configured shape, like the entry list itself;
 *   - exactly the CONFIGURED native runtimes (initially SYSTEM and
 *     DNA_CORE) are present, ascending by domain_id.
 * HF-4 (design docs/plans/2026-10-02-onchain-names-design.md rev 4 §1.1)
 * adds, over the generation list:
 *   - every exact tuple names ONE entry (no tuple in two generations);
 *   - every generation has exactly one SYSTEM and one CORE entry, and
 *     generation ids are 1..count with no gap;
 *   - per domain, ruleset_version strictly increases with generation,
 *     and runtime_kind / runtime_abi never change across generations
 *     (the switch copies them, §1.4);
 *   - generation 1 equals today's literals (SYSTEM v6 + 8f1f9cb2… policy,
 *     CORE v4) — the genesis generation is never re-pinned;
 *   - every SYSTEM entry carries a sealed policy, and each generation's
 *     SYSTEM policy prices every rule id of that generation's SYSTEM AND
 *     CORE descriptors;
 *   - the compiled vote literal DNAC_CFG_RULESET_GEN2_D2 re-derives from
 *     the generation-2 pins (dna_ruleset_gen_digest).
 * @return 0 healthy, -1 on the first violation.
 */
int nodus_witness_runtime_selfcheck(void);

/**
 * Nodus EVM (design §3): the execution-surface shape of ONE entry, by its
 * runtime ABI — the check nodus_witness_runtime_selfcheck runs on every
 * production entry, exported so a test table's entries (the EVM runtime)
 * are held to the same rule:
 *   ABI 1: auth, read_plan and exec present, exec_evm and
 *          prevalidate_evm NULL;
 *   ABI 2: auth, exec_evm and prevalidate_evm present, read_plan and
 *          exec NULL;
 *   both:  a compiled adapter that passes nodus_adapter_selfcheck, and a
 *          state_root hook;
 *   any other ABI: refused.
 * For the generation-1/2 entries (ABI 1, exec_evm NULL by omission) this
 * is exactly the presence check selfcheck ran before Nodus EVM.
 * @return 0 healthy, -1 broken.
 */
int nodus_runtime_hooks_check(const nodus_domain_runtime_t *rt);

/**
 * The initial DomainManifest of one compiled entry (pure): version 1, the
 * entry's domain / name / kind / abi / ruleset version + hash / tx types,
 * genesis_state_root = `genesis_payload_root`, fee policy GLOBAL_BURN,
 * quotas 0, upgrade authority CHAIN_CONFIG, activation_epoch 0, readiness
 * STAGED_V1. The ONE builder: the genesis registry (domreg_init_genesis),
 * the EVM edge (phase 6b'') and the EVM activation digest (selfcheck)
 * all use it. (Moved here verbatim from nodus_witness_domreg.c's
 * manifest_from_runtime by the Nodus EVM activation package.)
 */
void nodus_runtime_manifest_init(const nodus_domain_runtime_t *rt,
                                 const uint8_t genesis_payload_root[64],
                                 dna_domain_manifest_t *m);

#ifdef NODUS_EVM_ENABLED
/**
 * Nodus EVM (design §9): the EVM GENERATION's activation digest — what the
 * EVM_ACTIVE vote must name (dnac.h DNAC_CFG_EVM_ACTIVE_D) — re-derived
 * from the compiled generation: its SYSTEM / CORE / EVM ruleset hashes,
 * the EVM manifest (genesis root = the empty EVM root), the activation
 * spec version and the compiled EVM constants. Selfcheck compares it with
 * the literal; phase 6b'' registers exactly the manifest it hashed.
 * `evm_man_out` (may be NULL) receives that manifest.
 * @return 0 / -1.
 */
int nodus_runtime_evm_activation_digest(uint64_t *d_out,
                                        dna_domain_manifest_t *evm_man_out);
#endif

/* ── Nodus EVM: the ONE call-head decoder and the ONE pairing rule ──────────
 * Pure, always compiled (this module), so every consumer reads the SAME
 * bytes the SAME way: the EVM runtime's full decoder, the CORE EVMFUND
 * hook (amount / recipient of the sibling leg), and the block gas sum of
 * PrepareProposal / ProcessProposal / FinalizeBlock (design §8 "aynı
 * ayrıştırıcı"). Design §2 call bytes, all big-endian:
 *   CALL     ver ‖ to[32] ‖ value[32] ‖ gas_limit u64 ‖ nonce u64 ‖ …
 *   CREATE   ver ‖ value[32] ‖ gas_limit u64 ‖ nonce u64 ‖ …
 *   DEPOSIT  ver ‖ amount_raw u64 ‖ nonce u64                (exact 17)
 *   WITHDRAW ver ‖ amount_raw u64 ‖ nonce u64 ‖ dest_fp[64]  (exact 81)
 *   REDEEM   ver ‖ ticket_id[64] ‖ amount_raw u64 ‖ dest_fp[64] (exact 137)
 * ONE CODEC (Nodus EVM Faz 4): the head IS shared/dnac/evm_call_wire.h's
 * dna_evm_head_t, decoded by dna_evm_call_head — the same function the
 * wallet and nodus-cli build with, so no client can disagree with the
 * node about these bytes.
 */
typedef dna_evm_head_t nodus_rt_evm_head_t;

/** Decode the fixed head of an EVM call (dna_evm_call_head). CALL /
 *  CREATE: `ver` and every field up to and including nonce present (the
 *  rest — access list, data — is the full decoder's); bridge ops: EXACT
 *  length. @return 0 / -1 malformed (unknown op, wrong ver, short / long). */
int nodus_rt_evm_call_head(uint32_t op, const uint8_t *call, size_t len,
                           nodus_rt_evm_head_t *out);

/** The role an EVM op's CORE sibling must declare: FEE for CALL /
 *  CREATE, DEPOSIT for DEPOSIT, RELEASE for WITHDRAW / REDEEM; 0 for any
 *  other op. */
uint8_t nodus_rt_evm_role_for_op(uint32_t evm_op);

/** THE pairing rule (design §2), checked by BOTH runtimes: the envelope
 *  is exactly two legs — leg 0 CORE (DNA_DOMAIN_CORE) runtime_op
 *  DNA_CORERULE_EVMFUND, leg 1 EVM (DNA_DOMAIN_EVM) — and the CORE call's
 *  `ver` is NODUS_RT_EVMFUND_CALL_VER and its role byte is
 *  nodus_rt_evm_role_for_op(leg 1's op) != 0. Anything else — an orphan
 *  leg, a third leg, a mismatched role — is -1.
 *  @return 0 paired / -1 refused. */
int nodus_rt_evm_pair_check(const dna_env_view_t *env);

/** Nodus EVM (design §8 mempool): the SYNTHETIC conflict-key ops of an EVM leg
 *  — never adapter ops, never rows (outside the adapter's op space, so a
 *  key can never alias an effect row's): (sender32 ‖ nonce u64 BE) for
 *  every nonce'd op — with the tip-nonce rule, two pending transactions of
 *  one sender carry the same nonce and collide: ONE pending per sender —
 *  and the ticket id for REDEEM. */
#define NODUS_RT_EVM_KEY_SENDER_NONCE 0x80000010u
#define NODUS_RT_EVM_KEY_TICKET       0x80000011u

/** The ONE derivation of an EVM leg's conflict keys (the dry run's full
 *  mode and its VM-less recheck, and the EVM runtime's prevalidate hook,
 *  all call it): from the call head and the leg's VERIFIED verdict
 *  (sender = signer_fp[0][0..32]). @return 0 / -1 (the head does not
 *  decode, or the verdict is not one signer). */
int nodus_rt_evm_conflict_keys(const dna_env_view_t *env, uint16_t leg,
                               const nodus_rt_auth_verdict_t *verdict,
                               nodus_rt_v2_keys_t *keys);

/** One envelope's share of the EVM BLOCK GAS SUM (design §8): for a leg
 *  naming `evm_domain` — CALL / CREATE whose head decodes: the DECLARED
 *  gas_limit; DEPOSIT / WITHDRAW / REDEEM: NODUS_RT_EVM_BRIDGE_GAS;
 *  anything else (another op, a head that does not decode): 0. Other
 *  domains' legs count 0. A failed or refused item keeps its share: the
 *  value depends on the bytes alone. Pure. */
uint64_t nodus_rt_evm_env_block_gas(const dna_env_view_t *env,
                                    uint32_t evm_domain);

/* ── Native-runtime hook implementations (witness tree) ───────────────
 * Referenced by the compiled table; implemented in
 * nodus_witness_v2_claims.c so this module stays free of witness/db
 * dependencies. These are the ONLY places that know SYSTEM's / CORE's
 * concrete state composition — the generic executor calls hooks only. */
int nodus_rt_system_state_root(const nodus_domain_runtime_t *rt,
                               struct nodus_witness *w, uint8_t out[64]);
int nodus_rt_system_payload_root(const nodus_domain_runtime_t *rt,
                                 struct nodus_witness *w, uint8_t out[64]);
int nodus_rt_core_state_root(const nodus_domain_runtime_t *rt,
                             struct nodus_witness *w, uint8_t out[64]);
int nodus_rt_core_asset_check(const nodus_domain_runtime_t *rt,
                              const uint8_t *asset_ref, uint16_t len);
int nodus_rt_core_claim_apply(const nodus_domain_runtime_t *rt,
                              struct nodus_witness *w,
                              const nodus_rt_claim_t *claim,
                              uint8_t out_output_id[64]);
int nodus_rt_core_invariant(const nodus_domain_runtime_t *rt,
                            struct nodus_witness *w);
/* S7 — implemented in nodus_witness_v2_pools.c (the CORE runtime's
 * pool policy: the configured native D=24 shielded pool). */
int nodus_rt_core_state_init(const nodus_domain_runtime_t *rt,
                             struct nodus_witness *w,
                             uint64_t activation_global_height);

/* ── Native auth season: production execution surface ─────────────────
 * Implemented in nodus_witness_rt_native.c. The shared auth hook is the
 * ONE compiled implementation of auth_kind 1 (both production entries
 * reference the same symbol — scheme verification cannot fork per
 * domain); the per-domain read_plan/exec pairs implement — today under
 * SYSTEM ruleset_version 6 (the stake lifecycle since O11) — the stake
 * lifecycle DNA_SYSRULE_STAKE / DELEGATE / UNSTAKE / UNDELEGATE and
 * DNA_SYSRULE_CHAIN_CONFIG (SYSTEM) and — today under CORE
 * ruleset_version 4 — DNA_CORERULE_SPEND, DNA_CORERULE_BURN, DNA_CORERULE_TOKEN_CREATE
 * and DNA_CORERULE_SYSFUND (DNA_CORE), and deterministically reject
 * every other owned runtime_op. The compiled adapters are exported so
 * tests can drive them directly. */
int nodus_rt_auth_dsa87_v1(const nodus_domain_runtime_t *rt,
                           const dna_env_view_t *env, uint16_t leg_index,
                           const nodus_rt_exec_ctx_t *ctx,
                           nodus_rt_auth_verdict_t *out);
/** "NDS.CCSET.v1" resolved-committee-set hash over the fps in committee
 *  (stake-ranked) order — the ONE derivation the engine, the auth hook
 *  and every signer share. Preimage: tag(16) ‖ count u16 BE ‖ count ×
 *  SHA3-512(pubkey)[64]. HONEST LABEL: this hashes the RESOLVED
 *  committee (nodus_committee_get_for_block's answer), NOT the persisted
 *  "NDS.VSET.v1" snapshot row — the bootstrap path has no row, and
 *  every honest node resolves the same members in the same order, which
 *  is what makes the value consensus-safe. @return 0 / -1. */
int nodus_rt_committee_set_hash(const uint8_t (*fps)[64], uint32_t count,
                                uint8_t out[64]);
/** "NDS.CCAPPR.v1" committee approval digest — what one committee seat
 *  signs under auth_kind 2. Preimage (154 B): tag(16) ‖
 *  leg_auth_digest(64) ‖ set_hash(64) ‖ epoch u64 BE ‖ index u16 BE,
 *  with epoch = nodus_v2_epoch_for_height(H-1) for execution height H
 *  (verbatim the engine's committee-resolution expression).
 *  @return 0 / -1. */
int nodus_rt_cc_approval_digest(const uint8_t leg_auth_digest[64],
                                const uint8_t set_hash[64],
                                uint64_t epoch, uint16_t index,
                                uint8_t out[64]);
int nodus_rt_core_read_plan(const nodus_domain_runtime_t *rt,
                            const dna_env_view_t *env, uint16_t leg_index,
                            const nodus_rt_exec_ctx_t *ctx,
                            nodus_rt_read_req_t *reqs_out,
                            uint16_t max_reqs, uint16_t *n_out);
int nodus_rt_core_exec(const nodus_domain_runtime_t *rt,
                       const dna_env_view_t *env, uint16_t leg_index,
                       const nodus_rt_exec_ctx_t *ctx,
                       const nodus_rt_read_res_t *reads, uint16_t n_reads,
                       uint8_t *res_out, size_t res_cap,
                       size_t *res_len_out);
int nodus_rt_system_read_plan(const nodus_domain_runtime_t *rt,
                              const dna_env_view_t *env, uint16_t leg_index,
                              const nodus_rt_exec_ctx_t *ctx,
                              nodus_rt_read_req_t *reqs_out,
                              uint16_t max_reqs, uint16_t *n_out);
int nodus_rt_system_exec(const nodus_domain_runtime_t *rt,
                         const dna_env_view_t *env, uint16_t leg_index,
                         const nodus_rt_exec_ctx_t *ctx,
                         const nodus_rt_read_res_t *reads, uint16_t n_reads,
                         uint8_t *res_out, size_t res_cap,
                         size_t *res_len_out);
extern const struct nodus_domain_adapter NODUS_RT_CORE_ADAPTER;
extern const struct nodus_domain_adapter NODUS_RT_SYSTEM_ADAPTER;

/* ── O15J Faz 2 — the CORE UTXO record, exported ─────────────────────
 * The exact byte length of the canonical CORE UTXO effect value. The
 * LAYOUT stays private to nodus_witness_rt_native.c (its offsets are that
 * adapter's business); what an engine-internal producer needs is the size
 * of the buffer it hands to the builder below. A _Static_assert in the .c
 * pins this name to the adapter's own RTN_UTXO_REC_LEN, so the two cannot
 * drift apart silently. */
#define NODUS_RT_CORE_UTXO_REC_LEN 284u

/**
 * Build ONE canonical CORE UTXO CREATE effect from explicit fields.
 *
 * For ENGINE-INTERNAL producers of CORE UTXOs that have no envelope leg
 * to derive the record from — today: the epoch settlement
 * (nodus_witness_v2_econ.c). The op id, the mutation kind, the
 * precondition (PRE_ABSENT) and the two lengths are the RUNTIME's, never
 * the caller's; only the row's data fields are supplied. That is what
 * keeps ONE encoder of the 284-byte record in the tree: a settlement UTXO
 * and a spend output are byte-identical in shape by construction, not by
 * a comment claiming they are.
 *
 * `value` must point at NODUS_RT_CORE_UTXO_REC_LEN writable bytes and
 * must OUTLIVE the effect and any view decoded from its encoding
 * (effect_wire.h LIFETIME RULE). `owner_fp_hex` is exactly 128
 * lowercase-hex characters and is never read past 128.
 *
 * @return 0 / -1 on a NULL argument.
 */
int nodus_rt_core_utxo_create_eff(dna_effect_in_t *eff, uint8_t *value,
                                  const uint8_t nullifier[64],
                                  const char *owner_fp_hex,
                                  uint64_t amount,
                                  const uint8_t token_id[64],
                                  const uint8_t tx_hash[64],
                                  uint32_t output_index,
                                  uint64_t block_height,
                                  uint64_t unlock_block);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_RUNTIME_H */
