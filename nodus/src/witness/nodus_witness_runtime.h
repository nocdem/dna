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
 * RulesetDescriptor (shared/dnac/domain_wire.h, tag "DNA.RULESET.v1") —
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
 * "DNA.EFFRES.v1" typed-effect result). Both MUST stay NULL in the
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

#ifdef __cplusplus
extern "C" {
#endif

/** This release's native runtime ABI. */
#define NODUS_DOMAIN_RUNTIME_ABI_V1  ((uint32_t)1)

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

/** Largest mediated-read request list one leg may emit. Mirrors the
 *  engine's own batch bound (NODUS_V2_ENV_BATCH_MAX == the apply
 *  engine's MAX_OPS == 16) — an engine array bound, not a priced
 *  policy; a plan exceeding it is rejected, never truncated. */
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
 * TWO supported schemes this release (capacity season):
 *
 *   auth_kind 1 — NODUS_RT_AUTHKIND_DSA87_MULTI_V1: auth_data =
 *     signer_count u8 (1..NODUS_RT_AUTH_MAX_SIGNERS)
 *     ‖ signer_count × ( pubkey[2592] ‖ signature[4627] )
 *   with pubkeys STRICTLY ascending (memcmp — duplicates and disorder
 *   reject, so exactly ONE encoding exists per signer set), each
 *   signature an ML-DSA-87 signature over the 64-byte engine-derived
 *   leg auth_digest (env_wire.h "DNA.ENVAUTH.v1": binds chain identity,
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
 *   "DNA.CCAPPR.v1": leg auth_digest ‖ resolved-set hash ‖ governing
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
 * Every other auth_kind value REJECTS (unsupported scheme, fail-closed),
 * and a runtime accepts only the kinds its allowed_auth_kinds mask
 * declares (table field below).
 * Verification work is priced by w_authbyte at reservation — the hook
 * charges nothing, so authorization is never charged twice. */
#define NODUS_RT_AUTHKIND_DSA87_MULTI_V1  ((uint8_t)1)
#define NODUS_RT_AUTHKIND_DSA87_CC_V1     ((uint8_t)2)
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
    uint8_t  set_hash[64];         /* "DNA.CCSET.v1" resolved-set hash   */
    const uint8_t *pubkeys;        /* count × 2592, contiguous           */
    const uint8_t (*fps)[64];      /* count × SHA3-512(pubkey)           */
} nodus_rt_committee_t;

/** The engine-owned verdict of ONE leg's verified authorization. Only
 *  the engine writes it (through the resolved auth hook); runtimes read
 *  it through ctx->auth. Kind 1 leaves the approval fields ZERO; kind 2
 *  fills them from the verified committee evidence. */
typedef struct {
    uint16_t n_signers;                  /* 1..NODUS_RT_AUTH_MAX_SIGNERS */
    uint8_t  signer_fp[NODUS_RT_AUTH_MAX_SIGNERS][64]; /* SHA3-512(pk)   */
    /* capacity season — committee approval evidence (kind 2 only):      */
    uint16_t n_approvals;                /* verified DISTINCT approvals  */
    uint16_t committee_n;                /* resolved committee size the
                                          * approvals verified against   */
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
     * (n_approvals / committee_n), never the raw snapshot. */
    const nodus_rt_committee_t *committee;
} nodus_rt_exec_ctx_t;

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
 * read results; produces ONLY canonical "DNA.EFFRES.v1" result bytes in
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
     * declares {1,2}; CORE declares {1}. */
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
    nodus_rt_root_fn      state_root;    /* domain state root (S5/S6)     */
    /* OPTIONAL activation payload root: the value compared against the
     * registry-committed genesis_state_root when this domain's
     * DomainHead is created at ACTIVATION. NULL = the state root itself
     * (the generic case — a runtime whose state root contains no
     * self-referencing container legs). SYSTEM sets it to the
     * "DNA.SYSPAYL.v1" payload root (the S5 genesis cycle break) — the
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

/** Exact-tuple lookup in the compiled production table
 *  (SYSTEM + DNA_CORE only). @return the entry or NULL. */
const nodus_domain_runtime_t *
nodus_runtime_lookup(uint32_t domain_id, uint8_t runtime_kind,
                     uint32_t runtime_abi, uint32_t ruleset_version,
                     const uint8_t ruleset_hash[DNA_DOM_HASH_LEN]);

/** The compiled production table. @param n_out receives the entry count. */
const nodus_domain_runtime_t *nodus_runtime_builtin_table(size_t *n_out);

/**
 * Self-check of the production table, fail-closed:
 *   - every entry's pinned ruleset_hash equals a FRESH
 *     dna_ruleset_desc_hash of its checked-in descriptor;
 *   - allowed_auth_kinds is non-zero, names only compiled kinds (1/2),
 *     and matches the configured shape exactly: SYSTEM {1,2}, CORE {1};
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
 * @return 0 healthy, -1 on the first violation.
 */
int nodus_witness_runtime_selfcheck(void);

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
 * domain); the per-domain read_plan/exec pairs implement — since O11,
 * under SYSTEM ruleset_version 3 — the stake lifecycle
 * DNA_SYSRULE_STAKE / DELEGATE / UNSTAKE / UNDELEGATE and
 * DNA_SYSRULE_CHAIN_CONFIG (SYSTEM) and — under CORE ruleset_version 3
 * — DNA_CORERULE_SPEND, DNA_CORERULE_BURN, DNA_CORERULE_TOKEN_CREATE
 * and DNA_CORERULE_SYSFUND (DNA_CORE), and deterministically reject
 * every other owned runtime_op. The compiled adapters are exported so
 * tests can drive them directly. */
int nodus_rt_auth_dsa87_v1(const nodus_domain_runtime_t *rt,
                           const dna_env_view_t *env, uint16_t leg_index,
                           const nodus_rt_exec_ctx_t *ctx,
                           nodus_rt_auth_verdict_t *out);
/** "DNA.CCSET.v1" resolved-committee-set hash over the fps in committee
 *  (stake-ranked) order — the ONE derivation the engine, the auth hook
 *  and every signer share. Preimage: tag(16) ‖ count u16 BE ‖ count ×
 *  SHA3-512(pubkey)[64]. HONEST LABEL: this hashes the RESOLVED
 *  committee (nodus_committee_get_for_block's answer), NOT the persisted
 *  "DNA.VSET.v1" snapshot row — the bootstrap path has no row, and
 *  every honest node resolves the same members in the same order, which
 *  is what makes the value consensus-safe. @return 0 / -1. */
int nodus_rt_committee_set_hash(const uint8_t (*fps)[64], uint32_t count,
                                uint8_t out[64]);
/** "DNA.CCAPPR.v1" committee approval digest — what one committee seat
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
