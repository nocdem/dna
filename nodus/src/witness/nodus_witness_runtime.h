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
 * auth_kind 1 is the ONE supported scheme this release:
 *   NODUS_RT_AUTHKIND_DSA87_MULTI_V1 — auth_data =
 *     signer_count u8 (1..NODUS_RT_AUTH_MAX_SIGNERS)
 *     ‖ signer_count × ( pubkey[2592] ‖ signature[4627] )
 *   with pubkeys STRICTLY ascending (memcmp — duplicates and disorder
 *   reject, so exactly ONE encoding exists per signer set), each
 *   signature an ML-DSA-87 signature over the 64-byte engine-derived
 *   leg auth_digest (env_wire.h "DNA.ENVAUTH.v1": binds chain identity,
 *   expiry, fee, resource ceilings, every leg's domain / runtime_op /
 *   ruleset identity / call bytes through auth_context_commit — so
 *   changing ANY of them invalidates every signature). Every other
 *   auth_kind value REJECTS (unsupported scheme, fail-closed).
 * Verification work is priced by w_authbyte at reservation — the hook
 * charges nothing, so authorization is never charged twice. */
#define NODUS_RT_AUTHKIND_DSA87_MULTI_V1  ((uint8_t)1)
#define NODUS_RT_AUTH_MAX_SIGNERS         8
#define NODUS_RT_AUTH_SIGNER_LEN          (2592u + 4627u)   /* pk ‖ sig  */

/** The engine-owned verdict of ONE leg's verified authorization. Only
 *  the engine writes it (through the resolved auth hook); runtimes read
 *  it through ctx->auth. */
typedef struct {
    uint16_t n_signers;                  /* 1..NODUS_RT_AUTH_MAX_SIGNERS */
    uint8_t  signer_fp[NODUS_RT_AUTH_MAX_SIGNERS][64]; /* SHA3-512(pk)   */
} nodus_rt_auth_verdict_t;

/** The engine-owned execution context for one leg. Every pointer is a
 *  BORROWED engine buffer, valid for the hook call only. All identity
 *  material is ENGINE-DERIVED (env_preflight.h): tx_id and the two
 *  commitments are derived from the envelope bytes + chain identity +
 *  contextual rulesets — a runtime can bind to them but can never
 *  choose them. `auth` is the ENGINE-owned VERIFIED verdict of this
 *  leg's authorization (native auth season): NULL only while the auth
 *  hook itself runs; non-NULL for read_plan/exec, whose ownership /
 *  authority decisions MUST bind to it and to nothing carried by the
 *  envelope bytes. */
typedef struct {
    const uint8_t *chain_id;              /* [DNA_CHAIN_ID_LEN]           */
    uint64_t       global_height;         /* the block being applied      */
    uint64_t       epoch;                 /* DERIVED from global block
                                           * count — never wall clock     */
    const uint8_t *tx_id;                 /* [64] engine-derived identity */
    const uint8_t *auth_context_commit;   /* [64] derived commitment      */
    const uint8_t *leg_auth_digest;       /* [64] this leg's derived
                                           * commitment                   */
    const nodus_rt_auth_verdict_t *auth;  /* engine-VERIFIED verdict      */
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
    /* The typed EXECUTION boundary (header block above). Native auth
     * season: the production SYSTEM and DNA_CORE entries carry REAL
     * compiled implementations (SYSTEM: DNA_SYSRULE_CHAIN_CONFIG;
     * DNA_CORE: DNA_CORERULE_SPEND — every other owned runtime_op is a
     * deterministic reject inside the hooks until its own migration
     * slice). NULL exec = this runtime cannot execute envelope legs
     * (engine fails the leg closed); NULL read_plan = it reads
     * nothing. */
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
 * domain); the per-domain read_plan/exec pairs implement exactly
 * DNA_SYSRULE_CHAIN_CONFIG (SYSTEM) and DNA_CORERULE_SPEND (DNA_CORE)
 * and deterministically reject every other owned runtime_op. The
 * compiled adapters are exported so tests can drive them directly. */
int nodus_rt_auth_dsa87_v1(const nodus_domain_runtime_t *rt,
                           const dna_env_view_t *env, uint16_t leg_index,
                           const nodus_rt_exec_ctx_t *ctx,
                           nodus_rt_auth_verdict_t *out);
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

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_RUNTIME_H */
