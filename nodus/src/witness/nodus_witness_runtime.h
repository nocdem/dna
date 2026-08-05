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
 * S5 boundary: the apply/root hooks are declared but MUST be NULL in S4 —
 * the atomic global-block apply pipeline is Season-5 scope, and
 * nodus_witness_runtime_selfcheck() enforces their absence.
 *
 * @file nodus_witness_runtime.h
 */

#ifndef NODUS_WITNESS_RUNTIME_H
#define NODUS_WITNESS_RUNTIME_H

#include <stdint.h>
#include <stddef.h>

#include "dnac/domain_wire.h"

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
 *  (fail-closed — an unknown type has NO cost, not a default one). */
typedef int (*nodus_rt_cost_fn)(const struct nodus_domain_runtime *rt,
                                uint8_t tx_type, uint32_t *cost_out);

/** RESERVED Season-5 hooks (atomic apply / domain state root). Declared so
 *  the boundary shape is fixed now; MUST be NULL in S4. */
typedef int (*nodus_rt_apply_fn)(const struct nodus_domain_runtime *rt,
                                 void *apply_ctx);
typedef int (*nodus_rt_root_fn)(const struct nodus_domain_runtime *rt,
                                uint8_t out_root[64]);

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
    nodus_rt_apply_fn apply_reserved;    /* S5 — NULL in S4               */
    nodus_rt_root_fn  root_reserved;     /* S5 — NULL in S4               */
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
 *   - admit and tx_cost are present; apply/root hooks are NULL (S4);
 *   - exactly SYSTEM and DNA_CORE are present, ascending by domain_id.
 * @return 0 healthy, -1 on the first violation.
 */
int nodus_witness_runtime_selfcheck(void);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_RUNTIME_H */
