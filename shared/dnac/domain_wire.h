/**
 * @file shared/dnac/domain_wire.h
 * @brief Ledger V2 Season 4 — canonical domain manifest / registry /
 *        readiness codec (INACTIVE).
 *
 * Four canonical objects live here, all compiled identically into libdna
 * and libnodus (the chain_config_wire / tx_wire single-source pattern):
 *
 *   1. DomainManifest v1     — the immutable, versioned ruleset/runtime
 *                              descriptor of one execution domain.
 *   2. RulesetDescriptor v1  — the reproducible, checked-in canonical
 *                              description of one NATIVE_BUILTIN ruleset;
 *                              its tagged SHA3-512 digest is the
 *                              `ruleset_hash` a manifest and the compiled
 *                              runtime table both pin. Pure data — never
 *                              derived from compiler output, build paths,
 *                              timestamps or object code, so the digest is
 *                              identical across compilers, OSes and paths.
 *   3. DomainRegistryRecord v1 — the MUTABLE activation state of one
 *                              domain (status + current/pending manifest
 *                              references + scheduling metadata). Kept
 *                              deliberately separate from the immutable
 *                              manifest (S4 charter: do not mix ruleset
 *                              description with activation state).
 *   4. ReadinessSignal v1    — one validator's signed statement that its
 *                              locally compiled runtime table contains the
 *                              EXACT proposed ruleset tuple.
 *
 * ACTIVATION: nothing in live consensus calls anything here. The active
 * chain keeps the v3 five-input state_root and V1 block hash
 * byte-identical; Type 11 stays REJECT-only; the V2 wire stays inactive.
 * The domain registry activates only with the Ledger V2 devnet reset.
 *
 * Conventions (identical discipline to ledger_roots_v2.h / vset_wire.h):
 *   - SHA3-512 everywhere (qgp_sha3_512);
 *   - every hash preimage starts with a FIXED 16-byte zero-padded ASCII tag;
 *   - fixed-width unsigned integers, BIG-ENDIAN; explicit lengths for every
 *     variable collection; iterated sets strictly ascending by their
 *     canonical key (rejects duplicates AND non-canonical order);
 *   - no native struct serialization; no padding- or endian-dependent bytes;
 *   - unknown mandatory enum values are a DECODE reject (fail-closed);
 *   - enum value 0 is INVALID everywhere so zeroed memory can never decode
 *     as a valid object (S3 precedent: DNA_VSET_RULESET_INVALID). NOTE:
 *     this deliberately departs from the architecture report §5.3
 *     parenthetical "(0 = NATIVE_BUILTIN)" — classified JUDGMENT in the S4
 *     report; the season charter only requires fail-closed unknowns and the
 *     current-source convention wins;
 *   - every failure path returns -1 and produces NO partial result.
 *
 * ── TAG TABLE (each exactly 16 bytes, zero-padded) ────────────────────
 *   "DNA.DOMMAN.v1"   manifest hash              (locked by the S4 charter)
 *   "DNA.RULESET.v1"  ruleset descriptor digest  (S4 JUDGMENT tag)
 *   "DNA.DRLEAF.v1"   registry record leaf       (S4 JUDGMENT tag)
 *   "DNA.DRNODE.v1"   registry Merkle inner node (S4 JUDGMENT tag)
 *   "DNA.DOMRDY.v1"   readiness signal preimage  (S4 JUDGMENT tag)
 *   "DNA.DOMPROP.v1"  proposal digest            (S4 JUDGMENT tag)
 *   "DNA.E.DOMREG.v1" EMPTY registry root        (frozen since S2 —
 *                     ledger_roots_v2.h; dna_v2_empty_root(DNA_V2_EMPTY_DOMREG))
 *
 * ── DomainManifest v1 canonical layout (199 + tx_type_count bytes) ────
 *   off   0  manifest_version    u32 BE   (= 1)
 *   off   4  domain_id           u32 BE
 *   off   8  name[32]            ASCII 0x21..0x7E, zero-padded; first byte
 *                                non-NUL; no non-NUL byte after the first NUL
 *   off  40  runtime_kind        u8       (1 = NATIVE_BUILTIN; only value)
 *   off  41  runtime_abi         u32 BE
 *   off  45  ruleset_version     u32 BE
 *   off  49  ruleset_hash[64]
 *   off 113  genesis_state_root[64]
 *   off 177  tx_type_count       u16 BE   (0..256)
 *   off 179  tx_types[count]     u8 each, STRICTLY ascending
 *   then     fee_policy          u8       (1 = GLOBAL_BURN; only value)
 *            quota_tx_per_block  u16 BE   (0 = unbounded within global cap)
 *            quota_verify_cost   u32 BE   (0 = unbounded within global budget)
 *            upgrade_authority   u8       (1 = CHAIN_CONFIG governance)
 *            activation_epoch    u64 BE   (epoch START height; 0 = genesis)
 *            readiness_policy    u32 BE   (1 = STAGED_V1, the locked S4
 *                                          staged activation policy)
 *   manifest_hash = SHA3-512("DNA.DOMMAN.v1" ‖ the canonical bytes)
 *
 * ── RulesetDescriptor v1 canonical layout (52 + 4·rules + types bytes) ─
 *   descriptor_version u32 BE (= 1) ‖ domain_id u32 BE ‖ name[32]
 *   ‖ runtime_abi u32 BE ‖ ruleset_version u32 BE
 *   ‖ rule_count u16 BE ‖ rule_ids[count] u32 BE STRICTLY ascending
 *   ‖ tx_type_count u16 BE ‖ tx_types[count] u8 STRICTLY ascending
 *   ruleset_hash = SHA3-512("DNA.RULESET.v1" ‖ the canonical bytes)
 *
 * ── DomainRegistryRecord v1 canonical layout (223 bytes, fixed) ────────
 *   off   0  record_version               u32 BE (= 1)
 *   off   4  domain_id                    u32 BE
 *   off   8  status                       u8   (1..5, see enum)
 *   off   9  current_manifest_hash[64]
 *   off  73  pending_present              u8   (0/1)
 *   off  74  pending_manifest_hash[64]    all-zero IFF pending_present == 0
 *   off 138  proposal_present             u8   (0/1)
 *   off 139  proposal_digest[64]          all-zero IFF proposal_present == 0
 *   off 203  scheduled_activation_epoch   u64 BE (0 = none)
 *   off 211  readiness_deadline_epoch     u64 BE (0 = none)
 *   off 219  postpone_count               u32 BE
 *   leaf = SHA3-512("DNA.DRLEAF.v1" ‖ the 223 canonical bytes)
 *
 *   Status-coherence rules (validated by encode AND decode, fail-closed):
 *     REGISTERED: pending_present == 0; scheduling fields == 0 (a proposal
 *                 for INITIAL activation targets the CURRENT manifest).
 *     SCHEDULED:  proposal_present == 1; pending_present == 0;
 *                 scheduled_activation_epoch != 0; readiness_deadline != 0.
 *     ACTIVE:     proposal_present == 1 IFF pending_present == 1 (an
 *                 upgrade proposal always targets a NEW pending manifest);
 *                 scheduling fields nonzero only when proposal_present.
 *     PAUSED / RETIRED: no proposal, no pending, no scheduling fields.
 *     postpone_count nonzero only when scheduled_activation_epoch != 0.
 *
 * ── ReadinessSignal v1 ────────────────────────────────────────────────
 *   Signed preimage (EXACTLY 233 bytes):
 *     tag                (16)  "DNA.DOMRDY.v1" zero-padded
 *     msg_version        ( 4)  u32 BE (= 1)
 *     chain_id           (32)
 *     voter_id           (32)  SHA3-512(pubkey)[0..31] — the S3 identity
 *     domain_id          ( 4)  u32 BE
 *     runtime_kind       ( 1)  u8
 *     runtime_abi        ( 4)  u32 BE
 *     ruleset_version    ( 4)  u32 BE
 *     ruleset_hash       (64)
 *     proposal_digest    (64)
 *     signal_epoch       ( 8)  u64 BE — the EPOCH START HEIGHT of the epoch
 *                              the signal is cast in (freshness context; the
 *                              snapshot for that epoch is the membership
 *                              authority the signal is counted against)
 *   Signature: Dilithium5 (ML-DSA-87) over the 233-byte preimage — the
 *   existing validator signing mechanism; no new primitive.
 *
 *   Wire form (4844 bytes): the 217 preimage bytes AFTER the tag, then
 *   signature[4627]. The tag never travels — it joins in the hash domain
 *   only, like every other tag here.
 *
 * ── Proposal digest ───────────────────────────────────────────────────
 *   SHA3-512("DNA.DOMPROP.v1" ‖ chain_id[32] ‖ domain_id(4 BE)
 *            ‖ target_manifest_hash[64] ‖ proposal_nonce(8 BE)
 *            ‖ proposed_at_epoch(8 BE))
 *   A modified or re-issued proposal carries a new nonce/epoch, so its
 *   digest changes and every readiness signal for the old digest is dead —
 *   replay across proposals is structurally impossible.
 *
 * ── Registry Merkle root ──────────────────────────────────────────────
 *   leaves  = record leaf hashes, STRICTLY ascending domain_id;
 *   the FIRST record MUST be DNA_DOMAIN_SYSTEM (a non-empty registry
 *   without SYSTEM is malformed state, same rule as domains_root);
 *   inner   = SHA3-512("DNA.DRNODE.v1" ‖ left[64] ‖ right[64]);
 *   odd node PROMOTED unchanged (never duplicated); n == 1 → the leaf;
 *   n == 0 → dna_v2_empty_root(DNA_V2_EMPTY_DOMREG) — byte-identical to
 *   the S2 placeholder, so every pre-registry chain's system_state_root
 *   is unchanged.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef SHARED_DNAC_DOMAIN_WIRE_H
#define SHARED_DNAC_DOMAIN_WIRE_H

#include <stdint.h>
#include <stddef.h>

#include "ledger_ids.h"
#include "ledger_roots_v2.h"   /* DNA_V2_ROOT_LEN, DNA_V2_EMPTY_DOMREG */

#ifdef __cplusplus
extern "C" {
#endif

/* ── Field widths / caps ────────────────────────────────────────────── */
#define DNA_DOM_NAME_LEN        32
#define DNA_DOM_HASH_LEN        64      /* SHA3-512 */
#define DNA_DOM_MAX_TX_TYPES    256     /* u8 type space — hard cap        */
#define DNA_DOM_MAX_RULE_IDS    1024    /* descriptor sanity cap           */
#define DNA_DOM_SIG_LEN         4627    /* Dilithium5 (ML-DSA-87)          */
#define DNA_DOM_VOTER_ID_LEN    32

/* ── Enums — 0 is INVALID everywhere (fail-closed on zeroed memory) ──── */
#define DNA_RUNTIME_INVALID        ((uint8_t)0)
#define DNA_RUNTIME_NATIVE_BUILTIN ((uint8_t)1)   /* only value in S4 */

#define DNA_FEEPOL_INVALID         ((uint8_t)0)
#define DNA_FEEPOL_GLOBAL_BURN     ((uint8_t)1)   /* only value in S4 */

#define DNA_UPGAUTH_INVALID        ((uint8_t)0)
#define DNA_UPGAUTH_CHAIN_CONFIG   ((uint8_t)1)   /* only value in S4 */

#define DNA_RDYPOL_INVALID         ((uint32_t)0)
#define DNA_RDYPOL_STAGED_V1       ((uint32_t)1)  /* the locked S4 policy */

typedef enum {
    DNA_DOMST_INVALID    = 0,   /* never encoded, always rejected          */
    DNA_DOMST_REGISTERED = 1,   /* manifest registered, not active         */
    DNA_DOMST_SCHEDULED  = 2,   /* initial activation scheduled            */
    DNA_DOMST_ACTIVE     = 3,   /* executing (may carry a pending upgrade) */
    DNA_DOMST_PAUSED     = 4,   /* governance-paused; admission rejects    */
    DNA_DOMST_RETIRED    = 5    /* terminal                                */
} dna_domain_status_t;

/* ══════════════════════════════════════════════════════════════════════
 * 1. DomainManifest v1
 * ════════════════════════════════════════════════════════════════════ */

#define DNA_DOMMAN_VERSION      1u
#define DNA_DOMMAN_FIXED_HEAD   179  /* bytes before tx_types[]            */
#define DNA_DOMMAN_FIXED_TAIL   20   /* bytes after tx_types[]             */
#define DNA_DOMMAN_ENC_LEN(count) \
    ((size_t)DNA_DOMMAN_FIXED_HEAD + (size_t)(count) + DNA_DOMMAN_FIXED_TAIL)
#define DNA_DOMMAN_MAX_ENC_LEN  DNA_DOMMAN_ENC_LEN(DNA_DOM_MAX_TX_TYPES)

typedef struct {
    uint32_t manifest_version;                 /* must be 1                */
    uint32_t domain_id;
    uint8_t  name[DNA_DOM_NAME_LEN];           /* canonical zero-padded    */
    uint8_t  runtime_kind;                     /* DNA_RUNTIME_*            */
    uint32_t runtime_abi;
    uint32_t ruleset_version;
    uint8_t  ruleset_hash[DNA_DOM_HASH_LEN];
    uint8_t  genesis_state_root[DNA_DOM_HASH_LEN];
    uint16_t tx_type_count;                    /* 0..DNA_DOM_MAX_TX_TYPES  */
    uint8_t  tx_types[DNA_DOM_MAX_TX_TYPES];   /* strictly ascending       */
    uint8_t  fee_policy;                       /* DNA_FEEPOL_*             */
    uint16_t quota_tx_per_block;               /* 0 = unbounded-in-global  */
    uint32_t quota_verify_cost;                /* 0 = unbounded-in-global  */
    uint8_t  upgrade_authority;                /* DNA_UPGAUTH_*            */
    uint64_t activation_epoch;                 /* epoch START height       */
    uint32_t readiness_policy;                 /* DNA_RDYPOL_*             */
} dna_domain_manifest_t;

/** Structural + canonical validation (the exact rule set encode and decode
 *  share): version, enum values, name canonicality, type-list bounds and
 *  strict ascent. @return 0 valid / -1. */
int dna_domman_validate(const dna_domain_manifest_t *m);

/** Exact encoded size of a VALID manifest, or 0 if encode would reject. */
size_t dna_domman_encoded_len(const dna_domain_manifest_t *m);

/** Canonical encode. Rejects (-1, dst untouched) anything validate
 *  rejects, plus a short dst. @param written optional. */
int dna_domman_encode(const dna_domain_manifest_t *m,
                      uint8_t *dst, size_t cap, size_t *written);

/** Strict decode: `len` must EXACTLY equal the length implied by the
 *  encoded tx_type_count (truncation and trailing bytes both reject), then
 *  the full validate rule set applies. @return 0 / -1. */
int dna_domman_decode(const uint8_t *src, size_t len,
                      dna_domain_manifest_t *out);

/** manifest_hash = SHA3-512("DNA.DOMMAN.v1" ‖ canonical bytes).
 *  Rejects an invalid manifest. @return 0 / -1. */
int dna_domman_hash(const dna_domain_manifest_t *m,
                    uint8_t out[DNA_DOM_HASH_LEN]);

/**
 * True (0) iff `tx_type` is in the manifest's ownership list.
 * @return 0 owned, 1 not owned, -1 invalid input.
 */
int dna_domman_owns_type(const dna_domain_manifest_t *m, uint8_t tx_type);

/* ══════════════════════════════════════════════════════════════════════
 * 2. RulesetDescriptor v2
 *
 * v2 (Ledger V2 execution season) APPENDS meter_policy_digest to the v1
 * layout and retires v1: descriptor_version 1 is REJECTED everywhere (the
 * layer is inactive with zero live consumers, so there is no v1 data to
 * migrate — carrying a dead version would be dead code). The digest is
 * what makes the metering policy CONSENSUS-BOUND: a validator matches a
 * ruleset only on the exact descriptor hash, the hash commits the policy
 * digest, and the digest commits every weight (res_meter.h
 * dna_meter_policy_digest) — so two validators claiming the same ruleset
 * identity structurally cannot price differently.
 *
 * An ALL-ZERO meter_policy_digest means "this ruleset declares no
 * metering policy" (a domain that is priced under another authority —
 * the engine takes the block policy from the SYSTEM ruleset, the one
 * mandatory protocol domain). Non-zero means the runtime carrying this
 * descriptor MUST carry the exact policy whose identity digest matches
 * (enforced by nodus_witness_runtime_selfcheck and by the engine's
 * block-start snapshot).
 * ════════════════════════════════════════════════════════════════════ */

#define DNA_RULESET_DESC_VERSION 2u

typedef struct {
    uint32_t descriptor_version;               /* must be 2                */
    uint32_t domain_id;
    uint8_t  name[DNA_DOM_NAME_LEN];
    uint32_t runtime_abi;
    uint32_t ruleset_version;
    uint16_t rule_count;                       /* 0..DNA_DOM_MAX_RULE_IDS  */
    const uint32_t *rule_ids;                  /* strictly ascending       */
    uint16_t tx_type_count;                    /* 0..DNA_DOM_MAX_TX_TYPES  */
    const uint8_t *tx_types;                   /* strictly ascending       */
    uint8_t  meter_policy_digest[DNA_DOM_HASH_LEN]; /* dna_meter_policy_digest
                                                * of the committed policy;
                                                * ALL-ZERO = none declared */
} dna_ruleset_desc_t;

/** ruleset_hash = SHA3-512("DNA.RULESET.v1" ‖ canonical descriptor bytes,
 *  v2 layout: version(4) ‖ domain_id(4) ‖ name(32) ‖ abi(4) ‖
 *  ruleset_version(4) ‖ rule_count(2) ‖ rule_ids ‖ tx_type_count(2) ‖
 *  tx_types ‖ meter_policy_digest(64)). The 16-byte tag names the object
 *  FAMILY; the version field inside the preimage is what versions the
 *  layout, so v1 and v2 descriptors can never collide.
 *  Rejects (-1): NULL, version != 2, non-canonical name, over-cap or
 *  non-ascending lists (NULL list allowed iff its count is 0). */
int dna_ruleset_desc_hash(const dna_ruleset_desc_t *d,
                          uint8_t out[DNA_DOM_HASH_LEN]);

/* ══════════════════════════════════════════════════════════════════════
 * 3. DomainRegistryRecord v1
 * ════════════════════════════════════════════════════════════════════ */

#define DNA_DOMREG_REC_VERSION 1u
#define DNA_DOMREG_REC_ENC_LEN 223

typedef struct {
    uint32_t record_version;                   /* must be 1                */
    uint32_t domain_id;
    uint8_t  status;                           /* dna_domain_status_t 1..5 */
    uint8_t  current_manifest_hash[DNA_DOM_HASH_LEN];
    uint8_t  pending_present;                  /* 0/1                      */
    uint8_t  pending_manifest_hash[DNA_DOM_HASH_LEN];
    uint8_t  proposal_present;                 /* 0/1                      */
    uint8_t  proposal_digest[DNA_DOM_HASH_LEN];
    uint64_t scheduled_activation_epoch;       /* epoch START height; 0=∅  */
    uint64_t readiness_deadline_epoch;         /* epoch START height; 0=∅  */
    uint32_t postpone_count;
} dna_domreg_record_t;

/** Structural + status-coherence validation (header table). 0 / -1. */
int dna_domreg_record_validate(const dna_domreg_record_t *r);

/** Canonical 223-byte encode; rejects anything validate rejects. */
int dna_domreg_record_encode(const dna_domreg_record_t *r,
                             uint8_t out[DNA_DOMREG_REC_ENC_LEN]);

/** Strict decode of EXACTLY 223 bytes + full validation. */
int dna_domreg_record_decode(const uint8_t *src, size_t len,
                             dna_domreg_record_t *out);

/** leaf = SHA3-512("DNA.DRLEAF.v1" ‖ 223 canonical bytes). 0 / -1. */
int dna_domreg_record_leaf(const dna_domreg_record_t *r,
                           uint8_t out[DNA_V2_ROOT_LEN]);

/**
 * domain_registry_root over records STRICTLY ascending by domain_id;
 * a non-empty registry MUST start with DNA_DOMAIN_SYSTEM; n == 0 yields
 * the frozen S2 tagged empty root (DNA_V2_EMPTY_DOMREG). @return 0 / -1.
 */
int dna_domreg_root(const dna_domreg_record_t *records, size_t n,
                    uint8_t out[DNA_V2_ROOT_LEN]);

/* ══════════════════════════════════════════════════════════════════════
 * 4. Proposal digest + ReadinessSignal v1
 * ════════════════════════════════════════════════════════════════════ */

/** SHA3-512("DNA.DOMPROP.v1" ‖ chain_id ‖ domain_id ‖ target_manifest_hash
 *  ‖ proposal_nonce ‖ proposed_at_epoch). @return 0 / -1 (NULL args). */
int dna_domprop_digest(const uint8_t chain_id[DNA_CHAIN_ID_LEN],
                       uint32_t domain_id,
                       const uint8_t target_manifest_hash[DNA_DOM_HASH_LEN],
                       uint64_t proposal_nonce,
                       uint64_t proposed_at_epoch,
                       uint8_t out[DNA_DOM_HASH_LEN]);

#define DNA_DOMRDY_MSG_VERSION   1u
#define DNA_DOMRDY_PREIMAGE_LEN  233
#define DNA_DOMRDY_WIRE_LEN      (DNA_DOMRDY_PREIMAGE_LEN - 16 + DNA_DOM_SIG_LEN)
                                 /* 217 field bytes + 4627 sig = 4844      */

typedef struct {
    uint32_t msg_version;                      /* must be 1                */
    uint8_t  chain_id[DNA_CHAIN_ID_LEN];
    uint8_t  voter_id[DNA_DOM_VOTER_ID_LEN];
    uint32_t domain_id;
    uint8_t  runtime_kind;
    uint32_t runtime_abi;
    uint32_t ruleset_version;
    uint8_t  ruleset_hash[DNA_DOM_HASH_LEN];
    uint8_t  proposal_digest[DNA_DOM_HASH_LEN];
    uint64_t signal_epoch;                     /* EPOCH START HEIGHT       */
    uint8_t  signature[DNA_DOM_SIG_LEN];
} dna_readiness_signal_t;

/** Build the exact 233-byte signed preimage. Rejects (-1): NULL args,
 *  msg_version != 1, runtime_kind == DNA_RUNTIME_INVALID. */
int dna_domrdy_preimage(const dna_readiness_signal_t *s,
                        uint8_t out[DNA_DOMRDY_PREIMAGE_LEN]);

/** Canonical wire encode (4844 bytes): the 217 preimage bytes after the
 *  tag, then signature. Same rejects as preimage. */
int dna_domrdy_encode(const dna_readiness_signal_t *s,
                      uint8_t out[DNA_DOMRDY_WIRE_LEN]);

/** Strict decode of EXACTLY DNA_DOMRDY_WIRE_LEN bytes; same validation. */
int dna_domrdy_decode(const uint8_t *src, size_t len,
                      dna_readiness_signal_t *out);

/* ══════════════════════════════════════════════════════════════════════
 * 5. DomainUpdate v1 + domain_updates_root + touched-list (Ledger V2 S5)
 * ════════════════════════════════════════════════════════════════════ */

/*
 * ── S5 TAG TABLE (16 bytes, zero-padded; all JUDGMENT, versioned) ─────
 *   "DNA.DUPD.v1"      DomainUpdate hash
 *   "DNA.DUNODE.v1"    domain_updates_root inner node
 *   "DNA.E.DUPD.v1"    EMPTY domain_updates_root (block touching nothing)
 *   "DNA.DTXB.v1"      per-domain ordered tx-batch commitment
 *   "DNA.E.DUPDPRV.v1" genesis previous-update linkage (16 chars exact)
 *
 * ── DomainUpdate v1 canonical layout (368 bytes, fixed, BE) ───────────
 *   off   0  update_version    u32 (= 1)
 *   off   4  domain_id         u32
 *   off   8  old_height        u64
 *   off  16  new_height        u64   (MUST equal old_height + 1)
 *   off  24  global_height     u64
 *   off  32  pre_root[64]
 *   off  96  post_root[64]
 *   off 160  tx_batch_root[64]      ("DNA.DTXB.v1" commitment below)
 *   off 224  ruleset_version   u32
 *   off 228  ruleset_hash[64]
 *   off 292  res_tx_count      u32
 *   off 296  res_verify_cost   u64
 *   off 304  prev_update_hash[64]   (genesis: dna_dupd_prev_genesis)
 *   total 368
 *   update_hash = SHA3-512("DNA.DUPD.v1" ‖ the 368 canonical bytes)
 *
 * ── tx-batch commitment ───────────────────────────────────────────────
 *   SHA3-512("DNA.DTXB.v1" ‖ count u32 BE ‖ tx_id[64] × count) — the
 *   domain-LOCAL order (deterministic: the block's canonical order
 *   restricted to this domain). count 0 is legal (a mandatory
 *   deterministic transition with no carrying tx).
 *
 * ── domain_updates_root ───────────────────────────────────────────────
 *   Leaves = update hashes of the TOUCHED domains only, STRICTLY
 *   ascending domain_id (duplicates/order violations reject); inner =
 *   SHA3-512("DNA.DUNODE.v1" ‖ L ‖ R), odd node PROMOTED; n == 1 → the
 *   leaf; n == 0 → SHA3-512 of the "DNA.E.DUPD.v1" tag alone.
 *
 * ── touched-domain list (v2_tx_index canonical form) ──────────────────
 *   count u16 BE ‖ domain_id u32 BE × count, STRICTLY ascending;
 *   count ∈ [1, DNA_TOUCHED_MAX]; decode rejects duplicates, descending
 *   order, zero count and any length mismatch.
 */

#define DNA_DUPD_VERSION   1u
#define DNA_DUPD_ENC_LEN   368
#define DNA_TOUCHED_MAX    64   /* sanity cap on touched domains per tx  */

typedef struct {
    uint32_t update_version;               /* must be 1                  */
    uint32_t domain_id;
    uint64_t old_height;
    uint64_t new_height;                   /* must be old_height + 1     */
    uint64_t global_height;
    uint8_t  pre_root[DNA_V2_ROOT_LEN];
    uint8_t  post_root[DNA_V2_ROOT_LEN];
    uint8_t  tx_batch_root[DNA_V2_ROOT_LEN];
    uint32_t ruleset_version;
    uint8_t  ruleset_hash[DNA_DOM_HASH_LEN];
    uint32_t res_tx_count;
    uint64_t res_verify_cost;
    uint8_t  prev_update_hash[DNA_V2_ROOT_LEN];
} dna_domain_update_t;

/** Structural validation: version 1; new_height == old_height + 1 (with
 *  overflow guard). @return 0 / -1. */
int dna_dupd_validate(const dna_domain_update_t *u);

/** Canonical 368-byte encode; rejects anything validate rejects. */
int dna_dupd_encode(const dna_domain_update_t *u,
                    uint8_t out[DNA_DUPD_ENC_LEN]);

/** Strict decode of EXACTLY 368 bytes + full validation. */
int dna_dupd_decode(const uint8_t *src, size_t len,
                    dna_domain_update_t *out);

/** update_hash = SHA3-512("DNA.DUPD.v1" ‖ canonical bytes). 0 / -1. */
int dna_dupd_hash(const dna_domain_update_t *u,
                  uint8_t out[DNA_V2_ROOT_LEN]);

/** Genesis previous-update linkage: SHA3-512("DNA.E.DUPDPRV.v1"). */
int dna_dupd_prev_genesis(uint8_t out[DNA_V2_ROOT_LEN]);

/** SHA3-512("DNA.DTXB.v1" ‖ count u32 BE ‖ tx_ids). tx_ids may be NULL
 *  iff n == 0. @return 0 / -1. */
int dna_v2_tx_batch_root(const uint8_t (*tx_ids)[DNA_V2_ROOT_LEN],
                         uint32_t n, uint8_t out[DNA_V2_ROOT_LEN]);

/**
 * domain_updates_root over TOUCHED updates, strictly ascending domain_id;
 * n == 0 yields the tagged empty root. @return 0 / -1.
 */
int dna_v2_domain_updates_root(const dna_domain_update_t *updates, size_t n,
                               uint8_t out[DNA_V2_ROOT_LEN]);

/** Encoded length of a touched list of n domains (0 on invalid n). */
size_t dna_touched_encoded_len(uint16_t n);

/** Canonical touched-list encode: count u16 BE + u32 BE ids strictly
 *  ascending; n ∈ [1, DNA_TOUCHED_MAX]. @return 0 / -1. */
int dna_touched_encode(const uint32_t *domain_ids, uint16_t n,
                       uint8_t *dst, size_t cap, size_t *written);

/** Strict decode (exact length, ascent, bounds). `ids_out` must hold
 *  DNA_TOUCHED_MAX entries. @return 0 with *n_out set, -1. */
int dna_touched_decode(const uint8_t *src, size_t len,
                       uint32_t *ids_out, uint16_t *n_out);

#ifdef __cplusplus
}
#endif

#endif /* SHARED_DNAC_DOMAIN_WIRE_H */
