/**
 * @file nodus_witness_v2_gen.h
 * @brief Ledger V2 O15J Faz 1 — the PURE-V2 genesis builder: a complete
 *        Ledger V2 chain derived from a local operator config, with NO
 *        legacy ancestor.
 *
 * The activation seam (nodus_witness_v2_seam.c) derives a successor from
 * a TERMINAL LEGACY DATABASE. This module derives a chain from NOTHING
 * but a config. It reuses the seam's proven steps 4 and 6-8 verbatim —
 * provisional-DB creation, vset_commit_genesis + domreg_init_genesis +
 * dna_gman_encode + nodus_witness_v2_genesis_ex, the supply
 * post-conditions, the genesis bundle persist, and the
 * rename-only-on-COMPLETE discipline — and replaces exactly the three
 * steps that were legacy-shaped:
 *
 *   seam step 1  terminal binding       → REPLACED: source_tag is
 *                                         "DNA.GENESIS.v1" and
 *                                         source_commit is
 *                                         SHA3-512(canonical config).
 *   seam step 2  fail-closed legacy     → REMOVED: there is no legacy
 *                classification          state to classify.
 *   seam step 3  claim leaves from      → REPLACED: leaves come from the
 *                legacy UTXOs             config's allocation list.
 *   seam step 5  INSERT … SELECT FROM   → REPLACED: validators,
 *                legacy.*                 delegations, validator_stats,
 *                                         epoch_state, supply_tracking
 *                                         and chain_config_history are
 *                                         seeded from the config.
 *
 * ════════════════════════════════════════════════════════════════════
 * NO LIVE CONSUMER YET. Nothing calls nodus_witness_v2_gen_derive on a
 * running node: startup wiring (choosing this path over the legacy
 * bootstrap, and the G5 refusal of a legacy-derived database) is NOT
 * part of Faz 1. This module is complete and tested, but inert.
 * ════════════════════════════════════════════════════════════════════
 *
 * ── DETERMINISM ─────────────────────────────────────────────────────
 * Two nodes given a byte-identical config MUST derive a byte-identical
 * chain — same chain id, same genesis BlockID, same roots, same
 * snapshots. Everything on this path is a pure function of the config:
 * no clock, no network, no environment, no readdir order, no prior
 * database, no rand()/getrandom(). Both collections are sorted by an
 * explicit strict total key before ANY byte is written or hashed
 * (validators by pubkey ASC, allocations by source_id ASC), so caller
 * insertion order cannot influence a single output byte — including the
 * SQLite rowid order that a whole-database digest sees.
 *
 * ── THE ECONOMIC PARAMETERS ARE COMMITTED GENESIS STATE (Block 2C) ──
 * DNAC_BLOCKS_PER_YEAR, DNAC_DECIMAL_UNIT (nodus_witness_emission.h:33,
 * :41) and DNAC_EPOCH_LENGTH (dnac.h:171) are all `#ifndef`-guarded, so
 * `-D` changes how much a node mints and where its epoch boundaries fall,
 * and the Stage F halving test expects exactly such a build: it requires
 * a binary carrying -DDNAC_BLOCKS_PER_YEAR=<BY> and SKIPs when the value
 * is not declared (test_halving_boundaries.sh:37, :57-65). They
 * reach the state root and, before Block 2C, appeared in NO committed
 * field — so a differently-built node derived the SAME chain id, joined
 * cleanly, and then credited a different amount at some later height.
 *
 * All four economic parameters now travel two INDEPENDENT paths, and the
 * two are not the same property:
 *
 *   A. INTO source_commit. They are fields of the canonical config
 *      encoding, so source_commit changes with them; the manifest carries
 *      source_commit into dna_bh2_genesis_block_id as an explicit input
 *      (nodus_witness_v2_apply.c:865), and chain id = f(genesis BlockID).
 *      A mismatched build therefore derives a DIFFERENT CHAIN and cannot
 *      join. An invisible split becomes a loud refusal — that is the
 *      point, and the accepted consequence is that a harness built with
 *      a short tokenomic year derives a different chain than production.
 *      It always WAS a different chain; only the identity was hiding it.
 *      OPERATIONAL NOTE: such a harness must ALSO put its own <BY> in the
 *      genesis config, or this builder refuses to derive at all. No
 *      harness does that today — nothing calls
 *      nodus_witness_v2_gen_derive on a running node yet (see the NO LIVE
 *      CONSUMER banner above) — but whoever wires it must.
 *
 *   B. INTO COMMITTED, READABLE STATE. gen_seed_state writes them as
 *      chain_config_history rows at effective_block 0 — the inflation
 *      start under its existing governance id, the other three in the
 *      reserved econ band (nodus_chain_config.h). Those rows reach
 *      chain_config_root → SYSTEM root (nodus_witness_roots_v2.c:266,
 *      :285) and travel to joiners in the genesis bundle
 *      (nodus_witness_v2_bundle.c:47). Path A alone would be DECORATIVE:
 *      a joiner never runs this builder, so only a readable committed
 *      value can catch a mismatched build that arrived by syncing.
 *      nodus_witness_v2_econ_params_load is the reader.
 *
 * The builder ALSO keeps the fail-closed equality check for all three
 * schedule constants (it was already there for epoch_length). Both, not
 * either: the equality check stops a bad DERIVATION at the config, while
 * the committed rows stop a bad JOIN at the first block. Neither covers
 * the other's case.
 *
 * `inflation_start_block` is the mirror-image fix. This builder used to
 * ASSERT chain_config_history was empty, so the emission gate's
 * nodus_chain_config_get_u64(..., 1ULL) fell to its default forever and
 * every derived chain minted from height 1, configurable only by a later
 * governance vote. It is now expressible AT GENESIS.
 *
 * ⚠ ONE INPUT THE CONFIG STILL DOES NOT FIX (stated, not hidden):
 *   The compiled SYSTEM/CORE ruleset_version / ruleset_hash pins reach
 *   the chain id through the domain manifests. Nothing here detects a
 *   build mismatch in those. BUILD IDENTITY REMAINS AN EXPLICIT TRUST
 *   ASSUMPTION for that leg.
 *
 * Config sort order controls `source_commit` ONLY. It does NOT control
 * the committed `validator_set_hash`: the committed snapshot order is
 * (self_stake + external_delegated) DESC with a
 * SHA3-512(0x02 ‖ pubkey ‖ state_seed) ASC tiebreak
 * (nodus_witness_validator.c:320, nodus_witness_committee.c:46-63,
 * 416-429), and with the equal-stake composition this builder enforces
 * ALL validators form one tied group, so the whole committed order is
 * the tiebreak-hash order.
 *
 * ── THREAT MODEL ────────────────────────────────────────────────────
 * The operator's LOCAL config is the trust root — the same anchor the
 * shipped joiner already uses (--v2-genesis-pin, O15E Faz D), local by
 * construction and never wire-settable. A malformed, lying,
 * over-allocating or under-allocating config FAILS CLOSED: every check
 * runs BEFORE the provisional database is renamed into place, and on any
 * failure the scratch directory is cleared, so nothing partial ever
 * survives. An operator who feeds different configs to different nodes
 * gets different chain ids — detectable, never silent — but that is not
 * preventable from inside a node.
 *
 * ── THE SIX RED-TEAM DEFECTS THIS MODULE CLOSES ─────────────────────
 *   L2-F1  supply_tracking is written BEFORE genesis, and the builder
 *          asserts nodus_witness_v2_supply_check == 0 as a
 *          post-condition (the seam does not). The consumer half —
 *          an absent row on a chain that HAS a V2 genesis is now a hard
 *          failure — is in nodus_witness_v2_claims.c.
 *   L2-F2  dna_dist_check_totals is called against the manifest's
 *          total_claimable, which is derived independently as
 *          total_supply_raw − Σ self_stake.
 *   L2-F3  the claim window is pinned to [0, UINT64_MAX]; any other
 *          window is refused.
 *   L2-F4  every seeded validator row is validated against
 *          nodus_witness_v2_epoch_val_rec_ok — the graduation's own
 *          predicate — both before insert and after read-back.
 *   L2-F6  the legacy genesis rules P.1 (exact validator count), P.2
 *          (supply sum) and P.3 (pairwise-distinct pubkeys) have
 *          equivalents here; the legacy path that owned them
 *          (dnac/src/transaction/genesis.c:112-165) is not on this lane.
 *   L1-F1  validator_stats is carried in the genesis bundle
 *          (nodus_witness_v2_bundle.c).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef NODUS_WITNESS_V2_GEN_H
#define NODUS_WITNESS_V2_GEN_H

#include "witness/nodus_witness.h"

#include "dnac/dnac.h"              /* DNAC_PUBKEY_SIZE, DNAC_*_SIZE     */

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** The config schema this build understands. Any other value rejects.
 *
 *  2 — O15J Faz 2 Block 2C added the economic parameters
 *  (blocks_per_year, decimal_unit, inflation_start_block) to the config
 *  and to the canonical encoding. A version-1 config is REFUSED rather
 *  than defaulted: the whole point of this change is that an economic
 *  parameter is never supplied by a structural default. */
#define NODUS_V2_GEN_CONFIG_VERSION   2u

/**
 * The manifest `source_tag` a pure-V2 genesis carries. Distinct from the
 * seam's DNA.LEGACY.TERM.v1 by construction: the tag is what tells a
 * reader WHICH derivation produced the chain. The codec places no
 * constraint on the value beyond 1..DNA_GMAN_SRCTAG_MAX bytes
 * (shared/dnac/manifest_wire.c:138), so this string is a local
 * convention, not a wire requirement.
 *
 * The length EXCLUDES the C NUL: 14 bytes are committed.
 */
#define NODUS_V2_GEN_SOURCE_TAG       "DNA.GENESIS.v1"
#define NODUS_V2_GEN_SOURCE_TAG_LEN   14u

/** The 16-byte, zero-padded domain tag of the canonical config encoding
 *  (the repo's tagged-preimage idiom, shared/dnac/manifest_wire.c:21-30). */
#define NODUS_V2_GEN_CFG_TAG          "DNA.GENCFG.v1"
#define NODUS_V2_GEN_CFG_TAG_LEN      16u

/** source_commit is a bare SHA3-512 digest: 64 bytes, and 64 <=
 *  DNA_GMAN_SRCCOMMIT_MAX (256), so it fits the manifest. */
#define NODUS_V2_GEN_SRCCOMMIT_LEN    64u

/** An allocation's opaque identifier is a fixed 64 bytes. */
#define NODUS_V2_GEN_SRCID_LEN        64u

/** Upper bound on config validators. The exact-count rule (P.1) pins the
 *  accepted value to DNAC_COMMITTEE_SIZE; this is the array bound. */
#define NODUS_V2_GEN_MAX_VALIDATORS   NODUS_V2_ACTIVE_SET_MAX

/** Upper bound on config allocations. Far above any devnet composition;
 *  refuse rather than allocate unbounded. */
#define NODUS_V2_GEN_MAX_ALLOCS       65536u

/**
 * One genesis validator, exactly as it will be committed.
 *
 * `unstake_destination_fp` MUST be 128 lowercase-hex characters followed
 * by a NUL at index 128 — the shape nodus_witness_v2_epoch_val_rec_ok
 * demands. A row that violates it passes genesis (the validator merkle
 * leaf legally hashes 128 zero bytes) and then halts the chain at the
 * first graduation boundary; the builder therefore refuses it here.
 */
typedef struct {
    uint8_t  pubkey[DNAC_PUBKEY_SIZE];                     /* 2592 */
    uint8_t  unstake_destination_pubkey[DNAC_PUBKEY_SIZE]; /* 2592 */
    uint8_t  unstake_destination_fp[DNAC_FINGERPRINT_SIZE];/* 129  */
    uint64_t self_stake;         /* MUST equal DNAC_SELF_STAKE_AMOUNT   */
    uint16_t commission_bps;     /* 0 .. DNAC_COMMISSION_BPS_MAX        */
} nodus_v2_gen_validator_t;

/**
 * One genesis allocation — a distribution leaf, claimable from block 1.
 *
 * `source_id` is an opaque, operator-chosen identifier, UNIQUE within
 * the config; it is the leaf's claim identity and feeds the claim
 * nullifier. `dest_binding` MUST be SHA3-512(claimant ML-DSA-87 pubkey)
 * — the claim pipeline binds the claimant's key to it byte-for-byte
 * (nodus_witness_v2_claims.c:510-517) and a claim whose key does not
 * hash to this value is rejected as a substitution.
 */
typedef struct {
    uint8_t  source_id[NODUS_V2_GEN_SRCID_LEN];
    uint8_t  dest_binding[64];
    uint64_t amount;             /* raw base units; MUST be >= 1        */
} nodus_v2_gen_alloc_t;

/**
 * The whole genesis config.
 *
 * ⚠ ~160 KB. HEAP-ALLOCATE IT (calloc); a stack instance overflows the
 * default thread stack in the same way nodus_witness_t does.
 */
typedef struct {
    uint32_t config_version;     /* NODUS_V2_GEN_CONFIG_VERSION         */
    uint64_t total_supply_raw;   /* == Σ allocations + Σ self_stake     */

    /* ── THE ECONOMIC PARAMETERS (Block 2C) ───────────────────────────
     * All four are hashed into source_commit AND committed as
     * chain_config_history rows — see the ECONOMIC PARAMETERS block in
     * the file header for which binding each one buys. */
    uint64_t epoch_length;       /* MUST equal the compiled
                                  * DNAC_EPOCH_LENGTH — see the
                                  * DETERMINISM note in this header     */
    uint64_t blocks_per_year;    /* MUST equal the compiled
                                  * DNAC_BLOCKS_PER_YEAR                */
    uint64_t decimal_unit;       /* MUST equal the compiled
                                  * DNAC_DECIMAL_UNIT                   */
    uint64_t inflation_start_block;
                                 /* FREE: 0 = emission off for the life
                                  * of the chain; otherwise the first
                                  * minted height. Bounded by
                                  * DNAC_CFG_MAX_INFLATION_START_BLOCK  */

    uint64_t claim_start_height; /* MUST be 0                           */
    uint64_t claim_end_height;   /* MUST be UINT64_MAX                  */

    uint16_t n_validators;       /* MUST equal DNAC_COMMITTEE_SIZE      */
    nodus_v2_gen_validator_t validators[NODUS_V2_GEN_MAX_VALIDATORS];

    uint32_t n_allocs;           /* 1 .. NODUS_V2_GEN_MAX_ALLOCS        */
    const nodus_v2_gen_alloc_t *allocs;  /* caller-owned, n_allocs long */
} nodus_v2_gen_config_t;

/**
 * The canonical config encoding — the ONE byte sequence a config hashes
 * to. Fixed-width or explicitly length-prefixed throughout; every
 * integer big-endian; no floats; no optional fields, therefore no
 * presence bytes and no defaults.
 *
 *   tag                          16   NODUS_V2_GEN_CFG_TAG, zero-padded
 *   config_version              u32be
 *   total_supply_raw            u64be
 *   epoch_length                u64be
 *   blocks_per_year             u64be   ← Block 2C
 *   decimal_unit                u64be   ← Block 2C
 *   inflation_start_block       u64be   ← Block 2C
 *   claim_start_height          u64be
 *   claim_end_height            u64be
 *   validator_count             u16be
 *     × count, sorted pubkey ASC:
 *       pubkey                   2592
 *       unstake_destination_pubkey 2592
 *       unstake_destination_fp    129   (128 hex chars + the NUL byte)
 *       self_stake              u64be
 *       commission_bps          u16be
 *   alloc_count                 u32be
 *     × count, sorted source_id ASC:
 *       source_id_len           u16be   (always NODUS_V2_GEN_SRCID_LEN,
 *                                        written explicitly — never a
 *                                        structural default)
 *       source_id                 len
 *       amount                  u64be
 *       dest_binding               64
 *
 * The config is FULLY VALIDATED before a byte is produced, so an encoded
 * config is by construction a derivable one.
 *
 * @param out      receives a malloc'd buffer the caller must free().
 * @param out_len  receives its length.
 * @return 0 / -1 (invalid config, overflow, or allocation failure).
 */
int nodus_witness_v2_gen_config_encode(const nodus_v2_gen_config_t *cfg,
                                       uint8_t **out, size_t *out_len);

/**
 * source_commit = SHA3-512(canonical config bytes).
 *
 * The value operators compare across nodes BEFORE starting, and the
 * value that binds the config into the chain identity transitively
 * (manifest → genesis BlockID → chain id).
 *
 * @return 0 / -1.
 */
int nodus_witness_v2_gen_source_commit(const nodus_v2_gen_config_t *cfg,
                                       uint8_t out[NODUS_V2_GEN_SRCCOMMIT_LEN]);

/**
 * Validate a config against EVERY genesis rule, touching no filesystem
 * and no database. Exactly the checks nodus_witness_v2_gen_derive runs
 * first, exposed so an operator tool (and a test) can get the verdict
 * without deriving.
 *
 * @return 0 the config is derivable; -1 it is not (the reason is logged).
 */
int nodus_witness_v2_gen_config_validate(const nodus_v2_gen_config_t *cfg);

/**
 * Derive a complete Ledger V2 chain from `cfg` into `data_path`.
 *
 * Fail-closed and all-or-nothing: the whole derivation happens inside a
 * scratch subdirectory and only a COMPLETE chain is renamed up into
 * `data_path` (a same-filesystem rename, therefore atomic). On ANY
 * failure the scratch directory is cleared and `data_path` is untouched.
 *
 * IDEMPOTENT: if `data_path` already holds a pure-V2 chain database this
 * returns 0 without deriving anything and without writing `out_chain32`.
 *
 * @param data_path   the witness data directory.
 * @param cfg         the operator config (heap-allocated; see the type).
 * @param out_chain32 optional; on a fresh derivation receives the
 *                    32-byte derived chain id.
 * @return 0 derived (or already present); -1 refused / failed.
 */
int nodus_witness_v2_gen_derive(const char *data_path,
                                const nodus_v2_gen_config_t *cfg,
                                uint8_t out_chain32[32]);

/**
 * Is `db_path` a PURE-V2 chain database — i.e. does it carry a committed
 * height-0 genesis manifest whose source_tag is NODUS_V2_GEN_SOURCE_TAG?
 *
 * The pure-V2 counterpart of nodus_witness_v2_seam_is_successor, which
 * probes for the seam's own tag and therefore does NOT recognise a chain
 * built by this module.
 *
 * @return 1 yes, 0 no, -1 the database could not be probed.
 */
int nodus_witness_v2_gen_is_pure(const char *db_path);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_V2_GEN_H */
