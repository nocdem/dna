/**
 * @file nodus_witness_v2_gen.h
 * @brief Ledger V2 O15J Faz 1 — the PURE-V2 genesis builder: a complete
 *        Ledger V2 chain derived from a local operator config, with NO
 *        legacy ancestor.
 *
 * This module derives a chain from NOTHING but a config. It is the only
 * way a Ledger V2 chain is born.
 *
 * PROVENANCE (the seam it grew out of is GONE — O15J Faz 3 removed the
 * whole V1→V2 activation ceremony, including nodus_witness_v2_seam.c).
 * That seam derived a successor from a TERMINAL LEGACY DATABASE. This
 * module kept its proven steps 4 and 6-8 verbatim — provisional-DB
 * creation, vset_commit_genesis + domreg_init_genesis + dna_gman_encode
 * + the engine genesis, the supply post-conditions, the genesis bundle
 * persist, and the rename-only-on-COMPLETE discipline — and replaced
 * exactly the steps that were legacy-shaped. The step numbers below are
 * the seam's, kept because they are how this module's own structure is
 * still organised; the file they refer to no longer exists. (The engine
 * genesis is nodus_witness_v2_genesis_cmt since W2; the version-2
 * derivation that called nodus_witness_v2_genesis_ex is deleted by
 * tokenomics-v3 P4.)
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
 * LIVE CONSUMERS (tokenomics-v3 P4, re-derived by grep): the genesis
 * ceremony `nodus-server --derive-v2-genesis` calls
 * nodus_witness_v2_gen_derive_v3 (nodus-server.c run_derive_v2_genesis);
 * a running node reads its identity and document through
 * nodus_witness_v2_gen_stored_chain_id / _stored_doc (the post-open gate
 * in nodus_witness.c, the startup table in nodus_witness_cmt_node.c).
 * The "NO LIVE CONSUMER YET" banner that stood here described Faz 1.
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
 * DNAC_BLOCKS_PER_YEAR, DNAC_DECIMAL_UNIT (nodus_witness_emission.h:48,
 * :53 since tokenomics-v3 P2 cut that header down to them) and
 * DNAC_EPOCH_LENGTH (dnac.h:171) are all `#ifndef`-guarded, so
 * `-D` changes (before P2 deleted the mint: how much a node minted, and
 * still today) where its epoch boundaries fall and the voting-power unit,
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
 *   A. INTO THE CHAIN ID. They are fields of the genesis document's body,
 *      so both the manifest's source_commit and the chain id (the hash
 *      of the completed document, `nodus_witness_v2_gen_chain_id`)
 *      change with them. (Under the deleted version-2 derivation the
 *      route was source_commit → dna_bh2_genesis_block_id → chain id;
 *      the property is the same.)
 *      A mismatched build therefore derives a DIFFERENT CHAIN and cannot
 *      join. An invisible split becomes a loud refusal — that is the
 *      point, and the accepted consequence is that a harness built with
 *      a short tokenomic year derives a different chain than production.
 *      It always WAS a different chain; only the identity was hiding it.
 *      OPERATIONAL NOTE: such a harness must ALSO put its own <BY> in the
 *      genesis config, or this builder refuses to derive at all — the
 *      Genesis Protocol harness does (stagef_up_v2.sh writes
 *      blocks_per_year from STAGEF_BLOCKS_PER_YEAR).
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
 * `inflation_start_block` — RETIRED by tokenomics-v3 P2 (P2-4). Block 2C
 * made it expressible at genesis and committed it as a
 * chain_config_history row (param id 3); P2 deletes the per-block mint it
 * gated and retires param id 3, so the field stays in the config and in
 * the encoding (the document layout is unchanged) but its ONLY legal
 * value is 0 (gen_plan_build refuses any other) and it is no longer
 * committed as a row.
 *
 * ── THE REWARD RESERVE (tokenomics-v3 P2, P2-1) ─────────────────────
 * A version-3 config's `reward_pool_initial` is carved OUT of the fixed
 * `total_supply_raw` (decision file §1: no minting; 200M of 1B is the
 * validator reward reserve): Rule P.2 is
 *   Σ allocations + Σ self_stake + reward_pool_initial == total_supply_raw
 * and supply_tracking.reward_pool is seeded with it. `reward_divisor_log2`
 * has ONE legal value
 * (NODUS_V2_GEN_REWARD_DIVISOR_LOG2) and `payout_interval_epochs` must be
 * >= 1 (nodus_witness_v2_gen_v3_validate).
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
 *          total_supply_raw − Σ self_stake − reward_pool_initial
 *          (tokenomics-v3 P2: the reserve is not claimable).
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
#include "dnac/cmt_genesis.h"       /* cmt_genesis_doc_t (version 3)     */
#include "dnac/cmt_params.h"        /* cmt_consensus_params_t            */

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** The ONLY config schema this build understands (D-18 rev 4). Any
 *  other value is refused by gen_plan_build.
 *
 *  3 — FLEET-TM-R3 W2 (R3-C1, package C1b). The config BODY (the table
 *  below; version 2 was that body alone, with the Block 2C economic
 *  parameters) is carried with `config_version` reading 3, and the
 *  cometbft `GenesisDoc` fields (types/genesis.go:38-46), the consensus
 *  parameters (proto/tendermint/types/params.proto), the committee's
 *  Comet validator rows, `app_hash`, `chain_id` and the tokenomics pool
 *  fields are APPENDED after it.
 *
 *  Version 2 — the pure-V2 chain with a height-0 genesis block — was
 *  closed by R3 W3 (D-17 rev 10 (9)) and its derivation, its constant
 *  (NODUS_V2_GEN_CONFIG_VERSION = 2) and its two public encoders are
 *  DELETED by tokenomics-v3 P4 (OBLIGATION atlas-dec-71525f3b). */
#define NODUS_V2_GEN_CONFIG_VERSION_V3   3u

/** `consensus_protocol` — the one accepted value: cometbft @709fd12b.
 *  0 is invalid rather than "unset": a genesis that does not name its
 *  consensus has no defined validity rules (D-18 rev 4). */
#define NODUS_V2_GEN_CONSENSUS_COMETBFT  1u

/** Storage for a Comet validator `Name` (types/genesis.go:34), INCLUDING
 *  the NUL — the same bound cmt_genesis.h:93 uses. */
#define NODUS_V2_GEN_CMT_NAME_MAX        64u
/** The longest `name` the encoding carries: the length is a u8 and the
 *  storage keeps room for the terminator. */
#define NODUS_V2_GEN_CMT_NAME_LEN_MAX    63u

/** The derived chain id: the first 32 bytes of SHA3-512 over the whole
 *  version-3 encoding with the `chain_id` field itself all-zero. */
#define NODUS_V2_GEN_CHAIN_ID_LEN        32u

/** `app_hash` is the ledger's 64-byte global state root after the
 *  genesis apply (D-19 rev 6 (1): AppHash carries the ledger root). */
#define NODUS_V2_GEN_APP_HASH_LEN        64u

/** The key the completed genesis document is stored under in `cmt_state`
 *  — the REFERENCE's own key string, `genesisDocKey` at
 *  cometbft@709fd12b node/setup.go:551 (written by saveGenesisDoc :606-611,
 *  read by loadGenesisDoc :589-604). NOT `stateKey`: that one holds the
 *  State (D-18 rev 4 corrects D-24 rev 3's wording). */
#define NODUS_V2_GEN_GENESIS_DOC_KEY     "genesisDoc"

/** tokenomics-v3 P2 — the per-epoch payout divisor, log2: payout =
 *  reward_pool >> 16 = floor(pool / 65 536) (decision file
 *  2026-09-22-nodus-tokenomics-v3-operator.md §1 "Her epoch ödülü:
 *  floor(mevcut ödül havuzu / 65.536)"). The document's
 *  `reward_divisor_log2` has THIS one legal value
 *  (nodus_witness_v2_gen_v3_validate); the distribution shifts by it
 *  (nodus_witness_v2_econ.c). */
#define NODUS_V2_GEN_REWARD_DIVISOR_LOG2             16u

/** tokenomics-v3 P2 — the payout interval default, in epochs (decision
 *  §1 "Ödeme her 24 epoch'ta yapılacak"). `_v3_defaults` writes it; a
 *  chain with no stored document (the pre-document fixture lane) uses it
 *  (nodus_witness_v2_payout_interval). */
#define NODUS_V2_GEN_PAYOUT_INTERVAL_EPOCHS_DEFAULT  24u

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
 * VERSION 3 ONLY — one cometbft `GenesisValidator`
 * (cometbft@709fd12b types/genesis.go:30-35), as the container carries it.
 *
 * `address` is the 32-byte witness id of `pub_key`
 * (SHA3-512(pubkey)[0..31] — `cmt_address_hash`, cmt_tmhash.h:255, the
 * same computation as `nodus_chain_config_derive_witness_id`,
 * nodus_witness_chain_config.c:637-652, under the K-1 substitutions).
 * `pub_key` is the RAW ML-DSA-87 key, NOT the proto3 `PublicKey`
 * wrapper: this container is not proto3, and the params' key-type list
 * already says what the reference's key oneof says (D-18 rev 4).
 * `power` is int64 as the reference's field is (genesis.go:33).
 * `name` is free — it may be empty — and display-only in the reference.
 *
 * These rows are CARRIED but not authoritative: the derivation refuses
 * unless every row equals the row derived from the stake entries
 * (address from the key, power = (self_stake + delegated) /
 * decimal_unit). Carrying them is what lets a transmitted document be
 * checked by eye; deriving them is what makes them true.
 */
typedef struct {
    uint8_t  address[NODUS_V2_GEN_CHAIN_ID_LEN];   /* 32, genesis.go:31 */
    uint8_t  pub_key[DNAC_PUBKEY_SIZE];            /* 2592, :32 RAW     */
    int64_t  power;                                /* :33               */
    uint8_t  name_len;                             /* 0 .. 63           */
    char     name[NODUS_V2_GEN_CMT_NAME_MAX];      /* :34, NUL-term.    */
} nodus_v2_gen_cmt_validator_t;

/**
 * The whole genesis config.
 *
 * ⚠ ROUGHLY 255 KB since the version-3 fields arrived — computed from
 * the field widths at the platform's natural alignment, not measured:
 * NODUS_V2_GEN_MAX_VALIDATORS (32 since tokenomics-v3 P3-7; was 30)
 * validator entries of about 5.3 KB (2 × 2592 + 129 + 8 + 2) plus 32
 * Comet rows of about 2.7 KB (32 + 2592 + 8 + 1 + 64), the consensus
 * parameters and the scalars. HEAP-ALLOCATE IT (calloc); a stack
 * instance overflows the default thread stack in the same way
 * nodus_witness_t does, and it does so sooner than before.
 */
typedef struct {
    uint32_t config_version;     /* NODUS_V2_GEN_CONFIG_VERSION_V3      */
    uint64_t total_supply_raw;   /* == Σ allocations + Σ self_stake
                                  * + reward_pool_initial
                                  * (tokenomics-v3 P2 Rule P.2)         */

    /* ── THE ECONOMIC PARAMETERS (Block 2C) ───────────────────────────
     * All four are hashed into source_commit; the first three are
     * committed as chain_config_history rows — see the ECONOMIC
     * PARAMETERS block in the file header for which binding each one
     * buys. tokenomics-v3 P2: inflation_start_block is RETIRED (MUST be
     * 0, no longer committed as a row). */
    uint64_t epoch_length;       /* MUST equal the compiled
                                  * DNAC_EPOCH_LENGTH — see the
                                  * DETERMINISM note in this header     */
    uint64_t blocks_per_year;    /* MUST equal the compiled
                                  * DNAC_BLOCKS_PER_YEAR                */
    uint64_t decimal_unit;       /* MUST equal the compiled
                                  * DNAC_DECIMAL_UNIT                   */
    uint64_t inflation_start_block;
                                 /* RETIRED (tokenomics-v3 P2): MUST be
                                  * 0 — there is no per-block mint to
                                  * start. Kept in the encoding so the
                                  * document layout does not change.    */

    uint64_t claim_start_height; /* MUST be 0                           */
    uint64_t claim_end_height;   /* MUST be UINT64_MAX                  */

    uint16_t n_validators;       /* MUST equal DNAC_COMMITTEE_SIZE      */
    nodus_v2_gen_validator_t validators[NODUS_V2_GEN_MAX_VALIDATORS];

    uint32_t n_allocs;           /* 1 .. NODUS_V2_GEN_MAX_ALLOCS        */
    const nodus_v2_gen_alloc_t *allocs;  /* caller-owned, n_allocs long */

    /* ══ THE VERSION-3 TAIL (D-18 rev 4) ══════════════════════════════
     * Every field below is written by the version-3 encoder AFTER the
     * body (`gen_encode_planned` stops at `allocs`). They are all ZERO in
     * a calloc'd config, and zero is a REFUSAL for the ones that have no
     * legal zero (consensus_protocol, genesis_time_ms), never a
     * default. */

    uint32_t consensus_protocol; /* NODUS_V2_GEN_CONSENSUS_COMETBFT     */
    uint64_t genesis_time_ms;    /* UTC milliseconds, producer-written.
                                  * 0 is REFUSED: the reference fills a
                                  * zero time from the clock
                                  * (types/genesis.go:101-103) and a
                                  * derivation that reads a clock is not
                                  * deterministic (D-18 rev 4)          */
    uint64_t initial_height;     /* types/genesis.go:41. 0 is legal and
                                  * the DOCUMENT completes it to 1
                                  * (:79-81) — but the CONFIG carries
                                  * what was written, so 0 and 1 are two
                                  * different chain ids for one completed
                                  * document. State it, do not silently
                                  * normalise: the encoding is the
                                  * operator's bytes.                   */

    /* proto/tendermint/types/params.proto — every scalar int64, `app`
     * uint64. Defaults MUST be byte-equal to cmt_default_consensus_params
     * (shared/dnac/cmt_params.c:47-110). */
    cmt_consensus_params_t consensus_params;

    /* The committee as cometbft sees it. MUST equal the rows derived
     * from the validators above; a mismatch refuses derivation. */
    uint16_t n_comet_validators;
    nodus_v2_gen_cmt_validator_t
             comet_validators[NODUS_V2_GEN_MAX_VALIDATORS];

    /* The ledger's global state root after the genesis apply — an
     * OUTPUT of the derivation, zero in an operator's config, written by
     * nodus_witness_v2_gen_derive_v3 before the chain id is computed. */
    uint8_t  app_hash[NODUS_V2_GEN_APP_HASH_LEN];

    /* The derived chain id — also an OUTPUT, and zeroed in BOTH hash
     * preimages (it cannot commit to itself). */
    uint8_t  chain_id[NODUS_V2_GEN_CHAIN_ID_LEN];

    /* Tokenomics v2 (atlas-dec-93ff0761d40f5bc16fbae607ab54f458):
     * 200 000 000 NODUS reserve, payout = pool >> 16 per epoch,
     * settlement every 24 epochs. Carried at genesis so the reserve is a
     * committed fact rather than a compiled constant.
     * tokenomics-v3 P2 BINDS all three: reward_pool_initial seeds
     * supply_tracking.reward_pool (Rule P.2 carves it out of
     * total_supply_raw); reward_divisor_log2 MUST equal
     * NODUS_V2_GEN_REWARD_DIVISOR_LOG2; payout_interval_epochs >= 1 is
     * the payday period the chain reads back from its stored document
     * (nodus_witness_v2_payout_interval). */
    uint64_t reward_pool_initial;
    uint64_t reward_divisor_log2;
    uint64_t payout_interval_epochs;
} nodus_v2_gen_config_t;

/*
 * The canonical config BODY — the first part of the version-3 document
 * (the tail is appended after it, see the VERSION 3 banner below).
 * Fixed-width or explicitly length-prefixed throughout; every integer
 * big-endian; no floats; no optional fields, therefore no presence bytes
 * and no defaults.
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
 * tokenomics-v3 P4 (OBLIGATION atlas-dec-71525f3b): the body is no longer
 * a public product of its own. The version-2 entries that exposed it —
 * nodus_witness_v2_gen_config_encode (these bytes alone) and
 * nodus_witness_v2_gen_source_commit (their SHA3-512) — are DELETED with
 * the version-2 derivation nodus_witness_v2_gen_derive. The version-3
 * document, its chain id and its source_commit are the `_v3_` functions
 * below.
 */

/**
 * Validate a config against the SHARED genesis rules (gen_plan_build),
 * touching no filesystem and no database: the schedule constants, the
 * claim window, Rule P.1/P.2/P.3, the validator shape and
 * payout-fingerprint derivation, the allocation set — and, since
 * tokenomics-v3 P4, config_version == 3.
 *
 * It does NOT check the version-3 tail (consensus protocol, genesis
 * time, parameters, Comet rows); a 0 here means "the shared rules pass",
 * not "derivable". The full verdict is nodus_witness_v2_gen_v3_validate,
 * and nodus_witness_v2_gen_derive_v3 runs it.
 *
 * @return 0 the shared rules pass; -1 they do not (the reason is logged).
 */
int nodus_witness_v2_gen_config_validate(const nodus_v2_gen_config_t *cfg);

/**
 * Is `db_path` a PURE-V2 chain database — i.e. does it carry a committed
 * height-0 genesis manifest whose source_tag is NODUS_V2_GEN_SOURCE_TAG?
 *
 * Since O15J Faz 3 this is the ONLY chain-role probe: the activation
 * seam's counterpart (nodus_witness_v2_seam_is_successor, which matched
 * the terminal-legacy tag) was removed with the rest of the ceremony.
 * A database carrying that older tag is therefore no longer recognised
 * as a V2 chain by anything — see the note in nodus_witness.c's
 * post-open gate.
 *
 * @return 1 yes, 0 no, -1 the database could not be probed.
 */
int nodus_witness_v2_gen_is_pure(const char *db_path);

/* ══════════════════════════════════════════════════════════════════════
 * VERSION 3 — THE COMETBFT GENESIS DOCUMENT (D-18 rev 4, W2 / R3-C1b)
 *
 * ── THE CANONICAL ENCODING ────────────────────────────────────────────
 * Every integer BIG-ENDIAN; a signed value is 8-byte two's complement.
 * The body is the table above, with `config_version` reading 3 — it is
 * produced by ONE function (`gen_encode_planned`), never by a second
 * copy of the layout. APPENDED after it, in this order:
 *
 *   consensus_protocol              u32be   1 = cometbft @709fd12b
 *   genesis_time                    u64be   UTC milliseconds
 *   initial_height                  u64be   types/genesis.go:41
 *   block.max_bytes                 i64be   params.proto:25
 *   block.max_gas                   i64be   params.proto:28
 *   evidence.max_age_num_blocks     i64be   params.proto:39
 *   evidence.max_age_duration       i64be   NANOSECONDS — the Go value,
 *                                           NOT the proto wire: the
 *                                           field is a
 *                                           google.protobuf.Duration
 *                                           carrying
 *                                           (gogoproto.stdduration)
 *                                           (params.proto:46-47), which
 *                                           Go holds as a time.Duration
 *                                           = int64 nanoseconds, and
 *                                           that int64 is what this
 *                                           container writes
 *   evidence.max_bytes              i64be   params.proto:52
 *   pub_key_type_count              u16be   1 .. 8
 *     × count:  len                 u16be   1 .. 31
 *               ascii                 len
 *   version.app                     u64be   params.proto:69
 *   abci.vote_extensions_enable_height  i64be  params.proto:81-92
 *   comet_validator_count           u16be   == validator_count
 *     × count, SAME ORDER as the validators above (pubkey ASC):
 *               address               32
 *               pub_key             2592    RAW ML-DSA-87
 *               power               i64be
 *               name_len             u8      <= 63
 *               name            name_len
 *   app_hash                          64
 *   chain_id                          32
 *   reward_pool_initial             u64be
 *   reward_divisor_log2             u64be
 *   payout_interval_epochs          u64be
 *
 * ── THE TWO HASHES, AND WHY THEY ZERO DIFFERENT FIELDS ────────────────
 *   chain_id      = SHA3-512(the whole encoding, tag included, with the
 *                   `chain_id` field all-zero)[0..31]. A field cannot
 *                   commit to itself; zeroing it is the only
 *                   non-circular form, and it is the operator's ruling
 *                   S3 a.
 *   source_commit = SHA3-512(the whole encoding with `chain_id` AND
 *                   `app_hash` all-zero). This is the manifest binding,
 *                   and the manifest is committed BEFORE the genesis
 *                   apply whose global root BECOMES app_hash — so
 *                   app_hash cannot be in its preimage without making
 *                   the derivation circular.
 *
 * ORDER OF THE DERIVATION, therefore: source_commit → ledger genesis →
 * app_hash → chain_id → store the completed document.
 *
 * ── WHAT IS NOT HERE ──────────────────────────────────────────────────
 * The reference's `AppState` (types/genesis.go:45) has no counterpart:
 * this chain's application state is the ledger the derivation builds,
 * not a blob inside the document (the same reason cmt_genesis.h:113-118
 * gives for omitting it).
 * ════════════════════════════════════════════════════════════════════ */

/**
 * Fill the version-3 fields that have a DEFAULT — and only those.
 *
 *   config_version         = 3
 *   consensus_protocol     = cometbft
 *   consensus_params       = cmt_default_consensus_params() verbatim
 *                            (the function itself, never a copy of its
 *                            values: the byte-equality test then proves
 *                            the ENCODING, not a transcription)
 *   reward_pool_initial    = 200 000 000 × 10^8
 *   reward_divisor_log2    = 16
 *   payout_interval_epochs = 24
 *
 * `genesis_time_ms`, `initial_height`, the validators, the allocations
 * and the economic parameters are NOT touched: none of them has a
 * defensible default and each reaches the chain id.
 *
 * @return 0 / -1 on NULL.
 */
int nodus_witness_v2_gen_v3_defaults(nodus_v2_gen_config_t *cfg);

/**
 * Derive the Comet validator rows from the stake entries, in the
 * canonical validator order (pubkey ASC — the encoding's order).
 *
 *   address = SHA3-512(pubkey)[0..31]
 *   power   = (self_stake + delegated) / decimal_unit, integer division
 *
 * DELEGATED IS ZERO AT GENESIS and this is not an assumption: the config
 * has no delegation input at all, gen_seed_state writes every validator
 * row with total_delegated = external_delegated = 0, and it ASSERTS the
 * `delegations` table empty before genesis (nodus_witness_v2_gen.c's
 * must_be_empty list). If a later version adds genesis delegations, this
 * is the one place that changes.
 *
 * An existing row for the same pubkey KEEPS its `name`; every other
 * field is overwritten. `n_comet_validators` becomes `n_validators`.
 *
 * @return 0 / -1 (NULL, a config the shared rules refuse, or a power
 *         that does not fit int64).
 */
int nodus_witness_v2_gen_v3_fill_comet_rows(nodus_v2_gen_config_t *cfg);

/**
 * The VERSION-3 verdict: the shared rules (config_validate) plus every
 * version-3 rule — consensus_protocol == cometbft, genesis_time_ms != 0,
 * initial_height <= INT64_MAX, the consensus params' own ValidateBasic
 * (cmt_consensus_params_validate_basic), at least one key type, every
 * name_len <= 63, and ROW EQUALITY: every carried Comet row must equal
 * the row derived from the stake entries.
 *
 * `app_hash` and `chain_id` are NOT constrained here — they are outputs,
 * zero in an operator's config and set by the derivation.
 *
 * @return 0 derivable; -1 refused (the reason is logged).
 */
int nodus_witness_v2_gen_v3_validate(const nodus_v2_gen_config_t *cfg);

/**
 * The canonical version-3 encoding of `cfg`, exactly as the table above.
 *
 * SHAPE ONLY: this refuses a config whose bytes cannot be WRITTEN
 * (wrong version, a count or length out of range, a name longer than 63)
 * but NOT one whose Comet rows disagree with the stake entries — that is
 * a derivation rule, and an encoder that enforced it could not produce
 * the very vectors a test needs to prove the rows reach the chain id.
 *
 * @param out      receives a malloc'd buffer the caller must free().
 * @param out_len  receives its length.
 * @return 0 / -1.
 */
int nodus_witness_v2_gen_v3_encode(const nodus_v2_gen_config_t *cfg,
                                   uint8_t **out, size_t *out_len);

/**
 * The STRICT inverse of the encoder: exact length, every count and
 * length bound checked, no trailing byte, and a version field that must
 * read 3 — a version-2 encoding is REFUSED here rather than read as a
 * prefix.
 *
 * @param buf/len     the encoded document.
 * @param cfg_out     caller-allocated (~240 KB — calloc it, never a
 *                    stack instance), fully overwritten on success.
 * @param allocs_out  receives a malloc'd allocation array the caller
 *                    must free() AFTER it is done with `cfg_out`;
 *                    `cfg_out->allocs` points into it.
 * @return 0 / -1.
 */
int nodus_witness_v2_gen_v3_decode(const uint8_t *buf, size_t len,
                                   nodus_v2_gen_config_t *cfg_out,
                                   nodus_v2_gen_alloc_t **allocs_out);

/**
 * chain_id = SHA3-512(version-3 encoding with `chain_id` zeroed)[0..31].
 * Identical whether `cfg->chain_id` holds the answer or zeros — that is
 * what makes a stored document checkable against itself.
 * @return 0 / -1.
 */
int nodus_witness_v2_gen_chain_id(const nodus_v2_gen_config_t *cfg,
                                  uint8_t out32[NODUS_V2_GEN_CHAIN_ID_LEN]);

/**
 * source_commit = SHA3-512(version-3 encoding with `chain_id` AND
 * `app_hash` zeroed) — the manifest's binding for a version-3 chain.
 * @return 0 / -1.
 */
int nodus_witness_v2_gen_v3_source_commit(
        const nodus_v2_gen_config_t *cfg,
        uint8_t out[NODUS_V2_GEN_SRCCOMMIT_LEN]);

/**
 * Project a version-3 config onto the PORT's own genesis document
 * (shared/dnac/cmt_genesis.h:119-131) and run the reference's
 * `ValidateAndComplete` (types/genesis.go:69-106) over it.
 *
 * The milliseconds become a {seconds, nanos} pair and are range-checked
 * with cmt_time_validate BEFORE the document is built: the reference's
 * ValidateAndComplete tests a time only for Go's ZERO (:101), so an
 * out-of-range instant would pass it and fail much later inside the
 * codec. A zero `genesis_time_ms` is refused here for the same reason
 * D-18 gives — the completion branch reads a clock.
 *
 * MUTATES `out` the way the reference mutates its document: an
 * initial_height of 0 becomes 1, an absent address is filled from the
 * key, absent params become the defaults.
 *
 * @param out   caller-owned document; `out->validators` is set to `vals`.
 * @param vals  storage for at least `cfg->n_comet_validators` rows.
 * @param cap   how many rows `vals` holds.
 * @return 0; -1 on a refusal from either side (the reason is logged).
 */
int nodus_witness_v2_gen_to_cmt_doc(const nodus_v2_gen_config_t *cfg,
                                    cmt_genesis_doc_t *out,
                                    cmt_genesis_validator_t *vals,
                                    size_t cap);

/**
 * Derive a complete VERSION-3 chain from `cfg` into `data_path` — the
 * ONLY chain derivation this build has (the ceremony:
 * `nodus-server --derive-v2-genesis`).
 *
 * The steps, in order (D-18 rev 5 (1) as amended by R3 W3):
 *   · the database is created and migrated to the live schema rung
 *     (S16 since tokenomics-v3 P2) BEFORE the ledger genesis runs;
 *   · the SYSTEM state is seeded from the config (validators,
 *     validator_stats.active_count, supply_tracking with the reward
 *     reserve, the committed econ band), then the genesis validator-set
 *     snapshots (epoch 0 and E) and the domain registry;
 *   · the genesis apply is the Comet entry
 *     (nodus_witness_v2_genesis_cmt) — NO height-0 `v2_blocks` row is
 *     written at all (D-19 rev 6 withdrew the genesis block) — which
 *     also writes the epoch-0 balance copy;
 *   · `app_hash` is the global root that apply returns, `chain_id` is
 *     the hash of the completed document, and the COMPLETED DOCUMENT
 *     BYTES are stored in `cmt_state` under "genesisDoc" (the
 *     reference's key, node/setup.go:551);
 *   · the database is named witness_<chain_id[0..15] hex>.db — a file
 *     SELECTION convention, never the identity.
 *
 * `stateKey` is NOT written here: in the reference the State is made on
 * the node's FIRST START (node/setup.go:581 LoadFromDBOrGenesisDoc).
 *
 * Fail-closed and all-or-nothing: a scratch subdirectory, a rename only
 * on COMPLETE, and the scratch cleared on every exit.
 *
 * IDEMPOTENCY: a chain built from THIS config (same source_commit) is a
 * success and derives nothing; a chain built from a different one
 * refuses. Both verdicts come from the committed manifest; the genesis
 * APPLY itself has no idempotent branch at all.
 *
 * @param out_chain32 optional; on a fresh derivation receives the
 *                    32-byte derived chain id.
 * @return 0 derived (or already present); -1 refused / failed.
 */
int nodus_witness_v2_gen_derive_v3(const char *data_path,
                                   const nodus_v2_gen_config_t *cfg,
                                   uint8_t out_chain32[NODUS_V2_GEN_CHAIN_ID_LEN]);

/**
 * The stored genesis DOCUMENT of an OPEN version-3 chain —
 * CANONICAL-STRICT, the four checks of `..._stored_chain_id` below.
 *
 * This is the accessor `..._stored_chain_id` is built on: the four checks
 * are performed HERE, once, and that function is a wrapper that returns
 * the id out of the document this one decoded. A caller that needs the
 * whole document — the startup table's
 * `LoadStateFromDBOrGenesisDocProvider` (node/setup.go:556-587,
 * nodus_witness_cmt_node.c) — must not re-implement the checks, and a
 * caller that needs only the id must not decode ~56 KB twice.
 *
 * Read the four checks, and WHY EACH IS LOAD-BEARING, at
 * `..._stored_chain_id` — they are stated there once and not repeated.
 * The `chain_id` field of `*cfg_out` is the RECOMPUTED hash, which check
 * 4 has just proved equal to the stored field.
 *
 * @param cfg_out    caller-owned, ~240 KB: NEVER A STACK OBJECT. Filled
 *                   only on success; its contents are undefined on -1.
 * @param allocs_out receives the allocation list the decoder allocated,
 *                   which `cfg_out->allocs` points at. The CALLER frees
 *                   it with `free()` — on success and on failure alike;
 *                   it is set to NULL when there is nothing to free.
 * @return 0; -1 (no row, a row that does not decode, a document that
 *         breaks a genesis rule, a document that is not in canonical
 *         form, a chain_id field that does not hash to its own document,
 *         or a DB fault — never a value).
 */
int nodus_witness_v2_gen_stored_doc(nodus_witness_t *w,
                                    nodus_v2_gen_config_t *cfg_out,
                                    nodus_v2_gen_alloc_t **allocs_out);

/**
 * tokenomics-v3 P2 — IS a genesis document stored? Three-valued, because
 * `nodus_witness_v2_gen_stored_doc` answers -1 both for "no row" and for
 * a fault and a caller that must choose between "this chain has no
 * document" and "this node cannot read its document" needs the two
 * apart. Checks only PRESENCE (a non-empty "genesisDoc" row in
 * `cmt_state`); reading the document is still `..._stored_doc`'s job,
 * with all four of its checks.
 *
 * @return 1 present; 0 absent (no `cmt_state` table — below S14 — or no
 *         row); -1 a probe fault (never "absent").
 */
int nodus_witness_v2_gen_stored_doc_present(nodus_witness_t *w);

/**
 * The stored chain id of an OPEN version-3 chain — CANONICAL-STRICT.
 *
 * Load "genesisDoc" from `cmt_state`, then FOUR checks before a byte is
 * returned, because this value names the chain a node believes it is on:
 *   1. the document DECODES strictly (every bound, no trailing byte);
 *   2. its CONTENT RULES hold — `nodus_witness_v2_gen_v3_validate`
 *      passes: the Comet rows equal the rows the stake entries produce,
 *      the supply equation balances, the claim window is the pinned one,
 *      every validator is writable-shaped;
 *   3. the stored bytes are the CANONICAL FORM — re-encoding the decoded
 *      document reproduces them byte for byte;
 *   4. the stored `chain_id` field EQUALS SHA3-512(the document with
 *      that field blanked)[0..31], so those 32 bytes are a checksum of
 *      the other ~56 KB and not an assertion whoever can write the row
 *      gets to make.
 * Any failure is -1 with a log naming which check failed; a one-byte
 * edit anywhere in the row is a refusal, never a different chain id.
 *
 * ALL FOUR ARE LOAD-BEARING — none subsumes another, and check 3 exists
 * because check 2 cannot do its job alone:
 *   · a SWAPPED pair of validator entries passes 1, 2 and 4 and fails
 *     only 3. It passes 2 because `gen_plan_build` SORTS an unsorted
 *     array rather than refusing it, so both sides of the row comparison
 *     are normalised before they meet; it passes 4 because the re-encode
 *     that produces the hash sorts them back. Only comparing the stored
 *     BYTES with the canonical ones sees it. The same normalisation
 *     applies to the allocation list, and to any normalisation added
 *     later — which is why 3 is a byte comparison and not a list of
 *     order checks;
 *   · a FLIPPED byte inside the chain_id field passes 1, 2 and 3 — it
 *     round-trips through the encoder — and fails only 4;
 *   · a Comet row whose power does not match its stake passes 1, 3 and 4
 *     — it is carried verbatim and re-hashes to itself — and fails
 *     only 2.
 *
 * ONE CONSEQUENCE WORTH KNOWING: check 2 runs the shared genesis rules,
 * which include the equality of the document's economic parameters with
 * the COMPILED ones. A binary built with different -DDNAC_EPOCH_LENGTH /
 * BLOCKS_PER_YEAR / DECIMAL_UNIT therefore REFUSES to read an identity
 * out of a document it could not have derived — the same fail-closed
 * rule the derivation applies, moved to the reader.
 *
 * nodus_witness_v2_chain_id (nodus_witness_v2_claims.c) reads the
 * height-0 block row where one exists and FALLS BACK to this accessor
 * where none does (W2 / R3-C1a) — so a version-3 chain and every older
 * chain are served by the same call, and no chain that has the row sees
 * a different answer.
 *
 * Only `w->db` is used, so a read-only handle with nothing else set is
 * enough — which matters for the offline ceremony (nodus-server.c reads
 * the landed chain id through this accessor with nothing but `db` set)
 * and for the witness's own post-open gate: since R3 W3 (package C2a)
 * `witness_post_open_gate` (nodus_witness.c) recognises a version-3
 * chain by its S14 stores AND this accessor succeeding, and sets the
 * chain role from the document's id — the W2-era refusal of a
 * version-3 chain at open is gone (D-17 rev 10 (9), as built: rev 11).
 *
 * @return 0; -1 (no row, a row that does not decode, a document that is
 *         not canonical, a chain_id field that does not hash to its own
 *         document, or a DB fault — never a value).
 */
int nodus_witness_v2_gen_stored_chain_id(
        nodus_witness_t *w, uint8_t out32[NODUS_V2_GEN_CHAIN_ID_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_V2_GEN_H */
