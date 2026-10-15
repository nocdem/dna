/**
 * @file ledger.h
 * @brief DNAC Transaction Ledger API
 *
 * The transaction ledger provides a permanent, auditable record of all
 * transactions with Merkle proofs for verification.
 *
 * Features:
 * - Sequential transaction numbering
 * - Incremental Merkle tree for chain integrity
 * - Supply tracking (genesis, burned, current)
 * - Transaction existence proofs
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef DNAC_LEDGER_H
#define DNAC_LEDGER_H

#include "dnac.h"
#include "dnac/transaction.h"
#include "dnac/block.h"

#include <string.h>  /* for memcmp in dnac_is_native_token inline helper */

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Constants
 * ========================================================================== */

/** Merkle root size (SHA3-512) */
#define DNAC_MERKLE_ROOT_SIZE       64

/** Maximum Merkle proof depth (leaf-to-root path length).
 *  Matches nodus/src/witness/nodus_witness_merkle.c. */
#define DNAC_MERKLE_MAX_DEPTH       32

/* ============================================================================
 * Merkle Inclusion Proof (Anchored Design — 2026-04-16)
 *
 * Generic leaf-to-root proof for any Merkle tree in DNAC. Used for both:
 *   - UTXO inclusion in state_root  (block.state_root)
 *   - TX inclusion in tx_root       (block.tx_root)
 *
 * The "root" field stores the tree root against which this proof verifies.
 * The caller is responsible for matching the root to a BFT-anchored block
 * header via dnac_block_anchor_t (Task 20).
 *
 * RFC 6962 domain tags (MUST match nodus/src/witness/nodus_witness_merkle.c):
 *   leaf_hash(d)      = SHA3-512(0x00 || d)
 *   inner_hash(L, R)  = SHA3-512(0x01 || L || R)
 * ========================================================================== */
typedef struct {
    /* Composite leaf digest (pre-tag). For UTXO proofs this is the output of
     * nodus_witness_merkle_leaf_hash(nullifier || owner || amount || token_id
     *                                 || tx_hash || output_index
     *                                 || unlock_block). For TX
     * proofs this is the raw tx_hash. In either case, the verifier applies
     * the 0x00 leaf tag internally. */
    uint8_t  leaf_hash[DNAC_MERKLE_ROOT_SIZE];

    /* Sibling hashes along the leaf-to-root path, leaf level first. */
    uint8_t  siblings[DNAC_MERKLE_MAX_DEPTH][DNAC_MERKLE_ROOT_SIZE];

    /* Per-level sibling position:
     *   directions[i] == 1  -> sibling is on the LEFT, cur on RIGHT
     *   directions[i] == 0  -> sibling is on the RIGHT, cur on LEFT
     */
    uint8_t  directions[DNAC_MERKLE_MAX_DEPTH];

    /* Number of valid siblings/directions (0 = single-leaf tree). */
    int      proof_length;

    /* Expected root (state_root or tx_root). */
    uint8_t  root[DNAC_MERKLE_ROOT_SIZE];
} dnac_merkle_proof_t;

/* ============================================================================
 * Client Query Functions
 * ========================================================================== */

/**
 * @brief Get supply information from witnesses
 *
 * @param ctx DNAC context
 * @param genesis_out Output genesis supply
 * @param burned_out Output total burned
 * @param current_out Output current supply
 * @return DNAC_SUCCESS or error code
 */
int dnac_ledger_get_supply(dnac_context_t *ctx,
                           uint64_t *genesis_out,
                           uint64_t *burned_out,
                           uint64_t *current_out);

/**
 * @brief Verify a Merkle proof against its embedded root.
 *
 * Pure function — no DB, no network, no allocation. Hashes the leaf with
 * the RFC 6962 leaf tag (0x00), walks up the sibling chain with the inner
 * tag (0x01), and compares the result to proof->root.
 *
 * This does NOT verify that proof->root is BFT-trusted. Pair with
 * dnac_anchor_verify (Task 20+) for full trust.
 *
 * @param proof Proof to verify
 * @return true on hash match, false on any mismatch or invalid input.
 */
bool dnac_merkle_verify_proof(const dnac_merkle_proof_t *proof);

/**
 * @brief Compute the composite UTXO leaf digest (pre-leaf-tag).
 *
 * Mirrors the server-side `nodus_witness_merkle_leaf_hash` byte layout
 * exactly — a single-bit drift anywhere here silently breaks every
 * anchored UTXO proof in the chain. Layout (all little-endian, 340 bytes,
 * no tag — root-layout round K1, 2026-09-25 appended unlock_block):
 *
 *   SHA3-512( nullifier(64)
 *           || owner_fingerprint(128, NUL-padded)
 *           || amount_le(8)
 *           || token_id(64)
 *           || tx_hash(64)
 *           || output_index_le(4)
 *           || unlock_block_le(8) )
 *
 * The output is the "leaf_hash" field of `dnac_merkle_proof_t`. The
 * verifier (`dnac_merkle_verify_proof`) applies the RFC 6962 0x00 leaf
 * tag internally, so callers MUST NOT pre-tag.
 *
 * @param nullifier     64-byte nullifier.
 * @param owner         NUL-terminated owner fingerprint (<= 128 bytes used).
 * @param amount        UTXO amount in raw base units.
 * @param token_id      64-byte token identifier (zeros = native DNAC).
 * @param tx_hash       64-byte creating transaction hash.
 * @param output_index  UTXO index within its transaction.
 * @param out           Output buffer, DNAC_MERKLE_ROOT_SIZE bytes.
 * @param unlock_block  The coin's unlock_block (0 = spendable) — the
 *                      witness's `ub` field; hashed last.
 * @return 0 on success, -1 on NULL arg or OpenSSL failure.
 */
int dnac_utxo_compute_leaf_hash(const uint8_t *nullifier,
                                 const char *owner,
                                 uint64_t amount,
                                 const uint8_t *token_id,
                                 const uint8_t *tx_hash,
                                 uint32_t output_index,
                                 uint8_t out[DNAC_MERKLE_ROOT_SIZE],
                                 uint64_t unlock_block);

/* ============================================================================
 * Block Anchor — binds a block header to its 2f+1 PRECOMMIT signatures
 *
 * An anchor proves that a block_hash (and thus the state_root and tx_root it
 * contains) was finalized by BFT consensus. Clients fetch an anchor, verify
 * its commit_cert against the trusted_state's roster, and then trust the
 * state_root/tx_root inside for Merkle proof verification.
 * ========================================================================== */

#define DNAC_DILITHIUM5_SIG_SIZE 4627
#define DNAC_WITNESS_ID_SIZE     32

typedef struct {
    /* Fingerprint of the signing witness — first DNAC_WITNESS_ID_SIZE bytes
     * of SHA3-512(pubkey). Matches the convention used by the witness cluster
     * BFT code when identifying signers. */
    uint8_t signer_id[DNAC_WITNESS_ID_SIZE];

    /* Dilithium5 signature over the block's block_hash. */
    uint8_t signature[DNAC_DILITHIUM5_SIG_SIZE];
} dnac_witness_signature_t;

typedef struct {
    /* The block header whose block_hash is signed. The client MUST
     * recompute the hash from the header fields before trusting the
     * stored block_hash (prevents a malicious peer from sending a header
     * with one hash and signatures over a different hash). */
    dnac_block_t             header;

    /* Up to DNAC_MAX_WITNESSES_COMPILE_CAP PRECOMMIT signatures.
     * Duplicate signers are counted once; unknown signers are rejected. */
    dnac_witness_signature_t sigs[DNAC_MAX_WITNESSES_COMPILE_CAP];
    int                      sig_count;
} dnac_block_anchor_t;

/* ============================================================================
 * Trusted State — per-chain runtime trust anchor
 *
 * One instance per chain the client tracks. Populated by dnac_genesis_verify
 * (Phase 5) from verified genesis bytes. All subsequent block/UTXO/TX
 * verification goes through this struct — NO hardcoded roster lookups
 * elsewhere in the code.
 * ========================================================================== */

typedef struct {
    /* chain_id (= genesis block hash) — the single hardcoded value this
     * trust state derives from. */
    uint8_t                 chain_id[DNAC_BLOCK_HASH_SIZE];

    /* Chain definition (witness pubkeys, params, token info) — extracted
     * from the verified genesis block. */
    dnac_chain_definition_t chain_def;

    /* Most recently verified block anchor. Updated as the client follows
     * the chain. Starts at the genesis block after bootstrap. */
    dnac_block_anchor_t     latest_verified_anchor;
} dnac_trusted_state_t;

/**
 * Verify a block anchor: recomputes the block hash, checks that 2f+1
 * valid Dilithium5 signatures from the trusted roster cover it.
 *
 * Pure function — no DB, no network, no allocation beyond sig verify.
 *
 * @return true if the anchor is valid, false otherwise.
 */
bool dnac_anchor_verify(const dnac_block_anchor_t *anchor,
                         const dnac_trusted_state_t *trust);

/**
 * Verify genesis block bytes against a hardcoded chain_id.
 *
 * Decodes the input, checks it's genesis (height 0, prev_hash zeros,
 * is_genesis flag set), recomputes the block hash, and compares to
 * expected_chain_id. On success, populates trust_out with the verified
 * chain_def and chain_id. latest_verified_anchor is left zeroed; the
 * caller must set it via dnac_anchor_verify.
 *
 * Pure function — no DB, no network.
 *
 * @param bytes             Encoded genesis block (from dnac_block_encode).
 * @param len               Number of bytes.
 * @param expected_chain_id Hardcoded 64-byte chain_id to verify against.
 * @param trust_out         [out] Populated trusted state on success.
 * @return true on success, false on any verification failure.
 */
bool dnac_genesis_verify(const uint8_t *bytes, size_t len,
                          const uint8_t expected_chain_id[DNAC_BLOCK_HASH_SIZE],
                          dnac_trusted_state_t *trust_out);

/* ============================================================================
 * High-level verification wrappers (Tasks 29+)
 *
 * These orchestrate the three primitives (merkle_verify_proof,
 * anchor_verify, chain_id match) into full end-to-end trust checks that
 * client code can call directly.
 * ========================================================================== */

/**
 * Verify a UTXO belongs to a BFT-finalized state.
 *
 * Checks (in order):
 *   1. proof->root matches anchor->header.state_root
 *   2. dnac_anchor_verify(anchor, trust) passes
 *   3. dnac_merkle_verify_proof(proof) passes
 *
 * The caller supplies a proof whose leaf_hash is the composite UTXO digest
 * (see nodus_witness_merkle_leaf_hash for the composition rule).
 *
 * @return true only if all three checks succeed.
 */
bool dnac_utxo_verify_anchored(const dnac_merkle_proof_t *state_root_proof,
                                const dnac_block_anchor_t *anchor,
                                const dnac_trusted_state_t *trust);

/**
 * Verify a historical TX belongs to a BFT-finalized block.
 *
 * Checks (in order):
 *   1. proof->root matches anchor->header.tx_root
 *   2. dnac_anchor_verify(anchor, trust) passes
 *   3. dnac_merkle_verify_proof(proof) passes
 *
 * The proof's leaf_hash should be the raw TX hash (the server-side
 * build_tx_proof applies the 0x00 leaf tag internally, symmetric to the
 * client verifier).
 */
bool dnac_tx_verify_anchored(const dnac_merkle_proof_t *tx_root_proof,
                              const dnac_block_anchor_t *anchor,
                              const dnac_trusted_state_t *trust);

/**
 * Compare a token_id to the chain's native_token_id (committed in genesis).
 *
 * Inline — safe to call in hot paths. Not a consensus rule — just a
 * convenience helper. See dnac/include/dnac/token_types.h for code-level
 * type prefix constants.
 */
static inline bool dnac_is_native_token(const uint8_t token_id[DNAC_TOKEN_ID_SIZE],
                                         const dnac_trusted_state_t *trust) {
    if (!token_id || !trust) return false;
    return memcmp(token_id, trust->chain_def.native_token_id,
                   DNAC_TOKEN_ID_SIZE) == 0;
}

#ifdef __cplusplus
}
#endif

#endif /* DNAC_LEDGER_H */
