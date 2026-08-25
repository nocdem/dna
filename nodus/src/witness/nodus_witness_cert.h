/**
 * Nodus — Witness Sync Cert Preimage Signing
 *
 * Phase 7.5 — wire-independent cert preimage signing for sync cert
 * verification. Each witness signs a fixed 144-byte preimage at
 * precommit time; sync receivers reconstruct the preimage locally and
 * verify each cert against the senders' Dilithium5 public key.
 *
 * The preimage layout is:
 *
 *   [0..7]    domain tag = {'c','e','r','t',0,0,0,0}    (8 bytes)
 *   [8..71]   block_hash                                (64 bytes)
 *   [72..103] voter_id                                  (32 bytes)
 *   [104..111] height (little-endian)                   (8 bytes)
 *   [112..143] chain_id                                 (32 bytes)
 *
 * Total: 144 bytes. The 8-byte ASCII-and-NUL domain tag prevents
 * cross-protocol signature reuse and is used as a byte array literal,
 * never as a C string (no implicit NUL terminator).
 *
 * @file nodus_witness_cert.h
 */

#ifndef NODUS_WITNESS_CERT_H
#define NODUS_WITNESS_CERT_H

#include "nodus/nodus_types.h"
#include "witness/nodus_witness.h"
#include "protocol/nodus_tier3.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NODUS_WITNESS_CERT_PREIMAGE_LEN  144

/** 8-byte domain tag — declared extern so callers and tests reference
 * the same authoritative copy. */
extern const uint8_t NODUS_WITNESS_CERT_DOMAIN_TAG[8];

/**
 * Compute the 144-byte cert preimage into out_buf.
 *
 * Pure function — no DB access, no global state. All inputs are
 * passed explicitly and the layout is byte-exact so that signers and
 * verifiers always agree.
 *
 * @param block_hash 64-byte block hash
 * @param voter_id   32-byte witness ID of the precommit signer
 * @param height     block height the cert attests to
 * @param chain_id   32-byte chain identifier
 * @param out_buf    caller-owned 144-byte buffer
 * @return 0 on success, -1 on NULL input
 */
int nodus_witness_compute_cert_preimage(const uint8_t *block_hash,
                                          const uint8_t *voter_id,
                                          uint64_t height,
                                          const uint8_t *chain_id,
                                          uint8_t *out_buf);

/**
 * Verify a batch of sync certificates against the TRANSIENT transport
 * roster.
 *
 * **RETIRED FROM THE LIVE CONSENSUS PATHS (O15G).** This form resolves each
 * signer's pubkey from `w->roster`, the DHT-propagated transport mesh, which
 * is timing-dependent (a signer absent from the local roster is silently
 * dropped). At N>7 that timing dependence wedged honest nodes on a
 * cryptographically-valid quorum cert — the O15F 7→20 defect. The live COMMIT
 * path (nodus_witness_bft.c) and the sync replay path for heights >= 2
 * (nodus_witness_sync.c) now use nodus_witness_verify_certs_snapshot(), which
 * binds the pubkey source to the committed committee snapshot.
 *
 * The ONE remaining caller is the UNANCHORED genesis (db_height == 1) leg of
 * legacy sync — a genesis-creating founder node, or a legacy fixture that
 * reached replay WITHOUT a DISCOVER bootstrap (w->g_quorum_cdh_set == false).
 * There no snapshot authority is committed yet and no bootstrap anchor exists,
 * so the roster + genesis-TX chain_def seat count is the only source.
 *
 * This is NOT a sanctioned steady-state path. Design §7.6 forbids a DHT-roster
 * genesis authority, and O15G §8.1 CLOSES it for the bootstrapped-joiner case:
 * once a joiner has the DISCOVER-agreed chain_def hash (g_quorum_cdh_set), the
 * genesis leg binds the synced genesis to that anchor and verifies block-1
 * certs against the ANCHORED chain_def's own validator set
 * (nodus_witness_sync_genesis_anchor_check), never the roster. Do NOT
 * re-introduce this roster form on any anchored or height >= 2 path.
 *
 * For each cert, looks up the voter_id in the roster, reconstructs
 * the cert_preimage from the caller-supplied (block_hash, height,
 * chain_id) and the cert's own voter_id, and Dilithium5-verifies the
 * signature against the roster pubkey. Voters not in the roster, or
 * verification failures, are silently dropped from the count.
 *
 * **CRITICAL:** the caller MUST pass a block_hash that was recomputed
 * locally (e.g. via nodus_witness_compute_block_hash on locally-replayed
 * data), NEVER the wire-supplied block_hash from the sync_rsp. Phase 11
 * task 11.4 is the wiring point.
 *
 * @param block_hash   64-byte block hash, locally recomputed
 * @param height       block height the cert attests to
 * @param chain_id     32-byte chain identifier
 * @param roster       witness roster used to resolve voter pubkeys
 * @param certs        cert array from a sync_rsp
 * @param cert_count   length of certs[]
 * @param quorum       minimum verified count for success
 * @return number of verified certs (>= quorum) on success, -1 on
 *         insufficient quorum
 */
int nodus_witness_verify_sync_certs(const uint8_t *block_hash,
                                      uint64_t height,
                                      const uint8_t *chain_id,
                                      const nodus_witness_roster_t *roster,
                                      const nodus_t3_sync_cert_t *certs,
                                      uint32_t cert_count,
                                      uint32_t quorum);

/**
 * Verify a batch of certificates against the COMMITTED committee snapshot
 * for the block's height — the O15G snapshot-authority verifier.
 *
 * Cert acceptance is a judgement about WHO WAS PERMITTED TO SIGN a block at
 * its height. That is committed consensus state (the validator_set_snapshots
 * row for epoch(height)), identical on every node — NOT the verifier's present
 * transport mesh. This function binds signer-pubkey resolution to that
 * authority so two honest nodes reach the same verdict regardless of their
 * roster propagation state (Determinism G-D1).
 *
 * Layer A — authority resolution (roster-free):
 *   - successor chain (w->v2_successor): nodus_witness_v2_epoch_authority_for_height;
 *   - legacy chain:                      nodus_committee_get_for_block(_alloc).
 *   The committee's canonical voter_ids are RE-DERIVED verify-time from each
 *   member's pubkey via nodus_chain_config_derive_witness_id — the stored
 *   voter_id is never trusted. A stored-vs-derived mismatch, or a duplicate
 *   member / pubkey in the snapshot, is a LOCAL AUTHORITY CORRUPTION.
 *
 * Layer B — unique-signature count (POLICY_LEGACY_CERT, order-free):
 *   legacy certs are arrival-ordered (no canonical sort — bft.c collection
 *   dedups by pubkey, does not sort), so signers are walked in WIRE ORDER;
 *   a non-member signer, a duplicate signer (seen[] set) and a bad signature
 *   are each dropped from the count (NEVER a whole-batch reject — that would
 *   hand a Byzantine relayer a liveness wedge, Security G-S2). Only unique
 *   valid committee signers count, verified over the UNCHANGED 144-byte
 *   compute_cert_preimage. Success requires verified >= quorum, where quorum
 *   comes ONLY from the resolved snapshot (never w->bft_config.quorum).
 *
 * Result algebra (nodus_witness_v2_result.h; -2/-3 are BOTH non-verdicts, so
 * their boundary cannot fork the chain — it only steers local retry):
 *   >= quorum          VALID (returns the unique-valid signer count)
 *   -1 CONSENSUS_INVALID   quorum not met against a KNOWN authority (peer-rotate)
 *   -3 NOT_YET_LINKABLE    no committed authority for this epoch yet, and the
 *                          epoch boundary that freezes it has NOT passed on
 *                          this node (prerequisite sync + bounded backoff)
 *   -2 INTERNAL_FAULT      local corruption / unreadable snapshot / derive or
 *                          alloc failure, OR a snapshot that MUST exist
 *                          (its boundary already passed) yet is missing
 *                          (fail-closed; NEVER a negative vote)
 *
 * **CRITICAL:** the caller MUST pass a block_hash recomputed locally, never
 * the wire-supplied one — same discipline as nodus_witness_verify_sync_certs.
 * This function does NOT verify genesis (height 1) certs: the genesis exemption
 * stays with the legacy roster leg (design §7.6).
 *
 * @param w           witness context (DB open; carries v2_successor + chain role)
 * @param block_hash  64-byte block hash, locally recomputed
 * @param height      block height the cert attests to (>= 2)
 * @param chain_id    32-byte chain identifier (as the signer used at sign time)
 * @param certs       cert array (wire order)
 * @param cert_count  length of certs[]
 * @param out_quorum  optional; set to the resolved snapshot quorum when Layer A
 *                    resolves (for logging). Untouched on Layer-A failure.
 * @return unique valid signer count (>= quorum) on success, else -1/-2/-3.
 */
int nodus_witness_verify_certs_snapshot(nodus_witness_t *w,
                                          const uint8_t *block_hash,
                                          uint64_t height,
                                          const uint8_t *chain_id,
                                          const nodus_t3_sync_cert_t *certs,
                                          uint32_t cert_count,
                                          uint32_t *out_quorum);

/**
 * Verify a batch of certificates against the validator set carried in an
 * ANCHORED genesis chain_def blob — the O15G HIGH-2 genesis-authority verifier.
 *
 * The genesis block precedes any committed validator_set_snapshot, so the
 * snapshot verifier above cannot resolve its authority. The authority instead
 * is the genesis chain_def's OWN `initial_validators[]` set — but that set is
 * only trustworthy once the chain_def blob has been bound to the DISCOVER-agreed
 * anchor (SHA3-512(chain_def) == w->g_quorum_cdh), which the caller
 * (nodus_witness_sync_genesis_anchor_check) checks BEFORE calling this.
 *
 * The initial_validators[] pubkeys are parsed inline from the pinned chain_def
 * layout (mirrors nodus_witness_genesis_seed.c:40-95 — the SAME walk the genesis
 * validator seeding uses; chain_def_codec.c is not linked into libnodus). Each
 * member's canonical voter_id is RE-DERIVED from its pubkey
 * (nodus_chain_config_derive_witness_id); a duplicate member / pubkey in the
 * chain_def is a LOCAL AUTHORITY CORRUPTION. Layer-B counting is identical to
 * the snapshot verifier: order-free, non-member / duplicate / bad-sig each
 * DROPPED (never a whole-batch reject), quorum = dna_bft_quorum(iv_count) from
 * the ANCHORED (never attacker-declared) validator count.
 *
 * @param block_hash  64-byte cert-preimage block_hash (locally recomputed)
 * @param height      block height (1 for genesis)
 * @param chain_id    32-byte chain_id AS THE SIGNER USED — for genesis this is
 *                    all-zeros (chain_id is derived only at commit_genesis)
 * @param cd_blob     the ANCHORED chain_def blob (already g_quorum_cdh-verified)
 * @param cd_blob_len length of cd_blob
 * @param certs       cert array (wire order)
 * @param cert_count  length of certs[]
 * @param out_quorum  optional; set to dna_bft_quorum(iv_count) when parsed
 * @return unique valid signer count (>= quorum) on success; -1
 *         CONSENSUS_INVALID (quorum shortfall); -2 INTERNAL_FAULT (malformed
 *         chain_def / derive or alloc failure — every peer serves the same
 *         anchored bytes, so a peer rotation cannot help: fail closed)
 */
int nodus_witness_verify_certs_chain_def(const uint8_t *block_hash,
                                          uint64_t height,
                                          const uint8_t *chain_id,
                                          const uint8_t *cd_blob,
                                          uint32_t cd_blob_len,
                                          const nodus_t3_sync_cert_t *certs,
                                          uint32_t cert_count,
                                          uint32_t *out_quorum);

/* O15G HIGH-2 — result codes for nodus_witness_sync_genesis_anchor_check.
 * Every non-OK code is a genesis REJECT (the sync leg aborts). The codes are
 * distinct for logging + unit assertions; the caller treats all of them alike. */
typedef enum {
    NODUS_W_GENESIS_ANCHOR_OK           =  0,  /* certs >= quorum vs anchored set */
    NODUS_W_GENESIS_ANCHOR_MALFORMED    = -1,  /* not genesis / no chain_def / bad fp */
    NODUS_W_GENESIS_ANCHOR_CDH_MISMATCH = -2,  /* SHA3(chain_def) != g_quorum_cdh   */
    NODUS_W_GENESIS_ANCHOR_CID_MISMATCH = -3,  /* derive_chain_id != w->chain_id     */
    NODUS_W_GENESIS_ANCHOR_CERT_SHORT   = -4,  /* certs < quorum vs anchored set      */
    NODUS_W_GENESIS_ANCHOR_FAULT        = -5   /* local sha/derive/alloc/corrupt cd   */
} nodus_w_genesis_anchor_result_t;

/**
 * Bind a synced genesis block to the DISCOVER-agreed bootstrap anchor and
 * verify its block-1 certs against the ANCHORED chain_def — the O15G HIGH-2
 * fix (design §8.1). MUST be called only when w->g_quorum_cdh_set is true
 * (a bootstrapped joiner); it returns NODUS_W_GENESIS_ANCHOR_FAULT otherwise.
 *
 * In order: extract the genesis TX's chain_def trailer; REQUIRE
 * SHA3-512(chain_def) == w->g_quorum_cdh (else CDH_MISMATCH — forged genesis);
 * REQUIRE derive_chain_id(genesis) == w->chain_id (else CID_MISMATCH,
 * belt-and-braces — the genesis tx_hash does NOT cover the chain_def trailer,
 * so the g_quorum_cdh check is the load-bearing anchor); then verify certs
 * against the anchored chain_def's initial_validators[] via
 * nodus_witness_verify_certs_chain_def with a ZERO cert chain_id (genesis
 * signers used a zero chain_id at sign time).
 *
 * @param w           witness context (carries g_quorum_cdh + chain_id)
 * @param tx_data     serialized genesis TX (rsp->batch_txs[0].tx_data)
 * @param tx_len      length of tx_data
 * @param tx_hash     the genesis TX hash (rsp->batch_txs[0].tx_hash)
 * @param block_hash  64-byte cert-preimage block_hash (locally recomputed)
 * @param certs       cert array from the sync response
 * @param cert_count  length of certs[]
 * @return NODUS_W_GENESIS_ANCHOR_OK (0) on full success, else a negative
 *         nodus_w_genesis_anchor_result_t code.
 */
int nodus_witness_sync_genesis_anchor_check(nodus_witness_t *w,
                                            const uint8_t *tx_data,
                                            uint32_t tx_len,
                                            const uint8_t *tx_hash,
                                            const uint8_t *block_hash,
                                            const nodus_t3_sync_cert_t *certs,
                                            uint32_t cert_count);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_CERT_H */
