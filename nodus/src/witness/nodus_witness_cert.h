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
 * Verify a batch of sync certificates against locally-known facts.
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

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_CERT_H */
