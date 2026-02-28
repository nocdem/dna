/**
 * Nodus v5 — Identity Generation & Management
 *
 * Generates Dilithium5 identity from seed or randomly.
 * CRITICAL: seed derivation MUST match dht_identity_generate_from_seed()
 * to preserve user fingerprints across the v4→v5 migration.
 *
 * @file nodus_identity.h
 */

#ifndef NODUS_IDENTITY_H
#define NODUS_IDENTITY_H

#include "nodus/nodus_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Generate identity from 32-byte seed (deterministic).
 *
 * Same seed → same keypair → same fingerprint.
 * Uses qgp_dsa87_keypair_derand() which is identical to
 * pqcrystals_dilithium5_ref_keypair_from_seed() used by OpenDHT-PQ.
 *
 * @param seed      32-byte seed (from BIP39 master seed derivation)
 * @param id_out    Output identity
 * @return 0 on success, -1 on error
 */
int nodus_identity_from_seed(const uint8_t *seed, nodus_identity_t *id_out);

/**
 * Generate random identity (non-deterministic).
 *
 * @param id_out    Output identity
 * @return 0 on success, -1 on error
 */
int nodus_identity_generate(nodus_identity_t *id_out);

/**
 * Save identity to directory (pk, sk, fingerprint files).
 *
 * Files written:
 *   {path}/nodus.pk   (2592 bytes)
 *   {path}/nodus.sk   (4896 bytes)
 *   {path}/nodus.fp   (128 hex chars + newline)
 *
 * @param id    Identity to save
 * @param path  Directory path (must exist)
 * @return 0 on success, -1 on error
 */
int nodus_identity_save(const nodus_identity_t *id, const char *path);

/**
 * Load identity from directory.
 *
 * @param path    Directory path
 * @param id_out  Output identity
 * @return 0 on success, -1 on error
 */
int nodus_identity_load(const char *path, nodus_identity_t *id_out);

/**
 * Derive the 64-bit value_id from identity (for PUT operations).
 * Returns first 8 bytes of SHA3-512(pk) as little-endian uint64.
 *
 * @param id  Identity
 * @return value_id
 */
uint64_t nodus_identity_value_id(const nodus_identity_t *id);

/**
 * Export identity to buffer (pk + sk = 7488 bytes).
 *
 * Caller must free *buf with free().
 *
 * @param id   Identity to export
 * @param buf  Output buffer (allocated by callee)
 * @param len  Output length (always 7488)
 * @return 0 on success, -1 on error
 */
int nodus_identity_export(const nodus_identity_t *id, uint8_t **buf, size_t *len);

/**
 * Import identity from buffer (pk + sk = 7488 bytes).
 *
 * Derives node_id and fingerprint from the imported public key.
 *
 * @param buf     Input buffer (7488 bytes: pk + sk)
 * @param len     Buffer length (must be 7488)
 * @param id_out  Output identity (caller-owned, stack or heap)
 * @return 0 on success, -1 on error
 */
int nodus_identity_import(const uint8_t *buf, size_t len, nodus_identity_t *id_out);

/**
 * Securely zero identity memory.
 *
 * @param id  Identity to clear
 */
void nodus_identity_clear(nodus_identity_t *id);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_IDENTITY_H */
