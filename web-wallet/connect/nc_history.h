/**
 * @file web-wallet/connect/nc_history.h
 * @brief Nodus Connect (web) — at-rest encryption of the chat history
 *        records kept in the browser (package NC-4a).
 *
 * Governing records (docs/plans/decisions/):
 *   2026-09-30-connect-history-at-rest.md (rev 2, approved 2026-10-01)
 *   2026-09-30-nodus-connect-thin-core.md, addendum Q4 = (a): the key comes
 *     from the existing SQLCipher derivation of the identity secret; records
 *     are sealed with qgp_aes AES-256-GCM; no second password.
 *
 * Construction (decision rev 2, items 1-4):
 *   R = SHA3-512(Dilithium5 secret key || "sqlcipher-db-key")   64 raw bytes
 *       — the digest whose hex messenger/database/db_encryption.c:25-58
 *         (db_derive_encryption_key) hands to SQLCipher as the passphrase.
 *   K = HKDF-SHA3-256(salt = vault id (16 B), IKM = R,
 *                     info = "nodus-connect-history-v1" (no NUL), L = 32)
 *       — shared/crypto/hash/hkdf_sha3.c; R is wiped once K exists.
 *   record = qgp_aes256_encrypt(K, plaintext, AAD) with a fresh random
 *       12-byte nonce per record (shared/crypto/enc/qgp_aes.c:60) and a
 *       16-byte tag; nonce, ciphertext and tag are returned SEPARATELY,
 *       as qgp_aes.h does. The byte layout in which the caller stores the
 *       three is not fixed by rev 2 and is not fixed here.
 *   AAD = u16be(len(store)) || store || u16be(len(id)) || id
 *       — length-prefixed so two different (store, id) pairs can never give
 *         the same AAD bytes (decision item 4).
 *
 * Invocation budget: SP 800-38D §8.3 allows at most 2^32 invocations of the
 * authenticated-encryption function per key with random 96-bit nonces. The
 * caller persists a per-key counter (IndexedDB, a later package) and passes
 * it in; encryption is refused once the counter reaches 2^32, and the
 * counter is incremented only when a record was actually produced.
 *
 * Lifetime (decision item 5): K lives only while the session is open and is
 * never written to disk — the caller wipes it with qgp_secure_memzero.
 *
 * Return codes: NC_HISTORY_OK (0), NC_HISTORY_REFUSED (-1) = the input is
 * refused (bad argument, length out of range, budget exhausted, and on
 * decrypt a record that does not authenticate), NC_HISTORY_FAULT (-2) =
 * a crypto-library or allocation failure.
 */

#ifndef NC_HISTORY_H
#define NC_HISTORY_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NC_HISTORY_OK        0
#define NC_HISTORY_REFUSED  (-1)
#define NC_HISTORY_FAULT    (-2)

#define NC_HISTORY_SK_LEN        4896   /* QGP_DSA87_SECRETKEYBYTES        */
#define NC_HISTORY_ROOT_LEN      64     /* SHA3-512 digest                 */
#define NC_HISTORY_VAULT_ID_LEN  16     /* web-wallet/src/vault.js:70      */
#define NC_HISTORY_KEY_LEN       32     /* AES-256                         */
#define NC_HISTORY_NONCE_LEN     12     /* qgp_aes.c:60                    */
#define NC_HISTORY_TAG_LEN       16     /* qgp_aes.c:101                   */
#define NC_HISTORY_NAME_MAX      65535  /* u16be length prefix in the AAD  */
/* SP 800-38D §8.3: random-nonce invocations per key. */
#define NC_HISTORY_MAX_INVOCATIONS ((uint64_t)1 << 32)

/* HKDF info, used without its terminating NUL. */
#define NC_HISTORY_HKDF_INFO "nodus-connect-history-v1"

/**
 * R = SHA3-512(sk || "sqlcipher-db-key"), 64 raw bytes. hex(R) is exactly
 * the string db_derive_encryption_key returns for the same sk.
 * sk_len must be NC_HISTORY_SK_LEN (the app passes the Dilithium5 key file's
 * private_key_size, dna_engine_identity.c:381 — 4896 for Dilithium5; this
 * wrapper only refuses any other length, the digest is the same).
 * Exposed for the equivalence test; production callers use
 * nc_history_derive_key, which wipes R. On failure root_out is zeroed.
 * @return 0 / -1 refused input / -2 hash or allocation fault
 */
int nc_history_root(const uint8_t *sk, size_t sk_len,
                    uint8_t root_out[NC_HISTORY_ROOT_LEN]);

/**
 * K = HKDF-SHA3-256(salt = vault_id, IKM = R, info = NC_HISTORY_HKDF_INFO, 32)
 * with R computed from sk and wiped before return. On failure key_out is
 * zeroed.
 * @return 0 / -1 refused input / -2 hash, HKDF or allocation fault
 */
int nc_history_derive_key(const uint8_t *sk, size_t sk_len,
                          const uint8_t vault_id[NC_HISTORY_VAULT_ID_LEN],
                          uint8_t key_out[NC_HISTORY_KEY_LEN]);

/**
 * Seal one history record.
 *
 * @param key        K from nc_history_derive_key
 * @param counter    in: invocations already made under this key;
 *                   out: +1 on success, unchanged on any failure
 * @param store      IndexedDB object-store name bytes (<= 65535; may be
 *                   empty, then may be NULL)
 * @param id         record id bytes (<= 65535; may be empty, then NULL)
 * @param pt,pt_len  plaintext; 1..INT_MAX bytes (qgp_aes refuses an empty
 *                   plaintext, qgp_aes.c:49-52, and hands lengths to
 *                   OpenSSL as int, qgp_aes.c:87)
 * @param ct_out     pt_len bytes (GCM: ciphertext length = plaintext length)
 * @param nonce_out  12 bytes, fresh random per call
 * @param tag_out    16 bytes
 * @return 0 / -1 refused input or budget exhausted (*counter >= 2^32) /
 *         -2 RNG, cipher or allocation fault
 */
int nc_history_encrypt(const uint8_t key[NC_HISTORY_KEY_LEN],
                       uint64_t *counter,
                       const uint8_t *store, size_t store_len,
                       const uint8_t *id, size_t id_len,
                       const uint8_t *pt, size_t pt_len,
                       uint8_t *ct_out,
                       uint8_t nonce_out[NC_HISTORY_NONCE_LEN],
                       uint8_t tag_out[NC_HISTORY_TAG_LEN]);

/**
 * Open one history record. store and id must be the ones it was sealed
 * under. pt_out receives ct_len bytes; on any failure it is wiped.
 *
 * @return 0 / -1 refused input or the record does not authenticate /
 *         -2 allocation fault while building the AAD.
 * NOTE: qgp_aes256_decrypt returns the same -1 for a tag mismatch
 * (qgp_aes.c:184-192) and for an OpenSSL context allocation failure
 * (qgp_aes.c:146-149); this wrapper cannot tell them apart and reports
 * both as -1.
 */
int nc_history_decrypt(const uint8_t key[NC_HISTORY_KEY_LEN],
                       const uint8_t *store, size_t store_len,
                       const uint8_t *id, size_t id_len,
                       const uint8_t *ct, size_t ct_len,
                       const uint8_t nonce[NC_HISTORY_NONCE_LEN],
                       const uint8_t tag[NC_HISTORY_TAG_LEN],
                       uint8_t *pt_out);

#ifdef __cplusplus
}
#endif

#endif /* NC_HISTORY_H */
