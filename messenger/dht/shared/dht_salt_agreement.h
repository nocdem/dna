/**
 * @file dht_salt_agreement.h
 * @brief Per-contact salt agreement via DHT (Kyber1024 dual-encrypted)
 *
 * Stores the agreed DHT message salt for a contact pair on a deterministic
 * DHT key. Both parties can read it (Kyber-encrypted for each). Provides
 * self-healing salt recovery on engine startup.
 *
 * Agreement key: SHA3-512(min(fp_a, fp_b) + ":" + max(fp_a, fp_b) + ":salt_agreement")
 * Encryption: Same as GEK IKP — Kyber1024 KEM + AES-256-GCM per party
 *
 * Security:
 * - All values fetched via get_all, signature-verified against both parties
 * - Third-party values (invalid signature) are discarded
 * - Diverged salts resolved by deterministic tiebreaker (lower SHA3 hash wins)
 */

#ifndef DHT_SALT_AGREEMENT_H
#define DHT_SALT_AGREEMENT_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Salt size (AES-256 key = 32 bytes) */
#define SALT_AGREEMENT_SIZE 32

/* Version for the agreement packet */
#define SALT_AGREEMENT_VERSION 1

/* TTL for salt agreement DHT value (30 days) */
#define SALT_AGREEMENT_TTL (30 * 24 * 3600)

/**
 * Compute the deterministic DHT key for a contact pair's salt agreement.
 *
 * key = SHA3-512(min(fp_a, fp_b) + ":" + max(fp_a, fp_b) + ":salt_agreement")
 *
 * @param fp_a First fingerprint (128-char hex)
 * @param fp_b Second fingerprint (128-char hex)
 * @param key_out Output buffer for string key (must be >= 300 bytes)
 * @param key_out_size Size of key_out buffer
 * @return 0 on success, -1 on error
 */
int salt_agreement_make_key(
    const char *fp_a,
    const char *fp_b,
    char *key_out,
    size_t key_out_size
);

/**
 * Publish salt to the DHT agreement key, dual-encrypted for both parties.
 *
 * Uses GEK pattern: Kyber1024 encapsulate for each party's pubkey,
 * AES-256-GCM encrypt the salt, sign with publisher's Dilithium5 key.
 *
 * @param my_fp            Publisher's fingerprint (128-char hex)
 * @param contact_fp       Contact's fingerprint (128-char hex)
 * @param salt             32-byte salt to publish
 * @param my_kyber_pub     Publisher's Kyber1024 public key (1568 bytes)
 * @param contact_kyber_pub Contact's Kyber1024 public key (1568 bytes)
 * @param my_dilithium_priv Publisher's Dilithium5 private key (4896 bytes)
 * @return 0 on success, -1 on error
 */
int salt_agreement_publish(
    const char *my_fp,
    const char *contact_fp,
    const uint8_t salt[SALT_AGREEMENT_SIZE],
    const uint8_t *my_kyber_pub,
    const uint8_t *contact_kyber_pub,
    const uint8_t *my_dilithium_priv
);

/**
 * Fetch and decrypt salt from the DHT agreement key (authenticated).
 *
 * Fetches ALL values on the agreement key, verifies Dilithium signatures
 * against both parties' signing pubkeys, discards third-party values.
 * If multiple valid values with different salts exist (diverged), picks
 * the salt with the lower SHA3-512 hash (deterministic tiebreaker).
 *
 * @param my_fp              My fingerprint (128-char hex)
 * @param contact_fp         Contact's fingerprint (128-char hex)
 * @param my_kyber_priv      My Kyber1024 private key (3168 bytes)
 * @param my_sign_pub        My Dilithium5 public key (2592 bytes)
 * @param contact_sign_pub   Contact's Dilithium5 public key (2592 bytes)
 * @param salt_out           Output buffer for decrypted salt (32 bytes)
 * @return 0 on success, -1 on error, -2 if not found in DHT
 */
int salt_agreement_fetch(
    const char *my_fp,
    const char *contact_fp,
    const uint8_t *my_kyber_priv,
    const uint8_t *my_sign_pub,
    const uint8_t *contact_sign_pub,
    uint8_t salt_out[SALT_AGREEMENT_SIZE]
);

/**
 * Verify and reconcile salt for a single contact.
 *
 * Compares local salt (contacts_db) with DHT agreement key value.
 * Reconciliation rules:
 *   DHT match local       -> OK, no action
 *   DHT != local          -> deterministic tiebreaker, re-publish winner
 *   DHT exists, local empty -> store DHT salt locally (recovery)
 *   DHT empty, local exists -> publish local to DHT
 *   Both empty            -> no salt (backward compat, pre-salt contact)
 *
 * @param my_fp              My fingerprint (128-char hex)
 * @param contact_fp         Contact's fingerprint (128-char hex)
 * @param my_kyber_pub       My Kyber1024 public key (1568 bytes)
 * @param my_kyber_priv      My Kyber1024 private key (3168 bytes)
 * @param contact_kyber_pub  Contact's Kyber1024 public key (1568 bytes) — can be NULL if unavailable
 * @param my_sign_pub        My Dilithium5 public key (2592 bytes)
 * @param my_dilithium_priv  My Dilithium5 private key (4896 bytes)
 * @param contact_sign_pub   Contact's Dilithium5 public key (2592 bytes)
 * @return 0 on success (salt verified/reconciled), -1 on error, 1 if no salt (pre-salt contact)
 */
int salt_agreement_verify(
    const char *my_fp,
    const char *contact_fp,
    const uint8_t *my_kyber_pub,
    const uint8_t *my_kyber_priv,
    const uint8_t *contact_kyber_pub,
    const uint8_t *my_sign_pub,
    const uint8_t *my_dilithium_priv,
    const uint8_t *contact_sign_pub
);

#ifdef __cplusplus
}
#endif

#endif /* DHT_SALT_AGREEMENT_H */
