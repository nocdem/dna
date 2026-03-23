/**
 * @file dht_salt_agreement.c
 * @brief Per-contact salt agreement via DHT (Kyber1024 dual-encrypted)
 *
 * Implements deterministic salt storage/recovery for contact pairs.
 * Uses GEK pattern (Kyber1024 KEM + AES-256-GCM) for dual encryption.
 *
 * Security: all fetched values are signature-verified against both parties'
 * Dilithium5 pubkeys. Third-party values are discarded. Diverged salts
 * are resolved by deterministic tiebreaker (lower SHA3 hash wins).
 */

#include "dht_salt_agreement.h"
#include "../messenger/gek.h"
#include "nodus_ops.h"
#include "../../database/contacts_db.h"
#include "crypto/hash/qgp_sha3.h"
#include "crypto/sign/qgp_dilithium.h"
#include "crypto/utils/qgp_log.h"

#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>   /* htons/ntohs */
#else
#include <arpa/inet.h>  /* htons/ntohs */
#endif

#define LOG_TAG "SALT_AGREE"

/* Fingerprint binary size (SHA3-512 = 64 bytes) */
#define FP_BIN_SIZE 64

/* Packet layout sizes */
#define PACKET_VERSION_SIZE   2
#define PACKET_ENTRY_SIZE     (FP_BIN_SIZE + GEK_ENC_TOTAL_SIZE)  /* 64 + 1628 = 1692 */
#define PACKET_DATA_SIZE      (PACKET_VERSION_SIZE + 2 * PACKET_ENTRY_SIZE)  /* 2 + 3384 = 3386 */
#define PACKET_TOTAL_SIZE     (PACKET_DATA_SIZE + QGP_DSA87_SIGNATURE_BYTES)  /* 3386 + 4627 = 8013 */

/* ============================================================================
 * HELPERS
 * ============================================================================ */

/** Convert 128-char hex fingerprint to 64-byte binary */
static int fp_hex_to_bin(const char *hex, uint8_t bin[FP_BIN_SIZE]) {
    if (!hex || strlen(hex) < 128) return -1;
    for (int i = 0; i < FP_BIN_SIZE; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%02x", &byte) != 1) return -1;
        bin[i] = (uint8_t)byte;
    }
    return 0;
}

/**
 * Try to decrypt salt from a parsed packet for the given fingerprint.
 * Returns 0 on success, -1 if fingerprint not found or decryption fails.
 */
static int packet_decrypt_salt(
    const uint8_t *data,
    size_t data_len,
    const uint8_t my_fp_bin[FP_BIN_SIZE],
    const uint8_t *my_kyber_priv,
    uint8_t salt_out[SALT_AGREEMENT_SIZE]
) {
    if (data_len < PACKET_DATA_SIZE) return -1;

    /* Check version */
    uint16_t version;
    memcpy(&version, data, 2);
    version = ntohs(version);
    if (version != SALT_AGREEMENT_VERSION) return -1;

    /* Find my entry (check both slots) */
    const uint8_t *my_encrypted = NULL;
    size_t entry1_offset = PACKET_VERSION_SIZE;
    size_t entry2_offset = PACKET_VERSION_SIZE + PACKET_ENTRY_SIZE;

    if (memcmp(data + entry1_offset, my_fp_bin, FP_BIN_SIZE) == 0) {
        my_encrypted = data + entry1_offset + FP_BIN_SIZE;
    } else if (memcmp(data + entry2_offset, my_fp_bin, FP_BIN_SIZE) == 0) {
        my_encrypted = data + entry2_offset + FP_BIN_SIZE;
    } else {
        return -1;  /* My fingerprint not in this packet */
    }

    /* Decrypt with my Kyber private key */
    return gek_decrypt(my_encrypted, GEK_ENC_TOTAL_SIZE, my_kyber_priv, salt_out);
}

/**
 * Verify packet signature against one of the two parties' Dilithium pubkeys.
 * Returns 0 if signature is valid for either party, -1 if invalid.
 */
static int packet_verify_signature(
    const uint8_t *data,
    size_t data_len,
    const uint8_t *sign_pub_a,
    const uint8_t *sign_pub_b
) {
    if (data_len < PACKET_DATA_SIZE + 1) return -1;

    const uint8_t *sig = data + PACKET_DATA_SIZE;
    size_t sig_len = data_len - PACKET_DATA_SIZE;

    /* Try party A's pubkey */
    if (sign_pub_a &&
        qgp_dsa87_verify(sig, sig_len, data, PACKET_DATA_SIZE, sign_pub_a) == 0) {
        return 0;
    }

    /* Try party B's pubkey */
    if (sign_pub_b &&
        qgp_dsa87_verify(sig, sig_len, data, PACKET_DATA_SIZE, sign_pub_b) == 0) {
        return 0;
    }

    return -1;  /* Neither party signed this */
}

/* ============================================================================
 * KEY DERIVATION
 * ============================================================================ */

int salt_agreement_make_key(
    const char *fp_a,
    const char *fp_b,
    char *key_out,
    size_t key_out_size
) {
    if (!fp_a || !fp_b || !key_out || key_out_size < 300) {
        return -1;
    }
    if (strlen(fp_a) < 128 || strlen(fp_b) < 128) {
        return -1;
    }

    /* Sort fingerprints lexicographically */
    const char *min_fp = (strcmp(fp_a, fp_b) <= 0) ? fp_a : fp_b;
    const char *max_fp = (min_fp == fp_a) ? fp_b : fp_a;

    /* Build input: min_fp + ":" + max_fp + ":salt_agreement" */
    char input[400];
    int len = snprintf(input, sizeof(input), "%.128s:%.128s:salt_agreement", min_fp, max_fp);
    if (len <= 0 || (size_t)len >= sizeof(input)) {
        return -1;
    }

    /* SHA3-512 hash */
    uint8_t hash[64];
    qgp_sha3_512((const uint8_t *)input, (size_t)len, hash);

    /* Convert to hex string */
    for (int i = 0; i < 64; i++) {
        snprintf(key_out + i * 2, 3, "%02x", hash[i]);
    }
    key_out[128] = '\0';

    return 0;
}

/* ============================================================================
 * PUBLISH
 * ============================================================================ */

int salt_agreement_publish(
    const char *my_fp,
    const char *contact_fp,
    const uint8_t salt[SALT_AGREEMENT_SIZE],
    const uint8_t *my_kyber_pub,
    const uint8_t *contact_kyber_pub,
    const uint8_t *my_dilithium_priv
) {
    if (!my_fp || !contact_fp || !salt || !my_kyber_pub ||
        !contact_kyber_pub || !my_dilithium_priv) {
        return -1;
    }

    /* Compute DHT key */
    char dht_key[300];
    if (salt_agreement_make_key(my_fp, contact_fp, dht_key, sizeof(dht_key)) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to compute agreement key");
        return -1;
    }

    /* Sort fingerprints to determine packet order */
    const char *lower_fp, *higher_fp;
    const uint8_t *lower_kyber, *higher_kyber;
    if (strcmp(my_fp, contact_fp) <= 0) {
        lower_fp = my_fp;
        higher_fp = contact_fp;
        lower_kyber = my_kyber_pub;
        higher_kyber = contact_kyber_pub;
    } else {
        lower_fp = contact_fp;
        higher_fp = my_fp;
        lower_kyber = contact_kyber_pub;
        higher_kyber = my_kyber_pub;
    }

    /* Build packet */
    uint8_t packet[PACKET_TOTAL_SIZE];
    memset(packet, 0, sizeof(packet));
    size_t offset = 0;

    /* Version (network byte order) */
    uint16_t version = htons(SALT_AGREEMENT_VERSION);
    memcpy(packet + offset, &version, 2);
    offset += 2;

    /* Entry 1: lower fingerprint + encrypted salt */
    uint8_t fp_bin[FP_BIN_SIZE];
    if (fp_hex_to_bin(lower_fp, fp_bin) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid lower fingerprint");
        return -1;
    }
    memcpy(packet + offset, fp_bin, FP_BIN_SIZE);
    offset += FP_BIN_SIZE;

    if (gek_encrypt(salt, lower_kyber, packet + offset) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to encrypt salt for lower party");
        return -1;
    }
    offset += GEK_ENC_TOTAL_SIZE;

    /* Entry 2: higher fingerprint + encrypted salt */
    if (fp_hex_to_bin(higher_fp, fp_bin) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid higher fingerprint");
        return -1;
    }
    memcpy(packet + offset, fp_bin, FP_BIN_SIZE);
    offset += FP_BIN_SIZE;

    if (gek_encrypt(salt, higher_kyber, packet + offset) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to encrypt salt for higher party");
        return -1;
    }
    offset += GEK_ENC_TOTAL_SIZE;

    /* Sign the data portion with Dilithium5 */
    size_t sig_len = 0;
    if (qgp_dsa87_sign(packet + offset, &sig_len,
                        packet, PACKET_DATA_SIZE,
                        my_dilithium_priv) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to sign agreement packet");
        return -1;
    }

    size_t total_size = PACKET_DATA_SIZE + sig_len;

    /* Publish to DHT */
    int rc = nodus_ops_put_str(dht_key, packet, total_size,
                               SALT_AGREEMENT_TTL, nodus_ops_value_id());
    if (rc != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to publish salt agreement to DHT");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Published salt agreement for %.16s...↔%.16s... (%zu bytes)",
                 my_fp, contact_fp, total_size);
    return 0;
}

/* ============================================================================
 * FETCH (AUTHENTICATED)
 * ============================================================================ */

int salt_agreement_fetch(
    const char *my_fp,
    const char *contact_fp,
    const uint8_t *my_kyber_priv,
    const uint8_t *my_sign_pub,
    const uint8_t *contact_sign_pub,
    uint8_t salt_out[SALT_AGREEMENT_SIZE]
) {
    if (!my_fp || !contact_fp || !my_kyber_priv || !salt_out ||
        !my_sign_pub || !contact_sign_pub) {
        return -1;
    }

    /* Compute DHT key */
    char dht_key[300];
    if (salt_agreement_make_key(my_fp, contact_fp, dht_key, sizeof(dht_key)) != 0) {
        return -1;
    }

    /* Fetch ALL values from DHT (multiple publishers may exist) */
    uint8_t **values = NULL;
    size_t *lens = NULL;
    size_t count = 0;
    int rc = nodus_ops_get_all_str(dht_key, &values, &lens, &count);
    if (rc != 0 || !values || count == 0) {
        free(values);
        free(lens);
        return -2;  /* Not found */
    }

    /* Convert my fingerprint to binary for packet parsing */
    uint8_t my_fp_bin[FP_BIN_SIZE];
    if (fp_hex_to_bin(my_fp, my_fp_bin) != 0) {
        goto cleanup_not_found;
    }

    /* Collect authenticated salts */
    uint8_t valid_salts[16][SALT_AGREEMENT_SIZE];  /* Max 16 valid values */
    size_t valid_count = 0;

    for (size_t i = 0; i < count && valid_count < 16; i++) {
        if (!values[i] || lens[i] < PACKET_DATA_SIZE) continue;

        /* Verify signature against both parties' pubkeys */
        if (packet_verify_signature(values[i], lens[i],
                                     my_sign_pub, contact_sign_pub) != 0) {
            QGP_LOG_WARN(LOG_TAG, "Discarding value %zu: invalid signature (third party)", i);
            continue;
        }

        /* Decrypt salt from authenticated packet */
        uint8_t salt[SALT_AGREEMENT_SIZE];
        if (packet_decrypt_salt(values[i], lens[i], my_fp_bin, my_kyber_priv, salt) == 0) {
            memcpy(valid_salts[valid_count], salt, SALT_AGREEMENT_SIZE);
            valid_count++;
        }
    }

    /* Cleanup DHT data */
    for (size_t i = 0; i < count; i++) free(values[i]);
    free(values);
    free(lens);

    if (valid_count == 0) {
        return -2;  /* No authenticated values found */
    }

    if (valid_count == 1) {
        memcpy(salt_out, valid_salts[0], SALT_AGREEMENT_SIZE);
        return 0;
    }

    /* Deduplicate: if all decrypted salts are identical, no real divergence.
     * This happens when both parties publish the same salt — Kyber KEM produces
     * different ciphertext each time, so DHT has multiple entries but the
     * underlying plaintext salt is the same. */
    size_t unique_count = 1;
    for (size_t i = 1; i < valid_count; i++) {
        bool is_dup = false;
        for (size_t j = 0; j < i; j++) {
            if (memcmp(valid_salts[i], valid_salts[j], SALT_AGREEMENT_SIZE) == 0) {
                is_dup = true;
                break;
            }
        }
        if (!is_dup) unique_count++;
    }

    if (unique_count == 1) {
        /* All values decrypt to the same salt — no divergence */
        memcpy(salt_out, valid_salts[0], SALT_AGREEMENT_SIZE);
        return 0;
    }

    /* Multiple DISTINCT salts (true divergence) — deterministic tiebreaker.
     * Hash each salt with SHA3-512, pick the one with the lowest hash.
     * Both parties compute the same result → guaranteed convergence. */
    QGP_LOG_WARN(LOG_TAG, "Diverged salts detected (%zu unique of %zu valid), applying tiebreaker",
                 unique_count, valid_count);

    size_t winner = 0;
    uint8_t winner_hash[64];
    qgp_sha3_512(valid_salts[0], SALT_AGREEMENT_SIZE, winner_hash);

    for (size_t i = 1; i < valid_count; i++) {
        uint8_t candidate_hash[64];
        qgp_sha3_512(valid_salts[i], SALT_AGREEMENT_SIZE, candidate_hash);
        if (memcmp(candidate_hash, winner_hash, 64) < 0) {
            winner = i;
            memcpy(winner_hash, candidate_hash, 64);
        }
    }

    memcpy(salt_out, valid_salts[winner], SALT_AGREEMENT_SIZE);
    QGP_LOG_INFO(LOG_TAG, "Tiebreaker selected salt %zu of %zu", winner, valid_count);
    return 0;

cleanup_not_found:
    for (size_t i = 0; i < count; i++) free(values[i]);
    free(values);
    free(lens);
    return -2;
}

/* ============================================================================
 * VERIFY / RECONCILE
 * ============================================================================ */

int salt_agreement_verify(
    const char *my_fp,
    const char *contact_fp,
    const uint8_t *my_kyber_pub,
    const uint8_t *my_kyber_priv,
    const uint8_t *contact_kyber_pub,
    const uint8_t *my_sign_pub,
    const uint8_t *my_dilithium_priv,
    const uint8_t *contact_sign_pub
) {
    if (!my_fp || !contact_fp || !my_kyber_pub || !my_kyber_priv ||
        !my_dilithium_priv || !my_sign_pub || !contact_sign_pub) {
        return -1;
    }

    /* Get local salt */
    uint8_t local_salt[SALT_AGREEMENT_SIZE];
    bool has_local = (contacts_db_get_salt(contact_fp, local_salt) == 0);

    /* Check if local salt is all zeros (unset) */
    if (has_local) {
        bool all_zero = true;
        for (int i = 0; i < SALT_AGREEMENT_SIZE; i++) {
            if (local_salt[i] != 0) { all_zero = false; break; }
        }
        if (all_zero) has_local = false;
    }

    /* Fetch authenticated DHT salt */
    uint8_t dht_salt[SALT_AGREEMENT_SIZE];
    int fetch_rc = salt_agreement_fetch(my_fp, contact_fp, my_kyber_priv,
                                         my_sign_pub, contact_sign_pub, dht_salt);
    bool has_dht = (fetch_rc == 0);

    /* Reconcile */
    if (has_dht && has_local) {
        if (memcmp(local_salt, dht_salt, SALT_AGREEMENT_SIZE) == 0) {
            /* Match — no action needed */
            QGP_LOG_DEBUG(LOG_TAG, "[VERIFY] Salt match for %.16s...", contact_fp);
            return 0;
        } else {
            /* Mismatch — use tiebreaker (fetch already applied it if multiple
             * DHT values existed). Now compare local vs DHT winner. */
            uint8_t local_hash[64], dht_hash[64];
            qgp_sha3_512(local_salt, SALT_AGREEMENT_SIZE, local_hash);
            qgp_sha3_512(dht_salt, SALT_AGREEMENT_SIZE, dht_hash);

            const uint8_t *winner_salt;
            if (memcmp(local_hash, dht_hash, 64) <= 0) {
                winner_salt = local_salt;
                QGP_LOG_INFO(LOG_TAG, "[VERIFY] Salt mismatch for %.16s... — local wins tiebreaker",
                            contact_fp);
            } else {
                winner_salt = dht_salt;
                contacts_db_set_salt(contact_fp, dht_salt);
                QGP_LOG_INFO(LOG_TAG, "[VERIFY] Salt mismatch for %.16s... — DHT wins tiebreaker",
                            contact_fp);
            }

            /* Re-publish winner to DHT so both parties converge */
            if (contact_kyber_pub) {
                salt_agreement_publish(my_fp, contact_fp, winner_salt,
                                      my_kyber_pub, contact_kyber_pub,
                                      my_dilithium_priv);
            }
            return 0;
        }
    } else if (has_dht && !has_local) {
        /* Recovery — DHT has authenticated salt, local doesn't */
        QGP_LOG_INFO(LOG_TAG, "[VERIFY] Recovering salt from DHT for %.16s...", contact_fp);
        contacts_db_set_salt(contact_fp, dht_salt);
        return 0;
    } else if (!has_dht && has_local) {
        /* Migration — publish local salt to DHT */
        if (!contact_kyber_pub) {
            QGP_LOG_DEBUG(LOG_TAG, "[VERIFY] No contact Kyber pubkey for %.16s..., skip publish",
                         contact_fp);
            return 0;  /* Can't publish without contact's key, but local is fine */
        }
        QGP_LOG_INFO(LOG_TAG, "[VERIFY] Publishing local salt to DHT for %.16s...", contact_fp);
        salt_agreement_publish(my_fp, contact_fp, local_salt,
                              my_kyber_pub, contact_kyber_pub, my_dilithium_priv);
        return 0;
    } else {
        /* Both empty — pre-salt contact */
        QGP_LOG_DEBUG(LOG_TAG, "[VERIFY] No salt for %.16s... (pre-salt contact)", contact_fp);
        return 1;
    }
}
