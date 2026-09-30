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
#include "codec/salt_agreement_codec.h"
#include "../messenger/gek.h"
#include "nodus_ops.h"
#include "../../database/contacts_db.h"
#include "crypto/hash/qgp_sha3.h"
#include "crypto/sign/qgp_dilithium.h"
#include "crypto/utils/qgp_log.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>   /* htons/ntohs */
#else
#include <arpa/inet.h>  /* htons/ntohs */
#endif

#define LOG_TAG "SALT_AGREE"

/* NC-1: the packet layout macros (FP_BIN_SIZE, PACKET_*), the four packet
 * helpers (now salt_agreement_fp_hex_to_bin / _packet_data_size_for_version /
 * _packet_decrypt_salt / _packet_verify_signature) and salt_agreement_make_key
 * moved verbatim to codec/salt_agreement_codec.{h,c}. NC-1b: the packet
 * build of salt_agreement_publish_internal moved there too
 * (salt_agreement_build_packet). */

/* ============================================================================
 * PUBLISH
 * ============================================================================ */

/**
 * Shared implementation for salt_agreement_publish() / _v2() (KEM Faz 1,
 * R9). Emits packet v2 (per-entry alg byte, ML-KEM-1024) ONLY when BOTH
 * my_mlkem_pub and contact_mlkem_pub are non-NULL; otherwise builds the
 * unchanged v1 packet — same all-or-nothing gate as ikp_build (design §5.4).
 */
static int salt_agreement_publish_internal(
    const char *my_fp,
    const char *contact_fp,
    const uint8_t salt[SALT_AGREEMENT_SIZE],
    const uint8_t *my_kyber_pub,
    const uint8_t *contact_kyber_pub,
    const uint8_t *my_mlkem_pub,
    const uint8_t *contact_mlkem_pub,
    const uint8_t *my_dilithium_priv
) {
    if (!my_fp || !contact_fp || !salt || !my_kyber_pub ||
        !contact_kyber_pub || !my_dilithium_priv) {
        return -1;
    }

    bool use_v2 = (my_mlkem_pub != NULL && contact_mlkem_pub != NULL);

    /* Compute DHT key */
    char dht_key[300];
    if (salt_agreement_make_key(my_fp, contact_fp, dht_key, sizeof(dht_key)) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to compute agreement key");
        return -1;
    }

    /* Build packet — stack buffer sized for the larger (v2) layout; only
     * the first `data_size` (+ signature) bytes are ever used/published.
     * NC-1b: the build is salt_agreement_build_packet
     * (codec/salt_agreement_codec.c). */
    uint8_t packet[PACKET_TOTAL_SIZE_V2];
    size_t total_size = 0;
    if (salt_agreement_build_packet(my_fp, contact_fp, salt,
                                    my_kyber_pub, contact_kyber_pub,
                                    my_mlkem_pub, contact_mlkem_pub,
                                    my_dilithium_priv,
                                    packet, &total_size) != 0) {
        return -1;
    }

    /* Publish to DHT */
    int rc = nodus_ops_put_str(dht_key, packet, total_size,
                               SALT_AGREEMENT_TTL, nodus_ops_value_id());
    if (rc != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to publish salt agreement to DHT");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Published salt agreement (%s) for %.16s...<->%.16s... (%zu bytes)",
                 use_v2 ? "v2" : "v1", my_fp, contact_fp, total_size);
    return 0;
}

int salt_agreement_publish(
    const char *my_fp,
    const char *contact_fp,
    const uint8_t salt[SALT_AGREEMENT_SIZE],
    const uint8_t *my_kyber_pub,
    const uint8_t *contact_kyber_pub,
    const uint8_t *my_dilithium_priv
) {
    return salt_agreement_publish_internal(my_fp, contact_fp, salt,
                                           my_kyber_pub, contact_kyber_pub,
                                           NULL, NULL, my_dilithium_priv);
}

int salt_agreement_publish_v2(
    const char *my_fp,
    const char *contact_fp,
    const uint8_t salt[SALT_AGREEMENT_SIZE],
    const uint8_t *my_kyber_pub,
    const uint8_t *contact_kyber_pub,
    const uint8_t *my_mlkem_pub,
    const uint8_t *contact_mlkem_pub,
    const uint8_t *my_dilithium_priv
) {
    return salt_agreement_publish_internal(my_fp, contact_fp, salt,
                                           my_kyber_pub, contact_kyber_pub,
                                           my_mlkem_pub, contact_mlkem_pub,
                                           my_dilithium_priv);
}

/* ============================================================================
 * FETCH (AUTHENTICATED)
 * ============================================================================ */

/**
 * Shared implementation for salt_agreement_fetch() / _v2() (KEM Faz 1, R9).
 * Accepts both v1 and v2 values found on the agreement key; my_mlkem_priv
 * (nullable) is required only to decrypt a v2 entry whose alg byte is
 * SALT_AGREEMENT_ALG_MLKEM1024.
 */
static int salt_agreement_fetch_internal(
    const char *my_fp,
    const char *contact_fp,
    const uint8_t *my_kyber_priv,
    const uint8_t *my_mlkem_priv,
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
    if (salt_agreement_fp_hex_to_bin(my_fp, my_fp_bin) != 0) {
        goto cleanup_not_found;
    }

    /* Collect authenticated salts */
    uint8_t valid_salts[16][SALT_AGREEMENT_SIZE];  /* Max 16 valid values */
    size_t valid_count = 0;

    for (size_t i = 0; i < count && valid_count < 16; i++) {
        if (!values[i] || lens[i] < PACKET_VERSION_SIZE) continue;

        /* KEM Faz 1 (R9): peek the version to pick the right data_size for
         * signature verification — v1 and v2 packets may both be present. */
        uint16_t pkt_version;
        memcpy(&pkt_version, values[i], 2);
        pkt_version = ntohs(pkt_version);
        size_t data_size = salt_agreement_packet_data_size_for_version(pkt_version);
        if (data_size == 0 || lens[i] < data_size) continue;

        /* Verify signature against both parties' pubkeys */
        if (salt_agreement_packet_verify_signature(values[i], lens[i], data_size,
                                     my_sign_pub, contact_sign_pub) != 0) {
            QGP_LOG_WARN(LOG_TAG, "Discarding value %zu: invalid signature (third party)", i);
            continue;
        }

        /* Decrypt salt from authenticated packet */
        uint8_t salt[SALT_AGREEMENT_SIZE];
        if (salt_agreement_packet_decrypt_salt(values[i], lens[i], my_fp_bin, my_kyber_priv,
                                my_mlkem_priv, salt) == 0) {
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

int salt_agreement_fetch(
    const char *my_fp,
    const char *contact_fp,
    const uint8_t *my_kyber_priv,
    const uint8_t *my_sign_pub,
    const uint8_t *contact_sign_pub,
    uint8_t salt_out[SALT_AGREEMENT_SIZE]
) {
    return salt_agreement_fetch_internal(my_fp, contact_fp, my_kyber_priv, NULL,
                                         my_sign_pub, contact_sign_pub, salt_out);
}

int salt_agreement_fetch_v2(
    const char *my_fp,
    const char *contact_fp,
    const uint8_t *my_kyber_priv,
    const uint8_t *my_mlkem_priv,
    const uint8_t *my_sign_pub,
    const uint8_t *contact_sign_pub,
    uint8_t salt_out[SALT_AGREEMENT_SIZE]
) {
    return salt_agreement_fetch_internal(my_fp, contact_fp, my_kyber_priv, my_mlkem_priv,
                                         my_sign_pub, contact_sign_pub, salt_out);
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
