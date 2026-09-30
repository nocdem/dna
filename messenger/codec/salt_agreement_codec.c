/**
 * @file salt_agreement_codec.c
 * @brief Per-contact salt agreement: key derivation + packet parse helpers
 *
 * NC-1: moved verbatim out of dht/shared/dht_salt_agreement.c. The only
 * changes are `static` dropped and the `salt_agreement_` name prefix on the
 * four former helpers (see salt_agreement_codec.h). No network I/O, no
 * database.
 *
 * NC-1b: the packet build moved here from salt_agreement_publish_internal
 * as salt_agreement_build_packet (plumbing listed at the function).
 */

#include "codec/salt_agreement_codec.h"
#include "crypto/hash/qgp_sha3.h"
#include "crypto/sign/qgp_dilithium.h"
#include "crypto/utils/qgp_log.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>   /* htons/ntohs */
#else
#include <arpa/inet.h>  /* htons/ntohs */
#endif

#define LOG_TAG "SALT_AGREE"

/* ============================================================================
 * HELPERS
 * ============================================================================ */

/** Convert 128-char hex fingerprint to 64-byte binary */
int salt_agreement_fp_hex_to_bin(const char *hex, uint8_t bin[FP_BIN_SIZE]) {
    if (!hex || strlen(hex) < 128) return -1;
    for (int i = 0; i < FP_BIN_SIZE; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%02x", &byte) != 1) return -1;
        bin[i] = (uint8_t)byte;
    }
    return 0;
}

/**
 * Data-portion size for a packet's version field (KEM Faz 1, R9: v1 or v2).
 * Returns 0 for an unsupported version.
 */
size_t salt_agreement_packet_data_size_for_version(uint16_t version) {
    if (version == SALT_AGREEMENT_VERSION) return PACKET_DATA_SIZE;
    if (version == SALT_AGREEMENT_VERSION_V2) return PACKET_DATA_SIZE_V2;
    return 0;
}

/**
 * Try to decrypt salt from a parsed packet for the given fingerprint.
 * Accepts v1 (SALT_AGREEMENT_VERSION) and v2 (SALT_AGREEMENT_VERSION_V2,
 * KEM Faz 1, R9) — v2 entries carry an alg byte selecting the KEM used
 * (gek_decrypt_alg): SALT_AGREEMENT_ALG_MLKEM1024 needs my_mlkem_priv,
 * SALT_AGREEMENT_ALG_KYBER_R3 uses my_kyber_priv (same as v1).
 * Returns 0 on success, -1 if fingerprint not found, decryption fails, or
 * the entry's alg needs a key that was not provided (my_mlkem_priv NULL).
 */
int salt_agreement_packet_decrypt_salt(
    const uint8_t *data,
    size_t data_len,
    const uint8_t my_fp_bin[FP_BIN_SIZE],
    const uint8_t *my_kyber_priv,
    const uint8_t *my_mlkem_priv,
    uint8_t salt_out[SALT_AGREEMENT_SIZE]
) {
    if (data_len < PACKET_VERSION_SIZE) return -1;

    uint16_t version;
    memcpy(&version, data, 2);
    version = ntohs(version);

    if (version == SALT_AGREEMENT_VERSION) {
        if (data_len < PACKET_DATA_SIZE) return -1;

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

        return gek_decrypt_alg(SALT_AGREEMENT_ALG_KYBER_R3, my_encrypted,
                               GEK_ENC_TOTAL_SIZE, my_kyber_priv, salt_out);
    }

    if (version == SALT_AGREEMENT_VERSION_V2) {
        if (data_len < PACKET_DATA_SIZE_V2) return -1;

        const uint8_t *my_entry = NULL;
        size_t entry1_offset = PACKET_VERSION_SIZE;
        size_t entry2_offset = PACKET_VERSION_SIZE + PACKET_ENTRY_SIZE_V2;

        if (memcmp(data + entry1_offset, my_fp_bin, FP_BIN_SIZE) == 0) {
            my_entry = data + entry1_offset;
        } else if (memcmp(data + entry2_offset, my_fp_bin, FP_BIN_SIZE) == 0) {
            my_entry = data + entry2_offset;
        } else {
            return -1;  /* My fingerprint not in this packet */
        }

        uint8_t alg = my_entry[FP_BIN_SIZE];
        const uint8_t *encrypted = my_entry + FP_BIN_SIZE + 1;

        if (alg == SALT_AGREEMENT_ALG_MLKEM1024) {
            if (!my_mlkem_priv) return -1;
            return gek_decrypt_alg(SALT_AGREEMENT_ALG_MLKEM1024, encrypted,
                                   GEK_ENC_TOTAL_SIZE, my_mlkem_priv, salt_out);
        }
        if (alg == SALT_AGREEMENT_ALG_KYBER_R3) {
            return gek_decrypt_alg(SALT_AGREEMENT_ALG_KYBER_R3, encrypted,
                                   GEK_ENC_TOTAL_SIZE, my_kyber_priv, salt_out);
        }
        return -1;  /* unknown alg */
    }

    return -1;  /* unsupported version */
}

/**
 * Verify packet signature against one of the two parties' Dilithium pubkeys.
 * data_size is the version-specific data portion (PACKET_DATA_SIZE or
 * PACKET_DATA_SIZE_V2, KEM Faz 1, R9) — the signature covers the data
 * portion exactly as it always has, only its length changed for v2.
 * Returns 0 if signature is valid for either party, -1 if invalid.
 */
int salt_agreement_packet_verify_signature(
    const uint8_t *data,
    size_t data_len,
    size_t data_size,
    const uint8_t *sign_pub_a,
    const uint8_t *sign_pub_b
) {
    if (data_size == 0 || data_len < data_size + 1) return -1;

    const uint8_t *sig = data + data_size;
    size_t sig_len = data_len - data_size;

    /* Try party A's pubkey */
    if (sign_pub_a &&
        qgp_dsa87_verify(sig, sig_len, data, data_size, sign_pub_a) == 0) {
        return 0;
    }

    /* Try party B's pubkey */
    if (sign_pub_b &&
        qgp_dsa87_verify(sig, sig_len, data, data_size, sign_pub_b) == 0) {
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
 * PACKET BUILD (NC-1b)
 * ============================================================================ */

/**
 * Moved from salt_agreement_publish_internal (dht_salt_agreement.c).
 * Plumbing added around the unchanged statements: the argument check (the
 * caller keeps its own identical one, plus packet / total_size_out); the
 * packet buffer is the caller's, so `memset(packet, 0, sizeof(packet))`
 * became `memset(packet, 0, PACKET_TOTAL_SIZE_V2)` (sizeof of an array
 * parameter is the pointer size); the size goes out through
 * total_size_out. The DHT key is computed by the caller BEFORE this call
 * (same failure order as before).
 */
int salt_agreement_build_packet(
    const char *my_fp,
    const char *contact_fp,
    const uint8_t salt[SALT_AGREEMENT_SIZE],
    const uint8_t *my_kyber_pub,
    const uint8_t *contact_kyber_pub,
    const uint8_t *my_mlkem_pub,
    const uint8_t *contact_mlkem_pub,
    const uint8_t *my_dilithium_priv,
    uint8_t packet[PACKET_TOTAL_SIZE_V2],
    size_t *total_size_out
) {
    if (!my_fp || !contact_fp || !salt || !my_kyber_pub ||
        !contact_kyber_pub || !my_dilithium_priv || !packet || !total_size_out) {
        return -1;
    }

    bool use_v2 = (my_mlkem_pub != NULL && contact_mlkem_pub != NULL);

    /* Sort fingerprints to determine packet order */
    const char *lower_fp, *higher_fp;
    const uint8_t *lower_kyber, *higher_kyber;
    const uint8_t *lower_mlkem, *higher_mlkem;
    if (strcmp(my_fp, contact_fp) <= 0) {
        lower_fp = my_fp;
        higher_fp = contact_fp;
        lower_kyber = my_kyber_pub;
        higher_kyber = contact_kyber_pub;
        lower_mlkem = my_mlkem_pub;
        higher_mlkem = contact_mlkem_pub;
    } else {
        lower_fp = contact_fp;
        higher_fp = my_fp;
        lower_kyber = contact_kyber_pub;
        higher_kyber = my_kyber_pub;
        lower_mlkem = contact_mlkem_pub;
        higher_mlkem = my_mlkem_pub;
    }

    /* Build packet — the caller's buffer is sized for the larger (v2)
     * layout; only the first `data_size` (+ signature) bytes are ever
     * used/published. */
    memset(packet, 0, PACKET_TOTAL_SIZE_V2);
    size_t offset = 0;

    /* Version (network byte order) */
    uint16_t version = htons(use_v2 ? SALT_AGREEMENT_VERSION_V2 : SALT_AGREEMENT_VERSION);
    memcpy(packet + offset, &version, 2);
    offset += 2;

    /* Entry 1: lower fingerprint + [alg byte, v2 only] + encrypted salt */
    uint8_t fp_bin[FP_BIN_SIZE];
    if (salt_agreement_fp_hex_to_bin(lower_fp, fp_bin) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid lower fingerprint");
        return -1;
    }
    memcpy(packet + offset, fp_bin, FP_BIN_SIZE);
    offset += FP_BIN_SIZE;

    if (use_v2) {
        packet[offset] = SALT_AGREEMENT_ALG_MLKEM1024;
        offset += 1;
        if (gek_encrypt_alg(SALT_AGREEMENT_ALG_MLKEM1024, salt, lower_mlkem, packet + offset) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to encrypt salt for lower party (v2)");
            return -1;
        }
    } else {
        if (gek_encrypt(salt, lower_kyber, packet + offset) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to encrypt salt for lower party");
            return -1;
        }
    }
    offset += GEK_ENC_TOTAL_SIZE;

    /* Entry 2: higher fingerprint + [alg byte, v2 only] + encrypted salt */
    if (salt_agreement_fp_hex_to_bin(higher_fp, fp_bin) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid higher fingerprint");
        return -1;
    }
    memcpy(packet + offset, fp_bin, FP_BIN_SIZE);
    offset += FP_BIN_SIZE;

    if (use_v2) {
        packet[offset] = SALT_AGREEMENT_ALG_MLKEM1024;
        offset += 1;
        if (gek_encrypt_alg(SALT_AGREEMENT_ALG_MLKEM1024, salt, higher_mlkem, packet + offset) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to encrypt salt for higher party (v2)");
            return -1;
        }
    } else {
        if (gek_encrypt(salt, higher_kyber, packet + offset) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to encrypt salt for higher party");
            return -1;
        }
    }
    offset += GEK_ENC_TOTAL_SIZE;

    size_t data_size = offset;  /* == PACKET_DATA_SIZE or PACKET_DATA_SIZE_V2 */

    /* Sign the data portion with Dilithium5 — same mechanism for v1 and v2,
     * only the length of what's signed changed. */
    size_t sig_len = 0;
    if (qgp_dsa87_sign(packet + offset, &sig_len,
                        packet, data_size,
                        my_dilithium_priv) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to sign agreement packet");
        return -1;
    }

    size_t total_size = data_size + sig_len;

    *total_size_out = total_size;
    return 0;
}
