/**
 * @file seed_storage.c
 * @brief Encrypted Master Seed Storage Implementation
 *
 * Uses Kyber1024 KEM + AES-256-GCM for post-quantum secure seed storage.
 *
 * @author DNA Messenger Team
 * @date 2025-12-11
 */

#include "seed_storage.h"
#include "qgp_kyber.h"
#include "qgp_aes.h"
#include "qgp_platform.h"
#include "qgp_log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#ifdef _WIN32
#include <io.h>
#else
#include <unistd.h>
#include <sys/stat.h>
#endif

#define LOG_TAG "SEED_STORAGE"

/* ============================================================================
 * INTERNAL HELPERS
 * ============================================================================ */

/**
 * Securely wipe memory
 */
static void secure_memzero(void *ptr, size_t len) {
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--) {
        *p++ = 0;
    }
}

/**
 * Build full path to seed file
 */
static int build_seed_path(const char *identity_dir, char *path_out, size_t path_size) {
    if (!identity_dir || !path_out || path_size < 32) {
        return -1;
    }

    int written = snprintf(path_out, path_size, "%s/%s", identity_dir, SEED_STORAGE_FILE);
    if (written < 0 || (size_t)written >= path_size) {
        return -1;
    }

    return 0;
}

/**
 * Set file permissions to owner-only (0600)
 */
static int set_file_permissions(const char *path) {
#ifdef _WIN32
    /* Windows: no direct chmod equivalent, skip */
    (void)path;
    return 0;
#else
    if (chmod(path, S_IRUSR | S_IWUSR) != 0) {
        QGP_LOG_WARN(LOG_TAG, "Failed to set file permissions: %s", strerror(errno));
        return -1;
    }
    return 0;
#endif
}

/* ============================================================================
 * PUBLIC FUNCTIONS
 * ============================================================================ */

int seed_storage_save(
    const uint8_t master_seed[64],
    const uint8_t kem_pubkey[1568],
    const char *identity_dir
) {
    if (!master_seed || !kem_pubkey || !identity_dir) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid arguments to seed_storage_save");
        return -1;
    }

    int result = -1;
    FILE *fp = NULL;
    uint8_t *file_buffer = NULL;

    /* Buffers for KEM and AES */
    uint8_t kem_ciphertext[SEED_STORAGE_KEM_CT_SIZE];
    uint8_t shared_secret[32];  /* Kyber1024 shared secret is 32 bytes */
    uint8_t nonce[SEED_STORAGE_NONCE_SIZE];
    uint8_t tag[SEED_STORAGE_TAG_SIZE];
    uint8_t encrypted_seed[SEED_STORAGE_SEED_SIZE];
    size_t encrypted_len = 0;

    /* Build file path */
    char seed_path[512];
    if (build_seed_path(identity_dir, seed_path, sizeof(seed_path)) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to build seed path");
        goto cleanup;
    }

    /* Step 1: Kyber1024 encapsulation */
    QGP_LOG_DEBUG(LOG_TAG, "Performing KEM encapsulation...");
    if (qgp_kem1024_encapsulate(kem_ciphertext, shared_secret, kem_pubkey) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "KEM encapsulation failed");
        goto cleanup;
    }

    /* Step 2: AES-256-GCM encryption of master seed */
    QGP_LOG_DEBUG(LOG_TAG, "Encrypting master seed with AES-256-GCM...");
    if (qgp_aes256_encrypt(
            shared_secret,              /* 32-byte key from KEM */
            master_seed, 64,            /* plaintext: master seed */
            NULL, 0,                    /* no AAD */
            encrypted_seed, &encrypted_len,
            nonce, tag) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "AES-256-GCM encryption failed");
        goto cleanup;
    }

    if (encrypted_len != SEED_STORAGE_SEED_SIZE) {
        QGP_LOG_ERROR(LOG_TAG, "Unexpected encrypted length: %zu (expected %d)",
                      encrypted_len, SEED_STORAGE_SEED_SIZE);
        goto cleanup;
    }

    /* Step 3: Write to file */
    /* Format: kem_ciphertext (1568) || nonce (12) || tag (16) || encrypted_seed (64) */
    file_buffer = malloc(SEED_STORAGE_TOTAL_SIZE);
    if (!file_buffer) {
        QGP_LOG_ERROR(LOG_TAG, "Memory allocation failed");
        goto cleanup;
    }

    size_t offset = 0;
    memcpy(file_buffer + offset, kem_ciphertext, SEED_STORAGE_KEM_CT_SIZE);
    offset += SEED_STORAGE_KEM_CT_SIZE;
    memcpy(file_buffer + offset, nonce, SEED_STORAGE_NONCE_SIZE);
    offset += SEED_STORAGE_NONCE_SIZE;
    memcpy(file_buffer + offset, tag, SEED_STORAGE_TAG_SIZE);
    offset += SEED_STORAGE_TAG_SIZE;
    memcpy(file_buffer + offset, encrypted_seed, SEED_STORAGE_SEED_SIZE);

    /* Write file */
    fp = fopen(seed_path, "wb");
    if (!fp) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to open file for writing: %s (%s)",
                      seed_path, strerror(errno));
        goto cleanup;
    }

    if (fwrite(file_buffer, 1, SEED_STORAGE_TOTAL_SIZE, fp) != SEED_STORAGE_TOTAL_SIZE) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to write seed file");
        goto cleanup;
    }

    fclose(fp);
    fp = NULL;

    /* Set restrictive permissions */
    set_file_permissions(seed_path);

    QGP_LOG_INFO(LOG_TAG, "Master seed saved securely to %s", seed_path);
    result = 0;

cleanup:
    /* Securely wipe sensitive data */
    secure_memzero(shared_secret, sizeof(shared_secret));
    secure_memzero(encrypted_seed, sizeof(encrypted_seed));
    if (file_buffer) {
        secure_memzero(file_buffer, SEED_STORAGE_TOTAL_SIZE);
        free(file_buffer);
    }
    if (fp) {
        fclose(fp);
    }

    return result;
}

int seed_storage_load(
    uint8_t master_seed_out[64],
    const uint8_t kem_privkey[3168],
    const char *identity_dir
) {
    if (!master_seed_out || !kem_privkey || !identity_dir) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid arguments to seed_storage_load");
        return -1;
    }

    int result = -1;
    FILE *fp = NULL;
    uint8_t *file_buffer = NULL;

    /* Buffers for KEM and AES */
    uint8_t shared_secret[32];
    size_t decrypted_len = 0;

    /* Build file path */
    char seed_path[512];
    if (build_seed_path(identity_dir, seed_path, sizeof(seed_path)) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to build seed path");
        goto cleanup;
    }

    /* Check if file exists */
    if (!seed_storage_exists(identity_dir)) {
        QGP_LOG_DEBUG(LOG_TAG, "Seed file does not exist: %s", seed_path);
        goto cleanup;
    }

    /* Read file */
    fp = fopen(seed_path, "rb");
    if (!fp) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to open seed file: %s (%s)",
                      seed_path, strerror(errno));
        goto cleanup;
    }

    file_buffer = malloc(SEED_STORAGE_TOTAL_SIZE);
    if (!file_buffer) {
        QGP_LOG_ERROR(LOG_TAG, "Memory allocation failed");
        goto cleanup;
    }

    if (fread(file_buffer, 1, SEED_STORAGE_TOTAL_SIZE, fp) != SEED_STORAGE_TOTAL_SIZE) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to read seed file (truncated?)");
        goto cleanup;
    }

    fclose(fp);
    fp = NULL;

    /* Parse file buffer */
    size_t offset = 0;
    const uint8_t *kem_ciphertext = file_buffer + offset;
    offset += SEED_STORAGE_KEM_CT_SIZE;
    const uint8_t *nonce = file_buffer + offset;
    offset += SEED_STORAGE_NONCE_SIZE;
    const uint8_t *tag = file_buffer + offset;
    offset += SEED_STORAGE_TAG_SIZE;
    const uint8_t *encrypted_seed = file_buffer + offset;

    /* Step 1: Kyber1024 decapsulation */
    QGP_LOG_DEBUG(LOG_TAG, "Performing KEM decapsulation...");
    if (qgp_kem1024_decapsulate(shared_secret, kem_ciphertext, kem_privkey) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "KEM decapsulation failed");
        goto cleanup;
    }

    /* Step 2: AES-256-GCM decryption */
    QGP_LOG_DEBUG(LOG_TAG, "Decrypting master seed with AES-256-GCM...");
    if (qgp_aes256_decrypt(
            shared_secret,
            encrypted_seed, SEED_STORAGE_SEED_SIZE,
            NULL, 0,  /* no AAD */
            nonce, tag,
            master_seed_out, &decrypted_len) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "AES-256-GCM decryption failed (auth tag mismatch?)");
        /* Wipe output on failure */
        secure_memzero(master_seed_out, 64);
        goto cleanup;
    }

    if (decrypted_len != 64) {
        QGP_LOG_ERROR(LOG_TAG, "Unexpected decrypted length: %zu (expected 64)", decrypted_len);
        secure_memzero(master_seed_out, 64);
        goto cleanup;
    }

    QGP_LOG_INFO(LOG_TAG, "Master seed loaded successfully from %s", seed_path);
    result = 0;

cleanup:
    /* Securely wipe sensitive data */
    secure_memzero(shared_secret, sizeof(shared_secret));
    if (file_buffer) {
        secure_memzero(file_buffer, SEED_STORAGE_TOTAL_SIZE);
        free(file_buffer);
    }
    if (fp) {
        fclose(fp);
    }

    return result;
}

bool seed_storage_exists(const char *identity_dir) {
    if (!identity_dir) {
        return false;
    }

    char seed_path[512];
    if (build_seed_path(identity_dir, seed_path, sizeof(seed_path)) != 0) {
        return false;
    }

    FILE *fp = fopen(seed_path, "rb");
    if (fp) {
        fclose(fp);
        return true;
    }
    return false;
}

int seed_storage_delete(const char *identity_dir) {
    if (!identity_dir) {
        return -1;
    }

    char seed_path[512];
    if (build_seed_path(identity_dir, seed_path, sizeof(seed_path)) != 0) {
        return -1;
    }

    if (remove(seed_path) != 0) {
        if (errno != ENOENT) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to delete seed file: %s (%s)",
                          seed_path, strerror(errno));
            return -1;
        }
    }

    QGP_LOG_INFO(LOG_TAG, "Seed file deleted: %s", seed_path);
    return 0;
}
