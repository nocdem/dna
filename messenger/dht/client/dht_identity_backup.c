/**
 * DHT Identity Backup Implementation
 * Encrypted backup of random DHT signing identity for BIP39 recovery
 *
 * Uses dht_chunked layer for automatic chunking, compression, and parallel fetch.
 *
 * @file dht_identity_backup.c
 * @author DNA Messenger Team
 * @date 2025-11-12
 */

#include "dht_identity_backup.h"
#include "../shared/dht_chunked.h"
#include "../crypto/utils/qgp_sha3.h"
#include "../crypto/utils/qgp_platform.h"
#include "../crypto/utils/qgp_aes.h"
#include "../crypto/utils/qgp_random.h"
#include "../crypto/kem/kem.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>
#ifdef _WIN32
#include <direct.h>
#define mkdir(path, mode) _mkdir(path)
#endif
#include "../crypto/utils/qgp_log.h"

#define LOG_TAG "DHT_BACKUP"

//=============================================================================
// Helper Functions
//=============================================================================

/**
 * Generate base key string for identity backup storage
 * Format: "fingerprint:dht_identity"
 * The dht_chunked layer handles hashing internally
 */
static int make_base_key(const char *user_fingerprint, char *key_out, size_t key_out_size) {
    if (!user_fingerprint || !key_out) return -1;

    // Fingerprint is 128-char hex string
    size_t fp_len = strlen(user_fingerprint);
    if (fp_len != 128) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid fingerprint length: %zu (expected 128)\n", fp_len);
        return -1;
    }

    int ret = snprintf(key_out, key_out_size, "%s:dht_identity", user_fingerprint);
    if (ret < 0 || (size_t)ret >= key_out_size) {
        QGP_LOG_ERROR(LOG_TAG, "Base key buffer too small\n");
        return -1;
    }

    return 0;
}

/**
 * Get local backup file path
 */
int dht_identity_get_local_path(const char *user_fingerprint, char *path_out) {
    if (!user_fingerprint || !path_out) return -1;

    const char *home = qgp_platform_home_dir();
    if (!home) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to get home directory\n");
        return -1;
    }

#ifdef _WIN32
    snprintf(path_out, 512, "%s\\.dna\\%s\\dht_identity.enc", home, user_fingerprint);
#else
    snprintf(path_out, 512, "%s/.dna/%s/dht_identity.enc", home, user_fingerprint);
#endif

    return 0;
}

/**
 * Ensure identity directory exists (creates ~/.dna/<fingerprint>/ and ~/.dna/<fingerprint>/db/)
 */
static int ensure_identity_dir(const char *user_fingerprint) {
    const char *home = qgp_platform_home_dir();
    if (!home) return -1;

    // Create ~/.dna directory
    char dna_dir[512];
#ifdef _WIN32
    snprintf(dna_dir, sizeof(dna_dir), "%s\\.dna", home);
    mkdir(dna_dir);
#else
    snprintf(dna_dir, sizeof(dna_dir), "%s/.dna", home);
    mkdir(dna_dir, 0700);
#endif

    // Create ~/.dna/<fingerprint> directory
    char identity_dir[512];
#ifdef _WIN32
    snprintf(identity_dir, sizeof(identity_dir), "%s\\.dna\\%s", home, user_fingerprint);
    mkdir(identity_dir);
#else
    snprintf(identity_dir, sizeof(identity_dir), "%s/.dna/%s", home, user_fingerprint);
    mkdir(identity_dir, 0700);
#endif

    // Create ~/.dna/<fingerprint>/db directory
    char db_dir[512];
#ifdef _WIN32
    snprintf(db_dir, sizeof(db_dir), "%s\\.dna\\%s\\db", home, user_fingerprint);
    mkdir(db_dir);
#else
    snprintf(db_dir, sizeof(db_dir), "%s/.dna/%s/db", home, user_fingerprint);
    mkdir(db_dir, 0700);
#endif

    return 0;
}

/**
 * Save encrypted backup to local file
 */
static int save_to_local_file(
    const char *user_fingerprint,
    const uint8_t *encrypted_data,
    size_t encrypted_size)
{
    if (!user_fingerprint || !encrypted_data) return -1;

    // Ensure identity directory exists
    if (ensure_identity_dir(user_fingerprint) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to create identity directory\n");
        return -1;
    }

    char path[512];
    if (dht_identity_get_local_path(user_fingerprint, path) != 0) {
        return -1;
    }

    FILE *fp = fopen(path, "wb");
    if (!fp) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to create file: %s (errno %d)\n", path, errno);
        return -1;
    }

    size_t written = fwrite(encrypted_data, 1, encrypted_size, fp);
    fclose(fp);

    if (written != encrypted_size) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to write complete file\n");
        return -1;
    }

    // Set permissions to 600 (owner read/write only)
#ifndef _WIN32
    chmod(path, S_IRUSR | S_IWUSR);
#endif

    QGP_LOG_INFO(LOG_TAG, "Saved to local file: %s (%zu bytes)\n", path, encrypted_size);
    return 0;
}

/**
 * Read encrypted backup from local file
 */
static int read_from_local_file(
    const char *user_fingerprint,
    uint8_t **data_out,
    size_t *size_out)
{
    if (!user_fingerprint || !data_out || !size_out) return -1;

    char path[512];
    if (dht_identity_get_local_path(user_fingerprint, path) != 0) {
        return -1;
    }

    FILE *fp = fopen(path, "rb");
    if (!fp) {
        // File not found is expected on first login
        return -1;
    }

    // Get file size
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (file_size <= 0 || file_size > 10 * 1024 * 1024) {  // Max 10MB
        QGP_LOG_ERROR(LOG_TAG, "Invalid file size: %ld\n", file_size);
        fclose(fp);
        return -1;
    }

    uint8_t *data = (uint8_t*)malloc(file_size);
    if (!data) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to allocate buffer\n");
        fclose(fp);
        return -1;
    }

    size_t read_size = fread(data, 1, file_size, fp);
    fclose(fp);

    if ((long)read_size != file_size) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to read complete file\n");
        free(data);
        return -1;
    }

    *data_out = data;
    *size_out = read_size;

    QGP_LOG_INFO(LOG_TAG, "Read from local file: %s (%zu bytes)\n", path, read_size);
    return 0;
}

//=============================================================================
// Public API
//=============================================================================

/**
 * Create new random DHT identity and save encrypted backup
 */
int dht_identity_create_and_backup(
    const char *user_fingerprint,
    const uint8_t *kyber_pubkey,
    dht_context_t *dht_ctx,
    dht_identity_t **identity_out)
{
    if (!user_fingerprint || !kyber_pubkey || !dht_ctx || !identity_out) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid parameters for create_and_backup\n");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Creating new random DHT identity for %s\n", user_fingerprint);

    // Step 1: Generate random DHT identity (RSA-2048)
    dht_identity_t *identity = NULL;
    if (dht_identity_generate_random(&identity) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to generate random identity\n");
        return -1;
    }

    // Step 2: Export identity to PEM buffer
    uint8_t *pem_buffer = NULL;
    size_t pem_size = 0;
    if (dht_identity_export_to_buffer(identity, &pem_buffer, &pem_size) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to export identity\n");
        dht_identity_free(identity);
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Exported identity to PEM buffer (%zu bytes)\n", pem_size);

    // Step 3: Encrypt with Kyber1024 public key using Kyber KEM + AES-256-GCM
    // Format: [kyber_ct(1568)][aes_iv(12)][aes_tag(16)][encrypted_pem]

    // Kyber encapsulation (generate shared secret)
    uint8_t kyber_ct[1568];  // Kyber1024 ciphertext size
    uint8_t shared_secret[32];  // Kyber output is 32 bytes

    if (crypto_kem_enc(kyber_ct, shared_secret, kyber_pubkey) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Kyber encapsulation failed\n");
        free(pem_buffer);
        dht_identity_free(identity);
        return -1;
    }

    // AES-256-GCM encryption with shared secret as key
    uint8_t iv[12];  // GCM IV
    uint8_t tag[16]; // GCM authentication tag
    qgp_randombytes(iv, sizeof(iv));

    uint8_t *encrypted_pem = (uint8_t*)malloc(pem_size);
    if (!encrypted_pem) {
        QGP_LOG_ERROR(LOG_TAG, "Memory allocation failed\n");
        free(pem_buffer);
        dht_identity_free(identity);
        return -1;
    }

    size_t encrypted_pem_len = pem_size;
    if (qgp_aes256_encrypt(shared_secret, pem_buffer, pem_size, NULL, 0,
                           encrypted_pem, &encrypted_pem_len, iv, tag) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "AES encryption failed\n");
        free(pem_buffer);
        free(encrypted_pem);
        dht_identity_free(identity);
        return -1;
    }

    free(pem_buffer);

    // Construct final encrypted blob
    size_t total_size = 1568 + 12 + 16 + pem_size;
    uint8_t *encrypted_data = (uint8_t*)malloc(total_size);
    if (!encrypted_data) {
        QGP_LOG_ERROR(LOG_TAG, "Memory allocation failed\n");
        free(encrypted_pem);
        dht_identity_free(identity);
        return -1;
    }

    memcpy(encrypted_data, kyber_ct, 1568);
    memcpy(encrypted_data + 1568, iv, 12);
    memcpy(encrypted_data + 1568 + 12, tag, 16);
    memcpy(encrypted_data + 1568 + 12 + 16, encrypted_pem, pem_size);
    free(encrypted_pem);

    QGP_LOG_INFO(LOG_TAG, "Encrypted identity (%zu bytes)\n", total_size);

    // Step 4: Save to local file
    if (save_to_local_file(user_fingerprint, encrypted_data, total_size) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Warning: Failed to save to local file\n");
        // Continue anyway - try DHT
    }

    // Step 5: Publish to DHT
    int publish_result = dht_identity_publish_backup(
        user_fingerprint, encrypted_data, total_size, dht_ctx);

    if (publish_result != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Warning: Failed to publish to DHT\n");
        // Continue anyway - local file exists
    }

    free(encrypted_data);

    *identity_out = identity;
    QGP_LOG_INFO(LOG_TAG, "Successfully created and backed up identity\n");
    return 0;
}

/**
 * Load DHT identity from local encrypted backup
 */
int dht_identity_load_from_local(
    const char *user_fingerprint,
    const uint8_t *kyber_privkey,
    dht_identity_t **identity_out)
{
    if (!user_fingerprint || !kyber_privkey || !identity_out) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid parameters for load_from_local\n");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Loading from local file for %s\n", user_fingerprint);

    // Step 1: Read encrypted backup from file
    uint8_t *encrypted_data = NULL;
    size_t encrypted_size = 0;
    if (read_from_local_file(user_fingerprint, &encrypted_data, &encrypted_size) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Local file not found\n");
        return -1;
    }

    // Step 2: Decrypt with Kyber1024 private key using Kyber KEM + AES-256-GCM
    // Format: [kyber_ct(1568)][aes_iv(12)][aes_tag(16)][encrypted_pem]

    if (encrypted_size < 1568 + 12 + 16) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid encrypted backup size: %zu\n", encrypted_size);
        free(encrypted_data);
        return -1;
    }

    // Extract components
    uint8_t *kyber_ct = encrypted_data;
    uint8_t *iv = encrypted_data + 1568;
    uint8_t *tag = encrypted_data + 1568 + 12;
    uint8_t *encrypted_pem = encrypted_data + 1568 + 12 + 16;
    size_t encrypted_pem_size = encrypted_size - (1568 + 12 + 16);

    // Kyber decapsulation (recover shared secret)
    uint8_t shared_secret[32];
    if (crypto_kem_dec(shared_secret, kyber_ct, kyber_privkey) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Kyber decapsulation failed\n");
        free(encrypted_data);
        return -1;
    }

    // AES-256-GCM decryption
    uint8_t *decrypted_pem = malloc(encrypted_pem_size);
    if (!decrypted_pem) {
        QGP_LOG_ERROR(LOG_TAG, "Memory allocation failed\n");
        free(encrypted_data);
        return -1;
    }

    size_t decrypted_pem_len = encrypted_pem_size;
    if (qgp_aes256_decrypt(shared_secret, encrypted_pem, encrypted_pem_size, NULL, 0,
                           iv, tag, decrypted_pem, &decrypted_pem_len) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "AES decryption failed (corrupted or wrong key)\n");
        free(encrypted_data);
        free(decrypted_pem);
        return -1;
    }

    free(encrypted_data);
    QGP_LOG_INFO(LOG_TAG, "Decrypted identity (%zu bytes)\n", decrypted_pem_len);

    // Step 3: Import PEM data to DHT identity
    dht_identity_t *identity = NULL;
    if (dht_identity_import_from_buffer(decrypted_pem, decrypted_pem_len, &identity) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to import identity from buffer\n");
        free(decrypted_pem);
        return -1;
    }

    free(decrypted_pem);

    *identity_out = identity;
    QGP_LOG_INFO(LOG_TAG, "Successfully loaded from local file\n");
    return 0;
}

/**
 * Fetch DHT identity from DHT and decrypt (recovery on new device)
 */
int dht_identity_fetch_from_dht(
    const char *user_fingerprint,
    const uint8_t *kyber_privkey,
    dht_context_t *dht_ctx,
    dht_identity_t **identity_out)
{
    if (!user_fingerprint || !kyber_privkey || !dht_ctx || !identity_out) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid parameters for fetch_from_dht\n");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Fetching from DHT for %s\n", user_fingerprint);

    // Step 1: Generate base key for chunked storage
    char base_key[256];
    if (make_base_key(user_fingerprint, base_key, sizeof(base_key)) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to generate base key\n");
        return -1;
    }

    // Step 2: Fetch from DHT using chunked layer
    uint8_t *encrypted_data = NULL;
    size_t encrypted_size = 0;

    if (dht_chunked_fetch(dht_ctx, base_key, &encrypted_data, &encrypted_size) != DHT_CHUNK_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Not found in DHT\n");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Fetched from DHT (%zu bytes)\n", encrypted_size);

    // Step 3: Decrypt with Kyber1024 private key using Kyber KEM + AES-256-GCM
    // Format: [kyber_ct(1568)][aes_iv(12)][aes_tag(16)][encrypted_pem]

    if (encrypted_size < 1568 + 12 + 16) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid DHT backup size: %zu\n", encrypted_size);
        free(encrypted_data);
        return -1;
    }

    // Extract components
    uint8_t *kyber_ct = encrypted_data;
    uint8_t *iv = encrypted_data + 1568;
    uint8_t *tag = encrypted_data + 1568 + 12;
    uint8_t *encrypted_pem = encrypted_data + 1568 + 12 + 16;
    size_t encrypted_pem_size = encrypted_size - (1568 + 12 + 16);

    // Kyber decapsulation (recover shared secret)
    uint8_t shared_secret[32];
    if (crypto_kem_dec(shared_secret, kyber_ct, kyber_privkey) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Kyber decapsulation failed\n");
        free(encrypted_data);
        return -1;
    }

    // AES-256-GCM decryption
    uint8_t *decrypted_pem = malloc(encrypted_pem_size);
    if (!decrypted_pem) {
        QGP_LOG_ERROR(LOG_TAG, "Memory allocation failed\n");
        free(encrypted_data);
        return -1;
    }

    size_t decrypted_pem_len2 = encrypted_pem_size;
    if (qgp_aes256_decrypt(shared_secret, encrypted_pem, encrypted_pem_size, NULL, 0,
                           iv, tag, decrypted_pem, &decrypted_pem_len2) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "AES decryption failed (corrupted or wrong key)\n");
        free(encrypted_data);
        free(decrypted_pem);
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Decrypted identity (%zu bytes)\n", decrypted_pem_len2);

    // Step 4: Save to local file (for next login)
    if (save_to_local_file(user_fingerprint, encrypted_data, encrypted_size) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Warning: Failed to save to local file\n");
        // Continue anyway
    }

    free(encrypted_data);

    // Step 5: Import to DHT identity
    dht_identity_t *identity = NULL;
    if (dht_identity_import_from_buffer(decrypted_pem, decrypted_pem_len2, &identity) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to import identity from buffer\n");
        free(decrypted_pem);
        return -1;
    }

    free(decrypted_pem);

    *identity_out = identity;
    QGP_LOG_INFO(LOG_TAG, "Successfully fetched and recovered from DHT\n");
    return 0;
}

/**
 * Publish encrypted DHT identity backup to DHT
 */
int dht_identity_publish_backup(
    const char *user_fingerprint,
    const uint8_t *encrypted_backup,
    size_t backup_size,
    dht_context_t *dht_ctx)
{
    if (!user_fingerprint || !encrypted_backup || !dht_ctx) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid parameters for publish_backup\n");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Publishing backup to DHT for %s (%zu bytes)\n",
           user_fingerprint, backup_size);

    // Generate base key for chunked storage
    char base_key[256];
    if (make_base_key(user_fingerprint, base_key, sizeof(base_key)) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to generate base key\n");
        return -1;
    }

    // Publish to DHT using chunked layer (handles compression, chunking, signing)
    int result = dht_chunked_publish(dht_ctx, base_key, encrypted_backup, backup_size, DHT_CHUNK_TTL_365DAY);

    if (result != DHT_CHUNK_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to publish to DHT: %s\n", dht_chunked_strerror(result));
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Successfully published to DHT\n");
    return 0;
}

/**
 * Check if local backup file exists
 */
bool dht_identity_local_exists(const char *user_fingerprint) {
    if (!user_fingerprint) return false;

    char path[512];
    if (dht_identity_get_local_path(user_fingerprint, path) != 0) {
        return false;
    }

    struct stat st;
    return (stat(path, &st) == 0);
}

/**
 * Check if DHT backup exists
 */
bool dht_identity_dht_exists(
    const char *user_fingerprint,
    dht_context_t *dht_ctx)
{
    if (!user_fingerprint || !dht_ctx) return false;

    char base_key[256];
    if (make_base_key(user_fingerprint, base_key, sizeof(base_key)) != 0) {
        return false;
    }

    uint8_t *data = NULL;
    size_t size = 0;
    int result = dht_chunked_fetch(dht_ctx, base_key, &data, &size);

    if (result == DHT_CHUNK_OK && data) {
        free(data);
        return true;
    }

    return false;
}
