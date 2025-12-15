/*
 * qgp_key.c - QGP Key Management 
 *
 * Memory management and serialization for QGP keys.
 * Uses QGP's own file format with no external dependencies.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypto/utils/qgp_types.h"
#include "crypto/utils/qgp_log.h"
#include "crypto/utils/key_encryption.h"

// ============================================================================
// KEY MEMORY MANAGEMENT
// ============================================================================

/**
 * Create a new QGP key structure
 *
 * @param type: Key algorithm type
 * @param purpose: Key purpose (signing or encryption)
 * @return: Allocated key structure (caller must free with qgp_key_free())
 */
qgp_key_t* qgp_key_new(qgp_key_type_t type, qgp_key_purpose_t purpose) {
    qgp_key_t *key = QGP_CALLOC(1, sizeof(qgp_key_t));
    if (!key) {
        return NULL;
    }

    key->type = type;
    key->purpose = purpose;
    key->public_key = NULL;
    key->public_key_size = 0;
    key->private_key = NULL;
    key->private_key_size = 0;
    memset(key->name, 0, sizeof(key->name));

    return key;
}

/**
 * Free a QGP key structure
 *
 * @param key: Key to free (can be NULL)
 */
void qgp_key_free(qgp_key_t *key) {
    if (!key) {
        return;
    }

    // Securely wipe private key before freeing
    if (key->private_key) {
        memset(key->private_key, 0, key->private_key_size);
        QGP_FREE(key->private_key);
    }

    // Free public key
    if (key->public_key) {
        QGP_FREE(key->public_key);
    }

    // Wipe and free key structure
    memset(key, 0, sizeof(qgp_key_t));
    QGP_FREE(key);
}

// ============================================================================
// KEY SERIALIZATION
// ============================================================================

/**
 * Save private key to file
 *
 * File format: [header | public_key | private_key]
 *
 * @param key: Key to save
 * @param path: Output file path
 * @return: 0 on success, -1 on error
 */
int qgp_key_save(const qgp_key_t *key, const char *path) {
    if (!key || !path) {
        QGP_LOG_ERROR("KEY", "qgp_key_save: Invalid arguments");
        return -1;
    }

    if (!key->public_key || !key->private_key) {
        QGP_LOG_ERROR("KEY", "qgp_key_save: Key has no public or private key data");
        return -1;
    }

    FILE *fp = fopen(path, "wb");
    if (!fp) {
        QGP_LOG_ERROR("KEY", "qgp_key_save: Cannot open file: %s", path);
        return -1;
    }

    // Prepare header
    qgp_privkey_file_header_t header;
    memset(&header, 0, sizeof(header));
    memcpy(header.magic, QGP_PRIVKEY_MAGIC, 8);
    header.version = QGP_PRIVKEY_VERSION;
    header.key_type = key->type;
    header.purpose = key->purpose;
    header.public_key_size = key->public_key_size;
    header.private_key_size = key->private_key_size;
    strncpy(header.name, key->name, sizeof(header.name) - 1);

    // Write header
    if (fwrite(&header, sizeof(header), 1, fp) != 1) {
        QGP_LOG_ERROR("KEY", "qgp_key_save: Failed to write header");
        fclose(fp);
        return -1;
    }

    // Write public key
    if (fwrite(key->public_key, 1, key->public_key_size, fp) != key->public_key_size) {
        QGP_LOG_ERROR("KEY", "qgp_key_save: Failed to write public key");
        fclose(fp);
        return -1;
    }

    // Write private key
    if (fwrite(key->private_key, 1, key->private_key_size, fp) != key->private_key_size) {
        QGP_LOG_ERROR("KEY", "qgp_key_save: Failed to write private key");
        fclose(fp);
        return -1;
    }

    fclose(fp);
    return 0;
}

/**
 * Load private key from file
 *
 * @param path: Input file path
 * @param key_out: Output key (caller must free with qgp_key_free())
 * @return: 0 on success, -1 on error
 */
int qgp_key_load(const char *path, qgp_key_t **key_out) {
    if (!path || !key_out) {
        QGP_LOG_ERROR("KEY", "qgp_key_load: Invalid arguments");
        return -1;
    }

    FILE *fp = fopen(path, "rb");
    if (!fp) {
        QGP_LOG_ERROR("KEY", "qgp_key_load: Cannot open file: %s", path);
        return -1;
    }

    // Read header
    qgp_privkey_file_header_t header;
    if (fread(&header, sizeof(header), 1, fp) != 1) {
        QGP_LOG_ERROR("KEY", "qgp_key_load: Failed to read header");
        fclose(fp);
        return -1;
    }

    // Validate header
    if (memcmp(header.magic, QGP_PRIVKEY_MAGIC, 8) != 0) {
        QGP_LOG_ERROR("KEY", "qgp_key_load: Invalid magic (not a QGP private key file)");
        fclose(fp);
        return -1;
    }

    if (header.version != QGP_PRIVKEY_VERSION) {
        QGP_LOG_ERROR("KEY", "qgp_key_load: Unsupported version: %d", header.version);
        fclose(fp);
        return -1;
    }

    // Create key structure
    qgp_key_t *key = qgp_key_new((qgp_key_type_t)header.key_type, (qgp_key_purpose_t)header.purpose);
    if (!key) {
        QGP_LOG_ERROR("KEY", "qgp_key_load: Memory allocation failed");
        fclose(fp);
        return -1;
    }

    strncpy(key->name, header.name, sizeof(key->name) - 1);

    // Allocate and read public key
    key->public_key_size = header.public_key_size;
    key->public_key = QGP_MALLOC(key->public_key_size);
    if (!key->public_key) {
        QGP_LOG_ERROR("KEY", "qgp_key_load: Memory allocation failed for public key");
        qgp_key_free(key);
        fclose(fp);
        return -1;
    }

    if (fread(key->public_key, 1, key->public_key_size, fp) != key->public_key_size) {
        QGP_LOG_ERROR("KEY", "qgp_key_load: Failed to read public key");
        qgp_key_free(key);
        fclose(fp);
        return -1;
    }

    // Allocate and read private key
    key->private_key_size = header.private_key_size;
    key->private_key = QGP_MALLOC(key->private_key_size);
    if (!key->private_key) {
        QGP_LOG_ERROR("KEY", "qgp_key_load: Memory allocation failed for private key");
        qgp_key_free(key);
        fclose(fp);
        return -1;
    }

    if (fread(key->private_key, 1, key->private_key_size, fp) != key->private_key_size) {
        QGP_LOG_ERROR("KEY", "qgp_key_load: Failed to read private key");
        qgp_key_free(key);
        fclose(fp);
        return -1;
    }

    fclose(fp);
    *key_out = key;
    return 0;
}

/**
 * Save public key to file
 *
 * @param key: Key containing public key
 * @param path: Output file path
 * @return: 0 on success, -1 on error
 */
int qgp_pubkey_save(const qgp_key_t *key, const char *path) {
    if (!key || !path) {
        QGP_LOG_ERROR("KEY", "qgp_pubkey_save: Invalid arguments");
        return -1;
    }

    if (!key->public_key) {
        QGP_LOG_ERROR("KEY", "qgp_pubkey_save: Key has no public key data");
        return -1;
    }

    FILE *fp = fopen(path, "wb");
    if (!fp) {
        QGP_LOG_ERROR("KEY", "qgp_pubkey_save: Cannot open file: %s", path);
        return -1;
    }

    // Prepare header
    qgp_pubkey_file_header_t header;
    memset(&header, 0, sizeof(header));
    memcpy(header.magic, QGP_PUBKEY_MAGIC, 8);
    header.version = QGP_PUBKEY_VERSION;
    header.key_type = key->type;
    header.purpose = key->purpose;
    header.public_key_size = key->public_key_size;
    strncpy(header.name, key->name, sizeof(header.name) - 1);

    // Write header
    if (fwrite(&header, sizeof(header), 1, fp) != 1) {
        QGP_LOG_ERROR("KEY", "qgp_pubkey_save: Failed to write header");
        fclose(fp);
        return -1;
    }

    // Write public key
    if (fwrite(key->public_key, 1, key->public_key_size, fp) != key->public_key_size) {
        QGP_LOG_ERROR("KEY", "qgp_pubkey_save: Failed to write public key");
        fclose(fp);
        return -1;
    }

    fclose(fp);
    return 0;
}

/**
 * Load public key from file
 *
 * @param path: Input file path
 * @param key_out: Output key (caller must free with qgp_key_free())
 * @return: 0 on success, -1 on error
 */
int qgp_pubkey_load(const char *path, qgp_key_t **key_out) {
    if (!path || !key_out) {
        QGP_LOG_ERROR("KEY", "qgp_pubkey_load: Invalid arguments");
        return -1;
    }

    FILE *fp = fopen(path, "rb");
    if (!fp) {
        QGP_LOG_ERROR("KEY", "qgp_pubkey_load: Cannot open file: %s", path);
        return -1;
    }

    // Read header
    qgp_pubkey_file_header_t header;
    if (fread(&header, sizeof(header), 1, fp) != 1) {
        QGP_LOG_ERROR("KEY", "qgp_pubkey_load: Failed to read header");
        fclose(fp);
        return -1;
    }

    // Validate header
    if (memcmp(header.magic, QGP_PUBKEY_MAGIC, 8) != 0) {
        QGP_LOG_ERROR("KEY", "qgp_pubkey_load: Invalid magic (not a QGP public key file)");
        fclose(fp);
        return -1;
    }

    if (header.version != QGP_PUBKEY_VERSION) {
        QGP_LOG_ERROR("KEY", "qgp_pubkey_load: Unsupported version: %d", header.version);
        fclose(fp);
        return -1;
    }

    // Create key structure
    qgp_key_t *key = qgp_key_new((qgp_key_type_t)header.key_type, (qgp_key_purpose_t)header.purpose);
    if (!key) {
        QGP_LOG_ERROR("KEY", "qgp_pubkey_load: Memory allocation failed");
        fclose(fp);
        return -1;
    }

    strncpy(key->name, header.name, sizeof(key->name) - 1);

    // Allocate and read public key
    key->public_key_size = header.public_key_size;
    key->public_key = QGP_MALLOC(key->public_key_size);
    if (!key->public_key) {
        QGP_LOG_ERROR("KEY", "qgp_pubkey_load: Memory allocation failed for public key");
        qgp_key_free(key);
        fclose(fp);
        return -1;
    }

    if (fread(key->public_key, 1, key->public_key_size, fp) != key->public_key_size) {
        QGP_LOG_ERROR("KEY", "qgp_pubkey_load: Failed to read public key");
        qgp_key_free(key);
        fclose(fp);
        return -1;
    }

    fclose(fp);
    *key_out = key;
    return 0;
}

// ============================================================================
// PASSWORD-PROTECTED KEY SERIALIZATION
// ============================================================================

/**
 * Securely wipe memory
 */
static void qgp_secure_memzero(void *ptr, size_t len) {
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--) {
        *p++ = 0;
    }
}

/**
 * Save private key with optional password encryption
 *
 * @param key: Key to save
 * @param path: Output file path
 * @param password: Password for encryption (NULL for unencrypted - not recommended)
 * @return: 0 on success, -1 on error
 */
int qgp_key_save_encrypted(const qgp_key_t *key, const char *path, const char *password) {
    if (!key || !path) {
        QGP_LOG_ERROR("KEY", "qgp_key_save_encrypted: Invalid arguments");
        return -1;
    }

    if (!key->public_key || !key->private_key) {
        QGP_LOG_ERROR("KEY", "qgp_key_save_encrypted: Key has no public or private key data");
        return -1;
    }

    int result = -1;
    uint8_t *raw_data = NULL;
    size_t raw_size = 0;

    /* Calculate total size: header + public_key + private_key */
    raw_size = sizeof(qgp_privkey_file_header_t) + key->public_key_size + key->private_key_size;
    raw_data = malloc(raw_size);
    if (!raw_data) {
        QGP_LOG_ERROR("KEY", "qgp_key_save_encrypted: Memory allocation failed");
        return -1;
    }

    /* Prepare header */
    qgp_privkey_file_header_t header;
    memset(&header, 0, sizeof(header));
    memcpy(header.magic, QGP_PRIVKEY_MAGIC, 8);
    header.version = QGP_PRIVKEY_VERSION;
    header.key_type = key->type;
    header.purpose = key->purpose;
    header.public_key_size = key->public_key_size;
    header.private_key_size = key->private_key_size;
    strncpy(header.name, key->name, sizeof(header.name) - 1);

    /* Serialize key to buffer */
    size_t offset = 0;
    memcpy(raw_data + offset, &header, sizeof(header));
    offset += sizeof(header);
    memcpy(raw_data + offset, key->public_key, key->public_key_size);
    offset += key->public_key_size;
    memcpy(raw_data + offset, key->private_key, key->private_key_size);

    /* Save with optional encryption */
    if (key_save_encrypted(raw_data, raw_size, password, path) != 0) {
        QGP_LOG_ERROR("KEY", "qgp_key_save_encrypted: Failed to save encrypted key");
        goto cleanup;
    }

    result = 0;

cleanup:
    if (raw_data) {
        qgp_secure_memzero(raw_data, raw_size);
        free(raw_data);
    }

    return result;
}

/**
 * Load private key with optional password decryption
 *
 * @param path: Input file path
 * @param password: Password for decryption (NULL if unencrypted)
 * @param key_out: Output key (caller must free with qgp_key_free())
 * @return: 0 on success, -1 on error
 */
int qgp_key_load_encrypted(const char *path, const char *password, qgp_key_t **key_out) {
    if (!path || !key_out) {
        QGP_LOG_ERROR("KEY", "qgp_key_load_encrypted: Invalid arguments");
        return -1;
    }

    int result = -1;
    uint8_t *raw_data = NULL;
    size_t raw_size = 0;
    qgp_key_t *key = NULL;

    /* Allocate buffer for largest possible key
     * Dilithium5: pubkey=2592, privkey=4896 + header ~280 = ~7800
     * Kyber1024: pubkey=1568, privkey=3168 + header ~280 = ~5000
     * Use 16KB to be safe
     */
    size_t buffer_size = 16384;
    raw_data = malloc(buffer_size);
    if (!raw_data) {
        QGP_LOG_ERROR("KEY", "qgp_key_load_encrypted: Memory allocation failed");
        return -1;
    }

    /* Load and decrypt */
    if (key_load_encrypted(path, password, raw_data, buffer_size, &raw_size) != 0) {
        QGP_LOG_ERROR("KEY", "qgp_key_load_encrypted: Failed to load key (wrong password?)");
        goto cleanup;
    }

    /* Validate minimum size */
    if (raw_size < sizeof(qgp_privkey_file_header_t)) {
        QGP_LOG_ERROR("KEY", "qgp_key_load_encrypted: Data too small");
        goto cleanup;
    }

    /* Parse header */
    qgp_privkey_file_header_t header;
    memcpy(&header, raw_data, sizeof(header));

    /* Validate magic */
    if (memcmp(header.magic, QGP_PRIVKEY_MAGIC, 8) != 0) {
        QGP_LOG_ERROR("KEY", "qgp_key_load_encrypted: Invalid magic (not a QGP private key)");
        goto cleanup;
    }

    if (header.version != QGP_PRIVKEY_VERSION) {
        QGP_LOG_ERROR("KEY", "qgp_key_load_encrypted: Unsupported version: %d", header.version);
        goto cleanup;
    }

    /* Validate size */
    size_t expected_size = sizeof(header) + header.public_key_size + header.private_key_size;
    if (raw_size < expected_size) {
        QGP_LOG_ERROR("KEY", "qgp_key_load_encrypted: Data truncated");
        goto cleanup;
    }

    /* Create key structure */
    key = qgp_key_new((qgp_key_type_t)header.key_type, (qgp_key_purpose_t)header.purpose);
    if (!key) {
        QGP_LOG_ERROR("KEY", "qgp_key_load_encrypted: Memory allocation failed");
        goto cleanup;
    }

    strncpy(key->name, header.name, sizeof(key->name) - 1);

    /* Allocate and copy public key */
    key->public_key_size = header.public_key_size;
    key->public_key = QGP_MALLOC(key->public_key_size);
    if (!key->public_key) {
        QGP_LOG_ERROR("KEY", "qgp_key_load_encrypted: Memory allocation failed for public key");
        qgp_key_free(key);
        key = NULL;
        goto cleanup;
    }
    memcpy(key->public_key, raw_data + sizeof(header), key->public_key_size);

    /* Allocate and copy private key */
    key->private_key_size = header.private_key_size;
    key->private_key = QGP_MALLOC(key->private_key_size);
    if (!key->private_key) {
        QGP_LOG_ERROR("KEY", "qgp_key_load_encrypted: Memory allocation failed for private key");
        qgp_key_free(key);
        key = NULL;
        goto cleanup;
    }
    memcpy(key->private_key, raw_data + sizeof(header) + header.public_key_size, key->private_key_size);

    *key_out = key;
    result = 0;

cleanup:
    if (raw_data) {
        qgp_secure_memzero(raw_data, buffer_size);
        free(raw_data);
    }

    return result;
}

/**
 * Check if a key file is password-protected
 *
 * @param path: Key file path
 * @return: true if encrypted, false if unencrypted or error
 */
bool qgp_key_file_is_encrypted(const char *path) {
    return key_file_is_encrypted(path);
}
