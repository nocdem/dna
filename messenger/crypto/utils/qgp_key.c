/*
 * qgp_key.c - QGP Key Management 
 *
 * Memory management and serialization for QGP keys.
 * Uses QGP's own file format with no external dependencies.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "crypto/utils/qgp_types.h"
#include "crypto/utils/qgp_log.h"
#include "crypto/utils/qgp_platform.h"
#include "crypto/utils/qgp_compiler.h"
#include "crypto/utils/key_encryption.h"
#include "qgp.h"  /* For write_armored_file */

#define LOG_TAG "KEY"

/* v0.6.47: Thread-safe gmtime wrapper (security fix) */
static inline struct tm *safe_gmtime(const time_t *timer, struct tm *result) {
#ifdef _WIN32
    return (gmtime_s(result, timer) == 0) ? result : NULL;
#else
    return gmtime_r(timer, result);
#endif
}

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
        qgp_secure_memzero(key->private_key, key->private_key_size);
        QGP_FREE(key->private_key);
    }

    // Free public key
    if (key->public_key) {
        QGP_FREE(key->public_key);
    }

    // Wipe and free key structure
    qgp_secure_memzero(key, sizeof(qgp_key_t));
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

// ============================================================================
// PUBLIC KEY EXPORT
// ============================================================================

/* Public key bundle file format */
#define PQSIGNUM_PUBKEY_MAGIC "PQPUBKEY"
#define PQSIGNUM_PUBKEY_VERSION 0x02  /* Version 2: Category 5 key sizes */

PACK_STRUCT_BEGIN
typedef struct {
    char magic[8];              /* "PQPUBKEY" */
    uint8_t version;            /* 0x02 (Category 5) */
    uint8_t sign_key_type;      /* Signing algorithm type */
    uint8_t enc_key_type;       /* Encryption algorithm type */
    uint8_t reserved;           /* Reserved */
    uint32_t sign_pubkey_size;  /* Signing public key size */
    uint32_t enc_pubkey_size;   /* Encryption public key size */
} PACK_STRUCT_END pqsignum_pubkey_header_t;

static const char* get_sign_algorithm_name(qgp_key_type_t type) {
    switch (type) {
        case QGP_KEY_TYPE_DSA87:
            return "ML-DSA-87";
        case QGP_KEY_TYPE_KEM1024:
            return "ML-KEM-1024";
        default:
            return "Unknown";
    }
}

/**
 * Export public keys to shareable file
 *
 * Creates a .pub file containing bundled signing + encryption public keys.
 *
 * @param name: Key name (without extension)
 * @param key_dir: Directory containing .dsa and .kem files
 * @param output_file: Output .pub file path
 * @return: 0 on success, non-zero on error
 */
int qgp_key_export_pubkey(const char *name, const char *key_dir, const char *output_file) {
    qgp_key_t *sign_key = NULL;
    qgp_key_t *enc_key = NULL;
    uint8_t *sign_pubkey = NULL;
    uint8_t *enc_pubkey = NULL;
    uint64_t sign_pubkey_size = 0;
    uint64_t enc_pubkey_size = 0;
    int ret = -1;

    QGP_LOG_INFO(LOG_TAG, "Exporting public keys for: %s", name);

    /* Load signing key */
    char sign_filename[512];
    snprintf(sign_filename, sizeof(sign_filename), "%s.dsa", name);
    char *sign_key_path = qgp_platform_join_path(key_dir, sign_filename);
    if (!sign_key_path) {
        QGP_LOG_ERROR(LOG_TAG, "Memory allocation failed for sign key path");
        return -1;
    }

    if (!qgp_platform_file_exists(sign_key_path)) {
        QGP_LOG_ERROR(LOG_TAG, "Signing key not found: %s", sign_key_path);
        free(sign_key_path);
        return -1;
    }

    if (qgp_key_load(sign_key_path, &sign_key) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to load signing key");
        free(sign_key_path);
        return -1;
    }
    free(sign_key_path);

    /* Load encryption key */
    char enc_filename[512];
    snprintf(enc_filename, sizeof(enc_filename), "%s.kem", name);
    char *enc_key_path = qgp_platform_join_path(key_dir, enc_filename);
    if (!enc_key_path) {
        QGP_LOG_ERROR(LOG_TAG, "Memory allocation failed for enc key path");
        goto cleanup;
    }

    if (!qgp_platform_file_exists(enc_key_path)) {
        QGP_LOG_ERROR(LOG_TAG, "Encryption key not found: %s", enc_key_path);
        free(enc_key_path);
        goto cleanup;
    }

    if (qgp_key_load(enc_key_path, &enc_key) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to load encryption key");
        free(enc_key_path);
        goto cleanup;
    }
    free(enc_key_path);

    /* Extract public keys */
    if (sign_key->type == QGP_KEY_TYPE_DSA87) {
        sign_pubkey_size = sign_key->public_key_size;
        sign_pubkey = malloc(sign_pubkey_size);
        if (!sign_pubkey) {
            QGP_LOG_ERROR(LOG_TAG, "Memory allocation failed");
            goto cleanup;
        }
        memcpy(sign_pubkey, sign_key->public_key, sign_pubkey_size);
    }

    enc_pubkey_size = enc_key->public_key_size;
    if (enc_pubkey_size != 1568) {  /* Kyber1024 public key size */
        QGP_LOG_ERROR(LOG_TAG, "Invalid Kyber1024 public key size");
        goto cleanup;
    }
    enc_pubkey = malloc(enc_pubkey_size);
    if (!enc_pubkey) {
        QGP_LOG_ERROR(LOG_TAG, "Memory allocation failed");
        goto cleanup;
    }
    memcpy(enc_pubkey, enc_key->public_key, enc_pubkey_size);

    /* Build header */
    pqsignum_pubkey_header_t header;
    memset(&header, 0, sizeof(header));
    memcpy(header.magic, PQSIGNUM_PUBKEY_MAGIC, 8);
    header.version = PQSIGNUM_PUBKEY_VERSION;
    header.sign_key_type = (uint8_t)sign_key->type;
    header.enc_key_type = (uint8_t)enc_key->type;
    header.reserved = 0;
    header.sign_pubkey_size = (uint32_t)sign_pubkey_size;
    header.enc_pubkey_size = (uint32_t)enc_pubkey_size;

    /* Calculate total size and build bundle */
    size_t total_size = sizeof(header) + sign_pubkey_size + enc_pubkey_size;
    uint8_t *bundle = malloc(total_size);
    if (!bundle) {
        QGP_LOG_ERROR(LOG_TAG, "Memory allocation failed");
        goto cleanup;
    }

    memcpy(bundle, &header, sizeof(header));
    memcpy(bundle + sizeof(header), sign_pubkey, sign_pubkey_size);
    memcpy(bundle + sizeof(header) + sign_pubkey_size, enc_pubkey, enc_pubkey_size);

    /* Build armor headers */
    static char header_buf[5][128];
    const char *armor_headers[5];
    size_t header_count = 0;

    snprintf(header_buf[0], sizeof(header_buf[0]), "Version: qgp 1.1");
    armor_headers[header_count++] = header_buf[0];

    snprintf(header_buf[1], sizeof(header_buf[1]), "Name: %s", name);
    armor_headers[header_count++] = header_buf[1];

    snprintf(header_buf[2], sizeof(header_buf[2]), "SigningAlgorithm: %s",
             get_sign_algorithm_name(sign_key->type));
    armor_headers[header_count++] = header_buf[2];

    snprintf(header_buf[3], sizeof(header_buf[3]), "EncryptionAlgorithm: ML-KEM-1024");
    armor_headers[header_count++] = header_buf[3];

    time_t now = time(NULL);
    struct tm tm_buf;
    char time_str[64];
    if (safe_gmtime(&now, &tm_buf)) {
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S UTC", &tm_buf);
    } else {
        strncpy(time_str, "0000-00-00 00:00:00 UTC", sizeof(time_str));
    }
    snprintf(header_buf[4], sizeof(header_buf[4]), "Created: %s", time_str);
    armor_headers[header_count++] = header_buf[4];

    /* Write armored file */
    if (write_armored_file(output_file, "PUBLIC KEY", bundle, total_size,
                          armor_headers, header_count) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to write ASCII armored file");
        free(bundle);
        goto cleanup;
    }

    free(bundle);
    QGP_LOG_INFO(LOG_TAG, "Public keys exported to: %s", output_file);
    ret = 0;

cleanup:
    if (sign_pubkey) free(sign_pubkey);
    if (enc_pubkey) free(enc_pubkey);
    if (sign_key) qgp_key_free(sign_key);
    if (enc_key) qgp_key_free(enc_key);

    return ret;
}

/* Legacy wrapper for compatibility */
int cmd_export_pubkey(const char *name, const char *key_dir, const char *output_file) {
    return qgp_key_export_pubkey(name, key_dir, output_file);
}
