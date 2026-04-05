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
#include <sys/stat.h>
#ifndef _WIN32
#include <unistd.h>
#endif
#include "crypto/utils/qgp_types.h"
#include "crypto/utils/qgp_log.h"
#include "crypto/utils/qgp_platform.h"
#include "crypto/utils/qgp_compiler.h"
#include "crypto/utils/platform_keystore.h"
#include "crypto/key/key_encryption.h"
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

    /* Restrict key file permissions to owner-only (M-14 security fix) */
    chmod(path, 0600);

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
    /* Delegate to qgp_key_load_encrypted with NULL password.
     * This makes qgp_key_load TEE-aware: DNAT-wrapped files are unwrapped
     * transparently, DNAK (password-encrypted) files fail with NULL password
     * (expected — caller must use qgp_key_load_encrypted with actual password),
     * and plain QGPK files load as before. */
    return qgp_key_load_encrypted(path, NULL, key_out);
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
    uint8_t *inner_data = NULL;
    size_t inner_size = 0;
    size_t inner_alloc_size = 0;
    uint8_t *wrapped = NULL;
    size_t wrapped_len = 0;

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

    /* Check if TEE is available */
    bool tee_available = platform_keystore_available();

    if (!tee_available) {
        /* No TEE - use existing path (key_save_encrypted handles password encryption + write) */
        if (key_save_encrypted(raw_data, raw_size, password, path) != 0) {
            QGP_LOG_ERROR("KEY", "qgp_key_save_encrypted: Failed to save encrypted key");
            goto cleanup;
        }
        result = 0;
        goto cleanup;
    }

    /* TEE path: produce inner data (password-encrypted or raw), then TEE wrap it */
    if (password && strlen(password) > 0) {
        /* Password encrypt first (inner layer) */
        size_t inner_buf_size = raw_size + KEY_ENC_HEADER_SIZE;
        inner_data = malloc(inner_buf_size);
        if (!inner_data) {
            QGP_LOG_ERROR("KEY", "qgp_key_save_encrypted: Memory allocation failed for inner buffer");
            goto cleanup;
        }
        inner_alloc_size = inner_buf_size;
        if (key_encrypt(raw_data, raw_size, password, inner_data, &inner_size) != 0) {
            QGP_LOG_ERROR("KEY", "qgp_key_save_encrypted: Password encryption failed");
            goto cleanup;
        }
    } else {
        /* No password — inner is just raw_data (no allocation, just point) */
        inner_data = raw_data;
        inner_size = raw_size;
    }

    /* TEE wrap the inner data */
    if (platform_keystore_wrap(inner_data, inner_size, &wrapped, &wrapped_len) != 0) {
        QGP_LOG_ERROR("KEY", "qgp_key_save_encrypted: TEE wrap failed");
        goto cleanup;
    }

    /* Write DNAT file: 6-byte header + wrapped data (ATOMIC: temp + fsync + rename) */
    char tmp_path[1024];
    int tmp_ret = snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", path);
    if (tmp_ret < 0 || (size_t)tmp_ret >= sizeof(tmp_path)) {
        QGP_LOG_ERROR("KEY", "qgp_key_save_encrypted: Path too long");
        goto cleanup;
    }

    FILE *fp = fopen(tmp_path, "wb");
    if (!fp) {
        QGP_LOG_ERROR("KEY", "qgp_key_save_encrypted: Cannot create temp file: %s", tmp_path);
        goto cleanup;
    }

    uint8_t dnat_header[PLATFORM_KEYSTORE_HEADER_SIZE];
    memcpy(dnat_header, PLATFORM_KEYSTORE_MAGIC, PLATFORM_KEYSTORE_MAGIC_SIZE);
    dnat_header[4] = PLATFORM_KEYSTORE_VERSION;
    dnat_header[5] = PLATFORM_KEYSTORE_KEY_VER;

    size_t expected = PLATFORM_KEYSTORE_HEADER_SIZE + wrapped_len;
    size_t written = 0;
    written += fwrite(dnat_header, 1, PLATFORM_KEYSTORE_HEADER_SIZE, fp);
    written += fwrite(wrapped, 1, wrapped_len, fp);

    if (written != expected) {
        QGP_LOG_ERROR("KEY", "qgp_key_save_encrypted: Short write to temp file (%zu/%zu)", written, expected);
        fclose(fp);
        unlink(tmp_path);
        goto cleanup;
    }

    if (fflush(fp) != 0) {
        QGP_LOG_ERROR("KEY", "qgp_key_save_encrypted: fflush failed");
        fclose(fp);
        unlink(tmp_path);
        goto cleanup;
    }

#ifndef _WIN32
    if (fsync(fileno(fp)) != 0) {
        QGP_LOG_ERROR("KEY", "qgp_key_save_encrypted: fsync failed");
        fclose(fp);
        unlink(tmp_path);
        goto cleanup;
    }
#endif

    if (fclose(fp) != 0) {
        QGP_LOG_ERROR("KEY", "qgp_key_save_encrypted: fclose failed");
        unlink(tmp_path);
        goto cleanup;
    }

    /* Atomic rename — on success, old file replaced; on failure, old file intact */
    if (rename(tmp_path, path) != 0) {
        QGP_LOG_ERROR("KEY", "qgp_key_save_encrypted: rename failed: %s -> %s", tmp_path, path);
        unlink(tmp_path);
        goto cleanup;
    }

    chmod(path, S_IRUSR | S_IWUSR);  /* 0600 */
    result = 0;

cleanup:
    /* inner_data only needs free if it's a separate allocation (password path) */
    if (inner_data && inner_data != raw_data) {
        qgp_secure_memzero(inner_data, inner_alloc_size);
        free(inner_data);
    }
    if (raw_data) {
        qgp_secure_memzero(raw_data, raw_size);
        free(raw_data);
    }
    if (wrapped) {
        qgp_secure_memzero(wrapped, wrapped_len);
        free(wrapped);
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
        return -1;  /* No allocations yet — safe to return directly */
    }

    int result = -1;
    uint8_t *file_data = NULL;
    size_t file_size = 0;
    uint8_t *inner_data = NULL;
    size_t inner_size = 0;
    bool inner_allocated = false;
    uint8_t raw_buffer[16384];
    size_t raw_size = 0;
    qgp_key_t *key = NULL;
    FILE *fp = NULL;

    memset(raw_buffer, 0, sizeof(raw_buffer));

    /* Read file into memory */
    fp = fopen(path, "rb");
    if (!fp) {
        QGP_LOG_ERROR("KEY", "qgp_key_load_encrypted: Cannot open file: %s", path);
        goto cleanup;
    }

    fseek(fp, 0, SEEK_END);
    long fs = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (fs <= 0 || fs > PLATFORM_KEYSTORE_MAX_FILE) {
        QGP_LOG_ERROR("KEY", "qgp_key_load_encrypted: Invalid file size: %ld", fs);
        goto cleanup;
    }
    file_size = (size_t)fs;

    file_data = malloc(file_size);
    if (!file_data) {
        QGP_LOG_ERROR("KEY", "qgp_key_load_encrypted: Memory allocation failed");
        goto cleanup;
    }
    if (fread(file_data, 1, file_size, fp) != file_size) {
        QGP_LOG_ERROR("KEY", "qgp_key_load_encrypted: fread failed");
        goto cleanup;
    }
    fclose(fp);
    fp = NULL;

    /* Detect DNAT magic */
    if (file_size > PLATFORM_KEYSTORE_HEADER_SIZE &&
        memcmp(file_data, PLATFORM_KEYSTORE_MAGIC, PLATFORM_KEYSTORE_MAGIC_SIZE) == 0) {
        /* TEE-wrapped — unwrap */
        uint8_t *wrapped_payload = file_data + PLATFORM_KEYSTORE_HEADER_SIZE;
        size_t wrapped_len = file_size - PLATFORM_KEYSTORE_HEADER_SIZE;

        if (!platform_keystore_available()) {
            QGP_LOG_ERROR("KEY", "qgp_key_load_encrypted: File is TEE-wrapped but TEE unavailable");
            goto cleanup;
        }

        if (platform_keystore_unwrap(wrapped_payload, wrapped_len,
                                      &inner_data, &inner_size) != 0) {
            QGP_LOG_ERROR("KEY", "qgp_key_load_encrypted: TEE unwrap failed (key invalidated?)");
            result = -2;  /* Special code: TEE failure — caller maps to DNA_ENGINE_ERROR_TEE_FAILED */
            goto cleanup;
        }
        inner_allocated = true;
    } else {
        /* Legacy format (DNAK or QGPK) — use file_data directly */
        inner_data = file_data;
        inner_size = file_size;
    }

    /* Decrypt/parse inner data using key_load_from_buffer */
    if (key_load_from_buffer(inner_data, inner_size, password,
                              raw_buffer, sizeof(raw_buffer), &raw_size) != 0) {
        QGP_LOG_ERROR("KEY", "qgp_key_load_encrypted: Failed to decrypt key data (wrong password?)");
        goto cleanup;
    }

    /* Validate minimum size */
    if (raw_size < sizeof(qgp_privkey_file_header_t)) {
        QGP_LOG_ERROR("KEY", "qgp_key_load_encrypted: Data too small");
        goto cleanup;
    }

    /* Parse header */
    qgp_privkey_file_header_t header;
    memcpy(&header, raw_buffer, sizeof(header));

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
    memcpy(key->public_key, raw_buffer + sizeof(header), key->public_key_size);

    /* Allocate and copy private key */
    key->private_key_size = header.private_key_size;
    key->private_key = QGP_MALLOC(key->private_key_size);
    if (!key->private_key) {
        QGP_LOG_ERROR("KEY", "qgp_key_load_encrypted: Memory allocation failed for private key");
        qgp_key_free(key);
        key = NULL;
        goto cleanup;
    }
    memcpy(key->private_key, raw_buffer + sizeof(header) + header.public_key_size, key->private_key_size);

    *key_out = key;
    result = 0;

cleanup:
    if (fp) fclose(fp);
    /* inner_data may alias file_data — only free if allocated by unwrap */
    if (inner_allocated && inner_data) {
        qgp_secure_memzero(inner_data, inner_size);
        free(inner_data);
    }
    if (file_data) {
        qgp_secure_memzero(file_data, file_size);
        free(file_data);
    }
    qgp_secure_memzero(raw_buffer, sizeof(raw_buffer));
    return result;
}

/**
 * Check if a key file is password-protected
 *
 * @param path: Key file path
 * @return: true if encrypted, false if unencrypted or error
 */
bool qgp_key_file_is_encrypted(const char *path) {
    if (!path) return false;

    /* Check if file is TEE-wrapped (DNAT magic) — if so, unwrap and check inner */
    FILE *fp = fopen(path, "rb");
    if (!fp) return false;

    uint8_t magic[PLATFORM_KEYSTORE_MAGIC_SIZE];
    size_t n = fread(magic, 1, PLATFORM_KEYSTORE_MAGIC_SIZE, fp);

    if (n == PLATFORM_KEYSTORE_MAGIC_SIZE &&
        memcmp(magic, PLATFORM_KEYSTORE_MAGIC, PLATFORM_KEYSTORE_MAGIC_SIZE) == 0) {
        /* DNAT-wrapped: unwrap and check inner magic */
        fseek(fp, 0, SEEK_END);
        long fs = ftell(fp);
        fseek(fp, 0, SEEK_SET);

        if (fs <= 0 || fs > PLATFORM_KEYSTORE_MAX_FILE) {
            fclose(fp);
            return false;
        }

        uint8_t *file_data = malloc((size_t)fs);
        if (!file_data) {
            fclose(fp);
            return false;
        }
        if (fread(file_data, 1, (size_t)fs, fp) != (size_t)fs) {
            free(file_data);
            fclose(fp);
            return false;
        }
        fclose(fp);

        if (!platform_keystore_available()) {
            /* Can't unwrap without TEE — can't determine encryption state */
            qgp_secure_memzero(file_data, (size_t)fs);
            free(file_data);
            return false;
        }

        uint8_t *inner = NULL;
        size_t inner_len = 0;
        int rc = platform_keystore_unwrap(
            file_data + PLATFORM_KEYSTORE_HEADER_SIZE,
            (size_t)fs - PLATFORM_KEYSTORE_HEADER_SIZE,
            &inner, &inner_len);
        qgp_secure_memzero(file_data, (size_t)fs);
        free(file_data);

        if (rc != 0 || !inner) return false;

        /* Check inner magic: DNAK = password-encrypted, anything else = not */
        bool is_dnak = (inner_len >= KEY_ENC_MAGIC_SIZE &&
                        memcmp(inner, KEY_ENC_MAGIC, KEY_ENC_MAGIC_SIZE) == 0);
        qgp_secure_memzero(inner, inner_len);
        free(inner);
        return is_dnak;
    }

    fclose(fp);
    /* Legacy (non-DNAT): use original check */
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
