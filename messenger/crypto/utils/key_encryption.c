/**
 * @file key_encryption.c
 * @brief Password-based Key Encryption Implementation
 *
 * Uses PBKDF2-SHA256 + AES-256-GCM for secure key encryption.
 *
 * @author DNA Messenger Team
 * @date 2025-12-15
 */

#include "key_encryption.h"
#include "qgp_random.h"
#include "qgp_log.h"
#include "qgp_platform.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#ifdef _WIN32
#include <io.h>
#else
#include <sys/stat.h>
#endif

#define LOG_TAG "KEY_ENC"

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
 * Derive AES-256 key from password using PBKDF2-SHA256
 */
static int derive_key_from_password(
    const char *password,
    const uint8_t salt[KEY_ENC_SALT_SIZE],
    uint8_t key_out[32]
) {
    if (!password || !salt || !key_out) {
        return -1;
    }

    int result = PKCS5_PBKDF2_HMAC(
        password,
        (int)strlen(password),
        salt,
        KEY_ENC_SALT_SIZE,
        KEY_ENC_PBKDF2_ITERATIONS,
        EVP_sha256(),
        32,  /* AES-256 key size */
        key_out
    );

    if (result != 1) {
        QGP_LOG_ERROR(LOG_TAG, "PBKDF2 key derivation failed");
        return -1;
    }

    return 0;
}

/**
 * AES-256-GCM encrypt
 */
static int aes256_gcm_encrypt(
    const uint8_t key[32],
    const uint8_t nonce[KEY_ENC_NONCE_SIZE],
    const uint8_t *plaintext,
    size_t plaintext_len,
    uint8_t *ciphertext,
    uint8_t tag[KEY_ENC_TAG_SIZE]
) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to create cipher context");
        return -1;
    }

    int result = -1;
    int len;
    int ciphertext_len;

    /* Initialize encryption */
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        QGP_LOG_ERROR(LOG_TAG, "EVP_EncryptInit_ex failed");
        goto cleanup;
    }

    /* Set nonce length */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, KEY_ENC_NONCE_SIZE, NULL) != 1) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to set nonce length");
        goto cleanup;
    }

    /* Set key and nonce */
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to set key and nonce");
        goto cleanup;
    }

    /* Encrypt */
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, (int)plaintext_len) != 1) {
        QGP_LOG_ERROR(LOG_TAG, "EVP_EncryptUpdate failed");
        goto cleanup;
    }
    ciphertext_len = len;

    /* Finalize */
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        QGP_LOG_ERROR(LOG_TAG, "EVP_EncryptFinal_ex failed");
        goto cleanup;
    }
    ciphertext_len += len;

    /* Get tag */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, KEY_ENC_TAG_SIZE, tag) != 1) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to get auth tag");
        goto cleanup;
    }

    result = ciphertext_len;

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return result;
}

/**
 * AES-256-GCM decrypt
 */
static int aes256_gcm_decrypt(
    const uint8_t key[32],
    const uint8_t nonce[KEY_ENC_NONCE_SIZE],
    const uint8_t tag[KEY_ENC_TAG_SIZE],
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    uint8_t *plaintext
) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to create cipher context");
        return -1;
    }

    int result = -1;
    int len;
    int plaintext_len;

    /* Initialize decryption */
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        QGP_LOG_ERROR(LOG_TAG, "EVP_DecryptInit_ex failed");
        goto cleanup;
    }

    /* Set nonce length */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, KEY_ENC_NONCE_SIZE, NULL) != 1) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to set nonce length");
        goto cleanup;
    }

    /* Set key and nonce */
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to set key and nonce");
        goto cleanup;
    }

    /* Decrypt */
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, (int)ciphertext_len) != 1) {
        QGP_LOG_ERROR(LOG_TAG, "EVP_DecryptUpdate failed");
        goto cleanup;
    }
    plaintext_len = len;

    /* Set expected tag */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, KEY_ENC_TAG_SIZE, (void *)tag) != 1) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to set auth tag");
        goto cleanup;
    }

    /* Finalize and verify tag */
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
        QGP_LOG_DEBUG(LOG_TAG, "Authentication failed (wrong password or corrupted data)");
        goto cleanup;
    }
    plaintext_len += len;

    result = plaintext_len;

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return result;
}

/**
 * Set file permissions to owner-only (0600)
 */
static void set_file_permissions(const char *path) {
#ifndef _WIN32
    if (chmod(path, S_IRUSR | S_IWUSR) != 0) {
        QGP_LOG_WARN(LOG_TAG, "Failed to set file permissions: %s", strerror(errno));
    }
#else
    (void)path;
#endif
}

/* ============================================================================
 * PUBLIC FUNCTIONS
 * ============================================================================ */

int key_encrypt(
    const uint8_t *key_data,
    size_t key_data_size,
    const char *password,
    uint8_t *encrypted_out,
    size_t *encrypted_size
) {
    if (!key_data || key_data_size == 0 || !password || !encrypted_out || !encrypted_size) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid arguments to key_encrypt");
        return -1;
    }

    int result = -1;
    uint8_t salt[KEY_ENC_SALT_SIZE];
    uint8_t nonce[KEY_ENC_NONCE_SIZE];
    uint8_t derived_key[32];
    uint8_t tag[KEY_ENC_TAG_SIZE];

    /* Generate random salt */
    if (qgp_randombytes(salt, KEY_ENC_SALT_SIZE) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to generate random salt");
        goto cleanup;
    }

    /* Generate random nonce */
    if (qgp_randombytes(nonce, KEY_ENC_NONCE_SIZE) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to generate random nonce");
        goto cleanup;
    }

    /* Derive key from password */
    if (derive_key_from_password(password, salt, derived_key) != 0) {
        goto cleanup;
    }

    /* Build output buffer */
    size_t offset = 0;

    /* Magic */
    memcpy(encrypted_out + offset, KEY_ENC_MAGIC, KEY_ENC_MAGIC_SIZE);
    offset += KEY_ENC_MAGIC_SIZE;

    /* Version */
    encrypted_out[offset++] = KEY_ENC_VERSION;

    /* Salt */
    memcpy(encrypted_out + offset, salt, KEY_ENC_SALT_SIZE);
    offset += KEY_ENC_SALT_SIZE;

    /* Nonce */
    memcpy(encrypted_out + offset, nonce, KEY_ENC_NONCE_SIZE);
    offset += KEY_ENC_NONCE_SIZE;

    /* Reserve space for tag (will fill after encryption) */
    size_t tag_offset = offset;
    offset += KEY_ENC_TAG_SIZE;

    /* Encrypt key data */
    int ciphertext_len = aes256_gcm_encrypt(
        derived_key,
        nonce,
        key_data,
        key_data_size,
        encrypted_out + offset,
        tag
    );

    if (ciphertext_len < 0) {
        QGP_LOG_ERROR(LOG_TAG, "AES-GCM encryption failed");
        goto cleanup;
    }

    /* Copy tag to reserved space */
    memcpy(encrypted_out + tag_offset, tag, KEY_ENC_TAG_SIZE);

    *encrypted_size = offset + ciphertext_len;
    result = 0;

    QGP_LOG_DEBUG(LOG_TAG, "Key encrypted successfully (size: %zu -> %zu)",
                  key_data_size, *encrypted_size);

cleanup:
    secure_memzero(salt, sizeof(salt));
    secure_memzero(nonce, sizeof(nonce));
    secure_memzero(derived_key, sizeof(derived_key));
    secure_memzero(tag, sizeof(tag));

    return result;
}

int key_decrypt(
    const uint8_t *encrypted_data,
    size_t encrypted_size,
    const char *password,
    uint8_t *key_out,
    size_t *key_size
) {
    if (!encrypted_data || encrypted_size < KEY_ENC_HEADER_SIZE ||
        !password || !key_out || !key_size) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid arguments to key_decrypt");
        return -1;
    }

    int result = -1;
    uint8_t derived_key[32];

    size_t offset = 0;

    /* Verify magic */
    if (memcmp(encrypted_data + offset, KEY_ENC_MAGIC, KEY_ENC_MAGIC_SIZE) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid file format (bad magic)");
        return -1;
    }
    offset += KEY_ENC_MAGIC_SIZE;

    /* Check version */
    uint8_t version = encrypted_data[offset++];
    if (version != KEY_ENC_VERSION) {
        QGP_LOG_ERROR(LOG_TAG, "Unsupported file version: %d", version);
        return -1;
    }

    /* Extract salt */
    const uint8_t *salt = encrypted_data + offset;
    offset += KEY_ENC_SALT_SIZE;

    /* Extract nonce */
    const uint8_t *nonce = encrypted_data + offset;
    offset += KEY_ENC_NONCE_SIZE;

    /* Extract tag */
    const uint8_t *tag = encrypted_data + offset;
    offset += KEY_ENC_TAG_SIZE;

    /* Ciphertext is the rest */
    const uint8_t *ciphertext = encrypted_data + offset;
    size_t ciphertext_len = encrypted_size - offset;

    /* Derive key from password */
    if (derive_key_from_password(password, salt, derived_key) != 0) {
        goto cleanup;
    }

    /* Decrypt */
    int plaintext_len = aes256_gcm_decrypt(
        derived_key,
        nonce,
        tag,
        ciphertext,
        ciphertext_len,
        key_out
    );

    if (plaintext_len < 0) {
        QGP_LOG_DEBUG(LOG_TAG, "Decryption failed (wrong password?)");
        goto cleanup;
    }

    *key_size = (size_t)plaintext_len;
    result = 0;

    QGP_LOG_DEBUG(LOG_TAG, "Key decrypted successfully (size: %zu)", *key_size);

cleanup:
    secure_memzero(derived_key, sizeof(derived_key));

    return result;
}

int key_save_encrypted(
    const uint8_t *key_data,
    size_t key_data_size,
    const char *password,
    const char *file_path
) {
    if (!key_data || key_data_size == 0 || !file_path) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid arguments to key_save_encrypted");
        return -1;
    }

    int result = -1;
    uint8_t *buffer = NULL;
    FILE *fp = NULL;

    if (password && strlen(password) > 0) {
        /* Encrypted save */
        size_t buffer_size = key_data_size + KEY_ENC_HEADER_SIZE;
        buffer = malloc(buffer_size);
        if (!buffer) {
            QGP_LOG_ERROR(LOG_TAG, "Memory allocation failed");
            return -1;
        }

        size_t encrypted_size;
        if (key_encrypt(key_data, key_data_size, password, buffer, &encrypted_size) != 0) {
            goto cleanup;
        }

        fp = fopen(file_path, "wb");
        if (!fp) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to open file for writing: %s", file_path);
            goto cleanup;
        }

        if (fwrite(buffer, 1, encrypted_size, fp) != encrypted_size) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to write encrypted key file");
            goto cleanup;
        }

        QGP_LOG_INFO(LOG_TAG, "Saved password-encrypted key to: %s", file_path);
    } else {
        /* Unencrypted save (not recommended, but allowed) */
        fp = fopen(file_path, "wb");
        if (!fp) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to open file for writing: %s", file_path);
            goto cleanup;
        }

        if (fwrite(key_data, 1, key_data_size, fp) != key_data_size) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to write key file");
            goto cleanup;
        }

        QGP_LOG_WARN(LOG_TAG, "Saved UNENCRYPTED key to: %s (not recommended)", file_path);
    }

    result = 0;

cleanup:
    if (fp) {
        fclose(fp);
        set_file_permissions(file_path);
    }
    if (buffer) {
        secure_memzero(buffer, key_data_size + KEY_ENC_HEADER_SIZE);
        free(buffer);
    }

    return result;
}

int key_load_encrypted(
    const char *file_path,
    const char *password,
    uint8_t *key_out,
    size_t key_out_size,
    size_t *key_size
) {
    if (!file_path || !key_out || key_out_size == 0 || !key_size) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid arguments to key_load_encrypted");
        return -1;
    }

    int result = -1;
    FILE *fp = NULL;
    uint8_t *buffer = NULL;

    fp = fopen(file_path, "rb");
    if (!fp) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to open key file: %s", file_path);
        return -1;
    }

    /* Get file size */
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (file_size <= 0 || file_size > 100000) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid key file size: %ld", file_size);
        goto cleanup;
    }

    buffer = malloc((size_t)file_size);
    if (!buffer) {
        QGP_LOG_ERROR(LOG_TAG, "Memory allocation failed");
        goto cleanup;
    }

    if (fread(buffer, 1, (size_t)file_size, fp) != (size_t)file_size) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to read key file");
        goto cleanup;
    }

    fclose(fp);
    fp = NULL;

    /* Check if file is encrypted */
    bool is_encrypted = (file_size >= KEY_ENC_HEADER_SIZE &&
                         memcmp(buffer, KEY_ENC_MAGIC, KEY_ENC_MAGIC_SIZE) == 0);

    if (is_encrypted) {
        if (!password || strlen(password) == 0) {
            QGP_LOG_ERROR(LOG_TAG, "Key file is encrypted but no password provided");
            goto cleanup;
        }

        if (key_decrypt(buffer, (size_t)file_size, password, key_out, key_size) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to decrypt key file (wrong password?)");
            goto cleanup;
        }
    } else {
        /* Unencrypted file - just copy */
        if ((size_t)file_size > key_out_size) {
            QGP_LOG_ERROR(LOG_TAG, "Key output buffer too small");
            goto cleanup;
        }

        memcpy(key_out, buffer, (size_t)file_size);
        *key_size = (size_t)file_size;

        QGP_LOG_WARN(LOG_TAG, "Loaded UNENCRYPTED key from: %s", file_path);
    }

    result = 0;

cleanup:
    if (fp) {
        fclose(fp);
    }
    if (buffer) {
        secure_memzero(buffer, (size_t)file_size);
        free(buffer);
    }

    return result;
}

bool key_file_is_encrypted(const char *file_path) {
    if (!file_path) {
        return false;
    }

    FILE *fp = fopen(file_path, "rb");
    if (!fp) {
        return false;
    }

    uint8_t magic[KEY_ENC_MAGIC_SIZE];
    bool is_encrypted = false;

    if (fread(magic, 1, KEY_ENC_MAGIC_SIZE, fp) == KEY_ENC_MAGIC_SIZE) {
        is_encrypted = (memcmp(magic, KEY_ENC_MAGIC, KEY_ENC_MAGIC_SIZE) == 0);
    }

    fclose(fp);
    return is_encrypted;
}

int key_change_password(
    const char *file_path,
    const char *old_password,
    const char *new_password
) {
    if (!file_path) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid arguments to key_change_password");
        return -1;
    }

    int result = -1;
    uint8_t *key_data = NULL;
    size_t key_size = 0;

    /* Allocate buffer for largest possible key (Dilithium5 private = 4896 bytes) */
    size_t buffer_size = 8192;
    key_data = malloc(buffer_size);
    if (!key_data) {
        QGP_LOG_ERROR(LOG_TAG, "Memory allocation failed");
        return -1;
    }

    /* Load key with old password */
    if (key_load_encrypted(file_path, old_password, key_data, buffer_size, &key_size) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to load key with old password");
        goto cleanup;
    }

    /* Save with new password */
    if (key_save_encrypted(key_data, key_size, new_password, file_path) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to save key with new password");
        goto cleanup;
    }

    QGP_LOG_INFO(LOG_TAG, "Password changed successfully for: %s", file_path);
    result = 0;

cleanup:
    if (key_data) {
        secure_memzero(key_data, buffer_size);
        free(key_data);
    }

    return result;
}

int key_verify_password(
    const char *file_path,
    const char *password
) {
    if (!file_path || !password) {
        return -1;
    }

    /* Allocate small buffer - we just need to verify decryption works */
    uint8_t key_data[8192];
    size_t key_size;

    int result = key_load_encrypted(file_path, password, key_data, sizeof(key_data), &key_size);

    /* Always wipe the buffer */
    secure_memzero(key_data, sizeof(key_data));

    return result;
}
