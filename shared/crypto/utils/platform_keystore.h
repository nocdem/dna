// shared/crypto/utils/platform_keystore.h
#ifndef PLATFORM_KEYSTORE_H
#define PLATFORM_KEYSTORE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * CONSTANTS
 * ============================================================================ */

#define PLATFORM_KEYSTORE_MAGIC      "DNAT"
#define PLATFORM_KEYSTORE_MAGIC_SIZE 4
#define PLATFORM_KEYSTORE_VERSION    0x01
#define PLATFORM_KEYSTORE_KEY_VER    0x01
#define PLATFORM_KEYSTORE_HEADER_SIZE 6  /* magic(4) + version(1) + key_ver(1) */
#define PLATFORM_KEYSTORE_MAX_FILE   16384  /* 16KB max input */
#define PLATFORM_KEYSTORE_GCM_IV_SIZE  12
#define PLATFORM_KEYSTORE_GCM_TAG_SIZE 16

/* Return codes */
#define PLATFORM_KEYSTORE_OK              0
#define PLATFORM_KEYSTORE_ALREADY_WRAPPED 1
#define PLATFORM_KEYSTORE_UNAVAILABLE     2
#define PLATFORM_KEYSTORE_NO_MNEMONIC     3
#define PLATFORM_KEYSTORE_ERROR          -1

/* ============================================================================
 * FUNCTIONS
 * ============================================================================ */

/**
 * Check if hardware keystore (TEE) is available on this platform.
 * Android: checks if AndroidKeyStore is accessible and JVM is initialized.
 * Desktop: always returns false (noop backend).
 */
bool platform_keystore_available(void);

/**
 * Wrap data with hardware-backed AES-256-GCM key.
 *
 * Output format: [12-byte IV][ciphertext + 16-byte GCM tag]
 * The 6-byte DNAT header is passed as GCM AAD (authenticated but not encrypted).
 *
 * @param data      Input data to wrap
 * @param data_len  Input data length (must be <= PLATFORM_KEYSTORE_MAX_FILE)
 * @param out       Output: allocated buffer (caller must free)
 * @param out_len   Output: size of allocated buffer
 * @return          0 on success, -1 on error
 */
int platform_keystore_wrap(
    const uint8_t *data, size_t data_len,
    uint8_t **out, size_t *out_len);

/**
 * Unwrap data with hardware-backed AES-256-GCM key.
 *
 * Input format: [12-byte IV][ciphertext + 16-byte GCM tag]
 * The 6-byte DNAT header is passed as GCM AAD for verification.
 *
 * @param data      Wrapped data (IV + ciphertext + tag)
 * @param data_len  Wrapped data length
 * @param out       Output: allocated buffer (caller must free)
 * @param out_len   Output: size of allocated buffer
 * @return          0 on success, -1 on error
 */
int platform_keystore_unwrap(
    const uint8_t *data, size_t data_len,
    uint8_t **out, size_t *out_len);

/**
 * Migrate a key file from legacy format to TEE-wrapped format.
 *
 * Thread-safe (internal mutex). Performs atomic write (temp + fsync + rename).
 * Checks that mnemonic backup exists before migrating.
 * Creates a .bak copy of the original file before modification (safety net).
 *
 * @param file_path  Path to key file (identity.dsa or identity.kem)
 * @param data_dir   Path to data directory (for mnemonic check)
 * @return  0=migrated, 1=already wrapped, 2=TEE unavailable,
 *          3=no mnemonic backup, -1=error
 */
int platform_keystore_migrate_file(const char *file_path,
                                    const char *data_dir);

/**
 * Check if a file is TEE-wrapped (starts with "DNAT" magic).
 *
 * @param file_path  Path to check
 * @return           true if TEE-wrapped, false otherwise
 */
bool platform_keystore_is_wrapped(const char *file_path);

#ifdef __ANDROID__
/**
 * Initialize JNI state for platform keystore.
 * Called from JNI_OnLoad in dna_jni.c.
 *
 * @param jvm  JavaVM pointer
 */
void platform_keystore_jni_init(void *jvm);
#endif

#ifdef __cplusplus
}
#endif

#endif /* PLATFORM_KEYSTORE_H */
