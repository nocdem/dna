// shared/crypto/utils/platform_keystore_noop.c
/**
 * Platform keystore — noop backend for Linux/Windows/macOS.
 * TEE is not available on desktop. All TEE operations return "unavailable".
 *
 * Note: platform_keystore_is_wrapped() is implemented here (not a TEE op —
 * just reads file magic) so desktop builds can still detect DNAT files.
 */

#include <stdio.h>
#include <string.h>
#include "crypto/utils/platform_keystore.h"
#include "crypto/utils/qgp_log.h"

#include "crypto/utils/qgp_safe_string.h"   /* Phase 03: unsafe-string poison guard */

#define LOG_TAG "KEYSTORE"

bool platform_keystore_available(void) {
    return false;
}

int platform_keystore_wrap(
    const uint8_t *data, size_t data_len,
    uint8_t **out, size_t *out_len)
{
    (void)data; (void)data_len;
    if (out) *out = NULL;
    if (out_len) *out_len = 0;
    return PLATFORM_KEYSTORE_ERROR;
}

int platform_keystore_unwrap(
    const uint8_t *data, size_t data_len,
    uint8_t **out, size_t *out_len)
{
    (void)data; (void)data_len;
    if (out) *out = NULL;
    if (out_len) *out_len = 0;
    return PLATFORM_KEYSTORE_ERROR;
}

int platform_keystore_migrate_file(const char *file_path,
                                    const char *data_dir)
{
    (void)file_path; (void)data_dir;
    return PLATFORM_KEYSTORE_UNAVAILABLE;
}

bool platform_keystore_is_wrapped(const char *file_path) {
    if (!file_path) return false;

    FILE *fp = fopen(file_path, "rb");
    if (!fp) return false;

    char magic[PLATFORM_KEYSTORE_MAGIC_SIZE];
    size_t n = fread(magic, 1, PLATFORM_KEYSTORE_MAGIC_SIZE, fp);
    fclose(fp);

    return (n == PLATFORM_KEYSTORE_MAGIC_SIZE &&
            memcmp(magic, PLATFORM_KEYSTORE_MAGIC, PLATFORM_KEYSTORE_MAGIC_SIZE) == 0);
}
