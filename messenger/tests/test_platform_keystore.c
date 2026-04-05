#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "crypto/utils/platform_keystore.h"
#include "crypto/key/key_encryption.h"

static void test_noop_unavailable(void) {
    printf("  test_noop_unavailable... ");
    assert(platform_keystore_available() == false);
    printf("OK\n");
}

static void test_noop_wrap_sets_null_on_error(void) {
    printf("  test_noop_wrap_sets_null_on_error... ");
    uint8_t data[] = {1, 2, 3, 4};
    uint8_t *out = (uint8_t *)0xDEADBEEF;  /* Pre-fill with junk */
    size_t out_len = 999;
    assert(platform_keystore_wrap(data, 4, &out, &out_len) == PLATFORM_KEYSTORE_ERROR);
    assert(out == NULL);
    assert(out_len == 0);
    printf("OK\n");
}

static void test_noop_unwrap_sets_null_on_error(void) {
    printf("  test_noop_unwrap_sets_null_on_error... ");
    uint8_t data[] = {1, 2, 3, 4};
    uint8_t *out = (uint8_t *)0xDEADBEEF;
    size_t out_len = 999;
    assert(platform_keystore_unwrap(data, 4, &out, &out_len) == PLATFORM_KEYSTORE_ERROR);
    assert(out == NULL);
    assert(out_len == 0);
    printf("OK\n");
}

static void test_noop_migrate_returns_unavailable(void) {
    printf("  test_noop_migrate_returns_unavailable... ");
    assert(platform_keystore_migrate_file("/tmp/test.dsa", "/tmp") == PLATFORM_KEYSTORE_UNAVAILABLE);
    printf("OK\n");
}

static void test_is_wrapped_nonexistent(void) {
    printf("  test_is_wrapped_nonexistent... ");
    assert(platform_keystore_is_wrapped("/tmp/does_not_exist_12345.key") == false);
    printf("OK\n");
}

static void test_is_wrapped_null_path(void) {
    printf("  test_is_wrapped_null_path... ");
    assert(platform_keystore_is_wrapped(NULL) == false);
    printf("OK\n");
}

static void test_is_wrapped_legacy_qgpk(void) {
    printf("  test_is_wrapped_legacy_qgpk... ");
    const char *path = "/tmp/test_legacy_key.bin";
    FILE *fp = fopen(path, "wb");
    assert(fp);
    fwrite("QGPK1234", 1, 8, fp);
    fclose(fp);
    assert(platform_keystore_is_wrapped(path) == false);
    remove(path);
    printf("OK\n");
}

static void test_is_wrapped_dnat_file(void) {
    printf("  test_is_wrapped_dnat_file... ");
    const char *path = "/tmp/test_dnat_key.bin";
    FILE *fp = fopen(path, "wb");
    assert(fp);
    fwrite("DNAT\x01\x01", 1, 6, fp);
    fwrite("fake_payload_data", 1, 17, fp);
    fclose(fp);
    assert(platform_keystore_is_wrapped(path) == true);
    remove(path);
    printf("OK\n");
}

static void test_is_wrapped_file_too_short(void) {
    printf("  test_is_wrapped_file_too_short... ");
    const char *path = "/tmp/test_short.bin";
    FILE *fp = fopen(path, "wb");
    assert(fp);
    fwrite("DN", 1, 2, fp);  /* Only 2 bytes, not 4 */
    fclose(fp);
    assert(platform_keystore_is_wrapped(path) == false);
    remove(path);
    printf("OK\n");
}

static void test_key_load_from_buffer_raw(void) {
    printf("  test_key_load_from_buffer_raw... ");
    /* Raw data (no DNAK magic) should be copied directly */
    uint8_t raw_data[] = {0x01, 0x02, 0x03, 0x04, 0x05};
    uint8_t out[32] = {0};
    size_t out_len = 0;

    int rc = key_load_from_buffer(raw_data, sizeof(raw_data), NULL,
                                   out, sizeof(out), &out_len);
    assert(rc == 0);
    assert(out_len == sizeof(raw_data));
    assert(memcmp(out, raw_data, sizeof(raw_data)) == 0);
    printf("OK\n");
}

static void test_key_load_from_buffer_too_small(void) {
    printf("  test_key_load_from_buffer_too_small... ");
    uint8_t raw_data[100] = {0};
    uint8_t out[10] = {0};
    size_t out_len = 0;

    int rc = key_load_from_buffer(raw_data, sizeof(raw_data), NULL,
                                   out, sizeof(out), &out_len);
    assert(rc == -1);  /* Output buffer too small */
    printf("OK\n");
}

static void test_key_load_from_buffer_invalid_args(void) {
    printf("  test_key_load_from_buffer_invalid_args... ");
    uint8_t out[32] = {0};
    size_t out_len = 0;

    assert(key_load_from_buffer(NULL, 10, NULL, out, sizeof(out), &out_len) == -1);
    assert(key_load_from_buffer((uint8_t *)"data", 0, NULL, out, sizeof(out), &out_len) == -1);
    printf("OK\n");
}

int main(void) {
    printf("test_platform_keystore:\n");
    test_noop_unavailable();
    test_noop_wrap_sets_null_on_error();
    test_noop_unwrap_sets_null_on_error();
    test_noop_migrate_returns_unavailable();
    test_is_wrapped_nonexistent();
    test_is_wrapped_null_path();
    test_is_wrapped_legacy_qgpk();
    test_is_wrapped_dnat_file();
    test_is_wrapped_file_too_short();
    test_key_load_from_buffer_raw();
    test_key_load_from_buffer_too_small();
    test_key_load_from_buffer_invalid_args();
    printf("All platform_keystore tests passed!\n");
    return 0;
}
