/**
 * @file fuzz_base58.c
 * @brief libFuzzer harness for Base58 decoding
 *
 * Fuzzes base58_decode() from crypto/utils/base58.c
 *
 * Common vulnerabilities to find:
 * - Integer overflows in size calculations
 * - Buffer overflows from large inputs
 * - Invalid character handling
 * - Leading zeros handling
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "crypto/utils/base58.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* Limit input size to avoid timeouts */
    if (size == 0 || size > 512) {
        return 0;
    }

    /* Null-terminate for base58_decode (expects C string) */
    char *input = malloc(size + 1);
    if (!input) {
        return 0;
    }
    memcpy(input, data, size);
    input[size] = '\0';

    /*
     * Allocate output buffer using the same macro as real code
     * BASE58_DECODE_SIZE(a_in_size) = (2 * a_in_size + 1)
     */
    size_t out_size = BASE58_DECODE_SIZE(size);
    uint8_t *output = malloc(out_size);
    if (!output) {
        free(input);
        return 0;
    }

    /* Zero output buffer to detect overflows */
    memset(output, 0, out_size);

    /* This should handle invalid base58 characters gracefully */
    base58_decode(input, output);

    free(input);
    free(output);
    return 0;
}
