/**
 * @file fuzz_value.c
 * @brief libFuzzer harness: signed DHT value (NodusValue) decode + verify.
 *
 * Entry points (all exported, none modified):
 *   nodus_value_deserialize   src/core/nodus_value.c:305
 *   nodus_value_verify        src/core/nodus_value.c
 *   nodus_value_serialize     src/core/nodus_value.c
 *   nodus_value_free          src/core/nodus_value.c
 *
 * The web core's read primitive (design §1.4 R0) decodes the value a node
 * returns and checks its signature and owner before acting on it (design §5
 * G10); this target is that decode + check on arbitrary bytes. A value that
 * decodes is re-serialised, which exercises the encoder on every field
 * combination the decoder accepts.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

#include "core/nodus_value.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    nodus_value_t *val = NULL;   /* must be NULL on entry (nodus_value.c:308) */
    if (nodus_value_deserialize(data, size, &val) != 0) {
        return 0;
    }

    (void)nodus_value_verify(val);

    uint8_t *buf = NULL;
    size_t len = 0;
    if (nodus_value_serialize(val, &buf, &len) == 0) {
        free(buf);
    }

    nodus_value_free(val);
    return 0;
}
