/*
 * Test: dna_group_outbox_make_key MUST accept and embed a per-group salt
 *
 * Phase 6 / Plan 04. GREEN after plan 04 ships salt-required signature.
 *
 * CORE-04: the group outbox now requires a per-group 32-byte salt for key
 * derivation. NULL-salt calls are rejected. Key format is
 * "dna:group:<uuid>:out:<day>:<salt_hex>".
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "dht/client/dna_group_outbox.h"

int main(void) {
    fprintf(stderr, "Test: dna_group_outbox_make_key salted (CORE-04)\n");
    fprintf(stderr, "================================================\n");

    const char *group_uuid = "00000000-0000-4000-8000-000000000000";
    uint64_t day_bucket = 19825;
    char key[512];

    uint8_t salt[32];
    memset(salt, 0xAA, sizeof(salt));

    /* Salted call (plan-04 signature) */
    int rc = dna_group_outbox_make_key(group_uuid, day_bucket, salt, key, sizeof(key));
    if (rc != 0) {
        fprintf(stderr, "FAIL: salted dna_group_outbox_make_key returned %d\n", rc);
        return 1;
    }
    fprintf(stderr, "salted key: %s\n", key);
    if (!strstr(key, "dna:group:") || !strstr(key, group_uuid) ||
        !strstr(key, ":out:") ||
        !strstr(key,
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")) {
        fprintf(stderr, "FAIL: salted key missing expected components: %s\n", key);
        return 1;
    }

    /* NULL-salt must be rejected */
    rc = dna_group_outbox_make_key(group_uuid, day_bucket, NULL, key, sizeof(key));
    if (rc == 0) {
        fprintf(stderr, "FAIL: NULL salt was accepted (must reject)\n");
        return 1;
    }

    fprintf(stderr, "PASS: salted key derivation GREEN\n");
    return 0;
}
