/*
 * Test: dna_group_outbox_make_key MUST accept and embed a per-group salt
 *
 * Phase 6 / Plan 04 target. RED today, GREEN after plan 04.
 *
 * CORE-04: the group outbox is currently the only remaining DHT key producer
 * that emits deterministic, unsalted keys. Plan 04 adds a `salt` parameter
 * to dna_group_outbox_make_key, requires non-NULL salt, and rewrites all
 * call sites to thread a per-group 32-byte salt through.
 *
 * Today the function signature has no salt parameter at all, so the salted
 * call cannot even be compiled. We `#if 0` it out and force a RED exit.
 *
 * TODO(plan-04): re-enable the salted block below after dna_group_outbox_make_key
 *                gains a `const uint8_t *salt` parameter.
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

    /* Sanity check: the current (unsalted) signature must still compile and
     * produce a key. Plan 04 will REMOVE this overload and require a salt. */
    int rc = dna_group_outbox_make_key(group_uuid, day_bucket, key, sizeof(key));
    if (rc != 0) {
        fprintf(stderr, "FAIL: current unsalted dna_group_outbox_make_key returned %d\n", rc);
        return 1;
    }
    fprintf(stderr, "current key (unsalted): %s\n", key);
    if (!strstr(key, "dna:group:") || !strstr(key, group_uuid) ||
        !strstr(key, ":out:")) {
        fprintf(stderr, "FAIL: current key shape unexpected: %s\n", key);
        return 1;
    }

#if 0 /* TODO(plan-04): re-enable after dna_group_outbox_make_key gains salt parameter */
    uint8_t salt[32];
    memset(salt, 0xAA, sizeof(salt));

    /* Salted call (post plan-04 signature) */
    rc = dna_group_outbox_make_key(group_uuid, day_bucket, salt, key, sizeof(key));
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
    return 0;
#endif

    /* Wave 0 contract: RED today (the salted assertion above is gated). */
    fprintf(stderr,
            "RED: TODO(plan-04) — dna_group_outbox_make_key has no salt "
            "parameter yet; the salted assertions are guarded with #if 0 "
            "and this test is intentionally RED until plan 04 ships.\n");
    return 1;
}
