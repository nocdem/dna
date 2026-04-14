/*
 * Test: dht_dm_outbox_make_key MUST reject NULL salt
 *
 * Phase 6 / Plan 05 target. RED today, GREEN after plan 05.
 *
 * CORE-04 close-out: the DM outbox already supports salted keys but still
 * accepts salt==NULL and falls back to a deterministic legacy key format.
 * Plan 05 removes the NULL fallback so any code path that forgets to thread
 * the salt through fails loudly.
 *
 * Today the NULL-salt path returns 0 and produces an unsalted key — so the
 * NULL assertion below fails (RED). The non-NULL salted path is asserted as
 * a sanity check and must already be GREEN today.
 *
 * TODO(plan-05): once dht_dm_outbox_make_key returns non-zero on NULL salt,
 *                this test goes GREEN automatically with no edits required.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "dht/shared/dht_dm_outbox.h"

int main(void) {
    fprintf(stderr, "Test: dht_dm_outbox_make_key NULL-salt rejection (CORE-04)\n");
    fprintf(stderr, "==========================================================\n");

    char sender_fp[129];
    char recipient_fp[129];
    memset(sender_fp, 'a', 128);   sender_fp[128]   = '\0';
    memset(recipient_fp, 'b', 128); recipient_fp[128] = '\0';

    char key[512];
    int rc;

    /* (1) Salted path must already work today: assert success + hex suffix. */
    uint8_t salt[32];
    memset(salt, 0xCC, sizeof(salt));
    rc = dht_dm_outbox_make_key(sender_fp, recipient_fp, 12345,
                                salt, key, sizeof(key));
    if (rc != 0) {
        fprintf(stderr, "FAIL: salted call returned %d\n", rc);
        return 1;
    }
    if (!strstr(key,
                "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")) {
        fprintf(stderr, "FAIL: salted key missing 0xCC hex suffix: %s\n", key);
        return 1;
    }
    fprintf(stderr, "salted key OK\n");

    /* (2) NULL-salt path MUST be rejected after plan 05.
     *     Today this returns 0 and produces a legacy key — RED. */
    rc = dht_dm_outbox_make_key(sender_fp, recipient_fp, 12345,
                                NULL, key, sizeof(key));
    if (rc == 0) {
        fprintf(stderr,
                "FAIL: dht_dm_outbox_make_key accepted NULL salt "
                "(produced key=%s). TODO(plan-05): remove the legacy "
                "unsalted fallback branch.\n", key);
        return 1;
    }

    fprintf(stderr, "PASS: NULL salt rejected\n");
    return 0;
}
