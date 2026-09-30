/**
 * @file dm_outbox_codec.c
 * @brief DM outbox day-bucket key derivation — codec unit
 *
 * NC-1 (Web Connect design rev 5 §1.3, operator decision 2026-09-30 Q2 = a):
 * dht_dm_outbox_get_day_bucket / dht_dm_outbox_make_key moved verbatim out
 * of dht/shared/dht_dm_outbox.c (which also runs the thread pool and the
 * nodus_ops puts/gets) so the native library and the web thin core compile
 * the same code. Declarations stay in dht_dm_outbox.h. No network I/O.
 *
 * Key string: "<sender>:outbox:<recipient>:<day>:<salt hex>",
 * day = unix time / 86400; a NULL salt is refused.
 */

#include "dht/shared/dht_dm_outbox.h"
#include <stdio.h>
#include <time.h>

#include "crypto/utils/qgp_log.h"

#define LOG_TAG "DHT_DM_OUTBOX"

/*============================================================================
 * Key Generation
 *============================================================================*/

uint64_t dht_dm_outbox_get_day_bucket(void) {
    return (uint64_t)time(NULL) / DNA_DM_OUTBOX_SECONDS_PER_DAY;
}

int dht_dm_outbox_make_key(
    const char *sender_fp,
    const char *recipient_fp,
    uint64_t day_bucket,
    const uint8_t *salt,
    char *key_out,
    size_t key_out_size
) {
    if (!sender_fp || !recipient_fp || !key_out || key_out_size < 300) {
        return -1;
    }

    /* CORE-04: salt is required. The legacy unsalted fallback branch was
     * removed in phase 6 plan 05. A NULL salt now returns -1 so that any
     * caller that forgets to thread the per-contact salt through fails
     * loudly instead of publishing a deterministic, metadata-leaking key. */
    if (!salt) {
        QGP_LOG_ERROR(LOG_TAG,
            "dht_dm_outbox_make_key: salt is required (NULL passed) "
            "- refusing to produce unsalted key");
        return -1;
    }

    /* Use current day if day_bucket is 0 */
    if (day_bucket == 0) {
        day_bucket = dht_dm_outbox_get_day_bucket();
    }

    /* Salted key format: sender_fp:outbox:recipient_fp:day_bucket:SALT_HEX */
    char salt_hex[65];
    for (int i = 0; i < 32; i++) {
        snprintf(salt_hex + (i * 2), 3, "%02x", salt[i]);
    }
    salt_hex[64] = '\0';

    int written = snprintf(key_out, key_out_size, "%s:outbox:%s:%lu:%s",
                           sender_fp, recipient_fp, (unsigned long)day_bucket, salt_hex);
    if (written < 0 || (size_t)written >= key_out_size) {
        return -1;
    }

    return 0;
}
