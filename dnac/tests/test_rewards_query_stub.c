/* Task 38 — verifies the dnac_get_pending_rewards() stub returns
 * DNAC_ERROR_NOT_IMPLEMENTED cleanly, doesn't crash, and always zeroes
 * *total_pending_out so callers can't act on uninitialised values.
 *
 * Full coverage of the real RPC lands in Phase 14 Task 61 + Phase 17.
 */

#include "dnac/dnac.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK fail at %s:%d: %s\n", \
                __FILE__, __LINE__, #cond); \
        exit(1); \
    } \
} while (0)

int main(void) {
    uint64_t pending = 0xDEADBEEFDEADBEEFULL;

    /* NULL ctx + NULL claimant — stub still zeroes output and returns
     * NOT_IMPLEMENTED. */
    int rc = dnac_get_pending_rewards(NULL, NULL, &pending, NULL, NULL);
    CHECK(rc == DNAC_ERROR_NOT_IMPLEMENTED);
    CHECK(pending == 0);

    /* Poison output again; confirm the stub re-zeroes on every call. */
    pending = 0xCAFEBABECAFEBABEULL;
    uint8_t pub[DNAC_PUBKEY_SIZE];
    memset(pub, 0x11, sizeof(pub));
    rc = dnac_get_pending_rewards(NULL, pub, &pending, NULL, NULL);
    CHECK(rc == DNAC_ERROR_NOT_IMPLEMENTED);
    CHECK(pending == 0);

    /* NULL total_pending_out — input-validation gate. */
    rc = dnac_get_pending_rewards(NULL, NULL, NULL, NULL, NULL);
    CHECK(rc == DNAC_ERROR_INVALID_PARAM);

    printf("test_rewards_query_stub: ALL CHECKS PASSED\n");
    return 0;
}
