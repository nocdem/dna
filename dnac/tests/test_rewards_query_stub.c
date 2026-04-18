/* Phase 14 Task 64 — dnac_get_pending_rewards now wires through to the
 * witness RPC. Without a live witness this test can only cover the
 * input-validation gates and the "not initialised" fast-path (nodus
 * singleton absent in a unit-test process). Full coverage lands in
 * Phase 17 integration tests with a running witness.
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

    /* NULL total_pending_out → INVALID_PARAM. */
    int rc = dnac_get_pending_rewards(NULL, NULL, NULL, NULL, NULL);
    CHECK(rc == DNAC_ERROR_INVALID_PARAM);

    /* NULL ctx → INVALID_PARAM, output zeroed. */
    pending = 0xCAFEBABECAFEBABEULL;
    rc = dnac_get_pending_rewards(NULL, NULL, &pending, NULL, NULL);
    CHECK(rc == DNAC_ERROR_INVALID_PARAM);
    CHECK(pending == 0);

    /* Poisoned pending survives the explicit-claimant path too. The
     * real RPC call cannot happen in a unit-test (no nodus singleton),
     * so we expect either INVALID_PARAM (NULL ctx gate) or
     * NOT_INITIALIZED downstream. */
    pending = 0x1122334455667788ULL;
    uint8_t pub[DNAC_PUBKEY_SIZE];
    memset(pub, 0x11, sizeof(pub));
    rc = dnac_get_pending_rewards(NULL, pub, &pending, NULL, NULL);
    CHECK(rc == DNAC_ERROR_INVALID_PARAM);
    CHECK(pending == 0);

    printf("test_rewards_query_stub: ALL CHECKS PASSED\n");
    return 0;
}
