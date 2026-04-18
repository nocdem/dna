/* Phase 14 Task 64 — dnac_validator_list() and dnac_get_committee()
 * now wire through to the witness RPCs. Without a live witness this
 * test can only cover the input-validation gates plus the
 * "not initialised" fast-path (nodus singleton absent in a unit-test
 * process). Full coverage lands in Phase 17 integration tests with a
 * running witness.
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
    dnac_validator_list_entry_t entries[DNAC_COMMITTEE_SIZE];
    int count = 0xDEADBEEF;

    /* -----------------------------------------------------------------
     * dnac_validator_list — input validation gates still apply.
     * ---------------------------------------------------------------*/

    /* NULL count_out → INVALID_PARAM. */
    CHECK(dnac_validator_list(NULL, -1, entries, DNAC_COMMITTEE_SIZE, NULL)
          == DNAC_ERROR_INVALID_PARAM);

    /* Non-NULL out with zero capacity → INVALID_PARAM. */
    count = 0xDEADBEEF;
    CHECK(dnac_validator_list(NULL, -1, entries, 0, &count)
          == DNAC_ERROR_INVALID_PARAM);

    /* NULL out with non-zero capacity → INVALID_PARAM. */
    count = 0xDEADBEEF;
    CHECK(dnac_validator_list(NULL, -1, NULL, 4, &count)
          == DNAC_ERROR_INVALID_PARAM);

    /* Happy-path shape — no live witness in unit-test, nodus singleton
     * absent → NOT_INITIALIZED. Count and buffer still zeroed (pre-RPC
     * defensive zero). */
    count = 0xDEADBEEF;
    int rc = dnac_validator_list(NULL, -1, entries,
                                 DNAC_COMMITTEE_SIZE, &count);
    CHECK(rc == DNAC_ERROR_NOT_INITIALIZED);
    CHECK(count == 0);

    /* Probe-only call (out=NULL, max_entries=0) hits NOT_INITIALIZED too. */
    count = 0xDEADBEEF;
    rc = dnac_validator_list(NULL, 0 /* ACTIVE */, NULL, 0, &count);
    CHECK(rc == DNAC_ERROR_NOT_INITIALIZED);
    CHECK(count == 0);

    /* -----------------------------------------------------------------
     * dnac_get_committee
     * ---------------------------------------------------------------*/

    /* NULL out → INVALID_PARAM. */
    count = 0xDEADBEEF;
    CHECK(dnac_get_committee(NULL, NULL, &count)
          == DNAC_ERROR_INVALID_PARAM);

    /* NULL count_out → INVALID_PARAM. */
    CHECK(dnac_get_committee(NULL, entries, NULL)
          == DNAC_ERROR_INVALID_PARAM);

    /* No live witness → NOT_INITIALIZED; count zeroed. */
    count = 0xDEADBEEF;
    rc = dnac_get_committee(NULL, entries, &count);
    CHECK(rc == DNAC_ERROR_NOT_INITIALIZED);
    CHECK(count == 0);

    printf("test_validator_queries_stub: ALL CHECKS PASSED\n");
    return 0;
}
