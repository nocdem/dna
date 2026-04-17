/* Task 39 — verifies the dnac_validator_list() and dnac_get_committee()
 * stubs return DNAC_ERROR_NOT_IMPLEMENTED cleanly, don't crash, and
 * always zero *count_out + the caller's buffer so no uninitialised
 * data reaches UI code.
 *
 * Full coverage of the real RPCs lands in Phase 14 Tasks 62 & 63 +
 * Phase 17 integration tests.
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

static void poison_entries(dnac_validator_list_entry_t *buf, int n) {
    memset(buf, 0xA5, (size_t)n * sizeof(*buf));
}

static int all_zero(const dnac_validator_list_entry_t *buf, int n) {
    const unsigned char *p = (const unsigned char *)buf;
    size_t total = (size_t)n * sizeof(*buf);
    for (size_t i = 0; i < total; i++) {
        if (p[i] != 0) return 0;
    }
    return 1;
}

int main(void) {
    dnac_validator_list_entry_t entries[DNAC_COMMITTEE_SIZE];
    int count = 0xDEADBEEF;

    /* -----------------------------------------------------------------
     * dnac_validator_list
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

    /* Happy path — not implemented, buffer + count both zeroed. */
    poison_entries(entries, DNAC_COMMITTEE_SIZE);
    count = 0xDEADBEEF;
    int rc = dnac_validator_list(NULL, -1, entries,
                                 DNAC_COMMITTEE_SIZE, &count);
    CHECK(rc == DNAC_ERROR_NOT_IMPLEMENTED);
    CHECK(count == 0);
    CHECK(all_zero(entries, DNAC_COMMITTEE_SIZE));

    /* Probe-only call (out=NULL, max_entries=0) must be legal. */
    count = 0xDEADBEEF;
    rc = dnac_validator_list(NULL, 0 /* ACTIVE */, NULL, 0, &count);
    CHECK(rc == DNAC_ERROR_NOT_IMPLEMENTED);
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

    /* Happy path — not implemented, buffer + count both zeroed. */
    poison_entries(entries, DNAC_COMMITTEE_SIZE);
    count = 0xDEADBEEF;
    rc = dnac_get_committee(NULL, entries, &count);
    CHECK(rc == DNAC_ERROR_NOT_IMPLEMENTED);
    CHECK(count == 0);
    CHECK(all_zero(entries, DNAC_COMMITTEE_SIZE));

    printf("test_validator_queries_stub: ALL CHECKS PASSED\n");
    return 0;
}
