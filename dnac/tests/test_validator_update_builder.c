/* Task 37 — input-validation coverage for dnac_validator_update().
 *
 * Only the parameter-gate checks that fire before the builder touches
 * the dna_engine / nodus layer are exercised here. Rule K freshness
 * (current_block - signed_at_block <= DNAC_SIGN_FRESHNESS_WINDOW) and
 * the commission-increase epoch-notice rule run witness-side at
 * state-apply time and are covered in Phase 17.
 */

#include "dnac/dnac.h"

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
    dnac_context_t *dummy = (dnac_context_t *)(uintptr_t)0x1;

    const uint64_t sample_signed_block = 42;

    /* NULL ctx. */
    CHECK(dnac_validator_update(NULL, 500, sample_signed_block, NULL, NULL)
          == DNAC_ERROR_INVALID_PARAM);

    /* signed_at_block == 0. */
    CHECK(dnac_validator_update(dummy, 500, 0, NULL, NULL)
          == DNAC_ERROR_INVALID_PARAM);

    /* new_commission_bps > DNAC_COMMISSION_BPS_MAX (10000). */
    CHECK(dnac_validator_update(dummy,
                                DNAC_COMMISSION_BPS_MAX + 1,
                                sample_signed_block, NULL, NULL)
          == DNAC_ERROR_INVALID_PARAM);

    /* Wildly out-of-range bps still hits the same gate. */
    CHECK(dnac_validator_update(dummy, 0xFFFF, sample_signed_block, NULL, NULL)
          == DNAC_ERROR_INVALID_PARAM);

    /* Boundary cases (new_commission_bps == DNAC_COMMISSION_BPS_MAX and
     * new_commission_bps == 0) are acceptable per Rule K and must pass
     * the parameter-gate. We don't exercise them against the dummy ctx
     * because doing so steps past the gate into dnac_get_engine(), which
     * requires a real context. End-to-end coverage of the happy path
     * lands in Phase 17 Tasks 78-82. */

    printf("test_validator_update_builder: OK\n");
    return 0;
}
