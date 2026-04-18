/* Task 36 — input-validation coverage for dnac_claim_reward().
 *
 * Only the parameter-gate checks that fire before the builder touches
 * the dna_engine / nodus layer are exercised here. The freshness gate
 * (current_block <= valid_before_block) and Rule L dust-floor check
 * run witness-side at state-apply time and are covered in Phase 17.
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

    uint8_t validator[DNAC_PUBKEY_SIZE];
    memset(validator, 0xCD, sizeof(validator));

    const uint64_t sample_max_pending = 100000000ULL;     /* 1 DNAC */
    const uint64_t sample_valid_block = 1000;

    /* NULL ctx. */
    CHECK(dnac_claim_reward(NULL, validator,
                            sample_max_pending, sample_valid_block,
                            NULL, NULL)
          == DNAC_ERROR_INVALID_PARAM);

    /* NULL target_validator_pubkey. */
    CHECK(dnac_claim_reward(dummy, NULL,
                            sample_max_pending, sample_valid_block,
                            NULL, NULL)
          == DNAC_ERROR_INVALID_PARAM);

    /* max_pending_amount == 0. */
    CHECK(dnac_claim_reward(dummy, validator,
                            0, sample_valid_block,
                            NULL, NULL)
          == DNAC_ERROR_INVALID_PARAM);

    /* valid_before_block == 0. */
    CHECK(dnac_claim_reward(dummy, validator,
                            sample_max_pending, 0,
                            NULL, NULL)
          == DNAC_ERROR_INVALID_PARAM);

    printf("test_claim_builder: OK\n");
    return 0;
}
