/* Task 35 — input-validation coverage for
 * dnac_delegate() / dnac_undelegate().
 *
 * Only the parameter-gate checks that fire before the builder touches the
 * dna_engine / nodus layer are exercised here. The engine-dependent
 * Rule S check (signer != validator_pubkey) needs a real context and is
 * deferred to integration coverage in Phase 17 Tasks 78-82.
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
    memset(validator, 0xAB, sizeof(validator));

    /* -----------------------------------------------------------------
     * dnac_delegate guards
     * ---------------------------------------------------------------*/

    /* NULL ctx. */
    CHECK(dnac_delegate(NULL, validator, DNAC_MIN_DELEGATION, NULL, NULL)
          == DNAC_ERROR_INVALID_PARAM);

    /* NULL validator_pubkey. */
    CHECK(dnac_delegate(dummy, NULL, DNAC_MIN_DELEGATION, NULL, NULL)
          == DNAC_ERROR_INVALID_PARAM);

    /* Amount below DNAC_MIN_DELEGATION (100 DNAC). */
    CHECK(dnac_delegate(dummy, validator, DNAC_MIN_DELEGATION - 1, NULL, NULL)
          == DNAC_ERROR_INVALID_PARAM);

    /* Zero amount → still below minimum. */
    CHECK(dnac_delegate(dummy, validator, 0, NULL, NULL)
          == DNAC_ERROR_INVALID_PARAM);

    /* -----------------------------------------------------------------
     * dnac_undelegate guards
     * ---------------------------------------------------------------*/

    /* NULL ctx. */
    CHECK(dnac_undelegate(NULL, validator, 100, NULL, NULL)
          == DNAC_ERROR_INVALID_PARAM);

    /* NULL validator_pubkey. */
    CHECK(dnac_undelegate(dummy, NULL, 100, NULL, NULL)
          == DNAC_ERROR_INVALID_PARAM);

    /* Zero amount. */
    CHECK(dnac_undelegate(dummy, validator, 0, NULL, NULL)
          == DNAC_ERROR_INVALID_PARAM);

    printf("test_delegate_builder: OK\n");
    return 0;
}
