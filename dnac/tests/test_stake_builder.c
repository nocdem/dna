/* Task 34 — input-validation coverage for dnac_stake() / dnac_unstake().
 *
 * This is a lightweight client-side test: we drive only the input-
 * validation guards at the top of each builder, which reject malformed
 * parameters *before* the code touches the dna_engine / nodus layer.
 *
 * Full end-to-end builder coverage (UTXO selection, hash preimage, witness
 * attestation, broadcast) requires a networked context and is exercised
 * in Phase 17 Tasks 78-82 (integration tests).
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

/* 128 lowercase-hex chars = valid fingerprint string. */
static const char *VALID_FP =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

int main(void) {
    /* -----------------------------------------------------------------
     * dnac_stake guards
     * ---------------------------------------------------------------*/

    /* NULL ctx */
    CHECK(dnac_stake(NULL, 500, VALID_FP, NULL, NULL)
          == DNAC_ERROR_INVALID_PARAM);

    /* NULL unstake_destination_fp (ctx is non-NULL sentinel — we want
     * the pre-check to fire; real context init needs DNA engine). */
    dnac_context_t *dummy = (dnac_context_t *)(uintptr_t)0x1;
    CHECK(dnac_stake(dummy, 500, NULL, NULL, NULL)
          == DNAC_ERROR_INVALID_PARAM);

    /* commission_bps > 10000 */
    CHECK(dnac_stake(dummy, (uint16_t)(DNAC_COMMISSION_BPS_MAX + 1),
                     VALID_FP, NULL, NULL)
          == DNAC_ERROR_INVALID_PARAM);

    /* Malformed fingerprint: wrong length. */
    CHECK(dnac_stake(dummy, 500, "dead", NULL, NULL)
          == DNAC_ERROR_INVALID_PARAM);

    /* Malformed fingerprint: non-hex char. */
    char bad_fp[129];
    memcpy(bad_fp, VALID_FP, 128);
    bad_fp[64] = 'Z';            /* illegal hex char */
    bad_fp[128] = '\0';
    CHECK(dnac_stake(dummy, 500, bad_fp, NULL, NULL)
          == DNAC_ERROR_INVALID_PARAM);

    /* Uppercase hex is rejected (we accept lowercase only — matches
     * DNAC fingerprint convention). */
    char upper_fp[129];
    memcpy(upper_fp, VALID_FP, 128);
    upper_fp[0] = 'A';
    upper_fp[128] = '\0';
    CHECK(dnac_stake(dummy, 500, upper_fp, NULL, NULL)
          == DNAC_ERROR_INVALID_PARAM);

    /* -----------------------------------------------------------------
     * dnac_unstake guards
     * ---------------------------------------------------------------*/

    CHECK(dnac_unstake(NULL, NULL, NULL) == DNAC_ERROR_INVALID_PARAM);

    printf("test_stake_builder: OK\n");
    return 0;
}
