/* Test: DNAC version reflects stake v1 feature branch bump.
 *
 * This test locks the version numbers for Phase 1 completion.
 * When the feature lands on main and the suffix is dropped,
 * this test will be updated along with the release bump.
 */
#include "dnac/version.h"
#include <stdio.h>
#include <string.h>

#define CHECK_EQ_INT(actual, expected) do {                               \
    if ((int)(actual) != (int)(expected)) {                               \
        fprintf(stderr,                                                   \
                "test_version_bump: FAIL - %s == %d, expected %d\n",      \
                #actual, (int)(actual), (int)(expected));                 \
        return 1;                                                         \
    }                                                                     \
} while (0)

int main(void) {
    /* Phase 1 Task 4: DNAC bumped from 0.16.0 to 0.17.0-stake.wip */
    CHECK_EQ_INT(DNAC_VERSION_MAJOR, 0);
    CHECK_EQ_INT(DNAC_VERSION_MINOR, 17);    /* bumped from 16 */
    CHECK_EQ_INT(DNAC_VERSION_PATCH, 0);

    /* String must contain -stake.wip suffix so debug logs make origin obvious */
    if (strstr(DNAC_VERSION_STRING, "stake.wip") == NULL) {
        fprintf(stderr, "test_version_bump: FAIL - VERSION_STRING '%s' missing 'stake.wip' suffix\n",
                DNAC_VERSION_STRING);
        return 1;
    }

    printf("test_version_bump: PASS (version = %s)\n", DNAC_VERSION_STRING);
    return 0;
}
