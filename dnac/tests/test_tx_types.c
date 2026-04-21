/* Test: new stake/delegation TX type enum values exist with correct numbers.
 *
 * NOTE: uses explicit if+return rather than assert() so that Release builds
 * (which define NDEBUG and turn assert() into a no-op) still enforce the
 * contract.
 */
#include "dnac/dnac.h"
#include <stdio.h>

#define CHECK_EQ(actual, expected) do {                                   \
    if ((int)(actual) != (int)(expected)) {                               \
        fprintf(stderr,                                                   \
                "test_tx_types: FAIL — %s == %d, expected %d\n",          \
                #actual, (int)(actual), (int)(expected));                 \
        return 1;                                                         \
    }                                                                     \
} while (0)

int main(void) {
    CHECK_EQ(DNAC_TX_GENESIS, 0);
    CHECK_EQ(DNAC_TX_SPEND, 1);
    CHECK_EQ(DNAC_TX_BURN, 2);
    CHECK_EQ(DNAC_TX_TOKEN_CREATE, 3);
    CHECK_EQ(DNAC_TX_STAKE, 4);
    CHECK_EQ(DNAC_TX_DELEGATE, 5);
    CHECK_EQ(DNAC_TX_UNSTAKE, 6);
    CHECK_EQ(DNAC_TX_UNDELEGATE, 7);
    CHECK_EQ(DNAC_TX_VALIDATOR_UPDATE, 9);
    printf("test_tx_types: PASS\n");
    return 0;
}
