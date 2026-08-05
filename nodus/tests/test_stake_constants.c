/* Test: stake/committee/timing constants are defined with correct values.
 *
 * Uses explicit CHECK_EQ (not assert) — dnac Release builds define NDEBUG
 * which turns assert into a no-op, letting the test silently pass.
 */
#include "dnac/dnac.h"
#include "dnac/validator.h"     /* S3: DNAC_VALIDATOR_ELIGIBLE */
#include "dnac/ledger_ids.h"    /* S3: DNA_MAX_ACTIVE_VALIDATORS */
#include <stdio.h>
#include <stdint.h>

#define CHECK_EQ(actual, expected) do {                                   \
    if ((unsigned long long)(actual) != (unsigned long long)(expected)) { \
        fprintf(stderr,                                                   \
                "test_stake_constants: FAIL — %s == %llu, expected %llu\n",\
                #actual, (unsigned long long)(actual),                    \
                (unsigned long long)(expected));                          \
        return 1;                                                         \
    }                                                                     \
} while (0)

int main(void) {
    CHECK_EQ(DNAC_SELF_STAKE_AMOUNT, 10000000ULL * 100000000ULL);
    CHECK_EQ(DNAC_MIN_DELEGATION, 100ULL * 100000000ULL);
    CHECK_EQ(DNAC_MAX_DELEGATIONS_PER_DELEGATOR, 64);
    CHECK_EQ(DNAC_MAX_VALIDATORS, 128);
    CHECK_EQ(DNAC_UNSTAKE_COOLDOWN_BLOCKS, 17280);
    CHECK_EQ(DNAC_EPOCH_LENGTH, 720);
    CHECK_EQ(DNAC_MIN_TENURE_BLOCKS, 1440);
    /* S3: DNAC_COMMITTEE_SIZE is no longer "the" committee size — it is
     * DNA's initial seat count and the governance MINIMUM. Its value is
     * still 7 and the live chain still runs at it, so the pin stays. */
    CHECK_EQ(DNAC_COMMITTEE_SIZE, 7);
    CHECK_EQ(DNAC_MAX_ACTIVE_VALIDATORS, 128);
    /* The dnac.h mirror and the shared/ definition must not drift — they
     * are duplicated on purpose (dnac.h stays free of shared/ includes)
     * and a mismatch would size the witness arrays against one ceiling
     * while the wire codec validated against another. */
    CHECK_EQ(DNAC_MAX_ACTIVE_VALIDATORS, DNA_MAX_ACTIVE_VALIDATORS);
    /* TARGET_ACTIVE_COUNT governance range = [initial seats, ceiling]. */
    CHECK_EQ(DNAC_CFG_MIN_TARGET_ACTIVE, DNAC_COMMITTEE_SIZE);
    CHECK_EQ(DNAC_CFG_MAX_TARGET_ACTIVE, DNAC_MAX_ACTIVE_VALIDATORS);

    /* S3 status enum: ELIGIBLE is APPENDED at 4. Every value below it
     * keeps its meaning — the byte is wire-stable and already committed
     * into validator Merkle leaves on the live chain. */
    CHECK_EQ(DNAC_VALIDATOR_ACTIVE,       0);
    CHECK_EQ(DNAC_VALIDATOR_RETIRING,     1);
    CHECK_EQ(DNAC_VALIDATOR_UNSTAKED,     2);
    CHECK_EQ(DNAC_VALIDATOR_AUTO_RETIRED, 3);
    CHECK_EQ(DNAC_VALIDATOR_ELIGIBLE,     4);
    CHECK_EQ(DNAC_LIVENESS_THRESHOLD_BPS, 8000);
    CHECK_EQ(DNAC_AUTO_RETIRE_EPOCHS, 3);
    CHECK_EQ(DNAC_SIGN_FRESHNESS_WINDOW, 32);
    CHECK_EQ(DNAC_COMMISSION_BPS_MAX, 10000);
    CHECK_EQ(DNAC_SETTLEMENT_ATTENDANCE_WINDOW_BLOCKS, 120);
    CHECK_EQ(DNAC_CHAIN_CONFIG_GRACE_ERGONOMIC_BLOCKS, 720);
    CHECK_EQ(DNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS, 17280);

    /* Sanity: MIN_TENURE must be 2× EPOCH_LENGTH per design §3.6 */
    CHECK_EQ(DNAC_MIN_TENURE_BLOCKS, 2 * DNAC_EPOCH_LENGTH);

    printf("test_stake_constants: PASS\n");
    return 0;
}
