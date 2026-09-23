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
    /* tokenomics-v3 P1 (operator decision 2026-09-23, decision file §1
     * line 79 + §3's last entries): the liveness bar is 5000 bps, not
     * the retired 8000, and the auto-retire threshold is 2 consecutive
     * DUTY epochs, not 3. Both values are re-pinned here deliberately —
     * this file exists so a silent drift in either is caught, and the
     * 8000 value in particular must never come back: the value that
     * bounds this bar is the WORST-case attendance every member sees
     * when every block commits on exactly a quorum with the excluded
     * signers rotating (~67-73 %, since a block commits on MORE than
     * two-thirds of the members' signatures — a FLOOR on the healthy
     * average, not a ceiling; round 5 correction). A bar ABOVE that
     * worst case lets a jittery-but-healthy cluster put its ENTIRE
     * active set below the bar, and two such epochs empty the validator
     * list with no way to repair it. A bar below it cannot fail the
     * whole set alone, which is why Rule N still carries a SEPARATE
     * floor: the bar and the 120-block recency window can fail
     * DIFFERENT members in the same boundary. That floor has no
     * constant to pin since round 6 (decision file §3 2026-09-23, "Rule
     * N TABANI WEIGHT ÜZERİNDEN", replacing the count floor "Rule N
     * TABANI = 4" and its DNAC_RULE_N_MIN_BONDED): it is the voting-power
     * inequality (P - max) > P * 2 / 3 over the next epoch's seatable
     * set, pinned behaviourally in test_v2_epoch.c §12c/§12e-§12i. */
    CHECK_EQ(DNAC_LIVENESS_THRESHOLD_BPS, 5000);
    CHECK_EQ(DNAC_AUTO_RETIRE_EPOCHS, 2);
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
