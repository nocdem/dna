/* Test: validator/delegation/reward record struct sizes and fields match spec. */
#include "dnac/validator.h"
#include "dnac/dnac.h"
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>

#define CHECK_EQ(actual, expected) do {                                   \
    if ((unsigned long long)(actual) != (unsigned long long)(expected)) { \
        fprintf(stderr,                                                   \
                "test_validator_structs: FAIL — %s == %llu, expected %llu\n",\
                #actual, (unsigned long long)(actual),                    \
                (unsigned long long)(expected));                          \
        return 1;                                                         \
    }                                                                     \
} while (0)

int main(void) {
    /* Status enum values are wire-stable — keep pinned. */
    CHECK_EQ(DNAC_VALIDATOR_ACTIVE, 0);
    CHECK_EQ(DNAC_VALIDATOR_RETIRING, 1);
    CHECK_EQ(DNAC_VALIDATOR_UNSTAKED, 2);
    CHECK_EQ(DNAC_VALIDATOR_AUTO_RETIRED, 3);

    /* Spot-check key field types by assigning typed values */
    dnac_validator_record_t v;
    v.self_stake = DNAC_SELF_STAKE_AMOUNT;
    v.total_delegated = 0;
    v.external_delegated = 0;
    v.commission_bps = 500;
    v.pending_commission_bps = 0;
    v.status = DNAC_VALIDATOR_ACTIVE;
    CHECK_EQ(v.self_stake, DNAC_SELF_STAKE_AMOUNT);
    CHECK_EQ(v.status, 0);

    /* Presence checks — ensure fields compile (sizeof of field arrays) */
    CHECK_EQ(sizeof(v.pubkey), DNAC_PUBKEY_SIZE);
    CHECK_EQ(sizeof(v.unstake_destination_pubkey), DNAC_PUBKEY_SIZE);
    CHECK_EQ(sizeof(v.unstake_destination_fp), DNAC_FINGERPRINT_SIZE);

    dnac_delegation_record_t d;
    CHECK_EQ(sizeof(d.delegator_pubkey), DNAC_PUBKEY_SIZE);
    CHECK_EQ(sizeof(d.validator_pubkey), DNAC_PUBKEY_SIZE);

    /* v0.16: dnac_reward_record_t + d.reward_snapshot removed with the
     * accumulator reward system. Push-settlement emits UTXOs at epoch
     * boundaries so there is no per-validator reward leaf anymore. */

    /* Suppress unused-variable warnings for fields we only check by sizeof */
    (void)v; (void)d;

    printf("test_validator_structs: PASS\n");
    return 0;
}
