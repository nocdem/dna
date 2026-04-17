/**
 * Test: state_root = SHA3-512(utxo || validator || delegation || reward)
 *
 * Pins the composite state_root (witness stake v1 / Phase 3 Task 10) to an
 * exact byte sequence for a genesis-equivalent input. Any accidental
 * change to the combiner formula, subtree order, or tree-tag constants
 * will break this KAT immediately — preventing a silent consensus fork.
 *
 * Genesis-equivalent input:
 *   utxo_root       = 64 × 0x00   (canonical pre-state, 64 zero bytes)
 *   validator_root  = nodus_merkle_empty_root(NODUS_TREE_TAG_VALIDATOR)
 *   delegation_root = nodus_merkle_empty_root(NODUS_TREE_TAG_DELEGATION)
 *   reward_root     = nodus_merkle_empty_root(NODUS_TREE_TAG_REWARD)
 *
 * Expected state_root derived via Python:
 *   python3 -c "
 *     import hashlib
 *     utxo = bytes(64)
 *     val  = hashlib.sha3_512(bytes([0x02, 0x00])).digest()
 *     deleg= hashlib.sha3_512(bytes([0x03, 0x00])).digest()
 *     rew  = hashlib.sha3_512(bytes([0x04, 0x00])).digest()
 *     print(hashlib.sha3_512(utxo + val + deleg + rew).hexdigest())
 *   "
 * → 7419cd1f0231390b99b97f18fc7770294af528459f5265f98ccc710dfe986db0
 *   e9b0e73724af97af8ed302b7a083c46d4367b568e0ec383cdbafd661a51c68fe
 */

#include "witness/nodus_witness_merkle.h"
#include "nodus/nodus_types.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>

static int check_bytes(const char *label,
                       const uint8_t got[64],
                       const uint8_t want[64]) {
    if (memcmp(got, want, 64) != 0) {
        fprintf(stderr, "test_state_root_4subtree: FAIL — %s\n  got:  ", label);
        for (int i = 0; i < 64; i++) fprintf(stderr, "%02x", got[i]);
        fprintf(stderr, "\n  want: ");
        for (int i = 0; i < 64; i++) fprintf(stderr, "%02x", want[i]);
        fprintf(stderr, "\n");
        return 1;
    }
    return 0;
}

int main(void) {
    /* Assemble genesis-equivalent subtree roots. */
    uint8_t utxo_root[64] = {0};
    uint8_t validator_root[64];
    uint8_t delegation_root[64];
    uint8_t reward_root[64];
    nodus_merkle_empty_root(NODUS_TREE_TAG_VALIDATOR,  validator_root);
    nodus_merkle_empty_root(NODUS_TREE_TAG_DELEGATION, delegation_root);
    nodus_merkle_empty_root(NODUS_TREE_TAG_REWARD,     reward_root);

    uint8_t state_root[64];
    nodus_merkle_combine_state_root(utxo_root, validator_root,
                                    delegation_root, reward_root,
                                    state_root);

    /* KAT — computed via the Python snippet in the file header. */
    const uint8_t expected[64] = {
        0x74, 0x19, 0xcd, 0x1f, 0x02, 0x31, 0x39, 0x0b,
        0x99, 0xb9, 0x7f, 0x18, 0xfc, 0x77, 0x70, 0x29,
        0x4a, 0xf5, 0x28, 0x45, 0x9f, 0x52, 0x65, 0xf9,
        0x8c, 0xcc, 0x71, 0x0d, 0xfe, 0x98, 0x6d, 0xb0,
        0xe9, 0xb0, 0xe7, 0x37, 0x24, 0xaf, 0x97, 0xaf,
        0x8e, 0xd3, 0x02, 0xb7, 0xa0, 0x83, 0xc4, 0x6d,
        0x43, 0x67, 0xb5, 0x68, 0xe0, 0xec, 0x38, 0x3c,
        0xdb, 0xaf, 0xd6, 0x61, 0xa5, 0x1c, 0x68, 0xfe,
    };
    if (check_bytes("state_root(genesis-equivalent)", state_root, expected))
        return 1;

    /* Order sensitivity: swapping any two subtree roots MUST change output. */
    uint8_t swapped[64];
    nodus_merkle_combine_state_root(validator_root, utxo_root,
                                    delegation_root, reward_root,
                                    swapped);
    if (memcmp(state_root, swapped, 64) == 0) {
        fprintf(stderr, "test_state_root_4subtree: FAIL — "
                        "swap(utxo, validator) left state_root unchanged\n");
        return 1;
    }

    nodus_merkle_combine_state_root(utxo_root, validator_root,
                                    reward_root, delegation_root,
                                    swapped);
    if (memcmp(state_root, swapped, 64) == 0) {
        fprintf(stderr, "test_state_root_4subtree: FAIL — "
                        "swap(delegation, reward) left state_root unchanged\n");
        return 1;
    }

    /* Determinism: re-running with identical inputs yields identical output. */
    uint8_t again[64];
    nodus_merkle_combine_state_root(utxo_root, validator_root,
                                    delegation_root, reward_root,
                                    again);
    if (check_bytes("determinism", again, state_root))
        return 1;

    /* Tag cross-check: the empty-root helpers that Phase 3 uses for
     * validator/delegation/reward MUST differ per tree tag — otherwise
     * the combiner would collapse identically-tagged subtrees. */
    if (memcmp(validator_root, delegation_root, 64) == 0 ||
        memcmp(validator_root, reward_root,     64) == 0 ||
        memcmp(delegation_root, reward_root,    64) == 0) {
        fprintf(stderr, "test_state_root_4subtree: FAIL — "
                        "empty-root helpers collided across tags\n");
        return 1;
    }

    printf("test_state_root_4subtree: PASS\n");
    return 0;
}
