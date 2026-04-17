/* Test: Merkle tree-tag domain separator constants are defined with
 * the wire-stable numeric values. These bytes appear in leaf-key
 * preimages and leaf-value hash preimages; changing them would
 * invalidate every existing state_root. Locked by this test.
 *
 * Uses explicit CHECK macro rather than assert() — nodus tests must
 * survive Release builds.
 */
#include "nodus/nodus_types.h"
#include <stdio.h>
#include <stdint.h>

#define CHECK_EQ_U8(actual, expected) do {                                \
    if ((unsigned)(actual) != (unsigned)(expected)) {                     \
        fprintf(stderr,                                                   \
                "test_merkle_tree_tags: FAIL — %s == 0x%02x, expected 0x%02x\n",\
                #actual, (unsigned)(actual), (unsigned)(expected));       \
        return 1;                                                         \
    }                                                                     \
} while (0)

int main(void) {
    CHECK_EQ_U8(NODUS_TREE_TAG_UTXO,        0x01);
    CHECK_EQ_U8(NODUS_TREE_TAG_VALIDATOR,   0x02);
    CHECK_EQ_U8(NODUS_TREE_TAG_DELEGATION,  0x03);
    CHECK_EQ_U8(NODUS_TREE_TAG_REWARD,      0x04);

    /* Sanity: all four tags distinct */
    CHECK_EQ_U8(NODUS_TREE_TAG_UTXO        != NODUS_TREE_TAG_VALIDATOR, 1);
    CHECK_EQ_U8(NODUS_TREE_TAG_UTXO        != NODUS_TREE_TAG_DELEGATION, 1);
    CHECK_EQ_U8(NODUS_TREE_TAG_UTXO        != NODUS_TREE_TAG_REWARD, 1);
    CHECK_EQ_U8(NODUS_TREE_TAG_VALIDATOR   != NODUS_TREE_TAG_DELEGATION, 1);
    CHECK_EQ_U8(NODUS_TREE_TAG_VALIDATOR   != NODUS_TREE_TAG_REWARD, 1);
    CHECK_EQ_U8(NODUS_TREE_TAG_DELEGATION  != NODUS_TREE_TAG_REWARD, 1);

    printf("test_merkle_tree_tags: PASS\n");
    return 0;
}
