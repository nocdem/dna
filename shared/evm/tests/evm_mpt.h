/**
 * @file evm_mpt.h
 * @brief Ethereum Merkle Patricia Trie ROOT computation — TEST-ONLY.
 *
 * Used only by the state-test harness to compute the post-state root that
 * the official fixtures commit to. Port of execution-specs @a87891f7
 * src/ethereum/merkle_patricia_trie.py:
 *   - secured tries hash each key with keccak256 first (_prepare_data, :441-445)
 *   - keys are nibble lists (bytes_to_nibble_list, :395-404)
 *   - patricialize (:507-581): 1 key -> leaf; common prefix > 0 -> extension;
 *     else 16-way branch with an optional value for a key ending here
 *   - hex-prefix encoding (nibble_list_to_compact, :360-392)
 *   - encode_internal_node (:213-249): a node whose RLP is < 32 bytes is
 *     embedded in its parent as-is, otherwise the parent holds keccak256 of
 *     the RLP; an absent child is the empty string
 *   - root (:478-504) = keccak256(rlp(root node)); for the empty trie that
 *     is keccak256(rlp(b"")) = 56e81f17...b421 (EMPTY_TRIE_ROOT, :71-75)
 *
 * Construction is from a SORTED copy of the leaves, by recursion over
 * contiguous ranges — no hash map, no insertion-order dependence (the
 * Python reference iterates a dict, but its result does not depend on that
 * order; ours does not either). Recursion depth is bounded by the longest
 * key's nibble count + 1 (65 for a secured trie).
 */
#ifndef EVM_TEST_MPT_H
#define EVM_TEST_MPT_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** One leaf. `val` is the already-encoded value stored at the key (for a
 *  state trie: the RLP account; for a storage trie: rlp(uint)); it must be
 *  non-empty (merkle_patricia_trie.py:438-439). */
typedef struct {
    const uint8_t *key;
    size_t         key_len;
    const uint8_t *val;
    size_t         val_len;
} evm_mpt_kv;

/**
 * Compute the trie root over n leaves (any order; a sorted copy is made).
 * @param secured  1: keys are keccak256-hashed first (state/storage tries).
 * @return 0, -1 (duplicate key after hashing, or empty value), -2 (alloc).
 */
int evm_mpt_root(const evm_mpt_kv *kvs, size_t n, int secured,
                 uint8_t root[32]);

#ifdef __cplusplus
}
#endif

#endif /* EVM_TEST_MPT_H */
