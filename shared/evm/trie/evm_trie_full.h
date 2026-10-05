/**
 * @file evm_trie_full.h
 * @brief Full-rebuild MPT root — a straight port of the reference, used
 *        ONLY by trie/test_trie.c as an in-C cross-check of the incremental
 *        trie (evm_trie.c). Not production code; never linked into a node.
 *
 * Port of execution-specs @a87891f7 src/ethereum/merkle_patricia_trie.py:
 * _prepare_data :407-448, patricialize :507-581, encode_internal_node
 * :213-249, nibble_list_to_compact :360-392, bytes_to_nibble_list
 * :395-404, common_prefix_length :350-357, root :478-504. Unlike the
 * incremental trie it accepts keys of any length (unsecured mode), so
 * branch values and short keys are exercised too.
 *
 * Two hash modes, the only parameter:
 *   EVM_TRIE_FULL_SHA3_512  the Nodus EVM substitutions (design §6): node digest
 *                           and secure key SHA3-512, inline threshold 64;
 *   EVM_TRIE_FULL_KECCAK256 the reference unchanged: keccak256, threshold
 *                           32 — reproduces official Ethereum roots, which
 *                           shows the structure code is the reference's.
 * In both modes the inline threshold equals the digest length.
 */
#ifndef EVM_TRIE_FULL_H
#define EVM_TRIE_FULL_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    EVM_TRIE_FULL_SHA3_512  = 0,
    EVM_TRIE_FULL_KECCAK256 = 1
} evm_trie_full_hash;

/** One entry; `val` is the opaque, non-empty value (:438-439). */
typedef struct {
    const uint8_t *key;
    size_t         key_len;
    const uint8_t *val;
    size_t         val_len;
} evm_trie_full_kv;

/** Digest length of a mode: 64 or 32. */
size_t evm_trie_full_digest_len(evm_trie_full_hash h);

/**
 * Root over n entries (any order). `root` receives digest_len(h) bytes.
 * @param secured 1: hash every key with the mode's hash first (:441-445).
 * @return 0, -1 (empty value, duplicate key after hashing, bad mode),
 *         -2 (allocation / hash failure).
 */
int evm_trie_full_root(const evm_trie_full_kv *kvs, size_t n, int secured,
                       evm_trie_full_hash h, uint8_t *root);

#ifdef __cplusplus
}
#endif

#endif /* EVM_TRIE_FULL_H */
