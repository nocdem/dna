/**
 * @file evm_trie_proof.h
 * @brief HF-9 WP6: Merkle Patricia proofs over the SHA3-512 trie of
 *        evm_trie.h - prove (single path and union of paths) and verify
 *        (single and batch). Linkable by the node and by clients.
 *
 * Plan docs/plans/approved/2026-11-04-hf9.md §10.1, §10.2 (AD-8, AD-9);
 * Kurultay 55 A10 - A12, F-18 .. F-25.
 *
 * PROVE (go-ethereum v1.17.8 trie/proof.go:37-95 with substitution 2): the
 * nodes on the path to SHA3-512(key), each node whose encoding is >= 64 bytes
 * (a node below the threshold lives inside its parent), and always the root.
 * A node is loaded only when the path reaches it: an extension is NOT
 * followed into its child when its segment mismatches (so the off-path child
 * of a mismatching extension is not emitted, as in the reference). An empty
 * trie emits no node. The reference emits the root with `i == 0`
 * (proof.go:37-95); the batch union is deduplicated and ordered ascending by
 * SHA3-512 digest (plan §10.2).
 *
 * VERIFY (proof.go:111-135, trienode/proof.go:130-146 with AD-9): nodes are
 * indexed by the VERIFIER's own SHA3-512 of each node (never a sender-supplied
 * key), strictly ascending and unique; the walk starts at the authenticated
 * leg root. A nil child or a mismatching extension proves absence (a
 * mismatching extension without its off-path hashed child); a node required
 * by the path that is not in the bundle is an ERROR, never absence. At each
 * node's authenticated position evm_trie_node_check runs (decode at that
 * depth with the parent's expected-branch flag, re-encode and compare,
 * structural checks, size class); the Z-52 eager extension-child load is the
 * store's alone. The empty leg (root = SHA3-512(0x80)) proves absence of
 * every key with an EMPTY bundle; whether that root is authentic is the
 * caller's (the composition proof, ledger_roots_v2.h).
 *
 * The bundle proves each requested key independently; it is not a range or
 * completeness proof (A10).
 *
 * ERRORS: 0 ok; -1 invalid argument or a bound exceeded; -2 the store or the
 * proof failed a check.
 */
#ifndef EVM_TRIE_PROOF_H
#define EVM_TRIE_PROOF_H

#include <stddef.h>
#include <stdint.h>

#include "evm_trie.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Bounds (plan §10.2, D26, A11, F-20, F-21), checked before any allocation or
 * traversal. */
#define EVM_TRIE_PROOF_MAX_KEYS        128u
#define EVM_TRIE_PROOF_NODES_PER_KEY   131u   /* <= 129 on a path (evm_trie.h
                                               * COST) + a margin           */
#define EVM_TRIE_PROOF_MAX_NODES \
    (EVM_TRIE_PROOF_MAX_KEYS * EVM_TRIE_PROOF_NODES_PER_KEY)
#define EVM_TRIE_PROOF_NODE_MAX_BYTES  EVM_TRIE_NODE_MAX_BYTES

/** A growing node set (prove output). Owned: release with
 *  evm_trie_proof_set_free. */
typedef struct {
    uint8_t digest[EVM_TRIE_DIGEST_LEN];
    uint8_t *rlp;
    size_t   len;
} evm_trie_proof_node_t;

typedef struct {
    evm_trie_proof_node_t *v;
    size_t n, cap;
} evm_trie_proof_set_t;

void evm_trie_proof_set_free(evm_trie_proof_set_t *s);

/** SHA3-512(key) - the 64-byte secured path of a key. @return 0 / -2. */
int evm_trie_proof_path_of_key(const uint8_t *key, size_t key_len,
                               uint8_t path[EVM_TRIE_PATH_LEN]);

/** Add the proof nodes of `path` under `root` to `set` (duplicates across
 *  paths are removed by evm_trie_proof_set_finish). Every node loaded from
 *  the store is checked (digest, evm_trie_node_check). An absent key is a
 *  valid proof (0). @return 0, -1, -2. */
int evm_trie_prove_path(const evm_trie_store_t *store,
                        const uint8_t root[EVM_TRIE_DIGEST_LEN],
                        const uint8_t path[EVM_TRIE_PATH_LEN],
                        evm_trie_proof_set_t *set);

/** Sort `set` ascending by digest and drop duplicates. @return 0 / -2. */
int evm_trie_proof_set_finish(evm_trie_proof_set_t *s);

/** The per-node function of Kurultay 55 F-25: SHA3-512(rlp) must equal
 *  `digest` (the digest the node was indexed under), then
 *  evm_trie_node_check on that one node. No other node is loaded.
 *  @return 0, -1, -2. */
int evm_trie_proof_check_node(const uint8_t digest[EVM_TRIE_DIGEST_LEN],
                              const uint8_t *rlp, size_t len, size_t depth,
                              int expect_branch, int size_class,
                              evm_trie_node_view_t *out);

/** One verified result. `val` points INTO the bundle's node bytes. */
typedef struct {
    int            found;
    const uint8_t *val;
    size_t         val_len;
} evm_trie_proof_result_t;

/** Verify `n_keys` (1 .. EVM_TRIE_PROOF_MAX_KEYS, no duplicate path) paths
 *  against `root` with the bundle `nodes[0..n_nodes)` (each at most
 *  EVM_TRIE_PROOF_NODE_MAX_BYTES, at most EVM_TRIE_PROOF_MAX_NODES, strictly
 *  ascending by their SHA3-512 digest). `res` receives one result per path,
 *  in order. For the empty root the bundle must be empty and every result is
 *  absent. @return 0, -1 (bounds, duplicates), -2 (the proof fails). */
int evm_trie_proof_verify_batch(const uint8_t root[EVM_TRIE_DIGEST_LEN],
                                const uint8_t *const *nodes,
                                const size_t *node_lens, size_t n_nodes,
                                const uint8_t (*paths)[EVM_TRIE_PATH_LEN],
                                size_t n_keys, evm_trie_proof_result_t *res);

#ifdef __cplusplus
}
#endif

#endif /* EVM_TRIE_PROOF_H */
