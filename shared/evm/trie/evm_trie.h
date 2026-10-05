/**
 * @file evm_trie.h
 * @brief Nodus EVM state commitment: persistent, incremental Merkle Patricia
 *        Trie with SHA3-512 node digests (consensus code).
 *
 * Decision: docs/plans/decisions/2026-10-04-nodus-evm-kurultay-k2-summary.md #1;
 * design: docs/plans/2026-10-04-nodus-evm-chain-integration-design.md rev 3 §6.
 *
 * ROOT DEFINITION (pinned): execution-specs @a87891f7
 * src/ethereum/merkle_patricia_trie.py — root() :478-504, _prepare_data
 * :407-448, patricialize :507-581, encode_internal_node :213-249,
 * nibble_list_to_compact :360-392, bytes_to_nibble_list :395-404 — with
 * exactly these substitutions (§6) and no other change:
 *   (1) node digest keccak256 -> SHA3-512 (64 bytes) wherever the reference
 *       hashes a node (:249, :501);
 *   (2) inline threshold: a node whose RLP is < 64 bytes is embedded in its
 *       parent (reference: < 32, :246); the same constant replaces the 32
 *       in root() :500 — under either branch of root() the result is then
 *       SHA3-512(RLP(root node)), which is what this code computes;
 *   (3) secure key = SHA3-512(raw key) -> a 64-byte path of 128 nibbles
 *       (reference: keccak256, :441-445);
 *   (4) empty root = SHA3-512(RLP(b"")) = SHA3-512(0x80) (reference
 *       EMPTY_TRIE_ROOT :71-75 is keccak256 of the same byte);
 *   (5) leaf values are opaque, non-empty bytes supplied by the caller (the
 *       account leaf RLP is built by the caller; encode_node :266-267 stores
 *       Bytes unchanged).
 *
 * WHAT IS OURS (not the reference's): the incremental persistent update
 * algorithm. Its correctness claim is design invariant I4: the root after
 * any sequence of updates equals the reference root of the resulting key
 * set (checked by trie/test_trie.c against trie/trie_oracle.py and against
 * the separate full-rebuild port trie/evm_trie_full.c).
 *
 * PATH INTERFACE: every production trie in §6 (account trie, storage tries,
 * tickets_root) is secured, so every path is exactly 128 nibbles. The
 * *_path functions take that 64-byte path directly; the keyed functions
 * hash the raw key first (substitution 3) and call them. The path entry
 * points do not change the root definition: a reference Trie with
 * secured=False over 64-byte keys builds the same structure. They exist so
 * tests can choose paths with long shared prefixes (the only way to reach
 * the 64-byte inline boundary; SHA3-512 preimages cannot be ground into
 * such prefixes).
 *
 * Consequences of fixed 128-nibble paths, used and enforced here: no key is
 * a prefix of another, so a branch never carries a value (its 17th item is
 * always b""); every branch has >= 2 children; an extension's child is
 * always a branch; a leaf's remaining key is exactly 128 - depth nibbles.
 *
 * STORE CONTRACT (evm_trie_store_t):
 *   get(ctx, digest, &rlp, &len):
 *       0  found: *rlp is a malloc()-allocated buffer of *len (> 0) bytes;
 *          ownership passes to the trie, which releases it with free().
 *       1  absent (the trie reports this as a fault, -2: a digest reachable
 *          from a committed root must exist).
 *      -2  store fault.
 *   put(ctx, digest, rlp, len):
 *       0 ok, anything else is a fault. `rlp` is owned by the trie and only
 *       valid during the call; the store copies it. A digest may be put
 *       again with identical bytes (a delete followed by a re-insert
 *       regenerates the same node); put must be idempotent.
 *   The store is keyed by digest only; it is never iterated by the trie.
 *
 * LOAD VERIFICATION (every node obtained through get, design §6 rev 3):
 *   - SHA3-512(rlp) must equal the digest it was fetched under;
 *   - the RLP must be canonical, checked operationally: the node is decoded
 *     and re-encoded, and the re-encoding must equal the stored bytes;
 *   - structural checks (ours, beyond RLP canonicality — they reject node
 *     shapes the reference's patricialize never produces for 128-nibble
 *     paths): a list of 2 or 17 items; hex-prefix flag nibble 0..3 with a
 *     zero pad nibble when even; a leaf's key = exactly the remaining
 *     nibbles, non-empty value; an extension segment >= 1 nibble leaving
 *     >= 1 nibble below it, with a branch child; a branch value b"" and >= 2
 *     children; a child reference is b"", a 64-byte string, or an embedded
 *     list whose encoding is < 64 bytes; a node reached through a 64-byte
 *     reference encodes to >= 64 bytes (the root excepted).
 *   Any failure is -2.
 *
 * ERRORS: 0 ok; 1 absent (get only); -1 invalid argument (NULL, empty
 * value where one is required); -2 fault (store fault, verification
 * failure, allocation failure, hash failure). A -2 is STICKY: the handle
 * may hold a half-applied update, so every later call on it returns -2.
 * Close it and reopen at the last committed root.
 *
 * COST: set/delete/get touch only the nodes on one path (<= 129 nodes,
 * plus one sibling on a delete that collapses a branch); commit encodes and
 * hashes only nodes modified since the last commit. No full scan.
 *
 * DETERMINISM: no hash map, no iteration over unordered data; commit writes
 * nodes in post-order, children in nibble order 0..15.
 *
 * MEMORY: commit releases every in-memory node and keeps only the new root
 * digest; nodes are loaded again on demand. A handle is not thread-safe.
 */
#ifndef EVM_TRIE_H
#define EVM_TRIE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define EVM_TRIE_DIGEST_LEN   64   /* SHA3-512                      */
#define EVM_TRIE_PATH_LEN     64   /* bytes of a secured path       */
#define EVM_TRIE_PATH_NIBBLES 128

typedef struct {
    void *ctx;
    int (*get)(void *ctx, const uint8_t digest[64], uint8_t **rlp,
               size_t *len);
    int (*put)(void *ctx, const uint8_t digest[64], const uint8_t *rlp,
               size_t len);
} evm_trie_store_t;

typedef struct evm_trie evm_trie_t;

/** Write the empty-trie root SHA3-512(0x80) (substitution 4).
 *  @return 0 or -2 (hash failure). */
int evm_trie_empty_root(uint8_t root[EVM_TRIE_DIGEST_LEN]);

/** Open the trie committed under `root`. Nothing is loaded yet: the root
 *  node is fetched (and verified) by the first operation that needs it.
 *  The empty-root constant opens an empty trie without any store call.
 *  The store struct is copied. @return 0, -1, -2. */
int evm_trie_open(const evm_trie_store_t *store,
                  const uint8_t root[EVM_TRIE_DIGEST_LEN], evm_trie_t **out);

/** Release the handle and every uncommitted change. NULL is a no-op. */
void evm_trie_close(evm_trie_t *t);

/** Set key -> value; value_len == 0 deletes the key (absent key: no-op).
 *  The key is hashed with SHA3-512 first; any key length, including 0.
 *  @return 0, -1, -2. */
int evm_trie_set(evm_trie_t *t, const uint8_t *key, size_t key_len,
                 const uint8_t *value, size_t value_len);

/** Delete key (same as evm_trie_set with value_len 0). */
int evm_trie_delete(evm_trie_t *t, const uint8_t *key, size_t key_len);

/** Look key up. On 0, *value is a malloc()-allocated copy the caller
 *  frees with free(), *value_len > 0. @return 0 found, 1 absent, -1, -2. */
int evm_trie_get(evm_trie_t *t, const uint8_t *key, size_t key_len,
                 uint8_t **value, size_t *value_len);

/** Path-level forms of set / get: `path` is the 64-byte secured path
 *  itself (see PATH INTERFACE above). */
int evm_trie_set_path(evm_trie_t *t, const uint8_t path[EVM_TRIE_PATH_LEN],
                      const uint8_t *value, size_t value_len);
int evm_trie_get_path(evm_trie_t *t, const uint8_t path[EVM_TRIE_PATH_LEN],
                      uint8_t **value, size_t *value_len);

/** Write every node modified since the last commit (post-order) through
 *  store->put and return the new root digest. Only nodes whose encoding is
 *  >= 64 bytes are written (smaller ones live inside their parent), plus
 *  the root node always; an empty trie writes nothing and returns the
 *  empty root. On success the handle stays open at the new root.
 *  @return 0, -1, -2. */
int evm_trie_commit(evm_trie_t *t, uint8_t root[EVM_TRIE_DIGEST_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* EVM_TRIE_H */
