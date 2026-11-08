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
 *   An extension's hashed child is loaded and verified together with the
 *   extension (same checks, and it must be a branch), not when a later
 *   step reaches it: a stored extension over a leaf or another extension
 *   faults at the extension's load, on every path that reaches the
 *   extension, whether or not the path continues below it.
 *
 * RLP: the node RLP is the encoding of ethereum-rlp 0.1.6 (PyPI sdist,
 * sha256 ede36f53b53c8da21f19259a676eed8790950d47f0b42cb928ac8a3c562282f3,
 * the version execution-specs a87891f7 pins in uv.lock), src/ethereum_rlp/
 * rlp.py encode :66-130, decode :143-159 and :387-543. Conformity of evm_trie_rlp.c to it is checked by test_rlp_conformity
 * against vectors from rlp_conformity_oracle.py.
 *
 * COST: set/delete/get touch only the nodes on one path (<= 129 nodes,
 * plus one sibling on a delete that collapses a branch, plus one extension
 * child: the child of an extension on the path is loaded with it); commit
 * encodes and hashes only nodes modified since the last commit. No full
 * scan.
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

/* ── HF-9 WP6: the per-node check for proofs (plan §10.1, Kurultay 55 A12 /
 *    F-24 / F-25) ─────────────────────────────────────────────────────────
 * The node-level checks of LOAD VERIFICATION above, on ONE supplied node:
 * decode at `depth` nibbles with the parent reference's expected-branch flag,
 * re-encode and compare (canonical form), the structural checks and the size
 * class. It performs NO store call and loads NO child (the Z-52 eager
 * extension-child check belongs to the store's resolve only). The digest
 * comparison (SHA3-512(rlp) == the digest it was reached under) is the
 * caller's. The existing store paths are unchanged: this reuses the same
 * decoder. */
#define EVM_TRIE_NODE_LEAF     1
#define EVM_TRIE_NODE_EXT      2
#define EVM_TRIE_NODE_BRANCH   3

#define EVM_TRIE_CHILD_NONE      0
#define EVM_TRIE_CHILD_HASH      1   /* a 64-byte reference                 */
#define EVM_TRIE_CHILD_EMBEDDED  2   /* an embedded node, encoding < 64 B   */

/** Size class of the supplied node: the root (any size), a node reached
 *  through a 64-byte reference (>= 64 bytes) or an embedded node (< 64). */
#define EVM_TRIE_NODE_ROOT      1
#define EVM_TRIE_NODE_HASHED    2
#define EVM_TRIE_NODE_EMBEDDED  3

#define EVM_TRIE_NODE_MAX_BYTES 1060 /* the largest canonical HF-9 node: a
                                      * branch of sixteen 64-byte references
                                      * (16 x 66) + the empty value (1) + the
                                      * list prefix (3) */

typedef struct {
    int            kind;                 /* EVM_TRIE_NODE_*                  */
    uint8_t        nib[EVM_TRIE_PATH_NIBBLES]; /* leaf rest / ext segment    */
    size_t         nlen;
    const uint8_t *val;                  /* leaf value, points into `rlp`    */
    size_t         val_len;
    struct {
        int            kind;             /* EVM_TRIE_CHILD_*                 */
        const uint8_t *p;                /* HASH: 64 digest bytes; EMBEDDED:
                                          * the child's encoding (into rlp)  */
        size_t         len;
    } child[16];                         /* EXT uses child[0]                */
} evm_trie_node_view_t;

/** @return 0 ok; -1 invalid argument; -2 the node fails a check. */
int evm_trie_node_check(const uint8_t *rlp, size_t len, size_t depth,
                        int expect_branch, int size_class,
                        evm_trie_node_view_t *out);

#ifdef __cplusplus
}
#endif

#endif /* EVM_TRIE_H */
