/**
 * @file evm_membackend.h
 * @brief In-memory account set + evm_backend_t over it — TEST-ONLY.
 *
 * Holds a state-test fixture's `pre` allocation (and, in the harness, the
 * merged post-state and the fixture's expected `post.state`). Accounts are
 * kept sorted by address and each account's storage sorted by key; lookups
 * are binary searches — no hash map, deterministic (design §4 D3).
 *
 * BLOCKHASH: the backend serves exactly one hash — block 0 — and only when
 * the fixture env carries `previousHash`. That is what the reference
 * state-test runner does (execution-specs @a87891f7
 * packages/testing/src/execution_testing/evm_tools/statetest/__init__.py:
 * 111-114 maps `previousHash` to block_hashes key "0", nothing else); see
 * the findings block at the top of statetest.c.
 *
 * Build protocol: init -> add_account (+ add_slot on the account just added;
 * the returned pointer is invalidated by the next add_account) -> finalize
 * (sorts, rejects duplicates) -> bind / lookups / state_root.
 */
#ifndef EVM_TEST_MEMBACKEND_H
#define EVM_TEST_MEMBACKEND_H

#include <stdint.h>
#include <stddef.h>
#include "evm.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    evm_bytes32 key;
    evm_bytes32 val;                 /* never zero (absent == zero)        */
} evm_mem_slot;

typedef struct {
    evm_addr      addr;
    uint64_t      nonce;
    uint8_t       balance[32];       /* big-endian                         */
    uint8_t      *code;              /* owned; NULL when code_len == 0     */
    size_t        code_len;
    evm_bytes32   code_hash;         /* keccak256(code)                    */
    evm_mem_slot *slots;             /* owned, sorted by key after finalize */
    size_t        n_slots;
    size_t        cap_slots;
} evm_mem_account;

typedef struct {
    evm_mem_account *acc;            /* sorted by addr after finalize      */
    size_t           n;
    size_t           cap;
    int              finalized;
    int              has_block0_hash;
    evm_bytes32      block0_hash;
} evm_membackend;

void evm_membackend_init(evm_membackend *mb);
void evm_membackend_free(evm_membackend *mb);

/**
 * Add an account (copies the code). `code_hash` NULL -> keccak256(code) is
 * computed; non-NULL -> taken as given (used when rebuilding a post-state
 * from the engine's change set, which reports the hash).
 * @return 0, -2 alloc; *out (optional) points at the new account until the
 *         next add_account.
 */
int evm_membackend_add_account(evm_membackend *mb, const evm_addr *addr,
                               uint64_t nonce, const uint8_t balance[32],
                               const uint8_t *code, size_t code_len,
                               const evm_bytes32 *code_hash,
                               evm_mem_account **out);

/** Add a storage slot to an account; a zero value is dropped (an absent
 *  slot is zero — state_mpt.py set_storage / trie_set default).
 *  @return 0, -2 alloc. */
int evm_mem_account_add_slot(evm_mem_account *a, const evm_bytes32 *key,
                             const evm_bytes32 *val);

/** Sort accounts and slots. @return 0, -1 duplicate address or slot key. */
int evm_membackend_finalize(evm_membackend *mb);

const evm_mem_account *evm_membackend_find(const evm_membackend *mb,
                                           const evm_addr *addr);
/** @return the slot value or NULL when absent (= zero). */
const evm_bytes32 *evm_mem_account_find_slot(const evm_mem_account *a,
                                             const evm_bytes32 *key);

/** Fill `be` with callbacks reading this (finalized) set. */
void evm_membackend_bind(const evm_membackend *mb, evm_backend_t *be);

/**
 * State root of this (finalized) account set (state_mpt.py:82-120):
 * state trie (secured) of key = the low `addr_bytes` bytes of the address
 * word, value = rlp([nonce, balance, storage_root, code_hash])
 * (merkle_patricia_trie.py:193-210); storage_root = secured trie of
 * key = 32-byte slot, value = rlp(uint) (merkle_patricia_trie.py:252-269),
 * or EMPTY_TRIE_ROOT when the account has no non-zero slot.
 * @return 0, -1 (addr_bytes not 20/32), -2 alloc.
 */
int evm_membackend_state_root(const evm_membackend *mb, unsigned addr_bytes,
                              uint8_t root[32]);

#ifdef __cplusplus
}
#endif

#endif /* EVM_TEST_MEMBACKEND_H */
