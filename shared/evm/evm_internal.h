/**
 * @file evm_internal.h
 * @brief Private interfaces shared by the Nodus EVM engine translation units
 *        (evm_state.c, evm_interp.c, evm_tx.c, evm_precompile.c).
 *
 * Not part of the API contract (evm.h). Every function here follows the
 * engine-wide return convention: 0 success, -1 deterministic refusal,
 * -2 node fault (allocation failure, backend failure, broken invariant),
 * -3 EVM_BUDGET (a backend read was refused; propagated with EVM_CHECK and
 * recorded in evm_state.budget_hit).
 *
 * State model (port of execution-specs@a87891f7 prague/state_tracker.py):
 *   backend (PreState)  <-  block layer (BlockState)  <-  tx layer
 *   (TransactionState). Reads walk tx -> block -> backend exactly as the
 *   reference's get_account_optional / get_storage do. Only the tx layer is
 *   journaled; a journal mark replaces the reference's copy_tx_state()
 *   snapshot and evm_st_revert() replaces restore_tx_state().
 */
#ifndef EVM_INTERNAL_H
#define EVM_INTERNAL_H

#include <stdint.h>
#include <stddef.h>
#include "evm.h"
#include "evm_u256.h"
#include "crypto/hash/keccak256.h"

#define EVM_FAULT (-2)

/* Propagate the result of a call that may reach the backend: EVM_BUDGET
 * (-3, evm.h) passes through unchanged, every other non-zero value is a
 * fault. Calls that cannot reach the backend (allocation, bounds) keep
 * `return EVM_FAULT`. The per-tx flag evm_state.budget_hit (set at the
 * backend boundary) is what evm_tx_apply trusts; this macro keeps the
 * return value honest along the way. */
#define EVM_CHECK(x) do { int rc_ = (x); \
        if (rc_ != 0) return rc_ == EVM_BUDGET ? EVM_BUDGET : EVM_FAULT; \
    } while (0)

/* keccak256("") — ethereum/state.py EMPTY_CODE_HASH */
extern const evm_bytes32 evm_empty_code_hash;

/* An account value (ethereum/state.py Account: nonce, balance, code_hash).
 * `code` is a borrowed pointer owned by the state (code arena or backend
 * code cache). code == NULL with a non-empty code_hash means "the backend
 * code of the SAME address" — an account's code can only change through
 * set_code(), which always attaches a blob (DEVIATION: the reference keys
 * code by hash; our backend serves code by address, evm.h get_code). */
typedef struct {
    uint64_t    nonce;
    evm_u256    balance;
    evm_bytes32 code_hash;
    const uint8_t *code;
    size_t      code_len;
} evm_acct_t;

typedef struct evm_avl_node {
    struct evm_avl_node *l, *r;
    int h;
    uint8_t key[32];
} evm_avl_node;

typedef struct evm_slot_rec evm_slot_rec;
typedef struct evm_addr_rec evm_addr_rec;

struct evm_slot_rec {
    evm_avl_node node;               /* key = storage key (bytes32)        */
    /* backend cache */
    uint8_t  pre_loaded;
    evm_u256 pre;
    /* block layer: BlockState.storage_writes[addr][key] */
    uint8_t  blk_has;
    evm_u256 blk;
    /* tx layer — valid only while tx_epoch == state epoch */
    uint64_t tx_epoch;
    uint8_t  tx_present;             /* TransactionState.storage_writes    */
    uint8_t  tx_warm;                /* (addr,key) in accessed_storage_keys */
    uint64_t tx_gen;                 /* written under this clear generation */
    evm_u256 tx_val;
    evm_u256 tx_transient;           /* TransactionState.transient_storage */
};

struct evm_addr_rec {
    evm_avl_node node;               /* key = 32-byte address              */
    /* backend cache */
    uint8_t  pre_loaded;
    uint8_t  pre_exists;
    uint8_t  pre_code_loaded;
    evm_acct_t pre;
    uint32_t pre_code_size;
    uint8_t *pre_code;               /* owned                               */
    uint8_t  pre_storage_loaded;     /* backend has_storage cached (EIP-7610) */
    uint8_t  pre_has_storage;
    /* block layer */
    uint8_t  blk_has_acct;           /* addr in BlockState.account_writes   */
    uint8_t  blk_acct_none;          /* ... and the value is None           */
    uint8_t  blk_cleared;            /* addr in BlockState.storage_clears   */
    uint64_t blk_nwrites;            /* |BlockState.storage_writes[addr]|   */
    evm_acct_t blk;
    /* tx layer — valid only while tx_epoch == state epoch */
    uint64_t tx_epoch;
    uint8_t  tx_has_acct;
    uint8_t  tx_acct_none;
    uint8_t  tx_cleared;             /* addr in TransactionState.storage_clears */
    uint8_t  tx_created;             /* created_accounts (NOT journaled)    */
    uint8_t  tx_warm;                /* addr in accessed_addresses          */
    uint8_t  tx_to_delete;           /* addr in accounts_to_delete          */
    uint64_t tx_gen;                 /* current clear generation            */
    uint64_t tx_nwrites;             /* |TransactionState.storage_writes[addr]|
                                      * (visible persistent writes; journaled) */
    evm_acct_t tx;
    evm_slot_rec **tx_slots;         /* slots whose tx part is current      */
    size_t   n_tx_slots, cap_tx_slots;
    evm_avl_node *slots;             /* slot tree                           */
};

typedef struct {
    uint8_t  kind;
    uint8_t  f0, f1;
    evm_addr_rec *a;
    evm_slot_rec *s;
    uint64_t g;
    uint64_t c;                      /* old tx_nwrites (J_STORE, J_CLEAR)   */
    evm_acct_t acct;
    evm_u256 v;
} evm_journal_entry;

/* Jump-destination bitmap cached per code hash (evm_interp.c). */
typedef struct {
    evm_avl_node node;               /* key = keccak256(code)               */
    size_t   code_len;
    uint8_t *bitmap;                 /* owned; NULL when code_len == 0      */
} evm_jd_rec;

typedef struct evm_code_blob {
    struct evm_code_blob *next;
    size_t len;
    uint8_t data[];
} evm_code_blob;

struct evm_state {
    evm_config_t        cfg;
    const evm_backend_t *be;
    evm_avl_node       *root;        /* address tree                        */
    uint64_t            epoch;       /* current transaction epoch (>= 1)    */
    uint64_t            gen_counter; /* monotonic storage-clear generation  */
    evm_journal_entry  *j;
    size_t              nj, capj;
    evm_log_t          *logs;        /* logs of the running tx              */
    size_t              nlogs, caplogs;
    evm_addr_rec      **tx_touched;  /* address records with a current tx part */
    size_t              n_touched, cap_touched;
    evm_code_blob      *arena;
    uint64_t            block_gas_used;
    evm_avl_node       *jd_root;     /* evm_jd_rec tree; lives with the state.
                                      * Results never depend on it: a miss
                                      * recomputes the identical bitmap.   */
    /* Sticky per tx: a backend callback answered EVM_BUDGET. Set only at
     * the backend boundary (evm_state.c be_* wrappers), never cleared by
     * a frame revert — that is what makes BUDGET uncatchable. Reset at
     * the start of evm_tx_apply. */
    int                 budget_hit;
    /* evm_tx_result_t.wei_destroyed of the running tx (journaled:
     * J_WEI_DESTROYED). */
    evm_u256            wei_destroyed;
    /* Tickets of the running tx (Nodus profile; journaled: J_TICKET). */
    evm_ticket_t       *tickets;
    size_t              ntickets, captickets;
};

/** Grow a vector to hold one more element: new capacity = cap ? 2*cap :
 *  init, computed with checked arithmetic against SIZE_MAX. On any
 *  overflow or allocation failure returns -2 and leaves *p / *cap
 *  untouched (red-team round 1, fix 6). */
int evm_grow(void **p, size_t *cap, size_t elem, size_t init);

/** count * elem without overflow: @return 0 and *out, or -2. */
static inline int evm_size_mul(size_t count, size_t elem, size_t *out)
{
    if (elem != 0 && count > SIZE_MAX / elem) return -2;
    *out = count * elem;
    return 0;
}

/* ── address helpers ─────────────────────────────────────────────────── */
/** Stack word -> address: low addr_bytes bytes (prague/utils/address.py
 *  to_address_masked in 20-byte mode; the full word in 32-byte mode). */
void evm_addr_from_word(const evm_state_t *st, const evm_u256 *w, evm_addr *out);
void evm_addr_to_word(const evm_addr *a, evm_u256 *out);
/** Address k (1..17, right-aligned) is a precompile in THIS configuration:
 *  bit k of cfg.precompile_mask is set (evm.h). */
int  evm_precompile_enabled(const evm_state_t *st, const evm_addr *a);
/** 1..0x11 right-aligned (prague/vm/precompiled_contracts/mapping.py) —
 *  numeric range only; consensus decisions use evm_precompile_enabled. */
int  evm_is_precompile(const evm_addr *a);
int  evm_acct_is_empty(const evm_acct_t *a);
void evm_acct_empty(evm_acct_t *a);

/* ── state reads (prague/state_tracker.py) ────────────────────────────── */
int evm_st_get_account_optional(evm_state_t *st, const evm_addr *addr,
                                int *exists, evm_acct_t *out);
int evm_st_get_account(evm_state_t *st, const evm_addr *addr, evm_acct_t *out);
/** Code of the account `acct` read at `addr`. */
int evm_st_get_code(evm_state_t *st, const evm_addr *addr,
                    const evm_acct_t *acct, const uint8_t **code, size_t *len);
int evm_st_get_storage(evm_state_t *st, const evm_addr *addr,
                       const evm_bytes32 *key, evm_u256 *out);
int evm_st_get_storage_original(evm_state_t *st, const evm_addr *addr,
                                const evm_bytes32 *key, evm_u256 *out);
int evm_st_get_transient(evm_state_t *st, const evm_addr *addr,
                         const evm_bytes32 *key, evm_u256 *out);
int evm_st_account_exists(evm_state_t *st, const evm_addr *addr, int *out);
int evm_st_account_deployable(evm_state_t *st, const evm_addr *addr, int *out);
int evm_st_is_account_alive(evm_state_t *st, const evm_addr *addr, int *out);
int evm_st_is_created(evm_state_t *st, const evm_addr *addr, int *out);

/* ── state writes (journaled on the tx layer) ─────────────────────────── */
int evm_st_set_account(evm_state_t *st, const evm_addr *addr,
                       const evm_acct_t *acct /* NULL = None */);
int evm_st_set_storage(evm_state_t *st, const evm_addr *addr,
                       const evm_bytes32 *key, const evm_u256 *val);
int evm_st_destroy_account(evm_state_t *st, const evm_addr *addr);
int evm_st_destroy_storage(evm_state_t *st, const evm_addr *addr);
int evm_st_mark_account_created(evm_state_t *st, const evm_addr *addr);
int evm_st_set_transient(evm_state_t *st, const evm_addr *addr,
                         const evm_bytes32 *key, const evm_u256 *val);
int evm_st_move_ether(evm_state_t *st, const evm_addr *from,
                      const evm_addr *to, const evm_u256 *amount);
int evm_st_create_ether(evm_state_t *st, const evm_addr *addr,
                        const evm_u256 *amount);
int evm_st_set_balance(evm_state_t *st, const evm_addr *addr,
                       const evm_u256 *amount);
int evm_st_increment_nonce(evm_state_t *st, const evm_addr *addr);
int evm_st_set_code(evm_state_t *st, const evm_addr *addr,
                    const uint8_t *code, size_t len);

/* ── per-tx sets (accessed_addresses / accessed_storage_keys,
 *    accounts_to_delete, logs) — journaled ─────────────────────────────── */
/** If addr is warm: *was_warm = 1. Else add it (journaled), *was_warm = 0. */
int evm_st_access_addr(evm_state_t *st, const evm_addr *addr, int *was_warm);
int evm_st_access_slot(evm_state_t *st, const evm_addr *addr,
                       const evm_bytes32 *key, int *was_warm);
int evm_st_add_to_delete(evm_state_t *st, const evm_addr *addr);
/** Appends a log (copies data). */
int evm_st_add_log(evm_state_t *st, const evm_addr *addr,
                   const evm_bytes32 *topics, unsigned n_topics,
                   const uint8_t *data, size_t len);
/** wei_destroyed += amount (journaled). Overflow: -2 in the Nodus
 *  profile, saturation in the Ethereum profile (evm.h). */
int evm_st_add_destroyed(evm_state_t *st, const evm_u256 *amount);
/** Append a ticket (journaled; seq = number of live tickets, evm.h
 *  evm_ticket_t). Computes ticket_id from intent_id. @return 0, -2. */
int evm_st_add_ticket(evm_state_t *st, const uint8_t intent_id[64],
                      const evm_u256 *amount, const uint8_t dest_fp[64]);

/* ── backend access that is not an account/storage read ──────────────── */
/** BLOCKHASH through the backend (0, -2, or -3 with budget_hit set). */
int evm_st_block_hash(evm_state_t *st, uint64_t number, evm_bytes32 *hash,
                      int *available);

/* ── journal ──────────────────────────────────────────────────────────── */
size_t evm_st_mark(const evm_state_t *st);
void   evm_st_revert(evm_state_t *st, size_t mark);

/* ── transaction lifecycle ────────────────────────────────────────────── */
/** Destroy every account flagged in accounts_to_delete (process_transaction
 *  tail). */
int  evm_st_destroy_marked(evm_state_t *st);
/** incorporate_tx_into_block(): merge the tx layer into the block layer and
 *  start a new tx epoch. The journal and the log list are emptied (logs are
 *  freed unless the caller took them). */
int  evm_st_commit_tx(evm_state_t *st);
/** Drop the logs collected in the running tx (frees their data). */
void evm_st_clear_logs(evm_state_t *st);
/** Abandon the running tx without applying anything: undo the whole
 *  journal, drop logs and tickets, and start a new tx epoch so every tx
 *  part becomes stale (the change set equals the one before the tx).
 *  Backend caches stay filled (not part of the change set).
 *  @return 0, -2. */
int  evm_st_abort_tx(evm_state_t *st);

/* ── code arena ───────────────────────────────────────────────────────── */
int evm_st_store_code(evm_state_t *st, const uint8_t *code, size_t len,
                      const uint8_t **out);

/* ── jump-destination cache ───────────────────────────────────────────── */
/** Cached bitmap for code with this hash, or NULL. */
const evm_jd_rec *evm_st_jd_find(const evm_state_t *st, const evm_bytes32 *hash);
/** Insert (takes ownership of bitmap, even on failure). @return 0, -2. */
int evm_st_jd_store(evm_state_t *st, const evm_bytes32 *hash, size_t code_len,
                    uint8_t *bitmap, const evm_jd_rec **out);

/* ── non-mutating reads for transaction refusal (red-team fix 5) ───────
 * Same answer as the evm_st_get_* readers, but they never insert a record
 * and never fill a cache: after a refusal the overlay is byte-identical. */
int evm_st_peek_account(const evm_state_t *st, const evm_addr *addr,
                        int *exists, evm_acct_t *out);
/** *is_del = the code of `acct` (read at `addr`) is a valid EIP-7702
 *  designator (eoa_delegation.py:is_valid_delegation). */
int evm_st_peek_is_delegation(const evm_state_t *st, const evm_addr *addr,
                              const evm_acct_t *acct, int *is_del);

/* ── interpreter (evm_interp.c) ───────────────────────────────────────── */
typedef struct {
    const evm_block_env_t *env;
    evm_addr  origin;
    evm_u256  gas_price;             /* effective gas price                 */
    int       blob_fee_done;         /* BLOBBASEFEE computed lazily         */
    int       blob_fee_fault;
    evm_u256  blob_fee;
    const uint8_t *intent_id;        /* evm_tx_t.intent_id (64 bytes)       */
} evm_tx_env_t;

typedef struct {
    evm_addr  caller;
    int       is_create;             /* message.target == Bytes0           */
    evm_addr  target;                /* current_target                      */
    evm_addr  code_address;          /* valid when !is_create               */
    uint64_t  gas;
    evm_u256  value;
    const uint8_t *data;  size_t data_len;
    const uint8_t *code;  size_t code_len;
    int       has_code_hash;         /* code came from an account          */
    evm_bytes32 code_hash;           /* (jump-destination cache key)       */
} evm_message_t;

typedef struct {
    uint64_t  gas_left;
    int64_t   refund_counter;
    evm_exec_status_t status;        /* SUCCESS when no error               */
    uint8_t  *output;                /* owned by the caller after return    */
    size_t    output_len;
} evm_call_output_t;

/** prague/vm/interpreter.py:process_message_call (top level, depth 0).
 *  @return 0 (out filled), -2 fault. */
int evm_process_message_call(evm_state_t *st, evm_tx_env_t *txenv,
                             evm_message_t *msg, evm_call_output_t *out);

/** prague/utils/address.py:compute_contract_address (width-parametric). */
int evm_compute_contract_address(const evm_state_t *st, const evm_addr *sender,
                                 uint64_t nonce, evm_addr *out);

/* ── precompiles (evm_precompile.c) ───────────────────────────────────── */
typedef enum {
    EVM_PC_OK = 0,                   /* output set                          */
    EVM_PC_OOG,                      /* OutOfGasError                       */
    EVM_PC_INVALID                   /* InvalidParameter / other halt       */
} evm_pc_result_t;

/** Run the precompile at `addr` (evm_is_precompile(addr) must hold).
 *  *gas_left is charged per the reference. *out (malloc'd, may be NULL when
 *  *out_len == 0) is owned by the caller. @return 0 (*res set) or -2. */
int evm_precompile_run(const evm_addr *addr, const uint8_t *data, size_t len,
                       uint64_t *gas_left, evm_pc_result_t *res,
                       uint8_t **out, size_t *out_len);

/* ── 64-bit saturating gas arithmetic (evm_interp.c) ──────────────────── */
#define EVM_GAS_SAT UINT64_MAX
static inline uint64_t evm_gas_add(uint64_t a, uint64_t b)
{
    return (a > EVM_GAS_SAT - b) ? EVM_GAS_SAT : a + b;
}
static inline uint64_t evm_gas_mul(uint64_t a, uint64_t b)
{
    if (a == 0 || b == 0) return 0;
    return (a > EVM_GAS_SAT / b) ? EVM_GAS_SAT : a * b;
}
/** Portable 64x64 -> 128-bit multiply (design §4 D2: no __int128). */
static inline void evm_mul64(uint64_t a, uint64_t b, uint64_t *hi, uint64_t *lo)
{
    uint64_t al = a & 0xffffffffu, ah = a >> 32;
    uint64_t bl = b & 0xffffffffu, bh = b >> 32;
    uint64_t ll = al * bl, lh = al * bh, hl = ah * bl, hh = ah * bh;
    uint64_t mid = (ll >> 32) + (lh & 0xffffffffu) + (hl & 0xffffffffu);
    *lo = (ll & 0xffffffffu) | (mid << 32);
    *hi = hh + (lh >> 32) + (hl >> 32) + (mid >> 32);
}
/** ceil32(n) / 32 for a 64-bit n (no overflow). */
static inline uint64_t evm_words(uint64_t n)
{
    return n / 32u + ((n % 32u) != 0);
}

/** keccak256 that never hands a NULL pointer to the shared implementation:
 *  shared/crypto/hash/keccak256.c:144 memcpy()s the input even when its
 *  length is 0, which is undefined behaviour for NULL (UBSan, Prague
 *  conformance run 2026-10-04). Empty code / initcode / KECCAK256 of zero
 *  bytes reach here with data == NULL. @return 0, non-zero on failure. */
static inline int evm_keccak(const uint8_t *data, size_t len, uint8_t out[32])
{
    static const uint8_t empty[1] = { 0 };
    return keccak256(len ? data : empty, len, out);
}

#endif /* EVM_INTERNAL_H */
