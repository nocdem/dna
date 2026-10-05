/**
 * @file evm.h
 * @brief Nodus EVM execution engine — public API (Nodus EVM phase 1).
 *
 * Design: /opt/dna/docs/plans/2026-10-04-nodus-evm-engine-design.md (local).
 * Reference (pinned): ethereum/execution-specs @a87891f7, fork Prague
 * (src/ethereum/forks/prague/). Conformance: execution-spec-tests v5.4.0
 * fixtures_stable, Prague state tests, with the documented exclusions.
 *
 * SHAPE
 *   - The engine never touches storage directly. Committed state is PULLED
 *     through an evm_backend_t (read-only callbacks); every write goes into
 *     an engine-owned journaled overlay (evm_state_t). After execution the
 *     caller reads the overlay's canonical, totally ordered change set.
 *   - One overlay may carry several transactions in sequence (a block); the
 *     backend is never written by the engine.
 *   - Address width is a configuration value: 20 (Ethereum) or 32 (Nodus).
 *     Addresses are always held as 32 bytes, value right-aligned (the stack
 *     word form); in 20-byte mode bytes 0..11 are zero.
 *
 * RETURN CONVENTION (whole API)
 *    0  success / a deterministic outcome was produced
 *   -1  deterministic refusal (invalid input/transaction) — same on every node
 *   -2  NODE FAULT (allocation failure, backend read failure, broken
 *       invariant) — never converted into an outcome; the caller aborts.
 *   -3  EVM_BUDGET: the backend refused a read with its deterministic
 *       host-work verdict (chain integration design §3). Inside execution
 *       it is not returned: it ends the whole transaction as an applied
 *       failure (status EVM_EXEC_BUDGET). It is returned only when nothing
 *       could be applied (see evm_tx_apply / evm_tx_prevalidate).
 */
#ifndef EVM_H
#define EVM_H

#include <stdint.h>
#include <stddef.h>
#include "evm_u256.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── basic types ──────────────────────────────────────────────────── */
typedef struct { uint8_t b[32]; } evm_bytes32;   /* big-endian word        */
typedef evm_bytes32 evm_addr;                     /* right-aligned address  */

typedef enum {
    EVM_FORK_PRAGUE = 1
} evm_fork_t;

/* Return code of a backend callback (and of the API, see above). */
#define EVM_BUDGET (-3)

/* ── resource limits (Prague values; design §4 D6) ─────────────────── */
#define EVM_STACK_LIMIT          1024
#define EVM_CALL_DEPTH_LIMIT     1024
#define EVM_MAX_CODE_SIZE        24576u          /* EIP-170              */
#define EVM_MAX_INITCODE_SIZE    49152u          /* EIP-3860             */

/* ── configuration ────────────────────────────────────────────────── */
typedef struct {
    evm_fork_t fork;            /* EVM_FORK_PRAGUE                         */
    uint8_t    addr_bytes;      /* 20 (Ethereum) or 32 (Nodus)             */
    /* CHAINID opcode value and tx chain-id checks. A full 256-bit word:
     * Nodus chain ids are 32 bytes and are NEVER truncated (Kurultay
     * nodus-evm-k1, Astra Q2i.4); Ethereum fixtures carry small values. */
    evm_u256   chain_id;
    /* Precompile set as CONFIGURATION (red-team round 1): bit k (k = 1..17)
     * set = address k is a precompile — warmed at tx start (EIP-2929) and
     * dispatched to its implementation; bit clear = address k is an
     * ordinary account. Bit 0 and bits 18..31 must be zero (evm_state_new
     * returns NULL otherwise). Prague = bits 1..17 = EVM_PRECOMPILES_PRAGUE.
     * Every precompile is built in; a library that cannot initialise is a
     * node fault (-2), never an EVM-visible outcome. */
    uint32_t   precompile_mask;
    /* ── Nodus profile (chain integration design §5, §10). All fields
     * below are ignored when nodus_profile == 0 (Ethereum behaviour,
     * the official conformance run); a zeroed config is Ethereum. ── */
    /* 0 = Ethereum (default), 1 = Nodus. Any other value: evm_state_new
     * returns NULL. In the Nodus profile the caller supplies
     * env->base_fee = 0 and tx gas prices 0 (design §10); the engine
     * applies no extra fee rule of its own. */
    int        nodus_profile;
    /* The ticket system address (design §5, EVM_WITHDRAW_ADDR). Warm at
     * tx start like the precompiles, code-less. Only a CALL (not
     * CALLCODE / DELEGATECALL / STATICCALL) carrying value > 0 with
     * value % ticket_unit == 0 and exactly 64 bytes of calldata (the
     * destination fingerprint) creates a ticket: ticket_gas is charged
     * from the gas forwarded to that frame, the value is DEBITED from the
     * caller and credited to nobody (it leaves wei_live for wei_tickets),
     * and the frame returns the 64-byte ticket_id (evm_ticket_t). Any
     * other call into it is an exceptional halt of the called frame (the
     * forwarded gas is consumed, no value moves) — including a CALL whose
     * caller lacks the value (an ordinary CALL would return 0 and refund
     * the gas instead). A top-level tx to this address follows the same
     * rule. Value that reaches the address by other means (SELFDESTRUCT
     * beneficiary) lands in its ordinary account balance and is locked
     * there forever: nothing can spend from it. Must not be a numeric
     * precompile address and, in 20-byte mode, must be canonical
     * (bytes 0..11 zero); evm_state_new returns NULL otherwise. */
    evm_addr   ticket_addr;
    /* q: ticket value granularity in wei (Nodus: 10^10). Must be non-zero
     * in the Nodus profile. */
    evm_u256   ticket_unit;
    /* Gas charged for creating one ticket (design §5: 25000; the node
     * passes NODUS_RT_EVM_TICKET_GAS), on top of the CALL opcode's own
     * costs — which for this target are access + CALL_VALUE only (see
     * the deviation list below). */
    uint64_t   ticket_gas;
    /* NODUS PROFILE DEVIATIONS from Prague (execution-specs@a87891f7),
     * each applied only when nodus_profile == 1:
     *   - ticket_addr: a CALL into it runs the ticket hook instead of a
     *     message call (above; evm_interp.c ticket_frame).
     *   - ticket_addr: a CALL with value into it is NOT charged the
     *     NEW_ACCOUNT surcharge of system.py:call, whether or not the
     *     address is alive (evm_interp.c op_call_family; Kurultay
     *     2026-10-05 red-team 1, F12). A ticket CALL therefore costs
     *     access (warm) + CALL_VALUE + memory, plus ticket_gas taken
     *     from the forwarded gas — the same on every node regardless of
     *     the ticket address's balance. SELFDESTRUCT to that address
     *     keeps the reference NEW_ACCOUNT rule. */
} evm_config_t;

#define EVM_PRECOMPILES_PRAGUE   0x0003FFFEu     /* bits 1..17          */

/* ── backend: committed state, read-only, pulled on demand ────────── */
typedef struct {
    int         exists;         /* 0 = no account at this address          */
    uint64_t    nonce;
    evm_u256    balance;
    evm_bytes32 code_hash;      /* keccak256(code); keccak256("") if none  */
    uint32_t    code_size;
} evm_account_t;

typedef struct {
    void *ctx;
    /* Every callback below may also return EVM_BUDGET (-3): a
     * deterministic "host-work budget exhausted" verdict (chain
     * integration design §3). The engine ends the running transaction as
     * an applied failure (EVM_EXEC_BUDGET) that no inner frame can catch.
     * Any value other than 0 / -3 is a fault (-2). */
    /** @return 0 (out filled; out->exists says whether the account
     *  exists), -2 fault. */
    int (*get_account)(void *ctx, const evm_addr *addr, evm_account_t *out);
    /** Copy the account's code into buf (cap >= code_size reported by
     *  get_account). The bytes MUST be exactly the code whose keccak256
     *  is the code_hash get_account reported: the engine does not
     *  re-hash them (engine design §5 trust assumption: the backend
     *  serves correct data). A backend that cannot vouch for that —
     *  storage corruption, a digest mismatch — returns -2, never the
     *  bytes. The node backend verifies both stored digests on every
     *  read (nodus_witness_rt_evm.c be_get_code). @return 0, -2 fault. */
    int (*get_code)(void *ctx, const evm_addr *addr,
                    uint8_t *buf, size_t cap, size_t *len_out);
    /** Committed storage value (absent slot = zero). @return 0, -2. */
    int (*get_storage)(void *ctx, const evm_addr *addr,
                       const evm_bytes32 *key, evm_bytes32 *val_out);
    /** Hash of block `number` (BLOCKHASH). *available = 0 when the backend
     *  does not serve that height. @return 0, -2. */
    int (*get_block_hash)(void *ctx, uint64_t number,
                          evm_bytes32 *hash_out, int *available);
    /** *out = 1 when the committed state holds ANY non-zero storage slot
     *  for `addr`, else 0. @return 0, -2 fault (a fault is never "no
     *  storage"). Used by the EIP-7610 deployability check, which Nodus
     *  RETAINS although execution-specs commit 2ce21915 (2026-08-25)
     *  removed it upstream: with it, a CREATE never lands on — and never
     *  destroys — committed storage (an unbounded storage destroy
     *  otherwise). Prague reference: state_tracker.py account_has_storage
     *  before 2ce21915. */
    int (*has_storage)(void *ctx, const evm_addr *addr, int *out);
} evm_backend_t;

/* ── block environment ────────────────────────────────────────────── */
typedef struct {
    evm_addr    coinbase;
    uint64_t    number;
    uint64_t    timestamp;
    uint64_t    gas_limit;
    evm_u256    base_fee;            /* EIP-1559 base fee per gas          */
    evm_bytes32 prev_randao;         /* PREVRANDAO (EIP-4399)              */
    uint64_t    excess_blob_gas;     /* BLOBBASEFEE derivation (EIP-4844)  */
} evm_block_env_t;

/* ── transaction ──────────────────────────────────────────────────── */
typedef struct {
    evm_addr           addr;
    uint32_t           n_keys;
    const evm_bytes32 *keys;
} evm_access_entry_t;

typedef struct {
    uint8_t   type;                  /* 0 legacy, 1 EIP-2930, 2 EIP-1559;
                                      * 3 (blob) and 4 (set-code) are NOT
                                      * supported -> evm_tx_apply returns -1
                                      * with EVM_TXERR_TYPE_UNSUPPORTED     */
    evm_addr  sender;                /* already authenticated by the caller */
    int       is_create;
    evm_addr  to;                    /* ignored when is_create             */
    uint64_t  nonce;
    uint64_t  gas_limit;
    evm_u256  gas_price;             /* type 0/1                           */
    evm_u256  max_fee_per_gas;       /* type 2                             */
    evm_u256  max_priority_fee_per_gas; /* type 2                          */
    evm_u256  value;
    const uint8_t *data;
    size_t    data_len;
    uint32_t  n_access;
    const evm_access_entry_t *access;
    int       has_chain_id;          /* type 0 may omit (pre-EIP-155)       */
    evm_u256  chain_id;              /* compared with cfg->chain_id         */
    /* Nodus profile: the chain intent id of this transaction, the
     * global-uniqueness half of every ticket_id it creates (evm_ticket_t).
     * Ignored (keep zero) in the Ethereum profile. */
    uint8_t   intent_id[64];
} evm_tx_t;

/** Why a transaction was refused (-1 from evm_tx_apply). */
typedef enum {
    EVM_TXERR_NONE = 0,
    EVM_TXERR_TYPE_UNSUPPORTED,
    EVM_TXERR_NONCE_TOO_LOW,
    EVM_TXERR_NONCE_TOO_HIGH,
    EVM_TXERR_NONCE_MAX,             /* EIP-2681                           */
    EVM_TXERR_INSUFFICIENT_FUNDS,
    EVM_TXERR_INTRINSIC_GAS,
    EVM_TXERR_GAS_ALLOWANCE,         /* gas_limit > block gas limit         */
    EVM_TXERR_FEE_CAP_BELOW_BASE,
    EVM_TXERR_PRIORITY_ABOVE_CAP,
    EVM_TXERR_SENDER_NOT_EOA,        /* EIP-3607                           */
    EVM_TXERR_INITCODE_TOO_LARGE,    /* EIP-3860                           */
    EVM_TXERR_CHAIN_ID,
    EVM_TXERR_OTHER
} evm_tx_error_t;

/** How the top-level execution ended (when the tx was applied). */
typedef enum {
    EVM_EXEC_SUCCESS = 0,
    EVM_EXEC_REVERT,
    EVM_EXEC_OUT_OF_GAS,
    EVM_EXEC_INVALID_OPCODE,
    EVM_EXEC_STACK_UNDERFLOW,
    EVM_EXEC_STACK_OVERFLOW,
    EVM_EXEC_BAD_JUMP,
    EVM_EXEC_STATIC_VIOLATION,
    EVM_EXEC_RETURNDATA_OOB,
    EVM_EXEC_CREATE_COLLISION,
    EVM_EXEC_CODE_TOO_LARGE,
    EVM_EXEC_INVALID_CODE_PREFIX,    /* EIP-3541 (0xEF)                    */
    EVM_EXEC_PRECOMPILE_FAILURE,
    EVM_EXEC_BUDGET                  /* a backend read returned EVM_BUDGET:
                                      * the whole tx failed (no frame can
                                      * catch it); every execution change
                                      * is reverted to the point after the
                                      * nonce increment and fee debit;
                                      * gas_used = gas_limit, no output,
                                      * logs, tickets; wei_destroyed = 0  */
} evm_exec_status_t;

typedef struct {
    evm_addr     addr;
    uint8_t      n_topics;           /* 0..4                                */
    evm_bytes32  topics[4];
    uint8_t     *data;               /* owned by the result                */
    size_t       data_len;
} evm_log_t;

typedef struct {
    evm_tx_error_t    tx_error;      /* set when evm_tx_apply returned -1   */
    evm_exec_status_t status;        /* set when it returned 0              */
    uint64_t          gas_used;      /* after refund (what the sender paid) */
    /* The execution WORK before the EIP-3529 refund: gas_limit − the gas
     * left when the top frame returned (used_before in evm_tx_apply).
     * Informational — no state, receipt or root reads it; the node's
     * §18 simulation budget charges it (red-team 1 F12), because a
     * refund lowers what the sender pays, not what the node ran. Set
     * when evm_tx_apply returned 0. */
    uint64_t          gas_used_pre_refund;
    evm_addr          created;       /* contract address for a create tx   */
    uint8_t          *output;        /* return / revert data, owned         */
    size_t            output_len;
    evm_log_t        *logs;          /* owned; empty unless SUCCESS         */
    size_t            n_logs;
    /* Wei that left existence in this tx (chain integration design §5,
     * rev 3): (a) at SELFDESTRUCT of an account created in this tx, its
     * balance at the moment it is zeroed (with beneficiary == itself that
     * is the value it sent to itself; otherwise 0), plus (b) the balance
     * every account still held when it was deleted (accounts_to_delete at
     * the end of the tx — value received after its SELFDESTRUCT; EIP-161
     * removal only deletes empty accounts, so it adds 0). Journaled: a
     * reverted frame takes its part back. Set when evm_tx_apply returned
     * 0. Nodus profile: overflow past 2^256 is a fault (-2); Ethereum
     * profile: saturates at 2^256 - 1 (fixtures may hold several balances
     * near 2^256; conformance behaviour must not change). */
    evm_u256          wei_destroyed;
    /* Tickets created by this tx, in creation order (Nodus profile only;
     * empty unless SUCCESS). Owned; freed by evm_tx_result_free. */
    size_t            n_tickets;
    struct evm_ticket *tickets;
} evm_tx_result_t;

/* One withdrawal ticket (chain integration design §5).
 *   ticket_id = SHA3-512("NDS.EVMTKT.v1\0\0\0" (16 bytes) ||
 *                        tx->intent_id (64 bytes) || seq (u32 big-endian))
 * where seq is the ticket's index among the tickets that exist at the
 * moment it is created (a ticket dropped by a reverted frame frees its
 * index), so the surviving tickets of a tx are numbered 0..n-1 in
 * creation order. */
typedef struct evm_ticket {
    uint8_t  ticket_id[64];
    evm_u256 amount_wei;             /* the CALL value (multiple of q)      */
    uint8_t  dest_fp[64];            /* the CALL's 64 bytes of calldata     */
} evm_ticket_t;

void evm_tx_result_free(evm_tx_result_t *r);

/* ── overlay state ────────────────────────────────────────────────── */
typedef struct evm_state evm_state_t;

/** @return NULL on allocation failure (fault). Borrowed pointers must
 *  outlive the state. */
evm_state_t *evm_state_new(const evm_config_t *cfg, const evm_backend_t *be);
void         evm_state_free(evm_state_t *st);

/**
 * Apply one transaction on top of the overlay (Ethereum Prague state
 * transition: validity checks, intrinsic gas incl. EIP-7623 floor, fee
 * debit, value transfer, execution, refunds, coinbase priority fee).
 * @return 0 applied (res->status says how execution ended — including
 *         EVM_EXEC_BUDGET; the overlay holds the post-state), -1
 *         transaction refused (res->tx_error; the overlay is unchanged),
 *         -2 fault (overlay must be discarded), -3 EVM_BUDGET only when the
 *         backend refused a read that the engine needs BEFORE anything can
 *         be applied (the validity checks, the sender load for the nonce
 *         increment / fee debit) or while writing the tail of ANY outcome
 *         (refund, coinbase credit, end-of-tx deletions): nothing is
 *         applied and the overlay's change set is unchanged.
 */
int evm_tx_apply(evm_state_t *st, const evm_block_env_t *env,
                 const evm_tx_t *tx, evm_tx_result_t *res);

/**
 * Pre-validation for mempool recheck (chain integration design §4, §8):
 * runs exactly the validity checks evm_tx_apply runs before execution —
 * the same function — and nothing else. Reads through non-mutating peeks:
 * the overlay is left byte-identical (no record inserted, no cache
 * filled, no journal entry).
 * @return 0 valid, -1 refused (res->tx_error), -2 fault, -3 EVM_BUDGET
 *         (a backend read was refused). res holds no owned memory after
 *         the call (evm_tx_result_free is harmless).
 */
int evm_tx_prevalidate(evm_state_t *st, const evm_block_env_t *env,
                       const evm_tx_t *tx, evm_tx_result_t *res);

/* ── canonical change set ─────────────────────────────────────────── */
typedef struct {
    evm_addr     addr;
    int          deleted;            /* account removed (SELFDESTRUCT in its
                                      * creation tx / EIP-161 cleanup)      */
    uint64_t     nonce;
    evm_u256     balance;
    int          code_changed;       /* code below is the full new code     */
    const uint8_t *code;
    size_t       code_len;
    evm_bytes32  code_hash;
    int          storage_cleared;    /* all committed storage is dropped    */
} evm_account_change_t;

typedef struct {
    /** Called once per touched account, in strictly ascending address
     *  order. @return 0 continue, non-zero abort (passed back). */
    int (*account)(void *ctx, const evm_account_change_t *c);
    /** Called for every storage slot whose value differs from the
     *  committed value, ascending by key, after its account's callback.
     *  A zero value means the slot is deleted. */
    int (*storage)(void *ctx, const evm_addr *addr, const evm_bytes32 *key,
                   const evm_bytes32 *value);
    void *ctx;
} evm_change_visitor_t;

/** Walk the overlay's change set (relative to the backend). Order is total
 *  and independent of insertion/hashing (design §4 D3). @return 0, the
 *  visitor's non-zero value, or -2 fault. The walk may read the backend
 *  (pre-state of a slot or account the overlay never loaded); ANY
 *  non-zero backend answer there, EVM_BUDGET included, is -2: the change
 *  set of an applied transaction must always be producible. */
int evm_state_visit_changes(const evm_state_t *st,
                            const evm_change_visitor_t *v);

#ifdef __cplusplus
}
#endif

#endif /* EVM_H */
