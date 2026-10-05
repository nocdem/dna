/**
 * @file evm_bench_wl.h
 * @brief Nodus EVM measurement gate — the worst-case EVM workloads, shared by
 *        the engine bench (shared/evm/bench/evm_bench.c) and the node-path
 *        bench (nodus/tests/bench/bench_evm_apply.c). MEASUREMENT TOOL
 *        ONLY: nothing here is consensus code, nothing here is linked into
 *        a node.
 *
 * Purpose: design docs/plans/2026-10-04-nodus-evm-chain-integration-design.md
 * §8 "Faz 3 kapısı" — the worst cost per gas of loop opcodes, KECCAK,
 * modexp, BLS pairing, bn254 pairing, memory and reads is MEASURED so the
 * operator can choose EVM_BLOCK_GAS_LIMIT / EVM_TX_GAS_CAP from numbers
 * (decision 2026-10-04-nodus-evm-kurultay-k2-summary.md item 3: the values
 * await the measurement gate). This module changes no placeholder.
 *
 * Every workload is ONE call transaction of a hand-assembled contract
 * (32-byte Nodus addresses, Prague opcodes) whose calldata parameters are
 * sized from the transaction's gas limit. The contract code never depends
 * on the gas limit, so the node bench deploys each code once and calls it
 * with per-transaction calldata.
 *
 * Gas schedule: execution-specs@a87891f7 src/ethereum/forks/prague/vm/
 * gas.py (cited per workload in evm_bench_wl.c) — the same pin the engine
 * ports (shared/evm/evm_gas.h).
 */
#ifndef EVM_BENCH_WL_H
#define EVM_BENCH_WL_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Workload groups (for the summary). */
enum {
    WL_GROUP_OP = 1,       /* interpreter-bound opcode loops             */
    WL_GROUP_KECCAK,       /* KECCAK256                                  */
    WL_GROUP_MEM,          /* memory expansion / MCOPY                   */
    WL_GROUP_STORAGE,      /* SSTORE / SLOAD                             */
    WL_GROUP_ACCOUNT,      /* cold account touches                       */
    WL_GROUP_CALL,         /* call depth                                 */
    WL_GROUP_CREATE,       /* CREATE / CREATE2                           */
    WL_GROUP_PRECOMPILE,   /* precompiles 0x01..0x11                     */
    WL_GROUP_LOG           /* LOG4                                       */
};

typedef struct {
    const char *name;      /* stable CLI name, e.g. "pc-blake2f-max"      */
    int         group;     /* WL_GROUP_*                                  */
    /* 1 = needs no pre-filled backend state, so the node bench can run it
     * as is; 0 = engine-only (needs accounts with code the engine bench
     * installs straight into its in-memory backend). */
    int         node_ok;
    const char *why;       /* what it does and why it is a worst case     */
    int         kind;      /* internal builder id                         */
    int         var;       /* internal variant                            */
} wl_def_t;

typedef struct {
    uint64_t gas_limit;    /* the transaction gas limit                   */
    uint64_t slot_base;    /* storage workloads: first slot touched       */
} wl_params_t;

typedef struct {
    const wl_def_t *def;
    uint8_t  *code;        /* runtime code of the workload contract       */
    size_t    code_len;
    uint8_t  *data;        /* calldata of the call                        */
    size_t    data_len;
    /* engine-bench backend prefill (the node bench pre-fills through
     * blocks or not at all): */
    uint64_t  prefill_slots;     /* contract slots [0, n) hold value 1     */
    uint64_t  prefill_accounts;  /* accounts acct_base + i, balance 1      */
    size_t    prefill_code_len;  /* zero-byte code of each such account    */
    uint8_t   acct_base[32];
    /* precompile workloads: */
    uint8_t   pc_addr;           /* 0x01..0x11; 0 = not a precompile one   */
    uint64_t  pc_cost;           /* EXACT gas of one call: measured once by
                                  * evm_precompile_run on the full input,
                                  * which also proves the input valid      */
    size_t    pc_input_len;      /* bytes per call                         */
    uint64_t  pc_k;              /* points / pairs / units per call        */
    /* gas a loop may legitimately leave unused (one iteration's guard);
     * the drivers flag a run that used less than gas_limit - slack. */
    uint64_t  slack;
} wl_inst_t;

/** Number of workloads, and the i-th (0-based). */
size_t          wl_count(void);
const wl_def_t *wl_get(size_t i);
/** By name; NULL when unknown. */
const wl_def_t *wl_find(const char *name);

/**
 * Build one instance at `p->gas_limit`. Precompile workloads size their
 * input to the gas (k points / rounds / modulus length) and run the
 * precompile ONCE through evm_precompile_run (untimed) to take its exact
 * cost and to prove the input valid.
 * @return 0; -1 the workload does not fit this gas limit (msg says why);
 *         -2 fault (allocation, or the precompile refused the input —
 *         msg says which).
 */
int  wl_build(const wl_def_t *d, const wl_params_t *p, wl_inst_t *out,
              char *msg, size_t msg_cap);
void wl_inst_free(wl_inst_t *w);

/** Storage workloads: rewrite the start slot in the calldata (word 1). */
void wl_set_slot_base(wl_inst_t *w, uint64_t slot_base);

/** Intrinsic gas of a 32-byte-address CALL tx with this calldata
 *  (21 000 + 4 per zero byte + 16 per non-zero byte, gas.py
 *  calculate_intrinsic_cost; no access list). */
uint64_t wl_intrinsic(const uint8_t *data, size_t len);

/** Prague memory expansion cost of `bytes` (gas.py:247
 *  calculate_memory_gas_cost: 3 * words + words^2 // 512). */
uint64_t wl_mem_cost(uint64_t bytes);

/**
 * Initcode that deploys `rt` (any length <= 65535):
 *   PUSH2 len PUSH1 14 PUSH1 0 CODECOPY PUSH2 len PUSH1 0 RETURN ‖ rt
 * (environment.py:268 codecopy pops memory_start, code_start, size;
 * system.py:237 return_ pops start, size). Caller frees *out.
 * @return 0 / -2.
 */
int  wl_initcode(const uint8_t *rt, size_t rl, uint8_t **out, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* EVM_BENCH_WL_H */
