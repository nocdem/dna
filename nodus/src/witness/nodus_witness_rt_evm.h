/**
 * @file nodus_witness_rt_evm.h
 * @brief Nodus EVM — the EVM domain's runtime (runtime ABI 2): call decoding,
 *        execution through the Nodus EVM engine over the engine's reader,
 *        the typed-effect stream, the storage adapter, the SHA3-512 MPT
 *        state commitment, the domain invariant and activation state.
 *
 * Design: docs/plans/2026-10-04-nodus-evm-chain-integration-design.md rev 3
 * (§1-§8, §10, §11). Decisions: docs/plans/decisions/2026-10-04-nodus-evm-
 * domain.md, 2026-10-04-nodus-evm-kurultay-k1.md (operator decisions 1-5),
 * 2026-10-04-nodus-evm-kurultay-k2-summary.md (operator decisions 1-3: MPT +
 * SHA3-512; one pending transaction per sender; the EVM gas sum is the one
 * block limit).
 *
 * ACTIVATION (the activation package): the compiled EVM GENERATION
 * (nodus_witness_runtime.c, NODUS_RT_GEN_EVM) carries this runtime; a
 * chain resolves it only after the height-activated EVM_ACTIVE vote's
 * edge (chain_config param 14, phase 6b'' of nodus_witness_v2_apply.c
 * registers the domain ACTIVE at the end of block H-1). Before that edge
 * no registry names domain 2 and nothing here runs.
 *
 * PAIRING (design §2): every EVM leg is leg 1 of EXACTLY [CORE EVMFUND] +
 * [EVM op] with the role matching the op — nodus_rt_evm_pair_check, the
 * SAME rule the CORE hook applies from its side. CORE pays the fee (role
 * FEE), locks the deposit into the CORE reserve (role DEPOSIT) or
 * releases a UTXO from it (role RELEASE), from the amounts in THIS leg's
 * call bytes; this runtime moves only the EVM side (balances, META,
 * tickets). The reserve is CORE state (v2_evm_reserve), read by the
 * invariant through nodus_witness_core_evm_reserve_get.
 *
 * PRE-VALIDATION (design §4, §8): nodus_rt_evm_prevalidate is the ONE
 * shared pre-validation — exec runs it first, CheckTx (a NEW entry and its
 * recheck alike, red-team 1 F1) runs ONLY it (no VM) and takes the conflict
 * keys from it.
 *
 * BUILD: this file and the EVM engine (shared/evm, the vendored blst,
 * c-kzg-4844 and mcl) are compiled into libnodus only in the standalone
 * nodus build on non-Windows hosts (nodus/CMakeLists.txt, which also
 * defines NODUS_EVM_ENABLED there — the switch that adds the EVM
 * generation to the compiled table). The engine (nodus_witness_v2_apply.c)
 * reaches this file through the runtime table's function pointers, with
 * ONE exception: the per-leg trie batch below (nodus_rt_evm_leg_begin /
 * _flush / _discard), which exec_evm_leg calls by name under
 * #ifdef NODUS_EVM_ENABLED for the EVM adapter only (red-team-1 F6 — the
 * runtime and adapter descriptors carry no leg begin/end hook; adding one
 * changes nodus_witness_runtime.h / nodus_witness_v2_adapter.h).
 */
#ifndef NODUS_WITNESS_RT_EVM_H
#define NODUS_WITNESS_RT_EVM_H

#include <stdint.h>
#include <stddef.h>

#include "witness/nodus_witness_runtime.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── runtime ops (design §2) — the descriptor's rule ids: NODUS_RT_EVM_CALL
 *    .. NODUS_RT_EVM_REDEEM and NODUS_RT_EVM_CALL_VER live in
 *    nodus_witness_runtime.h (the always-compiled call-head decoder and the
 *    CORE EVMFUND hook read them too). ──────────────────────────────────── */

/* ── adapter op ids (design §4) — also the reader op ids of the domain's
 *    state. Ascending; the stream's canonical order is the effect codec's
 *    (kind, op, key). ───────────────────────────────────────────────── */
#define NODUS_RT_EVM_OP_ACCT         1u   /* addr32 → 148-byte record    */
#define NODUS_RT_EVM_OP_SLOT         2u   /* addr32‖slot32 → 32 bytes    */
#define NODUS_RT_EVM_OP_CODE         3u   /* digest64‖chunk u8 → ≤ 8192  */
#define NODUS_RT_EVM_OP_TICKET       4u   /* ticket_id64 → 72 bytes      */
#define NODUS_RT_EVM_OP_META         5u   /* 0x01 → 96 bytes             */
#define NODUS_RT_EVM_OP_HAS_STORAGE  6u   /* addr32 → present, READ-ONLY */
/* (The SYNTHETIC mempool conflict-key ops NODUS_RT_EVM_KEY_SENDER_NONCE /
 *  NODUS_RT_EVM_KEY_TICKET live in nodus_witness_runtime.h with their one
 *  derivation, nodus_rt_evm_conflict_keys.) */

/** ACCT value (design §4): nonce u64 ‖ balance_wei[32] ‖
 *  code_hash_keccak[32] ‖ code_size u32 ‖ code_digest_sha3[64] ‖
 *  storage_count u64 — all big-endian. */
#define NODUS_RT_EVM_ACCT_LEN        148u
/** TICKET value: amount_raw u64 ‖ dest_fp[64]. */
#define NODUS_RT_EVM_TICKET_LEN      72u
/** META value: wei_live[32] ‖ wei_tickets[32] ‖ wei_lost[32] (design §6;
 *  the C1 reserve mirror is gone — the reserve is CORE state). */
#define NODUS_RT_EVM_META_LEN        96u
/** CODE chunk size (= DNA_EFFECT_MAX_VALUE_LEN). */
#define NODUS_RT_EVM_CODE_CHUNK      8192u

/** q: wei per raw unit (operator decision k1 #3: 1 raw unit = 10^10). */
#define NODUS_RT_EVM_Q               10000000000ull
/** Gas of creating one ticket (design §5; pending the Faz 3 measurement). */
#define NODUS_RT_EVM_TICKET_GAS      25000u

/** The EVM descriptor's rule list {1..5} — the ONE array the production
 *  table entry and nodus_rt_evm_runtime_build share. */
#define NODUS_RT_EVM_N_RULES 5u
extern const uint32_t NODUS_RT_EVM_RULES[NODUS_RT_EVM_N_RULES];

/**
 * Fill `out` with the EVM runtime entry: domain DNA_DOMAIN_EVM, runtime
 * ABI 2, ruleset_version 1, rules {1..5}, no legacy tx types, the shared
 * ML-DSA-87 auth hook (auth_kind 1 only), exec_evm, prevalidate_evm, the
 * adapter, state root, invariant and state_init. `ruleset_hash` is
 * DERIVED here through dna_ruleset_desc_hash, `generation` 0 — the TEST
 * builder (a test runtime table); the production entry is the EVM
 * generation's in nodus_witness_runtime.c, with the pinned digest.
 * @return 0 / -1.
 */
int nodus_rt_evm_runtime_build(nodus_domain_runtime_t *out);

/** The EVM domain's legacy-surface hooks: it owns no legacy tx type, so
 *  both refuse every type (-1). */
int nodus_rt_evm_admit(const nodus_domain_runtime_t *rt, uint8_t tx_type,
                       uint32_t pool_id);
int nodus_rt_evm_tx_cost(const nodus_domain_runtime_t *rt, uint8_t tx_type,
                         uint32_t *cost_out);

/** The EVM domain root of the EMPTY state (empty account and ticket
 *  tries, zero META) — what state_init produces; the genesis_state_root a
 *  registration commits. No database. @return 0 / -1. */
int nodus_rt_evm_empty_state_root(uint8_t out[64]);

/** The ticket system address SHA3-512("NDS.EVMWITHDRAW.v1")[0..32]
 *  (design §5; the 18 ASCII bytes, no terminator). @return 0 / -1. */
int nodus_rt_evm_ticket_addr(uint8_t out[32]);

/* ── the §18 RPC simulation (evm_call / evm_estimate) ───────────────────
 * Design §18 ("taze overlay, ... durum yazmaz") and §8 rev 4 (the RPC
 * simulation's node-local bound is a concurrency count and a per-request
 * gas cap — never a clock window): ONE CALL (to != NULL) or CREATE run by
 * the chain's own execution function (rtevm_exec_vm — pre-validation,
 * the engine, the change-set visit and the success-stream build) over a
 * FRESH overlay and a NON-METERING reader of the COMMITTED tables. Nothing
 * is written. The nonce is the sender's committed nonce; the sender is
 * the 32-byte address itself (no signature: a read). The reader keeps the
 * engine's read caps (NODUS_RT_EVM_READS_BASE, NODUS_RT_EVM_MAX_READ_BYTES)
 * so BUDGET outcomes match; it has no unit budget. The effect-ceiling
 * failure path (a success stream over the envelope's declaration) is NOT
 * simulated: it depends on the envelope's declaration, which a call does
 * not have. The CALLER must hold the committed state still for the
 * duration (the witness loop: one handler at a time, no open block). */
typedef struct {
    const uint8_t *from;               /* 32: the EVM sender              */
    const uint8_t *to;                 /* 32, NULL = CREATE               */
    const uint8_t *value;              /* 32 BE wei, NULL = 0             */
    const uint8_t *data;               /* call data / initcode            */
    uint32_t       data_len;
    uint64_t       gas_limit;          /* 1 .. NODUS_RT_EVM_TX_GAS_CAP    */
    const uint8_t *chain_id;           /* 32                              */
    uint64_t       global_height;      /* the block it would land in:
                                        * committed tip + 1               */
    uint64_t       block_time_s;       /* the committed tip block's header
                                        * seconds (design §10)            */
    uint64_t       evm_block_gas_limit;/* param 15 at global_height       */
} nodus_rt_evm_sim_req_t;

typedef struct {
    int      executed;     /* 0: refused BEFORE execution (nonce / value /
                            *    intrinsic gas / EIP-3607 / caps) — no
                            *    status; 1: it ran                        */
    int      success;      /* executed: 1 success, 0 applied failure      */
    int      budget;       /* the failure was the read BUDGET verdict     */
    uint64_t gas_used;     /* what a receipt would say: the engine's gas on
                            * success, gas_limit on failure (design §4)   */
    uint64_t engine_gas_used; /* the engine's own figure, either outcome  */
    uint64_t engine_work_gas; /* the engine's PRE-refund execution gas
                               * (evm_tx_result_t.gas_used_pre_refund):
                               * what the §18 budget charges — the receipt
                               * figures above keep their meaning; 0 when
                               * not executed                             */
    uint8_t *output;       /* heap: return data, or REVERT data           */
    size_t   output_len;
    uint8_t  created[32];  /* a successful CREATE                         */
    int      has_created;
    uint64_t reads;        /* distinct logical reads — what the engine's
                            * reader would charge (w_read each)           */
} nodus_rt_evm_sim_res_t;

/** Run one simulation. `rt` is the EVM domain's registered runtime.
 *  @return 0 (*res filled; free with nodus_rt_evm_sim_res_free) / -1 the
 *  request is outside the bounds (gas 0 or over the cap, initcode over
 *  EIP-3860, a read budget hit before execution) / -2 node fault. */
int nodus_rt_evm_simulate(const nodus_domain_runtime_t *rt,
                          struct nodus_witness *w,
                          const nodus_rt_evm_sim_req_t *req,
                          nodus_rt_evm_sim_res_t *res);
void nodus_rt_evm_sim_res_free(nodus_rt_evm_sim_res_t *res);

/* ── the per-leg trie batch (red-team-1 F6) ─────────────────────────────
 * Between begin and flush every EVM adapter mutation of `w` writes its
 * ROWS at once but applies its trie changes (storage tries, account
 * trie, tickets trie) to in-memory tries only; flush commits each touched
 * trie ONCE and writes the new storage / account / tickets roots, inside
 * the caller's transaction. The roots equal the per-effect commits' byte
 * for byte (a root depends only on the final key set). Discard drops the
 * in-memory changes: no trie node and no root was written, so the
 * caller's savepoint rollback of the rows leaves nothing behind. A
 * mutation with no open batch commits by itself (the per-effect path).
 * While a batch is open nodus_rt_evm_state_root refuses (-1).
 * One batch at a time per thread. Not used by any dry run (no mutation). */

/** Open the batch. @return 0 / -1 (bad argument, allocation, or a batch
 *  still open — the leftover is dropped and the call refused). */
int nodus_rt_evm_leg_begin(struct nodus_witness *w);
/** Commit every touched trie once and close the batch (closed on failure
 *  too; the caller rolls its savepoint back). @return 0 / -1 (no batch
 *  open for `w`, a failed mutation inside it, a store or trie fault). */
int nodus_rt_evm_leg_flush(struct nodus_witness *w);
/** Drop the open batch of `w` without writing anything. No batch: no-op. */
void nodus_rt_evm_leg_discard(struct nodus_witness *w);
/** Is a batch open for `w` on this thread? 1 / 0. */
int nodus_rt_evm_leg_open(struct nodus_witness *w);

/* ── the hooks (referenced by the entry above) ──────────────────────── */
int nodus_rt_evm_exec(const nodus_domain_runtime_t *rt,
                      const dna_env_view_t *env, uint16_t leg_index,
                      const nodus_rt_exec_ctx_t *ctx,
                      const nodus_rt_v2_reader_t *reader,
                      nodus_rt_v2_out_t *out);
int nodus_rt_evm_prevalidate(const nodus_domain_runtime_t *rt,
                             const dna_env_view_t *env, uint16_t leg_index,
                             const nodus_rt_exec_ctx_t *ctx,
                             const nodus_rt_v2_reader_t *reader,
                             nodus_rt_v2_keys_t *keys);
int nodus_rt_evm_state_root(const nodus_domain_runtime_t *rt,
                            struct nodus_witness *w, uint8_t out[64]);
int nodus_rt_evm_invariant(const nodus_domain_runtime_t *rt,
                           struct nodus_witness *w);
int nodus_rt_evm_state_init(const nodus_domain_runtime_t *rt,
                            struct nodus_witness *w,
                            uint64_t activation_global_height);
extern const struct nodus_domain_adapter NODUS_RT_EVM_ADAPTER;

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_RT_EVM_H */
