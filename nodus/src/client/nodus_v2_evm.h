/**
 * @file nodus/src/client/nodus_v2_evm.h
 * @brief The shared EVM envelope builder (Nodus EVM) — [CORE EVMFUND] + [EVM op]
 *        priced, funded, signed and read back, no I/O.
 *
 * Governing records: design docs/plans/2026-10-04-nodus-evm-chain-integration-
 * design.md rev 3 §2 (envelope = [CORE EVMFUND leg, op 9] + [EVM leg,
 * domain 2, ops 1-5]; EVM sender = SHA3-512(ML-DSA-87 pk)[0..32]), §8 (the
 * fee is a CORE-funded DECLARED ceiling: res_max_total_units >= static
 * units + gas_limit × w_gas + FAIL_RESERVE, fee >= units × gas price),
 * §16 (SDK), §18 (evm_estimate); decisions 2026-10-04-nodus-evm-kurultay-k1.md
 * (operator 1: CORE-funded ceiling fee; 3: q = 10^10; 4: explicit 64-byte
 * withdraw recipient + tickets), 2026-10-04-nodus-evm-kurultay-k2-summary.md
 * (operator 2: one pending EVM transaction per sender), and
 * 2026-09-25-web-wallet-nodus-send-transport.md ("İşlem kurucu": the
 * wallet builds with the SAME C code nodus-cli uses).
 *
 * WHAT IT IS: the web wallet's EVM build (web-wallet/crypto/nodus-send-
 * wasm.c nsw_evm_core / nsw_evm_min_units), moved out so nodus-cli `evm`
 * and the wallet build byte-identical envelopes from identical inputs (the
 * hedged ML-DSA signature excepted — nodus_v2_spend.h). Pure: no socket,
 * no clock, no database, no RNG (the change seed is derived from the input
 * nullifiers). The call bytes are shared/dnac/evm_call_wire.c — the codec
 * the node itself decodes with.
 *
 * THE CHAIN IS THE SPECIFICATION:
 *   CORE EVMFUND (nodus_witness_rt_native.c rtn_evmfund_parse / _exec):
 *     reads = in_count + 1 (FEE) / + 2 (DEPOSIT, RELEASE: the reserve)
 *     effects (exact, rtn_evmfund_exec): n_out (+1 release UTXO for
 *     RELEASE) CREATEs, the pool SET, (+ the reserve SET for DEPOSIT /
 *     RELEASE), n_in DELETEs.
 *   EVM leg (nodus_witness_rt_evm.c): bridge ops read 2 keys (ACCT or
 *     TICKET, then META) and write exactly 2 effects (ACCT + META, or the
 *     TICKET DELETE + META); CALL / CREATE read at run time (charged per
 *     logical key — the node's evm_estimate counts them) and stream their
 *     effects against the declared ceilings (over = the paid failure path).
 *
 * UNITS (design §8): the smallest res_max_total_units for an envelope of
 * one SHAPE is
 *   static units (dna_meter_plan_build_ex, the EVM leg streamed)
 *   + (funding reads + bridge reads) × w_read
 *   + CALL / CREATE: gas_limit × w_gas + FAIL_RESERVE
 * — nodus_v2_evm_min_units. A CALL / CREATE also reads at run time; those
 * units come from the node's evm_estimate: its `ue` is the minimum of the
 * REFERENCE SHAPE (nodus_v2_evm_ref_units: one input, one change output,
 * the default effect declaration, no access list) plus the reads the
 * simulation observed × w_read, so a client recovers the read units as
 * `ue − nodus_v2_evm_ref_units(same op, data length, gas)` and adds them
 * to the minimum of its OWN shape (nodus_v2_evm_req_t.evm_read_units).
 * Both sides call the same function with the same inputs, so the
 * difference is exact.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef NODUS_V2_EVM_H
#define NODUS_V2_EVM_H

#include <stdint.h>
#include <stddef.h>

#include "nodus/nodus_v2_spend.h"   /* rc values, ruleset id, coin type   */
#include "dnac/evm_call_wire.h"     /* the ONE call / EVMFUND codec        */

#ifdef __cplusplus
extern "C" {
#endif

/** The default declaration of a CALL / CREATE leg (the node test's
 *  nodus/tests/test_v2_evm.c EVM_MAXEFF / EVM_MAXBYTES). Every declared
 *  effect and byte is priced; a stream over it takes the paid failure
 *  path (design §4). */
#define NODUS_V2_EVM_DEF_EFFECTS       256u
#define NODUS_V2_EVM_DEF_EFFECT_BYTES  65536u
/** The logical reads of a bridge op's EVM leg (rtevm_bridge_pre). */
#define NODUS_V2_EVM_BRIDGE_READS      2u
/** The fee-fixed-point pass limit (the wallet's nsw_evm_core). */
#define NODUS_V2_EVM_MAX_PASSES        8

/** Refusals of this module beyond the shared nodus_v2_spend_rc_t values it
 *  also returns (ERR_ARG, ERR_ALLOC, ERR_OVERFLOW, ERR_MAX_INPUTS,
 *  ERR_INPUT_SUM, ERR_INSUFFICIENT, ERR_METER, ERR_GAS_OVERFLOW,
 *  ERR_FEE_UNSETTLED, ERR_HASH, ERR_ENCODE, ERR_PREFLIGHT1, ERR_SIGN,
 *  ERR_PREFLIGHT2, ERR_DECODE). */
typedef enum {
    NODUS_V2_EVM_ERR_GAS        = -60,  /* gas_limit 0 or > the tx cap   */
    NODUS_V2_EVM_ERR_NO_CODE    = -61,  /* CREATE without initcode       */
    NODUS_V2_EVM_ERR_BRIDGE_DATA= -62,  /* data / access list on a bridge*/
    NODUS_V2_EVM_ERR_AMOUNT     = -63,  /* bridge amount 0               */
    NODUS_V2_EVM_ERR_OP_WEIGHT  = -64,  /* the policy does not weigh op 9 */
    NODUS_V2_EVM_ERR_UNITS_LOW  = -65,  /* a fixed ceiling < the minimum */
    NODUS_V2_EVM_ERR_MISMATCH   = -66,  /* read-back differs from request*/
    NODUS_V2_EVM_ERR_DECL       = -67,  /* effect declaration out of range*/
    NODUS_V2_EVM_ERR_OP         = -68   /* not an EVM op 1..5            */
} nodus_v2_evm_rc_t;

/** The EXACT (res_max_effects, res_max_effect_bytes) of the CORE EVMFUND
 *  leg of `role` with n_in inputs and n_out change outputs
 *  (rtn_evmfund_exec's effect list):
 *    rel = (role == RELEASE), rsv = (role != FEE)
 *    effects = n_in + n_out + rel + 1 + rsv
 *    bytes   = 23 + 84·effects + (64 + 284)·(n_out + rel)
 *              + (1 + 8)·(1 + rsv) + 64·n_in
 *  @return 0 / -1 (unknown role). */
int nodus_v2_evm_fund_decl(uint8_t role, uint32_t n_in, uint32_t n_out,
                           uint32_t *effects_out, uint32_t *bytes_out);

/** The EXACT declaration of a bridge op's EVM leg (rtevm_bridge: ACCT 148
 *  + META 96 for DEPOSIT / WITHDRAW; TICKET DELETE + META 96 for REDEEM):
 *  2 effects; 23 + 2·84 + (32 + 148) + (1 + 96) = 468, or
 *  23 + 2·84 + 64 + (1 + 96) = 352. @return 0 / -1 (not a bridge op). */
int nodus_v2_evm_bridge_decl(uint32_t op, uint32_t *effects_out,
                             uint32_t *bytes_out);

/** The smallest res_max_total_units the node accepts for an envelope of
 *  this SHAPE (see "UNITS" above): EVM leg `op` with call length
 *  `evm_call_len` and declaration (effects, effect_bytes), gas_limit
 *  (CALL / CREATE only), the funding leg's role-for-op with n_in inputs
 *  and n_out change outputs, CORE leg version `core_version`, policy
 *  `pol` (the SYSTEM meter policy of the generation the envelope is built
 *  for). A function of lengths and declarations only.
 *  @return NODUS_V2_SPEND_OK / _ERR_ARG / _ERR_ALLOC / _ERR_ENCODE /
 *  NODUS_V2_EVM_ERR_OP_WEIGHT / _ERR_METER / _ERR_OVERFLOW;
 *  `meter_status` (may be NULL) receives the meter's status. */
int nodus_v2_evm_min_units(const dna_meter_policy_t *pol,
                           uint32_t core_version, uint32_t op,
                           size_t evm_call_len, uint32_t effects,
                           uint32_t effect_bytes, uint64_t gas_limit,
                           int n_in, int n_out, uint64_t *out,
                           int *meter_status);

/** The REFERENCE SHAPE the node's evm_estimate prices (`ue`): CALL or
 *  CREATE with `data_len` bytes of data / initcode and NO access list, the
 *  default declaration, one funding input, one change output.
 *  @return as nodus_v2_evm_min_units. */
int nodus_v2_evm_ref_units(const dna_meter_policy_t *pol,
                           uint32_t core_version, uint32_t op,
                           uint32_t data_len, uint64_t gas_limit,
                           uint64_t *out);

typedef struct {
    const nodus_v2_ruleset_id_t *rs;  /* CORE tuple + SYSTEM policy of the
                                       * generation the node runs (it must
                                       * weigh CORE op 9: the EVM
                                       * generation)                       */
    uint32_t       evm_ruleset_version;
    const uint8_t *evm_ruleset_hash;  /* 64 bytes                          */
    const uint8_t *chain32;           /* DNA_CHAIN_ID_LEN bytes            */
    uint64_t       tip;               /* committed tip (>= 1)              */
    uint64_t       expiry_height;     /* checked by the caller             */
    uint64_t       gas_price;         /* 0 = the rule is off               */
    const uint8_t *pk;                /* ML-DSA-87 pk 2592 B: signs BOTH
                                       * legs, owns every input; the EVM
                                       * sender is SHA3-512(pk)[0..32]     */
    const uint8_t *sk;                /* 4896 B                            */
    dna_evm_call_t call;              /* op + scalars; data / access list
                                       * borrowed (CALL / CREATE only)     */
    uint32_t       effects, effect_bytes; /* CALL / CREATE declaration;
                                       * 0, 0 = the default                */
    uint64_t       units;             /* 0 = the minimum + evm_read_units;
                                       * otherwise this exact ceiling,
                                       * refused when below the minimum    */
    uint64_t       evm_read_units;    /* see "UNITS" (0 for a bridge op)   */
    const nodus_v2_coin_t *coins;     /* candidate NATIVE coins, any order;
                                       * `kind` / `used` ignored           */
    int            n_coins;
} nodus_v2_evm_req_t;

typedef struct {
    uint8_t       *env;               /* heap; nodus_v2_evm_built_free     */
    size_t         env_len;
    uint8_t        wire_id[64];
    uint8_t        intent_id[64];
    uint8_t        role;
    uint64_t       fee, change, units, sum_in, min_units;
    int            n_in;
    uint8_t        in_nul[DNA_EVMFUND_MAX_IN][64];
    uint8_t        change_id[64];     /* SHA3-512(owner ‖ seed) when change */
    dna_evm_call_t dec;               /* the EVM call decoded back from
                                       * `env` (pointers into env)         */
} nodus_v2_evm_built_t;

/** Which numbers a refusal carries (for the caller's message). */
typedef struct {
    uint64_t units, min_units, fee, need;
    int      n_in;
    int      leg;           /* signing: the failing leg                 */
    int      meter_status;  /* the meter's status on ERR_METER          */
} nodus_v2_evm_err_t;

/**
 * Build, sign and self-check ONE [CORE EVMFUND] + [EVM op] envelope, then
 * decode it back and refuse unless every decoded field equals the request.
 * Funding: candidate coins ascending by nullifier until they cover
 * lock + fee (lock = amount_raw for DEPOSIT, else 0), at most 15; change
 * (sum − lock − fee) is ONE native output to the signer when > 0, its seed
 * SHA3-512(input nullifiers)[0..32]. units / fee: a fixed point over the
 * funding shape (at most NODUS_V2_EVM_MAX_PASSES): units = the minimum of
 * the shape (+ evm_read_units) or the fixed `units`; fee = max(floor,
 * units × gas_price), floor = max(DNAC_MIN_FEE_RAW, NODUS_W_BASE_TX_FEE)
 * (rtn_evmfund_exec's two floors).
 * @return NODUS_V2_SPEND_OK or a refusal (`err` may be NULL).
 */
int nodus_v2_evm_build(const nodus_v2_evm_req_t *req,
                       nodus_v2_evm_built_t *out, nodus_v2_evm_err_t *err);

void nodus_v2_evm_built_free(nodus_v2_evm_built_t *b);

/**
 * The address a CREATE transaction deploys to, in the Nodus 32-byte address
 * mode (design §2): keccak256(rlp([sender, nonce])), all 32 bytes kept —
 * execution-specs@a87891f7 prague/utils/address.py compute_contract_address
 * with the sender encoded as its full 32 bytes. The engine's rule is
 * shared/evm/evm_interp.c evm_compute_contract_address (cfg.addr_bytes 32);
 * a top-level CREATE uses the transaction's own nonce (shared/evm/evm_tx.c
 * evm_compute_contract_address(st, sender, now.nonce - 1, ...)). Restated
 * here, I/O-free, so nodus-cli and the wallet can check a receipt's "cr"
 * against the SIGNED transaction's sender and nonce; pinned to the engine's
 * independent oracle vectors (shared/evm/tests/addr32_vectors.h, generated
 * by addr32_oracle.py) by web-wallet/test/evm-call-wire-wasm.test.js (the
 * parity wasm, nsw_test_evm_create_address).
 * `sender`: the EVM sender, SHA3-512(ML-DSA-87 pk)[0..32].
 * @return 0, or -1 (NULL argument / hash failure).
 */
int nodus_v2_evm_create_address(const uint8_t sender[32], uint64_t nonce,
                                uint8_t out[32]);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_V2_EVM_H */
