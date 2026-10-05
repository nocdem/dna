/**
 * @file evm_gas.h
 * @brief Prague gas schedule for the Nodus EVM (Nodus EVM phase 1).
 *
 * Every value is copied from execution-specs@a87891f7
 * src/ethereum/forks/prague/vm/gas.py, class GasCosts (lines 30-189), unless
 * another file is named. Names follow the reference (GasCosts.<NAME> ->
 * EVM_G_<NAME>). Constants of code paths this phase does not implement
 * (bn254, KZG, BLS, blobs, EIP-7702 authorizations, header gas-limit rules —
 * design §1, §3) are listed too, marked unused.
 */
#ifndef EVM_GAS_H
#define EVM_GAS_H

#include <stdint.h>

/* ── tiers ─────────────────────────────────────────────────────────── */
#define EVM_G_BASE                       2u      /* GasCosts.BASE            */
#define EVM_G_VERY_LOW                   3u      /* GasCosts.VERY_LOW        */
#define EVM_G_LOW                        5u      /* GasCosts.LOW             */
#define EVM_G_MID                        8u      /* GasCosts.MID             */
#define EVM_G_HIGH                       10u     /* GasCosts.HIGH            */

/* ── access (EIP-2929) ─────────────────────────────────────────────── */
#define EVM_G_WARM_ACCESS                100u    /* GasCosts.WARM_ACCESS     */
#define EVM_G_COLD_ACCOUNT_ACCESS        2600u   /* GasCosts.COLD_ACCOUNT_ACCESS */
#define EVM_G_COLD_STORAGE_ACCESS        2100u   /* GasCosts.COLD_STORAGE_ACCESS */

/* ── storage (EIP-2200 / EIP-3529) ─────────────────────────────────── */
#define EVM_G_STORAGE_SET                20000u  /* GasCosts.STORAGE_SET     */
#define EVM_G_COLD_STORAGE_WRITE         5000u   /* GasCosts.COLD_STORAGE_WRITE */
#define EVM_G_REFUND_STORAGE_CLEAR       4800    /* GasCosts.REFUND_STORAGE_CLEAR */

/* ── calls ─────────────────────────────────────────────────────────── */
#define EVM_G_CALL_STIPEND               2300u   /* GasCosts.CALL_STIPEND    */
#define EVM_G_CALL_VALUE                 9000u   /* GasCosts.CALL_VALUE      */
#define EVM_G_NEW_ACCOUNT                25000u  /* GasCosts.NEW_ACCOUNT     */

/* ── contract creation ─────────────────────────────────────────────── */
#define EVM_G_CODE_DEPOSIT_PER_BYTE      200u    /* GasCosts.CODE_DEPOSIT_PER_BYTE */
#define EVM_G_CODE_INIT_PER_WORD         2u      /* GasCosts.CODE_INIT_PER_WORD (EIP-3860) */

/* ── utility ───────────────────────────────────────────────────────── */
#define EVM_G_ZERO                       0u      /* GasCosts.ZERO            */
#define EVM_G_MEMORY_PER_WORD            3u      /* GasCosts.MEMORY_PER_WORD */
#define EVM_G_FAST_STEP                  5u      /* GasCosts.FAST_STEP       */

/* ── precompiles ───────────────────────────────────────────────────── */
#define EVM_G_PRECOMPILE_ECRECOVER       3000u   /* GasCosts.PRECOMPILE_ECRECOVER */
#define EVM_G_PRECOMPILE_SHA256_BASE     60u     /* GasCosts.PRECOMPILE_SHA256_BASE */
#define EVM_G_PRECOMPILE_SHA256_PER_WORD 12u     /* GasCosts.PRECOMPILE_SHA256_PER_WORD */
#define EVM_G_PRECOMPILE_RIPEMD160_BASE  600u    /* GasCosts.PRECOMPILE_RIPEMD160_BASE */
#define EVM_G_PRECOMPILE_RIPEMD160_PER_WORD 120u /* GasCosts.PRECOMPILE_RIPEMD160_PER_WORD */
#define EVM_G_PRECOMPILE_IDENTITY_BASE   15u     /* GasCosts.PRECOMPILE_IDENTITY_BASE */
#define EVM_G_PRECOMPILE_IDENTITY_PER_WORD 3u    /* GasCosts.PRECOMPILE_IDENTITY_PER_WORD */
#define EVM_G_PRECOMPILE_BLAKE2F_PER_ROUND 1u    /* GasCosts.PRECOMPILE_BLAKE2F_PER_ROUND */
/* modexp (EIP-2565): prague/vm/precompiled_contracts/modexp.py:GQUADDIVISOR
 * and the floor 200 in gas_cost(). */
#define EVM_G_MODEXP_QUAD_DIVISOR        3u
#define EVM_G_MODEXP_MIN                 200u

/* KZG point evaluation (EIP-4844), BLS12-381 (EIP-2537), alt_bn128
 * (EIP-196/197, EIP-1108 prices). */
#define EVM_G_PRECOMPILE_POINT_EVALUATION 50000u /* GasCosts.PRECOMPILE_POINT_EVALUATION */
#define EVM_G_PRECOMPILE_BLS_G1ADD       375u    /* GasCosts.PRECOMPILE_BLS_G1ADD */
#define EVM_G_PRECOMPILE_BLS_G1MUL       12000u  /* GasCosts.PRECOMPILE_BLS_G1MUL */
#define EVM_G_PRECOMPILE_BLS_G1MAP       5500u   /* GasCosts.PRECOMPILE_BLS_G1MAP */
#define EVM_G_PRECOMPILE_BLS_G2ADD       600u    /* GasCosts.PRECOMPILE_BLS_G2ADD */
#define EVM_G_PRECOMPILE_BLS_G2MUL       22500u  /* GasCosts.PRECOMPILE_BLS_G2MUL */
#define EVM_G_PRECOMPILE_BLS_G2MAP       23800u  /* GasCosts.PRECOMPILE_BLS_G2MAP */
#define EVM_G_PRECOMPILE_ECADD           150u    /* GasCosts.PRECOMPILE_ECADD */
#define EVM_G_PRECOMPILE_ECMUL           6000u   /* GasCosts.PRECOMPILE_ECMUL */
#define EVM_G_PRECOMPILE_ECPAIRING_BASE  45000u  /* GasCosts.PRECOMPILE_ECPAIRING_BASE */
#define EVM_G_PRECOMPILE_ECPAIRING_PER_POINT 34000u /* GasCosts.PRECOMPILE_ECPAIRING_PER_POINT */
/* BLS12-381 pairing: literal `32600 * k + 37700` in
 * prague/vm/precompiled_contracts/bls12_381/bls12_381_pairing.py */
#define EVM_G_PRECOMPILE_BLS_PAIRING_PER_PAIR 32600u
#define EVM_G_PRECOMPILE_BLS_PAIRING_BASE 37700u

/* ── authorization (EIP-7702; type-4 txs are refused in this phase) ─── */
#define EVM_G_AUTH_PER_EMPTY_ACCOUNT     25000   /* GasCosts.AUTH_PER_EMPTY_ACCOUNT */
#define EVM_G_REFUND_AUTH_PER_EXISTING_ACCOUNT 12500 /* GasCosts.REFUND_AUTH_PER_EXISTING_ACCOUNT */

/* ── blobs (type-3 txs are refused; header-level constants) ─────────── */
#define EVM_G_PER_BLOB                   131072u /* GasCosts.PER_BLOB = 2**17 */
#define EVM_G_BLOB_TARGET_GAS_PER_BLOCK  786432u /* GasCosts.BLOB_TARGET_GAS_PER_BLOCK */

/* ── block gas limit adjustment (header validation, not engine) ─────── */
#define EVM_G_LIMIT_ADJUSTMENT_FACTOR    1024u   /* GasCosts.LIMIT_ADJUSTMENT_FACTOR */
#define EVM_G_LIMIT_MINIMUM              5000u   /* GasCosts.LIMIT_MINIMUM */

/* The static OPCODE_* entries of GasCosts are aliases of the tiers above
 * (e.g. OPCODE_ADD = VERY_LOW, OPCODE_MUL = LOW, OPCODE_ADDMOD = MID,
 * OPCODE_JUMPI = HIGH, OPCODE_COINBASE = BASE); evm_interp.c uses the tier
 * name at each opcode, matching gas.py lines 112-168. */

/* ── blob fee (BLOBBASEFEE opcode only) ────────────────────────────── */
#define EVM_G_BLOB_MIN_GASPRICE          1u      /* GasCosts.BLOB_MIN_GASPRICE */
#define EVM_G_BLOB_BASE_FEE_UPDATE_FRACTION 5007716u /* GasCosts.BLOB_BASE_FEE_UPDATE_FRACTION */

/* ── transactions ──────────────────────────────────────────────────── */
#define EVM_G_TX_BASE                    21000u  /* GasCosts.TX_BASE         */
#define EVM_G_TX_CREATE                  32000u  /* GasCosts.TX_CREATE       */
#define EVM_G_TX_DATA_TOKEN_STANDARD     4u      /* GasCosts.TX_DATA_TOKEN_STANDARD */
#define EVM_G_TX_DATA_TOKEN_FLOOR        10u     /* GasCosts.TX_DATA_TOKEN_FLOOR (EIP-7623) */
#define EVM_G_TX_ACCESS_LIST_ADDRESS     2400u   /* GasCosts.TX_ACCESS_LIST_ADDRESS */
#define EVM_G_TX_ACCESS_LIST_STORAGE_KEY 1900u   /* GasCosts.TX_ACCESS_LIST_STORAGE_KEY */

/* ── opcodes with a fixed cost ─────────────────────────────────────── */
#define EVM_G_OPCODE_JUMPDEST            1u      /* GasCosts.OPCODE_JUMPDEST */
#define EVM_G_OPCODE_BLOCKHASH           20u     /* GasCosts.OPCODE_BLOCKHASH */
#define EVM_G_OPCODE_BLOBHASH            3u      /* GasCosts.OPCODE_BLOBHASH */
#define EVM_G_OPCODE_SELFBALANCE         EVM_G_FAST_STEP /* GasCosts.OPCODE_SELFBALANCE */
#define EVM_G_OPCODE_TLOAD               EVM_G_WARM_ACCESS /* GasCosts.OPCODE_TLOAD (EIP-1153) */
#define EVM_G_OPCODE_TSTORE              EVM_G_WARM_ACCESS /* GasCosts.OPCODE_TSTORE (EIP-1153) */

/* ── opcodes with a dynamic part ───────────────────────────────────── */
#define EVM_G_OPCODE_COPY_PER_WORD       3u      /* GasCosts.OPCODE_COPY_PER_WORD */
#define EVM_G_OPCODE_RETURNDATACOPY_PER_WORD 3u  /* GasCosts.OPCODE_RETURNDATACOPY_PER_WORD */
#define EVM_G_OPCODE_CREATE_BASE         32000u  /* GasCosts.OPCODE_CREATE_BASE */
#define EVM_G_OPCODE_EXP_BASE            10u     /* GasCosts.OPCODE_EXP_BASE */
#define EVM_G_OPCODE_EXP_PER_BYTE        50u     /* GasCosts.OPCODE_EXP_PER_BYTE */
#define EVM_G_OPCODE_KECCAK256_BASE      30u     /* GasCosts.OPCODE_KECCAK256_BASE */
#define EVM_G_OPCODE_KECCAK256_PER_WORD  6u      /* GasCosts.OPCODE_KECCAK256_PER_WORD */
#define EVM_G_OPCODE_LOG_BASE            375u    /* GasCosts.OPCODE_LOG_BASE */
#define EVM_G_OPCODE_LOG_DATA_PER_BYTE   8u      /* GasCosts.OPCODE_LOG_DATA_PER_BYTE */
#define EVM_G_OPCODE_LOG_TOPIC           375u    /* GasCosts.OPCODE_LOG_TOPIC */
#define EVM_G_OPCODE_SELFDESTRUCT_BASE   5000u   /* GasCosts.OPCODE_SELFDESTRUCT_BASE */
#define EVM_G_OPCODE_SELFDESTRUCT_NEW_ACCOUNT 25000u /* GasCosts.OPCODE_SELFDESTRUCT_NEW_ACCOUNT */

/* ── limits (prague/vm/interpreter.py:63-65, vm/stack.py:push) ─────── */
#define EVM_L_STACK_DEPTH_LIMIT          1024u   /* interpreter.py STACK_DEPTH_LIMIT */
#define EVM_L_MAX_CODE_SIZE              0x6000u /* interpreter.py MAX_CODE_SIZE (EIP-170) */
#define EVM_L_MAX_INIT_CODE_SIZE         (2u * EVM_L_MAX_CODE_SIZE) /* EIP-3860 */
#define EVM_L_STACK_ITEMS                1024u   /* vm/stack.py:push */

/* ── EIP-7702 delegation designator (prague/vm/eoa_delegation.py) ──── */
#define EVM_DELEGATION_MARKER_LEN        3u      /* EOA_DELEGATION_MARKER b"\xef\x01\x00" */
#define EVM_DELEGATED_CODE_LENGTH        23u     /* EOA_DELEGATED_CODE_LENGTH */

/* ── precompile address range (prague/vm/precompiled_contracts/__init__.py)
 *    0x01 ECRECOVER .. 0x11 BLS12_MAP_FP2_TO_G2 ─────────────────────── */
#define EVM_PRECOMPILE_FIRST             0x01u
#define EVM_PRECOMPILE_LAST              0x11u

#endif /* EVM_GAS_H */
