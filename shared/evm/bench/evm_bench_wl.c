/**
 * @file evm_bench_wl.c
 * @brief Nodus EVM measurement gate — worst-case EVM workloads (see the header).
 *
 * MEASUREMENT TOOL ONLY — not consensus code.
 *
 * Citations: "gas.py:N" = execution-specs@a87891f7
 * src/ethereum/forks/prague/vm/gas.py line N (class GasCosts);
 * "instructions/X.py:N" = the opcode's function in
 * src/ethereum/forks/prague/vm/instructions/X.py, whose pop() lines fix
 * the stack order every contract below is assembled for;
 * "precompiled_contracts/X.py" = the precompile's gas rule.
 *
 * Every contract is a GAS-GUARDED LOOP unless stated: each iteration first
 * checks `GAS < thresh` (comparison.py:24 less_than pops left = GAS, then
 * right = thresh) and stops cleanly, so the transaction ends in SUCCESS
 * with its state changes kept (an out-of-gas end would discard them and
 * measure a different, cheaper path). `thresh` is one iteration's gas
 * plus margin, so at most one iteration's worth of gas stays unused
 * (wl_inst_t.slack).
 *
 * Precompile calls honour the 63/64 rule (gas.py:354 max_message_call_gas):
 * the guard is cost + cost/63 + PC_GUARD, so the last call always has its
 * full price forwarded and never fails — a failing call would burn the
 * forwarded gas as fake "work" and inflate Mgas/s.
 */
#define _POSIX_C_SOURCE 200809L

#include "evm_bench_wl.h"
#include "evm.h"
#include "evm_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── opcodes (execution-specs@a87891f7 prague/vm/instructions/__init__.py) */
#define O_STOP         0x00
#define O_ADD          0x01
#define O_MUL          0x02
#define O_SUB          0x03
#define O_DIV          0x04
#define O_MULMOD       0x09
#define O_EXP          0x0a
#define O_LT           0x10
#define O_GT           0x11
#define O_ISZERO       0x15
#define O_KECCAK256    0x20
#define O_ADDRESS      0x30
#define O_BALANCE      0x31
#define O_CALLDATALOAD 0x35
#define O_CALLDATASIZE 0x36
#define O_CALLDATACOPY 0x37
#define O_CODECOPY     0x39
#define O_EXTCODESIZE  0x3b
#define O_EXTCODECOPY  0x3c
#define O_POP          0x50
#define O_MSTORE       0x52
#define O_MSTORE8      0x53
#define O_SLOAD        0x54
#define O_SSTORE       0x55
#define O_JUMP         0x56
#define O_JUMPI        0x57
#define O_GAS          0x5a
#define O_JUMPDEST     0x5b
#define O_MCOPY        0x5e
#define O_PUSH1        0x60
#define O_PUSH2        0x61
#define O_PUSH32       0x7f
#define O_DUP1         0x80
#define O_DUP2         0x81
#define O_DUP3         0x82
#define O_DUP4         0x83
#define O_SWAP1        0x90
#define O_LOG4         0xa4
#define O_CREATE       0xf0
#define O_CALL         0xf1
#define O_RETURN       0xf3
#define O_CREATE2      0xf5
#define O_STATICCALL   0xfa

/* op-loop code size target (EIP-170 limit 24 576, evm.h EVM_MAX_CODE_SIZE) */
#define OPLOOP_CODE_TARGET 24000u
/* margin added to a precompile call's 63/64-adjusted price in the guard */
#define PC_GUARD 1200u

/* ══ small helpers ═══════════════════════════════════════════════════ */

static uint64_t words_of(uint64_t bytes) { return (bytes + 31u) / 32u; }

uint64_t wl_mem_cost(uint64_t bytes)
{
    uint64_t w = words_of(bytes);
    return 3u * w + (w * w) / 512u;           /* gas.py:247-267 */
}

uint64_t wl_intrinsic(const uint8_t *data, size_t len)
{
    /* transactions.py:621,627: tokens = zeros + 4 * non-zeros, cost =
     * tokens * TX_DATA_TOKEN_STANDARD (4) over TX_BASE 21 000 */
    uint64_t g = 21000u;
    for (size_t i = 0; i < len; i++) g += data[i] ? 16u : 4u;
    return g;
}

static void word_u64(uint8_t w[32], uint64_t v)
{
    memset(w, 0, 32);
    for (int i = 0; i < 8; i++) w[31 - i] = (uint8_t)(v >> (8 * i));
}

static int hexv(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* hex -> bytes; returns the byte count, 0 on malformed input / no room */
static size_t unhex(const char *s, uint8_t *out, size_t cap)
{
    size_t n = strlen(s);
    if (n % 2 || n / 2 > cap) return 0;
    for (size_t i = 0; i < n / 2; i++) {
        int hi = hexv(s[2 * i]), lo = hexv(s[2 * i + 1]);
        if (hi < 0 || lo < 0) return 0;
        out[i] = (uint8_t)(hi * 16 + lo);
    }
    return n / 2;
}

static void msgf(char *msg, size_t cap, const char *what)
{
    if (msg && cap) snprintf(msg, cap, "%s", what);
}

/* ══ assembler with labels (PUSH2 fix-ups) ════════════════════════════ */

#define AS_LABELS 8
#define AS_FIXES  32

typedef struct {
    uint8_t b[EVM_MAX_CODE_SIZE];
    size_t  n;
    int     err;
    size_t  lab[AS_LABELS];
    int     lab_set[AS_LABELS];
    size_t  fix_at[AS_FIXES];
    int     fix_lab[AS_FIXES];
    int     nfix;
} as_t;

static void as_b(as_t *a, uint8_t v)
{
    if (a->n >= sizeof(a->b)) {
        a->err = 1;
        return;
    }
    a->b[a->n++] = v;
}

static void as_push(as_t *a, const uint8_t *v, size_t len)
{
    as_b(a, (uint8_t)(O_PUSH1 + len - 1));
    for (size_t i = 0; i < len; i++) as_b(a, v[i]);
}

/* minimal-width PUSH of v (PUSH1 0 for zero) */
static void as_pushu(as_t *a, uint64_t v)
{
    uint8_t be[8];
    size_t n = 1;
    while (n < 8 && (v >> (8 * n)) != 0) n++;
    for (size_t i = 0; i < n; i++) be[i] = (uint8_t)(v >> (8 * (n - 1 - i)));
    as_push(a, be, n);
}

/* calldata word i (PUSH1 32*i CALLDATALOAD; environment.py:158) */
static void as_cdw(as_t *a, unsigned i)
{
    as_pushu(a, 32u * i);
    as_b(a, O_CALLDATALOAD);
}

/* a label is a JUMPDEST at the current position */
static void as_label(as_t *a, int id)
{
    a->lab[id] = a->n;
    a->lab_set[id] = 1;
    as_b(a, O_JUMPDEST);
}

static void as_ref(as_t *a, int id)
{
    if (a->nfix >= AS_FIXES) {
        a->err = 1;
        return;
    }
    as_b(a, O_PUSH2);
    a->fix_at[a->nfix] = a->n;
    a->fix_lab[a->nfix++] = id;
    as_b(a, 0);
    as_b(a, 0);
}

static void as_jump(as_t *a, int id)
{
    as_ref(a, id);
    as_b(a, O_JUMP);
}

/* JUMPI pops destination, then condition (control_flow.py jumpi) */
static void as_jumpi(as_t *a, int id)
{
    as_ref(a, id);
    as_b(a, O_JUMPI);
}

/* if GAS < thresh goto end. Cost: PUSHn 3 + GAS 2 + LT 3 + PUSH2 3 +
 * JUMPI 10 = 21 gas. */
static void as_guard_const(as_t *a, uint64_t thresh, int end)
{
    as_pushu(a, thresh);
    as_b(a, O_GAS);
    as_b(a, O_LT);
    as_jumpi(a, end);
}

/* if GAS < calldata word i goto end */
static void as_guard_cd(as_t *a, unsigned i, int end)
{
    as_cdw(a, i);
    as_b(a, O_GAS);
    as_b(a, O_LT);
    as_jumpi(a, end);
}

static int as_finish(as_t *a, uint8_t **code, size_t *len)
{
    if (a->err) return -2;
    for (int i = 0; i < a->nfix; i++) {
        int id = a->fix_lab[i];
        if (!a->lab_set[id] || a->lab[id] > 0xffffu) return -2;
        a->b[a->fix_at[i]] = (uint8_t)(a->lab[id] >> 8);
        a->b[a->fix_at[i] + 1] = (uint8_t)a->lab[id];
    }
    *code = malloc(a->n);
    if (!*code) return -2;
    memcpy(*code, a->b, a->n);
    *len = a->n;
    return 0;
}

int wl_initcode(const uint8_t *rt, size_t rl, uint8_t **out, size_t *out_len)
{
    if (rl > 0xffffu) return -2;
    uint8_t *b = malloc(14 + rl);
    if (!b) return -2;
    const uint8_t hdr[14] = {
        O_PUSH2, (uint8_t)(rl >> 8), (uint8_t)rl,     /* size              */
        O_PUSH1, 14,                                  /* code_start        */
        O_PUSH1, 0,                                   /* memory_start      */
        O_CODECOPY,
        O_PUSH2, (uint8_t)(rl >> 8), (uint8_t)rl,     /* size              */
        O_PUSH1, 0,                                   /* start             */
        O_RETURN
    };
    memcpy(b, hdr, 14);
    if (rl) memcpy(b + 14, rt, rl);
    *out = b;
    *out_len = 14 + rl;
    return 0;
}

/* ══ the workload table ═══════════════════════════════════════════════ */

enum { K_OP = 1, K_KECCAK, K_MEMX, K_MCOPY, K_STORE, K_ACCT, K_DEPTH,
       K_CREATE, K_PC, K_LOG };

/* op-loop variants */
enum { OPV_JUMPDEST, OPV_ADD, OPV_MULMOD, OPV_DIV, OPV_EXP };
/* storage variants */
enum { STV_SSTORE_FRESH, STV_SLOAD_PRESENT, STV_SLOAD_ABSENT };
/* account variants */
enum { ACV_BALANCE, ACV_EXTCODESIZE, ACV_EXTCODECOPY };
/* create variants */
enum { CRV_CREATE2_MAXINIT, CRV_CREATE_MAXCODE, CRV_CREATE2_MAXCODE };
/* log variants */
enum { LGV_MAX, LGV_1K, LGV_0 };
/* keccak variants */
enum { KCV_32, KCV_4K, KCV_1M };
/* precompile variants */
enum {
    PCV_ECREC, PCV_SHA_32, PCV_SHA_32K, PCV_RIP_32, PCV_RIP_32K,
    PCV_ID_32, PCV_ID_32K,
    PCV_MX_FLOOR32, PCV_MX_FLOOR64, PCV_MX_FLOOR128, PCV_MX_1024E1,
    PCV_MX_1024E1_EVEN, PCV_MX_MAXEXP, PCV_MX_MAXEXP_EVEN,
    PCV_BN_ADD, PCV_BN_MUL, PCV_BN_PAIR1, PCV_BN_PAIRMAX,
    PCV_B2F_12, PCV_B2F_MAX, PCV_KZG,
    PCV_G1ADD, PCV_G2ADD, PCV_G1MSM1, PCV_G1MSM128, PCV_G1MSMMAX,
    PCV_G2MSM1, PCV_G2MSM128, PCV_G2MSMMAX, PCV_BLSPAIR1, PCV_BLSPAIRMAX,
    PCV_MAPG1, PCV_MAPG2
};

static const wl_def_t WL[] = {
    /* ── interpreter dispatch ───────────────────────────────────────── */
    { "op-jumpdest", WL_GROUP_OP, 1,
      "straight-line JUMPDEST x ~24 000 per pass: 1 gas per dispatched "
      "instruction, the most instructions per gas (gas.py:138 "
      "OPCODE_JUMPDEST = 1)", K_OP, OPV_JUMPDEST },
    { "op-add", WL_GROUP_OP, 1,
      "DUP2 ADD repeated: 6 gas per 2 instructions (gas.py:112 "
      "OPCODE_ADD = VERY_LOW = 3, :165 OPCODE_DUP = 3)", K_OP, OPV_ADD },
    { "op-mulmod", WL_GROUP_OP, 1,
      "DUP3 DUP3 DUP3 MULMOD POP on full 256-bit operands: 512-bit "
      "product + reduction for 8 gas (gas.py:120 OPCODE_MULMOD = MID = 8)",
      K_OP, OPV_MULMOD },
    { "op-div", WL_GROUP_OP, 1,
      "DUP2 DUP2 DIV POP, (2^256-1) / (2^128+3): a 256/129-bit long "
      "division for 5 gas (gas.py:115 OPCODE_DIV = LOW = 5)",
      K_OP, OPV_DIV },
    { "op-exp", WL_GROUP_OP, 1,
      "DUP2 DUP2 EXP POP, 256-bit base ^ 0xff: 8 squarings + multiplies "
      "for 60 gas (gas.py:181-182 EXP_BASE 10 + 50 per exponent byte)",
      K_OP, OPV_EXP },
    /* ── KECCAK256 ──────────────────────────────────────────────────── */
    { "keccak-32", WL_GROUP_KECCAK, 1,
      "KECCAK256 of 32 bytes in a loop: per-call overhead, 36 gas "
      "(gas.py:183-184 KECCAK256_BASE 30 + 6 per word)", K_KECCAK, KCV_32 },
    { "keccak-4k", WL_GROUP_KECCAK, 1,
      "KECCAK256 of 4 KiB in a loop: 6 gas per 32 bytes "
      "(gas.py:184)", K_KECCAK, KCV_4K },
    { "keccak-1m", WL_GROUP_KECCAK, 1,
      "KECCAK256 of 1 MiB (memory paid once, gas.py:247) in a loop: the "
      "large-memory hash rate, 6 gas per 32 bytes (gas.py:184)",
      K_KECCAK, KCV_1M },
    /* ── memory ─────────────────────────────────────────────────────── */
    { "mem-expand-max", WL_GROUP_MEM, 1,
      "ONE MSTORE8 at the largest offset the tx gas pays for: memory "
      "expansion to the gas-bounded maximum (gas.py:247-267, 3*w + "
      "w^2/512 — ~3.9 MB at 30 M gas)", K_MEMX, 0 },
    { "mem-mcopy-256k", WL_GROUP_MEM, 1,
      "MCOPY 256 KiB -> 256 KiB in a loop: 3 gas per word copied "
      "(instructions/memory.py:145 mcopy, gas.py:179 COPY_PER_WORD)",
      K_MCOPY, 0 },
    /* ── storage ────────────────────────────────────────────────────── */
    { "sstore-fresh", WL_GROUP_STORAGE, 1,
      "SSTORE value 1 into distinct never-written slots: 22 100 gas each "
      "(instructions/storage.py:63 sstore: COLD_STORAGE_ACCESS 2 100 "
      "gas.py:45 + STORAGE_SET 20 000 gas.py:48) — the most slot writes "
      "per gas", K_STORE, STV_SSTORE_FRESH },
    { "sload-present", WL_GROUP_STORAGE, 1,
      "SLOAD of distinct cold slots that EXIST (engine: pre-filled in the "
      "backend; node: written by sstore-fresh blocks first): 2 100 gas "
      "each (storage.py:32, gas.py:45) — the most backend reads per gas",
      K_STORE, STV_SLOAD_PRESENT },
    { "sload-absent", WL_GROUP_STORAGE, 1,
      "SLOAD of distinct cold slots that do NOT exist (a miss per read; "
      "same 2 100 gas, gas.py:45)", K_STORE, STV_SLOAD_ABSENT },
    /* ── cold accounts ──────────────────────────────────────────────── */
    { "acct-balance", WL_GROUP_ACCOUNT, 1,
      "BALANCE of distinct cold addresses: 2 600 gas each "
      "(environment.py:57, gas.py:44 COLD_ACCOUNT_ACCESS). Engine: the "
      "accounts exist (pre-filled); node: they do not (a miss per read)",
      K_ACCT, ACV_BALANCE },
    { "acct-extcodesize", WL_GROUP_ACCOUNT, 1,
      "EXTCODESIZE of distinct cold addresses: 2 600 gas each "
      "(environment.py:329, gas.py:44). Engine: accounts exist; node: "
      "absent", K_ACCT, ACV_EXTCODESIZE },
    { "acct-extcodecopy-24k", WL_GROUP_ACCOUNT, 0,
      "EXTCODECOPY 32 bytes from distinct cold accounts each holding a "
      "24 576-byte code: the engine loads the whole code "
      "(evm_interp.c EXTCODECOPY -> evm_st_get_code) for 2 600 + 3 gas "
      "(environment.py:362, gas.py:44,179). ENGINE ONLY (needs pre-filled "
      "code)", K_ACCT, ACV_EXTCODECOPY },
    /* ── call depth ─────────────────────────────────────────────────── */
    { "depth-staticcall", WL_GROUP_CALL, 1,
      "self-STATICCALL recursion until the 63/64 rule (gas.py:354) "
      "starves it (~600 frames at 30 M), repeated: ~120 gas per frame "
      "(WARM_ACCESS 100, gas.py:43; system.py:657)", K_DEPTH, 0 },
    { "depth-call", WL_GROUP_CALL, 1,
      "the same recursion through CALL value 0 (system.py:351)",
      K_DEPTH, 1 },
    /* ── create ─────────────────────────────────────────────────────── */
    { "create2-maxinit", WL_GROUP_CREATE, 1,
      "CREATE2 with a 49 152-byte (EIP-3860 max) all-STOP initcode, salt "
      "counter: initcode hashed + analysed, empty code deployed; 32 000 + "
      "2/word + 6/word (gas.py:180,58,184; system.py:184)",
      K_CREATE, CRV_CREATE2_MAXINIT },
    { "create-maxcode", WL_GROUP_CREATE, 1,
      "CREATE with a 49 152-byte initcode returning 24 576 zero bytes "
      "(EIP-170 max code): code deposit 200/byte (gas.py:57) dominates "
      "(system.py:138)", K_CREATE, CRV_CREATE_MAXCODE },
    { "create2-maxcode", WL_GROUP_CREATE, 1,
      "the same through CREATE2 (adds the initcode hash, gas.py:184)",
      K_CREATE, CRV_CREATE2_MAXCODE },
    /* ── precompiles (STATICCALL loop, inputs from evm_precompile.c
     *    PC_KATS — execution-specs test vectors cited there) ─────────── */
    { "pc-ecrecover", WL_GROUP_PRECOMPILE, 1,
      "ecrecover of a VALID signature (full recovery): 3 000 gas "
      "(gas.py:73)", K_PC, PCV_ECREC },
    { "pc-sha256-32", WL_GROUP_PRECOMPILE, 1,
      "sha256 of 32 bytes: 72 gas, call overhead bound (gas.py:74-75)",
      K_PC, PCV_SHA_32 },
    { "pc-sha256-32k", WL_GROUP_PRECOMPILE, 1,
      "sha256 of 32 KiB: 60 + 12 per word (gas.py:74-75)",
      K_PC, PCV_SHA_32K },
    { "pc-ripemd160-32", WL_GROUP_PRECOMPILE, 1,
      "ripemd160 of 32 bytes: 720 gas (gas.py:76-77)", K_PC, PCV_RIP_32 },
    { "pc-ripemd160-32k", WL_GROUP_PRECOMPILE, 1,
      "ripemd160 of 32 KiB: 600 + 120 per word (gas.py:76-77)",
      K_PC, PCV_RIP_32K },
    { "pc-identity-32", WL_GROUP_PRECOMPILE, 1,
      "identity of 32 bytes: 18 gas, call overhead bound (gas.py:78-79)",
      K_PC, PCV_ID_32 },
    { "pc-identity-32k", WL_GROUP_PRECOMPILE, 1,
      "identity of 32 KiB: 15 + 3 per word (gas.py:78-79)",
      K_PC, PCV_ID_32K },
    { "pc-modexp-floor-32", WL_GROUP_PRECOMPILE, 1,
      "modexp 32-byte base/modulus, 38-bit exponent: the most work at the "
      "200-gas floor for this size (precompiled_contracts/modexp.py:132-166"
      ", EIP-2565)", K_PC, PCV_MX_FLOOR32 },
    { "pc-modexp-floor-64", WL_GROUP_PRECOMPILE, 1,
      "modexp 64-byte base/modulus, 10-bit exponent, at the 200-gas floor "
      "(modexp.py:132-166)", K_PC, PCV_MX_FLOOR64 },
    { "pc-modexp-floor-128", WL_GROUP_PRECOMPILE, 1,
      "modexp 128-byte base/modulus, 3-bit exponent, at the 200-gas floor "
      "(modexp.py:132-166)", K_PC, PCV_MX_FLOOR128 },
    { "pc-modexp-1024-e1", WL_GROUP_PRECOMPILE, 1,
      "modexp 1024-byte (EIP-7823 bound) base/odd modulus, exponent 3 "
      "(iteration count 1): 128^2/3 = 5 461 gas for 8 192-bit arithmetic "
      "(modexp.py:132-166)", K_PC, PCV_MX_1024E1 },
    { "pc-modexp-1024-e1-even", WL_GROUP_PRECOMPILE, 1,
      "as pc-modexp-1024-e1 with an EVEN modulus (no Montgomery form in "
      "GMP mpz_powm)", K_PC, PCV_MX_1024E1_EVEN },
    { "pc-modexp-maxexp", WL_GROUP_PRECOMPILE, 1,
      "modexp, 1024-byte all-0xff exponent (iteration count 8 191), the "
      "largest base/odd modulus whose price fits ONE call in the tx "
      "(modexp.py:132-166; EIP-7823 bound 1024)", K_PC, PCV_MX_MAXEXP },
    { "pc-modexp-maxexp-even", WL_GROUP_PRECOMPILE, 1,
      "as pc-modexp-maxexp with an even modulus", K_PC,
      PCV_MX_MAXEXP_EVEN },
    { "pc-bn-add", WL_GROUP_PRECOMPILE, 1,
      "alt_bn128 add: 150 gas (gas.py:88)", K_PC, PCV_BN_ADD },
    { "pc-bn-mul", WL_GROUP_PRECOMPILE, 1,
      "alt_bn128 mul of G1 by a 256-bit all-ones scalar: 6 000 gas "
      "(gas.py:89)", K_PC, PCV_BN_MUL },
    { "pc-bn-pair-1", WL_GROUP_PRECOMPILE, 1,
      "alt_bn128 pairing, 1 pair: 45 000 + 34 000 (gas.py:90-91) — the "
      "base price covers the final exponentiation", K_PC, PCV_BN_PAIR1 },
    { "pc-bn-pair-max", WL_GROUP_PRECOMPILE, 1,
      "alt_bn128 pairing with the most pairs that fit ONE call "
      "(gas.py:90-91)", K_PC, PCV_BN_PAIRMAX },
    { "pc-blake2f-12", WL_GROUP_PRECOMPILE, 1,
      "blake2f 12 rounds: 12 gas, call overhead bound (gas.py:80)",
      K_PC, PCV_B2F_12 },
    { "pc-blake2f-max", WL_GROUP_PRECOMPILE, 1,
      "blake2f with the most rounds that fit ONE call: 1 gas per round "
      "(gas.py:80 PRECOMPILE_BLAKE2F_PER_ROUND)", K_PC, PCV_B2F_MAX },
    { "pc-kzg", WL_GROUP_PRECOMPILE, 1,
      "KZG point evaluation of a VALID proof: 50 000 gas (gas.py:81)",
      K_PC, PCV_KZG },
    { "pc-bls-g1add", WL_GROUP_PRECOMPILE, 1,
      "BLS12-381 G1 add: 375 gas (gas.py:82)", K_PC, PCV_G1ADD },
    { "pc-bls-g2add", WL_GROUP_PRECOMPILE, 1,
      "BLS12-381 G2 add: 600 gas (gas.py:85)", K_PC, PCV_G2ADD },
    { "pc-bls-g1msm-1", WL_GROUP_PRECOMPILE, 1,
      "BLS12-381 G1 MSM, 1 point (subgroup check + mul): 12 000 gas "
      "(gas.py:83)", K_PC, PCV_G1MSM1 },
    { "pc-bls-g1msm-128", WL_GROUP_PRECOMPILE, 1,
      "G1 MSM, 128 points (max discount 519/1000 reached; "
      "bls12_381/__init__.py:299-301)", K_PC, PCV_G1MSM128 },
    { "pc-bls-g1msm-max", WL_GROUP_PRECOMPILE, 1,
      "G1 MSM with the most points that fit ONE call (discount 519)",
      K_PC, PCV_G1MSMMAX },
    { "pc-bls-g2msm-1", WL_GROUP_PRECOMPILE, 1,
      "BLS12-381 G2 MSM, 1 point: 22 500 gas (gas.py:86)",
      K_PC, PCV_G2MSM1 },
    { "pc-bls-g2msm-128", WL_GROUP_PRECOMPILE, 1,
      "G2 MSM, 128 points (discount 524/1000; __init__.py:300)",
      K_PC, PCV_G2MSM128 },
    { "pc-bls-g2msm-max", WL_GROUP_PRECOMPILE, 1,
      "G2 MSM with the most points that fit ONE call", K_PC, PCV_G2MSMMAX },
    { "pc-bls-pair-1", WL_GROUP_PRECOMPILE, 1,
      "BLS12-381 pairing, 1 pair: 37 700 + 32 600 "
      "(bls12_381/bls12_381_pairing.py:45)", K_PC, PCV_BLSPAIR1 },
    { "pc-bls-pair-max", WL_GROUP_PRECOMPILE, 1,
      "BLS12-381 pairing with the most pairs that fit ONE call "
      "(bls12_381_pairing.py:45)", K_PC, PCV_BLSPAIRMAX },
    { "pc-bls-map-g1", WL_GROUP_PRECOMPILE, 1,
      "BLS12-381 map Fp -> G1: 5 500 gas (gas.py:84)", K_PC, PCV_MAPG1 },
    { "pc-bls-map-g2", WL_GROUP_PRECOMPILE, 1,
      "BLS12-381 map Fp2 -> G2: 23 800 gas (gas.py:87)", K_PC, PCV_MAPG2 },
    /* ── logs ───────────────────────────────────────────────────────── */
    { "log4-max", WL_GROUP_LOG, 1,
      "ONE LOG4 with the largest data the tx gas pays for (memory + 8 "
      "per byte; gas.py:185-187, instructions/log.py:31)", K_LOG, LGV_MAX },
    { "log4-1k", WL_GROUP_LOG, 1,
      "LOG4 of 1 KiB in a loop (gas.py:185-187)", K_LOG, LGV_1K },
    { "log4-0", WL_GROUP_LOG, 1,
      "LOG4 with no data in a loop: 1 875 gas per log record "
      "(gas.py:185,187)", K_LOG, LGV_0 },
};

size_t wl_count(void) { return sizeof(WL) / sizeof(WL[0]); }

const wl_def_t *wl_get(size_t i) { return i < wl_count() ? &WL[i] : NULL; }

const wl_def_t *wl_find(const char *name)
{
    for (size_t i = 0; i < wl_count(); i++)
        if (strcmp(WL[i].name, name) == 0) return &WL[i];
    return NULL;
}

/* ══ precompile inputs ════════════════════════════════════════════════
 * Copied from shared/evm/evm_precompile.c PC_KATS (the sources of each
 * vector are cited there: execution-specs@a87891f7 tests/). A copying
 * error cannot pass silently: wl_build runs every input through
 * evm_precompile_run and refuses anything but EVM_PC_OK with the
 * expected output length. */

/* 0x01 frontier/precompiles/test_ecrecover.py id=valid_signature_1 */
static const char KAT_ECREC[] =
    "18c547e4f7b0f325ad1e56f57e26c745b09a3e503d86e00e5255ff7f715d3d1c"
    "000000000000000000000000000000000000000000000000000000000000001c"
    "73b1693892219d736caba55bdb67216e485557ea6b6af75f37096c9aa6a5a75f"
    "eeb940b1d03b21e36b0e47e79769f095fe2ab855bd91e3a38756b7d75a9c4549";
/* 0x06 byzantium/eip196_ec_add_mul/test_ecadd.py id=p1_plus_q1 */
static const char KAT_BN_ADD[] =
    "17c139df0efee0f766bc0204762b774362e4ded88953a39ce849a8a7fa163fa9"
    "01e0559bacb160664764a357af8a9fe70baa9258e0b959273ffc5718c6d4cc7c"
    "039730ea8dff1254c0fee9c0ea777d29a9c710b7e616683f194f18c43b43b869"
    "073a5ffcc6fc7a28c30723d6e58ce577356982d65b833a5a5c15bf9024b43d98";
/* 0x08 byzantium/eip197_ec_pairing/test_ecpairing.py id=one_pair:
 * G1 (1, 2) ‖ the G2 point used there */
static const char KAT_BN_PAIR1[] =
    "0000000000000000000000000000000000000000000000000000000000000001"
    "0000000000000000000000000000000000000000000000000000000000000002"
    "198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2"
    "1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed"
    "090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b"
    "12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa";
/* 0x09 istanbul/eip152_blake2/test_blake2.py id=valid-rounds-12 */
static const char KAT_B2F[] =
    "0000000c"
    "48c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5"
    "d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b"
    "6162630000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0300000000000000" "0000000000000000" "01";
/* 0x0a cancun/eip4844_blobs/point_evaluation_vectors/
 * go_kzg_4844_verify_kzg_proof.json
 * verify_kzg_proof_case_correct_proof_26b753dec0560daa */
static const char KAT_KZG[] =
    "01ad7666ef9d8f53b5adf54f029b13b6f171b1d0bd346a2ede315d3e243484ef"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "73e66878b46ae3705eb6a46a89213de7d3686828bfce5c19400fffff00100001"
    "93efc82d2017e9c57834a1246463e64774e56183bb247c8fc9dd98c56817e878"
    "d97b05f5c8d900acf1fbbbca6f146556"
    "b82ded761997f2c6f1bb3db1e1dada2ef06d936551667c82f659b75f99d2da20"
    "68b81340823ee4e829a93c9fbed7810d";
/* 0x0b prague/eip2537_bls_12_381_precompiles/vectors/add_G1_bls.json
 * bls_g1add_g1+p1 (bytes 0..127 = the G1 generator) */
static const char KAT_G1ADD[] =
    "0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0f"
    "c3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"
    "0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4"
    "fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1"
    "00000000000000000000000000000000112b98340eee2777cc3c14163dea3ec9"
    "7977ac3dc5c70da32e6e87578f44912e902ccef9efe28d4a78b8999dfbca9426"
    "00000000000000000000000000000000186b28d92356c4dfec4b5201ad099dbd"
    "ede3781f8998ddf929b4cd7756192185ca7b8f4ef7088f813270ac3d48868a21";
/* 0x0f pairing_check_bls.json bls_pairing_e(aG1,bG2)=e(abG1,G2):
 * [G1 aG1 | G2 bG2 | G1 | G2 = the G2 generator]; bytes 128..383 (bG2)
 * and 512..767 (the generator) are two valid G2 points */
static const char KAT_BLS_PAIR_A[] =
    "000000000000000000000000000000000491d1b0ecd9bb917989f0e74f0dea04"
    "22eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a"
    "0000000000000000000000000000000017cd7061575d3e8034fcea62adaa1a3b"
    "c38dca4b50e4c5c01d04dd78037c9cee914e17944ea99e7ad84278e5d49f36c4"
    "000000000000000000000000000000000bc2357c6782bbb6a078d9e171fc7a81"
    "f7bd8ca73eb485e76317359908bb09bd372fd362a637512a9d48019b383e5489"
    "0000000000000000000000000000000004b8f49c3bac0247a09487049492b0ed"
    "99cf90c56263141daa35f011330d3ced3f3ad78d252c51a3bb42fc7d8f182594"
    "000000000000000000000000000000000982d17b17404ac198a0ff5f2dffa56a"
    "328d95ec4732d9cca9da420ec7cf716dc63d56d0f5179a8b1ec71fe0328fe882"
    "00000000000000000000000000000000147c92cb19e43943bb20c5360a6c4347"
    "411eb8ffb3d6f19cc428a8dc0cb3fd1eb3ad02b1c21e21c78f65a7691ee63de9"
    "0000000000000000000000000000000016cae74dc6523e5273dbd2d9d25c53f1"
    "e2c453e6d9ba3f605021cfb514fa0bdf721b05f2200f32591d733e739fabf438"
    "000000000000000000000000000000001405df65fb71b738510b3a2fc31c33ef"
    "3d884ccc84efb1017341a368bf40727b7ad8cdc8e3fd6b0eb94102488c5cb770"
    "00000000000000000000000000000000024aa2b2f08f0a91260805272dc51051"
    "c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8"
    "0000000000000000000000000000000013e02b6052719f607dacd3a088274f65"
    "596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e"
    "000000000000000000000000000000000d1b3cc2c7027888be51d9ef691d77bc"
    "b679afda66c73f17f9ee3837a55024f78c71363275a75d75d86bab79f74782aa"
    "0000000000000000000000000000000013fa4d4a0ad8b1ce186ed5061789213d"
    "993923066dddaf1040bc3ff59f825c78df74f2d75467e25e0f55f8a00fa030ed";
/* 0x0f pairing_check_bls.json bls_pairing_non-degeneracy_e(P,Q)!= 1:
 * bytes 0..383 = (G1 generator, G2 generator) */
static const char KAT_BLS_PAIR_B[] =
    "0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0f"
    "c3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"
    "0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4"
    "fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1"
    "00000000000000000000000000000000024aa2b2f08f0a91260805272dc51051"
    "c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8"
    "0000000000000000000000000000000013e02b6052719f607dacd3a088274f65"
    "596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e"
    "000000000000000000000000000000000ce5d527727d6e118cc9cdc6da2e351a"
    "adfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801"
    "000000000000000000000000000000000606c4a02ea734cc32acd2b02bc28b99"
    "cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be";
/* 0x11 map_fp2_to_G2_bls.json bls_g2map_ (one Fp2 element; its first
 * 64 bytes are one canonical Fp element, used for map Fp -> G1) */
static const char KAT_MAP_G2[] =
    "0000000000000000000000000000000007355d25caf6e7f2f0cb2812ca0e513b"
    "d026ed09dda65b177500fa31714e09ea0ded3a078b526bed3307f804d4b93b04"
    "0000000000000000000000000000000002829ce3c021339ccb5caf3e187f6370"
    "e1e2a311dec9b75363117063ab2015603ff52c3d3b98f19c2f65575e99e8b78c";

/* ══ code builders ════════════════════════════════════════════════════ */

static void push_fill(as_t *a, uint8_t fill_first, uint8_t fill)
{
    uint8_t w[32];
    memset(w, fill, 32);
    w[0] = fill_first;
    as_push(a, w, 32);
}

/* op loops: LOOP: guard; body x reps; JUMP LOOP; END: STOP */
static int code_op(int var, uint8_t **code, size_t *len, uint64_t *slack)
{
    as_t *a = calloc(1, sizeof(*a));
    if (!a) return -2;
    uint8_t body[5];
    size_t bl = 0;
    uint64_t bg = 0;
    switch (var) {
    case OPV_JUMPDEST:
        body[bl++] = O_JUMPDEST;
        bg = 1;
        break;
    case OPV_ADD:                                  /* [1, 2]                */
        as_pushu(a, 1);
        as_pushu(a, 2);
        body[bl++] = O_DUP2;                       /* [a, b, a]             */
        body[bl++] = O_ADD;                        /* [a, a + b]            */
        bg = 3 + 3;
        break;
    case OPV_MULMOD:
        /* arithmetic.py:265 mulmod pops x, y, z: (x * y) % z. Stack
         * [A, B, C] -> DUP3 x3 -> [A, B, C, A, B, C]: x = C, y = B,
         * z = A (the modulus, pushed first). */
        push_fill(a, 0xff, 0xff);                  /* A = 2^256 - 1 - ...   */
        a->b[a->n - 1] = 0x43;                     /*   ...ff43, odd        */
        push_fill(a, 0xfe, 0xdc);                  /* B                     */
        push_fill(a, 0xfd, 0xba);                  /* C                     */
        body[bl++] = O_DUP3;
        body[bl++] = O_DUP3;
        body[bl++] = O_DUP3;
        body[bl++] = O_MULMOD;
        body[bl++] = O_POP;
        bg = 3 + 3 + 3 + 8 + 2;
        break;
    case OPV_DIV: {
        /* arithmetic.py:108 div pops dividend, then divisor. Stack
         * [divisor, dividend] -> DUP2 DUP2 -> dividend on top. */
        uint8_t d[32];
        memset(d, 0, 32);
        d[15] = 0x01;                              /* 2^128 + 3             */
        d[31] = 0x03;
        as_push(a, d, 32);
        push_fill(a, 0xff, 0xff);                  /* 2^256 - 1             */
        body[bl++] = O_DUP2;
        body[bl++] = O_DUP2;
        body[bl++] = O_DIV;
        body[bl++] = O_POP;
        bg = 3 + 3 + 5 + 2;
        break;
    }
    case OPV_EXP:
        /* arithmetic.py:296 exp pops base, then exponent. Stack
         * [exponent, base] -> DUP2 DUP2 -> base on top. */
        as_pushu(a, 0xff);                         /* exponent, 1 byte      */
        push_fill(a, 0xfe, 0xa7);                  /* base                  */
        body[bl++] = O_DUP2;
        body[bl++] = O_DUP2;
        body[bl++] = O_EXP;
        body[bl++] = O_POP;
        bg = 3 + 3 + (10 + 50) + 2;
        break;
    default:
        free(a);
        return -2;
    }
    size_t pro = a->n;
    /* fixed per pass: JUMPDEST 1, guard <= 4 + 21 bytes, PUSH2+JUMP 4,
     * END 2 */
    size_t reps = (OPLOOP_CODE_TARGET - pro - 40) / bl;
    /* one pass: body + JUMPDEST 1 + guard 21 + PUSH2 3 + JUMP 8 */
    uint64_t pass = bg * (uint64_t)reps + 33;
    uint64_t thresh = pass + 64;
    as_label(a, 0);
    as_guard_const(a, thresh, 1);
    for (size_t r = 0; r < reps; r++)
        for (size_t i = 0; i < bl; i++) as_b(a, body[i]);
    as_jump(a, 0);
    as_label(a, 1);
    as_b(a, O_STOP);
    *slack = thresh;
    int rc = as_finish(a, code, len);
    free(a);
    return rc;
}

/* KECCAK: calldata w0 = L, w1 = thresh.
 * keccak.py:29 keccak pops memory_start, then size. */
static int code_keccak(uint8_t **code, size_t *len)
{
    as_t *a = calloc(1, sizeof(*a));
    if (!a) return -2;
    as_label(a, 0);
    as_guard_cd(a, 1, 1);
    as_cdw(a, 0);                                  /* size                  */
    as_pushu(a, 0);                                /* start                 */
    as_b(a, O_KECCAK256);
    as_b(a, O_POP);
    as_jump(a, 0);
    as_label(a, 1);
    as_b(a, O_STOP);
    int rc = as_finish(a, code, len);
    free(a);
    return rc;
}

/* MEMX: calldata w0 = offset. memory.py:60 mstore8 pops start, value. */
static int code_memx(uint8_t **code, size_t *len)
{
    as_t *a = calloc(1, sizeof(*a));
    if (!a) return -2;
    as_pushu(a, 0);                                /* value                 */
    as_cdw(a, 0);                                  /* start = offset        */
    as_b(a, O_MSTORE8);
    as_b(a, O_STOP);
    int rc = as_finish(a, code, len);
    free(a);
    return rc;
}

/* MCOPY: calldata w0 = M, w1 = thresh. Expand to 2M once, then
 * MCOPY(dest 0, src M, len M) (memory.py:145 mcopy pops destination,
 * source, length). */
static int code_mcopy(uint8_t **code, size_t *len)
{
    as_t *a = calloc(1, sizeof(*a));
    if (!a) return -2;
    as_pushu(a, 0);                                /* value                 */
    as_cdw(a, 0);
    as_b(a, O_DUP1);
    as_b(a, O_ADD);                                /* [0, 2M]               */
    as_pushu(a, 1);
    as_b(a, O_SWAP1);
    as_b(a, O_SUB);                                /* [0, 2M - 1]           */
    as_b(a, O_MSTORE8);
    as_label(a, 0);
    as_guard_cd(a, 1, 1);
    as_cdw(a, 0);                                  /* length = M            */
    as_b(a, O_DUP1);                               /* source = M            */
    as_pushu(a, 0);                                /* destination = 0       */
    as_b(a, O_MCOPY);
    as_jump(a, 0);
    as_label(a, 1);
    as_b(a, O_STOP);
    int rc = as_finish(a, code, len);
    free(a);
    return rc;
}

/* STORAGE (sstore-fresh / sload-*): calldata w0 = mode (0 store, else
 * load), w1 = first slot. storage.py:63 sstore pops key, then value;
 * storage.py:32 sload pops key. */
static int code_storage(uint8_t **code, size_t *len)
{
    as_t *a = calloc(1, sizeof(*a));
    if (!a) return -2;
    as_cdw(a, 1);                                  /* [slot]                */
    as_cdw(a, 0);                                  /* [slot, mode]          */
    as_jumpi(a, 1);                                /* mode != 0 -> LOAD     */
    as_label(a, 0);                                /* STORE loop            */
    as_guard_const(a, 25000, 2);
    as_pushu(a, 1);                                /* value                 */
    as_b(a, O_DUP2);                               /* key = slot            */
    as_b(a, O_SSTORE);
    as_pushu(a, 1);
    as_b(a, O_ADD);
    as_jump(a, 0);
    as_label(a, 1);                                /* LOAD loop             */
    as_guard_const(a, 5000, 2);
    as_b(a, O_DUP1);
    as_b(a, O_SLOAD);
    as_b(a, O_POP);
    as_pushu(a, 1);
    as_b(a, O_ADD);
    as_jump(a, 1);
    as_label(a, 2);
    as_b(a, O_STOP);
    int rc = as_finish(a, code, len);
    free(a);
    return rc;
}

/* ACCT: calldata w0 = first address (32-byte word, incremented).
 * environment.py:57 balance / :329 extcodesize pop address;
 * :362 extcodecopy pops address, memory_start, code_start, size. */
static int code_acct(int var, uint8_t **code, size_t *len)
{
    as_t *a = calloc(1, sizeof(*a));
    if (!a) return -2;
    as_cdw(a, 0);                                  /* [addr]                */
    as_label(a, 0);
    as_guard_const(a, 5000, 1);
    if (var == ACV_BALANCE) {
        as_b(a, O_DUP1);
        as_b(a, O_BALANCE);
        as_b(a, O_POP);
    } else if (var == ACV_EXTCODESIZE) {
        as_b(a, O_DUP1);
        as_b(a, O_EXTCODESIZE);
        as_b(a, O_POP);
    } else {
        as_pushu(a, 32);                           /* size                  */
        as_pushu(a, 0);                            /* code_start            */
        as_pushu(a, 0);                            /* memory_start          */
        as_b(a, O_DUP4);                           /* address               */
        as_b(a, O_EXTCODECOPY);
    }
    as_pushu(a, 1);
    as_b(a, O_ADD);
    as_jump(a, 0);
    as_label(a, 1);
    as_b(a, O_STOP);
    int rc = as_finish(a, code, len);
    free(a);
    return rc;
}

/* push the self-call; system.py:657 staticcall pops gas, to, in_start,
 * in_size, out_start, out_size; :351 call adds value after `to`. */
static void depth_call(as_t *a, int use_call)
{
    as_pushu(a, 0);                                /* out_size              */
    as_pushu(a, 0);                                /* out_start             */
    as_pushu(a, 0);                                /* in_size               */
    as_pushu(a, 0);                                /* in_start              */
    if (use_call) as_pushu(a, 0);                  /* value                 */
    as_b(a, O_ADDRESS);                            /* to = self             */
    as_b(a, O_GAS);
    as_b(a, use_call ? O_CALL : O_STATICCALL);
    as_b(a, O_POP);
}

/* DEPTH: top-level call (calldata non-empty) loops the recursion; an
 * inner frame (empty calldata) calls itself once and stops. */
static int code_depth(int use_call, uint8_t **code, size_t *len)
{
    as_t *a = calloc(1, sizeof(*a));
    if (!a) return -2;
    as_b(a, O_CALLDATASIZE);
    as_jumpi(a, 0);
    depth_call(a, use_call);
    as_b(a, O_STOP);
    as_label(a, 0);
    as_label(a, 1);
    as_guard_const(a, 100000, 2);
    depth_call(a, use_call);
    as_jump(a, 1);
    as_label(a, 2);
    as_b(a, O_STOP);
    int rc = as_finish(a, code, len);
    free(a);
    return rc;
}

#define CR_INIT_SIZE  0xC000u                      /* 49 152 (EIP-3860)     */
#define CR_THRESH_INIT 70000u
#define CR_THRESH_CODE 5200000u

/* CREATE / CREATE2 (system.py:138 create pops endowment, start, size;
 * :184 create2 adds salt after size). The max-code initcode is
 * PUSH2 0x6000 PUSH1 0 RETURN = 61 60 00 60 00 f3 at memory 0 (written
 * once with MSTORE, memory.py:29 pops start, value); the rest of the
 * 49 152 bytes are zero. The max-init initcode is all zero (STOP). */
static int code_create(int var, uint8_t **code, size_t *len, uint64_t *slack)
{
    as_t *a = calloc(1, sizeof(*a));
    if (!a) return -2;
    uint64_t thresh = CR_THRESH_INIT;
    if (var != CRV_CREATE2_MAXINIT) {
        uint8_t w[32];
        memset(w, 0, 32);
        w[0] = O_PUSH2;
        w[1] = 0x60;
        w[2] = 0x00;
        w[3] = O_PUSH1;
        w[4] = 0x00;
        w[5] = O_RETURN;
        as_push(a, w, 32);                         /* value                 */
        as_pushu(a, 0);                            /* start                 */
        as_b(a, O_MSTORE);
        thresh = CR_THRESH_CODE;
    }
    int is2 = (var != CRV_CREATE_MAXCODE);
    if (is2) as_pushu(a, 0);                       /* [salt counter]        */
    as_label(a, 0);
    as_guard_const(a, thresh, 1);
    if (is2) as_b(a, O_DUP1);                      /* salt                  */
    as_pushu(a, CR_INIT_SIZE);                     /* size                  */
    as_pushu(a, 0);                                /* start                 */
    as_pushu(a, 0);                                /* endowment             */
    as_b(a, is2 ? O_CREATE2 : O_CREATE);
    as_b(a, O_POP);
    if (is2) {
        as_pushu(a, 1);
        as_b(a, O_ADD);
    }
    as_jump(a, 0);
    as_label(a, 1);
    as_b(a, O_STOP);
    *slack = thresh;
    int rc = as_finish(a, code, len);
    free(a);
    return rc;
}

/* TOTAL = calldata w2 (k) * w1 (u) */
static void as_total(as_t *a)
{
    as_cdw(a, 2);
    as_cdw(a, 1);
    as_b(a, O_MUL);
}

/* PCLOOP: calldata w0 = precompile address word, w1 = u (unit bytes),
 * w2 = k (units), w3 = out_len, w4 = thresh, w5 = pre-expansion offset,
 * then the unit at 0xC0. memory[0, u) = unit (environment.py:207
 * calldatacopy pops memory_start, data_start, size), replicated k times
 * with MCOPY, memory pre-expanded over the output region, then
 * STATICCALL(GAS, addr, 0, total, total, out_len) in a guarded loop. */
#define PC_DATA_OFF 0xC0u
static int code_pcloop(uint8_t **code, size_t *len)
{
    as_t *a = calloc(1, sizeof(*a));
    if (!a) return -2;
    as_cdw(a, 1);                                  /* size = u              */
    as_pushu(a, PC_DATA_OFF);                      /* data_start            */
    as_pushu(a, 0);                                /* memory_start          */
    as_b(a, O_CALLDATACOPY);
    as_cdw(a, 1);                                  /* [off = u]             */
    as_label(a, 0);                                /* REP                   */
    as_b(a, O_DUP1);
    as_total(a);                                   /* [off, off, total]     */
    as_b(a, O_GT);                                 /* total > off           */
    as_b(a, O_ISZERO);
    as_jumpi(a, 1);                                /* done when !(total>off)*/
    as_cdw(a, 1);                                  /* length = u            */
    as_pushu(a, 0);                                /* source = 0            */
    as_b(a, O_DUP3);                               /* destination = off     */
    as_b(a, O_MCOPY);
    as_cdw(a, 1);
    as_b(a, O_ADD);                                /* off += u              */
    as_jump(a, 0);
    as_label(a, 1);                                /* REPDONE               */
    as_b(a, O_POP);
    as_pushu(a, 0);                                /* value                 */
    as_cdw(a, 5);                                  /* start                 */
    as_b(a, O_MSTORE8);
    as_label(a, 2);                                /* LOOP                  */
    as_guard_cd(a, 4, 3);
    as_cdw(a, 3);                                  /* out_size              */
    as_total(a);                                   /* out_start = total     */
    as_total(a);                                   /* in_size = total       */
    as_pushu(a, 0);                                /* in_start              */
    as_cdw(a, 0);                                  /* to                    */
    as_b(a, O_GAS);
    as_b(a, O_STATICCALL);
    as_b(a, O_POP);
    as_jump(a, 2);
    as_label(a, 3);
    as_b(a, O_STOP);
    int rc = as_finish(a, code, len);
    free(a);
    return rc;
}

/* LOG4: calldata w0 = L, w1 = thresh. log.py:31 log_n pops start, size,
 * then topic 1..4. */
static int code_log(uint8_t **code, size_t *len)
{
    as_t *a = calloc(1, sizeof(*a));
    if (!a) return -2;
    as_label(a, 0);
    as_guard_cd(a, 1, 1);
    as_pushu(a, 4);
    as_pushu(a, 3);
    as_pushu(a, 2);
    as_pushu(a, 1);
    as_cdw(a, 0);                                  /* size                  */
    as_pushu(a, 0);                                /* start                 */
    as_b(a, O_LOG4);
    as_jump(a, 0);
    as_label(a, 1);
    as_b(a, O_STOP);
    int rc = as_finish(a, code, len);
    free(a);
    return rc;
}

/* ══ calldata ═════════════════════════════════════════════════════════ */

static int data_words(wl_inst_t *w, const uint64_t *v, size_t n)
{
    w->data = calloc(n ? n : 1, 32);
    if (!w->data) return -2;
    for (size_t i = 0; i < n; i++) word_u64(w->data + 32 * i, v[i]);
    w->data_len = 32 * n;
    return 0;
}

void wl_set_slot_base(wl_inst_t *w, uint64_t slot_base)
{
    if (w && w->data && w->data_len >= 64) word_u64(w->data + 32, slot_base);
}

/* ══ precompile sizing ════════════════════════════════════════════════ */

typedef struct {
    uint8_t  addr;
    uint8_t *unit;
    size_t   u;
    uint64_t k;
    size_t   out_len;       /* expected output length; SIZE_MAX = total   */
} pcs_t;

/* gas spent before the first guard: intrinsic (all bytes counted
 * non-zero: conservative), CALLDATACOPY + replication MCOPYs, the memory
 * of input + output */
static uint64_t pc_overhead(size_t u, uint64_t k, uint64_t out_len)
{
    uint64_t total = (uint64_t)u * k;
    return 21000u + 16u * (PC_DATA_OFF + (uint64_t)u) +
           wl_mem_cost(total + out_len) + 3u * words_of(u) + 100u +
           k * (100u + 3u * words_of(u)) + 400u;
}

static int pc_fits(uint64_t gas, uint64_t cost, size_t u, uint64_t k,
                   uint64_t out_len)
{
    uint64_t need = pc_overhead(u, k, out_len) + cost + cost / 63u + PC_GUARD;
    return need <= gas;
}

static uint64_t modexp_cost(uint64_t bl, uint64_t el, uint64_t ml,
                            const uint8_t *ehead, size_t eh_len)
{
    /* modexp.py:132-166 (EIP-2565), mirrored by evm_precompile.c
     * pc_modexp — used for SIZING only; the exact cost is measured */
    uint64_t maxl = bl > ml ? bl : ml;
    uint64_t words = (maxl + 7u) / 8u;
    uint64_t hbits = 0;
    for (size_t i = 0; i < eh_len; i++) {
        if (ehead[i]) {
            uint8_t b = ehead[i];
            unsigned nb = 0;
            while (b) { nb++; b >>= 1; }
            hbits = (uint64_t)(eh_len - 1 - i) * 8u + nb;
            break;
        }
    }
    uint64_t iters;
    if (el <= 32 && hbits == 0) iters = 0;
    else if (el <= 32) iters = hbits - 1;
    else iters = 8u * (el - 32u) + (hbits > 0 ? hbits - 1 : 0);
    if (iters < 1) iters = 1;
    uint64_t c = words * words * iters / 3u;
    return c < 200u ? 200u : c;
}

/* modexp unit: 3 length words ‖ base (0xfe..) ‖ exponent ‖ modulus
 * (0xff.., last byte 0xfe when even) */
static int modexp_unit(pcs_t *s, uint64_t bl, const uint8_t *ex, uint64_t el,
                       uint64_t ml, int even)
{
    s->u = 96 + bl + el + ml;
    s->unit = calloc(1, s->u);
    if (!s->unit) return -2;
    word_u64(s->unit, bl);
    word_u64(s->unit + 32, el);
    word_u64(s->unit + 64, ml);
    memset(s->unit + 96, 0xfe, bl);
    memcpy(s->unit + 96 + bl, ex, el);
    memset(s->unit + 96 + bl + el, 0xff, ml);
    if (even && ml) s->unit[s->u - 1] = 0xfe;
    s->k = 1;
    s->out_len = ml;
    s->addr = 0x05;
    return 0;
}

static int unit_hex(pcs_t *s, uint8_t addr, const char *hex, size_t off,
                    size_t len, size_t out_len)
{
    uint8_t buf[1024];
    size_t n = unhex(hex, buf, sizeof(buf));
    if (n == 0 || off + len > n) return -2;
    s->unit = malloc(len);
    if (!s->unit) return -2;
    memcpy(s->unit, buf + off, len);
    s->u = len;
    s->k = 1;
    s->addr = addr;
    s->out_len = out_len;
    return 0;
}

/* largest k (>= kmin) whose formula price fits one call: 0 if none */
static uint64_t pc_kmax(uint64_t gas, size_t u, uint64_t out_len,
                        uint64_t base, uint64_t per_num, uint64_t per_den,
                        uint64_t kmin)
{
    uint64_t hi = gas / (per_num / per_den + 1u) + 2u;
    for (uint64_t k = hi; k >= kmin && k > 0; k--) {
        uint64_t cost = base + k * per_num / per_den;
        if (pc_fits(gas, cost, u, k, out_len)) return k;
    }
    return 0;
}

static int pc_spec(int var, uint64_t gas, pcs_t *s, char *msg, size_t cap)
{
    memset(s, 0, sizeof(*s));
    int rc = 0;
    uint8_t ex[1024];
    switch (var) {
    case PCV_ECREC:
        return unit_hex(s, 0x01, KAT_ECREC, 0, 128, 32);
    case PCV_SHA_32:
    case PCV_SHA_32K:
    case PCV_RIP_32:
    case PCV_RIP_32K:
    case PCV_ID_32:
    case PCV_ID_32K:
        s->u = 32;
        s->unit = calloc(1, 32);
        if (!s->unit) return -2;
        s->k = (var == PCV_SHA_32K || var == PCV_RIP_32K ||
                var == PCV_ID_32K) ? 1024u : 1u;
        s->addr = (var == PCV_SHA_32 || var == PCV_SHA_32K) ? 0x02 :
                  (var == PCV_RIP_32 || var == PCV_RIP_32K) ? 0x03 : 0x04;
        s->out_len = s->addr == 0x04 ? SIZE_MAX : 32;
        return 0;
    case PCV_MX_FLOOR32:
        ex[0] = 0x3f; memset(ex + 1, 0xff, 4);     /* 38 bits               */
        return modexp_unit(s, 32, ex, 5, 32, 0);
    case PCV_MX_FLOOR64:
        ex[0] = 0x03; ex[1] = 0xff;                /* 10 bits               */
        return modexp_unit(s, 64, ex, 2, 64, 0);
    case PCV_MX_FLOOR128:
        ex[0] = 0x07;                              /* 3 bits                */
        return modexp_unit(s, 128, ex, 1, 128, 0);
    case PCV_MX_1024E1:
    case PCV_MX_1024E1_EVEN:
        ex[0] = 0x03;                              /* iteration count 1     */
        return modexp_unit(s, 1024, ex, 1, 1024,
                           var == PCV_MX_1024E1_EVEN);
    case PCV_MX_MAXEXP:
    case PCV_MX_MAXEXP_EVEN: {
        memset(ex, 0xff, sizeof(ex));
        for (uint64_t ml = 1024; ml >= 8; ml -= 8) {
            uint64_t cost = modexp_cost(ml, 1024, ml, ex, 32);
            size_t u = 96 + ml + 1024 + ml;
            if (pc_fits(gas, cost, u, 1, ml))
                return modexp_unit(s, ml, ex, 1024, ml,
                                   var == PCV_MX_MAXEXP_EVEN);
        }
        msgf(msg, cap, "no modulus length fits one call at this gas");
        return -1;
    }
    case PCV_BN_ADD:
        return unit_hex(s, 0x06, KAT_BN_ADD, 0, 128, 64);
    case PCV_BN_MUL:
        rc = unit_hex(s, 0x07, KAT_BN_PAIR1, 0, 64, 64);
        if (rc) return rc;
        {
            uint8_t *n = realloc(s->unit, 96);
            if (!n) return -2;
            s->unit = n;
            memset(s->unit + 64, 0xff, 32);        /* scalar 2^256 - 1      */
            s->u = 96;
        }
        return 0;
    case PCV_BN_PAIR1:
        return unit_hex(s, 0x08, KAT_BN_PAIR1, 0, 192, 32);
    case PCV_BN_PAIRMAX:
        rc = unit_hex(s, 0x08, KAT_BN_PAIR1, 0, 192, 32);
        if (rc) return rc;
        s->k = pc_kmax(gas, 192, 32, 45000u, 34000u, 1u, 1u);
        break;
    case PCV_B2F_12:
        return unit_hex(s, 0x09, KAT_B2F, 0, 213, 64);
    case PCV_B2F_MAX: {
        rc = unit_hex(s, 0x09, KAT_B2F, 0, 213, 64);
        if (rc) return rc;
        uint64_t ov = pc_overhead(213, 1, 64) + PC_GUARD;
        if (ov >= gas) {
            msgf(msg, cap, "gas too small for blake2f-max");
            return -1;
        }
        uint64_t r = (gas - ov) * 63u / 64u;
        while (r > 0 && !pc_fits(gas, r, 213, 1, 64)) r--;
        if (r == 0 || r > 0xffffffffu) {
            msgf(msg, cap, "no round count fits one call at this gas");
            return -1;
        }
        s->unit[0] = (uint8_t)(r >> 24);
        s->unit[1] = (uint8_t)(r >> 16);
        s->unit[2] = (uint8_t)(r >> 8);
        s->unit[3] = (uint8_t)r;
        return 0;
    }
    case PCV_KZG:
        return unit_hex(s, 0x0a, KAT_KZG, 0, 192, 64);
    case PCV_G1ADD:
        return unit_hex(s, 0x0b, KAT_G1ADD, 0, 256, 128);
    case PCV_G2ADD: {
        uint8_t buf[768];
        if (unhex(KAT_BLS_PAIR_A, buf, sizeof(buf)) != 768) return -2;
        s->unit = malloc(512);
        if (!s->unit) return -2;
        memcpy(s->unit, buf + 128, 256);           /* bG2                   */
        memcpy(s->unit + 256, buf + 512, 256);     /* the G2 generator      */
        s->u = 512;
        s->k = 1;
        s->addr = 0x0d;
        s->out_len = 256;
        return 0;
    }
    case PCV_G1MSM1:
    case PCV_G1MSM128:
    case PCV_G1MSMMAX:
        rc = unit_hex(s, 0x0c, KAT_G1ADD, 0, 128, 128);
        if (rc) return rc;
        {
            uint8_t *n = realloc(s->unit, 160);
            if (!n) return -2;
            s->unit = n;
            memset(s->unit + 128, 0xff, 32);       /* scalar                */
            s->u = 160;
        }
        if (var == PCV_G1MSM128) s->k = 128;
        if (var == PCV_G1MSMMAX)                   /* k >= 128: discount 519 */
            s->k = pc_kmax(gas, 160, 128, 0, 12000u * 519u, 1000u, 128u);
        break;
    case PCV_G2MSM1:
    case PCV_G2MSM128:
    case PCV_G2MSMMAX:
        rc = unit_hex(s, 0x0e, KAT_BLS_PAIR_B, 128, 256, 256);
        if (rc) return rc;
        {
            uint8_t *n = realloc(s->unit, 288);
            if (!n) return -2;
            s->unit = n;
            memset(s->unit + 256, 0xff, 32);
            s->u = 288;
        }
        if (var == PCV_G2MSM128) s->k = 128;
        if (var == PCV_G2MSMMAX)                   /* k >= 128: discount 524 */
            s->k = pc_kmax(gas, 288, 256, 0, 22500u * 524u, 1000u, 128u);
        break;
    case PCV_BLSPAIR1:
        return unit_hex(s, 0x0f, KAT_BLS_PAIR_B, 0, 384, 32);
    case PCV_BLSPAIRMAX:
        rc = unit_hex(s, 0x0f, KAT_BLS_PAIR_B, 0, 384, 32);
        if (rc) return rc;
        s->k = pc_kmax(gas, 384, 32, 37700u, 32600u, 1u, 1u);
        break;
    case PCV_MAPG1:
        return unit_hex(s, 0x10, KAT_MAP_G2, 0, 64, 128);
    case PCV_MAPG2:
        return unit_hex(s, 0x11, KAT_MAP_G2, 0, 128, 256);
    default:
        return -2;
    }
    if (s->k == 0) {
        msgf(msg, cap, "no point/pair count fits one call at this gas");
        return -1;
    }
    return 0;
}

static int build_pc(int var, const wl_params_t *p, wl_inst_t *w, char *msg,
                    size_t cap)
{
    pcs_t s;
    int rc = pc_spec(var, p->gas_limit, &s, msg, cap);
    if (rc != 0) {
        free(s.unit);
        return rc;
    }
    uint64_t total = (uint64_t)s.u * s.k;
    uint64_t out_len = s.out_len == SIZE_MAX ? total : (uint64_t)s.out_len;
    uint8_t *input = malloc(total ? total : 1);
    if (!input) {
        free(s.unit);
        return -2;
    }
    for (uint64_t i = 0; i < s.k; i++) memcpy(input + i * s.u, s.unit, s.u);

    /* the exact price, measured once (and the input proven valid) */
    evm_addr a;
    memset(&a, 0, sizeof(a));
    a.b[31] = s.addr;
    const uint64_t start = UINT64_C(1) << 50;
    uint64_t left = start;
    evm_pc_result_t res = EVM_PC_INVALID;
    uint8_t *out = NULL;
    size_t olen = 0;
    rc = evm_precompile_run(&a, input, (size_t)total, &left, &res, &out,
                            &olen);
    free(out);
    free(input);
    if (rc != 0 || res != EVM_PC_OK || olen != out_len) {
        if (msg && cap)
            snprintf(msg, cap, "precompile 0x%02x refused the input "
                     "(rc %d, result %d, output %zu bytes, want %llu)",
                     s.addr, rc, (int)res, olen,
                     (unsigned long long)out_len);
        free(s.unit);
        return -2;
    }
    w->pc_cost = start - left;
    w->pc_addr = s.addr;
    w->pc_input_len = (size_t)total;
    w->pc_k = s.k;
    if (!pc_fits(p->gas_limit, w->pc_cost, s.u, s.k, out_len)) {
        if (msg && cap)
            snprintf(msg, cap, "one call (%llu gas exact) does not fit "
                     "this gas limit", (unsigned long long)w->pc_cost);
        free(s.unit);
        return -1;
    }
    uint64_t thresh = w->pc_cost + w->pc_cost / 63u + PC_GUARD;
    w->slack = thresh;

    w->data_len = PC_DATA_OFF + s.u;
    w->data = calloc(1, w->data_len);
    if (!w->data) {
        free(s.unit);
        return -2;
    }
    w->data[31] = s.addr;                         /* w0: to                */
    word_u64(w->data + 32, s.u);                  /* w1: u                 */
    word_u64(w->data + 64, s.k);                  /* w2: k                 */
    word_u64(w->data + 96, out_len);              /* w3: out_len           */
    word_u64(w->data + 128, thresh);              /* w4: guard             */
    word_u64(w->data + 160, total + out_len - 1); /* w5: pre-expansion     */
    memcpy(w->data + PC_DATA_OFF, s.unit, s.u);
    free(s.unit);
    return code_pcloop(&w->code, &w->code_len);
}

/* ══ wl_build ═════════════════════════════════════════════════════════ */

int wl_build(const wl_def_t *d, const wl_params_t *p, wl_inst_t *out,
             char *msg, size_t cap)
{
    memset(out, 0, sizeof(*out));
    out->def = d;
    if (msg && cap) msg[0] = '\0';
    const uint64_t g = p->gas_limit;
    int rc = -2;
    switch (d->kind) {
    case K_OP:
        rc = code_op(d->var, &out->code, &out->code_len, &out->slack);
        if (rc == 0 && out->slack + 21000u > g) rc = -1;
        break;
    case K_KECCAK: {
        uint64_t L = d->var == KCV_32 ? 32u : d->var == KCV_4K ? 4096u
                                                              : 1048576u;
        uint64_t th = 30u + 6u * words_of(L) + wl_mem_cost(L) + 200u;
        uint64_t v[2] = { L, th };
        out->slack = th;
        rc = data_words(out, v, 2);
        if (rc == 0) rc = code_keccak(&out->code, &out->code_len);
        if (rc == 0 && wl_intrinsic(out->data, out->data_len) + th > g)
            rc = -1;
        break;
    }
    case K_MEMX: {
        /* the largest w with mem(32w) within the gas left after the
         * intrinsic (32 data bytes counted non-zero) and ~20 gas of
         * opcodes */
        uint64_t avail = g > 21000u + 16u * 32u + 100u
                             ? g - 21000u - 16u * 32u - 100u : 0;
        uint64_t lo = 0, hi = 1;
        while (wl_mem_cost(hi * 32u) <= avail) hi *= 2;
        while (lo + 1 < hi) {
            uint64_t mid = lo + (hi - lo) / 2;
            if (wl_mem_cost(mid * 32u) <= avail) lo = mid;
            else hi = mid;
        }
        if (lo == 0) {
            rc = -1;
            break;
        }
        uint64_t v[1] = { lo * 32u - 1u };
        out->slack = 2000u;
        rc = data_words(out, v, 1);
        if (rc == 0) rc = code_memx(&out->code, &out->code_len);
        break;
    }
    case K_MCOPY: {
        const uint64_t M = 262144u;
        uint64_t th = 3u + 3u * words_of(M) + 200u;
        uint64_t v[2] = { M, th };
        out->slack = th;
        rc = data_words(out, v, 2);
        if (rc == 0) rc = code_mcopy(&out->code, &out->code_len);
        if (rc == 0 && wl_intrinsic(out->data, out->data_len) +
                           wl_mem_cost(2u * M) + th > g)
            rc = -1;
        break;
    }
    case K_STORE: {
        uint64_t v[2] = { d->var == STV_SSTORE_FRESH ? 0u : 1u,
                          p->slot_base };
        rc = data_words(out, v, 2);
        if (rc == 0) rc = code_storage(&out->code, &out->code_len);
        out->slack = d->var == STV_SSTORE_FRESH ? 25000u : 5000u;
        if (d->var == STV_SLOAD_PRESENT) out->prefill_slots = g / 2100u + 64u;
        break;
    }
    case K_ACCT: {
        memset(out->acct_base, 0xA5, 24);          /* low 8 bytes count up  */
        rc = data_words(out, NULL, 0);
        if (rc != 0) break;
        free(out->data);
        out->data = malloc(32);
        if (!out->data) {
            rc = -2;
            break;
        }
        memcpy(out->data, out->acct_base, 32);
        out->data_len = 32;
        rc = code_acct(d->var, &out->code, &out->code_len);
        out->slack = 5000u;
        out->prefill_accounts = g / 2600u + 64u;
        if (d->var == ACV_EXTCODECOPY) out->prefill_code_len = EVM_MAX_CODE_SIZE;
        break;
    }
    case K_DEPTH: {
        uint64_t v[1] = { 1u };                    /* non-empty calldata    */
        rc = data_words(out, v, 1);
        if (rc == 0) rc = code_depth(d->var, &out->code, &out->code_len);
        out->slack = 100000u;
        break;
    }
    case K_CREATE:
        rc = data_words(out, NULL, 0);
        out->data_len = 0;
        if (rc == 0)
            rc = code_create(d->var, &out->code, &out->code_len, &out->slack);
        if (rc == 0 && out->slack + 21000u > g) rc = -1;
        break;
    case K_PC:
        rc = build_pc(d->var, p, out, msg, cap);
        break;
    case K_LOG: {
        uint64_t L;
        if (d->var == LGV_1K) {
            L = 1024u;
        } else if (d->var == LGV_0) {
            L = 0;
        } else {
            /* largest multiple of 32 with 1 875 + 8L + mem(L) + 300
             * within the gas left after the intrinsic (64 data bytes,
             * counted non-zero) */
            uint64_t avail = g > 21000u + 16u * 64u + 400u
                                 ? g - 21000u - 16u * 64u - 400u : 0;
            uint64_t lo = 0, hi = 1;
            while (1875u + 8u * hi * 32u + wl_mem_cost(hi * 32u) <= avail)
                hi *= 2;
            while (lo + 1 < hi) {
                uint64_t mid = lo + (hi - lo) / 2;
                if (1875u + 8u * mid * 32u + wl_mem_cost(mid * 32u) <= avail)
                    lo = mid;
                else
                    hi = mid;
            }
            L = lo * 32u;
        }
        uint64_t th = 1875u + 8u * L + wl_mem_cost(L) + 200u;
        uint64_t v[2] = { L, th };
        out->slack = th;
        rc = data_words(out, v, 2);
        if (rc == 0) rc = code_log(&out->code, &out->code_len);
        if (rc == 0 && wl_intrinsic(out->data, out->data_len) + th > g)
            rc = -1;
        break;
    }
    default:
        rc = -2;
    }
    if (rc == -1 && msg && cap && !msg[0])
        msgf(msg, cap, "does not fit this gas limit");
    if (rc == -2 && msg && cap && !msg[0])
        msgf(msg, cap, "build fault (allocation or assembler)");
    if (rc != 0) wl_inst_free(out);
    return rc;
}

void wl_inst_free(wl_inst_t *w)
{
    if (!w) return;
    free(w->code);
    free(w->data);
    const wl_def_t *d = w->def;
    memset(w, 0, sizeof(*w));
    w->def = d;
}
