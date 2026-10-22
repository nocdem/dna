/**
 * @file test_mldsa_precompile.c
 * @brief Nodus ML-DSA-87 signature verification precompile (evm.h
 *        mldsa_precompile) — engine checks plus the NIST ACVP primitive
 *        fixture (compile-and-run standalone).
 *
 * Spec under test: decision docs/plans/decisions/2026-10-21-mldsa87-evm-
 * precompile.md (items 1-8, "Measurement", "Input field order") and design
 * docs/plans/2026-10-21-mldsa87-evm-precompile-design.md rev 2 §1.1-1.8,
 * §5. Gas literals below are written out by hand from the decision
 * (25 000 + 12 per 32-byte message word), not computed by the engine's
 * formula.
 *
 * Two layers, kept separate (design §1.8):
 *   PRECOMPILE LAYER — self-consistent: one ML-DSA-87 key from the fixed
 *   seed KEY_SEED (qgp_dsa87_keypair_derand, no randomness), signatures
 *   made at run time with qgp_dsa87_sign_ctx (hedged: a fresh signature
 *   each run, every one valid). The expected address is
 *   qgp_sha3_512(pk)[0..32] — the same function the engine calls; this
 *   layer proves the engine's framing, gas, classes and paths, NOT the
 *   primitives.
 *   PRIMITIVE LAYER — external: the NIST ACVP-Server ML-DSA-sigVer-FIPS204
 *   test group 5 (ML-DSA-87, external interface, pure; 15 cases) through
 *   qgp_dsa87_verify_ctx; fixture and provenance in
 *   tests/fixtures/mldsa87/README.md.
 *
 * Checks (each prints PASS/FAIL under its name):
 *   m1_valid_lengths       valid -> 32-byte address at message lengths 0,
 *                          1, 32, 33 and 65 536 (input 7219 .. 72 755);
 *                          gas exactly 25000 / 25012 / 25012 / 25024 /
 *                          49576, proven by running each with gas_left ==
 *                          that amount (OK, 0 left) and with a large
 *                          budget (the same amount taken)
 *   m2_length_bounds       input 0 and 7218 bytes -> empty, 25000 gas;
 *                          72 756 bytes (a VALID signature over 65 537
 *                          bytes) -> empty, 49588 gas
 *   m3_wrong_context       the same message signed with the empty context
 *                          (qgp_dsa87_sign, the chain's form) and with
 *                          "nodus.valbind.v1" -> empty, 25012 gas;
 *                          control: "nodus.evm.attest.v1" -> address
 *   m4_altered             valid input with one byte flipped in the
 *                          message, the signature or the key -> empty
 *   m5_out_of_gas          gas_left = gas - 1 -> EVM_PC_OOG, no output,
 *                          for a valid input and for the malformed lengths
 *                          7218 and 72 756 (out of gas wins over malformed)
 *   m6_resolver            evm_precompile_resolve / evm_precompile_run_cfg
 *                          / evm_precompile_run: the tag address is a
 *                          precompile only with the switch on in the Nodus
 *                          32-byte profile; the numeric entry and a
 *                          switched-off config refuse it (-2); a numeric-
 *                          looking 0x..ce address is no precompile
 *   m7_state_new           evm_state_new refuses the switch with
 *                          addr_bytes 20, with nodus_profile 0, with
 *                          ticket_addr == the tag address, and the value 2;
 *                          accepts 0 and a valid 1
 *   m8_call_kinds          switch on: a contract CALL / STATICCALL /
 *                          DELEGATECALL / CALLCODE with the tx calldata as
 *                          input -> success 1, RETURNDATASIZE 32, output =
 *                          the address (stored in slots 0/1/2)
 *   m9_switch_off_ordinary switch off: the same CALL -> success 1,
 *                          RETURNDATASIZE 0, memory untouched (an ordinary
 *                          code-less account; nothing dispatched)
 *   m10_warm_cold          GAS window around a 0-input STATICCALL: to an
 *                          absent ordinary address 21 + 2600 = 2621; to
 *                          the tag address with the switch off 2621 (cold,
 *                          not dispatched); on 21 + 100 + 25000 = 25121
 *                          (warm at tx start, the precompile charged)
 *   m11_top_level          switch on: a tx straight to the tag address
 *                          -> SUCCESS, output = the address
 *   m12_acvp_group5        the 15 ACVP group-5 cases agree with
 *                          expectedResults (3 valid, 12 invalid); a
 *                          missing or short fixture is a FAILURE
 *
 * NOT covered here (design §5): fault injection into the SHA3 backend /
 * allocation (class c), norm and hint boundary cases, the activation path
 * (H-1 / H, restart, replay) and the companion library.
 *
 * `--gen-kat` mode: prints the start-up self-test vectors (evm_precompile.c
 * PC_KATS32) as C initialisers — key from KEY_SEED, message KAT_MSG, one
 * signature under "nodus.evm.attest.v1" and one under the empty context —
 * after checking both through the precompile entry. Run once by hand; the
 * output is pasted into evm_precompile.c and reviewed with it. Hedged
 * signing: a re-run prints different (equally valid) signatures; the key,
 * message and address are reproducible from the recorded seed.
 *
 * Requirements: a default build; qgp_randombytes must be provided by the
 * link (the signer, dsa/sign.c, needs it). Reads the committed fixture at
 * MLDSA_ACVP_FIXTURE (an absolute path compiled in by the Makefile).
 * Leaves nothing behind. How it can lie: the precompile layer shares
 * qgp_sha3_512 and the dsa code with the engine (a primitive bug both sides
 * share is invisible there — the ACVP layer is what pins the verifier).
 *
 * Standalone harness: reports via fprintf; exit 0 = every check passed,
 * 1 = a check failed, 2 = engine fault/OOM.
 */
#include "evm.h"
#include "evm_internal.h"
#include "evm_membackend.h"
#include "crypto/hash/qgp_sha3.h"
#include "crypto/sign/qgp_dilithium.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef MLDSA_ACVP_FIXTURE
#error "MLDSA_ACVP_FIXTURE (path of the ACVP group-5 fixture) must be defined"
#endif

/* ── opcodes (execution-specs@a87891f7 prague/vm/instructions) ──────── */
#define OP_STOP           0x00
#define OP_SUB            0x03
#define OP_CALLDATASIZE   0x36
#define OP_CALLDATACOPY   0x37
#define OP_RETURNDATASIZE 0x3d
#define OP_POP            0x50
#define OP_MLOAD          0x51
#define OP_SSTORE         0x55
#define OP_GAS            0x5a
#define OP_PUSH1          0x60
#define OP_SWAP1          0x90
#define OP_CALL           0xf1
#define OP_CALLCODE       0xf2
#define OP_DELEGATECALL   0xf4
#define OP_STATICCALL     0xfa

#define TX_GAS            5000000ull
#define PK_LEN            EVM_MLDSA87_PK_BYTES
#define SIG_LEN           EVM_MLDSA87_SIG_BYTES
#define PREFIX            EVM_MLDSA87_PREFIX_BYTES

/* The recorded key seed of this file (layer 2): bytes 0x00..0x1f. */
static const uint8_t KEY_SEED[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };

/* --gen-kat message: the 32 ASCII bytes "Nodus EVM ML-DSA-87 self-test v1" */
static const char KAT_MSG[] = "Nodus EVM ML-DSA-87 self-test v1";

static const uint8_t VALBIND_CTX[] = "nodus.valbind.v1";   /* 16 + NUL */
static const uint8_t ATTEST_CTX[] = EVM_MLDSA87_CTX;     /* 19 + NUL */

/* ── check bookkeeping ─────────────────────────────────────────────── */

static unsigned g_fail_checks;
static unsigned g_check_fail;
static const char *g_check;

static void check_begin(const char *name)
{
    g_check = name;
    g_check_fail = 0;
}

static void expect(int cond, const char *what)
{
    if (!cond) {
        fprintf(stderr, "  [FAIL] %s: %s\n", g_check, what);
        g_check_fail++;
    }
}

static void check_end(void)
{
    fprintf(stderr, "%s: %s\n", g_check, g_check_fail ? "FAIL" : "PASS");
    if (g_check_fail) g_fail_checks++;
}

static void fatal(const char *what)
{
    fprintf(stderr, "FATAL (%s): %s\n", g_check ? g_check : "setup", what);
    exit(2);
}

/* ── key material and inputs ───────────────────────────────────────── */

static uint8_t g_pk[PK_LEN];
static uint8_t g_sk[QGP_DSA87_SECRETKEYBYTES];
static uint8_t g_addr[32];                 /* SHA3-512(pk)[0..32] */

static void key_setup(void)
{
    uint8_t h[QGP_SHA3_512_DIGEST_LENGTH];
    if (qgp_dsa87_keypair_derand(g_pk, g_sk, KEY_SEED) != 0)
        fatal("qgp_dsa87_keypair_derand");
    if (qgp_sha3_512(g_pk, PK_LEN, h) != 0) fatal("qgp_sha3_512");
    memcpy(g_addr, h, 32);
}

static void msg_fill(uint8_t *m, size_t n)
{
    for (size_t i = 0; i < n; i++) m[i] = (uint8_t)(i * 7u + 3u);
}

/* pk ‖ sig ‖ msg, the signature made under (ctx, ctxlen); ctx == NULL
 * signs with the empty context through qgp_dsa87_sign */
static uint8_t *make_input(const uint8_t *pk, const uint8_t *msg, size_t mlen,
                           const uint8_t *ctx, size_t ctxlen, size_t *len)
{
    static const uint8_t one = 0;
    size_t siglen = 0;
    uint8_t *in = malloc(PREFIX + mlen);
    if (!in) fatal("malloc");
    memcpy(in, pk, PK_LEN);
    if (mlen) memcpy(in + PREFIX, msg, mlen);
    const uint8_t *m = mlen ? msg : &one;
    int rc = ctx ? qgp_dsa87_sign_ctx(in + PK_LEN, &siglen, m, mlen, ctx,
                                      ctxlen, g_sk)
                 : qgp_dsa87_sign(in + PK_LEN, &siglen, m, mlen, g_sk);
    if (rc != 0 || siglen != SIG_LEN) fatal("ML-DSA-87 signing");
    *len = PREFIX + mlen;
    return in;
}

static void cfg_base(evm_config_t *cfg, int on)
{
    uint8_t chain[32];
    for (int k = 0; k < 32; k++) chain[k] = (uint8_t)(0xA0 + k);
    memset(cfg, 0, sizeof(*cfg));
    cfg->fork = EVM_FORK_PRAGUE;
    cfg->addr_bytes = 32;
    evm_u256_from_be(&cfg->chain_id, chain);
    cfg->precompile_mask = EVM_PRECOMPILES_PRAGUE;
    cfg->nodus_profile = 1;
    memset(cfg->ticket_addr.b, 0xEE, 32);
    evm_u256_from_u64(&cfg->ticket_unit, 10000000000ull);
    cfg->ticket_gas = 25000;
    cfg->mldsa_precompile = on;
}

/* the precompile entry the interpreter uses; -2 is fatal */
typedef struct {
    evm_pc_result_t res;
    uint8_t        *out;
    size_t          out_len;
    uint64_t        gas_left;
} pc_run_t;

static void pc_run(const uint8_t *in, size_t len, uint64_t gas, pc_run_t *r)
{
    evm_config_t cfg;
    cfg_base(&cfg, 1);
    memset(r, 0, sizeof(*r));
    r->gas_left = gas;
    if (evm_precompile_run_cfg(&cfg, &evm_mldsa87_addr, in, len, &r->gas_left,
                               &r->res, &r->out, &r->out_len) != 0)
        fatal("evm_precompile_run_cfg fault");
}

static int is_address(const pc_run_t *r)
{
    return r->res == EVM_PC_OK && r->out_len == 32 &&
           memcmp(r->out, g_addr, 32) == 0;
}

static int is_empty_ok(const pc_run_t *r)
{
    return r->res == EVM_PC_OK && r->out_len == 0;
}

/* ── precompile layer ──────────────────────────────────────────────── */

static void m1_valid_lengths(void)
{
    static const size_t   len[5] = { 0, 1, 32, 33, 65536 };
    static const uint64_t gas[5] = { 25000, 25012, 25012, 25024, 49576 };
    check_begin("m1_valid_lengths");
    for (int i = 0; i < 5; i++) {
        size_t n = 0;
        uint8_t *msg = malloc(len[i] ? len[i] : 1);
        if (!msg) fatal("malloc");
        msg_fill(msg, len[i]);
        uint8_t *in = make_input(g_pk, msg, len[i], ATTEST_CTX,
                                 EVM_MLDSA87_CTX_LEN, &n);
        pc_run_t r;
        pc_run(in, n, gas[i], &r);
        expect(is_address(&r), "valid -> address (gas_left == exact gas)");
        expect(r.gas_left == 0, "exact gas taken (none left)");
        free(r.out);
        pc_run(in, n, 10000000u, &r);
        expect(is_address(&r), "valid -> address (large budget)");
        expect(10000000u - r.gas_left == gas[i], "gas charged");
        free(r.out);
        free(in);
        free(msg);
    }
    check_end();
}

static void m2_length_bounds(void)
{
    pc_run_t r;
    size_t n = 0;
    check_begin("m2_length_bounds");
    uint8_t *zero = calloc(1, PREFIX);
    if (!zero) fatal("calloc");
    pc_run(zero, 0, 10000000u, &r);
    expect(is_empty_ok(&r) && 10000000u - r.gas_left == 25000,
           "input 0 bytes -> empty, 25000 gas");
    free(r.out);
    pc_run(zero, PREFIX - 1, 10000000u, &r);
    expect(is_empty_ok(&r) && 10000000u - r.gas_left == 25000,
           "input 7218 bytes -> empty, 25000 gas");
    free(r.out);
    free(zero);

    uint8_t *msg = malloc(EVM_MLDSA87_MSG_MAX + 1u);
    if (!msg) fatal("malloc");
    msg_fill(msg, EVM_MLDSA87_MSG_MAX + 1u);
    uint8_t *in = make_input(g_pk, msg, EVM_MLDSA87_MSG_MAX + 1u, ATTEST_CTX,
                             EVM_MLDSA87_CTX_LEN, &n);
    expect(n == 72756u, "input is 72756 bytes");
    expect(qgp_dsa87_verify_ctx(in + PK_LEN, SIG_LEN, msg,
                                EVM_MLDSA87_MSG_MAX + 1u, ATTEST_CTX,
                                EVM_MLDSA87_CTX_LEN, g_pk) == 0,
           "control: the 65537-byte signature itself is valid");
    pc_run(in, n, 10000000u, &r);
    expect(is_empty_ok(&r) && 10000000u - r.gas_left == 49588,
           "input 72756 bytes -> empty, 49588 gas");
    free(r.out);
    free(in);
    free(msg);
    check_end();
}

static void m3_wrong_context(void)
{
    uint8_t msg[32];
    size_t n = 0;
    pc_run_t r;
    check_begin("m3_wrong_context");
    msg_fill(msg, sizeof(msg));

    uint8_t *in = make_input(g_pk, msg, sizeof(msg), NULL, 0, &n);
    pc_run(in, n, 10000000u, &r);
    expect(is_empty_ok(&r) && 10000000u - r.gas_left == 25012,
           "empty context (chain signature) -> empty, 25012 gas");
    free(r.out);
    free(in);

    in = make_input(g_pk, msg, sizeof(msg), VALBIND_CTX,
                    sizeof(VALBIND_CTX) - 1u, &n);
    pc_run(in, n, 10000000u, &r);
    expect(is_empty_ok(&r) && 10000000u - r.gas_left == 25012,
           "\"nodus.valbind.v1\" -> empty, 25012 gas");
    free(r.out);
    free(in);

    in = make_input(g_pk, msg, sizeof(msg), ATTEST_CTX, EVM_MLDSA87_CTX_LEN,
                    &n);
    pc_run(in, n, 10000000u, &r);
    expect(is_address(&r), "control: \"nodus.evm.attest.v1\" -> address");
    free(r.out);
    free(in);
    check_end();
}

static void m4_altered(void)
{
    static const size_t at[3] = { PREFIX + 5u, PK_LEN + 100u, 50u };
    static const char *const what[3] = {
        "message byte flipped -> empty",
        "signature byte flipped -> empty",
        "public key byte flipped -> empty" };
    uint8_t msg[32];
    size_t n = 0;
    check_begin("m4_altered");
    msg_fill(msg, sizeof(msg));
    for (int i = 0; i < 3; i++) {
        pc_run_t r;
        uint8_t *in = make_input(g_pk, msg, sizeof(msg), ATTEST_CTX,
                                 EVM_MLDSA87_CTX_LEN, &n);
        in[at[i]] ^= 0x01;
        pc_run(in, n, 10000000u, &r);
        expect(is_empty_ok(&r) && 10000000u - r.gas_left == 25012, what[i]);
        free(r.out);
        free(in);
    }
    check_end();
}

static void m5_out_of_gas(void)
{
    uint8_t msg[32];
    size_t n = 0;
    pc_run_t r;
    check_begin("m5_out_of_gas");
    msg_fill(msg, sizeof(msg));
    uint8_t *in = make_input(g_pk, msg, sizeof(msg), ATTEST_CTX,
                             EVM_MLDSA87_CTX_LEN, &n);
    pc_run(in, n, 25011, &r);
    expect(r.res == EVM_PC_OOG && r.out_len == 0, "valid, gas - 1 -> OOG");
    free(r.out);
    pc_run(in, n, 25012, &r);
    expect(is_address(&r), "control: valid, exact gas -> address");
    free(r.out);
    free(in);

    uint8_t *big = calloc(1, 72756u);
    if (!big) fatal("calloc");
    pc_run(big, PREFIX - 1, 24999, &r);
    expect(r.res == EVM_PC_OOG && r.out_len == 0,
           "7218 bytes, 24999 gas -> OOG (wins over malformed)");
    free(r.out);
    pc_run(big, 72756u, 49587, &r);
    expect(r.res == EVM_PC_OOG && r.out_len == 0,
           "72756 bytes, 49587 gas -> OOG (wins over malformed)");
    free(r.out);
    free(big);
    check_end();
}

static void m6_resolver(void)
{
    evm_config_t on, off, eth;
    evm_addr numeric_ce, one;
    evm_pc_result_t res;
    uint8_t *out = NULL;
    size_t out_len = 0;
    uint64_t gas = 100000;
    check_begin("m6_resolver");
    cfg_base(&on, 1);
    cfg_base(&off, 0);
    cfg_base(&eth, 1);
    eth.nodus_profile = 0;
    memset(numeric_ce.b, 0, 32);
    numeric_ce.b[31] = 0xce;
    memset(one.b, 0, 32);
    one.b[31] = 0x01;

    expect(evm_precompile_resolve(&on, &evm_mldsa87_addr) == EVM_PC_ID_MLDSA87,
           "on: tag address resolves");
    expect(evm_precompile_resolve(&off, &evm_mldsa87_addr) == 0,
           "off: tag address is an ordinary account");
    expect(evm_precompile_resolve(&eth, &evm_mldsa87_addr) == 0,
           "switch set outside the Nodus profile: not resolved");
    expect(evm_precompile_resolve(&on, &one) == 0x01, "numeric 0x01");
    expect(evm_precompile_resolve(&on, &numeric_ce) == 0,
           "0x..ce (numeric form) is no precompile");
    on.precompile_mask = 0;
    expect(evm_precompile_resolve(&on, &one) == 0, "mask bit clear: 0x01 off");
    expect(evm_precompile_resolve(&on, &evm_mldsa87_addr) == EVM_PC_ID_MLDSA87,
           "the tag address does not depend on the numeric mask");
    expect(evm_precompile_run_cfg(&off, &evm_mldsa87_addr, NULL, 0, &gas, &res,
                                  &out, &out_len) == -2,
           "run_cfg with the switch off refuses the tag address");
    expect(evm_precompile_run(&evm_mldsa87_addr, NULL, 0, &gas, &res, &out,
                              &out_len) == -2,
           "the numeric entry refuses the tag address");
    expect(gas == 100000 && out == NULL && out_len == 0,
           "a refusal charges nothing");
    check_end();
}

/* ── engine layer ──────────────────────────────────────────────────── */

typedef struct {
    uint8_t b[512];
    size_t  n;
} asm_t;

static void a_byte(asm_t *a, uint8_t v)
{
    if (a->n >= sizeof(a->b)) fatal("assembler overflow");
    a->b[a->n++] = v;
}

static void a_push1(asm_t *a, uint8_t v)
{
    a_byte(a, OP_PUSH1);
    a_byte(a, v);
}

static void a_push32(asm_t *a, const uint8_t v[32])
{
    a_byte(a, OP_PUSH1 + 31);
    for (int i = 0; i < 32; i++) a_byte(a, v[i]);
}

static void addr_of(uint8_t tag, uint8_t out[32])
{
    memset(out, tag, 32);
}

static const uint8_t SENDER_TAG = 0x5E, CONTRACT_TAG = 0xC0, CTRL_TAG = 0xD0;

/* CALLDATACOPY the whole calldata to memory 0, call `target` with it
 * (op), output to memory 0 (32 bytes); slot 0 = success, slot 1 =
 * RETURNDATASIZE, slot 2 = memory word 0 */
static void code_call_kind(asm_t *a, uint8_t op, const uint8_t target[32])
{
    memset(a, 0, sizeof(*a));
    a_byte(a, OP_CALLDATASIZE);
    a_push1(a, 0);
    a_push1(a, 0);
    a_byte(a, OP_CALLDATACOPY);
    a_push1(a, 32);                       /* retSize   */
    a_push1(a, 0);                        /* retOffset */
    a_byte(a, OP_CALLDATASIZE);           /* argsSize  */
    a_push1(a, 0);                        /* argsOffset */
    if (op == OP_CALL || op == OP_CALLCODE) a_push1(a, 0);   /* value */
    a_push32(a, target);
    a_byte(a, OP_GAS);
    a_byte(a, op);
    a_push1(a, 0);
    a_byte(a, OP_SSTORE);
    a_byte(a, OP_RETURNDATASIZE);
    a_push1(a, 1);
    a_byte(a, OP_SSTORE);
    a_push1(a, 0);
    a_byte(a, OP_MLOAD);
    a_push1(a, 2);
    a_byte(a, OP_SSTORE);
    a_byte(a, OP_STOP);
}

/* slot 0 = the gas between two GAS readings around a 0-input STATICCALL
 * to `target`: GAS, 4 x PUSH1 (12), PUSH32 (3), GAS (2), STATICCALL
 * (access + callee), POP (2), GAS (2) -> 21 + access + callee gas */
static void code_gas_window(asm_t *a, const uint8_t target[32])
{
    memset(a, 0, sizeof(*a));
    a_byte(a, OP_GAS);
    a_push1(a, 0);
    a_push1(a, 0);
    a_push1(a, 0);
    a_push1(a, 0);
    a_push32(a, target);
    a_byte(a, OP_GAS);
    a_byte(a, OP_STATICCALL);
    a_byte(a, OP_POP);
    a_byte(a, OP_GAS);
    a_byte(a, OP_SWAP1);
    a_byte(a, OP_SUB);
    a_push1(a, 0);
    a_byte(a, OP_SSTORE);
    a_byte(a, OP_STOP);
}

typedef struct {
    evm_membackend  mb;
    evm_backend_t   be;
    evm_config_t    cfg;
    evm_block_env_t env;
    evm_state_t    *st;
} run_t;

static void run_open(run_t *r, int on, const asm_t *code)
{
    uint8_t a[32], zero[32];
    evm_addr x;
    memset(r, 0, sizeof(*r));
    memset(zero, 0, 32);
    evm_membackend_init(&r->mb);
    addr_of(SENDER_TAG, a);
    memcpy(x.b, a, 32);
    if (evm_membackend_add_account(&r->mb, &x, 0, zero, NULL, 0, NULL,
                                   NULL) != 0)
        fatal("add sender");
    if (code) {
        addr_of(CONTRACT_TAG, a);
        memcpy(x.b, a, 32);
        if (evm_membackend_add_account(&r->mb, &x, 1, zero, code->b, code->n,
                                       NULL, NULL) != 0)
            fatal("add contract");
    }
    if (evm_membackend_finalize(&r->mb) != 0) fatal("finalize");
    evm_membackend_bind(&r->mb, &r->be);
    cfg_base(&r->cfg, on);
    memset(&r->env, 0, sizeof(r->env));
    r->env.number = 100;
    r->env.timestamp = 1000;
    r->env.gas_limit = 30000000;
    r->st = evm_state_new(&r->cfg, &r->be);
    if (!r->st) fatal("evm_state_new");
}

static void run_close(run_t *r)
{
    evm_state_free(r->st);
    evm_membackend_free(&r->mb);
}

static int run_tx(run_t *r, const uint8_t to[32], const uint8_t *data,
                  size_t data_len, evm_tx_result_t *res)
{
    evm_tx_t tx;
    memset(&tx, 0, sizeof(tx));
    memset(res, 0, sizeof(*res));
    tx.type = 0;
    addr_of(SENDER_TAG, tx.sender.b);
    memcpy(tx.to.b, to, 32);
    tx.gas_limit = TX_GAS;
    tx.data = data;
    tx.data_len = data_len;
    tx.has_chain_id = 1;
    tx.chain_id = r->cfg.chain_id;
    for (int k = 0; k < 64; k++) tx.intent_id[k] = (uint8_t)(0x40 + k);
    int rc = evm_tx_apply(r->st, &r->env, &tx, res);
    if (rc == -2) fatal("evm_tx_apply fault");
    return rc;
}

typedef struct {
    uint8_t addr[32];
    uint8_t slot[3][32];
} slots_t;

static int cb_account(void *ctx, const evm_account_change_t *ch)
{
    (void)ctx;
    (void)ch;
    return 0;
}

static int cb_storage(void *ctx, const evm_addr *addr, const evm_bytes32 *key,
                      const evm_bytes32 *value)
{
    slots_t *s = ctx;
    if (memcmp(addr->b, s->addr, 32) != 0) return 0;
    for (int i = 0; i < 31; i++)
        if (key->b[i] != 0) return 0;
    if (key->b[31] < 3) memcpy(s->slot[key->b[31]], value->b, 32);
    return 0;
}

static void read_slots(const run_t *r, slots_t *s)
{
    evm_change_visitor_t v;
    memset(s->slot, 0, sizeof(s->slot));
    addr_of(CONTRACT_TAG, s->addr);
    v.account = cb_account;
    v.storage = cb_storage;
    v.ctx = s;
    if (evm_state_visit_changes(r->st, &v) != 0) fatal("visit_changes");
}

static int word_is_u64(const uint8_t w[32], uint64_t v)
{
    for (int i = 0; i < 24; i++)
        if (w[i]) return 0;
    for (int i = 0; i < 8; i++)
        if (w[31 - i] != (uint8_t)(v >> (8 * i))) return 0;
    return 1;
}

static uint64_t word_u64v(const uint8_t w[32])
{
    uint64_t v = 0;
    for (int i = 0; i < 24; i++)
        if (w[i]) return UINT64_MAX;
    for (int i = 24; i < 32; i++) v = (v << 8) | w[i];
    return v;
}

static void m8_call_kinds(void)
{
    static const uint8_t ops[4] = { OP_CALL, OP_STATICCALL, OP_DELEGATECALL,
                                    OP_CALLCODE };
    static const char *const name[4] = { "CALL", "STATICCALL",
                                          "DELEGATECALL", "CALLCODE" };
    uint8_t msg[32], c[32];
    size_t n = 0;
    check_begin("m8_call_kinds");
    msg_fill(msg, sizeof(msg));
    addr_of(CONTRACT_TAG, c);
    uint8_t *in = make_input(g_pk, msg, sizeof(msg), ATTEST_CTX,
                             EVM_MLDSA87_CTX_LEN, &n);
    for (int k = 0; k < 4; k++) {
        asm_t code;
        run_t r;
        evm_tx_result_t res;
        slots_t s;
        code_call_kind(&code, ops[k], evm_mldsa87_addr.b);
        run_open(&r, 1, &code);
        int rc = run_tx(&r, c, in, n, &res);
        read_slots(&r, &s);
        fprintf(stderr, "  %s:\n", name[k]);
        expect(rc == 0 && res.status == EVM_EXEC_SUCCESS, "tx SUCCESS");
        expect(word_is_u64(s.slot[0], 1), "call success 1");
        expect(word_is_u64(s.slot[1], 32), "RETURNDATASIZE 32");
        expect(memcmp(s.slot[2], g_addr, 32) == 0, "output = signer address");
        evm_tx_result_free(&res);
        run_close(&r);
    }
    free(in);
    check_end();
}

static void m9_switch_off_ordinary(void)
{
    uint8_t msg[32], c[32];
    size_t n = 0;
    asm_t code;
    run_t r;
    evm_tx_result_t res;
    slots_t s;
    check_begin("m9_switch_off_ordinary");
    msg_fill(msg, sizeof(msg));
    addr_of(CONTRACT_TAG, c);
    uint8_t *in = make_input(g_pk, msg, sizeof(msg), ATTEST_CTX,
                             EVM_MLDSA87_CTX_LEN, &n);
    code_call_kind(&code, OP_CALL, evm_mldsa87_addr.b);
    run_open(&r, 0, &code);
    int rc = run_tx(&r, c, in, n, &res);
    read_slots(&r, &s);
    expect(rc == 0 && res.status == EVM_EXEC_SUCCESS, "tx SUCCESS");
    expect(word_is_u64(s.slot[0], 1), "call success 1 (code-less account)");
    expect(word_is_u64(s.slot[1], 0), "RETURNDATASIZE 0 (not dispatched)");
    expect(memcmp(s.slot[2], g_pk, 32) == 0,
           "memory word 0 untouched (still the first 32 key bytes)");
    evm_tx_result_free(&res);
    run_close(&r);
    free(in);
    check_end();
}

static uint64_t gas_window(int on, const uint8_t target[32])
{
    uint8_t c[32];
    asm_t code;
    run_t r;
    evm_tx_result_t res;
    slots_t s;
    addr_of(CONTRACT_TAG, c);
    code_gas_window(&code, target);
    run_open(&r, on, &code);
    int rc = run_tx(&r, c, NULL, 0, &res);
    read_slots(&r, &s);
    expect(rc == 0 && res.status == EVM_EXEC_SUCCESS, "tx SUCCESS");
    evm_tx_result_free(&res);
    run_close(&r);
    return word_u64v(s.slot[0]);
}

static void m10_warm_cold(void)
{
    uint8_t ctrl[32];
    check_begin("m10_warm_cold");
    addr_of(CTRL_TAG, ctrl);
    uint64_t cold = gas_window(0, ctrl);
    uint64_t off = gas_window(0, evm_mldsa87_addr.b);
    uint64_t on = gas_window(1, evm_mldsa87_addr.b);
    expect(cold == 2621, "control: absent ordinary address 21 + 2600");
    expect(off == cold, "switch off: cold, nothing dispatched (= control)");
    expect(on == 25121, "switch on: warm 100 + precompile 25000 + 21");
    check_end();
}

static void m11_top_level(void)
{
    uint8_t msg[32];
    size_t n = 0;
    run_t r;
    evm_tx_result_t res;
    check_begin("m11_top_level");
    msg_fill(msg, sizeof(msg));
    uint8_t *in = make_input(g_pk, msg, sizeof(msg), ATTEST_CTX,
                             EVM_MLDSA87_CTX_LEN, &n);
    run_open(&r, 1, NULL);
    int rc = run_tx(&r, evm_mldsa87_addr.b, in, n, &res);
    expect(rc == 0 && res.status == EVM_EXEC_SUCCESS, "tx SUCCESS");
    expect(res.output_len == 32 && memcmp(res.output, g_addr, 32) == 0,
           "output = signer address");
    evm_tx_result_free(&res);
    run_close(&r);
    free(in);
    check_end();
}

static void m7_state_new(void)
{
    evm_config_t cfg;
    evm_membackend mb;
    evm_backend_t be;
    evm_state_t *st;
    check_begin("m7_state_new");
    evm_membackend_init(&mb);
    if (evm_membackend_finalize(&mb) != 0) fatal("finalize");
    evm_membackend_bind(&mb, &be);

    cfg_base(&cfg, 1);
    st = evm_state_new(&cfg, &be);
    expect(st != NULL, "switch on, Nodus 32-byte profile accepted");
    evm_state_free(st);
    cfg_base(&cfg, 0);
    st = evm_state_new(&cfg, &be);
    expect(st != NULL, "switch off accepted");
    evm_state_free(st);

    cfg_base(&cfg, 1);
    cfg.addr_bytes = 20;
    memset(cfg.ticket_addr.b, 0, 12);
    expect(evm_state_new(&cfg, &be) == NULL, "addr_bytes 20 refused");
    cfg_base(&cfg, 1);
    cfg.nodus_profile = 0;
    expect(evm_state_new(&cfg, &be) == NULL, "Ethereum profile refused");
    cfg_base(&cfg, 1);
    memcpy(cfg.ticket_addr.b, evm_mldsa87_addr.b, 32);
    expect(evm_state_new(&cfg, &be) == NULL, "ticket_addr == tag refused");
    cfg_base(&cfg, 2);
    expect(evm_state_new(&cfg, &be) == NULL, "switch value 2 refused");
    evm_membackend_free(&mb);
    check_end();
}

/* ── primitive layer: NIST ACVP group 5 ────────────────────────────── */

static int hexval(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

/* "-" = empty; @return byte count, or -1 on malformed hex / overflow */
static long unhex(const char *h, uint8_t *o, size_t cap)
{
    size_t n = strlen(h);
    if (strcmp(h, "-") == 0) return 0;
    if (n % 2 != 0 || n / 2 > cap) return -1;
    for (size_t i = 0; i < n / 2; i++) {
        int hi = hexval((unsigned char)h[2 * i]);
        int lo = hexval((unsigned char)h[2 * i + 1]);
        if (hi < 0 || lo < 0) return -1;
        o[i] = (uint8_t)(hi * 16 + lo);
    }
    return (long)(n / 2);
}

/* Split a fixture line in place at single spaces; the line must end in
 * "\n" (a longer line than the buffer is malformed). @return the number of
 * fields, or -1 when the line has more than `max` fields or no newline. */
static int split_fields(char *line, char **field, int max)
{
    char *nl = strchr(line, '\n');
    int n = 0;
    if (!nl) return -1;
    *nl = '\0';
    for (char *p = line;;) {
        if (n == max) return -1;
        field[n++] = p;
        char *sp = strchr(p, ' ');
        if (!sp) break;
        *sp = '\0';
        p = sp + 1;
    }
    for (int i = n; i < max; i++) field[i] = NULL;
    return n;
}

static void m12_acvp_group5(void)
{
    enum { LINE_CAP = 1 << 16, MSG_CAP = 1 << 15 };
    static char line[LINE_CAP];
    static uint8_t pk[PK_LEN], sig[SIG_LEN + 1], msg[MSG_CAP], ctx[256];
    unsigned cases = 0, agree = 0, valid = 0;
    int next_tc = 61;
    check_begin("m12_acvp_group5");
    FILE *f = fopen(MLDSA_ACVP_FIXTURE, "r");
    expect(f != NULL, "fixture " MLDSA_ACVP_FIXTURE " readable");
    while (f && fgets(line, sizeof(line), f)) {
        char *field[6];
        int nf = split_fields(line, field, 6);
        char *tc = field[0], *ex = field[1], *hp = field[2], *hs = field[3];
        char *hm = field[4], *hc = field[5];
        if (nf != 6) {
            expect(0, "malformed fixture line");
            break;
        }
        long lp = unhex(hp, pk, sizeof(pk));
        long ls = unhex(hs, sig, sizeof(sig));
        long lm = unhex(hm, msg, sizeof(msg));
        long lc = unhex(hc, ctx, sizeof(ctx));
        if (lp != (long)PK_LEN || ls < 0 || lm < 0 || lc < 0 ||
            atoi(tc) != next_tc || (ex[0] != '0' && ex[0] != '1')) {
            expect(0, "malformed fixture field");
            break;
        }
        next_tc++;
        int want = ex[0] == '1';
        int got = qgp_dsa87_verify_ctx(sig, (size_t)ls, lm ? msg : pk,
                                       (size_t)lm, ctx, (size_t)lc, pk) == 0;
        cases++;
        valid += (unsigned)want;
        if (got == want) agree++;
        else fprintf(stderr, "  tcId %d: expected %d, got %d\n", next_tc - 1,
                     want, got);
    }
    if (f) fclose(f);
    expect(cases == 15, "15 cases read (tcId 61..75)");
    expect(valid == 3, "3 of them valid (tcId 63, 67, 70)");
    expect(agree == cases, "every case agrees with expectedResults");
    check_end();
}

/* ── --gen-kat: the start-up self-test vectors ─────────────────────── */

static void print_array(const char *name, const uint8_t *b, size_t n)
{
    fprintf(stdout, "static const uint8_t %s[%zu] = {\n", name, n);
    for (size_t i = 0; i < n; i++)
        fprintf(stdout, "%s0x%02x,%s", (i % 12) ? " " : "    ", b[i],
                (i % 12 == 11 || i + 1 == n) ? "\n" : "");
    fprintf(stdout, "};\n");
}

static int gen_kat(void)
{
    const uint8_t *msg = (const uint8_t *)KAT_MSG;
    const size_t mlen = sizeof(KAT_MSG) - 1u;
    size_t n_ok = 0, n_bad = 0;
    pc_run_t r;
    g_check = "gen-kat";
    uint8_t *ok = make_input(g_pk, msg, mlen, ATTEST_CTX, EVM_MLDSA87_CTX_LEN,
                             &n_ok);
    uint8_t *bad = make_input(g_pk, msg, mlen, NULL, 0, &n_bad);
    pc_run(ok, n_ok, 10000000u, &r);
    if (!is_address(&r) || 10000000u - r.gas_left != 25012)
        fatal("generated valid row does not give the address");
    free(r.out);
    pc_run(bad, n_bad, 10000000u, &r);
    if (!is_empty_ok(&r) || 10000000u - r.gas_left != 25012)
        fatal("generated wrong-context row does not give empty output");
    free(r.out);
    fprintf(stdout,
            "/* Generated by shared/evm/tests/test_mldsa_precompile.c "
            "--gen-kat:\n"
            " * key = qgp_dsa87_keypair_derand(seed 0x00..0x1f), message = the "
            "%zu ASCII\n"
            " * bytes \"%s\"; MLDSA_KAT_SIG under \"%s\"\n"
            " * (qgp_dsa87_sign_ctx), MLDSA_KAT_SIG_EMPTYCTX under the empty "
            "context\n"
            " * (qgp_dsa87_sign); MLDSA_KAT_ADDR = SHA3-512(pk)[0..32]. Hedged "
            "signing:\n"
            " * the signatures are one valid draw, not reproducible. */\n",
            mlen, KAT_MSG, EVM_MLDSA87_CTX);
    print_array("MLDSA_KAT_PK", g_pk, PK_LEN);
    print_array("MLDSA_KAT_SIG", ok + PK_LEN, SIG_LEN);
    print_array("MLDSA_KAT_SIG_EMPTYCTX", bad + PK_LEN, SIG_LEN);
    print_array("MLDSA_KAT_MSG", msg, mlen);
    print_array("MLDSA_KAT_ADDR", g_addr, 32);
    free(ok);
    free(bad);
    return 0;
}

int main(int argc, char **argv)
{
    key_setup();
    if (argc == 2 && strcmp(argv[1], "--gen-kat") == 0) return gen_kat();
    if (argc != 1) {
        fprintf(stderr, "usage: %s [--gen-kat]\n", argv[0]);
        return 2;
    }
    m1_valid_lengths();
    m2_length_bounds();
    m3_wrong_context();
    m4_altered();
    m5_out_of_gas();
    m6_resolver();
    m7_state_new();
    m8_call_kinds();
    m9_switch_off_ordinary();
    m10_warm_cold();
    m11_top_level();
    m12_acvp_group5();
    fprintf(stderr, "test_mldsa_precompile: %s (%u failed check(s))\n",
            g_fail_checks ? "FAIL" : "PASS", g_fail_checks);
    return g_fail_checks ? 1 : 0;
}
