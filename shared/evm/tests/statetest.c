/**
 * @file statetest.c
 * @brief Official Ethereum state-test runner for the Nodus EVM engine
 *        (Nodus EVM phase 1) — TEST-ONLY.
 *
 * Usage:
 *   statetest [--fork Prague] [--addr-bytes 20] [--filter SUBSTR] [--verbose]
 *             <file-or-dir>...
 *   statetest --differential [--fork Prague] [--filter S] [--verbose]
 *             <file-or-dir>...   (20/32-byte differential, see the block
 *             above run_diff_case; Nodus-derived, not an official result)
 *   statetest --list-forks <file-or-dir>...
 *   statetest --verify-fixture-roots [--fork F] [--filter S] <file-or-dir>...
 *
 * Design: docs/plans/2026-10-04-nodus-evm-engine-design.md (local) §1, §3.
 * Decision: docs/plans/decisions/2026-10-04-nodus-evm-domain.md (local).
 * Fixtures: execution-spec-tests v5.4.0 fixtures_stable, state_tests/.
 * Reference: ethereum/execution-specs @a87891f7e69eab1f903233c61c5514d8c94bd5d1.
 *
 * ======================================================================
 * FINDINGS — how the reference runs a state test (read, not recalled).
 * Paths are relative to the execution-specs checkout; "statetest/" is
 * packages/testing/src/execution_testing/evm_tools/statetest/, "t8n/" is
 * packages/testing/src/execution_testing/evm_tools/t8n/.
 *
 * Runner shape. statetest/__init__.py:99-176 turns one fixture post entry
 * into a t8n run: data/gasLimit/value are taken at indexes.{data,gas,value}
 * (:120-131); accessLists[d] is used only when non-null (:132-134); the run
 * is t8n with --state-test (:152-163) -> T8N.run_state_test
 * (t8n/__init__.py:341-370): build the block environment, process exactly
 * one transaction, NO system operations (no beacon root / history
 * contract call, no withdrawals, no block reward). The reference runner
 * passes when the post state root equals post.hash (statetest/:289); it
 * does not itself compare `logs` — this runner compares both.
 *
 * (a) BLOCKHASH. statetest/__init__.py:111-114 builds env.blockHashes as
 *     {"0": previousHash} if the fixture env has `previousHash`, else {}.
 *     t8n/block_environment.py:205-223 turns that into the list of the
 *     last min(256, number) hashes, None for unknown heights, [] when no
 *     hashes are given. Prague BLOCKHASH
 *     (src/ethereum/forks/prague/vm/instructions/block.py:46-61) returns 0
 *     when number >= current or current > number + 256, else indexes that
 *     list from the end. With an empty list (or a None entry) that index
 *     is a Python IndexError / TypeError — not an EthereumException, so a
 *     fill that reached it would have crashed; no stable fixture can
 *     depend on it. Measured over all 18 869 Prague cases of the pinned
 *     fixtures: no env carries `previousHash`, and currentNumber is 0x01
 *     in every one. => the in-memory backend serves block 0's hash only
 *     when `previousHash` is present, and reports `available = 0` for
 *     every other height (evm_membackend.c mb_get_block_hash). What the
 *     ENGINE pushes for available = 0 is the engine's contract, not ours.
 *
 * (b) Logs hash. t8n/result.py:98: logs_hash =
 *     keccak256(rlp.encode(block_output.block_logs)); block_logs gets the
 *     transaction's logs (src/ethereum/forks/prague/fork.py:958). A Log is
 *     the dataclass (address, topics, data)
 *     (src/ethereum/forks/prague/blocks.py:307-331). Encoding it as the RLP
 *     list [address (20 bytes), [topic (32 bytes)...], data] is what
 *     `ethereum_rlp` does with a dataclass — UNVERIFIED FROM SOURCE: the
 *     ethereum_rlp package (pyproject.toml: ethereum-rlp>=0.1.6,<0.2) is
 *     not in the local checkout. The empty case is grounded:
 *     keccak256(rlp([])) = 1dcc4de8...9347 (src/ethereum/forks/london/
 *     fork.py:79 EMPTY_OMMER_HASH; value in packages/testing/src/
 *     execution_testing/base_types/constants.py:19-21), and every fixture
 *     entry without logs carries exactly that `logs` value.
 *
 * (c) expectException. process_transaction
 *     (src/ethereum/forks/prague/fork.py:843-875) runs validate_transaction
 *     and check_transaction BEFORE the first state write
 *     (increment_nonce, :875); check_transaction only raises (no write).
 *     On an exception the T8N catches it and records a rejected tx
 *     (t8n/__init__.py:351-361); incorporate_tx_into_block (fork.py:960) is
 *     never reached, so the block diff is empty and the root is the
 *     PRE-state root (t8n/result.py:82-92); block_logs stays empty, so
 *     logs = keccak256(rlp([])). Measured on the pinned fixtures: in all
 *     759 Prague expectException entries post.state equals pre (zero
 *     slots ignored) and logs = 1dcc4de8...9347. => expectException passes iff
 *     evm_tx_apply returns -1, the overlay holds no change, and the
 *     root/logs equal the fixture values.
 *
 * (d) Block environment (t8n/block_environment.py; JSON aliases
 *     packages/testing/src/execution_testing/test_types/block_types.py:
 *     106-128 and fixtures/state.py FixtureEnvironment):
 *       currentCoinbase      -> coinbase                     (:54)
 *       currentNumber        -> number                       (:51)
 *       currentTimestamp     -> time                         (:53)
 *       currentGasLimit      -> block_gas_limit              (:52)
 *       currentBaseFee       -> base_fee_per_gas, as given   (:105-106);
 *                               absent -> derived from parent fields: NOT
 *                               supported here (ERROR)
 *       currentRandom        -> prev_randao = int -> 32 bytes big-endian
 *                               (:197-202), absent -> zero; used because
 *                               Prague is PoS (:72-73)
 *       currentDifficulty    -> ignored for a PoS fork (:72-77)
 *       currentExcessBlobGas -> excess_blob_gas, as given    (:123-124);
 *                               absent -> derived: NOT supported (ERROR)
 *       parent_beacon_block_root = None in a state test       (:79-81)
 *     chain id: fixtures/state.py FixtureConfig.chain_id (`config.chainid`,
 *     default 1). The reference runner itself ignores `config` and uses the
 *     t8n CLI default --state.chainid = 1 (t8n/cli.py:73, :366); the two
 *     agree on every Prague case (measured: config.chainid = 0x01 in all
 *     18 869). This runner uses config.chainid, default 1.
 *
 * Transaction chain id. The fixture carries no chainId field (measured:
 * 0/18 869 Prague cases), so it is read from `txbytes`: a typed tx is
 * type || rlp([chain_id, ...]) (src/ethereum/forks/prague/transactions.py
 * decode_transaction :519-539, AccessListTransaction :134-145,
 * FeeMarketTransaction :207-217); a legacy tx is rlp([nonce, gas_price,
 * gas, to, value, data, v, r, s]) and its chain id is None for v in
 * {27, 28}, else (v - 35) >> 1; v < 35 is refused (transactions.py:
 * 660-675). The engine checks has_chain_id/chain_id against the config.
 * Both chain ids are evm_u256 in the API (evm.h, commit 072a5a76); the
 * reference types the tx chain id as U64 (transactions.py:145, :217), so
 * a txbytes chain id above 64 bits is an ERROR here, not a truncation.
 *
 * Post-state root (state_mpt.py:82-120): pre accounts, then the engine's
 * change set applied in the reference diff order — storage clears, account
 * changes (None = removed), storage changes (zero = removed); state trie
 * key = address (20 bytes in Ethereum mode), value rlp([nonce, balance,
 * storage_root, code_hash]) (merkle_patricia_trie.py:193-210). Pre-state
 * accounts are all inserted (empty ones too) and zero pre-storage values
 * dropped (packages/testing/src/execution_testing/test_types/
 * account_types.py:464-503). EIP-161 empty-account handling is taken from
 * the engine's change set, never re-implemented here.
 * ======================================================================
 *
 * CLASSES (a skip is never a pass):
 *   PASS      root and logs equal the fixture (and, for expectException,
 *             the tx was refused)
 *   FAIL      anything else the engine decided
 *   FAULT     evm_tx_apply / evm_state_new / visit_changes returned -2
 *   ERROR     the harness could not represent the case (bad hex, missing
 *             env field, undecodable txbytes, ...) — not an engine verdict
 *   EXCLUDED  type-3 blob or type-4 set-code tx (design §1)
 * (Every Prague precompile is built in: there is no "precompile
 * unavailable" outcome and no PENDING class.)
 * Exit: 0 iff FAIL == FAULT == ERROR == 0 and at least one case ran;
 * 1 otherwise; 2 usage; 3 no case of the selected fork was found.
 * --differential has its own classes (AGREE / DIFFER / UNEXPLAINED /
 * FAULT / ERROR / WIDE20 / EXCLUDED); exit 0 iff UNEXPLAINED == FAULT ==
 * ERROR == WIDE20 == 0 and at least one case ran (an intended DIFFER is
 * not a failure).
 *
 * Output goes to stdout/stderr through stdio: the report IS this test
 * tool's product (same practice as shared/crypto/zk/tests).
 */
#define _POSIX_C_SOURCE 200809L

#include "evm.h"
#include "evm_u256.h"
#include "evm_rlp.h"
#include "evm_mpt.h"
#include "evm_membackend.h"
#include "crypto/hash/keccak256.h"

#include <json-c/json.h>

#include <dirent.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

/* ── options / counters ─────────────────────────────────────────────── */

typedef struct {
    const char *fork;
    unsigned    addr_bytes;
    const char *filter;
    int         verbose;
    int         list_forks;
    int         verify_roots;
    int         differential;
} opts_t;

typedef struct {
    unsigned long pass, fail, fault, error;
    unsigned long excl_blob, excl_setcode;
    unsigned long deviation;
} counts_t;

/* DOCUMENTED NODUS DEVIATIONS from Prague — cases whose expected Prague
 * result differs ONLY because Nodus adopted a rule Prague does not have.
 * Each entry is matched by exact test name AND data index, and is counted
 * as DEVIATION (never PASS) only when the case would otherwise FAIL.
 * EIP-7823 (modexp lengths <= 1024, Ethereum Osaka; adopted to bound modexp
 * work and GMP memory — decision in the engine design §3 / ledger
 * 2026-10-04): verified by decoding each case's modexp length words —
 *   modexp d29: exp_len 0x40000000000 (4 398 046 511 104),
 *   modexp d30: exp_len 2^255,
 *   randomStatetest650: MSTORE(0x20, 0x10000000) -> exp_len 268 435 456,
 *     then STATICCALL 0x05. */
static const struct { const char *name; long d; const char *why; } DEVIATIONS[] = {
    { "tests/static/state_tests/stPreCompiledContracts/modexpFiller.json::"
      "modexp[fork_Prague-state_test-d29-g0]", 0, "EIP-7823 modexp bound" },
    { "tests/static/state_tests/stPreCompiledContracts/modexpFiller.json::"
      "modexp[fork_Prague-state_test-d29-g1]", 0, "EIP-7823 modexp bound" },
    { "tests/static/state_tests/stPreCompiledContracts/modexpFiller.json::"
      "modexp[fork_Prague-state_test-d29-g2]", 0, "EIP-7823 modexp bound" },
    { "tests/static/state_tests/stPreCompiledContracts/modexpFiller.json::"
      "modexp[fork_Prague-state_test-d29-g3]", 0, "EIP-7823 modexp bound" },
    { "tests/static/state_tests/stPreCompiledContracts/modexpFiller.json::"
      "modexp[fork_Prague-state_test-d30-g0]", 0, "EIP-7823 modexp bound" },
    { "tests/static/state_tests/stPreCompiledContracts/modexpFiller.json::"
      "modexp[fork_Prague-state_test-d30-g1]", 0, "EIP-7823 modexp bound" },
    { "tests/static/state_tests/stPreCompiledContracts/modexpFiller.json::"
      "modexp[fork_Prague-state_test-d30-g2]", 0, "EIP-7823 modexp bound" },
    { "tests/static/state_tests/stPreCompiledContracts/modexpFiller.json::"
      "modexp[fork_Prague-state_test-d30-g3]", 0, "EIP-7823 modexp bound" },
    { "tests/static/state_tests/stRandom2/randomStatetest650Filler.json::"
      "randomStatetest650[fork_Prague-state_test-]", 0,
      "EIP-7823 modexp bound" },
};

static opts_t   g_opt;
static counts_t g_cnt;

/* ── small helpers ──────────────────────────────────────────────────── */

static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static const char *strip0x(const char *s)
{
    return (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) ? s + 2 : s;
}

/* Number (any digit count) -> 32-byte big-endian, right-aligned.
 * @return 0, -1 not hex / does not fit 256 bits. */
static int hex_be32(const char *s, uint8_t out[32])
{
    s = strip0x(s);
    size_t len = strlen(s);
    while (len > 0 && *s == '0') { s++; len--; }
    if (len > 64) return -1;
    memset(out, 0, 32);
    size_t o = 32 - (len + 1) / 2;
    size_t i = 0;
    if (len % 2) {
        int v = hexval(s[0]);
        if (v < 0) return -1;
        out[o++] = (uint8_t)v;
        i = 1;
    }
    for (; i < len; i += 2) {
        int hi = hexval(s[i]), lo = hexval(s[i + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[o++] = (uint8_t)(hi * 16 + lo);
    }
    return 0;
}

static int hex_u64(const char *s, uint64_t *out)
{
    uint8_t b[32];
    if (hex_be32(s, b) != 0) return -1;
    for (int i = 0; i < 24; i++) if (b[i]) return -1;
    uint64_t v = 0;
    for (int i = 24; i < 32; i++) v = (v << 8) | b[i];
    *out = v;
    return 0;
}

/* Byte string (even digit count). *out malloc'd (NULL when empty). */
static int hex_bytes(const char *s, uint8_t **out, size_t *len)
{
    s = strip0x(s);
    size_t n = strlen(s);
    *out = NULL;
    *len = 0;
    if (n % 2) return -1;
    if (n == 0) return 0;
    uint8_t *p = malloc(n / 2);
    if (!p) return -2;
    for (size_t i = 0; i < n; i += 2) {
        int hi = hexval(s[i]), lo = hexval(s[i + 1]);
        if (hi < 0 || lo < 0) { free(p); return -1; }
        p[i / 2] = (uint8_t)(hi * 16 + lo);
    }
    *out = p;
    *len = n / 2;
    return 0;
}

/* Address (<= 20 significant bytes) -> right-aligned 32-byte word. */
static int hex_addr(const char *s, evm_addr *a)
{
    if (hex_be32(s, a->b) != 0) return -1;
    for (int i = 0; i < 12; i++) if (a->b[i]) return -1;
    return 0;
}

static void hex_print(FILE *f, const uint8_t *b, size_t n)
{
    for (size_t i = 0; i < n; i++) fprintf(f, "%02x", b[i]);
}

static json_object *jget(json_object *o, const char *key)
{
    json_object *v = NULL;
    if (!o || !json_object_is_type(o, json_type_object)) return NULL;
    if (!json_object_object_get_ex(o, key, &v)) return NULL;
    return v;
}

static const char *jstr(json_object *o, const char *key)
{
    json_object *v = jget(o, key);
    if (!v || !json_object_is_type(v, json_type_string)) return NULL;
    return json_object_get_string(v);
}

/* Element idx of array field `key` as a string. */
static const char *jarr_str(json_object *o, const char *key, size_t idx)
{
    json_object *a = jget(o, key);
    if (!a || !json_object_is_type(a, json_type_array)) return NULL;
    if (idx >= json_object_array_length(a)) return NULL;
    json_object *v = json_object_array_get_idx(a, idx);
    if (!v || !json_object_is_type(v, json_type_string)) return NULL;
    return json_object_get_string(v);
}

static const char *tx_error_name(evm_tx_error_t e)
{
    switch (e) {
    case EVM_TXERR_NONE:                return "NONE";
    case EVM_TXERR_TYPE_UNSUPPORTED:    return "TYPE_UNSUPPORTED";
    case EVM_TXERR_NONCE_TOO_LOW:       return "NONCE_TOO_LOW";
    case EVM_TXERR_NONCE_TOO_HIGH:      return "NONCE_TOO_HIGH";
    case EVM_TXERR_NONCE_MAX:           return "NONCE_MAX";
    case EVM_TXERR_INSUFFICIENT_FUNDS:  return "INSUFFICIENT_FUNDS";
    case EVM_TXERR_INTRINSIC_GAS:       return "INTRINSIC_GAS";
    case EVM_TXERR_GAS_ALLOWANCE:       return "GAS_ALLOWANCE";
    case EVM_TXERR_FEE_CAP_BELOW_BASE:  return "FEE_CAP_BELOW_BASE";
    case EVM_TXERR_PRIORITY_ABOVE_CAP:  return "PRIORITY_ABOVE_CAP";
    case EVM_TXERR_SENDER_NOT_EOA:      return "SENDER_NOT_EOA";
    case EVM_TXERR_INITCODE_TOO_LARGE:  return "INITCODE_TOO_LARGE";
    case EVM_TXERR_CHAIN_ID:            return "CHAIN_ID";
    case EVM_TXERR_OTHER:               return "OTHER";
    }
    return "?";
}

static const char *status_name(evm_exec_status_t s)
{
    switch (s) {
    case EVM_EXEC_SUCCESS:                return "SUCCESS";
    case EVM_EXEC_REVERT:                 return "REVERT";
    case EVM_EXEC_OUT_OF_GAS:             return "OUT_OF_GAS";
    case EVM_EXEC_INVALID_OPCODE:         return "INVALID_OPCODE";
    case EVM_EXEC_STACK_UNDERFLOW:        return "STACK_UNDERFLOW";
    case EVM_EXEC_STACK_OVERFLOW:         return "STACK_OVERFLOW";
    case EVM_EXEC_BAD_JUMP:               return "BAD_JUMP";
    case EVM_EXEC_STATIC_VIOLATION:       return "STATIC_VIOLATION";
    case EVM_EXEC_RETURNDATA_OOB:         return "RETURNDATA_OOB";
    case EVM_EXEC_CREATE_COLLISION:       return "CREATE_COLLISION";
    case EVM_EXEC_CODE_TOO_LARGE:         return "CODE_TOO_LARGE";
    case EVM_EXEC_INVALID_CODE_PREFIX:    return "INVALID_CODE_PREFIX";
    case EVM_EXEC_PRECOMPILE_FAILURE:     return "PRECOMPILE_FAILURE";
    case EVM_EXEC_BUDGET:                 return "BUDGET";
    }
    return "?";
}

/* ── per-case reporting ─────────────────────────────────────────────── */

typedef struct {
    const char *file;
    const char *name;
    size_t      post_idx;
    long        d, g, v;
} case_id_t;

static void report(const char *cls, const case_id_t *c, const char *fmt, ...)
#if defined(__GNUC__)
    __attribute__((format(printf, 3, 4)))
#endif
    ;

static void report(const char *cls, const case_id_t *c, const char *fmt, ...)
{
    va_list ap;
    printf("%-8s %s :: %s [post %zu d=%ld g=%ld v=%ld]: ", cls, c->file,
           c->name, c->post_idx, c->d, c->g, c->v);
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    putchar('\n');
}

/* ── fixture alloc -> account set ───────────────────────────────────── */

static int load_alloc(json_object *alloc, evm_membackend *mb,
                      char *err, size_t errlen)
{
    if (!alloc || !json_object_is_type(alloc, json_type_object)) {
        snprintf(err, errlen, "alloc is not an object");
        return -1;
    }
    json_object_object_foreach(alloc, akey, aval) {
        evm_addr addr;
        uint64_t nonce;
        uint8_t bal[32];
        uint8_t *code = NULL;
        size_t code_len = 0;
        const char *sn = jstr(aval, "nonce"), *sb = jstr(aval, "balance");
        const char *sc = jstr(aval, "code");
        json_object *st = jget(aval, "storage");
        if (hex_addr(akey, &addr) != 0 || !sn || !sb || !sc ||
            hex_u64(sn, &nonce) != 0 || hex_be32(sb, bal) != 0 ||
            hex_bytes(sc, &code, &code_len) != 0 ||
            (st && !json_object_is_type(st, json_type_object))) {
            free(code);
            snprintf(err, errlen, "bad account %s", akey);
            return -1;
        }
        evm_mem_account *a = NULL;
        int rc = evm_membackend_add_account(mb, &addr, nonce, bal, code,
                                            code_len, NULL, &a);
        free(code);
        if (rc != 0) { snprintf(err, errlen, "out of memory"); return -2; }
        if (st) {
            json_object_object_foreach(st, skey, sval) {
                evm_bytes32 k, v;
                if (!json_object_is_type(sval, json_type_string) ||
                    hex_be32(skey, k.b) != 0 ||
                    hex_be32(json_object_get_string(sval), v.b) != 0) {
                    snprintf(err, errlen, "bad storage in %s", akey);
                    return -1;
                }
                if (evm_mem_account_add_slot(a, &k, &v) != 0) {
                    snprintf(err, errlen, "out of memory");
                    return -2;
                }
            }
        }
    }
    if (evm_membackend_finalize(mb) != 0) {
        snprintf(err, errlen, "duplicate address or storage key");
        return -1;
    }
    return 0;
}

/* ── engine change set -> collected list ────────────────────────────── */

typedef struct {
    evm_bytes32 key, val;
} kv32_t;

typedef struct {
    evm_addr    addr;
    int         deleted;
    uint64_t    nonce;
    uint8_t     balance[32];
    int         code_changed;
    uint8_t    *code;
    size_t      code_len;
    evm_bytes32 code_hash;
    int         storage_cleared;
    kv32_t     *slots;
    size_t      n_slots, cap_slots;
} change_t;

typedef struct {
    change_t *v;
    size_t    n, cap;
    char      why[200];
} changes_t;

enum { VISIT_ORDER = 1, VISIT_OOM = 2 };

static void changes_free(changes_t *cs)
{
    for (size_t i = 0; i < cs->n; i++) {
        free(cs->v[i].code);
        free(cs->v[i].slots);
    }
    free(cs->v);
    memset(cs, 0, sizeof(*cs));
}

static int visit_account(void *ctx, const evm_account_change_t *c)
{
    changes_t *cs = ctx;
    if (cs->n > 0 && memcmp(cs->v[cs->n - 1].addr.b, c->addr.b, 32) >= 0) {
        snprintf(cs->why, sizeof(cs->why),
                 "change set: account order not strictly ascending");
        return VISIT_ORDER;
    }
    if (cs->n == cs->cap) {
        size_t ncap = cs->cap ? cs->cap * 2 : 16;
        change_t *nv = realloc(cs->v, ncap * sizeof(*nv));
        if (!nv) return VISIT_OOM;
        cs->v = nv;
        cs->cap = ncap;
    }
    change_t *d = &cs->v[cs->n];
    memset(d, 0, sizeof(*d));
    d->addr = c->addr;
    d->deleted = c->deleted;
    d->nonce = c->nonce;
    evm_u256_to_be(d->balance, &c->balance);
    d->code_changed = c->code_changed;
    d->code_hash = c->code_hash;
    d->storage_cleared = c->storage_cleared;
    if (c->code_changed && c->code_len) {
        d->code = malloc(c->code_len);
        if (!d->code) return VISIT_OOM;
        memcpy(d->code, c->code, c->code_len);
        d->code_len = c->code_len;
    }
    cs->n++;
    return 0;
}

static int visit_storage(void *ctx, const evm_addr *addr,
                         const evm_bytes32 *key, const evm_bytes32 *value)
{
    changes_t *cs = ctx;
    if (cs->n == 0 || memcmp(cs->v[cs->n - 1].addr.b, addr->b, 32) != 0) {
        snprintf(cs->why, sizeof(cs->why),
                 "change set: storage slot not after its account");
        return VISIT_ORDER;
    }
    change_t *d = &cs->v[cs->n - 1];
    if (d->n_slots > 0 &&
        memcmp(d->slots[d->n_slots - 1].key.b, key->b, 32) >= 0) {
        snprintf(cs->why, sizeof(cs->why),
                 "change set: storage key order not strictly ascending");
        return VISIT_ORDER;
    }
    if (d->n_slots == d->cap_slots) {
        size_t ncap = d->cap_slots ? d->cap_slots * 2 : 4;
        kv32_t *ns = realloc(d->slots, ncap * sizeof(*ns));
        if (!ns) return VISIT_OOM;
        d->slots = ns;
        d->cap_slots = ncap;
    }
    d->slots[d->n_slots].key = *key;
    d->slots[d->n_slots].val = *value;
    d->n_slots++;
    return 0;
}

/* Merge pre + change list into `post` (state_mpt.py:82-120 order).
 * @return 0, -1 inconsistent change set (why filled), -2 OOM. */
static int build_post(const evm_membackend *pre, const changes_t *cs,
                      evm_membackend *post, char *why, size_t whylen)
{
    static const uint8_t empty_code_hash[32] = {
        0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d,
        0xb2, 0xdc, 0xc7, 0x03, 0xc0, 0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82,
        0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70
    };  /* keccak256(b"") — EMPTY_CODE_HASH */
    size_t i = 0, j = 0;
    while (i < pre->n || j < cs->n) {
        const evm_mem_account *p = NULL;
        const change_t *c = NULL;
        if (j >= cs->n) {
            p = &pre->acc[i++];
        } else if (i >= pre->n) {
            c = &cs->v[j++];
        } else {
            int cmp = memcmp(pre->acc[i].addr.b, cs->v[j].addr.b, 32);
            if (cmp < 0) p = &pre->acc[i++];
            else if (cmp > 0) c = &cs->v[j++];
            else { p = &pre->acc[i++]; c = &cs->v[j++]; }
        }

        evm_mem_account *a = NULL;
        if (!c) {                                   /* untouched pre account */
            if (evm_membackend_add_account(post, &p->addr, p->nonce,
                                           p->balance, p->code, p->code_len,
                                           &p->code_hash, &a) != 0)
                return -2;
            for (size_t k = 0; k < p->n_slots; k++)
                if (evm_mem_account_add_slot(a, &p->slots[k].key,
                                             &p->slots[k].val) != 0)
                    return -2;
            continue;
        }
        if (c->deleted) continue;                   /* removed (and its slots) */

        const uint8_t *code = NULL;
        size_t code_len = 0;
        if (c->code_changed) {
            uint8_t h[32];
            code = c->code;
            code_len = c->code_len;
            if (keccak256(code_len ? code : (const uint8_t *)"", code_len,
                          h) != 0)
                return -2;
            if (memcmp(h, c->code_hash.b, 32) != 0) {
                snprintf(why, whylen, "change set: code_hash != keccak(code)");
                return -1;
            }
        } else if (p) {
            code = p->code;
            code_len = p->code_len;
            if (memcmp(p->code_hash.b, c->code_hash.b, 32) != 0) {
                snprintf(why, whylen,
                         "change set: code_hash changed without code_changed");
                return -1;
            }
        } else if (memcmp(c->code_hash.b, empty_code_hash, 32) != 0) {
            snprintf(why, whylen,
                     "change set: new account with code_hash but no code");
            return -1;
        }
        if (evm_membackend_add_account(post, &c->addr, c->nonce, c->balance,
                                       code, code_len, &c->code_hash, &a) != 0)
            return -2;

        /* storage: base (pre unless cleared) merged with the changed slots;
         * a zero changed value removes the slot (add_slot drops zeros). */
        size_t bn = (p && !c->storage_cleared) ? p->n_slots : 0;
        size_t x = 0, y = 0;
        while (x < bn || y < c->n_slots) {
            int cmp;
            if (y >= c->n_slots) cmp = -1;
            else if (x >= bn) cmp = 1;
            else cmp = memcmp(p->slots[x].key.b, c->slots[y].key.b, 32);
            const evm_bytes32 *k, *v;
            if (cmp < 0) { k = &p->slots[x].key; v = &p->slots[x].val; x++; }
            else {
                k = &c->slots[y].key; v = &c->slots[y].val; y++;
                if (cmp == 0) x++;
            }
            if (evm_mem_account_add_slot(a, k, v) != 0) return -2;
        }
    }
    return evm_membackend_finalize(post) == 0 ? 0 : -2;
}

/* keccak256(rlp([[address, [topics...], data], ...])) — finding (b). */
static int logs_hash(const evm_tx_result_t *res, int applied,
                     unsigned addr_bytes, uint8_t out[32])
{
    evm_rlp_buf b = {0};
    int rc = 0;
    if (applied) {
        for (size_t i = 0; i < res->n_logs && rc == 0; i++) {
            const evm_log_t *l = &res->logs[i];
            size_t ls = b.len;
            rc = evm_rlp_put_bytes(&b, l->addr.b + (32 - addr_bytes),
                                   addr_bytes);
            size_t ts = b.len;
            for (unsigned t = 0; t < l->n_topics && t < 4 && rc == 0; t++)
                rc = evm_rlp_put_bytes(&b, l->topics[t].b, 32);
            if (rc == 0) rc = evm_rlp_wrap_list(&b, ts);
            if (rc == 0) rc = evm_rlp_put_bytes(&b, l->data, l->data_len);
            if (rc == 0) rc = evm_rlp_wrap_list(&b, ls);
            if (rc == 0 && l->n_topics > 4) rc = -1;
        }
    }
    if (rc == 0) rc = evm_rlp_wrap_list(&b, 0);
    if (rc == 0 && keccak256(b.p, b.len, out) != 0) rc = -2;
    evm_rlp_buf_free(&b);
    return rc;
}

/* Verbose: difference between the computed post-state and the fixture's
 * post.state (bounded output). */
static void print_state_diff(const evm_membackend *got,
                             const evm_membackend *want)
{
    int lines = 0;
    const int max_lines = 24;
    size_t i = 0, j = 0;
    while ((i < got->n || j < want->n) && lines < max_lines) {
        int cmp;
        if (j >= want->n) cmp = -1;
        else if (i >= got->n) cmp = 1;
        else cmp = memcmp(got->acc[i].addr.b, want->acc[j].addr.b, 32);
        if (cmp < 0) {
            printf("    + unexpected account 0x");
            hex_print(stdout, got->acc[i].addr.b + 12, 20);
            putchar('\n');
            lines++; i++;
            continue;
        }
        if (cmp > 0) {
            printf("    - missing account    0x");
            hex_print(stdout, want->acc[j].addr.b + 12, 20);
            putchar('\n');
            lines++; j++;
            continue;
        }
        const evm_mem_account *g = &got->acc[i++], *w = &want->acc[j++];
        if (g->nonce != w->nonce) {
            printf("    ~ 0x"); hex_print(stdout, g->addr.b + 12, 20);
            printf(" nonce got %llu want %llu\n",
                   (unsigned long long)g->nonce, (unsigned long long)w->nonce);
            lines++;
        }
        if (memcmp(g->balance, w->balance, 32) != 0) {
            printf("    ~ 0x"); hex_print(stdout, g->addr.b + 12, 20);
            printf(" balance got 0x"); hex_print(stdout, g->balance, 32);
            printf(" want 0x"); hex_print(stdout, w->balance, 32);
            putchar('\n');
            lines++;
        }
        if (memcmp(g->code_hash.b, w->code_hash.b, 32) != 0) {
            printf("    ~ 0x"); hex_print(stdout, g->addr.b + 12, 20);
            printf(" code_hash got "); hex_print(stdout, g->code_hash.b, 32);
            printf(" want "); hex_print(stdout, w->code_hash.b, 32);
            putchar('\n');
            lines++;
        }
        size_t x = 0, y = 0;
        while ((x < g->n_slots || y < w->n_slots) && lines < max_lines) {
            int c2;
            if (y >= w->n_slots) c2 = -1;
            else if (x >= g->n_slots) c2 = 1;
            else c2 = memcmp(g->slots[x].key.b, w->slots[y].key.b, 32);
            if (c2 == 0 &&
                memcmp(g->slots[x].val.b, w->slots[y].val.b, 32) == 0) {
                x++; y++;
                continue;
            }
            printf("    ~ 0x"); hex_print(stdout, g->addr.b + 12, 20);
            printf(" slot ");
            hex_print(stdout, (c2 <= 0 ? g->slots[x].key.b
                                       : w->slots[y].key.b), 32);
            printf(" got ");
            if (c2 <= 0) hex_print(stdout, g->slots[x].val.b, 32);
            else printf("0");
            printf(" want ");
            if (c2 >= 0) hex_print(stdout, w->slots[y].val.b, 32);
            else printf("0");
            putchar('\n');
            lines++;
            if (c2 <= 0) x++;
            if (c2 >= 0) y++;
        }
    }
    if (lines >= max_lines) printf("    ... (diff truncated)\n");
}

/* ── per-test parsed inputs ─────────────────────────────────────────── */

typedef struct {
    evm_block_env_t env;
    evm_u256        chain_id;           /* full word (evm.h, 072a5a76) */
    int             has_prev_hash;
    evm_bytes32     prev_hash;
} test_env_t;

static int parse_env(json_object *test, test_env_t *te, char *err,
                     size_t errlen)
{
    json_object *env = jget(test, "env");
    memset(te, 0, sizeof(*te));
    if (!env) { snprintf(err, errlen, "no env"); return -1; }
    const char *s;
    uint8_t b[32];

    if (!(s = jstr(env, "currentCoinbase")) || hex_addr(s, &te->env.coinbase))
        { snprintf(err, errlen, "env.currentCoinbase"); return -1; }
    if (!(s = jstr(env, "currentNumber")) || hex_u64(s, &te->env.number))
        { snprintf(err, errlen, "env.currentNumber"); return -1; }
    if (!(s = jstr(env, "currentTimestamp")) ||
        hex_u64(s, &te->env.timestamp))
        { snprintf(err, errlen, "env.currentTimestamp"); return -1; }
    if (!(s = jstr(env, "currentGasLimit")) ||
        hex_u64(s, &te->env.gas_limit))
        { snprintf(err, errlen, "env.currentGasLimit"); return -1; }
    if (!(s = jstr(env, "currentBaseFee")) || hex_be32(s, b))
        { snprintf(err, errlen, "env.currentBaseFee missing/invalid "
                   "(parent derivation not supported)"); return -1; }
    evm_u256_from_be(&te->env.base_fee, b);
    if ((s = jstr(env, "currentRandom")) != NULL) {
        if (hex_be32(s, te->env.prev_randao.b))
            { snprintf(err, errlen, "env.currentRandom"); return -1; }
    }
    if (!(s = jstr(env, "currentExcessBlobGas")) ||
        hex_u64(s, &te->env.excess_blob_gas))
        { snprintf(err, errlen, "env.currentExcessBlobGas missing/invalid "
                   "(parent derivation not supported)"); return -1; }
    if ((s = jstr(env, "previousHash")) != NULL) {
        if (hex_be32(s, te->prev_hash.b))
            { snprintf(err, errlen, "env.previousHash"); return -1; }
        te->has_prev_hash = 1;
    }
    evm_u256_from_u64(&te->chain_id, 1);    /* FixtureConfig default */
    json_object *cfg = jget(test, "config");
    if (cfg && (s = jstr(cfg, "chainid")) != NULL) {
        if (hex_be32(s, b))
            { snprintf(err, errlen, "config.chainid"); return -1; }
        evm_u256_from_be(&te->chain_id, b);
    }
    return 0;
}

/* Owned buffers of one built transaction. */
typedef struct {
    evm_tx_t            tx;
    uint8_t            *data;
    evm_access_entry_t *access;
    evm_bytes32        *keys;
} built_tx_t;

static void built_tx_free(built_tx_t *bt)
{
    free(bt->data);
    free(bt->access);
    free(bt->keys);
    memset(bt, 0, sizeof(*bt));
}

/* Chain id from txbytes (see header: transactions.py:519-539, 660-675).
 * Also cross-checks the tx type. */
static int txbytes_chain_id(const char *txhex, uint8_t type, evm_tx_t *tx,
                            char *err, size_t errlen)
{
    uint8_t *raw = NULL;
    size_t n = 0;
    int rc = -1;
    evm_rlp_item list, it;
    uint64_t v;
    if (hex_bytes(txhex, &raw, &n) != 0 || n == 0) {
        snprintf(err, errlen, "txbytes not decodable");
        goto out;
    }
    if (raw[0] >= 0xc0) {                                  /* legacy */
        if (type != 0) {
            snprintf(err, errlen, "txbytes legacy but fields say type %u",
                     type);
            goto out;
        }
        if (evm_rlp_decode_item(raw, n, &list) != 0 || list.total != n ||
            evm_rlp_list_get(&list, 6, &it) != 0 ||
            evm_rlp_item_to_u64(&it, &v) != 0) {
            snprintf(err, errlen, "txbytes legacy v not decodable");
            goto out;
        }
        if (v == 27 || v == 28) {
            tx->has_chain_id = 0;
            evm_u256_zero(&tx->chain_id);
        } else if (v < 35) {
            snprintf(err, errlen, "legacy v=%llu is refused by the reference "
                     "(InvalidSignatureError) and has no engine input form",
                     (unsigned long long)v);
            goto out;
        } else {
            tx->has_chain_id = 1;
            evm_u256_from_u64(&tx->chain_id, (v - 35) >> 1);
        }
    } else {
        if (raw[0] != type) {
            snprintf(err, errlen, "txbytes type %u but fields say type %u",
                     raw[0], type);
            goto out;
        }
        if (evm_rlp_decode_item(raw + 1, n - 1, &list) != 0 ||
            list.total != n - 1 ||
            evm_rlp_list_get(&list, 0, &it) != 0 ||
            evm_rlp_item_to_u64(&it, &v) != 0) {
            snprintf(err, errlen, "txbytes typed chain_id not decodable");
            goto out;
        }
        tx->has_chain_id = 1;
        evm_u256_from_u64(&tx->chain_id, v);
    }
    rc = 0;
out:
    free(raw);
    return rc;
}

static int build_tx(json_object *jtx, json_object *post, long d, long g,
                    long vi, built_tx_t *bt, char *err, size_t errlen)
{
    evm_tx_t *tx = &bt->tx;
    const char *s;
    uint8_t b[32];
    memset(bt, 0, sizeof(*bt));

    json_object *al_all = jget(jtx, "accessLists");
    if (jget(jtx, "maxFeePerGas")) tx->type = 2;
    else if (al_all) tx->type = 1;
    else tx->type = 0;

    if (!(s = jstr(jtx, "sender")) || hex_addr(s, &tx->sender))
        { snprintf(err, errlen, "transaction.sender"); return -1; }
    if (!(s = jstr(jtx, "to")))
        { snprintf(err, errlen, "transaction.to"); return -1; }
    if (strip0x(s)[0] == '\0') {
        tx->is_create = 1;
    } else if (hex_addr(s, &tx->to)) {
        snprintf(err, errlen, "transaction.to");
        return -1;
    }
    if (!(s = jstr(jtx, "nonce")) || hex_u64(s, &tx->nonce))
        { snprintf(err, errlen, "transaction.nonce"); return -1; }
    if (!(s = jarr_str(jtx, "gasLimit", (size_t)g)) ||
        hex_u64(s, &tx->gas_limit))
        { snprintf(err, errlen, "transaction.gasLimit[%ld]", g); return -1; }
    if (!(s = jarr_str(jtx, "value", (size_t)vi)) || hex_be32(s, b))
        { snprintf(err, errlen, "transaction.value[%ld]", vi); return -1; }
    evm_u256_from_be(&tx->value, b);
    if (!(s = jarr_str(jtx, "data", (size_t)d)) ||
        hex_bytes(s, &bt->data, &tx->data_len))
        { snprintf(err, errlen, "transaction.data[%ld]", d); return -1; }
    tx->data = bt->data;

    if (tx->type == 2) {
        if (!(s = jstr(jtx, "maxFeePerGas")) || hex_be32(s, b))
            { snprintf(err, errlen, "transaction.maxFeePerGas"); return -1; }
        evm_u256_from_be(&tx->max_fee_per_gas, b);
        if (!(s = jstr(jtx, "maxPriorityFeePerGas")) || hex_be32(s, b))
            { snprintf(err, errlen, "transaction.maxPriorityFeePerGas");
              return -1; }
        evm_u256_from_be(&tx->max_priority_fee_per_gas, b);
    } else {
        if (!(s = jstr(jtx, "gasPrice")) || hex_be32(s, b))
            { snprintf(err, errlen, "transaction.gasPrice"); return -1; }
        evm_u256_from_be(&tx->gas_price, b);
    }

    /* access list: accessLists[d], null = none (statetest/:132-134) */
    if (al_all) {
        if (!json_object_is_type(al_all, json_type_array) ||
            (size_t)d >= json_object_array_length(al_all))
            { snprintf(err, errlen, "transaction.accessLists[%ld]", d);
              return -1; }
        json_object *al = json_object_array_get_idx(al_all, (size_t)d);
        if (al && !json_object_is_type(al, json_type_null)) {
            if (!json_object_is_type(al, json_type_array))
                { snprintf(err, errlen, "accessLists[%ld] not array", d);
                  return -1; }
            size_t na = json_object_array_length(al), nk = 0;
            for (size_t i = 0; i < na; i++) {
                json_object *ks = jget(json_object_array_get_idx(al, i),
                                       "storageKeys");
                if (!ks || !json_object_is_type(ks, json_type_array))
                    { snprintf(err, errlen, "accessLists entry"); return -1; }
                nk += json_object_array_length(ks);
            }
            if (na > UINT32_MAX || nk > UINT32_MAX)
                { snprintf(err, errlen, "access list too large"); return -1; }
            bt->access = na ? calloc(na, sizeof(*bt->access)) : NULL;
            bt->keys = nk ? calloc(nk, sizeof(*bt->keys)) : NULL;
            if ((na && !bt->access) || (nk && !bt->keys))
                { snprintf(err, errlen, "out of memory"); return -2; }
            size_t kpos = 0;
            for (size_t i = 0; i < na; i++) {
                json_object *e = json_object_array_get_idx(al, i);
                json_object *ks = jget(e, "storageKeys");
                if (!(s = jstr(e, "address")) ||
                    hex_addr(s, &bt->access[i].addr))
                    { snprintf(err, errlen, "accessLists address"); return -1; }
                size_t nki = json_object_array_length(ks);
                bt->access[i].n_keys = (uint32_t)nki;
                bt->access[i].keys = nki ? &bt->keys[kpos] : NULL;
                for (size_t k = 0; k < nki; k++) {
                    json_object *kj = json_object_array_get_idx(ks, k);
                    if (!kj || !json_object_is_type(kj, json_type_string) ||
                        hex_be32(json_object_get_string(kj),
                                 bt->keys[kpos].b))
                        { snprintf(err, errlen, "accessLists key"); return -1; }
                    kpos++;
                }
            }
            tx->n_access = (uint32_t)na;
            tx->access = bt->access;
        }
    }

    if (!(s = jstr(post, "txbytes")))
        { snprintf(err, errlen, "post.txbytes"); return -1; }
    return txbytes_chain_id(s, tx->type, tx, err, errlen);
}

/* ── one case ───────────────────────────────────────────────────────── */

static void run_case(const case_id_t *cid, json_object *test, json_object *post,
                     const evm_membackend *pre, const test_env_t *te)
{
    char err[256] = "";
    uint8_t want_root[32], want_logs[32], got_root[32], got_logs[32];
    const char *s;
    json_object *jtx = jget(test, "transaction");

    if (!(s = jstr(post, "hash")) || hex_be32(s, want_root) ||
        !(s = jstr(post, "logs")) || hex_be32(s, want_logs)) {
        report("ERROR", cid, "post.hash / post.logs");
        g_cnt.error++;
        return;
    }
    const char *expect_exc = jstr(post, "expectException");

    built_tx_t bt;
    int brc = build_tx(jtx, post, cid->d, cid->g, cid->v, &bt, err,
                       sizeof(err));
    if (brc != 0) {
        report("ERROR", cid, "%s", err);
        g_cnt.error++;
        built_tx_free(&bt);
        return;
    }

    evm_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.fork = EVM_FORK_PRAGUE;
    cfg.addr_bytes = (uint8_t)g_opt.addr_bytes;
    cfg.chain_id = te->chain_id;
    cfg.precompile_mask = EVM_PRECOMPILES_PRAGUE;   /* Prague: 0x01..0x11 */

    evm_backend_t be;
    evm_membackend_bind(pre, &be);

    evm_state_t *st = evm_state_new(&cfg, &be);
    if (!st) {
        report("FAULT", cid, "evm_state_new returned NULL");
        g_cnt.fault++;
        built_tx_free(&bt);
        return;
    }

    evm_tx_result_t res;
    memset(&res, 0, sizeof(res));
    int rc = evm_tx_apply(st, &te->env, &bt.tx, &res);

    changes_t cs;
    memset(&cs, 0, sizeof(cs));
    evm_membackend got;
    evm_membackend_init(&got);

    if (rc == -2) {
        report("FAULT", cid, "evm_tx_apply returned -2");
        g_cnt.fault++;
        goto done;
    }
    if (rc != 0 && rc != -1) {
        /* -3 (EVM_BUDGET) cannot come from the in-memory backend; any
         * value other than 0 / -1 is a fault for the conformance run */
        report("FAULT", cid, "evm_tx_apply returned %d", rc);
        g_cnt.fault++;
        goto done;
    }
    if (expect_exc && rc == 0) {
        report("FAIL", cid, "expected %s, tx applied (status %s)", expect_exc,
               status_name(res.status));
        g_cnt.fail++;
        goto done;
    }
    if (!expect_exc && rc == -1) {
        report("FAIL", cid, "tx refused: %s", tx_error_name(res.tx_error));
        g_cnt.fail++;
        goto done;
    }

    {
        evm_change_visitor_t vis;
        vis.account = visit_account;
        vis.storage = visit_storage;
        vis.ctx = &cs;
        int vrc = evm_state_visit_changes(st, &vis);
        if (vrc == -2) {
            report("FAULT", cid, "evm_state_visit_changes returned -2");
            g_cnt.fault++;
            goto done;
        }
        if (vrc == VISIT_OOM) {
            report("ERROR", cid, "harness out of memory");
            g_cnt.error++;
            goto done;
        }
        if (vrc != 0) {
            report("FAIL", cid, "%s", cs.why[0] ? cs.why
                   : "evm_state_visit_changes returned an unexpected value");
            g_cnt.fail++;
            goto done;
        }
    }
    if (rc == -1 && cs.n != 0) {
        report("FAIL", cid, "tx refused (%s) but overlay holds %zu changed "
               "account(s)", tx_error_name(res.tx_error), cs.n);
        g_cnt.fail++;
        goto done;
    }

    {
        int prc = build_post(pre, &cs, &got, err, sizeof(err));
        if (prc == -1) {
            report("FAIL", cid, "%s", err);
            g_cnt.fail++;
            goto done;
        }
        if (prc != 0 ||
            evm_membackend_state_root(&got, g_opt.addr_bytes, got_root) != 0 ||
            logs_hash(&res, rc == 0, g_opt.addr_bytes, got_logs) != 0) {
            report("ERROR", cid, "harness could not compute root/logs");
            g_cnt.error++;
            goto done;
        }
    }

    {
        int root_ok = memcmp(got_root, want_root, 32) == 0;
        int logs_ok = memcmp(got_logs, want_logs, 32) == 0;
        if (root_ok && logs_ok) {
            g_cnt.pass++;
            if (g_opt.verbose) report("PASS", cid, "%s",
                                      expect_exc ? "refused as expected" : "");
            goto done;
        }
        for (size_t di = 0; di < sizeof(DEVIATIONS) / sizeof(DEVIATIONS[0]);
             di++) {
            if (strcmp(cid->name, DEVIATIONS[di].name) == 0 &&
                cid->d == DEVIATIONS[di].d) {
                report("DEVIATION", cid, "%s (documented Nodus rule; NOT a "
                       "pass)", DEVIATIONS[di].why);
                g_cnt.deviation++;
                goto done;
            }
        }
        report("FAIL", cid, "%s%s%s (rc %d, %s, gas_used %llu)",
               root_ok ? "" : "state root mismatch",
               (!root_ok && !logs_ok) ? ", " : "",
               logs_ok ? "" : "logs hash mismatch", rc,
               rc == 0 ? status_name(res.status) : tx_error_name(res.tx_error),
               (unsigned long long)res.gas_used);
        g_cnt.fail++;
        if (g_opt.verbose) {
            printf("    root got  "); hex_print(stdout, got_root, 32);
            printf("\n    root want "); hex_print(stdout, want_root, 32);
            printf("\n    logs got  "); hex_print(stdout, got_logs, 32);
            printf("\n    logs want "); hex_print(stdout, want_logs, 32);
            printf("\n    n_logs %zu\n", rc == 0 ? res.n_logs : (size_t)0);
            evm_membackend want;
            evm_membackend_init(&want);
            if (load_alloc(jget(post, "state"), &want, err, sizeof(err)) == 0)
                print_state_diff(&got, &want);
            else
                printf("    (post.state not loadable: %s)\n", err);
            evm_membackend_free(&want);
        }
    }

done:
    evm_membackend_free(&got);
    changes_free(&cs);
    evm_tx_result_free(&res);
    evm_state_free(st);
    built_tx_free(&bt);
}

/* --verify-fixture-roots: root(post.state) must equal post.hash. Checks
 * the harness's RLP/MPT/account encoding against official values; the
 * engine is not called. */
static void verify_fixture_root(const case_id_t *cid, json_object *post)
{
    char err[256];
    uint8_t want[32], got[32];
    const char *s = jstr(post, "hash");
    evm_membackend mb;
    evm_membackend_init(&mb);
    if (!s || hex_be32(s, want) != 0) {
        report("ERROR", cid, "post.hash");
        g_cnt.error++;
    } else if (load_alloc(jget(post, "state"), &mb, err, sizeof(err)) != 0) {
        report("ERROR", cid, "post.state: %s", err);
        g_cnt.error++;
    } else if (evm_membackend_state_root(&mb, 20, got) != 0) {
        report("ERROR", cid, "root computation failed");
        g_cnt.error++;
    } else if (memcmp(got, want, 32) != 0) {
        report("FAIL", cid, "root(post.state) != post.hash");
        g_cnt.fail++;
    } else {
        g_cnt.pass++;
    }
    evm_membackend_free(&mb);
}

/* ── --differential: the same case at addr_bytes 20 and 32 ─────────────
 *
 * NODUS-DERIVED, SELF-CONSISTENT — not an official result: both runs are
 * this engine, so a bug the two widths share is invisible here. Kurultay
 * #9 item 4 (docs/plans/decisions/2026-10-06-kurultay-9-evm-address-
 * width-summary.md; Astra r1 Q2).
 *
 * Inputs. hex_addr rejects any fixture address with a non-zero byte in
 * 0..11, so every pre-state / tx / access-list / coinbase address is
 * already the right-aligned 32-byte word with zero high bytes — the
 * zero-extended form the 32-byte engine accepts (evm_tx.c addr_canonical).
 * Both runs therefore get the SAME loaded pre, env and built tx; only
 * cfg.addr_bytes differs. nodus_profile = 0 in both (the Ethereum
 * profile, as in the conformance run): production also runs the Nodus
 * profile, which this mode does not exercise.
 *
 * Where the engine reads the width (grep of addr_bytes, read at f7aa7984):
 *   evm_addr_from_word (evm_state.c:92-99) — a stack word becomes an
 *     address: 20-byte mode masks bytes 0..11, 32-byte mode keeps them;
 *     consumers CALL family (evm_interp.c:972), SELFDESTRUCT (:1154),
 *     BALANCE (:1496), EXTCODESIZE (:1570), EXTCODECOPY (:1587),
 *     EXTCODEHASH (:1637);
 *   evm_compute_contract_address / create2_address (evm_interp.c:149-186)
 *     — the creator is encoded with addr_bytes bytes, 32-byte mode keeps
 *     the whole hash; used by CREATE/CREATE2 (:1109, :1113) and a create
 *     tx (evm_tx.c:354);
 *   addr_canonical (evm_tx.c:93-99) — cannot fire, inputs are canonical;
 *   ticket_addr checks (evm_state.c:1268) — Nodus profile only.
 * So with canonical inputs and profile 0 the two runs can only part when
 * a WIDE address (non-zero byte in 0..11) arises in the 32-byte run. The
 * runner records every address the engine hands the backend (a wrapper
 * around the in-memory backend) and every post-state account.
 *
 * Normalized result, compared in this order (the first difference is
 * the one reported): applied/refused -> tx_error or status -> gas_used ->
 * gas_used_pre_refund -> output -> wei_destroyed -> post-state (accounts
 * keyed by the low 20 bytes; nonce, balance, code_hash, storage) -> logs
 * (count; emitter projected to 20 bytes; topics; data). State roots and
 * logs hashes are NOT compared (trie keys / emitters differ in width).
 *
 * STRICT verdict per case (the primary one; printed per case, totals
 * first in the summary). An address map pairs every account the 32-byte
 * run created with its 20-byte counterpart, from the engine's own
 * creation preimages (block "creation events" below): CREATE by (creator
 * mapped, nonce), CREATE2 by (creator mapped, salt, initcode hash), or
 * (creator mapped, salt) with the initcode equal after substitution;
 * transitive. The 32-byte result is then translated (post accounts,
 * storage keys and values, log emitters / topics / aligned data words,
 * aligned output words, the created address) and must EQUAL the 20-byte
 * result on every normalized field (compare_runs, plus the created
 * address):
 *   S_AGREE      equal after substitution;
 *   S_DIFFER     not equal, and a width-dependent class is present —
 *                FIXTURE_20B, WIDE_WORD, MASKED_160 (evidence) or
 *                ADDR_ARITH (verified by a second translation); see the
 *                class block at classify_strict;
 *   S_UNEXPL     not equal, no such class: listed one per line with the
 *                first differing field after substitution.
 * Limit: FIXTURE_20B / WIDE_WORD / MASKED_160 are still presence-based —
 * a 32-byte defect inside a case that ALSO carries one of them is not
 * seen; only S_AGREE is an equality.
 *
 * Presence-based verdict (the first version of this mode, kept for its
 * counts and the old -> strict migration matrix; per-case lines with
 * --verbose):
 *   AGREE        normalized results equal
 *   DIFFER       results differ AND the 32-byte run produced a wide
 *                address; sub-labels (heuristic, per wide address):
 *       CREATE       the address re-derives as keccak(rlp([creator as
 *                    32 bytes, nonce])) for a known creator and a nonce
 *                    in its pre..post range (CREATE / create tx);
 *       WIDE_WORD    its low 20 bytes name an address the 20-byte run
 *                    saw (pre-state, a backend read, its post-state) or a
 *                    precompile number: a stack word with high bytes set
 *                    that 20-byte mode masks (BALANCE, EXTCODE{SIZE,COPY,
 *                    HASH}, the CALL family, SELFDESTRUCT, a precompile
 *                    number with high bits);
 *       CREATE2_OR_DERIVED  neither: not re-derivable here (CREATE2 needs
 *                    salt + initcode the harness does not see, or a word
 *                    computed from a created address).
 *   UNEXPLAINED  results differ and no wide address was seen
 *   FAULT        either run faulted (engine -2, inconsistent change set)
 *   ERROR        the harness could not represent / compute the case
 *   WIDE20       a wide address reached the backend in the 20-byte run
 *                (masking failed) — counted separately, never expected
 * Limit: BALANCE, EXTCODE{SIZE,COPY,HASH}, the CALL family and
 * SELFDESTRUCT charge the access cost before
 * the backend read; a wide word whose cold cost runs out of gas is never
 * recorded, so such a case shows as UNEXPLAINED and is read by hand.
 * --verbose also prints AGREE / BASELINE lines and, before each DIFFER
 * line, one "wide 0x<32 bytes> <label>" line per wide address.
 * BASELINE: the 20-byte run is also checked against the fixture (root,
 * logs, expectException) so the reader knows the reference side is the
 * conformant one; the documented DEVIATIONS show up there.
 */

typedef struct {
    const evm_backend_t *inner;
    evm_addr *seen;
    size_t    n, cap;
    int       oom;
} rec_be_t;

static int addr_is_wide(const evm_addr *a)
{
    for (int i = 0; i < 12; i++) if (a->b[i]) return 1;
    return 0;
}

static void rec_note(rec_be_t *r, const evm_addr *a)
{
    if (r->n == r->cap) {
        size_t ncap = r->cap ? r->cap * 2 : 32;
        evm_addr *nv = realloc(r->seen, ncap * sizeof(*nv));
        if (!nv) { r->oom = 1; return; }
        r->seen = nv;
        r->cap = ncap;
    }
    r->seen[r->n++] = *a;
}

static int rec_get_account(void *ctx, const evm_addr *addr, evm_account_t *out)
{
    rec_be_t *r = ctx;
    rec_note(r, addr);
    return r->inner->get_account(r->inner->ctx, addr, out);
}

static int rec_get_code(void *ctx, const evm_addr *addr, uint8_t *buf,
                        size_t cap, size_t *len_out)
{
    rec_be_t *r = ctx;
    rec_note(r, addr);
    return r->inner->get_code(r->inner->ctx, addr, buf, cap, len_out);
}

static int rec_get_storage(void *ctx, const evm_addr *addr,
                           const evm_bytes32 *key, evm_bytes32 *val_out)
{
    rec_be_t *r = ctx;
    rec_note(r, addr);
    return r->inner->get_storage(r->inner->ctx, addr, key, val_out);
}

static int rec_get_block_hash(void *ctx, uint64_t number, evm_bytes32 *hash_out,
                              int *available)
{
    rec_be_t *r = ctx;
    return r->inner->get_block_hash(r->inner->ctx, number, hash_out, available);
}

static int rec_has_storage(void *ctx, const evm_addr *addr, int *out)
{
    rec_be_t *r = ctx;
    rec_note(r, addr);
    return r->inner->has_storage(r->inner->ctx, addr, out);
}

static int cmp_addr(const void *a, const void *b)
{
    return memcmp(((const evm_addr *)a)->b, ((const evm_addr *)b)->b, 32);
}

/* Sort + deduplicate the recorded addresses (deterministic order). */
static void rec_sort_unique(rec_be_t *r)
{
    if (r->n == 0) return;
    qsort(r->seen, r->n, sizeof(evm_addr), cmp_addr);
    size_t w = 1;
    for (size_t i = 1; i < r->n; i++)
        if (memcmp(r->seen[i].b, r->seen[w - 1].b, 32) != 0)
            r->seen[w++] = r->seen[i];
    r->n = w;
}

static int rec_contains(const rec_be_t *r, const evm_addr *a)
{
    return r->n && bsearch(a, r->seen, r->n, sizeof(evm_addr), cmp_addr);
}

/* ── creation events (the strict comparison's address map) ──────────────
 *
 * The engine exposes no creation callback (the backend, evm.h:135-171, is
 * address-only). It derives every created address with ONE keccak256 over
 * a fixed preimage:
 *   CREATE / create tx  rlp([sender as addr_bytes bytes, nonce])
 *                       (evm_compute_contract_address, evm_interp.c:149-
 *                       165, hash at :161; op_create :1113, evm_tx.c:354);
 *   CREATE2             0xff ‖ sender (addr_bytes) ‖ salt ‖ keccak(initcode)
 *                       (create2_address, evm_interp.c:169-188, called at
 *                       :1109: the initcode hash at :181, then the
 *                       preimage at :184).
 * keccak256 is an undefined symbol of libevm.a (evm_interp.o, evm_state.o,
 * evm_precompile.o) supplied by the harness's keccak256.o, so the
 * statetest link wraps it (-Wl,--wrap=keccak256, tests/Makefile.statetest).
 * __wrap_keccak256 hashes through __real_keccak256 and, ONLY while
 * g_cr.log is set (around evm_tx_apply in exec_mode), keeps every preimage
 * with the CREATE or CREATE2 shape of THAT run's width, in call order:
 * (creator, nonce) or (creator, salt, initcode hash) and the address. The
 * CREATE2 initcode itself is kept when the previous keccak call's digest
 * is the preimage's initcode hash (:181 directly before :184). A KECCAK256
 * opcode (evm_interp.c:1479) over memory of the same shape is kept as
 * well — the same derivation, so it can only repeat a correct pair; tests
 * written for Ethereum compute 20-byte preimages, which the 32-byte run's
 * filter does not accept. Outside the window the wrapper is a
 * pass-through: run_case and the harness's own hashing are unchanged.
 */

enum { CR_CREATE = 1, CR_CREATE2 = 2 };

typedef struct {
    uint8_t     kind;              /* CR_CREATE / CR_CREATE2             */
    evm_addr    creator;           /* right-aligned                      */
    uint64_t    nonce;             /* CR_CREATE                          */
    evm_bytes32 salt, inithash;    /* CR_CREATE2                         */
    evm_addr    out;               /* 20: zero-extended hash[12:32]; 32: hash */
    uint8_t    *init;              /* CR_CREATE2 initcode copy, or NULL  */
    size_t      init_len;
    int         has_init;
} cr_event_t;

typedef struct {
    cr_event_t *v;
    size_t      n, cap;
    int         oom;
} cr_log_t;

static struct {
    cr_log_t *log;                 /* NULL: pass-through                 */
    unsigned  width;               /* 20 / 32 of the recording run       */
    uint8_t  *prev;                /* previous hashed input (copy)       */
    size_t    prev_len, prev_cap;
    uint8_t   prev_hash[32];
    int       has_prev;
} g_cr;

static void cr_log_free(cr_log_t *l)
{
    for (size_t i = 0; i < l->n; i++) free(l->v[i].init);
    free(l->v);
    memset(l, 0, sizeof(*l));
}

/* rlp([sender (L bytes), nonce]) exactly as evm_interp.c:149-165 writes it
 * (rlp_u64 :123-143: 0 -> 0x80, 1..0x7f one byte, else 0x80+n minimal
 * big-endian). @return 1 matched, 0 not this shape. */
static int cr_parse_create(const uint8_t *d, size_t len, unsigned L,
                           evm_addr *creator, uint64_t *nonce)
{
    if (len < 3 + L || len - 1 > 55) return 0;
    if (d[0] != 0xc0 + (len - 1) || d[1] != 0x80 + L) return 0;
    size_t p = 2 + L, rest = len - p;
    uint64_t v = 0;
    if (rest == 1) {
        if (d[p] == 0x80) v = 0;
        else if (d[p] >= 0x01 && d[p] < 0x80) v = d[p];
        else return 0;
    } else {
        if (d[p] < 0x81 || d[p] > 0x88) return 0;
        size_t n = (size_t)(d[p] - 0x80);
        if (rest != 1 + n || d[p + 1] == 0) return 0;
        if (n == 1 && d[p + 1] < 0x80) return 0;
        for (size_t i = 0; i < n; i++) v = (v << 8) | d[p + 1 + i];
    }
    memset(creator->b, 0, 32);
    memcpy(creator->b + 32 - L, d + 2, L);
    *nonce = v;
    return 1;
}

static void cr_note(const uint8_t *d, size_t len, const uint8_t h[32])
{
    cr_log_t *l = g_cr.log;
    unsigned L = g_cr.width;
    cr_event_t e;
    memset(&e, 0, sizeof(e));
    if (len == 1 + L + 64 && d[0] == 0xff) {
        e.kind = CR_CREATE2;
        memcpy(e.creator.b + 32 - L, d + 1, L);
        memcpy(e.salt.b, d + 1 + L, 32);
        memcpy(e.inithash.b, d + 1 + L + 32, 32);
        if (g_cr.has_prev && memcmp(g_cr.prev_hash, e.inithash.b, 32) == 0) {
            e.has_init = 1;
            e.init_len = g_cr.prev_len;
            if (e.init_len) {
                e.init = malloc(e.init_len);
                if (!e.init) { l->oom = 1; return; }
                memcpy(e.init, g_cr.prev, e.init_len);
            }
        }
    } else if (cr_parse_create(d, len, L, &e.creator, &e.nonce)) {
        e.kind = CR_CREATE;
    }
    if (e.kind) {
        memcpy(e.out.b, h, 32);
        if (L == 20) memset(e.out.b, 0, 12);
        if (l->n == l->cap) {
            size_t ncap = l->cap ? l->cap * 2 : 8;
            cr_event_t *nv = realloc(l->v, ncap * sizeof(*nv));
            if (!nv) { free(e.init); l->oom = 1; return; }
            l->v = nv;
            l->cap = ncap;
        }
        l->v[l->n++] = e;
    }
    /* this input is the "previous call" of the next one (CREATE2 :181) */
    g_cr.has_prev = 0;
    if (len > g_cr.prev_cap) {
        uint8_t *nb = realloc(g_cr.prev, len);
        if (!nb) { l->oom = 1; return; }
        g_cr.prev = nb;
        g_cr.prev_cap = len;
    }
    if (len) memcpy(g_cr.prev, d, len);
    g_cr.prev_len = len;
    memcpy(g_cr.prev_hash, h, 32);
    g_cr.has_prev = 1;
}

int __real_keccak256(const uint8_t *data, size_t len, uint8_t hash_out[32]);
int __wrap_keccak256(const uint8_t *data, size_t len, uint8_t hash_out[32]);

int __wrap_keccak256(const uint8_t *data, size_t len, uint8_t hash_out[32])
{
    int rc = __real_keccak256(data, len, hash_out);
    if (rc == 0 && g_cr.log && !g_cr.log->oom) cr_note(data, len, hash_out);
    return rc;
}

enum { RUN_OK = 0, RUN_FAULT = 1, RUN_ERROR = 2 };

/* One width's run of one case: everything the comparator needs. */
typedef struct {
    unsigned        addr_bytes;
    int             outcome;            /* RUN_OK / RUN_FAULT / RUN_ERROR */
    char            why[256];
    int             rc;                 /* evm_tx_apply: 0 applied, -1 refused */
    evm_tx_result_t res;
    evm_membackend  post;
    rec_be_t        rec;                /* addresses the backend served */
    cr_log_t        crl;                /* creation events, call order  */
} mode_run_t;

static void mode_run_free(mode_run_t *m)
{
    evm_tx_result_free(&m->res);
    evm_membackend_free(&m->post);
    free(m->rec.seen);
    cr_log_free(&m->crl);
    memset(m, 0, sizeof(*m));
}

/* state_new -> tx_apply -> visit_changes -> build_post at one width.
 * The same core as run_case, which is left as it is (the conformance path). */
static void exec_mode(unsigned addr_bytes, const evm_membackend *pre,
                      const test_env_t *te, const built_tx_t *bt, mode_run_t *m)
{
    memset(m, 0, sizeof(*m));
    m->addr_bytes = addr_bytes;
    evm_membackend_init(&m->post);

    evm_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.fork = EVM_FORK_PRAGUE;
    cfg.addr_bytes = (uint8_t)addr_bytes;
    cfg.chain_id = te->chain_id;
    cfg.precompile_mask = EVM_PRECOMPILES_PRAGUE;

    evm_backend_t inner, be;
    evm_membackend_bind(pre, &inner);
    m->rec.inner = &inner;
    be.ctx = &m->rec;
    be.get_account = rec_get_account;
    be.get_code = rec_get_code;
    be.get_storage = rec_get_storage;
    be.get_block_hash = rec_get_block_hash;
    be.has_storage = rec_has_storage;

    evm_state_t *st = evm_state_new(&cfg, &be);
    if (!st) {
        m->outcome = RUN_FAULT;
        snprintf(m->why, sizeof(m->why), "evm_state_new returned NULL");
        return;
    }
    g_cr.log = &m->crl;                 /* record creation preimages */
    g_cr.width = addr_bytes;
    g_cr.has_prev = 0;
    m->rc = evm_tx_apply(st, &te->env, &bt->tx, &m->res);
    g_cr.log = NULL;
    g_cr.has_prev = 0;
    if (m->rec.oom || m->crl.oom) {
        m->outcome = RUN_ERROR;
        snprintf(m->why, sizeof(m->why), "harness out of memory (recorder)");
        evm_state_free(st);
        return;
    }
    if (m->rc != 0 && m->rc != -1) {
        m->outcome = RUN_FAULT;
        snprintf(m->why, sizeof(m->why), "evm_tx_apply returned %d", m->rc);
        evm_state_free(st);
        return;
    }

    changes_t cs;
    memset(&cs, 0, sizeof(cs));
    evm_change_visitor_t vis;
    vis.account = visit_account;
    vis.storage = visit_storage;
    vis.ctx = &cs;
    int vrc = evm_state_visit_changes(st, &vis);
    if (vrc == VISIT_OOM) {
        m->outcome = RUN_ERROR;
        snprintf(m->why, sizeof(m->why), "harness out of memory");
    } else if (vrc != 0) {
        m->outcome = RUN_FAULT;
        snprintf(m->why, sizeof(m->why), "evm_state_visit_changes: %s",
                 cs.why[0] ? cs.why : "returned an unexpected value");
    } else {
        int prc = build_post(pre, &cs, &m->post, m->why, sizeof(m->why));
        if (prc == -1) m->outcome = RUN_FAULT;
        else if (prc != 0) {
            m->outcome = RUN_ERROR;
            snprintf(m->why, sizeof(m->why), "harness could not build post");
        }
    }
    changes_free(&cs);
    evm_state_free(st);
    rec_sort_unique(&m->rec);
}

/* Post-state account keyed by its low 20 bytes (the 20-byte projection). */
typedef struct {
    const evm_mem_account *a;
} proj_t;

static int cmp_proj(const void *x, const void *y)
{
    const evm_mem_account *a = ((const proj_t *)x)->a;
    const evm_mem_account *b = ((const proj_t *)y)->a;
    int c = memcmp(a->addr.b + 12, b->addr.b + 12, 20);
    return c ? c : memcmp(a->addr.b, b->addr.b, 12);   /* total order */
}

static proj_t *project_post(const evm_membackend *mb)
{
    proj_t *p = calloc(mb->n ? mb->n : 1, sizeof(*p));
    if (!p) return NULL;
    for (size_t i = 0; i < mb->n; i++) p[i].a = &mb->acc[i];
    qsort(p, mb->n, sizeof(*p), cmp_proj);
    return p;
}

static void addr20_str(const evm_addr *a, char out[43])
{
    static const char hx[] = "0123456789abcdef";
    out[0] = '0';
    out[1] = 'x';
    for (int i = 0; i < 20; i++) {
        out[2 + 2 * i] = hx[a->b[12 + i] >> 4];
        out[3 + 2 * i] = hx[a->b[12 + i] & 15];
    }
    out[42] = '\0';
}

/* @return 0 equal, 1 differ (field/detail filled), -1 OOM. */
static int compare_post(const evm_membackend *p20, const evm_membackend *p32,
                        char *field, size_t flen)
{
    proj_t *a = project_post(p20), *b = project_post(p32);
    int rc = 0;
    char s[43];
    if (!a || !b) { free(a); free(b); return -1; }
    for (size_t i = 1; i < p32->n && rc == 0; i++)
        if (memcmp(b[i - 1].a->addr.b + 12, b[i].a->addr.b + 12, 20) == 0) {
            addr20_str(&b[i].a->addr, s);
            snprintf(field, flen, "post.projection_collision %s", s);
            rc = 1;
        }
    size_t i = 0, j = 0;
    while (rc == 0 && (i < p20->n || j < p32->n)) {
        if (i >= p20->n || j >= p32->n) {
            const evm_mem_account *x = i < p20->n ? a[i].a : b[j].a;
            addr20_str(&x->addr, s);
            snprintf(field, flen, "post.account_set %s only in %u-byte run%s",
                     s, i < p20->n ? 20u : 32u,
                     addr_is_wide(&x->addr) ? " (wide)" : "");
            rc = 1;
            break;
        }
        const evm_mem_account *x = a[i].a, *y = b[j].a;
        int c = memcmp(x->addr.b + 12, y->addr.b + 12, 20);
        if (c != 0) {
            const evm_mem_account *z = c < 0 ? x : y;
            addr20_str(&z->addr, s);
            snprintf(field, flen, "post.account_set %s only in %u-byte run%s",
                     s, c < 0 ? 20u : 32u,
                     addr_is_wide(&z->addr) ? " (wide)" : "");
            rc = 1;
            break;
        }
        addr20_str(&x->addr, s);
        if (addr_is_wide(&y->addr))
            { snprintf(field, flen, "post.wide_address %s", s); rc = 1; }
        else if (x->nonce != y->nonce)
            { snprintf(field, flen, "post.nonce %s", s); rc = 1; }
        else if (memcmp(x->balance, y->balance, 32) != 0)
            { snprintf(field, flen, "post.balance %s", s); rc = 1; }
        else if (memcmp(x->code_hash.b, y->code_hash.b, 32) != 0)
            { snprintf(field, flen, "post.code_hash %s", s); rc = 1; }
        else if (x->n_slots != y->n_slots)
            { snprintf(field, flen, "post.storage %s (slot count)", s); rc = 1; }
        else {
            for (size_t k = 0; k < x->n_slots; k++)
                if (memcmp(x->slots[k].key.b, y->slots[k].key.b, 32) != 0 ||
                    memcmp(x->slots[k].val.b, y->slots[k].val.b, 32) != 0) {
                    snprintf(field, flen, "post.storage %s", s);
                    rc = 1;
                    break;
                }
        }
        i++;
        j++;
    }
    free(a);
    free(b);
    return rc;
}

/* First differing field of the normalized results. @return 0 equal,
 * 1 differ, -1 OOM. */
static int compare_runs(const mode_run_t *m20, const mode_run_t *m32,
                        char *field, size_t flen)
{
    const evm_tx_result_t *r = &m20->res, *q = &m32->res;
    if (m20->rc != m32->rc) {
        snprintf(field, flen, "applied/refused (20: %s, 32: %s)",
                 m20->rc == 0 ? status_name(r->status)
                              : tx_error_name(r->tx_error),
                 m32->rc == 0 ? status_name(q->status)
                              : tx_error_name(q->tx_error));
        return 1;
    }
    if (m20->rc == -1) {
        if (r->tx_error != q->tx_error) {
            snprintf(field, flen, "tx_error (20: %s, 32: %s)",
                     tx_error_name(r->tx_error), tx_error_name(q->tx_error));
            return 1;
        }
    } else if (r->status != q->status) {
        snprintf(field, flen, "status (20: %s, 32: %s)",
                 status_name(r->status), status_name(q->status));
        return 1;
    }
    if (r->gas_used != q->gas_used) {
        snprintf(field, flen, "gas_used (20: %llu, 32: %llu)",
                 (unsigned long long)r->gas_used,
                 (unsigned long long)q->gas_used);
        return 1;
    }
    if (m20->rc == 0) {
        if (r->gas_used_pre_refund != q->gas_used_pre_refund) {
            snprintf(field, flen, "gas_used_pre_refund (20: %llu, 32: %llu)",
                     (unsigned long long)r->gas_used_pre_refund,
                     (unsigned long long)q->gas_used_pre_refund);
            return 1;
        }
        if (r->output_len != q->output_len ||
            (r->output_len &&
             memcmp(r->output, q->output, r->output_len) != 0)) {
            snprintf(field, flen, "output (20: %zu bytes, 32: %zu bytes)",
                     r->output_len, q->output_len);
            return 1;
        }
        uint8_t w20[32], w32[32];
        evm_u256_to_be(w20, &r->wei_destroyed);
        evm_u256_to_be(w32, &q->wei_destroyed);
        if (memcmp(w20, w32, 32) != 0) {
            snprintf(field, flen, "wei_destroyed");
            return 1;
        }
    }
    int prc = compare_post(&m20->post, &m32->post, field, flen);
    if (prc != 0) return prc;
    if (m20->rc == 0) {
        if (r->n_logs != q->n_logs) {
            snprintf(field, flen, "logs.count (20: %zu, 32: %zu)",
                     r->n_logs, q->n_logs);
            return 1;
        }
        for (size_t i = 0; i < r->n_logs; i++) {
            const evm_log_t *x = &r->logs[i], *y = &q->logs[i];
            if (addr_is_wide(&y->addr)) {
                snprintf(field, flen, "logs[%zu].emitter (wide)", i);
                return 1;
            }
            if (memcmp(x->addr.b + 12, y->addr.b + 12, 20) != 0) {
                snprintf(field, flen, "logs[%zu].emitter", i);
                return 1;
            }
            if (x->n_topics != y->n_topics ||
                memcmp(x->topics, y->topics,
                       (x->n_topics <= 4 ? x->n_topics : 4) *
                       sizeof(evm_bytes32)) != 0) {
                snprintf(field, flen, "logs[%zu].topics", i);
                return 1;
            }
            if (x->data_len != y->data_len ||
                (x->data_len && memcmp(x->data, y->data, x->data_len) != 0)) {
                snprintf(field, flen, "logs[%zu].data", i);
                return 1;
            }
        }
    }
    return 0;
}

/* keccak(rlp([creator as 32 bytes, nonce])), the whole hash — the 32-byte
 * CREATE derivation (evm_interp.c:149-167), recomputed independently.
 * @return 0, -2. */
static int create32_addr(const evm_addr *creator, uint64_t nonce,
                         evm_addr *out)
{
    evm_rlp_buf b = {0};
    int rc = evm_rlp_put_bytes(&b, creator->b, 32);
    if (rc == 0) rc = evm_rlp_put_u64(&b, nonce);
    if (rc == 0) rc = evm_rlp_wrap_list(&b, 0);
    if (rc == 0 && keccak256(b.p, b.len, out->b) != 0) rc = -2;
    evm_rlp_buf_free(&b);
    return rc == 0 ? 0 : -2;
}

/* Nonce range a creator can have used: from its pre nonce (0 when it did
 * not exist) to its 32-byte post nonce; a creator absent from the post
 * (gone again in this tx) is tried over 64 nonces past its start. The
 * search is bounded (4096 nonces per creator). */
static int is_create_derived(const evm_addr *w, const evm_addr *creators,
                             size_t n_creators, const evm_membackend *pre,
                             const evm_membackend *post32)
{
    for (size_t c = 0; c < n_creators; c++) {
        const evm_mem_account *pa = evm_membackend_find(pre, &creators[c]);
        const evm_mem_account *qa = evm_membackend_find(post32, &creators[c]);
        uint64_t lo = pa ? pa->nonce : 0, hi;
        if (qa) hi = qa->nonce > lo ? qa->nonce : lo;
        else hi = lo > UINT64_MAX - 64 ? UINT64_MAX : lo + 64;
        if (hi - lo > 4096) hi = lo + 4096;     /* bounded search */
        for (uint64_t n = lo; ; n++) {
            evm_addr d;
            if (create32_addr(&creators[c], n, &d) != 0) return -2;
            if (memcmp(d.b, w->b, 32) == 0) return 1;
            if (n == hi) break;
        }
    }
    return 0;
}

enum { CLS_CREATE = 1, CLS_WIDE_WORD = 2, CLS_CREATE2_OR_DERIVED = 4 };

typedef struct {
    unsigned long agree, unexplained, fault, error, wide20;
    unsigned long differ_by_mask[8];
    unsigned long baseline_pass, baseline_other;
} diff_counts_t;

static diff_counts_t g_dc;

static void class_str(unsigned mask, char *out, size_t len)
{
    snprintf(out, len, "%s%s%s%s%s",
             (mask & CLS_CREATE) ? "CREATE" : "",
             ((mask & CLS_CREATE) && (mask & ~(unsigned)CLS_CREATE)) ? "+" : "",
             (mask & CLS_WIDE_WORD) ? "WIDE_WORD" : "",
             ((mask & CLS_WIDE_WORD) && (mask & CLS_CREATE2_OR_DERIVED))
                 ? "+" : "",
             (mask & CLS_CREATE2_OR_DERIVED) ? "CREATE2_OR_DERIVED" : "");
}

/* Sub-labels for the wide addresses of a differing case. @return the
 * class mask (0 = no wide address), -2 OOM/fault. */
static int classify_wide(const mode_run_t *m20, const mode_run_t *m32,
                         const evm_membackend *pre, const built_tx_t *bt)
{
    /* wide set: backend reads + post accounts + log emitters + created */
    rec_be_t wide = {0};
    for (size_t i = 0; i < m32->rec.n; i++)
        if (addr_is_wide(&m32->rec.seen[i])) rec_note(&wide, &m32->rec.seen[i]);
    for (size_t i = 0; i < m32->post.n; i++)
        if (addr_is_wide(&m32->post.acc[i].addr))
            rec_note(&wide, &m32->post.acc[i].addr);
    if (m32->rc == 0) {
        for (size_t i = 0; i < m32->res.n_logs; i++)
            if (addr_is_wide(&m32->res.logs[i].addr))
                rec_note(&wide, &m32->res.logs[i].addr);
        if (bt->tx.is_create && addr_is_wide(&m32->res.created))
            rec_note(&wide, &m32->res.created);
    }
    if (wide.oom) { free(wide.seen); return -2; }
    rec_sort_unique(&wide);
    if (wide.n == 0) { free(wide.seen); return 0; }

    /* candidate creators: sender, pre, 32-byte post, every wide address */
    rec_be_t cr = {0};
    rec_note(&cr, &bt->tx.sender);
    for (size_t i = 0; i < pre->n; i++) rec_note(&cr, &pre->acc[i].addr);
    for (size_t i = 0; i < m32->post.n; i++)
        rec_note(&cr, &m32->post.acc[i].addr);
    for (size_t i = 0; i < wide.n; i++) rec_note(&cr, &wide.seen[i]);
    if (cr.oom) { free(wide.seen); free(cr.seen); return -2; }
    rec_sort_unique(&cr);

    int mask = 0;
    for (size_t i = 0; i < wide.n; i++) {
        const evm_addr *w = &wide.seen[i];
        int d = is_create_derived(w, cr.seen, cr.n, pre, &m32->post);
        if (d < 0) { mask = -2; break; }
        int lbl;
        if (d) {
            lbl = CLS_CREATE;
        } else {
            evm_addr low = *w;
            memset(low.b, 0, 12);
            int is_pc = 1;
            for (int k = 12; k < 31; k++) if (low.b[k]) is_pc = 0;
            if (low.b[31] == 0 || low.b[31] > 0x11) is_pc = 0;
            if (is_pc || evm_membackend_find(pre, &low) ||
                rec_contains(&m20->rec, &low) ||
                evm_membackend_find(&m20->post, &low))
                lbl = CLS_WIDE_WORD;
            else
                lbl = CLS_CREATE2_OR_DERIVED;
        }
        mask |= lbl;
        if (g_opt.verbose) {
            char cls[64];
            class_str((unsigned)lbl, cls, sizeof(cls));
            printf("    wide 0x");
            hex_print(stdout, w->b, 32);
            printf(" %s\n", cls);
        }
    }
    free(wide.seen);
    free(cr.seen);
    return mask;
}

/* 20-byte run against the fixture (root, logs, expectException). */
static int baseline_pass(const mode_run_t *m20, json_object *post)
{
    uint8_t want_root[32], want_logs[32], got_root[32], got_logs[32];
    const char *s;
    if (m20->outcome != RUN_OK) return 0;
    if (!(s = jstr(post, "hash")) || hex_be32(s, want_root) ||
        !(s = jstr(post, "logs")) || hex_be32(s, want_logs))
        return 0;
    int expect_exc = jstr(post, "expectException") != NULL;
    if (expect_exc != (m20->rc == -1)) return 0;
    if (evm_membackend_state_root(&m20->post, 20, got_root) != 0 ||
        logs_hash(&m20->res, m20->rc == 0, 20, got_logs) != 0)
        return 0;
    return memcmp(got_root, want_root, 32) == 0 &&
           memcmp(got_logs, want_logs, 32) == 0;
}

/* ── strict comparison: address map + substitution ──────────────────── */

enum { MAP_CREATE = 1, MAP_CREATE2 = 2, MAP_CREATE2_INIT = 4 };

typedef struct {
    evm_addr w32, a20;
} amap_ent_t;

typedef struct {
    amap_ent_t *v;                      /* sorted by w32                 */
    size_t      n, cap;
    int         oom, conflict;
    unsigned    how;                    /* MAP_* bits used               */
    int         arith;                  /* tr_word second stage on       */
} amap_t;

static int cmp_amap(const void *k, const void *e)
{
    return memcmp(((const evm_addr *)k)->b, ((const amap_ent_t *)e)->w32.b, 32);
}

static const amap_ent_t *amap_find(const amap_t *m, const evm_addr *w)
{
    return m->n ? bsearch(w, m->v, m->n, sizeof(amap_ent_t), cmp_amap) : NULL;
}

static void amap_put(amap_t *m, const evm_addr *w, const evm_addr *a)
{
    const amap_ent_t *f = amap_find(m, w);
    if (f) {
        if (memcmp(f->a20.b, a->b, 32) != 0) m->conflict = 1;
        return;
    }
    if (m->n == m->cap) {
        size_t ncap = m->cap ? m->cap * 2 : 8;
        amap_ent_t *nv = realloc(m->v, ncap * sizeof(*nv));
        if (!nv) { m->oom = 1; return; }
        m->v = nv;
        m->cap = ncap;
    }
    size_t pos = m->n;
    while (pos > 0 && memcmp(m->v[pos - 1].w32.b, w->b, 32) > 0) pos--;
    memmove(m->v + pos + 1, m->v + pos, (m->n - pos) * sizeof(*m->v));
    m->v[pos].w32 = *w;
    m->v[pos].a20 = *a;
    m->n++;
}

/* A 32-byte run's address (or word) -> the 20-byte run's counterpart. A
 * narrow value names itself (inputs are canonical, see the block at the
 * top of this mode); a wide one only through the map.
 * @return 1 translated / identity, 0 wide and unmapped (*out = *in). */
static int amap_tr(const amap_t *m, const evm_addr *in, evm_addr *out)
{
    *out = *in;
    if (!addr_is_wide(in)) return 1;
    const amap_ent_t *f = amap_find(m, in);
    if (!f) return 0;
    *out = f->a20;
    return 1;
}

/* r = x - y (mod 2^256), big-endian. */
static void be_sub(uint8_t r[32], const uint8_t x[32], const uint8_t y[32])
{
    int borrow = 0;
    for (int i = 31; i >= 0; i--) {
        int d = (int)x[i] - (int)y[i] - borrow;
        borrow = d < 0;
        r[i] = (uint8_t)(d + (borrow ? 256 : 0));
    }
}

/* r = x + y (mod 2^256), big-endian. */
static void be_add(uint8_t r[32], const uint8_t x[32], const uint8_t y[32])
{
    unsigned carry = 0;
    for (int i = 31; i >= 0; i--) {
        unsigned s = (unsigned)x[i] + y[i] + carry;
        r[i] = (uint8_t)s;
        carry = s >> 8;
    }
}

/* |d| < 2^16 as a two's-complement 256-bit value. */
static int be_small(const uint8_t d[32])
{
    int pos = 1, ng = 1;
    for (int i = 0; i < 30; i++) {
        if (d[i] != 0x00) pos = 0;
        if (d[i] != 0xff) ng = 0;
    }
    return pos || (ng && (d[30] & 0x80));
}

static void tr_word(const amap_t *m, uint8_t *w)
{
    evm_addr a, b;
    memcpy(a.b, w, 32);
    if (amap_tr(m, &a, &b)) {
        memcpy(w, b.b, 32);
        return;
    }
    if (!m->arith) return;
    /* second stage: a word = w32 + d with |d| < 2^16 (arithmetic on an
     * address value) becomes a20 + d. First pair in w32 order wins. */
    for (size_t i = 0; i < m->n; i++) {
        uint8_t d[32];
        be_sub(d, w, m->v[i].w32.b);
        if (!be_small(d)) continue;
        be_add(w, m->v[i].a20.b, d);
        return;
    }
}

/* 32-byte-aligned words of a byte string (ABI encoding of output / log
 * data). An address word at an unaligned offset is not translated. */
static void tr_aligned(const amap_t *m, uint8_t *p, size_t len)
{
    for (size_t off = 0; off + 32 <= len; off += 32) tr_word(m, p + off);
}

/* Creation-event key: the whole preimage of the derivation. */
static int cmp_ev_key(const cr_event_t *a, const cr_event_t *b)
{
    if (a->kind != b->kind) return a->kind < b->kind ? -1 : 1;
    int c = memcmp(a->creator.b, b->creator.b, 32);
    if (c) return c;
    if (a->kind == CR_CREATE)
        return a->nonce < b->nonce ? -1 : a->nonce > b->nonce;
    c = memcmp(a->salt.b, b->salt.b, 32);
    if (c) return c;
    return memcmp(a->inithash.b, b->inithash.b, 32);
}

static int cmp_evp(const void *x, const void *y)
{
    return cmp_ev_key(*(const cr_event_t *const *)x,
                      *(const cr_event_t *const *)y);
}

/* CREATE2 whose initcode carries an address: every 32-byte window of the
 * 32-byte run's initcode equal to a mapped wide address becomes its
 * 20-byte counterpart word; the result must equal the 20-byte run's
 * initcode byte for byte. @return 1 equal, 0 not, -1 OOM. */
static int init_matches(const amap_t *m, const cr_event_t *e32,
                        const cr_event_t *e20)
{
    if (!e32->has_init || !e20->has_init || e32->init_len != e20->init_len)
        return 0;
    size_t len = e32->init_len;
    if (len < 32) return 0;            /* no room for a word: hashes differ */
    uint8_t *b = malloc(len);
    if (!b) return -1;
    memcpy(b, e32->init, len);
    for (size_t off = 0; off + 32 <= len; off++) {
        evm_addr a;
        memcpy(a.b, b + off, 32);
        const amap_ent_t *f = addr_is_wide(&a) ? amap_find(m, &a) : NULL;
        if (f) {
            memcpy(b + off, f->a20.b, 32);
            off += 31;
        }
    }
    int eq = memcmp(b, e20->init, len) == 0;
    free(b);
    return eq;
}

/* Pair every 32-byte creation event with its 20-byte counterpart:
 * CREATE by (creator mapped, nonce), CREATE2 by (creator mapped, salt,
 * initcode hash), and — when that fails — CREATE2 by (creator mapped,
 * salt) with the initcode equal after substitution (init_matches). A
 * creator that is itself a created contract maps through the pairs made
 * so far; passes repeat until none adds a pair (transitive). Every pass
 * walks the events in call order and the 20-byte events are searched in
 * key order, so the map does not depend on allocation or timing.
 * @return 0, -1 OOM. */
static int build_map(const mode_run_t *m20, const mode_run_t *m32, amap_t *map)
{
    size_t n20 = m20->crl.n, n32 = m32->crl.n;
    const cr_event_t **ix = malloc((n20 ? n20 : 1) * sizeof(*ix));
    char *done = calloc(n32 ? n32 : 1, 1);
    if (!ix || !done) { free(ix); free(done); return -1; }
    for (size_t i = 0; i < n20; i++) ix[i] = &m20->crl.v[i];
    qsort(ix, n20, sizeof(*ix), cmp_evp);

    int progress = 1;
    while (progress && !map->oom) {
        progress = 0;
        for (size_t i = 0; i < n32 && !map->oom; i++) {
            if (done[i]) continue;
            const cr_event_t *e = &m32->crl.v[i];
            cr_event_t probe = *e;
            if (!amap_tr(map, &e->creator, &probe.creator)) continue;
            const cr_event_t *pp = &probe;
            const cr_event_t **hit = n20 ? bsearch(&pp, ix, n20, sizeof(*ix),
                                                   cmp_evp) : NULL;
            if (hit) {
                amap_put(map, &e->out, &(*hit)->out);
                map->how |= e->kind == CR_CREATE ? MAP_CREATE : MAP_CREATE2;
                done[i] = progress = 1;
                continue;
            }
            if (e->kind != CR_CREATE2) continue;
            /* lower bound of (CREATE2, creator, salt, *) in key order */
            memset(probe.inithash.b, 0, 32);
            size_t lo = 0, hi = n20;
            while (lo < hi) {
                size_t mid = lo + (hi - lo) / 2;
                if (cmp_ev_key(ix[mid], &probe) < 0) lo = mid + 1;
                else hi = mid;
            }
            for (size_t k = lo; k < n20; k++) {
                const cr_event_t *f = ix[k];
                if (f->kind != CR_CREATE2 ||
                    memcmp(f->creator.b, probe.creator.b, 32) != 0 ||
                    memcmp(f->salt.b, probe.salt.b, 32) != 0)
                    break;
                int im = init_matches(map, e, f);
                if (im < 0) { map->oom = 1; break; }
                if (im) {
                    amap_put(map, &e->out, &f->out);
                    map->how |= MAP_CREATE2_INIT;
                    done[i] = progress = 1;
                    break;
                }
            }
        }
    }
    free(ix);
    free(done);
    return map->oom ? -1 : 0;
}

/* The 32-byte run with every address and address word translated to its
 * 20-byte counterpart: post accounts (their balance / nonce / code / slots
 * travel with the key), storage keys and values, log emitters, topics,
 * aligned log-data and output words, the created address. Code bytes are
 * NOT rewritten (a code that embeds an address keeps its 32-byte form).
 * @return 0, 1 translation collision (two accounts or two slots land on
 * one counterpart; why filled), -1 OOM. */
static int translate_run(const mode_run_t *m32, const amap_t *map,
                         mode_run_t *t, char *why, size_t wl)
{
    memset(t, 0, sizeof(*t));
    t->addr_bytes = 32;
    t->outcome = RUN_OK;
    t->rc = m32->rc;
    evm_membackend_init(&t->post);
    const evm_tx_result_t *q = &m32->res;
    evm_tx_result_t *r = &t->res;
    r->tx_error = q->tx_error;
    r->status = q->status;
    r->gas_used = q->gas_used;
    r->gas_used_pre_refund = q->gas_used_pre_refund;
    r->wei_destroyed = q->wei_destroyed;
    amap_tr(map, &q->created, &r->created);
    if (q->output_len) {
        r->output = malloc(q->output_len);
        if (!r->output) return -1;
        memcpy(r->output, q->output, q->output_len);
        r->output_len = q->output_len;
        tr_aligned(map, r->output, r->output_len);
    }
    if (q->n_logs) {
        r->logs = calloc(q->n_logs, sizeof(*r->logs));
        if (!r->logs) return -1;
        for (size_t i = 0; i < q->n_logs; i++) {
            const evm_log_t *x = &q->logs[i];
            evm_log_t *y = &r->logs[i];
            amap_tr(map, &x->addr, &y->addr);
            y->n_topics = x->n_topics;
            memcpy(y->topics, x->topics, sizeof(y->topics));
            for (unsigned k = 0; k < x->n_topics && k < 4; k++)
                tr_word(map, y->topics[k].b);
            if (x->data_len) {
                y->data = malloc(x->data_len);
                if (!y->data) return -1;
                memcpy(y->data, x->data, x->data_len);
                y->data_len = x->data_len;
                tr_aligned(map, y->data, y->data_len);
            }
            r->n_logs = i + 1;
        }
    }
    for (size_t i = 0; i < m32->post.n; i++) {
        const evm_mem_account *x = &m32->post.acc[i];
        evm_addr a;
        evm_mem_account *y = NULL;
        amap_tr(map, &x->addr, &a);
        if (evm_membackend_add_account(&t->post, &a, x->nonce, x->balance,
                                       x->code, x->code_len, &x->code_hash,
                                       &y) != 0)
            return -1;
        for (size_t k = 0; k < x->n_slots; k++) {
            evm_bytes32 key = x->slots[k].key, val = x->slots[k].val;
            tr_word(map, key.b);
            tr_word(map, val.b);
            if (evm_mem_account_add_slot(y, &key, &val) != 0) return -1;
        }
    }
    if (evm_membackend_finalize(&t->post) != 0) {
        snprintf(why, wl, "translation collision (two accounts or two slots "
                 "land on one 20-byte counterpart)");
        return 1;
    }
    return 0;
}

/* First differing field after substitution. @return 0 equal, 1 differ,
 * -1 OOM. */
static int compare_strict(const mode_run_t *m20, const mode_run_t *t32,
                          int is_create, char *field, size_t flen)
{
    int c = compare_runs(m20, t32, field, flen);
    if (c != 0) return c;
    if (m20->rc == 0 && is_create &&
        memcmp(m20->res.created.b, t32->res.created.b, 32) != 0) {
        snprintf(field, flen, "created address");
        return 1;
    }
    return 0;
}

/* Reason classes of a strict difference. The first two are width-
 * dependent by construction and justify the difference; the last two
 * are evidence only (a downstream symptom, never a reason by itself).
 *   FIXTURE_20B   the fixture names a 20-byte DERIVED address literally:
 *                 for a pair (w32, a20) the 32-byte run met a20 itself —
 *                 a20 is in the pre-state (pre-funded target, EIP-7610
 *                 collision account), is tx.to, the coinbase or in the
 *                 access list (warm list), or the 32-byte run's backend
 *                 read it (a PUSH20 / calldata literal; in 32-byte mode
 *                 the contract lives at w32). In 20-byte mode a20 IS the
 *                 created contract; in 32-byte mode it is an unrelated
 *                 account. Engine: evm_compute_contract_address /
 *                 create2_address keep the whole hash at 32
 *                 (evm_interp.c:149-188).
 *   WIDE_WORD     a wide address the 32-byte run touched that no creation
 *                 produced, whose low 20 bytes name an address the 20-byte
 *                 run knew (pre-state, a backend read, its post) or a
 *                 precompile: a stack word with high bytes set, which
 *                 20-byte mode masks and 32-byte mode keeps
 *                 (evm_addr_from_word, evm_state.c:92-99).
 *   MASKED_160    code built for 20-byte addresses truncates one: for a
 *                 pair (w32, a20) the 32-byte run met low20(w32) zero-
 *                 extended — a backend read / post account, or a storage
 *                 key or value, log topic, aligned log-data or output word.
 *                 Solidity's address cleanup AND(x, 2^160-1) (PUSH20 0xff..ff
 *                 AND, or PUSH1 1 PUSH1 0xa0 PUSH1 2 EXP SUB AND) is the
 *                 identity on a 20-byte address and a different account
 *                 on a 32-byte one.
 *   ADDR_ARITH    VERIFIED: the results become equal when, in addition, a
 *                 data word w32 + d (-2^15 <= d < 2^16, be_small) is
 *                 translated to a20 + d — arithmetic on an address value
 *                 (e.g. CREATE's result + 1 stored). Decided by a second
 *                 translation and compare, not by presence.
 *   UNPAIRED      a 32-byte creation without a 20-byte counterpart.
 *   UNMAPPED_WIDE a wide address neither created nor WIDE_WORD.
 * A case whose difference carries none of the four justifying classes is
 * STRICT_UNEXPLAINED. */
enum {
    SC_FIXTURE_20B = 1, SC_WIDE_WORD = 2, SC_MASKED_160 = 4,
    SC_ADDR_ARITH = 8, SC_UNPAIRED = 16, SC_UNMAPPED_WIDE = 32
};
#define SC_JUSTIFIED (SC_FIXTURE_20B | SC_WIDE_WORD | SC_MASKED_160 | \
                      SC_ADDR_ARITH)
#define SC_NCLASS 6

static void sclass_str(unsigned mask, char *out, size_t len)
{
    static const char *const nm[SC_NCLASS] = {
        "FIXTURE_20B", "WIDE_WORD", "MASKED_160", "ADDR_ARITH", "UNPAIRED",
        "UNMAPPED_WIDE"
    };
    size_t p = 0;
    out[0] = '\0';
    for (int k = 0; k < SC_NCLASS; k++) {
        if (!(mask & (1u << k))) continue;
        int w = snprintf(out + p, len - p, "%s%s", p ? "+" : "", nm[k]);
        if (w < 0 || (size_t)w >= len - p) break;
        p += (size_t)w;
    }
    if (!p) snprintf(out, len, "NONE");
}

static int is_precompile_low(const evm_addr *low)
{
    for (int k = 12; k < 31; k++) if (low->b[k]) return 0;
    return low->b[31] >= 0x01 && low->b[31] <= 0x11;
}

static int words_have(const uint8_t *p, size_t len, const evm_addr *w)
{
    for (size_t off = 0; off + 32 <= len; off += 32)
        if (memcmp(p + off, w->b, 32) == 0) return 1;
    return 0;
}

/* The run touched or produced the word w: backend read, post account,
 * storage key or value, log topic / aligned data word, aligned output. */
static int run_has(const mode_run_t *m, const evm_addr *w)
{
    if (rec_contains(&m->rec, w) || evm_membackend_find(&m->post, w))
        return 1;
    for (size_t i = 0; i < m->post.n; i++) {
        const evm_mem_account *a = &m->post.acc[i];
        for (size_t k = 0; k < a->n_slots; k++)
            if (memcmp(a->slots[k].key.b, w->b, 32) == 0 ||
                memcmp(a->slots[k].val.b, w->b, 32) == 0)
                return 1;
    }
    if (m->rc != 0) return 0;
    for (size_t i = 0; i < m->res.n_logs; i++) {
        const evm_log_t *l = &m->res.logs[i];
        for (unsigned k = 0; k < l->n_topics && k < 4; k++)
            if (memcmp(l->topics[k].b, w->b, 32) == 0) return 1;
        if (words_have(l->data, l->data_len, w)) return 1;
    }
    return words_have(m->res.output, m->res.output_len, w);
}

/* @return the SC_* mask (ADDR_ARITH is decided by the caller), -1 OOM. */
static int classify_strict(const mode_run_t *m20, const mode_run_t *m32,
                           const amap_t *map, const evm_membackend *pre,
                           const test_env_t *te, const built_tx_t *bt)
{
    unsigned mask = 0;
    for (size_t i = 0; i < map->n; i++) {
        const evm_addr *a = &map->v[i].a20;
        int hit = evm_membackend_find(pre, a) != NULL ||
                  rec_contains(&m32->rec, a) ||
                  memcmp(te->env.coinbase.b, a->b, 32) == 0 ||
                  (!bt->tx.is_create && memcmp(bt->tx.to.b, a->b, 32) == 0);
        for (uint32_t k = 0; !hit && k < bt->tx.n_access; k++)
            if (memcmp(bt->tx.access[k].addr.b, a->b, 32) == 0) hit = 1;
        if (hit) {
            mask |= SC_FIXTURE_20B;
            if (g_opt.verbose) {
                printf("    fixture_20b 0x");
                hex_print(stdout, a->b + 12, 20);
                printf(" (32-byte run: 0x");
                hex_print(stdout, map->v[i].w32.b, 32);
                printf(")\n");
            }
            break;
        }
    }
    for (size_t i = 0; i < map->n; i++) {
        evm_addr low = map->v[i].w32;
        memset(low.b, 0, 12);
        if (run_has(m32, &low)) {
            mask |= SC_MASKED_160;
            if (g_opt.verbose) {
                printf("    masked_160 0x");
                hex_print(stdout, low.b + 12, 20);
                printf("\n");
            }
            break;
        }
    }

    /* wide addresses of the 32-byte run */
    rec_be_t wide = {0};
    for (size_t i = 0; i < m32->rec.n; i++)
        if (addr_is_wide(&m32->rec.seen[i])) rec_note(&wide, &m32->rec.seen[i]);
    for (size_t i = 0; i < m32->post.n; i++)
        if (addr_is_wide(&m32->post.acc[i].addr))
            rec_note(&wide, &m32->post.acc[i].addr);
    if (m32->rc == 0)
        for (size_t i = 0; i < m32->res.n_logs; i++)
            if (addr_is_wide(&m32->res.logs[i].addr))
                rec_note(&wide, &m32->res.logs[i].addr);
    for (size_t i = 0; i < m32->crl.n; i++)
        if (addr_is_wide(&m32->crl.v[i].out) &&
            !amap_find(map, &m32->crl.v[i].out)) {
            mask |= SC_UNPAIRED;
            if (g_opt.verbose) {
                const cr_event_t *e = &m32->crl.v[i];
                printf("    unpaired %s creator 0x", e->kind == CR_CREATE
                                                     ? "CREATE" : "CREATE2");
                hex_print(stdout, e->creator.b, 32);
                if (e->kind == CR_CREATE)
                    printf(" nonce %llu", (unsigned long long)e->nonce);
                printf(" -> 0x");
                hex_print(stdout, e->out.b, 32);
                printf("\n");
            }
        }
    if (wide.oom) { free(wide.seen); return -1; }
    rec_sort_unique(&wide);
    for (size_t i = 0; i < wide.n; i++) {
        const evm_addr *w = &wide.seen[i];
        if (amap_find(map, w)) continue;
        int created = 0;
        for (size_t k = 0; k < m32->crl.n && !created; k++)
            if (memcmp(m32->crl.v[k].out.b, w->b, 32) == 0) created = 1;
        if (created) { mask |= SC_UNPAIRED; continue; }
        evm_addr low = *w;
        memset(low.b, 0, 12);
        if (is_precompile_low(&low) || evm_membackend_find(pre, &low) ||
            rec_contains(&m20->rec, &low) ||
            evm_membackend_find(&m20->post, &low))
            mask |= SC_WIDE_WORD;
        else
            mask |= SC_UNMAPPED_WIDE;
    }
    free(wide.seen);
    return (int)mask;
}

typedef struct {
    unsigned long agree, unexplained, error;
    unsigned long by_mask[1u << SC_NCLASS];
    unsigned long agree_create2;        /* agreed with a CREATE2 pair    */
    unsigned long agree_init;           /* ... one paired via initcode   */
    /* old verdict row (0 AGREE, 1..7 DIFFER mask, 8 UNEXPLAINED) x new
     * (0 STRICT_AGREE, 1 STRICT_DIFFER, 2 STRICT_UNEXPLAINED, 3 ERROR) */
    unsigned long mig[9][4];
} strict_counts_t;

static strict_counts_t g_sc;

/* Strict verdict of one case whose two runs are RUN_OK. old_row as in
 * strict_counts_t.mig. */
static void strict_case(const case_id_t *cid, const mode_run_t *m20,
                        const mode_run_t *m32, const evm_membackend *pre,
                        const test_env_t *te, const built_tx_t *bt,
                        int old_row)
{
    amap_t map;
    memset(&map, 0, sizeof(map));
    mode_run_t t32;
    memset(&t32, 0, sizeof(t32));       /* mode_run_free-safe when empty */
    char field[200] = "";
    int col = 3;

    if (build_map(m20, m32, &map) != 0) {
        report("ERROR", cid, "harness out of memory (address map)");
        goto out;
    }
    if (map.conflict) {
        report("ERROR", cid, "address map conflict: one 32-byte address "
               "paired with two 20-byte addresses");
        goto out;
    }
    int tr = translate_run(m32, &map, &t32, field, sizeof(field));
    if (tr < 0) {
        report("ERROR", cid, "harness out of memory (translate)");
        goto out;
    }
    int c = 1;
    if (tr == 0) c = compare_strict(m20, &t32, bt->tx.is_create, field,
                                    sizeof(field));
    if (c < 0) {
        report("ERROR", cid, "harness out of memory (strict compare)");
        goto out;
    }
    if (c == 0) {
        col = 0;
        g_sc.agree++;
        if (map.how & (MAP_CREATE2 | MAP_CREATE2_INIT)) g_sc.agree_create2++;
        if (map.how & MAP_CREATE2_INIT) g_sc.agree_init++;
        if (g_opt.verbose) report("S_AGREE", cid, "%zu address pair(s)", map.n);
        goto out;
    }
    int sm = classify_strict(m20, m32, &map, pre, te, bt);
    if (sm < 0) {
        report("ERROR", cid, "harness out of memory (strict classify)");
        goto out;
    }
    if (map.n) {                        /* second stage: ADDR_ARITH */
        mode_run_t t2;
        char f2[200] = "";
        map.arith = 1;
        int tr2 = translate_run(m32, &map, &t2, f2, sizeof(f2));
        int c2 = tr2 == 0 ? compare_strict(m20, &t2, bt->tx.is_create, f2,
                                           sizeof(f2))
                          : (tr2 < 0 ? -1 : 1);
        mode_run_free(&t2);
        map.arith = 0;
        if (c2 < 0) {
            report("ERROR", cid, "harness out of memory (second stage)");
            goto out;
        }
        if (c2 == 0) sm |= SC_ADDR_ARITH;
    }
    char cls[96];
    sclass_str((unsigned)sm, cls, sizeof(cls));
    if (sm & SC_JUSTIFIED) {
        col = 1;
        g_sc.by_mask[sm & 63]++;
        report("S_DIFFER", cid, "%s; first difference after substitution: %s",
               cls, field);
    } else {
        col = 2;
        g_sc.unexplained++;
        report("S_UNEXPL", cid, "%s; first difference after substitution: %s",
               cls, field);
    }

out:
    if (col == 3) g_sc.error++;
    g_sc.mig[old_row][col]++;
    mode_run_free(&t32);
    free(map.v);
}

static void run_diff_case(const case_id_t *cid, json_object *test,
                          json_object *post, const evm_membackend *pre,
                          const test_env_t *te)
{
    char err[256] = "";
    built_tx_t bt;
    if (build_tx(jget(test, "transaction"), post, cid->d, cid->g, cid->v, &bt,
                 err, sizeof(err)) != 0) {
        report("ERROR", cid, "%s", err);
        g_dc.error++;
        built_tx_free(&bt);
        return;
    }

    mode_run_t m20, m32;
    exec_mode(20, pre, te, &bt, &m20);
    exec_mode(32, pre, te, &bt, &m32);

    if (m20.outcome == RUN_OK && baseline_pass(&m20, post)) g_dc.baseline_pass++;
    else {
        g_dc.baseline_other++;
        if (g_opt.verbose) report("BASELINE", cid, "20-byte run != fixture");
    }

    for (size_t i = 0; i < m20.rec.n; i++)
        if (addr_is_wide(&m20.rec.seen[i])) {
            report("WIDE20", cid, "a wide address reached the backend in the "
                   "20-byte run (masking failed)");
            g_dc.wide20++;
            break;
        }

    if (m20.outcome != RUN_OK || m32.outcome != RUN_OK) {
        int fault = m20.outcome == RUN_FAULT || m32.outcome == RUN_FAULT;
        report(fault ? "FAULT" : "ERROR", cid, "20: %s / 32: %s",
               m20.outcome == RUN_OK ? "ok" : m20.why,
               m32.outcome == RUN_OK ? "ok" : m32.why);
        if (fault) g_dc.fault++;
        else g_dc.error++;
        goto done;
    }

    {
        char field[160] = "";
        int c = compare_runs(&m20, &m32, field, sizeof(field));
        if (c < 0) {
            report("ERROR", cid, "harness out of memory (compare)");
            g_dc.error++;
            goto done;
        }
        /* presence-based verdict (kept: its counts and the old -> strict
         * migration matrix; per-case lines under --verbose only) */
        int old_row;
        if (c == 0) {
            old_row = 0;
            g_dc.agree++;
            if (g_opt.verbose) report("AGREE", cid, "%s", "");
        } else {
            int mask = classify_wide(&m20, &m32, pre, &bt);
            if (mask < 0) {
                report("ERROR", cid, "harness out of memory (classify)");
                g_dc.error++;
                goto done;
            }
            if (mask == 0) {
                old_row = 8;
                g_dc.unexplained++;
                if (g_opt.verbose)
                    report("UNEXPLAINED", cid, "first difference: %s; no wide "
                           "address in the 32-byte run", field);
            } else {
                old_row = mask & 7;
                g_dc.differ_by_mask[mask & 7]++;
                if (g_opt.verbose) {
                    char cls[64];
                    class_str((unsigned)mask, cls, sizeof(cls));
                    report("DIFFER", cid, "%s; first difference: %s", cls,
                           field);
                }
            }
        }
        strict_case(cid, &m20, &m32, pre, te, &bt, old_row);
    }

done:
    mode_run_free(&m20);
    mode_run_free(&m32);
    built_tx_free(&bt);
}

/* ── per-file driver ────────────────────────────────────────────────── */

typedef struct {
    char         *name;
    unsigned long n;
} fork_count_t;

static fork_count_t *g_forks;
static size_t        g_nforks, g_capforks;
static unsigned long g_cases_seen;

static void fork_count_add(const char *name, unsigned long n)
{
    for (size_t i = 0; i < g_nforks; i++)
        if (strcmp(g_forks[i].name, name) == 0) { g_forks[i].n += n; return; }
    if (g_nforks == g_capforks) {
        size_t ncap = g_capforks ? g_capforks * 2 : 16;
        fork_count_t *nf = realloc(g_forks, ncap * sizeof(*nf));
        if (!nf) { fprintf(stderr, "out of memory\n"); exit(1); }
        g_forks = nf;
        g_capforks = ncap;
    }
    size_t l = strlen(name);
    char *copy = malloc(l + 1);
    if (!copy) { fprintf(stderr, "out of memory\n"); exit(1); }
    memcpy(copy, name, l + 1);
    g_forks[g_nforks].name = copy;
    g_forks[g_nforks].n = n;
    g_nforks++;
}

static int index_of(json_object *post, const char *which, long *out)
{
    json_object *ix = jget(post, "indexes");
    json_object *v = jget(ix, which);
    if (!v || !json_object_is_type(v, json_type_int)) return -1;
    int64_t x = json_object_get_int64(v);
    if (x < 0 || x > 0x7fffffff) return -1;
    *out = (long)x;
    return 0;
}

static void run_file(const char *path)
{
    json_object *root = json_object_from_file(path);
    if (!root || !json_object_is_type(root, json_type_object)) {
        printf("ERROR    %s: not a JSON object file\n", path);
        g_cnt.error++;
        if (root) json_object_put(root);
        return;
    }
    json_object_object_foreach(root, tname, test) {
        json_object *postmap = jget(test, "post");
        if (!postmap || !json_object_is_type(postmap, json_type_object))
            continue;
        if (g_opt.list_forks) {
            json_object_object_foreach(postmap, fname, farr) {
                if (json_object_is_type(farr, json_type_array))
                    fork_count_add(fname,
                                   (unsigned long)json_object_array_length(farr));
            }
            continue;
        }
        if (g_opt.filter && !strstr(tname, g_opt.filter)) continue;
        json_object *farr = jget(postmap, g_opt.fork);
        if (!farr || !json_object_is_type(farr, json_type_array)) continue;
        size_t nposts = json_object_array_length(farr);
        if (nposts == 0) continue;
        g_cases_seen += nposts;

        case_id_t cid = { path, tname, 0, -1, -1, -1 };

        if (g_opt.verify_roots) {
            for (size_t k = 0; k < nposts; k++) {
                json_object *post = json_object_array_get_idx(farr, k);
                cid.post_idx = k;
                if (index_of(post, "data", &cid.d) ||
                    index_of(post, "gas", &cid.g) ||
                    index_of(post, "value", &cid.v)) {
                    cid.d = cid.g = cid.v = -1;
                }
                verify_fixture_root(&cid, post);
            }
            continue;
        }

        /* EXCLUDED (design §1): decided by the transaction's fields. */
        json_object *jtx = jget(test, "transaction");
        int is_blob = jget(jtx, "blobVersionedHashes") != NULL ||
                      jget(jtx, "maxFeePerBlobGas") != NULL;
        int is_setcode = jget(jtx, "authorizationList") != NULL;
        if (is_blob || is_setcode) {
            if (is_blob) g_cnt.excl_blob += nposts;
            else g_cnt.excl_setcode += nposts;
            if (g_opt.verbose) {
                cid.post_idx = 0;
                report("EXCLUDED", &cid, "%zu case(s): %s", nposts,
                       is_blob ? "type-3 blob tx" : "type-4 set-code tx");
            }
            continue;
        }

        char err[256];
        test_env_t te;
        evm_membackend pre;
        evm_membackend_init(&pre);
        int prc = parse_env(test, &te, err, sizeof(err));
        if (prc == 0) prc = load_alloc(jget(test, "pre"), &pre, err,
                                       sizeof(err));
        if (prc != 0) {
            cid.post_idx = 0;
            report("ERROR", &cid, "%zu case(s): %s", nposts, err);
            g_cnt.error += nposts;
            evm_membackend_free(&pre);
            continue;
        }
        pre.has_block0_hash = te.has_prev_hash;
        pre.block0_hash = te.prev_hash;

        for (size_t k = 0; k < nposts; k++) {
            json_object *post = json_object_array_get_idx(farr, k);
            cid.post_idx = k;
            cid.d = cid.g = cid.v = -1;
            if (index_of(post, "data", &cid.d) ||
                index_of(post, "gas", &cid.g) ||
                index_of(post, "value", &cid.v)) {
                report("ERROR", &cid, "post.indexes");
                g_cnt.error++;
                continue;
            }
            if (g_opt.differential) run_diff_case(&cid, test, post, &pre, &te);
            else run_case(&cid, test, post, &pre, &te);
        }
        evm_membackend_free(&pre);
    }
    json_object_put(root);
}

/* ── path collection (sorted, deterministic) ────────────────────────── */

typedef struct {
    char  **v;
    size_t  n, cap;
} paths_t;

static int paths_add(paths_t *p, const char *s)
{
    if (p->n == p->cap) {
        size_t ncap = p->cap ? p->cap * 2 : 64;
        char **nv = realloc(p->v, ncap * sizeof(*nv));
        if (!nv) return -2;
        p->v = nv;
        p->cap = ncap;
    }
    size_t l = strlen(s);
    char *c = malloc(l + 1);
    if (!c) return -2;
    memcpy(c, s, l + 1);
    p->v[p->n++] = c;
    return 0;
}

static int ends_with_json(const char *s)
{
    size_t l = strlen(s);
    return l >= 5 && strcmp(s + l - 5, ".json") == 0;
}

static int collect_dir(const char *dir, paths_t *p)
{
    DIR *d = opendir(dir);
    if (!d) {
        fprintf(stderr, "cannot open directory %s\n", dir);
        return -1;
    }
    struct dirent *e;
    int rc = 0;
    while (rc == 0 && (e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        size_t l = strlen(dir) + 1 + strlen(e->d_name) + 1;
        char *full = malloc(l);
        if (!full) { rc = -2; break; }
        snprintf(full, l, "%s/%s", dir, e->d_name);
        struct stat sb;
        if (stat(full, &sb) == 0) {
            if (S_ISDIR(sb.st_mode)) rc = collect_dir(full, p);
            else if (S_ISREG(sb.st_mode) && ends_with_json(full))
                rc = paths_add(p, full);
        }
        free(full);
    }
    closedir(d);
    return rc;
}

static int cmp_str(const void *a, const void *b)
{
    return strcmp(*(char *const *)a, *(char *const *)b);
}

static int cmp_fork(const void *a, const void *b)
{
    return strcmp(((const fork_count_t *)a)->name,
                  ((const fork_count_t *)b)->name);
}

static int usage(const char *argv0)
{
    fprintf(stderr,
            "usage: %s [--fork Prague] [--addr-bytes 20|32] [--filter S]\n"
            "          [--verbose] <file-or-dir>...\n"
            "       %s --differential [--fork Prague] [--filter S] "
            "[--verbose] <file-or-dir>...\n"
            "       %s --list-forks <file-or-dir>...\n"
            "       %s --verify-fixture-roots [--fork F] [--filter S] "
            "<file-or-dir>...\n", argv0, argv0, argv0, argv0);
    return 2;
}

int main(int argc, char **argv)
{
    g_opt.fork = "Prague";
    g_opt.addr_bytes = 20;
    int first_path = -1, addr_bytes_given = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--fork") == 0 && i + 1 < argc) {
            g_opt.fork = argv[++i];
        } else if (strcmp(argv[i], "--differential") == 0) {
            g_opt.differential = 1;
        } else if (strcmp(argv[i], "--addr-bytes") == 0 && i + 1 < argc) {
            const char *a = argv[++i];
            addr_bytes_given = 1;
            if (strcmp(a, "20") == 0) g_opt.addr_bytes = 20;
            else if (strcmp(a, "32") == 0) g_opt.addr_bytes = 32;
            else return usage(argv[0]);
        } else if (strcmp(argv[i], "--filter") == 0 && i + 1 < argc) {
            g_opt.filter = argv[++i];
        } else if (strcmp(argv[i], "--verbose") == 0) {
            g_opt.verbose = 1;
        } else if (strcmp(argv[i], "--list-forks") == 0) {
            g_opt.list_forks = 1;
        } else if (strcmp(argv[i], "--verify-fixture-roots") == 0) {
            g_opt.verify_roots = 1;
        } else if (argv[i][0] == '-' && argv[i][1] == '-') {
            return usage(argv[0]);
        } else {
            first_path = i;
            break;
        }
    }
    if (first_path < 0) return usage(argv[0]);
    /* --differential runs both widths itself */
    if (g_opt.differential &&
        (addr_bytes_given || g_opt.list_forks || g_opt.verify_roots))
        return usage(argv[0]);
    if (!g_opt.list_forks && !g_opt.verify_roots &&
        strcmp(g_opt.fork, "Prague") != 0) {
        fprintf(stderr, "the engine implements only Prague (EVM_FORK_PRAGUE); "
                "use --list-forks to see what the fixtures contain\n");
        return 2;
    }

    paths_t paths = { NULL, 0, 0 };
    for (int i = first_path; i < argc; i++) {
        struct stat sb;
        if (stat(argv[i], &sb) != 0) {
            fprintf(stderr, "cannot stat %s\n", argv[i]);
            return 2;
        }
        if (S_ISDIR(sb.st_mode)) {
            size_t start = paths.n;
            if (collect_dir(argv[i], &paths) != 0) return 2;
            qsort(paths.v + start, paths.n - start, sizeof(char *), cmp_str);
        } else if (paths_add(&paths, argv[i]) != 0) {
            return 2;
        }
    }

    for (size_t i = 0; i < paths.n; i++) run_file(paths.v[i]);

    int exit_code;
    if (g_opt.list_forks) {
        qsort(g_forks, g_nforks, sizeof(fork_count_t), cmp_fork);
        printf("fork cases (post entries) in %zu file(s):\n", paths.n);
        for (size_t i = 0; i < g_nforks; i++)
            printf("  %-28s %lu\n", g_forks[i].name, g_forks[i].n);
        exit_code = 0;
    } else if (g_opt.differential) {
        unsigned long excl = g_cnt.excl_blob + g_cnt.excl_setcode;
        unsigned long differ = 0;
        for (int k = 1; k < 8; k++) differ += g_dc.differ_by_mask[k];
        unsigned long eligible = g_dc.agree + differ + g_dc.unexplained +
                                 g_dc.fault + g_dc.error;
        unsigned long error = g_dc.error + g_cnt.error;
        printf("=== differential 20/32 summary: fork %s, %zu file(s)%s%s ===\n"
               "    (Nodus-derived, self-consistent: the same engine runs "
               "both widths;\n     shared bugs are invisible; NOT an official "
               "result)\n",
               g_opt.fork, paths.n, g_opt.filter ? ", filter " : "",
               g_opt.filter ? g_opt.filter : "");
        printf("ELIGIBLE     %lu   (both widths ran or were attempted)\n",
               eligible);
        printf("-- strict (address map from the engine's creation preimages, "
               "32-byte result\n   translated to the 20-byte counterparts, "
               "then compared field by field) --\n");
        printf("STRICT_AGREE        %lu   (equal after substitution; %lu with "
               "a CREATE2 pair,\n                          %lu of them paired "
               "through the initcode)\n",
               g_sc.agree, g_sc.agree_create2, g_sc.agree_init);
        unsigned long sdiffer = 0;
        for (int k = 1; k < (1 << SC_NCLASS); k++) sdiffer += g_sc.by_mask[k];
        printf("STRICT_DIFFER       %lu   (a width-dependent reason class "
               "present)\n", sdiffer);
        for (int k = 1; k < (1 << SC_NCLASS); k++) {
            if (!g_sc.by_mask[k]) continue;
            char cls[96];
            sclass_str((unsigned)k, cls, sizeof(cls));
            printf("  %-40s %lu\n", cls, g_sc.by_mask[k]);
        }
        printf("STRICT_UNEXPLAINED  %lu   (S_UNEXPL lines above)\n",
               g_sc.unexplained);
        printf("STRICT_ERROR        %lu   (address map conflict / out of "
               "memory)\n", g_sc.error);
        printf("migration presence-based -> strict "
               "(S_AGREE / S_DIFFER / S_UNEXPL / S_ERROR):\n");
        for (int k = 0; k < 9; k++) {
            const unsigned long *row = g_sc.mig[k];
            if (!(row[0] | row[1] | row[2] | row[3])) continue;
            char cls[64];
            if (k == 0) snprintf(cls, sizeof(cls), "AGREE");
            else if (k == 8) snprintf(cls, sizeof(cls), "UNEXPLAINED");
            else {
                char sub[48];
                class_str((unsigned)k, sub, sizeof(sub));
                snprintf(cls, sizeof(cls), "DIFFER %s", sub);
            }
            printf("  %-40s %lu / %lu / %lu / %lu\n", cls, row[0], row[1],
                   row[2], row[3]);
        }
        printf("-- presence-based (the first version of this mode) --\n");
        printf("AGREE        %lu\n", g_dc.agree);
        printf("DIFFER       %lu   (a wide address arose in the 32-byte run; "
               "sub-labels heuristic)\n", differ);
        for (int k = 1; k < 8; k++) {
            if (!g_dc.differ_by_mask[k]) continue;
            char cls[64];
            class_str((unsigned)k, cls, sizeof(cls));
            printf("  %-32s %lu\n", cls, g_dc.differ_by_mask[k]);
        }
        printf("UNEXPLAINED  %lu   (differ, no wide address seen)\n",
               g_dc.unexplained);
        printf("FAULT        %lu\n", g_dc.fault);
        printf("ERROR        %lu   (harness could not represent the case)\n",
               error);
        printf("WIDE20       %lu   (wide address reached the backend in the "
               "20-byte run)\n", g_dc.wide20);
        printf("EXCLUDED     %lu   (design §1 — NOT compared)\n", excl);
        printf("  type-3 blob (blobVersionedHashes/maxFeePerBlobGas) %lu\n",
               g_cnt.excl_blob);
        printf("  type-4 set-code (authorizationList)                %lu\n",
               g_cnt.excl_setcode);
        printf("BASELINE     %lu of %lu eligible 20-byte runs equal the fixture "
               "(the rest include the documented DEVIATIONS)\n",
               g_dc.baseline_pass, g_dc.baseline_pass + g_dc.baseline_other);
        printf("TOTAL        %lu   (post entries of fork %s seen: %lu)\n",
               eligible + g_cnt.error + excl, g_opt.fork, g_cases_seen);
        if (g_cases_seen == 0) exit_code = 3;
        else if (g_dc.unexplained || g_dc.fault || error || g_dc.wide20 ||
                 g_sc.unexplained || g_sc.error || eligible == 0)
            exit_code = 1;
        else exit_code = 0;
    } else {
        unsigned long excl = g_cnt.excl_blob + g_cnt.excl_setcode;
        unsigned long total = g_cnt.pass + g_cnt.fail + g_cnt.fault +
                              g_cnt.error + excl +
                              g_cnt.deviation;
        printf("=== %s summary: fork %s, addr_bytes %u, %zu file(s)%s%s ===\n",
               g_opt.verify_roots ? "fixture-root self-check" : "statetest",
               g_opt.fork, g_opt.addr_bytes, paths.n,
               g_opt.filter ? ", filter " : "",
               g_opt.filter ? g_opt.filter : "");
        printf("PASS      %lu\n", g_cnt.pass);
        printf("FAIL      %lu\n", g_cnt.fail);
        printf("FAULT     %lu\n", g_cnt.fault);
        printf("ERROR     %lu   (harness could not represent the case)\n",
               g_cnt.error);
        if (!g_opt.verify_roots) {
            printf("DEVIATION %lu   (documented Nodus rule, listed in "
                   "statetest.c — NOT a pass)\n", g_cnt.deviation);
            printf("EXCLUDED  %lu   (design §1 — NOT a pass)\n", excl);
            printf("  type-3 blob (blobVersionedHashes/maxFeePerBlobGas) %lu\n",
                   g_cnt.excl_blob);
            printf("  type-4 set-code (authorizationList)                %lu\n",
                   g_cnt.excl_setcode);
        }
        printf("TOTAL     %lu   (post entries of fork %s seen: %lu)\n", total,
               g_opt.fork, g_cases_seen);
        if (g_cases_seen == 0) exit_code = 3;
        else if (g_cnt.fail || g_cnt.fault || g_cnt.error) exit_code = 1;
        else exit_code = 0;
    }

    for (size_t i = 0; i < paths.n; i++) free(paths.v[i]);
    free(paths.v);
    for (size_t i = 0; i < g_nforks; i++) free(g_forks[i].name);
    free(g_forks);
    free(g_cr.prev);
    return exit_code;
}
