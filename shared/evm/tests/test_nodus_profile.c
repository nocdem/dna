/**
 * @file test_nodus_profile.c
 * @brief Nodus EVM Nodus profile — BUDGET, wei_destroyed, tickets,
 *        evm_tx_prevalidate (engine checks, compile-and-run standalone).
 *
 * Spec under test: docs/plans/2026-10-04-nodus-evm-chain-integration-design.md
 * (rev 3) §3 (backend EVM_BUDGET: transaction-wide, uncatchable), §4
 * (pre-validation shared with apply), §5 (loss journaling rev 3, ticket
 * system address), §10 (Nodus block environment: base fee and gas price
 * 0, COINBASE 0). Public API only (evm.h), over the test-only in-memory
 * backend (tests/evm_membackend.c), 32-byte addresses.
 *
 * Checks (each prints PASS/FAIL under its name):
 *   n1_budget_nested_sload_uncatchable
 *       control: OUTER writes slot 0, CALLs INNER (SLOAD 5, SSTORE 6),
 *       writes the CALL result to slot 1 -> SUCCESS, slots 0/1 = 1.
 *       With the backend answering EVM_BUDGET on the 2nd storage read
 *       (INNER's SLOAD): rc 0, status EVM_EXEC_BUDGET, OUTER's slots 0
 *       and 1 absent (its write before the CALL is reverted and it never
 *       resumed to write slot 1 — the outer frame could not catch it),
 *       sender nonce +1, gas_used = gas_limit, no output/logs/tickets,
 *       wei_destroyed 0.
 *   n2_budget_before_checkpoint_abandons
 *       EVM_BUDGET on the sender's first read (validation peek) and on
 *       its second read (the nonce-increment load): evm_tx_apply returns
 *       -3 and the change set is empty.
 *   n3_wei_destroyed_paths
 *       (i)   create tx, value V, init code ADDRESS SELFDESTRUCT:
 *             wei_destroyed = V, the created account is gone;
 *       (ii)  factory CREATEs (endowment E) a child whose init code is
 *             CALLER SELFDESTRUCT (E goes back to the factory, +0), then
 *             CALLs the child with value X: the child is deleted at the
 *             end of the tx holding X -> wei_destroyed = X;
 *       (iii) a frame CREATEs a SELFDESTRUCT-to-self child (E destroyed)
 *             then REVERTs: wei_destroyed back to 0, its balance intact;
 *             control: the same frame without the REVERT -> E.
 *   n4_ticket_top_level_and_ids
 *       a top-level tx to the ticket address, value 3q, 64-byte calldata:
 *       SUCCESS, one ticket {id, 3q, dest}, output = id, sender debited
 *       3q, the ticket address untouched, gas_used = intrinsic + 25000.
 *       Ticket ids are checked against hashlib.sha3_512 (independent):
 *         python3 -c "import hashlib; d=b'NDS.EVMTKT.v1\0\0\0';
 *           i=bytes((0x40+k)&0xff for k in range(64));
 *           print(hashlib.sha3_512(d+i+(0).to_bytes(4,'big')).hexdigest())"
 *       (seq 1: (1).to_bytes(4,'big')).
 *   n5_ticket_contract_two_seq
 *       a contract CALLs the ticket address twice in one tx: tickets seq 0
 *       and seq 1 (ids from the vectors above), both returned into memory
 *       (slots), contract debited 2 * 2q.
 *   n6_ticket_rejected_shapes
 *       STATICCALL, DELEGATECALL, CALLCODE (value 2q), CALL value 0, CALL
 *       value 2q + 1, CALL with 63 bytes of calldata, CALL value 2q from a
 *       contract holding q: each call returns 0, consumes the forwarded
 *       gas (GAS after the call < 200000 of the 5 000 000 limit), creates
 *       no ticket, moves no value (contract balance unchanged, ticket
 *       address absent). Top-level tx with 63 bytes: status
 *       PRECOMPILE_FAILURE, gas_used = gas_limit, nonce +1, no ticket,
 *       value not moved.
 *   n7_ticket_in_reverted_frame
 *       R CALLs KREV (KREV creates a ticket, then REVERTs), then R creates
 *       its own ticket: exactly one ticket, seq 0 id, amount of R's call;
 *       KREV's balance unchanged.
 *   n8_prevalidate
 *       valid tx: 0, change set empty; the following evm_tx_apply makes
 *       the same number of backend account reads and the same change set
 *       as on a fresh state (no cache filled). Refusals (nonce too high,
 *       insufficient funds, intrinsic gas): prevalidate and apply agree
 *       on -1 and tx_error, change set empty. Backend EVM_BUDGET on the
 *       sender read: prevalidate -3, change set empty.
 *   n9_config_validation
 *       evm_state_new refuses nodus_profile 2, a precompile ticket
 *       address, a zero ticket unit.
 *   n10_ticket_call_price_ignores_liveness
 *       (F12, Kurultay 2026-10-05 red-team 1) a contract measures the GAS
 *       window around one ticket CALL (value 2q): 22 + 31800 both when the
 *       ticket address is absent and when it holds 1 wei (alive) — no
 *       NEW_ACCOUNT surcharge for that target; same tx gas_used in both.
 *       Control: the same CALL to an absent ordinary address is still
 *       charged NEW_ACCOUNT (22 + 34300). Derivation at n10.
 *
 * Standalone harness (like tests/test_addr32.c): reports via fprintf;
 * exit 0 = every check passed, 1 = a check failed, 2 = engine fault/OOM.
 */
#include "evm.h"
#include "evm_membackend.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── opcodes (execution-specs@a87891f7 prague/vm/instructions) ──────── */
#define OP_STOP          0x00
#define OP_SUB           0x03
#define OP_ADDRESS       0x30
#define OP_CALLER        0x33
#define OP_MLOAD         0x51
#define OP_MSTORE        0x52
#define OP_SLOAD         0x54
#define OP_SSTORE        0x55
#define OP_GAS           0x5a
#define OP_PUSH1         0x60
#define OP_DUP6          0x85
#define OP_SWAP1         0x90
#define OP_CREATE        0xf0
#define OP_CALL          0xf1
#define OP_CALLCODE      0xf2
#define OP_DELEGATECALL  0xf4
#define OP_STATICCALL    0xfa
#define OP_REVERT        0xfd
#define OP_SELFDESTRUCT  0xff

/* q = 10^10 wei (design §5) and the ticket gas (design §5: 25000) */
#define Q_UNIT           10000000000ull
#define TICKET_GAS       25000ull
#define TX_GAS           5000000ull

/* ticket ids for intent_id[k] = 0x40 + k (hashlib.sha3_512, see header) */
static const char *TICKET_ID_SEQ0 =
    "7e015e25c59f7fd8f75218fa7a55c55a81b6459eb053654bb9823908e6f80e65"
    "e362d9fa99852dc8c4a81b79408d2af6212db1b226cd1e8ee6a75743875718be";
static const char *TICKET_ID_SEQ1 =
    "19b2c51414a466e3addec9eb35f4a439866d0353d04bdee7a71fb0dd6f7f472e"
    "1e2b701acea341b205f689e12ba6e4c850900bc8785946567a26dc52e9017098";

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

/* ── small helpers ──────────────────────────────────────────────────── */

static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

static void hexn(uint8_t *out, const char *s, size_t n)
{
    for (size_t i = 0; i < n; i++)
        out[i] = (uint8_t)(hexval(s[2 * i]) * 16 + hexval(s[2 * i + 1]));
}

static void word_u64(uint8_t out[32], uint64_t v)
{
    memset(out, 0, 32);
    for (int i = 0; i < 8; i++) out[31 - i] = (uint8_t)(v >> (8 * i));
}

/* account address: all 32 bytes = tag (high 12 bytes non-zero: never a
 * precompile number, never a 20-byte projection) */
static void addr_of(uint8_t tag, uint8_t out[32])
{
    memset(out, tag, 32);
}

static int u256_eq_u64(const evm_u256 *a, uint64_t v)
{
    evm_u256 b;
    evm_u256_from_u64(&b, v);
    return evm_u256_cmp(a, &b) == 0;
}

/* intent id used by every tx: intent[k] = 0x40 + k */
static void intent_fill(uint8_t out[64])
{
    for (int k = 0; k < 64; k++) out[k] = (uint8_t)(0x40 + k);
}

/* destination fingerprint used by the ticket calls (no zero byte) */
static void dest_fill(uint8_t out[64])
{
    for (int k = 0; k < 64; k++) out[k] = (uint8_t)(0x11 + k);
}

/* ── tiny assembler ──────────────────────────────────────────────────── */

typedef struct {
    uint8_t b[2048];
    size_t  n;
    int     overflow;
} asm_t;

static void a_byte(asm_t *a, uint8_t v)
{
    if (a->n >= sizeof(a->b)) {
        a->overflow = 1;
        return;
    }
    a->b[a->n++] = v;
}

static void a_push(asm_t *a, const uint8_t *v, size_t len)
{
    a_byte(a, (uint8_t)(OP_PUSH1 + len - 1));
    for (size_t i = 0; i < len; i++) a_byte(a, v[i]);
}

static void a_push1(asm_t *a, uint8_t v)
{
    a_push(a, &v, 1);
}

static void a_push32(asm_t *a, const uint8_t v[32])
{
    a_push(a, v, 32);
}

static void a_push_u64(asm_t *a, uint64_t v)
{
    uint8_t w[32];
    word_u64(w, v);
    a_push32(a, w);
}

/* <value on stack> -> storage[slot] */
static void a_store(asm_t *a, uint8_t slot)
{
    a_push1(a, slot);
    a_byte(a, OP_SSTORE);
}

/* memory[0..64) = dest */
static void a_mstore_dest(asm_t *a, const uint8_t dest[64])
{
    a_push32(a, dest);
    a_push1(a, 0);
    a_byte(a, OP_MSTORE);
    a_push32(a, dest + 32);
    a_push1(a, 32);
    a_byte(a, OP_MSTORE);
}

/* a call forwarding all gas; value only for CALL / CALLCODE */
static void a_call(asm_t *a, uint8_t op, const uint8_t addr[32],
                   uint64_t value, uint8_t in_off, uint8_t in_size,
                   uint8_t out_off, uint8_t out_size)
{
    a_push1(a, out_size);
    a_push1(a, out_off);
    a_push1(a, in_size);
    a_push1(a, in_off);
    if (op == OP_CALL || op == OP_CALLCODE) a_push_u64(a, value);
    a_push32(a, addr);
    a_byte(a, OP_GAS);
    a_byte(a, op);
}

/* 2-byte init code right-aligned into memory word 0 (offset 30), then
 * CREATE(endowment, 30, 2) -> new address on the stack */
static void a_create2b(asm_t *a, uint8_t c0, uint8_t c1, uint64_t endowment)
{
    uint8_t code[2] = { c0, c1 };
    a_push(a, code, 2);
    a_push1(a, 0);
    a_byte(a, OP_MSTORE);
    a_push1(a, 2);
    a_push1(a, 30);
    a_push_u64(a, endowment);
    a_byte(a, OP_CREATE);
}

/* ── backend with injected EVM_BUDGET ──────────────────────────────── */

typedef struct {
    evm_backend_t inner;
    unsigned      account_calls, storage_calls;
    unsigned      budget_account_at;     /* 0 = never */
    unsigned      budget_storage_at;     /* 0 = never */
} bud_t;

static int bud_get_account(void *ctx, const evm_addr *addr, evm_account_t *out)
{
    bud_t *b = ctx;
    b->account_calls++;
    if (b->budget_account_at && b->account_calls == b->budget_account_at)
        return EVM_BUDGET;
    return b->inner.get_account(b->inner.ctx, addr, out);
}

static int bud_get_code(void *ctx, const evm_addr *addr, uint8_t *buf,
                        size_t cap, size_t *len_out)
{
    bud_t *b = ctx;
    return b->inner.get_code(b->inner.ctx, addr, buf, cap, len_out);
}

static int bud_get_storage(void *ctx, const evm_addr *addr,
                           const evm_bytes32 *key, evm_bytes32 *val_out)
{
    bud_t *b = ctx;
    b->storage_calls++;
    if (b->budget_storage_at && b->storage_calls == b->budget_storage_at)
        return EVM_BUDGET;
    return b->inner.get_storage(b->inner.ctx, addr, key, val_out);
}

static int bud_get_block_hash(void *ctx, uint64_t number, evm_bytes32 *hash,
                              int *available)
{
    bud_t *b = ctx;
    return b->inner.get_block_hash(b->inner.ctx, number, hash, available);
}

static int bud_has_storage(void *ctx, const evm_addr *addr, int *out)
{
    bud_t *b = ctx;
    return b->inner.has_storage(b->inner.ctx, addr, out);
}

/* ── run context ───────────────────────────────────────────────────── */

typedef struct {
    bud_t           bud;
    evm_backend_t   be;
    evm_config_t    cfg;
    evm_block_env_t env;
    evm_state_t    *st;
} run_t;

static void chain_id(evm_u256 *out)
{
    uint8_t b[32];
    for (int i = 0; i < 32; i++) b[i] = (uint8_t)(0xA0 + i);
    evm_u256_from_be(out, b);
}

static const uint8_t TICKET_TAG = 0xEE;

static void make_cfg(evm_config_t *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    cfg->fork = EVM_FORK_PRAGUE;
    cfg->addr_bytes = 32;
    chain_id(&cfg->chain_id);
    cfg->precompile_mask = EVM_PRECOMPILES_PRAGUE;
    cfg->nodus_profile = 1;
    addr_of(TICKET_TAG, cfg->ticket_addr.b);
    evm_u256_from_u64(&cfg->ticket_unit, Q_UNIT);
    cfg->ticket_gas = TICKET_GAS;
}

/* design §10: COINBASE 0, BASEFEE 0, PREVRANDAO 0 */
static void make_env(evm_block_env_t *env)
{
    memset(env, 0, sizeof(*env));
    env->number = 100;
    env->timestamp = 1000;
    env->gas_limit = 30000000;
}

static void run_open(run_t *r, const evm_membackend *mb)
{
    memset(r, 0, sizeof(*r));
    make_cfg(&r->cfg);
    make_env(&r->env);
    evm_membackend_bind(mb, &r->bud.inner);
    r->be.ctx = &r->bud;
    r->be.get_account = bud_get_account;
    r->be.get_code = bud_get_code;
    r->be.get_storage = bud_get_storage;
    r->be.get_block_hash = bud_get_block_hash;
    r->be.has_storage = bud_has_storage;
    r->st = evm_state_new(&r->cfg, &r->be);
    if (!r->st) fatal("evm_state_new");
}

static void run_close(run_t *r)
{
    evm_state_free(r->st);
    r->st = NULL;
}

static void make_tx(evm_tx_t *tx, const uint8_t from[32], uint64_t nonce,
                    const uint8_t *to, uint64_t value, const uint8_t *data,
                    size_t data_len)
{
    memset(tx, 0, sizeof(*tx));
    tx->type = 0;                         /* gas_price 0 = base_fee 0 */
    memcpy(tx->sender.b, from, 32);
    if (to) memcpy(tx->to.b, to, 32);
    else tx->is_create = 1;
    tx->nonce = nonce;
    tx->gas_limit = TX_GAS;
    evm_u256_from_u64(&tx->value, value);
    tx->data = data;
    tx->data_len = data_len;
    tx->has_chain_id = 1;
    chain_id(&tx->chain_id);
    intent_fill(tx->intent_id);
}

/* evm_tx_apply; -2 is fatal (no outcome to judge) */
static int apply(run_t *r, const evm_tx_t *tx, evm_tx_result_t *res)
{
    int rc = evm_tx_apply(r->st, &r->env, tx, res);
    if (rc == -2) fatal("evm_tx_apply fault");
    return rc;
}

/* ── captured change set ───────────────────────────────────────────── */

typedef struct {
    evm_addr addr;
    int      deleted;
    uint64_t nonce;
    uint8_t  balance[32];
    int      storage_cleared;
} acc_rec;

typedef struct {
    evm_addr    addr;
    evm_bytes32 key;
    evm_bytes32 val;
} slot_rec;

typedef struct {
    acc_rec  acc[64];
    size_t   na;
    slot_rec sl[128];
    size_t   ns;
} changes_t;

static int cb_account(void *ctx, const evm_account_change_t *ch)
{
    changes_t *c = ctx;
    if (c->na >= sizeof(c->acc) / sizeof(c->acc[0])) fatal("too many accounts");
    acc_rec *r = &c->acc[c->na++];
    memset(r, 0, sizeof(*r));
    r->addr = ch->addr;
    r->deleted = ch->deleted;
    r->nonce = ch->nonce;
    evm_u256_to_be(r->balance, &ch->balance);
    r->storage_cleared = ch->storage_cleared;
    return 0;
}

static int cb_storage(void *ctx, const evm_addr *addr, const evm_bytes32 *key,
                      const evm_bytes32 *value)
{
    changes_t *c = ctx;
    if (c->ns >= sizeof(c->sl) / sizeof(c->sl[0])) fatal("too many slots");
    slot_rec *s = &c->sl[c->ns++];
    s->addr = *addr;
    s->key = *key;
    s->val = *value;
    return 0;
}

static void collect(const evm_state_t *st, changes_t *c)
{
    memset(c, 0, sizeof(*c));
    evm_change_visitor_t v;
    v.account = cb_account;
    v.storage = cb_storage;
    v.ctx = c;
    if (evm_state_visit_changes(st, &v) != 0) fatal("visit_changes");
}

static int changes_equal(const changes_t *a, const changes_t *b)
{
    if (a->na != b->na || a->ns != b->ns) return 0;
    for (size_t i = 0; i < a->na; i++) {
        const acc_rec *x = &a->acc[i], *y = &b->acc[i];
        if (memcmp(x->addr.b, y->addr.b, 32) != 0 || x->deleted != y->deleted ||
            x->nonce != y->nonce || memcmp(x->balance, y->balance, 32) != 0 ||
            x->storage_cleared != y->storage_cleared)
            return 0;
    }
    for (size_t i = 0; i < a->ns; i++)
        if (memcmp(&a->sl[i], &b->sl[i], sizeof(a->sl[i])) != 0) return 0;
    return 1;
}

/* post-state views over (pre, change set) */
static const acc_rec *post_rec(const changes_t *c, const uint8_t a[32])
{
    for (size_t i = 0; i < c->na; i++)
        if (memcmp(c->acc[i].addr.b, a, 32) == 0) return &c->acc[i];
    return NULL;
}

static int post_exists(const evm_membackend *mb, const changes_t *c,
                       const uint8_t a[32])
{
    const acc_rec *r = post_rec(c, a);
    if (r) return !r->deleted;
    evm_addr x;
    memcpy(x.b, a, 32);
    return evm_membackend_find(mb, &x) != NULL;
}

static uint64_t post_nonce(const evm_membackend *mb, const changes_t *c,
                           const uint8_t a[32])
{
    const acc_rec *r = post_rec(c, a);
    if (r) return r->deleted ? 0 : r->nonce;
    evm_addr x;
    memcpy(x.b, a, 32);
    const evm_mem_account *m = evm_membackend_find(mb, &x);
    return m ? m->nonce : 0;
}

static int post_balance_is(const evm_membackend *mb, const changes_t *c,
                           const uint8_t a[32], uint64_t want)
{
    uint8_t got[32], w[32];
    const acc_rec *r = post_rec(c, a);
    word_u64(w, want);
    if (r) {
        if (r->deleted) memset(got, 0, 32);
        else memcpy(got, r->balance, 32);
    } else {
        evm_addr x;
        memcpy(x.b, a, 32);
        const evm_mem_account *m = evm_membackend_find(mb, &x);
        if (m) memcpy(got, m->balance, 32);
        else memset(got, 0, 32);
    }
    return memcmp(got, w, 32) == 0;
}

/* slot value after the tx (pre-state slots are never used here: every
 * contract starts with empty storage) */
static void post_slot(const changes_t *c, const uint8_t a[32], uint64_t key,
                      uint8_t out[32])
{
    uint8_t k[32];
    word_u64(k, key);
    memset(out, 0, 32);
    for (size_t i = 0; i < c->ns; i++)
        if (memcmp(c->sl[i].addr.b, a, 32) == 0 &&
            memcmp(c->sl[i].key.b, k, 32) == 0)
            memcpy(out, c->sl[i].val.b, 32);
}

static int post_slot_is(const changes_t *c, const uint8_t a[32], uint64_t key,
                        uint64_t want)
{
    uint8_t got[32], w[32];
    post_slot(c, a, key, got);
    word_u64(w, want);
    return memcmp(got, w, 32) == 0;
}

/* slot value as a u64 when it fits (the GAS readings) */
static uint64_t post_slot_u64(const changes_t *c, const uint8_t a[32],
                              uint64_t key)
{
    uint8_t got[32];
    uint64_t v = 0;
    post_slot(c, a, key, got);
    for (int i = 0; i < 24; i++)
        if (got[i]) return UINT64_MAX;
    for (int i = 24; i < 32; i++) v = (v << 8) | got[i];
    return v;
}

/* ── pre-state builders ─────────────────────────────────────────────── */

static void add_acc(evm_membackend *mb, uint8_t tag, uint64_t nonce,
                    uint64_t balance, const asm_t *code)
{
    uint8_t a[32], bal[32];
    addr_of(tag, a);
    word_u64(bal, balance);
    evm_addr x;
    memcpy(x.b, a, 32);
    if (code && code->overflow) fatal("assembler overflow");
    if (evm_membackend_add_account(mb, &x, nonce, bal,
                                   code ? code->b : NULL, code ? code->n : 0,
                                   NULL, NULL) != 0)
        fatal("membackend_add_account");
}

static void finalize(evm_membackend *mb)
{
    if (evm_membackend_finalize(mb) != 0) fatal("membackend_finalize");
}

#define T_SENDER 0x5e                     /* funded EOA, nonce 3           */
#define BAL_SENDER 1000000000000000000ull /* 1e18 wei                      */

/* ── n1: BUDGET at a nested SLOAD ───────────────────────────────────── */

static void n1(void)
{
    check_begin("n1_budget_nested_sload_uncatchable");
    const uint8_t T_OUTER = 0x61, T_INNER = 0x62;
    uint8_t outer[32], inner[32], sender[32];
    addr_of(T_OUTER, outer);
    addr_of(T_INNER, inner);
    addr_of(T_SENDER, sender);
    asm_t co, ci;
    memset(&co, 0, sizeof(co));
    a_push1(&co, 1);
    a_store(&co, 0);                      /* storage read #1 (OUTER slot 0) */
    a_call(&co, OP_CALL, inner, 0, 0, 0, 0, 0);
    a_store(&co, 1);                      /* CALL result -> slot 1          */
    a_byte(&co, OP_STOP);
    memset(&ci, 0, sizeof(ci));
    a_push1(&ci, 5);
    a_byte(&ci, OP_SLOAD);                /* storage read #2 (INNER slot 5) */
    a_store(&ci, 6);
    a_byte(&ci, OP_STOP);

    evm_membackend mb;
    evm_membackend_init(&mb);
    add_acc(&mb, T_SENDER, 3, BAL_SENDER, NULL);
    add_acc(&mb, T_OUTER, 1, 0, &co);
    add_acc(&mb, T_INNER, 1, 0, &ci);
    finalize(&mb);

    for (int budget = 0; budget <= 1; budget++) {
        run_t r;
        evm_tx_t tx;
        evm_tx_result_t res;
        changes_t cs;
        run_open(&r, &mb);
        r.bud.budget_storage_at = budget ? 2 : 0;
        make_tx(&tx, sender, 3, outer, 0, NULL, 0);
        int rc = apply(&r, &tx, &res);
        expect(rc == 0, "tx applied");
        collect(r.st, &cs);
        if (!budget) {
            expect(res.status == EVM_EXEC_SUCCESS, "control: SUCCESS");
            expect(post_slot_is(&cs, outer, 0, 1), "control: OUTER slot 0 = 1");
            expect(post_slot_is(&cs, outer, 1, 1), "control: CALL result 1");
        } else {
            expect(res.status == EVM_EXEC_BUDGET, "status EVM_EXEC_BUDGET");
            expect(r.bud.storage_calls == 2, "BUDGET hit at the inner SLOAD");
            expect(post_slot_is(&cs, outer, 0, 0),
                   "OUTER write before the CALL reverted");
            expect(post_slot_is(&cs, outer, 1, 0),
                   "OUTER never resumed (could not catch BUDGET)");
            expect(post_nonce(&mb, &cs, sender) == 4, "sender nonce +1");
            expect(res.gas_used == TX_GAS, "gas_used = gas_limit");
            expect(res.output_len == 0 && res.n_logs == 0 &&
                   res.n_tickets == 0, "no output, logs, tickets");
            expect(evm_u256_is_zero(&res.wei_destroyed), "wei_destroyed 0");
        }
        evm_tx_result_free(&res);
        run_close(&r);
    }
    evm_membackend_free(&mb);
    check_end();
}

/* ── n2: BUDGET before the execution checkpoint ─────────────────────── */

static void n2(void)
{
    check_begin("n2_budget_before_checkpoint_abandons");
    uint8_t sender[32], to[32];
    addr_of(T_SENDER, sender);
    addr_of(0x63, to);
    evm_membackend mb;
    evm_membackend_init(&mb);
    add_acc(&mb, T_SENDER, 3, BAL_SENDER, NULL);
    finalize(&mb);
    for (unsigned at = 1; at <= 2; at++) {
        run_t r;
        evm_tx_t tx;
        evm_tx_result_t res;
        changes_t cs;
        run_open(&r, &mb);
        r.bud.budget_account_at = at;
        make_tx(&tx, sender, 3, to, 5, NULL, 0);
        int rc = apply(&r, &tx, &res);
        expect(rc == EVM_BUDGET, at == 1 ? "validation peek: -3"
                                          : "nonce-increment load: -3");
        collect(r.st, &cs);
        expect(cs.na == 0 && cs.ns == 0, "nothing applied");
        evm_tx_result_free(&res);
        run_close(&r);
    }
    evm_membackend_free(&mb);
    check_end();
}

/* ── n3: wei_destroyed ──────────────────────────────────────────────── */

static void n3(void)
{
    check_begin("n3_wei_destroyed_paths");
    const uint8_t T_FACT = 0x71, T_H = 0x72, T_F2 = 0x73, T_HC = 0x74,
                  T_F3 = 0x75;
    const uint64_t V = 1000, E = 100, X = 7;
    uint8_t sender[32], fact[32], h[32], f2[32], hc[32], f3[32];
    addr_of(T_SENDER, sender);
    addr_of(T_FACT, fact);
    addr_of(T_H, h);
    addr_of(T_F2, f2);
    addr_of(T_HC, hc);
    addr_of(T_F3, f3);

    /* (ii) factory: CREATE(E, CALLER SELFDESTRUCT) -> c; CALL c value X;
     * result -> slot 0 */
    asm_t cf;
    memset(&cf, 0, sizeof(cf));
    a_create2b(&cf, OP_CALLER, OP_SELFDESTRUCT, E);     /* stack: c        */
    a_push1(&cf, 0);
    a_push1(&cf, 0);
    a_push1(&cf, 0);
    a_push1(&cf, 0);
    a_push_u64(&cf, X);                                 /* X,0,0,0,0,c     */
    a_byte(&cf, OP_DUP6);                               /* c,X,0,0,0,0,c   */
    a_byte(&cf, OP_GAS);
    a_byte(&cf, OP_CALL);
    a_store(&cf, 0);
    a_byte(&cf, OP_STOP);

    /* (iii) H: CREATE(E, ADDRESS SELFDESTRUCT) then REVERT; HC: same,
     * STOP instead (control) */
    asm_t ch, chc;
    memset(&ch, 0, sizeof(ch));
    a_create2b(&ch, OP_ADDRESS, OP_SELFDESTRUCT, E);
    a_push1(&ch, 0);
    a_push1(&ch, 0);
    a_byte(&ch, OP_REVERT);
    memset(&chc, 0, sizeof(chc));
    a_create2b(&chc, OP_ADDRESS, OP_SELFDESTRUCT, E);
    a_byte(&chc, OP_STOP);
    /* F2 / F3 call H / HC, result -> slot 0 */
    asm_t cf2, cf3;
    memset(&cf2, 0, sizeof(cf2));
    a_call(&cf2, OP_CALL, h, 0, 0, 0, 0, 0);
    a_store(&cf2, 0);
    a_byte(&cf2, OP_STOP);
    memset(&cf3, 0, sizeof(cf3));
    a_call(&cf3, OP_CALL, hc, 0, 0, 0, 0, 0);
    a_store(&cf3, 0);
    a_byte(&cf3, OP_STOP);

    evm_membackend mb;
    evm_membackend_init(&mb);
    add_acc(&mb, T_SENDER, 3, BAL_SENDER, NULL);
    add_acc(&mb, T_FACT, 1, 1000, &cf);
    add_acc(&mb, T_H, 1, 1000, &ch);
    add_acc(&mb, T_F2, 1, 0, &cf2);
    add_acc(&mb, T_HC, 1, 1000, &chc);
    add_acc(&mb, T_F3, 1, 0, &cf3);
    finalize(&mb);

    run_t r;
    evm_tx_t tx;
    evm_tx_result_t res;
    changes_t cs;

    /* (i) create tx: ADDRESS SELFDESTRUCT, value V */
    static const uint8_t init_self[2] = { OP_ADDRESS, OP_SELFDESTRUCT };
    run_open(&r, &mb);
    make_tx(&tx, sender, 3, NULL, V, init_self, sizeof(init_self));
    expect(apply(&r, &tx, &res) == 0 && res.status == EVM_EXEC_SUCCESS,
           "(i) create tx SUCCESS");
    expect(u256_eq_u64(&res.wei_destroyed, V), "(i) wei_destroyed = V");
    collect(r.st, &cs);
    expect(!post_exists(&mb, &cs, res.created.b), "(i) created account gone");
    expect(post_balance_is(&mb, &cs, sender, BAL_SENDER - V),
           "(i) sender paid V");
    evm_tx_result_free(&res);
    run_close(&r);

    /* (ii) SELFDESTRUCT to another, then value received in the same tx */
    run_open(&r, &mb);
    make_tx(&tx, sender, 3, fact, 0, NULL, 0);
    expect(apply(&r, &tx, &res) == 0 && res.status == EVM_EXEC_SUCCESS,
           "(ii) factory tx SUCCESS");
    expect(u256_eq_u64(&res.wei_destroyed, X), "(ii) wei_destroyed = X");
    collect(r.st, &cs);
    expect(post_slot_is(&cs, fact, 0, 1), "(ii) CALL into the child ok");
    expect(post_balance_is(&mb, &cs, fact, 1000 - X),
           "(ii) factory: E came back, X left");
    evm_tx_result_free(&res);
    run_close(&r);

    /* (iii) REVERT undoes the SELFDESTRUCT loss */
    run_open(&r, &mb);
    make_tx(&tx, sender, 3, f2, 0, NULL, 0);
    expect(apply(&r, &tx, &res) == 0 && res.status == EVM_EXEC_SUCCESS,
           "(iii) tx SUCCESS");
    expect(evm_u256_is_zero(&res.wei_destroyed),
           "(iii) wei_destroyed back to 0 after REVERT");
    collect(r.st, &cs);
    expect(post_slot_is(&cs, f2, 0, 0), "(iii) inner call reverted");
    expect(post_balance_is(&mb, &cs, h, 1000), "(iii) H balance intact");
    evm_tx_result_free(&res);
    run_close(&r);

    /* (iii) control: no REVERT -> E destroyed */
    run_open(&r, &mb);
    make_tx(&tx, sender, 3, f3, 0, NULL, 0);
    expect(apply(&r, &tx, &res) == 0 && res.status == EVM_EXEC_SUCCESS,
           "(iii) control tx SUCCESS");
    expect(u256_eq_u64(&res.wei_destroyed, E), "(iii) control: wei = E");
    evm_tx_result_free(&res);
    run_close(&r);

    evm_membackend_free(&mb);
    check_end();
}

/* ── tickets ────────────────────────────────────────────────────────── */

static void ticket_expect(const evm_ticket_t *t, const char *id_hex,
                          uint64_t amount, const char *what)
{
    uint8_t id[64], dest[64];
    hexn(id, id_hex, 64);
    dest_fill(dest);
    expect(memcmp(t->ticket_id, id, 64) == 0, what);
    expect(u256_eq_u64(&t->amount_wei, amount), "ticket amount");
    expect(memcmp(t->dest_fp, dest, 64) == 0, "ticket dest_fp");
}

static void n4(void)
{
    check_begin("n4_ticket_top_level_and_ids");
    uint8_t sender[32], tk[32], dest[64], id0[64];
    addr_of(T_SENDER, sender);
    addr_of(TICKET_TAG, tk);
    dest_fill(dest);
    hexn(id0, TICKET_ID_SEQ0, 64);
    evm_membackend mb;
    evm_membackend_init(&mb);
    add_acc(&mb, T_SENDER, 3, BAL_SENDER, NULL);
    finalize(&mb);

    run_t r;
    evm_tx_t tx;
    evm_tx_result_t res;
    changes_t cs;
    run_open(&r, &mb);
    make_tx(&tx, sender, 3, tk, 3 * Q_UNIT, dest, 64);
    expect(apply(&r, &tx, &res) == 0 && res.status == EVM_EXEC_SUCCESS,
           "top-level ticket tx SUCCESS");
    expect(res.n_tickets == 1, "one ticket");
    if (res.n_tickets == 1)
        ticket_expect(&res.tickets[0], TICKET_ID_SEQ0, 3 * Q_UNIT,
                      "ticket id = SHA3-512(domain || intent || 0)");
    expect(res.output_len == 64 && memcmp(res.output, id0, 64) == 0,
           "output = ticket_id");
    /* intrinsic: 21000 + 64 non-zero bytes * 16 = 22024 (floor 23560) */
    expect(res.gas_used == 22024 + TICKET_GAS, "gas = intrinsic + ticket_gas");
    collect(r.st, &cs);
    expect(post_balance_is(&mb, &cs, sender, BAL_SENDER - 3 * Q_UNIT),
           "sender debited 3q");
    expect(post_nonce(&mb, &cs, sender) == 4, "sender nonce +1");
    expect(!post_exists(&mb, &cs, tk), "ticket address credited nothing");
    expect(evm_u256_is_zero(&res.wei_destroyed), "no loss");
    evm_tx_result_free(&res);
    run_close(&r);
    evm_membackend_free(&mb);
    check_end();
}

static void n5(void)
{
    check_begin("n5_ticket_contract_two_seq");
    const uint8_t T_K = 0x81;
    uint8_t sender[32], tk[32], k[32], dest[64];
    addr_of(T_SENDER, sender);
    addr_of(TICKET_TAG, tk);
    addr_of(T_K, k);
    dest_fill(dest);
    asm_t ck;
    memset(&ck, 0, sizeof(ck));
    a_mstore_dest(&ck, dest);
    a_call(&ck, OP_CALL, tk, 2 * Q_UNIT, 0, 64, 0, 64);
    a_store(&ck, 0);
    a_push1(&ck, 0);
    a_byte(&ck, OP_MLOAD);
    a_store(&ck, 2);                      /* id[0..32) of ticket seq 0      */
    a_mstore_dest(&ck, dest);
    a_call(&ck, OP_CALL, tk, 2 * Q_UNIT, 0, 64, 0, 64);
    a_store(&ck, 1);
    a_push1(&ck, 32);
    a_byte(&ck, OP_MLOAD);
    a_store(&ck, 3);                      /* id[32..64) of ticket seq 1     */
    a_byte(&ck, OP_STOP);

    evm_membackend mb;
    evm_membackend_init(&mb);
    add_acc(&mb, T_SENDER, 3, BAL_SENDER, NULL);
    add_acc(&mb, T_K, 1, 5 * Q_UNIT, &ck);
    finalize(&mb);

    run_t r;
    evm_tx_t tx;
    evm_tx_result_t res;
    changes_t cs;
    run_open(&r, &mb);
    make_tx(&tx, sender, 3, k, 0, NULL, 0);
    expect(apply(&r, &tx, &res) == 0 && res.status == EVM_EXEC_SUCCESS,
           "tx SUCCESS");
    expect(res.n_tickets == 2, "two tickets");
    if (res.n_tickets == 2) {
        ticket_expect(&res.tickets[0], TICKET_ID_SEQ0, 2 * Q_UNIT, "seq 0 id");
        ticket_expect(&res.tickets[1], TICKET_ID_SEQ1, 2 * Q_UNIT, "seq 1 id");
    }
    collect(r.st, &cs);
    expect(post_slot_is(&cs, k, 0, 1) && post_slot_is(&cs, k, 1, 1),
           "both CALLs returned 1");
    uint8_t id0[64], id1[64], got[32];
    hexn(id0, TICKET_ID_SEQ0, 64);
    hexn(id1, TICKET_ID_SEQ1, 64);
    post_slot(&cs, k, 2, got);
    expect(memcmp(got, id0, 32) == 0, "returned id seq 0 (first half)");
    post_slot(&cs, k, 3, got);
    expect(memcmp(got, id1 + 32, 32) == 0, "returned id seq 1 (second half)");
    expect(post_balance_is(&mb, &cs, k, 5 * Q_UNIT - 4 * Q_UNIT),
           "contract debited 2 * 2q");
    expect(!post_exists(&mb, &cs, tk), "ticket address credited nothing");
    evm_tx_result_free(&res);
    run_close(&r);
    evm_membackend_free(&mb);
    check_end();
}

typedef struct {
    const char *name;
    uint8_t     op;
    uint64_t    value;
    uint8_t     in_size;
    uint64_t    balance;                  /* the calling contract's        */
} shape_t;

static void n6(void)
{
    check_begin("n6_ticket_rejected_shapes");
    static const shape_t shapes[] = {
        { "STATICCALL",              OP_STATICCALL,   0,              64, 5 * Q_UNIT },
        { "DELEGATECALL",            OP_DELEGATECALL, 0,              64, 5 * Q_UNIT },
        { "CALLCODE value 2q",       OP_CALLCODE,     2 * Q_UNIT,     64, 5 * Q_UNIT },
        { "CALL value 0",            OP_CALL,         0,              64, 5 * Q_UNIT },
        { "CALL value 2q+1",         OP_CALL,         2 * Q_UNIT + 1, 64, 5 * Q_UNIT },
        { "CALL 63-byte calldata",   OP_CALL,         2 * Q_UNIT,     63, 5 * Q_UNIT },
        { "CALL value 2q, holds q",  OP_CALL,         2 * Q_UNIT,     64, Q_UNIT },
    };
    const uint8_t T_K = 0x91;
    uint8_t sender[32], tk[32], k[32], dest[64];
    addr_of(T_SENDER, sender);
    addr_of(TICKET_TAG, tk);
    addr_of(T_K, k);
    dest_fill(dest);

    for (size_t i = 0; i < sizeof(shapes) / sizeof(shapes[0]); i++) {
        const shape_t *s = &shapes[i];
        asm_t ck;
        memset(&ck, 0, sizeof(ck));
        a_mstore_dest(&ck, dest);
        a_call(&ck, s->op, tk, s->value, 0, s->in_size, 0, 64);
        a_store(&ck, 0);                  /* call result                    */
        a_byte(&ck, OP_GAS);
        a_store(&ck, 1);                  /* gas left after the call        */
        a_byte(&ck, OP_STOP);
        evm_membackend mb;
        evm_membackend_init(&mb);
        add_acc(&mb, T_SENDER, 3, BAL_SENDER, NULL);
        add_acc(&mb, T_K, 1, s->balance, &ck);
        finalize(&mb);

        run_t r;
        evm_tx_t tx;
        evm_tx_result_t res;
        changes_t cs;
        run_open(&r, &mb);
        make_tx(&tx, sender, 3, k, 0, NULL, 0);
        int rc = apply(&r, &tx, &res);
        collect(r.st, &cs);
        char what[160];
        snprintf(what, sizeof(what), "%s: tx SUCCESS, call returned 0",
                 s->name);
        expect(rc == 0 && res.status == EVM_EXEC_SUCCESS &&
               post_slot_is(&cs, k, 0, 0), what);
        snprintf(what, sizeof(what), "%s: forwarded gas consumed", s->name);
        expect(post_slot_u64(&cs, k, 1) < 200000, what);
        snprintf(what, sizeof(what), "%s: no ticket, no value moved", s->name);
        expect(res.n_tickets == 0 &&
               post_balance_is(&mb, &cs, k, s->balance) &&
               !post_exists(&mb, &cs, tk), what);
        evm_tx_result_free(&res);
        run_close(&r);
        evm_membackend_free(&mb);
    }

    /* top-level, 63 bytes of calldata */
    evm_membackend mb;
    evm_membackend_init(&mb);
    add_acc(&mb, T_SENDER, 3, BAL_SENDER, NULL);
    finalize(&mb);
    run_t r;
    evm_tx_t tx;
    evm_tx_result_t res;
    changes_t cs;
    run_open(&r, &mb);
    make_tx(&tx, sender, 3, tk, 2 * Q_UNIT, dest, 63);
    expect(apply(&r, &tx, &res) == 0 &&
           res.status == EVM_EXEC_PRECOMPILE_FAILURE,
           "top-level 63 bytes: exceptional halt");
    expect(res.gas_used == TX_GAS, "top-level: gas_used = gas_limit");
    expect(res.n_tickets == 0, "top-level: no ticket");
    collect(r.st, &cs);
    expect(post_nonce(&mb, &cs, sender) == 4, "top-level: nonce +1");
    expect(post_balance_is(&mb, &cs, sender, BAL_SENDER),
           "top-level: value not moved");
    expect(!post_exists(&mb, &cs, tk), "top-level: ticket address untouched");
    evm_tx_result_free(&res);
    run_close(&r);
    evm_membackend_free(&mb);
    check_end();
}

static void n7(void)
{
    check_begin("n7_ticket_in_reverted_frame");
    const uint8_t T_R = 0xA1, T_KREV = 0xA2;
    uint8_t sender[32], tk[32], rr[32], krev[32], dest[64];
    addr_of(T_SENDER, sender);
    addr_of(TICKET_TAG, tk);
    addr_of(T_R, rr);
    addr_of(T_KREV, krev);
    dest_fill(dest);
    asm_t ckrev, cr;
    memset(&ckrev, 0, sizeof(ckrev));
    a_mstore_dest(&ckrev, dest);
    a_call(&ckrev, OP_CALL, tk, Q_UNIT, 0, 64, 0, 64);
    a_push1(&ckrev, 0);
    a_push1(&ckrev, 0);
    a_byte(&ckrev, OP_REVERT);
    memset(&cr, 0, sizeof(cr));
    a_call(&cr, OP_CALL, krev, 0, 0, 0, 0, 0);
    a_store(&cr, 0);                      /* 0: KREV reverted               */
    a_mstore_dest(&cr, dest);
    a_call(&cr, OP_CALL, tk, 2 * Q_UNIT, 0, 64, 0, 64);
    a_store(&cr, 1);
    a_byte(&cr, OP_STOP);

    evm_membackend mb;
    evm_membackend_init(&mb);
    add_acc(&mb, T_SENDER, 3, BAL_SENDER, NULL);
    add_acc(&mb, T_R, 1, 5 * Q_UNIT, &cr);
    add_acc(&mb, T_KREV, 1, 5 * Q_UNIT, &ckrev);
    finalize(&mb);

    run_t r;
    evm_tx_t tx;
    evm_tx_result_t res;
    changes_t cs;
    run_open(&r, &mb);
    make_tx(&tx, sender, 3, rr, 0, NULL, 0);
    expect(apply(&r, &tx, &res) == 0 && res.status == EVM_EXEC_SUCCESS,
           "tx SUCCESS");
    expect(res.n_tickets == 1, "the reverted frame's ticket is gone");
    if (res.n_tickets == 1)
        ticket_expect(&res.tickets[0], TICKET_ID_SEQ0, 2 * Q_UNIT,
                      "surviving ticket takes seq 0");
    collect(r.st, &cs);
    expect(post_slot_is(&cs, rr, 0, 0) && post_slot_is(&cs, rr, 1, 1),
           "KREV call 0, own ticket call 1");
    expect(post_balance_is(&mb, &cs, krev, 5 * Q_UNIT), "KREV balance intact");
    expect(post_balance_is(&mb, &cs, rr, 3 * Q_UNIT), "R debited 2q");
    evm_tx_result_free(&res);
    run_close(&r);
    evm_membackend_free(&mb);
    check_end();
}

/* ── n8: evm_tx_prevalidate ─────────────────────────────────────────── */

static void n8(void)
{
    check_begin("n8_prevalidate");
    uint8_t sender[32], to[32];
    addr_of(T_SENDER, sender);
    addr_of(0xB1, to);
    evm_membackend mb;
    evm_membackend_init(&mb);
    add_acc(&mb, T_SENDER, 3, BAL_SENDER, NULL);
    finalize(&mb);

    evm_tx_t tx;
    evm_tx_result_t res;
    changes_t after_pre, fresh;
    run_t r;

    /* valid: prevalidate leaves nothing; apply behaves as on a fresh state */
    make_tx(&tx, sender, 3, to, 5, NULL, 0);
    run_open(&r, &mb);
    expect(evm_tx_prevalidate(r.st, &r.env, &tx, &res) == 0, "valid: 0");
    evm_tx_result_free(&res);
    collect(r.st, &after_pre);
    expect(after_pre.na == 0 && after_pre.ns == 0, "valid: change set empty");
    r.bud.account_calls = 0;
    expect(apply(&r, &tx, &res) == 0 && res.status == EVM_EXEC_SUCCESS,
           "apply after prevalidate");
    unsigned calls_after_pre = r.bud.account_calls;
    evm_tx_result_free(&res);
    collect(r.st, &after_pre);
    run_close(&r);
    run_open(&r, &mb);
    expect(apply(&r, &tx, &res) == 0 && res.status == EVM_EXEC_SUCCESS,
           "apply on a fresh state");
    unsigned calls_fresh = r.bud.account_calls;
    evm_tx_result_free(&res);
    collect(r.st, &fresh);
    run_close(&r);
    expect(calls_after_pre == calls_fresh,
           "prevalidate filled no cache (same backend reads)");
    expect(changes_equal(&after_pre, &fresh), "same change set");

    /* refusals agree */
    static const struct { uint64_t nonce, value, gas; evm_tx_error_t err; }
        bad[] = {
            { 4, 5, TX_GAS, EVM_TXERR_NONCE_TOO_HIGH },
            { 3, BAL_SENDER + 1, TX_GAS, EVM_TXERR_INSUFFICIENT_FUNDS },
            { 3, 5, 20000, EVM_TXERR_INTRINSIC_GAS },
        };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        changes_t c1;
        make_tx(&tx, sender, bad[i].nonce, to, bad[i].value, NULL, 0);
        tx.gas_limit = bad[i].gas;
        run_open(&r, &mb);
        int rp = evm_tx_prevalidate(r.st, &r.env, &tx, &res);
        evm_tx_error_t ep = res.tx_error;
        evm_tx_result_free(&res);
        int ra = apply(&r, &tx, &res);
        evm_tx_error_t ea = res.tx_error;
        evm_tx_result_free(&res);
        collect(r.st, &c1);
        run_close(&r);
        expect(rp == -1 && ra == -1 && ep == bad[i].err && ea == bad[i].err,
               "refusal: prevalidate and apply agree");
        expect(c1.na == 0 && c1.ns == 0, "refusal: change set empty");
    }

    /* BUDGET on the sender read */
    make_tx(&tx, sender, 3, to, 5, NULL, 0);
    run_open(&r, &mb);
    r.bud.budget_account_at = 1;
    expect(evm_tx_prevalidate(r.st, &r.env, &tx, &res) == EVM_BUDGET,
           "BUDGET: prevalidate -3");
    evm_tx_result_free(&res);
    collect(r.st, &after_pre);
    expect(after_pre.na == 0 && after_pre.ns == 0, "BUDGET: change set empty");
    run_close(&r);

    evm_membackend_free(&mb);
    check_end();
}

/* ── n9: configuration validation ───────────────────────────────────── */

static void n9(void)
{
    check_begin("n9_config_validation");
    evm_membackend mb;
    evm_membackend_init(&mb);
    finalize(&mb);
    evm_backend_t be;
    evm_membackend_bind(&mb, &be);
    evm_config_t cfg;
    evm_state_t *st;

    make_cfg(&cfg);
    st = evm_state_new(&cfg, &be);
    expect(st != NULL, "valid Nodus config accepted");
    evm_state_free(st);

    make_cfg(&cfg);
    cfg.nodus_profile = 2;
    expect(evm_state_new(&cfg, &be) == NULL, "nodus_profile 2 refused");

    make_cfg(&cfg);
    memset(cfg.ticket_addr.b, 0, 32);
    cfg.ticket_addr.b[31] = 0x01;
    expect(evm_state_new(&cfg, &be) == NULL, "precompile ticket address refused");

    make_cfg(&cfg);
    evm_u256_zero(&cfg.ticket_unit);
    expect(evm_state_new(&cfg, &be) == NULL, "zero ticket unit refused");

    evm_membackend_free(&mb);
    check_end();
}

/* ── n10: ticket CALL price independent of the ticket address's liveness ─
 *
 * Contract K (balance 5q): memory[0..64) = dest, then
 *   GAS                        g1 (GAS charged its 2 before reading)
 *   PUSH1 64, PUSH1 0, PUSH1 64, PUSH1 0, PUSH32 value, PUSH32 target,
 *   GAS, CALL                  (a_call)
 *   GAS                        g2
 *   SWAP1, PUSH1 1, SSTORE     slot 1 = CALL result
 *   SWAP1, SUB, PUSH1 0, SSTORE  slot 0 = g1 - g2
 * so slot 0 = 6 * VERY_LOW (18) + BASE (2, the GAS inside a_call)
 *           + the CALL's net cost + BASE (2, GAS #2)
 *           = 22 + the CALL's net cost.
 * Memory is 64 bytes before the window, so the CALL's [0,64) regions add
 * no expansion. Net cost of a CALL with value (system.py:call +
 * gas.py:calculate_message_call_gas + interpreter.py: the child's unused
 * gas, stipend included, comes back to the caller):
 *   extra (access + NEW_ACCOUNT? + CALL_VALUE) - CALL_STIPEND + gas the
 *   child consumed.
 * Ticket target (warm at tx start, evm_tx.c; the hook consumes ticket_gas):
 *   100 + 0 + 9000 - 2300 + 25000 = 31800  ->  slot 0 = 31822,
 * in BOTH pre-states: ticket address absent (dead), and present with a
 * 1-wei balance (alive: is_account_alive = not empty). Under the
 * reference rule the absent case would add NEW_ACCOUNT (25000): 56822.
 * Control — the waiver is the ticket address only: the same CALL to an
 * absent ordinary address (cold, empty code: consumes nothing)
 *   2600 + 25000 + 9000 - 2300 + 0 = 34300  ->  slot 0 = 34322. */

static void n10_run(int ticket_alive, const uint8_t target[32],
                    uint64_t *delta, uint64_t *gas_used, size_t *n_tickets,
                    int *call_ok)
{
    const uint8_t T_K = 0xC1;
    uint8_t sender[32], k[32], dest[64];
    addr_of(T_SENDER, sender);
    addr_of(T_K, k);
    dest_fill(dest);
    asm_t ck;
    memset(&ck, 0, sizeof(ck));
    a_mstore_dest(&ck, dest);
    a_byte(&ck, OP_GAS);
    a_call(&ck, OP_CALL, target, 2 * Q_UNIT, 0, 64, 0, 64);
    a_byte(&ck, OP_GAS);
    a_byte(&ck, OP_SWAP1);
    a_store(&ck, 1);
    a_byte(&ck, OP_SWAP1);
    a_byte(&ck, OP_SUB);
    a_store(&ck, 0);
    a_byte(&ck, OP_STOP);

    evm_membackend mb;
    evm_membackend_init(&mb);
    add_acc(&mb, T_SENDER, 3, BAL_SENDER, NULL);
    add_acc(&mb, T_K, 1, 5 * Q_UNIT, &ck);
    if (ticket_alive) add_acc(&mb, TICKET_TAG, 0, 1, NULL);
    finalize(&mb);

    run_t r;
    evm_tx_t tx;
    evm_tx_result_t res;
    changes_t cs;
    run_open(&r, &mb);
    make_tx(&tx, sender, 3, k, 0, NULL, 0);
    expect(apply(&r, &tx, &res) == 0 && res.status == EVM_EXEC_SUCCESS,
           "tx SUCCESS");
    collect(r.st, &cs);
    *delta = post_slot_u64(&cs, k, 0);
    *call_ok = post_slot_is(&cs, k, 1, 1);
    *gas_used = res.gas_used;
    *n_tickets = res.n_tickets;
    evm_tx_result_free(&res);
    run_close(&r);
    evm_membackend_free(&mb);
}

static void n10(void)
{
    check_begin("n10_ticket_call_price_ignores_liveness");
    uint8_t tk[32], other[32];
    addr_of(TICKET_TAG, tk);
    addr_of(0x77, other);
    uint64_t d_dead, d_alive, d_other, g_dead, g_alive, g_other;
    size_t n_dead, n_alive, n_other;
    int ok_dead, ok_alive, ok_other;

    n10_run(0, tk, &d_dead, &g_dead, &n_dead, &ok_dead);
    n10_run(1, tk, &d_alive, &g_alive, &n_alive, &ok_alive);
    n10_run(0, other, &d_other, &g_other, &n_other, &ok_other);

    expect(ok_dead && n_dead == 1, "dead ticket address: CALL 1, one ticket");
    expect(ok_alive && n_alive == 1, "alive ticket address: CALL 1, one ticket");
    expect(d_dead == 31822, "dead ticket address: window = 22 + 31800");
    expect(d_alive == 31822, "alive ticket address: window = 22 + 31800");
    expect(d_dead == d_alive, "window identical, alive or not");
    expect(g_dead == g_alive, "tx gas_used identical, alive or not");
    expect(ok_other && n_other == 0 && d_other == 34322,
           "control: absent ordinary address keeps NEW_ACCOUNT (22 + 34300)");
    check_end();
}

int main(void)
{
    n1();
    n2();
    n3();
    n4();
    n5();
    n6();
    n7();
    n8();
    n9();
    n10();
    if (g_fail_checks) {
        fprintf(stderr, "test_nodus_profile: %u check(s) FAILED\n",
                g_fail_checks);
        return 1;
    }
    fprintf(stderr, "test_nodus_profile: all 10 checks passed\n");
    return 0;
}
