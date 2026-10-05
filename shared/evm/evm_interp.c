/**
 * @file evm_interp.c
 * @brief Iterative EVM interpreter (Nodus EVM phase 1, Prague).
 *
 * Port of execution-specs@a87891f7 src/ethereum/forks/prague/vm/
 * (interpreter.py, gas.py, memory.py, stack.py, runtime.py,
 * eoa_delegation.py, instructions/<group>.py) and utils/address.py.
 *
 * DEVIATION (control flow, design G4): the reference recurses —
 * generic_call/generic_create call process_message/process_create_message,
 * which run the child's opcode loop on the Python stack. Here every message
 * is a heap-allocated frame on an explicit frame stack. An opcode that
 * starts a child sets up the child exactly as process_message /
 * process_create_message do, pushes it and suspends the parent; when the
 * child ends, finish_frame() runs the tail of process_message /
 * process_create_message for the child and then the tail of
 * generic_call / generic_create for the parent. Native stack use does not
 * depend on call depth.
 *
 * Address width (design §2): one code path, cfg.addr_bytes is a parameter
 * (evm_addr_from_word, evm_compute_contract_address, create2_address).
 *
 * Gas arithmetic: every cost derived from a stack word saturates at
 * EVM_GAS_SAT (UINT64_MAX). INVARIANT: a frame's gas_left is always
 * < EVM_GAS_SAT — the top frame receives tx.gas - intrinsic.regular <=
 * UINT64_MAX - 21000 (TX_BASE is part of every intrinsic cost), a child
 * never receives more than its parent held before the charge (63/64 rule,
 * and the 2300 stipend is only given when the parent was charged
 * CALL_VALUE = 9000 on top of the forwarded gas), and a parent only gets
 * back what its child did not use. Hence charging a saturated cost always
 * fails with OutOfGasError, exactly as the reference's unbounded integers
 * would.
 */
#include <stdlib.h>
#include <string.h>
#include <gmp.h>

#include "evm_internal.h"
#include "evm_gas.h"
#include "crypto/hash/keccak256.h"

/* ── frames ─────────────────────────────────────────────────────────── */

enum { PEND_NONE = 0, PEND_CALL, PEND_CREATE };

typedef struct frame {
    /* Message (prague/vm/__init__.py Message) */
    evm_addr caller;
    evm_addr target;                 /* current_target                    */
    evm_addr code_address;
    int      is_create;
    evm_u256 value;
    const uint8_t *data;  size_t data_len;
    const uint8_t *code;  size_t code_len;
    /* `data` of a CALL child is a READ-ONLY view into the suspended
     * parent's memory (red-team fix 2), never owned by the frame. */
    uint8_t *code_owned;
    uint32_t depth;
    int      is_static;
    int      should_transfer;
    int      disable_precompiles;
    /* Evm (prague/vm/__init__.py Evm) */
    uint64_t pc;
    evm_u256 *stack;
    size_t   sp, scap;
    uint8_t *mem;
    size_t   mem_len;                /* always a multiple of 32           */
    uint64_t gas;
    const uint8_t *jd;               /* valid_jump_destinations bitmap    */
    uint8_t *jd_owned;               /* set when not from the state cache */
    int      has_code_hash;          /* code came from an account          */
    evm_bytes32 code_hash;
    int64_t  refund;
    uint8_t *out;   size_t out_len;  /* evm.output                        */
    uint8_t *ret;   size_t ret_len;  /* evm.return_data                   */
    int      done;
    evm_exec_status_t status;        /* SUCCESS = no error                */
    size_t   mark;                   /* journal snapshot                  */
    /* suspended CALL*/
    int      pend;
    uint64_t pend_out_off;
    uint64_t pend_out_size;
} frame;

typedef struct {
    evm_state_t   *st;
    evm_tx_env_t  *txenv;
    frame        **fs;
    size_t         n, cap;
} ctx_t;

static void frame_free(frame *f)
{
    if (!f) return;
    free(f->stack);
    free(f->mem);
    free(f->jd_owned);
    free(f->out);
    free(f->ret);
    free(f->code_owned);
    free(f);
}

/* ── word / address helpers ─────────────────────────────────────────── */

/* Uint(word) clamped: values >= 2^64 become EVM_GAS_SAT. */
static uint64_t sat64(const evm_u256 *v)
{
    uint64_t x;
    return evm_u256_to_u64(v, &x) ? x : EVM_GAS_SAT;
}

static void word_from_u64(evm_u256 *r, uint64_t v) { evm_u256_from_u64(r, v); }

static void key_from_word(evm_bytes32 *k, const evm_u256 *w)
{
    evm_u256_to_be(k->b, w);
}

/* RLP of a byte string (len <= 55) or of a uint64 scalar; enough for
 * rlp.encode([address, nonce]) (ethereum_rlp, scalar = minimal big-endian
 * bytes, 0 -> empty string). */
static size_t rlp_u64(uint8_t *out, uint64_t v)
{
    if (v == 0) {
        out[0] = 0x80;
        return 1;
    }
    if (v < 0x80) {
        out[0] = (uint8_t)v;
        return 1;
    }
    uint8_t tmp[8];
    size_t n = 0;
    while (v) {
        tmp[n++] = (uint8_t)(v & 0xff);
        v >>= 8;
    }
    out[0] = (uint8_t)(0x80 + n);
    for (size_t i = 0; i < n; i++)
        out[1 + i] = tmp[n - 1 - i];
    return 1 + n;
}

/* execution-specs@a87891f7 prague/utils/address.py:compute_contract_address
 * Width-parametric (design §2): the sender is encoded with addr_bytes bytes;
 * 20-byte mode keeps hash[12:32] (right-aligned), 32-byte mode keeps the
 * whole hash. */
int evm_compute_contract_address(const evm_state_t *st, const evm_addr *sender,
                                 uint64_t nonce, evm_addr *out)
{
    uint8_t buf[64];
    size_t L = st->cfg.addr_bytes;
    size_t p = 1;
    buf[p++] = (uint8_t)(0x80 + L);
    memcpy(buf + p, sender->b + (32 - L), L);
    p += L;
    p += rlp_u64(buf + p, nonce);
    buf[0] = (uint8_t)(0xc0 + (p - 1));      /* payload < 56 bytes */
    uint8_t h[32];
    if (keccak256(buf, p, h) != 0) return EVM_FAULT;
    memcpy(out->b, h, 32);
    if (L == 20) memset(out->b, 0, 12);
    return 0;
}

/* execution-specs@a87891f7 prague/utils/address.py:
 * compute_create2_contract_address (width-parametric, design §2). */
static int create2_address(const evm_state_t *st, const evm_addr *sender,
                           const evm_bytes32 *salt, const uint8_t *code,
                           size_t len, evm_addr *out)
{
    uint8_t buf[1 + 32 + 32 + 32];
    size_t L = st->cfg.addr_bytes;
    size_t p = 0;
    buf[p++] = 0xff;
    memcpy(buf + p, sender->b + (32 - L), L);
    p += L;
    memcpy(buf + p, salt->b, 32);
    p += 32;
    if (evm_keccak(code, len, buf + p) != 0) return EVM_FAULT;
    p += 32;
    uint8_t h[32];
    if (keccak256(buf, p, h) != 0) return EVM_FAULT;
    memcpy(out->b, h, 32);
    if (L == 20) memset(out->b, 0, 12);
    return 0;
}

/* ── EIP-7702 designator (prague/vm/eoa_delegation.py) ──────────────── */

/* is_valid_delegation + get_delegated_code_address. The designator carries
 * a 20-byte address; it is right-aligned into the 32-byte form in both
 * widths (design §2 does not define a 32-byte designator; EIP-3541 forbids
 * deploying 0xEF code, so it can only come from the pre-state). */
static int get_delegated(const uint8_t *code, size_t len, evm_addr *out)
{
    if (len != EVM_DELEGATED_CODE_LENGTH) return 0;
    if (code[0] != 0xef || code[1] != 0x01 || code[2] != 0x00) return 0;
    memset(out->b, 0, 12);
    memcpy(out->b + 12, code + EVM_DELEGATION_MARKER_LEN, 20);
    return 1;
}

/* ── memory gas (prague/vm/gas.py) ──────────────────────────────────── */

/* execution-specs@a87891f7 prague/vm/gas.py:calculate_memory_gas_cost
 * (size_in_bytes is a multiple of 32 here). Saturating. */
static uint64_t memory_gas_cost(uint64_t size_in_bytes)
{
    uint64_t words = evm_words(size_in_bytes);
    uint64_t linear = evm_gas_mul(words, EVM_G_MEMORY_PER_WORD);
    uint64_t hi, lo;
    evm_mul64(words, words, &hi, &lo);
    if (hi >> 9) return EVM_GAS_SAT;          /* words^2 / 512 >= 2^64 */
    uint64_t quad = (hi << 55) | (lo >> 9);
    return evm_gas_add(linear, quad);
}

typedef struct {
    const evm_u256 *start;
    const evm_u256 *size;
} mem_region;

/* execution-specs@a87891f7 prague/vm/gas.py:calculate_gas_extend_memory
 * *cost saturates; *new_len is meaningful only when *cost < EVM_GAS_SAT. */
static void extend_memory(uint64_t cur_len, const mem_region *r, size_t n,
                          uint64_t *cost, uint64_t *new_len)
{
    uint64_t to_be_paid = 0;
    uint64_t current = cur_len;
    for (size_t i = 0; i < n; i++) {
        if (evm_u256_is_zero(r[i].size)) continue;
        uint64_t s, z;
        if (!evm_u256_to_u64(r[i].start, &s) ||
            !evm_u256_to_u64(r[i].size, &z) ||
            s > UINT64_MAX - z || s + z > UINT64_MAX - 31) {
            *cost = EVM_GAS_SAT;
            *new_len = current;
            return;
        }
        uint64_t before = evm_words(current) * 32u;
        uint64_t after = evm_words(s + z) * 32u;
        if (after <= before) continue;
        uint64_t total = memory_gas_cost(after);
        if (total == EVM_GAS_SAT) {
            *cost = EVM_GAS_SAT;
            *new_len = current;
            return;
        }
        to_be_paid = evm_gas_add(to_be_paid, total - memory_gas_cost(before));
        current = after;
    }
    *cost = to_be_paid;
    *new_len = current;
}

/* `evm.memory += b"\x00" * expand_by` — only after the charge succeeded
 * (design §4 D4). Allocation failure at a gas-paid size is a node fault. */
static int mem_resize(frame *f, uint64_t new_len)
{
    if (new_len <= f->mem_len) return 0;
    if (new_len > SIZE_MAX) return EVM_FAULT;
    uint8_t *p = realloc(f->mem, (size_t)new_len);
    if (!p) return EVM_FAULT;
    memset(p + f->mem_len, 0, (size_t)new_len - f->mem_len);
    f->mem = p;
    f->mem_len = (size_t)new_len;
    return 0;
}

/* copy-style word cost: ceil32(size)//32 * per_word, saturating */
static uint64_t copy_cost(const evm_u256 *size, uint64_t per_word)
{
    uint64_t z;
    if (!evm_u256_to_u64(size, &z)) return EVM_GAS_SAT;
    return evm_gas_mul(evm_words(z), per_word);
}

/* execution-specs@a87891f7 prague/vm/memory.py:buffer_read into dst:
 * buffer[start:start+size] right-padded with zeros to `size`. */
static void buffer_read(uint8_t *dst, const uint8_t *buf, size_t buf_len,
                        const evm_u256 *start, size_t size)
{
    uint64_t s;
    if (size == 0) return;
    if (!evm_u256_to_u64(start, &s) || s >= buf_len) {
        memset(dst, 0, size);
        return;
    }
    size_t avail = buf_len - (size_t)s;
    size_t n = avail < size ? avail : size;
    memcpy(dst, buf + s, n);
    if (n < size) memset(dst + n, 0, size - n);
}

/* ── stack (prague/vm/stack.py) ─────────────────────────────────────── */

static int stack_reserve(frame *f)
{
    if (f->sp < f->scap) return 0;
    size_t nc = f->scap ? f->scap * 2 : 32;
    if (nc > EVM_L_STACK_ITEMS) nc = EVM_L_STACK_ITEMS;
    /* nc <= 1024: nc * 32 bytes cannot overflow size_t */
    evm_u256 *p = realloc(f->stack, nc * sizeof(*p));
    if (!p) return EVM_FAULT;
    f->stack = p;
    f->scap = nc;
    return 0;
}

/* ── frame end ──────────────────────────────────────────────────────── */

/* ExceptionalHalt: gas_left = 0, output = b"", error set. */
static void halt(frame *f, evm_exec_status_t s)
{
    f->gas = 0;
    free(f->out);
    f->out = NULL;
    f->out_len = 0;
    f->status = s;
    f->done = 1;
}

static void set_ret(frame *f, uint8_t *data, size_t len)
{
    free(f->ret);
    f->ret = data;
    f->ret_len = len;
}

/* ── jump destinations (prague/vm/runtime.py:get_valid_jump_destinations) */

static int is_defined_op(uint8_t op);

static uint8_t *compute_jumpdests(const uint8_t *code, size_t n)
{
    uint8_t *jd = calloc((n + 7) / 8, 1);
    if (!jd) return NULL;
    size_t pc = 0;
    while (pc < n) {
        uint8_t op = code[pc];
        if (!is_defined_op(op)) {
            pc += 1;
            continue;
        }
        if (op == 0x5b) {
            jd[pc / 8] |= (uint8_t)(1u << (pc % 8));
        } else if (op >= 0x60 && op <= 0x7f) {
            pc += (size_t)(op - 0x60 + 1);
        }
        pc += 1;
    }
    return jd;
}

/* Code read from an account is analysed once per code hash for the life of
 * the state (red-team fix 3; the cache never changes a result — a miss
 * recomputes the same bitmap). Init code of a CREATE frame has no account
 * and is analysed per frame (its size is gas-paid, EIP-3860). */
static int analyze_jumpdests(evm_state_t *st, frame *f)
{
    size_t n = f->code_len;
    if (n == 0) return 0;
    if (f->has_code_hash) {
        const evm_jd_rec *r = evm_st_jd_find(st, &f->code_hash);
        if (!r) {
            uint8_t *bm = compute_jumpdests(f->code, n);
            if (!bm) return EVM_FAULT;
            if (evm_st_jd_store(st, &f->code_hash, n, bm, &r) != 0)
                return EVM_FAULT;
        }
        if (r->code_len != n) return EVM_FAULT;   /* hash/code mismatch */
        f->jd = r->bitmap;
        return 0;
    }
    f->jd_owned = compute_jumpdests(f->code, n);
    if (!f->jd_owned) return EVM_FAULT;
    f->jd = f->jd_owned;
    return 0;
}

static int valid_jump(const frame *f, const evm_u256 *dest, uint64_t *out)
{
    uint64_t d;
    if (!evm_u256_to_u64(dest, &d) || d >= f->code_len) return 0;
    if (!(f->jd[d / 8] & (1u << (d % 8)))) return 0;
    *out = d;
    return 1;
}

/* ── BLOBBASEFEE (prague/vm/gas.py:calculate_blob_gas_price →
 *    ethereum/utils/numeric.py:taylor_exponential) ─────────────────── */

static int blob_base_fee(evm_tx_env_t *te, evm_u256 *out)
{
    if (te->blob_fee_fault) return EVM_FAULT;
    if (te->blob_fee_done) {
        *out = te->blob_fee;
        return 0;
    }
    mpz_t factor, num, den, i, output, acc, t, limit;
    mpz_inits(factor, num, den, i, output, acc, t, limit, NULL);
    mpz_set_ui(factor, EVM_G_BLOB_MIN_GASPRICE);
    mpz_set_ui(den, EVM_G_BLOB_BASE_FEE_UPDATE_FRACTION);
    {
        /* numerator = Uint(excess_blob_gas) (uint64) */
        uint64_t x = te->env->excess_blob_gas;
        mpz_set_ui(num, (unsigned long)(x >> 32));
        mpz_mul_2exp(num, num, 32);
        mpz_add_ui(num, num, (unsigned long)(x & 0xffffffffu));
    }
    mpz_set_ui(i, 1);
    mpz_set_ui(output, 0);
    mpz_mul(acc, factor, den);
    /* The function returns output // denominator (numeric.py:214); that
     * quotient must fit U256, i.e. output < denominator * 2^256. */
    mpz_set(limit, den);
    mpz_mul_2exp(limit, limit, 256);
    int rc = 0;
    while (mpz_sgn(acc) > 0) {
        mpz_add(output, output, acc);
        /* U256(blob_base_fee) raises when the value does not fit; the sum
         * only grows, so stop as soon as output // denominator reaches
         * 2^256 (also bounds the loop for any excess_blob_gas). */
        if (mpz_cmp(output, limit) >= 0) {
            rc = EVM_FAULT;
            break;
        }
        mpz_mul(acc, acc, num);
        mpz_mul(t, den, i);
        mpz_fdiv_q(acc, acc, t);
        mpz_add_ui(i, i, 1);
    }
    /* `return output // denominator` (ethereum/utils/numeric.py:214) —
     * excess_blob_gas = 0 gives factor * den // den = 1. */
    if (rc == 0) mpz_fdiv_q(output, output, den);
    if (rc == 0) {
        uint8_t be[32];
        size_t cnt = 0;
        memset(be, 0, sizeof(be));
        uint8_t tmp[32];
        mpz_export(tmp, &cnt, 1, 1, 1, 0, output);
        if (cnt > 32) rc = EVM_FAULT;
        else {
            memcpy(be + (32 - cnt), tmp, cnt);
            evm_u256_from_be(&te->blob_fee, be);
            te->blob_fee_done = 1;
            *out = te->blob_fee;
        }
    }
    if (rc != 0) te->blob_fee_fault = 1;
    mpz_clears(factor, num, den, i, output, acc, t, limit, NULL);
    return rc;
}

/* ── frame setup ────────────────────────────────────────────────────── */

static int push_frame(ctx_t *c, frame *f)
{
    if (c->n == c->cap) {
        void *p = c->fs;
        if (evm_grow(&p, &c->cap, sizeof(*c->fs), 16) != 0) return EVM_FAULT;
        c->fs = p;
    }
    c->fs[c->n++] = f;
    return 0;
}

/* The ticket system address as a frame (chain integration design §5;
 * Nodus profile only, evm.h ticket_addr). Shaped like a precompile: it
 * runs in the called frame, charges cfg.ticket_gas from that frame's gas,
 * and any refusal is an exceptional halt of that frame (its gas is
 * consumed; its journal — so the debit and the ticket — is reverted by
 * finish_frame). The value transfer of process_message is REPLACED: the
 * caller is debited and nobody is credited (the value leaves wei_live
 * for wei_tickets).
 *   - shape: only a CALL reaches here with target == ticket_addr and
 *     should_transfer && !is_static (CALLCODE / DELEGATECALL keep the
 *     caller as target; STATICCALL is static and carries no value);
 *   - value > 0 and value % ticket_unit == 0; calldata exactly 64 bytes
 *     (the destination fingerprint);
 *   - the caller holds the value (op_call_family does not short-circuit a
 *     CALL into this address, so an underfunded call halts here).
 * Success: the 64-byte ticket_id is the frame's output. */
static int ticket_frame(ctx_t *c, frame *f)
{
    evm_state_t *st = c->st;
    evm_u256 rem;
    evm_u256_mod(&rem, &f->value, &st->cfg.ticket_unit);
    if (memcmp(f->target.b, st->cfg.ticket_addr.b, 32) != 0 ||
        !f->should_transfer || f->is_static ||
        evm_u256_is_zero(&f->value) || !evm_u256_is_zero(&rem) ||
        f->data_len != 64) {
        halt(f, EVM_EXEC_PRECOMPILE_FAILURE);
        return 0;
    }
    if (f->gas < st->cfg.ticket_gas) {
        halt(f, EVM_EXEC_OUT_OF_GAS);
        return 0;
    }
    evm_acct_t from;
    EVM_CHECK(evm_st_get_account(st, &f->caller, &from));
    if (evm_u256_cmp(&from.balance, &f->value) < 0) {
        halt(f, EVM_EXEC_PRECOMPILE_FAILURE);
        return 0;
    }
    f->gas -= st->cfg.ticket_gas;
    evm_u256 left;
    evm_u256_sub(&left, &from.balance, &f->value);
    EVM_CHECK(evm_st_set_balance(st, &f->caller, &left));
    EVM_CHECK(evm_st_add_ticket(st, c->txenv->intent_id, &f->value, f->data));
    f->out = malloc(64);
    if (!f->out) return EVM_FAULT;
    memcpy(f->out, st->tickets[st->ntickets - 1].ticket_id, 64);
    f->out_len = 64;
    f->done = 1;
    return 0;
}

/* Body of execution-specs@a87891f7 prague/vm/interpreter.py:process_message
 * up to the opcode loop: snapshot (unless the caller already took it for a
 * create), value transfer, precompile dispatch. */
static int start_message(ctx_t *c, frame *f, int take_mark)
{
    evm_state_t *st = c->st;
    if (f->depth > EVM_L_STACK_DEPTH_LIMIT) {
        /* StackDepthLimitError — unreachable: callers check depth first */
        halt(f, EVM_EXEC_OUT_OF_GAS);
        return 0;
    }
    if (analyze_jumpdests(st, f) != 0) return EVM_FAULT;
    if (take_mark) f->mark = evm_st_mark(st);
    /* Nodus ticket system address (evm.h ticket_addr): runs INSTEAD of the
     * value transfer — the value never reaches its account. A delegated
     * call (EIP-7702 designator naming it, disable_precompiles) falls
     * through as an ordinary code-less account, as a precompile does. */
    if (st->cfg.nodus_profile && !f->is_create && !f->disable_precompiles &&
        memcmp(f->code_address.b, st->cfg.ticket_addr.b, 32) == 0)
        return ticket_frame(c, f);
    if (f->should_transfer && !evm_u256_is_zero(&f->value))
        EVM_CHECK(evm_st_move_ether(st, &f->caller, &f->target, &f->value));
    /* `code_address in PRE_COMPILED_CONTRACTS` — the set is configuration
     * (evm_config_t.precompile_mask, red-team fix 7): with its bit clear
     * the address is an ordinary account and its code runs. */
    if (!f->is_create && evm_precompile_enabled(st, &f->code_address)) {
        if (!f->disable_precompiles) {
            evm_pc_result_t res;
            uint8_t *out = NULL;
            size_t out_len = 0;
            if (evm_precompile_run(&f->code_address, f->data, f->data_len,
                                   &f->gas, &res, &out, &out_len) != 0)
                return EVM_FAULT;
            switch (res) {
            case EVM_PC_OK:
                f->out = out;
                f->out_len = out_len;
                f->done = 1;
                break;
            case EVM_PC_OOG:
                free(out);
                halt(f, EVM_EXEC_OUT_OF_GAS);
                break;
            case EVM_PC_INVALID:
                free(out);
                halt(f, EVM_EXEC_PRECOMPILE_FAILURE);
                break;
            default:
                /* every precompile is built in; a library that cannot
                 * initialise already returned -2 above */
                free(out);
                return EVM_FAULT;
            }
        } else {
            f->done = 1;   /* delegated to a precompile: nothing runs */
        }
    }
    return 0;
}

/* execution-specs@a87891f7 prague/vm/interpreter.py:process_create_message
 * (head): snapshot, destroy_storage, mark_account_created, increment_nonce,
 * then process_message. */
static int start_create(ctx_t *c, frame *f)
{
    evm_state_t *st = c->st;
    f->mark = evm_st_mark(st);
    if (evm_st_destroy_storage(st, &f->target) != 0) return EVM_FAULT;
    if (evm_st_mark_account_created(st, &f->target) != 0) return EVM_FAULT;
    EVM_CHECK(evm_st_increment_nonce(st, &f->target));
    /* process_message's own snapshot is subsumed: on any error of a create
     * frame the reference restores the earlier create snapshot. */
    return start_message(c, f, 0);
}

/* ── frame end: tails of process_message / process_create_message and of
 *    generic_call / generic_create ─────────────────────────────────── */

static int finish_frame(ctx_t *c, frame *f, evm_call_output_t *top_out)
{
    evm_state_t *st = c->st;

    /* process_message: `if evm.error: restore_tx_state(snapshot)` */
    if (f->status != EVM_EXEC_SUCCESS)
        evm_st_revert(st, f->mark);

    if (f->is_create && f->status == EVM_EXEC_SUCCESS) {
        /* execution-specs@a87891f7 prague/vm/interpreter.py:
         * process_create_message (tail) */
        evm_exec_status_t err = EVM_EXEC_SUCCESS;
        if (f->out_len > 0 && f->out[0] == 0xEF) {
            err = EVM_EXEC_INVALID_CODE_PREFIX;
        } else {
            uint64_t cost = evm_gas_mul((uint64_t)f->out_len,
                                        EVM_G_CODE_DEPOSIT_PER_BYTE);
            if (f->gas < cost)
                err = EVM_EXEC_OUT_OF_GAS;
            else {
                f->gas -= cost;
                /* reference raises OutOfGasError; labelled CODE_TOO_LARGE
                 * here (identical effects: halt, gas 0, revert) */
                if (f->out_len > EVM_L_MAX_CODE_SIZE)
                    err = EVM_EXEC_CODE_TOO_LARGE;
            }
        }
        if (err != EVM_EXEC_SUCCESS) {
            evm_st_revert(st, f->mark);
            halt(f, err);
        } else {
            EVM_CHECK(evm_st_set_code(st, &f->target, f->out, f->out_len));
        }
    }

    /* pop */
    c->n--;
    if (c->n == 0) {
        top_out->gas_left = f->gas;
        top_out->status = f->status;
        top_out->refund_counter = (f->status == EVM_EXEC_SUCCESS) ? f->refund : 0;
        top_out->output = f->out;
        top_out->output_len = f->out_len;
        f->out = NULL;
        frame_free(f);
        return 0;
    }
    frame *p = c->fs[c->n - 1];
    /* incorporate_child_on_error / incorporate_child_on_success */
    p->gas += f->gas;
    int ok = (f->status == EVM_EXEC_SUCCESS);
    if (ok) p->refund += f->refund;   /* logs, accounts_to_delete and the
                                       * accessed sets stay in the journal */
    evm_u256 w;
    if (p->pend == PEND_CREATE) {
        if (ok) {
            set_ret(p, NULL, 0);
            evm_addr_to_word(&f->target, &w);
        } else {
            set_ret(p, f->out, f->out_len);
            f->out = NULL;
            evm_u256_zero(&w);
        }
    } else {
        set_ret(p, f->out, f->out_len);
        f->out = NULL;
        word_from_u64(&w, ok ? 1 : 0);
        /* memory_write(output_start, child_output[:min(size, len)]) */
        size_t n = p->ret_len;
        if (p->pend_out_size < n) n = (size_t)p->pend_out_size;
        if (n > 0) {
            /* region was paid for and allocated before the call */
            if (p->pend_out_off > p->mem_len || n > p->mem_len - p->pend_out_off)
                return EVM_FAULT;
            memcpy(p->mem + p->pend_out_off, p->ret, n);
        }
    }
    p->stack[p->sp++] = w;            /* >= 3 items were popped: no overflow */
    p->pend = PEND_NONE;
    p->pc += 1;
    frame_free(f);
    return 0;
}

/* ── CALL* / CREATE* (prague/vm/instructions/system.py) ─────────────── */

/* execution-specs@a87891f7 prague/vm/gas.py:calculate_message_call_gas */
static void message_call_gas(const evm_u256 *value, uint64_t gas,
                             uint64_t gas_left, uint64_t memory_cost,
                             uint64_t extra_gas, uint64_t *cost,
                             uint64_t *sub_call)
{
    uint64_t stipend = evm_u256_is_zero(value) ? 0 : EVM_G_CALL_STIPEND;
    if (gas_left < evm_gas_add(extra_gas, memory_cost)) {
        *cost = evm_gas_add(gas, extra_gas);
        *sub_call = evm_gas_add(gas, stipend);
        return;
    }
    uint64_t avail = gas_left - memory_cost - extra_gas;
    uint64_t maxg = avail - avail / 64;       /* max_message_call_gas */
    if (gas > maxg) gas = maxg;
    *cost = evm_gas_add(gas, extra_gas);
    *sub_call = evm_gas_add(gas, stipend);
}

/* execution-specs@a87891f7 prague/vm/eoa_delegation.py:access_delegation */
static int access_delegation(ctx_t *c, const evm_addr *address,
                             int *disable, evm_addr *code_address,
                             const uint8_t **code, size_t *code_len,
                             evm_bytes32 *code_hash, uint64_t *gas_cost)
{
    evm_state_t *st = c->st;
    evm_acct_t acct;
    EVM_CHECK(evm_st_get_account(st, address, &acct));
    EVM_CHECK(evm_st_get_code(st, address, &acct, code, code_len));
    *code_hash = acct.code_hash;
    evm_addr del;
    if (!get_delegated(*code, *code_len, &del)) {
        *disable = 0;
        *code_address = *address;
        *gas_cost = 0;
        return 0;
    }
    int warm;
    if (evm_st_access_addr(st, &del, &warm) != 0) return EVM_FAULT;
    *gas_cost = warm ? EVM_G_WARM_ACCESS : EVM_G_COLD_ACCOUNT_ACCESS;
    EVM_CHECK(evm_st_get_account(st, &del, &acct));
    EVM_CHECK(evm_st_get_code(st, &del, &acct, code, code_len));
    *code_hash = acct.code_hash;
    *disable = 1;
    *code_address = del;
    return 0;
}

typedef struct {
    uint64_t gas;
    evm_u256 value;
    evm_addr caller, to, code_address;
    int should_transfer, is_staticcall, disable_precompiles;
    evm_u256 in_off, in_size;
    uint64_t out_off, out_size;
    const uint8_t *code;
    size_t code_len;
    evm_bytes32 code_hash;           /* account code: jump-dest cache key */
} generic_call_t;

static frame *new_frame(void)
{
    frame *f = calloc(1, sizeof(*f));
    if (f) f->status = EVM_EXEC_SUCCESS;
    return f;
}

/* execution-specs@a87891f7 prague/vm/instructions/system.py:generic_call
 * (head; the tail is in finish_frame). The caller has already popped the
 * arguments, charged gas and extended memory. */
static int generic_call(ctx_t *c, frame *f, const generic_call_t *p)
{
    set_ret(f, NULL, 0);
    if (f->depth + 1 > EVM_L_STACK_DEPTH_LIMIT) {
        f->gas += p->gas;
        evm_u256_zero(&f->stack[f->sp++]);
        f->pc += 1;
        return 0;
    }
    frame *ch = new_frame();
    if (!ch) return EVM_FAULT;
    /* call_data = memory_read_bytes(memory, in_off, in_size)
     * DEVIATION (copy avoidance, red-team fix 2): the reference copies the
     * bytes; here the child gets a READ-ONLY view (const pointer + length)
     * of the parent's memory, which is equivalent because:
     *  - the parent is suspended until the child (and all its
     *    descendants) finished: no opcode of the parent runs, so nothing
     *    writes or reallocs f->mem while the view is alive;
     *  - the only post-child write into parent memory (the CALL output
     *    copy in finish_frame) happens after the child stopped reading;
     *  - the child only reads `data` (CALLDATALOAD/SIZE/COPY copy OUT of it
     *    into the child's own memory; precompiles take `const uint8_t *`);
     *    the field is const-qualified, so no write path compiles;
     *  - a grandchild's view points into the child's own memory, never
     *    into this one.
     * No per-byte work is done here, so the per-call cost is O(1). */
    if (!evm_u256_is_zero(&p->in_size)) {
        uint64_t off = sat64(&p->in_off), sz = sat64(&p->in_size);
        if (off > f->mem_len || sz > f->mem_len - off) {   /* paid & extended */
            frame_free(ch);
            return EVM_FAULT;
        }
        ch->data = f->mem + off;
        ch->data_len = (size_t)sz;
    }
    ch->caller = p->caller;
    ch->target = p->to;
    ch->code_address = p->code_address;
    ch->is_create = 0;
    ch->gas = p->gas;
    ch->value = p->value;
    ch->code = p->code;
    ch->code_len = p->code_len;
    ch->has_code_hash = 1;
    ch->code_hash = p->code_hash;
    ch->depth = f->depth + 1;
    ch->should_transfer = p->should_transfer;
    ch->is_static = p->is_staticcall || f->is_static;
    ch->disable_precompiles = p->disable_precompiles;
    f->pend = PEND_CALL;
    f->pend_out_off = p->out_off;
    f->pend_out_size = p->out_size;
    if (push_frame(c, ch) != 0) {
        frame_free(ch);
        return EVM_FAULT;
    }
    return start_message(c, ch, 1);
}

/* execution-specs@a87891f7 prague/vm/instructions/system.py:generic_create
 * (head). Arguments already popped, gas charged, memory extended.
 * @return 0, 1 (exceptional halt `*hs` raised), -2. */
static int generic_create(ctx_t *c, frame *f, const evm_u256 *endowment,
                          const evm_addr *contract_address,
                          const evm_u256 *mstart, const evm_u256 *msize,
                          evm_exec_status_t *hs)
{
    evm_state_t *st = c->st;
    uint64_t off = 0, sz = 0;
    if (!evm_u256_is_zero(msize)) {
        off = sat64(mstart);
        sz = sat64(msize);
        if (off > f->mem_len || sz > f->mem_len - off) return EVM_FAULT;
    }
    if (sz > EVM_L_MAX_INIT_CODE_SIZE) {
        *hs = EVM_EXEC_OUT_OF_GAS;
        return 1;
    }
    uint64_t create_gas = f->gas - f->gas / 64;
    f->gas -= create_gas;
    if (f->is_static) {
        *hs = EVM_EXEC_STATIC_VIOLATION;
        return 1;
    }
    set_ret(f, NULL, 0);

    evm_acct_t sender;
    EVM_CHECK(evm_st_get_account(st, &f->target, &sender));
    if (evm_u256_cmp(&sender.balance, endowment) < 0 ||
        sender.nonce == UINT64_MAX ||
        f->depth + 1 > EVM_L_STACK_DEPTH_LIMIT) {
        f->gas += create_gas;
        evm_u256_zero(&f->stack[f->sp++]);
        f->pc += 1;
        return 0;
    }
    int warm;
    if (evm_st_access_addr(st, contract_address, &warm) != 0) return EVM_FAULT;
    int deployable;
    EVM_CHECK(evm_st_account_deployable(st, contract_address, &deployable));
    if (!deployable) {
        EVM_CHECK(evm_st_increment_nonce(st, &f->target));
        evm_u256_zero(&f->stack[f->sp++]);
        f->pc += 1;
        return 0;
    }
    EVM_CHECK(evm_st_increment_nonce(st, &f->target));

    frame *ch = new_frame();
    if (!ch) return EVM_FAULT;
    if (sz > 0) {
        ch->code_owned = malloc((size_t)sz);
        if (!ch->code_owned) {
            frame_free(ch);
            return EVM_FAULT;
        }
        memcpy(ch->code_owned, f->mem + off, (size_t)sz);
        ch->code = ch->code_owned;
        ch->code_len = (size_t)sz;
    }
    ch->caller = f->target;
    ch->target = *contract_address;
    ch->is_create = 1;
    ch->gas = create_gas;
    ch->value = *endowment;
    ch->depth = f->depth + 1;
    ch->should_transfer = 1;
    ch->is_static = 0;
    ch->disable_precompiles = 0;
    f->pend = PEND_CREATE;
    if (push_frame(c, ch) != 0) {
        frame_free(ch);
        return EVM_FAULT;
    }
    return start_create(c, ch);
}

/* ── opcode table helpers ──────────────────────────────────────────── */

/* prague/vm/instructions/__init__.py:Ops */
static int is_defined_op(uint8_t op)
{
    if (op <= 0x0b) return 1;
    if (op >= 0x10 && op <= 0x1d) return 1;
    if (op == 0x20) return 1;
    if (op >= 0x30 && op <= 0x4a) return 1;
    if (op >= 0x50 && op <= 0xa4) return 1;
    switch (op) {
    case 0xf0: case 0xf1: case 0xf2: case 0xf3: case 0xf4: case 0xf5:
    case 0xfa: case 0xfd: case 0xff:
        return 1;
    default:
        return 0;
    }
}

#define S(i)   (f->stack[f->sp - 1 - (i)])
#define NEED(n) do { if (f->sp < (size_t)(n)) { halt(f, EVM_EXEC_STACK_UNDERFLOW); return 0; } } while (0)
#define CHARGE(c) do { uint64_t c_ = (c); if (f->gas < c_) { halt(f, EVM_EXEC_OUT_OF_GAS); return 0; } f->gas -= c_; } while (0)
#define HALT(s) do { halt(f, (s)); return 0; } while (0)
/* EVM_BUDGET passes through, any other non-zero is a fault (EVM_CHECK) */
#define FAULT_IF(x) EVM_CHECK(x)
#define PUSH_WORD(w) do { \
        if (f->sp >= EVM_L_STACK_ITEMS) { halt(f, EVM_EXEC_STACK_OVERFLOW); return 0; } \
        if (stack_reserve(f) != 0) return EVM_FAULT; \
        f->stack[f->sp++] = (w); } while (0)

/* ADD / SUB with the BINOP signature (carry/borrow ignored: EVM
 * arithmetic is modulo 2^256 — arithmetic.py wrapping_add/wrapping_sub). */
static void u256_add_w(evm_u256 *r, const evm_u256 *a, const evm_u256 *b)
{
    (void)evm_u256_add(r, a, b);
}
static void u256_sub_w(evm_u256 *r, const evm_u256 *a, const evm_u256 *b)
{
    (void)evm_u256_sub(r, a, b);
}

/* chain id as a stack word (CHAINID). */
static void chain_id_word(const evm_state_t *st, evm_u256 *w)
{
    *w = st->cfg.chain_id;          /* full 256-bit word, never truncated */
}

/* binary op: pop x (top), y; push op(x, y) */
#define BINOP(fn, cost) do { NEED(2); CHARGE(cost); \
        fn(&S(1), &S(0), &S(1)); f->sp--; f->pc++; } while (0)

static int access_cost(ctx_t *c, const evm_addr *a, uint64_t *cost)
{
    int warm;
    if (evm_st_access_addr(c->st, a, &warm) != 0) return EVM_FAULT;
    *cost = warm ? EVM_G_WARM_ACCESS : EVM_G_COLD_ACCOUNT_ACCESS;
    return 0;
}

/* CALL / CALLCODE / DELEGATECALL / STATICCALL —
 * execution-specs@a87891f7 prague/vm/instructions/system.py:call,
 * callcode, delegatecall, staticcall. */
static int op_call_family(ctx_t *c, frame *f, uint8_t op)
{
    evm_state_t *st = c->st;
    int has_value = (op == 0xf1 || op == 0xf2);
    NEED(has_value ? 7 : 6);
    evm_u256 a_gas = S(0), a_addr = S(1), value;
    evm_u256 in_off, in_size, out_off, out_size;
    if (has_value) {
        value = S(2);
        in_off = S(3); in_size = S(4); out_off = S(5); out_size = S(6);
        f->sp -= 7;
    } else {
        evm_u256_zero(&value);
        in_off = S(2); in_size = S(3); out_off = S(4); out_size = S(5);
        f->sp -= 6;
    }
    uint64_t gas = sat64(&a_gas);
    evm_addr addr;
    evm_addr_from_word(st, &a_addr, &addr);

    mem_region r[2] = { { &in_off, &in_size }, { &out_off, &out_size } };
    uint64_t mem_cost, new_len;
    extend_memory(f->mem_len, r, 2, &mem_cost, &new_len);

    uint64_t access;
    FAULT_IF(access_cost(c, &addr, &access));

    int disable;
    evm_addr code_address;
    const uint8_t *code;
    size_t code_len;
    evm_bytes32 code_hash;
    uint64_t del_cost;
    FAULT_IF(access_delegation(c, &addr, &disable, &code_address, &code,
                               &code_len, &code_hash, &del_cost));
    access = evm_gas_add(access, del_cost);

    /* Nodus profile: a CALL whose target is the ticket system address
     * (evm.h ticket_addr) is priced by the ticket hook alone (ticket_gas,
     * design §5: 25 000). DEVIATION from system.py:call (Kurultay
     * 2026-10-05 red-team 1, F12): the NEW_ACCOUNT surcharge is NOT
     * applied to that target, so the cost of a ticket never depends on
     * whether the ticket address happens to be alive (a SELFDESTRUCT can
     * make it so). The liveness read is skipped for that target — one
     * backend read fewer, on every node alike. */
    int ticket_call = st->cfg.nodus_profile && op == 0xf1 &&
        memcmp(addr.b, st->cfg.ticket_addr.b, 32) == 0;
    uint64_t extra = access;
    if (op == 0xf1) {
        uint64_t create_cost = EVM_G_NEW_ACCOUNT;
        int alive;
        if (evm_u256_is_zero(&value) || ticket_call) create_cost = 0;
        else {
            FAULT_IF(evm_st_is_account_alive(st, &addr, &alive));
            if (alive) create_cost = 0;
        }
        extra = evm_gas_add(extra, create_cost);
    }
    if (op == 0xf1 || op == 0xf2)
        extra = evm_gas_add(extra, evm_u256_is_zero(&value) ? 0 : EVM_G_CALL_VALUE);

    uint64_t cost, sub_call;
    if (op == 0xf4 || op == 0xfa) {
        evm_u256 zero;
        evm_u256_zero(&zero);
        message_call_gas(&zero, gas, f->gas, mem_cost, extra, &cost, &sub_call);
    } else {
        message_call_gas(&value, gas, f->gas, mem_cost, extra, &cost, &sub_call);
    }
    CHARGE(evm_gas_add(cost, mem_cost));
    if (op == 0xf1 && f->is_static && !evm_u256_is_zero(&value))
        HALT(EVM_EXEC_STATIC_VIOLATION);
    FAULT_IF(mem_resize(f, new_len));

    generic_call_t p;
    memset(&p, 0, sizeof(p));
    p.gas = sub_call;
    p.code = code;
    p.code_len = code_len;
    p.code_hash = code_hash;
    p.code_address = code_address;
    p.disable_precompiles = disable;
    p.in_off = in_off;
    p.in_size = in_size;
    p.out_size = sat64(&out_size);
    p.out_off = evm_u256_is_zero(&out_size) ? 0 : sat64(&out_off);

    if (op == 0xf1 || op == 0xf2) {
        evm_acct_t me;
        FAULT_IF(evm_st_get_account(st, &f->target, &me));
        /* Nodus: a CALL into the ticket address is never short-circuited
         * here — an underfunded one halts inside ticket_frame (forwarded
         * gas consumed), the rule of evm.h ticket_addr. */
        if (!ticket_call && evm_u256_cmp(&me.balance, &value) < 0) {
            evm_u256_zero(&f->stack[f->sp++]);
            set_ret(f, NULL, 0);
            f->gas += sub_call;
            f->pc += 1;
            return 0;
        }
        p.value = value;
        p.caller = f->target;
        p.to = (op == 0xf1) ? addr : f->target;
        p.should_transfer = 1;
        p.is_staticcall = 0;
    } else if (op == 0xf4) {
        p.value = f->value;
        p.caller = f->caller;
        p.to = f->target;
        p.should_transfer = 0;
        p.is_staticcall = 0;
    } else {
        evm_u256_zero(&p.value);
        p.caller = f->target;
        p.to = addr;
        p.should_transfer = 1;
        p.is_staticcall = 1;
    }
    return generic_call(c, f, &p);
}

/* CREATE / CREATE2 — execution-specs@a87891f7
 * prague/vm/instructions/system.py:create, create2 */
static int op_create(ctx_t *c, frame *f, int is2)
{
    evm_state_t *st = c->st;
    NEED(is2 ? 4 : 3);
    evm_u256 endowment = S(0), mstart = S(1), msize = S(2), salt_w;
    if (is2) salt_w = S(3);
    f->sp -= is2 ? 4 : 3;

    mem_region r[1] = { { &mstart, &msize } };
    uint64_t mem_cost, new_len;
    extend_memory(f->mem_len, r, 1, &mem_cost, &new_len);
    /* init_code_cost(Uint(memory_size)) */
    uint64_t init_gas = copy_cost(&msize, EVM_G_CODE_INIT_PER_WORD);
    uint64_t cost = evm_gas_add(EVM_G_OPCODE_CREATE_BASE,
                                evm_gas_add(mem_cost, init_gas));
    if (is2)
        cost = evm_gas_add(cost, copy_cost(&msize, EVM_G_OPCODE_KECCAK256_PER_WORD));
    CHARGE(cost);
    FAULT_IF(mem_resize(f, new_len));

    evm_addr caddr;
    if (is2) {
        evm_bytes32 salt;
        key_from_word(&salt, &salt_w);
        const uint8_t *code = NULL;
        size_t len = 0;
        if (!evm_u256_is_zero(&msize)) {
            uint64_t off = sat64(&mstart);
            len = (size_t)sat64(&msize);
            if (off > f->mem_len || len > f->mem_len - off) return EVM_FAULT;
            code = f->mem + off;
        }
        FAULT_IF(create2_address(st, &f->target, &salt, code, len, &caddr));
    } else {
        evm_acct_t me;
        FAULT_IF(evm_st_get_account(st, &f->target, &me));
        FAULT_IF(evm_compute_contract_address(st, &f->target, me.nonce, &caddr));
    }
    evm_exec_status_t hs = EVM_EXEC_SUCCESS;
    int rc = generic_create(c, f, &endowment, &caddr, &mstart, &msize, &hs);
    if (rc == 1) HALT(hs);
    return rc;
}

/* RETURN / REVERT — prague/vm/instructions/system.py:return_, revert */
static int op_return(frame *f, int is_revert)
{
    NEED(2);
    evm_u256 start = S(0), size = S(1);
    f->sp -= 2;
    mem_region r[1] = { { &start, &size } };
    uint64_t mem_cost, new_len;
    extend_memory(f->mem_len, r, 1, &mem_cost, &new_len);
    CHARGE(mem_cost);
    FAULT_IF(mem_resize(f, new_len));
    free(f->out);
    f->out = NULL;
    f->out_len = 0;
    if (!evm_u256_is_zero(&size)) {
        uint64_t off = sat64(&start), sz = sat64(&size);
        if (off > f->mem_len || sz > f->mem_len - off) return EVM_FAULT;
        f->out = malloc((size_t)sz);
        if (!f->out) return EVM_FAULT;
        memcpy(f->out, f->mem + off, (size_t)sz);
        f->out_len = (size_t)sz;
    }
    if (is_revert) f->status = EVM_EXEC_REVERT;   /* raise Revert */
    f->done = 1;
    return 0;
}

/* SELFDESTRUCT — prague/vm/instructions/system.py:selfdestruct */
static int op_selfdestruct(ctx_t *c, frame *f)
{
    evm_state_t *st = c->st;
    NEED(1);
    evm_addr ben;
    evm_addr_from_word(st, &S(0), &ben);
    f->sp -= 1;
    uint64_t cost = EVM_G_OPCODE_SELFDESTRUCT_BASE;
    int warm;
    FAULT_IF(evm_st_access_addr(st, &ben, &warm));
    if (!warm) cost += EVM_G_COLD_ACCOUNT_ACCESS;
    int alive;
    evm_acct_t me;
    FAULT_IF(evm_st_is_account_alive(st, &ben, &alive));
    FAULT_IF(evm_st_get_account(st, &f->target, &me));
    if (!alive && !evm_u256_is_zero(&me.balance))
        cost += EVM_G_OPCODE_SELFDESTRUCT_NEW_ACCOUNT;
    CHARGE(cost);
    if (f->is_static) HALT(EVM_EXEC_STATIC_VIOLATION);
    FAULT_IF(evm_st_get_account(st, &f->target, &me));
    evm_u256 bal = me.balance;
    FAULT_IF(evm_st_move_ether(st, &f->target, &ben, &bal));
    int created;
    FAULT_IF(evm_st_is_created(st, &f->target, &created));
    if (created) {
        /* "If beneficiary is the same as originator, then the ether is
         * burnt" (system.py:574-576). Loss journaling, chain integration
         * design §5 rev 3 part (a): the balance at the moment it is zeroed
         * — the moved value when ben == self, 0 otherwise. */
        evm_u256 zero;
        evm_u256_zero(&zero);
        FAULT_IF(evm_st_get_account(st, &f->target, &me));
        if (!evm_u256_is_zero(&me.balance))
            FAULT_IF(evm_st_add_destroyed(st, &me.balance));
        FAULT_IF(evm_st_set_balance(st, &f->target, &zero));
        FAULT_IF(evm_st_add_to_delete(st, &f->target));
    }
    f->done = 1;
    return 0;
}

/* SSTORE — prague/vm/instructions/storage.py:sstore */
static int op_sstore(ctx_t *c, frame *f)
{
    evm_state_t *st = c->st;
    NEED(2);
    evm_bytes32 key;
    key_from_word(&key, &S(0));
    evm_u256 nv = S(1);
    f->sp -= 2;
    if (f->gas <= EVM_G_CALL_STIPEND) HALT(EVM_EXEC_OUT_OF_GAS);
    evm_u256 orig, cur;
    FAULT_IF(evm_st_get_storage_original(st, &f->target, &key, &orig));
    FAULT_IF(evm_st_get_storage(st, &f->target, &key, &cur));
    uint64_t cost = 0;
    int warm;
    FAULT_IF(evm_st_access_slot(st, &f->target, &key, &warm));
    if (!warm) cost += EVM_G_COLD_STORAGE_ACCESS;
    int o_eq_c = evm_u256_cmp(&orig, &cur) == 0;
    int c_eq_n = evm_u256_cmp(&cur, &nv) == 0;
    int o_eq_n = evm_u256_cmp(&orig, &nv) == 0;
    int o_zero = evm_u256_is_zero(&orig);
    int c_zero = evm_u256_is_zero(&cur);
    int n_zero = evm_u256_is_zero(&nv);
    if (o_eq_c && !c_eq_n) {
        if (o_zero) cost += EVM_G_STORAGE_SET;
        else cost += EVM_G_COLD_STORAGE_WRITE - EVM_G_COLD_STORAGE_ACCESS;
    } else {
        cost += EVM_G_WARM_ACCESS;
    }
    if (!c_eq_n) {
        if (!o_zero && !c_zero && n_zero)
            f->refund += EVM_G_REFUND_STORAGE_CLEAR;
        if (!o_zero && c_zero)
            f->refund -= EVM_G_REFUND_STORAGE_CLEAR;
        if (o_eq_n) {
            if (o_zero)
                f->refund += (int64_t)(EVM_G_STORAGE_SET - EVM_G_WARM_ACCESS);
            else
                f->refund += (int64_t)(EVM_G_COLD_STORAGE_WRITE -
                                       EVM_G_COLD_STORAGE_ACCESS -
                                       EVM_G_WARM_ACCESS);
        }
    }
    CHARGE(cost);
    if (f->is_static) HALT(EVM_EXEC_STATIC_VIOLATION);
    FAULT_IF(evm_st_set_storage(st, &f->target, &key, &nv));
    f->pc += 1;
    return 0;
}

/* *COPY into memory: CALLDATACOPY, CODECOPY, EXTCODECOPY (buffer source),
 * dest/src/size already popped; cost already charged by the caller. */
static int copy_to_mem(frame *f, const evm_u256 *mstart, const evm_u256 *src,
                       const evm_u256 *size, const uint8_t *buf, size_t len,
                       uint64_t new_len)
{
    FAULT_IF(mem_resize(f, new_len));
    if (evm_u256_is_zero(size)) return 0;
    uint64_t off = sat64(mstart), sz = sat64(size);
    if (off > f->mem_len || sz > f->mem_len - off) return EVM_FAULT;
    buffer_read(f->mem + off, buf, len, src, (size_t)sz);
    return 0;
}

/* LOGn — prague/vm/instructions/log.py:log_n */
static int op_log(ctx_t *c, frame *f, unsigned n)
{
    NEED(2 + n);
    evm_u256 start = S(0), size = S(1);
    evm_bytes32 topics[4];
    for (unsigned i = 0; i < n; i++)
        key_from_word(&topics[i], &S(2 + i));
    f->sp -= 2 + n;
    mem_region r[1] = { { &start, &size } };
    uint64_t mem_cost, new_len;
    extend_memory(f->mem_len, r, 1, &mem_cost, &new_len);
    uint64_t cost = evm_gas_add(EVM_G_OPCODE_LOG_BASE,
                    evm_gas_add(evm_gas_mul(EVM_G_OPCODE_LOG_DATA_PER_BYTE, sat64(&size)),
                    evm_gas_add(evm_gas_mul(EVM_G_OPCODE_LOG_TOPIC, n), mem_cost)));
    CHARGE(cost);
    FAULT_IF(mem_resize(f, new_len));
    if (f->is_static) HALT(EVM_EXEC_STATIC_VIOLATION);
    const uint8_t *data = NULL;
    size_t len = 0;
    if (!evm_u256_is_zero(&size)) {
        uint64_t off = sat64(&start);
        len = (size_t)sat64(&size);
        if (off > f->mem_len || len > f->mem_len - off) return EVM_FAULT;
        data = f->mem + off;
    }
    FAULT_IF(evm_st_add_log(c->st, &f->target, topics, n, data, len));
    f->pc += 1;
    return 0;
}

/* ── the opcode loop (prague/vm/interpreter.py:process_message, inner
 *    `while evm.running and evm.pc < ulen(evm.code)`) ─────────────── */

static int exec_frame(ctx_t *c, frame *f)
{
    evm_state_t *st = c->st;
    const evm_tx_env_t *te = c->txenv;
    size_t depth_before = c->n;
    while (!f->done) {
        if (f->pc >= f->code_len) {        /* ran off the end: STOP */
            f->done = 1;
            break;
        }
        uint8_t op = f->code[f->pc];
        evm_u256 w;
        uint64_t cost, mem_cost, new_len;

        if (op >= 0x60 && op <= 0x7f) {     /* PUSH1..PUSH32 */
            size_t nb = (size_t)(op - 0x60 + 1);
            CHARGE(EVM_G_VERY_LOW);
            uint8_t b[32];
            memset(b, 0, 32);
            evm_u256 at;
            word_from_u64(&at, f->pc + 1);
            buffer_read(b + (32 - nb), f->code, f->code_len, &at, nb);
            evm_u256_from_be(&w, b);
            PUSH_WORD(w);
            f->pc += 1 + nb;
            continue;
        }
        if (op >= 0x80 && op <= 0x8f) {     /* DUP1..DUP16 */
            size_t item = (size_t)(op - 0x80);
            CHARGE(EVM_G_VERY_LOW);
            if (item >= f->sp) HALT(EVM_EXEC_STACK_UNDERFLOW);
            w = S(item);
            PUSH_WORD(w);
            f->pc += 1;
            continue;
        }
        if (op >= 0x90 && op <= 0x9f) {     /* SWAP1..SWAP16 */
            size_t item = (size_t)(op - 0x90 + 1);
            CHARGE(EVM_G_VERY_LOW);
            if (item >= f->sp) HALT(EVM_EXEC_STACK_UNDERFLOW);
            w = S(0);
            S(0) = S(item);
            S(item) = w;
            f->pc += 1;
            continue;
        }
        if (op >= 0xa0 && op <= 0xa4) {
            FAULT_IF(op_log(c, f, (unsigned)(op - 0xa0)));
            continue;
        }

        switch (op) {
        /* ── control_flow.py ── */
        case 0x00:                          /* STOP */
            f->done = 1;
            f->pc += 1;
            break;
        case 0x56: {                        /* JUMP */
            NEED(1);
            evm_u256 d = S(0);
            f->sp--;
            CHARGE(EVM_G_MID);
            uint64_t dest;
            if (!valid_jump(f, &d, &dest)) HALT(EVM_EXEC_BAD_JUMP);
            f->pc = dest;
            break;
        }
        case 0x57: {                        /* JUMPI */
            NEED(2);
            evm_u256 d = S(0), cond = S(1);
            f->sp -= 2;
            CHARGE(EVM_G_HIGH);
            uint64_t dest;
            if (evm_u256_is_zero(&cond)) f->pc += 1;
            else if (!valid_jump(f, &d, &dest)) HALT(EVM_EXEC_BAD_JUMP);
            else f->pc = dest;
            break;
        }
        case 0x58:                          /* PC */
            CHARGE(EVM_G_BASE);
            word_from_u64(&w, f->pc);
            PUSH_WORD(w);
            f->pc += 1;
            break;
        case 0x5a:                          /* GAS */
            CHARGE(EVM_G_BASE);
            word_from_u64(&w, f->gas);
            PUSH_WORD(w);
            f->pc += 1;
            break;
        case 0x5b:                          /* JUMPDEST */
            CHARGE(EVM_G_OPCODE_JUMPDEST);
            f->pc += 1;
            break;

        /* ── arithmetic.py ── */
        case 0x01: BINOP(u256_add_w, EVM_G_VERY_LOW); break;
        case 0x02: BINOP(evm_u256_mul, EVM_G_LOW); break;
        case 0x03: BINOP(u256_sub_w, EVM_G_VERY_LOW); break;
        case 0x04: BINOP(evm_u256_div, EVM_G_LOW); break;
        case 0x05: BINOP(evm_u256_sdiv, EVM_G_LOW); break;
        case 0x06: BINOP(evm_u256_mod, EVM_G_LOW); break;
        case 0x07: BINOP(evm_u256_smod, EVM_G_LOW); break;
        case 0x08:                          /* ADDMOD */
        case 0x09: {                        /* MULMOD */
            NEED(3);
            evm_u256 x = S(0), y = S(1), z = S(2);
            f->sp -= 3;
            CHARGE(EVM_G_MID);
            if (op == 0x08) evm_u256_addmod(&w, &x, &y, &z);
            else evm_u256_mulmod(&w, &x, &y, &z);
            f->stack[f->sp++] = w;
            f->pc += 1;
            break;
        }
        case 0x0a: {                        /* EXP */
            NEED(2);
            evm_u256 base = S(0), e = S(1);
            f->sp -= 2;
            uint64_t ebytes = (evm_u256_bitlen(&e) + 7u) / 8u;
            CHARGE(EVM_G_OPCODE_EXP_BASE + EVM_G_OPCODE_EXP_PER_BYTE * ebytes);
            evm_u256_exp(&w, &base, &e);
            f->stack[f->sp++] = w;
            f->pc += 1;
            break;
        }
        case 0x0b: BINOP(evm_u256_signextend, EVM_G_LOW); break;

        /* ── comparison.py ── */
        case 0x10: case 0x11: case 0x12: case 0x13: case 0x14: {
            NEED(2);
            evm_u256 l = S(0), r = S(1);
            f->sp -= 2;
            CHARGE(EVM_G_VERY_LOW);
            int res;
            switch (op) {
            case 0x10: res = evm_u256_cmp(&l, &r) < 0; break;
            case 0x11: res = evm_u256_cmp(&l, &r) > 0; break;
            case 0x12: res = evm_u256_scmp(&l, &r) < 0; break;
            case 0x13: res = evm_u256_scmp(&l, &r) > 0; break;
            default:   res = evm_u256_cmp(&l, &r) == 0; break;
            }
            word_from_u64(&w, (uint64_t)res);
            f->stack[f->sp++] = w;
            f->pc += 1;
            break;
        }
        case 0x15:                          /* ISZERO */
            NEED(1);
            CHARGE(EVM_G_VERY_LOW);
            word_from_u64(&w, (uint64_t)evm_u256_is_zero(&S(0)));
            S(0) = w;
            f->pc += 1;
            break;

        /* ── bitwise.py ── */
        case 0x16: BINOP(evm_u256_and, EVM_G_VERY_LOW); break;
        case 0x17: BINOP(evm_u256_or, EVM_G_VERY_LOW); break;
        case 0x18: BINOP(evm_u256_xor, EVM_G_VERY_LOW); break;
        case 0x19:                          /* NOT */
            NEED(1);
            CHARGE(EVM_G_VERY_LOW);
            evm_u256_not(&S(0), &S(0));
            f->pc += 1;
            break;
        case 0x1a: BINOP(evm_u256_byte, EVM_G_VERY_LOW); break;
        case 0x1b: BINOP(evm_u256_shl, EVM_G_VERY_LOW); break;
        case 0x1c: BINOP(evm_u256_shr, EVM_G_VERY_LOW); break;
        case 0x1d: BINOP(evm_u256_sar, EVM_G_VERY_LOW); break;

        /* ── keccak.py ── */
        case 0x20: {                        /* KECCAK256 */
            NEED(2);
            evm_u256 start = S(0), size = S(1);
            f->sp -= 2;
            mem_region r[1] = { { &start, &size } };
            extend_memory(f->mem_len, r, 1, &mem_cost, &new_len);
            cost = evm_gas_add(EVM_G_OPCODE_KECCAK256_BASE,
                   evm_gas_add(copy_cost(&size, EVM_G_OPCODE_KECCAK256_PER_WORD),
                               mem_cost));
            CHARGE(cost);
            FAULT_IF(mem_resize(f, new_len));
            const uint8_t *data = NULL;
            size_t len = 0;
            if (!evm_u256_is_zero(&size)) {
                uint64_t off = sat64(&start);
                len = (size_t)sat64(&size);
                if (off > f->mem_len || len > f->mem_len - off) return EVM_FAULT;
                data = f->mem + off;
            }
            uint8_t h[32];
            FAULT_IF(evm_keccak(data, len, h));
            evm_u256_from_be(&w, h);
            f->stack[f->sp++] = w;
            f->pc += 1;
            break;
        }

        /* ── environment.py ── */
        case 0x30:                          /* ADDRESS */
            CHARGE(EVM_G_BASE);
            evm_addr_to_word(&f->target, &w);
            PUSH_WORD(w);
            f->pc += 1;
            break;
        case 0x31: {                        /* BALANCE */
            NEED(1);
            evm_addr a;
            evm_addr_from_word(st, &S(0), &a);
            f->sp--;
            FAULT_IF(access_cost(c, &a, &cost));
            CHARGE(cost);
            evm_acct_t acct;
            FAULT_IF(evm_st_get_account(st, &a, &acct));
            f->stack[f->sp++] = acct.balance;
            f->pc += 1;
            break;
        }
        case 0x32:                          /* ORIGIN */
            CHARGE(EVM_G_BASE);
            evm_addr_to_word(&te->origin, &w);
            PUSH_WORD(w);
            f->pc += 1;
            break;
        case 0x33:                          /* CALLER */
            CHARGE(EVM_G_BASE);
            evm_addr_to_word(&f->caller, &w);
            PUSH_WORD(w);
            f->pc += 1;
            break;
        case 0x34:                          /* CALLVALUE */
            CHARGE(EVM_G_BASE);
            PUSH_WORD(f->value);
            f->pc += 1;
            break;
        case 0x35: {                        /* CALLDATALOAD */
            NEED(1);
            evm_u256 start = S(0);
            CHARGE(EVM_G_VERY_LOW);
            uint8_t b[32];
            buffer_read(b, f->data, f->data_len, &start, 32);
            evm_u256_from_be(&S(0), b);
            f->pc += 1;
            break;
        }
        case 0x36:                          /* CALLDATASIZE */
            CHARGE(EVM_G_BASE);
            word_from_u64(&w, (uint64_t)f->data_len);
            PUSH_WORD(w);
            f->pc += 1;
            break;
        case 0x37:                          /* CALLDATACOPY */
        case 0x39: {                        /* CODECOPY */
            NEED(3);
            evm_u256 mstart = S(0), src = S(1), size = S(2);
            f->sp -= 3;
            mem_region r[1] = { { &mstart, &size } };
            extend_memory(f->mem_len, r, 1, &mem_cost, &new_len);
            cost = evm_gas_add(EVM_G_VERY_LOW,
                   evm_gas_add(copy_cost(&size, EVM_G_OPCODE_COPY_PER_WORD), mem_cost));
            CHARGE(cost);
            if (op == 0x37)
                FAULT_IF(copy_to_mem(f, &mstart, &src, &size, f->data, f->data_len, new_len));
            else
                FAULT_IF(copy_to_mem(f, &mstart, &src, &size, f->code, f->code_len, new_len));
            f->pc += 1;
            break;
        }
        case 0x38:                          /* CODESIZE */
            CHARGE(EVM_G_BASE);
            word_from_u64(&w, (uint64_t)f->code_len);
            PUSH_WORD(w);
            f->pc += 1;
            break;
        case 0x3a:                          /* GASPRICE */
            CHARGE(EVM_G_BASE);
            PUSH_WORD(te->gas_price);
            f->pc += 1;
            break;
        case 0x3b: {                        /* EXTCODESIZE */
            NEED(1);
            evm_addr a;
            evm_addr_from_word(st, &S(0), &a);
            f->sp--;
            FAULT_IF(access_cost(c, &a, &cost));
            CHARGE(cost);
            evm_acct_t acct;
            const uint8_t *code;
            size_t len;
            FAULT_IF(evm_st_get_account(st, &a, &acct));
            FAULT_IF(evm_st_get_code(st, &a, &acct, &code, &len));
            word_from_u64(&w, (uint64_t)len);
            f->stack[f->sp++] = w;
            f->pc += 1;
            break;
        }
        case 0x3c: {                        /* EXTCODECOPY */
            NEED(4);
            evm_addr a;
            evm_addr_from_word(st, &S(0), &a);
            evm_u256 mstart = S(1), src = S(2), size = S(3);
            f->sp -= 4;
            mem_region r[1] = { { &mstart, &size } };
            extend_memory(f->mem_len, r, 1, &mem_cost, &new_len);
            uint64_t acc;
            FAULT_IF(access_cost(c, &a, &acc));
            cost = evm_gas_add(acc,
                   evm_gas_add(copy_cost(&size, EVM_G_OPCODE_COPY_PER_WORD), mem_cost));
            CHARGE(cost);
            evm_acct_t acct;
            const uint8_t *code;
            size_t len;
            FAULT_IF(mem_resize(f, new_len));
            FAULT_IF(evm_st_get_account(st, &a, &acct));
            FAULT_IF(evm_st_get_code(st, &a, &acct, &code, &len));
            FAULT_IF(copy_to_mem(f, &mstart, &src, &size, code, len, new_len));
            f->pc += 1;
            break;
        }
        case 0x3d:                          /* RETURNDATASIZE */
            CHARGE(EVM_G_BASE);
            word_from_u64(&w, (uint64_t)f->ret_len);
            PUSH_WORD(w);
            f->pc += 1;
            break;
        case 0x3e: {                        /* RETURNDATACOPY */
            NEED(3);
            evm_u256 mstart = S(0), src = S(1), size = S(2);
            f->sp -= 3;
            mem_region r[1] = { { &mstart, &size } };
            extend_memory(f->mem_len, r, 1, &mem_cost, &new_len);
            cost = evm_gas_add(EVM_G_VERY_LOW,
                   evm_gas_add(copy_cost(&size, EVM_G_OPCODE_RETURNDATACOPY_PER_WORD),
                               mem_cost));
            CHARGE(cost);
            {
                /* Uint(start) + Uint(size) > len(return_data) -> OutOfBoundsRead */
                uint64_t s0, z0;
                if (!evm_u256_to_u64(&src, &s0) || !evm_u256_to_u64(&size, &z0) ||
                    s0 > UINT64_MAX - z0 || s0 + z0 > (uint64_t)f->ret_len)
                    HALT(EVM_EXEC_RETURNDATA_OOB);
            }
            FAULT_IF(copy_to_mem(f, &mstart, &src, &size, f->ret, f->ret_len, new_len));
            f->pc += 1;
            break;
        }
        case 0x3f: {                        /* EXTCODEHASH */
            NEED(1);
            evm_addr a;
            evm_addr_from_word(st, &S(0), &a);
            f->sp--;
            FAULT_IF(access_cost(c, &a, &cost));
            CHARGE(cost);
            evm_acct_t acct;
            FAULT_IF(evm_st_get_account(st, &a, &acct));
            if (evm_acct_is_empty(&acct)) evm_u256_zero(&w);
            else evm_u256_from_be(&w, acct.code_hash.b);
            f->stack[f->sp++] = w;
            f->pc += 1;
            break;
        }

        /* ── block.py ── */
        case 0x40: {                        /* BLOCKHASH */
            NEED(1);
            evm_u256 bn = S(0);
            f->sp--;
            CHARGE(EVM_G_OPCODE_BLOCKHASH);
            uint64_t cur = te->env->number, n;
            evm_u256_zero(&w);
            if (evm_u256_to_u64(&bn, &n) && cur > n && cur - n <= 256) {
                evm_bytes32 h;
                int avail = 0;
                FAULT_IF(evm_st_block_hash(st, n, &h, &avail));
                /* the reference always holds this hash
                 * (fork.py:get_last_256_block_hashes): not served = fault */
                if (!avail) return EVM_FAULT;
                evm_u256_from_be(&w, h.b);
            }
            f->stack[f->sp++] = w;
            f->pc += 1;
            break;
        }
        case 0x41:                          /* COINBASE */
            CHARGE(EVM_G_BASE);
            evm_addr_to_word(&te->env->coinbase, &w);
            PUSH_WORD(w);
            f->pc += 1;
            break;
        case 0x42:                          /* TIMESTAMP */
            CHARGE(EVM_G_BASE);
            word_from_u64(&w, te->env->timestamp);
            PUSH_WORD(w);
            f->pc += 1;
            break;
        case 0x43:                          /* NUMBER */
            CHARGE(EVM_G_BASE);
            word_from_u64(&w, te->env->number);
            PUSH_WORD(w);
            f->pc += 1;
            break;
        case 0x44:                          /* PREVRANDAO */
            CHARGE(EVM_G_BASE);
            evm_u256_from_be(&w, te->env->prev_randao.b);
            PUSH_WORD(w);
            f->pc += 1;
            break;
        case 0x45:                          /* GASLIMIT */
            CHARGE(EVM_G_BASE);
            word_from_u64(&w, te->env->gas_limit);
            PUSH_WORD(w);
            f->pc += 1;
            break;
        case 0x46:                          /* CHAINID */
            CHARGE(EVM_G_BASE);
            chain_id_word(st, &w);
            PUSH_WORD(w);
            f->pc += 1;
            break;
        case 0x47: {                        /* SELFBALANCE */
            CHARGE(EVM_G_OPCODE_SELFBALANCE);
            evm_acct_t acct;
            FAULT_IF(evm_st_get_account(st, &f->target, &acct));
            PUSH_WORD(acct.balance);
            f->pc += 1;
            break;
        }
        case 0x48:                          /* BASEFEE */
            CHARGE(EVM_G_BASE);
            PUSH_WORD(te->env->base_fee);
            f->pc += 1;
            break;
        case 0x49:                          /* BLOBHASH */
            NEED(1);
            CHARGE(EVM_G_OPCODE_BLOBHASH);
            /* tx types 0/1/2 carry no blob_versioned_hashes: every index
             * is out of range -> Bytes32(0) */
            evm_u256_zero(&S(0));
            f->pc += 1;
            break;
        case 0x4a:                          /* BLOBBASEFEE */
            CHARGE(EVM_G_BASE);
            FAULT_IF(blob_base_fee(c->txenv, &w));
            PUSH_WORD(w);
            f->pc += 1;
            break;

        /* ── stack.py / memory.py ── */
        case 0x50:                          /* POP */
            NEED(1);
            f->sp--;
            CHARGE(EVM_G_BASE);
            f->pc += 1;
            break;
        case 0x51:                          /* MLOAD */
        case 0x52:                          /* MSTORE */
        case 0x53: {                        /* MSTORE8 */
            NEED(op == 0x51 ? 1 : 2);
            evm_u256 start = S(0), val;
            if (op != 0x51) val = S(1);
            f->sp -= (op == 0x51) ? 1 : 2;
            evm_u256 sz;
            word_from_u64(&sz, op == 0x53 ? 1 : 32);
            mem_region r[1] = { { &start, &sz } };
            extend_memory(f->mem_len, r, 1, &mem_cost, &new_len);
            CHARGE(evm_gas_add(EVM_G_VERY_LOW, mem_cost));
            FAULT_IF(mem_resize(f, new_len));
            uint64_t off = sat64(&start);
            size_t need = (op == 0x53) ? 1 : 32;
            if (off > f->mem_len || need > f->mem_len - off) return EVM_FAULT;
            if (op == 0x51) {
                evm_u256_from_be(&w, f->mem + off);
                f->stack[f->sp++] = w;
            } else if (op == 0x52) {
                evm_u256_to_be(f->mem + off, &val);
            } else {
                f->mem[off] = (uint8_t)(val.w[0] & 0xff);
            }
            f->pc += 1;
            break;
        }
        case 0x59:                          /* MSIZE */
            CHARGE(EVM_G_BASE);
            word_from_u64(&w, (uint64_t)f->mem_len);
            PUSH_WORD(w);
            f->pc += 1;
            break;
        case 0x5e: {                        /* MCOPY */
            NEED(3);
            evm_u256 dst = S(0), src = S(1), len = S(2);
            f->sp -= 3;
            mem_region r[2] = { { &src, &len }, { &dst, &len } };
            extend_memory(f->mem_len, r, 2, &mem_cost, &new_len);
            cost = evm_gas_add(EVM_G_VERY_LOW,
                   evm_gas_add(copy_cost(&len, EVM_G_OPCODE_COPY_PER_WORD), mem_cost));
            CHARGE(cost);
            FAULT_IF(mem_resize(f, new_len));
            if (!evm_u256_is_zero(&len)) {
                uint64_t d = sat64(&dst), s = sat64(&src), n = sat64(&len);
                if (d > f->mem_len || n > f->mem_len - d ||
                    s > f->mem_len || n > f->mem_len - s)
                    return EVM_FAULT;
                memmove(f->mem + d, f->mem + s, (size_t)n);
            }
            f->pc += 1;
            break;
        }
        case 0x5f:                          /* PUSH0 */
            CHARGE(EVM_G_BASE);
            evm_u256_zero(&w);
            PUSH_WORD(w);
            f->pc += 1;
            break;

        /* ── storage.py ── */
        case 0x54: {                        /* SLOAD */
            NEED(1);
            evm_bytes32 key;
            key_from_word(&key, &S(0));
            f->sp--;
            int warm;
            FAULT_IF(evm_st_access_slot(st, &f->target, &key, &warm));
            CHARGE(warm ? EVM_G_WARM_ACCESS : EVM_G_COLD_STORAGE_ACCESS);
            FAULT_IF(evm_st_get_storage(st, &f->target, &key, &w));
            f->stack[f->sp++] = w;
            f->pc += 1;
            break;
        }
        case 0x55:                          /* SSTORE */
            FAULT_IF(op_sstore(c, f));
            break;
        case 0x5c: {                        /* TLOAD */
            NEED(1);
            evm_bytes32 key;
            key_from_word(&key, &S(0));
            CHARGE(EVM_G_OPCODE_TLOAD);
            FAULT_IF(evm_st_get_transient(st, &f->target, &key, &S(0)));
            f->pc += 1;
            break;
        }
        case 0x5d: {                        /* TSTORE */
            NEED(2);
            evm_bytes32 key;
            key_from_word(&key, &S(0));
            evm_u256 v = S(1);
            f->sp -= 2;
            CHARGE(EVM_G_OPCODE_TSTORE);
            if (f->is_static) HALT(EVM_EXEC_STATIC_VIOLATION);
            FAULT_IF(evm_st_set_transient(st, &f->target, &key, &v));
            f->pc += 1;
            break;
        }

        /* ── system.py ── */
        case 0xf0:
            FAULT_IF(op_create(c, f, 0));
            break;
        case 0xf5:
            FAULT_IF(op_create(c, f, 1));
            break;
        case 0xf1: case 0xf2: case 0xf4: case 0xfa:
            FAULT_IF(op_call_family(c, f, op));
            break;
        case 0xf3:
            FAULT_IF(op_return(f, 0));
            break;
        case 0xfd:
            FAULT_IF(op_return(f, 1));
            break;
        case 0xff:
            FAULT_IF(op_selfdestruct(c, f));
            break;

        default:                            /* InvalidOpcode (incl. 0xFE) */
            HALT(EVM_EXEC_INVALID_OPCODE);
        }
        if (c->n != depth_before) return 0; /* a child frame was pushed */
    }
    return 0;
}

/* ── driver ────────────────────────────────────────────────────────── */

static int run(ctx_t *c, evm_call_output_t *out)
{
    while (c->n > 0) {
        frame *f = c->fs[c->n - 1];
        if (!f->done) {
            size_t before = c->n;
            EVM_CHECK(exec_frame(c, f));
            if (c->n != before) continue;   /* run the child */
            if (!f->done) return EVM_FAULT; /* broken invariant */
        }
        EVM_CHECK(finish_frame(c, f, out));
    }
    return 0;
}

static void ctx_free(ctx_t *c)
{
    for (size_t i = 0; i < c->n; i++) frame_free(c->fs[i]);
    free(c->fs);
    c->fs = NULL;
    c->n = c->cap = 0;
}

/* execution-specs@a87891f7 prague/vm/interpreter.py:process_message_call */
int evm_process_message_call(evm_state_t *st, evm_tx_env_t *txenv,
                             evm_message_t *msg, evm_call_output_t *out)
{
    ctx_t c;
    memset(&c, 0, sizeof(c));
    c.st = st;
    c.txenv = txenv;
    memset(out, 0, sizeof(*out));
    out->status = EVM_EXEC_SUCCESS;

    frame *f = new_frame();
    if (!f) return EVM_FAULT;
    f->caller = msg->caller;
    f->target = msg->target;
    f->is_create = msg->is_create;
    f->gas = msg->gas;
    f->value = msg->value;
    f->data = msg->data;
    f->data_len = msg->data_len;
    f->code = msg->code;
    f->code_len = msg->code_len;
    f->has_code_hash = msg->has_code_hash;   /* 0 for create init code */
    f->code_hash = msg->code_hash;
    f->depth = 0;
    f->should_transfer = 1;
    f->is_static = 0;
    f->disable_precompiles = 0;

    int rc;
    if (msg->is_create) {
        int deployable;
        rc = evm_st_account_deployable(st, &msg->target, &deployable);
        if (rc != 0) {
            frame_free(f);
            return rc == EVM_BUDGET ? EVM_BUDGET : EVM_FAULT;
        }
        if (!deployable) {
            /* AddressCollision: gas_left 0, no logs, no refund */
            frame_free(f);
            out->gas_left = 0;
            out->refund_counter = 0;
            out->status = EVM_EXEC_CREATE_COLLISION;
            return 0;
        }
        /* code_address = None for a create message */
        f->data = NULL;
        f->data_len = 0;
        if (push_frame(&c, f) != 0) {
            frame_free(f);
            return EVM_FAULT;
        }
        rc = start_create(&c, f);
    } else {
        f->code_address = msg->code_address;
        /* (tx_env.authorizations is always empty: type 4 is refused) */
        evm_addr del;
        if (get_delegated(f->code, f->code_len, &del)) {
            int warm;
            evm_acct_t acct;
            f->disable_precompiles = 1;
            rc = evm_st_access_addr(st, &del, &warm);
            if (rc == 0) rc = evm_st_get_account(st, &del, &acct);
            if (rc == 0)
                rc = evm_st_get_code(st, &del, &acct, &f->code, &f->code_len);
            if (rc != 0) {
                frame_free(f);
                return rc == EVM_BUDGET ? EVM_BUDGET : EVM_FAULT;
            }
            f->has_code_hash = 1;
            f->code_hash = acct.code_hash;
            f->code_address = del;
        }
        if (push_frame(&c, f) != 0) {
            frame_free(f);
            return EVM_FAULT;
        }
        rc = start_message(&c, f, 1);
    }
    if (rc == 0) rc = run(&c, out);
    if (rc != 0) {
        free(out->output);
        out->output = NULL;
        out->output_len = 0;
    }
    ctx_free(&c);
    return rc;
}
