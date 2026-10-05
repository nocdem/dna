/**
 * @file evm_tx.c
 * @brief Prague state transition for one transaction (Nodus EVM phase 1).
 *
 * Port of execution-specs@a87891f7 src/ethereum/forks/prague/:
 *   transactions.py:validate_transaction, calculate_intrinsic_cost
 *   fork.py:check_transaction, process_transaction
 *   utils/message.py:prepare_message
 *
 * Scope (design §1): tx types 0, 1, 2. Types 3 (blob) and 4 (set-code)
 * are refused with EVM_TXERR_TYPE_UNSUPPORTED. Signature recovery is not
 * done here: evm_tx_t.sender is already authenticated by the caller.
 *
 * Every validity check runs before the first state write, in ONE function
 * (tx_validate) shared by evm_tx_apply and evm_tx_prevalidate; it reads
 * through the non-mutating peeks, so a refused transaction leaves the
 * overlay byte-identical.
 *
 * EVM_BUDGET (chain integration design §3): the execution checkpoint is
 * taken after the nonce increment and the fee debit. A backend BUDGET
 * verdict anywhere after it ends the transaction as an applied failure
 * (EVM_EXEC_BUDGET): every change since the checkpoint is reverted, the
 * gas is consumed as by an exceptional halt, and the ordinary tail runs
 * (refund, coinbase, deletions). A BUDGET verdict before the checkpoint
 * (validation, the sender load) or inside that tail abandons the tx:
 * nothing is applied and evm_tx_apply returns -3.
 */
#include <stdlib.h>
#include <string.h>

#include "evm_internal.h"
#include "evm_gas.h"

/* r = a * b; @return 1 on overflow past 2^256 (r undefined). */
static int mul_u256_u64(evm_u256 *r, const evm_u256 *a, uint64_t b)
{
    uint64_t carry = 0;
    evm_u256 out;
    for (int i = 0; i < 4; i++) {
        uint64_t hi, lo;
        evm_mul64(a->w[i], b, &hi, &lo);
        lo += carry;
        if (lo < carry) hi++;
        out.w[i] = lo;
        carry = hi;
    }
    *r = out;
    return carry != 0;
}

/* tx chain id vs the configured chain id */
static int chain_id_matches(const evm_state_t *st, const evm_tx_t *tx)
{
    return evm_u256_cmp(&tx->chain_id, &st->cfg.chain_id) == 0;
}

typedef struct {
    uint64_t regular;
    uint64_t calldata_floor;
} intrinsic_t;

/* execution-specs@a87891f7 prague/transactions.py:calculate_intrinsic_cost
 * (saturating: a saturated cost exceeds every uint64 gas limit except
 * UINT64_MAX itself, which TX_BASE alone already makes unreachable for
 * the remainder of the computation). */
static void calculate_intrinsic_cost(const evm_tx_t *tx, intrinsic_t *ic)
{
    uint64_t zeros = 0;
    for (size_t i = 0; i < tx->data_len; i++)
        if (tx->data[i] == 0) zeros++;
    uint64_t non_zeros = (uint64_t)tx->data_len - zeros;
    uint64_t tokens = evm_gas_add(zeros, evm_gas_mul(non_zeros, 4));
    ic->calldata_floor = evm_gas_add(evm_gas_mul(tokens, EVM_G_TX_DATA_TOKEN_FLOOR),
                                     EVM_G_TX_BASE);
    uint64_t data_cost = evm_gas_mul(tokens, EVM_G_TX_DATA_TOKEN_STANDARD);
    uint64_t create_cost = 0;
    if (tx->is_create)
        create_cost = evm_gas_add(EVM_G_TX_CREATE,
                                  evm_gas_mul(EVM_G_CODE_INIT_PER_WORD,
                                              evm_words((uint64_t)tx->data_len)));
    uint64_t access_cost = 0;
    if (tx->type == 1 || tx->type == 2) {        /* has_access_list */
        for (uint32_t i = 0; i < tx->n_access; i++) {
            access_cost = evm_gas_add(access_cost, EVM_G_TX_ACCESS_LIST_ADDRESS);
            access_cost = evm_gas_add(access_cost,
                evm_gas_mul(tx->access[i].n_keys, EVM_G_TX_ACCESS_LIST_STORAGE_KEY));
        }
    }
    ic->regular = evm_gas_add(EVM_G_TX_BASE,
                  evm_gas_add(data_cost, evm_gas_add(create_cost, access_cost)));
}

static int addr_canonical(const evm_state_t *st, const evm_addr *a)
{
    if (st->cfg.addr_bytes == 32) return 1;
    for (int i = 0; i < 12; i++)
        if (a->b[i] != 0) return 0;
    return 1;
}

static int refuse(evm_tx_result_t *res, evm_tx_error_t e)
{
    res->tx_error = e;
    return -1;
}

void evm_tx_result_free(evm_tx_result_t *r)
{
    if (!r) return;
    free(r->output);
    for (size_t i = 0; i < r->n_logs; i++)
        free(r->logs[i].data);
    free(r->logs);
    r->output = NULL;
    r->output_len = 0;
    r->logs = NULL;
    r->n_logs = 0;
    free(r->tickets);
    r->tickets = NULL;
    r->n_tickets = 0;
}

/* What tx_validate established, consumed by evm_tx_apply. */
typedef struct {
    intrinsic_t ic;
    evm_u256    effective_gas_price;
    evm_acct_t  sacct;               /* sender account (peeked)            */
} tx_checked_t;

/* Common entry checks of evm_tx_apply / evm_tx_prevalidate. */
static int tx_begin(evm_state_t *st, const evm_block_env_t *env,
                    const evm_tx_t *tx, evm_tx_result_t *res)
{
    if (!st || !env || !tx || !res) return EVM_FAULT;
    memset(res, 0, sizeof(*res));
    res->tx_error = EVM_TXERR_NONE;
    res->status = EVM_EXEC_SUCCESS;
    /* the previous tx must have been committed (a fault discards the
     * overlay; reuse after a fault is a caller bug) */
    if (st->n_touched != 0 || st->nj != 0 || st->nlogs != 0 ||
        st->ntickets != 0)
        return EVM_FAULT;
    return 0;
}

/* execution-specs@a87891f7 prague/transactions.py:validate_transaction and
 * fork.py:check_transaction — every check that runs before the first
 * state write. Never writes the overlay (peeks only).
 * @return 0 valid (*ck filled), -1 refused (res->tx_error), -2, -3. */
static int tx_validate(evm_state_t *st, const evm_block_env_t *env,
                       const evm_tx_t *tx, evm_tx_result_t *res,
                       tx_checked_t *ck)
{
    if (tx->type > 2) return refuse(res, EVM_TXERR_TYPE_UNSUPPORTED);
    /* Malformed for its type (cannot be expressed in the reference's
     * transaction classes): a legacy tx has no access list; types 1/2
     * always carry a chain id. */
    if (tx->type == 0 && tx->n_access != 0) return refuse(res, EVM_TXERR_OTHER);
    if (tx->type != 0 && !tx->has_chain_id) return refuse(res, EVM_TXERR_OTHER);
    if ((tx->data_len > 0 && !tx->data) || (tx->n_access > 0 && !tx->access))
        return refuse(res, EVM_TXERR_OTHER);
    for (uint32_t i = 0; i < tx->n_access; i++)
        if (tx->access[i].n_keys > 0 && !tx->access[i].keys)
            return refuse(res, EVM_TXERR_OTHER);
    /* evm.h: in 20-byte mode bytes 0..11 of every address are zero. A
     * non-canonical address would name a different overlay key than the
     * same address taken from the stack (to_address_masked). */
    if (!addr_canonical(st, &tx->sender) ||
        (!tx->is_create && !addr_canonical(st, &tx->to)))
        return refuse(res, EVM_TXERR_OTHER);
    for (uint32_t i = 0; i < tx->n_access; i++)
        if (!addr_canonical(st, &tx->access[i].addr))
            return refuse(res, EVM_TXERR_OTHER);
    if (!addr_canonical(st, &env->coinbase)) return EVM_FAULT;  /* caller bug */

    /* ── validate_transaction ─────────────────────────────────────── */
    intrinsic_t ic;
    calculate_intrinsic_cost(tx, &ic);
    ck->ic = ic;
    uint64_t need = ic.regular > ic.calldata_floor ? ic.regular : ic.calldata_floor;
    if (need > tx->gas_limit) return refuse(res, EVM_TXERR_INTRINSIC_GAS);
    if (tx->is_create && tx->data_len > EVM_L_MAX_INIT_CODE_SIZE)
        return refuse(res, EVM_TXERR_INITCODE_TOO_LARGE);
    if (tx->nonce >= UINT64_MAX) return refuse(res, EVM_TXERR_NONCE_MAX);
    if (tx->type == 2 &&
        evm_u256_cmp(&tx->max_fee_per_gas, &tx->max_priority_fee_per_gas) < 0)
        return refuse(res, EVM_TXERR_PRIORITY_ABOVE_CAP);

    /* ── check_transaction ────────────────────────────────────────── */
    if (st->block_gas_used > env->gas_limit) return EVM_FAULT;
    if (tx->gas_limit > env->gas_limit - st->block_gas_used)
        return refuse(res, EVM_TXERR_GAS_ALLOWANCE);
    /* (blob gas: types 0/1/2 use none) */
    if (tx->has_chain_id && !chain_id_matches(st, tx))
        return refuse(res, EVM_TXERR_CHAIN_ID);

    /* Red-team fix 5: every state-independent refusal (all of the above
     * and the fee checks below) happens before ANY account is read; the
     * state-dependent ones (nonce, balance, EOA) read through the
     * non-mutating evm_st_peek_* functions. A refused tx therefore leaves
     * the overlay byte-identical — no record inserted, no cache filled.
     * The reference's check order is unchanged: the fee checks come after
     * the chain-id check and before the nonce check in check_transaction,
     * and the (pure) sender read between them has no observable effect. */
    evm_u256 effective_gas_price, max_gas_fee;
    int max_fee_overflow;
    if (tx->type == 2) {                     /* FeeMarketCapableTransaction */
        if (evm_u256_cmp(&tx->max_fee_per_gas, &env->base_fee) < 0)
            return refuse(res, EVM_TXERR_FEE_CAP_BELOW_BASE);
        evm_u256 headroom, prio;
        evm_u256_sub(&headroom, &tx->max_fee_per_gas, &env->base_fee);
        prio = evm_u256_cmp(&tx->max_priority_fee_per_gas, &headroom) < 0
               ? tx->max_priority_fee_per_gas : headroom;
        /* prio <= max_fee - base_fee: no overflow */
        evm_u256_add(&effective_gas_price, &prio, &env->base_fee);
        max_fee_overflow = mul_u256_u64(&max_gas_fee, &tx->max_fee_per_gas,
                                        tx->gas_limit);
    } else {
        /* reference: `raise InvalidBlock` (no named error) */
        if (evm_u256_cmp(&tx->gas_price, &env->base_fee) < 0)
            return refuse(res, EVM_TXERR_FEE_CAP_BELOW_BASE);
        effective_gas_price = tx->gas_price;
        max_fee_overflow = mul_u256_u64(&max_gas_fee, &tx->gas_price,
                                        tx->gas_limit);
    }

    const evm_addr *sender = &tx->sender;
    evm_acct_t sacct;
    int sexists;
    EVM_CHECK(evm_st_peek_account(st, sender, &sexists, &sacct));

    if (sacct.nonce > tx->nonce) return refuse(res, EVM_TXERR_NONCE_TOO_LOW);
    if (sacct.nonce < tx->nonce) return refuse(res, EVM_TXERR_NONCE_TOO_HIGH);

    {
        /* Uint(balance) < max_gas_fee + Uint(value); a product or sum past
         * 2^256 exceeds every balance */
        evm_u256 total;
        if (max_fee_overflow ||
            evm_u256_add(&total, &max_gas_fee, &tx->value) ||
            evm_u256_cmp(&sacct.balance, &total) < 0)
            return refuse(res, EVM_TXERR_INSUFFICIENT_FUNDS);
    }
    if (memcmp(sacct.code_hash.b, evm_empty_code_hash.b, 32) != 0) {
        int is_del;
        EVM_CHECK(evm_st_peek_is_delegation(st, sender, &sacct, &is_del));
        if (!is_del) return refuse(res, EVM_TXERR_SENDER_NOT_EOA);
    }
    ck->effective_gas_price = effective_gas_price;
    ck->sacct = sacct;
    return 0;
}

/* A BUDGET verdict where no outcome can be written (before the execution
 * checkpoint, or inside the tail): abandon the tx, overlay unchanged. Any
 * other non-zero is a fault. */
static int abandon(evm_state_t *st, int rc)
{
    if (rc != EVM_BUDGET) return EVM_FAULT;
    if (evm_st_abort_tx(st) != 0) return EVM_FAULT;
    return EVM_BUDGET;
}

int evm_tx_prevalidate(evm_state_t *st, const evm_block_env_t *env,
                       const evm_tx_t *tx, evm_tx_result_t *res)
{
    tx_checked_t ck;
    int rc = tx_begin(st, env, tx, res);
    if (rc != 0) return rc;
    return tx_validate(st, env, tx, res, &ck);
}

/* execution-specs@a87891f7 prague/fork.py:process_transaction (with
 * transactions.py:validate_transaction and fork.py:check_transaction). */
int evm_tx_apply(evm_state_t *st, const evm_block_env_t *env,
                 const evm_tx_t *tx, evm_tx_result_t *res)
{
    tx_checked_t ck;
    int rc = tx_begin(st, env, tx, res);
    if (rc != 0) return rc;
    st->budget_hit = 0;
    rc = tx_validate(st, env, tx, res, &ck);
    if (rc != 0) return rc;               /* -1 / -2 / -3: nothing written */
    const intrinsic_t ic = ck.ic;
    const evm_u256 effective_gas_price = ck.effective_gas_price;
    const evm_acct_t sacct = ck.sacct;
    const evm_addr *sender = &tx->sender;

    /* ── process_transaction ──────────────────────────────────────── */
    evm_u256 effective_gas_fee, bal;
    /* <= max_gas_fee <= balance: cannot overflow */
    if (mul_u256_u64(&effective_gas_fee, &effective_gas_price, tx->gas_limit))
        return EVM_FAULT;
    uint64_t gas = tx->gas_limit - ic.regular;
    rc = evm_st_increment_nonce(st, sender);
    evm_u256_sub(&bal, &sacct.balance, &effective_gas_fee);
    if (rc == 0) rc = evm_st_set_balance(st, sender, &bal);
    if (rc != 0) return abandon(st, rc);

    /* Execution checkpoint (design §3 BUDGET): the nonce increment and the
     * fee debit stay; everything after this mark is reverted when a
     * backend read answers EVM_BUDGET. */
    const size_t exec_mark = evm_st_mark(st);

    /* access_list_addresses / access_list_storage_keys + prepare_message
     * warm set: origin, precompiles, coinbase (EIP-3651), access list,
     * current_target. Set semantics: insertion order is irrelevant. */
    int warm;
    if (evm_st_access_addr(st, &env->coinbase, &warm) != 0) return EVM_FAULT;
    if (tx->type == 1 || tx->type == 2) {
        for (uint32_t i = 0; i < tx->n_access; i++) {
            const evm_access_entry_t *e = &tx->access[i];
            if (evm_st_access_addr(st, &e->addr, &warm) != 0) return EVM_FAULT;
            for (uint32_t k = 0; k < e->n_keys; k++)
                if (evm_st_access_slot(st, &e->addr, &e->keys[k], &warm) != 0)
                    return EVM_FAULT;
        }
    }
    if (evm_st_access_addr(st, sender, &warm) != 0) return EVM_FAULT;
    /* PRE_COMPILED_CONTRACTS.keys(): the configured set (evm.h
     * precompile_mask, red-team fix 7) */
    for (unsigned p = EVM_PRECOMPILE_FIRST; p <= EVM_PRECOMPILE_LAST; p++) {
        if (!((st->cfg.precompile_mask >> p) & 1u)) continue;
        evm_addr pa;
        memset(pa.b, 0, 32);
        pa.b[31] = (uint8_t)p;
        if (evm_st_access_addr(st, &pa, &warm) != 0) return EVM_FAULT;
    }
    /* Nodus: the ticket system address is warm like a precompile (evm.h) */
    if (st->cfg.nodus_profile &&
        evm_st_access_addr(st, &st->cfg.ticket_addr, &warm) != 0)
        return EVM_FAULT;

    evm_tx_env_t txenv;
    memset(&txenv, 0, sizeof(txenv));
    txenv.env = env;
    txenv.origin = *sender;
    txenv.gas_price = effective_gas_price;
    txenv.intent_id = tx->intent_id;

    /* execution-specs@a87891f7 prague/utils/message.py:prepare_message */
    evm_message_t msg;
    memset(&msg, 0, sizeof(msg));
    msg.caller = *sender;
    msg.gas = gas;
    msg.value = tx->value;
    evm_call_output_t out;
    memset(&out, 0, sizeof(out));
    if (tx->is_create) {
        evm_acct_t now;
        /* the sender is in the tx layer (just written): no backend read */
        if (evm_st_get_account(st, sender, &now) != 0) return EVM_FAULT;
        if (now.nonce == 0) return EVM_FAULT;     /* just incremented */
        if (evm_compute_contract_address(st, sender, now.nonce - 1,
                                         &msg.target) != 0)
            return EVM_FAULT;
        msg.is_create = 1;
        msg.data = NULL;
        msg.data_len = 0;
        msg.code = tx->data;
        msg.code_len = tx->data_len;
    } else {
        evm_acct_t tacct;
        evm_acct_empty(&tacct);
        msg.target = tx->to;
        msg.code_address = tx->to;
        msg.data = tx->data;
        msg.data_len = tx->data_len;
        rc = evm_st_get_account(st, &tx->to, &tacct);
        if (rc == 0)
            rc = evm_st_get_code(st, &tx->to, &tacct, &msg.code, &msg.code_len);
        msg.has_code_hash = 1;               /* jump-destination cache key */
        msg.code_hash = tacct.code_hash;
    }
    if (rc == 0 && evm_st_access_addr(st, &msg.target, &warm) != 0)
        return EVM_FAULT;

    if (rc == 0) rc = evm_process_message_call(st, &txenv, &msg, &out);

    /* The sticky flag is the authority (evm_internal.h budget_hit): a
     * BUDGET verdict ends the tx however the frames unwound. */
    if (st->budget_hit) {
        free(out.output);
        evm_st_revert(st, exec_mark);
        memset(&out, 0, sizeof(out));
        out.gas_left = 0;                    /* consumed, as ExceptionalHalt */
        out.refund_counter = 0;
        out.status = EVM_EXEC_BUDGET;
    } else if (rc != 0) {
        return EVM_FAULT;                    /* (-3 never comes unflagged) */
    }

    /* EIP-7623: execution gas incl. refund, then the calldata floor */
    if (out.gas_left > tx->gas_limit || out.refund_counter < 0) {
        free(out.output);
        return EVM_FAULT;                   /* reference: U256(<0) raises */
    }
    uint64_t used_before = tx->gas_limit - out.gas_left;
    uint64_t refund = used_before / 5;
    if ((uint64_t)out.refund_counter < refund) refund = (uint64_t)out.refund_counter;
    uint64_t used_after = used_before - refund;
    if (used_after < ic.calldata_floor) used_after = ic.calldata_floor;
    uint64_t tx_gas_left = tx->gas_limit - used_after;

    evm_u256 refund_amount, prio_fee, fee;
    rc = 0;
    if (mul_u256_u64(&refund_amount, &effective_gas_price, tx_gas_left))
        rc = EVM_FAULT;
    /* non-1559: effective_gas_price == gas_price >= base_fee (checked).
     * Nodus profile (design §10): the caller sets base_fee = gas_price = 0,
     * so refund_amount = fee = 0 and the coinbase receives nothing; the
     * create_ether below still records the coinbase (a no-op entry). */
    evm_u256_sub(&prio_fee, &effective_gas_price, &env->base_fee);
    if (rc == 0 && mul_u256_u64(&fee, &prio_fee, used_after)) rc = EVM_FAULT;
    if (rc == 0) rc = evm_st_create_ether(st, sender, &refund_amount);
    if (rc == 0) rc = evm_st_create_ether(st, &env->coinbase, &fee);
    /* accounts_to_delete is empty when the top frame failed: its additions
     * were rolled back with the frame's journal */
    if (rc == 0) rc = evm_st_destroy_marked(st);
    if (rc != 0) {
        free(out.output);
        return abandon(st, rc);    /* BUDGET in the tail: nothing applied */
    }
    st->block_gas_used += used_after;      /* <= gas_limit - used before */

    res->gas_used = used_after;
    res->gas_used_pre_refund = used_before;
    res->status = out.status;
    res->output = out.output;
    res->output_len = out.output_len;
    if (tx->is_create) res->created = msg.target;
    if (out.status == EVM_EXEC_SUCCESS && st->nlogs > 0) {
        size_t bytes;
        if (evm_size_mul(st->nlogs, sizeof(*res->logs), &bytes) != 0 ||
            !(res->logs = malloc(bytes))) {
            evm_tx_result_free(res);
            return EVM_FAULT;
        }
        memcpy(res->logs, st->logs, bytes);
        res->n_logs = st->nlogs;
        st->nlogs = 0;                      /* ownership moved */
    }
    /* tickets exist only when the top frame succeeded: a failed frame's
     * journal took them back */
    if (out.status == EVM_EXEC_SUCCESS && st->ntickets > 0) {
        size_t bytes;
        if (evm_size_mul(st->ntickets, sizeof(*res->tickets), &bytes) != 0 ||
            !(res->tickets = malloc(bytes))) {
            evm_tx_result_free(res);
            return EVM_FAULT;
        }
        memcpy(res->tickets, st->tickets, bytes);
        res->n_tickets = st->ntickets;
    }
    res->wei_destroyed = st->wei_destroyed;

    if (evm_st_commit_tx(st) != 0) {
        evm_tx_result_free(res);
        return EVM_FAULT;
    }
    return 0;
}
