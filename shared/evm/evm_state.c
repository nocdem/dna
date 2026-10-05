/**
 * @file evm_state.c
 * @brief Journaled state overlay of the Nodus EVM (Nodus EVM phase 1).
 *
 * Port of execution-specs@a87891f7 src/ethereum/forks/prague/state_tracker.py
 * on top of the read-only evm_backend_t (the reference's PreState).
 *
 * Layers (as the reference): reads walk tx layer -> block layer -> backend.
 * The block layer holds the committed transactions of the overlay; the tx
 * layer holds the running transaction.
 *
 * DEVIATION (data structure, not semantics): the reference snapshots the
 * whole TransactionState by copying its dicts (copy_tx_state) and restores
 * the copy on failure (restore_tx_state). Here every tx-layer mutation
 * pushes an undo record to a journal; a snapshot is the journal length and a
 * restore pops records back to it. The reference's per-frame sets that are
 * merged only on success (accessed_addresses, accessed_storage_keys,
 * accounts_to_delete, logs — prague/vm/__init__.py
 * incorporate_child_on_success) ride on the same journal: a frame's mark is
 * taken where the reference copies them into the child message, so a failed
 * frame loses exactly its own additions.
 *
 * DEVIATION (data structure): storage_clears + "drop this tx's writes"
 * (destroy_storage) is implemented with a per-address clear generation: a
 * clear bumps the address's generation to a fresh value from a monotonic
 * counter, which makes every earlier tx-layer write invisible; reverting the
 * clear restores the old generation, which makes them visible again. A
 * generation value is never reused.
 *
 * created_accounts is NOT journaled: the reference shares it between
 * snapshots (copy_tx_state) and documents that the marker survives a reverted
 * creation (mark_account_created docstring).
 *
 * There is no "touched set" in this reference: EIP-161 empty-account removal
 * happens inside modify_state() after every account mutation; ported as-is.
 *
 * Determinism (design §4 D3): every container is an AVL tree keyed by the
 * 32-byte big-endian address / storage key compared with memcmp; the change
 * set is produced by in-order traversal (ascending numeric order). No hash
 * table, no pointer-value ordering. Tree depth is O(log n) so the recursive
 * tree walks are bounded independently of EVM call depth.
 */
#include <stdlib.h>
#include <string.h>

#include "evm_internal.h"
#include "evm_gas.h"
#include "crypto/hash/keccak256.h"
#include "crypto/hash/qgp_sha3.h"

/* ethereum/state.py EMPTY_CODE_HASH = keccak256(b"") */
const evm_bytes32 evm_empty_code_hash = { {
    0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c,
    0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03, 0xc0,
    0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b,
    0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70
} };

enum {
    J_ACCT = 1,       /* tx account write: f0 had, f1 none, acct old      */
    J_CLEAR,          /* storage clear: f0 old cleared, g old generation  */
    J_STORE,          /* tx slot write: f0 old present, g old gen, v old  */
    J_TRANSIENT,      /* transient write: v old                           */
    J_WARM_ADDR,      /* address became warm                              */
    J_WARM_SLOT,      /* slot became warm                                 */
    J_DELETE,         /* accounts_to_delete add                           */
    J_LOG,            /* log appended                                     */
    J_WEI_DESTROYED,  /* wei_destroyed changed: v old value               */
    J_TICKET          /* ticket appended                                  */
};

/* ── small helpers ──────────────────────────────────────────────────── */

static int hash_eq(const evm_bytes32 *a, const evm_bytes32 *b)
{
    return memcmp(a->b, b->b, 32) == 0;
}

void evm_acct_empty(evm_acct_t *a)
{
    memset(a, 0, sizeof(*a));
    a->code_hash = evm_empty_code_hash;
}

/* ethereum/state.py EMPTY_ACCOUNT equality: nonce 0, balance 0, empty code */
int evm_acct_is_empty(const evm_acct_t *a)
{
    return a->nonce == 0 && evm_u256_is_zero(&a->balance) &&
           hash_eq(&a->code_hash, &evm_empty_code_hash);
}

void evm_addr_from_word(const evm_state_t *st, const evm_u256 *w, evm_addr *out)
{
    /* execution-specs@a87891f7 prague/utils/address.py:to_address_masked
     * (20-byte mode); 32-byte mode keeps the whole word (design §2). */
    evm_u256_to_be(out->b, w);
    if (st->cfg.addr_bytes == 20)
        memset(out->b, 0, 12);
}

void evm_addr_to_word(const evm_addr *a, evm_u256 *out)
{
    evm_u256_from_be(out, a->b);
}

int evm_is_precompile(const evm_addr *a)
{
    /* prague/vm/precompiled_contracts/mapping.py: 0x01 .. 0x11. The numeric
     * addresses are the same in both widths (design §2). */
    for (int i = 0; i < 31; i++)
        if (a->b[i] != 0) return 0;
    return a->b[31] >= EVM_PRECOMPILE_FIRST && a->b[31] <= EVM_PRECOMPILE_LAST;
}

int evm_precompile_enabled(const evm_state_t *st, const evm_addr *a)
{
    /* configuration, not build (evm.h precompile_mask) */
    if (!evm_is_precompile(a)) return 0;
    return (st->cfg.precompile_mask >> a->b[31]) & 1u;
}

int evm_grow(void **p, size_t *cap, size_t elem, size_t init)
{
    size_t nc, bytes;
    if (*cap == 0) nc = init;
    else if (*cap > SIZE_MAX / 2) return EVM_FAULT;
    else nc = *cap * 2;
    if (evm_size_mul(nc, elem, &bytes) != 0) return EVM_FAULT;
    void *q = realloc(*p, bytes);
    if (!q) return EVM_FAULT;             /* *p untouched by a failed realloc */
    *p = q;
    *cap = nc;
    return 0;
}

/* ── AVL tree (insert-only; nodes live until evm_state_free) ─────────── */

static int avl_h(const evm_avl_node *n) { return n ? n->h : 0; }

static void avl_fix(evm_avl_node *n)
{
    int hl = avl_h(n->l), hr = avl_h(n->r);
    n->h = (hl > hr ? hl : hr) + 1;
}

static evm_avl_node *avl_rot_right(evm_avl_node *y)
{
    evm_avl_node *x = y->l;
    y->l = x->r;
    x->r = y;
    avl_fix(y);
    avl_fix(x);
    return x;
}

static evm_avl_node *avl_rot_left(evm_avl_node *x)
{
    evm_avl_node *y = x->r;
    x->r = y->l;
    y->l = x;
    avl_fix(x);
    avl_fix(y);
    return y;
}

static evm_avl_node *avl_balance(evm_avl_node *n)
{
    avl_fix(n);
    int bf = avl_h(n->l) - avl_h(n->r);
    if (bf > 1) {
        if (avl_h(n->l->l) < avl_h(n->l->r))
            n->l = avl_rot_left(n->l);
        return avl_rot_right(n);
    }
    if (bf < -1) {
        if (avl_h(n->r->r) < avl_h(n->r->l))
            n->r = avl_rot_right(n->r);
        return avl_rot_left(n);
    }
    return n;
}

/* nn's key is known to be absent. Recursion depth is the tree height,
 * O(log n). */
static evm_avl_node *avl_insert(evm_avl_node *n, evm_avl_node *nn)
{
    if (!n) {
        nn->l = nn->r = NULL;
        nn->h = 1;
        return nn;
    }
    if (memcmp(nn->key, n->key, 32) < 0)
        n->l = avl_insert(n->l, nn);
    else
        n->r = avl_insert(n->r, nn);
    return avl_balance(n);
}

static evm_avl_node *avl_find(evm_avl_node *n, const uint8_t key[32])
{
    while (n) {
        int c = memcmp(key, n->key, 32);
        if (c == 0) return n;
        n = c < 0 ? n->l : n->r;
    }
    return NULL;
}

/* ── records ───────────────────────────────────────────────────────── */

static evm_addr_rec *arec_find(const evm_state_t *st, const evm_addr *addr)
{
    return (evm_addr_rec *)avl_find(st->root, addr->b);
}

static int arec_get(evm_state_t *st, const evm_addr *addr, evm_addr_rec **out)
{
    evm_addr_rec *a = arec_find(st, addr);
    if (!a) {
        a = calloc(1, sizeof(*a));
        if (!a) return EVM_FAULT;
        memcpy(a->node.key, addr->b, 32);
        st->root = avl_insert(st->root, &a->node);
    }
    *out = a;
    return 0;
}

static evm_slot_rec *srec_find(const evm_addr_rec *a, const evm_bytes32 *key)
{
    return (evm_slot_rec *)avl_find(a->slots, key->b);
}

static int srec_get(evm_addr_rec *a, const evm_bytes32 *key, evm_slot_rec **out)
{
    evm_slot_rec *s = srec_find(a, key);
    if (!s) {
        s = calloc(1, sizeof(*s));
        if (!s) return EVM_FAULT;
        memcpy(s->node.key, key->b, 32);
        a->slots = avl_insert(a->slots, &s->node);
    }
    *out = s;
    return 0;
}

static int tx_cur(const evm_state_t *st, const evm_addr_rec *a)
{
    return a->tx_epoch == st->epoch;
}

static int stx_cur(const evm_state_t *st, const evm_slot_rec *s)
{
    return s->tx_epoch == st->epoch;
}

/* Make the address record's tx part current (lazy per-tx reset). */
static int arec_tx(evm_state_t *st, evm_addr_rec *a)
{
    if (tx_cur(st, a)) return 0;
    if (st->n_touched == st->cap_touched) {
        void *p = st->tx_touched;
        if (evm_grow(&p, &st->cap_touched, sizeof(*st->tx_touched), 64) != 0)
            return EVM_FAULT;
        st->tx_touched = p;
    }
    st->tx_touched[st->n_touched++] = a;
    a->tx_epoch = st->epoch;
    a->tx_has_acct = 0;
    a->tx_acct_none = 0;
    a->tx_cleared = 0;
    a->tx_created = 0;
    a->tx_warm = 0;
    a->tx_to_delete = 0;
    a->tx_gen = 0;
    a->tx_nwrites = 0;
    a->n_tx_slots = 0;
    return 0;
}

static int srec_tx(evm_state_t *st, evm_addr_rec *a, evm_slot_rec *s)
{
    if (arec_tx(st, a) != 0) return EVM_FAULT;
    if (stx_cur(st, s)) return 0;
    if (a->n_tx_slots == a->cap_tx_slots) {
        void *p = a->tx_slots;
        if (evm_grow(&p, &a->cap_tx_slots, sizeof(*a->tx_slots), 8) != 0)
            return EVM_FAULT;
        a->tx_slots = p;
    }
    a->tx_slots[a->n_tx_slots++] = s;
    s->tx_epoch = st->epoch;
    s->tx_present = 0;
    s->tx_warm = 0;
    s->tx_gen = 0;
    evm_u256_zero(&s->tx_val);
    evm_u256_zero(&s->tx_transient);
    return 0;
}

static int jpush(evm_state_t *st, evm_journal_entry **e)
{
    if (st->nj == st->capj) {
        void *p = st->j;
        if (evm_grow(&p, &st->capj, sizeof(*st->j), 256) != 0)
            return EVM_FAULT;
        st->j = p;
    }
    *e = &st->j[st->nj++];
    memset(*e, 0, sizeof(**e));
    return 0;
}

/* ── backend boundary ──────────────────────────────────────────────────
 * Every backend callback answer passes through be_rc(): 0 stays 0,
 * EVM_BUDGET (-3) stays -3 and sets the sticky per-tx budget_hit flag
 * (chain integration design §3: the verdict is transaction-wide and no
 * frame can catch it), anything else is a node fault (design §4 D5: never
 * "absent"). The non-mutating peeks (const state) use be_rc_peek(), which
 * maps the same way without the flag: their callers act on the value. */

static int be_rc_peek(int rc)
{
    if (rc == 0) return 0;
    return rc == EVM_BUDGET ? EVM_BUDGET : EVM_FAULT;
}

static int be_rc(evm_state_t *st, int rc)
{
    rc = be_rc_peek(rc);
    if (rc == EVM_BUDGET) st->budget_hit = 1;
    return rc;
}

int evm_st_block_hash(evm_state_t *st, uint64_t number, evm_bytes32 *hash,
                      int *available)
{
    *available = 0;
    return be_rc(st, st->be->get_block_hash(st->be->ctx, number, hash,
                                            available));
}

/* ── backend cache ─────────────────────────────────────────────────── */

static int arec_load_pre(evm_state_t *st, evm_addr_rec *a)
{
    if (a->pre_loaded) return 0;
    evm_account_t acc;
    memset(&acc, 0, sizeof(acc));
    evm_addr addr;
    memcpy(addr.b, a->node.key, 32);
    /* design §4 D5: anything but 0 is a node fault, never "absent" */
    EVM_CHECK(be_rc(st, st->be->get_account(st->be->ctx, &addr, &acc)));
    evm_acct_empty(&a->pre);
    a->pre_exists = acc.exists ? 1 : 0;
    if (acc.exists) {
        int empty_hash = hash_eq(&acc.code_hash, &evm_empty_code_hash);
        /* backend consistency: no code <=> empty code hash */
        if (empty_hash != (acc.code_size == 0))
            return EVM_FAULT;
        a->pre.nonce = acc.nonce;
        a->pre.balance = acc.balance;
        a->pre.code_hash = acc.code_hash;
        a->pre_code_size = acc.code_size;
    }
    a->pre_loaded = 1;
    return 0;
}

static int arec_load_code(evm_state_t *st, evm_addr_rec *a)
{
    if (a->pre_code_loaded) return 0;
    EVM_CHECK(arec_load_pre(st, a));
    if (!a->pre_exists || a->pre_code_size == 0) {
        a->pre_code_loaded = 1;
        return 0;
    }
    size_t cap = a->pre_code_size;
    uint8_t *buf = malloc(cap);
    if (!buf) return EVM_FAULT;
    size_t len = 0;
    evm_addr addr;
    memcpy(addr.b, a->node.key, 32);
    int rc = be_rc(st, st->be->get_code(st->be->ctx, &addr, buf, cap, &len));
    if (rc != 0 || len != cap) {
        free(buf);
        return rc == EVM_BUDGET ? EVM_BUDGET : EVM_FAULT;
    }
    /* The code is NOT re-hashed here: by the get_code contract (evm.h)
     * the backend returns exactly the bytes whose keccak256 is the
     * code_hash its get_account reported, and verifies that itself (the
     * node backend checks the stored SHA3-512 digest and the keccak hash
     * on every read, nodus_witness_rt_evm.c be_get_code). Hashing again
     * cost a full keccak of up to 24 KiB per cold code load (red-team 1
     * bench: acct-extcodecopy-24k). No per-hash cache instead: a cache
     * hit would skip a check a miss performs (cache-symmetry rule). */
    a->pre_code = buf;
    a->pre_code_loaded = 1;
    return 0;
}

static int srec_load_pre(evm_state_t *st, evm_addr_rec *a, evm_slot_rec *s)
{
    if (s->pre_loaded) return 0;
    evm_addr addr;
    evm_bytes32 key, val;
    memcpy(addr.b, a->node.key, 32);
    memcpy(key.b, s->node.key, 32);
    memset(val.b, 0, 32);
    EVM_CHECK(be_rc(st, st->be->get_storage(st->be->ctx, &addr, &key, &val)));
    evm_u256_from_be(&s->pre, val.b);
    s->pre_loaded = 1;
    return 0;
}

/* ── reads ─────────────────────────────────────────────────────────── */

/* execution-specs@a87891f7 prague/state_tracker.py:get_account_optional */
int evm_st_get_account_optional(evm_state_t *st, const evm_addr *addr,
                                int *exists, evm_acct_t *out)
{
    evm_addr_rec *a;
    if (arec_get(st, addr, &a) != 0) return EVM_FAULT;
    if (tx_cur(st, a) && a->tx_has_acct) {
        *exists = !a->tx_acct_none;
        if (*exists) *out = a->tx; else evm_acct_empty(out);
        return 0;
    }
    if (a->blk_has_acct) {
        *exists = !a->blk_acct_none;
        if (*exists) *out = a->blk; else evm_acct_empty(out);
        return 0;
    }
    EVM_CHECK(arec_load_pre(st, a));
    *exists = a->pre_exists;
    if (*exists) *out = a->pre; else evm_acct_empty(out);
    return 0;
}

/* execution-specs@a87891f7 prague/state_tracker.py:get_account */
int evm_st_get_account(evm_state_t *st, const evm_addr *addr, evm_acct_t *out)
{
    int exists;
    return evm_st_get_account_optional(st, addr, &exists, out);
}

/* execution-specs@a87891f7 prague/state_tracker.py:get_code
 * DEVIATION: keyed by (address, account) instead of code hash — see the
 * evm_acct_t comment in evm_internal.h. */
int evm_st_get_code(evm_state_t *st, const evm_addr *addr,
                    const evm_acct_t *acct, const uint8_t **code, size_t *len)
{
    if (hash_eq(&acct->code_hash, &evm_empty_code_hash)) {
        *code = NULL;
        *len = 0;
        return 0;
    }
    if (acct->code) {
        *code = acct->code;
        *len = acct->code_len;
        return 0;
    }
    evm_addr_rec *a;
    if (arec_get(st, addr, &a) != 0) return EVM_FAULT;
    EVM_CHECK(arec_load_code(st, a));
    /* invariant: a code-less non-empty hash is the backend code here */
    if (!a->pre_exists || !hash_eq(&a->pre.code_hash, &acct->code_hash))
        return EVM_FAULT;
    *code = a->pre_code;
    *len = a->pre_code_size;
    return 0;
}

/* execution-specs@a87891f7 prague/state_tracker.py:get_storage */
int evm_st_get_storage(evm_state_t *st, const evm_addr *addr,
                       const evm_bytes32 *key, evm_u256 *out)
{
    evm_addr_rec *a;
    if (arec_get(st, addr, &a) != 0) return EVM_FAULT;
    evm_slot_rec *s = srec_find(a, key);
    if (tx_cur(st, a)) {
        if (s && stx_cur(st, s) && s->tx_present && s->tx_gen == a->tx_gen) {
            *out = s->tx_val;
            return 0;
        }
        if (a->tx_cleared) {
            evm_u256_zero(out);
            return 0;
        }
    }
    if (s && s->blk_has) {
        *out = s->blk;
        return 0;
    }
    if (a->blk_cleared) {
        evm_u256_zero(out);
        return 0;
    }
    if (!s && srec_get(a, key, &s) != 0) return EVM_FAULT;
    EVM_CHECK(srec_load_pre(st, a, s));
    *out = s->pre;
    return 0;
}

/* execution-specs@a87891f7 prague/state_tracker.py:get_storage_original */
int evm_st_get_storage_original(evm_state_t *st, const evm_addr *addr,
                                const evm_bytes32 *key, evm_u256 *out)
{
    evm_addr_rec *a;
    if (arec_get(st, addr, &a) != 0) return EVM_FAULT;
    if (tx_cur(st, a) && a->tx_created) {
        evm_u256_zero(out);
        return 0;
    }
    evm_slot_rec *s = srec_find(a, key);
    if (s && s->blk_has) {
        *out = s->blk;
        return 0;
    }
    if (a->blk_cleared) {
        evm_u256_zero(out);
        return 0;
    }
    if (!s && srec_get(a, key, &s) != 0) return EVM_FAULT;
    EVM_CHECK(srec_load_pre(st, a, s));
    *out = s->pre;
    return 0;
}

/* execution-specs@a87891f7 prague/state_tracker.py:get_transient_storage */
int evm_st_get_transient(evm_state_t *st, const evm_addr *addr,
                         const evm_bytes32 *key, evm_u256 *out)
{
    evm_addr_rec *a = arec_find(st, addr);
    evm_slot_rec *s = a ? srec_find(a, key) : NULL;
    if (a && s && tx_cur(st, a) && stx_cur(st, s))
        *out = s->tx_transient;
    else
        evm_u256_zero(out);
    return 0;
}

/* execution-specs@a87891f7 prague/state_tracker.py:account_exists */
int evm_st_account_exists(evm_state_t *st, const evm_addr *addr, int *out)
{
    evm_acct_t acct;
    return evm_st_get_account_optional(st, addr, out, &acct);
}

/* execution-specs prague/state_tracker.py:account_has_storage as it stood
 * before commit 2ce21915 (parent of 2ce21915; removed there):
 *   tx_state.storage_writes.get(address)          -> non-empty dict
 *   tx_state.parent.storage_writes.get(address)   -> non-empty dict
 *   tx_state.parent.pre_state.account_has_storage(address)
 * A written slot counts even when its value is zero (dict truthiness).
 * The pre-state part is consulted regardless of storage_clears, exactly
 * as the reference does. */
static int account_has_storage(evm_state_t *st, evm_addr_rec *a, int *out)
{
    /* O(1) per check (red-team fix 4): journaled counters of PERSISTENT
     * storage writes only. Transient storage (TSTORE) and warm-only slot
     * records (SLOAD, access lists) never count — the reference checks
     * storage_writes only. */
    /* tx layer: |TransactionState.storage_writes[addr]| (destroy_storage
     * deleted the dict entry -> 0) */
    if (tx_cur(st, a) && a->tx_nwrites > 0) {
        *out = 1;
        return 0;
    }
    /* block layer: BlockState.storage_writes[address] non-empty */
    if (a->blk_nwrites > 0) {
        *out = 1;
        return 0;
    }
    /* pre-state (backend); a fault is never "no storage" (D5) */
    if (!a->pre_storage_loaded) {
        evm_addr addr;
        int has = 0;
        memcpy(addr.b, a->node.key, 32);
        EVM_CHECK(be_rc(st, st->be->has_storage(st->be->ctx, &addr, &has)));
        a->pre_has_storage = has ? 1 : 0;
        a->pre_storage_loaded = 1;
    }
    *out = a->pre_has_storage;
    return 0;
}

/* execution-specs@a87891f7 prague/state_tracker.py:account_deployable
 * DEVIATION: EIP-7610 retained; removed upstream at execution-specs
 * 2ce21915 because unreachable on Ethereum mainnet; Nodus keeps it so
 * CREATE never destroys committed storage (Kurultay nodus-evm-k1, Fable Q1a).
 * Ported from the Prague code removed by 2ce21915: an account that has
 * storage is not deployable. */
int evm_st_account_deployable(evm_state_t *st, const evm_addr *addr, int *out)
{
    evm_acct_t acct;
    EVM_CHECK(evm_st_get_account(st, addr, &acct));
    if (acct.nonce != 0 || !hash_eq(&acct.code_hash, &evm_empty_code_hash)) {
        *out = 0;
        return 0;
    }
    evm_addr_rec *a;
    int has;
    if (arec_get(st, addr, &a) != 0) return EVM_FAULT;
    EVM_CHECK(account_has_storage(st, a, &has));
    *out = !has;
    return 0;
}

/* execution-specs@a87891f7 prague/state_tracker.py:is_account_alive */
int evm_st_is_account_alive(evm_state_t *st, const evm_addr *addr, int *out)
{
    int exists;
    evm_acct_t acct;
    EVM_CHECK(evm_st_get_account_optional(st, addr, &exists, &acct));
    *out = exists && !evm_acct_is_empty(&acct);
    return 0;
}

/* `address in tx_state.created_accounts` */
int evm_st_is_created(evm_state_t *st, const evm_addr *addr, int *out)
{
    evm_addr_rec *a = arec_find(st, addr);
    *out = (a && tx_cur(st, a) && a->tx_created) ? 1 : 0;
    return 0;
}

/* ── writes ────────────────────────────────────────────────────────── */

/* execution-specs@a87891f7 prague/state_tracker.py:set_account */
int evm_st_set_account(evm_state_t *st, const evm_addr *addr,
                       const evm_acct_t *acct)
{
    evm_addr_rec *a;
    evm_journal_entry *e;
    if (arec_get(st, addr, &a) != 0) return EVM_FAULT;
    if (arec_tx(st, a) != 0) return EVM_FAULT;
    if (jpush(st, &e) != 0) return EVM_FAULT;
    e->kind = J_ACCT;
    e->a = a;
    e->f0 = a->tx_has_acct;
    e->f1 = a->tx_acct_none;
    e->acct = a->tx;
    a->tx_has_acct = 1;
    if (acct) {
        a->tx_acct_none = 0;
        a->tx = *acct;
    } else {
        a->tx_acct_none = 1;
        evm_acct_empty(&a->tx);
    }
    return 0;
}

/* execution-specs@a87891f7 prague/state_tracker.py:set_storage */
int evm_st_set_storage(evm_state_t *st, const evm_addr *addr,
                       const evm_bytes32 *key, const evm_u256 *val)
{
    int exists;
    evm_acct_t acct;
    evm_addr_rec *a;
    evm_slot_rec *s;
    evm_journal_entry *e;
    EVM_CHECK(evm_st_get_account_optional(st, addr, &exists, &acct));
    if (!exists) return EVM_FAULT;           /* reference: assert */
    if (arec_get(st, addr, &a) != 0) return EVM_FAULT;
    if (srec_get(a, key, &s) != 0) return EVM_FAULT;
    if (srec_tx(st, a, s) != 0) return EVM_FAULT;
    if (jpush(st, &e) != 0) return EVM_FAULT;
    e->kind = J_STORE;
    e->a = a;
    e->s = s;
    e->f0 = s->tx_present;
    e->g = s->tx_gen;
    e->v = s->tx_val;
    e->c = a->tx_nwrites;
    /* a new key in TransactionState.storage_writes[addr] */
    if (!(s->tx_present && s->tx_gen == a->tx_gen)) a->tx_nwrites++;
    s->tx_present = 1;
    s->tx_gen = a->tx_gen;
    s->tx_val = *val;
    return 0;
}

/* execution-specs@a87891f7 prague/state_tracker.py:destroy_storage */
int evm_st_destroy_storage(evm_state_t *st, const evm_addr *addr)
{
    evm_addr_rec *a;
    evm_journal_entry *e;
    if (arec_get(st, addr, &a) != 0) return EVM_FAULT;
    if (arec_tx(st, a) != 0) return EVM_FAULT;
    if (st->gen_counter == UINT64_MAX) return EVM_FAULT;
    if (jpush(st, &e) != 0) return EVM_FAULT;
    e->kind = J_CLEAR;
    e->a = a;
    e->f0 = a->tx_cleared;
    e->g = a->tx_gen;
    e->c = a->tx_nwrites;
    a->tx_cleared = 1;
    a->tx_gen = ++st->gen_counter;   /* drops this tx's writes (see header) */
    a->tx_nwrites = 0;               /* del tx_state.storage_writes[addr] */
    return 0;
}

/* execution-specs@a87891f7 prague/state_tracker.py:destroy_account
 * Loss journaling (chain integration design §5 rev 3, part (b)): the
 * balance the account still holds when it is deleted leaves existence and
 * is added to wei_destroyed. Callers: evm_st_destroy_marked (end of tx:
 * value received after a SELFDESTRUCT) and modify_commit (EIP-161 — only
 * an EMPTY account is destroyed there, so it adds 0). */
int evm_st_destroy_account(evm_state_t *st, const evm_addr *addr)
{
    evm_acct_t acct;
    EVM_CHECK(evm_st_get_account(st, addr, &acct));
    if (!evm_u256_is_zero(&acct.balance))
        EVM_CHECK(evm_st_add_destroyed(st, &acct.balance));
    if (evm_st_destroy_storage(st, addr) != 0) return EVM_FAULT;
    return evm_st_set_account(st, addr, NULL);
}

/* execution-specs@a87891f7 prague/state_tracker.py:mark_account_created */
int evm_st_mark_account_created(evm_state_t *st, const evm_addr *addr)
{
    evm_addr_rec *a;
    if (arec_get(st, addr, &a) != 0) return EVM_FAULT;
    if (arec_tx(st, a) != 0) return EVM_FAULT;
    a->tx_created = 1;                /* not journaled: see file header */
    return 0;
}

/* execution-specs@a87891f7 prague/state_tracker.py:set_transient_storage
 * (storing zero == popping the key: both read back as zero) */
int evm_st_set_transient(evm_state_t *st, const evm_addr *addr,
                         const evm_bytes32 *key, const evm_u256 *val)
{
    evm_addr_rec *a;
    evm_slot_rec *s;
    evm_journal_entry *e;
    if (arec_get(st, addr, &a) != 0) return EVM_FAULT;
    if (srec_get(a, key, &s) != 0) return EVM_FAULT;
    if (srec_tx(st, a, s) != 0) return EVM_FAULT;
    if (jpush(st, &e) != 0) return EVM_FAULT;
    e->kind = J_TRANSIENT;
    e->a = a;
    e->s = s;
    e->v = s->tx_transient;
    s->tx_transient = *val;
    return 0;
}

/* execution-specs@a87891f7 prague/state_tracker.py:modify_state — the
 * mutation itself is done by the caller on a copy; this is the tail:
 * set_account, then destroy the account if it exists and is empty
 * (EIP-161). */
static int modify_commit(evm_state_t *st, const evm_addr *addr,
                         const evm_acct_t *acct)
{
    if (evm_st_set_account(st, addr, acct) != 0) return EVM_FAULT;
    if (evm_acct_is_empty(acct))
        EVM_CHECK(evm_st_destroy_account(st, addr));
    return 0;
}

/* execution-specs@a87891f7 prague/state_tracker.py:move_ether */
int evm_st_move_ether(evm_state_t *st, const evm_addr *from,
                      const evm_addr *to, const evm_u256 *amount)
{
    evm_acct_t acct;
    EVM_CHECK(evm_st_get_account(st, from, &acct));
    if (evm_u256_cmp(&acct.balance, amount) < 0)
        return EVM_FAULT;             /* reference: raise AssertionError */
    evm_u256_sub(&acct.balance, &acct.balance, amount);
    EVM_CHECK(modify_commit(st, from, &acct));
    EVM_CHECK(evm_st_get_account(st, to, &acct));
    /* U256 overflow raises in the reference: not an outcome -> fault */
    if (evm_u256_add(&acct.balance, &acct.balance, amount)) return EVM_FAULT;
    EVM_CHECK(modify_commit(st, to, &acct));
    return 0;
}

/* execution-specs@a87891f7 prague/state_tracker.py:create_ether */
int evm_st_create_ether(evm_state_t *st, const evm_addr *addr,
                        const evm_u256 *amount)
{
    evm_acct_t acct;
    EVM_CHECK(evm_st_get_account(st, addr, &acct));
    if (evm_u256_add(&acct.balance, &acct.balance, amount)) return EVM_FAULT;
    EVM_CHECK(modify_commit(st, addr, &acct));
    return 0;
}

/* execution-specs@a87891f7 prague/state_tracker.py:set_account_balance */
int evm_st_set_balance(evm_state_t *st, const evm_addr *addr,
                       const evm_u256 *amount)
{
    evm_acct_t acct;
    EVM_CHECK(evm_st_get_account(st, addr, &acct));
    acct.balance = *amount;
    EVM_CHECK(modify_commit(st, addr, &acct));
    return 0;
}

/* execution-specs@a87891f7 prague/state_tracker.py:increment_nonce */
int evm_st_increment_nonce(evm_state_t *st, const evm_addr *addr)
{
    evm_acct_t acct;
    EVM_CHECK(evm_st_get_account(st, addr, &acct));
    /* Callers refuse nonce 2^64-1 before incrementing (validate_transaction,
     * generic_create); reaching it here is a broken invariant. */
    if (acct.nonce == UINT64_MAX) return EVM_FAULT;
    acct.nonce++;
    return modify_commit(st, addr, &acct);
}

/* execution-specs@a87891f7 prague/state_tracker.py:set_code */
int evm_st_set_code(evm_state_t *st, const evm_addr *addr,
                    const uint8_t *code, size_t len)
{
    evm_acct_t acct;
    evm_bytes32 h;
    const uint8_t *blob = NULL;
    if (evm_keccak(code, len, h.b) != 0) return EVM_FAULT;
    if (!hash_eq(&h, &evm_empty_code_hash)) {
        if (evm_st_store_code(st, code, len, &blob) != 0) return EVM_FAULT;
    }
    EVM_CHECK(evm_st_get_account(st, addr, &acct));
    acct.code_hash = h;
    acct.code = blob;
    acct.code_len = blob ? len : 0;
    return modify_commit(st, addr, &acct);
}

/* ── per-tx journaled sets ─────────────────────────────────────────── */

int evm_st_access_addr(evm_state_t *st, const evm_addr *addr, int *was_warm)
{
    evm_addr_rec *a;
    evm_journal_entry *e;
    if (arec_get(st, addr, &a) != 0) return EVM_FAULT;
    if (tx_cur(st, a) && a->tx_warm) {
        *was_warm = 1;
        return 0;
    }
    if (arec_tx(st, a) != 0) return EVM_FAULT;
    if (jpush(st, &e) != 0) return EVM_FAULT;
    e->kind = J_WARM_ADDR;
    e->a = a;
    a->tx_warm = 1;
    *was_warm = 0;
    return 0;
}

int evm_st_access_slot(evm_state_t *st, const evm_addr *addr,
                       const evm_bytes32 *key, int *was_warm)
{
    evm_addr_rec *a;
    evm_slot_rec *s;
    evm_journal_entry *e;
    if (arec_get(st, addr, &a) != 0) return EVM_FAULT;
    if (srec_get(a, key, &s) != 0) return EVM_FAULT;
    if (tx_cur(st, a) && stx_cur(st, s) && s->tx_warm) {
        *was_warm = 1;
        return 0;
    }
    if (srec_tx(st, a, s) != 0) return EVM_FAULT;
    if (jpush(st, &e) != 0) return EVM_FAULT;
    e->kind = J_WARM_SLOT;
    e->a = a;
    e->s = s;
    s->tx_warm = 1;
    *was_warm = 0;
    return 0;
}

int evm_st_add_to_delete(evm_state_t *st, const evm_addr *addr)
{
    evm_addr_rec *a;
    evm_journal_entry *e;
    if (arec_get(st, addr, &a) != 0) return EVM_FAULT;
    if (arec_tx(st, a) != 0) return EVM_FAULT;
    if (a->tx_to_delete) return 0;
    if (jpush(st, &e) != 0) return EVM_FAULT;
    e->kind = J_DELETE;
    e->a = a;
    a->tx_to_delete = 1;
    return 0;
}

int evm_st_add_log(evm_state_t *st, const evm_addr *addr,
                   const evm_bytes32 *topics, unsigned n_topics,
                   const uint8_t *data, size_t len)
{
    evm_journal_entry *e;
    if (n_topics > 4) return EVM_FAULT;
    if (st->nlogs == st->caplogs) {
        void *p = st->logs;
        if (evm_grow(&p, &st->caplogs, sizeof(*st->logs), 16) != 0)
            return EVM_FAULT;
        st->logs = p;
    }
    uint8_t *copy = NULL;
    if (len > 0) {
        copy = malloc(len);
        if (!copy) return EVM_FAULT;
        memcpy(copy, data, len);
    }
    if (jpush(st, &e) != 0) {
        free(copy);
        return EVM_FAULT;
    }
    e->kind = J_LOG;
    evm_log_t *l = &st->logs[st->nlogs++];
    memset(l, 0, sizeof(*l));
    l->addr = *addr;
    l->n_topics = (uint8_t)n_topics;
    for (unsigned i = 0; i < n_topics; i++)
        l->topics[i] = topics[i];
    l->data = copy;
    l->data_len = len;
    return 0;
}

int evm_st_add_destroyed(evm_state_t *st, const evm_u256 *amount)
{
    evm_journal_entry *e;
    evm_u256 sum;
    if (evm_u256_add(&sum, &st->wei_destroyed, amount)) {
        /* Nodus: wei_live <= q * reserve < 2^256, so the sum of what one tx
         * destroys cannot pass 2^256 — reaching it is a broken invariant.
         * Ethereum: fixtures may hold several balances near 2^256; the
         * counter is a result field only and saturates (evm.h). */
        if (st->cfg.nodus_profile) return EVM_FAULT;
        memset(sum.w, 0xff, sizeof(sum.w));
    }
    if (jpush(st, &e) != 0) return EVM_FAULT;
    e->kind = J_WEI_DESTROYED;
    e->v = st->wei_destroyed;
    st->wei_destroyed = sum;
    return 0;
}

/* evm.h evm_ticket_t: domain separator, 16 bytes ("NDS.EVMTKT.v1" + three
 * zero bytes). */
static const uint8_t TICKET_DOMAIN[16] = {
    'N', 'D', 'S', '.', 'E', 'V', 'M', 'T', 'K', 'T', '.', 'v', '1', 0, 0, 0
};

int evm_st_add_ticket(evm_state_t *st, const uint8_t intent_id[64],
                      const evm_u256 *amount, const uint8_t dest_fp[64])
{
    evm_journal_entry *e;
    if (st->ntickets >= UINT32_MAX) return EVM_FAULT;   /* seq is a u32 */
    if (st->ntickets == st->captickets) {
        void *p = st->tickets;
        if (evm_grow(&p, &st->captickets, sizeof(*st->tickets), 4) != 0)
            return EVM_FAULT;
        st->tickets = p;
    }
    uint32_t seq = (uint32_t)st->ntickets;
    uint8_t pre[16 + 64 + 4];
    memcpy(pre, TICKET_DOMAIN, 16);
    memcpy(pre + 16, intent_id, 64);
    pre[80] = (uint8_t)(seq >> 24);
    pre[81] = (uint8_t)(seq >> 16);
    pre[82] = (uint8_t)(seq >> 8);
    pre[83] = (uint8_t)seq;
    evm_ticket_t *t = &st->tickets[st->ntickets];
    memset(t, 0, sizeof(*t));
    if (qgp_sha3_512(pre, sizeof(pre), t->ticket_id) != 0) return EVM_FAULT;
    t->amount_wei = *amount;
    memcpy(t->dest_fp, dest_fp, 64);
    if (jpush(st, &e) != 0) return EVM_FAULT;
    e->kind = J_TICKET;
    st->ntickets++;
    return 0;
}

/* ── journal ───────────────────────────────────────────────────────── */

size_t evm_st_mark(const evm_state_t *st)
{
    return st->nj;
}

/* restore_tx_state(snapshot) equivalent: undo every record above `mark`
 * in reverse order. */
void evm_st_revert(evm_state_t *st, size_t mark)
{
    while (st->nj > mark) {
        evm_journal_entry *e = &st->j[--st->nj];
        switch (e->kind) {
        case J_ACCT:
            e->a->tx_has_acct = e->f0;
            e->a->tx_acct_none = e->f1;
            e->a->tx = e->acct;
            break;
        case J_CLEAR:
            e->a->tx_cleared = e->f0;
            e->a->tx_gen = e->g;
            e->a->tx_nwrites = e->c;
            break;
        case J_STORE:
            e->s->tx_present = e->f0;
            e->s->tx_gen = e->g;
            e->s->tx_val = e->v;
            e->a->tx_nwrites = e->c;
            break;
        case J_TRANSIENT:
            e->s->tx_transient = e->v;
            break;
        case J_WARM_ADDR:
            e->a->tx_warm = 0;
            break;
        case J_WARM_SLOT:
            e->s->tx_warm = 0;
            break;
        case J_DELETE:
            e->a->tx_to_delete = 0;
            break;
        case J_LOG:
            if (st->nlogs > 0) {
                st->nlogs--;
                free(st->logs[st->nlogs].data);
                st->logs[st->nlogs].data = NULL;
            }
            break;
        case J_WEI_DESTROYED:
            st->wei_destroyed = e->v;
            break;
        case J_TICKET:
            if (st->ntickets > 0) st->ntickets--;
            break;
        default:
            break;
        }
    }
}

/* ── transaction lifecycle ─────────────────────────────────────────── */

/* process_transaction: `for address in tx_output.accounts_to_delete:
 * destroy_account(...)`. Order-independent (each destroy touches only its
 * own address); walked in first-touch order, which is execution order. */
int evm_st_destroy_marked(evm_state_t *st)
{
    for (size_t i = 0; i < st->n_touched; i++) {
        evm_addr_rec *a = st->tx_touched[i];
        if (!a->tx_to_delete) continue;
        evm_addr addr;
        memcpy(addr.b, a->node.key, 32);
        EVM_CHECK(evm_st_destroy_account(st, &addr));
    }
    return 0;
}

static void slots_drop_block(evm_avl_node *n)
{
    if (!n) return;
    slots_drop_block(n->l);
    ((evm_slot_rec *)n)->blk_has = 0;
    slots_drop_block(n->r);
}

void evm_st_clear_logs(evm_state_t *st)
{
    for (size_t i = 0; i < st->nlogs; i++) {
        free(st->logs[i].data);
        st->logs[i].data = NULL;
    }
    st->nlogs = 0;
}

/* execution-specs@a87891f7 prague/state_tracker.py:incorporate_tx_into_block */
int evm_st_commit_tx(evm_state_t *st)
{
    for (size_t i = 0; i < st->n_touched; i++) {
        evm_addr_rec *a = st->tx_touched[i];
        if (a->tx_has_acct) {
            a->blk_has_acct = 1;
            a->blk_acct_none = a->tx_acct_none;
            a->blk = a->tx;
        }
        if (a->tx_cleared) {
            a->blk_cleared = 1;
            /* block.storage_writes.pop(address): walks only addresses
             * that hold block writes */
            if (a->blk_nwrites > 0) slots_drop_block(a->slots);
            a->blk_nwrites = 0;
        }
        for (size_t k = 0; k < a->n_tx_slots; k++) {
            evm_slot_rec *s = a->tx_slots[k];
            if (s->tx_present && s->tx_gen == a->tx_gen) {
                if (!s->blk_has) a->blk_nwrites++;
                s->blk_has = 1;
                s->blk = s->tx_val;
            }
        }
    }
    if (st->epoch == UINT64_MAX) return EVM_FAULT;
    st->epoch++;                       /* every tx part becomes stale */
    st->n_touched = 0;
    st->nj = 0;
    evm_st_clear_logs(st);
    st->ntickets = 0;
    evm_u256_zero(&st->wei_destroyed);
    return 0;
}

/* Undoing the whole journal restores every journaled tx-layer field;
 * the epoch bump then makes the remaining (unjournaled) tx parts — e.g.
 * tx_created, which the reference shares across snapshots — stale, so
 * nothing of the abandoned tx is visible to the next one. */
int evm_st_abort_tx(evm_state_t *st)
{
    evm_st_revert(st, 0);
    if (st->epoch == UINT64_MAX) return EVM_FAULT;
    st->epoch++;
    st->n_touched = 0;
    st->nj = 0;
    evm_st_clear_logs(st);
    st->ntickets = 0;
    evm_u256_zero(&st->wei_destroyed);
    return 0;
}

int evm_st_store_code(evm_state_t *st, const uint8_t *code, size_t len,
                      const uint8_t **out)
{
    if (len > SIZE_MAX - sizeof(evm_code_blob)) return EVM_FAULT;
    evm_code_blob *b = malloc(sizeof(*b) + len);
    if (!b) return EVM_FAULT;
    b->len = len;
    if (len) memcpy(b->data, code, len);
    b->next = st->arena;
    st->arena = b;
    *out = b->data;
    return 0;
}

/* ── jump-destination cache (red-team fix 3) ───────────────────────────
 * Keyed by keccak256(code); lives as long as the state; never evicted.
 * A hit returns exactly the bitmap a miss would compute, so results do
 * not depend on the cache — only CPU does. */

const evm_jd_rec *evm_st_jd_find(const evm_state_t *st, const evm_bytes32 *hash)
{
    return (const evm_jd_rec *)avl_find(st->jd_root, hash->b);
}

int evm_st_jd_store(evm_state_t *st, const evm_bytes32 *hash, size_t code_len,
                    uint8_t *bitmap, const evm_jd_rec **out)
{
    evm_jd_rec *r = (evm_jd_rec *)avl_find(st->jd_root, hash->b);
    if (r) {                          /* already cached: identical bitmap */
        free(bitmap);
        *out = r;
        return 0;
    }
    r = calloc(1, sizeof(*r));
    if (!r) {
        free(bitmap);
        return EVM_FAULT;
    }
    memcpy(r->node.key, hash->b, 32);
    r->code_len = code_len;
    r->bitmap = bitmap;
    st->jd_root = avl_insert(st->jd_root, &r->node);
    *out = r;
    return 0;
}

/* ── non-mutating reads (red-team fix 5) ────────────────────────────── */

/* get_account_optional without inserting a record or filling a cache. */
int evm_st_peek_account(const evm_state_t *st, const evm_addr *addr,
                        int *exists, evm_acct_t *out)
{
    const evm_addr_rec *a = arec_find(st, addr);
    if (a && tx_cur(st, a) && a->tx_has_acct) {
        *exists = !a->tx_acct_none;
        if (*exists) *out = a->tx; else evm_acct_empty(out);
        return 0;
    }
    if (a && a->blk_has_acct) {
        *exists = !a->blk_acct_none;
        if (*exists) *out = a->blk; else evm_acct_empty(out);
        return 0;
    }
    if (a && a->pre_loaded) {
        *exists = a->pre_exists;
        if (*exists) *out = a->pre; else evm_acct_empty(out);
        return 0;
    }
    evm_account_t acc;
    memset(&acc, 0, sizeof(acc));
    EVM_CHECK(be_rc_peek(st->be->get_account(st->be->ctx, addr, &acc)));
    evm_acct_empty(out);
    *exists = acc.exists ? 1 : 0;
    if (acc.exists) {
        if (hash_eq(&acc.code_hash, &evm_empty_code_hash) != (acc.code_size == 0))
            return EVM_FAULT;
        out->nonce = acc.nonce;
        out->balance = acc.balance;
        out->code_hash = acc.code_hash;
    }
    return 0;
}

static int is_designator(const uint8_t *code, size_t len)
{
    /* execution-specs@a87891f7 prague/vm/eoa_delegation.py:
     * is_valid_delegation */
    return len == EVM_DELEGATED_CODE_LENGTH &&
           code[0] == 0xef && code[1] == 0x01 && code[2] == 0x00;
}

int evm_st_peek_is_delegation(const evm_state_t *st, const evm_addr *addr,
                              const evm_acct_t *acct, int *is_del)
{
    *is_del = 0;
    if (hash_eq(&acct->code_hash, &evm_empty_code_hash)) return 0;
    if (acct->code) {
        *is_del = is_designator(acct->code, acct->code_len);
        return 0;
    }
    /* backend code of this same address (evm_acct_t invariant) */
    const evm_addr_rec *a = arec_find(st, addr);
    if (a && a->pre_code_loaded) {
        if (!a->pre_exists || !hash_eq(&a->pre.code_hash, &acct->code_hash))
            return EVM_FAULT;
        *is_del = is_designator(a->pre_code, a->pre_code_size);
        return 0;
    }
    evm_account_t acc;
    memset(&acc, 0, sizeof(acc));
    EVM_CHECK(be_rc_peek(st->be->get_account(st->be->ctx, addr, &acc)));
    if (!acc.exists || !hash_eq(&acc.code_hash, &acct->code_hash))
        return EVM_FAULT;
    if (acc.code_size != EVM_DELEGATED_CODE_LENGTH) return 0;
    uint8_t buf[EVM_DELEGATED_CODE_LENGTH];
    size_t len = 0;
    EVM_CHECK(be_rc_peek(st->be->get_code(st->be->ctx, addr, buf, sizeof(buf),
                                          &len)));
    if (len != sizeof(buf)) return EVM_FAULT;
    evm_bytes32 h;
    if (evm_keccak(buf, len, h.b) != 0 || !hash_eq(&h, &acct->code_hash))
        return EVM_FAULT;
    *is_del = is_designator(buf, len);
    return 0;
}

/* ── lifecycle ─────────────────────────────────────────────────────── */

evm_state_t *evm_state_new(const evm_config_t *cfg, const evm_backend_t *be)
{
    if (!cfg || !be || !be->get_account || !be->get_code ||
        !be->get_storage || !be->get_block_hash || !be->has_storage)
        return NULL;
    if (cfg->fork != EVM_FORK_PRAGUE) return NULL;
    if (cfg->addr_bytes != 20 && cfg->addr_bytes != 32) return NULL;
    /* precompile_mask: only bits 1..17 may be set (evm.h) */
    if (cfg->precompile_mask & ~EVM_PRECOMPILES_PRAGUE) return NULL;
    /* Nodus profile (evm.h): the ticket address is no precompile number,
     * canonical for the width, and the ticket unit is non-zero */
    if (cfg->nodus_profile != 0 && cfg->nodus_profile != 1) return NULL;
    if (cfg->nodus_profile) {
        if (evm_is_precompile(&cfg->ticket_addr)) return NULL;
        if (cfg->addr_bytes == 20)
            for (int i = 0; i < 12; i++)
                if (cfg->ticket_addr.b[i] != 0) return NULL;
        if (evm_u256_is_zero(&cfg->ticket_unit)) return NULL;
    }
    evm_state_t *st = calloc(1, sizeof(*st));
    if (!st) return NULL;
    st->cfg = *cfg;
    st->be = be;
    st->epoch = 1;
    return st;
}

static void free_slots(evm_avl_node *n)
{
    if (!n) return;
    free_slots(n->l);
    free_slots(n->r);
    free(n);
}

static void free_addrs(evm_avl_node *n)
{
    if (!n) return;
    free_addrs(n->l);
    free_addrs(n->r);
    evm_addr_rec *a = (evm_addr_rec *)n;
    free_slots(a->slots);
    free(a->tx_slots);
    free(a->pre_code);
    free(a);
}

static void free_jd(evm_avl_node *n)
{
    if (!n) return;
    free_jd(n->l);
    free_jd(n->r);
    free(((evm_jd_rec *)n)->bitmap);
    free(n);
}

void evm_state_free(evm_state_t *st)
{
    if (!st) return;
    free_addrs(st->root);
    free_jd(st->jd_root);
    evm_st_clear_logs(st);
    free(st->logs);
    free(st->tickets);
    free(st->j);
    free(st->tx_touched);
    while (st->arena) {
        evm_code_blob *n = st->arena->next;
        free(st->arena);
        st->arena = n;
    }
    free(st);
}

/* ── canonical change set (design §4 D3) ───────────────────────────── */

typedef struct {
    const evm_state_t *st;
    const evm_change_visitor_t *v;
    const evm_addr_rec *a;
    int rc;
} visit_ctx;

/* "every storage slot whose value differs from the committed value":
 * with storage_cleared the committed baseline is all-zero, so every
 * non-zero slot is reported; otherwise the slot is compared with the
 * backend value. Backend reads in this walk map EVERY non-zero answer,
 * EVM_BUDGET included, to a fault (evm.h evm_state_visit_changes). */
static int visit_slots(visit_ctx *c, const evm_avl_node *n)
{
    if (!n) return 0;
    int rc = visit_slots(c, n->l);
    if (rc) return rc;
    const evm_slot_rec *s = (const evm_slot_rec *)n;
    if (s->blk_has) {
        evm_addr addr;
        evm_bytes32 key, val;
        memcpy(addr.b, c->a->node.key, 32);
        memcpy(key.b, s->node.key, 32);
        int report;
        if (c->a->blk_cleared) {
            report = !evm_u256_is_zero(&s->blk);
        } else {
            evm_u256 base;
            if (s->pre_loaded) {
                base = s->pre;
            } else {
                evm_bytes32 bv;
                memset(bv.b, 0, 32);
                if (c->st->be->get_storage(c->st->be->ctx, &addr, &key, &bv) != 0)
                    return EVM_FAULT;
                evm_u256_from_be(&base, bv.b);
            }
            report = evm_u256_cmp(&base, &s->blk) != 0;
        }
        if (report) {
            evm_u256_to_be(val.b, &s->blk);
            rc = c->v->storage ? c->v->storage(c->v->ctx, &addr, &key, &val) : 0;
            if (rc) return rc;
        }
    }
    return visit_slots(c, n->r);
}

static int visit_addrs(visit_ctx *c, const evm_avl_node *n)
{
    if (!n) return 0;
    int rc = visit_addrs(c, n->l);
    if (rc) return rc;
    const evm_addr_rec *a = (const evm_addr_rec *)n;
    if (a->blk_has_acct || a->blk_cleared || a->blk_nwrites > 0) {
        evm_account_change_t ch;
        memset(&ch, 0, sizeof(ch));
        memcpy(ch.addr.b, a->node.key, 32);
        ch.storage_cleared = a->blk_cleared;

        /* pre-state account (backend) */
        int pre_exists;
        evm_bytes32 pre_hash = evm_empty_code_hash;
        evm_acct_t pre;
        evm_acct_empty(&pre);
        if (a->pre_loaded) {
            pre_exists = a->pre_exists;
            if (pre_exists) pre = a->pre;
        } else {
            evm_account_t acc;
            memset(&acc, 0, sizeof(acc));
            if (c->st->be->get_account(c->st->be->ctx, &ch.addr, &acc) != 0)
                return EVM_FAULT;
            pre_exists = acc.exists ? 1 : 0;
            if (pre_exists) {
                pre.nonce = acc.nonce;
                pre.balance = acc.balance;
                pre.code_hash = acc.code_hash;
            }
        }
        if (pre_exists) pre_hash = pre.code_hash;

        int exists;
        evm_acct_t fin;
        if (a->blk_has_acct) {
            exists = !a->blk_acct_none;
            if (exists) fin = a->blk; else evm_acct_empty(&fin);
        } else {
            exists = pre_exists;
            fin = pre;
        }
        if (!exists) {
            /* Also reported for an address that never existed (the
             * reference writes None + a storage clear for, e.g., a
             * zero-fee coinbase): a no-op for the consumer. */
            ch.deleted = 1;
            ch.code_hash = evm_empty_code_hash;
        } else {
            ch.nonce = fin.nonce;
            ch.balance = fin.balance;
            ch.code_hash = fin.code_hash;
            if (!hash_eq(&fin.code_hash, &pre_hash)) {
                ch.code_changed = 1;
                if (!hash_eq(&fin.code_hash, &evm_empty_code_hash)) {
                    if (!fin.code) return EVM_FAULT;   /* invariant */
                    ch.code = fin.code;
                    ch.code_len = fin.code_len;
                }
            }
        }
        rc = c->v->account ? c->v->account(c->v->ctx, &ch) : 0;
        if (rc) return rc;
        c->a = a;
        rc = visit_slots(c, a->slots);
        if (rc) return rc;
    }
    return visit_addrs(c, n->r);
}

int evm_state_visit_changes(const evm_state_t *st,
                            const evm_change_visitor_t *v)
{
    if (!st || !v) return EVM_FAULT;
    visit_ctx c;
    c.st = st;
    c.v = v;
    c.a = NULL;
    c.rc = 0;
    return visit_addrs(&c, st->root);
}
