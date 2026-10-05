/**
 * @file evm_membackend.c
 * @brief In-memory account set + evm_backend_t — TEST-ONLY. See header.
 */
#include "evm_membackend.h"
#include "evm_mpt.h"
#include "evm_rlp.h"
#include "crypto/hash/keccak256.h"

#include <stdlib.h>
#include <string.h>

void evm_membackend_init(evm_membackend *mb)
{
    memset(mb, 0, sizeof(*mb));
}

void evm_membackend_free(evm_membackend *mb)
{
    if (!mb) return;
    for (size_t i = 0; i < mb->n; i++) {
        free(mb->acc[i].code);
        free(mb->acc[i].slots);
    }
    free(mb->acc);
    memset(mb, 0, sizeof(*mb));
}

int evm_membackend_add_account(evm_membackend *mb, const evm_addr *addr,
                               uint64_t nonce, const uint8_t balance[32],
                               const uint8_t *code, size_t code_len,
                               const evm_bytes32 *code_hash,
                               evm_mem_account **out)
{
    if (mb->n == mb->cap) {
        size_t ncap = mb->cap ? mb->cap * 2 : 16;
        if (ncap > SIZE_MAX / sizeof(evm_mem_account)) return -2;
        evm_mem_account *na = realloc(mb->acc, ncap * sizeof(*na));
        if (!na) return -2;
        mb->acc = na;
        mb->cap = ncap;
    }
    evm_mem_account *a = &mb->acc[mb->n];
    memset(a, 0, sizeof(*a));
    a->addr = *addr;
    a->nonce = nonce;
    memcpy(a->balance, balance, 32);
    if (code_len) {
        a->code = malloc(code_len);
        if (!a->code) return -2;
        memcpy(a->code, code, code_len);
        a->code_len = code_len;
    }
    if (code_hash) {
        a->code_hash = *code_hash;
    } else if (keccak256(code_len ? code : (const uint8_t *)"", code_len,
                         a->code_hash.b) != 0) {
        free(a->code);
        return -2;
    }
    mb->n++;
    mb->finalized = 0;
    if (out) *out = a;
    return 0;
}

static int is_zero32(const uint8_t b[32])
{
    uint8_t acc = 0;
    for (int i = 0; i < 32; i++) acc |= b[i];
    return acc == 0;
}

int evm_mem_account_add_slot(evm_mem_account *a, const evm_bytes32 *key,
                             const evm_bytes32 *val)
{
    if (is_zero32(val->b)) return 0;
    if (a->n_slots == a->cap_slots) {
        size_t ncap = a->cap_slots ? a->cap_slots * 2 : 4;
        if (ncap > SIZE_MAX / sizeof(evm_mem_slot)) return -2;
        evm_mem_slot *ns = realloc(a->slots, ncap * sizeof(*ns));
        if (!ns) return -2;
        a->slots = ns;
        a->cap_slots = ncap;
    }
    a->slots[a->n_slots].key = *key;
    a->slots[a->n_slots].val = *val;
    a->n_slots++;
    return 0;
}

static int acc_cmp(const void *x, const void *y)
{
    const evm_mem_account *a = x, *b = y;
    return memcmp(a->addr.b, b->addr.b, 32);
}

static int slot_cmp(const void *x, const void *y)
{
    const evm_mem_slot *a = x, *b = y;
    return memcmp(a->key.b, b->key.b, 32);
}

int evm_membackend_finalize(evm_membackend *mb)
{
    if (mb->n > 1) qsort(mb->acc, mb->n, sizeof(evm_mem_account), acc_cmp);
    for (size_t i = 0; i < mb->n; i++) {
        if (i > 0 && acc_cmp(&mb->acc[i - 1], &mb->acc[i]) == 0) return -1;
        evm_mem_account *a = &mb->acc[i];
        if (a->n_slots > 1)
            qsort(a->slots, a->n_slots, sizeof(evm_mem_slot), slot_cmp);
        for (size_t j = 1; j < a->n_slots; j++)
            if (slot_cmp(&a->slots[j - 1], &a->slots[j]) == 0) return -1;
    }
    mb->finalized = 1;
    return 0;
}

const evm_mem_account *evm_membackend_find(const evm_membackend *mb,
                                           const evm_addr *addr)
{
    size_t lo = 0, hi = mb->n;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int c = memcmp(mb->acc[mid].addr.b, addr->b, 32);
        if (c == 0) return &mb->acc[mid];
        if (c < 0) lo = mid + 1;
        else hi = mid;
    }
    return NULL;
}

const evm_bytes32 *evm_mem_account_find_slot(const evm_mem_account *a,
                                             const evm_bytes32 *key)
{
    size_t lo = 0, hi = a->n_slots;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int c = memcmp(a->slots[mid].key.b, key->b, 32);
        if (c == 0) return &a->slots[mid].val;
        if (c < 0) lo = mid + 1;
        else hi = mid;
    }
    return NULL;
}

/* ── evm_backend_t callbacks ───────────────────────────────────────── */

static int mb_get_account(void *ctx, const evm_addr *addr, evm_account_t *out)
{
    const evm_membackend *mb = ctx;
    if (!mb->finalized) return -2;
    memset(out, 0, sizeof(*out));
    const evm_mem_account *a = evm_membackend_find(mb, addr);
    if (!a) {
        out->exists = 0;
        evm_u256_zero(&out->balance);
        return keccak256((const uint8_t *)"", 0, out->code_hash.b) == 0
               ? 0 : -2;
    }
    if (a->code_len > UINT32_MAX) return -2;
    out->exists = 1;
    out->nonce = a->nonce;
    evm_u256_from_be(&out->balance, a->balance);
    out->code_hash = a->code_hash;
    out->code_size = (uint32_t)a->code_len;
    return 0;
}

static int mb_get_code(void *ctx, const evm_addr *addr,
                       uint8_t *buf, size_t cap, size_t *len_out)
{
    const evm_membackend *mb = ctx;
    if (!mb->finalized) return -2;
    const evm_mem_account *a = evm_membackend_find(mb, addr);
    if (!a) {
        *len_out = 0;
        return 0;
    }
    if (cap < a->code_len) return -2;
    if (a->code_len) memcpy(buf, a->code, a->code_len);
    *len_out = a->code_len;
    return 0;
}

static int mb_get_storage(void *ctx, const evm_addr *addr,
                          const evm_bytes32 *key, evm_bytes32 *val_out)
{
    const evm_membackend *mb = ctx;
    if (!mb->finalized) return -2;
    memset(val_out, 0, sizeof(*val_out));
    const evm_mem_account *a = evm_membackend_find(mb, addr);
    if (!a) return 0;
    const evm_bytes32 *v = evm_mem_account_find_slot(a, key);
    if (v) *val_out = *v;
    return 0;
}

static int mb_get_block_hash(void *ctx, uint64_t number,
                             evm_bytes32 *hash_out, int *available)
{
    const evm_membackend *mb = ctx;
    memset(hash_out, 0, sizeof(*hash_out));
    if (number == 0 && mb->has_block0_hash) {
        *hash_out = mb->block0_hash;
        *available = 1;
    } else {
        *available = 0;
    }
    return 0;
}

/* Pre-state account_has_storage: any non-zero slot at the address (zero
 * slots are never stored: evm_mem_account_add_slot drops them). */
static int mb_has_storage(void *ctx, const evm_addr *addr, int *out)
{
    const evm_membackend *mb = ctx;
    if (!mb->finalized) return -2;
    const evm_mem_account *a = evm_membackend_find(mb, addr);
    *out = (a && a->n_slots > 0) ? 1 : 0;
    return 0;
}

void evm_membackend_bind(const evm_membackend *mb, evm_backend_t *be)
{
    be->ctx = (void *)(uintptr_t)mb;   /* callbacks only read through ctx */
    be->get_account = mb_get_account;
    be->get_code = mb_get_code;
    be->get_storage = mb_get_storage;
    be->get_block_hash = mb_get_block_hash;
    be->has_storage = mb_has_storage;
}

/* ── state root ─────────────────────────────────────────────────────── */

static int storage_root(const evm_mem_account *a, uint8_t root[32])
{
    int rc = 0;
    evm_mpt_kv *kv = NULL;
    evm_rlp_buf vals = {0};
    size_t *off = NULL;
    if (a->n_slots) {
        kv = malloc(a->n_slots * sizeof(*kv));
        off = malloc((a->n_slots + 1) * sizeof(*off));
        if (!kv || !off) { rc = -2; goto out; }
        for (size_t i = 0; i < a->n_slots; i++) {
            off[i] = vals.len;
            if (evm_rlp_put_uint_be(&vals, a->slots[i].val.b, 32) != 0) {
                rc = -2;
                goto out;
            }
        }
        off[a->n_slots] = vals.len;
        for (size_t i = 0; i < a->n_slots; i++) {
            kv[i].key = a->slots[i].key.b;
            kv[i].key_len = 32;
            kv[i].val = vals.p + off[i];
            kv[i].val_len = off[i + 1] - off[i];
        }
    }
    rc = evm_mpt_root(kv, a->n_slots, 1, root);
out:
    free(kv);
    free(off);
    evm_rlp_buf_free(&vals);
    return rc;
}

int evm_membackend_state_root(const evm_membackend *mb, unsigned addr_bytes,
                              uint8_t root[32])
{
    if (addr_bytes != 20 && addr_bytes != 32) return -1;
    if (!mb->finalized) return -1;
    int rc = 0;
    evm_mpt_kv *kv = NULL;
    size_t *off = NULL;
    evm_rlp_buf vals = {0};
    if (mb->n) {
        kv = malloc(mb->n * sizeof(*kv));
        off = malloc((mb->n + 1) * sizeof(*off));
        if (!kv || !off) { rc = -2; goto out; }
        for (size_t i = 0; i < mb->n; i++) {
            const evm_mem_account *a = &mb->acc[i];
            uint8_t sroot[32];
            if ((rc = storage_root(a, sroot)) != 0) goto out;
            off[i] = vals.len;
            size_t start = vals.len;
            if (evm_rlp_put_u64(&vals, a->nonce) != 0 ||
                evm_rlp_put_uint_be(&vals, a->balance, 32) != 0 ||
                evm_rlp_put_bytes(&vals, sroot, 32) != 0 ||
                evm_rlp_put_bytes(&vals, a->code_hash.b, 32) != 0 ||
                evm_rlp_wrap_list(&vals, start) != 0) {
                rc = -2;
                goto out;
            }
        }
        off[mb->n] = vals.len;
        for (size_t i = 0; i < mb->n; i++) {
            kv[i].key = mb->acc[i].addr.b + (32 - addr_bytes);
            kv[i].key_len = addr_bytes;
            kv[i].val = vals.p + off[i];
            kv[i].val_len = off[i + 1] - off[i];
        }
    }
    rc = evm_mpt_root(kv, mb->n, 1, root);
out:
    free(kv);
    free(off);
    evm_rlp_buf_free(&vals);
    return rc;
}
