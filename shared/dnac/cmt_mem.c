/**
 * @file shared/dnac/cmt_mem.c
 * @brief cometbft @709fd12b's Flood mempool in C — see the header for the
 *        synchronous-client statement that shapes every function below.
 *
 * Layout follows the reference files: config, errors, tx.go, mempoolTx,
 * the index (C-only), cache.go, ids.go, then clist_mempool.go in file
 * order with the recheck cursor last. Every function names its Go lines.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dnac/cmt_mem.h"

#include "crypto/utils/qgp_log.h"

#include <stdlib.h>
#include <string.h>

#define LOG_TAG "CMT_MEM"

/* ══ config/config.go ═════════════════════════════════════════════════ */

/* config.go:786-803 — DefaultMempoolConfig() */
int cmt_mempool_config_default(cmt_mempool_config_t *out)
{
    if (out == NULL) {
        return CMT_FAULT;
    }
    memset(out, 0, sizeof(*out));
    out->type            = CMT_MEMPOOL_TYPE_FLOOD;               /* :789 */
    out->recheck         = true;                                 /* :790 */
    out->recheck_timeout = (int64_t)1000 * (int64_t)1000000;     /* :791 1000 ms */
    out->broadcast       = true;                                 /* :792 */
    /* :793 WalPath "" — no field (header) */
    out->size            = 5000;                                 /* :796 */
    out->max_txs_bytes   = (int64_t)1024 * 1024 * 1024;          /* :797 1 GB */
    out->cache_size      = 10000;                                /* :798 */
    out->max_tx_bytes    = 1024 * 1024;                          /* :799 1 MB */
    out->experimental_max_gossip_connections_to_non_persistent_peers = 0; /* :800 */
    out->experimental_max_gossip_connections_to_persistent_peers     = 0; /* :801 */
    return CMT_OK;
}

/* config.go:824-850 — (*MempoolConfig) ValidateBasic() */
int cmt_mempool_config_validate_basic(const cmt_mempool_config_t *cfg)
{
    if (cfg == NULL) {
        return CMT_FAULT;
    }
    switch (cfg->type) {                                         /* :825 */
    case CMT_MEMPOOL_TYPE_FLOOD:                                 /* :826 */
    case CMT_MEMPOOL_TYPE_NOP:
    case CMT_MEMPOOL_TYPE_EMPTY:                                 /* :827 */
        break;
    default:
        return CMT_REJECT;                                       /* :829 */
    }
    if (cfg->size < 0) {                                         /* :831-833 */
        return CMT_REJECT;
    }
    if (cfg->max_txs_bytes < 0) {                                /* :834-836 */
        return CMT_REJECT;
    }
    if (cfg->cache_size < 0) {                                   /* :837-839 */
        return CMT_REJECT;
    }
    if (cfg->max_tx_bytes < 0) {                                 /* :840-842 */
        return CMT_REJECT;
    }
    if (cfg->experimental_max_gossip_connections_to_persistent_peers < 0) {
        return CMT_REJECT;                                       /* :843-845 */
    }
    if (cfg->experimental_max_gossip_connections_to_non_persistent_peers < 0) {
        return CMT_REJECT;                                       /* :846-848 */
    }
    return CMT_OK;                                               /* :849 */
}

/* ══ types/tx.go ══════════════════════════════════════════════════════ */

/* types/tx.go:33-35 — (tx Tx) Key(); SHA3-512 here (header). */
int cmt_mem_tx_key(const uint8_t *tx, size_t tx_len,
                   uint8_t out[CMT_MEM_TX_KEY_SIZE])
{
    return cmt_tx_hash(tx, tx_len, out);
}

/* types/tx.go:186-192 — ComputeProtoSizeForTxs(txs) */
int64_t cmt_mem_compute_proto_size_for_txs(const cmt_pb_bytes_t *txs,
                                           size_t n)
{
    int64_t size = 0;
    size_t  k;

    if (txs == NULL) {
        return 0;
    }
    for (k = 0; k < n; k++) {
        /* One length-delimited field-1 element per tx: tag (1 byte),
         * uvarint(len), the bytes — types.pb.go's Data.Size shape,
         * identical to mempool/types.pb.go:267-272. */
        size += 1 + (int64_t)cmt_pb_uvarint_size((uint64_t)txs[k].len) +
                (int64_t)txs[k].len;
    }
    return size;
}

/* ══ mempool/mempool.go:104-146 — the two filter constructors ═════════ */

/* mempool.go:117-124 — the closure of PreCheckMaxBytes */
int cmt_mem_pre_check_max_bytes_fn(void *ctx, const uint8_t *tx,
                                   size_t tx_len)
{
    const cmt_mem_pre_check_max_bytes_t *p =
        (const cmt_mem_pre_check_max_bytes_t *)ctx;
    cmt_pb_bytes_t one;
    int64_t        tx_size;

    if (p == NULL || (tx == NULL && tx_len != 0)) {
        return CMT_FAULT;
    }
    one.data = tx;
    one.len  = tx_len;
    tx_size  = cmt_mem_compute_proto_size_for_txs(&one, 1);       /* :118 */
    if (tx_size > p->max_bytes) {                                  /* :120 */
        return CMT_REJECT;   /* "tx size is too big: %d, max: %d" :121 */
    }
    return CMT_OK;                                                 /* :124 */
}

/* mempool.go:116-126 — PreCheckMaxBytes(maxBytes) */
int cmt_mem_pre_check_max_bytes(int64_t max_bytes,
                                cmt_mem_pre_check_max_bytes_t *storage,
                                cmt_mem_pre_check_t *out)
{
    if (storage == NULL || out == NULL) {
        return CMT_FAULT;
    }
    storage->max_bytes = max_bytes;
    out->fn  = cmt_mem_pre_check_max_bytes_fn;
    out->ctx = storage;
    return CMT_OK;
}

/* mempool.go:131-145 — the closure of PostCheckMaxGas */
int cmt_mem_post_check_max_gas_fn(void *ctx, const uint8_t *tx,
                                  size_t tx_len,
                                  const cmt_mem_response_check_tx_t *res)
{
    const cmt_mem_post_check_max_gas_t *p =
        (const cmt_mem_post_check_max_gas_t *)ctx;

    (void)tx;
    (void)tx_len;
    if (p == NULL || res == NULL) {
        return CMT_FAULT;
    }
    if (p->max_gas == -1) {                                        /* :132-134 */
        return CMT_OK;
    }
    if (res->gas_wanted < 0) {                                     /* :135-138 */
        return CMT_REJECT;   /* "gas wanted %d is negative" */
    }
    if (res->gas_wanted > p->max_gas) {                            /* :139-142 */
        return CMT_REJECT;   /* "gas wanted %d is greater than max gas %d" */
    }
    return CMT_OK;                                                 /* :144 */
}

/* mempool.go:130-146 — PostCheckMaxGas(maxGas) */
int cmt_mem_post_check_max_gas(int64_t max_gas,
                               cmt_mem_post_check_max_gas_t *storage,
                               cmt_mem_post_check_t *out)
{
    if (storage == NULL || out == NULL) {
        return CMT_FAULT;
    }
    storage->max_gas = max_gas;
    out->fn  = cmt_mem_post_check_max_gas_fn;
    out->ctx = storage;
    return CMT_OK;
}

/* ══ mempool/errors.go ════════════════════════════════════════════════ */

void cmt_mem_error_init(cmt_mem_error_t *e)
{
    if (e != NULL) {
        memset(e, 0, sizeof(*e));
        e->kind = CMT_MEM_ERR_NONE;
    }
}

/* errors.go:63-65 — IsPreCheckError(err) */
bool cmt_mem_is_pre_check_error(const cmt_mem_error_t *e)
{
    return e != NULL && e->kind == CMT_MEM_ERR_PRE_CHECK;
}

static void err_set_kind(cmt_mem_error_t *e, cmt_mem_err_kind_t kind)
{
    if (e != NULL) {
        cmt_mem_error_init(e);
        e->kind = kind;
    }
}

/* ══ mempool/mempoolTx.go ═════════════════════════════════════════════ */

/* mempoolTx.go:22-24 — Height() */
int64_t cmt_mem_tx_height(const cmt_mem_tx_t *tx)
{
    return (tx == NULL) ? 0 : tx->height;
}

/* mempoolTx.go:26-29 — isSender(peerID) */
bool cmt_mem_tx_is_sender(const cmt_mem_tx_t *tx, uint16_t peer_id)
{
    if (tx == NULL) {
        return false;
    }
    return (tx->senders[peer_id >> 3] & (uint8_t)(1u << (peer_id & 7u))) != 0;
}

/* mempoolTx.go:31-34 — addSender(senderID): LoadOrStore's `loaded`. */
bool cmt_mem_tx_add_sender(cmt_mem_tx_t *tx, uint16_t sender_id)
{
    bool loaded;

    if (tx == NULL) {
        return false;
    }
    loaded = cmt_mem_tx_is_sender(tx, sender_id);
    tx->senders[sender_id >> 3] |= (uint8_t)(1u << (sender_id & 7u));
    return loaded;
}

/* clist_mempool.go:439-443 — the allocation of a mempoolTx, with the
 * bytes copied into the same block. */
static cmt_mem_tx_t *mem_tx_new(int64_t height, int64_t gas_wanted,
                                const uint8_t *tx, size_t tx_len)
{
    cmt_mem_tx_t *m;

    m = (cmt_mem_tx_t *)calloc(1, sizeof(*m) + tx_len);
    if (m == NULL) {
        return NULL;
    }
    m->height     = height;                                        /* :440 */
    m->gas_wanted = gas_wanted;                                    /* :441 */
    m->tx         = (uint8_t *)(m + 1);                            /* :442 */
    m->tx_len     = tx_len;
    if (tx_len != 0) {
        memcpy(m->tx, tx, tx_len);
    }
    return m;
}

/* The CList's value destructor (cmt_clist.h "Value"). */
static void mem_tx_free_value(void *ctx, void *value)
{
    (void)ctx;
    free(value);
}

/* ══ the index (C-only; the shape behind both Go maps) ════════════════ */

static size_t index_hash(const cmt_mem_index_t *ix,
                         const uint8_t key[CMT_MEM_TX_KEY_SIZE])
{
    uint64_t h = 0;
    int      k;

    for (k = 0; k < 8; k++) {
        h = (h << 8) | (uint64_t)key[k];
    }
    return (size_t)(h & (uint64_t)(ix->cap - 1u));
}

/* Capacity: a power of two holding `want` entries at half load. */
static int index_init(cmt_mem_index_t *ix, size_t want)
{
    size_t cap = 16;

    while (cap < 2u * (want + 1u)) {
        if (cap > ((size_t)-1) / 2u) {
            return CMT_FAULT;
        }
        cap *= 2u;
    }
    ix->entries = (cmt_mem_index_entry_t *)calloc(cap, sizeof(*ix->entries));
    if (ix->entries == NULL) {
        return CMT_FAULT;
    }
    ix->cap   = cap;
    ix->count = 0;
    return CMT_OK;
}

static void index_free(cmt_mem_index_t *ix)
{
    free(ix->entries);
    ix->entries = NULL;
    ix->cap     = 0;
    ix->count   = 0;
}

static void index_clear(cmt_mem_index_t *ix)
{
    if (ix->entries != NULL) {
        memset(ix->entries, 0, ix->cap * sizeof(*ix->entries));
    }
    ix->count = 0;
}

/* The slot holding `key`, or SIZE_MAX. */
static size_t index_find(const cmt_mem_index_t *ix,
                         const uint8_t key[CMT_MEM_TX_KEY_SIZE])
{
    size_t i;
    size_t n;

    if (ix->entries == NULL) {
        return (size_t)-1;
    }
    i = index_hash(ix, key);
    for (n = 0; n < ix->cap; n++) {
        const cmt_mem_index_entry_t *e = &ix->entries[i];

        if (!e->used) {
            return (size_t)-1;
        }
        if (memcmp(e->key, key, CMT_MEM_TX_KEY_SIZE) == 0) {
            return i;
        }
        i = (i + 1u) & (ix->cap - 1u);
    }
    return (size_t)-1;
}

static void *index_load(const cmt_mem_index_t *ix,
                        const uint8_t key[CMT_MEM_TX_KEY_SIZE])
{
    size_t i = index_find(ix, key);

    return (i == (size_t)-1) ? NULL : ix->entries[i].val;
}

/* Insert or replace. CMT_FAULT when the table is full — the caller
 * sized it for its bound, so that is a bookkeeping defect. */
static int index_store(cmt_mem_index_t *ix,
                       const uint8_t key[CMT_MEM_TX_KEY_SIZE], void *val)
{
    size_t i;
    size_t n;

    if (ix->entries == NULL) {
        return CMT_FAULT;
    }
    i = index_hash(ix, key);
    for (n = 0; n < ix->cap; n++) {
        cmt_mem_index_entry_t *e = &ix->entries[i];

        if (!e->used) {
            memcpy(e->key, key, CMT_MEM_TX_KEY_SIZE);
            e->val  = val;
            e->used = true;
            ix->count++;
            return CMT_OK;
        }
        if (memcmp(e->key, key, CMT_MEM_TX_KEY_SIZE) == 0) {
            e->val = val;
            return CMT_OK;
        }
        i = (i + 1u) & (ix->cap - 1u);
    }
    return CMT_FAULT;
}

/* Delete with backward shift (no tombstones): every entry after the
 * hole whose home slot lies at or before the hole moves into it. */
static void index_delete(cmt_mem_index_t *ix,
                         const uint8_t key[CMT_MEM_TX_KEY_SIZE])
{
    size_t i = index_find(ix, key);
    size_t j;
    size_t mask;

    if (i == (size_t)-1) {
        return;
    }
    mask = ix->cap - 1u;
    ix->entries[i].used = false;
    ix->entries[i].val  = NULL;
    ix->count--;
    j = i;
    for (;;) {
        size_t k;
        bool   movable;

        j = (j + 1u) & mask;
        if (!ix->entries[j].used) {
            return;
        }
        k = index_hash(ix, ix->entries[j].key);
        /* The entry at j may move to i iff its home k is not cyclically
         * in (i, j]. */
        if (j > i) {
            movable = (k <= i) || (k > j);
        } else {
            movable = (k <= i) && (k > j);
        }
        if (movable) {
            ix->entries[i] = ix->entries[j];
            ix->entries[j].used = false;
            ix->entries[j].val  = NULL;
            i = j;
        }
    }
}

/* ══ mempool/cache.go ═════════════════════════════════════════════════ */

static void lru_unlink(cmt_mem_lru_tx_cache_t *c, cmt_mem_lru_node_t *n)
{
    if (n->prev != NULL) {
        n->prev->next = n->next;
    } else {
        c->front = n->next;
    }
    if (n->next != NULL) {
        n->next->prev = n->prev;
    } else {
        c->back = n->prev;
    }
    n->prev = NULL;
    n->next = NULL;
}

/* container/list PushBack: newest at the back. */
static void lru_push_back(cmt_mem_lru_tx_cache_t *c, cmt_mem_lru_node_t *n)
{
    n->prev = c->back;
    n->next = NULL;
    if (c->back != NULL) {
        c->back->next = n;
    } else {
        c->front = n;
    }
    c->back = n;
}

static void lru_rebuild_free_list(cmt_mem_lru_tx_cache_t *c)
{
    size_t k;

    c->free_list = NULL;
    for (k = c->nodes_cap; k > 0; k--) {
        cmt_mem_lru_node_t *n = &c->nodes[k - 1];

        n->in_use = false;
        n->prev   = NULL;
        n->next   = c->free_list;
        c->free_list = n;
    }
}

/* cache.go:42-48 — NewLRUTxCache(cacheSize) */
int cmt_mem_lru_tx_cache_init(cmt_mem_lru_tx_cache_t *c, int cache_size)
{
    if (c == NULL || cache_size < 0) {
        return CMT_FAULT;
    }
    memset(c, 0, sizeof(*c));
    c->size      = cache_size;                                     /* :44 */
    c->nodes_cap = (cache_size > 0) ? (size_t)cache_size : 1u;
    c->nodes = (cmt_mem_lru_node_t *)calloc(c->nodes_cap, sizeof(*c->nodes));
    if (c->nodes == NULL) {
        return CMT_FAULT;
    }
    if (index_init(&c->map, c->nodes_cap) != CMT_OK) {             /* :45 */
        free(c->nodes);
        c->nodes = NULL;
        return CMT_FAULT;
    }
    lru_rebuild_free_list(c);                                      /* :46 */
    return CMT_OK;
}

void cmt_mem_lru_tx_cache_free(cmt_mem_lru_tx_cache_t *c)
{
    if (c == NULL) {
        return;
    }
    index_free(&c->map);
    free(c->nodes);
    memset(c, 0, sizeof(*c));
}

/* cache.go:56-62 — Reset() */
void cmt_mem_lru_tx_cache_reset(cmt_mem_lru_tx_cache_t *c)
{
    if (c == NULL || c->nodes == NULL) {
        return;
    }
    index_clear(&c->map);                                          /* :60 */
    c->front = NULL;                                               /* :61 */
    c->back  = NULL;
    c->len   = 0;
    lru_rebuild_free_list(c);
}

/* cache.go:64-89 — Push(tx) */
bool cmt_mem_lru_tx_cache_push(cmt_mem_lru_tx_cache_t *c,
                               const uint8_t *tx, size_t tx_len)
{
    uint8_t             key[CMT_MEM_TX_KEY_SIZE];
    cmt_mem_lru_node_t *moved;
    cmt_mem_lru_node_t *n;

    if (c == NULL || c->nodes == NULL) {
        return false;
    }
    if (cmt_mem_tx_key(tx, tx_len, key) != CMT_OK) {                /* :68 */
        return false;
    }
    moved = (cmt_mem_lru_node_t *)index_load(&c->map, key);        /* :70 */
    if (moved != NULL) {                                           /* :71 */
        lru_unlink(c, moved);                                      /* :72 MoveToBack */
        lru_push_back(c, moved);
        return false;                                              /* :73 */
    }
    if (c->len >= c->size) {                                       /* :76 */
        cmt_mem_lru_node_t *front = c->front;                      /* :77 */

        if (front != NULL) {                                       /* :78 */
            index_delete(&c->map, front->key);                     /* :80 */
            lru_unlink(c, front);                                  /* :81 */
            front->in_use = false;
            front->next   = c->free_list;
            c->free_list  = front;
            c->len--;
        }
    }
    n = c->free_list;
    if (n == NULL) {
        /* Node storage is sized for exactly this bound; running out is
         * a bookkeeping defect of this file. */
        QGP_LOG_ERROR(LOG_TAG, "lru cache: node storage exhausted");
        return false;
    }
    c->free_list = n->next;
    n->in_use    = true;
    memcpy(n->key, key, CMT_MEM_TX_KEY_SIZE);
    lru_push_back(c, n);                                           /* :85 */
    if (index_store(&c->map, key, n) != CMT_OK) {                  /* :86 */
        lru_unlink(c, n);
        n->in_use    = false;
        n->next      = c->free_list;
        c->free_list = n;
        QGP_LOG_ERROR(LOG_TAG, "lru cache: index full");
        return false;
    }
    c->len++;
    return true;                                                   /* :88 */
}

/* cache.go:91-102 — Remove(tx) */
void cmt_mem_lru_tx_cache_remove(cmt_mem_lru_tx_cache_t *c,
                                 const uint8_t *tx, size_t tx_len)
{
    uint8_t             key[CMT_MEM_TX_KEY_SIZE];
    cmt_mem_lru_node_t *e;

    if (c == NULL || c->nodes == NULL) {
        return;
    }
    if (cmt_mem_tx_key(tx, tx_len, key) != CMT_OK) {                /* :95 */
        return;
    }
    e = (cmt_mem_lru_node_t *)index_load(&c->map, key);            /* :96 */
    index_delete(&c->map, key);                                    /* :97 */
    if (e != NULL) {                                               /* :99 */
        lru_unlink(c, e);                                          /* :100 */
        e->in_use    = false;
        e->next      = c->free_list;
        c->free_list = e;
        c->len--;
    }
}

/* cache.go:104-111 — Has(tx) */
bool cmt_mem_lru_tx_cache_has(const cmt_mem_lru_tx_cache_t *c,
                              const uint8_t *tx, size_t tx_len)
{
    uint8_t key[CMT_MEM_TX_KEY_SIZE];

    if (c == NULL || c->nodes == NULL) {
        return false;
    }
    if (cmt_mem_tx_key(tx, tx_len, key) != CMT_OK) {
        return false;
    }
    return index_load(&c->map, key) != NULL;                       /* :108-109 */
}

int cmt_mem_lru_tx_cache_len(const cmt_mem_lru_tx_cache_t *c)
{
    return (c == NULL) ? 0 : c->len;
}

/* cache.go:52-54 — GetList(): the test walk. */
const cmt_mem_lru_node_t *cmt_mem_lru_tx_cache_front(
        const cmt_mem_lru_tx_cache_t *c)
{
    return (c == NULL) ? NULL : c->front;
}

const cmt_mem_lru_node_t *cmt_mem_lru_node_next(const cmt_mem_lru_node_t *n)
{
    return (n == NULL) ? NULL : n->next;
}

const uint8_t *cmt_mem_lru_node_key(const cmt_mem_lru_node_t *n)
{
    return (n == NULL) ? NULL : n->key;
}

/* cache.go:15-29 dispatch; :113-120 NopTxCache */
void cmt_mem_tx_cache_reset(cmt_mem_tx_cache_t *c)
{
    if (c != NULL && c->kind == CMT_MEM_TX_CACHE_LRU) {
        cmt_mem_lru_tx_cache_reset(&c->lru);
    }
    /* :117 NopTxCache.Reset — nothing */
}

bool cmt_mem_tx_cache_push(cmt_mem_tx_cache_t *c, const uint8_t *tx,
                           size_t tx_len)
{
    if (c == NULL) {
        return false;
    }
    if (c->kind == CMT_MEM_TX_CACHE_LRU) {
        return cmt_mem_lru_tx_cache_push(&c->lru, tx, tx_len);
    }
    return true;                                                   /* :118 */
}

void cmt_mem_tx_cache_remove(cmt_mem_tx_cache_t *c, const uint8_t *tx,
                             size_t tx_len)
{
    if (c != NULL && c->kind == CMT_MEM_TX_CACHE_LRU) {
        cmt_mem_lru_tx_cache_remove(&c->lru, tx, tx_len);
    }
    /* :119 NopTxCache.Remove — nothing */
}

bool cmt_mem_tx_cache_has(const cmt_mem_tx_cache_t *c, const uint8_t *tx,
                          size_t tx_len)
{
    if (c != NULL && c->kind == CMT_MEM_TX_CACHE_LRU) {
        return cmt_mem_lru_tx_cache_has(&c->lru, tx, tx_len);
    }
    return false;                                                  /* :120 */
}

/* ══ mempool/ids.go ═══════════════════════════════════════════════════ */

static bool ids_active(const cmt_mem_ids_t *ids, uint16_t id)
{
    return (ids->active_ids[id >> 3] & (uint8_t)(1u << (id & 7u))) != 0;
}

static void ids_set_active(cmt_mem_ids_t *ids, uint16_t id)
{
    if (!ids_active(ids, id)) {
        ids->active_ids[id >> 3] |= (uint8_t)(1u << (id & 7u));
        ids->active_count++;
    }
}

static void ids_clear_active(cmt_mem_ids_t *ids, uint16_t id)
{
    if (ids_active(ids, id)) {
        ids->active_ids[id >> 3] &= (uint8_t)~(1u << (id & 7u));
        ids->active_count--;
    }
}

/* ids.go:65-71 — newMempoolIDs() */
int cmt_mem_ids_init(cmt_mem_ids_t *ids)
{
    if (ids == NULL) {
        return CMT_FAULT;
    }
    memset(ids, 0, sizeof(*ids));
    ids_set_active(ids, 0);                                        /* :68 */
    ids->next_id = 1;                                              /* :69 */
    return CMT_OK;
}

/* ids.go:30-43 — nextPeerID(). The uint16 `nextID++` wraps exactly as
 * Go's does. */
static int ids_next_peer_id(cmt_mem_ids_t *ids, uint16_t *out)
{
    uint16_t cur;

    if (ids->active_count == CMT_MEM_MAX_ACTIVE_IDS) {             /* :31 */
        /* :32 panic("node has maximum %d active IDs and wanted to get
         * one more") — CMT_FAULT: only this node's own reservations
         * reach it. */
        return CMT_FAULT;
    }
    while (ids_active(ids, ids->next_id)) {                        /* :35-39 */
        ids->next_id++;
    }
    cur = ids->next_id;                                            /* :40 */
    ids->next_id++;                                                /* :41 */
    *out = cur;                                                    /* :42 */
    return CMT_OK;
}

/* ids.go:19-26 — ReserveForPeer(peer) */
int cmt_mem_ids_reserve_for_peer(cmt_mem_ids_t *ids, int slot)
{
    uint16_t cur;
    int      rc;

    if (ids == NULL) {
        return CMT_FAULT;
    }
    if (slot < 0 || slot >= (int)CMT_MEM_MAX_PEERS) {
        return CMT_REJECT;
    }
    rc = ids_next_peer_id(ids, &cur);                              /* :23 */
    if (rc != CMT_OK) {
        return rc;
    }
    ids->peer_map[slot]     = cur;                                 /* :24 */
    ids->peer_present[slot] = true;
    ids_set_active(ids, cur);                                      /* :25 */
    return CMT_OK;
}

/* ids.go:46-55 — Reclaim(peer) */
int cmt_mem_ids_reclaim(cmt_mem_ids_t *ids, int slot)
{
    if (ids == NULL) {
        return CMT_FAULT;
    }
    if (slot < 0 || slot >= (int)CMT_MEM_MAX_PEERS) {
        return CMT_REJECT;
    }
    if (ids->peer_present[slot]) {                                 /* :50-51 */
        ids_clear_active(ids, ids->peer_map[slot]);                /* :52 */
        ids->peer_present[slot] = false;                           /* :53 */
        ids->peer_map[slot]     = 0;
    }
    return CMT_OK;
}

/* ids.go:58-63 — GetForPeer(peer): the map's zero value when absent. */
uint16_t cmt_mem_ids_get_for_peer(const cmt_mem_ids_t *ids, int slot)
{
    if (ids == NULL || slot < 0 || slot >= (int)CMT_MEM_MAX_PEERS) {
        return CMT_MEM_UNKNOWN_PEER_ID;
    }
    return ids->peer_present[slot] ? ids->peer_map[slot]
                                   : CMT_MEM_UNKNOWN_PEER_ID;      /* :62 */
}

/* ══ clist_mempool.go:697-801 — the recheck cursor ════════════════════ */

/* :724-726 — done() */
static bool recheck_done(const cmt_mem_t *mem)
{
    return !mem->recheck.is_rechecking;
}

bool cmt_mem_recheck_done(const cmt_mem_t *mem)
{
    return mem == NULL || recheck_done(mem);
}

/* Move the cursor reference: retain the new target, release the old. */
static void recheck_set_cursor(cmt_mem_t *mem, cmt_clist_elem_t *e)
{
    cmt_clist_elem_t *old = mem->recheck.cursor;

    cmt_clist_elem_ref(e);
    mem->recheck.cursor = e;
    cmt_clist_elem_unref(old);
}

static void recheck_set_end(cmt_mem_t *mem, cmt_clist_elem_t *e)
{
    cmt_clist_elem_t *old = mem->recheck.end;

    cmt_clist_elem_ref(e);
    mem->recheck.end = e;
    cmt_clist_elem_unref(old);
}

/* :712-720 — init(first, last) */
static int recheck_init(cmt_mem_t *mem, cmt_clist_elem_t *first,
                        cmt_clist_elem_t *last)
{
    if (!recheck_done(mem)) {
        /* :714 panic("Having more than one rechecking process at a time
         * is not possible.") — CMT_FAULT: an ordering defect inside
         * this node. */
        return CMT_FAULT;
    }
    recheck_set_cursor(mem, first);                                /* :716 */
    recheck_set_end(mem, last);                                    /* :717 */
    mem->recheck.num_pending_txs = 0;                              /* :718 */
    mem->recheck.is_rechecking   = true;                           /* :719 */
    return CMT_OK;
}

/* :729-733 — setDone() */
static void recheck_set_done(cmt_mem_t *mem)
{
    recheck_set_cursor(mem, NULL);                                 /* :730 */
    recheck_set_end(mem, NULL);   /* C-only release; see cmt_mem.h */
    mem->recheck.recheck_full  = false;                            /* :731 */
    mem->recheck.is_rechecking = false;                            /* :732 */
}

/* :736-738 — setNextEntry() */
static void recheck_set_next_entry(cmt_mem_t *mem)
{
    recheck_set_cursor(mem, cmt_clist_elem_next(mem->recheck.cursor));
}

/* :742-756 — tryFinish() */
static bool recheck_try_finish(cmt_mem_t *mem)
{
    if (mem->recheck.cursor == mem->recheck.end) {                 /* :743 */
        recheck_set_done(mem);                                     /* :745 */
    }
    if (recheck_done(mem)) {                                       /* :747 */
        /* :749-752 — the doneCh send: nobody waits, nothing to send. */
        return true;                                               /* :753 */
    }
    return false;                                                  /* :755 */
}

/* :765-782 — findNextEntryMatching(tx). A NULL cursor while not done is
 * the reference's nil dereference at :768 → CMT_FAULT; unreachable with
 * the synchronous client, which only ever answers the cursor's own tx. */
static int recheck_find_next_entry_matching(cmt_mem_t *mem,
                                            const uint8_t *tx, size_t tx_len,
                                            bool *found)
{
    *found = false;                                                /* :766 */
    for (; !recheck_done(mem); recheck_set_next_entry(mem)) {     /* :767 */
        const cmt_mem_tx_t *expected;

        if (mem->recheck.cursor == NULL) {
            return CMT_FAULT;
        }
        expected = (const cmt_mem_tx_t *)
                   cmt_clist_elem_value(mem->recheck.cursor);      /* :768 */
        if (expected != NULL && expected->tx_len == tx_len &&
            (tx_len == 0 || memcmp(tx, expected->tx, tx_len) == 0)) { /* :769 */
            *found = true;                                         /* :771 */
            mem->recheck.num_pending_txs--;                        /* :772 */
            break;                                                 /* :773 */
        }
    }
    if (!recheck_try_finish(mem)) {                                /* :777 */
        recheck_set_next_entry(mem);                               /* :779 */
    }
    return CMT_OK;                                                 /* :781 */
}

/* :791-795 — setRecheckFull() */
static bool recheck_set_recheck_full(cmt_mem_t *mem)
{
    bool rechecking   = !recheck_done(mem);                        /* :792 */
    bool recheck_full = mem->recheck.recheck_full;                 /* :793 Swap */

    mem->recheck.recheck_full = rechecking;
    return rechecking != recheck_full;                             /* :794 */
}

/* :799-801 — consideredFull() */
static bool recheck_considered_full(const cmt_mem_t *mem)
{
    return mem->recheck.recheck_full;
}

bool cmt_mem_recheck_considered_full(const cmt_mem_t *mem)
{
    return mem != NULL && recheck_considered_full(mem);
}

/* ══ clist_mempool.go:67-96 — NewCListMempool ═════════════════════════ */

int cmt_mem_init(cmt_mem_t *mem, const cmt_mempool_config_t *cfg,
                 const cmt_mem_app_t *app, int64_t height,
                 const cmt_mem_pre_check_t *pre_check,
                 const cmt_mem_post_check_t *post_check)
{
    if (mem == NULL || cfg == NULL || app == NULL) {
        return CMT_FAULT;
    }
    if (cfg->size < 0 || cfg->cache_size < 0) {
        return CMT_FAULT;
    }
    memset(mem, 0, sizeof(*mem));
    mem->config = cfg;                                             /* :74 */
    mem->app    = app;                                             /* :75 */
    if (cmt_clist_init(&mem->txs, mem_tx_free_value, NULL) != CMT_OK) {
        return CMT_FAULT;                                          /* :76 */
    }
    /* :77 newRecheck() — the zeroed struct (doneCh gone). */
    /* :78-79 logger / metrics — QGP_LOG / not ported. */
    mem->height = height;                                          /* :81 */

    if (cfg->cache_size > 0) {                                     /* :83 */
        mem->cache.kind = CMT_MEM_TX_CACHE_LRU;
        if (cmt_mem_lru_tx_cache_init(&mem->cache.lru,
                                      cfg->cache_size) != CMT_OK) { /* :84 */
            cmt_clist_free(&mem->txs);
            return CMT_FAULT;
        }
    } else {
        mem->cache.kind = CMT_MEM_TX_CACHE_NOP;                    /* :86 */
    }

    if (index_init(&mem->txs_map, (size_t)cfg->size) != CMT_OK) {  /* :50 */
        cmt_mem_lru_tx_cache_free(&mem->cache.lru);
        cmt_clist_free(&mem->txs);
        return CMT_FAULT;
    }

    /* :89 SetResponseCallback(globalCb) — no async client, nothing set. */

    if (pre_check != NULL) {                                       /* :91-93 */
        mem->pre_check = *pre_check;                               /* :138 */
    }
    if (post_check != NULL) {
        mem->post_check = *post_check;                             /* :145 */
    }
    return CMT_OK;                                                 /* :95 */
}

void cmt_mem_free(cmt_mem_t *mem)
{
    if (mem == NULL) {
        return;
    }
    recheck_set_cursor(mem, NULL);
    recheck_set_end(mem, NULL);
    cmt_clist_free(&mem->txs);
    index_free(&mem->txs_map);
    if (mem->cache.kind == CMT_MEM_TX_CACHE_LRU) {
        cmt_mem_lru_tx_cache_free(&mem->cache.lru);
    }
    memset(mem, 0, sizeof(*mem));
}

/* ══ clist_mempool.go:98-213 — accessors and small methods ════════════ */

/* :98-103 — getCElement(txKey) */
cmt_clist_elem_t *cmt_mem_get_celement(const cmt_mem_t *mem,
                                       const uint8_t key[CMT_MEM_TX_KEY_SIZE])
{
    if (mem == NULL || key == NULL) {
        return NULL;
    }
    return (cmt_clist_elem_t *)index_load(&mem->txs_map, key);     /* :99-100 */
}

/* :105-110 — getMemTx(txKey) */
cmt_mem_tx_t *cmt_mem_get_mem_tx(const cmt_mem_t *mem,
                                 const uint8_t key[CMT_MEM_TX_KEY_SIZE])
{
    cmt_clist_elem_t *e = cmt_mem_get_celement(mem, key);          /* :106 */

    return (e == NULL) ? NULL : (cmt_mem_tx_t *)cmt_clist_elem_value(e);
}

/* :112-122 — removeAllTxs() */
static int mem_remove_all_txs(cmt_mem_t *mem)
{
    cmt_clist_elem_t *e;

    for (e = cmt_clist_front(&mem->txs); e != NULL; ) {            /* :113 */
        cmt_clist_elem_t *next;

        /* Hold `e` across its own removal so that `e.Next()` (:113)
         * can still be read from it — cmt_clist.h's rule. */
        cmt_clist_elem_ref(e);
        if (cmt_clist_remove(&mem->txs, e, NULL) != CMT_OK) {      /* :114 */
            cmt_clist_elem_unref(e);
            return CMT_FAULT;
        }
        (void)cmt_clist_elem_detach_prev(e);                       /* :115 */
        next = cmt_clist_elem_next(e);
        cmt_clist_elem_unref(e);
        e = next;
    }
    index_clear(&mem->txs_map);                                    /* :118-121 */
    return CMT_OK;
}

/* :125-127 — EnableTxsAvailable() */
int cmt_mem_enable_txs_available(cmt_mem_t *mem,
                                 cmt_mem_txs_available_fn fn, void *ctx)
{
    if (mem == NULL) {
        return CMT_FAULT;
    }
    mem->txs_available_enabled = true;                             /* :126 */
    mem->txs_available_fn      = fn;
    mem->txs_available_ctx     = ctx;
    return CMT_OK;
}

/* :154-159 — Lock() */
bool cmt_mem_lock(cmt_mem_t *mem)
{
    bool flipped;

    if (mem == NULL) {
        return false;
    }
    flipped = recheck_set_recheck_full(mem);                       /* :155 */
    if (flipped) {
        QGP_LOG_DEBUG(LOG_TAG, "the state of recheckFull has flipped"); /* :156 */
    }
    /* :158 updateMtx.Lock() — single thread. */
    return flipped;
}

/* :162-164 — Unlock() */
void cmt_mem_unlock(cmt_mem_t *mem)
{
    (void)mem;   /* :163 updateMtx.Unlock() — single thread. */
}

/* :167-169 — Size() */
int cmt_mem_size(const cmt_mem_t *mem)
{
    return (mem == NULL) ? 0 : cmt_clist_len(&mem->txs);
}

/* :172-174 — SizeBytes() */
int64_t cmt_mem_size_bytes(const cmt_mem_t *mem)
{
    return (mem == NULL) ? 0 : mem->txs_bytes;
}

/* :177-184 — FlushAppConn() */
int cmt_mem_flush_app_conn(cmt_mem_t *mem, cmt_mem_error_t *out_err)
{
    int rc;

    cmt_mem_error_init(out_err);
    if (mem == NULL || mem->app == NULL || mem->app->flush == NULL) {
        return CMT_FAULT;
    }
    rc = mem->app->flush(mem->app->ctx);                           /* :178 */
    if (rc != CMT_OK) {                                            /* :179-181 */
        err_set_kind(out_err, CMT_MEM_ERR_FLUSH_APP_CONN);
        if (out_err != NULL) {
            out_err->wrapped = rc;
        }
        return CMT_REJECT;
    }
    return CMT_OK;                                                 /* :183 */
}

/* :187-195 — Flush() */
int cmt_mem_flush(cmt_mem_t *mem)
{
    if (mem == NULL) {
        return CMT_FAULT;
    }
    /* :188-189 RLock/RUnlock — single thread. */
    mem->txs_bytes = 0;                                            /* :191 */
    cmt_mem_tx_cache_reset(&mem->cache);                           /* :192 */
    return mem_remove_all_txs(mem);                                /* :194 */
}

/* :202-204 — TxsFront() */
cmt_clist_elem_t *cmt_mem_txs_front(const cmt_mem_t *mem)
{
    return (mem == NULL) ? NULL : cmt_clist_front(&mem->txs);
}

/* ══ clist_mempool.go:355-395 — addTx, RemoveTxByKey, isFull ══════════ */

/* :355-360 — addTx(memTx). On failure the memTx is NOT freed here; the
 * caller still owns it. */
static int mem_add_tx(cmt_mem_t *mem, cmt_mem_tx_t *mem_tx)
{
    cmt_clist_elem_t *e;
    uint8_t           key[CMT_MEM_TX_KEY_SIZE];

    if (cmt_mem_tx_key(mem_tx->tx, mem_tx->tx_len, key) != CMT_OK) {
        return CMT_FAULT;
    }
    if (cmt_clist_push_back(&mem->txs, mem_tx, &e) != CMT_OK) {    /* :356 */
        return CMT_FAULT;
    }
    if (index_store(&mem->txs_map, key, e) != CMT_OK) {            /* :357 */
        /* The map is sized for `Size` and isFull guards the list at
         * that bound; a full map is a defect of this file. Undo the
         * push so the pool stays consistent, and let the element go
         * WITHOUT its value (the caller still owns mem_tx). */
        void *dummy;

        cmt_clist_elem_ref(e);
        (void)cmt_clist_remove(&mem->txs, e, &dummy);
        e->value = NULL;
        cmt_clist_elem_unref(e);
        return CMT_FAULT;
    }
    mem->txs_bytes += (int64_t)mem_tx->tx_len;                     /* :358 */
    /* :359 metrics — not ported. */
    return CMT_OK;
}

/* :366-376 — RemoveTxByKey(txKey) */
int cmt_mem_remove_tx_by_key(cmt_mem_t *mem,
                             const uint8_t key[CMT_MEM_TX_KEY_SIZE],
                             cmt_mem_error_t *out_err)
{
    cmt_clist_elem_t   *elem;
    const cmt_mem_tx_t *mem_tx;

    cmt_mem_error_init(out_err);
    if (mem == NULL || key == NULL) {
        return CMT_FAULT;
    }
    elem = cmt_mem_get_celement(mem, key);                         /* :367 */
    if (elem == NULL) {
        err_set_kind(out_err, CMT_MEM_ERR_TX_NOT_FOUND);           /* :375 */
        return CMT_REJECT;
    }
    /* Hold the element: :371 reads its value AFTER :368 removed it. */
    cmt_clist_elem_ref(elem);
    if (cmt_clist_remove(&mem->txs, elem, NULL) != CMT_OK) {       /* :368 */
        cmt_clist_elem_unref(elem);
        return CMT_FAULT;
    }
    (void)cmt_clist_elem_detach_prev(elem);                        /* :369 */
    index_delete(&mem->txs_map, key);                              /* :370 */
    mem_tx = (const cmt_mem_tx_t *)cmt_clist_elem_value(elem);     /* :371 */
    if (mem_tx != NULL) {
        mem->txs_bytes -= (int64_t)mem_tx->tx_len;                 /* :372 */
    }
    cmt_clist_elem_unref(elem);
    return CMT_OK;                                                 /* :373 */
}

/* :378-395 — isFull(txSize). Returns true and fills `err` when full. */
static bool mem_is_full(const cmt_mem_t *mem, size_t tx_size,
                        cmt_mem_error_t *err)
{
    int     mem_size  = cmt_mem_size(mem);                         /* :379 */
    int64_t txs_bytes = cmt_mem_size_bytes(mem);                   /* :380 */

    if (mem_size >= mem->config->size ||
        (int64_t)tx_size + txs_bytes > mem->config->max_txs_bytes) { /* :381 */
        err_set_kind(err, CMT_MEM_ERR_MEMPOOL_IS_FULL);
        if (err != NULL) {
            err->num_txs       = mem_size;                         /* :383 */
            err->max_txs       = mem->config->size;                /* :384 */
            err->txs_bytes     = txs_bytes;                        /* :385 */
            err->max_txs_bytes = mem->config->max_txs_bytes;       /* :386 */
        }
        return true;
    }
    if (recheck_considered_full(mem)) {                            /* :390 */
        err_set_kind(err, CMT_MEM_ERR_RECHECK_FULL);               /* :391 */
        return true;
    }
    return false;                                                  /* :394 */
}

/* ══ clist_mempool.go:401-521 — the two callbacks and the signal ══════ */

/* :510-521 — notifyTxsAvailable() */
static int mem_notify_txs_available(cmt_mem_t *mem)
{
    if (cmt_mem_size(mem) == 0) {
        /* :512 panic("notified txs available but mempool is empty!") —
         * CMT_FAULT: the pool's own invariant. */
        return CMT_FAULT;
    }
    if (mem->txs_available_enabled && !mem->notified_txs_available) { /* :514 */
        mem->notified_txs_available = true;   /* the CompareAndSwap */
        /* :516-519 — the cap-1 non-blocking send; here the reader. */
        if (mem->txs_available_fn != NULL) {
            mem->txs_available_fn(mem->txs_available_ctx);
        }
    }
    return CMT_OK;
}

/* :401-474 — resCbFirstTime(tx, txInfo, res) */
static int mem_res_cb_first_time(cmt_mem_t *mem, const uint8_t *tx,
                                 size_t tx_len, const cmt_mem_tx_info_t *info,
                                 const cmt_mem_response_check_tx_t *res)
{
    int post_check_err = CMT_OK;                                   /* :408 */

    if (mem->post_check.fn != NULL) {                              /* :409 */
        post_check_err = mem->post_check.fn(mem->post_check.ctx, tx, tx_len,
                                            res);                  /* :410 */
    }
    if (res->code == CMT_MEM_CODE_TYPE_OK && post_check_err == CMT_OK) { /* :412 */
        cmt_mem_error_t   full;
        uint8_t           key[CMT_MEM_TX_KEY_SIZE];
        cmt_clist_elem_t *e;
        cmt_mem_tx_t     *mem_tx;
        int               rc;

        /* :413-422 — full again? drop the cache entry, refuse. */
        if (mem_is_full(mem, tx_len, &full)) {                     /* :415 */
            cmt_mem_tx_cache_remove(&mem->cache, tx, tx_len);      /* :417 */
            QGP_LOG_DEBUG(LOG_TAG, "mempool is full: number of txs %lld"
                          " (max: %lld), total txs bytes %lld (max: %lld)",
                          (long long)full.num_txs, (long long)full.max_txs,
                          (long long)full.txs_bytes,
                          (long long)full.max_txs_bytes);          /* :419 */
            return CMT_OK;                                         /* :421 */
        }

        /* :424-437 — already in the pool: record the sender, refuse. */
        if (cmt_mem_tx_key(tx, tx_len, key) != CMT_OK) {
            return CMT_FAULT;
        }
        e = (cmt_clist_elem_t *)index_load(&mem->txs_map, key);    /* :425 */
        if (e != NULL) {
            mem_tx = (cmt_mem_tx_t *)cmt_clist_elem_value(e);      /* :426 */
            (void)cmt_mem_tx_add_sender(mem_tx, info->sender_id);  /* :427 */
            QGP_LOG_DEBUG(LOG_TAG, "transaction already there, not adding"
                          " it again (len %zu, height %lld, total %d)",
                          tx_len, (long long)mem->height,
                          cmt_mem_size(mem));                      /* :428-434 */
            return CMT_OK;                                         /* :436 */
        }

        mem_tx = mem_tx_new(mem->height, res->gas_wanted, tx, tx_len); /* :439-443 */
        if (mem_tx == NULL) {
            return CMT_FAULT;
        }
        (void)cmt_mem_tx_add_sender(mem_tx, info->sender_id);      /* :444 */
        rc = mem_add_tx(mem, mem_tx);                              /* :445 */
        if (rc != CMT_OK) {
            free(mem_tx);
            return rc;
        }
        QGP_LOG_DEBUG(LOG_TAG, "added good transaction (len %zu, height"
                      " %lld, total %d)", tx_len, (long long)mem->height,
                      cmt_mem_size(mem));                          /* :446-452 */
        return mem_notify_txs_available(mem);                      /* :453 */
    }

    /* :454-469 — the application (or postCheck) refused it. */
    QGP_LOG_DEBUG(LOG_TAG, "rejected bad transaction (len %zu, sender id"
                  " %u, code %u, postCheckErr %d)", tx_len,
                  (unsigned)info->sender_id, (unsigned)res->code,
                  post_check_err);                                 /* :456-462 */
    /* :463 metrics — not ported. */
    if (!mem->config->keep_invalid_txs_in_cache) {                 /* :465 */
        cmt_mem_tx_cache_remove(&mem->cache, tx, tx_len);          /* :467 */
    }
    return CMT_OK;
}

/* :480-503 — resCbRecheck(tx, res) */
static int mem_res_cb_recheck(cmt_mem_t *mem, const uint8_t *tx,
                              size_t tx_len,
                              const cmt_mem_response_check_tx_t *res)
{
    bool found;
    int  post_check_err = CMT_OK;                                  /* :487 */
    int  rc;

    rc = recheck_find_next_entry_matching(mem, tx, tx_len, &found); /* :482 */
    if (rc != CMT_OK) {
        return rc;
    }
    if (!found) {
        return CMT_OK;                                             /* :484 */
    }
    if (mem->post_check.fn != NULL) {                              /* :488 */
        post_check_err = mem->post_check.fn(mem->post_check.ctx, tx, tx_len,
                                            res);                  /* :489 */
    }
    if (res->code != CMT_MEM_CODE_TYPE_OK || post_check_err != CMT_OK) { /* :492 */
        uint8_t         key[CMT_MEM_TX_KEY_SIZE];
        cmt_mem_error_t err;

        QGP_LOG_DEBUG(LOG_TAG, "tx is no longer valid (len %zu, code %u,"
                      " postCheckErr %d)", tx_len, (unsigned)res->code,
                      post_check_err);                             /* :494 */
        if (cmt_mem_tx_key(tx, tx_len, key) != CMT_OK) {
            return CMT_FAULT;
        }
        rc = cmt_mem_remove_tx_by_key(mem, key, &err);             /* :495 */
        if (rc == CMT_REJECT) {
            QGP_LOG_DEBUG(LOG_TAG, "Transaction could not be removed from"
                          " mempool (err kind %d)", (int)err.kind); /* :496 */
        } else if (rc != CMT_OK) {
            return rc;
        }
        if (!mem->config->keep_invalid_txs_in_cache) {             /* :498 */
            cmt_mem_tx_cache_remove(&mem->cache, tx, tx_len);      /* :499 */
            /* :500 metrics — not ported. */
        }
    }
    return CMT_OK;
}

/* :506-508 — TxsAvailable() */
bool cmt_mem_txs_available(const cmt_mem_t *mem)
{
    return mem != NULL && mem->txs_available_enabled;
}

/* ══ clist_mempool.go:223-278 — CheckTx ═══════════════════════════════ */

int cmt_mem_check_tx(cmt_mem_t *mem, const uint8_t *tx, size_t tx_len,
                     const cmt_mem_tx_info_t *info,
                     cmt_mem_response_check_tx_t *out_res,
                     cmt_mem_error_t *out_err)
{
    size_t                      tx_size;
    cmt_mem_request_check_tx_t  req;
    cmt_mem_response_check_tx_t res;
    int                         rc;

    cmt_mem_error_init(out_err);
    if (out_res != NULL) {
        memset(out_res, 0, sizeof(*out_res));
    }
    if (mem == NULL || info == NULL || (tx == NULL && tx_len != 0)) {
        return CMT_FAULT;
    }
    if (mem->app == NULL || mem->app->error == NULL ||
        mem->app->check_tx == NULL) {
        return CMT_FAULT;
    }
    /* :228-230 RLock / deferred RUnlock — single thread. */

    tx_size = tx_len;                                              /* :232 */

    if (mem_is_full(mem, tx_size, out_err)) {                      /* :234 */
        /* :235 metrics — not ported. */
        return CMT_REJECT;                                         /* :236 */
    }

    if ((int64_t)tx_size > (int64_t)mem->config->max_tx_bytes) {   /* :239 */
        err_set_kind(out_err, CMT_MEM_ERR_TX_TOO_LARGE);           /* :240 */
        if (out_err != NULL) {
            out_err->max    = mem->config->max_tx_bytes;           /* :241 */
            out_err->actual = (int64_t)tx_size;                    /* :242 */
        }
        return CMT_REJECT;
    }

    if (mem->pre_check.fn != NULL) {                               /* :246 */
        rc = mem->pre_check.fn(mem->pre_check.ctx, tx, tx_len);    /* :247 */
        if (rc != CMT_OK) {
            err_set_kind(out_err, CMT_MEM_ERR_PRE_CHECK);          /* :248 */
            if (out_err != NULL) {
                out_err->wrapped = rc;
            }
            return CMT_REJECT;
        }
    }

    /* :252-255 — "proxyAppConn may error if tx buffer is full" */
    rc = mem->app->error(mem->app->ctx);                           /* :253 */
    if (rc != CMT_OK) {
        err_set_kind(out_err, CMT_MEM_ERR_APP_CONN_MEMPOOL);       /* :254 */
        if (out_err != NULL) {
            out_err->wrapped = rc;
        }
        return CMT_REJECT;
    }

    if (!cmt_mem_tx_cache_push(&mem->cache, tx, tx_len)) {         /* :257 */
        /* :258-267 — seen before: record the new sender on the resident
         * transaction, if it is still resident. */
        uint8_t       key[CMT_MEM_TX_KEY_SIZE];
        cmt_mem_tx_t *mem_tx;

        if (cmt_mem_tx_key(tx, tx_len, key) != CMT_OK) {
            return CMT_FAULT;
        }
        mem_tx = cmt_mem_get_mem_tx(mem, key);                     /* :262 */
        if (mem_tx != NULL) {
            (void)cmt_mem_tx_add_sender(mem_tx, info->sender_id);  /* :263 */
        }
        err_set_kind(out_err, CMT_MEM_ERR_TX_IN_CACHE);            /* :268 */
        return CMT_REJECT;
    }

    /* :271 — CheckTxAsync(RequestCheckTx{Tx: tx}); synchronous here. */
    req.tx     = tx;
    req.tx_len = tx_len;
    req.type   = CMT_MEM_CHECK_TX_TYPE_NEW;
    memset(&res, 0, sizeof(res));
    rc = mem->app->check_tx(mem->app->ctx, &req, &res);
    if (rc != CMT_OK) {
        /* :272-274 panic("CheckTx request for tx %s failed") —
         * CMT_FAULT: the ABCI connection, node-local. */
        return CMT_FAULT;
    }

    /* :275 SetCallback(reqResCb(...)) — the response is here, so the
     * callback body (:334-350) runs now. */
    if (!recheck_done(mem)) {
        /* :335-338 panic("rechecking has not finished; cannot check new
         * tx") — CMT_FAULT: an ordering defect inside this node. */
        return CMT_FAULT;
    }
    rc = mem_res_cb_first_time(mem, tx, tx_len, info, &res);       /* :340 */
    if (rc != CMT_OK) {
        return rc;
    }
    /* :342-344 metrics — not ported. */
    if (out_res != NULL) {                                         /* :347-349 */
        *out_res = res;
    }
    return CMT_OK;                                                 /* :277 */
}

/* ══ clist_mempool.go:524-579 — the two reaps ═════════════════════════ */

/* :524-562 — ReapMaxBytesMaxGas(maxBytes, maxGas) */
int cmt_mem_reap_max_bytes_max_gas(const cmt_mem_t *mem, int64_t max_bytes,
                                   int64_t max_gas, cmt_pb_bytes_t *out,
                                   size_t out_cap, size_t *out_len)
{
    int64_t                 total_gas    = 0;                      /* :529 */
    int64_t                 running_size = 0;                      /* :530 */
    size_t                  n = 0;
    const cmt_clist_elem_t *e;

    if (out_len != NULL) {
        *out_len = 0;
    }
    if (mem == NULL || out_len == NULL || (out == NULL && out_cap != 0)) {
        return CMT_FAULT;
    }
    /* :525-526 RLock — single thread. :536 the capacity hint — n/a. */
    for (e = cmt_clist_front(&mem->txs); e != NULL;
         e = cmt_clist_elem_next(e)) {                             /* :537 */
        const cmt_mem_tx_t *mem_tx =
            (const cmt_mem_tx_t *)cmt_clist_elem_value(e);         /* :538 */
        cmt_pb_bytes_t one;
        int64_t        data_size;
        int64_t        new_total_gas;

        if (mem_tx == NULL) {
            return CMT_FAULT;
        }
        one.data  = mem_tx->tx;
        one.len   = mem_tx->tx_len;
        data_size = cmt_mem_compute_proto_size_for_txs(&one, 1);   /* :542 */

        /* :545-547 — the byte cap; the reference appends at :540 and
         * truncates here, which is this refusal. */
        if (max_bytes > -1 && running_size + data_size > max_bytes) {
            *out_len = n;
            return CMT_OK;                                         /* :546 */
        }
        running_size += data_size;                                 /* :549 */

        /* :555 — Go int64 addition wraps; done in uint64 so C's does
         * too instead of being undefined. */
        new_total_gas = (int64_t)((uint64_t)total_gas +
                                  (uint64_t)mem_tx->gas_wanted);
        if (max_gas > -1 && new_total_gas > max_gas) {             /* :556 */
            *out_len = n;
            return CMT_OK;                                         /* :557 */
        }
        total_gas = new_total_gas;                                 /* :559 */

        if (n >= out_cap) {
            return CMT_FAULT;   /* the caller's room, not a peer's doing */
        }
        out[n] = one;                                              /* :540 */
        n++;
    }
    *out_len = n;
    return CMT_OK;                                                 /* :561 */
}

/* :565-579 — ReapMaxTxs(max) */
int cmt_mem_reap_max_txs(const cmt_mem_t *mem, int max, cmt_pb_bytes_t *out,
                         size_t out_cap, size_t *out_len)
{
    size_t                  n = 0;
    const cmt_clist_elem_t *e;

    if (out_len != NULL) {
        *out_len = 0;
    }
    if (mem == NULL || out_len == NULL || (out == NULL && out_cap != 0)) {
        return CMT_FAULT;
    }
    /* :566-567 RLock — single thread. */
    if (max < 0) {                                                 /* :569 */
        max = cmt_clist_len(&mem->txs);                            /* :570 */
    }
    /* :573 — the capacity hint MinInt(Len, max): n/a. */
    /* :574 — NOTE reference quirk: `len(txs) <= max`, so up to max + 1
     * transactions are returned. Reproduced. */
    for (e = cmt_clist_front(&mem->txs); e != NULL && n <= (size_t)max;
         e = cmt_clist_elem_next(e)) {
        const cmt_mem_tx_t *mem_tx =
            (const cmt_mem_tx_t *)cmt_clist_elem_value(e);         /* :575 */

        if (mem_tx == NULL) {
            return CMT_FAULT;
        }
        if (n >= out_cap) {
            return CMT_FAULT;   /* the caller's room, not a peer's doing */
        }
        out[n].data = mem_tx->tx;                                  /* :576 */
        out[n].len  = mem_tx->tx_len;
        n++;
    }
    *out_len = n;
    return CMT_OK;                                                 /* :578 */
}

/* ══ clist_mempool.go:582-689 — Update and recheckTxs ═════════════════ */

/* :647-689 — recheckTxs() */
static int mem_recheck_txs(cmt_mem_t *mem)
{
    cmt_clist_elem_t *e;
    int               rc;

    QGP_LOG_DEBUG(LOG_TAG, "recheck txs (height %lld, num-txs %d)",
                  (long long)mem->height, cmt_mem_size(mem));      /* :648 */

    if (cmt_mem_size(mem) <= 0) {                                  /* :650 */
        return CMT_OK;                                             /* :651 */
    }
    if (mem->app == NULL || mem->app->check_tx == NULL ||
        mem->app->flush == NULL) {
        return CMT_FAULT;
    }

    rc = recheck_init(mem, cmt_clist_front(&mem->txs),
                      cmt_clist_back(&mem->txs));                  /* :654 */
    if (rc != CMT_OK) {
        return rc;
    }

    /* :656-657 — "globalCb may be called concurrently, but CheckTx
     * cannot be executed concurrently because this function has the
     * lock": here there is one thread and the callback runs in line. */
    for (e = cmt_clist_front(&mem->txs); e != NULL; ) {            /* :658 */
        const cmt_mem_tx_t         *mem_tx;
        cmt_mem_request_check_tx_t  req;
        cmt_mem_response_check_tx_t res;
        cmt_clist_elem_t           *next;

        /* Hold `e`: resCbRecheck may remove it, and `e.Next()` (:658)
         * is read from it afterwards. */
        cmt_clist_elem_ref(e);
        mem_tx = (const cmt_mem_tx_t *)cmt_clist_elem_value(e);    /* :659 */
        if (mem_tx == NULL) {
            cmt_clist_elem_unref(e);
            return CMT_FAULT;
        }
        mem->recheck.num_pending_txs++;                            /* :660 */

        /* :662-670 — CheckTxAsync(RequestCheckTx{Tx, Recheck}) */
        req.tx     = mem_tx->tx;
        req.tx_len = mem_tx->tx_len;
        req.type   = CMT_MEM_CHECK_TX_TYPE_RECHECK;
        memset(&res, 0, sizeof(res));
        rc = mem->app->check_tx(mem->app->ctx, &req, &res);
        if (rc != CMT_OK) {
            /* :669 panic("(re-)CheckTx request for tx %s failed") —
             * CMT_FAULT: the ABCI connection, node-local. */
            cmt_clist_elem_unref(e);
            return CMT_FAULT;
        }

        /* The sync client's answer: globalCb's recheck branch
         * (:301-311). */
        if (recheck_done(mem)) {
            QGP_LOG_ERROR(LOG_TAG, "rechecking has finished; discard late"
                          " recheck response");                    /* :304-307 */
        } else {
            /* :309 metrics — not ported. */
            rc = mem_res_cb_recheck(mem, mem_tx->tx, mem_tx->tx_len, &res); /* :310 */
            if (rc != CMT_OK) {
                cmt_clist_elem_unref(e);
                return rc;
            }
        }
        next = cmt_clist_elem_next(e);
        cmt_clist_elem_unref(e);
        e = next;
    }

    /* :673-674 — Flush; the error is discarded there too. */
    (void)mem->app->flush(mem->app->ctx);

    /* :676-683 — the select. Nothing asynchronous can complete the
     * recheck from here on, so the timeout branch (:679-681) applies at
     * once whenever the loop above did not finish it — which, with
     * every answer processed in line, it always has. RecheckTimeout is
     * not read (cmt_mem.h). */
    if (!recheck_done(mem)) {
        recheck_set_done(mem);                                     /* :680 */
        QGP_LOG_ERROR(LOG_TAG, "timed out waiting for recheck responses"); /* :681 */
    }

    if (mem->recheck.num_pending_txs > 0) {                        /* :685 */
        QGP_LOG_ERROR(LOG_TAG, "not all txs were rechecked (not-rechecked"
                      " %d)", (int)mem->recheck.num_pending_txs);  /* :686 */
    }
    QGP_LOG_DEBUG(LOG_TAG, "done rechecking txs (height %lld, num-txs %d)",
                  (long long)mem->height, cmt_mem_size(mem));      /* :688 */
    return CMT_OK;
}

/* :582-643 — Update(height, txs, txResults, preCheck, postCheck) */
int cmt_mem_update(cmt_mem_t *mem, int64_t height,
                   const cmt_pb_bytes_t *txs, size_t n_txs,
                   const cmt_pb_exec_tx_result_t *tx_results,
                   size_t n_results,
                   const cmt_mem_pre_check_t *pre_check,
                   const cmt_mem_post_check_t *post_check)
{
    size_t i;
    int    rc;

    if (mem == NULL || (txs == NULL && n_txs != 0) ||
        (tx_results == NULL && n_results != 0)) {
        return CMT_FAULT;
    }
    /* :603 indexes txResults[i] for every i < len(txs); a shorter
     * results list is Go's index panic — CMT_FAULT, the BlockExecutor's
     * contract (INVARIANT 7495d337 made explicit). */
    if (n_results < n_txs) {
        return CMT_FAULT;
    }
    QGP_LOG_DEBUG(LOG_TAG, "Update (height %lld, len(txs) %zu)",
                  (long long)height, n_txs);                       /* :589 */

    mem->height                 = height;                          /* :592 */
    mem->notified_txs_available = false;                           /* :593 */

    if (pre_check != NULL) {                                       /* :595-597 */
        mem->pre_check = *pre_check;
    }
    if (post_check != NULL) {                                      /* :598-600 */
        mem->post_check = *post_check;
    }

    for (i = 0; i < n_txs; i++) {                                  /* :602 */
        uint8_t         key[CMT_MEM_TX_KEY_SIZE];
        cmt_mem_error_t err;

        if (tx_results[i].code == CMT_MEM_CODE_TYPE_OK) {          /* :603 */
            (void)cmt_mem_tx_cache_push(&mem->cache, txs[i].data,
                                        txs[i].len);               /* :605 */
        } else if (!mem->config->keep_invalid_txs_in_cache) {      /* :606 */
            cmt_mem_tx_cache_remove(&mem->cache, txs[i].data,
                                    txs[i].len);                   /* :608 */
        }

        /* :611-625 — remove the committed tx; "not in mempool" is not
         * an error (an evil proposer can drop valid txs, :613-620). */
        if (cmt_mem_tx_key(txs[i].data, txs[i].len, key) != CMT_OK) {
            return CMT_FAULT;
        }
        rc = cmt_mem_remove_tx_by_key(mem, key, &err);             /* :621 */
        if (rc == CMT_REJECT) {
            QGP_LOG_DEBUG(LOG_TAG, "Committed transaction not in local"
                          " mempool (not an error)");              /* :622-624 */
        } else if (rc != CMT_OK) {
            return rc;
        }
    }

    if (mem->config->recheck) {                                    /* :629 */
        rc = mem_recheck_txs(mem);                                 /* :630 */
        if (rc != CMT_OK) {
            return rc;
        }
    }

    if (cmt_mem_size(mem) > 0) {                                   /* :634 */
        rc = mem_notify_txs_available(mem);                        /* :635 */
        if (rc != CMT_OK) {
            return rc;
        }
    }

    /* :639-640 metrics — not ported. */
    return CMT_OK;                                                 /* :642 */
}
