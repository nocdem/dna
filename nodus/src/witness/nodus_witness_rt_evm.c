/**
 * @file nodus_witness_rt_evm.c
 * @brief Nodus EVM — the EVM domain's runtime (runtime ABI 2). Contract and
 *        activation status: nodus_witness_rt_evm.h.
 *
 * Design: docs/plans/2026-10-04-nodus-evm-chain-integration-design.md rev 3.
 * Map of this file to the design:
 *   §2  call bytes and their mapping to evm_tx_t ......... rtevm_decode,
 *                                                           rtevm_exec_vm
 *   §3  the reader backend (charge-before-read lives in the engine,
 *       nodus_witness_v2_apply.c v2rd_read) .............. be_*
 *   §4  success stream / fixed failure effects, no-op account rule,
 *       deleted-account check ............................ rtevm_build_*
 *   §5  bridge ops, tickets, META counters, wei_destroyed
 *       conservation check ............................... rtevm_bridge,
 *                                                           rtevm_build_*
 *   §6  MPT-SHA3-512 commitment (shared/evm/trie/evm_trie.h is the
 *       implementation; the design's rt_evm_trie.{c,h} is superseded by
 *       it), account leaf RLP, META digest, EVM root ...... leaf_*, root
 *   §7  canonical receipt ................................. rcpt_*
 *   §10 block environment ................................. rtevm_exec_vm
 *
 * DETERMINISM: every output is a function of (committed state through the
 * reader, the envelope, the engine context). The effect stream is sorted
 * by the effect codec's total order (kind, op, key) over unique keys; the
 * change set the engine visits is already totally ordered (evm.h
 * evm_state_visit_changes). No clock, no RNG, no iteration over unordered
 * data. Trie node writes are content-addressed and idempotent.
 */

#include "witness/nodus_witness_rt_evm.h"
#include "witness/nodus_witness.h"
#include "witness/nodus_witness_v2_adapter.h"
#include "witness/nodus_witness_v2_claims.h"   /* the CORE reserve read */
#include "witness/nodus_witness_v2_apply.h"    /* §18 sim: BLOCKHASH    */

#include "evm/evm.h"
#include "evm/evm_gas.h"     /* the access-list intrinsic floor (F3)     */
#include "evm/trie/evm_trie.h"
#include "evm/trie/evm_trie_rlp.h"

#include "dnac/ledger_ids.h"
#include "dnac/domain_wire.h"
#include "dnac/effect_wire.h"
#include "crypto/hash/qgp_sha3.h"
#include "crypto/hash/keccak256.h"
#include "crypto/utils/qgp_log.h"

#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>

#define LOG_TAG "W_RT_EVM"

/* ── tags (16 bytes, zero-padded — the env_wire.h tag discipline) ─────── */
static const uint8_t TAG_EVMROOT[16] = "NDS.EVMROOT.v1";    /* design §6   */
static const uint8_t TAG_EVMMETA[16] = "NDS.EVMMETA.v1";    /* design §6   */
static const uint8_t TAG_EVMRCPT[16] = "NDS.EVMRCPT.v1";    /* design §7   */
/* design §5: EVM_WITHDRAW_ADDR = SHA3-512("NDS.EVMWITHDRAW.v1")[0..32] —
 * the 18 ASCII bytes, no terminator */
static const char TICKET_ADDR_PREIMAGE[] = "NDS.EVMWITHDRAW.v1";

/* ── small codecs ──────────────────────────────────────────────────────── */

static void put_u64be(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (56 - 8 * i));
}
static uint64_t get_u64be(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | p[i];
    return v;
}
static void put_u32be(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);  p[3] = (uint8_t)v;
}
static uint32_t get_u32be(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}

/** The constant code digests of the empty code (computed, never typed in). */
static int empty_code_hashes(uint8_t kec[32], uint8_t sha[64]) {
    static const uint8_t none[1] = { 0 };
    if (kec && keccak256(none, 0, kec) != 0) return -1;
    if (sha && qgp_sha3_512(none, 0, sha) != 0) return -1;
    return 0;
}

/* ── the 148-byte ACCT record (design §4) ─────────────────────────────── */

typedef struct {
    int      exists;
    uint64_t nonce;
    uint8_t  balance[32];
    uint8_t  code_hash[32];       /* keccak256(code)                       */
    uint32_t code_size;
    uint8_t  code_digest[64];     /* SHA3-512(code)                        */
    uint64_t storage_count;
} rtevm_acct_t;

static void acct_encode(const rtevm_acct_t *a, uint8_t out[NODUS_RT_EVM_ACCT_LEN]) {
    put_u64be(out, a->nonce);
    memcpy(out + 8, a->balance, 32);
    memcpy(out + 40, a->code_hash, 32);
    put_u32be(out + 72, a->code_size);
    memcpy(out + 76, a->code_digest, 64);
    put_u64be(out + 140, a->storage_count);
}

static int acct_decode(const uint8_t *v, uint32_t len, rtevm_acct_t *a) {
    if (len != NODUS_RT_EVM_ACCT_LEN) return -1;
    a->exists = 1;
    a->nonce = get_u64be(v);
    memcpy(a->balance, v + 8, 32);
    memcpy(a->code_hash, v + 40, 32);
    a->code_size = get_u32be(v + 72);
    memcpy(a->code_digest, v + 76, 64);
    a->storage_count = get_u64be(v + 140);
    if (a->code_size > EVM_MAX_CODE_SIZE) return -1;
    return 0;
}

/** The record of an account that does not exist yet (the empty code). */
static int acct_empty(rtevm_acct_t *a) {
    memset(a, 0, sizeof(*a));
    return empty_code_hashes(a->code_hash, a->code_digest);
}

/* ── growable buffers and the effect arena ──────────────────────────── */

typedef struct { uint8_t *p; size_t len, cap; } rt_buf;

static int buf_put(rt_buf *b, const void *d, size_t n) {
    if (n == 0) return 0;
    if (b->len + n < b->len) return -1;
    if (b->len + n > b->cap) {
        size_t nc = b->cap ? b->cap : 256;
        while (nc < b->len + n) {
            if (nc > SIZE_MAX / 2) return -1;
            nc *= 2;
        }
        uint8_t *g = realloc(b->p, nc);
        if (!g) return -1;
        b->p = g;
        b->cap = nc;
    }
    memcpy(b->p + b->len, d, n);
    b->len += n;
    return 0;
}

typedef struct ra_blk {
    struct ra_blk *next;
    size_t used, cap;
    uint8_t data[];
} ra_blk;

typedef struct { ra_blk *head; } rt_arena;

/** Byte memory that lives until the out is released (keys, values, code
 *  copies). @return NULL on allocation failure. */
static uint8_t *ra_alloc(rt_arena *a, size_t n) {
    if (n == 0) n = 1;
    if (!a->head || a->head->cap - a->head->used < n) {
        size_t cap = n > 65536 ? n : 65536;
        ra_blk *b = malloc(sizeof(*b) + cap);
        if (!b) return NULL;
        b->next = a->head;
        b->used = 0;
        b->cap = cap;
        a->head = b;
    }
    uint8_t *p = a->head->data + a->head->used;
    a->head->used += n;
    return p;
}

static void ra_free(rt_arena *a) {
    ra_blk *b = a->head;
    while (b) {
        ra_blk *n = b->next;
        free(b);
        b = n;
    }
    a->head = NULL;
}

/* ── the out's private state ────────────────────────────────────────── */

typedef struct {
    rt_arena          arena;
    dna_effect_in_t  *eff;
    uint32_t          n_eff, cap_eff;
    dna_effect_in_t   fail_eff[1];
    rt_buf            rcpt, fail_rcpt;
    evm_tx_result_t   res;
    int               res_set;
    nodus_rt_v2_log_t *logs;
    evm_access_entry_t *acc;          /* decoded access list              */
    evm_bytes32       *acc_keys;
} rtevm_priv_t;

static void rtevm_release(nodus_rt_v2_out_t *out) {
    if (!out || !out->priv) return;
    rtevm_priv_t *p = (rtevm_priv_t *)out->priv;
    ra_free(&p->arena);
    free(p->eff);
    free(p->rcpt.p);
    free(p->fail_rcpt.p);
    if (p->res_set) evm_tx_result_free(&p->res);
    free(p->logs);
    free(p->acc);
    free(p->acc_keys);
    free(p);
    memset(out, 0, sizeof(*out));
}

/** Append one effect whose key / value bytes are COPIED into the arena.
 *  @return 0 / -2 (allocation). */
static int eff_add(rtevm_priv_t *p, uint32_t op, uint8_t kind, uint8_t pre,
                   const uint8_t *key, uint16_t key_len,
                   const uint8_t *val, uint32_t val_len) {
    if (p->n_eff == p->cap_eff) {
        uint32_t nc = p->cap_eff ? p->cap_eff * 2 : 64;
        if (nc < p->cap_eff) return -2;
        dna_effect_in_t *g = realloc(p->eff, (size_t)nc * sizeof(*g));
        if (!g) return -2;
        p->eff = g;
        p->cap_eff = nc;
    }
    uint8_t *k = ra_alloc(&p->arena, key_len);
    uint8_t *v = val_len ? ra_alloc(&p->arena, val_len) : NULL;
    if (!k || (val_len && !v)) return -2;
    memcpy(k, key, key_len);
    if (val_len) memcpy(v, val, val_len);
    dna_effect_in_t *e = &p->eff[p->n_eff++];
    memset(e, 0, sizeof(*e));
    e->hdr.op_id = op;
    e->hdr.effect_kind = kind;
    e->hdr.precond_tag = pre;
    e->hdr.key_len = key_len;
    e->hdr.value_len = val_len;
    e->key = k;
    e->value = v;
    return 0;
}

/** The effect codec's total order (effect_wire.c eff_order_cmp): kind,
 *  op, then key bytes — the order the engine pages the stream in. Keys are
 *  unique per op by construction, so this is a total order and qsort's
 *  instability cannot show. */
static int eff_sort_cmp(const void *pa, const void *pb) {
    const dna_effect_in_t *a = (const dna_effect_in_t *)pa;
    const dna_effect_in_t *b = (const dna_effect_in_t *)pb;
    if (a->hdr.effect_kind != b->hdr.effect_kind)
        return a->hdr.effect_kind < b->hdr.effect_kind ? -1 : 1;
    if (a->hdr.op_id != b->hdr.op_id)
        return a->hdr.op_id < b->hdr.op_id ? -1 : 1;
    uint16_t m = a->hdr.key_len < b->hdr.key_len ? a->hdr.key_len
                                                 : b->hdr.key_len;
    int c = m ? memcmp(a->key, b->key, m) : 0;
    if (c != 0) return c;
    if (a->hdr.key_len != b->hdr.key_len)
        return a->hdr.key_len < b->hdr.key_len ? -1 : 1;
    return 0;
}

/* ── the reader backend (design §3) ───────────────────────────────────── */

#define RTEVM_BUDGET_RC 7      /* a visitor's own "budget" return (≠ -2) */

typedef struct {
    const nodus_rt_v2_reader_t *rd;
    nodus_rt_read_res_t        *rr;     /* heap scratch, one read at a time */
    int                         budget_hit;
} rtevm_be_t;

/** One reader call. @return 0, -3 (BUDGET, flagged), -2. */
static int be_read(rtevm_be_t *b, uint32_t op, const uint8_t *key,
                   uint16_t key_len) {
    int rc = b->rd->read(b->rd->ctx, op, key, key_len, b->rr);
    if (rc == 0) return 0;
    if (rc == NODUS_RT_V2_READ_BUDGET) {
        b->budget_hit = 1;
        return EVM_BUDGET;
    }
    return -2;
}

/** The ACCT record of `addr` (absent = an empty, non-existing record).
 *  @return 0, -3, -2. */
static int read_acct(rtevm_be_t *b, const uint8_t addr[32], rtevm_acct_t *a) {
    int rc = be_read(b, NODUS_RT_EVM_OP_ACCT, addr, 32);
    if (rc != 0) return rc;
    if (!b->rr->present) {
        if (acct_empty(a) != 0) return -2;
        return 0;
    }
    memset(a, 0, sizeof(*a));
    return acct_decode(b->rr->value, b->rr->value_len, a) == 0 ? 0 : -2;
}

static int be_get_account(void *ctx, const evm_addr *addr,
                          evm_account_t *out) {
    rtevm_be_t *b = (rtevm_be_t *)ctx;
    rtevm_acct_t a;
    int rc = read_acct(b, addr->b, &a);
    if (rc != 0) return rc;
    memset(out, 0, sizeof(*out));
    out->exists = a.exists;
    out->nonce = a.nonce;
    evm_u256_from_be(&out->balance, a.balance);
    memcpy(out->code_hash.b, a.code_hash, 32);
    out->code_size = a.code_size;
    return 0;
}

static int be_get_code(void *ctx, const evm_addr *addr, uint8_t *buf,
                       size_t cap, size_t *len_out) {
    rtevm_be_t *b = (rtevm_be_t *)ctx;
    rtevm_acct_t a;
    int rc = read_acct(b, addr->b, &a);
    if (rc != 0) return rc;
    *len_out = 0;
    if (!a.exists || a.code_size == 0) return 0;
    if (cap < a.code_size || !buf) return -2;
    uint32_t n_chunks = (a.code_size + NODUS_RT_EVM_CODE_CHUNK - 1) /
                        NODUS_RT_EVM_CODE_CHUNK;
    uint8_t key[65];
    memcpy(key, a.code_digest, 64);
    size_t off = 0;
    for (uint32_t i = 0; i < n_chunks; i++) {
        key[64] = (uint8_t)i;
        rc = be_read(b, NODUS_RT_EVM_OP_CODE, key, 65);
        if (rc != 0) return rc;
        size_t want = a.code_size - off;
        if (want > NODUS_RT_EVM_CODE_CHUNK) want = NODUS_RT_EVM_CODE_CHUNK;
        /* design §6: CODE chunks are verified against the digest — a
         * missing or short chunk is this node's storage, never a value */
        if (!b->rr->present || b->rr->value_len != want) return -2;
        memcpy(buf + off, b->rr->value, want);
        off += want;
    }
    uint8_t d[64], k[32];
    if (qgp_sha3_512(buf, off, d) != 0 || keccak256(buf, off, k) != 0)
        return -2;
    if (memcmp(d, a.code_digest, 64) != 0 || memcmp(k, a.code_hash, 32) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "stored code does not match its digests");
        return -2;
    }
    *len_out = off;
    return 0;
}

static int be_get_storage(void *ctx, const evm_addr *addr,
                          const evm_bytes32 *key, evm_bytes32 *val_out) {
    rtevm_be_t *b = (rtevm_be_t *)ctx;
    uint8_t k[64];
    memcpy(k, addr->b, 32);
    memcpy(k + 32, key->b, 32);
    int rc = be_read(b, NODUS_RT_EVM_OP_SLOT, k, 64);
    if (rc != 0) return rc;
    memset(val_out->b, 0, 32);
    if (b->rr->present) {
        if (b->rr->value_len != 32) return -2;
        memcpy(val_out->b, b->rr->value, 32);
    }
    return 0;
}

static int be_get_block_hash(void *ctx, uint64_t number,
                             evm_bytes32 *hash_out, int *available) {
    rtevm_be_t *b = (rtevm_be_t *)ctx;
    uint8_t k[8];
    put_u64be(k, number);
    int rc = be_read(b, NODUS_RT_V2_OP_BLOCKHASH, k, 8);
    if (rc != 0) return rc;
    memset(hash_out->b, 0, 32);
    *available = 0;
    if (b->rr->present) {
        if (b->rr->value_len != 32) return -2;
        memcpy(hash_out->b, b->rr->value, 32);
        *available = 1;
    }
    return 0;
}

static int be_has_storage(void *ctx, const evm_addr *addr, int *out) {
    rtevm_be_t *b = (rtevm_be_t *)ctx;
    int rc = be_read(b, NODUS_RT_EVM_OP_HAS_STORAGE, addr->b, 32);
    if (rc != 0) return rc;
    *out = b->rr->present ? 1 : 0;
    return 0;
}

/* ── META (design §5) ──────────────────────────────────────────────────── */

/* The activation package REMOVED the C1 reserve mirror: the reserve is
 * CORE state (v2_evm_reserve, moved by CORE EVMFUND), read by the
 * invariant through nodus_witness_core_evm_reserve_get. META is the three
 * wei counters only (design §6 "meta = wei_live ‖ wei_tickets ‖
 * wei_lost"). */
typedef struct {
    evm_u256 live, tickets, lost;
} rtevm_meta_t;

static void meta_encode(const rtevm_meta_t *m, uint8_t out[NODUS_RT_EVM_META_LEN]) {
    evm_u256_to_be(out, &m->live);
    evm_u256_to_be(out + 32, &m->tickets);
    evm_u256_to_be(out + 64, &m->lost);
}

static void meta_decode(const uint8_t v[NODUS_RT_EVM_META_LEN], rtevm_meta_t *m) {
    evm_u256_from_be(&m->live, v);
    evm_u256_from_be(&m->tickets, v + 32);
    evm_u256_from_be(&m->lost, v + 64);
}

static const uint8_t META_KEY[1] = { 0x01 };

/** META through the reader. The row exists from activation (state_init),
 *  so absence is this node's state, never a value. @return 0, -3, -2. */
static int read_meta(rtevm_be_t *b, rtevm_meta_t *m) {
    int rc = be_read(b, NODUS_RT_EVM_OP_META, META_KEY, 1);
    if (rc != 0) return rc;
    if (!b->rr->present || b->rr->value_len != NODUS_RT_EVM_META_LEN)
        return -2;
    meta_decode(b->rr->value, m);
    return 0;
}

/** q × raw as a u256. */
static void wei_of_raw(evm_u256 *out, uint64_t raw) {
    evm_u256 q, r;
    evm_u256_from_u64(&q, NODUS_RT_EVM_Q);
    evm_u256_from_u64(&r, raw);
    evm_u256_mul(out, &q, &r);           /* < 2^64 × 2^34: no wrap        */
}

/* ── the canonical receipt (design §7) ─────────────────────────────────
 *   "NDS.EVMRCPT.v1\0\0" ‖ status u8 ‖ op u8 ‖ evm_gas_used u64 ‖
 *   created[32] ‖ output_len u32 ‖ output ‖ n_logs u32 ‖
 *   n_logs × (addr[32] ‖ n_topics u8 ‖ topics ‖ data_len u32 ‖ data) ‖
 *   wei_destroyed[32] ‖ n_tickets u16 ‖ ticket_ids (64 each). */
static int rcpt_build(rt_buf *b, uint8_t status, uint8_t op, uint64_t gas,
                      const uint8_t created[32], const uint8_t *output,
                      size_t output_len, const evm_log_t *logs,
                      size_t n_logs, const evm_u256 *destroyed,
                      const evm_ticket_t *tickets, size_t n_tickets) {
    uint8_t t[32];
    static const uint8_t zero32[32] = { 0 };
    if (output_len > UINT32_MAX || n_logs > UINT32_MAX || n_tickets > 0xFFFF)
        return -1;
    if (buf_put(b, TAG_EVMRCPT, 16) != 0 || buf_put(b, &status, 1) != 0 ||
        buf_put(b, &op, 1) != 0)
        return -1;
    put_u64be(t, gas);
    if (buf_put(b, t, 8) != 0 || buf_put(b, created ? created : zero32, 32))
        return -1;
    put_u32be(t, (uint32_t)output_len);
    if (buf_put(b, t, 4) != 0 || buf_put(b, output, output_len) != 0)
        return -1;
    put_u32be(t, (uint32_t)n_logs);
    if (buf_put(b, t, 4) != 0) return -1;
    for (size_t i = 0; i < n_logs; i++) {
        const evm_log_t *lg = &logs[i];
        if (lg->n_topics > 4 || lg->data_len > UINT32_MAX) return -1;
        if (buf_put(b, lg->addr.b, 32) != 0 ||
            buf_put(b, &lg->n_topics, 1) != 0)
            return -1;
        for (uint8_t k = 0; k < lg->n_topics; k++)
            if (buf_put(b, lg->topics[k].b, 32) != 0) return -1;
        put_u32be(t, (uint32_t)lg->data_len);
        if (buf_put(b, t, 4) != 0 ||
            buf_put(b, lg->data, lg->data_len) != 0)
            return -1;
    }
    evm_u256_to_be(t, destroyed);
    if (buf_put(b, t, 32) != 0) return -1;
    t[0] = (uint8_t)(n_tickets >> 8);
    t[1] = (uint8_t)n_tickets;
    if (buf_put(b, t, 2) != 0) return -1;
    for (size_t i = 0; i < n_tickets; i++)
        if (buf_put(b, tickets[i].ticket_id, 64) != 0) return -1;
    return 0;
}

/** The receipt of an outcome with nothing but a status (the failure path,
 *  design §4 "makbuz: status 0, output BOŞ, log YOK, bilet YOK,
 *  wei_destroyed = 0, evm_gas_used = gas_limit", and the bridge ops). */
static int rcpt_plain(rt_buf *b, uint8_t status, uint8_t op, uint64_t gas) {
    evm_u256 z;
    evm_u256_zero(&z);
    return rcpt_build(b, status, op, gas, NULL, NULL, 0, NULL, 0, &z,
                      NULL, 0);
}

/* ── call bytes (design §2) ────────────────────────────────────────────── */

typedef struct {
    uint32_t op;
    uint8_t  to[32];
    uint8_t  value[32];
    uint64_t gas_limit;
    uint64_t nonce;
    uint32_t n_acc;
    uint64_t n_keys_total;
    const uint8_t *data;          /* CALL data / CREATE initcode          */
    uint32_t data_len;
    uint64_t amount_raw;
    uint8_t  dest_fp[64];
    uint8_t  ticket_id[64];
} rtevm_call_t;

/* ONE CODEC (Nodus EVM Faz 4): the shared codec's restated engine constant */
_Static_assert(DNA_EVM_MAX_INITCODE == EVM_MAX_INITCODE_SIZE,
               "the shared codec's EIP-3860 cap drifted from the engine's");
_Static_assert(DNA_EVM_Q == NODUS_RT_EVM_Q,
               "the shared codec's wei-per-raw-unit drifted");

/** The access list's share of the engine's intrinsic gas, from the COUNTS
 *  alone (red-team 1 F3): TX_BASE + 2400 × n_access + 1900 × n_keys —
 *  the access_cost term of evm_tx.c calculate_intrinsic_cost plus its
 *  base, every other term (calldata, CREATE) left out, so it never
 *  exceeds the engine's `ic.regular` and therefore never its `need`
 *  (evm_tx.c validate: max(regular, calldata_floor) > gas_limit refuses).
 *  Checked: an overflow is a value above every u64 gas_limit — the
 *  engine's saturating sum refuses it too. Duplicate entries count, as
 *  they do in the engine (Prague charges every listed entry).
 *  @return 0 the floor fits gas_limit / -1 the engine would refuse. */
static int access_intrinsic_floor_ok(uint64_t gas_limit, uint64_t n_access,
                                     uint64_t n_keys) {
    uint64_t a = 0, k = 0, s = 0;
    if (dna_ck_mul_u64(n_access, EVM_G_TX_ACCESS_LIST_ADDRESS, &a) != 0 ||
        dna_ck_mul_u64(n_keys, EVM_G_TX_ACCESS_LIST_STORAGE_KEY, &k) != 0 ||
        dna_ck_add_u64(a, k, &s) != 0 ||
        dna_ck_add_u64(s, EVM_G_TX_BASE, &s) != 0)
        return -1;
    return s > gas_limit ? -1 : 0;
}

/** Fill the engine's access list (p->acc / p->acc_keys) from a decoded
 *  call's well-formed access body: first the pure intrinsic floor from
 *  the counts (BEFORE any allocation — a list the engine's intrinsic
 *  check refuses is never materialized), then ONE linear cursor pass
 *  (dna_evm_access_next). Duplicate entries are kept, in wire order.
 *  @return 0 / -1 / -2 allocation. */
static int fill_access(const dna_evm_call_t *d, rtevm_priv_t *p) {
    if (d->n_access == 0) return 0;
    if (access_intrinsic_floor_ok(d->gas_limit, d->n_access,
                                  d->n_access_keys) != 0)
        return -1;
    p->acc = calloc(d->n_access, sizeof(*p->acc));
    p->acc_keys = d->n_access_keys
        ? calloc((size_t)d->n_access_keys, sizeof(*p->acc_keys)) : NULL;
    if (!p->acc || (d->n_access_keys && !p->acc_keys)) return -2;
    uint64_t kk = 0;
    size_t off = 0;
    for (uint16_t i = 0; i < d->n_access; i++) {
        const uint8_t *addr = NULL, *keys = NULL;
        uint16_t nk = 0;
        if (dna_evm_access_next(d->access, d->access_len, &off, &addr, &nk,
                                &keys) != 0)
            return -1;
        memcpy(p->acc[i].addr.b, addr, 32);
        p->acc[i].n_keys = nk;
        p->acc[i].keys = nk ? &p->acc_keys[kk] : NULL;
        for (uint16_t j = 0; j < nk; j++, kk++) {
            if (kk >= d->n_access_keys) return -1;
            memcpy(p->acc_keys[kk].b, keys + (size_t)j * 32, 32);
        }
    }
    /* the decode's walk proved the body is exactly these entries */
    if (off != d->access_len || kk != d->n_access_keys) return -1;
    return 0;
}

/** Decode the call bytes of runtime op `op` — exact length, BE, `ver`
 *  first; trailing bytes refuse (design §2) — through the ONE codec
 *  (shared/dnac/evm_call_wire.c dna_evm_call_decode, whose head is the
 *  same dna_evm_call_head the CORE EVMFUND hook and the block gas sum
 *  read). @return 0 / -1 / -2. */
static int rtevm_decode(uint32_t op, const uint8_t *c, size_t len,
                        rtevm_call_t *k, rtevm_priv_t *p) {
    memset(k, 0, sizeof(*k));
    k->op = op;
    dna_evm_call_t d;
    if (dna_evm_call_decode(op, c, len, &d) != 0) return -1;
    k->gas_limit = d.gas_limit;
    k->nonce = d.nonce;
    k->amount_raw = d.amount_raw;
    memcpy(k->to, d.to, 32);
    memcpy(k->value, d.value_wei, 32);
    memcpy(k->dest_fp, d.dest_fp, 64);
    memcpy(k->ticket_id, d.ticket_id, 64);
    if (op != NODUS_RT_EVM_CALL && op != NODUS_RT_EVM_CREATE)
        return 0;                       /* bridge ops: exact-length heads */
    k->n_acc = d.n_access;
    k->n_keys_total = d.n_access_keys;
    if (p) {
        int rc = fill_access(&d, p);
        if (rc != 0) return rc;
    }
    k->data = d.data;
    k->data_len = d.data_len;
    return 0;
}

/* ── effect builders (design §4) ─────────────────────────────────────── */

static int eff_acct(rtevm_priv_t *p, const uint8_t addr[32],
                    const rtevm_acct_t *pre, const rtevm_acct_t *post) {
    uint8_t v[NODUS_RT_EVM_ACCT_LEN];
    acct_encode(post, v);
    if (!pre->exists)
        return eff_add(p, NODUS_RT_EVM_OP_ACCT, DNA_EFFECT_CREATE,
                       DNA_EFFECT_PRE_ABSENT, addr, 32, v, sizeof(v));
    return eff_add(p, NODUS_RT_EVM_OP_ACCT, DNA_EFFECT_SET,
                   DNA_EFFECT_PRE_EXISTS, addr, 32, v, sizeof(v));
}

static int eff_meta(rtevm_priv_t *p, const rtevm_meta_t *m) {
    uint8_t v[NODUS_RT_EVM_META_LEN];
    meta_encode(m, v);
    return eff_add(p, NODUS_RT_EVM_OP_META, DNA_EFFECT_SET,
                   DNA_EFFECT_PRE_EXISTS, META_KEY, 1, v, sizeof(v));
}

static int acct_equal(const rtevm_acct_t *a, const rtevm_acct_t *b) {
    return a->nonce == b->nonce &&
           memcmp(a->balance, b->balance, 32) == 0 &&
           memcmp(a->code_hash, b->code_hash, 32) == 0 &&
           a->code_size == b->code_size &&
           memcmp(a->code_digest, b->code_digest, 64) == 0 &&
           a->storage_count == b->storage_count;
}

/* the engine admits a CALL/CREATE leg only if its declared ceilings carry
 * the failure result, and prices it against FAIL_RESERVE — pinned to the
 * one ACCT effect built below (res_meter.h DNA_METER_EVM_FAIL_*) */
_Static_assert(DNA_EFFECT_FIXED_HEAD + DNA_EFFECT_RECORD_LEN + 32 +
                   NODUS_RT_EVM_ACCT_LEN == DNA_METER_EVM_FAIL_BYTES,
               "the failure result's canonical length drifted");

/** The fixed failure-result effect (design §4): the sender's nonce + 1,
 *  nothing else — computed from the PRE-execution record. */
static int build_failure(rtevm_priv_t *p, const uint8_t sender[32],
                         const rtevm_acct_t *pre) {
    rtevm_acct_t post = *pre;
    if (!pre->exists && acct_empty(&post) != 0) return -2;
    if (post.nonce == UINT64_MAX) return -1;      /* prevalidate refuses */
    post.nonce++;
    uint8_t v[NODUS_RT_EVM_ACCT_LEN];
    acct_encode(&post, v);
    uint8_t *k = ra_alloc(&p->arena, 32);
    uint8_t *vv = ra_alloc(&p->arena, sizeof(v));
    if (!k || !vv) return -2;
    memcpy(k, sender, 32);
    memcpy(vv, v, sizeof(v));
    dna_effect_in_t *e = &p->fail_eff[0];
    memset(e, 0, sizeof(*e));
    e->hdr.op_id = NODUS_RT_EVM_OP_ACCT;
    e->hdr.effect_kind = pre->exists ? DNA_EFFECT_SET : DNA_EFFECT_CREATE;
    e->hdr.precond_tag = pre->exists ? DNA_EFFECT_PRE_EXISTS
                                     : DNA_EFFECT_PRE_ABSENT;
    e->hdr.key_len = 32;
    e->hdr.value_len = sizeof(v);
    e->key = k;
    e->value = vv;
    return 0;
}

/* ── the change-set visitor (design §4) ───────────────────────────────── */

typedef struct {
    uint8_t  addr[32];
    int      deleted;
    uint64_t nonce;
    uint8_t  balance[32];
    int      code_changed;
    uint8_t *code;               /* arena copy                            */
    size_t   code_len;
    uint8_t  code_hash[32];
    int      storage_cleared;
    uint32_t first_slot, n_slots;
} rtevm_achg_t;

typedef struct {
    uint8_t key[32];
    uint8_t val[32];
} rtevm_schg_t;

typedef struct {
    rtevm_priv_t *p;
    rtevm_achg_t *acc;
    size_t        n_acc, cap_acc;
    rtevm_schg_t *slot;
    size_t        n_slot, cap_slot;
} rtevm_vis_t;

static int vis_account(void *ctx, const evm_account_change_t *c) {
    rtevm_vis_t *v = (rtevm_vis_t *)ctx;
    if (v->n_acc == v->cap_acc) {
        size_t nc = v->cap_acc ? v->cap_acc * 2 : 32;
        rtevm_achg_t *g = realloc(v->acc, nc * sizeof(*g));
        if (!g) return -2;
        v->acc = g;
        v->cap_acc = nc;
    }
    rtevm_achg_t *a = &v->acc[v->n_acc++];
    memset(a, 0, sizeof(*a));
    memcpy(a->addr, c->addr.b, 32);
    a->deleted = c->deleted ? 1 : 0;
    a->nonce = c->nonce;
    evm_u256_to_be(a->balance, &c->balance);
    a->code_changed = c->code_changed ? 1 : 0;
    memcpy(a->code_hash, c->code_hash.b, 32);
    a->storage_cleared = c->storage_cleared ? 1 : 0;
    if (c->code_changed && c->code_len > 0) {
        if (!c->code || c->code_len > EVM_MAX_CODE_SIZE) return -2;
        a->code = ra_alloc(&v->p->arena, c->code_len);
        if (!a->code) return -2;
        memcpy(a->code, c->code, c->code_len);
        a->code_len = c->code_len;
    }
    a->first_slot = (uint32_t)v->n_slot;
    return 0;
}

static int vis_storage(void *ctx, const evm_addr *addr,
                       const evm_bytes32 *key, const evm_bytes32 *value) {
    rtevm_vis_t *v = (rtevm_vis_t *)ctx;
    /* the engine reports slots right after their account, ascending */
    if (v->n_acc == 0 ||
        memcmp(v->acc[v->n_acc - 1].addr, addr->b, 32) != 0)
        return -2;
    if (v->n_slot == v->cap_slot) {
        size_t nc = v->cap_slot ? v->cap_slot * 2 : 64;
        rtevm_schg_t *g = realloc(v->slot, nc * sizeof(*g));
        if (!g) return -2;
        v->slot = g;
        v->cap_slot = nc;
    }
    rtevm_schg_t *s = &v->slot[v->n_slot++];
    memcpy(s->key, key->b, 32);
    memcpy(s->val, value->b, 32);
    v->acc[v->n_acc - 1].n_slots++;
    return 0;
}

static int is_zero32(const uint8_t *b) {
    for (int i = 0; i < 32; i++)
        if (b[i]) return 0;
    return 1;
}

/** Checked u256 accumulate: *acc += x. @return 0 / -1 overflow. */
static int u256_acc(evm_u256 *acc, const evm_u256 *x) {
    evm_u256 r;
    if (evm_u256_add(&r, acc, x)) return -1;
    *acc = r;
    return 0;
}

/**
 * Turn a SUCCESSFUL CALL/CREATE's change set into the canonical stream
 * (design §4, §5). Pre-state comes through the reader (normally from its
 * cache: execution already read every account and every original slot
 * value it changed). @return 0 built; RTEVM_BUDGET_RC a read hit the
 * budget verdict (the caller takes the failure path — deterministic);
 * -2 fault (a broken invariant: conservation, a deleted account with
 * storage, a code change on a live contract, ...).
 */
static int build_success(rtevm_priv_t *p, rtevm_be_t *b,
                         const rtevm_vis_t *v, const evm_tx_result_t *res) {
    evm_u256 inc, dec;
    evm_u256_zero(&inc);
    evm_u256_zero(&dec);
    uint8_t (*code_done)[64] = NULL;     /* code digests already emitted */
    size_t n_code_done = 0;
    int ret = -2;

    if (v->n_acc && !(code_done = calloc(v->n_acc, sizeof(*code_done))))
        return -2;

    for (size_t i = 0; i < v->n_acc; i++) {
        const rtevm_achg_t *a = &v->acc[i];
        rtevm_acct_t pre;
        int rc = read_acct(b, a->addr, &pre);
        if (rc == EVM_BUDGET) { ret = RTEVM_BUDGET_RC; goto out; }
        if (rc != 0) goto out;

        /* EIP-7610 is retained (evm.h has_storage): a CREATE never lands
         * on committed storage, so a cleared account had none */
        if (a->storage_cleared && pre.exists && pre.storage_count != 0) {
            QGP_LOG_ERROR(LOG_TAG, "storage_cleared on an account with "
                          "%llu committed slots",
                          (unsigned long long)pre.storage_count);
            goto out;
        }

        /* slots: kind from (pre, post), storage_count from the deltas */
        uint64_t added = 0, removed = 0;
        for (uint32_t s = 0; s < a->n_slots; s++) {
            const rtevm_schg_t *sc = &v->slot[a->first_slot + s];
            uint8_t key[64];
            memcpy(key, a->addr, 32);
            memcpy(key + 32, sc->key, 32);
            int pre_nz = 0;
            if (!a->storage_cleared) {
                rc = be_read(b, NODUS_RT_EVM_OP_SLOT, key, 64);
                if (rc == EVM_BUDGET) { ret = RTEVM_BUDGET_RC; goto out; }
                if (rc != 0) goto out;
                if (b->rr->present) {
                    if (b->rr->value_len != 32 ||
                        is_zero32(b->rr->value))   /* zero = no row      */
                        goto out;
                    pre_nz = 1;
                }
            }
            int post_nz = !is_zero32(sc->val);
            if (a->deleted && post_nz) {
                QGP_LOG_ERROR(LOG_TAG, "a deleted account keeps storage");
                goto out;
            }
            if (!pre_nz && post_nz) {
                if (eff_add(p, NODUS_RT_EVM_OP_SLOT, DNA_EFFECT_CREATE,
                            DNA_EFFECT_PRE_ABSENT, key, 64, sc->val, 32) != 0)
                    goto out;
                added++;
            } else if (pre_nz && post_nz) {
                if (eff_add(p, NODUS_RT_EVM_OP_SLOT, DNA_EFFECT_SET,
                            DNA_EFFECT_PRE_EXISTS, key, 64, sc->val, 32) != 0)
                    goto out;
            } else if (pre_nz && !post_nz) {
                if (eff_add(p, NODUS_RT_EVM_OP_SLOT, DNA_EFFECT_DELETE,
                            DNA_EFFECT_PRE_EXISTS, key, 64, NULL, 0) != 0)
                    goto out;
                removed++;
            }
        }

        evm_u256 pre_bal, post_bal;
        evm_u256_from_be(&pre_bal, pre.balance);
        if (!pre.exists) evm_u256_zero(&pre_bal);

        if (a->deleted) {
            /* design §4: a deleted account has no committed slot */
            if (pre.exists) {
                if (pre.storage_count != 0 || added != 0) {
                    QGP_LOG_ERROR(LOG_TAG, "deleted account with storage");
                    goto out;
                }
                if (eff_add(p, NODUS_RT_EVM_OP_ACCT, DNA_EFFECT_DELETE,
                            DNA_EFFECT_PRE_EXISTS, a->addr, 32, NULL, 0) != 0)
                    goto out;
                if (u256_acc(&dec, &pre_bal) != 0) goto out;
            }
            continue;                    /* never existed: a no-op       */
        }

        rtevm_acct_t post;
        if (pre.exists) {
            post = pre;
        } else if (acct_empty(&post) != 0) {
            goto out;
        }
        post.exists = 1;
        post.nonce = a->nonce;
        memcpy(post.balance, a->balance, 32);
        if (a->code_changed) {
            if (a->code_len == 0) {        /* code removed, not deleted   */
                QGP_LOG_ERROR(LOG_TAG, "code removed from a live account");
                goto out;
            }
            if (pre.exists && pre.code_size != 0) {
                QGP_LOG_ERROR(LOG_TAG, "code replaced on a live contract");
                goto out;
            }
            post.code_size = (uint32_t)a->code_len;
            memcpy(post.code_hash, a->code_hash, 32);
            if (qgp_sha3_512(a->code, a->code_len, post.code_digest) != 0)
                goto out;
        }
        uint64_t base = pre.exists ? pre.storage_count : 0;
        if (base + added < base || base + added < removed) {
            QGP_LOG_ERROR(LOG_TAG, "storage_count underflow/overflow");
            goto out;
        }
        post.storage_count = base + added - removed;

        evm_u256_from_be(&post_bal, post.balance);
        int c = evm_u256_cmp(&post_bal, &pre_bal);
        evm_u256 d;
        if (c > 0) {
            evm_u256_sub(&d, &post_bal, &pre_bal);
            if (u256_acc(&inc, &d) != 0) goto out;
        } else if (c < 0) {
            evm_u256_sub(&d, &pre_bal, &post_bal);
            if (u256_acc(&dec, &d) != 0) goto out;
        }

        /* design §4 no-op account rule (I8): identical pre and post
         * produce no effect (the zero-fee coinbase touch, a pure storage
         * value change) */
        if (!pre.exists || !acct_equal(&pre, &post)) {
            if (eff_acct(p, a->addr, &pre, &post) != 0) goto out;
        }

        /* new code: its chunks, unless this digest is already stored or
         * already emitted by an earlier account of this stream */
        if (a->code_changed) {
            int seen = 0;
            for (size_t k = 0; k < n_code_done && !seen; k++)
                if (memcmp(code_done[k], post.code_digest, 64) == 0)
                    seen = 1;
            if (!seen) {
                uint8_t ck[65];
                memcpy(ck, post.code_digest, 64);
                ck[64] = 0;
                rc = be_read(b, NODUS_RT_EVM_OP_CODE, ck, 65);
                if (rc == EVM_BUDGET) { ret = RTEVM_BUDGET_RC; goto out; }
                if (rc != 0) goto out;
                if (!b->rr->present) {
                    uint32_t n_chunks = (uint32_t)((a->code_len +
                        NODUS_RT_EVM_CODE_CHUNK - 1) / NODUS_RT_EVM_CODE_CHUNK);
                    for (uint32_t k = 0; k < n_chunks; k++) {
                        size_t off = (size_t)k * NODUS_RT_EVM_CODE_CHUNK;
                        size_t n = a->code_len - off;
                        if (n > NODUS_RT_EVM_CODE_CHUNK)
                            n = NODUS_RT_EVM_CODE_CHUNK;
                        ck[64] = (uint8_t)k;
                        if (eff_add(p, NODUS_RT_EVM_OP_CODE,
                                    DNA_EFFECT_CREATE, DNA_EFFECT_PRE_ABSENT,
                                    ck, 65, a->code + off,
                                    (uint32_t)n) != 0)
                            goto out;
                    }
                }
                memcpy(code_done[n_code_done++], post.code_digest, 64);
            }
        }
    }

    /* tickets (design §5): value that left wei_live for wei_tickets */
    evm_u256 ticket_wei, q;
    evm_u256_zero(&ticket_wei);
    evm_u256_from_u64(&q, NODUS_RT_EVM_Q);
    for (size_t i = 0; i < res->n_tickets; i++) {
        const evm_ticket_t *t = &res->tickets[i];
        evm_u256 raw, back;
        uint64_t raw64 = 0;
        evm_u256_div(&raw, &t->amount_wei, &q);
        evm_u256_mul(&back, &raw, &q);
        if (evm_u256_cmp(&back, &t->amount_wei) != 0 ||
            !evm_u256_to_u64(&raw, &raw64) || raw64 == 0) {
            QGP_LOG_ERROR(LOG_TAG, "a ticket's value is not a u64 multiple "
                          "of q");
            goto out;
        }
        if (u256_acc(&ticket_wei, &t->amount_wei) != 0) goto out;
        uint8_t tv[NODUS_RT_EVM_TICKET_LEN];
        put_u64be(tv, raw64);
        memcpy(tv + 8, t->dest_fp, 64);
        if (eff_add(p, NODUS_RT_EVM_OP_TICKET, DNA_EFFECT_CREATE,
                    DNA_EFFECT_PRE_ABSENT, t->ticket_id, 64, tv,
                    sizeof(tv)) != 0)
            goto out;
    }

    /* design §5: Σ(balance deltas) == −(wei_destroyed + Σ ticket wei) —
     * VERIFIED, never used to compute a loss */
    {
        evm_u256 net, rhs;
        if (evm_u256_cmp(&dec, &inc) < 0) {
            QGP_LOG_ERROR(LOG_TAG, "EVM value conservation: balances grew");
            goto out;
        }
        evm_u256_sub(&net, &dec, &inc);
        if (evm_u256_add(&rhs, &res->wei_destroyed, &ticket_wei) ||
            evm_u256_cmp(&net, &rhs) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "EVM value conservation violated "
                          "(balance deltas != wei_destroyed + tickets)");
            goto out;
        }
    }

    /* META (design §5 table): destroyed x → live −x, lost +x; tickets t →
     * live −t, tickets +t */
    if (!evm_u256_is_zero(&res->wei_destroyed) ||
        !evm_u256_is_zero(&ticket_wei)) {
        rtevm_meta_t m;
        int rc = read_meta(b, &m);
        if (rc == EVM_BUDGET) { ret = RTEVM_BUDGET_RC; goto out; }
        if (rc != 0) goto out;
        evm_u256 out_live;
        if (evm_u256_sub(&out_live, &m.live, &res->wei_destroyed) ||
            evm_u256_sub(&out_live, &out_live, &ticket_wei)) {
            QGP_LOG_ERROR(LOG_TAG, "wei_live underflow");
            goto out;
        }
        m.live = out_live;
        if (u256_acc(&m.tickets, &ticket_wei) != 0 ||
            u256_acc(&m.lost, &res->wei_destroyed) != 0)
            goto out;
        if (eff_meta(p, &m) != 0) goto out;
    }
    ret = 0;
out:
    free(code_done);
    return ret;
}

/* ── CALL / CREATE (design §2, §4, §10) ──────────────────────────────── */

/** The VM frame of ONE CALL / CREATE leg — everything evm_state_new and
 *  the engine's apply borrow, kept alive together for the leg. */
typedef struct {
    evm_config_t    cfg;
    evm_backend_t   bk;
    evm_block_env_t benv;
    evm_tx_t        tx;
    rtevm_acct_t    sender_pre;
    evm_state_t    *st;
} rtevm_vm_t;

/**
 * THE shared pre-validation of a CALL / CREATE leg (design §4 "Ön
 * doğrulama"; §8 recheck): the gas declaration (cap + the units
 * inequality), the pre-reads of every account the tail needs, and the
 * engine's own validity checks (nonce == the committed nonce, value <=
 * balance, intrinsic gas, EIP-3607, chain id, the nonce ceiling). NOTHING
 * executes. On 0, vm->st is the state execution continues on (the
 * caller frees it with evm_state_free).
 * @return 0 / -1 refused / -2 fault.
 */
static int rtevm_vm_pre(const nodus_rt_exec_ctx_t *ctx,
                        const nodus_rt_v2_reader_t *reader,
                        const rtevm_call_t *k, rtevm_priv_t *p,
                        rtevm_be_t *be, rtevm_vm_t *vm) {
    const uint8_t *sender = ctx->auth->signer_fp[0];   /* fp[0..32]      */
    static const uint8_t zero32[32] = { 0 };
    memset(vm, 0, sizeof(*vm));

    /* pre-validation 1 — the gas declaration: gas_limit cap and the units
     * inequality (design §4 / §8), before any read */
    int rc = reader->declare_gas(reader->ctx, k->gas_limit, k->n_keys_total);
    if (rc != 0) return rc == -1 ? -1 : -2;

    /* the reads evm_tx_apply's tail cannot be allowed to hit the budget
     * for: sender, coinbase (zero), the call target — read (and cached)
     * BEFORE execution; a budget verdict here refuses the leg, nothing
     * has executed */
    rtevm_acct_t tmp;
    rc = read_acct(be, sender, &vm->sender_pre);
    if (rc == 0) rc = read_acct(be, zero32, &tmp);
    if (rc == 0 && k->op == NODUS_RT_EVM_CALL) rc = read_acct(be, k->to, &tmp);
    if (rc == EVM_BUDGET) return -1;
    if (rc != 0) return -2;

    evm_config_t *cfg = &vm->cfg;
    cfg->fork = EVM_FORK_PRAGUE;
    cfg->addr_bytes = 32;
    evm_u256_from_be(&cfg->chain_id, ctx->chain_id);  /* 32 bytes, never cut */
    cfg->precompile_mask = EVM_PRECOMPILES_PRAGUE;
    cfg->nodus_profile = 1;
    if (nodus_rt_evm_ticket_addr(cfg->ticket_addr.b) != 0) return -2;
    evm_u256_from_u64(&cfg->ticket_unit, NODUS_RT_EVM_Q);
    cfg->ticket_gas = NODUS_RT_EVM_TICKET_GAS;

    evm_backend_t *bk = &vm->bk;
    bk->ctx = be;
    bk->get_account = be_get_account;
    bk->get_code = be_get_code;
    bk->get_storage = be_get_storage;
    bk->get_block_hash = be_get_block_hash;
    bk->has_storage = be_has_storage;

    /* design §10: the Nodus block environment (coinbase 0, prevrandao 0) */
    evm_block_env_t *benv = &vm->benv;
    benv->number = ctx->global_height;
    benv->timestamp = ctx->block_time_s;
    benv->gas_limit = ctx->evm_block_gas_limit;
    evm_u256_zero(&benv->base_fee);
    benv->excess_blob_gas = 0;

    evm_tx_t *tx = &vm->tx;
    tx->type = 1;                              /* EIP-2930, always         */
    memcpy(tx->sender.b, sender, 32);
    tx->is_create = (k->op == NODUS_RT_EVM_CREATE);
    if (!tx->is_create) memcpy(tx->to.b, k->to, 32);
    tx->nonce = k->nonce;
    tx->gas_limit = k->gas_limit;
    evm_u256_zero(&tx->gas_price);
    evm_u256_from_be(&tx->value, k->value);
    tx->data = k->data;
    tx->data_len = k->data_len;
    tx->n_access = k->n_acc;
    tx->access = p->acc;
    tx->has_chain_id = 1;
    tx->chain_id = cfg->chain_id;
    memcpy(tx->intent_id, ctx->intent_id, 64);

    vm->st = evm_state_new(cfg, bk);
    if (!vm->st) return -2;
    /* pre-validation 2 — the engine's own validity checks (nonce,
     * value <= balance, intrinsic gas, EIP-3607, chain id, ...) */
    evm_tx_result_t pv;
    memset(&pv, 0, sizeof(pv));
    rc = evm_tx_prevalidate(vm->st, benv, tx, &pv);
    evm_tx_result_free(&pv);
    if (rc == 0) return 0;
    evm_state_free(vm->st);
    vm->st = NULL;
    return (rc == -1 || rc == EVM_BUDGET) ? -1 : -2;
}

static int rtevm_exec_vm(const nodus_rt_exec_ctx_t *ctx,
                         const nodus_rt_v2_reader_t *reader,
                         const rtevm_call_t *k, rtevm_priv_t *p,
                         rtevm_be_t *be, nodus_rt_v2_out_t *out) {
    const uint8_t *sender = ctx->auth->signer_fp[0];   /* fp[0..32]      */
    rtevm_vm_t *vm = calloc(1, sizeof(*vm));
    if (!vm) return -2;
    int rc = rtevm_vm_pre(ctx, reader, k, p, be, vm);
    if (rc != 0) {
        free(vm);
        return rc;
    }
    evm_state_t *st = vm->st;
    const rtevm_acct_t sender_pre = vm->sender_pre;
    int ret = -2;
    do {
        /* the fixed failure outcome, decided before execution (I10) */
        rc = build_failure(p, sender, &sender_pre);
        if (rc != 0) { ret = rc; break; }
        if (rcpt_plain(&p->fail_rcpt, 0, (uint8_t)k->op, k->gas_limit) != 0)
            break;

        memset(&p->res, 0, sizeof(p->res));
        rc = evm_tx_apply(st, &vm->benv, &vm->tx, &p->res);
        p->res_set = 1;
        if (rc == -1) { ret = -1; break; }    /* prevalidate passed: none */
        if (rc != 0) {
            /* -3 here means a tail read hit the budget although every
             * tail account was read before execution — an invariant of
             * this node, not a verdict */
            QGP_LOG_ERROR(LOG_TAG, "evm_tx_apply rc %d after pre-reads", rc);
            break;
        }

        out->gas_limit = k->gas_limit;
        out->failable = 1;
        if (p->res.status != EVM_EXEC_SUCCESS) {
            out->success = 0;                 /* REVERT / OOG / BUDGET ... */
            out->gas_used = k->gas_limit;
            ret = 0;
            break;
        }

        rtevm_vis_t vis;
        memset(&vis, 0, sizeof(vis));
        vis.p = p;
        evm_change_visitor_t cv;
        cv.account = vis_account;
        cv.storage = vis_storage;
        cv.ctx = &vis;
        be->budget_hit = 0;
        rc = evm_state_visit_changes(st, &cv);
        int brc = -2;
        if (rc == 0) {
            brc = build_success(p, be, &vis, &p->res);
        } else if (be->budget_hit) {
            brc = RTEVM_BUDGET_RC;            /* a visit-time read, §3   */
        }
        free(vis.acc);
        free(vis.slot);
        if (brc == RTEVM_BUDGET_RC) {
            /* deterministic: the change set could not be built within the
             * leg's read budget — the failure path, nothing applied */
            p->n_eff = 0;
            out->success = 0;
            out->gas_used = k->gas_limit;
            ret = 0;
            break;
        }
        if (brc != 0) break;

        qsort(p->eff, p->n_eff, sizeof(*p->eff), eff_sort_cmp);

        /* the success receipt (design §7) */
        const uint8_t *created = NULL;
        if (vm->tx.is_create) created = p->res.created.b;
        if (rcpt_build(&p->rcpt, 1, (uint8_t)k->op, p->res.gas_used, created,
                       p->res.output, p->res.output_len, p->res.logs,
                       p->res.n_logs, &p->res.wei_destroyed, p->res.tickets,
                       p->res.n_tickets) != 0)
            break;
        if (p->res.n_logs) {
            p->logs = calloc(p->res.n_logs, sizeof(*p->logs));
            if (!p->logs) break;
            for (size_t i = 0; i < p->res.n_logs; i++) {
                const evm_log_t *lg = &p->res.logs[i];
                p->logs[i].addr = lg->addr.b;
                p->logs[i].n_topics = lg->n_topics;
                p->logs[i].topics = lg->n_topics ? lg->topics[0].b : NULL;
                p->logs[i].data = lg->data;
                p->logs[i].data_len = (uint32_t)lg->data_len;
            }
            out->logs = p->logs;
            out->n_logs = (uint32_t)p->res.n_logs;
        }
        out->success = 1;
        out->gas_used = p->res.gas_used;
        ret = 0;
    } while (0);
    evm_state_free(st);
    free(vm);
    return ret;
}

/* ── DEPOSIT / WITHDRAW / REDEEM (design §2, §5): value moves, no VM ──
 * Every failure is -1: the whole item rolls back, the CORE EVMFUND half
 * (the reserve move and, for a release, the CORE UTXO) with it — the
 * principal is atomic (design §4). The CORE reserve is CORE's: these ops
 * move only the EVM side (a balance and META); CORE EVMFUND moves the
 * reserve by the SAME amount_raw, read from these same call bytes. */

/** What the bridge pre-validation established (the effects are built
 *  from it — nothing is read twice). */
typedef struct {
    rtevm_meta_t m;               /* META after the move                   */
    rtevm_acct_t pre, post;       /* DEPOSIT / WITHDRAW: the sender        */
} rtevm_bridge_t;

/**
 * THE shared pre-validation of a bridge op (design §4: "köprü op'ları
 * kod yürütmez: hepsi ön doğrulamadır"): non-zero amount; REDEEM: the
 * ticket exists and the call names it EXACTLY; DEPOSIT / WITHDRAW: nonce
 * == the committed nonce, WITHDRAW amount <= balance; the META move fits
 * its checked arithmetic. Fills *b with the post state.
 * @return 0 / -1 refused / -2 fault.
 */
static int rtevm_bridge_pre(const nodus_rt_exec_ctx_t *ctx,
                            const rtevm_call_t *k, rtevm_be_t *be,
                            rtevm_bridge_t *b) {
    const uint8_t *sender = ctx->auth->signer_fp[0];
    evm_u256 wei;
    int rc;

    memset(b, 0, sizeof(*b));
    if (k->amount_raw == 0) return -1;
    wei_of_raw(&wei, k->amount_raw);

    if (k->op == NODUS_RT_EVM_REDEEM) {
        rc = be_read(be, NODUS_RT_EVM_OP_TICKET, k->ticket_id, 64);
        if (rc == EVM_BUDGET) return -1;
        if (rc != 0) return -2;
        if (!be->rr->present) return -1;              /* unknown / spent */
        if (be->rr->value_len != NODUS_RT_EVM_TICKET_LEN) return -2;
        /* the call must name the ticket EXACTLY (design §2) — and the
         * CORE EVMFUND RELEASE pays exactly these call bytes */
        if (get_u64be(be->rr->value) != k->amount_raw ||
            memcmp(be->rr->value + 8, k->dest_fp, 64) != 0)
            return -1;
        rc = read_meta(be, &b->m);
        if (rc == EVM_BUDGET) return -1;
        if (rc != 0) return -2;
        if (evm_u256_sub(&b->m.tickets, &b->m.tickets, &wei)) {
            QGP_LOG_ERROR(LOG_TAG, "REDEEM: META below a live ticket");
            return -2;
        }
        return 0;
    }

    rc = read_acct(be, sender, &b->pre);
    if (rc == EVM_BUDGET) return -1;
    if (rc != 0) return -2;
    /* nonce discipline of every nonce'd op (design §2) */
    if ((b->pre.exists ? b->pre.nonce : 0) != k->nonce) return -1;
    if (k->nonce == UINT64_MAX) return -1;
    rc = read_meta(be, &b->m);
    if (rc == EVM_BUDGET) return -1;
    if (rc != 0) return -2;
    b->post = b->pre;
    if (!b->pre.exists && acct_empty(&b->post) != 0) return -2;
    b->post.exists = 1;
    b->post.nonce = k->nonce + 1;
    evm_u256 bal;
    evm_u256_from_be(&bal, b->post.balance);
    if (k->op == NODUS_RT_EVM_DEPOSIT) {
        if (evm_u256_add(&bal, &bal, &wei) ||
            evm_u256_add(&b->m.live, &b->m.live, &wei))
            return -1;
    } else {                                       /* WITHDRAW            */
        if (!b->pre.exists || evm_u256_cmp(&bal, &wei) < 0) return -1;
        evm_u256_sub(&bal, &bal, &wei);
        if (evm_u256_sub(&b->m.live, &b->m.live, &wei)) {
            QGP_LOG_ERROR(LOG_TAG, "WITHDRAW: META below a balance");
            return -2;
        }
    }
    evm_u256_to_be(b->post.balance, &bal);
    return 0;
}

static int rtevm_bridge(const nodus_rt_exec_ctx_t *ctx, const rtevm_call_t *k,
                        rtevm_priv_t *p, rtevm_be_t *be,
                        nodus_rt_v2_out_t *out) {
    const uint8_t *sender = ctx->auth->signer_fp[0];
    rtevm_bridge_t b;
    int rc = rtevm_bridge_pre(ctx, k, be, &b);
    if (rc != 0) return rc;
    if (k->op == NODUS_RT_EVM_REDEEM) {
        if (eff_add(p, NODUS_RT_EVM_OP_TICKET, DNA_EFFECT_DELETE,
                    DNA_EFFECT_PRE_EXISTS, k->ticket_id, 64, NULL, 0) != 0 ||
            eff_meta(p, &b.m) != 0)
            return -2;
    } else {
        if (eff_acct(p, sender, &b.pre, &b.post) != 0 ||
            eff_meta(p, &b.m) != 0)
            return -2;
    }
    qsort(p->eff, p->n_eff, sizeof(*p->eff), eff_sort_cmp);
    if (rcpt_plain(&p->rcpt, 1, (uint8_t)k->op, 0) != 0) return -2;
    out->success = 1;
    out->failable = 0;
    out->gas_limit = 0;
    out->gas_used = 0;
    return 0;
}

/* ── the shared prologue of both hooks: argument shape, authorization
 *    shape, the pairing rule, the decode ─────────────────────────────── */

/** @return 0 / -1 refused / -2 fault. */
static int rtevm_prologue(const dna_env_view_t *env, uint16_t leg_index,
                          const nodus_rt_exec_ctx_t *ctx,
                          const nodus_rt_v2_reader_t *reader,
                          rtevm_call_t *k, rtevm_priv_t *p) {
    if (!env || !ctx || !reader || !reader->read || !reader->declare_gas ||
        leg_index >= env->leg_count || !ctx->auth || !ctx->chain_id ||
        !ctx->intent_id)
        return -2;
    /* authorization (design §2): auth_kind 1, exactly one signer; the
     * EVM sender is that signer's fingerprint [0..32] */
    if (env->leg[leg_index].auth_kind != NODUS_RT_AUTHKIND_DSA87_MULTI_V1 ||
        ctx->auth->n_signers != 1)
        return -1;
    /* design §2: exactly [CORE EVMFUND] + [EVM op], the role matching —
     * the SAME rule the CORE hook applies from its side */
    if (leg_index != 1 || nodus_rt_evm_pair_check(env) != 0) return -1;
    return rtevm_decode(env->leg[leg_index].runtime_op,
                        env->buf + env->call_off[leg_index],
                        env->leg[leg_index].call_len, k, p);
}

/* ── the prevalidate_evm hook (design §8 recheck: NO VM — CheckTx's whole
 *    EVM admission, NEW entry and recheck, since red-team 1 F1) ───────── */

int nodus_rt_evm_prevalidate(const nodus_domain_runtime_t *rt,
                             const dna_env_view_t *env, uint16_t leg_index,
                             const nodus_rt_exec_ctx_t *ctx,
                             const nodus_rt_v2_reader_t *reader,
                             nodus_rt_v2_keys_t *keys) {
    (void)rt;
    if (keys) memset(keys, 0, sizeof(*keys));
    rtevm_priv_t *p = calloc(1, sizeof(*p));
    if (!p) return -2;
    rtevm_be_t be;
    memset(&be, 0, sizeof(be));
    be.rd = reader;
    be.rr = calloc(1, sizeof(*be.rr));
    rtevm_call_t k;
    int rc = be.rr ? rtevm_prologue(env, leg_index, ctx, reader, &k, p) : -2;
    if (rc == 0) {
        if (k.op == NODUS_RT_EVM_CALL || k.op == NODUS_RT_EVM_CREATE) {
            rtevm_vm_t *vm = calloc(1, sizeof(*vm));
            rc = vm ? rtevm_vm_pre(ctx, reader, &k, p, &be, vm) : -2;
            if (vm && vm->st) evm_state_free(vm->st);
            free(vm);
        } else {
            rtevm_bridge_t b;
            rc = rtevm_bridge_pre(ctx, &k, &be, &b);
        }
    }
    /* the conflict keys through their ONE derivation (runtime.h) */
    if (rc == 0 && keys &&
        nodus_rt_evm_conflict_keys(env, leg_index, ctx->auth, keys) != 0)
        rc = -2;                        /* the prologue decoded the head */
    free(be.rr);
    nodus_rt_v2_out_t tmp;
    memset(&tmp, 0, sizeof(tmp));
    tmp.priv = p;
    rtevm_release(&tmp);
    return rc;
}

/* ── the exec_evm hook ─────────────────────────────────────────────── */

int nodus_rt_evm_exec(const nodus_domain_runtime_t *rt,
                      const dna_env_view_t *env, uint16_t leg_index,
                      const nodus_rt_exec_ctx_t *ctx,
                      const nodus_rt_v2_reader_t *reader,
                      nodus_rt_v2_out_t *out) {
    (void)rt;
    if (!out) return -2;
    memset(out, 0, sizeof(*out));

    rtevm_priv_t *p = calloc(1, sizeof(*p));
    if (!p) return -2;
    out->priv = p;
    out->release = rtevm_release;

    rtevm_be_t be;
    memset(&be, 0, sizeof(be));
    be.rd = reader;
    be.rr = calloc(1, sizeof(*be.rr));
    if (!be.rr) return -2;

    /* the prologue and, inside each path, the pre-validation are the
     * functions the prevalidate_evm hook (CheckTx's VM-less admission)
     * runs — ONE shared pre-validation (design §8) */
    rtevm_call_t k;
    int rc = rtevm_prologue(env, leg_index, ctx, reader, &k, p);
    if (rc == 0) {
        if (k.op == NODUS_RT_EVM_CALL || k.op == NODUS_RT_EVM_CREATE)
            rc = rtevm_exec_vm(ctx, reader, &k, p, &be, out);
        else
            rc = rtevm_bridge(ctx, &k, p, &be, out);
    }
    free(be.rr);
    if (rc != 0) return rc;                    /* the engine releases out */

    out->effects = p->eff;
    out->n_effects = out->success ? p->n_eff : 0;
    if (out->failable) {
        out->fail_effects = p->fail_eff;
        out->n_fail_effects = 1;
        out->fail_receipt = p->fail_rcpt.p;
        out->fail_receipt_len = p->fail_rcpt.len;
    }
    if (out->success) {
        out->receipt = p->rcpt.p;
        out->receipt_len = p->rcpt.len;
    } else {
        /* the failure outcome is the only receipt (engine contract: the
         * success receipt slot is never empty) */
        out->receipt = p->fail_rcpt.p;
        out->receipt_len = p->fail_rcpt.len;
    }
    return 0;
}

/* ══ the §18 RPC simulation (evm_call / evm_estimate) ════════════════
 *
 * Contract: nodus_witness_rt_evm.h nodus_rt_evm_simulate. The SAME
 * execution function the chain runs (rtevm_exec_vm: rtevm_vm_pre, the
 * engine, the change-set visit and build_success) over a FRESH overlay and
 * a NON-METERING reader of the COMMITTED tables: every read is
 * nodus_witness_v2_read_one (the adapter's committed-row read, the one the
 * engine's reader serves) or the engine's BLOCKHASH rule; nothing is
 * written — the effect stream the run builds is discarded with the out.
 * The reader keeps the engine reader's per-leg caps (logical reads, read
 * bytes) so a BUDGET outcome looks the same; it has no unit budget (the
 * simulation is asked for the units). No clock: the block time is the
 * caller's (the committed tip block's header). */

typedef struct {
    uint32_t op;
    uint16_t key_len;
    uint8_t  key[DNA_EFFECT_MAX_KEY_LEN];
    uint8_t  present;
    uint32_t value_len;
    uint8_t *value;
} rtevm_sim_ent_t;

typedef struct {
    struct nodus_witness          *w;
    const nodus_domain_runtime_t  *rt;
    uint64_t                       global_height;
    uint64_t                       max_reads, n_reads, read_bytes;
    int                            gas_declared;
    rtevm_sim_ent_t              **ents;          /* sorted (op, key)    */
    size_t                         n_ents, cap_ents;
} rtevm_sim_rd_t;

static int sim_cmp(uint32_t op_a, const uint8_t *ka, uint16_t la,
                   uint32_t op_b, const uint8_t *kb, uint16_t lb) {
    if (op_a != op_b) return op_a < op_b ? -1 : 1;
    uint16_t mn = la < lb ? la : lb;
    int c = mn ? memcmp(ka, kb, mn) : 0;
    if (c != 0) return c;
    if (la != lb) return la < lb ? -1 : 1;
    return 0;
}

static void sim_rd_free(rtevm_sim_rd_t *c) {
    for (size_t i = 0; i < c->n_ents; i++) {
        free(c->ents[i]->value);
        free(c->ents[i]);
    }
    free(c->ents);
    c->ents = NULL;
    c->n_ents = c->cap_ents = 0;
}

/* nodus_rt_v2_reader_t.read over committed state, one logical read per
 * (op, key) — the engine reader's counting and caps, no meter. */
static int sim_read(void *ctxp, uint32_t op, const uint8_t *key,
                    uint16_t key_len, nodus_rt_read_res_t *res) {
    rtevm_sim_rd_t *c = (rtevm_sim_rd_t *)ctxp;
    if (!c || !key || !res || key_len < 1 ||
        key_len > DNA_EFFECT_MAX_KEY_LEN)
        return -2;
    memset(res, 0, sizeof(*res));
    size_t lo = 0, hi = c->n_ents;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        const rtevm_sim_ent_t *e = c->ents[mid];
        int r = sim_cmp(e->op, e->key, e->key_len, op, key, key_len);
        if (r == 0) {                       /* repeat: free (design §3 I2) */
            res->present = e->present;
            res->value_len = e->value_len;
            if (e->value_len) memcpy(res->value, e->value, e->value_len);
            return 0;
        }
        if (r < 0) lo = mid + 1; else hi = mid;
    }
    if (c->n_reads + 1 > c->max_reads) return NODUS_RT_V2_READ_BUDGET;
    c->n_reads++;
    if (op == NODUS_RT_V2_OP_BLOCKHASH) {
        if (key_len != 8) return -2;
        if (nodus_witness_v2_evm_blockhash((nodus_witness_t *)c->w,
                                           c->global_height,
                                           get_u64be(key), res) != 0)
            return -2;
    } else {
        nodus_rt_read_req_t req;
        memset(&req, 0, sizeof(req));
        req.op_id = op;
        req.key_len = key_len;
        memcpy(req.key, key, key_len);
        if (nodus_witness_v2_read_one(c->w, c->rt, &req, res) !=
            NODUS_ADAPTER_OK)
            return -2;
    }
    c->read_bytes += res->value_len;
    if (c->read_bytes > NODUS_RT_EVM_MAX_READ_BYTES)
        return NODUS_RT_V2_READ_BUDGET;
    if (c->n_ents == c->cap_ents) {
        size_t nc = c->cap_ents ? c->cap_ents * 2 : 64;
        rtevm_sim_ent_t **g = realloc(c->ents, nc * sizeof(*g));
        if (!g) return -2;
        c->ents = g;
        c->cap_ents = nc;
    }
    rtevm_sim_ent_t *e = calloc(1, sizeof(*e));
    if (!e) return -2;
    e->op = op;
    e->key_len = key_len;
    memcpy(e->key, key, key_len);
    e->present = res->present;
    e->value_len = res->value_len;
    if (res->value_len) {
        e->value = malloc(res->value_len);
        if (!e->value) { free(e); return -2; }
        memcpy(e->value, res->value, res->value_len);
    }
    memmove(&c->ents[lo + 1], &c->ents[lo],
            (c->n_ents - lo) * sizeof(*c->ents));
    c->ents[lo] = e;
    c->n_ents++;
    return 0;
}

/* nodus_rt_v2_reader_t.declare_gas: the per-tx cap and the read cap — the
 * engine reader's rules without the units inequality (the simulation is
 * what tells the caller the units). */
static int sim_declare_gas(void *ctxp, uint64_t gas_limit,
                           uint64_t n_access_keys) {
    rtevm_sim_rd_t *c = (rtevm_sim_rd_t *)ctxp;
    if (!c || c->gas_declared) return -2;
    if (gas_limit > NODUS_RT_EVM_TX_GAS_CAP) return -1;
    c->max_reads = NODUS_RT_EVM_READS_BASE + 2u * n_access_keys;
    c->gas_declared = 1;
    return 0;
}

void nodus_rt_evm_sim_res_free(nodus_rt_evm_sim_res_t *res) {
    if (!res) return;
    free(res->output);
    memset(res, 0, sizeof(*res));
}

int nodus_rt_evm_simulate(const nodus_domain_runtime_t *rt,
                          struct nodus_witness *w,
                          const nodus_rt_evm_sim_req_t *req,
                          nodus_rt_evm_sim_res_t *res) {
    if (!res) return -2;
    memset(res, 0, sizeof(*res));
    if (!rt || !w || !req || !req->from || !req->chain_id ||
        (req->data_len && !req->data))
        return -2;
    if (req->gas_limit == 0 || req->gas_limit > NODUS_RT_EVM_TX_GAS_CAP)
        return -1;
    if (!req->to && req->data_len > EVM_MAX_INITCODE_SIZE) return -1;

    rtevm_sim_rd_t sc;
    memset(&sc, 0, sizeof(sc));
    sc.w = w;
    sc.rt = rt;
    sc.global_height = req->global_height;
    sc.max_reads = NODUS_RT_EVM_READS_BASE;   /* until declare_gas       */
    nodus_rt_v2_reader_t rdr = { &sc, sim_read, sim_declare_gas };

    /* the sender: SHA3-512(pk)[0..32] is the chain's rule; the request
     * names the 32-byte address itself — a verdict of one signer whose
     * fingerprint starts with it */
    nodus_rt_auth_verdict_t *av = calloc(1, sizeof(*av));
    rtevm_priv_t *p = calloc(1, sizeof(*p));
    rtevm_be_t be;
    memset(&be, 0, sizeof(be));
    be.rd = &rdr;
    be.rr = calloc(1, sizeof(*be.rr));
    nodus_rt_v2_out_t out;
    memset(&out, 0, sizeof(out));
    int ret = -2;
    if (!av || !p || !be.rr) goto done;
    av->n_signers = 1;
    memcpy(av->signer_fp[0], req->from, 32);

    /* the nonce is the committed one (a simulation is never refused for
     * its nonce) — read through the same reader, so it is counted once */
    rtevm_acct_t sender;
    int rc = read_acct(&be, req->from, &sender);
    if (rc == EVM_BUDGET) { ret = -1; goto done; }
    if (rc != 0) goto done;

    rtevm_call_t k;
    memset(&k, 0, sizeof(k));
    k.op = req->to ? NODUS_RT_EVM_CALL : NODUS_RT_EVM_CREATE;
    if (req->to) memcpy(k.to, req->to, 32);
    if (req->value) memcpy(k.value, req->value, 32);
    k.gas_limit = req->gas_limit;
    k.nonce = sender.exists ? sender.nonce : 0;
    k.data = req->data_len ? req->data : NULL;
    k.data_len = req->data_len;

    static const uint8_t zero64[64] = { 0 };
    nodus_rt_exec_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.chain_id            = req->chain_id;
    ctx.global_height       = req->global_height;
    ctx.intent_id           = zero64;      /* ticket ids only: not shown  */
    ctx.auth                = av;
    ctx.block_time_s        = req->block_time_s;
    ctx.evm_block_gas_limit = req->evm_block_gas_limit;

    out.priv = p;
    out.release = rtevm_release;
    rc = rtevm_exec_vm(&ctx, &rdr, &k, p, &be, &out);
    res->reads = sc.n_reads;
    if (rc == -1) {                       /* refused before execution    */
        res->executed = 0;
        ret = 0;
        goto done;
    }
    if (rc != 0) goto done;
    res->executed = 1;
    res->success = out.success ? 1 : 0;
    res->budget = (p->res_set && p->res.status == EVM_EXEC_BUDGET) ? 1 : 0;
    /* the engine's own gas on success; the chain's failure figure
     * (gas_limit, design §4) otherwise — exactly what a receipt says */
    res->gas_used = out.gas_used;
    res->engine_gas_used = p->res_set ? p->res.gas_used : 0;
    res->engine_work_gas = p->res_set ? p->res.gas_used_pre_refund : 0;
    if (p->res_set && p->res.output_len) {
        res->output = malloc(p->res.output_len);
        if (!res->output) goto done;
        memcpy(res->output, p->res.output, p->res.output_len);
        res->output_len = p->res.output_len;
    }
    if (res->success && k.op == NODUS_RT_EVM_CREATE) {
        memcpy(res->created, p->res.created.b, 32);
        res->has_created = 1;
    }
    ret = 0;
done:
    if (ret != 0) nodus_rt_evm_sim_res_free(res);
    if (out.release) {
        out.release(&out);           /* frees p                          */
    } else if (p) {
        nodus_rt_v2_out_t tmp;
        memset(&tmp, 0, sizeof(tmp));
        tmp.priv = p;
        rtevm_release(&tmp);
    }
    free(be.rr);
    free(av);
    sim_rd_free(&sc);
    return ret;
}

/* ══ storage: the adapter, the tries, the root (design §4, §6) ════════ */

static sqlite3 *dbof(struct nodus_witness *w) {
    return ((nodus_witness_t *)w)->db;
}

/* ── META row ──────────────────────────────────────────────────────── */

typedef struct {
    rtevm_meta_t m;
    uint8_t      acct_root[64];
    uint8_t      tkt_root[64];
} rtevm_metarow_t;

/** @return 0 found, 1 absent, -1 fault (incl. a missing table). */
static int meta_load(sqlite3 *db, rtevm_metarow_t *r) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT wei_live, wei_tickets, wei_lost, account_trie_root, "
            "tickets_root FROM evm_meta WHERE id = 1",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    int rc = sqlite3_step(st);
    int ret = -1;
    if (rc == SQLITE_DONE) {
        ret = 1;
    } else if (rc == SQLITE_ROW) {
        if (sqlite3_column_bytes(st, 0) == 32 &&
            sqlite3_column_bytes(st, 1) == 32 &&
            sqlite3_column_bytes(st, 2) == 32 &&
            sqlite3_column_bytes(st, 3) == 64 &&
            sqlite3_column_bytes(st, 4) == 64) {
            evm_u256_from_be(&r->m.live, sqlite3_column_blob(st, 0));
            evm_u256_from_be(&r->m.tickets, sqlite3_column_blob(st, 1));
            evm_u256_from_be(&r->m.lost, sqlite3_column_blob(st, 2));
            memcpy(r->acct_root, sqlite3_column_blob(st, 3), 64);
            memcpy(r->tkt_root, sqlite3_column_blob(st, 4), 64);
            ret = 0;
        }
    }
    sqlite3_finalize(st);
    return ret;
}

/** Insert (`insert` 1) or update the one META row. @return 0 / -1. */
static int meta_store(sqlite3 *db, const rtevm_metarow_t *r, int insert) {
    sqlite3_stmt *st = NULL;
    const char *sql = insert
        ? "INSERT INTO evm_meta (id, wei_live, wei_tickets, wei_lost, "
          "account_trie_root, tickets_root) "
          "VALUES (1, ?1, ?2, ?3, ?4, ?5)"
        : "UPDATE evm_meta SET wei_live = ?1, wei_tickets = ?2, "
          "wei_lost = ?3, account_trie_root = ?4, tickets_root = ?5 "
          "WHERE id = 1";
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    uint8_t a[32], b[32], c[32];
    evm_u256_to_be(a, &r->m.live);
    evm_u256_to_be(b, &r->m.tickets);
    evm_u256_to_be(c, &r->m.lost);
    sqlite3_bind_blob(st, 1, a, 32, SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 2, b, 32, SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 3, c, 32, SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 4, r->acct_root, 64, SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 5, r->tkt_root, 64, SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) return -1;
    if (!insert && sqlite3_changes(db) != 1) return -1;
    return 0;
}

/* ── the trie node store (evm_trie.h STORE CONTRACT) ─────────────────── */

static int ts_get(void *ctx, const uint8_t digest[64], uint8_t **rlp,
                  size_t *len) {
    sqlite3 *db = (sqlite3 *)ctx;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT rlp FROM evm_trie_nodes WHERE digest = ?1",
            -1, &st, NULL) != SQLITE_OK)
        return -2;
    sqlite3_bind_blob(st, 1, digest, 64, SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);
    int ret = -2;
    if (rc == SQLITE_DONE) {
        ret = 1;
    } else if (rc == SQLITE_ROW) {
        int n = sqlite3_column_bytes(st, 0);
        const void *b = sqlite3_column_blob(st, 0);
        if (n > 0 && b) {
            uint8_t *c = malloc((size_t)n);
            if (c) {
                memcpy(c, b, (size_t)n);
                *rlp = c;
                *len = (size_t)n;
                ret = 0;
            }
        }
    }
    sqlite3_finalize(st);
    return ret;
}

/** INSERT if absent; an existing digest must hold the SAME bytes — a
 *  different node under one digest is this node's corruption (FAULT). */
static int ts_put(void *ctx, const uint8_t digest[64], const uint8_t *rlp,
                  size_t len) {
    sqlite3 *db = (sqlite3 *)ctx;
    sqlite3_stmt *st = NULL;
    if (len == 0 || len > INT32_MAX) return -2;
    if (sqlite3_prepare_v2(db,
            "SELECT rlp FROM evm_trie_nodes WHERE digest = ?1",
            -1, &st, NULL) != SQLITE_OK)
        return -2;
    sqlite3_bind_blob(st, 1, digest, 64, SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) {
        int same = (size_t)sqlite3_column_bytes(st, 0) == len &&
                   memcmp(sqlite3_column_blob(st, 0), rlp, len) == 0;
        sqlite3_finalize(st);
        if (!same) {
            QGP_LOG_ERROR(LOG_TAG, "trie node store: one digest, two bodies");
            return -2;
        }
        return 0;
    }
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) return -2;
    if (sqlite3_prepare_v2(db,
            "INSERT INTO evm_trie_nodes (digest, rlp) VALUES (?1, ?2)",
            -1, &st, NULL) != SQLITE_OK)
        return -2;
    sqlite3_bind_blob(st, 1, digest, 64, SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 2, rlp, (int)len, SQLITE_TRANSIENT);
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -2;
}

/** RLP of a big-endian unsigned integer: minimal bytes, zero = b"". */
static int rlp_put_uint(evm_trie_rlp_buf *b, const uint8_t *be, size_t n) {
    size_t i = 0;
    while (i < n && be[i] == 0) i++;
    return evm_trie_rlp_put_bytes(b, be + i, n - i) == 0 ? 0 : -1;
}

static int rlp_put_u64(evm_trie_rlp_buf *b, uint64_t v) {
    uint8_t t[8];
    put_u64be(t, v);
    return rlp_put_uint(b, t, 8);
}

/* ── the evm_accounts row ──────────────────────────────────────────── */

typedef struct {
    rtevm_acct_t a;
    uint8_t      storage_root[64];
} rtevm_acctrow_t;

/** @return 0 found, 1 absent, -1 fault. */
static int acct_row_load(sqlite3 *db, const uint8_t addr[32],
                         rtevm_acctrow_t *r) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT nonce, balance, code_hash, code_size, code_digest, "
            "storage_count, storage_root FROM evm_accounts WHERE addr = ?1",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_blob(st, 1, addr, 32, SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);
    int ret = -1;
    if (rc == SQLITE_DONE) {
        ret = 1;
    } else if (rc == SQLITE_ROW &&
               sqlite3_column_bytes(st, 1) == 32 &&
               sqlite3_column_bytes(st, 2) == 32 &&
               sqlite3_column_bytes(st, 4) == 64 &&
               sqlite3_column_bytes(st, 6) == 64) {
        memset(r, 0, sizeof(*r));
        r->a.exists = 1;
        r->a.nonce = (uint64_t)sqlite3_column_int64(st, 0);
        memcpy(r->a.balance, sqlite3_column_blob(st, 1), 32);
        memcpy(r->a.code_hash, sqlite3_column_blob(st, 2), 32);
        sqlite3_int64 cs = sqlite3_column_int64(st, 3);
        memcpy(r->a.code_digest, sqlite3_column_blob(st, 4), 64);
        r->a.storage_count = (uint64_t)sqlite3_column_int64(st, 5);
        memcpy(r->storage_root, sqlite3_column_blob(st, 6), 64);
        if (cs >= 0 && cs <= (sqlite3_int64)EVM_MAX_CODE_SIZE) {
            r->a.code_size = (uint32_t)cs;
            ret = 0;
        }
    }
    sqlite3_finalize(st);
    return ret;
}

static int acct_row_store(sqlite3 *db, const uint8_t addr[32],
                          const rtevm_acctrow_t *r) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO evm_accounts (addr, nonce, balance, "
            "code_hash, code_size, code_digest, storage_count, storage_root)"
            " VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_blob(st, 1, addr, 32, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)r->a.nonce);
    sqlite3_bind_blob(st, 3, r->a.balance, 32, SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 4, r->a.code_hash, 32, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 5, (sqlite3_int64)r->a.code_size);
    sqlite3_bind_blob(st, 6, r->a.code_digest, 64, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 7, (sqlite3_int64)r->a.storage_count);
    sqlite3_bind_blob(st, 8, r->storage_root, 64, SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

/**
 * The account-trie leaf of a row (design §6 substitution 5):
 * RLP([nonce, balance_wei, storage_root(64), code_hash_keccak(32),
 * code_size, code_digest_sha3(64), storage_count]). @return 0 / -1.
 */
static int acct_leaf_build(const rtevm_acctrow_t *r, evm_trie_rlp_buf *b) {
    uint8_t cs[4];
    put_u32be(cs, r->a.code_size);
    return (rlp_put_u64(b, r->a.nonce) == 0 &&
            rlp_put_uint(b, r->a.balance, 32) == 0 &&
            evm_trie_rlp_put_bytes(b, r->storage_root, 64) == 0 &&
            evm_trie_rlp_put_bytes(b, r->a.code_hash, 32) == 0 &&
            rlp_put_uint(b, cs, 4) == 0 &&
            evm_trie_rlp_put_bytes(b, r->a.code_digest, 64) == 0 &&
            rlp_put_u64(b, r->a.storage_count) == 0 &&
            evm_trie_rlp_wrap_list(b, 0) == 0) ? 0 : -1;
}

/* ── the per-leg trie batch (red-team-1 F6, Kurultay 2026-10-05) ───────
 *
 * Every trie an adapter mutation touches — the storage trie of each
 * touched account, the account trie, the tickets trie — is opened ONCE
 * at its committed root, takes every keyed set/delete of the batch in
 * memory (evm_trie.h: set/delete touch only in-memory nodes), and is
 * committed ONCE when the batch is flushed. Until then no trie node is
 * written and no root column moves: the evm_accounts.storage_root and
 * evm_meta.account_trie_root / tickets_root columns keep the roots the
 * batch opened at, which is exactly what makes a lazily opened handle
 * start from the right root.
 *
 * ROOT IDENTITY (design I4): a committed trie root depends only on the
 * final key set. Each storage trie ends with the same slots as under
 * per-effect commits; each account leaf is re-derived at flush from the
 * account's FINAL row, after its final storage_root is written — the row
 * today's last per-effect leaf sync of that address read. So the roots
 * equal the per-effect roots byte for byte (test_v2_evm.c section 12
 * applies one effect list both ways and checks against the full-rebuild
 * oracle). Fewer nodes are written: the intermediate roots never are.
 *
 * SCOPE: a batch is opened by nodus_rt_evm_leg_begin (the engine, inside
 * the EVM leg's inner savepoint) and ends with nodus_rt_evm_leg_flush
 * (before that savepoint is released) or nodus_rt_evm_leg_discard (every
 * other exit — the savepoint rollback then undoes the rows; the batch
 * held no node and no root in the database, so nothing else exists to
 * undo). A mutation with no open batch for its witness runs in a batch of
 * its own, flushed at once: the per-effect commit (the failure path's one
 * nonce effect, direct adapter calls).
 *
 * DETERMINISM: no hash map. The open storage tries and the addresses
 * whose leaf must be re-derived are arrays kept in ascending address
 * order (binary search + insert); the flush walks them in that order.
 * Node writes are content-addressed and idempotent (ts_put).
 *
 * THREADING: the open batch is per THREAD (one witness loop drives one
 * leg at a time) and names its witness; a mutation of another witness on
 * the same thread does not see it. */

typedef struct {
    uint8_t     addr[32];          /* first member: the search key        */
    evm_trie_t *t;                 /* opened at the row's storage_root    */
} rtevm_stor_t;

typedef struct {
    struct nodus_witness *w;
    sqlite3      *db;
    evm_trie_t   *acct;            /* opened at account_trie_root, lazily */
    evm_trie_t   *tkt;             /* opened at tickets_root, lazily      */
    rtevm_stor_t *stor;            /* ascending addr, unique              */
    size_t        n_stor, cap_stor;
    uint8_t     (*dirty)[32];      /* leaves to re-derive; ascending      */
    size_t        n_dirty, cap_dirty;
    int           broken;          /* a mutation failed: flush refuses    */
} rtevm_batch_t;

static _Thread_local rtevm_batch_t *t_batch = NULL;

static rtevm_batch_t *batch_new(struct nodus_witness *w) {
    rtevm_batch_t *b = calloc(1, sizeof(*b));
    if (!b) return NULL;
    b->w = w;
    b->db = dbof(w);
    return b;
}

/** Close every handle WITHOUT committing; free the batch. */
static void batch_free(rtevm_batch_t *b) {
    if (!b) return;
    evm_trie_close(b->acct);
    evm_trie_close(b->tkt);
    for (size_t i = 0; i < b->n_stor; i++) evm_trie_close(b->stor[i].t);
    free(b->stor);
    free(b->dirty);
    free(b);
}

/** The open batch of `w` on this thread, or NULL. */
static rtevm_batch_t *batch_of(struct nodus_witness *w) {
    return (t_batch && t_batch->w == w) ? t_batch : NULL;
}

/** Binary search over `n` records of `stride` bytes whose first 32 bytes
 *  are an address: the index of `addr` (*found 1) or its insertion point
 *  (*found 0). */
static size_t addr_pos(const uint8_t *base, size_t stride, size_t n,
                       const uint8_t addr[32], int *found) {
    size_t lo = 0, hi = n;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int c = memcmp(base + mid * stride, addr, 32);
        if (c == 0) {
            *found = 1;
            return mid;
        }
        if (c < 0) lo = mid + 1;
        else hi = mid;
    }
    *found = 0;
    return lo;
}

/** Mark `addr`'s account leaf for re-derivation at flush. @return 0/-1. */
static int batch_mark(rtevm_batch_t *b, const uint8_t addr[32]) {
    int f = 0;
    size_t i = addr_pos((const uint8_t *)b->dirty, 32, b->n_dirty, addr, &f);
    if (f) return 0;
    if (b->n_dirty == b->cap_dirty) {
        size_t nc = b->cap_dirty ? b->cap_dirty * 2 : 16;
        uint8_t (*g)[32] = realloc(b->dirty, nc * 32);
        if (!g) return -1;
        b->dirty = g;
        b->cap_dirty = nc;
    }
    memmove(b->dirty + i + 1, b->dirty + i, (b->n_dirty - i) * 32);
    memcpy(b->dirty[i], addr, 32);
    b->n_dirty++;
    return 0;
}

/** Is a storage trie of `addr` open in the batch? */
static int batch_has_stor(const rtevm_batch_t *b, const uint8_t addr[32]) {
    int f = 0;
    (void)addr_pos((const uint8_t *)b->stor, sizeof(rtevm_stor_t), b->n_stor,
                   addr, &f);
    return f;
}

/** The storage trie of `addr`: the open one, or opened now at `root` (the
 *  row's committed storage_root). @return the handle or NULL (fault). */
static evm_trie_t *batch_stor(rtevm_batch_t *b, const uint8_t addr[32],
                              const uint8_t root[64]) {
    int f = 0;
    size_t i = addr_pos((const uint8_t *)b->stor, sizeof(rtevm_stor_t),
                        b->n_stor, addr, &f);
    if (f) return b->stor[i].t;
    if (b->n_stor == b->cap_stor) {
        size_t nc = b->cap_stor ? b->cap_stor * 2 : 8;
        rtevm_stor_t *g = realloc(b->stor, nc * sizeof(*g));
        if (!g) return NULL;
        b->stor = g;
        b->cap_stor = nc;
    }
    evm_trie_store_t s = { b->db, ts_get, ts_put };
    evm_trie_t *t = NULL;
    if (evm_trie_open(&s, root, &t) != 0) return NULL;
    memmove(b->stor + i + 1, b->stor + i, (b->n_stor - i) * sizeof(*b->stor));
    memcpy(b->stor[i].addr, addr, 32);
    b->stor[i].t = t;
    b->n_stor++;
    return t;
}

/** The account (`tickets` 0) or tickets (`tickets` 1) trie, opened at the
 *  META row's committed root on first use. @return handle or NULL. */
static evm_trie_t *batch_top(rtevm_batch_t *b, int tickets) {
    evm_trie_t **slot = tickets ? &b->tkt : &b->acct;
    if (*slot) return *slot;
    rtevm_metarow_t mr;
    if (meta_load(b->db, &mr) != 0) return NULL;
    evm_trie_store_t s = { b->db, ts_get, ts_put };
    if (evm_trie_open(&s, tickets ? mr.tkt_root : mr.acct_root, slot) != 0) {
        *slot = NULL;
        return NULL;
    }
    return *slot;
}

/**
 * Commit the batch inside the caller's transaction: (1) each storage
 * trie, ascending address, its root written to the account row (an
 * account whose row is gone has no storage root to carry — its trie is
 * dropped uncommitted); (2) each marked leaf, ascending address,
 * re-derived from the FINAL row (no row = no leaf); (3) the account and
 * tickets tries, their roots into the META row (loaded fresh: a META SET
 * of the batch is in it). Does not free the batch. @return 0 / -1.
 */
static int batch_flush(rtevm_batch_t *b) {
    if (b->broken) return -1;
    for (size_t i = 0; i < b->n_stor; i++) {
        rtevm_acctrow_t r;
        int lrc = acct_row_load(b->db, b->stor[i].addr, &r);
        if (lrc < 0) return -1;
        if (lrc == 1) continue;
        if (evm_trie_commit(b->stor[i].t, r.storage_root) != 0) return -1;
        if (acct_row_store(b->db, b->stor[i].addr, &r) != 0) return -1;
    }
    if (b->n_dirty) {
        evm_trie_t *at = batch_top(b, 0);
        if (!at) return -1;
        for (size_t i = 0; i < b->n_dirty; i++) {
            rtevm_acctrow_t r;
            int lrc = acct_row_load(b->db, b->dirty[i], &r);
            if (lrc < 0) return -1;
            int rc;
            if (lrc == 1) {
                rc = evm_trie_delete(at, b->dirty[i], 32);
            } else {
                evm_trie_rlp_buf lb;
                memset(&lb, 0, sizeof(lb));
                rc = acct_leaf_build(&r, &lb);
                if (rc == 0) rc = evm_trie_set(at, b->dirty[i], 32, lb.p,
                                               lb.len);
                evm_trie_rlp_buf_free(&lb);
            }
            if (rc != 0) return -1;
        }
    }
    if (!b->acct && !b->tkt) return 0;
    rtevm_metarow_t mr;
    if (meta_load(b->db, &mr) != 0) return -1;
    if (b->acct && evm_trie_commit(b->acct, mr.acct_root) != 0) return -1;
    if (b->tkt && evm_trie_commit(b->tkt, mr.tkt_root) != 0) return -1;
    return meta_store(b->db, &mr, 0);
}

int nodus_rt_evm_leg_begin(struct nodus_witness *w) {
    if (!w) return -1;
    if (t_batch) {
        /* every exit of a leg ends its batch: a leftover is this node's
         * bug — dropped (it holds nothing in the database), and refused */
        QGP_LOG_ERROR(LOG_TAG, "leg batch begin: a batch is still open");
        batch_free(t_batch);
        t_batch = NULL;
        return -1;
    }
    t_batch = batch_new(w);
    return t_batch ? 0 : -1;
}

int nodus_rt_evm_leg_flush(struct nodus_witness *w) {
    rtevm_batch_t *b = batch_of(w);
    if (!w || !b) return -1;
    t_batch = NULL;
    int rc = batch_flush(b);
    batch_free(b);
    return rc;
}

void nodus_rt_evm_leg_discard(struct nodus_witness *w) {
    rtevm_batch_t *b = batch_of(w);
    if (!w || !b) return;
    t_batch = NULL;
    batch_free(b);
}

int nodus_rt_evm_leg_open(struct nodus_witness *w) {
    return w && batch_of(w) != NULL;
}

/** A code digest's reference: +1 (creating the row at 1). @return 0/-1. */
static int code_ref_add(sqlite3 *db, const uint8_t digest[64],
                        uint32_t code_size) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT refs, code_size FROM evm_code_refs WHERE digest = ?1",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_blob(st, 1, digest, 64, SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);
    sqlite3_int64 refs = 0, size = 0;
    if (rc == SQLITE_ROW) {
        refs = sqlite3_column_int64(st, 0);
        size = sqlite3_column_int64(st, 1);
    }
    sqlite3_finalize(st);
    if (rc != SQLITE_ROW && rc != SQLITE_DONE) return -1;
    if (rc == SQLITE_ROW && (refs < 1 || size != (sqlite3_int64)code_size))
        return -1;
    if (sqlite3_prepare_v2(db,
            rc == SQLITE_ROW
                ? "UPDATE evm_code_refs SET refs = refs + 1 WHERE digest = ?1"
                : "INSERT INTO evm_code_refs (digest, refs, code_size) "
                  "VALUES (?1, 1, ?2)",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_blob(st, 1, digest, 64, SQLITE_TRANSIENT);
    if (rc != SQLITE_ROW) sqlite3_bind_int64(st, 2, (sqlite3_int64)code_size);
    int rc2 = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc2 == SQLITE_DONE ? 0 : -1;
}

/* ── adapter ops ─────────────────────────────────────────────────────── */

#define K_C NODUS_ADAPTER_KIND_BIT(DNA_EFFECT_CREATE)
#define K_S NODUS_ADAPTER_KIND_BIT(DNA_EFFECT_SET)
#define K_D NODUS_ADAPTER_KIND_BIT(DNA_EFFECT_DELETE)
#define P_A NODUS_ADAPTER_PRECOND_BIT(DNA_EFFECT_PRE_ABSENT)
#define P_E NODUS_ADAPTER_PRECOND_BIT(DNA_EFFECT_PRE_EXISTS)

static const nodus_adapter_op_t EVM_OPS[6] = {
    { NODUS_RT_EVM_OP_ACCT,   (uint8_t)(K_C | K_S | K_D), (uint8_t)(P_A | P_E),
      32, 32, 0, NODUS_RT_EVM_ACCT_LEN },
    { NODUS_RT_EVM_OP_SLOT,   (uint8_t)(K_C | K_S | K_D), (uint8_t)(P_A | P_E),
      64, 64, 0, 32 },
    { NODUS_RT_EVM_OP_CODE,   K_C, P_A, 65, 65, 1, NODUS_RT_EVM_CODE_CHUNK },
    { NODUS_RT_EVM_OP_TICKET, (uint8_t)(K_C | K_D), (uint8_t)(P_A | P_E),
      64, 64, 0, NODUS_RT_EVM_TICKET_LEN },
    { NODUS_RT_EVM_OP_META,   K_S, P_E, 1, 1, NODUS_RT_EVM_META_LEN,
      NODUS_RT_EVM_META_LEN },
    /* READ-ONLY (allowed_kinds 0): an effect naming it dies as ERR_KIND */
    { NODUS_RT_EVM_OP_HAS_STORAGE, 0, 0, 32, 32, 0, 0 },
};

/** Does the row behind (op, key) exist? @return 1 / 0 / -1 fault. */
static int row_exists(sqlite3 *db, uint32_t op, const uint8_t *key,
                      uint16_t key_len) {
    const char *sql = NULL;
    switch (op) {
        case NODUS_RT_EVM_OP_ACCT:
            sql = "SELECT 1 FROM evm_accounts WHERE addr = ?1"; break;
        case NODUS_RT_EVM_OP_SLOT:
            sql = "SELECT 1 FROM evm_slots WHERE addr = ?1 AND slot = ?2";
            break;
        case NODUS_RT_EVM_OP_CODE:
            sql = "SELECT 1 FROM evm_code WHERE digest = ?1 AND chunk = ?2";
            break;
        case NODUS_RT_EVM_OP_TICKET:
            sql = "SELECT 1 FROM evm_tickets WHERE ticket_id = ?1"; break;
        case NODUS_RT_EVM_OP_META:
            if (key_len != 1 || key[0] != META_KEY[0]) return 0;
            sql = "SELECT 1 FROM evm_meta WHERE id = 1"; break;
        default:
            return -1;
    }
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    if (op == NODUS_RT_EVM_OP_SLOT) {
        sqlite3_bind_blob(st, 1, key, 32, SQLITE_TRANSIENT);
        sqlite3_bind_blob(st, 2, key + 32, 32, SQLITE_TRANSIENT);
    } else if (op == NODUS_RT_EVM_OP_CODE) {
        sqlite3_bind_blob(st, 1, key, 64, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 2, key[64]);
    } else if (op != NODUS_RT_EVM_OP_META) {
        sqlite3_bind_blob(st, 1, key, key_len, SQLITE_TRANSIENT);
    }
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc == SQLITE_ROW) return 1;
    if (rc == SQLITE_DONE) return 0;
    return -1;
}

static nodus_adapter_status_t evm_probe(
        const nodus_domain_adapter_t *ad, struct nodus_witness *w,
        uint32_t dom, const nodus_adapter_op_t *op,
        const uint8_t *key, uint16_t key_len,
        nodus_adapter_row_facts_t *facts) {
    (void)ad;
    if (dom != DNA_DOMAIN_EVM || !facts) return NODUS_ADAPTER_ERR_STORAGE_FAULT;
    int e = row_exists(dbof(w), op->op_id, key, key_len);
    if (e < 0) return NODUS_ADAPTER_ERR_STORAGE_FAULT;
    memset(facts, 0, sizeof(*facts));
    facts->exists = e;               /* only ABSENT / EXISTS are allowed */
    return NODUS_ADAPTER_OK;
}

static nodus_adapter_status_t evm_read(
        const nodus_domain_adapter_t *ad, struct nodus_witness *w,
        uint32_t dom, const nodus_adapter_op_t *op,
        const uint8_t *key, uint16_t key_len,
        int *present_out, uint8_t *value_out, uint32_t value_cap,
        uint32_t *value_len_out) {
    (void)ad;
    sqlite3 *db = dbof(w);
    *present_out = 0;
    *value_len_out = 0;
    if (dom != DNA_DOMAIN_EVM) return NODUS_ADAPTER_ERR_STORAGE_FAULT;
    switch (op->op_id) {
        case NODUS_RT_EVM_OP_ACCT:
        case NODUS_RT_EVM_OP_HAS_STORAGE: {
            rtevm_acctrow_t r;
            int rc = acct_row_load(db, key, &r);
            if (rc < 0) return NODUS_ADAPTER_ERR_STORAGE_FAULT;
            if (rc == 1) return NODUS_ADAPTER_OK;
            if (op->op_id == NODUS_RT_EVM_OP_HAS_STORAGE) {
                *present_out = r.a.storage_count > 0;   /* indexed, §3    */
                return NODUS_ADAPTER_OK;
            }
            if (value_cap < NODUS_RT_EVM_ACCT_LEN)
                return NODUS_ADAPTER_ERR_STORAGE_FAULT;
            acct_encode(&r.a, value_out);
            *present_out = 1;
            *value_len_out = NODUS_RT_EVM_ACCT_LEN;
            return NODUS_ADAPTER_OK;
        }
        case NODUS_RT_EVM_OP_META: {
            rtevm_metarow_t mr;
            if (key_len != 1 || key[0] != META_KEY[0]) return NODUS_ADAPTER_OK;
            int rc = meta_load(db, &mr);
            if (rc < 0) return NODUS_ADAPTER_ERR_STORAGE_FAULT;
            if (rc == 1) return NODUS_ADAPTER_OK;
            if (value_cap < NODUS_RT_EVM_META_LEN)
                return NODUS_ADAPTER_ERR_STORAGE_FAULT;
            meta_encode(&mr.m, value_out);
            *present_out = 1;
            *value_len_out = NODUS_RT_EVM_META_LEN;
            return NODUS_ADAPTER_OK;
        }
        default: break;
    }
    const char *sql = NULL;
    switch (op->op_id) {
        case NODUS_RT_EVM_OP_SLOT:
            sql = "SELECT value FROM evm_slots WHERE addr = ?1 AND slot = ?2";
            break;
        case NODUS_RT_EVM_OP_CODE:
            sql = "SELECT bytes FROM evm_code WHERE digest = ?1 AND "
                  "chunk = ?2";
            break;
        case NODUS_RT_EVM_OP_TICKET:
            sql = "SELECT amount_raw, dest_fp FROM evm_tickets WHERE "
                  "ticket_id = ?1";
            break;
        default:
            return NODUS_ADAPTER_ERR_STORAGE_FAULT;
    }
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return NODUS_ADAPTER_ERR_STORAGE_FAULT;
    if (op->op_id == NODUS_RT_EVM_OP_SLOT) {
        sqlite3_bind_blob(st, 1, key, 32, SQLITE_TRANSIENT);
        sqlite3_bind_blob(st, 2, key + 32, 32, SQLITE_TRANSIENT);
    } else if (op->op_id == NODUS_RT_EVM_OP_CODE) {
        sqlite3_bind_blob(st, 1, key, 64, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 2, key[64]);
    } else {
        sqlite3_bind_blob(st, 1, key, key_len, SQLITE_TRANSIENT);
    }
    int rc = sqlite3_step(st);
    nodus_adapter_status_t ret = NODUS_ADAPTER_ERR_STORAGE_FAULT;
    if (rc == SQLITE_DONE) {
        ret = NODUS_ADAPTER_OK;                         /* absent         */
    } else if (rc == SQLITE_ROW) {
        if (op->op_id == NODUS_RT_EVM_OP_TICKET) {
            if (sqlite3_column_bytes(st, 1) == 64 &&
                value_cap >= NODUS_RT_EVM_TICKET_LEN) {
                put_u64be(value_out, (uint64_t)sqlite3_column_int64(st, 0));
                memcpy(value_out + 8, sqlite3_column_blob(st, 1), 64);
                *present_out = 1;
                *value_len_out = NODUS_RT_EVM_TICKET_LEN;
                ret = NODUS_ADAPTER_OK;
            }
        } else {
            int n = sqlite3_column_bytes(st, 0);
            const void *b = sqlite3_column_blob(st, 0);
            if (n > 0 && b && (uint32_t)n <= value_cap &&
                (uint32_t)n <= op->value_len_max) {
                memcpy(value_out, b, (size_t)n);
                *present_out = 1;
                *value_len_out = (uint32_t)n;
                ret = NODUS_ADAPTER_OK;
            }
        }
    }
    sqlite3_finalize(st);
    return ret;
}

/** ACCT mutation (design §4): the row now; the leaf at the batch's flush.
 *  @return 0 / -1. */
static int mut_acct(rtevm_batch_t *bt, uint8_t kind, const uint8_t addr[32],
                    const uint8_t *v, uint32_t vlen) {
    sqlite3 *db = bt->db;
    rtevm_acctrow_t old;
    int lrc = acct_row_load(db, addr, &old);
    if (lrc < 0) return -1;
    if (kind == DNA_EFFECT_DELETE) {
        if (lrc != 0) return -1;
        /* design §4: a deleted account has no committed slot; and with
         * EIP-6780 only a same-tx-created (never committed) account can
         * be destroyed, so a committed deletion is an empty account */
        if (old.a.storage_count != 0 || old.a.code_size != 0) {
            QGP_LOG_ERROR(LOG_TAG, "ACCT DELETE of an account with storage "
                          "or code");
            return -1;
        }
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(db, "DELETE FROM evm_accounts WHERE addr = ?1",
                               -1, &st, NULL) != SQLITE_OK)
            return -1;
        sqlite3_bind_blob(st, 1, addr, 32, SQLITE_TRANSIENT);
        int rc = sqlite3_step(st);
        sqlite3_finalize(st);
        if (rc != SQLITE_DONE) return -1;
        return batch_mark(bt, addr);
    }
    rtevm_acctrow_t r;
    memset(&r, 0, sizeof(r));
    if (acct_decode(v, vlen, &r.a) != 0) return -1;
    if (kind == DNA_EFFECT_CREATE) {
        if (lrc != 1) return -1;
        /* a storage trie open for this address belongs to a row that
         * existed earlier in the batch; the stream's unique keys and
         * (kind, op, key) order cannot produce that — fail closed rather
         * than let the flush graft it onto the new account */
        if (batch_has_stor(bt, addr)) return -1;
        if (evm_trie_empty_root(r.storage_root) != 0) return -1;
        if (r.a.code_size > 0 &&
            code_ref_add(db, r.a.code_digest, r.a.code_size) != 0)
            return -1;
    } else {                                           /* SET            */
        if (lrc != 0) return -1;
        memcpy(r.storage_root, old.storage_root, 64);
        int code_moved = old.a.code_size != r.a.code_size ||
                         memcmp(old.a.code_digest, r.a.code_digest, 64) != 0;
        if (code_moved) {
            if (old.a.code_size != 0) {
                QGP_LOG_ERROR(LOG_TAG, "ACCT SET replaces live code");
                return -1;
            }
            if (r.a.code_size > 0 &&
                code_ref_add(db, r.a.code_digest, r.a.code_size) != 0)
                return -1;
        }
    }
    if (acct_row_store(db, addr, &r) != 0) return -1;
    return batch_mark(bt, addr);
}

/** SLOT mutation: the slot row now; the account's storage trie in the
 *  batch; its storage_root and leaf at the flush (design §4, §6 (6)).
 *  storage_count is the ACCT value's (the engine-built stream carries the
 *  post count). @return 0/-1. */
static int mut_slot(rtevm_batch_t *bt, uint8_t kind, const uint8_t key[64],
                    const uint8_t *v, uint32_t vlen) {
    sqlite3 *db = bt->db;
    rtevm_acctrow_t r;
    if (acct_row_load(db, key, &r) != 0) return -1;   /* account must exist */
    sqlite3_stmt *st = NULL;
    evm_trie_rlp_buf b;
    memset(&b, 0, sizeof(b));
    int rc;
    if (kind == DNA_EFFECT_DELETE) {
        if (sqlite3_prepare_v2(db,
                "DELETE FROM evm_slots WHERE addr = ?1 AND slot = ?2",
                -1, &st, NULL) != SQLITE_OK)
            return -1;
        sqlite3_bind_blob(st, 1, key, 32, SQLITE_TRANSIENT);
        sqlite3_bind_blob(st, 2, key + 32, 32, SQLITE_TRANSIENT);
    } else {
        if (vlen != 32 || is_zero32(v)) return -1;     /* zero = DELETE   */
        if (sqlite3_prepare_v2(db,
                "INSERT OR REPLACE INTO evm_slots (addr, slot, value) "
                "VALUES (?1, ?2, ?3)", -1, &st, NULL) != SQLITE_OK)
            return -1;
        sqlite3_bind_blob(st, 1, key, 32, SQLITE_TRANSIENT);
        sqlite3_bind_blob(st, 2, key + 32, 32, SQLITE_TRANSIENT);
        sqlite3_bind_blob(st, 3, v, 32, SQLITE_TRANSIENT);
    }
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) return -1;
    /* the row's storage_root is the committed one until the flush */
    evm_trie_t *t = batch_stor(bt, key, r.storage_root);
    if (!t) return -1;
    if (kind == DNA_EFFECT_DELETE) {
        rc = evm_trie_delete(t, key + 32, 32);
    } else {
        rc = rlp_put_uint(&b, v, 32);
        if (rc == 0) rc = evm_trie_set(t, key + 32, 32, b.p, b.len);
        evm_trie_rlp_buf_free(&b);
    }
    if (rc != 0) return -1;
    return batch_mark(bt, key);
}

/** TICKET mutation: the row now; the tickets trie in the batch (design
 *  §6: value RLP([amount_raw, dest_fp])). @return 0 / -1. */
static int mut_ticket(rtevm_batch_t *bt, uint8_t kind, const uint8_t id[64],
                      const uint8_t *v, uint32_t vlen) {
    sqlite3 *db = bt->db;
    sqlite3_stmt *st = NULL;
    int rc;
    evm_trie_rlp_buf b;
    memset(&b, 0, sizeof(b));
    if (kind == DNA_EFFECT_DELETE) {
        if (sqlite3_prepare_v2(db,
                "DELETE FROM evm_tickets WHERE ticket_id = ?1",
                -1, &st, NULL) != SQLITE_OK)
            return -1;
        sqlite3_bind_blob(st, 1, id, 64, SQLITE_TRANSIENT);
        rc = sqlite3_step(st);
        sqlite3_finalize(st);
        if (rc != SQLITE_DONE) return -1;
        evm_trie_t *t = batch_top(bt, 1);
        rc = t ? evm_trie_delete(t, id, 64) : -1;
    } else {
        if (vlen != NODUS_RT_EVM_TICKET_LEN) return -1;
        uint64_t amount = get_u64be(v);
        if (amount == 0) return -1;
        if (sqlite3_prepare_v2(db,
                "INSERT INTO evm_tickets (ticket_id, amount_raw, dest_fp) "
                "VALUES (?1, ?2, ?3)", -1, &st, NULL) != SQLITE_OK)
            return -1;
        sqlite3_bind_blob(st, 1, id, 64, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 2, (sqlite3_int64)amount);
        sqlite3_bind_blob(st, 3, v + 8, 64, SQLITE_TRANSIENT);
        rc = sqlite3_step(st);
        sqlite3_finalize(st);
        if (rc != SQLITE_DONE) return -1;
        rc = (rlp_put_u64(&b, amount) == 0 &&
              evm_trie_rlp_put_bytes(&b, v + 8, 64) == 0 &&
              evm_trie_rlp_wrap_list(&b, 0) == 0) ? 0 : -1;
        if (rc == 0) {
            evm_trie_t *t = batch_top(bt, 1);
            rc = t ? evm_trie_set(t, id, 64, b.p, b.len) : -1;
        }
        evm_trie_rlp_buf_free(&b);
    }
    return rc != 0 ? -1 : 0;
}

static nodus_adapter_status_t evm_mutate(
        const nodus_domain_adapter_t *ad, struct nodus_witness *w,
        uint32_t dom, const nodus_adapter_op_t *op, uint8_t kind,
        const uint8_t *key, uint16_t key_len,
        const uint8_t *value, uint32_t value_len) {
    (void)ad;
    sqlite3 *db = dbof(w);
    int rc = -1;
    if (dom != DNA_DOMAIN_EVM) return NODUS_ADAPTER_ERR_STORAGE_FAULT;
    /* the trie-touching ops run in the leg's open batch, or — none open
     * for this witness — in a batch of their own, committed at once */
    rtevm_batch_t *bt = NULL;
    int own = 0;
    if (op->op_id == NODUS_RT_EVM_OP_ACCT ||
        op->op_id == NODUS_RT_EVM_OP_SLOT ||
        op->op_id == NODUS_RT_EVM_OP_TICKET) {
        bt = batch_of(w);
        if (!bt) {
            bt = batch_new(w);
            if (!bt) return NODUS_ADAPTER_ERR_STORAGE_FAULT;
            own = 1;
        }
    }
    switch (op->op_id) {
        case NODUS_RT_EVM_OP_ACCT:
            rc = key_len == 32 ? mut_acct(bt, kind, key, value, value_len)
                               : -1;
            break;
        case NODUS_RT_EVM_OP_SLOT:
            rc = key_len == 64 ? mut_slot(bt, kind, key, value, value_len)
                               : -1;
            break;
        case NODUS_RT_EVM_OP_CODE: {
            if (kind != DNA_EFFECT_CREATE || key_len != 65 || value_len == 0)
                break;
            sqlite3_stmt *st = NULL;
            if (sqlite3_prepare_v2(db,
                    "INSERT INTO evm_code (digest, chunk, bytes) "
                    "VALUES (?1, ?2, ?3)", -1, &st, NULL) != SQLITE_OK)
                break;
            sqlite3_bind_blob(st, 1, key, 64, SQLITE_TRANSIENT);
            sqlite3_bind_int64(st, 2, key[64]);
            sqlite3_bind_blob(st, 3, value, (int)value_len, SQLITE_TRANSIENT);
            rc = sqlite3_step(st) == SQLITE_DONE ? 0 : -1;
            sqlite3_finalize(st);
            break;
        }
        case NODUS_RT_EVM_OP_TICKET:
            rc = key_len == 64 ? mut_ticket(bt, kind, key, value, value_len)
                               : -1;
            break;
        case NODUS_RT_EVM_OP_META: {
            rtevm_metarow_t mr;
            if (kind != DNA_EFFECT_SET || key_len != 1 ||
                key[0] != META_KEY[0] || value_len != NODUS_RT_EVM_META_LEN ||
                meta_load(db, &mr) != 0)
                break;
            meta_decode(value, &mr.m);
            rc = meta_store(db, &mr, 0);
            break;
        }
        default:
            break;
    }
    /* a failed mutation (any op) may have half-moved the leg: its batch
     * must never be committed */
    if (rc != 0) {
        if (bt) bt->broken = 1;
        rtevm_batch_t *lb = batch_of(w);
        if (lb) lb->broken = 1;
    }
    if (own) {
        if (rc == 0) rc = batch_flush(bt);
        batch_free(bt);
    }
    return rc == 0 ? NODUS_ADAPTER_OK : NODUS_ADAPTER_ERR_STORAGE_FAULT;
}

const nodus_domain_adapter_t NODUS_RT_EVM_ADAPTER = {
    .adapter_version = NODUS_DOMAIN_ADAPTER_V1,
    .ops = EVM_OPS,
    .n_ops = sizeof(EVM_OPS) / sizeof(EVM_OPS[0]),
    .probe = evm_probe,
    .mutate = evm_mutate,
    .read = evm_read
};

/* ── the EVM domain root (design §6) ──────────────────────────────────── */

/** SHA3-512("NDS.EVMROOT.v1\0\0" ‖ account_trie_root ‖ tickets_root ‖
 *  SHA3-512("NDS.EVMMETA.v1\0\0" ‖ wei_live ‖ wei_tickets ‖ wei_lost)). */
static int evm_root_of(const rtevm_metarow_t *r, uint8_t out[64]) {
    uint8_t pre[16 + 96];
    uint8_t md[64];
    memcpy(pre, TAG_EVMMETA, 16);
    evm_u256_to_be(pre + 16, &r->m.live);
    evm_u256_to_be(pre + 48, &r->m.tickets);
    evm_u256_to_be(pre + 80, &r->m.lost);
    if (qgp_sha3_512(pre, sizeof(pre), md) != 0) return -1;
    uint8_t top[16 + 64 * 3];
    memcpy(top, TAG_EVMROOT, 16);
    memcpy(top + 16, r->acct_root, 64);
    memcpy(top + 80, r->tkt_root, 64);
    memcpy(top + 144, md, 64);
    return qgp_sha3_512(top, sizeof(top), out) == 0 ? 0 : -1;
}

static int empty_metarow(rtevm_metarow_t *r) {
    memset(r, 0, sizeof(*r));
    evm_u256_zero(&r->m.live);
    evm_u256_zero(&r->m.tickets);
    evm_u256_zero(&r->m.lost);
    if (evm_trie_empty_root(r->acct_root) != 0) return -1;
    if (evm_trie_empty_root(r->tkt_root) != 0) return -1;
    return 0;
}

int nodus_rt_evm_empty_state_root(uint8_t out[64]) {
    rtevm_metarow_t r;
    if (!out || empty_metarow(&r) != 0) return -1;
    return evm_root_of(&r, out);
}

int nodus_rt_evm_ticket_addr(uint8_t out[32]) {
    uint8_t d[64];
    if (!out ||
        qgp_sha3_512((const uint8_t *)TICKET_ADDR_PREIMAGE,
                     sizeof(TICKET_ADDR_PREIMAGE) - 1, d) != 0)
        return -1;
    memcpy(out, d, 32);
    return 0;
}

int nodus_rt_evm_state_root(const nodus_domain_runtime_t *rt,
                            struct nodus_witness *w, uint8_t out[64]) {
    (void)rt;
    rtevm_metarow_t r;
    if (!w || !out) return -1;
    /* an open leg batch holds trie changes the META row's roots do not
     * carry yet: no root exists to report until it is flushed */
    if (batch_of(w)) return -1;
    /* the META row exists from activation on; before it there is no EVM
     * state to commit — the fail-closed answer, never a default root */
    if (meta_load(dbof(w), &r) != 0) return -1;
    return evm_root_of(&r, out);
}

/** Does `name` exist as a table? @return 1 / 0 / -1. */
static int table_present(sqlite3 *db, const char *name) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND "
            "name = ?1", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, name, -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);
    int ret = -1;
    if (rc == SQLITE_ROW) ret = sqlite3_column_int64(st, 0) > 0 ? 1 : 0;
    sqlite3_finalize(st);
    return ret;
}

/* design §5: wei_live + wei_tickets + wei_lost == q × reserve, where
 * `reserve` is the CORE EVM reserve bucket (v2_evm_reserve) — CORE state,
 * moved only by CORE EVMFUND in the same item as the EVM leg — read
 * through CORE's own accessor (nodus_witness_core_evm_reserve_get). The
 * engine's supply gate runs this at block start and block end, so both
 * halves of every item are in. */
int nodus_rt_evm_invariant(const nodus_domain_runtime_t *rt,
                           struct nodus_witness *w) {
    (void)rt;
    if (!w) return -1;
    sqlite3 *db = dbof(w);
    int tp = table_present(db, "evm_meta");
    if (tp < 0) return -1;            /* a fault is never "conserved"     */
    if (tp == 0) return 0;            /* pre-S17: no EVM state exists     */
    rtevm_metarow_t r;
    int rc = meta_load(db, &r);
    if (rc < 0) return -1;
    if (rc == 1) return 0;            /* not activated: no EVM value      */
    uint64_t reserve = 0;
    /* S17 created the reserve row with the EVM tables: absent = fault */
    if (nodus_witness_core_evm_reserve_get((nodus_witness_t *)w,
                                           &reserve) != 0)
        return -1;
    evm_u256 sum, want;
    if (evm_u256_add(&sum, &r.m.live, &r.m.tickets) ||
        evm_u256_add(&sum, &sum, &r.m.lost))
        return -1;
    wei_of_raw(&want, reserve);
    if (evm_u256_cmp(&sum, &want) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "EVM invariant violated: live + tickets + "
                      "lost != q x reserve");
        return -1;
    }
    return 0;
}

/* Activation-time state (design §9): empty tries, zero META. Idempotent
 * or conflict: an existing row equal to the initial state passes, any
 * other refuses. */
int nodus_rt_evm_state_init(const nodus_domain_runtime_t *rt,
                            struct nodus_witness *w,
                            uint64_t activation_global_height) {
    (void)rt;
    (void)activation_global_height;
    if (!w) return -1;
    sqlite3 *db = dbof(w);
    rtevm_metarow_t want, have;
    if (empty_metarow(&want) != 0) return -1;
    int rc = meta_load(db, &have);    /* a missing table (pre-S17) = -1 */
    if (rc < 0) return -1;
    if (rc == 1) return meta_store(db, &want, 1);
    if (evm_u256_cmp(&have.m.live, &want.m.live) != 0 ||
        evm_u256_cmp(&have.m.tickets, &want.m.tickets) != 0 ||
        evm_u256_cmp(&have.m.lost, &want.m.lost) != 0 ||
        memcmp(have.acct_root, want.acct_root, 64) != 0 ||
        memcmp(have.tkt_root, want.tkt_root, 64) != 0)
        return -1;
    return 0;
}

/* ── the runtime entry ───────────────────────────────────────────────── */

/* The EVM descriptor's rule list — ONE array, shared by the production
 * table entry (nodus_witness_runtime.c, the EVM generation) and the test
 * builder below. */
const uint32_t NODUS_RT_EVM_RULES[NODUS_RT_EVM_N_RULES] = {
    NODUS_RT_EVM_CALL, NODUS_RT_EVM_CREATE, NODUS_RT_EVM_DEPOSIT,
    NODUS_RT_EVM_WITHDRAW, NODUS_RT_EVM_REDEEM
};

/* The EVM domain owns no legacy tx type: the legacy surface refuses. */
int nodus_rt_evm_admit(const nodus_domain_runtime_t *rt, uint8_t tx_type,
                       uint32_t pool_id) {
    (void)rt; (void)tx_type; (void)pool_id;
    return -1;
}

int nodus_rt_evm_tx_cost(const nodus_domain_runtime_t *rt, uint8_t tx_type,
                         uint32_t *cost_out) {
    (void)rt; (void)tx_type; (void)cost_out;
    return -1;
}

int nodus_rt_evm_runtime_build(nodus_domain_runtime_t *out) {
    if (!out) return -1;
    memset(out, 0, sizeof(*out));
    out->domain_id = DNA_DOMAIN_EVM;
    out->runtime_kind = DNA_RUNTIME_NATIVE_BUILTIN;
    out->runtime_abi = NODUS_DOMAIN_RUNTIME_ABI_V2;
    out->ruleset_version = 1;
    out->generation = 0;               /* not a compiled generation yet   */
    out->descriptor.descriptor_version = DNA_RULESET_DESC_VERSION;
    out->descriptor.domain_id = DNA_DOMAIN_EVM;
    memcpy(out->descriptor.name, "EVM", 3);
    out->descriptor.runtime_abi = NODUS_DOMAIN_RUNTIME_ABI_V2;
    out->descriptor.ruleset_version = 1;
    out->descriptor.rule_count = NODUS_RT_EVM_N_RULES;
    out->descriptor.rule_ids = NODUS_RT_EVM_RULES;
    out->descriptor.tx_type_count = 0;
    out->descriptor.tx_types = NULL;
    if (dna_ruleset_desc_hash(&out->descriptor, out->ruleset_hash) != 0)
        return -1;
    out->admit = nodus_rt_evm_admit;
    out->tx_cost = nodus_rt_evm_tx_cost;
    out->auth = nodus_rt_auth_dsa87_v1;
    out->allowed_auth_kinds =
        NODUS_RT_AUTHKIND_BIT(NODUS_RT_AUTHKIND_DSA87_MULTI_V1);
    out->read_plan = NULL;
    out->exec = NULL;
    out->exec_evm = nodus_rt_evm_exec;
    out->prevalidate_evm = nodus_rt_evm_prevalidate;
    out->state_root = nodus_rt_evm_state_root;
    out->payload_root = NULL;
    out->asset_check = NULL;
    out->claim_apply = NULL;
    out->invariant = nodus_rt_evm_invariant;
    out->state_init = nodus_rt_evm_state_init;
    out->adapter = &NODUS_RT_EVM_ADAPTER;
    out->meter_policy = NULL;
    return nodus_runtime_hooks_check(out) == 0 ? 0 : -1;
}
