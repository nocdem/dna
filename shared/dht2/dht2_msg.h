/**
 * @file shared/dht2/dht2_msg.h
 * @brief DHT v2 package 2 — the wire messages: get / put requests, answer /
 *        receipt / refusal payloads, the pull-sync messages, the inbox
 *        control `_data`, and the bit-vector of `p_want`.
 *
 * Design rev 5 (FROZEN, docs/plans/2026-10-14-dht-v2-design.md): §4.4,
 * §4.5, §13 rows 7 (results), 11 (sizes), 12 (pull-sync), 14 (requests),
 * 15 (inbox control), 18 (answer payloads) — §13 is normative.
 * Operator decision docs/plans/decisions/2026-10-23-dht-v2-wire-gaps-
 * package2.md: requests and pull messages are strict DAG-CBOR maps with
 * text keys; pull messages carry no `op` and no `n`; read-repair is
 * `op` "put"; the pull-receipt keys are pf, sf, c, g, s, top, e; the LIST
 * answer's `req_cursor` is ABSENT on a first page.
 *
 * ENCODING: every message is ONE strict DAG-CBOR map, keys in the one
 * canonical order (length first, then bytewise — dag-cbor/spec.md:58),
 * decoded with the strict reader of dht2_cbor.h (shortest form, sorted
 * unique keys, no unknown key, no trailing byte, exact lengths) and then
 * RE-ENCODED and compared byte for byte (the package-1 identity check).
 * Counts are bounded BEFORE iteration. Integers are u64 (row 6); this
 * file adds or multiplies only compile-time bounded sizes (≤ 250 entries,
 * ⌈n/8⌉ of n ≤ 250, len / 73), so no runtime arithmetic can overflow.
 *
 * ERROR CODES (a READING — row 7 names none for these):
 *   · requests (get / put)                    → DHT2_E_MALFORMED_REQ
 *     (row 7 "Malformed request … a tier-2 protocol error, no signed
 *     answer");
 *   · answer / receipt / refusal payloads, pull messages, control `_data`
 *                                             → DHT2_E_BAD_ENCODING;
 *   · NULL argument / too-small buffer        → DHT2_E_ARG.
 * Encoders refuse content a decoder would refuse (same code as the
 * decoder of that message), so nothing is emitted that cannot be read.
 *
 * Every `out` of an encoder may be NULL: only *out_len (the exact size) is
 * produced. Decoded byte pointers point INTO the input (zero copy) or are
 * copied into fixed arrays, as each struct says.
 *
 * NOT here: the LIST request (dht2_envelope.h, package 1); the pull-
 * receipt's envelope domain (not decided — see the decision's "Still
 * open"); no sealing of the pull-receipt; no admission, holder or client
 * logic. Reads no clock, keeps no state, draws no randomness, no heap.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef SHARED_DHT2_MSG_H
#define SHARED_DHT2_MSG_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include "dht2/dht2_envelope.h"
#include "dht2/dht2_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ══ row 7: the per-key result ═════════════════════════════════════════ */

typedef enum {
    DHT2_RV_HASH = 0,     /* v = bstr 64 */
    DHT2_RV_NULL,         /* v = null (not held) */
    DHT2_RV_CODE,         /* v = uint code in {1..13, 16, 17} */
    DHT2_RV_HANDLED       /* v = [18, through] */
} dht2_rv_kind_t;

/** Which message carries the result — row 7 "null (not held — GET / LIST
 *  only, NEVER a PUT result)" and row 18 "LIST: v = the SHA3-512 … or 17". */
typedef enum {
    DHT2_RCTX_READ = 0,   /* read answer: hash, null, code, [18, through] */
    DHT2_RCTX_WRITE,      /* receipt: as read, but NEVER null */
    DHT2_RCTX_LIST        /* LIST answer's single element: hash or code 17 */
} dht2_rctx_t;

typedef struct {
    uint8_t        key[DHT2_HASH_LEN];      /* `k` */
    dht2_rv_kind_t kind;                    /* `v` … */
    uint8_t        hash[DHT2_HASH_LEN];     /* DHT2_RV_HASH */
    uint64_t       code;                    /* DHT2_RV_CODE */
    uint64_t       through;                 /* DHT2_RV_HANDLED */
} dht2_result_t;

/* ══ row 14: requests ══════════════════════════════════════════════════ */

typedef enum {
    DHT2_REQ_GET = 0,     /* {n, op "get", keys [bstr 64] ≤ 8} */
    DHT2_REQ_PUT          /* {n, op "put", envs [bstr] ≤ 8}; also read-repair */
} dht2_req_kind_t;

typedef struct {
    dht2_req_kind_t kind;
    uint8_t         nonce[DHT2_NONCE_LEN];                 /* `n` */
    size_t          count;                                  /* ≤ 8 */
    uint8_t         keys[DHT2_REQ_KEYS_MAX][DHT2_HASH_LEN]; /* GET */
    const uint8_t  *envs[DHT2_REQ_KEYS_MAX];                /* PUT, into input */
    size_t          env_lens[DHT2_REQ_KEYS_MAX];            /* each ≤ 262,144 */
} dht2_req_t;

/** Canonical bytes of a get / put request. @return DHT2_OK,
 *  DHT2_E_MALFORMED_REQ (count > 8, an env longer than DHT2_ENVELOPE_MAX),
 *  DHT2_E_ARG. */
int dht2_req_encode(const dht2_req_t *req, uint8_t *out, size_t cap,
                    size_t *out_len);

/** Strict decode + re-encode check. Row 7: nonce ≠ 32 B, > 8 keys, a key
 *  ≠ 64 B, an unknown `op`, any strict-CBOR fault → DHT2_E_MALFORMED_REQ. */
int dht2_req_decode(const uint8_t *in, size_t len, dht2_req_t *req);

/* ══ row 18: answer payloads ═══════════════════════════════════════════ */

/** Read answer (`/nodus/dht/answer/v1`) and write receipt
 *  (`/nodus/dht/receipt/v1`) share one shape {c, h, n, q, r, t}. */
typedef struct {
    uint8_t       q[DHT2_NONCE_LEN];      /* the request's nonce */
    uint8_t       n[DHT2_FP_LEN];         /* holder fp */
    uint8_t       c[DHT2_CHAIN_LEN];      /* chain id */
    uint64_t      h;                      /* committed height */
    uint64_t      t;                      /* tip block time, seconds */
    size_t        r_count;                /* ≤ 8 */
    dht2_result_t r[DHT2_REQ_KEYS_MAX];
} dht2_answer_t;

/** Read answer payload (null allowed in `v`). */
int dht2_answer_encode(const dht2_answer_t *a, uint8_t *out, size_t cap,
                       size_t *out_len);
int dht2_answer_decode(const uint8_t *in, size_t len, dht2_answer_t *a);

/** Write receipt payload: `r` never contains null (row 7). */
int dht2_receipt_encode(const dht2_answer_t *a, uint8_t *out, size_t cap,
                        size_t *out_len);
int dht2_receipt_decode(const uint8_t *in, size_t len, dht2_answer_t *a);

typedef struct {
    uint8_t  w[DHT2_FP_LEN];              /* writer fp */
    uint8_t  d[DHT2_HASH_LEN];            /* entry hash */
} dht2_list_entry_t;

/** LIST answer payload (`/nodus/dht/answer/v1`): the read answer's keys +
 *  {ctl, list, cursor?, complete, req_cursor?}; `r` is ONE element.
 *  Rules enforced (row 11, §4.4, decision 4): `list` ≤ 16; `w` strictly
 *  ascending; `cursor` (when present) = the last `w` listed; an empty page
 *  is `complete` = true with no cursor. */
typedef struct {
    uint8_t           q[DHT2_NONCE_LEN];
    uint8_t           n[DHT2_FP_LEN];
    uint8_t           c[DHT2_CHAIN_LEN];
    uint64_t          h;
    uint64_t          t;
    dht2_result_t     r;                  /* the single element */
    bool              has_ctl;            /* false ⇒ `ctl` is null */
    uint8_t           ctl[DHT2_HASH_LEN];
    size_t            list_count;         /* ≤ 16 */
    dht2_list_entry_t list[DHT2_LIST_PAGE_MAX];
    bool              has_cursor;
    uint8_t           cursor[DHT2_FP_LEN];
    bool              complete;
    bool              has_req_cursor;     /* absent on a first page */
    uint8_t           req_cursor[DHT2_FP_LEN];
} dht2_list_answer_t;

int dht2_list_answer_encode(const dht2_list_answer_t *a, uint8_t *out,
                            size_t cap, size_t *out_len);
int dht2_list_answer_decode(const uint8_t *in, size_t len,
                            dht2_list_answer_t *a);

/** Refusal payload (`/nodus/dht/refusal/v1`) {c, e, n, q}; `e` ∈ {14, 15},
 *  no `h` / `t` (row 7, row 18). */
typedef struct {
    uint8_t  q[DHT2_NONCE_LEN];
    uint8_t  n[DHT2_FP_LEN];
    uint8_t  c[DHT2_CHAIN_LEN];
    uint64_t e;                           /* DHT2_E_BUSY | DHT2_E_NOT_CAUGHT_UP */
} dht2_refusal_t;

int dht2_refusal_encode(const dht2_refusal_t *m, uint8_t *out, size_t cap,
                        size_t *out_len);
int dht2_refusal_decode(const uint8_t *in, size_t len, dht2_refusal_t *m);

/** §4.4: seal an answer / receipt / refusal payload under the domain /
 *  ctx `nodus.dht.answer.v1` (all three share it). `payload_type` is one
 *  of DHT2_PT_ANSWER / _RECEIPT / _REFUSAL (a C string, no NUL on the
 *  wire). `out` NULL → size only. @return as dht2_env_seal. */
int dht2_answer_seal(const char *payload_type, const uint8_t *payload,
                     size_t payload_len, const uint8_t *sk,
                     const uint8_t pk[DHT2_PUBKEY_LEN], uint8_t *out,
                     size_t cap, size_t *out_len);

/** Decode an answer envelope (≤ DHT2_ENVELOPE_MAX), require payload type
 *  = `payload_type`, verify under `nodus.dht.answer.v1`. On DHT2_OK `env`
 *  points into `in`. @return DHT2_OK, DHT2_E_TOO_LARGE,
 *  DHT2_E_BAD_ENCODING (decode fault or another payload type),
 *  DHT2_E_BAD_SIGNATURE, DHT2_E_HOLDER_FAULT, DHT2_E_ARG. The caller's
 *  §4.4 client rules (fp = `n`, `q`, `c`, eligibility) come after. */
int dht2_answer_open(const uint8_t *in, size_t len, const char *payload_type,
                     dht2_env_t *env);

/* ══ row 12: pull-sync messages ════════════════════════════════════════ */

typedef struct {
    uint64_t g;                           /* store generation */
    uint64_t top;                         /* global high-water mark */
} dht2_p_hello_t;                         /* {g, top} */

typedef struct {
    uint64_t g;
    uint64_t s;                           /* first insertion index wanted */
} dht2_p_get_t;                           /* {g, s} */

typedef struct {
    uint8_t a[DHT2_HASH_LEN];             /* address */
    uint8_t h[DHT2_HASH_LEN];             /* envelope hash */
    uint8_t p[DHT2_HASH_LEN];             /* placement-key hint */
} dht2_offer_entry_t;

typedef struct {
    uint64_t           g;
    uint64_t           top;
    size_t             e_count;           /* ≤ 250 */
    dht2_offer_entry_t e[DHT2_PULL_PAGE_MAX];
} dht2_p_offer_t;                         /* {e, g, top} — ~47 KB: keep off small stacks */

typedef struct {
    const uint8_t *b;                     /* into the input */
    size_t         b_len;                 /* = ⌈n/8⌉ */
} dht2_p_want_t;                          /* {b} */

typedef struct {
    uint64_t       i;                     /* offer index */
    bool           has_v;                 /* false ⇒ `v` is null (gone) */
    const uint8_t *v;                     /* canonical envelope, into input */
    size_t         v_len;                 /* ≤ 262,144 */
} dht2_p_deliver_t;                       /* {i, v} */

typedef struct {
    uint8_t a[DHT2_HASH_LEN];
    uint8_t h[DHT2_HASH_LEN];
} dht2_receipt_entry_t;

/** Pull-receipt PAYLOAD {c, e, g, s, pf, sf, top}. Its envelope domain is
 *  NOT decided: nothing here seals or opens it. */
typedef struct {
    uint8_t              pf[DHT2_FP_LEN];  /* puller fp */
    uint8_t              sf[DHT2_FP_LEN];  /* source fp */
    uint8_t              c[DHT2_CHAIN_LEN];
    uint64_t             g;
    uint64_t             s;
    uint64_t             top;
    size_t               e_count;          /* ≤ 250 */
    dht2_receipt_entry_t e[DHT2_PULL_PAGE_MAX]; /* ~32 KB */
} dht2_pull_receipt_t;

int dht2_p_hello_encode(const dht2_p_hello_t *m, uint8_t *out, size_t cap,
                        size_t *out_len);
int dht2_p_hello_decode(const uint8_t *in, size_t len, dht2_p_hello_t *m);
int dht2_p_get_encode(const dht2_p_get_t *m, uint8_t *out, size_t cap,
                      size_t *out_len);
int dht2_p_get_decode(const uint8_t *in, size_t len, dht2_p_get_t *m);
int dht2_p_offer_encode(const dht2_p_offer_t *m, uint8_t *out, size_t cap,
                        size_t *out_len);
int dht2_p_offer_decode(const uint8_t *in, size_t len, dht2_p_offer_t *m);

/** `p_want`: `b` of EXACTLY ⌈n/8⌉ bytes, bits ≥ n zero, n = the offer's
 *  entry count (≤ 250) — any other length → DHT2_E_BAD_ENCODING (the
 *  exchange aborts, row 12). */
int dht2_p_want_encode(const dht2_p_want_t *m, size_t n, uint8_t *out,
                       size_t cap, size_t *out_len);
int dht2_p_want_decode(const uint8_t *in, size_t len, size_t n,
                       dht2_p_want_t *m);

int dht2_p_deliver_encode(const dht2_p_deliver_t *m, uint8_t *out, size_t cap,
                          size_t *out_len);
int dht2_p_deliver_decode(const uint8_t *in, size_t len, dht2_p_deliver_t *m);

int dht2_pull_receipt_encode(const dht2_pull_receipt_t *m, uint8_t *out,
                             size_t cap, size_t *out_len);
int dht2_pull_receipt_decode(const uint8_t *in, size_t len,
                             dht2_pull_receipt_t *m);

/* ── the `p_want` bit-vector (row 12; Bee bitvector.go:52-61 LSB-first) ─
 * bit i = byte ⌊i/8⌋, mask 1 << (i mod 8). No bounds check: the caller
 * holds ⌈n/8⌉ bytes and i < n. */
size_t dht2_bits_len(size_t n);                     /* ⌈n/8⌉ */
bool   dht2_bits_get(const uint8_t *b, size_t i);
void   dht2_bits_set(uint8_t *b, size_t i);

/* ══ row 15: inbox control `_data` ═════════════════════════════════════ */

typedef struct {
    uint8_t  fp[DHT2_FP_LEN];
    uint8_t  mark;                        /* DHT2_CTL_HANDLED | DHT2_CTL_DENIED */
    uint64_t through;                     /* u64 BE on the wire */
} dht2_ctl_entry_t;

/** Encode `count` entries (strictly ascending by fp, valid marks, count ≤
 *  3,500). `out` NULL → size only. @return DHT2_OK, DHT2_E_BAD_ENCODING
 *  (order / mark / count), DHT2_E_ARG. */
int dht2_ctl_encode(const dht2_ctl_entry_t *e, size_t count, uint8_t *out,
                    size_t cap, size_t *out_len);

/** Validate a control `_data`: length a multiple of 73, ≤ 3,500 entries,
 *  marks 1 / 2, strictly ascending by fp. On DHT2_OK `*count` is the entry
 *  count. Other → DHT2_E_BAD_ENCODING. */
int dht2_ctl_check(const uint8_t *data, size_t len, size_t *count);

/** Entry `idx` of a data that dht2_ctl_check accepted. @return DHT2_OK or
 *  DHT2_E_ARG (idx out of range). */
int dht2_ctl_at(const uint8_t *data, size_t len, size_t idx,
                dht2_ctl_entry_t *out);

/** Lookup by fp in `data` (validated first). @return DHT2_OK with
 *  `*found` set (and `out` filled when found; `out` may be NULL),
 *  DHT2_E_BAD_ENCODING (invalid data), DHT2_E_ARG. */
int dht2_ctl_lookup(const uint8_t *data, size_t len,
                    const uint8_t fp[DHT2_FP_LEN], bool *found,
                    dht2_ctl_entry_t *out);

#ifdef __cplusplus
}
#endif

#endif /* SHARED_DHT2_MSG_H */
