/**
 * @file shared/dht2/dht2_cbor.h
 * @brief DHT v2 — strict DAG-CBOR token reader and canonical writer.
 *
 * WHAT: the byte-level layer under every DHT v2 signed map (record data,
 * §3.1; owner-signed LIST payload, §13 row 23; the package-2 wire messages).
 * It is a TOKEN reader: the schemas above it (dht2_record.c,
 * dht2_envelope.c, dht2_msg.c) match fixed text keys
 * and never need a generic tree.
 *
 * WHY NOT nodus/src/protocol/nodus_cbor.h: that decoder accepts long-form
 * integers and lengths and does not check map key order (design §13 row
 * 22: "the tree's decoder does not enforce shortest form"); it reports
 * major type 1 as an error (nodus_cbor.h:128-137) but nothing else of the
 * strict rules. Strict decoding is the whole point here, and shared/
 * cannot depend on nodus/src anyway.
 *
 * RULES ENFORCED ON DECODE (ipld bfd348aa specs/codecs/dag-cbor/spec.md
 * "Strictness" :46-66; the relaxed decoding of :68-78 is NOT offered):
 *   · integers and lengths of major types 0, 2-5 in their SHORTEST form
 *     (:55-56);
 *   · no indefinite lengths, no break token (:59);
 *   · no tags at all — tag 42 is not used by any DHT v2 schema (Kurultay
 *     #21 "Strict decode": "no tags (42 not used)"), so every major type 6
 *     is refused (:52, :57);
 *   · major type 7: the spec allows false / true / null and 64-bit floats
 *     (:60-65); no DHT v2 schema carries a float, so the reader offers
 *     false / true (0xf4 / 0xf5: `_del`, the LIST answer's `complete`) and
 *     null (0xf6: row-7 `v`, `ctl`, `p_deliver.v`) and every other
 *     major-type-7 item is refused;
 *   · arrays (major type 4): definite and shortest head only; the CALLER
 *     bounds the element count before it loops (dht2_cbor_rd_array returns
 *     whatever count the head claims);
 *   · major type 1 (negative integer) refused — design §13 row 6 "major
 *     type 0 only" (named deviation, row 21);
 *   · map keys: text only (spec "Map Keys" :42-44), strictly ascending by
 *     their encoded bytes, i.e. length first then bytewise (:58) — strict,
 *     so a duplicate key is refused too;
 *   · one top-level object, no trailing byte (:66) — the schema caller
 *     checks dht2_cbor_rd_done() at the end.
 * The schemas ALSO re-encode what they parsed and compare it byte for
 * byte with the input (design §3.1 "re-encode check").
 *
 * The writer emits only shortest forms, definite lengths, no tags, no
 * floats; it never sorts — each schema writes its keys in the fixed
 * canonical order, which the reader's order check then proves.
 *
 * No heap, no global state, no clock, no randomness; every read is
 * bounds-checked before it happens.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef SHARED_DHT2_CBOR_H
#define SHARED_DHT2_CBOR_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── reader ────────────────────────────────────────────────────────── */

typedef struct {
    const uint8_t *buf;
    size_t         len;
    size_t         pos;
    bool           err;     /* sticky: once set, every call fails */
} dht2_cbor_rd_t;

void dht2_cbor_rd_init(dht2_cbor_rd_t *r, const uint8_t *buf, size_t len);

/** Map header, definite and shortest. 0 / -1. */
int dht2_cbor_rd_map(dht2_cbor_rd_t *r, uint64_t *count);

/** A map KEY: a text string, shortest length. `prev`/`prev_len` is the
 *  previous key's text of the same map (NULL for the first key); the new
 *  key must sort strictly after it (length first, then bytewise). The
 *  returned pointer points INTO the reader's buffer. 0 / -1. */
int dht2_cbor_rd_key(dht2_cbor_rd_t *r, const uint8_t *prev, size_t prev_len,
                     const uint8_t **key, size_t *key_len);

/** Major type 0, shortest. 0 / -1 (major type 1 is -1). */
int dht2_cbor_rd_uint(dht2_cbor_rd_t *r, uint64_t *v);

/** Major type 2, shortest length; pointer into the buffer. 0 / -1. */
int dht2_cbor_rd_bytes(dht2_cbor_rd_t *r, const uint8_t **p, size_t *n);

/** Major type 3, shortest length; pointer into the buffer. 0 / -1. */
int dht2_cbor_rd_text(dht2_cbor_rd_t *r, const uint8_t **p, size_t *n);

/** Array header (major type 4), definite and shortest. The count is NOT
 *  checked against the remaining bytes here: the schema bounds it before
 *  iterating. 0 / -1. */
int dht2_cbor_rd_array(dht2_cbor_rd_t *r, uint64_t *count);

/** Exactly 0xf5 (true). 0 / -1. */
int dht2_cbor_rd_true(dht2_cbor_rd_t *r);

/** Exactly 0xf4 (false) or 0xf5 (true). 0 / -1. */
int dht2_cbor_rd_bool(dht2_cbor_rd_t *r, bool *v);

/** Exactly 0xf6 (null). 0 / -1. */
int dht2_cbor_rd_null(dht2_cbor_rd_t *r);

/** Major type (0-7) of the next item without consuming it; -1 at the end
 *  of input or after an error. For schemas whose value is one of several
 *  types (row-7 `v`). */
int dht2_cbor_rd_peek_mt(const dht2_cbor_rd_t *r);

/** True when the next byte is exactly 0xf6 (null); nothing consumed. */
bool dht2_cbor_rd_peek_null(const dht2_cbor_rd_t *r);

/** True when every byte was consumed without error (spec :66). */
bool dht2_cbor_rd_done(const dht2_cbor_rd_t *r);

/** Key equality helper for the schema parsers. */
bool dht2_cbor_key_is(const uint8_t *key, size_t key_len, const char *lit);

/* ── writer (forward) ──────────────────────────────────────────────────
 * Three modes over ONE emission path, so the bytes counted, written and
 * compared are the same bytes by construction:
 *   · WRITE   — into a caller buffer of `cap` bytes;
 *   · COUNT   — nothing stored, `len` = the size the item would take;
 *   · COMPARE — nothing stored; every byte is compared with `ref` at the
 *               same offset, and the first difference (or running past
 *               `ref_len`) sets `err`. This is the re-encode identity
 *               check of design §3.1 without a second buffer. */

typedef enum {
    DHT2_WR_WRITE = 0,
    DHT2_WR_COUNT,
    DHT2_WR_COMPARE
} dht2_wr_mode_t;

typedef struct {
    dht2_wr_mode_t mode;
    uint8_t       *buf;     /* WRITE */
    const uint8_t *ref;     /* COMPARE */
    size_t         cap;     /* WRITE: buffer size; COMPARE: ref length */
    size_t         len;
    bool           err;     /* sticky: overflow, or a COMPARE mismatch */
} dht2_cbor_wr_t;

void dht2_cbor_wr_init(dht2_cbor_wr_t *w, uint8_t *buf, size_t cap);
void dht2_cbor_wr_init_count(dht2_cbor_wr_t *w);
void dht2_cbor_wr_init_compare(dht2_cbor_wr_t *w, const uint8_t *ref,
                               size_t ref_len);
/** COMPARE mode: true when every emitted byte matched and ALL of `ref`
 *  was emitted. WRITE / COUNT: true when no error occurred. */
bool dht2_cbor_wr_ok(const dht2_cbor_wr_t *w);
void dht2_cbor_wr_map(dht2_cbor_wr_t *w, uint64_t count);
void dht2_cbor_wr_uint(dht2_cbor_wr_t *w, uint64_t v);
void dht2_cbor_wr_bytes(dht2_cbor_wr_t *w, const uint8_t *p, size_t n);
void dht2_cbor_wr_text(dht2_cbor_wr_t *w, const uint8_t *p, size_t n);
/** A text key given as a C string literal. */
void dht2_cbor_wr_key(dht2_cbor_wr_t *w, const char *lit);
void dht2_cbor_wr_true(dht2_cbor_wr_t *w);
void dht2_cbor_wr_bool(dht2_cbor_wr_t *w, bool v);
void dht2_cbor_wr_null(dht2_cbor_wr_t *w);
/** Array header, shortest form; the caller then writes `count` items. */
void dht2_cbor_wr_array(dht2_cbor_wr_t *w, uint64_t count);

/** Number of bytes the head of an item with argument `v` takes. */
size_t dht2_cbor_head_size(uint64_t v);

#ifdef __cplusplus
}
#endif

#endif /* SHARED_DHT2_CBOR_H */
