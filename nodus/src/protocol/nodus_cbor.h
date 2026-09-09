/**
 * Nodus — Minimal CBOR Encoder/Decoder
 *
 * Supports only the types we need: unsigned integers, byte strings,
 * text strings, arrays, maps. No floats, tags, or indefinite-length.
 * RFC 8949 compliant subset — debuggable at cbor.me.
 *
 * @file nodus_cbor.h
 */

#ifndef NODUS_CBOR_H
#define NODUS_CBOR_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── CBOR major types ────────────────────────────────────────────── */
#define CBOR_UINT     0   /* Major type 0: unsigned integer */
/* Major type 1: negative integer. It has exactly two doors —
 * cbor_decode_int (to read one) and cbor_decode_skip_signed (to step over
 * one without reading it). cbor_decode_next still reports it as an error,
 * deliberately (see those declarations). */
#define CBOR_NEGINT   1
#define CBOR_BSTR     2   /* Major type 2: byte string */
#define CBOR_TSTR     3   /* Major type 3: text string */
#define CBOR_ARRAY    4   /* Major type 4: array */
#define CBOR_MAP      5   /* Major type 5: map */
#define CBOR_TAG      6   /* Major type 6: tag (unused) */
#define CBOR_SIMPLE   7   /* Major type 7: simple/float */

/* Simple values */
#define CBOR_FALSE    0xF4
#define CBOR_TRUE     0xF5
#define CBOR_NULL     0xF6

/* ── Encoder ─────────────────────────────────────────────────────── */

/** CBOR encoder state */
typedef struct {
    uint8_t *buf;       /* Output buffer */
    size_t   cap;       /* Buffer capacity */
    size_t   pos;       /* Current write position */
    bool     error;     /* Set on overflow */
} cbor_encoder_t;

/** Initialize encoder with caller-provided buffer */
void cbor_encoder_init(cbor_encoder_t *enc, uint8_t *buf, size_t cap);

/** Encode unsigned integer */
void cbor_encode_uint(cbor_encoder_t *enc, uint64_t val);

/** RFC 8949 §3.1: val >= 0 → major type 0; val < 0 → major type 1 with argument (-1 - val).
 *  INT64_MIN → argument INT64_MAX (0x3B 7F FF FF FF FF FF FF FF). Shortest argument form. */
void cbor_encode_int(cbor_encoder_t *enc, int64_t val);

/** Encode byte string */
void cbor_encode_bstr(cbor_encoder_t *enc, const uint8_t *data, size_t len);

/** Encode text string (UTF-8, not validated) */
void cbor_encode_tstr(cbor_encoder_t *enc, const char *str, size_t len);

/** Encode NUL-terminated text string */
void cbor_encode_cstr(cbor_encoder_t *enc, const char *str);

/** Begin map with known element count */
void cbor_encode_map(cbor_encoder_t *enc, size_t count);

/** Begin array with known element count */
void cbor_encode_array(cbor_encoder_t *enc, size_t count);

/** Encode boolean */
void cbor_encode_bool(cbor_encoder_t *enc, bool val);

/** Encode null */
void cbor_encode_null(cbor_encoder_t *enc);

/** Return bytes written (0 if error) */
size_t cbor_encoder_len(const cbor_encoder_t *enc);

/* ── Decoder ─────────────────────────────────────────────────────── */

/** CBOR item types returned by decoder */
typedef enum {
    CBOR_ITEM_UINT,
    CBOR_ITEM_BSTR,
    CBOR_ITEM_TSTR,
    CBOR_ITEM_ARRAY,
    CBOR_ITEM_MAP,
    CBOR_ITEM_BOOL,
    CBOR_ITEM_NULL,
    CBOR_ITEM_END,      /* No more data */
    CBOR_ITEM_ERROR     /* Decode error */
} cbor_item_type_t;

/** Decoded CBOR item */
typedef struct {
    cbor_item_type_t type;
    union {
        uint64_t        uint_val;
        struct {
            const uint8_t *ptr;
            size_t         len;
        } bstr;
        struct {
            const char    *ptr;
            size_t         len;
        } tstr;
        size_t          count;      /* Array/map element count */
        bool            bool_val;
    };
} cbor_item_t;

/** Maximum nesting depth for CBOR containers (CRIT-1: prevents stack exhaustion) */
#define CBOR_MAX_DEPTH  32

/** Maximum array/map element count (M-01: prevents CPU DoS from crafted counts) */
#define NODUS_CBOR_MAX_ITEMS  4096

/** CBOR decoder state */
typedef struct {
    const uint8_t *buf;     /* Input buffer */
    size_t         len;     /* Total length */
    size_t         pos;     /* Current read position */
    bool           error;
    uint8_t        depth;   /* Current nesting depth (skip recursion) */
} cbor_decoder_t;

/** Initialize decoder */
void cbor_decoder_init(cbor_decoder_t *dec, const uint8_t *buf, size_t len);

/** Decode next item.
 *
 * Major type 1 (negative integer) is reported as CBOR_ITEM_ERROR here and
 * sets dec->error. That is NOT an oversight and must not be "fixed": every
 * existing arg decoder in tier1/2/3 tests `val.type == CBOR_ITEM_UINT` and
 * SKIPS anything else, so making this function return a negative item would
 * silently turn "reject" into "accept, field left at zero" for every legacy
 * message. Signed fields are read with cbor_decode_int below, which is the
 * only door to major type 1. */
cbor_item_t cbor_decode_next(cbor_decoder_t *dec);

/** Reads ONE item that must be an integer: major type 0 with argument <= INT64_MAX, or major type 1
 *  with argument <= INT64_MAX (value = -1 - argument). Any other major type, or an argument above
 *  INT64_MAX, sets dec->error and returns false (*out untouched). cbor_decode_next / peek / skip are
 *  UNCHANGED: major type 1 stays CBOR_ITEM_ERROR there — every legacy verb decoder keeps rejecting
 *  negative bytes exactly as today. */
bool cbor_decode_int(cbor_decoder_t *dec, int64_t *out);

/** Peek at next item type without consuming */
cbor_item_type_t cbor_decode_peek(const cbor_decoder_t *dec);

/** Skip one complete item (including nested containers) */
void cbor_decode_skip(cbor_decoder_t *dec);

/** Skips ONE item exactly like cbor_decode_skip, except that a major type 1 item (negative
 *  integer, RFC 8949 §3.1) is stepped over through cbor_decode_int instead of being an error,
 *  and *saw_negint (may be NULL) is set to true when at least one was stepped over. Everything
 *  else — truncation, reserved additional info, tags, floats, depth (CBOR_MAX_DEPTH), item
 *  count (NODUS_CBOR_MAX_ITEMS) — behaves byte-for-byte as cbor_decode_skip. cbor_decode_next /
 *  cbor_decode_peek / cbor_decode_skip stay UNCHANGED: ≈230 call sites in 12 files (measured
 *  2026-09-09) across tier1, tier2, tier3, nodus_client, witness, nodus-cli and messenger
 *  nodus_ops share them. */
void cbor_decode_skip_signed(cbor_decoder_t *dec, bool *saw_negint);

/**
 * Decode a map and look up a text-string key.
 * Positions decoder right after the value's header so caller can read it.
 * Returns the item for the value, or CBOR_ITEM_ERROR if key not found.
 * Resets decoder to start of map first, so call from map start.
 */
cbor_item_t cbor_map_find(cbor_decoder_t *dec, size_t map_count, const char *key);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_CBOR_H */
