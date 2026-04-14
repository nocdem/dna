/**
 * Nodus — Minimal CBOR Encoder/Decoder
 *
 * RFC 8949 compliant subset. Only encodes/decodes:
 * unsigned integers, byte strings, text strings, arrays, maps, booleans, null.
 * No floats, tags, or indefinite-length encoding.
 */

#include "protocol/nodus_cbor.h"
#include <string.h>

#include "crypto/utils/qgp_safe_string.h"   /* Phase 03: unsafe-string poison guard */

/* ── Internal helpers ────────────────────────────────────────────── */

static inline void enc_ensure(cbor_encoder_t *enc, size_t need) {
    if (enc->error || enc->pos + need > enc->cap)
        enc->error = true;
}

static void enc_byte(cbor_encoder_t *enc, uint8_t b) {
    enc_ensure(enc, 1);
    if (!enc->error)
        enc->buf[enc->pos++] = b;
}

/** Encode CBOR initial byte + argument (major type in high 3 bits) */
static void enc_head(cbor_encoder_t *enc, uint8_t major, uint64_t val) {
    uint8_t mt = (major & 0x07) << 5;

    if (val <= 23) {
        enc_byte(enc, mt | (uint8_t)val);
    } else if (val <= 0xFF) {
        enc_byte(enc, mt | 24);
        enc_byte(enc, (uint8_t)val);
    } else if (val <= 0xFFFF) {
        enc_byte(enc, mt | 25);
        enc_byte(enc, (uint8_t)(val >> 8));
        enc_byte(enc, (uint8_t)(val));
    } else if (val <= 0xFFFFFFFF) {
        enc_byte(enc, mt | 26);
        enc_byte(enc, (uint8_t)(val >> 24));
        enc_byte(enc, (uint8_t)(val >> 16));
        enc_byte(enc, (uint8_t)(val >> 8));
        enc_byte(enc, (uint8_t)(val));
    } else {
        enc_byte(enc, mt | 27);
        enc_byte(enc, (uint8_t)(val >> 56));
        enc_byte(enc, (uint8_t)(val >> 48));
        enc_byte(enc, (uint8_t)(val >> 40));
        enc_byte(enc, (uint8_t)(val >> 32));
        enc_byte(enc, (uint8_t)(val >> 24));
        enc_byte(enc, (uint8_t)(val >> 16));
        enc_byte(enc, (uint8_t)(val >> 8));
        enc_byte(enc, (uint8_t)(val));
    }
}

static void enc_raw(cbor_encoder_t *enc, const uint8_t *data, size_t len) {
    enc_ensure(enc, len);
    if (!enc->error) {
        memcpy(enc->buf + enc->pos, data, len);
        enc->pos += len;
    }
}

/* ── Encoder API ─────────────────────────────────────────────────── */

void cbor_encoder_init(cbor_encoder_t *enc, uint8_t *buf, size_t cap) {
    enc->buf = buf;
    enc->cap = cap;
    enc->pos = 0;
    enc->error = false;
}

void cbor_encode_uint(cbor_encoder_t *enc, uint64_t val) {
    enc_head(enc, CBOR_UINT, val);
}

void cbor_encode_bstr(cbor_encoder_t *enc, const uint8_t *data, size_t len) {
    enc_head(enc, CBOR_BSTR, len);
    enc_raw(enc, data, len);
}

void cbor_encode_tstr(cbor_encoder_t *enc, const char *str, size_t len) {
    enc_head(enc, CBOR_TSTR, len);
    enc_raw(enc, (const uint8_t *)str, len);
}

void cbor_encode_cstr(cbor_encoder_t *enc, const char *str) {
    size_t len = strlen(str);
    cbor_encode_tstr(enc, str, len);
}

void cbor_encode_map(cbor_encoder_t *enc, size_t count) {
    enc_head(enc, CBOR_MAP, count);
}

void cbor_encode_array(cbor_encoder_t *enc, size_t count) {
    enc_head(enc, CBOR_ARRAY, count);
}

void cbor_encode_bool(cbor_encoder_t *enc, bool val) {
    enc_byte(enc, val ? CBOR_TRUE : CBOR_FALSE);
}

void cbor_encode_null(cbor_encoder_t *enc) {
    enc_byte(enc, CBOR_NULL);
}

size_t cbor_encoder_len(const cbor_encoder_t *enc) {
    return enc->error ? 0 : enc->pos;
}

/* ── Decoder internals ───────────────────────────────────────────── */

static inline bool dec_has(const cbor_decoder_t *dec, size_t need) {
    return !dec->error && dec->pos + need <= dec->len;
}

static inline uint8_t dec_byte(cbor_decoder_t *dec) {
    if (!dec_has(dec, 1)) {
        dec->error = true;
        return 0;
    }
    return dec->buf[dec->pos++];
}

/** Decode argument value from initial byte's additional info */
static uint64_t dec_arg(cbor_decoder_t *dec, uint8_t ai) {
    if (ai <= 23) {
        return ai;
    } else if (ai == 24) {
        return dec_byte(dec);
    } else if (ai == 25) {
        if (!dec_has(dec, 2)) { dec->error = true; return 0; }
        uint64_t v = ((uint64_t)dec->buf[dec->pos] << 8) |
                     (uint64_t)dec->buf[dec->pos + 1];
        dec->pos += 2;
        return v;
    } else if (ai == 26) {
        if (!dec_has(dec, 4)) { dec->error = true; return 0; }
        uint64_t v = ((uint64_t)dec->buf[dec->pos]     << 24) |
                     ((uint64_t)dec->buf[dec->pos + 1] << 16) |
                     ((uint64_t)dec->buf[dec->pos + 2] <<  8) |
                     (uint64_t)dec->buf[dec->pos + 3];
        dec->pos += 4;
        return v;
    } else if (ai == 27) {
        if (!dec_has(dec, 8)) { dec->error = true; return 0; }
        uint64_t v = 0;
        for (int i = 0; i < 8; i++)
            v = (v << 8) | dec->buf[dec->pos + i];
        dec->pos += 8;
        return v;
    } else {
        dec->error = true;
        return 0;
    }
}

/* ── Decoder API ─────────────────────────────────────────────────── */

void cbor_decoder_init(cbor_decoder_t *dec, const uint8_t *buf, size_t len) {
    dec->buf = buf;
    dec->len = len;
    dec->pos = 0;
    dec->depth = 0;
    dec->error = false;
}

cbor_item_t cbor_decode_next(cbor_decoder_t *dec) {
    cbor_item_t item;
    memset(&item, 0, sizeof(item));

    if (!dec_has(dec, 1)) {
        item.type = (dec->pos >= dec->len) ? CBOR_ITEM_END : CBOR_ITEM_ERROR;
        return item;
    }

    uint8_t ib = dec_byte(dec);
    uint8_t mt = (ib >> 5) & 0x07;
    uint8_t ai = ib & 0x1F;

    switch (mt) {
    case CBOR_UINT: {
        item.type = CBOR_ITEM_UINT;
        item.uint_val = dec_arg(dec, ai);
        break;
    }
    case CBOR_BSTR: {
        uint64_t len = dec_arg(dec, ai);
        if (dec->error || !dec_has(dec, (size_t)len)) {
            dec->error = true;
            item.type = CBOR_ITEM_ERROR;
            return item;
        }
        item.type = CBOR_ITEM_BSTR;
        item.bstr.ptr = dec->buf + dec->pos;
        item.bstr.len = (size_t)len;
        dec->pos += (size_t)len;
        break;
    }
    case CBOR_TSTR: {
        uint64_t len = dec_arg(dec, ai);
        if (dec->error || !dec_has(dec, (size_t)len)) {
            dec->error = true;
            item.type = CBOR_ITEM_ERROR;
            return item;
        }
        item.type = CBOR_ITEM_TSTR;
        item.tstr.ptr = (const char *)(dec->buf + dec->pos);
        item.tstr.len = (size_t)len;
        dec->pos += (size_t)len;
        break;
    }
    case CBOR_ARRAY: {
        uint64_t n = dec_arg(dec, ai);
        if (n > NODUS_CBOR_MAX_ITEMS) {
            dec->error = true;
            item.type = CBOR_ITEM_ERROR;
            break;
        }
        item.type = CBOR_ITEM_ARRAY;
        item.count = (size_t)n;
        break;
    }
    case CBOR_MAP: {
        uint64_t n = dec_arg(dec, ai);
        if (n > NODUS_CBOR_MAX_ITEMS) {
            dec->error = true;
            item.type = CBOR_ITEM_ERROR;
            break;
        }
        item.type = CBOR_ITEM_MAP;
        item.count = (size_t)n;
        break;
    }
    case CBOR_SIMPLE: {
        if (ib == CBOR_FALSE) {
            item.type = CBOR_ITEM_BOOL;
            item.bool_val = false;
        } else if (ib == CBOR_TRUE) {
            item.type = CBOR_ITEM_BOOL;
            item.bool_val = true;
        } else if (ib == CBOR_NULL) {
            item.type = CBOR_ITEM_NULL;
        } else {
            /* Unsupported simple value / float */
            dec->error = true;
            item.type = CBOR_ITEM_ERROR;
        }
        break;
    }
    default:
        /* Negative ints, tags — unsupported */
        dec->error = true;
        item.type = CBOR_ITEM_ERROR;
        break;
    }

    if (dec->error)
        item.type = CBOR_ITEM_ERROR;
    return item;
}

cbor_item_type_t cbor_decode_peek(const cbor_decoder_t *dec) {
    if (dec->error || dec->pos >= dec->len)
        return (dec->pos >= dec->len) ? CBOR_ITEM_END : CBOR_ITEM_ERROR;

    uint8_t ib = dec->buf[dec->pos];
    uint8_t mt = (ib >> 5) & 0x07;

    switch (mt) {
    case CBOR_UINT:   return CBOR_ITEM_UINT;
    case CBOR_BSTR:   return CBOR_ITEM_BSTR;
    case CBOR_TSTR:   return CBOR_ITEM_TSTR;
    case CBOR_ARRAY:  return CBOR_ITEM_ARRAY;
    case CBOR_MAP:    return CBOR_ITEM_MAP;
    case CBOR_SIMPLE:
        if (ib == CBOR_FALSE || ib == CBOR_TRUE) return CBOR_ITEM_BOOL;
        if (ib == CBOR_NULL) return CBOR_ITEM_NULL;
        return CBOR_ITEM_ERROR;
    default:
        return CBOR_ITEM_ERROR;
    }
}

void cbor_decode_skip(cbor_decoder_t *dec) {
    cbor_item_t item = cbor_decode_next(dec);
    if (item.type == CBOR_ITEM_ERROR || item.type == CBOR_ITEM_END)
        return;

    /* For containers, recursively skip children */
    if (item.type == CBOR_ITEM_MAP) {
        if (dec->depth >= CBOR_MAX_DEPTH) { dec->error = true; return; }
        dec->depth++;
        for (size_t i = 0; i < item.count * 2 && !dec->error; i++)
            cbor_decode_skip(dec);
        dec->depth--;
    } else if (item.type == CBOR_ITEM_ARRAY) {
        if (dec->depth >= CBOR_MAX_DEPTH) { dec->error = true; return; }
        dec->depth++;
        for (size_t i = 0; i < item.count && !dec->error; i++)
            cbor_decode_skip(dec);
        dec->depth--;
    }
    /* Scalars (uint, bstr, tstr, bool, null) are already consumed */
}

cbor_item_t cbor_map_find(cbor_decoder_t *dec, size_t map_count, const char *key) {
    cbor_item_t result;
    memset(&result, 0, sizeof(result));
    result.type = CBOR_ITEM_ERROR;

    size_t key_len = strlen(key);

    for (size_t i = 0; i < map_count && !dec->error; i++) {
        /* Decode the key */
        cbor_item_t k = cbor_decode_next(dec);

        /* Check if this is the key we want */
        bool match = false;
        if (k.type == CBOR_ITEM_TSTR &&
            k.tstr.len == key_len &&
            memcmp(k.tstr.ptr, key, key_len) == 0) {
            match = true;
        }

        if (match) {
            /* Return the value item (caller reads the content) */
            result = cbor_decode_next(dec);
            return result;
        }

        /* Not our key — skip the value */
        cbor_decode_skip(dec);
    }

    return result;
}
