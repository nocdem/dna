/**
 * Nodus — DHT Value Operations
 *
 * Create, sign, verify, serialize/deserialize NodusValue.
 * Signature covers: key_hash + data + type + ttl + value_id + seq
 */

#include "core/nodus_value.h"
#include "crypto/nodus_sign.h"
#include "protocol/nodus_cbor.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ── Signing payload ─────────────────────────────────────────────── */

int nodus_value_sign_payload(const nodus_value_t *val,
                             uint8_t **buf_out, size_t *len_out) {
    if (!val || !buf_out || !len_out)
        return -1;

    /*
     * Payload layout (concatenation):
     *   key_hash  (64 bytes)
     *   data      (variable)
     *   type      (1 byte)
     *   ttl       (4 bytes, LE)
     *   value_id  (8 bytes, LE)
     *   seq       (8 bytes, LE)
     */
    size_t total = NODUS_KEY_BYTES + val->data_len + 1 + 4 + 8 + 8;
    uint8_t *buf = malloc(total);
    if (!buf)
        return -1;

    size_t pos = 0;

    /* key_hash */
    memcpy(buf + pos, val->key_hash.bytes, NODUS_KEY_BYTES);
    pos += NODUS_KEY_BYTES;

    /* data */
    if (val->data_len > 0 && val->data) {
        memcpy(buf + pos, val->data, val->data_len);
        pos += val->data_len;
    }

    /* type */
    buf[pos++] = (uint8_t)val->type;

    /* ttl (LE32) */
    buf[pos++] = (uint8_t)(val->ttl);
    buf[pos++] = (uint8_t)(val->ttl >> 8);
    buf[pos++] = (uint8_t)(val->ttl >> 16);
    buf[pos++] = (uint8_t)(val->ttl >> 24);

    /* value_id (LE64) */
    for (int i = 0; i < 8; i++)
        buf[pos++] = (uint8_t)(val->value_id >> (i * 8));

    /* seq (LE64) */
    for (int i = 0; i < 8; i++)
        buf[pos++] = (uint8_t)(val->seq >> (i * 8));

    *buf_out = buf;
    *len_out = total;
    return 0;
}

/* ── Create ──────────────────────────────────────────────────────── */

int nodus_value_create(const nodus_key_t *key_hash,
                       const uint8_t *data, size_t data_len,
                       nodus_value_type_t type, uint32_t ttl,
                       uint64_t value_id, uint64_t seq,
                       const nodus_pubkey_t *owner_pk,
                       nodus_value_t **val_out) {
    if (!key_hash || !owner_pk || !val_out)
        return -1;
    if (data_len > 0 && !data)
        return -1;

    nodus_value_t *val = calloc(1, sizeof(nodus_value_t));
    if (!val)
        return -1;

    val->key_hash = *key_hash;
    val->value_id = value_id;
    val->type = type;
    val->ttl = ttl;
    val->seq = seq;
    val->owner_pk = *owner_pk;

    /* Compute owner fingerprint */
    if (nodus_fingerprint(owner_pk, &val->owner_fp) != 0) {
        free(val);
        return -1;
    }

    /* Copy data */
    if (data_len > 0) {
        val->data = malloc(data_len);
        if (!val->data) {
            free(val);
            return -1;
        }
        memcpy(val->data, data, data_len);
        val->data_len = data_len;
    }

    /* Timestamps */
    val->created_at = (uint64_t)time(NULL);
    if (type == NODUS_VALUE_PERMANENT || ttl == 0) {
        val->expires_at = 0;
    } else {
        val->expires_at = val->created_at + ttl;
    }

    *val_out = val;
    return 0;
}

/* ── Sign / Verify ───────────────────────────────────────────────── */

int nodus_value_sign(nodus_value_t *val, const nodus_seckey_t *sk) {
    if (!val || !sk)
        return -1;

    uint8_t *payload = NULL;
    size_t payload_len = 0;

    if (nodus_value_sign_payload(val, &payload, &payload_len) != 0)
        return -1;

    int rc = nodus_sign(&val->signature, payload, payload_len, sk);
    free(payload);
    return rc;
}

int nodus_value_verify(const nodus_value_t *val) {
    if (!val)
        return -1;

    uint8_t *payload = NULL;
    size_t payload_len = 0;

    if (nodus_value_sign_payload(val, &payload, &payload_len) != 0)
        return -1;

    int rc = nodus_verify(&val->signature, payload, payload_len, &val->owner_pk);
    free(payload);
    return rc;
}

/* ── Serialize ───────────────────────────────────────────────────── */

int nodus_value_serialize(const nodus_value_t *val,
                          uint8_t **buf_out, size_t *len_out) {
    if (!val || !buf_out || !len_out)
        return -1;

    /*
     * Conservative buffer size estimate:
     * map(10) + keys + values.
     * Largest fields: owner_pk (2592), signature (4627), data (up to 1MB)
     * Header overhead for CBOR: ~200 bytes
     */
    size_t est = 256 + val->data_len + NODUS_PK_BYTES + NODUS_SIG_BYTES + NODUS_KEY_BYTES * 2;
    uint8_t *buf = malloc(est);
    if (!buf)
        return -1;

    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, est);

    cbor_encode_map(&enc, 10);

    /* "key" : bytes */
    cbor_encode_cstr(&enc, "key");
    cbor_encode_bstr(&enc, val->key_hash.bytes, NODUS_KEY_BYTES);

    /* "vid" : uint */
    cbor_encode_cstr(&enc, "vid");
    cbor_encode_uint(&enc, val->value_id);

    /* "data" : bytes */
    cbor_encode_cstr(&enc, "data");
    cbor_encode_bstr(&enc, val->data ? val->data : (const uint8_t *)"", val->data_len);

    /* "type" : uint */
    cbor_encode_cstr(&enc, "type");
    cbor_encode_uint(&enc, (uint64_t)val->type);

    /* "ttl" : uint */
    cbor_encode_cstr(&enc, "ttl");
    cbor_encode_uint(&enc, val->ttl);

    /* "created" : uint */
    cbor_encode_cstr(&enc, "created");
    cbor_encode_uint(&enc, val->created_at);

    /* "seq" : uint */
    cbor_encode_cstr(&enc, "seq");
    cbor_encode_uint(&enc, val->seq);

    /* "owner" : bytes (public key) */
    cbor_encode_cstr(&enc, "owner");
    cbor_encode_bstr(&enc, val->owner_pk.bytes, NODUS_PK_BYTES);

    /* "owner_fp" : bytes */
    cbor_encode_cstr(&enc, "owner_fp");
    cbor_encode_bstr(&enc, val->owner_fp.bytes, NODUS_KEY_BYTES);

    /* "sig" : bytes */
    cbor_encode_cstr(&enc, "sig");
    cbor_encode_bstr(&enc, val->signature.bytes, NODUS_SIG_BYTES);

    size_t written = cbor_encoder_len(&enc);
    if (written == 0) {
        free(buf);
        return -1;
    }

    *buf_out = buf;
    *len_out = written;
    return 0;
}

/* ── Deserialize ─────────────────────────────────────────────────── */

int nodus_value_deserialize(const uint8_t *buf, size_t len,
                            nodus_value_t **val_out) {
    if (!buf || !val_out || len == 0)
        return -1;

    cbor_decoder_t dec;
    cbor_decoder_init(&dec, buf, len);

    /* Expect map */
    cbor_item_t item = cbor_decode_next(&dec);
    if (item.type != CBOR_ITEM_MAP)
        return -1;

    nodus_value_t *val = calloc(1, sizeof(nodus_value_t));
    if (!val)
        return -1;

    size_t map_count = item.count;

    for (size_t i = 0; i < map_count && !dec.error; i++) {
        /* Key */
        cbor_item_t k = cbor_decode_next(&dec);
        if (k.type != CBOR_ITEM_TSTR) {
            cbor_decode_skip(&dec);
            continue;
        }

        /* Value */
        cbor_item_t v = cbor_decode_next(&dec);

        if (k.tstr.len == 3 && memcmp(k.tstr.ptr, "key", 3) == 0) {
            if (v.type == CBOR_ITEM_BSTR && v.bstr.len == NODUS_KEY_BYTES)
                memcpy(val->key_hash.bytes, v.bstr.ptr, NODUS_KEY_BYTES);
        } else if (k.tstr.len == 3 && memcmp(k.tstr.ptr, "vid", 3) == 0) {
            if (v.type == CBOR_ITEM_UINT)
                val->value_id = v.uint_val;
        } else if (k.tstr.len == 4 && memcmp(k.tstr.ptr, "data", 4) == 0) {
            if (v.type == CBOR_ITEM_BSTR && v.bstr.len > 0) {
                val->data = malloc(v.bstr.len);
                if (val->data) {
                    memcpy(val->data, v.bstr.ptr, v.bstr.len);
                    val->data_len = v.bstr.len;
                }
            }
        } else if (k.tstr.len == 4 && memcmp(k.tstr.ptr, "type", 4) == 0) {
            if (v.type == CBOR_ITEM_UINT)
                val->type = (nodus_value_type_t)v.uint_val;
        } else if (k.tstr.len == 3 && memcmp(k.tstr.ptr, "ttl", 3) == 0) {
            if (v.type == CBOR_ITEM_UINT)
                val->ttl = (uint32_t)v.uint_val;
        } else if (k.tstr.len == 7 && memcmp(k.tstr.ptr, "created", 7) == 0) {
            if (v.type == CBOR_ITEM_UINT)
                val->created_at = v.uint_val;
        } else if (k.tstr.len == 3 && memcmp(k.tstr.ptr, "seq", 3) == 0) {
            if (v.type == CBOR_ITEM_UINT)
                val->seq = v.uint_val;
        } else if (k.tstr.len == 5 && memcmp(k.tstr.ptr, "owner", 5) == 0) {
            if (v.type == CBOR_ITEM_BSTR && v.bstr.len == NODUS_PK_BYTES)
                memcpy(val->owner_pk.bytes, v.bstr.ptr, NODUS_PK_BYTES);
        } else if (k.tstr.len == 8 && memcmp(k.tstr.ptr, "owner_fp", 8) == 0) {
            if (v.type == CBOR_ITEM_BSTR && v.bstr.len == NODUS_KEY_BYTES)
                memcpy(val->owner_fp.bytes, v.bstr.ptr, NODUS_KEY_BYTES);
        } else if (k.tstr.len == 3 && memcmp(k.tstr.ptr, "sig", 3) == 0) {
            if (v.type == CBOR_ITEM_BSTR && v.bstr.len == NODUS_SIG_BYTES)
                memcpy(val->signature.bytes, v.bstr.ptr, NODUS_SIG_BYTES);
        }
    }

    if (dec.error) {
        nodus_value_free(val);
        return -1;
    }

    /* Compute expires_at */
    if (val->type == NODUS_VALUE_PERMANENT || val->ttl == 0) {
        val->expires_at = 0;
    } else {
        val->expires_at = val->created_at + val->ttl;
    }

    *val_out = val;
    return 0;
}

/* ── Free / Expire ───────────────────────────────────────────────── */

void nodus_value_free(nodus_value_t *val) {
    if (!val) return;
    free(val->data);
    free(val);
}

bool nodus_value_is_expired(const nodus_value_t *val, uint64_t now_unix) {
    if (!val)
        return true;
    if (val->type == NODUS_VALUE_PERMANENT || val->expires_at == 0)
        return false;
    return now_unix >= val->expires_at;
}
