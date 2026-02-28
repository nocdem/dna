/**
 * Nodus v5 — Tier 1 Protocol (Nodus-Nodus)
 *
 * CBOR encode/decode for inter-node messages.
 * UDP: ping, pong, find_node, nodes_found
 * TCP: store_value, store_ack, find_value, value_found,
 *      subscribe, unsubscribe, notify
 */

#include "protocol/nodus_tier1.h"
#include "protocol/nodus_cbor.h"
#include "core/nodus_value.h"

#include <string.h>
#include <stdlib.h>

/* ── Common encoder helpers ──────────────────────────────────────── */

static void encode_envelope(cbor_encoder_t *enc, size_t map_count,
                             uint32_t txn, char type, const char *method) {
    cbor_encode_map(enc, map_count);
    cbor_encode_cstr(enc, "t");  cbor_encode_uint(enc, txn);
    cbor_encode_cstr(enc, "y");  cbor_encode_tstr(enc, &type, 1);
    cbor_encode_cstr(enc, "q");  cbor_encode_cstr(enc, method);
}

static void encode_peers(cbor_encoder_t *enc, const nodus_peer_t *peers,
                          int count) {
    cbor_encode_array(enc, (size_t)count);
    for (int i = 0; i < count; i++) {
        cbor_encode_map(enc, 4);
        cbor_encode_cstr(enc, "id");
        cbor_encode_bstr(enc, peers[i].node_id.bytes, NODUS_KEY_BYTES);
        cbor_encode_cstr(enc, "ip");
        cbor_encode_cstr(enc, peers[i].ip);
        cbor_encode_cstr(enc, "up");
        cbor_encode_uint(enc, peers[i].udp_port);
        cbor_encode_cstr(enc, "tp");
        cbor_encode_uint(enc, peers[i].tcp_port);
    }
}

static int finish(cbor_encoder_t *enc, size_t *out_len) {
    size_t len = cbor_encoder_len(enc);
    if (len == 0) return -1;
    *out_len = len;
    return 0;
}

/* ── Encode functions ────────────────────────────────────────────── */

int nodus_t1_ping(uint32_t txn, const nodus_key_t *node_id,
                   uint8_t *buf, size_t cap, size_t *out_len) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    encode_envelope(&enc, 4, txn, 'q', "ping");
    cbor_encode_cstr(&enc, "a");
    cbor_encode_map(&enc, 1);
    cbor_encode_cstr(&enc, "id");
    cbor_encode_bstr(&enc, node_id->bytes, NODUS_KEY_BYTES);
    return finish(&enc, out_len);
}

int nodus_t1_pong(uint32_t txn, const nodus_key_t *node_id,
                   uint8_t *buf, size_t cap, size_t *out_len) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    encode_envelope(&enc, 4, txn, 'r', "pong");
    cbor_encode_cstr(&enc, "r");
    cbor_encode_map(&enc, 1);
    cbor_encode_cstr(&enc, "id");
    cbor_encode_bstr(&enc, node_id->bytes, NODUS_KEY_BYTES);
    return finish(&enc, out_len);
}

int nodus_t1_find_node(uint32_t txn, const nodus_key_t *target,
                        uint8_t *buf, size_t cap, size_t *out_len) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    encode_envelope(&enc, 4, txn, 'q', "fn");
    cbor_encode_cstr(&enc, "a");
    cbor_encode_map(&enc, 1);
    cbor_encode_cstr(&enc, "target");
    cbor_encode_bstr(&enc, target->bytes, NODUS_KEY_BYTES);
    return finish(&enc, out_len);
}

int nodus_t1_nodes_found(uint32_t txn, const nodus_peer_t *peers, int count,
                          uint8_t *buf, size_t cap, size_t *out_len) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    encode_envelope(&enc, 4, txn, 'r', "fn_r");
    cbor_encode_cstr(&enc, "r");
    cbor_encode_map(&enc, 1);
    cbor_encode_cstr(&enc, "nodes");
    encode_peers(&enc, peers, count);
    return finish(&enc, out_len);
}

int nodus_t1_store_value(uint32_t txn, const nodus_value_t *val,
                          uint8_t *buf, size_t cap, size_t *out_len) {
    /* Serialize the value separately */
    uint8_t *vbuf = NULL;
    size_t vlen = 0;
    if (nodus_value_serialize(val, &vbuf, &vlen) != 0)
        return -1;

    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    encode_envelope(&enc, 4, txn, 'q', "sv");
    cbor_encode_cstr(&enc, "a");
    cbor_encode_map(&enc, 1);
    cbor_encode_cstr(&enc, "val");
    cbor_encode_bstr(&enc, vbuf, vlen);

    free(vbuf);
    return finish(&enc, out_len);
}

int nodus_t1_store_ack(uint32_t txn,
                        uint8_t *buf, size_t cap, size_t *out_len) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    encode_envelope(&enc, 4, txn, 'r', "sv_ack");
    cbor_encode_cstr(&enc, "r");
    cbor_encode_map(&enc, 0);
    return finish(&enc, out_len);
}

int nodus_t1_find_value(uint32_t txn, const nodus_key_t *key,
                         uint8_t *buf, size_t cap, size_t *out_len) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    encode_envelope(&enc, 4, txn, 'q', "fv");
    cbor_encode_cstr(&enc, "a");
    cbor_encode_map(&enc, 1);
    cbor_encode_cstr(&enc, "k");
    cbor_encode_bstr(&enc, key->bytes, NODUS_KEY_BYTES);
    return finish(&enc, out_len);
}

int nodus_t1_value_found(uint32_t txn, const nodus_value_t *val,
                          uint8_t *buf, size_t cap, size_t *out_len) {
    uint8_t *vbuf = NULL;
    size_t vlen = 0;
    if (nodus_value_serialize(val, &vbuf, &vlen) != 0)
        return -1;

    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    encode_envelope(&enc, 4, txn, 'r', "fv_r");
    cbor_encode_cstr(&enc, "r");
    cbor_encode_map(&enc, 1);
    cbor_encode_cstr(&enc, "val");
    cbor_encode_bstr(&enc, vbuf, vlen);

    free(vbuf);
    return finish(&enc, out_len);
}

int nodus_t1_value_not_found(uint32_t txn, const nodus_peer_t *peers, int count,
                              uint8_t *buf, size_t cap, size_t *out_len) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    encode_envelope(&enc, 4, txn, 'r', "fv_r");
    cbor_encode_cstr(&enc, "r");
    cbor_encode_map(&enc, 1);
    cbor_encode_cstr(&enc, "nodes");
    encode_peers(&enc, peers, count);
    return finish(&enc, out_len);
}

int nodus_t1_subscribe(uint32_t txn, const nodus_key_t *key,
                        uint8_t *buf, size_t cap, size_t *out_len) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    encode_envelope(&enc, 4, txn, 'q', "sub");
    cbor_encode_cstr(&enc, "a");
    cbor_encode_map(&enc, 1);
    cbor_encode_cstr(&enc, "k");
    cbor_encode_bstr(&enc, key->bytes, NODUS_KEY_BYTES);
    return finish(&enc, out_len);
}

int nodus_t1_unsubscribe(uint32_t txn, const nodus_key_t *key,
                          uint8_t *buf, size_t cap, size_t *out_len) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    encode_envelope(&enc, 4, txn, 'q', "unsub");
    cbor_encode_cstr(&enc, "a");
    cbor_encode_map(&enc, 1);
    cbor_encode_cstr(&enc, "k");
    cbor_encode_bstr(&enc, key->bytes, NODUS_KEY_BYTES);
    return finish(&enc, out_len);
}

int nodus_t1_notify(uint32_t txn, const nodus_key_t *key,
                     const nodus_value_t *val,
                     uint8_t *buf, size_t cap, size_t *out_len) {
    uint8_t *vbuf = NULL;
    size_t vlen = 0;
    if (nodus_value_serialize(val, &vbuf, &vlen) != 0)
        return -1;

    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    encode_envelope(&enc, 4, txn, 'q', "ntf");
    cbor_encode_cstr(&enc, "a");
    cbor_encode_map(&enc, 2);
    cbor_encode_cstr(&enc, "k");
    cbor_encode_bstr(&enc, key->bytes, NODUS_KEY_BYTES);
    cbor_encode_cstr(&enc, "val");
    cbor_encode_bstr(&enc, vbuf, vlen);

    free(vbuf);
    return finish(&enc, out_len);
}

/* ── Decode ──────────────────────────────────────────────────────── */

static int decode_peers(cbor_decoder_t *dec, nodus_peer_t *peers,
                         int max, int *count) {
    cbor_item_t item = cbor_decode_next(dec);
    if (item.type != CBOR_ITEM_ARRAY) return -1;

    int n = (int)item.count;
    if (n > max) n = max;
    *count = 0;

    for (int i = 0; i < (int)item.count; i++) {
        cbor_item_t map_item = cbor_decode_next(dec);
        if (map_item.type != CBOR_ITEM_MAP) return -1;

        nodus_peer_t p;
        memset(&p, 0, sizeof(p));

        for (size_t j = 0; j < map_item.count; j++) {
            cbor_item_t key = cbor_decode_next(dec);
            if (key.type != CBOR_ITEM_TSTR) { cbor_decode_skip(dec); continue; }

            if (key.tstr.len == 2 && memcmp(key.tstr.ptr, "id", 2) == 0) {
                cbor_item_t val = cbor_decode_next(dec);
                if (val.type == CBOR_ITEM_BSTR && val.bstr.len == NODUS_KEY_BYTES)
                    memcpy(p.node_id.bytes, val.bstr.ptr, NODUS_KEY_BYTES);
            } else if (key.tstr.len == 2 && memcmp(key.tstr.ptr, "ip", 2) == 0) {
                cbor_item_t val = cbor_decode_next(dec);
                if (val.type == CBOR_ITEM_TSTR) {
                    size_t clen = val.tstr.len < sizeof(p.ip) - 1 ?
                                  val.tstr.len : sizeof(p.ip) - 1;
                    memcpy(p.ip, val.tstr.ptr, clen);
                    p.ip[clen] = '\0';
                }
            } else if (key.tstr.len == 2 && memcmp(key.tstr.ptr, "up", 2) == 0) {
                cbor_item_t val = cbor_decode_next(dec);
                if (val.type == CBOR_ITEM_UINT)
                    p.udp_port = (uint16_t)val.uint_val;
            } else if (key.tstr.len == 2 && memcmp(key.tstr.ptr, "tp", 2) == 0) {
                cbor_item_t val = cbor_decode_next(dec);
                if (val.type == CBOR_ITEM_UINT)
                    p.tcp_port = (uint16_t)val.uint_val;
            } else {
                cbor_decode_skip(dec);
            }
        }

        if (i < max)
            peers[(*count)++] = p;
    }
    return 0;
}

int nodus_t1_decode(const uint8_t *buf, size_t len, nodus_tier1_msg_t *msg) {
    if (!buf || !msg) return -1;
    memset(msg, 0, sizeof(*msg));

    cbor_decoder_t dec;
    cbor_decoder_init(&dec, buf, len);

    cbor_item_t top = cbor_decode_next(&dec);
    if (top.type != CBOR_ITEM_MAP) return -1;
    size_t map_count = top.count;

    for (size_t i = 0; i < map_count; i++) {
        cbor_item_t key = cbor_decode_next(&dec);
        if (key.type != CBOR_ITEM_TSTR) { cbor_decode_skip(&dec); continue; }

        /* "t" → transaction ID */
        if (key.tstr.len == 1 && key.tstr.ptr[0] == 't') {
            cbor_item_t val = cbor_decode_next(&dec);
            if (val.type == CBOR_ITEM_UINT)
                msg->txn_id = (uint32_t)val.uint_val;
        }
        /* "y" → type (q/r/e) */
        else if (key.tstr.len == 1 && key.tstr.ptr[0] == 'y') {
            cbor_item_t val = cbor_decode_next(&dec);
            if (val.type == CBOR_ITEM_TSTR && val.tstr.len >= 1)
                msg->type = val.tstr.ptr[0];
        }
        /* "q" → method name */
        else if (key.tstr.len == 1 && key.tstr.ptr[0] == 'q') {
            cbor_item_t val = cbor_decode_next(&dec);
            if (val.type == CBOR_ITEM_TSTR) {
                size_t clen = val.tstr.len < sizeof(msg->method) - 1 ?
                              val.tstr.len : sizeof(msg->method) - 1;
                memcpy(msg->method, val.tstr.ptr, clen);
                msg->method[clen] = '\0';
            }
        }
        /* "a" → arguments (query) */
        else if (key.tstr.len == 1 && key.tstr.ptr[0] == 'a') {
            cbor_item_t args = cbor_decode_next(&dec);
            if (args.type != CBOR_ITEM_MAP) continue;

            for (size_t j = 0; j < args.count; j++) {
                cbor_item_t akey = cbor_decode_next(&dec);
                if (akey.type != CBOR_ITEM_TSTR) {
                    cbor_decode_skip(&dec); continue;
                }

                if (akey.tstr.len == 2 && memcmp(akey.tstr.ptr, "id", 2) == 0) {
                    cbor_item_t val = cbor_decode_next(&dec);
                    if (val.type == CBOR_ITEM_BSTR && val.bstr.len == NODUS_KEY_BYTES)
                        memcpy(msg->node_id.bytes, val.bstr.ptr, NODUS_KEY_BYTES);
                } else if ((akey.tstr.len == 6 && memcmp(akey.tstr.ptr, "target", 6) == 0) ||
                           (akey.tstr.len == 1 && akey.tstr.ptr[0] == 'k')) {
                    cbor_item_t val = cbor_decode_next(&dec);
                    if (val.type == CBOR_ITEM_BSTR && val.bstr.len == NODUS_KEY_BYTES)
                        memcpy(msg->target.bytes, val.bstr.ptr, NODUS_KEY_BYTES);
                } else if (akey.tstr.len == 3 && memcmp(akey.tstr.ptr, "val", 3) == 0) {
                    cbor_item_t val = cbor_decode_next(&dec);
                    if (val.type == CBOR_ITEM_BSTR) {
                        nodus_value_deserialize(val.bstr.ptr, val.bstr.len, &msg->value);
                        msg->has_value = (msg->value != NULL);
                    }
                } else {
                    cbor_decode_skip(&dec);
                }
            }
        }
        /* "r" → results (response) */
        else if (key.tstr.len == 1 && key.tstr.ptr[0] == 'r') {
            cbor_item_t res = cbor_decode_next(&dec);
            if (res.type != CBOR_ITEM_MAP) continue;

            for (size_t j = 0; j < res.count; j++) {
                cbor_item_t rkey = cbor_decode_next(&dec);
                if (rkey.type != CBOR_ITEM_TSTR) {
                    cbor_decode_skip(&dec); continue;
                }

                if (rkey.tstr.len == 2 && memcmp(rkey.tstr.ptr, "id", 2) == 0) {
                    cbor_item_t val = cbor_decode_next(&dec);
                    if (val.type == CBOR_ITEM_BSTR && val.bstr.len == NODUS_KEY_BYTES)
                        memcpy(msg->node_id.bytes, val.bstr.ptr, NODUS_KEY_BYTES);
                } else if (rkey.tstr.len == 5 && memcmp(rkey.tstr.ptr, "nodes", 5) == 0) {
                    decode_peers(&dec, msg->peers, NODUS_T1_MAX_PEERS, &msg->peer_count);
                } else if (rkey.tstr.len == 3 && memcmp(rkey.tstr.ptr, "val", 3) == 0) {
                    cbor_item_t val = cbor_decode_next(&dec);
                    if (val.type == CBOR_ITEM_BSTR) {
                        nodus_value_deserialize(val.bstr.ptr, val.bstr.len, &msg->value);
                        msg->has_value = (msg->value != NULL);
                    }
                } else {
                    cbor_decode_skip(&dec);
                }
            }
        }
        else {
            cbor_decode_skip(&dec);
        }
    }

    return dec.error ? -1 : 0;
}

void nodus_t1_msg_free(nodus_tier1_msg_t *msg) {
    if (!msg) return;
    if (msg->value) {
        nodus_value_free(msg->value);
        msg->value = NULL;
    }
}
