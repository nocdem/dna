/**
 * Nodus — DHT IPC frames (component split S5b)
 *
 * The encoders and the ONE strict decoder of the storage.sock control
 * plane (prefaces and control messages), linked by both ends: core's IPC
 * DHT backend (server/nodus_dht_backend_ipc.c) and the nodus-storage
 * runtime (dht/nodus_dht_ipc.c). Pure functions of their arguments — no
 * state, no I/O, no clock. Formats: dht/nodus_dht_ipc.h.
 *
 * @file nodus_dht_ipc_wire.c
 */

#include "dht/nodus_dht_ipc.h"
#include "protocol/nodus_cbor.h"

#include <string.h>

/* ── Encoders ────────────────────────────────────────────────────── */

static size_t enc_done(const cbor_encoder_t *enc) {
    return enc->error ? 0 : cbor_encoder_len(enc);
}

size_t nodus_dht_ipc_encode_origin(const nodus_dht_ipc_preface_t *pf,
                                   uint8_t *buf, size_t cap) {
    if (!pf || !buf) return 0;
    bool client = pf->origin.kind == NODUS_DHT_ORIGIN_CLIENT;
    if (pf->origin.slot < 0) return 0;
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    cbor_encode_map(&enc, 8);
    cbor_encode_cstr(&enc, "q");  cbor_encode_cstr(&enc, NODUS_DHT_IPC_Q_ORIGIN);
    cbor_encode_cstr(&enc, "v");  cbor_encode_uint(&enc, NODUS_DHT_IPC_VERSION);
    cbor_encode_cstr(&enc, "k");  cbor_encode_uint(&enc, client ? 0 : 1);
    cbor_encode_cstr(&enc, "s");  cbor_encode_uint(&enc, (uint64_t)pf->origin.slot);
    cbor_encode_cstr(&enc, "g");  cbor_encode_uint(&enc, pf->origin.gen);
    cbor_encode_cstr(&enc, "b");  cbor_encode_bstr(&enc, pf->boot, NODUS_DHT_IPC_BOOT_LEN);
    cbor_encode_cstr(&enc, "fp"); cbor_encode_bstr(&enc, pf->fp.bytes, NODUS_KEY_BYTES);
    if (client) {
        cbor_encode_cstr(&enc, "pk");
        cbor_encode_bstr(&enc, pf->pk.bytes, NODUS_PK_BYTES);
    } else {
        cbor_encode_cstr(&enc, "ip");
        cbor_encode_cstr(&enc, pf->ip);
    }
    return enc_done(&enc);
}

size_t nodus_dht_ipc_encode_ctl(const uint8_t boot[NODUS_DHT_IPC_BOOT_LEN],
                                uint8_t *buf, size_t cap) {
    if (!boot || !buf) return 0;
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    cbor_encode_map(&enc, 3);
    cbor_encode_cstr(&enc, "q"); cbor_encode_cstr(&enc, NODUS_DHT_IPC_Q_CTL);
    cbor_encode_cstr(&enc, "v"); cbor_encode_uint(&enc, NODUS_DHT_IPC_VERSION);
    cbor_encode_cstr(&enc, "b"); cbor_encode_bstr(&enc, boot, NODUS_DHT_IPC_BOOT_LEN);
    return enc_done(&enc);
}

size_t nodus_dht_ipc_encode_udp(const char *q, const char *ip, uint16_t port,
                                const uint8_t *payload, size_t len,
                                uint8_t *buf, size_t cap) {
    if (!q || !ip || !payload || !buf) return 0;
    if (strcmp(q, NODUS_DHT_IPC_Q_UDP_IN) != 0 &&
        strcmp(q, NODUS_DHT_IPC_Q_UDP_OUT) != 0)
        return 0;
    if (strlen(ip) >= 64) return 0;
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    cbor_encode_map(&enc, 4);
    cbor_encode_cstr(&enc, "q");  cbor_encode_cstr(&enc, q);
    cbor_encode_cstr(&enc, "ip"); cbor_encode_cstr(&enc, ip);
    cbor_encode_cstr(&enc, "po"); cbor_encode_uint(&enc, port);
    cbor_encode_cstr(&enc, "p");  cbor_encode_bstr(&enc, payload, len);
    return enc_done(&enc);
}

size_t nodus_dht_ipc_encode_seen(nodus_dht_peer_seen_t kind,
                                 const nodus_key_t *node_id, const char *ip,
                                 uint16_t udp_port, uint16_t tcp_port,
                                 uint8_t *buf, size_t cap) {
    if (!node_id || !ip || !buf || strlen(ip) >= 64) return 0;
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    cbor_encode_map(&enc, 6);
    cbor_encode_cstr(&enc, "q");  cbor_encode_cstr(&enc, NODUS_DHT_IPC_Q_SEEN);
    cbor_encode_cstr(&enc, "k");  cbor_encode_uint(&enc, (uint64_t)kind);
    cbor_encode_cstr(&enc, "id"); cbor_encode_bstr(&enc, node_id->bytes, NODUS_KEY_BYTES);
    cbor_encode_cstr(&enc, "ip"); cbor_encode_cstr(&enc, ip);
    cbor_encode_cstr(&enc, "up"); cbor_encode_uint(&enc, udp_port);
    cbor_encode_cstr(&enc, "tp"); cbor_encode_uint(&enc, tcp_port);
    return enc_done(&enc);
}

size_t nodus_dht_ipc_encode_dead(const nodus_key_t *node_id,
                                 uint8_t *buf, size_t cap) {
    if (!node_id || !buf) return 0;
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    cbor_encode_map(&enc, 2);
    cbor_encode_cstr(&enc, "q");  cbor_encode_cstr(&enc, NODUS_DHT_IPC_Q_DEAD);
    cbor_encode_cstr(&enc, "id"); cbor_encode_bstr(&enc, node_id->bytes, NODUS_KEY_BYTES);
    return enc_done(&enc);
}

size_t nodus_dht_ipc_encode_members(const nodus_dht_ipc_member_t *m, int n,
                                    uint8_t *buf, size_t cap) {
    if (!buf || n < 0 || n > NODUS_DHT_IPC_MEMBERS_MAX || (n > 0 && !m))
        return 0;
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    cbor_encode_map(&enc, 2);
    cbor_encode_cstr(&enc, "q"); cbor_encode_cstr(&enc, NODUS_DHT_IPC_Q_MEMBERS);
    cbor_encode_cstr(&enc, "m");
    cbor_encode_array(&enc, (size_t)n);
    for (int i = 0; i < n; i++) {
        cbor_encode_array(&enc, 2);
        cbor_encode_bstr(&enc, m[i].node_id.bytes, NODUS_KEY_BYTES);
        cbor_encode_uint(&enc, m[i].offline_secs);
    }
    return enc_done(&enc);
}

size_t nodus_dht_ipc_encode_routing(const nodus_dht_peer_addr_t *r, int n,
                                    uint8_t *buf, size_t cap) {
    if (!buf || n < 0 || n > NODUS_DHT_IPC_ROUTING_MAX || (n > 0 && !r))
        return 0;
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    cbor_encode_map(&enc, 2);
    cbor_encode_cstr(&enc, "q"); cbor_encode_cstr(&enc, NODUS_DHT_IPC_Q_ROUTING);
    cbor_encode_cstr(&enc, "r");
    cbor_encode_array(&enc, (size_t)n);
    for (int i = 0; i < n; i++) {
        if (strnlen(r[i].ip, sizeof(r[i].ip)) >= sizeof(r[i].ip)) return 0;
        cbor_encode_array(&enc, 3);
        cbor_encode_bstr(&enc, r[i].node_id.bytes, NODUS_KEY_BYTES);
        cbor_encode_cstr(&enc, r[i].ip);
        cbor_encode_uint(&enc, r[i].tcp_port);
    }
    return enc_done(&enc);
}

/* ── The decoder ─────────────────────────────────────────────────── */

/* Keys, one bit each. */
enum {
    K_Q  = 1u << 0,  K_V  = 1u << 1,  K_K  = 1u << 2,  K_S  = 1u << 3,
    K_G  = 1u << 4,  K_B  = 1u << 5,  K_FP = 1u << 6,  K_PK = 1u << 7,
    K_IP = 1u << 8,  K_PO = 1u << 9,  K_P  = 1u << 10, K_ID = 1u << 11,
    K_UP = 1u << 12, K_TP = 1u << 13, K_M  = 1u << 14, K_R  = 1u << 15
};

static bool key_is(const cbor_item_t *k, const char *s) {
    size_t n = strlen(s);
    return k->tstr.len == n && memcmp(k->tstr.ptr, s, n) == 0;
}

static bool copy_tstr(const cbor_item_t *v, char *out, size_t cap) {
    if (v->type != CBOR_ITEM_TSTR || v->tstr.len >= cap) return false;
    /* No NUL inside: it is used as a C string. */
    if (memchr(v->tstr.ptr, '\0', v->tstr.len) != NULL) return false;
    memcpy(out, v->tstr.ptr, v->tstr.len);
    out[v->tstr.len] = '\0';
    return true;
}

static bool copy_bstr(const cbor_item_t *v, uint8_t *out, size_t len) {
    if (v->type != CBOR_ITEM_BSTR || v->bstr.len != len) return false;
    memcpy(out, v->bstr.ptr, len);
    return true;
}

static bool get_u16(const cbor_item_t *v, uint16_t *out) {
    if (v->type != CBOR_ITEM_UINT || v->uint_val > UINT16_MAX) return false;
    *out = (uint16_t)v->uint_val;
    return true;
}

static int decode_members(cbor_decoder_t *dec, const cbor_item_t *arr,
                          nodus_dht_ipc_msg_t *out) {
    if (arr->type != CBOR_ITEM_ARRAY ||
        arr->count > NODUS_DHT_IPC_MEMBERS_MAX)
        return -1;
    for (size_t i = 0; i < arr->count; i++) {
        cbor_item_t e = cbor_decode_next(dec);
        if (e.type != CBOR_ITEM_ARRAY || e.count != 2) return -1;
        cbor_item_t id = cbor_decode_next(dec);
        cbor_item_t off = cbor_decode_next(dec);
        if (!copy_bstr(&id, out->members[i].node_id.bytes, NODUS_KEY_BYTES) ||
            off.type != CBOR_ITEM_UINT)
            return -1;
        out->members[i].offline_secs = off.uint_val;
    }
    out->member_count = (int)arr->count;
    return 0;
}

static int decode_routing(cbor_decoder_t *dec, const cbor_item_t *arr,
                          nodus_dht_ipc_msg_t *out,
                          nodus_dht_peer_addr_t *rt, int rt_max) {
    if (arr->type != CBOR_ITEM_ARRAY || !rt || rt_max < 0 ||
        arr->count > (size_t)rt_max || arr->count > NODUS_DHT_IPC_ROUTING_MAX)
        return -1;
    for (size_t i = 0; i < arr->count; i++) {
        cbor_item_t e = cbor_decode_next(dec);
        if (e.type != CBOR_ITEM_ARRAY || e.count != 3) return -1;
        cbor_item_t id = cbor_decode_next(dec);
        cbor_item_t ip = cbor_decode_next(dec);
        cbor_item_t tp = cbor_decode_next(dec);
        memset(&rt[i], 0, sizeof(rt[i]));
        if (!copy_bstr(&id, rt[i].node_id.bytes, NODUS_KEY_BYTES) ||
            !copy_tstr(&ip, rt[i].ip, sizeof(rt[i].ip)) ||
            !get_u16(&tp, &rt[i].tcp_port))
            return -1;
    }
    out->routing_count = (int)arr->count;
    return 0;
}

int nodus_dht_ipc_decode(const uint8_t *p, size_t len, nodus_dht_ipc_msg_t *out,
                         nodus_dht_peer_addr_t *rt, int rt_max) {
    if (!out) return -1;
    memset(out, 0, sizeof(*out));
    if (!p || len == 0) return -1;

    cbor_decoder_t dec;
    cbor_decoder_init(&dec, p, len);
    cbor_item_t m = cbor_decode_next(&dec);
    if (m.type != CBOR_ITEM_MAP || m.count == 0 || m.count > 8) return -1;

    unsigned seen = 0;
    char q[16] = {0};
    uint64_t v_ver = 0, v_kind = 0, v_slot = 0, v_gen = 0;
    nodus_dht_ipc_msg_t tmp;
    memset(&tmp, 0, sizeof(tmp));

    for (size_t i = 0; i < m.count; i++) {
        cbor_item_t k = cbor_decode_next(&dec);
        if (k.type != CBOR_ITEM_TSTR) return -1;
        unsigned bit;
        bool ok;
        if (key_is(&k, "m") || key_is(&k, "r")) {
            /* The array is decoded in place (it is the value). */
            cbor_item_t arr = cbor_decode_next(&dec);
            if (key_is(&k, "m")) {
                bit = K_M;
                ok = !(seen & bit) && decode_members(&dec, &arr, &tmp) == 0;
            } else {
                bit = K_R;
                ok = !(seen & bit) &&
                     decode_routing(&dec, &arr, &tmp, rt, rt_max) == 0;
            }
            if (!ok) return -1;
            seen |= bit;
            continue;
        }
        cbor_item_t v = cbor_decode_next(&dec);
        if (key_is(&k, "q")) {
            bit = K_Q;  ok = copy_tstr(&v, q, sizeof(q));
        } else if (key_is(&k, "v")) {
            bit = K_V;  ok = v.type == CBOR_ITEM_UINT; v_ver = v.uint_val;
        } else if (key_is(&k, "k")) {
            bit = K_K;  ok = v.type == CBOR_ITEM_UINT; v_kind = v.uint_val;
        } else if (key_is(&k, "s")) {
            bit = K_S;  ok = v.type == CBOR_ITEM_UINT; v_slot = v.uint_val;
        } else if (key_is(&k, "g")) {
            bit = K_G;  ok = v.type == CBOR_ITEM_UINT; v_gen = v.uint_val;
        } else if (key_is(&k, "b")) {
            bit = K_B;  ok = copy_bstr(&v, tmp.boot, NODUS_DHT_IPC_BOOT_LEN);
        } else if (key_is(&k, "fp")) {
            bit = K_FP; ok = copy_bstr(&v, tmp.preface.fp.bytes, NODUS_KEY_BYTES);
        } else if (key_is(&k, "pk")) {
            bit = K_PK; ok = copy_bstr(&v, tmp.preface.pk.bytes, NODUS_PK_BYTES);
        } else if (key_is(&k, "ip")) {
            bit = K_IP; ok = copy_tstr(&v, tmp.ip, sizeof(tmp.ip));
        } else if (key_is(&k, "po")) {
            bit = K_PO; ok = get_u16(&v, &tmp.port);
        } else if (key_is(&k, "p")) {
            bit = K_P;  ok = v.type == CBOR_ITEM_BSTR;
            tmp.payload = v.bstr.ptr;
            tmp.payload_len = v.bstr.len;
        } else if (key_is(&k, "id")) {
            bit = K_ID; ok = copy_bstr(&v, tmp.node_id.bytes, NODUS_KEY_BYTES);
        } else if (key_is(&k, "up")) {
            bit = K_UP; ok = get_u16(&v, &tmp.port);
        } else if (key_is(&k, "tp")) {
            bit = K_TP; ok = get_u16(&v, &tmp.tcp_port);
        } else {
            return -1;
        }
        if (!ok || (seen & bit)) return -1;
        seen |= bit;
    }
    if (dec.error || dec.pos != len || !(seen & K_Q)) return -1;

    if (strcmp(q, NODUS_DHT_IPC_Q_ORIGIN) == 0) {
        unsigned common = K_Q | K_V | K_K | K_S | K_G | K_B | K_FP;
        if (v_ver != NODUS_DHT_IPC_VERSION) return -1;
        if (v_kind == 0) {
            if (seen != (common | K_PK)) return -1;
            tmp.preface.origin.kind = NODUS_DHT_ORIGIN_CLIENT;
            if (v_slot >= NODUS_MAX_SESSIONS) return -1;
        } else if (v_kind == 1) {
            if (seen != (common | K_IP)) return -1;
            tmp.preface.origin.kind = NODUS_DHT_ORIGIN_INTER;
            if (v_slot >= NODUS_MAX_INTER_SESSIONS) return -1;
            memcpy(tmp.preface.ip, tmp.ip, sizeof(tmp.preface.ip));
        } else {
            return -1;
        }
        if (v_gen == 0) return -1;   /* 0 = a cleared slot, never a session */
        tmp.preface.origin.slot = (int)v_slot;
        tmp.preface.origin.gen = v_gen;
        memcpy(tmp.preface.boot, tmp.boot, NODUS_DHT_IPC_BOOT_LEN);
        tmp.type = NODUS_DHT_IPC_MSG_ORIGIN;
    } else if (strcmp(q, NODUS_DHT_IPC_Q_CTL) == 0) {
        if (seen != (K_Q | K_V | K_B) || v_ver != NODUS_DHT_IPC_VERSION)
            return -1;
        tmp.type = NODUS_DHT_IPC_MSG_CTL;
    } else if (strcmp(q, NODUS_DHT_IPC_Q_UDP_IN) == 0 ||
               strcmp(q, NODUS_DHT_IPC_Q_UDP_OUT) == 0) {
        if (seen != (K_Q | K_IP | K_PO | K_P)) return -1;
        tmp.type = q[6] == 's' ? NODUS_DHT_IPC_MSG_UDP_OUT
                               : NODUS_DHT_IPC_MSG_UDP_IN;
    } else if (strcmp(q, NODUS_DHT_IPC_Q_SEEN) == 0) {
        if (seen != (K_Q | K_K | K_ID | K_IP | K_UP | K_TP)) return -1;
        if (v_kind > (uint64_t)NODUS_DHT_PEER_ALIVE) return -1;
        tmp.seen_kind = (nodus_dht_peer_seen_t)v_kind;
        tmp.type = NODUS_DHT_IPC_MSG_SEEN;
    } else if (strcmp(q, NODUS_DHT_IPC_Q_DEAD) == 0) {
        if (seen != (K_Q | K_ID)) return -1;
        tmp.type = NODUS_DHT_IPC_MSG_DEAD;
    } else if (strcmp(q, NODUS_DHT_IPC_Q_MEMBERS) == 0) {
        if (seen != (K_Q | K_M)) return -1;
        tmp.type = NODUS_DHT_IPC_MSG_MEMBERS;
    } else if (strcmp(q, NODUS_DHT_IPC_Q_ROUTING) == 0) {
        if (seen != (K_Q | K_R)) return -1;
        tmp.type = NODUS_DHT_IPC_MSG_ROUTING;
    } else {
        return -1;
    }
    *out = tmp;
    return 0;
}
