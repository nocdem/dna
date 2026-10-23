/**
 * Nodus — DHT v2: the storage process's view of its local witness.
 * Contract, timing rules and the "no caller yet" note: nodus_dht2_wview.h.
 *
 * Its own nodus_tcp_t, one connection (kind `ipc_dht` of witness.sock),
 * polled with a 0 ms wait from nodus_dht2_wview_tick. Answers are decoded
 * strictly: every key exactly once with its type and size, the "q" key
 * first, no trailing byte. A malformed, unsolicited (no such request
 * outstanding) or over-long (NODUS_WITNESS_IPC_DHT_FRAME_MAX) answer closes
 * the connection — the same way the core side treats a bad ipc_status
 * answer (server/nodus_chain_backend_ipc.c).
 *
 * @file nodus_dht2_wview.c
 */

#include "dht/nodus_dht2_wview.h"
#include "transport/nodus_tcp.h"
#include "protocol/nodus_cbor.h"
#include "crypto/utils/qgp_log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LOG_TAG "DHT2_WVIEW"

typedef struct {
    bool     used;
    bool     named;          /* true = positive (permanent) */
    uint8_t  fp[64];
    uint64_t h;              /* the answer's tip height */
} wv_name_entry_t;

struct nodus_dht2_wview {
    nodus_tcp_t       tcp;
    char              path[NODUS_TCP_UNIX_PATH_MAX];
    nodus_tcp_conn_t *conn;
    uint64_t          now_ms;            /* the tick being served */

    uint64_t          next_dial_ms;
    uint64_t          backoff_ms;

    /* snapshot */
    bool              snap_out;          /* a request is outstanding */
    uint64_t          snap_sent_ms;
    bool              snap_asked;        /* snap_last_req_ms is valid */
    uint64_t          snap_last_req_ms;
    bool              snap_have;
    uint64_t          snap_at_ms;        /* tick that received the answer */
    nodus_witness_dht_snap_t snap;

    /* sets */
    bool              sets_out;
    uint64_t          sets_sent_ms;
    bool              sets_retry_set;    /* sets_retry_ms is valid */
    uint64_t          sets_retry_ms;     /* no new sets request before it */
    bool              need_sets;
    bool              sets_have;
    nodus_witness_dht_sets_t *sets;
    nodus_witness_dht_sets_t *stage;     /* decode target, swapped in */

    /* names */
    bool              name_out;
    uint64_t          name_sent_ms;
    uint8_t           name_fp[64];
    bool              fault_set;         /* an {err} answer not yet reported */
    uint8_t           fault_fp[64];
    wv_name_entry_t   cache[NODUS_DHT2_WVIEW_NAME_CACHE_MAX];
    size_t            victim;            /* round-robin when the cache is full */
};

/* ── Small helpers ────────────────────────────────────────────────── */

static bool key_is(const cbor_item_t *k, const char *s) {
    size_t n = strlen(s);
    return k->type == CBOR_ITEM_TSTR && k->tstr.len == n &&
           memcmp(k->tstr.ptr, s, n) == 0;
}

static bool snap_fresh(const nodus_dht2_wview_t *wv, uint64_t now_ms) {
    if (!wv->conn || !wv->snap_have) return false;
    return now_ms < wv->snap_at_ms ||
           now_ms - wv->snap_at_ms <= NODUS_DHT2_WVIEW_SNAP_STALE_MS;
}

/* Close the connection; nodus_tcp_disconnect runs wv_on_disconnect. */
static void wv_close(nodus_dht2_wview_t *wv, const char *why) {
    if (!wv->conn) return;
    QGP_LOG_WARN(LOG_TAG, "closing the witness connection (%s): %s",
                 wv->path, why);
    nodus_tcp_disconnect(&wv->tcp, wv->conn);
}

static int wv_send(nodus_dht2_wview_t *wv, const char *q, const uint8_t *fp) {
    uint8_t buf[NODUS_WITNESS_IPC_CTL_FRAME_MAX];
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, sizeof(buf));
    cbor_encode_map(&enc, fp ? 2 : 1);
    cbor_encode_cstr(&enc, "q");
    cbor_encode_cstr(&enc, q);
    if (fp) {
        cbor_encode_cstr(&enc, "fp");
        cbor_encode_bstr(&enc, fp, 64);
    }
    size_t n = cbor_encoder_len(&enc);
    if (n == 0 || nodus_tcp_send(wv->conn, buf, n) != 0) return -1;
    return 0;
}

/* ── Answer decoding ──────────────────────────────────────────────── */

/* After "q": either the single entry "err" (a node-local fault) or the
 * fields. @return 1 err answer, 0 fields follow, -1 malformed. */
static int wv_err_or_fields(cbor_decoder_t *dec, size_t count,
                            size_t n_fields) {
    if (count == 1 + n_fields) return 0;
    if (count != 2) return -1;
    cbor_item_t k = cbor_decode_next(dec);
    cbor_item_t v = cbor_decode_next(dec);
    if (!key_is(&k, "err") || v.type != CBOR_ITEM_TSTR) return -1;
    return 1;
}

static int wv_on_snap(nodus_dht2_wview_t *wv, cbor_decoder_t *dec,
                      size_t count) {
    enum { K_CI = 1, K_H = 2, K_T = 4, K_CU = 8, K_E = 16, K_ALL = 31 };
    if (!wv->snap_out) return -1;
    int r = wv_err_or_fields(dec, count, 5);
    if (r < 0) return -1;
    wv->snap_out = false;
    if (r == 1) {                          /* {err}: no snapshot now */
        wv->snap_have = false;
        return 0;
    }
    nodus_witness_dht_snap_t sn;
    memset(&sn, 0, sizeof(sn));
    unsigned seen = 0;
    for (size_t i = 0; i < 5; i++) {
        cbor_item_t k = cbor_decode_next(dec);
        cbor_item_t v = cbor_decode_next(dec);
        unsigned bit;
        if (key_is(&k, "ci")) {
            if (v.type != CBOR_ITEM_BSTR || v.bstr.len != sizeof(sn.chain_id))
                return -1;
            memcpy(sn.chain_id, v.bstr.ptr, sizeof(sn.chain_id));
            bit = K_CI;
        } else if (key_is(&k, "h")) {
            if (v.type != CBOR_ITEM_UINT) return -1;
            sn.height = v.uint_val;
            bit = K_H;
        } else if (key_is(&k, "t")) {
            if (v.type != CBOR_ITEM_UINT) return -1;
            sn.tip_time = v.uint_val;
            bit = K_T;
        } else if (key_is(&k, "cu")) {
            if (v.type != CBOR_ITEM_BOOL) return -1;
            sn.consensus_up = v.bool_val;
            bit = K_CU;
        } else if (key_is(&k, "e")) {
            if (v.type != CBOR_ITEM_UINT) return -1;
            sn.epoch_start = v.uint_val;
            bit = K_E;
        } else {
            return -1;
        }
        if (seen & bit) return -1;
        seen |= bit;
    }
    if (seen != K_ALL) return -1;
    wv->snap = sn;
    wv->snap_have = true;
    wv->snap_at_ms = wv->now_ms;
    /* the sets are the frozen sets of one epoch: ask again when it moved */
    if (!wv->sets_have || wv->sets->e != sn.epoch_start) wv->need_sets = true;
    return 0;
}

/* An array of exactly-64-byte byte strings, at most DNA_V2_STORAGE_SET_MAX. */
static int wv_fp_array(cbor_decoder_t *dec, uint8_t out[][64], uint32_t *n) {
    cbor_item_t a = cbor_decode_next(dec);
    if (a.type != CBOR_ITEM_ARRAY || a.count > DNA_V2_STORAGE_SET_MAX)
        return -1;
    for (size_t i = 0; i < a.count; i++) {
        cbor_item_t v = cbor_decode_next(dec);
        if (v.type != CBOR_ITEM_BSTR || v.bstr.len != 64) return -1;
        memcpy(out[i], v.bstr.ptr, 64);
    }
    *n = (uint32_t)a.count;
    return 0;
}

static int wv_on_sets(nodus_dht2_wview_t *wv, cbor_decoder_t *dec,
                      size_t count) {
    enum { K_E = 1, K_S0 = 2, K_S1 = 4, K_RG = 8, K_ALL = 15 };
    if (!wv->sets_out) return -1;
    int r = wv_err_or_fields(dec, count, 4);
    if (r < 0) return -1;
    wv->sets_out = false;
    if (r == 1) {                          /* {err}: no sets; ask again later */
        wv->sets_have = false;
        wv->sets_retry_set = true;
        wv->sets_retry_ms = wv->now_ms + NODUS_DHT2_WVIEW_SNAP_EVERY_MS;
        return 0;
    }
    nodus_witness_dht_sets_t *st = wv->stage;
    memset(st, 0, sizeof(*st));
    unsigned seen = 0;
    for (size_t i = 0; i < 4; i++) {
        cbor_item_t k = cbor_decode_next(dec);
        unsigned bit;
        if (key_is(&k, "e")) {
            cbor_item_t v = cbor_decode_next(dec);
            if (v.type != CBOR_ITEM_UINT) return -1;
            st->e = v.uint_val;
            bit = K_E;
        } else if (key_is(&k, "s0")) {
            if (wv_fp_array(dec, st->s0, &st->n0) != 0) return -1;
            bit = K_S0;
        } else if (key_is(&k, "s1")) {
            if (wv_fp_array(dec, st->s1, &st->n1) != 0) return -1;
            bit = K_S1;
        } else if (key_is(&k, "rg")) {
            cbor_item_t a = cbor_decode_next(dec);
            if (a.type != CBOR_ITEM_ARRAY || a.count > DNA_V2_STORAGE_SET_MAX)
                return -1;
            for (size_t j = 0; j < a.count; j++) {
                cbor_item_t m = cbor_decode_next(dec);
                if (m.type != CBOR_ITEM_MAP || m.count != 2) return -1;
                unsigned rseen = 0;
                for (size_t x = 0; x < 2; x++) {
                    cbor_item_t rk = cbor_decode_next(dec);
                    cbor_item_t rv = cbor_decode_next(dec);
                    if (key_is(&rk, "f") && !(rseen & 1)) {
                        if (rv.type != CBOR_ITEM_BSTR || rv.bstr.len != 64)
                            return -1;
                        memcpy(st->rg[j].fp, rv.bstr.ptr, 64);
                        rseen |= 1;
                    } else if (key_is(&rk, "st") && !(rseen & 2)) {
                        if (rv.type != CBOR_ITEM_UINT ||
                            (rv.uint_val != DNA_V2_STORAGE_ACTIVE &&
                             rv.uint_val != DNA_V2_STORAGE_EXITING))
                            return -1;
                        st->rg[j].status = (uint8_t)rv.uint_val;
                        rseen |= 2;
                    } else {
                        return -1;
                    }
                }
            }
            st->nrg = (uint32_t)a.count;
            bit = K_RG;
        } else {
            return -1;
        }
        if (seen & bit) return -1;
        seen |= bit;
    }
    if (seen != K_ALL) return -1;
    wv->stage = wv->sets;                  /* swap: the decoded set goes live */
    wv->sets = st;
    wv->sets_have = true;
    wv->need_sets = false;
    return 0;
}

/* A cache slot for `fp`: its own, else a free one, else a negative, else
 * round-robin. Deterministic in the order of answers. */
static wv_name_entry_t *wv_cache_slot(nodus_dht2_wview_t *wv,
                                      const uint8_t fp[64]) {
    size_t free_i = NODUS_DHT2_WVIEW_NAME_CACHE_MAX;
    size_t neg_i = NODUS_DHT2_WVIEW_NAME_CACHE_MAX;
    for (size_t i = 0; i < NODUS_DHT2_WVIEW_NAME_CACHE_MAX; i++) {
        wv_name_entry_t *e = &wv->cache[i];
        if (!e->used) {
            if (free_i == NODUS_DHT2_WVIEW_NAME_CACHE_MAX) free_i = i;
        } else if (memcmp(e->fp, fp, 64) == 0) {
            return e;
        } else if (!e->named && neg_i == NODUS_DHT2_WVIEW_NAME_CACHE_MAX) {
            neg_i = i;
        }
    }
    if (free_i != NODUS_DHT2_WVIEW_NAME_CACHE_MAX) return &wv->cache[free_i];
    if (neg_i != NODUS_DHT2_WVIEW_NAME_CACHE_MAX) return &wv->cache[neg_i];
    wv_name_entry_t *e = &wv->cache[wv->victim];
    wv->victim = (wv->victim + 1) % NODUS_DHT2_WVIEW_NAME_CACHE_MAX;
    return e;
}

static int wv_on_name(nodus_dht2_wview_t *wv, cbor_decoder_t *dec,
                      size_t count) {
    if (!wv->name_out) return -1;
    if (count != 3 && count != 4) return -1;
    cbor_item_t k = cbor_decode_next(dec);
    cbor_item_t fp = cbor_decode_next(dec);
    if (!key_is(&k, "fp") || fp.type != CBOR_ITEM_BSTR || fp.bstr.len != 64 ||
        memcmp(fp.bstr.ptr, wv->name_fp, 64) != 0)
        return -1;
    if (count == 3) {                      /* {fp, err}: unreadable */
        cbor_item_t ek = cbor_decode_next(dec);
        cbor_item_t ev = cbor_decode_next(dec);
        if (!key_is(&ek, "err") || ev.type != CBOR_ITEM_TSTR) return -1;
        wv->name_out = false;
        wv->fault_set = true;
        memcpy(wv->fault_fp, wv->name_fp, 64);
        return 0;
    }
    uint64_t h = 0, n = 0;
    unsigned seen = 0;
    for (size_t i = 0; i < 2; i++) {
        cbor_item_t fk = cbor_decode_next(dec);
        cbor_item_t fv = cbor_decode_next(dec);
        if (key_is(&fk, "h") && !(seen & 1) && fv.type == CBOR_ITEM_UINT) {
            h = fv.uint_val;
            seen |= 1;
        } else if (key_is(&fk, "n") && !(seen & 2) &&
                   fv.type == CBOR_ITEM_UINT && fv.uint_val <= 1) {
            n = fv.uint_val;
            seen |= 2;
        } else {
            return -1;
        }
    }
    if (seen != 3) return -1;
    wv->name_out = false;
    wv_name_entry_t *e = wv_cache_slot(wv, wv->name_fp);
    e->used = true;
    e->named = (n == 1);
    memcpy(e->fp, wv->name_fp, 64);
    e->h = h;
    return 0;
}

/* One answer frame. @return 0 / -1 (close the connection). */
static int wv_decode(nodus_dht2_wview_t *wv, const uint8_t *p, size_t len) {
    cbor_decoder_t dec;
    cbor_decoder_init(&dec, p, len);
    cbor_item_t m = cbor_decode_next(&dec);
    if (m.type != CBOR_ITEM_MAP || m.count < 2 || m.count > 6) return -1;
    cbor_item_t k = cbor_decode_next(&dec);
    cbor_item_t q = cbor_decode_next(&dec);
    if (!key_is(&k, "q") || q.type != CBOR_ITEM_TSTR) return -1;

    int rc;
    if (q.tstr.len == strlen(NODUS_WITNESS_IPC_Q_DHT_SNAP) &&
        memcmp(q.tstr.ptr, NODUS_WITNESS_IPC_Q_DHT_SNAP, q.tstr.len) == 0)
        rc = wv_on_snap(wv, &dec, m.count);
    else if (q.tstr.len == strlen(NODUS_WITNESS_IPC_Q_DHT_SETS) &&
             memcmp(q.tstr.ptr, NODUS_WITNESS_IPC_Q_DHT_SETS, q.tstr.len) == 0)
        rc = wv_on_sets(wv, &dec, m.count);
    else if (q.tstr.len == strlen(NODUS_WITNESS_IPC_Q_NAME) &&
             memcmp(q.tstr.ptr, NODUS_WITNESS_IPC_Q_NAME, q.tstr.len) == 0)
        rc = wv_on_name(wv, &dec, m.count);
    else
        return -1;
    if (rc != 0 || dec.error || dec.pos != len) return -1;
    return 0;
}

/* ── Transport callbacks ──────────────────────────────────────────── */

static void wv_on_frame(nodus_tcp_conn_t *conn, const uint8_t *payload,
                        size_t len, void *ctx) {
    nodus_dht2_wview_t *wv = (nodus_dht2_wview_t *)ctx;
    if (conn != wv->conn) return;
    if (len > NODUS_WITNESS_IPC_DHT_FRAME_MAX) {
        wv_close(wv, "answer over NODUS_WITNESS_IPC_DHT_FRAME_MAX");
        return;
    }
    if (wv_decode(wv, payload, len) != 0)
        wv_close(wv, "malformed or unsolicited answer");
}

static void wv_on_disconnect(nodus_tcp_conn_t *conn, void *ctx) {
    nodus_dht2_wview_t *wv = (nodus_dht2_wview_t *)ctx;
    if (conn != wv->conn) return;
    wv->conn = NULL;
    /* nothing answered on a dead connection counts */
    wv->snap_out = wv->sets_out = wv->name_out = false;
    wv->snap_have = false;
    wv->sets_have = false;
    wv->need_sets = false;
    wv->sets_retry_set = false;
    wv->snap_asked = false;
    wv->fault_set = false;
    wv->next_dial_ms = wv->now_ms + wv->backoff_ms;
}

/* ── API ──────────────────────────────────────────────────────────── */

nodus_dht2_wview_t *nodus_dht2_wview_new(const char *sock_path) {
    if (!sock_path || strlen(sock_path) >= NODUS_TCP_UNIX_PATH_MAX) return NULL;
    nodus_dht2_wview_t *wv = calloc(1, sizeof(*wv));
    if (!wv) return NULL;
    wv->sets = calloc(1, sizeof(*wv->sets));
    wv->stage = calloc(1, sizeof(*wv->stage));
    if (!wv->sets || !wv->stage || nodus_tcp_init(&wv->tcp, -1) != 0) {
        free(wv->sets);
        free(wv->stage);
        free(wv);
        return NULL;
    }
    snprintf(wv->path, sizeof(wv->path), "%s", sock_path);
    wv->tcp.on_frame      = wv_on_frame;
    wv->tcp.on_disconnect = wv_on_disconnect;
    wv->tcp.cb_ctx        = wv;
    wv->backoff_ms = NODUS_DHT2_WVIEW_DIAL_BACKOFF_MIN_MS;
    return wv;
}

static void wv_dial(nodus_dht2_wview_t *wv) {
    if (wv->now_ms < wv->next_dial_ms) return;
    nodus_tcp_conn_t *c = nodus_tcp_unix_connect(&wv->tcp, wv->path,
                                                 NODUS_TCP_UNIX_UID_SELF);
    if (!c) {
        wv->next_dial_ms = wv->now_ms + wv->backoff_ms;
        wv->backoff_ms *= 2;
        if (wv->backoff_ms > NODUS_DHT2_WVIEW_DIAL_BACKOFF_MAX_MS)
            wv->backoff_ms = NODUS_DHT2_WVIEW_DIAL_BACKOFF_MAX_MS;
        return;
    }
    wv->conn = c;
    wv->backoff_ms = NODUS_DHT2_WVIEW_DIAL_BACKOFF_MIN_MS;
    wv->snap_out = wv->sets_out = wv->name_out = false;
    wv->snap_have = false;
    wv->sets_have = false;
    wv->sets_retry_set = false;
    wv->snap_asked = false;
    wv->fault_set = false;
    wv->need_sets = true;              /* "requested at start" (row 13) */
    QGP_LOG_INFO(LOG_TAG, "connection to the witness up (%s)", wv->path);
    if (wv_send(wv, NODUS_WITNESS_IPC_Q_DHT, NULL) != 0)
        wv_close(wv, "the ipc_dht preface could not be queued");
}

void nodus_dht2_wview_tick(nodus_dht2_wview_t *wv, uint64_t now_ms) {
    if (!wv) return;
    wv->now_ms = now_ms;
    if (!wv->conn) wv_dial(wv);
    if (!wv->conn) return;
    nodus_tcp_poll(&wv->tcp, 0);
    if (!wv->conn) return;

    /* a request unanswered for the timeout closes the connection */
    if ((wv->snap_out && now_ms - wv->snap_sent_ms >= NODUS_DHT2_WVIEW_REQ_TIMEOUT_MS) ||
        (wv->sets_out && now_ms - wv->sets_sent_ms >= NODUS_DHT2_WVIEW_REQ_TIMEOUT_MS) ||
        (wv->name_out && now_ms - wv->name_sent_ms >= NODUS_DHT2_WVIEW_REQ_TIMEOUT_MS)) {
        wv_close(wv, "a request timed out");
        return;
    }

    if (!wv->snap_out && (!wv->snap_asked ||
        now_ms - wv->snap_last_req_ms >= NODUS_DHT2_WVIEW_SNAP_EVERY_MS)) {
        if (wv_send(wv, NODUS_WITNESS_IPC_Q_DHT_SNAP, NULL) != 0) {
            wv_close(wv, "ipc_dht_snap could not be queued");
            return;
        }
        wv->snap_out = true;
        wv->snap_sent_ms = now_ms;
        wv->snap_asked = true;
        wv->snap_last_req_ms = now_ms;
    }
    if (wv->need_sets && !wv->sets_out &&
        (!wv->sets_retry_set || now_ms >= wv->sets_retry_ms)) {
        if (wv_send(wv, NODUS_WITNESS_IPC_Q_DHT_SETS, NULL) != 0) {
            wv_close(wv, "ipc_dht_sets could not be queued");
            return;
        }
        wv->sets_out = true;
        wv->sets_sent_ms = now_ms;
    }
}

bool nodus_dht2_wview_snap(const nodus_dht2_wview_t *wv, uint64_t now_ms,
                           nodus_witness_dht_snap_t *out) {
    if (!wv || !out || !snap_fresh(wv, now_ms)) return false;
    *out = wv->snap;
    return true;
}

const nodus_witness_dht_sets_t *nodus_dht2_wview_sets(
        const nodus_dht2_wview_t *wv, uint64_t now_ms) {
    if (!wv || !wv->sets_have || !snap_fresh(wv, now_ms) ||
        wv->sets->e != wv->snap.epoch_start)
        return NULL;
    return wv->sets;
}

nodus_dht2_wview_name_t nodus_dht2_wview_name(nodus_dht2_wview_t *wv,
                                              uint64_t now_ms,
                                              const uint8_t fp[64],
                                              uint64_t *h_out) {
    if (!wv || !fp) return NODUS_DHT2_WVIEW_NAME_UNAVAILABLE;
    if (wv->fault_set && memcmp(wv->fault_fp, fp, 64) == 0) {
        wv->fault_set = false;
        return NODUS_DHT2_WVIEW_NAME_FAULT;
    }
    for (size_t i = 0; i < NODUS_DHT2_WVIEW_NAME_CACHE_MAX; i++) {
        const wv_name_entry_t *e = &wv->cache[i];
        if (!e->used || memcmp(e->fp, fp, 64) != 0) continue;
        if (e->named) {                    /* names are permanent */
            if (h_out) *h_out = e->h;
            return NODUS_DHT2_WVIEW_NAME_NAMED;
        }
        /* a negative holds until the chain's h moves past the answer's */
        if (snap_fresh(wv, now_ms) && wv->snap.height <= e->h) {
            if (h_out) *h_out = e->h;
            return NODUS_DHT2_WVIEW_NAME_UNNAMED;
        }
        break;
    }
    if (!wv->conn) return NODUS_DHT2_WVIEW_NAME_UNAVAILABLE;
    if (wv->name_out) return NODUS_DHT2_WVIEW_NAME_PENDING;
    if (wv_send(wv, NODUS_WITNESS_IPC_Q_NAME, fp) != 0) {
        wv->now_ms = now_ms;
        wv_close(wv, "ipc_name could not be queued");
        return NODUS_DHT2_WVIEW_NAME_UNAVAILABLE;
    }
    wv->name_out = true;
    wv->name_sent_ms = now_ms;
    memcpy(wv->name_fp, fp, 64);
    return NODUS_DHT2_WVIEW_NAME_PENDING;
}

bool nodus_dht2_wview_connected(const nodus_dht2_wview_t *wv) {
    return wv && wv->conn != NULL;
}

void nodus_dht2_wview_free(nodus_dht2_wview_t *wv) {
    if (!wv) return;
    nodus_tcp_close(&wv->tcp);
    free(wv->sets);
    free(wv->stage);
    free(wv);
}
