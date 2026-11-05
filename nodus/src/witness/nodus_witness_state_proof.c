/**
 * @file nodus_witness_state_proof.c
 * @brief HF-9 WP6 - the state proof service. Contract, references and the
 *        limits rule: nodus_witness_state_proof.h.
 */
#include "witness/nodus_witness_state_proof.h"

#include "witness/nodus_witness_roots_v2.h"
#include "witness/nodus_witness_v2_produce.h"   /* nodus_witness_v2_tip_height */
#include "witness/nodus_witness_v2_apply.h"     /* committed_global_root       */
#include "protocol/nodus_cbor.h"
#include "protocol/nodus_tier2.h"             /* nodus_t2_error */
#include "transport/nodus_tcp.h"             /* slot, generation, send */
#include "nodus/nodus_types.h"                  /* NODUS_ERR_*, frame ceiling  */
#include "dnac/ledger_roots_v2.h"
#include "dnac/ledger_ids.h"
#include "evm/trie/evm_trie_proof.h"
#include "crypto/hash/qgp_sha3.h"
#include "crypto/utils/qgp_log.h"

#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LOG_TAG "STATE-PROOF"

static int fail(int *ec, char *em, size_t cap, int code, const char *msg)
{
    if (ec) *ec = code;
    if (em && cap) snprintf(em, cap, "%s", msg);
    if (code == NODUS_ERR_INTERNAL_ERROR)
        QGP_LOG_WARN(LOG_TAG, "dnac_state_proof: %s", msg);
    return -1;
}

/* ── the request ────────────────────────────────────────────────────── */

static int key_len_ok(int leg, size_t n)
{
    switch (leg) {
    case 1: case 2: case 3: case 5: return n == 64;
    case 4:                         return n >= 3 && n <= 36;
    case 6: case 7: case 8:         return n == 8;
    }
    return 0;
}

static int tkey(const cbor_item_t *k, const char *name)
{
    size_t n = strlen(name);
    return k->type == CBOR_ITEM_TSTR && k->tstr.len == n &&
           memcmp(k->tstr.ptr, name, n) == 0;
}

/* Skip ONE value and refuse truncation anywhere inside it (cbor_decode_skip
 * returns quietly at the end of the input, which would accept a request whose
 * last unknown argument has no value). */
static int skip_value(cbor_decoder_t *d, int depth)
{
    cbor_item_t it = cbor_decode_next(d);
    size_t left = d->pos < d->len ? d->len - d->pos : 0;
    if (it.type == CBOR_ITEM_END || it.type == CBOR_ITEM_ERROR || d->error ||
        depth > 8)
        return -1;
    if (it.type == CBOR_ITEM_ARRAY) {
        if (it.count > left) return -1;
        for (size_t j = 0; j < it.count; j++)
            if (skip_value(d, depth + 1) != 0) return -1;
    } else if (it.type == CBOR_ITEM_MAP) {
        if (it.count > left / 2) return -1;
        for (size_t j = 0; j < it.count * 2; j++)
            if (skip_value(d, depth + 1) != 0) return -1;
    }
    return 0;
}

/* Pass 1 over the "a" value: the args map's keys must be text; a "keys" array
 * above the 1..128 bound is refused at its HEADER, before any element is
 * read; everything else is skipped to its end. 0; -1 malformed; -2 the keys
 * bound. */
static int skip_args(cbor_decoder_t *d)
{
    cbor_item_t m = cbor_decode_next(d);
    if (m.type != CBOR_ITEM_MAP || d->error) return -1;
    for (size_t i = 0; i < m.count; i++) {
        cbor_item_t k = cbor_decode_next(d);
        if (k.type != CBOR_ITEM_TSTR) return -1;
        if (tkey(&k, "keys")) {
            cbor_item_t a = cbor_decode_next(d);
            if (a.type == CBOR_ITEM_END || a.type == CBOR_ITEM_ERROR ||
                d->error)
                return -1;
            if (a.type == CBOR_ITEM_ARRAY) {
                if (a.count > NODUS_STATE_PROOF_MAX_KEYS) return -2;
                for (size_t j = 0; j < a.count; j++)
                    if (skip_value(d, 1) != 0) return -1;
            } else if (a.type == CBOR_ITEM_MAP) {
                for (size_t j = 0; j < a.count * 2; j++)
                    if (skip_value(d, 1) != 0) return -1;
            }
        } else if (skip_value(d, 0) != 0) {
            return -1;
        }
    }
    return 0;
}

static int request_decode_core(const uint8_t *payload, size_t len,
                               nodus_state_proof_req_t *out,
                               int *ec, char *em, size_t cap,
                               cbor_decoder_t *decp)
{
#define dec (*decp)
    cbor_item_t top, args;
    int have_leg = 0, have_keys = 0;
    const int pe = NODUS_ERR_PROTOCOL_ERROR;

    if (!payload || !out) return fail(ec, em, cap, pe, "no request");
    memset(out, 0, sizeof(*out));
    top = cbor_decode_next(&dec);
    if (top.type != CBOR_ITEM_MAP) return fail(ec, em, cap, pe, "not a map");
    /* Pass 1: EVERY outer entry is read to its end (a truncated last
     * entry, known or unknown, refuses the request); the position of the
     * single "a" value is remembered. The generic Tier-2 skip that decoded
     * this frame before (nodus_tier2.c) returns quietly at the end of the
     * input; that leniency stays for other messages. */
    size_t a_pos = (size_t)-1;
    for (size_t i = 0; i < top.count; i++) {
        cbor_item_t k = cbor_decode_next(&dec);
        if (k.type != CBOR_ITEM_TSTR)
            return fail(ec, em, cap, pe, "truncated request");
        if (tkey(&k, "a")) {
            if (a_pos != (size_t)-1)
                return fail(ec, em, cap, pe, "args twice");
            a_pos = dec.pos;
            int sr = skip_args(&dec);
            if (sr == -2)
                return fail(ec, em, cap, pe, "keys is not one array of 1..128");
            if (sr != 0)
                return fail(ec, em, cap, pe, "malformed args map");
            continue;
        }
        if (skip_value(&dec, 0) != 0)
            return fail(ec, em, cap, pe, "truncated request");
    }
    if (a_pos == (size_t)-1) return fail(ec, em, cap, pe, "missing args map");
    /* Pass 2: the args map */
    dec.pos = a_pos;
    args = cbor_decode_next(&dec);
    if (args.type != CBOR_ITEM_MAP) return fail(ec, em, cap, pe, "missing args map");

    for (size_t i = 0; i < args.count; i++) {
        cbor_item_t k = cbor_decode_next(&dec);
        /* "short text keys" (plan §10.2): a non-text key (a container's
         * contents would otherwise be read as entries) is refused before its
         * value is touched */
        if (k.type != CBOR_ITEM_TSTR)
            return fail(ec, em, cap, pe, "an argument key is not text");
        if (tkey(&k, "leg")) {
            cbor_item_t v = cbor_decode_next(&dec);
            if (v.type != CBOR_ITEM_UINT || have_leg || v.uint_val < 1 ||
                v.uint_val > NODUS_STATE_PROOF_LEGS)
                return fail(ec, em, cap, pe, "leg is not one integer 1..8");
            out->leg = (int)v.uint_val;
            have_leg = 1;
        } else if (tkey(&k, "keys")) {
            cbor_item_t a = cbor_decode_next(&dec);
            if (a.type != CBOR_ITEM_ARRAY || have_keys || a.count < 1 ||
                a.count > NODUS_STATE_PROOF_MAX_KEYS)
                return fail(ec, em, cap, pe, "keys is not one array of 1..128");
            for (size_t j = 0; j < a.count; j++) {
                cbor_item_t b = cbor_decode_next(&dec);
                if (b.type != CBOR_ITEM_BSTR ||
                    b.bstr.len > NODUS_STATE_PROOF_KEY_MAX || b.bstr.len == 0)
                    return fail(ec, em, cap, pe, "a key is not a byte string "
                                "of 1..64 bytes");
                memcpy(out->keys[j], b.bstr.ptr, b.bstr.len);
                out->key_len[j] = b.bstr.len;
            }
            out->n_keys = a.count;
            have_keys = 1;
        } else if (skip_value(&dec, 0) != 0) {
            return fail(ec, em, cap, pe, "truncated argument value");
        }
    }
    if (dec.error || !have_leg || !have_keys)
        return fail(ec, em, cap, pe, "missing or invalid leg / keys");
    for (size_t i = 0; i < out->n_keys; i++) {
        if (!key_len_ok(out->leg, out->key_len[i]))
            return fail(ec, em, cap, pe, "a key has a length its leg cannot hold");
        for (size_t j = 0; j < i; j++)
            if (out->key_len[j] == out->key_len[i] &&
                memcmp(out->keys[j], out->keys[i], out->key_len[i]) == 0)
                return fail(ec, em, cap, pe, "a repeated key");
    }
    return 0;
#undef dec
}

/* The decoder is created here: the request is read by a decoder whose item
 * limit is the frame ceiling (no array in a frame holds more items than
 * bytes, and a raised decoder refuses a count above the bytes that remain and
 * treats END as an error, nodus_cbor.h), so an oversize "keys" array reaches
 * the explicit 1..128 bound as PROTOCOL_ERROR. */
int nodus_state_proof_request_decode_ex(const uint8_t *payload, size_t len,
                                        nodus_state_proof_req_t *out,
                                        int *ec, char *em, size_t cap,
                                        uint64_t *steps_out)
{
    cbor_decoder_t d;
    int rc;
    if (!payload || !out) return fail(ec, em, cap, NODUS_ERR_PROTOCOL_ERROR,
                                      "no request");
    cbor_decoder_init(&d, payload, len);
    cbor_decoder_set_max_items(&d, NODUS_MAX_FRAME_TCP);
    rc = request_decode_core(payload, len, out, ec, em, cap, &d);
    if (steps_out) *steps_out = d.steps;
    return rc;
}

int nodus_state_proof_request_decode(const uint8_t *payload, size_t len,
                                     nodus_state_proof_req_t *out,
                                     int *ec, char *em, size_t cap)
{
    return nodus_state_proof_request_decode_ex(payload, len, out, ec, em, cap,
                                               NULL);
}

/* ── the private context ───────────────────────────────────────────── */

nodus_witness_t *nodus_state_proof_ctx_open(const char *db_path)
{
    if (!db_path) return NULL;
    /* Heap, never stack: nodus_witness_t is multi-MB. Only `db` is used by
     * the leg readers (the nodus_witness_network_file.c precedent); the
     * runtime table stays NULL, so nodus_witness_v2_runtime_for falls back to
     * the full compiled table. */
    nodus_witness_t *w = calloc(1, sizeof(*w));
    if (!w) return NULL;
    if (sqlite3_open_v2(db_path, &w->db, SQLITE_OPEN_READONLY, NULL)
        != SQLITE_OK) {
        if (w->db) sqlite3_close(w->db);
        free(w);
        return NULL;
    }
    return w;
}

void nodus_state_proof_ctx_close(nodus_witness_t *ctx)
{
    if (!ctx) return;
    if (ctx->db) sqlite3_close(ctx->db);
    free(ctx);
}

/* ── the read-only node store of the prover (no shared counter) ────────── */

typedef struct {
    sqlite3      *db;
    sqlite3_stmt *st;
    size_t        loaded;
} ro_store_t;

static int ro_get(void *c, const uint8_t digest[64], uint8_t **rlp,
                  size_t *len)
{
    ro_store_t *s = c;
    sqlite3_reset(s->st);
    if (sqlite3_bind_blob(s->st, 1, digest, 64, SQLITE_TRANSIENT) != SQLITE_OK)
        return -2;
    int rc = sqlite3_step(s->st);
    if (rc == SQLITE_DONE) return 1;
    if (rc != SQLITE_ROW) return -2;
    int n = sqlite3_column_bytes(s->st, 0);
    /* the node-size bound BEFORE anything is allocated or copied (plan
     * §10.2: bounds are checked before allocation) */
    if (n <= 0 || n > EVM_TRIE_NODE_MAX_BYTES) return -2;
    const void *b = sqlite3_column_blob(s->st, 0);
    if (!b) return -2;
    uint8_t *cpy = malloc((size_t)n);
    if (!cpy) return -2;
    memcpy(cpy, b, (size_t)n);
    *rlp = cpy;
    *len = (size_t)n;
    s->loaded++;
    return 0;
}

static int ro_put(void *c, const uint8_t d[64], const uint8_t *r, size_t n)
{
    (void)c; (void)d; (void)r; (void)n;
    return -2;                          /* a proof never writes */
}

/* ── the response frame ───────────────────────────────────────────────── */

static void enc_cp(cbor_encoder_t *e, const dna_v2_proof_step_t *s)
{
    if (s->t == DNA_V2_PROOF_STEP_COMPOSE) {
        cbor_encode_map(e, 4);
        cbor_encode_cstr(e, "t");    cbor_encode_uint(e, s->t);
        cbor_encode_cstr(e, "tag");  cbor_encode_bstr(e, s->tag, 16);
        cbor_encode_cstr(e, "legs"); cbor_encode_array(e, s->n_legs);
        for (uint32_t k = 0; k < s->n_legs; k++)
            cbor_encode_bstr(e, s->legs[k], 64);
        cbor_encode_cstr(e, "i");    cbor_encode_uint(e, s->i);
    } else if (s->t == DNA_V2_PROOF_STEP_HEAD) {
        cbor_encode_map(e, 3);
        cbor_encode_cstr(e, "t");    cbor_encode_uint(e, s->t);
        cbor_encode_cstr(e, "head"); cbor_encode_bstr(e, s->head,
                                                      DNA_V2_DOMHEAD_ENC_LEN);
        cbor_encode_cstr(e, "luh");  cbor_encode_bstr(e, s->luh, 64);
    } else {
        cbor_encode_map(e, 5);
        cbor_encode_cstr(e, "t");    cbor_encode_uint(e, s->t);
        cbor_encode_cstr(e, "tag");  cbor_encode_bstr(e, s->tag, 16);
        cbor_encode_cstr(e, "n");    cbor_encode_uint(e, s->n);
        cbor_encode_cstr(e, "i");    cbor_encode_uint(e, s->i);
        cbor_encode_cstr(e, "sib");  cbor_encode_array(e, s->n_sib);
        for (uint32_t k = 0; k < s->n_sib; k++)
            cbor_encode_bstr(e, s->sib[k], 64);
    }
}

/* TEST SEAM (header): called inside the read transaction after the committed
 * height was read. NULL in production; set only by tests, before any build. */
static void (*g_stage_hook)(void *);
static void *g_stage_hook_ctx;

void nodus_state_proof_set_stage_hook(void (*fn)(void *), void *ctx)
{
    g_stage_hook = fn;
    g_stage_hook_ctx = ctx;
}

/* the work inside the read transaction */
static int build_snapshot(nodus_witness_t *w,
                          const nodus_state_proof_req_t *req, uint32_t txn,
                          uint8_t **frame, size_t *frame_len,
                          nodus_state_proof_stats_t *stats, int *ec, char *em,
                          size_t cap)
{
    const int ie = NODUS_ERR_INTERNAL_ERROR;
    nodus_witness_proof_legs_t legs;
    evm_trie_proof_set_t set = {0};
    ro_store_t ro = { w->db, NULL, 0 };
    dna_v2_proof_step_t *steps = NULL;
    evm_trie_proof_result_t *res = NULL;
    const uint8_t **np = NULL;
    size_t *nl = NULL;
    uint8_t (*paths)[64] = NULL;
    uint8_t *buf = NULL;
    uint64_t h = 0;
    uint8_t gr[64], lr[64], app[64];
    size_t ns = 0;
    int rc = -1;

    memset(&legs, 0, sizeof(legs));
    if (nodus_witness_v2_tip_height(w, &h) != 0) {
        fail(ec, em, cap, ie, "the committed height is unreadable");
        return -1;
    }
    if (g_stage_hook) g_stage_hook(g_stage_hook_ctx);   /* test seam, NULL in production */
    int lrc = nodus_witness_proof_legs_load(w, &legs);
    if (lrc == 1) {                       /* below generation 6: no tries */
        fail(ec, em, cap, NODUS_ERR_NOT_FOUND,
             "the snapshot is below generation 6");
        return -1;
    }
    if (lrc != 0) {
        fail(ec, em, cap, ie, "the composition legs are unreadable");
        return -1;
    }
    if (nodus_witness_v2_committed_global_root(w, gr) != 0 ||
        memcmp(gr, legs.global_root, 64) != 0) {
        fail(ec, em, cap, ie, "the legs do not compose to the committed "
             "AppHash");
        goto done;
    }

    steps = calloc(DNA_V2_PROOF_STEPS_MAX, sizeof(*steps));
    res = calloc(req->n_keys, sizeof(*res));
    paths = calloc(req->n_keys, 64);
    if (!steps || !res || !paths) { fail(ec, em, cap, ie, "allocation"); goto done; }
    {
        dna_v2_proof_legs_t in;
        memset(&in, 0, sizeof(in));
        in.core = (const uint8_t (*)[64])legs.core;
        in.stor = (const uint8_t (*)[64])legs.stor;
        in.sys = (const uint8_t (*)[64])legs.sys;
        in.heads = legs.heads;
        in.luh = (const uint8_t (*)[64])legs.luh;
        in.n_heads = legs.n_heads;
        memcpy(in.replay, legs.replay, 64);
        if (dna_v2_state_proof_cp_build(req->leg, &in, steps, &ns, lr, app)
                != 0 || memcmp(app, gr, 64) != 0) {
            fail(ec, em, cap, ie, "the composition proof does not end at "
                 "the committed AppHash");
            goto done;
        }
    }

    if (sqlite3_prepare_v2(w->db,
            "SELECT rlp FROM v2_trie_nodes WHERE digest = ?1", -1, &ro.st,
            NULL) != SQLITE_OK) {
        fail(ec, em, cap, ie, "the node store is unreadable");
        goto done;
    }
    {
        evm_trie_store_t store = { &ro, ro_get, ro_put };
        for (size_t k = 0; k < req->n_keys; k++) {
            if (evm_trie_proof_path_of_key(req->keys[k], req->key_len[k],
                                           paths[k]) != 0 ||
                evm_trie_prove_path(&store, lr, paths[k], &set) != 0) {
                fail(ec, em, cap, ie, "a trie node is missing or malformed");
                goto done;
            }
        }
    }
    if (evm_trie_proof_set_finish(&set) != 0 ||
        set.n > EVM_TRIE_PROOF_MAX_NODES) {
        fail(ec, em, cap, ie, "the node set is out of bounds");
        goto done;
    }

    /* the answer must verify against its own leg root and composition */
    np = calloc(set.n + 1, sizeof(*np));
    nl = calloc(set.n + 1, sizeof(*nl));
    if (!np || !nl) { fail(ec, em, cap, ie, "allocation"); goto done; }
    for (size_t i = 0; i < set.n; i++) {
        np[i] = set.v[i].rlp;
        nl[i] = set.v[i].len;
    }
    if (evm_trie_proof_verify_batch(lr, np, nl, set.n,
                                    (const uint8_t (*)[64])paths,
                                    req->n_keys, res) != 0 ||
        dna_v2_state_proof_cp_verify(req->leg, lr, steps, ns, gr) != 0) {
        fail(ec, em, cap, ie, "the proof failed its own verification");
        goto done;
    }
    for (size_t k = 0; k < req->n_keys; k++)
        if (res[k].found && res[k].val_len != 64) {
            fail(ec, em, cap, ie, "a leaf value is not 64 bytes");
            goto done;
        }

    /* the frame: {"t","y":"r","q","r": {"h","lr","nodes","res","cp"}} */
    {
        size_t bound = 512 + req->n_keys * 80 + ns * 6000;
        for (size_t i = 0; i < set.n; i++) bound += set.v[i].len + 9;
        const size_t ceil_ = (size_t)NODUS_MAX_FRAME_TCP;
        const int capped = bound > ceil_;
        if (capped) bound = ceil_;
        buf = malloc(bound);
        if (!buf) { fail(ec, em, cap, ie, "allocation"); goto done; }
        cbor_encoder_t e;
        cbor_encoder_init(&e, buf, bound);
        cbor_encode_map(&e, 4);
        cbor_encode_cstr(&e, "t"); cbor_encode_uint(&e, txn);
        cbor_encode_cstr(&e, "y"); cbor_encode_cstr(&e, "r");
        cbor_encode_cstr(&e, "q"); cbor_encode_cstr(&e, "dnac_state_proof");
        cbor_encode_cstr(&e, "r"); cbor_encode_map(&e, 5);
        cbor_encode_cstr(&e, "h");  cbor_encode_uint(&e, h);
        cbor_encode_cstr(&e, "lr"); cbor_encode_bstr(&e, lr, 64);
        cbor_encode_cstr(&e, "nodes"); cbor_encode_array(&e, set.n);
        for (size_t i = 0; i < set.n; i++)
            cbor_encode_bstr(&e, set.v[i].rlp, set.v[i].len);
        cbor_encode_cstr(&e, "res"); cbor_encode_array(&e, req->n_keys);
        for (size_t k = 0; k < req->n_keys; k++) {
            cbor_encode_map(&e, res[k].found ? 2 : 1);
            cbor_encode_cstr(&e, "f"); cbor_encode_bool(&e, res[k].found != 0);
            if (res[k].found) {
                cbor_encode_cstr(&e, "v");
                cbor_encode_bstr(&e, res[k].val, 64);
            }
        }
        cbor_encode_cstr(&e, "cp"); cbor_encode_array(&e, ns);
        for (size_t s = 0; s < ns; s++) enc_cp(&e, &steps[s]);
        size_t flen = cbor_encoder_len(&e);
        if (flen == 0 || flen > ceil_) {
            /* a bound exceeded: plan §10.2 "NODUS_ERR_PROTOCOL_ERROR
             * (malformed request or a bound exceeded)" - the client splits
             * the request */
            fail(ec, em, cap, NODUS_ERR_PROTOCOL_ERROR,
                 "the response is above the frame ceiling, split the request");
            goto done;
        }
        *frame = buf;
        *frame_len = flen;
        buf = NULL;
        if (stats) {
            stats->height = h;
            stats->nodes_loaded = ro.loaded;
            stats->nodes = set.n;
            stats->frame_bytes = flen;
        }
    }
    rc = 0;
done:
    free(buf);
    if (ro.st) sqlite3_finalize(ro.st);
    free(np); free(nl); free(paths); free(res); free(steps);
    evm_trie_proof_set_free(&set);
    nodus_witness_proof_legs_free(&legs);
    return rc;
}

int nodus_state_proof_build(nodus_witness_t *ctx,
                            const nodus_state_proof_req_t *req,
                            uint32_t txn_id, uint8_t **frame,
                            size_t *frame_len,
                            nodus_state_proof_stats_t *stats, int *ec,
                            char *em, size_t cap)
{
    if (frame) *frame = NULL;
    if (frame_len) *frame_len = 0;
    if (stats) memset(stats, 0, sizeof(*stats));
    if (ec) *ec = 0;
    if (!ctx || !ctx->db || !req || !frame || !frame_len || req->n_keys == 0 ||
        req->n_keys > NODUS_STATE_PROOF_MAX_KEYS || req->leg < 1 ||
        req->leg > NODUS_STATE_PROOF_LEGS)
        return fail(ec, em, cap, NODUS_ERR_INTERNAL_ERROR, "bad build call");
    /* one read transaction = one committed snapshot of the WAL database */
    if (sqlite3_exec(ctx->db, "BEGIN", NULL, NULL, NULL) != SQLITE_OK)
        return fail(ec, em, cap, NODUS_ERR_INTERNAL_ERROR,
                    "cannot begin a read transaction");
    int rc = build_snapshot(ctx, req, txn_id, frame, frame_len, stats, ec, em,
                            cap);
    sqlite3_exec(ctx->db, "ROLLBACK", NULL, NULL, NULL);
    return rc;
}

/* ── the service ───────────────────────────────────────────────────── */

enum { JOB_IDLE = 0, JOB_BUSY = 1, JOB_DONE = 2 };

typedef struct {
    int       state;                    /* under svc->mu                    */
    uint32_t  txn;
    uint8_t   tag[NODUS_STATE_PROOF_TAG_MAX];   /* copied at hand-off */
    size_t    tag_len;
    nodus_state_proof_req_t req;        /* embedded: no per-request allocation */
    uint8_t  *frame;
    size_t    frame_len;
    int       ec;
    char      em[96];
    nodus_state_proof_stats_t stats;
    pthread_t builder;
    int       built;
    nodus_witness_t *ctx;               /* the reader's private context     */
    struct nodus_state_proof_service *svc;
} job_t;

struct nodus_state_proof_service {
    pthread_mutex_t mu;
    pthread_cond_t  cv;
    int             stop;
    unsigned        n;
    unsigned        rate;
    job_t          *jobs;
    pthread_t      *th;
    unsigned        started;
    pthread_t       creator;
    int64_t         tat_ns;             /* the limiter, loop thread only    */
    nodus_state_proof_counters_t c;     /* loop-side fields: loop thread only */
    atomic_uint_fast64_t builds_started, builds_done, loop_builds;
};

static void *reader_main(void *arg)
{
    job_t *j = arg;
    struct nodus_state_proof_service *svc = j->svc;
    for (;;) {
        pthread_mutex_lock(&svc->mu);
        while (!svc->stop && j->state != JOB_BUSY)
            pthread_cond_wait(&svc->cv, &svc->mu);
        if (svc->stop) {
            pthread_mutex_unlock(&svc->mu);
            return NULL;
        }
        pthread_mutex_unlock(&svc->mu);

        atomic_fetch_add(&svc->builds_started, 1);
        if (pthread_equal(pthread_self(), svc->creator))
            atomic_fetch_add(&svc->loop_builds, 1);
        uint8_t *frame = NULL;
        size_t flen = 0;
        int ec = 0;
        char em[96] = "";
        nodus_state_proof_stats_t st;
        int rc = nodus_state_proof_build(j->ctx, &j->req, j->txn, &frame, &flen,
                                         &st, &ec, em, sizeof(em));
        atomic_fetch_add(&svc->builds_done, 1);

        pthread_mutex_lock(&svc->mu);
        j->builder = pthread_self();
        j->built = 1;
        j->frame = rc == 0 ? frame : NULL;
        j->frame_len = rc == 0 ? flen : 0;
        j->ec = rc == 0 ? 0 : (ec ? ec : NODUS_ERR_INTERNAL_ERROR);
        snprintf(j->em, sizeof(j->em), "%s", em);
        j->stats = st;
        j->state = JOB_DONE;
        pthread_mutex_unlock(&svc->mu);
    }
}

nodus_state_proof_service_t *
nodus_state_proof_service_new(const char *db_path,
                              const nodus_state_proof_limits_t *lim)
{
    if (!db_path || !lim) return NULL;
    struct nodus_state_proof_service *svc = calloc(1, sizeof(*svc));
    if (!svc) return NULL;
    pthread_mutex_init(&svc->mu, NULL);
    pthread_cond_init(&svc->cv, NULL);
    atomic_init(&svc->builds_started, 0);
    atomic_init(&svc->builds_done, 0);
    atomic_init(&svc->loop_builds, 0);
    svc->creator = pthread_self();
    svc->rate = lim->rate_per_sec;
    /* limit zero = not enabled: no reader, no thread, every request refused */
    svc->n = (lim->readers > 0 && lim->rate_per_sec > 0) ? lim->readers : 0;
    if (svc->n == 0) return svc;
    svc->jobs = calloc(svc->n, sizeof(*svc->jobs));
    svc->th = calloc(svc->n, sizeof(*svc->th));
    if (!svc->jobs || !svc->th) goto bad;
    for (unsigned i = 0; i < svc->n; i++) {
        svc->jobs[i].svc = svc;
        svc->jobs[i].ctx = nodus_state_proof_ctx_open(db_path);
        if (!svc->jobs[i].ctx) goto bad;
    }
    for (unsigned i = 0; i < svc->n; i++) {
        if (pthread_create(&svc->th[i], NULL, reader_main, &svc->jobs[i]) != 0)
            goto bad;
        svc->started++;
    }
    return svc;
bad:
    nodus_state_proof_service_free(svc, NULL, NULL);
    return NULL;
}

nodus_state_proof_counters_t
nodus_state_proof_service_counters(nodus_state_proof_service_t *svc)
{
    nodus_state_proof_counters_t c;
    memset(&c, 0, sizeof(c));
    if (!svc) return c;
    c = svc->c;
    c.builds_started = atomic_load(&svc->builds_started);
    c.builds_done = atomic_load(&svc->builds_done);
    c.loop_builds = atomic_load(&svc->loop_builds);
    return c;
}

/* The node-wide limiter in its GCRA form: tat is the instant at which the
 * bucket is full again; a request at `now` is admitted while it lies at most
 * rate - 1 intervals ahead. Integer nanoseconds; a refusal changes nothing
 * (the caller commits only when it also found a reader). */
static int limiter_check(const struct nodus_state_proof_service *s,
                         int64_t now, int64_t *new_tat)
{
    int64_t interval = 1000000000LL / (int64_t)s->rate;
    if (interval < 1) interval = 1;
    if (now < 0 || now > INT64_MAX - (int64_t)(s->rate + 1) * interval)
        return 0;
    int64_t tat = s->tat_ns > now ? s->tat_ns : now;
    if (tat - now > (int64_t)(s->rate - 1) * interval) return 0;
    *new_tat = tat + interval;
    return 1;
}

int nodus_state_proof_submit(nodus_state_proof_service_t *svc, int64_t now_ns,
                             const uint8_t *payload, size_t len,
                             uint32_t txn_id, const void *tag, size_t tag_len,
                             int *ec, char *em, size_t cap)
{
    if (!svc || !payload || tag_len > NODUS_STATE_PROOF_TAG_MAX ||
        (tag_len && !tag))
        return fail(ec, em, cap, NODUS_ERR_PROTOCOL_ERROR, "no request");
    svc->c.decoded++;
    /* the request is validated in bounded scratch storage (stack) BEFORE
     * anything is allocated or handed off; the job slot holds its own copy */
    nodus_state_proof_req_t req;
    if (nodus_state_proof_request_decode(payload, len, &req, ec, em, cap) != 0) {
        svc->c.refused_protocol++;
        return -1;
    }
    int64_t new_tat = 0;
    if (svc->n == 0 || !limiter_check(svc, now_ns, &new_tat)) {
        svc->c.refused_rate++;
        return fail(ec, em, cap, NODUS_ERR_RATE_LIMITED,
                    "state proof rate limit reached, ask another node");
    }
    job_t *job = NULL;
    pthread_mutex_lock(&svc->mu);
    for (unsigned i = 0; i < svc->n; i++)
        if (svc->jobs[i].state == JOB_IDLE) { job = &svc->jobs[i]; break; }
    if (job) {
        job->state = JOB_BUSY;
        job->txn = txn_id;
        if (tag_len) memcpy(job->tag, tag, tag_len);
        job->tag_len = tag_len;
        memcpy(&job->req, &req, sizeof(req));
        job->frame = NULL;
        job->frame_len = 0;
        job->ec = 0;
        job->em[0] = '\0';
        job->built = 0;
        pthread_cond_broadcast(&svc->cv);
    }
    pthread_mutex_unlock(&svc->mu);
    if (!job) {
        svc->c.refused_busy++;
        return fail(ec, em, cap, NODUS_ERR_RATE_LIMITED,
                    "every state proof reader is busy, ask another node");
    }
    svc->tat_ns = new_tat;               /* the token is spent only on a hand-off */
    svc->c.handed_off++;
    return 0;
}

size_t nodus_state_proof_poll(nodus_state_proof_service_t *svc,
                              nodus_state_proof_done_fn done, void *user)
{
    size_t n = 0;
    if (!svc || !done) return 0;
    for (unsigned i = 0; i < svc->n; i++) {
        job_t *j = &svc->jobs[i];
        uint8_t tag[NODUS_STATE_PROOF_TAG_MAX];
        uint8_t *frame;
        size_t flen;
        int ec;
        char em[96];
        nodus_state_proof_stats_t st;
        pthread_mutex_lock(&svc->mu);
        if (j->state != JOB_DONE) { pthread_mutex_unlock(&svc->mu); continue; }
        memcpy(tag, j->tag, sizeof(tag));    /* the slot is free after this */
        frame = j->frame; flen = j->frame_len; ec = j->ec;
        memcpy(em, j->em, sizeof(em));
        st = j->stats;
        j->frame = NULL;
        j->state = JOB_IDLE;
        pthread_mutex_unlock(&svc->mu);
        done(user, tag, frame, flen, ec, em, &st, 0);
        n++;
    }
    return n;
}

size_t nodus_state_proof_service_published(nodus_state_proof_service_t *svc)
{
    size_t n = 0;
    if (!svc) return 0;
    pthread_mutex_lock(&svc->mu);
    for (unsigned i = 0; i < svc->n; i++)
        if (svc->jobs[i].state == JOB_DONE) n++;
    pthread_mutex_unlock(&svc->mu);
    return n;
}

int nodus_state_proof_service_last_builder(nodus_state_proof_service_t *svc,
                                           unsigned reader, pthread_t *out)
{
    int ok = 0;
    if (!svc || !out || reader >= svc->n) return -1;
    pthread_mutex_lock(&svc->mu);
    if (svc->jobs[reader].built) {
        *out = svc->jobs[reader].builder;
        ok = 1;
    }
    pthread_mutex_unlock(&svc->mu);
    return ok ? 0 : -1;
}

void nodus_state_proof_service_free(nodus_state_proof_service_t *svc,
                                    nodus_state_proof_done_fn done, void *user)
{
    if (!svc) return;
    pthread_mutex_lock(&svc->mu);
    svc->stop = 1;
    pthread_cond_broadcast(&svc->cv);
    pthread_mutex_unlock(&svc->mu);
    for (unsigned i = 0; i < svc->started; i++) pthread_join(svc->th[i], NULL);
    for (unsigned i = 0; svc->jobs && i < svc->n; i++) {
        job_t *j = &svc->jobs[i];
        if (j->state != JOB_IDLE && done)
            done(user, j->tag, NULL, 0, 0, "", NULL, 1);
        free(j->frame);
        nodus_state_proof_ctx_close(j->ctx);
    }
    free(svc->jobs);
    free(svc->th);
    pthread_cond_destroy(&svc->cv);
    pthread_mutex_destroy(&svc->mu);
    free(svc);
}

/* ── the witness binding (the loop) ───────────────────────────────────── */

typedef struct {
    nodus_state_proof_conn_id_t id;
    uint32_t                    txn;
} conn_tag_t;

/* The identity of the asking connection: the transport's session generation
 * (non-zero only in session mode, nodus_tcp.c:270) AND the serial the witness
 * IPC listener stamps into conn->user_data at accept (nodus_witness_ipc.c).
 * The IPC transport is never in session mode, so its generation stays 0; the
 * serial is what tells a replacement connection in the same slot from the
 * one that asked. A connection with neither has no identity. */
_Static_assert(sizeof(uintptr_t) >= sizeof(uint64_t),
               "conn->user_data must carry the 64-bit IPC serial untruncated");

int nodus_state_proof_conn_id_of(struct nodus_tcp_conn *conn,
                                 nodus_state_proof_conn_id_t *id)
{
    if (!conn || !id || !conn->tcp_parent) return -1;
    id->tcp = conn->tcp_parent;
    id->slot = conn->slot;
    id->generation = conn->generation;
    id->serial = (uint64_t)(uintptr_t)conn->user_data;
    return (id->generation == 0 && id->serial == 0) ? -1 : 0;
}

struct nodus_tcp_conn *
nodus_state_proof_conn_alive(const nodus_state_proof_conn_id_t *id)
{
    if (!id || !id->tcp || id->slot < 0 || id->slot >= NODUS_TCP_MAX_CONNS)
        return NULL;
    nodus_tcp_conn_t *c = id->tcp->pool[id->slot];
    if (!c || c->close_pending || c->generation != id->generation ||
        (uint64_t)(uintptr_t)c->user_data != id->serial)
        return NULL;
    return c;
}

static void send_error_to(nodus_tcp_conn_t *c, uint32_t txn, int code,
                          const char *msg)
{
    uint8_t buf[512];
    size_t len = 0;
    if (nodus_t2_error(txn, code, msg, buf, sizeof(buf), &len) == 0)
        nodus_tcp_send(c, buf, len);
}

int nodus_witness_state_proof_enable(nodus_witness_t *w,
                                     const nodus_state_proof_limits_t *limits)
{
    if (!w || !w->db || !limits || w->state_proof) return -1;
    const char *path = sqlite3_db_filename(w->db, "main");
    if (!path || !*path) return -1;                 /* in-memory: no file */
    w->state_proof = nodus_state_proof_service_new(path, limits);
    return w->state_proof ? 0 : -1;
}

int nodus_witness_state_proof_enabled(const nodus_witness_t *w)
{
    return w && w->state_proof != NULL;
}

void nodus_witness_state_proof_handle(nodus_witness_t *w,
                                      struct nodus_tcp_conn *conn,
                                      const uint8_t *payload, size_t len,
                                      uint32_t txn_id, int64_t now_ns)
{
    int ec = 0;
    char em[96];
    if (!w || !conn || !payload) return;
    if (!w->state_proof) {
        /* not enabled = a node-wide limit of zero (header): refused at once,
         * before any decode or read */
        send_error_to(conn, txn_id, NODUS_ERR_RATE_LIMITED,
                      "state proofs are not served by this node");
        return;
    }
    /* The completion tag lives on the stack and is copied into the reader's
     * job slot only after the request was validated and admitted: nothing is
     * allocated for a refused request (plan §10.2: bounds before allocation). */
    conn_tag_t t;
    memset(&t, 0, sizeof(t));
    t.txn = txn_id;
    if (nodus_state_proof_conn_id_of(conn, &t.id) != 0) {
        /* no way to tell this connection from a replacement: fail closed */
        send_error_to(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                      "internal error");
        return;
    }
    if (nodus_state_proof_submit(w->state_proof, now_ns, payload, len, txn_id,
                                 &t, sizeof(t), &ec, em, sizeof(em)) != 0)
        send_error_to(conn, txn_id, ec ? ec : NODUS_ERR_INTERNAL_ERROR,
                      ec ? em : "internal error");
}

_Static_assert(sizeof(conn_tag_t) <= NODUS_STATE_PROOF_TAG_MAX,
               "the completion tag fits the job slot's tag area");

static void deliver(void *user, void *tag, uint8_t *frame, size_t flen,
                    int ec, const char *em,
                    const nodus_state_proof_stats_t *st, int dropped)
{
    conn_tag_t t;
    (void)user; (void)st;
    if (tag && !dropped) {
        memcpy(&t, tag, sizeof(t));
        /* the connection that asked, if it is still the one in its slot */
        nodus_tcp_conn_t *c = nodus_state_proof_conn_alive(&t.id);
        if (c) {
            if (frame) nodus_tcp_send(c, frame, flen);
            else send_error_to(c, t.txn, ec ? ec : NODUS_ERR_INTERNAL_ERROR,
                               ec ? em : "internal error");
        }
    }
    free(frame);
}

void nodus_witness_state_proof_poll(nodus_witness_t *w)
{
    if (!w || !w->state_proof) return;
    nodus_state_proof_poll(w->state_proof, deliver, NULL);
}

void nodus_witness_state_proof_disable(nodus_witness_t *w)
{
    if (!w || !w->state_proof) return;
    nodus_state_proof_service_free(w->state_proof, deliver, NULL);
    w->state_proof = NULL;
}
