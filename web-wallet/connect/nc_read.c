/* Nodus Connect thin core — R0, the three-outcome read, and the one PUT
 * helper (design rev 5 §1.4 R0 / R7, §2.1, §6.4 F1 / F4 / F5).
 *
 * The classifiers are pure functions of the reply (design §4 D4): no clock,
 * no retry, no I/O. Retries are the caller's schedule; a retry never turns
 * UNREADABLE into a write.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "nc_core.h"

#include "client/nodus_client_strict.h"
#include "core/nodus_value.h"
#include "crypto/nodus_sign.h"
#include "crypto/utils/qgp_log.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

#define LOG_TAG "NC_READ"

const char *nc_why_str(nc_why_t why) {
    switch (why) {
    case NC_WHY_NONE:          return "none";
    case NC_WHY_CANCELLED:     return "cancelled";
    case NC_WHY_NOT_CONNECTED: return "not_connected";
    case NC_WHY_TIMEOUT:       return "timeout";
    case NC_WHY_NODE_ERROR:    return "node_error";
    case NC_WHY_UNDECODABLE:   return "undecodable";
    case NC_WHY_BAD_SIGNATURE: return "bad_signature";
    case NC_WHY_WRONG_KEY:     return "wrong_key";
    case NC_WHY_WRONG_OWNER:   return "wrong_owner";
    case NC_WHY_BAD_RECORD:    return "bad_record";
    case NC_WHY_TOO_LARGE:     return "too_large";
    }
    return "unknown";
}

const char *nc_outcome_str(nc_outcome_t o) {
    switch (o) {
    case NC_FOUND:      return "found";
    case NC_EMPTY:      return "empty";
    case NC_UNREADABLE: return "unreadable";
    }
    return "unknown";
}

void nc_key_str(const char *s, nodus_key_t *out) {
    nodus_hash((const uint8_t *)s, strlen(s), out);
}

void nc_key_bytes(const uint8_t *b, size_t n, nodus_key_t *out) {
    nodus_hash(b, n, out);
}

int nc_fp_parse(const char *hex, nodus_key_t *out) {
    if (!hex || !out || strnlen(hex, NC_FP_HEX_LEN + 1) != NC_FP_HEX_LEN)
        return -1;
    for (size_t i = 0; i < NODUS_KEY_BYTES; i++) {
        int v[2];
        for (int j = 0; j < 2; j++) {
            char c = hex[2 * i + (size_t)j];
            v[j] = (c >= '0' && c <= '9') ? c - '0'
                 : (c >= 'a' && c <= 'f') ? c - 'a' + 10 : -1;
            if (v[j] < 0) return -1;
        }
        out->bytes[i] = (uint8_t)(v[0] << 4 | v[1]);
    }
    return 0;
}

/* The client's rc -> why, for everything that is not 0 / NOT_FOUND. */
static nc_why_t why_from_rc(int rc) {
    if (rc == NODUS_ERR_TIMEOUT)        return NC_WHY_TIMEOUT;
    if (rc == NODUS_ERR_PROTOCOL_ERROR) return NC_WHY_UNDECODABLE;
    if (rc == -1)                       return NC_WHY_NOT_CONNECTED;
    if (rc == NC_ERR_CANCELLED)         return NC_WHY_CANCELLED;
    /* The node could not look (DHT Package A): an error, never "empty". */
    if (rc == NODUS_ERR_UNAVAILABLE)    return NC_WHY_NODE_ERROR;
    return NC_WHY_NODE_ERROR;
}

/* One value against the DHT rules the core enforces on every read (G10). */
static nc_why_t check_value(const nodus_value_t *v, const nodus_key_t *key,
                            const nodus_key_t *owners, size_t n_owners) {
    if (nodus_value_verify(v) != 0) return NC_WHY_BAD_SIGNATURE;
    if (memcmp(v->key_hash.bytes, key->bytes, NODUS_KEY_BYTES) != 0)
        return NC_WHY_WRONG_KEY;
    if (n_owners == 0) return NC_WHY_NONE;
    for (size_t i = 0; i < n_owners; i++)
        if (memcmp(v->owner_fp.bytes, owners[i].bytes, NODUS_KEY_BYTES) == 0)
            return NC_WHY_NONE;
    return NC_WHY_WRONG_OWNER;
}

void nc_read_clear(nc_read_t *r) {
    if (!r) return;
    if (r->value) nodus_value_free(r->value);
    r->value = NULL;
}

void nc_classify_one(int rc, nodus_value_t *value, const nodus_key_t *key,
                     const nodus_key_t *expect_owner, nc_read_t *out) {
    memset(out, 0, sizeof(*out));
    out->node_rc = rc;
    if (rc == 0 && value) {
        nc_why_t why = check_value(value, key, expect_owner,
                                   expect_owner ? 1 : 0);
        if (why == NC_WHY_NONE) {
            out->outcome = NC_FOUND;
            out->value = value;
            return;
        }
        nodus_value_free(value);
        out->outcome = NC_UNREADABLE;
        out->why = why;
        return;
    }
    if (value) nodus_value_free(value);
    if (rc == NODUS_ERR_NOT_FOUND) {
        out->outcome = NC_EMPTY;
        return;
    }
    out->outcome = NC_UNREADABLE;
    /* rc 0 without a value cannot come from nodus_client_get_strict; it is
     * classified as undecodable rather than guessed as empty. */
    out->why = rc == 0 ? NC_WHY_UNDECODABLE : why_from_rc(rc);
}

bool nc_row_before(const nodus_value_t *a, const nodus_value_t *b) {
    bool ax = a->type == NODUS_VALUE_EXCLUSIVE, bx = b->type == NODUS_VALUE_EXCLUSIVE;
    if (ax != bx) return ax;
    if (a->seq != b->seq) return a->seq > b->seq;
    return a->value_id < b->value_id;
}

static void read_all_impl(const nc_ctx_t *ctx, const nodus_key_t *key,
                          const nodus_key_t *owners, size_t n_owners,
                          nodus_page_req_t *first, nc_read_all_t *out);

/* R0 for one owner's value (nc_core.h nc_read_one, expect_owner set): the
 * owner-filtered get-all, then one row of it. `first` (nullable): that
 * get-all's first page, already requested (nc_read_owner_many); NULL = the
 * read requests it itself. Ownership of first->vals moves here. */
static void read_owner_one(const nc_ctx_t *ctx, const nodus_key_t *key,
                           const nodus_key_t *owner, nodus_page_req_t *first,
                           nc_read_t *out) {
    nc_read_all_t all;
    read_all_impl(ctx, key, owner, 1, first, &all);
    memset(out, 0, sizeof(*out));
    out->outcome = all.outcome;
    out->why = all.why;
    out->node_rc = all.node_rc;
    out->foreign = all.wrong_owner;
    if (all.outcome != NC_FOUND) {
        nc_read_all_clear(&all);
        return;
    }
    /* An item that did not decode, failed its signature or is signed for
     * another key may be the owner's newest row: no answer (fail closed). */
    nc_why_t dropped = all.undecodable ? NC_WHY_UNDECODABLE
                     : all.bad_sig     ? NC_WHY_BAD_SIGNATURE
                     : all.wrong_key   ? NC_WHY_WRONG_KEY
                     : NC_WHY_NONE;
    if (dropped != NC_WHY_NONE) {
        nc_read_all_clear(&all);
        out->outcome = NC_UNREADABLE;
        out->why = dropped;
        QGP_LOG_INFO(LOG_TAG, "GET(owner) unreadable: %s next to the owner's "
                     "row", nc_why_str(dropped));
        return;
    }
    size_t best = 0;
    for (size_t i = 1; i < all.count; i++)
        if (nc_row_before(all.values[i], all.values[best])) best = i;
    out->value = all.values[best];
    all.values[best] = NULL;
    nc_read_all_clear(&all);
}

void nc_read_one(const nc_ctx_t *ctx, const nodus_key_t *key,
                 const nodus_key_t *expect_owner, nc_read_t *out) {
    if (expect_owner) {
        read_owner_one(ctx, key, expect_owner, NULL, out);
        return;
    }
    if (!ctx || !ctx->client || !key) {
        nc_classify_one(-1, NULL, key, expect_owner, out);
        return;
    }
    if (ctx->cancel && *ctx->cancel) {
        nc_classify_one(NC_ERR_CANCELLED, NULL, key, expect_owner, out);
        return;
    }
    nodus_value_t *v = NULL;
    int rc = nodus_client_get_strict(ctx->client, key, &v);
    nc_classify_one(rc, v, key, expect_owner, out);
    if (out->outcome == NC_UNREADABLE)
        QGP_LOG_INFO(LOG_TAG, "GET unreadable: %s (rc=%d)",
                     nc_why_str(out->why), rc);
}

void nc_read_all_clear(nc_read_all_t *r) {
    if (!r) return;
    for (size_t i = 0; i < r->count; i++) nodus_value_free(r->values[i]);
    free(r->values);
    r->values = NULL;
    r->count = 0;
}

void nc_classify_all(int rc, nodus_value_t **vals, size_t count,
                     size_t undecodable, const nodus_key_t *key,
                     const nodus_key_t *owners, size_t n_owners,
                     nc_read_all_t *out) {
    memset(out, 0, sizeof(*out));
    out->node_rc = rc;
    out->undecodable = undecodable;
    if (rc != 0) {
        for (size_t i = 0; i < count; i++) nodus_value_free(vals[i]);
        free(vals);
        /* An error reply carrying NOT_FOUND reads as the single GET's
         * NOT_FOUND does: EMPTY (which never authorises a write for a
         * restored identity either). */
        if (rc == NODUS_ERR_NOT_FOUND && undecodable == 0) {
            out->outcome = NC_EMPTY;
            return;
        }
        out->outcome = NC_UNREADABLE;
        out->why = why_from_rc(rc);
        return;
    }
    /* Accepted values are compacted in place, reply order kept. */
    size_t kept = 0;
    nc_why_t last_drop = NC_WHY_NONE;
    for (size_t i = 0; i < count; i++) {
        nc_why_t why = check_value(vals[i], key, owners, n_owners);
        if (why == NC_WHY_NONE) { vals[kept++] = vals[i]; continue; }
        if (why == NC_WHY_BAD_SIGNATURE)   out->bad_sig++;
        else if (why == NC_WHY_WRONG_KEY)  out->wrong_key++;
        else                               out->wrong_owner++;
        last_drop = why;
        nodus_value_free(vals[i]);
        vals[i] = NULL;
    }
    if (kept > 0) {
        out->outcome = NC_FOUND;
        out->partial = true;                 /* F5: never complete          */
        out->values = vals;
        out->count = kept;
        return;
    }
    free(vals);
    if (count == 0 && undecodable == 0) {
        out->outcome = NC_EMPTY;
        return;
    }
    out->outcome = NC_UNREADABLE;
    out->why = count == 0 ? NC_WHY_UNDECODABLE : last_drop;
}

/* Local only: an owner-filtered read with pages left (never a node code —
 * those are positive — nor an NC_ERR_*). */
#define NC_RC_TOO_LARGE (-1000)

/* Rows of every page of every loop of one nc_read_all, in reply order. */
typedef struct {
    nodus_value_t **vals;
    size_t          count;
    size_t          undecodable;
} page_acc_t;

static int acc_append(page_acc_t *acc, nodus_value_t **vals, size_t n) {
    if (n == 0) return 0;
    nodus_value_t **grown = realloc(acc->vals,
                                    (acc->count + n) * sizeof(*grown));
    if (!grown) return -1;
    memcpy(grown + acc->count, vals, n * sizeof(*grown));
    acc->vals = grown;
    acc->count += n;
    return 0;
}

/* Frees the rows a pipelined first page still holds (a read that ended
 * before taking them). */
static void first_page_free(nodus_page_req_t *first) {
    if (!first) return;
    for (size_t i = 0; i < first->count; i++) nodus_value_free(first->vals[i]);
    free(first->vals);
    first->vals = NULL;
    first->count = 0;
}

/* One paging loop (owner NULL = every owner): reads while the node says
 * "more", at most NC_READ_MAX_PAGES pages, cancel checked before every
 * page. Returns 0 or the first page's error (the rows read so far stay in
 * acc; the caller frees them). *more_left = pages remained after the cap.
 * `first` (nullable): page 0's answer, already requested with this key and
 * owner and no cursor (nodus_client_get_all_page_strict_many) — it takes
 * the place of page 0's request only; every check below runs on it
 * unchanged. Its rows move into acc (or are freed). */
static int read_pages(const nc_ctx_t *ctx, const nodus_key_t *key,
                      const nodus_key_t *owner, page_acc_t *acc,
                      bool *more_left, nodus_page_req_t *first) {
    nodus_dht_page_cursor_t cursor;
    bool have_cursor = false;
    *more_left = false;
    for (int page = 0; page < NC_READ_MAX_PAGES; page++) {
        nodus_value_t **vals = NULL;
        size_t n = 0, undecodable = 0;
        bool more = false, legacy = false;
        nodus_dht_page_cursor_t next;
        int rc;
        if (page == 0 && first) {
            rc = first->rc;
            vals = first->vals;
            n = first->count;
            more = first->more;
            next = first->cursor;
            legacy = first->legacy;
            undecodable = first->undecodable;
            first->vals = NULL;
            first->count = 0;
        } else {
            if (ctx->cancel && *ctx->cancel) return NC_ERR_CANCELLED;
            rc = nodus_client_get_all_page_strict(ctx->client, key, owner,
                                                  have_cursor ? &cursor : NULL,
                                                  &vals, &n, &more, &next,
                                                  &legacy, &undecodable);
        }
        if (rc != 0) {
            /* The client returns no row with an error; freed in case. */
            for (size_t i = 0; i < n; i++) nodus_value_free(vals[i]);
            free(vals);
            return rc;
        }
        acc->undecodable += undecodable;
        if (acc_append(acc, vals, n) != 0) {
            for (size_t i = 0; i < n; i++) nodus_value_free(vals[i]);
            free(vals);
            return NC_ERR_INTERNAL;
        }
        free(vals);
        if (legacy && n == 0) {
            /* A node that predates paging answers empty both for an empty
             * key and when it could not look: not EMPTY. */
            QGP_LOG_INFO(LOG_TAG, "GET_ALL(page): legacy reply without a row "
                         "— unreadable, not empty");
            return NODUS_ERR_UNAVAILABLE;
        }
        if (!more) return 0;
        cursor = next;
        have_cursor = true;
    }
    *more_left = true;
    return 0;
}

/* nc_read_all, with an optional pipelined first page for the FIRST loop
 * (first != NULL only with n_owners == 1: nc_read_owner_many). Every path
 * frees first's rows if it does not take them. */
static void read_all_impl(const nc_ctx_t *ctx, const nodus_key_t *key,
                          const nodus_key_t *owners, size_t n_owners,
                          nodus_page_req_t *first, nc_read_all_t *out) {
    if (!ctx || !ctx->client || !key) {
        first_page_free(first);
        nc_classify_all(-1, NULL, 0, 0, key, owners, n_owners, out);
        return;
    }
    if (ctx->cancel && *ctx->cancel) {
        first_page_free(first);
        nc_classify_all(NC_ERR_CANCELLED, NULL, 0, 0, key, owners, n_owners,
                        out);
        return;
    }
    page_acc_t acc;
    memset(&acc, 0, sizeof(acc));
    int rc = 0;
    bool more_left = false;
    size_t loops = n_owners > 0 ? n_owners : 1;
    for (size_t i = 0; i < loops && rc == 0; i++) {
        bool left = false;
        rc = read_pages(ctx, key, n_owners > 0 ? &owners[i] : NULL, &acc,
                        &left, i == 0 ? first : NULL);
        more_left = more_left || left;
    }
    first_page_free(first);              /* read_pages took it: a no-op    */
    if (rc == 0 && more_left && n_owners > 0) rc = NC_RC_TOO_LARGE;
    if (rc != 0) {
        /* Never through nc_classify_all's rc path: its NOT_FOUND -> EMPTY
         * branch must not turn a page error into EMPTY. */
        for (size_t i = 0; i < acc.count; i++) nodus_value_free(acc.vals[i]);
        free(acc.vals);
        memset(out, 0, sizeof(*out));
        out->outcome = NC_UNREADABLE;
        out->undecodable = acc.undecodable;
        if (rc == NC_RC_TOO_LARGE) {
            out->why = NC_WHY_TOO_LARGE;
        } else {
            out->why = why_from_rc(rc);
            out->node_rc = rc;
        }
        QGP_LOG_INFO(LOG_TAG, "GET_ALL unreadable: %s (rc=%d)",
                     nc_why_str(out->why), rc);
        return;
    }
    nc_classify_all(0, acc.vals, acc.count, acc.undecodable, key, owners,
                    n_owners, out);
    out->truncated = more_left;          /* owner-less only (rc 0 here)    */
    if (more_left) {
        QGP_LOG_INFO(LOG_TAG, "GET_ALL: pages left after %d — the answer is "
                     "truncated", NC_READ_MAX_PAGES);
        /* Rows remain at the node: "no item" is not what it said. */
        if (out->outcome == NC_EMPTY) {
            out->outcome = NC_UNREADABLE;
            out->why = NC_WHY_TOO_LARGE;
        }
    }
    if (out->outcome == NC_UNREADABLE)
        QGP_LOG_INFO(LOG_TAG, "GET_ALL unreadable: %s",
                     nc_why_str(out->why));
}

void nc_read_all(const nc_ctx_t *ctx, const nodus_key_t *key,
                 const nodus_key_t *owners, size_t n_owners,
                 nc_read_all_t *out) {
    read_all_impl(ctx, key, owners, n_owners, NULL, out);
}

int nc_read_owner_many(const nc_ctx_t *ctx, const nodus_key_t *keys,
                       const nodus_key_t *owners, size_t n, nc_read_t *outs) {
    if (!keys || !owners || !outs || n == 0 || n > NC_READ_MANY_MAX)
        return NC_ERR_ARG;
    memset(outs, 0, n * sizeof(*outs));
    for (size_t w = 0; w < n; w += NC_READ_PIPELINE) {
        size_t m = n - w < NC_READ_PIPELINE ? n - w : NC_READ_PIPELINE;
        nodus_page_req_t reqs[NC_READ_PIPELINE];
        memset(reqs, 0, sizeof(reqs));
        bool sent = false;
        /* No client / cancelled: nothing is sent; read_owner_one answers
         * each key as nc_read_one would (-1 / CANCELLED, no network). */
        if (ctx && ctx->client && !(ctx->cancel && *ctx->cancel)) {
            for (size_t j = 0; j < m; j++) {
                reqs[j].key = &keys[w + j];
                reqs[j].owner_fp = &owners[w + j];
                reqs[j].after = NULL;
            }
            sent = nodus_client_get_all_page_strict_many(ctx->client, reqs,
                                                         m) == 0;
        }
        for (size_t j = 0; j < m; j++)
            read_owner_one(ctx, &keys[w + j], &owners[w + j],
                           sent ? &reqs[j] : NULL, &outs[w + j]);
    }
    return NC_OK;
}

int nc_put(const nc_ctx_t *ctx, const nodus_key_t *key,
           const uint8_t *data, size_t data_len,
           nodus_value_type_t type, uint32_t ttl, uint64_t value_id) {
    if (!ctx || !ctx->client || !ctx->keys || !key) return NC_ERR_ARG;
    if (ctx->cancel && *ctx->cancel) return NC_ERR_CANCELLED;
    if (!nodus_client_is_ready(ctx->client)) return -1;

    const nodus_identity_t *id = &ctx->keys->id;
    uint64_t seq = (uint64_t)time(NULL);
    nodus_value_t *val = NULL;
    if (nodus_value_create(key, data, data_len, type, ttl, value_id, seq,
                           &id->pk, &val) != 0)
        return NC_ERR_INTERNAL;
    if (nodus_value_sign(val, &id->sk) != 0) {
        nodus_value_free(val);
        return NC_ERR_INTERNAL;
    }
    int rc = nodus_client_put_ex(ctx->client, key, data, data_len, type, ttl,
                                 value_id, seq, &val->signature, 0);
    nodus_value_free(val);
    if (rc != 0) QGP_LOG_INFO(LOG_TAG, "PUT refused or failed (rc=%d)", rc);
    return rc;
}
