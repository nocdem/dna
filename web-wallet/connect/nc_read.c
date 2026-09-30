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

void nc_read_one(const nc_ctx_t *ctx, const nodus_key_t *key,
                 const nodus_key_t *expect_owner, nc_read_t *out) {
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

void nc_read_all(const nc_ctx_t *ctx, const nodus_key_t *key,
                 const nodus_key_t *owners, size_t n_owners,
                 nc_read_all_t *out) {
    if (!ctx || !ctx->client || !key) {
        nc_classify_all(-1, NULL, 0, 0, key, owners, n_owners, out);
        return;
    }
    if (ctx->cancel && *ctx->cancel) {
        nc_classify_all(NC_ERR_CANCELLED, NULL, 0, 0, key, owners, n_owners,
                        out);
        return;
    }
    nodus_value_t **vals = NULL;
    size_t count = 0, undecodable = 0;
    int rc = nodus_client_get_all_strict(ctx->client, key, &vals, &count,
                                         &undecodable);
    nc_classify_all(rc, vals, count, undecodable, key, owners, n_owners, out);
    if (out->outcome == NC_UNREADABLE)
        QGP_LOG_INFO(LOG_TAG, "GET_ALL unreadable: %s (rc=%d)",
                     nc_why_str(out->why), rc);
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
