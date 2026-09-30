/* Nodus Connect thin core — R4, the own contact list ("<fp>:contactlist"),
 * design rev 5 §1.4 R4; thin-core decision S3/S5 (UNREADABLE never leads to
 * a write) and Q1 (only words generated in this session create a record).
 *
 * Every byte is the app's code, compiled verbatim:
 *   messenger/codec/contactlist_codec.c  JSON v2 (serialize / parse) and
 *                                         the CLST blob (encode / parse,
 *                                         moved out of dht_contactlist.c
 *                                         by NC-1b)
 *   messenger/dna_api.c                  self-Seal (dna_encrypt_message_raw
 *                                         = round-3 Kyber), decode,
 *                                         authorship
 * What is new here is only the orchestration: read in the same call as the
 * write, merge-only (never fewer entries; the desktop defect of an empty
 * local list overwriting the DHT list, messenger/BUGS.md:38, is not
 * carried), and the Q1 gate for the first list.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "nc_core.h"

#include "codec/contactlist_codec.h"
#include "dht/client/dht_contactlist.h"
#include "dna_api.h"
#include "crypto/utils/qgp_log.h"
#include "crypto/nodus_identity.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define LOG_TAG "NC_CLIST"

/* "<fp>:contactlist" (dht_contactlist.c make_base_key), hashed once as a
 * string (nodus_ops_get_str / nodus_ops_put_str_exclusive). The app passes
 * the identity fingerprint here (contacts.c -> ctx->identity, set from the
 * 128-char fingerprint by dna_engine_identity.c -> messenger_init). */
static void list_key(const char *fp, nodus_key_t *key) {
    char s[NC_FP_HEX_LEN + 16];
    snprintf(s, sizeof(s), "%s:contactlist", fp);
    nc_key_str(s, key);
}

void nc_contactlist_clear(nc_contactlist_t *l) {
    if (!l) return;
    nc_read_clear(&l->read);
    if (l->items) {
        memset(l->items, 0, l->count * sizeof(*l->items));
        free(l->items);
    }
    l->items = NULL;
    l->count = 0;
    l->invalid = 0;
    l->timestamp = 0;
}

static void free_parsed(char **contacts, uint8_t **salts, size_t count) {
    for (size_t i = 0; i < count; i++) {
        if (contacts) free(contacts[i]);
        if (salts && salts[i]) { memset(salts[i], 0, NC_SALT_LEN); free(salts[i]); }
    }
    free(contacts);
    free(salts);
}

/* dht_contactlist_fetch steps 3-6 on `blob`, keys = the own identity.
 * 0 and `out` filled (items, count, invalid, timestamp), or -1. */
static int decode_blob(const nc_keys_t *keys, const uint8_t *blob, size_t len,
                       nc_contactlist_t *out) {
    const uint8_t *enc = NULL;
    uint32_t enc_len = 0;
    if (dht_contactlist_blob_parse(blob, len, NULL, NULL, &enc, &enc_len) != 0)
        return -1;

    dna_context_t *dctx = dna_context_new();
    if (!dctx) return -1;
    uint8_t *pt = NULL, *sender = NULL, *sig = NULL;
    size_t pt_len = 0, sender_len = 0, sig_len = 0;
    uint64_t seal_ts = 0;
    dna_error_t drc = dna_decrypt_message_raw(dctx, enc, enc_len, keys->kyber_sk,
                                              &pt, &pt_len, &sender, &sender_len,
                                              &sig, &sig_len, &seal_ts);
    dna_context_free(dctx);
    int rc = -1;
    char *json = NULL;
    char **contacts = NULL;
    uint8_t **salts = NULL;
    size_t count = 0;
    uint64_t ts = 0;
    if (drc != DNA_OK) goto done;
    /* Self-sealed by the own key (dht_contactlist_fetch "Step 5"). */
    if (sender_len != 64 || !sig || sig_len == 0 ||
        dna_verify_seal_authorship(pt, pt_len, sig, sig_len, keys->id.pk.bytes,
                                   DHT_CONTACTLIST_DILITHIUM_PUBKEY_SIZE,
                                   sender, NULL) != DNA_OK)
        goto done;
    json = malloc(pt_len + 1);
    if (!json) goto done;
    memcpy(json, pt, pt_len);
    json[pt_len] = '\0';
    if (dht_contactlist_deserialize_from_json(json, &contacts, &count, &salts, &ts) != 0)
        goto done;

    out->items = calloc(count ? count : 1, sizeof(*out->items));
    if (!out->items) goto done;
    out->count = 0;
    out->invalid = 0;
    for (size_t i = 0; i < count; i++) {
        nodus_key_t chk;
        if (!contacts[i] || nc_fp_parse(contacts[i], &chk) != 0) {
            out->invalid++;
            continue;
        }
        nc_contact_t *c = &out->items[out->count++];
        memcpy(c->fp, contacts[i], NC_FP_HEX_LEN);
        c->fp[NC_FP_HEX_LEN] = '\0';
        c->has_salt = salts && salts[i];
        if (c->has_salt) memcpy(c->salt, salts[i], NC_SALT_LEN);
    }
    out->timestamp = ts;
    rc = 0;

done:
    free_parsed(contacts, salts, count);
    if (json) { memset(json, 0, pt_len); free(json); }
    if (pt) { memset(pt, 0, pt_len); free(pt); }
    free(sender);
    free(sig);
    return rc;
}

void nc_contactlist_read(const nc_ctx_t *ctx, nc_contactlist_t *out) {
    if (!out) return;
    memset(out, 0, sizeof(*out));
    nodus_key_t owner, key;
    if (!ctx || !ctx->keys || nc_fp_parse(ctx->keys->fp, &owner) != 0) {
        out->read.outcome = NC_UNREADABLE;
        out->read.why = NC_WHY_BAD_RECORD;
        return;
    }
    list_key(ctx->keys->fp, &key);
    nc_read_one(ctx, &key, &owner, &out->read);
    if (out->read.outcome != NC_FOUND) return;
    const nodus_value_t *v = out->read.value;
    int rc = decode_blob(ctx->keys, v->data, v->data_len, out);
    nc_read_clear(&out->read);
    if (rc != 0) {
        free(out->items);
        out->items = NULL;
        out->count = 0;
        out->invalid = 0;
        out->read.outcome = NC_UNREADABLE;
        out->read.why = NC_WHY_BAD_RECORD;
        return;
    }
    out->read.outcome = NC_FOUND;
}

int nc_contactlist_build(const nc_keys_t *keys, const nc_contact_t *items,
                         size_t count, uint64_t timestamp,
                         uint8_t **out, size_t *out_len) {
    if (!keys || !out || !out_len || (count > 0 && !items)) return NC_ERR_ARG;
    *out = NULL;
    *out_len = 0;

    const char **fps = calloc(count ? count : 1, sizeof(*fps));
    const uint8_t **salts = calloc(count ? count : 1, sizeof(*salts));
    if (!fps || !salts) { free(fps); free(salts); return NC_ERR_INTERNAL; }
    for (size_t i = 0; i < count; i++) {
        fps[i] = items[i].fp;
        salts[i] = items[i].has_salt ? items[i].salt : NULL;
    }

    int rc = NC_ERR_INTERNAL;
    uint8_t sig[DHT_CONTACTLIST_DILITHIUM_SIGNATURE_SIZE];
    size_t sig_len = sizeof(sig);
    uint8_t *enc = NULL, *blob = NULL;
    size_t enc_len = 0, blob_len = 0, json_len = 0;
    dna_context_t *dctx = NULL;
    dna_error_t erc;
    nc_contactlist_t back;
    memset(&back, 0, sizeof(back));

    /* dht_contactlist_publish steps 1-4. */
    char *json = dht_contactlist_serialize_to_json(keys->fp, fps, salts, count, timestamp);
    if (!json) goto done;
    json_len = strlen(json);
    if (qgp_dsa87_sign(sig, &sig_len, (const uint8_t *)json, json_len,
                       keys->id.sk.bytes) != 0)
        goto done;
    dctx = dna_context_new();
    if (!dctx) goto done;
    erc = dna_encrypt_message_raw(dctx, (const uint8_t *)json, json_len,
                                  keys->kyber_pk, keys->id.pk.bytes,
                                  keys->id.sk.bytes, timestamp, &enc, &enc_len);
    dna_context_free(dctx);
    if (erc != DNA_OK) goto done;
    if (dht_contactlist_blob_encode(timestamp, timestamp + DHT_CONTACTLIST_DEFAULT_TTL,
                                    enc, enc_len, sig, sig_len, &blob, &blob_len) != 0)
        goto done;

    /* The reader's path on the bytes that would be published: the same
     * entries must come back. */
    if (decode_blob(keys, blob, blob_len, &back) != 0 || back.count != count ||
        back.invalid != 0 || back.timestamp != timestamp) {
        QGP_LOG_ERROR(LOG_TAG, "built contact list does not read back — not published");
        goto done;
    }
    for (size_t i = 0; i < count; i++) {
        if (strcmp(back.items[i].fp, items[i].fp) != 0 ||
            back.items[i].has_salt != items[i].has_salt ||
            (items[i].has_salt &&
             memcmp(back.items[i].salt, items[i].salt, NC_SALT_LEN) != 0)) {
            QGP_LOG_ERROR(LOG_TAG, "built contact list reads back different entries");
            goto done;
        }
    }
    *out = blob;
    *out_len = blob_len;
    blob = NULL;
    rc = NC_OK;

done:
    nc_contactlist_clear(&back);
    if (json) { memset(json, 0, json_len); free(json); }
    free(enc);
    free(blob);
    free(fps);
    free(salts);
    return rc;
}

int nc_contactlist_add(const nc_ctx_t *ctx, const nc_contact_t *add,
                       size_t n_add, nc_list_result_t *res) {
    if (!res) return NC_ERR_ARG;
    memset(res, 0, sizeof(*res));
    if (!ctx || !ctx->keys) return NC_ERR_ARG;

    /* The input: 128 lowercase hex each, no duplicates. */
    if (!add || n_add == 0) { res->status = NC_LIST_REFUSED; return NC_OK; }
    for (size_t i = 0; i < n_add; i++) {
        nodus_key_t chk;
        if (nc_fp_parse(add[i].fp, &chk) != 0) { res->status = NC_LIST_REFUSED; return NC_OK; }
        for (size_t j = 0; j < i; j++)
            if (strcmp(add[i].fp, add[j].fp) == 0) { res->status = NC_LIST_REFUSED; return NC_OK; }
    }

    /* The base of the write is a read made in this same call. */
    nc_contactlist_t cur;
    nc_contactlist_read(ctx, &cur);
    res->read_outcome = cur.read.outcome;
    res->read_why = cur.read.why;
    if (cur.read.outcome == NC_EMPTY && ctx->fresh) {
        res->created = true;
    } else if (cur.read.outcome != NC_FOUND) {
        /* UNREADABLE, or EMPTY for a restored identity (Q1): no write. */
        nc_contactlist_clear(&cur);
        res->status = NC_LIST_WAIT;
        return NC_OK;
    } else if (cur.invalid > 0) {
        /* Rewriting would drop entries this core cannot carry over. */
        nc_contactlist_clear(&cur);
        res->status = NC_LIST_REFUSED;
        return NC_OK;
    }
    res->count_before = cur.count;

    const size_t cap = cur.count + n_add;
    uint8_t *blob = NULL;
    size_t blob_len = 0;
    nc_contact_t *merged = calloc(cap, sizeof(*merged));
    if (!merged) { nc_contactlist_clear(&cur); return NC_ERR_INTERNAL; }
    size_t n = 0;
    bool changed = res->created;
    for (size_t i = 0; i < cur.count; i++) merged[n++] = cur.items[i];
    for (size_t i = 0; i < n_add; i++) {
        size_t j;
        for (j = 0; j < n; j++)
            if (strcmp(merged[j].fp, add[i].fp) == 0) break;
        if (j == n) {
            merged[n++] = add[i];
            changed = true;
        } else if (!merged[j].has_salt && add[i].has_salt) {
            merged[j].has_salt = true;
            memcpy(merged[j].salt, add[i].salt, NC_SALT_LEN);
            changed = true;
        } else if (merged[j].has_salt && add[i].has_salt &&
                   memcmp(merged[j].salt, add[i].salt, NC_SALT_LEN) != 0) {
            res->salt_kept++;
        }
    }
    nc_contactlist_clear(&cur);

    int rc = NC_OK;
    if (!changed) {
        res->status = NC_LIST_UNCHANGED;
        res->count_after = n;
        goto done;
    }
    rc = nc_contactlist_build(ctx->keys, merged, n, (uint64_t)time(NULL),
                              &blob, &blob_len);
    if (rc != NC_OK) goto done;
    nodus_key_t key;
    list_key(ctx->keys->fp, &key);
    rc = nc_put(ctx, &key, blob, blob_len, NODUS_VALUE_EXCLUSIVE, 0,
                nodus_identity_value_id(&ctx->keys->id));
    res->put_rc = rc;
    res->count_after = n;
    if (rc == NC_ERR_CANCELLED) goto done;
    if (rc == 0) res->status = NC_LIST_PUBLISHED;
    else if (rc == NODUS_ERR_KEY_OWNED) res->status = NC_LIST_TAKEN;
    else res->status = NC_LIST_FAILED;
    rc = NC_OK;

done:
    free(blob);
    memset(merged, 0, cap * sizeof(*merged));
    free(merged);
    return rc;
}
