/* Nodus Connect thin core — R2, contact requests (design rev 5 §1.4 R2 and
 * §6.4 F3 / F5 / F6).
 *
 * Wire bytes: messenger/codec/contact_request_codec.c compiled verbatim
 * (dht_serialize_contact_request, dht_deserialize_contact_request,
 * dht_verify_contact_request, dht_generate_requests_inbox_key,
 * dht_fingerprint_to_value_id).
 *
 * THE SIGNING PREIMAGE. dht_send_contact_request builds it inline
 * (dht_contact_request.c:99-159) and dht_verify_contact_request rebuilds it
 * inline (contact_request_codec.c:377-437); NC-1 extracted no function that
 * returns it. It is NOT re-written here. dht_serialize_contact_request
 * (contact_request_codec.c:136-183) writes the same fields in the same
 * order with the same padding, followed by a 2-byte signature length and
 * the signature; with signature_len 0 its output is the preimage followed
 * by two zero bytes. nc_request_build signs that prefix and then runs the
 * codec's own deserialize + verify on the final bytes — the exact check the
 * frozen app applies on receipt (dht_fetch_contact_requests,
 * dht_contact_request.c:298-308). If the prefix were ever not the preimage,
 * the verify fails and nothing is published.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "nc_core.h"

#include "dht/shared/dht_contact_request.h"
#include "crypto/utils/qgp_log.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

#define LOG_TAG "NC_REQUEST"

/* F6: requests use the codec's value_id (first 16 hex chars of the SENDER
 * fingerprint, big-endian, contact_request_codec.c:58-86) — deliberately not
 * nodus_identity_value_id (first 8 bytes of node_id, little-endian). */
static uint64_t request_value_id(const char *sender_fp) {
    return dht_fingerprint_to_value_id(sender_fp);
}

/* SHA3-512(SHA3-512("<fp>:requests")): dht_generate_requests_inbox_key
 * hashes the string, nodus_ops_put / nodus_ops_get_all hash those 64 bytes
 * again (nodus_ops.c:116-126, :241-256). */
static void inbox_key(const char *fp, nodus_key_t *key) {
    uint8_t inbox[64];
    dht_generate_requests_inbox_key(fp, inbox);
    nc_key_bytes(inbox, sizeof(inbox), key);
}

int nc_request_build(const nc_keys_t *keys, const char *recipient_fp,
                     const char *message, const uint8_t *salt,
                     uint8_t **out, size_t *out_len) {
    if (!keys || !out || !out_len) return NC_ERR_ARG;
    *out = NULL;
    *out_len = 0;
    nodus_key_t chk_fp;
    if (nc_fp_parse(recipient_fp, &chk_fp) != 0) return NC_ERR_ARG;
    if (message && strnlen(message, 256) > 255) return NC_ERR_ARG;

    dht_contact_request_t *req = calloc(1, sizeof(*req));
    dht_contact_request_t *chk = calloc(1, sizeof(*chk));
    uint8_t *pre = NULL;
    size_t pre_len = 0;
    int rc = NC_ERR_INTERNAL;
    if (!req || !chk) goto done;

    /* The fields of dht_send_contact_request (dht_contact_request.c:62-97). */
    req->magic = DHT_CONTACT_REQUEST_MAGIC;
    req->timestamp = (uint64_t)time(NULL);
    req->expiry = req->timestamp + DHT_CONTACT_REQUEST_DEFAULT_TTL;
    if (salt) {
        req->version = DHT_CONTACT_REQUEST_VERSION_SALT;
        memcpy(req->dht_salt, salt, DHT_CONTACT_SALT_SIZE_CR);
        req->has_dht_salt = true;
    } else {
        req->version = DHT_CONTACT_REQUEST_VERSION;
    }
    memcpy(req->sender_fingerprint, keys->fp, NC_FP_HEX_LEN);
    req->sender_fingerprint[NC_FP_HEX_LEN] = '\0';
    req->sender_name[0] = '\0';                 /* the web registers no name */
    memcpy(req->sender_dilithium_pubkey, keys->id.pk.bytes,
           DHT_DILITHIUM5_PUBKEY_SIZE);
    if (message) memcpy(req->message, message, strlen(message));

    /* Preimage = serialisation with an empty signature, minus its 2-byte
     * signature length (see the file header). */
    req->signature_len = 0;
    if (dht_serialize_contact_request(req, &pre, &pre_len) != 0 ||
        pre_len < 2)
        goto done;
    size_t sig_len = DHT_DILITHIUM5_SIG_MAX_SIZE;
    if (qgp_dsa87_sign(req->signature, &sig_len, pre, pre_len - 2,
                       keys->id.sk.bytes) != 0)
        goto done;
    req->signature_len = sig_len;
    if (dht_serialize_contact_request(req, out, out_len) != 0) goto done;

    /* The receiver's check, on the bytes that would be published. */
    if (dht_deserialize_contact_request(*out, *out_len, chk) != 0 ||
        dht_verify_contact_request(chk) != 0 ||
        strcmp(chk->sender_fingerprint, keys->fp) != 0 ||
        chk->version != req->version ||
        strcmp(chk->message, req->message) != 0 ||
        (salt && memcmp(chk->dht_salt, salt, DHT_CONTACT_SALT_SIZE_CR) != 0)) {
        QGP_LOG_ERROR(LOG_TAG, "built request does not verify with the "
                      "codec — not published");
        free(*out);
        *out = NULL;
        *out_len = 0;
        goto done;
    }
    rc = NC_OK;

done:
    free(pre);
    free(req);
    free(chk);
    return rc;
}

static int request_put(const nc_ctx_t *ctx, const char *recipient_fp,
                       const char *message, const uint8_t *salt) {
    if (!ctx || !ctx->keys) return NC_ERR_ARG;
    uint8_t *bytes = NULL;
    size_t len = 0;
    int rc = nc_request_build(ctx->keys, recipient_fp, message, salt,
                              &bytes, &len);
    if (rc != NC_OK) return rc;
    nodus_key_t key;
    inbox_key(recipient_fp, &key);
    rc = nc_put(ctx, &key, bytes, len, NODUS_VALUE_EPHEMERAL,
                DHT_CONTACT_REQUEST_DEFAULT_TTL,
                request_value_id(ctx->keys->fp));
    free(bytes);
    return rc;
}

int nc_request_send(const nc_ctx_t *ctx, const char *recipient_fp,
                    const char *message, const uint8_t *salt) {
    return request_put(ctx, recipient_fp, message, salt);
}

int nc_request_accept(const nc_ctx_t *ctx, const char *requester_fp,
                      const uint8_t *salt_or_null) {
    return request_put(ctx, requester_fp, NC_CONTACT_ACCEPTED_MSG,
                       salt_or_null);
}

int nc_request_cancel(const nc_ctx_t *ctx, const char *recipient_fp) {
    if (!ctx || !ctx->keys) return NC_ERR_ARG;
    nodus_key_t chk;
    if (nc_fp_parse(recipient_fp, &chk) != 0) return NC_ERR_ARG;
    nodus_key_t key;
    inbox_key(recipient_fp, &key);
    const uint8_t empty_data[1] = { 0 };       /* dht_contact_request.c:375 */
    return nc_put(ctx, &key, empty_data, sizeof(empty_data),
                  NODUS_VALUE_EPHEMERAL, 1, request_value_id(ctx->keys->fp));
}

void nc_requests_clear(nc_requests_t *r) {
    if (!r) return;
    nc_read_all_clear(&r->read);
    free(r->items);
    r->items = NULL;
    r->count = 0;
}

int nc_requests_fetch(const nc_ctx_t *ctx, nc_requests_t *out) {
    if (!out) return NC_ERR_ARG;
    memset(out, 0, sizeof(*out));
    if (!ctx || !ctx->keys) return NC_ERR_ARG;

    nodus_key_t key;
    inbox_key(ctx->keys->fp, &key);
    nc_read_all(ctx, &key, NULL, 0, &out->read);
    if (out->read.outcome != NC_FOUND) return NC_OK;

    out->items = calloc(out->read.count, sizeof(nc_request_t));
    dht_contact_request_t *r = calloc(1, sizeof(*r));
    if (!out->items || !r) {
        free(r);
        nc_requests_clear(out);
        return NC_ERR_INTERNAL;
    }
    for (size_t i = 0; i < out->read.count; i++) {
        const nodus_value_t *v = out->read.values[i];
        if (v->data_len == 1) { out->cancelled++; continue; }
        memset(r, 0, sizeof(*r));
        nodus_key_t sender;
        if (dht_deserialize_contact_request(v->data, v->data_len, r) != 0 ||
            dht_verify_contact_request(r) != 0 ||
            nc_fp_parse(r->sender_fingerprint, &sender) != 0 ||
            memcmp(sender.bytes, v->owner_fp.bytes, NODUS_KEY_BYTES) != 0) {
            out->bad_request++;
            continue;
        }
        /* One entry per sender: the newest timestamp, the first in reply
         * order on a tie (deterministic for a given reply). */
        nc_request_t *slot = NULL;
        for (size_t j = 0; j < out->count; j++) {
            if (strcmp(out->items[j].sender_fp, r->sender_fingerprint) == 0) {
                slot = r->timestamp > out->items[j].timestamp
                           ? &out->items[j] : NULL;
                if (!slot) goto next;
                break;
            }
        }
        if (!slot) slot = &out->items[out->count++];
        memset(slot, 0, sizeof(*slot));
        memcpy(slot->sender_fp, r->sender_fingerprint, NC_FP_HEX_LEN);
        memcpy(slot->sender_name, r->sender_name, sizeof(slot->sender_name));
        slot->sender_name[sizeof(slot->sender_name) - 1] = '\0';
        memcpy(slot->message, r->message, sizeof(slot->message));
        slot->message[sizeof(slot->message) - 1] = '\0';
        slot->timestamp = r->timestamp;
        slot->expiry = r->expiry;
        slot->has_salt = r->has_dht_salt;
        if (r->has_dht_salt) memcpy(slot->salt, r->dht_salt, NC_SALT_LEN);
        slot->is_acceptance = strcmp(slot->message, NC_CONTACT_ACCEPTED_MSG) == 0;
    next:;
    }
    free(r);
    nc_read_all_clear(&out->read);     /* values freed, counters kept */
    return NC_OK;
}
