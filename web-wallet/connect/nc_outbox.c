/* Nodus Connect thin core — R5, the 1:1 outbox (daily bucket) and the ACK
 * (design rev 5 §1.4 R5, §5 G10 / G11).
 *
 * Wire bytes: messenger/codec/seal_multi_codec.c (2-recipient Seal),
 * messenger/codec/offline_queue_codec.c (day blob, ACK key),
 * messenger/codec/dm_outbox_codec.c (bucket key), messenger/dna_api.c
 * (Seal decode, authorship) — all compiled verbatim.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "nc_core.h"

#include "codec/seal_multi_codec.h"
#include "dht/shared/dht_dm_outbox.h"
#include "dht/shared/dht_offline_queue.h"
#include "dna_api.h"
#include "crypto/utils/qgp_types.h"
#include "crypto/utils/qgp_log.h"
#include "crypto/nodus_identity.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

#define LOG_TAG "NC_OUTBOX"

/* SHA3-512 of the bucket key string (nodus_ops_put_str / _get_str). */
static int outbox_key(const char *sender_fp, const char *recipient_fp,
                      uint64_t day, const uint8_t salt[NC_SALT_LEN],
                      nodus_key_t *key) {
    char s[512];
    if (dht_dm_outbox_make_key(sender_fp, recipient_fp, day, salt, s,
                               sizeof(s)) != 0)
        return -1;
    nc_key_str(s, key);
    return 0;
}

int nc_outbox_build(const nc_keys_t *keys, const nc_peer_t *peer,
                    const nc_outmsg_t *msgs, size_t n,
                    uint8_t **blob, size_t *blob_len, uint8_t *alg_out) {
    if (!keys || !peer || !blob || !blob_len || (n > 0 && !msgs))
        return NC_ERR_ARG;
    *blob = NULL;
    *blob_len = 0;
    if (n == 0 || n > NC_OUTBOX_MAX_MESSAGES) return NC_ERR_ARG;

    /* All-or-nothing algorithm (messages.c:411-449): this identity always
     * has an ML-KEM key; ML-KEM is used only if the peer's record has one. */
    uint8_t alg = peer->has_mlkem ? (uint8_t)QGP_KEY_TYPE_MLKEM1024
                                  : (uint8_t)QGP_KEY_TYPE_KEM1024;
    uint8_t *pubkeys[2];
    if (alg == QGP_KEY_TYPE_MLKEM1024) {
        pubkeys[0] = (uint8_t *)keys->mlkem_pk;      /* sender first */
        pubkeys[1] = (uint8_t *)peer->mlkem_pk;
    } else {
        pubkeys[0] = (uint8_t *)keys->kyber_pk;
        pubkeys[1] = (uint8_t *)peer->kyber_pk;
    }
    if (alg_out) *alg_out = alg;

    /* The encoder takes a qgp_key_t; it reads public_key and private_key
     * (seal_multi_codec.c). The key bytes stay in nc_keys_t. */
    qgp_key_t sign_key;
    memset(&sign_key, 0, sizeof(sign_key));
    sign_key.type = QGP_KEY_TYPE_DSA87;
    sign_key.public_key = (uint8_t *)keys->id.pk.bytes;
    sign_key.public_key_size = QGP_DSA87_PUBLICKEYBYTES;
    sign_key.private_key = (uint8_t *)keys->id.sk.bytes;
    sign_key.private_key_size = QGP_DSA87_SECRETKEYBYTES;

    dht_offline_message_t *om = calloc(n, sizeof(*om));
    if (!om) return NC_ERR_INTERNAL;
    int rc = NC_ERR_INTERNAL;
    size_t built = 0;
    for (size_t i = 0; i < n; i++) {
        if (!msgs[i].text) { rc = NC_ERR_ARG; goto done; }
        uint8_t *ct = NULL;
        size_t ct_len = 0;
        if (messenger_encrypt_multi_recipient(msgs[i].text,
                                              strlen(msgs[i].text), pubkeys, 2,
                                              &sign_key, msgs[i].timestamp,
                                              alg, &ct, &ct_len) != 0) {
            /* native skips a message it cannot seal (messages.c:477-480);
             * the web refuses the whole blob instead, so the caller never
             * believes a message went out that did not. */
            goto done;
        }
        om[built].seq_num = msgs[i].seq;
        om[built].timestamp = msgs[i].timestamp;
        om[built].expiry = msgs[i].timestamp + DNA_DM_OUTBOX_TTL;
        om[built].sender = strdup(keys->fp);
        om[built].recipient = strdup(peer->fp);
        om[built].ciphertext = ct;
        om[built].ciphertext_len = ct_len;
        built++;
        if (!om[built - 1].sender || !om[built - 1].recipient) goto done;
    }
    if (dht_serialize_messages(om, built, blob, blob_len) != 0) goto done;
    rc = NC_OK;

done:
    dht_offline_messages_free(om, built);
    memset(&sign_key, 0, sizeof(sign_key));
    return rc;
}

int nc_outbox_publish(const nc_ctx_t *ctx, const nc_peer_t *peer,
                      const uint8_t salt[NC_SALT_LEN], uint64_t day,
                      const nc_outmsg_t *msgs, size_t n, uint8_t *alg_out) {
    if (!ctx || !ctx->keys || !peer || !salt) return NC_ERR_ARG;
    /* CORE-04: no salt, no send (messages.c:505-515) — `salt` is required
     * by the signature above; dht_dm_outbox_make_key refuses NULL too. */
    nodus_key_t key;
    if (outbox_key(ctx->keys->fp, peer->fp, day, salt, &key) != 0)
        return NC_ERR_ARG;
    uint8_t *blob = NULL;
    size_t len = 0;
    int rc = nc_outbox_build(ctx->keys, peer, msgs, n, &blob, &len, alg_out);
    if (rc != NC_OK) return rc;
    rc = nc_put(ctx, &key, blob, len, NODUS_VALUE_EPHEMERAL, DNA_DM_OUTBOX_TTL,
                nodus_identity_value_id(&ctx->keys->id));
    free(blob);
    return rc;
}

void nc_inbox_clear(nc_inbox_t *in) {
    if (!in) return;
    nc_read_clear(&in->read);
    for (size_t i = 0; i < in->count; i++) free(in->items[i].plaintext);
    free(in->items);
    in->items = NULL;
    in->count = 0;
}

int nc_outbox_fetch_day(const nc_ctx_t *ctx, const nc_peer_t *peer,
                        const uint8_t salt[NC_SALT_LEN], uint64_t day,
                        nc_inbox_t *out) {
    if (!out) return NC_ERR_ARG;
    memset(out, 0, sizeof(*out));
    if (!ctx || !ctx->keys || !peer || !salt) return NC_ERR_ARG;

    nodus_key_t key, owner;
    /* the peer is the sender, this identity the recipient
     * (dht_dm_outbox_sync_day) */
    if (outbox_key(peer->fp, ctx->keys->fp, day, salt, &key) != 0 ||
        nc_fp_parse(peer->fp, &owner) != 0)
        return NC_ERR_ARG;
    nc_read_one(ctx, &key, &owner, &out->read);
    if (out->read.outcome != NC_FOUND) return NC_OK;

    dht_offline_message_t *msgs = NULL;
    size_t count = 0;
    const nodus_value_t *v = out->read.value;
    if (dht_deserialize_messages(v->data, v->data_len, &msgs, &count) != 0) {
        nc_read_clear(&out->read);
        out->read.outcome = NC_UNREADABLE;
        out->read.why = NC_WHY_BAD_RECORD;
        return NC_OK;
    }
    nc_read_clear(&out->read);                /* outcome FOUND is kept */
    uint8_t peer_fp_bin[64];
    {
        nodus_key_t k;
        nc_fp_parse(peer->fp, &k);
        memcpy(peer_fp_bin, k.bytes, sizeof(peer_fp_bin));
    }
    out->items = count ? calloc(count, sizeof(nc_inmsg_t)) : NULL;
    if (count && !out->items) {
        dht_offline_messages_free(msgs, count);
        return NC_ERR_INTERNAL;
    }
    dna_context_t *dctx = dna_context_new();
    if (!dctx) {
        dht_offline_messages_free(msgs, count);
        nc_inbox_clear(out);
        return NC_ERR_INTERNAL;
    }
    for (size_t i = 0; i < count; i++) {
        uint8_t *pt = NULL, *claimed = NULL, *sig = NULL;
        size_t pt_len = 0, claimed_len = 0, sig_len = 0;
        uint64_t ts = 0;
        int ok = dna_decrypt_message_raw_alg(dctx, msgs[i].ciphertext,
                                             msgs[i].ciphertext_len,
                                             ctx->keys->kyber_sk,
                                             ctx->keys->mlkem_sk,
                                             &pt, &pt_len, &claimed,
                                             &claimed_len, &sig, &sig_len,
                                             &ts) == DNA_OK &&
                 pt && pt_len > 0;
        /* Authorship gate (messenger_transport.c:651-716): the claimed
         * sender must be the peer whose outbox this is, and the signature
         * must verify under the peer's verified ML-DSA key. */
        ok = ok && claimed && claimed_len == 64 && sig && sig_len > 0 &&
             memcmp(claimed, peer_fp_bin, 64) == 0 &&
             dna_verify_seal_authorship(pt, pt_len, sig, sig_len,
                                        peer->dsa_pk, sizeof(peer->dsa_pk),
                                        claimed, NULL) == DNA_OK;
        if (ok) {
            nc_inmsg_t *m = &out->items[out->count++];
            m->seq = msgs[i].seq_num;
            m->sender_timestamp = ts;
            m->plaintext = pt;
            m->plaintext_len = pt_len;
            pt = NULL;
        } else {
            out->dropped++;
        }
        free(pt);
        free(claimed);
        free(sig);
    }
    dna_context_free(dctx);
    dht_offline_messages_free(msgs, count);
    return NC_OK;
}

/* SHA3-512(dht_generate_ack_key(...)): the codec hashes the base string,
 * nodus_ops_put / _get hash those 64 bytes again (nodus_ops.c:116-126). */
static int ack_key(const char *recipient, const char *sender,
                   const uint8_t salt[NC_SALT_LEN], nodus_key_t *key) {
    uint8_t k64[64];
    if (dht_generate_ack_key(recipient, sender, salt, k64) != 0) return -1;
    nc_key_bytes(k64, sizeof(k64), key);
    return 0;
}

int nc_ack_publish(const nc_ctx_t *ctx, const char *peer_fp,
                   const uint8_t salt[NC_SALT_LEN]) {
    if (!ctx || !ctx->keys || !peer_fp || !salt) return NC_ERR_ARG;
    nodus_key_t chk, key;
    if (nc_fp_parse(peer_fp, &chk) != 0) return NC_ERR_ARG;
    /* I am the recipient (ACK owner), the peer the sender (:136-138). */
    if (ack_key(ctx->keys->fp, peer_fp, salt, &key) != 0) return NC_ERR_ARG;
    /* The value: unix time, 8 bytes big-endian (dht_offline_queue.c
     * :145-157). Reproduced, not extracted: dht_publish_ack builds it
     * inline. */
    uint64_t t = (uint64_t)time(NULL);
    uint8_t value[8];
    for (int i = 0; i < 8; i++) value[i] = (uint8_t)(t >> (56 - 8 * i));
    return nc_put(ctx, &key, value, sizeof(value), NODUS_VALUE_EPHEMERAL,
                  DHT_ACK_TTL, 1 /* value_id 1, :160-163 */);
}

void nc_ack_read(const nc_ctx_t *ctx, const char *peer_fp,
                 const uint8_t salt[NC_SALT_LEN], nc_read_t *raw,
                 uint64_t *ack_ts) {
    if (ack_ts) *ack_ts = 0;
    if (!raw) return;
    memset(raw, 0, sizeof(*raw));
    nodus_key_t owner, key;
    if (!ctx || !ctx->keys || !salt || nc_fp_parse(peer_fp, &owner) != 0 ||
        ack_key(peer_fp, ctx->keys->fp, salt, &key) != 0) {
        raw->outcome = NC_UNREADABLE;
        raw->why = NC_WHY_BAD_RECORD;
        return;
    }
    nc_read_one(ctx, &key, &owner, raw);
    if (raw->outcome != NC_FOUND) return;
    const nodus_value_t *v = raw->value;
    if (v->data_len != 8) {                     /* ack_listen_callback */
        nc_read_clear(raw);
        raw->outcome = NC_UNREADABLE;
        raw->why = NC_WHY_BAD_RECORD;
        return;
    }
    uint64_t t = 0;
    for (int i = 0; i < 8; i++) t = (t << 8) | v->data[i];
    if (ack_ts) *ack_ts = t;
    nc_read_clear(raw);
}
