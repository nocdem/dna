/* Nodus Connect thin core — R3, the per-contact salt agreement: read, the
 * reconcile choice, and the gated publish (design rev 5 §1.4 R3, §4 D5,
 * §6.4 F5; thin-core decision S3/S5 and Q1).
 *
 * Every packet byte is the codec's (messenger/codec/salt_agreement_codec.c,
 * compiled verbatim): parse = data size per version, signature over either
 * party's key, KEM-unwrap of this party's entry; build =
 * salt_agreement_build_packet, the function the app's
 * salt_agreement_publish_internal calls since NC-1b. The web builds packet
 * v1 (round-3 Kyber for both parties): the frozen app publishes v1
 * (salt_agreement_publish passes NULL ML-KEM keys) and reads with
 * salt_agreement_fetch, which cannot unwrap an ML-KEM entry (design R3).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "nc_core.h"

#include "codec/salt_agreement_codec.h"
#include "crypto/hash/qgp_sha3.h"
#include "crypto/utils/qgp_log.h"
#include "crypto/nodus_identity.h"

#include <stdlib.h>
#include <string.h>

#define LOG_TAG "NC_SALT"

/* dht_salt_agreement.c salt_agreement_fetch_internal: "Max 16 valid values" */
#define NC_SALT_MAX_VALID 16

/* salt_agreement_make_key gives a hex string; nodus_ops_get_all_str /
 * nodus_ops_put_str hash that string (nodus_ops.c hash_str). */
static int salt_key(const char *my_fp, const char *peer_fp, nodus_key_t *key) {
    char key_hex[300];
    if (salt_agreement_make_key(my_fp, peer_fp, key_hex, sizeof(key_hex)) != 0)
        return -1;
    nc_key_str(key_hex, key);
    return 0;
}

void nc_salt_read_clear(nc_salt_read_t *r) {
    if (!r) return;
    nc_read_all_clear(&r->read);
    memset(r->salt, 0, sizeof(r->salt));
}

int nc_salt_read(const nc_ctx_t *ctx, const nc_peer_t *peer,
                 nc_salt_read_t *out) {
    if (!out) return NC_ERR_ARG;
    memset(out, 0, sizeof(*out));
    if (!ctx || !ctx->keys || !peer) return NC_ERR_ARG;
    const nc_keys_t *keys = ctx->keys;

    nodus_key_t key;
    if (salt_key(keys->fp, peer->fp, &key) != 0) return NC_ERR_ARG;

    /* G10: only the two parties may write this key. */
    nodus_key_t owners[2];
    if (nc_fp_parse(keys->fp, &owners[0]) != 0 ||
        nc_fp_parse(peer->fp, &owners[1]) != 0)
        return NC_ERR_ARG;
    nc_read_all(ctx, &key, owners, 2, &out->read);
    if (out->read.outcome != NC_FOUND) return NC_OK;

    uint8_t my_fp_bin[FP_BIN_SIZE];
    if (salt_agreement_fp_hex_to_bin(keys->fp, my_fp_bin) != 0) {
        nc_read_all_clear(&out->read);
        return NC_ERR_ARG;
    }

    /* The native collection loop, salt_agreement_fetch_internal. */
    uint8_t valid[NC_SALT_MAX_VALID][NC_SALT_LEN];
    size_t n_valid = 0;
    for (size_t i = 0; i < out->read.count && n_valid < NC_SALT_MAX_VALID; i++) {
        const nodus_value_t *v = out->read.values[i];
        if (v->data_len < PACKET_VERSION_SIZE) continue;
        /* 2-byte big-endian version peek (dht_salt_agreement.c, before
         * salt_agreement_packet_data_size_for_version). */
        uint16_t version = (uint16_t)((uint16_t)v->data[0] << 8 | v->data[1]);
        size_t data_size = salt_agreement_packet_data_size_for_version(version);
        if (data_size == 0 || v->data_len < data_size) continue;
        if (salt_agreement_packet_verify_signature(v->data, v->data_len,
                                                   data_size, keys->id.pk.bytes,
                                                   peer->dsa_pk) != 0)
            continue;
        out->authenticated++;
        uint8_t salt[NC_SALT_LEN];
        if (salt_agreement_packet_decrypt_salt(v->data, v->data_len, my_fp_bin,
                                               keys->kyber_sk, keys->mlkem_sk,
                                               salt) == 0) {
            memcpy(valid[n_valid++], salt, NC_SALT_LEN);
        }
        memset(salt, 0, sizeof(salt));
    }
    nc_read_all_clear(&out->read);

    if (n_valid == 0) { memset(valid, 0, sizeof(valid)); return NC_OK; }

    /* Identical salts collapse; distinct salts: lowest SHA3-512 wins
     * (dht_salt_agreement.c :299-342, design §4 D5). */
    size_t winner = 0;
    uint8_t winner_hash[64];
    qgp_sha3_512(valid[0], NC_SALT_LEN, winner_hash);
    for (size_t i = 1; i < n_valid; i++) {
        uint8_t h[64];
        qgp_sha3_512(valid[i], NC_SALT_LEN, h);
        if (memcmp(h, winner_hash, 64) < 0) {
            winner = i;
            memcpy(winner_hash, h, 64);
        }
    }
    memcpy(out->salt, valid[winner], NC_SALT_LEN);
    out->found = true;
    memset(valid, 0, sizeof(valid));
    return NC_OK;
}

static bool all_zero(const uint8_t *s) {
    for (size_t i = 0; i < NC_SALT_LEN; i++) if (s[i]) return false;
    return true;
}

nc_salt_choice_t nc_salt_choose(const uint8_t *local_or_null,
                                const uint8_t *dht_or_null,
                                uint8_t chosen[NC_SALT_LEN],
                                bool *republish_wanted) {
    if (republish_wanted) *republish_wanted = false;
    memset(chosen, 0, NC_SALT_LEN);
    /* salt_agreement_verify: an all-zero local salt counts as unset. */
    const uint8_t *local = (local_or_null && !all_zero(local_or_null))
                               ? local_or_null : NULL;
    const uint8_t *dht = dht_or_null;

    if (local && dht) {
        if (memcmp(local, dht, NC_SALT_LEN) == 0) {
            memcpy(chosen, local, NC_SALT_LEN);
            return NC_SALT_KEEP_LOCAL;
        }
        uint8_t hl[64], hd[64];
        qgp_sha3_512(local, NC_SALT_LEN, hl);
        qgp_sha3_512(dht, NC_SALT_LEN, hd);
        if (republish_wanted) *republish_wanted = true;
        if (memcmp(hl, hd, 64) <= 0) {
            memcpy(chosen, local, NC_SALT_LEN);
            return NC_SALT_KEEP_LOCAL;
        }
        memcpy(chosen, dht, NC_SALT_LEN);
        return NC_SALT_TAKE_DHT;
    }
    if (dht) {
        memcpy(chosen, dht, NC_SALT_LEN);
        return NC_SALT_TAKE_DHT;
    }
    if (local) {
        /* native: "Migration — publish local salt to DHT" */
        if (republish_wanted) *republish_wanted = true;
        memcpy(chosen, local, NC_SALT_LEN);
        return NC_SALT_KEEP_LOCAL;
    }
    return NC_SALT_NONE;
}

int nc_salt_build(const nc_keys_t *keys, const nc_peer_t *peer,
                  const uint8_t salt[NC_SALT_LEN],
                  uint8_t **out, size_t *out_len) {
    if (!keys || !peer || !salt || !out || !out_len) return NC_ERR_ARG;
    *out = NULL;
    *out_len = 0;
    nodus_key_t chk;
    if (nc_fp_parse(peer->fp, &chk) != 0) return NC_ERR_ARG;

    uint8_t *packet = malloc(PACKET_TOTAL_SIZE_V2);
    if (!packet) return NC_ERR_INTERNAL;
    size_t total = 0;
    /* v1: NULL ML-KEM keys, as salt_agreement_publish passes (file header). */
    if (salt_agreement_build_packet(keys->fp, peer->fp, salt,
                                    keys->kyber_pk, peer->kyber_pk,
                                    NULL, NULL, keys->id.sk.bytes,
                                    packet, &total) != 0) {
        free(packet);
        return NC_ERR_INTERNAL;
    }

    /* The reader's checks on the bytes that would be published: the data
     * size the version announces, the signature under this identity, and
     * this party's entry unwrapping to the same salt. */
    uint8_t my_fp_bin[FP_BIN_SIZE], back[NC_SALT_LEN];
    uint16_t version = (uint16_t)((uint16_t)packet[0] << 8 | packet[1]);
    size_t data_size = salt_agreement_packet_data_size_for_version(version);
    int ok = data_size == PACKET_DATA_SIZE &&
             total == data_size + QGP_DSA87_SIGNATURE_BYTES &&
             salt_agreement_packet_verify_signature(packet, total, data_size,
                                                    keys->id.pk.bytes, NULL) == 0 &&
             salt_agreement_fp_hex_to_bin(keys->fp, my_fp_bin) == 0 &&
             salt_agreement_packet_decrypt_salt(packet, total, my_fp_bin,
                                                keys->kyber_sk, keys->mlkem_sk,
                                                back) == 0 &&
             memcmp(back, salt, NC_SALT_LEN) == 0;
    memset(back, 0, sizeof(back));
    if (!ok) {
        QGP_LOG_ERROR(LOG_TAG, "built salt packet does not read back with "
                      "the codec — not published");
        free(packet);
        return NC_ERR_INTERNAL;
    }
    *out = packet;
    *out_len = total;
    return NC_OK;
}

void nc_salt_sync_clear(nc_salt_sync_t *s) {
    if (!s) return;
    nc_salt_read_clear(&s->read);
    memset(s->chosen, 0, sizeof(s->chosen));
}

int nc_salt_sync(const nc_ctx_t *ctx, const nc_peer_t *peer,
                 const uint8_t *local_or_null, nc_salt_sync_t *res) {
    if (!res) return NC_ERR_ARG;
    memset(res, 0, sizeof(*res));
    res->choice = NC_SALT_NONE;
    if (!ctx || !ctx->keys || !peer) return NC_ERR_ARG;

    /* The base of any write is a read made in this same call. */
    int rc = nc_salt_read(ctx, peer, &res->read);
    if (rc != NC_OK) return rc;
    if (res->read.read.outcome == NC_UNREADABLE ||
        (res->read.read.outcome == NC_FOUND && !res->read.found)) {
        /* Could not read, or values exist but none is usable: no write
         * (S3, S5). The caller keeps its local salt and retries later. */
        res->status = NC_SALT_SYNC_WAIT;
        return NC_OK;
    }

    const uint8_t *dht = res->read.found ? res->read.salt : NULL;
    bool republish = false;
    res->choice = nc_salt_choose(local_or_null, dht, res->chosen, &republish);
    if (!republish) {
        res->status = NC_SALT_SYNC_NOTHING_TO_WRITE;
        return NC_OK;
    }
    if (!dht && !ctx->fresh) {
        /* EMPTY (not proof of absence, design §2.1) for a restored
         * identity: Q1 forbids creating the record. */
        res->status = NC_SALT_SYNC_WAIT;
        return NC_OK;
    }

    /* Publish the winner, as salt_agreement_verify does on a mismatch and
     * on its migration path: PUT EPHEMERAL, SALT_AGREEMENT_TTL, own
     * value_id (salt_agreement_publish_internal -> nodus_ops_put_str). */
    uint8_t *packet = NULL;
    size_t len = 0;
    rc = nc_salt_build(ctx->keys, peer, res->chosen, &packet, &len);
    if (rc != NC_OK) return rc;
    nodus_key_t key;
    if (salt_key(ctx->keys->fp, peer->fp, &key) != 0) {
        free(packet);
        return NC_ERR_ARG;
    }
    rc = nc_put(ctx, &key, packet, len, NODUS_VALUE_EPHEMERAL,
                SALT_AGREEMENT_TTL, nodus_identity_value_id(&ctx->keys->id));
    free(packet);
    res->put_rc = rc;
    if (rc == NC_ERR_CANCELLED) return rc;
    res->status = rc == 0 ? NC_SALT_SYNC_PUBLISHED : NC_SALT_SYNC_FAILED;
    return NC_OK;
}
