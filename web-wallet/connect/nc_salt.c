/* Nodus Connect thin core — R3, the per-contact salt agreement: READ and
 * the reconcile CHOICE only (design rev 5 §1.4 R3, §4 D5, §6.4 F5).
 *
 * The PUBLISH is not here: the salt packet is built inline in
 * dht_salt_agreement.c salt_agreement_publish_internal (:49-176), which
 * NC-1 did not extract; re-deriving that layout here is what design §1.3
 * rules out. The parse side is the codec's (messenger/codec/
 * salt_agreement_codec.c): data size per version, signature over either
 * party's key, KEM-unwrap of this party's entry.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "nc_core.h"

#include "codec/salt_agreement_codec.h"
#include "crypto/hash/qgp_sha3.h"
#include "crypto/utils/qgp_log.h"

#include <string.h>

#define LOG_TAG "NC_SALT"

/* dht_salt_agreement.c salt_agreement_fetch_internal: "Max 16 valid values" */
#define NC_SALT_MAX_VALID 16

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

    /* salt_agreement_make_key gives a hex string; nodus_ops_get_all_str
     * hashes that string (nodus_ops.c hash_str). */
    char key_hex[300];
    if (salt_agreement_make_key(keys->fp, peer->fp, key_hex,
                                sizeof(key_hex)) != 0)
        return NC_ERR_ARG;
    nodus_key_t key;
    nc_key_str(key_hex, &key);

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
