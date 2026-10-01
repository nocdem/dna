/* Nodus Connect thin core — R1, the own profile (Anchor record
 * "<fp>:profile"), design rev 5 §1.4 R1 amended by the operator decision of
 * 2026-09-30 (thin-core decision "Profil yazımı"): first publish AND every
 * update EXCLUSIVE, same key, same value_id; NODUS_ERR_KEY_OWNED = "profile
 * address taken", never retried as an overwrite.
 *
 * The record bytes come from messenger/dht/client/dna_profile.c compiled
 * as-is (dna_identity_to_json / _unsigned / _from_json). The signature is
 * over json-c's re-serialisation, so the json-c version matters (design
 * §1.2) — see the NC-2 report.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "nc_core.h"

#include "crypto/hash/qgp_sha3.h"
#include "crypto/utils/qgp_log.h"
#include "crypto/nodus_identity.h"

#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define LOG_TAG "NC_PROFILE"

static void profile_key(const char *fp, nodus_key_t *key) {
    char s[NC_FP_HEX_LEN + 16];
    snprintf(s, sizeof(s), "%s:profile", fp);   /* keyserver_profiles.c:193 */
    nc_key_str(s, key);
}

static void mark_bad_record(nc_read_t *raw) {
    nc_read_clear(raw);
    raw->outcome = NC_UNREADABLE;
    raw->why = NC_WHY_BAD_RECORD;
}

/* R0 for a profile: get-all filtered to the owner (nc_core.h
 * nc_profile_read). A single GET cannot be used: a stranger's newer
 * PERMANENT row at the key would be the node's answer. The owner-row rule
 * (fail closed on an undecodable / bad-signature / wrong-key item next to
 * the owner's row; pick by nc_row_before) is nc_read_one's with an owner —
 * one copy, shared with the contact list and the outbox. */
static void read_owner_row(const nc_ctx_t *ctx, const nodus_key_t *key,
                           const nodus_key_t *owner, nc_read_t *raw) {
    nc_read_one(ctx, key, owner, raw);
    if (raw->foreign > 0)
        QGP_LOG_WARN(LOG_TAG, "%zu profile row(s) of another owner at the "
                     "key (ignored)", raw->foreign);
}

/* dht_keyserver_is_valid_registered_name (keyserver_lookup.c:161-182),
 * mirrored: that file is not in this build. */
static bool name_valid(const char *name) {
    if (!name) return false;
    size_t len = strlen(name);
    if (len == 0 || len >= 64) return false;
    if (len >= 3 && name[len - 1] == '.' && name[len - 2] == '.' && name[len - 3] == '.')
        return false;
    if (len >= 16) {
        bool all_hex = true;
        for (size_t i = 0; i < len && all_hex; i++) {
            char c = name[i];
            all_hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
                      (c >= 'A' && c <= 'F');
        }
        if (all_hex) return false;
    }
    return true;
}

/* One "<name>:lookup" read, owner = `owner`: 1 holds fp, 0 not, -1 fault. */
static int lookup_holds(const nc_ctx_t *ctx, const char *name, const char *fp,
                        const nodus_key_t *owner) {
    char s[80];
    if (snprintf(s, sizeof(s), "%s:lookup", name) >= (int)sizeof(s)) return 0;
    nodus_key_t key;
    nc_key_str(s, &key);
    nc_read_t raw;
    nc_read_one(ctx, &key, owner, &raw);
    int r;
    if (raw.outcome == NC_FOUND && raw.value)
        r = raw.value->data_len >= NC_FP_HEX_LEN &&
            memcmp(raw.value->data, fp, NC_FP_HEX_LEN) == 0;
    else
        r = raw.outcome == NC_EMPTY ? 0 : -1;
    nc_read_clear(&raw);
    return r;
}

int nc_name_verify(const nc_ctx_t *ctx, const char *fp, const char *name) {
    nodus_key_t owner;
    if (!ctx || !fp || nc_fp_parse(fp, &owner) != 0 || !name_valid(name))
        return 0;
    int r = lookup_holds(ctx, name, fp, &owner);
    if (r != 0) return r;
    char lower[64];
    size_t len = strlen(name);
    bool changed = false;
    for (size_t i = 0; i <= len; i++) {
        char c = name[i];
        lower[i] = (c >= 'A' && c <= 'Z') ? (char)(c - 'A' + 'a') : c;
        changed = changed || lower[i] != c;
    }
    return changed ? lookup_holds(ctx, lower, fp, &owner) : 0;
}

void nc_profile_read(const nc_ctx_t *ctx, const char *fp, nc_read_t *raw,
                     dna_unified_identity_t **identity_out,
                     nc_peer_t *peer_out) {
    if (identity_out) *identity_out = NULL;
    nodus_key_t owner, key;
    if (!raw) return;
    if (!fp || nc_fp_parse(fp, &owner) != 0) {
        memset(raw, 0, sizeof(*raw));
        raw->outcome = NC_UNREADABLE;
        raw->why = NC_WHY_BAD_RECORD;
        return;
    }
    profile_key(fp, &key);
    read_owner_row(ctx, &key, &owner, raw);
    if (raw->outcome != NC_FOUND) return;

    /* The frozen app's record checks, keyserver_lookup.c:95-150. */
    const nodus_value_t *v = raw->value;
    char *json = malloc(v->data_len + 1);
    if (!json) { mark_bad_record(raw); return; }
    memcpy(json, v->data, v->data_len);
    json[v->data_len] = '\0';

    dna_unified_identity_t *id = NULL;
    int ok = dna_identity_from_json(json, &id) == 0 && id;
    free(json);
    if (ok) {
        char *unsigned_json = dna_identity_to_json_unsigned(id);
        ok = unsigned_json &&
             qgp_dsa87_verify(id->signature, sizeof(id->signature),
                              (const uint8_t *)unsigned_json,
                              strlen(unsigned_json),
                              id->dilithium_pubkey) == 0;
        free(unsigned_json);
    }
    if (ok) {
        char computed[NC_FP_HEX_LEN + 1];
        ok = qgp_sha3_512_fingerprint(id->dilithium_pubkey,
                                      sizeof(id->dilithium_pubkey),
                                      computed) == 0 &&
             strcmp(computed, fp) == 0;
    }
    if (!ok) {
        QGP_LOG_WARN(LOG_TAG, "profile %.16s... failed the record checks", fp);
        dna_identity_free(id);
        mark_bad_record(raw);
        return;
    }
    if (peer_out) {
        memset(peer_out, 0, sizeof(*peer_out));
        memcpy(peer_out->fp, fp, NC_FP_HEX_LEN);
        memcpy(peer_out->dsa_pk, id->dilithium_pubkey, sizeof(peer_out->dsa_pk));
        memcpy(peer_out->kyber_pk, id->kyber_pubkey, sizeof(peer_out->kyber_pk));
        if (id->has_mlkem_pubkey) {
            memcpy(peer_out->mlkem_pk, id->mlkem_pubkey,
                   sizeof(peer_out->mlkem_pk));
            peer_out->has_mlkem = true;
        }
    }
    if (identity_out) *identity_out = id;
    else dna_identity_free(id);
}

/* ── the edit ─────────────────────────────────────────────────────── */

typedef struct {
    const char *name;
    size_t      offset;
    size_t      size;
} field_t;

#define F(member) { #member, offsetof(dna_unified_identity_t, member), \
                    sizeof(((dna_unified_identity_t *)0)->member) }
static const field_t TOP_FIELDS[] = {
    F(bio), F(location), F(website), F(avatar_base64),
};
#undef F
#define W(member) { #member, offsetof(dna_unified_identity_t, wallets) + \
                    offsetof(dna_wallets_t, member), \
                    sizeof(((dna_wallets_t *)0)->member) }
static const field_t WALLET_FIELDS[] = {
    W(backbone), W(eth), W(sol), W(trx), W(bsc),
};
#undef W
#define S(member) { #member, offsetof(dna_unified_identity_t, socials) + \
                    offsetof(dna_socials_t, member), \
                    sizeof(((dna_socials_t *)0)->member) }
static const field_t SOCIAL_FIELDS[] = {
    S(telegram), S(x), S(github), S(facebook), S(instagram), S(linkedin),
    S(google),
};
#undef S

#define COUNT(a) (sizeof(a) / sizeof((a)[0]))

static const field_t *find_field(const field_t *list, size_t n,
                                 const char *name) {
    for (size_t i = 0; i < n; i++)
        if (strcmp(list[i].name, name) == 0) return &list[i];
    return NULL;
}

/* Validate (apply == false) or apply (apply == true) one object level. */
static int patch_level(json_object *obj, const field_t *list, size_t n,
                       dna_unified_identity_t *id, bool apply) {
    json_object_object_foreach(obj, k, v) {
        const field_t *f = find_field(list, n, k);
        if (!f || !json_object_is_type(v, json_type_string)) return -1;
        const char *s = json_object_get_string(v);
        size_t len = (size_t)json_object_get_string_len(v);
        if (!s || len >= f->size || memchr(s, '\0', len)) return -1;
        if (apply) {
            char *dst = (char *)id + f->offset;
            memset(dst, 0, f->size);
            memcpy(dst, s, len);
        }
    }
    return 0;
}

static int patch_apply(json_object *patch, dna_unified_identity_t *id,
                       bool apply) {
    json_object_object_foreach(patch, k, v) {
        if (strcmp(k, "wallets") == 0 || strcmp(k, "socials") == 0) {
            if (!json_object_is_type(v, json_type_object)) return -1;
            bool w = k[0] == 'w';
            if (patch_level(v, w ? WALLET_FIELDS : SOCIAL_FIELDS,
                            w ? COUNT(WALLET_FIELDS) : COUNT(SOCIAL_FIELDS),
                            id, apply) != 0)
                return -1;
            continue;
        }
        const field_t *f = find_field(TOP_FIELDS, COUNT(TOP_FIELDS), k);
        if (!f || !json_object_is_type(v, json_type_string)) return -1;
        const char *s = json_object_get_string(v);
        size_t len = (size_t)json_object_get_string_len(v);
        if (!s || len >= f->size || memchr(s, '\0', len)) return -1;
        if (apply) {
            char *dst = (char *)id + f->offset;
            memset(dst, 0, f->size);
            memcpy(dst, s, len);
        }
    }
    return 0;
}

int nc_profile_publish(const nc_ctx_t *ctx, const char *patch_json,
                       nc_profile_result_t *res) {
    if (!res) return NC_ERR_ARG;
    memset(res, 0, sizeof(*res));
    if (!ctx || !ctx->keys || !patch_json) return NC_ERR_ARG;

    json_object *patch = json_tokener_parse(patch_json);
    if (!patch || !json_object_is_type(patch, json_type_object) ||
        patch_apply(patch, NULL, false) != 0) {
        if (patch) json_object_put(patch);
        res->status = NC_PROFILE_BAD_PATCH;
        return NC_OK;
    }

    const nc_keys_t *keys = ctx->keys;
    dna_unified_identity_t *id = NULL;
    /* The base of every write is a FOUND read made in this same call —
     * never a cached copy (design §6.4 F4: nothing here relies on a node
     * keeping the higher seq). */
    nc_profile_read(ctx, keys->fp, &res->read, &id, NULL);

    if (res->read.outcome == NC_EMPTY && ctx->fresh) {
        /* First-time record, keyserver_profiles.c:43-75 without a name. */
        id = dna_identity_create();
        if (!id) { json_object_put(patch); return NC_ERR_INTERNAL; }
        memcpy(id->fingerprint, keys->fp, NC_FP_HEX_LEN);
        memcpy(id->dilithium_pubkey, keys->id.pk.bytes,
               sizeof(id->dilithium_pubkey));
        memcpy(id->kyber_pubkey, keys->kyber_pk, sizeof(id->kyber_pubkey));
        res->created = true;
    } else if (res->read.outcome != NC_FOUND) {
        /* EMPTY for a restored identity, or UNREADABLE: no write (Q1, S3). */
        nc_read_clear(&res->read);
        json_object_put(patch);
        res->status = NC_PROFILE_WAIT;
        return NC_OK;
    }
    nc_read_clear(&res->read);

    /* mlkem_pubkey sits outside the signed part (dna_profile.c
     * identity_to_json_internal; keyserver_profiles.c:121-124). */
    memcpy(id->mlkem_pubkey, keys->mlkem_pk, sizeof(id->mlkem_pubkey));
    id->has_mlkem_pubkey = true;
    patch_apply(patch, id, true);
    json_object_put(patch);

    /* keyserver_profiles.c:156-184 */
    id->timestamp = (uint64_t)time(NULL);
    id->version++;
    int rc = NC_ERR_INTERNAL;
    char *unsigned_json = dna_identity_to_json_unsigned(id);
    size_t siglen = sizeof(id->signature);
    if (!unsigned_json ||
        qgp_dsa87_sign(id->signature, &siglen, (const uint8_t *)unsigned_json,
                       strlen(unsigned_json), keys->id.sk.bytes) != 0) {
        free(unsigned_json);
        dna_identity_free(id);
        return NC_ERR_INTERNAL;
    }
    free(unsigned_json);
    char *json = dna_identity_to_json(id);
    res->version = id->version;
    dna_identity_free(id);
    if (!json) return NC_ERR_INTERNAL;

    nodus_key_t key;
    profile_key(keys->fp, &key);
    rc = nc_put(ctx, &key, (const uint8_t *)json, strlen(json),
                NODUS_VALUE_EXCLUSIVE, 0, nodus_identity_value_id(&keys->id));
    free(json);
    res->put_rc = rc;
    if (rc == NC_ERR_CANCELLED) return rc;
    if (rc == 0) res->status = NC_PROFILE_PUBLISHED;
    else if (rc == NODUS_ERR_KEY_OWNED) res->status = NC_PROFILE_TAKEN;
    else res->status = NC_PROFILE_FAILED;
    return NC_OK;
}
