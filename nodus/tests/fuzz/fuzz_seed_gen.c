/**
 * @file fuzz_seed_gen.c
 * @brief Writes the seed corpora for the nodus fuzz targets.
 *
 * Every seed is produced by the REAL encoders — nothing here spells out a
 * wire byte by hand:
 *   value/      nodus_value_create + nodus_value_sign + nodus_value_serialize
 *   t2_decode/  nodus_t2_result / _result_multi / _result_empty / _error /
 *               _pong / _put_ok / _value_changed / _challenge / _auth_ok,
 *               plus one of them wrapped by nodus_frame_encode
 *   cbor/       the same tier-2 payloads and a serialized value (the CBOR
 *               decoder is fed exactly what nodus puts on the wire)
 *
 * The signing identity comes from nodus_identity_from_seed() with a fixed
 * seed, so the owner key is the same on every run. The signatures are NOT:
 * shared/crypto/sign/dsa/config.h:6 defines DILITHIUM_RANDOMIZED_SIGNING, so
 * a re-run writes different signature bytes (every one of them valid). The
 * seeds are starting points for the fuzzer, not test vectors; nothing
 * compares them byte-for-byte.
 *
 * Usage: fuzz_seed_gen <corpus-dir>
 *   <corpus-dir>/{value,t2_decode,cbor}/ are created if missing.
 * Exit status 0 = every seed written.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include <errno.h>

#include "crypto/utils/qgp_log.h"
#include "crypto/nodus_identity.h"
#include "crypto/nodus_sign.h"
#include "core/nodus_value.h"
#include "protocol/nodus_tier2.h"
#include "protocol/nodus_wire.h"

#define LOG_TAG "FUZZ_SEED_GEN"

#define SEED_BUF_CAP (64u * 1024u)

static const char *g_root;
static int g_failures;

static int ensure_dir(const char *path) {
    if (mkdir(path, 0755) == 0 || errno == EEXIST) {
        return 0;
    }
    QGP_LOG_ERROR(LOG_TAG, "mkdir %s failed", path);
    return -1;
}

static void write_seed(const char *sub, const char *name, const uint8_t *data, size_t len) {
    char path[4096];
    snprintf(path, sizeof(path), "%s/%s/%s", g_root, sub, name);
    FILE *f = fopen(path, "wb");
    if (!f || (len && fwrite(data, 1, len, f) != len)) {
        QGP_LOG_ERROR(LOG_TAG, "write %s failed", path);
        g_failures++;
    } else {
        QGP_LOG_INFO(LOG_TAG, "wrote %s (%zu bytes)", path, len);
    }
    if (f) {
        fclose(f);
    }
}

/* Encoder result check: an encoder that fails is a generator failure */
static void write_encoded(const char *sub, const char *name, int rc,
                          const uint8_t *buf, size_t len) {
    if (rc != 0 || len == 0) {
        QGP_LOG_ERROR(LOG_TAG, "encoder for %s/%s failed", sub, name);
        g_failures++;
        return;
    }
    write_seed(sub, name, buf, len);
}

static nodus_value_t *make_value(const nodus_identity_t *id, const char *key_str,
                                 const char *payload, nodus_value_type_t type,
                                 uint32_t ttl, uint64_t seq) {
    nodus_key_t key_hash;
    if (nodus_hash((const uint8_t *)key_str, strlen(key_str), &key_hash) != 0) {
        return NULL;
    }
    nodus_value_t *val = NULL;
    if (nodus_value_create(&key_hash, (const uint8_t *)payload, strlen(payload),
                           type, ttl, 1, seq, &id->pk, &val) != 0) {
        return NULL;
    }
    if (nodus_value_sign(val, &id->sk) != 0) {
        nodus_value_free(val);
        return NULL;
    }
    return val;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        QGP_LOG_ERROR(LOG_TAG, "usage: %s <corpus-dir>", argv[0]);
        return 1;
    }
    g_root = argv[1];

    char path[4096];
    const char *subs[] = { "value", "t2_decode", "cbor" };
    if (ensure_dir(g_root) != 0) {
        return 1;
    }
    for (size_t i = 0; i < sizeof(subs) / sizeof(subs[0]); i++) {
        snprintf(path, sizeof(path), "%s/%s", g_root, subs[i]);
        if (ensure_dir(path) != 0) {
            return 1;
        }
    }

    /* Fixed identity seed: deterministic keypair (signatures stay randomized) */
    uint8_t id_seed[32];
    for (size_t i = 0; i < sizeof(id_seed); i++) {
        id_seed[i] = (uint8_t)(0xA5 ^ i);
    }
    nodus_identity_t *id = calloc(1, sizeof(*id));
    if (!id || nodus_identity_from_seed(id_seed, id) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "nodus_identity_from_seed failed");
        free(id);
        return 1;
    }

    nodus_value_t *v_perm = make_value(id, "fuzz:seed:permanent", "permanent payload",
                                       NODUS_VALUE_PERMANENT, 0, 1);
    nodus_value_t *v_eph  = make_value(id, "fuzz:seed:ephemeral", "ephemeral payload",
                                       NODUS_VALUE_EPHEMERAL, 3600, 2);
    nodus_value_t *v_excl = make_value(id, "fuzz:seed:exclusive", "exclusive payload",
                                       NODUS_VALUE_EXCLUSIVE, 0, 3);
    if (!v_perm || !v_eph || !v_excl) {
        QGP_LOG_ERROR(LOG_TAG, "value create/sign failed");
        nodus_value_free(v_perm);
        nodus_value_free(v_eph);
        nodus_value_free(v_excl);
        nodus_identity_clear(id);
        free(id);
        return 1;
    }

    /* value/ */
    nodus_value_t *vals[3] = { v_perm, v_eph, v_excl };
    const char *vnames[3] = { "permanent.cbor", "ephemeral.cbor", "exclusive.cbor" };
    for (size_t i = 0; i < 3; i++) {
        uint8_t *vb = NULL;
        size_t vl = 0;
        int rc = nodus_value_serialize(vals[i], &vb, &vl);
        write_encoded("value", vnames[i], rc, vb, vl);
        if (rc == 0) {
            write_encoded("cbor", vnames[i], rc, vb, vl);
        }
        free(vb);
    }

    uint8_t *buf = malloc(SEED_BUF_CAP);
    uint8_t *frame = malloc(SEED_BUF_CAP + NODUS_FRAME_HEADER_SIZE);
    if (!buf || !frame) {
        QGP_LOG_ERROR(LOG_TAG, "out of memory");
        g_failures++;
        goto done;
    }
    size_t len = 0;
    int rc;

    /* t2_decode/ + cbor/: node -> client replies */
    rc = nodus_t2_result(10, v_perm, buf, SEED_BUF_CAP, &len);
    write_encoded("t2_decode", "result.cbor", rc, buf, len);
    write_encoded("cbor", "result.cbor", rc, buf, len);
    if (rc == 0) {
        size_t flen = nodus_frame_encode(frame, SEED_BUF_CAP + NODUS_FRAME_HEADER_SIZE,
                                         buf, (uint32_t)len);
        write_encoded("t2_decode", "result.frame", flen ? 0 : -1, frame, flen);
    }

    rc = nodus_t2_result_multi(11, vals, 3, buf, SEED_BUF_CAP, &len);
    write_encoded("t2_decode", "result_multi.cbor", rc, buf, len);

    rc = nodus_t2_result_empty(12, buf, SEED_BUF_CAP, &len);
    write_encoded("t2_decode", "result_empty.cbor", rc, buf, len);
    write_encoded("cbor", "result_empty.cbor", rc, buf, len);

    rc = nodus_t2_error(13, NODUS_ERR_NOT_FOUND, "key not found", buf, SEED_BUF_CAP, &len);
    write_encoded("t2_decode", "error.cbor", rc, buf, len);
    write_encoded("cbor", "error.cbor", rc, buf, len);

    rc = nodus_t2_pong(14, buf, SEED_BUF_CAP, &len);
    write_encoded("t2_decode", "pong.cbor", rc, buf, len);

    rc = nodus_t2_put_ok(15, buf, SEED_BUF_CAP, &len);
    write_encoded("t2_decode", "put_ok.cbor", rc, buf, len);

    rc = nodus_t2_value_changed(16, &v_eph->key_hash, v_eph, buf, SEED_BUF_CAP, &len);
    write_encoded("t2_decode", "value_changed.cbor", rc, buf, len);

    uint8_t nonce[NODUS_NONCE_LEN];
    for (size_t i = 0; i < sizeof(nonce); i++) {
        nonce[i] = (uint8_t)i;
    }
    rc = nodus_t2_challenge(1, nonce, buf, SEED_BUF_CAP, &len);
    write_encoded("t2_decode", "challenge.cbor", rc, buf, len);

    uint8_t token[NODUS_SESSION_TOKEN_LEN];
    for (size_t i = 0; i < sizeof(token); i++) {
        token[i] = (uint8_t)(0xF0 ^ i);
    }
    rc = nodus_t2_auth_ok(2, token, buf, SEED_BUF_CAP, &len);
    write_encoded("t2_decode", "auth_ok.cbor", rc, buf, len);

done:
    free(buf);
    free(frame);
    nodus_value_free(v_perm);
    nodus_value_free(v_eph);
    nodus_value_free(v_excl);
    nodus_identity_clear(id);
    free(id);

    if (g_failures) {
        QGP_LOG_ERROR(LOG_TAG, "%d seed(s) failed", g_failures);
        return 1;
    }
    return 0;
}
