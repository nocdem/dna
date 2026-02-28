/**
 * Nodus v5 — Identity Generation & Management
 *
 * Generates Dilithium5 keypairs from seed (deterministic) or randomly.
 * Seed derivation uses qgp_dsa87_keypair_derand() which produces
 * identical keypairs to OpenDHT-PQ's pqcrystals_dilithium5_ref_keypair_from_seed().
 */

#include "crypto/nodus_identity.h"
#include "crypto/nodus_sign.h"
#include "crypto/utils/qgp_dilithium.h"
#include "crypto/utils/qgp_platform.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef _WIN32
#include <io.h>
#define F_OK 0
#define access _access
#else
#include <unistd.h>
#endif

int nodus_identity_from_seed(const uint8_t *seed, nodus_identity_t *id_out) {
    if (!seed || !id_out)
        return -1;

    memset(id_out, 0, sizeof(*id_out));

    /* Deterministic keypair from seed — same algorithm as OpenDHT-PQ */
    int rc = qgp_dsa87_keypair_derand(id_out->pk.bytes, id_out->sk.bytes, seed);
    if (rc != 0)
        return -1;

    /* Derive node_id = SHA3-512(public_key) */
    rc = nodus_fingerprint(&id_out->pk, &id_out->node_id);
    if (rc != 0)
        return -1;

    /* Hex fingerprint */
    rc = nodus_fingerprint_hex(&id_out->pk, id_out->fingerprint);
    if (rc != 0)
        return -1;

    return 0;
}

int nodus_identity_generate(nodus_identity_t *id_out) {
    if (!id_out)
        return -1;

    memset(id_out, 0, sizeof(*id_out));

    /* Random keypair */
    int rc = qgp_dsa87_keypair(id_out->pk.bytes, id_out->sk.bytes);
    if (rc != 0)
        return -1;

    /* Derive node_id */
    rc = nodus_fingerprint(&id_out->pk, &id_out->node_id);
    if (rc != 0)
        return -1;

    /* Hex fingerprint */
    rc = nodus_fingerprint_hex(&id_out->pk, id_out->fingerprint);
    if (rc != 0)
        return -1;

    return 0;
}

int nodus_identity_save(const nodus_identity_t *id, const char *path) {
    if (!id || !path)
        return -1;

    char filepath[1024];
    FILE *f;

    /* Write public key */
    snprintf(filepath, sizeof(filepath), "%s/nodus.pk", path);
    f = fopen(filepath, "wb");
    if (!f) return -1;
    if (fwrite(id->pk.bytes, 1, NODUS_PK_BYTES, f) != NODUS_PK_BYTES) {
        fclose(f);
        return -1;
    }
    fclose(f);

    /* Write secret key */
    snprintf(filepath, sizeof(filepath), "%s/nodus.sk", path);
    f = fopen(filepath, "wb");
    if (!f) return -1;
    if (fwrite(id->sk.bytes, 1, NODUS_SK_BYTES, f) != NODUS_SK_BYTES) {
        fclose(f);
        return -1;
    }
    fclose(f);

    /* Write fingerprint */
    snprintf(filepath, sizeof(filepath), "%s/nodus.fp", path);
    f = fopen(filepath, "w");
    if (!f) return -1;
    fprintf(f, "%s\n", id->fingerprint);
    fclose(f);

    return 0;
}

int nodus_identity_load(const char *path, nodus_identity_t *id_out) {
    if (!path || !id_out)
        return -1;

    memset(id_out, 0, sizeof(*id_out));

    char filepath[1024];
    FILE *f;

    /* Read public key */
    snprintf(filepath, sizeof(filepath), "%s/nodus.pk", path);
    f = fopen(filepath, "rb");
    if (!f) return -1;
    if (fread(id_out->pk.bytes, 1, NODUS_PK_BYTES, f) != NODUS_PK_BYTES) {
        fclose(f);
        return -1;
    }
    fclose(f);

    /* Read secret key */
    snprintf(filepath, sizeof(filepath), "%s/nodus.sk", path);
    f = fopen(filepath, "rb");
    if (!f) return -1;
    if (fread(id_out->sk.bytes, 1, NODUS_SK_BYTES, f) != NODUS_SK_BYTES) {
        fclose(f);
        return -1;
    }
    fclose(f);

    /* Derive node_id from public key */
    int rc = nodus_fingerprint(&id_out->pk, &id_out->node_id);
    if (rc != 0)
        return -1;

    rc = nodus_fingerprint_hex(&id_out->pk, id_out->fingerprint);
    if (rc != 0)
        return -1;

    return 0;
}

uint64_t nodus_identity_value_id(const nodus_identity_t *id) {
    if (!id)
        return 0;

    /* First 8 bytes of node_id (SHA3-512 of pk), little-endian */
    uint64_t vid = 0;
    for (int i = 7; i >= 0; i--)
        vid = (vid << 8) | id->node_id.bytes[i];

    return vid;
}

int nodus_identity_export(const nodus_identity_t *id, uint8_t **buf, size_t *len) {
    if (!id || !buf || !len) return -1;
    size_t total = NODUS_PK_BYTES + NODUS_SK_BYTES;  /* 7488 */
    uint8_t *out = malloc(total);
    if (!out) return -1;
    memcpy(out, id->pk.bytes, NODUS_PK_BYTES);
    memcpy(out + NODUS_PK_BYTES, id->sk.bytes, NODUS_SK_BYTES);
    *buf = out;
    *len = total;
    return 0;
}

int nodus_identity_import(const uint8_t *buf, size_t len, nodus_identity_t *id_out) {
    if (!buf || !id_out) return -1;
    size_t total = NODUS_PK_BYTES + NODUS_SK_BYTES;  /* 7488 */
    if (len != total) return -1;

    memset(id_out, 0, sizeof(*id_out));
    memcpy(id_out->pk.bytes, buf, NODUS_PK_BYTES);
    memcpy(id_out->sk.bytes, buf + NODUS_PK_BYTES, NODUS_SK_BYTES);

    if (nodus_fingerprint(&id_out->pk, &id_out->node_id) != 0)
        return -1;
    if (nodus_fingerprint_hex(&id_out->pk, id_out->fingerprint) != 0)
        return -1;

    return 0;
}

void nodus_identity_clear(nodus_identity_t *id) {
    if (!id) return;
    /* Use volatile to prevent optimizer from removing the memset */
    volatile uint8_t *p = (volatile uint8_t *)id;
    for (size_t i = 0; i < sizeof(*id); i++)
        p[i] = 0;
}
