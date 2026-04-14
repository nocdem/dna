/**
 * Nodus — Identity Generation & Management
 *
 * Generates Dilithium5 keypairs from seed (deterministic) or randomly.
 * Seed derivation uses qgp_dsa87_keypair_derand() which produces
 * identical keypairs to OpenDHT-PQ's pqcrystals_dilithium5_ref_keypair_from_seed().
 */

#include "crypto/nodus_identity.h"
#include "crypto/nodus_sign.h"
#include "crypto/sign/qgp_dilithium.h"
#include "crypto/enc/qgp_kyber.h"
#include "crypto/enc/kyber_deterministic.h"
#include "crypto/hash/hkdf_sha3.h"
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
#include <sys/stat.h>

#include "crypto/utils/qgp_safe_string.h"   /* Phase 03: unsafe-string poison guard */
#endif

int nodus_identity_from_seed(const uint8_t *seed, nodus_identity_t *id_out) {
    if (!seed || !id_out)
        return -1;

    memset(id_out, 0, sizeof(*id_out));

    /* Deterministic Dilithium5 keypair from seed — same algorithm as OpenDHT-PQ */
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

    /* Derive Kyber1024 keypair from seed via HKDF */
    uint8_t kyber_seed[64];
    static const uint8_t hkdf_salt[] = "nodus-kyber-v1";
    static const uint8_t hkdf_info[] = "kyber-identity";
    rc = hkdf_sha3_256(hkdf_salt, sizeof(hkdf_salt) - 1,
                       seed, NODUS_SEED_BYTES,
                       hkdf_info, sizeof(hkdf_info) - 1,
                       kyber_seed, 32);
    if (rc != 0)
        return -1;

    rc = crypto_kem_keypair_derand(id_out->kyber_pk, id_out->kyber_sk, kyber_seed);
    qgp_secure_memzero(kyber_seed, sizeof(kyber_seed));
    if (rc != 0)
        return -1;

    id_out->has_kyber = true;
    return 0;
}

int nodus_identity_generate(nodus_identity_t *id_out) {
    if (!id_out)
        return -1;

    memset(id_out, 0, sizeof(*id_out));

    /* Random Dilithium5 keypair */
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

    /* Random Kyber1024 keypair */
    rc = qgp_kem1024_keypair(id_out->kyber_pk, id_out->kyber_sk);
    if (rc != 0)
        return -1;

    id_out->has_kyber = true;
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
#ifndef _WIN32
    chmod(filepath, 0600);  /* M-12: restrict secret key to owner-only */
#endif

    /* Write fingerprint */
    snprintf(filepath, sizeof(filepath), "%s/nodus.fp", path);
    f = fopen(filepath, "w");
    if (!f) return -1;
    fprintf(f, "%s\n", id->fingerprint);
    fclose(f);

    /* Write Kyber keypair (if available) */
    if (id->has_kyber) {
        snprintf(filepath, sizeof(filepath), "%s/nodus.kyber_pk", path);
        f = fopen(filepath, "wb");
        if (!f) return -1;
        if (fwrite(id->kyber_pk, 1, NODUS_KYBER_PK_BYTES, f) != NODUS_KYBER_PK_BYTES) {
            fclose(f);
            return -1;
        }
        fclose(f);

        snprintf(filepath, sizeof(filepath), "%s/nodus.kyber_sk", path);
        f = fopen(filepath, "wb");
        if (!f) return -1;
        if (fwrite(id->kyber_sk, 1, NODUS_KYBER_SK_BYTES, f) != NODUS_KYBER_SK_BYTES) {
            fclose(f);
            return -1;
        }
        fclose(f);
#ifndef _WIN32
        chmod(filepath, 0600);
#endif
    }

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

    /* Load Kyber keypair, or auto-generate if missing (migration from pre-Kyber identity) */
    snprintf(filepath, sizeof(filepath), "%s/nodus.kyber_pk", path);
    f = fopen(filepath, "rb");
    if (f) {
        if (fread(id_out->kyber_pk, 1, NODUS_KYBER_PK_BYTES, f) == NODUS_KYBER_PK_BYTES) {
            fclose(f);
            snprintf(filepath, sizeof(filepath), "%s/nodus.kyber_sk", path);
            f = fopen(filepath, "rb");
            if (f && fread(id_out->kyber_sk, 1, NODUS_KYBER_SK_BYTES, f) == NODUS_KYBER_SK_BYTES) {
                id_out->has_kyber = true;
            }
            if (f) fclose(f);
        } else {
            fclose(f);
        }
    }

    /* Auto-generate Kyber keypair if not found (first run with new binary) */
    if (!id_out->has_kyber) {
        if (qgp_kem1024_keypair(id_out->kyber_pk, id_out->kyber_sk) == 0) {
            id_out->has_kyber = true;
            /* Save for next startup */
            nodus_identity_save(id_out, path);
        }
    }

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
    /* M-13: Use platform secure memzero instead of hand-rolled volatile loop */
    qgp_secure_memzero(id, sizeof(*id));
}
