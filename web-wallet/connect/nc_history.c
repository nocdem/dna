/* Nodus Connect (web) — at-rest encryption of chat history records
 * (package NC-4a). Construction and its references: nc_history.h;
 * governing record docs/plans/decisions/2026-09-30-connect-history-at-rest.md
 * (rev 2).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "nc_history.h"

#include "crypto/enc/qgp_aes.h"
#include "crypto/hash/hkdf_sha3.h"
#include "crypto/hash/qgp_sha3.h"
#include "crypto/sign/qgp_dilithium.h"
#include "crypto/utils/qgp_log.h"
#include "crypto/utils/qgp_platform.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#define LOG_TAG "NC_HISTORY"

/* The SQLCipher key domain separator — the same literal as
 * messenger/database/db_encryption.c:23 (DB_KEY_DOMAIN_SEPARATOR), hashed
 * without its NUL (db_encryption.c:35-45 uses strlen). That function cannot
 * be called here: its unit also opens SQLCipher databases, which the web
 * build does not link. */
#define NC_HISTORY_DB_KEY_SEPARATOR "sqlcipher-db-key"

/* The header's literals, pinned to their sources. */
_Static_assert(NC_HISTORY_SK_LEN == QGP_DSA87_SECRETKEYBYTES,
               "history root hashes a Dilithium5 secret key");
_Static_assert(NC_HISTORY_ROOT_LEN == QGP_SHA3_512_DIGEST_LENGTH,
               "history root is a SHA3-512 digest");
_Static_assert(NC_HISTORY_KEY_LEN <= QGP_SHA3_256_DIGEST_LENGTH,
               "hkdf_sha3_256 expands a single block");

int nc_history_root(const uint8_t *sk, size_t sk_len,
                    uint8_t root_out[NC_HISTORY_ROOT_LEN]) {
    if (!root_out) return NC_HISTORY_REFUSED;
    memset(root_out, 0, NC_HISTORY_ROOT_LEN);
    if (!sk || sk_len != NC_HISTORY_SK_LEN) return NC_HISTORY_REFUSED;

    const size_t sep_len = strlen(NC_HISTORY_DB_KEY_SEPARATOR);
    const size_t total = sk_len + sep_len;
    uint8_t *input = (uint8_t *)malloc(total);
    if (!input) {
        QGP_LOG_ERROR(LOG_TAG, "root: allocation failed");
        return NC_HISTORY_FAULT;
    }
    memcpy(input, sk, sk_len);
    memcpy(input + sk_len, NC_HISTORY_DB_KEY_SEPARATOR, sep_len);

    int rc = qgp_sha3_512(input, total, root_out);

    qgp_secure_memzero(input, total);
    free(input);

    if (rc != 0) {
        qgp_secure_memzero(root_out, NC_HISTORY_ROOT_LEN);
        QGP_LOG_ERROR(LOG_TAG, "root: SHA3-512 failed");
        return NC_HISTORY_FAULT;
    }
    return NC_HISTORY_OK;
}

int nc_history_derive_key(const uint8_t *sk, size_t sk_len,
                          const uint8_t vault_id[NC_HISTORY_VAULT_ID_LEN],
                          uint8_t key_out[NC_HISTORY_KEY_LEN]) {
    if (!key_out) return NC_HISTORY_REFUSED;
    memset(key_out, 0, NC_HISTORY_KEY_LEN);
    if (!vault_id) return NC_HISTORY_REFUSED;

    uint8_t root[NC_HISTORY_ROOT_LEN];
    int rc = nc_history_root(sk, sk_len, root);
    if (rc != NC_HISTORY_OK) return rc;

    /* hkdf_sha3.c only returns -1 for a NULL argument (:80-83), an
     * oversized okm (:85-89) or info (:103-107) — none possible with these
     * constants — or for an OpenSSL HMAC failure (Extract :95, Expand
     * :115); so any -1 here is a fault. */
    const char *info = NC_HISTORY_HKDF_INFO;
    rc = hkdf_sha3_256(vault_id, NC_HISTORY_VAULT_ID_LEN,
                       root, sizeof(root),
                       (const uint8_t *)info, strlen(info),
                       key_out, NC_HISTORY_KEY_LEN);
    qgp_secure_memzero(root, sizeof(root));

    if (rc != 0) {
        qgp_secure_memzero(key_out, NC_HISTORY_KEY_LEN);
        QGP_LOG_ERROR(LOG_TAG, "derive_key: HKDF-SHA3-256 failed");
        return NC_HISTORY_FAULT;
    }
    return NC_HISTORY_OK;
}

/* AAD = u16be(store_len) || store || u16be(id_len) || id.
 * Heap: the AAD can reach 2 + 65535 + 2 + 65535 bytes, more than the
 * default wasm stack. Caller has already checked both lengths <= 65535
 * and the pointers for non-empty names. */
static uint8_t *build_aad(const uint8_t *store, size_t store_len,
                          const uint8_t *id, size_t id_len,
                          size_t *aad_len) {
    const size_t len = 2 + store_len + 2 + id_len;
    uint8_t *aad = (uint8_t *)malloc(len);
    if (!aad) return NULL;
    size_t off = 0;
    aad[off++] = (uint8_t)(store_len >> 8);
    aad[off++] = (uint8_t)(store_len & 0xff);
    if (store_len) memcpy(aad + off, store, store_len);
    off += store_len;
    aad[off++] = (uint8_t)(id_len >> 8);
    aad[off++] = (uint8_t)(id_len & 0xff);
    if (id_len) memcpy(aad + off, id, id_len);
    off += id_len;
    *aad_len = off;
    return aad;
}

static int names_ok(const uint8_t *store, size_t store_len,
                    const uint8_t *id, size_t id_len) {
    if (store_len > NC_HISTORY_NAME_MAX || id_len > NC_HISTORY_NAME_MAX)
        return 0;
    if ((store_len && !store) || (id_len && !id)) return 0;
    return 1;
}

int nc_history_encrypt(const uint8_t key[NC_HISTORY_KEY_LEN],
                       uint64_t *counter,
                       const uint8_t *store, size_t store_len,
                       const uint8_t *id, size_t id_len,
                       const uint8_t *pt, size_t pt_len,
                       uint8_t *ct_out,
                       uint8_t nonce_out[NC_HISTORY_NONCE_LEN],
                       uint8_t tag_out[NC_HISTORY_TAG_LEN]) {
    if (!key || !counter || !pt || !ct_out || !nonce_out || !tag_out)
        return NC_HISTORY_REFUSED;
    /* SP 800-38D §8.3 — checked before anything that consumes randomness. */
    if (*counter >= NC_HISTORY_MAX_INVOCATIONS) {
        QGP_LOG_ERROR(LOG_TAG, "encrypt: invocation budget of this key exhausted");
        return NC_HISTORY_REFUSED;
    }
    if (!names_ok(store, store_len, id, id_len)) return NC_HISTORY_REFUSED;
    /* qgp_aes.c:49-52 refuses empty plaintext; :87 passes the length to
     * OpenSSL as int. */
    if (pt_len == 0 || pt_len > (size_t)INT_MAX) return NC_HISTORY_REFUSED;

    size_t aad_len = 0;
    uint8_t *aad = build_aad(store, store_len, id, id_len, &aad_len);
    if (!aad) {
        QGP_LOG_ERROR(LOG_TAG, "encrypt: AAD allocation failed");
        return NC_HISTORY_FAULT;
    }

    size_t ct_len = 0;
    /* Every input qgp_aes256_encrypt refuses was refused above, so a -1
     * from it is the RNG (:60) or OpenSSL (:66-104). */
    int rc = qgp_aes256_encrypt(key, pt, pt_len, aad, aad_len,
                                ct_out, &ct_len, nonce_out, tag_out);
    free(aad);

    if (rc != 0 || ct_len != pt_len) {
        qgp_secure_memzero(ct_out, pt_len);
        memset(nonce_out, 0, NC_HISTORY_NONCE_LEN);
        memset(tag_out, 0, NC_HISTORY_TAG_LEN);
        QGP_LOG_ERROR(LOG_TAG, "encrypt: AES-256-GCM failed");
        return NC_HISTORY_FAULT;
    }
    (*counter)++;
    return NC_HISTORY_OK;
}

int nc_history_decrypt(const uint8_t key[NC_HISTORY_KEY_LEN],
                       const uint8_t *store, size_t store_len,
                       const uint8_t *id, size_t id_len,
                       const uint8_t *ct, size_t ct_len,
                       const uint8_t nonce[NC_HISTORY_NONCE_LEN],
                       const uint8_t tag[NC_HISTORY_TAG_LEN],
                       uint8_t *pt_out) {
    if (!key || !ct || !nonce || !tag || !pt_out) return NC_HISTORY_REFUSED;
    if (!names_ok(store, store_len, id, id_len)) return NC_HISTORY_REFUSED;
    /* qgp_aes.c:135-138 refuses empty ciphertext; :167 int length. */
    if (ct_len == 0 || ct_len > (size_t)INT_MAX) return NC_HISTORY_REFUSED;

    size_t aad_len = 0;
    uint8_t *aad = build_aad(store, store_len, id, id_len, &aad_len);
    if (!aad) {
        QGP_LOG_ERROR(LOG_TAG, "decrypt: AAD allocation failed");
        return NC_HISTORY_FAULT;
    }

    size_t pt_len = 0;
    int rc = qgp_aes256_decrypt(key, ct, ct_len, aad, aad_len,
                                nonce, tag, pt_out, &pt_len);
    free(aad);

    if (rc != 0 || pt_len != ct_len) {
        /* qgp_aes.c:190 wipes only what it wrote before the tag check. */
        qgp_secure_memzero(pt_out, ct_len);
        /* Tag mismatch and an OpenSSL context allocation failure are the
         * same -1 inside qgp_aes (see nc_history.h). */
        return NC_HISTORY_REFUSED;
    }
    return NC_HISTORY_OK;
}
