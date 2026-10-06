/**
 * qgp_trust.h - the signed trust state `qgp-trust` (bytes doc §2 + REV 2).
 *
 *   body    = canonical ASCII text, LF ends, lines sorted bytewise, records
 *             `key <fp 128 hex> <pk 5184 hex>` (R2-1), `revoked <fp 128 hex>`,
 *             `floor <package> <debian-version>`; at least one key.
 *   M_trust = "NDS.QGPTRUST.v1"\0 | serial(8,BE) | prev_digest(64) | signer(64) |
 *             SHA3-512(body)                                         (R2-3, 216 B)
 *   file    = 0x01 | serial(8,BE) | signer(64) | body_len(4,BE) | body |
 *             sig_len(2,BE)=4627 | sig(4627)
 *   prev_digest = SHA3-512 of the previously accepted trust FILE (zeros first).
 */
#ifndef QGP_TRUST_H
#define QGP_TRUST_H

#include <stddef.h>
#include <stdint.h>

#include "qgp_core.h"

typedef struct {
    uint8_t fp[QGP_HASH_LEN];
    uint8_t pk[QGP_PK_LEN];
} qgp_trust_key_t;

typedef struct {
    char  *pkg;   size_t pkg_n;     /* NUL-terminated copies */
    char  *ver;   size_t ver_n;
} qgp_trust_floor_t;

typedef struct {
    qgp_trust_key_t   *keys;     size_t n_keys;
    uint8_t          (*revoked)[QGP_HASH_LEN];
    size_t             n_revoked;
    qgp_trust_floor_t *floors;   size_t n_floors;
} qgp_trust_state_t;

typedef struct {
    uint64_t          serial;
    uint8_t           signer[QGP_HASH_LEN];
    const uint8_t    *body;      /* points into the file buffer */
    uint32_t          body_len;
    const uint8_t    *sig;       /* QGP_SIG_LEN bytes, points into the file buffer */
    qgp_trust_state_t state;
} qgp_trust_file_t;

/* A previously accepted trust file (owned copy) and its parsed form. */
typedef struct {
    uint8_t          *file;
    size_t            file_len;
    qgp_trust_file_t  parsed;
} qgp_trust_stored_t;

/* Canonical-body check (§2, R2-1, R2-6); fills `out` on success. */
qgp_rc_t qgp_trust_parse_body(const uint8_t *body, size_t len, qgp_trust_state_t *out);
void qgp_trust_state_free(qgp_trust_state_t *st);

const qgp_trust_key_t *qgp_trust_find_key(const qgp_trust_state_t *st, const uint8_t fp[QGP_HASH_LEN]);
int qgp_trust_is_revoked(const qgp_trust_state_t *st, const uint8_t fp[QGP_HASH_LEN]);
const qgp_trust_floor_t *qgp_trust_find_floor(const qgp_trust_state_t *st, const char *pkg, size_t pkg_n);

/* Layout parse of a trust file (version first, body_len bound before the body). */
qgp_rc_t qgp_trust_parse_file(const uint8_t *f, size_t len, qgp_trust_file_t *out);
void qgp_trust_file_free(qgp_trust_file_t *tf);

qgp_rc_t qgp_trust_m_trust(uint64_t serial, const uint8_t prev[QGP_HASH_LEN],
                           const uint8_t signer[QGP_HASH_LEN],
                           const uint8_t *body, size_t body_len,
                           uint8_t out[QGP_M_TRUST_LEN]);

/* Load an accepted file as the stored state (layout + canonical body only:
 * its signature was verified when it was accepted). Copies `f`. */
qgp_rc_t qgp_trust_stored_load(const uint8_t *f, size_t len, qgp_trust_stored_t *out);
void qgp_trust_stored_free(qgp_trust_stored_t *s);

/* Layout + policy check of a candidate file against `stored` (NULL = the
 * hand-checked bootstrap: signer must be a key of its own body, prev = zeros).
 * On success fills `out`, the M_trust the signer must have signed, and the
 * signer's pinned public key (stored state, or the file's own body at bootstrap).
 * No signature check. */
qgp_rc_t qgp_trust_check(const uint8_t *f, size_t len, const qgp_trust_stored_t *stored,
                         qgp_trust_file_t *out, uint8_t m_trust[QGP_M_TRUST_LEN],
                         const uint8_t **signer_pk);

/* qgp_trust_check + ML-DSA-87 verification. `out` may be NULL. */
qgp_rc_t qgp_trust_verify(const uint8_t *f, size_t len, const qgp_trust_stored_t *stored,
                          qgp_trust_file_t *out);

/* Build and sign a trust file over `body` with `serial`, chained to `prev`
 * (NULL = bootstrap). The result is run through qgp_trust_verify(result, prev)
 * before it is returned, so a file this refuses to accept is never produced. */
qgp_rc_t qgp_trust_make(const uint8_t *body, size_t body_len, uint64_t serial,
                        const qgp_trust_stored_t *prev,
                        const uint8_t sk[QGP_SK_LEN], const uint8_t pk[QGP_PK_LEN],
                        uint8_t **out, size_t *out_len);

#endif /* QGP_TRUST_H */
