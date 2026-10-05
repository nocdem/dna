/**
 * qgp_trust.c - trust state file: canonical body, file layout, M_trust chain,
 * monotonic acceptance policy (bytes doc §2 + REV 2 R2-1/R2-2/R2-3/R2-6).
 *
 * Check order follows the oracle (scripts/qgp-sign/qgp_deb_oracle.py
 * parse_body / parse_trust_file / accept_trust) so the reject reasons match
 * qgp_deb_kat.json. Readings implemented as the oracle records them:
 *  R-ASCII   any byte outside 0x20..0x7E other than LF refuses;
 *  R-SEP     fields separated by exactly one 0x20;
 *  R-HEX     fp and pk hex lowercase only;
 *  R-FILE    prev_digest is not carried in the file; it is SHA3-512 of the
 *            previously accepted file bytes (R-PREV), zeros at bootstrap;
 *  R-SERIAL  serial strictly greater than stored; gaps allowed;
 *  R-SIGNER  the signer is checked against the STORED state only (a key may
 *            sign the file that revokes itself);
 *  R-BOOT    bootstrap: signer must be a key of its own body; any serial;
 *  R-MONO    stored floors kept and >= (Debian comparison); new floors allowed;
 *            stored revocations kept.
 * One reading is STRICTER than the oracle (R-FLOORTOK left the grammar open):
 * a floor's <package> must satisfy deb-src-control(5) and its <debian-version>
 * deb-version(7), so every floor is comparable. No KAT vector is affected.
 */
#include "qgp_trust.h"
#include "qgp_debver.h"

#include <stdlib.h>
#include <string.h>

#include "crypto/utils/qgp_log.h"
#include "crypto/utils/qgp_safe_string.h"

#define LOG_TAG "QGP_TRUST"

/* "NDS.QGPTRUST.v1" (15) right-padded with one 0x00 to 16 (oracle R-TAGS). */
static const uint8_t TAG_TRUST[QGP_TAG_LEN] = {
    'N', 'D', 'S', '.', 'Q', 'G', 'P', 'T', 'R', 'U', 'S', 'T', '.', 'v', '1', 0
};
_Static_assert(QGP_M_TRUST_LEN == 216, "M_trust length");
_Static_assert(QGP_TRUST_FIXED == 77, "trust file fixed part");

#define FP_HEX_LEN (2 * QGP_HASH_LEN)   /* 128 */
#define PK_HEX_LEN (2 * QGP_PK_LEN)     /* 5184 */

typedef struct {
    const uint8_t *p;
    size_t         n;
} span_t;

/* Python bytes ordering: lexicographic, a proper prefix sorts first. */
static int span_cmp(const span_t *a, const span_t *b)
{
    size_t m = a->n < b->n ? a->n : b->n;
    int r = memcmp(a->p, b->p, m);
    if (r != 0)
        return r;
    if (a->n == b->n)
        return 0;
    return a->n < b->n ? -1 : 1;
}

static int span_cmp_qsort(const void *a, const void *b)
{
    return span_cmp((const span_t *)a, (const span_t *)b);
}

/* Split one line into space-separated tokens (at most `max`). Returns the token
 * count, or -1 on an empty token (bad separator). Counts beyond `max` are still
 * reported (as max + 1) so field-count errors are detected. */
static int split_tokens(const uint8_t *p, size_t n, span_t *tok, int max)
{
    int count = 0;
    size_t start = 0;
    for (size_t i = 0; i <= n; i++) {
        if (i == n || p[i] == ' ') {
            if (i == start)
                return -1;
            if (count < max) {
                tok[count].p = p + start;
                tok[count].n = i - start;
            }
            count++;
            if (count > max)
                count = max + 1;   /* keep scanning for empty tokens, cap the count */
            start = i + 1;
        }
    }
    return count;
}

static int span_is(const span_t *s, const char *lit)
{
    size_t n = strlen(lit);
    return s->n == n && memcmp(s->p, lit, n) == 0;
}

static int is_lower_hex(const span_t *s, size_t want)
{
    if (s->n != want)
        return 0;
    for (size_t i = 0; i < s->n; i++) {
        uint8_t c = s->p[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return 0;
    }
    return 1;
}

void qgp_trust_state_free(qgp_trust_state_t *st)
{
    if (!st)
        return;
    for (size_t i = 0; i < st->n_floors; i++) {
        free(st->floors[i].pkg);
        free(st->floors[i].ver);
    }
    free(st->floors);
    free(st->keys);
    free(st->revoked);
    memset(st, 0, sizeof(*st));
}

static char *dup_span(const span_t *s)
{
    char *c = malloc(s->n + 1);
    if (!c)
        return NULL;
    memcpy(c, s->p, s->n);
    c[s->n] = '\0';
    return c;
}

qgp_rc_t qgp_trust_parse_body(const uint8_t *body, size_t len, qgp_trust_state_t *out)
{
    if (!out)
        return QGP_E_ARG;
    memset(out, 0, sizeof(*out));
    if (!body && len != 0)
        return QGP_E_ARG;
    if (len > QGP_BODY_MAX)
        return QGP_E_BODY_TOO_LARGE;
    for (size_t i = 0; i < len; i++) {
        uint8_t c = body[i];
        if (c != 0x0A && !(c >= 0x20 && c <= 0x7E))
            return QGP_E_NON_PRINTABLE_ASCII_BYTE;
    }
    if (len == 0 || body[len - 1] != 0x0A)
        return QGP_E_MISSING_FINAL_LF;

    /* lines = body[:-1].split("\n") */
    size_t n_lines = 0;
    for (size_t i = 0; i < len; i++)
        if (body[i] == 0x0A)
            n_lines++;
    span_t *lines = calloc(n_lines, sizeof(*lines));
    span_t *sorted = calloc(n_lines, sizeof(*sorted));
    if (!lines || !sorted) {
        free(lines);
        free(sorted);
        return QGP_E_NOMEM;
    }
    size_t li = 0, start = 0;
    for (size_t i = 0; i < len; i++) {
        if (body[i] == 0x0A) {
            lines[li].p = body + start;
            lines[li].n = i - start;
            li++;
            start = i + 1;
        }
    }

    qgp_rc_t rc = QGP_OK;
    size_t n_keys = 0, n_revoked = 0, n_floors = 0;

    /* Per-line grammar, in file order. */
    for (size_t i = 0; i < n_lines && rc == QGP_OK; i++) {
        const span_t *ln = &lines[i];
        span_t tok[3];
        if (ln->n == 0) { rc = QGP_E_BLANK_LINE; break; }
        if (ln->p[ln->n - 1] == ' ') { rc = QGP_E_TRAILING_SPACE; break; }
        int nt = split_tokens(ln->p, ln->n, tok, 3);
        if (nt < 0) { rc = QGP_E_BAD_FIELD_SEPARATOR; break; }
        if (span_is(&tok[0], "key")) {
            if (nt != 3) { rc = QGP_E_BAD_FIELD_COUNT; break; }
            if (!is_lower_hex(&tok[1], FP_HEX_LEN)) { rc = QGP_E_BAD_FINGERPRINT_HEX; break; }
            if (!is_lower_hex(&tok[2], PK_HEX_LEN)) { rc = QGP_E_BAD_PK_HEX_OR_LENGTH; break; }
            uint8_t fp[QGP_HASH_LEN], h[QGP_HASH_LEN];
            uint8_t *pk = malloc(QGP_PK_LEN);
            if (!pk) { rc = QGP_E_NOMEM; break; }
            if (qgp_hex_decode_lower((const char *)tok[1].p, tok[1].n, fp, QGP_HASH_LEN) != 0 ||
                qgp_hex_decode_lower((const char *)tok[2].p, tok[2].n, pk, QGP_PK_LEN) != 0) {
                free(pk);
                rc = QGP_E_BAD_PK_HEX_OR_LENGTH;
                break;
            }
            int hrc = qgp_sha3_512(pk, QGP_PK_LEN, h);
            free(pk);
            if (hrc != 0) { rc = QGP_E_CRYPTO; break; }
            if (memcmp(h, fp, QGP_HASH_LEN) != 0) { rc = QGP_E_KEY_FP_MISMATCH; break; }
            n_keys++;
        } else if (span_is(&tok[0], "revoked")) {
            if (nt != 2) { rc = QGP_E_BAD_FIELD_COUNT; break; }
            if (!is_lower_hex(&tok[1], FP_HEX_LEN)) { rc = QGP_E_BAD_FINGERPRINT_HEX; break; }
            n_revoked++;
        } else if (span_is(&tok[0], "floor")) {
            if (nt != 3) { rc = QGP_E_BAD_FIELD_COUNT; break; }
            if (!qgp_debpkg_name_valid((const char *)tok[1].p, tok[1].n)) {
                rc = QGP_E_BAD_FLOOR_PACKAGE;
                break;
            }
            if (qgp_debver_check((const char *)tok[2].p, tok[2].n) != QGP_OK) {
                rc = QGP_E_BAD_FLOOR_VERSION;
                break;
            }
            n_floors++;
        } else {
            rc = QGP_E_UNKNOWN_RECORD_TYPE;
        }
    }

    /* Duplicate lines (checked on a sorted copy, independent of input order). */
    if (rc == QGP_OK) {
        memcpy(sorted, lines, n_lines * sizeof(*lines));
        qsort(sorted, n_lines, sizeof(*sorted), span_cmp_qsort);
        for (size_t i = 1; i < n_lines; i++) {
            if (span_cmp(&sorted[i - 1], &sorted[i]) == 0) { rc = QGP_E_DUPLICATE_LINE; break; }
        }
    }
    if (rc == QGP_OK) {
        for (size_t i = 1; i < n_lines; i++) {
            if (span_cmp(&lines[i - 1], &lines[i]) > 0) { rc = QGP_E_UNSORTED; break; }
        }
    }

    /* Build the state. */
    if (rc == QGP_OK) {
        out->keys = n_keys ? calloc(n_keys, sizeof(*out->keys)) : NULL;
        out->revoked = n_revoked ? calloc(n_revoked, sizeof(*out->revoked)) : NULL;
        out->floors = n_floors ? calloc(n_floors, sizeof(*out->floors)) : NULL;
        if ((n_keys && !out->keys) || (n_revoked && !out->revoked) || (n_floors && !out->floors))
            rc = QGP_E_NOMEM;
    }
    for (size_t i = 0; i < n_lines && rc == QGP_OK; i++) {
        span_t tok[3];
        (void)split_tokens(lines[i].p, lines[i].n, tok, 3);
        if (span_is(&tok[0], "key")) {
            qgp_trust_key_t k;
            if (qgp_hex_decode_lower((const char *)tok[1].p, tok[1].n, k.fp, QGP_HASH_LEN) != 0 ||
                qgp_hex_decode_lower((const char *)tok[2].p, tok[2].n, k.pk, QGP_PK_LEN) != 0) {
                rc = QGP_E_BAD_PK_HEX_OR_LENGTH;
                break;
            }
            if (qgp_trust_find_key(out, k.fp)) { rc = QGP_E_DUPLICATE_KEY_FP; break; }
            out->keys[out->n_keys++] = k;
        } else if (span_is(&tok[0], "revoked")) {
            if (qgp_hex_decode_lower((const char *)tok[1].p, tok[1].n,
                                     out->revoked[out->n_revoked], QGP_HASH_LEN) != 0) {
                rc = QGP_E_BAD_FINGERPRINT_HEX;
                break;
            }
            out->n_revoked++;
        } else {
            if (qgp_trust_find_floor(out, (const char *)tok[1].p, tok[1].n)) {
                rc = QGP_E_DUPLICATE_FLOOR;
                break;
            }
            qgp_trust_floor_t *fl = &out->floors[out->n_floors];
            fl->pkg = dup_span(&tok[1]);
            fl->ver = dup_span(&tok[2]);
            if (!fl->pkg || !fl->ver) {
                free(fl->pkg);
                free(fl->ver);
                fl->pkg = fl->ver = NULL;
                rc = QGP_E_NOMEM;
                break;
            }
            fl->pkg_n = tok[1].n;
            fl->ver_n = tok[2].n;
            out->n_floors++;
        }
    }
    if (rc == QGP_OK) {
        for (size_t i = 0; i < out->n_keys; i++) {
            if (qgp_trust_is_revoked(out, out->keys[i].fp)) { rc = QGP_E_KEY_AND_REVOKED; break; }
        }
    }
    if (rc == QGP_OK && out->n_keys == 0)
        rc = QGP_E_NO_KEY;

    free(lines);
    free(sorted);
    if (rc != QGP_OK)
        qgp_trust_state_free(out);
    return rc;
}

const qgp_trust_key_t *qgp_trust_find_key(const qgp_trust_state_t *st, const uint8_t fp[QGP_HASH_LEN])
{
    if (!st || !fp)
        return NULL;
    for (size_t i = 0; i < st->n_keys; i++)
        if (memcmp(st->keys[i].fp, fp, QGP_HASH_LEN) == 0)
            return &st->keys[i];
    return NULL;
}

int qgp_trust_is_revoked(const qgp_trust_state_t *st, const uint8_t fp[QGP_HASH_LEN])
{
    if (!st || !fp)
        return 0;
    for (size_t i = 0; i < st->n_revoked; i++)
        if (memcmp(st->revoked[i], fp, QGP_HASH_LEN) == 0)
            return 1;
    return 0;
}

const qgp_trust_floor_t *qgp_trust_find_floor(const qgp_trust_state_t *st, const char *pkg, size_t pkg_n)
{
    if (!st || !pkg)
        return NULL;
    for (size_t i = 0; i < st->n_floors; i++)
        if (st->floors[i].pkg_n == pkg_n && memcmp(st->floors[i].pkg, pkg, pkg_n) == 0)
            return &st->floors[i];
    return NULL;
}

qgp_rc_t qgp_trust_parse_file(const uint8_t *f, size_t len, qgp_trust_file_t *out)
{
    if (!out)
        return QGP_E_ARG;
    memset(out, 0, sizeof(*out));
    if (!f || len < 1)
        return QGP_E_FILE_LENGTH;
    if (f[0] != QGP_FORMAT_VERSION)              /* R2-6: version first */
        return QGP_E_FILE_VERSION;
    if (len < QGP_TRUST_FIXED)
        return QGP_E_FILE_LENGTH;
    uint32_t body_len = qgp_be32_get(f + 1 + 8 + QGP_HASH_LEN);
    if (body_len > QGP_BODY_MAX)                 /* before the body is read (R-BODYMAX) */
        return QGP_E_BODY_TOO_LARGE;
    if (len != (size_t)QGP_TRUST_FIXED + body_len + 2u + QGP_SIG_LEN)
        return QGP_E_FILE_LENGTH;
    uint16_t sig_len = qgp_be16_get(f + QGP_TRUST_FIXED + body_len);
    if (sig_len != QGP_SIG_LEN)
        return QGP_E_SIG_LEN;
    out->serial = qgp_be64_get(f + 1);
    memcpy(out->signer, f + 9, QGP_HASH_LEN);
    out->body = f + QGP_TRUST_FIXED;
    out->body_len = body_len;
    out->sig = f + QGP_TRUST_FIXED + body_len + 2;
    return qgp_trust_parse_body(out->body, body_len, &out->state);
}

void qgp_trust_file_free(qgp_trust_file_t *tf)
{
    if (!tf)
        return;
    qgp_trust_state_free(&tf->state);
    memset(tf, 0, sizeof(*tf));
}

qgp_rc_t qgp_trust_m_trust(uint64_t serial, const uint8_t prev[QGP_HASH_LEN],
                           const uint8_t signer[QGP_HASH_LEN],
                           const uint8_t *body, size_t body_len,
                           uint8_t out[QGP_M_TRUST_LEN])
{
    if (!prev || !signer || !body || !out)
        return QGP_E_ARG;
    uint8_t *p = out;
    memcpy(p, TAG_TRUST, QGP_TAG_LEN);   p += QGP_TAG_LEN;
    qgp_be64_put(p, serial);             p += 8;
    memcpy(p, prev, QGP_HASH_LEN);       p += QGP_HASH_LEN;
    memcpy(p, signer, QGP_HASH_LEN);     p += QGP_HASH_LEN;
    if (qgp_sha3_512(body, body_len, p) != 0)
        return QGP_E_CRYPTO;
    return QGP_OK;
}

qgp_rc_t qgp_trust_stored_load(const uint8_t *f, size_t len, qgp_trust_stored_t *out)
{
    if (!f || !out)
        return QGP_E_ARG;
    memset(out, 0, sizeof(*out));
    if (len > QGP_TRUST_FILE_MAX)
        return QGP_E_FILE_LENGTH;
    out->file = malloc(len ? len : 1);
    if (!out->file)
        return QGP_E_NOMEM;
    memcpy(out->file, f, len);
    out->file_len = len;
    qgp_rc_t rc = qgp_trust_parse_file(out->file, len, &out->parsed);
    if (rc != QGP_OK)
        qgp_trust_stored_free(out);
    return rc;
}

void qgp_trust_stored_free(qgp_trust_stored_t *s)
{
    if (!s)
        return;
    qgp_trust_file_free(&s->parsed);
    free(s->file);
    memset(s, 0, sizeof(*s));
}

qgp_rc_t qgp_trust_check(const uint8_t *f, size_t len, const qgp_trust_stored_t *stored,
                         qgp_trust_file_t *out, uint8_t m_trust[QGP_M_TRUST_LEN],
                         const uint8_t **signer_pk)
{
    if (!out || !m_trust)
        return QGP_E_ARG;
    qgp_rc_t rc = qgp_trust_parse_file(f, len, out);
    if (rc != QGP_OK)
        return rc;

    uint8_t prev[QGP_HASH_LEN];
    const qgp_trust_key_t *signer_key = NULL;

    if (!stored) {
        /* R-BOOT: hand-checked bootstrap, self-signed by a key of its own body. */
        signer_key = qgp_trust_find_key(&out->state, out->signer);
        if (!signer_key) { rc = QGP_E_SIGNER_NOT_TRUSTED; goto fail; }
        memset(prev, 0, sizeof(prev));
    } else {
        const qgp_trust_state_t *old = &stored->parsed.state;
        if (out->serial <= stored->parsed.serial) { rc = QGP_E_SERIAL_NOT_INCREASING; goto fail; }
        if (qgp_trust_is_revoked(old, out->signer)) { rc = QGP_E_SIGNER_REVOKED; goto fail; }
        signer_key = qgp_trust_find_key(old, out->signer);
        if (!signer_key) { rc = QGP_E_SIGNER_NOT_TRUSTED; goto fail; }
        for (size_t i = 0; i < old->n_revoked; i++) {
            if (!qgp_trust_is_revoked(&out->state, old->revoked[i])) {
                rc = QGP_E_REVOCATION_DROPPED;
                goto fail;
            }
        }
        for (size_t i = 0; i < old->n_floors; i++) {
            const qgp_trust_floor_t *of = &old->floors[i];
            const qgp_trust_floor_t *nf = qgp_trust_find_floor(&out->state, of->pkg, of->pkg_n);
            if (!nf) { rc = QGP_E_FLOOR_DROPPED; goto fail; }
            int cmp = 0;
            if (qgp_debver_cmp(nf->ver, nf->ver_n, of->ver, of->ver_n, &cmp) != QGP_OK) {
                rc = QGP_E_BAD_FLOOR_VERSION;
                goto fail;
            }
            if (cmp < 0) { rc = QGP_E_FLOOR_LOWERED; goto fail; }
        }
        if (qgp_sha3_512(stored->file, stored->file_len, prev) != 0) { rc = QGP_E_CRYPTO; goto fail; }
    }

    rc = qgp_trust_m_trust(out->serial, prev, out->signer, out->body, out->body_len, m_trust);
    if (rc != QGP_OK)
        goto fail;
    if (signer_pk)
        *signer_pk = signer_key->pk;
    return QGP_OK;

fail:
    qgp_trust_file_free(out);
    return rc;
}

qgp_rc_t qgp_trust_verify(const uint8_t *f, size_t len, const qgp_trust_stored_t *stored,
                          qgp_trust_file_t *out)
{
    qgp_trust_file_t local;
    qgp_trust_file_t *tf = out ? out : &local;
    uint8_t m[QGP_M_TRUST_LEN];
    const uint8_t *pk = NULL;
    qgp_rc_t rc = qgp_trust_check(f, len, stored, tf, m, &pk);
    if (rc != QGP_OK)
        return rc;
    /* pk may point into the stored state or into tf's own state: both live here. */
    if (qgp_dsa87_verify(tf->sig, QGP_SIG_LEN, m, sizeof(m), pk) != 0) {
        QGP_LOG_WARN(LOG_TAG, "trust file signature does not verify (serial %llu)",
                     (unsigned long long)tf->serial);
        qgp_trust_file_free(tf);
        return QGP_E_SIGNATURE;
    }
    if (!out)
        qgp_trust_file_free(&local);
    return QGP_OK;
}

qgp_rc_t qgp_trust_make(const uint8_t *body, size_t body_len, uint64_t serial,
                        const qgp_trust_stored_t *prev,
                        const uint8_t sk[QGP_SK_LEN], const uint8_t pk[QGP_PK_LEN],
                        uint8_t **out, size_t *out_len)
{
    if (!body || !sk || !pk || !out || !out_len)
        return QGP_E_ARG;
    *out = NULL;
    *out_len = 0;
    if (body_len > QGP_BODY_MAX)
        return QGP_E_BODY_TOO_LARGE;

    /* Refuse a non-canonical body before signing anything. */
    qgp_trust_state_t st;
    qgp_rc_t rc = qgp_trust_parse_body(body, body_len, &st);
    if (rc != QGP_OK)
        return rc;
    qgp_trust_state_free(&st);

    uint8_t signer[QGP_HASH_LEN], prev_digest[QGP_HASH_LEN];
    if (qgp_sha3_512(pk, QGP_PK_LEN, signer) != 0)
        return QGP_E_CRYPTO;
    if (prev) {
        if (qgp_sha3_512(prev->file, prev->file_len, prev_digest) != 0)
            return QGP_E_CRYPTO;
    } else {
        memset(prev_digest, 0, sizeof(prev_digest));
    }
    uint8_t m[QGP_M_TRUST_LEN];
    rc = qgp_trust_m_trust(serial, prev_digest, signer, body, body_len, m);
    if (rc != QGP_OK)
        return rc;
    uint8_t sig[QGP_SIG_LEN];
    size_t sig_len = 0;
    if (qgp_dsa87_sign(sig, &sig_len, m, sizeof(m), sk) != 0 || sig_len != QGP_SIG_LEN)
        return QGP_E_CRYPTO;
    if (qgp_dsa87_verify(sig, sig_len, m, sizeof(m), pk) != 0)
        return QGP_E_KEY_MISMATCH;

    size_t total = QGP_TRUST_FIXED + body_len + 2 + QGP_SIG_LEN;
    uint8_t *f = malloc(total);
    if (!f)
        return QGP_E_NOMEM;
    f[0] = QGP_FORMAT_VERSION;
    qgp_be64_put(f + 1, serial);
    memcpy(f + 9, signer, QGP_HASH_LEN);
    qgp_be32_put(f + 9 + QGP_HASH_LEN, (uint32_t)body_len);
    memcpy(f + QGP_TRUST_FIXED, body, body_len);
    qgp_be16_put(f + QGP_TRUST_FIXED + body_len, (uint16_t)QGP_SIG_LEN);
    memcpy(f + QGP_TRUST_FIXED + body_len + 2, sig, QGP_SIG_LEN);

    /* Never produce a file the acceptor would refuse. */
    rc = qgp_trust_verify(f, total, prev, NULL);
    if (rc != QGP_OK) {
        QGP_LOG_ERROR(LOG_TAG, "built trust file is not acceptable: %s", qgp_rc_str(rc));
        free(f);
        return rc;
    }
    *out = f;
    *out_len = total;
    return QGP_OK;
}
