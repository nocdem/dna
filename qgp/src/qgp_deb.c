/**
 * qgp_deb.c - strict ar walk of a .deb and the `_qgp.sig` member (bytes doc §1,
 * REV 2 R2-6/R2-7).
 *
 * Container references: deb(5) (dpkg 1.21.23: "!<arch>" ar archive; members
 * debian-binary, control.tar[.ext], data.tar[.ext] "in this exact order"; names
 * with an optional trailing slash; sizes "limited to 10 ASCII decimal digits")
 * and the glibc struct ar_hdr field widths (name 16, date 12, uid 6, gid 6,
 * mode 8, size 10, fmag "`\n" = 60 bytes). Odd-sized members are followed by one
 * "\n" pad byte.
 *
 * Parse order follows the oracle's reading R-ORDER, so the reject reasons match
 * qgp_deb_kat.json: per member header bounds, fmag, size digits, name/position,
 * `_qgp.sig` header exactness, member bounds, pad byte; after the four members
 * the member version byte, sig_len, prefix_len; then (qgp_deb_check) revoked,
 * unknown key.
 */
#include "qgp_deb.h"

#include <stdlib.h>
#include <string.h>

#include "crypto/utils/qgp_log.h"
#include "crypto/utils/qgp_safe_string.h"

#define LOG_TAG "QGP_DEB"

static const uint8_t AR_MAGIC[8] = { '!', '<', 'a', 'r', 'c', 'h', '>', '\n' };

/* "_qgp.sig" + 8 spaces | "0" + 11 sp | "0" + 5 sp | "0" + 5 sp | "100644" + 2 sp |
 * "4702" + 6 sp | "`\n" */
const uint8_t QGP_DEB_SIG_HEADER[QGP_AR_HDR_LEN] =
    "_qgp.sig        0           0     0     100644  4702      `\n";
_Static_assert(sizeof("_qgp.sig        0           0     0     100644  4702      `\n") - 1
               == QGP_AR_HDR_LEN, "_qgp.sig ar header must be 60 bytes");
_Static_assert(QGP_MEMBER_LEN == 4702, "member length");
_Static_assert(QGP_M_PKG_LEN == 152, "M_pkg length");

/* "NDS.QGPDEB.v1" (13) right-padded with 0x00 to 16 (oracle R-TAGS). */
static const uint8_t TAG_PKG[QGP_TAG_LEN] = {
    'N', 'D', 'S', '.', 'Q', 'G', 'P', 'D', 'E', 'B', '.', 'v', '1', 0, 0, 0
};

static const char *const NAMES_DEBIAN_BINARY[] = { "debian-binary" };
static const char *const NAMES_CONTROL[] = {
    "control.tar", "control.tar.gz", "control.tar.xz", "control.tar.zst"
};
static const char *const NAMES_DATA[] = {
    "data.tar", "data.tar.gz", "data.tar.xz", "data.tar.zst", "data.tar.bz2", "data.tar.lzma"
};

/* Name field = name, or name + "/", space-padded to 16 (R2-6, oracle R-NAMES). */
static int field_is_name(const uint8_t field[16], const char *name, int with_slash)
{
    uint8_t want[16];
    size_t n = strlen(name);
    if (n + (with_slash ? 1u : 0u) > 16)
        return 0;
    memset(want, ' ', sizeof(want));
    memcpy(want, name, n);
    if (with_slash)
        want[n] = '/';
    return memcmp(field, want, 16) == 0;
}

static int name_in(const uint8_t field[16], const char *const *names, size_t count)
{
    for (size_t i = 0; i < count; i++) {
        if (field_is_name(field, names[i], 0) || field_is_name(field, names[i], 1))
            return 1;
    }
    return 0;
}

/* 1..10 ASCII digits, left-aligned, remainder spaces (oracle R-AR-SIZE). */
static qgp_rc_t parse_size_field(const uint8_t f[10], uint64_t *out)
{
    size_t n = 10;
    while (n > 0 && f[n - 1] == ' ')
        n--;
    if (n == 0)
        return QGP_E_BAD_SIZE_FIELD;
    uint64_t v = 0;
    for (size_t i = 0; i < n; i++) {
        if (f[i] < '0' || f[i] > '9')
            return QGP_E_BAD_SIZE_FIELD;
        v = v * 10u + (uint64_t)(f[i] - '0');   /* <= 9,999,999,999: no overflow */
    }
    *out = v;
    return QGP_OK;
}

typedef struct {
    size_t   hdr_off[4];
    size_t   data_off[4];
    uint64_t size[4];
    size_t   count;
} ar_walk_t;

/* Walk exactly `want` members (3 = unsigned, 4 = signed); the file must end at
 * the last member's end (incl. its pad byte). */
static qgp_rc_t ar_walk(const uint8_t *d, size_t len, size_t want, ar_walk_t *w)
{
    memset(w, 0, sizeof(*w));
    if (len < sizeof(AR_MAGIC) || memcmp(d, AR_MAGIC, sizeof(AR_MAGIC)) != 0)
        return QGP_E_BAD_AR_MAGIC;

    size_t off = sizeof(AR_MAGIC);
    size_t idx = 0;
    while (off < len) {
        if (idx >= want)
            return want == 4 ? QGP_E_MEMBER_AFTER_QGP_SIG : QGP_E_EXTRA_MEMBER;
        if (len - off < QGP_AR_HDR_LEN)
            return QGP_E_TRUNCATED_HEADER;
        const uint8_t *hdr = d + off;
        if (hdr[58] != '`' || hdr[59] != '\n')
            return QGP_E_BAD_FMAG;
        uint64_t size;
        qgp_rc_t rc = parse_size_field(hdr + 48, &size);
        if (rc != QGP_OK)
            return rc;
        switch (idx) {
        case 0:
            if (!name_in(hdr, NAMES_DEBIAN_BINARY, 1))
                return QGP_E_UNEXPECTED_MEMBER_NAME;
            break;
        case 1:
            if (!name_in(hdr, NAMES_CONTROL, sizeof(NAMES_CONTROL) / sizeof(NAMES_CONTROL[0])))
                return QGP_E_UNEXPECTED_MEMBER_NAME;
            break;
        case 2:
            if (!name_in(hdr, NAMES_DATA, sizeof(NAMES_DATA) / sizeof(NAMES_DATA[0])))
                return QGP_E_UNEXPECTED_MEMBER_NAME;
            break;
        default:
            if (!field_is_name(hdr, "_qgp.sig", 0))
                return QGP_E_UNEXPECTED_MEMBER_NAME;
            if (memcmp(hdr, QGP_DEB_SIG_HEADER, QGP_AR_HDR_LEN) != 0)
                return QGP_E_QGP_SIG_HEADER_NOT_EXACT;
            break;
        }
        size_t start = off + QGP_AR_HDR_LEN;
        if (size > (uint64_t)(len - start))
            return QGP_E_TRUNCATED_MEMBER;
        size_t end = start + (size_t)size;
        size_t next;
        if (size % 2u == 1u) {
            if (end >= len || d[end] != '\n')
                return QGP_E_BAD_OR_MISSING_PADDING;
            next = end + 1;
        } else {
            next = end;
        }
        w->hdr_off[idx] = off;
        w->data_off[idx] = start;
        w->size[idx] = size;
        off = next;
        idx++;
    }
    if (idx < want)
        return QGP_E_MISSING_MEMBER;
    w->count = idx;
    return QGP_OK;
}

qgp_rc_t qgp_deb_m_pkg(const uint8_t key_id[QGP_HASH_LEN],
                       const uint8_t *prefix, size_t prefix_len,
                       uint8_t out[QGP_M_PKG_LEN])
{
    if (!key_id || !prefix || !out)
        return QGP_E_ARG;
    memcpy(out, TAG_PKG, QGP_TAG_LEN);
    memcpy(out + QGP_TAG_LEN, key_id, QGP_HASH_LEN);
    qgp_be64_put(out + QGP_TAG_LEN + QGP_HASH_LEN, (uint64_t)prefix_len);
    if (qgp_sha3_512(prefix, prefix_len, out + QGP_TAG_LEN + QGP_HASH_LEN + 8) != 0)
        return QGP_E_CRYPTO;
    return QGP_OK;
}

qgp_rc_t qgp_deb_parse_unsigned(const uint8_t *d, size_t len)
{
    ar_walk_t w;
    if (!d)
        return QGP_E_ARG;
    return ar_walk(d, len, 3, &w);
}

qgp_rc_t qgp_deb_parse_signed(const uint8_t *d, size_t len, qgp_deb_sig_info_t *out)
{
    ar_walk_t w;
    if (!d || !out)
        return QGP_E_ARG;
    memset(out, 0, sizeof(*out));
    qgp_rc_t rc = ar_walk(d, len, 4, &w);
    if (rc != QGP_OK)
        return rc;
    /* The exact-header check pinned the size to 4702. */
    const uint8_t *m = d + w.data_off[3];
    if (w.size[3] != QGP_MEMBER_LEN)
        return QGP_E_QGP_SIG_HEADER_NOT_EXACT;
    /* R2-6: version first */
    if (m[0] != QGP_FORMAT_VERSION)
        return QGP_E_MEMBER_VERSION;
    uint64_t prefix_len = qgp_be64_get(m + 1 + QGP_HASH_LEN);
    uint16_t sig_len = qgp_be16_get(m + 1 + QGP_HASH_LEN + 8);
    if (sig_len != QGP_SIG_LEN)
        return QGP_E_SIG_LEN;
    if (prefix_len != (uint64_t)w.hdr_off[3])
        return QGP_E_PREFIX_LEN_MISMATCH;
    out->prefix_len = w.hdr_off[3];
    memcpy(out->key_id, m + 1, QGP_HASH_LEN);
    out->sig = m + 1 + QGP_HASH_LEN + 8 + 2;
    return QGP_OK;
}

qgp_rc_t qgp_deb_check(const uint8_t *d, size_t len, const qgp_trust_state_t *st,
                       qgp_deb_sig_info_t *out, uint8_t m_pkg[QGP_M_PKG_LEN],
                       const uint8_t **pk_out)
{
    if (!d || !st || !out || !m_pkg)
        return QGP_E_ARG;
    qgp_rc_t rc = qgp_deb_parse_signed(d, len, out);
    if (rc != QGP_OK)
        return rc;
    if (qgp_trust_is_revoked(st, out->key_id))
        return QGP_E_REVOKED_KEY;
    const qgp_trust_key_t *k = qgp_trust_find_key(st, out->key_id);
    if (!k)
        return QGP_E_UNKNOWN_KEY;
    rc = qgp_deb_m_pkg(out->key_id, d, out->prefix_len, m_pkg);
    if (rc != QGP_OK)
        return rc;
    if (pk_out)
        *pk_out = k->pk;
    return QGP_OK;
}

qgp_rc_t qgp_deb_verify(const uint8_t *d, size_t len, const qgp_trust_state_t *st,
                        qgp_deb_sig_info_t *out)
{
    uint8_t m_pkg[QGP_M_PKG_LEN];
    const uint8_t *pk = NULL;
    qgp_deb_sig_info_t local;
    qgp_deb_sig_info_t *info = out ? out : &local;
    qgp_rc_t rc = qgp_deb_check(d, len, st, info, m_pkg, &pk);
    if (rc != QGP_OK)
        return rc;
    if (qgp_dsa87_verify(info->sig, QGP_SIG_LEN, m_pkg, sizeof(m_pkg), pk) != 0) {
        QGP_LOG_WARN(LOG_TAG, "package signature does not verify");
        return QGP_E_SIGNATURE;
    }
    return QGP_OK;
}

void qgp_deb_build_member(const uint8_t key_id[QGP_HASH_LEN], uint64_t prefix_len,
                          const uint8_t sig[QGP_SIG_LEN], uint8_t out[QGP_MEMBER_LEN])
{
    out[0] = QGP_FORMAT_VERSION;
    memcpy(out + 1, key_id, QGP_HASH_LEN);
    qgp_be64_put(out + 1 + QGP_HASH_LEN, prefix_len);
    qgp_be16_put(out + 1 + QGP_HASH_LEN + 8, (uint16_t)QGP_SIG_LEN);
    memcpy(out + 1 + QGP_HASH_LEN + 8 + 2, sig, QGP_SIG_LEN);
}

qgp_rc_t qgp_deb_sign(const uint8_t *d, size_t len,
                      const uint8_t sk[QGP_SK_LEN], const uint8_t pk[QGP_PK_LEN],
                      uint8_t **out, size_t *out_len)
{
    if (!d || !sk || !pk || !out || !out_len)
        return QGP_E_ARG;
    *out = NULL;
    *out_len = 0;
    if (len > QGP_FILE_MAX)
        return QGP_E_TOO_LARGE;

    qgp_rc_t rc = qgp_deb_parse_unsigned(d, len);
    if (rc != QGP_OK)
        return rc;

    uint8_t key_id[QGP_HASH_LEN];
    if (qgp_sha3_512(pk, QGP_PK_LEN, key_id) != 0)
        return QGP_E_CRYPTO;
    uint8_t m_pkg[QGP_M_PKG_LEN];
    rc = qgp_deb_m_pkg(key_id, d, len, m_pkg);
    if (rc != QGP_OK)
        return rc;

    uint8_t sig[QGP_SIG_LEN];
    size_t sig_len = 0;
    if (qgp_dsa87_sign(sig, &sig_len, m_pkg, sizeof(m_pkg), sk) != 0 || sig_len != QGP_SIG_LEN)
        return QGP_E_CRYPTO;
    if (qgp_dsa87_verify(sig, sig_len, m_pkg, sizeof(m_pkg), pk) != 0)
        return QGP_E_KEY_MISMATCH;

    size_t total = len + QGP_AR_HDR_LEN + QGP_MEMBER_LEN;
    uint8_t *buf = malloc(total);
    if (!buf)
        return QGP_E_NOMEM;
    memcpy(buf, d, len);
    memcpy(buf + len, QGP_DEB_SIG_HEADER, QGP_AR_HDR_LEN);
    qgp_deb_build_member(key_id, (uint64_t)len, sig, buf + len + QGP_AR_HDR_LEN);

    /* The output must parse as a signed .deb whose prefix is the whole input. */
    qgp_deb_sig_info_t info;
    rc = qgp_deb_parse_signed(buf, total, &info);
    if (rc != QGP_OK || info.prefix_len != len) {
        QGP_LOG_ERROR(LOG_TAG, "signed output does not re-parse: %s", qgp_rc_str(rc));
        free(buf);
        return rc != QGP_OK ? rc : QGP_E_PREFIX_LEN_MISMATCH;
    }
    *out = buf;
    *out_len = total;
    return QGP_OK;
}
