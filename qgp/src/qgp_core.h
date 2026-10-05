/**
 * qgp_core.h - QGP phase 1 (signing): shared constants, result codes, helpers.
 *
 * Byte layouts: docs/plans/2026-10-05-apt-qgp-signing-bytes.md items 1-3 as
 * amended by its REV 2 (APPROVED, docs/plans/decisions/2026-10-05-groups-apt-bytes-approved.md).
 * Independent oracle + KAT: scripts/qgp-sign/qgp_deb_oracle.py / qgp_deb_kat.json.
 *
 * Written fresh on shared/crypto (ML-DSA-87 via qgp_dsa87_*, SHA3-512 via
 * qgp_sha3_512). No code from the historical QGP repository.
 */
#ifndef QGP_CORE_H
#define QGP_CORE_H

#include <stddef.h>
#include <stdint.h>

#include "crypto/sign/qgp_dilithium.h"
#include "crypto/hash/qgp_sha3.h"

#define QGP_HASH_LEN      QGP_SHA3_512_DIGEST_LENGTH   /* 64 */
#define QGP_PK_LEN        QGP_DSA87_PUBLICKEYBYTES     /* 2592 */
#define QGP_SK_LEN        QGP_DSA87_SECRETKEYBYTES     /* 4896 */
#define QGP_SIG_LEN       QGP_DSA87_SIGNATURE_BYTES    /* 4627 */
#define QGP_TAG_LEN       16
#define QGP_FORMAT_VERSION 0x01

/* §1: M_pkg = tag(16) | key_id(64) | prefix_len(8,BE) | SHA3-512(prefix)(64) */
#define QGP_M_PKG_LEN     (QGP_TAG_LEN + QGP_HASH_LEN + 8 + QGP_HASH_LEN)          /* 152 */
/* §1: member = version(1) | key_id(64) | prefix_len(8,BE) | sig_len(2,BE) | sig */
#define QGP_MEMBER_LEN    (1 + QGP_HASH_LEN + 8 + 2 + QGP_SIG_LEN)                 /* 4702 */
/* R2-3: M_trust = tag(16) | serial(8) | prev_digest(64) | signer(64) | SHA3-512(body) */
#define QGP_M_TRUST_LEN   (QGP_TAG_LEN + 8 + QGP_HASH_LEN + QGP_HASH_LEN + QGP_HASH_LEN) /* 216 */
/* §2: file = version(1) | serial(8) | signer(64) | body_len(4) | body | sig_len(2) | sig */
#define QGP_TRUST_FIXED   (1 + 8 + QGP_HASH_LEN + 4)                               /* 77 */
#define QGP_BODY_MAX      (64u * 1024u)        /* R2-6, inclusive (oracle R-BODYMAX) */
#define QGP_TRUST_FILE_MAX (QGP_TRUST_FIXED + QGP_BODY_MAX + 2 + QGP_SIG_LEN)

/* Upper bound on any whole file this tool loads (a .deb, a file to sign). */
#define QGP_FILE_MAX      ((size_t)1 << 30)    /* 1 GiB */

/* Result codes. The deb / trust reject names match the oracle's reason strings
 * (qgp_deb_kat.json "expected_reason") so the test can compare them. */
typedef enum {
    QGP_OK = 0,
    /* generic */
    QGP_E_ARG,
    QGP_E_IO,
    QGP_E_NOMEM,
    QGP_E_TOO_LARGE,
    QGP_E_CRYPTO,
    QGP_E_SIGNATURE,          /* ML-DSA-87 verification failed */
    QGP_E_KEY_FILE,           /* key file wrong size / unsafe mode */
    QGP_E_KEY_MISMATCH,       /* secret key does not match the public key next to it */
    /* .deb container (§1, R2-6) */
    QGP_E_BAD_AR_MAGIC,
    QGP_E_MEMBER_AFTER_QGP_SIG,
    QGP_E_TRUNCATED_HEADER,
    QGP_E_BAD_FMAG,
    QGP_E_BAD_SIZE_FIELD,
    QGP_E_UNEXPECTED_MEMBER_NAME,
    QGP_E_QGP_SIG_HEADER_NOT_EXACT,
    QGP_E_TRUNCATED_MEMBER,
    QGP_E_BAD_OR_MISSING_PADDING,
    QGP_E_MISSING_MEMBER,
    QGP_E_MEMBER_VERSION,
    QGP_E_SIG_LEN,
    QGP_E_PREFIX_LEN_MISMATCH,
    QGP_E_REVOKED_KEY,
    QGP_E_UNKNOWN_KEY,
    QGP_E_EXTRA_MEMBER,       /* deb-sign input: a 4th member already present */
    /* trust body (§2, R2-1, R2-6) */
    QGP_E_BODY_TOO_LARGE,
    QGP_E_NON_PRINTABLE_ASCII_BYTE,
    QGP_E_MISSING_FINAL_LF,
    QGP_E_BLANK_LINE,
    QGP_E_TRAILING_SPACE,
    QGP_E_BAD_FIELD_SEPARATOR,
    QGP_E_BAD_FIELD_COUNT,
    QGP_E_BAD_FINGERPRINT_HEX,
    QGP_E_BAD_PK_HEX_OR_LENGTH,
    QGP_E_KEY_FP_MISMATCH,
    QGP_E_UNKNOWN_RECORD_TYPE,
    QGP_E_BAD_FLOOR_PACKAGE,
    QGP_E_BAD_FLOOR_VERSION,
    QGP_E_DUPLICATE_LINE,
    QGP_E_UNSORTED,
    QGP_E_DUPLICATE_KEY_FP,
    QGP_E_DUPLICATE_FLOOR,
    QGP_E_KEY_AND_REVOKED,
    QGP_E_NO_KEY,
    /* trust file + policy (§2, R2-2, R2-3) */
    QGP_E_FILE_LENGTH,
    QGP_E_FILE_VERSION,
    QGP_E_SERIAL_NOT_INCREASING,
    QGP_E_SIGNER_REVOKED,
    QGP_E_SIGNER_NOT_TRUSTED,
    QGP_E_REVOCATION_DROPPED,
    QGP_E_FLOOR_DROPPED,
    QGP_E_FLOOR_LOWERED,
    /* state dir / package policy (§1 verify, R2-5) */
    QGP_E_NO_TRUST_STATE,
    QGP_E_STATE_EXISTS,
    QGP_E_STATE_CORRUPT,
    QGP_E_DPKG_DEB,
    QGP_E_BAD_CONTROL_FIELDS,
    QGP_E_BAD_PACKAGE_NAME,
    QGP_E_BAD_VERSION,
    QGP_E_BAD_ARCHITECTURE,
    QGP_E_BELOW_FLOOR,
    QGP_E_DOWNGRADE,
    QGP_E__COUNT
} qgp_rc_t;

/* Stable lowercase name of a result code (oracle reason string where one exists). */
const char *qgp_rc_str(qgp_rc_t rc);

static inline void qgp_be64_put(uint8_t *p, uint64_t v)
{
    for (int i = 7; i >= 0; i--) { p[i] = (uint8_t)(v & 0xff); v >>= 8; }
}
static inline void qgp_be32_put(uint8_t *p, uint32_t v)
{
    for (int i = 3; i >= 0; i--) { p[i] = (uint8_t)(v & 0xff); v >>= 8; }
}
static inline void qgp_be16_put(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v & 0xff);
}
static inline uint64_t qgp_be64_get(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | p[i];
    return v;
}
static inline uint32_t qgp_be32_get(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}
static inline uint16_t qgp_be16_get(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

/* Lowercase hex. qgp_hex_encode writes 2*n chars + NUL (out must hold 2*n+1).
 * qgp_hex_decode_lower accepts exactly 2*n lowercase hex chars; returns 0 / -1. */
void qgp_hex_encode(const uint8_t *in, size_t n, char *out);
int qgp_hex_decode_lower(const char *in, size_t in_len, uint8_t *out, size_t n);

#endif /* QGP_CORE_H */
