/**
 * qgp_deb.h - the `_qgp.sig` package signature member (bytes doc §1 + REV 2).
 *
 *   prefix = file bytes from offset 0 ("!<arch>\n") through the end of the
 *            data.tar member INCLUDING its ar pad byte (R2-7);
 *   M_pkg  = "NDS.QGPDEB.v1"\0\0\0 | key_id(64) | prefix_len(8,BE) | SHA3-512(prefix)
 *   member = 0x01 | key_id(64) | prefix_len(8,BE) | sig_len(2,BE)=4627 | sig(4627)
 *   header = "_qgp.sig" + 8 spaces, mtime 0, uid 0, gid 0, mode 100644, size 4702.
 */
#ifndef QGP_DEB_H
#define QGP_DEB_H

#include <stddef.h>
#include <stdint.h>

#include "qgp_core.h"
#include "qgp_trust.h"

#define QGP_AR_HDR_LEN 60

/* The fixed 60-byte ar header of the `_qgp.sig` member (oracle QGP_HDR). */
extern const uint8_t QGP_DEB_SIG_HEADER[QGP_AR_HDR_LEN];

typedef struct {
    size_t         prefix_len;                 /* offset of the _qgp.sig header */
    uint8_t        key_id[QGP_HASH_LEN];
    const uint8_t *sig;                        /* QGP_SIG_LEN bytes inside the input */
} qgp_deb_sig_info_t;

/* M_pkg (152 bytes). */
qgp_rc_t qgp_deb_m_pkg(const uint8_t key_id[QGP_HASH_LEN],
                       const uint8_t *prefix, size_t prefix_len,
                       uint8_t out[QGP_M_PKG_LEN]);

/* Strict parse of an UNSIGNED .deb: exactly debian-binary, control.tar[.*],
 * data.tar[.*], nothing after (incl. the pad byte of an odd data member).
 * A 4th member refuses with QGP_E_EXTRA_MEMBER. */
qgp_rc_t qgp_deb_parse_unsigned(const uint8_t *d, size_t len);

/* Strict 4-member parse of a SIGNED .deb, then (R2-6) member version first,
 * sig_len, prefix_len recomputed. No trust lookup, no signature check. */
qgp_rc_t qgp_deb_parse_signed(const uint8_t *d, size_t len, qgp_deb_sig_info_t *out);

/* parse_signed + key in `st` and not revoked; builds M_pkg and returns the
 * pinned public key. No signature check (used by the KAT preimage test). */
qgp_rc_t qgp_deb_check(const uint8_t *d, size_t len, const qgp_trust_state_t *st,
                       qgp_deb_sig_info_t *out, uint8_t m_pkg[QGP_M_PKG_LEN],
                       const uint8_t **pk_out);

/* qgp_deb_check + ML-DSA-87 verification of the signature over M_pkg. */
qgp_rc_t qgp_deb_verify(const uint8_t *d, size_t len, const qgp_trust_state_t *st,
                        qgp_deb_sig_info_t *out);

/* Member content (4702 bytes) for a given key_id / prefix_len / signature. */
void qgp_deb_build_member(const uint8_t key_id[QGP_HASH_LEN], uint64_t prefix_len,
                          const uint8_t sig[QGP_SIG_LEN], uint8_t out[QGP_MEMBER_LEN]);

/* Sign an unsigned .deb: returns a new malloc'd buffer = input | header | member.
 * The signature is checked against `pk` before returning (a secret key that does
 * not belong to `pk` refuses with QGP_E_KEY_MISMATCH). */
qgp_rc_t qgp_deb_sign(const uint8_t *d, size_t len,
                      const uint8_t sk[QGP_SK_LEN], const uint8_t pk[QGP_PK_LEN],
                      uint8_t **out, size_t *out_len);

#endif /* QGP_DEB_H */
