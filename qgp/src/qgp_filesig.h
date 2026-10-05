/**
 * qgp_filesig.h - detached ML-DSA-87 signature over an arbitrary file.
 *
 * APPROVED by the operator 2026-10-05 ("evet"), recorded in
 * docs/plans/decisions/2026-10-03-apt-repo-qgp.md ("qgp file signature APPROVED"):
 *
 *   M_file = "NDS.QGPFILE.v1"\0\0 (16) | file_len(8,BE) | SHA3-512(file)(64)   (88 bytes)
 *   pure ML-DSA-87, empty context;
 *   signature file = the raw 4627-byte ML-DSA-87 signature, nothing else.
 *
 * The tag is the 14-byte string right-padded with 0x00 to 16, the same padding
 * rule the approved package (§1) and trust (§2) tags use.
 */
#ifndef QGP_FILESIG_H
#define QGP_FILESIG_H

#include <stddef.h>
#include <stdint.h>

#include "qgp_core.h"

#define QGP_M_FILE_LEN (QGP_TAG_LEN + 8 + QGP_HASH_LEN)   /* 88 */

qgp_rc_t qgp_filesig_msg_v1(const uint8_t *data, size_t len,
                            uint8_t out[QGP_M_FILE_LEN]);

/* Sign `data`; the signature is checked against `pk` before it is returned. */
qgp_rc_t qgp_filesig_sign_v1(const uint8_t *data, size_t len,
                             const uint8_t sk[QGP_SK_LEN],
                             const uint8_t pk[QGP_PK_LEN],
                             uint8_t sig[QGP_SIG_LEN]);

qgp_rc_t qgp_filesig_verify_v1(const uint8_t *data, size_t len,
                               const uint8_t *sig, size_t sig_len,
                               const uint8_t pk[QGP_PK_LEN]);

#endif /* QGP_FILESIG_H */
