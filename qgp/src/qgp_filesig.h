/**
 * qgp_filesig.h - detached ML-DSA-87 signature over an arbitrary file.
 *
 * !!! NOT IN THE APPROVED BYTES. !!!
 * docs/plans/2026-10-05-apt-qgp-signing-bytes.md (APPROVED) defines only the
 * package member (§1) and the trust file (§2). The message below was given by
 * the dispatch for `qgp sign` / `qgp verify` and awaits the operator's approval;
 * the function name carries that status so no caller mistakes it for an
 * approved format:
 *
 *   M_file = "NDS.QGPFILE.v1"\0\0 (16) | file_len(8,BE) | SHA3-512(file)(64)   (88 bytes)
 *   signature file = the raw 4627-byte ML-DSA-87 signature, nothing else.
 */
#ifndef QGP_FILESIG_H
#define QGP_FILESIG_H

#include <stddef.h>
#include <stdint.h>

#include "qgp_core.h"

#define QGP_M_FILE_LEN (QGP_TAG_LEN + 8 + QGP_HASH_LEN)   /* 88 */

qgp_rc_t qgp_filesig_msg_v1_UNAPPROVED(const uint8_t *data, size_t len,
                                       uint8_t out[QGP_M_FILE_LEN]);

/* Sign `data`; the signature is checked against `pk` before it is returned. */
qgp_rc_t qgp_filesig_sign_v1_UNAPPROVED(const uint8_t *data, size_t len,
                                        const uint8_t sk[QGP_SK_LEN],
                                        const uint8_t pk[QGP_PK_LEN],
                                        uint8_t sig[QGP_SIG_LEN]);

qgp_rc_t qgp_filesig_verify_v1_UNAPPROVED(const uint8_t *data, size_t len,
                                          const uint8_t *sig, size_t sig_len,
                                          const uint8_t pk[QGP_PK_LEN]);

#endif /* QGP_FILESIG_H */
