/**
 * qgp_filesig.c - detached file signature, format APPROVED 2026-10-05
 * (docs/plans/decisions/2026-10-03-apt-repo-qgp.md; layout in qgp_filesig.h).
 * Pure ML-DSA-87 (empty context) over a tagged message, the same construction
 * the approved §1/§2 messages use.
 */
#include "qgp_filesig.h"

#include <string.h>

#include "crypto/utils/qgp_safe_string.h"

/* "NDS.QGPFILE.v1" (14) right-padded with 0x00 to 16. */
static const uint8_t TAG_FILE[QGP_TAG_LEN] = {
    'N', 'D', 'S', '.', 'Q', 'G', 'P', 'F', 'I', 'L', 'E', '.', 'v', '1', 0, 0
};
_Static_assert(QGP_TAG_LEN == 16, "file tag length");
_Static_assert(QGP_M_FILE_LEN == 88, "M_file length");

qgp_rc_t qgp_filesig_msg_v1(const uint8_t *data, size_t len,
                            uint8_t out[QGP_M_FILE_LEN])
{
    static const uint8_t empty = 0;
    if ((!data && len != 0) || !out)
        return QGP_E_ARG;
    if (len > QGP_FILE_MAX)
        return QGP_E_TOO_LARGE;
    memcpy(out, TAG_FILE, QGP_TAG_LEN);
    qgp_be64_put(out + QGP_TAG_LEN, (uint64_t)len);
    if (qgp_sha3_512(data ? data : &empty, len, out + QGP_TAG_LEN + 8) != 0)
        return QGP_E_CRYPTO;
    return QGP_OK;
}

qgp_rc_t qgp_filesig_sign_v1(const uint8_t *data, size_t len,
                             const uint8_t sk[QGP_SK_LEN],
                             const uint8_t pk[QGP_PK_LEN],
                             uint8_t sig[QGP_SIG_LEN])
{
    if (!sk || !pk || !sig)
        return QGP_E_ARG;
    uint8_t m[QGP_M_FILE_LEN];
    qgp_rc_t rc = qgp_filesig_msg_v1(data, len, m);
    if (rc != QGP_OK)
        return rc;
    size_t sig_len = 0;
    if (qgp_dsa87_sign(sig, &sig_len, m, sizeof(m), sk) != 0 || sig_len != QGP_SIG_LEN)
        return QGP_E_CRYPTO;
    if (qgp_dsa87_verify(sig, sig_len, m, sizeof(m), pk) != 0)
        return QGP_E_KEY_MISMATCH;
    return QGP_OK;
}

qgp_rc_t qgp_filesig_verify_v1(const uint8_t *data, size_t len,
                               const uint8_t *sig, size_t sig_len,
                               const uint8_t pk[QGP_PK_LEN])
{
    if (!sig || !pk)
        return QGP_E_ARG;
    if (sig_len != QGP_SIG_LEN)
        return QGP_E_SIG_LEN;
    uint8_t m[QGP_M_FILE_LEN];
    qgp_rc_t rc = qgp_filesig_msg_v1(data, len, m);
    if (rc != QGP_OK)
        return rc;
    if (qgp_dsa87_verify(sig, sig_len, m, sizeof(m), pk) != 0)
        return QGP_E_SIGNATURE;
    return QGP_OK;
}
