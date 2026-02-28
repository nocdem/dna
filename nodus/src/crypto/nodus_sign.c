/**
 * Nodus v5 — Dilithium5 Crypto Wrapper
 *
 * Wraps shared/crypto qgp_dsa87_* functions with Nodus-typed API.
 */

#include "crypto/nodus_sign.h"
#include "crypto/utils/qgp_dilithium.h"
#include "crypto/utils/qgp_sha3.h"
#include "crypto/utils/qgp_platform.h"
#include <string.h>

int nodus_sign(nodus_sig_t *sig_out,
               const uint8_t *data, size_t data_len,
               const nodus_seckey_t *sk) {
    if (!sig_out || !data || !sk)
        return -1;

    size_t siglen = 0;
    int rc = qgp_dsa87_sign(sig_out->bytes, &siglen, data, data_len, sk->bytes);
    if (rc != 0)
        return -1;

    return 0;
}

int nodus_verify(const nodus_sig_t *sig,
                 const uint8_t *data, size_t data_len,
                 const nodus_pubkey_t *pk) {
    if (!sig || !data || !pk)
        return -1;

    return qgp_dsa87_verify(sig->bytes, NODUS_SIG_BYTES, data, data_len, pk->bytes);
}

int nodus_hash(const uint8_t *data, size_t data_len, nodus_key_t *hash_out) {
    if (!data || !hash_out)
        return -1;

    return qgp_sha3_512(data, data_len, hash_out->bytes);
}

int nodus_hash_hex(const uint8_t *data, size_t data_len, char *hex_out) {
    if (!data || !hex_out)
        return -1;

    return qgp_sha3_512_hex(data, data_len, hex_out, NODUS_KEY_HEX_LEN);
}

int nodus_fingerprint(const nodus_pubkey_t *pk, nodus_key_t *fp_out) {
    if (!pk || !fp_out)
        return -1;

    return qgp_sha3_512(pk->bytes, NODUS_PK_BYTES, fp_out->bytes);
}

int nodus_fingerprint_hex(const nodus_pubkey_t *pk, char *hex_out) {
    if (!pk || !hex_out)
        return -1;

    return qgp_sha3_512_fingerprint(pk->bytes, NODUS_PK_BYTES, hex_out);
}

int nodus_random(uint8_t *buf, size_t len) {
    if (!buf)
        return -1;

    return qgp_platform_random(buf, len);
}
