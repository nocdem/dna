/* Verify-only site SDK bridge. Construction and primitives stay in the
 * SAME nodus_sign.c / qgp_sha3_512 / ML-DSA-87 sources as the wallet.
 * Decision: 2026-10-28-extension-nodus-site-signing.md, origin addendum.
 * No identity, secret key, signing or key-generation entry point. */
#include "crypto/nodus_sign.h"
#include "crypto/hash/qgp_sha3.h"
#include "crypto/utils/qgp_platform.h"

/* Same volatile wipe as nodus-send-wasm.c, without a platform dependency. */
void qgp_secure_memzero(void *ptr, size_t len) {
    volatile uint8_t *p = ptr;
    while (len--) *p++ = 0;
}

int nsv_verify(const uint8_t *origin, size_t origin_len,
                const uint8_t *message, size_t message_len,
                const nodus_sig_t *signature, const nodus_pubkey_t *public_key) {
    return nodus_verify_site_message(signature, origin, origin_len,
                                      message, message_len, public_key) == 0;
}

/* Nodus address rule: web-wallet/src/nodus/derive.js deriveNodusAddress.
 * Caller supplies a full public key and a QGP_SHA3_512_DIGEST_LENGTH buffer;
 * JavaScript converts these digest bytes to lowercase hex. */
int nsv_address_of(const nodus_pubkey_t *public_key, uint8_t *address) {
    if (!public_key || !address) return -1;
    return qgp_sha3_512(public_key->bytes, sizeof(public_key->bytes), address);
}
