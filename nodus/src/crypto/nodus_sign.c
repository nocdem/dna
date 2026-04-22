/**
 * Nodus — Dilithium5 Crypto Wrapper
 *
 * Wraps shared/crypto qgp_dsa87_* functions with Nodus-typed API.
 * See nodus_sign.h for domain separation rationale (C2 fix).
 */

#include "crypto/nodus_sign.h"
#include "crypto/sign/qgp_dilithium.h"
#include "crypto/hash/qgp_sha3.h"
#include "crypto/utils/qgp_platform.h"
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include "crypto/utils/qgp_safe_string.h"   /* Phase 03: unsafe-string poison guard */

/* ───── Raw API (legacy + TX_HASH) ──────────────────────────────────── */

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

/* ───── Tagged preimage builder ─────────────────────────────────────── */

/* Build tagged preimage into buf. Returns bytes written, or 0 on error.
 * Caller must ensure buf has at least NODUS_SIGN_HEADER_LEN + data_len bytes.
 *
 * Layout: "NDS1" (4) || purpose (1) || data_len_be (4) || data (data_len).
 * data_len is u32 BE to rule out truncation attacks and SIZE_MAX overflow
 * on 32-bit platforms.
 */
static size_t build_tagged_preimage(uint8_t *buf, size_t buf_cap,
                                    uint8_t purpose,
                                    const uint8_t *data, size_t data_len) {
    if (!buf || !data) return 0;
    if (data_len > UINT32_MAX) return 0;
    if (buf_cap < NODUS_SIGN_HEADER_LEN + data_len) return 0;

    memcpy(buf, NODUS_SIGN_MAGIC, NODUS_SIGN_MAGIC_LEN);
    buf[NODUS_SIGN_MAGIC_LEN] = purpose;

    uint32_t dl = (uint32_t)data_len;
    buf[NODUS_SIGN_MAGIC_LEN + 1 + 0] = (uint8_t)(dl >> 24);
    buf[NODUS_SIGN_MAGIC_LEN + 1 + 1] = (uint8_t)(dl >> 16);
    buf[NODUS_SIGN_MAGIC_LEN + 1 + 2] = (uint8_t)(dl >> 8);
    buf[NODUS_SIGN_MAGIC_LEN + 1 + 3] = (uint8_t)(dl & 0xff);

    memcpy(buf + NODUS_SIGN_HEADER_LEN, data, data_len);
    return NODUS_SIGN_HEADER_LEN + data_len;
}

/* ───── Tagged sign/verify (internal engine) ────────────────────────── */

int nodus_sign_tagged(nodus_sig_t *sig_out,
                      uint8_t purpose,
                      const uint8_t *data, size_t data_len,
                      const nodus_seckey_t *sk) {
    if (!sig_out || !data || !sk) return -1;

    /* For most domains the data is small (32B-1600B). Use stack for <= 8KB,
     * heap above — we expect T3_ENVELOPE to be the largest practical case. */
    /* Safety cap: prevent SIZE_MAX overflow on 32-bit systems. Real upper
     * bound is set by the caller's wire format (~4 MB for VALUE_STORE). */
    if (data_len > (SIZE_MAX - NODUS_SIGN_HEADER_LEN)) return -1;

    const size_t preimage_len = NODUS_SIGN_HEADER_LEN + data_len;
    if (preimage_len < data_len) return -1;  /* overflow guard */

    uint8_t stack_buf[8192];
    uint8_t *buf;
    uint8_t *heap_buf = NULL;

    if (preimage_len <= sizeof(stack_buf)) {
        buf = stack_buf;
    } else {
        heap_buf = (uint8_t *)malloc(preimage_len);
        if (!heap_buf) return -1;
        buf = heap_buf;
    }

    size_t n = build_tagged_preimage(buf, preimage_len, purpose, data, data_len);
    if (n != preimage_len) {
        if (heap_buf) free(heap_buf);
        return -1;
    }

    size_t siglen = 0;
    int rc = qgp_dsa87_sign(sig_out->bytes, &siglen, buf, preimage_len, sk->bytes);

    if (heap_buf) {
        qgp_secure_memzero(heap_buf, preimage_len);
        free(heap_buf);
    }

    return (rc == 0) ? 0 : -1;
}

int nodus_verify_tagged(const nodus_sig_t *sig,
                        uint8_t purpose,
                        const uint8_t *data, size_t data_len,
                        const nodus_pubkey_t *pk) {
    if (!sig || !data || !pk) return -1;
    if (data_len > (SIZE_MAX - NODUS_SIGN_HEADER_LEN)) return -1;

    const size_t preimage_len = NODUS_SIGN_HEADER_LEN + data_len;
    if (preimage_len < data_len) return -1;

    uint8_t stack_buf[8192];
    uint8_t *buf;
    uint8_t *heap_buf = NULL;

    if (preimage_len <= sizeof(stack_buf)) {
        buf = stack_buf;
    } else {
        heap_buf = (uint8_t *)malloc(preimage_len);
        if (!heap_buf) return -1;
        buf = heap_buf;
    }

    size_t n = build_tagged_preimage(buf, preimage_len, purpose, data, data_len);
    if (n != preimage_len) {
        if (heap_buf) free(heap_buf);
        return -1;
    }

    int rc = qgp_dsa87_verify(sig->bytes, NODUS_SIG_BYTES, buf, preimage_len, pk->bytes);

    if (heap_buf) {
        free(heap_buf);
    }

    if (rc == 0) return 0;

    /* Compat fallback — accept raw (pre-11467980) client signatures. The
     * domain separation closes C2 (cross-domain sig reuse) for new clients;
     * this bridge lets Flutter/mobile builds still shipped with the old
     * libdna connect until they update. Keep gated by the auth_initiated_by_us
     * rule (H8 oracle stays closed either way). REMOVE once all deployed
     * clients ship commit 11467980 or later. */
    return qgp_dsa87_verify(sig->bytes, NODUS_SIG_BYTES, data, data_len, pk->bytes);
}

/* ───── Domain-specific wrappers ────────────────────────────────────── */

int nodus_sign_auth_challenge(nodus_sig_t *sig_out,
                              const uint8_t *nonce,
                              const nodus_seckey_t *sk) {
    return nodus_sign_tagged(sig_out, NODUS_PURPOSE_AUTH_CHALLENGE,
                              nonce, NODUS_NONCE_LEN, sk);
}

int nodus_verify_auth_challenge(const nodus_sig_t *sig,
                                const uint8_t *nonce,
                                const nodus_pubkey_t *pk) {
    return nodus_verify_tagged(sig, NODUS_PURPOSE_AUTH_CHALLENGE,
                                nonce, NODUS_NONCE_LEN, pk);
}

int nodus_sign_kyber_bind(nodus_sig_t *sig_out,
                          const uint8_t *sign_data, size_t sign_data_len,
                          const nodus_seckey_t *sk) {
    return nodus_sign_tagged(sig_out, NODUS_PURPOSE_KYBER_BIND,
                              sign_data, sign_data_len, sk);
}

int nodus_verify_kyber_bind(const nodus_sig_t *sig,
                            const uint8_t *sign_data, size_t sign_data_len,
                            const nodus_pubkey_t *pk) {
    return nodus_verify_tagged(sig, NODUS_PURPOSE_KYBER_BIND,
                                sign_data, sign_data_len, pk);
}

int nodus_sign_t3_envelope(nodus_sig_t *sig_out,
                           const uint8_t *envelope, size_t envelope_len,
                           const nodus_seckey_t *sk) {
    return nodus_sign_tagged(sig_out, NODUS_PURPOSE_T3_ENVELOPE,
                              envelope, envelope_len, sk);
}

int nodus_verify_t3_envelope(const nodus_sig_t *sig,
                             const uint8_t *envelope, size_t envelope_len,
                             const nodus_pubkey_t *pk) {
    return nodus_verify_tagged(sig, NODUS_PURPOSE_T3_ENVELOPE,
                                envelope, envelope_len, pk);
}

int nodus_sign_value_store(nodus_sig_t *sig_out,
                           const uint8_t *payload, size_t payload_len,
                           const nodus_seckey_t *sk) {
    return nodus_sign_tagged(sig_out, NODUS_PURPOSE_VALUE_STORE,
                              payload, payload_len, sk);
}

int nodus_verify_value_store(const nodus_sig_t *sig,
                             const uint8_t *payload, size_t payload_len,
                             const nodus_pubkey_t *pk) {
    return nodus_verify_tagged(sig, NODUS_PURPOSE_VALUE_STORE,
                                payload, payload_len, pk);
}

int nodus_sign_cert(nodus_sig_t *sig_out,
                    const uint8_t *preimage, size_t preimage_len,
                    const nodus_seckey_t *sk) {
    return nodus_sign_tagged(sig_out, NODUS_PURPOSE_CERT,
                              preimage, preimage_len, sk);
}

int nodus_verify_cert(const nodus_sig_t *sig,
                      const uint8_t *preimage, size_t preimage_len,
                      const nodus_pubkey_t *pk) {
    return nodus_verify_tagged(sig, NODUS_PURPOSE_CERT,
                                preimage, preimage_len, pk);
}

int nodus_sign_prepared_vote(nodus_sig_t *sig_out,
                              const uint8_t *preimage, size_t preimage_len,
                              const nodus_seckey_t *sk) {
    return nodus_sign_tagged(sig_out, NODUS_PURPOSE_PREPARED,
                              preimage, preimage_len, sk);
}

int nodus_verify_prepared_vote(const nodus_sig_t *sig,
                                const uint8_t *preimage, size_t preimage_len,
                                const nodus_pubkey_t *pk) {
    return nodus_verify_tagged(sig, NODUS_PURPOSE_PREPARED,
                                preimage, preimage_len, pk);
}

/* ───── Hash / identity helpers (unchanged) ─────────────────────────── */

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
