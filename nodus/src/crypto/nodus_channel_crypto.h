/**
 * Nodus — Channel Crypto (Kyber1024 + AES-256-GCM)
 *
 * Provides symmetric encrypt/decrypt for post-handshake channel traffic.
 * Used by both client↔server tunnel (H-01) and circuit E2E encryption.
 *
 * After Kyber KEM handshake, both sides call nodus_channel_crypto_init()
 * with the shared secret + nonces to derive the AES-256 session key.
 * All subsequent frames are encrypted with AES-256-GCM using a
 * counter-based nonce for replay protection.
 *
 * @file nodus_channel_crypto.h
 */

#ifndef NODUS_CHANNEL_CRYPTO_H
#define NODUS_CHANNEL_CRYPTO_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NODUS_CHANNEL_NONCE_LEN    12
#define NODUS_CHANNEL_TAG_LEN      16
#define NODUS_CHANNEL_OVERHEAD     (NODUS_CHANNEL_NONCE_LEN + NODUS_CHANNEL_TAG_LEN)  /* 28 */
#define NODUS_CHANNEL_KEY_LEN      32

typedef struct {
    bool     established;
    uint8_t  key[NODUS_CHANNEL_KEY_LEN];   /* AES-256 session key */
    uint64_t tx_counter;                    /* Monotonic nonce counter (send) */
    uint64_t rx_counter;                    /* Minimum expected counter (receive) */
} nodus_channel_crypto_t;

/**
 * Derive session key from KEM shared secret + handshake nonces.
 *
 * key = HKDF-SHA3-256(
 *   salt = nonce_c || nonce_s,
 *   ikm  = shared_secret,
 *   info = "nodus-channel-v1"
 * )
 *
 * @param cc              Channel crypto state (zeroed on entry)
 * @param shared_secret   32-byte Kyber shared secret
 * @param nonce_c         32-byte client nonce
 * @param nonce_s         32-byte server nonce
 * @return 0 on success
 */
int nodus_channel_crypto_init(nodus_channel_crypto_t *cc,
                               const uint8_t shared_secret[32],
                               const uint8_t nonce_c[32],
                               const uint8_t nonce_s[32]);

/**
 * Encrypt a frame payload.
 *
 * Output format: [12-byte nonce][ciphertext][16-byte tag]
 * out buffer must be at least plaintext_len + NODUS_CHANNEL_OVERHEAD bytes.
 *
 * @return 0 on success, -1 on error
 */
int nodus_channel_encrypt(nodus_channel_crypto_t *cc,
                           const uint8_t *plaintext, size_t plaintext_len,
                           uint8_t *out, size_t out_cap,
                           size_t *out_len);

/**
 * Decrypt a frame payload.
 *
 * Input format: [12-byte nonce][ciphertext][16-byte tag]
 * out buffer must be at least in_len - NODUS_CHANNEL_OVERHEAD bytes.
 *
 * @return 0 on success, -1 on auth failure or error
 */
int nodus_channel_decrypt(nodus_channel_crypto_t *cc,
                           const uint8_t *in, size_t in_len,
                           uint8_t *out, size_t out_cap,
                           size_t *out_len);

/**
 * Securely zero all key material.
 */
void nodus_channel_crypto_clear(nodus_channel_crypto_t *cc);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_CHANNEL_CRYPTO_H */
