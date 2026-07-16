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

/**
 * Direction role (C1 — bidirectional nonce reuse fix).
 *
 * Both ends of a channel derive the SAME AES key (same salt/ikm/info) and each
 * encrypts its own stream from tx_counter=0. Without a direction marker the two
 * sides therefore reuse (key, nonce) for every counter — a textbook AES-GCM
 * two-time pad plus GHASH authentication-key exposure.
 *
 * The role occupies the nonce's fixed field, giving each direction a distinct
 * IV space. Grounded in NIST SP 800-38D §8.2.1: "For any given key, no two
 * distinct devices shall share the same fixed field ... Compliance with these
 * two requirements implies compliance with the uniqueness requirement on IVs."
 *
 * Values are NON-ZERO on purpose: 0x00 is what a legacy (pre-fix) peer emits,
 * so an upgraded node must never pick it — otherwise a new initiator and a
 * legacy peer would collide on nonce[8]=0x00 during migration, reinstating the
 * very bug this closes.
 *
 * The role MUST be a static per-callsite constant (who dialed/opened vs who
 * accepted/attached) and MUST NEVER be computed by comparing fingerprints:
 * on a self-connection (equal fps) an fp comparison yields the same role on
 * both ends and the separation collapses.
 */
typedef enum {
    NODUS_CHANNEL_ROLE_LEGACY    = 0x00,  /* pre-fix peer; never chosen by us */
    NODUS_CHANNEL_ROLE_INITIATOR = 0x01,  /* dialed / opened the channel */
    NODUS_CHANNEL_ROLE_RESPONDER = 0x02   /* accepted / attached */
} nodus_channel_role_t;

#define NODUS_CHANNEL_ROLE_COUNT   3      /* legacy(0) + initiator(1) + responder(2) */

typedef struct {
    bool     established;
    uint8_t  key[NODUS_CHANNEL_KEY_LEN];   /* AES-256 session key */
    uint8_t  my_role;                       /* nodus_channel_role_t: our tx direction */
    uint64_t tx_counter;                    /* Monotonic nonce counter (send) */
    /* Minimum expected counter (receive), tracked PER observed role byte so the
     * two directions cannot alias in the replay window. Indexed by the role byte
     * (0..NODUS_CHANNEL_ROLE_COUNT-1). */
    uint64_t rx_counter[NODUS_CHANNEL_ROLE_COUNT];
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
 * Both ends derive the identical key; `role` is what separates the two
 * directions' nonce spaces (see nodus_channel_role_t).
 *
 * @param cc              Channel crypto state (zeroed on entry)
 * @param shared_secret   32-byte Kyber shared secret
 * @param nonce_c         32-byte client nonce
 * @param nonce_s         32-byte server nonce
 * @param role            OUR direction: INITIATOR if we dialed/opened this
 *                        channel, RESPONDER if we accepted/attached. Must be a
 *                        static codepath constant, never fp-derived.
 * @return 0 on success, -1 on error (incl. an invalid role)
 *
 * The state is zeroed on entry, so a fresh (even uninitialised) struct is fine.
 * Because of that this function CANNOT tell a live channel from garbage — the
 * re-init guard is therefore the CALLER's job: anyone holding a long-lived,
 * known-zeroed instance (a circuit handle, a conn) must refuse to re-key it
 * while `established` is true. Re-keying in place resets tx_counter to 0 under a
 * possibly-repeated key = immediate (key, nonce) reuse.
 */
int nodus_channel_crypto_init(nodus_channel_crypto_t *cc,
                               const uint8_t shared_secret[32],
                               const uint8_t nonce_c[32],
                               const uint8_t nonce_s[32],
                               nodus_channel_role_t role);

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
