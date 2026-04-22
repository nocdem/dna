/**
 * Nodus — Dilithium5 Crypto Wrapper
 *
 * Thin wrapper around shared/crypto qgp_dsa87_* functions.
 * Provides Nodus-typed API for sign/verify/hash operations.
 *
 * Domain-separated API (C2 fix):
 *   All new code MUST use the domain-specific wrappers (nodus_sign_auth_challenge,
 *   nodus_sign_kyber_bind, etc.). These prepend a "NDS1" + purpose-byte tag to the
 *   preimage so a signature made for domain A cannot be relayed against a verifier
 *   expecting domain B. Combined with the "we-initiated" conn flag, closes the
 *   Dilithium5 signing oracle at the challenge handler.
 *
 *   nodus_sign() / nodus_verify() remain as raw low-level helpers, used only by
 *   domain-specific wrappers and by TX_HASH verify (libdna-signed DNAC TXs, which
 *   already embed "DNAC_TX_V2\0" domain separator on the client side).
 *
 * @file nodus_sign.h
 */

#ifndef NODUS_SIGN_H
#define NODUS_SIGN_H

#include "nodus/nodus_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ───── Domain separation constants ─────────────────────────────────── */

/** 4-byte magic + version marker for tagged preimages. */
#define NODUS_SIGN_MAGIC          "NDS1"
#define NODUS_SIGN_MAGIC_LEN      4

/** Purpose byte identifies the signing domain. */
#define NODUS_PURPOSE_AUTH_CHALLENGE 0x01  /**< 32-byte nonce at auth handshake */
#define NODUS_PURPOSE_KYBER_BIND     0x02  /**< nonce + server kyber_pk bind */
#define NODUS_PURPOSE_T3_ENVELOPE    0x03  /**< Tier-3 BFT wire envelope */
#define NODUS_PURPOSE_VALUE_STORE    0x04  /**< DHT PUT value signature */
#define NODUS_PURPOSE_CERT           0x05  /**< BFT commit certificate */
/* 0x06 reserved for POST (channel posts); not implemented — channels disabled */

/** Tagged preimage layout:
 *    MAGIC (4) || purpose (1) || data_len_be (4) || data (data_len)
 *  Total header = 9 bytes. */
#define NODUS_SIGN_HEADER_LEN     (NODUS_SIGN_MAGIC_LEN + 1 + 4)

/* ───── Low-level raw API ───────────────────────────────────────────── */

/**
 * Raw Dilithium5 sign. USE ONLY for TX_HASH (libdna-signed DNAC TXs embed their
 * own "DNAC_TX_V2\0" prefix client-side). All other sign sites MUST use a
 * domain-specific wrapper below.
 *
 * @return 0 on success, -1 on error
 */
int nodus_sign(nodus_sig_t *sig_out,
               const uint8_t *data, size_t data_len,
               const nodus_seckey_t *sk);

/**
 * Raw Dilithium5 verify. USE ONLY for TX_HASH. All other verify sites MUST use
 * a domain-specific wrapper.
 *
 * @return 0 if valid, -1 if invalid
 */
int nodus_verify(const nodus_sig_t *sig,
                 const uint8_t *data, size_t data_len,
                 const nodus_pubkey_t *pk);

/* ───── Domain-separated wrappers (preferred API) ───────────────────── */

/**
 * Internal: sign over tagged preimage (MAGIC || purpose || len || data).
 * Public callers should use the purpose-specific wrappers below.
 */
int nodus_sign_tagged(nodus_sig_t *sig_out,
                      uint8_t purpose,
                      const uint8_t *data, size_t data_len,
                      const nodus_seckey_t *sk);

int nodus_verify_tagged(const nodus_sig_t *sig,
                        uint8_t purpose,
                        const uint8_t *data, size_t data_len,
                        const nodus_pubkey_t *pk);

/** AUTH_CHALLENGE domain — 32-byte nonce at auth handshake. */
int nodus_sign_auth_challenge(nodus_sig_t *sig_out,
                              const uint8_t *nonce,   /* NODUS_NONCE_LEN = 32 */
                              const nodus_seckey_t *sk);
int nodus_verify_auth_challenge(const nodus_sig_t *sig,
                                const uint8_t *nonce,
                                const nodus_pubkey_t *pk);

/** KYBER_BIND domain — nonce + server kyber_pk binding signature. */
int nodus_sign_kyber_bind(nodus_sig_t *sig_out,
                          const uint8_t *sign_data, size_t sign_data_len,
                          const nodus_seckey_t *sk);
int nodus_verify_kyber_bind(const nodus_sig_t *sig,
                            const uint8_t *sign_data, size_t sign_data_len,
                            const nodus_pubkey_t *pk);

/** T3_ENVELOPE domain — Tier-3 BFT wire envelope. */
int nodus_sign_t3_envelope(nodus_sig_t *sig_out,
                           const uint8_t *envelope, size_t envelope_len,
                           const nodus_seckey_t *sk);
int nodus_verify_t3_envelope(const nodus_sig_t *sig,
                             const uint8_t *envelope, size_t envelope_len,
                             const nodus_pubkey_t *pk);

/** VALUE_STORE domain — DHT PUT value signature. */
int nodus_sign_value_store(nodus_sig_t *sig_out,
                           const uint8_t *payload, size_t payload_len,
                           const nodus_seckey_t *sk);
int nodus_verify_value_store(const nodus_sig_t *sig,
                             const uint8_t *payload, size_t payload_len,
                             const nodus_pubkey_t *pk);

/** CERT domain — BFT commit certificate preimage. */
int nodus_sign_cert(nodus_sig_t *sig_out,
                    const uint8_t *preimage, size_t preimage_len,
                    const nodus_seckey_t *sk);
int nodus_verify_cert(const nodus_sig_t *sig,
                      const uint8_t *preimage, size_t preimage_len,
                      const nodus_pubkey_t *pk);

/* ───── Hash / identity helpers (unchanged) ─────────────────────────── */

int nodus_hash(const uint8_t *data, size_t data_len, nodus_key_t *hash_out);
int nodus_hash_hex(const uint8_t *data, size_t data_len, char *hex_out);
int nodus_fingerprint(const nodus_pubkey_t *pk, nodus_key_t *fp_out);
int nodus_fingerprint_hex(const nodus_pubkey_t *pk, char *hex_out);
int nodus_random(uint8_t *buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_SIGN_H */
