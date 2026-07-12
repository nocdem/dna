#ifndef DNA_CALL_CRYPTO_H
#define DNA_CALL_CRYPTO_H

/*
 * DNA Engine — Call Crypto (PQ VoIP Faz A)
 *
 * Per-call media key agreement for post-quantum voice/video calls.
 * See docs/plans/2026-07-12-pq-voip-faz-a-signaling-design.md §4.3.
 *
 * K_call = HKDF-SHA3-256(
 *              salt = caller_fp[0:32] || callee_fp[0:32]            (64 B)
 *              ikm  = ss_eph || ss_static                           (64 B)
 *              info = "dna-call-v1" || call_id(16) || SHA3-512(eph_pk)[0:32]  (59 B)
 *          ) -> 32 B
 *
 * Reuses only audited primitives: hkdf_sha3_256 (RFC 5869 Extract-then-Expand,
 * shared/crypto/hash/hkdf_sha3.h), qgp_sha3_512 (shared/crypto/hash/qgp_sha3.h).
 * No new KEM/KDF/cipher (ANA HEDEF: KAFADAN KRIPTO YASAK).
 *
 * @file dna_call_crypto.h
 */

#include <stddef.h>
#include <stdint.h>

/* Sizes (all pinned to shared/crypto headers). */
#define DNA_CALL_KEY_LEN        32u   /* AES-256 K_call */
#define DNA_CALL_SS_LEN         32u   /* Kyber1024 shared secret (QGP_KEM1024_SHAREDSECRET_BYTES) */
#define DNA_CALL_FP_LEN         64u   /* Dilithium5 fingerprint, raw bytes (SHA3-512) */
#define DNA_CALL_ID_LEN         16u   /* call_id, 128-bit CSPRNG */
#define DNA_CALL_KYBER_PK_LEN   1568u /* ML-KEM-1024 public key (QGP_KEM1024_PUBLICKEYBYTES) */

/* Domain-separation version tag (§2.4 design decision, modeled on
 * "nodus-channel-v1", nodus_channel_crypto.c:26). 11 bytes, no NUL. */
#define DNA_CALL_INFO_TAG       "dna-call-v1"
#define DNA_CALL_INFO_TAG_LEN   11u

/* Return codes. */
#define DNA_CALL_OK             0
#define DNA_CALL_ERR_NULL      -1
#define DNA_CALL_ERR_CRYPTO    -2
#define DNA_CALL_ERR_FORMAT    -3   /* missing/duplicate sig slot, bad base64 */
#define DNA_CALL_ERR_OVERSIZE  -4   /* body exceeds DNA_CALL_SIG_MAX_BODY */
#define DNA_CALL_ERR_VERIFY    -5   /* signature did not verify */

/* Canonical call-signal signing (§4.2, red-team F-SIG/F-JSON).
 *
 * The signed content is the signal body with an EMPTY sig value, i.e. it MUST
 * contain the literal token  "sig":""  exactly once. Signing computes Dilithium5
 * over those exact bytes and splices the base64 signature into the empty slot.
 * Verification operates on the EXACT RECEIVED bytes — it blanks the sig value
 * back to "" and verifies, never re-serializing — so it is immune to JSON
 * encoder differences (json-c vs Dart) that would otherwise break signatures.
 *
 * Constraint: no other field value may contain the literal substring  "sig":"  .
 * (Faz A signals carry no free-form text in the signed body, so this holds.)
 */
#define DNA_CALL_SIG_SLOT       "\"sig\":\"\""   /* literal: "sig":"" */
#define DNA_CALL_SIG_PREFIX     "\"sig\":\""     /* literal: "sig":"  */
#define DNA_CALL_SIG_MAX_BODY   65536u

/* Sign a call-signal body (must contain DNA_CALL_SIG_SLOT). Writes the signed
 * message (base64 sig spliced into the slot) to out. Returns DNA_CALL_OK. */
int dna_call_sign_body(const char *body, size_t body_len,
                       const uint8_t *dsa_sk,
                       char *out, size_t out_cap, size_t *out_len);

/* Verify a signed call-signal body against dsa_pk (2592-byte Dilithium5 pk).
 * Returns DNA_CALL_OK if valid, DNA_CALL_ERR_VERIFY / _FORMAT otherwise. */
int dna_call_verify_body(const char *signed_body, size_t signed_len,
                         const uint8_t *dsa_pk);

/*
 * Derive the per-call media key K_call (§4.3).
 *
 * caller_fp / callee_fp : 64-byte raw Dilithium5 fingerprints, in FIXED roles
 *                         (both endpoints know who is caller/callee), so both
 *                         sides compute an identical salt.
 * ss_eph                : 32-byte shared secret from the per-call ephemeral KEM.
 * ss_static             : 32-byte shared secret from the caller's static KEM.
 * call_id               : 16-byte per-call random id.
 * eph_pk                : 1568-byte ephemeral ML-KEM-1024 public key.
 * key_out               : 32-byte output K_call.
 *
 * Returns DNA_CALL_OK (0) on success, negative on error.
 */
int dna_call_derive_key(
    const uint8_t ss_eph[DNA_CALL_SS_LEN],
    const uint8_t ss_static[DNA_CALL_SS_LEN],
    const uint8_t caller_fp[DNA_CALL_FP_LEN],
    const uint8_t callee_fp[DNA_CALL_FP_LEN],
    const uint8_t call_id[DNA_CALL_ID_LEN],
    const uint8_t eph_pk[DNA_CALL_KYBER_PK_LEN],
    uint8_t key_out[DNA_CALL_KEY_LEN]);

/* ===================== canonical signal builder (§4.2) =====================
 *
 * Emits the canonical pre-sign signal body — a fixed-order JSON string with an
 * empty "sig":"" slot ready for dna_call_sign_body. Built by hand (single C
 * encoder, no json-c) so the byte layout is fully deterministic; all values are
 * hex / base64 / ints, which need no JSON string-escaping (F-JSON). Field order:
 *   {"type":"call_signal","v":1,"call":"<id>","sig":"","seq":<n>,"kind":"<K>"<,per-kind>}
 */

/* Signal kinds (wire string values). */
#define DNA_CALL_KIND_INVITE   "INVITE"
#define DNA_CALL_KIND_RINGING  "RINGING"
#define DNA_CALL_KIND_ACCEPT   "ACCEPT"
#define DNA_CALL_KIND_REJECT   "REJECT"
#define DNA_CALL_KIND_BUSY     "BUSY"
#define DNA_CALL_KIND_END      "END"

typedef struct {
    const char   *kind;          /* one of DNA_CALL_KIND_* (required) */
    const char   *call_id_hex;   /* 32 lowercase hex chars (16 B call_id) (required) */
    uint32_t      seq;           /* per-call, per-direction monotonic sequence */

    /* INVITE-only: */
    const char   *caller_fp_hex; /* 128 hex chars (64 B fingerprint) */
    const uint8_t *eph_pk;       /* 1568-byte ML-KEM-1024 ephemeral public key */
    const char   *cap_json;      /* pre-sorted "{...}" capabilities, or NULL -> "{}" */

    /* ACCEPT-only: */
    const uint8_t *eph_ct;       /* 1568-byte ephemeral ciphertext */
    const uint8_t *static_ct;    /* 1568-byte static ciphertext */

    /* REJECT / BUSY / END-only: */
    int           reason;
    int           has_reason;
} dna_call_signal_t;

/* Build the canonical body into out (NUL-terminated). *out_len excludes the NUL.
 * Returns DNA_CALL_OK, or _NULL / _FORMAT (bad field) / _OVERSIZE. */
int dna_call_build_body(const dna_call_signal_t *sig,
                        char *out, size_t out_cap, size_t *out_len);

/* ===================== signal parser (§4.2) =====================
 *
 * Extract fields from a RECEIVED signal body (signed or unsigned — the "sig"
 * field is ignored here; signature checking is dna_call_verify_body). MUST be
 * robust against arbitrary/adversarial input: every path returns an error
 * rather than reading out of bounds. Decoded base64 payloads are length-checked
 * to the exact expected size.
 */
typedef struct {
    char     kind[16];                 /* NUL-terminated, one of DNA_CALL_KIND_* */
    char     call_id_hex[DNA_CALL_ID_LEN * 2 + 1];   /* 32 hex + NUL */
    uint32_t seq;

    int      has_caller;
    char     caller_fp_hex[DNA_CALL_FP_LEN * 2 + 1]; /* 128 hex + NUL (INVITE) */

    int      has_eph_pk;
    uint8_t  eph_pk[DNA_CALL_KYBER_PK_LEN];          /* INVITE */

    int      has_eph_ct;
    uint8_t  eph_ct[DNA_CALL_KYBER_PK_LEN];          /* ACCEPT */
    int      has_static_ct;
    uint8_t  static_ct[DNA_CALL_KYBER_PK_LEN];       /* ACCEPT */

    int      has_reason;
    int      reason;                                 /* REJECT / BUSY / END */
} dna_call_parsed_t;

/* Parse a received body into *out. Returns DNA_CALL_OK, or _NULL / _FORMAT
 * (malformed, missing required field, bad base64/length). */
int dna_call_parse_body(const char *body, size_t body_len,
                        dna_call_parsed_t *out);

#endif /* DNA_CALL_CRYPTO_H */
