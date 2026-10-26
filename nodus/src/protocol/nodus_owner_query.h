/**
 * Nodus — the owner-signed chain query `qa` (DHT v2 package 3d)
 *
 * Design docs/plans/2026-10-26-dht-v2-3d-no-login-design.md rev 5 §3 (bytes
 * approved by the operator 2026-10-26). A wallet on a no-login (ANON) client
 * session proves ownership of one owner-only read by signing the request:
 * the T2 request carries a top-level field `qa` beside `a`, and `qa` is an
 * RFC 0002 signed envelope built by dht2_env_seal — the code the owner-signed
 * LIST request uses (shared/dht2/dht2_envelope.h).
 *
 *   domain = FIPS 204 ctx   "nodus.chain.query.v1"           (20 B, OURS)
 *   payload type            "/nodus/chain/query/v1"           (21 B, OURS)
 *   envelope key            the owner's / member's ML-DSA-87 key
 *   payload                 strict DAG-CBOR map {c, m, o, s}:
 *                             c  chain id, 32 B
 *                             m  method name (text)
 *                             o  64 B — per method (below)
 *                             s  the session's transcript T, 64 B
 *
 * `o` per method (checked by the witness handler that knows the arguments):
 *   dnac_utxo, dnac_addr_history   the owner fingerprint, raw, == the
 *                                  hex-decoded `owner` argument
 *   dnac_delegations               SHA3-512(`pubkey` argument), which must
 *                                  equal the fingerprint of the envelope key
 *   dnac_msig_utxo / _addr_history the vault address (== `owner`), then the
 *                                  full G8.1 descriptor and membership rule
 *
 * The verifier (nodus_oq_open) does, in this order: size bound, envelope
 * decode, payload type (explicit), signature under the domain, payload strict
 * decode, `c` == this node's chain id, `m` == the dispatched method, `s` ==
 * this session's T. The caller then checks `o` against the method's argument
 * and applies today's C11 / G8.1 rule with the envelope key in place of the
 * session key. The check is a pure function of the envelope, the request and
 * T: no clock, no state.
 *
 * T is the node's own copy of the handshake transcript (nodus_tcp_sc_transcript)
 * — never a client-supplied value.
 *
 * @file nodus_owner_query.h
 */

#ifndef NODUS_OWNER_QUERY_H
#define NODUS_OWNER_QUERY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NODUS_OQ_DOMAIN        "nodus.chain.query.v1"
#define NODUS_OQ_PAYLOAD_TYPE  "/nodus/chain/query/v1"

#define NODUS_OQ_CHAIN_LEN     32u
#define NODUS_OQ_O_LEN         64u
#define NODUS_OQ_T_LEN         64u
#define NODUS_OQ_PK_LEN        2592u    /* ML-DSA-87 public key */
#define NODUS_OQ_FP_LEN        64u
/** Longest method name (dnac_msig_addr_history = 22). */
#define NODUS_OQ_METHOD_MAX    32u
/** Payload bound, OURS: map head 1 + c 36 + m (2 + 1 + 32) + o 68 + s 68 = 208
 *  at most; 256 leaves nothing unaccounted. */
#define NODUS_OQ_PAYLOAD_MAX   256u
/** Envelope bound, OURS: PublicKey field ~2.6 KB + type 23 + payload <= 259 +
 *  signature 4,631 = about 7.5 KB; 8,192. A larger `qa` is refused before
 *  any decoding (the generic RFC 0002 bound, 262,144, is far above it). */
#define NODUS_OQ_ENV_MAX       8192u

/* nodus_oq_open results */
#define NODUS_OQ_OK            0
#define NODUS_OQ_E_MALFORMED  (-1)   /* size, decode, payload type, payload */
#define NODUS_OQ_E_SIGNATURE  (-2)   /* the signature does not verify       */
#define NODUS_OQ_E_BINDING    (-3)   /* c / m / s do not match              */
#define NODUS_OQ_E_FAULT      (-4)   /* allocation / hashing fault          */

typedef struct {
    uint8_t chain[NODUS_OQ_CHAIN_LEN];
    char    method[NODUS_OQ_METHOD_MAX + 1];
    uint8_t o[NODUS_OQ_O_LEN];
    uint8_t s[NODUS_OQ_T_LEN];
} nodus_oq_payload_t;

/** The strict DAG-CBOR payload {c, m, o, s}, keys in canonical order.
 *  `out` NULL = size only. @return 0, -1 (bad argument / method too long /
 *  does not fit). */
int nodus_oq_payload_encode(const nodus_oq_payload_t *p, uint8_t *out,
                            size_t cap, size_t *out_len);

/** Strict decode with a re-encode identity check. @return 0 / -1. */
int nodus_oq_payload_decode(const uint8_t *in, size_t len,
                            nodus_oq_payload_t *p);

/** The owner signs: `qa` for method `method`, owner value `o` and session
 *  transcript `t`, under `sk` / `pk` (ML-DSA-87). `out` NULL = size only.
 *  @return 0, -1 (bad argument), -4 (signing fault). */
int nodus_oq_build(const uint8_t chain[NODUS_OQ_CHAIN_LEN], const char *method,
                   const uint8_t o[NODUS_OQ_O_LEN],
                   const uint8_t t[NODUS_OQ_T_LEN],
                   const uint8_t *sk, const uint8_t pk[NODUS_OQ_PK_LEN],
                   uint8_t *out, size_t cap, size_t *out_len);

/** What a verified `qa` proves. */
typedef struct {
    uint8_t pk[NODUS_OQ_PK_LEN];    /* the signer's key */
    uint8_t fp[NODUS_OQ_FP_LEN];    /* SHA3-512(pk) */
    uint8_t o[NODUS_OQ_O_LEN];      /* the payload's `o` — the CALLER checks it */
} nodus_oq_proof_t;

/** Verify one `qa` envelope (the order above). On NODUS_OQ_OK `proof` holds
 *  the signer and `o`; on any other result it is zeroed. */
int nodus_oq_open(const uint8_t *env, size_t env_len,
                  const uint8_t chain[NODUS_OQ_CHAIN_LEN], const char *method,
                  const uint8_t t[NODUS_OQ_T_LEN], nodus_oq_proof_t *proof);

/** Find the top-level `qa` byte string of a T2 request frame (the raw CBOR
 *  map the client sent). @return 0 found (`*env` points INTO `frame`), 1 no
 *  `qa`, -1 not a map / a malformed frame / `qa` twice or not a byte string. */
int nodus_oq_find(const uint8_t *frame, size_t frame_len,
                  const uint8_t **env, size_t *env_len);

/** The five owner-only chain reads that take `qa` (exact method names). */
bool nodus_oq_method_takes_qa(const char *method);

/** The `o` of dnac_delegations: SHA3-512 of the request's `pubkey` argument.
 *  @return 0 and `out` set; -1 for a pubkey that is not exactly
 *  NODUS_OQ_PK_LEN bytes or is all zero (a zero key names no owner). */
int nodus_oq_delegations_subject(const uint8_t *pubkey, size_t len,
                                 uint8_t out[NODUS_OQ_O_LEN]);

/** A verified `qa`'s `o` names `subject` — the per-method value the request
 *  itself carries (the hex-decoded `owner` of dnac_utxo / dnac_addr_history,
 *  the vault address of the two msig reads, nodus_oq_delegations_subject of
 *  dnac_delegations). Constant-time compare of 64 bytes. */
bool nodus_oq_subject_ok(const uint8_t o[NODUS_OQ_O_LEN],
                         const uint8_t subject[NODUS_OQ_O_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_OWNER_QUERY_H */
