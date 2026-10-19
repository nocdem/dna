/**
 * @file shared/dht2/dht2_envelope.h
 * @brief DHT v2 — libp2p RFC 0002 Signed Envelope (holder answers,
 *        receipts, address announcements, the owner-signed LIST request)
 *        and the LIST request of §13 row 23.
 *
 * Design rev 5: §4.4 (signed answers, "Answer envelope deviation"), §2
 * "Endpoints" (address announcement domain), §13 row 1 (envelope key +
 * payload type), row 23 (owner-signed LIST request bytes).
 *
 * Reference: libp2p-specs 78e75c6f RFC/0002-signed-envelopes.md —
 * Envelope { PublicKey public_key = 1; bytes payload_type = 2;
 * bytes payload = 3; bytes signature = 5; } (:77-93); signed buffer =
 * uvarint(len domain) ‖ domain ‖ uvarint(len payload_type) ‖ payload_type
 * ‖ uvarint(len payload) ‖ payload (:111-122), uvarints per the
 * multiformats unsigned-varint spec (unsigned-varint dd184f1c README.md
 * :19-27, minimal encoding). Envelope encoding / decoding follows the
 * tree's proto3 rules (shared/dnac/cmt_pb.h:22-52): emitted canonically
 * (ascending, each once, omit-empty); decoded in any order, unknown fields
 * skipped, last-one-wins, the embedded PublicKey MERGED.
 *
 * NAMED DEVIATIONS (design §13 row 21):
 *   · field 1 carries the tree's ML-DSA-87 branch of the protobuf
 *     PublicKey (field 9, cmt_pb.h:43-44) — libp2p's KeyType enum has
 *     only RSA / Ed25519 / Secp256k1 / ECDSA (peer-ids.md:60-66) (row 1);
 *   · the domain string is used BOTH inside RFC 0002's signed buffer AND
 *     as the FIPS 204 ctx of the ML-DSA-87 signature (§4.4);
 *   · the owner-signed LIST request (row 23) is ours.
 * Payload types: dht2_types.h DHT2_PT_* (RFC 0002 :50-54, one slash).
 *
 * ⚠ API CONTRACT: dht2_env_decode does NOT verify the signature; a decoded
 * envelope's payload and fp are unproven until dht2_env_verify returns
 * DHT2_OK. dht2_list_req_open runs the full order itself (verify before
 * the owner check). Holder admission of anything carried in an envelope
 * follows design §4.1's full order — verify before use or store.
 *
 * READING (kept as written): dht2_list_req_open's DHT2_E_BAD_CHAIN (3) and
 * DHT2_E_BAD_SIGNATURE (9) are INTERNAL results; only `not-owner` (17) is
 * a decided LIST answer (row 23). How a holder answers 3 / 9 on a LIST
 * request is decided in the holder package.
 *
 * Allocates only the RFC 0002 signed buffer (seal / verify), freed on
 * every path.
 *
 * Only the envelope layer and the LIST request live here: the answer /
 * receipt / refusal payload maps (row 18) are a later package.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef SHARED_DHT2_ENVELOPE_H
#define SHARED_DHT2_ENVELOPE_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include "dht2/dht2_types.h"
#include "dnac/cmt_pb.h"

#ifdef __cplusplus
extern "C" {
#endif

/** A decoded envelope; the byte pointers point INTO the decoded input. */
typedef struct {
    cmt_pb_public_key_t pk;                 /* field 1 */
    uint8_t             fp[DHT2_FP_LEN];    /* SHA3-512(pk.key) */
    const uint8_t      *payload_type;       /* field 2 */
    size_t              payload_type_len;
    const uint8_t      *payload;            /* field 3 */
    size_t              payload_len;
    const uint8_t      *sig;                /* field 5 */
    size_t              sig_len;
} dht2_env_t;

/**
 * Sign and encode. `domain` is one of the DHT2_DOMAIN_* strings;
 * `payload_type` one of DHT2_PT_* (as bytes, no NUL). Hedged ML-DSA-87
 * with ctx = domain. `out` NULL → *out_len = the exact size (no signing).
 * @return DHT2_OK, DHT2_E_ARG, DHT2_E_HOLDER_FAULT (allocation or signing
 * failed).
 */
int dht2_env_seal(const char *domain,
                  const uint8_t *payload_type, size_t payload_type_len,
                  const uint8_t *payload, size_t payload_len,
                  const uint8_t *sk, const uint8_t pk[DHT2_PUBKEY_LEN],
                  uint8_t *out, size_t cap, size_t *out_len);

/** Decode. Does NOT verify the signature — call dht2_env_verify before
 *  trusting payload or fp. `max_len` bounds `len` BEFORE decoding.
 *  @return DHT2_OK, DHT2_E_TOO_LARGE, DHT2_E_BAD_ENCODING (incl. a
 *  missing or non-ML-DSA-87 key). */
int dht2_env_decode(const uint8_t *in, size_t len, size_t max_len,
                    dht2_env_t *env);

/** Verify the signature over RFC 0002's buffer under `domain` (= ctx).
 *  @return DHT2_OK, DHT2_E_BAD_SIGNATURE, DHT2_E_HOLDER_FAULT (alloc). */
int dht2_env_verify(const dht2_env_t *env, const char *domain);

/* ── §13 row 23: the owner-signed LIST request ─────────────────────── */

typedef struct {
    uint8_t nonce[DHT2_NONCE_LEN];     /* `n` */
    uint8_t chain[DHT2_CHAIN_LEN];     /* `c` */
    uint8_t inbox[DHT2_ID_LEN];        /* `inbox` */
    bool    has_cursor;
    uint8_t cursor[DHT2_FP_LEN];       /* `cursor?` (exclusive, row 11) */
} dht2_list_req_t;

/** Strict DAG-CBOR {op "list", n, c, inbox, cursor?} — keys in the one
 *  canonical order c, n, op, inbox, cursor. `out` NULL → size only.
 *  @return DHT2_OK or DHT2_E_ARG. */
int dht2_list_payload_encode(const dht2_list_req_t *req, uint8_t *out,
                             size_t cap, size_t *out_len);

/** Strict decode + re-encode check. @return DHT2_OK or
 *  DHT2_E_MALFORMED_REQ (row 7: nonce ≠ 32 B, a bad cursor, unknown
 *  operation, any strict-CBOR fault). */
int dht2_list_payload_decode(const uint8_t *in, size_t len,
                             dht2_list_req_t *req);

/** The owner signs: RFC 0002 envelope, domain / ctx `nodus.dht.list.v1`,
 *  payload type DHT2_PT_LIST. `out` NULL → size only.
 *  @return as dht2_env_seal. */
int dht2_list_req_build(const dht2_list_req_t *req, const uint8_t *sk,
                        const uint8_t pk[DHT2_PUBKEY_LEN], uint8_t *out,
                        size_t cap, size_t *out_len);

/**
 * Holder side, in this order (cheap checks first, the owner binding only
 * after the key is proven):
 *   size ≤ 262,144 B, envelope decodes, payload type = DHT2_PT_LIST,
 *   payload strict-decodes                       → DHT2_E_MALFORMED_REQ
 *   `c` = `local_chain`                          → DHT2_E_BAD_CHAIN
 *   signature under `nodus.dht.list.v1`          → DHT2_E_BAD_SIGNATURE
 *   SHA3-512(`nodus.dht.inbox.v1` ‖ c ‖ SHA3-512(signer key)) = `inbox`
 *                                                → DHT2_E_NOT_OWNER (17)
 * Only 17 is decided by row 23; 3 and 9 here are internal results (see
 * the header's READING).
 * On DHT2_OK `req` holds the request and `owner_fp` (may be NULL) the
 * signer's fp.
 */
int dht2_list_req_open(const uint8_t *in, size_t len,
                       const uint8_t local_chain[DHT2_CHAIN_LEN],
                       dht2_list_req_t *req, uint8_t *owner_fp);

#ifdef __cplusplus
}
#endif

#endif /* SHARED_DHT2_ENVELOPE_H */
