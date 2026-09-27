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
#define NODUS_PURPOSE_T3_ENVELOPE    0x03  /**< RETIRED (P2P-PORT F5): the
                                              Tier-3 envelope; reserved,
                                              never reassigned */
#define NODUS_PURPOSE_VALUE_STORE    0x04  /**< DHT PUT value signature */
#define NODUS_PURPOSE_CERT           0x05  /**< BFT commit certificate */
/* 0x06 reserved for POST (channel posts); not implemented — channels disabled */
#define NODUS_PURPOSE_PREPARED       0x07  /**< C5: PBFT prepared-cert (per-voter
                                              sig over the 116-byte preimage
                                              "prepared"+chain_id+view+height+
                                              tx_hash) */
/** O15N view-authority statement — a node's per-node attestation that it
 *  observed a view-change quorum. 0x08 is the next free value after
 *  PREPARED; nothing above it is assigned. */
#define NODUS_PURPOSE_VIEWOK         0x08
/** Faz 1 KEM migration (docs/plans/decisions/2026-09-23-kem-mlkem-
 *  migration.md) — nonce + server mlkem_pk bind. Same ROLE as KYBER_BIND
 *  (0x02, tier-2 auth-time KEM-pubkey binding) but, unlike it, IS in the
 *  strict set (nodus_sign_purpose_is_strict(), corrected 2026-09-23 — N1
 *  delta 1, D2): its preimage shape (mlkem_pk || nonce) collides with
 *  KYBER_BIND's (kyber_pk || nonce) at the same length, so without the
 *  NDS1 tag a kpk_sig and an mpk_sig would be interchangeable. 0x09 is
 *  the next free value after VIEWOK. */
#define NODUS_PURPOSE_MLKEM_BIND     0x09
/** 4004 session authentication (docs/plans/decisions/2026-09-26-witness-
 *  port-session.md "Etiketler"; session design §2.1 row 7) — each side of
 *  the secret connection (shared/dnac/cmt_p2p_secret.h) signs the 32-byte
 *  challenge derived from the handshake's shared secret, the port of
 *  cometbft @709fd12b p2p/conn/secret_connection.go:163 signChallenge.
 *  STRICT (nodus_sign_purpose_is_strict()): brand new, no shipped binary
 *  has produced or checked a 0x0A signature, and a 32-byte raw preimage
 *  is byte-shape-identical to AUTH_CHALLENGE's (0x01, non-strict, raw
 *  compat fallback) 32-byte nonce — without the NDS1 tag a session
 *  signature and an auth-challenge signature would verify against each
 *  other's bytes. 0x0A is the next free value after MLKEM_BIND. */
#define NODUS_PURPOSE_SESSION_AUTH   0x0A
/** Signed witness address record (decision record "N7 ADDR bayt düzeni",
 *  session design §2R3 N7 FINAL; p2p-port design R-P2P-4) — a validator's
 *  own ADDR record "nodus.wsess.addr.v1" ‖ chain_id32 ‖ pk_fp ‖ ip ‖ port ‖
 *  seq, gossiped by PEX (phase F4). STRICT, same class as 0x0A: brand new,
 *  no compat to keep. 0x0B is the next free value after SESSION_AUTH. */
#define NODUS_PURPOSE_WITNESS_ADDR   0x0B

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
 * True for the purposes whose NDS1 domain tag is MANDATORY on both sides —
 * no raw signing, no raw-verify fallback.
 *
 * Strict today: NODUS_PURPOSE_PREPARED (0x07), NODUS_PURPOSE_VIEWOK (0x08),
 * NODUS_PURPOSE_MLKEM_BIND (0x09, Faz 1 KEM migration, corrected 2026-09-23
 * — N1 delta 1, D2), NODUS_PURPOSE_SESSION_AUTH (0x0A) and
 * NODUS_PURPOSE_WITNESS_ADDR (0x0B) (4004 session, decision record
 * 2026-09-26-witness-port-session.md — brand new, strict from their first
 * line, like 0x09). MLKEM_BIND is strict DESPITE being a tier-2 client/
 * inter-node auth-time binding like its non-strict sibling KYBER_BIND
 * (0x02): without the tag, its preimage (mlkem_pk || nonce, 1600 bytes) is
 * byte-shape-identical to KYBER_BIND's (kyber_pk || nonce), so a raw
 * kpk_sig and a raw mpk_sig would verify against EACH OTHER's data — an
 * on-path attacker could swap them and force a spurious verify failure.
 * Being brand new in this same migration (no shipped binary has ever
 * produced or checked a 0x09 signature), it has no pre-existing wide-
 * compat behaviour to preserve, unlike 0x01-0x05. See nodus_sign.c for
 * the full citation.
 *
 * ⚠ Both sides or it is theatre: lifting the bypass on the signing half
 * alone changes nothing an attacker has to defeat, because the verifier
 * would still accept a raw signature. This one predicate is what keeps
 * nodus_sign_tagged() and nodus_verify_tagged() from drifting apart.
 */
bool nodus_sign_purpose_is_strict(uint8_t purpose);

/**
 * Internal: sign over tagged preimage (MAGIC || purpose || len || data).
 * Public callers should use the purpose-specific wrappers below.
 *
 * Strict purposes sign the TAGGED preimage. Non-strict purposes sign the
 * raw data (the shipped-client compat bridge) — see the comment in
 * nodus_sign.c.
 */
int nodus_sign_tagged(nodus_sig_t *sig_out,
                      uint8_t purpose,
                      const uint8_t *data, size_t data_len,
                      const nodus_seckey_t *sk);

/**
 * Strict purposes: tagged verify ONLY — a raw signature is refused.
 * Non-strict purposes: tagged verify first, raw verify as a compat fallback.
 */
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

/** MLKEM_BIND domain (Faz 1 KEM migration) — nonce + server mlkem_pk
 *  binding signature. Same ROLE as KYBER_BIND (tier-2 client/inter-node
 *  auth-time KEM-pubkey binding), but IS in nodus_sign_purpose_is_strict()
 *  — corrected 2026-09-23 (N1 delta 1, D2): see the comment at that
 *  predicate's definition for why (preimage-shape collision with
 *  KYBER_BIND). Always signs/verifies the NDS1-tagged preimage; no raw
 *  fallback either direction. */
int nodus_sign_mlkem_bind(nodus_sig_t *sig_out,
                          const uint8_t *sign_data, size_t sign_data_len,
                          const nodus_seckey_t *sk);
int nodus_verify_mlkem_bind(const nodus_sig_t *sig,
                            const uint8_t *sign_data, size_t sign_data_len,
                            const nodus_pubkey_t *pk);

/** SESSION_AUTH domain (4004 secret connection, session design §2.1 rows
 *  7 and 9) — the 32-byte challenge. IS in nodus_sign_purpose_is_strict():
 *  always the NDS1-tagged preimage, no raw fallback either direction. */
int nodus_sign_session_auth(nodus_sig_t *sig_out,
                            const uint8_t *challenge, size_t challenge_len,
                            const nodus_seckey_t *sk);
int nodus_verify_session_auth(const nodus_sig_t *sig,
                              const uint8_t *challenge, size_t challenge_len,
                              const nodus_pubkey_t *pk);

/** WITNESS_ADDR domain (signed ADDR record, session design §2R3 N7 FINAL
 *  bytes; consumer: PEX, phase F4). IS in nodus_sign_purpose_is_strict():
 *  always the NDS1-tagged preimage, no raw fallback either direction. */
int nodus_sign_witness_addr(nodus_sig_t *sig_out,
                            const uint8_t *record, size_t record_len,
                            const nodus_seckey_t *sk);
int nodus_verify_witness_addr(const nodus_sig_t *sig,
                              const uint8_t *record, size_t record_len,
                              const nodus_pubkey_t *pk);

/* P2P-PORT F5 — the T3_ENVELOPE sign/verify pair is DELETED with the
 * tier-3 envelope (port 4004 authenticates by its secret connection,
 * purpose 0x0A). Purpose 0x03 stays reserved, never reassigned. */

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

/** PREPARED domain (C5) — PBFT prepared-cert per-voter signature.
 *  Preimage (116 bytes, built by compute_prepared_preimage in
 *  nodus_witness_bft.c): "prepared"(8B ASCII, no NUL) || chain_id(32B) ||
 *  view(4B BE) || height(8B BE) || tx_hash(64B).
 *  STRICT purpose — NDS1-wrapped on both sides, no raw fallback. */
int nodus_sign_prepared_vote(nodus_sig_t *sig_out,
                              const uint8_t *preimage, size_t preimage_len,
                              const nodus_seckey_t *sk);
int nodus_verify_prepared_vote(const nodus_sig_t *sig,
                                const uint8_t *preimage, size_t preimage_len,
                                const nodus_pubkey_t *pk);

/** VIEWOK domain (O15N Faz 2B) — one node's statement that IT observed a
 *  view-change quorum, i.e. the OUTCOME of a view change, never a vote.
 *  Preimage (148 bytes, built by compute_view_ok_preimage in
 *  nodus_witness_bft.c): "viewok\0\0"(8B, 6 ASCII + 2 NUL pad) ||
 *  chain_id(32B) || height(8B BE) || view(4B BE) ||
 *  committee_set_hash(64B) || voter_id(32B).
 *  STRICT purpose — NDS1-wrapped on both sides, no raw fallback. */
int nodus_sign_view_ok(nodus_sig_t *sig_out,
                        const uint8_t *preimage, size_t preimage_len,
                        const nodus_seckey_t *sk);
int nodus_verify_view_ok(const nodus_sig_t *sig,
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
