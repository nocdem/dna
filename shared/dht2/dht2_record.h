/**
 * @file shared/dht2/dht2_record.h
 * @brief DHT v2 — the signed record: data map, class matrix, canonical
 *        envelope, identifiers / address, and the order of versions.
 *
 * Design: docs/plans/2026-10-14-dht-v2-design.md rev 5 (FROZEN):
 *   §3.1 Encoding (envelope, signature + FIPS 204 ctx, data map keys,
 *        address, size, STORED / canonical form);
 *   §3.2 Identifiers (`_id` labels and preimages, feed head, inbox ctl);
 *   §4.2 Order of versions (Select);
 *   §13 rows 3 (`_prev`), 4 (canonical envelope), 5 (`_class` + matrix +
 *        class max), 6 (integers, Validity), 7 (codes used here), 15
 *        (inbox control `_data` shape, as row 5's matrix cell requires).
 *
 * References (pinned, /home/nocdem/refs):
 *   · IPNS record — ipfs-specs 3000be69 src/ipns/ipns-record.md:195-238
 *     (IpnsEntry: pubKey 7, signatureV2 8, data 9), :139-191 (fields);
 *   · DAG-CBOR — ipld bfd348aa specs/codecs/dag-cbor/spec.md:46-66;
 *   · boxo v0.43.0 ipns/validation.go:242-256 (selectRecord, bytes.Compare
 *     tie-break), ipns/record.go:662-705 (compare: Sequence, then
 *     Validity), validation.go:72-74 (expired lower bound);
 *   · Bee v2.8.2 pkg/soc/soc.go:199-207 (address = H(id ‖ owner));
 *   · the tree's proto3 rules shared/dnac/cmt_pb.h:22-52 (emission rules,
 *     re-encodable decode) and its ML-DSA-87 PublicKey branch (field 9,
 *     cmt_pb.h:43-44), through cmt_pb_public_key_marshal / _unmarshal.
 *
 * NAMED DEVIATIONS (design §13 row 21) carried by this file:
 *   · pubKey = the tree's ML-DSA-87 branch of the protobuf PublicKey
 *     (libp2p's key types are RSA / Ed25519 / Secp256k1 / ECDSA);
 *   · the signature is ML-DSA-87 over the `data` bytes with FIPS 204 ctx
 *     `nodus.dht.record.v1`, replacing the `"ipns-signature:" ‖ data`
 *     prefix of ipns-record.md:339;
 *   · `Sequence` ≥ 1 (IPNS starts at 0) and negative integers refused
 *     (row 6);
 *   · unknown data keys refused (IPNS lets them be ignored,
 *     ipns-record.md:181-191) (row 5);
 *   · `Validity` narrowed to the 20-byte form (dht2_time.h);
 *   · the order of versions ends "larger canonical data bytes → larger
 *     signature bytes" where boxo's selectRecord compares the whole
 *     (re-encodable) record bytes (Kurultay #21 khan 2).
 *
 * READINGS this file makes where the design names no code (reported to
 * the ORCHESTRATOR; each sits in one function):
 *   · class-independent byte-form faults → `bad-encoding` (2): a missing
 *     IPNS key / `_chain` / `_id` / `_class`, a wrong fixed length,
 *     `TTL` ≠ 0, `Value` not empty, `Sequence` 0, `ValidityType` ∉ {0,1},
 *     `_prev` length ∉ {0, 64}, `_del` ≠ true, a missing / malformed
 *     pubKey, a `Validity` text that is not the 20-byte form;
 *   · per-class faults → `bad-class` (6): `_class` ∉ 1…5 (row 5 says so),
 *     a matrix presence violation, a feed head `_data` ≠ 8 B, a malformed
 *     row-15 control list, an inbox control `_id` ≠ the signer's own, a
 *     `ValidityType` ⇔ `Validity` disagreement (type 0 with an empty
 *     `Validity`, type 1 with a non-empty one — §4.1 lists it among the
 *     class rules, after chain / address / holder);
 *   · no-expiry (ValidityType 1) where the class max is finite →
 *     `too-long` (8).
 * READINGS of the design's rules (kept as written):
 *   · a NAMED writer's class 1 / 3 / 5 record may carry a finite expiry
 *     (ValidityType 0) with no upper bound — row 5 "no expiry allowed
 *     (ValidityType 1) with a name" read as "the class max is unbounded";
 *   · an empty `_data` (length 0) is valid for classes 1, 2, 4 — row 5
 *     requires the key, not a length;
 *   · a ValidityType ⇔ Validity mismatch is `bad-class` (6), not
 *     `bad-encoding`: dht2_data_decode lets it through (the re-encode
 *     identity check still covers it) and dht2_record_check_class refuses
 *     it, so the §4.1 order holds (chain 3 before it).
 *
 * ⚠ API CONTRACT — NO FUNCTION HERE EXCEPT dht2_record_verify CHECKS THE
 * SIGNATURE. dht2_record_parse, dht2_data_decode, dht2_record_canonical,
 * dht2_record_compare and dht2_record_placement_key operate on UNVERIFIED
 * bytes. Admission must run design §4.1's full order — size, decode,
 * chain, owner, address, holder check, class rules, expiry, SIGNATURE
 * (dht2_record_verify), then Select and store; a record must never be
 * stored, compared against a held version or hashed into a receipt before
 * dht2_record_verify returned DHT2_OK.
 *
 * Reads no clock, keeps no state, draws no randomness except inside
 * qgp_dsa87_sign_ctx's hedged signing (FIPS 204 §3.4). One function
 * allocates: dht2_id (its preimage, freed before it returns; every
 * failure path frees it too).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef SHARED_DHT2_RECORD_H
#define SHARED_DHT2_RECORD_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include "dht2/dht2_types.h"
#include "dnac/cmt_pb.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── the data map (§3.1 "Data map keys", §13 row 5) ────────────────────
 * `data` / `prev` point into the caller's buffer (zero-copy): after
 * dht2_data_decode they point into the decoded bytes, which must outlive
 * the struct. For encoding the caller sets them. */
typedef struct {
    uint64_t       sequence;                    /* `Sequence`, ≥ 1 */
    uint64_t       validity_type;               /* 0 EOL, 1 none */
    uint64_t       expiry;                      /* seconds; valid when type 0 */
    uint8_t        chain[DHT2_CHAIN_LEN];       /* `_chain` */
    uint8_t        id[DHT2_ID_LEN];             /* `_id` */
    uint64_t       cls;                         /* `_class` */
    bool           del;                         /* `_del` present (= true) */
    bool           has_data;                    /* `_data` present */
    const uint8_t *data;
    size_t         data_len;
    bool           has_prev;                    /* `_prev` present */
    const uint8_t *prev;                        /* length 0 or 64 */
    size_t         prev_len;
} dht2_data_t;

/** Canonical DAG-CBOR of `d`: keys in the one order strict DAG-CBOR
 *  allows — TTL, _id, _del, Value, _data, _prev, _chain, _class,
 *  Sequence, Validity, ValidityType (length first, then bytewise; each
 *  only when present). `out` NULL → only *out_len (the size).
 *  @return DHT2_OK, DHT2_E_BAD_ENCODING (a field the canonical form
 *  cannot carry: Sequence 0, ValidityType ∉ {0,1}, expiry beyond
 *  9999-12-31T23:59:59Z, `_prev` length ∉ {0,64}), DHT2_E_ARG (buffer). */
int dht2_data_encode(const dht2_data_t *d, uint8_t *out, size_t cap,
                     size_t *out_len);

/** Strict decode + re-encode identity check (design §3.1, §13 rows 5-6,
 *  22). @return DHT2_OK or DHT2_E_BAD_ENCODING. Class rules are NOT
 *  applied here (dht2_record_check_class), nor is any signature. */
int dht2_data_decode(const uint8_t *in, size_t len, dht2_data_t *d);

/* ── the envelope (§3.1, §13 row 4) ────────────────────────────────── */

typedef struct {
    cmt_pb_public_key_t pk;                     /* field 7, decoded */
    uint8_t             fp[DHT2_FP_LEN];        /* SHA3-512(pk.key) */
    const uint8_t      *sig;                    /* field 8 (into input) */
    size_t              sig_len;
    const uint8_t      *data;                   /* field 9 (into input) */
    size_t              data_len;
    dht2_data_t         d;                      /* parsed field 9 */
    uint8_t             address[DHT2_HASH_LEN]; /* H(_id ‖ fp) */
} dht2_record_t;

/**
 * §4.1 steps up to and including the address, in its order:
 *   size ≤ 262,144 B (BEFORE any decode)           → DHT2_E_TOO_LARGE
 *   envelope decodes (cmt_pb.h:46-52 contract)      → DHT2_E_BAD_ENCODING
 *   `data` strict DAG-CBOR, re-encodes identically → DHT2_E_BAD_ENCODING
 *   `_chain` = `local_chain`                       → DHT2_E_BAD_CHAIN
 *   pubKey → owner fp (ML-DSA-87 branch, 2592 B)   → DHT2_E_BAD_ENCODING
 *   address = SHA3-512(`_id` ‖ fp); if `expect_address` is non-NULL it
 *   must equal it                                  → DHT2_E_BAD_ADDRESS
 * The holder check (`not-holder`), class rules, expiry and signature come
 * after, from the functions below, in that order. `rec` points into `in`.
 * Envelope decode follows the generated Unmarshal: fields in any order,
 * unknown fields skipped by wire type, a repeated field last-one-wins.
 * Does NOT verify the signature (see the API CONTRACT above).
 */
int dht2_record_parse(const uint8_t *in, size_t len,
                      const uint8_t local_chain[DHT2_CHAIN_LEN],
                      const uint8_t *expect_address, dht2_record_t *rec);

/** Row 5 class rules (+ row 15 control-list shape, §3.2 inbox-control
 *  binding). @return DHT2_OK or DHT2_E_BAD_CLASS. */
int dht2_record_check_class(const dht2_record_t *rec);

/** §4.1 "expiry > holder chain time and ≤ holder chain time + class max
 *  + 3 h" with row 5's class max by the WRITER's (= signer's) name
 *  status. @return DHT2_OK, DHT2_E_EXPIRED, DHT2_E_TOO_LONG,
 *  DHT2_E_BAD_CLASS (class out of range — never reached after
 *  dht2_record_check_class). */
int dht2_record_check_expiry(const dht2_record_t *rec, uint64_t chain_now,
                             bool writer_named);

/** ML-DSA-87 verify over the `data` bytes, ctx `nodus.dht.record.v1`.
 *  @return DHT2_OK or DHT2_E_BAD_SIGNATURE. */
int dht2_record_verify(const dht2_record_t *rec);

/** §3.1 "Stored form" / row 4: fields 7, 8, 9 only, in field order, each
 *  once, proto3 emission rules (cmt_pb.h:22), unknown fields dropped.
 *  `out` NULL → only *out_len. Does NOT verify the signature; it REFUSES
 *  (DHT2_E_BAD_SIGNATURE) a record whose signature is not exactly the
 *  ML-DSA-87 size (4627 B), so no canonical form exists for a record that
 *  could never verify. @return DHT2_OK, DHT2_E_BAD_SIGNATURE, DHT2_E_ARG. */
int dht2_record_canonical(const dht2_record_t *rec, uint8_t *out, size_t cap,
                          size_t *out_len);

/** Client side: encode `d`, sign it (hedged, ctx `nodus.dht.record.v1`)
 *  with `sk` (4896 B) and write the CANONICAL envelope with `pk`
 *  (2592 B). `out` NULL → *out_len = the exact size (no signing).
 *  @return DHT2_OK, DHT2_E_BAD_ENCODING (d not encodable),
 *  DHT2_E_TOO_LARGE (> 262,144 B), DHT2_E_ARG, DHT2_E_HOLDER_FAULT
 *  (the signing call failed). */
int dht2_record_build(const dht2_data_t *d, const uint8_t *sk,
                      const uint8_t pk[DHT2_PUBKEY_LEN], uint8_t *out,
                      size_t cap, size_t *out_len);

/** §4.2 order of two versions AT THE SAME ADDRESS: larger `Sequence` →
 *  later expiry (no expiry above any expiry) → larger canonical data bytes
 *  → larger signature bytes ("larger bytes" = Go bytes.Compare: first
 *  differing byte, then the shorter is smaller). Does NOT verify either
 *  signature: both must have passed dht2_record_verify. A NULL side is
 *  "nothing held" and loses to a present one (both NULL → 0).
 *  @return > 0 if `a` wins, < 0 if `b` wins, 0 if both are the same
 *  version. */
int dht2_record_compare(const dht2_record_t *a, const dht2_record_t *b);

/** §2 placement key: the INBOX id for classes 4 and 5 (class 4: its
 *  `_id`; class 5: SHA3-512(`nodus.dht.inbox.v1` ‖ `_chain` ‖ signer fp)
 *  — the inbox its signer owns), the record's address otherwise. Does NOT
 *  verify the signature: on an unverified record the signer fp is a
 *  claim. @return DHT2_OK, DHT2_E_ARG, DHT2_E_HOLDER_FAULT. */
int dht2_record_placement_key(const dht2_record_t *rec,
                              uint8_t out[DHT2_HASH_LEN]);

/* ── identifiers (§3.2) and address (§3.1) ─────────────────────────── */

/** SHA3-512(label ‖ chain_id (32 B) ‖ params). `label` is one of the
 *  DHT2_LABEL_* strings (ASCII, no NUL). `params` may be NULL when
 *  `params_len` is 0. @return 0 / -1. */
int dht2_id(const char *label, const uint8_t chain[DHT2_CHAIN_LEN],
            const uint8_t *params, size_t params_len,
            uint8_t out[DHT2_ID_LEN]);

/** Feed entry `_id` = SHA3-512(topic ‖ index as 8-byte big-endian)
 *  (§3.2; Bee pkg/feeds/feed.go:70-71, sequence/sequence.go:47-51). */
int dht2_id_feed_entry(const uint8_t topic[DHT2_HASH_LEN], uint64_t index,
                       uint8_t out[DHT2_ID_LEN]);

/** Feed head `_id` = SHA3-512(`nodus.dht.head.v1` ‖ chain ‖ topic). */
int dht2_id_feed_head(const uint8_t chain[DHT2_CHAIN_LEN],
                      const uint8_t topic[DHT2_HASH_LEN],
                      uint8_t out[DHT2_ID_LEN]);

/** Inbox id = SHA3-512(`nodus.dht.inbox.v1` ‖ chain ‖ recipient fp). */
int dht2_id_inbox(const uint8_t chain[DHT2_CHAIN_LEN],
                  const uint8_t recipient_fp[DHT2_FP_LEN],
                  uint8_t out[DHT2_ID_LEN]);

/** Inbox control `_id` = SHA3-512(`nodus.dht.inbox.ctl.v1` ‖ chain ‖
 *  recipient fp). */
int dht2_id_inbox_ctl(const uint8_t chain[DHT2_CHAIN_LEN],
                      const uint8_t recipient_fp[DHT2_FP_LEN],
                      uint8_t out[DHT2_ID_LEN]);

/* Typed client-side `_id` helpers — preimages fixed by the operator
 * decision docs/plans/decisions/2026-10-23-dht-v2-id-param-bytes.md (every
 * field fixed length). Holders never compute these (design §13 row 5). */

/** dm topic = SHA3-512(`nodus.dht.dm.v1` ‖ chain ‖ recipient fp ‖ salt 32). */
int dht2_id_dm(const uint8_t chain[DHT2_CHAIN_LEN],
               const uint8_t recipient_fp[DHT2_FP_LEN],
               const uint8_t salt[DHT2_SALT_LEN],
               uint8_t out[DHT2_ID_LEN]);

/** Group head `_id` = SHA3-512(`nodus.dht.group.head.v1` ‖ chain ‖
 *  group id 32). No key version. */
int dht2_id_group_head(const uint8_t chain[DHT2_CHAIN_LEN],
                       const uint8_t group_id[DHT2_GROUP_ID_LEN],
                       uint8_t out[DHT2_ID_LEN]);

/** Group record `_id` = SHA3-512(`nodus.dht.group.record.v1` ‖ chain ‖
 *  group id 32 ‖ key version u64 BE, 8 B). */
int dht2_id_group_record(const uint8_t chain[DHT2_CHAIN_LEN],
                         const uint8_t group_id[DHT2_GROUP_ID_LEN],
                         uint64_t key_version, uint8_t out[DHT2_ID_LEN]);

/** Group key packet `_id` = SHA3-512(`nodus.dht.group.keys.v1` ‖ chain ‖
 *  group id 32 ‖ key version u64 BE, 8 B). */
int dht2_id_group_keys(const uint8_t chain[DHT2_CHAIN_LEN],
                       const uint8_t group_id[DHT2_GROUP_ID_LEN],
                       uint64_t key_version, uint8_t out[DHT2_ID_LEN]);

/** Group feed topic = SHA3-512(`nodus.dht.group.feed.v1` ‖ chain ‖
 *  group id 32). No key version. */
int dht2_id_group_feed(const uint8_t chain[DHT2_CHAIN_LEN],
                       const uint8_t group_id[DHT2_GROUP_ID_LEN],
                       uint8_t out[DHT2_ID_LEN]);

/** Address = SHA3-512(`_id` ‖ owner fp) (Bee soc.go:199-207). */
int dht2_address(const uint8_t id[DHT2_ID_LEN],
                 const uint8_t owner_fp[DHT2_FP_LEN],
                 uint8_t out[DHT2_HASH_LEN]);

/** Owner fp = SHA3-512(raw 2592-byte ML-DSA-87 key) — the tree's
 *  fingerprint (nodus/src/crypto/nodus_sign.c:392). */
int dht2_fp(const uint8_t pk[DHT2_PUBKEY_LEN], uint8_t out[DHT2_FP_LEN]);

/** Go bytes.Compare: -1 / 0 / 1. */
int dht2_bytes_compare(const uint8_t *a, size_t alen,
                       const uint8_t *b, size_t blen);

#ifdef __cplusplus
}
#endif

#endif /* SHARED_DHT2_RECORD_H */
