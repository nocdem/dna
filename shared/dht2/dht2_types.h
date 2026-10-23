/**
 * @file shared/dht2/dht2_types.h
 * @brief DHT v2 — the constants every dht2 codec file shares: sizes, the
 *        row-7 result codes, the FIPS 204 ctx / RFC 0002 domain strings,
 *        the `_id` labels and the RFC 0002 payload types.
 *
 * Design: docs/plans/2026-10-14-dht-v2-design.md rev 5 (FROZEN) — §3.1,
 * §3.2, §4.4, §13 rows 1, 5, 6, 7, 23. Every string below is copied from
 * that text (and, for the payload types, RFC 0002 :50-54); none is ours.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef SHARED_DHT2_TYPES_H
#define SHARED_DHT2_TYPES_H

#include <stdint.h>
#include <stddef.h>

#include "crypto/sign/qgp_dilithium.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── sizes ─────────────────────────────────────────────────────────── */

/** §3.1 "Size": the WHOLE encoded envelope ≤ 262,144 B, checked before any
 *  decode (Kurultay #21, last bullet). */
#define DHT2_ENVELOPE_MAX     262144u

#define DHT2_HASH_LEN         64u    /* SHA3-512 */
#define DHT2_FP_LEN           64u    /* SHA3-512(raw ML-DSA-87 key), nodus_sign.c:392 */
#define DHT2_CHAIN_LEN        32u    /* `_chain`, §3.1 */
#define DHT2_ID_LEN           64u    /* `_id`, §3.1 */
#define DHT2_NONCE_LEN        32u    /* `n` / `q`, §13 rows 2, 23 */
#define DHT2_VALIDITY_LEN     20u    /* `YYYY-MM-DDTHH:MM:SSZ`, §3.1 */
#define DHT2_PUBKEY_LEN       QGP_DSA87_PUBLICKEYBYTES  /* 2592 */
#define DHT2_SIG_LEN          QGP_DSA87_SIGNATURE_BYTES /* 4627 */

/* ── §13 row 5: `_class` ───────────────────────────────────────────── */
#define DHT2_CLASS_OWNER       1u
#define DHT2_CLASS_FEED_ENTRY  2u
#define DHT2_CLASS_FEED_HEAD   3u
#define DHT2_CLASS_INBOX_ENTRY 4u
#define DHT2_CLASS_INBOX_CTL   5u

/* ── §13 row 6: ValidityType ───────────────────────────────────────── */
#define DHT2_VT_EOL            0u   /* `Validity` present, 20 B */
#define DHT2_VT_NONE           1u   /* no expiry (ours), `Validity` empty */

/* ── §13 row 5 "Class max" / §5 (seconds) ──────────────────────────── */
#define DHT2_SEC_7D            604800u
#define DHT2_SEC_24H           86400u
#define DHT2_SEC_SLACK_3H      10800u   /* §4.1 "class max + 3 h" */

/* ── §13 row 7: per-key result codes ──────────────────────────────────
 * 0 is not a wire code: it is this codec's "the check passed". */
#define DHT2_OK                 0
#define DHT2_E_TOO_LARGE        1
#define DHT2_E_BAD_ENCODING     2
#define DHT2_E_BAD_CHAIN        3
#define DHT2_E_BAD_ADDRESS      4
#define DHT2_E_NOT_HOLDER       5
#define DHT2_E_BAD_CLASS        6
#define DHT2_E_EXPIRED          7
#define DHT2_E_TOO_LONG         8
#define DHT2_E_BAD_SIGNATURE    9
#define DHT2_E_QUOTA           10
#define DHT2_E_POOL_FULL       11
#define DHT2_E_DENIED          12
#define DHT2_E_NODE_FULL       13
#define DHT2_E_BUSY            14   /* call-level, row 7 / row 18 */
#define DHT2_E_NOT_CAUGHT_UP   15   /* call-level, row 7 / row 18 */
#define DHT2_E_HOLDER_FAULT    16
#define DHT2_E_NOT_OWNER       17
#define DHT2_E_HANDLED         18
/** NOT a row-7 code: row 7 "Malformed request … a tier-2 protocol error,
 *  no signed answer". Returned by the request decoders only. */
#define DHT2_E_MALFORMED_REQ  (-2)
/** NOT a row-7 code: a NULL argument / too-small output buffer — the
 *  caller's bug, never a verdict on input bytes. */
#define DHT2_E_ARG            (-1)

/* ── FIPS 204 ctx (records) and RFC 0002 domains (= ctx), §3.1, §4.4,
 *    §2 "Endpoints", §13 row 23 ─────────────────────────────────────── */
#define DHT2_CTX_RECORD   "nodus.dht.record.v1"
#define DHT2_DOMAIN_ANSWER "nodus.dht.answer.v1"
#define DHT2_DOMAIN_ADDR   "nodus.dht.addr.v1"
#define DHT2_DOMAIN_LIST   "nodus.dht.list.v1"

/* ── RFC 0002 payload types (§13 rows 1, 2, 12, 18, 23) ────────────────
 * The "path" multicodec 0x2f (multicodec table.csv:29) IS the path's own
 * leading '/': RFC 0002 (libp2p-specs 78e75c6f,
 * RFC/0002-signed-envelopes.md:50-54) — path payload types have "the form
 * `/some/thing`, using the namespace multicodec whose binary value is
 * equivalent to the UTF-8 `/` character". So each payload type is exactly
 * its ASCII path, first byte 0x2f, ONE slash (design §13 row 1):
 *     bytes = "/nodus/dht/list/v1" = 2f 6e 6f 64 75 73 … */
#define DHT2_PT_ANSWER        "/nodus/dht/answer/v1"
#define DHT2_PT_RECEIPT       "/nodus/dht/receipt/v1"
#define DHT2_PT_REFUSAL       "/nodus/dht/refusal/v1"
#define DHT2_PT_PULL_RECEIPT  "/nodus/dht/pull-receipt/v1"
#define DHT2_PT_ADDR          "/nodus/dht/addr/v1"
#define DHT2_PT_LIST          "/nodus/dht/list/v1"

/* ── §3.2 `_id` labels (ASCII, no NUL — Kurultay #21 "Signature ctx
 *    labels and record identifiers") ─────────────────────────────────── */
#define DHT2_LABEL_PROFILE      "nodus.dht.profile.v1"
#define DHT2_LABEL_CONTACTLIST  "nodus.dht.contactlist.v1"
#define DHT2_LABEL_GROUP_HEAD   "nodus.dht.group.head.v1"
#define DHT2_LABEL_GROUP_RECORD "nodus.dht.group.record.v1"
#define DHT2_LABEL_GROUP_KEYS   "nodus.dht.group.keys.v1"
#define DHT2_LABEL_DM           "nodus.dht.dm.v1"
#define DHT2_LABEL_GROUP_FEED   "nodus.dht.group.feed.v1"
#define DHT2_LABEL_HEAD         "nodus.dht.head.v1"
#define DHT2_LABEL_INBOX        "nodus.dht.inbox.v1"
#define DHT2_LABEL_INBOX_CTL    "nodus.dht.inbox.ctl.v1"

/* ── package 2: message bounds (§13 rows 7, 11, 12, 14, 15) ────────────── */

/** Row 7: > 8 keys is malformed; row 14: get `keys` / put `envs` ≤ 8. */
#define DHT2_REQ_KEYS_MAX      8u
/** Row 11: a LIST page lists ≤ 16 entries. */
#define DHT2_LIST_PAGE_MAX     16u
/** Row 12: `p_offer` carries ≤ 250 entries (Bee DefaultMaxPage). */
#define DHT2_PULL_PAGE_MAX     250u
/** Row 15: control `_data` entry = fp 64 ‖ mark 1 ‖ through 8 (u64 BE),
 *  ≤ 3,500 entries; mark 1 HANDLED / 2 DENIED. */
#define DHT2_CTL_ENTRY_LEN     73u
#define DHT2_CTL_ENTRIES_MAX   3500u
#define DHT2_CTL_HANDLED       1u
#define DHT2_CTL_DENIED        2u

/** Decision 2026-10-23-dht-v2-id-param-bytes.md: dm salt 32 B, group id
 *  32 B, group key version u32 big-endian. */
#define DHT2_SALT_LEN          32u
#define DHT2_GROUP_ID_LEN      32u
#define DHT2_KEY_VERSION_LEN   4u

/* ── row 11: the derived maximum answer MESSAGE ────────────────────────
 * Record bytes per call: 8 keys × 262,144 B (the records travel beside
 * the answer, row 18). The answer ENVELOPE (RFC 0002, protobuf, the
 * tree's proto3 sizes) for 8 keys, every term:
 *   payload (strict DAG-CBOR, read answer, the largest of the three
 *   8-key payloads; every uint taken at its 9-byte maximum):
 *     map head                                   1
 *     "c"  key 2 + bstr 32  (head 2 + 32)       36
 *     "h"  key 2 + uint 9                       11
 *     "n"  key 2 + bstr 64  (head 2 + 64)       68
 *     "q"  key 2 + bstr 32                      36
 *     "r"  key 2 + array head 1 + 8 × element 137, where one element is
 *          map head 1 + "k" 2 + bstr 64 (66) + "v" 2 + the larger of
 *          bstr 64 (66) and [18, through] (1 + 1 + 9 = 11)
 *                                            1099
 *     "t"  key 2 + uint 9                       11
 *   = 1262 B.
 *   (A LIST answer's payload is another bound: one `r` element plus
 *   ≤ 16 {w, d} entries ≈ 2.4 KB, its records ≤ 2 MiB — row 11.)
 *   envelope field 1, the public key: tag 1 + uvarint(2595) 2 +
 *     PublicKey message (tag 1 + uvarint(2592) 2 + 2592 key) = 2598
 *   field 2, payload type: tag 1 + len 1 + 21 ("/nodus/dht/receipt/v1" and
 *     "/nodus/dht/refusal/v1" are the longest) = 23
 *   field 3, payload: tag 1 + uvarint(1262) 2 + 1262 = 1265
 *   field 5, signature: tag 1 + uvarint(4627) 2 + 4627 = 4630.
 * The `_Static_assert` of the total against NODUS_MAX_FRAME_TCP lives in
 * nodus/tests/test_dht2_msg.c (shared/ does not include nodus headers). */
#define DHT2_ANSWER_PAYLOAD_MAX \
    (1u + 36u + 11u + 68u + 36u + (2u + 1u + 8u * 137u) + 11u)
#define DHT2_ANSWER_ENV_MAX \
    ((1u + 2u + (1u + 2u + DHT2_PUBKEY_LEN)) + (1u + 1u + 21u) + \
     (1u + 2u + DHT2_ANSWER_PAYLOAD_MAX) + (1u + 2u + DHT2_SIG_LEN))
#define DHT2_ANSWER_MSG_MAX \
    (DHT2_REQ_KEYS_MAX * DHT2_ENVELOPE_MAX + DHT2_ANSWER_ENV_MAX)

/** §2 / design rev 5: R = 4 holders per record (scope 4f). */
#define DHT2_R                 4u

/** Largest storage set nearest_R / eligible accept: the registry bound
 *  design §13 row 13 states ("≤ 256, nodus_witness_rt_native.c:6252").
 *  Keeps the O(n²) duplicate scan bounded. */
#define DHT2_SET_MAX           256u

#ifdef __cplusplus
}
#endif

#endif /* SHARED_DHT2_TYPES_H */
