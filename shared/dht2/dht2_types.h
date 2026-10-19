/**
 * @file shared/dht2/dht2_types.h
 * @brief DHT v2 — the constants every dht2 codec file shares: sizes, the
 *        row-7 result codes, the FIPS 204 ctx / RFC 0002 domain strings,
 *        the `_id` labels and the RFC 0002 payload types.
 *
 * Design: docs/plans/2026-10-14-dht-v2-design.md rev 5 (FROZEN) — §3.1,
 * §3.2, §4.4, §13 rows 1, 5, 6, 7, 23. Every string below is copied from
 * that text; none is ours. Where the design text admits two byte readings
 * the constant says so (DHT2_PT_*).
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
 * ⚠ BYTE READING PENDING ORCHESTRATOR CONFIRMATION. The design says
 * "the 'path' multicodec (0x2f, multicodec table.csv:29) followed by the
 * ASCII path, as RFC 0002 suggests" (row 1) and "multicodec 'path' 0x2f +
 * `/nodus/dht/list/v1`" (row 23). RFC 0002 (libp2p-specs 78e75c6f,
 * RFC/0002-signed-envelopes.md:48-54) says path payload types have "the
 * form `/some/thing`, using the namespace multicodec whose binary value
 * is equivalent to the UTF-8 `/` character" — i.e. the path's own
 * leading '/' IS the 0x2f code. That is the reading written here:
 *     bytes = "/nodus/dht/list/v1"   (first byte 0x2f, ONE slash)
 * The other literal reading, 0x2f ‖ "/nodus/dht/list/v1" (= two leading
 * slashes), is NOT used. Every payload type lives in this one block, so
 * the answer changes one place. */
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

/** §2 / design rev 5: R = 4 holders per record (scope 4f). */
#define DHT2_R                 4u

#ifdef __cplusplus
}
#endif

#endif /* SHARED_DHT2_TYPES_H */
