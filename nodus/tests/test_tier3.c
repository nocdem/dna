/**
 * Nodus — Tier 3 Protocol Unit Test
 *
 * Round-trip encode/decode test for the SURVIVING message types this
 * file exercises directly: the peer mesh (9-11: w_rost_q, w_rost_r,
 * w_ident), the genesis bundle (24-25) and the cometbft envelope
 * (35-39). Tests: encode -> decode -> verify field equality. Also tests
 * sign/verify round-trip.
 *
 * The chain_config vote-collect RPC (14-15, kept per register
 * R3-W4-D-8) has NO round-trip encode/decode test anywhere today — not
 * in this file (its only appearances here are the live_verbs /
 * method-name table rows below, never an actual encode-decode-verify
 * cycle) and not in test_cc_client.c either, which only exercises
 * argument validation and timeouts against a dead peer and never
 * decodes a `w_cc_vote_rsp`. This was already true at 4a43e3a9, before
 * this delta touched either file — it is a pre-existing coverage gap,
 * not something this delta introduced or a substitute this delta can
 * name.
 *
 * R3 W4-D (Delta B) retired verbs 1-8, 12-13, 16-23 and 26-27 (the
 * legacy PBFT propose/vote/commit/view-change/forward round, block
 * sync, bootstrap discovery/genesis-fetch and view authority) with the
 * closed consensus lane — their tests are deleted with them, per-verb
 * struct by per-verb struct, the same way the legacy Tendermint reactor
 * verbs 28-34 (T2 wire design §4.2, D-16 rev 4) were RETIRED in W3.
 *
 * ── cometbft envelope sections (verbs 35-39, D-16 rev 5, W3) ─────────
 *
 * The legacy Tendermint reactor verbs 28-34 were RETIRED in W3 and their
 * tests deleted with them — the per-verb CBOR structs they exercised no
 * longer exist. This file's W3 sections replace them.
 *
 * WHAT THEY PROVE. That the cometbft envelope codec ({m: bstr}, one
 * shape for all five verbs, D-16 rev 5) is a bijection over its
 * declared domain: each verb survives encode → decode → verify with
 * `m` unchanged; the method tables agree in both directions; the
 * retired verbs 28-34 answer NULL/0 everywhere; a message that departs
 * from the exact-key-set spec — a missing "m", an extra key, "m" of
 * the wrong CBOR type — is refused; `m` exactly at its class ceiling
 * is accepted THROUGH THE SAME HAND-BUILT FRAME the oversize case uses
 * (the CONTROL that makes the oversize refusal mean something — see HOW
 * THEY CAN LIE (1)) and one byte above is refused by the DECODER's own
 * pass-2 cap (dec_w_cmt_args), never merely by the ENCODER'S buffer
 * running out first. They also prove
 * NODUS_T3_CMT_ENVELOPE_OVERHEAD is an over-estimate of the envelope's
 * real cost (measured, not asserted) and pin the mempool ceiling
 * (NODUS_T3_CMT_TXS_M_MAX) against `cmt_memr_get_channels` at the
 * DEFAULT mempool config — the only place that number is tied to its
 * source, since cmt_memr computes it at runtime, not as a compile-time
 * constant.
 *
 * AND ONE MORE, WHICH IS A PIN RATHER THAN A FEATURE, WITH A CAVEAT
 * READ THE WHOLE PARAGRAPH BEFORE TRUSTING IT:
 * test_universal_negint_pin proves the D-22 rev 3 admission set is
 * EMPTY — a negative integer anywhere in `a` returns -1 for every verb,
 * legacy or new, under a known key, an unknown key, or nested in an
 * array. THE MECHANISM IS TWO LAYERS, NOT ONE, and dropping either
 * layer ALONE flips NOTHING today: pass 2 resets `dec.error` before
 * re-walking `a` (nodus_tier3.c:2195) through the ordinary
 * cbor_decode_next / cbor_decode_skip, and cbor_decode_next's own
 * `default:` branch sets `dec->error = true` on ANY major-type-1 byte
 * it reads, unconditionally (nodus_cbor.c:274-278) — so even with the
 * `if (a_negint) return -1;` gate deleted, every one of this file's five
 * cases is STILL refused, by pass 2's own error propagation, not by the
 * gate. The gate is the SECOND layer: it is what stays load-bearing if
 * the FIRST layer ALSO changes — specifically for the legacy shapes,
 * cases (i)-(iii), whose decoder reads a negative's value with a
 * `val.type == CBOR_ITEM_UINT` check that ignores the type rather than
 * reject it (case i, nodus_tier3.c's dec_rost_q_args) or skip an
 * unknown key's value outright (cases ii/iii) — if `cbor_decode_next`
 * or the legacy skip idiom ever stopped erroring on a negative, ONLY
 * the gate would still refuse those three. Cases (iv)/(v), the cometbft
 * envelope verbs, are NOT in that set: `dec_w_cmt_args` (nodus_tier3.c)
 * refuses ANY key but "m" outright, before reading its value at all
 * (case v), and refuses "m"'s own value on a bare TYPE mismatch,
 * independent of sign (case iv) — {m: bstr} has no position where a
 * negative could otherwise pass, with or without the gate, with or
 * without a tolerant walker. So this test's real claim is REGRESSION
 * INSURANCE on the layer that would survive a walker change (i)-(iii),
 * and cases (iv)/(v) additionally confirm the strict decoder still
 * refuses those specific frames — see each case's own comment.
 *
 * WHAT THEY REQUIRE. Nothing beyond a default build: no compile flag, no
 * environment variable, no network, no filesystem. Keys come from
 * qgp_dsa87_keypair_derand with a fixed seed, so there is no RNG, no clock
 * and no port — the file is `ctest -j` safe and byte-reproducible.
 *
 * WHAT THEY LEAVE BEHIND. Nothing. No files, no processes, no global state
 * beyond this process's own static buffers; every heap buffer is freed.
 *
 * HOW THEY CAN LIE. (1) The negative and strict-key-set cases, AND the
 * oversize half of the at-ceiling sections, drive a HAND-BUILT envelope,
 * so a mistake in the builder would make every one of them "pass" by
 * rejecting for the wrong reason; each such test runs a CONTROL first
 * (a hand-built frame the decoder must ACCEPT — for the negative/strict
 * cases, an ordinary frame; for one_cmt_ceiling, `m` at EXACTLY m_cap
 * through the SAME builder) so a builder defect fails loudly instead of
 * silently strengthening the assertion that follows. Before this
 * control existed, one_cmt_ceiling's oversize case was VACUOUS for
 * verbs 35/39: its buffer gave the builder only 4096 B of slack, ~4.7 KB
 * short of what wsig plus the fixed fields cost, so the encoder
 * overflowed (`w3_frame_end` returned -99) and `nodus_t3_decode` was
 * NEVER CALLED — the test read -99 as "refused" and passed without
 * exercising `dec_w_cmt_args`'s pass-2 cap at all. (2) A green run says
 * nothing about the host rules — ValidateBasic, the wh.cid
 * derived-identity gate and the vote admission rules live in cmt_msgs /
 * cmt_conr / cmt_memr and are not exercised by this codec at all; `m`'s
 * bytes are carried opaque, never interpreted. (3) The at-ceiling
 * sections prove the class buffer holds a maximal message on THIS
 * host's allocator; they say nothing about the frame layer beyond the
 * one static assert in nodus_tier3.c, or about peer.c's receive
 * buffers, which are still sized for legacy verbs. (4) THE DECODED
 * MESSAGE IS ONLY AS VALID AS THE BUFFER IT WAS
 * DECODED FROM: `out.w_cmt.m` is zero-copy for every one of the five
 * verbs, and `out.wsig` points into the buffer too, for EVERY verb,
 * because it sits outside the union (nodus_tier3.h). So any test that
 * reads `m`, reads `wsig`, or calls nodus_t3_verify after the fixture
 * returns must own the buffer and free it afterwards — the `keep`
 * parameter on cmt_roundtrip states which caller needs to.
 */

#include "protocol/nodus_tier3.h"
#include "protocol/nodus_cbor.h"
#include "crypto/nodus_sign.h"
#include "crypto/nodus_identity.h"
#include "crypto/sign/qgp_dilithium.h"   /* qgp_dsa87_keypair_derand */
#include "dnac/cmt_mem.h"                /* cmt_mempool_config_default */
#include "dnac/cmt_memr.h"               /* cmt_memr_get_channels — the TXS ceiling pin */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#define TEST_PASS(name) fprintf(stderr, "  PASS: %s\n", name)
#define TEST_FAIL(name, msg) do { \
    fprintf(stderr, "  FAIL: %s — %s\n", name, msg); \
    failures++; \
} while(0)

static int failures = 0;

/* Test identity (generated once) */
static nodus_identity_t test_id;
static int identity_ready = 0;

static void ensure_identity(void) {
    if (identity_ready) return;
    if (nodus_identity_generate(&test_id) != 0) {
        fprintf(stderr, "FATAL: cannot generate test identity\n");
        exit(1);
    }
    identity_ready = 1;
}

/* Fill a header with test data */
static void fill_header(nodus_t3_header_t *hdr) {
    hdr->version = NODUS_T3_BFT_PROTOCOL_VER;
    hdr->round = 42;
    hdr->view = 3;
    memset(hdr->sender_id, 0xAA, NODUS_T3_WITNESS_ID_LEN);
    hdr->timestamp = 1709300000;
    hdr->nonce = 12345678;
    memset(hdr->chain_id, 0xBB, 32);
}

static void check_header(const nodus_t3_header_t *a, const nodus_t3_header_t *b,
                           const char *test_name) {
    if (a->version != b->version ||
        a->round != b->round ||
        a->view != b->view ||
        memcmp(a->sender_id, b->sender_id, NODUS_T3_WITNESS_ID_LEN) != 0 ||
        a->timestamp != b->timestamp ||
        a->nonce != b->nonce ||
        memcmp(a->chain_id, b->chain_id, 32) != 0) {
        TEST_FAIL(test_name, "header mismatch");
    }
}

/* ── Test data ───────────────────────────────────────────────────── */

static uint8_t test_tx_hash[NODUS_T3_TX_HASH_LEN];
static uint8_t test_nullifiers[NODUS_T3_MAX_TX_INPUTS][NODUS_T3_NULLIFIER_LEN];
static uint8_t test_tx_data[256];
static uint8_t test_pubkey[NODUS_PK_BYTES];
static uint8_t test_sig[NODUS_SIG_BYTES];

static void init_test_data(void) {
    memset(test_tx_hash, 0x11, sizeof(test_tx_hash));
    for (int i = 0; i < NODUS_T3_MAX_TX_INPUTS; i++)
        memset(test_nullifiers[i], 0x20 + i, NODUS_T3_NULLIFIER_LEN);
    for (int i = 0; i < (int)sizeof(test_tx_data); i++)
        test_tx_data[i] = (uint8_t)(i & 0xFF);
    memset(test_pubkey, 0x33, NODUS_PK_BYTES);
    memset(test_sig, 0x44, NODUS_SIG_BYTES);
}

/* ── Test: method ↔ type mapping ─────────────────────────────────── */

/* R3 W4-D (Delta B) — the LIVE verb set is no longer a contiguous range:
 * retirement leaves gaps (1-8, 12-13, 16-23, 26-34 are all "not a verb"
 * numbers, never reused). This test now names every surviving verb
 * explicitly rather than looping a range, so a future retirement or
 * addition must touch this array by hand instead of silently widening
 * or narrowing what gets checked. */
static const nodus_t3_msg_type_t live_verbs[] = {
    NODUS_T3_ROST_Q, NODUS_T3_ROST_R, NODUS_T3_IDENT,
    NODUS_T3_CC_VOTE_REQ, NODUS_T3_CC_VOTE_RSP,
    NODUS_T3_V2_GBUNDLE_REQ, NODUS_T3_V2_GBUNDLE_RSP,
    NODUS_T3_CMT_STATE, NODUS_T3_CMT_DATA, NODUS_T3_CMT_VOTE,
    NODUS_T3_CMT_VOTE_SET_BITS, NODUS_T3_CMT_TXS,
};

static void test_method_type_mapping(void) {
    const char *name = "method_type_mapping";

    for (size_t i = 0; i < sizeof(live_verbs) / sizeof(live_verbs[0]); i++) {
        nodus_t3_msg_type_t t = live_verbs[i];
        const char *method = nodus_t3_type_to_method(t);
        if (!method) { TEST_FAIL(name, "type_to_method returned NULL"); return; }
        nodus_t3_msg_type_t back = nodus_t3_method_to_type(method);
        if (back != t) { TEST_FAIL(name, "round-trip type mismatch"); return; }
    }

    if (nodus_t3_type_to_method(0) != NULL) {
        TEST_FAIL(name, "type 0 should return NULL"); return;
    }
    if (nodus_t3_method_to_type("invalid") != 0) {
        TEST_FAIL(name, "invalid method should return 0"); return;
    }

    TEST_PASS(name);
}

/* ── Encode/decode round-trip helper ─────────────────────────────── */

static uint8_t enc_buf[NODUS_T3_MAX_MSG_SIZE];

static int roundtrip(nodus_t3_msg_t *in, nodus_t3_msg_t *out) {
    ensure_identity();

    size_t len = 0;
    if (nodus_t3_encode(in, &test_id.sk, enc_buf, sizeof(enc_buf), &len) != 0)
        return -1;
    if (len == 0) return -1;

    if (nodus_t3_decode(enc_buf, len, out) != 0)
        return -2;

    return 0;
}

/* R3 W4-D (Delta B) — test_propose, test_prevote, test_precommit,
 * test_commit, test_viewchg, test_newview, test_viewchg_with_prepared,
 * test_newview_with_reproposal, test_fwd_req and test_fwd_rsp (verbs
 * 1-8, the legacy PBFT propose/vote/commit/view-change/forward round)
 * are DELETED with the closed consensus lane: their subject enum values,
 * arg structs and codec are all gone (nodus_tier3.h/.c). */

/* ── Test: w_rost_q round-trip ───────────────────────────────────── */

static void test_rost_q(void) {
    const char *name = "w_rost_q";
    nodus_t3_msg_t in, out;
    memset(&in, 0, sizeof(in));

    in.type = NODUS_T3_ROST_Q;
    in.txn_id = 108;
    fill_header(&in.header);
    in.rost_q.version = 2;

    int rc = roundtrip(&in, &out);
    if (rc != 0) { TEST_FAIL(name, rc == -1 ? "encode failed" : "decode failed"); return; }

    if (out.type != NODUS_T3_ROST_Q) { TEST_FAIL(name, "type"); return; }
    if (out.rost_q.version != 2) { TEST_FAIL(name, "version"); return; }
    if (nodus_t3_verify(&out, &test_id.pk) != 0) {
        TEST_FAIL(name, "wsig verify"); return;
    }

    TEST_PASS(name);
}

/* ── Test: w_rost_r round-trip ───────────────────────────────────── */

static void test_rost_r(void) {
    const char *name = "w_rost_r";
    nodus_t3_msg_t in, out;
    memset(&in, 0, sizeof(in));

    static uint8_t rwid[NODUS_T3_WITNESS_ID_LEN];
    static uint8_t rpk[NODUS_PK_BYTES];
    static uint8_t rsig[NODUS_SIG_BYTES];

    memset(rwid, 0xF1, NODUS_T3_WITNESS_ID_LEN);
    memset(rpk, 0xF2, NODUS_PK_BYTES);
    memset(rsig, 0xF3, NODUS_SIG_BYTES);

    in.type = NODUS_T3_ROST_R;
    in.txn_id = 109;
    fill_header(&in.header);

    in.rost_r.version = 1;
    in.rost_r.n_witnesses = 1;
    in.rost_r.witnesses[0].witness_id = rwid;
    in.rost_r.witnesses[0].pubkey = rpk;
    snprintf(in.rost_r.witnesses[0].address,
             sizeof(in.rost_r.witnesses[0].address), "192.168.0.1:4001");
    in.rost_r.witnesses[0].joined_epoch = 10;
    in.rost_r.witnesses[0].active = true;
    in.rost_r.roster_sig = rsig;

    int rc = roundtrip(&in, &out);
    if (rc != 0) { TEST_FAIL(name, rc == -1 ? "encode failed" : "decode failed"); return; }

    if (out.type != NODUS_T3_ROST_R) { TEST_FAIL(name, "type"); return; }
    if (out.rost_r.version != 1) { TEST_FAIL(name, "version"); return; }
    if (out.rost_r.n_witnesses != 1) { TEST_FAIL(name, "n_witnesses"); return; }
    if (!out.rost_r.witnesses[0].witness_id ||
        memcmp(out.rost_r.witnesses[0].witness_id, rwid,
               NODUS_T3_WITNESS_ID_LEN) != 0) {
        TEST_FAIL(name, "witness_id"); return;
    }
    if (strcmp(out.rost_r.witnesses[0].address, "192.168.0.1:4001") != 0) {
        TEST_FAIL(name, "address"); return;
    }
    if (!out.rost_r.witnesses[0].active) { TEST_FAIL(name, "active"); return; }
    if (!out.rost_r.roster_sig ||
        memcmp(out.rost_r.roster_sig, rsig, NODUS_SIG_BYTES) != 0) {
        TEST_FAIL(name, "roster_sig"); return;
    }
    if (nodus_t3_verify(&out, &test_id.pk) != 0) {
        TEST_FAIL(name, "wsig verify"); return;
    }

    TEST_PASS(name);
}

/* ── Test: w_ident round-trip ────────────────────────────────────── */

static void test_ident(void) {
    const char *name = "w_ident";
    nodus_t3_msg_t in, out;
    memset(&in, 0, sizeof(in));

    static uint8_t iwid[NODUS_T3_WITNESS_ID_LEN];
    static uint8_t ipk[NODUS_PK_BYTES];
    memset(iwid, 0xA1, NODUS_T3_WITNESS_ID_LEN);
    memset(ipk, 0xA2, NODUS_PK_BYTES);

    in.type = NODUS_T3_IDENT;
    in.txn_id = 110;
    fill_header(&in.header);
    in.ident.witness_id = iwid;
    in.ident.pubkey = ipk;
    snprintf(in.ident.address, sizeof(in.ident.address), "10.0.0.1:4001");

    int rc = roundtrip(&in, &out);
    if (rc != 0) { TEST_FAIL(name, rc == -1 ? "encode failed" : "decode failed"); return; }

    if (out.type != NODUS_T3_IDENT) { TEST_FAIL(name, "type"); return; }
    if (!out.ident.witness_id ||
        memcmp(out.ident.witness_id, iwid, NODUS_T3_WITNESS_ID_LEN) != 0) {
        TEST_FAIL(name, "witness_id"); return;
    }
    if (!out.ident.pubkey ||
        memcmp(out.ident.pubkey, ipk, NODUS_PK_BYTES) != 0) {
        TEST_FAIL(name, "pubkey"); return;
    }
    if (strcmp(out.ident.address, "10.0.0.1:4001") != 0) {
        TEST_FAIL(name, "address"); return;
    }
    if (nodus_t3_verify(&out, &test_id.pk) != 0) {
        TEST_FAIL(name, "wsig verify"); return;
    }

    TEST_PASS(name);
}

/* R3 W4-D (Delta B) — test_sync_req and test_sync_rsp (verbs 12-13, the
 * legacy block-sync request/response) are DELETED with the closed
 * consensus lane: NODUS_T3_SYNC_REQ / _RSP and their arg structs are
 * gone (nodus_tier3.h/.c). */

/* ── Test: verify with wrong key fails ───────────────────────────── */

/* R3 W4-D (Delta B) — this case used to build a w_viewchg (verb 5,
 * retired). The wrong-key rejection it proves is verb-agnostic
 * (nodus_t3_verify checks the Dilithium5 signature the same way for
 * every type), so it is rewritten onto a LIVE verb, w_rost_q, rather
 * than deleted. */
static void test_verify_wrong_key(void) {
    const char *name = "verify_wrong_key";
    nodus_t3_msg_t in, out;
    memset(&in, 0, sizeof(in));

    in.type = NODUS_T3_ROST_Q;
    in.txn_id = 200;
    fill_header(&in.header);
    in.rost_q.version = 1;

    int rc = roundtrip(&in, &out);
    if (rc != 0) { TEST_FAIL(name, "roundtrip"); return; }

    /* Generate a different identity */
    nodus_identity_t other;
    if (nodus_identity_generate(&other) != 0) {
        TEST_FAIL(name, "generate other identity"); return;
    }

    /* Verify with wrong key should fail */
    if (nodus_t3_verify(&out, &other.pk) == 0) {
        TEST_FAIL(name, "should have failed with wrong key"); return;
    }

    TEST_PASS(name);
}

/* R3 W4-D (Delta B) — test_propose_zero_nullifiers (w_propose's
 * batch-of-1, zero-nullifier genesis entry, verb 1) is DELETED with the
 * closed consensus lane: nodus_t3_batch_tx_t, the struct whose
 * nullifier_count this test pinned, is gone (nodus_tier3.h), and no
 * surviving verb (9-11, 14-15, 24-25, 35-39) carries a batch-of-txs
 * shape for this property to attach to. */

/* ══════════════════════════════════════════════════════════════════
 * cometbft envelope — verbs 35-39 (D-16 rev 5, W3)
 * ══════════════════════════════════════════════════════════════════ */

/* Deterministic keypair — qgp_dsa87_keypair_derand with a fixed seed (the
 * test_qc_v2.c idiom, unchanged from wave 1). Deliberately NOT
 * ensure_identity() above, which draws from the RNG: these sections must
 * be reproducible. */
static nodus_pubkey_t cmt_pk;
static nodus_seckey_t cmt_sk;
static int            cmt_keys_ready = 0;

static void cmt_ensure_keys(void) {
    if (cmt_keys_ready) return;
    uint8_t seed[32];
    memset(seed, 0x5A, sizeof(seed));
    if (qgp_dsa87_keypair_derand(cmt_pk.bytes, cmt_sk.bytes, seed) != 0) {
        fprintf(stderr, "FATAL: derand keypair failed\n");
        exit(1);
    }
    cmt_keys_ready = 1;
}

/* Encode through the type's OWN class buffer, then decode. Using
 * nodus_t3_max_msg_size for the allocation is the point: if a class bound
 * were too small for its own maximal message, encode would fail here. */
/* ⚠ BUFFER LIFETIME IS PART OF THE CONTRACT — for TWO reasons, and the
 * second one applies to every verb:
 *
 *   1. `w_cmt.m` points INTO the buffer this helper allocates (zero-copy,
 *      the same idiom the retired nodus_t3_tm_prop_t's `v` and
 *      w_v2_range_r's `frames` use — nodus_t3_w_cmt_t in nodus_tier3.h).
 *   2. `out.wsig` points into it too, for EVERY verb. It lives OUTSIDE the
 *      union (nodus_tier3.h) and is set to a pointer into the decode
 *      buffer in pass 1; nodus_t3_verify memcpy's NODUS_SIG_BYTES from it.
 *
 * So `out` is only as valid as the buffer, and the rule is:
 *
 * keep == NULL  → the buffer is freed here. Safe ONLY for a caller that
 *                 neither reads out.wsig nor calls nodus_t3_verify after
 *                 the return, and does not read out.w_cmt.m. Reading the
 *                 copied scalar fields (type, header, m_len) is fine.
 *                 The helper's own verify below is the only verify such a
 *                 caller gets, and it runs while the buffer is alive.
 * keep != NULL  → the buffer is handed over on success and *keep is the
 *                 caller's to free, after its last read of `out`. On every
 *                 failure path *keep is NULL and the buffer is already
 *                 freed, so the caller can free(*keep) unconditionally. */
static int cmt_roundtrip(nodus_t3_msg_t *in, nodus_t3_msg_t *out,
                         size_t *enc_len_out, uint8_t **keep) {
    cmt_ensure_keys();
    if (keep) *keep = NULL;

    size_t cap = nodus_t3_max_msg_size(in->type);
    if (cap == 0) return -3;
    uint8_t *buf = malloc(cap);
    if (!buf) return -4;

    size_t len = 0;
    int rc = nodus_t3_encode(in, &cmt_sk, buf, cap, &len);
    if (rc != 0 || len == 0) { free(buf); return -1; }
    if (nodus_t3_decode(buf, len, out) != 0) { free(buf); return -2; }
    /* Verify inside the class buffer — a failure here would mean the
     * bound nodus_t3_verify allocates cannot hold this message. */
    if (nodus_t3_verify(out, &cmt_pk) != 0) { free(buf); return -5; }

    if (enc_len_out) *enc_len_out = len;
    if (keep) *keep = buf;      /* caller owns it now */
    else      free(buf);
    return 0;
}

/* ── The generic hand-built envelope, shared by every W3 structural
 *    test below ────────────────────────────────────────────────────
 *
 * The builder writes a complete {t, y, q, wh, a, wsig} frame so the
 * decoder sees a well-formed envelope and the ONLY thing under test is
 * the `a` map the caller supplies between the two halves; wsig is
 * filler because nodus_t3_decode does not verify it. Renamed and
 * generalized from wave 1's tm_frame_begin/tm_frame_end (same idiom,
 * no longer Tendermint-specific): w3_frame_begin_buf takes an explicit
 * buffer so the class-ceiling tests can use one far larger than the
 * 64 KiB default; w3_frame_begin is the small-buffer convenience the
 * structural and negint-pin tests use. */
static uint8_t w3_filler[QGP_DSA87_SIGNATURE_BYTES];
static uint8_t w3_small_frame[64 * 1024];

static void w3_frame_begin_buf(cbor_encoder_t *enc, const char *method,
                               uint8_t *buf, size_t cap) {
    cbor_encoder_init(enc, buf, cap);
    cbor_encode_map(enc, 6);
    cbor_encode_cstr(enc, "t"); cbor_encode_uint(enc, 42);
    cbor_encode_cstr(enc, "y"); cbor_encode_cstr(enc, "q");
    cbor_encode_cstr(enc, "q"); cbor_encode_cstr(enc, method);
    /* wh — the 7 keys enc_wh emits, same order */
    cbor_encode_cstr(enc, "wh");
    cbor_encode_map(enc, 7);
    cbor_encode_cstr(enc, "v");   cbor_encode_uint(enc, NODUS_T3_BFT_PROTOCOL_VER);
    cbor_encode_cstr(enc, "rnd"); cbor_encode_uint(enc, 0);
    cbor_encode_cstr(enc, "vw");  cbor_encode_uint(enc, 0);
    cbor_encode_cstr(enc, "sid"); cbor_encode_bstr(enc, w3_filler, 32);
    cbor_encode_cstr(enc, "ts");  cbor_encode_uint(enc, 1);
    cbor_encode_cstr(enc, "nc");  cbor_encode_uint(enc, 2);
    cbor_encode_cstr(enc, "cid"); cbor_encode_bstr(enc, w3_filler, 32);
    cbor_encode_cstr(enc, "a");
}

static void w3_frame_begin(cbor_encoder_t *enc, const char *method) {
    w3_frame_begin_buf(enc, method, w3_small_frame, sizeof(w3_small_frame));
}

static int w3_frame_end(cbor_encoder_t *enc, nodus_t3_msg_t *out) {
    cbor_encode_cstr(enc, "wsig");
    cbor_encode_bstr(enc, w3_filler, QGP_DSA87_SIGNATURE_BYTES);
    size_t len = cbor_encoder_len(enc);
    if (len == 0) return -99;               /* builder overflowed */
    return nodus_t3_decode(enc->buf, len, out);
}

/* ── Test: method ↔ type table for the cometbft envelope verbs ────── */

static void test_cmt_method_table(void) {
    const char *name = "cmt_method_table";

    static const struct { nodus_t3_msg_type_t t; const char *m; } tbl[] = {
        { NODUS_T3_CMT_STATE,         "w_cmt_state" },
        { NODUS_T3_CMT_DATA,          "w_cmt_data"  },
        { NODUS_T3_CMT_VOTE,          "w_cmt_vote"  },
        { NODUS_T3_CMT_VOTE_SET_BITS, "w_cmt_bits"  },
        { NODUS_T3_CMT_TXS,           "w_cmt_txs"   },
    };

    for (size_t i = 0; i < sizeof(tbl) / sizeof(tbl[0]); i++) {
        const char *m = nodus_t3_type_to_method(tbl[i].t);
        if (!m || strcmp(m, tbl[i].m) != 0) {
            TEST_FAIL(name, "type_to_method string mismatch"); return;
        }
        if (nodus_t3_method_to_type(tbl[i].m) != tbl[i].t) {
            TEST_FAIL(name, "method_to_type round-trip"); return;
        }
    }

    /* Values do not move: 35-39 are the new envelope block, fixed at
     * these numbers. R3 W4-D retired 26-27 (view authority) along with
     * 1-8/12-23 — this check no longer anchors on the last pre-existing
     * verb before them, since NODUS_T3_VIEWOK_REQ (formerly 27) is
     * deleted; 35-39's own values are the only thing left to pin. */
    if (NODUS_T3_CMT_STATE != 35 ||
        NODUS_T3_CMT_DATA != 36 || NODUS_T3_CMT_VOTE != 37 ||
        NODUS_T3_CMT_VOTE_SET_BITS != 38 || NODUS_T3_CMT_TXS != 39) {
        TEST_FAIL(name, "enum values moved"); return;
    }

    /* A retired number is recognised by NEITHER table — 26-34 now, not
     * just 28-34, since this delta retires 26-27 too. */
    for (int v = 26; v <= 34; v++) {
        if (nodus_t3_type_to_method((nodus_t3_msg_type_t)v) != NULL) {
            TEST_FAIL(name, "a retired verb still has a method string"); return;
        }
    }

    /* Every method string must fit nodus_t3_msg_t.method[16] with its NUL,
     * or pass 1 truncates it and method_to_type silently returns 0. The
     * longest name here is "w_cmt_state" (11). */
    for (size_t i = 0; i < sizeof(tbl) / sizeof(tbl[0]); i++) {
        if (strlen(tbl[i].m) > 15) {
            TEST_FAIL(name, "method string would be truncated at decode"); return;
        }
    }

    TEST_PASS(name);
}

/* ── Test: per-verb round-trip ───────────────────────────────────── */

static void test_cmt_roundtrip(void) {
    const char *name = "cmt_roundtrip";
    static const nodus_t3_msg_type_t verbs[] = {
        NODUS_T3_CMT_STATE, NODUS_T3_CMT_DATA, NODUS_T3_CMT_VOTE,
        NODUS_T3_CMT_VOTE_SET_BITS, NODUS_T3_CMT_TXS
    };
    static const uint8_t payload[32] = {
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
        17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32
    };

    for (size_t i = 0; i < sizeof(verbs) / sizeof(verbs[0]); i++) {
        nodus_t3_msg_t in, out;
        uint8_t *keep = NULL;
        memset(&in, 0, sizeof(in));
        in.type = verbs[i];
        in.txn_id = 3500;
        fill_header(&in.header);
        in.w_cmt.m     = payload;
        in.w_cmt.m_len = sizeof(payload);

        /* `keep`: w_cmt.m is zero-copy, so it must still point at live
         * memory for the memcmp below. */
        if (cmt_roundtrip(&in, &out, NULL, &keep) != 0) {
            TEST_FAIL(name, "roundtrip"); return;
        }
        check_header(&in.header, &out.header, name);
        if (out.type != verbs[i]) {
            free(keep); TEST_FAIL(name, "type mismatch"); return;
        }
        if (out.w_cmt.m_len != sizeof(payload) ||
            memcmp(out.w_cmt.m, payload, sizeof(payload)) != 0) {
            free(keep); TEST_FAIL(name, "m mismatch"); return;
        }
        free(keep);
    }
    TEST_PASS(name);
}

/* ── Test: strict key set — exactly "m", no more and no fewer ──────── */

static void test_cmt_strict_key_set(void) {
    const char *name = "cmt_strict_key_set";
    nodus_t3_msg_t out;
    cbor_encoder_t enc;

    /* CONTROL: a legitimate {m: bstr} — must be ACCEPTED, or the three
     * negatives below prove nothing. */
    w3_frame_begin(&enc, "w_cmt_state");
    cbor_encode_map(&enc, 1);
    cbor_encode_cstr(&enc, "m"); cbor_encode_bstr(&enc, w3_filler, 8);
    if (w3_frame_end(&enc, &out) != 0) {
        TEST_FAIL(name, "the valid control frame was REJECTED"); return;
    }
    if (out.type != NODUS_T3_CMT_STATE || out.w_cmt.m_len != 8) {
        TEST_FAIL(name, "control decoded to the wrong fields"); return;
    }

    /* missing "m" — an empty args map. */
    w3_frame_begin(&enc, "w_cmt_state");
    cbor_encode_map(&enc, 0);
    if (w3_frame_end(&enc, &out) == 0) {
        TEST_FAIL(name, "missing m accepted"); return;
    }

    /* an extra key beside "m". */
    w3_frame_begin(&enc, "w_cmt_state");
    cbor_encode_map(&enc, 2);
    cbor_encode_cstr(&enc, "m");   cbor_encode_bstr(&enc, w3_filler, 8);
    cbor_encode_cstr(&enc, "zzz"); cbor_encode_uint(&enc, 1);
    if (w3_frame_end(&enc, &out) == 0) {
        TEST_FAIL(name, "extra key accepted"); return;
    }

    /* "m" a duplicate key. */
    w3_frame_begin(&enc, "w_cmt_state");
    cbor_encode_map(&enc, 2);
    cbor_encode_cstr(&enc, "m"); cbor_encode_bstr(&enc, w3_filler, 8);
    cbor_encode_cstr(&enc, "m"); cbor_encode_bstr(&enc, w3_filler, 4);
    if (w3_frame_end(&enc, &out) == 0) {
        TEST_FAIL(name, "duplicate m accepted"); return;
    }

    /* "m" as the wrong CBOR type — a mempool verb this time, for a
     * second reactor's coverage. */
    w3_frame_begin(&enc, "w_cmt_txs");
    cbor_encode_map(&enc, 1);
    cbor_encode_cstr(&enc, "m"); cbor_encode_uint(&enc, 7);
    if (w3_frame_end(&enc, &out) == 0) {
        TEST_FAIL(name, "m as uint accepted"); return;
    }

    TEST_PASS(name);
}

/* ── Test: the two class ceilings, at the boundary on both sides ──── */

/* `m` exactly at the class max is ACCEPTED through the real encode/verify
 * path (D-16 rev 5's own numbers, not a guess); one byte above is REFUSED
 * by pass 2 (dec_w_cmt_args), proven with a HAND-BUILT frame so the
 * assertion is about the DECODER's own cap, never merely that the
 * encoder happens to refuse the same input first (enc_args's cap is the
 * SAME macro, so testing only the encoder would not distinguish the two
 * — a hostile peer does not go through nodus_t3_encode). */
static void one_cmt_ceiling(nodus_t3_msg_type_t type, size_t m_cap,
                            const char *label) {
    char name[64];
    snprintf(name, sizeof(name), "cmt_ceiling_%s", label);

    {
        nodus_t3_msg_t in, out;
        uint8_t *keep = NULL;
        uint8_t *payload = (uint8_t *)malloc(m_cap);
        if (!payload) { TEST_FAIL(name, "alloc payload"); return; }
        memset(payload, 0x42, m_cap);

        memset(&in, 0, sizeof(in));
        in.type = type;
        fill_header(&in.header);
        in.w_cmt.m     = payload;
        in.w_cmt.m_len = m_cap;

        if (cmt_roundtrip(&in, &out, NULL, &keep) != 0) {
            free(payload);
            TEST_FAIL(name, "at-ceiling m REFUSED"); return;
        }
        if (out.w_cmt.m_len != m_cap) {
            free(keep); free(payload);
            TEST_FAIL(name, "at-ceiling m_len mismatch"); return;
        }
        free(keep);
        free(payload);
    }

    {
        const char *method = nodus_t3_type_to_method(type);
        /* NODUS_T3_CMT_ENVELOPE_OVERHEAD (8192), not a smaller hand-picked
         * slack: the wsig alone is QGP_DSA87_SIGNATURE_BYTES == 4627 B,
         * plus its bstr header, plus the {t,y,q,wh} fields
         * w3_frame_begin_buf writes ahead of "a" — comfortably over the
         * 4096 this test used to give itself, which is EXACTLY what made
         * the case below vacuous (see the CONTROL immediately after). */
        size_t      cap    = m_cap + (size_t)NODUS_T3_CMT_ENVELOPE_OVERHEAD;
        uint8_t    *frame  = (uint8_t *)malloc(cap);
        uint8_t    *over   = (uint8_t *)malloc(m_cap + 1u);
        cbor_encoder_t enc;
        nodus_t3_msg_t out;
        int rc;

        if (!frame || !over) {
            free(frame); free(over);
            TEST_FAIL(name, "alloc oversize"); return;
        }
        memset(over, 0x42, m_cap + 1u);

        /* CONTROL: `m` at EXACTLY m_cap, through the SAME hand-built
         * frame this test uses for the oversize case, must be ACCEPTED —
         * this proves `cap` actually holds the frame, so a refusal below
         * is dec_w_cmt_args's pass-2 cap (nodus_tier3.c:2547), never the
         * encoder overflowing first. Without this control the REFUTED
         * defect recurs by construction: shrink `cap` and w3_frame_end
         * returns -99 (the builder overflowed, nodus_cbor.c:127-128)
         * before nodus_t3_decode ever runs, and `rc == 0` below stays
         * false for the wrong reason — the m_cap+1 case would "pass" by
         * never exercising the decoder at all. */
        w3_frame_begin_buf(&enc, method, frame, cap);
        cbor_encode_map(&enc, 1);
        cbor_encode_cstr(&enc, "m");
        cbor_encode_bstr(&enc, over, m_cap);
        rc = w3_frame_end(&enc, &out);
        if (rc != 0) {
            free(frame); free(over);
            TEST_FAIL(name, "at-ceiling m through the hand-built frame "
                            "was REFUSED (cap is too small for the builder)");
            return;
        }
        if (out.w_cmt.m_len != m_cap) {
            free(frame); free(over);
            TEST_FAIL(name, "at-ceiling m_len mismatch (hand-built frame)");
            return;
        }

        /* THE CASE UNDER TEST: m_cap+1, same builder, same cap. Must be
         * refused BY THE DECODER — rc must be neither 0 (accepted) nor
         * -99 (the builder overflowed, w3_frame_end's own escape hatch).
         * A -99 here, with the control above green, would mean this
         * specific value of m_cap+1 needs one byte more slack than `cap`
         * gives it — still a builder-sizing defect, not proof of
         * dec_w_cmt_args's cap. */
        w3_frame_begin_buf(&enc, method, frame, cap);
        cbor_encode_map(&enc, 1);
        cbor_encode_cstr(&enc, "m");
        cbor_encode_bstr(&enc, over, m_cap + 1u);
        rc = w3_frame_end(&enc, &out);

        free(frame);
        free(over);
        if (rc == 0) { TEST_FAIL(name, "m_cap+1 accepted"); return; }
        if (rc == -99) {
            TEST_FAIL(name, "m_cap+1 case is VACUOUS: the builder "
                            "overflowed (-99) before the decoder ever ran");
            return;
        }
    }

    TEST_PASS(name);
}

/* ── Test: verify fails under the wrong key ────────────────────────── */

static void test_cmt_verify_wrong_key(void) {
    const char *name = "cmt_verify_wrong_key";
    nodus_t3_msg_t in, out;
    uint8_t *keep = NULL;
    static const uint8_t payload[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    nodus_pubkey_t other_pk;
    nodus_seckey_t other_sk;
    uint8_t seed[32];
    int rc;

    memset(seed, 0x77, sizeof(seed));
    if (qgp_dsa87_keypair_derand(other_pk.bytes, other_sk.bytes, seed) != 0) {
        TEST_FAIL(name, "derand keypair"); return;
    }

    memset(&in, 0, sizeof(in));
    in.type = NODUS_T3_CMT_STATE;
    fill_header(&in.header);
    in.w_cmt.m     = payload;
    in.w_cmt.m_len = sizeof(payload);

    /* `keep`: nodus_t3_verify below runs AFTER the helper returns, and
     * reads out.wsig, which points into the encode buffer for every
     * verb (nodus_tier3.h). */
    if (cmt_roundtrip(&in, &out, NULL, &keep) != 0) {
        TEST_FAIL(name, "roundtrip"); return;
    }
    rc = nodus_t3_verify(&out, &other_pk);
    free(keep);
    if (rc == 0) { TEST_FAIL(name, "verified under the wrong key"); return; }
    TEST_PASS(name);
}

/* ── THE UNIVERSAL PIN (D-22 rev 3) ────────────────────────────────
 *
 * Rev 2 admitted a negative integer in `a` for the two retired signed
 * verbs (28 sst/lcr, 29 vr) only. Rev 3 (W3) makes the admitted set
 * EMPTY: no verb, retired, legacy or new, may carry a negative
 * anywhere in `a`. Pass 1 walks `a` with cbor_decode_skip_signed, which
 * does NOT error on major type 1, then nodus_t3_decode's unconditional
 * gate ("if (a_negint) return -1;") refuses the frame before pass 2
 * ever runs.
 *
 * THE PIN IS REGRESSION INSURANCE ON A SECOND LAYER, NOT A SINGLE
 * FAULT DETECTOR — read the file header's negint-pin paragraph for the
 * full mechanism. Dropping the gate ALONE flips nothing below today:
 * pass 2 resets dec.error and re-walks `a` through the ordinary
 * cbor_decode_next, whose `default:` branch sets dec->error on ANY
 * major-type-1 byte unconditionally (nodus_cbor.c:274-278), so every
 * case here is still refused by pass 2 itself. The gate is what stays
 * load-bearing if cbor_decode_next (or the legacy unknown-key skip
 * idiom) ALSO stopped erroring on a negative — true for cases (i)-(iii)
 * below, whose decoder would then silently accept or ignore
 * the negative; NOT true for (iv)/(v), the cometbft envelope verbs,
 * where dec_w_cmt_args refuses those specific frames for a completely
 * sign-independent reason (see each case's own comment).
 *
 * R3 W4-D (Delta B) — cases (i)-(iii) and their control used to build
 * w_sync_req (verb 12), retired with the closed consensus lane. A
 * retired method string now decodes as "not a verb" regardless of what
 * `a` carries, which would make these cases pass VACUOUSLY (rejected
 * for the wrong reason) rather than exercising the negint gate at all.
 * Rewritten onto w_rost_q (verb 9, LIVE): dec_rost_q_args
 * (nodus_tier3.c) still uses the exact "known key / unknown key -> skip"
 * idiom the retired sync_req decoder had, so the property these three
 * cases guard is unchanged.
 *
 * Each case's CONTROL runs first. If a hand-built frame carrying only
 * ordinary unsigned integers is not accepted, the negative that
 * follows it proves nothing at all. */
static void test_universal_negint_pin(void) {
    const char *name = "universal_negint_pin";
    nodus_t3_msg_t out;
    cbor_encoder_t enc;

    /* CONTROL 1: a live legacy-shaped verb (w_rost_q) with an unsigned
     * `v` — must be ACCEPTED. */
    w3_frame_begin(&enc, "w_rost_q");
    cbor_encode_map(&enc, 1);
    cbor_encode_cstr(&enc, "v"); cbor_encode_uint(&enc, 7);
    if (w3_frame_end(&enc, &out) != 0) {
        TEST_FAIL(name, "the legacy-shaped control frame was REJECTED — "
                        "the negatives below would prove nothing");
        return;
    }
    if (out.type != NODUS_T3_ROST_Q || out.rost_q.version != 7) {
        TEST_FAIL(name, "legacy-shaped control decoded to the wrong fields"); return;
    }

    /* CONTROL 2: verb 35 (w_cmt_state) with a legitimate {m: bstr} —
     * must be ACCEPTED. */
    w3_frame_begin(&enc, "w_cmt_state");
    cbor_encode_map(&enc, 1);
    cbor_encode_cstr(&enc, "m"); cbor_encode_bstr(&enc, w3_filler, 8);
    if (w3_frame_end(&enc, &out) != 0) {
        TEST_FAIL(name, "the cmt control frame was REJECTED"); return;
    }
    if (out.type != NODUS_T3_CMT_STATE || out.w_cmt.m_len != 8) {
        TEST_FAIL(name, "cmt control decoded to the wrong fields"); return;
    }

    /* (i) legacy-shaped verb — a negative under a key its decoder KNOWS. */
    w3_frame_begin(&enc, "w_rost_q");
    cbor_encode_map(&enc, 1);
    cbor_encode_cstr(&enc, "v"); cbor_encode_int(&enc, -7);
    if (w3_frame_end(&enc, &out) == 0) {
        TEST_FAIL(name, "legacy-shaped verb accepted a negative under a "
                        "known key"); return;
    }

    /* (ii) legacy-shaped verb — a negative under a key it does NOT know —
     * the dangerous one, because dec_rost_q_args's own idiom is "unknown
     * key -> skip". */
    w3_frame_begin(&enc, "w_rost_q");
    cbor_encode_map(&enc, 2);
    cbor_encode_cstr(&enc, "v");   cbor_encode_uint(&enc, 7);
    cbor_encode_cstr(&enc, "zzz"); cbor_encode_int(&enc, -1);
    if (w3_frame_end(&enc, &out) == 0) {
        TEST_FAIL(name, "legacy-shaped verb accepted a negative under an "
                        "unknown key"); return;
    }

    /* (iii) legacy-shaped verb — a negative NESTED inside an array under
     * an unknown key — proves the flag propagates through the signed
     * walker's recursion. */
    w3_frame_begin(&enc, "w_rost_q");
    cbor_encode_map(&enc, 2);
    cbor_encode_cstr(&enc, "v");   cbor_encode_uint(&enc, 7);
    cbor_encode_cstr(&enc, "zzz");
    cbor_encode_array(&enc, 2);
    cbor_encode_uint(&enc, 1);
    cbor_encode_int(&enc, -5);
    if (w3_frame_end(&enc, &out) == 0) {
        TEST_FAIL(name, "legacy-shaped verb accepted a negative nested in "
                        "an array"); return;
    }

    /* (iv) verb 35 (w_cmt_state) — a negative under its OWN key "m",
     * wrong type and negative at once. DOES NOT ISOLATE THE GATE: the
     * gate refuses it (a_negint set in pass 1), but so, independently,
     * does dec_w_cmt_args's own `val.type != CBOR_ITEM_BSTR` check —
     * `cbor_decode_next` returns CBOR_ITEM_ERROR for -1 regardless of
     * sign-tolerance, so this frame is refused on a bare TYPE mismatch,
     * with or without the gate. See the file header's negint-pin
     * paragraph. */
    w3_frame_begin(&enc, "w_cmt_state");
    cbor_encode_map(&enc, 1);
    cbor_encode_cstr(&enc, "m"); cbor_encode_int(&enc, -1);
    if (w3_frame_end(&enc, &out) == 0) {
        TEST_FAIL(name, "verb 35 accepted a negative under its own key"); return;
    }

    /* (v) verb 39 (w_cmt_txs), the OTHER reactor's channel — a negative
     * under an unknown key. DOES NOT ISOLATE THE GATE EITHER:
     * dec_w_cmt_args's exact-key-set enforcement refuses ANY key but
     * "m" outright (`else { dec->error = true; return; }`) WITHOUT EVER
     * READING "zzz"'s value — the frame is refused for being the wrong
     * shape, never for what sign that value carries. D-22 rev 3's
     * admitted set is still empty for every verb; this case just does
     * not prove that fact on its own. See the file header's negint-pin
     * paragraph. */
    w3_frame_begin(&enc, "w_cmt_txs");
    cbor_encode_map(&enc, 2);
    cbor_encode_cstr(&enc, "m");   cbor_encode_bstr(&enc, w3_filler, 8);
    cbor_encode_cstr(&enc, "zzz"); cbor_encode_int(&enc, -1);
    if (w3_frame_end(&enc, &out) == 0) {
        TEST_FAIL(name, "verb 39 accepted a negative under an unknown key"); return;
    }

    TEST_PASS(name);
}

/* ── Test: the per-verb ceiling table ────────────────────────────── */

static void test_cmt_max_msg_size(void) {
    const char *name = "cmt_max_msg_size";

    static const struct { nodus_t3_msg_type_t t; size_t want; } tbl[] = {
        { NODUS_T3_CMT_STATE,
          (size_t)NODUS_T3_CMT_CONS_M_MAX + NODUS_T3_CMT_ENVELOPE_OVERHEAD },
        { NODUS_T3_CMT_DATA,
          (size_t)NODUS_T3_CMT_CONS_M_MAX + NODUS_T3_CMT_ENVELOPE_OVERHEAD },
        { NODUS_T3_CMT_VOTE,
          (size_t)NODUS_T3_CMT_CONS_M_MAX + NODUS_T3_CMT_ENVELOPE_OVERHEAD },
        { NODUS_T3_CMT_VOTE_SET_BITS,
          (size_t)NODUS_T3_CMT_CONS_M_MAX + NODUS_T3_CMT_ENVELOPE_OVERHEAD },
        { NODUS_T3_CMT_TXS,
          (size_t)NODUS_T3_CMT_TXS_M_MAX + NODUS_T3_CMT_ENVELOPE_OVERHEAD },
    };
    for (size_t i = 0; i < sizeof(tbl) / sizeof(tbl[0]); i++) {
        if (nodus_t3_max_msg_size(tbl[i].t) != tbl[i].want) {
            TEST_FAIL(name, "class ceiling mismatch"); return;
        }
    }

    /* Retired numbers 26-34: no ceiling to report (extended from 28-34 —
     * R3 W4-D retires 26-27 too). */
    for (int v = 26; v <= 34; v++) {
        if (nodus_t3_max_msg_size((nodus_t3_msg_type_t)v) != 0) {
            TEST_FAIL(name, "a retired verb still has a ceiling"); return;
        }
    }

    /* R3 W4-D — every LIVE verb outside the explicit CMT case list falls
     * into nodus_t3_max_msg_size's `default:` branch and gets the generic
     * bound the legacy path used (NODUS_W_MAX_SYNC_RSP_SIZE), same as
     * before this delta. Rewritten off the deleted verbs (w_propose,
     * w_commit, w_sync_rsp, w_viewok, w_v2_range_rsp — all retired) onto
     * the surviving non-CMT verbs: roster/ident (9-11), the chain_config
     * vote-collect RPC (14-15, register R3-W4-D-8) and the genesis
     * bundle (24-25). */
    static const nodus_t3_msg_type_t non_cmt_live[] = {
        NODUS_T3_ROST_Q, NODUS_T3_ROST_R, NODUS_T3_IDENT,
        NODUS_T3_CC_VOTE_REQ, NODUS_T3_CC_VOTE_RSP,
        NODUS_T3_V2_GBUNDLE_REQ, NODUS_T3_V2_GBUNDLE_RSP
    };
    for (size_t i = 0; i < sizeof(non_cmt_live) / sizeof(non_cmt_live[0]); i++) {
        if (nodus_t3_max_msg_size(non_cmt_live[i]) != (size_t)NODUS_W_MAX_SYNC_RSP_SIZE) {
            TEST_FAIL(name, "non-CMT live verb bound changed"); return;
        }
    }

    /* Not a verb at all → no ceiling to report. */
    if (nodus_t3_max_msg_size((nodus_t3_msg_type_t)0) != 0) {
        TEST_FAIL(name, "non-verb must report 0"); return;
    }

    fprintf(stderr, "    CONS class %u, TXS class %u, overhead %u\n",
            NODUS_T3_CMT_CONS_M_MAX, NODUS_T3_CMT_TXS_M_MAX,
            NODUS_T3_CMT_ENVELOPE_OVERHEAD);

    TEST_PASS(name);
}

/* ── Test: the MEASURED envelope overhead at a maximal message ─────── */

static void test_cmt_envelope_overhead(void) {
    const char *name = "cmt_envelope_overhead";
    const size_t m_cap = (size_t)NODUS_T3_CMT_TXS_M_MAX;
    uint8_t *payload = (uint8_t *)malloc(m_cap);
    nodus_t3_msg_t in, out;
    size_t enc_len = 0;
    uint8_t *keep = NULL;
    size_t overhead;

    if (!payload) { TEST_FAIL(name, "alloc"); return; }
    memset(payload, 0x11, m_cap);

    memset(&in, 0, sizeof(in));
    in.type = NODUS_T3_CMT_TXS;
    fill_header(&in.header);
    in.w_cmt.m     = payload;
    in.w_cmt.m_len = m_cap;

    if (cmt_roundtrip(&in, &out, &enc_len, &keep) != 0) {
        free(payload); TEST_FAIL(name, "roundtrip"); return;
    }
    free(keep);
    free(payload);

    if (enc_len <= m_cap) {
        TEST_FAIL(name, "encoded no larger than its own m"); return;
    }
    overhead = enc_len - m_cap;
    fprintf(stderr, "    TXS: m %zu B, encoded %zu B, overhead %zu B (<= %u)\n",
            m_cap, enc_len, overhead, NODUS_T3_CMT_ENVELOPE_OVERHEAD);
    if (overhead > (size_t)NODUS_T3_CMT_ENVELOPE_OVERHEAD) {
        TEST_FAIL(name, "NODUS_T3_CMT_ENVELOPE_OVERHEAD is not an over-estimate");
        return;
    }
    TEST_PASS(name);
}

/* ── Test: the mempool ceiling pin ─────────────────────────────────
 *
 * NODUS_T3_CMT_TXS_M_MAX (1 048 584) is NOT a compile-time constant on
 * the cmt_memr side — cmt_memr_get_channels computes it at runtime
 * from cmt_mempool_config_t.max_tx_bytes (Message{Txs{[MaxTxBytes]}}
 * .Size()) — so it cannot be _Static_assert'd against its source the
 * way NODUS_T3_CMT_CONS_M_MAX is against CMT_CONR_MAX_MSG_SIZE
 * (nodus_tier3.c). This is the only place the two numbers are tied
 * together: a bare `cmt_memr_t` whose `config` is the library's own
 * DEFAULT, asked for its channel descriptor. */
static void test_cmt_memr_ceiling_pin(void) {
    const char *name = "cmt_memr_ceiling_pin";
    cmt_mempool_config_t cfg;
    cmt_memr_t memr;
    cmt_memr_channel_descriptor_t desc;

    if (cmt_mempool_config_default(&cfg) != CMT_OK) {
        TEST_FAIL(name, "cmt_mempool_config_default"); return;
    }
    memset(&memr, 0, sizeof(memr));
    memr.config = &cfg;

    if (cmt_memr_get_channels(&memr, &desc) != CMT_OK) {
        TEST_FAIL(name, "cmt_memr_get_channels"); return;
    }
    fprintf(stderr, "    memr recv_message_capacity = %zu, want %u\n",
            desc.recv_message_capacity, NODUS_T3_CMT_TXS_M_MAX);
    if (desc.recv_message_capacity != (size_t)NODUS_T3_CMT_TXS_M_MAX) {
        TEST_FAIL(name, "TXS ceiling drifted from cmt_memr_get_channels"); return;
    }
    TEST_PASS(name);
}

/* ── Test: verbs 24/25 (genesis bundle), the R3 W3 32-byte pin flip ────
 *
 * WHAT THIS PROVES. D-24 rev 4 (1): `pin` on both nodus_t3_w_v2_gbundle_q_t
 * and _r_t is 32 bytes, not 64 — the chain id, because a version-3 chain
 * has no genesis BLOCK to pin a 64-byte BlockID to (D-19 rev 6). A
 * correctly-shaped REQUEST and RESPONSE round-trip through the real
 * encoder/decoder with every field surviving exactly; a `p` of the wrong
 * length (31 or 33 bytes) is a HARD DECODE ERROR (dec->error = true),
 * not a silently-zeroed field — the deliberate departure from this
 * file's usual "wrong length leaves the field zero" convention for most
 * fixed bstrs, because the pin is the whole of a joiner's trust decision
 * and an ambiguous decode of it is unacceptable (nodus_tier3.c's "p"
 * branches say so). The RESPONSE's `d` chunk is proven at exactly
 * NODUS_T3_V2_GBUNDLE_CHUNK_MAX (accepted) and one byte over (refused by
 * the DECODER itself, through a hand-built frame using the SAME buffer
 * capacity for both the control and the oversize case — the
 * one_cmt_ceiling discipline this file already uses, so a refusal here
 * cannot be the builder overflowing first).
 *
 * WHAT IT REQUIRES. Nothing beyond a default build; no environment.
 *
 * WHAT IT LEAVES BEHIND. Nothing — every allocation is freed on every
 * path, heap-allocated per this project's fixture rule (a 48 KB+ chunk
 * buffer does not belong on a test's stack).
 *
 * HOW IT CAN LIE. If nodus_t3_verify ever grew a length check for verbs
 * 24/25 that happened to also reject 31/33-byte input for an unrelated
 * reason (e.g. a total-message-size coincidence), the "refused" assertion
 * would pass without the DECODER's own strict-length branch ever running.
 * Guarded against here the same way one_cmt_ceiling guards its own claim:
 * the CONTROL (exactly 32 bytes) is proven ACCEPTED through the identical
 * code path first, so the fixture is known to reach the decoder's "p"
 * branch before the negative cases run against it. */

static void test_v2_gbundle_roundtrip(void) {
    const char *name = "v2_gbundle_roundtrip";
    nodus_t3_msg_t in, out;

    /* REQUEST (verb 24): chain[32], pin[32], offset. */
    memset(&in, 0, sizeof(in));
    in.type = NODUS_T3_V2_GBUNDLE_REQ;
    fill_header(&in.header);
    memset(in.w_v2_gbundle_q.chain, 0x11, 32);
    memset(in.w_v2_gbundle_q.pin,   0x22, 32);
    in.w_v2_gbundle_q.offset = 4096;

    memset(&out, 0, sizeof(out));
    if (roundtrip(&in, &out) != 0) {
        TEST_FAIL(name, "w_v2_gbundle_q round trip REFUSED"); return;
    }
    if (memcmp(out.w_v2_gbundle_q.chain, in.w_v2_gbundle_q.chain, 32) != 0 ||
        memcmp(out.w_v2_gbundle_q.pin,   in.w_v2_gbundle_q.pin,   32) != 0 ||
        out.w_v2_gbundle_q.offset != in.w_v2_gbundle_q.offset) {
        TEST_FAIL(name, "w_v2_gbundle_q field mismatch"); return;
    }

    /* RESPONSE (verb 25): chain[32], pin[32], total, offset, chunk. */
    size_t chunk_len = 4096;
    uint8_t *chunk = malloc(chunk_len);
    if (!chunk) { TEST_FAIL(name, "alloc chunk"); return; }
    for (size_t i = 0; i < chunk_len; i++) chunk[i] = (uint8_t)(i & 0xFF);

    memset(&in, 0, sizeof(in));
    in.type = NODUS_T3_V2_GBUNDLE_RSP;
    fill_header(&in.header);
    memset(in.w_v2_gbundle_r.chain, 0x33, 32);
    memset(in.w_v2_gbundle_r.pin,   0x44, 32);
    in.w_v2_gbundle_r.total     = 90000;
    in.w_v2_gbundle_r.offset    = 4096;
    in.w_v2_gbundle_r.chunk     = chunk;
    in.w_v2_gbundle_r.chunk_len = (uint32_t)chunk_len;

    memset(&out, 0, sizeof(out));
    if (roundtrip(&in, &out) != 0) {
        free(chunk);
        TEST_FAIL(name, "w_v2_gbundle_r round trip REFUSED"); return;
    }
    if (memcmp(out.w_v2_gbundle_r.chain, in.w_v2_gbundle_r.chain, 32) != 0 ||
        memcmp(out.w_v2_gbundle_r.pin,   in.w_v2_gbundle_r.pin,   32) != 0 ||
        out.w_v2_gbundle_r.total  != in.w_v2_gbundle_r.total ||
        out.w_v2_gbundle_r.offset != in.w_v2_gbundle_r.offset ||
        out.w_v2_gbundle_r.chunk_len != (uint32_t)chunk_len ||
        memcmp(out.w_v2_gbundle_r.chunk, chunk, chunk_len) != 0) {
        free(chunk);
        TEST_FAIL(name, "w_v2_gbundle_r field mismatch"); return;
    }
    free(chunk);

    TEST_PASS(name);
}

/* A `p` of exactly `plen` bytes in a hand-built verb-24 frame; 0 decoded
 * ok / -1 refused. `method`/`extra_keys` let the same builder serve both
 * the REQUEST (3 keys: c, p, o) and RESPONSE (5 keys: c, p, t, o, d)
 * shapes without duplicating the frame plumbing. */
static int gbundle_pin_len_probe(const char *method, int is_rsp,
                                 size_t plen, nodus_t3_msg_t *out) {
    cbor_encoder_t enc;
    uint8_t pinbuf[64];
    memset(pinbuf, 0x55, sizeof(pinbuf));

    w3_frame_begin(&enc, method);
    cbor_encode_map(&enc, is_rsp ? 5 : 3);
    cbor_encode_cstr(&enc, "c"); cbor_encode_bstr(&enc, w3_filler, 32);
    cbor_encode_cstr(&enc, "p"); cbor_encode_bstr(&enc, pinbuf, plen);
    if (is_rsp) {
        cbor_encode_cstr(&enc, "t"); cbor_encode_uint(&enc, 100);
        cbor_encode_cstr(&enc, "o"); cbor_encode_uint(&enc, 0);
        cbor_encode_cstr(&enc, "d"); cbor_encode_bstr(&enc, w3_filler, 8);
    } else {
        cbor_encode_cstr(&enc, "o"); cbor_encode_uint(&enc, 0);
    }
    return w3_frame_end(&enc, out);
}

static void test_v2_gbundle_pin_length(void) {
    const char *name = "v2_gbundle_pin_length";
    nodus_t3_msg_t out;

    /* CONTROL: exactly 32 bytes, both verbs — must be ACCEPTED, or the
     * refusals below prove nothing. */
    if (gbundle_pin_len_probe("w_v2_gbundle_q", 0, 32, &out) != 0) {
        TEST_FAIL(name, "control REQUEST (32-byte p) was REFUSED"); return;
    }
    {
        /* 0x55, the probe's fill byte — confirms the pin actually decoded
         * rather than the check passing on a zeroed field. */
        uint8_t want[32];
        memset(want, 0x55, sizeof(want));
        if (memcmp(out.w_v2_gbundle_q.pin, want, sizeof(want)) != 0) {
            TEST_FAIL(name, "control REQUEST pin bytes not as encoded");
            return;
        }
    }
    if (gbundle_pin_len_probe("w_v2_gbundle_r", 1, 32, &out) != 0) {
        TEST_FAIL(name, "control RESPONSE (32-byte p) was REFUSED"); return;
    }

    /* 31 and 33 bytes, both verbs — HARD REFUSED (dec->error), not a
     * zero-filled pin. */
    if (gbundle_pin_len_probe("w_v2_gbundle_q", 0, 31, &out) == 0) {
        TEST_FAIL(name, "REQUEST with a 31-byte p was ACCEPTED"); return;
    }
    if (gbundle_pin_len_probe("w_v2_gbundle_q", 0, 33, &out) == 0) {
        TEST_FAIL(name, "REQUEST with a 33-byte p was ACCEPTED"); return;
    }
    if (gbundle_pin_len_probe("w_v2_gbundle_r", 1, 31, &out) == 0) {
        TEST_FAIL(name, "RESPONSE with a 31-byte p was ACCEPTED"); return;
    }
    if (gbundle_pin_len_probe("w_v2_gbundle_r", 1, 33, &out) == 0) {
        TEST_FAIL(name, "RESPONSE with a 33-byte p was ACCEPTED"); return;
    }

    TEST_PASS(name);
}

/* The RESPONSE's `d` chunk at exactly NODUS_T3_V2_GBUNDLE_CHUNK_MAX
 * (ACCEPTED) and one byte over (REFUSED by the decoder itself) — the
 * one_cmt_ceiling discipline: both cases use the SAME hand-built-frame
 * buffer capacity, so the oversize refusal cannot be the builder
 * overflowing first. */
static void test_v2_gbundle_chunk_ceiling(void) {
    const char *name = "v2_gbundle_chunk_ceiling";
    /* NODUS_T3_CMT_ENVELOPE_OVERHEAD (8192), not a smaller hand-picked
     * slack — the one_cmt_ceiling discipline (see its comment above):
     * the wsig alone is QGP_DSA87_SIGNATURE_BYTES == 4627 B, plus its
     * bstr header, plus the {t,y,q,wh} fields w3_frame_begin_buf writes
     * ahead of "a", plus this function's own c/p/t/o fields ahead of
     * "d" — comfortably over a hand-picked 4096, which is exactly what
     * made the +1 case below vacuous before this fix (see the CONTROL
     * immediately after). */
    size_t cap = (size_t)NODUS_T3_V2_GBUNDLE_CHUNK_MAX +
                 (size_t)NODUS_T3_CMT_ENVELOPE_OVERHEAD;
    uint8_t *frame = malloc(cap);
    uint8_t *data  = malloc((size_t)NODUS_T3_V2_GBUNDLE_CHUNK_MAX + 1u);
    if (!frame || !data) {
        free(frame); free(data);
        TEST_FAIL(name, "alloc"); return;
    }
    memset(data, 0x66, (size_t)NODUS_T3_V2_GBUNDLE_CHUNK_MAX + 1u);

    /* CONTROL: exactly CHUNK_MAX, through the SAME cap the oversize case
     * below uses — must be ACCEPTED. */
    {
        cbor_encoder_t enc;
        nodus_t3_msg_t out;
        w3_frame_begin_buf(&enc, "w_v2_gbundle_r", frame, cap);
        cbor_encode_map(&enc, 5);
        cbor_encode_cstr(&enc, "c"); cbor_encode_bstr(&enc, w3_filler, 32);
        cbor_encode_cstr(&enc, "p"); cbor_encode_bstr(&enc, w3_filler, 32);
        cbor_encode_cstr(&enc, "t"); cbor_encode_uint(&enc, 999);
        cbor_encode_cstr(&enc, "o"); cbor_encode_uint(&enc, 0);
        cbor_encode_cstr(&enc, "d");
        cbor_encode_bstr(&enc, data, (size_t)NODUS_T3_V2_GBUNDLE_CHUNK_MAX);
        if (w3_frame_end(&enc, &out) != 0) {
            free(frame); free(data);
            TEST_FAIL(name, "at-ceiling chunk (through the hand-built "
                            "frame) was REFUSED — cap too small for the "
                            "builder, not a decoder claim"); return;
        }
        if (out.w_v2_gbundle_r.chunk_len !=
            (uint32_t)NODUS_T3_V2_GBUNDLE_CHUNK_MAX) {
            free(frame); free(data);
            TEST_FAIL(name, "at-ceiling chunk_len mismatch"); return;
        }
    }

    /* CHUNK_MAX + 1, the SAME cap — must be refused BY THE DECODER: rc
     * must be neither 0 (accepted) nor -99 (w3_frame_end's own "the
     * builder overflowed" escape hatch, nodus_cbor.c:127-128). A -99
     * here, with the control above green, would mean this specific
     * value of CHUNK_MAX+1 needs one byte more slack than `cap` gives
     * it — still a builder-sizing defect in THIS test, not proof of
     * dec_w_v2_gbundle_r_args's cap. */
    {
        cbor_encoder_t enc;
        nodus_t3_msg_t out;
        int rc;
        w3_frame_begin_buf(&enc, "w_v2_gbundle_r", frame, cap);
        cbor_encode_map(&enc, 5);
        cbor_encode_cstr(&enc, "c"); cbor_encode_bstr(&enc, w3_filler, 32);
        cbor_encode_cstr(&enc, "p"); cbor_encode_bstr(&enc, w3_filler, 32);
        cbor_encode_cstr(&enc, "t"); cbor_encode_uint(&enc, 999);
        cbor_encode_cstr(&enc, "o"); cbor_encode_uint(&enc, 0);
        cbor_encode_cstr(&enc, "d");
        cbor_encode_bstr(&enc, data,
                         (size_t)NODUS_T3_V2_GBUNDLE_CHUNK_MAX + 1u);
        rc = w3_frame_end(&enc, &out);
        if (rc == 0) {
            free(frame); free(data);
            TEST_FAIL(name, "CHUNK_MAX+1 was ACCEPTED"); return;
        }
        if (rc == -99) {
            free(frame); free(data);
            TEST_FAIL(name, "CHUNK_MAX+1 case is VACUOUS: the builder "
                            "overflowed (-99) before the decoder ever ran");
            return;
        }
    }

    free(frame);
    free(data);
    TEST_PASS(name);
}

/* ── Main ────────────────────────────────────────────────────────── */

int main(void) {
    fprintf(stderr, "=== Tier 3 Protocol Tests ===\n");

    init_test_data();

    test_method_type_mapping();
    test_rost_q();
    test_rost_r();
    test_ident();
    test_verify_wrong_key();

    /* cometbft envelope — verbs 35-39 (D-16 rev 5, W3). */
    fprintf(stderr, "--- cometbft envelope (verbs 35-39) ---\n");
    test_cmt_method_table();
    test_cmt_roundtrip();
    test_cmt_strict_key_set();
    one_cmt_ceiling(NODUS_T3_CMT_STATE, (size_t)NODUS_T3_CMT_CONS_M_MAX, "cons");
    one_cmt_ceiling(NODUS_T3_CMT_TXS,   (size_t)NODUS_T3_CMT_TXS_M_MAX,  "txs");
    test_cmt_verify_wrong_key();
    test_universal_negint_pin();
    test_cmt_max_msg_size();
    test_cmt_envelope_overhead();
    test_cmt_memr_ceiling_pin();

    /* genesis bundle verbs 24/25 — the R3 W3 32-byte pin flip (D-24 rev 4). */
    fprintf(stderr, "--- genesis bundle (verbs 24/25, D-24 rev 4) ---\n");
    test_v2_gbundle_roundtrip();
    test_v2_gbundle_pin_length();
    test_v2_gbundle_chunk_ceiling();

    fprintf(stderr, "\n%d test(s) failed\n", failures);
    return failures > 0 ? 1 : 0;
}
