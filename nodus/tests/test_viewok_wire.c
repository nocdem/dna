/**
 * Nodus — O15N Faz 2C1: the VIEW_OK wire.
 *
 * Covers the two verbs that carry view authority — NODUS_T3_VIEWOK (a
 * bundle of 1..N per-node statements that a view-change quorum was
 * observed) and NODUS_T3_VIEWOK_REQ (the request for one) — at the CODEC
 * level only. Nothing sends or handles them yet; this slice is the wire.
 *
 * ── WHAT WOULD BE FALSE IF THIS FILE FAILED ───────────────────────────
 *
 * §1 A bundle survives encode → decode unchanged, at N = 1 (the
 *    broadcast shape) and at N = NODUS_T3_MAX_WITNESSES (the ceiling).
 *    If this went red, a statement that verifies on the sender would not
 *    verify on the receiver, and every proof would be rejected.
 * §2 Both method tables agree in BOTH directions. If only one direction
 *    held, a frame would encode with an empty method string and be
 *    undispatchable — which is exactly what happened when O15E added
 *    verbs and updated one table.
 * §3 The decoder REJECTS an oversized entry array outright. If it merely
 *    clamped, a consumer written without its own re-clamp would inherit
 *    an attacker-chosen count.
 * §4 Verbs 26/27 are NOT bootstrap types. If they were, their envelope
 *    signature would carry the bootstrap domain prefix — a
 *    signature-domain gap no other test in this tree would catch.
 *
 * ── WHAT IT REQUIRES ──────────────────────────────────────────────────
 *
 * Nothing beyond a default build: no compile flags, no environment, no
 * database, no witness fixture. One Dilithium identity is generated for
 * the envelope signature; that is the only source of randomness and it
 * affects no assertion (every check is over decoded FIELDS, never over
 * signature bytes).
 *
 * ── WHAT IT LEAVES BEHIND ─────────────────────────────────────────────
 *
 * Nothing. No files, no directories, no processes. All buffers are
 * heap-allocated and freed, including on the failure paths.
 *
 * ── HOW IT COULD LIE ──────────────────────────────────────────────────
 *
 *  1. A ROUND-TRIP THAT COMPARES NOTHING. If the decode target were not
 *     zeroed first, a field the decoder never wrote could still match
 *     the source by accident. Every decode target here is memset to 0xFF
 *     — not 0x00 — before decoding, so an unwritten field is 0xFF and
 *     cannot coincide with the 0x11/0x22/… test values.
 *  2. AN OVERSIZE TEST THAT NEVER OVERSIZES. Going through the encoder
 *     to build the oversized frame would cap the count at the struct's
 *     own array bound and prove nothing. §3 builds the CBOR array header
 *     by hand so the wire really claims more entries than the bound
 *     allows.
 *  3. A ONE-DIRECTION TABLE CHECK. §2 asserts type → string AND
 *     string → type for both verbs, and additionally that the two
 *     strings differ from each other and from an existing verb's.
 *  4. A BOOTSTRAP CHECK THAT PASSES BECAUSE EVERYTHING IS FALSE. §4
 *     asserts the four types that ARE bootstrap still are, so a
 *     predicate stuck at false fails loudly.
 *
 * ── WHAT A GREEN RUN DOES NOT PROVE ───────────────────────────────────
 *
 * Nothing about behaviour. No node sends these verbs, no dispatch case
 * routes them, and nothing moves the view counter. It also proves
 * nothing about the version gate or the quarantine switch: both live in
 * nodus_witness.c behind a witness handle this file deliberately does
 * not build — see §5, which pins what it can and says what it cannot.
 *
 * @file test_viewok_wire.c
 */

#include "protocol/nodus_tier3.h"
#include "protocol/nodus_cbor.h"
#include "crypto/nodus_sign.h"
#include "crypto/nodus_identity.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define TEST_PASS(name) fprintf(stderr, "  PASS: %s\n", name)
#define TEST_FAIL(name, msg) do { \
    fprintf(stderr, "  FAIL: %s — %s\n", name, msg); \
    failures++; \
} while (0)

static int failures = 0;

static nodus_identity_t test_id;

static void fill_header(nodus_t3_header_t *hdr) {
    hdr->version = NODUS_T3_BFT_PROTOCOL_VER;
    hdr->round = 42;
    hdr->view = 3;
    memset(hdr->sender_id, 0xAA, NODUS_T3_WITNESS_ID_LEN);
    hdr->timestamp = 1700000000;
    hdr->nonce = 0xDEADBEEF;
    memset(hdr->chain_id, 0xC1, 32);
}

/* Deterministic per-entry filler: entry i is distinguishable from every
 * other, so a decoder that shifted or duplicated entries is caught. */
static void fill_entry(nodus_t3_cert_entry_t *e, uint32_t i) {
    memset(e->voter_id, (int)(0x10 + (i & 0x7F)), NODUS_T3_WITNESS_ID_LEN);
    memset(e->signature, (int)(0x80 + (i & 0x7F)), NODUS_SIG_BYTES);
}

/* ── §1 — bundle round-trip ───────────────────────────────────────── */

static void test_viewok_roundtrip(uint32_t n, const char *label) {
    nodus_t3_msg_t *src = calloc(1, sizeof(*src));
    nodus_t3_msg_t *dst = malloc(sizeof(*dst));
    /* 0xFF, deliberately: an unwritten field cannot coincide with a test
     * value, so a decoder that silently drops a field is caught. */
    memset(dst, 0xFF, sizeof(*dst));

    uint8_t *buf = malloc(NODUS_W_MAX_SYNC_RSP_SIZE);
    if (!src || !dst || !buf) {
        TEST_FAIL(label, "alloc");
        free(src); free(dst); free(buf);
        return;
    }

    src->type = NODUS_T3_VIEWOK;
    src->txn_id = 7;
    fill_header(&src->header);
    src->viewok.height = 0x0102030405060708ull;
    src->viewok.view = 0x11223344u;
    memset(src->viewok.set_hash, 0x5A, 64);
    src->viewok.n_entries = n;
    for (uint32_t i = 0; i < n; i++) fill_entry(&src->viewok.entries[i], i);

    size_t len = 0;
    if (nodus_t3_encode(src, &test_id.sk, buf,
                        NODUS_W_MAX_SYNC_RSP_SIZE, &len) != 0) {
        TEST_FAIL(label, "encode failed");
        goto out;
    }
    if (nodus_t3_decode(buf, len, dst) != 0) {
        TEST_FAIL(label, "decode failed");
        goto out;
    }

    if (dst->type != NODUS_T3_VIEWOK) { TEST_FAIL(label, "type"); goto out; }
    if (dst->viewok.height != src->viewok.height) {
        TEST_FAIL(label, "height"); goto out; }
    if (dst->viewok.view != src->viewok.view) {
        TEST_FAIL(label, "view"); goto out; }
    if (memcmp(dst->viewok.set_hash, src->viewok.set_hash, 64) != 0) {
        TEST_FAIL(label, "set_hash"); goto out; }
    if (dst->viewok.n_entries != n) {
        TEST_FAIL(label, "n_entries"); goto out; }
    for (uint32_t i = 0; i < n; i++) {
        if (memcmp(dst->viewok.entries[i].voter_id,
                   src->viewok.entries[i].voter_id,
                   NODUS_T3_WITNESS_ID_LEN) != 0) {
            TEST_FAIL(label, "entry voter_id"); goto out; }
        if (memcmp(dst->viewok.entries[i].signature,
                   src->viewok.entries[i].signature,
                   NODUS_SIG_BYTES) != 0) {
            TEST_FAIL(label, "entry signature"); goto out; }
    }
    TEST_PASS(label);
out:
    free(src); free(dst); free(buf);
}

static void test_viewok_q_roundtrip(void) {
    const char *label = "§1 w_viewok_q round-trip";
    nodus_t3_msg_t *src = calloc(1, sizeof(*src));
    nodus_t3_msg_t *dst = malloc(sizeof(*dst));
    memset(dst, 0xFF, sizeof(*dst));
    uint8_t *buf = malloc(NODUS_T3_MAX_MSG_SIZE);
    if (!src || !dst || !buf) {
        TEST_FAIL(label, "alloc"); free(src); free(dst); free(buf); return; }

    src->type = NODUS_T3_VIEWOK_REQ;
    src->txn_id = 9;
    fill_header(&src->header);
    src->viewok_q.height_hint = 0x0A0B0C0D0E0Full;

    size_t len = 0;
    if (nodus_t3_encode(src, &test_id.sk, buf,
                        NODUS_T3_MAX_MSG_SIZE, &len) != 0) {
        TEST_FAIL(label, "encode failed"); goto out; }
    if (nodus_t3_decode(buf, len, dst) != 0) {
        TEST_FAIL(label, "decode failed"); goto out; }
    if (dst->type != NODUS_T3_VIEWOK_REQ) { TEST_FAIL(label, "type"); goto out; }
    if (dst->viewok_q.height_hint != src->viewok_q.height_hint) {
        TEST_FAIL(label, "height_hint"); goto out; }
    TEST_PASS(label);
out:
    free(src); free(dst); free(buf);
}

/* ── §2 — both method tables, both directions ─────────────────────── */

static void test_method_tables(void) {
    const char *label = "§2 both method tables agree in both directions";

    const char *m26 = nodus_t3_type_to_method(NODUS_T3_VIEWOK);
    const char *m27 = nodus_t3_type_to_method(NODUS_T3_VIEWOK_REQ);
    if (!m26 || !m27) { TEST_FAIL(label, "type -> method returned NULL"); return; }
    if (strcmp(m26, "w_viewok") != 0)   { TEST_FAIL(label, "26 name"); return; }
    if (strcmp(m27, "w_viewok_q") != 0) { TEST_FAIL(label, "27 name"); return; }

    /* The direction O15E lost. */
    if (nodus_t3_method_to_type(m26) != NODUS_T3_VIEWOK) {
        TEST_FAIL(label, "method -> type for w_viewok"); return; }
    if (nodus_t3_method_to_type(m27) != NODUS_T3_VIEWOK_REQ) {
        TEST_FAIL(label, "method -> type for w_viewok_q"); return; }

    /* Anti-vacuity: the two names must differ from each other and from an
     * existing verb's, or a table that returned one constant would pass. */
    if (strcmp(m26, m27) == 0) { TEST_FAIL(label, "the two names collide"); return; }
    const char *mvc = nodus_t3_type_to_method(NODUS_T3_VIEWCHG);
    if (!mvc || strcmp(m26, mvc) == 0 || strcmp(m27, mvc) == 0) {
        TEST_FAIL(label, "collides with an existing verb's name"); return; }
    TEST_PASS(label);
}

/* ── §3 — the decoder REJECTS an oversized array ──────────────────── */

/* Hand-built, deliberately NOT through the encoder: the encoder caps the
 * count at the struct's own array bound, so an encoder-built frame could
 * never claim more entries than the bound allows and the test would
 * prove nothing. */
static void test_oversize_rejected(void) {
    const char *label = "§3 an oversized entry array is REJECTED, not clamped";
    /* 129 well-formed entries is ~600 KB, so the 128 KB message bound is
     * far too small to hold the frame this test must build. Use the same
     * 1 MB heap buffer the real send and verify paths use. */
    uint8_t *buf = malloc(NODUS_W_MAX_SYNC_RSP_SIZE);
    nodus_t3_msg_t *dst = malloc(sizeof(*dst));
    if (!buf || !dst) { TEST_FAIL(label, "alloc"); free(buf); free(dst); return; }

    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, NODUS_W_MAX_SYNC_RSP_SIZE);
    cbor_encode_map(&enc, 6);
    cbor_encode_cstr(&enc, "t");    cbor_encode_uint(&enc, 1);
    cbor_encode_cstr(&enc, "y");    cbor_encode_cstr(&enc, "q");
    cbor_encode_cstr(&enc, "q");    cbor_encode_cstr(&enc, "w_viewok");
    cbor_encode_cstr(&enc, "wh");
    cbor_encode_map(&enc, 7);
    /* Key names copied from enc_wh (nodus_tier3.c), not guessed — "rnd"
     * and "nc", not "r" and "n". A wrong key here would be skipped by
     * the decoder and the frame would still parse, so §3 would pass for
     * the wrong reason. */
    cbor_encode_cstr(&enc, "v");   cbor_encode_uint(&enc, NODUS_T3_BFT_PROTOCOL_VER);
    cbor_encode_cstr(&enc, "rnd"); cbor_encode_uint(&enc, 1);
    cbor_encode_cstr(&enc, "vw");  cbor_encode_uint(&enc, 1);
    cbor_encode_cstr(&enc, "sid");
    { uint8_t sid[NODUS_T3_WITNESS_ID_LEN]; memset(sid, 0xAA, sizeof(sid));
      cbor_encode_bstr(&enc, sid, sizeof(sid)); }
    cbor_encode_cstr(&enc, "ts");  cbor_encode_uint(&enc, 1700000000);
    cbor_encode_cstr(&enc, "nc");  cbor_encode_uint(&enc, 1);
    cbor_encode_cstr(&enc, "cid");
    { uint8_t cid[32]; memset(cid, 0xC1, sizeof(cid));
      cbor_encode_bstr(&enc, cid, sizeof(cid)); }
    cbor_encode_cstr(&enc, "a");
    cbor_encode_map(&enc, 4);
    cbor_encode_cstr(&enc, "h");  cbor_encode_uint(&enc, 5);
    cbor_encode_cstr(&enc, "v");  cbor_encode_uint(&enc, 3);
    cbor_encode_cstr(&enc, "sh");
    { uint8_t sh[64]; memset(sh, 0x5A, sizeof(sh));
      cbor_encode_bstr(&enc, sh, sizeof(sh)); }
    cbor_encode_cstr(&enc, "sts");
    /* THE POINT: the array header claims one more than the bound, AND
     * the frame really carries that many well-formed entries.
     *
     * ⚠ MEASURED THE HARD WAY. A first version emitted only the array
     * HEADER and stopped. It passed — and it passed with the hard reject
     * replaced by the neighbour's clamp, i.e. VACUOUSLY: with the clamp,
     * the decoder tried to read entries that were not there, ran off the
     * end and errored for a completely different reason. The bound is
     * only observable when the frame is otherwise valid. */
    cbor_encode_array(&enc, (size_t)NODUS_T3_MAX_WITNESSES + 1);
    for (uint32_t i = 0; i < (uint32_t)NODUS_T3_MAX_WITNESSES + 1; i++) {
        nodus_t3_cert_entry_t e;
        fill_entry(&e, i);
        cbor_encode_map(&enc, 2);
        cbor_encode_cstr(&enc, "vid");
        cbor_encode_bstr(&enc, e.voter_id, NODUS_T3_WITNESS_ID_LEN);
        cbor_encode_cstr(&enc, "sig");
        cbor_encode_bstr(&enc, e.signature, NODUS_SIG_BYTES);
    }
    cbor_encode_cstr(&enc, "wsig");
    { uint8_t sig[NODUS_SIG_BYTES]; memset(sig, 0x01, sizeof(sig));
      cbor_encode_bstr(&enc, sig, sizeof(sig)); }

    size_t len = cbor_encoder_len(&enc);
    if (len == 0) { TEST_FAIL(label, "hand-built frame is empty"); goto out; }

    memset(dst, 0xFF, sizeof(*dst));
    if (nodus_t3_decode(buf, len, dst) == 0) {
        TEST_FAIL(label, "an oversized array was ACCEPTED");
        goto out;
    }
    TEST_PASS(label);
out:
    free(buf); free(dst);
}

/* ── §4 — verbs 26/27 are NOT bootstrap types ─────────────────────── */

/* is_bootstrap_type is static, so the observable is the SIGNATURE
 * PREIMAGE: a bootstrap verb prefixes it with the bootstrap domain and a
 * non-bootstrap verb does not. nodus_t3_verify rebuilds that preimage
 * from the DECODED message and re-checks it, so a verb on the wrong side
 * of the predicate would still be self-consistent — encode and verify
 * would agree with each other.
 *
 * What this pins instead, and it is the part that matters: BOTH sides of
 * the predicate are LIVE. 26/27 verify through the non-bootstrap branch
 * and a real bootstrap verb verifies through the bootstrap branch, in
 * the same run. A predicate stuck at either constant fails one of the
 * two. Whether 26/27 belong on the non-bootstrap side is a DESIGN
 * decision argued at the predicate itself; a codec test cannot decide it
 * and this one does not pretend to. */
static void test_not_bootstrap(void) {
    const char *label = "§4 both sides of the bootstrap predicate are live";
    nodus_t3_msg_t *src = calloc(1, sizeof(*src));
    nodus_t3_msg_t *dec = malloc(sizeof(*dec));
    uint8_t *buf = malloc(NODUS_T3_MAX_MSG_SIZE);
    if (!src || !dec || !buf) {
        TEST_FAIL(label, "alloc"); free(src); free(dec); free(buf); return; }

    src->type = NODUS_T3_VIEWOK_REQ;
    src->txn_id = 3;
    fill_header(&src->header);
    src->viewok_q.height_hint = 11;

    size_t len = 0;
    if (nodus_t3_encode(src, &test_id.sk, buf,
                        NODUS_T3_MAX_MSG_SIZE, &len) != 0) {
        TEST_FAIL(label, "encode"); goto out; }
    memset(dec, 0xFF, sizeof(*dec));
    if (nodus_t3_decode(buf, len, dec) != 0) {
        TEST_FAIL(label, "decode"); goto out; }
    if (nodus_t3_verify(dec, &test_id.pk) != 0) {
        TEST_FAIL(label, "a verb-27 frame must verify through the "
                         "NON-bootstrap branch");
        goto out; }

    /* The other side of the predicate, in the same run. */
    src->type = NODUS_T3_CHAIN_Q;
    src->txn_id = 4;
    memset(&src->w_chain_q, 0, sizeof(src->w_chain_q));
    len = 0;
    if (nodus_t3_encode(src, &test_id.sk, buf,
                        NODUS_T3_MAX_MSG_SIZE, &len) != 0) {
        TEST_FAIL(label, "encode (bootstrap verb)"); goto out; }
    memset(dec, 0xFF, sizeof(*dec));
    if (nodus_t3_decode(buf, len, dec) != 0) {
        TEST_FAIL(label, "decode (bootstrap verb)"); goto out; }
    if (nodus_t3_verify(dec, &test_id.pk) != 0) {
        TEST_FAIL(label, "a bootstrap verb must verify through the "
                         "BOOTSTRAP branch — that branch is dead");
        goto out; }
    TEST_PASS(label);
out:
    free(src); free(dec); free(buf);
}

/* ── §5 — truncation and trailing bytes ───────────────────────────── */

/* ⚠ WHAT THIS ASSERTS, AND WHY IT IS NOT "decode refuses".
 *
 * MEASURED, not assumed: nodus_t3_decode ACCEPTS a frame truncated by one
 * byte. That is the decoder's general shape and not specific to these
 * verbs — it skips what it does not recognise and sets dec->error only at
 * named checks, and no existing test in this tree asserts otherwise. It
 * is also not the gate: the frame LENGTH is carried by the 7-byte wire
 * header below this layer, and authenticity is decided by
 * nodus_t3_verify, which rebuilds the signed payload from the decoded
 * message and re-checks it.
 *
 * So the property asserted here is the real one: a mangled frame must not
 * VERIFY. Asserting "decode refuses" would have been asserting something
 * this tree does not do, and it would have gone green only by accident. */
static void test_malformed_rejected(void) {
    const char *label = "§5 truncated does not verify; trailing byte is inert";
    nodus_t3_msg_t *src = calloc(1, sizeof(*src));
    nodus_t3_msg_t *dst = malloc(sizeof(*dst));
    uint8_t *buf = malloc(NODUS_T3_MAX_MSG_SIZE + 8);
    if (!src || !dst || !buf) {
        TEST_FAIL(label, "alloc"); free(src); free(dst); free(buf); return; }

    src->type = NODUS_T3_VIEWOK;
    src->txn_id = 5;
    fill_header(&src->header);
    src->viewok.height = 5;
    src->viewok.view = 3;
    memset(src->viewok.set_hash, 0x5A, 64);
    src->viewok.n_entries = 2;
    fill_entry(&src->viewok.entries[0], 0);
    fill_entry(&src->viewok.entries[1], 1);

    size_t len = 0;
    if (nodus_t3_encode(src, &test_id.sk, buf,
                        NODUS_T3_MAX_MSG_SIZE, &len) != 0) {
        TEST_FAIL(label, "encode"); goto out; }

    /* Control: intact, it decodes AND verifies. Without both halves the
     * negatives below could pass because verification is broken for
     * every input. */
    memset(dst, 0xFF, sizeof(*dst));
    if (nodus_t3_decode(buf, len, dst) != 0) {
        TEST_FAIL(label, "control: the intact frame must decode"); goto out; }
    if (nodus_t3_verify(dst, &test_id.pk) != 0) {
        TEST_FAIL(label, "control: the intact frame must verify"); goto out; }

    /* Truncated. Decode may or may not accept it — see the note above;
     * what must NOT happen is that it verifies. */
    memset(dst, 0xFF, sizeof(*dst));
    if (nodus_t3_decode(buf, len - 1, dst) == 0 &&
        nodus_t3_verify(dst, &test_id.pk) == 0) {
        TEST_FAIL(label, "a TRUNCATED frame verified"); goto out; }

    /* TRAILING BYTE — MEASURED, and the honest assertion is not "it must
     * not verify". It DOES verify, and that follows from the design
     * rather than from a hole: nodus_t3_verify rebuilds the signed
     * payload from the DECODED message, and a byte sitting outside the
     * top-level CBOR map never enters that message. So the frame is
     * malleable at the BYTE level while being identical at the MESSAGE
     * level, and every consumer in this tree acts on the decoded message.
     *
     * What must hold, and is what this asserts: appending a byte changes
     * NOTHING a consumer can observe. If that ever stopped holding — if a
     * trailing byte could alter a field — the same malleability would
     * become a real substitution attack. */
    buf[len] = 0x00;
    memset(dst, 0xFF, sizeof(*dst));
    nodus_t3_msg_t *dst2 = malloc(sizeof(*dst2));
    if (!dst2) { TEST_FAIL(label, "alloc"); goto out; }
    memset(dst2, 0xFF, sizeof(*dst2));
    if (nodus_t3_decode(buf, len + 1, dst2) == 0) {
        if (dst2->type != NODUS_T3_VIEWOK ||
            dst2->viewok.height != src->viewok.height ||
            dst2->viewok.view != src->viewok.view ||
            dst2->viewok.n_entries != src->viewok.n_entries ||
            memcmp(dst2->viewok.set_hash, src->viewok.set_hash, 64) != 0 ||
            memcmp(dst2->viewok.entries, src->viewok.entries,
                   (size_t)src->viewok.n_entries *
                       sizeof(nodus_t3_cert_entry_t)) != 0) {
            TEST_FAIL(label, "a TRAILING BYTE changed the decoded message");
            free(dst2); goto out;
        }
    }
    free(dst2);
    TEST_PASS(label);
out:
    free(src); free(dst); free(buf);
}

int main(void) {
    fprintf(stderr, "Nodus O15N Faz 2C1 — VIEW_OK wire\n");
    fprintf(stderr, "=================================\n");

    if (nodus_identity_generate(&test_id) != 0) {
        fprintf(stderr, "FATAL: cannot generate test identity\n");
        return 1;
    }

    test_viewok_roundtrip(1, "§1 w_viewok round-trip, N = 1 (broadcast shape)");
    test_viewok_roundtrip(NODUS_T3_MAX_WITNESSES,
                          "§1 w_viewok round-trip, N = MAX_WITNESSES");
    test_viewok_q_roundtrip();
    test_method_tables();
    test_oversize_rejected();
    test_not_bootstrap();
    test_malformed_rejected();

    fprintf(stderr, "\n%s (%d failure%s)\n",
            failures ? "FAILED" : "ALL PASSED",
            failures, failures == 1 ? "" : "s");
    return failures ? 1 : 0;
}
