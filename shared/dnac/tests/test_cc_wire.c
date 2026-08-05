/**
 * @file shared/dnac/tests/test_cc_wire.c
 * @brief Round-trip + boundary tests for dnac_cc_wire_{encode,decode}.
 *
 * Hard-Fork v1 Stage C (shared refactor). Drift between encoder and
 * decoder is a silent consensus break, so this test pins the wire layout
 * by-bytes against a known-answer vector.
 *
 * Ledger V2 S3: the vote-slot cap moved 7 -> DNA_MAX_ACTIVE_VALIDATORS.
 * That makes dnac_cc_wire_ext_t ~583 KiB and DNAC_CC_WIRE_MAX_LEN ~583 KiB,
 * so every fixture and every scratch buffer in this file is HEAP allocated —
 * the pre-S3 stack locals would blow the stack. The S3 additions are:
 *   - count == MAX_SLOTS (128) accepts and round-trips
 *   - count == MAX_SLOTS + 1 (129) and count == 255 are decode-rejected
 *   - the historical 5-vote shape still encodes to exactly the same bytes
 *     it did pre-S3 (strict-superset claim)
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dnac/chain_config_wire.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures = 0;

#define CHECK(cond) do {                                                \
    if (!(cond)) {                                                       \
        fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);  \
        failures++;                                                      \
    }                                                                    \
} while (0)

/* Every allocation below is checked; a NULL would otherwise crash the whole
 * binary and report as a segfault rather than a test failure. */
#define MUST_ALLOC(p) do {                                               \
    if (!(p)) {                                                          \
        fprintf(stderr, "FATAL %s:%d: allocation failed\n",               \
                __FILE__, __LINE__);                                      \
        exit(2);                                                          \
    }                                                                    \
} while (0)

static dnac_cc_wire_ext_t *ext_new(void) {
    dnac_cc_wire_ext_t *f = calloc(1, sizeof(*f));
    MUST_ALLOC(f);
    return f;
}

static uint8_t *buf_new(void) {
    uint8_t *b = calloc(1, DNAC_CC_WIRE_MAX_LEN);
    MUST_ALLOC(b);
    return b;
}

/* Deterministic filler — vote i's bytes depend only on i, so the same
 * fixture can be rebuilt for an independent byte-level comparison. */
static void fill_test_fields(dnac_cc_wire_ext_t *f, uint8_t n_votes) {
    memset(f, 0, sizeof(*f));
    f->param_id               = 2;      /* BLOCK_INTERVAL_SEC */
    f->new_value              = 7;
    f->effective_block_height = 100000;
    f->proposal_nonce         = 0x1122334455667788ULL;
    f->signed_at_block        = 99500;
    f->valid_before_block     = 100500;
    f->committee_sig_count    = n_votes;
    for (uint8_t i = 0; i < n_votes; i++) {
        for (int j = 0; j < DNAC_CC_WIRE_WITNESS_ID_SIZE; j++)
            f->votes[i].witness_id[j] = (uint8_t)(0xA0 + i + j);
        for (int j = 0; j < DNAC_CC_WIRE_SIGNATURE_SIZE; j++)
            f->votes[i].signature[j] = (uint8_t)((i * 31 + j) & 0xFF);
    }
}

static void test_size_formula(void) {
    dnac_cc_wire_ext_t *f = ext_new();
    fill_test_fields(f, 5);
    CHECK(dnac_cc_wire_encoded_size(f) ==
          DNAC_CC_WIRE_FIXED_LEN + 5u * DNAC_CC_WIRE_PER_VOTE);

    /* The historical committee size is no longer the cap. */
    f->committee_sig_count = 7;
    CHECK(dnac_cc_wire_encoded_size(f) ==
          DNAC_CC_WIRE_FIXED_LEN + 7u * DNAC_CC_WIRE_PER_VOTE);

    f->committee_sig_count = DNAC_CC_WIRE_MAX_SLOTS;
    CHECK(dnac_cc_wire_encoded_size(f) == DNAC_CC_WIRE_MAX_LEN);

    /* Clamp: count > cap treated as cap. */
    f->committee_sig_count = 255;
    CHECK(dnac_cc_wire_encoded_size(f) == DNAC_CC_WIRE_MAX_LEN);

    CHECK(dnac_cc_wire_encoded_size(NULL) == 0);
    free(f);
}

/* Round-trip across the historical band (5..7) AND the S3 boundary
 * (MAX_SLOTS-1, MAX_SLOTS). */
static void roundtrip_one(uint8_t n) {
    dnac_cc_wire_ext_t *in  = ext_new();
    dnac_cc_wire_ext_t *out = ext_new();
    uint8_t *buf = buf_new();
    size_t written = 0, consumed = 0;

    fill_test_fields(in, n);
    CHECK(dnac_cc_wire_encode(in, buf, DNAC_CC_WIRE_MAX_LEN, &written) == 0);
    CHECK(written == dnac_cc_wire_encoded_size(in));

    memset(out, 0xCC, sizeof(*out));
    CHECK(dnac_cc_wire_decode(buf, written, out, &consumed) == 0);
    CHECK(consumed == written);

    CHECK(out->param_id               == in->param_id);
    CHECK(out->new_value              == in->new_value);
    CHECK(out->effective_block_height == in->effective_block_height);
    CHECK(out->proposal_nonce         == in->proposal_nonce);
    CHECK(out->signed_at_block        == in->signed_at_block);
    CHECK(out->valid_before_block     == in->valid_before_block);
    CHECK(out->committee_sig_count    == n);

    for (uint8_t i = 0; i < n; i++) {
        CHECK(memcmp(out->votes[i].witness_id,
                     in->votes[i].witness_id,
                     DNAC_CC_WIRE_WITNESS_ID_SIZE) == 0);
        CHECK(memcmp(out->votes[i].signature,
                     in->votes[i].signature,
                     DNAC_CC_WIRE_SIGNATURE_SIZE) == 0);
    }
    /* Unused slots zeroed by decoder — checked across the FULL slot array,
     * so a decoder that forgot to widen its memset would be caught. */
    for (int i = n; i < DNAC_CC_WIRE_MAX_SLOTS; i++) {
        static const uint8_t zero_wid[DNAC_CC_WIRE_WITNESS_ID_SIZE] = {0};
        static const uint8_t zero_sig[DNAC_CC_WIRE_SIGNATURE_SIZE]  = {0};
        CHECK(memcmp(out->votes[i].witness_id, zero_wid,
                     sizeof(zero_wid)) == 0);
        CHECK(memcmp(out->votes[i].signature, zero_sig,
                     sizeof(zero_sig)) == 0);
    }

    free(buf);
    free(out);
    free(in);
}

static void test_encode_decode_roundtrip(void) {
    for (uint8_t n = 5; n <= 7; n++) roundtrip_one(n);      /* historical band */
    roundtrip_one(8);                                        /* first new count */
    roundtrip_one(DNAC_CC_WIRE_MAX_SLOTS - 1);               /* 127 */
    roundtrip_one(DNAC_CC_WIRE_MAX_SLOTS);                   /* 128 — S3 cap */
}

static void test_truncated_input_rejected(void) {
    dnac_cc_wire_ext_t *in  = ext_new();
    dnac_cc_wire_ext_t *out = ext_new();
    uint8_t *buf = buf_new();
    size_t written = 0, consumed = 0;

    fill_test_fields(in, 5);
    CHECK(dnac_cc_wire_encode(in, buf, DNAC_CC_WIRE_MAX_LEN, &written) == 0);

    /* Short by one byte at every boundary. */
    CHECK(dnac_cc_wire_decode(buf, DNAC_CC_WIRE_FIXED_LEN - 1,
                              out, &consumed) == -1);
    CHECK(dnac_cc_wire_decode(buf, written - 1,
                              out, &consumed) == -1);

    /* A count the buffer cannot back is rejected on LENGTH (not on the cap):
     * 8 is now a legal count, but the 5-vote buffer is too short for it. */
    buf[DNAC_CC_WIRE_FIXED_LEN - 1] = 8;
    CHECK(dnac_cc_wire_decode(buf, written, out, &consumed) == -1);

    free(buf);
    free(out);
    free(in);
}

/* S3: the CAP itself. 128 accepts, 129 and 255 are rejected on the cap
 * check — before any length arithmetic, so even a buffer large enough to
 * hold them cannot get through. */
static void test_slot_cap_enforced(void) {
    dnac_cc_wire_ext_t *in  = ext_new();
    dnac_cc_wire_ext_t *out = ext_new();
    uint8_t *buf = buf_new();
    size_t written = 0, consumed = 0;

    fill_test_fields(in, DNAC_CC_WIRE_MAX_SLOTS);
    CHECK(dnac_cc_wire_encode(in, buf, DNAC_CC_WIRE_MAX_LEN, &written) == 0);
    CHECK(written == DNAC_CC_WIRE_MAX_LEN);
    CHECK(dnac_cc_wire_decode(buf, written, out, &consumed) == 0);

    /* Overwrite the count byte in an otherwise well-formed max-length
     * buffer. The buffer is the largest one the format allows, so the ONLY
     * thing that can reject these is the cap check. */
    buf[DNAC_CC_WIRE_FIXED_LEN - 1] = (uint8_t)(DNAC_CC_WIRE_MAX_SLOTS + 1);
    CHECK(dnac_cc_wire_decode(buf, written, out, &consumed) == -1);

    buf[DNAC_CC_WIRE_FIXED_LEN - 1] = 255;
    CHECK(dnac_cc_wire_decode(buf, written, out, &consumed) == -1);

    /* Restore the legal count: the same bytes decode again, proving the two
     * rejects above were caused by the count byte and nothing else. */
    buf[DNAC_CC_WIRE_FIXED_LEN - 1] = (uint8_t)DNAC_CC_WIRE_MAX_SLOTS;
    CHECK(dnac_cc_wire_decode(buf, written, out, &consumed) == 0);
    CHECK(out->committee_sig_count == DNAC_CC_WIRE_MAX_SLOTS);

    free(buf);
    free(out);
    free(in);
}

static void test_short_dst_buffer_rejected(void) {
    dnac_cc_wire_ext_t *in = ext_new();
    uint8_t *buf = buf_new();
    size_t written = 0;

    fill_test_fields(in, DNAC_CC_WIRE_MAX_SLOTS);
    CHECK(dnac_cc_wire_encode(in, buf, DNAC_CC_WIRE_FIXED_LEN,
                               &written) == -1);
    CHECK(dnac_cc_wire_encode(in, buf, DNAC_CC_WIRE_MAX_LEN - 1,
                               &written) == -1);
    CHECK(dnac_cc_wire_encode(in, buf, DNAC_CC_WIRE_MAX_LEN,
                               &written) == 0);

    free(buf);
    free(in);
}

static void test_null_args(void) {
    dnac_cc_wire_ext_t *f = ext_new();
    uint8_t buf[16];
    size_t sz = 0;
    fill_test_fields(f, 5);

    CHECK(dnac_cc_wire_encode(NULL, buf, sizeof(buf), &sz) == -1);
    CHECK(dnac_cc_wire_encode(f,    NULL, sizeof(buf), &sz) == -1);
    CHECK(dnac_cc_wire_encode(f,    buf, sizeof(buf), NULL) == -1);

    CHECK(dnac_cc_wire_decode(NULL, sizeof(buf), f, &sz) == -1);
    CHECK(dnac_cc_wire_decode(buf,  sizeof(buf), NULL, &sz) == -1);
    CHECK(dnac_cc_wire_decode(buf,  sizeof(buf), f, NULL) == -1);

    free(f);
}

static void test_known_answer_header(void) {
    /* Pin the fixed-header byte layout against a hand-computed vector so a
     * drift between encoder and decoder (or an accidental endian flip)
     * fails loudly rather than silently diverging consensus. */
    dnac_cc_wire_ext_t *in = ext_new();
    uint8_t *buf = buf_new();
    size_t written = 0;

    in->param_id               = 0x03;
    in->new_value              = 0x0102030405060708ULL;
    in->effective_block_height = 0x1112131415161718ULL;
    in->proposal_nonce         = 0x2122232425262728ULL;
    in->signed_at_block        = 0x3132333435363738ULL;
    in->valid_before_block     = 0x4142434445464748ULL;
    in->committee_sig_count    = 0;

    CHECK(dnac_cc_wire_encode(in, buf, DNAC_CC_WIRE_MAX_LEN, &written) == 0);
    CHECK(written == DNAC_CC_WIRE_FIXED_LEN);

    const uint8_t expected[DNAC_CC_WIRE_FIXED_LEN] = {
        0x03,
        0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
        0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,
        0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,
        0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,
        0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,
        0x00
    };
    CHECK(memcmp(buf, expected, DNAC_CC_WIRE_FIXED_LEN) == 0);

    free(buf);
    free(in);
}

/* S3 strict-superset claim: a historical-shape (5-vote) transaction must
 * encode to EXACTLY the bytes the pre-S3 encoder produced.
 *
 * The check is a full-image comparison against an expectation assembled
 * here from first principles — the 42-byte header KAT (same hand-computed
 * vector as test_known_answer_header, with the count byte set to 5) followed
 * by 5 × (witness_id[32] || signature[4627]) laid down at
 * FIXED_LEN + i*PER_VOTE. Nothing in that expectation is read back from the
 * encoder, so it fails if any offset, order or width moved. It is a LAYOUT
 * pin, not a 23 KiB literal: the vote bytes are regenerated by the same
 * deterministic rule the fixture used. */
static void test_historical_shape_byte_identity(void) {
    dnac_cc_wire_ext_t *in = ext_new();
    uint8_t *buf = buf_new();
    uint8_t *expect = buf_new();
    size_t written = 0;

    fill_test_fields(in, 5);
    CHECK(dnac_cc_wire_encode(in, buf, DNAC_CC_WIRE_MAX_LEN, &written) == 0);

    const size_t hist_len = DNAC_CC_WIRE_FIXED_LEN + 5u * DNAC_CC_WIRE_PER_VOTE;
    CHECK(written == hist_len);
    CHECK(hist_len == 23337);   /* 42 + 5*4659 — the pre-S3 wire length */

    /* Header: fixture values, big-endian, in the pre-S3 field order. */
    const uint8_t hdr[DNAC_CC_WIRE_FIXED_LEN] = {
        0x02,                                            /* param_id 2 */
        0,0,0,0,0,0,0,0x07,                              /* new_value 7 */
        0,0,0,0,0,0x01,0x86,0xA0,                        /* effective 100000 */
        0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,         /* nonce */
        0,0,0,0,0,0x01,0x84,0xAC,                        /* signed_at 99500 */
        0,0,0,0,0,0x01,0x88,0x94,                        /* valid_before 100500 */
        0x05                                             /* committee_sig_count */
    };
    memcpy(expect, hdr, DNAC_CC_WIRE_FIXED_LEN);

    for (uint8_t i = 0; i < 5; i++) {
        uint8_t *slot = expect + DNAC_CC_WIRE_FIXED_LEN +
                        (size_t)i * DNAC_CC_WIRE_PER_VOTE;
        for (int j = 0; j < DNAC_CC_WIRE_WITNESS_ID_SIZE; j++)
            slot[j] = (uint8_t)(0xA0 + i + j);
        uint8_t *sig = slot + DNAC_CC_WIRE_WITNESS_ID_SIZE;
        for (int j = 0; j < DNAC_CC_WIRE_SIGNATURE_SIZE; j++)
            sig[j] = (uint8_t)((i * 31 + j) & 0xFF);
    }

    CHECK(memcmp(buf, expect, hist_len) == 0);

    /* Nothing is written past the historical length — the widened slot
     * array must not add trailing padding. buf came from calloc, so any
     * non-zero byte beyond `written` can only have come from the encoder. */
    size_t trailing_nonzero = 0;
    for (size_t i = hist_len; i < DNAC_CC_WIRE_MAX_LEN; i++)
        if (buf[i] != 0) trailing_nonzero++;
    CHECK(trailing_nonzero == 0);

    free(expect);
    free(buf);
    free(in);
}

int main(void) {
    test_size_formula();
    test_encode_decode_roundtrip();
    test_truncated_input_rejected();
    test_slot_cap_enforced();
    test_short_dst_buffer_rejected();
    test_null_args();
    test_known_answer_header();
    test_historical_shape_byte_identity();

    if (failures) {
        fprintf(stderr, "test_cc_wire: %d check(s) failed\n", failures);
        return 1;
    }
    printf("test_cc_wire: all checks passed\n");
    return 0;
}
