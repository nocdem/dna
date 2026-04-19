/**
 * @file shared/dnac/tests/test_cc_wire.c
 * @brief Round-trip + boundary tests for dnac_cc_wire_{encode,decode}.
 *
 * Hard-Fork v1 Stage C (shared refactor). Drift between encoder and
 * decoder is a silent consensus break, so this test pins the wire layout
 * by-bytes against a known-answer vector.
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
    dnac_cc_wire_ext_t f;
    fill_test_fields(&f, 5);
    CHECK(dnac_cc_wire_encoded_size(&f) ==
          DNAC_CC_WIRE_FIXED_LEN + 5u * DNAC_CC_WIRE_PER_VOTE);

    f.committee_sig_count = 7;
    CHECK(dnac_cc_wire_encoded_size(&f) == DNAC_CC_WIRE_MAX_LEN);

    /* Clamp: count > cap treated as cap. */
    f.committee_sig_count = 99;
    CHECK(dnac_cc_wire_encoded_size(&f) == DNAC_CC_WIRE_MAX_LEN);

    CHECK(dnac_cc_wire_encoded_size(NULL) == 0);
}

static void test_encode_decode_roundtrip(void) {
    dnac_cc_wire_ext_t in, out;
    uint8_t buf[DNAC_CC_WIRE_MAX_LEN];
    size_t written = 0, consumed = 0;

    for (uint8_t n = 5; n <= 7; n++) {
        fill_test_fields(&in, n);
        CHECK(dnac_cc_wire_encode(&in, buf, sizeof(buf), &written) == 0);
        CHECK(written == dnac_cc_wire_encoded_size(&in));

        memset(&out, 0xCC, sizeof(out));
        CHECK(dnac_cc_wire_decode(buf, written, &out, &consumed) == 0);
        CHECK(consumed == written);

        CHECK(out.param_id               == in.param_id);
        CHECK(out.new_value              == in.new_value);
        CHECK(out.effective_block_height == in.effective_block_height);
        CHECK(out.proposal_nonce         == in.proposal_nonce);
        CHECK(out.signed_at_block        == in.signed_at_block);
        CHECK(out.valid_before_block     == in.valid_before_block);
        CHECK(out.committee_sig_count    == n);

        for (uint8_t i = 0; i < n; i++) {
            CHECK(memcmp(out.votes[i].witness_id,
                         in.votes[i].witness_id,
                         DNAC_CC_WIRE_WITNESS_ID_SIZE) == 0);
            CHECK(memcmp(out.votes[i].signature,
                         in.votes[i].signature,
                         DNAC_CC_WIRE_SIGNATURE_SIZE) == 0);
        }
        /* Unused slots zeroed by decoder. */
        for (uint8_t i = n; i < DNAC_CC_WIRE_COMMITTEE_SIZE; i++) {
            uint8_t zero_wid[DNAC_CC_WIRE_WITNESS_ID_SIZE] = {0};
            uint8_t zero_sig[DNAC_CC_WIRE_SIGNATURE_SIZE]  = {0};
            CHECK(memcmp(out.votes[i].witness_id, zero_wid,
                         sizeof(zero_wid)) == 0);
            CHECK(memcmp(out.votes[i].signature, zero_sig,
                         sizeof(zero_sig)) == 0);
        }
    }
}

static void test_truncated_input_rejected(void) {
    dnac_cc_wire_ext_t in, out;
    uint8_t buf[DNAC_CC_WIRE_MAX_LEN];
    size_t written = 0, consumed = 0;

    fill_test_fields(&in, 5);
    CHECK(dnac_cc_wire_encode(&in, buf, sizeof(buf), &written) == 0);

    /* Short by one byte at every boundary. */
    CHECK(dnac_cc_wire_decode(buf, DNAC_CC_WIRE_FIXED_LEN - 1,
                              &out, &consumed) == -1);
    CHECK(dnac_cc_wire_decode(buf, written - 1,
                              &out, &consumed) == -1);

    /* count > cap rejected. */
    buf[DNAC_CC_WIRE_FIXED_LEN - 1] = 8;
    CHECK(dnac_cc_wire_decode(buf, written, &out, &consumed) == -1);
}

static void test_short_dst_buffer_rejected(void) {
    dnac_cc_wire_ext_t in;
    uint8_t buf[DNAC_CC_WIRE_MAX_LEN];
    size_t written = 0;

    fill_test_fields(&in, 7);
    CHECK(dnac_cc_wire_encode(&in, buf, DNAC_CC_WIRE_FIXED_LEN,
                               &written) == -1);
    CHECK(dnac_cc_wire_encode(&in, buf, DNAC_CC_WIRE_MAX_LEN - 1,
                               &written) == -1);
    CHECK(dnac_cc_wire_encode(&in, buf, DNAC_CC_WIRE_MAX_LEN,
                               &written) == 0);
}

static void test_null_args(void) {
    dnac_cc_wire_ext_t f;
    uint8_t buf[16];
    size_t sz = 0;
    fill_test_fields(&f, 5);

    CHECK(dnac_cc_wire_encode(NULL, buf, sizeof(buf), &sz) == -1);
    CHECK(dnac_cc_wire_encode(&f,   NULL, sizeof(buf), &sz) == -1);
    CHECK(dnac_cc_wire_encode(&f,   buf, sizeof(buf), NULL) == -1);

    CHECK(dnac_cc_wire_decode(NULL, sizeof(buf), &f, &sz) == -1);
    CHECK(dnac_cc_wire_decode(buf,  sizeof(buf), NULL, &sz) == -1);
    CHECK(dnac_cc_wire_decode(buf,  sizeof(buf), &f, NULL) == -1);
}

static void test_known_answer_header(void) {
    /* Pin the fixed-header byte layout against a hand-computed vector so a
     * drift between encoder and decoder (or an accidental endian flip)
     * fails loudly rather than silently diverging consensus. */
    dnac_cc_wire_ext_t in;
    uint8_t buf[DNAC_CC_WIRE_MAX_LEN];
    size_t written = 0;

    memset(&in, 0, sizeof(in));
    in.param_id               = 0x03;
    in.new_value              = 0x0102030405060708ULL;
    in.effective_block_height = 0x1112131415161718ULL;
    in.proposal_nonce         = 0x2122232425262728ULL;
    in.signed_at_block        = 0x3132333435363738ULL;
    in.valid_before_block     = 0x4142434445464748ULL;
    in.committee_sig_count    = 0;

    CHECK(dnac_cc_wire_encode(&in, buf, sizeof(buf), &written) == 0);
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
}

int main(void) {
    test_size_formula();
    test_encode_decode_roundtrip();
    test_truncated_input_rejected();
    test_short_dst_buffer_rejected();
    test_null_args();
    test_known_answer_header();

    if (failures) {
        fprintf(stderr, "test_cc_wire: %d check(s) failed\n", failures);
        return 1;
    }
    printf("test_cc_wire: all checks passed\n");
    return 0;
}
