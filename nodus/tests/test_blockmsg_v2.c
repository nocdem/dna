/**
 * @file nodus/tests/test_blockmsg_v2.c
 * @brief O15B — canonical BlockMessage v1 codec.
 *
 * The codec is the outermost thing a hostile peer touches, so the tests
 * that matter are the negative ones. Its whole job is to turn arbitrary
 * bytes into either a bounded structural view or a specific refusal, while
 * allocating nothing and computing no consensus value.
 *
 * Sections:
 *   1  round trip and byte-exact offsets
 *   2  truncation at EVERY field boundary
 *   3  trailing bytes
 *   4  version dispatch (msg + body)
 *   5  length fields: zero, over-cap, and overflowed
 *   6  the claim/pool carriage rejection
 *   7  canonical-form equality
 *   8  deterministic decoder fuzz
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dnac/blockmsg_v2.h"

static int checks;
#define CHECK(c, msg)                                                     \
    do {                                                                  \
        if (!(c)) {                                                       \
            printf("CHECK failed at %s:%d: %s\n", __FILE__, __LINE__,      \
                   msg);                                                  \
            exit(1);                                                      \
        }                                                                 \
        checks++;                                                         \
    } while (0)

static uint8_t g_header[DNA_BH2_ENC_SIZE];
static uint8_t g_qc[64];
static uint8_t g_env0[100];
static uint8_t g_env1[7];

static void fixtures(void) {
    for (size_t i = 0; i < sizeof(g_header); i++) g_header[i] = (uint8_t)(i & 0xff);
    g_header[0] = 3;
    for (size_t i = 0; i < sizeof(g_qc); i++)   g_qc[i]   = (uint8_t)(0xA0 + (i & 0x0f));
    for (size_t i = 0; i < sizeof(g_env0); i++) g_env0[i] = (uint8_t)(i * 3u);
    for (size_t i = 0; i < sizeof(g_env1); i++) g_env1[i] = (uint8_t)(0xE0 + i);
}

/* A message with `nenv` envelopes (0, 1 or 2). */
static void build(dnac_blkmsg_v2_t *m, uint32_t nenv) {
    memset(m, 0, sizeof(*m));
    m->msg_version  = DNA_BLKW_VERSION;
    m->body_version = DNA_BLKW_BODY_VERSION;
    m->header       = g_header;
    m->qc           = g_qc;
    m->qc_len       = (uint32_t)sizeof(g_qc);
    m->timestamp    = 0x0102030405060708ULL;
    memset(m->proposer_id, 0x5c, sizeof(m->proposer_id));
    if (nenv >= 1) { m->env[0].bytes = g_env0; m->env[0].len = sizeof(g_env0); }
    if (nenv >= 2) { m->env[1].bytes = g_env1; m->env[1].len = sizeof(g_env1); }
    m->env_count = nenv;
}

static size_t enc(const dnac_blkmsg_v2_t *m, uint8_t *buf, size_t cap) {
    size_t n = 0;
    if (dnac_blkmsg_v2_encode(m, buf, cap, &n) != DNAC_BLKW_OK) return 0;
    return n;
}

static uint32_t rd32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  | (uint32_t)p[3];
}

int main(void) {
    printf("=== O15B — canonical BlockMessage v1 codec ===\n");
    fixtures();

    static uint8_t buf[65536];

    /* ── 1. ROUND TRIP AND BYTE-EXACT OFFSETS ─────────────────────────
     * Offsets are asserted against hand-computed literals, not against
     * the encoder's own arithmetic — otherwise the test would only prove
     * the encoder agrees with itself. */
    {
        dnac_blkmsg_v2_t m;
        build(&m, 2);
        size_t n = enc(&m, buf, sizeof(buf));
        CHECK(n > 0, "encode succeeds");

        /* prefix(6) + header(413) + 4 + qc(64) + 4
         *   + [4 + 100] + [4 + 7] + 4 + 4 + 32 + 8 */
        size_t want = 6 + 413 + 4 + 64 + 4 + (4 + 100) + (4 + 7) + 4 + 4 + 32 + 8;
        CHECK(n == want, "encoded length matches the hand-computed layout");
        CHECK(dnac_blkmsg_v2_encoded_len(&m) == n,
              "encoded_len agrees with encode");

        CHECK(buf[0] == DNA_BLKW_VERSION,      "off 0  = msg_version");
        CHECK(buf[1] == DNA_BLKW_BODY_VERSION, "off 1  = body_version");
        CHECK(rd32(buf + 2) == (uint32_t)DNA_BH2_ENC_SIZE,
              "off 2  = header_len");
        CHECK(memcmp(buf + 6, g_header, DNA_BH2_ENC_SIZE) == 0,
              "off 6  = header bytes");
        CHECK(rd32(buf + 6 + 413) == (uint32_t)sizeof(g_qc),
              "off 419 = qc_len");
        CHECK(memcmp(buf + 423, g_qc, sizeof(g_qc)) == 0,
              "off 423 = qc bytes");
        CHECK(rd32(buf + 423 + 64) == 2u, "env_count follows the QC");

        dnac_blkmsg_v2_t d;
        CHECK(dnac_blkmsg_v2_decode(buf, n, &d) == DNAC_BLKW_OK, "decode OK");
        CHECK(d.msg_version == DNA_BLKW_VERSION, "msg_version round-trips");
        CHECK(d.qc_len == sizeof(g_qc), "qc_len round-trips");
        CHECK(memcmp(d.qc, g_qc, sizeof(g_qc)) == 0, "qc round-trips");
        CHECK(memcmp(d.header, g_header, DNA_BH2_ENC_SIZE) == 0,
              "header round-trips");
        CHECK(d.env_count == 2, "env_count round-trips");
        CHECK(d.env[0].len == sizeof(g_env0) &&
              memcmp(d.env[0].bytes, g_env0, sizeof(g_env0)) == 0,
              "envelope 0 round-trips");
        CHECK(d.env[1].len == sizeof(g_env1) &&
              memcmp(d.env[1].bytes, g_env1, sizeof(g_env1)) == 0,
              "envelope 1 round-trips");
        CHECK(d.timestamp == 0x0102030405060708ULL, "timestamp round-trips");
        CHECK(d.proposer_id[0] == 0x5c && d.proposer_id[31] == 0x5c,
              "proposer_id round-trips");
        CHECK(d.consumed == n, "consumed equals the input length");

        /* Zero envelopes is a legitimate block, not a degenerate one. */
        dnac_blkmsg_v2_t z;
        build(&z, 0);
        size_t zn = enc(&z, buf, sizeof(buf));
        CHECK(zn > 0, "a zero-envelope block encodes");
        CHECK(dnac_blkmsg_v2_decode(buf, zn, &d) == DNAC_BLKW_OK &&
              d.env_count == 0, "and decodes with no envelopes");
    }

    /* ── 2. TRUNCATION AT EVERY BOUNDARY ──────────────────────────────
     * Every prefix of a valid message must be rejected — none may decode
     * into a usable view, and `*out` must be left zeroed. */
    {
        dnac_blkmsg_v2_t m;
        build(&m, 2);
        size_t n = enc(&m, buf, sizeof(buf));
        CHECK(n > 0, "encode succeeds");

        int all_rejected = 1, all_zeroed = 1;
        for (size_t cut = 0; cut < n; cut++) {
            dnac_blkmsg_v2_t d;
            memset(&d, 0xAA, sizeof(d));
            dnac_blkmsg_status_t st = dnac_blkmsg_v2_decode(buf, cut, &d);
            if (st == DNAC_BLKW_OK) { all_rejected = 0; break; }
            if (d.header || d.qc || d.env_count || d.consumed) all_zeroed = 0;
        }
        CHECK(all_rejected, "EVERY truncation of a valid message is rejected");
        CHECK(all_zeroed,
              "a rejected decode leaves the output fully zeroed");

        /* THE SAME SWEEP, ON EXACTLY-SIZED HEAP BUFFERS.
         *
         * The loop above hands the decoder a pointer into a 64 KiB static
         * buffer, so a decoder that read past the claimed length would
         * still be reading VALID memory — no sanitizer could see it, and
         * the §17 mutation campaign proved the point: deleting the prefix
         * bounds check survived both the test AND ASan, because the reads
         * landed in slack.
         *
         * A real receive buffer is not slack-padded. Copying each prefix
         * into an exact-size allocation makes any over-read a genuine
         * heap-buffer-overflow that ASan reports, which is what turns this
         * from "the decoder returned an error" into "the decoder did not
         * touch memory it was not given". */
        for (size_t cut = 0; cut < n; cut++) {
            uint8_t *exact = malloc(cut ? cut : 1);
            CHECK(exact != NULL, "exact-size buffer allocated");
            if (cut) memcpy(exact, buf, cut);
            dnac_blkmsg_v2_t d;
            dnac_blkmsg_status_t st = dnac_blkmsg_v2_decode(exact, cut, &d);
            if (st == DNAC_BLKW_OK) all_rejected = 0;
            free(exact);
        }
        CHECK(all_rejected,
              "every truncation is rejected WITHOUT reading past the buffer "
              "it was given (run under ASan, this is the real assertion)");
    }

    /* ── 3. TRAILING BYTES ────────────────────────────────────────────
     * The single rule that stops one block having many encodings. */
    {
        dnac_blkmsg_v2_t m;
        build(&m, 1);
        size_t n = enc(&m, buf, sizeof(buf) - 4);
        CHECK(n > 0, "encode succeeds");
        buf[n] = 0x00;
        dnac_blkmsg_v2_t d;
        CHECK(dnac_blkmsg_v2_decode(buf, n + 1, &d) == DNAC_BLKW_ERR_TRAILING,
              "ONE trailing zero byte is a reject");
        buf[n] = 0xff;
        CHECK(dnac_blkmsg_v2_decode(buf, n + 1, &d) == DNAC_BLKW_ERR_TRAILING,
              "one trailing non-zero byte is a reject");
    }

    /* ── 4. VERSION DISPATCH ──────────────────────────────────────────
     * Version is read BEFORE any length is believed, and an unknown
     * version is never reinterpreted under this layout. */
    {
        dnac_blkmsg_v2_t m;
        build(&m, 1);
        size_t n = enc(&m, buf, sizeof(buf));
        dnac_blkmsg_v2_t d;

        uint8_t save = buf[0];
        buf[0] = 0;
        CHECK(dnac_blkmsg_v2_decode(buf, n, &d) == DNAC_BLKW_ERR_VERSION,
              "msg_version 0 is INVALID");
        buf[0] = (uint8_t)(DNA_BLKW_VERSION + 1u);
        CHECK(dnac_blkmsg_v2_decode(buf, n, &d) == DNAC_BLKW_ERR_VERSION,
              "an unknown msg_version fails closed");
        buf[0] = 0xff;
        CHECK(dnac_blkmsg_v2_decode(buf, n, &d) == DNAC_BLKW_ERR_VERSION,
              "0xff msg_version fails closed");
        buf[0] = save;

        save = buf[1];
        buf[1] = 0;
        CHECK(dnac_blkmsg_v2_decode(buf, n, &d) == DNAC_BLKW_ERR_BODY_VERSION,
              "body_version 0 is INVALID");
        buf[1] = (uint8_t)(DNA_BLKW_BODY_VERSION + 7u);
        CHECK(dnac_blkmsg_v2_decode(buf, n, &d) == DNAC_BLKW_ERR_BODY_VERSION,
              "an unknown body_version fails closed, AS ITS OWN CLASS");
        buf[1] = save;
    }

    /* ── 5. LENGTH FIELDS ─────────────────────────────────────────────
     * Each is bounded BEFORE it is used to advance, so a hostile length
     * can neither over-read nor wrap. */
    {
        dnac_blkmsg_v2_t m;
        build(&m, 1);
        size_t n = enc(&m, buf, sizeof(buf));
        dnac_blkmsg_v2_t d;

        /* header_len is fixed; anything else rejects on length alone. */
        buf[2] = 0; buf[3] = 0; buf[4] = 0x01; buf[5] = 0x5c;   /* 348 */
        CHECK(dnac_blkmsg_v2_decode(buf, n, &d) == DNAC_BLKW_ERR_HEADER_LEN,
              "a v2-sized header length is rejected on length alone");
        buf[2] = 0xff; buf[3] = 0xff; buf[4] = 0xff; buf[5] = 0xff;
        CHECK(dnac_blkmsg_v2_decode(buf, n, &d) == DNAC_BLKW_ERR_HEADER_LEN,
              "an enormous header_len is rejected BEFORE it is used");
        n = enc(&m, buf, sizeof(buf));   /* restore */

        /* qc_len: 0 is malformed, not "no certificate". */
        buf[419] = 0; buf[420] = 0; buf[421] = 0; buf[422] = 0;
        CHECK(dnac_blkmsg_v2_decode(buf, n, &d) == DNAC_BLKW_ERR_QC_LEN,
              "a zero-length QC is MALFORMED — a block travels with its "
              "certificate or not at all");
        buf[419] = 0xff; buf[420] = 0xff; buf[421] = 0xff; buf[422] = 0xff;
        CHECK(dnac_blkmsg_v2_decode(buf, n, &d) == DNAC_BLKW_ERR_QC_LEN,
              "an over-cap qc_len is rejected before it is used to advance");
        n = enc(&m, buf, sizeof(buf));

        /* env_count over the wire cap. */
        size_t ec_off = 6 + 413 + 4 + sizeof(g_qc);
        buf[ec_off] = 0; buf[ec_off+1] = 0; buf[ec_off+2] = 0;
        buf[ec_off+3] = (uint8_t)(DNA_BLKW_MAX_ENVS + 1u);
        CHECK(dnac_blkmsg_v2_decode(buf, n, &d) == DNAC_BLKW_ERR_ENV_COUNT,
              "env_count over the cap is rejected");
        buf[ec_off] = 0xff; buf[ec_off+1] = 0xff;
        buf[ec_off+2] = 0xff; buf[ec_off+3] = 0xff;
        CHECK(dnac_blkmsg_v2_decode(buf, n, &d) == DNAC_BLKW_ERR_ENV_COUNT,
              "an enormous env_count cannot drive an allocation");
        n = enc(&m, buf, sizeof(buf));

        /* env_len: 0 and over-cap. */
        size_t el_off = ec_off + 4;
        buf[el_off] = 0; buf[el_off+1] = 0; buf[el_off+2] = 0; buf[el_off+3] = 0;
        CHECK(dnac_blkmsg_v2_decode(buf, n, &d) == DNAC_BLKW_ERR_ENV_LEN,
              "a zero-length envelope is rejected — it would give one block "
              "two encodings");
        buf[el_off] = 0xff; buf[el_off+1] = 0xff;
        buf[el_off+2] = 0xff; buf[el_off+3] = 0xff;
        CHECK(dnac_blkmsg_v2_decode(buf, n, &d) == DNAC_BLKW_ERR_ENV_LEN,
              "an env_len of 0xffffffff is rejected, NOT wrapped");
        n = enc(&m, buf, sizeof(buf));
        CHECK(n > 0, "restored");
    }

    /* ── 6. CLAIM / POOL CARRIAGE ─────────────────────────────────────
     * Declared and required to be zero. A block carrying claims must not
     * be readable as a block that carries none. */
    {
        dnac_blkmsg_v2_t m;
        build(&m, 1);
        size_t n = enc(&m, buf, sizeof(buf));
        dnac_blkmsg_v2_t d;

        size_t cc_off = n - (4 + 4 + 32 + 8);
        buf[cc_off + 3] = 1;                       /* claim_count = 1 */
        CHECK(dnac_blkmsg_v2_decode(buf, n, &d) == DNAC_BLKW_ERR_UNSUPPORTED,
              "a non-zero claim_count is REFUSED, never silently dropped");
        buf[cc_off + 3] = 0;
        buf[cc_off + 7] = 1;                       /* pool_count = 1 */
        CHECK(dnac_blkmsg_v2_decode(buf, n, &d) == DNAC_BLKW_ERR_UNSUPPORTED,
              "a non-zero pool_batch_count is REFUSED");
        buf[cc_off + 7] = 0;
        CHECK(dnac_blkmsg_v2_decode(buf, n, &d) == DNAC_BLKW_OK,
              "and the restored message decodes again");
    }

    /* ── 7. CANONICAL FORM ────────────────────────────────────────────
     * Decoding alone does not prove one-encoding-per-block; the property
     * is checked. */
    {
        dnac_blkmsg_v2_t m;
        build(&m, 2);
        size_t n = enc(&m, buf, sizeof(buf));
        CHECK(dnac_blkmsg_v2_reencode_equals(buf, n) == 1,
              "an encoder-produced message IS canonical");
        buf[n] = 0x01;
        CHECK(dnac_blkmsg_v2_reencode_equals(buf, n + 1) == 0,
              "a message with trailing bytes is NOT canonical");
        CHECK(dnac_blkmsg_v2_reencode_equals(buf, 0) == 0,
              "empty input is not canonical");
        CHECK(dnac_blkmsg_v2_reencode_equals(NULL, 10) == 0,
              "NULL input is not canonical");
    }

    /* ── 8. DETERMINISTIC DECODER FUZZ ────────────────────────────────
     * A seeded xorshift so a failure is reproducible — a random seed
     * would make a red run unrepeatable, which is the flakiness this
     * project forbids. The property is not "decodes" but "never crashes,
     * never over-reads, and anything it accepts re-encodes to itself". */
    {
        uint64_t s = 0x9E3779B97F4A7C15ULL;
        dnac_blkmsg_v2_t base;
        build(&base, 2);
        size_t n = enc(&base, buf, sizeof(buf));
        CHECK(n > 0, "fuzz base encodes");

        static uint8_t mut[65536];
        int accepted = 0;
        for (int iter = 0; iter < 20000; iter++) {
            s ^= s << 13; s ^= s >> 7; s ^= s << 17;
            memcpy(mut, buf, n);
            size_t len = n;
            /* Either flip a byte, or truncate, or extend. */
            switch (s % 3u) {
            case 0: mut[s % len] ^= (uint8_t)(1u << ((s >> 8) % 8u)); break;
            case 1: len = (size_t)(s % (uint64_t)n);                  break;
            default:
                len = n + 1;
                if (len <= sizeof(mut)) mut[n] = (uint8_t)(s >> 16);
                else len = n;
                break;
            }
            dnac_blkmsg_v2_t d;
            if (dnac_blkmsg_v2_decode(mut, len, &d) == DNAC_BLKW_OK) {
                accepted++;
                /* Anything accepted must be exactly canonical — a
                 * tolerated variant would be a second encoding. */
                CHECK(dnac_blkmsg_v2_reencode_equals(mut, len) == 1,
                      "every accepted fuzz mutant is canonical");
                CHECK(d.consumed == len, "consumed == len for accepted input");
            }
        }
        printf("  fuzz: 20000 mutants, %d accepted (all canonical)\n",
               accepted);
        checks++;
    }

    /* ── 9. ARGUMENT HANDLING ─────────────────────────────────────────── */
    {
        dnac_blkmsg_v2_t d;
        CHECK(dnac_blkmsg_v2_decode(NULL, 10, &d) == DNAC_BLKW_ERR_ARG,
              "NULL source is ERR_ARG");
        CHECK(dnac_blkmsg_v2_decode(buf, 10, NULL) == DNAC_BLKW_ERR_ARG,
              "NULL output is ERR_ARG");
        CHECK(dnac_blkmsg_v2_encoded_len(NULL) == 0, "NULL length is 0");
        size_t out = 0;
        dnac_blkmsg_v2_t m;
        build(&m, 1);
        CHECK(dnac_blkmsg_v2_encode(&m, buf, 4, &out) == DNAC_BLKW_ERR_ARG,
              "a too-small destination is refused, never overrun");
        CHECK(out == 0, "and writes nothing");
        CHECK(strcmp(dnac_blkmsg_v2_status_name(DNAC_BLKW_ERR_TRAILING),
                     "ERR_TRAILING") == 0, "status names are stable");
    }

    printf("test_blockmsg_v2: ALL %d checks passed\n", checks);
    return 0;
}
