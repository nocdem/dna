/**
 * Nodus — cometbft C port (pin v0.38.26), blocksync: the channel-0x40 messages
 * of `shared/dnac/cmt_bsync_msgs.c` (blocksync/msgs.go, errors.go and the
 * generated proto/tendermint/blocksync/types.pb.go).
 *
 * ── WHAT IT PROVES ─────────────────────────────────────────────────────
 * That the five messages are the reference's BYTES and that the decoder
 * accepts and refuses exactly what the generated decoder does. If this
 * file failed, one of these would be false:
 *   · every message encodes to the bytes the generated writers produce,
 *     hand-derived from types.pb.go:439-718 and pinned here as vectors:
 *     StatusRequest `22 00`; BlockRequest{0} `0a 00`; BlockRequest{5}
 *     `0a 02 08 05`; NoBlockResponse{7} `12 02 08 07`;
 *     StatusResponse{h=3,b=1} `2a 04 08 03 10 01`; StatusResponse{h=3,
 *     b=0} `2a 02 08 03` (a zero field is omitted, :570); BlockResponse
 *     without and with an ExtendedCommit (field 1 before field 2 on the
 *     wire, :500-523); BlockRequest{-1} with the 10-byte varint of
 *     `uint64(-1)`;
 *   · `cmt_bsync_msg_size` equals the marshalled length for each;
 *   · each vector decodes back to its message (kind and fields);
 *   · the LAST sum occurrence wins (types.pb.go:1335, :1440);
 *   · inside ONE BlockResponse two field-1 occurrences MERGE into the
 *     concatenation of their payloads (:1071-1076), an empty field 2 is
 *     a present-but-empty ExtendedCommit;
 *   · unknown fields are skipped (:1477-1489); a sum field with the wrong
 *     wire type (:1303), an int64 with the wrong wire type (:905), a
 *     truncated length and a wire type 4 (:1295-1297) are refused;
 *   · an empty Message decodes to NONE and `ValidateMsg` refuses it; a
 *     negative height / base, and base > height, are refused
 *     (msgs.go:29-49); a valid message of each kind passes;
 *   · MaxMsgSize is MaxBlockSizeBytes + 4 + 1 = 104 857 605 (msgs.go:
 *     12-19), and a marshal into a buffer one byte short is refused;
 *   · the SigCount stub (cometbft@v0.38.26 stub.pb.go:561-1102, the view
 *     FilterMsgBytes decodes first, reactor.go:287-297) counts
 *     Block.LastCommit and ExtCommit signatures without reading them,
 *     SUMS them across repeated field-3 / field-1 occurrences (:619,
 *     :705, :914) where the full decoder keeps only the last, skips a
 *     leading non-BlockResponse field, counts one million entries, and
 *     refuses wire type 4, a non-length-delimited field 3 or signature
 *     entry, and a truncated length. Without the merge the "concatenated
 *     Messages" check reads 6, not 11.
 *
 * ── WHAT IT REQUIRES ───────────────────────────────────────────────────
 * COMPILE FLAGS: `CMT_SOFTWARE_VERSION`, which the nodus build defines for
 *   every cmt_* target. A DEFAULT BUILD is enough.
 * ENVIRONMENT: nothing. No network, no files, no clock, no randomness.
 * Safe under `ctest -j`.
 *
 * ── WHAT IT LEAVES BEHIND ──────────────────────────────────────────────
 * Nothing: no files, no processes; every owned merge copy is released.
 *
 * ── HOW IT CAN LIE ─────────────────────────────────────────────────────
 *  1. The vectors are HAND-DERIVED from the generated Go code by the same
 *     author who wrote the encoder (the KAFADAN "circular" caution): no
 *     Go program was run to produce them. What makes them trustworthy is
 *     that each byte is traceable to one line of types.pb.go named in the
 *     comment beside it; a reader can re-derive them in a minute.
 *  2. The Block and ExtendedCommit PAYLOADS here are opaque byte strings:
 *     this file proves the framing, not the Block codec (that is
 *     cmt_pb_store's and test_cmt_block's, and test_cmt_bsync_reactor
 *     sends real blocks through this framing).
 *  3. The oversize rule is a reactor-boundary check; here only the
 *     constant is pinned — test_cmt_bsync_reactor drives the refusal.
 *  4. The SigCount inputs carry `22 02 08 01` per signature, NOT the full
 *     CommitSig upstream's helper marshals (which always writes a
 *     timestamp): the stub never reads an entry's payload (NoSig), so the
 *     count is the same; the real decode of such bytes is not asked here.
 *     "No allocation" is by construction (the function calls no
 *     allocator) — nothing here measures it, unlike Go's AllocsPerRun.
 *
 * @file test_cmt_bsync_msgs.c
 */

#include "dnac/cmt_bsync_msgs.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, (msg)); \
        return 1; \
    } \
} while (0)

static int g_checks = 0;
#define OK() do { g_checks++; } while (0)

/* Encode `m`, compare with `want`, check Size, decode it back. */
static int roundtrip(const cmt_bsync_msg_t *m, const uint8_t *want,
                     size_t want_len, cmt_bsync_msg_t *back)
{
    uint8_t buf[64];
    size_t  n = 0;

    CHECK(cmt_bsync_msg_size(m) == want_len, "Size() matches the vector"); OK();
    CHECK(cmt_bsync_msg_marshal(m, buf, sizeof(buf), &n) == CMT_OK, "marshal"); OK();
    CHECK(n == want_len && memcmp(buf, want, n) == 0, "bytes match the vector"); OK();
    cmt_bsync_msg_init(back);
    CHECK(cmt_bsync_msg_unmarshal(want, want_len, back) == CMT_OK, "unmarshal"); OK();
    CHECK(back->kind == m->kind, "kind survives"); OK();
    return 0;
}

static int t_vectors(void)
{
    cmt_bsync_msg_t m, back;

    /* StatusRequest: :683-697 frames an empty body → tag 0x22, len 0. */
    {
        static const uint8_t v[] = { 0x22, 0x00 };

        cmt_bsync_msg_init(&m);
        m.kind = CMT_BSYNC_MSG_STATUS_REQUEST;
        if (roundtrip(&m, v, sizeof(v), &back) != 0) return 1;
    }
    /* BlockRequest{0}: :444 omits the zero height; :620-634 still frames. */
    {
        static const uint8_t v[] = { 0x0a, 0x00 };

        cmt_bsync_msg_init(&m);
        m.kind = CMT_BSYNC_MSG_BLOCK_REQUEST;
        if (roundtrip(&m, v, sizeof(v), &back) != 0) return 1;
        CHECK(back.height == 0, "height 0"); OK();
    }
    /* BlockRequest{5}: :444-448 `08 05`, framed 0x0a. */
    {
        static const uint8_t v[] = { 0x0a, 0x02, 0x08, 0x05 };

        cmt_bsync_msg_init(&m);
        m.kind   = CMT_BSYNC_MSG_BLOCK_REQUEST;
        m.height = 5;
        if (roundtrip(&m, v, sizeof(v), &back) != 0) return 1;
        CHECK(back.height == 5, "height 5"); OK();
    }
    /* NoBlockResponse{7}: :472-476, framed 0x12 (:653). */
    {
        static const uint8_t v[] = { 0x12, 0x02, 0x08, 0x07 };

        cmt_bsync_msg_init(&m);
        m.kind   = CMT_BSYNC_MSG_NO_BLOCK_RESPONSE;
        m.height = 7;
        if (roundtrip(&m, v, sizeof(v), &back) != 0) return 1;
        CHECK(back.height == 7, "height 7"); OK();
    }
    /* StatusResponse{h=3, b=1}: :565-581 writes base (0x10) then height
     * (0x08) backward → height first on the wire; framed 0x2a (:716). */
    {
        static const uint8_t v[] = { 0x2a, 0x04, 0x08, 0x03, 0x10, 0x01 };

        cmt_bsync_msg_init(&m);
        m.kind   = CMT_BSYNC_MSG_STATUS_RESPONSE;
        m.height = 3;
        m.base   = 1;
        if (roundtrip(&m, v, sizeof(v), &back) != 0) return 1;
        CHECK(back.height == 3 && back.base == 1, "height 3 base 1"); OK();
    }
    /* StatusResponse{h=3, b=0}: base omitted (:570). */
    {
        static const uint8_t v[] = { 0x2a, 0x02, 0x08, 0x03 };

        cmt_bsync_msg_init(&m);
        m.kind   = CMT_BSYNC_MSG_STATUS_RESPONSE;
        m.height = 3;
        if (roundtrip(&m, v, sizeof(v), &back) != 0) return 1;
        CHECK(back.height == 3 && back.base == 0, "base 0 omitted"); OK();
    }
    /* BlockResponse{Block=01 02 03}: :512-523 `0a 03 01 02 03`, framed
     * 0x1a (:674). */
    {
        static const uint8_t blk[] = { 0x01, 0x02, 0x03 };
        static const uint8_t v[] = { 0x1a, 0x05, 0x0a, 0x03, 0x01, 0x02, 0x03 };

        cmt_bsync_msg_init(&m);
        m.kind      = CMT_BSYNC_MSG_BLOCK_RESPONSE;
        m.has_block = true;
        m.block     = blk;
        m.block_len = sizeof(blk);
        if (roundtrip(&m, v, sizeof(v), &back) != 0) return 1;
        CHECK(back.has_block && back.block_len == 3 &&
              memcmp(back.block, blk, 3) == 0 && !back.has_ext_commit,
              "block view, no ext commit"); OK();
        cmt_bsync_msg_release(&back);
    }
    /* BlockResponse{Block, ExtCommit=aa bb}: ext (field 2, 0x12) is
     * written first backward (:500-511) → after the block on the wire. */
    {
        static const uint8_t blk[] = { 0x01, 0x02, 0x03 };
        static const uint8_t ext[] = { 0xaa, 0xbb };
        static const uint8_t v[] = { 0x1a, 0x09, 0x0a, 0x03, 0x01, 0x02, 0x03,
                                     0x12, 0x02, 0xaa, 0xbb };

        cmt_bsync_msg_init(&m);
        m.kind           = CMT_BSYNC_MSG_BLOCK_RESPONSE;
        m.has_block      = true;
        m.block          = blk;
        m.block_len      = sizeof(blk);
        m.has_ext_commit = true;
        m.ext_commit     = ext;
        m.ext_commit_len = sizeof(ext);
        if (roundtrip(&m, v, sizeof(v), &back) != 0) return 1;
        CHECK(back.has_ext_commit && back.ext_commit_len == 2 &&
              memcmp(back.ext_commit, ext, 2) == 0, "ext commit view"); OK();
        cmt_bsync_msg_release(&back);
    }
    /* BlockRequest{-1}: `uint64(-1)` is nine 0xff and a 0x01 (:445). */
    {
        static const uint8_t v[] = { 0x0a, 0x0b, 0x08,
                                     0xff, 0xff, 0xff, 0xff, 0xff,
                                     0xff, 0xff, 0xff, 0xff, 0x01 };

        cmt_bsync_msg_init(&m);
        m.kind   = CMT_BSYNC_MSG_BLOCK_REQUEST;
        m.height = -1;
        if (roundtrip(&m, v, sizeof(v), &back) != 0) return 1;
        CHECK(back.height == -1, "negative height survives decode"); OK();
    }
    return 0;
}

static int t_decoder_rules(void)
{
    cmt_bsync_msg_t m;

    cmt_bsync_msg_init(&m);
    /* last sum occurrence wins (:1440 then :1335) */
    {
        static const uint8_t v[] = { 0x22, 0x00, 0x0a, 0x02, 0x08, 0x05 };

        CHECK(cmt_bsync_msg_unmarshal(v, sizeof(v), &m) == CMT_OK, "decode"); OK();
        CHECK(m.kind == CMT_BSYNC_MSG_BLOCK_REQUEST && m.height == 5,
              "the later BlockRequest replaces the StatusRequest"); OK();
    }
    /* merge inside one BlockResponse (:1071-1076): 01 02 ‖ 03 04 */
    {
        static const uint8_t v[] = { 0x1a, 0x0a,
                                     0x0a, 0x02, 0x01, 0x02,
                                     0x0a, 0x02, 0x03, 0x04,
                                     0x12, 0x00 };
        static const uint8_t want[] = { 0x01, 0x02, 0x03, 0x04 };

        CHECK(cmt_bsync_msg_unmarshal(v, sizeof(v), &m) == CMT_OK, "decode"); OK();
        CHECK(m.kind == CMT_BSYNC_MSG_BLOCK_RESPONSE && m.has_block &&
              m.block_len == 4 && memcmp(m.block, want, 4) == 0,
              "two field-1 occurrences concatenate"); OK();
        CHECK(m.block_owned != NULL, "the merged copy is owned"); OK();
        CHECK(m.has_ext_commit && m.ext_commit_len == 0,
              "an empty field 2 is a present, empty ExtendedCommit"); OK();
        cmt_bsync_msg_release(&m);
        CHECK(m.block_owned == NULL && m.kind == CMT_BSYNC_MSG_NONE,
              "release frees and resets"); OK();
    }
    /* an unknown field (6, varint) is skipped */
    {
        static const uint8_t v[] = { 0x30, 0x01, 0x22, 0x00 };

        CHECK(cmt_bsync_msg_unmarshal(v, sizeof(v), &m) == CMT_OK &&
              m.kind == CMT_BSYNC_MSG_STATUS_REQUEST, "unknown skipped"); OK();
    }
    /* sum field with wire type 0 (:1303) */
    {
        static const uint8_t v[] = { 0x08, 0x01 };

        CHECK(cmt_bsync_msg_unmarshal(v, sizeof(v), &m) == CMT_REJECT,
              "wrong wire type for a sum field"); OK();
        CHECK(m.kind == CMT_BSYNC_MSG_NONE, "left released"); OK();
    }
    /* BlockRequest.height with wire type 2 (:905) */
    {
        static const uint8_t v[] = { 0x0a, 0x02, 0x0a, 0x00 };

        CHECK(cmt_bsync_msg_unmarshal(v, sizeof(v), &m) == CMT_REJECT,
              "wrong wire type for an int64"); OK();
    }
    /* truncated length */
    {
        static const uint8_t v[] = { 0x0a, 0x05, 0x08 };

        CHECK(cmt_bsync_msg_unmarshal(v, sizeof(v), &m) == CMT_REJECT,
              "length past the end"); OK();
    }
    /* wire type 4 (:1295-1297) */
    {
        static const uint8_t v[] = { 0x0c };

        CHECK(cmt_bsync_msg_unmarshal(v, sizeof(v), &m) == CMT_REJECT,
              "end group"); OK();
    }
    /* empty Message → NONE, and ValidateMsg refuses it */
    {
        cmt_bsync_msg_err_t e = CMT_BSYNC_MSG_ERR_NONE;

        CHECK(cmt_bsync_msg_unmarshal(NULL, 0, &m) == CMT_OK &&
              m.kind == CMT_BSYNC_MSG_NONE, "empty decodes to NONE"); OK();
        CHECK(cmt_bsync_validate_msg(&m, &e) == CMT_REJECT &&
              e == CMT_BSYNC_MSG_ERR_NIL_MESSAGE, "NONE refused"); OK();
    }
    return 0;
}

static int t_validate(void)
{
    cmt_bsync_msg_t     m;
    cmt_bsync_msg_err_t e;

    cmt_bsync_msg_init(&m);
    m.kind = CMT_BSYNC_MSG_BLOCK_REQUEST;
    m.height = -1;
    CHECK(cmt_bsync_validate_msg(&m, &e) == CMT_REJECT &&
          e == CMT_BSYNC_MSG_ERR_INVALID_HEIGHT, "msgs.go:29-31"); OK();
    m.height = 0;
    CHECK(cmt_bsync_validate_msg(&m, &e) == CMT_OK, "height 0 is fine"); OK();

    m.kind = CMT_BSYNC_MSG_NO_BLOCK_RESPONSE;
    m.height = -3;
    CHECK(cmt_bsync_validate_msg(&m, &e) == CMT_REJECT &&
          e == CMT_BSYNC_MSG_ERR_INVALID_HEIGHT, "msgs.go:37-39"); OK();

    m.kind = CMT_BSYNC_MSG_STATUS_RESPONSE;
    m.height = 10;
    m.base = -1;
    CHECK(cmt_bsync_validate_msg(&m, &e) == CMT_REJECT &&
          e == CMT_BSYNC_MSG_ERR_INVALID_BASE, "msgs.go:41-43"); OK();
    m.base = 0;
    m.height = -1;
    CHECK(cmt_bsync_validate_msg(&m, &e) == CMT_REJECT &&
          e == CMT_BSYNC_MSG_ERR_INVALID_HEIGHT, "msgs.go:44-46"); OK();
    m.base = 11;
    m.height = 10;
    CHECK(cmt_bsync_validate_msg(&m, &e) == CMT_REJECT &&
          e == CMT_BSYNC_MSG_ERR_INVALID_HEIGHT, "msgs.go:47-49 base > height"); OK();
    m.base = 10;
    CHECK(cmt_bsync_validate_msg(&m, &e) == CMT_OK, "base == height passes"); OK();

    m.kind = CMT_BSYNC_MSG_STATUS_REQUEST;
    CHECK(cmt_bsync_validate_msg(&m, &e) == CMT_OK, "msgs.go:50-51"); OK();
    m.kind = CMT_BSYNC_MSG_BLOCK_RESPONSE;
    CHECK(cmt_bsync_validate_msg(&m, &e) == CMT_OK,
          "msgs.go:32-35 — decoding is the reactor's"); OK();
    return 0;
}

static int t_sizes(void)
{
    cmt_bsync_msg_t m;
    uint8_t         buf[3];
    size_t          n = 0;

    CHECK(CMT_BSYNC_MAX_MSG_SIZE == (size_t)104857605u,
          "MaxMsgSize = 104857600 + 4 + 1 (msgs.go:12-19)"); OK();
    cmt_bsync_msg_init(&m);
    m.kind = CMT_BSYNC_MSG_BLOCK_REQUEST;
    m.height = 5;                                /* 4 bytes on the wire */
    CHECK(cmt_bsync_msg_marshal(&m, buf, sizeof(buf), &n) == CMT_REJECT,
          "a buffer one byte short is refused"); OK();
    return 0;
}

/* ══ the SigCount stub (cometbft@v0.38.26 stub.pb.go, nosig.go) ══════ */

static size_t uv_size(uint64_t v)
{
    size_t n = 1;

    while (v >= 0x80u) {
        v >>= 7;
        n++;
    }
    return n;
}

static size_t put_uv(uint8_t *out, uint64_t v)
{
    size_t n = 0;

    while (v >= 0x80u) {
        out[n++] = (uint8_t)(v | 0x80u);
        v >>= 7;
    }
    out[n++] = (uint8_t)v;
    return n;
}

/* The shape of upstream's `blockResponseBytesWithSigs` (v0.38.26
 * reactor_test.go, pkgA_tests.diff): Message{3: BlockResponse{1:
 * Block{4: Commit{4: sig × commit_sigs}}, 2: ExtendedCommit{4: sig ×
 * ext_sigs}}}. Each signature entry is `22 02 08 01` (field 4, a
 * CommitSig carrying only BlockIdFlag = ABSENT) — its payload is opaque to
 * the stub (NoSig). Heap; the caller frees. */
static uint8_t *br_with_sigs(size_t commit_sigs, size_t ext_sigs, size_t *out_len)
{
    size_t   commit_body = commit_sigs * 4u;
    size_t   ext_body = ext_sigs * 4u;
    size_t   block_body = 1u + uv_size(commit_body) + commit_body;
    size_t   br_body = (1u + uv_size(block_body) + block_body) +
                       (1u + uv_size(ext_body) + ext_body);
    size_t   total = 1u + uv_size(br_body) + br_body;
    uint8_t *b = (uint8_t *)malloc(total);
    size_t   o = 0, i;

    if (b == NULL) {
        return NULL;
    }
    b[o++] = 0x1a;                                  /* Message.block_response */
    o += put_uv(b + o, br_body);
    b[o++] = 0x0a;                                  /* BlockResponse.block    */
    o += put_uv(b + o, block_body);
    b[o++] = 0x22;                                  /* Block.last_commit      */
    o += put_uv(b + o, commit_body);
    for (i = 0; i < commit_sigs; i++) {
        b[o++] = 0x22; b[o++] = 0x02; b[o++] = 0x08; b[o++] = 0x01;
    }
    b[o++] = 0x12;                                  /* BlockResponse.ext_commit */
    o += put_uv(b + o, ext_body);
    for (i = 0; i < ext_sigs; i++) {
        b[o++] = 0x22; b[o++] = 0x02; b[o++] = 0x08; b[o++] = 0x01;
    }
    *out_len = o;
    return b;
}

static int t_sig_count(void)
{
    static const uint8_t req[]     = { 0x0a, 0x02, 0x08, 0x05 };
    static const uint8_t junk[]    = { 0x0c };             /* wire type 4 */
    static const uint8_t br_wt0[]  = { 0x18, 0x01 };       /* field 3, varint */
    static const uint8_t trunc[]   = { 0x1a, 0x05, 0x0a };
    /* Block{4: Commit{field 4 as a VARINT}} — :885 refuses it */
    static const uint8_t sig_wt0[] = { 0x1a, 0x06, 0x0a, 0x04, 0x22, 0x02, 0x20, 0x01 };
    bool     is_br = true;
    size_t   cs = 99, es = 99, n1 = 0, n2 = 0;
    uint8_t *a, *b, *cat;

    CHECK(cmt_bsync_msg_sig_count(NULL, 0, &is_br, &cs, &es) == CMT_OK &&
          !is_br && cs == 0 && es == 0, "empty: not a BlockResponse"); OK();
    CHECK(cmt_bsync_msg_sig_count(req, sizeof(req), &is_br, &cs, &es) == CMT_OK &&
          !is_br, "a BlockRequest is skipped (:626-638)"); OK();

    a = br_with_sigs(3, 2, &n1);
    CHECK(a != NULL, "alloc"); OK();
    CHECK(cmt_bsync_msg_sig_count(a, n1, &is_br, &cs, &es) == CMT_OK &&
          is_br && cs == 3 && es == 2, "3 commit sigs, 2 extended sigs"); OK();
    free(a);

    a = br_with_sigs(10001, 0, &n1);
    CHECK(a != NULL && cmt_bsync_msg_sig_count(a, n1, &is_br, &cs, &es) == CMT_OK &&
          cs == 10001 && es == 0, "MaxVotesCount + 1 counted"); OK();
    free(a);

    /* two whole Messages concatenated: the stub MERGES field 3 (:619)
     * and appends signatures (:914, :999) — the sum is counted */
    a = br_with_sigs(5, 0, &n1);
    b = br_with_sigs(6, 1, &n2);
    cat = (a && b) ? (uint8_t *)malloc(n1 + n2) : NULL;
    CHECK(cat != NULL, "alloc"); OK();
    memcpy(cat, a, n1);
    memcpy(cat + n1, b, n2);
    CHECK(cmt_bsync_msg_sig_count(cat, n1 + n2, &is_br, &cs, &es) == CMT_OK &&
          is_br && cs == 11 && es == 1, "duplicate fields: counts are SUMMED"); OK();
    {
        cmt_bsync_msg_t m;
        bool            last_wins;

        /* ...while the FULL decoder keeps only the last occurrence
         * (types.pb.go:1372-1406): the second Message's Block{4: 6 sigs}
         * = 1 + 1 + 24 = 26 bytes and its 4-byte ExtendedCommit. */
        cmt_bsync_msg_init(&m);
        last_wins = cmt_bsync_msg_unmarshal(cat, n1 + n2, &m) == CMT_OK &&
                    m.kind == CMT_BSYNC_MSG_BLOCK_RESPONSE &&
                    m.block_len == 26u && m.has_ext_commit &&
                    m.ext_commit_len == 4u;
        cmt_bsync_msg_release(&m);
        CHECK(last_wins, "the full decoder: last occurrence wins"); OK();
    }
    free(a);
    free(b);
    free(cat);

    /* a leading empty BlockRequest field, then an oversized response:
     * the stub still counts it */
    a = br_with_sigs(10001, 0, &n1);
    cat = a ? (uint8_t *)malloc(n1 + 2u) : NULL;
    CHECK(cat != NULL, "alloc"); OK();
    cat[0] = 0x0a;
    cat[1] = 0x00;
    memcpy(cat + 2, a, n1);
    CHECK(cmt_bsync_msg_sig_count(cat, n1 + 2u, &is_br, &cs, &es) == CMT_OK &&
          is_br && cs == 10001, "0a 00 prefix: still counted"); OK();
    free(a);
    free(cat);

    /* the TestStubUnmarshalAllocs sizes: one million entries, counted
     * with no allocation (none is made by the function at all) */
    a = br_with_sigs(1000000, 0, &n1);
    CHECK(a != NULL && cmt_bsync_msg_sig_count(a, n1, &is_br, &cs, &es) == CMT_OK &&
          cs == 1000000, "1m commit sigs"); OK();
    free(a);
    a = br_with_sigs(0, 1000000, &n1);
    CHECK(a != NULL && cmt_bsync_msg_sig_count(a, n1, &is_br, &cs, &es) == CMT_OK &&
          es == 1000000, "1m extended sigs"); OK();
    free(a);

    /* refusals — "malformed blocksync message" (reactor.go:290-292) */
    CHECK(cmt_bsync_msg_sig_count(junk, sizeof(junk), &is_br, &cs, &es) == CMT_REJECT,
          "wire type 4 (:583-585)"); OK();
    CHECK(cmt_bsync_msg_sig_count(br_wt0, sizeof(br_wt0), &is_br, &cs, &es) == CMT_REJECT,
          "field 3 not length-delimited (:591-593)"); OK();
    CHECK(cmt_bsync_msg_sig_count(trunc, sizeof(trunc), &is_br, &cs, &es) == CMT_REJECT,
          "truncated (:616-618)"); OK();
    CHECK(cmt_bsync_msg_sig_count(sig_wt0, sizeof(sig_wt0), &is_br, &cs, &es) == CMT_REJECT,
          "a signature entry that is not length-delimited (:885)"); OK();
    return 0;
}

typedef struct {
    const char *name;
    int (*fn)(void);
} s_case_t;

int main(void)
{
    static const s_case_t cases[] = {
        { "vectors (types.pb.go:439-718)",           t_vectors },
        { "decoder rules (types.pb.go:1273-1497)",   t_decoder_rules },
        { "ValidateMsg (msgs.go:21-56)",             t_validate },
        { "MaxMsgSize (msgs.go:12-19)",              t_sizes },
        { "SigCount stub (v0.38.26 stub.pb.go)",     t_sig_count },
    };
    size_t i;
    size_t failed = 0u;

    for (i = 0u; i < sizeof(cases) / sizeof(cases[0]); i++) {
        if (cases[i].fn() != 0) {
            fprintf(stderr, "FAIL %s\n", cases[i].name);
            failed++;
        } else {
            printf("ok   %s\n", cases[i].name);
        }
    }
    printf("%d checks, %zu case(s) failed\n", g_checks, failed);
    return failed == 0u ? 0 : 1;
}
