/**
 * @file test_storage_probe.c
 * @brief Storage reward v1 rev 4 (the ARCHIVE reward), package B2b-1 —
 *        the archive probe's transport-independent half
 *        (nodus_witness_storage_probe.h) and the serving side's refusals
 *        (nodus_witness_storage_reporter.h nodus_witness_stprobe_serve).
 *
 * Decisions: docs/plans/decisions/2026-10-05-storage-reward-is-for-
 * archive.md, 2026-10-05-archive-reward-bytes-approved.md (bytes doc §6),
 * 2026-10-05-kurultay-7-archive-reward-summary.md.
 *
 * WHAT EACH CASE PINS DOWN
 *  request_wire     the request is EXACTLY the bytes doc §6 layout (the
 *                   padded tag at the front, every field at its offset,
 *                   288 bytes), rq = SHA3-512 of those 288 bytes, and the
 *                   decoder refuses a short / long message, a wrong kind
 *                   and a wrong tag.
 *  request_checks   the serving side's pure refusals: wrong chain, not
 *                   addressed to this node, reporter != the authenticated
 *                   sender, epoch_start not a boundary, past the deadline
 *                   (deadline == now is still in time).
 *  answer_wire      a refusal is kind ‖ rq ‖ code and nothing more; an OK
 *                   answer decodes only with three bounded samples and no
 *                   trailing byte.
 *  answer_build     over a fixture block store the serving side's answer
 *                   for nonce-derived samples verifies with the
 *                   reporter's chain (good answer), is NOT OK when late
 *                   or answering another request, and is NOT_HELD when a
 *                   sampled part or the header of h+1 is missing.
 *  verify_chain     every link of the bytes doc §6 chain refuses on its
 *                   own: header that does not decode, wrong header (hash),
 *                   header of the wrong height, header whose
 *                   last_block_id is not block h, part count 0, proof for
 *                   another part index, proof claiming another total, a
 *                   non-last part of the wrong size, a tampered part, an
 *                   oversized header.
 *  report_build     the STORAGE_REPORT call layout (bit i LSB-first =
 *                   member i, unused bits zero, length 78 + ceil(n/8)),
 *                   and the 1-leg SYSTEM envelope: op 9, fee 0, the
 *                   expiry asked, the call carried verbatim, one signer
 *                   whose ML-DSA-87 signature verifies over the leg's
 *                   auth digest.
 *  epoch_math       the probing epoch of a tip, the pacing slots, the
 *                   report window's both edges and the expiry cap.
 *  serve_refusals   with a minimal chain database: unknown set, S(H)
 *                   mismatch, this node not a member, no eligible block
 *                   (B == 0), and the pure refusals reached through the
 *                   full serving path.
 *
 * WHAT IT DOES NOT COVER (how it can lie): the requester-not-seated
 * refusal and the serving path's OK answer through
 * nodus_witness_stprobe_serve need a validator snapshot table — the OK
 * answer is proven one level down (answer_build, the same builder); the
 * 4004 channel, the reporter's pacing over live blocks and the mempool
 * submission run only on a live node (harness scenario not written in
 * this package).
 *
 * Requirements: a default build; no environment; leaves nothing behind
 * (in-memory databases only).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_host.h"
#include "witness/nodus_witness_cmt_store.h"
#include "witness/nodus_witness_storage_probe.h"
#include "witness/nodus_witness_storage_reporter.h"
#include "witness/nodus_witness_runtime.h"
#include "crypto/nodus_identity.h"

#include "dnac/dnac.h"
#include "dnac/cmt_block.h"
#include "dnac/cmt_merkle.h"
#include "dnac/cmt_part_set.h"
#include "dnac/cmt_pb.h"
#include "dnac/cmt_pb_store.h"
#include "dnac/env_wire.h"
#include "dnac/env_preflight.h"
#include "dnac/ledger_roots_v2.h"
#include "crypto/hash/qgp_sha3.h"
#include "crypto/sign/qgp_dilithium.h"

#include <inttypes.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, \
                (msg)); \
        return 1; \
    } \
    g_checks++; \
} while (0)

static int g_checks = 0;

#define E_LEN  ((uint64_t)DNAC_EPOCH_LENGTH)
#define P_LEN  ((uint64_t)DNA_V2_SEGMENT_BLOCKS)

static const uint8_t CHAIN[32] = {
    0xC1, 0xC1, 0xC1, 0xC1, 0xC1, 0xC1, 0xC1, 0xC1,
    0xC1, 0xC1, 0xC1, 0xC1, 0xC1, 0xC1, 0xC1, 0xC1,
    0xC1, 0xC1, 0xC1, 0xC1, 0xC1, 0xC1, 0xC1, 0xC1,
    0xC1, 0xC1, 0xC1, 0xC1, 0xC1, 0xC1, 0xC1, 0xC1 };

static void fill(uint8_t *p, size_t n, uint8_t seed) {
    for (size_t i = 0; i < n; i++) p[i] = (uint8_t)(seed + i * 13u);
}

static uint64_t be64(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | p[i];
    return v;
}

static void sample_req(nodus_stprobe_req_t *r) {
    memset(r, 0, sizeof(*r));
    memcpy(r->chain_id, CHAIN, 32);
    r->epoch_start = 2 * E_LEN;
    fill(r->set_hash, 64, 0x10);
    fill(r->target_fp, 64, 0x20);
    fill(r->reporter_fp, 64, 0x30);
    fill(r->nonce, 32, 0x40);
    r->deadline_ms = 1700000000123ULL;
}

/* ══ request_wire ══════════════════════════════════════════════════════ */

static int t_request_wire(void) {
    nodus_stprobe_req_t r, d;
    uint8_t msg[NODUS_STPROBE_REQ_MSG_LEN];
    sample_req(&r);
    CHECK(nodus_stprobe_req_encode(&r, msg) == 0, "encode");
    CHECK(sizeof(msg) == 289 && msg[0] == NODUS_STPROBE_KIND_REQ,
          "kind byte then the 288-byte body");
    /* bytes doc §6: "NDS.STPROBE.v2" padded to 16 with 0x00 */
    {
        static const uint8_t tag[16] = { 'N', 'D', 'S', '.', 'S', 'T', 'P',
                                         'R', 'O', 'B', 'E', '.', 'v', '2',
                                         0x00, 0x00 };
        CHECK(memcmp(msg + 1, tag, 16) == 0, "padded tag at the front");
    }
    const uint8_t *b = msg + 1;
    CHECK(memcmp(b + 16, r.chain_id, 32) == 0, "chain_id at 16");
    CHECK(be64(b + 48) == r.epoch_start, "epoch_start BE at 48");
    CHECK(memcmp(b + 56, r.set_hash, 64) == 0, "S(H) at 56");
    CHECK(memcmp(b + 120, r.target_fp, 64) == 0, "target_fp at 120");
    CHECK(memcmp(b + 184, r.reporter_fp, 64) == 0, "reporter_fp at 184");
    CHECK(memcmp(b + 248, r.nonce, 32) == 0, "nonce at 248");
    CHECK(be64(b + 280) == r.deadline_ms, "deadline_ms BE at 280");

    uint8_t rq[64], want[64];
    CHECK(nodus_stprobe_req_id(&r, rq) == 0, "rq");
    CHECK(qgp_sha3_512(b, NODUS_STPROBE_REQ_LEN, want) == 0, "sha3");
    CHECK(memcmp(rq, want, 64) == 0, "rq = SHA3-512(the 288 body bytes)");

    CHECK(nodus_stprobe_req_decode(msg, sizeof(msg), &d) == 0, "decode");
    CHECK(memcmp(&d, &r, sizeof(r)) == 0 ||
          (memcmp(d.chain_id, r.chain_id, 32) == 0 &&
           d.epoch_start == r.epoch_start &&
           memcmp(d.set_hash, r.set_hash, 64) == 0 &&
           memcmp(d.target_fp, r.target_fp, 64) == 0 &&
           memcmp(d.reporter_fp, r.reporter_fp, 64) == 0 &&
           memcmp(d.nonce, r.nonce, 32) == 0 &&
           d.deadline_ms == r.deadline_ms), "round trip");

    CHECK(nodus_stprobe_req_decode(msg, sizeof(msg) - 1, &d) != 0, "short");
    uint8_t longer[NODUS_STPROBE_REQ_MSG_LEN + 1];
    memcpy(longer, msg, sizeof(msg));
    longer[sizeof(msg)] = 0;
    CHECK(nodus_stprobe_req_decode(longer, sizeof(longer), &d) != 0, "long");
    uint8_t bad[NODUS_STPROBE_REQ_MSG_LEN];
    memcpy(bad, msg, sizeof(msg));
    bad[0] = NODUS_STPROBE_KIND_ANS;
    CHECK(nodus_stprobe_req_decode(bad, sizeof(bad), &d) != 0, "wrong kind");
    memcpy(bad, msg, sizeof(msg));
    bad[1 + 13] = '1';                      /* "NDS.STPROBE.v1" */
    CHECK(nodus_stprobe_req_decode(bad, sizeof(bad), &d) != 0, "wrong tag");
    memcpy(bad, msg, sizeof(msg));
    bad[1 + 15] = 0x01;                     /* padding not zero */
    CHECK(nodus_stprobe_req_decode(bad, sizeof(bad), &d) != 0,
          "non-zero tag padding");
    return 0;
}

/* ══ request_checks ════════════════════════════════════════════════════ */

static int t_request_checks(void) {
    nodus_stprobe_req_t r;
    sample_req(&r);
    uint8_t own[64], sender[64], other[64];
    memcpy(own, r.target_fp, 64);
    memcpy(sender, r.reporter_fp, 64);
    fill(other, 64, 0x99);
    const uint64_t now = r.deadline_ms;

    CHECK(nodus_stprobe_req_check(&r, own, CHAIN, sender, E_LEN, now) ==
          NODUS_STPROBE_OK, "in time (deadline == now)");
    CHECK(nodus_stprobe_req_check(&r, own, CHAIN, sender, E_LEN, now + 1) ==
          NODUS_STPROBE_REF_LATE, "past the deadline");
    {
        uint8_t ch[32];
        memcpy(ch, CHAIN, 32);
        ch[31] ^= 1;
        CHECK(nodus_stprobe_req_check(&r, own, ch, sender, E_LEN, now) ==
              NODUS_STPROBE_REF_WRONG_CHAIN, "wrong chain");
    }
    CHECK(nodus_stprobe_req_check(&r, other, CHAIN, sender, E_LEN, now) ==
          NODUS_STPROBE_REF_NOT_ADDRESSED, "not addressed to this node");
    CHECK(nodus_stprobe_req_check(&r, own, CHAIN, other, E_LEN, now) ==
          NODUS_STPROBE_REF_NOT_REPORTER,
          "reporter_fp is not the authenticated sender");
    nodus_stprobe_req_t m = r;
    m.epoch_start = 0;
    CHECK(nodus_stprobe_req_check(&m, own, CHAIN, sender, E_LEN, now) ==
          NODUS_STPROBE_REF_MALFORMED, "epoch_start 0");
    m.epoch_start = 2 * E_LEN + 1;
    CHECK(nodus_stprobe_req_check(&m, own, CHAIN, sender, E_LEN, now) ==
          NODUS_STPROBE_REF_MALFORMED, "epoch_start not a boundary");
    return 0;
}

/* ══ the block-store fixture ═══════════════════════════════════════════
 * Block h: 2 · 65536 + 1000 + (h mod 7) bytes → 3 parts. block_id(h).hash
 * is SHA3-512("blk" ‖ h) (any 64 bytes — the verifier only compares it
 * with header(h+1).last_block_id). header(h+1) is a valid header naming
 * that hash and the part set; its own hash is what v2_blocks would hold
 * at h+1. Stored: P:h:0..2 and H:(h+1). */

typedef struct {
    sqlite3           *db;
    nodus_cmt_store_t  store;
} fx_t;

static int fx_open(fx_t *f) {
    memset(f, 0, sizeof(*f));
    if (sqlite3_open(":memory:", &f->db) != SQLITE_OK) return -1;
    if (sqlite3_exec(f->db,
            "CREATE TABLE cmt_blockstore (key BLOB PRIMARY KEY, "
            "value BLOB NOT NULL);"
            "CREATE TABLE cmt_state (key BLOB PRIMARY KEY, "
            "value BLOB NOT NULL);", NULL, NULL, NULL) != SQLITE_OK)
        return -1;
    return nodus_cmt_store_init(&f->store, f->db, false) == CMT_OK ? 0 : -1;
}

static void fx_close(fx_t *f) {
    nodus_cmt_store_release(&f->store);
    sqlite3_close(f->db);
}

static void fx_block_hash(uint64_t h, uint8_t out[64]) {
    uint8_t pre[3 + 8];
    memcpy(pre, "blk", 3);
    for (int i = 0; i < 8; i++) pre[3 + i] = (uint8_t)(h >> (56 - 8 * i));
    qgp_sha3_512(pre, sizeof(pre), out);
}

/* header(h+1) naming block h with part-set header `psh` */
static void fx_header(uint64_t h, const cmt_part_set_header_t *psh,
                      cmt_pb_header_t *hd) {
    cmt_pb_header_init(hd);
    hd->version.block = CMT_BLOCK_PROTOCOL;
    memcpy(hd->chain_id, CHAIN, 32);
    hd->chain_id_len = 32;
    hd->height = (int64_t)(h + 1);
    hd->time.seconds = 1700000000 + (int64_t)h;
    hd->time.nanos = 0;
    fx_block_hash(h, hd->last_block_id.hash);
    hd->last_block_id.hash_len = 64;
    hd->last_block_id.part_set_header = *psh;
    fill(hd->last_commit_hash, 64, 1);      hd->last_commit_hash_len = 64;
    fill(hd->data_hash, 64, 2);             hd->data_hash_len = 64;
    fill(hd->validators_hash, 64, 3);       hd->validators_hash_len = 64;
    fill(hd->next_validators_hash, 64, 4);  hd->next_validators_hash_len = 64;
    fill(hd->consensus_hash, 64, 5);        hd->consensus_hash_len = 64;
    fill(hd->app_hash, 64, 6);              hd->app_hash_len = 64;
    fill(hd->last_results_hash, 64, 7);     hd->last_results_hash_len = 64;
    fill(hd->evidence_hash, 64, 8);         hd->evidence_hash_len = 64;
    fill(hd->proposer_address, 32, 9);      hd->proposer_address_len = 32;
}

static char *fx_key(char *buf, size_t cap, const char *fmt, int64_t a,
                    int b) {
    if (b < 0) snprintf(buf, cap, fmt, a);
    else snprintf(buf, cap, fmt, a, b);
    return buf;
}

/* Store block h (parts + header(h+1) meta). Optionally skip a part or the
 * meta. Outputs this node's v2_blocks hashes at h and h+1 and the part
 * count. */
static int fx_put_block(fx_t *f, uint64_t h, int skip_part, int skip_meta,
                        uint8_t hash_h[64], uint8_t hash_h1[64],
                        uint32_t *total_out) {
    const size_t len = 2 * 65536 + 1000 + (size_t)(h % 7);
    uint8_t *data = malloc(len);
    cmt_part_t *parts = calloc(4, sizeof(*parts));
    cmt_pb_header_t *hd = calloc(1, sizeof(*hd));
    cmt_pb_block_meta_t *bm = calloc(1, sizeof(*bm));
    uint8_t *buf = malloc(80000);
    cmt_part_set_t ps;
    int ret = -1;
    char key[NODUS_CMT_STORE_KEY_MAX];
    if (!data || !parts || !hd || !bm || !buf) goto done;
    for (size_t j = 0; j < len; j++) data[j] = (uint8_t)(h * 31u + j * 7u);
    if (cmt_new_part_set_from_data(data, len, CMT_BLOCK_PART_SIZE_BYTES,
                                   parts, 4, &ps) != CMT_OK)
        goto done;
    cmt_part_set_header_t psh;
    if (cmt_part_set_header(&ps, &psh) != CMT_OK) goto done;
    for (uint32_t i = 0; i < ps.total; i++) {
        size_t n = 0;
        if ((int)i == skip_part) continue;
        if (cmt_pb_part_marshal(&parts[i], buf, 80000, &n) != CMT_OK)
            goto done;
        if (nodus_cmt_store_set(&f->store, false,
                                fx_key(key, sizeof(key), "P:%" PRId64 ":%d",
                                       (int64_t)h, (int)i), buf, n) != CMT_OK)
            goto done;
    }
    fx_header(h, &psh, hd);
    if (cmt_header_hash(hd, hash_h1) != CMT_OK) goto done;
    fx_block_hash(h, hash_h);
    if (!skip_meta) {
        size_t n = 0;
        cmt_pb_store_block_meta_init(bm);
        memcpy(bm->block_id.hash, hash_h1, 64);
        bm->block_id.hash_len = 64;
        bm->block_id.part_set_header.total = 1;
        fill(bm->block_id.part_set_header.hash, 64, 0x77);
        bm->block_id.part_set_header.hash_len = 64;
        bm->header = *hd;
        bm->block_size = 1000;
        if (cmt_pb_store_block_meta_marshal(bm, buf, 80000, &n) != CMT_OK)
            goto done;
        if (nodus_cmt_store_set(&f->store, false,
                                fx_key(key, sizeof(key), "H:%" PRId64,
                                       (int64_t)(h + 1), -1), buf, n)
                != CMT_OK)
            goto done;
    }
    if (total_out) *total_out = ps.total;
    ret = 0;
done:
    free(buf);
    free(bm);
    free(hd);
    free(parts);
    free(data);
    return ret;
}

/* ══ answer_wire ═══════════════════════════════════════════════════════ */

static int t_answer_wire(void) {
    uint8_t rq[64], ref[NODUS_STPROBE_REFUSAL_LEN];
    nodus_stprobe_ans_view_t a;
    fill(rq, 64, 0x55);
    CHECK(nodus_stprobe_ans_refusal(rq, NODUS_STPROBE_OK, ref) != 0,
          "OK is never a refusal");
    CHECK(nodus_stprobe_ans_refusal(rq, NODUS_STPROBE_REF_NOT_HELD, ref) == 0,
          "refusal");
    CHECK(ref[0] == NODUS_STPROBE_KIND_ANS && memcmp(ref + 1, rq, 64) == 0 &&
          ref[65] == NODUS_STPROBE_REF_NOT_HELD, "kind ‖ rq ‖ code");
    CHECK(nodus_stprobe_ans_decode(ref, sizeof(ref), &a) == 0 &&
          a.code == NODUS_STPROBE_REF_NOT_HELD &&
          memcmp(a.rq, rq, 64) == 0, "refusal decodes");
    {
        uint8_t longer[NODUS_STPROBE_REFUSAL_LEN + 1];
        memcpy(longer, ref, sizeof(ref));
        longer[sizeof(ref)] = 0;
        CHECK(nodus_stprobe_ans_decode(longer, sizeof(longer), &a) != 0,
              "a refusal carries nothing more");
    }
    CHECK(nodus_stprobe_ans_decode(ref, sizeof(ref) - 1, &a) != 0, "short");

    /* an OK answer, built over the fixture */
    fx_t f;
    CHECK(fx_open(&f) == 0, "fixture");
    uint8_t x[3][64], hh[3][64], hh1[3][64];
    uint64_t h[3] = { 100, 200, 300 };
    for (int i = 0; i < 3; i++) {
        memset(x[i], 0, 64);
        CHECK(fx_put_block(&f, h[i], -1, 0, hh[i], hh1[i], NULL) == 0,
              "block");
    }
    uint8_t *msg = malloc(NODUS_STPROBE_MSG_MAX);
    size_t len = 0;
    CHECK(msg != NULL, "alloc");
    CHECK(nodus_stprobe_answer_build(&f.store, rq,
                                     (const uint8_t (*)[64])x, h, P_LEN,
                                     msg, NODUS_STPROBE_MSG_MAX, &len) ==
          NODUS_STPROBE_OK, "answer built");
    CHECK(nodus_stprobe_ans_decode(msg, len, &a) == 0 &&
          a.code == NODUS_STPROBE_OK, "OK answer decodes");
    CHECK(a.s[0].part_len == CMT_BLOCK_PART_SIZE_BYTES,
          "x = 0 picks part 0, a full part");
    CHECK(nodus_stprobe_ans_decode(msg, len - 1, &a) != 0, "truncated");
    msg[len] = 0;
    CHECK(nodus_stprobe_ans_decode(msg, len + 1, &a) != 0, "trailing byte");
    {
        /* sample 0's header length beyond the bound */
        uint8_t save[4];
        memcpy(save, msg + 66, 4);
        msg[66] = 0; msg[67] = 0; msg[68] = 0x08; msg[69] = 0x01; /* 2049 */
        CHECK(nodus_stprobe_ans_decode(msg, len, &a) != 0,
              "header length past NODUS_STPROBE_HEADER_MAX");
        memcpy(msg + 66, save, 4);
        CHECK(nodus_stprobe_ans_decode(msg, len, &a) == 0, "restored");
    }
    free(msg);
    fx_close(&f);
    return 0;
}

/* ══ answer_build ══════════════════════════════════════════════════════ */

static int t_answer_build(void) {
    fx_t f;
    CHECK(fx_open(&f) == 0, "fixture");
    uint8_t nonce[32], target[64], rq[64];
    fill(nonce, 32, 0xA1);
    fill(target, 64, 0xB2);
    fill(rq, 64, 0xC3);
    const uint64_t ks[2] = { 1, 3 };
    const uint64_t B = 2 * P_LEN;
    uint8_t x[3][64], hh[3][64], hh1[3][64];
    uint64_t h[3];
    CHECK(nodus_stprobe_samples(nonce, target, ks, 2, x, h) == 0, "samples");
    for (int i = 0; i < 3; i++) {
        CHECK((h[i] >= 1 && h[i] <= P_LEN) ||
              (h[i] >= 2 * P_LEN + 1 && h[i] <= 3 * P_LEN),
              "every sample lies in segment 1 or 3");
        CHECK(fx_put_block(&f, h[i], -1, 0, hh[i], hh1[i], NULL) == 0,
              "block");
    }
    {
        uint64_t one[1] = { 1 }, bad[2] = { 3, 1 };
        uint8_t xx[3][64];
        uint64_t hx[3];
        CHECK(nodus_stprobe_samples(nonce, target, one, 0, xx, hx) != 0,
              "B == 0: no samples");
        CHECK(nodus_stprobe_samples(nonce, target, bad, 2, xx, hx) != 0,
              "segments not ascending");
        uint8_t again[3][64];
        uint64_t hagain[3];
        CHECK(nodus_stprobe_samples(nonce, target, ks, 2, again, hagain) ==
              0 && memcmp(again, x, sizeof(x)) == 0 &&
              memcmp(hagain, h, sizeof(h)) == 0,
              "the same nonce gives the same samples on both sides");
        uint8_t x0[64];
        CHECK(dna_v2_storage_sample_x(nonce, target, 0, x0) == 0 &&
              memcmp(x0, x[0], 64) == 0, "x_0 is the bytes doc §6 x_0");
    }

    uint8_t *msg = malloc(NODUS_STPROBE_MSG_MAX);
    size_t len = 0;
    nodus_stprobe_ans_view_t a;
    CHECK(msg != NULL, "alloc");
    CHECK(nodus_stprobe_answer_build(&f.store, rq,
                                     (const uint8_t (*)[64])x, h, B,
                                     msg, NODUS_STPROBE_MSG_MAX, &len) ==
          NODUS_STPROBE_OK, "answer built");
    CHECK(len <= NODUS_STPROBE_MSG_MAX, "fits the channel");
    CHECK(nodus_stprobe_ans_decode(msg, len, &a) == 0, "decodes");
    CHECK(nodus_stprobe_answer_ok(&a, rq, (const uint8_t (*)[64])x, B, h,
                                  (const uint8_t (*)[64])hh,
                                  (const uint8_t (*)[64])hh1, 50, 50),
          "good answer: OK (answer at the deadline)");
    CHECK(!nodus_stprobe_answer_ok(&a, rq, (const uint8_t (*)[64])x, B, h,
                                   (const uint8_t (*)[64])hh,
                                   (const uint8_t (*)[64])hh1, 51, 50),
          "late: NOT OK");
    {
        uint8_t other[64];
        memcpy(other, rq, 64);
        other[0] ^= 1;
        CHECK(!nodus_stprobe_answer_ok(&a, other, (const uint8_t (*)[64])x,
                                       B, h, (const uint8_t (*)[64])hh,
                                       (const uint8_t (*)[64])hh1, 0, 50),
              "an answer to another request: NOT OK");
    }
    {
        /* a refusal answer to the right request is still NOT OK */
        uint8_t ref[NODUS_STPROBE_REFUSAL_LEN];
        nodus_stprobe_ans_view_t ra;
        CHECK(nodus_stprobe_ans_refusal(rq, NODUS_STPROBE_REF_NOT_HELD,
                                        ref) == 0 &&
              nodus_stprobe_ans_decode(ref, sizeof(ref), &ra) == 0,
              "refusal");
        CHECK(!nodus_stprobe_answer_ok(&ra, rq, (const uint8_t (*)[64])x, B,
                                       h, (const uint8_t (*)[64])hh,
                                       (const uint8_t (*)[64])hh1, 0, 50),
              "a refusal: NOT OK");
    }

    /* NOT_HELD: a part missing, the meta of h+1 missing */
    {
        fx_t g;
        uint8_t a1[64], b1[64];
        CHECK(fx_open(&g) == 0, "fixture 2");
        for (int i = 0; i < 3; i++)
            CHECK(fx_put_block(&g, h[i], -1, 0, a1, b1, NULL) == 0,
                  "blocks written");
        /* now delete every part of h[0] */
        char key[NODUS_CMT_STORE_KEY_MAX];
        for (int p = 0; p < 3; p++) {
            snprintf(key, sizeof(key), "P:%" PRId64 ":%d", (int64_t)h[0], p);
            CHECK(nodus_cmt_store_delete(&g.store, false, key) == CMT_OK,
                  "delete part");
        }
        CHECK(nodus_stprobe_answer_build(&g.store, rq,
                                         (const uint8_t (*)[64])x, h, B,
                                         msg, NODUS_STPROBE_MSG_MAX, &len) ==
              NODUS_STPROBE_REF_NOT_HELD, "a sampled part not held");
        fx_close(&g);
    }
    {
        fx_t g;
        uint8_t a1[64], b1[64];
        CHECK(fx_open(&g) == 0, "fixture 3");
        for (int i = 0; i < 3; i++)
            CHECK(fx_put_block(&g, h[i], -1, i == 2, a1, b1, NULL) == 0,
                  "blocks, the last without header(h+1)");
        CHECK(h[2] == h[0] || h[2] == h[1] ||
              nodus_stprobe_answer_build(&g.store, rq,
                                         (const uint8_t (*)[64])x, h, B,
                                         msg, NODUS_STPROBE_MSG_MAX, &len) ==
              NODUS_STPROBE_REF_NOT_HELD, "header(h+1) not held");
        fx_close(&g);
    }
    free(msg);
    fx_close(&f);
    return 0;
}

/* ══ verify_chain ══════════════════════════════════════════════════════
 * Block h = 100, 3 parts; x chosen so that the part index is 0 (x[8..12)
 * = 0) or 1 (x[11] = 1); every negative changes ONE link. */

typedef struct {
    uint8_t *hdr;   size_t hdr_len;
    uint8_t *part;  size_t part_len;
    uint8_t *proof; size_t proof_len;
} vbuf_t;

static int load_part(fx_t *f, uint64_t h, int idx, vbuf_t *v) {
    cmt_part_t *part = calloc(1, sizeof(*part));
    uint8_t *arena_buf = malloc(CMT_BLOCK_PART_SIZE_BYTES);
    bool found = false;
    int ret = -1;
    if (!part || !arena_buf) goto done;
    cmt_pb_arena_t ar = { arena_buf, CMT_BLOCK_PART_SIZE_BYTES, 0 };
    if (nodus_cmt_bs_load_block_part(&f->store, (int64_t)h, idx, &ar, part,
                                     &found) != CMT_OK || !found)
        goto done;
    v->part_len = part->bytes.len;
    memcpy(v->part, part->bytes.data, part->bytes.len);
    if (cmt_pb_proof_marshal(&part->proof, v->proof, NODUS_STPROBE_PROOF_MAX,
                             &v->proof_len) != CMT_OK)
        goto done;
    ret = 0;
done:
    free(arena_buf);
    free(part);
    return ret;
}

static nodus_stprobe_sample_view_t vview(const vbuf_t *v) {
    nodus_stprobe_sample_view_t s;
    s.header = v->hdr;   s.header_len = (uint32_t)v->hdr_len;
    s.part = v->part;    s.part_len = (uint32_t)v->part_len;
    s.proof = v->proof;  s.proof_len = (uint32_t)v->proof_len;
    return s;
}

static int t_verify_chain(void) {
    fx_t f;
    const uint64_t h = 100;
    uint8_t hh[64], hh1[64];
    uint32_t total = 0;
    CHECK(fx_open(&f) == 0, "fixture");
    CHECK(fx_put_block(&f, h, -1, 0, hh, hh1, &total) == 0 && total == 3,
          "block of 3 parts");

    vbuf_t v;
    v.hdr = malloc(NODUS_STPROBE_HEADER_MAX + 16);
    v.part = malloc(CMT_BLOCK_PART_SIZE_BYTES);
    v.proof = malloc(NODUS_STPROBE_PROOF_MAX);
    cmt_pb_block_meta_t *bm = calloc(1, sizeof(*bm));
    CHECK(v.hdr && v.part && v.proof && bm, "alloc");
    {
        bool found = false;
        CHECK(nodus_cmt_bs_load_block_meta(&f.store, (int64_t)(h + 1), bm,
                                           &found) == CMT_OK && found,
              "meta of h+1");
        CHECK(cmt_pb_header_marshal(&bm->header, v.hdr,
                                    NODUS_STPROBE_HEADER_MAX, &v.hdr_len) ==
              CMT_OK, "header proto");
    }
    CHECK(load_part(&f, h, 0, &v) == 0, "part 0 and its proof");

    uint8_t x[64];
    memset(x, 0, 64);
    nodus_stprobe_sample_view_t s = vview(&v);
    CHECK(nodus_stprobe_verify_sample(x, P_LEN, h, hh, hh1, &s) ==
          NODUS_STPROBE_V_OK, "good sample");

    /* header that does not decode: field 1, LEN, truncated */
    {
        uint8_t junk[2] = { 0x0A, 0xFF };
        nodus_stprobe_sample_view_t t = s;
        t.header = junk;
        t.header_len = 2;
        CHECK(nodus_stprobe_verify_sample(x, P_LEN, h, hh, hh1, &t) ==
              NODUS_STPROBE_V_HEADER_DECODE, "header does not decode");
    }
    /* wrong header: this node committed another header at h+1 */
    {
        uint8_t other[64];
        memcpy(other, hh1, 64);
        other[5] ^= 0x40;
        CHECK(nodus_stprobe_verify_sample(x, P_LEN, h, hh, other, &s) ==
              NODUS_STPROBE_V_HEADER_HASH, "wrong header");
    }
    /* the genuine header(h+1) offered as the header of another height */
    CHECK(nodus_stprobe_verify_sample(x, P_LEN, h + 1, hh, hh1, &s) ==
          NODUS_STPROBE_V_HEADER_HEIGHT, "header of the wrong height");
    /* its last_block_id is not this node's block h */
    {
        uint8_t other[64];
        memcpy(other, hh, 64);
        other[0] ^= 1;
        CHECK(nodus_stprobe_verify_sample(x, P_LEN, h, other, hh1, &s) ==
              NODUS_STPROBE_V_BLOCK_ID, "wrong block id");
    }
    /* a header (hashing correctly) whose part count is 0 */
    {
        cmt_pb_header_t *z = calloc(1, sizeof(*z));
        uint8_t zh[64], zbuf[NODUS_STPROBE_HEADER_MAX];
        size_t zl = 0;
        CHECK(z != NULL, "alloc");
        *z = bm->header;
        z->last_block_id.part_set_header.total = 0;
        CHECK(cmt_header_hash(z, zh) == CMT_OK &&
              cmt_pb_header_marshal(z, zbuf, sizeof(zbuf), &zl) == CMT_OK,
              "variant header");
        nodus_stprobe_sample_view_t t = s;
        t.header = zbuf;
        t.header_len = (uint32_t)zl;
        CHECK(nodus_stprobe_verify_sample(x, P_LEN, h, hh, zh, &t) ==
              NODUS_STPROBE_V_PART_TOTAL, "part count 0");
        free(z);
    }
    /* the sampled part is 1, the answer carries part 0 with its proof */
    {
        uint8_t x1[64];
        memset(x1, 0, 64);
        x1[11] = 1;
        CHECK(nodus_stprobe_verify_sample(x1, P_LEN, h, hh, hh1, &s) ==
              NODUS_STPROBE_V_PART_INDEX, "proof for another part index");
    }
    /* the proof claims another total */
    {
        cmt_proof_t *pf = calloc(1, sizeof(*pf));
        uint8_t pbuf[NODUS_STPROBE_PROOF_MAX];
        size_t pl = 0;
        CHECK(pf != NULL, "alloc");
        cmt_pb_proof_init(pf);
        CHECK(cmt_pb_proof_unmarshal(v.proof, v.proof_len, pf) == CMT_OK,
              "proof decodes");
        pf->total += 1;
        CHECK(cmt_pb_proof_marshal(pf, pbuf, sizeof(pbuf), &pl) == CMT_OK,
              "proof re-encoded");
        nodus_stprobe_sample_view_t t = s;
        t.proof = pbuf;
        t.proof_len = (uint32_t)pl;
        CHECK(nodus_stprobe_verify_sample(x, P_LEN, h, hh, hh1, &t) ==
              NODUS_STPROBE_V_PROOF_TOTAL, "proof claims another total");
        free(pf);
    }
    /* a non-last part one byte short (Part.ValidateBasic) */
    {
        nodus_stprobe_sample_view_t t = s;
        t.part_len -= 1;
        CHECK(nodus_stprobe_verify_sample(x, P_LEN, h, hh, hh1, &t) ==
              NODUS_STPROBE_V_PART_BASIC, "non-last part of the wrong size");
    }
    /* a tampered part */
    {
        v.part[1234] ^= 0x01;
        CHECK(nodus_stprobe_verify_sample(x, P_LEN, h, hh, hh1, &s) ==
              NODUS_STPROBE_V_PROOF, "tampered part");
        v.part[1234] ^= 0x01;
        CHECK(nodus_stprobe_verify_sample(x, P_LEN, h, hh, hh1, &s) ==
              NODUS_STPROBE_V_OK, "restored");
    }
    /* bounds */
    {
        nodus_stprobe_sample_view_t t = s;
        t.header_len = NODUS_STPROBE_HEADER_MAX + 1;
        CHECK(nodus_stprobe_verify_sample(x, P_LEN, h, hh, hh1, &t) ==
              NODUS_STPROBE_V_BOUNDS, "oversized header");
    }
    free(bm);
    free(v.hdr);
    free(v.part);
    free(v.proof);
    fx_close(&f);
    return 0;
}

/* ══ report_build ══════════════════════════════════════════════════════ */

static int t_report_build(void) {
    uint8_t sh[64], call[NODUS_STPROBE_REPORT_CALL_MAX];
    size_t cl = 0;
    fill(sh, 64, 0x3C);
    bool ok[11] = { true, false, true, false, false, false, false, true,
                    false, true, false };
    CHECK(nodus_stprobe_report_call(5 * E_LEN, 4, sh, ok, 11, call, &cl) == 0,
          "call");
    CHECK(cl == 78u + 2u, "78 + ceil(11/8)");
    CHECK(be64(call) == 5 * E_LEN, "epoch_start BE");
    CHECK(call[8] == 0 && call[9] == 0 && call[10] == 0 && call[11] == 4,
          "seat BE");
    CHECK(memcmp(call + 12, sh, 64) == 0, "S(H)");
    CHECK(call[76] == 0 && call[77] == 2, "bitmap_len BE");
    CHECK(call[78] == 0x85, "bits 0, 2, 7 (LSB-first)");
    CHECK(call[79] == 0x02, "bit 9; unused high bits zero");
    CHECK(nodus_stprobe_report_call(5 * E_LEN, 4, sh, NULL, 0, call, &cl) ==
          0 && cl == 78u, "an empty set: no bitmap byte");
    {
        bool *big = calloc(DNA_V2_STORAGE_SET_MAX + 1, sizeof(*big));
        CHECK(big != NULL, "alloc");
        CHECK(nodus_stprobe_report_call(5 * E_LEN, 4, sh, big,
                                        DNA_V2_STORAGE_SET_MAX, call, &cl) ==
              0 && cl == 78u + 32u, "256 members: 32 bytes");
        CHECK(nodus_stprobe_report_call(5 * E_LEN, 4, sh, big,
                                        DNA_V2_STORAGE_SET_MAX + 1, call,
                                        &cl) != 0, "257 refused");
        free(big);
    }

    /* the envelope */
    CHECK(nodus_stprobe_report_call(5 * E_LEN, 4, sh, ok, 11, call, &cl) == 0,
          "call again");
    nodus_identity_t *id = calloc(1, sizeof(*id));
    uint8_t seed[32];
    fill(seed, 32, 0x61);
    CHECK(id && nodus_identity_from_seed(seed, id) == 0, "identity");
    uint8_t rsh[64];
    fill(rsh, 64, 0x6E);
    const uint32_t ver = 8;
    const uint64_t app = 6 * E_LEN + 1, expiry = 6 * E_LEN + 50;
    uint8_t *env = NULL;
    size_t el = 0;
    CHECK(nodus_stprobe_report_env(CHAIN, ver, rsh, app, app - 1, call, cl,
                                   id->pk.bytes, id->sk.bytes, &env, &el) !=
          0 && env == NULL, "expiry below the applying height refused");
    CHECK(nodus_stprobe_report_env(CHAIN, ver, rsh, app, expiry, call, cl,
                                   id->pk.bytes, id->sk.bytes, &env, &el) ==
          0 && env != NULL, "envelope");
    dna_env_view_t vw;
    CHECK(dna_env_decode(env, el, &vw) == 0, "decodes");
    CHECK(vw.leg_count == 1 && vw.leg[0].domain_id == DNA_DOMAIN_SYSTEM &&
          vw.leg[0].runtime_op == DNA_SYSRULE_STORAGE_REPORT &&
          vw.leg[0].ruleset_version == ver &&
          vw.leg[0].auth_kind == NODUS_RT_AUTHKIND_DSA87_MULTI_V1,
          "one SYSTEM STORAGE_REPORT leg, auth kind 1");
    CHECK(vw.fee_amount == 0 && vw.expiry_height == expiry,
          "fee 0, the expiry asked");
    CHECK(vw.leg[0].call_len == cl &&
          memcmp(vw.buf + vw.call_off[0], call, cl) == 0,
          "the call verbatim");
    const uint8_t *auth = vw.buf + vw.auth_off[0];
    CHECK(vw.leg[0].auth_len == 1u + NODUS_RT_AUTH_SIGNER_LEN &&
          auth[0] == 1 && memcmp(auth + 1, id->pk.bytes, 2592) == 0,
          "one signer: this node's key");
    {
        dna_env_leg_ctx_t lc;
        dna_env_preflight_t *pf = calloc(1, sizeof(*pf));
        CHECK(pf != NULL, "alloc");
        memset(&lc, 0, sizeof(lc));
        lc.domain_id = DNA_DOMAIN_SYSTEM;
        lc.ruleset_version = ver;
        memcpy(lc.ruleset_hash, rsh, 64);
        CHECK(dna_env_preflight(env, el, CHAIN, app, &lc, 1, pf) ==
              DNA_ENV_PF_OK, "preflight at the applying height");
        CHECK(qgp_dsa87_verify(auth + 1 + 2592, QGP_DSA87_SIGNATURE_BYTES,
                               pf->auth_digest[0], 64, id->pk.bytes) == 0,
              "the signature covers the leg's auth digest");
        free(pf);
    }
    free(env);
    free(id);
    return 0;
}

/* ══ epoch_math ════════════════════════════════════════════════════════ */

static int t_epoch_math(void) {
    uint64_t H = 0, ex = 0;
    for (int pass = 0; pass < 2; pass++) {
        const uint64_t E = pass == 0 ? 720u : 15u;
        CHECK(nodus_stprobe_epoch_for_tip(E - 1, E, &H) != 0,
              "no epoch before the first boundary");
        CHECK(nodus_stprobe_epoch_for_tip(E, E, &H) == 0 && H == E,
              "the boundary itself opens its epoch (set(H) committed)");
        CHECK(nodus_stprobe_epoch_for_tip(2 * E - 1, E, &H) == 0 && H == E,
              "the epoch's last tip");
        CHECK(nodus_stprobe_epoch_for_tip(2 * E, E, &H) == 0 && H == 2 * E,
              "the next boundary");

        const uint64_t H0 = 3 * E;
        uint64_t prev = H0;
        for (size_t j = 0; j < 7; j++) {
            uint64_t s = nodus_stprobe_slot_height(H0, E, j, 7);
            CHECK(s >= prev && s < H0 + (3 * E) / 4 + 1,
                  "slots ascend inside the first 3/4");
            prev = s;
        }
        CHECK(nodus_stprobe_slot_height(H0, E, 0, 7) == H0, "first slot H");

        /* window (H+E, H+E+⌊E/2⌋] over the applying height tip + 1 */
        const uint64_t close = H0 + E + E / 2;
        CHECK(nodus_stprobe_report_window(H0, E, H0 + E - 1, &ex) == 1,
              "applying height H+E: not open");
        CHECK(nodus_stprobe_report_window(H0, E, H0 + E, &ex) == 0 &&
              ex == (H0 + E + 100 < close ? H0 + E + 100 : close),
              "applying H+E+1: open, expiry min(tip+100, close)");
        CHECK(nodus_stprobe_report_window(H0, E, close - 1, &ex) == 0 &&
              ex == close, "applying height = close: last chance");
        CHECK(nodus_stprobe_report_window(H0, E, close, &ex) == -1,
              "applying height past close: closed");
    }
    {
        const uint64_t E = 720u, H0 = 1440u;
        CHECK(nodus_stprobe_report_window(H0, E, H0 + E, &ex) == 0 &&
              ex == H0 + E + 100, "production: expiry = tip + 100");
    }
    return 0;
}

/* ══ serve_refusals ════════════════════════════════════════════════════ */

typedef struct {
    nodus_witness_t      *w;
    nodus_witness_host_t  host;
    nodus_identity_t     *id;
    uint8_t               fp[64];
} sw_t;

static int sw_open(sw_t *s) {
    memset(s, 0, sizeof(*s));
    s->w = calloc(1, sizeof(*s->w));
    s->id = calloc(1, sizeof(*s->id));
    uint8_t seed[32];
    fill(seed, 32, 0x17);
    if (!s->w || !s->id || nodus_identity_from_seed(seed, s->id) != 0)
        return -1;
    if (qgp_sha3_512(s->id->pk.bytes, 2592, s->fp) != 0) return -1;
    s->host.identity = s->id;
    s->w->host = &s->host;
    if (sqlite3_open(":memory:", &s->w->db) != SQLITE_OK) return -1;
    if (sqlite3_exec(s->w->db, NODUS_V2_STSETS_DDL, NULL, NULL, NULL) !=
            SQLITE_OK ||
        sqlite3_exec(s->w->db, NODUS_V2_STMEMB_DDL, NULL, NULL, NULL) !=
            SQLITE_OK ||
        sqlite3_exec(s->w->db, NODUS_V2_STSEGS_DDL, NULL, NULL, NULL) !=
            SQLITE_OK)
        return -1;
    memcpy(s->w->v2_chain32, CHAIN, 32);
    s->w->v2_chain32_valid = true;
    return 0;
}

static void sw_close(sw_t *s) {
    if (s->w) sqlite3_close(s->w->db);
    free(s->w);
    free(s->id);
}

/* storage_set(H) of the given members (sorted here). */
static int sw_set(sw_t *s, uint64_t H, uint8_t (*fps)[64], size_t n,
                  uint8_t set_hash[64]) {
    for (size_t i = 1; i < n; i++)
        for (size_t j = i; j > 0 && memcmp(fps[j - 1], fps[j], 64) > 0; j--) {
            uint8_t t[64];
            memcpy(t, fps[j], 64);
            memcpy(fps[j], fps[j - 1], 64);
            memcpy(fps[j - 1], t, 64);
        }
    if (dna_v2_storage_set_hash(H, (const uint8_t (*)[64])fps, n,
                                set_hash) != 0)
        return -1;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(s->w->db, "INSERT INTO v2_storage_sets VALUES "
                           "(?1, ?2, ?3)", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)H);
    sqlite3_bind_blob(st, 2, set_hash, 64, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 3, (sqlite3_int64)n);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) return -1;
    for (size_t i = 0; i < n; i++) {
        if (sqlite3_prepare_v2(s->w->db, "INSERT INTO v2_storage_set_members "
                               "VALUES (?1, ?2, 0)", -1, &st, NULL) !=
                SQLITE_OK)
            return -1;
        sqlite3_bind_int64(st, 1, (sqlite3_int64)H);
        sqlite3_bind_blob(st, 2, fps[i], 64, SQLITE_TRANSIENT);
        rc = sqlite3_step(st);
        sqlite3_finalize(st);
        if (rc != SQLITE_DONE) return -1;
    }
    return 0;
}

static int t_serve_refusals(void) {
    sw_t s;
    CHECK(sw_open(&s) == 0, "minimal chain database");
    const uint64_t H = 3 * E_LEN, now = 1000;
    uint8_t reporter[64], other[64], sh[64];
    fill(reporter, 64, 0x30);
    fill(other, 64, 0x44);
    uint8_t *out = malloc(NODUS_STPROBE_MSG_MAX);
    size_t len = 0;
    CHECK(out != NULL, "alloc");

    nodus_stprobe_req_t r;
    memset(&r, 0, sizeof(r));
    memcpy(r.chain_id, CHAIN, 32);
    r.epoch_start = H;
    memcpy(r.target_fp, s.fp, 64);
    memcpy(r.reporter_fp, reporter, 64);
    fill(r.nonce, 32, 0x40);
    r.deadline_ms = now;

#define SERVE(req) nodus_witness_stprobe_serve(s.w, NULL, reporter, (req), \
                                               E_LEN, now, out,          \
                                               NODUS_STPROBE_MSG_MAX, &len)
    /* the pure refusals, through the full path */
    {
        nodus_stprobe_req_t m = r;
        m.chain_id[0] ^= 1;
        CHECK(SERVE(&m) == NODUS_STPROBE_REF_WRONG_CHAIN, "wrong chain");
        m = r;
        memcpy(m.target_fp, other, 64);
        CHECK(SERVE(&m) == NODUS_STPROBE_REF_NOT_ADDRESSED, "not addressed");
        m = r;
        memcpy(m.reporter_fp, other, 64);
        CHECK(SERVE(&m) == NODUS_STPROBE_REF_NOT_REPORTER, "not the sender");
        m = r;
        m.deadline_ms = now - 1;
        CHECK(SERVE(&m) == NODUS_STPROBE_REF_LATE, "past the deadline");
    }
    /* no storage_set(H) on this node */
    CHECK(SERVE(&r) == NODUS_STPROBE_REF_UNKNOWN_SET, "unknown set");

    /* storage_set(H) without this node */
    {
        uint8_t m[1][64];
        memcpy(m[0], other, 64);
        CHECK(sw_set(&s, H, m, 1, sh) == 0, "set without this node");
        memcpy(r.set_hash, sh, 64);
        CHECK(SERVE(&r) == NODUS_STPROBE_REF_NOT_MEMBER, "not a member");
        r.set_hash[0] ^= 1;
        CHECK(SERVE(&r) == NODUS_STPROBE_REF_SET_MISMATCH, "S(H) differs");
    }
    /* storage_set(H + E) WITH this node, no set at H (no grace passed)
     * and no published segment: B == 0 */
    {
        uint8_t m[2][64];
        memcpy(m[0], other, 64);
        memcpy(m[1], s.fp, 64);
        CHECK(sw_set(&s, H + E_LEN, m, 2, sh) == 0, "set with this node");
        nodus_stprobe_req_t q = r;
        q.epoch_start = H + E_LEN;
        memcpy(q.set_hash, sh, 64);
        CHECK(SERVE(&q) == NODUS_STPROBE_REF_NO_BLOCKS,
              "no eligible block: B == 0");
    }
#undef SERVE
    CHECK(len == 0, "a refusal writes no answer");
    free(out);
    sw_close(&s);
    return 0;
}

int main(void) {
    static const struct {
        const char *name;
        int (*fn)(void);
    } cases[] = {
        { "request_wire",    t_request_wire },
        { "request_checks",  t_request_checks },
        { "answer_wire",     t_answer_wire },
        { "answer_build",    t_answer_build },
        { "verify_chain",    t_verify_chain },
        { "report_build",    t_report_build },
        { "epoch_math",      t_epoch_math },
        { "serve_refusals",  t_serve_refusals },
    };
    size_t failed = 0, n = sizeof(cases) / sizeof(cases[0]);
    for (size_t i = 0; i < n; i++) {
        int rc = cases[i].fn();
        fprintf(stderr, "%-18s %s\n", cases[i].name, rc == 0 ? "ok" : "FAIL");
        if (rc != 0) failed++;
    }
    fprintf(stderr, "test_storage_probe: %zu/%zu cases passed, %d checks\n",
            n - failed, n, g_checks);
    return failed ? 1 : 0;
}
