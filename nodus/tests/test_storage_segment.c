/**
 * @file test_storage_segment.c
 * @brief Storage reward v1 rev 4 (the ARCHIVE reward), package B2b-2 —
 *        the segment file (nodus_witness_storage_segment.h), the channel
 *        0x73 wire and serving side (nodus_witness_storage_fetch.h), the
 *        holder's must-hold / deletion rule (nodus_witness_storage_
 *        holder.h) and the 0x72 probe answered from a file.
 *
 * Decisions: docs/plans/decisions/2026-10-05-storage-reward-is-for-
 * archive.md, 2026-10-05-archive-reward-bytes-approved.md (bytes doc §6
 * chain, §7 file), 2026-10-05-kurultay-7-archive-reward-summary.md
 * (items 2, 4, 5, 7), 2026-10-03-block-pruning-7-paydays.md.
 *
 * THE FIXTURE (built once): a block store and a v2_blocks table holding a
 * REAL chain over segment k = 1 — block h (h = 1 … 17280) is a small
 * payload (one part; every height ≡ 7 mod 1000 is 70 000+ bytes, two
 * parts), header(h+1) names block h by v2_blocks[h] and its part-set
 * header, v2_blocks[h+1] = cmt_header_hash(header(h+1)); H:(h+1) holds
 * that header, P:h:i the parts, C:17280 a commit (two signatures, any
 * bytes) whose hash is header(17281).last_commit_hash. 17280 is the
 * consensus constant and is not shrunk.
 *
 * WHAT EACH CASE PINS DOWN
 *  roundtrip        export from the store → publish → read back: the data
 *                   file header (tag, k, count) and the first record's
 *                   prefix (h, header length, header(2) bytes, part
 *                   count); index size 207 408 with every entry matching
 *                   a re-read of its record; marker size 105, its tag, k,
 *                   sizes, flags 0 (no validators in the state store: the
 *                   commit is hash-bound only) and SHA3-512(index); every
 *                   part read back equals the store's raw P:h:i (heights
 *                   1, 7, 1007, 9000, 17280 — single and two-part
 *                   blocks); header(h+1) equals the marshalled meta;
 *                   the commit equals C:17280; held == 1.
 *  completeness     nothing is written for a piece that fails: a tampered
 *                   part (V_PROOF), a part with another index, a header
 *                   of another height / another chain position, a
 *                   commit of another height or with a flipped signature
 *                   (V_COMMIT_HASH); finish refuses an incomplete build;
 *                   a .dat without a valid marker is not held and goes
 *                   back to the resume scan; a marker whose index hash
 *                   does not match is not held.
 *  fetch_wire       the 0x73 request bytes at their offsets, rq = SHA3-512
 *                   of the 37-byte body; every malformed request refused
 *                   (short, long, kind, tag, padding, k 0, h outside k,
 *                   commit not at k·P, cont 2); an answer's refusal is
 *                   exactly kind ‖ rq ‖ code; an OK answer decodes only
 *                   within its bounds, without a trailing byte; the shape
 *                   rule (header iff cont 0, commit has no proof, a part
 *                   has one); the per-requester budget (spent / take,
 *                   reset at a new epoch, table full).
 *  fetch_e2e        a whole segment FETCHED piece by piece from a held
 *                   file (answers encoded, decoded, shape-checked, every
 *                   piece verified by the build) is byte-identical to the
 *                   export; the store and the file give the same answer;
 *                   a corrupted answer (part byte, proof, header, commit)
 *                   is refused before it is written.
 *  resume           a partial build closed mid-block with a torn tail is
 *                   reopened, re-verified, cut to the last complete
 *                   record and finished — byte-identical to the export; a
 *                   partial file whose record on disk was tampered is cut
 *                   AT that record.
 *  serve_refusals   nodus_witness_stfetch_serve: no epoch yet, no frozen
 *                   set, requester not in the set, in the set but no
 *                   registry row, EXITING, segment not published, nothing
 *                   held; then OK from the held file.
 *  overlap_delete   must-hold over a displaced holder: held at H (holder),
 *                   still held at H+E (the overlap epoch, still probed),
 *                   deleted at H+2E; the deletion removes only published
 *                   segments (a file of an unpublished k stays); nothing
 *                   is deleted while storage_set(H) is absent.
 *  probe_from_file  LAST (it prunes the fixture): the 0x72 answer built
 *                   from the block store; the sampled blocks deleted from
 *                   the store (pruned) → the store says NOT_HELD and the
 *                   segment file answers with the SAME bytes, which the
 *                   reporter's chain accepts against v2_blocks.
 *
 * WHAT IT DOES NOT COVER (how it can lie): the terminal commit's
 * SIGNATURE path (a state store holding validators(17280) and real
 * ML-DSA-87 commit signatures) is not built here — the fixture proves the
 * hash-binding path and the flag bit 0; the 4004 transport (0x73 on a
 * live host, peer rotation, timeouts), the holder's tick and the
 * retain_blocks warning run only on a live node (no harness scenario in
 * this package); the serving side's budget is proven as a function, not
 * through nodus_witness_sthold_on_msg.
 *
 * Requirements: a default build; no environment. Writes under a fresh
 * mkdtemp directory in $TMPDIR (or /tmp) and removes it at the end; the
 * databases are in memory. Run time: the fixture builds 17 280 blocks.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_cmt_store.h"
#include "witness/nodus_witness_storage_segment.h"
#include "witness/nodus_witness_storage_fetch.h"
#include "witness/nodus_witness_storage_holder.h"
#include "witness/nodus_witness_storage_probe.h"
#include "witness/nodus_witness_v2_storage.h"

#include "dnac/dnac.h"
#include "dnac/cmt_block.h"
#include "dnac/cmt_merkle.h"
#include "dnac/cmt_part_set.h"
#include "dnac/cmt_pb.h"
#include "dnac/cmt_pb_store.h"
#include "dnac/ledger_roots_v2.h"
#include "crypto/hash/qgp_sha3.h"

#include <dirent.h>
#include <fcntl.h>
#include <inttypes.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

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
static uint32_t be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

/* ── temp directories ────────────────────────────────────────────────── */

static char g_root[512];

static void rm_tree(const char *path) {
    DIR *d = opendir(path);
    if (d) {
        struct dirent *e;
        while ((e = readdir(d)) != NULL) {
            if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
                continue;
            char p[1024];
            snprintf(p, sizeof(p), "%s/%s", path, e->d_name);
            struct stat st;
            if (lstat(p, &st) == 0 && S_ISDIR(st.st_mode)) rm_tree(p);
            else unlink(p);
        }
        closedir(d);
    }
    rmdir(path);
}

static int mk_sub(const char *name, char *out, size_t cap) {
    int n = snprintf(out, cap, "%s/%s", g_root, name);
    if (n < 0 || (size_t)n >= cap) return -1;
    return mkdir(out, 0700) == 0 ? 0 : -1;
}

/* Whole file into a malloc'd buffer. */
static uint8_t *slurp(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *b = n > 0 ? malloc((size_t)n) : NULL;
    if (b && fread(b, 1, (size_t)n, f) != (size_t)n) { free(b); b = NULL; }
    fclose(f);
    if (b) *len = (size_t)n;
    return b;
}

static int files_equal(const char *a, const char *b) {
    size_t la = 0, lb = 0;
    uint8_t *x = slurp(a, &la), *y = slurp(b, &lb);
    int eq = x && y && la == lb && memcmp(x, y, la) == 0;
    free(x);
    free(y);
    return eq;
}

static int file_exists(const char *p) {
    struct stat st;
    return stat(p, &st) == 0;
}

/* ══ the fixture ═══════════════════════════════════════════════════════ */

typedef struct {
    sqlite3           *db;          /* cmt tables + v2_blocks            */
    nodus_cmt_store_t  store;
    uint8_t          (*v2)[64];     /* v2[h], h = 0 … P+1                 */
    uint8_t           *commit;      /* C:P                                */
    size_t             commit_len;
    char               export_dir[512];   /* the published export        */
} sfx_t;

static sfx_t G;

static int v2_put(sqlite3 *db, uint64_t h, const uint8_t id[64]) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, "INSERT INTO v2_blocks (global_height, "
                           "block_id) VALUES (?1, ?2)", -1, &st, NULL)
            != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)h);
    sqlite3_bind_blob(st, 2, id, 64, SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

static void hdr_fill(uint64_t hp1, const uint8_t prev[64],
                     const cmt_part_set_header_t *psh, cmt_pb_header_t *hd) {
    cmt_pb_header_init(hd);
    hd->version.block = CMT_BLOCK_PROTOCOL;
    memcpy(hd->chain_id, CHAIN, 32);
    hd->chain_id_len = 32;
    hd->height = (int64_t)hp1;
    hd->time.seconds = 1700000000 + (int64_t)hp1;
    hd->time.nanos = 0;
    memcpy(hd->last_block_id.hash, prev, 64);
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

/* The commit of P naming block_id {v2[P], psh}. */
static int commit_build(const uint8_t bh[64], const cmt_part_set_header_t *psh,
                        uint8_t *out, size_t cap, size_t *len,
                        uint8_t chash[64]) {
    cmt_pb_commit_t c;
    cmt_pb_commit_sig_t *sigs = calloc(2, sizeof(*sigs));
    if (!sigs) return -1;
    cmt_pb_commit_init(&c);
    c.height = (int64_t)P_LEN;
    c.round = 0;
    memcpy(c.block_id.hash, bh, 64);
    c.block_id.hash_len = 64;
    c.block_id.part_set_header = *psh;
    for (int i = 0; i < 2; i++) {
        cmt_pb_commit_sig_init(&sigs[i]);
        sigs[i].block_id_flag = CMT_BLOCK_ID_FLAG_COMMIT;
        fill(sigs[i].validator_address, 32, (uint8_t)(0x40 + i));
        sigs[i].validator_address_len = 32;
        sigs[i].timestamp.seconds = 1700000000 + (int64_t)P_LEN;
        sigs[i].timestamp.nanos = i;
        fill(sigs[i].signature, CMT_PB_SIG_MAX, (uint8_t)(0x60 + i));
        sigs[i].signature_len = CMT_PB_SIG_MAX;
    }
    c.signatures = sigs;
    c.signatures_cap = 2;
    c.signatures_len = 2;
    int ret = -1;
    if (cmt_pb_commit_marshal(&c, out, cap, len) == CMT_OK &&
        cmt_commit_hash(&c, chash) == CMT_OK)
        ret = 0;
    free(sigs);
    return ret;
}

static int fx_build(void) {
    memset(&G, 0, sizeof(G));
    if (sqlite3_open(":memory:", &G.db) != SQLITE_OK) return -1;
    if (sqlite3_exec(G.db,
            "CREATE TABLE cmt_blockstore (key BLOB PRIMARY KEY, "
            "value BLOB NOT NULL);"
            "CREATE TABLE cmt_state (key BLOB PRIMARY KEY, "
            "value BLOB NOT NULL);"
            "CREATE TABLE v2_blocks (global_height INTEGER PRIMARY KEY, "
            "block_id BLOB NOT NULL);", NULL, NULL, NULL) != SQLITE_OK)
        return -1;
    if (nodus_cmt_store_init(&G.store, G.db, false) != CMT_OK) return -1;
    G.v2 = calloc(P_LEN + 2, 64);
    G.commit = malloc(NODUS_SEG_COMMIT_MAX);
    uint8_t *data = malloc(70100);
    cmt_part_t *parts = calloc(4, sizeof(*parts));
    cmt_pb_header_t *hd = calloc(1, sizeof(*hd));
    cmt_pb_block_meta_t *bm = calloc(1, sizeof(*bm));
    uint8_t *buf = malloc(90000);
    int ret = -1;
    char key[NODUS_CMT_STORE_KEY_MAX];
    if (!G.v2 || !G.commit || !data || !parts || !hd || !bm || !buf)
        goto done;
    if (sqlite3_exec(G.db, "BEGIN", NULL, NULL, NULL) != SQLITE_OK) goto done;
    {
        const char seed[] = "segment-fixture-block-0";
        if (qgp_sha3_512((const uint8_t *)seed, sizeof(seed), G.v2[1]) != 0 ||
            v2_put(G.db, 1, G.v2[1]) != 0)
            goto done;
    }
    for (uint64_t h = 1; h <= P_LEN; h++) {
        const size_t len = (h % 1000u == 7u) ? 70000u + (size_t)(h % 13u)
                                             : 120u + (size_t)(h % 50u);
        for (size_t j = 0; j < len; j++)
            data[j] = (uint8_t)(h * 31u + j * 7u);
        cmt_part_set_t ps;
        cmt_part_set_header_t psh;
        if (cmt_new_part_set_from_data(data, len, CMT_BLOCK_PART_SIZE_BYTES,
                                       parts, 4, &ps) != CMT_OK ||
            cmt_part_set_header(&ps, &psh) != CMT_OK)
            goto done;
        for (uint32_t i = 0; i < ps.total; i++) {
            size_t n = 0;
            if (cmt_pb_part_marshal(&parts[i], buf, 90000, &n) != CMT_OK)
                goto done;
            snprintf(key, sizeof(key), "P:%" PRId64 ":%d", (int64_t)h, (int)i);
            if (nodus_cmt_store_set(&G.store, false, key, buf, n) != CMT_OK)
                goto done;
        }
        hdr_fill(h + 1, G.v2[h], &psh, hd);
        if (h == P_LEN) {
            uint8_t ch[64];
            if (commit_build(G.v2[h], &psh, G.commit, NODUS_SEG_COMMIT_MAX,
                             &G.commit_len, ch) != 0)
                goto done;
            memcpy(hd->last_commit_hash, ch, 64);
            snprintf(key, sizeof(key), "C:%" PRId64, (int64_t)h);
            if (nodus_cmt_store_set(&G.store, false, key, G.commit,
                                    G.commit_len) != CMT_OK)
                goto done;
        }
        if (cmt_header_hash(hd, G.v2[h + 1]) != CMT_OK ||
            v2_put(G.db, h + 1, G.v2[h + 1]) != 0)
            goto done;
        size_t n = 0;
        cmt_pb_store_block_meta_init(bm);
        memcpy(bm->block_id.hash, G.v2[h + 1], 64);
        bm->block_id.hash_len = 64;
        bm->block_id.part_set_header.total = 1;
        fill(bm->block_id.part_set_header.hash, 64, 0x77);
        bm->block_id.part_set_header.hash_len = 64;
        bm->header = *hd;
        bm->block_size = 1000;
        if (cmt_pb_store_block_meta_marshal(bm, buf, 90000, &n) != CMT_OK)
            goto done;
        snprintf(key, sizeof(key), "H:%" PRId64, (int64_t)(h + 1));
        if (nodus_cmt_store_set(&G.store, false, key, buf, n) != CMT_OK)
            goto done;
    }
    if (sqlite3_exec(G.db, "COMMIT", NULL, NULL, NULL) != SQLITE_OK) goto done;
    /* the store's Base / Height (store.go:57-58) as a node holding the
     * whole range would have them */
    G.store.base = 1;
    G.store.height = (int64_t)P_LEN + 1;
    ret = 0;
done:
    free(buf);
    free(bm);
    free(hd);
    free(parts);
    free(data);
    return ret;
}

/* Export segment 1 from the fixture store into `dir`, finish. */
static int export_all(const char *dir) {
    nodus_seg_build_t *b = NULL;
    if (nodus_seg_build_open(dir, 1, G.db, &b) != 0) return -1;
    while (nodus_seg_build_resume_step(b, 4096) == 0) { }
    for (;;) {
        int rc = nodus_seg_export_step(b, &G.store, 4096, NULL);
        if (rc == 1) break;
        if (rc < 0) { nodus_seg_build_free(b); return -1; }
    }
    return nodus_seg_build_finish(b);
}

static int raw_get(const char *key, uint8_t *out, size_t cap, size_t *len) {
    const uint8_t *v = NULL;
    size_t n = 0;
    if (nodus_cmt_store_get(&G.store, false, key, &v, &n) != CMT_OK ||
        n == 0 || n > cap)
        return -1;
    memcpy(out, v, n);
    *len = n;
    return 0;
}

/* ══ roundtrip ═════════════════════════════════════════════════════════ */

static int t_roundtrip(void) {
    char p[NODUS_SEG_PATH_MAX];
    CHECK(mk_sub("export", G.export_dir, sizeof(G.export_dir)) == 0, "dir");
    CHECK(nodus_seg_held(G.export_dir, 1) == 0, "nothing held before");
    CHECK(nodus_seg_store_has(&G.store, 1), "the store has segment 1");
    CHECK(!nodus_seg_store_has(&G.store, 2), "but not segment 2");
    CHECK(export_all(G.export_dir) == 0, "export + publish");
    CHECK(nodus_seg_held(G.export_dir, 1) == 1, "held after publish");
    CHECK(nodus_seg_path(G.export_dir, 1, NODUS_SEG_F_DAT_TMP, p,
                         sizeof(p)) == 0 && !file_exists(p),
          "no temporary left");

    /* the data file: header and the first record's prefix */
    size_t dl = 0, il = 0, ml = 0;
    CHECK(nodus_seg_path(G.export_dir, 1, NODUS_SEG_F_DAT, p, sizeof(p)) == 0,
          "path");
    uint8_t *dat = slurp(p, &dl);
    CHECK(dat && dl > NODUS_SEG_DATA_HDR_LEN, "data file");
    {
        static const uint8_t tag[16] = { 'N', 'D', 'S', '.', 'S', 'E', 'G',
                                         'F', 'I', 'L', 'E', '.', 'v', '1',
                                         0, 0 };
        CHECK(memcmp(dat, tag, 16) == 0, "data tag NDS.SEGFILE.v1 padded");
    }
    CHECK(be64(dat + 16) == 1 && be32(dat + 24) == 17280u, "k, count");
    const uint8_t *r0 = dat + NODUS_SEG_DATA_HDR_LEN;
    CHECK(be64(r0) == 1, "record 0 is height 1");
    const uint32_t hl0 = be32(r0 + 8);
    {
        nodus_cmt_block_meta_t *m = malloc(sizeof(*m));
        uint8_t hb[NODUS_SEG_HEADER_MAX];
        size_t n = 0;
        bool found = false;
        CHECK(m && nodus_cmt_bs_load_block_meta(&G.store, 2, m, &found) ==
                       CMT_OK && found, "meta 2");
        CHECK(cmt_pb_header_marshal(&m->header, hb, sizeof(hb), &n) == CMT_OK,
              "marshal header(2)");
        CHECK(n == hl0 && memcmp(r0 + 12, hb, n) == 0,
              "record 0 carries header(2), the successor header");
        CHECK(be32(r0 + 12 + hl0) == 1, "height 1 has one part");
        free(m);
    }

    /* the index */
    CHECK(nodus_seg_path(G.export_dir, 1, NODUS_SEG_F_IDX, p, sizeof(p)) == 0,
          "path");
    uint8_t *idx = slurp(p, &il);
    CHECK(idx && il == NODUS_SEG_INDEX_LEN && il == 207408u, "index size");
    CHECK(be64(idx + 16) == 1 && be32(idx + 24) == 17280u, "index k, count");
    CHECK(be64(idx + 28) == NODUS_SEG_DATA_HDR_LEN && be32(idx + 36) == 1,
          "entry 0: offset of record 0, one part");
    {
        const uint8_t *t = idx + 28 + 17280u * 12u;
        CHECK(be64(t + 12) == dl, "index data_size");
        CHECK(be32(t + 8) == G.commit_len &&
              memcmp(dat + be64(t), G.commit, G.commit_len) == 0,
              "commit offset / length point at C:17280");
    }
    for (uint64_t h = 1; h <= P_LEN; h += 997) {
        const uint8_t *e = idx + 28 + (h - 1) * 12;
        CHECK(be64(dat + be64(e)) == h, "every sampled entry points at its "
              "record");
    }

    /* the marker */
    CHECK(nodus_seg_path(G.export_dir, 1, NODUS_SEG_F_OK, p, sizeof(p)) == 0,
          "path");
    uint8_t *mk = slurp(p, &ml);
    CHECK(mk && ml == 105u, "marker size");
    {
        static const uint8_t tag[16] = { 'N', 'D', 'S', '.', 'S', 'E', 'G',
                                         'D', 'O', 'N', 'E', '.', 'v', '1',
                                         0, 0 };
        uint8_t hx[64];
        CHECK(memcmp(mk, tag, 16) == 0, "marker tag");
        CHECK(be64(mk + 16) == 1 && be64(mk + 24) == dl &&
              be64(mk + 32) == il, "marker k / sizes");
        CHECK(mk[40] == 0, "flags 0: no validators here, hash-bound only");
        CHECK(qgp_sha3_512(idx, il, hx) == 0 && memcmp(hx, mk + 41, 64) == 0,
              "marker carries SHA3-512(index)");
    }

    /* read back through the reader */
    nodus_seg_reader_t *r = NULL;
    CHECK(nodus_seg_reader_open(G.export_dir, 1, &r) == 0, "reader");
    CHECK(nodus_seg_reader_flags(r) == 0, "reader flags");
    {
        static const uint64_t hs[5] = { 1, 7, 1007, 9000, 17280 };
        uint8_t *a = malloc(NODUS_SEG_PART_PROTO_MAX);
        uint8_t *b = malloc(NODUS_SEG_PART_PROTO_MAX);
        uint8_t hb[NODUS_SEG_HEADER_MAX];
        CHECK(a && b, "alloc");
        for (int i = 0; i < 5; i++) {
            uint32_t n = 0;
            size_t hlen = 0;
            CHECK(nodus_seg_reader_get(r, hs[i], hb, &hlen, &n, 0, NULL,
                                       NULL) == 0, "header + count");
            CHECK(n == ((hs[i] % 1000u == 7u) ? 2u : 1u), "part count");
            for (uint32_t j = 0; j < n; j++) {
                size_t la = 0, lb = 0;
                char key[NODUS_CMT_STORE_KEY_MAX];
                snprintf(key, sizeof(key), "P:%" PRId64 ":%d",
                         (int64_t)hs[i], (int)j);
                CHECK(nodus_seg_reader_get(r, hs[i], NULL, NULL, &n, j, a,
                                           &la) == 0, "part");
                CHECK(raw_get(key, b, NODUS_SEG_PART_PROTO_MAX, &lb) == 0 &&
                      la == lb && memcmp(a, b, la) == 0,
                      "the part as stored (P:h:i)");
            }
            uint32_t n2 = 0;
            size_t la = 0;
            CHECK(nodus_seg_reader_get(r, hs[i], NULL, NULL, &n2, n, a, &la)
                      == 1, "a part past the count");
        }
        uint32_t n = 0;
        CHECK(nodus_seg_reader_get(r, 0, NULL, NULL, &n, 0, NULL, NULL) == 1 &&
              nodus_seg_reader_get(r, P_LEN + 1, NULL, NULL, &n, 0, NULL,
                                   NULL) == 1, "heights outside segment 1");
        size_t cl = 0;
        uint8_t *cb = malloc(NODUS_SEG_COMMIT_MAX);
        CHECK(cb && nodus_seg_reader_commit(r, cb, NODUS_SEG_COMMIT_MAX, &cl)
                        == 0 && cl == G.commit_len &&
              memcmp(cb, G.commit, cl) == 0, "the terminal commit");
        free(cb);
        free(a);
        free(b);
    }
    nodus_seg_reader_close(r);
    CHECK(nodus_seg_build_open(G.export_dir, 1, G.db, &(nodus_seg_build_t *){
              NULL }) != 0 && nodus_seg_held(G.export_dir, 1) == 1,
          "a held segment is never reopened (its marker stays)");
    free(mk);
    free(idx);
    free(dat);
    return 0;
}

/* ══ completeness ══════════════════════════════════════════════════════ */

/* header(h+1) proto and the raw part i of height h, from the fixture */
static int piece(uint64_t h, uint32_t i, uint8_t *hb, size_t *hl,
                 uint8_t *pp, size_t *pl) {
    nodus_cmt_block_meta_t *m = malloc(sizeof(*m));
    bool found = false;
    int ret = -1;
    char key[NODUS_CMT_STORE_KEY_MAX];
    if (m && nodus_cmt_bs_load_block_meta(&G.store, (int64_t)h + 1, m,
                                          &found) == CMT_OK && found &&
        cmt_pb_header_marshal(&m->header, hb, NODUS_SEG_HEADER_MAX, hl)
            == CMT_OK) {
        snprintf(key, sizeof(key), "P:%" PRId64 ":%d", (int64_t)h, (int)i);
        if (!pp || raw_get(key, pp, NODUS_SEG_PART_PROTO_MAX, pl) == 0)
            ret = 0;
    }
    free(m);
    return ret;
}

static int t_completeness(void) {
    char dir[512], p[NODUS_SEG_PATH_MAX];
    CHECK(mk_sub("complete", dir, sizeof(dir)) == 0, "dir");
    nodus_seg_build_t *b = NULL;
    CHECK(nodus_seg_build_open(dir, 1, G.db, &b) == 0, "open");
    CHECK(nodus_seg_build_resume_step(b, 1) == 1, "nothing to resume");
    CHECK(nodus_seg_build_finish(b) != 0, "finish refuses an empty build");

    uint8_t hb[NODUS_SEG_HEADER_MAX], *pp = malloc(NODUS_SEG_PART_PROTO_MAX);
    size_t hl = 0, pl = 0;
    CHECK(pp && piece(1, 0, hb, &hl, pp, &pl) == 0, "piece 1");
    CHECK(nodus_seg_path(dir, 1, NODUS_SEG_F_DAT_TMP, p, sizeof(p)) == 0,
          "path");
    struct stat st0, st1;
    CHECK(stat(p, &st0) == 0 && st0.st_size == NODUS_SEG_DATA_HDR_LEN,
          "only the data header so far");

    /* a part before its header */
    CHECK(nodus_seg_build_put_part_proto(b, 1, 0, pp, pl) == NODUS_SEG_V_ORDER,
          "a part needs its header first");
    /* header(h+1) of the wrong height, then of the wrong chain position */
    {
        uint8_t h2[NODUS_SEG_HEADER_MAX];
        size_t l2 = 0;
        CHECK(piece(2, 0, h2, &l2, NULL, NULL) == 0, "header(3)");
        CHECK(nodus_seg_build_put_header(b, 1, h2, l2) ==
              NODUS_SEG_V_HEADER_HASH, "header(3) offered as header(2)");
        uint8_t bad[NODUS_SEG_HEADER_MAX];
        memcpy(bad, hb, hl);
        bad[hl / 2] ^= 0x01;
        nodus_seg_v_t v = nodus_seg_build_put_header(b, 1, bad, hl);
        CHECK(v == NODUS_SEG_V_HEADER_HASH || v == NODUS_SEG_V_HEADER_DECODE,
              "a flipped header byte");
        CHECK(nodus_seg_build_put_header(b, 2, hb, hl) == NODUS_SEG_V_ORDER,
              "not the height the build is on");
    }
    CHECK(stat(p, &st1) == 0 && st1.st_size == st0.st_size,
          "a refused header writes nothing");
    CHECK(nodus_seg_build_put_header(b, 1, hb, hl) == NODUS_SEG_V_OK, "header");
    CHECK(stat(p, &st0) == 0, "stat");
    {
        /* the part's payload is the proto's field 2: flip its last byte —
         * the proof no longer holds */
        uint8_t *bad = malloc(pl);
        CHECK(bad != NULL, "alloc");
        memcpy(bad, pp, pl);
        cmt_part_t *pt = malloc(sizeof(*pt));
        uint8_t *ab = malloc(CMT_BLOCK_PART_SIZE_BYTES);
        cmt_pb_arena_t ar = { ab, CMT_BLOCK_PART_SIZE_BYTES, 0 };
        CHECK(pt && ab && cmt_pb_part_unmarshal(pp, pl, pt, &ar) == CMT_OK,
              "decode the part");
        /* find the payload inside the proto and flip its first byte */
        const uint8_t *pay = pt->bytes.data;
        size_t at = 0;
        for (; at + pt->bytes.len <= pl; at++)
            if (memcmp(pp + at, pay, pt->bytes.len) == 0) break;
        CHECK(at + pt->bytes.len <= pl, "payload located");
        bad[at] ^= 0x5A;
        CHECK(nodus_seg_build_put_part_proto(b, 1, 0, bad, pl) ==
              NODUS_SEG_V_PROOF, "a tampered part: the proof refuses it");
        CHECK(nodus_seg_build_put_part(b, 1, 0, bad + at, pt->bytes.len,
                                       pp, 0) != NODUS_SEG_V_OK,
              "a part with no proof");
        free(ab);
        free(pt);
        free(bad);
    }
    CHECK(nodus_seg_build_put_part_proto(b, 1, 1, pp, pl) == NODUS_SEG_V_ORDER,
          "part 1 before part 0");
    CHECK(stat(p, &st1) == 0 && st1.st_size == st0.st_size,
          "a refused part writes nothing");
    CHECK(nodus_seg_build_put_part_proto(b, 1, 0, pp, pl) == NODUS_SEG_V_OK,
          "the honest part");
    {
        /* height 2: another block's parts offered in its place */
        uint8_t h3[NODUS_SEG_HEADER_MAX], hx[NODUS_SEG_HEADER_MAX];
        size_t l3 = 0, lx = 0, p7l = 0;
        uint8_t *p7 = malloc(NODUS_SEG_PART_PROTO_MAX);
        CHECK(p7 && piece(2, 0, h3, &l3, NULL, NULL) == 0 &&
              piece(1007, 1, hx, &lx, p7, &p7l) == 0, "pieces");
        CHECK(nodus_seg_build_put_header(b, 2, h3, l3) == NODUS_SEG_V_OK,
              "header(3)");
        CHECK(nodus_seg_build_put_part_proto(b, 2, 0, pp, pl) ==
              NODUS_SEG_V_PROOF,
              "block 1's part 0 for block 2's: the proof refuses it");
        CHECK(nodus_seg_build_put_part_proto(b, 2, 0, p7, p7l) ==
              NODUS_SEG_V_PART_INDEX,
              "block 1007's part 1 for part 0: another index");
        free(p7);
    }
    nodus_seg_build_discard(b);
    CHECK(!file_exists(p), "discard removes the temporary");

    /* a commit refused: build a fresh one up to the commit by export,
     * then offer bad commits */
    CHECK(nodus_seg_build_open(dir, 1, G.db, &b) == 0 &&
          nodus_seg_build_resume_step(b, 1) == 1, "reopen");
    /* every height but the last by export (an export step that reaches
     * the end adds the commit too), the last one by hand */
    CHECK(nodus_seg_export_step(b, &G.store, (uint32_t)P_LEN - 1, NULL) == 0,
          "heights 1 … 17279");
    {
        size_t lp = 0;
        CHECK(piece(P_LEN, 0, hb, &hl, pp, &lp) == 0, "piece 17280");
        CHECK(nodus_seg_build_put_header(b, P_LEN, hb, hl) == NODUS_SEG_V_OK &&
              nodus_seg_build_put_part_proto(b, P_LEN, 0, pp, lp) ==
                  NODUS_SEG_V_OK, "height 17280");
        uint64_t h = 0;
        uint32_t part = 0;
        bool nh = true;
        CHECK(nodus_seg_build_next(b, &h, &part, &nh) == 0 && h == P_LEN &&
              part == NODUS_SEG_PART_COMMIT && !nh,
              "the commit is next, header(17281) already held");
    }
    {
        uint8_t *bad = malloc(G.commit_len);
        CHECK(bad != NULL, "alloc");
        memcpy(bad, G.commit, G.commit_len);
        bad[G.commit_len - 10] ^= 0x01;          /* inside a signature */
        nodus_seg_v_t v = nodus_seg_build_put_commit(b, bad, G.commit_len,
                                                     &G.store);
        CHECK(v == NODUS_SEG_V_COMMIT_HASH || v == NODUS_SEG_V_COMMIT_DECODE,
              "a flipped commit byte breaks the hash binding");
        free(bad);
        CHECK(nodus_seg_build_finish(b) != 0,
              "finish refuses a build without its terminal commit");
        CHECK(nodus_seg_build_put_commit(b, G.commit, G.commit_len, &G.store)
                  == NODUS_SEG_V_OK, "the honest commit (hash-bound)");
        CHECK(nodus_seg_build_put_commit(b, G.commit, G.commit_len, &G.store)
                  == NODUS_SEG_V_ORDER, "only one terminal commit");
    }
    CHECK(nodus_seg_build_finish(b) == 0, "complete → published");
    CHECK(nodus_seg_held(dir, 1) == 1, "held");

    /* a marker that does not agree: not held; a .dat without a marker is
     * moved back to the resume scan */
    {
        char ok[NODUS_SEG_PATH_MAX], dat[NODUS_SEG_PATH_MAX];
        CHECK(nodus_seg_path(dir, 1, NODUS_SEG_F_OK, ok, sizeof(ok)) == 0 &&
              nodus_seg_path(dir, 1, NODUS_SEG_F_DAT, dat, sizeof(dat)) == 0,
              "paths");
        size_t ml = 0;
        uint8_t *mk = slurp(ok, &ml);
        CHECK(mk && ml == 105, "marker");
        mk[41] ^= 1;                              /* the index hash */
        FILE *f = fopen(ok, "wb");
        CHECK(f && fwrite(mk, 1, ml, f) == ml, "rewrite marker");
        fclose(f);
        free(mk);
        CHECK(nodus_seg_held(dir, 1) == 0, "an index hash mismatch: not held");
        CHECK(unlink(ok) == 0, "drop the marker");
        CHECK(nodus_seg_held(dir, 1) == 0, "no marker: not held");
        CHECK(nodus_seg_build_open(dir, 1, G.db, &b) == 0,
              "reopen a published file without a marker");
        CHECK(!file_exists(dat) && file_exists(p),
              "the data file is back under the resume scan");
        int rc;
        while ((rc = nodus_seg_build_resume_step(b, 4096)) == 0) { }
        CHECK(rc == 1, "every record re-verified");
        uint64_t h = 0;
        uint32_t part = 0;
        bool nh = false;
        CHECK(nodus_seg_build_next(b, &h, &part, &nh) == 0 &&
              part == NODUS_SEG_PART_COMMIT,
              "the scan keeps every height, re-adds the commit");
        CHECK(nodus_seg_build_put_commit(b, G.commit, G.commit_len, &G.store)
                  == NODUS_SEG_V_OK && nodus_seg_build_finish(b) == 0,
              "finished again");
        char ref[NODUS_SEG_PATH_MAX];
        CHECK(nodus_seg_path(G.export_dir, 1, NODUS_SEG_F_DAT, ref,
                             sizeof(ref)) == 0 && files_equal(dat, ref),
              "identical to the export");
    }
    free(pp);
    return 0;
}

/* ══ fetch_wire ════════════════════════════════════════════════════════ */

static int t_fetch_wire(void) {
    nodus_stfetch_req_t r = { 3, 2 * P_LEN + 5, 1, NODUS_STFETCH_CONT_FIRST };
    nodus_stfetch_req_t d;
    uint8_t m[NODUS_STFETCH_REQ_MSG_LEN];
    CHECK(nodus_stfetch_req_encode(&r, m) == 0, "encode");
    CHECK(sizeof(m) == 38 && m[0] == NODUS_STFETCH_KIND_REQ, "kind ‖ 37");
    {
        static const uint8_t tag[16] = { 'N', 'D', 'S', '.', 'S', 'T', 'F',
                                         'E', 'T', 'C', 'H', '.', 'v', '1',
                                         0, 0 };
        CHECK(memcmp(m + 1, tag, 16) == 0, "padded tag");
    }
    CHECK(be64(m + 17) == 3 && be64(m + 25) == 2 * P_LEN + 5 &&
          be32(m + 33) == 1 && m[37] == 0, "k, h, part, cont at their offsets");
    {
        uint8_t rq[64], want[64];
        CHECK(nodus_stfetch_req_id(&r, rq) == 0 &&
              qgp_sha3_512(m + 1, 37, want) == 0 && memcmp(rq, want, 64) == 0,
              "rq = SHA3-512(the 37 body bytes)");
    }
    CHECK(nodus_stfetch_req_decode(m, sizeof(m), &d) == 0 && d.k == r.k &&
          d.h == r.h && d.part == r.part && d.cont == r.cont, "round trip");
    CHECK(nodus_stfetch_req_decode(m, sizeof(m) - 1, &d) != 0, "short");
    {
        uint8_t l[NODUS_STFETCH_REQ_MSG_LEN + 1];
        memcpy(l, m, sizeof(m));
        l[sizeof(m)] = 0;
        CHECK(nodus_stfetch_req_decode(l, sizeof(l), &d) != 0, "long");
    }
#define MUT(off, val, what) do { \
        uint8_t x[NODUS_STFETCH_REQ_MSG_LEN]; \
        memcpy(x, m, sizeof(m)); \
        x[off] = (uint8_t)(val); \
        CHECK(nodus_stfetch_req_decode(x, sizeof(x), &d) != 0, what); \
    } while (0)
    MUT(0, NODUS_STFETCH_KIND_ANS, "wrong kind");
    MUT(1 + 13, '2', "wrong tag");
    MUT(1 + 15, 1, "tag padding not zero");
    MUT(37, 2, "cont 2");
#undef MUT
    {
        nodus_stfetch_req_t q = r;
        q.k = 0;
        CHECK(nodus_stfetch_req_encode(&q, m) != 0, "k 0");
        q = r;
        q.h = 2 * P_LEN;                         /* segment 2's last */
        CHECK(nodus_stfetch_req_encode(&q, m) != 0, "h outside segment k");
        q = r;
        q.part = NODUS_SEG_PART_COMMIT;
        CHECK(nodus_stfetch_req_encode(&q, m) != 0, "commit not at k·P");
        q.h = 3 * P_LEN;
        CHECK(nodus_stfetch_req_encode(&q, m) == 0 &&
              nodus_stfetch_req_decode(m, sizeof(m), &d) == 0 &&
              d.part == NODUS_SEG_PART_COMMIT, "commit at k·P");
    }

    /* answers */
    uint8_t rq[64], ref[NODUS_STFETCH_REFUSAL_LEN];
    nodus_stfetch_ans_view_t a;
    fill(rq, 64, 0x31);
    CHECK(nodus_stfetch_ans_refusal(rq, NODUS_STFETCH_OK, ref) != 0,
          "OK is never a refusal");
    CHECK(nodus_stfetch_ans_refusal(rq, NODUS_STFETCH_REF_BUDGET, ref) == 0 &&
          ref[0] == NODUS_STFETCH_KIND_ANS && memcmp(ref + 1, rq, 64) == 0 &&
          ref[65] == NODUS_STFETCH_REF_BUDGET, "kind ‖ rq ‖ code");
    CHECK(nodus_stfetch_ans_decode(ref, sizeof(ref), &a) == 0 &&
          a.code == NODUS_STFETCH_REF_BUDGET, "refusal decodes");
    {
        uint8_t l[NODUS_STFETCH_REFUSAL_LEN + 1];
        memcpy(l, ref, sizeof(ref));
        l[sizeof(ref)] = 0;
        CHECK(nodus_stfetch_ans_decode(l, sizeof(l), &a) != 0,
              "a refusal carries nothing more");
    }
    uint8_t *out = malloc(NODUS_STFETCH_MSG_MAX + 1);
    uint8_t hdr[100], body[300], proof[80];
    size_t len = 0;
    CHECK(out != NULL, "alloc");
    fill(hdr, sizeof(hdr), 1);
    fill(body, sizeof(body), 2);
    fill(proof, sizeof(proof), 3);
    CHECK(nodus_stfetch_ans_encode(rq, hdr, sizeof(hdr), body, sizeof(body),
                                   proof, sizeof(proof), out,
                                   NODUS_STFETCH_MSG_MAX, &len) == 0 &&
          len == 66 + 12 + 100 + 300 + 80, "OK answer length");
    CHECK(nodus_stfetch_ans_decode(out, len, &a) == 0 && a.hdr_len == 100 &&
          a.body_len == 300 && a.proof_len == 80 &&
          memcmp(a.body, body, 300) == 0, "OK answer decodes");
    CHECK(nodus_stfetch_ans_decode(out, len - 1, &a) != 0, "truncated");
    out[len] = 0;
    CHECK(nodus_stfetch_ans_decode(out, len + 1, &a) != 0, "trailing byte");
    out[66] = 0; out[67] = 0; out[68] = 0x08; out[69] = 0x01;   /* 2049 */
    CHECK(nodus_stfetch_ans_decode(out, len, &a) != 0, "header past 2048");
    CHECK(nodus_stfetch_ans_encode(rq, hdr, sizeof(hdr), body, sizeof(body),
                                   proof, NODUS_STPROBE_PROOF_MAX + 1, out,
                                   NODUS_STFETCH_MSG_MAX, &len) != 0,
          "proof past 8192 not encoded");

    /* the shape rule */
    {
        nodus_stfetch_req_t pr = { 1, 5, 0, NODUS_STFETCH_CONT_FIRST };
        nodus_stfetch_req_t cr = { 1, P_LEN, NODUS_SEG_PART_COMMIT,
                                   NODUS_STFETCH_CONT_HAVE_HDR };
        nodus_stfetch_ans_view_t v;
        memset(&v, 0, sizeof(v));
        v.code = NODUS_STFETCH_OK;
        v.hdr = hdr;  v.hdr_len = 100;
        v.body = body; v.body_len = 300;
        v.proof = proof; v.proof_len = 80;
        CHECK(nodus_stfetch_ans_shape_ok(&pr, &v), "part with header + proof");
        v.hdr_len = 0;
        CHECK(!nodus_stfetch_ans_shape_ok(&pr, &v),
              "cont 0 needs the header");
        v.hdr_len = 100;
        v.proof_len = 0;
        CHECK(!nodus_stfetch_ans_shape_ok(&pr, &v), "a part needs its proof");
        CHECK(!nodus_stfetch_ans_shape_ok(&cr, &v),
              "cont 1 must not carry a header");
        v.hdr_len = 0;
        CHECK(nodus_stfetch_ans_shape_ok(&cr, &v), "commit: body, no proof");
        v.proof_len = 80;
        CHECK(!nodus_stfetch_ans_shape_ok(&cr, &v), "commit with a proof");
        v.code = NODUS_STFETCH_REF_NOT_HELD;
        CHECK(!nodus_stfetch_ans_shape_ok(&cr, &v), "a refusal has no shape");
    }

    /* the budget */
    {
        nodus_stfetch_budget_t *s = calloc(2, sizeof(*s));
        uint8_t a1[64], a2[64], a3[64];
        fill(a1, 64, 0xA1);
        fill(a2, 64, 0xA2);
        fill(a3, 64, 0xA3);
        const uint64_t H = 5 * E_LEN;
        CHECK(s != NULL, "alloc");
        CHECK(!nodus_stfetch_budget_spent(s, 2, a1, H), "fresh: not spent");
        CHECK(nodus_stfetch_budget_take(s, 2, a1, H,
                                        NODUS_STFETCH_EPOCH_BUDGET - 1) == 0,
              "charge all but one byte");
        CHECK(!nodus_stfetch_budget_spent(s, 2, a1, H), "one byte left");
        CHECK(nodus_stfetch_budget_take(s, 2, a1, H, 4096) == 0,
              "the last answer may overrun");
        CHECK(nodus_stfetch_budget_spent(s, 2, a1, H) &&
              nodus_stfetch_budget_take(s, 2, a1, H, 1) == 1,
              "spent: refused");
        CHECK(nodus_stfetch_budget_take(s, 2, a2, H, 10) == 0, "a second "
              "requester has its own budget");
        CHECK(nodus_stfetch_budget_take(s, 2, a3, H, 10) == 1,
              "table full of this epoch's requesters: refused");
        CHECK(!nodus_stfetch_budget_spent(s, 2, a1, H + E_LEN) &&
              nodus_stfetch_budget_take(s, 2, a1, H + E_LEN, 10) == 0,
              "a new epoch resets the budget");
        CHECK(nodus_stfetch_budget_take(s, 2, a3, H + E_LEN, 10) == 0,
              "a slot of an older epoch is reused");
        free(s);
    }
    free(out);
    return 0;
}

/* ══ fetch_e2e ═════════════════════════════════════════════════════════
 * The client loop without a network: next → request → the server's
 * answer (from the HELD export) → encode / decode / shape → put. */

static int fetch_one(nodus_seg_build_t *b, const char *src_dir,
                     nodus_cmt_store_t *src_store, uint8_t *ans,
                     int corrupt) {
    uint64_t h = 0;
    uint32_t part = 0;
    bool nh = false;
    if (nodus_seg_build_next(b, &h, &part, &nh) != 0) return -1;
    nodus_stfetch_req_t r = { nodus_seg_build_k(b), h, part,
                              nh ? NODUS_STFETCH_CONT_FIRST
                                 : NODUS_STFETCH_CONT_HAVE_HDR };
    uint8_t m[NODUS_STFETCH_REQ_MSG_LEN];
    nodus_stfetch_req_t got;
    size_t len = 0;
    if (nodus_stfetch_req_encode(&r, m) != 0 ||
        nodus_stfetch_req_decode(m, sizeof(m), &got) != 0)
        return -1;
    if (nodus_stfetch_answer_build(src_store, src_dir, &got, ans,
                                   NODUS_STFETCH_MSG_MAX, &len)
            != NODUS_STFETCH_OK)
        return -1;
    nodus_stfetch_ans_view_t a;
    if (nodus_stfetch_ans_decode(ans, len, &a) != 0 ||
        !nodus_stfetch_ans_shape_ok(&r, &a))
        return -1;
    if (corrupt) ans[len - 1] ^= 0x01;    /* the last byte of proof/body */
    nodus_seg_v_t v = NODUS_SEG_V_OK;
    if (a.hdr_len) v = nodus_seg_build_put_header(b, h, a.hdr, a.hdr_len);
    if (v != NODUS_SEG_V_OK) return 2;
    if (part == NODUS_SEG_PART_COMMIT)
        v = nodus_seg_build_put_commit(b, a.body, a.body_len, NULL);
    else
        v = nodus_seg_build_put_part(b, h, part, a.body, a.body_len, a.proof,
                                     a.proof_len);
    return v == NODUS_SEG_V_OK ? 0 : 2;
}

static int t_fetch_e2e(void) {
    char dir[512], p[NODUS_SEG_PATH_MAX], ref[NODUS_SEG_PATH_MAX];
    uint8_t *ans = malloc(NODUS_STFETCH_MSG_MAX);
    uint8_t *ans2 = malloc(NODUS_STFETCH_MSG_MAX);
    CHECK(ans && ans2, "alloc");
    CHECK(mk_sub("fetch", dir, sizeof(dir)) == 0, "dir");

    /* the store and the file answer the same bytes */
    {
        static const nodus_stfetch_req_t rs[4] = {
            { 1, 1007, 1, NODUS_STFETCH_CONT_FIRST },
            { 1, 1007, 0, NODUS_STFETCH_CONT_HAVE_HDR },
            { 1, P_LEN, NODUS_SEG_PART_COMMIT, NODUS_STFETCH_CONT_FIRST },
            { 1, P_LEN, NODUS_SEG_PART_COMMIT, NODUS_STFETCH_CONT_HAVE_HDR } };
        for (int i = 0; i < 4; i++) {
            size_t l1 = 0, l2 = 0;
            CHECK(nodus_stfetch_answer_build(&G.store, NULL, &rs[i], ans,
                                             NODUS_STFETCH_MSG_MAX, &l1) ==
                  NODUS_STFETCH_OK, "from the store");
            CHECK(nodus_stfetch_answer_build(NULL, G.export_dir, &rs[i], ans2,
                                             NODUS_STFETCH_MSG_MAX, &l2) ==
                  NODUS_STFETCH_OK, "from the file");
            CHECK(l1 == l2 && memcmp(ans, ans2, l1) == 0,
                  "store and file give the same answer");
        }
        nodus_stfetch_req_t past = { 1, 5, 1, NODUS_STFETCH_CONT_FIRST };
        size_t l = 0;
        CHECK(nodus_stfetch_answer_build(&G.store, G.export_dir, &past, ans,
                                         NODUS_STFETCH_MSG_MAX, &l) ==
              NODUS_STFETCH_REF_NOT_HELD && l == 0,
              "a part past the block's count is not held");
        CHECK(nodus_stfetch_answer_build(NULL, dir, &past, ans,
                                         NODUS_STFETCH_MSG_MAX, &l) ==
              NODUS_STFETCH_REF_NOT_HELD, "nothing held in an empty dir");
    }

    nodus_seg_build_t *b = NULL;
    CHECK(nodus_seg_build_open(dir, 1, G.db, &b) == 0 &&
          nodus_seg_build_resume_step(b, 1) == 1, "open");
    /* corrupted answers are refused and nothing is written */
    CHECK(fetch_one(b, G.export_dir, NULL, ans, 1) == 2,
          "a corrupted proof byte (height 1) is refused");
    CHECK(fetch_one(b, G.export_dir, NULL, ans, 0) == 0, "then the honest one");
    int n = 1, rc;
    while ((rc = fetch_one(b, G.export_dir, NULL, ans, 0)) == 0) n++;
    CHECK(rc == -1 && nodus_seg_build_next(b, &(uint64_t){0},
                                           &(uint32_t){0},
                                           &(bool){false}) == 1,
          "every piece fetched");
    CHECK(n == 17280 + 18 + 1, "one request per part and one for the commit");
    CHECK(nodus_seg_build_finish(b) == 0, "published");
    CHECK(nodus_seg_path(dir, 1, NODUS_SEG_F_DAT, p, sizeof(p)) == 0 &&
          nodus_seg_path(G.export_dir, 1, NODUS_SEG_F_DAT, ref, sizeof(ref))
              == 0 && files_equal(p, ref),
          "the fetched data file is byte-identical to the export");
    CHECK(nodus_seg_path(dir, 1, NODUS_SEG_F_IDX, p, sizeof(p)) == 0 &&
          nodus_seg_path(G.export_dir, 1, NODUS_SEG_F_IDX, ref, sizeof(ref))
              == 0 && files_equal(p, ref), "and its index");
    free(ans2);
    free(ans);
    return 0;
}

/* ══ resume ════════════════════════════════════════════════════════════ */

static int t_resume(void) {
    char dir[512], p[NODUS_SEG_PATH_MAX], ref[NODUS_SEG_PATH_MAX];
    uint8_t *ans = malloc(NODUS_STFETCH_MSG_MAX);
    CHECK(ans != NULL, "alloc");
    CHECK(mk_sub("resume", dir, sizeof(dir)) == 0, "dir");
    CHECK(nodus_seg_path(dir, 1, NODUS_SEG_F_DAT_TMP, p, sizeof(p)) == 0,
          "path");

    /* download up to the middle of block 1007 (2 parts): header + part 0 */
    nodus_seg_build_t *b = NULL;
    CHECK(nodus_seg_build_open(dir, 1, G.db, &b) == 0 &&
          nodus_seg_build_resume_step(b, 1) == 1, "open");
    for (;;) {
        uint64_t h = 0;
        uint32_t part = 0;
        bool nh = false;
        CHECK(nodus_seg_build_next(b, &h, &part, &nh) == 0, "next");
        if (h == 1007 && part == 1) break;
        CHECK(fetch_one(b, G.export_dir, NULL, ans, 0) == 0, "fetch");
    }
    nodus_seg_build_free(b);                     /* the "crash" */
    {
        /* a torn tail: half a length prefix */
        FILE *f = fopen(p, "ab");
        CHECK(f && fwrite("\x00\x01", 1, 2, f) == 2, "tear");
        fclose(f);
    }
    CHECK(nodus_seg_build_open(dir, 1, G.db, &b) == 0, "reopen");
    int rc;
    while ((rc = nodus_seg_build_resume_step(b, 64)) == 0) { }
    CHECK(rc == 1, "scan over");
    {
        uint64_t h = 0;
        uint32_t part = 0;
        bool nh = false;
        CHECK(nodus_seg_build_next(b, &h, &part, &nh) == 0 && h == 1007 &&
              part == 0 && nh,
              "cut to the last complete record: block 1007 again, header "
              "needed");
    }
    while ((rc = fetch_one(b, G.export_dir, NULL, ans, 0)) == 0) { }
    CHECK(nodus_seg_build_finish(b) == 0, "finished after the restart");
    CHECK(nodus_seg_path(dir, 1, NODUS_SEG_F_DAT, p, sizeof(p)) == 0 &&
          nodus_seg_path(G.export_dir, 1, NODUS_SEG_F_DAT, ref, sizeof(ref))
              == 0 && files_equal(p, ref),
          "byte-identical to the export");

    /* a partial file with a record tampered ON DISK is cut at it */
    char dir2[512];
    CHECK(mk_sub("resume2", dir2, sizeof(dir2)) == 0, "dir2");
    CHECK(nodus_seg_build_open(dir2, 1, G.db, &b) == 0 &&
          nodus_seg_build_resume_step(b, 1) == 1, "open");
    CHECK(nodus_seg_export_step(b, &G.store, 100, NULL) == 0, "100 heights");
    nodus_seg_build_free(b);
    CHECK(nodus_seg_path(dir2, 1, NODUS_SEG_F_DAT_TMP, p, sizeof(p)) == 0,
          "path");
    {
        /* flip the last byte of the file: inside record 100's last part */
        size_t l = 0;
        uint8_t *x = slurp(p, &l);
        CHECK(x && l > 100, "partial");
        x[l - 1] ^= 0x01;
        FILE *f = fopen(p, "wb");
        CHECK(f && fwrite(x, 1, l, f) == l, "rewrite");
        fclose(f);
        free(x);
    }
    CHECK(nodus_seg_build_open(dir2, 1, G.db, &b) == 0, "reopen");
    while ((rc = nodus_seg_build_resume_step(b, 7)) == 0) { }
    {
        uint64_t h = 0;
        uint32_t part = 0;
        bool nh = false;
        CHECK(rc == 1 && nodus_seg_build_next(b, &h, &part, &nh) == 0 &&
              h == 100 && part == 0 && nh,
              "the tampered record 100 is cut, 1 … 99 kept");
    }
    nodus_seg_build_discard(b);
    free(ans);
    return 0;
}

/* ══ the witness fixture (serve_refusals, overlap_delete) ══════════════ */

static int w_open(nodus_witness_t **out) {
    nodus_witness_t *w = calloc(1, sizeof(*w));
    if (!w) return -1;
    if (sqlite3_open(":memory:", &w->db) != SQLITE_OK ||
        sqlite3_exec(w->db, NODUS_V2_STSETS_DDL, NULL, NULL, NULL) != SQLITE_OK ||
        sqlite3_exec(w->db, NODUS_V2_STMEMB_DDL, NULL, NULL, NULL) != SQLITE_OK ||
        sqlite3_exec(w->db, NODUS_V2_STSEGS_DDL, NULL, NULL, NULL) != SQLITE_OK ||
        sqlite3_exec(w->db, NODUS_V2_STORAGE_DDL, NULL, NULL, NULL) != SQLITE_OK ||
        sqlite3_exec(w->db, "CREATE TABLE v2_blocks (global_height INTEGER "
                     "PRIMARY KEY, block_id BLOB NOT NULL)", NULL, NULL,
                     NULL) != SQLITE_OK) {
        sqlite3_close(w->db);
        free(w);
        return -1;
    }
    *out = w;
    return 0;
}

static void w_close(nodus_witness_t *w) {
    if (!w) return;
    sqlite3_close(w->db);
    free(w);
}

static int w_exec(nodus_witness_t *w, const char *sql, uint64_t a,
                  const uint8_t *blob, int blen, uint64_t b) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)a);
    if (blob) sqlite3_bind_blob(st, 2, blob, blen, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 3, (sqlite3_int64)b);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

/* storage_set(H) of n members (sorted here) with their frozen streaks. */
static int w_set(nodus_witness_t *w, uint64_t H, uint8_t (*fps)[64],
                 uint32_t *streak, size_t n) {
    for (size_t i = 1; i < n; i++)
        for (size_t j = i; j > 0 && memcmp(fps[j - 1], fps[j], 64) > 0; j--) {
            uint8_t t[64];
            uint32_t s = streak[j];
            memcpy(t, fps[j], 64);
            memcpy(fps[j], fps[j - 1], 64);
            memcpy(fps[j - 1], t, 64);
            streak[j] = streak[j - 1];
            streak[j - 1] = s;
        }
    uint8_t sh[64];
    if (dna_v2_storage_set_hash(H, (const uint8_t (*)[64])fps, n, sh) != 0 ||
        w_exec(w, "INSERT INTO v2_storage_sets VALUES (?1, ?2, ?3)", H, sh,
               64, n) != 0)
        return -1;
    for (size_t i = 0; i < n; i++)
        if (w_exec(w, "INSERT INTO v2_storage_set_members VALUES (?1, ?2, ?3)",
                   H, fps[i], 64, streak[i]) != 0)
            return -1;
    return 0;
}

static int w_registry(nodus_witness_t *w, const uint8_t fp[64], int status) {
    uint8_t *pk = calloc(1, 2592);
    sqlite3_stmt *st = NULL;
    int ret = -1;
    if (!pk) return -1;
    if (sqlite3_prepare_v2(w->db, "INSERT OR REPLACE INTO v2_storage_nodes "
                           "VALUES (?1, ?2, ?1, 1000000, ?3, 1, 0, 0)", -1,
                           &st, NULL) == SQLITE_OK) {
        sqlite3_bind_blob(st, 1, fp, 64, SQLITE_TRANSIENT);
        sqlite3_bind_blob(st, 2, pk, 2592, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 3, status);
        ret = sqlite3_step(st) == SQLITE_DONE ? 0 : -1;
    }
    sqlite3_finalize(st);
    free(pk);
    return ret;
}

/* ══ serve_refusals ════════════════════════════════════════════════════ */

static int t_serve_refusals(void) {
    nodus_witness_t *w = NULL;
    CHECK(w_open(&w) == 0, "witness database");
    uint8_t me[64], other[64], root[64];
    fill(me, 64, 0x11);
    fill(other, 64, 0x99);
    fill(root, 64, 0x5E);
    uint8_t *out = malloc(NODUS_STFETCH_MSG_MAX);
    size_t len = 0;
    CHECK(out != NULL, "alloc");
    nodus_stfetch_req_t r = { 1, 1007, 1, NODUS_STFETCH_CONT_FIRST };
    const uint64_t H = 30 * E_LEN;
#define SERVE(dir) nodus_witness_stfetch_serve(w, NULL, (dir), me, &r, E_LEN, \
                                               out, NODUS_STFETCH_MSG_MAX,   \
                                               &len)
    CHECK(SERVE(G.export_dir) == NODUS_STFETCH_REF_UNKNOWN_SET,
          "no block yet: no epoch");
    {
        sqlite3_stmt *st = NULL;
        CHECK(sqlite3_prepare_v2(w->db, "INSERT INTO v2_blocks VALUES (?1, ?2)",
                                 -1, &st, NULL) == SQLITE_OK, "prepare");
        sqlite3_bind_int64(st, 1, (sqlite3_int64)(H + 5));
        sqlite3_bind_blob(st, 2, root, 64, SQLITE_TRANSIENT);
        CHECK(sqlite3_step(st) == SQLITE_DONE, "tip H + 5");
        sqlite3_finalize(st);
    }
    CHECK(SERVE(G.export_dir) == NODUS_STFETCH_REF_UNKNOWN_SET,
          "no frozen set at H");
    {
        uint8_t m[1][64];
        uint32_t s[1] = { 0 };
        memcpy(m[0], other, 64);
        CHECK(w_set(w, H, m, s, 1) == 0, "set(H) without the requester");
    }
    CHECK(SERVE(G.export_dir) == NODUS_STFETCH_REF_NOT_MEMBER,
          "not in the frozen set");
    CHECK(w_exec(w, "DELETE FROM v2_storage_set_members WHERE epoch_start = ?1",
                 H, NULL, 0, 0) == 0 &&
          w_exec(w, "DELETE FROM v2_storage_sets WHERE epoch_start = ?1", H,
                 NULL, 0, 0) == 0, "drop set(H)");
    {
        uint8_t m[2][64];
        uint32_t s[2] = { 0, 0 };
        memcpy(m[0], other, 64);
        memcpy(m[1], me, 64);
        CHECK(w_set(w, H, m, s, 2) == 0, "set(H) with the requester");
    }
    CHECK(SERVE(G.export_dir) == NODUS_STFETCH_REF_NOT_MEMBER,
          "a member with no registry row");
    CHECK(w_registry(w, me, 2) == 0, "EXITING");
    CHECK(SERVE(G.export_dir) == NODUS_STFETCH_REF_NOT_MEMBER,
          "an EXITING member is not served");
    CHECK(w_registry(w, me, 1) == 0, "ACTIVE");
    CHECK(SERVE(G.export_dir) == NODUS_STFETCH_REF_NOT_PUBLISHED,
          "segment 1 not published");
    CHECK(w_exec(w, "INSERT INTO v2_storage_segments VALUES (?1, ?2, ?3)", 1,
                 root, 64, 2 * E_LEN) == 0, "publish segment 1");
    CHECK(SERVE(NULL) == NODUS_STFETCH_REF_NOT_HELD, "nothing held");
    CHECK(len == 0, "a refusal writes no length");
    CHECK(SERVE(G.export_dir) == NODUS_STFETCH_OK && len > 0,
          "served from the held file");
    {
        uint8_t *x = malloc(NODUS_STFETCH_MSG_MAX);
        size_t l2 = 0;
        CHECK(x && nodus_stfetch_answer_build(NULL, G.export_dir, &r, x,
                                              NODUS_STFETCH_MSG_MAX, &l2) ==
                       NODUS_STFETCH_OK && l2 == len &&
              memcmp(x, out, len) == 0, "the same bytes as the piece alone");
        free(x);
    }
#undef SERVE
    free(out);
    w_close(w);
    return 0;
}

/* ══ overlap_delete ════════════════════════════════════════════════════ */

static int touch(const char *dir, const char *name) {
    char p[1024];
    snprintf(p, sizeof(p), "%s/%s", dir, name);
    FILE *f = fopen(p, "wb");
    if (!f) return -1;
    fputc('x', f);
    fclose(f);
    return 0;
}

static int has(const char *dir, const char *name) {
    char p[1024];
    snprintf(p, sizeof(p), "%s/%s", dir, name);
    return file_exists(p);
}

static int t_overlap_delete(void) {
    nodus_witness_t *w = NULL;
    CHECK(w_open(&w) == 0, "witness database");
    char dir[512];
    CHECK(mk_sub("gc", dir, sizeof(dir)) == 0, "dir");

    /* four members; segment 1 published at E; its holders over a set of
     * all four are the 3 nearest — pick `me` among them */
    uint8_t m[4][64], root[64];
    for (int i = 0; i < 4; i++) fill(m[i], 64, (uint8_t)(0x20 + 0x11 * i));
    fill(root, 64, 0x3C);
    CHECK(w_exec(w, "INSERT INTO v2_storage_segments VALUES (?1, ?2, ?3)", 1,
                 root, 64, E_LEN) == 0, "segment 1 published at E");

    const uint64_t H = 4 * E_LEN;
    uint8_t s0[4][64];
    uint32_t z[4] = { 0, 0, 0, 0 };
    memcpy(s0, m, sizeof(m));
    CHECK(w_set(w, H - E_LEN, s0, z, 4) == 0, "set(H-E)");
    memcpy(s0, m, sizeof(m));
    uint32_t z2[4] = { 0, 0, 0, 0 };
    CHECK(w_set(w, H, s0, z2, 4) == 0, "set(H)");

    nodus_storage_set_t *set = calloc(1, sizeof(*set));
    uint8_t hf[3][64];
    size_t nh = 0;
    CHECK(set && nodus_witness_storage_set_get(w, H, set) == 0 &&
          nodus_witness_storage_holders(set, root, hf, &nh) == 0 && nh == 3,
          "three holders at H");
    uint8_t me[64];
    memcpy(me, hf[0], 64);

    uint64_t ks[8];
    size_t n = 0;
    CHECK(nodus_witness_sthold_must_hold(w, H, me, ks, 8, &n) == 0 && n == 1 &&
          ks[0] == 1, "at H: a holder must hold segment 1");

    /* files of segment 1, of an unpublished segment 99, and another file */
    CHECK(touch(dir, "seg-1.dat") == 0 && touch(dir, "seg-1.idx") == 0 &&
          touch(dir, "seg-1.ok") == 0 && touch(dir, "seg-99.dat.tmp") == 0 &&
          touch(dir, "notes.txt") == 0, "files");
    CHECK(nodus_witness_sthold_gc(w, dir, H, me) == 0 && has(dir, "seg-1.ok"),
          "at H nothing is deleted");

    /* at H+E: `me` is skipped (fail_streak 3 frozen) → not a holder of
     * set(H+E), but it held segment 1 over set(H) and segment 1 was
     * published <= H: the overlap epoch */
    {
        uint8_t s1[4][64];
        uint32_t st[4];
        memcpy(s1, m, sizeof(m));
        for (int i = 0; i < 4; i++)
            st[i] = memcmp(s1[i], me, 64) == 0 ? 3u : 0u;
        CHECK(w_set(w, H + E_LEN, s1, st, 4) == 0, "set(H+E), me skipped");
    }
    CHECK(nodus_witness_sthold_must_hold(w, H + E_LEN, me, ks, 8, &n) == 0 &&
          n == 1 && ks[0] == 1, "at H+E: still held (the overlap epoch)");
    CHECK(nodus_witness_sthold_gc(w, dir, H + E_LEN, me) == 0 &&
          has(dir, "seg-1.dat") && has(dir, "seg-1.ok"),
          "at H+E nothing is deleted");
    {
        /* the other members still hold it at H+E: they are holders */
        uint8_t other[64];
        memcpy(other, hf[1], 64);
        CHECK(nodus_witness_sthold_must_hold(w, H + E_LEN, other, ks, 8, &n)
                  == 0 && n == 1, "a continuing holder holds it");
    }

    /* no storage_set(H+2E) yet: nothing may be deleted */
    CHECK(nodus_witness_sthold_must_hold(w, H + 2 * E_LEN, me, ks, 8, &n) == 1,
          "no set(H+2E): must-hold not computed");
    CHECK(nodus_witness_sthold_gc(w, dir, H + 2 * E_LEN, me) == -1 &&
          has(dir, "seg-1.ok"), "and nothing is deleted");

    /* at H+2E: me still skipped, and not a holder over set(H+E) */
    {
        uint8_t s2[4][64];
        uint32_t st[4];
        memcpy(s2, m, sizeof(m));
        for (int i = 0; i < 4; i++)
            st[i] = memcmp(s2[i], me, 64) == 0 ? 4u : 0u;
        CHECK(w_set(w, H + 2 * E_LEN, s2, st, 4) == 0, "set(H+2E)");
    }
    CHECK(nodus_witness_sthold_must_hold(w, H + 2 * E_LEN, me, ks, 8, &n) == 0 &&
          n == 0, "at H+2E: the overlap has passed");
    CHECK(nodus_witness_sthold_gc(w, dir, H + 2 * E_LEN, me) == 1,
          "segment 1 deleted");
    CHECK(!has(dir, "seg-1.dat") && !has(dir, "seg-1.idx") &&
          !has(dir, "seg-1.ok"), "every file of segment 1 gone");
    CHECK(has(dir, "seg-99.dat.tmp") && has(dir, "notes.txt"),
          "an unpublished segment and other files stay");

    /* the directory rule */
    {
        char d[NODUS_SEG_PATH_MAX];
        w->data_path[0] = '\0';
        CHECK(nodus_witness_sthold_dir(w, d, sizeof(d)) != 0,
              "no data path: no directory");
        snprintf(w->data_path, sizeof(w->data_path), "/var/x");
        CHECK(nodus_witness_sthold_dir(w, d, sizeof(d)) == 0 &&
              strcmp(d, "/var/x/segments") == 0, "the default name");
        snprintf(w->config.segment_dir, sizeof(w->config.segment_dir),
                 "archive");
        CHECK(nodus_witness_sthold_dir(w, d, sizeof(d)) == 0 &&
              strcmp(d, "/var/x/archive") == 0, "the configured name");
        snprintf(w->config.segment_dir, sizeof(w->config.segment_dir), "..");
        CHECK(nodus_witness_sthold_dir(w, d, sizeof(d)) != 0, "\"..\" refused");
        snprintf(w->config.segment_dir, sizeof(w->config.segment_dir), "a/b");
        CHECK(nodus_witness_sthold_dir(w, d, sizeof(d)) != 0, "'/' refused");
    }
    {
        uint64_t k = 0;
        CHECK(nodus_seg_name_parse("seg-12.dat", &k) == 0 && k == 12, "name");
        CHECK(nodus_seg_name_parse("seg-12.ok.tmp", &k) == 0, "name");
        CHECK(nodus_seg_name_parse("seg-012.dat", &k) != 0 &&
              nodus_seg_name_parse("seg-0.dat", &k) != 0 &&
              nodus_seg_name_parse("seg-12.bak", &k) != 0 &&
              nodus_seg_name_parse("seg-.dat", &k) != 0, "other names");
    }
    free(set);
    w_close(w);
    return 0;
}

/* ══ probe_from_file (LAST: prunes the fixture) ════════════════════════ */

static int t_probe_from_file(void) {
    uint8_t nonce[32], target[64], rq[64];
    fill(nonce, 32, 0xA1);
    fill(target, 64, 0xB2);
    fill(rq, 64, 0xC3);
    const uint64_t ks[1] = { 1 };
    const uint64_t B = P_LEN;
    uint8_t x[3][64], hh[3][64], hh1[3][64];
    uint64_t h[3];
    CHECK(nodus_stprobe_samples(nonce, target, ks, 1, x, h) == 0, "samples");
    for (int i = 0; i < 3; i++) {
        memcpy(hh[i], G.v2[h[i]], 64);
        memcpy(hh1[i], G.v2[h[i] + 1], 64);
    }
    uint8_t *a1 = malloc(NODUS_STPROBE_MSG_MAX);
    uint8_t *a2 = malloc(NODUS_STPROBE_MSG_MAX);
    size_t l1 = 0, l2 = 0;
    CHECK(a1 && a2, "alloc");
    CHECK(nodus_stprobe_answer_build(&G.store, rq, (const uint8_t (*)[64])x,
                                     h, B, a1, NODUS_STPROBE_MSG_MAX, &l1) ==
          NODUS_STPROBE_OK, "the answer from the block store");

    /* prune: the sampled blocks' parts and their successor metas go */
    for (int i = 0; i < 3; i++) {
        char key[NODUS_CMT_STORE_KEY_MAX];
        snprintf(key, sizeof(key), "H:%" PRId64, (int64_t)(h[i] + 1));
        CHECK(nodus_cmt_store_delete(&G.store, false, key) == CMT_OK, "meta");
        for (int j = 0; j < 2; j++) {
            snprintf(key, sizeof(key), "P:%" PRId64 ":%d", (int64_t)h[i], j);
            CHECK(nodus_cmt_store_delete(&G.store, false, key) == CMT_OK,
                  "part");
        }
    }
    CHECK(nodus_stprobe_answer_build(&G.store, rq, (const uint8_t (*)[64])x,
                                     h, B, a2, NODUS_STPROBE_MSG_MAX, &l2) ==
          NODUS_STPROBE_REF_NOT_HELD, "the pruned store no longer answers");

    /* the serving side's per-sample rule: store, else the file */
    size_t off = 0;
    CHECK(nodus_stprobe_answer_begin(rq, a2, NODUS_STPROBE_MSG_MAX, &off) == 0,
          "begin");
    for (int i = 0; i < 3; i++) {
        nodus_stprobe_code_t c = nodus_stprobe_sample_from_store(
            &G.store, x[i], B, h[i], a2, NODUS_STPROBE_MSG_MAX, &off);
        CHECK(c == NODUS_STPROBE_REF_NOT_HELD, "not in the store");
        c = nodus_seg_probe_sample(G.export_dir, x[i], B, h[i], a2,
                                   NODUS_STPROBE_MSG_MAX, &off);
        CHECK(c == NODUS_STPROBE_OK, "from the segment file");
    }
    CHECK(off == l1 && memcmp(a1, a2, l1) == 0,
          "the file answers with the same bytes as the store did");
    nodus_stprobe_ans_view_t av;
    CHECK(nodus_stprobe_ans_decode(a2, off, &av) == 0, "decodes");
    CHECK(nodus_stprobe_answer_ok(&av, rq, (const uint8_t (*)[64])x, B, h,
                                  (const uint8_t (*)[64])hh,
                                  (const uint8_t (*)[64])hh1, 0, 10),
          "the reporter's chain accepts it against v2_blocks");
    {
        char empty[512];
        size_t o2 = 0;
        CHECK(mk_sub("probe-empty", empty, sizeof(empty)) == 0 &&
              nodus_stprobe_answer_begin(rq, a2, NODUS_STPROBE_MSG_MAX, &o2)
                  == 0 &&
              nodus_seg_probe_sample(empty, x[0], B, h[0], a2,
                                     NODUS_STPROBE_MSG_MAX, &o2) ==
                  NODUS_STPROBE_REF_NOT_HELD,
              "no file held: NOT_HELD");
    }
    free(a2);
    free(a1);
    return 0;
}

int main(void) {
    static const struct {
        const char *name;
        int (*fn)(void);
    } cases[] = {
        { "roundtrip",       t_roundtrip },
        { "completeness",    t_completeness },
        { "fetch_wire",      t_fetch_wire },
        { "fetch_e2e",       t_fetch_e2e },
        { "resume",          t_resume },
        { "serve_refusals",  t_serve_refusals },
        { "overlap_delete",  t_overlap_delete },
        { "probe_from_file", t_probe_from_file },
    };
    const char *tmp = getenv("TMPDIR");
    snprintf(g_root, sizeof(g_root), "%s/test_storage_segment.XXXXXX",
             (tmp && tmp[0]) ? tmp : "/tmp");
    if (!mkdtemp(g_root)) {
        fprintf(stderr, "test_storage_segment: mkdtemp failed\n");
        return 1;
    }
    if (fx_build() != 0) {
        fprintf(stderr, "test_storage_segment: fixture build failed\n");
        rm_tree(g_root);
        return 1;
    }
    size_t failed = 0, n = sizeof(cases) / sizeof(cases[0]);
    for (size_t i = 0; i < n; i++) {
        int rc = cases[i].fn();
        fprintf(stderr, "%-18s %s\n", cases[i].name, rc == 0 ? "ok" : "FAIL");
        if (rc != 0) failed++;
    }
    fprintf(stderr, "test_storage_segment: %zu/%zu cases passed, %d checks\n",
            n - failed, n, g_checks);
    nodus_cmt_store_release(&G.store);
    sqlite3_close(G.db);
    free(G.v2);
    free(G.commit);
    rm_tree(g_root);
    return failed ? 1 : 0;
}
