/**
 * DNA Explorer — unit tests (index schema v2, version-3 chain).
 *
 * Macro style follows nodus/tests/test_storage.c (TEST/PASS/FAIL + counters).
 * No network: the sync paths run against exp_sync_source_t fakes that
 * answer dnac_v3_block pages from fixtures. Databases are ":memory:" unless
 * a test needs a file (schema rebuild, chain-reset rename) — those use
 * mkstemp paths, never fixed names (CI parallelism).
 */

#include "exp_db.h"
#include "exp_extract.h"
#include "exp_chain.h"
#include "exp_sync.h"
#include "exp_json.h"
#include "exp_http.h"
#include "nodus/nodus.h"
#include <sqlite3.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

#define TEST(name) do { printf("  %-60s", name); } while(0)
#define PASS()     do { printf("PASS\n"); passed++; } while(0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while(0)

static int passed = 0;
static int failed = 0;

static void fill(uint8_t *buf, size_t n, uint8_t v) {
    memset(buf, v, n);
}

/* 128 repeats of one hex char + NUL — a well-formed fingerprint. */
static void set_test_fp(char *fp_out, char hexchar) {
    memset(fp_out, hexchar, 128);
    fp_out[128] = '\0';
}

static void bytes_to_hex128(const uint8_t b[64], char out[129]) {
    static const char hexchars[] = "0123456789abcdef";
    for (int i = 0; i < 64; i++) {
        out[i * 2]     = hexchars[(b[i] >> 4) & 0xF];
        out[i * 2 + 1] = hexchars[b[i] & 0xF];
    }
    out[128] = '\0';
}

/* Count non-overlapping occurrences of `needle` in `hay`. */
static int count_substr(const char *hay, const char *needle) {
    int n = 0;
    const char *p = hay;
    size_t nlen = strlen(needle);
    while ((p = strstr(p, needle)) != NULL) {
        n++;
        p += nlen;
    }
    return n;
}

static void unlink_db_files(const char *path) {
    char buf[512];
    unlink(path);
    snprintf(buf, sizeof(buf), "%s-wal", path);
    unlink(buf);
    snprintf(buf, sizeof(buf), "%s-shm", path);
    unlink(buf);
}

/* ── Page fixtures ─────────────────────────────────────────────────── */

/* The header every fixture page of height h carries. */
static void page_header(nodus_dnac_v3_block_result_t *p, uint64_t h, uint32_t n,
                        uint64_t applied, uint64_t tip) {
    memset(p, 0, sizeof(*p));
    p->height = h;
    fill(p->block_id, 64, (uint8_t)(0x10 + h));
    fill(p->prev_block_id, 64, (uint8_t)(0x10 + h - 1));
    p->time_ms = 1700000000000ULL + h * 1000;
    fill(p->proposer, 32, 0xA0);
    p->proposer_len = 32;
    fill(p->global_root, 64, 0x77);
    p->applied_count = applied;
    p->total_items = n;
    p->tip = tip;
}

/* The fixture block used by the db/http tests (height h):
 *   item 0: applied spend — creates coin X (owner A, 500 native)
 *   item 1: refused envelope — code 7, a fee, no ids, no effects
 *   item 2: applied delegate — consumes X, creates Y (owner B, 400),
 *           consumes an unknown coin U (created outside the index),
 *           writes a DELEGATE record (validator V, delegator A) */
static void fixture_page(nodus_dnac_v3_block_result_t *p, uint64_t h) {
    page_header(p, h, 3, 2, h);
    p->count = 3;
    p->items = calloc(3, sizeof(nodus_dnac_v3_item_t));

    nodus_dnac_v3_item_t *it = &p->items[0];
    it->index = 0;
    it->kind = NODUS_DNAC_V3_KIND_ENVELOPE;
    it->code = 0;
    it->has_wire_id = true;   fill(it->wire_id, 64, 0x31);
    it->has_intent_id = true; fill(it->intent_id, 64, 0x41);
    it->has_fee = true;       it->fee = 1000;
    strcpy(it->op, "spend");
    it->has_effects = true;
    it->n_created = 1;
    fill(it->created[0].id, 64, 0xC1);
    set_test_fp(it->created[0].owner, 'a');
    it->created[0].amount = 500;

    it = &p->items[1];
    it->index = 1;
    it->kind = NODUS_DNAC_V3_KIND_ENVELOPE;
    it->code = 7;
    it->has_fee = true;       it->fee = 2000;
    strcpy(it->op, "spend");

    it = &p->items[2];
    it->index = 2;
    it->kind = NODUS_DNAC_V3_KIND_ENVELOPE;
    it->code = 0;
    it->has_wire_id = true;   fill(it->wire_id, 64, 0x33);
    it->has_intent_id = true; fill(it->intent_id, 64, 0x43);
    it->has_fee = true;       it->fee = 3000;
    strcpy(it->op, "delegate");
    it->has_effects = true;
    it->n_consumed = 2;
    fill(it->consumed[0], 64, 0xC1);   /* X, created by item 0 */
    fill(it->consumed[1], 64, 0xEE);   /* U, never indexed */
    it->n_created = 1;
    fill(it->created[0].id, 64, 0xC2);
    set_test_fp(it->created[0].owner, 'b');
    it->created[0].amount = 400;
    it->rec_kind = NODUS_DNAC_V3_REC_DELEGATE;
    set_test_fp(it->rec_validator_fp, 'c');
    set_test_fp(it->rec_delegator_fp, 'a');
    it->rec_amount = 100;
}

/* Index the fixture block at height 1 into `db`. */
static int seed_fixture(exp_db_t *db) {
    nodus_dnac_v3_block_result_t p;
    fixture_page(&p, 1);
    exp_block_batch_t b;
    exp_block_batch_init(&b);
    int rc = exp_extract_page(&p, &b);
    if (rc == 0) rc = exp_db_write_height(db, &b);
    exp_block_batch_free(&b);
    nodus_client_free_v3_block_result(&p);
    return rc;
}

/* Index an empty block at height h. */
static int write_empty_height(exp_db_t *db, uint64_t h) {
    nodus_dnac_v3_block_result_t p;
    page_header(&p, h, 0, 0, h);
    exp_block_batch_t b;
    exp_block_batch_init(&b);
    int rc = exp_extract_page(&p, &b);
    if (rc == 0) rc = exp_db_write_height(db, &b);
    exp_block_batch_free(&b);
    return rc;
}

/* ── Fake sync source ──────────────────────────────────────────────── */

typedef struct {
    uint8_t  chain_id32[32];
    uint64_t tip;
    int      server;
    int      rotations;
    uint32_t n_items;       /* items per height (all applied, one coin each) */
    uint32_t page_size;     /* items per page */
    uint64_t fail_height;   /* 0 = never fail */
    uint32_t fail_from;     /* the page (by first index) that fails */
    int      page_calls;
    nodus_dnac_supply_buckets_t buckets;  /* has == false: an older node */
} fake_src_t;

static int fake_tip(void *ctx, exp_chain_tip_t *out) {
    fake_src_t *f = ctx;
    memset(out, 0, sizeof(*out));
    memcpy(out->chain_id32, f->chain_id32, 32);
    out->tip = f->tip;
    out->supply_current = 123;
    out->buckets = f->buckets;
    return 0;
}

/* The genesis-day buckets of the live chain (decision
 * 2026-09-30-scan-supply-buckets.md; genesis.conf): 1 000 000 000 NODUS
 * total, 200M reward reserve, service pools 1-4 = 100M / 100M / 50M /
 * 50M, pools 5-9 = 0 (genesis outputs), 50M unclaimed — circulating
 * 450M. Raw units = NODUS × 10^8. */
#define NODUS_RAW(n) ((uint64_t)(n) * 100000000ULL)
static void genesis_day_buckets(nodus_dnac_supply_buckets_t *b) {
    memset(b, 0, sizeof(*b));
    b->has = true;
    b->current_supply = NODUS_RAW(1000000000);
    b->reward_pool = NODUS_RAW(200000000);
    b->treasury[0] = NODUS_RAW(100000000);
    b->treasury[1] = NODUS_RAW(100000000);
    b->treasury[2] = NODUS_RAW(50000000);
    b->treasury[3] = NODUS_RAW(50000000);
    b->unclaimed = NODUS_RAW(50000000);
}

static int fake_page(void *ctx, uint64_t h, uint32_t from, nodus_dnac_v3_block_result_t *out) {
    fake_src_t *f = ctx;
    f->page_calls++;
    if (f->fail_height == h && f->fail_from == from) return NODUS_ERR_TIMEOUT;

    page_header(out, h, f->n_items, f->n_items, f->tip);
    uint32_t left = f->n_items - from;
    uint32_t cnt = left < f->page_size ? left : f->page_size;
    out->count = cnt;
    out->items = calloc(cnt ? cnt : 1, sizeof(nodus_dnac_v3_item_t));
    if (!out->items) return -1;
    for (uint32_t j = 0; j < cnt; j++) {
        nodus_dnac_v3_item_t *it = &out->items[j];
        it->index = from + j;
        it->kind = NODUS_DNAC_V3_KIND_ENVELOPE;
        it->has_wire_id = true;
        fill(it->wire_id, 64, (uint8_t)(from + j));
        it->wire_id[0] = (uint8_t)h;
        strcpy(it->op, "spend");
        it->has_effects = true;
        it->n_created = 1;
        fill(it->created[0].id, 64, (uint8_t)(from + j));
        it->created[0].id[0] = (uint8_t)h;
        it->created[0].id[1] = 0xCC;
        set_test_fp(it->created[0].owner, 'd');
        it->created[0].amount = 1 + from + j;
    }
    if (from + cnt < f->n_items) {
        out->has_next = true;
        out->next_index = from + cnt;
    }
    return 0;
}

static int fake_server(void *ctx) {
    return ((fake_src_t *)ctx)->server;
}

static void fake_rotate(void *ctx) {
    fake_src_t *f = ctx;
    f->rotations++;
    f->server++;
}

static void fake_source(exp_sync_source_t *src, fake_src_t *f) {
    src->ctx = f;
    src->tip = fake_tip;
    src->page = fake_page;
    src->server = fake_server;
    src->rotate = fake_rotate;
}

/* ── exp_db: schema v2 ─────────────────────────────────────────────── */

static void test_db_schema_version(void) {
    TEST("exp_db: fresh index carries schema_version 2");

    exp_db_t *db = NULL;
    if (exp_db_open(":memory:", &db) != 0) { FAIL("open failed"); return; }
    uint64_t v = 0;
    if (exp_db_get_meta_u64(db, "schema_version", &v) != 0 || v != EXP_DB_SCHEMA_VERSION) {
        FAIL("schema_version missing or wrong");
        exp_db_close(db);
        return;
    }
    exp_db_close(db);
    PASS();
}

/* A v1 index (ledger-sequence tables, no schema_version) is dropped and
 * rebuilt as v2 on open; a v2 index is kept across a reopen. */
static void test_db_schema_rebuild_on_mismatch(void) {
    TEST("exp_db: v1 index dropped + rebuilt as v2; v2 kept on reopen");

    char path[] = "/tmp/exp_db_v1_XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) { FAIL("mkstemp failed"); return; }
    close(fd);

    sqlite3 *raw = NULL;
    if (sqlite3_open(path, &raw) != SQLITE_OK) { FAIL("raw open failed"); unlink_db_files(path); return; }
    const char *v1 =
        "CREATE TABLE txs (hash BLOB PRIMARY KEY, seq INTEGER);"
        "CREATE TABLE addr_stats (address TEXT, token_id BLOB, balance INTEGER);"
        "CREATE TABLE meta (key TEXT PRIMARY KEY, value BLOB);"
        "INSERT INTO meta VALUES ('last_indexed_seq', 5);"
        "INSERT INTO meta VALUES ('chain_id', x'4242424242424242424242424242424242424242424242424242424242424242');";
    if (sqlite3_exec(raw, v1, NULL, NULL, NULL) != SQLITE_OK) {
        FAIL("v1 seed failed");
        sqlite3_close(raw);
        unlink_db_files(path);
        return;
    }
    sqlite3_close(raw);

    exp_db_t *db = NULL;
    if (exp_db_open(path, &db) != 0) { FAIL("open of v1 file failed"); unlink_db_files(path); return; }

    uint64_t v = 0, seq = 0;
    uint8_t blob[32];
    size_t len = 0;
    int ok = exp_db_get_meta_u64(db, "schema_version", &v) == 0 && v == EXP_DB_SCHEMA_VERSION &&
             exp_db_get_meta_u64(db, "last_indexed_seq", &seq) != 0 &&
             exp_db_get_meta_blob(db, "chain_id", blob, sizeof(blob), &len) != 0;
    if (!ok) { FAIL("v1 meta survived or version not set"); exp_db_close(db); unlink_db_files(path); return; }

    if (seed_fixture(db) != 0) { FAIL("write into rebuilt index failed"); exp_db_close(db); unlink_db_files(path); return; }
    exp_db_close(db);

    /* the v1 tables are gone */
    if (sqlite3_open(path, &raw) != SQLITE_OK) { FAIL("raw reopen failed"); unlink_db_files(path); return; }
    sqlite3_stmt *s = NULL;
    int n_v1 = -1;
    if (sqlite3_prepare_v2(raw, "SELECT COUNT(*) FROM sqlite_master WHERE name IN ('txs','addr_stats','tx_io')",
                           -1, &s, NULL) == SQLITE_OK && sqlite3_step(s) == SQLITE_ROW) {
        n_v1 = sqlite3_column_int(s, 0);
    }
    sqlite3_finalize(s);
    sqlite3_close(raw);
    if (n_v1 != 0) { FAIL("v1 tables still present"); unlink_db_files(path); return; }

    /* v2 reopen keeps the data */
    if (exp_db_open(path, &db) != 0) { FAIL("v2 reopen failed"); unlink_db_files(path); return; }
    uint64_t last = 0;
    if (exp_db_get_meta_u64(db, "last_indexed_height", &last) != 0 || last != 1) {
        FAIL("v2 reopen lost the index");
        exp_db_close(db);
        unlink_db_files(path);
        return;
    }
    exp_db_close(db);
    unlink_db_files(path);
    PASS();
}

/* ── exp_extract + exp_db: mapping and queries ─────────────────────── */

static void test_write_height_and_queries(void) {
    TEST("write_height: block/items/ios/record + consumed-coin resolution");

    exp_db_t *db = NULL;
    if (exp_db_open(":memory:", &db) != 0) { FAIL("open failed"); return; }
    if (seed_fixture(db) != 0) { FAIL("seed failed"); exp_db_close(db); return; }

    exp_block_row_t blk;
    if (exp_db_query_block_by_height(db, 1, &blk) != 0 || blk.n_items != 3 ||
        blk.applied_count != 2 || blk.proposer_len != 32 || blk.time_ms != 1700000001000ULL) {
        FAIL("block row mismatch");
        exp_db_close(db);
        return;
    }
    uint8_t bid[64];
    fill(bid, 64, 0x11);
    exp_block_row_t by_id;
    if (exp_db_query_block_by_id(db, bid, &by_id) != 0 || by_id.height != 1) {
        FAIL("block by id failed");
        exp_db_close(db);
        return;
    }

    exp_item_row_t items[4];
    int n = 0;
    if (exp_db_query_items(db, 1, 0, 4, items, &n) != 0 || n != 3) { FAIL("items count"); exp_db_close(db); return; }
    if (items[1].code != 7 || items[1].has_effects || items[1].has_wire_id || !items[1].has_fee ||
        items[1].fee != 2000) {
        FAIL("refused item row mismatch");
        exp_db_close(db);
        return;
    }
    if (items[2].rec.kind != NODUS_DNAC_V3_REC_DELEGATE || items[2].rec.amount != 100 ||
        items[2].rec.validator[0] != 'c' || items[2].rec.delegator[0] != 'a' || items[2].rec.dest[0] != '\0') {
        FAIL("record mismatch");
        exp_db_close(db);
        return;
    }
    if (items[0].block_time_ms != 1700000001000ULL || strcmp(items[2].op, "delegate") != 0) {
        FAIL("item time/op mismatch");
        exp_db_close(db);
        return;
    }

    uint8_t id[64];
    exp_item_row_t it;
    fill(id, 64, 0x33);
    if (exp_db_query_item_by_id(db, id, &it) != 0 || it.idx != 2) { FAIL("by wire id"); exp_db_close(db); return; }
    fill(id, 64, 0x41);
    if (exp_db_query_item_by_id(db, id, &it) != 0 || it.idx != 0) { FAIL("by intent id"); exp_db_close(db); return; }

    exp_io_row_t ios[8];
    int nio = 0;
    if (exp_db_query_item_ios(db, 1, 2, ios, 8, &nio) != 0 || nio != 3) { FAIL("ios count"); exp_db_close(db); return; }
    /* (dir, pos) order: consumed X, consumed U, created Y */
    char fp_a[129], fp_b[129];
    set_test_fp(fp_a, 'a');
    set_test_fp(fp_b, 'b');
    if (ios[0].dir != 0 || !ios[0].has_owner || strcmp(ios[0].address, fp_a) != 0 || ios[0].amount != 500) {
        FAIL("consumed X not resolved to its creator");
        exp_db_close(db);
        return;
    }
    if (ios[1].dir != 0 || ios[1].has_owner) { FAIL("consumed U should stay unresolved"); exp_db_close(db); return; }
    if (ios[2].dir != 1 || strcmp(ios[2].address, fp_b) != 0 || ios[2].amount != 400) {
        FAIL("created Y mismatch");
        exp_db_close(db);
        return;
    }

    /* history: A = created X (item 0) + consumed X / delegator (item 2) */
    exp_item_row_t hist[4];
    int nh = 0;
    if (exp_db_query_address(db, fp_a, UINT64_MAX, UINT32_MAX, 4, hist, &nh) != 0 || nh != 2 ||
        hist[0].idx != 2 || hist[1].idx != 0) {
        FAIL("address A history");
        exp_db_close(db);
        return;
    }
    /* cursor strictly before 1:2 */
    if (exp_db_query_address(db, fp_a, 1, 2, 4, hist, &nh) != 0 || nh != 1 || hist[0].idx != 0) {
        FAIL("address cursor");
        exp_db_close(db);
        return;
    }
    char fp_c[129];
    set_test_fp(fp_c, 'c');
    if (exp_db_query_address(db, fp_c, UINT64_MAX, UINT32_MAX, 4, hist, &nh) != 0 || nh != 1 || hist[0].idx != 2) {
        FAIL("validator history via record");
        exp_db_close(db);
        return;
    }

    if (exp_db_verify_index(db) != 0) { FAIL("verify_index on a clean index"); exp_db_close(db); return; }

    exp_db_close(db);
    PASS();
}

static void test_write_height_order_enforced(void) {
    TEST("write_height: only the next height is accepted");

    exp_db_t *db = NULL;
    if (exp_db_open(":memory:", &db) != 0) { FAIL("open failed"); return; }

    if (write_empty_height(db, 2) == 0) { FAIL("height 2 on an empty index accepted"); exp_db_close(db); return; }
    if (write_empty_height(db, 1) != 0) { FAIL("height 1 refused"); exp_db_close(db); return; }
    if (write_empty_height(db, 1) == 0) { FAIL("height 1 accepted twice"); exp_db_close(db); return; }
    if (write_empty_height(db, 3) == 0) { FAIL("gap accepted"); exp_db_close(db); return; }

    uint64_t last = 0;
    if (exp_db_get_meta_u64(db, "last_indexed_height", &last) != 0 || last != 1) {
        FAIL("watermark moved on a refused write");
        exp_db_close(db);
        return;
    }
    exp_db_close(db);
    PASS();
}

static void test_verify_index_detects_gap(void) {
    TEST("verify_index: watermark beyond the stored blocks -> inconsistent");

    exp_db_t *db = NULL;
    if (exp_db_open(":memory:", &db) != 0) { FAIL("open failed"); return; }
    for (uint64_t h = 1; h <= 3; h++) {
        if (write_empty_height(db, h) != 0) { FAIL("seed failed"); exp_db_close(db); return; }
    }
    if (exp_db_verify_index(db) != 0) { FAIL("clean index reported inconsistent"); exp_db_close(db); return; }
    exp_db_set_meta_u64(db, "last_indexed_height", 5);
    if (exp_db_verify_index(db) == 0) { FAIL("gap not detected"); exp_db_close(db); return; }
    exp_db_close(db);
    PASS();
}

static void test_extract_refuses_mismatched_page(void) {
    TEST("extract_page: other block's page / index gap refused, batch kept");

    nodus_dnac_v3_block_result_t p1, p2;
    page_header(&p1, 5, 4, 4, 9);
    p1.count = 2;
    p1.items = calloc(2, sizeof(nodus_dnac_v3_item_t));
    p1.items[0].index = 0;
    p1.items[1].index = 1;
    p1.has_next = true;
    p1.next_index = 2;

    exp_block_batch_t b;
    exp_block_batch_init(&b);
    if (exp_extract_page(&p1, &b) != 0 || b.n_items != 2) { FAIL("first page refused"); goto out1; }

    /* same height, different block id (another server after a rotate) */
    page_header(&p2, 5, 4, 4, 9);
    fill(p2.block_id, 64, 0x99);
    p2.count = 2;
    p2.items = calloc(2, sizeof(nodus_dnac_v3_item_t));
    p2.items[0].index = 2;
    p2.items[1].index = 3;
    if (exp_extract_page(&p2, &b) == 0 || b.n_items != 2) { FAIL("foreign header accepted"); goto out2; }

    /* right header, but it skips item 2 */
    fill(p2.block_id, 64, (uint8_t)(0x10 + 5));
    p2.items[0].index = 3;
    p2.count = 1;
    if (exp_extract_page(&p2, &b) == 0 || b.n_items != 2) { FAIL("index gap accepted"); goto out2; }

    /* the correct continuation */
    p2.items[0].index = 2;
    p2.count = 2;
    if (exp_extract_page(&p2, &b) != 0 || b.n_items != 4) { FAIL("continuation refused"); goto out2; }

    PASS();
out2:
    nodus_client_free_v3_block_result(&p2);
out1:
    nodus_client_free_v3_block_result(&p1);
    exp_block_batch_free(&b);
}

/* ── exp_sync ──────────────────────────────────────────────────────── */

static void test_sync_collect_concatenates_pages(void) {
    TEST("collect_block: 10 items in pages of 3 -> 4 pages, in order");

    fake_src_t f;
    memset(&f, 0, sizeof(f));
    f.tip = 1;
    f.n_items = 10;
    f.page_size = 3;
    exp_sync_source_t src;
    fake_source(&src, &f);

    exp_block_batch_t b;
    exp_block_batch_init(&b);
    if (exp_sync_collect_block(&src, 1, &b) != 0) { FAIL("collect failed"); exp_block_batch_free(&b); return; }
    if (f.page_calls != 4 || b.n_items != 10 || b.n_ios != 10) {
        FAIL("page/item/io count");
        exp_block_batch_free(&b);
        return;
    }
    for (size_t i = 0; i < b.n_items; i++) {
        if (b.items[i].idx != i || b.ios[i].idx != i || b.ios[i].amount != 1 + i) {
            FAIL("items/ios not concatenated in index order");
            exp_block_batch_free(&b);
            return;
        }
    }
    exp_block_batch_free(&b);
    PASS();
}

static void test_sync_partial_height_keeps_watermark(void) {
    TEST("tick: a failed page mid-height leaves the watermark, then resumes");

    exp_db_t *db = NULL;
    if (exp_db_open(":memory:", &db) != 0) { FAIL("open failed"); return; }

    fake_src_t f;
    memset(&f, 0, sizeof(f));
    fill(f.chain_id32, 32, 0x42);
    f.tip = 3;
    f.n_items = 5;
    f.page_size = 2;
    f.fail_height = 2;
    f.fail_from = 2;           /* the second page of height 2 */
    exp_sync_source_t src;
    fake_source(&src, &f);

    exp_reset_fsm_t fsm;
    memset(&fsm, 0, sizeof(fsm));
    if (exp_sync_tick(&src, &db, ":memory:", &fsm, NULL) != -1) { FAIL("tick should fail"); exp_db_close(db); return; }

    uint64_t last = 0;
    exp_block_row_t row;
    if (exp_db_get_meta_u64(db, "last_indexed_height", &last) != 0 || last != 1 ||
        exp_db_query_block_by_height(db, 2, &row) == 0) {
        FAIL("height 2 partially written or watermark advanced");
        exp_db_close(db);
        return;
    }

    f.fail_height = 0;
    if (exp_sync_tick(&src, &db, ":memory:", &fsm, NULL) != 0) { FAIL("retry tick failed"); exp_db_close(db); return; }
    exp_item_row_t items[8];
    int n = 0;
    if (exp_db_get_meta_u64(db, "last_indexed_height", &last) != 0 || last != 3 ||
        exp_db_query_items(db, 2, 0, 8, items, &n) != 0 || n != 5) {
        FAIL("resume did not index heights 2..3 whole");
        exp_db_close(db);
        return;
    }
    if (exp_db_verify_index(db) != 0) { FAIL("index inconsistent after resume"); exp_db_close(db); return; }
    exp_db_close(db);
    PASS();
}

static void test_sync_tick_height_bound(void) {
    TEST("tick: stops at the per-tick height bound and returns 1");

    exp_db_t *db = NULL;
    if (exp_db_open(":memory:", &db) != 0) { FAIL("open failed"); return; }

    fake_src_t f;
    memset(&f, 0, sizeof(f));
    fill(f.chain_id32, 32, 0x42);
    f.tip = EXP_SYNC_MAX_HEIGHTS_PER_TICK + 10;
    f.n_items = 0;
    f.page_size = 1;
    exp_sync_source_t src;
    fake_source(&src, &f);

    exp_reset_fsm_t fsm;
    memset(&fsm, 0, sizeof(fsm));
    uint64_t last = 0;
    if (exp_sync_tick(&src, &db, ":memory:", &fsm, NULL) != 1 ||
        exp_db_get_meta_u64(db, "last_indexed_height", &last) != 0 || last != EXP_SYNC_MAX_HEIGHTS_PER_TICK) {
        FAIL("first tick should stop at the bound with rc 1");
        exp_db_close(db);
        return;
    }
    if (exp_sync_tick(&src, &db, ":memory:", &fsm, NULL) != 0 ||
        exp_db_get_meta_u64(db, "last_indexed_height", &last) != 0 || last != f.tip) {
        FAIL("second tick should finish at the tip with rc 0");
        exp_db_close(db);
        return;
    }
    uint64_t tip = 0, supply = 0;
    if (exp_db_get_meta_u64(db, "tip_height", &tip) != 0 || tip != f.tip ||
        exp_db_get_meta_u64(db, "supply_current", &supply) != 0 || supply != 123) {
        FAIL("tip/supply meta not stored");
        exp_db_close(db);
        return;
    }
    exp_db_close(db);
    PASS();
}

/* Supply buckets, pure half: the meta blob round-trips, circulating is the
 * decision's formula (genesis day = 450 000 000 NODUS), and every path
 * that would wrap below zero is refused rather than answered. */
static void test_supply_buckets_pure(void) {
    TEST("supply buckets: blob round trip + circulating + underflow");

    nodus_dnac_supply_buckets_t b, u;
    uint8_t blob[EXP_SUPPLY_BUCKETS_BLOB_LEN];
    uint64_t circ = 0;

    genesis_day_buckets(&b);
    exp_supply_buckets_pack(&b, blob);
    if (blob[0] != 1 || exp_supply_buckets_unpack(blob, sizeof(blob), &u) != 0 || !u.has ||
        u.current_supply != b.current_supply || u.reward_pool != b.reward_pool ||
        memcmp(u.treasury, b.treasury, sizeof(b.treasury)) != 0 || u.unclaimed != b.unclaimed) {
        FAIL("round trip");
        return;
    }
    if (exp_supply_circulating(&u, &circ) != 0 || circ != NODUS_RAW(450000000)) {
        FAIL("genesis day must be 450 000 000 NODUS circulating");
        return;
    }

    /* exactly zero left is an answer, one raw unit more is not */
    u.current_supply = NODUS_RAW(550000000);
    if (exp_supply_circulating(&u, &circ) != 0 || circ != 0) { FAIL("zero circulating"); return; }
    u.current_supply -= 1;
    circ = 7;
    if (exp_supply_circulating(&u, &circ) != -1 || circ != 7) { FAIL("unclaimed underflow must refuse"); return; }
    genesis_day_buckets(&u);
    u.reward_pool = u.current_supply + 1;
    if (exp_supply_circulating(&u, &circ) != -1) { FAIL("reward_pool underflow must refuse"); return; }
    genesis_day_buckets(&u);
    u.treasury[8] = UINT64_MAX;
    if (exp_supply_circulating(&u, &circ) != -1) { FAIL("treasury underflow must refuse"); return; }

    /* an older node: has 0 packs to an all-zero blob and has no circulating */
    memset(&b, 0, sizeof(b));
    b.reward_pool = 99;                        /* ignored when has is false */
    exp_supply_buckets_pack(&b, blob);
    for (size_t i = 0; i < sizeof(blob); i++) {
        if (blob[i] != 0) { FAIL("has-false blob must be all zero"); return; }
    }
    if (exp_supply_buckets_unpack(blob, sizeof(blob), &u) != 0 || u.has ||
        exp_supply_circulating(&u, &circ) != -1) {
        FAIL("has-false blob must unpack to no buckets");
        return;
    }

    /* a malformed blob is refused */
    if (exp_supply_buckets_unpack(blob, sizeof(blob) - 1, &u) != -1 || u.has) { FAIL("short blob"); return; }
    blob[0] = 2;
    if (exp_supply_buckets_unpack(blob, sizeof(blob), &u) != -1 || u.has) { FAIL("flag 2"); return; }
    PASS();
}

/* Supply buckets, sync half: an accepted observation stores its buckets
 * as the one blob, and a later observation WITHOUT buckets (an older
 * node) replaces them — the previous server's figures never linger. */
static void test_sync_stores_buckets(void) {
    TEST("tick: buckets stored as one blob; an older node clears them");

    exp_db_t *db = NULL;
    if (exp_db_open(":memory:", &db) != 0) { FAIL("open failed"); return; }

    fake_src_t f;
    memset(&f, 0, sizeof(f));
    fill(f.chain_id32, 32, 0x42);
    f.tip = 1;
    f.n_items = 0;
    f.page_size = 1;
    genesis_day_buckets(&f.buckets);
    exp_sync_source_t src;
    fake_source(&src, &f);

    exp_reset_fsm_t fsm;
    memset(&fsm, 0, sizeof(fsm));
    uint8_t blob[EXP_SUPPLY_BUCKETS_BLOB_LEN];
    size_t len = 0;
    nodus_dnac_supply_buckets_t u;
    if (exp_sync_tick(&src, &db, ":memory:", &fsm, NULL) != 0 ||
        exp_db_get_meta_blob(db, EXP_META_SUPPLY_BUCKETS, blob, sizeof(blob), &len) != 0 ||
        exp_supply_buckets_unpack(blob, len, &u) != 0 || !u.has ||
        u.reward_pool != f.buckets.reward_pool || u.treasury[3] != f.buckets.treasury[3] ||
        u.unclaimed != f.buckets.unclaimed || u.current_supply != f.buckets.current_supply) {
        FAIL("buckets not stored");
        exp_db_close(db);
        return;
    }

    memset(&f.buckets, 0, sizeof(f.buckets));
    f.tip = 2;
    if (exp_sync_tick(&src, &db, ":memory:", &fsm, NULL) != 0 ||
        exp_db_get_meta_blob(db, EXP_META_SUPPLY_BUCKETS, blob, sizeof(blob), &len) != 0 ||
        exp_supply_buckets_unpack(blob, len, &u) != 0 || u.has) {
        FAIL("an older node's observation must replace the buckets");
        exp_db_close(db);
        return;
    }
    exp_db_close(db);
    PASS();
}

/* The F4 FSM is keyed on chain_id32: the reference lives in meta
 * "chain_id32" (a legacy "chain_id" blob is ignored), a different
 * chain_id32 from one server is PENDING (nothing indexed, rotate), the
 * same one from a second server CONFIRMS and archives the index. */
static void test_sync_fsm_keys_on_chain_id32(void) {
    TEST("tick: reset FSM keyed on chain_id32 (adopt / PENDING / CONFIRMED)");

    char path[] = "/tmp/exp_sync_fsm_XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) { FAIL("mkstemp failed"); return; }
    close(fd);

    exp_db_t *db = NULL;
    if (exp_db_open(path, &db) != 0) { FAIL("open failed"); unlink_db_files(path); return; }

    uint8_t legacy[32];
    fill(legacy, 32, 0x55);
    exp_db_set_meta_blob(db, "chain_id", legacy, 32);

    exp_reset_fsm_t fsm;
    memset(&fsm, 0, sizeof(fsm));
    exp_sync_preseed(db, &fsm);
    uint8_t zero[32] = {0};
    if (memcmp(fsm.ref_chain_id, zero, 32) != 0) { FAIL("legacy chain_id preseeded the FSM"); goto out; }

    fake_src_t f;
    memset(&f, 0, sizeof(f));
    fill(f.chain_id32, 32, 0x42);
    f.tip = 2;
    f.n_items = 1;
    f.page_size = 4;
    exp_sync_source_t src;
    fake_source(&src, &f);

    /* first observation adopts 0x42 and indexes */
    uint8_t got[32];
    size_t len = 0;
    if (exp_sync_tick(&src, &db, path, &fsm, NULL) != 0 ||
        exp_db_get_meta_blob(db, "chain_id32", got, sizeof(got), &len) != 0 || len != 32 ||
        memcmp(got, f.chain_id32, 32) != 0) {
        FAIL("chain_id32 not adopted into meta");
        goto out;
    }

    /* another chain from server 0: PENDING, rotate, nothing indexed */
    fill(f.chain_id32, 32, 0x99);
    f.tip = 5;
    int calls = f.page_calls;
    uint64_t last = 0;
    if (exp_sync_tick(&src, &db, path, &fsm, NULL) != 0 || f.rotations != 1 || f.page_calls != calls ||
        exp_db_get_meta_u64(db, "last_indexed_height", &last) != 0 || last != 2) {
        FAIL("PENDING tick indexed or did not rotate");
        goto out;
    }

    /* the same from server 1: CONFIRMED -> index archived, fresh db */
    if (exp_sync_tick(&src, &db, path, &fsm, NULL) != 0 || !db) { FAIL("CONFIRMED tick failed"); goto out; }
    if (exp_db_get_meta_blob(db, "chain_id32", got, sizeof(got), &len) != 0 ||
        memcmp(got, f.chain_id32, 32) != 0 ||
        exp_db_get_meta_u64(db, "last_indexed_height", &last) == 0) {
        FAIL("fresh index not re-keyed on the new chain_id32");
        goto out;
    }
    char stale[512];
    if (exp_sync_stale_name(path, f.chain_id32, stale, sizeof(stale)) != 0 || access(stale, F_OK) != 0) {
        FAIL("stale index not archived");
        goto out;
    }
    unlink_db_files(stale);
    PASS();
out:
    if (db) exp_db_close(db);
    unlink_db_files(path);
}

/* ── exp_chain_config_load ──────────────────────────────────────────
 * mkstemp — a fixed filename would race under CI parallelism. */

static void test_chain_config_load(void) {
    TEST("exp_chain_config_load (2 servers + comment + blank line)");

    char path[] = "/tmp/exp_chain_test_XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) { FAIL("mkstemp failed"); return; }

    FILE *f = fdopen(fd, "w");
    if (!f) { FAIL("fdopen failed"); close(fd); unlink(path); return; }
    fprintf(f, "# comment line, should be skipped\n");
    fprintf(f, "127.0.0.1 4001\n");
    fprintf(f, "   \n");                 /* whitespace-only line */
    fprintf(f, "203.0.113.5 4002\n");
    fclose(f);

    exp_server_t servers[4];
    int count = -1;
    int rc = exp_chain_config_load(path, servers, 4, &count);
    unlink(path);

    if (rc != 0 || count != 2) { FAIL("config_load count mismatch"); return; }
    if (strcmp(servers[0].host, "127.0.0.1") != 0 || servers[0].port != 4001) {
        FAIL("config_load servers[0] mismatch");
        return;
    }
    if (strcmp(servers[1].host, "203.0.113.5") != 0 || servers[1].port != 4002) {
        FAIL("config_load servers[1] mismatch");
        return;
    }

    PASS();
}

static void test_chain_config_load_rejects_malformed(void) {
    TEST("exp_chain_config_load rejects a malformed line");

    char path[] = "/tmp/exp_chain_test_bad_XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) { FAIL("mkstemp failed"); return; }

    FILE *f = fdopen(fd, "w");
    if (!f) { FAIL("fdopen failed"); close(fd); unlink(path); return; }
    fprintf(f, "127.0.0.1 4001\n");
    fprintf(f, "this-line-has-no-port\n");
    fclose(f);

    exp_server_t servers[4];
    int count = -1;
    int rc = exp_chain_config_load(path, servers, 4, &count);
    unlink(path);

    if (rc == 0) { FAIL("expected failure for malformed line"); return; }

    PASS();
}

static void test_chain_config_load_rejects_port_zero(void) {
    TEST("exp_chain_config_load rejects port 0");

    char path[] = "/tmp/exp_chain_test_port0_XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) { FAIL("mkstemp failed"); return; }

    FILE *f = fdopen(fd, "w");
    if (!f) { FAIL("fdopen failed"); close(fd); unlink(path); return; }
    fprintf(f, "127.0.0.1 4001\n");
    fprintf(f, "127.0.0.2 0\n");
    fclose(f);

    exp_server_t servers[4];
    int count = -1;
    int rc = exp_chain_config_load(path, servers, 4, &count);
    unlink(path);

    if (rc == 0) { FAIL("expected failure for port 0"); return; }

    PASS();
}

static void test_chain_config_load_rejects_duplicate(void) {
    TEST("exp_chain_config_load rejects duplicate (host,port) pair");

    char path[] = "/tmp/exp_chain_test_dup_XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) { FAIL("mkstemp failed"); return; }

    FILE *f = fdopen(fd, "w");
    if (!f) { FAIL("fdopen failed"); close(fd); unlink(path); return; }
    fprintf(f, "127.0.0.1 4001\n");
    fprintf(f, "203.0.113.5 4002\n");
    fprintf(f, "127.0.0.1 4001\n");   /* exact duplicate of line 1 */
    fclose(f);

    exp_server_t servers[4];
    int count = -1;
    int rc = exp_chain_config_load(path, servers, 4, &count);
    unlink(path);

    if (rc == 0) { FAIL("expected failure for duplicate (host,port) pair"); return; }

    PASS();
}

/* ── exp_reset_fsm_feed (F4) — pure logic ───────────────────────────── */

static void test_reset_fsm_match_is_no(void) {
    TEST("reset FSM: matching chain_id -> NO");

    exp_reset_fsm_t fsm;
    memset(&fsm, 0, sizeof(fsm));

    uint8_t ref[32];
    fill(ref, 32, 0x42);

    /* first feed (fsm zero-initialized) adopts ref as the reference */
    if (exp_reset_fsm_feed(&fsm, ref, 0) != EXP_RESET_NO) { FAIL("first feed should be NO"); return; }
    /* subsequent matching feeds from any server stay NO */
    if (exp_reset_fsm_feed(&fsm, ref, 1) != EXP_RESET_NO) { FAIL("matching feed should be NO"); return; }

    PASS();
}

static void test_reset_fsm_one_mismatch_pending(void) {
    TEST("reset FSM: one mismatch -> PENDING");

    exp_reset_fsm_t fsm;
    memset(&fsm, 0, sizeof(fsm));
    uint8_t ref[32];  fill(ref, 32, 0x42);
    uint8_t cand[32]; fill(cand, 32, 0x99);

    exp_reset_fsm_feed(&fsm, ref, 0);  /* establish reference */
    if (exp_reset_fsm_feed(&fsm, cand, 0) != EXP_RESET_PENDING) {
        FAIL("first mismatch should be PENDING");
        return;
    }

    PASS();
}

static void test_reset_fsm_same_server_twice_still_pending(void) {
    TEST("reset FSM: same server reporting mismatch twice -> still PENDING");

    exp_reset_fsm_t fsm;
    memset(&fsm, 0, sizeof(fsm));
    uint8_t ref[32];  fill(ref, 32, 0x42);
    uint8_t cand[32]; fill(cand, 32, 0x99);

    exp_reset_fsm_feed(&fsm, ref, 0);
    exp_reset_fsm_feed(&fsm, cand, 3);
    if (exp_reset_fsm_feed(&fsm, cand, 3) != EXP_RESET_PENDING) {
        FAIL("same-server repeat should still be PENDING (only 1 distinct server)");
        return;
    }

    PASS();
}

static void test_reset_fsm_two_servers_two_polls_confirmed(void) {
    TEST("reset FSM: 2 distinct servers x 2 polls -> CONFIRMED");

    exp_reset_fsm_t fsm;
    memset(&fsm, 0, sizeof(fsm));
    uint8_t ref[32];  fill(ref, 32, 0x42);
    uint8_t cand[32]; fill(cand, 32, 0x99);

    exp_reset_fsm_feed(&fsm, ref, 0);
    if (exp_reset_fsm_feed(&fsm, cand, 0) != EXP_RESET_PENDING) { FAIL("poll1 should be PENDING"); return; }
    if (exp_reset_fsm_feed(&fsm, cand, 1) != EXP_RESET_CONFIRMED) {
        FAIL("poll2 from a distinct server should be CONFIRMED");
        return;
    }

    PASS();
}

static void test_reset_fsm_mismatch_then_match_back_to_no(void) {
    TEST("reset FSM: mismatch then match -> back to NO");

    exp_reset_fsm_t fsm;
    memset(&fsm, 0, sizeof(fsm));
    uint8_t ref[32];  fill(ref, 32, 0x42);
    uint8_t cand[32]; fill(cand, 32, 0x99);

    exp_reset_fsm_feed(&fsm, ref, 0);
    exp_reset_fsm_feed(&fsm, cand, 0);   /* PENDING */
    if (exp_reset_fsm_feed(&fsm, ref, 1) != EXP_RESET_NO) {
        FAIL("matching feed after a mismatch should return to NO");
        return;
    }
    /* tracking state cleared, not just the return code */
    if (exp_reset_fsm_feed(&fsm, cand, 2) != EXP_RESET_PENDING) {
        FAIL("post-reset mismatch should restart at PENDING");
        return;
    }

    PASS();
}

static void test_reset_fsm_candidate_switch_restarts(void) {
    TEST("reset FSM: switching mismatching candidate restarts tracking");

    exp_reset_fsm_t fsm;
    memset(&fsm, 0, sizeof(fsm));
    uint8_t ref[32];    fill(ref, 32, 0x42);
    uint8_t cand_x[32]; fill(cand_x, 32, 0x11);
    uint8_t cand_y[32]; fill(cand_y, 32, 0x22);

    exp_reset_fsm_feed(&fsm, ref, 0);
    if (exp_reset_fsm_feed(&fsm, cand_x, 0) != EXP_RESET_PENDING) { FAIL("cand_x poll1 should be PENDING"); return; }
    if (exp_reset_fsm_feed(&fsm, cand_y, 1) != EXP_RESET_PENDING) {
        FAIL("candidate switch should restart at PENDING, not CONFIRMED");
        return;
    }
    if (exp_reset_fsm_feed(&fsm, cand_y, 2) != EXP_RESET_CONFIRMED) {
        FAIL("cand_y poll2 (distinct server) should be CONFIRMED");
        return;
    }

    PASS();
}

static void test_reset_fsm_negative_index_does_not_mutate(void) {
    TEST("reset FSM: server_index -1 is a no-op (no sentinel collision)");

    exp_reset_fsm_t fsm;
    memset(&fsm, 0, sizeof(fsm));
    uint8_t ref[32];  fill(ref, 32, 0x42);
    uint8_t cand[32]; fill(cand, 32, 0x99);

    exp_reset_fsm_feed(&fsm, ref, 0);   /* establish reference */
    if (exp_reset_fsm_feed(&fsm, cand, 5) != EXP_RESET_PENDING) {
        FAIL("first mismatch (server 5) should be PENDING");
        return;
    }
    if (exp_reset_fsm_feed(&fsm, cand, -1) != EXP_RESET_PENDING) {
        FAIL("server_index -1 feed should report current status (PENDING), not mutate");
        return;
    }
    if (exp_reset_fsm_feed(&fsm, cand, -1) != EXP_RESET_PENDING) {
        FAIL("repeated server_index -1 feeds should stay PENDING (still a no-op)");
        return;
    }
    if (exp_reset_fsm_feed(&fsm, cand, 6) != EXP_RESET_CONFIRMED) {
        FAIL("second distinct real server should CONFIRM (only 1 real + this one = 2 distinct)");
        return;
    }

    PASS();
}

static void test_sync_stale_name(void) {
    TEST("exp_sync_stale_name: path+hex8 join, truncation-safe, rejects NULL");

    uint8_t chain_id[32];
    memset(chain_id, 0, sizeof(chain_id));
    chain_id[0] = 0xDE; chain_id[1] = 0xAD; chain_id[2] = 0xBE; chain_id[3] = 0xEF;

    char out[256];
    if (exp_sync_stale_name("/var/lib/dna-explorer/index.db", chain_id, out, sizeof(out)) != 0) {
        FAIL("expected success");
        return;
    }
    if (strcmp(out, "/var/lib/dna-explorer/index.db.stale-deadbeef") != 0) {
        FAIL("unexpected stale db path");
        return;
    }

    uint8_t chain_id2[32];
    fill(chain_id2, 32, 0x11);
    char small[8];
    if (exp_sync_stale_name("/a", chain_id2, small, sizeof(small)) == 0) {
        FAIL("expected failure on truncation");
        return;
    }

    if (exp_sync_stale_name(NULL, chain_id2, out, sizeof(out)) == 0) { FAIL("NULL db_path should fail"); return; }
    if (exp_sync_stale_name("/a", NULL, out, sizeof(out)) == 0) { FAIL("NULL chain_id should fail"); return; }
    if (exp_sync_stale_name("/a", chain_id2, NULL, sizeof(out)) == 0) { FAIL("NULL out should fail"); return; }
    if (exp_sync_stale_name("/a", chain_id2, out, 0) == 0) { FAIL("outlen 0 should fail"); return; }

    PASS();
}

/* ── exp_json ──────────────────────────────────────────────────────── */

static void test_json_str_escaping(void) {
    TEST("exp_json_str escapes quote/backslash/control chars");

    exp_json_t j;
    exp_json_init(&j);
    exp_json_str(&j, "a\"b\\c\nd\te");

    const char *expected = "\"a\\\"b\\\\c\\nd\\te\"";
    if (strcmp(j.buf, expected) != 0) {
        printf("(got: %s) ", j.buf ? j.buf : "(null)");
        FAIL("escaped output mismatch");
        exp_json_freebuf(&j);
        return;
    }
    exp_json_freebuf(&j);

    exp_json_t j2;
    exp_json_init(&j2);
    char raw_ctrl[2] = { 0x01, '\0' };
    exp_json_str(&j2, raw_ctrl);
    if (strcmp(j2.buf, "\"\\u0001\"") != 0) {
        printf("(got: %s) ", j2.buf ? j2.buf : "(null)");
        FAIL("\\u00XX escape mismatch");
        exp_json_freebuf(&j2);
        return;
    }
    exp_json_freebuf(&j2);

    exp_json_t j3;
    exp_json_init(&j3);
    exp_json_str(&j3, NULL);
    if (strcmp(j3.buf, "\"\"") != 0) {
        FAIL("NULL input should emit empty string literal");
        exp_json_freebuf(&j3);
        return;
    }
    exp_json_freebuf(&j3);

    PASS();
}

static void test_json_hex_emit(void) {
    TEST("exp_json_hex emits lowercase hex string");

    uint8_t b[4] = {0xDE, 0xAD, 0xBE, 0xEF};
    exp_json_t j;
    exp_json_init(&j);
    exp_json_hex(&j, b, sizeof(b));

    if (strcmp(j.buf, "\"deadbeef\"") != 0) {
        printf("(got: %s) ", j.buf ? j.buf : "(null)");
        FAIL("hex emit mismatch");
        exp_json_freebuf(&j);
        return;
    }
    exp_json_freebuf(&j);

    exp_json_t j2;
    exp_json_init(&j2);
    exp_json_hex(&j2, NULL, 0);
    if (strcmp(j2.buf, "\"\"") != 0) {
        FAIL("zero-length hex should emit empty string literal");
        exp_json_freebuf(&j2);
        return;
    }
    exp_json_freebuf(&j2);

    PASS();
}

/* ── exp_http_route ────────────────────────────────────────────────── */

/* Route `path` on `db`; 0 when the status matches `want` and every
 * `needles` entry (NULL-terminated) occurs in the body. */
static int route_expect(exp_db_t *db, const char *path, int want, const char *const *needles) {
    exp_http_ctx_t ctx = {0};
    ctx.db = &db;
    int stop = 0;
    ctx.stop = &stop;

    exp_json_t body;
    int status = -1;
    if (exp_http_route(&ctx, "GET", path, &body, &status) != 0) return -1;
    int ok = (status == want);
    for (int i = 0; ok && needles && needles[i]; i++) {
        if (!strstr(body.buf, needles[i])) ok = 0;
    }
    if (!ok) printf("(%s -> %d: %s) ", path, status, body.buf ? body.buf : "(null)");
    exp_json_freebuf(&body);
    return ok ? 0 : -1;
}

static void test_route_stats_and_blocks(void) {
    TEST("route: /api/stats + /api/blocks (limit clamp, JSON shape)");

    exp_db_t *db = NULL;
    if (exp_db_open(":memory:", &db) != 0) { FAIL("open failed"); return; }
    for (uint64_t h = 1; h <= 150; h++) {
        if (write_empty_height(db, h) != 0) { FAIL("seed failed"); exp_db_close(db); return; }
    }
    exp_db_set_meta_u64(db, "tip_height", 151);

    static const char *const stats_needles[] = { "\"indexed_height\":150", "\"tip_height\":151",
                                                 "\"chain_id\":null", "\"reward_pool\":null",
                                                 "\"treasury\":null", "\"unclaimed\":null",
                                                 "\"circulating\":null", NULL };
    if (route_expect(db, "/api/stats", 200, stats_needles) != 0) { FAIL("stats"); exp_db_close(db); return; }

    exp_http_ctx_t ctx = {0};
    ctx.db = &db;
    int stop = 0;
    ctx.stop = &stop;
    exp_json_t body;
    int status = -1;
    exp_http_route(&ctx, "GET", "/api/blocks?limit=9999", &body, &status);
    int n = (status == 200) ? count_substr(body.buf, "\"height\":") : -1;
    int shape = status == 200 && strstr(body.buf, "{\"height\":150,\"block_id\":\"") &&
                strstr(body.buf, "\"applied_count\":0,\"n_items\":0}");
    exp_json_freebuf(&body);
    if (n != 100 || !shape) { FAIL("blocks clamp/shape"); exp_db_close(db); return; }

    exp_db_close(db);
    PASS();
}

/* /api/stats supply buckets: the stored blob is served as strings, pool
 * 1..9 in order, with circulating computed from the blob alone; an
 * underflowing blob keeps its buckets but answers circulating null; an
 * older node's blob answers every bucket null. */
static void test_route_stats_buckets(void) {
    TEST("route: /api/stats supply buckets + circulating (null on underflow)");

    exp_db_t *db = NULL;
    if (exp_db_open(":memory:", &db) != 0) { FAIL("open failed"); return; }

    nodus_dnac_supply_buckets_t b;
    uint8_t blob[EXP_SUPPLY_BUCKETS_BLOB_LEN];
    genesis_day_buckets(&b);
    exp_supply_buckets_pack(&b, blob);
    exp_db_set_meta_blob(db, EXP_META_SUPPLY_BUCKETS, blob, sizeof(blob));
    exp_db_set_meta_u64(db, "supply_genesis", NODUS_RAW(1000000000));

    static const char *const genesis_day[] = {
        "\"supply_genesis\":\"100000000000000000\"",
        "\"reward_pool\":\"20000000000000000\"",
        "\"treasury\":[\"10000000000000000\",\"10000000000000000\",\"5000000000000000\","
        "\"5000000000000000\",\"0\",\"0\",\"0\",\"0\",\"0\"]",
        "\"unclaimed\":\"5000000000000000\"",
        "\"circulating\":\"45000000000000000\"", NULL };
    if (route_expect(db, "/api/stats", 200, genesis_day) != 0) { FAIL("genesis-day stats"); exp_db_close(db); return; }

    b.reward_pool = b.current_supply + 1;
    exp_supply_buckets_pack(&b, blob);
    exp_db_set_meta_blob(db, EXP_META_SUPPLY_BUCKETS, blob, sizeof(blob));
    static const char *const underflow[] = { "\"reward_pool\":\"100000000000000001\"",
                                             "\"circulating\":null", NULL };
    if (route_expect(db, "/api/stats", 200, underflow) != 0) { FAIL("underflow must be null"); exp_db_close(db); return; }

    memset(&b, 0, sizeof(b));
    exp_supply_buckets_pack(&b, blob);
    exp_db_set_meta_blob(db, EXP_META_SUPPLY_BUCKETS, blob, sizeof(blob));
    static const char *const older[] = { "\"reward_pool\":null", "\"treasury\":null",
                                         "\"unclaimed\":null", "\"circulating\":null", NULL };
    if (route_expect(db, "/api/stats", 200, older) != 0) { FAIL("older node must be null"); exp_db_close(db); return; }

    exp_db_close(db);
    PASS();
}

static void test_route_block_tx_address(void) {
    TEST("route: /api/block, /api/tx (id + position), /api/address");

    exp_db_t *db = NULL;
    if (exp_db_open(":memory:", &db) != 0) { FAIL("open failed"); return; }
    if (seed_fixture(db) != 0) { FAIL("seed failed"); exp_db_close(db); return; }

    static const char *const block_needles[] = {
        "\"n_items\":3", "\"prev_id\":", "\"position\":\"1:1\"", "\"refused\":true",
        "\"code\":7", "\"op\":\"delegate\"", "\"next_from\":null", NULL };
    if (route_expect(db, "/api/block/1", 200, block_needles) != 0) { FAIL("block"); exp_db_close(db); return; }

    static const char *const page_needles[] = { "\"position\":\"1:0\"", "\"next_from\":1", NULL };
    if (route_expect(db, "/api/block/1?limit=1", 200, page_needles) != 0) { FAIL("block page"); exp_db_close(db); return; }

    char fp_a[129], fp_b[129], wire_hex[129], path[512];
    set_test_fp(fp_a, 'a');
    set_test_fp(fp_b, 'b');
    uint8_t wire[64];
    fill(wire, 64, 0x33);
    bytes_to_hex128(wire, wire_hex);

    char want_in[300], want_out[300];
    snprintf(want_in, sizeof(want_in), "\"address\":\"%s\",\"token_id\":", fp_a);
    snprintf(want_out, sizeof(want_out), "\"address\":\"%s\"", fp_b);
    const char *tx_needles[] = { "\"position\":\"1:2\"", "\"fee\":\"3000\"",
                                 "\"record\":{\"kind\":\"delegate\"", want_in,
                                 "\"address\":null,\"token_id\":null,\"amount\":null",
                                 want_out, "\"amount\":\"400\"", NULL };
    snprintf(path, sizeof(path), "/api/tx/%s", wire_hex);
    if (route_expect(db, path, 200, tx_needles) != 0) { FAIL("tx by wire id"); exp_db_close(db); return; }

    static const char *const refused_needles[] = { "\"refused\":true", "\"wire_id\":null",
                                                   "\"inputs\":[],\"outputs\":[]", NULL };
    if (route_expect(db, "/api/tx/1:1", 200, refused_needles) != 0) { FAIL("tx by position"); exp_db_close(db); return; }
    if (route_expect(db, "/api/tx/1:9", 404, NULL) != 0) { FAIL("missing position"); exp_db_close(db); return; }

    static const char *const addr_needles[] = { "\"balances\":null", "\"balance_status\":\"unavailable\"",
                                                "\"position\":\"1:2\"", "\"position\":\"1:0\"",
                                                "\"next_before\":null", NULL };
    snprintf(path, sizeof(path), "/api/address/%s", fp_a);
    if (route_expect(db, path, 200, addr_needles) != 0) { FAIL("address"); exp_db_close(db); return; }

    static const char *const addr_page[] = { "\"next_before\":\"1:2\"", NULL };
    snprintf(path, sizeof(path), "/api/address/%s?limit=1", fp_a);
    if (route_expect(db, path, 200, addr_page) != 0) { FAIL("address page cursor"); exp_db_close(db); return; }
    snprintf(path, sizeof(path), "/api/address/%s?before=nope", fp_a);
    if (route_expect(db, path, 400, NULL) != 0) { FAIL("address bad cursor"); exp_db_close(db); return; }

    exp_db_close(db);
    PASS();
}

static void test_route_search(void) {
    TEST("route: /api/search reports every match (tx, block, address)");

    exp_db_t *db = NULL;
    if (exp_db_open(":memory:", &db) != 0) { FAIL("open failed"); return; }

    /* One 128-hex string that is at once a wire id, the block id and an
     * owner fingerprint. */
    uint8_t H[64];
    fill(H, 64, 0xAB);
    char h_hex[129];
    bytes_to_hex128(H, h_hex);

    nodus_dnac_v3_block_result_t p;
    page_header(&p, 1, 1, 1, 1);
    memcpy(p.block_id, H, 64);
    p.count = 1;
    p.items = calloc(1, sizeof(nodus_dnac_v3_item_t));
    p.items[0].index = 0;
    p.items[0].kind = NODUS_DNAC_V3_KIND_ENVELOPE;
    p.items[0].has_wire_id = true;
    memcpy(p.items[0].wire_id, H, 64);
    p.items[0].has_effects = true;
    p.items[0].n_created = 1;
    fill(p.items[0].created[0].id, 64, 0x01);
    memcpy(p.items[0].created[0].owner, h_hex, 129);
    p.items[0].created[0].amount = 1;

    exp_block_batch_t b;
    exp_block_batch_init(&b);
    int rc = exp_extract_page(&p, &b);
    if (rc == 0) rc = exp_db_write_height(db, &b);
    exp_block_batch_free(&b);
    nodus_client_free_v3_block_result(&p);
    if (rc != 0) { FAIL("seed failed"); exp_db_close(db); return; }

    char path[256];
    snprintf(path, sizeof(path), "/api/search?q=%s", h_hex);
    static const char *const all3[] = { "\"type\":\"tx\"", "\"type\":\"block\"", "\"type\":\"address\"", NULL };
    if (route_expect(db, path, 200, all3) != 0) { FAIL("hex search"); exp_db_close(db); return; }

    static const char *const pos[] = { "{\"type\":\"tx\",\"target\":\"1:0\"}", NULL };
    if (route_expect(db, "/api/search?q=1:0", 200, pos) != 0) { FAIL("position search"); exp_db_close(db); return; }
    static const char *const height[] = { "{\"type\":\"block\",\"target\":\"1\"}", NULL };
    if (route_expect(db, "/api/search?q=1", 200, height) != 0) { FAIL("height search"); exp_db_close(db); return; }
    static const char *const none[] = { "{\"matches\":[]}", NULL };
    if (route_expect(db, "/api/search?q=zzz", 200, none) != 0) { FAIL("no-match search"); exp_db_close(db); return; }

    exp_db_close(db);
    PASS();
}

/* HF-4 NAME_REGISTER fixture (height 1):
 *   item 0: applied spend — creates coin X (owner A, 500 native)
 *   item 1: applied name_register "punk" — consumes X, creates change
 *           (owner A, 1), price 50000000000 ("nm"/"pr") */
static void name_fixture_page(nodus_dnac_v3_block_result_t *p) {
    page_header(p, 1, 2, 2, 1);
    p->count = 2;
    p->items = calloc(2, sizeof(nodus_dnac_v3_item_t));

    nodus_dnac_v3_item_t *it = &p->items[0];
    it->index = 0;
    it->kind = NODUS_DNAC_V3_KIND_ENVELOPE;
    it->has_wire_id = true;   fill(it->wire_id, 64, 0x51);
    it->has_intent_id = true; fill(it->intent_id, 64, 0x61);
    it->has_fee = true;       it->fee = 1000;
    strcpy(it->op, "spend");
    it->has_effects = true;
    it->n_created = 1;
    fill(it->created[0].id, 64, 0xD1);
    set_test_fp(it->created[0].owner, 'a');
    it->created[0].amount = 500;

    it = &p->items[1];
    it->index = 1;
    it->kind = NODUS_DNAC_V3_KIND_ENVELOPE;
    it->has_wire_id = true;   fill(it->wire_id, 64, 0x52);
    it->has_intent_id = true; fill(it->intent_id, 64, 0x62);
    it->has_fee = true;       it->fee = 1000;
    strcpy(it->op, "name_register");
    it->has_effects = true;
    it->n_consumed = 1;
    fill(it->consumed[0], 64, 0xD1);   /* X, created by item 0 */
    it->n_created = 1;
    fill(it->created[0].id, 64, 0xD2);
    set_test_fp(it->created[0].owner, 'a');
    it->created[0].amount = 1;
    strcpy(it->name, "punk");
    it->name_price = 50000000000ULL;
}

/* A registration is indexed with its name, price and owner (the first
 * input's resolved address); every other item answers name null; search
 * finds the name (type "name", the item's position); the index verifies. */
static void test_name_register_indexed(void) {
    TEST("HF-4: op 8 item -> item_names (name, price, owner) + search");

    exp_db_t *db = NULL;
    if (exp_db_open(":memory:", &db) != 0) { FAIL("open failed"); return; }
    nodus_dnac_v3_block_result_t p;
    name_fixture_page(&p);
    exp_block_batch_t b;
    exp_block_batch_init(&b);
    int rc = exp_extract_page(&p, &b);
    if (rc == 0) rc = exp_db_write_height(db, &b);
    exp_block_batch_free(&b);
    nodus_client_free_v3_block_result(&p);
    if (rc != 0) { FAIL("seed failed"); exp_db_close(db); return; }

    char fp_a[129], want_owner[200];
    set_test_fp(fp_a, 'a');
    snprintf(want_owner, sizeof(want_owner), "\"name_owner\":\"%s\"", fp_a);
    const char *tx_needles[] = { "\"op\":\"name_register\"", "\"name\":\"punk\"",
                                 "\"name_price\":\"50000000000\"", want_owner,
                                 "\"burned\":null", NULL };
    if (route_expect(db, "/api/tx/1:1", 200, tx_needles) != 0) { FAIL("registration item"); exp_db_close(db); return; }

    static const char *const plain[] = { "\"name\":null,\"name_price\":null,\"name_owner\":null", NULL };
    if (route_expect(db, "/api/tx/1:0", 200, plain) != 0) { FAIL("other item must carry name null"); exp_db_close(db); return; }

    static const char *const found[] = { "{\"type\":\"name\",\"target\":\"1:1\"}", NULL };
    if (route_expect(db, "/api/search?q=punk", 200, found) != 0) { FAIL("name search"); exp_db_close(db); return; }
    static const char *const none[] = { "{\"matches\":[]}", NULL };
    if (route_expect(db, "/api/search?q=punkk", 200, none) != 0) { FAIL("unknown name"); exp_db_close(db); return; }
    /* upper case is not how the chain stores a name: no match */
    if (route_expect(db, "/api/search?q=PUNK", 200, none) != 0) { FAIL("upper-case name"); exp_db_close(db); return; }

    char path[300];
    snprintf(path, sizeof(path), "/api/address/%s", fp_a);
    static const char *const addr[] = { "\"position\":\"1:1\"", "\"name\":\"punk\"", NULL };
    if (route_expect(db, path, 200, addr) != 0) { FAIL("owner history"); exp_db_close(db); return; }

    if (exp_db_verify_index(db) != 0) { FAIL("verify_index"); exp_db_close(db); return; }
    exp_db_close(db);
    PASS();
}

/* One applied chain_config vote item at (h, index). */
static void cc_item(nodus_dnac_v3_item_t *it, uint32_t index, uint8_t tag,
                    uint8_t param_id, uint64_t new_value, uint64_t effective) {
    it->index = index;
    it->kind = NODUS_DNAC_V3_KIND_ENVELOPE;
    it->has_wire_id = true;   fill(it->wire_id, 64, tag);
    it->has_intent_id = true; fill(it->intent_id, 64, (uint8_t)(tag + 1));
    strcpy(it->op, "chain_config");
    it->has_effects = true;
    it->rec_kind = NODUS_DNAC_V3_REC_CHAIN_CONFIG;
    it->cc_param_id = param_id;
    it->cc_new_value = new_value;
    it->cc_effective = effective;
}

/* Governance fixture:
 *   height 1: item 0 applied delegate (a record that is NOT chain_config),
 *             item 1 applied chain_config HF2_ACTIVE (7) = 1 @ 1500,
 *             item 2 refused envelope (no record)
 *   height 2: item 0 applied chain_config RULESET_GEN2 (9) =
 *             4962894749133920991 @ 3151 (above 2^53: a string),
 *             item 1 applied chain_config unknown id 200 = 5 @ 4000 */
static int seed_governance(exp_db_t *db) {
    nodus_dnac_v3_block_result_t p;
    exp_block_batch_t b;
    int rc;

    page_header(&p, 1, 3, 2, 2);
    p.count = 3;
    p.items = calloc(3, sizeof(nodus_dnac_v3_item_t));
    nodus_dnac_v3_item_t *it = &p.items[0];
    it->index = 0;
    it->kind = NODUS_DNAC_V3_KIND_ENVELOPE;
    it->has_wire_id = true;   fill(it->wire_id, 64, 0x71);
    it->has_intent_id = true; fill(it->intent_id, 64, 0x72);
    strcpy(it->op, "delegate");
    it->has_effects = true;
    it->rec_kind = NODUS_DNAC_V3_REC_DELEGATE;
    set_test_fp(it->rec_validator_fp, 'c');
    set_test_fp(it->rec_delegator_fp, 'a');
    it->rec_amount = 100;
    cc_item(&p.items[1], 1, 0x73, 7, 1, 1500);
    it = &p.items[2];
    it->index = 2;
    it->kind = NODUS_DNAC_V3_KIND_ENVELOPE;
    it->code = 7;
    strcpy(it->op, "chain_config");
    exp_block_batch_init(&b);
    rc = exp_extract_page(&p, &b);
    if (rc == 0) rc = exp_db_write_height(db, &b);
    exp_block_batch_free(&b);
    nodus_client_free_v3_block_result(&p);
    if (rc != 0) return rc;

    page_header(&p, 2, 2, 2, 2);
    p.count = 2;
    p.items = calloc(2, sizeof(nodus_dnac_v3_item_t));
    cc_item(&p.items[0], 0, 0x75, 9, 4962894749133920991ULL, 3151);
    cc_item(&p.items[1], 1, 0x77, 200, 5, 4000);
    exp_block_batch_init(&b);
    rc = exp_extract_page(&p, &b);
    if (rc == 0) rc = exp_db_write_height(db, &b);
    exp_block_batch_free(&b);
    nodus_client_free_v3_block_result(&p);
    return rc;
}

/* /api/governance lists exactly the chain_config records, (height, index)
 * ascending, with the param's name (null for an unknown id), the value as
 * a decimal string, the effective height, the item's ids, the stored tip
 * (null before the first observation) and truncated false. An empty index
 * answers an empty list. */
static void test_route_governance(void) {
    TEST("route: /api/governance (chain_config only, ordered, names, tip)");

    exp_db_t *db = NULL;
    if (exp_db_open(":memory:", &db) != 0) { FAIL("open failed"); return; }

    static const char *const empty[] = { "{\"tip\":null,\"indexed_height\":null,\"records\":[],\"truncated\":false}", NULL };
    if (route_expect(db, "/api/governance", 200, empty) != 0) { FAIL("empty index"); exp_db_close(db); return; }

    if (seed_governance(db) != 0) { FAIL("seed failed"); exp_db_close(db); return; }

    static const char *const no_tip[] = { "{\"tip\":null,\"indexed_height\":2,", NULL };
    if (route_expect(db, "/api/governance", 200, no_tip) != 0) { FAIL("tip must be null before observed"); exp_db_close(db); return; }

    exp_db_set_meta_u64(db, "tip_height", 3000);

    char wire[129], intent[129], want_ids[400];
    uint8_t w[64], in[64];
    fill(w, 64, 0x73); fill(in, 64, 0x74);
    bytes_to_hex128(w, wire);
    bytes_to_hex128(in, intent);
    snprintf(want_ids, sizeof(want_ids), "\"wire_id\":\"%s\",\"intent_id\":\"%s\"}", wire, intent);

    const char *const needles[] = {
        "{\"tip\":3000,\"indexed_height\":2,\"records\":[",
        "{\"position\":\"1:1\",\"height\":1,\"index\":1,\"time\":1700000001000,\"param_id\":7,"
        "\"param_name\":\"HF2_ACTIVE\",\"new_value\":\"1\",\"effective_height\":1500,",
        want_ids,
        "\"param_id\":9,\"param_name\":\"RULESET_GEN2\",\"new_value\":\"4962894749133920991\","
        "\"effective_height\":3151,",
        "\"param_id\":200,\"param_name\":null,\"new_value\":\"5\",\"effective_height\":4000,",
        "],\"truncated\":false}",
        NULL };

    exp_http_ctx_t ctx = {0};
    ctx.db = &db;
    int stop = 0;
    ctx.stop = &stop;
    exp_json_t body;
    int status = -1;
    if (exp_http_route(&ctx, "GET", "/api/governance", &body, &status) != 0) { FAIL("route"); exp_db_close(db); return; }
    int ok = (status == 200);
    for (int i = 0; ok && needles[i]; i++) if (!strstr(body.buf, needles[i])) ok = 0;
    /* exactly three records — the delegate record and the refused item are not listed */
    if (ok && count_substr(body.buf, "\"param_id\":") != 3) ok = 0;
    /* (height, index) ascending */
    if (ok) {
        const char *a = strstr(body.buf, "\"position\":\"1:1\"");
        const char *c = strstr(body.buf, "\"position\":\"2:0\"");
        const char *d = strstr(body.buf, "\"position\":\"2:1\"");
        if (!a || !c || !d || !(a < c && c < d)) ok = 0;
    }
    if (!ok) printf("(%d: %s) ", status, body.buf ? body.buf : "(null)");
    exp_json_freebuf(&body);
    if (!ok) { FAIL("governance body"); exp_db_close(db); return; }

    if (exp_db_verify_index(db) != 0) { FAIL("verify_index"); exp_db_close(db); return; }
    exp_db_close(db);
    PASS();
}

/* item_ok's name rule: a name only on an applied item, with a price, and
 * only of the chain's bytes; a price only with a name. Each bad page is
 * refused whole and leaves the batch empty. */
static void test_extract_refuses_bad_name(void) {
    TEST("HF-4: extract refuses a bad name / price / refused-item name");

    static const struct { const char *name; uint64_t price; uint32_t code; int effects; } bad[] = {
        { "Punk", 50000000000ULL, 0, 1 },        /* upper case            */
        { "ab", 50000000000ULL, 0, 1 },          /* too short             */
        { "deadbeef", 100000000ULL, 0, 1 },      /* all-hex, length 8     */
        { "punk", 0, 0, 1 },                     /* name without a price  */
        { "", 100000000ULL, 0, 1 },              /* price without a name  */
        { "punk", 50000000000ULL, 7, 0 },        /* refused item          */
    };
    for (size_t k = 0; k < sizeof(bad) / sizeof(bad[0]); k++) {
        nodus_dnac_v3_block_result_t p;
        name_fixture_page(&p);
        nodus_dnac_v3_item_t *it = &p.items[1];
        memset(it->name, 0, sizeof(it->name));
        strcpy(it->name, bad[k].name);
        it->name_price = bad[k].price;
        it->code = bad[k].code;
        if (!bad[k].effects) {
            it->has_effects = false;
            it->n_consumed = 0;
            it->n_created = 0;
            it->has_intent_id = false;
            it->has_wire_id = false;
        }
        exp_block_batch_t b;
        exp_block_batch_init(&b);
        int rc = exp_extract_page(&p, &b);
        size_t n = b.n_items;
        exp_block_batch_free(&b);
        nodus_client_free_v3_block_result(&p);
        if (rc == 0 || n != 0) {
            char msg[96];
            snprintf(msg, sizeof(msg), "bad case %zu accepted", k);
            FAIL(msg);
            return;
        }
    }
    /* "deadbee" (7 hex characters) is a legal name */
    nodus_dnac_v3_block_result_t p;
    name_fixture_page(&p);
    strcpy(p.items[1].name, "deadbee");
    exp_block_batch_t b;
    exp_block_batch_init(&b);
    int rc = exp_extract_page(&p, &b);
    exp_block_batch_free(&b);
    nodus_client_free_v3_block_result(&p);
    if (rc != 0) { FAIL("deadbee refused"); return; }
    PASS();
}

static void test_route_errors(void) {
    TEST("route: 404 unknown path, 405 POST, 400 malformed ids");

    exp_db_t *db = NULL;
    if (exp_db_open(":memory:", &db) != 0) { FAIL("open failed"); return; }

    exp_http_ctx_t ctx = {0};
    ctx.db = &db;
    int stop = 0;
    ctx.stop = &stop;
    exp_json_t body;
    int status = -1;
    exp_http_route(&ctx, "POST", "/api/stats", &body, &status);
    exp_json_freebuf(&body);
    if (status != 405) { FAIL("expected 405"); exp_db_close(db); return; }

    if (route_expect(db, "/api/nope", 404, NULL) != 0 ||
        route_expect(db, "/api/tx/not-a-valid-id", 400, NULL) != 0 ||
        route_expect(db, "/api/tx/0:1", 400, NULL) != 0 ||
        route_expect(db, "/api/block/xyz", 400, NULL) != 0 ||
        route_expect(db, "/api/block/1?from=abc", 400, NULL) != 0 ||
        route_expect(db, "/api/block/1", 404, NULL) != 0 ||
        route_expect(db, "/api/address/short", 400, NULL) != 0) {
        FAIL("error status mismatch");
        exp_db_close(db);
        return;
    }

    exp_db_close(db);
    PASS();
}

/* ctx->db is exp_db_t** so exp_http_route observes a confirmed-reset swap;
 * a NULL *ctx->db degrades to a clean 503 on every route. */
static void test_route_null_db_503(void) {
    TEST("route: *ctx->db == NULL -> 503 index unavailable");

    exp_db_t *null_db = NULL;
    static const char *const err[] = { "\"error\":", NULL };
    if (route_expect(null_db, "/api/stats", 503, err) != 0) { FAIL("expected 503"); return; }
    PASS();
}

/* ── /api/address balance (dnac_balance through exp_balance_source_t) ── */

typedef struct {
    int               mode;          /* 0 ok (two tokens), 1 fail, 2 ok empty */
    int               calls;
    char              last_owner[129];
    pthread_rwlock_t *lock;          /* when set: must NOT be held by us   */
    int               lock_was_free; /* the writer side could be taken     */
} fake_balance_t;

static int fake_balance_get(void *vctx, const char *owner_hex,
                            nodus_dnac_balance_result_t *out) {
    fake_balance_t *f = (fake_balance_t *)vctx;
    memset(out, 0, sizeof(*out));
    f->calls++;
    snprintf(f->last_owner, sizeof(f->last_owner), "%s", owner_hex);
    if (f->lock) {
        /* a writer can take the lock only if no reader holds it — i.e. the
         * route called us OUTSIDE its rdlock span */
        if (pthread_rwlock_trywrlock(f->lock) == 0) {
            f->lock_was_free = 1;
            pthread_rwlock_unlock(f->lock);
        }
    }
    if (f->mode == 1) return -1;
    out->tip = 42;
    if (f->mode == 2) return 0;
    out->count = 2;
    out->tokens = calloc(2, sizeof(*out->tokens));
    if (!out->tokens) { out->count = 0; return -1; }
    /* native first, as the node orders them */
    out->tokens[0].total = 700;
    out->tokens[0].spendable = 300;
    out->tokens[0].coins = 3;
    fill(out->tokens[1].token_id, 64, 0x07);
    out->tokens[1].total = 5;
    out->tokens[1].spendable = 5;
    out->tokens[1].coins = 1;
    return 0;
}

/* Route `path` with `src` wired and `lock` as db_lock; 0 when the status
 * matches and every needle occurs. */
static int route_expect_bal(exp_db_t *db, const exp_balance_source_t *src,
                            pthread_rwlock_t *lock, const char *path,
                            int want, const char *const *needles) {
    exp_http_ctx_t ctx = {0};
    ctx.db = &db;
    int stop = 0;
    ctx.stop = &stop;
    ctx.balance = src;
    ctx.db_lock = lock;

    exp_json_t body;
    int status = -1;
    if (exp_http_route(&ctx, "GET", path, &body, &status) != 0) return -1;
    int ok = (status == want);
    for (int i = 0; ok && needles && needles[i]; i++) {
        if (!strstr(body.buf, needles[i])) ok = 0;
    }
    if (!ok) printf("(%s -> %d: %s) ", path, status, body.buf ? body.buf : "(null)");
    exp_json_freebuf(&body);
    return ok ? 0 : -1;
}

static void test_route_address_balance(void) {
    TEST("route: /api/address balances from the source (ok / empty / unavailable)");

    exp_db_t *db = NULL;
    if (exp_db_open(":memory:", &db) != 0) { FAIL("open failed"); return; }
    if (seed_fixture(db) != 0) { FAIL("seed failed"); exp_db_close(db); return; }

    pthread_rwlock_t lock;
    if (pthread_rwlock_init(&lock, NULL) != 0) { FAIL("lock init"); exp_db_close(db); return; }

    fake_balance_t f;
    memset(&f, 0, sizeof(f));
    f.lock = &lock;
    exp_balance_source_t src = { &f, fake_balance_get };

    char fp_a[129], tok7[129], path[512], want_tok[200];
    set_test_fp(fp_a, 'a');
    uint8_t t7[64];
    fill(t7, 64, 0x07);
    bytes_to_hex128(t7, tok7);
    snprintf(path, sizeof(path), "/api/address/%s", fp_a);
    snprintf(want_tok, sizeof(want_tok),
             "{\"token_id\":\"%s\",\"total\":\"5\",\"spendable\":\"5\",\"coins\":1}", tok7);

    /* ok: the node's list, amounts as decimal strings, history intact */
    const char *ok_needles[] = {
        "\"balances\":[{\"token_id\":\"0000", "\"total\":\"700\",\"spendable\":\"300\",\"coins\":3}",
        want_tok, "\"balance_status\":\"ok\"", "\"position\":\"1:2\"", "\"next_before\":null", NULL };
    if (route_expect_bal(db, &src, &lock, path, 200, ok_needles) != 0) {
        FAIL("ok"); goto out;
    }
    if (f.calls != 1 || strcmp(f.last_owner, fp_a) != 0) { FAIL("source asked for the address"); goto out; }
    if (!f.lock_was_free) { FAIL("the balance was fetched under db_lock"); goto out; }

    /* empty: a real zero — status ok, an empty list */
    f.mode = 2;
    static const char *const empty_needles[] = { "\"balances\":[],\"balance_status\":\"ok\"", NULL };
    if (route_expect_bal(db, &src, &lock, path, 200, empty_needles) != 0) { FAIL("empty"); goto out; }

    /* the source fails: unavailable, never a zero; history still served */
    f.mode = 1;
    static const char *const bad_needles[] = { "\"balances\":null,\"balance_status\":\"unavailable\"",
                                               "\"position\":\"1:2\"", NULL };
    if (route_expect_bal(db, &src, &lock, path, 200, bad_needles) != 0) { FAIL("unavailable"); goto out; }

    /* a malformed address never reaches the source */
    f.calls = 0;
    if (route_expect_bal(db, &src, &lock, "/api/address/short", 400, NULL) != 0 || f.calls != 0) {
        FAIL("bad address reached the source"); goto out;
    }

    /* the index gone (a reset's reopen failure): 503, not a half answer */
    f.mode = 0;
    static const char *const err[] = { "\"error\":\"index unavailable\"", NULL };
    if (route_expect_bal(NULL, &src, &lock, path, 503, err) != 0) { FAIL("null db"); goto out; }

    pthread_rwlock_destroy(&lock);
    exp_db_close(db);
    PASS();
    return;
out:
    pthread_rwlock_destroy(&lock);
    exp_db_close(db);
}

/* ── /api/tps (throughput from block time) ─────────────────────────── */

/* Index a synthetic itemless block: height h, block time `time_ms`,
 * `applied` applied transactions (blocks.applied_count). */
static int write_tps_block(exp_db_t *db, uint64_t h, uint64_t time_ms, uint64_t applied) {
    exp_block_batch_t b;
    exp_block_batch_init(&b);
    b.have_header = 1;
    b.block.height = h;
    fill(b.block.block_id, 64, (uint8_t)(0x10 + h));
    fill(b.block.prev_id, 64, (uint8_t)(0x10 + h - 1));
    b.block.time_ms = time_ms;
    fill(b.block.proposer, 32, 0xA0);
    b.block.proposer_len = 32;
    b.block.applied_count = applied;
    b.block.n_items = 0;
    int rc = exp_db_write_height(db, &b);
    exp_block_batch_free(&b);
    return rc;
}

/* UTC hour start used by the tps fixtures (a real-epoch time). */
static uint64_t tps_hour0(void) {
    const uint64_t t = 1700000000000ULL;
    return t - t % EXP_TPS_HOUR_MS;
}

/* Bucketing over a synthetic index: now = the newest block's time (30 min
 * + 0.5 s into an hour); the minute and hour windows are (now - span, now]
 * — a block exactly at now - span is OUT, one ms later IN; history is 24
 * UTC-aligned hours oldest first, empty hours zero, a block older than 23 h
 * before the current hour absent, the hour in progress counted in its
 * elapsed seconds (rounded up). */
static void test_tps_bucketing(void) {
    TEST("exp_db: tps windows (edges exclusive) + 24 hourly buckets");

    const uint64_t H = EXP_TPS_HOUR_MS, T0 = tps_hour0();
    const uint64_t now = T0 + 30 * 60000 + 500;

    exp_db_t *db = NULL;
    if (exp_db_open(":memory:", &db) != 0) { FAIL("open failed"); return; }

    exp_tps_t t;
    if (exp_db_query_tps(db, &t) != 0 || t.have != 0) { FAIL("empty index must answer have=0"); exp_db_close(db); return; }

    const struct { uint64_t time_ms, applied; } blocks[] = {
        { T0 - 25 * H,          1000 },  /* before the history window */
        { T0 - 23 * H,          7 },     /* bucket 0, its first ms */
        { T0 - 22 * H - 1,      3 },     /* bucket 0, its last ms */
        { T0 - 2 * H + 5,       0 },     /* bucket 21, a heartbeat */
        { now - H,              11 },    /* bucket 22; last_hour edge: OUT */
        { now - H + 1,          13 },    /* bucket 22; last_hour: IN */
        { now - 60000,          17 },    /* bucket 23; last_minute edge: OUT */
        { now - 59999,          19 },    /* last_minute: IN */
        { now,                  2 },     /* the newest block = now */
    };
    for (size_t i = 0; i < sizeof(blocks) / sizeof(blocks[0]); i++) {
        if (write_tps_block(db, i + 1, blocks[i].time_ms, blocks[i].applied) != 0) {
            FAIL("seed failed"); exp_db_close(db); return;
        }
    }

    if (exp_db_query_tps(db, &t) != 0 || !t.have) { FAIL("query failed"); exp_db_close(db); return; }

    int ok = t.now_ms == now &&
             t.last_minute.blocks == 2 && t.last_minute.tx == 21 &&
             t.last_hour.blocks == 4 && t.last_hour.tx == 13 + 17 + 19 + 2 &&
             t.n_history == EXP_TPS_HISTORY_HOURS;
    if (!ok) { FAIL("windows wrong"); exp_db_close(db); return; }

    for (int i = 0; i < t.n_history; i++) {
        const exp_tps_bucket_t *b = &t.history[i];
        uint64_t want_blocks = 0, want_tx = 0, want_secs = 3600;
        if (i == 0)  { want_blocks = 2; want_tx = 10; }
        if (i == 21) { want_blocks = 1; want_tx = 0; }
        if (i == 22) { want_blocks = 2; want_tx = 24; }
        if (i == 23) { want_blocks = 3; want_tx = 38; want_secs = 1801; }
        if (b->start_ms != T0 - 23 * H + (uint64_t)i * H || b->start_ms % H != 0 ||
            b->count.blocks != want_blocks || b->count.tx != want_tx || b->seconds != want_secs) {
            printf("(bucket %d: start %llu blocks %llu tx %llu secs %llu) ", i,
                   (unsigned long long)b->start_ms, (unsigned long long)b->count.blocks,
                   (unsigned long long)b->count.tx, (unsigned long long)b->seconds);
            FAIL("bucket wrong");
            exp_db_close(db);
            return;
        }
    }

    /* the JSON shape: 24 buckets, decimal-string tps */
    char now_needle[64], first_needle[96];
    snprintf(now_needle, sizeof(now_needle), "{\"now_ms\":%llu,", (unsigned long long)now);
    snprintf(first_needle, sizeof(first_needle),
             "\"history\":[{\"start_ms\":%llu,\"tx\":10,\"blocks\":2,\"seconds\":3600,\"tps\":\"0.00\"}",
             (unsigned long long)(T0 - 23 * H));
    const char *const needles[] = {
        now_needle, first_needle,
        "\"last_minute\":{\"tx\":21,\"blocks\":2,\"seconds\":60,\"tps\":\"0.35\"}",
        "\"last_hour\":{\"tx\":51,\"blocks\":4,\"seconds\":3600,\"tps\":\"0.01\"}",
        "\"tx\":38,\"blocks\":3,\"seconds\":1801,\"tps\":\"0.02\"}]}",
        NULL };
    if (route_expect(db, "/api/tps", 200, needles) != 0) { FAIL("route shape"); exp_db_close(db); return; }

    exp_http_ctx_t ctx = {0};
    ctx.db = &db;
    int stop = 0;
    ctx.stop = &stop;
    exp_json_t body;
    int status = -1;
    exp_http_route(&ctx, "GET", "/api/tps", &body, &status);
    int n_buckets = (status == 200) ? count_substr(body.buf, "\"start_ms\":") : -1;
    exp_json_freebuf(&body);
    if (n_buckets != EXP_TPS_HISTORY_HOURS) { FAIL("history must hold 24 buckets"); exp_db_close(db); return; }

    exp_db_close(db);
    PASS();
}

/* tps strings: two decimals, half up, carried into the whole part; an
 * empty index answers nulls and an empty history. */
static void test_tps_rounding_and_empty(void) {
    TEST("route: /api/tps rounding (half up, carry) + empty index");

    exp_db_t *db = NULL;
    if (exp_db_open(":memory:", &db) != 0) { FAIL("open failed"); return; }

    static const char *const empty[] = {
        "{\"now_ms\":null,\"last_minute\":null,\"last_hour\":null,\"history\":[]}", NULL };
    if (route_expect(db, "/api/tps", 200, empty) != 0) { FAIL("empty index"); exp_db_close(db); return; }

    const uint64_t H = EXP_TPS_HOUR_MS, T0 = tps_hour0();
    const uint64_t now = T0 + 30 * 60000 + 500;          /* the hour in progress: 1801 s */
    /* bucket 22: 18 / 3600 = 0.005 -> "0.01" (half up, not truncated);
     * bucket 23: 5402 / 1801 = 2.9994 -> "3.00" (carry);
     * minute 5402 / 60 = 90.033 -> "90.03"; hour 5402 / 3600 = 1.5006 -> "1.50" */
    if (write_tps_block(db, 1, T0 - H + 10, 18) != 0 ||
        write_tps_block(db, 2, now, 5402) != 0) {
        FAIL("seed failed"); exp_db_close(db); return;
    }
    static const char *const needles[] = {
        "\"last_minute\":{\"tx\":5402,\"blocks\":1,\"seconds\":60,\"tps\":\"90.03\"}",
        "\"last_hour\":{\"tx\":5402,\"blocks\":1,\"seconds\":3600,\"tps\":\"1.50\"}",
        "\"tx\":18,\"blocks\":1,\"seconds\":3600,\"tps\":\"0.01\"}",
        "\"tx\":5402,\"blocks\":1,\"seconds\":1801,\"tps\":\"3.00\"}]}",
        NULL };
    if (route_expect(db, "/api/tps", 200, needles) != 0) { FAIL("rounding"); exp_db_close(db); return; }

    exp_db_close(db);
    PASS();
}

/* Bounded cost: the index file carries idx_blocks_time and sqlite plans
 * the window aggregate as a range search of it. */
static void test_tps_index_used(void) {
    TEST("exp_db: idx_blocks_time exists and serves the tps span query");

    char path[] = "/tmp/exp_db_tps_XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) { FAIL("mkstemp failed"); return; }
    close(fd);

    exp_db_t *db = NULL;
    if (exp_db_open(path, &db) != 0) { FAIL("open failed"); unlink_db_files(path); return; }
    exp_db_close(db);

    sqlite3 *raw = NULL;
    if (sqlite3_open(path, &raw) != SQLITE_OK) { FAIL("raw open failed"); unlink_db_files(path); return; }
    sqlite3_stmt *s = NULL;
    int n_idx = -1;
    if (sqlite3_prepare_v2(raw, "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = 'idx_blocks_time'",
                           -1, &s, NULL) == SQLITE_OK && sqlite3_step(s) == SQLITE_ROW) {
        n_idx = sqlite3_column_int(s, 0);
    }
    sqlite3_finalize(s);

    int uses_index = 0;
    s = NULL;
    if (sqlite3_prepare_v2(raw, "EXPLAIN QUERY PLAN SELECT COUNT(*), IFNULL(SUM(applied_count), 0) "
                                "FROM blocks WHERE time_ms > ?1 AND time_ms <= ?2",
                           -1, &s, NULL) == SQLITE_OK) {
        while (sqlite3_step(s) == SQLITE_ROW) {
            const unsigned char *detail = sqlite3_column_text(s, 3);
            if (detail && strstr((const char *)detail, "idx_blocks_time")) uses_index = 1;
        }
    }
    sqlite3_finalize(s);
    sqlite3_close(raw);
    unlink_db_files(path);

    if (n_idx != 1) { FAIL("idx_blocks_time missing"); return; }
    if (!uses_index) { FAIL("span query does not use idx_blocks_time"); return; }
    PASS();
}

int main(void) {
    printf("=== DNA Explorer Tests ===\n");

    test_db_schema_version();
    test_db_schema_rebuild_on_mismatch();
    test_write_height_and_queries();
    test_write_height_order_enforced();
    test_verify_index_detects_gap();
    test_extract_refuses_mismatched_page();
    test_sync_collect_concatenates_pages();
    test_sync_partial_height_keeps_watermark();
    test_sync_tick_height_bound();
    test_supply_buckets_pure();
    test_sync_stores_buckets();
    test_sync_fsm_keys_on_chain_id32();
    test_chain_config_load();
    test_chain_config_load_rejects_malformed();
    test_chain_config_load_rejects_port_zero();
    test_chain_config_load_rejects_duplicate();
    test_reset_fsm_match_is_no();
    test_reset_fsm_one_mismatch_pending();
    test_reset_fsm_same_server_twice_still_pending();
    test_reset_fsm_two_servers_two_polls_confirmed();
    test_reset_fsm_mismatch_then_match_back_to_no();
    test_reset_fsm_candidate_switch_restarts();
    test_reset_fsm_negative_index_does_not_mutate();
    test_sync_stale_name();
    test_json_str_escaping();
    test_json_hex_emit();
    test_route_stats_and_blocks();
    test_route_stats_buckets();
    test_route_block_tx_address();
    test_route_search();
    test_name_register_indexed();
    test_route_governance();
    test_extract_refuses_bad_name();
    test_route_errors();
    test_route_null_db_503();
    test_route_address_balance();
    test_tps_bucketing();
    test_tps_rounding_and_empty();
    test_tps_index_used();

    printf("\n=== Results: %d passed, %d failed ===\n", passed, failed);
    return failed > 0 ? 1 : 0;
}
