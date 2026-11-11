/**
 * test_amm_nodus_watch.c -- the nodus-amm Nodus watcher (amm_nodus_watch.c)
 * against a scriptable STUB node behind the amm_node.h seam table.
 *
 * WHAT IT PROVES (plan docs/plans/2026-11-08-swap-bot-plan.nodus1.md rev. 4,
 * section 19 "test_amm_engine" Nodus lines and section 8 step 6, section 11,
 * section 13, section 17; givens items 32, 49, 54, 59):
 *   N1  a native `spend_in` row on the bot's address whose peer is the
 *       request's sender, whose amount is the approved amount and whose block
 *       time is within the approval's validity COUNTS the swap (approved ->
 *       paid_waiting_depth -> counted in one transaction, the permanent
 *       marker "nodus:<hex>" written, the row stored `counted`), with the id
 *       kind WIRE (the wire id named in the request, matched through the
 *       address history);
 *   N2  the same with the id kind INTENT (the row's wire id resolved to the
 *       intent id by a block walk); and the two kinds are NOT interchangeable:
 *       an approval naming the intent id is not matched by a WIRE watcher and
 *       the other way round (both are held: plan question 12 is undecided,
 *       neither is a default; a zero id kind is refused at construction);
 *   N3  a TOKEN row (token not all zero) and every other kind (spend_out,
 *       burn, fee, claim) is IGNORED: no row is stored, no swap moves;
 *   N4  an unmatched payment is HELD (givens item 32): another sender,
 *       another amount, no approval at all; the row is stored `held` with its
 *       reason, no swap changes, the cursor still moves;
 *   N5  the start of an approval is a CHAIN HEIGHT, the end a block time (no
 *       wall clock is compared with chain state): a payment in a block at or
 *       below the committed tip read at approval is held (review finding
 *       (a); height == tip held, one above counts), ts after the expiry is
 *       held, ts == expiry counts; an approval with an unreadable tip (0) is
 *       refused;
 *   N6  a payment whose block time is within the validity and which the bot
 *       reads long after the expiry time still counts (givens item 54): the
 *       chain is far ahead, no wall clock is involved;
 *   N7  window observation (plan line 315): observed only when the history
 *       was processed through a block whose time is LATER than the expiry
 *       (equal is not later); not observed before any step, while a read
 *       fails (the cursor does not move) or while the block is not past the
 *       expiry; a later block releases it;
 *   N8  liquidity depth (givens item 49, plan line 328): tip - block >= 3
 *       counts, depth 2 does not; an unreadable tip is unknown, never a
 *       verdict;
 *   N9  ONE INCOMING TRANSFER, PAID AT MOST ONCE (givens item 59): a second
 *       approval naming the same transfer stays unpaid; a second row of the
 *       same transfer is held; a marker that already exists holds the row and
 *       leaves the swap approved; a row is never processed twice;
 *   N10 startup refusal (plan line 283): the node not indexing, a from_height
 *       of 0, or a from_height above the bot's start height refuses
 *       (AMM_NW_REFUSED, nothing written); from_height at the start height is
 *       accepted; the threshold stays the configured start height whatever the
 *       stored cursor is (cursor 12: from_height 13 and 6 refuse, 5 passes);
 *   N11 an unreadable answer is never a zero: tip, block time, a history page
 *       (also the second page), the block walk (incomplete or block not held)
 *       -> AMM_NW_UNKNOWN; nothing is written by a failed history read; rows
 *       before an unresolvable row are written, the cursor does not move, the
 *       next step skips what is recorded and counts the rest; an incomplete
 *       block walk RESUMES at its last validated page;
 *   N12 paging: pages of 2 rows, rows of one height split across pages, all
 *       rows judged oldest first;
 *   N13 configuration: a zero id kind, a page limit above 100, a missing
 *       seam function, a zero start height are refused (NULL);
 *   N14 restart: a reopened journal and a new watcher continue from the stored
 *       cursor; the commit failing between decision and write (test hook)
 *       writes nothing and the same rows are judged after the restart;
 *   N15 rows above the committed tip are not judged until the tip reaches
 *       them;
 *   N16 the pure matcher: kind, token, peer, amount, time bounds.
 * WHAT IT REQUIRES: a default build; one mkdtemp directory under /tmp, removed
 *   at the end; no network, no clock reads by the code under test.
 * LEAVES BEHIND: nothing.
 * HOW IT CAN LIE: the stub answers what the test tells it to; it proves the
 *   watcher's logic against those answers, not the node's behaviour (the real
 *   address index, the real block walk and the real chain are not here). Block
 *   times are scripted (1000 + 10 * height unless a test overrides them); the
 *   BFT-time monotonicity the window rule rests on is a property of the node
 *   (nodus_witness_cmt_host.c:1178), asserted by the scripted times only. The
 *   stub history is filtered and sorted by the stub, not by an index.
 */
#include <dirent.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "amm_nodus_watch.h"

static int g_failures = 0;
static int g_checks = 0;

#define CHECK(cond, what)                                                    \
    do {                                                                     \
        g_checks++;                                                          \
        if (cond) { printf("  ok    %s\n", what); }                          \
        else { printf("  FAIL  %s  (line %d)\n", what, __LINE__); g_failures++; } \
    } while (0)

/* ── the stub node ──────────────────────────────────────────────────── */

#define MAX_ROWS  64
#define MAX_ITEMS 32

typedef struct {
    uint64_t tip;
    int      tip_rc;                 /* non-zero: ruleset_info fails        */
    int      bt_rc;                  /* non-zero: block_time fails          */
    uint64_t bt_fixed;               /* non-zero: every block has this time */
    nodus_dnac_addr_history_entry_t rows[MAX_ROWS];
    int      nrows;
    int      enabled;
    uint64_t from_height;
    int      hist_rc;                /* non-zero: every history call fails  */
    int      hist_fail_call;         /* >0: this call number (1-based) fails */
    int      hist_calls;
    unsigned last_limit;
    struct { uint64_t h; uint8_t wire[64]; uint8_t intent[64]; } items[MAX_ITEMS];
    int      nitems;
    int      item_rc;                /* AMM_NODE_ERR / NOT_HELD: every walk fails */
    uint64_t item_fail_h;            /* non-zero: the walk of THIS height fails ... */
    int      item_fail_rc;           /* ... with this code                    */
    int      item_calls;
    int      item_slow_pages;        /* >0: the first call stops at page 3 (ERR) */
    uint32_t item_last_from;         /* the `from` the latest call started at */
    int      item_from0_calls;
} stub_t;

static uint64_t bt_of(const stub_t *s, uint64_t h) {
    return s->bt_fixed ? s->bt_fixed : 1000 + 10 * h;
}

static int s_ruleset(void *c, nodus_dnac_ruleset_info_t *out, uint64_t dl) {
    stub_t *s = c; (void)dl;
    if (s->tip_rc) return AMM_NODE_ERR;
    memset(out, 0, sizeof(*out));
    out->tip = s->tip;
    return AMM_NODE_OK;
}

static int s_block_time(void *c, uint64_t h, uint64_t *t, uint64_t dl) {
    stub_t *s = c; (void)dl;
    if (s->bt_rc) return s->bt_rc;
    *t = bt_of(s, h);
    return AMM_NODE_OK;
}

static int cmp_desc(const void *a, const void *b) {
    const nodus_dnac_addr_history_entry_t *x = a, *y = b;
    if (x->h != y->h) return x->h < y->h ? 1 : -1;
    if (x->i != y->i) return x->i < y->i ? 1 : -1;
    if (x->q != y->q) return x->q < y->q ? 1 : -1;
    return 0;
}

static int s_history(void *c, unsigned limit, const nodus_dnac_addr_history_cursor_t *before,
                     nodus_dnac_addr_history_result_t *out, uint64_t dl) {
    stub_t *s = c; (void)dl;
    s->hist_calls++;
    s->last_limit = limit;
    if (s->hist_rc) return AMM_NODE_ERR;
    if (s->hist_fail_call && s->hist_calls == s->hist_fail_call) return AMM_NODE_ERR;
    nodus_dnac_addr_history_entry_t sorted[MAX_ROWS];
    memcpy(sorted, s->rows, (size_t)s->nrows * sizeof(sorted[0]));
    qsort(sorted, (size_t)s->nrows, sizeof(sorted[0]), cmp_desc);
    memset(out, 0, sizeof(*out));
    out->enabled = s->enabled != 0;
    out->from_height = s->from_height;
    out->entries = calloc(limit ? limit : 1, sizeof(*out->entries));
    for (int i = 0; i < s->nrows && out->count < limit; i++) {
        const nodus_dnac_addr_history_entry_t *e = &sorted[i];
        if (before) {                       /* strictly older than the cursor */
            int older = e->h < before->h ||
                        (e->h == before->h && (e->i < before->i ||
                         (e->i == before->i && e->q < before->q)));
            if (!older) continue;
        }
        out->entries[out->count++] = *e;
    }
    return AMM_NODE_OK;
}

static void s_history_free(void *c, nodus_dnac_addr_history_result_t *r) {
    (void)c;
    free(r->entries);
    r->entries = NULL;
    r->count = 0;
}

static int s_item_intent(void *c, uint64_t h, const uint8_t wire[64], uint8_t intent[64],
                         uint32_t *from, int *found, uint64_t dl) {
    stub_t *s = c; (void)dl;
    s->item_calls++;
    s->item_last_from = *from;
    if (*from == 0) s->item_from0_calls++;
    if (s->item_rc) return s->item_rc;
    if (s->item_fail_h && h == s->item_fail_h) return s->item_fail_rc;
    if (s->item_slow_pages > 0) {            /* a slow block: stops at page 3 once */
        if (*from < 3) { *from = 3; s->item_slow_pages = 0; return AMM_NODE_ERR; }
    }
    *found = 0;
    for (int i = 0; i < s->nitems; i++)
        if (s->items[i].h == h && !memcmp(s->items[i].wire, wire, 64)) {
            memcpy(intent, s->items[i].intent, 64);
            *found = 1;
        }
    return AMM_NODE_OK;
}

static void stub_vt(stub_t *s, amm_node_t *vt) {
    memset(vt, 0, sizeof(*vt));
    vt->ctx = s;
    vt->ruleset_info = s_ruleset;
    vt->block_time = s_block_time;
    vt->addr_history = s_history;
    vt->addr_history_free = s_history_free;
    vt->item_intent = s_item_intent;
}

/* ── fixtures ───────────────────────────────────────────────────────── */

static char g_dir[64], g_path[128];
static amm_journal_t *g_j;
static stub_t g_s;
static amm_node_t g_vt;
static amm_nodus_watch_t *g_w;
static uint64_t g_ctr = 1;
static uint64_t g_atip = 5;     /* the committed tip the next approval "read" (0 = unreadable) */

static void cleanup_dir(void) {
    DIR *d = opendir(g_dir);
    if (!d) return;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        char p[512];
        snprintf(p, sizeof(p), "%s/%s", g_dir, e->d_name);
        unlink(p);
    }
    closedir(d);
    rmdir(g_dir);
}

static amm_nodus_watch_cfg_t mkcfg(amm_nw_id_kind_t kind) {
    amm_nodus_watch_cfg_t c;
    memset(&c, 0, sizeof(c));
    c.node = &g_vt;
    c.journal = g_j;
    c.id_kind = kind;
    c.start_height = 5;
    c.liquidity_wait_blocks = 3;
    c.page_limit = 100;
    c.max_pages = 50;
    c.inflight_max = 500000000ULL;     /* the room a seen payment takes (plan section 13, revision 12) */
    return c;
}

static void stub_reset(void) {
    memset(&g_s, 0, sizeof(g_s));
    g_s.tip = 12;
    g_s.enabled = 1;
    g_s.from_height = 1;
    stub_vt(&g_s, &g_vt);
}

/* A fresh journal, a fresh stub, a watcher of the given id kind. */
static void fresh(amm_nw_id_kind_t kind) {
    if (g_w) { amm_nodus_watch_free(g_w); g_w = NULL; }
    if (g_j) { amm_journal_close(g_j); g_j = NULL; }
    unlink(g_path);
    char p[160];
    snprintf(p, sizeof(p), "%s-wal", g_path); unlink(p);
    snprintf(p, sizeof(p), "%s-shm", g_path); unlink(p);
    if (amm_journal_open(g_path, &g_j) != 0) { printf("FATAL open\n"); exit(2); }
    stub_reset();
    g_atip = 5;
    amm_nodus_watch_cfg_t c = mkcfg(kind);
    g_w = amm_nodus_watch_new(&c);
    if (!g_w) { printf("FATAL watcher\n"); exit(2); }
}

static void restart(amm_nw_id_kind_t kind) {
    amm_nodus_watch_free(g_w);
    amm_journal_close(g_j);
    if (amm_journal_open(g_path, &g_j) != 0) { printf("FATAL reopen\n"); exit(2); }
    amm_nodus_watch_cfg_t c = mkcfg(kind);
    g_w = amm_nodus_watch_new(&c);
    if (!g_w) { printf("FATAL watcher\n"); exit(2); }
}

static void peer_of(char c, char out[129]) { memset(out, c, 128); out[128] = '\0'; }

static void mkid(uint8_t b, uint8_t id[64]) { memset(id, b, 64); }

/* A NODUS -> USDT approval from sender 128 x `c`, naming the transfer id
 * 64 x `idb` ("nodus:<hex>"), for `amount`, valid [approved_at, expiry]. */
static int approve(char c, uint64_t amount, uint8_t idb, uint64_t approved_at,
                   uint64_t expiry, amm_swap_t *s) {
    static char snd[16][129], idt[16][AMM_TID_MAX], dst[41];
    static unsigned k = 0;
    unsigned i = k++ % 16;
    peer_of(c, snd[i]);
    memset(dst, 'b', 40); dst[40] = '\0';
    uint8_t id[64];
    mkid(idb, id);
    amm_nodus_watch_id_text(id, idt[i], sizeof(idt[i]));
    amm_approve_t a;
    memset(&a, 0, sizeof(a));
    a.dir = AMM_NODUS_TO_USDT;
    a.sender = snd[i]; a.dest = dst;
    a.amount = amount; a.minimum = 1; a.value_usdt = 1;
    a.approved_at = approved_at; a.expiry = expiry;
    a.approved_tip = g_atip;
    a.incoming_id = idt[i];
    uint64_t n = g_ctr++;
    for (int b = 0; b < 8; b++) a.req_no[31 - b] = (uint8_t)(n >> (8 * b));
    for (int b = 0; b < 16; b++) a.rand16[b] = (uint8_t)(n * 29 + b);
    a.swap_max = 100000000ULL; a.inflight_max = 500000000ULL;
    return amm_journal_approve(g_j, &a, s) == AMM_J_OK;
}

/* A history row. kind "spend_in" unless given; token all zero unless tokb. */
static void add_row(uint64_t h, uint32_t i, uint32_t q, const char *kind, char peer_c,
                    uint64_t amount, uint64_t ts, uint8_t wireb, uint8_t tokb) {
    nodus_dnac_addr_history_entry_t *e = &g_s.rows[g_s.nrows++];
    memset(e, 0, sizeof(*e));
    e->h = h; e->i = i; e->q = q;
    snprintf(e->kind, sizeof(e->kind), "%s", kind);
    e->amount = amount;
    if (tokb) memset(e->token_id, tokb, 64);
    if (peer_c) peer_of(peer_c, e->peer);
    e->has_wire = 1;
    memset(e->wire_id, wireb, 64);
    e->ts = ts;
}

static void pay(uint64_t h, char peer_c, uint64_t amount, uint64_t ts, uint8_t wireb) {
    add_row(h, 0, 0, "spend_in", peer_c, amount, ts, wireb, 0);
}

static int swap_is(const amm_swap_t *s, const char *st) {
    amm_swap_t g;
    return amm_journal_swap_by_seq(g_j, s->seq, &g) == 0 && !strcmp(g.state, st);
}

static int nrows_state(const char *st) {
    amm_nrow_t l[64];
    int n = 0;
    return amm_journal_nrow_list(g_j, st, l, 64, &n) == 0 ? n : -1;
}

static uint64_t cursor(const char *name) {
    uint64_t v = 0;
    return amm_journal_cursor_get(g_j, name, &v) == 0 ? v : (uint64_t)-1;
}

static int step(amm_nodus_step_t *o) { return amm_nodus_watch_step(g_w, 0, o); }

static int fail_hook(void) { return 1; }

/* ── tests ──────────────────────────────────────────────────────────── */

static void n1_wire(void) {
    printf("N1 matched by the wire id\n");
    fresh(AMM_NW_ID_WIRE);
    amm_swap_t s;
    CHECK(approve('c', 500, 0x11, 1000, 2000, &s), "setup: an approval naming wire id 0x11..");
    pay(10, 'c', 500, 1100, 0x11);
    amm_nodus_step_t o;
    CHECK(step(&o) == AMM_NW_OK && o.rows == 1 && o.counted == 1 && o.held == 0 && o.tip == 12 &&
          o.through == 12, "the step counts the payment");
    CHECK(swap_is(&s, "counted"), "the swap is counted");
    uint8_t id[64];
    char txt[AMM_TID_MAX];
    mkid(0x11, id);
    amm_nodus_watch_id_text(id, txt, sizeof(txt));
    CHECK(strlen(txt) == 134 && !strncmp(txt, "nodus:1111", 10), "the id text is nodus:<128 hex>");
    CHECK(amm_journal_marker_exists(g_j, txt) == 0, "the permanent marker nodus:<hex> is written");
    amm_nrow_t r;
    CHECK(amm_journal_nrow_get(g_j, 10, 0, 0, &r) == 0 && !strcmp(r.state, "counted") &&
          r.swap_seq == s.seq && r.amount == 500 && r.ts == 1100, "the row is stored counted with its swap");
    CHECK(cursor("nodus_scan") == 12 && cursor("nodus_scan_ts") == 1120,
          "the cursor and the header time of its block moved together");
    CHECK(g_s.item_calls == 0, "the WIRE kind needs no block walk");
    CHECK(step(&o) == AMM_NW_OK && o.rows == 0 && o.counted == 0, "a second step judges nothing again");
}

static void n2_intent(void) {
    printf("N2 matched by the intent id; the two kinds are not interchangeable\n");
    fresh(AMM_NW_ID_INTENT);
    amm_swap_t s;
    CHECK(approve('c', 500, 0x22, 1000, 2000, &s), "setup: an approval naming INTENT id 0x22..");
    pay(10, 'c', 500, 1100, 0x11);                    /* the row carries the wire id 0x11.. */
    g_s.items[g_s.nitems].h = 10;
    mkid(0x11, g_s.items[g_s.nitems].wire);
    mkid(0x22, g_s.items[g_s.nitems].intent);
    g_s.nitems++;
    amm_nodus_step_t o;
    CHECK(step(&o) == AMM_NW_OK && o.counted == 1 && swap_is(&s, "counted"),
          "the wire id is resolved to the intent id by a block walk and the swap counts");
    CHECK(g_s.item_calls == 1, "one block walk");
    uint8_t id[64];
    char txt[AMM_TID_MAX];
    mkid(0x22, id);
    amm_nodus_watch_id_text(id, txt, sizeof(txt));
    CHECK(amm_journal_marker_exists(g_j, txt) == 0, "the marker is keyed by the INTENT id");

    /* a WIRE watcher does not match an approval that names the intent id */
    fresh(AMM_NW_ID_WIRE);
    CHECK(approve('c', 500, 0x22, 1000, 2000, &s), "setup: approval naming 0x22.. (the intent id)");
    pay(10, 'c', 500, 1100, 0x11);
    CHECK(step(&o) == AMM_NW_OK && o.counted == 0 && o.held == 1 && swap_is(&s, "approved"),
          "WIRE kind: the row (wire 0x11..) does not match an approval naming 0x22..: held");
    /* an INTENT watcher does not match an approval that names the wire id */
    fresh(AMM_NW_ID_INTENT);
    CHECK(approve('c', 500, 0x11, 1000, 2000, &s), "setup: approval naming 0x11.. (the wire id)");
    pay(10, 'c', 500, 1100, 0x11);
    g_s.items[0].h = 10; mkid(0x11, g_s.items[0].wire); mkid(0x22, g_s.items[0].intent); g_s.nitems = 1;
    CHECK(step(&o) == AMM_NW_OK && o.counted == 0 && o.held == 1 && swap_is(&s, "approved"),
          "INTENT kind: an approval naming the wire id is not matched: held");
    /* the block holds no applied item with that wire id: held, never matched */
    fresh(AMM_NW_ID_INTENT);
    CHECK(approve('c', 500, 0x22, 1000, 2000, &s), "setup");
    pay(10, 'c', 500, 1100, 0x11);
    CHECK(step(&o) == AMM_NW_OK && o.held == 1 && o.counted == 0, "no applied item with the wire id: held");
    amm_nrow_t r;
    CHECK(amm_journal_nrow_get(g_j, 10, 0, 0, &r) == 0 && strstr(r.reason, "no applied item") != NULL,
          "  with its reason");
    /* no default */
    amm_nodus_watch_cfg_t c = mkcfg((amm_nw_id_kind_t)0);
    CHECK(amm_nodus_watch_new(&c) == NULL, "id kind 0 (no default) is refused");
}

static void n3_ignored(void) {
    printf("N3 token rows and other kinds are ignored\n");
    fresh(AMM_NW_ID_WIRE);
    amm_swap_t s;
    CHECK(approve('c', 500, 0x11, 1000, 2000, &s), "setup");
    add_row(10, 0, 0, "spend_in", 'c', 500, 1100, 0x11, 0x05);    /* a TOKEN payment of 500 */
    add_row(10, 1, 0, "spend_out", 'c', 500, 1100, 0x11, 0);
    add_row(10, 2, 0, "burn", 0, 500, 1100, 0x11, 0);
    add_row(11, 0, 0, "fee", 0, 500, 1110, 0x11, 0);
    add_row(11, 1, 0, "claim", 0, 500, 1110, 0x11, 0);
    amm_nodus_step_t o;
    CHECK(step(&o) == AMM_NW_OK && o.rows == 0 && o.ignored == 5, "five history rows ignored");
    CHECK(nrows_state(NULL) == 0, "no row is stored (a token row is not even held)");
    CHECK(swap_is(&s, "approved"), "the swap does not move");
    CHECK(cursor("nodus_scan") == 12, "the cursor moved");
}

static void n4_held(void) {
    printf("N4 an unmatched payment is held\n");
    fresh(AMM_NW_ID_WIRE);
    amm_swap_t s;
    CHECK(approve('c', 500, 0x11, 1000, 2000, &s), "setup: approval for sender c, amount 500, id 0x11..");
    pay(8, 'd', 500, 1080, 0x11);       /* another sender, the id of the approval */
    pay(9, 'c', 501, 1090, 0x11);       /* the right sender, another amount        */
    pay(10, 'c', 500, 1100, 0x33);      /* the right sender and amount, another id */
    pay(11, 'e', 7, 1110, 0x44);        /* no approval at all                      */
    amm_nodus_step_t o;
    CHECK(step(&o) == AMM_NW_OK && o.rows == 4 && o.held == 4 && o.counted == 0, "four rows, all held");
    CHECK(nrows_state("held") == 4 && nrows_state("counted") == 0, "four held rows stored");
    CHECK(swap_is(&s, "approved"), "the approval is untouched (not paid)");
    amm_nrow_t r;
    CHECK(amm_journal_nrow_get(g_j, 11, 0, 0, &r) == 0 && !strcmp(r.state, "held") &&
          strstr(r.reason, "no approval") != NULL && r.swap_seq == 0, "a held row says why and names no swap");
    CHECK(cursor("nodus_scan") == 12, "the cursor moved past the held rows");
    amm_nrow_t l[8];
    int n = 0;
    CHECK(amm_journal_nrow_list(g_j, "held", l, 8, &n) == 0 && n == 4 && l[0].height == 8 && l[3].height == 11,
          "the held rows are listed for the operator in order");
}

static void n5_time(void) {
    printf("N5 chain height bounds the start, block time bounds the end\n");
    fresh(AMM_NW_ID_WIRE);
    amm_swap_t s1, s2, s3, s4, s5, s6;
    /* every approval is valid until 1500; the lower bound is the committed tip the
     * bot read at approval (g_atip), never a wall-clock time */
    g_atip = 9;                                    /* a payment in block 9 is NOT above it */
    CHECK(approve('1', 10, 0x01, 1200, 1500, &s1), "setup: approval read at tip 9");
    g_atip = 5;
    CHECK(approve('2', 10, 0x02, 1200, 1500, &s2) && approve('4', 10, 0x04, 1200, 1500, &s4),
          "setup: approvals read at tip 5");
    g_atip = 10;                                   /* a payment in block 11 is one above it */
    CHECK(approve('3', 10, 0x03, 1200, 1500, &s3), "setup: approval read at tip 10");
    g_atip = 13;
    CHECK(approve('5', 10, 0x05, 1200, 1500, &s5), "setup: approval read at tip 13");
    g_atip = 13;
    CHECK(approve('6', 10, 0x06, 1200, 1500, &s6), "setup: approval read at tip 13");
    g_atip = 0;                                    /* an unreadable tip refuses the approval */
    amm_swap_t sx;
    CHECK(!approve('7', 10, 0x07, 1200, 1500, &sx), "an unreadable tip (0): the approval is refused, never stored as 0");
    g_atip = 5;
    pay(9, '1', 10, 1300, 0x01);        /* block 9 == the approval's tip: not above it  */
    pay(10, '2', 10, 1501, 0x02);       /* one second after the expiry                  */
    pay(11, '3', 10, 1300, 0x03);       /* block 11 == tip 10 + 1: counts               */
    pay(12, '4', 10, 1500, 0x04);       /* exactly the expiry: counts                   */
    pay(13, '5', 10, 1300, 0x05);       /* block 13 == the approval's tip 13: held      */
    g_s.tip = 14;
    add_row(14, 0, 0, "spend_in", '6', 10, 1300, 0x06, 0);   /* one above tip 13: counts */
    amm_nodus_step_t o;
    CHECK(step(&o) == AMM_NW_OK && o.counted == 3 && o.held == 3, "three counted, three held");
    CHECK(swap_is(&s1, "approved") && swap_is(&s2, "approved") && swap_is(&s5, "approved"),
          "height == tip, after the expiry: the swaps stay unpaid");
    CHECK(swap_is(&s3, "counted") && swap_is(&s4, "counted") && swap_is(&s6, "counted"),
          "one block above the tip counts; ts == expiry counts");
    amm_nrow_t r;
    CHECK(amm_journal_nrow_get(g_j, 9, 0, 0, &r) == 0 && strstr(r.reason, "before") != NULL,
          "the early row says it is not above the tip read at the approval");
    CHECK(amm_journal_nrow_get(g_j, 10, 0, 0, &r) == 0 && strstr(r.reason, "after") != NULL,
          "the late row says it is after the expiry");
}

static void n6_late_read(void) {
    printf("N6 an in-window payment read after the expiry time counts\n");
    fresh(AMM_NW_ID_WIRE);
    amm_swap_t s;
    CHECK(approve('c', 500, 0x11, 1000, 1100, &s), "setup: valid [1000, 1100]");
    pay(10, 'c', 500, 1100, 0x11);
    g_s.tip = 500;                       /* the chain is far ahead: block time 6000 */
    amm_nodus_step_t o;
    CHECK(step(&o) == AMM_NW_OK && o.counted == 1 && swap_is(&s, "counted"),
          "read at tip 500 (block time 6000 > expiry 1100), ts 1100 <= expiry: counted");
    CHECK(amm_nodus_watch_window_observed(g_w, 1100) == 1, "and the window is observed");
}

static void n7_window(void) {
    printf("N7 window observation\n");
    fresh(AMM_NW_ID_WIRE);
    CHECK(amm_nodus_watch_window_observed(g_w, 1000) == 0, "before any step: not observed");
    amm_nodus_step_t o;
    CHECK(step(&o) == AMM_NW_OK && cursor("nodus_scan_ts") == 1120, "a step at tip 12 (block time 1120)");
    CHECK(amm_nodus_watch_window_observed(g_w, 1119) == 1, "expiry 1119 < 1120: observed");
    CHECK(amm_nodus_watch_window_observed(g_w, 1120) == 0, "expiry 1120 == block time: NOT observed (later is required)");
    CHECK(amm_nodus_watch_window_observed(g_w, 1200) == 0, "expiry 1200 > block time: not observed");
    /* a failed read does not move the cursor: the window stays open */
    g_s.tip = 20;
    g_s.bt_rc = AMM_NODE_ERR;
    CHECK(step(&o) == AMM_NW_UNKNOWN && cursor("nodus_scan") == 12, "block time unreadable: unknown, cursor unmoved");
    CHECK(amm_nodus_watch_window_observed(g_w, 1200) == 0, "expiry 1200 still not observed");
    g_s.bt_rc = 0;
    g_s.hist_rc = AMM_NODE_ERR;
    CHECK(step(&o) == AMM_NW_UNKNOWN && cursor("nodus_scan") == 12, "history unreadable: unknown, cursor unmoved");
    CHECK(amm_nodus_watch_window_observed(g_w, 1200) == 0, "the clock does not release the window");
    g_s.hist_rc = 0;
    CHECK(step(&o) == AMM_NW_OK && cursor("nodus_scan") == 20, "readable again: the cursor moves to 20 (time 1200)");
    CHECK(amm_nodus_watch_window_observed(g_w, 1200) == 0, "expiry 1200 == block time 1200: still not observed");
    g_s.tip = 21;
    CHECK(step(&o) == AMM_NW_OK && amm_nodus_watch_window_observed(g_w, 1200) == 1,
          "tip 21 (time 1210) > 1200: observed");
    /* survives a restart: recomputed from the stored cursor, not from the clock */
    restart(AMM_NW_ID_WIRE);
    CHECK(amm_nodus_watch_window_observed(g_w, 1200) == 1 && amm_nodus_watch_window_observed(g_w, 1210) == 0,
          "the observation survives a restart (stored cursor and time)");
}

static void n8_depth(void) {
    printf("N8 liquidity depth: 3 Nodus blocks\n");
    CHECK(amm_nodus_depth_ok(12, 10, 3) == 0, "tip 12, block 10: depth 2 not counted");
    CHECK(amm_nodus_depth_ok(13, 10, 3) == 1, "tip 13, block 10: depth 3 counted");
    CHECK(amm_nodus_depth_ok(10, 10, 3) == 0 && amm_nodus_depth_ok(5, 10, 3) == 0,
          "a tip at or below the block is never deep");
    CHECK(amm_nodus_depth_ok(10, 10, 0) == 1, "wait 0: the block itself");
    fresh(AMM_NW_ID_WIRE);
    int reached = 9;
    g_s.tip = 12;
    CHECK(amm_nodus_watch_depth_reached(g_w, 10, 0, &reached) == 0 && reached == 0, "stub tip 12: not reached");
    g_s.tip = 13;
    CHECK(amm_nodus_watch_depth_reached(g_w, 10, 0, &reached) == 0 && reached == 1, "stub tip 13: reached");
    g_s.tip_rc = AMM_NODE_ERR;
    reached = 9;
    CHECK(amm_nodus_watch_depth_reached(g_w, 10, 0, &reached) == 1 && reached == 9,
          "an unreadable tip is unknown, never a verdict");
}

static void n9_once(void) {
    printf("N9 one incoming transfer, paid at most once\n");
    fresh(AMM_NW_ID_WIRE);
    amm_swap_t a, b;
    CHECK(approve('c', 500, 0x11, 1000, 2000, &a) && approve('d', 500, 0x11, 1000, 2000, &b),
          "setup: two approvals (different senders) naming the SAME transfer id");
    pay(10, 'c', 500, 1100, 0x11);
    add_row(10, 0, 1, "spend_in", 'c', 500, 1100, 0x11, 0);    /* a second row of the same transfer */
    amm_nodus_step_t o;
    CHECK(step(&o) == AMM_NW_OK && o.counted == 1 && o.held == 1, "one row counts, the second row of the transfer is held");
    CHECK(swap_is(&a, "counted") && swap_is(&b, "approved"), "the second approval stays unpaid");
    amm_nrow_t r;
    CHECK(amm_journal_nrow_get(g_j, 10, 0, 1, &r) == 0 && !strcmp(r.state, "held"), "the second row is held");
    /* a later row from the second sender with the same id: the id is taken */
    pay(13, 'd', 500, 1130, 0x11);
    g_s.tip = 20;
    CHECK(step(&o) == AMM_NW_OK && o.held == 1 && o.counted == 0 && swap_is(&b, "approved"),
          "a later payment naming the same id from the other sender: held, its swap not paid");
    /* an existing marker (as a previous run would have left it) holds the row */
    fresh(AMM_NW_ID_WIRE);
    amm_swap_t c;
    CHECK(approve('c', 500, 0x55, 1000, 2000, &c), "setup");
    uint8_t id[64];
    char txt[AMM_TID_MAX], sql[300];
    mkid(0x55, id);
    amm_nodus_watch_id_text(id, txt, sizeof(txt));
    snprintf(sql, sizeof(sql), "INSERT INTO paid_markers(transfer_id, swap_seq) VALUES('%s', 999)", txt);
    sqlite3 *db = NULL;
    CHECK(sqlite3_open(g_path, &db) == SQLITE_OK && sqlite3_exec(db, sql, NULL, NULL, NULL) == SQLITE_OK,
          "a marker of an earlier payout exists");
    sqlite3_close(db);
    pay(10, 'c', 500, 1100, 0x55);
    CHECK(step(&o) == AMM_NW_OK && o.held == 1 && o.counted == 0 && swap_is(&c, "approved"),
          "the row is held and the swap is not paid twice");
    CHECK(amm_journal_nrow_get(g_j, 10, 0, 0, &r) == 0 && strstr(r.reason, "already counted") != NULL,
          "  with its reason");
    /* a row is never processed twice (cursor reset by hand) */
    CHECK(amm_journal_cursor_reset(g_j, "nodus_scan", 4) == 0, "the cursor is put back (a rescan)");
    CHECK(step(&o) == AMM_NW_OK && o.skipped == 1 && o.rows == 0 && nrows_state(NULL) == 1,
          "the recorded row is skipped, not judged and not stored again");
}

static void n10_startup(void) {
    printf("N10 startup refusal\n");
    fresh(AMM_NW_ID_WIRE);
    char why[160];
    CHECK(amm_nodus_watch_index_ok(1, 5, 5) == 1 && amm_nodus_watch_index_ok(1, 4, 5) == 1 &&
          amm_nodus_watch_index_ok(1, 6, 5) == 0 && amm_nodus_watch_index_ok(0, 1, 5) == 0 &&
          amm_nodus_watch_index_ok(1, 0, 5) == 0, "the pure rule: indexing, from_height non-zero and <= resume");
    CHECK(amm_nodus_watch_start_check(g_w, 0, why, sizeof(why)) == AMM_NW_OK, "indexing from height 1, start 5: accepted");
    g_s.from_height = 5;
    CHECK(amm_nodus_watch_start_check(g_w, 0, why, sizeof(why)) == AMM_NW_OK, "from_height == the start height: accepted");
    g_s.from_height = 6;
    CHECK(amm_nodus_watch_start_check(g_w, 0, why, sizeof(why)) == AMM_NW_REFUSED &&
          strstr(why, "starts at height 6") != NULL, "from_height 6 above the start height 5: refused, with the reason");
    g_s.from_height = 1; g_s.enabled = 0;
    CHECK(amm_nodus_watch_start_check(g_w, 0, why, sizeof(why)) == AMM_NW_REFUSED &&
          strstr(why, "addr_history_index") != NULL, "not indexing: refused, with the reason");
    g_s.enabled = 1; g_s.from_height = 0;
    CHECK(amm_nodus_watch_start_check(g_w, 0, why, sizeof(why)) == AMM_NW_REFUSED, "from_height 0 (never indexed): refused");
    g_s.from_height = 1; g_s.hist_rc = AMM_NODE_ERR;
    CHECK(amm_nodus_watch_start_check(g_w, 0, why, sizeof(why)) == AMM_NW_UNKNOWN, "an unreadable node is unknown, not a refusal");
    g_s.hist_rc = 0;

    /* the step refuses too, and writes nothing */
    amm_swap_t s;
    CHECK(approve('c', 500, 0x11, 1000, 2000, &s), "setup");
    pay(10, 'c', 500, 1100, 0x11);
    g_s.enabled = 0;
    amm_nodus_step_t o;
    CHECK(step(&o) == AMM_NW_REFUSED, "the node not indexing: the step refuses");
    CHECK(nrows_state(NULL) == 0 && swap_is(&s, "approved"), "  nothing written, the swap unmoved");
    uint64_t cv = 0;
    CHECK(amm_journal_cursor_get(g_j, "nodus_scan", &cv) == 1, "  no cursor stored");
    g_s.enabled = 1; g_s.from_height = 8;                     /* above the start height 5 */
    CHECK(step(&o) == AMM_NW_REFUSED && nrows_state(NULL) == 0, "from_height above the start height: the step refuses");
    g_s.from_height = 5;
    CHECK(step(&o) == AMM_NW_OK && o.counted == 1, "from_height == start: the step runs");
    /* plan line 283: the threshold stays the configured START height (5)
     * whatever the stored cursor is (the cursor is 12 now) */
    g_s.tip = 20;
    g_s.from_height = 13;                                     /* == cursor + 1, above the start height */
    CHECK(step(&o) == AMM_NW_REFUSED, "with a cursor at 12, from_height 13 (cursor + 1) is above the start height 5: refused");
    CHECK(amm_nodus_watch_start_check(g_w, 0, NULL, 0) == AMM_NW_REFUSED, "the startup check agrees");
    g_s.from_height = 6;
    CHECK(step(&o) == AMM_NW_REFUSED, "from_height 6 above the start height 5: refused");
    g_s.from_height = 5;
    CHECK(step(&o) == AMM_NW_OK && o.through == 20, "from_height 5 == the start height: accepted");
}

static void n11_unreadable(void) {
    printf("N11 an unreadable answer is never a zero\n");
    fresh(AMM_NW_ID_WIRE);
    amm_swap_t s;
    CHECK(approve('c', 500, 0x11, 1000, 2000, &s), "setup");
    pay(10, 'c', 500, 1100, 0x11);
    amm_nodus_step_t o;
    g_s.tip_rc = AMM_NODE_ERR;
    CHECK(step(&o) == AMM_NW_UNKNOWN && nrows_state(NULL) == 0 && swap_is(&s, "approved"), "tip unreadable: unknown, nothing written");
    g_s.tip_rc = 0; g_s.tip = 0;
    CHECK(step(&o) == AMM_NW_UNKNOWN, "a reported tip of 0 is not a tip");
    g_s.tip = 12;
    g_s.bt_rc = AMM_NODE_ERR;
    CHECK(step(&o) == AMM_NW_UNKNOWN && nrows_state(NULL) == 0, "block time unreadable: unknown, nothing written");
    g_s.bt_rc = AMM_NODE_NOT_HELD;
    CHECK(step(&o) == AMM_NW_UNKNOWN, "block time of a block the node does not hold: unknown");
    g_s.bt_rc = 0;
    g_s.hist_rc = AMM_NODE_ERR;
    CHECK(step(&o) == AMM_NW_UNKNOWN && nrows_state(NULL) == 0 && swap_is(&s, "approved"), "history unreadable: unknown, nothing written");
    g_s.hist_rc = 0;

    /* the SECOND page fails: nothing at all is written, not even the rows of page 1 */
    fresh(AMM_NW_ID_WIRE);
    CHECK(approve('c', 500, 0x11, 1000, 2000, &s), "setup");
    amm_nodus_watch_free(g_w);
    amm_nodus_watch_cfg_t c = mkcfg(AMM_NW_ID_WIRE);
    c.page_limit = 2;
    g_w = amm_nodus_watch_new(&c);
    pay(8, 'd', 1, 1080, 0x01); pay(9, 'd', 2, 1090, 0x02); pay(10, 'c', 500, 1100, 0x11);
    g_s.hist_fail_call = 2;
    CHECK(step(&o) == AMM_NW_UNKNOWN, "page 2 unreadable: unknown");
    uint64_t cv = 0;
    CHECK(nrows_state(NULL) == 0 && swap_is(&s, "approved") && amm_journal_cursor_get(g_j, "nodus_scan", &cv) == 1,
          "  no row, no swap move and no cursor from a partial history");
    g_s.hist_fail_call = 0;
    CHECK(step(&o) == AMM_NW_OK && o.counted == 1 && o.held == 2, "readable again: all three rows judged");

    /* the block walk (INTENT kind): rows before the unresolvable one are written, the cursor does not move */
    fresh(AMM_NW_ID_INTENT);
    amm_swap_t a;
    CHECK(approve('c', 500, 0x22, 1000, 2000, &a), "setup (INTENT)");
    pay(8, 'd', 1, 1080, 0x01);
    pay(10, 'c', 500, 1100, 0x11);
    g_s.items[0].h = 8;  mkid(0x01, g_s.items[0].wire); mkid(0x77, g_s.items[0].intent);
    g_s.items[1].h = 10; mkid(0x11, g_s.items[1].wire); mkid(0x22, g_s.items[1].intent);
    g_s.nitems = 2;
    g_s.item_fail_h = 10;                                /* only the walk of height 10 fails */
    g_s.item_fail_rc = AMM_NODE_ERR;
    CHECK(step(&o) == AMM_NW_UNKNOWN && o.rows == 1 && o.held == 1,
          "an incomplete walk on the second row: unknown, the first row (height 8) is written held");
    CHECK(nrows_state("held") == 1 && nrows_state("counted") == 0 && swap_is(&a, "approved"),
          "  the unresolvable row is not stored and its swap does not move");
    CHECK(amm_journal_cursor_get(g_j, "nodus_scan", &cv) == 1, "  the cursor did not move");
    g_s.item_fail_rc = AMM_NODE_NOT_HELD;                /* a block the node does not hold */
    CHECK(step(&o) == AMM_NW_UNKNOWN && o.skipped == 1 && o.rows == 0,
          "a block the node does not hold: unknown too; the recorded row is skipped");
    CHECK(amm_journal_cursor_get(g_j, "nodus_scan", &cv) == 1, "  the cursor did not move");
    g_s.item_fail_h = 0;
    CHECK(step(&o) == AMM_NW_OK && o.skipped == 1 && o.counted == 1 && o.held == 0 && swap_is(&a, "counted"),
          "the walk is readable again: the recorded row is skipped, the swap counts");
    CHECK(cursor("nodus_scan") == 12, "and the cursor moves");
}

static void n11b_resume_walk(void) {
    printf("N11b an incomplete block walk resumes at its last validated page\n");
    fresh(AMM_NW_ID_INTENT);
    amm_swap_t a;
    CHECK(approve('c', 500, 0x22, 1000, 2000, &a), "setup");
    pay(10, 'c', 500, 1100, 0x11);
    g_s.items[0].h = 10; mkid(0x11, g_s.items[0].wire); mkid(0x22, g_s.items[0].intent); g_s.nitems = 1;
    g_s.item_slow_pages = 1;
    amm_nodus_step_t o;
    CHECK(step(&o) == AMM_NW_UNKNOWN && g_s.item_calls == 1 && g_s.item_last_from == 0,
          "the first call (a slow block) stops at page 3: unknown");
    CHECK(step(&o) == AMM_NW_OK && g_s.item_calls == 2 && g_s.item_last_from == 3 && g_s.item_from0_calls == 1,
          "the second step resumes at page 3, not at page 0");
    CHECK(o.counted == 1 && swap_is(&a, "counted"), "and the swap counts");
}

static void n12_paging(void) {
    printf("N12 paging\n");
    fresh(AMM_NW_ID_WIRE);
    amm_nodus_watch_free(g_w);
    amm_nodus_watch_cfg_t c = mkcfg(AMM_NW_ID_WIRE);
    c.page_limit = 2;
    g_w = amm_nodus_watch_new(&c);
    amm_swap_t s;
    CHECK(approve('c', 500, 0x11, 1000, 2000, &s), "setup");
    /* five rows, three of them at height 9 (a page cut inside one height) */
    add_row(8, 0, 0, "spend_in", 'd', 1, 1080, 0x01, 0);
    add_row(9, 0, 0, "spend_in", 'd', 2, 1090, 0x02, 0);
    add_row(9, 1, 0, "spend_in", 'c', 500, 1090, 0x11, 0);
    add_row(9, 1, 1, "spend_in", 'd', 3, 1090, 0x03, 0);
    add_row(11, 0, 0, "spend_in", 'd', 4, 1110, 0x04, 0);
    amm_nodus_step_t o;
    CHECK(step(&o) == AMM_NW_OK && o.rows == 5 && o.counted == 1 && o.held == 4, "all five rows judged");
    CHECK(g_s.hist_calls == 3 && g_s.last_limit == 2, "three pages of 2");
    amm_nrow_t l[8];
    int n = 0;
    CHECK(amm_journal_nrow_list(g_j, NULL, l, 8, &n) == 0 && n == 5 && l[0].height == 8 && l[1].item == 0 &&
          l[2].item == 1 && l[2].seq == 0 && l[3].seq == 1 && l[4].height == 11, "stored in (height, item, seq) order");
    /* a backlog beyond the page bound is unknown, nothing is cut */
    fresh(AMM_NW_ID_WIRE);
    amm_nodus_watch_free(g_w);
    c = mkcfg(AMM_NW_ID_WIRE);
    c.page_limit = 2; c.max_pages = 2;
    g_w = amm_nodus_watch_new(&c);
    for (uint64_t h = 6; h <= 11; h++) pay(h, 'd', h, 1000 + 10 * h, (uint8_t)h);
    CHECK(step(&o) == AMM_NW_UNKNOWN && nrows_state(NULL) == 0, "6 rows over a bound of 2 pages of 2: unknown, nothing cut or written");
}

static void n13_config(void) {
    printf("N13 configuration\n");
    fresh(AMM_NW_ID_WIRE);
    amm_nodus_watch_cfg_t c = mkcfg(AMM_NW_ID_WIRE);
    amm_nodus_watch_t *w = amm_nodus_watch_new(&c);
    CHECK(w != NULL, "a valid configuration builds");
    amm_nodus_watch_free(w);
    c = mkcfg(AMM_NW_ID_INTENT);
    w = amm_nodus_watch_new(&c);
    CHECK(w != NULL, "the other id kind builds as well");
    amm_nodus_watch_free(w);
    c = mkcfg((amm_nw_id_kind_t)0);
    CHECK(amm_nodus_watch_new(&c) == NULL, "no id kind: refused");
    c = mkcfg((amm_nw_id_kind_t)3);
    CHECK(amm_nodus_watch_new(&c) == NULL, "an unknown id kind: refused");
    c = mkcfg(AMM_NW_ID_WIRE); c.page_limit = 101;
    CHECK(amm_nodus_watch_new(&c) == NULL, "a page limit above the node's 100: refused");
    c = mkcfg(AMM_NW_ID_WIRE); c.page_limit = 0;
    CHECK(amm_nodus_watch_new(&c) == NULL, "a zero page limit: refused");
    c = mkcfg(AMM_NW_ID_WIRE); c.max_pages = 0;
    CHECK(amm_nodus_watch_new(&c) == NULL, "a zero page bound: refused");
    c = mkcfg(AMM_NW_ID_WIRE); c.start_height = 0;
    CHECK(amm_nodus_watch_new(&c) == NULL, "a zero start height: refused");
    c = mkcfg(AMM_NW_ID_WIRE); c.liquidity_wait_blocks = 0;
    CHECK(amm_nodus_watch_new(&c) == NULL, "a zero liquidity wait: refused");
    c = mkcfg(AMM_NW_ID_WIRE); c.journal = NULL;
    CHECK(amm_nodus_watch_new(&c) == NULL, "no journal: refused");
    amm_node_t vt = g_vt;
    vt.item_intent = NULL;
    c = mkcfg(AMM_NW_ID_WIRE); c.node = &vt;
    CHECK(amm_nodus_watch_new(&c) == NULL, "a missing seam function: refused");
    vt = g_vt; vt.block_time = NULL; c.node = &vt;
    CHECK(amm_nodus_watch_new(&c) == NULL, "a missing block_time: refused");
}

static void n14_restart(void) {
    printf("N14 restart\n");
    fresh(AMM_NW_ID_WIRE);
    amm_swap_t s, t;
    CHECK(approve('c', 500, 0x11, 1000, 2000, &s) && approve('d', 600, 0x12, 1000, 2000, &t), "setup");
    pay(10, 'c', 500, 1100, 0x11);
    amm_nodus_step_t o;
    CHECK(step(&o) == AMM_NW_OK && o.counted == 1, "a step counts the first payment");
    restart(AMM_NW_ID_WIRE);
    CHECK(cursor("nodus_scan") == 12 && swap_is(&s, "counted"), "the cursor and the swap survive a restart");
    pay(14, 'd', 600, 1140, 0x12);
    g_s.tip = 15;
    CHECK(step(&o) == AMM_NW_OK && o.rows == 1 && o.skipped == 0 && o.counted == 1 && swap_is(&t, "counted"),
          "after the restart only the new height is read and judged");

    /* the commit fails between decision and write: nothing is written */
    fresh(AMM_NW_ID_WIRE);
    CHECK(approve('c', 500, 0x11, 1000, 2000, &s), "setup");
    pay(10, 'c', 500, 1100, 0x11);
    amm_journal_test_precommit_hook(fail_hook);
    CHECK(step(&o) == AMM_NW_ERR, "the commit fails: the step reports an error");
    amm_journal_test_precommit_hook(NULL);
    restart(AMM_NW_ID_WIRE);
    uint64_t cv = 0;
    CHECK(nrows_state(NULL) == 0 && swap_is(&s, "approved") && amm_journal_cursor_get(g_j, "nodus_scan", &cv) == 1,
          "a REOPENED journal holds the old state: no row, the swap approved, no cursor");
    CHECK(step(&o) == AMM_NW_OK && o.counted == 1 && swap_is(&s, "counted"), "the same payment is judged and counted after the restart");
}

static void n15_above_tip(void) {
    printf("N15 rows above the committed tip\n");
    fresh(AMM_NW_ID_WIRE);
    amm_swap_t s;
    CHECK(approve('c', 500, 0x11, 1000, 2000, &s), "setup");
    pay(14, 'c', 500, 1140, 0x11);          /* the history is ahead of the tip read first */
    amm_nodus_step_t o;
    CHECK(step(&o) == AMM_NW_OK && o.rows == 0 && swap_is(&s, "approved") && cursor("nodus_scan") == 12,
          "tip 12: the row at height 14 is not judged yet");
    g_s.tip = 14;
    CHECK(step(&o) == AMM_NW_OK && o.rows == 1 && o.counted == 1, "tip 14: it is judged now");
}

static void n16_match(void) {
    printf("N16 the pure matcher\n");
    amm_swap_t s;
    memset(&s, 0, sizeof(s));
    s.amount = 500; s.approved_at = 1000; s.approved_tip = 9; s.expiry = 2000;
    peer_of('c', s.sender);
    nodus_dnac_addr_history_entry_t e;
    memset(&e, 0, sizeof(e));
    snprintf(e.kind, sizeof(e.kind), "spend_in");
    e.amount = 500; e.ts = 1500; e.h = 10; peer_of('c', e.peer);
    CHECK(amm_nodus_watch_match(&e, &s) == AMM_NM_MATCH, "spend_in, native, sender, amount, height above the tip, time within: MATCH");
    e.ts = 1; CHECK(amm_nodus_watch_match(&e, &s) == AMM_NM_MATCH, "no lower bound by time: a block time before approved_at still MATCHes");
    e.ts = 2000; CHECK(amm_nodus_watch_match(&e, &s) == AMM_NM_MATCH, "ts == expiry: MATCH");
    e.ts = 1500; e.h = 9;  CHECK(amm_nodus_watch_match(&e, &s) == AMM_NM_HELD_EARLY, "height == the approval's tip: HELD_EARLY");
    e.h = 8;  CHECK(amm_nodus_watch_match(&e, &s) == AMM_NM_HELD_EARLY, "height below the tip: HELD_EARLY");
    e.h = 10; e.ts = 1500;
    e.ts = 2001; CHECK(amm_nodus_watch_match(&e, &s) == AMM_NM_HELD_EXPIRED, "ts after the expiry: HELD_EXPIRED");
    e.ts = 1500; e.amount = 501;
    CHECK(amm_nodus_watch_match(&e, &s) == AMM_NM_HELD_VALUE, "another amount: HELD_VALUE");
    e.amount = 500; peer_of('d', e.peer);
    CHECK(amm_nodus_watch_match(&e, &s) == AMM_NM_NONE, "another sender: NONE");
    peer_of('c', e.peer); e.token_id[3] = 1;
    CHECK(amm_nodus_watch_match(&e, &s) == AMM_NM_IGNORED, "a token row: IGNORED, whatever else matches");
    e.token_id[3] = 0; snprintf(e.kind, sizeof(e.kind), "spend_out");
    CHECK(amm_nodus_watch_match(&e, &s) == AMM_NM_IGNORED, "spend_out: IGNORED");
    snprintf(e.kind, sizeof(e.kind), "spend_in"); s.approved_tip = 10;
    CHECK(amm_nodus_watch_match(&e, &s) == AMM_NM_HELD_EARLY, "a tip at the payment's height never matches");
}

/* N17 (revision 12, plan section 13, givens item 94). PROVES: the transaction that
 * records a matching Nodus payment as seen gives the swap room, or puts it in the
 * line: with a 500 USDT total, a 300 USDT swap seen first is counted and holds its
 * room; a second 300 USDT payment seen in the same step finds the room full, is
 * NOT counted (paid_waiting_depth, room 0, seen number 2), its row is still taken by
 * it and the step reports it as waiting. FALSE PASS: the swaps' v is written by the
 * test, not by the engine; the engine's later grant of the freed room is
 * test_amm_engine E14. */
static void n17_room(void) {
    printf("N17 a seen payment takes room or waits in line\n");
    fresh(AMM_NW_ID_WIRE);
    amm_swap_t a, b;
    char snd[2][129], dst[41], idt[2][AMM_TID_MAX];
    memset(dst, 'b', 40); dst[40] = '\0';
    for (int i = 0; i < 2; i++) {
        peer_of(i == 0 ? 'c' : 'd', snd[i]);
        uint8_t id[64];
        mkid((uint8_t)(0x11 + i), id);
        amm_nodus_watch_id_text(id, idt[i], sizeof(idt[i]));
        amm_approve_t ap;
        memset(&ap, 0, sizeof(ap));
        ap.dir = AMM_NODUS_TO_USDT; ap.sender = snd[i]; ap.dest = dst;
        ap.amount = 500; ap.minimum = 1; ap.value_usdt = 300000000ULL;
        ap.approved_at = 1000; ap.expiry = 2000; ap.approved_tip = g_atip;
        ap.incoming_id = idt[i];
        uint64_t n = g_ctr++;
        for (int k = 0; k < 8; k++) ap.req_no[31 - k] = (uint8_t)(n >> (8 * k));
        for (int k = 0; k < 16; k++) ap.rand16[k] = (uint8_t)(n * 29 + k);
        ap.swap_max = 400000000ULL; ap.inflight_max = 500000000ULL;
        CHECK(amm_journal_approve(g_j, &ap, i == 0 ? &a : &b) == AMM_J_OK, "setup: a 300 USDT approval");
    }
    pay(8, 'c', 500, 1100, 0x11);
    pay(9, 'd', 500, 1100, 0x12);
    amm_nodus_step_t o;
    amm_swap_t ga, gb;
    CHECK(step(&o) == AMM_NW_OK && o.counted == 1 && o.waiting == 1 &&
          amm_journal_swap_by_seq(g_j, a.seq, &ga) == 0 && !strcmp(ga.state, "counted") && ga.room == 1 &&
          ga.seen_seq == 1 &&
          amm_journal_swap_by_seq(g_j, b.seq, &gb) == 0 && !strcmp(gb.state, "paid_waiting_depth") &&
          gb.room == 0 && gb.seen_seq == 2 && nrows_state("counted") == 2,
          "the first seen payment is counted with room; the second waits in line (not counted), its row taken");
}

int main(void) {
    printf("test_amm_nodus_watch\n");
    snprintf(g_dir, sizeof(g_dir), "/tmp/amm_nw_testXXXXXX");
    if (!mkdtemp(g_dir)) { printf("FATAL mkdtemp\n"); return 2; }
    snprintf(g_path, sizeof(g_path), "%s/journal.db", g_dir);

    n1_wire();
    n2_intent();
    n3_ignored();
    n4_held();
    n5_time();
    n6_late_read();
    n7_window();
    n8_depth();
    n9_once();
    n10_startup();
    n11_unreadable();
    n11b_resume_walk();
    n12_paging();
    n13_config();
    n14_restart();
    n15_above_tip();
    n16_match();
    n17_room();

    if (g_w) amm_nodus_watch_free(g_w);
    if (g_j) amm_journal_close(g_j);
    cleanup_dir();
    printf("%d checks, %d failures\n", g_checks, g_failures);
    return g_failures ? 1 : 0;
}
