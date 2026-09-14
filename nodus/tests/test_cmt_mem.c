/**
 * Nodus — cometbft @709fd12b C port, wave R3-M: the Flood mempool of
 * `shared/dnac/cmt_mem.c` and its wire `shared/dnac/cmt_pb_mempool.c`,
 * ported from `mempool/clist_mempool_test.go`, `mempool/cache_test.go`,
 * `mempool/ids_test.go` and `mempool/reactor_test.go:411-434`
 * (INACTIVE layer).
 *
 * Every case names the Go `func Test…` it comes from and its line; an
 * assertion STRONGER or WEAKER than the reference's is labelled at the
 * site, and so is every place a private Go field or method the reference
 * test reaches into is replaced by a public call.
 *
 * ── WHAT IT PROVES ─────────────────────────────────────────────────────
 * That the ported mempool admits, orders, reaps, updates and rechecks
 * transactions exactly as cometbft's CList mempool does when driven by a
 * synchronous application, and that its two wire messages are the bytes
 * the generated encoder writes. If this file failed, one of these would
 * be false:
 *   · THE WIRE. `Message{Txs{[tx]}}` marshals to the reference's own
 *     golden hex (reactor_test.go:417-418, TestMempoolVectors); an empty
 *     Txs inside a Message is `0a 00` and a nil Sum is nothing; an empty
 *     element is a real `0a 00`; every message round-trips; the decoder
 *     refuses a truncated body, a wrong wire type and an element beyond
 *     the caller's slots or arena, SKIPS an unknown field as the
 *     generated code does, and `Unwrap` refuses a nil Sum.
 *   · THE CONFIG. `DefaultMempoolConfig` is the pinned values field for
 *     field (config.go:786-803) and `ValidateBasic` refuses each
 *     negative bound and an unknown type (:824-850).
 *   · `ComputeProtoSizeForTxs` equals the LENGTH `cmt_pb_data_marshal`
 *     produces for the same list, which is its definition
 *     (types/tx.go:188-192).
 *   · THE CACHE. `Push` reports `added == false` on a repeat (the
 *     reference's false) and evicts the OLDEST key when full; `Remove`
 *     and `Has` agree with the map; the list order after Update is the
 *     reference's (cache_test.go). C-only: a NULL or freed cache is a
 *     FAULT out of Push and Remove, never "already in cache" — the
 *     hash-backend FAULT itself (cmt_mem.h "NO GO LINE") is not
 *     reachable here, since the OpenSSL backend does not fail on demand.
 *   · THE IDS. Reservation hands out 1, 2, … and never reuses an id that
 *     is still active; reclaim frees it; the 65 535th active id is the
 *     FAULT the reference panics on (ids_test.go).
 *   · THE POOL. ReapMaxBytesMaxGas honours both caps and -1 (fifteen
 *     rows); pre/post filters admit and refuse as the reference's table
 *     says; Update caches committed txs, evicts them from the pool,
 *     drops failed ones from the cache, and rechecks the rest; an
 *     invalid tx is kept in the cache only when the config says so;
 *     TxsAvailable fires ONCE per height and only when there is
 *     something; SerialReap's thousand-tx sequence reaps the counts the
 *     reference expects; SizeBytes tracks every add, remove, flush and
 *     the MaxTxsBytes bound; a tx above MaxTxBytes is `ErrTxTooLarge`
 *     with the reference's fields; the cache saturating does not let a
 *     tx into the pool twice; and the two application-failure paths are
 *     FAULTs where the reference panics.
 *
 * ── WHAT IT REQUIRES ───────────────────────────────────────────────────
 * COMPILE FLAGS: `CMT_SOFTWARE_VERSION`, which the nodus build defines
 *   for every cmt_* target (cmt_mem.c does not read it). NOTHING ELSE —
 *   a DEFAULT BUILD is enough; `QGP_FAULT_INJECT` does not matter,
 *   nothing here has a fail point.
 * ENVIRONMENT: none. No variable is read or written.
 * No network, no files, no clock, no randomness, no threads. The
 * application is a stand-in written from abci/example/kvstore/kvstore.go
 * :130-158 (CheckTx accepts a tx with exactly one `=` or `:` that is not
 * the first or last byte, GasWanted 1) — a TEST STAND-IN, never a rule
 * of the port (pin record rev 15). Its validator-transaction branch
 * (:132-136, "val=" prefix) is NOT reproduced: no ported test produces
 * such a tx. FinalizeBlock/Commit (:196-356) are not reproduced either:
 * the kvstore's CheckTx reads no state (:130-142), so the reference
 * tests' commits change nothing the mempool observes.
 * CONFIG: every case runs on `cmt_mempool_config_default()` — the
 * reference fixture is `TestMempoolConfig` (config.go:806-810, CacheSize
 * 1000) through a helper this wave did not open. Traced: exactly ONE
 * ported assertion depends on 1000 versus 10 000 — `NoCacheOverflow`
 * admits `CacheSize` + 1 txs into a pool of `Size` 5 000, so that case
 * sets CacheSize 1000 and says so at the site; SerialReap at 1000 would
 * evict only txs 0..99, which are never re-delivered, and at 10 000
 * evicts nothing. Every other case that sets a field says so.
 *
 * ── WHAT IT LEAVES BEHIND ──────────────────────────────────────────────
 * Nothing. No files, no directories, no processes, no global state
 * between cases: each builds its own pool and frees it. A CHECK failure
 * returns early and leaks, which is acceptable in a failing test process.
 *
 * ── HOW IT CAN LIE ─────────────────────────────────────────────────────
 *  1. The vectors beyond the two transcribed TestMempoolVectors rows come
 *     from shared/dnac/tests/cmt_pb_oracle.py, an independent Python
 *     encoder — a second opinion on the ENCODING that shares the
 *     reading of the reference with the C code. Only the two transcribed
 *     rows compare against cometbft itself.
 *  2. The application is a stand-in, so "the application accepts /
 *     refuses" is what THIS file's stand-in does. The mempool's own
 *     branches on the answer are what is proven, not the kvstore.
 *  3. Randomness is replaced by deterministic generators of the same
 *     SHAPE (`NewRandomTx` → a counter-derived `xx=…` of the same length;
 *     `rand.Read` → a byte pattern). A collision the reference would make
 *     with probability 2^-256 cannot happen here at all, and a property
 *     that only random bytes would have hit is not exercised.
 *  4. Three reference tests reach private methods (`resCbFirstTime`,
 *     `recheckTxs`) directly; here they are driven through the public
 *     surface (CheckTx with a cache removal; Update with no txs). The
 *     branch reached is the same; the entry is not, and each site says
 *     so.
 *  5. NO GO IMPLEMENTATION IS RUN. "Matches cometbft" rests on reading.
 *  6. The over-read negatives assert return codes; only a sanitizer
 *     build (the O9 sweep) can observe an actual over-read.
 *
 * ── NOT PORTED — BLOCKED BY ────────────────────────────────────────────
 *   · `TestMempoolUpdateDoesNotPanicWhenApplicationMissedTx`
 *     (clist_mempool_test.go:274-320): its subject is a recheck RESPONSE
 *     THAT NEVER ARRIVES from an asynchronous client (the mock answers
 *     txs[1] and txs[3] by hand, later). With the synchronous client the
 *     application returns the answer by value; a missed response cannot
 *     exist. The guard it exercises (:304-308) is ported and unreachable.
 *   · `TestMempoolRemoteAppConcurrency` (:705-730): a socket ABCI server
 *     and randomised peers — concurrency, no synchronous counterpart.
 *   · `TestMempoolConcurrentUpdateAndReceiveCheckTxResponse` (:732-763):
 *     two goroutines per height racing `Update` and `resCbFirstTime`.
 *   · `TestMempoolAsyncRecheckTxReturnError` (:867-928): the async
 *     client's Flush delivering two of four recheck responses.
 *   · `TestMempoolRecheckRace` (:931-955): a data-race regression over a
 *     socket client.
 *   · `TestMempoolConcurrentCheckTxAndUpdate` (:959-992): a reaping
 *     goroutine racing CheckTx.
 *
 * @file test_cmt_mem.c
 */

#include "dnac/cmt_mem.h"
#include "dnac/cmt_pb_mempool.h"

#include "crypto/hash/qgp_sha3.h"

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

/* ══ vectors — GENERATED by shared/dnac/tests/cmt_pb_oracle.py ════════ */

#define V_MEM_MSG_TXS_EMPTY_LEN 2
static const uint8_t V_MEM_MSG_TXS_EMPTY[2] = {
    0x0a, 0x00,
};
#define V_MEM_TXS_THREE_LEN 8
static const uint8_t V_MEM_TXS_THREE[8] = {
    0x0a, 0x00, 0x0a, 0x02, 0x61, 0x62, 0x0a, 0x00,
};
#define V_MEM_MSG_TXS_THREE_LEN 10
static const uint8_t V_MEM_MSG_TXS_THREE[10] = {
    0x0a, 0x08, 0x0a, 0x00, 0x0a, 0x02, 0x61, 0x62, 0x0a, 0x00,
};
/* reactor_test.go:417 "tx 1" — TRANSCRIBED from the reference. */
#define V_MEM_MSG_TX1_LEN 5
static const uint8_t V_MEM_MSG_TX1[5] = {
    0x0a, 0x03, 0x0a, 0x01, 0x7b,
};
/* reactor_test.go:418 "tx 2" — TRANSCRIBED from the reference. */
#define V_MEM_MSG_TX2_LEN 29
static const uint8_t V_MEM_MSG_TX2[29] = {
    0x0a, 0x1b, 0x0a, 0x19, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x20, 0x65, 0x6e,
    0x63, 0x6f, 0x64, 0x69, 0x6e, 0x67, 0x20, 0x69, 0x6e, 0x20, 0x6d, 0x65,
    0x6d, 0x70, 0x6f, 0x6f, 0x6c,
};
#define V_MEM_MSG_TWO_300_LEN 609
static const char V_MEM_MSG_TWO_300_SHA3[] =
    "5f23709eb99a8c8e20818eaa02d2b8b452474fa76f4f5df53a59361b0e0217148531a5eff1b36ae59149157482f04fd6012108a136dd1254e140e102f70578db";
#define V_MEM_RECV_MESSAGE_CAPACITY 1048584

/* ══ fixture ══════════════════════════════════════════════════════════ */

/* The oracle's `pat(n, seed)`: byte i = (seed + 7*i) mod 256. */
static void pat(uint8_t *out, size_t n, unsigned seed)
{
    size_t i;

    for (i = 0; i < n; i++) {
        out[i] = (uint8_t)((seed + 7u * i) & 0xFFu);
    }
}

static int hex_eq(const uint8_t *b, size_t n, const char *hex)
{
    size_t i;

    if (strlen(hex) != 2u * n) {
        return 0;
    }
    for (i = 0; i < n; i++) {
        char s[3];

        snprintf(s, sizeof(s), "%02x", b[i]);
        if (s[0] != hex[2 * i] || s[1] != hex[2 * i + 1]) {
            return 0;
        }
    }
    return 1;
}

static int sha3_hex_eq(const uint8_t *b, size_t n, const char *hex)
{
    uint8_t d[64];

    if (qgp_sha3_512(b, n, d) != 0) {
        return 0;
    }
    return hex_eq(d, 64, hex);
}

/* ── the application stand-in (kvstore.go:130-158) ─────────────────── */

typedef struct {
    int      check_tx_calls;     /* every request                          */
    int      recheck_calls;      /* those with type RECHECK                */
    int      fail_at_call;       /* mock: the N-th request (1-based) FAILS */
    bool     reject_all;         /* mock: every tx gets `reject_code`      */
    uint32_t reject_code;
    int      error_rc;           /* Error() (app_conn.go:31)               */
    int      flush_rc;           /* Flush() (app_conn.go:35)               */
    int      flush_calls;
} tapp_t;

/* kvstore.go:147-158 — isValidTx: exactly one `:` and no `=`, or exactly
 * one `=` and no `:`, and the one separator neither first nor last. */
static bool kv_is_valid_tx(const uint8_t *tx, size_t len)
{
    size_t colons = 0, equals = 0, i;

    for (i = 0; i < len; i++) {
        if (tx[i] == ':') { colons++; }
        if (tx[i] == '=') { equals++; }
    }
    if (colons == 1 && equals == 0) {                          /* :148 */
        return !(len > 0 && tx[0] == ':') && !(len > 0 && tx[len - 1] == ':');
    }
    if (equals == 1 && colons == 0) {                          /* :152 */
        return !(len > 0 && tx[0] == '=') && !(len > 0 && tx[len - 1] == '=');
    }
    return false;                                              /* :157 */
}

#define KV_CODE_TYPE_INVALID_TX_FORMAT 2u   /* kvstore/code.go:7 */

static int tapp_check_tx(void *ctx, const cmt_mem_request_check_tx_t *req,
                         cmt_mem_response_check_tx_t *res)
{
    tapp_t *a = (tapp_t *)ctx;

    a->check_tx_calls++;
    if (req->type == CMT_MEM_CHECK_TX_TYPE_RECHECK) {
        a->recheck_calls++;
    }
    if (a->fail_at_call != 0 && a->check_tx_calls == a->fail_at_call) {
        return CMT_REJECT;   /* the mock's `errors.New("")` */
    }
    if (a->reject_all) {
        res->code = a->reject_code;
        return CMT_OK;
    }
    /* kvstore.go:130-142 */
    if (!kv_is_valid_tx(req->tx, req->tx_len)) {               /* :137 */
        res->code = KV_CODE_TYPE_INVALID_TX_FORMAT;            /* :138 */
        return CMT_OK;
    }
    res->code       = CMT_MEM_CODE_TYPE_OK;                    /* :141 */
    res->gas_wanted = 1;
    return CMT_OK;
}

static int tapp_error(void *ctx)
{
    return ((tapp_t *)ctx)->error_rc;
}

static int tapp_flush(void *ctx)
{
    tapp_t *a = (tapp_t *)ctx;

    a->flush_calls++;
    return a->flush_rc;
}

/* One pool with its stand-in, on the default config unless a case
 * changes `cfg` before `fx_init`. */
typedef struct {
    cmt_mempool_config_t cfg;
    tapp_t               app;
    cmt_mem_app_t        app_if;
    cmt_mem_t            mem;
    int                  fired;   /* TxsAvailable callback count */
} fx_t;

static void fx_on_txs_available(void *ctx)
{
    ((fx_t *)ctx)->fired++;
}

static void fx_prepare(fx_t *fx)
{
    memset(fx, 0, sizeof(*fx));
    (void)cmt_mempool_config_default(&fx->cfg);
    fx->app_if.ctx      = &fx->app;
    fx->app_if.error    = tapp_error;
    fx->app_if.check_tx = tapp_check_tx;
    fx->app_if.flush    = tapp_flush;
}

/* clist_mempool_test.go:62-81 — newMempoolWithApp / ...AndConfig, height 0. */
static int fx_init(fx_t *fx)
{
    return cmt_mem_init(&fx->mem, &fx->cfg, &fx->app_if, 0, NULL, NULL);
}

static void fx_free(fx_t *fx)
{
    cmt_mem_free(&fx->mem);
}

/* ── transaction generators (abci/example/kvstore/helpers.go) ───────── */

static const char ALPHABET[] =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/* helpers.go:66-68 — NewTxFromID(i): "%d=%d". */
static size_t tx_from_id(uint8_t *out, size_t cap, int i)
{
    int n = snprintf((char *)out, cap, "%d=%d", i, i);

    return (n < 0) ? 0 : (size_t)n;
}

/* helpers.go:47-49 — NewTx(key, value): "key=value". */
static size_t tx_kv(uint8_t *out, size_t cap, const char *key, const char *value)
{
    int n = snprintf((char *)out, cap, "%s=%s", key, value);

    return (n < 0) ? 0 : (size_t)n;
}

/* helpers.go:51-56 — NewRandomTx(size): NewTx(Str(2), Str(size-3)), i.e.
 * `kk=vvv…` of exactly `size` bytes. SUBSTITUTION: the two random strings
 * are derived from `seq` deterministically and injectively (the value
 * starts with the decimal seq when it has room), so every tx of a run is
 * distinct and the same across runs. size >= 4 as the reference asserts. */
static size_t tx_random(uint8_t *out, size_t size, unsigned seq)
{
    size_t vlen = size - 3u;
    size_t i;

    out[0] = (uint8_t)ALPHABET[(seq / 62u) % 62u];
    out[1] = (uint8_t)ALPHABET[seq % 62u];
    out[2] = '=';
    if (vlen >= 10u) {
        char dec[16];

        snprintf(dec, sizeof(dec), "%010u", seq);
        memcpy(out + 3, dec, 10);
        for (i = 10; i < vlen; i++) {
            out[3 + i] = (uint8_t)ALPHABET[(seq * 7u + (unsigned)i * 13u) % 62u];
        }
    } else {
        for (i = 0; i < vlen; i++) {
            out[3 + i] = (uint8_t)ALPHABET[(seq * 7u + (unsigned)i * 13u + seq / 3844u) % 62u];
        }
    }
    return size;
}

/* A list of txs owned by the test (the reference's `types.Txs`). */
typedef struct {
    uint8_t        *buf;
    cmt_pb_bytes_t *v;
    size_t          n;
} txlist_t;

static unsigned g_seq = 1;

/* clist_mempool_test.go:117-124 — NewRandomTxs(numTxs, txLen) */
static int txlist_random(txlist_t *l, size_t n, size_t tx_len)
{
    size_t i;

    l->buf = (uint8_t *)malloc(n * tx_len + 1u);
    l->v   = (cmt_pb_bytes_t *)calloc(n + 1u, sizeof(*l->v));
    l->n   = n;
    if (l->buf == NULL || l->v == NULL) {
        return 1;
    }
    for (i = 0; i < n; i++) {
        l->v[i].data = l->buf + i * tx_len;
        l->v[i].len  = tx_random(l->buf + i * tx_len, tx_len, g_seq++);
    }
    return 0;
}

/* reactor_test.go:342-348 / clist_mempool_test.go:135-145 shape —
 * NewTxFromID(first .. first+num-1). */
static int txlist_from_ids(txlist_t *l, int first, size_t n)
{
    size_t i;

    l->buf = (uint8_t *)malloc(n * 32u + 1u);
    l->v   = (cmt_pb_bytes_t *)calloc(n + 1u, sizeof(*l->v));
    l->n   = n;
    if (l->buf == NULL || l->v == NULL) {
        return 1;
    }
    for (i = 0; i < n; i++) {
        l->v[i].data = l->buf + i * 32u;
        l->v[i].len  = tx_from_id(l->buf + i * 32u, 32u, first + (int)i);
    }
    return 0;
}

static void txlist_free(txlist_t *l)
{
    free(l->buf);
    free(l->v);
    l->buf = NULL;
    l->v   = NULL;
    l->n   = 0;
}

/* clist_mempool_test.go:1030-1036 — abciResponses(n, code) */
static cmt_pb_exec_tx_result_t *abci_responses(size_t n, uint32_t code)
{
    cmt_pb_exec_tx_result_t *r = (cmt_pb_exec_tx_result_t *)calloc(n + 1u, sizeof(*r));
    size_t i;

    if (r == NULL) {
        return NULL;
    }
    for (i = 0; i < n; i++) {
        r[i].code = code;
    }
    return r;
}

/* clist_mempool_test.go:101-114 — callCheckTx: every tx through CheckTx
 * with the given sender; a pre-check error is skipped; any other error
 * fails. Returns 0 on success. */
static int call_check_tx(cmt_mem_t *mem, const txlist_t *l, uint16_t peer_id)
{
    cmt_mem_tx_info_t info;
    size_t            i;

    memset(&info, 0, sizeof(info));
    info.sender_id = peer_id;
    for (i = 0; i < l->n; i++) {
        cmt_mem_error_t err;
        int rc = cmt_mem_check_tx(mem, l->v[i].data, l->v[i].len, &info,
                                  NULL, &err);

        if (rc == CMT_OK) {
            continue;
        }
        if (rc == CMT_REJECT && cmt_mem_is_pre_check_error(&err)) {
            continue;                                          /* :108-110 */
        }
        return 1;                                              /* :111 */
    }
    return 0;
}

/* clist_mempool_test.go:128-133 — addRandomTxs(count, peerID): 20-byte txs. */
static int add_random_txs(cmt_mem_t *mem, size_t count, uint16_t peer_id,
                          txlist_t *out)
{
    if (txlist_random(out, count, 20) != 0) {
        return 1;
    }
    return call_check_tx(mem, out, peer_id);
}

/* A single CheckTx with the empty TxInfo{} (sender 0). */
static int check_one(cmt_mem_t *mem, const uint8_t *tx, size_t len,
                     cmt_mem_response_check_tx_t *res, cmt_mem_error_t *err)
{
    cmt_mem_tx_info_t info;

    memset(&info, 0, sizeof(info));
    return cmt_mem_check_tx(mem, tx, len, &info, res, err);
}

/* mp.Update(height, txs, abciResponses(len, code), nil, nil) */
static int update_with(cmt_mem_t *mem, int64_t height, const cmt_pb_bytes_t *txs,
                       size_t n, uint32_t code)
{
    cmt_pb_exec_tx_result_t *r = abci_responses(n, code);
    int rc;

    if (r == NULL) {
        return CMT_FAULT;
    }
    rc = cmt_mem_update(mem, height, txs, n, r, n, NULL, NULL);
    free(r);
    return rc;
}

/* ══ the wire (cmt_pb_mempool) ════════════════════════════════════════ */

static uint8_t g_buf[4096];

/* reactor_test.go:411-434 — TestMempoolVectors, plus the oracle's
 * derived vectors and the round trips. */
static int t_pb_vectors(void)
{
    cmt_pb_mempool_message_t m;
    cmt_pb_bytes_t           slots[4];
    cmt_pb_bytes_t           one;
    size_t                   n;
    uint8_t                 *big;
    cmt_pb_bytes_t           two[2];

    /* :417 "tx 1" */
    one.data = (const uint8_t *)"\x7b";
    one.len  = 1;
    /* Slot fields before `_init` everywhere below: the init preserves
     * exactly `txs`/`txs_cap` (cmt_pb.c:1901-1914) and must not read
     * them from an uninitialised local. */
    m.txs.txs     = &one;
    m.txs.txs_cap = 1;
    cmt_pb_mempool_message_init(&m);
    m.sum         = CMT_PB_MEMPOOL_MSG_TXS;
    m.txs.txs_len = 1;
    CHECK(cmt_pb_mempool_message_marshal(&m, g_buf, sizeof(g_buf), &n) == CMT_OK,
          "marshal tx 1");
    CHECK(n == V_MEM_MSG_TX1_LEN && memcmp(g_buf, V_MEM_MSG_TX1, n) == 0,
          "TestMempoolVectors tx 1: 0a030a017b");
    CHECK(cmt_pb_mempool_message_size(&m) == n, "Size() is the length");
    OK();

    /* :418 "tx 2" */
    one.data = (const uint8_t *)"proto encoding in mempool";
    one.len  = 25;
    CHECK(cmt_pb_mempool_message_marshal(&m, g_buf, sizeof(g_buf), &n) == CMT_OK,
          "marshal tx 2");
    CHECK(n == V_MEM_MSG_TX2_LEN && memcmp(g_buf, V_MEM_MSG_TX2, n) == 0,
          "TestMempoolVectors tx 2");
    CHECK(cmt_pb_mempool_message_size(&m) == n, "Size() is the length");
    OK();

    /* Wrap (message.go:29-33) produces the same message. */
    {
        cmt_pb_mempool_txs_t     txs;
        cmt_pb_mempool_message_t w;

        txs.txs     = &one;
        txs.txs_cap = 1;
        cmt_pb_mempool_txs_init(&txs);
        txs.txs_len = 1;
        CHECK(cmt_pb_mempool_txs_wrap(&txs, &w) == CMT_OK, "Wrap");
        CHECK(w.sum == CMT_PB_MEMPOOL_MSG_TXS && w.txs.txs == &one, "wrapped");
        CHECK(cmt_pb_mempool_message_marshal(&w, g_buf, sizeof(g_buf), &n) == CMT_OK &&
              n == V_MEM_MSG_TX2_LEN && memcmp(g_buf, V_MEM_MSG_TX2, n) == 0,
              "Wrap marshals to the same bytes");
        CHECK(cmt_pb_mempool_txs_wrap(NULL, &w) == CMT_FAULT, "NULL");
    }
    OK();

    /* Message{Txs{}}: the branch is written empty → `0a 00`
     * (types.pb.go:236-247). Message{nil}: nothing (:217). */
    m.txs.txs_len = 0;
    CHECK(cmt_pb_mempool_message_marshal(&m, g_buf, sizeof(g_buf), &n) == CMT_OK,
          "marshal empty Txs");
    CHECK(n == V_MEM_MSG_TXS_EMPTY_LEN && memcmp(g_buf, V_MEM_MSG_TXS_EMPTY, n) == 0,
          "Message{Txs{}} = 0a 00");
    CHECK(cmt_pb_mempool_message_size(&m) == 2, "Size 2");
    m.sum = CMT_PB_MEMPOOL_MSG_NONE;
    CHECK(cmt_pb_mempool_message_marshal(&m, g_buf, sizeof(g_buf), &n) == CMT_OK &&
          n == 0, "Message{nil} = nothing");
    CHECK(cmt_pb_mempool_message_size(&m) == 0, "Size 0");
    CHECK(cmt_pb_mempool_message_size(NULL) == 0, "Size(nil) 0 (:277)");
    m.sum = (cmt_pb_mempool_msg_kind_t)7;
    CHECK(cmt_pb_mempool_message_marshal(&m, g_buf, sizeof(g_buf), &n) == CMT_REJECT,
          "a sum outside the oneof is refused");
    CHECK(cmt_pb_mempool_message_marshal(NULL, g_buf, sizeof(g_buf), &n) == CMT_FAULT,
          "NULL");
    OK();

    /* Txs{"", "ab", ""} — an empty element is a real `0a 00` (:186-192
     * write every element). */
    {
        cmt_pb_bytes_t three[3];
        cmt_pb_mempool_txs_t txs;

        three[0].data = NULL; three[0].len = 0;
        three[1].data = (const uint8_t *)"ab"; three[1].len = 2;
        three[2].data = NULL; three[2].len = 0;
        txs.txs = three; txs.txs_cap = 3;
        cmt_pb_mempool_txs_init(&txs);
        txs.txs_len = 3;
        CHECK(cmt_pb_mempool_txs_marshal(&txs, g_buf, sizeof(g_buf), &n) == CMT_OK &&
              n == V_MEM_TXS_THREE_LEN && memcmp(g_buf, V_MEM_TXS_THREE, n) == 0,
              "Txs{\"\",\"ab\",\"\"}");
        CHECK(cmt_pb_mempool_txs_size(&txs) == 8, "Txs.Size 8");
        CHECK(cmt_pb_mempool_txs_size(NULL) == 0, "Txs.Size(nil) 0 (:262)");
        cmt_pb_mempool_message_init(&m);
        m.sum = CMT_PB_MEMPOOL_MSG_TXS;
        m.txs = txs;
        CHECK(cmt_pb_mempool_message_marshal(&m, g_buf, sizeof(g_buf), &n) == CMT_OK &&
              n == V_MEM_MSG_TXS_THREE_LEN &&
              memcmp(g_buf, V_MEM_MSG_TXS_THREE, n) == 0,
              "Message{Txs{\"\",\"ab\",\"\"}}");
    }
    OK();

    /* Two 300-byte txs: multi-byte varints on element and frame. */
    big = (uint8_t *)malloc(600);
    CHECK(big != NULL, "alloc");
    pat(big, 300, 1);
    pat(big + 300, 300, 2);
    two[0].data = big;       two[0].len = 300;
    two[1].data = big + 300; two[1].len = 300;
    m.txs.txs = two; m.txs.txs_cap = 2;
    cmt_pb_mempool_message_init(&m);
    m.sum = CMT_PB_MEMPOOL_MSG_TXS;
    m.txs.txs_len = 2;
    CHECK(cmt_pb_mempool_message_marshal(&m, g_buf, sizeof(g_buf), &n) == CMT_OK,
          "marshal two 300");
    CHECK(n == V_MEM_MSG_TWO_300_LEN && sha3_hex_eq(g_buf, n, V_MEM_MSG_TWO_300_SHA3),
          "two 300-byte txs: oracle digest");
    CHECK(cmt_pb_mempool_message_size(&m) == n, "Size() is the length");
    /* A buffer one byte too small is refused, not truncated. */
    CHECK(cmt_pb_mempool_message_marshal(&m, g_buf, n - 1u, &n) == CMT_REJECT,
          "does not fit");
    OK();

    /* Round trip of the two-tx message: decode(encode(m)) re-encodes to
     * the same bytes and nothing points into the input. */
    {
        uint8_t                  enc[700];
        size_t                   enc_len;
        uint8_t                  arena_buf[700];
        cmt_pb_arena_t           arena = { arena_buf, sizeof(arena_buf), 0 };
        cmt_pb_mempool_message_t d;
        size_t                   n2;
        const cmt_pb_mempool_txs_t *u;

        CHECK(cmt_pb_mempool_message_marshal(&m, enc, sizeof(enc), &enc_len) == CMT_OK,
              "encode");
        d.txs.txs     = slots;
        d.txs.txs_cap = 4;
        cmt_pb_mempool_message_init(&d);
        CHECK(cmt_pb_mempool_message_unmarshal(enc, enc_len, &d, &arena) == CMT_OK,
              "decode");
        CHECK(d.sum == CMT_PB_MEMPOOL_MSG_TXS && d.txs.txs_len == 2, "two txs");
        CHECK(d.txs.txs[0].len == 300 && memcmp(d.txs.txs[0].data, big, 300) == 0 &&
              d.txs.txs[1].len == 300 && memcmp(d.txs.txs[1].data, big + 300, 300) == 0,
              "bytes survive");
        CHECK(d.txs.txs[0].data >= arena_buf &&
              d.txs.txs[0].data < arena_buf + sizeof(arena_buf),
              "the tx lives in the arena, not the input");
        memset(enc, 0xEE, sizeof(enc));
        CHECK(memcmp(d.txs.txs[0].data, big, 300) == 0,
              "overwriting the input does not touch the decoded tx");
        CHECK(cmt_pb_mempool_message_unwrap(&d, &u) == CMT_OK && u == &d.txs,
              "Unwrap gives the Txs branch");
        CHECK(cmt_pb_mempool_message_marshal(&d, g_buf, sizeof(g_buf), &n2) == CMT_OK &&
              n2 == V_MEM_MSG_TWO_300_LEN && sha3_hex_eq(g_buf, n2, V_MEM_MSG_TWO_300_SHA3),
              "re-encodes to the same bytes");
    }
    free(big);
    OK();
    return 0;
}

/* The decoder: refusals and the generated code's tolerances. */
static int t_pb_decode(void)
{
    cmt_pb_bytes_t              slots[2];
    uint8_t                     arena_buf[64];
    cmt_pb_arena_t              arena = { arena_buf, sizeof(arena_buf), 0 };
    cmt_pb_mempool_message_t    d;
    const cmt_pb_mempool_txs_t *u;
    static const uint8_t truncated[]   = { 0x0a, 0x05, 0x0a, 0x01 };
    static const uint8_t wrong_wt[]    = { 0x08, 0x01 };
    static const uint8_t inner_wt[]    = { 0x0a, 0x02, 0x08, 0x01 };
    static const uint8_t unknown_skip[] = { 0x10, 0x07, 0x0a, 0x03, 0x0a, 0x01, 0x7b };
    static const uint8_t unknown_ld[]  = { 0x12, 0x02, 0xaa, 0xbb, 0x0a, 0x00 };
    static const uint8_t three[]       = { 0x0a, 0x06, 0x0a, 0x00, 0x0a, 0x00, 0x0a, 0x00 };
    static const uint8_t twice[]       = { 0x0a, 0x03, 0x0a, 0x01, 0x7b, 0x0a, 0x03, 0x0a, 0x01, 0x7c };
    static const uint8_t bad_varint[]  = { 0x0a, 0x80 };
    static const uint8_t end_group[]   = { 0x0c };
    static const uint8_t big_elem[]    = { 0x0a, 0x04, 0x0a, 0x02, 0x61, 0x62 };

#define DECODE(buf, len) \
    (arena.used = 0, d.txs.txs = slots, d.txs.txs_cap = 2, \
     cmt_pb_mempool_message_init(&d), \
     cmt_pb_mempool_message_unmarshal((buf), (len), &d, &arena))

    /* A nil Sum: zero bytes decode (:392 loop never runs), Unwrap
     * refuses (message.go:42-43). */
    CHECK(DECODE(NULL, 0) == CMT_OK && d.sum == CMT_PB_MEMPOOL_MSG_NONE,
          "empty input is Message{nil}");
    CHECK(cmt_pb_mempool_message_unwrap(&d, &u) == CMT_REJECT && u == NULL,
          "Unwrap of a nil Sum is the error");
    CHECK(cmt_pb_mempool_message_unwrap(NULL, &u) == CMT_FAULT, "NULL");
    OK();

    /* `0a 00`: Message{Txs{}} — a Txs with no elements, unwrappable. */
    CHECK(DECODE(V_MEM_MSG_TXS_EMPTY, 2) == CMT_OK && d.sum == CMT_PB_MEMPOOL_MSG_TXS &&
          d.txs.txs_len == 0, "Message{Txs{}}");
    CHECK(cmt_pb_mempool_message_unwrap(&d, &u) == CMT_OK && u->txs_len == 0,
          "Unwrap: empty Txs");
    OK();

    /* Refusals (INVARIANT 7495d337): every one from a buffer sized
     * exactly to its input. */
    CHECK(DECODE(truncated, sizeof(truncated)) == CMT_REJECT,
          "a body length running past the end (:444-446)");
    CHECK(DECODE(wrong_wt, sizeof(wrong_wt)) == CMT_REJECT,
          "field 1 with wire type 0 (:419-421)");
    CHECK(DECODE(inner_wt, sizeof(inner_wt)) == CMT_REJECT,
          "Txs.txs with wire type 0 (:337-339)");
    CHECK(DECODE(bad_varint, sizeof(bad_varint)) == CMT_REJECT,
          "a length varint with no terminator");
    CHECK(DECODE(end_group, sizeof(end_group)) == CMT_REJECT,
          "an end-group tag (:411-413)");
    CHECK(DECODE(three, sizeof(three)) == CMT_REJECT,
          "three elements into two slots — refused, not truncated");
    arena.cap = 1;
    CHECK(DECODE(big_elem, sizeof(big_elem)) == CMT_REJECT,
          "an element the arena cannot hold — refused");
    arena.cap = sizeof(arena_buf);
    OK();

    /* Tolerances the generated decoder has: an unknown field (2, varint
     * and length-delimited) is SKIPPED (:453-466), and a repeated
     * field-1 is last-one-wins with a fresh Txs (:447-451). */
    CHECK(DECODE(unknown_skip, sizeof(unknown_skip)) == CMT_OK &&
          d.sum == CMT_PB_MEMPOOL_MSG_TXS && d.txs.txs_len == 1 &&
          d.txs.txs[0].len == 1 && d.txs.txs[0].data[0] == 0x7b,
          "unknown varint field 2 skipped, Txs decoded");
    CHECK(DECODE(unknown_ld, sizeof(unknown_ld)) == CMT_OK &&
          d.sum == CMT_PB_MEMPOOL_MSG_TXS && d.txs.txs_len == 0,
          "unknown length-delimited field 2 skipped");
    CHECK(DECODE(twice, sizeof(twice)) == CMT_OK && d.txs.txs_len == 1 &&
          d.txs.txs[0].data[0] == 0x7c,
          "a second field 1 REPLACES the first (fresh Txs, not appended)");
    OK();

    CHECK(cmt_pb_mempool_message_unmarshal(NULL, 3, &d, &arena) == CMT_FAULT,
          "NULL input with a length");
    CHECK(cmt_pb_mempool_message_unmarshal(twice, sizeof(twice), NULL, &arena) == CMT_FAULT,
          "NULL message");
    OK();
#undef DECODE
    return 0;
}

/* ══ config.go:702-850 ════════════════════════════════════════════════ */

/* config.go:786-803 DefaultMempoolConfig, :824-850 ValidateBasic. */
static int t_config(void)
{
    cmt_mempool_config_t c;

    CHECK(cmt_mempool_config_default(&c) == CMT_OK, "default");
    CHECK(c.type == CMT_MEMPOOL_TYPE_FLOOD, ":789 Type flood");
    CHECK(c.recheck, ":790 Recheck true");
    CHECK(c.recheck_timeout == (int64_t)1000000000, ":791 RecheckTimeout 1000 ms");
    CHECK(c.broadcast, ":792 Broadcast true");
    CHECK(c.size == 5000, ":796 Size 5000");
    CHECK(c.max_txs_bytes == (int64_t)1073741824, ":797 MaxTxsBytes 1 GB");
    CHECK(c.cache_size == 10000, ":798 CacheSize 10000");
    CHECK(!c.keep_invalid_txs_in_cache, "KeepInvalidTxsInCache false (unset)");
    CHECK(c.max_tx_bytes == 1048576, ":799 MaxTxBytes 1 MB");
    CHECK(c.max_batch_bytes == 0, "MaxBatchBytes unset");
    CHECK(c.experimental_max_gossip_connections_to_non_persistent_peers == 0, ":800");
    CHECK(c.experimental_max_gossip_connections_to_persistent_peers == 0, ":801");
    CHECK(cmt_mempool_config_default(NULL) == CMT_FAULT, "NULL");
    OK();

    CHECK(cmt_mempool_config_validate_basic(&c) == CMT_OK, "the default validates");
    c.type = CMT_MEMPOOL_TYPE_NOP;
    CHECK(cmt_mempool_config_validate_basic(&c) == CMT_OK, ":826 nop accepted");
    c.type = CMT_MEMPOOL_TYPE_EMPTY;
    CHECK(cmt_mempool_config_validate_basic(&c) == CMT_OK, ":827 empty accepted");
    c.type = (cmt_mempool_type_t)9;
    CHECK(cmt_mempool_config_validate_basic(&c) == CMT_REJECT, ":829 unknown type");
    c.type = CMT_MEMPOOL_TYPE_FLOOD;
    c.size = -1;
    CHECK(cmt_mempool_config_validate_basic(&c) == CMT_REJECT, ":831 size");
    c.size = 0;
    CHECK(cmt_mempool_config_validate_basic(&c) == CMT_OK, "size 0 is allowed");
    c.max_txs_bytes = -1;
    CHECK(cmt_mempool_config_validate_basic(&c) == CMT_REJECT, ":834 max_txs_bytes");
    c.max_txs_bytes = 0;
    c.cache_size = -1;
    CHECK(cmt_mempool_config_validate_basic(&c) == CMT_REJECT, ":837 cache_size");
    c.cache_size = 0;
    c.max_tx_bytes = -1;
    CHECK(cmt_mempool_config_validate_basic(&c) == CMT_REJECT, ":840 max_tx_bytes");
    c.max_tx_bytes = 0;
    c.experimental_max_gossip_connections_to_persistent_peers = -1;
    CHECK(cmt_mempool_config_validate_basic(&c) == CMT_REJECT, ":843");
    c.experimental_max_gossip_connections_to_persistent_peers = 0;
    c.experimental_max_gossip_connections_to_non_persistent_peers = -1;
    CHECK(cmt_mempool_config_validate_basic(&c) == CMT_REJECT, ":846");
    c.experimental_max_gossip_connections_to_non_persistent_peers = 0;
    CHECK(cmt_mempool_config_validate_basic(&c) == CMT_OK, "clean again");
    CHECK(cmt_mempool_config_validate_basic(NULL) == CMT_FAULT, "NULL");
    OK();
    return 0;
}

/* ══ types/tx.go:188-192, mempool.go:116-146 ══════════════════════════ */

/* ComputeProtoSizeForTxs == len(Data{txs}.Marshal()), by definition. */
static int t_proto_size_and_filters(void)
{
    uint8_t        buf[512];
    cmt_pb_bytes_t v[3];
    cmt_pb_data_t  d;
    size_t         n;
    size_t         lens[] = { 0, 1, 20, 127, 128, 300 };
    size_t         k;
    cmt_mem_pre_check_max_bytes_t pre_store;
    cmt_mem_pre_check_t           pre;
    cmt_mem_post_check_max_gas_t  post_store;
    cmt_mem_post_check_t          post;
    cmt_mem_response_check_tx_t   res;

    pat(buf, sizeof(buf), 3);
    for (k = 0; k < sizeof(lens) / sizeof(lens[0]); k++) {
        v[0].data = buf;
        v[0].len  = lens[k];
        d.txs = v; d.txs_cap = 1;
        cmt_pb_data_init(&d);
        d.txs_len = 1;
        CHECK(cmt_pb_data_marshal(&d, g_buf, sizeof(g_buf), &n) == CMT_OK, "marshal");
        CHECK(cmt_mem_compute_proto_size_for_txs(v, 1) == (int64_t)n,
              "ComputeProtoSizeForTxs([tx]) == len(Data.Marshal())");
    }
    v[0].data = buf; v[0].len = 20;
    v[1].data = buf; v[1].len = 0;
    v[2].data = buf; v[2].len = 200;
    d.txs = v; d.txs_cap = 3;
    cmt_pb_data_init(&d);
    d.txs_len = 3;
    CHECK(cmt_pb_data_marshal(&d, g_buf, sizeof(g_buf), &n) == CMT_OK, "marshal 3");
    CHECK(cmt_mem_compute_proto_size_for_txs(v, 3) == (int64_t)n, "three txs");
    CHECK(cmt_mem_compute_proto_size_for_txs(v, 0) == 0 &&
          cmt_mem_compute_proto_size_for_txs(NULL, 0) == 0, "empty list");
    /* The 20-byte tx every table-driven case below relies on is 22. */
    CHECK(cmt_mem_compute_proto_size_for_txs(v, 1) == 22, "a 20-byte tx is 22 on the wire");
    OK();

    /* mempool.go:116-126 PreCheckMaxBytes: the 20-byte tx (22) against
     * 10, 21, 22, 30. */
    CHECK(cmt_mem_pre_check_max_bytes(10, &pre_store, &pre) == CMT_OK, "ctor");
    CHECK(pre.fn(pre.ctx, buf, 20) == CMT_REJECT, "22 > 10 refused (:120)");
    pre_store.max_bytes = 21;
    CHECK(pre.fn(pre.ctx, buf, 20) == CMT_REJECT, "22 > 21 refused");
    pre_store.max_bytes = 22;
    CHECK(pre.fn(pre.ctx, buf, 20) == CMT_OK, "22 > 22 is false: admitted");
    pre_store.max_bytes = 30;
    CHECK(pre.fn(pre.ctx, buf, 20) == CMT_OK, "admitted");
    CHECK(cmt_mem_pre_check_max_bytes(1, NULL, &pre) == CMT_FAULT, "NULL storage");
    CHECK(cmt_mem_pre_check_max_bytes_fn(NULL, buf, 1) == CMT_FAULT, "NULL ctx");
    OK();

    /* mempool.go:130-146 PostCheckMaxGas. */
    memset(&res, 0, sizeof(res));
    CHECK(cmt_mem_post_check_max_gas(-1, &post_store, &post) == CMT_OK, "ctor");
    res.gas_wanted = -5;
    CHECK(post.fn(post.ctx, buf, 20, &res) == CMT_OK, "maxGas -1 → nil even for negative (:132-134)");
    post_store.max_gas = 0;
    CHECK(post.fn(post.ctx, buf, 20, &res) == CMT_REJECT, "negative gas wanted (:135-138)");
    res.gas_wanted = 1;
    CHECK(post.fn(post.ctx, buf, 20, &res) == CMT_REJECT, "1 > 0 (:139-142)");
    post_store.max_gas = 1;
    CHECK(post.fn(post.ctx, buf, 20, &res) == CMT_OK, "1 > 1 is false");
    post_store.max_gas = 3000;
    CHECK(post.fn(post.ctx, buf, 20, &res) == CMT_OK, "admitted");
    CHECK(cmt_mem_post_check_max_gas_fn(post.ctx, buf, 20, NULL) == CMT_FAULT, "NULL res");
    OK();

    /* mempool.go:149 / types/tx.go:33-35 — the key is cmt_tx_hash. */
    {
        uint8_t k1[CMT_MEM_TX_KEY_SIZE], k2[CMT_TMHASH_SIZE];

        CHECK(cmt_mem_tx_key(buf, 20, k1) == CMT_OK, "key");
        CHECK(cmt_tx_hash(buf, 20, k2) == CMT_OK, "hash");
        CHECK(memcmp(k1, k2, CMT_TMHASH_SIZE) == 0, "Key() == Hash() under substitution 1");
        CHECK(cmt_mem_tx_key(NULL, 0, k1) == CMT_OK, "the empty tx has a key (H(\"\"))");
    }
    OK();
    return 0;
}

/* ══ mempool/mempoolTx.go, errors.go ══════════════════════════════════ */

static int t_mem_tx_and_errors(void)
{
    cmt_mem_tx_t   *tx = (cmt_mem_tx_t *)calloc(1, sizeof(*tx));
    cmt_mem_error_t e;

    CHECK(tx != NULL, "alloc");
    tx->height = 7;
    CHECK(cmt_mem_tx_height(tx) == 7 && cmt_mem_tx_height(NULL) == 0, "Height()");
    CHECK(!cmt_mem_tx_is_sender(tx, 0) && !cmt_mem_tx_is_sender(tx, 65535), "no senders");
    CHECK(!cmt_mem_tx_add_sender(tx, 5), "addSender: not loaded the first time");
    CHECK(cmt_mem_tx_add_sender(tx, 5), "addSender: loaded the second time");
    CHECK(cmt_mem_tx_is_sender(tx, 5) && !cmt_mem_tx_is_sender(tx, 4) &&
          !cmt_mem_tx_is_sender(tx, 6), "isSender exact");
    (void)cmt_mem_tx_add_sender(tx, 65535);
    (void)cmt_mem_tx_add_sender(tx, 0);
    CHECK(cmt_mem_tx_is_sender(tx, 65535) && cmt_mem_tx_is_sender(tx, 0),
          "the whole uint16 space is addressable");
    CHECK(!cmt_mem_tx_is_sender(NULL, 1) && !cmt_mem_tx_add_sender(NULL, 1), "NULL");
    free(tx);
    OK();

    cmt_mem_error_init(&e);
    CHECK(e.kind == CMT_MEM_ERR_NONE && !cmt_mem_is_pre_check_error(&e), "none");
    e.kind = CMT_MEM_ERR_PRE_CHECK;
    CHECK(cmt_mem_is_pre_check_error(&e), "IsPreCheckError (:63-65)");
    e.kind = CMT_MEM_ERR_TX_IN_CACHE;
    CHECK(!cmt_mem_is_pre_check_error(&e) && !cmt_mem_is_pre_check_error(NULL), "not");
    cmt_mem_error_init(NULL);
    OK();
    return 0;
}

/* ══ cache_test.go ════════════════════════════════════════════════════ */

/* cache_test.go:17-42 — TestCacheRemove. `rand.Read` → a byte pattern
 * (fixture note 3). The two counts the reference reads —
 * len(cacheMap) and list.Len() — are one count here. The reference's
 * `Push` is one bool; here it is CMT_OK + `*out_added` (a hash-backend
 * failure is CMT_FAULT, never "already in cache" — cmt_mem.h), so every
 * `Push` below asserts the code AND the bool. */
static int t_cache_remove(void)
{
    cmt_mem_lru_tx_cache_t c;
    int     num_txs = 10;                                     /* :19 */
    uint8_t txs[10][32];
    bool    added;
    int     i;

    CHECK(cmt_mem_lru_tx_cache_init(&c, 100) == CMT_OK, "NewLRUTxCache(100)"); /* :18 */
    for (i = 0; i < num_txs; i++) {
        pat(txs[i], 32, (unsigned)(40 + i));                  /* :24-25 */
        CHECK(cmt_mem_lru_tx_cache_push_ex(&c, txs[i], 32, &added) == CMT_OK && added,
              "Push");                                        /* :29 */
        CHECK(cmt_mem_lru_tx_cache_len(&c) == i + 1, "len == i+1 (:32-33)");
    }
    for (i = 0; i < num_txs; i++) {
        CHECK(cmt_mem_lru_tx_cache_remove(&c, txs[i], 32) == CMT_OK, "Remove"); /* :37 */
        CHECK(cmt_mem_lru_tx_cache_len(&c) == num_txs - (i + 1),
              "len == numTxs-(i+1) (:39-40)");
        CHECK(!cmt_mem_lru_tx_cache_has(&c, txs[i], 32), "removed");
    }
    CHECK(cmt_mem_lru_tx_cache_remove(&c, txs[0], 32) == CMT_OK &&
          cmt_mem_lru_tx_cache_len(&c) == 0, "Remove of a missing key is a no-op (:96-101)");
    cmt_mem_lru_tx_cache_free(&c);
    OK();

    /* C-only: Push's LRU semantics (cache.go:64-89) — a repeat is
     * `added == false` (the reference's false, :73) and moves to the
     * BACK; when full the FRONT (oldest) goes. */
    CHECK(cmt_mem_lru_tx_cache_init(&c, 3) == CMT_OK, "size 3");
    CHECK(cmt_mem_lru_tx_cache_push_ex(&c, txs[0], 32, &added) == CMT_OK && added, "0");
    CHECK(cmt_mem_lru_tx_cache_push_ex(&c, txs[1], 32, &added) == CMT_OK && added, "1");
    CHECK(cmt_mem_lru_tx_cache_push_ex(&c, txs[2], 32, &added) == CMT_OK && added, "2");
    CHECK(cmt_mem_lru_tx_cache_push_ex(&c, txs[0], 32, &added) == CMT_OK && !added,
          "repeat → CMT_OK, added false (:73) — not a FAULT");
    CHECK(cmt_mem_lru_tx_cache_len(&c) == 3, "still 3");
    /* order is now 1, 2, 0 (0 moved to the back) */
    CHECK(cmt_mem_lru_tx_cache_push_ex(&c, txs[3], 32, &added) == CMT_OK && added,
          "3 evicts the front");
    CHECK(!cmt_mem_lru_tx_cache_has(&c, txs[1], 32), "1 (the oldest) evicted (:77-81)");
    CHECK(cmt_mem_lru_tx_cache_has(&c, txs[0], 32) && cmt_mem_lru_tx_cache_has(&c, txs[2], 32) &&
          cmt_mem_lru_tx_cache_has(&c, txs[3], 32), "2, 0, 3 present");
    {
        const cmt_mem_lru_node_t *n = cmt_mem_lru_tx_cache_front(&c);
        uint8_t k[64];

        CHECK(cmt_mem_tx_key(txs[2], 32, k) == CMT_OK &&
              memcmp(cmt_mem_lru_node_key(n), k, 64) == 0, "front is 2");
        n = cmt_mem_lru_node_next(n);
        CHECK(cmt_mem_tx_key(txs[0], 32, k) == CMT_OK &&
              memcmp(cmt_mem_lru_node_key(n), k, 64) == 0, "then 0");
        n = cmt_mem_lru_node_next(n);
        CHECK(cmt_mem_tx_key(txs[3], 32, k) == CMT_OK &&
              memcmp(cmt_mem_lru_node_key(n), k, 64) == 0, "then 3");
        CHECK(cmt_mem_lru_node_next(n) == NULL, "end");
    }
    cmt_mem_lru_tx_cache_reset(&c);                           /* :56-62 */
    CHECK(cmt_mem_lru_tx_cache_len(&c) == 0 && !cmt_mem_lru_tx_cache_has(&c, txs[0], 32) &&
          cmt_mem_lru_tx_cache_front(&c) == NULL, "Reset");
    CHECK(cmt_mem_lru_tx_cache_push_ex(&c, txs[0], 32, &added) == CMT_OK && added,
          "usable after Reset");
    cmt_mem_lru_tx_cache_free(&c);
    OK();

    /* NewLRUTxCache(0) still keeps ONE key (cache.go:76-84: eviction
     * only when Front() is non-nil, then the push). */
    CHECK(cmt_mem_lru_tx_cache_init(&c, 0) == CMT_OK, "size 0");
    CHECK(cmt_mem_lru_tx_cache_push_ex(&c, txs[0], 32, &added) == CMT_OK && added, "first push");
    CHECK(cmt_mem_lru_tx_cache_len(&c) == 1, "one key held");
    CHECK(cmt_mem_lru_tx_cache_push_ex(&c, txs[1], 32, &added) == CMT_OK && added,
          "second push evicts the first");
    CHECK(cmt_mem_lru_tx_cache_len(&c) == 1 && cmt_mem_lru_tx_cache_has(&c, txs[1], 32) &&
          !cmt_mem_lru_tx_cache_has(&c, txs[0], 32), "only the newest");
    cmt_mem_lru_tx_cache_free(&c);
    CHECK(cmt_mem_lru_tx_cache_init(&c, -1) == CMT_FAULT, "negative size");
    CHECK(cmt_mem_lru_tx_cache_init(NULL, 1) == CMT_FAULT, "NULL");
    /* The C-only failure channel (no Go line — cmt_mem.h's "NO GO LINE"
     * panic): a NULL or freed cache is a FAULT, never "already there";
     * `c` was just freed, so its node storage is NULL. */
    added = true;
    CHECK(cmt_mem_lru_tx_cache_push_ex(&c, txs[0], 32, &added) == CMT_FAULT && !added,
          "push into a freed cache → FAULT, added false");
    CHECK(cmt_mem_lru_tx_cache_push_ex(NULL, txs[0], 32, &added) == CMT_FAULT &&
          cmt_mem_lru_tx_cache_push_ex(&c, txs[0], 32, NULL) == CMT_FAULT &&
          cmt_mem_lru_tx_cache_remove(NULL, txs[0], 32) == CMT_FAULT &&
          cmt_mem_lru_tx_cache_remove(&c, txs[0], 32) == CMT_FAULT, "NULL / freed → FAULT");
    OK();

    /* The Nop cache (cache.go:113-120) through the dispatcher. */
    {
        cmt_mem_tx_cache_t nop;

        memset(&nop, 0, sizeof(nop));
        nop.kind = CMT_MEM_TX_CACHE_NOP;
        CHECK(cmt_mem_tx_cache_push_ex(&nop, txs[0], 32, &added) == CMT_OK && added,
              "Nop Push → true (:118)");
        CHECK(cmt_mem_tx_cache_push_ex(&nop, txs[0], 32, &added) == CMT_OK && added,
              "and again");
        CHECK(!cmt_mem_tx_cache_has(&nop, txs[0], 32), "Nop Has → false (:120)");
        CHECK(cmt_mem_tx_cache_remove(&nop, txs[0], 32) == CMT_OK, "Nop Remove (:119)");
        cmt_mem_tx_cache_reset(&nop);
        CHECK(cmt_mem_tx_cache_push_ex(NULL, txs[0], 32, &added) == CMT_FAULT &&
              cmt_mem_tx_cache_push_ex(&nop, txs[0], 32, NULL) == CMT_FAULT &&
              cmt_mem_tx_cache_remove(NULL, txs[0], 32) == CMT_FAULT &&
              !cmt_mem_tx_cache_has(NULL, txs[0], 32),
              "NULL → FAULT (Has keeps the reference's bool)");
    }
    OK();
    return 0;
}

/* cache_test.go:44-114 — TestCacheAfterUpdate. The walk is
 * `cache.GetList().Front()` → `Next()` (:88-109), oldest first, compared
 * against `txsInCache` given NEWEST first. */
static int t_cache_after_update(void)
{
    fx_t *fx = (fx_t *)calloc(1, sizeof(*fx));
    static const struct {
        int num_txs_to_create;
        int update_indices[4];  int n_update;
        int re_add_indices[4];  int n_re_add;
        int txs_in_cache[4];    int n_in_cache;
    } tests[] = {
        { 1, { 0 }, 0, { 1 }, 1, { 1, 0 }, 2 },        /* :59 adding new txs works */
        { 2, { 1 }, 1, { 0 }, 0, { 1, 0 }, 2 },        /* :60 update doesn't remove tx from cache */
        { 2, { 2 }, 1, { 0 }, 0, { 2, 1, 0 }, 3 },     /* :61 update adds new tx to cache */
        { 2, { 1 }, 1, { 1 }, 1, { 1, 0 }, 2 },        /* :62 re-adding after update doesn't make dupe */
    };
    size_t tc;

    CHECK(fx != NULL, "alloc");
    fx_prepare(fx);
    CHECK(fx_init(fx) == CMT_OK, "newMempoolWithApp");       /* :45-47 */

    for (tc = 0; tc < sizeof(tests) / sizeof(tests[0]); tc++) {
        uint8_t        tx[64];
        cmt_pb_bytes_t upd[4];
        uint8_t        updbuf[4][64];
        int            i;
        const cmt_mem_lru_node_t *node;
        int            counter;
        char           key[16];

        for (i = 0; i < tests[tc].num_txs_to_create; i++) {  /* :65-71 */
            cmt_mem_response_check_tx_t res;
            size_t len;

            snprintf(key, sizeof(key), "%d", i);
            len = tx_kv(tx, sizeof(tx), key, "value");
            CHECK(check_one(&fx->mem, tx, len, &res, NULL) == CMT_OK, "CheckTx");
            CHECK(res.code == CMT_MEM_CODE_TYPE_OK, "require.False(resp.IsErr())");
        }
        for (i = 0; i < tests[tc].n_update; i++) {           /* :73-77 */
            snprintf(key, sizeof(key), "%d", tests[tc].update_indices[i]);
            upd[i].data = updbuf[i];
            upd[i].len  = tx_kv(updbuf[i], 64, key, "value");
        }
        CHECK(update_with(&fx->mem, (int64_t)tc, upd, (size_t)tests[tc].n_update,
                          CMT_MEM_CODE_TYPE_OK) == CMT_OK, "Update");  /* :78-79 */
        for (i = 0; i < tests[tc].n_re_add; i++) {           /* :81-86 */
            cmt_mem_response_check_tx_t res;
            size_t len;
            int    rc;

            snprintf(key, sizeof(key), "%d", tests[tc].re_add_indices[i]);
            len = tx_kv(tx, sizeof(tx), key, "value");
            rc  = check_one(&fx->mem, tx, len, &res, NULL);
            /* `_ = mp.CheckTx(...)`: the error is ignored; the callback,
             * when it runs, must see no app error. */
            CHECK(rc == CMT_OK || rc == CMT_REJECT, "CheckTx ran");
            if (rc == CMT_OK) {
                CHECK(res.code == CMT_MEM_CODE_TYPE_OK, "require.False(resp.IsErr())");
            }
        }

        CHECK(fx->mem.cache.kind == CMT_MEM_TX_CACHE_LRU, "cache is the LRU (:88)");
        node    = cmt_mem_lru_tx_cache_front(&fx->mem.cache.lru);   /* :89 */
        counter = 0;
        while (node != NULL) {                                /* :91-109 */
            uint8_t exp[64];
            uint8_t expected_key[64];
            size_t  len;

            CHECK(counter != tests[tc].n_in_cache, "cache larger than expected (:92-93)");
            snprintf(key, sizeof(key), "%d",
                     tests[tc].txs_in_cache[tests[tc].n_in_cache - counter - 1]);  /* :96 */
            len = tx_kv(exp, sizeof(exp), key, "value");
            CHECK(cmt_mem_tx_key(exp, len, expected_key) == CMT_OK, "key");  /* :97 */
            CHECK(memcmp(expected_key, cmt_mem_lru_node_key(node), CMT_MEM_TX_KEY_SIZE) == 0,
                  "Equality failed on index (:106)");
            counter++;
            node = cmt_mem_lru_node_next(node);               /* :108 */
        }
        CHECK(counter == tests[tc].n_in_cache, "cache smaller than expected (:110-111)");
        CHECK(cmt_mem_flush(&fx->mem) == CMT_OK, "Flush (:112)");
        OK();
    }
    fx_free(fx);
    free(fx);
    return 0;
}

/* ══ ids_test.go ══════════════════════════════════════════════════════ */

/* ids_test.go:11-23 — TestMempoolIDsBasic. The mock peer is slot 0. */
static int t_ids_basic(void)
{
    cmt_mem_ids_t *ids = (cmt_mem_ids_t *)calloc(1, sizeof(*ids));

    CHECK(ids != NULL, "alloc");
    CHECK(cmt_mem_ids_init(ids) == CMT_OK, "newMempoolIDs");   /* :12 */
    CHECK(cmt_mem_ids_get_for_peer(ids, 0) == 0, "unreserved slot reads 0 (ids.go:62)");
    CHECK(cmt_mem_ids_reserve_for_peer(ids, 0) == CMT_OK, "Reserve");  /* :16 */
    CHECK(cmt_mem_ids_get_for_peer(ids, 0) == 1, "id 1 (:17)");
    CHECK(cmt_mem_ids_reclaim(ids, 0) == CMT_OK, "Reclaim");   /* :18 */
    CHECK(cmt_mem_ids_get_for_peer(ids, 0) == 0, "reclaimed slot reads 0");
    CHECK(cmt_mem_ids_reserve_for_peer(ids, 0) == CMT_OK, "Reserve");  /* :20 */
    CHECK(cmt_mem_ids_get_for_peer(ids, 0) == 2, "id 2 (:21): nextID does not go back");
    CHECK(cmt_mem_ids_reclaim(ids, 0) == CMT_OK, "Reclaim");   /* :22 */
    OK();

    /* C-only: two slots, and the scan skips an active id (ids.go:35-39). */
    CHECK(cmt_mem_ids_reserve_for_peer(ids, 3) == CMT_OK, "slot 3");
    CHECK(cmt_mem_ids_get_for_peer(ids, 3) == 3, "id 3");
    CHECK(cmt_mem_ids_reserve_for_peer(ids, 7) == CMT_OK, "slot 7");
    CHECK(cmt_mem_ids_get_for_peer(ids, 7) == 4, "id 4");
    CHECK(cmt_mem_ids_reclaim(ids, 3) == CMT_OK, "reclaim 3");
    CHECK(cmt_mem_ids_reclaim(ids, 3) == CMT_OK, "reclaiming an empty slot is a no-op (:50-51)");
    CHECK(cmt_mem_ids_get_for_peer(ids, 7) == 4, "7 untouched");
    CHECK(cmt_mem_ids_reserve_for_peer(ids, 128) == CMT_REJECT &&
          cmt_mem_ids_reserve_for_peer(ids, -1) == CMT_REJECT, "slot range");
    CHECK(cmt_mem_ids_get_for_peer(ids, 128) == 0 && cmt_mem_ids_get_for_peer(NULL, 0) == 0,
          "out of range reads 0");
    CHECK(cmt_mem_ids_init(NULL) == CMT_FAULT && cmt_mem_ids_reserve_for_peer(NULL, 0) == CMT_FAULT &&
          cmt_mem_ids_reclaim(NULL, 0) == CMT_FAULT, "NULL");
    OK();

    /* C-only: the uint16 counter wraps (ids.go:41 `nextID++`) and the
     * scan skips 0, which is active forever (:68). Reserve slot 1
     * repeatedly WITHOUT reclaiming — the reference overwrites the map
     * entry and leaks the old id (:24-25), which is exactly what lets
     * the counter be driven — until nextID has wrapped. */
    {
        cmt_mem_ids_t *w = (cmt_mem_ids_t *)calloc(1, sizeof(*w));

        CHECK(w != NULL, "alloc");
        CHECK(cmt_mem_ids_init(w) == CMT_OK, "init");
        w->next_id = 65533;   /* jump the counter near the wrap */
        CHECK(cmt_mem_ids_reserve_for_peer(w, 1) == CMT_OK && cmt_mem_ids_get_for_peer(w, 1) == 65533, "65533");
        CHECK(cmt_mem_ids_reserve_for_peer(w, 1) == CMT_OK && cmt_mem_ids_get_for_peer(w, 1) == 65534, "65534");
        CHECK(cmt_mem_ids_reserve_for_peer(w, 1) == CMT_OK && cmt_mem_ids_get_for_peer(w, 1) == 65535, "65535");
        CHECK(cmt_mem_ids_reserve_for_peer(w, 1) == CMT_OK && cmt_mem_ids_get_for_peer(w, 1) == 1,
              "wrapped: 0 is skipped (active), 1 is next");
        free(w);
    }
    OK();
    free(ids);
    return 0;
}

/* ids_test.go:25-42 — TestMempoolIDsPanicsIfNodeRequestsOvermaxActiveIDs.
 * INTENT PORT, labelled: the reference reserves for 65 534 DISTINCT mock
 * peers; with 128 slots the same count of ACTIVE ids is reached by
 * re-reserving one slot without reclaiming, which the literal port
 * allows for the same reason the Go one does (the map entry is
 * overwritten, the old id stays active — ids.go:24-25). The 65 535th
 * active id is the FAULT the reference panics on (:31-33). */
static int t_ids_panics_over_max(void)
{
    cmt_mem_ids_t *ids = (cmt_mem_ids_t *)calloc(1, sizeof(*ids));
    int i;

    CHECK(ids != NULL, "alloc");
    CHECK(cmt_mem_ids_init(ids) == CMT_OK, "newMempoolIDs (:31)");
    CHECK(ids->active_count == 1, "0 is already reserved for UnknownPeerID (:30)");
    for (i = 0; i < (int)CMT_MEM_MAX_ACTIVE_IDS - 1; i++) {   /* :33-36 */
        CHECK(cmt_mem_ids_reserve_for_peer(ids, 0) == CMT_OK, "ReserveForPeer");
    }
    CHECK(ids->active_count == CMT_MEM_MAX_ACTIVE_IDS, "65535 active");
    CHECK(cmt_mem_ids_reserve_for_peer(ids, 0) == CMT_FAULT,
          "the next reservation is the panic → FAULT (:38-41)");  /* :38-41 */
    /* STRONGER than the reference: the failed reservation changed
     * nothing (Go's panic unwinds without a defined state). The loop
     * handed out ids 1..65534 (nextID starts at 1, :69), so slot 0
     * still holds the last one, 65534; id 0 is the 65 535th active. */
    CHECK(ids->active_count == CMT_MEM_MAX_ACTIVE_IDS && cmt_mem_ids_get_for_peer(ids, 0) == 65534,
          "state unchanged after the refusal");
    free(ids);
    OK();
    return 0;
}

/* ══ clist_mempool_test.go ════════════════════════════════════════════ */

/* clist_mempool_test.go:147-192 — TestReapMaxBytesMaxGas */
static int t_reap_max_bytes_max_gas(void)
{
    fx_t    *fx = (fx_t *)calloc(1, sizeof(*fx));
    txlist_t l;
    cmt_pb_bytes_t *got = (cmt_pb_bytes_t *)calloc(64, sizeof(*got));
    size_t   got_n;
    const cmt_mem_tx_t *tx0;
    static const struct {
        int     num_txs_to_create;
        int64_t max_bytes;
        int64_t max_gas;
        int     expected_num_txs;
    } tests[] = {                                             /* :163-184 */
        { 20, -1, -1, 20 },
        { 20, -1, 0, 0 },
        { 20, -1, 10, 10 },
        { 20, -1, 30, 20 },
        { 20, 0, -1, 0 },
        { 20, 0, 10, 0 },
        { 20, 10, 10, 0 },
        { 20, 24, 10, 1 },
        { 20, 240, 5, 5 },
        { 20, 240, -1, 10 },
        { 20, 240, 10, 10 },
        { 20, 240, 15, 10 },
        { 20, 20000, -1, 20 },
        { 20, 20000, 5, 5 },
        { 20, 20000, 30, 20 },
    };
    size_t tc;

    CHECK(fx != NULL && got != NULL, "alloc");
    fx_prepare(fx);
    CHECK(fx_init(fx) == CMT_OK, "newMempoolWithApp");       /* :148-150 */

    /* :153-159 — gas and length of the first tx. `mp.TxsFront().Value`
     * is the public TxsFront here too. */
    CHECK(add_random_txs(&fx->mem, 1, CMT_MEM_UNKNOWN_PEER_ID, &l) == 0, "addRandomTxs(1)");
    tx0 = (const cmt_mem_tx_t *)cmt_clist_elem_value(cmt_mem_txs_front(&fx->mem)); /* :155 */
    CHECK(tx0 != NULL && tx0->gas_wanted == 1, "transactions gas was set incorrectly (:156)");
    CHECK(tx0->tx_len == 20, "Tx is longer than 20 bytes (:158)");
    txlist_free(&l);
    CHECK(cmt_mem_flush(&fx->mem) == CMT_OK, "Flush (:159)");
    OK();

    for (tc = 0; tc < sizeof(tests) / sizeof(tests[0]); tc++) {   /* :185-191 */
        CHECK(add_random_txs(&fx->mem, (size_t)tests[tc].num_txs_to_create,
                             CMT_MEM_UNKNOWN_PEER_ID, &l) == 0, "addRandomTxs");
        CHECK(cmt_mem_size(&fx->mem) == tests[tc].num_txs_to_create, "all admitted");
        CHECK(cmt_mem_reap_max_bytes_max_gas(&fx->mem, tests[tc].max_bytes, tests[tc].max_gas,
                                             got, 64, &got_n) == CMT_OK, "Reap");  /* :187 */
        CHECK((int)got_n == tests[tc].expected_num_txs, "Got %d txs, expected %d (:188)");
        /* STRONGER: the reaped txs are the FRONT of the list, in order. */
        {
            size_t i;

            for (i = 0; i < got_n; i++) {
                CHECK(got[i].len == l.v[i].len && memcmp(got[i].data, l.v[i].data, got[i].len) == 0,
                      "reaped in mempool order");
            }
        }
        txlist_free(&l);
        CHECK(cmt_mem_flush(&fx->mem) == CMT_OK, "Flush (:190)");
    }
    OK();

    /* C-only: the caller's room is checked — too small is a FAULT, and
     * NULL is a FAULT. */
    CHECK(add_random_txs(&fx->mem, 3, CMT_MEM_UNKNOWN_PEER_ID, &l) == 0, "3 txs");
    CHECK(cmt_mem_reap_max_bytes_max_gas(&fx->mem, -1, -1, got, 2, &got_n) == CMT_FAULT,
          "out_cap 2 for 3 txs → FAULT");
    CHECK(cmt_mem_reap_max_bytes_max_gas(&fx->mem, -1, -1, got, 64, NULL) == CMT_FAULT, "NULL out_len");
    txlist_free(&l);
    OK();
    fx_free(fx);
    free(fx);
    free(got);
    return 0;
}

static int nop_pre(void *ctx, const uint8_t *tx, size_t len)
{
    (void)ctx; (void)tx; (void)len;
    return CMT_OK;                                            /* :201 */
}

static int nop_post(void *ctx, const uint8_t *tx, size_t len,
                    const cmt_mem_response_check_tx_t *res)
{
    (void)ctx; (void)tx; (void)len; (void)res;
    return CMT_OK;                                            /* :202 */
}

/* clist_mempool_test.go:194-231 — TestMempoolFilters */
static int t_mempool_filters(void)
{
    fx_t *fx = (fx_t *)calloc(1, sizeof(*fx));
    cmt_pb_bytes_t empty_tx_arr[1];                           /* :199 */
    static const struct {
        int     num_txs_to_create;
        int64_t pre_max_bytes;    /* -2 = nopPreFilter */
        int64_t post_max_gas;     /* -2 = nopPostFilter */
        int     expected_num_txs;
    } tests[] = {                                             /* :206-223 */
        { 10, -2, -2, 10 },
        { 10, 10, -2, 0 },
        { 10, 22, -2, 10 },
        { 10, -2, -1, 10 },
        { 10, -2, 0, 0 },
        { 10, -2, 1, 10 },
        { 10, -2, 3000, 10 },
        { 10, 10, 20, 0 },
        { 10, 30, 20, 10 },
        { 10, 22, 1, 10 },
        { 10, 22, 0, 0 },
    };
    size_t tc;

    CHECK(fx != NULL, "alloc");
    fx_prepare(fx);
    CHECK(fx_init(fx) == CMT_OK, "newMempoolWithApp");
    empty_tx_arr[0].data = NULL;
    empty_tx_arr[0].len  = 0;

    for (tc = 0; tc < sizeof(tests) / sizeof(tests[0]); tc++) {   /* :224-230 */
        cmt_mem_pre_check_max_bytes_t pre_store;
        cmt_mem_post_check_max_gas_t  post_store;
        cmt_mem_pre_check_t           pre;
        cmt_mem_post_check_t          post;
        cmt_pb_exec_tx_result_t      *r;
        txlist_t                      l;

        if (tests[tc].pre_max_bytes == -2) {
            pre.fn = nop_pre; pre.ctx = NULL;
        } else {
            CHECK(cmt_mem_pre_check_max_bytes(tests[tc].pre_max_bytes, &pre_store, &pre) == CMT_OK, "pre");
        }
        if (tests[tc].post_max_gas == -2) {
            post.fn = nop_post; post.ctx = NULL;
        } else {
            CHECK(cmt_mem_post_check_max_gas(tests[tc].post_max_gas, &post_store, &post) == CMT_OK, "post");
        }
        r = abci_responses(1, CMT_MEM_CODE_TYPE_OK);
        CHECK(r != NULL, "alloc");
        CHECK(cmt_mem_update(&fx->mem, 1, empty_tx_arr, 1, r, 1, &pre, &post) == CMT_OK,
              "Update with the empty tx (:225-226)");
        free(r);
        CHECK(add_random_txs(&fx->mem, (size_t)tests[tc].num_txs_to_create,
                             CMT_MEM_UNKNOWN_PEER_ID, &l) == 0, "addRandomTxs (:227)");
        CHECK(cmt_mem_size(&fx->mem) == tests[tc].expected_num_txs,
              "mempool had the incorrect size (:228)");
        txlist_free(&l);
        CHECK(cmt_mem_flush(&fx->mem) == CMT_OK, "Flush (:229)");
    }
    OK();
    fx_free(fx);
    free(fx);
    return 0;
}

/* clist_mempool_test.go:233-272 — TestMempoolUpdate */
static int t_mempool_update(void)
{
    fx_t *fx = (fx_t *)calloc(1, sizeof(*fx));
    uint8_t         buf[32];
    cmt_pb_bytes_t  one;
    cmt_mem_error_t err;

    CHECK(fx != NULL, "alloc");
    fx_prepare(fx);
    CHECK(fx_init(fx) == CMT_OK, "newMempoolWithApp");

    /* 1. Adds valid txs to the cache (:239-248) */
    one.data = buf;
    one.len  = tx_from_id(buf, sizeof(buf), 1);
    CHECK(update_with(&fx->mem, 1, &one, 1, CMT_MEM_CODE_TYPE_OK) == CMT_OK, "Update tx1");
    CHECK(check_one(&fx->mem, buf, one.len, NULL, &err) == CMT_REJECT &&
          err.kind == CMT_MEM_ERR_TX_IN_CACHE, "ErrTxInCache (:244-247)");
    OK();

    /* 2. Removes valid txs from the mempool (:250-258) */
    one.len = tx_from_id(buf, sizeof(buf), 2);
    CHECK(check_one(&fx->mem, buf, one.len, NULL, &err) == CMT_OK, "CheckTx tx2");
    CHECK(cmt_mem_size(&fx->mem) == 1, "one resident");
    CHECK(update_with(&fx->mem, 1, &one, 1, CMT_MEM_CODE_TYPE_OK) == CMT_OK, "Update tx2");
    CHECK(cmt_mem_size(&fx->mem) == 0, "assert.Zero(mp.Size()) (:257)");
    OK();

    /* 3. Removes invalid transactions from the cache and the mempool
     * (:260-271) */
    one.len = tx_from_id(buf, sizeof(buf), 3);
    CHECK(check_one(&fx->mem, buf, one.len, NULL, &err) == CMT_OK, "CheckTx tx3");
    CHECK(update_with(&fx->mem, 1, &one, 1, 1) == CMT_OK, "Update tx3 with code 1");
    CHECK(cmt_mem_size(&fx->mem) == 0, "assert.Zero (:267)");
    CHECK(check_one(&fx->mem, buf, one.len, NULL, &err) == CMT_OK,
          "tx3 is out of the cache: CheckTx succeeds (:269-270)");
    OK();

    /* C-only: a results list shorter than the txs is the index panic →
     * FAULT; NULL is FAULT. */
    {
        cmt_pb_exec_tx_result_t *r = abci_responses(1, CMT_MEM_CODE_TYPE_OK);
        cmt_pb_bytes_t two[2];

        two[0] = one;
        two[1] = one;
        CHECK(r != NULL, "alloc");
        CHECK(cmt_mem_update(&fx->mem, 2, two, 2, r, 1, NULL, NULL) == CMT_FAULT,
              "txResults shorter than txs → FAULT (:603)");
        CHECK(cmt_mem_update(NULL, 2, two, 2, r, 2, NULL, NULL) == CMT_FAULT, "NULL");
        free(r);
    }
    OK();
    fx_free(fx);
    free(fx);
    return 0;
}

/* clist_mempool_test.go:322-374 — TestMempool_KeepInvalidTxsInCache.
 * `wcfg.Mempool.KeepInvalidTxsInCache = true` (:325-326). The
 * `app.FinalizeBlock` of :342-345 is not reproduced (fixture note). */
static int t_keep_invalid_txs_in_cache(void)
{
    fx_t *fx = (fx_t *)calloc(1, sizeof(*fx));
    uint8_t a[8], b[8];
    cmt_pb_bytes_t          both[2];
    cmt_pb_exec_tx_result_t results[2];
    cmt_mem_error_t         err;

    CHECK(fx != NULL, "alloc");
    fx_prepare(fx);
    fx->cfg.keep_invalid_txs_in_cache = true;                 /* :326 */
    CHECK(fx_init(fx) == CMT_OK, "newMempoolWithAppAndConfig");

    /* 1. An invalid transaction must remain in the cache after Update
     * (:330-361). a = BigEndian(0), b = BigEndian(1) — neither has an
     * `=`, so the stand-in refuses both, as the kvstore does. */
    memset(a, 0, 8);                                          /* :332-333 */
    memset(b, 0, 8); b[7] = 1;                                /* :335-336 */
    CHECK(check_one(&fx->mem, b, 8, NULL, &err) == CMT_OK, "CheckTx(b) returns nil (:338-339)");
    CHECK(cmt_mem_size(&fx->mem) == 0, "b was refused by the app, not resident");
    both[0].data = a; both[0].len = 8;
    both[1].data = b; both[1].len = 8;
    memset(results, 0, sizeof(results));
    results[0].code = CMT_MEM_CODE_TYPE_OK;                   /* :347 */
    results[1].code = 2;
    CHECK(cmt_mem_update(&fx->mem, 1, both, 2, results, 2, NULL, NULL) == CMT_OK, "Update");
    CHECK(check_one(&fx->mem, a, 8, NULL, &err) == CMT_REJECT && err.kind == CMT_MEM_ERR_TX_IN_CACHE,
          "a must be added to the cache (:350-354)");
    CHECK(check_one(&fx->mem, b, 8, NULL, &err) == CMT_REJECT && err.kind == CMT_MEM_ERR_TX_IN_CACHE,
          "b must remain in the cache (:356-360)");
    OK();

    /* 2. (:363-373): `mp.cache.Remove(a)` is the public cache call. */
    CHECK(cmt_mem_tx_cache_remove(&fx->mem.cache, a, 8) == CMT_OK, "cache.Remove(a) (:369)");
    CHECK(check_one(&fx->mem, a, 8, NULL, &err) == CMT_OK, "CheckTx(a) succeeds (:371-372)");
    OK();
    fx_free(fx);
    free(fx);
    return 0;
}

/* clist_mempool_test.go:376-418 — TestTxsAvailable. `ensureFire` /
 * `ensureNoFire` (:83-99) wait on the channel with a timeout; here the
 * channel is the callback and the count is read at once. */
static int t_txs_available(void)
{
    fx_t    *fx = (fx_t *)calloc(1, sizeof(*fx));
    txlist_t txs, more;
    cmt_pb_bytes_t *all;

    CHECK(fx != NULL, "alloc");
    fx_prepare(fx);
    CHECK(fx_init(fx) == CMT_OK, "newMempoolWithApp");
    CHECK(!cmt_mem_txs_available(&fx->mem), "TxsAvailable is nil before Enable (:90)");
    CHECK(cmt_mem_enable_txs_available(&fx->mem, fx_on_txs_available, fx) == CMT_OK,
          "EnableTxsAvailable (:381)");
    CHECK(cmt_mem_txs_available(&fx->mem), "now non-nil");

    CHECK(fx->fired == 0, "with no txs, it shouldnt fire (:386)");
    CHECK(add_random_txs(&fx->mem, 100, CMT_MEM_UNKNOWN_PEER_ID, &txs) == 0, "100 txs (:389)");
    CHECK(fx->fired == 1, "it should only fire once (:390-391)");
    OK();

    /* Update with half: fires once for the new height (:393-401). */
    CHECK(update_with(&fx->mem, 1, txs.v, 50, CMT_MEM_CODE_TYPE_OK) == CMT_OK, "Update half");
    CHECK(cmt_mem_size(&fx->mem) == 50, "50 remain");
    CHECK(fx->fired == 2, "fires once now for the new height (:400-401)");
    OK();

    /* More txs at the same height: no fire (:403-405). */
    CHECK(add_random_txs(&fx->mem, 50, CMT_MEM_UNKNOWN_PEER_ID, &more) == 0, "50 more");
    CHECK(fx->fired == 2, "already fired for this height (:405)");
    OK();

    /* Update with everything: nothing left, no fire (:407-412). */
    all = (cmt_pb_bytes_t *)calloc(100, sizeof(*all));
    CHECK(all != NULL, "alloc");
    memcpy(all, txs.v + 50, 50 * sizeof(*all));
    memcpy(all + 50, more.v, 50 * sizeof(*all));
    CHECK(update_with(&fx->mem, 2, all, 100, CMT_MEM_CODE_TYPE_OK) == CMT_OK, "Update all");
    CHECK(cmt_mem_size(&fx->mem) == 0, "empty");
    CHECK(fx->fired == 2, "should not fire as there are no txs left (:412)");
    free(all);
    txlist_free(&txs);
    txlist_free(&more);
    OK();

    /* A bunch more: fires once (:414-417). */
    CHECK(add_random_txs(&fx->mem, 100, CMT_MEM_UNKNOWN_PEER_ID, &txs) == 0, "100 txs");
    CHECK(fx->fired == 3, "it should only fire once (:416-417)");
    txlist_free(&txs);
    OK();
    fx_free(fx);
    free(fx);
    return 0;
}

/* clist_mempool_test.go:420-527 — TestSerialReap. `commitRange` (the
 * consensus connection's FinalizeBlock/Commit, :467-492) changes nothing
 * the mempool observes with the kvstore's stateless CheckTx (fixture
 * note) and is not reproduced; `updateRange` is. The test's own
 * `cacheMap` (:432) is the `seen` bitmap here. */
static int t_serial_reap(void)
{
    fx_t    *fx = (fx_t *)calloc(1, sizeof(*fx));
    uint8_t *seen = (uint8_t *)calloc(1100, 1);
    cmt_pb_bytes_t *got = (cmt_pb_bytes_t *)calloc(1101, sizeof(*got));
    size_t   got_n;
    int      i;

    CHECK(fx != NULL && seen != NULL && got != NULL, "alloc");
    fx_prepare(fx);
    CHECK(fx_init(fx) == CMT_OK, "newMempoolWithApp");

#define DELIVER_TXS_RANGE(start, end) do {                                   \
        for (i = (start); i < (end); i++) {                                  \
            uint8_t         tb[32];                                          \
            char            k[16];                                           \
            size_t          len;                                             \
            cmt_mem_error_t e;                                               \
            int             rc;                                              \
            snprintf(k, sizeof(k), "%d", i);                                 \
            len = tx_kv(tb, sizeof(tb), k, "true");             /* :436 */  \
            rc  = check_one(&fx->mem, tb, len, NULL, &e);       /* :437 */  \
            if (seen[i]) {                                                   \
                CHECK(rc == CMT_REJECT, "expected error for cached tx (:440)"); \
            } else {                                                         \
                CHECK(rc == CMT_OK, "expected no err for uncached tx (:442)"); \
            }                                                                \
            seen[i] = 1;                                        /* :444 */  \
            rc = check_one(&fx->mem, tb, len, NULL, &e);        /* :447 */  \
            CHECK(rc == CMT_REJECT && e.kind == CMT_MEM_ERR_TX_IN_CACHE,     \
                  "Expected error after CheckTx on duplicated tx (:448)");   \
        }                                                                    \
    } while (0)

#define REAP_CHECK(exp) do {                                                 \
        CHECK(cmt_mem_reap_max_bytes_max_gas(&fx->mem, -1, -1, got, 1101, &got_n) == CMT_OK, \
              "ReapMaxBytesMaxGas(-1, -1) (:453)");                          \
        CHECK((int)got_n == (exp), "Expected to reap exp txs (:454)");       \
    } while (0)

#define UPDATE_RANGE(start, end) do {                                        \
        size_t          n = (size_t)((end) - (start));                       \
        uint8_t        *ub = (uint8_t *)malloc(n * 32u);                     \
        cmt_pb_bytes_t *uv = (cmt_pb_bytes_t *)calloc(n, sizeof(*uv));       \
        CHECK(ub != NULL && uv != NULL, "alloc");                            \
        for (i = (start); i < (end); i++) {                                  \
            char k[16];                                                      \
            snprintf(k, sizeof(k), "%d", i);                                 \
            uv[i - (start)].data = ub + (size_t)(i - (start)) * 32u;         \
            uv[i - (start)].len  = tx_kv(ub + (size_t)(i - (start)) * 32u, 32u, k, "true"); /* :460 */ \
        }                                                                    \
        CHECK(update_with(&fx->mem, 0, uv, n, CMT_MEM_CODE_TYPE_OK) == CMT_OK, "Update (:462)"); \
        free(ub); free(uv);                                                  \
    } while (0)

    DELIVER_TXS_RANGE(0, 100);                                /* :497 */
    REAP_CHECK(100);                                          /* :500 */
    REAP_CHECK(100);                                          /* :503 */
    DELIVER_TXS_RANGE(0, 1000);                               /* :507 */
    REAP_CHECK(1000);                                         /* :510 */
    REAP_CHECK(1000);                                         /* :513 */
    /* :516 commitRange(0, 500) — not reproduced (header). */
    UPDATE_RANGE(0, 500);                                     /* :517 */
    REAP_CHECK(500);                                          /* :520 */
    DELIVER_TXS_RANGE(900, 1100);                             /* :523 */
    REAP_CHECK(600);                                          /* :526 */
    OK();

#undef DELIVER_TXS_RANGE
#undef REAP_CHECK
#undef UPDATE_RANGE
    fx_free(fx);
    free(fx);
    free(seen);
    free(got);
    return 0;
}

/* clist_mempool_test.go:529-573 — TestMempool_CheckTxChecksTxSize.
 * `cmtrand.Bytes(len)` → a byte pattern (the stand-in refuses it, as the
 * kvstore would refuse bytes with no `=`; the assertion is on CheckTx's
 * RETURN, which does not depend on the app's answer). The
 * `gogotypes.BytesValue` size check of :559-562 is a proto sanity check
 * unrelated to the mempool and is not reproduced. */
static int t_check_tx_checks_tx_size(void)
{
    fx_t   *fx = (fx_t *)calloc(1, sizeof(*fx));
    int     max_tx_size;
    size_t  lens[6];
    bool    errs[6] = { false, false, false, false, false, true };
    size_t  i;

    CHECK(fx != NULL, "alloc");
    fx_prepare(fx);
    CHECK(fx_init(fx) == CMT_OK, "newMempoolWithApp");
    max_tx_size = fx->cfg.max_tx_bytes;                       /* :536 */
    lens[0] = 10; lens[1] = 1000; lens[2] = 1000000;          /* :543-545 */
    lens[3] = (size_t)max_tx_size - 1u;                       /* :548 */
    lens[4] = (size_t)max_tx_size;                            /* :549 */
    lens[5] = (size_t)max_tx_size + 1u;                       /* :550 */

    for (i = 0; i < 6; i++) {                                 /* :553-572 */
        uint8_t        *tx = (uint8_t *)malloc(lens[i] + 1u);
        cmt_mem_error_t err;
        int             rc;

        CHECK(tx != NULL, "alloc");
        pat(tx, lens[i], (unsigned)i);                        /* :556 */
        rc = check_one(&fx->mem, tx, lens[i], NULL, &err);    /* :558 */
        if (!errs[i]) {
            CHECK(rc == CMT_OK, "require.NoError (:565)");
        } else {
            CHECK(rc == CMT_REJECT && err.kind == CMT_MEM_ERR_TX_TOO_LARGE &&
                  err.max == max_tx_size && err.actual == (int64_t)lens[i],
                  "ErrTxTooLarge{Max, Actual} (:567-570)");
        }
        free(tx);
    }
    OK();
    fx_free(fx);
    free(fx);
    return 0;
}

/* clist_mempool_test.go:575-663 — TestMempoolTxsBytes.
 * `cfg.Mempool.MaxTxsBytes = 100` (:581). Step 6's FinalizeBlock/Commit
 * on the app (:642-648) is not reproduced (fixture note); its assertion
 * at :653 — 10, the tx is STILL resident after the recheck, because the
 * kvstore's CheckTx accepts it again — is. */
static int t_mempool_txs_bytes(void)
{
    fx_t *fx = (fx_t *)calloc(1, sizeof(*fx));
    fx_t *fx2 = (fx_t *)calloc(1, sizeof(*fx2));
    uint8_t         tx1[16], tx2[32], tx3[128], tx4[16], txb[16];
    size_t          l1, l2, l3, l4, lb;
    cmt_pb_bytes_t  one;
    cmt_mem_error_t err;
    uint8_t         key[CMT_MEM_TX_KEY_SIZE];

    CHECK(fx != NULL && fx2 != NULL, "alloc");
    fx_prepare(fx);
    fx->cfg.max_txs_bytes = 100;                              /* :581 */
    CHECK(fx_init(fx) == CMT_OK, "newMempoolWithAppAndConfig");

    /* 1. zero by default (:585-586) */
    CHECK(cmt_mem_size_bytes(&fx->mem) == 0, "SizeBytes 0");
    /* 2. len(tx) after CheckTx (:588-592) */
    l1 = tx_random(tx1, 10, 9001);
    CHECK(check_one(&fx->mem, tx1, l1, NULL, &err) == CMT_OK, "CheckTx tx1");
    CHECK(cmt_mem_size_bytes(&fx->mem) == 10, "10");
    /* 3. zero again after tx is removed by Update (:594-597) */
    one.data = tx1; one.len = l1;
    CHECK(update_with(&fx->mem, 1, &one, 1, CMT_MEM_CODE_TYPE_OK) == CMT_OK, "Update");
    CHECK(cmt_mem_size_bytes(&fx->mem) == 0, "0");
    /* 4. zero after Flush (:599-606) */
    l2 = tx_random(tx2, 20, 9002);
    CHECK(check_one(&fx->mem, tx2, l2, NULL, &err) == CMT_OK, "CheckTx tx2");
    CHECK(cmt_mem_size_bytes(&fx->mem) == 20, "20");
    CHECK(cmt_mem_flush(&fx->mem) == CMT_OK, "Flush");
    CHECK(cmt_mem_size_bytes(&fx->mem) == 0, "0");
    OK();

    /* 5. ErrMempoolIsFull when MaxTxsBytes is reached (:608-617) */
    l3 = tx_random(tx3, 100, 9003);
    CHECK(check_one(&fx->mem, tx3, l3, NULL, &err) == CMT_OK, "CheckTx tx3 (100 == 100 fits)");
    l4 = tx_random(tx4, 10, 9004);
    CHECK(check_one(&fx->mem, tx4, l4, NULL, &err) == CMT_REJECT &&
          err.kind == CMT_MEM_ERR_MEMPOOL_IS_FULL, "ErrMempoolIsFull (:615-616)");
    CHECK(err.num_txs == 1 && err.max_txs == 5000 && err.txs_bytes == 100 && err.max_txs_bytes == 100,
          "its fields (errors.go:31-37)");
    OK();

    /* 6. after a recheck the tx stays (:619-653) — a fresh pool. */
    fx_prepare(fx2);
    CHECK(fx_init(fx2) == CMT_OK, "newMempoolWithApp (app2)");
    lb = tx_random(txb, 10, 9005);
    CHECK(check_one(&fx2->mem, txb, lb, NULL, &err) == CMT_OK, "CheckTx txBytes");
    CHECK(cmt_mem_size_bytes(&fx2->mem) == 10, "10 (:630)");
    CHECK(update_with(&fx2->mem, 1, NULL, 0, CMT_MEM_CODE_TYPE_OK) == CMT_OK,
          "Update with nothing committed → recheck (:651)");
    CHECK(fx2->app.recheck_calls == 1, "txBytes was rechecked");
    CHECK(cmt_mem_size_bytes(&fx2->mem) == 10, "10 (:653): still resident");
    OK();

    /* 7. RemoveTxByKey (:655-662) */
    CHECK(check_one(&fx2->mem, tx1, l1, NULL, &err) == CMT_OK, "CheckTx tx1");
    CHECK(cmt_mem_size_bytes(&fx2->mem) == 20, "20 (:658)");
    {
        static const uint8_t seven[1] = { 0x07 };

        CHECK(cmt_mem_tx_key(seven, 1, key) == CMT_OK, "key of {0x07}");
        CHECK(cmt_mem_remove_tx_by_key(&fx2->mem, key, &err) == CMT_REJECT &&
              err.kind == CMT_MEM_ERR_TX_NOT_FOUND, "assert.Error (:659)");
    }
    CHECK(cmt_mem_size_bytes(&fx2->mem) == 20, "20 (:660)");
    CHECK(cmt_mem_tx_key(tx1, l1, key) == CMT_OK, "key of tx1");
    CHECK(cmt_mem_remove_tx_by_key(&fx2->mem, key, &err) == CMT_OK, "assert.NoError (:661)");
    CHECK(cmt_mem_size_bytes(&fx2->mem) == 10, "10 (:662)");
    CHECK(cmt_mem_remove_tx_by_key(NULL, key, &err) == CMT_FAULT, "NULL");
    OK();
    fx_free(fx);
    fx_free(fx2);
    free(fx);
    free(fx2);
    return 0;
}

/* clist_mempool_test.go:665-699 — TestMempoolNoCacheOverflow. The
 * reference uses the async socket connection; with the synchronous
 * client `FlushAppConn` (:673, :681, :688) has nothing to flush and is
 * called for the row's sake. `mp.cache.Has` (:683) and the `mp.txs`
 * walk (:693-697) are the public calls.
 *
 * CONFIG: this case runs at CacheSize 1000 — the reference fixture's
 * `TestMempoolConfig` value (config.go:808) — and NOT the default
 * 10 000, because :677-680 saturate the cache with `CacheSize` txs that
 * must ALL be admitted (`require.NoError`) into a pool whose `Size` is
 * 5 000; at 10 000 the 5 001st is `ErrMempoolIsFull` and the case would
 * measure the pool bound instead of the cache. */
static int t_no_cache_overflow(void)
{
    fx_t   *fx = (fx_t *)calloc(1, sizeof(*fx));
    uint8_t tx0[32];
    size_t  l0;
    int     i;
    int     found = 0;
    const cmt_clist_elem_t *e;
    uint8_t key0[CMT_MEM_TX_KEY_SIZE];
    cmt_mem_error_t err;

    CHECK(fx != NULL, "alloc");
    fx_prepare(fx);
    fx->cfg.cache_size = 1000;                                /* config.go:808 */
    CHECK(fx_init(fx) == CMT_OK, "newMempoolWithAsyncConnection → sync here");

    l0 = tx_from_id(tx0, sizeof(tx0), 0);                     /* :670 */
    CHECK(check_one(&fx->mem, tx0, l0, NULL, &err) == CMT_OK, "add tx0 (:671)");
    CHECK(cmt_mem_flush_app_conn(&fx->mem, &err) == CMT_OK, "FlushAppConn (:673)");
    CHECK(fx->app.flush_calls == 1, "the Flush row was called");

    for (i = 1; i <= fx->cfg.cache_size; i++) {               /* :677-680 */
        uint8_t tb[32];
        size_t  len = tx_from_id(tb, sizeof(tb), i);

        CHECK(check_one(&fx->mem, tb, len, NULL, &err) == CMT_OK, "saturate the cache (:678-679)");
    }
    CHECK(cmt_mem_flush_app_conn(&fx->mem, &err) == CMT_OK, "FlushAppConn (:681)");
    CHECK(!cmt_mem_tx_cache_has(&fx->mem.cache, tx0, l0), "tx0 evicted from the cache (:683)");
    CHECK(cmt_mem_size(&fx->mem) == fx->cfg.cache_size + 1, "every tx is resident");
    OK();

    /* add again tx0 (:685-689): not in the cache, so the app is asked;
     * it is already in the POOL, so resCbFirstTime's :425-437 branch
     * does not add it a second time. */
    CHECK(check_one(&fx->mem, tx0, l0, NULL, &err) == CMT_OK, "CheckTx tx0 again (:686-687)");
    CHECK(cmt_mem_flush_app_conn(&fx->mem, &err) == CMT_OK, "FlushAppConn (:688)");
    CHECK(cmt_mem_tx_key(tx0, l0, key0) == CMT_OK, "key");
    for (e = cmt_mem_txs_front(&fx->mem); e != NULL; e = cmt_clist_elem_next(e)) { /* :693 */
        const cmt_mem_tx_t *mt = (const cmt_mem_tx_t *)cmt_clist_elem_value(e);
        uint8_t k[CMT_MEM_TX_KEY_SIZE];

        CHECK(mt != NULL && cmt_mem_tx_key(mt->tx, mt->tx_len, k) == CMT_OK, "key");
        if (memcmp(k, key0, CMT_MEM_TX_KEY_SIZE) == 0) {     /* :694 */
            found++;
        }
    }
    CHECK(found == 1, "tx0 should appear only once in mp.txs (:698)");
    OK();
    fx_free(fx);
    free(fx);
    return 0;
}

/* clist_mempool_test.go:765-796 — TestMempoolNotifyTxsAvailable. The
 * reference calls the PRIVATE `resCbFirstTime` twice (:779, :786) with a
 * canned OK response. Here both calls go through the public
 * `cmt_mem_check_tx` (fixture note 4): the first as-is; for the second
 * the cache entry is removed first, because the public path would
 * otherwise stop at `ErrTxInCache` (:257-269) before reaching the branch
 * the reference targets, "already in the pool" (:425-437). The
 * private fields it reads (`txsAvailable`, `notifiedTxsAvailable`) are
 * read here too — the struct is exposed for that. */
static int t_notify_txs_available(void)
{
    fx_t   *fx = (fx_t *)calloc(1, sizeof(*fx));
    uint8_t tx[32];
    size_t  len;
    cmt_mem_error_t err;

    CHECK(fx != NULL, "alloc");
    fx_prepare(fx);
    CHECK(fx_init(fx) == CMT_OK, "newMempoolWithAppAndConfig");

    CHECK(cmt_mem_enable_txs_available(&fx->mem, fx_on_txs_available, fx) == CMT_OK,
          "EnableTxsAvailable (:773)");
    CHECK(fx->mem.txs_available_enabled, "assert.NotNil(mp.txsAvailable) (:774)");
    CHECK(!fx->mem.notified_txs_available, "require.False(notifiedTxsAvailable) (:775)");

    len = tx_from_id(tx, sizeof(tx), 1);                      /* :778 */
    CHECK(check_one(&fx->mem, tx, len, NULL, &err) == CMT_OK, "resCbFirstTime via CheckTx (:779)");
    CHECK(cmt_mem_size(&fx->mem) == 1, "pool size mismatch (:780)");
    CHECK(fx->mem.notified_txs_available, "require.True (:781)");
    CHECK(fx->fired == 1, "require.Len(TxsAvailable(), 1) (:782): one signal");
    OK();

    /* :785-789 — the same tx again should not notify. */
    CHECK(cmt_mem_tx_cache_remove(&fx->mem.cache, tx, len) == CMT_OK,
          "cache.Remove — WEAKER/DIFFERENT entry: see above");
    CHECK(check_one(&fx->mem, tx, len, NULL, &err) == CMT_OK, "resCbFirstTime via CheckTx (:786)");
    CHECK(cmt_mem_size(&fx->mem) == 1, "require.Equal(1, Size) (:787)");
    CHECK(fx->mem.notified_txs_available, "require.True (:788)");
    CHECK(fx->fired == 1, "require.Empty(TxsAvailable()) (:789): no second signal");
    OK();

    /* :791-795 — Update removes the tx and clears the flag. */
    {
        cmt_pb_bytes_t one;

        one.data = tx; one.len = len;
        CHECK(update_with(&fx->mem, 1, &one, 1, CMT_MEM_CODE_TYPE_OK) == CMT_OK, "Update (:792)");
    }
    CHECK(cmt_mem_size(&fx->mem) == 0, "require.Zero (:794)");
    CHECK(!fx->mem.notified_txs_available, "require.False (:795)");
    CHECK(fx->fired == 1, "and nothing fired for an empty pool");
    OK();
    fx_free(fx);
    free(fx);
    return 0;
}

/* clist_mempool_test.go:799-821 — TestMempoolSyncCheckTxReturnError:
 * the app's CheckTx request FAILS (`errors.New("")`, :811) → the
 * reference panics (:814-820) → CMT_FAULT here (clist_mempool.go:273). */
static int t_sync_check_tx_return_error(void)
{
    fx_t   *fx = (fx_t *)calloc(1, sizeof(*fx));
    static const uint8_t tx[1] = { 0x01 };                    /* :810 */
    cmt_mem_error_t err;

    CHECK(fx != NULL, "alloc");
    fx_prepare(fx);
    fx->app.fail_at_call = 1;                                 /* :811 .Once() */
    CHECK(fx_init(fx) == CMT_OK, "newMempoolWithAppMock");
    CHECK(check_one(&fx->mem, tx, 1, NULL, &err) == CMT_FAULT,
          "CheckTx did not panic (:816) → FAULT");
    CHECK(fx->app.check_tx_calls == 1, "the request was made");
    CHECK(cmt_mem_size(&fx->mem) == 0, "nothing admitted");
    OK();
    fx_free(fx);
    free(fx);
    return 0;
}

/* clist_mempool_test.go:824-863 — TestMempoolSyncRecheckTxReturnError:
 * two txs in; on the recheck the first request succeeds and the second
 * FAILS (:850-854) → the reference panics in `recheckTxs` (:857-862) →
 * CMT_FAULT here (clist_mempool.go:669). The reference calls the PRIVATE
 * `recheckTxs` directly; here `Update` with no txs triggers it (fixture
 * note 4; `Recheck` is true on the default config). */
static int t_sync_recheck_tx_return_error(void)
{
    fx_t   *fx = (fx_t *)calloc(1, sizeof(*fx));
    static const uint8_t t1[1] = { 0x01 };                    /* :836 */
    static const uint8_t t2[1] = { 0x02 };
    cmt_mem_error_t err;

    CHECK(fx != NULL, "alloc");
    fx_prepare(fx);
    /* The mock accepts every tx with Code OK (:838 newReqRes(tx, OK)). */
    fx->app.reject_all  = true;
    fx->app.reject_code = CMT_MEM_CODE_TYPE_OK;
    CHECK(fx_init(fx) == CMT_OK, "newMempoolWithAppMock");
    CHECK(check_one(&fx->mem, t1, 1, NULL, &err) == CMT_OK, "CheckTx 0x01 (:840-841)");
    CHECK(check_one(&fx->mem, t2, 1, NULL, &err) == CMT_OK, "CheckTx 0x02");
    CHECK(cmt_mem_size(&fx->mem) == 2, "require.Len(txs, Size) (:846)");
    CHECK(cmt_mem_recheck_done(&fx->mem), "no recheck in progress");

    /* Calls so far: 2. The 3rd (recheck of 0x01) succeeds, the 4th
     * (recheck of 0x02) fails (:850-854). */
    fx->app.fail_at_call = 4;
    CHECK(update_with(&fx->mem, 1, NULL, 0, CMT_MEM_CODE_TYPE_OK) == CMT_FAULT,
          "recheckTxs did not panic (:859) → FAULT");
    CHECK(fx->app.recheck_calls == 2, "both rechecks were requested; the second failed");
    OK();
    fx_free(fx);
    free(fx);
    return 0;
}

/* C-only: the small methods the reference tests do not reach on their
 * own — Lock/Unlock (:154-164), FlushAppConn's error (:177-184),
 * `app->error` (:253-255), the empty-tx key, ReapMaxTxs and its `<=
 * max` quirk (:574), RemoveTxByKey's bytes, and the recheck's
 * `consideredFull` while nothing is rechecking. */
static int t_small_methods(void)
{
    fx_t    *fx = (fx_t *)calloc(1, sizeof(*fx));
    txlist_t l;
    cmt_pb_bytes_t got[8];
    size_t   got_n;
    cmt_mem_error_t err;

    CHECK(fx != NULL, "alloc");
    fx_prepare(fx);
    CHECK(fx_init(fx) == CMT_OK, "init");

    /* Lock: setRecheckFull flips nothing when no recheck is running
     * (:155, :791-795) — and with the synchronous client one never is
     * outside Update. */
    CHECK(!cmt_mem_lock(&fx->mem), "Lock: recheckFull did not flip");
    CHECK(!cmt_mem_recheck_considered_full(&fx->mem), "consideredFull false (:799-801)");
    cmt_mem_unlock(&fx->mem);
    CHECK(!cmt_mem_lock(NULL), "NULL");
    cmt_mem_unlock(NULL);
    OK();

    /* FlushAppConn wraps the app's error (:179-181). */
    fx->app.flush_rc = 7;
    CHECK(cmt_mem_flush_app_conn(&fx->mem, &err) == CMT_REJECT &&
          err.kind == CMT_MEM_ERR_FLUSH_APP_CONN && err.wrapped == 7, "ErrFlushAppConn{7}");
    fx->app.flush_rc = CMT_OK;
    CHECK(cmt_mem_flush_app_conn(&fx->mem, &err) == CMT_OK && err.kind == CMT_MEM_ERR_NONE, "ok");
    CHECK(cmt_mem_flush_app_conn(NULL, &err) == CMT_FAULT, "NULL");
    OK();

    /* app->error (:253-255) — before the cache and the app. */
    fx->app.error_rc = 3;
    CHECK(add_random_txs(&fx->mem, 1, 0, &l) != 0, "callCheckTx fails on a non-precheck error");
    CHECK(check_one(&fx->mem, l.v[0].data, l.v[0].len, NULL, &err) == CMT_REJECT &&
          err.kind == CMT_MEM_ERR_APP_CONN_MEMPOOL && err.wrapped == 3, "ErrAppConnMempool{3}");
    CHECK(fx->app.check_tx_calls == 0, "the app was never asked");
    CHECK(!cmt_mem_tx_cache_has(&fx->mem.cache, l.v[0].data, l.v[0].len),
          "and the cache was not pushed (the error precedes :257)");
    fx->app.error_rc = CMT_OK;
    txlist_free(&l);
    OK();

    /* ReapMaxTxs (:565-579): -1 is everything; `max` returns up to
     * max + 1 — the reference's own quirk at :574, reproduced. */
    CHECK(add_random_txs(&fx->mem, 5, 0, &l) == 0, "5 txs");
    CHECK(cmt_mem_reap_max_txs(&fx->mem, -1, got, 8, &got_n) == CMT_OK && got_n == 5, "-1 → all 5");
    CHECK(cmt_mem_reap_max_txs(&fx->mem, 2, got, 8, &got_n) == CMT_OK && got_n == 3,
          "NOTE quirk :574 `len(txs) <= max`: max 2 returns 3");
    CHECK(cmt_mem_reap_max_txs(&fx->mem, 0, got, 8, &got_n) == CMT_OK && got_n == 1,
          "max 0 returns 1");
    CHECK(cmt_mem_reap_max_txs(&fx->mem, 10, got, 8, &got_n) == CMT_OK && got_n == 5,
          "max above the size returns all");
    CHECK(got[0].len == l.v[0].len && memcmp(got[0].data, l.v[0].data, got[0].len) == 0 &&
          got[4].len == l.v[4].len && memcmp(got[4].data, l.v[4].data, got[4].len) == 0,
          "in mempool order");
    CHECK(cmt_mem_reap_max_txs(&fx->mem, -1, got, 4, &got_n) == CMT_FAULT, "out_cap too small → FAULT");
    CHECK(cmt_mem_reap_max_txs(NULL, -1, got, 8, &got_n) == CMT_FAULT, "NULL");
    OK();

    /* The empty tx: a key, admitted (the stand-in refuses it: no `=`),
     * and TxTooLarge is not it. */
    CHECK(check_one(&fx->mem, NULL, 0, NULL, &err) == CMT_OK, "the empty tx reaches the app");
    CHECK(cmt_mem_size(&fx->mem) == 5, "and was refused by it");
    OK();

    /* getCElement / getMemTx (:98-110). */
    {
        uint8_t key[CMT_MEM_TX_KEY_SIZE];
        const cmt_mem_tx_t *mt;

        CHECK(cmt_mem_tx_key(l.v[2].data, l.v[2].len, key) == CMT_OK, "key");
        CHECK(cmt_mem_get_celement(&fx->mem, key) != NULL, "getCElement");
        mt = cmt_mem_get_mem_tx(&fx->mem, key);
        CHECK(mt != NULL && mt->tx_len == l.v[2].len && memcmp(mt->tx, l.v[2].data, mt->tx_len) == 0,
              "getMemTx is the resident copy");
        CHECK(mt->height == 0, "validated at height 0 (:440)");
        CHECK(cmt_mem_tx_is_sender(mt, 0), "sender 0 recorded (:444)");
        CHECK(cmt_mem_remove_tx_by_key(&fx->mem, key, &err) == CMT_OK, "RemoveTxByKey");
        CHECK(cmt_mem_get_celement(&fx->mem, key) == NULL && cmt_mem_get_mem_tx(&fx->mem, key) == NULL,
              "gone");
        CHECK(cmt_mem_size(&fx->mem) == 4 && cmt_mem_size_bytes(&fx->mem) == 80, "4 × 20 bytes");
    }
    OK();

    /* Duplicate through the cache records the new sender (:257-269). */
    {
        uint8_t key[CMT_MEM_TX_KEY_SIZE];
        cmt_mem_tx_info_t info;
        const cmt_mem_tx_t *mt;

        memset(&info, 0, sizeof(info));
        info.sender_id = 42;
        CHECK(cmt_mem_check_tx(&fx->mem, l.v[0].data, l.v[0].len, &info, NULL, &err) == CMT_REJECT &&
              err.kind == CMT_MEM_ERR_TX_IN_CACHE, "ErrTxInCache");
        CHECK(cmt_mem_tx_key(l.v[0].data, l.v[0].len, key) == CMT_OK, "key");
        mt = cmt_mem_get_mem_tx(&fx->mem, key);
        CHECK(mt != NULL && cmt_mem_tx_is_sender(mt, 42) && cmt_mem_tx_is_sender(mt, 0),
              "sender 42 recorded on the resident tx (:262-263)");
        CHECK(cmt_mem_check_tx(&fx->mem, l.v[0].data, l.v[0].len, NULL, NULL, &err) == CMT_FAULT,
              "NULL info");
    }
    txlist_free(&l);
    OK();

    /* Update keeps the filters when NULL is passed (:595-600) and
     * replaces them when given. */
    {
        cmt_mem_pre_check_max_bytes_t st;
        cmt_mem_pre_check_t           pre;

        CHECK(cmt_mem_pre_check_max_bytes(1, &st, &pre) == CMT_OK, "pre 1");
        CHECK(update_with(&fx->mem, 3, NULL, 0, CMT_MEM_CODE_TYPE_OK) == CMT_OK, "Update");
        CHECK(fx->mem.pre_check.fn == NULL, "NULL keeps none");
        CHECK(cmt_mem_update(&fx->mem, 4, NULL, 0, NULL, 0, &pre, NULL) == CMT_OK, "Update with pre");
        CHECK(fx->mem.pre_check.fn == cmt_mem_pre_check_max_bytes_fn, "replaced");
        CHECK(cmt_mem_update(&fx->mem, 5, NULL, 0, NULL, 0, NULL, NULL) == CMT_OK, "Update");
        CHECK(fx->mem.pre_check.fn == cmt_mem_pre_check_max_bytes_fn, "kept");
        CHECK(fx->mem.height == 5, "height stored (:592)");
        CHECK(add_random_txs(&fx->mem, 1, 0, &l) == 0, "a 20-byte tx");
        CHECK(check_one(&fx->mem, l.v[0].data, l.v[0].len, NULL, &err) == CMT_REJECT &&
              err.kind == CMT_MEM_ERR_PRE_CHECK, "the 1-byte pre-check refuses it");
        txlist_free(&l);
    }
    OK();

    /* Init refusals. */
    {
        cmt_mem_t m2;
        cmt_mempool_config_t bad;

        (void)cmt_mempool_config_default(&bad);
        bad.size = -1;
        CHECK(cmt_mem_init(&m2, &bad, &fx->app_if, 0, NULL, NULL) == CMT_FAULT, "negative size");
        CHECK(cmt_mem_init(NULL, &fx->cfg, &fx->app_if, 0, NULL, NULL) == CMT_FAULT, "NULL");
        CHECK(cmt_mem_init(&m2, &fx->cfg, NULL, 0, NULL, NULL) == CMT_FAULT, "NULL app");
        /* CacheSize 0 → the Nop cache (:83-87): a repeat is not refused. */
        bad.size = 10;
        bad.cache_size = 0;
        CHECK(cmt_mem_init(&m2, &bad, &fx->app_if, 0, NULL, NULL) == CMT_OK, "cache 0");
        CHECK(m2.cache.kind == CMT_MEM_TX_CACHE_NOP, "NopTxCache chosen (:86)");
        CHECK(add_random_txs(&m2, 1, 0, &l) == 0, "one tx");
        CHECK(check_one(&m2, l.v[0].data, l.v[0].len, NULL, &err) == CMT_OK,
              "with the Nop cache the repeat reaches the app (no ErrTxInCache)");
        CHECK(cmt_mem_size(&m2) == 1, "and is not added twice (:425-437)");
        txlist_free(&l);
        cmt_mem_free(&m2);
        cmt_mem_free(NULL);
    }
    OK();
    fx_free(fx);
    free(fx);
    return 0;
}

typedef struct {
    const char *name;
    int       (*fn)(void);
} s_case_t;

int main(void)
{
    static const s_case_t cases[] = {
        { "pb_vectors (TestMempoolVectors)",            t_pb_vectors },
        { "pb_decode",                                  t_pb_decode },
        { "config (DefaultMempoolConfig, ValidateBasic)", t_config },
        { "proto_size_and_filters",                     t_proto_size_and_filters },
        { "mem_tx_and_errors",                          t_mem_tx_and_errors },
        { "cache_remove (TestCacheRemove)",             t_cache_remove },
        { "cache_after_update (TestCacheAfterUpdate)",  t_cache_after_update },
        { "ids_basic (TestMempoolIDsBasic)",            t_ids_basic },
        { "ids_panics_over_max (TestMempoolIDsPanicsIfNodeRequestsOvermaxActiveIDs)",
          t_ids_panics_over_max },
        { "reap_max_bytes_max_gas (TestReapMaxBytesMaxGas)", t_reap_max_bytes_max_gas },
        { "mempool_filters (TestMempoolFilters)",       t_mempool_filters },
        { "mempool_update (TestMempoolUpdate)",         t_mempool_update },
        { "keep_invalid_txs_in_cache (TestMempool_KeepInvalidTxsInCache)",
          t_keep_invalid_txs_in_cache },
        { "txs_available (TestTxsAvailable)",           t_txs_available },
        { "serial_reap (TestSerialReap)",               t_serial_reap },
        { "check_tx_checks_tx_size (TestMempool_CheckTxChecksTxSize)",
          t_check_tx_checks_tx_size },
        { "mempool_txs_bytes (TestMempoolTxsBytes)",    t_mempool_txs_bytes },
        { "no_cache_overflow (TestMempoolNoCacheOverflow)", t_no_cache_overflow },
        { "notify_txs_available (TestMempoolNotifyTxsAvailable)",
          t_notify_txs_available },
        { "sync_check_tx_return_error (TestMempoolSyncCheckTxReturnError)",
          t_sync_check_tx_return_error },
        { "sync_recheck_tx_return_error (TestMempoolSyncRecheckTxReturnError)",
          t_sync_recheck_tx_return_error },
        { "small_methods",                              t_small_methods },
    };
    size_t i;
    size_t n = sizeof(cases) / sizeof(cases[0]);
    size_t failed = 0u;

    for (i = 0u; i < n; i++) {
        if (cases[i].fn() != 0) {
            fprintf(stderr, "FAIL %s\n", cases[i].name);
            failed++;
        } else {
            printf("ok   %s\n", cases[i].name);
        }
    }
    printf("test_cmt_mem: %zu/%zu cases, %d groups\n", n - failed, n, g_checks);
    return (failed == 0u) ? 0 : 1;
}
