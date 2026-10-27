/**
 * Nodus — Client SDK: nodus_client_get_all_page_strict_many (pipelined
 * strict page reads, web 0.1.73).
 *
 * The REAL client runs against a fake server built the way
 * test_client_spend_status.c builds its fake (nodus_tcp_t + nodus_t2_*
 * encoders, plain auth_ok, unencrypted session). The fake HOLDS every
 * paged get_all it receives and answers only once it holds the number of
 * requests the case expects — then in REVERSE order of arrival. A client
 * that waited for one reply before sending the next request would get no
 * reply at all (the fake never answers fewer than the expected count), so
 * every case below fails with NODUS_ERR_TIMEOUT unless all requests were
 * in flight together.
 *
 * What it proves:
 *   P1  4 keys, replies in reverse order: every item rc 0, exactly one row,
 *       the row of ITS key (key_hash and the per-key data byte) — replies
 *       are routed by txn, not by position; more / legacy false,
 *       undecodable 0. The fake saw 4 get_all frames, each with "pg", "own"
 *       = that item's owner, no "after", 4 distinct txns.
 *   P2  3 keys, the middle one never answered: that item rc
 *       NODUS_ERR_TIMEOUT, the two others rc 0 with their own rows.
 *   P3  one item answered with error 21 (unavailable): that item rc
 *       NODUS_ERR_UNAVAILABLE, the others rc 0.
 *   P4  one item's "vals" carries a non-byte-string item next to its row:
 *       that item rc 0, count 1, undecodable 1 (the strict count is kept
 *       per item); the others undecodable 0.
 *   P5  one item answered as a pre-paging node (result_multi, no "more"):
 *       that item rc 0, legacy true (strict: the caller decides).
 *   A1  n == 0, n > NODUS_CLIENT_PAGE_PIPELINE_MAX, a NULL key, NULL reqs:
 *       -1 and the fake received no request.
 *
 * What it requires: default standalone nodus build; no environment.
 * Ports: the fake listens on 127.0.0.1:0 (kernel-chosen); no fixed port.
 * The client's request timeout is set to 1500 ms so P2's silent item
 * completes; that is the case's input, not a tuned wait (every other item
 * is answered as soon as the fake holds all of a case's requests).
 * What it leaves behind: nothing (fake thread joined, client closed).
 *
 * How it can lie:
 *   - The fake ignores "own" and decides every reply; the cases prove the
 *     client's sending and routing, not a real node's answers.
 *   - This is the native client (read thread). The browser build has no
 *     read thread: there wait_response polls the transport itself
 *     (nodus_client.c wait_response, client_on_frame), which this test
 *     does not run.
 *   - A fake that never answers makes each item time out; each case asserts
 *     its exact codes and rows, so that shows up as a FAIL, never a pass.
 */

#include "nodus/nodus.h"
#include "transport/nodus_tcp.h"
#include "protocol/nodus_tier2.h"
#include "protocol/nodus_cbor.h"
#include "core/nodus_value.h"
#include "crypto/nodus_sign.h"
#include "crypto/nodus_identity.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdatomic.h>

#define TEST(name) do { printf("  %-70s", name); fflush(stdout); } while (0)
#define PASS()     do { printf("PASS\n"); passed++; } while (0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while (0)

static int passed = 0;
static int failed = 0;

/* ── Fake server (test_client_spend_status.c pattern) ──────────────── */

#define FAKE_BUF_SIZE 65536
#define HELD_MAX      16
#define NONE          (-1)

typedef struct {
    nodus_tcp_conn_t *conn;
    uint32_t          txn;
    nodus_key_t       key;
    bool              page;
    bool              has_own;
    nodus_key_t       own;
    bool              has_after;
} held_t;

typedef struct {
    nodus_tcp_t     *tcp;
    _Atomic bool     stop;
    pthread_t        tid;
    uint8_t         *buf;
    pthread_mutex_t  mu;
    held_t           held[HELD_MAX];
    int              nheld;        /* requests of the current case        */
    int              total;        /* every get_all received, all cases   */
    /* the case: answer once `expect` requests are held; the marker (first
     * key byte) of the request answered specially, or NONE */
    int              expect;
    int              silent;       /* never answered                      */
    int              error;        /* error 21 (unavailable)              */
    int              undecodable;  /* row + a non-bstr item               */
    int              legacy;       /* result_multi, no "more"             */
} fake_server_t;

static fake_server_t g_fake;
static nodus_identity_t *g_owner_id;

/* A row of `key` whose data is the key's marker byte (the client does not
 * verify signatures; the row is not signed). */
static nodus_value_t *mk_row(const nodus_key_t *key) {
    nodus_value_t *v = NULL;
    uint8_t marker = key->bytes[0];
    if (nodus_value_create(key, &marker, 1, NODUS_VALUE_PERMANENT, 0,
                           marker, 1, &g_owner_id->pk, &v) != 0)
        return NULL;
    return v;
}

/* Same header layout as nodus_tier2.c enc_response_header (static there). */
static void fake_resp_header(cbor_encoder_t *enc, uint32_t txn, const char *method) {
    cbor_encode_map(enc, 4);
    cbor_encode_cstr(enc, "t"); cbor_encode_uint(enc, txn);
    cbor_encode_cstr(enc, "y"); cbor_encode_cstr(enc, "r");
    cbor_encode_cstr(enc, "q"); cbor_encode_cstr(enc, method);
}

/* Called with g_fake.mu held, on the fake's poll thread. */
static void fake_answer(const held_t *h) {
    int marker = h->key.bytes[0];
    size_t len = 0;
    if (marker == g_fake.silent) return;
    if (marker == g_fake.error) {
        if (nodus_t2_error(h->txn, NODUS_ERR_UNAVAILABLE, "unavailable",
                           g_fake.buf, FAKE_BUF_SIZE, &len) == 0)
            nodus_tcp_send(h->conn, g_fake.buf, len);
        return;
    }
    nodus_value_t *row = mk_row(&h->key);
    if (!row) return;
    if (marker == g_fake.legacy) {
        if (nodus_t2_result_multi(h->txn, &row, 1, g_fake.buf, FAKE_BUF_SIZE,
                                  &len) == 0)
            nodus_tcp_send(h->conn, g_fake.buf, len);
    } else if (marker == g_fake.undecodable) {
        uint8_t *vbuf = NULL;
        size_t vlen = 0;
        if (nodus_value_serialize(row, &vbuf, &vlen) == 0) {
            cbor_encoder_t enc;
            cbor_encoder_init(&enc, g_fake.buf, FAKE_BUF_SIZE);
            fake_resp_header(&enc, h->txn, "result");
            cbor_encode_cstr(&enc, "r");
            cbor_encode_map(&enc, 2);
            cbor_encode_cstr(&enc, "vals");
            cbor_encode_array(&enc, 2);
            cbor_encode_bstr(&enc, vbuf, vlen);
            cbor_encode_uint(&enc, 7);           /* not a byte string */
            cbor_encode_cstr(&enc, "more");
            cbor_encode_bool(&enc, false);
            len = cbor_encoder_len(&enc);
            if (len > 0 && !enc.error) nodus_tcp_send(h->conn, g_fake.buf, len);
        }
        free(vbuf);
    } else {
        nodus_t2_page_info_t page;
        memset(&page, 0, sizeof(page));
        if (nodus_t2_result_page(h->txn, &row, 1, &page, g_fake.buf,
                                 FAKE_BUF_SIZE, &len) == 0)
            nodus_tcp_send(h->conn, g_fake.buf, len);
    }
    nodus_value_free(row);
}

static void fake_on_frame(nodus_tcp_conn_t *conn, const uint8_t *payload,
                           size_t len, void *ctx) {
    (void)ctx;
    nodus_tier2_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    if (nodus_t2_decode(payload, len, &msg) != 0) {
        nodus_t2_msg_free(&msg);
        return;
    }

    size_t out = 0;
    if (strcmp(msg.method, "hello") == 0) {
        uint8_t nonce[NODUS_NONCE_LEN];
        nodus_random(nonce, NODUS_NONCE_LEN);
        if (nodus_t2_challenge(msg.txn_id, nonce,
                                g_fake.buf, FAKE_BUF_SIZE, &out) == 0)
            nodus_tcp_send(conn, g_fake.buf, out);
    } else if (strcmp(msg.method, "auth") == 0) {
        uint8_t token[NODUS_SESSION_TOKEN_LEN];
        memset(token, 0x5a, sizeof(token));
        if (nodus_t2_auth_ok(msg.txn_id, token,
                              g_fake.buf, FAKE_BUF_SIZE, &out) == 0)
            nodus_tcp_send(conn, g_fake.buf, out);
    } else if (strcmp(msg.method, "get_all") == 0) {
        pthread_mutex_lock(&g_fake.mu);
        g_fake.total++;
        if (g_fake.nheld < HELD_MAX) {
            held_t *h = &g_fake.held[g_fake.nheld++];
            h->conn = conn;
            h->txn = msg.txn_id;
            h->key = msg.key;
            h->page = msg.page;
            h->has_own = msg.has_own;
            h->own = msg.own_fp;
            h->has_after = msg.has_after;
        }
        /* Every request of the case is in: answer, last one first. */
        if (g_fake.nheld == g_fake.expect)
            for (int i = g_fake.nheld - 1; i >= 0; i--)
                fake_answer(&g_fake.held[i]);
        pthread_mutex_unlock(&g_fake.mu);
    }
    nodus_t2_msg_free(&msg);
}

static void *fake_thread(void *arg) {
    (void)arg;
    while (!atomic_load(&g_fake.stop))
        nodus_tcp_poll(g_fake.tcp, 20);
    return NULL;
}

static int start_fake_server(void) {
    memset(&g_fake, 0, sizeof(g_fake));
    pthread_mutex_init(&g_fake.mu, NULL);
    g_fake.tcp = calloc(1, sizeof(nodus_tcp_t));
    g_fake.buf = malloc(FAKE_BUF_SIZE);
    if (!g_fake.tcp || !g_fake.buf) return -1;
    if (nodus_tcp_init(g_fake.tcp, -1) != 0) return -1;
    g_fake.tcp->on_frame = fake_on_frame;
    if (nodus_tcp_listen(g_fake.tcp, "127.0.0.1", 0) != 0) return -1;
    atomic_store(&g_fake.stop, false);
    return pthread_create(&g_fake.tid, NULL, fake_thread, NULL) == 0 ? 0 : -1;
}

static void stop_fake_server(void) {
    atomic_store(&g_fake.stop, true);
    pthread_join(g_fake.tid, NULL);
    nodus_tcp_close(g_fake.tcp);
    free(g_fake.tcp);
    free(g_fake.buf);
    pthread_mutex_destroy(&g_fake.mu);
}

/* A new case: nothing held, `expect` requests to wait for. */
static void fake_case(int expect, int silent, int error, int undecodable,
                      int legacy) {
    pthread_mutex_lock(&g_fake.mu);
    g_fake.nheld = 0;
    g_fake.expect = expect;
    g_fake.silent = silent;
    g_fake.error = error;
    g_fake.undecodable = undecodable;
    g_fake.legacy = legacy;
    pthread_mutex_unlock(&g_fake.mu);
}

/* ── Cases ─────────────────────────────────────────────────────────── */

static nodus_key_t g_keys[NODUS_CLIENT_PAGE_PIPELINE_MAX + 1];
static nodus_key_t g_owners[NODUS_CLIENT_PAGE_PIPELINE_MAX + 1];

static void setup_reqs(nodus_page_req_t *reqs, size_t n) {
    memset(reqs, 0, n * sizeof(*reqs));
    for (size_t i = 0; i < n; i++) {
        reqs[i].key = &g_keys[i];
        reqs[i].owner_fp = &g_owners[i];
        reqs[i].after = NULL;
    }
}

static void free_reqs(nodus_page_req_t *reqs, size_t n) {
    for (size_t i = 0; i < n; i++) {
        for (size_t j = 0; j < reqs[i].count; j++)
            nodus_value_free(reqs[i].vals[j]);
        free(reqs[i].vals);
        reqs[i].vals = NULL;
        reqs[i].count = 0;
    }
}

/* Item i answered with exactly its own row, as a paging node. */
static bool own_row(const nodus_page_req_t *r) {
    return r->rc == 0 && r->count == 1 && r->vals && r->vals[0] &&
           nodus_key_cmp(&r->vals[0]->key_hash, r->key) == 0 &&
           r->vals[0]->data_len == 1 &&
           r->vals[0]->data[0] == r->key->bytes[0] &&
           !r->more && !r->legacy && r->undecodable == 0;
}

static void run_cases(nodus_client_t *c) {
    nodus_page_req_t reqs[NODUS_CLIENT_PAGE_PIPELINE_MAX + 1];
    int rc;

    TEST("P1 4 keys, reverse replies -> each item its own row");
    fake_case(4, NONE, NONE, NONE, NONE);
    setup_reqs(reqs, 4);
    rc = nodus_client_get_all_page_strict_many(c, reqs, 4);
    {
        bool ok = rc == 0;
        for (int i = 0; i < 4 && ok; i++) ok = own_row(&reqs[i]);
        pthread_mutex_lock(&g_fake.mu);
        ok = ok && g_fake.nheld == 4;
        for (int i = 0; i < g_fake.nheld && ok; i++) {
            const held_t *h = &g_fake.held[i];
            ok = h->page && h->has_own && !h->has_after &&
                 nodus_key_cmp(&h->own, &g_owners[h->key.bytes[0] - 0xA0]) == 0;
            for (int j = 0; j < i && ok; j++)
                ok = g_fake.held[j].txn != h->txn;
        }
        pthread_mutex_unlock(&g_fake.mu);
        if (ok) PASS(); else FAIL("rows not routed to their own requests");
    }
    free_reqs(reqs, 4);

    TEST("P2 middle key never answered -> TIMEOUT there, rows elsewhere");
    fake_case(3, 0xA1, NONE, NONE, NONE);
    setup_reqs(reqs, 3);
    rc = nodus_client_get_all_page_strict_many(c, reqs, 3);
    if (rc == 0 && own_row(&reqs[0]) && own_row(&reqs[2]) &&
        reqs[1].rc == NODUS_ERR_TIMEOUT && reqs[1].count == 0 &&
        reqs[1].vals == NULL)
        PASS();
    else FAIL("per-item timeout not kept apart");
    free_reqs(reqs, 3);

    TEST("P3 one key unavailable -> NODUS_ERR_UNAVAILABLE there only");
    fake_case(3, NONE, 0xA2, NONE, NONE);
    setup_reqs(reqs, 3);
    rc = nodus_client_get_all_page_strict_many(c, reqs, 3);
    if (rc == 0 && own_row(&reqs[0]) && own_row(&reqs[1]) &&
        reqs[2].rc == NODUS_ERR_UNAVAILABLE && reqs[2].count == 0)
        PASS();
    else FAIL("per-item error code not kept apart");
    free_reqs(reqs, 3);

    TEST("P4 one key with a non-bstr item -> undecodable 1 there only");
    fake_case(3, NONE, NONE, 0xA0, NONE);
    setup_reqs(reqs, 3);
    rc = nodus_client_get_all_page_strict_many(c, reqs, 3);
    if (rc == 0 && reqs[0].rc == 0 && reqs[0].count == 1 &&
        reqs[0].undecodable == 1 && !reqs[0].legacy &&
        own_row(&reqs[1]) && own_row(&reqs[2]))
        PASS();
    else FAIL("per-item undecodable count not kept");
    free_reqs(reqs, 3);

    TEST("P5 one key from a pre-paging node -> legacy there only");
    fake_case(2, NONE, NONE, NONE, 0xA1);
    setup_reqs(reqs, 2);
    rc = nodus_client_get_all_page_strict_many(c, reqs, 2);
    if (rc == 0 && own_row(&reqs[0]) && reqs[1].rc == 0 &&
        reqs[1].legacy && !reqs[1].more && reqs[1].count == 1)
        PASS();
    else FAIL("per-item legacy flag not kept");
    free_reqs(reqs, 2);

    TEST("A1 bad shapes -> -1, nothing sent");
    pthread_mutex_lock(&g_fake.mu);
    int before = g_fake.total;
    pthread_mutex_unlock(&g_fake.mu);
    fake_case(100, NONE, NONE, NONE, NONE);
    setup_reqs(reqs, NODUS_CLIENT_PAGE_PIPELINE_MAX + 1);
    bool ok = nodus_client_get_all_page_strict_many(c, reqs, 0) == -1 &&
              nodus_client_get_all_page_strict_many(
                  c, reqs, NODUS_CLIENT_PAGE_PIPELINE_MAX + 1) == -1 &&
              nodus_client_get_all_page_strict_many(c, NULL, 1) == -1;
    reqs[1].key = NULL;
    ok = ok && nodus_client_get_all_page_strict_many(c, reqs, 2) == -1 &&
         reqs[0].rc == -1 && reqs[0].vals == NULL;
    pthread_mutex_lock(&g_fake.mu);
    ok = ok && g_fake.total == before;
    pthread_mutex_unlock(&g_fake.mu);
    if (ok) PASS(); else FAIL("a bad shape was accepted or sent");
}

int main(void) {
    printf("=== Nodus client pipelined strict page reads ===\n");

    nodus_identity_t *client_id = calloc(1, sizeof(*client_id));
    g_owner_id = calloc(1, sizeof(*g_owner_id));
    if (!client_id || !g_owner_id ||
        nodus_identity_generate(client_id) != 0 ||
        nodus_identity_generate(g_owner_id) != 0) {
        printf("FATAL: identities\n");
        return 1;
    }
    /* Item i: key filled with 0xA0 + i (its marker), owner with 0x10 + i. */
    for (int i = 0; i <= NODUS_CLIENT_PAGE_PIPELINE_MAX; i++) {
        memset(g_keys[i].bytes, 0xA0 + i, NODUS_KEY_BYTES);
        memset(g_owners[i].bytes, 0x10 + i, NODUS_KEY_BYTES);
    }

    if (start_fake_server() != 0) {
        printf("FATAL: fake server did not start\n");
        return 1;
    }

    nodus_client_t *c = calloc(1, sizeof(*c));
    if (!c) {
        printf("FATAL: alloc\n");
        return 1;
    }
    nodus_client_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.servers[0].ip, sizeof(cfg.servers[0].ip), "127.0.0.1");
    cfg.servers[0].port = g_fake.tcp->port;
    cfg.server_count = 1;
    cfg.connect_timeout_ms = 3000;
    cfg.request_timeout_ms = 1500;

    if (nodus_client_init(c, &cfg, client_id) != 0) {
        printf("FATAL: client init\n");
        return 1;
    }
    if (nodus_client_connect(c) != 0 || !nodus_client_is_ready(c)) {
        printf("FATAL: client did not connect to the fake server\n");
        nodus_client_close(c);
        return 1;
    }

    run_cases(c);

    nodus_client_close(c);
    free(c);
    stop_fake_server();
    nodus_identity_clear(client_id);
    free(client_id);
    nodus_identity_clear(g_owner_id);
    free(g_owner_id);

    printf("\n=== Results: %d passed, %d failed ===\n", passed, failed);
    return failed > 0 ? 1 : 0;
}
