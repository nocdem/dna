/**
 * Nodus — client SDK: an error reply without a valid code, and an
 * out-of-memory pending slot (C-10 b, C-07), over a real client and a fake
 * node on 127.0.0.1.
 *
 * The REAL client runs against a fake node built like test_client_strict_get.c
 * builds its fake (nodus_tcp_t + the 4001 session module of
 * nodus_test_session.h). The fake answers "dnac_utxo" with a reply shape
 * chosen per case and counts the requests it received.
 *
 * What it proves:
 *   E1  {"y":"e"} with no code         nodus_client_dnac_utxo returns
 *                                      NODUS_ERR_PROTOCOL_ERROR (not 0).
 *   E2  error code 0                   NODUS_ERR_PROTOCOL_ERROR.
 *   E3  error code 2^32 + 5            NODUS_ERR_PROTOCOL_ERROR (the old
 *                                      narrowing read it as the valid code 5).
 *   E4  error code NODUS_ERR_RATE_LIMITED   returned unchanged.
 *   E5  honest reply                   0 (control).
 *   M1  the reply buffer of the pending slot cannot be allocated
 *                                      (calloc of exactly one
 *                                      nodus_tier2_msg_t fails once, on the
 *                                      calling thread): the call fails with
 *                                      -1, NO request reaches the node, and
 *                                      the next call works. Before the fix
 *                                      the slot was published with a NULL
 *                                      reply buffer, the request was sent,
 *                                      and the node's answer made the
 *                                      client write through NULL (crash).
 *
 * Compile flags: the target links with -Wl,--wrap=calloc (the failure seam);
 * environment: none. Ports: the fake listens on 127.0.0.1:0.
 * Leaves behind: nothing (fake thread joined, client closed).
 *
 * How it can lie:
 *   - Only dnac_utxo is driven; the other dnac_* request functions share
 *     find_response_map / client_error_rc in the same file but are not each
 *     exercised here.
 *   - The calloc seam fires on the first calloc of that exact size made by
 *     the calling thread after it is armed; if some other calloc of that size
 *     preceded the pending slot's, M1 would fail the wrong allocation (the
 *     assertion "no request reached the node" would then still hold, but the
 *     crash-before-fix argument would not apply).
 *   - A fake that never answers makes a call time out; every case asserts its
 *     exact code, so that shows as FAIL, never PASS.
 */

#include "nodus/nodus.h"
#include "transport/nodus_tcp.h"
#include "protocol/nodus_tier2.h"
#include "protocol/nodus_cbor.h"
#include "crypto/nodus_identity.h"
#include "nodus_test_session.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── calloc failure seam (-Wl,--wrap=calloc) ─────────────────────── */

extern void *__real_calloc(size_t n, size_t sz);
static __thread int t_fail_next = 0;

void *__wrap_calloc(size_t n, size_t sz) {
    if (t_fail_next && n == 1 && sz == sizeof(nodus_tier2_msg_t)) {
        t_fail_next = 0;
        return NULL;
    }
    return __real_calloc(n, sz);
}

/* ── fake node ───────────────────────────────────────────────────── */

typedef enum {
    MODE_HONEST = 0,
    MODE_ERR_NOCODE,
    MODE_ERR_ZERO,
    MODE_ERR_WRAP,        /* code 2^32 + 5 */
    MODE_ERR_RATE
} reply_mode_t;

static nodus_identity_t g_node_id;
static nodus_inter_session_module_t *g_node_mod;
static nodus_tcp_t *g_tcp;
static pthread_t g_tid;
static _Atomic bool g_stop;
static _Atomic int g_mode;
static _Atomic int g_requests;
static uint8_t g_buf[65536];

static void reply_head(cbor_encoder_t *e, uint32_t txn, const char *y, size_t pairs) {
    cbor_encoder_init(e, g_buf, sizeof(g_buf));
    cbor_encode_map(e, pairs);
    cbor_encode_cstr(e, "t"); cbor_encode_uint(e, txn);
    cbor_encode_cstr(e, "y"); cbor_encode_cstr(e, y);
    cbor_encode_cstr(e, "q"); cbor_encode_cstr(e, "dnac_utxo");
    cbor_encode_cstr(e, "r");
}

static void fake_on_frame(nodus_tcp_conn_t *conn, const uint8_t *payload,
                          size_t len, void *ctx) {
    (void)ctx;
    nodus_tier2_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    if (nodus_t2_decode(payload, len, &msg) != 0) { nodus_t2_msg_free(&msg); return; }
    if (strcmp(msg.method, "dnac_utxo") == 0) {
        atomic_fetch_add(&g_requests, 1);
        cbor_encoder_t e;
        int mode = atomic_load(&g_mode);
        if (mode == MODE_HONEST) {
            uint8_t tid[64];
            memset(tid, 0xA1, sizeof(tid));
            reply_head(&e, msg.txn_id, "r", 4);
            cbor_encode_map(&e, 2);
            cbor_encode_cstr(&e, "count"); cbor_encode_uint(&e, 1);
            cbor_encode_cstr(&e, "utxos");
            cbor_encode_array(&e, 1);
            cbor_encode_map(&e, 2);
            cbor_encode_cstr(&e, "amount"); cbor_encode_uint(&e, 9);
            cbor_encode_cstr(&e, "tid"); cbor_encode_bstr(&e, tid, sizeof(tid));
        } else {
            reply_head(&e, msg.txn_id, "e", 4);
            if (mode == MODE_ERR_NOCODE) {
                cbor_encode_map(&e, 1);
            } else {
                cbor_encode_map(&e, 2);
                cbor_encode_cstr(&e, "code");
                cbor_encode_uint(&e, mode == MODE_ERR_ZERO ? 0ULL :
                                     mode == MODE_ERR_WRAP ? 0x100000005ULL :
                                     (uint64_t)NODUS_ERR_RATE_LIMITED);
            }
            cbor_encode_cstr(&e, "msg"); cbor_encode_cstr(&e, "x");
        }
        size_t n = cbor_encoder_len(&e);
        if (n > 0 && !e.error) nodus_tcp_send(conn, g_buf, n);
    }
    nodus_t2_msg_free(&msg);
}

static void *fake_thread(void *arg) {
    (void)arg;
    while (!atomic_load(&g_stop)) nodus_tcp_poll(g_tcp, 20);
    return NULL;
}

static int start_fake(void) {
    g_tcp = calloc(1, sizeof(nodus_tcp_t));
    if (!g_tcp || nodus_tcp_init(g_tcp, -1) != 0) return -1;
    g_tcp->on_frame = fake_on_frame;
    if (nodus_identity_generate(&g_node_id) != 0 ||
        !(g_node_mod = nts_attach(g_tcp, &g_node_id))) return -1;
    if (nodus_tcp_listen(g_tcp, "127.0.0.1", 0) != 0) return -1;
    atomic_store(&g_stop, false);
    return pthread_create(&g_tid, NULL, fake_thread, NULL) == 0 ? 0 : -1;
}

static void stop_fake(void) {
    atomic_store(&g_stop, true);
    pthread_join(g_tid, NULL);
    nodus_tcp_close(g_tcp);
    nodus_inter_session_free(g_node_mod);
    nodus_identity_clear(&g_node_id);
    free(g_tcp);
}

/* ── cases ───────────────────────────────────────────────────────── */

static int failed = 0;
#define CHECK(cond, name) do { \
    if (cond) printf("  %-66s PASS\n", name); \
    else { printf("  %-66s FAIL (%s:%d)\n", name, __FILE__, __LINE__); failed++; } \
} while (0)

int main(void) {
    printf("=== Nodus client: error reply without a code / pending-slot OOM ===\n");

    nodus_identity_t *client_id = calloc(1, sizeof(*client_id));
    if (!client_id || nodus_identity_generate(client_id) != 0 || start_fake() != 0) {
        printf("FATAL: setup\n");
        return 1;
    }

    nodus_client_t *c = calloc(1, sizeof(*c));
    nodus_client_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.servers[0].ip, sizeof(cfg.servers[0].ip), "127.0.0.1");
    cfg.servers[0].port = g_tcp->port;
    cfg.server_count = 1;
    cfg.connect_timeout_ms = 3000;
    cfg.request_timeout_ms = 2000;
    nts_trust(&cfg, &g_node_id);
    if (!c || nodus_client_init(c, &cfg, client_id) != 0 ||
        nodus_client_connect(c) != 0 || !nodus_client_is_ready(c)) {
        printf("FATAL: client did not connect to the fake node\n");
        return 1;
    }

    nodus_dnac_utxo_result_t res;
    int rc;

    atomic_store(&g_mode, MODE_ERR_NOCODE);
    rc = nodus_client_dnac_utxo(c, "owner", 10, &res);
    CHECK(rc == NODUS_ERR_PROTOCOL_ERROR, "E1 error reply without a code -> protocol error");

    atomic_store(&g_mode, MODE_ERR_ZERO);
    rc = nodus_client_dnac_utxo(c, "owner", 10, &res);
    CHECK(rc == NODUS_ERR_PROTOCOL_ERROR, "E2 error code 0 -> protocol error");

    atomic_store(&g_mode, MODE_ERR_WRAP);
    rc = nodus_client_dnac_utxo(c, "owner", 10, &res);
    CHECK(rc == NODUS_ERR_PROTOCOL_ERROR, "E3 error code 2^32+5 is not code 5");

    atomic_store(&g_mode, MODE_ERR_RATE);
    rc = nodus_client_dnac_utxo(c, "owner", 10, &res);
    CHECK(rc == NODUS_ERR_RATE_LIMITED, "E4 a valid error code is returned unchanged");

    atomic_store(&g_mode, MODE_HONEST);
    rc = nodus_client_dnac_utxo(c, "owner", 10, &res);
    CHECK(rc == 0 && res.count == 1, "E5 honest reply decodes (control)");
    if (rc == 0) nodus_client_free_utxo_result(&res);

    /* M1: pending-slot reply buffer cannot be allocated. */
    int before = atomic_load(&g_requests);
    t_fail_next = 1;
    rc = nodus_client_dnac_utxo(c, "owner", 10, &res);
    t_fail_next = 0;
    CHECK(rc == -1, "M1 allocation failure -> call fails");
    CHECK(atomic_load(&g_requests) == before, "M1 no request reached the node");
    rc = nodus_client_dnac_utxo(c, "owner", 10, &res);
    CHECK(rc == 0, "M1 the next call works");
    if (rc == 0) nodus_client_free_utxo_result(&res);

    nodus_client_close(c);
    free(c);
    stop_fake();
    nodus_identity_clear(client_id);
    free(client_id);

    printf("\n=== Results: %d failed ===\n", failed);
    return failed ? 1 : 0;
}
