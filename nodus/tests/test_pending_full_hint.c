/**
 * Nodus — pending-full parks only DHT replication frames (component split
 * S5a, decision 2026-10-01-nodus-component-split item 33).
 *
 * When a 4002 send fits neither the write buffer nor the pending queue, the
 * transport hands the frame to nodus_server_on_pending_full. Before S5a it
 * wrote ANY such frame for an authenticated cluster member into the DHT's
 * hinted-handoff table — presence p_sync, circuit ri_* frames, relayed
 * replies (nodus/BUGS.md "hint only replication frames"). Now only a DHT
 * replication frame is parked: the payload's CBOR envelope is a query
 * ("y" == "q") whose method ("q") is "sv" (nodus_t1_store_value) or "m_sv"
 * (nodus_t2_media_store_value). Everything else is dropped with a log line.
 *
 * Pins down, in-process (calloc'd server, a fake DHT backend that records
 * hint_store, one heap conn; no socket, no store, no clock):
 *   1. T1 sv and T2 m_sv are parked: hint_store called once each, with the
 *      peer's identity and the frame exactly as nodus_frame_encode builds
 *      it from the payload.
 *   2. Dropped (hint_store NOT called): T2 p_sync, T2 ri_close, T1 ntf,
 *      T1 sub, the replies fv_r and sv_ack, a T2 error, and bytes that are
 *      not CBOR.
 *   3. The gates in front are unchanged: an sv frame for a conn with no
 *      authenticated peer identity, or for a peer that is not a cluster
 *      member, is not parked.
 *
 * Requires: default build. Leaves behind: nothing.
 * RED on the tree before S5a: nodus_server_on_pending_full is static
 * (server_on_pending_full) — and it parked every case in 2.
 */

#include "server/nodus_server.h"
#include "server/nodus_dht_backend.h"
#include "protocol/nodus_tier1.h"
#include "protocol/nodus_tier2.h"
#include "protocol/nodus_wire.h"
#include "core/nodus_value.h"
#include "core/nodus_media_storage.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define TEST(name) do { printf("  %-62s", name); } while(0)
#define PASS()     do { printf("PASS\n"); passed++; } while(0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while(0)
#define CHECK(c, m) do { if (!(c)) { FAIL(m); goto out; } } while(0)

static int passed = 0;
static int failed = 0;

/* ── A DHT backend that records what is parked ─────────────────────── */

typedef struct {
    nodus_dht_backend_t base;
    int                 calls;
    nodus_key_t         node_id;
    uint8_t            *frame;
    size_t              len;
} fake_dht_t;

static int fake_hint_store(nodus_dht_backend_t *b, const nodus_key_t *node_id,
                           const char *ip, uint16_t port,
                           const uint8_t *frame, size_t len) {
    (void)ip; (void)port;
    fake_dht_t *f = (fake_dht_t *)b;
    f->calls++;
    f->node_id = *node_id;
    free(f->frame);
    f->frame = malloc(len);
    if (f->frame) memcpy(f->frame, frame, len);
    f->len = f->frame ? len : 0;
    return 0;
}

static const nodus_dht_backend_ops_t fake_ops = {
    .hint_store = fake_hint_store,
};

typedef struct {
    nodus_server_t   *srv;
    fake_dht_t        dht;
    nodus_tcp_conn_t *conn;
} fixture_t;

static nodus_key_t g_peer;

static int fixture_open(fixture_t *fx, bool authenticated, bool member) {
    memset(fx, 0, sizeof(*fx));
    fx->srv = calloc(1, sizeof(*fx->srv));
    fx->conn = calloc(1, sizeof(*fx->conn));
    if (!fx->srv || !fx->conn) return -1;
    fx->dht.base.ops = &fake_ops;
    fx->srv->dht = &fx->dht.base;
    if (member) {
        fx->srv->cluster.peer_count = 1;
        fx->srv->cluster.peers[0].node_id = g_peer;
    }
    fx->conn->fd = -1;
    fx->conn->slot = 4;
    fx->conn->is_nodus = true;
    snprintf(fx->conn->ip, sizeof(fx->conn->ip), "%s", "10.4.4.4");
    fx->conn->port = 4002;
    if (authenticated) {
        fx->conn->peer_id = g_peer;
        fx->conn->peer_id_set = true;
    }
    return 0;
}

static void fixture_close(fixture_t *fx) {
    free(fx->dht.frame);
    free(fx->conn);
    free(fx->srv);
    memset(fx, 0, sizeof(*fx));
}

/* Hand `payload` to the hook on a fresh authenticated-member fixture;
 * return how many times it was parked (-1: fixture failure). When
 * `framed_ok` is non-NULL it reports whether the parked frame equals
 * nodus_frame_encode(payload) and was keyed on the peer's identity. */
static int park_count(const uint8_t *payload, size_t len, bool *framed_ok) {
    fixture_t fx;
    if (fixture_open(&fx, true, true) != 0) { fixture_close(&fx); return -1; }
    nodus_server_on_pending_full(fx.conn, payload, len, fx.srv);
    int calls = fx.dht.calls;
    if (framed_ok) {
        *framed_ok = false;
        uint8_t *want = malloc(NODUS_FRAME_HEADER_SIZE + len);
        if (want && calls == 1 &&
            nodus_frame_encode(want, NODUS_FRAME_HEADER_SIZE + len, payload,
                               (uint32_t)len) == NODUS_FRAME_HEADER_SIZE + len &&
            fx.dht.len == NODUS_FRAME_HEADER_SIZE + len &&
            memcmp(fx.dht.frame, want, fx.dht.len) == 0 &&
            nodus_key_cmp(&fx.dht.node_id, &g_peer) == 0)
            *framed_ok = true;
        free(want);
    }
    fixture_close(&fx);
    return calls;
}

static uint8_t buf[65536];

static void test_replication_parked(void) {
    TEST("T1 sv and T2 m_sv are parked, framed, keyed on the peer");
    nodus_value_t *v = NULL;
    nodus_key_t key;
    nodus_pubkey_t pk;
    size_t len = 0;
    bool framed = false;
    nodus_media_meta_t meta;
    const uint8_t chunk[4] = { 1, 2, 3, 4 };
    memset(&key, 0x21, sizeof(key));
    memset(&pk, 0x22, sizeof(pk));
    memset(&meta, 0, sizeof(meta));
    memset(meta.content_hash, 0x33, sizeof(meta.content_hash));
    meta.chunk_count = 1;
    meta.total_size = 4;
    CHECK(nodus_value_create(&key, (const uint8_t *)"s5a", 3, NODUS_VALUE_PERMANENT,
                             0, 1, 1, &pk, &v) == 0, "value");
    CHECK(nodus_t1_store_value(0, v, buf, sizeof(buf), &len) == 0, "enc sv");
    CHECK(park_count(buf, len, &framed) == 1, "sv not parked");
    CHECK(framed, "sv parked frame / identity wrong");

    CHECK(nodus_t2_media_store_value(0, &meta, 0, chunk, sizeof(chunk),
                                     buf, sizeof(buf), &len) == 0, "enc m_sv");
    CHECK(park_count(buf, len, &framed) == 1, "m_sv not parked");
    CHECK(framed, "m_sv parked frame / identity wrong");
    PASS();
out:
    nodus_value_free(v);
}

static void test_others_dropped(void) {
    TEST("p_sync, ri_close, ntf, sub, fv_r, sv_ack, error, junk dropped");
    nodus_value_t *v = NULL;
    nodus_key_t key, fps[2];
    nodus_pubkey_t pk;
    size_t len = 0;
    memset(&key, 0x41, sizeof(key));
    memset(&pk, 0x42, sizeof(pk));
    memset(fps, 0x43, sizeof(fps));
    CHECK(nodus_value_create(&key, (const uint8_t *)"s5a", 3, NODUS_VALUE_PERMANENT,
                             0, 1, 1, &pk, &v) == 0, "value");

    CHECK(nodus_t2_presence_sync(0, fps, 2, buf, sizeof(buf), &len) == 0, "enc p_sync");
    CHECK(park_count(buf, len, NULL) == 0, "p_sync parked");
    CHECK(nodus_t2_ri_close(0, 77, buf, sizeof(buf), &len) == 0, "enc ri_close");
    CHECK(park_count(buf, len, NULL) == 0, "ri_close parked");
    CHECK(nodus_t1_notify(0, &key, v, buf, sizeof(buf), &len) == 0, "enc ntf");
    CHECK(park_count(buf, len, NULL) == 0, "ntf parked");
    CHECK(nodus_t1_subscribe(0, &key, buf, sizeof(buf), &len) == 0, "enc sub");
    CHECK(park_count(buf, len, NULL) == 0, "sub parked");
    CHECK(nodus_t1_value_found(5, v, buf, sizeof(buf), &len) == 0, "enc fv_r");
    CHECK(park_count(buf, len, NULL) == 0, "fv_r reply parked");
    CHECK(nodus_t1_store_ack(6, buf, sizeof(buf), &len) == 0, "enc sv_ack");
    CHECK(park_count(buf, len, NULL) == 0, "sv_ack reply parked");
    CHECK(nodus_t2_error(7, NODUS_ERR_INTERNAL_ERROR, "x", buf, sizeof(buf), &len) == 0,
          "enc error");
    CHECK(park_count(buf, len, NULL) == 0, "error parked");
    {
        const uint8_t junk[] = { 0xff, 0x00, 0x13, 0x37 };
        CHECK(park_count(junk, sizeof(junk), NULL) == 0, "non-CBOR bytes parked");
    }
    PASS();
out:
    nodus_value_free(v);
}

static void test_gates_kept(void) {
    TEST("sv for an unauthenticated conn / non-member is not parked");
    nodus_value_t *v = NULL;
    nodus_key_t key;
    nodus_pubkey_t pk;
    size_t len = 0;
    fixture_t fx;
    memset(&fx, 0, sizeof(fx));
    memset(&key, 0x51, sizeof(key));
    memset(&pk, 0x52, sizeof(pk));
    CHECK(nodus_value_create(&key, (const uint8_t *)"s5a", 3, NODUS_VALUE_PERMANENT,
                             0, 1, 1, &pk, &v) == 0, "value");
    CHECK(nodus_t1_store_value(0, v, buf, sizeof(buf), &len) == 0, "enc sv");

    CHECK(fixture_open(&fx, false, true) == 0, "fixture");
    nodus_server_on_pending_full(fx.conn, buf, len, fx.srv);
    CHECK(fx.dht.calls == 0, "parked for an unauthenticated conn");
    fixture_close(&fx);

    CHECK(fixture_open(&fx, true, false) == 0, "fixture");
    nodus_server_on_pending_full(fx.conn, buf, len, fx.srv);
    CHECK(fx.dht.calls == 0, "parked for a peer that is not a cluster member");
    PASS();
out:
    fixture_close(&fx);
    nodus_value_free(v);
}

int main(void) {
    printf("=== Split S5a item 33: pending-full parks only replication ===\n");
    memset(&g_peer, 0x9d, sizeof(g_peer));
    test_replication_parked();
    test_others_dropped();
    test_gates_kept();
    printf("\n%d passed, %d failed\n", passed, failed);
    return failed ? 1 : 0;
}
