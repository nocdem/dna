/**
 * Nodus — DHT IPC (component split S5b)
 *
 * Decision docs/plans/decisions/2026-10-01-nodus-component-split.md items
 * 17, 19, 27, 29, 31, 32, 34 ("connection checks are the S5 gate"). The
 * core side (server/nodus_dht_backend_ipc.c — the IPC DHT backend
 * nodus-server uses with storage_external) against the storage side
 * (dht/nodus_dht_ipc.c — the nodus-storage runtime, here with a REAL DHT
 * opened in a mkdtemp directory), over a real <dir>/storage.sock. Core
 * itself is replaced by test callbacks (nodus_dht_ipc_core_t) that record
 * what core would write to a session, send from UDP 4000, or close. Where
 * the order of two connections must be controlled, the test plays core
 * with raw connections of its own (a "raw core") and holds them open.
 *
 * Proves:
 *   1  routing snapshot: the storage side pushes its routing table's peers
 *      on a new control connection; core's routing_snapshot answers them,
 *      node id included (the presence pin, decision 30);
 *   2  membership snapshot: core's members reach the storage side's
 *      hint_wanted (member + offline < NODUS_HINT_OFFLINE_SKIP_SEC), and a
 *      change (a new member past the threshold) is re-pushed;
 *   3  a client put: the origin preface carries the session's fp + pk (the
 *      value's signature verifies under the preface key → the value is
 *      stored), the shadow opens with the session's generation, and the
 *      reply reaches core addressed to (CLIENT, slot, that generation);
 *   4  cross-origin push: a 4002 `sv` arriving on an INTER origin notifies
 *      a CLIENT origin's listener — the value_changed push reaches core
 *      addressed to that client session;
 *   5  the INTER preface carries the peer's fp and address: a 4002 `sub`
 *      records exactly those as the subscriber;
 *   6  UDP relay: a datagram core hands over is answered by the DHT through
 *      core's udp_send to the sender's address; peer events keep their
 *      call order (ALIVE then DEAD of one node leaves it out of routing);
 *   7  decision 32: when the storage side closes an origin connection,
 *      core is told to end exactly that session (close_origin), and the
 *      shadow is gone;
 *   8  slot reuse, deterministic reorder (raw core, held fds): a newer
 *      preface for a slot whose previous connection is still OPEN takes the
 *      slot; frames on the old connection are dropped; the old
 *      connection's EOF afterwards does not touch the new shadow; an OLDER
 *      preface of the same boot id is refused; a preface of another boot
 *      id (core restarted, generations from 1 again) takes the slot;
 *   9  decision 31: with the control connection down a client DHT request
 *      is answered AT ONCE with exactly nodus_t2_error(txn,
 *      NODUS_ERR_UNAVAILABLE, NODUS_DHT_NO_STORAGE_MSG), and NO origin
 *      connection is dialled (the storage side never opens the shadow);
 *  10  core-side bound: with the storage side not reading, client requests
 *      are forwarded until the origin connection holds
 *      NODUS_DHT_IPC_QUEUE_MAX queued bytes; the next request gets the
 *      decision-31 error for ITS txn, the connection stays (no
 *      close_origin), and once the storage side reads again every
 *      forwarded request is answered;
 *  11  storage-side bound: with core not reading (raw core), replies are
 *      queued until NODUS_DHT_IPC_REPLY_QUEUE_MAX; then the connection is
 *      closed and the shadow cleared;
 *  12  full snapshot re-push: a second core (new control connection, no
 *      routing change) receives the routing snapshot; after the storage
 *      runtime is restarted (no membership), core re-pushes its unchanged
 *      membership on the new control connection;
 *  13  origin generation over sockets (test_origin_gen cases 2-3): a get
 *      whose batch forward is still pending when core closes the session
 *      and opens the slot's next one (which then talks on it) never
 *      reaches core — not for the old generation, not for the new;
 *  14  the partial-wipe marker rule with storage_external
 *      (nodus_server_marker_dbs_ready): true in-process; with
 *      storage_external true only when nodus.db AND channels.db exist.
 *  S5b fix round:
 *  8   (extended, F5) a raw core announces its boot id on a control
 *      connection first; an origin preface of an unannounced boot id is
 *      refused; a control connection of a NEW boot id closes the old
 *      core's origin connections and clears their shadows;
 *  11b (F1) many SMALL replies (32 KiB) to a core that does not read: the
 *      transport's own ceiling (write buffer + 20-frame pending FIFO) is
 *      reached below the 16 MiB byte bound — the lost reply closes the
 *      origin (before the fix it was dropped silently);
 *  15  (F5) a batch forward pending for (slot 14, gen 5) of an old core
 *      boot is cancelled when the new boot's control connection arrives —
 *      before the new boot's (slot 14, gen 5) opens — and its reply never
 *      reaches the new session, which itself is served;
 *  16  (F4) client and 4002 origin caps are separate (lowered to 1 + 1 by
 *      the test hook): a second client session gets the decision-31
 *      error at once while a 4002 session still opens; a second 4002
 *      session's frame is dropped (its sub is never recorded);
 *  17  (F3) the storage process's open (nodus_dht_ipc_open_storage) runs
 *      the partial-wipe gate: marker + chain DB + no nodus.db → refused
 *      and NO database created; marker + nothing → opens.
 *  F6 (a control connection counts as up only after storage's first frame)
 *  is what b_ready / raw_ctl wait for; a case that needs it waits for it.
 *
 * Requires: a default build; no environment. Uses three mkdtemp
 * directories under /tmp and removes them; binds one loopback TCP listener
 * on an ephemeral port (case 13); no fixed port.
 * How it can lie: every wait is a bounded poll loop whose exhaustion FAILs
 * the case (a timeout is never a pass); the polls' own 5 ms waits only pace
 * the loop. Absences are read after a bounded number of polls and each is
 * paired with a positive check on the same path: "no origin dialled" (9)
 * with the error having been sent; "old EOF ignored" / "old frame dropped"
 * (8) with the new shadow's own listen key present; "no deferred reply"
 * (13) with the batch forward having been active for the old generation
 * and having ended, and the new session's own reply arriving.
 */

#define _DEFAULT_SOURCE 1   /* mkdtemp under -std=c11 */

#include "server/nodus_dht_backend.h"
#include "server/nodus_server.h"
#include "dht/nodus_dht.h"
#include "dht/nodus_dht_ipc.h"
#include "transport/nodus_tcp.h"
#include "protocol/nodus_tier1.h"
#include "protocol/nodus_tier2.h"
#include "core/nodus_value.h"
#include "crypto/nodus_identity.h"
#include "crypto/nodus_sign.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#define TEST(name) do { printf("  %-64s", name); fflush(stdout); } while(0)
#define PASS()     do { printf("PASS\n"); passed++; } while(0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while(0)

#define POLL_ROUNDS 600

static int passed = 0;
static int failed = 0;

static char g_dir[64];
static char g_sock[NODUS_TCP_UNIX_PATH_MAX];
static nodus_identity_t g_id;          /* storage identity, also the client */
static uint8_t g_token[NODUS_SESSION_TOKEN_LEN];

static nodus_dht_ipc_t     *S = NULL;  /* storage runtime */
static nodus_dht_t         *D = NULL;  /* its DHT */
static nodus_dht_backend_t *B = NULL;  /* core's IPC backend */

/* ── The core stand-in ────────────────────────────────────────────── */

#define CAP_MAX 4096
typedef struct {
    nodus_dht_origin_t o;
    uint32_t           txn;
    char               type;
    char               method[64];
    int                err_code;
    char               err_msg[128];
    bool               has_value;
    uint8_t            raw[256];
    size_t             raw_len;      /* 0 when the frame was larger */
} cap_t;

static cap_t caps[CAP_MAX];
static int   ncaps = 0;

static int core_send_to_origin(void *ctx, nodus_dht_origin_t origin,
                               const uint8_t *frame, size_t len) {
    (void)ctx;
    if (ncaps >= CAP_MAX) return 0;
    cap_t *c = &caps[ncaps++];
    memset(c, 0, sizeof(*c));
    c->o = origin;
    if (len <= sizeof(c->raw)) {
        memcpy(c->raw, frame, len);
        c->raw_len = len;
    }
    nodus_tier2_msg_t m;
    memset(&m, 0, sizeof(m));
    if (nodus_t2_decode(frame, len, &m) == 0) {
        c->txn = m.txn_id;
        c->type = m.type;
        snprintf(c->method, sizeof(c->method), "%s", m.method);
        c->err_code = m.error_code;
        snprintf(c->err_msg, sizeof(c->err_msg), "%s", m.error_msg);
        c->has_value = m.value != NULL;
    }
    nodus_t2_msg_free(&m);
    return 0;
}

static int  udp_count = 0;
static char udp_ip[64];
static uint16_t udp_port = 0;
static uint32_t udp_txn = 0;
static char udp_method[16];

static int core_udp_send(void *ctx, const uint8_t *payload, size_t len,
                         const char *ip, uint16_t port) {
    (void)ctx;
    udp_count++;
    snprintf(udp_ip, sizeof(udp_ip), "%s", ip);
    udp_port = port;
    nodus_tier1_msg_t t1;
    memset(&t1, 0, sizeof(t1));
    if (nodus_t1_decode(payload, len, &t1) == 0) {
        udp_txn = t1.txn_id;
        snprintf(udp_method, sizeof(udp_method), "%s", t1.method);
    }
    nodus_t1_msg_free(&t1);
    return 0;
}

#define CLOSE_MAX 64
static nodus_dht_origin_t closes[CLOSE_MAX];
static int nclose = 0;

static void core_close_origin(void *ctx, nodus_dht_origin_t origin) {
    (void)ctx;
    if (nclose < CLOSE_MAX) closes[nclose++] = origin;
}

static nodus_dht_ipc_member_t g_members[NODUS_DHT_IPC_MEMBERS_MAX];
static int g_members_n = 0;

static int core_members(void *ctx, nodus_dht_ipc_member_t *out, int max) {
    (void)ctx;
    int n = g_members_n < max ? g_members_n : max;
    memcpy(out, g_members, (size_t)n * sizeof(*out));
    return n;
}

static void core_cb(nodus_dht_ipc_core_t *c) {
    memset(c, 0, sizeof(*c));
    c->send_to_origin = core_send_to_origin;
    c->udp_send       = core_udp_send;
    c->close_origin   = core_close_origin;
    c->members        = core_members;
}

/* ── Helpers ──────────────────────────────────────────────────────── */

static void pump_once(nodus_dht_backend_t *b) {
    if (b) b->ops->tick(b);
    if (S) {
        nodus_dht_ipc_poll(S, 5);
        nodus_dht_ipc_tick(S);
    }
    if (b) b->ops->tick(b);
}

static const cap_t *find_cap(uint32_t txn, int kind, int slot) {
    for (int i = 0; i < ncaps; i++)
        if (caps[i].txn == txn && (int)caps[i].o.kind == kind &&
            caps[i].o.slot == slot)
            return &caps[i];
    return NULL;
}

static bool any_cap_txn(uint32_t txn) {
    for (int i = 0; i < ncaps; i++)
        if (caps[i].txn == txn) return true;
    return false;
}

static void rand_key(nodus_key_t *k) {
    nodus_random(k->bytes, NODUS_KEY_BYTES);
}

/* A value under `key` owned and signed by g_id. */
static nodus_value_t *mk_value(const nodus_key_t *key, size_t data_len,
                               uint64_t vid, uint64_t seq) {
    uint8_t *data = malloc(data_len ? data_len : 1);
    if (!data) return NULL;
    memset(data, 0x5A, data_len ? data_len : 1);
    nodus_value_t *v = NULL;
    if (nodus_value_create(key, data, data_len, NODUS_VALUE_EPHEMERAL,
                           NODUS_DEFAULT_TTL, vid, seq, &g_id.pk, &v) != 0 ||
        nodus_value_sign(v, &g_id.sk) != 0) {
        if (v) nodus_value_free(v);
        free(data);
        return NULL;
    }
    free(data);
    return v;
}

static int open_storage(void) {
    S = nodus_dht_ipc_new(&g_id, false);
    D = calloc(1, sizeof(*D));
    if (!S || !D) return -1;
    nodus_dht_host_t host;
    nodus_dht_ipc_host(S, &host);
    if (nodus_dht_init(D, &host) != 0) return -1;
    if (nodus_dht_open(D, g_dir, "127.0.0.1", 4002) != 0) return -1;
    nodus_dht_ipc_attach(S, D);
    return nodus_dht_ipc_listen(S, g_sock);
}

/* ── A raw core (held connections) ────────────────────────────────── */

static nodus_tcp_t g_raw;
static int raw_disconnects = 0;
static int raw_frames = 0;

/* The T2 txn ids of the last frames the raw core read (replies). */
static uint32_t raw_txn[4096];
static int      raw_ntxn = 0;

static void raw_on_frame(nodus_tcp_conn_t *conn, const uint8_t *payload,
                         size_t len, void *ctx) {
    (void)conn; (void)ctx;
    raw_frames++;
    nodus_tier2_msg_t m;
    memset(&m, 0, sizeof(m));
    if (nodus_t2_decode(payload, len, &m) == 0 && raw_ntxn < 4096)
        raw_txn[raw_ntxn++] = m.txn_id;
    nodus_t2_msg_free(&m);
}

static bool raw_got_txn(uint32_t txn) {
    for (int i = 0; i < raw_ntxn; i++)
        if (raw_txn[i] == txn) return true;
    return false;
}

/* The raw core's control connection: storage takes the boot id of a
 * control preface as the current core's (S5b F5) and refuses origin
 * prefaces of any other boot id. Replaces B's control connection (one
 * per storage) — B's own sessions are dropped by storage as the old
 * core's; cases that use B afterwards wait for it with b_ready. */
static void raw_pump(int rounds);

static nodus_tcp_conn_t *raw_ctl(uint8_t boot_byte) {
    nodus_tcp_conn_t *c = nodus_tcp_unix_connect(&g_raw, g_sock,
                                                 NODUS_TCP_UNIX_UID_SELF);
    if (!c) return NULL;
    uint8_t boot[NODUS_DHT_IPC_BOOT_LEN];
    memset(boot, boot_byte, sizeof(boot));
    uint8_t buf[64];
    size_t n = nodus_dht_ipc_encode_ctl(boot, buf, sizeof(buf));
    if (!n || nodus_tcp_send(c, buf, n) != 0) return NULL;
    /* Confirmed, as core's backend confirms it (F6): storage answers a new
     * control connection with its routing snapshot — only then is its boot
     * id the current one, and origin prefaces of it are accepted. */
    int before = raw_frames;
    for (int i = 0; i < POLL_ROUNDS && raw_frames == before; i++)
        raw_pump(1);
    return raw_frames > before ? c : NULL;
}

static void pump_once(nodus_dht_backend_t *b);

/* B's control connection is up and confirmed (F6) — after a raw core or a
 * second core replaced it. */
static bool b_ready(void) {
    for (int i = 0; i < POLL_ROUNDS * 4 && !nodus_dht_backend_ipc_ready(B); i++)
        pump_once(B);
    for (int i = 0; i < 10; i++) pump_once(B);
    return nodus_dht_backend_ipc_ready(B);
}

static void raw_on_disconnect(nodus_tcp_conn_t *conn, void *ctx) {
    (void)conn; (void)ctx;
    raw_disconnects++;
}

static nodus_tcp_conn_t *raw_origin(int slot, uint64_t gen, uint8_t boot_byte) {
    nodus_tcp_conn_t *c = nodus_tcp_unix_connect(&g_raw, g_sock,
                                                 NODUS_TCP_UNIX_UID_SELF);
    if (!c) return NULL;
    nodus_dht_ipc_preface_t *pf = calloc(1, sizeof(*pf));
    uint8_t *buf = malloc(NODUS_PK_BYTES + 512);
    if (!pf || !buf) { free(pf); free(buf); return NULL; }
    pf->origin.kind = NODUS_DHT_ORIGIN_CLIENT;
    pf->origin.slot = slot;
    pf->origin.gen = gen;
    memset(pf->boot, boot_byte, sizeof(pf->boot));
    pf->fp = g_id.node_id;
    pf->pk = g_id.pk;
    size_t n = nodus_dht_ipc_encode_origin(pf, buf, NODUS_PK_BYTES + 512);
    int rc = n ? nodus_tcp_send(c, buf, n) : -1;
    free(pf);
    free(buf);
    return rc == 0 ? c : NULL;
}

static void raw_pump(int rounds) {
    for (int i = 0; i < rounds; i++) {
        nodus_tcp_poll(&g_raw, 2);
        nodus_dht_ipc_poll(S, 2);
        nodus_dht_ipc_tick(S);
    }
}

static int raw_listen(nodus_tcp_conn_t *c, uint32_t txn, const nodus_key_t *k) {
    uint8_t buf[512];
    size_t n = 0;
    if (nodus_t2_listen(txn, g_token, k, buf, sizeof(buf), &n) != 0) return -1;
    return nodus_tcp_send(c, buf, n);
}

/* ── Cases ────────────────────────────────────────────────────────── */

static nodus_key_t idP;   /* a routing peer (unreachable 4002: port 3) */

static void case_routing_snapshot(void) {
    TEST("1 routing snapshot (with node id) reaches core");
    rand_key(&idP);
    nodus_dht_peer_seen(D, NODUS_DHT_PEER_ALIVE, &idP, "127.0.0.1", 1, 3);
    nodus_dht_peer_addr_t out[8];
    int n = 0;
    for (int i = 0; i < POLL_ROUNDS && n == 0; i++) {
        pump_once(B);
        n = B->ops->routing_snapshot(B, out, 8);
    }
    if (n != 1) { FAIL("no routing snapshot at core"); return; }
    if (nodus_key_cmp(&out[0].node_id, &idP) != 0 ||
        strcmp(out[0].ip, "127.0.0.1") != 0 || out[0].tcp_port != 3) {
        FAIL("snapshot entry differs from the routing entry");
        return;
    }
    PASS();
}

static void case_membership(void) {
    TEST("2 membership snapshot drives hint_wanted; a change is re-pushed");
    nodus_dht_host_t h;
    nodus_dht_ipc_host(S, &h);
    nodus_key_t idQ, idX;
    rand_key(&idQ);
    rand_key(&idX);
    g_members[0].node_id = idP;
    g_members[0].offline_secs = 5;
    g_members_n = 1;
    bool ok = false;
    for (int i = 0; i < POLL_ROUNDS && !ok; i++) {
        pump_once(B);
        ok = h.hint_wanted(h.ctx, &idP);
    }
    if (!ok) { FAIL("member never wanted a hint"); return; }
    if (h.hint_wanted(h.ctx, &idX)) { FAIL("a non-member wants a hint"); return; }
    /* A new member: the member set changed — pushed. */
    g_members[1].node_id = idQ;
    g_members[1].offline_secs = 1;
    g_members_n = 2;
    ok = false;
    for (int i = 0; i < POLL_ROUNDS && !ok; i++) {
        pump_once(B);
        ok = h.hint_wanted(h.ctx, &idQ);
    }
    if (!ok) { FAIL("a new member was not pushed"); return; }
    /* The same member now offline past the threshold: a projected change
     * (the crossing) — pushed, and no hint is wanted for it any more. */
    g_members[1].offline_secs = NODUS_HINT_OFFLINE_SKIP_SEC + 100;
    for (int i = 0; i < POLL_ROUNDS && ok; i++) {
        pump_once(B);
        ok = h.hint_wanted(h.ctx, &idQ);
    }
    if (ok) { FAIL("the threshold crossing was not pushed"); return; }
    if (!h.hint_wanted(h.ctx, &idP)) { FAIL("the other member was lost"); return; }
    PASS();
}

static void case_client_put(void) {
    TEST("3 client put: preface fp+pk, shadow gen, reply to (CLIENT,5,7)");
    nodus_dht_origin_t o = { NODUS_DHT_ORIGIN_CLIENT, 5, 7 };
    B->ops->session_opened(B, o);

    nodus_key_t key;
    rand_key(&key);
    nodus_value_t *v = mk_value(&key, 100, 1, 1);
    if (!v) { FAIL("value"); return; }
    uint8_t buf[4096];
    size_t n = 0;
    if (nodus_t2_put(101, g_token, &key, v->data, v->data_len,
                     NODUS_VALUE_EPHEMERAL, NODUS_DEFAULT_TTL, 1, 1,
                     &v->signature, buf, sizeof(buf), &n) != 0) {
        nodus_value_free(v);
        FAIL("encode put");
        return;
    }
    nodus_value_free(v);
    nodus_tier2_msg_t m;
    memset(&m, 0, sizeof(m));
    nodus_t2_decode(buf, n, &m);
    B->ops->client_frame(B, 5, &g_id.node_id, &g_id.pk, buf, n, &m);
    nodus_t2_msg_free(&m);

    const cap_t *c = NULL;
    for (int i = 0; i < POLL_ROUNDS && !(c = find_cap(101, 0, 5)); i++)
        pump_once(B);
    if (!c) { FAIL("no reply at core"); return; }
    if (c->o.gen != 7) { FAIL("reply not addressed to generation 7"); return; }
    if (c->type == 'e') { FAIL(c->err_msg); return; }
    if (!D->sessions[5].open || D->sessions[5].gen != 7) {
        FAIL("shadow not open with generation 7");
        return;
    }
    nodus_value_t *got = NULL;
    if (nodus_storage_get(&D->storage, &key, &got) != 0 || !got) {
        FAIL("value not stored (preface pk did not verify it)");
        return;
    }
    nodus_value_free(got);
    PASS();
}

static nodus_key_t g_peer_fp;

static void case_cross_origin(void) {
    TEST("4 cross-origin push: 4002 sv notifies the client's listener");
    nodus_key_t key;
    rand_key(&key);
    uint8_t buf[8192];
    size_t n = 0;
    if (nodus_t2_listen(102, g_token, &key, buf, sizeof(buf), &n) != 0) {
        FAIL("encode listen");
        return;
    }
    nodus_tier2_msg_t m;
    memset(&m, 0, sizeof(m));
    nodus_t2_decode(buf, n, &m);
    B->ops->client_frame(B, 5, &g_id.node_id, &g_id.pk, buf, n, &m);
    nodus_t2_msg_free(&m);
    const cap_t *c = NULL;
    for (int i = 0; i < POLL_ROUNDS && !(c = find_cap(102, 0, 5)); i++)
        pump_once(B);
    if (!c || c->type == 'e' || D->sessions[5].listen_count != 1) {
        FAIL("listen not in place");
        return;
    }

    nodus_dht_origin_t io = { NODUS_DHT_ORIGIN_INTER, 9, 8 };
    B->ops->session_opened(B, io);
    rand_key(&g_peer_fp);
    nodus_value_t *v = mk_value(&key, 64, 2, 1);
    if (!v || nodus_t1_store_value(103, v, buf, sizeof(buf), &n) != 0) {
        if (v) nodus_value_free(v);
        FAIL("encode sv");
        return;
    }
    nodus_value_free(v);
    nodus_tier1_msg_t t1;
    memset(&t1, 0, sizeof(t1));
    nodus_t1_decode(buf, n, &t1);
    int before = ncaps;
    B->ops->inter_t1(B, 9, &g_peer_fp, "10.1.2.3", buf, n, &t1);
    nodus_t1_msg_free(&t1);

    bool got = false;
    for (int i = 0; i < POLL_ROUNDS && !got; i++) {
        pump_once(B);
        for (int k = before; k < ncaps; k++)
            if (caps[k].o.kind == NODUS_DHT_ORIGIN_CLIENT && caps[k].o.slot == 5 &&
                caps[k].o.gen == 7 && strcmp(caps[k].method, "value_changed") == 0 &&
                caps[k].has_value)
                got = true;
    }
    if (!got) { FAIL("no value_changed push to (CLIENT,5,7)"); return; }
    PASS();
}

static void case_inter_preface(void) {
    TEST("5 INTER preface carries peer fp + ip (sub records them)");
    nodus_key_t key;
    rand_key(&key);
    uint8_t buf[512];
    size_t n = 0;
    if (nodus_t1_subscribe(104, &key, buf, sizeof(buf), &n) != 0) {
        FAIL("encode sub");
        return;
    }
    nodus_tier1_msg_t t1;
    memset(&t1, 0, sizeof(t1));
    nodus_t1_decode(buf, n, &t1);
    B->ops->inter_t1(B, 9, &g_peer_fp, "10.1.2.3", buf, n, &t1);
    nodus_t1_msg_free(&t1);
    bool ok = false;
    for (int i = 0; i < POLL_ROUNDS && !ok; i++) {
        pump_once(B);
        for (int k = 0; k < NODUS_MAX_SUBSCRIPTIONS && !ok; k++) {
            const nodus_subscription_t *e = &D->subscriptions.entries[k];
            if (e->active && nodus_key_cmp(&e->key, &key) == 0) {
                if (nodus_key_cmp(&e->subscriber_node_id, &g_peer_fp) != 0 ||
                    strcmp(e->subscriber_ip, "10.1.2.3") != 0) {
                    FAIL("subscriber identity / address not the preface's");
                    return;
                }
                ok = true;
            }
        }
    }
    if (!ok) { FAIL("subscription never recorded"); return; }
    PASS();
}

static void case_udp_relay(void) {
    TEST("6 UDP relay both ways; peer events keep their call order");
    nodus_key_t target;
    rand_key(&target);
    uint8_t buf[512];
    size_t n = 0;
    if (nodus_t1_find_node(105, &target, buf, sizeof(buf), &n) != 0) {
        FAIL("encode fn");
        return;
    }
    nodus_tier1_msg_t t1;
    memset(&t1, 0, sizeof(t1));
    nodus_t1_decode(buf, n, &t1);
    int before = udp_count;
    B->ops->udp_frame(B, "127.0.0.9", 40000, buf, n, &t1);
    nodus_t1_msg_free(&t1);
    for (int i = 0; i < POLL_ROUNDS && udp_count == before; i++)
        pump_once(B);
    if (udp_count == before) { FAIL("no datagram back at core"); return; }
    if (strcmp(udp_ip, "127.0.0.9") != 0 || udp_port != 40000 ||
        udp_txn != 105 || strcmp(udp_method, "fn_r") != 0) {
        FAIL("datagram not the fn answer to the sender");
        return;
    }

    nodus_key_t idS, idT;
    rand_key(&idS);
    rand_key(&idT);
    B->ops->peer_seen(B, NODUS_DHT_PEER_ALIVE, &idS, "127.0.0.20", 1000, 1002);
    B->ops->peer_dead(B, &idS);
    B->ops->peer_seen(B, NODUS_DHT_PEER_ALIVE, &idT, "127.0.0.21", 1000, 1002);
    nodus_peer_t p;
    bool t_in = false;
    for (int i = 0; i < POLL_ROUNDS && !t_in; i++) {
        pump_once(B);
        t_in = nodus_routing_lookup(&D->routing, &idT, &p) == 0;
    }
    if (!t_in) { FAIL("ALIVE never reached routing"); return; }
    if (nodus_routing_lookup(&D->routing, &idS, &p) == 0) {
        FAIL("ALIVE + DEAD applied out of order");
        return;
    }
    /* Leave routing as the next cases expect: idP only. */
    nodus_dht_peer_dead(D, &idT);
    PASS();
}

static void case_decision32(void) {
    TEST("7 storage closes an origin -> core ends exactly that session");
    /* A frame no client could send (core forwards only decoded requests):
     * the storage side refuses it and closes the origin connection. */
    static const uint8_t junk[] = { 0xFF };   /* not CBOR at all */
    nodus_tier2_msg_t m;
    memset(&m, 0, sizeof(m));
    m.txn_id = 106;
    int before = nclose;
    B->ops->client_frame(B, 5, &g_id.node_id, &g_id.pk, junk, sizeof(junk), &m);
    for (int i = 0; i < POLL_ROUNDS && nclose == before; i++)
        pump_once(B);
    if (nclose != before + 1) { FAIL("core was not told"); return; }
    if (closes[before].kind != NODUS_DHT_ORIGIN_CLIENT ||
        closes[before].slot != 5 || closes[before].gen != 7) {
        FAIL("close_origin named another session");
        return;
    }
    if (D->sessions[5].open) { FAIL("shadow still open"); return; }
    /* Core ends the session: */
    nodus_dht_origin_t o = { NODUS_DHT_ORIGIN_CLIENT, 5, 7 };
    B->ops->session_closed(B, o);
    PASS();
}

static void case_slot_reuse(void) {
    TEST("8 slot reuse: newer preface wins, old frames + old EOF ignored");
    nodus_tcp_init(&g_raw, -1);
    g_raw.on_frame = raw_on_frame;
    g_raw.on_disconnect = raw_on_disconnect;
    nodus_key_t k1, k2, k3;
    rand_key(&k1);
    rand_key(&k2);
    rand_key(&k3);
    const int slot = 3;

    if (!raw_ctl(0x11)) { FAIL("raw control (boot 0x11)"); goto out; }
    nodus_tcp_conn_t *a = raw_origin(slot, 100, 0x11);
    if (!a || raw_listen(a, 1, &k1) != 0) { FAIL("conn A"); goto out; }
    for (int i = 0; i < POLL_ROUNDS &&
                    !(D->sessions[slot].gen == 100 &&
                      D->sessions[slot].listen_count == 1); i++)
        raw_pump(1);
    if (D->sessions[slot].gen != 100 || D->sessions[slot].listen_count != 1) {
        FAIL("A's shadow");
        goto out;
    }

    /* B opens the slot again while A is still open (core closed A's
     * session; its EOF has not been delivered — the test holds it). */
    nodus_tcp_conn_t *b2 = raw_origin(slot, 101, 0x11);
    if (!b2 || raw_listen(b2, 2, &k2) != 0) { FAIL("conn B"); goto out; }
    for (int i = 0; i < POLL_ROUNDS &&
                    !(D->sessions[slot].gen == 101 &&
                      D->sessions[slot].listen_count == 1); i++)
        raw_pump(1);
    if (D->sessions[slot].gen != 101 || D->sessions[slot].listen_count != 1 ||
        nodus_key_cmp(&D->sessions[slot].listen_keys[0], &k2) != 0) {
        FAIL("B's shadow is not fresh with its own listen");
        goto out;
    }

    /* A frame on A now belongs to an ended session. */
    raw_listen(a, 3, &k3);
    raw_pump(50);
    if (D->sessions[slot].listen_count != 1) {
        FAIL("a frame on the old connection reached the new shadow");
        goto out;
    }
    /* A's EOF, late: the new shadow stays. */
    nodus_tcp_disconnect(&g_raw, a);
    raw_pump(50);
    if (!D->sessions[slot].open || D->sessions[slot].gen != 101 ||
        D->sessions[slot].listen_count != 1) {
        FAIL("the old EOF touched the new shadow");
        goto out;
    }

    /* An older preface (same boot id) is refused. */
    int disc = raw_disconnects;
    nodus_tcp_conn_t *c = raw_origin(slot, 99, 0x11);
    if (!c) { FAIL("conn C"); goto out; }
    for (int i = 0; i < POLL_ROUNDS && raw_disconnects == disc; i++)
        raw_pump(1);
    if (raw_disconnects == disc) { FAIL("older preface not refused"); goto out; }
    if (D->sessions[slot].gen != 101) { FAIL("older preface took the slot"); goto out; }

    /* A preface of a boot id no control connection announced is refused
     * (F5: only the current core's sessions). */
    disc = raw_disconnects;
    nodus_tcp_conn_t *x = raw_origin(slot, 500, 0x33);
    if (!x) { FAIL("conn X"); goto out; }
    for (int i = 0; i < POLL_ROUNDS && raw_disconnects == disc; i++)
        raw_pump(1);
    if (raw_disconnects == disc || D->sessions[slot].gen != 101) {
        FAIL("a preface of an unannounced boot id was not refused");
        goto out;
    }

    /* Another boot id (core restarted): its control connection drops the
     * old core's sessions (B2's connection is closed, the shadow cleared);
     * then generation 1 of the new boot takes the slot. */
    disc = raw_disconnects;
    if (!raw_ctl(0x22)) { FAIL("raw control (boot 0x22)"); goto out; }
    for (int i = 0; i < POLL_ROUNDS &&
                    (D->sessions[slot].open || raw_disconnects == disc); i++)
        raw_pump(1);
    if (D->sessions[slot].open || raw_disconnects == disc) {
        FAIL("the old boot's session survived a new boot's control");
        goto out;
    }
    nodus_tcp_conn_t *e = raw_origin(slot, 1, 0x22);
    if (!e) { FAIL("conn E"); goto out; }
    for (int i = 0; i < POLL_ROUNDS && D->sessions[slot].gen != 1; i++)
        raw_pump(1);
    if (D->sessions[slot].gen != 1 || D->sessions[slot].listen_count != 0) {
        FAIL("a new boot id did not take the slot");
        goto out;
    }
    PASS();
out:
    nodus_tcp_close(&g_raw);
    for (int i = 0; i < 20; i++) {    /* the storage side sees every EOF */
        nodus_dht_ipc_poll(S, 2);
        nodus_dht_ipc_tick(S);
    }
}

static void case_control_down(void) {
    TEST("9 control down: decision-31 error at once, no origin dialled");
    nodus_dht_ipc_core_t cb;
    core_cb(&cb);
    nodus_dht_backend_t *b2 = NULL;
    if (nodus_dht_backend_ipc_open(g_dir, &cb, &b2) != 0) {
        FAIL("open");
        return;
    }
    /* Never ticked: no control connection, although storage listens. */
    nodus_dht_origin_t o = { NODUS_DHT_ORIGIN_CLIENT, 7, 50 };
    b2->ops->session_opened(b2, o);
    nodus_key_t key;
    rand_key(&key);
    uint8_t buf[512];
    size_t n = 0;
    nodus_t2_get(777, g_token, &key, buf, sizeof(buf), &n);
    nodus_tier2_msg_t m;
    memset(&m, 0, sizeof(m));
    nodus_t2_decode(buf, n, &m);
    int before = ncaps;
    b2->ops->client_frame(b2, 7, &g_id.node_id, &g_id.pk, buf, n, &m);
    nodus_t2_msg_free(&m);

    uint8_t want[256];
    size_t wlen = 0;
    nodus_t2_error(777, NODUS_ERR_UNAVAILABLE, NODUS_DHT_NO_STORAGE_MSG,
                   want, sizeof(want), &wlen);
    bool at_once = ncaps == before + 1 && caps[before].o.slot == 7 &&
                   caps[before].o.gen == 50 && caps[before].raw_len == wlen &&
                   memcmp(caps[before].raw, want, wlen) == 0;
    for (int i = 0; i < 50; i++) {
        nodus_dht_ipc_poll(S, 2);
        nodus_dht_ipc_tick(S);
    }
    bool no_dial = !D->sessions[7].open;
    b2->ops->close(b2);
    if (!at_once) { FAIL("the error was not these bytes, at once"); return; }
    if (!no_dial) { FAIL("an origin connection was dialled"); return; }
    PASS();
}

static void case_core_bound(void) {
    TEST("10 core bound: 4 MiB queued -> error for that txn, conn stays");
    if (!b_ready()) { FAIL("core's control connection never confirmed"); return; }
    const int slot = 11;
    nodus_dht_origin_t o = { NODUS_DHT_ORIGIN_CLIENT, slot, 60 };
    B->ops->session_opened(B, o);
    for (int i = 0; i < 20; i++) pump_once(B);   /* control is up */

    const size_t dlen = 256 * 1024;
    uint8_t *data = calloc(1, dlen);
    uint8_t *buf = malloc(dlen + 16384);
    if (!data || !buf) { free(data); free(buf); FAIL("alloc"); return; }
    nodus_key_t key;
    rand_key(&key);
    nodus_sig_t sig;
    memset(&sig, 0, sizeof(sig));
    int forwarded = 0;
    bool refused = false;
    uint32_t refused_txn = 0;
    int nclose0 = nclose;
    for (int i = 0; i < 200 && !refused; i++) {
        uint32_t txn = 2000 + (uint32_t)i;
        size_t n = 0;
        if (nodus_t2_put(txn, g_token, &key, data, dlen, NODUS_VALUE_EPHEMERAL,
                         NODUS_DEFAULT_TTL, 1, (uint64_t)i + 1, &sig,
                         buf, dlen + 16384, &n) != 0)
            break;
        nodus_tier2_msg_t m;
        memset(&m, 0, sizeof(m));
        m.txn_id = txn;
        int before = ncaps;
        /* Core only (the storage side is not polled): core's own transport
         * is not polled either, so nothing drains the queue. */
        B->ops->client_frame(B, slot, &g_id.node_id, &g_id.pk, buf, n, &m);
        if (ncaps > before && caps[before].txn == txn &&
            caps[before].err_code == NODUS_ERR_UNAVAILABLE) {
            refused = true;
            refused_txn = txn;
        } else {
            forwarded++;
        }
    }
    free(data);
    free(buf);
    if (!refused) { FAIL("never refused"); return; }
    if (forwarded < 1) { FAIL("nothing forwarded before the bound"); return; }
    if (nclose != nclose0) { FAIL("the bound closed the session"); return; }
    /* The storage side reads again: every forwarded request is answered. */
    int answered = 0;
    for (int i = 0; i < POLL_ROUNDS * 4 && answered < forwarded; i++) {
        pump_once(B);
        answered = 0;
        for (int k = 0; k < ncaps; k++)
            if (caps[k].o.slot == slot && caps[k].txn >= 2000 &&
                caps[k].txn < refused_txn && caps[k].o.gen == 60)
                answered++;
    }
    if (answered < forwarded) { FAIL("not every forwarded request answered"); return; }
    if (nclose != nclose0) { FAIL("a session was closed"); return; }
    B->ops->session_closed(B, o);
    PASS();
}

static void case_storage_bound(void) {
    TEST("11 storage bound: 16 MiB unread replies -> origin closed");
    nodus_tcp_init(&g_raw, -1);
    g_raw.on_frame = raw_on_frame;
    g_raw.on_disconnect = raw_on_disconnect;
    const int slot = 12;
    nodus_key_t key;
    rand_key(&key);
    nodus_value_t *v = mk_value(&key, 2 * 1024 * 1024, 7, 1);
    if (!v || nodus_storage_put(&D->storage, v) != 0) {
        if (v) nodus_value_free(v);
        FAIL("seed value");
        nodus_tcp_close(&g_raw);
        return;
    }
    nodus_value_free(v);

    if (!raw_ctl(0x44)) { FAIL("raw control"); nodus_tcp_close(&g_raw); return; }
    nodus_tcp_conn_t *c = raw_origin(slot, 500, 0x44);
    if (!c) { FAIL("conn"); nodus_tcp_close(&g_raw); return; }
    uint8_t buf[512];
    for (int i = 0; i < 14; i++) {
        size_t n = 0;
        nodus_t2_get(3000 + (uint32_t)i, g_token, &key, buf, sizeof(buf), &n);
        nodus_tcp_send(c, buf, n);
    }
    /* Flush the requests out, then stop reading on the "core" side. */
    nodus_tcp_poll(&g_raw, 5);
    int disc = raw_disconnects;
    bool opened = false;
    for (int i = 0; i < POLL_ROUNDS && !opened; i++) {
        nodus_dht_ipc_poll(S, 2);
        nodus_dht_ipc_tick(S);
        opened = D->sessions[slot].open;
    }
    bool closed = false;
    for (int i = 0; i < POLL_ROUNDS && !closed; i++) {
        nodus_dht_ipc_poll(S, 2);
        nodus_dht_ipc_tick(S);
        closed = opened && !D->sessions[slot].open;
    }
    /* Now read: the close arrives behind what was queued. */
    for (int i = 0; i < POLL_ROUNDS && raw_disconnects == disc; i++)
        nodus_tcp_poll(&g_raw, 5);
    bool seen = raw_disconnects > disc;
    nodus_tcp_close(&g_raw);
    if (!opened) { FAIL("the origin never opened"); return; }
    if (!closed) { FAIL("the shadow was not cleared"); return; }
    if (!seen) { FAIL("the connection was not closed"); return; }
    PASS();
}

static void case_storage_bound_small(void) {
    TEST("11b small unread replies: transport queue full -> origin closed");
    /* F1: with replies far below NODUS_DHT_IPC_REPLY_QUEUE_MAX each (32 KiB),
     * the transport's own ceiling — a ~5 MiB write buffer plus a pending
     * FIFO of NODUS_PENDING_MAX_FRAMES (20) frames — is reached long before
     * 16 MiB. Before the fix the next reply was refused by the transport
     * and silently lost; now that loss (a failed send, or the pending-full
     * hook) closes the origin, so core ends the session (decision 32). */
    nodus_tcp_init(&g_raw, -1);
    g_raw.on_frame = raw_on_frame;
    g_raw.on_disconnect = raw_on_disconnect;
    raw_ntxn = 0;
    const int slot = 16;
    nodus_key_t key;
    rand_key(&key);
    nodus_value_t *v = mk_value(&key, 32 * 1024, 8, 1);
    if (!v || nodus_storage_put(&D->storage, v) != 0) {
        if (v) nodus_value_free(v);
        FAIL("seed value");
        nodus_tcp_close(&g_raw);
        return;
    }
    nodus_value_free(v);

    if (!raw_ctl(0x55)) { FAIL("raw control"); nodus_tcp_close(&g_raw); return; }
    nodus_tcp_conn_t *c = raw_origin(slot, 1, 0x55);
    if (!c) { FAIL("conn"); nodus_tcp_close(&g_raw); return; }
    uint8_t buf[512];
    /* 400 gets ≈ 80 KB of requests (fits the socket at once); 400 × 32 KiB
     * ≈ 12.5 MiB of replies — more than the transport ceiling, less than
     * the 16 MiB byte bound. */
    for (int i = 0; i < 400; i++) {
        size_t n = 0;
        nodus_t2_get(5000 + (uint32_t)i, g_token, &key, buf, sizeof(buf), &n);
        nodus_tcp_send(c, buf, n);
    }
    nodus_tcp_poll(&g_raw, 5);
    int disc = raw_disconnects;
    bool opened = false;
    for (int i = 0; i < POLL_ROUNDS && !opened; i++) {
        nodus_dht_ipc_poll(S, 2);
        nodus_dht_ipc_tick(S);
        opened = D->sessions[slot].open;
    }
    bool closed = false;
    for (int i = 0; i < POLL_ROUNDS * 2 && !closed; i++) {
        nodus_dht_ipc_poll(S, 2);
        nodus_dht_ipc_tick(S);
        closed = opened && !D->sessions[slot].open;
    }
    for (int i = 0; i < POLL_ROUNDS && raw_disconnects == disc; i++)
        nodus_tcp_poll(&g_raw, 5);
    bool seen = raw_disconnects > disc;
    nodus_tcp_close(&g_raw);
    for (int i = 0; i < 20; i++) {
        nodus_dht_ipc_poll(S, 2);
        nodus_dht_ipc_tick(S);
    }
    if (!opened) { FAIL("the origin never opened"); return; }
    if (!closed) { FAIL("a lost small reply did not close the origin"); return; }
    if (!seen) { FAIL("the connection was not closed"); return; }
    PASS();
}

static void case_boot_cancel(void) {
    TEST("15 a new core boot cancels the old core's deferred replies");
    /* F5: generations restart at 1 with a new core boot id, so the old
     * core's (slot 14, gen 5) and the new core's (slot 14, gen 5) are equal
     * origins. A batch forward pending for the old one must be dropped when
     * the new boot's control connection arrives — before the new session
     * opens — or its reply would reach the new client. */
    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t al = sizeof(a);
    if (lfd < 0 || bind(lfd, (struct sockaddr *)&a, sizeof(a)) != 0 ||
        listen(lfd, 8) != 0 ||
        getsockname(lfd, (struct sockaddr *)&a, &al) != 0) {
        if (lfd >= 0) close(lfd);
        FAIL("listener");
        return;
    }
    uint16_t tport = ntohs(a.sin_port);
    nodus_key_t idR;
    rand_key(&idR);
    nodus_dht_peer_seen(D, NODUS_DHT_PEER_ALIVE, &idR, "127.0.0.1",
                        (uint16_t)(tport - 2), tport);

    nodus_tcp_init(&g_raw, -1);
    g_raw.on_frame = raw_on_frame;
    g_raw.on_disconnect = raw_on_disconnect;
    raw_ntxn = 0;
    const int slot = 14;
    bool ok = false;
    const char *why = "";
    nodus_key_t kx, kl;
    rand_key(&kx);
    rand_key(&kl);
    uint8_t buf[512];
    size_t n = 0;

    if (!raw_ctl(0x66)) { why = "raw control (old boot)"; goto out; }
    nodus_tcp_conn_t *c1 = raw_origin(slot, 5, 0x66);
    if (!c1) { why = "old conn"; goto out; }
    nodus_t2_get(6001, g_token, &kx, buf, sizeof(buf), &n);
    nodus_tcp_send(c1, buf, n);
    bool active = false;
    for (int i = 0; i < POLL_ROUNDS && !active; i++) {
        raw_pump(1);
        for (int k = 0; k < NODUS_BF_MAX_BATCHES; k++)
            if (D->bf_state.batches[k].active &&
                D->bf_state.batches[k].origin.slot == slot &&
                D->bf_state.batches[k].origin.gen == 5)
                active = true;
    }
    if (!active) { why = "no batch forward for the old (14, 5)"; goto out; }

    if (!raw_ctl(0x77)) { why = "raw control (new boot)"; goto out; }
    for (int k = 0; k < NODUS_BF_MAX_BATCHES; k++)
        if (D->bf_state.batches[k].active) { why = "deferred batch survived"; goto out; }
    if (D->sessions[slot].open) { why = "the old shadow survived"; goto out; }

    nodus_tcp_conn_t *c2 = raw_origin(slot, 5, 0x77);
    if (!c2 || raw_listen(c2, 6002, &kl) != 0) { why = "new conn"; goto out; }
    for (int i = 0; i < POLL_ROUNDS && !raw_got_txn(6002); i++)
        raw_pump(1);
    if (!raw_got_txn(6002)) { why = "the new session got no reply"; goto out; }

    close(lfd);
    lfd = -1;
    for (int i = 0; i < 200; i++) {
        raw_pump(1);
        nodus_dht_tick(D);
    }
    if (raw_got_txn(6001)) { why = "the old core's reply reached the new session"; goto out; }
    ok = true;
out:
    if (lfd >= 0) close(lfd);
    nodus_dht_peer_dead(D, &idR);
    nodus_tcp_close(&g_raw);
    for (int i = 0; i < 20; i++) {
        nodus_dht_ipc_poll(S, 2);
        nodus_dht_ipc_tick(S);
    }
    if (ok) PASS(); else FAIL(why);
}

static void case_caps(void) {
    TEST("16 client and 4002 origin caps are separate");
    /* F4: caps lowered to 1 + 1 (test hook). A second client session gets
     * the decision-31 error at once while a 4002 session still opens; a
     * second 4002 session's frame is dropped (its sub never recorded). */
    nodus_dht_ipc_core_t cb;
    core_cb(&cb);
    nodus_dht_backend_t *b4 = NULL;
    if (nodus_dht_backend_ipc_open(g_dir, &cb, &b4) != 0) { FAIL("open"); return; }
    nodus_dht_backend_ipc_test_set_caps(b4, 1, 1);
    for (int i = 0; i < POLL_ROUNDS * 4 && !nodus_dht_backend_ipc_ready(b4); i++)
        pump_once(b4);
    bool ok = false;
    const char *why = "";
    if (!nodus_dht_backend_ipc_ready(b4)) { why = "control never confirmed"; goto out; }

    nodus_dht_origin_t c20 = { NODUS_DHT_ORIGIN_CLIENT, 20, 900 };
    nodus_dht_origin_t c21 = { NODUS_DHT_ORIGIN_CLIENT, 21, 901 };
    nodus_dht_origin_t i30 = { NODUS_DHT_ORIGIN_INTER, 30, 902 };
    nodus_dht_origin_t i31 = { NODUS_DHT_ORIGIN_INTER, 31, 903 };
    b4->ops->session_opened(b4, c20);
    b4->ops->session_opened(b4, c21);
    b4->ops->session_opened(b4, i30);
    b4->ops->session_opened(b4, i31);

    nodus_key_t k;
    rand_key(&k);
    uint8_t buf[512];
    size_t n = 0;
    nodus_tier2_msg_t m;
    nodus_t2_listen(7001, g_token, &k, buf, sizeof(buf), &n);
    memset(&m, 0, sizeof(m));
    nodus_t2_decode(buf, n, &m);
    b4->ops->client_frame(b4, 20, &g_id.node_id, &g_id.pk, buf, n, &m);
    nodus_t2_msg_free(&m);
    int before = ncaps;
    nodus_t2_listen(7002, g_token, &k, buf, sizeof(buf), &n);
    memset(&m, 0, sizeof(m));
    nodus_t2_decode(buf, n, &m);
    b4->ops->client_frame(b4, 21, &g_id.node_id, &g_id.pk, buf, n, &m);
    nodus_t2_msg_free(&m);
    if (!(ncaps == before + 1 && caps[before].txn == 7002 &&
          caps[before].err_code == NODUS_ERR_UNAVAILABLE)) {
        why = "the second client session did not get the error at once";
        goto out;
    }

    nodus_key_t s1, s2, pfp;
    rand_key(&s1);
    rand_key(&s2);
    rand_key(&pfp);
    nodus_tier1_msg_t t1;
    nodus_t1_subscribe(7003, &s1, buf, sizeof(buf), &n);
    memset(&t1, 0, sizeof(t1));
    nodus_t1_decode(buf, n, &t1);
    b4->ops->inter_t1(b4, 30, &pfp, "10.9.9.30", buf, n, &t1);
    nodus_t1_msg_free(&t1);
    nodus_t1_subscribe(7004, &s2, buf, sizeof(buf), &n);
    memset(&t1, 0, sizeof(t1));
    nodus_t1_decode(buf, n, &t1);
    b4->ops->inter_t1(b4, 31, &pfp, "10.9.9.31", buf, n, &t1);
    nodus_t1_msg_free(&t1);

    bool got1 = false, got2 = false;
    for (int i = 0; i < POLL_ROUNDS && !got1; i++) {
        pump_once(b4);
        for (int e = 0; e < NODUS_MAX_SUBSCRIPTIONS; e++) {
            const nodus_subscription_t *s = &D->subscriptions.entries[e];
            if (!s->active) continue;
            if (nodus_key_cmp(&s->key, &s1) == 0) got1 = true;
            if (nodus_key_cmp(&s->key, &s2) == 0) got2 = true;
        }
    }
    for (int i = 0; i < 50; i++) pump_once(b4);
    for (int e = 0; e < NODUS_MAX_SUBSCRIPTIONS; e++) {
        const nodus_subscription_t *s = &D->subscriptions.entries[e];
        if (s->active && nodus_key_cmp(&s->key, &s2) == 0) got2 = true;
    }
    if (!got1) { why = "the first 4002 session (client cap full) did not open"; goto out; }
    if (got2) { why = "a 4002 session past its cap was served"; goto out; }
    ok = true;
out:
    b4->ops->close(b4);
    for (int i = 0; i < 20; i++) {
        nodus_dht_ipc_poll(S, 2);
        nodus_dht_ipc_tick(S);
    }
    if (ok) PASS(); else FAIL(why);
}

static void case_storage_gate(void) {
    TEST("17 storage runs the partial-wipe gate before opening its DBs");
    /* F3: marker + a chain DB + no nodus.db is a partial wipe — the
     * storage process refuses and creates NOTHING (nodus.db / channels.db
     * stay absent); with all three absent (+ marker) it opens. */
    char dir[64];
    snprintf(dir, sizeof(dir), "/tmp/nodus_sgate_XXXXXX");
    if (!mkdtemp(dir)) { FAIL("mkdtemp"); return; }
    char p_marker[160], p_wit[160], p_db[160], p_ch[160];
    snprintf(p_marker, sizeof(p_marker), "%s/%s", dir,
             NODUS_PARTIAL_WIPE_GENESIS_MARKER);
    snprintf(p_wit, sizeof(p_wit), "%s/witness_abcd.db", dir);
    snprintf(p_db, sizeof(p_db), "%s/nodus.db", dir);
    snprintf(p_ch, sizeof(p_ch), "%s/channels.db", dir);
    FILE *f = fopen(p_marker, "w");
    if (f) fclose(f);
    f = fopen(p_wit, "w");
    if (f) fclose(f);

    nodus_dht_host_t h;
    nodus_dht_ipc_host(S, &h);
    nodus_dht_t *d2 = calloc(1, sizeof(*d2));
    bool ok = false;
    const char *why = "";
    if (!d2 || nodus_dht_init(d2, &h) != 0) { why = "dht init"; goto out; }
    int rc = nodus_dht_ipc_open_storage(d2, dir, "127.0.0.1", 4002);
    struct stat st;
    if (rc != -2) { why = "the gate did not refuse"; goto out_dht; }
    if (stat(p_db, &st) == 0 || stat(p_ch, &st) == 0) {
        why = "a database was created despite the refusal";
        goto out_dht;
    }
    /* Positive control: marker, no database at all → a fresh start. */
    unlink(p_wit);
    rc = nodus_dht_ipc_open_storage(d2, dir, "127.0.0.1", 4002);
    if (rc != 0 || stat(p_db, &st) != 0) { why = "a clean directory was refused"; goto out_dht; }
    ok = true;
out_dht:
    nodus_dht_stop(d2);
    nodus_dht_close(d2);
out:
    free(d2);
    {
        char cmd[160];
        snprintf(cmd, sizeof(cmd), "rm -rf %s", dir);
        if (system(cmd) != 0) { /* best effort */ }
    }
    if (ok) PASS(); else FAIL(why);
}

static void case_repush(void) {
    TEST("12 full snapshot re-push on a new control connection");
    /* (a) A second core: no routing change, yet it gets the snapshot. */
    nodus_dht_ipc_core_t cb;
    core_cb(&cb);
    nodus_dht_backend_t *b3 = NULL;
    if (nodus_dht_backend_ipc_open(g_dir, &cb, &b3) != 0) { FAIL("open"); return; }
    nodus_dht_peer_addr_t out[8];
    int n = 0;
    for (int i = 0; i < POLL_ROUNDS && n == 0; i++) {
        pump_once(b3);
        n = b3->ops->routing_snapshot(b3, out, 8);
    }
    b3->ops->close(b3);
    for (int i = 0; i < 20; i++) pump_once(B);
    if (n != 1 || nodus_key_cmp(&out[0].node_id, &idP) != 0) {
        FAIL("a new control connection got no routing snapshot");
        return;
    }

    /* (b) The storage runtime restarts (no membership yet); core's
     * membership did not change, and still arrives in full. */
    nodus_dht_ipc_free(S);
    S = nodus_dht_ipc_new(&g_id, false);
    if (!S) { FAIL("restart"); return; }
    nodus_dht_ipc_host(S, &D->host);
    nodus_dht_ipc_attach(S, D);
    if (nodus_dht_ipc_listen(S, g_sock) != 0) { FAIL("relisten"); return; }
    nodus_dht_host_t h;
    nodus_dht_ipc_host(S, &h);
    if (h.hint_wanted(h.ctx, &idP)) { FAIL("a fresh runtime has a snapshot"); return; }
    bool ok = false;
    for (int i = 0; i < POLL_ROUNDS * 4 && !ok; i++) {
        pump_once(B);
        ok = h.hint_wanted(h.ctx, &idP);
    }
    if (!ok) { FAIL("membership not re-pushed on reconnect"); return; }
    PASS();
}

static void case_origin_gen(void) {
    TEST("13 a deferred reply never reaches the slot's next session");
    if (!b_ready()) { FAIL("core's control connection never confirmed"); return; }
    /* A 4002 peer that accepts and never answers: the batch forward to it
     * stays pending until the test closes the listener. */
    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = 0;
    socklen_t al = sizeof(a);
    if (lfd < 0 || bind(lfd, (struct sockaddr *)&a, sizeof(a)) != 0 ||
        listen(lfd, 8) != 0 ||
        getsockname(lfd, (struct sockaddr *)&a, &al) != 0) {
        if (lfd >= 0) close(lfd);
        FAIL("listener");
        return;
    }
    uint16_t tport = ntohs(a.sin_port);
    nodus_key_t idR;
    rand_key(&idR);
    nodus_dht_peer_dead(D, &idP);
    nodus_dht_peer_seen(D, NODUS_DHT_PEER_ALIVE, &idR, "127.0.0.1",
                        (uint16_t)(tport - 2), tport);

    const int slot = 13;
    nodus_dht_origin_t o1 = { NODUS_DHT_ORIGIN_CLIENT, slot, 300 };
    B->ops->session_opened(B, o1);
    nodus_key_t kx;
    rand_key(&kx);
    uint8_t buf[512];
    size_t n = 0;
    nodus_t2_get(1300, g_token, &kx, buf, sizeof(buf), &n);
    nodus_tier2_msg_t m;
    memset(&m, 0, sizeof(m));
    nodus_t2_decode(buf, n, &m);
    B->ops->client_frame(B, slot, &g_id.node_id, &g_id.pk, buf, n, &m);
    nodus_t2_msg_free(&m);

    bool active = false;
    for (int i = 0; i < POLL_ROUNDS && !active; i++) {
        pump_once(B);
        for (int k = 0; k < NODUS_BF_MAX_BATCHES; k++)
            if (D->bf_state.batches[k].active &&
                D->bf_state.batches[k].origin.gen == 300)
                active = true;
    }
    if (!active) { close(lfd); FAIL("no batch forward for generation 300"); return; }

    /* Core ends the session and the slot's next one talks at once. */
    B->ops->session_closed(B, o1);
    nodus_dht_origin_t o2 = { NODUS_DHT_ORIGIN_CLIENT, slot, 301 };
    B->ops->session_opened(B, o2);
    nodus_key_t kl;
    rand_key(&kl);
    nodus_t2_listen(1301, g_token, &kl, buf, sizeof(buf), &n);
    memset(&m, 0, sizeof(m));
    nodus_t2_decode(buf, n, &m);
    B->ops->client_frame(B, slot, &g_id.node_id, &g_id.pk, buf, n, &m);
    nodus_t2_msg_free(&m);
    const cap_t *c = NULL;
    for (int i = 0; i < POLL_ROUNDS && !(c = find_cap(1301, 0, slot)); i++)
        pump_once(B);
    if (!c || c->o.gen != 301 || D->sessions[slot].gen != 301) {
        close(lfd);
        FAIL("the next session did not open");
        return;
    }

    /* The peer goes away: the forward ends, the batch replies — to nobody. */
    close(lfd);
    bool done = false;
    for (int i = 0; i < POLL_ROUNDS * 4 && !done; i++) {
        pump_once(B);
        nodus_dht_tick(D);
        done = true;
        for (int k = 0; k < NODUS_BF_MAX_BATCHES; k++)
            if (D->bf_state.batches[k].active) done = false;
    }
    for (int i = 0; i < 20; i++) pump_once(B);
    nodus_dht_peer_dead(D, &idR);
    if (!done) { FAIL("the batch forward never ended"); return; }
    if (any_cap_txn(1300)) { FAIL("the deferred reply reached core"); return; }
    B->ops->session_closed(B, o2);
    PASS();
}

static void case_marker_rule(void) {
    TEST("14 marker rule: storage_external waits for both DHT databases");
    char dir[64];
    snprintf(dir, sizeof(dir), "/tmp/nodus_mark_XXXXXX");
    if (!mkdtemp(dir)) { FAIL("mkdtemp"); return; }
    nodus_server_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.data_path, sizeof(cfg.data_path), "%s", dir);
    char p1[128], p2[128];
    snprintf(p1, sizeof(p1), "%s/nodus.db", dir);
    snprintf(p2, sizeof(p2), "%s/channels.db", dir);

    bool inproc = nodus_server_marker_dbs_ready(&cfg);
    cfg.storage_external = true;
    bool none = nodus_server_marker_dbs_ready(&cfg);
    FILE *f = fopen(p1, "w");
    if (f) fclose(f);
    bool one = nodus_server_marker_dbs_ready(&cfg);
    f = fopen(p2, "w");
    if (f) fclose(f);
    bool both = nodus_server_marker_dbs_ready(&cfg);
    unlink(p1);
    unlink(p2);
    rmdir(dir);
    if (!inproc) { FAIL("in-process mode must not wait"); return; }
    if (none || one) { FAIL("armed before both databases exist"); return; }
    if (!both) { FAIL("not armed with both databases present"); return; }
    PASS();
}

int main(void) {
    printf("test_dht_ipc (split S5b)\n");
    snprintf(g_dir, sizeof(g_dir), "/tmp/nodus_dipc_XXXXXX");
    if (!mkdtemp(g_dir) ||
        nodus_dht_ipc_sock_path(g_dir, g_sock, sizeof(g_sock)) != 0 ||
        nodus_identity_generate(&g_id) != 0) {
        printf("  setup FAILED\n");
        return 1;
    }
    nodus_random(g_token, sizeof(g_token));

    if (open_storage() != 0) {
        printf("  storage setup FAILED\n");
        return 1;
    }
    nodus_dht_ipc_core_t cb;
    core_cb(&cb);
    if (nodus_dht_backend_ipc_open(g_dir, &cb, &B) != 0) {
        printf("  backend setup FAILED\n");
        return 1;
    }

    case_routing_snapshot();
    case_membership();
    case_client_put();
    case_cross_origin();
    case_inter_preface();
    case_udp_relay();
    case_decision32();
    case_control_down();
    case_core_bound();
    case_repush();
    case_origin_gen();
    /* The raw-core cases replace B's control connection (one per storage;
     * the storage side then drops B's sessions as the old core's) — they
     * run after every case that uses B's sessions. */
    case_slot_reuse();
    case_storage_bound();
    case_storage_bound_small();
    case_boot_cancel();
    case_caps();
    case_storage_gate();
    case_marker_rule();

    B->ops->close(B);
    nodus_dht_stop(D);
    nodus_dht_ipc_free(S);
    nodus_dht_close(D);
    free(D);
    nodus_identity_clear(&g_id);

    char cmd[160];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", g_dir);
    if (system(cmd) != 0) { /* best effort */ }

    printf("\n%d passed, %d failed\n", passed, failed);
    return failed ? 1 : 0;
}
