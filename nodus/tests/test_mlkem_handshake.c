/**
 * Nodus — ML-KEM-1024 Handshake Tests (Faz 1 KEM migration)
 *
 * Governing decision: docs/plans/decisions/2026-09-23-kem-mlkem-migration.md
 * (K1-K6) and docs/plans/2026-09-23-mlkem-fips203-migration-design.md §5.8-
 * §5.10 (nodus).
 *
 * Three drives over the REAL handshake handlers (a real nodus_server_t,
 * spawned in a thread, exactly like test_client.c's server_thread):
 *
 *   (a) new client <-> new server (both ML-KEM-capable): the client's
 *       do_auth() picks alg=1 whenever the server's mpk/mpk_sig verify.
 *       Proven two ways: client.has_cached_server_mlkem becomes true only
 *       on that path (nodus_client.c), and an encrypted DHT put+get
 *       roundtrip succeeds end-to-end (a session-key mismatch would fail
 *       AEAD decrypt and the request would time out — so success proves
 *       both sides derived the IDENTICAL key).
 *
 *   (b) legacy-wire client (hand-rolled over nodus_tcp_t + the public
 *       nodus_t2_* encoders, forcing alg=0 and never looking at mpk/
 *       mpk_sig — i.e. exactly what a pre-Faz-1 client's wire traffic
 *       looks like) <-> new server: exercises the REAL
 *       nodus_auth_handle_key_init_alg(...,key_alg=0,...), which delegates
 *       to the UNCHANGED nodus_auth_handle_key_init() (Kyber round-3
 *       decapsulation). Proven the same way as (a): a real ping/pong
 *       roundtrip over the resulting channel.
 *
 *   (c) new client <-> server WITHOUT an ML-KEM keypair
 *       (identity.has_mlkem == false, simulating a not-yet-upgraded node):
 *       AUTH_OK carries no mpk/mpk_sig, so the client's do_auth() never
 *       takes the ML-KEM branch and falls back to Kyber round-3 — proven
 *       by has_cached_server_kyber == true && has_cached_server_mlkem ==
 *       false, plus a put+get roundtrip.
 *
 * Also (N6 "Also:"): nodus_identity_from_seed() ML-KEM determinism, and
 * nodus_identity_load() auto-generating + saving a missing ML-KEM keypair.
 *
 * N1 delta 1 additions (2026-09-23, orchestrator run + verifier + red-team
 * lens C findings):
 *   D1  test_drive_a/b/c/d4/d5's nodus_server_t are `static` (~21 MB each,
 *       far past a stack frame — this is what SIGSEGV'd the first version
 *       of this file).
 *   D2  test_mlkem_bind_strict_no_swap: MLKEM_BIND is strict; a kpk_sig
 *       replayed as mpk_sig, and a raw signature, are both rejected.
 *   D3  test_identity_load_mlkem_partial_regenerates/_pair_present_unchanged:
 *       the atomic write-then-rename helper in nodus_identity.c.
 *   D4  test_d4_inbound_e2e_no_key_refused: an inbound E2E circuit with no
 *       matching local key is refused, never delivered with e2e_active
 *       left false (which the send path would otherwise treat as
 *       "plaintext is fine").
 *   D5  test_d5_mlkem_cache_cleared_on_rollback: a fresh signed kpk-only
 *       AUTH_OK clears a stale cached mlkem pubkey.
 *   D6  (test_tier2.c) alg values other than the literal 1 decode as 0.
 *   D7  test_d7_key_init_mlkem_at_server_without_mlkem_answers: the server
 *       answers with an error frame instead of staying silent.
 *   D10 test_identity_from_seed_derives_mlkem/_mlkem_pk_kat_pin: the
 *       operator-approved SHAKE256 seed derivation (replaces the earlier
 *       HKDF-blocked version of this file).
 *
 * N1 delta 2 additions (2026-09-23, orchestrator run + delta-1 verifier):
 *   E1  test_identity_load_mlkem_pair_mismatch_regenerates: a loaded
 *       mlkem_pk that does not match the ek copy embedded in mlkem_sk
 *       (FIPS 203 dk layout, offset 1536) is treated as absent and
 *       regenerated, never advertised as a signed mpk it cannot
 *       decapsulate.
 */

#include "nodus/nodus.h"
#include "server/nodus_server.h"
#include "transport/nodus_tcp.h"
#include "protocol/nodus_tier2.h"
#include "crypto/nodus_sign.h"
#include "crypto/nodus_identity.h"
#include "crypto/nodus_channel_crypto.h"
#include "crypto/enc/qgp_kyber.h"
#include "crypto/enc/qgp_mlkem.h"
#include "crypto/enc/kem/fips202.h"   /* shake256(): the D10 coins step, re-derived in the KAT */
#include "crypto/hash/qgp_sha3.h"
#include "core/nodus_value.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/stat.h>

extern void qgp_secure_memzero(void *ptr, size_t len);

#define TEST(name) do { printf("  %-70s", name); } while(0)
#define PASS()     do { printf("PASS\n"); passed++; } while(0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while(0)

static int passed = 0;
static int failed = 0;

/* ── Real server harness (mirrors test_client.c's server_thread) ────── */

typedef struct {
    nodus_server_config_t config;
    pthread_t             tid;
    volatile bool         ready;
    bool                  disable_mlkem;
} test_server_ctx_t;

/* Passed by pointer to the thread; bundles the ctx with the caller-owned
 * nodus_server_t (kept `static` inside the test function, per D1 — NOT a
 * stack local: at ~21 MB it would blow a default thread stack; see the
 * D1 note in the file header above and the sizing comment on each drive
 * function's `static nodus_server_t server;`). */
typedef struct {
    test_server_ctx_t *ctx;
    nodus_server_t    *server;
} server_thread_arg_t;

static void *server_thread_fn(void *arg_) {
    server_thread_arg_t *arg = (server_thread_arg_t *)arg_;
    test_server_ctx_t *ctx = arg->ctx;

    char cmd[256];
    snprintf(cmd, sizeof(cmd), "mkdir -p %s", ctx->config.data_path);
    system(cmd);

    if (nodus_server_init(arg->server, &ctx->config) != 0) {
        fprintf(stderr, "test_mlkem_handshake: server init failed\n");
        free(arg);
        return NULL;
    }

    if (ctx->disable_mlkem) {
        /* Drive (c): simulate a pre-Faz-1 server that has an identity but
         * no ML-KEM keypair yet. nodus_server_init() -> nodus_identity_
         * generate() always produces one now (Faz 1) — clear the flag to
         * model a node that has not upgraded. The underlying bytes are
         * left alone; only the "do I have one" flag changes, matching
         * what a real pre-Faz-1 identity.kyber-only file set would load
         * as. */
        arg->server->identity.has_mlkem = false;
    }

    ctx->ready = true;
    nodus_server_run(arg->server);
    nodus_server_close(arg->server);

    snprintf(cmd, sizeof(cmd), "rm -rf %s", ctx->config.data_path);
    system(cmd);
    free(arg);
    return NULL;
}

/* Bounded wait (see test_client.c 2026-07-21 comment): an unbounded
 * `while (!ready)` turns a port-bind race into a silent infinite hang. */
static int start_test_server(test_server_ctx_t *ctx, nodus_server_t *server,
                              uint16_t base_port, bool disable_mlkem) {
    memset(ctx, 0, sizeof(*ctx));
    memset(&ctx->config, 0, sizeof(ctx->config));
    snprintf(ctx->config.bind_ip, sizeof(ctx->config.bind_ip), "127.0.0.1");
    ctx->config.udp_port     = base_port;
    ctx->config.tcp_port     = (uint16_t)(base_port + 1);
    ctx->config.peer_port    = (uint16_t)(base_port + 2);
    ctx->config.ch_port      = (uint16_t)(base_port + 3);
    ctx->config.witness_port = (uint16_t)(base_port + 4);
    snprintf(ctx->config.data_path, sizeof(ctx->config.data_path),
             "/tmp/nodus_mlkem_test_%u_%d", (unsigned)base_port, getpid());
    ctx->disable_mlkem = disable_mlkem;

    server_thread_arg_t *arg = malloc(sizeof(*arg));
    if (!arg) return -1;
    arg->ctx = ctx;
    arg->server = server;

    if (pthread_create(&ctx->tid, NULL, server_thread_fn, arg) != 0) {
        free(arg);
        return -1;
    }

    int waited_ms = 0;
    while (!ctx->ready && waited_ms < 5000) {
        usleep(10000);
        waited_ms += 10;
    }
    return ctx->ready ? 0 : -1;
}

static void stop_test_server(test_server_ctx_t *ctx, nodus_server_t *server) {
    nodus_server_stop(server);
    pthread_join(ctx->tid, NULL);
}

/* ── Drive (a)/(c): real nodus_client_t against a real server ───────── */

static bool run_client_drive(uint16_t server_tcp_port, bool *out_has_mlkem_cache,
                              bool *out_has_kyber_cache) {
    nodus_identity_t client_id;
    nodus_identity_generate(&client_id);

    nodus_client_t client;
    nodus_client_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.servers[0].ip, sizeof(cfg.servers[0].ip), "127.0.0.1");
    cfg.servers[0].port = server_tcp_port;
    cfg.server_count = 1;

    bool ok = (nodus_client_init(&client, &cfg, &client_id) == 0) &&
              (nodus_client_connect(&client) == 0) &&
              nodus_client_is_ready(&client);

    if (out_has_mlkem_cache) *out_has_mlkem_cache = client.has_cached_server_mlkem;
    if (out_has_kyber_cache) *out_has_kyber_cache = client.has_cached_server_kyber;

    if (ok) {
        nodus_key_t key;
        nodus_hash((const uint8_t *)"mlkem-handshake-drive", 21, &key);
        const char *data = "faz-1 kem migration handshake payload";
        nodus_value_t *val = NULL;
        if (nodus_value_create(&key, (const uint8_t *)data, strlen(data),
                                NODUS_VALUE_EPHEMERAL, NODUS_DEFAULT_TTL,
                                1, 0, &client_id.pk, &val) != 0 || !val) {
            ok = false;
        } else {
            nodus_value_sign(val, &client_id.sk);
            ok = (nodus_client_put(&client, &key, (const uint8_t *)data, strlen(data),
                                    NODUS_VALUE_EPHEMERAL, NODUS_DEFAULT_TTL,
                                    1, 0, &val->signature) == 0);
            nodus_value_free(val);
        }

        if (ok) {
            nodus_value_t *got = NULL;
            ok = (nodus_client_get(&client, &key, &got) == 0) && got &&
                 got->data_len == strlen(data) &&
                 memcmp(got->data, data, strlen(data)) == 0;
            if (got) nodus_value_free(got);
        }
    }

    nodus_client_close(&client);
    nodus_identity_clear(&client_id);
    return ok;
}

static void test_drive_a_new_client_new_server(void) {
    TEST("drive (a): new client <-> new server -> alg=1, matching session key");

    test_server_ctx_t sctx;
    /* D1 (N1 delta 1): nodus_server_t is ~21.27 MB (sizeof, measured via
     * `nm -S` on a probe .o — not by running anything), far past the
     * default 8 MB thread stack. It MUST have static or heap storage
     * duration, never a stack local — test_client.c:34 keeps its one
     * server `static` for exactly this reason. A stack local here
     * SIGSEGVs (confirmed by the orchestrator's run, crash at this
     * function). nodus_client_t (run_client_drive() below) is ~36 KB
     * (0.4% of an 8 MB stack) — checked the same way, safe as a local. */
    static nodus_server_t server;
    if (start_test_server(&sctx, &server, 18100, false) != 0) {
        FAIL("server did not come up within 5s");
        return;
    }
    usleep(100000); /* let the server settle, same margin as test_client.c */

    bool has_mlkem_cache = false, has_kyber_cache = false;
    bool ok = run_client_drive(sctx.config.tcp_port, &has_mlkem_cache, &has_kyber_cache);

    /* has_cached_server_mlkem is set ONLY inside the has_mpk branch of
     * nodus_client.c do_auth(), after nodus_verify_mlkem_bind() succeeded
     * and qgp_mlkem1024_encapsulate()+key_ack completed — the direct,
     * inspectable proof that alg=1 was negotiated, not merely "some
     * session key". */
    if (ok && has_mlkem_cache)
        PASS();
    else
        FAIL("ML-KEM handshake did not complete or session key mismatch");

    stop_test_server(&sctx, &server);
}

static void test_drive_c_new_client_server_without_mlkem(void) {
    TEST("drive (c): new client <-> server WITHOUT mlkem -> Kyber fallback");

    test_server_ctx_t sctx;
    /* D1 (N1 delta 1): see the sizing comment on drive (a) above — same
     * fix, static storage duration, not a stack local. */
    static nodus_server_t server;
    if (start_test_server(&sctx, &server, 18120, true /* disable_mlkem */) != 0) {
        FAIL("server did not come up within 5s");
        return;
    }
    usleep(100000);

    bool has_mlkem_cache = false, has_kyber_cache = false;
    bool ok = run_client_drive(sctx.config.tcp_port, &has_mlkem_cache, &has_kyber_cache);

    /* AUTH_OK carried no mpk (server.identity.has_mlkem == false) -> the
     * client must never cache an ML-KEM pubkey, only the Kyber one. */
    if (ok && has_kyber_cache && !has_mlkem_cache)
        PASS();
    else
        FAIL("Kyber fallback handshake failed, or client wrongly cached mlkem");

    stop_test_server(&sctx, &server);
}

/* D4 (N1 delta 1) — an inbound E2E circuit whose alg the local identity
 * cannot decapsulate must be REFUSED, never delivered with e2e_active
 * left false (which the send path treats as "plaintext ok", see the
 * comment in client_on_frame()'s circ_inbound handler). */
static volatile bool g_d4_got_inbound;

static void d4_on_inbound(struct nodus_client *client, const nodus_key_t *peer_fp,
                           nodus_circuit_handle_t *h, void *user) {
    (void)client; (void)peer_fp; (void)h; (void)user;
    g_d4_got_inbound = true;
}

static void test_d4_inbound_e2e_no_key_refused(void) {
    TEST("D4: inbound e2e circuit with no matching key is refused, not plaintext");

    test_server_ctx_t sctx;
    static nodus_server_t server;
    if (start_test_server(&sctx, &server, 18130, false) != 0) {
        FAIL("server did not come up within 5s");
        return;
    }
    usleep(100000);

    /* Client A: identity WITHOUT an ML-KEM key (simulates a client that
     * has not generated one yet — same technique as drive (c)'s server:
     * force the flag false directly after a real generate()). */
    nodus_identity_t id_a;
    nodus_identity_generate(&id_a);
    id_a.has_mlkem = false;

    nodus_client_t client_a;
    nodus_client_config_t cfg_a;
    memset(&cfg_a, 0, sizeof(cfg_a));
    snprintf(cfg_a.servers[0].ip, sizeof(cfg_a.servers[0].ip), "127.0.0.1");
    cfg_a.servers[0].port = sctx.config.tcp_port;
    cfg_a.server_count = 1;

    g_d4_got_inbound = false;

    bool ok = (nodus_client_init(&client_a, &cfg_a, &id_a) == 0) &&
              (nodus_client_connect(&client_a) == 0) &&
              nodus_client_is_ready(&client_a);
    if (ok) nodus_circuit_set_inbound_cb(&client_a, d4_on_inbound, NULL);

    /* Client B: a normal identity, opens an E2E circuit AT A with
     * alg=1 (ML-KEM) even though A never advertised having one — exactly
     * what a misconfigured or malicious peer/relay could send (the
     * server relays "ect"/"alg" opaquely, per the design; it never checks
     * that the target actually has the claimed algorithm). B encapsulates
     * against ITS OWN mlkem_pk (any real ML-KEM key passes
     * qgp_mlkem1024_ek_check — random bytes would not) purely to produce
     * a well-formed 1568-byte ciphertext; A never attempts to decapsulate
     * it at all in the fixed code path (it fails on the has_mlkem check
     * first), so which bytes are in the ciphertext is irrelevant here. */
    nodus_identity_t id_b;
    nodus_identity_generate(&id_b);

    nodus_client_t client_b;
    nodus_client_config_t cfg_b;
    memset(&cfg_b, 0, sizeof(cfg_b));
    snprintf(cfg_b.servers[0].ip, sizeof(cfg_b.servers[0].ip), "127.0.0.1");
    cfg_b.servers[0].port = sctx.config.tcp_port;
    cfg_b.server_count = 1;

    ok = ok && (nodus_client_init(&client_b, &cfg_b, &id_b) == 0) &&
              (nodus_client_connect(&client_b) == 0) &&
              nodus_client_is_ready(&client_b);

    nodus_circuit_handle_t *out = NULL;
    if (ok) {
        /* Return value deliberately ignored: whether B's OWN view of the
         * open succeeded or failed is not what this test is about — only
         * what A did with the resulting circ_inbound matters. */
        nodus_circuit_open_e2e_alg(&client_b, &id_a.node_id, id_b.mlkem_pk, 1,
                                    NULL, NULL, NULL, &out);
    }

    /* Give A's background read thread time to process the circ_inbound
     * push and (if the fix is broken) call d4_on_inbound. */
    usleep(300000);

    bool a_accepted_no_circuit = true;
    for (int i = 0; i < NODUS_CLIENT_MAX_CIRCUITS; i++) {
        if (client_a.circuits[i].in_use) {
            a_accepted_no_circuit = false;
            break;
        }
    }

    if (ok && !g_d4_got_inbound && a_accepted_no_circuit) {
        PASS();
    } else {
        FAIL("client accepted an E2E circuit it cannot decapsulate");
    }

    if (out) nodus_circuit_close(out);
    nodus_client_close(&client_b);
    nodus_client_close(&client_a);
    nodus_identity_clear(&id_a);
    nodus_identity_clear(&id_b);
    stop_test_server(&sctx, &server);
}

/* D5 (N1 delta 1) — cache hygiene: a fresh, signed, kpk-only AUTH_OK
 * (server has no mpk) must clear a STALE cached mlkem pubkey from a
 * previous session (server rollback, or failover to a different cluster
 * server that hasn't generated an ML-KEM key yet). */
static void test_d5_mlkem_cache_cleared_on_rollback(void) {
    TEST("D5: fresh signed kpk-only AUTH_OK clears a stale mlkem cache");

    test_server_ctx_t sctx_a, sctx_b;
    static nodus_server_t server_a, server_b;
    if (start_test_server(&sctx_a, &server_a, 18140, false) != 0) {
        FAIL("server A did not come up within 5s");
        return;
    }
    if (start_test_server(&sctx_b, &server_b, 18150, true /* disable_mlkem */) != 0) {
        FAIL("server B did not come up within 5s");
        stop_test_server(&sctx_a, &server_a);
        return;
    }
    usleep(100000);

    nodus_identity_t id;
    nodus_identity_generate(&id);

    nodus_client_t client;
    nodus_client_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.servers[0].ip, sizeof(cfg.servers[0].ip), "127.0.0.1");
    cfg.servers[0].port = sctx_a.config.tcp_port;
    cfg.server_count = 1;

    bool ok = (nodus_client_init(&client, &cfg, &id) == 0) &&
              (nodus_client_connect(&client) == 0) &&
              nodus_client_is_ready(&client);

    /* First connect to server A (mlkem-capable) -> cache set. */
    ok = ok && client.has_cached_server_mlkem;

    /* Reconnect the SAME client struct to server B (mlkem DISABLED), using
     * nodus_client_force_disconnect() + a second nodus_client_connect()
     * call -- NOT the SDK's own auto_reconnect path (this client has
     * auto_reconnect left false; force_disconnect is documented as a
     * teardown helper "before joining threads that may be blocked", used
     * here only to drive do_auth() a second time on purpose). Verified by
     * reading: force_disconnect() (nodus_client.c) stops the read thread,
     * closes the fd, sets conn=NULL/state=DISCONNECTED, but does NOT
     * touch has_cached_server_mlkem, the identity, or the mutexes (unlike
     * nodus_client_close(), which destroys the mutexes and clears the
     * identity) -- and nodus_client_connect() -> do_connect_one() runs
     * do_auth() SYNCHRONOUSLY, starting a fresh read thread (which resets
     * read_thread_stop to false, start_read_thread()) only AFTER do_auth()
     * already succeeded. So this exercises do_auth() fresh, with a stale
     * cache still set, pointed at a server that will never send mpk. */
    if (ok) {
        nodus_client_force_disconnect(&client);
        client.config.servers[0].port = sctx_b.config.tcp_port;
        ok = (nodus_client_connect(&client) == 0) && nodus_client_is_ready(&client);
    }

    /* D5: server B's fresh, signed AUTH_OK carried kpk but no mpk -> the
     * stale cache from server A must be cleared, not silently reused. */
    if (ok)
        ok = client.has_cached_server_kyber && !client.has_cached_server_mlkem;

    if (ok) PASS(); else FAIL("stale mlkem cache survived a fresh kpk-only AUTH_OK");

    nodus_client_close(&client);
    nodus_identity_clear(&id);
    stop_test_server(&sctx_a, &server_a);
    stop_test_server(&sctx_b, &server_b);
}

/* ── Drive (b): hand-rolled legacy-wire client (real transport, real
 * server, manual protocol driving — see the file header for why this
 * exists instead of the public nodus_client_t API). ────────────────── */

typedef struct {
    nodus_tier2_msg_t msg;
    bool              got;
} manual_rx_t;

static manual_rx_t g_manual_rx;

static void manual_on_frame(nodus_tcp_conn_t *conn, const uint8_t *payload,
                             size_t len, void *ctx) {
    (void)conn; (void)ctx;
    nodus_t2_msg_free(&g_manual_rx.msg);
    memset(&g_manual_rx.msg, 0, sizeof(g_manual_rx.msg));
    if (nodus_t2_decode(payload, len, &g_manual_rx.msg) == 0)
        g_manual_rx.got = true;
}

static bool manual_wait(nodus_tcp_t *tcp, int timeout_ms) {
    g_manual_rx.got = false;
    for (int elapsed = 0; elapsed < timeout_ms; elapsed += 20) {
        nodus_tcp_poll(tcp, 20);
        if (g_manual_rx.got) return true;
    }
    return false;
}

static void test_drive_b_legacy_client_new_server(void) {
    TEST("drive (b): legacy-wire client (alg=0) <-> new server -> round-3 decap");

    test_server_ctx_t sctx;
    /* D1 (N1 delta 1): see the sizing comment on drive (a) above — same
     * fix, static storage duration, not a stack local. */
    static nodus_server_t server;
    if (start_test_server(&sctx, &server, 18110, false) != 0) {
        FAIL("server did not come up within 5s");
        return;
    }
    usleep(100000);

    nodus_identity_t old_id;
    nodus_identity_generate(&old_id);

    nodus_tcp_t tcp;
    nodus_tcp_init(&tcp, -1);
    tcp.on_frame = manual_on_frame;
    memset(&g_manual_rx, 0, sizeof(g_manual_rx));

    nodus_tcp_conn_t *conn = nodus_tcp_connect(&tcp, "127.0.0.1", sctx.config.tcp_port);
    for (int i = 0; i < 200 && (!conn || conn->state != NODUS_CONN_CONNECTED); i++)
        nodus_tcp_poll(&tcp, 10);

    bool ok = (conn != NULL && conn->state == NODUS_CONN_CONNECTED);
    if (!ok) FAIL("TCP connect failed");

    uint8_t buf[16384];
    size_t len = 0;

    /* HELLO -> CHALLENGE */
    if (ok) {
        nodus_t2_hello(1, &old_id.pk, &old_id.node_id, buf, sizeof(buf), &len);
        nodus_tcp_send(conn, buf, len);
        ok = manual_wait(&tcp, 3000) &&
             strcmp(g_manual_rx.msg.method, "challenge") == 0;
        if (!ok) FAIL("no challenge response");
    }

    /* Sign nonce, send AUTH -> AUTH_OK. An old client never looks at
     * mpk/mpk_sig even if the (new, ML-KEM-capable) server included them —
     * it only reads kyber_pk/kpk_sig, exactly like a shipped pre-Faz-1
     * binary would. */
    uint8_t token[NODUS_SESSION_TOKEN_LEN];
    uint8_t server_kyber_pk[NODUS_KYBER_PK_BYTES];
    if (ok) {
        uint8_t nonce[NODUS_NONCE_LEN];
        memcpy(nonce, g_manual_rx.msg.nonce, NODUS_NONCE_LEN);
        nodus_sig_t sig;
        nodus_sign_auth_challenge(&sig, nonce, &old_id.sk);
        len = 0;
        nodus_t2_auth(2, &sig, buf, sizeof(buf), &len);
        nodus_tcp_send(conn, buf, len);
        ok = manual_wait(&tcp, 3000) &&
             strcmp(g_manual_rx.msg.method, "auth_ok") == 0 &&
             g_manual_rx.msg.has_kyber_pk;
        if (!ok) {
            FAIL("no auth_ok / no kyber_pk");
        } else {
            memcpy(token, g_manual_rx.msg.token, NODUS_SESSION_TOKEN_LEN);
            memcpy(server_kyber_pk, g_manual_rx.msg.kyber_pk, NODUS_KYBER_PK_BYTES);
        }
    }

    /* Encapsulate against the server's Kyber pk ONLY (ignore mlkem_pk even
     * if present), send KEY_INIT with alg=0 explicit — this is the exact
     * frame a pre-Faz-1 client emits, byte-identical per
     * test_key_init_legacy_byte_identical (test_tier2.c). */
    if (ok) {
        uint8_t ct[NODUS_KYBER_CT_BYTES], ss[NODUS_KYBER_SS_BYTES];
        ok = (qgp_kem1024_encapsulate(ct, ss, server_kyber_pk) == 0);
        if (!ok) {
            FAIL("Kyber encapsulate failed");
        } else {
            uint8_t nc[NODUS_NONCE_LEN];
            nodus_random(nc, NODUS_NONCE_LEN);
            len = 0;
            nodus_t2_key_init(3, ct, nc, 0, buf, sizeof(buf), &len);
            nodus_tcp_send(conn, buf, len);
            ok = manual_wait(&tcp, 3000) &&
                 strcmp(g_manual_rx.msg.method, "key_ack") == 0 &&
                 g_manual_rx.msg.has_key_nonce;
            if (!ok) {
                FAIL("no key_ack");
            } else {
                /* nodus_tcp_send/recv auto-encrypt/decrypt via
                 * conn->channel_crypto once established (nodus_tcp.c) —
                 * setting this up is all a manual client needs to do. */
                ok = (nodus_channel_crypto_init(&conn->channel_crypto, ss, nc,
                                                 g_manual_rx.msg.key_nonce,
                                                 NODUS_CHANNEL_ROLE_INITIATOR) == 0);
                if (!ok) FAIL("channel crypto init failed");
            }
            qgp_secure_memzero(ss, sizeof(ss));
        }
    }

    /* Prove the round-3 session actually works end to end: an
     * authenticated, encrypted ping/pong round trip. This exercises the
     * REAL nodus_auth_handle_key_init_alg(...,key_alg=0,...) ->
     * nodus_auth_handle_key_init() delegation on the server side. */
    if (ok) {
        len = 0;
        nodus_t2_ping(4, token, buf, sizeof(buf), &len);
        nodus_tcp_send(conn, buf, len);
        ok = manual_wait(&tcp, 3000) && strcmp(g_manual_rx.msg.method, "pong") == 0;
        if (!ok) FAIL("no pong over the round-3 encrypted channel");
    }

    if (ok) PASS();

    nodus_t2_msg_free(&g_manual_rx.msg);
    nodus_tcp_close(&tcp);
    nodus_identity_clear(&old_id);
    stop_test_server(&sctx, &server);
}

/* D7 (N1 delta 1) — answer, don't hang: KEY_INIT alg=1 at a server with no
 * ML-KEM keypair must get an error frame promptly, not the silence that
 * left a sender waiting out its connect_timeout. Reuses drive (b)'s
 * manual-wire helpers (manual_on_frame/manual_wait/g_manual_rx) above. */
static void test_d7_key_init_mlkem_at_server_without_mlkem_answers(void) {
    TEST("D7: KEY_INIT alg=1 at a server without mlkem answers, doesn't hang");

    test_server_ctx_t sctx;
    static nodus_server_t server;
    if (start_test_server(&sctx, &server, 18160, true /* disable_mlkem */) != 0) {
        FAIL("server did not come up within 5s");
        return;
    }
    usleep(100000);

    nodus_identity_t id;
    nodus_identity_generate(&id);

    nodus_tcp_t tcp;
    nodus_tcp_init(&tcp, -1);
    tcp.on_frame = manual_on_frame;
    memset(&g_manual_rx, 0, sizeof(g_manual_rx));

    nodus_tcp_conn_t *conn = nodus_tcp_connect(&tcp, "127.0.0.1", sctx.config.tcp_port);
    for (int i = 0; i < 200 && (!conn || conn->state != NODUS_CONN_CONNECTED); i++)
        nodus_tcp_poll(&tcp, 10);

    bool ok = (conn != NULL && conn->state == NODUS_CONN_CONNECTED);
    if (!ok) FAIL("TCP connect failed");

    uint8_t buf[16384];
    size_t len = 0;

    if (ok) {
        nodus_t2_hello(1, &id.pk, &id.node_id, buf, sizeof(buf), &len);
        nodus_tcp_send(conn, buf, len);
        ok = manual_wait(&tcp, 3000) && strcmp(g_manual_rx.msg.method, "challenge") == 0;
        if (!ok) FAIL("no challenge response");
    }

    if (ok) {
        uint8_t nonce[NODUS_NONCE_LEN];
        memcpy(nonce, g_manual_rx.msg.nonce, NODUS_NONCE_LEN);
        nodus_sig_t sig;
        nodus_sign_auth_challenge(&sig, nonce, &id.sk);
        len = 0;
        nodus_t2_auth(2, &sig, buf, sizeof(buf), &len);
        nodus_tcp_send(conn, buf, len);
        ok = manual_wait(&tcp, 3000) && strcmp(g_manual_rx.msg.method, "auth_ok") == 0;
        if (!ok) FAIL("no auth_ok");
    }

    /* Deliberately send KEY_INIT alg=1 even though this server has no
     * ML-KEM keypair (disable_mlkem=true) -- an attacker or a
     * misconfigured client could do this. The ciphertext bytes are
     * irrelevant: D7's fix answers BEFORE ever touching them. */
    if (ok) {
        uint8_t ct[NODUS_MLKEM_CT_BYTES];
        memset(ct, 0xEF, sizeof(ct));
        uint8_t nc[NODUS_NONCE_LEN];
        nodus_random(nc, NODUS_NONCE_LEN);
        len = 0;
        nodus_t2_key_init(3, ct, nc, 1, buf, sizeof(buf), &len);
        nodus_tcp_send(conn, buf, len);
        /* The whole point of D7: this must come back promptly, not after
         * a full connect_timeout worth of silence. */
        ok = manual_wait(&tcp, 3000) && g_manual_rx.msg.type == 'e' &&
             g_manual_rx.msg.error_code == NODUS_ERR_PROTOCOL_ERROR;
        if (!ok) FAIL("server stayed silent instead of answering with an error");
    }

    if (ok) PASS();

    nodus_t2_msg_free(&g_manual_rx.msg);
    nodus_tcp_close(&tcp);
    nodus_identity_clear(&id);
    stop_test_server(&sctx, &server);
}

/* ── Identity determinism / migration (N6 "Also:") ───────────────────── */

/* D10 (N1 delta 1, operator decision 2026-09-23): nodus_identity_from_seed()
 * now derives a real ML-KEM-1024 keypair via SHAKE256 (the messenger's
 * seed_derivation.c shape), not HKDF — see the comment at that function.
 * This is the ORIGINAL N6 assertion the HKDF blocker had prevented:
 * determinism (same seed twice -> byte-identical keys), has_mlkem == true,
 * and the ML-KEM key is NOT the Kyber key (independent derivation, not the
 * same seed accidentally reused across two different KEMs). */
static void test_identity_from_seed_derives_mlkem(void) {
    TEST("identity from seed twice: mlkem derived, deterministic, != kyber key");

    uint8_t seed[32];
    memset(seed, 0x5C, sizeof(seed));

    nodus_identity_t id1, id2;
    int rc1 = nodus_identity_from_seed(seed, &id1);
    int rc2 = nodus_identity_from_seed(seed, &id2);

    bool ok = (rc1 == 0) && (rc2 == 0) &&
              id1.has_mlkem && id2.has_mlkem &&
              memcmp(id1.mlkem_pk, id2.mlkem_pk, NODUS_MLKEM_PK_BYTES) == 0 &&
              memcmp(id1.mlkem_sk, id2.mlkem_sk, NODUS_MLKEM_SK_BYTES) == 0 &&
              /* Independent derivation, not an accidental alias: the
               * ML-KEM pk must differ from the Kyber round-3 pk even
               * though both come from the same 32-byte seed (different
               * HKDF/SHAKE context strings, F1-F6 different core). */
              memcmp(id1.mlkem_pk, id1.kyber_pk, NODUS_MLKEM_PK_BYTES) != 0;

    if (ok) PASS(); else FAIL("mlkem key not derived, not deterministic, or aliases kyber key");

    nodus_identity_clear(&id1);
    nodus_identity_clear(&id2);
}

/* D10 fixed-seed KAT for the seed-derived ML-KEM-1024 identity key,
 * seed = 32 x 0x01. Three legs, each labelled by what grounds it
 * (ANA HEDEF: KAFADAN KRİPTO YASAK — nothing here is a self-approved
 * "plausible" number):
 *
 *   (1) COINS — GROUNDED, INDEPENDENT ORACLE. The derivation is
 *       coins[64] = SHAKE256(seed[32] || "nodus-mlkem-1024", 64) (decision
 *       file K3, docs/plans/decisions/2026-09-23-kem-mlkem-migration.md;
 *       nodus_identity.c nodus_identity_from_seed). EXPECTED_COINS below was
 *       computed OUTSIDE this tree with Python's hashlib.shake_256 (an
 *       independent SHAKE256 implementation), 2026-09-23:
 *         python3 -c "import hashlib; print(hashlib.shake_256(b'\x01'*32 +
 *                     b'nodus-mlkem-1024').hexdigest(64))"
 *       The test recomputes the coins with the tree's shake256() and
 *       compares — proving the tree's SHAKE256 and the exact preimage
 *       layout (seed first, then the 16 ASCII bytes, no NUL).
 *   (2) STRUCTURE — PROVEN BY CONSTRUCTION. qgp_mlkem1024_keypair_derand()
 *       over those coins must yield exactly the identity's mlkem_pk/mlkem_sk,
 *       proving nodus_identity_from_seed() feeds THESE coins (and nothing
 *       else — no extra hashing, no truncation) into the ACVP-verified
 *       keygen (messenger/tests/test_mlkem1024.c, NIST ACVP FIPS 203 final).
 *   (3) REGRESSION SENTINEL — SELF-CONSISTENT, labelled as such. The
 *       SHA3-256 of mlkem_pk is pinned to the value this tree produced on
 *       2026-09-23 (first run, ORCHESTRATOR). It is NOT an external ML-KEM
 *       vector; it exists so a silent change to any step above (context
 *       string, byte order, KEM implementation) fails loudly. Legs (1) and
 *       (2) are what make a change here diagnosable rather than mysterious. */
static void test_identity_from_seed_mlkem_pk_kat_pin(void) {
    TEST("identity from seed=32x0x01: ML-KEM coins (Python SHAKE256 oracle) + keypair_derand equality + pk SHA3-256 sentinel");

    /* Leg (1): independent oracle — hashlib.shake_256, see the comment. */
    static const uint8_t EXPECTED_COINS[64] = {
        0x20,0x47,0xe0,0xcf,0x1e,0x4f,0x1c,0xc9,0x2e,0xb9,0x88,0x8d,0x24,0x71,0x0e,0x23,
        0xd2,0x2c,0xd4,0x15,0xce,0xf2,0xb6,0xd1,0xf2,0x52,0xbd,0x30,0x43,0x9f,0x80,0x11,
        0x6f,0x26,0xd6,0x5a,0x05,0x4f,0xb4,0x2a,0x82,0x3f,0x3c,0x21,0xbe,0x1e,0x79,0x2a,
        0xb9,0xf7,0x5c,0x07,0x98,0x45,0x4b,0x08,0x73,0x43,0xa9,0x7f,0xf4,0x1e,0xf6,0xd8,
    };
    /* Leg (3): this tree's own value, first run 2026-09-23 — a sentinel. */
    static const uint8_t EXPECTED_PK_SHA3_256[32] = {
        0x7f,0x57,0xd8,0x80,0xc4,0x9a,0xb5,0xa7,0xd1,0x26,0xe7,0xe5,0x27,0x7c,0xab,0x97,
        0x80,0x3b,0xc6,0x33,0x46,0xab,0xf3,0x98,0x79,0x10,0x8c,0x75,0x2e,0x53,0x35,0xc3,
    };

    uint8_t seed[32];
    memset(seed, 0x01, sizeof(seed));

    /* Leg (1): recompute the coins with the tree's SHAKE256 over the exact
     * preimage the identity code uses (seed || 16 ASCII bytes, no NUL). */
    static const uint8_t ctx[] = "nodus-mlkem-1024";
    uint8_t preimage[32 + sizeof(ctx) - 1];
    memcpy(preimage, seed, 32);
    memcpy(preimage + 32, ctx, sizeof(ctx) - 1);
    uint8_t coins[64];
    shake256(coins, sizeof(coins), preimage, sizeof(preimage));
    if (memcmp(coins, EXPECTED_COINS, sizeof(coins)) != 0) {
        FAIL("leg 1: tree SHAKE256(seed || \"nodus-mlkem-1024\") != Python hashlib.shake_256 oracle");
        return;
    }

    nodus_identity_t id;
    int rc = nodus_identity_from_seed(seed, &id);
    if (rc != 0 || !id.has_mlkem) {
        FAIL("nodus_identity_from_seed failed or has_mlkem == false");
        return;
    }

    /* Leg (2): the identity's key pair IS keypair_derand(coins). */
    uint8_t pk2[NODUS_MLKEM_PK_BYTES], sk2[NODUS_MLKEM_SK_BYTES];
    if (qgp_mlkem1024_keypair_derand(pk2, sk2, coins) != 0) {
        FAIL("leg 2: qgp_mlkem1024_keypair_derand failed");
        nodus_identity_clear(&id);
        return;
    }
    if (memcmp(pk2, id.mlkem_pk, NODUS_MLKEM_PK_BYTES) != 0 ||
        memcmp(sk2, id.mlkem_sk, NODUS_MLKEM_SK_BYTES) != 0) {
        FAIL("leg 2: identity mlkem key pair != keypair_derand(coins)");
        qgp_secure_memzero(sk2, sizeof(sk2));
        nodus_identity_clear(&id);
        return;
    }
    qgp_secure_memzero(sk2, sizeof(sk2));

    /* Leg (3): the regression sentinel. */
    uint8_t digest[32];
    bool ok = (qgp_sha3_256(id.mlkem_pk, NODUS_MLKEM_PK_BYTES, digest) == 0);
    if (ok) {
        char digest_hex[65];
        for (int i = 0; i < 32; i++)
            snprintf(digest_hex + i * 2, 3, "%02x", digest[i]);
        printf("computed=%s ", digest_hex);
        ok = (memcmp(digest, EXPECTED_PK_SHA3_256, sizeof(EXPECTED_PK_SHA3_256)) == 0);
    }

    if (ok) {
        PASS();
    } else {
        FAIL("leg 3: pk SHA3-256 sentinel mismatch — legs 1 and 2 passed, so the "
             "KEM implementation itself changed; re-derive on purpose or find out why");
    }

    nodus_identity_clear(&id);
}

static void test_identity_load_generates_missing_mlkem(void) {
    TEST("identity load without mlkem files: generated and saved");

    /* D1 (N1 delta 1): unique per pid so a parallel ctest run (or a stale
     * leftover from a killed prior run) never collides on this path. */
    char tmpdir[256];
    snprintf(tmpdir, sizeof(tmpdir), "/tmp/nodus_test_mlkem_identity_%d", getpid());
    mkdir(tmpdir, 0700);

    nodus_identity_t id_orig;
    nodus_identity_generate(&id_orig); /* has_mlkem = true */
    int rc = nodus_identity_save(&id_orig, tmpdir);
    if (rc != 0) {
        FAIL("save failed");
        nodus_identity_clear(&id_orig);
        rmdir(tmpdir);
        return;
    }

    /* Simulate a pre-Faz-1 identity directory: remove the mlkem files
     * only, keep pk/sk/fp/kyber_pk/kyber_sk. */
    char path[256];
    snprintf(path, sizeof(path), "%s/nodus.mlkem_pk", tmpdir); remove(path);
    snprintf(path, sizeof(path), "%s/nodus.mlkem_sk", tmpdir); remove(path);

    nodus_identity_t id_loaded;
    rc = nodus_identity_load(tmpdir, &id_loaded);

    bool ok = (rc == 0) && id_loaded.has_mlkem;

    /* "and saved": the missing files must now exist on disk, right sizes. */
    if (ok) {
        struct stat st;
        snprintf(path, sizeof(path), "%s/nodus.mlkem_pk", tmpdir);
        ok = ok && (stat(path, &st) == 0) && ((size_t)st.st_size == NODUS_MLKEM_PK_BYTES);
        snprintf(path, sizeof(path), "%s/nodus.mlkem_sk", tmpdir);
        ok = ok && (stat(path, &st) == 0) && ((size_t)st.st_size == NODUS_MLKEM_SK_BYTES);
    }

    if (ok) PASS(); else FAIL("mlkem keypair not regenerated/saved on load");

    snprintf(path, sizeof(path), "%s/nodus.pk", tmpdir); remove(path);
    snprintf(path, sizeof(path), "%s/nodus.sk", tmpdir); remove(path);
    snprintf(path, sizeof(path), "%s/nodus.fp", tmpdir); remove(path);
    snprintf(path, sizeof(path), "%s/nodus.kyber_pk", tmpdir); remove(path);
    snprintf(path, sizeof(path), "%s/nodus.kyber_sk", tmpdir); remove(path);
    snprintf(path, sizeof(path), "%s/nodus.mlkem_pk", tmpdir); remove(path);
    snprintf(path, sizeof(path), "%s/nodus.mlkem_sk", tmpdir); remove(path);
    rmdir(tmpdir);

    nodus_identity_clear(&id_orig);
    nodus_identity_clear(&id_loaded);
}

/* D3 (N1 delta 1): pk present, sk missing (a partial file set — exactly
 * what the OLD non-atomic nodus_identity_save() could leave behind on a
 * crash mid-write) -> regenerated (a FRESH keypair, not a half-read of
 * the old one) and BOTH files rewritten via identity_write_file_atomic(),
 * with no leftover .tmp files. */
static void test_identity_load_mlkem_partial_regenerates(void) {
    TEST("identity load: mlkem pk present, sk missing -> regenerated, both written");

    char tmpdir[256];
    snprintf(tmpdir, sizeof(tmpdir), "/tmp/nodus_test_mlkem_partial_%d", getpid());
    mkdir(tmpdir, 0700);

    nodus_identity_t id_orig;
    nodus_identity_generate(&id_orig);
    int rc = nodus_identity_save(&id_orig, tmpdir);
    if (rc != 0) {
        FAIL("save failed");
        nodus_identity_clear(&id_orig);
        rmdir(tmpdir);
        return;
    }

    char path[256];
    snprintf(path, sizeof(path), "%s/nodus.mlkem_sk", tmpdir);
    remove(path);

    nodus_identity_t id_loaded;
    rc = nodus_identity_load(tmpdir, &id_loaded);

    bool ok = (rc == 0) && id_loaded.has_mlkem;
    /* Regenerated, not half-read: the loaded pk must NOT match the
     * original (a fresh random keypair was generated). */
    if (ok)
        ok = memcmp(id_loaded.mlkem_pk, id_orig.mlkem_pk, NODUS_MLKEM_PK_BYTES) != 0;

    if (ok) {
        struct stat st;
        snprintf(path, sizeof(path), "%s/nodus.mlkem_pk", tmpdir);
        ok = ok && (stat(path, &st) == 0) && ((size_t)st.st_size == NODUS_MLKEM_PK_BYTES);
        snprintf(path, sizeof(path), "%s/nodus.mlkem_sk", tmpdir);
        ok = ok && (stat(path, &st) == 0) && ((size_t)st.st_size == NODUS_MLKEM_SK_BYTES);
        /* identity_write_file_atomic() must never leave its ".tmp" behind
         * on the success path (rename consumes it). */
        snprintf(path, sizeof(path), "%s/nodus.mlkem_pk.tmp", tmpdir);
        ok = ok && (stat(path, &st) != 0);
        snprintf(path, sizeof(path), "%s/nodus.mlkem_sk.tmp", tmpdir);
        ok = ok && (stat(path, &st) != 0);
    }

    if (ok) PASS(); else FAIL("partial mlkem file set not regenerated/rewritten correctly");

    snprintf(path, sizeof(path), "%s/nodus.pk", tmpdir); remove(path);
    snprintf(path, sizeof(path), "%s/nodus.sk", tmpdir); remove(path);
    snprintf(path, sizeof(path), "%s/nodus.fp", tmpdir); remove(path);
    snprintf(path, sizeof(path), "%s/nodus.kyber_pk", tmpdir); remove(path);
    snprintf(path, sizeof(path), "%s/nodus.kyber_sk", tmpdir); remove(path);
    snprintf(path, sizeof(path), "%s/nodus.mlkem_pk", tmpdir); remove(path);
    snprintf(path, sizeof(path), "%s/nodus.mlkem_sk", tmpdir); remove(path);
    rmdir(tmpdir);

    nodus_identity_clear(&id_orig);
    nodus_identity_clear(&id_loaded);
}

/* D3 (N1 delta 1): the pair present -> load() must be read-only for the
 * ML-KEM files (no unnecessary rewrite), bytes equal to what was saved. */
static void test_identity_load_mlkem_pair_present_unchanged(void) {
    TEST("identity load: mlkem pk+sk pair present -> loaded unchanged (bytes equal)");

    char tmpdir[256];
    snprintf(tmpdir, sizeof(tmpdir), "/tmp/nodus_test_mlkem_pair_%d", getpid());
    mkdir(tmpdir, 0700);

    nodus_identity_t id_orig;
    nodus_identity_generate(&id_orig);
    int rc = nodus_identity_save(&id_orig, tmpdir);
    if (rc != 0) {
        FAIL("save failed");
        nodus_identity_clear(&id_orig);
        rmdir(tmpdir);
        return;
    }

    nodus_identity_t id_loaded;
    rc = nodus_identity_load(tmpdir, &id_loaded);

    bool ok = (rc == 0) && id_loaded.has_mlkem &&
        memcmp(id_orig.mlkem_pk, id_loaded.mlkem_pk, NODUS_MLKEM_PK_BYTES) == 0 &&
        memcmp(id_orig.mlkem_sk, id_loaded.mlkem_sk, NODUS_MLKEM_SK_BYTES) == 0;

    if (ok) PASS(); else FAIL("mlkem pair present but load() changed the bytes");

    char path[256];
    snprintf(path, sizeof(path), "%s/nodus.pk", tmpdir); remove(path);
    snprintf(path, sizeof(path), "%s/nodus.sk", tmpdir); remove(path);
    snprintf(path, sizeof(path), "%s/nodus.fp", tmpdir); remove(path);
    snprintf(path, sizeof(path), "%s/nodus.kyber_pk", tmpdir); remove(path);
    snprintf(path, sizeof(path), "%s/nodus.kyber_sk", tmpdir); remove(path);
    snprintf(path, sizeof(path), "%s/nodus.mlkem_pk", tmpdir); remove(path);
    snprintf(path, sizeof(path), "%s/nodus.mlkem_sk", tmpdir); remove(path);
    rmdir(tmpdir);

    nodus_identity_clear(&id_orig);
    nodus_identity_clear(&id_loaded);
}

/* E1 (N1 delta 2, verifier LOW/real): nodus_identity_load() must not trust
 * a pk/sk pair whose files simply both happened to read fully — they must
 * belong to the SAME keypair. identity_write_file_atomic() renames
 * nodus.mlkem_pk and nodus.mlkem_sk in two SEPARATE open+write+rename
 * sequences, so two crashes on the same node (each mid-rename on a
 * DIFFERENT one of the two files) could leave a pk from one generation
 * next to an sk from another. See the memcmp(mlkem_pk, mlkem_sk+1536,...)
 * check added to nodus_identity_load() (nodus_identity.c) for the FIPS
 * 203 layout citation. */
static void test_identity_load_mlkem_pair_mismatch_regenerates(void) {
    TEST("identity load: mismatched mlkem pk/sk pair -> regenerated (E1)");

    char tmpdir[256];
    snprintf(tmpdir, sizeof(tmpdir), "/tmp/nodus_test_mlkem_mismatch_%d", getpid());
    mkdir(tmpdir, 0700);

    nodus_identity_t id_a, id_b;
    nodus_identity_generate(&id_a);
    nodus_identity_generate(&id_b);   /* a DIFFERENT valid ML-KEM-1024 keypair */

    int rc = nodus_identity_save(&id_a, tmpdir);
    if (rc != 0) {
        FAIL("save failed");
        nodus_identity_clear(&id_a);
        nodus_identity_clear(&id_b);
        rmdir(tmpdir);
        return;
    }

    /* Overwrite nodus.mlkem_pk with id_b's pk -- a DIFFERENT valid
     * ML-KEM-1024 public key, simulating the file-pair-mismatch window
     * E1 closes. Written directly (not through the production atomic
     * helper, which is static to nodus_identity.c and not exported --
     * this only needs to set up the on-disk mismatch, not exercise the
     * writer). */
    char pk_path[256];
    snprintf(pk_path, sizeof(pk_path), "%s/nodus.mlkem_pk", tmpdir);
    FILE *f = fopen(pk_path, "wb");
    bool wrote = f && (fwrite(id_b.mlkem_pk, 1, NODUS_MLKEM_PK_BYTES, f) == NODUS_MLKEM_PK_BYTES);
    if (f) fclose(f);

    nodus_identity_t id_loaded;
    memset(&id_loaded, 0, sizeof(id_loaded));
    bool ok = wrote;
    if (ok) {
        rc = nodus_identity_load(tmpdir, &id_loaded);
        ok = (rc == 0) && id_loaded.has_mlkem;
    }

    /* Regenerated -- must be neither id_a's nor id_b's mlkem_pk (a FRESH
     * random keypair), and internally consistent (pk == sk's embedded ek
     * copy at offset 1536 -- the exact check E1 added). */
    if (ok) {
        ok = memcmp(id_loaded.mlkem_pk, id_a.mlkem_pk, NODUS_MLKEM_PK_BYTES) != 0 &&
             memcmp(id_loaded.mlkem_pk, id_b.mlkem_pk, NODUS_MLKEM_PK_BYTES) != 0 &&
             memcmp(id_loaded.mlkem_pk, id_loaded.mlkem_sk + 1536,
                    NODUS_MLKEM_PK_BYTES) == 0;
    }

    /* Both files on disk changed too (regenerated + rewritten, not left
     * as the mismatched pair). */
    if (ok) {
        uint8_t disk_pk[NODUS_MLKEM_PK_BYTES];
        FILE *rf = fopen(pk_path, "rb");
        bool read_ok = rf && (fread(disk_pk, 1, sizeof(disk_pk), rf) == sizeof(disk_pk));
        if (rf) fclose(rf);
        ok = read_ok && (memcmp(disk_pk, id_b.mlkem_pk, NODUS_MLKEM_PK_BYTES) != 0);
    }

    if (ok) PASS(); else FAIL("mismatched mlkem pk/sk pair was not detected/regenerated");

    char path[256];
    snprintf(path, sizeof(path), "%s/nodus.pk", tmpdir); remove(path);
    snprintf(path, sizeof(path), "%s/nodus.sk", tmpdir); remove(path);
    snprintf(path, sizeof(path), "%s/nodus.fp", tmpdir); remove(path);
    snprintf(path, sizeof(path), "%s/nodus.kyber_pk", tmpdir); remove(path);
    snprintf(path, sizeof(path), "%s/nodus.kyber_sk", tmpdir); remove(path);
    snprintf(path, sizeof(path), "%s/nodus.mlkem_pk", tmpdir); remove(path);
    snprintf(path, sizeof(path), "%s/nodus.mlkem_sk", tmpdir); remove(path);
    rmdir(tmpdir);

    nodus_identity_clear(&id_a);
    nodus_identity_clear(&id_b);
    nodus_identity_clear(&id_loaded);
}

/* D2 (N1 delta 1): MLKEM_BIND must be strict (nodus_sign_purpose_is_strict(),
 * nodus_sign.c) precisely because its preimage (mlkem_pk || nonce) is the
 * same length/shape as KYBER_BIND's (kyber_pk || nonce) — without the NDS1
 * tag the two signatures would be interchangeable. This pins the closed
 * swap AND the closed raw-signature bypass, without breaking the genuine
 * path. */
static void test_mlkem_bind_strict_no_swap(void) {
    TEST("MLKEM_BIND strict: kpk_sig cannot be replayed as mpk_sig, raw rejected");

    nodus_identity_t id;
    nodus_identity_generate(&id);

    uint8_t nonce[NODUS_NONCE_LEN];
    memset(nonce, 0x5D, sizeof(nonce));

    /* A genuine KYBER_BIND signature over (kyber_pk || nonce). */
    uint8_t kyber_sign_data[NODUS_KYBER_PK_BYTES + NODUS_NONCE_LEN];
    memcpy(kyber_sign_data, id.kyber_pk, NODUS_KYBER_PK_BYTES);
    memcpy(kyber_sign_data + NODUS_KYBER_PK_BYTES, nonce, NODUS_NONCE_LEN);
    nodus_sig_t kpk_sig;
    bool sign_ok = (nodus_sign_kyber_bind(&kpk_sig, kyber_sign_data,
                                           sizeof(kyber_sign_data), &id.sk) == 0);

    /* Present kpk_sig AS an mpk_sig, with mpk := kyber_pk — same bytes,
     * same length (NODUS_KYBER_PK_BYTES == NODUS_MLKEM_PK_BYTES), exactly
     * the swap D2 exists to close. */
    uint8_t mlkem_sign_data[NODUS_MLKEM_PK_BYTES + NODUS_NONCE_LEN];
    memcpy(mlkem_sign_data, id.kyber_pk, NODUS_MLKEM_PK_BYTES);
    memcpy(mlkem_sign_data + NODUS_MLKEM_PK_BYTES, nonce, NODUS_NONCE_LEN);

    bool swap_rejected = sign_ok &&
        nodus_verify_mlkem_bind(&kpk_sig, mlkem_sign_data,
                                 sizeof(mlkem_sign_data), &id.pk) != 0;

    /* A raw (untagged) Dilithium5 signature over the SAME bytes an honest
     * mpk_sig would cover must also be rejected — MLKEM_BIND is strict,
     * no raw fallback either side. */
    nodus_sig_t raw_sig;
    bool raw_sign_ok = (nodus_sign(&raw_sig, mlkem_sign_data,
                                    sizeof(mlkem_sign_data), &id.sk) == 0);
    bool raw_rejected = raw_sign_ok &&
        nodus_verify_mlkem_bind(&raw_sig, mlkem_sign_data,
                                 sizeof(mlkem_sign_data), &id.pk) != 0;

    /* Sanity: a genuine, correctly-tagged mpk_sig MUST still verify —
     * otherwise this test would "pass" by breaking the real path instead
     * of proving only the swap/raw bypass are closed. */
    nodus_sig_t mpk_sig;
    bool genuine_ok =
        (nodus_sign_mlkem_bind(&mpk_sig, mlkem_sign_data,
                                sizeof(mlkem_sign_data), &id.sk) == 0) &&
        (nodus_verify_mlkem_bind(&mpk_sig, mlkem_sign_data,
                                  sizeof(mlkem_sign_data), &id.pk) == 0);

    if (sign_ok && swap_rejected && raw_sign_ok && raw_rejected && genuine_ok) {
        PASS();
    } else {
        FAIL("kpk_sig/raw signature accepted as mpk_sig, or genuine mpk_sig broken");
    }

    nodus_identity_clear(&id);
}

int main(void) {
    printf("=== Nodus ML-KEM-1024 Handshake Tests (Faz 1 KEM migration) ===\n");

    test_identity_from_seed_derives_mlkem();
    test_identity_from_seed_mlkem_pk_kat_pin();
    test_identity_load_generates_missing_mlkem();
    test_identity_load_mlkem_partial_regenerates();
    test_identity_load_mlkem_pair_present_unchanged();
    test_identity_load_mlkem_pair_mismatch_regenerates();
    test_mlkem_bind_strict_no_swap();
    test_drive_a_new_client_new_server();
    test_drive_b_legacy_client_new_server();
    test_d7_key_init_mlkem_at_server_without_mlkem_answers();
    test_drive_c_new_client_server_without_mlkem();
    test_d4_inbound_e2e_no_key_refused();
    test_d5_mlkem_cache_cleared_on_rollback();

    printf("\n=== Results: %d passed, %d failed ===\n", passed, failed);
    return failed > 0 ? 1 : 0;
}
