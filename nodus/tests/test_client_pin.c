/**
 * Nodus — Client SDK server-key pin + monotonic timeout tests
 *
 * Design: docs/plans/2026-09-25-web-wallet-nodus-send-design.md rev 2,
 * package (c1) (§0a.3; RT1 L3 F1 / F8). Governing records:
 * docs/plans/decisions/2026-09-25-web-wallet-nodus-send-transport.md
 * ("Sunucu doğrulama"; addendum 2026-09-29 "pinli (tarayıcı) istemci YALNIZ
 * ML-KEM-1024"), docs/plans/decisions/2026-09-23-kem-mlkem-migration.md
 * (K1 rev 2: the Kyber round-3 path stays for UNPINNED clients),
 * nodus/BUGS.md "Tier-2 AUTH_OK: a kpk without kpk_sig".
 *
 * What it proves — nodus_client_config_t.pinned_server_fps:
 *   P1  init refuses a broken pin (count > 0 with NULL list, count < 0).
 *   P2  real nodus_server_t, pin = its fingerprint → connects over
 *       ML-KEM-1024, client->server_dil_pk is that server's key.
 *   P2b the matching fingerprint is not the first list entry → connects.
 *   P3  real server, pin list holding only OTHER fingerprints → refused.
 *   P4  real server, no pin → connects (unchanged behaviour).
 *   Fake server (hand-rolled over nodus_tcp_t + nodus_t2_* encoders, so it
 *   can send the AUTH_OK shapes a real server never sends). Every weak
 *   path: refused WITH a pin, still accepted WITHOUT one:
 *   W1  AUTH_OK without kpk → unencrypted session.
 *   W2  AUTH_OK without kpk + client holds a cached Kyber key → the
 *       cached-key reconnect branch.
 *   W3  kpk without spk/kpk_sig ("legacy server").
 *   W4  signed kpk + mpk whose mpk_sig is by ANOTHER key → Kyber fallback.
 *   W5  signed kpk + mpk with no mpk_sig.
 *   W6  signed kpk, no mpk at all → Kyber round-3. A pinned client is
 *       ML-KEM-1024 only (operator 2026-09-29, "5 evet"): refused.
 *   C1  control: the same fake, signed kpk + correctly signed mpk, pinned
 *       to ITS key → connects over ML-KEM. Without this, W1-W6 "refused"
 *       could mean "the fake is broken", not "the pin refused it".
 *   C2  the same fully signed fake under a pin to another key → refused.
 *   Monotonic clock (unit level):
 *   T1  nodus_time_mono_ms() never goes back and advances at least as far
 *       as a sleep.
 *   T2  a server that accepts TCP and never answers: the connect fails and
 *       at least connect_timeout_ms of MONOTONIC time passed. The limit
 *       exercised is do_auth's wait for the HELLO reply (wait_response,
 *       which do_auth runs with connect_timeout_ms), since the TCP connect
 *       itself completes at once on loopback. Lower bound only — no upper
 *       bound is asserted (an upper bound is a timing assertion that fails
 *       under load; CLAUDE.md DETERMINISM).
 *
 * What it requires: default build, nothing else. No environment.
 * Ports: real server 15400-15404 (test-unique, see the parallel-safety
 * note in nodus/CMakeLists.txt); the fake server listens on 127.0.0.1:0
 * (kernel-chosen). Data dir /tmp/nodus_client_pin_test_<pid>, removed at
 * the end.
 *
 * What it leaves behind: nothing (server thread joined, data dir removed).
 *
 * How it can lie:
 *   - W1-W6 prove the refusal happens, not WHICH check refused; the
 *     reason is only in the client's log (QGP_LOG_ERROR lines).
 *   - T2 cannot step the wall clock (needs root), so it does not prove
 *     that a wall-clock jump leaves a wait unchanged — only that the
 *     wait lasted its full limit on the monotonic clock. It exercises the
 *     HELLO wait, not the TCP-connect wait loop in do_connect_one.
 *   - The fake never decapsulates the KEY_INIT; an unpinned "accepted"
 *     means do_auth returned 0 after key_ack, not that traffic flows.
 *   - Native build only: the __EMSCRIPTEN__ branches (no read thread,
 *     emscripten_sleep yields, the poll() loop) are not run by any test;
 *     web-wallet/scripts/check-nodus-client-wasm.sh only compiles them.
 */

#include "nodus/nodus.h"
#include "server/nodus_server.h"
#include "transport/nodus_tcp.h"
#include "protocol/nodus_tier2.h"
#include "protocol/nodus_cbor.h"
#include "crypto/nodus_sign.h"
#include "crypto/nodus_identity.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <stdatomic.h>

#define TEST(name) do { printf("  %-70s", name); fflush(stdout); } while (0)
#define PASS()     do { printf("PASS\n"); passed++; } while (0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while (0)

static int passed = 0;
static int failed = 0;

#define REAL_BASE_PORT 15400

/* ── Real server (test_client.c / test_mlkem_handshake.c pattern) ─────── */

/* Large — static, never a stack local. */
static nodus_server_t g_server;
static nodus_server_config_t g_server_cfg;
static pthread_t g_server_tid;
/* g_server_init_done: set by the server thread once its start-up has
 * finished, success or failure (mkdir or nodus_server_init); g_server_ready:
 * it succeeded. start_real_server waits for this outcome, not for a time
 * budget: init runs the witness start checks (the EVM precompile self-test
 * loads the KZG setup), whose duration depends on the host — the old
 * 5000 ms budget could expire with init still running (2026-10-05, Nodus
 * EVM red-team 1 F2). Both flags are read and written only under
 * g_init_lock; the waiter sleeps on g_init_cond. */
static pthread_mutex_t g_init_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  g_init_cond = PTHREAD_COND_INITIALIZER;
static bool g_server_ready = false;
static bool g_server_init_done = false;

static void server_init_outcome(bool ready) {
    pthread_mutex_lock(&g_init_lock);
    g_server_ready = ready;
    g_server_init_done = true;
    pthread_cond_broadcast(&g_init_cond);
    pthread_mutex_unlock(&g_init_lock);
}

static void *real_server_thread(void *arg) {
    (void)arg;
    char cmd[320];
    snprintf(cmd, sizeof(cmd), "mkdir -p %s", g_server_cfg.data_path);
    if (system(cmd) != 0) {
        server_init_outcome(false);
        return NULL;
    }

    if (nodus_server_init(&g_server, &g_server_cfg) != 0) {
        fprintf(stderr, "test_client_pin: server init failed\n");
        server_init_outcome(false);
        return NULL;
    }
    server_init_outcome(true);
    nodus_server_run(&g_server);
    nodus_server_close(&g_server);

    snprintf(cmd, sizeof(cmd), "rm -rf %s", g_server_cfg.data_path);
    if (system(cmd) != 0) fprintf(stderr, "test_client_pin: cleanup failed\n");
    return NULL;
}

static int start_real_server(void) {
    memset(&g_server_cfg, 0, sizeof(g_server_cfg));
    snprintf(g_server_cfg.bind_ip, sizeof(g_server_cfg.bind_ip), "127.0.0.1");
    g_server_cfg.udp_port     = REAL_BASE_PORT;
    g_server_cfg.tcp_port     = REAL_BASE_PORT + 1;
    g_server_cfg.peer_port    = REAL_BASE_PORT + 2;
    g_server_cfg.ch_port      = REAL_BASE_PORT + 3;
    g_server_cfg.witness_port = REAL_BASE_PORT + 4;
    snprintf(g_server_cfg.data_path, sizeof(g_server_cfg.data_path),
             "/tmp/nodus_client_pin_test_%d", getpid());

    if (pthread_create(&g_server_tid, NULL, real_server_thread, NULL) != 0)
        return -1;
    /* Wait for the start-up OUTCOME. This used to be a 5000 ms bounded
     * wait because a bare `while (!ready)` turned a bind failure into a
     * hang; a failed start now signals its outcome too, so the wait needs
     * no time budget (see g_server_init_done). */
    pthread_mutex_lock(&g_init_lock);
    while (!g_server_init_done)
        pthread_cond_wait(&g_init_cond, &g_init_lock);
    bool ready = g_server_ready;
    pthread_mutex_unlock(&g_init_lock);
    return ready ? 0 : -1;
}

static void stop_real_server(void) {
    nodus_server_stop(&g_server);
    pthread_join(g_server_tid, NULL);
}

/* ── Fake server ───────────────────────────────────────────────────── */

typedef enum {
    FAKE_SILENT = 0,       /* accepts, never answers                    */
    FAKE_NO_KPK,           /* plain auth_ok (token only)                */
    FAKE_KPK_UNSIGNED,     /* auth_ok {tok, kpk}                        */
    FAKE_SIGNED,           /* auth_ok {tok, kpk, spk, kpk_sig} — no mpk  */
    FAKE_SIGNED_MLKEM,     /* + mpk, mpk_sig by its own key (correct)   */
    FAKE_MPK_BAD_SIG,      /* signed kpk + mpk signed by another key    */
    FAKE_MPK_NO_SIG        /* signed kpk + mpk, no mpk_sig              */
} fake_mode_t;

typedef struct {
    nodus_tcp_t       *tcp;
    nodus_identity_t  *id;       /* the fake's own key (spk, kpk, mpk)   */
    nodus_identity_t  *other;    /* signs the bad mpk_sig (W4)          */
    _Atomic int        mode;
    _Atomic bool       stop;
    uint8_t            nonce[NODUS_NONCE_LEN];
    pthread_t          tid;
    uint8_t           *buf;
} fake_server_t;

#define FAKE_BUF_SIZE 32768

static fake_server_t g_fake;

/* Same header layout as nodus_tier2.c enc_response_header (static there). */
static void fake_resp_header(cbor_encoder_t *enc, uint32_t txn, const char *method) {
    cbor_encode_map(enc, 4);
    cbor_encode_cstr(enc, "t"); cbor_encode_uint(enc, txn);
    cbor_encode_cstr(enc, "y"); cbor_encode_cstr(enc, "r");
    cbor_encode_cstr(enc, "q"); cbor_encode_cstr(enc, method);
}

static void fake_send(nodus_tcp_conn_t *conn, cbor_encoder_t *enc) {
    size_t len = cbor_encoder_len(enc);
    if (len > 0 && !enc->error) nodus_tcp_send(conn, g_fake.buf, len);
}

static void fake_send_auth_ok(nodus_tcp_conn_t *conn, uint32_t txn) {
    int mode = atomic_load(&g_fake.mode);
    uint8_t token[NODUS_SESSION_TOKEN_LEN];
    memset(token, 0x5a, sizeof(token));
    size_t len = 0;

    if (mode == FAKE_NO_KPK) {
        if (nodus_t2_auth_ok(txn, token, g_fake.buf, FAKE_BUF_SIZE, &len) == 0)
            nodus_tcp_send(conn, g_fake.buf, len);
        return;
    }

    cbor_encoder_t enc;
    cbor_encoder_init(&enc, g_fake.buf, FAKE_BUF_SIZE);

    if (mode == FAKE_KPK_UNSIGNED) {
        fake_resp_header(&enc, txn, "auth_ok");
        cbor_encode_cstr(&enc, "r");
        cbor_encode_map(&enc, 2);
        cbor_encode_cstr(&enc, "tok");
        cbor_encode_bstr(&enc, token, NODUS_SESSION_TOKEN_LEN);
        cbor_encode_cstr(&enc, "kpk");
        cbor_encode_bstr(&enc, g_fake.id->kyber_pk, NODUS_KYBER_PK_BYTES);
        fake_send(conn, &enc);
        return;
    }

    /* Every remaining mode signs kpk || nonce with the fake's own key. */
    uint8_t sd[NODUS_KYBER_PK_BYTES + NODUS_NONCE_LEN];
    memcpy(sd, g_fake.id->kyber_pk, NODUS_KYBER_PK_BYTES);
    memcpy(sd + NODUS_KYBER_PK_BYTES, g_fake.nonce, NODUS_NONCE_LEN);
    nodus_sig_t kpk_sig;
    if (nodus_sign_kyber_bind(&kpk_sig, sd, sizeof(sd), &g_fake.id->sk) != 0) return;

    if (mode == FAKE_SIGNED) {
        if (nodus_t2_auth_ok_kyber(txn, token, g_fake.id->kyber_pk, &g_fake.id->pk,
                                    &kpk_sig, NULL, NULL,
                                    g_fake.buf, FAKE_BUF_SIZE, &len) == 0)
            nodus_tcp_send(conn, g_fake.buf, len);
        return;
    }

    if (mode == FAKE_MPK_BAD_SIG || mode == FAKE_SIGNED_MLKEM) {
        /* A well-formed MLKEM_BIND signature — by the fake's own key
         * (correct), or by a key that is NOT spk (W4). */
        uint8_t msd[NODUS_MLKEM_PK_BYTES + NODUS_NONCE_LEN];
        memcpy(msd, g_fake.id->mlkem_pk, NODUS_MLKEM_PK_BYTES);
        memcpy(msd + NODUS_MLKEM_PK_BYTES, g_fake.nonce, NODUS_NONCE_LEN);
        const nodus_seckey_t *signer = (mode == FAKE_SIGNED_MLKEM)
                                       ? &g_fake.id->sk : &g_fake.other->sk;
        nodus_sig_t mpk_sig;
        if (nodus_sign_mlkem_bind(&mpk_sig, msd, sizeof(msd), signer) != 0) return;
        if (nodus_t2_auth_ok_kyber(txn, token, g_fake.id->kyber_pk, &g_fake.id->pk,
                                    &kpk_sig, g_fake.id->mlkem_pk, &mpk_sig,
                                    g_fake.buf, FAKE_BUF_SIZE, &len) == 0)
            nodus_tcp_send(conn, g_fake.buf, len);
        return;
    }

    if (mode == FAKE_MPK_NO_SIG) {
        fake_resp_header(&enc, txn, "auth_ok");
        cbor_encode_cstr(&enc, "r");
        cbor_encode_map(&enc, 5);
        cbor_encode_cstr(&enc, "tok");
        cbor_encode_bstr(&enc, token, NODUS_SESSION_TOKEN_LEN);
        cbor_encode_cstr(&enc, "kpk");
        cbor_encode_bstr(&enc, g_fake.id->kyber_pk, NODUS_KYBER_PK_BYTES);
        cbor_encode_cstr(&enc, "spk");
        cbor_encode_bstr(&enc, g_fake.id->pk.bytes, NODUS_PK_BYTES);
        cbor_encode_cstr(&enc, "kpk_sig");
        cbor_encode_bstr(&enc, kpk_sig.bytes, NODUS_SIG_BYTES);
        cbor_encode_cstr(&enc, "mpk");
        cbor_encode_bstr(&enc, g_fake.id->mlkem_pk, NODUS_MLKEM_PK_BYTES);
        fake_send(conn, &enc);
        return;
    }
}

static void fake_on_frame(nodus_tcp_conn_t *conn, const uint8_t *payload,
                           size_t len, void *ctx) {
    (void)ctx;
    if (atomic_load(&g_fake.mode) == FAKE_SILENT) return;

    nodus_tier2_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    if (nodus_t2_decode(payload, len, &msg) != 0) {
        nodus_t2_msg_free(&msg);
        return;
    }

    size_t out = 0;
    if (strcmp(msg.method, "hello") == 0) {
        nodus_random(g_fake.nonce, NODUS_NONCE_LEN);
        if (nodus_t2_challenge(msg.txn_id, g_fake.nonce,
                                g_fake.buf, FAKE_BUF_SIZE, &out) == 0)
            nodus_tcp_send(conn, g_fake.buf, out);
    } else if (strcmp(msg.method, "auth") == 0) {
        fake_send_auth_ok(conn, msg.txn_id);
    } else if (strcmp(msg.method, "key_init") == 0) {
        /* Never decapsulated — the ack only lets do_auth finish. */
        uint8_t nonce_s[NODUS_NONCE_LEN];
        nodus_random(nonce_s, NODUS_NONCE_LEN);
        if (nodus_t2_key_ack(msg.txn_id, nonce_s,
                              g_fake.buf, FAKE_BUF_SIZE, &out) == 0)
            nodus_tcp_send(conn, g_fake.buf, out);
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
    g_fake.tcp   = calloc(1, sizeof(nodus_tcp_t));
    g_fake.id    = calloc(1, sizeof(nodus_identity_t));
    g_fake.other = calloc(1, sizeof(nodus_identity_t));
    g_fake.buf   = malloc(FAKE_BUF_SIZE);
    if (!g_fake.tcp || !g_fake.id || !g_fake.other || !g_fake.buf) return -1;
    if (nodus_identity_generate(g_fake.id) != 0) return -1;
    if (nodus_identity_generate(g_fake.other) != 0) return -1;
    if (!g_fake.id->has_kyber || !g_fake.id->has_mlkem) return -1;

    if (nodus_tcp_init(g_fake.tcp, -1) != 0) return -1;
    g_fake.tcp->on_frame = fake_on_frame;
    if (nodus_tcp_listen(g_fake.tcp, "127.0.0.1", 0) != 0) return -1;
    atomic_store(&g_fake.mode, FAKE_SILENT);
    atomic_store(&g_fake.stop, false);
    return pthread_create(&g_fake.tid, NULL, fake_thread, NULL) == 0 ? 0 : -1;
}

static void stop_fake_server(void) {
    atomic_store(&g_fake.stop, true);
    pthread_join(g_fake.tid, NULL);
    nodus_tcp_close(g_fake.tcp);
    free(g_fake.tcp);
    nodus_identity_clear(g_fake.id);
    nodus_identity_clear(g_fake.other);
    free(g_fake.id);
    free(g_fake.other);
    free(g_fake.buf);
}

/* ── Client helpers ────────────────────────────────────────────────── */

static nodus_identity_t *g_client_id;

static void client_cfg(nodus_client_config_t *cfg, uint16_t port,
                        const nodus_key_t *pins, int pin_count,
                        int connect_timeout_ms) {
    memset(cfg, 0, sizeof(*cfg));
    snprintf(cfg->servers[0].ip, sizeof(cfg->servers[0].ip), "127.0.0.1");
    cfg->servers[0].port = port;
    cfg->server_count = 1;
    cfg->connect_timeout_ms = connect_timeout_ms;
    cfg->pinned_server_fps = pins;
    cfg->pinned_server_fp_count = pin_count;
}

/* Connect once. Returns the nodus_client_connect result (0 / -1), or -2 if
 * init itself failed. *out_client (optional) receives the still-open
 * client; the caller closes + frees it. preload_kyber: seed the client's
 * cached server Kyber key before connecting (the W2 cached branch). */
static int connect_once(uint16_t port, const nodus_key_t *pins, int pin_count,
                         int connect_timeout_ms, const uint8_t *preload_kyber,
                         nodus_client_t **out_client) {
    nodus_client_t *c = calloc(1, sizeof(*c));
    if (!c) return -2;
    nodus_client_config_t cfg;
    client_cfg(&cfg, port, pins, pin_count, connect_timeout_ms);
    if (nodus_client_init(c, &cfg, g_client_id) != 0) {
        free(c);
        return -2;
    }
    if (preload_kyber) {
        memcpy(c->cached_server_kyber_pk, preload_kyber, NODUS_KYBER_PK_BYTES);
        c->has_cached_server_kyber = true;
    }
    int rc = nodus_client_connect(c);
    if (out_client) {
        *out_client = c;
    } else {
        nodus_client_close(c);
        free(c);
    }
    return rc;
}

static void close_client(nodus_client_t *c) {
    if (!c) return;
    nodus_client_close(c);
    free(c);
}

/* A fingerprint that is neither the real server's nor the fake's. */
static void unrelated_fp(nodus_key_t *out) {
    nodus_identity_t *x = calloc(1, sizeof(*x));
    memset(out, 0, sizeof(*out));
    if (!x) return;
    if (nodus_identity_generate(x) == 0)
        nodus_fingerprint(&x->pk, out);
    nodus_identity_clear(x);
    free(x);
}

/* ── P1: init validation ───────────────────────────────────────────── */

static void test_init_rejects_broken_pin(void) {
    TEST("P1 init refuses count>0 with NULL list, and count<0");
    nodus_client_t *c = calloc(1, sizeof(*c));
    if (!c) { FAIL("alloc"); return; }
    nodus_client_config_t cfg;
    nodus_key_t one;
    memset(&one, 0x11, sizeof(one));

    client_cfg(&cfg, 1, NULL, 1, 0);
    int rc_null = nodus_client_init(c, &cfg, g_client_id);
    if (rc_null == 0) nodus_client_close(c);

    client_cfg(&cfg, 1, &one, -1, 0);
    int rc_neg = nodus_client_init(c, &cfg, g_client_id);
    if (rc_neg == 0) nodus_client_close(c);

    client_cfg(&cfg, 1, &one, 1, 0);
    int rc_ok = nodus_client_init(c, &cfg, g_client_id);
    if (rc_ok == 0) nodus_client_close(c);

    client_cfg(&cfg, 1, NULL, 0, 0);
    int rc_none = nodus_client_init(c, &cfg, g_client_id);
    if (rc_none == 0) nodus_client_close(c);
    free(c);

    if (rc_null == -1 && rc_neg == -1 && rc_ok == 0 && rc_none == 0) PASS();
    else FAIL("init accepted a broken pin or refused a valid one");
}

/* ── P2-P4: real server ────────────────────────────────────────────── */

static void test_real_server(void) {
    nodus_key_t server_fp, other_fp;
    nodus_fingerprint(&g_server.identity.pk, &server_fp);
    unrelated_fp(&other_fp);
    uint16_t port = (uint16_t)(REAL_BASE_PORT + 1);

    TEST("P2 real server, pinned to its key -> connects, encrypted");
    {
        nodus_client_t *c = NULL;
        int rc = connect_once(port, &server_fp, 1, 5000, NULL, &c);
        nodus_key_t got;
        memset(&got, 0, sizeof(got));
        if (c && c->has_server_dil_pk) nodus_fingerprint(&c->server_dil_pk, &got);
        bool ok = rc == 0 && c && nodus_client_is_ready(c) &&
                  c->has_cached_server_mlkem && c->has_server_dil_pk &&
                  nodus_key_cmp(&got, &server_fp) == 0;
        close_client(c);
        if (ok) PASS(); else FAIL("pinned connect to the right server failed");
    }

    TEST("P2b pin list with the match NOT first -> connects");
    {
        nodus_key_t pins[3];
        pins[0] = other_fp;
        memset(&pins[1], 0x77, sizeof(pins[1]));
        pins[2] = server_fp;
        int rc = connect_once(port, pins, 3, 5000, NULL, NULL);
        if (rc == 0) PASS(); else FAIL("list membership not honoured");
    }

    TEST("P3 real server, pin list without its key -> refused");
    {
        nodus_key_t pins[2];
        pins[0] = other_fp;
        memset(&pins[1], 0x77, sizeof(pins[1]));
        int rc = connect_once(port, pins, 2, 5000, NULL, NULL);
        if (rc == -1) PASS(); else FAIL("connected to an unpinned server");
    }

    TEST("P4 real server, no pin -> connects (unchanged)");
    {
        int rc = connect_once(port, NULL, 0, 5000, NULL, NULL);
        if (rc == 0) PASS(); else FAIL("unpinned connect failed");
    }
}

/* ── W1-W6, C1-C2: fake server ─────────────────────────────────────── */

typedef struct {
    const char *name_pinned;
    const char *name_unpinned;
    fake_mode_t mode;
    bool        preload_cache;
} weak_case_t;

static void run_weak_case(const weak_case_t *wc, const nodus_key_t *fake_fp) {
    uint16_t port = g_fake.tcp->port;
    atomic_store(&g_fake.mode, wc->mode);
    const uint8_t *cache = wc->preload_cache ? g_fake.id->kyber_pk : NULL;

    TEST(wc->name_pinned);
    int rc = connect_once(port, fake_fp, 1, 3000, cache, NULL);
    if (rc == -1) PASS(); else FAIL("pinned client accepted a weak handshake");

    TEST(wc->name_unpinned);
    nodus_client_t *c = NULL;
    rc = connect_once(port, NULL, 0, 3000, cache, &c);
    bool ok = rc == 0 && c && nodus_client_is_ready(c);
    /* W4: the unpinned client must have dropped to Kyber (no ML-KEM cache). */
    if (ok && wc->mode == FAKE_MPK_BAD_SIG) ok = !c->has_cached_server_mlkem;
    close_client(c);
    if (ok) PASS(); else FAIL("unpinned behaviour changed");
}

static void test_fake_server(void) {
    nodus_key_t fake_fp, other_fp;
    nodus_fingerprint(&g_fake.id->pk, &fake_fp);
    unrelated_fp(&other_fp);
    uint16_t port = g_fake.tcp->port;

    TEST("C1 control: fake, signed kpk + mpk, pinned to its key -> ML-KEM");
    atomic_store(&g_fake.mode, FAKE_SIGNED_MLKEM);
    {
        nodus_client_t *c = NULL;
        int rc = connect_once(port, &fake_fp, 1, 3000, NULL, &c);
        bool ok = rc == 0 && c && c->has_cached_server_mlkem;
        close_client(c);
        if (ok) PASS(); else FAIL("fake server broken — W1-W6 prove nothing");
    }

    TEST("C2 fake, signed kpk + mpk, pinned to another key -> refused");
    {
        int rc = connect_once(port, &other_fp, 1, 3000, NULL, NULL);
        if (rc == -1) PASS(); else FAIL("connected to an unpinned server");
    }

    static const weak_case_t cases[] = {
        { "W1 no kpk (unencrypted), pinned -> refused",
          "W1 no kpk (unencrypted), unpinned -> accepted",
          FAKE_NO_KPK, false },
        { "W2 no kpk + cached Kyber key, pinned -> refused",
          "W2 no kpk + cached Kyber key, unpinned -> accepted",
          FAKE_NO_KPK, true },
        { "W3 kpk without spk/kpk_sig, pinned -> refused",
          "W3 kpk without spk/kpk_sig, unpinned -> accepted",
          FAKE_KPK_UNSIGNED, false },
        { "W4 mpk_sig by another key, pinned -> refused",
          "W4 mpk_sig by another key, unpinned -> Kyber fallback",
          FAKE_MPK_BAD_SIG, false },
        { "W5 mpk without mpk_sig, pinned -> refused",
          "W5 mpk without mpk_sig, unpinned -> accepted",
          FAKE_MPK_NO_SIG, false },
        { "W6 signed kpk, no mpk (Kyber only), pinned -> refused",
          "W6 signed kpk, no mpk (Kyber only), unpinned -> accepted",
          FAKE_SIGNED, false },
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
        run_weak_case(&cases[i], &fake_fp);
}

/* ── T1-T2: monotonic clock ────────────────────────────────────────── */

static void test_mono_clock(void) {
    TEST("T1 nodus_time_mono_ms never goes back, advances >= a sleep");
    uint64_t prev = nodus_time_mono_ms();
    bool monotone = true;
    for (int i = 0; i < 10000; i++) {
        uint64_t now = nodus_time_mono_ms();
        if (now < prev) { monotone = false; break; }
        prev = now;
    }
    uint64_t a = nodus_time_mono_ms();
    usleep(120 * 1000);
    uint64_t b = nodus_time_mono_ms();
    if (monotone && b >= a + 120) PASS();
    else FAIL("monotonic clock went back or did not advance");
}

static void test_timeout_on_mono_clock(void) {
    TEST("T2 silent server: HELLO wait fails after >= connect_timeout_ms");
    atomic_store(&g_fake.mode, FAKE_SILENT);
    const int limit_ms = 400;
    uint64_t t0 = nodus_time_mono_ms();
    int rc = connect_once(g_fake.tcp->port, NULL, 0, limit_ms, NULL, NULL);
    uint64_t spent = nodus_time_mono_ms() - t0;
    /* Lower bound only (see file header). */
    if (rc == -1 && spent >= (uint64_t)limit_ms) PASS();
    else FAIL("timed out early, or connected to a silent server");
}

int main(void) {
    printf("=== Nodus client server-key pin + monotonic timeout tests ===\n");

    g_client_id = calloc(1, sizeof(*g_client_id));
    if (!g_client_id || nodus_identity_generate(g_client_id) != 0) {
        printf("FATAL: client identity\n");
        return 1;
    }

    test_mono_clock();
    test_init_rejects_broken_pin();

    if (start_fake_server() != 0) {
        printf("FATAL: fake server did not start\n");
        return 1;
    }
    test_fake_server();
    test_timeout_on_mono_clock();
    stop_fake_server();

    if (start_real_server() != 0) {
        printf("FATAL: real server did not start (ports %d-%d)\n",
               REAL_BASE_PORT, REAL_BASE_PORT + 4);
        return 1;
    }
    test_real_server();
    stop_real_server();

    nodus_identity_clear(g_client_id);
    free(g_client_id);

    printf("\n=== Results: %d passed, %d failed ===\n", passed, failed);
    return failed > 0 ? 1 : 0;
}
