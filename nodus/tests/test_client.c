/**
 * Nodus — Client SDK Test
 *
 * Tests the public nodus_client API against a local test server.
 * Exercises connect, auth, DHT put/get/listen, channel create/post/get/subscribe.
 */

#include "nodus/nodus.h"
#include "server/nodus_server.h"
#include "crypto/nodus_sign.h"
#include "crypto/nodus_identity.h"
#include "core/nodus_value.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) do { \
    tests_run++; \
    printf("  [%d] %-45s ", tests_run, name); \
} while (0)

#define PASS() do { tests_passed++; printf("PASS\n"); } while (0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); } while (0)

/* ── Server thread ──────────────────────────────────────────────── */

static nodus_server_t server;
static volatile bool server_ready = false;

static void *server_thread(void *arg) {
    (void)arg;
    nodus_server_config_t config;
    memset(&config, 0, sizeof(config));
    snprintf(config.bind_ip, sizeof(config.bind_ip), "127.0.0.1");
    config.udp_port = 15000;
    config.tcp_port = 15001;
    snprintf(config.data_path, sizeof(config.data_path),
             "/tmp/nodus_client_test_%d", getpid());

    char cmd[256];
    snprintf(cmd, sizeof(cmd), "mkdir -p %s", config.data_path);
    system(cmd);

    if (nodus_server_init(&server, &config) != 0) {
        fprintf(stderr, "server init failed\n");
        return NULL;
    }

    server_ready = true;
    nodus_server_run(&server);
    nodus_server_close(&server);

    snprintf(cmd, sizeof(cmd), "rm -rf %s", config.data_path);
    system(cmd);
    return NULL;
}

/* ── Callback tracking ──────────────────────────────────────────── */

static volatile bool got_value_changed = false;
static volatile bool got_ch_post_notify = false;
static volatile bool got_state_ready = false;

static void on_value_changed(const nodus_key_t *key, const nodus_value_t *val,
                              void *user_data) {
    (void)key; (void)val; (void)user_data;
    got_value_changed = true;
}

static void on_ch_post(const uint8_t channel_uuid[16],
                        const nodus_channel_post_t *post,
                        void *user_data) {
    (void)channel_uuid; (void)post; (void)user_data;
    got_ch_post_notify = true;
}

static void on_state_change(nodus_client_state_t old_state,
                              nodus_client_state_t new_state,
                              void *user_data) {
    (void)old_state; (void)user_data;
    if (new_state == NODUS_CLIENT_READY)
        got_state_ready = true;
}

/* ── Tests ──────────────────────────────────────────────────────── */

static nodus_client_t client;
static nodus_identity_t client_id;

/**
 * Sign a channel post using JSON format matching the messenger client.
 */
static int sign_channel_post(const uint8_t post_uuid[16],
                               const uint8_t ch_uuid[16],
                               const nodus_key_t *author_fp,
                               const char *body, uint64_t timestamp,
                               const nodus_seckey_t *sk,
                               nodus_sig_t *sig_out) {
    char pu[37], cu[37], fp_hex[NODUS_KEY_HEX_LEN];
    snprintf(pu, sizeof(pu),
             "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             post_uuid[0], post_uuid[1], post_uuid[2], post_uuid[3],
             post_uuid[4], post_uuid[5], post_uuid[6], post_uuid[7],
             post_uuid[8], post_uuid[9], post_uuid[10], post_uuid[11],
             post_uuid[12], post_uuid[13], post_uuid[14], post_uuid[15]);
    snprintf(cu, sizeof(cu),
             "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             ch_uuid[0], ch_uuid[1], ch_uuid[2], ch_uuid[3],
             ch_uuid[4], ch_uuid[5], ch_uuid[6], ch_uuid[7],
             ch_uuid[8], ch_uuid[9], ch_uuid[10], ch_uuid[11],
             ch_uuid[12], ch_uuid[13], ch_uuid[14], ch_uuid[15]);
    for (int i = 0; i < NODUS_KEY_BYTES; i++)
        snprintf(fp_hex + i * 2, 3, "%02x", author_fp->bytes[i]);

    size_t cap = 512 + strlen(body);
    char *json = malloc(cap);
    if (!json) return -1;
    int len = snprintf(json, cap,
        "{\"post_uuid\":\"%s\","
        "\"channel_uuid\":\"%s\","
        "\"author\":\"%s\","
        "\"body\":\"%s\","
        "\"created_at\":%llu}",
        pu, cu, fp_hex, body, (unsigned long long)timestamp);
    int rc = nodus_sign(sig_out, (const uint8_t *)json, (size_t)len, sk);
    free(json);
    return rc;
}

static void test_init(void) {
    TEST("client SDK init");
    nodus_identity_generate(&client_id);

    nodus_client_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.servers[0].ip, sizeof(cfg.servers[0].ip), "127.0.0.1");
    cfg.servers[0].port = 15001;
    cfg.server_count = 1;
    cfg.auto_reconnect = true;
    cfg.on_value_changed = on_value_changed;
    cfg.on_ch_post = on_ch_post;
    cfg.on_state_change = on_state_change;

    int rc = nodus_client_init(&client, &cfg, &client_id);
    if (rc == 0 && client.state == NODUS_CLIENT_DISCONNECTED)
        PASS();
    else
        FAIL("init returned error or bad state");
}

static void test_connect(void) {
    TEST("client connects and authenticates");
    int rc = nodus_client_connect(&client);
    if (rc == 0 && nodus_client_is_ready(&client))
        PASS();
    else
        FAIL("connect/auth failed");
}

static void test_fingerprint(void) {
    TEST("client fingerprint matches identity");
    const char *fp = nodus_client_fingerprint(&client);
    if (fp && strcmp(fp, client_id.fingerprint) == 0)
        PASS();
    else
        FAIL("fingerprint mismatch");
}

static void test_put(void) {
    TEST("client put DHT value");
    nodus_key_t key;
    nodus_hash((const uint8_t *)"test-key", 8, &key);

    const char *data = "hello from client SDK";
    nodus_value_t *val = NULL;
    nodus_value_create(&key, (const uint8_t *)data, strlen(data),
                        NODUS_VALUE_EPHEMERAL, NODUS_DEFAULT_TTL,
                        1, 0, &client_id.pk, &val);
    nodus_value_sign(val, &client_id.sk);

    int rc = nodus_client_put(&client, &key,
                               (const uint8_t *)data, strlen(data),
                               NODUS_VALUE_EPHEMERAL, NODUS_DEFAULT_TTL,
                               1, 0, &val->signature);
    nodus_value_free(val);

    if (rc == 0) PASS();
    else FAIL("put failed");
}

static void test_get(void) {
    TEST("client get DHT value");
    nodus_key_t key;
    nodus_hash((const uint8_t *)"test-key", 8, &key);

    nodus_value_t *val = NULL;
    int rc = nodus_client_get(&client, &key, &val);

    if (rc == 0 && val && val->data_len > 0 &&
        memcmp(val->data, "hello from client SDK", 21) == 0) {
        PASS();
    } else {
        FAIL("get failed or data mismatch");
    }
    if (val) nodus_value_free(val);
}

static void test_get_not_found(void) {
    TEST("client get returns NOT_FOUND for missing key");
    nodus_key_t key;
    nodus_hash((const uint8_t *)"nonexistent-key-xyz", 19, &key);

    nodus_value_t *val = NULL;
    int rc = nodus_client_get(&client, &key, &val);

    if (rc == NODUS_ERR_NOT_FOUND && val == NULL) PASS();
    else FAIL("expected NOT_FOUND");
    if (val) nodus_value_free(val);
}

static void test_listen(void) {
    TEST("client listen + value_changed notification");

    nodus_key_t key;
    nodus_hash((const uint8_t *)"listen-key", 10, &key);

    int rc = nodus_client_listen(&client, &key);
    if (rc != 0) { FAIL("listen failed"); return; }

    /* Now PUT with the same key using a second client */
    nodus_client_t client2;
    nodus_identity_t id2;
    nodus_identity_generate(&id2);

    nodus_client_config_t cfg2;
    memset(&cfg2, 0, sizeof(cfg2));
    snprintf(cfg2.servers[0].ip, sizeof(cfg2.servers[0].ip), "127.0.0.1");
    cfg2.servers[0].port = 15001;
    cfg2.server_count = 1;
    nodus_client_init(&client2, &cfg2, &id2);
    nodus_client_connect(&client2);

    const char *data = "update";
    nodus_value_t *val = NULL;
    nodus_value_create(&key, (const uint8_t *)data, strlen(data),
                        NODUS_VALUE_EPHEMERAL, NODUS_DEFAULT_TTL,
                        1, 0, &id2.pk, &val);
    nodus_value_sign(val, &id2.sk);
    /* Reset flag BEFORE PUT — read thread may deliver notification instantly */
    got_value_changed = false;
    nodus_client_put(&client2, &key, (const uint8_t *)data, strlen(data),
                      NODUS_VALUE_EPHEMERAL, NODUS_DEFAULT_TTL,
                      1, 0, &val->signature);
    nodus_value_free(val);

    /* Wait for the read thread to deliver the notification */
    for (int i = 0; i < 500 && !got_value_changed; i++) {
        struct timespec ts = { 0, 10000000L }; /* 10ms */
        nanosleep(&ts, NULL);
    }

    if (got_value_changed) PASS();
    else FAIL("no value_changed notification");

    nodus_client_close(&client2);
    nodus_identity_clear(&id2);
}

static void test_unlisten(void) {
    TEST("client unlisten removes subscription");
    nodus_key_t key;
    nodus_hash((const uint8_t *)"listen-key", 10, &key);

    int rc = nodus_client_unlisten(&client, &key);
    if (rc == 0 && client.listen_count == 0) PASS();
    else FAIL("unlisten failed");
}

/* ── Channel tests ──────────────────────────────────────────────── */

static uint8_t test_ch_uuid[NODUS_UUID_BYTES];

static void test_ch_create(void) {
    TEST("client create channel");
    nodus_random(test_ch_uuid, NODUS_UUID_BYTES);
    int rc = nodus_client_ch_create(&client, test_ch_uuid);
    if (rc == 0) PASS();
    else FAIL("ch_create failed");
}

static void test_ch_post(void) {
    TEST("client post to channel");
    uint8_t post_uuid[NODUS_UUID_BYTES];
    nodus_random(post_uuid, NODUS_UUID_BYTES);

    const char *body = "SDK channel message";
    uint64_t ts = nodus_time_now();

    nodus_sig_t sig;
    sign_channel_post(post_uuid, test_ch_uuid, &client_id.node_id,
                       body, ts, &client_id.sk, &sig);

    uint64_t ra = 0;
    int rc = nodus_client_ch_post(&client, test_ch_uuid, post_uuid,
                                   (const uint8_t *)body, strlen(body),
                                   ts, &sig, &ra);
    if (rc == 0 && ra > 0) PASS();
    else FAIL("ch_post failed or bad received_at");
}

static void test_ch_get_posts(void) {
    TEST("client get channel posts");

    nodus_channel_post_t *posts = NULL;
    size_t count = 0;
    int rc = nodus_client_ch_get_posts(&client, test_ch_uuid, 0, 100,
                                        &posts, &count);
    if (rc == 0 && count == 1 && posts &&
        memcmp(posts[0].body, "SDK channel message", 19) == 0) {
        PASS();
    } else {
        FAIL("get_posts failed");
    }
    nodus_client_free_posts(posts, count);
}

static void test_ch_subscribe_notify(void) {
    TEST("client channel subscribe + notification");

    int rc = nodus_client_ch_subscribe(&client, test_ch_uuid);
    if (rc != 0) { FAIL("subscribe failed"); return; }

    /* Post with a second client */
    nodus_client_t client2;
    nodus_identity_t id2;
    nodus_identity_generate(&id2);

    nodus_client_config_t cfg2;
    memset(&cfg2, 0, sizeof(cfg2));
    snprintf(cfg2.servers[0].ip, sizeof(cfg2.servers[0].ip), "127.0.0.1");
    cfg2.servers[0].port = 15001;
    cfg2.server_count = 1;
    nodus_client_init(&client2, &cfg2, &id2);
    nodus_client_connect(&client2);

    uint8_t post_uuid[NODUS_UUID_BYTES];
    nodus_random(post_uuid, NODUS_UUID_BYTES);
    const char *body = "notify test";
    uint64_t ts = nodus_time_now();

    nodus_sig_t sig;
    sign_channel_post(post_uuid, test_ch_uuid, &id2.node_id,
                       body, ts, &id2.sk, &sig);

    /* Reset flag BEFORE post — read thread may deliver notification instantly */
    got_ch_post_notify = false;
    nodus_client_ch_post(&client2, test_ch_uuid, post_uuid,
                          (const uint8_t *)body, strlen(body), ts, &sig, NULL);

    /* Wait for the read thread to deliver the notification */
    for (int i = 0; i < 500 && !got_ch_post_notify; i++) {
        struct timespec ts = { 0, 10000000L }; /* 10ms */
        nanosleep(&ts, NULL);
    }

    if (got_ch_post_notify) PASS();
    else FAIL("no ch_post notification");

    nodus_client_close(&client2);
    nodus_identity_clear(&id2);
}

static void test_ch_unsubscribe(void) {
    TEST("client channel unsubscribe");
    int rc = nodus_client_ch_unsubscribe(&client, test_ch_uuid);
    if (rc == 0 && client.ch_sub_count == 0) PASS();
    else FAIL("unsubscribe failed");
}

static void test_state_check(void) {
    TEST("client state is READY");
    if (nodus_client_state(&client) == NODUS_CLIENT_READY &&
        got_state_ready)
        PASS();
    else
        FAIL("unexpected state");
}

/* ── Multi-server failover test ─────────────────────────────────── */

static void test_failover_bad_server(void) {
    TEST("client failover skips bad server");

    nodus_client_t fc;
    nodus_identity_t fid;
    nodus_identity_generate(&fid);

    nodus_client_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    /* Server 0: unreachable */
    snprintf(cfg.servers[0].ip, sizeof(cfg.servers[0].ip), "127.0.0.1");
    cfg.servers[0].port = 19999;
    /* Server 1: the real server */
    snprintf(cfg.servers[1].ip, sizeof(cfg.servers[1].ip), "127.0.0.1");
    cfg.servers[1].port = 15001;
    cfg.server_count = 2;
    cfg.connect_timeout_ms = 1000;

    nodus_client_init(&fc, &cfg, &fid);
    int rc = nodus_client_connect(&fc);

    if (rc == 0 && nodus_client_is_ready(&fc) && fc.server_idx == 1)
        PASS();
    else
        FAIL("failover did not skip bad server");

    nodus_client_close(&fc);
    nodus_identity_clear(&fid);
}

/* ── Main ───────────────────────────────────────────────────────── */

int main(void) {
    printf("=== Nodus Client SDK Test ===\n\n");

    /* Start server */
    pthread_t srv_tid;
    pthread_create(&srv_tid, NULL, server_thread, NULL);
    while (!server_ready) usleep(10000);
    usleep(100000);  /* Let server settle */

    /* Run tests */
    test_init();
    test_connect();
    test_fingerprint();
    test_state_check();
    test_put();
    test_get();
    test_get_not_found();
    test_listen();
    test_unlisten();
    test_ch_create();
    test_ch_post();
    test_ch_get_posts();
    test_ch_subscribe_notify();
    test_ch_unsubscribe();
    test_failover_bad_server();

    /* Cleanup */
    nodus_client_close(&client);
    nodus_server_stop(&server);
    pthread_join(srv_tid, NULL);

    printf("\n%d/%d tests passed\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
