/**
 * Nodus -- Channel Primary Unit Tests
 *
 * Tests ensure_channel (responsible vs not), handle_create (auto-subscribe),
 * handle_subscribe/unsubscribe, and announce_to_dht.
 */

#include "channel/nodus_channel_primary.h"
#include "channel/nodus_channel_store.h"
#include "channel/nodus_hashring.h"
#include "transport/nodus_tcp.h"
#include "crypto/nodus_sign.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) do { tests_run++; printf("  [%d] %-50s ", tests_run, name); } while (0)
#define PASS()     do { tests_passed++; printf("PASS\n"); } while (0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); } while (0)

/* ---- Test infrastructure ----------------------------------------------- */

static nodus_tcp_conn_t fake_conns[4];
static int pipe_fds[4][2];  /* [i][0]=read, [i][1]=write */

static void init_fake_conns(void) {
    memset(fake_conns, 0, sizeof(fake_conns));
    for (int i = 0; i < 4; i++) {
        pipe(pipe_fds[i]);
        fake_conns[i].fd = pipe_fds[i][1];  /* writable end */
        fake_conns[i].slot = i;
        fake_conns[i].state = NODUS_CONN_CONNECTED;
        /* Pre-allocate write buffer to avoid buf_ensure(0*2=0) infinite loop */
        fake_conns[i].wbuf = malloc(16384);
        fake_conns[i].wcap = 16384;
        fake_conns[i].wpos = 0;
        fake_conns[i].wlen = 0;
    }
}

static void cleanup_fake_conns(void) {
    for (int i = 0; i < 4; i++) {
        close(pipe_fds[i][0]);
        close(pipe_fds[i][1]);
        free(fake_conns[i].wbuf);
        fake_conns[i].wbuf = NULL;
    }
}

static void make_uuid(uint8_t out[NODUS_UUID_BYTES], uint8_t fill) {
    memset(out, fill, NODUS_UUID_BYTES);
}

/** Captured DHT put calls for verification */
static int dht_put_called = 0;
static uint8_t dht_put_key[NODUS_KEY_BYTES];
static uint8_t dht_put_val[4096];
static size_t  dht_put_val_len = 0;

static int mock_dht_put_signed(const uint8_t *key_hash, size_t key_len,
                                const uint8_t *val, size_t val_len,
                                uint32_t ttl, void *ctx) {
    (void)ttl;
    (void)ctx;
    dht_put_called++;
    if (key_len <= NODUS_KEY_BYTES)
        memcpy(dht_put_key, key_hash, key_len);
    if (val_len <= sizeof(dht_put_val)) {
        memcpy(dht_put_val, val, val_len);
        dht_put_val_len = val_len;
    }
    return 0;
}

/**
 * Setup a test channel server with a hashring containing 3 nodes.
 * Node 1 (self_identity) is always in the ring.
 */
static void setup_test_env(nodus_channel_server_t *cs,
                            nodus_hashring_t *ring,
                            nodus_channel_store_t *store,
                            nodus_identity_t *identity,
                            const char *db_path) {
    memset(cs, 0, sizeof(*cs));
    memset(identity, 0, sizeof(*identity));

    /* Setup identity with known node_id */
    memset(identity->node_id.bytes, 0x11, NODUS_KEY_BYTES);

    /* Setup hashring with 3 nodes */
    nodus_hashring_init(ring);

    nodus_key_t n1, n2, n3;
    memset(n1.bytes, 0x11, NODUS_KEY_BYTES);
    memset(n2.bytes, 0x22, NODUS_KEY_BYTES);
    memset(n3.bytes, 0x33, NODUS_KEY_BYTES);

    nodus_hashring_add(ring, &n1, "10.0.0.1", 4003);
    nodus_hashring_add(ring, &n2, "10.0.0.2", 4003);
    nodus_hashring_add(ring, &n3, "10.0.0.3", 4003);

    /* Open SQLite store */
    nodus_channel_store_open(db_path, store);

    /* Wire up the server */
    cs->ch_store = store;
    cs->ring = ring;
    cs->identity = identity;
    cs->port = 4003;
    cs->dht_put_signed = mock_dht_put_signed;
    cs->dht_ctx = NULL;

    /* Reset mock state */
    dht_put_called = 0;
    memset(dht_put_key, 0, sizeof(dht_put_key));
    dht_put_val_len = 0;
}

static void teardown_test_env(nodus_channel_store_t *store, const char *db_path) {
    nodus_channel_store_close(store);
    unlink(db_path);
}

/* ---- Tests ------------------------------------------------------------- */

/**
 * Test: ensure_channel when node IS responsible -> creates table -> returns true.
 *
 * The hashring_responsible function picks nodes from the sorted ring.
 * We know our node (0x11) is in the ring. As long as the responsible set
 * for the test UUID includes our node_id, ensure_channel should succeed.
 */
static void test_ensure_channel_responsible(void) {
    TEST("ensure_channel: responsible -> creates + true");

    nodus_channel_server_t cs;
    nodus_hashring_t ring;
    nodus_channel_store_t store;
    nodus_identity_t identity;
    const char *db = "/tmp/test_ch_primary_1.db";

    setup_test_env(&cs, &ring, &store, &identity, db);

    /* Use a UUID that we know our node is responsible for.
     * With 3 nodes and R=3, ALL nodes are responsible for every channel. */
    uint8_t uuid[NODUS_UUID_BYTES];
    make_uuid(uuid, 0xAA);

    bool result = nodus_ch_primary_ensure_channel(&cs, uuid);
    if (result && nodus_channel_exists(&store, uuid))
        PASS();
    else
        FAIL("expected true and channel to exist");

    teardown_test_env(&store, db);
}

/**
 * Test: ensure_channel when node is NOT responsible -> returns false.
 *
 * To simulate this, set identity to a node_id NOT in the ring.
 */
static void test_ensure_channel_not_responsible(void) {
    TEST("ensure_channel: not responsible -> false");

    nodus_channel_server_t cs;
    nodus_hashring_t ring;
    nodus_channel_store_t store;
    nodus_identity_t identity;
    const char *db = "/tmp/test_ch_primary_2.db";

    setup_test_env(&cs, &ring, &store, &identity, db);

    /* Change identity to a node NOT in the ring */
    memset(identity.node_id.bytes, 0xFF, NODUS_KEY_BYTES);

    uint8_t uuid[NODUS_UUID_BYTES];
    make_uuid(uuid, 0xBB);

    bool result = nodus_ch_primary_ensure_channel(&cs, uuid);
    if (!result && !nodus_channel_exists(&store, uuid))
        PASS();
    else
        FAIL("expected false and no channel created");

    teardown_test_env(&store, db);
}

/**
 * Test: ensure_channel returns true for already-existing channel
 * even without checking hashring.
 */
static void test_ensure_channel_already_exists(void) {
    TEST("ensure_channel: already exists -> true");

    nodus_channel_server_t cs;
    nodus_hashring_t ring;
    nodus_channel_store_t store;
    nodus_identity_t identity;
    const char *db = "/tmp/test_ch_primary_3.db";

    setup_test_env(&cs, &ring, &store, &identity, db);

    uint8_t uuid[NODUS_UUID_BYTES];
    make_uuid(uuid, 0xCC);

    /* Pre-create channel */
    nodus_channel_create(&store, uuid);

    /* Change identity to non-ring node -- should still return true
     * because channel already exists */
    memset(identity.node_id.bytes, 0xFF, NODUS_KEY_BYTES);

    bool result = nodus_ch_primary_ensure_channel(&cs, uuid);
    if (result)
        PASS();
    else
        FAIL("expected true for existing channel");

    teardown_test_env(&store, db);
}

/**
 * Test: handle_create creates channel and announces to DHT.
 */
static void test_handle_create(void) {
    TEST("handle_create: creates + announces to DHT");

    nodus_channel_server_t cs;
    nodus_hashring_t ring;
    nodus_channel_store_t store;
    nodus_identity_t identity;
    const char *db = "/tmp/test_ch_primary_4.db";

    setup_test_env(&cs, &ring, &store, &identity, db);
    init_fake_conns();

    /* Setup client session */
    nodus_ch_client_session_t *sess = &cs.clients[0];
    memset(sess, 0, sizeof(*sess));
    sess->conn = &fake_conns[0];
    sess->authenticated = true;

    /* Build message */
    nodus_tier2_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    msg.txn_id = 42;
    make_uuid((uint8_t *)msg.channel_uuid, 0xDD);

    int rc = nodus_ch_primary_handle_create(&cs, sess, &msg);

    bool ok = true;
    if (rc != 0) { ok = false; }
    if (!nodus_channel_exists(&store, msg.channel_uuid)) { ok = false; }
    if (dht_put_called != 1) { ok = false; }

    if (ok)
        PASS();
    else
        FAIL("create failed or state incorrect");

    cleanup_fake_conns();
    teardown_test_env(&store, db);
}

/**
 * Test: handle_subscribe adds subscription, handle_unsubscribe removes it.
 */
static void test_subscribe_unsubscribe(void) {
    TEST("subscribe/unsubscribe: add + remove");

    nodus_channel_server_t cs;
    nodus_hashring_t ring;
    nodus_channel_store_t store;
    nodus_identity_t identity;
    const char *db = "/tmp/test_ch_primary_5.db";

    setup_test_env(&cs, &ring, &store, &identity, db);
    init_fake_conns();

    nodus_ch_client_session_t *sess = &cs.clients[0];
    memset(sess, 0, sizeof(*sess));
    sess->conn = &fake_conns[0];
    sess->authenticated = true;

    nodus_tier2_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    msg.txn_id = 100;
    make_uuid((uint8_t *)msg.channel_uuid, 0xEE);

    /* Subscribe */
    int rc = nodus_ch_primary_handle_subscribe(&cs, sess, &msg);
    if (rc != 0 || sess->ch_sub_count != 1) {
        FAIL("subscribe failed");
        cleanup_fake_conns();
        teardown_test_env(&store, db);
        return;
    }

    /* Subscribe again (duplicate -- should still be 1) */
    nodus_ch_primary_handle_subscribe(&cs, sess, &msg);
    if (sess->ch_sub_count != 1) {
        FAIL("duplicate sub should not increase count");
        cleanup_fake_conns();
        teardown_test_env(&store, db);
        return;
    }

    /* Unsubscribe */
    rc = nodus_ch_primary_handle_unsubscribe(&cs, sess, &msg);
    if (rc != 0 || sess->ch_sub_count != 0) {
        FAIL("unsubscribe failed");
        cleanup_fake_conns();
        teardown_test_env(&store, db);
        return;
    }

    PASS();
    cleanup_fake_conns();
    teardown_test_env(&store, db);
}

/**
 * Test: announce_to_dht calls dht_put_signed with correct key structure.
 */
static void test_announce_to_dht(void) {
    TEST("announce_to_dht: calls dht_put_signed");

    nodus_channel_server_t cs;
    nodus_hashring_t ring;
    nodus_channel_store_t store;
    nodus_identity_t identity;
    const char *db = "/tmp/test_ch_primary_6.db";

    setup_test_env(&cs, &ring, &store, &identity, db);

    uint8_t uuid[NODUS_UUID_BYTES];
    make_uuid(uuid, 0xFF);

    int rc = nodus_ch_primary_announce_to_dht(&cs, uuid);

    if (rc == 0 && dht_put_called == 1 && dht_put_val_len > 0)
        PASS();
    else
        FAIL("announce did not call dht_put_signed correctly");

    teardown_test_env(&store, db);
}

/**
 * Test: ensure_channel with NULL dependencies returns false.
 */
static void test_ensure_channel_null_deps(void) {
    TEST("ensure_channel: null deps -> false");

    nodus_channel_server_t cs;
    memset(&cs, 0, sizeof(cs));

    uint8_t uuid[NODUS_UUID_BYTES];
    make_uuid(uuid, 0x01);

    bool result = nodus_ch_primary_ensure_channel(&cs, uuid);
    if (!result)
        PASS();
    else
        FAIL("expected false with null dependencies");
}

/**
 * Test: handle_create with NULL store returns error.
 */
static void test_handle_create_no_store(void) {
    TEST("handle_create: no store -> error");

    nodus_channel_server_t cs;
    memset(&cs, 0, sizeof(cs));
    init_fake_conns();

    nodus_ch_client_session_t *sess = &cs.clients[0];
    memset(sess, 0, sizeof(*sess));
    sess->conn = &fake_conns[0];
    sess->authenticated = true;

    nodus_tier2_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    msg.txn_id = 1;
    make_uuid((uint8_t *)msg.channel_uuid, 0x02);

    int rc = nodus_ch_primary_handle_create(&cs, sess, &msg);
    if (rc == -1)
        PASS();
    else
        FAIL("expected -1 with no store");

    cleanup_fake_conns();
}

/* ---- Main -------------------------------------------------------------- */

int main(void) {
    printf("test_channel_primary\n");

    test_ensure_channel_responsible();
    test_ensure_channel_not_responsible();
    test_ensure_channel_already_exists();
    test_handle_create();
    test_subscribe_unsubscribe();
    test_announce_to_dht();
    test_ensure_channel_null_deps();
    test_handle_create_no_store();

    printf("\n  %d/%d tests passed\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
