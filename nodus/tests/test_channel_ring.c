/**
 * Nodus -- Channel Ring Management Unit Tests
 *
 * Tests init, track/untrack, is_tracked, handle_ack, handle_evict.
 * No live TCP connections required.
 */

#include "channel/nodus_channel_ring.h"
#include "channel/nodus_hashring.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) do { tests_run++; printf("  [%d] %-50s ", tests_run, name); } while (0)
#define PASS()     do { tests_passed++; printf("PASS\n"); } while (0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); } while (0)

static void make_uuid(uint8_t out[NODUS_UUID_BYTES], uint8_t fill)
{
    memset(out, fill, NODUS_UUID_BYTES);
}

static void make_key(nodus_key_t *k, uint8_t fill)
{
    memset(k->bytes, fill, NODUS_KEY_BYTES);
}

/* ---- Stubs for functions called by ring module but not tested here ------ */

/* nodus_ch_primary_announce_to_dht: stub (no DHT in unit test) */
int nodus_ch_primary_announce_to_dht(nodus_channel_server_t *cs,
                                      const uint8_t channel_uuid[NODUS_UUID_BYTES])
{
    (void)cs; (void)channel_uuid;
    return 0;
}

/* nodus_ch_notify_ring_changed: stub */
void nodus_ch_notify_ring_changed(nodus_channel_server_t *cs,
                                   const uint8_t channel_uuid[NODUS_UUID_BYTES],
                                   uint32_t new_version)
{
    (void)cs; (void)channel_uuid; (void)new_version;
}

/* nodus_tcp_send: stub */
int nodus_tcp_send(nodus_tcp_conn_t *conn,
                    const uint8_t *payload, size_t len)
{
    (void)conn; (void)payload; (void)len;
    return 0;
}

/* nodus_time_now_ms: stub returning fixed value */
uint64_t nodus_time_now_ms(void)
{
    return 1000000;
}

/* ---- Test: init zeroes everything -------------------------------------- */

static void test_init_zeroed(void)
{
    TEST("init: zeroed state");
    nodus_ch_ring_t rm;
    nodus_channel_server_t cs;
    memset(&cs, 0, sizeof(cs));

    nodus_ch_ring_init(&rm, &cs);

    if (rm.channel_count != 0 || rm.last_tick_ms != 0 || rm.cs != &cs) {
        FAIL("fields not zeroed or cs not set");
        return;
    }

    bool all_inactive = true;
    for (int i = 0; i < NODUS_CH_RING_MAX_TRACKED; i++) {
        if (rm.channels[i].active) { all_inactive = false; break; }
    }
    if (!all_inactive) { FAIL("channels not inactive"); return; }

    PASS();
}

/* ---- Test: track and is_tracked ---------------------------------------- */

static void test_track_basic(void)
{
    TEST("track: add channel, verify tracked");
    nodus_ch_ring_t rm;
    nodus_channel_server_t cs;
    memset(&cs, 0, sizeof(cs));
    nodus_ch_ring_init(&rm, &cs);

    uint8_t uuid[NODUS_UUID_BYTES];
    make_uuid(uuid, 0xAA);

    int rc = nodus_ch_ring_track(&rm, uuid, 1);
    if (rc != 0) { FAIL("track returned non-zero"); return; }
    if (rm.channel_count != 1) { FAIL("channel_count wrong"); return; }
    if (!nodus_ch_ring_is_tracked(&rm, uuid)) { FAIL("not tracked"); return; }

    PASS();
}

/* ---- Test: track duplicate --------------------------------------------- */

static void test_track_duplicate(void)
{
    TEST("track: duplicate returns 0, no double entry");
    nodus_ch_ring_t rm;
    nodus_channel_server_t cs;
    memset(&cs, 0, sizeof(cs));
    nodus_ch_ring_init(&rm, &cs);

    uint8_t uuid[NODUS_UUID_BYTES];
    make_uuid(uuid, 0xBB);

    nodus_ch_ring_track(&rm, uuid, 1);
    int rc = nodus_ch_ring_track(&rm, uuid, 2);
    if (rc != 0) { FAIL("duplicate track should return 0"); return; }
    if (rm.channel_count != 1) { FAIL("should still be 1 entry"); return; }

    PASS();
}

/* ---- Test: track full -------------------------------------------------- */

static void test_track_full(void)
{
    TEST("track: full returns -1 on overflow");
    nodus_ch_ring_t rm;
    nodus_channel_server_t cs;
    memset(&cs, 0, sizeof(cs));
    nodus_ch_ring_init(&rm, &cs);

    /* Fill all slots */
    for (int i = 0; i < NODUS_CH_RING_MAX_TRACKED; i++) {
        uint8_t uuid[NODUS_UUID_BYTES];
        memset(uuid, 0, NODUS_UUID_BYTES);
        uuid[0] = (uint8_t)(i & 0xFF);
        uuid[1] = (uint8_t)((i >> 8) & 0xFF);
        int rc = nodus_ch_ring_track(&rm, uuid, 1);
        if (rc != 0) { FAIL("track failed before full"); return; }
    }

    /* One more should fail */
    uint8_t overflow_uuid[NODUS_UUID_BYTES];
    memset(overflow_uuid, 0xFF, NODUS_UUID_BYTES);
    int rc = nodus_ch_ring_track(&rm, overflow_uuid, 1);
    if (rc != -1) { FAIL("should return -1 when full"); return; }

    PASS();
}

/* ---- Test: untrack ----------------------------------------------------- */

static void test_untrack(void)
{
    TEST("untrack: remove channel, verify not tracked");
    nodus_ch_ring_t rm;
    nodus_channel_server_t cs;
    memset(&cs, 0, sizeof(cs));
    nodus_ch_ring_init(&rm, &cs);

    uint8_t uuid[NODUS_UUID_BYTES];
    make_uuid(uuid, 0xCC);

    nodus_ch_ring_track(&rm, uuid, 1);
    nodus_ch_ring_untrack(&rm, uuid);

    if (nodus_ch_ring_is_tracked(&rm, uuid)) {
        FAIL("still tracked after untrack"); return;
    }

    PASS();
}

/* ---- Test: untrack reuses slot ----------------------------------------- */

static void test_untrack_reuses_slot(void)
{
    TEST("untrack: slot reused on next track");
    nodus_ch_ring_t rm;
    nodus_channel_server_t cs;
    memset(&cs, 0, sizeof(cs));
    nodus_ch_ring_init(&rm, &cs);

    uint8_t uuid1[NODUS_UUID_BYTES], uuid2[NODUS_UUID_BYTES];
    make_uuid(uuid1, 0x01);
    make_uuid(uuid2, 0x02);

    nodus_ch_ring_track(&rm, uuid1, 1);
    nodus_ch_ring_track(&rm, uuid2, 1);
    int count_before = rm.channel_count;  /* Should be 2 */

    nodus_ch_ring_untrack(&rm, uuid1);

    uint8_t uuid3[NODUS_UUID_BYTES];
    make_uuid(uuid3, 0x03);
    nodus_ch_ring_track(&rm, uuid3, 1);

    /* Should reuse the inactive slot, not append */
    if (rm.channel_count != count_before) {
        FAIL("channel_count grew instead of reusing slot"); return;
    }
    if (!nodus_ch_ring_is_tracked(&rm, uuid3)) {
        FAIL("uuid3 not tracked"); return;
    }

    PASS();
}

/* ---- Test: is_tracked returns false for unknown ------------------------ */

static void test_is_tracked_false(void)
{
    TEST("is_tracked: false for unknown channel");
    nodus_ch_ring_t rm;
    nodus_channel_server_t cs;
    memset(&cs, 0, sizeof(cs));
    nodus_ch_ring_init(&rm, &cs);

    uint8_t uuid[NODUS_UUID_BYTES];
    make_uuid(uuid, 0xDD);

    if (nodus_ch_ring_is_tracked(&rm, uuid)) {
        FAIL("should be false for empty ring"); return;
    }

    PASS();
}

/* ---- Test: handle_ack agree -- ring version incremented ---------------- */

static void test_handle_ack_agree(void)
{
    TEST("handle_ack: agree increments ring_version");

    nodus_ch_ring_t rm;
    nodus_channel_server_t cs;
    memset(&cs, 0, sizeof(cs));

    /* Set up hashring with a node that we'll "evict" */
    nodus_hashring_t ring;
    nodus_hashring_init(&ring);

    nodus_key_t dead_id;
    make_key(&dead_id, 0x42);
    nodus_hashring_add(&ring, &dead_id, "10.0.0.1", 4003);
    /* nodus_hashring_add bumps version; record current version */
    uint32_t old_version = ring.version;

    cs.ring = &ring;

    nodus_identity_t ident;
    memset(&ident, 0, sizeof(ident));
    cs.identity = &ident;

    nodus_ch_ring_init(&rm, &cs);

    /* Track a channel and set up a pending check */
    uint8_t uuid[NODUS_UUID_BYTES];
    make_uuid(uuid, 0xEE);
    nodus_ch_ring_track(&rm, uuid, old_version);

    /* Manually set check_pending */
    rm.channels[0].check_pending = true;
    memcpy(&rm.channels[0].check_node_id, &dead_id, sizeof(nodus_key_t));
    int rc = nodus_ch_ring_handle_ack(&rm, uuid, true);
    if (rc != 0) { FAIL("handle_ack returned error"); return; }
    if (ring.version != old_version + 1) {
        FAIL("ring version not incremented"); return;
    }
    if (rm.channels[0].check_pending) {
        FAIL("check_pending not cleared"); return;
    }
    /* Dead node should be removed from ring */
    if (nodus_hashring_contains(&ring, &dead_id)) {
        FAIL("dead node still in hashring"); return;
    }

    PASS();
}

/* ---- Test: handle_ack disagree -- no version change -------------------- */

static void test_handle_ack_disagree(void)
{
    TEST("handle_ack: disagree, no version change");

    nodus_ch_ring_t rm;
    nodus_channel_server_t cs;
    memset(&cs, 0, sizeof(cs));

    nodus_hashring_t ring;
    nodus_hashring_init(&ring);

    nodus_key_t node_id;
    make_key(&node_id, 0x77);
    nodus_hashring_add(&ring, &node_id, "10.0.0.2", 4003);
    uint32_t version_after_add = ring.version;

    cs.ring = &ring;

    nodus_identity_t ident;
    memset(&ident, 0, sizeof(ident));
    cs.identity = &ident;

    nodus_ch_ring_init(&rm, &cs);

    uint8_t uuid[NODUS_UUID_BYTES];
    make_uuid(uuid, 0xFF);
    nodus_ch_ring_track(&rm, uuid, version_after_add);

    rm.channels[0].check_pending = true;
    memcpy(&rm.channels[0].check_node_id, &node_id, sizeof(nodus_key_t));

    int rc = nodus_ch_ring_handle_ack(&rm, uuid, false);
    if (rc != 0) { FAIL("handle_ack returned error"); return; }
    if (ring.version != version_after_add) { FAIL("version changed on disagree"); return; }
    if (nodus_hashring_contains(&ring, &node_id) != true) {
        FAIL("node removed despite disagree"); return;
    }

    PASS();
}

/* ---- Test: handle_ack for unknown channel ------------------------------ */

static void test_handle_ack_unknown(void)
{
    TEST("handle_ack: unknown channel returns -1");

    nodus_ch_ring_t rm;
    nodus_channel_server_t cs;
    memset(&cs, 0, sizeof(cs));
    nodus_ch_ring_init(&rm, &cs);

    uint8_t uuid[NODUS_UUID_BYTES];
    make_uuid(uuid, 0x99);

    int rc = nodus_ch_ring_handle_ack(&rm, uuid, true);
    if (rc != -1) { FAIL("should return -1 for unknown"); return; }

    PASS();
}

/* ---- Test: handle_evict ------------------------------------------------ */

static void test_handle_evict(void)
{
    TEST("handle_evict: channel untracked");

    nodus_ch_ring_t rm;
    nodus_channel_server_t cs;
    memset(&cs, 0, sizeof(cs));
    nodus_ch_ring_init(&rm, &cs);

    uint8_t uuid[NODUS_UUID_BYTES];
    make_uuid(uuid, 0x55);
    nodus_ch_ring_track(&rm, uuid, 3);

    int rc = nodus_ch_ring_handle_evict(&rm, uuid, 4);
    if (rc != 0) { FAIL("handle_evict returned error"); return; }
    if (nodus_ch_ring_is_tracked(&rm, uuid)) {
        FAIL("channel still tracked after evict"); return;
    }

    PASS();
}

/* ---- Main -------------------------------------------------------------- */

int main(void)
{
    printf("=== Nodus Channel Ring Management Tests ===\n\n");

    test_init_zeroed();
    test_track_basic();
    test_track_duplicate();
    test_track_full();
    test_untrack();
    test_untrack_reuses_slot();
    test_is_tracked_false();
    test_handle_ack_agree();
    test_handle_ack_disagree();
    test_handle_ack_unknown();
    test_handle_evict();

    printf("\n%d/%d tests passed\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
