/**
 * Nodus — Witness peer table dedup / slot leak regression tests
 *
 * Exercises nodus_witness_peer_ensure() and asserts the invariant
 *   peer_count == unique(witness_ids across identified slots)
 * under common sequences.
 *
 * One test (test_orphan_slot_from_init) is a documented XFAIL that
 * demonstrates the slot leak bug: when a pre-existing slot has a
 * zero witness_id (as created by nodus_witness_peer_init at startup
 * for seed addresses), a subsequent peer_ensure() call for the real
 * witness_id on the SAME conn creates a NEW slot instead of claiming
 * the orphan — peer_count grows by one despite no new peer.
 *
 * See memory/project_witness_peer_table_slot_leak.md for the full
 * root cause analysis and refactor direction.
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_peer.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_validator.h"
#include "nodus/nodus_chain_config.h"
#include "transport/nodus_tcp.h"

#include "dnac/dnac.h"
#include "dnac/validator.h"
#include "crypto/hash/qgp_sha3.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sqlite3.h>
#include <unistd.h>

#define TEST(name) do { printf("  %-60s", name); } while(0)
#define PASS()     do { printf("PASS\n"); passed++; } while(0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while(0)
#define XFAIL(msg) do { printf("XFAIL (known bug): %s\n", msg); xfailed++; } while(0)

static int passed = 0;
static int failed = 0;
static int xfailed = 0;

static void fill_id(uint8_t *out, uint8_t byte) {
    memset(out, byte, NODUS_T3_WITNESS_ID_LEN);
}

/* Count slots whose witness_id is unique among identified slots. */
static int unique_identified_peers(const nodus_witness_t *w) {
    int unique = 0;
    for (int i = 0; i < w->peer_count; i++) {
        if (!w->peers[i].identified) continue;
        int dup = 0;
        for (int j = 0; j < i; j++) {
            if (!w->peers[j].identified) continue;
            if (memcmp(w->peers[i].witness_id,
                       w->peers[j].witness_id,
                       NODUS_T3_WITNESS_ID_LEN) == 0) {
                dup = 1;
                break;
            }
        }
        if (!dup) unique++;
    }
    return unique;
}

/* ── Tests ───────────────────────────────────────────────────────── */

static void test_single_peer_baseline(void) {
    TEST("baseline: one peer_ensure creates exactly one identified slot");

    static nodus_witness_t w;   /* multi-MB — static storage, not stack */
    memset(&w, 0, sizeof(w));

    uint8_t id[NODUS_T3_WITNESS_ID_LEN];
    fill_id(id, 0xAA);
    struct nodus_tcp_conn c = { .state = NODUS_CONN_CONNECTED };

    nodus_witness_peer_ensure(&w, id, &c);

    if (w.peer_count != 1)       { FAIL("peer_count != 1"); return; }
    if (!w.peers[0].identified)  { FAIL("slot not identified"); return; }
    if (w.peers[0].conn != &c)   { FAIL("conn mismatch"); return; }
    if (unique_identified_peers(&w) != 1) { FAIL("uniqueness broken"); return; }
    PASS();
}

static void test_distinct_peers_distinct_slots(void) {
    TEST("distinct witness_ids create distinct slots");

    static nodus_witness_t w;   /* multi-MB — static storage, not stack */
    memset(&w, 0, sizeof(w));

    uint8_t id1[NODUS_T3_WITNESS_ID_LEN], id2[NODUS_T3_WITNESS_ID_LEN];
    fill_id(id1, 0x11);
    fill_id(id2, 0x22);
    struct nodus_tcp_conn c1 = { .state = NODUS_CONN_CONNECTED };
    struct nodus_tcp_conn c2 = { .state = NODUS_CONN_CONNECTED };

    nodus_witness_peer_ensure(&w, id1, &c1);
    nodus_witness_peer_ensure(&w, id2, &c2);

    if (w.peer_count != 2) { FAIL("peer_count != 2"); return; }
    if (unique_identified_peers(&w) != 2) { FAIL("uniqueness broken"); return; }
    PASS();
}

static void test_reconnect_same_peer_dedupes(void) {
    TEST("reconnect: dead conn adopted by new conn, no new slot");

    static nodus_witness_t w;   /* multi-MB — static storage, not stack */
    memset(&w, 0, sizeof(w));

    uint8_t id[NODUS_T3_WITNESS_ID_LEN];
    fill_id(id, 0xBB);
    struct nodus_tcp_conn c1 = { .state = NODUS_CONN_CONNECTED };
    struct nodus_tcp_conn c2 = { .state = NODUS_CONN_CONNECTED };

    nodus_witness_peer_ensure(&w, id, &c1);

    /* First conn dies */
    c1.state = NODUS_CONN_CLOSED;

    /* Same peer reconnects on a new conn */
    nodus_witness_peer_ensure(&w, id, &c2);

    if (w.peer_count != 1) {
        char buf[80];
        snprintf(buf, sizeof(buf), "peer_count=%d (expected 1)", w.peer_count);
        FAIL(buf);
        return;
    }
    if (w.peers[0].conn != &c2) { FAIL("did not adopt new conn"); return; }
    PASS();
}

static void test_second_inbound_keeps_existing(void) {
    TEST("second inbound on live peer: kept, no duplicate slot");

    static nodus_witness_t w;   /* multi-MB — static storage, not stack */
    memset(&w, 0, sizeof(w));

    uint8_t id[NODUS_T3_WITNESS_ID_LEN];
    fill_id(id, 0x33);
    struct nodus_tcp_conn c1 = { .state = NODUS_CONN_CONNECTED };
    struct nodus_tcp_conn c2 = { .state = NODUS_CONN_CONNECTED };

    nodus_witness_peer_ensure(&w, id, &c1);
    nodus_witness_peer_ensure(&w, id, &c2);

    /* peer_ensure prefers existing live conn; c2 should be ignored */
    if (w.peer_count != 1) {
        char buf[80];
        snprintf(buf, sizeof(buf), "peer_count=%d (expected 1)", w.peer_count);
        FAIL(buf);
        return;
    }
    if (w.peers[0].conn != &c1) { FAIL("slot does not point to c1"); return; }
    PASS();
}

static void test_orphan_slot_from_init(void) {
    TEST("orphan slot (zero witness_id) + peer_ensure same conn");

    static nodus_witness_t w;   /* multi-MB — static storage, not stack */
    memset(&w, 0, sizeof(w));

    /* Simulate nodus_witness_peer_init: a slot for a seed address is
     * created with a live conn but witness_id still zero — the real
     * witness_id will be filled when w_ident arrives. */
    struct nodus_tcp_conn c = { .state = NODUS_CONN_CONNECTED };
    w.peers[0].conn = &c;
    w.peers[0].identified = false;
    /* witness_id stays zero */
    w.peer_count = 1;

    /* Now dispatch_t3 receives a non-IDENT T3 message from witness_id=X
     * on the same conn and calls peer_ensure(X, &c). A CORRECT
     * implementation should recognize the orphan slot (by conn) and
     * fill in the witness_id without creating a new slot. */
    uint8_t id_x[NODUS_T3_WITNESS_ID_LEN];
    fill_id(id_x, 0xCC);
    nodus_witness_peer_ensure(&w, id_x, &c);

    if (w.peer_count == 1) {
        /* Correct behavior — either the bug was fixed or never existed
         * on this code path. Treat as PASS to future-proof the test. */
        PASS();
        return;
    }

    /* Current buggy behavior: peer_count grows because
     * find_peer_by_id(X) misses the orphan slot. */
    char buf[120];
    snprintf(buf, sizeof(buf),
             "peer_count=%d, orphan slot leaked (pre-existing bug)",
             w.peer_count);
    XFAIL(buf);
}

/* ══════════════════════════════════════════════════════════════════════
 * round 5 (R5-6, red-team L1-2) — the TCP 4004 admission gate
 * (`nodus_witness_peer_handle_ident`, nodus_witness_peer.c) now admits a
 * key that is a member of EITHER the committee for `peer_tip + 1`
 * (forward) OR the committee for `peer_tip - 1` (the set cometbft can
 * still be using, its own two-height lag). No test in this tree called
 * `nodus_witness_peer_handle_ident` before this round (grep for
 * `w_ident` / admission across `nodus/tests/` found none) — this is the
 * smallest case that proves it: three ACTIVE validators, a governed
 * TARGET_ACTIVE_COUNT that DIFFERS between epoch 0 (target 2) and epoch
 * E (target 1), so the committee genuinely differs between
 * `peer_tip - 1` (epoch 0, {HIGH, LOW}) and `peer_tip + 1` (epoch E,
 * {HIGH}) — both epochs take the bootstrap path
 * (`e_start < DNAC_EPOCH_LENGTH + 1`, nodus_witness_committee.c:247),
 * which reads the LIVE `validators` table by stake, not a historical
 * snapshot, so no lookback block or tenure setup is needed. LOW is
 * therefore a member of committee(tip-1) but NOT committee(tip+1) — it
 * must be ADMITTED. NONE is a member of neither — it must be REFUSED.
 * ════════════════════════════════════════════════════════════════════ */

static int gate_seed_validator(nodus_witness_t *w, uint8_t fill,
                               uint64_t stake) {
    dnac_validator_record_t v;
    memset(&v, 0, sizeof(v));
    memset(v.pubkey, fill, DNAC_PUBKEY_SIZE);
    v.self_stake = stake;
    v.status = (uint8_t)DNAC_VALIDATOR_ACTIVE;
    v.active_since_block = 1;
    v.commission_bps = 100;
    uint8_t fp_raw[64];
    if (qgp_sha3_512(v.pubkey, DNAC_PUBKEY_SIZE, fp_raw) != 0) return -1;
    static const char hexd[] = "0123456789abcdef";
    for (int i = 0; i < 64; i++) {
        v.unstake_destination_fp[2 * i]     = hexd[fp_raw[i] >> 4];
        v.unstake_destination_fp[2 * i + 1] = hexd[fp_raw[i] & 0xF];
    }
    v.unstake_destination_fp[128] = '\0';
    memset(v.unstake_destination_pubkey, fill, DNAC_PUBKEY_SIZE);
    return nodus_validator_insert(w, &v);
}

/* Governs TARGET_ACTIVE_COUNT at `effective_block`, the same DDL/columns
 * `nodus_witness_chain_config.c`'s own apply path writes
 * (chain_config_history: param_id, new_value, effective_block,
 * commit_block, tx_hash, proposal_nonce, created_at_unix). */
static int gate_seed_target(nodus_witness_t *w, uint64_t effective_block,
                            uint64_t value) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "INSERT INTO chain_config_history (param_id, new_value, "
            "effective_block, commit_block, tx_hash, proposal_nonce, "
            "created_at_unix) VALUES (?1, ?2, ?3, 0, zeroblob(32), 0, 0)",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int(st, 1, (int)DNAC_CFG_TARGET_ACTIVE_COUNT);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)value);
    sqlite3_bind_int64(st, 3, (sqlite3_int64)effective_block);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

/* `MAX(height) FROM blocks` is this test's `peer_tip` — a single
 * explicit-height row is enough (test_committee_cache.c's own
 * `insert_block_row` pattern; `blocks.height` is bindable directly, not
 * autoincrement-only). */
static int gate_seed_block(nodus_witness_t *w, uint64_t height) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "INSERT OR REPLACE INTO blocks (height, tx_root, tx_count, "
            "timestamp, proposer_id, prev_hash, state_root) VALUES "
            "(?1, zeroblob(64), 0, 1000, zeroblob(32), zeroblob(64), "
            "zeroblob(64))", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)height);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

static void test_ident_committee_gate(void) {
    TEST("R5-6: admits via EITHER tip-1/tip+1 committee, refuses neither");

    static nodus_witness_t w;   /* multi-MB — static storage, not stack */
    memset(&w, 0, sizeof(w));
    char dir[] = "/tmp/test_ident_gate_XXXXXX";
    if (!mkdtemp(dir)) { FAIL("mkdtemp"); return; }
    snprintf(w.data_path, sizeof(w.data_path), "%s", dir);

    uint8_t chain_id[16];
    memset(chain_id, 0x77, sizeof(chain_id));
    if (nodus_witness_create_chain_db(&w, chain_id) != 0) {
        FAIL("create_chain_db"); return;
    }
    if (nodus_chain_config_db_migrate(&w) != 0) {
        FAIL("chain_config_db_migrate"); return;
    }

    /* HIGH (3000) always ranks #1; LOW (2000) ranks #2; NONE (1000)
     * never fits inside a target of 1 or 2. */
    if (gate_seed_validator(&w, 0xA1, 3000) != 0 ||
        gate_seed_validator(&w, 0xA2, 2000) != 0 ||
        gate_seed_validator(&w, 0xA3, 1000) != 0) {
        FAIL("seed validators"); return;
    }

    const uint64_t E = (uint64_t)DNAC_EPOCH_LENGTH;
    if (gate_seed_target(&w, 0, 2) != 0 ||
        gate_seed_target(&w, E, 1) != 0) {
        FAIL("seed TARGET_ACTIVE_COUNT rows"); return;
    }
    if (gate_seed_block(&w, E) != 0) { FAIL("seed block row"); return; }

    uint8_t pk_low[DNAC_PUBKEY_SIZE], pk_none[DNAC_PUBKEY_SIZE];
    memset(pk_low, 0xA2, DNAC_PUBKEY_SIZE);
    memset(pk_none, 0xA3, DNAC_PUBKEY_SIZE);
    uint8_t wid_low[NODUS_T3_WITNESS_ID_LEN], wid_none[NODUS_T3_WITNESS_ID_LEN];
    fill_id(wid_low, 0xB2);
    fill_id(wid_none, 0xB3);

    /* Local roster pre-seeded with THIS node's own entry (HIGH), as on a
     * running node. With an empty roster the admitted IDENT would take
     * the roster-gossip branch (`w->roster.n_witnesses <= 1`,
     * nodus_witness_peer.c:969-971) and send_rost_q signs with
     * `&w->server->identity.sk` (nodus_witness_peer.c:1025) — this
     * fixture has no server, and gossip is not the subject here. The
     * IDENT carries no block height, so the size-mismatch branch stays
     * off too: no send on these fake conns. */
    {
        nodus_witness_roster_entry_t self;
        memset(&self, 0, sizeof(self));
        fill_id(self.witness_id, 0xB1);
        memset(self.pubkey, 0xA1, NODUS_PK_BYTES);
        self.active = true;
        if (nodus_witness_roster_add(&w, &self) != 0) {
            FAIL("seed own roster entry"); return;
        }
    }

    struct nodus_tcp_conn c_low  = { .state = NODUS_CONN_CONNECTED };
    struct nodus_tcp_conn c_none = { .state = NODUS_CONN_CONNECTED };

    nodus_t3_msg_t m_low;
    memset(&m_low, 0, sizeof(m_low));
    m_low.ident.witness_id = wid_low;
    m_low.ident.pubkey     = pk_low;
    if (nodus_witness_peer_handle_ident(&w, &c_low, &m_low) != 0) {
        FAIL("LOW (committee(tip-1) only) was refused, should be ADMITTED");
        return;
    }

    nodus_t3_msg_t m_none;
    memset(&m_none, 0, sizeof(m_none));
    m_none.ident.witness_id = wid_none;
    m_none.ident.pubkey     = pk_none;
    if (nodus_witness_peer_handle_ident(&w, &c_none, &m_none) == 0) {
        FAIL("NONE (in neither committee) was admitted, should be REFUSED");
        return;
    }

    PASS();
}

/* ── Main ────────────────────────────────────────────────────────── */

int main(void) {
    printf("Witness peer table dedup / slot leak tests\n");
    printf("==========================================\n");

    test_single_peer_baseline();
    test_distinct_peers_distinct_slots();
    test_reconnect_same_peer_dedupes();
    test_second_inbound_keeps_existing();
    test_orphan_slot_from_init();
    test_ident_committee_gate();

    printf("\nPassed: %d\nFailed: %d\nXFailed: %d\n", passed, failed, xfailed);

    /* XFAIL does not fail the test run — it documents a known bug
     * without blocking CI. Real failures still return nonzero. */
    return failed == 0 ? 0 : 1;
}
