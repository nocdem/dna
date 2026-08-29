/**
 * Nodus — an unauthenticated IDENT must not move this node's PBFT view.
 *
 * ── WHAT THIS PROVES ─────────────────────────────────────────────────
 *
 * `w->current_view` is the PBFT view counter. It decides BOTH the leader
 * (nodus_witness_bft_leader_index(epoch, view, n) = (epoch+view)%n,
 * nodus_witness_bft.c:584) AND what gets signed (compute_prepared_preimage
 * reads it — nodus_witness_bft.c:4249 leader side, :5303 follower side).
 *
 * Until v0.19.24 nodus_witness_peer_handle_ident adopted a peer's
 * advertised `current_view` straight off the wire, bounded only by a
 * delta <= 10000 test. T3 IDENT is EXEMPT from the wsig signature verify
 * (`if (msg.type != NODUS_T3_IDENT)`, nodus_witness.c:2011), and the
 * dispatcher's own comment at nodus_witness.c:2055-2056 says an IDENT's
 * claim "is unauthenticated and must not be acted on". So ONE
 * unauthenticated peer could move this node's leader election and the
 * bytes it signs. The adoption is deleted; this test pins the deletion.
 *
 * The property that would be FALSE if this test failed: an
 * unauthenticated IDENT claiming a higher view cannot move this node's
 * PBFT view counter. Reference model: CometBFT/Tendermint receives the
 * identical peer-round announcement and writes it to PeerRoundState
 * only — never to `cs.Round`.
 *
 * ── WHAT IT REQUIRES ─────────────────────────────────────────────────
 *
 * Nothing beyond a DEFAULT build. No compile flags (no
 * -DQGP_FAULT_INJECT, no -DDNAC_EPOCH_LENGTH override), no environment
 * variables, no running cluster, no chain database, no network. The
 * witness fixture is a zeroed heap struct and the TCP connection is a
 * stack stub that is never written to.
 *
 * ── WHAT IT LEAVES BEHIND ────────────────────────────────────────────
 *
 * Nothing. No files, no directories, no node dirs, no arm files, no
 * sockets, no processes. The single heap allocation is freed.
 *
 * ── HOW IT CAN LIE ───────────────────────────────────────────────────
 *
 * The dangerous false-PASS is the handler REFUSING the message early:
 * `current_view` would then still read 5 while never having reached the
 * deleted block at all. Three assertions close that hole and must not
 * be removed:
 *   - the handler's return value is 0 (not the -1 of the committee
 *     admission gate or the missing-field guard);
 *   - `remote_height` was written from the IDENT, and
 *   - `remote_checksum` matches the IDENT's state_root byte for byte.
 * Those last two are set in the SAME `if (ident->has_block_height)`
 * body that used to hold the adoption, immediately above where it sat —
 * so if they are correct the deleted site was genuinely executed past.
 *
 * A second way to lie would be for the roster-gossip branch to fire and
 * call send_rost_q() on the stub connection; the fixture pins
 * roster_size == n_witnesses == 2 precisely so that branch is not taken.
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_peer.h"
#include "transport/nodus_tcp.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define CHECK(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK fail at %s:%d: %s\n", \
                __FILE__, __LINE__, #cond); \
        exit(1); \
    } } while (0)

#define CHECK_EQ(a, b) do { \
    long long _a = (long long)(a), _b = (long long)(b); \
    if (_a != _b) { \
        fprintf(stderr, "CHECK_EQ fail at %s:%d: %lld != %lld\n", \
                __FILE__, __LINE__, _a, _b); \
        exit(1); \
    } } while (0)

/* The node's own view, chosen so that every probe below is strictly
 * higher — the only direction the deleted block ever moved it. */
#define LOCAL_VIEW      5u

#define PEER_ID_BYTE    0xAAu
#define PEER_PK_BYTE    0xBBu
#define OTHER_ID_BYTE   0xCCu
#define PEER_ADDRESS    "192.0.2.7:4004"

static uint8_t peer_id[NODUS_T3_WITNESS_ID_LEN];
static uint8_t peer_pk[NODUS_PK_BYTES];

/* Seed a roster the handler will RECOGNISE, so it takes the ordinary
 * known-peer path: no roster_add, and n_witnesses stays at 2. Two
 * entries (not one) matter — the gossip branch fires unconditionally
 * when n_witnesses <= 1, which would reach send_rost_q on the stub
 * connection. */
static void seed_roster(nodus_witness_t *w) {
    memset(&w->roster, 0, sizeof(w->roster));

    memcpy(w->roster.witnesses[0].witness_id, peer_id,
           NODUS_T3_WITNESS_ID_LEN);
    memcpy(w->roster.witnesses[0].pubkey, peer_pk, NODUS_PK_BYTES);
    snprintf(w->roster.witnesses[0].address,
             sizeof(w->roster.witnesses[0].address), "%s", PEER_ADDRESS);
    w->roster.witnesses[0].active = true;

    memset(w->roster.witnesses[1].witness_id, OTHER_ID_BYTE,
           NODUS_T3_WITNESS_ID_LEN);
    memset(w->roster.witnesses[1].pubkey, 0xDD, NODUS_PK_BYTES);
    snprintf(w->roster.witnesses[1].address,
             sizeof(w->roster.witnesses[1].address), "192.0.2.8:4004");
    w->roster.witnesses[1].active = true;

    w->roster.n_witnesses = 2;
}

/* Build the w_ident a peer would put on the wire. `claimed_view` is the
 * only field that varies between scenarios. */
static void build_ident(nodus_t3_msg_t *msg,
                        uint32_t claimed_view,
                        uint64_t claimed_height,
                        uint8_t state_root_byte) {
    memset(msg, 0, sizeof(*msg));
    msg->type = NODUS_T3_IDENT;
    snprintf(msg->method, sizeof(msg->method), "w_ident");

    msg->ident.witness_id = peer_id;
    msg->ident.pubkey     = peer_pk;
    snprintf(msg->ident.address, sizeof(msg->ident.address),
             "%s", PEER_ADDRESS);

    msg->ident.has_block_height = true;
    msg->ident.block_height     = claimed_height;
    memset(msg->ident.state_root, state_root_byte, NODUS_KEY_BYTES);
    msg->ident.current_view     = claimed_view;

    /* Equal to the local roster size, so the gossip branch stays shut
     * and send_rost_q() is never reached with the stub connection. */
    msg->ident.roster_size = 2;
    msg->ident.ts_local    = (uint64_t)time(NULL);
}

/* Locate the peer slot the handler upserted, by identity rather than by
 * assuming index 0. */
static int find_peer_slot(const nodus_witness_t *w) {
    for (int i = 0; i < w->peer_count; i++) {
        if (memcmp(w->peers[i].witness_id, peer_id,
                   NODUS_T3_WITNESS_ID_LEN) == 0)
            return i;
    }
    return -1;
}

/* Drive the REAL handler and assert the whole post-condition:
 *   - the view counter did NOT move, and
 *   - the peer state that MUST still be learned from an IDENT was. */
static void run_probe(nodus_witness_t *w,
                      struct nodus_tcp_conn *conn,
                      uint32_t claimed_view,
                      uint64_t claimed_height,
                      uint8_t state_root_byte,
                      const char *label) {
    nodus_t3_msg_t msg;
    build_ident(&msg, claimed_view, claimed_height, state_root_byte);

    int rc = nodus_witness_peer_handle_ident(w, conn, &msg);

    /* Not an early refusal: the handler ran to completion. */
    CHECK_EQ(rc, 0);

    int pi = find_peer_slot(w);
    CHECK(pi >= 0);

    /* THE PROPERTY: an unauthenticated claim cannot move the counter. */
    CHECK_EQ(w->current_view, LOCAL_VIEW);

    /* Non-vacuity: the has_block_height body — the exact block the
     * adoption used to sit in — really did execute. */
    CHECK_EQ(w->peers[pi].remote_height, claimed_height);

    uint8_t expect_root[NODUS_KEY_BYTES];
    memset(expect_root, state_root_byte, NODUS_KEY_BYTES);
    CHECK_EQ(memcmp(w->peers[pi].remote_checksum, expect_root,
                    NODUS_KEY_BYTES), 0);

    printf("[ok] %s: claimed view %u ignored, view still %u "
           "(height %llu and state_root learned)\n",
           label, claimed_view, w->current_view,
           (unsigned long long)w->peers[pi].remote_height);
}

int main(void) {
    printf("Witness IDENT view-adoption removal (O15 / v0.19.24)\n");
    printf("=====================================================\n");

    memset(peer_id, PEER_ID_BYTE, sizeof(peer_id));
    memset(peer_pk, PEER_PK_BYTE, sizeof(peer_pk));

    /* nodus_witness_t is multi-MB — heap, never stack. */
    nodus_witness_t *w = calloc(1, sizeof(*w));
    CHECK(w != NULL);

    seed_roster(w);
    w->current_view = LOCAL_VIEW;

    /* A calloc'd witness has running == false, so nodus_witness_sync_check
     * (called at the end of the handler) returns immediately, and db ==
     * NULL, so the committee admission gate resolves an empty committee
     * and accepts liberally. Neither touches the view counter. */
    struct nodus_tcp_conn conn = { .state = NODUS_CONN_CONNECTED };

    /* ── T1: a plausible higher view (the case the deleted code took) ─
     * delta = 895, comfortably inside the old <= 10000 bound, so the
     * pre-v0.19.24 build WOULD have adopted 900 here. */
    run_probe(w, &conn, 900u, 4242ull, 0x5A, "T1 higher view");

    /* ── T2: the exact boundary the old bound admitted ────────────────
     * delta == 10000 satisfied `delta <= 10000`, so this is the largest
     * jump the deleted code accepted. It must be as inert as any other. */
    run_probe(w, &conn, LOCAL_VIEW + 10000u, 4243ull, 0x6B,
              "T2 boundary delta=10000");

    /* ── T3: far beyond the old bound ─────────────────────────────────
     * The old code REJECTED this one, so on its own it could not tell a
     * fixed build from a broken one. It is here to show the distinction
     * no longer exists: bounded or unbounded, the claim is inert. */
    run_probe(w, &conn, 50000u, 4244ull, 0x7C, "T3 delta>10000");

    /* The counter never moved across all three, and exactly one peer
     * slot was used — the handler deduped rather than growing the table
     * on every IDENT. */
    CHECK_EQ(w->current_view, LOCAL_VIEW);
    CHECK_EQ(w->peer_count, 1);
    CHECK_EQ(w->roster.n_witnesses, 2);

    free(w);
    printf("PASS test_witness_ident_no_view_adopt\n");
    return 0;
}
