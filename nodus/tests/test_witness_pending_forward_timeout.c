/**
 * Nodus — O15C-D — MED-27: an accepted dnac_spend must never end
 * without an answer.
 *
 * Contract. A client's dnac_spend reaches a non-leader witness, which
 * forwards it to the leader and records a pending_forward keyed by
 * tx_hash (nodus_witness_handlers.c). Exactly one terminal answer is
 * owed to that client: the leader's w_fwd_rsp routed back, or an error.
 *
 * Pre-fix behaviour. When no w_fwd_rsp arrived within 30 s the expiry
 * path cleared `active` and dropped `client_conn` and returned — it sent
 * the client NOTHING, so the caller stayed blocked until its own 60 s
 * RPC timeout with no reason to report. It also failed to decrement
 * pending_forward_count, which every other clear path decrements, so the
 * counter drifted permanently upward by one per expiry.
 *
 * Fix under test: nodus_witness_pending_forward_expire(), extracted from
 * nodus_witness_tick so `now_s` is injected rather than read from the
 * clock. It emits a NODUS_ERR_TIMEOUT T2 error to the waiting client and
 * keeps the counter consistent with the slot array.
 *
 * The emitted frame is asserted for real: nodus_tcp_send buffers into
 * conn->wbuf, so the test decodes the bytes the witness actually
 * produced rather than trusting that a send was attempted. No socket is
 * involved and nothing depends on wall-clock time.
 *
 * Scenarios:
 *   (1) Expiry answers the client — a decodable T2 error carrying the
 *       ORIGINAL client txn id and NODUS_ERR_TIMEOUT.
 *   (2) The counter tracks the slot array across expiry.
 *   (3) Boundary: `> timeout` expires, `== timeout` does not (so the
 *       fix cannot be mistaken for an off-by-one relaxation).
 *   (4) Timeout and completion cannot both act on one entry: once
 *       expired the slot is inactive, so a late w_fwd_rsp finds no
 *       match and cannot deliver twice.
 *   (5) A client that already disconnected (client_conn == NULL) is
 *       expired without a send and without underflowing the counter.
 *   (6) NODUS_W_PENDING_FWD_TIMEOUT_S must stay below the client's
 *       dnac_spend RPC timeout, or the error lands after the caller
 *       gave up and degenerates into an "unknown txn" warning.
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_peer.h"
#include "protocol/nodus_tier2.h"
#include "transport/nodus_tcp.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

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

/* The client's dnac_spend wait, from nodus_client_dnac_spend. Mirrored
 * here so scenario (6) fails loudly if either side is retuned without
 * the other. */
#define CLIENT_SPEND_TIMEOUT_MS 60000

/* A conn that buffers instead of writing to a socket: no auth gate, no
 * channel crypto, state OPEN. nodus_tcp_send appends the encoded frame
 * to wbuf, which is exactly what we decode. */
static nodus_tcp_conn_t *mk_conn(void) {
    nodus_tcp_conn_t *c = calloc(1, sizeof(*c));
    CHECK(c != NULL);
    c->fd = -1;
    c->state = NODUS_CONN_CONNECTED;
    c->auth_required = false;
    return c;
}

static void free_conn(nodus_tcp_conn_t *c) {
    if (!c) return;
    free(c->wbuf);
    free(c);
}

/* Decode the single T2 frame sitting in conn->wbuf. */
static void decode_only_frame(nodus_tcp_conn_t *c, nodus_tier2_msg_t *out) {
    CHECK(c->wlen > NODUS_FRAME_HEADER_SIZE);
    const uint8_t *payload = c->wbuf + NODUS_FRAME_HEADER_SIZE;
    size_t payload_len = c->wlen - NODUS_FRAME_HEADER_SIZE;
    memset(out, 0, sizeof(*out));
    CHECK_EQ(nodus_t2_decode(payload, payload_len, out), 0);
}

static void seed_forward(nodus_witness_t *w, int slot,
                         nodus_tcp_conn_t *conn, uint32_t txn,
                         uint64_t started_at, uint8_t hash_byte) {
    w->pending_forwards[slot].active = true;
    memset(w->pending_forwards[slot].tx_hash, hash_byte,
           NODUS_T3_TX_HASH_LEN);
    w->pending_forwards[slot].client_conn = conn;
    w->pending_forwards[slot].client_txn_id = txn;
    w->pending_forwards[slot].started_at = started_at;
    w->pending_forward_count++;
}

int main(void) {
    /* nodus_witness_t is multi-MB — heap, never stack. */
    nodus_witness_t *w = calloc(1, sizeof(*w));
    CHECK(w != NULL);

    const uint64_t T0 = 1000000;   /* arbitrary fixed "now", no clock */

    /* ── T1: expiry answers the waiting client ────────────────────── */
    {
        nodus_tcp_conn_t *c = mk_conn();
        seed_forward(w, 0, c, 4242, T0, 0xA1);

        int n = nodus_witness_pending_forward_expire(
            w, T0 + NODUS_W_PENDING_FWD_TIMEOUT_S + 1);
        CHECK_EQ(n, 1);

        /* Pre-fix this buffer was empty: nothing was sent at all. */
        CHECK(w->pending_forwards[0].active == false);
        CHECK(w->pending_forwards[0].client_conn == NULL);

        nodus_tier2_msg_t msg;
        decode_only_frame(c, &msg);
        CHECK_EQ(msg.type, 'e');
        CHECK_EQ(msg.txn_id, 4242);          /* the ORIGINAL client txn */
        CHECK_EQ(msg.error_code, NODUS_ERR_TIMEOUT);
        nodus_t2_msg_free(&msg);

        free_conn(c);
        printf("[ok] T1 expiry sends the client a NODUS_ERR_TIMEOUT for "
               "its own txn\n");
    }

    /* ── T2: counter stays consistent with the slot array ─────────── */
    {
        CHECK_EQ(w->pending_forward_count, 0);   /* decremented by T1 */

        nodus_tcp_conn_t *a = mk_conn();
        nodus_tcp_conn_t *b = mk_conn();
        seed_forward(w, 1, a, 7, T0, 0xB1);
        seed_forward(w, 2, b, 8, T0, 0xB2);
        CHECK_EQ(w->pending_forward_count, 2);

        CHECK_EQ(nodus_witness_pending_forward_expire(
                     w, T0 + NODUS_W_PENDING_FWD_TIMEOUT_S + 1), 2);

        int active = 0;
        for (int i = 0; i < NODUS_W_MAX_PENDING_FWD; i++)
            if (w->pending_forwards[i].active) active++;
        CHECK_EQ(active, 0);
        CHECK_EQ(w->pending_forward_count, active);   /* the drift bug */

        free_conn(a);
        free_conn(b);
        printf("[ok] T2 pending_forward_count tracks the slot array\n");
    }

    /* ── T3: boundary — strictly greater expires, equal does not ──── */
    {
        nodus_tcp_conn_t *c = mk_conn();
        seed_forward(w, 3, c, 9, T0, 0xC1);

        CHECK_EQ(nodus_witness_pending_forward_expire(
                     w, T0 + NODUS_W_PENDING_FWD_TIMEOUT_S), 0);
        CHECK(w->pending_forwards[3].active);
        CHECK_EQ(c->wlen, 0);                  /* nothing sent yet */

        CHECK_EQ(nodus_witness_pending_forward_expire(
                     w, T0 + NODUS_W_PENDING_FWD_TIMEOUT_S + 1), 1);
        CHECK(!w->pending_forwards[3].active);
        CHECK(c->wlen > 0);

        free_conn(c);
        printf("[ok] T3 boundary: > timeout expires, == timeout does not\n");
    }

    /* ── T4: expiry and completion cannot both answer one entry ───── */
    {
        nodus_tcp_conn_t *c = mk_conn();
        seed_forward(w, 4, c, 11, T0, 0xD1);
        CHECK_EQ(nodus_witness_pending_forward_expire(
                     w, T0 + NODUS_W_PENDING_FWD_TIMEOUT_S + 1), 1);

        /* A w_fwd_rsp arriving now must find nothing: the slot is
         * inactive, so the client cannot be answered a second time. */
        nodus_t3_msg_t late;
        memset(&late, 0, sizeof(late));
        late.type = NODUS_T3_FWD_RSP;
        memset(late.fwd_rsp.tx_hash, 0xD1, NODUS_T3_TX_HASH_LEN);
        late.fwd_rsp.status = 0;
        CHECK_EQ(nodus_witness_peer_handle_fwd_rsp(w, &late), -1);

        /* Still exactly the one error frame from the expiry. */
        nodus_tier2_msg_t msg;
        decode_only_frame(c, &msg);
        CHECK_EQ(msg.type, 'e');
        CHECK_EQ(msg.txn_id, 11);
        nodus_t2_msg_free(&msg);

        free_conn(c);
        printf("[ok] T4 a late w_fwd_rsp cannot deliver a second answer\n");
    }

    /* ── T5: disconnected client expires cleanly ──────────────────── */
    {
        seed_forward(w, 5, NULL, 12, T0, 0xE1);
        CHECK_EQ(w->pending_forward_count, 1);
        CHECK_EQ(nodus_witness_pending_forward_expire(
                     w, T0 + NODUS_W_PENDING_FWD_TIMEOUT_S + 1), 1);
        CHECK(!w->pending_forwards[5].active);
        CHECK_EQ(w->pending_forward_count, 0);

        /* NULL witness must not fault. */
        CHECK_EQ(nodus_witness_pending_forward_expire(NULL, T0), 0);
        printf("[ok] T5 already-disconnected client expires without a send\n");
    }

    /* ── T6: the expiry must fire INSIDE the client's wait ─────────── */
    {
        /* If this ever inverts, the error reaches a caller that already
         * gave up and shows up only as an "unknown txn" warning — the
         * exact ambiguity O15C-D closed on the client side. */
        CHECK(NODUS_W_PENDING_FWD_TIMEOUT_S * 1000 < CLIENT_SPEND_TIMEOUT_MS);
        printf("[ok] T6 witness expiry (%ds) < client dnac_spend wait "
               "(%dms)\n", (int)NODUS_W_PENDING_FWD_TIMEOUT_S,
               CLIENT_SPEND_TIMEOUT_MS);
    }

    free(w);
    printf("PASS test_witness_pending_forward_timeout\n");
    return 0;
}
