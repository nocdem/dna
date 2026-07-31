/**
 * Nodus — spend-result failure-path contract test (K1 / K2)
 *
 * K2: when the leader's batch commit fails, the block was rolled back
 * and every client whose TX was in that batch must be told ERROR — the
 * old code fell through and emitted a SIGNED APPROVED receipt for a
 * block that does not exist.
 *
 * The emitter has a trap. nodus_witness_send_spend_result() takes the
 * error branch only when BOTH conditions hold:
 *
 *     if (status != DNAC_STATUS_APPROVED && error_msg)   <- handlers.c:2161
 *
 * A non-APPROVED status with a NULL message falls THROUGH that branch
 * and still emits the signed receipt — the client would read an
 * attestation for a block that never landed. bft_emit_batch_replies
 * therefore substitutes a message when a caller passes a non-APPROVED
 * status with none, and this test pins both halves of that contract:
 *
 *   1. status=ERROR + message  → T2 error frame, NO receipt.
 *   2. status=ERROR + NULL     → receipt anyway (the trap), which is
 *                                exactly why the guard exists.
 *
 * Observation is direct and offline: the conn's fd is -1, so the
 * frame nodus_tcp_send builds stays in conn->wbuf (send_progress
 * breaks out of its write loop on the failed write) and we decode it
 * in place. No sockets, no poll, no timing, no randomness.
 *
 * NOT COVERED HERE (stated plainly rather than faked): the K1 early
 * return itself — "leader whose batch failed broadcasts no COMMIT" —
 * lives inside handle_vote's PRECOMMIT-quorum branch, which is only
 * reachable with a full committee of Dilithium-signed peer votes. That
 * needs the 7-node Genesis Protocol harness, not a unit fixture.
 */

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_handlers.h"
#include "witness/nodus_witness_mempool.h"
#include "server/nodus_server.h"
#include "transport/nodus_tcp.h"
#include "protocol/nodus_wire.h"
#include "crypto/nodus_identity.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEST(name) do { printf("  %-58s", name); } while (0)
#define PASS()     do { printf("PASS\n"); passed++; } while (0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while (0)

static int passed = 0;
static int failed = 0;

/* Mirror of nodus_witness_handlers.c:54-56 (file-local defines there). */
#define DNAC_STATUS_APPROVED   0
#define DNAC_STATUS_ERROR      2

/* Does the buffer contain the literal byte sequence? The receipt is
 * built by enc_dnac_response(..., "dnac_spend", ...) so the CBOR text
 * string "dnac_spend" appears verbatim; nodus_t2_error never writes it. */
static int contains(const uint8_t *hay, size_t hay_len, const char *needle) {
    size_t nlen = strlen(needle);
    if (nlen > hay_len) return 0;
    for (size_t i = 0; i + nlen <= hay_len; i++) {
        if (memcmp(hay + i, needle, nlen) == 0) return 1;
    }
    return 0;
}

/* Decode the single frame sitting in conn->wbuf. Returns 0 on success. */
static int take_frame(nodus_tcp_conn_t *conn, nodus_frame_t *frame) {
    if (conn->wlen <= conn->wpos) return -1;
    int used = nodus_frame_decode(conn->wbuf + conn->wpos,
                                  conn->wlen - conn->wpos, frame);
    return (used > 0) ? 0 : -1;
}

static void reset_conn(nodus_tcp_conn_t *conn) {
    conn->wlen = 0;
    conn->wpos = 0;
}

int main(void) {
    printf("\nNodus spend-result failure-path contract (K1 / K2)\n");
    printf("============================================================\n\n");

    /* nodus_witness_t and nodus_server_t are both multi-MB — heap. */
    nodus_witness_t *w = calloc(1, sizeof(*w));
    struct nodus_server *srv = calloc(1, sizeof(*srv));
    nodus_tcp_conn_t *conn = calloc(1, sizeof(*conn));
    nodus_witness_mempool_entry_t *entry = calloc(1, sizeof(*entry));
    if (!w || !srv || !conn || !entry) {
        fprintf(stderr, "calloc failed\n");
        return 1;
    }

    /* Deterministic identity — fixed seed, never random (the receipt
     * path signs with it, and a blockchain test must be reproducible). */
    uint8_t seed[32];
    memset(seed, 0x5A, sizeof(seed));
    if (nodus_identity_from_seed(seed, &srv->identity) != 0) {
        fprintf(stderr, "identity derive failed\n");
        return 1;
    }
    w->server = srv;
    memset(w->my_id, 0x33, sizeof(w->my_id));
    memset(w->chain_id, 0x44, sizeof(w->chain_id));

    /* fd = -1: the write in send_progress fails, so the encoded frame
     * stays in conn->wbuf where we can read it.
     *
     * wbuf/wcap MUST be initialised exactly the way conn_alloc does it
     * (nodus_tcp.c:105-108). A calloc'd conn has wcap == 0, and
     * buf_ensure's doubling loop cannot leave 0 — the same review round
     * that caught this also put a floor in buf_ensure itself, but the
     * fixture must still model a real connection rather than lean on
     * that guard. */
    conn->fd = -1;
    conn->state = NODUS_CONN_CONNECTED;
    conn->auth_required = false;
    conn->wcap = NODUS_TCP_BUF_INIT;
    conn->wbuf = malloc(conn->wcap);
    if (!conn->wbuf) {
        fprintf(stderr, "wbuf alloc failed\n");
        return 1;
    }

    memset(entry->tx_hash, 0x77, sizeof(entry->tx_hash));
    entry->client_conn = conn;
    entry->client_txn_id = 4242;
    entry->committed_block_height = 0;
    entry->committed_tx_index = 0;

    const char *err_msg = "batch commit failed - block rolled back";

    /* ── 1. Non-vacuity: APPROVED emits the receipt ──────────────── */
    TEST("APPROVED emits a dnac_spend receipt");
    reset_conn(conn);
    nodus_witness_send_spend_result(w, entry, DNAC_STATUS_APPROVED, NULL);
    {
        nodus_frame_t f;
        if (take_frame(conn, &f) != 0) {
            FAIL("no frame emitted");
        } else if (!contains(f.payload, f.payload_len, "dnac_spend")) {
            FAIL("APPROVED did not emit a receipt");
        } else {
            PASS();
        }
    }

    /* ── 2. K2: ERROR + message → error frame, no receipt ────────── */
    TEST("ERROR + message emits an error, never a receipt");
    reset_conn(conn);
    nodus_witness_send_spend_result(w, entry, DNAC_STATUS_ERROR, err_msg);
    {
        nodus_frame_t f;
        if (take_frame(conn, &f) != 0) {
            FAIL("no frame emitted");
        } else if (contains(f.payload, f.payload_len, "dnac_spend")) {
            FAIL("APPROVED-shaped receipt emitted for a rolled-back block");
        } else if (!contains(f.payload, f.payload_len, err_msg)) {
            FAIL("error message not carried to the client");
        } else {
            PASS();
        }
    }

    /* ── 3. The trap: ERROR + NULL still emits the receipt ───────── */
    TEST("ERROR + NULL message still emits a receipt (the trap)");
    reset_conn(conn);
    nodus_witness_send_spend_result(w, entry, DNAC_STATUS_ERROR, NULL);
    {
        nodus_frame_t f;
        if (take_frame(conn, &f) != 0) {
            FAIL("no frame emitted");
        } else if (!contains(f.payload, f.payload_len, "dnac_spend")) {
            FAIL("trap no longer reproduces — bft_emit_batch_replies' "
                 "non-NULL-message guard may now be dead code; re-check "
                 "nodus_witness_handlers.c:2161 before deleting it");
        } else {
            PASS();
        }
    }

    free(conn->wbuf);
    free(entry);
    free(conn);
    free(srv);
    free(w);

    printf("\n============================================================\n");
    printf("Results: %d passed, %d failed\n\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
