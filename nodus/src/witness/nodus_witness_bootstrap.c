/**
 * Nodus — Witness Auto-Bootstrap (PR 3 Yol B)
 *
 * State machine implementation. Phases:
 *
 *   - C1  Skeleton (committed)
 *   - C2  HAVE_CHAIN branch (committed)
 *   - C3  DISCOVER branch + C-1 gate + C-2 cabal reject + retry/exit
 *   - C4  --cold-bootstrap operator override (next)
 *   - C5  FETCH_GENESIS branch (atomic chain_def + genesis write, H-7)
 *   - C6  Wire bootstrap_start into nodus_witness_init
 *
 * @file nodus_witness_bootstrap.c
 */

#include "witness/nodus_witness_bootstrap.h"
#include "witness/nodus_witness.h"
#include "witness/nodus_witness_bft.h"
#include "protocol/nodus_tier3.h"
#include "transport/nodus_tcp.h"
#include "server/nodus_server.h"
#include "crypto/utils/qgp_random.h"
#include "dnac/dnac.h"

#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sqlite3.h>

#define NODUS_W_BOOTSTRAP_DEFAULT_ROUND_TIMEOUT_MS  5000U
#define NODUS_W_BOOTSTRAP_MAX_ATTEMPTS              10
#define NODUS_W_BOOTSTRAP_ROUND_TIMEOUT_MS          10000U
#define NODUS_W_BOOTSTRAP_MAX_RESPONSES             64

/* Pre-attempt wait schedule in seconds.
 *
 * Index = attempt - 1 (attempt 1 waits 0s before firing). Total
 * cumulative wall-clock budget through attempt 10 is roughly
 * 10*(timeout) + sum(waits) = 100s + 1950s ≈ 34 minutes. After the
 * 10th attempt fails we fall through to exit code 2; systemd's
 * RestartSec=300 + StartLimitBurst=3 + StartLimitIntervalSec=86400
 * configuration fail-stops the unit after 3 cycles in 24 h. */
static const uint32_t BOOTSTRAP_WAIT_SCHEDULE_SEC[NODUS_W_BOOTSTRAP_MAX_ATTEMPTS] = {
    0, 30, 60, 120, 240, 300, 300, 300, 300, 300
};

/* ── Response tally ──────────────────────────────────────────────── */

/* Per-process response collection. The bootstrap state machine is a
 * singleton per witness binary — only one instance runs per process —
 * so file-scope storage is safe. Each round resets the buffer in
 * start_discover_round before broadcasting a fresh nonce. */
typedef struct {
    uint8_t  sender_id[32];                      /* NODUS_T3_WITNESS_ID_LEN */
    uint8_t  cid[32];
    uint8_t  cdh[64];                            /* NODUS_T3_TX_HASH_LEN */
    bool     valid;
} bootstrap_response_t;

static bootstrap_response_t g_responses[NODUS_W_BOOTSTRAP_MAX_RESPONSES];
static int g_response_count = 0;

/* ── Local helpers ───────────────────────────────────────────────── */

static uint64_t monotonic_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}

static int64_t chain_tip_height(sqlite3 *db) {
    if (!db) return -1;
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT COALESCE(MAX(height), 0) FROM blocks",
            -1, &stmt, NULL) != SQLITE_OK) {
        return -1;
    }
    int64_t out = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        out = sqlite3_column_int64(stmt, 0);
    }
    sqlite3_finalize(stmt);
    return out;
}

/* Return the count of authenticated, identified witness peers. Zero
 * is a valid steady-state value during early startup before the peer
 * mesh comes up; the DISCOVER state machine simply waits for the next
 * tick. */
static int count_authd_peers(const nodus_witness_t *w) {
    if (!w) return 0;
    int n = 0;
    for (int i = 0; i < w->peer_count; i++) {
        if (w->peers[i].identified &&
            w->peers[i].auth_state == PEER_AUTH_OK &&
            w->peers[i].conn) {
            n++;
        }
    }
    return n;
}

/* Quorum threshold over the seed_nodes count: (2*N)/3 + 1. */
static int discover_quorum_threshold(int seed_count) {
    if (seed_count <= 0) return 1;
    return (2 * seed_count) / 3 + 1;
}

/* Walk the response tally, group by (cid, cdh), and return the size of
 * the largest agreeing group. Out-params return that group's cid/cdh.
 * Returns 0 if the tally is empty. */
static int discover_largest_agreement(uint8_t out_cid[32],
                                       uint8_t out_cdh[64]) {
    int best = 0;
    for (int i = 0; i < g_response_count; i++) {
        if (!g_responses[i].valid) continue;
        int n = 0;
        for (int j = 0; j < g_response_count; j++) {
            if (!g_responses[j].valid) continue;
            if (memcmp(g_responses[i].cid, g_responses[j].cid, 32) == 0 &&
                memcmp(g_responses[i].cdh, g_responses[j].cdh, 64) == 0) {
                n++;
            }
        }
        if (n > best) {
            best = n;
            memcpy(out_cid, g_responses[i].cid, 32);
            memcpy(out_cdh, g_responses[i].cdh, 64);
        }
    }
    return best;
}

/* ── DISCOVER state machine ──────────────────────────────────────── */

static int broadcast_chain_q(nodus_witness_t *w) {
    if (!w || !w->server) return -1;

    nodus_t3_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    msg.type = NODUS_T3_CHAIN_Q;
    msg.txn_id = (uint32_t)(monotonic_ms() & 0xFFFFFFFFu);
    msg.header.version = 1;
    msg.header.round = 0;
    msg.header.view = 0;
    memcpy(msg.header.sender_id, w->my_id, NODUS_T3_WITNESS_ID_LEN);
    msg.header.timestamp = (uint64_t)time(NULL);
    msg.header.nonce = 0;
    /* During DISCOVER the local chain_id is unknown; use NODUS_BOOTSTRAP_CID
     * marker (all-0xBB) so receivers can distinguish a bootstrap query
     * from a steady-state T3 frame. The receiver's C-2 path keys off the
     * payload nonce, not the header chain_id, so this marker is purely
     * advisory. */
    memset(msg.header.chain_id, 0xBB, 32);
    memcpy(msg.w_chain_q.nonce, w->bootstrap_round_nonce,
           NODUS_W_BOOTSTRAP_NONCE_LEN);

    uint8_t buf[NODUS_T3_MAX_MSG_SIZE];
    size_t len = 0;
    if (nodus_t3_encode(&msg, &w->server->identity.sk,
                         buf, sizeof(buf), &len) != 0) {
        fprintf(stderr,
                "WITNESS-BOOTSTRAP: encode w_chain_q failed\n");
        return -1;
    }

    int sent = 0;
    for (int i = 0; i < w->peer_count; i++) {
        if (!w->peers[i].identified) continue;
        if (w->peers[i].auth_state != PEER_AUTH_OK) continue;
        if (!w->peers[i].conn) continue;
        if (nodus_tcp_send(w->peers[i].conn, buf, len) > 0) sent++;
    }
    fprintf(stderr,
            "WITNESS-BOOTSTRAP: w_chain_q broadcast attempt=%d "
            "authd_peers=%d sent=%d\n",
            w->bootstrap_attempt, count_authd_peers(w), sent);
    return sent;
}

static void start_discover_round(nodus_witness_t *w) {
    /* Fresh nonce every round so a captured response from attempt N
     * does not satisfy the quorum check at attempt N+1 (C-4). */
    qgp_randombytes(w->bootstrap_round_nonce, NODUS_W_BOOTSTRAP_NONCE_LEN);

    /* Reset the response tally — only this round's echoes count. */
    memset(g_responses, 0, sizeof(g_responses));
    g_response_count = 0;

    uint64_t now = monotonic_ms();
    w->bootstrap_round_deadline_ms = now + NODUS_W_BOOTSTRAP_ROUND_TIMEOUT_MS;

    (void)broadcast_chain_q(w);
}

/* Schedule the next attempt with exponential backoff per design
 * Section 3. After the 10th attempt fails we drop into the exit-2
 * path on the next tick. */
static void schedule_next_attempt(nodus_witness_t *w) {
    int idx = w->bootstrap_attempt;  /* 0-indexed into wait schedule */
    if (idx < 0) idx = 0;
    if (idx >= NODUS_W_BOOTSTRAP_MAX_ATTEMPTS) {
        idx = NODUS_W_BOOTSTRAP_MAX_ATTEMPTS - 1;
    }
    uint32_t wait_sec = BOOTSTRAP_WAIT_SCHEDULE_SEC[idx];
    w->bootstrap_next_attempt_ms = monotonic_ms() + (uint64_t)wait_sec * 1000ULL;
}

/* ── Public API ──────────────────────────────────────────────────── */

int nodus_witness_bootstrap_start(nodus_witness_t *w) {
    if (!w) return -1;

    w->bootstrap_state = (int)NODUS_W_BOOTSTRAP_INIT;
    w->bootstrap_attempt = 0;
    w->bootstrap_next_attempt_ms = 0;
    w->bootstrap_round_deadline_ms = 0;

    /* w->db == NULL means witness_scan_chain_db found no witness_*.db
     * file — fresh node, no genesis yet. Treat as tip == 0 so we
     * fall through to the DISCOVER branch instead of the DB-error
     * path. */
    int64_t tip;
    if (w->db == NULL) {
        tip = 0;
    } else {
        tip = chain_tip_height(w->db);
        if (tip < 0) return -1;
    }

    if (tip >= 1) {
        /* HAVE_CHAIN branch (C2 — unchanged in C3). */
        w->bootstrap_state = (int)NODUS_W_BOOTSTRAP_HAVE_CHAIN;
        (void)refresh_bft_config_from_committee(w, (uint64_t)tip);

        uint32_t rto = w->bft_config.round_timeout_ms;
        if (rto == 0) rto = NODUS_W_BOOTSTRAP_DEFAULT_ROUND_TIMEOUT_MS;
        w->bootstrap_settle_until_ms = monotonic_ms() + (uint64_t)(2U * rto);

        w->bootstrap_state = (int)NODUS_W_BOOTSTRAP_BOOTSTRAP_CONFIG;
        w->bootstrap_state = (int)NODUS_W_BOOTSTRAP_DONE;

        fprintf(stderr,
                "WITNESS-BOOTSTRAP: state=DONE branch=HAVE_CHAIN tip=%lld "
                "settle_until_ms=%llu\n",
                (long long)tip,
                (unsigned long long)w->bootstrap_settle_until_ms);
        return 0;
    }

    /* DISCOVER branch (C3) — chain DB is empty. */

    /* C-1 startup gate: bootstrap quorum strength MUST equal BFT
     * quorum strength. Operator's seed_nodes config has to include at
     * least the full committee or a Byzantine subset of seeds could
     * outvote the honest peers during DISCOVER. Refuse to start
     * rather than degrade silently. */
    int seed_count = w->server ? w->server->config.seed_count : 0;
    if (seed_count < DNAC_COMMITTEE_SIZE) {
        fprintf(stderr,
                "WITNESS-BOOTSTRAP: C-1 gate FAIL — seed_count=%d < "
                "committee_size=%d. Add seed_nodes to operator config "
                "before restarting fresh node.\n",
                seed_count, DNAC_COMMITTEE_SIZE);
        return -1;
    }

    w->bootstrap_state = (int)NODUS_W_BOOTSTRAP_DISCOVER;
    w->bootstrap_attempt = 0;
    /* First attempt fires on the first tick (no wait before attempt 1). */
    w->bootstrap_next_attempt_ms = monotonic_ms();

    fprintf(stderr,
            "WITNESS-BOOTSTRAP: state=DISCOVER seed_count=%d "
            "threshold=%d (= (2*N)/3 + 1)\n",
            seed_count, discover_quorum_threshold(seed_count));
    return 0;
}

void nodus_witness_bootstrap_tick(nodus_witness_t *w) {
    if (!w) return;
    if (w->bootstrap_state != (int)NODUS_W_BOOTSTRAP_DISCOVER) return;

    uint64_t now = monotonic_ms();
    int seed_count = w->server ? w->server->config.seed_count : 0;
    int threshold = discover_quorum_threshold(seed_count);

    /* Round-deadline check first: if a round is still in flight and
     * the deadline has not elapsed, do nothing — handle_chain_r will
     * advance the state machine if quorum is reached. */
    if (w->bootstrap_attempt > 0 && now < w->bootstrap_round_deadline_ms) {
        /* Check quorum opportunistically: if responses arrived before
         * the deadline, advance immediately. */
        uint8_t agree_cid[32], agree_cdh[64];
        int agree = discover_largest_agreement(agree_cid, agree_cdh);
        if (agree >= threshold) {
            fprintf(stderr,
                    "WITNESS-BOOTSTRAP: quorum reached (agree=%d "
                    "threshold=%d) — advancing to FETCH_GENESIS (stub)\n",
                    agree, threshold);
            /* C5 will replace this stub with the real FETCH_GENESIS
             * fetch + atomic write + BOOTSTRAP_CONFIG transition. */
            w->bootstrap_state = (int)NODUS_W_BOOTSTRAP_FETCH_GENESIS;
        }
        return;
    }

    /* Either no round has fired yet (attempt == 0) or the previous
     * round's deadline has passed without quorum. Fire the next
     * attempt. */
    if (now < w->bootstrap_next_attempt_ms) return;

    if (w->bootstrap_attempt >= NODUS_W_BOOTSTRAP_MAX_ATTEMPTS) {
        fprintf(stderr,
                "WITNESS-BOOTSTRAP: max attempts (%d) exhausted — "
                "exiting with code 2 so systemd RestartSec handles "
                "outer recovery (H-11 mitigation).\n",
                NODUS_W_BOOTSTRAP_MAX_ATTEMPTS);
        exit(2);
    }

    w->bootstrap_attempt++;
    start_discover_round(w);
    schedule_next_attempt(w);
}

/* ── T3 dispatch handlers ────────────────────────────────────────── */

void nodus_witness_bootstrap_handle_chain_q(nodus_witness_t *w,
                                             struct nodus_tcp_conn *conn,
                                             const nodus_t3_msg_t *msg) {
    if (!w || !msg) return;

    /* C-2 cabal protection: a node that does not yet have a chain MUST
     * NOT respond to w_chain_q. Otherwise two fresh nodes can agree on
     * a fictitious chain_id between themselves before the operator
     * notices. Only HAVE_CHAIN / DONE peers respond — UNLESS the
     * --cold-bootstrap operator escape is set (C4), in which case
     * this node is the explicit cold-DR seed and answers anyway.
     * Operator MUST set the flag on exactly one node; multiple
     * cold-bootstrap seeds re-introduce the cabal risk. */
    bool is_cold = w->server && w->server->config.is_cold_bootstrap;
    if (!is_cold &&
        (w->bootstrap_state == (int)NODUS_W_BOOTSTRAP_DISCOVER ||
         w->bootstrap_state == (int)NODUS_W_BOOTSTRAP_FETCH_GENESIS)) {
        fprintf(stderr,
                "WITNESS-BOOTSTRAP: w_chain_q from peer dropped "
                "(C-2: own state=DISCOVER/FETCH_GENESIS, no chain to advertise)\n");
        return;
    }
    if (is_cold) {
        fprintf(stderr,
                "WITNESS-BOOTSTRAP: w_chain_q answered via "
                "--cold-bootstrap operator escape (C4); cabal "
                "protection bypassed — operator MUST not run more "
                "than one node with this flag.\n");
    }

    /* Otherwise this witness has a chain — fetch tip + cdh and send
     * back a w_chain_r echo. The actual chain_def_blob hash lookup is
     * implemented in C5 (chain_def is stored on the genesis block row
     * via v14 migration); for C3 we send back a zeroed cdh as a
     * placeholder so the wire path is exercised without leaking
     * uninitialized stack to the network. */
    int64_t tip = chain_tip_height(w->db);
    if (tip < 1) return;  /* no chain — covered by C-2 path above */

    nodus_t3_msg_t rsp;
    memset(&rsp, 0, sizeof(rsp));
    rsp.type = NODUS_T3_CHAIN_R;
    rsp.txn_id = msg->txn_id;
    rsp.header.version = 1;
    memcpy(rsp.header.sender_id, w->my_id, NODUS_T3_WITNESS_ID_LEN);
    rsp.header.timestamp = (uint64_t)time(NULL);
    memcpy(rsp.header.chain_id, w->chain_id, 32);

    memcpy(rsp.w_chain_r.cid, w->chain_id, 32);
    rsp.w_chain_r.tip = (uint64_t)tip;
    /* gh / cdh are filled in by C5. For the C3 wire-up we emit zeroes
     * and rely on the C-2 + nonce-echo invariants for security; the
     * receiver's quorum check still groups by (cid, cdh) so all-zero
     * cdh entries cluster together harmlessly. */
    memcpy(rsp.w_chain_r.nonce, msg->w_chain_q.nonce,
           NODUS_W_BOOTSTRAP_NONCE_LEN);

    uint8_t buf[NODUS_T3_MAX_MSG_SIZE];
    size_t len = 0;
    if (nodus_t3_encode(&rsp, &w->server->identity.sk,
                         buf, sizeof(buf), &len) != 0)
        return;
    if (conn) (void)nodus_tcp_send(conn, buf, len);
}

void nodus_witness_bootstrap_handle_chain_r(nodus_witness_t *w,
                                             const nodus_t3_msg_t *msg) {
    if (!w || !msg) return;
    if (w->bootstrap_state != (int)NODUS_W_BOOTSTRAP_DISCOVER) return;

    /* Stale-nonce filter (C-4): only this round's echoes count. */
    if (memcmp(msg->w_chain_r.nonce, w->bootstrap_round_nonce,
               NODUS_W_BOOTSTRAP_NONCE_LEN) != 0) {
        return;
    }

    /* Drop if this peer's id already responded — one vote per peer. */
    for (int i = 0; i < g_response_count; i++) {
        if (g_responses[i].valid &&
            memcmp(g_responses[i].sender_id,
                   msg->header.sender_id, 32) == 0) {
            return;
        }
    }

    if (g_response_count >= NODUS_W_BOOTSTRAP_MAX_RESPONSES) return;
    bootstrap_response_t *r = &g_responses[g_response_count++];
    memcpy(r->sender_id, msg->header.sender_id, 32);
    memcpy(r->cid, msg->w_chain_r.cid, 32);
    memcpy(r->cdh, msg->w_chain_r.cdh, 64);
    r->valid = true;
}

void nodus_witness_bootstrap_handle_genesis_req(nodus_witness_t *w,
                                                 struct nodus_tcp_conn *conn,
                                                 const nodus_t3_msg_t *msg) {
    /* C5 implements the actual chain_def_blob fetch + send. C3 only
     * stubs the dispatch wire so the message type is recognized. */
    (void)w; (void)conn; (void)msg;
}

void nodus_witness_bootstrap_handle_genesis_rsp(nodus_witness_t *w,
                                                 const nodus_t3_msg_t *msg) {
    /* C5 implements the FETCH_GENESIS state. C3 dispatch is wired so
     * the message decodes cleanly when the state machine is in
     * FETCH_GENESIS — for now drop on non-FETCH state. */
    (void)w; (void)msg;
}
