/**
 * @file nodus/tests/test_cc_collect.c
 * @brief The node-side governance approval collection (`dnac_cc_collect`,
 *        decision docs/plans/decisions/2026-09-26-cc-approval-via-own-node.md)
 *        on a REAL derived version-3 chain with 7 REAL ML-DSA-87 committee
 *        keys, REAL loopback p2p hosts and a REAL 4001 reply path.
 *
 * ── WHAT IT PROVES ─────────────────────────────────────────────────────
 * The collector is node B (committee key 1): its witness holds the chain
 * and its 4004 host B. Seats A (key 0) and S (key 2) and an outside key X
 * are connected to B as p2p hosts WITHOUT a witness — they receive B's
 * 0x71 request and never answer, so every answer below is handed to B's
 * collector by the test itself (`nodus_witness_cc_collect_on_rsp`, the
 * entry the host's cc_receive calls for a 0x71 response) and every
 * deadline is driven with an explicit clock value
 * (`nodus_witness_cc_collect_tick`). Seats 3..6 have no connection.
 * The requesting 4001 session is a real `nodus_tcp_conn_t` over one end
 * of a socketpair(2) in B's session table; the reply is read off the
 * other end and decoded with the client SDK's own decoder
 * (`nodus_dnac_cc_collect_decode`) — so the node's encoder and the
 * client's decoder are proven to agree on the wire.
 *  (a) NOTHING CONNECTED ENDS AT ONCE: with no p2p host every other seat
 *      is "not connected" and the reply is on the socket when
 *      `nodus_witness_cc_collect_start` returns — no collection pending.
 *  (b) OWN-IDENTITY GATE (decision (2)): a requester key that is not B's
 *      identity is refused, nothing pends, nothing is written.
 *  (c) NOT A SEAT: a node whose identity holds no seat refuses to collect.
 *  (d) BUSY: a second request while one is pending is refused; the
 *      pending one is untouched.
 *  (e) ONLY ASKED PEERS ARE HEARD, ONLY FOR THIS REQUEST: a response from
 *      seat A (asked) whose request id `rq` is an EARLIER envelope's
 *      SHA3-512, or all zero, is not taken (decision
 *      2026-09-27-p2p-fix-2.md (2)); a response from X (connected, not a
 *      seat, never asked) and from seat 3's ID (a seat, not connected,
 *      never asked) is not taken; A's answer carrying THIS envelope's id
 *      is taken; a second response from A (already answered) is not.
 *  (f) DEADLINE: one millisecond before NODUS_CC_COLLECT_DEADLINE_MS the
 *      collection still pends; at the deadline it ends.
 *  (g) PER-SEAT RESULTS: the reply names every seat but B's own, in
 *      ascending order, with the right status — A answered (its refusal
 *      and reason), S no answer, seats 3..6 not connected — under the
 *      request's txn id.
 *  (h) APPROVALS ROUND-TRIP: when A and S both answer ok, the collection
 *      ends on the LAST answer with no tick, and each entry carries the
 *      responder's seat, signature, set hash and epoch byte-exact.
 *  (i) SESSION GONE: when the requesting session is no longer
 *      authenticated at reply time, the collection still ends and
 *      nothing is written to its socket.
 *
 * ── WHAT IT REQUIRES ───────────────────────────────────────────────────
 * Compile flags: none beyond a default build. Environment: none.
 * Loopback TCP on 127.0.0.1 (ephemeral ports), socketpair(2) (Linux),
 * SQLite >= 3.35.0 (the chain derivation, as test_cc_appr).
 *
 * ── WHAT IT LEAVES BEHIND ──────────────────────────────────────────────
 * One /tmp/test_cc_collect_XXXXXX directory, removed at the end. A run
 * that fails a check leaves it behind.
 *
 * ── HOW IT CAN LIE ─────────────────────────────────────────────────────
 *  1. The answers are injected, not received: that a REAL 0x71 response
 *     reaches `nodus_witness_cc_collect_on_rsp` through cc_receive — and
 *     that a real seat's responder answers B's real request — is
 *     test_witness_p2p (2d)'s, not this file's. The responses injected
 *     here are synthetic (no real signature): the collector relays them
 *     and never verifies one; the CLI does (nodus-cli.c
 *     cc_propose_judge_seat).
 *  2. The deadline is driven with explicit clock values; that the p2p
 *     host's poll feeds the monotonic clock to the tick is read in
 *     nodus_witness_p2p_poll, not run here.
 *  3. The 4001 routing (nodus_server.c → the chain backend →
 *     nodus_witness_handle_cc_collect,
 *     the session's key and token) is not exercised: this file calls
 *     `nodus_witness_cc_collect_start` with the values that routing
 *     passes. The Genesis Protocol scenario test_cmt_chain_config.sh
 *     drives the whole path from the CLI.
 *  4. Every connection wait is bounded (WAIT_MS, 30 s) and fails as a
 *     timeout, never passes. The bound is not tuned to a measurement: the
 *     author never ran this test (BUILDER agents do not run tests).
 *  5. Channel 0x71's send queue holds NODUS_P2P_CCAPPR_SEND_QUEUE (2)
 *     messages. The collections here are started without the loop
 *     running, so between two of them the test polls until B's 0x71
 *     queues to A and S are drained (a progress condition, not a sleep);
 *     without that the third collection would read A and S as "send
 *     failed". A production node polls continuously, and the CLI waits
 *     5 s between its two rounds.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sqlite3.h>

#include "crypto/hash/qgp_sha3.h"
#include "crypto/sign/qgp_dilithium.h"
#include "crypto/enc/qgp_mlkem.h"

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_p2p.h"
#include "witness/nodus_witness_v2_gen.h"
#include "witness/nodus_witness_v2_produce.h"
#include "witness/nodus_witness_committee.h"
#include "witness/nodus_witness_emission.h"
#include "server/nodus_server.h"
#include "transport/nodus_tcp.h"
#include "protocol/nodus_tier3.h"
#include "protocol/nodus_wire.h"
#include "protocol/nodus_cbor.h"
#include "nodus/nodus.h"                  /* nodus_dnac_cc_collect_decode */

#include "dnac/dnac.h"
#include "dnac/cmt_p2p_peer.h"

#define WAIT_MS 30000

static int g_checks = 0;

#define CHECK(cond, msg) do {                                              \
    if (!(cond)) {                                                         \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, \
                (msg));                                                    \
        rc = 1;                                                            \
        goto out;                                                          \
    }                                                                      \
    g_checks++;                                                            \
} while (0)

/* ══ keys — deterministic REAL ML-DSA-87 (test_witness_p2p.c's shape) ═ */

#define N_KEYS  ((int)DNAC_COMMITTEE_SIZE)
#define K_X     (N_KEYS + 0)      /* outside the committee              */
#define N_ALL   (N_KEYS + 1)
#define GEN_TIME_MS 1767225600000ULL

typedef struct {
    uint8_t pk[QGP_DSA87_PUBLICKEYBYTES];
    uint8_t sk[QGP_DSA87_SECRETKEYBYTES];
    uint8_t voter[32];
} keyset_t;

static keyset_t g_ks[N_ALL];

static int make_keys(void) {
    for (int i = 0; i < N_ALL; i++) {
        uint8_t seed[32], full[64];
        memset(seed, (uint8_t)(0x40 + i), sizeof(seed));
        if (qgp_dsa87_keypair_derand(g_ks[i].pk, g_ks[i].sk, seed) != 0)
            return -1;
        if (qgp_sha3_512(g_ks[i].pk, QGP_DSA87_PUBLICKEYBYTES, full) != 0)
            return -1;
        memcpy(g_ks[i].voter, full, 32);
    }
    return 0;
}

static int ident_make(nodus_identity_t *id, int k) {
    uint8_t coins[QGP_MLKEM1024_COINS_BYTES];

    memset(id, 0, sizeof(*id));
    memcpy(id->pk.bytes, g_ks[k].pk, NODUS_PK_BYTES);
    memcpy(id->sk.bytes, g_ks[k].sk, QGP_DSA87_SECRETKEYBYTES);
    if (qgp_sha3_512(id->pk.bytes, NODUS_PK_BYTES, id->node_id.bytes) != 0)
        return -1;
    memset(coins, (uint8_t)(0x90 + k), sizeof(coins));
    if (qgp_mlkem1024_keypair_derand(id->mlkem_pk, id->mlkem_sk, coins) != 0)
        return -1;
    id->has_mlkem = true;
    return 0;
}

static int key_id(int k, char out[CMT_P2P_ID_CAP]) {
    return cmt_p2p_pubkey_to_id(g_ks[k].pk, out) == CMT_OK ? 0 : -1;
}

static void rmrf(const char *path) {
    char cmd[300];
    if (!path || !path[0]) return;
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", path);
    if (system(cmd) != 0) { /* best effort */ }
}

static char g_root[64];

static int subdir(const char *tag, char *out, size_t cap) {
    snprintf(out, cap, "%s/%s", g_root, tag);
    return mkdir(out, 0700) == 0 ? 0 : -1;
}

static int64_t mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* ══ the chain fixture (test_witness_p2p.c's copy — the tree's per-file
 * fixture convention) ══════════════════════════════════════════════════ */

typedef struct {
    nodus_v2_gen_config_t *cfg;
    nodus_v2_gen_alloc_t  *allocs;
} cfgbox_t;

static void cfg_free(cfgbox_t *b) {
    if (b) { free(b->cfg); free(b->allocs); memset(b, 0, sizeof(*b)); }
}

static int cfg_make_v3_real(cfgbox_t *b) {
    nodus_v2_gen_config_t *c;
    memset(b, 0, sizeof(*b));
    b->cfg    = calloc(1, sizeof(*b->cfg));
    b->allocs = calloc(1, sizeof(*b->allocs));
    if (!b->cfg || !b->allocs) { cfg_free(b); return -1; }
    c = b->cfg;
    c->config_version        = NODUS_V2_GEN_CONFIG_VERSION_V3;
    c->total_supply_raw      = DNAC_DEFAULT_TOTAL_SUPPLY;
    c->epoch_length          = (uint64_t)DNAC_EPOCH_LENGTH;
    c->blocks_per_year       = (uint64_t)DNAC_BLOCKS_PER_YEAR;
    c->decimal_unit          = (uint64_t)DNAC_DECIMAL_UNIT;
    c->inflation_start_block = 0ULL;
    c->claim_start_height    = 0;
    c->claim_end_height      = UINT64_MAX;
    c->n_validators          = (uint16_t)N_KEYS;
    for (uint16_t k = 0; k < (uint16_t)N_KEYS; k++) {
        nodus_v2_gen_validator_t *v = &c->validators[k];
        memcpy(v->pubkey, g_ks[k].pk, DNAC_PUBKEY_SIZE);
        for (size_t bb = 0; bb < DNAC_PUBKEY_SIZE; bb++)
            v->unstake_destination_pubkey[bb] = (uint8_t)(v->pubkey[bb] ^ 0x5A);
        {
            static const char hexd[] = "0123456789abcdef";
            uint8_t dg[64];
            qgp_sha3_512(v->unstake_destination_pubkey, DNAC_PUBKEY_SIZE, dg);
            for (int i = 0; i < 64; i++) {
                v->unstake_destination_fp[2 * i]     = (uint8_t)hexd[dg[i] >> 4];
                v->unstake_destination_fp[2 * i + 1] = (uint8_t)hexd[dg[i] & 0x0F];
            }
            v->unstake_destination_fp[128] = 0;
        }
        /* general multisig ONAY 2: a genesis row's destination pubkey is
         * ALL ZERO (the fp above is only a shape-valid address) */
        memset(v->unstake_destination_pubkey, 0, DNAC_PUBKEY_SIZE);
        v->self_stake     = DNAC_SELF_STAKE_AMOUNT;
        v->commission_bps = (uint16_t)(100 * (k + 1));
    }
    memset(b->allocs[0].source_id, 0, sizeof(b->allocs[0].source_id));
    b->allocs[0].source_id[0] = 0x30;
    qgp_sha3_512(g_ks[0].pk, DNAC_PUBKEY_SIZE, b->allocs[0].dest_binding);
    b->allocs[0].amount = 93000000000000000ULL;
    c->n_allocs = 1;
    c->allocs   = b->allocs;

    if (nodus_witness_v2_gen_v3_defaults(c) != 0) { cfg_free(b); return -1; }
    c->reward_pool_initial = 0;
    c->genesis_time_ms = GEN_TIME_MS;
    c->initial_height  = 1;
    if (nodus_witness_v2_gen_v3_fill_comet_rows(c) != 0) { cfg_free(b); return -1; }
    return 0;
}

typedef struct {
    nodus_witness_t *w;
    nodus_server_t  *srv;
    nodus_witness_host_t host;              /* w->host, filled from srv */
    cfgbox_t         box;
    char             dir[128];
    uint8_t          chain32[32];
} gfx_t;

static int gfx_open(gfx_t *g, int k) {
    char path[600];
    memset(g, 0, sizeof(*g));
    if (cfg_make_v3_real(&g->box) != 0) return -1;
    if (nodus_witness_v2_gen_v3_validate(g->box.cfg) != 0) return -1;
    if (subdir("B", g->dir, sizeof(g->dir)) != 0) return -1;
    if (nodus_witness_v2_gen_derive_v3(g->dir, g->box.cfg, g->chain32) != 0)
        return -1;
    {
        char hex[33];
        for (int i = 0; i < 16; i++) snprintf(hex + 2 * i, 3, "%02x", g->chain32[i]);
        hex[32] = '\0';
        snprintf(path, sizeof(path), "%s/witness_%s.db", g->dir, hex);
    }
    g->w   = calloc(1, sizeof(*g->w));
    g->srv = calloc(1, sizeof(*g->srv));
    if (!g->w || !g->srv) return -1;
    if (sqlite3_open_v2(path, &g->w->db, SQLITE_OPEN_READWRITE, NULL) != SQLITE_OK)
        return -1;
    snprintf(g->w->data_path, sizeof(g->w->data_path), "%s", g->dir);
    g->w->cached_committee_epoch_start = UINT64_MAX;
    g->w->v2_successor     = true;
    g->w->v2_ingress_armed = true;
    memcpy(g->w->v2_chain32, g->chain32, 32);
    if (ident_make(&g->srv->identity, k) != 0) return -1;
    /* The server's own host fill: identity by pointer, and the session
     * lookup over g->srv->sessions[] that sess_open() populates. */
    nodus_server_witness_host(g->srv, &g->host);
    g->w->host = &g->host;
    memcpy(g->w->my_id, g_ks[k].voter, 32);
    return 0;
}

static void gfx_close(gfx_t *g) {
    if (g->w) {
        nodus_witness_p2p_free(g->w->p2p);   /* aborts a pending collection */
        g->w->p2p = NULL;
        nodus_witness_cc_collect_abort(g->w);
        if (g->w->db) sqlite3_close(g->w->db);
        free(g->w);
        g->w = NULL;
    }
    free(g->srv); g->srv = NULL;
    cfg_free(&g->box);
}

/* ══ p2p hosts (test_witness_p2p.c's shape) ════════════════════════════ */

static void cfg_local(nodus_p2p_config_t *c) {
    nodus_p2p_config_default(c);
    c->pex = false;
    c->addr_book_strict = false;
    c->allow_duplicate_ip = true;
}

static nodus_witness_p2p_t *host_new(nodus_witness_t *w,
                                     const nodus_identity_t *id,
                                     const uint8_t chain[32],
                                     const nodus_p2p_config_t *cfg,
                                     const char *dir) {
    nodus_witness_p2p_params_t prm;

    memset(&prm, 0, sizeof(prm));
    prm.identity = id;
    prm.chain_id = chain;
    prm.cfg = cfg;
    prm.listen_ip = "127.0.0.1";
    prm.listen_port = 0;
    prm.external_ip = "";
    prm.data_path = dir;
    prm.seq_dir = dir;
    prm.open_listener = true;
    return nodus_witness_p2p_new(w, &prm);
}

static void dial_str(const nodus_witness_p2p_t *p, char *out, size_t cap) {
    snprintf(out, cap, "%s@127.0.0.1:%u", nodus_witness_p2p_id(p),
             (unsigned)nodus_witness_p2p_listen_port(p));
}

static int dial(nodus_witness_p2p_t *from, const nodus_witness_p2p_t *to) {
    char s[CMT_P2P_NETADDR_STR_MAX];
    const char *list[1];

    dial_str(to, s, sizeof(s));
    list[0] = s;
    return cmt_p2p_switch_dial_peers_async(nodus_witness_p2p_switch(from), list, 1)
           == CMT_P2P_ERR_NONE ? 0 : -1;
}

/* Poll every host until B holds every id in `ids` (or the budget ends). */
static bool drive_until_linked(nodus_witness_p2p_t **hosts, int n_hosts,
                               nodus_witness_p2p_t *b, char ids[][CMT_P2P_ID_CAP],
                               int n_ids) {
    int64_t end = mono_ms() + WAIT_MS;

    for (;;) {
        bool all = true;
        for (int i = 0; i < n_hosts; i++) nodus_witness_p2p_poll(hosts[i], 1);
        for (int i = 0; i < n_ids; i++)
            if (!nodus_witness_p2p_has_peer(b, ids[i])) all = false;
        if (all) return true;
        if (mono_ms() > end) return false;
    }
}

/* B's channel-0x71 queue to `id` holds nothing unsent: the queue is empty
 * and no message is mid-send. The channel's send queue holds
 * NODUS_P2P_CCAPPR_SEND_QUEUE (2) messages and Send ≡ TrySend (R-P2P-19):
 * collections started back to back WITHOUT a poll between them would find
 * it full on the third and read the seat as "send failed". */
static bool cc_chan_drained(nodus_witness_p2p_t *b, const char *id) {
    cmt_p2p_peer_t *peer = cmt_p2p_peer_set_get(
        cmt_p2p_switch_peers(nodus_witness_p2p_switch(b)), id);

    if (peer == NULL) return false;
    for (int i = 0; i < peer->mconn.n_channels; i++) {
        const cmt_p2p_mconn_channel_t *ch = &peer->mconn.channels[i];
        if (ch->desc.id == NODUS_P2P_CH_CC_APPR)
            return ch->sq_len == 0 && ch->sending_off >= ch->sending_len;
    }
    return false;
}

/* Poll every host until B's 0x71 queues to A and S are drained. Called
 * only while no collection pends (B's tick is then a no-op); A and S have
 * no witness, so they drop the request they receive. */
static bool drive_until_drained(nodus_witness_p2p_t **hosts, int n_hosts,
                                nodus_witness_p2p_t *b, const char *id_a,
                                const char *id_s) {
    int64_t end = mono_ms() + WAIT_MS;

    for (;;) {
        for (int i = 0; i < n_hosts; i++) nodus_witness_p2p_poll(hosts[i], 1);
        if (cc_chan_drained(b, id_a) && cc_chan_drained(b, id_s)) return true;
        if (mono_ms() > end) return false;
    }
}

/* ══ the requesting 4001 session: a real nodus_tcp_conn_t over a
 * socketpair, in B's session table ════════════════════════════════════ */

typedef struct {
    int               sv[2];          /* [0] the node's end, [1] ours  */
    nodus_tcp_conn_t *conn;
    uint8_t           token[NODUS_SESSION_TOKEN_LEN];
} sess_t;

static int sess_open(sess_t *s, nodus_server_t *srv, int key) {
    memset(s, 0, sizeof(*s));
    s->sv[0] = s->sv[1] = -1;
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, s->sv) != 0) return -1;
    if (fcntl(s->sv[0], F_SETFL, O_NONBLOCK) != 0 ||
        fcntl(s->sv[1], F_SETFL, O_NONBLOCK) != 0)
        return -1;
    s->conn = calloc(1, sizeof(*s->conn));
    if (!s->conn) return -1;
    s->conn->fd = s->sv[0];
    s->conn->state = NODUS_CONN_CONNECTED;
    memset(s->token, 0x5c, sizeof(s->token));

    nodus_session_t *ss = &srv->sessions[0];
    memset(ss, 0, sizeof(*ss));
    ss->conn = s->conn;
    ss->authenticated = true;
    memcpy(ss->client_pk.bytes, g_ks[key].pk, NODUS_PK_BYTES);
    memcpy(ss->token, s->token, sizeof(s->token));
    return 0;
}

static void sess_close(sess_t *s, nodus_server_t *srv) {
    if (srv) memset(&srv->sessions[0], 0, sizeof(srv->sessions[0]));
    if (s->conn) {
        free(s->conn->wbuf);
        free(s->conn->rbuf);
        free(s->conn);
        s->conn = NULL;
    }
    if (s->sv[0] >= 0) close(s->sv[0]);
    if (s->sv[1] >= 0) close(s->sv[1]);
    s->sv[0] = s->sv[1] = -1;
}

/* Read ONE framed reply off our end. @return 0 and `*out` decoded (and
 * `*txn` from the message's "t"); 1 nothing there; -1 malformed. */
static int sess_read_reply(sess_t *s, nodus_dnac_cc_collect_result_t *out,
                           uint32_t *txn) {
    static uint8_t buf[1 << 20];
    size_t have = 0;
    nodus_frame_t fr;

    for (;;) {
        ssize_t n = read(s->sv[1], buf + have, sizeof(buf) - have);
        if (n > 0) { have += (size_t)n; continue; }
        if (n < 0 && errno == EINTR) continue;
        break;                               /* EAGAIN / EOF: all read */
    }
    if (have == 0) return 1;
    if (nodus_frame_decode(buf, have, &fr) <= 0) return -1;
    if (nodus_dnac_cc_collect_decode(fr.payload, fr.payload_len, out) != 0)
        return -1;
    {
        cbor_decoder_t dec;
        cbor_decoder_init(&dec, fr.payload, fr.payload_len);
        cbor_item_t top = cbor_decode_next(&dec);
        *txn = UINT32_MAX;
        if (top.type != CBOR_ITEM_MAP) return -1;
        for (size_t i = 0; i < top.count; i++) {
            cbor_item_t k = cbor_decode_next(&dec);
            if (k.type == CBOR_ITEM_TSTR && k.tstr.len == 1 && k.tstr.ptr[0] == 't') {
                cbor_item_t v = cbor_decode_next(&dec);
                if (v.type == CBOR_ITEM_UINT) *txn = (uint32_t)v.uint_val;
            } else {
                cbor_decode_skip(&dec);
            }
        }
    }
    return 0;
}

/* The committee position of key `k` at the tip (the collector's own
 * resolution: nodus_committee_get_for_block_alloc at the tip). */
static int seat_of(nodus_witness_t *w, int k) {
    nodus_committee_member_t *cm = NULL;
    int n = 0, seat = -1;
    uint64_t tip = 0;

    if (nodus_witness_v2_tip_height(w, &tip) != 0 ||
        nodus_committee_get_for_block_alloc(w, tip, &cm, &n) != 0) {
        free(cm);
        return -1;
    }
    for (int i = 0; i < n; i++)
        if (memcmp(cm[i].pubkey, g_ks[k].pk, NODUS_PK_BYTES) == 0) seat = i;
    free(cm);
    return seat;
}

static const nodus_dnac_cc_collect_entry_t *entry_for(
        const nodus_dnac_cc_collect_result_t *r, int seat) {
    for (int i = 0; i < r->count; i++)
        if (r->entries[i].seat == (uint16_t)seat) return &r->entries[i];
    return NULL;
}

/* ══ the cases ═════════════════════════════════════════════════════════ */

static int run(void) {
    int rc = 0;
    gfx_t g;
    sess_t s;
    static nodus_identity_t idA, idS, idX;
    nodus_witness_p2p_t *B = NULL, *A = NULL, *S = NULL, *X = NULL;
    nodus_witness_p2p_t *hosts[4];
    nodus_p2p_config_t cfgB, cfgP;
    char dA[128], dS[128], dX[128];
    char ids[3][CMT_P2P_ID_CAP], id3[CMT_P2P_ID_CAP];
    static const uint8_t env[5] = { 0x01, 0x02, 0x03, 0x04, 0x05 };
    /* an EARLIER collection's envelope: an answer to it is stale here */
    static const uint8_t old_env[5] = { 0x01, 0x02, 0x03, 0x04, 0x06 };
    uint8_t rq[NODUS_T3_CC_APPR_RQ_BYTES], rq_old[NODUS_T3_CC_APPR_RQ_BYTES];
    nodus_dnac_cc_collect_result_t *res = calloc(1, sizeof(*res));
    char err[160];
    uint32_t txn = 0;
    int seat_self, seat_a, seat_s, seat_3;
    int64_t t0;

    memset(&g, 0, sizeof(g));
    memset(&s, 0, sizeof(s));
    s.sv[0] = s.sv[1] = -1;
    CHECK(res != NULL, "result alloc");
    /* the request identity every answer carries (nodus_tier3.h `rq`):
     * SHA3-512 of the envelope asked about */
    CHECK(qgp_sha3_512(env, sizeof(env), rq) == 0 &&
          qgp_sha3_512(old_env, sizeof(old_env), rq_old) == 0, "request ids");
    CHECK(gfx_open(&g, 1) == 0, "the derived version-3 chain (node B = key 1)");
    CHECK(sess_open(&s, g.srv, 1) == 0, "B's own 4001 session (key 1)");
    seat_self = seat_of(g.w, 1);
    seat_a    = seat_of(g.w, 0);
    seat_s    = seat_of(g.w, 2);
    seat_3    = seat_of(g.w, 3);
    CHECK(seat_self >= 0 && seat_a >= 0 && seat_s >= 0 && seat_3 >= 0,
          "keys 0-3 hold seats");

    /* (a) no p2p host: nothing can be asked — the reply is sent at once */
    CHECK(nodus_witness_cc_collect_start(g.w, g_ks[1].pk, s.token, 11, env,
                                         sizeof(env), mono_ms(), err,
                                         sizeof(err)) == 0, err);
    CHECK(g.w->cc_collect == NULL, "(a) nothing asked: no collection pends");
    CHECK(sess_read_reply(&s, res, &txn) == 0, "(a) the reply is on the socket");
    CHECK(txn == 11, "(a) under the request's txn id");
    CHECK(res->count == N_KEYS - 1, "(a) one entry per seat but B's own");
    for (int i = 0; i < res->count; i++) {
        CHECK(res->entries[i].status == NODUS_CC_COLLECT_ST_NOT_CONNECTED &&
              !res->entries[i].ok, "(a) every other seat: not connected");
        CHECK(res->entries[i].seat != (uint16_t)seat_self, "(a) B's own seat absent");
        CHECK(i == 0 || res->entries[i].seat > res->entries[i - 1].seat,
              "(a) ascending seat order");
    }

    /* (c) a node that holds no seat refuses to collect. Run while B has no
     * p2p host yet: the host borrows B's identity, which this case
     * rebinds for one call. */
    {
        nodus_identity_t saved = g.srv->identity;
        CHECK(ident_make(&g.srv->identity, K_X) == 0, "rebind B to X's key");
        err[0] = '\0';
        int crc = nodus_witness_cc_collect_start(g.w, g_ks[K_X].pk, s.token, 13,
                                                 env, sizeof(env), mono_ms(),
                                                 err, sizeof(err));
        g.srv->identity = saved;
        CHECK(crc == -1 && strstr(err, "not a committee seat") != NULL,
              "(c) a non-seat node refuses to collect");
        CHECK(g.w->cc_collect == NULL, "(c) nothing pends");
        CHECK(sess_read_reply(&s, res, &txn) == 1, "(c) nothing written");
    }

    /* the hosts: B (with B's witness), A / S / X (no witness — silent) */
    CHECK(ident_make(&idA, 0) == 0 && ident_make(&idS, 2) == 0 &&
          ident_make(&idX, K_X) == 0, "identities");
    CHECK(key_id(0, ids[0]) == 0 && key_id(2, ids[1]) == 0 &&
          key_id(K_X, ids[2]) == 0 && key_id(3, id3) == 0, "ids");
    CHECK(subdir("A", dA, sizeof(dA)) == 0 && subdir("S", dS, sizeof(dS)) == 0 &&
          subdir("X", dX, sizeof(dX)) == 0, "dirs");
    cfg_local(&cfgB);
    cfg_local(&cfgP);
    B = host_new(g.w, &g.srv->identity, g.chain32, &cfgB, g.dir);
    CHECK(B != NULL, "host B");
    g.w->p2p = B;
    A = host_new(NULL, &idA, g.chain32, &cfgP, dA);
    S = host_new(NULL, &idS, g.chain32, &cfgP, dS);
    X = host_new(NULL, &idX, g.chain32, &cfgP, dX);
    CHECK(A != NULL && S != NULL && X != NULL, "hosts A S X");
    CHECK(dial(A, B) == 0 && dial(S, B) == 0 && dial(X, B) == 0, "dials");
    hosts[0] = B; hosts[1] = A; hosts[2] = S; hosts[3] = X;
    CHECK(drive_until_linked(hosts, 4, B, ids, 3), "A, S and X connected to B");

    /* (b) own-identity gate */
    err[0] = '\0';
    CHECK(nodus_witness_cc_collect_start(g.w, g_ks[0].pk, s.token, 12, env,
                                         sizeof(env), mono_ms(), err,
                                         sizeof(err)) == -1,
          "(b) another identity's request is refused");
    CHECK(strstr(err, "own identity") != NULL, err);
    CHECK(g.w->cc_collect == NULL, "(b) nothing pends");
    CHECK(sess_read_reply(&s, res, &txn) == 1, "(b) nothing written");

    /* (d) start, then busy */
    t0 = mono_ms();
    CHECK(nodus_witness_cc_collect_start(g.w, g_ks[1].pk, s.token, 21, env,
                                         sizeof(env), t0, err,
                                         sizeof(err)) == 0, err);
    CHECK(g.w->cc_collect != NULL, "(d) A and S asked: the collection pends");
    err[0] = '\0';
    CHECK(nodus_witness_cc_collect_start(g.w, g_ks[1].pk, s.token, 22, env,
                                         sizeof(env), t0, err,
                                         sizeof(err)) == -1 &&
          strstr(err, "busy") != NULL, "(d) a second request is refused: busy");
    CHECK(g.w->cc_collect != NULL, "(d) the pending collection is untouched");

    /* (e) only asked peers are heard, and only for THIS request */
    {
        nodus_t3_cc_appr_rsp_t r;
        memset(&r, 0, sizeof(r));
        snprintf(r.reason, sizeof(r.reason), "the envelope failed preflight");
        /* decision 2026-09-27-p2p-fix-2.md (2): A's answer to an EARLIER
         * envelope (its `rq`), or one with no request id at all, is not
         * an answer to this collection — even from a seat it asked */
        memcpy(r.rq, rq_old, sizeof(r.rq));
        CHECK(!nodus_witness_cc_collect_on_rsp(g.w, ids[0], &r),
              "(e) A's STALE answer (another envelope's rq) is not taken");
        memset(r.rq, 0, sizeof(r.rq));
        CHECK(!nodus_witness_cc_collect_on_rsp(g.w, ids[0], &r),
              "(e) A's answer with a zero rq is not taken");
        memcpy(r.rq, rq, sizeof(r.rq));
        CHECK(!nodus_witness_cc_collect_on_rsp(g.w, ids[2], &r),
              "(e) X (connected, never asked) is not heard");
        CHECK(!nodus_witness_cc_collect_on_rsp(g.w, id3, &r),
              "(e) seat 3 (not connected, never asked) is not heard");
        CHECK(nodus_witness_cc_collect_on_rsp(g.w, ids[0], &r),
              "(e) A's refusal is taken");
        CHECK(!nodus_witness_cc_collect_on_rsp(g.w, ids[0], &r),
              "(e) A's second response is not taken");
        CHECK(g.w->cc_collect != NULL, "(e) S still awaited");
    }

    /* (f) deadline */
    nodus_witness_cc_collect_tick(g.w, t0 + (int64_t)NODUS_CC_COLLECT_DEADLINE_MS - 1);
    CHECK(g.w->cc_collect != NULL, "(f) 1 ms before the deadline: still pending");
    CHECK(sess_read_reply(&s, res, &txn) == 1, "(f) no reply yet");
    nodus_witness_cc_collect_tick(g.w, t0 + (int64_t)NODUS_CC_COLLECT_DEADLINE_MS);
    CHECK(g.w->cc_collect == NULL, "(f) at the deadline: ended");

    /* (g) per-seat results */
    CHECK(sess_read_reply(&s, res, &txn) == 0, "(g) the reply is on the socket");
    CHECK(txn == 21, "(g) under the request's txn id");
    CHECK(res->count == N_KEYS - 1, "(g) one entry per seat but B's own");
    CHECK(entry_for(res, seat_self) == NULL, "(g) B's own seat absent");
    {
        const nodus_dnac_cc_collect_entry_t *ea = entry_for(res, seat_a);
        const nodus_dnac_cc_collect_entry_t *es = entry_for(res, seat_s);
        CHECK(ea && ea->status == NODUS_CC_COLLECT_ST_ANSWERED && !ea->ok &&
              strcmp(ea->reason, "the envelope failed preflight") == 0,
              "(g) A: answered, its refusal and reason");
        CHECK(es && es->status == NODUS_CC_COLLECT_ST_NO_ANSWER && !es->ok,
              "(g) S: asked, no answer by the deadline");
        for (int k = 3; k < N_KEYS; k++) {
            const nodus_dnac_cc_collect_entry_t *e = entry_for(res, seat_of(g.w, k));
            CHECK(e && e->status == NODUS_CC_COLLECT_ST_NOT_CONNECTED && !e->ok,
                  "(g) seats 3..6: not connected");
        }
    }
    CHECK(drive_until_drained(hosts, 4, B, ids[0], ids[1]),
          "B's 0x71 queues to A and S drained before the next collection");

    /* (h) approvals round-trip; the last answer ends it with no tick */
    {
        nodus_t3_cc_appr_rsp_t ra, rs;
        memset(&ra, 0, sizeof(ra));
        memset(&rs, 0, sizeof(rs));
        ra.ok = true; ra.seat = (uint16_t)seat_a; ra.epoch = 3;
        memset(ra.sig, 0xA1, sizeof(ra.sig));
        memset(ra.set_hash, 0xA2, sizeof(ra.set_hash));
        rs.ok = true; rs.seat = (uint16_t)seat_s; rs.epoch = 3;
        memset(rs.sig, 0xB1, sizeof(rs.sig));
        memset(rs.set_hash, 0xB2, sizeof(rs.set_hash));
        memcpy(ra.rq, rq, sizeof(ra.rq));
        memcpy(rs.rq, rq, sizeof(rs.rq));

        CHECK(nodus_witness_cc_collect_start(g.w, g_ks[1].pk, s.token, 31, env,
                                             sizeof(env), mono_ms(), err,
                                             sizeof(err)) == 0, err);
        CHECK(nodus_witness_cc_collect_on_rsp(g.w, ids[0], &ra), "(h) A answers");
        CHECK(g.w->cc_collect != NULL, "(h) S still awaited");
        CHECK(nodus_witness_cc_collect_on_rsp(g.w, ids[1], &rs), "(h) S answers");
        CHECK(g.w->cc_collect == NULL, "(h) the last answer ended it");
        CHECK(sess_read_reply(&s, res, &txn) == 0 && txn == 31,
              "(h) the reply is on the socket");
        const nodus_dnac_cc_collect_entry_t *ea = entry_for(res, seat_a);
        const nodus_dnac_cc_collect_entry_t *es = entry_for(res, seat_s);
        CHECK(ea && ea->status == NODUS_CC_COLLECT_ST_ANSWERED && ea->ok &&
              ea->rsp_seat == ra.seat && ea->epoch == 3 &&
              memcmp(ea->sig, ra.sig, sizeof(ra.sig)) == 0 &&
              memcmp(ea->set_hash, ra.set_hash, 64) == 0,
              "(h) A's approval byte-exact");
        CHECK(es && es->status == NODUS_CC_COLLECT_ST_ANSWERED && es->ok &&
              es->rsp_seat == rs.seat &&
              memcmp(es->sig, rs.sig, sizeof(rs.sig)) == 0 &&
              memcmp(es->set_hash, rs.set_hash, 64) == 0,
              "(h) S's approval byte-exact");
    }
    CHECK(drive_until_drained(hosts, 4, B, ids[0], ids[1]),
          "B's 0x71 queues to A and S drained before the next collection");

    /* (i) the session is gone at reply time: nothing is written */
    {
        nodus_t3_cc_appr_rsp_t r;
        memset(&r, 0, sizeof(r));
        snprintf(r.reason, sizeof(r.reason), "refused");
        memcpy(r.rq, rq, sizeof(r.rq));
        CHECK(nodus_witness_cc_collect_start(g.w, g_ks[1].pk, s.token, 41, env,
                                             sizeof(env), mono_ms(), err,
                                             sizeof(err)) == 0, err);
        g.srv->sessions[0].authenticated = false;   /* the CLI went away */
        CHECK(nodus_witness_cc_collect_on_rsp(g.w, ids[0], &r), "(i) A answers");
        CHECK(nodus_witness_cc_collect_on_rsp(g.w, ids[1], &r), "(i) S answers");
        CHECK(g.w->cc_collect == NULL, "(i) the collection ended");
        CHECK(sess_read_reply(&s, res, &txn) == 1,
              "(i) no reply for a session that is gone");
    }

out:
    nodus_witness_p2p_free(A);
    nodus_witness_p2p_free(S);
    nodus_witness_p2p_free(X);
    sess_close(&s, g.srv);
    gfx_close(&g);                   /* frees B */
    free(res);
    return rc;
}

/* Encode {"r": {"res": [ n entries {i, st} ] × n_res keys}} with the r
 * map claiming `r_claim` pairs. @return the length. */
static size_t enc_collect_reply(uint8_t *buf, size_t cap, int n_res, size_t n,
                                size_t r_claim) {
    cbor_encoder_t enc;

    cbor_encoder_init(&enc, buf, cap);
    cbor_encode_map(&enc, 1);
    cbor_encode_cstr(&enc, "r");
    cbor_encode_map(&enc, r_claim);
    for (int k = 0; k < n_res; k++) {
        cbor_encode_cstr(&enc, "res");
        cbor_encode_array(&enc, n);
        for (size_t j = 0; j < n; j++) {
            cbor_encode_map(&enc, 2);
            cbor_encode_cstr(&enc, "i");
            cbor_encode_uint(&enc, (uint64_t)j);
            cbor_encode_cstr(&enc, "st");
            cbor_encode_uint(&enc, 0);
        }
    }
    return cbor_encoder_len(&enc);
}

/* red-team M2 — the client SDK's reply decoder
 * (nodus_dnac_cc_collect_decode):
 *  · ONE "res" key with entries decodes (the control);
 *  · a SECOND "res" key is refused (-1): before the fix its entries were
 *    appended after the first's with `count` running on, so two arrays
 *    each within the cap wrote past `entries[]` (RED: 0 and an
 *    out-of-bounds count);
 *  · a reply whose map claims more pairs than it carries is refused by
 *    the decoder's sticky error flag (RED: 0 — the missing pair read as
 *    an ERROR item and was skipped). */
static int decode_hardening(void) {
    int rc = 0;
    static uint8_t buf[65536];
    nodus_dnac_cc_collect_result_t *res = calloc(1, sizeof(*res));
    size_t cap_entries, n, len;

    CHECK(res != NULL, "result alloc");
    cap_entries = sizeof(res->entries) / sizeof(res->entries[0]);
    n = cap_entries - 1;             /* each array alone fits; two do not */

    len = enc_collect_reply(buf, sizeof(buf), 1, n, 1);
    CHECK(len > 0 && nodus_dnac_cc_collect_decode(buf, len, res) == 0 &&
          res->count == (int)n, "(M2) one res key decodes");

    len = enc_collect_reply(buf, sizeof(buf), 2, n, 2);
    CHECK(len > 0 && nodus_dnac_cc_collect_decode(buf, len, res) == -1,
          "(M2) a second res key is refused");

    len = enc_collect_reply(buf, sizeof(buf), 1, 2, 2);   /* claims 2 pairs */
    CHECK(len > 0 && nodus_dnac_cc_collect_decode(buf, len, res) == -1,
          "(M2) a map short of its claimed pairs is refused (dec.error)");
out:
    free(res);
    return rc;
}

int main(void) {
    int rc;

    snprintf(g_root, sizeof(g_root), "/tmp/test_cc_collect_XXXXXX");
    if (mkdtemp(g_root) == NULL) {
        fprintf(stderr, "mkdtemp failed\n");
        return 1;
    }
    if (make_keys() != 0) {
        fprintf(stderr, "key generation failed\n");
        return 1;
    }
    rc = decode_hardening();
    if (rc == 0) rc = run();
    if (rc == 0) {
        rmrf(g_root);
        fprintf(stderr, "test_cc_collect: all %d checks passed\n", g_checks);
    } else {
        fprintf(stderr, "test_cc_collect: FAILED (%d checks passed before "
                "the failure; %s left behind)\n", g_checks, g_root);
    }
    return rc;
}
