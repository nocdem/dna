/**
 * @file nodus/tests/test_witness_p2p.c
 * @brief The 4004 p2p HOST (nodus_witness_p2p.{h,c}, fleet P2P-PORT phase
 *        F5) driven over REAL loopback sockets, REAL ML-DSA-87 / ML-KEM-1024
 *        keys, the REAL worker threads and a REAL derived version-3 chain.
 *
 * ── WHAT IT PROVES ─────────────────────────────────────────────────────
 * Part 1 — two hosts P and Q (no chain; Q names P as a persistent peer):
 *  (1a) THE WORKER THREADS RUN: creating P with n_workers = 3 adds exactly
 *       3 threads to the process (/proc/self/task) and freeing it removes
 *       them; every handshake below completes, and a handshake job has no
 *       other executor than those threads (h_submit only queues).
 *  (1b) A REAL-SOCKET CONNECTION: Q dials P over 127.0.0.1 and both switch
 *       peer sets name the other's ID (the ID is derived from the
 *       authenticated key, so a wrong key could not produce it).
 *  (1b') BLOCK SYNC 0x40 BEFORE LIVE (the held-StatusResponse DEVIATION,
 *       nodus_witness_p2p.h "THE BLOCK SYNC SEAM"): before Q's lane is
 *       live, P sends a BlockRequest and two StatusResponses (41, then
 *       42) on 0x40. Q stops nobody, holds only the LATEST (42), and at
 *       lane_live — its block sync reactor built and started first —
 *       the reactor's pool already knows P at height 42 (base 1,
 *       maxPeerHeight 42) with NO tick and NO status broadcast
 *       (reactor.go:325), and the held entry is consumed. Q's pool
 *       routine is then stopped (P serves no blocks; its requests would
 *       time P out during (1c)-(1e)).
 *  (1c) CONSENSUS ON 0x20: a real marshalled NewRoundStep sent by P on
 *       channel 0x20 lands in Q's cmt_conr_t — Q's PeerState for P reads
 *       height 5, round 0. Q's lane went live AFTER the connection existed
 *       (the R-P2P-47 admission path, nodus_witness_p2p_lane_live); P's
 *       lane was live before (the switch's InitPeer/AddPeer path).
 *  (1d) CONSENSUS ON 0x21 / 0x22 / 0x23: bytes P sends on each channel are
 *       decoded by Q's cmt_conr_receive — an undecodable body makes the
 *       reactor ask for StopPeerForError (reactor.go:237-240), which the
 *       host defers and runs: Q drops P. The shim has no decoder of its
 *       own, so only the consensus reactor can cause this drop. Q then
 *       re-dials P (persistent, switch.go:343-357) and the reactors see P
 *       again.
 *  (1e) MEMPOOL ON 0x30: a tx admitted to P's mempool (sender 0, the RPC
 *       idiom) is gossiped by P's cmt_memr over channel 0x30 and admitted
 *       to Q's mempool (cmt_mem_size == 1).
 *  (1e') A RECEIVE FAULT STOPS THE LANE (red-team rows 5-n / 5-n+): with
 *       Q's application CheckTx failing (CMT_FAULT, the reference's panic
 *       at mempool/clist_mempool.go:272-274), a second tx P gossips makes
 *       Q's cmt_memr_receive return CMT_FAULT inside the switch's receive
 *       callback, and Q's nodus_witness_p2p_lane_tick then returns
 *       CMT_FAULT — and again on the next call (sticky); P's stays CMT_OK.
 *  (1f) RESTART RE-DIALS PERSISTENT PEERS: Q is freed and rebuilt with the
 *       same identity and config; the new Q dials P on its own (node.go:
 *       563-564) and both sides see each other again.
 * Part 2 — a seat B on a REAL derived version-3 chain (7 committee keys):
 *  (2a) THE BONDED SET is the chain's: B's host reports the committee keys
 *       bonded and an outside key not.
 *  (2a') THE PURGE RUNS ONLY ON A SET CHANGE (RT2 D-F1): the IDs handed
 *       to the address book's purge (nodus_witness_p2p_bonded_joined_total)
 *       are every member at the first refresh, none at a refresh over the
 *       same chain, and every member again after the set was emptied (no
 *       chain database) and refilled. The purge itself — only the given
 *       IDs lose their unsigned entry / ban — is test_p2p_pex's
 *       (test_book_bans). B runs without PEX (no book): the joined count
 *       is computed whether or not a book exists.
 *  (2b) THE INBOUND CAP BINDS THE UNBONDED ONLY (K2): with
 *       max_num_inbound_peers = 1, an unbonded C gets in, a second unbonded
 *       D is refused, and a BONDED A still gets in (B then has 2 inbound
 *       peers, above the cap of 1).
 *  (2c) A WRONG-CHAIN PEER IS REFUSED: E, whose chain id differs in one
 *       byte, fails its dial with an error and B never lists it.
 *  (2d) 0x71 ROUND TRIP, COLLECTED BY THE PROPOSER'S OWN NODE (decision
 *       2026-09-26-cc-approval-via-own-node.md): B starts an approval
 *       collection for its OWN identity's 4001 session (a real
 *       nodus_tcp_conn_t over a socketpair in B's session table) with an
 *       undecodable envelope. B sends the 0x71 request over its EXISTING
 *       connection to seat A — A is a p2p host WITH a witness on the same
 *       chain (a second database handle, key 0) — and A's responder
 *       answers on 0x71: it passes the requester-seat gate (B is a seat)
 *       and refuses at the preflight ("the envelope failed preflight").
 *       B's cc_receive hands that to its collection, which ends (A was
 *       the only connected seat) and writes the reply to the session's
 *       socket: A's seat ANSWERED with that reason, seats 2..6 NOT
 *       CONNECTED, B's own seat absent — decoded with the client SDK's
 *       decoder. No second 4004 identity is ever dialed.
 *  (2e) 0x70 REQUEST / RESPONSE: a fresh joiner J (pin = B's chain id, no
 *       chain) connected to B and to C asks for the genesis bundle on
 *       0x70 (nodus_witness_v2_join_tick), B serves it on 0x70 (from its
 *       in-memory bundle copy, RT2 B-F2), J re-derives it, ADOPTS the
 *       chain (v2_join.active clears, J's chain id equals the pin) and
 *       builds its consensus binding on its OWN p2p host
 *       (nodus_witness_cmt_live_init) — after which J's host reports the
 *       adopted chain's bonded set. C (no witness) answers no 0x70
 *       request: if J's first source is C, C is excluded after one
 *       request interval and B is asked from offset 0 — either order ends
 *       in the adoption.
 *  (2g) 0x70 ONE SOURCE PER DOWNLOAD (decision 2026-09-27-p2p-fix-2.md
 *       (3)), run on J before (2e) with J's own requests (its tick) and
 *       FORGED answers handed to its 0x70 entry: a chunk from the peer
 *       that is not the source is dropped; the source's chunk is taken;
 *       the next chunk is asked of the SAME source; a changed `total`
 *       excludes the source and drops its bytes; the next peer starts
 *       from offset 0; a request left unanswered for an interval
 *       excludes its source, and with every connected peer excluded the
 *       ring is cleared and a source chosen again; a whole bundle that
 *       fails at adopt excludes its source.
 *  (2f) 0x70 OUTSTANDING REQUEST / PER-REQUESTER GATE (red-team H2),
 *       run before (2e): a response is taken only from the peer asked,
 *       for the offset asked, once; a newer request replaces the older;
 *       a request to a peer not held leaves nothing outstanding. B's
 *       serve gate holds a requester for 100 ms without holding back
 *       another. The request C sends names a pin B does not run, so B
 *       answers nothing; the take is driven directly (the joiner's
 *       handle_gbundle_r path is (2e)'s).
 *
 * ── WHAT IT REQUIRES ───────────────────────────────────────────────────
 * Compile flags: none beyond a default build (CMT_SOFTWARE_VERSION, which
 * every cmt_* target gets). Environment: none. Loopback TCP on 127.0.0.1
 * (ephemeral ports), /proc/self/task (Linux), SQLite >= 3.35.0 (the S14
 * rung the chain derivation needs, as test_cc_appr).
 *
 * ── WHAT IT LEAVES BEHIND ──────────────────────────────────────────────
 * One /tmp/test_witness_p2p_XXXXXX directory, removed at the end. A run
 * that fails a check leaves it behind (and its sockets die with the
 * process).
 *
 * ── HOW IT CAN LIE ─────────────────────────────────────────────────────
 *  1. Every wait is bounded (WAIT_MS, 30 s; the joiner 60 s). A machine
 *     that cannot finish a loopback handshake or a reconnect (5-8 s,
 *     switch.go:26 + the dial randomizer) inside the bound FAILS the check
 *     as a timeout — it never passes for the wrong reason. The bounds are
 *     not tuned to a measurement: the test has never been run by its
 *     author (BUILDER agents do not run tests).
 *  2. (1d) proves the bytes of 0x21-0x23 reach cmt_conr_receive through
 *     the decode-failure stop; it does NOT prove a VALID Data / Vote /
 *     VoteSetBits message is acted on — the reactors run with
 *     wait_sync = true (no started state machine, test_cmt_net's former
 *     shape), under which the reference IGNORES those three channels
 *     (reactor.go:317, :336, :358). A live state machine over this host is
 *     the Genesis Protocol harness's ground.
 *  3. Part 1's block store is a zeroed nodus_cmt_store_t (the deleted
 *     test_cmt_net's HOW IT CAN LIE 1 applies unchanged): no gossip branch
 *     that loads a block runs here.
 *  4. (2b)'s refusal of D is observed from outside: D's dial concluded
 *     (the dial observer fired) and D holds no peer afterwards, and B's
 *     peer set never named D. WHICH gate refused D (the switch's inbound
 *     filter or the transport's listener limit) is not distinguished.
 *  5. (2e) depends on the joiner's whole adoption path (bundle apply,
 *     scan, cmt_live_init); a failure anywhere there reads as a 0x70
 *     timeout. B's serve and J's receive are not separately observed.
 *     Whether J asked C first is not asserted (the peer set's order);
 *     the exclusion of an unanswering source is asserted in (2g), where
 *     the "interval" is simulated by clearing last_req_ms, not waited.
 *     (2g)'s answers are forged: that a REAL peer's changed total or bad
 *     bundle reaches the joiner is the path (2e) takes for a good one.
 *  6. The address book file and PEX are not exercised (pex = false on
 *     every host here; test_p2p_addrbook / test_p2p_pex own them).
 *  7. (2d) proves the relay with a REFUSAL (an undecodable envelope): a
 *     seat's SIGNED approval over a valid envelope is test_cc_appr's
 *     (the verdict) and test_cc_collect's (the relay, byte-exact), not
 *     this file's. A's answer must arrive inside B's 5000 ms collection
 *     deadline (B's poll feeds it the real monotonic clock); a slower
 *     machine reads A as NO_ANSWER and the check fails as such.
 *  8. (1e') provokes the sticky lane fault through ONE seam only — the
 *     mempool receive, via the application's CheckTx (no production test
 *     hook exists or is added). The other sites that feed the same flag
 *     (consensus and block sync receive, the held-status replay, the
 *     reactors' InitPeer / AddPeer / RemovePeer) share its one code path
 *     (lane_fault_note / the flag) but are covered by reading, not by this
 *     test. That the witness stops on the lane tick's CMT_FAULT
 *     (nodus_witness.c witness_cmt_tick) is not exercised here either.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sched.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sqlite3.h>

#include "crypto/hash/qgp_sha3.h"
#include "crypto/sign/qgp_dilithium.h"
#include "crypto/enc/qgp_mlkem.h"

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_p2p.h"
#include "witness/nodus_witness_v2_gen.h"
#include "witness/nodus_witness_v2_join.h"
#include "witness/nodus_witness_v2_bundle.h"    /* the served bytes (2e) */
#include "witness/nodus_witness_v2_produce.h"   /* tip height (2d)       */
#include "witness/nodus_witness_committee.h"    /* A's seat index (2d)   */
#include "witness/nodus_witness_emission.h"
#include "server/nodus_server.h"
#include "transport/nodus_tcp.h"
#include "protocol/nodus_tier3.h"
#include "protocol/nodus_wire.h"
#include "nodus/nodus.h"                      /* nodus_dnac_cc_collect_decode */

#include "dnac/dnac.h"
#include "dnac/cmt_mem.h"
#include "dnac/cmt_msgs.h"
#include "dnac/cmt_pb.h"
#include "dnac/cmt_p2p_peer.h"

#include "test_cmt_common.h"

#define WAIT_MS        30000
#define JOIN_WAIT_MS   60000

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

/* ══ keys — deterministic REAL ML-DSA-87 (test_cc_appr.c's shape) ═════ */

#define N_KEYS  ((int)DNAC_COMMITTEE_SIZE)
#define K_C     (N_KEYS + 0)      /* unbonded, admitted under the cap  */
#define K_D     (N_KEYS + 1)      /* unbonded, refused by the cap      */
#define K_E     (N_KEYS + 2)      /* another chain                     */
#define K_P     (N_KEYS + 3)      /* part 1                            */
#define K_Q     (N_KEYS + 4)      /* part 1                            */
#define N_ALL   (N_KEYS + 5)
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

/* A node identity for key `k`: the DSA pair, node_id = SHA3-512(pk), and
 * an ML-KEM-1024 pair from deterministic coins (any valid key serves). */
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

/* Threads in this process right now (Linux). */
static int thread_count(void) {
    DIR *d = opendir("/proc/self/task");
    struct dirent *e;
    int n = 0;

    if (d == NULL) return -1;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] != '.') n++;
    }
    closedir(d);
    return n;
}

/* The thread count once it has come down to `want`, or the last count
 * read. pthread_join returns when the joined thread clears its tid (the
 * CLONE_CHILD_CLEARTID wake in do_exit), BEFORE the kernel removes it
 * from /proc/self/task — measured on this machine: a count read right
 * after joining three threads still listed one of them 238 times in
 * 200 000 (scratchpad join_race.c, 2026-09-28), and no /proc state
 * (Z/X) marks those entries reliably. That lag is what failed this test
 * once under `ctest -j4` ("freeing P did not join its 3 worker threads"
 * after 3.16 s). A thread that was NOT joined never leaves the list, so
 * re-reading until the count drops still tells the two apart; the bound
 * is on reads (each after a sched_yield), not on seconds. */
static int thread_count_settled(int want) {
    int n = thread_count();
    for (int i = 0; i < 100000 && n != want; i++) {
        sched_yield();
        n = thread_count();
    }
    return n;
}

/* ══ hosts ═════════════════════════════════════════════════════════════ */

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
                                     const char *dir, int n_workers) {
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
    prm.n_workers = n_workers;
    return nodus_witness_p2p_new(w, &prm);
}

static void dial_str(const nodus_witness_p2p_t *p, char *out, size_t cap) {
    snprintf(out, cap, "%s@127.0.0.1:%u", nodus_witness_p2p_id(p),
             (unsigned)nodus_witness_p2p_listen_port(p));
}

static bool has_peer(nodus_witness_p2p_t *p, const char *id) {
    return cmt_p2p_peer_set_get(cmt_p2p_switch_peers(nodus_witness_p2p_switch(p)),
                                id) != NULL;
}

/* One dial through the switch (non-persistent), outcome to `obs`. */
typedef struct {
    bool fired;
    int  err;
} dial_obs_t;

static void on_dial(void *ctx, const cmt_p2p_netaddr_t *addr, int err) {
    dial_obs_t *o = (dial_obs_t *)ctx;
    (void)addr;
    o->fired = true;
    o->err = err;
}

static int dial_once(nodus_witness_p2p_t *from, const nodus_witness_p2p_t *to,
                     dial_obs_t *obs) {
    char s[CMT_P2P_NETADDR_STR_MAX];
    const char *list[1];

    memset(obs, 0, sizeof(*obs));
    cmt_p2p_switch_set_dial_observer(nodus_witness_p2p_switch(from), on_dial, obs);
    dial_str(to, s, sizeof(s));
    list[0] = s;
    return cmt_p2p_switch_dial_peers_async(nodus_witness_p2p_switch(from), list, 1)
           == CMT_P2P_ERR_NONE ? 0 : -1;
}

/* ══ the consensus lane of part 1 (test_cmt_net's former fixture shape) */

static int app_error(void *ctx) { (void)ctx; return CMT_OK; }

static int app_check_tx(void *ctx, const cmt_mem_request_check_tx_t *req,
                        cmt_mem_response_check_tx_t *res) {
    (void)ctx; (void)req;
    res->code       = CMT_MEM_CODE_TYPE_OK;
    res->gas_wanted = 0;
    res->gas_used   = 0;
    return CMT_OK;
}

static int app_flush(void *ctx) { (void)ctx; return CMT_OK; }

/* (1e') the application connection failing — the reference panics
 * (mempool/clist_mempool.go:272-274); cmt_mem_check_tx answers CMT_FAULT. */
static int app_check_tx_fault(void *ctx, const cmt_mem_request_check_tx_t *req,
                              cmt_mem_response_check_tx_t *res) {
    (void)ctx; (void)req; (void)res;
    return CMT_FAULT;
}

/* The lane's clock: the wall clock, canonical — the witness's own
 * witness_cmt_now shape. The mempool reactor's sleeps are read against
 * it, so a frozen clock would stall the gossip routine. */
static int real_now(void *ctx, cmt_time_t *out) {
    struct timespec ts;
    cmt_time_t raw;

    (void)ctx;
    if (out == NULL || clock_gettime(CLOCK_REALTIME, &ts) != 0) return CMT_FAULT;
    raw.seconds = (int64_t)ts.tv_sec;
    raw.nanos   = (int32_t)ts.tv_nsec;
    return cmt_time_canonical(raw, out);
}

typedef struct {
    tc_t                 tc;
    nodus_cmt_store_t    store;      /* zeroed — HOW IT CAN LIE 3 */
    cmt_conr_t           conr;
    cmt_mem_app_t        app;
    cmt_mempool_config_t mcfg;
    cmt_mem_t            mem;
    cmt_memr_t           memr;
    bool tc_up, conr_up, mem_up, memr_up;
    nodus_witness_p2p_t *p;
    /* (1b') the block sync reactor, when `want_bs` (built, started and
     * bound BEFORE lane_live, as nodus_witness.c does) */
    bool                 want_bs;
    cmt_bsync_reactor_t *bs;
} lane_t;

/* The block sync reactor's store/executor rows for (1b'): an EMPTY store
 * at the genesis state's height 0 — nothing to serve, nothing to apply
 * (no block reaches this reactor here). */
static int bs_h_zero(void *ctx, int64_t *out) { (void)ctx; *out = 0; return CMT_OK; }
static int bs_h_load(void *ctx, int64_t h, cmt_block_t **out, size_t *hint,
                     bool *found)
{
    (void)ctx; (void)h; (void)hint;
    *out = NULL;
    *found = false;
    return CMT_OK;
}
static int bs_h_ext(void *ctx, int64_t h, cmt_extended_commit_t *out, bool *found)
{
    (void)ctx; (void)h; (void)out;
    *found = false;
    return CMT_OK;
}
static int bs_h_save(void *ctx, cmt_block_t *b, const cmt_part_set_t *ps,
                     const cmt_commit_t *c)
{
    (void)ctx; (void)b; (void)ps; (void)c;
    return CMT_FAULT;
}
static int bs_h_save_ext(void *ctx, cmt_block_t *b, const cmt_part_set_t *ps,
                         const cmt_extended_commit_t *ec)
{
    (void)ctx; (void)b; (void)ps; (void)ec;
    return CMT_FAULT;
}
static int bs_h_abci(void *ctx, cmt_abci_params_t *out)
{
    (void)ctx;
    memset(out, 0, sizeof(*out));
    return CMT_OK;
}
static int bs_h_validate(void *ctx, const cmt_state_t *st, cmt_block_t *b)
{
    (void)ctx; (void)st; (void)b;
    return CMT_FAULT;
}
static int bs_h_apply(void *ctx, const cmt_block_id_t *id, cmt_block_t *b,
                      cmt_state_t *st)
{
    (void)ctx; (void)id; (void)b; (void)st;
    return CMT_FAULT;
}

static int lane_bs_up(lane_t *l, nodus_witness_p2p_t *p) {
    cmt_bsync_host_t   h;
    cmt_bsync_limits_t lim;

    memset(&h, 0, sizeof(h));
    if (nodus_witness_p2p_bsync_host_fill(p, &h) != CMT_OK) return -1;
    h.exec_ctx = NULL;
    h.bs_base = bs_h_zero;
    h.bs_height = bs_h_zero;
    h.bs_load_block = bs_h_load;
    h.bs_load_block_extended_commit = bs_h_ext;
    h.bs_save_block = bs_h_save;
    h.bs_save_block_with_extended_commit = bs_h_save_ext;
    h.ss_load_abci_params = bs_h_abci;
    h.validate_block = bs_h_validate;
    h.apply_verified_block = bs_h_apply;
    lim.max_txs = 16;
    lim.max_evidence = 1;
    l->bs = calloc(1, sizeof(*l->bs));
    if (l->bs == NULL ||
        cmt_bsync_reactor_init(l->bs, l->tc.genesis, true, NULL, 0, &h, &lim) != CMT_OK ||
        cmt_bsync_reactor_start(l->bs) != CMT_OK)
        return -1;
    nodus_witness_p2p_bsync_bind(p, l->bs);
    return 0;
}

static int lane_up(lane_t *l, nodus_witness_p2p_t *p) {
    l->p = p;
    if (tc_setup(&l->tc, 1, 0, 0) != 0) return -1;
    l->tc_up = true;
    if (nodus_witness_p2p_lane_prepare(p, &l->store, real_now, NULL) != CMT_OK)
        return -1;
    if (cmt_conr_init(&l->conr, l->tc.cs, true /* wait_sync */,
                      nodus_witness_p2p_conr_host(p), p,
                      nodus_witness_p2p_recv_arena(p)) != CMT_OK)
        return -1;
    l->conr_up = true;
    if (cmt_conr_start(&l->conr) != CMT_OK) return -1;
    l->app.ctx      = NULL;
    l->app.error    = app_error;
    l->app.check_tx = app_check_tx;
    l->app.flush    = app_flush;
    if (cmt_mempool_config_default(&l->mcfg) != CMT_OK) return -1;
    if (cmt_mem_init(&l->mem, &l->mcfg, &l->app, 0, NULL, NULL) != CMT_OK)
        return -1;
    l->mem_up = true;
    if (cmt_memr_init(&l->memr, &l->mcfg, &l->mem,
                      nodus_witness_p2p_memr_host(p)) != CMT_OK)
        return -1;
    l->memr_up = true;
    if (cmt_memr_start(&l->memr) != CMT_OK) return -1;
    nodus_witness_p2p_lane_bind(p, &l->conr, &l->memr);
    if (l->want_bs && lane_bs_up(l, p) != 0) return -1;
    return nodus_witness_p2p_lane_live(p) == CMT_OK ? 0 : -1;
}

/* Before the host is freed (the host lets go of the reactors first). */
static void lane_down(lane_t *l) {
    if (l->p != NULL) nodus_witness_p2p_lane_unbind(l->p);
    if (l->bs != NULL) {
        cmt_bsync_reactor_stop(l->bs);
        cmt_bsync_reactor_free(l->bs);
        free(l->bs);
        l->bs = NULL;
    }
    if (l->memr_up) cmt_memr_free(&l->memr);
    if (l->mem_up)  cmt_mem_free(&l->mem);
    if (l->conr_up) cmt_conr_free(&l->conr);
    if (l->tc_up)   tc_teardown(&l->tc);
    l->memr_up = l->mem_up = l->conr_up = l->tc_up = false;
    l->p = NULL;
}

/* The index of the one peer the consensus reactor holds, or -1. */
static int conr_only_peer(const cmt_conr_t *c) {
    int found = -1;
    for (int i = 0; i < CMT_CONR_MAX_PEERS; i++) {
        if (c->peers[i].in_set) {
            if (found >= 0) return -1;
            found = i;
        }
    }
    return found;
}

/* A real marshalled NewRoundStep (height 5, round 0) — the deleted
 * test_cmt_net.c's build_new_round_step. */
static int build_new_round_step(uint8_t *out, size_t cap, size_t *out_len) {
    cmt_msg_t             msg;
    cmt_pb_cons_message_t pb;

    memset(&msg, 0, sizeof(msg));
    msg.kind                               = CMT_PB_CONS_MSG_NEW_ROUND_STEP;
    msg.u.new_round_step.height            = 5;
    msg.u.new_round_step.round             = 0;
    msg.u.new_round_step.step              = CMT_ROUND_STEP_NEW_HEIGHT;
    msg.u.new_round_step.last_commit_round = 0;
    cmt_pb_cons_message_init(&pb);
    if (cmt_msg_to_proto(&msg, &pb) != CMT_OK) return -1;
    return cmt_pb_cons_message_marshal(&pb, out, cap, out_len) == CMT_OK ? 0 : -1;
}

/* ══ the driver: every host polled in turn until `pred` holds ═════════ */

typedef struct {
    nodus_witness_p2p_t *p;
    bool                 lane;      /* its lane is live: tick it        */
    nodus_witness_t     *joiner;    /* run its join tick                */
} drv_t;

typedef bool (*pred_fn)(void *ctx);

static bool drive(drv_t *d, int n, pred_fn pred, void *ctx, int64_t budget_ms) {
    int64_t end = mono_ms() + budget_ms;

    for (;;) {
        for (int i = 0; i < n; i++) {
            if (d[i].joiner != NULL) nodus_witness_v2_join_tick(d[i].joiner);
            if (d[i].p != NULL) nodus_witness_p2p_poll(d[i].p, 1);
            if (d[i].p != NULL && d[i].lane)
                (void)nodus_witness_p2p_lane_tick(d[i].p, NULL);
        }
        if (pred(ctx)) return true;
        if (mono_ms() > end) return false;
    }
}

/* ── predicates ─────────────────────────────────────────────────────── */

typedef struct {
    nodus_witness_p2p_t *a, *b;
    lane_t *la, *lb;             /* when set: the reactors hold the peer */
} pair_t;

static bool pred_linked(void *ctx) {
    pair_t *x = (pair_t *)ctx;
    if (!has_peer(x->a, nodus_witness_p2p_id(x->b)) ||
        !has_peer(x->b, nodus_witness_p2p_id(x->a)))
        return false;
    if (x->la != NULL && conr_only_peer(&x->la->conr) < 0) return false;
    if (x->lb != NULL && conr_only_peer(&x->lb->conr) < 0) return false;
    return true;
}

static bool pred_unlinked_at_b(void *ctx) {
    pair_t *x = (pair_t *)ctx;
    return !has_peer(x->b, nodus_witness_p2p_id(x->a));
}

static bool pred_nrs(void *ctx) {
    lane_t *l = (lane_t *)ctx;
    int i = conr_only_peer(&l->conr);
    cmt_prs_t prs;

    if (i < 0) return false;
    cmt_ps_get_round_state(&l->conr.peers[i].ps, &prs);
    return prs.height == 5 && prs.round == 0;
}

static bool pred_mempool_one(void *ctx) {
    return cmt_mem_size(&((lane_t *)ctx)->mem) == 1;
}

/* (1e') the host's lane tick reports the fault a receive raised. */
static bool pred_lane_fault(void *ctx) {
    return nodus_witness_p2p_lane_tick((nodus_witness_p2p_t *)ctx, NULL)
           == CMT_FAULT;
}

typedef struct {
    dial_obs_t *obs;
    nodus_witness_p2p_t *dialer;
} dial_done_t;

static bool pred_dial_settled(void *ctx) {
    dial_done_t *x = (dial_done_t *)ctx;
    return x->obs->fired && nodus_witness_p2p_peer_count(x->dialer) == 0;
}

static bool pred_dial_fired(void *ctx) {
    return ((dial_obs_t *)ctx)->fired;
}

typedef struct {
    nodus_witness_p2p_t *p;
    const char *id;
} has_t;

static bool pred_has(void *ctx) {
    has_t *x = (has_t *)ctx;
    return has_peer(x->p, x->id);
}

/* (1b') the host holds `id`'s StatusResponse at height 42. The two
 * statuses travel on one channel in order, so 42 held means 41 was
 * seen and replaced. */
static bool pred_bs_held_42(void *ctx) {
    has_t *x = (has_t *)ctx;
    int64_t h = -1;

    return nodus_witness_p2p_bsync_status_held(x->p, x->id, &h) && h == 42;
}

static bool pred_join_done(void *ctx) {
    return !nodus_witness_v2_join_active((nodus_witness_t *)ctx);
}

typedef struct {
    nodus_witness_p2p_t *p;
    const char *id1, *id2;
} pair2_t;

static bool pred_has_both(void *ctx) {
    pair2_t *x = (pair2_t *)ctx;
    return has_peer(x->p, x->id1) && has_peer(x->p, x->id2);
}

/* ══ PART 1 — P and Q ══════════════════════════════════════════════════ */

static int part1(void) {
    int rc = 0;
    static nodus_identity_t idP, idQ;
    static const uint8_t chain[32] = {
        0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
        0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
        0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
        0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a };
    nodus_p2p_config_t cfgP, cfgQ;
    char dirP[128], dirQ[128], sP[CMT_P2P_NETADDR_STR_MAX];
    char idp[CMT_P2P_ID_CAP], idq[CMT_P2P_ID_CAP];
    nodus_witness_p2p_t *P = NULL, *Q = NULL;
    lane_t *lP = calloc(1, sizeof(*lP)), *lQ = calloc(1, sizeof(*lQ));
    drv_t d[2];
    pair_t pr;
    int t0;

    CHECK(lP != NULL && lQ != NULL, "lane alloc");
    CHECK(ident_make(&idP, K_P) == 0 && ident_make(&idQ, K_Q) == 0, "identities");
    CHECK(key_id(K_P, idp) == 0 && key_id(K_Q, idq) == 0, "ids");
    CHECK(subdir("P", dirP, sizeof(dirP)) == 0 &&
          subdir("Q", dirQ, sizeof(dirQ)) == 0, "dirs");

    /* (1a) the worker threads */
    cfg_local(&cfgP);
    t0 = thread_count();
    CHECK(t0 > 0, "/proc/self/task readable");
    P = host_new(NULL, &idP, chain, &cfgP, dirP, 3);
    CHECK(P != NULL, "host P");
    CHECK(thread_count() == t0 + 3, "(1a) n_workers = 3 started 3 threads");
    CHECK(strcmp(nodus_witness_p2p_id(P), idp) == 0, "P's id is its key's");
    CHECK(nodus_witness_p2p_listen_port(P) != 0, "P listens");
    /* P's lane is live BEFORE any peer exists: the switch's InitPeer /
     * AddPeer path feeds its reactors. */
    CHECK(lane_up(lP, P) == 0, "P's lane");

    cfg_local(&cfgQ);
    dial_str(P, sP, sizeof(sP));
    CHECK(nodus_p2p_config_add_persistent(&cfgQ, sP) == 0, "Q persistent P");
    Q = host_new(NULL, &idQ, chain, &cfgQ, dirQ, 0);
    CHECK(Q != NULL, "host Q");

    /* (1b) real-socket connection */
    memset(&pr, 0, sizeof(pr));
    pr.a = P; pr.b = Q; pr.la = lP;
    memset(d, 0, sizeof(d));
    d[0].p = P; d[0].lane = true;
    d[1].p = Q;
    CHECK(drive(d, 2, pred_linked, &pr, WAIT_MS), "(1b) P and Q connected");
    CHECK(nodus_witness_p2p_peer_count(P) == 1 &&
          nodus_witness_p2p_peer_count(Q) == 1, "(1b) one peer each");

    /* (1b') 0x40 BEFORE Q's lane is live (the block sync seam's
     * DEVIATION, nodus_witness_p2p.h): P sends a BlockRequest (dropped,
     * P not stopped) and then TWO StatusResponses; Q holds only the
     * latest, and the moment its lane goes live — block sync reactor
     * started first — the pool knows P at height 42 without any tick,
     * i.e. without waiting for the 10 s status broadcast (reactor.go:325). */
    {
        cmt_bsync_msg_t m;
        uint8_t b[32];
        size_t n = 0;
        const cmt_bsync_peer_t *bp;
        has_t hq = { Q, idp };

        cmt_bsync_msg_init(&m);
        m.kind = CMT_BSYNC_MSG_BLOCK_REQUEST;
        m.height = 1;
        CHECK(cmt_bsync_msg_marshal(&m, b, sizeof(b), &n) == CMT_OK, "(1b') BlockRequest");
        CHECK(nodus_witness_p2p_send(P, idq, CMT_BSYNC_CHANNEL, b, n), "(1b') send BlockRequest");
        m.kind = CMT_BSYNC_MSG_STATUS_RESPONSE;
        m.base = 1;
        m.height = 41;
        CHECK(cmt_bsync_msg_marshal(&m, b, sizeof(b), &n) == CMT_OK, "(1b') status 41");
        CHECK(nodus_witness_p2p_send(P, idq, CMT_BSYNC_CHANNEL, b, n), "(1b') send status 41");
        m.height = 42;
        CHECK(cmt_bsync_msg_marshal(&m, b, sizeof(b), &n) == CMT_OK, "(1b') status 42");
        CHECK(nodus_witness_p2p_send(P, idq, CMT_BSYNC_CHANNEL, b, n), "(1b') send status 42");
        CHECK(drive(d, 2, pred_bs_held_42, &hq, WAIT_MS),
              "(1b') Q holds P's LATEST StatusResponse (42, not 41) before "
              "its lane is live");
        CHECK(has_peer(Q, idp) && has_peer(P, idq),
              "(1b') nothing received before live stops the peer");

        lQ->want_bs = true;
        CHECK(lane_up(lQ, Q) == 0, "Q's lane (with block sync)");
        bp = cmt_bsync_pool_peer(cmt_bsync_reactor_pool(lQ->bs), idp);
        CHECK(bp != NULL && bp->height == 42 && bp->base == 1,
              "(1b') at lane_live the pool knows P at 42 — no tick, no broadcast");
        CHECK(cmt_bsync_pool_max_peer_height(cmt_bsync_reactor_pool(lQ->bs)) == 42,
              "(1b') maxPeerHeight 42");
        CHECK(!nodus_witness_p2p_bsync_status_held(Q, idp, NULL),
              "(1b') the held status is consumed by the replay");
        /* Stop the pool routine: P serves no blocks (it has no block sync
         * reactor), so Q's requests would time P out (pool.go:623-631) in
         * the middle of (1c)-(1e). Receive keeps working when stopped. */
        cmt_bsync_reactor_stop(lQ->bs);
    }
    d[1].lane = true;
    pr.lb = lQ;
    CHECK(drive(d, 2, pred_linked, &pr, WAIT_MS),
          "(1c) the reactors hold the peer on both sides");

    /* (1c) 0x20 */
    {
        uint8_t nrs[256];
        size_t len = 0;
        CHECK(build_new_round_step(nrs, sizeof(nrs), &len) == 0, "build NRS");
        CHECK(nodus_witness_p2p_send(P, idq, 0x20, nrs, len), "(1c) send 0x20");
        CHECK(drive(d, 2, pred_nrs, lQ, WAIT_MS),
              "(1c) NewRoundStep on 0x20 reached Q's consensus reactor");
        CHECK(has_peer(Q, idp), "(1c) a valid 0x20 message keeps the peer");
    }

    /* (1d) 0x21 / 0x22 / 0x23 — undecodable body, the reactor stops P */
    for (uint8_t ch = 0x21; ch <= 0x23; ch++) {
        static const uint8_t junk[3] = { 0xff, 0xff, 0xff };
        char what[96];

        snprintf(what, sizeof(what), "(1d) send 0x%02x", ch);
        CHECK(nodus_witness_p2p_send(P, idq, ch, junk, sizeof(junk)), what);
        snprintf(what, sizeof(what),
                 "(1d) Q's consensus reactor decoded 0x%02x and dropped P", ch);
        CHECK(drive(d, 2, pred_unlinked_at_b, &pr, WAIT_MS), what);
        snprintf(what, sizeof(what),
                 "(1d) Q re-dialed its persistent peer after 0x%02x", ch);
        CHECK(drive(d, 2, pred_linked, &pr, WAIT_MS), what);
    }

    /* (1e) 0x30 */
    {
        static const uint8_t tx[8] = { 9, 9, 9, 9, 9, 9, 9, 9 };
        cmt_mem_tx_info_t info;

        memset(&info, 0, sizeof(info));        /* sender 0: the RPC idiom */
        CHECK(cmt_mem_check_tx(&lP->mem, tx, sizeof(tx), &info, NULL, NULL)
              == CMT_OK, "(1e) P admits the tx");
        CHECK(cmt_mem_size(&lP->mem) == 1, "(1e) P holds it");
        CHECK(drive(d, 2, pred_mempool_one, lQ, WAIT_MS),
              "(1e) the tx crossed channel 0x30 into Q's mempool");
    }

    /* (1e') a CMT_FAULT inside a receive callback reaches the lane tick
     * (red-team rows 5-n / 5-n+): Q's application connection now fails,
     * P gossips a SECOND tx (the first is in Q's cache and would not
     * reach CheckTx), Q's cmt_memr_receive answers CMT_FAULT from inside
     * the switch's callback, and Q's nodus_witness_p2p_lane_tick — the
     * call on which the witness stops participating — returns CMT_FAULT,
     * and keeps returning it. P is untouched: the fault is Q's own. */
    {
        static const uint8_t tx2[8] = { 7, 7, 7, 7, 7, 7, 7, 7 };
        cmt_mem_tx_info_t info;

        CHECK(nodus_witness_p2p_lane_tick(Q, NULL) == CMT_OK,
              "(1e') before the fault Q's lane tick is OK");
        lQ->app.check_tx = app_check_tx_fault;   /* cmt_mem keeps &lQ->app */
        memset(&info, 0, sizeof(info));
        CHECK(cmt_mem_check_tx(&lP->mem, tx2, sizeof(tx2), &info, NULL, NULL)
              == CMT_OK, "(1e') P admits the second tx");
        CHECK(drive(d, 2, pred_lane_fault, Q, WAIT_MS),
              "(1e') Q's receive FAULT surfaces as a lane-tick CMT_FAULT");
        CHECK(nodus_witness_p2p_lane_tick(Q, NULL) == CMT_FAULT,
              "(1e') the lane fault is sticky");
        CHECK(nodus_witness_p2p_lane_tick(P, NULL) == CMT_OK,
              "(1e') P's lane is not faulted");
    }

    /* (1f) restart Q: the new Q dials its persistent peer on its own */
    lane_down(lQ);
    nodus_witness_p2p_free(Q);
    Q = NULL;
    Q = host_new(NULL, &idQ, chain, &cfgQ, dirQ, 0);
    CHECK(Q != NULL, "host Q rebuilt");
    d[1].p = Q; d[1].lane = false;
    pr.b = Q; pr.lb = NULL;
    CHECK(drive(d, 2, pred_linked, &pr, WAIT_MS),
          "(1f) the restarted Q re-dialed P");

out:
    if (lQ != NULL) lane_down(lQ);
    nodus_witness_p2p_free(Q);
    if (lP != NULL) lane_down(lP);
    if (P != NULL) {
        /* Back to the count before P existed (Q runs no workers): a count
         * read here, right after Q's free, could itself still list a
         * thread the kernel has not reaped (thread_count_settled). */
        nodus_witness_p2p_free(P);
        if (rc == 0 && thread_count_settled(t0) != t0) {
            fprintf(stderr, "CHECK failed: (1a) freeing P did not join its "
                    "3 worker threads\n");
            rc = 1;
        } else if (rc == 0) {
            g_checks++;
        }
    }
    free(lP);
    free(lQ);
    return rc;
}

/* ══ PART 2 — the chain fixture (test_cc_appr.c:156-277's shape, this
 * file's own copy: the tree's per-file fixture convention) ═══════════ */

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
    cfgbox_t         box;
    char             dir[128];
    uint8_t          chain32[32];
} gfx_t;

/* The seat: the derived chain opened as a successor, identity key `k`. */
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
    g->w->server = g->srv;
    memcpy(g->w->my_id, g_ks[k].voter, 32);
    return 0;
}

static void gfx_close(gfx_t *g) {
    if (g->w) {
        nodus_witness_p2p_free(g->w->p2p);
        g->w->p2p = NULL;
        if (g->w->db) sqlite3_close(g->w->db);
        free(g->w);
        g->w = NULL;
    }
    free(g->srv); g->srv = NULL;
    cfg_free(&g->box);
}

/* (2d) — a second witness on the SAME chain database (its own handle),
 * identity key `k`: seat A's responder. */
static int seat_witness_open(const gfx_t *g, int k, nodus_witness_t **w_out,
                             nodus_server_t **s_out) {
    char path[600], hex[33];
    nodus_witness_t *w = calloc(1, sizeof(*w));
    nodus_server_t  *s = calloc(1, sizeof(*s));

    *w_out = w;
    *s_out = s;
    if (!w || !s) return -1;
    for (int i = 0; i < 16; i++) snprintf(hex + 2 * i, 3, "%02x", g->chain32[i]);
    hex[32] = '\0';
    snprintf(path, sizeof(path), "%s/witness_%s.db", g->dir, hex);
    if (sqlite3_open_v2(path, &w->db, SQLITE_OPEN_READWRITE, NULL) != SQLITE_OK)
        return -1;
    snprintf(w->data_path, sizeof(w->data_path), "%s", g->dir);
    w->cached_committee_epoch_start = UINT64_MAX;
    w->v2_successor     = true;
    w->v2_ingress_armed = true;
    memcpy(w->v2_chain32, g->chain32, 32);
    if (ident_make(&s->identity, k) != 0) return -1;
    w->server = s;
    memcpy(w->my_id, g_ks[k].voter, 32);
    return 0;
}

/* (2d) — the requesting 4001 session: a real nodus_tcp_conn_t over one
 * end of a socketpair, in `srv`'s session table as identity key `k`. */
typedef struct {
    int               sv[2];          /* [0] the node's end, [1] ours  */
    nodus_tcp_conn_t *conn;
    uint8_t           token[NODUS_SESSION_TOKEN_LEN];
} sess_t;

static int sess_open(sess_t *s, nodus_server_t *srv, int k) {
    s->sv[0] = s->sv[1] = -1;
    s->conn = NULL;
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, s->sv) != 0) return -1;
    if (fcntl(s->sv[0], F_SETFL, O_NONBLOCK) != 0 ||
        fcntl(s->sv[1], F_SETFL, O_NONBLOCK) != 0)
        return -1;
    s->conn = calloc(1, sizeof(*s->conn));
    if (!s->conn) return -1;
    s->conn->fd = s->sv[0];
    s->conn->state = NODUS_CONN_CONNECTED;
    memset(s->token, 0x3c, sizeof(s->token));
    memset(&srv->sessions[0], 0, sizeof(srv->sessions[0]));
    srv->sessions[0].conn = s->conn;
    srv->sessions[0].authenticated = true;
    memcpy(srv->sessions[0].client_pk.bytes, g_ks[k].pk, NODUS_PK_BYTES);
    memcpy(srv->sessions[0].token, s->token, sizeof(s->token));
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

/* Read the one framed reply off our end and decode it with the client
 * SDK's decoder. @return 0; 1 nothing there; -1 malformed. */
static int sess_read_reply(sess_t *s, nodus_dnac_cc_collect_result_t *out) {
    static uint8_t buf[1 << 20];
    size_t have = 0;
    nodus_frame_t fr;

    for (;;) {
        ssize_t n = read(s->sv[1], buf + have, sizeof(buf) - have);
        if (n > 0) { have += (size_t)n; continue; }
        if (n < 0 && errno == EINTR) continue;
        break;
    }
    if (have == 0) return 1;
    if (nodus_frame_decode(buf, have, &fr) <= 0) return -1;
    return nodus_dnac_cc_collect_decode(fr.payload, fr.payload_len, out) == 0
           ? 0 : -1;
}

static bool pred_collect_done(void *ctx) {
    return ((nodus_witness_t *)ctx)->cc_collect == NULL;
}

static int part2(void) {
    int rc = 0;
    gfx_t g;
    static nodus_identity_t idA, idC, idD, idE;
    nodus_witness_p2p_t *A = NULL, *C = NULL, *D = NULL, *E = NULL, *B = NULL;
    nodus_witness_t *wJ = NULL, *wA = NULL;
    nodus_server_t *sJ = NULL, *sA = NULL;
    sess_t sess = { { -1, -1 }, NULL, { 0 } };
    nodus_dnac_cc_collect_result_t *cres = NULL;
    nodus_p2p_config_t cfgB, cfgX, cfgJ;
    char dA[128], dC[128], dD[128], dE[128], dJ[128];
    char ida[CMT_P2P_ID_CAP], idc[CMT_P2P_ID_CAP], idd[CMT_P2P_ID_CAP];
    char ide[CMT_P2P_ID_CAP], idb[CMT_P2P_ID_CAP];
    uint8_t other_chain[32];
    dial_obs_t obs;
    drv_t d[6];
    int nd;

    memset(&g, 0, sizeof(g));
    CHECK(gfx_open(&g, 1) == 0, "the derived version-3 chain (seat = key 1)");
    CHECK(ident_make(&idA, 0) == 0 && ident_make(&idC, K_C) == 0 &&
          ident_make(&idD, K_D) == 0 && ident_make(&idE, K_E) == 0, "identities");
    CHECK(key_id(0, ida) == 0 && key_id(K_C, idc) == 0 && key_id(K_D, idd) == 0 &&
          key_id(K_E, ide) == 0 && key_id(1, idb) == 0, "ids");
    CHECK(subdir("A", dA, sizeof(dA)) == 0 && subdir("C", dC, sizeof(dC)) == 0 &&
          subdir("D", dD, sizeof(dD)) == 0 && subdir("E", dE, sizeof(dE)) == 0 &&
          subdir("J", dJ, sizeof(dJ)) == 0, "dirs");

    cfg_local(&cfgB);
    cfgB.max_num_inbound_peers = 1;
    B = host_new(g.w, &g.srv->identity, g.chain32, &cfgB, g.dir, 0);
    CHECK(B != NULL, "host B");
    g.w->p2p = B;

    /* (2a) the bonded set is the chain's */
    CHECK(nodus_witness_p2p_bonded_count(B) >= 1, "(2a) B has a bonded set");
    for (int k = 0; k < N_KEYS; k++) {
        char id[CMT_P2P_ID_CAP];
        CHECK(key_id(k, id) == 0 && nodus_witness_p2p_is_bonded(B, id),
              "(2a) every committee key is bonded");
    }
    CHECK(!nodus_witness_p2p_is_bonded(B, idc) && !nodus_witness_p2p_is_bonded(B, idd),
          "(2a) an outside key is not bonded");

    /* (2a') RT2 D-F1 — the purge's input is only the IDs that JOINED the
     * set: the first refresh (from no set) joined every member; a refresh
     * over the same chain joins none; a set emptied (no chain database)
     * and refilled joins every member again. */
    {
        uint64_t j0 = nodus_witness_p2p_bonded_joined_total(B);
        int nb = nodus_witness_p2p_bonded_count(B);
        sqlite3 *keep = g.w->db;

        CHECK(j0 == (uint64_t)nb, "(2a') the first refresh joined every member");
        nodus_witness_p2p_refresh_bonded(B);
        CHECK(nodus_witness_p2p_bonded_joined_total(B) == j0 &&
              nodus_witness_p2p_bonded_count(B) == nb,
              "(2a') an unchanged set joins nothing: no purge");
        g.w->db = NULL;
        nodus_witness_p2p_refresh_bonded(B);
        CHECK(nodus_witness_p2p_bonded_count(B) == 0, "(2a') no chain: empty set");
        g.w->db = keep;
        nodus_witness_p2p_refresh_bonded(B);
        CHECK(nodus_witness_p2p_bonded_count(B) == nb &&
              nodus_witness_p2p_bonded_joined_total(B) == j0 + (uint64_t)nb,
              "(2a') refilled: every member joined again");
    }

    cfg_local(&cfgX);
    /* A is seat key 0 WITH a witness on the same chain (a second
     * database handle): its responder answers B's 0x71 request in (2d). */
    CHECK(seat_witness_open(&g, 0, &wA, &sA) == 0, "seat A's witness (key 0)");
    A = host_new(wA, &sA->identity, g.chain32, &cfgX, dA, 0);
    if (A != NULL) wA->p2p = A;
    C = host_new(NULL, &idC, g.chain32, &cfgX, dC, 0);
    D = host_new(NULL, &idD, g.chain32, &cfgX, dD, 0);
    memcpy(other_chain, g.chain32, 32);
    other_chain[31] ^= 0x01;
    E = host_new(NULL, &idE, other_chain, &cfgX, dE, 0);
    CHECK(A != NULL && C != NULL && D != NULL && E != NULL, "hosts A C D E");

    memset(d, 0, sizeof(d));
    d[0].p = B; d[1].p = A; d[2].p = C; d[3].p = D; d[4].p = E;
    nd = 5;

    /* (2b) unbonded C under the cap: in */
    {
        has_t h = { B, idc };
        CHECK(dial_once(C, B, &obs) == 0, "C dials B");
        CHECK(drive(d, nd, pred_has, &h, WAIT_MS), "(2b) unbonded C admitted (1/1)");
    }
    /* (2b) unbonded D over the cap: refused */
    {
        dial_done_t x = { &obs, D };
        CHECK(dial_once(D, B, &obs) == 0, "D dials B");
        CHECK(drive(d, nd, pred_dial_settled, &x, WAIT_MS),
              "(2b) D's dial concluded and D holds no peer");
        CHECK(!has_peer(B, idd), "(2b) unbonded D refused over the cap");
    }
    /* (2b) bonded A over the cap: in */
    {
        has_t h = { B, ida };
        CHECK(dial_once(A, B, &obs) == 0, "A dials B");
        CHECK(drive(d, nd, pred_has, &h, WAIT_MS), "(2b) bonded A admitted over the cap");
        CHECK(has_peer(B, idc) && !has_peer(B, idd), "(2b) C kept, D absent");
    }

    /* (2c) wrong chain: refused */
    CHECK(dial_once(E, B, &obs) == 0, "E dials B");
    CHECK(drive(d, nd, pred_dial_fired, &obs, WAIT_MS), "(2c) E's dial concluded");
    CHECK(obs.err != CMT_P2P_ERR_NONE, "(2c) E's dial failed");
    CHECK(!has_peer(B, ide) && nodus_witness_p2p_peer_count(E) == 0,
          "(2c) the wrong-chain peer is on neither side");

    /* (2d) 0x71 collected by B for its own identity: B asks seat A over
     * the existing connection; A's responder refuses the undecodable
     * envelope at the preflight (the requester gate passed: B is a seat). */
    {
        static const uint8_t junk_env[3] = { 0x01, 0x02, 0x03 };
        char err[160];
        nodus_committee_member_t *cm = NULL;
        int cmn = 0, seat_a = -1, seat_b = -1;
        uint64_t tip = 0;

        cres = calloc(1, sizeof(*cres));
        CHECK(cres != NULL, "(2d) result alloc");
        CHECK(nodus_witness_v2_tip_height(g.w, &tip) == 0 &&
              nodus_committee_get_for_block_alloc(g.w, tip, &cm, &cmn) == 0,
              "(2d) the committee at the tip");
        for (int i = 0; i < cmn; i++) {
            if (memcmp(cm[i].pubkey, g_ks[0].pk, NODUS_PK_BYTES) == 0) seat_a = i;
            if (memcmp(cm[i].pubkey, g_ks[1].pk, NODUS_PK_BYTES) == 0) seat_b = i;
        }
        free(cm);
        CHECK(seat_a >= 0 && seat_b >= 0 && cmn == N_KEYS, "(2d) A and B hold seats");
        CHECK(sess_open(&sess, g.srv, 1) == 0, "(2d) B's own 4001 session");
        CHECK(nodus_witness_cc_collect_start(g.w, g_ks[1].pk, sess.token, 7,
                                             junk_env, sizeof(junk_env),
                                             nodus_p2p_mono_ns(NULL) / 1000000,
                                             err, sizeof(err)) == 0, err);
        CHECK(g.w->cc_collect != NULL, "(2d) A was asked: the collection pends");
        CHECK(drive(d, nd, pred_collect_done, g.w, WAIT_MS),
              "(2d) the collection ended");
        CHECK(sess_read_reply(&sess, cres) == 0, "(2d) the reply is on B's session");
        CHECK(cres->count == N_KEYS - 1, "(2d) one entry per seat but B's own");
        for (int i = 0; i < cres->count; i++) {
            const nodus_dnac_cc_collect_entry_t *e = &cres->entries[i];
            CHECK(e->seat != (uint16_t)seat_b, "(2d) B's own seat absent");
            if (e->seat == (uint16_t)seat_a) {
                CHECK(e->status == NODUS_CC_COLLECT_ST_ANSWERED && !e->ok,
                      e->status == NODUS_CC_COLLECT_ST_NO_ANSWER
                          ? "(2d) A did not answer inside B's deadline"
                          : "(2d) A answered with a refusal");
                CHECK(strcmp(e->reason, "the envelope failed preflight") == 0,
                      e->reason);
            } else {
                CHECK(e->status == NODUS_CC_COLLECT_ST_NOT_CONNECTED,
                      "(2d) every other seat: not connected to B");
            }
        }
    }

    /* (2f) red-team H2 — 0x70: the joiner's ONE outstanding request and
     * the serving side's per-requester gate. C (connected to B) sends a
     * real 0x70 request through nodus_witness_p2p_gb_request — naming a
     * pin B does not run, so B answers nothing and nothing else moves.
     * A response is taken only from the peer asked, for the offset asked,
     * once; a newer request replaces the older (its late answer is
     * dropped). Every refusal is a DROP (the caller stops nobody). */
    {
        nodus_t3_w_v2_gbundle_q_t q;
        uint8_t qb[128];
        size_t ql = 0;

        memset(&q, 0, sizeof(q));
        memcpy(q.chain, other_chain, 32);
        memcpy(q.pin, other_chain, 32);
        q.offset = 0;
        CHECK(nodus_t3_gbundle_q_encode(&q, qb, sizeof(qb), &ql) == 0, "(2f) encode @0");
        CHECK(!nodus_witness_p2p_gb_take(C, idb, 0),
              "(2f) nothing outstanding: a response is dropped");
        CHECK(nodus_witness_p2p_gb_request(C, idb, 0, qb, ql), "(2f) C asks B @0");
        CHECK(!nodus_witness_p2p_gb_take(C, ida, 0), "(2f) from another peer: dropped");
        CHECK(!nodus_witness_p2p_gb_take(C, idb, 1), "(2f) another offset: dropped");
        CHECK(nodus_witness_p2p_gb_take(C, idb, 0),
              "(2f) the peer asked, the offset asked: taken");
        CHECK(!nodus_witness_p2p_gb_take(C, idb, 0), "(2f) a second copy: dropped");

        CHECK(nodus_witness_p2p_gb_request(C, idb, 0, qb, ql), "(2f) C asks B @0 again");
        q.offset = 4096;
        CHECK(nodus_t3_gbundle_q_encode(&q, qb, sizeof(qb), &ql) == 0, "(2f) encode @4096");
        CHECK(nodus_witness_p2p_gb_request(C, idb, 4096, qb, ql), "(2f) C asks B @4096");
        CHECK(!nodus_witness_p2p_gb_take(C, idb, 0),
              "(2f) the replaced request's late answer: dropped");
        CHECK(nodus_witness_p2p_gb_take(C, idb, 4096), "(2f) the current one: taken");
        CHECK(!nodus_witness_p2p_gb_request(C, idd, 0, qb, ql),
              "(2f) a request to a peer C does not hold is not queued");
        CHECK(!nodus_witness_p2p_gb_take(C, idd, 0),
              "(2f) ... and leaves nothing outstanding");

        /* the serving side: 100 ms per REQUESTER, not node-wide */
        CHECK(nodus_witness_p2p_gb_serve_allow(B, idc, 1000), "(2f) C served @1000");
        CHECK(!nodus_witness_p2p_gb_serve_allow(B, idc, 1099), "(2f) C again @1099: held");
        CHECK(nodus_witness_p2p_gb_serve_allow(B, idd, 1099),
              "(2f) D @1099: not held back by C's gap");
        CHECK(nodus_witness_p2p_gb_serve_allow(B, idc, 1100), "(2f) C @1100: served");
        CHECK(!nodus_witness_p2p_gb_serve_allow(B, idc, 1050),
              "(2f) a clock that went back reads as just served");
    }

    /* (2e) 0x70: the joiner J pulls the bundle and adopts — preceded by
     * (2g), the single-source download driven by hand on the same J */
    {
        char sB[CMT_P2P_NETADDR_STR_MAX], sC[CMT_P2P_NETADDR_STR_MAX];
        pair2_t jl;

        sJ = calloc(1, sizeof(*sJ));
        wJ = calloc(1, sizeof(*wJ));
        CHECK(sJ != NULL && wJ != NULL, "joiner alloc");
        CHECK(ident_make(&sJ->identity, 2) == 0, "joiner identity (key 2)");
        sJ->config.has_v2_genesis_pin = true;
        memcpy(sJ->config.v2_genesis_pin, g.chain32, 32);
        wJ->server = sJ;
        wJ->cached_committee_epoch_start = UINT64_MAX;
        snprintf(wJ->data_path, sizeof(wJ->data_path), "%s", dJ);
        memcpy(wJ->my_id, g_ks[2].voter, 32);
        CHECK(nodus_witness_v2_join_arm(wJ) == 1, "(2e) the joiner is armed");

        /* J's peers: B (serves the bundle) and C (a host with no witness:
         * it answers no 0x70 request — the "refusing" peer) */
        cfg_local(&cfgJ);
        dial_str(B, sB, sizeof(sB));
        dial_str(C, sC, sizeof(sC));
        CHECK(nodus_p2p_config_add_persistent(&cfgJ, sB) == 0 &&
              nodus_p2p_config_add_persistent(&cfgJ, sC) == 0,
              "J persistent B and C");
        wJ->p2p = host_new(wJ, &sJ->identity, g.chain32, &cfgJ, dJ, 0);
        CHECK(wJ->p2p != NULL, "host J (network = the pin)");
        CHECK(nodus_witness_p2p_bonded_count(wJ->p2p) == 0,
              "(2e) a joiner has no bonded set yet");

        /* linked first, with NO join tick running: (2g) drives it */
        d[nd].p = wJ->p2p;
        d[nd].joiner = NULL;
        nd++;
        jl.p = wJ->p2p; jl.id1 = idb; jl.id2 = idc;
        CHECK(drive(d, nd, pred_has_both, &jl, WAIT_MS), "(2g) J holds B and C");

        /* (2g) decision 2026-09-27-p2p-fix-2.md (3): ONE source per
         * download; a failing source is excluded and the next one starts
         * from offset 0. The responses are forged and handed to the
         * joiner's own 0x70 entry (the one gb_receive calls); the
         * requests are the joiner's real ones (its tick, through the
         * host's outstanding-request record). */
        {
            static const uint8_t junk[64] = { 0x5c };
            char first[CMT_P2P_ID_CAP], other[CMT_P2P_ID_CAP], s[CMT_P2P_ID_CAP];
            nodus_t3_w_v2_gbundle_r_t r;

            memset(&r, 0, sizeof(r));
            memcpy(r.chain, g.chain32, 32);
            memcpy(r.pin, g.chain32, 32);
            r.total = 1000;
            r.offset = 0;
            r.chunk = junk;
            r.chunk_len = (uint32_t)sizeof(junk);

            wJ->v2_join.last_req_ms = 0;
            nodus_witness_v2_join_tick(wJ);
            CHECK(wJ->v2_join.src[0] != '\0' && wJ->v2_join.awaiting,
                  "(2g) a source is chosen and asked @0");
            snprintf(first, sizeof(first), "%s", wJ->v2_join.src);
            snprintf(other, sizeof(other), "%s", strcmp(first, idb) == 0 ? idc : idb);

            nodus_witness_v2_join_handle_gbundle_r(wJ, other, &r);
            CHECK(wJ->v2_join.acc_len == 0 && strcmp(wJ->v2_join.src, first) == 0,
                  "(2g) a chunk from a peer that is not the source: dropped");
            nodus_witness_v2_join_handle_gbundle_r(wJ, first, &r);
            CHECK(wJ->v2_join.acc_len == sizeof(junk) && !wJ->v2_join.awaiting,
                  "(2g) the source's chunk @0: taken");

            wJ->v2_join.last_req_ms = 0;
            nodus_witness_v2_join_tick(wJ);
            CHECK(strcmp(wJ->v2_join.src, first) == 0 && wJ->v2_join.awaiting &&
                  wJ->v2_join.acc_len == sizeof(junk),
                  "(2g) the next chunk is asked of the SAME source");

            r.offset = sizeof(junk);
            r.total = 2000;                        /* the source changed it */
            nodus_witness_v2_join_handle_gbundle_r(wJ, first, &r);
            CHECK(nodus_witness_v2_join_is_excluded(wJ, first) &&
                  wJ->v2_join.src[0] == '\0' && wJ->v2_join.acc_len == 0,
                  "(2g) a changed total: the source is excluded, its bytes dropped");

            wJ->v2_join.last_req_ms = 0;
            nodus_witness_v2_join_tick(wJ);
            CHECK(strcmp(wJ->v2_join.src, other) == 0 && wJ->v2_join.awaiting &&
                  wJ->v2_join.acc_len == 0,
                  "(2g) the next peer starts from offset 0");

            /* no answer for a whole interval: `other` refused too; with
             * every connected peer excluded the round starts over */
            wJ->v2_join.last_req_ms = 0;
            nodus_witness_v2_join_tick(wJ);
            CHECK(wJ->v2_join.n_excl == 0 && wJ->v2_join.src[0] != '\0' &&
                  wJ->v2_join.acc_len == 0 && wJ->v2_join.awaiting,
                  "(2g) an unanswered chunk excludes; all excluded: start over");

            /* a whole bundle that fails at adopt excludes its source */
            snprintf(s, sizeof(s), "%s", wJ->v2_join.src);
            r.offset = 0;
            r.total = sizeof(junk);
            nodus_witness_v2_join_handle_gbundle_r(wJ, s, &r);
            CHECK(nodus_witness_v2_join_active(wJ) &&
                  nodus_witness_v2_join_is_excluded(wJ, s) &&
                  wJ->v2_join.src[0] == '\0' && wJ->v2_join.acc_len == 0,
                  "(2g) a bundle that fails at adopt: its source is excluded");

            /* (2e) starts a fresh join attempt */
            wJ->v2_join.n_excl = 0;
            wJ->v2_join.excl_next = 0;
            wJ->v2_join.awaiting = false;
            wJ->v2_join.last_req_ms = 0;
        }

        d[nd - 1].joiner = wJ;
        CHECK(drive(d, nd, pred_join_done, wJ, JOIN_WAIT_MS),
              "(2e) the bundle crossed 0x70 and the joiner adopted it");
        CHECK(wJ->db != NULL && memcmp(wJ->v2_chain32, g.chain32, 32) == 0,
              "(2e) the adopted chain is the pinned one");
        CHECK(wJ->cmt_node != NULL, "(2e) the consensus binding was built on J's host");
        CHECK(nodus_witness_p2p_is_bonded(wJ->p2p, idb),
              "(2e) J's host now reads the adopted chain's bonded set");
        /* RT2 B-F2: B served from its in-memory copy, the database's
         * bytes exactly; another chain id finds no copy */
        {
            const uint8_t *cp = NULL;
            size_t cl = 0, dl = 0;
            uint8_t *db = NULL;

            CHECK(nodus_witness_p2p_gb_bundle(B, g.chain32, &cp, &cl),
                  "(2e) B holds the bundle copy it served from");
            CHECK(nodus_witness_v2_bundle_get(g.w, &db, &dl) == 0 &&
                  dl == cl && memcmp(db, cp, cl) == 0,
                  "(2e) the copy is the database's bundle, byte-exact");
            free(db);
            CHECK(!nodus_witness_p2p_gb_bundle(B, other_chain, &cp, &cl),
                  "(2e) no copy for another chain id");
        }
    }

out:
    if (wJ != NULL) {
        nodus_witness_close(wJ);          /* frees its p2p host too */
        free(wJ);
    }
    free(sJ);
    sess_close(&sess, g.srv);
    free(cres);
    nodus_witness_p2p_free(A);
    if (wA != NULL) {
        if (wA->db) sqlite3_close(wA->db);
        free(wA);
    }
    free(sA);
    nodus_witness_p2p_free(C);
    nodus_witness_p2p_free(D);
    nodus_witness_p2p_free(E);
    gfx_close(&g);                        /* frees B */
    return rc;
}

int main(void) {
    int rc = 0;

    snprintf(g_root, sizeof(g_root), "/tmp/test_witness_p2p_XXXXXX");
    if (mkdtemp(g_root) == NULL) {
        fprintf(stderr, "mkdtemp failed\n");
        return 1;
    }
    if (make_keys() != 0) {
        fprintf(stderr, "key generation failed\n");
        return 1;
    }
    if (part1() != 0) rc = 1;
    if (rc == 0 && part2() != 0) rc = 1;
    if (rc == 0) {
        rmrf(g_root);
        fprintf(stderr, "test_witness_p2p: all %d checks passed\n", g_checks);
    } else {
        fprintf(stderr, "test_witness_p2p: FAILED (%d checks passed before "
                "the failure; %s left behind)\n", g_checks, g_root);
    }
    return rc;
}
