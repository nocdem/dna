/**
 * @file nodus/tests/test_cmt_live.c
 * @brief The server binding driven LIVE through the REAL
 *        `nodus_witness_init` -> `nodus_witness_tick` path over a REAL
 *        version-3 chain — ported onto the 4004 p2p host (fleet P2P-PORT
 *        phase F5, fix round 1).
 *
 * The first version of this file (FLEET-TM-R3 W3 package C2a) drove the
 * deleted transport glue (nodus_witness_cmt_net) and the deleted tier-3
 * dispatcher, with a hand-registered roster peer on a dummy connection.
 * Its three cases whose SUBJECT still exists are ported here; the peer is
 * now a real second p2p host on 127.0.0.1. Its version-gate case (the
 * tier-3 header's protocol version, deleted with the envelope — the P2P
 * version is checked in HELLO: test_p2p_secret / test_p2p_switch), its
 * mesh-tick case (the deleted IDENT dial loop) and its adopt-then-live
 * case (the joiner's full adoption over 0x70 is test_witness_p2p (2e))
 * are not.
 *
 * ── THE STANDING BLOCKER (unchanged, see the first version's header) ──
 * DNAC genesis requires EXACTLY DNAC_COMMITTEE_SIZE (7) equal-stake
 * validators (nodus_witness_v2_gen.c Rule P.1 and the stake pin), so ONE
 * live process holds 1/7 of the voting power and never commits a block.
 * Nothing here proves block production.
 *
 * ── WHAT EACH CASE PROVES ──────────────────────────────────────────────
 *  1. t_genesis_wait_and_peer_admission
 *     (a) BEFORE the document's genesis_time_ms, `cmt_live` stays false
 *         across real ticks — witness_cmt_tick's genesis-time gate
 *         (nodus_witness.c, node.go:518-524) starts no reactor;
 *     (b) a REAL p2p peer (key 1) that connected BEFORE that point is in
 *         the witness's switch but NOT in the consensus reactor's peer
 *         set — the host admits peers only once both reactors run
 *         (R-P2P-47);
 *     (c) the tick that crosses genesis_time starts both reactors and the
 *         block sync reactor and, in that SAME tick, admits the connected
 *         peer (nodus_witness_p2p_lane_live). Since the blocksync port
 *         (decision 2026-09-29-blocksync-before-testnet.md) the consensus
 *         reactor WAITS for block sync — blockSync = !onlyValidatorIsUs is
 *         true with 7 validators (node.go:375) — so cmt_cs_start is NOT
 *         reached (`cs_started` false, reactor.go:83-88);
 *     (d) ~2 s of further ticks (past the 1 s switch ticker) leave the
 *         peer admitted and the node STILL in block sync: the peer is a
 *         bare p2p host with no 0x40 reactor, so the pool has no peer and
 *         IsCaughtUp is false (pool.go:209-212), and 1/7 of the power is
 *         below localNodeBlocksTheChain's 1/3 (reactor.go:307-314);
 *     (e) the peer's host going away removes it from the reactor again.
 *  2. t_checktx_funded_and_forged — a REAL claim against the genesis
 *     allocation, through the LIVE node's own mempool (`n->mem`), is
 *     admitted; the identical fields signed by another validator's key
 *     are refused (nodus_witness_v2_claim_admit's signature check).
 *     Admission only — never inclusion (the blocker).
 *  3. t_restart_reopens_same_role — nodus_witness_close then a second
 *     nodus_witness_init over the SAME server and data directory: the
 *     SAME version-3 chain id, the binding rebuilt, and the 4004 host
 *     listening again on the configured port.
 *
 * ── WHAT IT REQUIRES ───────────────────────────────────────────────────
 * Compile flags: none beyond a default build. Environment: none. SQLite
 * >= 3.35.0. Loopback TCP: the witness listens on a port this file finds
 * free (bind 127.0.0.1:0, read it, close) just before init — see HOW IT
 * CAN LIE 2. The WALL clock is real (witness_cmt_now), the reference's
 * own genesis-time read; every wait on it is a bounded tick loop.
 *
 * ── WHAT IT LEAVES BEHIND ──────────────────────────────────────────────
 * Nothing: one /tmp/test_cmt_live_* directory per case, removed at its
 * close — since P2P-PORT F6 also when the case aborts through CHECK
 * (main() closes the fixture the case left open, g_live_open).
 *
 * ── HOW IT CAN LIE ─────────────────────────────────────────────────────
 *  1. One validator of seven (the blocker): no quorum, no commit.
 *  2. The witness port is found free, closed, then bound by
 *     nodus_witness_init: another process taking it in between fails the
 *     init (a visible CHECK failure, never a pass).
 *  3. Case 1 needs the peer connected before genesis_time: GENESIS_LEAD_MS
 *     (8 s) must cover the chain derivation, the init and one loopback
 *     handshake. If it does not, the "connected before genesis" CHECK
 *     fails — the case never passes with (a)/(b) unobserved.
 *  4. Case 2 needs the activation gate armed at open (the ingress
 *     precondition CHECK): a closed gate would refuse both claims alike.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <inttypes.h>
#include <sqlite3.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include "crypto/hash/qgp_sha3.h"
#include "crypto/sign/qgp_dilithium.h"
#include "crypto/enc/qgp_mlkem.h"

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_p2p.h"
#include "witness/nodus_witness_v2_gen.h"
#include "witness/nodus_witness_v2_claims.h"
#include "witness/nodus_witness_v2_gate.h"
#include "witness/nodus_witness_emission.h"
#include "witness/nodus_witness_cmt_node.h"
#include "server/nodus_server.h"
#include "nodus/nodus_types.h"

#include "dnac/dnac.h"
#include "dnac/manifest_wire.h"
#include "dnac/cmt_mem.h"
#include "dnac/cmt_conr.h"
#include "dnac/cmt_memr.h"

#define CHECK(cond, msg) do {                                              \
    if (!(cond)) {                                                         \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, \
                (msg));                                                    \
        return 1;                                                          \
    }                                                                      \
    g_checks++;                                                            \
} while (0)

static int g_checks = 0;

#define N_KEYS ((int)DNAC_COMMITTEE_SIZE)

typedef struct {
    uint8_t pk[QGP_DSA87_PUBLICKEYBYTES];
    uint8_t sk[QGP_DSA87_SECRETKEYBYTES];
    uint8_t voter[32];
} keyset_t;

static keyset_t g_ks[N_KEYS];

static int make_keys(void) {
    for (int i = 0; i < N_KEYS; i++) {
        uint8_t seed[32], full[64];
        memset(seed, (uint8_t)(0x60 + i), sizeof(seed));
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
    memset(coins, (uint8_t)(0xA0 + k), sizeof(coins));
    if (qgp_mlkem1024_keypair_derand(id->mlkem_pk, id->mlkem_sk, coins) != 0)
        return -1;
    id->has_mlkem = true;
    return 0;
}

static void hex_lower_fp(const uint8_t *src, size_t src_len, uint8_t *out129) {
    static const char hexd[] = "0123456789abcdef";
    uint8_t d[64];

    qgp_sha3_512(src, src_len, d);
    for (int i = 0; i < 64; i++) {
        out129[2 * i]     = (uint8_t)hexd[d[i] >> 4];
        out129[2 * i + 1] = (uint8_t)hexd[d[i] & 0x0F];
    }
    out129[128] = 0;
}

static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000L);
}

/* A port nothing listens on right now (HOW IT CAN LIE 2). */
static uint16_t free_port(void) {
    struct sockaddr_in a;
    socklen_t al = (socklen_t)sizeof(a);
    uint16_t port = 0;
    int fd = socket(AF_INET, SOCK_STREAM, 0);

    if (fd < 0) return 0;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(fd, (struct sockaddr *)&a, sizeof(a)) == 0 &&
        getsockname(fd, (struct sockaddr *)&a, &al) == 0)
        port = ntohs(a.sin_port);
    close(fd);
    return port;
}

#define TREASURY_RAW     93000000000000000ULL
#define GENESIS_LEAD_MS  8000ULL          /* HOW IT CAN LIE 3 */
#define TICK_SLEEP_US    20000            /* between ticks (20 ms)        */
#define WAIT_TICKS_MAX   1000             /* 1000 ticks ≥ 20 s bound      */

/* ══ FIXTURE — the first version's cfg_make_v3_real / live_open, with
 *    the server's 4004 config (bind 127.0.0.1, a free witness port, the
 *    localhost p2p settings) and an ML-KEM key the host needs. ═══════ */

typedef struct {
    nodus_v2_gen_config_t *cfg;
    nodus_v2_gen_alloc_t  *allocs;
} cfgbox_t;

static void cfg_free(cfgbox_t *b) {
    if (b) { free(b->cfg); free(b->allocs); memset(b, 0, sizeof(*b)); }
}

static int cfg_make_v3_real(cfgbox_t *b, uint64_t genesis_time_ms) {
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
        hex_lower_fp(v->unstake_destination_pubkey, DNAC_PUBKEY_SIZE,
                     v->unstake_destination_fp);
        /* general multisig ONAY 2: a genesis row's destination pubkey is
         * ALL ZERO (the fp above is only a shape-valid address) */
        memset(v->unstake_destination_pubkey, 0, DNAC_PUBKEY_SIZE);
        v->self_stake     = DNAC_SELF_STAKE_AMOUNT;
        v->commission_bps = (uint16_t)(100 * (k + 1));
    }
    memset(b->allocs[0].source_id, 0, sizeof(b->allocs[0].source_id));
    b->allocs[0].source_id[0] = 0x30;
    qgp_sha3_512(g_ks[0].pk, DNAC_PUBKEY_SIZE, b->allocs[0].dest_binding);
    b->allocs[0].amount = TREASURY_RAW;
    c->n_allocs = 1;
    c->allocs   = b->allocs;
    if (nodus_witness_v2_gen_v3_defaults(c) != 0) { cfg_free(b); return -1; }
    c->reward_pool_initial = 0;
    c->genesis_time_ms = genesis_time_ms;
    c->initial_height  = 1;
    if (nodus_witness_v2_gen_v3_fill_comet_rows(c) != 0) { cfg_free(b); return -1; }
    return 0;
}

static void rmrf(const char *path) {
    char cmd[300];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", path);
    if (system(cmd) != 0) { /* best effort */ }
}

typedef struct {
    nodus_server_t  *srv;
    nodus_witness_t *w;
    bool             w_inited;    /* nodus_witness_init succeeded and no
                                   * nodus_witness_close since */
    bool             dir_made;
    cfgbox_t         box;
    char             dir[128];
    uint8_t          chain32[32];
} live_t;

/* P2P-PORT F6 — every allocation live_open makes is released on EVERY
 * path (LeakSanitizer found cfg_make_v3_real's two callocs leaking when a
 * case returned through CHECK): the open fixture is registered here and
 * main() closes it after a case that returned without live_close; a
 * failing live_open closes what it built itself. Cases keep their live_t
 * in STATIC storage so this pointer outlives the case's frame. */
static live_t *g_live_open;
/* Case 1's second p2p host, released the same way. */
static nodus_witness_p2p_t *g_peer_host;

static void live_close(live_t *L) {
    /* A failed nodus_witness_init is freed WITHOUT nodus_witness_close
     * (nodus_witness.c init: "the caller frees `witness` without
     * nodus_witness_close on a failed init"). */
    if (L->w && L->w_inited) nodus_witness_close(L->w);
    L->w_inited = false;
    free(L->w);   L->w = NULL;
    free(L->srv); L->srv = NULL;
    cfg_free(&L->box);
    if (L->dir_made) rmrf(L->dir);
    L->dir_made = false;
    if (g_live_open == L) g_live_open = NULL;
}

static int live_open(live_t *L, const char *tag, uint64_t genesis_time_ms) {
    nodus_witness_config_t wcfg;

    memset(L, 0, sizeof(*L));
    g_live_open = L;
    if (cfg_make_v3_real(&L->box, genesis_time_ms) != 0) goto fail;
    if (nodus_witness_v2_gen_v3_validate(L->box.cfg) != 0) goto fail;
    snprintf(L->dir, sizeof(L->dir), "/tmp/test_cmt_live_%s_XXXXXX", tag);
    if (!mkdtemp(L->dir)) goto fail;
    L->dir_made = true;
    if (nodus_witness_v2_gen_derive_v3(L->dir, L->box.cfg, L->chain32) != 0)
        goto fail;

    L->srv = calloc(1, sizeof(*L->srv));
    L->w   = calloc(1, sizeof(*L->w));
    if (!L->srv || !L->w) goto fail;
    if (ident_make(&L->srv->identity, 0) != 0) goto fail;
    snprintf(L->srv->config.data_path, sizeof(L->srv->config.data_path),
             "%s", L->dir);
    snprintf(L->srv->config.bind_ip, sizeof(L->srv->config.bind_ip),
             "127.0.0.1");
    L->srv->config.witness_port = free_port();
    if (L->srv->config.witness_port == 0) goto fail;
    nodus_p2p_config_default(&L->srv->config.p2p);
    L->srv->config.p2p.pex = false;
    L->srv->config.p2p.addr_book_strict = false;
    L->srv->config.p2p.allow_duplicate_ip = true;

    memset(&wcfg, 0, sizeof(wcfg));
    if (nodus_witness_init(L->w, L->srv, &wcfg) != 0) goto fail;
    L->w_inited = true;
    if (memcmp(L->w->v2_chain32, L->chain32, 32) != 0) goto fail;
    return 0;

fail:
    live_close(L);
    return -1;
}

static int conr_in_set_count(const cmt_conr_t *c) {
    int n = 0;
    for (int i = 0; i < CMT_CONR_MAX_PEERS; i++)
        if (c->peers[i].in_set) n++;
    return n;
}

/* ══ CASE 1 ════════════════════════════════════════════════════════════ */

static int t_genesis_wait_and_peer_admission(void) {
    static live_t L;   /* static: g_live_open outlives this frame */
    uint64_t gt;
    int i;
    nodus_cmt_node_t *n;
    cmt_conr_t *conr;
    cmt_memr_t *memr;
    cmt_bsync_reactor_t *bs;
    static nodus_identity_t id1;
    nodus_p2p_config_t pcfg;
    nodus_witness_p2p_params_t prm;
    nodus_witness_p2p_t *P1;
    char pdir[128], wid[CMT_P2P_ID_CAP], s[CMT_P2P_NETADDR_STR_MAX];
    cmt_p2p_netaddr_t na;
    bool connected = false;

    gt = now_ms() + GENESIS_LEAD_MS;
    CHECK(live_open(&L, "gwait", gt) == 0, "one live validator, genesis in "
          "the near future");
    n    = (nodus_cmt_node_t *)L.w->cmt_node;
    conr = (cmt_conr_t *)L.w->cmt_conr;
    memr = (cmt_memr_t *)L.w->cmt_memr;
    CHECK(n && conr && memr && L.w->p2p, "the binding and the 4004 host "
          "were built at init");
    CHECK(!L.w->cmt_live && !conr->running && !memr->running,
          "nothing runs before genesis");

    /* The second identity: a real p2p host dialing the witness. */
    CHECK(ident_make(&id1, 1) == 0, "identity 1");
    snprintf(pdir, sizeof(pdir), "%s/p1", L.dir);
    CHECK(mkdir(pdir, 0700) == 0, "peer dir");
    nodus_p2p_config_default(&pcfg);
    pcfg.pex = false;
    pcfg.addr_book_strict = false;
    pcfg.allow_duplicate_ip = true;
    memset(&prm, 0, sizeof(prm));
    prm.identity = &id1;
    prm.chain_id = L.chain32;
    prm.cfg = &pcfg;
    prm.listen_ip = "127.0.0.1";
    prm.external_ip = "";
    prm.data_path = pdir;
    prm.seq_dir = pdir;
    prm.open_listener = true;
    P1 = nodus_witness_p2p_new(NULL, &prm);
    g_peer_host = P1;                  /* freed by main() on a CHECK exit */
    CHECK(P1 != NULL, "peer host");
    snprintf(wid, sizeof(wid), "%s", nodus_witness_p2p_id(L.w->p2p));
    snprintf(s, sizeof(s), "%s@127.0.0.1:%u", wid,
             (unsigned)L.srv->config.witness_port);
    CHECK(cmt_p2p_netaddr_new_string(s, strlen(s), &na) == CMT_P2P_ERR_NONE,
          "witness address");
    CHECK(cmt_p2p_switch_dial_peer_with_address(nodus_witness_p2p_switch(P1),
                                                &na) == CMT_P2P_ERR_NONE,
          "the peer dials the witness");

    /* (a)(b) before genesis_time */
    for (i = 0; i < WAIT_TICKS_MAX && now_ms() < gt; i++) {
        CHECK(L.w->running, "the node has not halted while waiting");
        nodus_witness_tick(L.w);
        nodus_witness_p2p_poll(P1, 1);
        /* The loop head read the clock BEFORE the tick; the node reads its
         * own inside it, after the p2p wait (nodus_witness.c genesis-time
         * check). Under load genesis_time can pass in between and the node
         * goes live correctly — the assertion must use a clock read AFTER
         * the tick: live is wrong only if even that read is before gt
         * (ORCHESTRATOR repair 2026-09-26, found under ctest -j4). */
        CHECK(!L.w->cmt_live || now_ms() >= gt,
              "(a) cmt_live stays false before genesis_time");
        if (L.w->cmt_live) {
            break;                  /* genesis passed inside this tick */
        }
        CHECK(conr_in_set_count(conr) == 0,
              "(b) no peer enters the consensus reactor before it runs");
        if (nodus_witness_p2p_peer_count(L.w->p2p) == 1) connected = true;
        usleep(TICK_SLEEP_US);
    }
    CHECK(connected, "(b) the peer was connected at the switch BEFORE "
          "genesis_time (HOW IT CAN LIE 3)");

    /* (c) the tick crossing genesis_time */
    for (i = 0; i < WAIT_TICKS_MAX && !L.w->cmt_live; i++) {
        CHECK(L.w->running, "node halted while starting the lane");
        nodus_witness_tick(L.w);
        nodus_witness_p2p_poll(P1, 1);
        usleep(TICK_SLEEP_US);
    }
    CHECK(L.w->cmt_live, "(c) the tick started the lane at genesis_time");
    /* Blocksync port (decision 2026-09-29-blocksync-before-testnet.md):
     * with 7 genesis validators blockSync = !onlyValidatorIsUs is TRUE
     * (node.go:375), so the lane starts the reactors but the consensus
     * reactor WAITS for block sync — cmt_cs_start is NOT reached here; it
     * is reached at SwitchToConsensus (consensus/reactor.go:107-141). */
    bs = nodus_witness_p2p_bsync(L.w->p2p);
    CHECK(conr->running && memr->running,
          "(c) both reactors run at genesis_time");
    CHECK(bs != NULL && cmt_bsync_reactor_is_syncing(bs),
          "(c) the block sync reactor runs its pool routine (blockSync)");
    CHECK(cmt_conr_wait_sync(conr) && !n->cs_started,
          "(c) the consensus reactor waits for block sync: cmt_cs_start "
          "not reached (reactor.go:83-88)");
    CHECK(conr_in_set_count(conr) == 1,
          "(c) the connected peer was admitted in that same tick");

    /* (d) — past the 1 s switch ticker (blocksync/reactor.go:331) the node
     * is STILL in block sync: the peer runs no block sync reactor (a bare
     * p2p host), so the pool has no 0x40 peer and IsCaughtUp is false
     * (pool.go:209-212), and one validator of seven holds < 1/3 of the
     * power (localNodeBlocksTheChain, reactor.go:307-314). Bounded by
     * tick count, not a wall-clock verdict: the assertion is that nothing
     * switches, whatever the elapsed time. */
    for (i = 0; i < 100; i++) {                    /* 100 × 20 ms ≥ 2 s */
        CHECK(L.w->running, "node halted while in block sync");
        nodus_witness_tick(L.w);
        nodus_witness_p2p_poll(P1, 1);
        usleep(TICK_SLEEP_US);
    }
    CHECK(conr_in_set_count(conr) == 1, "(d) still admitted");
    CHECK(cmt_bsync_pool_is_running(cmt_bsync_reactor_pool(bs)) &&
          cmt_bsync_reactor_pool(bs)->n_peers == 0,
          "(d) the block sync pool has no peer (the peer has no 0x40 "
          "reactor)");
    CHECK(cmt_bsync_reactor_is_syncing(bs) && !cmt_bsync_reactor_switched(bs) &&
          cmt_conr_wait_sync(conr) && !n->cs_started,
          "(d) with no block sync peer the node stays in block sync and "
          "never starts consensus");

    /* (e) the peer goes away */
    nodus_witness_p2p_free(P1);
    g_peer_host = NULL;
    for (i = 0; i < WAIT_TICKS_MAX && conr_in_set_count(conr) != 0; i++) {
        nodus_witness_tick(L.w);
        usleep(TICK_SLEEP_US);
    }
    CHECK(conr_in_set_count(conr) == 0, "(e) removed once its host is gone");

    live_close(&L);
    return 0;
}

/* ══ CASE 2 — the first version's t_checktx_funded_and_forged ══════════ */

static int t_checktx_funded_and_forged(void) {
    static live_t L;   /* static: g_live_open outlives this frame */
    nodus_cmt_node_t *n;
    dna_gman_t m;
    dna_dist_leaf_t leaf;
    uint8_t mh[64], leaf_hash[64];
    dna_claim_t *good, *bad;
    uint8_t *cbytes, *bbytes;
    size_t clen = 0, blen = 0;
    cmt_mem_tx_info_t info;
    cmt_mem_response_check_tx_t res;
    cmt_mem_error_t err;

    CHECK(live_open(&L, "checktx", now_ms() - 5000) == 0,
          "one live validator, chain already past genesis_time");
    n = (nodus_cmt_node_t *)L.w->cmt_node;
    CHECK(n && n->mem, "the startup table built the real mempool");

    CHECK(nodus_witness_v2_manifest_load(L.w, 0, &m) == 0,
          "the genesis manifest is committed at seq 0");
    CHECK(dna_gman_hash(&m, mh) == 0, "its hash");
    CHECK(m.dist_present == 1, "it carries a distribution section");

    memset(&leaf, 0, sizeof(leaf));
    leaf.leaf_version  = DNA_DIST_VERSION;
    leaf.source_id_len = (uint16_t)NODUS_V2_GEN_SRCID_LEN;
    memcpy(leaf.source_id, L.box.allocs[0].source_id, NODUS_V2_GEN_SRCID_LEN);
    leaf.source_amount = L.box.allocs[0].amount;
    memcpy(leaf.dest_binding, L.box.allocs[0].dest_binding, 64);
    CHECK(dna_dist_leaf_hash(&leaf, leaf_hash) == 0, "leaf hash");

    good = calloc(1, sizeof(*good));
    bad  = calloc(1, sizeof(*bad));
    cbytes = malloc(DNA_CLAIM_MAX_WIRE);
    bbytes = malloc(DNA_CLAIM_MAX_WIRE);
    CHECK(good && bad && cbytes && bbytes, "alloc");

    good->claim_version = DNA_CLAIM_VERSION;
    memcpy(good->chain_id, L.chain32, DNA_CHAIN_ID_LEN);
    memcpy(good->manifest_hash, mh, 64);
    good->leaf_index    = 0;
    good->source_id_len = leaf.source_id_len;
    memcpy(good->source_id, leaf.source_id, leaf.source_id_len);
    good->source_amount = leaf.source_amount;
    memcpy(good->dest_binding, leaf.dest_binding, 64);
    good->n_siblings = 0;
    good->auth_mode  = DNA_CLAIMAUTH_DNA_NATIVE;
    memcpy(good->pubkey, g_ks[0].pk, QGP_DSA87_PUBLICKEYBYTES);
    {
        uint8_t pre[DNA_CLAIM_PREIMAGE_MAX];
        size_t pre_len = 0, siglen = 0;
        CHECK(dna_claim_preimage(good, pre, &pre_len) == 0, "preimage");
        CHECK(qgp_dsa87_sign(good->signature, &siglen, pre, pre_len,
                             g_ks[0].sk) == 0 && siglen == DNA_CLAIM_SIG_LEN,
              "the funded claimant signs it");
    }
    CHECK(dna_claim_encode(good, cbytes, DNA_CLAIM_MAX_WIRE, &clen) == 0,
          "the funded claim encodes");

    memcpy(bad, good, sizeof(*bad));
    {
        uint8_t pre[DNA_CLAIM_PREIMAGE_MAX];
        size_t pre_len = 0, siglen = 0;
        CHECK(dna_claim_preimage(bad, pre, &pre_len) == 0, "preimage");
        CHECK(qgp_dsa87_sign(bad->signature, &siglen, pre, pre_len,
                             g_ks[1].sk) == 0, "signed with the WRONG key");
    }
    CHECK(dna_claim_encode(bad, bbytes, DNA_CLAIM_MAX_WIRE, &blen) == 0,
          "it encodes too — refused at authorization, not at decode");

    CHECK(nodus_witness_v2_ingress_is_armed(L.w) == 1,
          "the activation gate armed at open (HOW IT CAN LIE 4)");

    memset(&info, 0, sizeof(info));
    memset(&res, 0, sizeof(res));
    cmt_mem_error_init(&err);
    CHECK(cmt_mem_check_tx(n->mem, cbytes, clen, &info, &res, &err) == CMT_OK,
          "the funded claim is served by the live mempool");
    CHECK(res.code == CMT_MEM_CODE_TYPE_OK, "and admitted at once");

    memset(&res, 0, sizeof(res));
    cmt_mem_error_init(&err);
    CHECK(cmt_mem_check_tx(n->mem, bbytes, blen, &info, &res, &err) == CMT_OK,
          "the forged claim is also served");
    CHECK(res.code != CMT_MEM_CODE_TYPE_OK, "and REFUSED — the claim "
          "signature check (nodus_witness_v2_claim_admit)");

    free(bbytes);
    free(cbytes);
    free(bad);
    free(good);
    live_close(&L);
    return 0;
}

/* ══ CASE 3 — the first version's t_restart_reopens_same_role ══════════ */

static int t_restart_reopens_same_role(void) {
    static live_t L;   /* static: g_live_open outlives this frame */
    uint8_t chain_before[32];
    nodus_witness_config_t wcfg;

    CHECK(live_open(&L, "restart", now_ms() - 5000) == 0,
          "one live validator, chain already past genesis_time");
    memcpy(chain_before, L.w->v2_chain32, 32);
    CHECK(L.w->v2_successor && L.w->cmt_node && L.w->p2p,
          "a version-3 chain with its binding and 4004 host");

    nodus_witness_close(L.w);
    L.w_inited = false;
    CHECK(L.w->p2p == NULL, "close freed the 4004 host");
    memset(&wcfg, 0, sizeof(wcfg));
    CHECK(nodus_witness_init(L.w, L.srv, &wcfg) == 0,
          "the SAME server, over the SAME data directory, re-inits");
    L.w_inited = true;
    CHECK(L.w->v2_successor, "the chain role is rediscovered");
    CHECK(memcmp(L.w->v2_chain32, chain_before, 32) == 0,
          "and it is the SAME chain id");
    CHECK(L.w->cmt_node && L.w->cmt_conr && L.w->cmt_memr,
          "the cometbft server binding is rebuilt");
    CHECK(L.w->p2p != NULL &&
          nodus_witness_p2p_listen_port(L.w->p2p) == L.srv->config.witness_port,
          "the 4004 host listens again on the configured port");

    live_close(&L);
    return 0;
}

int main(void) {
    struct { const char *name; int (*fn)(void); } cases[] = {
        { "genesis_wait_and_peer_admission", t_genesis_wait_and_peer_admission },
        { "checktx_funded_and_forged",       t_checktx_funded_and_forged },
        { "restart_reopens_same_role",       t_restart_reopens_same_role },
    };
    size_t failed = 0, ncases = sizeof(cases) / sizeof(cases[0]);

    if (make_keys() != 0) {
        fprintf(stderr, "test_cmt_live: key generation failed\n");
        return 1;
    }
    for (size_t i = 0; i < ncases; i++) {
        int rc = cases[i].fn();
        /* a case that returned through CHECK left its fixture open */
        if (g_peer_host) {
            nodus_witness_p2p_free(g_peer_host);
            g_peer_host = NULL;
        }
        if (g_live_open) live_close(g_live_open);
        fprintf(stderr, "%-34s %s\n", cases[i].name, rc == 0 ? "ok" : "FAIL");
        if (rc != 0) failed++;
    }
    fprintf(stderr, "test_cmt_live: %zu/%zu cases passed, %d checks\n",
            ncases - failed, ncases, g_checks);
    return failed ? 1 : 0;
}
