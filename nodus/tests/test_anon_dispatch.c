/**
 * Nodus — the no-login (ANON) client session on the server (DHT v2 package 3d)
 *
 * Design docs/plans/2026-10-26-dht-v2-3d-no-login-design.md rev 5 §2;
 * decisions/2026-10-26-wallet-no-node-login.md; decisions/2026-10-26-kurultay-
 * 45-summary.md (khan decisions 1-7: the v1 legacy DHT reads are refused on
 * ANON, dnac_node_duties stays own-node only).
 *
 * WHAT IT PROVES (each case would be false if the rule it names were missing):
 *   1. ALLOWLIST (nodus_server_anon_method_ok, the function dispatch_t2 calls
 *      first on an ANON session): every name of design §2 passes — dnac_spend,
 *      the fifteen public chain reads, the five owner-only reads, the eight
 *      evm_*, ping / status / servers — and every name of the chain list is a
 *      method nodus_chain_method_routed routes. REFUSED: put, get, get_all,
 *      get_batch, cnt_batch, listen, unlisten, ch_*, m_*, pq, circ_*,
 *      dnac_cc_collect, dnac_node_duties, w_*, dht2_* (a later package), the
 *      pre-login hello / auth, near misses (prefix, suffix, case, empty, NULL).
 *   2. NO PRINCIPAL IN THE SESSION TABLE: ANON sessions (zero client_fp) are
 *      never one identity's sessions — nodus_sessions_count_fp counts none,
 *      newest_fp finds none, evict_plan evicts none — while identified
 *      sessions that carry the same zero fingerprint ARE counted (so it is the
 *      flag, not the value, that excludes).
 *   3. nodus_auth_session_start ON A REAL ANON CONNECTION (loopback, a real
 *      handshake: an ANON initiator against a CLIENT responder that holds the
 *      KEM-key certificate): the session is anonymous and authenticated, its
 *      client_pk / client_fp are zero, the connection's peer_id_set stays
 *      false, the layer reports no peer key, srv->presence stays empty, no
 *      other session is evicted, and the client receives exactly one T2
 *      auth_ok whose token is the session's token (non-zero).
 *
 * NOT covered: dispatch_t2 itself (static); the witness side of the owner-only
 * reads (test_owner_query.c covers `qa`; the identified dispatcher is covered
 * by test_msig_query / test_addr_index); the IPC prefaces
 * (test_witness_ipc.c, test_dht_ipc.c).
 *
 * Requires: a default build (no flags, no environment). Loopback on an
 * ephemeral port (127.0.0.1:0), the layer's handshake worker threads.
 * Leaves behind: nothing (sockets closed, workers joined, heap freed).
 * How it can lie: case 3 waits a bounded number of poll rounds for the token
 * frame and FAILs if it does not arrive (a timeout is never a pass).
 */

#include "server/nodus_server.h"
#include "witness/nodus_witness_ipc.h"
#include "transport/nodus_tcp.h"
#include "transport/nodus_tcp_sc.h"
#include "protocol/nodus_tier2.h"
#include "crypto/nodus_identity.h"
#include "crypto/nodus_sign.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEST(name) do { printf("  %-66s", name); fflush(stdout); } while (0)
#define PASS()     do { printf("PASS\n"); passed++; } while (0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while (0)

static int passed = 0;
static int failed = 0;

/* ── 1. allowlist ────────────────────────────────────────────────── */

static const char *const k_allowed[] = {
    "dnac_spend",
    "dnac_balance", "dnac_supply", "dnac_roster", "dnac_v3_block",
    "dnac_light_block", "dnac_token_list", "dnac_token_info", "dnac_fee_info",
    "dnac_ruleset_info", "dnac_name_lookup", "dnac_name_of",
    "dnac_storage_status", "dnac_storage_by_owner", "dnac_committee_query",
    "dnac_validator_list_query",
    "dnac_utxo", "dnac_addr_history", "dnac_delegations", "dnac_msig_utxo",
    "dnac_msig_addr_history",
    "evm_account", "evm_code", "evm_storage", "evm_call", "evm_estimate",
    "evm_receipt", "evm_logs", "evm_ticket",
    "ping", "status", "servers",
};

static const char *const k_refused[] = {
    "put", "get", "get_all", "get_batch", "cnt_batch", "listen", "unlisten",
    "ch_list", "ch_search", "ch_get", "m_put", "m_meta", "m_chunk", "pq",
    "circ_open", "circ_data", "circ_close",
    "dnac_cc_collect", "dnac_node_duties",
    "w_ident", "w_vote", "w_propose", "w_",
    "dht2_get", "dht2_put", "dht2_list",
    "hello", "auth", "key_init",
    /* near misses */
    "dnac_", "dnac_spend ", " dnac_spend", "DNAC_SPEND", "dnac_spendx",
    "dnac_utxo2", "evm_", "evm_unknown", "evm_call_", "ping2", "pin", "Status",
    "dnac", "evm", "",
};

static void test_allowlist(void) {
    TEST("allowlist: every design §2 name passes");
    int ok = 1;
    for (size_t i = 0; i < sizeof(k_allowed) / sizeof(k_allowed[0]); i++)
        if (!nodus_server_anon_method_ok(k_allowed[i])) {
            printf("[%s refused] ", k_allowed[i]);
            ok = 0;
        }
    ok = ok && sizeof(k_allowed) / sizeof(k_allowed[0]) == 32;   /* 1+15+5+8+3 */
    if (ok) PASS(); else FAIL("a listed method is refused (or the list is not design §2's 32)");

    TEST("allowlist: put/listen/get/dnac_cc_collect/dnac_node_duties/w_*/dht2_* refused");
    ok = 1;
    for (size_t i = 0; i < sizeof(k_refused) / sizeof(k_refused[0]); i++)
        if (nodus_server_anon_method_ok(k_refused[i])) {
            printf("[%s allowed] ", k_refused[i]);
            ok = 0;
        }
    ok = ok && !nodus_server_anon_method_ok(NULL) && !nodus_chain_anon_method_ok(NULL);
    if (ok) PASS(); else FAIL("a method that must be refused is on the list");

    TEST("allowlist: the chain names are routed chain methods; ping/status/servers are not");
    ok = 1;
    for (size_t i = 0; i < sizeof(k_allowed) / sizeof(k_allowed[0]); i++) {
        bool chain = strncmp(k_allowed[i], "dnac_", 5) == 0 ||
                     strncmp(k_allowed[i], "evm_", 4) == 0;
        if (chain != nodus_chain_method_routed(k_allowed[i]) ||
            chain != nodus_chain_anon_method_ok(k_allowed[i]))
            ok = 0;
    }
    /* dnac_cc_collect and dnac_node_duties ARE routed, and are NOT allowed */
    ok = ok && nodus_chain_method_routed("dnac_cc_collect") &&
         !nodus_chain_anon_method_ok("dnac_cc_collect") &&
         nodus_chain_method_routed("dnac_node_duties") &&
         !nodus_chain_anon_method_ok("dnac_node_duties");
    if (ok) PASS(); else FAIL("the shared chain list and the routing predicate disagree");
}

/* ── 2. session table ────────────────────────────────────────────── */

#define NS 8

static void test_session_table(void) {
    static nodus_session_t s[NS];
    static nodus_tcp_conn_t conn[NS];      /* only the pointer is read */
    nodus_key_t zero;
    int victims[NS];

    memset(s, 0, sizeof(s));
    memset(conn, 0, sizeof(conn));
    memset(&zero, 0, sizeof(zero));

    TEST("session table: ANON sessions (zero fp) are no identity's sessions");
    for (int i = 0; i < NS; i++) {
        s[i].conn = &conn[i];
        s[i].authenticated = true;
        s[i].anonymous = true;
        s[i].auth_seq = (uint64_t)(i + 1);
    }
    int ok = nodus_sessions_count_fp(s, NS, &zero, NULL) == 0 &&
             nodus_sessions_newest_fp(s, NS, &zero) == NULL &&
             nodus_sessions_evict_plan(s, NS, &s[NS - 1], 1, victims, NS) == 0;
    if (ok) PASS(); else FAIL("an ANON session was counted, found or evicted as an identity's");

    TEST("session table: identified sessions with the same zero fp ARE counted");
    for (int i = 0; i < NS; i++) s[i].anonymous = false;
    ok = nodus_sessions_count_fp(s, NS, &zero, NULL) == NS &&
         nodus_sessions_newest_fp(s, NS, &zero) == &s[NS - 1] &&
         nodus_sessions_evict_plan(s, NS, &s[NS - 1], 4, victims, NS) == NS - 4;
    if (ok) PASS(); else FAIL("the flag, not the value, must be what excludes ANON sessions");
}

/* ── 3. a real ANON session start ────────────────────────────────── */

static nodus_server_t *g_srv;
static nodus_tcp_t     g_srv_tcp, g_cli_tcp;
static nodus_identity_t g_node;
static uint8_t g_kc[CMT_P2P_SC_SIG_SIZE];
static uint8_t g_chain[CMT_P2P_SC_CHAIN_ID_SIZE];
static int g_start_rc = 12345, g_starts = 0;
static int g_srv_slot = -1;
static int g_cli_frames = 0, g_cli_sessions = 0;
static uint8_t g_cli_token[NODUS_SESSION_TOKEN_LEN];
static bool g_cli_is_auth_ok = false;

static void srv_on_accept(nodus_tcp_conn_t *conn, void *ctx) {
    (void)ctx;
    nodus_session_t *sess = &g_srv->sessions[conn->slot];
    sess->conn = conn;
    g_srv_slot = conn->slot;
    nodus_tcp_sc_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.role = CMT_P2P_SC_ROLE_RESPONDER;
    cfg.profile = &CMT_P2P_SC_PROFILE_CLIENT;
    cfg.id = &g_node;
    cfg.anon_kc_sig = g_kc;                 /* family-UNBOUND: CLIENT or ANON */
    cfg.proto_ver = NODUS_CSESS_PROTO_VERSION;
    memcpy(cfg.chain_id, g_chain, sizeof(cfg.chain_id));
    if (nodus_tcp_sc_enable(&g_srv_tcp, conn, &cfg) != 0)
        nodus_tcp_disconnect(&g_srv_tcp, conn);
}

static void srv_on_session(nodus_tcp_conn_t *conn, void *ctx) {
    (void)ctx;
    g_starts++;
    g_start_rc = nodus_auth_session_start(g_srv, &g_srv->sessions[conn->slot]);
}

static void cli_on_session(nodus_tcp_conn_t *conn, void *ctx) {
    (void)conn; (void)ctx;
    g_cli_sessions++;
}

static void cli_on_frame(nodus_tcp_conn_t *conn, const uint8_t *payload, size_t len,
                         void *ctx) {
    (void)conn; (void)ctx;
    g_cli_frames++;
    nodus_tier2_msg_t m;
    memset(&m, 0, sizeof(m));
    if (g_cli_frames == 1 && nodus_t2_decode(payload, len, &m) == 0 &&
        strcmp(m.method, "auth_ok") == 0 && m.has_token) {
        g_cli_is_auth_ok = true;
        memcpy(g_cli_token, m.token, NODUS_SESSION_TOKEN_LEN);
    }
    nodus_t2_msg_free(&m);
}

static void test_anon_session_start(void) {
    TEST("ANON connection: nodus_auth_session_start makes a principal-less session");
    g_srv = calloc(1, sizeof(*g_srv));
    /* the responder's KEM key: the certificate (nodus_tcp_sc_kc_sign) needs it */
    if (!g_srv || nodus_identity_generate(&g_node) != 0 || !g_node.has_mlkem) {
        FAIL("setup");
        return;
    }
    memset(g_chain, 0x42, sizeof(g_chain));
    if (nodus_tcp_sc_kc_sign(&g_node, g_chain, g_kc) != 0) { FAIL("kc sign"); return; }

    nodus_key_t pin;
    if (nodus_fingerprint(&g_node.pk, &pin) != 0) { FAIL("pin"); return; }

    nodus_tcp_init(&g_srv_tcp, -1);
    nodus_tcp_init(&g_cli_tcp, -1);
    g_srv_tcp.on_accept = srv_on_accept;
    g_srv_tcp.on_session = srv_on_session;
    g_cli_tcp.on_session = cli_on_session;
    g_cli_tcp.on_frame = cli_on_frame;
    if (nodus_tcp_listen(&g_srv_tcp, "127.0.0.1", 0) != 0) { FAIL("listen"); return; }
    nodus_tcp_conn_t *cc = nodus_tcp_connect(&g_cli_tcp, "127.0.0.1", g_srv_tcp.port);
    if (!cc) { FAIL("connect"); return; }

    nodus_tcp_sc_cfg_t ccfg;
    memset(&ccfg, 0, sizeof(ccfg));
    ccfg.role = CMT_P2P_SC_ROLE_INITIATOR;
    ccfg.profile = &CMT_P2P_SC_PROFILE_ANON;       /* no key, no login */
    ccfg.id = NULL;
    ccfg.proto_ver = NODUS_CSESS_PROTO_VERSION;
    memcpy(ccfg.chain_id, g_chain, sizeof(ccfg.chain_id));
    ccfg.expected_peer = &pin;
    if (nodus_tcp_sc_enable(&g_cli_tcp, cc, &ccfg) != 0) { FAIL("client enable"); return; }

    for (int i = 0; i < 3000 && !(g_cli_frames >= 1 && g_starts >= 1); i++) {
        nodus_tcp_poll(&g_srv_tcp, 1);
        nodus_tcp_poll(&g_cli_tcp, 1);
    }
    if (g_starts != 1 || g_start_rc != 0 || g_cli_frames != 1 || !g_cli_is_auth_ok) {
        FAIL("no session start / no token message");
        return;
    }

    nodus_session_t *sess = &g_srv->sessions[g_srv_slot];
    nodus_tcp_conn_t *sc = sess->conn;
    uint8_t zeros64[64] = {0};
    uint8_t zeros_pk[NODUS_PK_BYTES] = {0};
    uint8_t tok0[NODUS_SESSION_TOKEN_LEN] = {0};
    uint8_t pkb[CMT_P2P_SC_DSA_PK_SIZE];
    int ok = sess->anonymous && sess->authenticated &&
             memcmp(sess->client_fp.bytes, zeros64, 64) == 0 &&
             memcmp(sess->client_pk.bytes, zeros_pk, NODUS_PK_BYTES) == 0 &&
             sc != NULL && !sc->peer_id_set && sc->authenticated &&
             nodus_tcp_sc_is_anonymous(sc) && nodus_tcp_sc_peer_pubkey(sc, pkb) == -1 &&
             g_srv->presence.count == 0 &&
             g_srv->next_auth_seq == 1 && sess->auth_seq == 1 &&
             memcmp(sess->token, tok0, sizeof(tok0)) != 0 &&
             memcmp(sess->token, g_cli_token, NODUS_SESSION_TOKEN_LEN) == 0 &&
             nodus_sessions_count_fp(g_srv->sessions, NODUS_MAX_SESSIONS,
                                     &sess->client_fp, NULL) == 0 &&
             g_cli_sessions == 1;
    if (ok) PASS(); else FAIL("the ANON session carries a principal, a presence entry or a wrong token");

    nodus_tcp_close(&g_cli_tcp);
    nodus_tcp_close(&g_srv_tcp);
    nodus_identity_clear(&g_node);
    free(g_srv);
    g_srv = NULL;
}

int main(void) {
    printf("test_anon_dispatch (DHT v2 package 3d, ANON session):\n");
    test_allowlist();
    test_session_table();
    test_anon_session_start();
    printf("\n%d passed, %d failed\n", passed, failed);
    return failed ? 1 : 0;
}
