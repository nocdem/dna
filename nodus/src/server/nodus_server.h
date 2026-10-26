/**
 * Nodus — Server Core
 *
 * Dual-transport event loop (UDP Kademlia + TCP data/clients).
 * Session management, authentication, message dispatch.
 *
 * @file nodus_server.h
 */

#ifndef NODUS_SERVER_H
#define NODUS_SERVER_H

#include <signal.h>                /* sig_atomic_t — see stop_requested */
#include <string.h>                /* the static inline config helpers */

#include "nodus/nodus_types.h"
#include "transport/nodus_tcp.h"
#include "transport/nodus_udp.h"
#include "dht/nodus_dht.h"                  /* session slots, DHT types (S4) */
#include "server/nodus_dht_backend.h"       /* srv->dht */
#include "channel/nodus_channel_server.h"
#include "channel/nodus_channel_replication.h"
#include "channel/nodus_channel_ring.h"
#include "consensus/nodus_cluster.h"
#include "crypto/nodus_identity.h"
#include "crypto/nodus_channel_crypto.h"
#include "witness/nodus_witness.h"          /* nodus_witness_config_t */
#include "net/nodus_p2p_host.h"             /* nodus_p2p_config_t (P2P-PORT F5) */
#include "witness/nodus_witness_host.h"     /* the witness's host view (S1) */
#include "witness/nodus_witness_network_file.h" /* nodus_network_file_target_t */
#include "server/nodus_chain_backend.h"     /* srv->chain */
#include "server/nodus_presence.h"
#include "server/nodus_inter_dial.h"       /* the 4002 dialer handshake (S5a) */
#include "server/nodus_partial_wipe.h"     /* the H-10 boot gate (S5b) */
#include "circuit/nodus_circuit.h"
#include "circuit/nodus_inter_circuit.h"
#include "crypto/nodus_channel_crypto.h"
#include "protocol/nodus_tier2.h"   /* nodus_t2_cursor_t / page info (DHT Package A) */

#ifdef __cplusplus
extern "C" {
#endif

#define NODUS_MAX_SEED_NODES   16

/* ── Configuration ───────────────────────────────────────────────── */

typedef struct {
    char        bind_ip[64];
    char        external_ip[64];    /* Public IP to advertise to clients (empty = use bind_ip) */
    uint16_t    udp_port;
    uint16_t    tcp_port;
    uint16_t    peer_port;          /* Inter-node TCP port (default: 4002) */
    uint16_t    ch_port;            /* Channel client TCP port (default: 4003) */
    uint16_t    witness_port;       /* Witness BFT TCP port (default: 4004) */
    char        identity_path[256];
    char        data_path[256];
    char        seed_nodes[NODUS_MAX_SEED_NODES][64];
    uint16_t    seed_ports[NODUS_MAX_SEED_NODES];
    int         seed_count;

    /* Witness module (optional DNAC BFT consensus) */
    nodus_witness_config_t  witness;

    /* RETIRED (DHT v2 3b-2, Kurultay #43 mandatory fixes: "the 4002
     * require_peer_auth gate deleted"). Every 4002 connection runs the node
     * session (SecretConnection, NODE profile) unconditionally, as every
     * 4004 connection runs the witness one; nothing reads this field. It
     * stays in the struct only so that existing node configs that set it
     * ("require_peer_auth": false) still parse — setting it false no
     * longer opens a plaintext 4002 (tools/nodus_node_config.c is not
     * touched by this package). */
    bool        require_peer_auth;

    /* P2P-PORT F5 — the witness port 4004's p2p section (reference
     * config.go P2P key names; net/nodus_p2p_host.h). */
    nodus_p2p_config_t p2p;

    /* R3 W4 — is_cold_bootstrap (the PR 3 Yol B / C-2 cold-DR escape) is
     * DELETED with the closed consensus lane, field and all: its one
     * reader (nodus_witness_bootstrap.c, which bypassed the DISCOVER
     * bootstrap state machine's C-2 cabal protection on incoming
     * w_chain_q when this flag was set) is deleted with that file, and
     * the field itself no longer exists in this struct — there is
     * nothing left for the CLI/config to set. */

    /* O15E Faz D — local successor genesis PIN for a fresh joiner. When
     * `has_v2_genesis_pin` is set and the node has no successor chain,
     * the joiner bootstrap pulls the canonical genesis bundle from a
     * peer, re-derives the genesis, and adopts it ONLY if the derivation
     * matches `v2_genesis_pin`. Operator-supplied (CLI/config), NEVER
     * wire-settable. Without it a fresh node is not a successor joiner.
     *
     * R3 W3 (D-24 rev 4 (1)): 32 bytes — the chain id, not a 64-byte
     * genesis BlockID. A version-3 chain has no genesis BLOCK to pin to
     * (D-19 rev 6 withdrew it); its only identity is the hash of its
     * stored genesis DOCUMENT (D-18 rev 4), which is exactly what this
     * field holds. */
    bool        has_v2_genesis_pin;
    uint8_t     v2_genesis_pin[32];

    /* P2P-PORT F6 — the published network file (decision
     * 2026-09-26-witness-port-session.md "Ağ config dosyası"): its path
     * (nodus.json key "network_file"; `--network-file` overrides) and, when
     * the file carries a pin, that pin. `has_network_pin` arms the start
     * check in nodus_server_init: a node that HOLDS a chain whose id is
     * not the file's pin refuses to start. A `--v2-genesis-pin` given
     * alone keeps its old meaning (inert when a chain is present). */
    char        network_file[256];
    bool        has_network_pin;
    uint8_t     network_pin[32];

    /* WebSocket entry of the client port (decision
     * 2026-09-25-web-wallet-nodus-send-transport.md; nodus_ws.h).
     * ws_port: nodus.json "ws_port"; 0 = OFF (default). The listener is
     * ALWAYS bound to 127.0.0.1 — there is no address setting; the public
     * side is a local TLS proxy (Caddy). It is a second listening socket of
     * `tcp` (the client transport), not a separate transport.
     * ws_origins: nodus.json "ws_origins" (array of strings); allowed
     * browser Origin values, exact match. count 0 = the default
     * NODUS_WS_DEFAULT_ORIGIN, applied in nodus_server_init. */
    uint16_t            ws_port;
    nodus_ws_origins_t  ws_origins;

    /* Node-local address history index (decision docs/plans/decisions/
     * 2026-10-01-node-address-history-index.md rev 2;
     * witness/nodus_witness_addr_index.h). nodus.json
     * "addr_history_index": true; default OFF. Off = the writers write
     * nothing. It changes no root — the setting may differ per node. */
    bool                addr_history_index;

    /* Component split S3 (decision docs/plans/decisions/2026-10-01-nodus-
     * component-split.md items 5, 7, 19, 20): the witness runs as its own
     * process (`nodus-witness`) and this server reaches it over the Unix
     * socket <data_path>/witness.sock (server/nodus_chain_backend_ipc.c)
     * instead of starting it in this process. nodus.json
     * "witness_external": true / `--witness-external`; default false =
     * the in-process witness, unchanged. When true this server opens no
     * port 4004 and holds no chain database; the partial-wipe gate and
     * (nodus-server only — nodus-core's loader applies no network file;
     * nodus-witness runs that check itself) the network-file pin check
     * still run here. nodus-witness refuses
     * to start unless its loaded config has it too
     * (tools/nodus-witness.c). */
    bool                witness_external;

    /* Component split S5b (decision docs/plans/decisions/2026-10-01-nodus-
     * component-split.md items 7, 16, 19, 31, 32): the DHT / storage half
     * runs as its own process (`nodus-storage`) and this server reaches it
     * over the Unix socket <data_path>/storage.sock
     * (server/nodus_dht_backend_ipc.c) instead of opening nodus.db and
     * channels.db itself. nodus.json "storage_external": true /
     * `--storage-external` (tools/nodus_node_config.c, beside
     * witness_external); default false = the in-process DHT,
     * unchanged. When true this server keeps 4000 / 4001 / 4002, sessions,
     * cluster, presence and circuits; the partial-wipe gate still runs here
     * (decision item 9). nodus-storage refuses to start unless its loaded
     * config has it too (tools/nodus-storage.c). */
    bool                storage_external;
} nodus_server_config_t;

/* ── Inter-node session (rate limiting + the peer identity the node
 *    session proved) ── */

typedef struct {
    nodus_tcp_conn_t   *conn;
    /* Generation of this session as the DHT's origins name it
     * (nodus_dht_origin_t): a fresh value from srv->next_session_gen where
     * conn is set (connect / accept); 0 once cleared. */
    uint64_t            dht_gen;

    /* The PEER's identity as the node session proved it (DHT v2 3b-2:
     * set at on_session from the SecretConnection's authenticated key, on a
     * dialed conn as well as on an accepted one — nodus_inter_session_proven).
     * `authenticated` is true exactly from then on; no 4002 frame is
     * dispatched before (the layer holds the input back). */
    nodus_key_t         client_fp;
    nodus_pubkey_t      client_pk;
    bool                authenticated;

    /* Per-session rate limiting (the DHT methods' sv / fv windows are the
     * DHT's: nodus_dht_inter_session_t) */
    uint64_t            ps_window_start;
    int                 ps_count;
    uint64_t            cr_window_start;
    int                 cr_count;
    uint64_t            w_window_start;
    int                 w_count;
} nodus_inter_session_t;

/* ── Client session ──────────────────────────────────────────────── */

typedef struct {
    nodus_tcp_conn_t   *conn;
    /* Generation of this session as the DHT's origins name it
     * (nodus_dht_origin_t): a fresh value from srv->next_session_gen where
     * conn is set (accept); 0 once cleared. */
    uint64_t            dht_gen;
    nodus_key_t         client_fp;
    nodus_pubkey_t      client_pk;
    uint8_t             token[NODUS_SESSION_TOKEN_LEN];
    bool                authenticated;
    bool                is_nodus;
    /* Order of this session's authentication on this server: a fresh value
     * from srv->next_auth_seq when the SecretConnection becomes
     * authenticated; 0 = never authenticated (session_clear zeroes it).
     * Names "oldest" for the per-identity session limit and "newest" for
     * the circuit target — a counter, not a clock, so two auths in one tick
     * never tie. */
    uint64_t            auth_seq;

    /* The session's LISTEN keys and put-rate window are the DHT's
     * (nodus_dht_session_t, same slot). */

    /* Circuit table (VPN mesh Faz 1) */
    nodus_circuit_table_t   circuits;

    /* Chain-method budget (nodus_session_chain_charge): start of the
     * current window on nodus_time_mono_ms() and the units spent in it.
     * session_clear zeroes both. */
    uint64_t                chain_window_start_ms;
    uint32_t                chain_units_used;
} nodus_session_t;

/* ── Server ──────────────────────────────────────────────────────── */

typedef struct nodus_server {
    nodus_server_config_t   config;
    nodus_identity_t        identity;

    /* Shared event loop */
    int                     epoll_fd;

    /* Transports */
    nodus_tcp_t             tcp;
    nodus_tcp_t             inter_tcp;      /* Inter-node TCP transport (port 4002) */
    /* P2P-PORT F5 — `witness_tcp` (the nodus_tcp framed transport on port
     * 4004) is DELETED: 4004 is the witness's p2p host
     * (witness->p2p, nodus_witness_p2p.h). */
    nodus_udp_t             udp;

    /* The DHT / storage half (routing, lookups, replication, nodus.db,
     * channels.db), behind the DHT backend (split S4,
     * server/nodus_dht_backend.h). Set by nodus_server_init. */
    nodus_dht_backend_t    *dht;

    /* Consensus */
    nodus_cluster_t         cluster;

    /* The witness module, behind the chain backend (NULL when its init
     * failed — the node runs without consensus) */
    nodus_chain_backend_t  *chain;
    /* The partial-wipe marker has been written by this process: at the end
     * of nodus_server_init, or (split S3 witness_external / S5b
     * storage_external) by nodus_server_run once the chain is open and the
     * DHT's databases exist (nodus_server_marker_dbs_ready). Read only in
     * those two modes. */
    bool                    genesis_marker_armed;
    /* S5b: the second the run loop last asked nodus_server_marker_dbs_ready
     * (it stats two files; once a second at most while waiting). */
    uint64_t                last_marker_check;

    /* Presence tracking (connected clients, cluster-wide) */
    nodus_presence_table_t  presence;

    /* Inter-node circuit forwarding (VPN mesh Faz 1) */
    nodus_inter_circuit_table_t inter_circuits;

    /* New channel system (TCP 4003) */
    nodus_channel_server_t      ch_server;
    nodus_ch_replication_t      ch_replication;
    nodus_ch_ring_t             ch_ring;
    bool                        ch_startup_done;  /* One-shot: rejoin sent */

    /* Sessions (indexed by conn->slot) */
    nodus_session_t         sessions[NODUS_MAX_SESSIONS];
    nodus_inter_session_t   inter_sessions[NODUS_MAX_INTER_SESSIONS];
    /* Last session generation handed out (client and 4002 sessions share
     * it; only increases — the first is 1). Decision
     * 2026-10-01-nodus-component-split.md item 29. */
    uint64_t                next_session_gen;
    /* Last client auth_seq handed out (nodus_session_t.auth_seq; only
     * increases — the first is 1). */
    uint64_t                next_auth_seq;

    /* CRIT-4: TCP idle connection sweep (every 30s) */
    uint64_t                last_idle_sweep;

    /* The pre-session deadline (Kurultay #43 O-5) of the two accepting
     * transports is looked at once a second on the monotonic clock: the
     * nodus_time_mono_ms() of the last look. */
    uint64_t                last_presession_mono_ms;

    /* The node-session config of the 4002 pool (srv->inter_tcp.auth_ctx
     * points here): this node's identity and where the chain id comes from
     * (the chain backend; zero until a chain is open — then no 4001 / 4002
     * session is made). */
    nodus_inter_session_cfg_t inter_cfg;

    /* The chain id every session of this node is bound to (the HELLO of
     * 4001 / WebSocket and of 4002): the 32-byte v3 chain id, learned from the
     * chain backend's chain_id_v3 op (in-process witness, or the `c3` of
     * nodus-witness' ipc_status — NOT the legacy padded `ci`) at the
     * first accept / dial that finds it non-zero, then kept: a chain id never
     * changes for the life of the process. Until it is known, sessions are
     * refused (fail closed) — nodus_server_chain_id. */
    uint8_t                 chain_id[32];
    bool                    chain_id_known;
    /* While unknown the backend is asked at most once a second:
     * nodus_time_mono_ms() of the last ask, and whether there was one. */
    bool                    chain_id_tried;
    uint64_t                chain_id_try_mono_ms;

    /* Phase 1 visibility: send diagnostics dump timer */
    uint64_t                last_stats_dump;

    /* Process start time for cluster-status uptime field (Task 0.2) */
    uint64_t                start_time;

    bool                    running;

    /* Set by nodus_server_stop(), which nodus-server calls from its
     * SIGINT/SIGTERM handler. SEPARATE from `running` because
     * nodus_server_run() sets `running = true` on entry: a stop that
     * arrives during nodus_server_init() — which is a long operation
     * (storage migration, VACUUM, identity generation, witness init) —
     * would otherwise be overwritten a moment later and the process
     * would ignore the signal for the rest of its life. The Stage F
     * harness kills its short-lived identity-generation spawns exactly
     * in that window, so it hit this intermittently and hung
     * stagef_up.sh in `wait`. sig_atomic_t because a signal handler
     * writes it. */
    volatile sig_atomic_t   stop_requested;
} nodus_server_t;

/**
 * Split S6 — the in-process constructors nodus_server_init_ex calls, as a
 * table (decision docs/plans/decisions/2026-10-01-nodus-component-split.md
 * items 2, 12). nodus_server.c references no in-process DHT or witness
 * object by name: nodus-core links the IPC table and nothing pulls
 * nodus_dht_server.c / nodus_witness.c into it (tests/core_linked.cmake).
 *
 *   admit      NULL, or called first with the config: non-zero refuses the
 *              start (logged by the callee) before anything is opened.
 *   check_pin  the network file's pin-at-start check
 *              (nodus_chain_backend_inproc_check_pin), run when
 *              `has_network_pin`. NULL = this table holds no chain
 *              database: a set pin refuses the start (logged).
 *   dht_new /  the in-process DHT, phases one and two
 *   dht_open   (nodus_dht_backend_inproc_new / _open), used when
 *              !storage_external. NULL = refuse the start (logged).
 *   chain_open the in-process witness (nodus_chain_backend_inproc_open),
 *              used when !witness_external. NULL = refuse the start
 *              (logged).
 */
typedef struct {
    int (*admit)(const nodus_server_config_t *config);
    int (*check_pin)(const char *data_path, const uint8_t pin[32]);
    int (*dht_new)(const nodus_dht_host_t *host, nodus_dht_backend_t **out);
    int (*dht_open)(nodus_dht_backend_t *b, const char *data_path,
                    const char *self_ip, uint16_t self_peer_port);
    int (*chain_open)(const nodus_witness_host_t *host,
                      const nodus_witness_config_t *config,
                      nodus_chain_backend_t **out);
} nodus_server_backends_t;

/** The in-process table (server/nodus_server_backends_inproc.c) —
 *  nodus-server, and every unit test through nodus_server_init. */
extern const nodus_server_backends_t nodus_server_backends_inproc;

/** The IPC-only table (server/nodus_server_backends_ipc.c) — nodus-core.
 *  Its `admit` refuses unless BOTH storage_external and witness_external
 *  are set; every in-process slot is NULL. */
extern const nodus_server_backends_t nodus_server_backends_ipc;

/**
 * Load this node's identity from directory `path`, or create it on a first
 * start — never replace an existing one. nodus_server_init uses it for a
 * non-empty identity_path (decision 2026-10-01-nodus-component-split item
 * 10: only the core writes identity files).
 *
 *  - nodus_identity_load(path) succeeds → 0.
 *  - It fails and NEITHER `<path>/nodus.pk` NOR `<path>/nodus.sk` exists
 *    (lstat → ENOENT for both) → first start: generate, then
 *    nodus_identity_save; 1 when both succeed. A failed save → -1: an
 *    identity that is not on disk would be replaced on the next start.
 *  - It fails and either file exists, or lstat fails with anything but
 *    ENOENT (unreadable, truncated, half-restored) → -1, logged with the
 *    path; nothing is generated and no file is written.
 *
 * @param path  identity directory (non-empty)
 * @param out   the identity; securely cleared whenever -1 is returned
 * @return 0 loaded, 1 created and saved, -1 refused or failed
 */
int nodus_server_identity_load_or_create(const char *path, nodus_identity_t *out);

/**
 * Initialize server with config. Loads identity, opens storage, binds ports.
 * -1 also when identity_path holds an identity that cannot be loaded
 * (nodus_server_identity_load_or_create above).
 * = nodus_server_init_ex(srv, config, &nodus_server_backends_inproc);
 * defined in server/nodus_server_backends_inproc.c.
 */
int nodus_server_init(nodus_server_t *srv, const nodus_server_config_t *config);

/**
 * Split S6 — nodus_server_init with an explicit constructor table `be`
 * (above). Same contract as nodus_server_init; -1 also when `be` is NULL
 * or refuses (admit, or a NULL slot the config needs).
 */
int nodus_server_init_ex(nodus_server_t *srv, const nodus_server_config_t *config,
                         const nodus_server_backends_t *be);

/* nodus_server_check_partial_wipe (PR 3 / E5, H-10) is declared in
 * server/nodus_partial_wipe.h, included above — its own object since
 * split S5b, so nodus-storage links it without this server. */

/**
 * Split S5b — may this server arm the partial-wipe marker now, as far as the
 * DHT's two databases go? The marker asserts "all three databases are real"
 * (O16A, nodus_server_init). The in-process DHT has opened nodus.db and
 * channels.db before the marker is armed, so: true. With
 * `storage_external` this process opens neither — nodus-storage does, and
 * may not have yet — so: true only when both files exist under data_path
 * ("/tmp" when empty), the rule tools/nodus-witness.c (core_dbs_present)
 * applies from the other side. Reads the file system only (stat).
 */
bool nodus_server_marker_dbs_ready(const nodus_server_config_t *cfg);

/* ── S1 witness seam ──────────────────────────────────────────────────
 *
 * Decision docs/plans/decisions/2026-10-01-nodus-component-split.md: the
 * witness sees this server only through a nodus_witness_host_t
 * (witness/nodus_witness_host.h), and the server reaches the witness only
 * through `srv->chain` (server/nodus_chain_backend.h). The network file
 * and the chain-pin check moved to witness/nodus_witness_network_file.h.
 */

/**
 * Fill the witness's host view from this server: `identity` points at
 * `srv->identity`; the config subset is copied from `srv->config` (seq_dir
 * = identity_path, where the p2p address-record sequence file lives);
 * `find_session_conn` searches `srv->sessions[]` for an authenticated
 * session with that client key and session token. nodus_server_init calls
 * it after loading the identity; a caller that edits `srv->config`
 * afterwards must fill again.
 */
void nodus_server_witness_host(nodus_server_t *srv, nodus_witness_host_t *out);

_Static_assert(sizeof(((nodus_witness_host_config_t *)0)->bind_ip) ==
               sizeof(((nodus_server_config_t *)0)->bind_ip),
               "host bind_ip must hold the server's");
_Static_assert(sizeof(((nodus_witness_host_config_t *)0)->external_ip) ==
               sizeof(((nodus_server_config_t *)0)->external_ip),
               "host external_ip must hold the server's");
_Static_assert(sizeof(((nodus_witness_host_config_t *)0)->data_path) ==
               sizeof(((nodus_server_config_t *)0)->data_path),
               "host data_path must hold the server's");
_Static_assert(sizeof(((nodus_witness_host_config_t *)0)->seq_dir) ==
               sizeof(((nodus_server_config_t *)0)->identity_path),
               "host seq_dir must hold the server's identity_path");

/**
 * The witness's configuration subset, copied from a node config — the ONE
 * definition both hosts use: nodus_server_witness_host (the combined
 * binary) and tools/nodus-witness.c (split S3), so the two processes give
 * the witness byte-identical settings — with ONE exception: seq_dir.
 * Here seq_dir = identity_path, where the combined binary has always kept
 * the p2p address-record sequence file. nodus-witness clears it after
 * this call (seq_dir "" → the witness uses data_path), because only core
 * writes the identity directory (decision
 * 2026-10-01-nodus-component-split items 10 and 21).
 * `static inline` on purpose: the nodus-witness binary must not link
 * nodus_server.c (test_split_linked).
 */
static inline void
nodus_server_witness_host_config(const nodus_server_config_t *cfg,
                                 nodus_witness_host_config_t *out) {
    memset(out, 0, sizeof(*out));
    memcpy(out->bind_ip, cfg->bind_ip, sizeof(out->bind_ip));
    memcpy(out->external_ip, cfg->external_ip, sizeof(out->external_ip));
    out->witness_port = cfg->witness_port;
    memcpy(out->data_path, cfg->data_path, sizeof(out->data_path));
    /* The combined binary's address-record sequence file stays where it
     * has always been: the identity directory (empty → the witness uses
     * data_path; nodus-witness empties it). */
    memcpy(out->seq_dir, cfg->identity_path, sizeof(out->seq_dir));
    out->p2p = cfg->p2p;
    out->has_v2_genesis_pin = cfg->has_v2_genesis_pin;
    memcpy(out->v2_genesis_pin, cfg->v2_genesis_pin,
           sizeof(out->v2_genesis_pin));
    out->addr_history_index = cfg->addr_history_index;
}

#ifdef NODUS_HAS_JSONC
/** The fields of `cfg` a network file sets (nodus_network_file_apply).
 *  `static inline` so that tools/nodus_node_config.c (shared by
 *  nodus-server and nodus-witness) does not pull nodus_server.c into the
 *  witness binary. */
static inline nodus_network_file_target_t
nodus_server_network_file_target(nodus_server_config_t *cfg) {
    nodus_network_file_target_t t = {
        .p2p                = &cfg->p2p,
        .has_v2_genesis_pin = &cfg->has_v2_genesis_pin,
        .v2_genesis_pin     = cfg->v2_genesis_pin,
        .has_network_pin    = &cfg->has_network_pin,
        .network_pin        = cfg->network_pin,
    };
    return t;
}
#endif /* NODUS_HAS_JSONC */

/**
 * Run the server event loop (blocks until stopped).
 */
int nodus_server_run(nodus_server_t *srv);

/**
 * Stop the server (sets running=false, returns from run).
 */
void nodus_server_stop(nodus_server_t *srv);

/**
 * Clean up all resources.
 */
void nodus_server_close(nodus_server_t *srv);

/* ── S4 DHT seam ──────────────────────────────────────────────────────
 *
 * Decision 2026-10-01-nodus-component-split.md items 2-4, 16, 17: the DHT
 * half sees this server only through a nodus_dht_host_t
 * (dht/nodus_dht.h), and the server reaches the DHT only through
 * `srv->dht` (server/nodus_dht_backend.h).
 */

/**
 * Fill the DHT's host view from this server: `identity` points at
 * `srv->identity`; send_to_origin writes to `srv->sessions[slot].conn` /
 * `srv->inter_sessions[slot].conn` when that session's dht_gen equals the
 * origin's generation (else nothing is sent, -1); udp_send uses `srv->udp`;
 * inter_send
 * is the inter-node pool send (`srv->inter_tcp`); hint_wanted asks
 * `srv->cluster`.
 */
void nodus_server_dht_host(nodus_server_t *srv, nodus_dht_host_t *out);

/**
 * The chain id this node's sessions are bound to (DHT v2 3b-2): from the chain
 * backend's status — the in-process witness, or the `ci` of nodus-witness'
 * ipc_status in the split — the first time it is non-zero, then kept in the
 * server. @return true and `out` filled; false while it is not known (no chain
 * backend, no chain open, the witness not answering): every session, 4001 /
 * WebSocket and 4002, accept and dial alike, is then REFUSED — fail closed,
 * there is no session without a chain.
 */
bool nodus_server_chain_id(nodus_server_t *srv, uint8_t out[32]);

/**
 * Core's outbound 4002 dial — find-or-dial on `srv->inter_tcp`, shared by
 * every outbound site core has: the DHT host's inter_send (replication,
 * republish, hinted retry), presence p_sync and circuits (decision
 * 2026-10-01-nodus-component-split item 30).
 *
 * Find (nodus_server_inter_find): with `expected_node_id` NULL, the first
 * pool entry for ip:port is returned as it is, whatever it is (unchanged
 * behaviour). With a node_id, a pooled conn is returned only if WE dialed
 * it (auth_initiated_by_us) and its identity is that node_id — its
 * expected_peer_id (the pin recorded at dial) and/or its proven peer_id
 * (set after auth_ok passed the pin) equal it, and neither, when set,
 * differs. An accepted (inbound) conn, a dial pinned to another node_id,
 * a conn proven for another node_id, or an unpinned dial is NOT reused:
 * a fresh conn is dialed beside it (the pool allows several conns to one
 * ip:port; the transport has no duplicate check). A pooled conn is never
 * re-pinned.
 *
 * Dial: a new connection is opened, marked is_nodus, and — when
 * `expected_node_id` is non-NULL — that identity is recorded as
 * conn->expected_peer_id: the dialer's auth_ok handler pins
 * fingerprint(server_pk) against it and refuses a connection without one
 * (CRIT-1).
 *
 * @return the connection, or NULL if the dial could not be started.
 */
nodus_tcp_conn_t *nodus_server_inter_dial(nodus_server_t *srv, const char *ip,
                                          uint16_t port,
                                          const nodus_key_t *expected_node_id);

/**
 * The find half of nodus_server_inter_dial (the match rule above), without
 * dialing. NULL when no pooled conn qualifies.
 */
nodus_tcp_conn_t *nodus_server_inter_find(nodus_server_t *srv, const char *ip,
                                          uint16_t port,
                                          const nodus_key_t *expected_node_id);

/* ── Client session start (used by server) ───────────────────────── */

/**
 * The client session of `sess` just became AUTHENTICATED (4001 / WebSocket;
 * the transport's on_session): what the T2 hello → challenge → auth → auth_ok
 * handler used to do when the AUTH signature verified (DHT v2 3b-2, Kurultay
 * #43 O-1 / O-2 b), re-homed here:
 *   - the client identity: sess->client_pk from the SecretConnection's
 *     authenticated key, client_fp its fingerprint; conn->peer_id / peer_pk;
 *   - sess->authenticated, sess->auth_seq (srv->next_auth_seq);
 *   - the per-identity session limit (NODUS_MAX_SESSIONS_PER_IDENTITY): the
 *     oldest sessions of the same identity are disconnected;
 *   - presence (nodus_presence_add_local);
 *   - a fresh session token, sent as the FIRST sealed frame: the T2 `auth_ok`
 *     message (txn 0) carrying the token and nothing else. The token is a
 *     correlation key only — identity is the connection (O-2 b).
 * No payload cap is lifted here: the cap (NODUS_PREAUTH_PAYLOAD_MAX) is
 * retired with the hello / auth path — before authentication no nodus frame
 * exists on the connection, only the layer's handshake messages.
 * @return 0; -1 when the peer key cannot be read (the caller disconnects).
 */
int nodus_auth_session_start(nodus_server_t *srv, nodus_session_t *sess);

/* ── Sessions of one identity (client port 4001) ────────────────────
 *
 * One identity may hold up to NODUS_MAX_SESSIONS_PER_IDENTITY live
 * authenticated sessions on one node. Through 0.25.4 an authentication
 * disconnected EVERY other session of the same fingerprint (a ghost-socket
 * cleanup for mobile reconnects); two devices of one account — the
 * operator's phone and PC with Nodus Connect open — that landed on the
 * same node then evicted each other in a loop (dropped connections,
 * failed reads, missed messages), and that rule also blocked the
 * multi-device design. 4 = the operator's per-account device limit. A
 * mobile client's ghost is still cleared: it is the oldest session of its
 * identity, so it goes first once the limit is reached (below it, the
 * 30 s idle sweep closes it). A session is "live" when authenticated and
 * conn != NULL; sessions[i] is slot i. Inter-node sessions (4002/4004)
 * are a different table and are not affected. */
#define NODUS_MAX_SESSIONS_PER_IDENTITY 4

/* ── Client port front door (decision 2026-10-14-kurultay-20-summary.md;
 *    operator's simple version, rpc-front-door design) ────────────────
 *
 * (The pre-auth frame cap NODUS_PREAUTH_PAYLOAD_MAX is RETIRED, Kurultay
 * #43 O-5: before the session is authenticated the connection carries only
 * the SecretConnection's own handshake messages, bounded by that layer, and
 * the 15 s / 30 s pre-session deadline — nodus_tcp_sc_presession_sweep.) */

/* The pre-session deadline of the accepting transports (4001 / WebSocket and
 * 4002), Kurultay #43 O-5, on the monotonic clock: a connection that is not
 * authenticated is closed NODUS_PRESESSION_IDLE_MS after its last socket byte
 * and NODUS_PRESESSION_ABS_MS after it connected, whichever comes first. The
 * per-IP caps (NODUS_MAX_CONNS_PER_IP, 20 + 20) are unchanged. */
#define NODUS_PRESESSION_IDLE_MS   15000u
#define NODUS_PRESESSION_ABS_MS    30000u
/* New handshakes one IP may start per minute on each accepting port (4001 +
 * WebSocket, 4002): operator decision 2026-10-24, "60/min per IP"
 * (decisions/2026-10-24-dht-v2-handshake-rate.md). Set as
 * nodus_tcp_t.hs_rate_per_min on both transports; monotonic clock. */
#define NODUS_HANDSHAKE_RATE_PER_MIN 60u

/* Per-session budget for chain methods (every request for which
 * nodus_chain_method_routed() is true): a fixed window of
 * NODUS_CHAIN_RATE_WINDOW_MS on core's monotonic clock, at most
 * NODUS_CHAIN_RATE_BUDGET units in it; over → NODUS_ERR_RATE_LIMITED, the
 * request is not forwarded. JUDGMENT, not measured: the largest legal
 * envelope is 1 MiB (DNA_ENV_MAX_TOTAL_LEN) → ⌈1048576 / 4627⌉ = 227
 * units, so one spend always fits a fresh window (core charges the T2
 * payload length, which adds the request's hash / pk / sig / fee ≈ 7.4 KB:
 * ≤ 229 units for a 1 MiB envelope); a wallet's 100-page scan
 * and an explorer catch-up stay below it. Node-local: core's clock,
 * never the witness's consensus paths. */
#define NODUS_CHAIN_RATE_WINDOW_MS  10000u
#define NODUS_CHAIN_RATE_BUDGET     300u
/* One unit of a dnac_spend = the bytes of one ML-DSA-87 signature. */
#define NODUS_CHAIN_RATE_UNIT_BYTES 4627u
_Static_assert(NODUS_CHAIN_RATE_UNIT_BYTES == NODUS_SIG_BYTES,
               "spend unit is one signature's bytes");

/** Units a dnac_spend of `len` bytes costs: ⌈len / 4627⌉, at least 1. */
uint32_t nodus_chain_spend_units(size_t len);

/** Charge `units` to the session's chain budget at monotonic time
 *  `now_ms` (rate_check_put shape): a window older than
 *  NODUS_CHAIN_RATE_WINDOW_MS starts over; if the units do not fit what is
 *  left of NODUS_CHAIN_RATE_BUDGET nothing is charged and false is
 *  returned. */
bool nodus_session_chain_charge(nodus_session_t *sess, uint32_t units,
                                uint64_t now_ms);

/** Number of live sessions in sessions[0..n) authenticated as `fp`, not
 *  counting `exclude` (NULL = count all). */
int nodus_sessions_count_fp(const nodus_session_t *sessions, int n,
                            const nodus_key_t *fp,
                            const nodus_session_t *exclude);

/** The live session authenticated as `fp` with the highest auth_seq (the
 *  identity's most recent authentication), or NULL. */
nodus_session_t *nodus_sessions_newest_fp(nodus_session_t *sessions, int n,
                                          const nodus_key_t *fp);

/** The slots to disconnect so that `keep` (just authenticated) and at most
 *  max_per_identity - 1 other live sessions of keep's fingerprint remain:
 *  the others with the LOWEST auth_seq first, oldest first in slots_out.
 *  `keep` is never chosen. Returns the number written (<= cap). */
int nodus_sessions_evict_plan(const nodus_session_t *sessions, int n,
                              const nodus_session_t *keep,
                              int max_per_identity,
                              int *slots_out, int cap);

/* ════════════════════════════════════════════════════════════════════
 * INTERNAL — exposed ONLY so unit tests can drive them in-process
 * (tests/test_inter_circuit_uaf.c, test_inter_preauth_gate.c,
 * test_bf_forward_frames.c, test_inter_role_split.c). Not an API: no other
 * module calls these. The DHT Package A helpers are in dht/nodus_dht.h.
 * ════════════════════════════════════════════════════════════════════ */

/** F1: a 4002 conn is going away — close every inter-circuit routed over
 *  it, tell the attached local client (circ_open_err while the open is
 *  pending, else circ_close) and unlink the client's circuit. Called by
 *  the inter-port disconnect callback before the conn is freed. */
void nodus_server_inter_conn_closed(nodus_server_t *srv,
                                    const nodus_tcp_conn_t *conn);

/** F1: free pending_open inter-circuits older than max_age_ms, unlinking
 *  the attached client circuit first (circ_open_err TIMEOUT to the client).
 *  @return number freed */
int nodus_server_inter_sweep_orphans(nodus_server_t *srv, uint64_t now_ms,
                                     uint64_t max_age_ms);

/** The pre-session deadline (Kurultay #43 O-5) of the two accepting
 *  transports as of `now_mono_ms` (nodus_time_mono_ms scale): close every
 *  unauthenticated layer connection idle NODUS_PRESESSION_IDLE_MS or older
 *  than NODUS_PRESESSION_ABS_MS. The run loop calls it once a second; tests
 *  call it with a time they choose. @return connections closed. */
int nodus_server_presession_sweep(nodus_server_t *srv, uint64_t now_mono_ms);

/** The 4002 frame dispatcher (the node session's gate), for in-process
 *  tests. */
void nodus_server_dispatch_inter_frame(nodus_server_t *srv,
                                       nodus_inter_session_t *sess,
                                       const uint8_t *payload, size_t len);

/** The body of the 4002 transport's on_disconnect callback (F1 circuit
 *  release + inter session clear), for in-process tests. */
void nodus_server_inter_disconnected(nodus_server_t *srv, nodus_tcp_conn_t *conn);

/** The 4002 transport's pending-full hook (`ctx` = the server): a frame to
 *  an authenticated cluster member that neither wbuf nor the pending queue
 *  could take is parked in the DHT hint table ONLY if it is a DHT
 *  replication frame (T1 "sv" / T2 "m_sv" query); anything else is dropped
 *  with a log line (split S5a, decision item 33). For in-process tests. */
void nodus_server_on_pending_full(nodus_tcp_conn_t *conn,
                                  const uint8_t *payload, size_t len,
                                  void *ctx);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_SERVER_H */
