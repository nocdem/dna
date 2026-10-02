/**
 * Nodus — DHT IPC (the nodus-storage process's local socket)
 *
 * Component split S5b (decision docs/plans/decisions/2026-10-01-nodus-
 * component-split.md items 7, 16, 17, 19, 27, 29, 31-34): the DHT / storage
 * half runs as its own process and core (nodus-server with
 * "storage_external") reaches it over ONE Unix domain socket,
 * <data_path>/storage.sock (mode 0600, both ends checked with SO_PEERCRED —
 * nodus_tcp_unix_listen / nodus_tcp_unix_connect). Frames are ordinary nodus
 * wire frames (the transport's 7-byte header), plaintext; no handshake
 * method exists here. Nothing on 4000 / 4001 / 4002 changes.
 *
 * Two kinds of connection, told apart by their FIRST frame (the preface):
 *
 *   origin (one per core session — client 4001 / WebSocket, or 4002 — that
 *   has sent a DHT request; decision item 19, "session lifetime = connection
 *   lifetime"):
 *     first frame  {"q":"ds_origin","v":1,"k":0|1,"s":slot,"g":gen,
 *                   "b":bstr 8 core boot id,"fp":bstr 64,
 *                   CLIENT (k 0): "pk":bstr NODUS_PK_BYTES,
 *                   INTER  (k 1): "ip":tstr peer address}
 *                  — THIS is "session opened": the storage process opens
 *                  the slot's shadow (nodus_dht_session_opened) with that
 *                  generation;
 *     then         the session's request payloads, unchanged (core's
 *                  dispatch routed them to the DHT; the storage side
 *                  re-decodes them with the same decoders: T2 for client
 *                  requests and 4002 fv / get_batch / m_sv, T1 for 4002
 *                  sv / sub / unsub / ntf);
 *     replies      every frame the DHT writes to that origin (replies, and
 *                  listener pushes from any other origin's request) comes
 *                  back on this connection; core writes it to the session
 *                  unchanged;
 *     EOF          is "session closed": the shadow is cleared — only when
 *                  the shadow still belongs to THIS connection's preface
 *                  (same boot id and generation). A slot's new preface may
 *                  be processed before the previous connection's EOF (the
 *                  slot was reused); that late EOF then changes nothing.
 *
 *   control (one per core):
 *     first frame  {"q":"ds_ctl","v":1,"b":bstr 8 core boot id}
 *     core → storage, in call order:
 *       {"q":"ds_udp","ip":tstr,"po":uint,"p":bstr}  a UDP 4000 datagram
 *                    for the DHT (fn, fn_r, sv, fv), as received;
 *       {"q":"ds_seen","k":uint kind,"id":bstr 64,"ip":tstr,"up":uint,
 *        "tp":uint}  nodus_dht_peer_seen (all four kinds, in order);
 *       {"q":"ds_dead","id":bstr 64}                 nodus_dht_peer_dead;
 *       {"q":"ds_mbr","m":[[bstr 64 node id, uint offline seconds], ...]}
 *                    core's cluster membership (decision item 27) — on
 *                    change, at least every NODUS_DHT_IPC_SNAPSHOT_MAX_SEC,
 *                    and in full on every (re)connect.
 *     storage → core:
 *       {"q":"ds_udps","ip":tstr,"po":uint,"p":bstr} send this T1 datagram
 *                    from UDP 4000 (raw CBOR);
 *       {"q":"ds_rt","r":[[bstr 64 node id, tstr ip, uint tcp port], ...]}
 *                    the routing table's peers in bucket order (decision
 *                    item 17; presence p_sync dials them, pinned) — when
 *                    the projected set changes, at least every
 *                    NODUS_DHT_IPC_SNAPSHOT_MAX_SEC, and in full on every
 *                    new control connection.
 *
 * A first frame that is not a preface of this version (a wrong "q", e.g. a
 * core dialling the witness socket, or another "v") closes the connection.
 * The control connection is never closed for a queue bound: past
 * NODUS_DHT_IPC_CTL_QUEUE_MAX a UDP datagram is dropped (the newest), and a
 * snapshot that could not be sent — or that the transport reports lost —
 * is sent again in full at the next check (NODUS_DHT_IPC_SNAPSHOT_CHECK_MS;
 * only a new control connection is served without waiting). A peer event
 * core could not send is counted and WARNed; a lost peer_dead is re-sent
 * (server/nodus_dht_backend_ipc.c).
 *
 * The boot id: core's IPC backend draws 8 random bytes when it is created.
 * Generations restart at 1 when core restarts, so (boot id, generation)
 * names a session. The CURRENT boot id is the one of the latest control
 * connection; core dials an origin only once its control connection is
 * confirmed (this side has answered on it), so an origin preface of any
 * other boot id is refused. A control connection of a NEW boot id means
 * the old core is gone: before anything of the new core opens, every
 * deferred DHT reply is cancelled (nodus_dht_cancel_deferred), every shadow
 * is closed and every origin connection of the old core is closed (S5b fix
 * round F5). Within one boot id a preface replaces a slot's live
 * connection only when its generation is newer.
 *
 * Determinism: nothing here reaches consensus state — the storage process
 * is DHT only; its clocks schedule this node's own pushes and sweeps.
 *
 * @file nodus_dht_ipc.h
 */

#ifndef NODUS_DHT_IPC_H
#define NODUS_DHT_IPC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "nodus/nodus_types.h"
#include "dht/nodus_dht.h"

#ifdef __cplusplus
extern "C" {
#endif

/** The socket file, under the node's data_path. */
#define NODUS_DHT_IPC_SOCK_NAME      "storage.sock"

/** The preface version both ends speak ("v"). */
#define NODUS_DHT_IPC_VERSION        1

/** Frame methods ("q"). */
#define NODUS_DHT_IPC_Q_ORIGIN       "ds_origin"
#define NODUS_DHT_IPC_Q_CTL          "ds_ctl"
#define NODUS_DHT_IPC_Q_UDP_IN       "ds_udp"
#define NODUS_DHT_IPC_Q_SEEN         "ds_seen"
#define NODUS_DHT_IPC_Q_DEAD         "ds_dead"
#define NODUS_DHT_IPC_Q_MEMBERS      "ds_mbr"
#define NODUS_DHT_IPC_Q_UDP_OUT      "ds_udps"
#define NODUS_DHT_IPC_Q_ROUTING      "ds_rt"

#define NODUS_DHT_IPC_BOOT_LEN       8

/** Cluster members in a membership snapshot (NODUS_CLUSTER_MAX_PEERS;
 *  core asserts the two are equal). */
#define NODUS_DHT_IPC_MEMBERS_MAX    16

/** Routing peers in a routing snapshot: the whole table
 *  (NODUS_BUCKETS × NODUS_K, the presence tick's PRESENCE_MAX_PEERS). */
#define NODUS_DHT_IPC_ROUTING_MAX    (NODUS_BUCKETS * NODUS_K)

/** A snapshot is re-sent at least this often, changed or not (decisions
 *  17 and 27: "on change / at most 30 s"); a change is looked for every
 *  NODUS_DHT_IPC_SNAPSHOT_CHECK_MS. */
#define NODUS_DHT_IPC_SNAPSHOT_MAX_SEC   30
#define NODUS_DHT_IPC_SNAPSHOT_CHECK_MS  1000

/*
 * Queue bounds (the S3 rules, witness/nodus_witness_ipc.h). "Queued" = the
 * bytes a connection has for its peer that the kernel has not yet taken
 * (wlen - wpos + pending_bytes). Each bound is checked BEFORE a frame is
 * queued, so one frame of the transport's largest size still goes onto an
 * idle connection.
 *
 * Core → storage, per origin connection: NODUS_DHT_IPC_QUEUE_MAX (4 MiB). A
 * client request past it is answered NODUS_DHT_NO_STORAGE_MSG and not
 * queued; a 4002 frame past it is dropped (logged). The connection stays.
 *
 * Storage → core, per origin connection: NODUS_DHT_IPC_REPLY_QUEUE_MAX
 * (16 MiB) — covers a batch-forward result (NODUS_MAX_VALUE_SIZE + 64 KiB)
 * and get_all pages between two core reads. A reply or push to an origin
 * connection at that bound is not queued and the connection is closed (at
 * the end of that poll pass); core then closes that client session
 * (decision item 32) — its listen keys went with the shadow, and the client
 * is told by its reconnect, never silently. The same holds for ANY reply
 * or push the transport could not take — a failed send, or a frame its
 * pending-full hook reports lost (many small frames reach the transport's
 * own ceiling — ~5 MiB write buffer + NODUS_PENDING_MAX_FRAMES queued
 * frames — before 16 MiB): S5b fix round F1.
 *
 * Control connection, either direction: NODUS_DHT_IPC_CTL_QUEUE_MAX. Never
 * a close; see the file comment.
 */
#define NODUS_DHT_IPC_QUEUE_MAX        ((size_t)4 * 1024 * 1024)
#define NODUS_DHT_IPC_REPLY_QUEUE_MAX  ((size_t)16 * 1024 * 1024)
#define NODUS_DHT_IPC_CTL_QUEUE_MAX    ((size_t)4 * 1024 * 1024)

/**
 * The socket path for `data_path` ("/tmp" when empty — where the DHT puts
 * its databases then). @return 0, or -1 when it does not fit `cap`.
 */
static inline int nodus_dht_ipc_sock_path(const char *data_path,
                                          char *out, size_t cap) {
    int n = snprintf(out, cap, "%s/%s",
                     (data_path && data_path[0]) ? data_path : "/tmp",
                     NODUS_DHT_IPC_SOCK_NAME);
    return (n < 0 || (size_t)n >= cap) ? -1 : 0;
}

/* ── The frames (nodus_dht_ipc_wire.c — both ends link it) ─────────── */

/** One cluster member of a membership snapshot. */
typedef struct {
    nodus_key_t node_id;
    uint64_t    offline_secs;   /* nodus_cluster_peer_offline_secs at push */
} nodus_dht_ipc_member_t;

/** An origin connection's preface. */
typedef struct {
    nodus_dht_origin_t origin;                  /* kind, slot, generation */
    uint8_t            boot[NODUS_DHT_IPC_BOOT_LEN];
    nodus_key_t        fp;      /* CLIENT: the session's identity;
                                 * INTER: the peer's (zero when none) */
    nodus_pubkey_t     pk;      /* CLIENT only */
    char               ip[64];  /* INTER only: the peer conn's address */
} nodus_dht_ipc_preface_t;

typedef enum {
    NODUS_DHT_IPC_MSG_INVALID = 0,
    NODUS_DHT_IPC_MSG_ORIGIN,
    NODUS_DHT_IPC_MSG_CTL,
    NODUS_DHT_IPC_MSG_UDP_IN,
    NODUS_DHT_IPC_MSG_SEEN,
    NODUS_DHT_IPC_MSG_DEAD,
    NODUS_DHT_IPC_MSG_MEMBERS,
    NODUS_DHT_IPC_MSG_UDP_OUT,
    NODUS_DHT_IPC_MSG_ROUTING
} nodus_dht_ipc_msg_type_t;

/** One decoded control-plane frame. `payload` points INTO the decoded
 *  buffer (valid while it is). A routing snapshot is written to the
 *  caller's buffer given to nodus_dht_ipc_decode. */
typedef struct {
    nodus_dht_ipc_msg_type_t type;
    nodus_dht_ipc_preface_t  preface;                       /* ORIGIN */
    uint8_t                  boot[NODUS_DHT_IPC_BOOT_LEN];  /* CTL */
    /* UDP_IN / UDP_OUT */
    char                     ip[64];
    uint16_t                 port;
    const uint8_t           *payload;
    size_t                   payload_len;
    /* SEEN / DEAD (ip, port above: ip and udp port of SEEN) */
    nodus_dht_peer_seen_t    seen_kind;
    nodus_key_t              node_id;
    uint16_t                 tcp_port;
    /* MEMBERS */
    nodus_dht_ipc_member_t   members[NODUS_DHT_IPC_MEMBERS_MAX];
    int                      member_count;
    /* ROUTING (written to the caller's buffer) */
    int                      routing_count;
} nodus_dht_ipc_msg_t;

/**
 * Decode one IPC control-plane frame (a preface or a control message).
 * Strict: a CBOR map with exactly the keys of its "q", each once, of its
 * type and size; no trailing bytes; a preface of another "v" is refused.
 * `rt` / `rt_max`: where a routing snapshot's peers go (NULL / 0 refuses
 * one; more than `rt_max` peers refuses it).
 * @return 0 and `out` set; -1 refused (`out->type` INVALID).
 */
int nodus_dht_ipc_decode(const uint8_t *p, size_t len, nodus_dht_ipc_msg_t *out,
                         nodus_dht_peer_addr_t *rt, int rt_max);

/** Encoders. Each writes one frame payload into `buf` and returns its
 *  length, or 0 when it does not fit `cap` (nothing to send). */
size_t nodus_dht_ipc_encode_origin(const nodus_dht_ipc_preface_t *pf,
                                   uint8_t *buf, size_t cap);
size_t nodus_dht_ipc_encode_ctl(const uint8_t boot[NODUS_DHT_IPC_BOOT_LEN],
                                uint8_t *buf, size_t cap);
/** `q`: NODUS_DHT_IPC_Q_UDP_IN or NODUS_DHT_IPC_Q_UDP_OUT. */
size_t nodus_dht_ipc_encode_udp(const char *q, const char *ip, uint16_t port,
                                const uint8_t *payload, size_t len,
                                uint8_t *buf, size_t cap);
size_t nodus_dht_ipc_encode_seen(nodus_dht_peer_seen_t kind,
                                 const nodus_key_t *node_id, const char *ip,
                                 uint16_t udp_port, uint16_t tcp_port,
                                 uint8_t *buf, size_t cap);
size_t nodus_dht_ipc_encode_dead(const nodus_key_t *node_id,
                                 uint8_t *buf, size_t cap);
size_t nodus_dht_ipc_encode_members(const nodus_dht_ipc_member_t *m, int n,
                                    uint8_t *buf, size_t cap);
size_t nodus_dht_ipc_encode_routing(const nodus_dht_peer_addr_t *r, int n,
                                    uint8_t *buf, size_t cap);

/** Largest encoded routing snapshot (every peer with a 63-byte ip) — the
 *  buffer an encoder of a full table needs. */
#define NODUS_DHT_IPC_ROUTING_FRAME_MAX \
    ((size_t)64 + (size_t)NODUS_DHT_IPC_ROUTING_MAX * (8 + NODUS_KEY_BYTES + 2 + 63 + 4))

/* ── The storage side (nodus_dht_ipc.c — the nodus-storage process) ── */

typedef struct nodus_dht_ipc nodus_dht_ipc_t;

/**
 * The storage process's IPC runtime: the listener on storage.sock with its
 * origin shadows and the control connection, AND the process's own
 * outbound 4002 pool (decision item 16: replication, republish, hinted
 * handoff, listen forwarding dial from here, on the shared dialer
 * server/nodus_inter_dial.h, pinned — decision 28). `identity` (read only)
 * must outlive it; `require_peer_auth` is the node's setting, so the
 * dialed conns speak the 4002 handshake exactly when core's would.
 * NULL on allocation / transport failure.
 */
nodus_dht_ipc_t *nodus_dht_ipc_new(const nodus_identity_t *identity,
                                   bool require_peer_auth);

/**
 * The DHT's host view in the storage process: send_to_origin writes to the
 * origin's connection (generation-checked); udp_send asks core on the
 * control connection; inter_send is the process's own outbound pool;
 * hint_wanted reads core's last membership snapshot. Fill before
 * nodus_dht_init.
 */
void nodus_dht_ipc_host(nodus_dht_ipc_t *ipc, nodus_dht_host_t *out);

/**
 * Open the storage process's databases (nodus_dht_open) — but FIRST run the
 * partial-wipe boot gate core runs (nodus_server_check_partial_wipe,
 * server/nodus_partial_wipe.h; decision item 9), when `data_path` is set,
 * exactly as nodus_server_init does. nodus_dht_open creates a missing
 * nodus.db / channels.db; without the gate a storage process started
 * before core on a partly wiped host would recreate the file and core's
 * gate would then pass.
 * @return 0 opened; -2 the gate refused (its message printed, NOTHING
 *         opened or created); -1 a database did not open (logged).
 */
int nodus_dht_ipc_open_storage(nodus_dht_t *dht, const char *data_path,
                               const char *self_ip, uint16_t self_peer_port);

/** The DHT this runtime serves (initialised and opened). Before the first
 *  poll. */
void nodus_dht_ipc_attach(nodus_dht_ipc_t *ipc, nodus_dht_t *dht);

/** Open storage.sock (nodus_tcp_unix_listen, this euid only). 0 / -1. */
int nodus_dht_ipc_listen(nodus_dht_ipc_t *ipc, const char *path);

/** One pass of the socket's and the outbound pool's events, waiting up to
 *  `timeout_ms` in the first poll (0 ms while input is pending). */
void nodus_dht_ipc_poll(nodus_dht_ipc_t *ipc, int timeout_ms);

/** The runtime's periodic work, once per loop pass: deferred closes of
 *  origin connections over their reply bound, the routing-snapshot push,
 *  the outbound pool's idle / auth-timeout sweep and its stale-peer
 *  cleanup. */
void nodus_dht_ipc_tick(nodus_dht_ipc_t *ipc);

/** true while either transport has input left on its pending-read list. */
bool nodus_dht_ipc_read_pending(const nodus_dht_ipc_t *ipc);

/** Close every connection and the socket (its file is removed), free. */
void nodus_dht_ipc_free(nodus_dht_ipc_t *ipc);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_DHT_IPC_H */
