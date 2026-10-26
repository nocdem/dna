/**
 * Nodus — Witness IPC (the nodus-witness process's local socket)
 *
 * Component split S3: the listener side of <data_path>/witness.sock. The
 * frame formats and connection kinds are documented in nodus_witness_ipc.h;
 * the core side is server/nodus_chain_backend_ipc.c.
 *
 * Its own nodus_tcp_t (never the client or the inter-node pool), one
 * connection kind per slot of that pool, decided by the connection's first
 * frame. A session connection carries the client session's identity from
 * its preface onto the connection itself (peer_pk / peer_id /
 * peer_id_set), because the witness's dnac handlers read the requester
 * from `conn` exactly as they do on a client connection in the combined
 * binary (nodus_auth.c sets the same three fields there).
 *
 * Bound: a connection whose own queue toward core has reached
 * NODUS_WITNESS_IPC_REPLY_QUEUE_MAX is closed on its next frame instead of
 * dispatching it (ipc_on_frame) — the witness's memory per connection
 * stays bounded when core stops reading, and nothing here ever waits.
 *
 * @file nodus_witness_ipc.c
 */

#include "witness/nodus_witness_ipc.h"
#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"          /* nodus_witness_block_height */
#include "witness/nodus_witness_p2p.h"         /* nodus_witness_p2p_listen_port */
#include "witness/nodus_witness_v2_apply.h"    /* nodus_witness_v2_committed_global_root (W4-H),
                                                * nodus_witness_v2_tip_block_time */
#include "witness/nodus_witness_v2_produce.h"  /* nodus_witness_v2_tip_height */
#include "witness/nodus_witness_v2_storage.h"  /* nodus_witness_storage_set_get */
#include "witness/nodus_witness_cmt_node.h"    /* nodus_cmt_node_t.cs_started */
#include "witness/nodus_witness_v2_claims.h"   /* nodus_witness_v2_chain_id */
#include "dnac/dnac.h"                         /* DNAC_EPOCH_LENGTH, dnac_name_bytes_ok */
#include "transport/nodus_tcp.h"
#include "protocol/nodus_cbor.h"
#include "protocol/nodus_tier2.h"
#include "crypto/nodus_sign.h"                 /* nodus_fingerprint */
#include "crypto/utils/qgp_log.h"

#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>

#define LOG_TAG "WITNESS_IPC"

/* Frames one IPC connection may hand the witness per poll pass (the
 * transport's read_budget_frames): one session socket cannot take a whole
 * pass. A count only — no clock on the witness side. */
#define NODUS_WITNESS_IPC_READ_BUDGET_FRAMES  8

/* ── Status (shared with the in-process backend) ─────────────────── */

void nodus_witness_status_fill(nodus_witness_t *w,
                               nodus_t2_status_info_t *info) {
    if (!w->db) return;
    info->block_height = nodus_witness_block_height(w);
    if (w->v2_successor) {
        /* R3 W4 package H: on a version-3 chain the legacy cached
         * state root is never written (the Comet apply lane keeps
         * no `blocks` row), so the column was EMPTY while HEIGHT
         * already reported the `v2_blocks` tip. Report the committed
         * GLOBAL ROOT of that tip instead — the row the engine wrote
         * (`nodus_witness_v2_committed_global_root`: the authority is
         * the stored `v2_blocks.global_root`, never a recompute), the
         * same quantity `stagef_cmt_diff_at_floor` compares across
         * nodes. A chain with no committed row yet leaves it zero. */
        if (nodus_witness_v2_committed_global_root(w,
                                                   info->state_root) != 0) {
            memset(info->state_root, 0, sizeof(info->state_root));
        }
    }
    /* Root-layout round (K3): the legacy `else` branch that copied
     * `cached_state_root` is deleted with that field (it had no
     * writer); a non-successor witness reports the zeroed
     * state_root from the caller's memset, as it already did. */
    memcpy(info->chain_id, w->chain_id, 32);
}

/* ── ipc_dht answers (DHT v2 design rev 5 §13 row 13) ────────────── */

/* The last epoch boundary H the committed tip has passed — the boundary
 * whose frozen storage_set(H) governs the epoch (H, H+E] the tip lies in.
 * The same expression as handlers.c st_epoch_set (`*H_out = tip − tip %
 * E`, dnac_storage_status "es"); 0 = no boundary yet. */
static uint64_t dht_epoch_start(uint64_t tip) {
    const uint64_t E = (uint64_t)DNAC_EPOCH_LENGTH;
    return tip - tip % E;
}

/* The chain id every DHT v2 reader and every session compares: the 32-byte
 * v3 chain id (the hash of the stored genesis document,
 * nodus_witness_v2_chain_id — what 4004's HELLO carries and what every
 * client / ceremony / explorer knows), NOT `w->chain_id`, the legacy 16-byte
 * id padded with zeros that the T2 `status` RPC reports. No v3 id yet (no
 * open chain, no stored genesis document) is an error, never a zero id. */
int nodus_witness_dht_chain_id(nodus_witness_t *w, uint8_t out[32]) {
    _Static_assert(DNA_CHAIN_ID_LEN == 32, "the session's chain id is 32 bytes");
    if (!w || !out || !w->db) return -1;
    return nodus_witness_v2_chain_id(w, out) == 0 ? 0 : -1;
}

int nodus_witness_dht_snap_fill(nodus_witness_t *w,
                                nodus_witness_dht_snap_t *out) {
    uint64_t tip = 0, secs = 0;

    if (!w || !out || !w->db) return -1;
    memset(out, 0, sizeof(*out));
    if (nodus_witness_v2_tip_height(w, &tip) != 0) return -1;
    /* all-or-error: a tip without readable block meta has no time */
    if (nodus_witness_v2_tip_block_time(w, tip, &secs) != 0) return -1;
    if (nodus_witness_dht_chain_id(w, out->chain_id) != 0) {
        memset(out, 0, sizeof(*out));
        return -1;
    }
    out->height = tip;
    out->tip_time = secs;
    /* `cs_started` is set exactly when cmt_cs_start has run (directly at
     * start, or at the block-sync switch — nodus_witness_cmt_node.h) and
     * cleared only on release: the row's latch. The same read as
     * handlers.c duty_sync_read. */
    out->consensus_up = w->cmt_live && w->cmt_node != NULL &&
        ((const nodus_cmt_node_t *)w->cmt_node)->cs_started;
    out->epoch_start = dht_epoch_start(tip);
    return 0;
}

/* The registry rows ACTIVE and EXITING, node_fp ASC. @return 0 / -1. */
static int dht_registry_rows(nodus_witness_t *w,
                             nodus_witness_dht_sets_t *out) {
    sqlite3_stmt *st = NULL;
    int rc, ret = 0;

    out->nrg = 0;
    if (sqlite3_prepare_v2(w->db,
            "SELECT node_fp, status FROM v2_storage_nodes "
            "WHERE status IN (?1, ?2) ORDER BY node_fp ASC",
            -1, &st, NULL) != SQLITE_OK) {
        sqlite3_finalize(st);
        return -1;
    }
    if (sqlite3_bind_int(st, 1, DNA_V2_STORAGE_ACTIVE) != SQLITE_OK ||
        sqlite3_bind_int(st, 2, DNA_V2_STORAGE_EXITING) != SQLITE_OK) {
        sqlite3_finalize(st);
        return -1;
    }
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        int sv = sqlite3_column_int(st, 1);
        if (out->nrg >= DNA_V2_STORAGE_SET_MAX ||
            sqlite3_column_type(st, 0) != SQLITE_BLOB ||
            sqlite3_column_bytes(st, 0) != 64 ||
            sqlite3_column_blob(st, 0) == NULL ||
            (sv != DNA_V2_STORAGE_ACTIVE && sv != DNA_V2_STORAGE_EXITING)) {
            ret = -1;          /* malformed row / more live rows than the cap */
            break;
        }
        memcpy(out->rg[out->nrg].fp, sqlite3_column_blob(st, 0), 64);
        out->rg[out->nrg].status = (uint8_t)sv;
        out->nrg++;
    }
    if (ret == 0 && rc != SQLITE_DONE) ret = -1;
    sqlite3_finalize(st);
    return ret;
}

/* S(H) into out_fps. A set that is absent (1) or unreadable / fails its
 * hash check (-1) is a fault for the caller. */
static int dht_set_members(nodus_witness_t *w, uint64_t H,
                           uint8_t fps[][64], uint32_t *n_out) {
    nodus_storage_set_t *set = calloc(1, sizeof(*set));
    int ret = -1;

    if (!set) return -1;
    if (nodus_witness_storage_set_get(w, H, set) == 0 &&
        set->count <= DNA_V2_STORAGE_SET_MAX) {
        memcpy(fps, set->fps, (size_t)set->count * 64);
        *n_out = set->count;
        ret = 0;
    }
    free(set);
    return ret;
}

int nodus_witness_dht_sets_fill(nodus_witness_t *w,
                                nodus_witness_dht_sets_t *out) {
    const uint64_t E = (uint64_t)DNAC_EPOCH_LENGTH;
    uint64_t tip = 0;

    if (!w || !out || !w->db) return -1;
    memset(out, 0, sizeof(*out));
    if (nodus_witness_v2_tip_height(w, &tip) != 0) return -1;
    out->e = dht_epoch_start(tip);
    if (out->e > 0) {
        if (dht_set_members(w, out->e, out->s0, &out->n0) != 0) return -1;
        if (out->e > E &&
            dht_set_members(w, out->e - E, out->s1, &out->n1) != 0)
            return -1;
    }
    if (dht_registry_rows(w, out) != 0) return -1;
    return 0;
}

int nodus_witness_dht_name_fill(nodus_witness_t *w, const uint8_t fp[64],
                                nodus_witness_dht_name_t *out) {
    uint64_t tip = 0;
    sqlite3_stmt *st = NULL;
    bool named = false;
    int ok = 0;

    if (!w || !fp || !out || !w->db) return -1;
    memset(out, 0, sizeof(*out));
    if (nodus_witness_v2_tip_height(w, &tip) != 0) return -1;
    /* handle_dnac_name_of's lookup (nodus_witness_handlers.c): no row =
     * absent; a row that fails the byte rule is a fault, never "absent". */
    if (sqlite3_prepare_v2(w->db,
            "SELECT name, registered_height FROM v2_names WHERE owner = ?1",
            -1, &st, NULL) == SQLITE_OK &&
        sqlite3_bind_blob(st, 1, fp, 64, SQLITE_TRANSIENT) == SQLITE_OK) {
        int rc = sqlite3_step(st);
        if (rc == SQLITE_DONE) {
            ok = 1;
        } else if (rc == SQLITE_ROW) {
            int nl = sqlite3_column_bytes(st, 0);
            const uint8_t *nm = sqlite3_column_blob(st, 0);
            if (nm && dnac_name_bytes_ok(nm, (size_t)nl) &&
                sqlite3_column_int64(st, 1) >= 1) {
                named = true;
                ok = 1;
            }
        }
    }
    sqlite3_finalize(st);
    if (!ok) return -1;
    out->height = tip;
    out->named = named;
    return 0;
}

/* ── Handlers bound to a witness ─────────────────────────────────── */

static void witness_h_dispatch_dnac(void *ctx, nodus_tcp_conn_t *conn,
                                    const uint8_t *payload, size_t len,
                                    const char *method, uint32_t txn_id) {
    nodus_witness_dispatch_dnac((nodus_witness_t *)ctx, conn, payload, len,
                                method, txn_id);
}

static void witness_h_cc_collect(void *ctx, nodus_tcp_conn_t *conn,
                                 const uint8_t client_pk[NODUS_PK_BYTES],
                                 const uint8_t token[NODUS_SESSION_TOKEN_LEN],
                                 const uint8_t *payload, size_t len,
                                 uint32_t txn_id) {
    nodus_witness_handle_cc_collect((nodus_witness_t *)ctx, conn, client_pk,
                                    token, payload, len, txn_id);
}

static void witness_h_status(void *ctx, nodus_witness_ipc_status_t *out) {
    nodus_witness_t *w = (nodus_witness_t *)ctx;
    nodus_t2_status_info_t info;

    memset(&info, 0, sizeof(info));
    nodus_witness_status_fill(w, &info);
    memset(out, 0, sizeof(*out));
    out->chain_open = w->db != NULL;
    out->height = info.block_height;
    memcpy(out->state_root, info.state_root, sizeof(out->state_root));
    memcpy(out->chain_id, info.chain_id, sizeof(out->chain_id));
    if (nodus_witness_dht_chain_id(w, out->chain_id_v3) != 0)
        memset(out->chain_id_v3, 0, sizeof(out->chain_id_v3));
    out->p2p_opened = w->p2p != NULL;
    out->listen_port = nodus_witness_p2p_listen_port(w->p2p);
}

static int witness_h_dht_snap(void *ctx, nodus_witness_dht_snap_t *out) {
    return nodus_witness_dht_snap_fill((nodus_witness_t *)ctx, out);
}

static int witness_h_dht_sets(void *ctx, nodus_witness_dht_sets_t *out) {
    return nodus_witness_dht_sets_fill((nodus_witness_t *)ctx, out);
}

static int witness_h_dht_name(void *ctx, const uint8_t fp[64],
                              nodus_witness_dht_name_t *out) {
    return nodus_witness_dht_name_fill((nodus_witness_t *)ctx, fp, out);
}

static int witness_h_roles(void *ctx, uint8_t (*fps)[64], uint32_t max,
                           uint32_t *n) {
    nodus_witness_t *w = (nodus_witness_t *)ctx;
    return w->p2p ? nodus_witness_p2p_roles_fill(w->p2p, fps, max, n) : -1;
}

void nodus_witness_ipc_handlers_for(nodus_witness_t *w,
                                    nodus_witness_ipc_handlers_t *out) {
    memset(out, 0, sizeof(*out));
    out->roles         = witness_h_roles;
    out->dispatch_dnac = witness_h_dispatch_dnac;
    out->cc_collect    = witness_h_cc_collect;
    out->status        = witness_h_status;
    out->dht_snap      = witness_h_dht_snap;
    out->dht_sets      = witness_h_dht_sets;
    out->dht_name      = witness_h_dht_name;
    out->ctx           = w;
}

/* ── The listener ────────────────────────────────────────────────── */

typedef enum {
    IPC_KIND_NONE = 0,      /* accepted, first frame not seen yet */
    IPC_KIND_SESSION,       /* ipc_hello: one core client session */
    IPC_KIND_CTL,           /* ipc_ctl: core's control connection */
    IPC_KIND_DHT            /* ipc_dht: nodus-storage's chain view (row 13) */
} ipc_kind_t;

typedef struct {
    ipc_kind_t  kind;
    uint8_t     token[NODUS_SESSION_TOKEN_LEN];
    uint8_t     pk[NODUS_PK_BYTES];
} ipc_slot_t;

struct nodus_witness_ipc {
    nodus_tcp_t                   tcp;
    nodus_witness_ipc_handlers_t  h;
    /* Indexed by conn->slot of `tcp` (its pool index). */
    ipc_slot_t                    slots[NODUS_TCP_MAX_CONNS];
};

static ipc_slot_t *ipc_slot(nodus_witness_ipc_t *ipc, nodus_tcp_conn_t *conn) {
    if (!conn || conn->slot < 0 || conn->slot >= NODUS_TCP_MAX_CONNS)
        return NULL;
    return &ipc->slots[conn->slot];
}

static void ipc_slot_reset(ipc_slot_t *s) {
    memset(s, 0, sizeof(*s));
}

/* Parse a control-plane frame: a CBOR map of at most three entries with
 * "q" (text) and, for ipc_hello, "pk" and "tk" (byte strings of exactly
 * their sizes). Any other key, a repeated key, a wrong type or size, or
 * trailing bytes refuse the frame.
 * @return 0 and `q` (NUL-terminated) set; -1 refused. */
static int ipc_parse_ctl(const uint8_t *p, size_t len,
                         char q[32], bool *has_pk, uint8_t pk[NODUS_PK_BYTES],
                         bool *has_tk,
                         uint8_t tk[NODUS_SESSION_TOKEN_LEN]) {
    cbor_decoder_t dec;
    cbor_decoder_init(&dec, p, len);

    cbor_item_t m = cbor_decode_next(&dec);
    if (m.type != CBOR_ITEM_MAP || m.count == 0 || m.count > 3) return -1;

    bool has_q = false;
    *has_pk = false;
    *has_tk = false;
    for (size_t i = 0; i < m.count; i++) {
        cbor_item_t k = cbor_decode_next(&dec);
        if (k.type != CBOR_ITEM_TSTR) return -1;
        cbor_item_t v = cbor_decode_next(&dec);
        if (k.tstr.len == 1 && memcmp(k.tstr.ptr, "q", 1) == 0) {
            if (has_q || v.type != CBOR_ITEM_TSTR || v.tstr.len >= 32)
                return -1;
            memcpy(q, v.tstr.ptr, v.tstr.len);
            q[v.tstr.len] = '\0';
            has_q = true;
        } else if (k.tstr.len == 2 && memcmp(k.tstr.ptr, "pk", 2) == 0) {
            if (*has_pk || v.type != CBOR_ITEM_BSTR ||
                v.bstr.len != NODUS_PK_BYTES)
                return -1;
            memcpy(pk, v.bstr.ptr, NODUS_PK_BYTES);
            *has_pk = true;
        } else if (k.tstr.len == 2 && memcmp(k.tstr.ptr, "tk", 2) == 0) {
            if (*has_tk || v.type != CBOR_ITEM_BSTR ||
                v.bstr.len != NODUS_SESSION_TOKEN_LEN)
                return -1;
            memcpy(tk, v.bstr.ptr, NODUS_SESSION_TOKEN_LEN);
            *has_tk = true;
        } else {
            return -1;
        }
    }
    if (dec.error || dec.pos != len || !has_q) return -1;
    return 0;
}

static void ipc_refuse(nodus_witness_ipc_t *ipc, nodus_tcp_conn_t *conn,
                       const char *why) {
    QGP_LOG_WARN(LOG_TAG, "closing IPC connection slot=%d: %s",
                 conn->slot, why);
    nodus_tcp_disconnect(&ipc->tcp, conn);
}

static void ipc_on_first_frame(nodus_witness_ipc_t *ipc, ipc_slot_t *s,
                               nodus_tcp_conn_t *conn,
                               const uint8_t *payload, size_t len) {
    char q[32];
    bool has_pk = false, has_tk = false;
    uint8_t pk[NODUS_PK_BYTES];
    uint8_t tk[NODUS_SESSION_TOKEN_LEN];

    if (ipc_parse_ctl(payload, len, q, &has_pk, pk, &has_tk, tk) != 0) {
        ipc_refuse(ipc, conn, "first frame is not an IPC preface");
        return;
    }
    if (strcmp(q, NODUS_WITNESS_IPC_Q_HELLO) == 0 && has_pk && has_tk) {
        nodus_pubkey_t pub;
        nodus_key_t fp;

        memcpy(pub.bytes, pk, NODUS_PK_BYTES);
        if (nodus_fingerprint(&pub, &fp) != 0) {
            ipc_refuse(ipc, conn, "preface key has no fingerprint");
            return;
        }
        s->kind = IPC_KIND_SESSION;
        memcpy(s->pk, pk, NODUS_PK_BYTES);
        memcpy(s->token, tk, NODUS_SESSION_TOKEN_LEN);
        /* The requester, on the connection, as nodus_auth.c records it
         * on a client connection after AUTH. */
        conn->peer_pk = pub;
        conn->peer_id = fp;
        conn->peer_id_set = true;
        return;
    }
    if (strcmp(q, NODUS_WITNESS_IPC_Q_CTL) == 0 && !has_pk && !has_tk) {
        s->kind = IPC_KIND_CTL;
        return;
    }
    if (strcmp(q, NODUS_WITNESS_IPC_Q_DHT) == 0 && !has_pk && !has_tk) {
        s->kind = IPC_KIND_DHT;
        /* its requests are tiny: the transport refuses a larger frame
         * header before buffering any of the payload */
        conn->max_payload = NODUS_WITNESS_IPC_CTL_FRAME_MAX;
        return;
    }
    ipc_refuse(ipc, conn, "first frame is not ipc_hello, ipc_ctl or "
               "ipc_dht");
}

static void ipc_on_session_frame(nodus_witness_ipc_t *ipc, ipc_slot_t *s,
                                 nodus_tcp_conn_t *conn,
                                 const uint8_t *payload, size_t len) {
    nodus_tier2_msg_t msg;
    memset(&msg, 0, sizeof(msg));

    /* The decoder the server's dispatch_t2 uses. Core forwards only
     * frames that decoded there, with this session's token. */
    if (nodus_t2_decode(payload, len, &msg) != 0) {
        nodus_t2_msg_free(&msg);
        ipc_refuse(ipc, conn, "session frame does not decode");
        return;
    }
    /* No token check: the token is a correlation key, never an authorization
     * input (Kurultay #43 O-2 b). The identity is this IPC session (its
     * preface, s->pk); s->token stays for correlation (cc_collect below). */
    if (strcmp(msg.method, "dnac_cc_collect") == 0) {
        ipc->h.cc_collect(ipc->h.ctx, conn, s->pk, s->token,
                          payload, len, msg.txn_id);
    } else if (nodus_chain_method_routed(msg.method)) {
        /* dnac_* and the Nodus EVM evm_* read RPC (nodus_witness_ipc.h) */
        ipc->h.dispatch_dnac(ipc->h.ctx, conn, payload, len,
                             msg.method, msg.txn_id);
    } else {
        nodus_t2_msg_free(&msg);
        ipc_refuse(ipc, conn, "session frame is not a dnac_* / evm_* "
                   "method");
        return;
    }
    nodus_t2_msg_free(&msg);
}

/* {"q":"ipc_roles","fp":<n*64 bytes>} or {"q":"ipc_roles","err":why}: the
 * active-role set for core's per-IP exemption. A handler that is not bound
 * closes the asker (like the dht_* callbacks). */
static void ipc_answer_roles(nodus_witness_ipc_t *ipc, nodus_tcp_conn_t *conn) {
    if (!ipc->h.roles) {
        ipc_refuse(ipc, conn, "ipc_roles has no handler");
        return;
    }
    uint8_t (*fps)[64] = malloc((size_t)NODUS_WITNESS_IPC_ROLES_MAX * 64);
    uint32_t n = 0;
    size_t cap = (size_t)NODUS_WITNESS_IPC_ROLES_MAX * 64 + 64;
    uint8_t *buf = malloc(cap);
    if (!fps || !buf) {
        free(fps);
        free(buf);
        return;
    }
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    cbor_encode_map(&enc, 2);
    cbor_encode_cstr(&enc, "q"); cbor_encode_cstr(&enc, NODUS_WITNESS_IPC_Q_ROLES);
    if (ipc->h.roles(ipc->h.ctx, fps, NODUS_WITNESS_IPC_ROLES_MAX, &n) == 0) {
        cbor_encode_cstr(&enc, "fp"); cbor_encode_bstr(&enc, (const uint8_t *)fps, (size_t)n * 64);
    } else {
        cbor_encode_cstr(&enc, "err"); cbor_encode_cstr(&enc, "roles unavailable");
    }
    size_t len = cbor_encoder_len(&enc);
    if (len > 0)
        nodus_tcp_send(conn, buf, len);
    free(fps);
    free(buf);
}

static void ipc_on_ctl_frame(nodus_witness_ipc_t *ipc, nodus_tcp_conn_t *conn,
                             const uint8_t *payload, size_t len) {
    char q[32];
    bool has_pk = false, has_tk = false;
    uint8_t pk[NODUS_PK_BYTES];
    uint8_t tk[NODUS_SESSION_TOKEN_LEN];

    if (ipc_parse_ctl(payload, len, q, &has_pk, pk, &has_tk, tk) == 0 &&
        strcmp(q, NODUS_WITNESS_IPC_Q_ROLES) == 0 && !has_pk && !has_tk) {
        ipc_answer_roles(ipc, conn);
        return;
    }
    if (ipc_parse_ctl(payload, len, q, &has_pk, pk, &has_tk, tk) != 0 ||
        strcmp(q, NODUS_WITNESS_IPC_Q_STATUS) != 0 || has_pk || has_tk) {
        ipc_refuse(ipc, conn, "control frame is not ipc_status or ipc_roles");
        return;
    }

    nodus_witness_ipc_status_t st;
    memset(&st, 0, sizeof(st));
    ipc->h.status(ipc->h.ctx, &st);

    uint8_t buf[NODUS_WITNESS_IPC_CTL_FRAME_MAX];
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, sizeof(buf));
    cbor_encode_map(&enc, 8);
    cbor_encode_cstr(&enc, "q");  cbor_encode_cstr(&enc, NODUS_WITNESS_IPC_Q_STATUS);
    cbor_encode_cstr(&enc, "co"); cbor_encode_bool(&enc, st.chain_open);
    cbor_encode_cstr(&enc, "h");  cbor_encode_uint(&enc, st.height);
    cbor_encode_cstr(&enc, "sr"); cbor_encode_bstr(&enc, st.state_root,
                                                   sizeof(st.state_root));
    cbor_encode_cstr(&enc, "ci"); cbor_encode_bstr(&enc, st.chain_id,
                                                   sizeof(st.chain_id));
    cbor_encode_cstr(&enc, "c3"); cbor_encode_bstr(&enc, st.chain_id_v3,
                                                   sizeof(st.chain_id_v3));
    cbor_encode_cstr(&enc, "po"); cbor_encode_bool(&enc, st.p2p_opened);
    cbor_encode_cstr(&enc, "lp"); cbor_encode_uint(&enc, st.listen_port);
    size_t n = cbor_encoder_len(&enc);
    if (n == 0) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "ipc_status answer does not fit its "
                      "buffer");
        return;
    }
    nodus_tcp_send(conn, buf, n);
}

/* ── The `ipc_dht` kind (row 13) ─────────────────────────────────── */

/* Parse an ipc_dht request: a CBOR map of one entry "q" (text) or, for
 * ipc_name, two entries "q" and "fp" (a byte string of exactly 64). Any
 * other key, a repeat, a wrong type or size, or trailing bytes refuse it.
 * @return 0 and `q` (NUL-terminated), `has_fp`, `fp` set; -1 refused. */
static int ipc_parse_dht(const uint8_t *p, size_t len, char q[32],
                         bool *has_fp, uint8_t fp[64]) {
    cbor_decoder_t dec;
    cbor_decoder_init(&dec, p, len);

    cbor_item_t m = cbor_decode_next(&dec);
    if (m.type != CBOR_ITEM_MAP || m.count == 0 || m.count > 2) return -1;

    bool has_q = false;
    *has_fp = false;
    for (size_t i = 0; i < m.count; i++) {
        cbor_item_t k = cbor_decode_next(&dec);
        if (k.type != CBOR_ITEM_TSTR) return -1;
        cbor_item_t v = cbor_decode_next(&dec);
        if (k.tstr.len == 1 && memcmp(k.tstr.ptr, "q", 1) == 0) {
            /* a NUL inside the text would end it early under strcmp */
            if (has_q || v.type != CBOR_ITEM_TSTR || v.tstr.len >= 32 ||
                memchr(v.tstr.ptr, '\0', v.tstr.len) != NULL)
                return -1;
            memcpy(q, v.tstr.ptr, v.tstr.len);
            q[v.tstr.len] = '\0';
            has_q = true;
        } else if (k.tstr.len == 2 && memcmp(k.tstr.ptr, "fp", 2) == 0) {
            if (*has_fp || v.type != CBOR_ITEM_BSTR || v.bstr.len != 64)
                return -1;
            memcpy(fp, v.bstr.ptr, 64);
            *has_fp = true;
        } else {
            return -1;
        }
    }
    if (dec.error || dec.pos != len || !has_q) return -1;
    return 0;
}

/* {"q":q,["fp":fp,]"err":why} — the node-local fault answer. */
static void ipc_dht_send_err(nodus_tcp_conn_t *conn, const char *q,
                             const uint8_t *fp, const char *why) {
    uint8_t buf[NODUS_WITNESS_IPC_CTL_FRAME_MAX];
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, sizeof(buf));
    cbor_encode_map(&enc, fp ? 3 : 2);
    cbor_encode_cstr(&enc, "q");   cbor_encode_cstr(&enc, q);
    if (fp) { cbor_encode_cstr(&enc, "fp"); cbor_encode_bstr(&enc, fp, 64); }
    cbor_encode_cstr(&enc, "err"); cbor_encode_cstr(&enc, why);
    size_t n = cbor_encoder_len(&enc);
    if (n > 0) nodus_tcp_send(conn, buf, n);
}

static void ipc_dht_answer_snap(nodus_witness_ipc_t *ipc,
                                nodus_tcp_conn_t *conn) {
    nodus_witness_dht_snap_t sn;
    memset(&sn, 0, sizeof(sn));
    if (ipc->h.dht_snap(ipc->h.ctx, &sn) != 0) {
        ipc_dht_send_err(conn, NODUS_WITNESS_IPC_Q_DHT_SNAP, NULL,
                         "snapshot unavailable");
        return;
    }
    uint8_t buf[NODUS_WITNESS_IPC_CTL_FRAME_MAX];
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, sizeof(buf));
    cbor_encode_map(&enc, 6);
    cbor_encode_cstr(&enc, "q");  cbor_encode_cstr(&enc, NODUS_WITNESS_IPC_Q_DHT_SNAP);
    cbor_encode_cstr(&enc, "ci"); cbor_encode_bstr(&enc, sn.chain_id,
                                                   sizeof(sn.chain_id));
    cbor_encode_cstr(&enc, "h");  cbor_encode_uint(&enc, sn.height);
    cbor_encode_cstr(&enc, "t");  cbor_encode_uint(&enc, sn.tip_time);
    cbor_encode_cstr(&enc, "cu"); cbor_encode_bool(&enc, sn.consensus_up);
    cbor_encode_cstr(&enc, "e");  cbor_encode_uint(&enc, sn.epoch_start);
    size_t n = cbor_encoder_len(&enc);
    if (n == 0) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "ipc_dht_snap answer does not fit its "
                      "buffer");
        ipc_dht_send_err(conn, NODUS_WITNESS_IPC_Q_DHT_SNAP, NULL,
                         "snapshot unavailable");
        return;
    }
    nodus_tcp_send(conn, buf, n);
}

static void ipc_dht_answer_sets(nodus_witness_ipc_t *ipc,
                                nodus_tcp_conn_t *conn) {
    nodus_witness_dht_sets_t *sets = calloc(1, sizeof(*sets));
    uint8_t *buf = malloc(NODUS_WITNESS_IPC_DHT_FRAME_MAX);

    if (!sets || !buf || ipc->h.dht_sets(ipc->h.ctx, sets) != 0 ||
        sets->n0 > DNA_V2_STORAGE_SET_MAX ||
        sets->n1 > DNA_V2_STORAGE_SET_MAX ||
        sets->nrg > DNA_V2_STORAGE_SET_MAX) {
        ipc_dht_send_err(conn, NODUS_WITNESS_IPC_Q_DHT_SETS, NULL,
                         "sets unavailable");
        goto done;
    }
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, NODUS_WITNESS_IPC_DHT_FRAME_MAX);
    cbor_encode_map(&enc, 5);
    cbor_encode_cstr(&enc, "q");  cbor_encode_cstr(&enc, NODUS_WITNESS_IPC_Q_DHT_SETS);
    cbor_encode_cstr(&enc, "e");  cbor_encode_uint(&enc, sets->e);
    cbor_encode_cstr(&enc, "s0"); cbor_encode_array(&enc, sets->n0);
    for (uint32_t i = 0; i < sets->n0; i++)
        cbor_encode_bstr(&enc, sets->s0[i], 64);
    cbor_encode_cstr(&enc, "s1"); cbor_encode_array(&enc, sets->n1);
    for (uint32_t i = 0; i < sets->n1; i++)
        cbor_encode_bstr(&enc, sets->s1[i], 64);
    cbor_encode_cstr(&enc, "rg"); cbor_encode_array(&enc, sets->nrg);
    for (uint32_t i = 0; i < sets->nrg; i++) {
        cbor_encode_map(&enc, 2);
        cbor_encode_cstr(&enc, "f");  cbor_encode_bstr(&enc, sets->rg[i].fp, 64);
        cbor_encode_cstr(&enc, "st"); cbor_encode_uint(&enc, sets->rg[i].status);
    }
    size_t n = cbor_encoder_len(&enc);
    if (n == 0) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "ipc_dht_sets answer does not fit "
                      "NODUS_WITNESS_IPC_DHT_FRAME_MAX");
        ipc_dht_send_err(conn, NODUS_WITNESS_IPC_Q_DHT_SETS, NULL,
                         "sets unavailable");
        goto done;
    }
    nodus_tcp_send(conn, buf, n);
done:
    free(buf);
    free(sets);
}

static void ipc_dht_answer_name(nodus_witness_ipc_t *ipc,
                                nodus_tcp_conn_t *conn, const uint8_t fp[64]) {
    nodus_witness_dht_name_t nm;
    memset(&nm, 0, sizeof(nm));
    if (ipc->h.dht_name(ipc->h.ctx, fp, &nm) != 0) {
        ipc_dht_send_err(conn, NODUS_WITNESS_IPC_Q_NAME, fp,
                         "names store unreadable");
        return;
    }
    uint8_t buf[NODUS_WITNESS_IPC_CTL_FRAME_MAX];
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, sizeof(buf));
    cbor_encode_map(&enc, 4);
    cbor_encode_cstr(&enc, "q");  cbor_encode_cstr(&enc, NODUS_WITNESS_IPC_Q_NAME);
    cbor_encode_cstr(&enc, "fp"); cbor_encode_bstr(&enc, fp, 64);
    cbor_encode_cstr(&enc, "h");  cbor_encode_uint(&enc, nm.height);
    cbor_encode_cstr(&enc, "n");  cbor_encode_uint(&enc, nm.named ? 1u : 0u);
    size_t n = cbor_encoder_len(&enc);
    if (n == 0) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "ipc_name answer does not fit its "
                      "buffer");
        ipc_dht_send_err(conn, NODUS_WITNESS_IPC_Q_NAME, fp,
                         "names store unreadable");
        return;
    }
    nodus_tcp_send(conn, buf, n);
}

static void ipc_on_dht_frame(nodus_witness_ipc_t *ipc, nodus_tcp_conn_t *conn,
                             const uint8_t *payload, size_t len) {
    char q[32];
    bool has_fp = false;
    uint8_t fp[64];

    if (len > NODUS_WITNESS_IPC_CTL_FRAME_MAX ||
        ipc_parse_dht(payload, len, q, &has_fp, fp) != 0) {
        ipc_refuse(ipc, conn, "dht frame is not a well-formed request");
        return;
    }
    if (strcmp(q, NODUS_WITNESS_IPC_Q_DHT_SNAP) == 0 && !has_fp &&
        ipc->h.dht_snap) {
        ipc_dht_answer_snap(ipc, conn);
    } else if (strcmp(q, NODUS_WITNESS_IPC_Q_DHT_SETS) == 0 && !has_fp &&
               ipc->h.dht_sets) {
        ipc_dht_answer_sets(ipc, conn);
    } else if (strcmp(q, NODUS_WITNESS_IPC_Q_NAME) == 0 && has_fp &&
               ipc->h.dht_name) {
        ipc_dht_answer_name(ipc, conn, fp);
    } else {
        ipc_refuse(ipc, conn, "dht frame is not ipc_dht_snap, "
                   "ipc_dht_sets or ipc_name");
    }
}

static void ipc_on_accept(nodus_tcp_conn_t *conn, void *ctx) {
    ipc_slot_t *s = ipc_slot((nodus_witness_ipc_t *)ctx, conn);
    if (s) ipc_slot_reset(s);
}

static void ipc_on_disconnect(nodus_tcp_conn_t *conn, void *ctx) {
    ipc_slot_t *s = ipc_slot((nodus_witness_ipc_t *)ctx, conn);
    if (s) ipc_slot_reset(s);
}

/* Bytes this connection has queued toward core and the kernel has not yet
 * taken (the write buffer's unsent part plus the pending FIFO). */
static size_t ipc_queued_bytes(const nodus_tcp_conn_t *conn) {
    return (conn->wlen - conn->wpos) + conn->pending_bytes;
}

static void ipc_on_frame(nodus_tcp_conn_t *conn, const uint8_t *payload,
                         size_t len, void *ctx) {
    nodus_witness_ipc_t *ipc = (nodus_witness_ipc_t *)ctx;
    ipc_slot_t *s = ipc_slot(ipc, conn);
    if (!s) return;

    /* Bound (NODUS_WITNESS_IPC_REPLY_QUEUE_MAX): core is not reading this
     * connection's replies. Close it rather than dispatch more work that
     * would only grow the queue. Closing is the choice that cannot hold
     * up consensus: it runs here, on this loop, and never waits; the
     * transport has no "stop reading this connection" switch, and leaving
     * frames unread would not shrink the queue either. Core sees the
     * close, forgets the session socket, and its next `dnac_*` dials a
     * new one; what it had forwarded on this one gets no answer (the
     * client times out), as when the witness goes away. */
    if (s->kind != IPC_KIND_NONE &&
        ipc_queued_bytes(conn) >= NODUS_WITNESS_IPC_REPLY_QUEUE_MAX) {
        ipc_refuse(ipc, conn, "its queue to core is over "
                   "NODUS_WITNESS_IPC_REPLY_QUEUE_MAX — core is not "
                   "reading it");
        return;
    }

    switch (s->kind) {
    case IPC_KIND_NONE:
        ipc_on_first_frame(ipc, s, conn, payload, len);
        break;
    case IPC_KIND_SESSION:
        ipc_on_session_frame(ipc, s, conn, payload, len);
        break;
    case IPC_KIND_CTL:
        ipc_on_ctl_frame(ipc, conn, payload, len);
        break;
    case IPC_KIND_DHT:
        ipc_on_dht_frame(ipc, conn, payload, len);
        break;
    }
}

nodus_witness_ipc_t *nodus_witness_ipc_new(const nodus_witness_ipc_handlers_t *h) {
    if (!h || !h->dispatch_dnac || !h->cc_collect || !h->status) return NULL;

    nodus_witness_ipc_t *ipc = calloc(1, sizeof(*ipc));
    if (!ipc) return NULL;
    if (nodus_tcp_init(&ipc->tcp, -1) != 0) {
        free(ipc);
        return NULL;
    }
    ipc->h = *h;
    ipc->tcp.on_accept     = ipc_on_accept;
    ipc->tcp.on_frame      = ipc_on_frame;
    ipc->tcp.on_disconnect = ipc_on_disconnect;
    ipc->tcp.cb_ctx        = ipc;
    ipc->tcp.read_budget_frames = NODUS_WITNESS_IPC_READ_BUDGET_FRAMES;
    return ipc;
}

int nodus_witness_ipc_listen(nodus_witness_ipc_t *ipc, const char *path) {
    if (!ipc || !path) return -1;
    return nodus_tcp_unix_listen(&ipc->tcp, path, NODUS_TCP_UNIX_UID_SELF);
}

void nodus_witness_ipc_poll(nodus_witness_ipc_t *ipc, int timeout_ms) {
    if (!ipc) return;
    nodus_tcp_poll(&ipc->tcp, timeout_ms);
}

nodus_tcp_conn_t *nodus_witness_ipc_find_session_conn(
        void *ctx,
        const uint8_t pk[NODUS_PK_BYTES],
        const uint8_t token[NODUS_SESSION_TOKEN_LEN]) {
    nodus_witness_ipc_t *ipc = (nodus_witness_ipc_t *)ctx;
    if (!ipc || !pk || !token) return NULL;
    for (int i = 0; i < NODUS_TCP_MAX_CONNS; i++) {
        const ipc_slot_t *s = &ipc->slots[i];
        nodus_tcp_conn_t *c = ipc->tcp.pool[i];
        if (s->kind == IPC_KIND_SESSION && c != NULL && !c->close_pending &&
            memcmp(s->token, token, NODUS_SESSION_TOKEN_LEN) == 0 &&
            memcmp(s->pk, pk, NODUS_PK_BYTES) == 0) {
            return c;
        }
    }
    return NULL;
}

void nodus_witness_ipc_free(nodus_witness_ipc_t *ipc) {
    if (!ipc) return;
    nodus_tcp_close(&ipc->tcp);
    free(ipc);
}
