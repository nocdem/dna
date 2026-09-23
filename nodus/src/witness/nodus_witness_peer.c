/**
 * Nodus — Witness Peer Mesh Implementation
 *
 * Manages TCP connections to peer witnesses. Ported from
 * dnac/src/bft/peer.c (552 lines) and dnac/src/bft/roster.c (526 lines).
 *
 * Key adaptations from DNAC:
 *   - No pthreads (reconnection via tick function in epoll loop)
 *   - No global state (all state in nodus_witness_t)
 *   - Connections via nodus_tcp_connect() (dedicated witness TCP port 4004)
 *   - IDENT exchange via Tier 3 CBOR (not custom binary protocol)
 *   - Roster file loading only (DHT persistence not needed — we ARE the DHT)
 */

#include "witness/nodus_witness_peer.h"
#include "witness/nodus_witness_committee.h"   /* Task 59 — committee roster */
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_merkle.h"
#include "protocol/nodus_tier3.h"
#include "protocol/nodus_tier2.h"
#include "server/nodus_server.h"
#include "transport/nodus_tcp.h"
#include "crypto/nodus_sign.h"
#include "protocol/nodus_cbor.h"
#include "core/nodus_storage.h"
#include "core/nodus_value.h"
#include "crypto/utils/qgp_log.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* PR 3 / F4 — mock nodus_version override for H-9 mixed-version
 * harness coverage. When non-zero, w_ident sends this value in place
 * of the real packed (MAJOR<<16|MINOR<<8|PATCH) version. Enables
 * test_bootstrap_mixed_version.sh to bring up 1 fake-old node + 6
 * normal nodes and verify the H-9 exit(3) on a fresh-bootstrap node.
 *
 * Set via the dev-only --mock-nodus-version=N CLI flag (or JSON
 * config key mock_nodus_version); zero / unset means use the real
 * compile-time constants. */
static uint32_t g_mock_nodus_version = 0;

void nodus_witness_peer_set_mock_version(uint32_t packed) {
    g_mock_nodus_version = packed;
}
uint32_t nodus_witness_peer_get_mock_version(void) {
    return g_mock_nodus_version;
}
#include <time.h>

#include "crypto/utils/qgp_safe_string.h"   /* Phase 03: unsafe-string poison guard */

#define LOG_TAG "WITNESS-PEER"

/* Forward declarations */
static int send_rost_q(nodus_witness_t *w, struct nodus_tcp_conn *conn);

/* Reconnect timing */
#define RECONNECT_BASE_SEC   5
#define RECONNECT_MAX_SHIFT  5      /* Max exponential backoff: 2^5 = 32x */

/* ── Roster ──────────────────────────────────────────────────────── */

/* R3 W4 — moved verbatim from nodus_witness_bft.c (deleted with the closed
 * consensus lane, bft.c:1300 and :1353). F17 A4 — roster is transport-only
 * (peer discovery + witness_id<->pubkey map); the committee is the frozen
 * epoch validator set the cometbft application state reads, not derived
 * from this roster. */

int nodus_witness_roster_find(const nodus_witness_roster_t *roster,
                                const uint8_t *witness_id) {
    if (!roster || !witness_id) return -1;

    for (uint32_t i = 0; i < roster->n_witnesses; i++) {
        if (memcmp(roster->witnesses[i].witness_id, witness_id,
                   NODUS_T3_WITNESS_ID_LEN) == 0)
            return (int)i;
    }
    return -1;
}

int nodus_witness_roster_add(nodus_witness_t *w,
                               const nodus_witness_roster_entry_t *entry) {
    if (!w || !entry) return -1;

    if (w->roster.n_witnesses >= NODUS_T3_MAX_WITNESSES)
        return -1;

    /* Duplicate check */
    if (nodus_witness_roster_find(&w->roster, entry->witness_id) >= 0)
        return 0;

    memcpy(&w->roster.witnesses[w->roster.n_witnesses], entry,
           sizeof(nodus_witness_roster_entry_t));
    w->roster.n_witnesses++;
    w->roster.version++;

    /* F17 A4 — roster is now transport-only (peer discovery +
     * witness_id↔pubkey map). The committee is the frozen epoch
     * validator set the cometbft application state reads, not derived
     * from this roster. No my_index tracking needed: self-identity in
     * consensus paths is resolved via w->server->identity.pk against
     * the committee pubkey list. */

    fprintf(stderr, "%s: roster add (now %u witnesses, transport)\n",
            LOG_TAG, w->roster.n_witnesses);
    return 0;
}

/* ── Address parsing ─────────────────────────────────────────────── */

static int parse_address(const char *addr, char *ip_out, size_t ip_cap,
                          uint16_t *port_out) {
    if (!addr || !addr[0]) return -1;

    const char *colon = strrchr(addr, ':');
    if (!colon || colon == addr) return -1;

    size_t ip_len = (size_t)(colon - addr);
    if (ip_len >= ip_cap) return -1;

    memcpy(ip_out, addr, ip_len);
    ip_out[ip_len] = '\0';

    int port = atoi(colon + 1);
    if (port <= 0 || port > 65535) return -1;

    *port_out = (uint16_t)port;
    return 0;
}

/* ── Peer lookup helpers ─────────────────────────────────────────── */

/** Find peer by witness_id. Returns index or -1. */
static int find_peer_by_id(const nodus_witness_t *w,
                            const uint8_t *witness_id) {
    for (int i = 0; i < w->peer_count; i++) {
        if (memcmp(w->peers[i].witness_id, witness_id,
                   NODUS_T3_WITNESS_ID_LEN) == 0)
            return i;
    }
    return -1;
}

/**
 * Find-or-create a peer entry, deduping on witness_id, conn pointer, AND
 * address.  Pass NULL or zero for unknown fields.  Previously each of four
 * call sites did its own (different) dedup, so a seed bootstrap entry with
 * zero witness_id and outbound conn would not get merged when the same
 * peer's w_ident arrived on an inbound conn — broadcast ended up sending
 * to the same logical peer via two slots ("sent=11" with 6 real peers).
 * A single routine matches on whichever identifier is present, in order
 * from strongest to weakest: witness_id → conn → address.
 *
 * Returns peer index (>= 0), or -1 if the table is full.
 *
 * Identifier fields on the matched slot are upgraded from unset to the
 * caller-supplied value.  For conn, an already-live connection wins over
 * a new one to preserve bidirectional broadcast for high-latency peers.
 */
static int witness_peer_upsert(nodus_witness_t *w,
                                 const uint8_t *witness_id,
                                 struct nodus_tcp_conn *conn,
                                 const char *address) {
    if (!w) return -1;

    static const uint8_t zero_id[NODUS_T3_WITNESS_ID_LEN] = {0};
    bool id_valid = witness_id && memcmp(witness_id, zero_id,
                                          NODUS_T3_WITNESS_ID_LEN) != 0;
    bool addr_valid = address && address[0];

    int pi = -1;

    /* 1. Match by witness_id (globally unique identity) */
    if (id_valid) {
        for (int i = 0; i < w->peer_count; i++) {
            if (memcmp(w->peers[i].witness_id, witness_id,
                       NODUS_T3_WITNESS_ID_LEN) == 0) { pi = i; break; }
        }
    }

    /* 2. Match by conn pointer */
    if (pi < 0 && conn) {
        for (int i = 0; i < w->peer_count; i++) {
            if (w->peers[i].conn == conn) { pi = i; break; }
        }
    }

    /* 3. Match by address (logical endpoint — catches seed-bootstrap
     * entries that haven't learned their real witness_id yet) */
    if (pi < 0 && addr_valid) {
        for (int i = 0; i < w->peer_count; i++) {
            if (strcmp(w->peers[i].address, address) == 0) { pi = i; break; }
        }
    }

    /* No match → prefer reusing a dead slot (conn dropped + not
     * identified) before extending peer_count. conn_closed leaves
     * such slots in a recoverable state; without this reuse path the
     * table grows monotonically toward NODUS_T3_MAX_WITNESSES over
     * the node lifetime on NAT-rebind / pre-ident reconnect edge
     * cases. Dedup passes above still match live peers to their
     * existing slot, so reuse only fires for genuinely fresh peers. */
    if (pi < 0) {
        for (int i = 0; i < w->peer_count; i++) {
            if (!w->peers[i].conn && !w->peers[i].identified) {
                pi = i;
                break;
            }
        }
        if (pi < 0) {
            if (w->peer_count >= NODUS_T3_MAX_WITNESSES) return -1;
            pi = w->peer_count++;
        }
        memset(&w->peers[pi], 0, sizeof(w->peers[pi]));
    }

    /* Upgrade fields — only fill what was previously unset, so later
     * partial callers can't stomp authoritative data written earlier. */
    if (id_valid) {
        memcpy(w->peers[pi].witness_id, witness_id,
               NODUS_T3_WITNESS_ID_LEN);
    }
    if (conn) {
        if (!w->peers[pi].conn ||
            w->peers[pi].conn->state != NODUS_CONN_CONNECTED) {
            w->peers[pi].conn = conn;
        }
    }
    if (addr_valid && !w->peers[pi].address[0]) {
        size_t n = strlen(address);
        if (n >= sizeof(w->peers[pi].address))
            n = sizeof(w->peers[pi].address) - 1;
        memcpy(w->peers[pi].address, address, n);
        w->peers[pi].address[n] = '\0';
    }

    return pi;
}

/* ── Ensure peer entry for inbound connection ────────────────────── */

/**
 * Create or update a peer entry for a roster-verified sender arriving
 * on an inbound TCP connection.  This makes the mesh bidirectional:
 * nodes that connected TO us can now also be reached for broadcasts.
 *
 * Rules:
 *  - Skip self
 *  - If peer exists with an active outbound conn, keep it (prefer outbound)
 *  - If peer exists with a dead/null conn, update conn + mark identified
 *  - If peer not found and space available, create new entry from roster
 */
void nodus_witness_peer_ensure(nodus_witness_t *w,
                                const uint8_t *witness_id,
                                struct nodus_tcp_conn *conn) {
    if (!w || !witness_id || !conn) return;

    /* Skip self */
    if (memcmp(witness_id, w->my_id, NODUS_T3_WITNESS_ID_LEN) == 0)
        return;

    /* Upsert handles the witness_id / conn / address dedup; address is
     * pulled from the roster so a seed-bootstrap entry (zero id, same
     * address) gets adopted instead of creating a duplicate slot. */
    int ri = nodus_witness_roster_find(&w->roster, witness_id);
    const char *ri_addr =
        (ri >= 0 && w->roster.witnesses[ri].address[0])
            ? w->roster.witnesses[ri].address
            : NULL;

    int pi = witness_peer_upsert(w, witness_id, conn, ri_addr);
    if (pi < 0) return;

    w->peers[pi].identified = true;
    w->peers[pi].connect_failures = 0;
}

/* find_peer_by_addr and find_peer_by_conn removed — DHT is primary discovery */

/* (connect_to_entry removed — reconnection handled in peer_tick) */

/* ── Roster sort helper ──────────────────────────────────────────── */

static int roster_cmp(const void *a, const void *b) {
    const nodus_witness_roster_entry_t *ea = (const nodus_witness_roster_entry_t *)a;
    const nodus_witness_roster_entry_t *eb = (const nodus_witness_roster_entry_t *)b;
    return memcmp(ea->witness_id, eb->witness_id, NODUS_T3_WITNESS_ID_LEN);
}

/* ── Build roster from DHT pubkey registry + TCP peers ────────────── */

static const char NODUS_PK_REGISTRY_KEY[] = "nodus:pk";

int nodus_witness_rebuild_roster_from_peers(nodus_witness_t *w,
                                            nodus_witness_roster_t *out) {
    if (!w || !out) return -1;

    memset(out, 0, sizeof(*out));

    /* Add self first */
    nodus_witness_roster_entry_t *self = &out->witnesses[0];
    memcpy(self->witness_id, w->my_id, NODUS_T3_WITNESS_ID_LEN);
    memcpy(self->pubkey, w->server->identity.pk.bytes, NODUS_PK_BYTES);
    const char *my_ip = w->server->config.external_ip[0]
                      ? w->server->config.external_ip
                      : w->server->config.bind_ip;
    uint16_t my_wport = w->server->config.witness_port
                      ? w->server->config.witness_port
                      : NODUS_DEFAULT_WITNESS_PORT;
    snprintf(self->address, sizeof(self->address), "%s:%u",
             my_ip, my_wport);
    self->active = true;
    out->n_witnesses = 1;

    /* ── Primary source: DHT pubkey registry ──────────────────────── */
    nodus_key_t pk_key;
    nodus_hash((const uint8_t *)NODUS_PK_REGISTRY_KEY,
               sizeof(NODUS_PK_REGISTRY_KEY) - 1, &pk_key);

    nodus_value_t **vals = NULL;
    size_t val_count = 0;
    if (nodus_storage_get_all(&w->server->storage, &pk_key,
                                &vals, &val_count) == 0 && vals) {
        for (size_t vi = 0; vi < val_count && out->n_witnesses < NODUS_T3_MAX_WITNESSES; vi++) {
            nodus_value_t *val = vals[vi];
            if (!val || !val->data || val->data_len == 0) continue;

            /* Verify signature */
            if (nodus_value_verify(val) != 0) continue;

            /* Skip expired */
            if (nodus_value_is_expired(val, (uint64_t)time(NULL))) continue;

            /* Decode CBOR payload: { "id": node_id, "pk": pubkey, "ip": ip, "port": port } */
            cbor_decoder_t dec;
            cbor_decoder_init(&dec, val->data, val->data_len);
            cbor_item_t top = cbor_decode_next(&dec);
            if (top.type != CBOR_ITEM_MAP) continue;

            uint8_t node_id[NODUS_KEY_BYTES] = {0};
            uint8_t pubkey[NODUS_PK_BYTES] = {0};
            char ip[64] = {0};
            uint16_t port = 0;
            bool has_id = false, has_pk = false;

            for (size_t m = 0; m < top.count; m++) {
                cbor_item_t k = cbor_decode_next(&dec);
                if (k.type != CBOR_ITEM_TSTR) { cbor_decode_skip(&dec); continue; }

                if (k.tstr.len == 2 && memcmp(k.tstr.ptr, "id", 2) == 0) {
                    cbor_item_t v = cbor_decode_next(&dec);
                    if (v.type == CBOR_ITEM_BSTR && v.bstr.len == NODUS_KEY_BYTES) {
                        memcpy(node_id, v.bstr.ptr, NODUS_KEY_BYTES);
                        has_id = true;
                    }
                } else if (k.tstr.len == 2 && memcmp(k.tstr.ptr, "pk", 2) == 0) {
                    cbor_item_t v = cbor_decode_next(&dec);
                    if (v.type == CBOR_ITEM_BSTR && v.bstr.len == NODUS_PK_BYTES) {
                        memcpy(pubkey, v.bstr.ptr, NODUS_PK_BYTES);
                        has_pk = true;
                    }
                } else if (k.tstr.len == 2 && memcmp(k.tstr.ptr, "ip", 2) == 0) {
                    cbor_item_t v = cbor_decode_next(&dec);
                    if (v.type == CBOR_ITEM_TSTR && v.tstr.len < sizeof(ip)) {
                        memcpy(ip, v.tstr.ptr, v.tstr.len);
                        ip[v.tstr.len] = '\0';
                    }
                } else if (k.tstr.len == 4 && memcmp(k.tstr.ptr, "port", 4) == 0) {
                    cbor_item_t v = cbor_decode_next(&dec);
                    if (v.type == CBOR_ITEM_UINT)
                        port = (uint16_t)v.uint_val;
                } else {
                    cbor_decode_skip(&dec);
                }
            }

            if (!has_id || !has_pk) continue;

            /* Skip self */
            if (memcmp(node_id, w->my_id, NODUS_T3_WITNESS_ID_LEN) == 0)
                continue;

            /* Duplicate check */
            bool dup = false;
            for (uint32_t j = 0; j < out->n_witnesses; j++) {
                if (memcmp(out->witnesses[j].witness_id,
                           node_id, NODUS_T3_WITNESS_ID_LEN) == 0) {
                    dup = true;
                    break;
                }
            }
            if (dup) continue;

            nodus_witness_roster_entry_t *entry =
                &out->witnesses[out->n_witnesses];
            memcpy(entry->witness_id, node_id, NODUS_T3_WITNESS_ID_LEN);
            memcpy(entry->pubkey, pubkey, NODUS_PK_BYTES);
            if (ip[0] && port)
                snprintf(entry->address, sizeof(entry->address), "%s:%u", ip, port);
            entry->active = true;
            out->n_witnesses++;
        }

        /* Free values */
        for (size_t vi = 0; vi < val_count; vi++)
            nodus_value_free(vals[vi]);
        free(vals);
    }

    /* ── Fallback: w_ident peers not already in roster ────────────── */
    static const uint8_t zero_id[NODUS_T3_WITNESS_ID_LEN] = {0};
    for (int i = 0; i < w->peer_count && out->n_witnesses < NODUS_T3_MAX_WITNESSES; i++) {
        nodus_witness_peer_t *peer = &w->peers[i];
        if (!peer->identified) continue;
        if (!peer->conn || peer->conn->state != NODUS_CONN_CONNECTED) continue;
        if (memcmp(peer->witness_id, zero_id, NODUS_T3_WITNESS_ID_LEN) == 0)
            continue;

        bool dup = false;
        for (uint32_t j = 0; j < out->n_witnesses; j++) {
            if (memcmp(out->witnesses[j].witness_id,
                       peer->witness_id, NODUS_T3_WITNESS_ID_LEN) == 0) {
                dup = true;
                break;
            }
        }
        if (dup) continue;

        /* ⚠ AN ENTRY WE CANNOT KEY IS WORSE THAN NO ENTRY — DO NOT ADD IT.
         *
         * This block used to write the witness_id unconditionally and the
         * pubkey only `if (ri >= 0)`. `out` is memset to zero at the top of
         * this function, so a peer whose key this node has not learned yet
         * was added with a REAL id and an ALL-ZERO public key.
         *
         * What that costs, and it is permanent:
         *   1. nodus_witness_roster_find() matches on witness_id, so the
         *      lookup SUCCEEDS and nodus_t3_verify runs against the zero
         *      key — every frame from that peer fails
         *      (`T3 <method> wsig verification failed (roster N)`).
         *   2. The duplicate check at the top of this same merge is ALSO
         *      by witness_id, so once the keyless entry exists the correct
         *      one can never replace it. The node is locked out of that
         *      peer for good.
         *
         * Measured on test_v2_grow_7_20.sh STEP 6c at N=20 (nodus/BUGS.md,
         * N=20 entry): `cand3` logged 143 consecutive verification failures,
         * all against one roster index, and stalled at 13/13 prevotes
         * needing 14 — the single peer it could not verify was the missing
         * vote. `cand1` and `cand4` showed the same shape, 132 and 133
         * failures against a different index, on an earlier run. At exact
         * quorum every alive node must vote, so ONE unverifiable peer is
         * the difference between a chain that commits and one that cannot.
         *
         * Skipping is safe and self-healing: the peer is added on a later
         * rebuild, once its key arrives through IDENT or the DHT `nodus:pk`
         * registry. A missing entry costs one rebuild; a keyless one costs
         * the peer forever. */
        int ri = nodus_witness_roster_find(&w->roster, peer->witness_id);
        if (ri < 0) continue;

        nodus_witness_roster_entry_t *entry =
            &out->witnesses[out->n_witnesses];
        memcpy(entry->witness_id, peer->witness_id, NODUS_T3_WITNESS_ID_LEN);
        memcpy(entry->pubkey, w->roster.witnesses[ri].pubkey, NODUS_PK_BYTES);
        snprintf(entry->address, sizeof(entry->address), "%s", peer->address);
        entry->active = true;
        out->n_witnesses++;
    }

    /* Sort deterministically by witness_id for consistent leader election */
    if (out->n_witnesses > 1) {
        qsort(out->witnesses, out->n_witnesses,
              sizeof(nodus_witness_roster_entry_t), roster_cmp);
    }

    out->version = w->roster.version + 1;
    return (int)out->n_witnesses;
}

/* ── Send IDENT ──────────────────────────────────────────────────── */

int nodus_witness_peer_send_ident(nodus_witness_t *w,
                                  struct nodus_tcp_conn *conn) {
    if (!w || !conn) return -1;

    nodus_t3_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    msg.type = NODUS_T3_IDENT;
    msg.txn_id = ++w->next_txn_id;
    snprintf(msg.method, sizeof(msg.method), "w_ident");

    /* Fill identity fields */
    msg.ident.witness_id = w->my_id;
    msg.ident.pubkey = w->server->identity.pk.bytes;
    const char *ident_ip = w->server->config.external_ip[0]
                         ? w->server->config.external_ip
                         : w->server->config.bind_ip;
    uint16_t ident_wport = w->server->config.witness_port
                         ? w->server->config.witness_port
                         : NODUS_DEFAULT_WITNESS_PORT;
    snprintf(msg.ident.address, sizeof(msg.ident.address),
             "%s:%u", ident_ip, ident_wport);

    /* Block height, UTXO checksum, and view for sync/leader detection */
    msg.ident.block_height = nodus_witness_block_height(w);
    if (w->cached_state_root_valid) {
        memcpy(msg.ident.state_root, w->cached_state_root, NODUS_KEY_BYTES);
    } else {
        /* Phase 3 / Task 10: peer identification advertises the composite
         * state_root (utxo || validator || delegation || reward). */
        if (nodus_witness_merkle_compute_state_root(w, msg.ident.state_root) != 0) {
            /* D4 (2026-07-31) — was an unchecked call. Advertise the
             * all-zero "unknown" checksum, EXPLICITLY: consumers skip a
             * zero remote_checksum instead of scoring it as agreement or
             * disagreement (nodus_witness_sync.c:305 and :434), so this
             * node simply does not contribute to the divergence tally
             * until it can compute a real root.
             *
             * The memset at the top of this function already zeroes msg,
             * and compute_state_root leaves root_out untouched on failure
             * — but relying on that pair was implicit correctness, and
             * D2 made this failure path genuinely reachable. Re-zero so
             * the guarantee is local and visible. */
            memset(msg.ident.state_root, 0, NODUS_KEY_BYTES);
            QGP_LOG_ERROR(LOG_TAG,
                "IDENT: state_root compute failed — advertising all-zero "
                "(unknown) checksum at height %llu",
                (unsigned long long)msg.ident.block_height);
        }
    }
    /* R3 W4 — `w->current_view` no longer exists: the legacy view counter
     * was deleted with the closed consensus lane. The wire field stays
     * (byte-identical IDENT frame) and is written 0; the receive side
     * already never acts on it (see nodus_witness_peer_handle_ident's own
     * comment below). */
    msg.ident.current_view = 0;
    msg.ident.roster_size = w->roster.n_witnesses;
    msg.ident.ts_local = (uint64_t)time(NULL);  /* Phase 10 / Task 10.4 */
    msg.ident.has_block_height = true;

    /* CC-OPS-002 / Q14 — advertise binary + schema version so peers can
     * detect skew at handshake time instead of via silent state_root
     * divergence post-first-block. Packed version: MAJOR<<16 | MINOR<<8 | PATCH.
     *
     * F4 mock override: when --mock-nodus-version=N is set, send N
     * instead of the real version. Used by stagef
     * test_bootstrap_mixed_version.sh to verify H-9 exit(3) on a
     * fresh-bootstrap node when the cluster has any peer reporting
     * an older version. */
    if (g_mock_nodus_version != 0) {
        msg.ident.nodus_version = g_mock_nodus_version;
    } else {
        msg.ident.nodus_version =
            ((uint32_t)NODUS_VERSION_MAJOR << 16) |
            ((uint32_t)NODUS_VERSION_MINOR <<  8) |
            ((uint32_t)NODUS_VERSION_PATCH);
    }
    msg.ident.chain_config_schema = NODUS_CHAIN_CONFIG_SCHEMA_VERSION;

    /* Fill header */
    msg.header.version = NODUS_T3_BFT_PROTOCOL_VER;
    msg.header.round = 0;
    msg.header.view = 0;
    memcpy(msg.header.sender_id, w->my_id, NODUS_T3_WITNESS_ID_LEN);
    msg.header.timestamp = (uint64_t)time(NULL);
    nodus_random((uint8_t *)&msg.header.nonce, sizeof(msg.header.nonce));
    memcpy(msg.header.chain_id, w->chain_id, 32);

    /* Encode and sign */
    uint8_t buf[NODUS_T3_MAX_MSG_SIZE];
    size_t len = 0;

    if (nodus_t3_encode(&msg, &w->server->identity.sk,
                         buf, sizeof(buf), &len) != 0) {
        fprintf(stderr, "%s: failed to encode w_ident\n", LOG_TAG);
        return -1;
    }

    return nodus_tcp_send(conn, buf, len);
}

/* ── Handle IDENT ────────────────────────────────────────────────── */

/* ── Fix 3: startup chain_id quorum check ─────────────────────────
 *
 * Called from handle_ident for every peer w_ident we receive during
 * the first 300s after witness activation. Tracks distinct dissenters
 * (peers on a different chain) and agreers (peers on the same chain).
 * If dissent reaches strict majority of observed peers and we have at
 * least 2 dissenters, the witness self-quarantines. See dispatch_t3
 * in nodus_witness.c for where the quarantine flag is enforced.
 *
 * Non-reverts: agreement evidence alone can never clear a quarantine.
 * Operator intervention (restart after fixing the disk state) is the
 * only way out — by design, to prevent a self-heal loop on ambiguity.
 */
#define WITNESS_CHAIN_QUORUM_WINDOW_SEC  300

/* R3 W4 — non-static so a test can still pin the DG-2 matrix directly, but
 * this function's former shared declaration site (nodus_witness_bft_internal.h,
 * alongside its twin verify_chain_id) is DELETED with the rest of the closed
 * consensus lane; verify_chain_id was bft.c's own and went with it.
 * QUESTION for the CONVERT resolution (test_v2_restart_gate.c, package
 * W4-P): that test currently includes nodus_witness_bft_internal.h for this
 * prototype under NODUS_WITNESS_INTERNAL_API — it needs a new declaration
 * site (this file's own header, gated the same way, is the natural one) once
 * its surviving cases are decided. Not resolved here: this package does not
 * touch test files. */
void witness_chain_quorum_observe(nodus_witness_t *w,
                                    const uint8_t *peer_id,
                                    const uint8_t *peer_chain_id) {
    if (!w || !peer_id || !peer_chain_id) return;
    if (w->quarantined) return;  /* Already decided — sticky */

    static const uint8_t zero[32] = {0};

    /* O15L DG-2 (G3) — THE SAME (chain_id, db) MATRIX verify_chain_id
     * takes (nodus_witness_bft.c). This is the self-quarantine detector,
     * so the failure mode of the old all-zero skip was the mirror of the
     * one there: a node with a zeroed identity went BLIND to its own
     * divergence at exactly the moment it was most likely to be the
     * diverged one. Both consumers of that exemption move together, or
     * fixing one just relocates the hole.
     *
     * The observable here is whether an observation is COUNTED:
     *
     *   chain_id != 0, db != NULL   healthy               -> OBSERVE
     *   chain_id != 0, db == NULL   open failed, id kept  -> OBSERVE
     *   chain_id == 0, db == NULL   genuine pre-genesis   -> skip
     *   chain_id == 0, db != NULL   invariant violation   -> skip, loudly
     *
     * Rows 3 and 4 both count nothing — a node with no identity has no
     * opinion to compare a peer against — and differ only in that row 4
     * is a violated invariant and says so. */
    if (memcmp(w->chain_id, zero, 32) == 0) {
        if (w->db) {
            fprintf(stderr,
                    "%s: INVARIANT VIOLATION — chain_id is all-zero while "
                    "the chain database is OPEN; the chain-quorum detector "
                    "cannot judge dissent and is standing down.\n", LOG_TAG);
        }
        /* Row 3 (silent) and row 4 (logged): nothing to compare against. */
        return;
    }

    /* Skip if peer is pre-genesis (no opinion) — unchanged by O15L; this
     * is a statement about the PEER, not about us. */
    if (memcmp(peer_chain_id, zero, 32) == 0) return;

    /* Only check within startup window — after this we trust the cluster
     * decision that's already been made and rely on per-message
     * chain_id verification in nodus_witness_bft.c. */
    uint64_t now = (uint64_t)time(NULL);
    if (now > w->activated_at_sec + WITNESS_CHAIN_QUORUM_WINDOW_SEC) return;

    bool disagree = (memcmp(w->chain_id, peer_chain_id, 32) != 0);

    /* Dedup by peer_id in the appropriate list */
    uint8_t (*list)[NODUS_T3_WITNESS_ID_LEN] =
        disagree ? w->chain_dissent_ids : w->chain_agree_ids;
    uint32_t *count = disagree ? &w->chain_dissent_count : &w->chain_agree_count;
    uint32_t cap = NODUS_T3_MAX_WITNESSES;

    for (uint32_t i = 0; i < *count; i++) {
        if (memcmp(list[i], peer_id, NODUS_T3_WITNESS_ID_LEN) == 0)
            return;  /* Already counted */
    }
    if (*count >= cap) return;  /* Should never happen (bounded by roster) */
    memcpy(list[*count], peer_id, NODUS_T3_WITNESS_ID_LEN);
    (*count)++;

    if (disagree) {
        char local_hex[17], peer_hex[17];
        for (int i = 0; i < 8; i++) {
            snprintf(local_hex + i * 2, 3, "%02x", w->chain_id[i]);
            snprintf(peer_hex + i * 2, 3, "%02x", peer_chain_id[i]);
        }
        fprintf(stderr, "%s: CHAIN_QUORUM: peer reports chain %s (local %s) — dissent=%u agree=%u\n",
                LOG_TAG, peer_hex, local_hex,
                w->chain_dissent_count, w->chain_agree_count);
    }

    /* Quarantine decision:
     *   >=2 distinct dissenters AND strict majority of observed peers disagree
     * A single dissenter (network race, a peer still catching up) is
     * not enough. */
    if (w->chain_dissent_count >= 2 &&
        w->chain_dissent_count > w->chain_agree_count) {
        w->quarantined = true;
        fprintf(stderr, "%s: QUARANTINED — %u peers disagree with local chain_id "
                "vs %u that agree. Refusing BFT activity until operator "
                "intervention. Check /var/lib/nodus/data/witness_*.db files.\n",
                LOG_TAG, w->chain_dissent_count, w->chain_agree_count);
    }
}

int nodus_witness_peer_handle_ident(nodus_witness_t *w,
                                    struct nodus_tcp_conn *conn,
                                    const nodus_t3_msg_t *msg) {
    if (!w || !conn || !msg) return -1;

    const nodus_t3_ident_t *ident = &msg->ident;
    if (!ident->witness_id || !ident->pubkey) {
        fprintf(stderr, "%s: w_ident missing required fields\n", LOG_TAG);
        return -1;
    }

    /* F17 B1 — TCP 4004 admission gate. After the handshake has
     * revealed the peer's pubkey, reject the connection if the peer
     * is not a member of the chain-derived committee for the next
     * block. This is defense-in-depth on top of A3's vote-time
     * authorization: non-committee peers cannot vote (A3) and also
     * cannot consume a gossip-roster slot or TCP 4004 resources (B1).
     *
     * Pre-genesis (committee empty) is handled liberally — the check
     * is a no-op until the chain has any validators. Otherwise,
     * reject ident from any pubkey not in the current committee.
     *
     * tokenomics-v3 P1 round 5 (O6 red-team L1-2): cometbft's own
     * two-height lag means a validator set change the LEDGER already
     * applied is not yet the set cometbft is voting with — it still
     * validates heights H and H+1 with the PREVIOUS set. A member that
     * is still an honest voter under that previous set could be refused
     * here purely because this gate only ever asked the FORWARD
     * committee, and once refused it cannot redial to keep signing.
     * Accept the ident if the pubkey is a member of EITHER the committee
     * for `peer_tip + 1` (forward — unchanged) OR the committee for
     * `peer_tip - 1` (the set cometbft can still be using, guarded
     * against underflow at low heights). This gate has NO counterpart in
     * the cometbft reference — p2p there does not filter peers by
     * validator set at all — so it remains registered attack surface,
     * not a ported behaviour, whichever committee(s) it consults. */
    {
        /* S3: heap — a DNAC_MAX_ACTIVE_VALIDATORS committee is ~334 KB. */
        bool reject = false;
        /* O15O Faz 1 — a faulted height read takes the SAME path this
         * gate already takes for a committee-lookup failure and for
         * cm_count == 0: `reject` stays false and the ident is accepted
         * liberally. That is deliberate and it is the safer of the two
         * directions HERE, because the alternative is not "refuse" but
         * "resolve the committee for height 1": a bogus height would ask
         * the wrong committee and could evict a legitimate peer from the
         * mesh, which is a liveness failure with no security gain. This
         * is a defence-in-depth transport gate (F17 B1); vote-time
         * authorization (A3) is the line that must not fail open, and it
         * resolves its own committee on the checked accessor. */
        uint64_t peer_tip = 0;
        if (nodus_witness_block_height_checked(w, &peer_tip) != 0) {
            fprintf(stderr,
                    "%s: w_ident — chain-height read faulted; treating the "
                    "admission gate as pre-genesis (accept) rather than "
                    "resolving the committee at height 1\n", LOG_TAG);
        } else {
            bool in_committee = false;
            bool fwd_resolved = false;

            nodus_committee_member_t *fwd = NULL;
            int fwd_count = 0;
            if (nodus_committee_get_for_block_alloc(w, peer_tip + 1, &fwd,
                                                    &fwd_count) == 0 &&
                fwd_count > 0) {
                fwd_resolved = true;
                for (int i = 0; i < fwd_count; i++) {
                    if (memcmp(fwd[i].pubkey, ident->pubkey,
                              DNAC_PUBKEY_SIZE) == 0) {
                        in_committee = true;
                        break;
                    }
                }
            }
            free(fwd);

            /* The lagging committee can only WIDEN admission — it is
             * consulted only when the forward committee resolved and
             * refused. A forward lookup that failed or came back empty
             * keeps its pre-round-5 meaning (accept), whatever the lag
             * lookup would say (O6 verifier, round 5). */
            if (fwd_resolved && !in_committee && peer_tip >= 1) {
                nodus_committee_member_t *lag = NULL;
                int lag_count = 0;
                if (nodus_committee_get_for_block_alloc(w, peer_tip - 1,
                                                        &lag,
                                                        &lag_count) == 0 &&
                    lag_count > 0) {
                    for (int i = 0; i < lag_count; i++) {
                        if (memcmp(lag[i].pubkey, ident->pubkey,
                                  DNAC_PUBKEY_SIZE) == 0) {
                            in_committee = true;
                            break;
                        }
                    }
                }
                free(lag);
            }

            /* Forward committee failed or empty: pre-genesis / bootstrap
             * / lookup fault — accept liberally, exactly as before. */
            reject = fwd_resolved && !in_committee;
        }
        if (reject) {
            fprintf(stderr,
                    "%s: w_ident rejected — peer pubkey not in "
                    "the forward or the lagging committee (transport "
                    "admission gate)\n",
                    LOG_TAG);
            return -1;
        }
    }

    /* Fix 3: chain_id quorum tracking — piggybacks on T3 message header */
    witness_chain_quorum_observe(w, ident->witness_id, msg->header.chain_id);

    /* Try to find in roster by witness_id */
    int roster_idx = nodus_witness_roster_find(&w->roster,
                                                 ident->witness_id);

    if (roster_idx < 0 && ident->address[0]) {
        /* Not in roster by ID — check by address (placeholder entry only).
         * Only overwrite if pubkey is zero (placeholder). Never overwrite
         * an established identity — prevents address-based impersonation. */
        static const uint8_t zero_pk[NODUS_PK_BYTES] = {0};
        for (uint32_t i = 0; i < w->roster.n_witnesses; i++) {
            if (strcmp(w->roster.witnesses[i].address,
                       ident->address) == 0) {
                if (memcmp(w->roster.witnesses[i].pubkey, zero_pk,
                           NODUS_PK_BYTES) != 0) {
                    /* Entry already has a real identity — don't overwrite */
                    QGP_LOG_WARN(LOG_TAG, "address match at %s but pubkey "
                            "already set, skipping overwrite",
                            ident->address);
                    break;
                }
                roster_idx = (int)i;
                /* Update placeholder ID and pubkey with real identity */
                memcpy(w->roster.witnesses[i].witness_id,
                       ident->witness_id, NODUS_T3_WITNESS_ID_LEN);
                memcpy(w->roster.witnesses[i].pubkey,
                       ident->pubkey, NODUS_PK_BYTES);
                w->roster.version++;
                fprintf(stderr, "%s: updated roster %d identity at %s\n",
                        LOG_TAG, roster_idx, ident->address);
                break;
            }
        }
    }

    if (roster_idx < 0) {
        /* Unknown witness — add to roster if space */
        nodus_witness_roster_entry_t entry;
        memset(&entry, 0, sizeof(entry));
        memcpy(entry.witness_id, ident->witness_id,
               NODUS_T3_WITNESS_ID_LEN);
        memcpy(entry.pubkey, ident->pubkey, NODUS_PK_BYTES);
        snprintf(entry.address, sizeof(entry.address),
                 "%s", ident->address);
        entry.active = true;

        if (nodus_witness_roster_add(w, &entry) == 0) {
            roster_idx = nodus_witness_roster_find(&w->roster,
                                                     ident->witness_id);
        }
    }

    /* Unified upsert: dedups on witness_id, conn, AND address — matches
     * a prior seed-bootstrap slot (zero id, same address, outbound conn)
     * when the peer's w_ident lands on a separate inbound conn, avoiding
     * the dual-slot "sent=11" broadcast fanout.  The address is already
     * present in the ident message. */
    int pi = witness_peer_upsert(w, ident->witness_id, conn, ident->address);

    if (pi >= 0) {
        /* Refresh address in case the ident carries a more canonical
         * form (e.g., external IP vs. bootstrap seed IP). Upsert only
         * fills address when unset; explicit overwrite keeps it fresh. */
        snprintf(w->peers[pi].address, sizeof(w->peers[pi].address),
                 "%s", ident->address);
        bool first_ident = !w->peers[pi].identified;
        w->peers[pi].identified = true;
        w->peers[pi].connect_failures = 0;

        /* Eager roster rebuild on first IDENT from this peer. Without this
         * the roster grows only on the 60s epoch tick (WITNESS_EPOCH_SECS
         * in nodus_witness.c), which is far slower than fresh-cluster
         * bootstrap needs — a genesis TX arriving in the first 60s after
         * startup would hit `consensus disabled (n=1 < 5)` even with all
         * witness peers already connected + identified. Setting last_epoch
         * to 0 forces the next nodus_witness_tick (~50ms) to run the full
         * rebuild + swap path. Idempotent on re-IDENT because the
         * first_ident gate prevents retriggering on steady-state peers. */
        if (first_ident) {
            w->last_epoch = 0;
        }

        /* Phase 10 / Task 10.4 — clock skew probe */
        {
            int64_t now_s = (int64_t)time(NULL);
            int64_t skew = now_s - (int64_t)ident->ts_local;
            w->peers[pi].last_skew_sec = skew;
            int64_t abs_skew = skew < 0 ? -skew : skew;
            if (abs_skew > 10) {
                QGP_LOG_WARN(LOG_TAG, "clock skew %lld s vs peer %s",
                             (long long)skew, w->peers[pi].address);
            }
        }

        /* CC-OPS-002 / Q14 — binary-skew / schema mismatch probe.
         * Legacy peers (pre hard-fork v1) don't send nv/ccs → both 0 →
         * treated as incompatible. Matching peers run the same binary
         * and schema → compatible. Mismatch logged once per handshake
         * with the pinned "PEER SCHEMA MISMATCH" literal so ops
         * log-tripwires fire instead of waiting for state_root divergence
         * at the next block. */
        {
            uint32_t local_nv =
                ((uint32_t)NODUS_VERSION_MAJOR << 16) |
                ((uint32_t)NODUS_VERSION_MINOR <<  8) |
                ((uint32_t)NODUS_VERSION_PATCH);
            uint32_t local_ccs = NODUS_CHAIN_CONFIG_SCHEMA_VERSION;
            w->peers[pi].remote_nodus_version       = ident->nodus_version;
            w->peers[pi].remote_chain_config_schema = ident->chain_config_schema;
            bool compat = (ident->nodus_version == local_nv) &&
                          (ident->chain_config_schema == local_ccs);
            /* Log on every incompatible handshake so ops tripwires see
             * every instance of a mismatched peer re-identifying. We
             * deliberately don't gate on previous state — peers that
             * never went compatible still need to show up. */
            if (!compat) {
                QGP_LOG_ERROR(LOG_TAG,
                    "PEER SCHEMA MISMATCH peer=%s local_nv=0x%06x "
                    "local_ccs=%u remote_nv=0x%06x remote_ccs=%u",
                    w->peers[pi].address,
                    (unsigned)local_nv, (unsigned)local_ccs,
                    (unsigned)ident->nodus_version,
                    (unsigned)ident->chain_config_schema);
                /* Q17 / CC-OPS-005 — counter for downstream ops dashboards. */
                w->chain_config_peer_schema_mismatch++;
            }
            w->peers[pi].version_compatible = compat;
        }

        /* Store peer's chain state for sync decisions */
        if (ident->has_block_height) {
            w->peers[pi].remote_height = ident->block_height;
            memcpy(w->peers[pi].remote_checksum, ident->state_root,
                   NODUS_KEY_BYTES);

            /* R3 W4 — `ident->current_view` is received and not acted on:
             * it stays on the wire as a gossip / observability field only
             * (this node's own send side writes it 0, see
             * nodus_witness_peer_send_ident above). There is no local
             * `w->current_view` left to adopt it into — the legacy view
             * counter and the round machinery that read it were deleted
             * with the closed consensus lane. IDENT is also EXEMPT from
             * the wsig verify (nodus_witness.c dispatch_t3), so its claims
             * are unauthenticated regardless. */
        }
    }

    /* Roster gossip: request peer's roster if their roster size differs.
     * This is the root cause fix for roster inconsistency after restart:
     * DHT R=3 replication means not all nodes see all nodus:pk entries.
     * By requesting the full roster from each identified peer, we converge
     * to a consistent roster across all nodes.
     * Rate limited: max one w_rost_q per peer per 60 seconds. */
    bool need_gossip = false;
    if (ident->has_block_height &&
        ident->roster_size > 0 &&
        ident->roster_size != w->roster.n_witnesses) {
        need_gossip = true;
    } else if (w->roster.n_witnesses <= 1) {
        need_gossip = true;
    }

    if (need_gossip && pi >= 0) {
        uint64_t now_rost = nodus_time_now();
        if (now_rost - w->peers[pi].last_rost_q_time >= 60) {
            w->peers[pi].last_rost_q_time = now_rost;
            QGP_LOG_INFO(LOG_TAG, "roster mismatch (local=%u, peer=%u) — "
                    "requesting roster via w_rost_q",
                    w->roster.n_witnesses,
                    ident->roster_size);
            send_rost_q(w, conn);
        }
    }

    return 0;
}

/* R3 W4 — nodus_witness_peer_handle_fwd_req (the FWD_REQ intake, O15K
 * pool-then-forward, the legacy admission/validation verify calls) and
 * nodus_witness_peer_handle_fwd_rsp (the FWD_RSP receipt path) are DELETED
 * with the closed consensus lane: verbs FWD_REQ/FWD_RSP are dropped by the
 * dispatcher (D-16 rev 5) and never reach a handler; their only callers —
 * nodus_witness_bft_start_round_from_entries, nodus_witness_send_spend_result,
 * the legacy pending_forwards table, the legacy mempool — are deleted
 * with them. */

/* ── Send roster query ──────────────────────────────────────────── */

/**
 * Send w_rost_q to a peer to request their roster.
 * Called after w_ident exchange to activate roster gossip.
 */
static int send_rost_q(nodus_witness_t *w, struct nodus_tcp_conn *conn) {
    if (!w || !conn) return -1;

    nodus_t3_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    msg.type = NODUS_T3_ROST_Q;
    msg.txn_id = ++w->next_txn_id;
    snprintf(msg.method, sizeof(msg.method), "w_rost_q");

    msg.rost_q.version = w->roster.version;

    /* Fill header */
    msg.header.version = NODUS_T3_BFT_PROTOCOL_VER;
    memcpy(msg.header.sender_id, w->my_id, NODUS_T3_WITNESS_ID_LEN);
    msg.header.timestamp = (uint64_t)time(NULL);
    nodus_random((uint8_t *)&msg.header.nonce, sizeof(msg.header.nonce));
    memcpy(msg.header.chain_id, w->chain_id, 32);

    /* Encode and sign */
    uint8_t buf[NODUS_T3_MAX_MSG_SIZE];
    size_t len = 0;

    if (nodus_t3_encode(&msg, &w->server->identity.sk,
                         buf, sizeof(buf), &len) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "failed to encode w_rost_q");
        return -1;
    }

    return nodus_tcp_send(conn, buf, len);
}

/* ── Roster query ────────────────────────────────────────────────── */

int nodus_witness_peer_handle_rost_q(nodus_witness_t *w,
                                     struct nodus_tcp_conn *conn,
                                     const nodus_t3_msg_t *msg) {
    if (!w || !conn || !msg) return -1;

    /* Build roster response */
    nodus_t3_msg_t rsp;
    memset(&rsp, 0, sizeof(rsp));
    rsp.type = NODUS_T3_ROST_R;
    /* F20 — echo request txn_id so the proposer's short-lived RPC can
     * correlate response-to-request on its single connection. Mirrors
     * the CC_VOTE_RSP fix (commit f334b3ff). */
    rsp.txn_id = msg->txn_id;
    snprintf(rsp.method, sizeof(rsp.method), "w_rost_r");

    rsp.rost_r.version = w->roster.version;
    rsp.rost_r.n_witnesses = w->roster.n_witnesses;

    for (uint32_t i = 0; i < w->roster.n_witnesses; i++) {
        rsp.rost_r.witnesses[i].witness_id =
            w->roster.witnesses[i].witness_id;
        rsp.rost_r.witnesses[i].pubkey =
            w->roster.witnesses[i].pubkey;
        snprintf(rsp.rost_r.witnesses[i].address,
                 sizeof(rsp.rost_r.witnesses[i].address),
                 "%s", w->roster.witnesses[i].address);
        rsp.rost_r.witnesses[i].joined_epoch =
            w->roster.witnesses[i].joined_epoch;
        rsp.rost_r.witnesses[i].active =
            w->roster.witnesses[i].active;
    }

    /* Fill header */
    rsp.header.version = NODUS_T3_BFT_PROTOCOL_VER;
    memcpy(rsp.header.sender_id, w->my_id, NODUS_T3_WITNESS_ID_LEN);
    rsp.header.timestamp = (uint64_t)time(NULL);
    nodus_random((uint8_t *)&rsp.header.nonce, sizeof(rsp.header.nonce));
    memcpy(rsp.header.chain_id, w->chain_id, 32);

    /* Encode and send */
    uint8_t buf[NODUS_T3_MAX_MSG_SIZE];
    size_t len = 0;

    if (nodus_t3_encode(&rsp, &w->server->identity.sk,
                         buf, sizeof(buf), &len) != 0) {
        fprintf(stderr, "%s: failed to encode w_rost_r\n", LOG_TAG);
        return -1;
    }

    return nodus_tcp_send(conn, buf, len);
}

/* ── DHT-verified witness identity set ──────────────────────────── */

/** Pre-built lookup table of verified (witness_id, pubkey) pairs from DHT. */
typedef struct {
    uint8_t witness_id[NODUS_T3_WITNESS_ID_LEN];
    uint8_t pubkey[NODUS_PK_BYTES];
} dht_verified_entry_t;

typedef struct {
    dht_verified_entry_t entries[NODUS_T3_MAX_WITNESSES];
    uint32_t count;
} dht_verified_set_t;

/**
 * Build a verified set of (witness_id, pubkey) pairs from the DHT nodus:pk
 * registry. Each entry is Dilithium5-signed — a single DHT scan + verify
 * pass, then O(1) lookups per roster candidate. Reduces verify cost from
 * O(N*M) to O(M) where M = DHT entries.
 */
static void build_dht_verified_set(nodus_witness_t *w,
                                    dht_verified_set_t *out) {
    memset(out, 0, sizeof(*out));

    nodus_key_t pk_key;
    nodus_hash((const uint8_t *)NODUS_PK_REGISTRY_KEY,
               sizeof(NODUS_PK_REGISTRY_KEY) - 1, &pk_key);

    nodus_value_t **vals = NULL;
    size_t val_count = 0;
    if (nodus_storage_get_all(&w->server->storage, &pk_key,
                                &vals, &val_count) != 0 || !vals)
        return;

    uint64_t now = (uint64_t)time(NULL);
    for (size_t vi = 0; vi < val_count && out->count < NODUS_T3_MAX_WITNESSES; vi++) {
        nodus_value_t *val = vals[vi];
        if (!val || !val->data || val->data_len == 0) continue;
        if (nodus_value_verify(val) != 0) continue;
        if (nodus_value_is_expired(val, now)) continue;

        /* Decode CBOR to extract node_id and pk */
        cbor_decoder_t dec;
        cbor_decoder_init(&dec, val->data, val->data_len);
        cbor_item_t top = cbor_decode_next(&dec);
        if (top.type != CBOR_ITEM_MAP) continue;

        uint8_t dht_id[NODUS_KEY_BYTES] = {0};
        uint8_t dht_pk[NODUS_PK_BYTES] = {0};
        bool has_id = false, has_pk = false;

        for (size_t m = 0; m < top.count; m++) {
            cbor_item_t k = cbor_decode_next(&dec);
            if (k.type != CBOR_ITEM_TSTR) { cbor_decode_skip(&dec); continue; }
            if (k.tstr.len == 2 && memcmp(k.tstr.ptr, "id", 2) == 0) {
                cbor_item_t v = cbor_decode_next(&dec);
                if (v.type == CBOR_ITEM_BSTR && v.bstr.len == NODUS_KEY_BYTES) {
                    memcpy(dht_id, v.bstr.ptr, NODUS_KEY_BYTES);
                    has_id = true;
                }
            } else if (k.tstr.len == 2 && memcmp(k.tstr.ptr, "pk", 2) == 0) {
                cbor_item_t v = cbor_decode_next(&dec);
                if (v.type == CBOR_ITEM_BSTR && v.bstr.len == NODUS_PK_BYTES) {
                    memcpy(dht_pk, v.bstr.ptr, NODUS_PK_BYTES);
                    has_pk = true;
                }
            } else {
                cbor_decode_skip(&dec);
            }
        }

        if (has_id && has_pk) {
            dht_verified_entry_t *e = &out->entries[out->count++];
            memcpy(e->witness_id, dht_id, NODUS_T3_WITNESS_ID_LEN);
            memcpy(e->pubkey, dht_pk, NODUS_PK_BYTES);
        }
    }

    for (size_t vi = 0; vi < val_count; vi++)
        nodus_value_free(vals[vi]);
    free(vals);
}

/** Check if a witness_id+pubkey pair exists in the pre-built verified set. */
static bool dht_verified_set_contains(const dht_verified_set_t *set,
                                       const uint8_t *witness_id,
                                       const uint8_t *pubkey) {
    for (uint32_t i = 0; i < set->count; i++) {
        if (memcmp(set->entries[i].witness_id, witness_id,
                   NODUS_T3_WITNESS_ID_LEN) == 0 &&
            memcmp(set->entries[i].pubkey, pubkey, NODUS_PK_BYTES) == 0)
            return true;
    }
    return false;
}

/**
 * Check if a witness_id has an active, authenticated peer connection.
 * Fallback for entries not yet in DHT (e.g. fresh joins).
 */
static bool verify_witness_has_peer(const nodus_witness_t *w,
                                     const uint8_t *witness_id) {
    for (int i = 0; i < w->peer_count; i++) {
        if (!w->peers[i].identified) continue;
        if (!w->peers[i].conn) continue;
        if (w->peers[i].conn->state != NODUS_CONN_CONNECTED) continue;
        if (memcmp(w->peers[i].witness_id, witness_id,
                   NODUS_T3_WITNESS_ID_LEN) == 0)
            return true;
    }
    return false;
}

/* ── Roster response ─────────────────────────────────────────────── */

int nodus_witness_peer_handle_rost_r(nodus_witness_t *w,
                                     const nodus_t3_msg_t *msg) {
    if (!w || !msg) return -1;

    const nodus_t3_rost_r_t *r = &msg->rost_r;

    QGP_LOG_INFO(LOG_TAG, "received roster v%u with %u witnesses (local=%u)",
            r->version, r->n_witnesses, w->roster.n_witnesses);

    /* Build verified identity set from DHT once (O(M) Dilithium5 verifies),
     * then O(1) lookup per candidate entry — avoids O(N*M) repeated scans. */
    dht_verified_set_t dht_set;
    build_dht_verified_set(w, &dht_set);

    /* Merge entries we don't have — only if verified against DHT or peer mesh */
    uint32_t old_count = w->roster.n_witnesses;
    uint32_t rejected = 0;
    for (uint32_t i = 0; i < r->n_witnesses; i++) {
        if (!r->witnesses[i].witness_id) continue;
        if (!r->witnesses[i].pubkey) { rejected++; continue; }

        /* Skip self */
        if (memcmp(r->witnesses[i].witness_id, w->my_id,
                   NODUS_T3_WITNESS_ID_LEN) == 0)
            continue;

        /* Skip entries already in roster */
        if (nodus_witness_roster_find(&w->roster,
                                       r->witnesses[i].witness_id) >= 0)
            continue;

        /* Verify: entry must be attested in DHT, have an active peer conn,
         * or come from a Dilithium5-authenticated gossip source (the w_rost_r
         * message itself is wsig-signed by the sender). */
        if (!dht_verified_set_contains(&dht_set, r->witnesses[i].witness_id,
                                        r->witnesses[i].pubkey) &&
            !verify_witness_has_peer(w, r->witnesses[i].witness_id)) {
            /* Fallback: if the gossip sender is in our roster (authenticated),
             * trust their roster entries. The sender's message is Dilithium5
             * signed — they vouch for these entries. */
            int sender_idx = nodus_witness_roster_find(&w->roster,
                                                         msg->header.sender_id);
            if (sender_idx < 0) {
                rejected++;
                continue;
            }
        }

        nodus_witness_roster_entry_t entry;
        memset(&entry, 0, sizeof(entry));
        memcpy(entry.witness_id, r->witnesses[i].witness_id,
               NODUS_T3_WITNESS_ID_LEN);
        memcpy(entry.pubkey, r->witnesses[i].pubkey, NODUS_PK_BYTES);
        snprintf(entry.address, sizeof(entry.address),
                 "%s", r->witnesses[i].address);
        entry.joined_epoch = r->witnesses[i].joined_epoch;
        entry.active = r->witnesses[i].active;

        nodus_witness_roster_add(w, &entry);
    }

    if (rejected > 0) {
        QGP_LOG_WARN(LOG_TAG, "roster gossip rejected %u unverified entries",
                rejected);
    }

    /* If roster grew, sort deterministically and recalculate my_index */
    if (w->roster.n_witnesses > old_count) {
        if (w->roster.n_witnesses > 1) {
            qsort(w->roster.witnesses, w->roster.n_witnesses,
                  sizeof(nodus_witness_roster_entry_t), roster_cmp);
        }
        /* F17 A2 — BFT config NOT recomputed from gossip. Refreshed
         * from the chain committee at round-start. */

        QGP_LOG_INFO(LOG_TAG, "roster gossip merged: %u -> %u witnesses "
                "(transport)",
                old_count, w->roster.n_witnesses);
    }

    return 0;
}

/* ── Peer mesh initialization ────────────────────────────────────── */

int nodus_witness_peer_init(nodus_witness_t *w) {
    if (!w) return -1;

    /* Dynamic roster — initial build from DHT registry + witness peers.
     * At init time, witness TCP connections may not be established yet.
     * Full roster will be built on first epoch tick (60s).
     *
     * F17 A2/A4 — roster is transport-only; the committee is the frozen
     * epoch validator set the cometbft application state reads, and
     * self-identity queries resolve through the committee pubkey
     * lookup. */
    nodus_witness_rebuild_roster_from_peers(w, &w->roster);

    /* Bootstrap: connect to all seed nodes on witness TCP port (4004).
     * Seed nodes are configured as IP:UDP_port, witness_port = UDP + 4.
     * This establishes the initial mesh; w_ident exchange populates the roster. */
    nodus_tcp_t *wtcp = (nodus_tcp_t *)w->tcp;
    for (int i = 0; i < w->server->config.seed_count; i++) {
        uint16_t seed_witness_port = w->server->config.seed_ports[i] + 4;
        const char *seed_ip = w->server->config.seed_nodes[i];

        /* Skip if already connected */
        nodus_tcp_conn_t *existing = nodus_tcp_find_by_addr(
            wtcp, seed_ip, seed_witness_port);
        if (existing && existing->state == NODUS_CONN_CONNECTED)
            continue;

        nodus_tcp_conn_t *conn = nodus_tcp_connect(wtcp, seed_ip, seed_witness_port);
        if (conn) {
            /* witness_id stays unknown until w_ident — upsert by address so
             * a later identified peer merges into this slot instead of
             * forking a duplicate entry. */
            char addr[256];
            snprintf(addr, sizeof(addr), "%s:%u", seed_ip, seed_witness_port);
            int pi = witness_peer_upsert(w, NULL, conn, addr);
            if (pi >= 0)
                w->peers[pi].last_attempt = nodus_time_now();
        }
    }

    fprintf(stderr, "%s: peer mesh init (roster=%u witnesses, seeds=%d, "
            "peers=%d)\n",
            LOG_TAG, w->roster.n_witnesses,
            w->server->config.seed_count, w->peer_count);
    return 0;
}

/* ── Periodic tick ───────────────────────────────────────────────── */

void nodus_witness_peer_tick(nodus_witness_t *w) {
    if (!w || !w->running) return;

    uint64_t now = nodus_time_now();
    nodus_tcp_t *wtcp = (nodus_tcp_t *)w->tcp;

    /* Clean up peers with dead connections */
    for (int i = 0; i < w->peer_count; i++) {
        if (w->peers[i].conn &&
            w->peers[i].conn->state == NODUS_CONN_CLOSED) {
            w->peers[i].conn = NULL;
            w->peers[i].identified = false;
        }
    }

    /* Reconnect to roster peers that have no active connection.
     * Witness TCP 4004 connections are NOT managed by Kademlia (which uses UDP 4000),
     * so the witness module must actively connect to discovered peers. */
    for (uint32_t i = 0; i < w->roster.n_witnesses; i++) {
        /* F17 A4 — skip self via witness_id comparison (no my_index). */
        if (memcmp(w->roster.witnesses[i].witness_id, w->my_id,
                    NODUS_T3_WITNESS_ID_LEN) == 0) continue;
        if (!w->roster.witnesses[i].active) continue;
        if (!w->roster.witnesses[i].address[0]) continue;

        /* Check if we already have a connected peer for this roster entry */
        int pi = find_peer_by_id(w, w->roster.witnesses[i].witness_id);
        if (pi >= 0 && w->peers[pi].conn &&
            w->peers[pi].conn->state == NODUS_CONN_CONNECTED)
            continue;

        /* Apply exponential backoff */
        if (pi >= 0) {
            uint64_t backoff = RECONNECT_BASE_SEC;
            if (w->peers[pi].connect_failures > 0) {
                int shift = w->peers[pi].connect_failures > RECONNECT_MAX_SHIFT
                            ? RECONNECT_MAX_SHIFT
                            : w->peers[pi].connect_failures;
                backoff <<= shift;
            }
            if (now - w->peers[pi].last_attempt < backoff) continue;
        }

        char ip[64];
        uint16_t port;
        if (parse_address(w->roster.witnesses[i].address,
                          ip, sizeof(ip), &port) != 0)
            continue;

        /* Check if already connected via witness TCP */
        nodus_tcp_conn_t *existing = nodus_tcp_find_by_addr(wtcp, ip, port);
        if (existing && existing->state == NODUS_CONN_CONNECTED) {
            if (pi >= 0) {
                w->peers[pi].conn = existing;
                w->peers[pi].identified = true;
                w->peers[pi].connect_failures = 0;
            }
            continue;
        }

        /* Initiate witness TCP connection (port 4004) */
        nodus_tcp_conn_t *conn = nodus_tcp_connect(wtcp, ip, port);
        if (!conn) {
            if (pi >= 0) {
                w->peers[pi].connect_failures++;
                w->peers[pi].last_attempt = now;
            }
            continue;
        }

        /* Merge-or-create via unified upsert: catches the seed-bootstrap
         * slot (zero id, same address) so reconnection adopts the slot
         * instead of forking a duplicate. */
        pi = witness_peer_upsert(w,
                                   w->roster.witnesses[i].witness_id,
                                   conn,
                                   w->roster.witnesses[i].address);

        if (pi >= 0) {
            /* Unconditionally refresh conn during reconnect — the old
             * slot's conn may be dead/closed and this is the authoritative
             * fresh connection just opened for this roster entry. */
            w->peers[pi].conn = conn;
            w->peers[pi].connect_failures = 0;
            w->peers[pi].last_attempt = now;
        }
    }

    /* Seed-bootstrap retry. The roster-driven reconnect loop above only
     * retries peers that already appear in w->roster — at fresh-cluster
     * startup the roster is {self} and everything else arrives via IDENT.
     * Seed-bootstrap entries created by peer_init carry witness_id=0
     * (not yet identified). If their initial TCP connect failed (e.g.,
     * the remote wasn't listening yet during a spawn race), they'd never
     * be retried: the roster reconnect skips them, so auth + IDENT can
     * never complete and the roster can never grow. Retry them here.
     * The hello send + auth handshake is driven by on_witness_connect
     * in nodus_server.c — gated on config.require_peer_auth, which must
     * be enabled for the witness mesh to form on a fresh cluster. */
    static const uint8_t zero_id_seed[NODUS_T3_WITNESS_ID_LEN] = {0};
    for (int i = 0; i < w->peer_count; i++) {
        if (w->peers[i].conn &&
            w->peers[i].conn->state == NODUS_CONN_CONNECTED)
            continue;
        if (memcmp(w->peers[i].witness_id, zero_id_seed,
                   NODUS_T3_WITNESS_ID_LEN) != 0)
            continue;  /* roster-linked; handled above */
        if (!w->peers[i].address[0]) continue;

        uint64_t backoff = RECONNECT_BASE_SEC;
        if (w->peers[i].connect_failures > 0) {
            int shift = w->peers[i].connect_failures > RECONNECT_MAX_SHIFT
                        ? RECONNECT_MAX_SHIFT
                        : w->peers[i].connect_failures;
            backoff <<= shift;
        }
        if (now - w->peers[i].last_attempt < backoff) continue;

        char ip[64];
        uint16_t port;
        if (parse_address(w->peers[i].address, ip, sizeof(ip), &port) != 0)
            continue;

        nodus_tcp_conn_t *existing = nodus_tcp_find_by_addr(wtcp, ip, port);
        if (existing && existing->state == NODUS_CONN_CONNECTED) {
            w->peers[i].conn = existing;
            w->peers[i].connect_failures = 0;
            continue;
        }

        nodus_tcp_conn_t *conn = nodus_tcp_connect(wtcp, ip, port);
        w->peers[i].last_attempt = now;
        if (!conn) {
            w->peers[i].connect_failures++;
            continue;
        }
        w->peers[i].conn = conn;
        w->peers[i].auth_state = PEER_AUTH_NONE;
    }

    /* Mark peers as identified when their TCP connection is established.
     * No w_ident exchange needed — roster already has witness_id and pubkey
     * from DHT registry. We match by IP address from the roster entry.
     * Skip peers with zero witness_id (seed peers not yet matched to roster). */
    static const uint8_t zero_id2[NODUS_T3_WITNESS_ID_LEN] = {0};
    for (int i = 0; i < w->peer_count; i++) {
        if (w->peers[i].identified) continue;
        if (!w->peers[i].conn) continue;
        if (w->peers[i].conn->state != NODUS_CONN_CONNECTED) continue;
        if (memcmp(w->peers[i].witness_id, zero_id2,
                   NODUS_T3_WITNESS_ID_LEN) == 0)
            continue;

        /* C-02: Send hello for Dilithium5 auth before w_ident.
         * If auth_state is NONE, start auth. If AUTH_OK, send w_ident. */
        if (w->peers[i].auth_state == PEER_AUTH_NONE) {
            /* Send hello with our identity */
            nodus_server_t *srv = (nodus_server_t *)w->server;
            uint8_t buf[8192];
            size_t len = 0;
            nodus_t2_hello(0, &srv->identity.pk, &srv->identity.node_id,
                           buf, sizeof(buf), &len);
            nodus_tcp_send(w->peers[i].conn, buf, len);
            w->peers[i].auth_state = PEER_AUTH_HELLO_SENT;
            continue;  /* Wait for challenge response */
        }

        if (w->peers[i].auth_state != PEER_AUTH_OK)
            continue;  /* Still authenticating */

        /* Connection established + authenticated — peer is identified via roster */
        w->peers[i].identified = true;

        /* Announce ourselves so the remote side can register us as a peer */
        nodus_witness_peer_send_ident(w, w->peers[i].conn);
    }
}

/* ── Connected count ─────────────────────────────────────────────── */

int nodus_witness_peer_connected_count(const nodus_witness_t *w) {
    if (!w) return 0;

    int count = 0;
    for (int i = 0; i < w->peer_count; i++) {
        if (w->peers[i].conn &&
            w->peers[i].conn->state == NODUS_CONN_CONNECTED &&
            w->peers[i].identified)
            count++;
    }
    return count;
}

/* ── Connection closed notification ──────────────────────────────── */

void nodus_witness_peer_conn_closed(nodus_witness_t *w,
                                     struct nodus_tcp_conn *conn) {
    if (!w || !conn) return;

    for (int i = 0; i < w->peer_count; i++) {
        if (w->peers[i].conn == conn) {
            w->peers[i].conn = NULL;
            w->peers[i].identified = false;
        }
    }
}

/* ── Close ───────────────────────────────────────────────────────── */

void nodus_witness_peer_close(nodus_witness_t *w) {
    if (!w) return;

    /* Peer connections are managed by the server's TCP transport
       and will be cleaned up when the server shuts down.
       Just clear our references. */
    for (int i = 0; i < w->peer_count; i++) {
        w->peers[i].conn = NULL;
        w->peers[i].identified = false;
    }
    w->peer_count = 0;

    fprintf(stderr, "%s: peer mesh closed\n", LOG_TAG);
}
