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
#include "witness/nodus_witness_bft.h"
#include "witness/nodus_witness_committee.h"   /* Task 59 — committee roster */
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_merkle.h"
#include "witness/nodus_witness_handlers.h"
#include "protocol/nodus_tier3.h"
#include "protocol/nodus_tier2.h"
#include "server/nodus_server.h"
#include "transport/nodus_tcp.h"
#include "crypto/nodus_sign.h"
#include "protocol/nodus_cbor.h"
#include "core/nodus_storage.h"
#include "core/nodus_value.h"
#include "witness/nodus_witness_sync.h"
#include "crypto/utils/qgp_log.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "crypto/utils/qgp_safe_string.h"   /* Phase 03: unsafe-string poison guard */

#define LOG_TAG "WITNESS-PEER"

/* Forward declarations */
static int send_rost_q(nodus_witness_t *w, struct nodus_tcp_conn *conn);

/* Reconnect timing */
#define RECONNECT_BASE_SEC   5
#define RECONNECT_MAX_SHIFT  5      /* Max exponential backoff: 2^5 = 32x */

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

    /* No match → allocate new slot if space is available */
    if (pi < 0) {
        if (w->peer_count >= NODUS_T3_MAX_WITNESSES) return -1;
        pi = w->peer_count++;
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

        nodus_witness_roster_entry_t *entry =
            &out->witnesses[out->n_witnesses];
        memcpy(entry->witness_id, peer->witness_id, NODUS_T3_WITNESS_ID_LEN);
        int ri = nodus_witness_roster_find(&w->roster, peer->witness_id);
        if (ri >= 0)
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
        nodus_witness_merkle_compute_state_root(w, msg.ident.state_root);
    }
    msg.ident.current_view = w->current_view;
    msg.ident.roster_size = w->roster.n_witnesses;
    msg.ident.ts_local = (uint64_t)time(NULL);  /* Phase 10 / Task 10.4 */
    msg.ident.has_block_height = true;

    /* CC-OPS-002 / Q14 — advertise binary + schema version so peers can
     * detect skew at handshake time instead of via silent state_root
     * divergence post-first-block. Packed version: MAJOR<<16 | MINOR<<8 | PATCH. */
    msg.ident.nodus_version =
        ((uint32_t)NODUS_VERSION_MAJOR << 16) |
        ((uint32_t)NODUS_VERSION_MINOR <<  8) |
        ((uint32_t)NODUS_VERSION_PATCH);
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

static void witness_chain_quorum_observe(nodus_witness_t *w,
                                          const uint8_t *peer_id,
                                          const uint8_t *peer_chain_id) {
    if (!w || !peer_id || !peer_chain_id) return;
    if (w->quarantined) return;  /* Already decided — sticky */

    /* Skip if we are still pre-genesis (all-zero chain_id) */
    static const uint8_t zero[32] = {0};
    if (memcmp(w->chain_id, zero, 32) == 0) return;
    /* Skip if peer is pre-genesis (no opinion) */
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
        w->peers[pi].identified = true;
        w->peers[pi].connect_failures = 0;

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

            /* View sync: adopt higher view from peer.
             * Prevents leader election mismatch after restart.
             * Bounded: reject jumps > 10000 to prevent manipulation.
             * current_view is not persisted — resets to 0 on restart.
             * 10000 ~= 14 hours of continuous leader failure at 5s intervals. */
            if (ident->current_view > w->current_view) {
                uint32_t delta = ident->current_view - w->current_view;
                if (delta <= 10000) {
                    QGP_LOG_INFO(LOG_TAG, "adopting higher view %u from peer "
                            "(was %u)", ident->current_view, w->current_view);
                    w->current_view = ident->current_view;
                } else {
                    QGP_LOG_WARN(LOG_TAG, "rejecting view jump "
                            "%u -> %u (delta=%u > 10000)",
                            w->current_view, ident->current_view, delta);
                }
            }
        }
    }

    /* Trigger sync check — peer may be ahead of us */
    nodus_witness_sync_check(w);

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

/* ── Forward request (non-leader → leader) ───────────────────────── */

int nodus_witness_peer_handle_fwd_req(nodus_witness_t *w,
                                      const nodus_t3_msg_t *msg) {
    if (!w || !msg) return -1;

    const nodus_t3_fwd_req_t *fwd = &msg->fwd_req;

    /* Force roster swap if pending */
    if (w->pending_roster_ready &&
        w->pending_roster.n_witnesses != w->roster.n_witnesses) {
        memcpy(&w->roster, &w->pending_roster, sizeof(w->roster));
        memcpy(&w->bft_config, &w->pending_bft_config, sizeof(w->bft_config));
        w->pending_roster_ready = false;
        w->my_index = nodus_witness_roster_find(&w->roster, w->my_id);
    }

    /* Only leader handles forward requests */
    if (!nodus_witness_bft_is_leader(w)) {
        fprintf(stderr, "%s: w_fwd_req but not leader\n", LOG_TAG);
        return -1;
    }

    if (!fwd->tx_data || fwd->tx_len == 0 ||
        fwd->tx_len > NODUS_T3_MAX_TX_SIZE) {
        fprintf(stderr, "%s: w_fwd_req invalid tx_data\n", LOG_TAG);
        return -1;
    }

    fprintf(stderr, "%s: w_fwd_req (tx_len=%u, fee=%lu)\n",
            LOG_TAG, fwd->tx_len, (unsigned long)fwd->fee);

    /* Extract nullifiers from tx_data for mempool entry.
     * DNAC serialization: [version(1)] [type(1)] [timestamp(8)] [tx_hash(64)]
     *                     [input_count(1)] [inputs...]
     * Each input: [nullifier(64)] [amount(8)] */
    const size_t input_count_offset = 1 + 1 + 8 + NODUS_T3_TX_HASH_LEN;

    if (fwd->tx_len < 2) return -1;
    uint8_t tx_type = fwd->tx_data[1];
    uint8_t nullifiers[NODUS_T3_MAX_TX_INPUTS][NODUS_T3_NULLIFIER_LEN];
    uint8_t nullifier_count = 0;

    if (tx_type != NODUS_W_TX_GENESIS) {
        if (fwd->tx_len < input_count_offset + 1) return -1;
        nullifier_count = fwd->tx_data[input_count_offset];
        if (nullifier_count > NODUS_T3_MAX_TX_INPUTS) return -1;

        size_t offset = input_count_offset + 1;
        for (int i = 0; i < nullifier_count; i++) {
            if (offset + NODUS_T3_NULLIFIER_LEN > fwd->tx_len)
                return -1;
            memcpy(nullifiers[i], fwd->tx_data + offset,
                   NODUS_T3_NULLIFIER_LEN);
            offset += NODUS_T3_NULLIFIER_LEN + 8 + 64; /* nullifier + amount + token_id */
        }
    }

    /* Phase 7 / Task 7.5 — forwarded genesis goes through batch-of-1
     * BFT round. Phase 6 commit_genesis dispatch (Task 7.6) handles
     * chain DB bootstrap at commit time. */
    if (tx_type == NODUS_W_TX_GENESIS) {
        fprintf(stderr, "%s: forwarded genesis TX — batch-of-1 BFT path\n",
                LOG_TAG);

        nodus_witness_mempool_entry_t *e = calloc(1, sizeof(*e));
        if (!e) return -1;
        memcpy(e->tx_hash, fwd->tx_hash, NODUS_T3_TX_HASH_LEN);
        e->tx_type = tx_type;
        e->nullifier_count = nullifier_count;
        for (int i = 0; i < nullifier_count; i++)
            memcpy(e->nullifiers[i], nullifiers[i], NODUS_T3_NULLIFIER_LEN);
        e->tx_data = malloc(fwd->tx_len);
        if (!e->tx_data) { free(e); return -1; }
        memcpy(e->tx_data, fwd->tx_data, fwd->tx_len);
        e->tx_len = fwd->tx_len;
        if (fwd->client_pubkey)
            memcpy(e->client_pubkey, fwd->client_pubkey, NODUS_PK_BYTES);
        if (fwd->client_sig)
            memcpy(e->client_sig, fwd->client_sig, NODUS_SIG_BYTES);
        e->fee = fwd->fee;
        e->client_conn = NULL;
        e->is_forwarded = true;
        memcpy(e->forwarder_id, fwd->forwarder_id, NODUS_T3_WITNESS_ID_LEN);

        nodus_witness_mempool_entry_t *entries[1] = { e };
        int rc = nodus_witness_bft_start_round_from_entries(w, entries, 1);
        if (rc != 0) {
            nodus_witness_mempool_entry_free(e);
        }
        return rc;
    }

    /* Add forwarded TX to mempool instead of immediate BFT round */
    nodus_witness_mempool_entry_t *entry = calloc(1, sizeof(*entry));
    if (!entry) return -1;

    memcpy(entry->tx_hash, fwd->tx_hash, NODUS_T3_TX_HASH_LEN);
    entry->nullifier_count = nullifier_count;
    for (int i = 0; i < nullifier_count; i++)
        memcpy(entry->nullifiers[i], nullifiers[i], NODUS_T3_NULLIFIER_LEN);
    entry->tx_type = tx_type;
    entry->tx_data = malloc(fwd->tx_len);
    if (!entry->tx_data) { free(entry); return -1; }
    memcpy(entry->tx_data, fwd->tx_data, fwd->tx_len);
    entry->tx_len = fwd->tx_len;
    if (fwd->client_pubkey)
        memcpy(entry->client_pubkey, fwd->client_pubkey, NODUS_PK_BYTES);
    if (fwd->client_sig)
        memcpy(entry->client_sig, fwd->client_sig, NODUS_SIG_BYTES);
    entry->fee = fwd->fee;
    entry->client_conn = NULL;  /* No direct client conn for forwarded TX */
    entry->is_forwarded = true;
    memcpy(entry->forwarder_id, fwd->forwarder_id, NODUS_T3_WITNESS_ID_LEN);

    int rc = nodus_witness_mempool_add(&w->mempool, entry);
    if (rc != 0) {
        fprintf(stderr, "%s: fwd_req mempool add failed: %d\n", LOG_TAG, rc);
        nodus_witness_mempool_entry_free(entry);
    }

    return rc;
}

/* ── Forward response (leader → forwarder) ───────────────────────── */

int nodus_witness_peer_handle_fwd_rsp(nodus_witness_t *w,
                                      const nodus_t3_msg_t *msg) {
    if (!w || !msg) return -1;

    const nodus_t3_fwd_rsp_t *rsp = &msg->fwd_rsp;

    fprintf(stderr, "%s: w_fwd_rsp status=%u (%u witness sigs)\n",
            LOG_TAG, rsp->status, rsp->witness_count);

    /* Match pending forward by tx_hash */
    int pf_idx = -1;
    for (int i = 0; i < NODUS_W_MAX_PENDING_FWD; i++) {
        if (w->pending_forwards[i].active &&
            memcmp(w->pending_forwards[i].tx_hash, rsp->tx_hash,
                   NODUS_T3_TX_HASH_LEN) == 0) {
            pf_idx = i;
            break;
        }
    }
    if (pf_idx < 0) {
        fprintf(stderr, "%s: w_fwd_rsp no matching pending forward\n",
                LOG_TAG);
        return -1;
    }

    struct nodus_tcp_conn *client_conn = w->pending_forwards[pf_idx].client_conn;
    uint32_t client_txn_id = w->pending_forwards[pf_idx].client_txn_id;

    /* Clear pending forward slot */
    w->pending_forwards[pf_idx].active = false;
    w->pending_forwards[pf_idx].client_conn = NULL;
    if (w->pending_forward_count > 0) w->pending_forward_count--;

    if (!client_conn) {
        fprintf(stderr, "%s: w_fwd_rsp client conn gone\n", LOG_TAG);
        return -1;
    }

    /* Send spend result to original client. Phase 13 / Task 13.2 — the
     * fwd_rsp wire now carries block_height / tx_index / chain_id from
     * the leader, so the forwarder can pass the full receipt through to
     * the client instead of hardcoding 0/0. */
    if (rsp->status == 0) {
        nodus_witness_mempool_entry_t stack_entry;
        memset(&stack_entry, 0, sizeof(stack_entry));
        memcpy(stack_entry.tx_hash, rsp->tx_hash, NODUS_T3_TX_HASH_LEN);
        stack_entry.client_conn = client_conn;
        stack_entry.client_txn_id = client_txn_id;
        stack_entry.committed_block_height = rsp->block_height;
        stack_entry.committed_tx_index = rsp->tx_index;
        nodus_witness_send_spend_result(w, &stack_entry, 0, NULL);
    } else {
        /* Send error response */
        uint8_t err_buf[512];
        size_t err_len = 0;
        nodus_t2_error(client_txn_id, NODUS_ERR_PROTOCOL_ERROR,
                        "consensus rejected",
                        err_buf, sizeof(err_buf), &err_len);
        if (err_len > 0)
            nodus_tcp_send(client_conn, err_buf, err_len);
    }

    fprintf(stderr, "%s: forwarded spend result to client (txn=%u)\n",
            LOG_TAG, client_txn_id);
    return 0;
}

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
    rsp.txn_id = ++w->next_txn_id;
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
        w->my_index = nodus_witness_roster_find(&w->roster, w->my_id);

        /* Recompute BFT config for new roster size */
        nodus_witness_bft_config_init(&w->bft_config,
                                       w->roster.n_witnesses);

        QGP_LOG_INFO(LOG_TAG, "roster gossip merged: %u -> %u witnesses, "
                "quorum=%u, my_index=%d",
                old_count, w->roster.n_witnesses,
                w->bft_config.quorum, w->my_index);
    }

    return 0;
}

/* ── Peer mesh initialization ────────────────────────────────────── */

int nodus_witness_peer_init(nodus_witness_t *w) {
    if (!w) return -1;

    /* Dynamic roster — initial build from DHT registry + witness peers.
     * At init time, witness TCP connections may not be established yet.
     * Full roster will be built on first epoch tick (60s). */
    nodus_witness_rebuild_roster_from_peers(w, &w->roster);
    nodus_witness_bft_config_init(&w->bft_config, w->roster.n_witnesses);

    /* Update my_index in roster */
    w->my_index = -1;
    for (uint32_t i = 0; i < w->roster.n_witnesses; i++) {
        if (memcmp(w->roster.witnesses[i].witness_id,
                   w->my_id, NODUS_T3_WITNESS_ID_LEN) == 0) {
            w->my_index = (int)i;
            break;
        }
    }

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
        if ((int)i == w->my_index) continue;
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

    /* Also clear any BFT round state referencing this conn */
    if (w->round_state.client_conn == conn)
        w->round_state.client_conn = NULL;

    /* H-15: Clear pending forwards referencing this connection */
    for (int pfi = 0; pfi < NODUS_W_MAX_PENDING_FWD; pfi++) {
        if (w->pending_forwards[pfi].active &&
            w->pending_forwards[pfi].client_conn == conn) {
            w->pending_forwards[pfi].active = false;
            w->pending_forwards[pfi].client_conn = NULL;
            if (w->pending_forward_count > 0) w->pending_forward_count--;
        }
    }

    /* Remove mempool entries for this connection */
    nodus_witness_mempool_remove_by_conn(&w->mempool, conn);

    /* Clear batch_entries refs to this conn (active round) */
    for (int bi = 0; bi < w->round_state.batch_count; bi++) {
        if (w->round_state.batch_entries[bi] &&
            w->round_state.batch_entries[bi]->client_conn == conn) {
            w->round_state.batch_entries[bi]->client_conn = NULL;
        }
    }
}

/* ── Phase 13 / Task 59 — Committee-snapshot BFT roster ──────────── */

/**
 * Return the BFT peer set (committee) authoritative for a given block
 * height. Thin pass-through over the Task 53 committee cache.
 *
 * Invariants:
 *   - For every block height within a single epoch, all 7 witnesses
 *     derive bit-identical committees from the same committed DB state
 *     (design §3.6: post-commit lookback + state_seed tiebreak).
 *   - The underlying cache is keyed on e_start; the transition to a
 *     new epoch is observed transparently on the first query whose
 *     block_height crosses the boundary.
 *   - Mid-epoch STAKE / DELEGATE / UNSTAKE mutate the validator table
 *     but NOT the frozen committee membership — the cache intentionally
 *     ignores them. BFT quorum on block N therefore never races a
 *     mid-block stake change.
 */
int nodus_witness_peer_current_set(nodus_witness_t *w,
                                     uint64_t block_height,
                                     nodus_committee_member_t *out,
                                     int max_entries,
                                     int *count_out) {
    if (!w || !out || !count_out || max_entries <= 0) return -1;
    return nodus_committee_get_for_block(w, block_height, out,
                                           max_entries, count_out);
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
