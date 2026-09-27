/**
 * @file shared/dnac/cmt_p2p_nodeinfo.h
 * @brief cometbft @709fd12b `p2p/node_info.go` ported to C — the
 *        `DefaultNodeInfo` two peers exchange inside the secret connection
 *        (transport.go:541-581), its `Validate`, its `CompatibleWith`, and
 *        the `tendermint.p2p.DefaultNodeInfo` protobuf codec.
 *
 * ═══ ACTIVATION: INACTIVE ═══════════════════════════════════════════════
 * Phase F3 of fleet P2P-PORT (docs/plans/2026-09-26-p2p-port-design.md §2
 * row "node_info.go", §9). First consumer: cmt_p2p_transport (same phase).
 * Additive only.
 * ════════════════════════════════════════════════════════════════════════
 *
 * ── WIRE (DEVIATION R-P2P-2: the tree's own codec, byte-identical field
 *    numbers) ─────────────────────────────────────────────────────────────
 * proto/tendermint/p2p/types.proto:14-34, marshalled as types.pb.go:399-
 * 546 does and parsed as :786-1316 does:
 *   ProtocolVersion      { uint64 p2p = 1; uint64 block = 2; uint64 app = 3; }
 *   DefaultNodeInfo      { ProtocolVersion protocol_version = 1 (always);
 *                          string default_node_id = 2; string listen_addr = 3;
 *                          string network = 4; string version = 5;
 *                          bytes channels = 6; string moniker = 7;
 *                          DefaultNodeInfoOther other = 8 (always); }
 *   DefaultNodeInfoOther { string tx_index = 1; string rpc_address = 2; }
 * Scalars / strings / bytes are omit-empty; the two embedded messages are
 * `nullable=false` and written even when empty (`0a 00`, `42 00`). The
 * decoder takes any field order, skips unknown fields, lets the last
 * scalar / string win and MERGES a repeated embedded message (the
 * generated code unmarshals into the existing value, :951, :1178).
 * No UTF-8 check on strings (gogoproto's generated Unmarshal does none).
 *
 * ── VALUES THIS PORT PUTS IN (host-supplied, see `cmt_p2p_node_info_make`)
 *   · protocol_version.p2p = CMT_P2P_PROTOCOL_VERSION (8) — the dispatch;
 *     the same number the secret connection carries as N9 `proto_ver`.
 *     NOTE: `CompatibleWith` does NOT compare the P2P version
 *     (node_info.go:185-193 compares Block and Network only). A peer on
 *     another P2P version is refused one layer lower, by the secret
 *     connection's HELLO check (cmt_p2p_secret.h rows 1-2, N9).
 *   · protocol_version.block / .app — the host's (node.go:938-942 passes
 *     `state.Version.Consensus`; CMT_BLOCK_PROTOCOL = 11, cmt_block.h:210).
 *   · network — the 32-byte version-3 chain id as 64 lowercase hex digits
 *     (`cmt_p2p_network_from_chain_id`); a joiner that has no chain yet
 *     puts its genesis pin there — the same 32 bytes. p2p-port design §2.
 *   · version, moniker, listen_addr, channels, other — the host's
 *     (node.go:936-975); F5 fills them. `listen_addr` must be an IP
 *     literal (R-P2P-24, cmt_p2p_netaddr.h).
 *
 * ── STORAGE ────────────────────────────────────────────────────────────
 * The reference's strings are Go strings of any length, bounded only by
 * the 10240-byte message (`maxNodeInfoSize`, :16). Here every string /
 * bytes field is a span into one 10240-byte arena inside the struct, so a
 * decoded NodeInfo holds exactly what the reference would, with no
 * per-field cap of its own. Read a field with `cmt_p2p_node_info_get`.
 *
 * ── DETERMINISM ────────────────────────────────────────────────────────
 * Node-local transport data (design §6 D1); pure functions; no clock.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef CMT_P2P_NODEINFO_H
#define CMT_P2P_NODEINFO_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "cmt_tmhash.h"
#include "cmt_p2p_netaddr.h"

#ifdef __cplusplus
extern "C" {
#endif

/** node_info.go:16 `maxNodeInfoSize` (also `MaxNodeInfoSize()`, :21-23). */
#define CMT_P2P_MAX_NODE_INFO_SIZE 10240
/** node_info.go:17 `maxNumChannels`. */
#define CMT_P2P_MAX_NUM_CHANNELS   16
/** The P2P protocol version this port speaks (dispatch; equals the
 *  secret connection's N9 `proto_ver`). The reference's
 *  `version.P2PProtocol` is 8 as well (version/version.go). */
#define CMT_P2P_PROTOCOL_VERSION   8u
/** 32-byte chain id → 64 hex digits + NUL. */
#define CMT_P2P_NETWORK_CAP        65

/** node_info.go:49-53 `ProtocolVersion`. */
typedef struct {
    uint64_t p2p;
    uint64_t block;
    uint64_t app;
} cmt_p2p_protocol_version_t;

/** The string / bytes fields of DefaultNodeInfo (+ Other). */
typedef enum {
    CMT_P2P_NI_ID = 0,          /* default_node_id  (2)          */
    CMT_P2P_NI_LISTEN_ADDR,     /* listen_addr      (3)          */
    CMT_P2P_NI_NETWORK,         /* network          (4)          */
    CMT_P2P_NI_VERSION,         /* version          (5)          */
    CMT_P2P_NI_CHANNELS,        /* channels         (6, bytes)   */
    CMT_P2P_NI_MONIKER,         /* moniker          (7)          */
    CMT_P2P_NI_TX_INDEX,        /* other.tx_index   (8.1)        */
    CMT_P2P_NI_RPC_ADDRESS,     /* other.rpc_address (8.2)       */
    CMT_P2P_NI_NUM_FIELDS
} cmt_p2p_ni_field_t;

typedef struct {
    uint32_t off;
    uint32_t len;
} cmt_p2p_ni_span_t;

/** node_info.go:79-102 `DefaultNodeInfo` (+ `DefaultNodeInfoOther`).
 *  ≈ 10.3 KB: heap or static, not the stack. */
typedef struct {
    cmt_p2p_protocol_version_t protocol_version;
    cmt_p2p_ni_span_t f[CMT_P2P_NI_NUM_FIELDS];
    uint8_t  arena[CMT_P2P_MAX_NODE_INFO_SIZE];
    size_t   used;
} cmt_p2p_node_info_t;

/** An empty NodeInfo (every field ""). */
void cmt_p2p_node_info_init(cmt_p2p_node_info_t *ni);

/** Set one string / bytes field (a copy into the arena).
 *  @return CMT_OK; CMT_REJECT when the arena is full; CMT_FAULT on NULL. */
int cmt_p2p_node_info_set(cmt_p2p_node_info_t *ni, cmt_p2p_ni_field_t f,
                          const void *bytes, size_t len);

/** Set a field from a NUL-terminated string. */
int cmt_p2p_node_info_set_str(cmt_p2p_node_info_t *ni, cmt_p2p_ni_field_t f,
                              const char *s);

/** A field's bytes (NOT NUL-terminated) and length. Never NULL. */
const uint8_t *cmt_p2p_node_info_get(const cmt_p2p_node_info_t *ni,
                                     cmt_p2p_ni_field_t f, size_t *len);

/** True when field `f` equals the `len` bytes of `s`. */
bool cmt_p2p_node_info_field_eq(const cmt_p2p_node_info_t *ni,
                                cmt_p2p_ni_field_t f,
                                const void *s, size_t len);

/** The chain id as `Network`: 64 lowercase hex digits + NUL. */
void cmt_p2p_network_from_chain_id(const uint8_t chain_id[32],
                                   char out[CMT_P2P_NETWORK_CAP]);

/**
 * The values `makeNodeInfo` (node.go:928-975) assembles, from the host.
 * Every string NUL-terminated; `channels` is the byte list.
 */
typedef struct {
    uint64_t       block_version;       /* state.Version.Consensus.Block */
    uint64_t       app_version;         /* state.Version.Consensus.App   */
    const char    *node_id;             /* nodeKey.ID()                  */
    const uint8_t *chain_id;            /* 32 bytes → Network            */
    const char    *version;             /* version.TMCoreSemVer → ours   */
    const uint8_t *channels;
    size_t         n_channels;
    const char    *moniker;
    const char    *tx_index;            /* "on" / "off" / ""             */
    const char    *rpc_address;
    const char    *listen_addr;         /* external or listen address    */
} cmt_p2p_node_info_params_t;

/**
 * node.go:928-975 `makeNodeInfo` minus the reactor lists (the host passes
 * the channels): fills `ni` and runs `Validate` (:973-974).
 * @return CMT_P2P_ERR_NONE; CMT_P2P_ERR_REJECTED_NODE_INFO_INVALID when
 *         Validate refuses; CMT_REJECT when it does not fit the arena;
 *         CMT_FAULT on NULL.
 */
int cmt_p2p_node_info_make(cmt_p2p_node_info_t *ni,
                           const cmt_p2p_node_info_params_t *p);

/** node_info.go:122-174 `Validate`.
 *  @return CMT_P2P_ERR_NONE or CMT_P2P_ERR_REJECTED_NODE_INFO_INVALID;
 *          CMT_FAULT on NULL / allocation failure. */
int cmt_p2p_node_info_validate(const cmt_p2p_node_info_t *ni);

/** node_info.go:179-215 `CompatibleWith` — `ours` against `other`: same
 *  Block version, same Network, and (unless `ours` has no channels) one
 *  channel in common. @return CMT_P2P_ERR_NONE or
 *  CMT_P2P_ERR_REJECTED_INCOMPATIBLE; CMT_FAULT on NULL. */
int cmt_p2p_node_info_compatible_with(const cmt_p2p_node_info_t *ours,
                                      const cmt_p2p_node_info_t *other);

/** node_info.go:221-224 `NetAddress` — ID @ self-reported listen_addr.
 *  @return as `cmt_p2p_netaddr_new_string`. */
int cmt_p2p_node_info_net_address(const cmt_p2p_node_info_t *ni,
                                  cmt_p2p_netaddr_t *out);

/** node_info.go:226-228 `HasChannel`. */
bool cmt_p2p_node_info_has_channel(const cmt_p2p_node_info_t *ni,
                                   uint8_t ch_id);

/** types.pb.go:437-500 `DefaultNodeInfo.MarshalToSizedBuffer` (+ :399-420,
 *  :522-546). Bare message bytes (the caller delimits it).
 *  @return CMT_OK; CMT_REJECT if it does not fit `cap`; CMT_FAULT. */
int cmt_p2p_node_info_marshal(const cmt_p2p_node_info_t *ni, uint8_t *out,
                              size_t cap, size_t *out_len);

/** types.pb.go:893-1202 `DefaultNodeInfo.Unmarshal` (+ :786-892,
 *  :1203-1316) into a freshly initialised `ni`.
 *  @return CMT_OK; CMT_REJECT (malformed / larger than the arena);
 *          CMT_FAULT on NULL. */
int cmt_p2p_node_info_unmarshal(const uint8_t *in, size_t len,
                                cmt_p2p_node_info_t *ni);

#ifdef __cplusplus
}
#endif

#endif /* CMT_P2P_NODEINFO_H */
