/**
 * Nodus — the native tools' network identity (DHT v2 package 3c)
 *
 * Since the client session moved onto the SecretConnection layer
 * (nodus_client_init, nodus/include/nodus/nodus.h), a client needs, for
 * every connection, the pin of the server it means to talk to and the id of
 * the chain it means to talk on. A native tool (nodus-cli, nodus-light,
 * nodus-circ, the faucet, the explorer, the bench / harness tools) gets
 * both from this module.
 *
 * Decision docs/plans/decisions/2026-10-24-dht-v2-tool-network-identity.md
 * (operator: "Both"): a NETWORK FILE is the normal source; the flags
 * `--pin <128 hex>` and `--chain <64 hex>` override it; with neither a file
 * nor flags the tool refuses before any byte is sent (Kurultay #43 O-6,
 * decisions/2026-10-23-kurultay-43-summary.md).
 *
 * THE FILE (JSON; json-c, as nodus_witness_network_file.c — without
 * NODUS_HAS_JSONC a file cannot be read and only the flags work):
 *
 *   {"chain_id": "<64 lowercase hex>",
 *    "nodes": [{"ip": "<IPv4 literal>", "port": <1..65535>,
 *               "fp": "<128 lowercase hex>"}, ...]}
 *
 * It mirrors the web wallet's network settings (chain + endpoints + pins,
 * web-wallet/src/nodus/send-module.js) but each fingerprint is written next to
 * its ip:port. WHAT THE BINDING IS: nodus_tool_net_resolve() and a
 * single-server nodus_tool_net_fill() give the client exactly that endpoint's
 * pin. nodus_client holds ONE pin SET per config, though: with more than one
 * server (nodus_tool_net_fill with server_count > 1, nodus_tool_net_fill_all)
 * a listed node's key is accepted on ANY listed endpoint, as in the web
 * wallet — a redirect can only land on another listed node. The fingerprint is SHA3-512 of the node's ML-DSA-87 public key
 * (nodus_fingerprint(); the same 64 bytes as a node id).
 *
 * Strict: any other key, a chain id / fp that is not exactly 64 / 128
 * LOWERCASE hex digits (or is all zero), an ip that is not a dotted-quad
 * IPv4 literal, a port outside 1..65535, an ip:port listed twice, an empty
 * node list, or more than NODUS_TOOL_NET_MAX_NODES nodes refuses the WHOLE
 * file, with the reason in the error text.
 *
 * Where the file is: the `--network <path>` flag, else the environment
 * variable NODUS_NETWORK. There is no default path.
 *
 * @file nodus_tool_network.h
 */

#ifndef NODUS_TOOL_NETWORK_H
#define NODUS_TOOL_NETWORK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "nodus/nodus.h"
#include "nodus/nodus_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Most nodes a file may list: the Tier-3 witness cap (nodus_types.h). */
#define NODUS_TOOL_NET_MAX_NODES   NODUS_T3_MAX_WITNESSES

/** Size an error buffer should have. */
#define NODUS_TOOL_NET_ERR_SIZE    192

/** Environment variable that names the network file when no flag does. */
#define NODUS_TOOL_NET_ENV         "NODUS_NETWORK"

typedef struct {
    char        ip[16];             /* dotted quad, NUL-terminated */
    uint16_t    port;
    nodus_key_t fp;
} nodus_tool_net_node_t;

/**
 * The resolved network identity of one tool process. Zero-initialise with
 * nodus_tool_net_init(). It is also the storage the pin list of every
 * nodus_client_config_t filled by nodus_tool_net_fill*() points into
 * (pinned_server_fps is not copied by nodus_client_init): keep it alive as
 * long as any such client.
 */
typedef struct {
    /* from the file */
    bool                  has_file;
    uint8_t               chain[NODUS_CLIENT_CHAIN_ID_SIZE];
    int                   node_count;
    nodus_tool_net_node_t nodes[NODUS_TOOL_NET_MAX_NODES];
    /* from the flags */
    bool                  has_pin_flag;
    nodus_key_t           pin_flag;
    bool                  has_chain_flag;
    uint8_t               chain_flag[NODUS_CLIENT_CHAIN_ID_SIZE];
    /* pin storage handed to client configs (distinct values) */
    nodus_key_t           pins[NODUS_TOOL_NET_MAX_NODES + 1];
    int                   pin_count;
} nodus_tool_net_t;

/** Zero `t`. */
void nodus_tool_net_init(nodus_tool_net_t *t);

/**
 * Parse file text (len bytes) into `t`'s file part. On any refusal `t`'s
 * file part is cleared and `err` (NODUS_TOOL_NET_ERR_SIZE) names the reason.
 * Needs json-c; without it returns -1 ("built without json-c").
 * @return 0 / -1.
 */
int nodus_tool_net_parse(nodus_tool_net_t *t, const char *text, size_t len,
                         char *err, size_t err_size);

/** Read `path` (at most 1 MiB) and nodus_tool_net_parse() it. @return 0 / -1. */
int nodus_tool_net_load_file(nodus_tool_net_t *t, const char *path,
                             char *err, size_t err_size);

/** `--pin`: exactly 128 lowercase hex digits, not all zero. @return 0 / -1. */
int nodus_tool_net_set_pin_hex(nodus_tool_net_t *t, const char *hex,
                               char *err, size_t err_size);

/** `--chain`: exactly 64 lowercase hex digits, not all zero. @return 0 / -1. */
int nodus_tool_net_set_chain_hex(nodus_tool_net_t *t, const char *hex,
                                 char *err, size_t err_size);

/**
 * Set a tool's identity from its command line values: `network_path` (the
 * `--network` flag, or NULL → the NODUS_NETWORK environment variable, or no
 * file), `pin_hex` / `chain_hex` (the flags, or NULL). A file that is named
 * and bad refuses even when both flags are given. No file and no flags is
 * NOT an error here — the refusal comes at resolve time, naming what is
 * missing. @return 0 / -1 (err set).
 */
int nodus_tool_net_open(nodus_tool_net_t *t, const char *network_path,
                        const char *pin_hex, const char *chain_hex,
                        char *err, size_t err_size);

/**
 * The chain id alone: the `--chain` flag, else the file's. Neither → -1,
 * err names it. (For a caller that already holds its own server pin.)
 */
int nodus_tool_net_chain(const nodus_tool_net_t *t,
                         uint8_t chain_out[NODUS_CLIENT_CHAIN_ID_SIZE],
                         char *err, size_t err_size);

/**
 * The pin and chain id for one connection to ip:port. Pin: the `--pin` flag,
 * else the file's entry for exactly that ip:port. Chain id: the `--chain`
 * flag, else the file's. Either missing → -1, err names which and why.
 * Either output may be NULL.
 */
int nodus_tool_net_resolve(const nodus_tool_net_t *t, const char *ip,
                           uint16_t port, nodus_key_t *pin_out,
                           uint8_t chain_out[NODUS_CLIENT_CHAIN_ID_SIZE],
                           char *err, size_t err_size);

/**
 * Complete a client config whose servers[0..server_count) are set: resolves
 * every server's pin, fills pinned_server_fps / pinned_server_fp_count (into
 * `t`, de-duplicated) and expected_chain_id / has_expected_chain_id. On
 * -1 nothing of `cfg` is modified.
 */
int nodus_tool_net_fill(nodus_tool_net_t *t, nodus_client_config_t *cfg,
                        char *err, size_t err_size);

/**
 * For a tool that connects to "any of the nodes": set cfg->servers /
 * server_count from the file's node list (in file order, at most
 * NODUS_CLIENT_MAX_SERVERS — the client's own cap), then
 * nodus_tool_net_fill(). Needs a file. The resulting pin list is a SET: any
 * listed node's key is accepted on any listed endpoint (not per-endpoint).
 * Keeping the per-endpoint binding would need a per-server pin in
 * nodus_client_config_t / the connect loop (nodus_client.c, not 3c's), or
 * one single-server client per node.
 */
int nodus_tool_net_fill_all(nodus_tool_net_t *t, nodus_client_config_t *cfg,
                            char *err, size_t err_size);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_TOOL_NETWORK_H */
