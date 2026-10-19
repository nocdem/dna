/**
 * @file nodus/tools/nodus_light_checkpoint.h
 * @brief nodus-light's compiled network table: the chain id, the default
 *        pinned nodes (TCP 4001) and the RELEASE DEFAULT CHECKPOINT.
 *
 * Governing records: docs/plans/decisions/2026-10-16-kurultay-25-summary.md
 *   · K25-1 (operator 2026-10-16, "3"): the trust root is BOTH a default
 *     checkpoint carried by the release AND operator input from any source
 *     the operator chooses (`nodus-light run --trust-height H --trust-hash
 *     HEX`), with no approval from us and no new release needed. The
 *     "≥ 2 peers agree" check of item 9 is a consistency check only, never
 *     the root.
 *   · item 8: a light provider is a PINNED 4001 session, never unpinned.
 * Nothing in this file is a consensus value: it decides what ONE light
 * client asks and starts from.
 *
 * ── THE NODES ──────────────────────────────────────────────────────────
 * Copied from web-wallet/src/nodus/send-module.js:88-110 (the Nodus
 * testnet, chain born 2026-09-30): the six hosts of `endpoints` and EU-6
 * (75.119.141.51, which runs no WebSocket entry and so is not in that
 * list), each paired with its pin from `pins` BY THE TRAILING LABEL —
 * the two lists are in different orders there. The port here is the
 * client port 4001, not the wallet's 443. Each pin is SHA3-512 of the
 * node's server key (identity/nodus.fp), 128 hex characters.
 *
 * ── THE CHAIN ID ───────────────────────────────────────────────────────
 * send-module.js:88 `chainId`, 64 hex characters = the 32-byte version-3
 * chain id. The cometbft header's chain_id on that chain is those 32 RAW
 * bytes (the genesis document copies cfg->chain_id, 32 bytes:
 * nodus_witness_v2_gen.c `out->chain_id_len = NODUS_V2_GEN_CHAIN_ID_LEN`),
 * so nodus-light decodes the hex before handing it to the light client.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef NODUS_LIGHT_CHECKPOINT_H
#define NODUS_LIGHT_CHECKPOINT_H

#include <stdint.h>

/** send-module.js:88 — the version-3 chain id, hex of 32 bytes. */
#define NODUS_LIGHT_CHAIN_ID_HEX \
    "a48d1a785500a1cdecd739ecd53ef0e95b1dc4a7a300f49176a7fa25ae176114"

/** The client port of every default node (TCP 4001, Tier 2 sessions). */
#define NODUS_LIGHT_DEFAULT_PORT 4001u

typedef struct {
    const char *label;     /* the trailing comment in send-module.js */
    const char *host;
    uint16_t    port;
    const char *pin_hex;   /* 128 hex = SHA3-512 of the server key   */
} nodus_light_default_node_t;

/** send-module.js:94-110, host ↔ pin matched by label; `endpoints`
 *  order, then EU-6. */
static const nodus_light_default_node_t NODUS_LIGHT_DEFAULT_NODES[] = {
    { "EU-5", "164.68.116.180", NODUS_LIGHT_DEFAULT_PORT,
      "a7b23e52f02af2d2f526d58c741bb405825af8e31d753dc670b9c94cc01d2401"
      "fc7ecb8ddbdc1f33fe0bda0a365580e905d5f23c1be51d38c3d6055f5faa5ae6" },
    { "US-1", "154.38.182.161", NODUS_LIGHT_DEFAULT_PORT,
      "03499d1fae35f9e9aaf60a1c3f18d8c7d1ffa49f2c65bd4b6a531bdf8ef92c21"
      "c90bf5e64f29fb0b9f689ac20e7dc9df418784c788ffc43c735c9b38253038e0" },
    { "EU-1", "161.97.85.25", NODUS_LIGHT_DEFAULT_PORT,
      "fd429639366cbc41d98db7603d51166ed5542d2d161cf69ff1ab6dbe80176197"
      "dca892177f95cdb4757073531588bf63c7d3b91f6f016e0035272068de74b35c" },
    { "EU-2", "156.67.24.125", NODUS_LIGHT_DEFAULT_PORT,
      "16af3eaa620ab5d239ca63abd01943c7b1a8580a3c0204ec8a093bf7992c79df"
      "073b8ac0cacb4f01d6155fff97ef85a908dae4a044f70c1d523da1f43ce09dd7" },
    { "EU-3", "156.67.25.251", NODUS_LIGHT_DEFAULT_PORT,
      "04cdf00b3c37782b7df02fc0f71ba3b74893a60cbb800369d9ee6e97c46dd3ed"
      "af31ddf6cb29798c6e8e603d4c0dbb18e24f9d8f30c7adaeefad078f2225a659" },
    { "EU-4", "164.68.105.227", NODUS_LIGHT_DEFAULT_PORT,
      "681c12a60cae6956d1c7a1b8c75b08594961888e0d8319882fee4c94ce77b55f"
      "d7c1daee065caaacee6c28fb4f69226d1bca716a7be34e831604c88c4cbc6298" },
    { "EU-6", "75.119.141.51", NODUS_LIGHT_DEFAULT_PORT,
      "6573f74c177c9d97ba784e9607b487125f973f71026931e522051d9ba6fe713a"
      "3dcadce98d4ad2e6eb854c56f6717918fbc1691b39b7adb15cc577b138213466" },
};

#define NODUS_LIGHT_DEFAULT_NODE_COUNT \
    (sizeof(NODUS_LIGHT_DEFAULT_NODES) / sizeof(NODUS_LIGHT_DEFAULT_NODES[0]))

/**
 * THE RELEASE DEFAULT CHECKPOINT (K25-1, "the release carries a default
 * checkpoint") — EMPTY in this build.
 *
 * Filled at release from a real block after the RPC is live; K25-1. The
 * `dnac_light_block` RPC is on no live node yet, so no block has been read
 * through it and no value may be written here: a height and hash typed in
 * without that read would be an invented trust root.
 *
 * `height == 0` means "no default": `nodus-light run` on an empty store
 * then refuses and tells the operator to pass --trust-height and
 * --trust-hash. When filled, `hash_hex` is the 128-hex header hash
 * (SHA3-512, cmt_header_hash) of the block at `height` on the chain of
 * NODUS_LIGHT_CHAIN_ID_HEX.
 */
typedef struct {
    int64_t     height;
    const char *hash_hex;
} nodus_light_checkpoint_t;

static const nodus_light_checkpoint_t NODUS_LIGHT_RELEASE_CHECKPOINT = {
    0,      /* no default — see above */
    ""
};

#endif /* NODUS_LIGHT_CHECKPOINT_H */
