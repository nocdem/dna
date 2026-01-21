/**
 * @file config.h
 * @brief Anchor server configuration
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef DNAC_ANCHOR_CONFIG_H
#define DNAC_ANCHOR_CONFIG_H

/* DHT key prefixes */
#define ANCHOR_REQUEST_PREFIX   "dnac:nodus:request:"
#define ANCHOR_RESPONSE_PREFIX  "dnac:nodus:response:"
#define ANCHOR_IDENTITY_PREFIX  "dnac:anchor:identity:"
#define ANCHOR_NULLIFIER_PREFIX "dnac:anchor:nullifier:"

/* Timing configuration */
#define ANCHOR_POLL_INTERVAL_MS      100
#define ANCHOR_REPLICATION_TIMEOUT_MS 5000
#define ANCHOR_REQUEST_TTL_SEC       60
#define ANCHOR_RESPONSE_TTL_SEC      300
#define ANCHOR_IDENTITY_TTL_SEC      3600

/* Database configuration */
#define ANCHOR_DB_FILENAME          "anchor_nullifiers.db"

/* Hardcoded peer anchor servers (fingerprints)
 * Update these with real server fingerprints after deployment.
 * NULL-terminated array.
 */
static const char *ANCHOR_PEERS[] = {
    /* Add peer fingerprints here after deployment */
    /* "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef...", */
    NULL
};

#endif /* DNAC_ANCHOR_CONFIG_H */
