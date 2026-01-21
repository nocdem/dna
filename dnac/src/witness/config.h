/**
 * @file config.h
 * @brief Witness server configuration
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef DNAC_WITNESS_CONFIG_H
#define DNAC_WITNESS_CONFIG_H

/* DHT key prefixes */
#define WITNESS_REQUEST_PREFIX   "dnac:nodus:request:"
#define WITNESS_RESPONSE_PREFIX  "dnac:nodus:response:"
#define WITNESS_IDENTITY_PREFIX  "dnac:witness:identity:"
#define WITNESS_NULLIFIER_PREFIX "dnac:witness:nullifier:"

/* Timing configuration */
#define WITNESS_REPLICATION_TIMEOUT_MS 5000
#define WITNESS_REQUEST_TTL_SEC       60
#define WITNESS_RESPONSE_TTL_SEC      300
#define WITNESS_IDENTITY_TTL_SEC      3600

/* Listener configuration */
#define WITNESS_MAX_LISTENERS         2  /* Request + Replication */

/* Database configuration */
#define WITNESS_DB_FILENAME          "witness_nullifiers.db"

/* Hardcoded peer witness servers (fingerprints)
 * Update these with real server fingerprints after deployment.
 * NULL-terminated array.
 */
static const char *WITNESS_PEERS[] = {
    /* Add peer fingerprints here after deployment */
    /* "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef...", */
    NULL
};

#endif /* DNAC_WITNESS_CONFIG_H */
