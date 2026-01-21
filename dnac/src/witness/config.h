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
#define WITNESS_REQUEST_PREFIX        "dnac:nodus:request:"
#define WITNESS_RESPONSE_PREFIX       "dnac:nodus:response:"
#define WITNESS_IDENTITY_PREFIX       "dnac:witness:identity:"
#define WITNESS_NULLIFIER_PREFIX      "dnac:witness:nullifier:"

/* Epoch-based DHT key prefixes */
#define WITNESS_ANNOUNCE_PREFIX       "dnac:witness:announce:"
#define WITNESS_EPOCH_REQUEST_PREFIX  "dnac:nodus:epoch:request:"

/* Timing configuration */
#define WITNESS_REPLICATION_TIMEOUT_MS 5000
#define WITNESS_REQUEST_TTL_SEC       60
#define WITNESS_RESPONSE_TTL_SEC      300
#define WITNESS_IDENTITY_TTL_SEC      3600

/* Epoch configuration */
#define WITNESS_EPOCH_ANNOUNCE_TTL_SEC 3600   /* 1 hour */
#define WITNESS_EPOCH_REQUEST_TTL_SEC  300    /* 5 minutes */

/* Listener configuration */
#define WITNESS_MAX_LISTENERS         3  /* Current epoch + Previous epoch + Replication */

/* Database configuration */
#define WITNESS_DB_FILENAME          "witness_nullifiers.db"

/* Hardcoded peer witness servers (fingerprints)
 * Update these with real server fingerprints after deployment.
 * NULL-terminated array.
 */
static const char *WITNESS_PEERS[] = {
    "46de00d4e2ac54bdb70f3867498707ebaca58c65ca7713569fe183ffeeea46bdf380804405430d4684d8fc17b4702003d46d013151749a43fdc6b84d7472709d",  /* node1 - 192.168.0.195 */
    "d43514f121b508ca304ce741edca0bd1fbe661fe5fbd6f188b6831d0794179977083e9fbae4aa40e7d16ee73918b6e26f9c29011914415732322a2b129303634",  /* treasury - 192.168.0.196 */
    "7dea0967abe22f720be1b1c0f68131eb1e39d93a5bb58039836fe842a10fefec1db52df710238edcb90216f232da5c621e4a2e92b6c42508b64baf43594935e7",  /* cpunkroot2 - 192.168.0.199 */
    NULL
};

#endif /* DNAC_WITNESS_CONFIG_H */
