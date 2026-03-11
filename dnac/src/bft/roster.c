/**
 * @file roster.c
 * @brief BFT Witness Roster Management
 *
 * Manages the witness roster: discovery, storage, and updates.
 * Roster is stored in DHT for distributed access.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "dnac/bft.h"
#include <dna/dna_engine.h>
#include "crypto/utils/qgp_log.h"
#include "crypto/hash/qgp_sha3.h"

#define LOG_TAG "BFT_ROSTER"

/* ============================================================================
 * Config & Leader Election (moved from consensus.c in v0.10.3)
 * ========================================================================== */

void dnac_bft_config_init(dnac_bft_config_t *config, uint32_t n_witnesses) {
    if (!config) return;

    config->n_witnesses = n_witnesses;

    if (n_witnesses == 0) {
        config->f_tolerance = 0;
        config->quorum = 0;
    } else {
        config->f_tolerance = (n_witnesses - 1) / 3;
        config->quorum = 2 * config->f_tolerance + 1;
    }

    config->round_timeout_ms = DNAC_BFT_ROUND_TIMEOUT_MS;
    config->view_change_timeout_ms = DNAC_BFT_VIEW_CHANGE_TIMEOUT_MS;
    config->max_view_changes = DNAC_BFT_MAX_VIEW_CHANGES;
    config->tcp_port = 0;  /* Unused — witness runs inside nodus-server */
}

int dnac_bft_get_leader_index(uint64_t epoch, uint32_t view, int n_witnesses) {
    if (n_witnesses <= 0) return 0;
    return (int)((epoch + view) % (uint64_t)n_witnesses);
}

int dnac_bft_get_quorum(int n_witnesses) {
    if (n_witnesses <= 0) return 0;
    int f = (n_witnesses - 1) / 3;
    return 2 * f + 1;
}

/* ============================================================================
 * Roster Find (moved from consensus.c in v0.10.3)
 * ========================================================================== */

int dnac_bft_roster_find(const dnac_roster_t *roster, const uint8_t *witness_id) {
    if (!roster || !witness_id) return -1;

    for (uint32_t i = 0; i < roster->n_witnesses; i++) {
        if (memcmp(roster->witnesses[i].witness_id, witness_id,
                   DNAC_BFT_WITNESS_ID_SIZE) == 0) {
            return (int)i;
        }
    }
    return -1;
}

/* ============================================================================
 * DHT Functions for Roster Persistence (Gap 27-28: v0.6.0)
 *
 * Uses libdna's synchronous DHT API:
 * - dht_get: Synchronous get, returns first value
 * - dht_put_signed_sync: Synchronous signed put with timeout
 * ========================================================================== */

#include "nodus_ops.h"

/* Roster DHT value_id (fixed for replacement behavior) */
#define ROSTER_DHT_VALUE_ID 1
#define ROSTER_DHT_TTL_SECS (7 * 24 * 3600)  /* 1 week */
#define ROSTER_DHT_TIMEOUT_MS 5000           /* 5 seconds */

static int dna_dht_get_sync(const uint8_t *key, size_t key_len,
                            uint8_t *buffer, size_t buffer_len, size_t *data_len_out) {
    if (!key || !buffer || !data_len_out) {
        return -1;
    }

    uint8_t *value = NULL;
    size_t value_len = 0;

    int rc = nodus_ops_get(key, key_len, &value, &value_len);
    if (rc != 0 || value == NULL || value_len == 0) {
        QGP_LOG_DEBUG(LOG_TAG, "DHT get returned no data");
        *data_len_out = 0;
        return -1;
    }

    /* Copy to caller's buffer */
    if (value_len > buffer_len) {
        QGP_LOG_WARN(LOG_TAG, "DHT data too large: %zu > %zu", value_len, buffer_len);
        free(value);
        return -1;
    }

    memcpy(buffer, value, value_len);
    *data_len_out = value_len;
    free(value);

    QGP_LOG_DEBUG(LOG_TAG, "DHT get success: %zu bytes", value_len);
    return 0;
}

static int dna_dht_put_signed_sync(const uint8_t *key, size_t key_len,
                                   const uint8_t *data, size_t data_len) {
    if (!key || !data) {
        return -1;
    }

    int rc = nodus_ops_put(key, key_len, data, data_len,
                           ROSTER_DHT_TTL_SECS, ROSTER_DHT_VALUE_ID);
    if (rc != 0) {
        QGP_LOG_WARN(LOG_TAG, "DHT put failed: %d", rc);
        return -1;
    }

    QGP_LOG_DEBUG(LOG_TAG, "DHT put success: %zu bytes", data_len);
    return 0;
}

/* ============================================================================
 * DHT Key Generation
 * ========================================================================== */

/**
 * Generate DHT key for roster storage
 */
static void roster_get_dht_key_ctx(const uint8_t *chain_id, uint8_t *key_out) {
    /* v0.10.0: Zone-scoped roster key: "dnac:bft:roster:" + hex(chain_id)
     * Falls back to base key when chain_id is NULL or all-zeros */
    if (chain_id) {
        /* Check if non-zero */
        int is_zero = 1;
        for (int i = 0; i < 32 && is_zero; i++) {
            if (chain_id[i] != 0) is_zero = 0;
        }
        if (!is_zero) {
            uint8_t key_data[128];
            size_t offset = 0;
            memcpy(key_data, DNAC_BFT_ROSTER_KEY ":", strlen(DNAC_BFT_ROSTER_KEY) + 1);
            offset = strlen(DNAC_BFT_ROSTER_KEY) + 1;
            static const char hex[] = "0123456789abcdef";
            for (int i = 0; i < 32; i++) {
                key_data[offset++] = hex[(chain_id[i] >> 4) & 0xF];
                key_data[offset++] = hex[chain_id[i] & 0xF];
            }
            qgp_sha3_256(key_data, offset, key_out);
            return;
        }
    }
    /* Pre-genesis or no chain_id: use base key */
    qgp_sha3_256((const uint8_t*)DNAC_BFT_ROSTER_KEY,
                 strlen(DNAC_BFT_ROSTER_KEY),
                 key_out);
}

static void roster_get_dht_key(uint8_t *key_out) {
    roster_get_dht_key_ctx(NULL, key_out);
}

/* ============================================================================
 * Roster Initialization
 * ========================================================================== */

int dnac_bft_roster_init(dnac_roster_t *roster) {
    if (!roster) return DNAC_BFT_ERROR_INVALID_PARAM;

    memset(roster, 0, sizeof(dnac_roster_t));
    roster->version = 1;

    return DNAC_BFT_SUCCESS;
}

int dnac_bft_roster_init_with_self(dnac_roster_t *roster,
                                   const uint8_t *witness_id,
                                   const uint8_t *pubkey,
                                   const char *address) {
    if (!roster || !witness_id || !pubkey || !address) {
        return DNAC_BFT_ERROR_INVALID_PARAM;
    }

    dnac_bft_roster_init(roster);

    /* Add ourselves as first witness */
    dnac_roster_entry_t *entry = &roster->witnesses[0];
    memcpy(entry->witness_id, witness_id, DNAC_BFT_WITNESS_ID_SIZE);
    memcpy(entry->pubkey, pubkey, DNAC_PUBKEY_SIZE);
    strncpy(entry->address, address, DNAC_BFT_MAX_ADDRESS_LEN - 1);
    entry->joined_epoch = time(NULL) / DNAC_EPOCH_DURATION_SEC;
    entry->active = true;

    roster->n_witnesses = 1;

    QGP_LOG_INFO(LOG_TAG, "Roster initialized with self at %s", address);
    return DNAC_BFT_SUCCESS;
}

/* ============================================================================
 * Roster DHT Operations
 * ========================================================================== */

int dnac_bft_roster_load_from_dht(dnac_bft_context_t *ctx) {
    if (!ctx || !ctx->dna_engine) {
        return DNAC_BFT_ERROR_INVALID_PARAM;
    }

    /* Generate DHT key (v0.10.0: zone-scoped) */
    uint8_t key[32];
    roster_get_dht_key_ctx(ctx->chain_id, key);

    /* Fetch from DHT */
    uint8_t buffer[65536];
    size_t data_len = 0;

    QGP_LOG_DEBUG(LOG_TAG, "Loading roster from DHT...");

    int rc = dna_dht_get_sync(key, 32, buffer, sizeof(buffer), &data_len);
    if (rc != 0 || data_len == 0) {
        QGP_LOG_INFO(LOG_TAG, "No roster found in DHT (new network?)");
        return DNAC_BFT_ERROR_NOT_FOUND;
    }

    /* Deserialize */
    pthread_mutex_lock(&ctx->mutex);
    rc = dnac_bft_roster_deserialize(buffer, data_len, &ctx->roster);
    pthread_mutex_unlock(&ctx->mutex);

    if (rc != DNAC_BFT_SUCCESS) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to deserialize roster");
        return rc;
    }

    /* Update config based on roster size */
    dnac_bft_config_init(&ctx->config, ctx->roster.n_witnesses);

    /* Find our index */
    ctx->my_index = dnac_bft_roster_find(&ctx->roster, ctx->my_id);

    QGP_LOG_INFO(LOG_TAG, "Loaded roster v%u with %u witnesses (my index: %d)",
                ctx->roster.version, ctx->roster.n_witnesses, ctx->my_index);

    return DNAC_BFT_SUCCESS;
}

int dnac_bft_roster_save_to_dht(dnac_bft_context_t *ctx) {
    if (!ctx || !ctx->dna_engine) {
        return DNAC_BFT_ERROR_INVALID_PARAM;
    }

    /* Serialize roster */
    uint8_t buffer[65536];
    size_t written;

    pthread_mutex_lock(&ctx->mutex);
    int rc = dnac_bft_roster_serialize(&ctx->roster, buffer, sizeof(buffer), &written);
    pthread_mutex_unlock(&ctx->mutex);

    if (rc != DNAC_BFT_SUCCESS) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to serialize roster");
        return rc;
    }

    /* Generate DHT key (v0.10.0: zone-scoped) */
    uint8_t key[32];
    roster_get_dht_key_ctx(ctx->chain_id, key);

    /* Store in DHT */
    QGP_LOG_DEBUG(LOG_TAG, "Saving roster to DHT (%zu bytes)...", written);

    rc = dna_dht_put_signed_sync(key, 32, buffer, written);
    if (rc != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to save roster to DHT");
        return DNAC_BFT_ERROR_NETWORK;
    }

    QGP_LOG_INFO(LOG_TAG, "Roster v%u saved to DHT", ctx->roster.version);
    return DNAC_BFT_SUCCESS;
}

/* ============================================================================
 * Roster Modification
 * ========================================================================== */

int dnac_bft_roster_add_witness(dnac_bft_context_t *ctx,
                                const uint8_t *witness_id,
                                const uint8_t *pubkey,
                                const char *address) {
    if (!ctx || !witness_id || !pubkey || !address) {
        return DNAC_BFT_ERROR_INVALID_PARAM;
    }

    pthread_mutex_lock(&ctx->mutex);

    /* Check if already in roster by ID */
    int existing = dnac_bft_roster_find(&ctx->roster, witness_id);
    if (existing >= 0) {
        /* Update address if changed */
        if (strcmp(ctx->roster.witnesses[existing].address, address) != 0) {
            strncpy(ctx->roster.witnesses[existing].address, address,
                    DNAC_BFT_MAX_ADDRESS_LEN - 1);
            ctx->roster.version++;
            QGP_LOG_INFO(LOG_TAG, "Updated witness %d address to %s", existing, address);
        }
        pthread_mutex_unlock(&ctx->mutex);
        return DNAC_BFT_SUCCESS;
    }

    /* Check if already in roster by address (placeholder entry from roster file) */
    for (uint32_t i = 0; i < ctx->roster.n_witnesses; i++) {
        if (strcmp(ctx->roster.witnesses[i].address, address) == 0) {
            /* Update ID and pubkey for existing address entry */
            memcpy(ctx->roster.witnesses[i].witness_id, witness_id, DNAC_BFT_WITNESS_ID_SIZE);
            memcpy(ctx->roster.witnesses[i].pubkey, pubkey, DNAC_PUBKEY_SIZE);
            ctx->roster.version++;
            QGP_LOG_INFO(LOG_TAG, "Updated witness %u identity at %s", i, address);
            pthread_mutex_unlock(&ctx->mutex);
            return DNAC_BFT_SUCCESS;
        }
    }

    /* Check capacity */
    if (ctx->roster.n_witnesses >= DNAC_BFT_MAX_WITNESSES) {
        pthread_mutex_unlock(&ctx->mutex);
        QGP_LOG_ERROR(LOG_TAG, "Roster full");
        return DNAC_BFT_ERROR_ROSTER_FULL;
    }

    /* Add new entry */
    dnac_roster_entry_t *entry = &ctx->roster.witnesses[ctx->roster.n_witnesses];
    memcpy(entry->witness_id, witness_id, DNAC_BFT_WITNESS_ID_SIZE);
    memcpy(entry->pubkey, pubkey, DNAC_PUBKEY_SIZE);
    strncpy(entry->address, address, DNAC_BFT_MAX_ADDRESS_LEN - 1);
    entry->joined_epoch = time(NULL) / DNAC_EPOCH_DURATION_SEC;
    entry->active = true;

    ctx->roster.n_witnesses++;
    ctx->roster.version++;

    /* Update config */
    dnac_bft_config_init(&ctx->config, ctx->roster.n_witnesses);

    QGP_LOG_INFO(LOG_TAG, "Added witness %d at %s (now %u witnesses)",
                ctx->roster.n_witnesses - 1, address, ctx->roster.n_witnesses);

    pthread_mutex_unlock(&ctx->mutex);
    return DNAC_BFT_SUCCESS;
}

int dnac_bft_roster_remove_witness(dnac_bft_context_t *ctx,
                                   const uint8_t *witness_id) {
    if (!ctx || !witness_id) {
        return DNAC_BFT_ERROR_INVALID_PARAM;
    }

    pthread_mutex_lock(&ctx->mutex);

    int index = dnac_bft_roster_find(&ctx->roster, witness_id);
    if (index < 0) {
        pthread_mutex_unlock(&ctx->mutex);
        return DNAC_BFT_ERROR_PEER_NOT_FOUND;
    }

    /* Mark as inactive (don't remove to preserve history) */
    ctx->roster.witnesses[index].active = false;
    ctx->roster.version++;

    /* Recalculate active count and config */
    uint32_t active_count = 0;
    for (uint32_t i = 0; i < ctx->roster.n_witnesses; i++) {
        if (ctx->roster.witnesses[i].active) {
            active_count++;
        }
    }
    dnac_bft_config_init(&ctx->config, active_count);

    QGP_LOG_INFO(LOG_TAG, "Deactivated witness %d (%u active witnesses)",
                index, active_count);

    pthread_mutex_unlock(&ctx->mutex);
    return DNAC_BFT_SUCCESS;
}

/* ============================================================================
 * Roster Queries
 * ========================================================================== */

int dnac_bft_roster_get_active_count(const dnac_roster_t *roster) {
    if (!roster) return 0;

    int count = 0;
    for (uint32_t i = 0; i < roster->n_witnesses; i++) {
        if (roster->witnesses[i].active) {
            count++;
        }
    }
    return count;
}

const dnac_roster_entry_t* dnac_bft_roster_get_entry(const dnac_roster_t *roster,
                                                     int index) {
    if (!roster || index < 0 || index >= (int)roster->n_witnesses) {
        return NULL;
    }
    return &roster->witnesses[index];
}

int dnac_bft_roster_get_leader(const dnac_roster_t *roster,
                               uint64_t epoch,
                               uint32_t view,
                               dnac_roster_entry_t *entry_out) {
    if (!roster || roster->n_witnesses == 0) {
        return DNAC_BFT_ERROR_INVALID_PARAM;
    }

    /* BUG-3 fix: Select leader from active witnesses only.
     * Previous code used n_witnesses (total), which could select an
     * inactive witness as leader, stalling consensus. */
    int active_indices[DNAC_BFT_MAX_WITNESSES];
    int active_count = 0;
    for (uint32_t i = 0; i < roster->n_witnesses; i++) {
        if (roster->witnesses[i].active)
            active_indices[active_count++] = (int)i;
    }

    if (active_count == 0) {
        return DNAC_BFT_ERROR_NO_QUORUM;
    }

    int leader_pos = dnac_bft_get_leader_index(epoch, view, active_count);
    int leader_index = active_indices[leader_pos];

    if (entry_out) {
        memcpy(entry_out, &roster->witnesses[leader_index], sizeof(dnac_roster_entry_t));
    }

    return leader_index;
}

/* ============================================================================
 * Roster Printing (Debug)
 * ========================================================================== */

void dnac_bft_roster_print(const dnac_roster_t *roster) {
    if (!roster) {
        printf("Roster: (null)\n");
        return;
    }

    printf("Roster v%u (%u witnesses):\n", roster->version, roster->n_witnesses);

    for (uint32_t i = 0; i < roster->n_witnesses; i++) {
        const dnac_roster_entry_t *e = &roster->witnesses[i];
        printf("  [%u] %.8s... at %s %s (epoch %lu)\n",
               i,
               (const char*)e->witness_id,  /* First 8 chars of hex ID */
               e->address,
               e->active ? "[ACTIVE]" : "[INACTIVE]",
               (unsigned long)e->joined_epoch);
    }
}

/* ============================================================================
 * Client Roster Discovery
 * ========================================================================== */

/**
 * Load roster from file (used by clients to discover witnesses)
 * File format: one address per line (IP:port)
 */
static int load_roster_from_file_client(const char *filename, dnac_roster_t *roster_out) {
    FILE *f = fopen(filename, "r");
    if (!f) {
        return DNAC_BFT_ERROR_NOT_FOUND;
    }

    dnac_bft_roster_init(roster_out);

    char line[256];
    while (fgets(line, sizeof(line), f) && roster_out->n_witnesses < DNAC_BFT_MAX_WITNESSES) {
        /* Remove newline */
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';
        char *cr = strchr(line, '\r');
        if (cr) *cr = '\0';

        /* Skip empty lines and comments */
        if (line[0] == '\0' || line[0] == '#') continue;

        /* Trim whitespace */
        char *addr = line;
        while (*addr == ' ' || *addr == '\t') addr++;
        if (*addr == '\0') continue;

        /* Add entry with placeholder ID (client only needs address) */
        dnac_roster_entry_t *entry = &roster_out->witnesses[roster_out->n_witnesses];
        memset(entry, 0, sizeof(dnac_roster_entry_t));

        /* Generate placeholder ID from address hash */
        qgp_sha3_256((const uint8_t*)addr, strlen(addr), entry->witness_id);

        snprintf(entry->address, DNAC_BFT_MAX_ADDRESS_LEN, "%s", addr);
        entry->active = true;
        entry->joined_epoch = time(NULL) / DNAC_EPOCH_DURATION_SEC;

        roster_out->n_witnesses++;
        QGP_LOG_DEBUG(LOG_TAG, "Loaded witness address: %s", addr);
    }

    fclose(f);

    if (roster_out->n_witnesses == 0) {
        return DNAC_BFT_ERROR_NOT_FOUND;
    }

    QGP_LOG_INFO(LOG_TAG, "Loaded roster with %u witnesses from %s",
                 roster_out->n_witnesses, filename);
    return DNAC_BFT_SUCCESS;
}

int dnac_bft_client_discover_roster(void *dna_engine, dnac_roster_t *roster_out) {
    if (!roster_out) {
        return DNAC_BFT_ERROR_INVALID_PARAM;
    }

    /* Try loading from file first (multiple locations) */
    const char *roster_paths[] = {
        NULL,  /* Will be filled with ~/.dna/roster.txt */
        "./roster.txt",
        NULL
    };

    /* Build path for ~/.dna/roster.txt */
    char home_roster[512] = {0};
    const char *home = getenv("HOME");
    if (home) {
        snprintf(home_roster, sizeof(home_roster), "%s/.dna/roster.txt", home);
        roster_paths[0] = home_roster;
    }

    for (int i = 0; roster_paths[i] != NULL; i++) {
        QGP_LOG_DEBUG(LOG_TAG, "Trying roster file: %s", roster_paths[i]);
        int rc = load_roster_from_file_client(roster_paths[i], roster_out);
        if (rc == DNAC_BFT_SUCCESS) {
            return DNAC_BFT_SUCCESS;
        }
    }

    /* Fall back to DHT */
    if (dna_engine) {
        /* Generate DHT key */
        uint8_t key[32];
        roster_get_dht_key(key);

        /* Fetch from DHT */
        uint8_t buffer[65536];
        size_t data_len = 0;

        QGP_LOG_DEBUG(LOG_TAG, "Client discovering roster from DHT...");

        int rc = dna_dht_get_sync(key, 32, buffer, sizeof(buffer), &data_len);
        if (rc == 0 && data_len > 0) {
            /* Deserialize */
            rc = dnac_bft_roster_deserialize(buffer, data_len, roster_out);
            if (rc == DNAC_BFT_SUCCESS) {
                QGP_LOG_INFO(LOG_TAG, "Discovered roster v%u with %u witnesses from DHT",
                            roster_out->version, roster_out->n_witnesses);
                return DNAC_BFT_SUCCESS;
            }
        }
    }

    QGP_LOG_WARN(LOG_TAG, "No roster found (no file, DHT not available)");
    return DNAC_BFT_ERROR_NOT_FOUND;
}
