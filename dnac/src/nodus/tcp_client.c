/**
 * @file tcp_client.c
 * @brief DNAC witness client functions — Nodus SDK based
 *
 * All functions that previously used direct TCP connections to witnesses
 * now use the Nodus client SDK (nodus_client_dnac_*) which routes through
 * the authenticated Nodus TCP connection on port 4001.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>

#include "dnac/nodus.h"
#include "dnac/ledger.h"
#include "dnac/commitment.h"
#include "dnac/wallet.h"
#include "dnac/db.h"
#include "crypto/utils/qgp_random.h"
#include "crypto/utils/qgp_log.h"
#include "crypto/hash/qgp_sha3.h"

/* Nodus client SDK (public API) */
#include "nodus/nodus.h"
#include "crypto/utils/qgp_safe_string.h"   /* Phase 03: unsafe-string poison guard */

/* Nodus singleton access (not on DNAC include path, use extern) */
extern nodus_client_t *nodus_singleton_get(void);
extern void nodus_singleton_lock(void);
extern void nodus_singleton_unlock(void);

#define LOG_TAG "NODUS_TCP"

/* External wallet functions */
extern dna_engine_t *dnac_get_engine(dnac_context_t *ctx);
extern const char *dnac_get_owner_fingerprint(dnac_context_t *ctx);


/* ============================================================================
 * BFT Witness Request (via Nodus SDK)
 * ========================================================================== */

int dnac_bft_witness_request(void *dna_engine,
                             const dnac_spend_request_t *request,
                             dnac_witness_sig_t *witnesses_out,
                             int *witness_count_out) {
    (void)dna_engine;

    if (!request || !witnesses_out || !witness_count_out) {
        return DNAC_ERROR_INVALID_PARAM;
    }

    *witness_count_out = 0;

    nodus_client_t *client = nodus_singleton_get();
    if (!client) {
        QGP_LOG_ERROR(LOG_TAG, "Nodus singleton not initialized");
        return DNAC_ERROR_NETWORK;
    }

    nodus_singleton_lock();

    nodus_pubkey_t sender_pk;
    memcpy(sender_pk.bytes, request->sender_pubkey, NODUS_PK_BYTES);
    nodus_sig_t sender_sig;
    memcpy(sender_sig.bytes, request->signature, NODUS_SIG_BYTES);

    nodus_dnac_spend_result_t result;
    int rc = nodus_client_dnac_spend(client,
                                      request->tx_hash,
                                      request->tx_data,
                                      request->tx_len,
                                      &sender_pk,
                                      &sender_sig,
                                      request->fee_amount,
                                      &result);

    nodus_singleton_unlock();

    if (rc != 0) {
        QGP_LOG_ERROR(LOG_TAG, "BFT spend request failed: %d", rc);
        return (rc == NODUS_ERR_TIMEOUT) ? DNAC_ERROR_TIMEOUT
                                         : DNAC_ERROR_NETWORK;
    }

    if (result.status != NODUS_DNAC_APPROVED) {
        QGP_LOG_WARN(LOG_TAG, "Witness rejected: status=%d", result.status);
        return DNAC_ERROR_DOUBLE_SPEND;
    }

    memcpy(witnesses_out[0].witness_id, result.witness_id, 32);
    memcpy(witnesses_out[0].signature, result.signature, NODUS_SIG_BYTES);
    memcpy(witnesses_out[0].server_pubkey, result.witness_pubkey,
           NODUS_PK_BYTES);
    witnesses_out[0].timestamp = result.timestamp;
    *witness_count_out = 1;

    QGP_LOG_INFO(LOG_TAG, "BFT consensus approved transaction");
    return DNAC_SUCCESS;
}

/* ============================================================================
 * Roster Discovery (via Nodus SDK)
 * ========================================================================== */

int dnac_bft_discover_witnesses(void *dna_engine,
                                dnac_witness_info_t **servers_out,
                                int *count_out) {
    (void)dna_engine;

    if (!servers_out || !count_out) {
        return DNAC_ERROR_INVALID_PARAM;
    }

    *servers_out = NULL;
    *count_out = 0;

    nodus_client_t *client = nodus_singleton_get();
    if (!client) return DNAC_ERROR_NOT_INITIALIZED;

    nodus_singleton_lock();

    nodus_dnac_roster_result_t roster;
    int rc = nodus_client_dnac_roster(client, &roster);

    nodus_singleton_unlock();

    if (rc != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Roster discovery failed: %d", rc);
        return DNAC_ERROR_NOT_FOUND;
    }

    if (roster.count <= 0) {
        return DNAC_ERROR_NOT_FOUND;
    }

    /* Allocate output array */
    *servers_out = calloc(roster.count, sizeof(dnac_witness_info_t));
    if (!*servers_out) return DNAC_ERROR_OUT_OF_MEMORY;

    /* Convert roster entries to witness info */
    static const char hex[] = "0123456789abcdef";
    for (int i = 0; i < roster.count; i++) {
        nodus_dnac_roster_entry_t *entry = &roster.entries[i];
        dnac_witness_info_t *info = &(*servers_out)[i];

        /* Convert witness_id to hex string */
        for (int j = 0; j < NODUS_T3_WITNESS_ID_LEN; j++) {
            info->id[j * 2] = hex[(entry->witness_id[j] >> 4) & 0xF];
            info->id[j * 2 + 1] = hex[entry->witness_id[j] & 0xF];
        }
        info->id[NODUS_T3_WITNESS_ID_LEN * 2] = '\0';

        strncpy(info->address, entry->address, sizeof(info->address) - 1);
        memcpy(info->pubkey, entry->pubkey, NODUS_PK_BYTES);
        info->is_available = entry->active;

        /* Derive fingerprint from public key: hex(SHA3-512(pubkey)) */
        uint8_t fp_hash[64];
        if (qgp_sha3_512(entry->pubkey, NODUS_PK_BYTES, fp_hash) == 0) {
            for (int j = 0; j < 64; j++) {
                info->fingerprint[j * 2] = hex[(fp_hash[j] >> 4) & 0xF];
                info->fingerprint[j * 2 + 1] = hex[fp_hash[j] & 0xF];
            }
            info->fingerprint[128] = '\0';
        }
    }

    *count_out = roster.count;

    QGP_LOG_INFO(LOG_TAG, "Discovered %d BFT witnesses", *count_out);
    return DNAC_SUCCESS;
}

/* ============================================================================
 * Check Nullifier via Nodus SDK
 * ========================================================================== */

int dnac_bft_check_nullifier(void *dna_engine,
                             const uint8_t *nullifier,
                             bool *is_spent_out) {
    (void)dna_engine;

    if (!nullifier || !is_spent_out) {
        return DNAC_ERROR_INVALID_PARAM;
    }

    *is_spent_out = false;

    nodus_client_t *client = nodus_singleton_get();
    if (!client) return DNAC_ERROR_NOT_INITIALIZED;

    nodus_singleton_lock();

    nodus_dnac_nullifier_result_t result;
    int rc = nodus_client_dnac_nullifier(client, nullifier, &result);

    nodus_singleton_unlock();

    if (rc != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Nullifier check failed: %d", rc);
        return DNAC_ERROR_NETWORK;
    }

    *is_spent_out = result.is_spent;

    QGP_LOG_DEBUG(LOG_TAG, "Nullifier check result: is_spent=%d",
                  result.is_spent);
    return DNAC_SUCCESS;
}

/* ============================================================================
 * Ping Witness (Health Check)
 * ========================================================================== */

int dnac_bft_ping_witness(const char *address, int *latency_ms_out) {
    (void)address;

    /* Health check via nodus connection state */
    nodus_client_t *client = nodus_singleton_get();
    if (!client || !nodus_client_is_ready(client)) {
        return DNAC_ERROR_NETWORK;
    }

    if (latency_ms_out) *latency_ms_out = 0;
    return DNAC_SUCCESS;
}

/* ============================================================================
 * Ledger Query Functions (via Nodus SDK)
 * ========================================================================== */

int dnac_ledger_query_tx(dnac_context_t *ctx,
                         const uint8_t *tx_hash,
                         dnac_ledger_entry_t *entry_out,
                         dnac_merkle_proof_t *proof_out) {
    if (!ctx || !tx_hash || !entry_out) {
        return DNAC_ERROR_INVALID_PARAM;
    }

    nodus_client_t *client = nodus_singleton_get();
    if (!client) return DNAC_ERROR_NOT_INITIALIZED;

    nodus_singleton_lock();

    nodus_dnac_ledger_result_t result;
    int rc = nodus_client_dnac_ledger(client, tx_hash, &result);

    nodus_singleton_unlock();

    if (rc != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Ledger query failed: %d", rc);
        return DNAC_ERROR_NETWORK;
    }

    if (!result.found) {
        return DNAC_ERROR_NOT_FOUND;
    }

    /* Copy to output */
    memset(entry_out, 0, sizeof(*entry_out));
    entry_out->sequence_number = result.sequence;
    memcpy(entry_out->tx_hash, result.tx_hash, DNAC_TX_HASH_SIZE);
    entry_out->tx_type = result.tx_type;
    entry_out->timestamp = result.timestamp;
    entry_out->epoch = result.epoch;

    /* Proof not available via CBOR ledger query (use dnac_utxo_proof) */
    (void)proof_out;

    QGP_LOG_INFO(LOG_TAG, "Ledger query: seq=%llu, type=%d",
                 (unsigned long long)entry_out->sequence_number,
                 entry_out->tx_type);
    return DNAC_SUCCESS;
}

int dnac_ledger_get_supply(dnac_context_t *ctx,
                           uint64_t *genesis_out,
                           uint64_t *burned_out,
                           uint64_t *current_out) {
    if (!ctx) return DNAC_ERROR_INVALID_PARAM;

    nodus_client_t *client = nodus_singleton_get();
    if (!client) return DNAC_ERROR_NOT_INITIALIZED;

    nodus_singleton_lock();

    nodus_dnac_supply_result_t result;
    int rc = nodus_client_dnac_supply(client, &result);

    nodus_singleton_unlock();

    if (rc != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Supply query failed: %d", rc);
        return DNAC_ERROR_NETWORK;
    }

    if (genesis_out) *genesis_out = result.genesis_supply;
    if (burned_out) *burned_out = result.total_burned;
    if (current_out) *current_out = result.current_supply;

    /* Store chain_id in context for inbox key scoping */
    dnac_set_chain_id(ctx, result.chain_id);

    QGP_LOG_INFO(LOG_TAG, "Supply query: genesis=%llu, burned=%llu, "
                 "current=%llu",
                 (unsigned long long)result.genesis_supply,
                 (unsigned long long)result.total_burned,
                 (unsigned long long)result.current_supply);
    return DNAC_SUCCESS;
}

/* ============================================================================
 * Ledger Range Query (via Nodus SDK)
 * ========================================================================== */

int dnac_ledger_sync_range(dnac_context_t *ctx,
                            uint64_t from_seq,
                            uint64_t to_seq,
                            dnac_ledger_entry_t *entries_out,
                            int max_entries,
                            int *count_out,
                            uint64_t *total_out) {
    if (!ctx || !entries_out || !count_out || max_entries <= 0) {
        return DNAC_ERROR_INVALID_PARAM;
    }

    *count_out = 0;
    if (total_out) *total_out = 0;

    nodus_client_t *client = nodus_singleton_get();
    if (!client) return DNAC_ERROR_NOT_INITIALIZED;

    nodus_singleton_lock();

    nodus_dnac_range_result_t result;
    int rc = nodus_client_dnac_ledger_range(client, from_seq, to_seq, &result);

    nodus_singleton_unlock();

    if (rc != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Range query failed: %d", rc);
        return DNAC_ERROR_NETWORK;
    }

    /* Copy entries to output */
    int copy_count = (result.count < max_entries) ? result.count : max_entries;
    for (int i = 0; i < copy_count; i++) {
        const nodus_dnac_range_entry_t *e = &result.entries[i];
        memset(&entries_out[i], 0, sizeof(entries_out[i]));

        entries_out[i].sequence_number = e->sequence;
        memcpy(entries_out[i].tx_hash, e->tx_hash, DNAC_TX_HASH_SIZE);
        entries_out[i].tx_type = e->tx_type;
        entries_out[i].timestamp = e->timestamp;
        entries_out[i].epoch = e->epoch;
    }

    *count_out = copy_count;
    if (total_out) *total_out = result.total_entries;

    nodus_client_free_range_result(&result);

    QGP_LOG_INFO(LOG_TAG, "Range sync: from=%llu to=%llu returned=%d "
                 "total=%llu",
                 (unsigned long long)from_seq,
                 (unsigned long long)to_seq,
                 copy_count,
                 (unsigned long long)result.total_entries);
    return DNAC_SUCCESS;
}

/* ============================================================================
 * UTXO Query Functions (via Nodus SDK)
 * ========================================================================== */

int dnac_wallet_recover_from_witnesses(dnac_context_t *ctx,
                                        int *recovered_count,
                                        uint64_t *total_amount) {
    if (!ctx) return DNAC_ERROR_INVALID_PARAM;

    if (recovered_count) *recovered_count = 0;
    if (total_amount) *total_amount = 0;

    /* Get our owner fingerprint */
    const char *fingerprint = dnac_get_owner_fingerprint(ctx);
    if (!fingerprint) {
        QGP_LOG_ERROR(LOG_TAG, "recover: owner fingerprint is NULL");
        return DNAC_ERROR_NOT_INITIALIZED;
    }

    sqlite3 *db = dnac_get_db(ctx);
    if (!db) {
        QGP_LOG_ERROR(LOG_TAG, "recover: db is NULL");
        return DNAC_ERROR_NOT_INITIALIZED;
    }

    nodus_client_t *client = nodus_singleton_get();
    if (!client) {
        QGP_LOG_ERROR(LOG_TAG, "recover: nodus singleton is NULL");
        return DNAC_ERROR_NOT_INITIALIZED;
    }

    size_t fplen = strlen(fingerprint);
    /* Checksum to bypass LogSanitizer redaction */
    uint32_t fp_cksum = 0;
    for (size_t i = 0; i < fplen; i++) fp_cksum = fp_cksum * 31 + (uint8_t)fingerprint[i];
    QGP_LOG_DEBUG(LOG_TAG, "recover: fp_len=%zu fp_cksum=%u fp[0..3]=%c%c%c%c",
                  fplen, fp_cksum, fingerprint[0], fingerprint[1], fingerprint[2], fingerprint[3]);

    nodus_singleton_lock();

    nodus_dnac_utxo_result_t result;
    int rc = nodus_client_dnac_utxo(client, fingerprint,
                                      NODUS_DNAC_MAX_UTXO_RESULTS, &result);

    nodus_singleton_unlock();

    QGP_LOG_DEBUG(LOG_TAG, "recover: nodus_client_dnac_utxo rc=%d, result.count=%d",
                  rc, rc == 0 ? result.count : -1);

    if (rc != 0) {
        QGP_LOG_ERROR(LOG_TAG, "UTXO recovery failed: %d", rc);
        return DNAC_ERROR_NETWORK;
    }

    /* Step 1: Get current local unspent UTXOs */
    dnac_utxo_t *local_utxos = NULL;
    int local_count = 0;
    dnac_db_get_unspent_utxos(db, fingerprint, &local_utxos, &local_count);

    /* Step 2: Mark local UTXOs not in witness set as spent */
    for (int i = 0; i < local_count; i++) {
        bool found = false;
        for (int j = 0; j < result.count; j++) {
            if (memcmp(local_utxos[i].nullifier, result.entries[j].nullifier,
                       DNAC_NULLIFIER_SIZE) == 0) {
                found = true;
                break;
            }
        }
        if (!found) {
            dnac_db_mark_utxo_spent(db, local_utxos[i].nullifier, NULL);
            QGP_LOG_INFO(LOG_TAG, "Marked stale UTXO as spent (amount=%llu)",
                         (unsigned long long)local_utxos[i].amount);
        }
    }
    free(local_utxos);

    /* Step 3: Store witness UTXOs that are missing locally */
    int count = 0;
    uint64_t total = 0;
    for (int i = 0; i < result.count; i++) {
        nodus_dnac_utxo_entry_t *e = &result.entries[i];
        if (total + e->amount < total) {
            QGP_LOG_ERROR(LOG_TAG, "UTXO total overflow at entry %d", i);
            break;  /* Stop accumulating on overflow */
        }
        total += e->amount;

        /* Build UTXO from witness data */
        dnac_utxo_t utxo = {0};
        utxo.version = 1;
        memcpy(utxo.tx_hash, e->tx_hash, DNAC_TX_HASH_SIZE);
        utxo.output_index = e->output_index;
        utxo.amount = e->amount;
        memcpy(utxo.nullifier, e->nullifier, DNAC_NULLIFIER_SIZE);
        snprintf(utxo.owner_fingerprint, sizeof(utxo.owner_fingerprint),
                 "%s", fingerprint);
        memcpy(utxo.token_id, e->token_id, DNAC_TOKEN_ID_SIZE);
        utxo.status = DNAC_UTXO_UNSPENT;
        utxo.received_at = (uint64_t)time(NULL);

        /* INSERT OR IGNORE — won't overwrite existing entries */
        rc = dnac_db_store_utxo(db, &utxo);
        if (rc == DNAC_SUCCESS) {
            count++;
        }

        QGP_LOG_DEBUG(LOG_TAG, "Witness UTXO: amount=%llu, output_index=%u",
                      (unsigned long long)e->amount, e->output_index);
    }

    nodus_client_free_utxo_result(&result);

    if (recovered_count) *recovered_count = count;
    if (total_amount) *total_amount = total;

    if (count > 0) {
        QGP_LOG_INFO(LOG_TAG, "Witness recovery: stored %d new UTXOs, total: %llu",
                     count, (unsigned long long)total);
    }

    return DNAC_SUCCESS;
}

/* ============================================================================
 * Transaction Query (v0.10.0 hub/spoke)
 * ========================================================================== */

int dnac_query_transaction(dnac_context_t *ctx,
                            const uint8_t *tx_hash,
                            uint8_t **tx_data_out,
                            uint32_t *tx_len_out,
                            uint8_t *tx_type_out,
                            uint64_t *block_height_out) {
    if (!ctx || !tx_hash || !tx_data_out || !tx_len_out) {
        return DNAC_ERROR_INVALID_PARAM;
    }

    *tx_data_out = NULL;
    *tx_len_out = 0;

    nodus_client_t *client = nodus_singleton_get();
    if (!client) return DNAC_ERROR_NOT_INITIALIZED;

    nodus_singleton_lock();

    nodus_dnac_tx_result_t result;
    int rc = nodus_client_dnac_tx(client, tx_hash, &result);

    nodus_singleton_unlock();

    if (rc != 0) {
        QGP_LOG_ERROR(LOG_TAG, "TX query failed: %d", rc);
        return DNAC_ERROR_NETWORK;
    }

    if (!result.found) {
        return DNAC_ERROR_NOT_FOUND;
    }

    *tx_data_out = result.tx_data;   /* Ownership transferred to caller */
    *tx_len_out = result.tx_len;

    if (tx_type_out) *tx_type_out = result.tx_type;
    if (block_height_out) *block_height_out = result.block_height;

    QGP_LOG_INFO(LOG_TAG, "TX query: type=%d, len=%u, block=%llu",
                 result.tx_type, result.tx_len,
                 (unsigned long long)result.block_height);
    return DNAC_SUCCESS;
}

/* ============================================================================
 * Block Query (v0.10.0 hub/spoke)
 * ========================================================================== */

int dnac_query_block(dnac_context_t *ctx,
                      uint64_t height,
                      uint8_t *tx_hash_out,
                      uint8_t *tx_type_out,
                      uint64_t *timestamp_out,
                      uint8_t *proposer_out) {
    if (!ctx) return DNAC_ERROR_INVALID_PARAM;

    nodus_client_t *client = nodus_singleton_get();
    if (!client) return DNAC_ERROR_NOT_INITIALIZED;

    nodus_singleton_lock();

    nodus_dnac_block_result_t result;
    int rc = nodus_client_dnac_block(client, height, &result);

    nodus_singleton_unlock();

    if (rc != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Block query failed: %d", rc);
        return DNAC_ERROR_NETWORK;
    }

    if (!result.found) {
        return DNAC_ERROR_NOT_FOUND;
    }

    if (tx_hash_out) memcpy(tx_hash_out, result.tx_hash, DNAC_TX_HASH_SIZE);
    if (tx_type_out) *tx_type_out = result.tx_type;
    if (timestamp_out) *timestamp_out = result.timestamp;
    if (proposer_out) memcpy(proposer_out, result.proposer_id, 32);

    QGP_LOG_INFO(LOG_TAG, "Block query: height=%llu, type=%d",
                 (unsigned long long)height, result.tx_type);
    return DNAC_SUCCESS;
}

/* ============================================================================
 * Block Range Query (v0.10.0 hub/spoke)
 * ========================================================================== */

int dnac_query_block_range(dnac_context_t *ctx,
                            uint64_t from_height,
                            uint64_t to_height,
                            int *count_out,
                            uint64_t *total_out) {
    if (!ctx || !count_out) return DNAC_ERROR_INVALID_PARAM;

    *count_out = 0;
    if (total_out) *total_out = 0;

    nodus_client_t *client = nodus_singleton_get();
    if (!client) return DNAC_ERROR_NOT_INITIALIZED;

    nodus_singleton_lock();

    nodus_dnac_block_range_result_t result;
    int rc = nodus_client_dnac_block_range(client, from_height, to_height,
                                             &result);

    nodus_singleton_unlock();

    if (rc != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Block range query failed: %d", rc);
        return DNAC_ERROR_NETWORK;
    }

    *count_out = result.count;
    if (total_out) *total_out = result.total_blocks;

    nodus_client_free_block_range_result(&result);

    QGP_LOG_INFO(LOG_TAG, "Block range: from=%llu to=%llu returned=%d",
                 (unsigned long long)from_height,
                 (unsigned long long)to_height, *count_out);
    return DNAC_SUCCESS;
}

/* ============================================================================
 * Transaction History (from Nodus witnesses)
 * ========================================================================== */

int dnac_get_remote_history(dnac_context_t *ctx,
                             dnac_tx_history_t **history_out,
                             int *count_out) {
    if (!ctx || !history_out || !count_out)
        return DNAC_ERROR_INVALID_PARAM;

    *history_out = NULL;
    *count_out = 0;

    const char *fingerprint = dnac_get_owner_fingerprint(ctx);
    if (!fingerprint) {
        QGP_LOG_ERROR(LOG_TAG, "remote_history: owner fingerprint is NULL");
        return DNAC_ERROR_NOT_INITIALIZED;
    }

    nodus_client_t *client = nodus_singleton_get();
    if (!client) {
        QGP_LOG_ERROR(LOG_TAG, "remote_history: nodus singleton is NULL");
        return DNAC_ERROR_NOT_INITIALIZED;
    }

    nodus_singleton_lock();

    nodus_dnac_history_result_t result;
    int rc = nodus_client_dnac_history(client, fingerprint,
                                        NODUS_DNAC_MAX_HISTORY_RESULTS,
                                        &result);

    nodus_singleton_unlock();

    if (rc != 0) {
        QGP_LOG_ERROR(LOG_TAG, "remote_history: nodus query failed: %d", rc);
        return DNAC_ERROR_NETWORK;
    }

    QGP_LOG_INFO(LOG_TAG, "remote_history: received %d entries from Nodus",
                 result.count);

    /* Convert Nodus entries to DNAC history format */
    if (result.count > 0) {
        dnac_tx_history_t *history = calloc((size_t)result.count,
                                             sizeof(dnac_tx_history_t));
        if (!history) {
            nodus_client_free_history_result(&result);
            return DNAC_ERROR_OUT_OF_MEMORY;
        }

        for (int i = 0; i < result.count; i++) {
            nodus_dnac_history_entry_t *e = &result.entries[i];
            dnac_tx_history_t *h = &history[i];

            memcpy(h->tx_hash, e->tx_hash, DNAC_TX_HASH_SIZE);
            h->type = (dnac_tx_type_t)e->tx_type;
            h->fee = e->fee;
            h->timestamp = e->timestamp;

            /* Compute send_amount and counterparty from per-output data.
             * send_amount = sum of outputs NOT owned by us (transfer)
             * counterparty = first non-us output owner (recipient)
             * If we are receiver: amount = sum of our outputs */
            bool is_sender = (e->sender_fp[0] &&
                              strcmp(e->sender_fp, fingerprint) == 0);

            uint64_t send_amount = 0;
            uint64_t recv_amount = 0;
            bool token_id_set = false;

            for (int oi = 0; oi < e->output_count; oi++) {
                bool output_is_mine = (strcmp(e->outputs[oi].owner_fp,
                                              fingerprint) == 0);
                /* Capture token_id from first relevant output */
                if (!token_id_set) {
                    memcpy(h->token_id, e->outputs[oi].token_id,
                           DNAC_TOKEN_ID_SIZE);
                    token_id_set = true;
                }
                if (is_sender) {
                    if (!output_is_mine) {
                        /* Output to someone else = transferred amount */
                        send_amount += e->outputs[oi].amount;
                        if (h->counterparty[0] == '\0') {
                            strncpy(h->counterparty,
                                    e->outputs[oi].owner_fp,
                                    DNAC_FINGERPRINT_SIZE - 1);
                        }
                    }
                    /* output_is_mine = change, ignore */
                } else {
                    if (output_is_mine) {
                        recv_amount += e->outputs[oi].amount;
                    }
                }
            }

            if (is_sender) {
                h->amount_delta = -(int64_t)send_amount;
                /* If no non-self output found (genesis?), counterparty = empty */
            } else {
                h->amount_delta = (int64_t)recv_amount;
                /* Counterparty is the sender */
                strncpy(h->counterparty, e->sender_fp,
                        DNAC_FINGERPRINT_SIZE - 1);
            }
        }

        *history_out = history;
        *count_out = result.count;
    }

    nodus_client_free_history_result(&result);
    return DNAC_SUCCESS;
}

/* ============================================================================
 * UTXO Proof (stub)
 * ========================================================================== */

int dnac_utxo_get_proof(dnac_context_t *ctx,
                        const uint8_t *commitment,
                        dnac_smt_proof_t *proof_out) {
    /* UTXO proof query not yet available via Nodus SDK.
     * This will be added in a future phase. */
    (void)ctx; (void)commitment; (void)proof_out;

    QGP_LOG_WARN(LOG_TAG, "dnac_utxo_get_proof: not yet implemented via "
                 "Nodus SDK");
    return DNAC_ERROR_NOT_FOUND;
}
