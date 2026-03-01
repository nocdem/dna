/**
 * @file tcp_client.c
 * @brief DNAC witness client functions — Nodus v5 SDK based
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
#include <time.h>

#include "dnac/nodus.h"
#include "dnac/ledger.h"
#include "dnac/commitment.h"
#include "dnac/wallet.h"
#include "dnac/db.h"
#include "crypto/utils/qgp_random.h"
#include "crypto/utils/qgp_log.h"
#include <openssl/evp.h>

/* Nodus client SDK (public API) */
#include "nodus/nodus.h"

/* Nodus singleton access (not on DNAC include path, use extern) */
extern nodus_client_t *nodus_singleton_get(void);
extern void nodus_singleton_lock(void);
extern void nodus_singleton_unlock(void);

#define LOG_TAG "NODUS_TCP"

/* External wallet functions */
extern dna_engine_t *dnac_get_engine(dnac_context_t *ctx);
extern const char *dnac_get_owner_fingerprint(dnac_context_t *ctx);

/* Compute SHA3-512 hash */
static int compute_sha3_512(const uint8_t *data, size_t len,
                             uint8_t *hash_out) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;

    if (EVP_DigestInit_ex(ctx, EVP_sha3_512(), NULL) != 1 ||
        EVP_DigestUpdate(ctx, data, len) != 1 ||
        EVP_DigestFinal_ex(ctx, hash_out, NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    EVP_MD_CTX_free(ctx);
    return 0;
}

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
        if (compute_sha3_512(entry->pubkey, NODUS_PK_BYTES, fp_hash) == 0) {
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
    if (!fingerprint) return DNAC_ERROR_NOT_INITIALIZED;

    nodus_client_t *client = nodus_singleton_get();
    if (!client) return DNAC_ERROR_NOT_INITIALIZED;

    nodus_singleton_lock();

    nodus_dnac_utxo_result_t result;
    int rc = nodus_client_dnac_utxo(client, fingerprint,
                                      NODUS_DNAC_MAX_UTXO_RESULTS, &result);

    nodus_singleton_unlock();

    if (rc != 0) {
        QGP_LOG_ERROR(LOG_TAG, "UTXO recovery failed: %d", rc);
        return DNAC_ERROR_NETWORK;
    }

    /* Sum up UTXOs */
    int count = 0;
    uint64_t total = 0;
    for (int i = 0; i < result.count; i++) {
        total += result.entries[i].amount;
        count++;

        QGP_LOG_DEBUG(LOG_TAG, "Found UTXO: amount=%llu, output_index=%u",
                      (unsigned long long)result.entries[i].amount,
                      result.entries[i].output_index);
    }

    nodus_client_free_utxo_result(&result);

    if (recovered_count) *recovered_count = count;
    if (total_amount) *total_amount = total;

    if (count > 0) {
        QGP_LOG_INFO(LOG_TAG, "Witness recovery found %d UTXOs, total: %llu",
                     count, (unsigned long long)total);
    } else {
        QGP_LOG_INFO(LOG_TAG, "No UTXOs found for this identity");
    }

    return DNAC_SUCCESS;
}

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
