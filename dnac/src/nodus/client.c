/**
 * @file client.c
 * @brief Witness client — Nodus SDK based
 *
 * All witness operations go through the Nodus client SDK
 * (nodus_client_dnac_*) which communicates with witnesses
 * via CBOR over Nodus TCP.
 */

#include "dnac/nodus.h"
#include "dnac/wallet.h"
#include "dnac/block.h"
#include "dnac/chain_def_codec.h"
#include <string.h>
#include <stdlib.h>
#include <pthread.h>

/* libdna crypto utilities */
#include "crypto/sign/qgp_dilithium.h"
#include "crypto/hash/qgp_sha3.h"
#include "crypto/utils/qgp_log.h"

/* Nodus client SDK (public API) */
#include "nodus/nodus.h"
#include "crypto/utils/qgp_safe_string.h"   /* Phase 03: unsafe-string poison guard */

/* Nodus singleton access (not on DNAC include path, use extern) */
extern nodus_client_t *nodus_singleton_get(void);
extern void nodus_singleton_lock(void);
extern void nodus_singleton_unlock(void);

#define LOG_TAG "DNAC_NODUS"

/* ============================================================================
 * Internal State
 * ========================================================================== */

/* Cached witness server list (shared with discovery.c) */
dnac_witness_info_t *g_witness_servers = NULL;
int g_witness_count = 0;
uint64_t g_witness_cache_time = 0;
pthread_mutex_t g_witness_cache_mutex = PTHREAD_MUTEX_INITIALIZER;  /* M-30 */
#define WITNESS_CACHE_TTL_SEC 300  /* 5 minute cache */

/* ============================================================================
 * Public Functions
 * ========================================================================== */

int dnac_witness_init(dnac_context_t *ctx) {
    if (!ctx) return -1;

    /* Clear cached server list */
    pthread_mutex_lock(&g_witness_cache_mutex);
    if (g_witness_servers) {
        dnac_free_witness_list(g_witness_servers, g_witness_count);
        g_witness_servers = NULL;
        g_witness_count = 0;
    }
    g_witness_cache_time = 0;
    pthread_mutex_unlock(&g_witness_cache_mutex);

    return 0;
}

void dnac_witness_shutdown(dnac_context_t *ctx) {
    (void)ctx;

    /* Free cached server list */
    pthread_mutex_lock(&g_witness_cache_mutex);
    if (g_witness_servers) {
        dnac_free_witness_list(g_witness_servers, g_witness_count);
        g_witness_servers = NULL;
        g_witness_count = 0;
    }
    pthread_mutex_unlock(&g_witness_cache_mutex);
}

int dnac_witness_request(dnac_context_t *ctx,
                         const dnac_spend_request_t *request,
                         dnac_witness_sig_t *witnesses_out,
                         int *witness_count_out) {
    if (!ctx || !request || !witnesses_out || !witness_count_out) {
        return DNAC_ERROR_INVALID_PARAM;
    }

    *witness_count_out = 0;

    nodus_client_t *client = nodus_singleton_get();
    if (!client) {
        QGP_LOG_ERROR(LOG_TAG, "Nodus singleton not initialized");
        return DNAC_ERROR_NOT_INITIALIZED;
    }

    nodus_singleton_lock();

    /* Build nodus types from DNAC request */
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
        if (rc == NODUS_ERR_TIMEOUT) {
            QGP_LOG_ERROR(LOG_TAG, "Witness request timed out");
            return DNAC_ERROR_TIMEOUT;
        }
        if (rc == NODUS_ERR_ALREADY_EXISTS) {
            QGP_LOG_WARN(LOG_TAG, "Genesis already exists");
            return DNAC_ERROR_GENESIS_EXISTS;
        }
        if (rc == NODUS_ERR_DOUBLE_SPEND) {
            QGP_LOG_WARN(LOG_TAG, "Double-spend detected");
            return DNAC_ERROR_DOUBLE_SPEND;
        }
        QGP_LOG_ERROR(LOG_TAG, "Witness request failed: %d", rc);
        return DNAC_ERROR_WITNESS_FAILED;
    }

    if (result.status != NODUS_DNAC_APPROVED) {
        QGP_LOG_WARN(LOG_TAG, "Witness rejected: status=%d", result.status);
        return DNAC_ERROR_DOUBLE_SPEND;
    }

    /* Copy witness signature */
    memcpy(witnesses_out[0].witness_id, result.witness_id, 32);
    memcpy(witnesses_out[0].signature, result.signature, NODUS_SIG_BYTES);
    memcpy(witnesses_out[0].server_pubkey, result.witness_pubkey, NODUS_PK_BYTES);
    witnesses_out[0].timestamp = result.timestamp;
    /* Phase 13 / Task 13.1 — receipt fields (block_height, tx_index,
     * chain_id) needed for client-side spndrslt preimage verification. */
    witnesses_out[0].block_height = result.block_height;
    witnesses_out[0].tx_index = result.tx_index;
    memcpy(witnesses_out[0].chain_id, result.chain_id, 32);

    *witness_count_out = 1;

    QGP_LOG_INFO(LOG_TAG, "BFT consensus approved transaction");
    return DNAC_SUCCESS;
}

int dnac_get_current_fee(dnac_context_t *ctx, uint64_t *fee_out) {
    if (!ctx || !fee_out) return DNAC_ERROR_INVALID_PARAM;

    nodus_client_t *client = nodus_singleton_get();
    if (!client) return DNAC_ERROR_NOT_INITIALIZED;

    nodus_singleton_lock();

    nodus_dnac_fee_info_t info;
    int rc = nodus_client_dnac_fee_info(client, &info);

    nodus_singleton_unlock();

    if (rc != 0) {
        /* Fallback: use base fee if witness unreachable */
        *fee_out = 1000000;  /* 0.01 DNAC */
        return DNAC_SUCCESS;
    }

    *fee_out = info.min_fee;

    /* Perf-harness override (2026-04-24): DNA_BENCH_FEE_MULT env
     * multiplies the dynamic fee. Lets bench clients out-pay the
     * query→submit surge race. Ignored when unset or <1; capped at
     * 100 so a stray env cannot blow past reason. No production
     * effect unless the env var is explicitly set. */
    const char *mult_env = getenv("DNA_BENCH_FEE_MULT");
    if (mult_env && *mult_env) {
        char *end = NULL;
        unsigned long mult = strtoul(mult_env, &end, 10);
        if (end && *end == '\0' && mult > 1 && mult <= 100) {
            *fee_out *= mult;
        }
    }
    return DNAC_SUCCESS;
}

int dnac_witness_replay(dnac_context_t *ctx,
                         const uint8_t *tx_hash,
                         dnac_witness_sig_t *witness_out) {
    if (!ctx || !tx_hash || !witness_out) {
        return DNAC_ERROR_INVALID_PARAM;
    }

    memset(witness_out, 0, sizeof(*witness_out));

    nodus_client_t *client = nodus_singleton_get();
    if (!client) {
        QGP_LOG_ERROR(LOG_TAG, "Nodus singleton not initialized");
        return DNAC_ERROR_NOT_INITIALIZED;
    }

    nodus_singleton_lock();

    nodus_dnac_spend_result_t result;
    int rc = nodus_client_dnac_spend_replay(client, tx_hash, &result);

    nodus_singleton_unlock();

    if (rc != 0) {
        if (rc == NODUS_ERR_NOT_FOUND) {
            QGP_LOG_DEBUG(LOG_TAG, "Spend replay: tx_hash not committed");
            return DNAC_ERROR_NOT_FOUND;
        }
        if (rc == NODUS_ERR_TIMEOUT) {
            QGP_LOG_WARN(LOG_TAG, "Spend replay timed out");
            return DNAC_ERROR_TIMEOUT;
        }
        QGP_LOG_ERROR(LOG_TAG, "Spend replay failed: %d", rc);
        return DNAC_ERROR_NETWORK;
    }

    if (result.status != NODUS_DNAC_APPROVED) {
        QGP_LOG_WARN(LOG_TAG, "Spend replay: unexpected status=%d",
                     result.status);
        return DNAC_ERROR_NOT_FOUND;
    }

    /* Mirror the layout of dnac_witness_request's witnesses_out[0]. */
    memcpy(witness_out->witness_id, result.witness_id, 32);
    memcpy(witness_out->signature, result.signature, NODUS_SIG_BYTES);
    memcpy(witness_out->server_pubkey, result.witness_pubkey, NODUS_PK_BYTES);
    witness_out->timestamp = result.timestamp;
    witness_out->block_height = result.block_height;
    witness_out->tx_index = result.tx_index;
    memcpy(witness_out->chain_id, result.chain_id, 32);

    QGP_LOG_INFO(LOG_TAG, "Spend replay recovered receipt for committed TX "
                          "(block=%llu, tx_index=%u)",
                 (unsigned long long)result.block_height, result.tx_index);
    return DNAC_SUCCESS;
}

int dnac_witness_check_nullifier(dnac_context_t *ctx,
                                 const uint8_t *nullifier,
                                 bool *is_spent_out) {
    if (!ctx || !nullifier || !is_spent_out) {
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

bool dnac_witness_verify(const dnac_witness_sig_t *witness,
                         const uint8_t *tx_hash,
                         const uint8_t *witness_pubkey) {
    if (!witness || !tx_hash || !witness_pubkey) return false;

    /* Phase 12 / Task 13.1 — reconstruct the 221-byte spndrslt preimage
     * the witness Dilithium5-signed at commit time. Requires the
     * receipt fields (block_height, tx_index, chain_id) to be populated
     * on the witness struct — they are when the caller is verifying a
     * fresh receipt straight from nodus_client_dnac_spend, but NOT when
     * verifying a serialized TX from on-chain (those fields are
     * receipt-only and don't persist into serialize.c). */
    static const uint8_t spend_tag[8] = { 's','p','n','d','r','s','l','t' };
    uint8_t preimage[221];
    memset(preimage, 0, sizeof(preimage));

    memcpy(preimage,        spend_tag, 8);
    memcpy(preimage + 8,    tx_hash, DNAC_TX_HASH_SIZE);
    memcpy(preimage + 72,   witness->witness_id, 32);

    uint8_t wpk_hash[64];
    qgp_sha3_512(witness->server_pubkey, DNAC_PUBKEY_SIZE, wpk_hash);
    memcpy(preimage + 104, wpk_hash, 64);

    memcpy(preimage + 168, witness->chain_id, 32);

    for (int i = 0; i < 8; i++)
        preimage[200 + i] = (uint8_t)((witness->timestamp >> (i * 8)) & 0xFF);
    for (int i = 0; i < 8; i++)
        preimage[208 + i] = (uint8_t)((witness->block_height >> (i * 8)) & 0xFF);
    for (int i = 0; i < 4; i++)
        preimage[216 + i] = (uint8_t)((witness->tx_index >> (i * 8)) & 0xFF);
    preimage[220] = 0;  /* APPROVED */

    int ret = qgp_dsa87_verify(witness->signature, DNAC_SIGNATURE_SIZE,
                               preimage, sizeof(preimage), witness_pubkey);
    return (ret == 0);
}

int dnac_request_genesis(dnac_context_t *ctx, dnac_block_t *block_out) {
    if (!ctx || !block_out) return DNAC_ERROR_INVALID_PARAM;

    nodus_client_t *client = nodus_singleton_get();
    if (!client) {
        QGP_LOG_ERROR(LOG_TAG, "Nodus singleton not initialized");
        return DNAC_ERROR_NOT_INITIALIZED;
    }

    nodus_dnac_genesis_result_t result;
    memset(&result, 0, sizeof(result));

    nodus_singleton_lock();
    int rc = nodus_client_dnac_genesis(client, &result);
    nodus_singleton_unlock();

    if (rc != 0) {
        QGP_LOG_ERROR(LOG_TAG, "dnac_genesis query failed: %d", rc);
        nodus_client_free_genesis_result(&result);
        if (rc == NODUS_ERR_TIMEOUT) return DNAC_ERROR_TIMEOUT;
        return DNAC_ERROR_NETWORK;
    }

    if (!result.found) {
        QGP_LOG_WARN(LOG_TAG, "dnac_genesis: witness has no genesis row");
        nodus_client_free_genesis_result(&result);
        return DNAC_ERROR_NOT_FOUND;
    }

    if (!result.chain_def_blob || result.chain_def_blob_len == 0) {
        QGP_LOG_ERROR(LOG_TAG, "dnac_genesis: missing chain_def blob");
        nodus_client_free_genesis_result(&result);
        return DNAC_ERROR_INVALID_PARAM;
    }

    /* Reassemble a dnac_block_t from the raw fields, decode chain_def,
     * then recompute the block hash. The caller compares block_hash to
     * its hardcoded chain_id for trust bootstrap. */
    memset(block_out, 0, sizeof(*block_out));
    block_out->block_height = result.height;
    memcpy(block_out->prev_block_hash, result.prev_hash,
           DNAC_BLOCK_HASH_SIZE);
    memcpy(block_out->state_root, result.state_root,
           DNAC_BLOCK_HASH_SIZE);
    memcpy(block_out->tx_root, result.tx_root, DNAC_BLOCK_HASH_SIZE);
    block_out->tx_count = result.tx_count;
    block_out->timestamp = result.timestamp;
    memcpy(block_out->proposer_id, result.proposer_id,
           DNAC_BLOCK_PROPOSER_SIZE);
    block_out->is_genesis = true;

    if (dnac_chain_def_decode(result.chain_def_blob,
                               result.chain_def_blob_len,
                               &block_out->chain_def) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "dnac_genesis: chain_def decode failed");
        nodus_client_free_genesis_result(&result);
        memset(block_out, 0, sizeof(*block_out));
        return DNAC_ERROR_INVALID_PARAM;
    }

    nodus_client_free_genesis_result(&result);

    if (dnac_block_compute_hash(block_out) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "dnac_genesis: block_compute_hash failed");
        memset(block_out, 0, sizeof(*block_out));
        return DNAC_ERROR_INVALID_PARAM;
    }

    QGP_LOG_INFO(LOG_TAG, "dnac_genesis: fetched genesis block (height=%llu)",
                 (unsigned long long)block_out->block_height);
    return DNAC_SUCCESS;
}

/* Messenger/nodus layer helpers — declared in messenger/dht/shared/nodus_init.h
 * but not on the DNAC include path, so forward-declare here. */
extern int nodus_messenger_get_bootstrap_servers(nodus_server_endpoint_t *out,
                                                  int max_count);
extern const nodus_identity_t *nodus_messenger_get_identity_ref(void);

/* ── Per-peer genesis fetch helper ──────────────────────────────────
 * Opens a short-lived nodus client against a single endpoint, queries
 * dnac_genesis, reassembles the block, and computes its block_hash.
 * Returns 0 on success with `block_out` fully populated (including
 * block_hash). Non-zero return means this peer couldn't produce a
 * usable response — caller should skip it in the tally.
 */
static int fetch_genesis_from_peer(const nodus_server_endpoint_t *endpoint,
                                    const nodus_identity_t *identity,
                                    dnac_block_t *block_out) {
    if (!endpoint || !identity || !block_out) return -1;

    nodus_client_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.servers[0] = *endpoint;
    cfg.server_count = 1;
    cfg.request_timeout_ms = 5000;

    nodus_client_t client;
    memset(&client, 0, sizeof(client));

    if (nodus_client_init(&client, &cfg, identity) != 0) {
        QGP_LOG_DEBUG(LOG_TAG, "genesis quorum: init fail for %s:%u",
                      endpoint->ip, (unsigned)endpoint->port);
        return -1;
    }

    int rc = -1;
    if (nodus_client_connect(&client) != 0) {
        QGP_LOG_DEBUG(LOG_TAG, "genesis quorum: connect fail %s:%u",
                      endpoint->ip, (unsigned)endpoint->port);
        goto done;
    }

    nodus_dnac_genesis_result_t result;
    memset(&result, 0, sizeof(result));
    int qrc = nodus_client_dnac_genesis(&client, &result);
    if (qrc != 0 || !result.found ||
        !result.chain_def_blob || result.chain_def_blob_len == 0) {
        QGP_LOG_DEBUG(LOG_TAG, "genesis quorum: query fail %s:%u rc=%d",
                      endpoint->ip, (unsigned)endpoint->port, qrc);
        nodus_client_free_genesis_result(&result);
        goto done;
    }

    memset(block_out, 0, sizeof(*block_out));
    block_out->block_height = result.height;
    memcpy(block_out->prev_block_hash, result.prev_hash, DNAC_BLOCK_HASH_SIZE);
    memcpy(block_out->state_root, result.state_root, DNAC_BLOCK_HASH_SIZE);
    memcpy(block_out->tx_root, result.tx_root, DNAC_BLOCK_HASH_SIZE);
    block_out->tx_count = result.tx_count;
    block_out->timestamp = result.timestamp;
    memcpy(block_out->proposer_id, result.proposer_id, DNAC_BLOCK_PROPOSER_SIZE);
    block_out->is_genesis = true;

    if (dnac_chain_def_decode(result.chain_def_blob,
                               result.chain_def_blob_len,
                               &block_out->chain_def) != 0) {
        QGP_LOG_DEBUG(LOG_TAG, "genesis quorum: chain_def decode fail %s:%u",
                      endpoint->ip, (unsigned)endpoint->port);
        nodus_client_free_genesis_result(&result);
        memset(block_out, 0, sizeof(*block_out));
        goto done;
    }

    nodus_client_free_genesis_result(&result);

    if (dnac_block_compute_hash(block_out) != 0) {
        QGP_LOG_DEBUG(LOG_TAG, "genesis quorum: block_compute_hash fail %s:%u",
                      endpoint->ip, (unsigned)endpoint->port);
        memset(block_out, 0, sizeof(*block_out));
        goto done;
    }

    rc = 0;

done:
    nodus_client_close(&client);
    return rc;
}

int dnac_request_genesis_quorum(dnac_context_t *ctx,
                                 dnac_block_t *block_out,
                                 int *verified_count_out,
                                 int *total_responses_out) {
    if (!ctx || !block_out) return DNAC_ERROR_INVALID_PARAM;

    if (verified_count_out) *verified_count_out = 0;
    if (total_responses_out) *total_responses_out = 0;

    nodus_server_endpoint_t servers[NODUS_CLIENT_MAX_SERVERS];
    int server_count = nodus_messenger_get_bootstrap_servers(
        servers, NODUS_CLIENT_MAX_SERVERS);
    if (server_count < DNAC_GENESIS_QUORUM_THRESHOLD) {
        QGP_LOG_ERROR(LOG_TAG,
            "genesis quorum: bootstrap list has %d peers, need >= %d",
            server_count, DNAC_GENESIS_QUORUM_THRESHOLD);
        return DNAC_ERROR_NOT_INITIALIZED;
    }

    const nodus_identity_t *identity = nodus_messenger_get_identity_ref();
    if (!identity) {
        QGP_LOG_ERROR(LOG_TAG, "genesis quorum: no loaded identity");
        return DNAC_ERROR_NOT_INITIALIZED;
    }

    dnac_block_t *blocks = calloc((size_t)server_count, sizeof(dnac_block_t));
    if (!blocks) return DNAC_ERROR_OUT_OF_MEMORY;

    int got = 0;
    for (int i = 0; i < server_count; i++) {
        if (fetch_genesis_from_peer(&servers[i], identity, &blocks[got]) == 0) {
            got++;
        }
    }

    if (total_responses_out) *total_responses_out = got;

    if (got == 0) {
        QGP_LOG_ERROR(LOG_TAG,
            "genesis quorum: no peers returned a usable response");
        free(blocks);
        return DNAC_ERROR_TIMEOUT;
    }

    /* Tally by block_hash — find the majority */
    int best_votes = 0;
    int best_idx = -1;
    for (int i = 0; i < got; i++) {
        int votes = 0;
        for (int j = 0; j < got; j++) {
            if (memcmp(blocks[i].block_hash, blocks[j].block_hash,
                        DNAC_BLOCK_HASH_SIZE) == 0) {
                votes++;
            }
        }
        if (votes > best_votes) {
            best_votes = votes;
            best_idx = i;
        }
    }

    if (verified_count_out) *verified_count_out = best_votes;

    if (best_votes < DNAC_GENESIS_QUORUM_THRESHOLD) {
        QGP_LOG_ERROR(LOG_TAG,
            "genesis quorum: only %d/%d peers agree, need >= %d — possible "
            "compromised bootstrap or chain divergence",
            best_votes, got, DNAC_GENESIS_QUORUM_THRESHOLD);
        free(blocks);
        return (got < DNAC_GENESIS_QUORUM_THRESHOLD)
                   ? DNAC_ERROR_TIMEOUT
                   : DNAC_ERROR_WITNESS_FAILED;
    }

    QGP_LOG_INFO(LOG_TAG,
        "genesis quorum: %d/%d peers agree on genesis block (height=%llu)",
        best_votes, got, (unsigned long long)blocks[best_idx].block_height);
    memcpy(block_out, &blocks[best_idx], sizeof(dnac_block_t));
    free(blocks);
    return DNAC_SUCCESS;
}

int dnac_witness_ping(dnac_context_t *ctx,
                      const uint8_t *server_id,
                      int *latency_ms_out) {
    (void)ctx; (void)server_id;

    if (!latency_ms_out) return -1;
    *latency_ms_out = -1;

    /* Ping is handled by Nodus SDK connection-level keepalive.
     * For health checking, use nodus_client_is_ready(). */
    nodus_client_t *client = nodus_singleton_get();
    if (!client || !nodus_client_is_ready(client)) return -1;

    *latency_ms_out = 0;
    return 0;
}
