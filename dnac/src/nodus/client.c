/**
 * @file client.c
 * @brief Witness server client (DHT-based)
 *
 * Implements the client-side of the witness attestation protocol:
 * 1. Client PUTs SpendRequest to witness server's request key
 * 2. Witness checks nullifier, signs if OK, PUTs response
 * 3. Client GETs responses from all servers
 * 4. Client collects 2+ witness signatures
 *
 * Communication is DHT-based (no direct TCP).
 */

#include "dnac/nodus.h"
#include "dnac/wallet.h"
#include "dnac/witness.h"
#include "dnac/epoch.h"
#include <dna/dna_engine.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <pthread.h>
#include <openssl/evp.h>

/* libdna crypto utilities */
#include "crypto/utils/qgp_dilithium.h"
#include "crypto/utils/qgp_log.h"

#include "nodus_ops.h"

/* Dilithium5 verification from libdna */
extern int dna_engine_verify_signature(dna_engine_t *engine,
                                       const uint8_t *pubkey,
                                       size_t pubkey_len,
                                       const uint8_t *data,
                                       size_t data_len,
                                       const uint8_t *signature,
                                       size_t sig_len);

#define LOG_TAG "DNAC_NODUS"

/* DHT key prefixes */
#define NODUS_REQUEST_PREFIX "dnac:nodus:request:"
#define NODUS_RESPONSE_PREFIX "dnac:nodus:response:"

/* Epoch-based DHT key prefixes */
#define NODUS_ANNOUNCE_PREFIX      "dnac:witness:announce:"
#define NODUS_EPOCH_REQUEST_PREFIX "dnac:nodus:epoch:request:"

/* Retry configuration */
#define NODUS_MAX_RETRIES       3
#define NODUS_RETRY_DELAY_MS    1000
#define NODUS_POLL_INTERVAL_MS  500

/* ============================================================================
 * Witness Collection Context (for listener callback)
 * ========================================================================== */

typedef struct {
    dnac_witness_sig_t *witnesses;       /* Output array */
    int *count;                          /* Pointer to witness count */
    int required;                        /* Number of witnesses needed */
    dnac_witness_info_t *servers;        /* Known servers for pubkey lookup */
    int server_count;
    const uint8_t *tx_hash;              /* Transaction hash for verification */
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    bool done;
} witness_collect_ctx_t;

/* ============================================================================
 * Internal State
 * ========================================================================== */

/* Cached witness server list (shared with discovery.c) */
dnac_witness_info_t *g_witness_servers = NULL;
int g_witness_count = 0;
uint64_t g_witness_cache_time = 0;
#define WITNESS_CACHE_TTL_SEC 300  /* 5 minute cache */

/* ============================================================================
 * Helper Functions
 * ========================================================================== */

/**
 * Compute SHA3-512 hash of data
 */
static int compute_sha3_512(const uint8_t *data, size_t len, uint8_t *hash_out) {
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

/**
 * Build DHT key for witness request
 * Key: SHA3-512("dnac:nodus:request:" + witness_id + ":" + tx_hash)
 */
static int build_request_key(const uint8_t *witness_id, const uint8_t *tx_hash,
                             uint8_t *key_out) {
    uint8_t key_data[256];
    size_t offset = 0;

    memcpy(key_data + offset, NODUS_REQUEST_PREFIX, strlen(NODUS_REQUEST_PREFIX));
    offset += strlen(NODUS_REQUEST_PREFIX);
    memcpy(key_data + offset, witness_id, 32);
    offset += 32;
    key_data[offset++] = ':';
    memcpy(key_data + offset, tx_hash, DNAC_TX_HASH_SIZE);
    offset += DNAC_TX_HASH_SIZE;

    return compute_sha3_512(key_data, offset, key_out);
}

/**
 * Build DHT key for witness response
 * Key: SHA3-512("dnac:nodus:response:" + tx_hash + ":" + requester_fp)
 */
static int build_response_key(const uint8_t *tx_hash, const char *requester_fp,
                              uint8_t *key_out) {
    uint8_t key_data[512];
    size_t offset = 0;

    memcpy(key_data + offset, NODUS_RESPONSE_PREFIX, strlen(NODUS_RESPONSE_PREFIX));
    offset += strlen(NODUS_RESPONSE_PREFIX);
    memcpy(key_data + offset, tx_hash, DNAC_TX_HASH_SIZE);
    offset += DNAC_TX_HASH_SIZE;
    key_data[offset++] = ':';
    size_t fp_len = strlen(requester_fp);
    memcpy(key_data + offset, requester_fp, fp_len);
    offset += fp_len;

    return compute_sha3_512(key_data, offset, key_out);
}

/**
 * Build permanent announcement key for witness
 * Key: SHA3-512("dnac:witness:announce:" + witness_fingerprint)
 */
static int build_announcement_key(const char *witness_fp, const uint8_t *chain_id,
                                    uint8_t *key_out) {
    uint8_t key_data[384];
    size_t offset = 0;

    memcpy(key_data, NODUS_ANNOUNCE_PREFIX, strlen(NODUS_ANNOUNCE_PREFIX));
    offset += strlen(NODUS_ANNOUNCE_PREFIX);

    /* v0.10.0: Include chain_id hex for zone scoping */
    if (chain_id) {
        static const char hex[] = "0123456789abcdef";
        for (int i = 0; i < 32; i++) {
            key_data[offset++] = hex[(chain_id[i] >> 4) & 0xF];
            key_data[offset++] = hex[chain_id[i] & 0xF];
        }
        key_data[offset++] = ':';
    }

    size_t fp_len = strlen(witness_fp);
    memcpy(key_data + offset, witness_fp, fp_len);
    offset += fp_len;

    return compute_sha3_512(key_data, offset, key_out);
}

/**
 * Build epoch-based request key
 * Key: SHA3-512("dnac:nodus:epoch:request:" + witness_fp + ":" + epoch)
 */
static int build_epoch_request_key(const char *witness_fp, uint64_t epoch,
                                   uint8_t *key_out) {
    uint8_t key_data[256];
    size_t offset = 0;

    memcpy(key_data, NODUS_EPOCH_REQUEST_PREFIX,
           strlen(NODUS_EPOCH_REQUEST_PREFIX));
    offset += strlen(NODUS_EPOCH_REQUEST_PREFIX);

    size_t fp_len = strlen(witness_fp);
    memcpy(key_data + offset, witness_fp, fp_len);
    offset += fp_len;

    key_data[offset++] = ':';

    /* Append epoch as 8-byte little-endian */
    for (int i = 0; i < 8; i++) {
        key_data[offset++] = (epoch >> (i * 8)) & 0xFF;
    }

    return compute_sha3_512(key_data, offset, key_out);
}

/**
 * Fetch witness announcement from permanent DHT key
 */
static int fetch_witness_announcement(const char *witness_fp,
                                      dnac_witness_announcement_t *announcement_out) {
    /* Build announcement key */
    uint8_t announce_key[64];
    if (build_announcement_key(witness_fp, NULL, announce_key) != 0) {
        return -1;
    }

    /* GET from DHT */
    uint8_t *data = NULL;
    size_t data_len = 0;
    int rc = nodus_ops_get(announce_key, 64, &data, &data_len);

    if (rc != 0 || !data || data_len == 0) {
        return -1;
    }

    /* Deserialize */
    rc = witness_announcement_deserialize(data, data_len, announcement_out);
    free(data);

    return rc;
}

/**
 * Get current timestamp in milliseconds
 */
static uint64_t get_time_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

/**
 * Sleep for milliseconds
 */
static void sleep_ms(int ms) {
    struct timespec ts = { .tv_sec = ms / 1000, .tv_nsec = (ms % 1000) * 1000000 };
    nanosleep(&ts, NULL);
}

/**
 * DHT listener callback for witness responses
 */
static bool witness_response_callback(const uint8_t *value, size_t value_len,
                                      bool expired, void *user_data) {
    QGP_LOG_DEBUG(LOG_TAG, "witness_response_callback: len=%zu expired=%d", value_len, expired);
    witness_collect_ctx_t *ctx = (witness_collect_ctx_t *)user_data;
    if (!ctx) return false;
    if (expired || !value || value_len == 0) return true;

    pthread_mutex_lock(&ctx->mutex);

    /* Already have enough? */
    if (ctx->done || *ctx->count >= ctx->required) {
        pthread_mutex_unlock(&ctx->mutex);
        return false;  /* Stop listening */
    }

    /* Deserialize response */
    dnac_spend_response_t response;
    int deser_rc = dnac_spend_response_deserialize(value, value_len, &response);
    if (deser_rc != 0) {
        QGP_LOG_DEBUG(LOG_TAG, "response_callback: deserialize failed rc=%d", deser_rc);
        pthread_mutex_unlock(&ctx->mutex);
        return true;  /* Continue listening */
    }

    QGP_LOG_DEBUG(LOG_TAG, "response_callback: status=%d witness_id=%02x%02x%02x%02x...",
                  response.status, response.witness_id[0], response.witness_id[1],
                  response.witness_id[2], response.witness_id[3]);

    if (response.status != DNAC_NODUS_STATUS_APPROVED) {
        QGP_LOG_DEBUG(LOG_TAG, "response_callback: not approved, continuing");
        pthread_mutex_unlock(&ctx->mutex);
        return true;
    }

    /* Find server's public key */
    const uint8_t *witness_pubkey = NULL;
    for (int i = 0; i < ctx->server_count; i++) {
        uint8_t witness_id_bytes[32];
        for (int j = 0; j < 32; j++) {
            sscanf(&ctx->servers[i].id[j*2], "%2hhx", &witness_id_bytes[j]);
        }
        if (memcmp(witness_id_bytes, response.witness_id, 32) == 0) {
            witness_pubkey = ctx->servers[i].pubkey;
            QGP_LOG_DEBUG(LOG_TAG, "response_callback: found witness pubkey in server list");
            break;
        }
    }

    /* Use response.server_pubkey if available */
    const uint8_t *verify_pubkey = witness_pubkey;
    if (response.server_pubkey[0] != 0) {
        verify_pubkey = response.server_pubkey;
        QGP_LOG_DEBUG(LOG_TAG, "response_callback: using server_pubkey from response");
    }

    if (!verify_pubkey) {
        QGP_LOG_DEBUG(LOG_TAG, "response_callback: no verify_pubkey available");
        pthread_mutex_unlock(&ctx->mutex);
        return true;
    }

    /* Build witness sig and verify */
    dnac_witness_sig_t witness;
    memcpy(witness.witness_id, response.witness_id, 32);
    memcpy(witness.signature, response.signature, DNAC_SIGNATURE_SIZE);
    memcpy(witness.server_pubkey, verify_pubkey, DNAC_PUBKEY_SIZE);
    witness.timestamp = response.timestamp;

    if (!dnac_witness_verify(&witness, ctx->tx_hash, verify_pubkey)) {
        QGP_LOG_ERROR(LOG_TAG, "response_callback: witness signature verification FAILED");
        pthread_mutex_unlock(&ctx->mutex);
        return true;
    }
    QGP_LOG_INFO(LOG_TAG, "response_callback: witness %02x%02x%02x%02x... v%d.%d.%d VERIFIED",
                 response.witness_id[0], response.witness_id[1],
                 response.witness_id[2], response.witness_id[3],
                 response.software_version[0],
                 response.software_version[1],
                 response.software_version[2]);

    /* Check for duplicate */
    for (int i = 0; i < *ctx->count; i++) {
        if (memcmp(ctx->witnesses[i].witness_id, witness.witness_id, 32) == 0) {
            pthread_mutex_unlock(&ctx->mutex);
            return true;  /* Duplicate, continue listening */
        }
    }

    /* Store witness signature */
    ctx->witnesses[*ctx->count] = witness;
    (*ctx->count)++;

    /* Have enough? Signal completion */
    if (*ctx->count >= ctx->required) {
        ctx->done = true;
        pthread_cond_signal(&ctx->cond);
        pthread_mutex_unlock(&ctx->mutex);
        return false;  /* Stop listening */
    }

    pthread_mutex_unlock(&ctx->mutex);
    return true;  /* Continue listening */
}

/* ============================================================================
 * Public Functions
 * ========================================================================== */

int dnac_witness_init(dnac_context_t *ctx) {
    if (!ctx) return -1;

    /* Clear cached server list */
    if (g_witness_servers) {
        dnac_free_witness_list(g_witness_servers, g_witness_count);
        g_witness_servers = NULL;
        g_witness_count = 0;
    }
    g_witness_cache_time = 0;

    return 0;
}

void dnac_witness_shutdown(dnac_context_t *ctx) {
    (void)ctx;

    /* Free cached server list */
    if (g_witness_servers) {
        dnac_free_witness_list(g_witness_servers, g_witness_count);
        g_witness_servers = NULL;
        g_witness_count = 0;
    }
}

/* External BFT TCP-based witness request function */
extern int dnac_bft_witness_request(void *dna_engine,
                                    const dnac_spend_request_t *request,
                                    dnac_witness_sig_t *witnesses_out,
                                    int *witness_count_out);

int dnac_witness_request(dnac_context_t *ctx,
                         const dnac_spend_request_t *request,
                         dnac_witness_sig_t *witnesses_out,
                         int *witness_count_out) {
    if (!ctx || !request || !witnesses_out || !witness_count_out) {
        return DNAC_ERROR_INVALID_PARAM;
    }

    *witness_count_out = 0;

    /* Get DNA engine */
    dna_engine_t *engine = dnac_get_engine(ctx);
    if (!engine) return DNAC_ERROR_NOT_INITIALIZED;

    QGP_LOG_INFO(LOG_TAG, "Using BFT TCP-based witness request");

    /* Use TCP-based BFT witness request
     * BFT consensus handles the request, collecting signatures from quorum.
     * With BFT, we get one "consensus signature" that represents agreement
     * of 2f+1 witnesses, but for backwards compatibility we report it as
     * a single witness response.
     */
    int rc = dnac_bft_witness_request(engine, request, witnesses_out, witness_count_out);

    if (rc == DNAC_SUCCESS) {
        QGP_LOG_INFO(LOG_TAG, "BFT consensus approved transaction with %d attestation(s)",
                     *witness_count_out);

        /* BFT returns 1 attestation representing consensus agreement.
         * The BFT consensus ensures at least 2 witnesses agreed internally,
         * so 1 signed attestation proves quorum was reached.
         * We keep the actual count (1) instead of inflating to 2 to avoid
         * sending garbage data for unpopulated witness slots. */

        return DNAC_SUCCESS;
    }

    if (rc == DNAC_ERROR_DOUBLE_SPEND) {
        QGP_LOG_WARN(LOG_TAG, "BFT consensus rejected: double spend");
        return DNAC_ERROR_DOUBLE_SPEND;
    }

    QGP_LOG_ERROR(LOG_TAG, "BFT witness request failed: %d", rc);
    return DNAC_ERROR_WITNESS_FAILED;
}

int dnac_witness_check_nullifier(dnac_context_t *ctx,
                                 const uint8_t *nullifier,
                                 bool *is_spent_out) {
    if (!ctx || !nullifier || !is_spent_out) {
        return DNAC_ERROR_INVALID_PARAM;
    }

    *is_spent_out = false;

    /* Build nullifier lookup key */
    /* Key: SHA3-512("dnac:nullifier:" + nullifier) */
    uint8_t key_data[256];
    size_t offset = 0;
    const char *prefix = "dnac:nullifier:";
    memcpy(key_data, prefix, strlen(prefix));
    offset = strlen(prefix);
    memcpy(key_data + offset, nullifier, DNAC_NULLIFIER_SIZE);
    offset += DNAC_NULLIFIER_SIZE;

    uint8_t lookup_key[64];
    if (compute_sha3_512(key_data, offset, lookup_key) != 0) {
        return DNAC_ERROR_CRYPTO;
    }

    /* Query DHT for nullifier */
    uint8_t *value = NULL;
    size_t value_len = 0;
    int rc = nodus_ops_get(lookup_key, 64, &value, &value_len);

    if (rc == 0 && value && value_len > 0) {
        /* Nullifier found - it has been spent */
        *is_spent_out = true;
        free(value);
    }

    return DNAC_SUCCESS;
}

bool dnac_witness_verify(const dnac_witness_sig_t *witness,
                         const uint8_t *tx_hash,
                         const uint8_t *witness_pubkey) {
    if (!witness || !tx_hash || !witness_pubkey) return false;

    /* Build signed data: tx_hash + witness_id + timestamp */
    uint8_t signed_data[DNAC_TX_HASH_SIZE + 32 + 8];
    memcpy(signed_data, tx_hash, DNAC_TX_HASH_SIZE);
    memcpy(signed_data + DNAC_TX_HASH_SIZE, witness->witness_id, 32);

    /* Little-endian timestamp */
    for (int i = 0; i < 8; i++) {
        signed_data[DNAC_TX_HASH_SIZE + 32 + i] = (witness->timestamp >> (i * 8)) & 0xFF;
    }

    /* Verify Dilithium5 signature */
    int ret = qgp_dsa87_verify(witness->signature, DNAC_SIGNATURE_SIZE,
                               signed_data, sizeof(signed_data),
                               witness_pubkey);
    return (ret == 0);
}

uint64_t dnac_witness_calculate_fee(uint64_t amount) {
    /* 0.1% fee (10 basis points) */
    uint64_t fee = (amount * DNAC_FEE_RATE_BPS) / 10000;
    return fee > 0 ? fee : 1;  /* Minimum 1 unit */
}

int dnac_witness_ping(dnac_context_t *ctx,
                      const uint8_t *server_id,
                      int *latency_ms_out) {
    if (!ctx || !server_id || !latency_ms_out) {
        return -1;
    }

    *latency_ms_out = -1;

    /* Build ping key */
    uint8_t key_data[128];
    const char *prefix = "dnac:nodus:ping:";
    memcpy(key_data, prefix, strlen(prefix));
    memcpy(key_data + strlen(prefix), server_id, 32);

    uint8_t ping_key[64];
    if (compute_sha3_512(key_data, strlen(prefix) + 32, ping_key) != 0) {
        return -1;
    }

    /* PUT ping and measure time to GET response */
    uint64_t start = get_time_ms();

    uint8_t ping_data[8];
    memcpy(ping_data, &start, 8);

    int rc = nodus_ops_put_permanent(ping_key, 64, ping_data, 8,
                                     start % 1000);
    if (rc != 0) return -1;

    /* Wait for pong (response at same key from server) */
    sleep_ms(100);  /* Give server time to respond */

    uint8_t *pong_data = NULL;
    size_t pong_len = 0;
    rc = nodus_ops_get(ping_key, 64, &pong_data, &pong_len);

    if (rc == 0 && pong_data && pong_len >= 8) {
        uint64_t end = get_time_ms();
        *latency_ms_out = (int)(end - start);
        free(pong_data);
        return 0;
    }

    if (pong_data) free(pong_data);
    return -1;
}
