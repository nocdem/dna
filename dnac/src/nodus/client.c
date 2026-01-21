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
#include <dna/dna_engine.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <pthread.h>
#include <openssl/evp.h>

/* libdna crypto utilities */
#include "crypto/utils/qgp_dilithium.h"

/* Forward declare DHT context type */
typedef struct dht_context dht_context_t;

/* DHT functions from libdna */
extern void* dna_engine_get_dht_context(dna_engine_t *engine);
extern int dht_put_signed(dht_context_t *ctx,
                          const uint8_t *key, size_t key_len,
                          const uint8_t *value, size_t value_len,
                          uint64_t value_id,
                          unsigned int ttl_seconds,
                          const char *caller);
extern int dht_get(dht_context_t *ctx,
                   const uint8_t *key, size_t key_len,
                   uint8_t **value_out, size_t *value_len_out);

/* DHT listen callback type */
typedef bool (*dht_listen_callback_t)(
    const uint8_t *value,
    size_t value_len,
    bool expired,
    void *user_data
);

/* DHT listen functions from libdna */
extern size_t dht_listen(dht_context_t *ctx,
                         const uint8_t *key, size_t key_len,
                         dht_listen_callback_t callback,
                         void *user_data);
extern void dht_cancel_listen(dht_context_t *ctx, size_t token);

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
    if (dnac_spend_response_deserialize(value, value_len, &response) != 0) {
        pthread_mutex_unlock(&ctx->mutex);
        return true;  /* Continue listening */
    }

    if (response.status != DNAC_NODUS_STATUS_APPROVED) {
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
            break;
        }
    }

    /* Use response.server_pubkey if available */
    const uint8_t *verify_pubkey = witness_pubkey;
    if (response.server_pubkey[0] != 0) {
        verify_pubkey = response.server_pubkey;
    }

    if (!verify_pubkey) {
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
        pthread_mutex_unlock(&ctx->mutex);
        return true;
    }

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

int dnac_witness_request(dnac_context_t *ctx,
                         const dnac_spend_request_t *request,
                         dnac_witness_sig_t *witnesses_out,
                         int *witness_count_out) {
    if (!ctx || !request || !witnesses_out || !witness_count_out) {
        return DNAC_ERROR_INVALID_PARAM;
    }

    *witness_count_out = 0;

    /* Get DNA engine and DHT context */
    dna_engine_t *engine = dnac_get_engine(ctx);
    if (!engine) return DNAC_ERROR_NOT_INITIALIZED;

    dht_context_t *dht = (dht_context_t *)dna_engine_get_dht_context(engine);
    if (!dht) return DNAC_ERROR_NETWORK;

    /* Get owner fingerprint for response key */
    const char *owner_fp = dnac_get_owner_fingerprint(ctx);
    if (!owner_fp) return DNAC_ERROR_NOT_INITIALIZED;

    /* Discover witness servers if needed */
    dnac_witness_info_t *servers = NULL;
    int server_count = 0;
    int rc = dnac_witness_discover(ctx, &servers, &server_count);
    if (rc != DNAC_SUCCESS || server_count == 0) {
        return DNAC_ERROR_NETWORK;
    }

    /* Serialize spend request */
    uint8_t req_buffer[16384];
    size_t req_len = 0;
    rc = dnac_spend_request_serialize(request, req_buffer, sizeof(req_buffer), &req_len);
    if (rc != 0) {
        dnac_free_witness_list(servers, server_count);
        return DNAC_ERROR_CRYPTO;
    }

    /* Send request to all witness servers */
    int servers_contacted = 0;
    for (int i = 0; i < server_count && i < DNAC_MAX_WITNESS_SERVERS; i++) {
        /* Build request key for this server */
        uint8_t request_key[64];
        uint8_t witness_id_bytes[32];

        /* Convert hex ID to bytes */
        for (int j = 0; j < 32 && servers[i].id[j*2]; j++) {
            sscanf(&servers[i].id[j*2], "%2hhx", &witness_id_bytes[j]);
        }

        if (build_request_key(witness_id_bytes, request->tx_hash, request_key) != 0) {
            continue;
        }

        /* PUT request to DHT */
        rc = dht_put_signed(dht, request_key, 64, req_buffer, req_len,
                           1, /* value_id */
                           60, /* TTL 60 seconds */
                           "witness_request");
        if (rc == 0) {
            servers_contacted++;
        }
    }

    if (servers_contacted == 0) {
        dnac_free_witness_list(servers, server_count);
        return DNAC_ERROR_NETWORK;
    }

    /* Build response key */
    uint8_t response_key[64];
    if (build_response_key(request->tx_hash, owner_fp, response_key) != 0) {
        dnac_free_witness_list(servers, server_count);
        return DNAC_ERROR_CRYPTO;
    }

    /* Setup witness collection context */
    witness_collect_ctx_t collect_ctx = {
        .witnesses = witnesses_out,
        .count = witness_count_out,
        .required = DNAC_WITNESSES_REQUIRED,
        .servers = servers,
        .server_count = server_count,
        .tx_hash = request->tx_hash,
        .done = false
    };
    pthread_mutex_init(&collect_ctx.mutex, NULL);
    pthread_cond_init(&collect_ctx.cond, NULL);

    /* Start listening for witness responses */
    size_t listen_token = dht_listen(dht, response_key, 64,
                                     witness_response_callback, &collect_ctx);
    if (listen_token == 0) {
        pthread_mutex_destroy(&collect_ctx.mutex);
        pthread_cond_destroy(&collect_ctx.cond);
        dnac_free_witness_list(servers, server_count);
        return DNAC_ERROR_NETWORK;
    }

    /* Wait for enough witnesses with timeout */
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += DNAC_NODUS_TIMEOUT_MS / 1000;
    ts.tv_nsec += (DNAC_NODUS_TIMEOUT_MS % 1000) * 1000000;
    if (ts.tv_nsec >= 1000000000) {
        ts.tv_sec++;
        ts.tv_nsec -= 1000000000;
    }

    pthread_mutex_lock(&collect_ctx.mutex);
    while (!collect_ctx.done && *witness_count_out < DNAC_WITNESSES_REQUIRED) {
        int wait_rc = pthread_cond_timedwait(&collect_ctx.cond, &collect_ctx.mutex, &ts);
        if (wait_rc != 0) break;  /* Timeout or error */
    }
    pthread_mutex_unlock(&collect_ctx.mutex);

    /* Cancel listener */
    dht_cancel_listen(dht, listen_token);

    /* Cleanup */
    pthread_mutex_destroy(&collect_ctx.mutex);
    pthread_cond_destroy(&collect_ctx.cond);
    dnac_free_witness_list(servers, server_count);

    if (*witness_count_out >= DNAC_WITNESSES_REQUIRED) {
        return DNAC_SUCCESS;
    }

    return DNAC_ERROR_WITNESS_FAILED;
}

int dnac_witness_check_nullifier(dnac_context_t *ctx,
                                 const uint8_t *nullifier,
                                 bool *is_spent_out) {
    if (!ctx || !nullifier || !is_spent_out) {
        return DNAC_ERROR_INVALID_PARAM;
    }

    *is_spent_out = false;

    /* Get DNA engine and DHT context */
    dna_engine_t *engine = dnac_get_engine(ctx);
    if (!engine) return DNAC_ERROR_NOT_INITIALIZED;

    dht_context_t *dht = (dht_context_t *)dna_engine_get_dht_context(engine);
    if (!dht) return DNAC_ERROR_NETWORK;

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
    int rc = dht_get(dht, lookup_key, 64, &value, &value_len);

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

    /* Get DNA engine and DHT context */
    dna_engine_t *engine = dnac_get_engine(ctx);
    if (!engine) return -1;

    dht_context_t *dht = (dht_context_t *)dna_engine_get_dht_context(engine);
    if (!dht) return -1;

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

    int rc = dht_put_signed(dht, ping_key, 64, ping_data, 8,
                           start % 1000, /* unique value_id */
                           30, /* TTL */
                           "nodus_ping");
    if (rc != 0) return -1;

    /* Wait for pong (response at same key from server) */
    sleep_ms(100);  /* Give server time to respond */

    uint8_t *pong_data = NULL;
    size_t pong_len = 0;
    rc = dht_get(dht, ping_key, 64, &pong_data, &pong_len);

    if (rc == 0 && pong_data && pong_len >= 8) {
        uint64_t end = get_time_ms();
        *latency_ms_out = (int)(end - start);
        free(pong_data);
        return 0;
    }

    if (pong_data) free(pong_data);
    return -1;
}
