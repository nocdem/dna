/**
 * @file client.c
 * @brief Nodus RPC client (DHT-based)
 *
 * Implements the client-side of the Nodus anchoring protocol:
 * 1. Client PUTs SpendRequest to Nodus server's request key
 * 2. Nodus checks nullifier, signs if OK, PUTs response
 * 3. Client GETs responses from all servers
 * 4. Client collects 2+ anchor signatures
 *
 * Communication is DHT-based (no direct TCP).
 */

#include "dnac/nodus.h"
#include "dnac/wallet.h"
#include <dna/dna_engine.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
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
 * Internal State
 * ========================================================================== */

/* Cached Nodus server list (shared with discovery.c) */
dnac_nodus_info_t *g_nodus_servers = NULL;
int g_nodus_count = 0;
uint64_t g_nodus_cache_time = 0;
#define NODUS_CACHE_TTL_SEC 300  /* 5 minute cache */

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
 * Build DHT key for Nodus request
 * Key: SHA3-512("dnac:nodus:request:" + nodus_id + ":" + tx_hash)
 */
static int build_request_key(const uint8_t *nodus_id, const uint8_t *tx_hash,
                             uint8_t *key_out) {
    uint8_t key_data[256];
    size_t offset = 0;

    memcpy(key_data + offset, NODUS_REQUEST_PREFIX, strlen(NODUS_REQUEST_PREFIX));
    offset += strlen(NODUS_REQUEST_PREFIX);
    memcpy(key_data + offset, nodus_id, 32);
    offset += 32;
    key_data[offset++] = ':';
    memcpy(key_data + offset, tx_hash, DNAC_TX_HASH_SIZE);
    offset += DNAC_TX_HASH_SIZE;

    return compute_sha3_512(key_data, offset, key_out);
}

/**
 * Build DHT key for Nodus response
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

/* ============================================================================
 * Public Functions
 * ========================================================================== */

int dnac_nodus_init(dnac_context_t *ctx) {
    if (!ctx) return -1;

    /* Clear cached server list */
    if (g_nodus_servers) {
        dnac_free_nodus_list(g_nodus_servers, g_nodus_count);
        g_nodus_servers = NULL;
        g_nodus_count = 0;
    }
    g_nodus_cache_time = 0;

    return 0;
}

void dnac_nodus_shutdown(dnac_context_t *ctx) {
    (void)ctx;

    /* Free cached server list */
    if (g_nodus_servers) {
        dnac_free_nodus_list(g_nodus_servers, g_nodus_count);
        g_nodus_servers = NULL;
        g_nodus_count = 0;
    }
}

int dnac_nodus_request_anchors(dnac_context_t *ctx,
                               const dnac_spend_request_t *request,
                               dnac_anchor_t *anchors_out,
                               int *anchor_count_out) {
    if (!ctx || !request || !anchors_out || !anchor_count_out) {
        return DNAC_ERROR_INVALID_PARAM;
    }

    *anchor_count_out = 0;

    /* Get DNA engine and DHT context */
    dna_engine_t *engine = dnac_get_engine(ctx);
    if (!engine) return DNAC_ERROR_NOT_INITIALIZED;

    dht_context_t *dht = (dht_context_t *)dna_engine_get_dht_context(engine);
    if (!dht) return DNAC_ERROR_NETWORK;

    /* Get owner fingerprint for response key */
    const char *owner_fp = dnac_get_owner_fingerprint(ctx);
    if (!owner_fp) return DNAC_ERROR_NOT_INITIALIZED;

    /* Discover Nodus servers if needed */
    dnac_nodus_info_t *servers = NULL;
    int server_count = 0;
    int rc = dnac_nodus_discover(ctx, &servers, &server_count);
    if (rc != DNAC_SUCCESS || server_count == 0) {
        return DNAC_ERROR_NETWORK;
    }

    /* Serialize spend request */
    uint8_t req_buffer[16384];
    size_t req_len = 0;
    rc = dnac_spend_request_serialize(request, req_buffer, sizeof(req_buffer), &req_len);
    if (rc != 0) {
        dnac_free_nodus_list(servers, server_count);
        return DNAC_ERROR_CRYPTO;
    }

    /* Send request to all Nodus servers */
    int servers_contacted = 0;
    for (int i = 0; i < server_count && i < DNAC_MAX_NODUS_SERVERS; i++) {
        /* Build request key for this server */
        uint8_t request_key[64];
        uint8_t nodus_id_bytes[32];

        /* Convert hex ID to bytes */
        for (int j = 0; j < 32 && servers[i].id[j*2]; j++) {
            sscanf(&servers[i].id[j*2], "%2hhx", &nodus_id_bytes[j]);
        }

        if (build_request_key(nodus_id_bytes, request->tx_hash, request_key) != 0) {
            continue;
        }

        /* PUT request to DHT */
        rc = dht_put_signed(dht, request_key, 64, req_buffer, req_len,
                           1, /* value_id */
                           60, /* TTL 60 seconds */
                           "nodus_request");
        if (rc == 0) {
            servers_contacted++;
        }
    }

    if (servers_contacted == 0) {
        dnac_free_nodus_list(servers, server_count);
        return DNAC_ERROR_NETWORK;
    }

    /* Build response key */
    uint8_t response_key[64];
    if (build_response_key(request->tx_hash, owner_fp, response_key) != 0) {
        dnac_free_nodus_list(servers, server_count);
        return DNAC_ERROR_CRYPTO;
    }

    /* Poll for responses until we have enough anchors or timeout */
    uint64_t start_time = get_time_ms();
    uint64_t timeout = DNAC_NODUS_TIMEOUT_MS;

    while (*anchor_count_out < DNAC_ANCHORS_REQUIRED &&
           (get_time_ms() - start_time) < timeout) {

        /* GET responses from DHT */
        uint8_t *resp_data = NULL;
        size_t resp_len = 0;

        rc = dht_get(dht, response_key, 64, &resp_data, &resp_len);
        if (rc == 0 && resp_data && resp_len > 0) {
            /* Deserialize response */
            dnac_spend_response_t response;
            if (dnac_spend_response_deserialize(resp_data, resp_len, &response) == 0) {
                if (response.status == DNAC_NODUS_STATUS_APPROVED) {
                    /* Find server's public key */
                    const uint8_t *nodus_pubkey = NULL;
                    for (int i = 0; i < server_count; i++) {
                        uint8_t nodus_id_bytes[32];
                        for (int j = 0; j < 32; j++) {
                            sscanf(&servers[i].id[j*2], "%2hhx", &nodus_id_bytes[j]);
                        }
                        if (memcmp(nodus_id_bytes, response.nodus_id, 32) == 0) {
                            nodus_pubkey = servers[i].pubkey;
                            break;
                        }
                    }

                    /* Verify anchor signature using pubkey from response */
                    /* Use response.server_pubkey if available, fall back to discovered pubkey */
                    const uint8_t *verify_pubkey = nodus_pubkey;
                    if (response.server_pubkey[0] != 0) {
                        verify_pubkey = response.server_pubkey;
                    }

                    if (verify_pubkey) {
                        dnac_anchor_t anchor;
                        memcpy(anchor.nodus_id, response.nodus_id, 32);
                        memcpy(anchor.signature, response.signature, DNAC_SIGNATURE_SIZE);
                        memcpy(anchor.server_pubkey, verify_pubkey, DNAC_PUBKEY_SIZE);
                        anchor.timestamp = response.timestamp;

                        if (dnac_nodus_verify_anchor(&anchor, request->tx_hash, verify_pubkey)) {
                            /* Check for duplicate */
                            bool is_dup = false;
                            for (int i = 0; i < *anchor_count_out; i++) {
                                if (memcmp(anchors_out[i].nodus_id, anchor.nodus_id, 32) == 0) {
                                    is_dup = true;
                                    break;
                                }
                            }

                            if (!is_dup) {
                                anchors_out[*anchor_count_out] = anchor;
                                (*anchor_count_out)++;
                            }
                        }
                    }
                }
            }
            free(resp_data);
        }

        /* Don't spin too fast */
        if (*anchor_count_out < DNAC_ANCHORS_REQUIRED) {
            sleep_ms(NODUS_POLL_INTERVAL_MS);
        }
    }

    dnac_free_nodus_list(servers, server_count);

    if (*anchor_count_out >= DNAC_ANCHORS_REQUIRED) {
        return DNAC_SUCCESS;
    }

    return DNAC_ERROR_ANCHOR_FAILED;
}

int dnac_nodus_check_nullifier(dnac_context_t *ctx,
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

bool dnac_nodus_verify_anchor(const dnac_anchor_t *anchor,
                              const uint8_t *tx_hash,
                              const uint8_t *nodus_pubkey) {
    if (!anchor || !tx_hash || !nodus_pubkey) return false;

    /* Build signed data: tx_hash + nodus_id + timestamp */
    uint8_t signed_data[DNAC_TX_HASH_SIZE + 32 + 8];
    memcpy(signed_data, tx_hash, DNAC_TX_HASH_SIZE);
    memcpy(signed_data + DNAC_TX_HASH_SIZE, anchor->nodus_id, 32);

    /* Little-endian timestamp */
    for (int i = 0; i < 8; i++) {
        signed_data[DNAC_TX_HASH_SIZE + 32 + i] = (anchor->timestamp >> (i * 8)) & 0xFF;
    }

    /* Verify Dilithium5 signature */
    int ret = qgp_dsa87_verify(anchor->signature, DNAC_SIGNATURE_SIZE,
                               signed_data, sizeof(signed_data),
                               nodus_pubkey);
    return (ret == 0);
}

uint64_t dnac_nodus_calculate_fee(uint64_t amount) {
    /* 0.1% fee (10 basis points) */
    uint64_t fee = (amount * DNAC_FEE_RATE_BPS) / 10000;
    return fee > 0 ? fee : 1;  /* Minimum 1 unit */
}

int dnac_nodus_ping(dnac_context_t *ctx,
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
