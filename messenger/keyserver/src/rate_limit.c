/*
 * Rate Limiting - Token Bucket Algorithm
 */

#include "rate_limit.h"
#include <string.h>
#include <time.h>
#include <stdlib.h>

#define MAX_BUCKETS 10000

typedef struct {
    char ip[46];
    time_t last_refill;
    int tokens_register;
    int tokens_lookup;
    int tokens_list;
} bucket_t;

static bucket_t *buckets[MAX_BUCKETS] = {0};
static int bucket_count = 0;

// Simple hash function for IP addresses
static unsigned int hash_ip(const char *ip) {
    unsigned int hash = 5381;
    int c;
    while ((c = *ip++)) {
        hash = ((hash << 5) + hash) + c;
    }
    return hash % MAX_BUCKETS;
}

void rate_limit_init(void) {
    memset(buckets, 0, sizeof(buckets));
    bucket_count = 0;
}

static bucket_t* get_or_create_bucket(const char *ip) {
    unsigned int idx = hash_ip(ip);

    // Check if bucket exists
    if (buckets[idx] && strcmp(buckets[idx]->ip, ip) == 0) {
        return buckets[idx];
    }

    // Create new bucket
    bucket_t *bucket = calloc(1, sizeof(bucket_t));
    if (!bucket) return NULL;

    strncpy(bucket->ip, ip, sizeof(bucket->ip) - 1);
    bucket->last_refill = time(NULL);
    bucket->tokens_register = g_config.rate_limit_register_count;
    bucket->tokens_lookup = g_config.rate_limit_lookup_count;
    bucket->tokens_list = g_config.rate_limit_list_count;

    // Handle collision - simple replace for now
    if (buckets[idx]) {
        free(buckets[idx]);
    }

    buckets[idx] = bucket;
    bucket_count++;

    return bucket;
}

static void refill_tokens(bucket_t *bucket) {
    time_t now = time(NULL);
    time_t elapsed = now - bucket->last_refill;

    if (elapsed <= 0) return;

    // Refill register tokens (per hour)
    if (elapsed >= g_config.rate_limit_register_period) {
        bucket->tokens_register = g_config.rate_limit_register_count;
    }

    // Refill lookup tokens (per minute)
    int lookup_periods = elapsed / g_config.rate_limit_lookup_period;
    if (lookup_periods > 0) {
        bucket->tokens_lookup += lookup_periods * g_config.rate_limit_lookup_count;
        if (bucket->tokens_lookup > g_config.rate_limit_lookup_count) {
            bucket->tokens_lookup = g_config.rate_limit_lookup_count;
        }
    }

    // Refill list tokens (per minute)
    int list_periods = elapsed / g_config.rate_limit_list_period;
    if (list_periods > 0) {
        bucket->tokens_list += list_periods * g_config.rate_limit_list_count;
        if (bucket->tokens_list > g_config.rate_limit_list_count) {
            bucket->tokens_list = g_config.rate_limit_list_count;
        }
    }

    bucket->last_refill = now;
}

bool rate_limit_check(const char *ip, rate_limit_type_t type) {
    if (!ip) return false;

    bucket_t *bucket = get_or_create_bucket(ip);
    if (!bucket) return false;

    refill_tokens(bucket);

    switch (type) {
        case RATE_LIMIT_REGISTER:
            if (bucket->tokens_register > 0) {
                bucket->tokens_register--;
                return true;
            }
            break;

        case RATE_LIMIT_LOOKUP:
            if (bucket->tokens_lookup > 0) {
                bucket->tokens_lookup--;
                return true;
            }
            break;

        case RATE_LIMIT_LIST:
            if (bucket->tokens_list > 0) {
                bucket->tokens_list--;
                return true;
            }
            break;
    }

    return false;
}

void rate_limit_cleanup(void) {
    for (int i = 0; i < MAX_BUCKETS; i++) {
        if (buckets[i]) {
            free(buckets[i]);
            buckets[i] = NULL;
        }
    }
    bucket_count = 0;
}
