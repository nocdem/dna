/*
 * Rate Limiting - Token Bucket Algorithm
 */

#ifndef RATE_LIMIT_H
#define RATE_LIMIT_H

#include "keyserver.h"

// Rate limit types
typedef enum {
    RATE_LIMIT_TYPE_REGISTER,
    RATE_LIMIT_TYPE_LOOKUP,
    RATE_LIMIT_TYPE_LIST
} rate_limit_type_t;

/**
 * Initialize rate limiter
 */
void rate_limit_init(void);

/**
 * Check if IP is allowed to make request
 *
 * @param ip: Client IP address
 * @param type: Type of rate limit to check
 * @return true if allowed, false if rate limited
 */
bool rate_limit_check(const char *ip, rate_limit_type_t type);

/**
 * Cleanup rate limiter (call on shutdown)
 */
void rate_limit_cleanup(void);

#endif // RATE_LIMIT_H
