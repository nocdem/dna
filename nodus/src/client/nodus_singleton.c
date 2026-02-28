/**
 * Nodus v5 — Singleton Client Implementation
 *
 * @file nodus_singleton.c
 */

#include "client/nodus_singleton.h"
#include <string.h>

static nodus_client_t g_client;
static bool g_initialized = false;

int nodus_singleton_init(const nodus_client_config_t *config,
                          const nodus_identity_t *identity) {
    if (g_initialized) return -1;  /* Already initialized */
    int rc = nodus_client_init(&g_client, config, identity);
    if (rc == 0) g_initialized = true;
    return rc;
}

int nodus_singleton_connect(void) {
    if (!g_initialized) return -1;
    return nodus_client_connect(&g_client);
}

nodus_client_t *nodus_singleton_get(void) {
    return g_initialized ? &g_client : NULL;
}

bool nodus_singleton_is_ready(void) {
    return g_initialized && nodus_client_is_ready(&g_client);
}

int nodus_singleton_poll(int timeout_ms) {
    if (!g_initialized) return -1;
    return nodus_client_poll(&g_client, timeout_ms);
}

const nodus_identity_t *nodus_singleton_identity(void) {
    return g_initialized ? &g_client.identity : NULL;
}

void nodus_singleton_close(void) {
    if (!g_initialized) return;
    nodus_client_close(&g_client);
    g_initialized = false;
}
