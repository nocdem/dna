/**
 * Nodus — Singleton Client Implementation
 *
 * Thread safety: g_initialized is _Atomic so that nodus_singleton_get()
 * (hot path, no mutex) sees close() immediately. The mutex protects
 * init/close against concurrent structural changes.
 *
 * @file nodus_singleton.c
 */

#include "client/nodus_singleton.h"
#include <string.h>

#ifdef _WIN32
  #include <windows.h>
  static CRITICAL_SECTION g_cs;
  static int g_cs_init = 0;
  static void ensure_cs(void) {
      if (!g_cs_init) { InitializeCriticalSection(&g_cs); g_cs_init = 1; }
  }
  static volatile LONG g_initialized_win = 0;
  #define ATOMIC_LOAD_INIT()  (InterlockedCompareExchange(&g_initialized_win, 0, 0) != 0)
  #define ATOMIC_STORE_INIT(v) InterlockedExchange(&g_initialized_win, (v) ? 1 : 0)
#else
  #include <pthread.h>
  #include <stdatomic.h>
  static pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;
  static _Atomic bool g_initialized = false;
  #define ATOMIC_LOAD_INIT()   atomic_load(&g_initialized)
  #define ATOMIC_STORE_INIT(v) atomic_store(&g_initialized, (v))
#endif

static nodus_client_t g_client;

int nodus_singleton_init(const nodus_client_config_t *config,
                          const nodus_identity_t *identity) {
    if (ATOMIC_LOAD_INIT()) return -1;  /* Already initialized */
    int rc = nodus_client_init(&g_client, config, identity);
    if (rc == 0) ATOMIC_STORE_INIT(true);
    return rc;
}

int nodus_singleton_connect(void) {
    if (!ATOMIC_LOAD_INIT()) return -1;
    return nodus_client_connect(&g_client);
}

nodus_client_t *nodus_singleton_get(void) {
    return ATOMIC_LOAD_INIT() ? &g_client : NULL;
}

bool nodus_singleton_is_ready(void) {
    return ATOMIC_LOAD_INIT() && nodus_client_is_ready(&g_client);
}

int nodus_singleton_poll(int timeout_ms) {
    if (!ATOMIC_LOAD_INIT()) return -1;
    return nodus_client_poll(&g_client, timeout_ms);
}

const nodus_identity_t *nodus_singleton_identity(void) {
    return ATOMIC_LOAD_INIT() ? &g_client.identity : NULL;
}

void nodus_singleton_close(void) {
    if (!ATOMIC_LOAD_INIT()) return;
    /* Set false FIRST so racing get() callers see NULL immediately,
     * rather than getting a pointer to a half-destroyed client. */
    ATOMIC_STORE_INIT(false);
    nodus_client_close(&g_client);
}

void nodus_singleton_force_disconnect(void) {
    if (!ATOMIC_LOAD_INIT()) return;
    nodus_client_force_disconnect(&g_client);
}

void nodus_singleton_lock(void) {
#ifdef _WIN32
    ensure_cs();
    EnterCriticalSection(&g_cs);
#else
    pthread_mutex_lock(&g_mutex);
#endif
}

void nodus_singleton_unlock(void) {
#ifdef _WIN32
    LeaveCriticalSection(&g_cs);
#else
    pthread_mutex_unlock(&g_mutex);
#endif
}
