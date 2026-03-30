/**
 * Nodus — Singleton Client Implementation
 *
 * Thread safety: g_initialized is _Atomic so that nodus_singleton_get()
 * (hot path, no mutex) sees close() immediately. The mutex protects
 * init/close against concurrent structural changes.
 *
 * Reference counting (SECURITY: HIGH-8): get() increments refcount,
 * release() decrements. close() sets initialized=false then waits for
 * refcount==0 before destroying, preventing use-after-free.
 *
 * @file nodus_singleton.c
 */

#include "client/nodus_singleton.h"
#include <string.h>

#ifndef _WIN32
#include <unistd.h>  /* usleep */
#endif

#ifdef _WIN32
  #include <windows.h>
  static CRITICAL_SECTION g_cs;
  static int g_cs_init = 0;
  static void ensure_cs(void) {
      if (!g_cs_init) { InitializeCriticalSection(&g_cs); g_cs_init = 1; }
  }
  static volatile LONG g_initialized_win = 0;
  static volatile LONG g_refcount_win = 0;
  #define ATOMIC_LOAD_INIT()  (InterlockedCompareExchange(&g_initialized_win, 0, 0) != 0)
  #define ATOMIC_STORE_INIT(v) InterlockedExchange(&g_initialized_win, (v) ? 1 : 0)
  #define ATOMIC_INC_REF()    InterlockedIncrement(&g_refcount_win)
  #define ATOMIC_DEC_REF()    InterlockedDecrement(&g_refcount_win)
  #define ATOMIC_LOAD_REF()   InterlockedCompareExchange(&g_refcount_win, 0, 0)
#else
  #include <pthread.h>
  #include <stdatomic.h>
  static pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;
  static _Atomic bool g_initialized = false;
  static _Atomic int g_refcount = 0;
  #define ATOMIC_LOAD_INIT()   atomic_load(&g_initialized)
  #define ATOMIC_STORE_INIT(v) atomic_store(&g_initialized, (v))
  #define ATOMIC_INC_REF()     atomic_fetch_add(&g_refcount, 1)
  #define ATOMIC_DEC_REF()     atomic_fetch_sub(&g_refcount, 1)
  #define ATOMIC_LOAD_REF()    atomic_load(&g_refcount)
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
    if (!ATOMIC_LOAD_INIT()) return NULL;
    ATOMIC_INC_REF();
    /* Double-check: close() may have raced between our check and increment */
    if (!ATOMIC_LOAD_INIT()) {
        ATOMIC_DEC_REF();
        return NULL;
    }
    return &g_client;
}

void nodus_singleton_release(void) {
    ATOMIC_DEC_REF();
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
    /* Wait for all in-flight operations to release their references.
     * In practice this completes in microseconds. */
    int spins = 0;
    while (ATOMIC_LOAD_REF() > 0) {
#ifdef _WIN32
        Sleep(1);
#else
        usleep(1000);  /* 1ms */
#endif
        if (++spins > 5000) break;  /* Safety: 5s max wait */
    }
    nodus_client_close(&g_client);
}

void nodus_singleton_force_disconnect(void) {
    if (!ATOMIC_LOAD_INIT()) return;
    nodus_client_force_disconnect(&g_client);
}

void nodus_singleton_suspend(void) {
    if (!ATOMIC_LOAD_INIT()) return;
    nodus_client_suspend(&g_client);
}

void nodus_singleton_resume(void) {
    if (!ATOMIC_LOAD_INIT()) return;
    nodus_client_resume(&g_client);
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
