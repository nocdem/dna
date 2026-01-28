/*
 * DNA Engine - Shared Includes
 *
 * Common includes for all engine modules.
 * This file centralizes the include dependencies to avoid duplication.
 */

#ifndef DNA_ENGINE_INCLUDES_H
#define DNA_ENGINE_INCLUDES_H

#define _XOPEN_SOURCE 700  /* For strptime */

/* Standard library includes (all platforms) */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <dirent.h>
#include <sys/stat.h>
#include <errno.h>
#include <unistd.h>

#ifdef _WIN32
#include <direct.h>
#include <windows.h>
#define platform_mkdir(path, mode) _mkdir(path)

/* Windows doesn't have strndup */
static inline char* win_strndup(const char* s, size_t n) {
    size_t len = strlen(s);
    if (len > n) len = n;
    char* result = (char*)malloc(len + 1);
    if (result) {
        memcpy(result, s, len);
        result[len] = '\0';
    }
    return result;
}
#define strndup win_strndup

/* Windows doesn't have strcasecmp */
#define strcasecmp _stricmp

/* Windows doesn't have strptime - simple parser for YYYY-MM-DD HH:MM:SS */
static inline char* win_strptime(const char* s, const char* format, struct tm* tm) {
    (void)format; /* We only support one format */
    int year, month, day, hour, min, sec;
    if (sscanf(s, "%d-%d-%d %d:%d:%d", &year, &month, &day, &hour, &min, &sec) == 6) {
        tm->tm_year = year - 1900;
        tm->tm_mon = month - 1;
        tm->tm_mday = day;
        tm->tm_hour = hour;
        tm->tm_min = min;
        tm->tm_sec = sec;
        tm->tm_isdst = -1;
        return (char*)(s + 19); /* Return pointer past parsed string */
    }
    return NULL;
}
#define strptime win_strptime

#else
#include <strings.h>  /* For strcasecmp */
#define platform_mkdir(path, mode) mkdir(path, mode)
#endif

/* Internal header with structures and task types */
#include "dna_engine_internal.h"
#include "dna_api.h"
#include "dna_config.h"

/* Crypto utilities */
#include "crypto/utils/threadpool.h"
#include "crypto/utils/qgp_types.h"
#include "crypto/utils/qgp_platform.h"
#include "crypto/utils/qgp_log.h"
#include "crypto/utils/qgp_sha3.h"
#include "crypto/utils/qgp_dilithium.h"
#include "crypto/utils/key_encryption.h"
#include "crypto/utils/seed_storage.h"
#include "crypto/utils/base58.h"
#include "crypto/bip39/bip39.h"

/* Messenger core */
#include "messenger.h"
#include "messenger/init.h"
#include "messenger/messages.h"
#include "messenger/groups.h"
#include "messenger/gek.h"
#include "messenger/status.h"
#include "messenger_transport.h"
#include "message_backup.h"

/* DHT */
#include "dht/client/dht_singleton.h"
#include "dht/core/dht_keyserver.h"
#include "dht/core/dht_listen.h"
#include "dht/core/dht_context.h"
#include "dht/client/dht_contactlist.h"
#include "dht/client/dht_message_backup.h"
#include "dht/client/dna_feed.h"
#include "dht/client/dna_profile.h"
#include "dht/client/dna_group_outbox.h"
#include "dht/client/dht_addressbook.h"
#include "dht/shared/dht_offline_queue.h"
#include "dht/shared/dht_chunked.h"
#include "dht/shared/dht_contact_request.h"
#include "dht/shared/dht_groups.h"
#include "dht/shared/dht_dm_outbox.h"

/* Transport */
#include "transport/transport.h"
#include "transport/internal/transport_core.h"

/* Database */
#include "database/presence_cache.h"
#include "database/keyserver_cache.h"
#include "database/profile_cache.h"
#include "database/profile_manager.h"
#include "database/contacts_db.h"
#include "database/addressbook_db.h"
#include "database/group_invitations.h"

/* Blockchain/Wallet */
#include "cellframe_wallet.h"
#include "cellframe_wallet_create.h"
#include "cellframe_rpc.h"
#include "cellframe_tx_builder.h"
#include "cellframe_sign.h"
#include "cellframe_json.h"
#include "blockchain/blockchain_wallet.h"
#include "blockchain/cellframe/cellframe_addr.h"
#include "blockchain/ethereum/eth_wallet.h"
#include "blockchain/ethereum/eth_erc20.h"
#include "blockchain/solana/sol_wallet.h"
#include "blockchain/solana/sol_rpc.h"
#include "blockchain/solana/sol_spl.h"
#include "blockchain/tron/trx_wallet.h"
#include "blockchain/tron/trx_rpc.h"
#include "blockchain/tron/trx_trc20.h"

/* JSON */
#include <json-c/json.h>

#define LOG_TAG "DNA_ENGINE"

/* Use engine-specific error codes */
#define DNA_OK 0

/* DHT stabilization - wait for routing table to fill after bootstrap */
#define DHT_STABILIZATION_MAX_SECONDS 15  /* Maximum wait time */
#define DHT_STABILIZATION_MIN_NODES 2     /* Minimum good nodes for reliable operations */

/* v0.6.47: Thread-safe gmtime wrapper (security fix) */
static inline struct tm *safe_gmtime(const time_t *timer, struct tm *result) {
#ifdef _WIN32
    return (gmtime_s(result, timer) == 0) ? result : NULL;
#else
    return gmtime_r(timer, result);
#endif
}

/* ============================================================================
 * CROSS-MODULE FUNCTION DECLARATIONS
 *
 * Functions that are called across engine modules need declarations here.
 * ============================================================================ */

/* From dna_engine_core.c */
dht_context_t* dna_get_dht_ctx(dna_engine_t *engine);
qgp_key_t* dna_load_private_key(dna_engine_t *engine);
qgp_key_t* dna_load_encryption_key(dna_engine_t *engine);
void init_log_config(void);
bool dht_wait_for_stabilization(dna_engine_t *engine);
int dna_start_presence_heartbeat(dna_engine_t *engine);
void* dna_engine_stabilization_retry_thread(void *arg);

/* From dna_engine_p2p.c */
void dna_engine_cancel_all_outbox_listeners(dna_engine_t *engine);
void dna_engine_cancel_all_presence_listeners(dna_engine_t *engine);
void dna_engine_cancel_contact_request_listener(dna_engine_t *engine);
size_t dna_engine_start_contact_request_listener(dna_engine_t *engine);
void dna_engine_cancel_ack_listener(dna_engine_t *engine, const char *contact_fingerprint);
void dna_engine_cancel_all_ack_listeners(dna_engine_t *engine);
size_t dna_engine_listen_outbox(dna_engine_t *engine, const char *contact_fingerprint);
size_t dna_engine_start_presence_listener(dna_engine_t *engine, const char *contact_fingerprint);
size_t dna_engine_start_ack_listener(dna_engine_t *engine, const char *contact_fingerprint);
int dna_engine_listen_all_contacts(dna_engine_t *engine);
int dna_engine_retry_pending_messages(dna_engine_t *engine);

/* From dna_engine_groups.c */
int dna_engine_subscribe_all_groups(dna_engine_t *engine);
void dna_engine_unsubscribe_all_groups(dna_engine_t *engine);
int dna_engine_check_group_day_rotation(dna_engine_t *engine);
int dna_engine_check_outbox_day_rotation(dna_engine_t *engine);

/* Global engine accessors (thread-safe) */
extern dna_engine_t *g_dht_callback_engine;
extern pthread_mutex_t g_engine_global_mutex;

/* Android callbacks */
extern dna_android_notification_cb g_android_notification_cb;
extern void *g_android_notification_data;
extern dna_android_group_message_cb g_android_group_message_cb;
extern void *g_android_group_message_data;
extern dna_android_contact_request_cb g_android_contact_request_cb;
extern void *g_android_contact_request_data;
extern dna_android_reconnect_cb g_android_reconnect_cb;
extern void *g_android_reconnect_data;
extern pthread_mutex_t g_android_callback_mutex;

#endif /* DNA_ENGINE_INCLUDES_H */
