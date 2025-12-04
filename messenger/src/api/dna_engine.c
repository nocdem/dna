/*
 * DNA Engine - Implementation
 *
 * Core engine implementation providing async API for DNA Messenger.
 */

#include "dna_engine_internal.h"
#include "dna_api.h"
#include "messenger_p2p.h"
#include "dht/client/dht_singleton.h"
#include "dht/core/dht_keyserver.h"
#include "dht/client/dht_contactlist.h"
#include "dht/client/dna_feed.h"
#include "dht/client/dna_profile.h"
#include "p2p/p2p_transport.h"
#include "database/presence_cache.h"
#include "database/profile_cache.h"
#include "crypto/utils/qgp_types.h"
#include "crypto/utils/qgp_platform.h"

/* Blockchain/Wallet includes for send_tokens */
#include "blockchain/wallet.h"
#include "blockchain/blockchain_rpc.h"
#include "blockchain/blockchain_tx_builder_minimal.h"
#include "blockchain/blockchain_sign_minimal.h"
#include "blockchain/blockchain_json_minimal.h"
#include "crypto/utils/base58.h"
#include <time.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <dirent.h>
#include <sys/stat.h>
#include <errno.h>
#include <unistd.h>

/* Use engine-specific error codes */
#define DNA_OK 0

/* Forward declarations for static helpers */
static dht_context_t* dna_get_dht_ctx(dna_engine_t *engine);
static qgp_key_t* dna_load_private_key(dna_engine_t *engine);

/* ============================================================================
 * ERROR STRINGS
 * ============================================================================ */

const char* dna_engine_error_string(int error) {
    if (error == 0) return "Success";
    if (error == DNA_ENGINE_ERROR_INIT) return "Initialization failed";
    if (error == DNA_ENGINE_ERROR_NOT_INITIALIZED) return "Not initialized";
    if (error == DNA_ENGINE_ERROR_NETWORK) return "Network error";
    if (error == DNA_ENGINE_ERROR_DATABASE) return "Database error";
    if (error == DNA_ENGINE_ERROR_TIMEOUT) return "Operation timed out";
    if (error == DNA_ENGINE_ERROR_BUSY) return "Engine busy";
    if (error == DNA_ENGINE_ERROR_NO_IDENTITY) return "No identity loaded";
    if (error == DNA_ENGINE_ERROR_ALREADY_EXISTS) return "Already exists";
    if (error == DNA_ENGINE_ERROR_PERMISSION) return "Permission denied";
    /* Fall back to base dna_api.h error strings */
    if (error == DNA_ERROR_INVALID_ARG) return "Invalid argument";
    if (error == DNA_ERROR_NOT_FOUND) return "Not found";
    if (error == DNA_ERROR_CRYPTO) return "Cryptographic error";
    if (error == DNA_ERROR_INTERNAL) return "Internal error";
    return "Unknown error";
}

/* ============================================================================
 * TASK QUEUE IMPLEMENTATION
 * ============================================================================ */

void dna_task_queue_init(dna_task_queue_t *queue) {
    memset(queue->tasks, 0, sizeof(queue->tasks));
    atomic_store(&queue->head, 0);
    atomic_store(&queue->tail, 0);
}

bool dna_task_queue_push(dna_task_queue_t *queue, const dna_task_t *task) {
    size_t head = atomic_load(&queue->head);
    size_t next_head = (head + 1) % DNA_TASK_QUEUE_SIZE;

    /* Check if full */
    if (next_head == atomic_load(&queue->tail)) {
        return false;
    }

    queue->tasks[head] = *task;
    atomic_store(&queue->head, next_head);
    return true;
}

bool dna_task_queue_pop(dna_task_queue_t *queue, dna_task_t *task_out) {
    size_t tail = atomic_load(&queue->tail);

    /* Check if empty */
    if (tail == atomic_load(&queue->head)) {
        return false;
    }

    *task_out = queue->tasks[tail];
    atomic_store(&queue->tail, (tail + 1) % DNA_TASK_QUEUE_SIZE);
    return true;
}

bool dna_task_queue_empty(dna_task_queue_t *queue) {
    return atomic_load(&queue->head) == atomic_load(&queue->tail);
}

/* ============================================================================
 * REQUEST ID GENERATION
 * ============================================================================ */

dna_request_id_t dna_next_request_id(dna_engine_t *engine) {
    dna_request_id_t id = atomic_fetch_add(&engine->next_request_id, 1) + 1;
    /* Ensure never returns 0 (invalid) */
    if (id == DNA_REQUEST_ID_INVALID) {
        id = atomic_fetch_add(&engine->next_request_id, 1) + 1;
    }
    return id;
}

/* ============================================================================
 * TASK SUBMISSION
 * ============================================================================ */

dna_request_id_t dna_submit_task(
    dna_engine_t *engine,
    dna_task_type_t type,
    const dna_task_params_t *params,
    dna_task_callback_t callback,
    void *user_data
) {
    if (!engine) {
        return DNA_REQUEST_ID_INVALID;
    }

    dna_task_t task = {0};
    task.request_id = dna_next_request_id(engine);
    task.type = type;
    if (params) {
        task.params = *params;
    }
    task.callback = callback;
    task.user_data = user_data;
    task.cancelled = false;

    pthread_mutex_lock(&engine->task_mutex);
    bool pushed = dna_task_queue_push(&engine->task_queue, &task);
    if (pushed) {
        pthread_cond_signal(&engine->task_cond);
    }
    pthread_mutex_unlock(&engine->task_mutex);

    return pushed ? task.request_id : DNA_REQUEST_ID_INVALID;
}

/* ============================================================================
 * TASK PARAMETER CLEANUP
 * ============================================================================ */

void dna_free_task_params(dna_task_t *task) {
    switch (task->type) {
        case TASK_SEND_MESSAGE:
            free(task->params.send_message.message);
            break;
        case TASK_CREATE_GROUP:
            if (task->params.create_group.members) {
                for (int i = 0; i < task->params.create_group.member_count; i++) {
                    free(task->params.create_group.members[i]);
                }
                free(task->params.create_group.members);
            }
            break;
        case TASK_SEND_GROUP_MESSAGE:
            free(task->params.send_group_message.message);
            break;
        case TASK_CREATE_FEED_POST:
            free(task->params.create_feed_post.text);
            break;
        default:
            break;
    }
}

/* ============================================================================
 * WORKER THREAD
 * ============================================================================ */

void* dna_worker_thread(void *arg) {
    dna_engine_t *engine = (dna_engine_t*)arg;

    while (!atomic_load(&engine->shutdown_requested)) {
        dna_task_t task;
        bool has_task = false;

        pthread_mutex_lock(&engine->task_mutex);
        while (dna_task_queue_empty(&engine->task_queue) &&
               !atomic_load(&engine->shutdown_requested)) {
            pthread_cond_wait(&engine->task_cond, &engine->task_mutex);
        }

        if (!atomic_load(&engine->shutdown_requested)) {
            has_task = dna_task_queue_pop(&engine->task_queue, &task);
        }
        pthread_mutex_unlock(&engine->task_mutex);

        if (has_task && !task.cancelled) {
            dna_execute_task(engine, &task);
            dna_free_task_params(&task);
        }
    }

    return NULL;
}

int dna_start_workers(dna_engine_t *engine) {
    atomic_store(&engine->shutdown_requested, false);

    for (int i = 0; i < DNA_WORKER_THREAD_COUNT; i++) {
        int rc = pthread_create(&engine->worker_threads[i], NULL, dna_worker_thread, engine);
        if (rc != 0) {
            /* Stop already-started threads */
            atomic_store(&engine->shutdown_requested, true);
            pthread_cond_broadcast(&engine->task_cond);
            for (int j = 0; j < i; j++) {
                pthread_join(engine->worker_threads[j], NULL);
            }
            return -1;
        }
    }
    return 0;
}

void dna_stop_workers(dna_engine_t *engine) {
    atomic_store(&engine->shutdown_requested, true);

    pthread_mutex_lock(&engine->task_mutex);
    pthread_cond_broadcast(&engine->task_cond);
    pthread_mutex_unlock(&engine->task_mutex);

    for (int i = 0; i < DNA_WORKER_THREAD_COUNT; i++) {
        pthread_join(engine->worker_threads[i], NULL);
    }
}

/* ============================================================================
 * EVENT DISPATCH
 * ============================================================================ */

void dna_dispatch_event(dna_engine_t *engine, const dna_event_t *event) {
    pthread_mutex_lock(&engine->event_mutex);
    dna_event_cb callback = engine->event_callback;
    void *user_data = engine->event_user_data;
    pthread_mutex_unlock(&engine->event_mutex);

    if (callback) {
        callback(event, user_data);
    }
}

/* ============================================================================
 * TASK EXECUTION DISPATCH
 * ============================================================================ */

void dna_execute_task(dna_engine_t *engine, dna_task_t *task) {
    switch (task->type) {
        /* Identity */
        case TASK_LIST_IDENTITIES:
            dna_handle_list_identities(engine, task);
            break;
        case TASK_CREATE_IDENTITY:
            dna_handle_create_identity(engine, task);
            break;
        case TASK_LOAD_IDENTITY:
            dna_handle_load_identity(engine, task);
            break;
        case TASK_REGISTER_NAME:
            dna_handle_register_name(engine, task);
            break;
        case TASK_GET_DISPLAY_NAME:
            dna_handle_get_display_name(engine, task);
            break;
        case TASK_LOOKUP_NAME:
            dna_handle_lookup_name(engine, task);
            break;
        case TASK_GET_PROFILE:
            dna_handle_get_profile(engine, task);
            break;
        case TASK_UPDATE_PROFILE:
            dna_handle_update_profile(engine, task);
            break;

        /* Contacts */
        case TASK_GET_CONTACTS:
            dna_handle_get_contacts(engine, task);
            break;
        case TASK_ADD_CONTACT:
            dna_handle_add_contact(engine, task);
            break;
        case TASK_REMOVE_CONTACT:
            dna_handle_remove_contact(engine, task);
            break;

        /* Messaging */
        case TASK_SEND_MESSAGE:
            dna_handle_send_message(engine, task);
            break;
        case TASK_GET_CONVERSATION:
            dna_handle_get_conversation(engine, task);
            break;
        case TASK_CHECK_OFFLINE_MESSAGES:
            dna_handle_check_offline_messages(engine, task);
            break;

        /* Groups */
        case TASK_GET_GROUPS:
            dna_handle_get_groups(engine, task);
            break;
        case TASK_CREATE_GROUP:
            dna_handle_create_group(engine, task);
            break;
        case TASK_SEND_GROUP_MESSAGE:
            dna_handle_send_group_message(engine, task);
            break;
        case TASK_GET_INVITATIONS:
            dna_handle_get_invitations(engine, task);
            break;
        case TASK_ACCEPT_INVITATION:
            dna_handle_accept_invitation(engine, task);
            break;
        case TASK_REJECT_INVITATION:
            dna_handle_reject_invitation(engine, task);
            break;

        /* Wallet */
        case TASK_LIST_WALLETS:
            dna_handle_list_wallets(engine, task);
            break;
        case TASK_GET_BALANCES:
            dna_handle_get_balances(engine, task);
            break;
        case TASK_SEND_TOKENS:
            dna_handle_send_tokens(engine, task);
            break;
        case TASK_GET_TRANSACTIONS:
            dna_handle_get_transactions(engine, task);
            break;

        /* P2P & Presence */
        case TASK_REFRESH_PRESENCE:
            dna_handle_refresh_presence(engine, task);
            break;
        case TASK_LOOKUP_PRESENCE:
            dna_handle_lookup_presence(engine, task);
            break;
        case TASK_SYNC_CONTACTS_TO_DHT:
            dna_handle_sync_contacts_to_dht(engine, task);
            break;
        case TASK_SYNC_CONTACTS_FROM_DHT:
            dna_handle_sync_contacts_from_dht(engine, task);
            break;
        case TASK_SYNC_GROUPS:
            dna_handle_sync_groups(engine, task);
            break;
        case TASK_SUBSCRIBE_TO_CONTACTS:
            dna_handle_subscribe_to_contacts(engine, task);
            break;
        case TASK_GET_REGISTERED_NAME:
            dna_handle_get_registered_name(engine, task);
            break;

        /* Feed */
        case TASK_GET_FEED_CHANNELS:
            dna_handle_get_feed_channels(engine, task);
            break;
        case TASK_CREATE_FEED_CHANNEL:
            dna_handle_create_feed_channel(engine, task);
            break;
        case TASK_INIT_DEFAULT_CHANNELS:
            dna_handle_init_default_channels(engine, task);
            break;
        case TASK_GET_FEED_POSTS:
            dna_handle_get_feed_posts(engine, task);
            break;
        case TASK_CREATE_FEED_POST:
            dna_handle_create_feed_post(engine, task);
            break;
        case TASK_ADD_FEED_COMMENT:
            dna_handle_add_feed_comment(engine, task);
            break;
        case TASK_GET_FEED_COMMENTS:
            dna_handle_get_feed_comments(engine, task);
            break;
        case TASK_CAST_FEED_VOTE:
            dna_handle_cast_feed_vote(engine, task);
            break;
        case TASK_GET_FEED_VOTES:
            dna_handle_get_feed_votes(engine, task);
            break;
        case TASK_CAST_COMMENT_VOTE:
            dna_handle_cast_comment_vote(engine, task);
            break;
        case TASK_GET_COMMENT_VOTES:
            dna_handle_get_comment_votes(engine, task);
            break;
    }
}

/* ============================================================================
 * LIFECYCLE FUNCTIONS
 * ============================================================================ */

dna_engine_t* dna_engine_create(const char *data_dir) {
    dna_engine_t *engine = calloc(1, sizeof(dna_engine_t));
    if (!engine) {
        return NULL;
    }

    /* Set data directory */
    if (data_dir) {
        engine->data_dir = strdup(data_dir);
    } else {
        /* Default to ~/.dna */
        const char *home = getenv("HOME");
        if (home) {
            size_t len = strlen(home) + 6; /* "/.dna" + null */
            engine->data_dir = malloc(len);
            if (engine->data_dir) {
                snprintf(engine->data_dir, len, "%s/.dna", home);
            }
        }
    }

    if (!engine->data_dir) {
        free(engine);
        return NULL;
    }

    /* Ensure data directory exists */
    mkdir(engine->data_dir, 0700);

    /* Initialize synchronization */
    pthread_mutex_init(&engine->event_mutex, NULL);
    pthread_mutex_init(&engine->task_mutex, NULL);
    pthread_mutex_init(&engine->name_cache_mutex, NULL);
    pthread_cond_init(&engine->task_cond, NULL);

    /* Initialize name cache */
    engine->name_cache_count = 0;

    /* Initialize task queue */
    dna_task_queue_init(&engine->task_queue);

    /* Initialize request ID counter */
    atomic_store(&engine->next_request_id, 0);

    /* Initialize DHT singleton */
    dht_singleton_init();

    /* Start worker threads */
    if (dna_start_workers(engine) != 0) {
        pthread_mutex_destroy(&engine->event_mutex);
        pthread_mutex_destroy(&engine->task_mutex);
        pthread_cond_destroy(&engine->task_cond);
        free(engine->data_dir);
        free(engine);
        return NULL;
    }

    return engine;
}

void dna_engine_set_event_callback(
    dna_engine_t *engine,
    dna_event_cb callback,
    void *user_data
) {
    if (!engine) return;

    pthread_mutex_lock(&engine->event_mutex);
    engine->event_callback = callback;
    engine->event_user_data = user_data;
    pthread_mutex_unlock(&engine->event_mutex);
}

void dna_engine_destroy(dna_engine_t *engine) {
    if (!engine) return;

    /* Stop worker threads */
    dna_stop_workers(engine);

    /* Free messenger context */
    if (engine->messenger) {
        messenger_free(engine->messenger);
    }

    /* Free wallet list */
    if (engine->wallet_list) {
        wallet_list_free(engine->wallet_list);
    }

    /* Cleanup synchronization */
    pthread_mutex_destroy(&engine->event_mutex);
    pthread_mutex_destroy(&engine->task_mutex);
    pthread_mutex_destroy(&engine->name_cache_mutex);
    pthread_cond_destroy(&engine->task_cond);

    /* Free data directory */
    free(engine->data_dir);

    free(engine);
}

const char* dna_engine_get_fingerprint(dna_engine_t *engine) {
    if (!engine || !engine->identity_loaded) {
        return NULL;
    }
    return engine->fingerprint;
}

/* ============================================================================
 * IDENTITY SCAN HELPER
 * ============================================================================ */

int dna_scan_identities(const char *data_dir, char ***fingerprints_out, int *count_out) {
    DIR *dir = opendir(data_dir);
    if (!dir) {
        *fingerprints_out = NULL;
        *count_out = 0;
        return 0; /* Empty result, not an error */
    }

    /* First pass: count .dsa files with 128-char fingerprint names */
    int count = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        size_t len = strlen(entry->d_name);
        if (len == 132 && strcmp(entry->d_name + 128, ".dsa") == 0) {
            /* Check it's all hex */
            bool valid = true;
            for (int i = 0; i < 128 && valid; i++) {
                char c = entry->d_name[i];
                valid = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
            }
            if (valid) count++;
        }
    }

    if (count == 0) {
        closedir(dir);
        *fingerprints_out = NULL;
        *count_out = 0;
        return 0;
    }

    /* Allocate array */
    char **fingerprints = calloc(count, sizeof(char*));
    if (!fingerprints) {
        closedir(dir);
        return -1;
    }

    /* Second pass: collect fingerprints */
    rewinddir(dir);
    int idx = 0;
    while ((entry = readdir(dir)) != NULL && idx < count) {
        size_t len = strlen(entry->d_name);
        if (len == 132 && strcmp(entry->d_name + 128, ".dsa") == 0) {
            bool valid = true;
            for (int i = 0; i < 128 && valid; i++) {
                char c = entry->d_name[i];
                valid = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
            }
            if (valid) {
                fingerprints[idx] = strndup(entry->d_name, 128);
                if (!fingerprints[idx]) {
                    /* Cleanup on error */
                    for (int j = 0; j < idx; j++) {
                        free(fingerprints[j]);
                    }
                    free(fingerprints);
                    closedir(dir);
                    return -1;
                }
                idx++;
            }
        }
    }

    closedir(dir);
    *fingerprints_out = fingerprints;
    *count_out = idx;
    return 0;
}

/* ============================================================================
 * IDENTITY TASK HANDLERS
 * ============================================================================ */

void dna_handle_list_identities(dna_engine_t *engine, dna_task_t *task) {
    char **fingerprints = NULL;
    int count = 0;

    int rc = dna_scan_identities(engine->data_dir, &fingerprints, &count);

    /* Prefetch and cache display names for all identities */
    if (rc == 0 && count > 0) {
        dht_context_t *dht = dna_get_dht_ctx(engine);
        if (dht) {
            pthread_mutex_lock(&engine->name_cache_mutex);

            for (int i = 0; i < count && i < DNA_NAME_CACHE_MAX; i++) {
                /* Check if already cached */
                bool found = false;
                for (int j = 0; j < engine->name_cache_count; j++) {
                    if (strcmp(engine->name_cache[j].fingerprint, fingerprints[i]) == 0) {
                        found = true;
                        break;
                    }
                }

                if (!found) {
                    /* Fetch from DHT and cache */
                    char *display_name = NULL;
                    if (dna_get_display_name(dht, fingerprints[i], &display_name) == 0 && display_name) {
                        /* Only cache if it's a real name (not just shortened fingerprint) */
                        if (strlen(display_name) < 20 || strstr(display_name, "...") == NULL) {
                            if (engine->name_cache_count < DNA_NAME_CACHE_MAX) {
                                strncpy(engine->name_cache[engine->name_cache_count].fingerprint,
                                        fingerprints[i], 128);
                                strncpy(engine->name_cache[engine->name_cache_count].display_name,
                                        display_name, 63);
                                engine->name_cache_count++;
                                printf("[DNA_ENGINE] Cached name: %s -> %s\n",
                                       fingerprints[i], display_name);
                            }
                        }
                        free(display_name);
                    }
                }
            }

            pthread_mutex_unlock(&engine->name_cache_mutex);
        }
    }

    int error = (rc == 0) ? DNA_OK : DNA_ENGINE_ERROR_DATABASE;
    task->callback.identities(task->request_id, error, fingerprints, count, task->user_data);

    /* Caller is responsible for freeing via dna_free_strings */
}

void dna_handle_create_identity(dna_engine_t *engine, dna_task_t *task) {
    char fingerprint_buf[129] = {0};

    int rc = messenger_generate_keys_from_seeds(
        task->params.create_identity.signing_seed,
        task->params.create_identity.encryption_seed,
        engine->data_dir,
        fingerprint_buf
    );

    int error = DNA_OK;
    char *fingerprint = NULL;
    if (rc != 0) {
        error = DNA_ERROR_CRYPTO;
    } else {
        /* Allocate on heap - caller must free via dna_free_string */
        fingerprint = strdup(fingerprint_buf);
    }

    task->callback.identity_created(
        task->request_id,
        error,
        fingerprint,
        task->user_data
    );
}

void dna_handle_load_identity(dna_engine_t *engine, dna_task_t *task) {
    const char *fingerprint = task->params.load_identity.fingerprint;
    int error = DNA_OK;

    /* Free existing messenger context if any */
    if (engine->messenger) {
        messenger_free(engine->messenger);
        engine->messenger = NULL;
        engine->identity_loaded = false;
    }

    /* Initialize messenger with fingerprint */
    engine->messenger = messenger_init(fingerprint);
    if (!engine->messenger) {
        error = DNA_ENGINE_ERROR_INIT;
        goto done;
    }

    /* Copy fingerprint */
    strncpy(engine->fingerprint, fingerprint, 128);
    engine->fingerprint[128] = '\0';

    /* Load DHT identity */
    messenger_load_dht_identity(fingerprint);

    /* Initialize contacts database BEFORE P2P/offline message check
     * This is required because offline message check queries contacts' outboxes */
    if (contacts_db_init(fingerprint) != 0) {
        printf("[DNA_ENGINE] Warning: Failed to initialize contacts database\n");
        /* Non-fatal - continue, contacts will be initialized on first access */
    }

    /* Initialize P2P transport for DHT and messaging */
    if (messenger_p2p_init(engine->messenger) != 0) {
        printf("[DNA_ENGINE] Warning: Failed to initialize P2P transport\n");
        /* Non-fatal - continue without P2P, DHT operations will still work via singleton */
    } else {
        /* P2P initialized successfully - complete P2P setup */
        /* Note: Presence already registered in messenger_p2p_init() */

        /* 1. Subscribe to contacts for push notifications */
        if (messenger_p2p_subscribe_to_contacts(engine->messenger) == 0) {
            printf("[DNA_ENGINE] Subscribed to contacts for push notifications\n");
        } else {
            printf("[DNA_ENGINE] Warning: Failed to subscribe to contacts\n");
        }

        /* 2. Check for offline messages (Model E: query contacts' outboxes) */
        size_t offline_count = 0;
        if (messenger_p2p_check_offline_messages(engine->messenger, &offline_count) == 0) {
            if (offline_count > 0) {
                printf("[DNA_ENGINE] Received %zu offline messages\n", offline_count);
            } else {
                printf("[DNA_ENGINE] No offline messages found\n");
            }
        } else {
            printf("[DNA_ENGINE] Warning: Failed to check offline messages\n");
        }
    }

    engine->identity_loaded = true;

    /* Dispatch identity loaded event */
    dna_event_t event = {0};
    event.type = DNA_EVENT_IDENTITY_LOADED;
    strncpy(event.data.identity_loaded.fingerprint, fingerprint, 128);
    dna_dispatch_event(engine, &event);

done:
    task->callback.completion(task->request_id, error, task->user_data);
}

void dna_handle_register_name(dna_engine_t *engine, dna_task_t *task) {
    int error = DNA_OK;

    if (!engine->identity_loaded || !engine->messenger) {
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
        goto done;
    }

    int rc = messenger_register_name(
        engine->messenger,
        engine->fingerprint,
        task->params.register_name.name
    );

    if (rc != 0) {
        error = DNA_ENGINE_ERROR_NETWORK;
    }

done:
    task->callback.completion(task->request_id, error, task->user_data);
}

/* Helper: Update in-memory name cache */
static void update_name_cache(dna_engine_t *engine, const char *fingerprint, const char *name) {
    if (!name || strlen(name) == 0) return;
    /* Only cache real names, not shortened fingerprints */
    if (strlen(name) >= 20 && strstr(name, "...") != NULL) return;

    pthread_mutex_lock(&engine->name_cache_mutex);
    /* Check if already cached */
    for (int i = 0; i < engine->name_cache_count; i++) {
        if (strcmp(engine->name_cache[i].fingerprint, fingerprint) == 0) {
            /* Update existing entry */
            strncpy(engine->name_cache[i].display_name, name, 63);
            pthread_mutex_unlock(&engine->name_cache_mutex);
            return;
        }
    }
    /* Add new entry */
    if (engine->name_cache_count < DNA_NAME_CACHE_MAX) {
        strncpy(engine->name_cache[engine->name_cache_count].fingerprint,
                fingerprint, 128);
        strncpy(engine->name_cache[engine->name_cache_count].display_name,
                name, 63);
        engine->name_cache_count++;
        printf("[DNA_ENGINE] Cached name: %s -> %s\n", fingerprint, name);
    }
    pthread_mutex_unlock(&engine->name_cache_mutex);
}

/* Helper: Background DHT refresh for display name (runs in worker thread) */
static void refresh_display_name_from_dht(dna_engine_t *engine, const char *fingerprint) {
    dht_context_t *dht = dht_singleton_get();
    if (!dht) return;

    char *name_out = NULL;
    int rc = dna_get_display_name(dht, fingerprint, &name_out);

    if (rc == 0 && name_out && strlen(name_out) > 0) {
        /* Update in-memory cache */
        update_name_cache(engine, fingerprint, name_out);
        printf("[DNA_ENGINE] Background refresh: %s -> %s\n", fingerprint, name_out);
        free(name_out);
    }
}

void dna_handle_get_display_name(dna_engine_t *engine, dna_task_t *task) {
    char display_name_buf[256] = {0};
    int error = DNA_OK;
    char *display_name = NULL;
    const char *fingerprint = task->params.get_display_name.fingerprint;
    bool need_background_refresh = false;

    /* 1. Check in-memory cache first (fastest) */
    pthread_mutex_lock(&engine->name_cache_mutex);
    for (int i = 0; i < engine->name_cache_count; i++) {
        if (strcmp(engine->name_cache[i].fingerprint, fingerprint) == 0) {
            strncpy(display_name_buf, engine->name_cache[i].display_name,
                    sizeof(display_name_buf) - 1);
            pthread_mutex_unlock(&engine->name_cache_mutex);
            printf("[DNA_ENGINE] Memory cache hit: %s -> %s\n", fingerprint, display_name_buf);
            goto done;
        }
    }
    pthread_mutex_unlock(&engine->name_cache_mutex);

    /* 2. Check persistent profile_cache (SQLite) */
    dna_unified_identity_t *cached_identity = NULL;
    uint64_t cached_at = 0;
    int cache_rc = profile_cache_get(fingerprint, &cached_identity, &cached_at);

    if (cache_rc == 0 && cached_identity && cached_identity->display_name[0] != '\0') {
        /* Found in profile cache */
        strncpy(display_name_buf, cached_identity->display_name, sizeof(display_name_buf) - 1);

        /* Update in-memory cache */
        update_name_cache(engine, fingerprint, cached_identity->display_name);

        /* Check if expired (>7 days) - schedule background refresh */
        uint64_t now = (uint64_t)time(NULL);
        uint64_t age = now - cached_at;
        if (age >= PROFILE_CACHE_TTL_SECONDS) {
            need_background_refresh = true;
            printf("[DNA_ENGINE] Profile cache hit (expired, will refresh): %s -> %s\n",
                   fingerprint, display_name_buf);
        } else {
            printf("[DNA_ENGINE] Profile cache hit: %s -> %s (age: %lu sec)\n",
                   fingerprint, display_name_buf, (unsigned long)age);
        }

        dna_identity_free(cached_identity);

        if (need_background_refresh) {
            /* Do background refresh after returning cached value */
            refresh_display_name_from_dht(engine, fingerprint);
        }
        goto done;
    }

    if (cached_identity) {
        dna_identity_free(cached_identity);
    }

    /* 3. Not in any cache - fetch from DHT */
    dht_context_t *dht = dht_singleton_get();
    if (!dht) {
        error = DNA_ENGINE_ERROR_NETWORK;
        goto done;
    }

    char *name_out = NULL;
    int rc = dna_get_display_name(dht, fingerprint, &name_out);

    if (rc == 0 && name_out) {
        strncpy(display_name_buf, name_out, sizeof(display_name_buf) - 1);

        /* Update in-memory cache */
        update_name_cache(engine, fingerprint, name_out);

        free(name_out);
    } else {
        /* Fall back to shortened fingerprint */
        snprintf(display_name_buf, sizeof(display_name_buf), "%.16s...", fingerprint);
    }

done:
    /* Allocate on heap for thread-safe callback - caller frees via dna_free_string */
    display_name = strdup(display_name_buf);
    task->callback.display_name(task->request_id, error, display_name, task->user_data);
}

void dna_handle_lookup_name(dna_engine_t *engine, dna_task_t *task) {
    (void)engine;  /* Not needed for DHT lookup */
    char fingerprint_buf[129] = {0};
    int error = DNA_OK;
    char *fingerprint = NULL;

    dht_context_t *dht = dht_singleton_get();
    if (!dht) {
        error = DNA_ENGINE_ERROR_NETWORK;
        goto done;
    }

    char *fp_out = NULL;
    int rc = dna_lookup_by_name(dht, task->params.lookup_name.name, &fp_out);

    if (rc == 0 && fp_out) {
        /* Name is taken - return the fingerprint of who owns it */
        strncpy(fingerprint_buf, fp_out, sizeof(fingerprint_buf) - 1);
        free(fp_out);
    } else if (rc == -2) {
        /* Name not found = available, return empty string */
        fingerprint_buf[0] = '\0';
    } else {
        /* Other error */
        error = DNA_ENGINE_ERROR_NETWORK;
    }

done:
    /* Allocate on heap for thread-safe callback - caller frees via dna_free_string */
    fingerprint = strdup(fingerprint_buf);
    task->callback.display_name(task->request_id, error, fingerprint, task->user_data);
}

void dna_handle_get_profile(dna_engine_t *engine, dna_task_t *task) {
    int error = DNA_OK;
    dna_profile_t *profile = NULL;

    if (!engine->identity_loaded || !engine->messenger) {
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
        goto done;
    }

    dht_context_t *dht = dna_get_dht_ctx(engine);
    if (!dht) {
        error = DNA_ENGINE_ERROR_NETWORK;
        goto done;
    }

    /* Load identity from DHT */
    dna_unified_identity_t *identity = NULL;
    int rc = dna_load_identity(dht, engine->fingerprint, &identity);

    if (rc != 0 || !identity) {
        if (rc == -2) {
            /* No profile yet - return empty profile */
            profile = (dna_profile_t*)calloc(1, sizeof(dna_profile_t));
        } else {
            error = DNA_ENGINE_ERROR_NETWORK;
        }
        goto done;
    }

    /* Copy identity data to profile struct */
    profile = (dna_profile_t*)calloc(1, sizeof(dna_profile_t));
    if (!profile) {
        error = DNA_ERROR_INTERNAL;
        dna_identity_free(identity);
        goto done;
    }

    /* Wallets */
    strncpy(profile->backbone, identity->wallets.backbone, sizeof(profile->backbone) - 1);
    strncpy(profile->kelvpn, identity->wallets.kelvpn, sizeof(profile->kelvpn) - 1);
    strncpy(profile->subzero, identity->wallets.subzero, sizeof(profile->subzero) - 1);
    strncpy(profile->cpunk_testnet, identity->wallets.cpunk_testnet, sizeof(profile->cpunk_testnet) - 1);
    strncpy(profile->btc, identity->wallets.btc, sizeof(profile->btc) - 1);
    strncpy(profile->eth, identity->wallets.eth, sizeof(profile->eth) - 1);
    strncpy(profile->sol, identity->wallets.sol, sizeof(profile->sol) - 1);

    /* Socials */
    strncpy(profile->telegram, identity->socials.telegram, sizeof(profile->telegram) - 1);
    strncpy(profile->twitter, identity->socials.x, sizeof(profile->twitter) - 1);
    strncpy(profile->github, identity->socials.github, sizeof(profile->github) - 1);

    /* Bio and avatar */
    strncpy(profile->bio, identity->bio, sizeof(profile->bio) - 1);
    strncpy(profile->avatar_base64, identity->avatar_base64, sizeof(profile->avatar_base64) - 1);

    dna_identity_free(identity);

done:
    task->callback.profile(task->request_id, error, profile, task->user_data);
}

void dna_handle_update_profile(dna_engine_t *engine, dna_task_t *task) {
    int error = DNA_OK;

    if (!engine->identity_loaded || !engine->messenger) {
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
        goto done;
    }

    dht_context_t *dht = dna_get_dht_ctx(engine);
    if (!dht) {
        error = DNA_ENGINE_ERROR_NETWORK;
        goto done;
    }

    /* Load private keys for signing */
    qgp_key_t *sign_key = dna_load_private_key(engine);
    if (!sign_key) {
        error = DNA_ENGINE_ERROR_PERMISSION;
        goto done;
    }

    /* Load encryption key for kyber pubkey */
    char enc_key_path[512];
    snprintf(enc_key_path, sizeof(enc_key_path), "%s/%s.kem",
             engine->data_dir, engine->fingerprint);
    qgp_key_t *enc_key = NULL;
    if (qgp_key_load(enc_key_path, &enc_key) != 0 || !enc_key) {
        error = DNA_ENGINE_ERROR_PERMISSION;
        qgp_key_free(sign_key);
        goto done;
    }

    /* Build profile data structure */
    dna_profile_data_t profile_data = {0};
    const dna_profile_t *p = &task->params.update_profile.profile;

    /* Wallets */
    strncpy(profile_data.wallets.backbone, p->backbone, sizeof(profile_data.wallets.backbone) - 1);
    strncpy(profile_data.wallets.kelvpn, p->kelvpn, sizeof(profile_data.wallets.kelvpn) - 1);
    strncpy(profile_data.wallets.subzero, p->subzero, sizeof(profile_data.wallets.subzero) - 1);
    strncpy(profile_data.wallets.cpunk_testnet, p->cpunk_testnet, sizeof(profile_data.wallets.cpunk_testnet) - 1);
    strncpy(profile_data.wallets.btc, p->btc, sizeof(profile_data.wallets.btc) - 1);
    strncpy(profile_data.wallets.eth, p->eth, sizeof(profile_data.wallets.eth) - 1);
    strncpy(profile_data.wallets.sol, p->sol, sizeof(profile_data.wallets.sol) - 1);

    /* Socials */
    strncpy(profile_data.socials.telegram, p->telegram, sizeof(profile_data.socials.telegram) - 1);
    strncpy(profile_data.socials.x, p->twitter, sizeof(profile_data.socials.x) - 1);
    strncpy(profile_data.socials.github, p->github, sizeof(profile_data.socials.github) - 1);

    /* Bio and avatar */
    strncpy(profile_data.bio, p->bio, sizeof(profile_data.bio) - 1);
    strncpy(profile_data.avatar_base64, p->avatar_base64, sizeof(profile_data.avatar_base64) - 1);

    /* Update profile in DHT */
    int rc = dna_update_profile(dht, engine->fingerprint, &profile_data,
                                 sign_key->private_key, sign_key->public_key,
                                 enc_key->public_key);

    qgp_key_free(sign_key);
    qgp_key_free(enc_key);

    if (rc != 0) {
        error = DNA_ENGINE_ERROR_NETWORK;
    }

done:
    task->callback.completion(task->request_id, error, task->user_data);
}

/* ============================================================================
 * CONTACTS TASK HANDLERS
 * ============================================================================ */

void dna_handle_get_contacts(dna_engine_t *engine, dna_task_t *task) {
    int error = DNA_OK;
    dna_contact_t *contacts = NULL;
    int count = 0;

    if (!engine->identity_loaded) {
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
        goto done;
    }

    /* Initialize contacts database for this identity */
    if (contacts_db_init(engine->fingerprint) != 0) {
        error = DNA_ENGINE_ERROR_DATABASE;
        goto done;
    }

    /* Get contact list from local database */
    contact_list_t *list = NULL;
    if (contacts_db_list(&list) != 0 || !list) {
        error = DNA_ENGINE_ERROR_DATABASE;
        goto done;
    }

    if (list->count > 0) {
        contacts = calloc(list->count, sizeof(dna_contact_t));
        if (!contacts) {
            contacts_db_free_list(list);
            error = DNA_ERROR_INTERNAL;
            goto done;
        }

        dht_context_t *dht = dht_singleton_get();

        for (size_t i = 0; i < list->count; i++) {
            strncpy(contacts[i].fingerprint, list->contacts[i].identity, 128);

            /* Try to get display name from DHT */
            if (dht) {
                char *name = NULL;
                if (dna_get_display_name(dht, list->contacts[i].identity, &name) == 0 && name) {
                    strncpy(contacts[i].display_name, name, sizeof(contacts[i].display_name) - 1);
                    free(name);
                } else {
                    snprintf(contacts[i].display_name, sizeof(contacts[i].display_name),
                             "%.16s...", list->contacts[i].identity);
                }
            } else {
                snprintf(contacts[i].display_name, sizeof(contacts[i].display_name),
                         "%.16s...", list->contacts[i].identity);
            }

            /* Check presence cache for online status and last seen */
            contacts[i].is_online = presence_cache_get(list->contacts[i].identity);
            contacts[i].last_seen = (uint64_t)presence_cache_last_seen(list->contacts[i].identity);
        }
        count = (int)list->count;
    }

    contacts_db_free_list(list);

done:
    task->callback.contacts(task->request_id, error, contacts, count, task->user_data);
}

void dna_handle_add_contact(dna_engine_t *engine, dna_task_t *task) {
    int error = DNA_OK;
    char fingerprint[129] = {0};

    if (!engine->identity_loaded) {
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
        goto done;
    }

    const char *identifier = task->params.add_contact.identifier;

    /* Check if it's already a fingerprint (128 hex chars) */
    bool is_fingerprint = (strlen(identifier) == 128);
    if (is_fingerprint) {
        for (int i = 0; i < 128 && is_fingerprint; i++) {
            char c = identifier[i];
            is_fingerprint = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
        }
    }

    if (is_fingerprint) {
        strncpy(fingerprint, identifier, 128);
    } else {
        /* Lookup name in DHT */
        dht_context_t *dht = dht_singleton_get();
        if (!dht) {
            error = DNA_ENGINE_ERROR_NETWORK;
            goto done;
        }

        char *fp_out = NULL;
        if (dna_lookup_by_name(dht, identifier, &fp_out) != 0 || !fp_out) {
            error = DNA_ERROR_NOT_FOUND;
            goto done;
        }
        strncpy(fingerprint, fp_out, 128);
        free(fp_out);
    }

    /* Initialize contacts database for this identity */
    if (contacts_db_init(engine->fingerprint) != 0) {
        error = DNA_ENGINE_ERROR_DATABASE;
        goto done;
    }

    /* Add to local contacts database */
    int rc = contacts_db_add(fingerprint, NULL);
    if (rc == -2) {
        error = DNA_ENGINE_ERROR_ALREADY_EXISTS;
        goto done;
    } else if (rc != 0) {
        error = DNA_ENGINE_ERROR_DATABASE;
        goto done;
    }

    /* Sync to DHT */
    messenger_sync_contacts_to_dht(engine->messenger);

done:
    task->callback.completion(task->request_id, error, task->user_data);
}

void dna_handle_remove_contact(dna_engine_t *engine, dna_task_t *task) {
    int error = DNA_OK;

    if (!engine->identity_loaded) {
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
        goto done;
    }

    /* Initialize contacts database for this identity */
    if (contacts_db_init(engine->fingerprint) != 0) {
        error = DNA_ENGINE_ERROR_DATABASE;
        goto done;
    }

    if (contacts_db_remove(task->params.remove_contact.fingerprint) != 0) {
        error = DNA_ERROR_NOT_FOUND;
    }

    /* Sync to DHT */
    if (error == DNA_OK) {
        messenger_sync_contacts_to_dht(engine->messenger);
    }

done:
    task->callback.completion(task->request_id, error, task->user_data);
}

/* ============================================================================
 * MESSAGING TASK HANDLERS
 * ============================================================================ */

void dna_handle_send_message(dna_engine_t *engine, dna_task_t *task) {
    int error = DNA_OK;

    if (!engine->identity_loaded || !engine->messenger) {
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
        goto done;
    }

    const char *recipients[1] = { task->params.send_message.recipient };

    int rc = messenger_send_message(
        engine->messenger,
        recipients,
        1,
        task->params.send_message.message,
        0,  /* group_id = 0 for direct messages */
        0   /* message_type = chat */
    );

    if (rc != 0) {
        error = DNA_ENGINE_ERROR_NETWORK;
    }

done:
    task->callback.completion(task->request_id, error, task->user_data);
}

void dna_handle_get_conversation(dna_engine_t *engine, dna_task_t *task) {
    int error = DNA_OK;
    dna_message_t *messages = NULL;
    int count = 0;

    if (!engine->identity_loaded || !engine->messenger) {
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
        goto done;
    }

    message_info_t *msg_infos = NULL;
    int msg_count = 0;

    int rc = messenger_get_conversation(
        engine->messenger,
        task->params.get_conversation.contact,
        &msg_infos,
        &msg_count
    );

    if (rc != 0) {
        error = DNA_ENGINE_ERROR_DATABASE;
        goto done;
    }

    if (msg_count > 0) {
        messages = calloc(msg_count, sizeof(dna_message_t));
        if (!messages) {
            messenger_free_messages(msg_infos, msg_count);
            error = DNA_ERROR_INTERNAL;
            goto done;
        }

        for (int i = 0; i < msg_count; i++) {
            messages[i].id = msg_infos[i].id;
            strncpy(messages[i].sender, msg_infos[i].sender ? msg_infos[i].sender : "", 128);
            strncpy(messages[i].recipient, msg_infos[i].recipient ? msg_infos[i].recipient : "", 128);

            /* Decrypt message */
            char *plaintext = NULL;
            size_t plaintext_len = 0;
            if (messenger_decrypt_message(engine->messenger, msg_infos[i].id, &plaintext, &plaintext_len) == 0) {
                messages[i].plaintext = plaintext;
            } else {
                messages[i].plaintext = strdup("[Decryption failed]");
            }

            /* Parse timestamp */
            if (msg_infos[i].timestamp) {
                /* Assume ISO format, convert to unix time */
                messages[i].timestamp = (uint64_t)time(NULL); /* Simplified */
            }

            /* Determine if outgoing */
            messages[i].is_outgoing = (msg_infos[i].sender &&
                strcmp(msg_infos[i].sender, engine->fingerprint) == 0);

            /* Map status string to int */
            if (msg_infos[i].status) {
                if (strcmp(msg_infos[i].status, "read") == 0) {
                    messages[i].status = 3;
                } else if (strcmp(msg_infos[i].status, "delivered") == 0) {
                    messages[i].status = 2;
                } else if (strcmp(msg_infos[i].status, "sent") == 0) {
                    messages[i].status = 1;
                } else {
                    messages[i].status = 0;
                }
            }

            messages[i].message_type = msg_infos[i].message_type;
        }
        count = msg_count;

        messenger_free_messages(msg_infos, msg_count);
    }

done:
    task->callback.messages(task->request_id, error, messages, count, task->user_data);
}

void dna_handle_check_offline_messages(dna_engine_t *engine, dna_task_t *task) {
    int error = DNA_OK;

    if (!engine->identity_loaded || !engine->messenger) {
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
        goto done;
    }

    /* Use messenger's contacts_auto_sync which handles offline queue internally */
    int rc = messenger_contacts_auto_sync(engine->messenger);
    if (rc != 0) {
        /* Non-fatal - just no new messages */
    }

done:
    task->callback.completion(task->request_id, error, task->user_data);
}

/* ============================================================================
 * GROUPS TASK HANDLERS
 * ============================================================================ */

void dna_handle_get_groups(dna_engine_t *engine, dna_task_t *task) {
    int error = DNA_OK;
    dna_group_t *groups = NULL;
    int count = 0;

    if (!engine->identity_loaded) {
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
        goto done;
    }

    /* Get groups from local cache via DHT groups API */
    dht_group_cache_entry_t *entries = NULL;
    int entry_count = 0;
    if (dht_groups_list_for_user(engine->fingerprint, &entries, &entry_count) != 0) {
        error = DNA_ENGINE_ERROR_DATABASE;
        goto done;
    }

    if (entry_count > 0) {
        groups = calloc(entry_count, sizeof(dna_group_t));
        if (!groups) {
            dht_groups_free_cache_entries(entries, entry_count);
            error = DNA_ERROR_INTERNAL;
            goto done;
        }

        for (int i = 0; i < entry_count; i++) {
            strncpy(groups[i].uuid, entries[i].group_uuid, 36);
            strncpy(groups[i].name, entries[i].name, sizeof(groups[i].name) - 1);
            strncpy(groups[i].creator, entries[i].creator, 128);
            groups[i].member_count = 0; /* Cache doesn't store member count */
            groups[i].created_at = entries[i].created_at;
        }
        count = entry_count;

        dht_groups_free_cache_entries(entries, entry_count);
    }

done:
    task->callback.groups(task->request_id, error, groups, count, task->user_data);
}

void dna_handle_create_group(dna_engine_t *engine, dna_task_t *task) {
    int error = DNA_OK;
    char group_uuid[37] = {0};

    if (!engine->identity_loaded || !engine->messenger) {
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
        goto done;
    }

    int group_id = 0;
    int rc = messenger_create_group(
        engine->messenger,
        task->params.create_group.name,
        NULL, /* description */
        (const char**)task->params.create_group.members,
        task->params.create_group.member_count,
        &group_id
    );

    if (rc != 0) {
        error = DNA_ERROR_INTERNAL;
        goto done;
    }

    /* Get UUID from group ID - simplified, actual impl would query database */
    snprintf(group_uuid, sizeof(group_uuid), "%08x-0000-0000-0000-000000000000", group_id);

done:
    task->callback.group_created(task->request_id, error,
                                  (error == DNA_OK) ? group_uuid : NULL,
                                  task->user_data);
}

void dna_handle_send_group_message(dna_engine_t *engine, dna_task_t *task) {
    int error = DNA_OK;

    if (!engine->identity_loaded || !engine->messenger) {
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
        goto done;
    }

    int rc = messenger_send_group_message(
        engine->messenger,
        task->params.send_group_message.group_uuid,
        task->params.send_group_message.message
    );

    if (rc != 0) {
        error = DNA_ENGINE_ERROR_NETWORK;
    }

done:
    task->callback.completion(task->request_id, error, task->user_data);
}

void dna_handle_get_invitations(dna_engine_t *engine, dna_task_t *task) {
    int error = DNA_OK;
    dna_invitation_t *invitations = NULL;
    int count = 0;

    if (!engine->identity_loaded) {
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
        goto done;
    }

    /* Initialize invitations database for this identity */
    if (group_invitations_init(engine->fingerprint) != 0) {
        error = DNA_ENGINE_ERROR_DATABASE;
        goto done;
    }

    group_invitation_t *entries = NULL;
    int entry_count = 0;
    if (group_invitations_get_pending(&entries, &entry_count) != 0) {
        error = DNA_ENGINE_ERROR_DATABASE;
        goto done;
    }

    if (entry_count > 0) {
        invitations = calloc(entry_count, sizeof(dna_invitation_t));
        if (!invitations) {
            group_invitations_free(entries, entry_count);
            error = DNA_ERROR_INTERNAL;
            goto done;
        }

        for (int i = 0; i < entry_count; i++) {
            strncpy(invitations[i].group_uuid, entries[i].group_uuid, 36);
            strncpy(invitations[i].group_name, entries[i].group_name, sizeof(invitations[i].group_name) - 1);
            strncpy(invitations[i].inviter, entries[i].inviter, 128);
            invitations[i].member_count = entries[i].member_count;
            invitations[i].invited_at = (uint64_t)entries[i].invited_at;
        }
        count = entry_count;

        group_invitations_free(entries, entry_count);
    }

done:
    task->callback.invitations(task->request_id, error, invitations, count, task->user_data);
}

void dna_handle_accept_invitation(dna_engine_t *engine, dna_task_t *task) {
    int error = DNA_OK;

    if (!engine->identity_loaded || !engine->messenger) {
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
        goto done;
    }

    int rc = messenger_accept_group_invitation(
        engine->messenger,
        task->params.invitation.group_uuid
    );

    if (rc != 0) {
        error = DNA_ENGINE_ERROR_NETWORK;
    }

done:
    task->callback.completion(task->request_id, error, task->user_data);
}

void dna_handle_reject_invitation(dna_engine_t *engine, dna_task_t *task) {
    int error = DNA_OK;

    if (!engine->identity_loaded || !engine->messenger) {
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
        goto done;
    }

    int rc = messenger_reject_group_invitation(
        engine->messenger,
        task->params.invitation.group_uuid
    );

    if (rc != 0) {
        error = DNA_ERROR_INTERNAL;
    }

done:
    task->callback.completion(task->request_id, error, task->user_data);
}

/* ============================================================================
 * WALLET TASK HANDLERS
 * ============================================================================ */

void dna_handle_list_wallets(dna_engine_t *engine, dna_task_t *task) {
    int error = DNA_OK;
    dna_wallet_t *wallets = NULL;
    int count = 0;

    /* Free existing wallet list */
    if (engine->wallet_list) {
        wallet_list_free(engine->wallet_list);
        engine->wallet_list = NULL;
    }

    int rc = wallet_list_cellframe(&engine->wallet_list);
    if (rc != 0 || !engine->wallet_list) {
        error = DNA_ENGINE_ERROR_DATABASE;
        goto done;
    }

    wallet_list_t *list = engine->wallet_list;
    if (list->count > 0) {
        wallets = calloc(list->count, sizeof(dna_wallet_t));
        if (!wallets) {
            error = DNA_ERROR_INTERNAL;
            goto done;
        }

        for (size_t i = 0; i < list->count; i++) {
            strncpy(wallets[i].name, list->wallets[i].name, sizeof(wallets[i].name) - 1);
            strncpy(wallets[i].address, list->wallets[i].address, sizeof(wallets[i].address) - 1);
            wallets[i].sig_type = (int)list->wallets[i].sig_type;
            wallets[i].is_protected = (list->wallets[i].status == WALLET_STATUS_PROTECTED);
        }
        count = (int)list->count;
    }

    engine->wallets_loaded = true;

done:
    task->callback.wallets(task->request_id, error, wallets, count, task->user_data);
}

void dna_handle_get_balances(dna_engine_t *engine, dna_task_t *task) {
    int error = DNA_OK;
    dna_balance_t *balances = NULL;
    int count = 0;

    if (!engine->wallets_loaded || !engine->wallet_list) {
        error = DNA_ENGINE_ERROR_NOT_INITIALIZED;
        goto done;
    }

    wallet_list_t *list = engine->wallet_list;
    int idx = task->params.get_balances.wallet_index;

    if (idx < 0 || idx >= (int)list->count) {
        error = DNA_ERROR_INVALID_ARG;
        goto done;
    }

    cellframe_wallet_t *wallet = &list->wallets[idx];

    /* Get address for Backbone network */
    char address[WALLET_ADDRESS_MAX] = {0};
    if (wallet_get_address(wallet, "Backbone", address) != 0) {
        error = DNA_ENGINE_ERROR_NETWORK;
        goto done;
    }

    /* Pre-allocate balances for CPUNK and CELL (only supported tokens) */
    balances = calloc(2, sizeof(dna_balance_t));
    if (!balances) {
        error = DNA_ERROR_INTERNAL;
        goto done;
    }

    /* Initialize with defaults */
    strncpy(balances[0].token, "CPUNK", sizeof(balances[0].token) - 1);
    strncpy(balances[0].network, "Backbone", sizeof(balances[0].network) - 1);
    strcpy(balances[0].balance, "0.0");

    strncpy(balances[1].token, "CELL", sizeof(balances[1].token) - 1);
    strncpy(balances[1].network, "Backbone", sizeof(balances[1].network) - 1);
    strcpy(balances[1].balance, "0.0");

    count = 2;

    /* Query balance via RPC - response contains all tokens for address */
    cellframe_rpc_response_t *response = NULL;
    int rc = cellframe_rpc_get_balance("Backbone", address, "CPUNK", &response);

    if (rc == 0 && response && response->result) {
        json_object *jresult = response->result;

        /* Parse response format: result[0][0]["tokens"][i] */
        if (json_object_is_type(jresult, json_type_array) &&
            json_object_array_length(jresult) > 0) {

            json_object *first = json_object_array_get_idx(jresult, 0);
            if (first && json_object_is_type(first, json_type_array) &&
                json_object_array_length(first) > 0) {

                json_object *wallet_obj = json_object_array_get_idx(first, 0);
                json_object *tokens_obj = NULL;

                if (wallet_obj && json_object_object_get_ex(wallet_obj, "tokens", &tokens_obj)) {
                    int token_count = json_object_array_length(tokens_obj);

                    for (int i = 0; i < token_count; i++) {
                        json_object *token_entry = json_object_array_get_idx(tokens_obj, i);
                        json_object *token_info_obj = NULL;
                        json_object *coins_obj = NULL;

                        if (!json_object_object_get_ex(token_entry, "coins", &coins_obj)) {
                            continue;
                        }

                        if (!json_object_object_get_ex(token_entry, "token", &token_info_obj)) {
                            continue;
                        }

                        json_object *ticker_obj = NULL;
                        if (json_object_object_get_ex(token_info_obj, "ticker", &ticker_obj)) {
                            const char *ticker = json_object_get_string(ticker_obj);
                            const char *coins = json_object_get_string(coins_obj);

                            /* Match ticker to our balance slots */
                            if (ticker && coins) {
                                if (strcmp(ticker, "CPUNK") == 0) {
                                    strncpy(balances[0].balance, coins, sizeof(balances[0].balance) - 1);
                                } else if (strcmp(ticker, "CELL") == 0) {
                                    strncpy(balances[1].balance, coins, sizeof(balances[1].balance) - 1);
                                }
                            }
                        }
                    }
                }
            }
        }

        cellframe_rpc_response_free(response);
    }

done:
    task->callback.balances(task->request_id, error, balances, count, task->user_data);
}

/* Network fee constants for send_tokens */
#define NETWORK_FEE_DATOSHI 2000000000000000ULL  /* 0.002 CELL */
#define NETWORK_FEE_COLLECTOR "Rj7J7MiX2bWy8sNyX38bB86KTFUnSn7sdKDsTFa2RJyQTDWFaebrj6BucT7Wa5CSq77zwRAwevbiKy1sv1RBGTonM83D3xPDwoyGasZ7"
#define DEFAULT_VALIDATOR_FEE_DATOSHI 100000000000000ULL  /* 0.0001 CELL */

/* UTXO structure for transaction building */
typedef struct {
    cellframe_hash_t hash;
    uint32_t idx;
    uint256_t value;
} engine_utxo_t;

void dna_handle_send_tokens(dna_engine_t *engine, dna_task_t *task) {
    int error = DNA_OK;
    engine_utxo_t *selected_utxos = NULL;
    cellframe_tx_builder_t *builder = NULL;
    cellframe_rpc_response_t *utxo_resp = NULL;
    cellframe_rpc_response_t *submit_resp = NULL;
    uint8_t *dap_sign = NULL;
    char *json = NULL;

    if (!engine->wallets_loaded || !engine->wallet_list) {
        error = DNA_ENGINE_ERROR_NOT_INITIALIZED;
        goto done;
    }

    /* Get task parameters */
    int wallet_index = task->params.send_tokens.wallet_index;
    const char *recipient = task->params.send_tokens.recipient;
    const char *amount_str = task->params.send_tokens.amount;
    const char *network = task->params.send_tokens.network;

    /* Get wallet */
    wallet_list_t *wallets = (wallet_list_t*)engine->wallet_list;
    if (wallet_index < 0 || wallet_index >= wallets->count) {
        error = DNA_ERROR_INVALID_ARG;
        goto done;
    }

    cellframe_wallet_t *wallet = &wallets->wallets[wallet_index];

    /* Check if address is available */
    if (wallet->address[0] == '\0') {
        fprintf(stderr, "[ENGINE] Wallet address not available\n");
        error = DNA_ERROR_INTERNAL;
        goto done;
    }

    char address[WALLET_ADDRESS_MAX];
    strncpy(address, wallet->address, WALLET_ADDRESS_MAX - 1);
    address[WALLET_ADDRESS_MAX - 1] = '\0';

    /* Parse amount */
    uint256_t amount = {0};
    if (cellframe_uint256_from_str(amount_str, &amount) != 0) {
        fprintf(stderr, "[ENGINE] Failed to parse amount: %s\n", amount_str);
        error = DNA_ERROR_INVALID_ARG;
        goto done;
    }

    /* Use default validator fee */
    uint256_t fee = {0};
    fee.lo.lo = DEFAULT_VALIDATOR_FEE_DATOSHI;

    /* STEP 1: Query UTXOs */
    int num_selected_utxos = 0;
    uint64_t total_input_u64 = 0;
    uint64_t required_u64 = amount.lo.lo + NETWORK_FEE_DATOSHI + fee.lo.lo;

    if (cellframe_rpc_get_utxo(network, address, "CELL", &utxo_resp) != 0 || !utxo_resp) {
        fprintf(stderr, "[ENGINE] Failed to query UTXOs from RPC\n");
        error = DNA_ENGINE_ERROR_NETWORK;
        goto done;
    }

    if (utxo_resp->result) {
        /* Parse UTXO response: result[0][0]["outs"][] */
        if (json_object_is_type(utxo_resp->result, json_type_array) &&
            json_object_array_length(utxo_resp->result) > 0) {

            json_object *first_array = json_object_array_get_idx(utxo_resp->result, 0);
            if (first_array && json_object_is_type(first_array, json_type_array) &&
                json_object_array_length(first_array) > 0) {

                json_object *first_item = json_object_array_get_idx(first_array, 0);
                json_object *outs_obj = NULL;

                if (first_item && json_object_object_get_ex(first_item, "outs", &outs_obj) &&
                    json_object_is_type(outs_obj, json_type_array)) {

                    int num_utxos = json_object_array_length(outs_obj);
                    if (num_utxos == 0) {
                        fprintf(stderr, "[ENGINE] No UTXOs available\n");
                        error = DNA_ERROR_NOT_FOUND;
                        goto done;
                    }

                    /* Parse all UTXOs */
                    engine_utxo_t *all_utxos = (engine_utxo_t*)malloc(sizeof(engine_utxo_t) * num_utxos);
                    if (!all_utxos) {
                        error = DNA_ERROR_INTERNAL;
                        goto done;
                    }
                    int valid_utxos = 0;

                    for (int i = 0; i < num_utxos; i++) {
                        json_object *utxo_obj = json_object_array_get_idx(outs_obj, i);
                        json_object *jhash = NULL, *jidx = NULL, *jvalue = NULL;

                        if (utxo_obj &&
                            json_object_object_get_ex(utxo_obj, "prev_hash", &jhash) &&
                            json_object_object_get_ex(utxo_obj, "out_prev_idx", &jidx) &&
                            json_object_object_get_ex(utxo_obj, "value_datoshi", &jvalue)) {

                            const char *hash_str = json_object_get_string(jhash);
                            const char *value_str = json_object_get_string(jvalue);

                            /* Parse hash */
                            if (hash_str && strlen(hash_str) >= 66 && hash_str[0] == '0' && hash_str[1] == 'x') {
                                for (int j = 0; j < 32; j++) {
                                    sscanf(hash_str + 2 + (j * 2), "%2hhx", &all_utxos[valid_utxos].hash.raw[j]);
                                }
                                all_utxos[valid_utxos].idx = json_object_get_int(jidx);
                                cellframe_uint256_from_str(value_str, &all_utxos[valid_utxos].value);
                                valid_utxos++;
                            }
                        }
                    }

                    if (valid_utxos == 0) {
                        fprintf(stderr, "[ENGINE] No valid UTXOs\n");
                        free(all_utxos);
                        error = DNA_ERROR_NOT_FOUND;
                        goto done;
                    }

                    /* Select UTXOs (greedy selection) */
                    selected_utxos = (engine_utxo_t*)malloc(sizeof(engine_utxo_t) * valid_utxos);
                    if (!selected_utxos) {
                        free(all_utxos);
                        error = DNA_ERROR_INTERNAL;
                        goto done;
                    }

                    for (int i = 0; i < valid_utxos; i++) {
                        selected_utxos[num_selected_utxos++] = all_utxos[i];
                        total_input_u64 += all_utxos[i].value.lo.lo;

                        if (total_input_u64 >= required_u64) {
                            break;
                        }
                    }

                    free(all_utxos);

                    /* Check if we have enough */
                    if (total_input_u64 < required_u64) {
                        fprintf(stderr, "[ENGINE] Insufficient funds. Need: %lu, Have: %lu\n",
                                (unsigned long)required_u64, (unsigned long)total_input_u64);
                        error = DNA_ERROR_INTERNAL;
                        goto done;
                    }

                } else {
                    fprintf(stderr, "[ENGINE] Invalid UTXO response format\n");
                    error = DNA_ENGINE_ERROR_NETWORK;
                    goto done;
                }
            } else {
                fprintf(stderr, "[ENGINE] Invalid UTXO response format\n");
                error = DNA_ENGINE_ERROR_NETWORK;
                goto done;
            }
        } else {
            fprintf(stderr, "[ENGINE] Invalid UTXO response format\n");
            error = DNA_ENGINE_ERROR_NETWORK;
            goto done;
        }
    }

    /* STEP 2: Build transaction */
    builder = cellframe_tx_builder_new();
    if (!builder) {
        fprintf(stderr, "[ENGINE] Failed to create tx builder\n");
        error = DNA_ERROR_INTERNAL;
        goto done;
    }

    /* Set timestamp */
    uint64_t ts = (uint64_t)time(NULL);
    cellframe_tx_set_timestamp(builder, ts);

    /* Parse recipient address from Base58 */
    uint8_t recipient_addr_buf[BASE58_DECODE_SIZE(256)];
    size_t decoded_size = base58_decode(recipient, recipient_addr_buf);
    if (decoded_size != sizeof(cellframe_addr_t)) {
        fprintf(stderr, "[ENGINE] Invalid recipient address\n");
        error = DNA_ERROR_INVALID_ARG;
        goto done;
    }
    cellframe_addr_t recipient_addr;
    memcpy(&recipient_addr, recipient_addr_buf, sizeof(cellframe_addr_t));

    /* Parse network collector address */
    uint8_t network_collector_buf[BASE58_DECODE_SIZE(256)];
    decoded_size = base58_decode(NETWORK_FEE_COLLECTOR, network_collector_buf);
    if (decoded_size != sizeof(cellframe_addr_t)) {
        fprintf(stderr, "[ENGINE] Invalid network collector address\n");
        error = DNA_ERROR_INTERNAL;
        goto done;
    }
    cellframe_addr_t network_collector_addr;
    memcpy(&network_collector_addr, network_collector_buf, sizeof(cellframe_addr_t));

    /* Parse sender address (for change) */
    uint8_t sender_addr_buf[BASE58_DECODE_SIZE(256)];
    decoded_size = base58_decode(address, sender_addr_buf);
    if (decoded_size != sizeof(cellframe_addr_t)) {
        fprintf(stderr, "[ENGINE] Invalid sender address\n");
        error = DNA_ERROR_INTERNAL;
        goto done;
    }
    cellframe_addr_t sender_addr;
    memcpy(&sender_addr, sender_addr_buf, sizeof(cellframe_addr_t));

    /* Calculate network fee */
    uint256_t network_fee = {0};
    network_fee.lo.lo = NETWORK_FEE_DATOSHI;

    /* Calculate change */
    uint64_t change_u64 = total_input_u64 - amount.lo.lo - NETWORK_FEE_DATOSHI - fee.lo.lo;
    uint256_t change = {0};
    change.lo.lo = change_u64;

    /* Add all IN items */
    for (int i = 0; i < num_selected_utxos; i++) {
        if (cellframe_tx_add_in(builder, &selected_utxos[i].hash, selected_utxos[i].idx) != 0) {
            fprintf(stderr, "[ENGINE] Failed to add IN item\n");
            error = DNA_ERROR_INTERNAL;
            goto done;
        }
    }

    /* Add OUT item (recipient) */
    if (cellframe_tx_add_out(builder, &recipient_addr, amount) != 0) {
        fprintf(stderr, "[ENGINE] Failed to add recipient OUT\n");
        error = DNA_ERROR_INTERNAL;
        goto done;
    }

    /* Add OUT item (network fee collector) */
    if (cellframe_tx_add_out(builder, &network_collector_addr, network_fee) != 0) {
        fprintf(stderr, "[ENGINE] Failed to add network fee OUT\n");
        error = DNA_ERROR_INTERNAL;
        goto done;
    }

    /* Add OUT item (change) - only if change > 0 */
    if (change.hi.hi != 0 || change.hi.lo != 0 || change.lo.hi != 0 || change.lo.lo != 0) {
        if (cellframe_tx_add_out(builder, &sender_addr, change) != 0) {
            fprintf(stderr, "[ENGINE] Failed to add change OUT\n");
            error = DNA_ERROR_INTERNAL;
            goto done;
        }
    }

    /* Add OUT_COND item (validator fee) */
    if (cellframe_tx_add_fee(builder, fee) != 0) {
        fprintf(stderr, "[ENGINE] Failed to add validator fee\n");
        error = DNA_ERROR_INTERNAL;
        goto done;
    }

    /* STEP 3: Sign transaction */
    size_t tx_size;
    const uint8_t *tx_data = cellframe_tx_get_signing_data(builder, &tx_size);
    if (!tx_data) {
        fprintf(stderr, "[ENGINE] Failed to get transaction data\n");
        error = DNA_ERROR_INTERNAL;
        goto done;
    }

    /* Sign transaction */
    size_t dap_sign_size = 0;
    if (cellframe_sign_transaction(tx_data, tx_size,
                                    wallet->private_key, wallet->private_key_size,
                                    wallet->public_key, wallet->public_key_size,
                                    &dap_sign, &dap_sign_size) != 0) {
        fprintf(stderr, "[ENGINE] Failed to sign transaction\n");
        free((void*)tx_data);
        error = DNA_ERROR_CRYPTO;
        goto done;
    }

    free((void*)tx_data);

    /* Add signature to transaction */
    if (cellframe_tx_add_signature(builder, dap_sign, dap_sign_size) != 0) {
        fprintf(stderr, "[ENGINE] Failed to add signature\n");
        error = DNA_ERROR_INTERNAL;
        goto done;
    }

    /* STEP 4: Convert to JSON */
    const uint8_t *signed_tx = cellframe_tx_get_data(builder, &tx_size);
    if (!signed_tx) {
        fprintf(stderr, "[ENGINE] Failed to get signed transaction\n");
        error = DNA_ERROR_INTERNAL;
        goto done;
    }

    if (cellframe_tx_to_json(signed_tx, tx_size, &json) != 0) {
        fprintf(stderr, "[ENGINE] Failed to convert to JSON\n");
        error = DNA_ERROR_INTERNAL;
        goto done;
    }

    /* STEP 5: Submit to RPC */
    if (cellframe_rpc_submit_tx(network, "main", json, &submit_resp) != 0 || !submit_resp) {
        fprintf(stderr, "[ENGINE] Failed to submit transaction to RPC\n");
        error = DNA_ENGINE_ERROR_NETWORK;
        goto done;
    }

    /* Check response */
    if (submit_resp->result) {
        bool tx_created = false;

        if (json_object_is_type(submit_resp->result, json_type_array) &&
            json_object_array_length(submit_resp->result) > 0) {

            json_object *first_elem = json_object_array_get_idx(submit_resp->result, 0);
            if (first_elem) {
                json_object *jtx_create = NULL;
                if (json_object_object_get_ex(first_elem, "tx_create", &jtx_create)) {
                    tx_created = json_object_get_boolean(jtx_create);
                }
            }
        }

        if (!tx_created) {
            fprintf(stderr, "[ENGINE] Transaction failed to create\n");
            error = DNA_ERROR_INTERNAL;
            goto done;
        }

        printf("[ENGINE] Transaction submitted successfully!\n");
    }

done:
    if (selected_utxos) free(selected_utxos);
    if (builder) cellframe_tx_builder_free(builder);
    if (utxo_resp) cellframe_rpc_response_free(utxo_resp);
    if (submit_resp) cellframe_rpc_response_free(submit_resp);
    if (dap_sign) free(dap_sign);
    if (json) free(json);

    task->callback.completion(task->request_id, error, task->user_data);
}

void dna_handle_get_transactions(dna_engine_t *engine, dna_task_t *task) {
    int error = DNA_OK;
    dna_transaction_t *transactions = NULL;
    int count = 0;
    cellframe_rpc_response_t *resp = NULL;

    if (!engine->wallets_loaded || !engine->wallet_list) {
        error = DNA_ENGINE_ERROR_NOT_INITIALIZED;
        goto done;
    }

    /* Get wallet address */
    int wallet_index = task->params.get_transactions.wallet_index;
    const char *network = task->params.get_transactions.network;

    wallet_list_t *wallets = (wallet_list_t*)engine->wallet_list;
    if (wallet_index < 0 || wallet_index >= wallets->count) {
        error = DNA_ERROR_INVALID_ARG;
        goto done;
    }

    cellframe_wallet_t *wallet = &wallets->wallets[wallet_index];
    if (wallet->address[0] == '\0') {
        error = DNA_ERROR_INTERNAL;
        goto done;
    }

    /* Query transaction history from RPC */
    if (cellframe_rpc_get_tx_history(network, wallet->address, &resp) != 0 || !resp) {
        fprintf(stderr, "[ENGINE] Failed to query tx history from RPC\n");
        error = DNA_ENGINE_ERROR_NETWORK;
        goto done;
    }

    if (!resp->result) {
        /* No transactions - return empty list */
        goto done;
    }

    /* Parse response: result[0] = {addr, limit}, result[1..n] = transactions */
    if (!json_object_is_type(resp->result, json_type_array)) {
        error = DNA_ENGINE_ERROR_NETWORK;
        goto done;
    }

    /* First element is array with addr/limit, skip it */
    /* Count actual transaction objects (starting from index 1) */
    int array_len = json_object_array_length(resp->result);
    if (array_len <= 1) {
        /* Only header, no transactions */
        goto done;
    }

    /* First array element contains addr and limit objects */
    json_object *first_elem = json_object_array_get_idx(resp->result, 0);
    if (!first_elem || !json_object_is_type(first_elem, json_type_array)) {
        error = DNA_ENGINE_ERROR_NETWORK;
        goto done;
    }

    /* Get transactions array - it's inside first_elem starting at index 2 */
    int tx_array_len = json_object_array_length(first_elem);
    int tx_count = tx_array_len - 2;  /* Skip addr and limit objects */

    if (tx_count <= 0) {
        goto done;
    }

    /* Allocate transactions array */
    transactions = calloc(tx_count, sizeof(dna_transaction_t));
    if (!transactions) {
        error = DNA_ERROR_INTERNAL;
        goto done;
    }

    /* Parse each transaction */
    for (int i = 0; i < tx_count; i++) {
        json_object *tx_obj = json_object_array_get_idx(first_elem, i + 2);
        if (!tx_obj) continue;

        json_object *jhash = NULL, *jstatus = NULL, *jtx_created = NULL, *jdata = NULL;

        json_object_object_get_ex(tx_obj, "hash", &jhash);
        json_object_object_get_ex(tx_obj, "status", &jstatus);
        json_object_object_get_ex(tx_obj, "tx_created", &jtx_created);
        json_object_object_get_ex(tx_obj, "data", &jdata);

        /* Copy hash */
        if (jhash) {
            strncpy(transactions[count].tx_hash, json_object_get_string(jhash),
                    sizeof(transactions[count].tx_hash) - 1);
        }

        /* Copy status */
        if (jstatus) {
            strncpy(transactions[count].status, json_object_get_string(jstatus),
                    sizeof(transactions[count].status) - 1);
        }

        /* Copy timestamp */
        if (jtx_created) {
            strncpy(transactions[count].timestamp, json_object_get_string(jtx_created),
                    sizeof(transactions[count].timestamp) - 1);
        }

        /* Parse data - can be array (old format) or object (new format) */
        if (jdata) {
            json_object *jtx_type = NULL, *jtoken = NULL;
            json_object *jrecv_coins = NULL, *jsend_coins = NULL;
            json_object *jsrc_addr = NULL, *jdst_addr = NULL;
            json_object *jaddr_from = NULL, *jaddrs_to = NULL;

            if (json_object_is_type(jdata, json_type_array)) {
                /* Old format: data is array, use first item */
                if (json_object_array_length(jdata) > 0) {
                    json_object *data_item = json_object_array_get_idx(jdata, 0);
                    if (data_item) {
                        json_object_object_get_ex(data_item, "tx_type", &jtx_type);
                        json_object_object_get_ex(data_item, "token", &jtoken);
                        json_object_object_get_ex(data_item, "recv_coins", &jrecv_coins);
                        json_object_object_get_ex(data_item, "send_coins", &jsend_coins);
                        json_object_object_get_ex(data_item, "source_address", &jsrc_addr);
                        json_object_object_get_ex(data_item, "destination_address", &jdst_addr);
                    }
                }
            } else if (json_object_is_type(jdata, json_type_object)) {
                /* New format: data is object with address_from, addresses_to */
                json_object_object_get_ex(jdata, "ticker", &jtoken);
                json_object_object_get_ex(jdata, "address_from", &jaddr_from);
                json_object_object_get_ex(jdata, "addresses_to", &jaddrs_to);
            }

            /* Determine direction and parse addresses */
            if (jtx_type) {
                /* Old format with tx_type */
                const char *tx_type = json_object_get_string(jtx_type);
                if (strcmp(tx_type, "recv") == 0) {
                    strncpy(transactions[count].direction, "received",
                            sizeof(transactions[count].direction) - 1);
                    if (jrecv_coins) {
                        strncpy(transactions[count].amount, json_object_get_string(jrecv_coins),
                                sizeof(transactions[count].amount) - 1);
                    }
                    if (jsrc_addr) {
                        strncpy(transactions[count].other_address, json_object_get_string(jsrc_addr),
                                sizeof(transactions[count].other_address) - 1);
                    }
                } else if (strcmp(tx_type, "send") == 0) {
                    strncpy(transactions[count].direction, "sent",
                            sizeof(transactions[count].direction) - 1);
                    if (jsend_coins) {
                        strncpy(transactions[count].amount, json_object_get_string(jsend_coins),
                                sizeof(transactions[count].amount) - 1);
                    }
                    /* For destination, skip network fee collector address */
                    if (jdst_addr) {
                        const char *dst = json_object_get_string(jdst_addr);
                        if (dst && strcmp(dst, NETWORK_FEE_COLLECTOR) != 0 &&
                            strstr(dst, "DAP_CHAIN") == NULL) {
                            strncpy(transactions[count].other_address, dst,
                                    sizeof(transactions[count].other_address) - 1);
                        }
                    }
                }
            } else if (jaddr_from && jaddrs_to) {
                /* New format: determine direction by comparing wallet address */
                const char *from_addr = json_object_get_string(jaddr_from);

                /* Check if we sent this (our address is sender) */
                if (from_addr && strcmp(from_addr, wallet->address) == 0) {
                    strncpy(transactions[count].direction, "sent",
                            sizeof(transactions[count].direction) - 1);

                    /* Find recipient (first non-fee address in addresses_to) */
                    if (json_object_is_type(jaddrs_to, json_type_array)) {
                        int addrs_len = json_object_array_length(jaddrs_to);
                        for (int k = 0; k < addrs_len; k++) {
                            json_object *addr_entry = json_object_array_get_idx(jaddrs_to, k);
                            if (!addr_entry) continue;

                            json_object *jaddr = NULL, *jval = NULL;
                            json_object_object_get_ex(addr_entry, "address", &jaddr);
                            json_object_object_get_ex(addr_entry, "value", &jval);

                            if (jaddr) {
                                const char *addr = json_object_get_string(jaddr);
                                /* Skip fee collector and change addresses (back to sender) */
                                if (addr && strcmp(addr, NETWORK_FEE_COLLECTOR) != 0 &&
                                    strcmp(addr, from_addr) != 0) {
                                    strncpy(transactions[count].other_address, addr,
                                            sizeof(transactions[count].other_address) - 1);
                                    if (jval) {
                                        strncpy(transactions[count].amount, json_object_get_string(jval),
                                                sizeof(transactions[count].amount) - 1);
                                    }
                                    break;  /* Use first valid recipient */
                                }
                            }
                        }
                    }
                } else {
                    /* We received this */
                    strncpy(transactions[count].direction, "received",
                            sizeof(transactions[count].direction) - 1);
                    if (from_addr) {
                        strncpy(transactions[count].other_address, from_addr,
                                sizeof(transactions[count].other_address) - 1);
                    }

                    /* Find amount sent to us */
                    if (json_object_is_type(jaddrs_to, json_type_array)) {
                        int addrs_len = json_object_array_length(jaddrs_to);
                        for (int k = 0; k < addrs_len; k++) {
                            json_object *addr_entry = json_object_array_get_idx(jaddrs_to, k);
                            if (!addr_entry) continue;

                            json_object *jaddr = NULL, *jval = NULL;
                            json_object_object_get_ex(addr_entry, "address", &jaddr);
                            json_object_object_get_ex(addr_entry, "value", &jval);

                            if (jaddr) {
                                const char *addr = json_object_get_string(jaddr);
                                if (addr && strcmp(addr, wallet->address) == 0 && jval) {
                                    strncpy(transactions[count].amount, json_object_get_string(jval),
                                            sizeof(transactions[count].amount) - 1);
                                    break;
                                }
                            }
                        }
                    }
                }
            }

            if (jtoken) {
                strncpy(transactions[count].token, json_object_get_string(jtoken),
                        sizeof(transactions[count].token) - 1);
            }
        }

        count++;
    }

done:
    if (resp) cellframe_rpc_response_free(resp);
    task->callback.transactions(task->request_id, error, transactions, count, task->user_data);
}

/* ============================================================================
 * PUBLIC API FUNCTIONS
 * ============================================================================ */

/* Identity */
dna_request_id_t dna_engine_list_identities(
    dna_engine_t *engine,
    dna_identities_cb callback,
    void *user_data
) {
    if (!engine || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_callback_t cb = { .identities = callback };
    return dna_submit_task(engine, TASK_LIST_IDENTITIES, NULL, cb, user_data);
}

dna_request_id_t dna_engine_create_identity(
    dna_engine_t *engine,
    const uint8_t signing_seed[32],
    const uint8_t encryption_seed[32],
    dna_identity_created_cb callback,
    void *user_data
) {
    if (!engine || !signing_seed || !encryption_seed || !callback) {
        return DNA_REQUEST_ID_INVALID;
    }

    dna_task_params_t params = {0};
    memcpy(params.create_identity.signing_seed, signing_seed, 32);
    memcpy(params.create_identity.encryption_seed, encryption_seed, 32);

    dna_task_callback_t cb = { .identity_created = callback };
    return dna_submit_task(engine, TASK_CREATE_IDENTITY, &params, cb, user_data);
}

int dna_engine_create_identity_sync(
    dna_engine_t *engine,
    const uint8_t signing_seed[32],
    const uint8_t encryption_seed[32],
    char fingerprint_out[129]
) {
    if (!engine || !signing_seed || !encryption_seed || !fingerprint_out) {
        return DNA_ERROR_INVALID_ARG;
    }

    int rc = messenger_generate_keys_from_seeds(signing_seed, encryption_seed, engine->data_dir, fingerprint_out);
    return (rc == 0) ? DNA_OK : DNA_ERROR_CRYPTO;
}

dna_request_id_t dna_engine_load_identity(
    dna_engine_t *engine,
    const char *fingerprint,
    dna_completion_cb callback,
    void *user_data
) {
    if (!engine || !fingerprint || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.load_identity.fingerprint, fingerprint, 128);

    dna_task_callback_t cb = { .completion = callback };
    return dna_submit_task(engine, TASK_LOAD_IDENTITY, &params, cb, user_data);
}

dna_request_id_t dna_engine_register_name(
    dna_engine_t *engine,
    const char *name,
    dna_completion_cb callback,
    void *user_data
) {
    if (!engine || !name || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.register_name.name, name, sizeof(params.register_name.name) - 1);

    dna_task_callback_t cb = { .completion = callback };
    return dna_submit_task(engine, TASK_REGISTER_NAME, &params, cb, user_data);
}

dna_request_id_t dna_engine_get_display_name(
    dna_engine_t *engine,
    const char *fingerprint,
    dna_display_name_cb callback,
    void *user_data
) {
    if (!engine || !fingerprint || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.get_display_name.fingerprint, fingerprint, 128);

    dna_task_callback_t cb = { .display_name = callback };
    return dna_submit_task(engine, TASK_GET_DISPLAY_NAME, &params, cb, user_data);
}

dna_request_id_t dna_engine_lookup_name(
    dna_engine_t *engine,
    const char *name,
    dna_display_name_cb callback,
    void *user_data
) {
    if (!engine || !name || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.lookup_name.name, name, sizeof(params.lookup_name.name) - 1);

    dna_task_callback_t cb = { .display_name = callback };
    return dna_submit_task(engine, TASK_LOOKUP_NAME, &params, cb, user_data);
}

dna_request_id_t dna_engine_get_profile(
    dna_engine_t *engine,
    dna_profile_cb callback,
    void *user_data
) {
    if (!engine || !callback) return DNA_REQUEST_ID_INVALID;
    if (!engine->identity_loaded) return DNA_REQUEST_ID_INVALID;

    dna_task_callback_t cb = { .profile = callback };
    return dna_submit_task(engine, TASK_GET_PROFILE, NULL, cb, user_data);
}

dna_request_id_t dna_engine_update_profile(
    dna_engine_t *engine,
    const dna_profile_t *profile,
    dna_completion_cb callback,
    void *user_data
) {
    if (!engine || !profile || !callback) return DNA_REQUEST_ID_INVALID;
    if (!engine->identity_loaded) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    params.update_profile.profile = *profile;

    dna_task_callback_t cb = { .completion = callback };
    return dna_submit_task(engine, TASK_UPDATE_PROFILE, &params, cb, user_data);
}

/* Contacts */
dna_request_id_t dna_engine_get_contacts(
    dna_engine_t *engine,
    dna_contacts_cb callback,
    void *user_data
) {
    if (!engine || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_callback_t cb = { .contacts = callback };
    return dna_submit_task(engine, TASK_GET_CONTACTS, NULL, cb, user_data);
}

dna_request_id_t dna_engine_add_contact(
    dna_engine_t *engine,
    const char *identifier,
    dna_completion_cb callback,
    void *user_data
) {
    if (!engine || !identifier || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.add_contact.identifier, identifier, sizeof(params.add_contact.identifier) - 1);

    dna_task_callback_t cb = { .completion = callback };
    return dna_submit_task(engine, TASK_ADD_CONTACT, &params, cb, user_data);
}

dna_request_id_t dna_engine_remove_contact(
    dna_engine_t *engine,
    const char *fingerprint,
    dna_completion_cb callback,
    void *user_data
) {
    if (!engine || !fingerprint || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.remove_contact.fingerprint, fingerprint, 128);

    dna_task_callback_t cb = { .completion = callback };
    return dna_submit_task(engine, TASK_REMOVE_CONTACT, &params, cb, user_data);
}

/* Messaging */
dna_request_id_t dna_engine_send_message(
    dna_engine_t *engine,
    const char *recipient_fingerprint,
    const char *message,
    dna_completion_cb callback,
    void *user_data
) {
    if (!engine || !recipient_fingerprint || !message || !callback) {
        return DNA_REQUEST_ID_INVALID;
    }

    dna_task_params_t params = {0};
    strncpy(params.send_message.recipient, recipient_fingerprint, 128);
    params.send_message.message = strdup(message);
    if (!params.send_message.message) {
        return DNA_REQUEST_ID_INVALID;
    }

    dna_task_callback_t cb = { .completion = callback };
    return dna_submit_task(engine, TASK_SEND_MESSAGE, &params, cb, user_data);
}

dna_request_id_t dna_engine_get_conversation(
    dna_engine_t *engine,
    const char *contact_fingerprint,
    dna_messages_cb callback,
    void *user_data
) {
    if (!engine || !contact_fingerprint || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.get_conversation.contact, contact_fingerprint, 128);

    dna_task_callback_t cb = { .messages = callback };
    return dna_submit_task(engine, TASK_GET_CONVERSATION, &params, cb, user_data);
}

dna_request_id_t dna_engine_check_offline_messages(
    dna_engine_t *engine,
    dna_completion_cb callback,
    void *user_data
) {
    if (!engine || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_callback_t cb = { .completion = callback };
    return dna_submit_task(engine, TASK_CHECK_OFFLINE_MESSAGES, NULL, cb, user_data);
}

/* Groups */
dna_request_id_t dna_engine_get_groups(
    dna_engine_t *engine,
    dna_groups_cb callback,
    void *user_data
) {
    if (!engine || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_callback_t cb = { .groups = callback };
    return dna_submit_task(engine, TASK_GET_GROUPS, NULL, cb, user_data);
}

dna_request_id_t dna_engine_create_group(
    dna_engine_t *engine,
    const char *name,
    const char **member_fingerprints,
    int member_count,
    dna_group_created_cb callback,
    void *user_data
) {
    if (!engine || !name || !callback) return DNA_REQUEST_ID_INVALID;
    if (member_count > 0 && !member_fingerprints) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.create_group.name, name, sizeof(params.create_group.name) - 1);
    params.create_group.member_count = member_count;

    if (member_count > 0) {
        params.create_group.members = calloc(member_count, sizeof(char*));
        if (!params.create_group.members) {
            return DNA_REQUEST_ID_INVALID;
        }
        for (int i = 0; i < member_count; i++) {
            params.create_group.members[i] = strdup(member_fingerprints[i]);
            if (!params.create_group.members[i]) {
                for (int j = 0; j < i; j++) {
                    free(params.create_group.members[j]);
                }
                free(params.create_group.members);
                return DNA_REQUEST_ID_INVALID;
            }
        }
    }

    dna_task_callback_t cb = { .group_created = callback };
    return dna_submit_task(engine, TASK_CREATE_GROUP, &params, cb, user_data);
}

dna_request_id_t dna_engine_send_group_message(
    dna_engine_t *engine,
    const char *group_uuid,
    const char *message,
    dna_completion_cb callback,
    void *user_data
) {
    if (!engine || !group_uuid || !message || !callback) {
        return DNA_REQUEST_ID_INVALID;
    }

    dna_task_params_t params = {0};
    strncpy(params.send_group_message.group_uuid, group_uuid, 36);
    params.send_group_message.message = strdup(message);
    if (!params.send_group_message.message) {
        return DNA_REQUEST_ID_INVALID;
    }

    dna_task_callback_t cb = { .completion = callback };
    return dna_submit_task(engine, TASK_SEND_GROUP_MESSAGE, &params, cb, user_data);
}

dna_request_id_t dna_engine_get_invitations(
    dna_engine_t *engine,
    dna_invitations_cb callback,
    void *user_data
) {
    if (!engine || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_callback_t cb = { .invitations = callback };
    return dna_submit_task(engine, TASK_GET_INVITATIONS, NULL, cb, user_data);
}

dna_request_id_t dna_engine_accept_invitation(
    dna_engine_t *engine,
    const char *group_uuid,
    dna_completion_cb callback,
    void *user_data
) {
    if (!engine || !group_uuid || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.invitation.group_uuid, group_uuid, 36);

    dna_task_callback_t cb = { .completion = callback };
    return dna_submit_task(engine, TASK_ACCEPT_INVITATION, &params, cb, user_data);
}

dna_request_id_t dna_engine_reject_invitation(
    dna_engine_t *engine,
    const char *group_uuid,
    dna_completion_cb callback,
    void *user_data
) {
    if (!engine || !group_uuid || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.invitation.group_uuid, group_uuid, 36);

    dna_task_callback_t cb = { .completion = callback };
    return dna_submit_task(engine, TASK_REJECT_INVITATION, &params, cb, user_data);
}

/* Wallet */
dna_request_id_t dna_engine_list_wallets(
    dna_engine_t *engine,
    dna_wallets_cb callback,
    void *user_data
) {
    if (!engine || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_callback_t cb = { .wallets = callback };
    return dna_submit_task(engine, TASK_LIST_WALLETS, NULL, cb, user_data);
}

dna_request_id_t dna_engine_get_balances(
    dna_engine_t *engine,
    int wallet_index,
    dna_balances_cb callback,
    void *user_data
) {
    if (!engine || !callback || wallet_index < 0) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    params.get_balances.wallet_index = wallet_index;

    dna_task_callback_t cb = { .balances = callback };
    return dna_submit_task(engine, TASK_GET_BALANCES, &params, cb, user_data);
}

dna_request_id_t dna_engine_send_tokens(
    dna_engine_t *engine,
    int wallet_index,
    const char *recipient_address,
    const char *amount,
    const char *token,
    const char *network,
    dna_completion_cb callback,
    void *user_data
) {
    if (!engine || !recipient_address || !amount || !token || !network || !callback) {
        return DNA_REQUEST_ID_INVALID;
    }
    if (wallet_index < 0) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    params.send_tokens.wallet_index = wallet_index;
    strncpy(params.send_tokens.recipient, recipient_address, sizeof(params.send_tokens.recipient) - 1);
    strncpy(params.send_tokens.amount, amount, sizeof(params.send_tokens.amount) - 1);
    strncpy(params.send_tokens.token, token, sizeof(params.send_tokens.token) - 1);
    strncpy(params.send_tokens.network, network, sizeof(params.send_tokens.network) - 1);

    dna_task_callback_t cb = { .completion = callback };
    return dna_submit_task(engine, TASK_SEND_TOKENS, &params, cb, user_data);
}

dna_request_id_t dna_engine_get_transactions(
    dna_engine_t *engine,
    int wallet_index,
    const char *network,
    dna_transactions_cb callback,
    void *user_data
) {
    if (!engine || !network || !callback || wallet_index < 0) {
        return DNA_REQUEST_ID_INVALID;
    }

    dna_task_params_t params = {0};
    params.get_transactions.wallet_index = wallet_index;
    strncpy(params.get_transactions.network, network, sizeof(params.get_transactions.network) - 1);

    dna_task_callback_t cb = { .transactions = callback };
    return dna_submit_task(engine, TASK_GET_TRANSACTIONS, &params, cb, user_data);
}

/* ============================================================================
 * P2P & PRESENCE PUBLIC API
 * ============================================================================ */

dna_request_id_t dna_engine_refresh_presence(
    dna_engine_t *engine,
    dna_completion_cb callback,
    void *user_data
) {
    if (!engine || !callback) {
        return DNA_REQUEST_ID_INVALID;
    }

    dna_task_callback_t cb = { .completion = callback };
    return dna_submit_task(engine, TASK_REFRESH_PRESENCE, NULL, cb, user_data);
}

bool dna_engine_is_peer_online(dna_engine_t *engine, const char *fingerprint) {
    if (!engine || !fingerprint || !engine->messenger) {
        return false;
    }

    return messenger_p2p_peer_online(engine->messenger, fingerprint);
}

dna_request_id_t dna_engine_lookup_presence(
    dna_engine_t *engine,
    const char *fingerprint,
    dna_presence_cb callback,
    void *user_data
) {
    if (!engine || !fingerprint || !callback) {
        return DNA_REQUEST_ID_INVALID;
    }

    dna_task_params_t params;
    memset(&params, 0, sizeof(params));
    snprintf(params.lookup_presence.fingerprint, sizeof(params.lookup_presence.fingerprint),
             "%s", fingerprint);

    dna_task_callback_t cb = { .presence = callback };
    return dna_submit_task(engine, TASK_LOOKUP_PRESENCE, &params, cb, user_data);
}

dna_request_id_t dna_engine_sync_contacts_to_dht(
    dna_engine_t *engine,
    dna_completion_cb callback,
    void *user_data
) {
    if (!engine || !callback) {
        return DNA_REQUEST_ID_INVALID;
    }

    dna_task_callback_t cb = { .completion = callback };
    return dna_submit_task(engine, TASK_SYNC_CONTACTS_TO_DHT, NULL, cb, user_data);
}

dna_request_id_t dna_engine_sync_contacts_from_dht(
    dna_engine_t *engine,
    dna_completion_cb callback,
    void *user_data
) {
    if (!engine || !callback) {
        return DNA_REQUEST_ID_INVALID;
    }

    dna_task_callback_t cb = { .completion = callback };
    return dna_submit_task(engine, TASK_SYNC_CONTACTS_FROM_DHT, NULL, cb, user_data);
}

dna_request_id_t dna_engine_sync_groups(
    dna_engine_t *engine,
    dna_completion_cb callback,
    void *user_data
) {
    if (!engine || !callback) {
        return DNA_REQUEST_ID_INVALID;
    }

    dna_task_callback_t cb = { .completion = callback };
    return dna_submit_task(engine, TASK_SYNC_GROUPS, NULL, cb, user_data);
}

dna_request_id_t dna_engine_subscribe_to_contacts(
    dna_engine_t *engine,
    dna_completion_cb callback,
    void *user_data
) {
    if (!engine || !callback) {
        return DNA_REQUEST_ID_INVALID;
    }

    dna_task_callback_t cb = { .completion = callback };
    return dna_submit_task(engine, TASK_SUBSCRIBE_TO_CONTACTS, NULL, cb, user_data);
}

dna_request_id_t dna_engine_get_registered_name(
    dna_engine_t *engine,
    dna_display_name_cb callback,
    void *user_data
) {
    if (!engine || !callback) {
        return DNA_REQUEST_ID_INVALID;
    }

    dna_task_callback_t cb = { .display_name = callback };
    return dna_submit_task(engine, TASK_GET_REGISTERED_NAME, NULL, cb, user_data);
}

/* ============================================================================
 * P2P & PRESENCE HANDLERS
 * ============================================================================ */

void dna_handle_refresh_presence(dna_engine_t *engine, dna_task_t *task) {
    if (task->cancelled) return;

    int error = DNA_OK;

    if (!engine->messenger) {
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
    } else {
        if (messenger_p2p_refresh_presence(engine->messenger) != 0) {
            error = DNA_ENGINE_ERROR_NETWORK;
        }
    }

    if (task->callback.completion) {
        task->callback.completion(task->request_id, error, task->user_data);
    }
}

void dna_handle_lookup_presence(dna_engine_t *engine, dna_task_t *task) {
    if (task->cancelled) return;

    int error = DNA_OK;
    uint64_t last_seen = 0;

    if (!engine->messenger) {
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
    } else {
        if (messenger_p2p_lookup_presence(engine->messenger,
                task->params.lookup_presence.fingerprint,
                &last_seen) != 0) {
            /* Not found is not an error - just return 0 timestamp */
            last_seen = 0;
        }
    }

    if (task->callback.presence) {
        task->callback.presence(task->request_id, error, last_seen, task->user_data);
    }
}

void dna_handle_sync_contacts_to_dht(dna_engine_t *engine, dna_task_t *task) {
    if (task->cancelled) return;

    int error = DNA_OK;

    if (!engine->messenger) {
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
    } else {
        if (messenger_sync_contacts_to_dht(engine->messenger) != 0) {
            error = DNA_ENGINE_ERROR_NETWORK;
        }
    }

    if (task->callback.completion) {
        task->callback.completion(task->request_id, error, task->user_data);
    }
}

void dna_handle_sync_contacts_from_dht(dna_engine_t *engine, dna_task_t *task) {
    if (task->cancelled) return;

    int error = DNA_OK;

    if (!engine->messenger) {
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
    } else {
        if (messenger_sync_contacts_from_dht(engine->messenger) != 0) {
            error = DNA_ENGINE_ERROR_NETWORK;
        }
    }

    if (task->callback.completion) {
        task->callback.completion(task->request_id, error, task->user_data);
    }
}

void dna_handle_sync_groups(dna_engine_t *engine, dna_task_t *task) {
    if (task->cancelled) return;

    int error = DNA_OK;

    if (!engine->messenger) {
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
    } else {
        if (messenger_sync_groups(engine->messenger) != 0) {
            error = DNA_ENGINE_ERROR_NETWORK;
        }
    }

    if (task->callback.completion) {
        task->callback.completion(task->request_id, error, task->user_data);
    }
}

void dna_handle_subscribe_to_contacts(dna_engine_t *engine, dna_task_t *task) {
    if (task->cancelled) return;

    int error = DNA_OK;

    if (!engine->messenger) {
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
    } else {
        if (messenger_p2p_subscribe_to_contacts(engine->messenger) != 0) {
            error = DNA_ENGINE_ERROR_NETWORK;
        }
    }

    if (task->callback.completion) {
        task->callback.completion(task->request_id, error, task->user_data);
    }
}

void dna_handle_get_registered_name(dna_engine_t *engine, dna_task_t *task) {
    if (task->cancelled) return;

    int error = DNA_OK;
    char *name = NULL;

    if (!engine->messenger || !engine->identity_loaded) {
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
    } else {
        dht_context_t *dht_ctx = dht_singleton_get();
        if (dht_ctx) {
            char *registered_name = NULL;
            int ret = dht_keyserver_reverse_lookup(dht_ctx, engine->fingerprint, &registered_name);
            if (ret == 0 && registered_name) {
                name = registered_name; /* Transfer ownership */
            }
            /* Not found is not an error - just returns NULL name */
        }
    }

    if (task->callback.display_name) {
        /* Caller frees via dna_free_string - don't free here due to async callback */
        task->callback.display_name(task->request_id, error, name, task->user_data);
    }
}

/* ============================================================================
 * BACKWARD COMPATIBILITY
 * ============================================================================ */

void* dna_engine_get_messenger_context(dna_engine_t *engine) {
    if (!engine) return NULL;
    return engine->messenger;
}

void* dna_engine_get_dht_context(dna_engine_t *engine) {
    (void)engine; /* DHT is global singleton */
    return dht_singleton_get();
}

/* ============================================================================
 * MEMORY MANAGEMENT
 * ============================================================================ */

void dna_free_strings(char **strings, int count) {
    if (!strings) return;
    for (int i = 0; i < count; i++) {
        free(strings[i]);
    }
    free(strings);
}

void dna_free_contacts(dna_contact_t *contacts, int count) {
    (void)count;
    free(contacts);
}

void dna_free_messages(dna_message_t *messages, int count) {
    if (!messages) return;
    for (int i = 0; i < count; i++) {
        free(messages[i].plaintext);
    }
    free(messages);
}

void dna_free_groups(dna_group_t *groups, int count) {
    (void)count;
    free(groups);
}

void dna_free_invitations(dna_invitation_t *invitations, int count) {
    (void)count;
    free(invitations);
}

void dna_free_wallets(dna_wallet_t *wallets, int count) {
    (void)count;
    free(wallets);
}

void dna_free_balances(dna_balance_t *balances, int count) {
    (void)count;
    free(balances);
}

void dna_free_transactions(dna_transaction_t *transactions, int count) {
    (void)count;
    free(transactions);
}

void dna_free_feed_channels(dna_channel_info_t *channels, int count) {
    (void)count;
    free(channels);
}

void dna_free_feed_posts(dna_post_info_t *posts, int count) {
    if (!posts) return;
    for (int i = 0; i < count; i++) {
        free(posts[i].text);
    }
    free(posts);
}

void dna_free_feed_post(dna_post_info_t *post) {
    if (!post) return;
    free(post->text);
    free(post);
}

void dna_free_feed_comments(dna_comment_info_t *comments, int count) {
    if (!comments) return;
    for (int i = 0; i < count; i++) {
        free(comments[i].text);
    }
    free(comments);
}

void dna_free_feed_comment(dna_comment_info_t *comment) {
    if (!comment) return;
    free(comment->text);
    free(comment);
}

void dna_free_profile(dna_profile_t *profile) {
    if (!profile) return;
    free(profile);
}

/* ============================================================================
 * FEED HANDLERS
 * ============================================================================ */

/* Helper: Get DHT context from engine */
static dht_context_t* dna_get_dht_ctx(dna_engine_t *engine) {
    if (!engine || !engine->messenger || !engine->messenger->p2p_transport) {
        return NULL;
    }
    return p2p_transport_get_dht_context(engine->messenger->p2p_transport);
}

/* Helper: Get private key for signing (caller frees with qgp_key_free) */
static qgp_key_t* dna_load_private_key(dna_engine_t *engine) {
    if (!engine || !engine->identity_loaded) {
        return NULL;
    }

    char key_path[512];
    snprintf(key_path, sizeof(key_path), "%s/%s.dsa",
             engine->data_dir, engine->fingerprint);

    qgp_key_t *key = NULL;
    if (qgp_key_load(key_path, &key) != 0 || !key) {
        return NULL;
    }
    return key;
}

void dna_handle_get_feed_channels(dna_engine_t *engine, dna_task_t *task) {
    dht_context_t *dht = dna_get_dht_ctx(engine);
    if (!dht) {
        task->callback.feed_channels(task->request_id, DNA_ENGINE_ERROR_NETWORK,
                                     NULL, 0, task->user_data);
        return;
    }

    dna_feed_registry_t *registry = NULL;
    int ret = dna_feed_registry_get(dht, &registry);

    if (ret == 0 && registry && registry->channel_count > 0) {
        /* Convert to engine format */
        dna_channel_info_t *channels = calloc(registry->channel_count, sizeof(dna_channel_info_t));
        if (channels) {
            for (size_t i = 0; i < registry->channel_count; i++) {
                strncpy(channels[i].channel_id, registry->channels[i].channel_id, 64);
                strncpy(channels[i].name, registry->channels[i].name, 63);
                strncpy(channels[i].description, registry->channels[i].description, 511);
                strncpy(channels[i].creator_fingerprint, registry->channels[i].creator_fingerprint, 128);
                channels[i].created_at = registry->channels[i].created_at;
                channels[i].subscriber_count = registry->channels[i].subscriber_count;
                channels[i].last_activity = registry->channels[i].last_activity;

                /* Count posts from last 7 days */
                int post_count = 0;
                time_t now = time(NULL);
                for (int day = 0; day < 7; day++) {
                    time_t t = now - (day * 86400);
                    struct tm *tm = gmtime(&t);
                    char date[12];
                    snprintf(date, sizeof(date), "%04d%02d%02d",
                             tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday);

                    dna_feed_post_t *posts = NULL;
                    size_t count = 0;
                    if (dna_feed_posts_get_by_channel(dht, channels[i].channel_id, date, &posts, &count) == 0) {
                        post_count += (int)count;
                        free(posts);
                    }
                }
                channels[i].post_count = post_count;
            }
            task->callback.feed_channels(task->request_id, DNA_OK,
                                         channels, (int)registry->channel_count, task->user_data);
        } else {
            task->callback.feed_channels(task->request_id, DNA_ERROR_INTERNAL,
                                         NULL, 0, task->user_data);
        }
        dna_feed_registry_free(registry);
    } else if (ret == -2) {
        /* No registry - return empty */
        task->callback.feed_channels(task->request_id, DNA_OK, NULL, 0, task->user_data);
    } else {
        task->callback.feed_channels(task->request_id, DNA_ERROR_INTERNAL,
                                     NULL, 0, task->user_data);
        if (registry) dna_feed_registry_free(registry);
    }
}

void dna_handle_create_feed_channel(dna_engine_t *engine, dna_task_t *task) {
    dht_context_t *dht = dna_get_dht_ctx(engine);
    qgp_key_t *key = dna_load_private_key(engine);

    if (!dht || !key) {
        if (key) qgp_key_free(key);
        task->callback.feed_channel(task->request_id, DNA_ENGINE_ERROR_NO_IDENTITY,
                                    NULL, task->user_data);
        return;
    }

    dna_feed_channel_t *new_channel = NULL;
    int ret = dna_feed_channel_create(dht,
                                       task->params.create_feed_channel.name,
                                       task->params.create_feed_channel.description,
                                       engine->fingerprint,
                                       key->private_key,
                                       &new_channel);
    qgp_key_free(key);

    if (ret == 0 && new_channel) {
        dna_channel_info_t *channel = calloc(1, sizeof(dna_channel_info_t));
        if (channel) {
            strncpy(channel->channel_id, new_channel->channel_id, 64);
            strncpy(channel->name, new_channel->name, 63);
            strncpy(channel->description, new_channel->description, 511);
            strncpy(channel->creator_fingerprint, new_channel->creator_fingerprint, 128);
            channel->created_at = new_channel->created_at;
            channel->subscriber_count = 1;
            channel->last_activity = new_channel->created_at;
        }
        dna_feed_channel_free(new_channel);
        task->callback.feed_channel(task->request_id, DNA_OK, channel, task->user_data);
    } else if (ret == -2) {
        task->callback.feed_channel(task->request_id, DNA_ENGINE_ERROR_ALREADY_EXISTS,
                                    NULL, task->user_data);
    } else {
        task->callback.feed_channel(task->request_id, DNA_ERROR_INTERNAL,
                                    NULL, task->user_data);
    }
}

void dna_handle_init_default_channels(dna_engine_t *engine, dna_task_t *task) {
    dht_context_t *dht = dna_get_dht_ctx(engine);
    qgp_key_t *key = dna_load_private_key(engine);

    if (!dht || !key) {
        if (key) qgp_key_free(key);
        task->callback.completion(task->request_id, DNA_ENGINE_ERROR_NO_IDENTITY, task->user_data);
        return;
    }

    int created = dna_feed_init_default_channels(dht, engine->fingerprint, key->private_key);
    qgp_key_free(key);

    task->callback.completion(task->request_id, created >= 0 ? DNA_OK : DNA_ERROR_INTERNAL,
                              task->user_data);
}

void dna_handle_get_feed_posts(dna_engine_t *engine, dna_task_t *task) {
    dht_context_t *dht = dna_get_dht_ctx(engine);
    if (!dht) {
        task->callback.feed_posts(task->request_id, DNA_ENGINE_ERROR_NETWORK,
                                  NULL, 0, task->user_data);
        return;
    }

    const char *date = task->params.get_feed_posts.date[0] ? task->params.get_feed_posts.date : NULL;

    dna_feed_post_t *posts = NULL;
    size_t count = 0;
    int ret = dna_feed_posts_get_by_channel(dht, task->params.get_feed_posts.channel_id,
                                            date, &posts, &count);

    if (ret == 0 && posts && count > 0) {
        /* Convert to engine format */
        dna_post_info_t *out_posts = calloc(count, sizeof(dna_post_info_t));
        if (out_posts) {
            for (size_t i = 0; i < count; i++) {
                strncpy(out_posts[i].post_id, posts[i].post_id, 199);
                strncpy(out_posts[i].channel_id, posts[i].channel_id, 64);
                strncpy(out_posts[i].author_fingerprint, posts[i].author_fingerprint, 128);
                out_posts[i].text = strdup(posts[i].text);
                out_posts[i].timestamp = posts[i].timestamp;
                out_posts[i].updated = posts[i].updated;

                /* Fetch actual comment count from DHT */
                dna_feed_comment_t *comments = NULL;
                size_t comment_count = 0;
                if (dna_feed_comments_get(dht, posts[i].post_id, &comments, &comment_count) == 0) {
                    out_posts[i].comment_count = (int)comment_count;
                    dna_feed_comments_free(comments, comment_count);
                } else {
                    out_posts[i].comment_count = 0;
                }

                out_posts[i].upvotes = posts[i].upvotes;
                out_posts[i].downvotes = posts[i].downvotes;
                out_posts[i].user_vote = posts[i].user_vote;
                out_posts[i].verified = (posts[i].signature_len > 0);
            }
            task->callback.feed_posts(task->request_id, DNA_OK,
                                      out_posts, (int)count, task->user_data);
        } else {
            task->callback.feed_posts(task->request_id, DNA_ERROR_INTERNAL,
                                      NULL, 0, task->user_data);
        }
        free(posts);
    } else if (ret == -2) {
        /* No posts - return empty */
        task->callback.feed_posts(task->request_id, DNA_OK, NULL, 0, task->user_data);
    } else {
        task->callback.feed_posts(task->request_id, DNA_ERROR_INTERNAL,
                                  NULL, 0, task->user_data);
        if (posts) free(posts);
    }
}

void dna_handle_create_feed_post(dna_engine_t *engine, dna_task_t *task) {
    dht_context_t *dht = dna_get_dht_ctx(engine);
    qgp_key_t *key = dna_load_private_key(engine);

    if (!dht || !key) {
        if (key) qgp_key_free(key);
        task->callback.feed_post(task->request_id, DNA_ENGINE_ERROR_NO_IDENTITY,
                                 NULL, task->user_data);
        return;
    }

    dna_feed_post_t *new_post = NULL;
    int ret = dna_feed_post_create(dht,
                                    task->params.create_feed_post.channel_id,
                                    engine->fingerprint,
                                    task->params.create_feed_post.text,
                                    key->private_key,
                                    &new_post);
    qgp_key_free(key);

    if (ret == 0 && new_post) {
        dna_post_info_t *post = calloc(1, sizeof(dna_post_info_t));
        if (post) {
            strncpy(post->post_id, new_post->post_id, 199);
            strncpy(post->channel_id, new_post->channel_id, 64);
            strncpy(post->author_fingerprint, new_post->author_fingerprint, 128);
            post->text = strdup(new_post->text);
            post->timestamp = new_post->timestamp;
            post->updated = new_post->updated;
            post->comment_count = new_post->comment_count;
            post->upvotes = 0;
            post->downvotes = 0;
            post->user_vote = 0;
            post->verified = true;
        }
        dna_feed_post_free(new_post);
        task->callback.feed_post(task->request_id, DNA_OK, post, task->user_data);
    } else {
        task->callback.feed_post(task->request_id, DNA_ERROR_INTERNAL,
                                 NULL, task->user_data);
    }
}

void dna_handle_add_feed_comment(dna_engine_t *engine, dna_task_t *task) {
    dht_context_t *dht = dna_get_dht_ctx(engine);
    qgp_key_t *key = dna_load_private_key(engine);

    if (!dht || !key) {
        if (key) qgp_key_free(key);
        task->callback.feed_comment(task->request_id, DNA_ENGINE_ERROR_NO_IDENTITY,
                                    NULL, task->user_data);
        return;
    }

    dna_feed_comment_t *new_comment = NULL;
    int ret = dna_feed_comment_add(dht,
                                    task->params.add_feed_comment.post_id,
                                    engine->fingerprint,
                                    task->params.add_feed_comment.text,
                                    key->private_key,
                                    &new_comment);
    qgp_key_free(key);

    if (ret == 0 && new_comment) {
        dna_comment_info_t *comment = calloc(1, sizeof(dna_comment_info_t));
        if (comment) {
            strncpy(comment->comment_id, new_comment->comment_id, 199);
            strncpy(comment->post_id, new_comment->post_id, 199);
            strncpy(comment->author_fingerprint, new_comment->author_fingerprint, 128);
            comment->text = strdup(new_comment->text);
            comment->timestamp = new_comment->timestamp;
            comment->upvotes = 0;
            comment->downvotes = 0;
            comment->user_vote = 0;
            comment->verified = true;
        }
        dna_feed_comment_free(new_comment);
        task->callback.feed_comment(task->request_id, DNA_OK, comment, task->user_data);
    } else {
        task->callback.feed_comment(task->request_id, DNA_ERROR_INTERNAL,
                                    NULL, task->user_data);
    }
}

void dna_handle_get_feed_comments(dna_engine_t *engine, dna_task_t *task) {
    dht_context_t *dht = dna_get_dht_ctx(engine);
    if (!dht) {
        task->callback.feed_comments(task->request_id, DNA_ENGINE_ERROR_NETWORK,
                                     NULL, 0, task->user_data);
        return;
    }

    dna_feed_comment_t *comments = NULL;
    size_t count = 0;
    int ret = dna_feed_comments_get(dht, task->params.get_feed_comments.post_id,
                                     &comments, &count);

    if (ret == 0 && comments && count > 0) {
        dna_comment_info_t *out_comments = calloc(count, sizeof(dna_comment_info_t));
        if (out_comments) {
            for (size_t i = 0; i < count; i++) {
                strncpy(out_comments[i].comment_id, comments[i].comment_id, 199);
                strncpy(out_comments[i].post_id, comments[i].post_id, 199);
                strncpy(out_comments[i].author_fingerprint, comments[i].author_fingerprint, 128);
                out_comments[i].text = strdup(comments[i].text);
                out_comments[i].timestamp = comments[i].timestamp;
                out_comments[i].upvotes = comments[i].upvotes;
                out_comments[i].downvotes = comments[i].downvotes;
                out_comments[i].user_vote = comments[i].user_vote;
                out_comments[i].verified = (comments[i].signature_len > 0);
            }
            task->callback.feed_comments(task->request_id, DNA_OK,
                                         out_comments, (int)count, task->user_data);
        } else {
            task->callback.feed_comments(task->request_id, DNA_ERROR_INTERNAL,
                                         NULL, 0, task->user_data);
        }
        dna_feed_comments_free(comments, count);
    } else {
        task->callback.feed_comments(task->request_id, DNA_OK, NULL, 0, task->user_data);
        if (comments) dna_feed_comments_free(comments, count);
    }
}

void dna_handle_cast_feed_vote(dna_engine_t *engine, dna_task_t *task) {
    dht_context_t *dht = dna_get_dht_ctx(engine);
    qgp_key_t *key = dna_load_private_key(engine);

    if (!dht || !key) {
        if (key) qgp_key_free(key);
        task->callback.completion(task->request_id, DNA_ENGINE_ERROR_NO_IDENTITY, task->user_data);
        return;
    }

    int ret = dna_feed_vote_cast(dht,
                                  task->params.cast_feed_vote.post_id,
                                  engine->fingerprint,
                                  task->params.cast_feed_vote.vote_value,
                                  key->private_key);
    qgp_key_free(key);

    if (ret == 0) {
        task->callback.completion(task->request_id, DNA_OK, task->user_data);
    } else if (ret == -2) {
        task->callback.completion(task->request_id, DNA_ENGINE_ERROR_ALREADY_EXISTS, task->user_data);
    } else {
        task->callback.completion(task->request_id, DNA_ERROR_INTERNAL, task->user_data);
    }
}

void dna_handle_get_feed_votes(dna_engine_t *engine, dna_task_t *task) {
    dht_context_t *dht = dna_get_dht_ctx(engine);
    if (!dht) {
        task->callback.feed_post(task->request_id, DNA_ENGINE_ERROR_NETWORK,
                                 NULL, task->user_data);
        return;
    }

    dna_feed_votes_t *votes = NULL;
    int ret = dna_feed_votes_get(dht, task->params.get_feed_votes.post_id, &votes);

    dna_post_info_t *post = calloc(1, sizeof(dna_post_info_t));
    if (post) {
        strncpy(post->post_id, task->params.get_feed_votes.post_id, 199);
        if (ret == 0 && votes) {
            post->upvotes = votes->upvote_count;
            post->downvotes = votes->downvote_count;
            post->user_vote = engine->identity_loaded ?
                              dna_feed_get_user_vote(votes, engine->fingerprint) : 0;
            dna_feed_votes_free(votes);
        }
        task->callback.feed_post(task->request_id, DNA_OK, post, task->user_data);
    } else {
        if (votes) dna_feed_votes_free(votes);
        task->callback.feed_post(task->request_id, DNA_ERROR_INTERNAL, NULL, task->user_data);
    }
}

void dna_handle_cast_comment_vote(dna_engine_t *engine, dna_task_t *task) {
    dht_context_t *dht = dna_get_dht_ctx(engine);
    qgp_key_t *key = dna_load_private_key(engine);

    if (!dht || !key) {
        if (key) qgp_key_free(key);
        task->callback.completion(task->request_id, DNA_ENGINE_ERROR_NO_IDENTITY, task->user_data);
        return;
    }

    int ret = dna_feed_comment_vote_cast(dht,
                                          task->params.cast_comment_vote.comment_id,
                                          engine->fingerprint,
                                          task->params.cast_comment_vote.vote_value,
                                          key->private_key);
    qgp_key_free(key);

    if (ret == 0) {
        task->callback.completion(task->request_id, DNA_OK, task->user_data);
    } else if (ret == -2) {
        task->callback.completion(task->request_id, DNA_ENGINE_ERROR_ALREADY_EXISTS, task->user_data);
    } else {
        task->callback.completion(task->request_id, DNA_ERROR_INTERNAL, task->user_data);
    }
}

void dna_handle_get_comment_votes(dna_engine_t *engine, dna_task_t *task) {
    dht_context_t *dht = dna_get_dht_ctx(engine);
    if (!dht) {
        task->callback.feed_comment(task->request_id, DNA_ENGINE_ERROR_NETWORK,
                                    NULL, task->user_data);
        return;
    }

    dna_feed_votes_t *votes = NULL;
    int ret = dna_feed_comment_votes_get(dht, task->params.get_comment_votes.comment_id, &votes);

    dna_comment_info_t *comment = calloc(1, sizeof(dna_comment_info_t));
    if (comment) {
        strncpy(comment->comment_id, task->params.get_comment_votes.comment_id, 199);
        if (ret == 0 && votes) {
            comment->upvotes = votes->upvote_count;
            comment->downvotes = votes->downvote_count;
            comment->user_vote = engine->identity_loaded ?
                                 dna_feed_get_user_vote(votes, engine->fingerprint) : 0;
            dna_feed_votes_free(votes);
        }
        task->callback.feed_comment(task->request_id, DNA_OK, comment, task->user_data);
    } else {
        if (votes) dna_feed_votes_free(votes);
        task->callback.feed_comment(task->request_id, DNA_ERROR_INTERNAL, NULL, task->user_data);
    }
}

/* ============================================================================
 * FEED PUBLIC API
 * ============================================================================ */

dna_request_id_t dna_engine_get_feed_channels(
    dna_engine_t *engine,
    dna_feed_channels_cb callback,
    void *user_data
) {
    if (!engine || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_callback_t cb = {0};
    cb.feed_channels = callback;
    return dna_submit_task(engine, TASK_GET_FEED_CHANNELS, NULL, cb, user_data);
}

dna_request_id_t dna_engine_create_feed_channel(
    dna_engine_t *engine,
    const char *name,
    const char *description,
    dna_feed_channel_cb callback,
    void *user_data
) {
    if (!engine || !name || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.create_feed_channel.name, name, 63);
    if (description) {
        strncpy(params.create_feed_channel.description, description, 511);
    }

    dna_task_callback_t cb = {0};
    cb.feed_channel = callback;
    return dna_submit_task(engine, TASK_CREATE_FEED_CHANNEL, &params, cb, user_data);
}

dna_request_id_t dna_engine_init_default_channels(
    dna_engine_t *engine,
    dna_completion_cb callback,
    void *user_data
) {
    if (!engine || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_callback_t cb = {0};
    cb.completion = callback;
    return dna_submit_task(engine, TASK_INIT_DEFAULT_CHANNELS, NULL, cb, user_data);
}

dna_request_id_t dna_engine_get_feed_posts(
    dna_engine_t *engine,
    const char *channel_id,
    const char *date,
    dna_feed_posts_cb callback,
    void *user_data
) {
    if (!engine || !channel_id || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.get_feed_posts.channel_id, channel_id, 64);
    if (date) {
        strncpy(params.get_feed_posts.date, date, 11);
    }

    dna_task_callback_t cb = {0};
    cb.feed_posts = callback;
    return dna_submit_task(engine, TASK_GET_FEED_POSTS, &params, cb, user_data);
}

dna_request_id_t dna_engine_create_feed_post(
    dna_engine_t *engine,
    const char *channel_id,
    const char *text,
    dna_feed_post_cb callback,
    void *user_data
) {
    if (!engine || !channel_id || !text || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.create_feed_post.channel_id, channel_id, 64);
    params.create_feed_post.text = strdup(text);
    if (!params.create_feed_post.text) return DNA_REQUEST_ID_INVALID;

    dna_task_callback_t cb = {0};
    cb.feed_post = callback;
    return dna_submit_task(engine, TASK_CREATE_FEED_POST, &params, cb, user_data);
}

dna_request_id_t dna_engine_add_feed_comment(
    dna_engine_t *engine,
    const char *post_id,
    const char *text,
    dna_feed_comment_cb callback,
    void *user_data
) {
    if (!engine || !post_id || !text || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.add_feed_comment.post_id, post_id, 199);
    params.add_feed_comment.text = strdup(text);
    if (!params.add_feed_comment.text) return DNA_REQUEST_ID_INVALID;

    dna_task_callback_t cb = {0};
    cb.feed_comment = callback;
    return dna_submit_task(engine, TASK_ADD_FEED_COMMENT, &params, cb, user_data);
}

dna_request_id_t dna_engine_get_feed_comments(
    dna_engine_t *engine,
    const char *post_id,
    dna_feed_comments_cb callback,
    void *user_data
) {
    if (!engine || !post_id || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.get_feed_comments.post_id, post_id, 199);

    dna_task_callback_t cb = {0};
    cb.feed_comments = callback;
    return dna_submit_task(engine, TASK_GET_FEED_COMMENTS, &params, cb, user_data);
}

dna_request_id_t dna_engine_cast_feed_vote(
    dna_engine_t *engine,
    const char *post_id,
    int8_t vote_value,
    dna_completion_cb callback,
    void *user_data
) {
    if (!engine || !post_id || !callback) return DNA_REQUEST_ID_INVALID;
    if (vote_value != 1 && vote_value != -1) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.cast_feed_vote.post_id, post_id, 199);
    params.cast_feed_vote.vote_value = vote_value;

    dna_task_callback_t cb = {0};
    cb.completion = callback;
    return dna_submit_task(engine, TASK_CAST_FEED_VOTE, &params, cb, user_data);
}

dna_request_id_t dna_engine_get_feed_votes(
    dna_engine_t *engine,
    const char *post_id,
    dna_feed_post_cb callback,
    void *user_data
) {
    if (!engine || !post_id || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.get_feed_votes.post_id, post_id, 199);

    dna_task_callback_t cb = {0};
    cb.feed_post = callback;
    return dna_submit_task(engine, TASK_GET_FEED_VOTES, &params, cb, user_data);
}

dna_request_id_t dna_engine_cast_comment_vote(
    dna_engine_t *engine,
    const char *comment_id,
    int8_t vote_value,
    dna_completion_cb callback,
    void *user_data
) {
    if (!engine || !comment_id || !callback) return DNA_REQUEST_ID_INVALID;
    if (vote_value != 1 && vote_value != -1) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.cast_comment_vote.comment_id, comment_id, 199);
    params.cast_comment_vote.vote_value = vote_value;

    dna_task_callback_t cb = {0};
    cb.completion = callback;
    return dna_submit_task(engine, TASK_CAST_COMMENT_VOTE, &params, cb, user_data);
}

dna_request_id_t dna_engine_get_comment_votes(
    dna_engine_t *engine,
    const char *comment_id,
    dna_feed_comment_cb callback,
    void *user_data
) {
    if (!engine || !comment_id || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.get_comment_votes.comment_id, comment_id, 199);

    dna_task_callback_t cb = {0};
    cb.feed_comment = callback;
    return dna_submit_task(engine, TASK_GET_COMMENT_VOTES, &params, cb, user_data);
}
