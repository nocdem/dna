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
#include "p2p/p2p_transport.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <dirent.h>
#include <sys/stat.h>
#include <errno.h>
#include <unistd.h>

/* Use engine-specific error codes */
#define DNA_OK 0

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
    pthread_cond_init(&engine->task_cond, NULL);

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

    int error = (rc == 0) ? DNA_OK : DNA_ENGINE_ERROR_DATABASE;
    task->callback.identities(task->request_id, error, fingerprints, count, task->user_data);

    /* Caller is responsible for freeing via dna_free_strings */
}

void dna_handle_create_identity(dna_engine_t *engine, dna_task_t *task) {
    char fingerprint[129] = {0};

    int rc = messenger_generate_keys_from_seeds(
        task->params.create_identity.signing_seed,
        task->params.create_identity.encryption_seed,
        fingerprint
    );

    int error = DNA_OK;
    if (rc != 0) {
        error = DNA_ERROR_CRYPTO;
    }

    task->callback.identity_created(
        task->request_id,
        error,
        (error == DNA_OK) ? fingerprint : NULL,
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

    /* Enable P2P if available */
    if (engine->messenger->p2p_transport) {
        engine->messenger->p2p_enabled = true;
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

void dna_handle_get_display_name(dna_engine_t *engine, dna_task_t *task) {
    char display_name[256] = {0};
    int error = DNA_OK;

    dht_context_t *dht = dht_singleton_get();
    if (!dht) {
        error = DNA_ENGINE_ERROR_NETWORK;
        goto done;
    }

    char *name_out = NULL;
    int rc = dna_get_display_name(dht, task->params.get_display_name.fingerprint, &name_out);

    if (rc == 0 && name_out) {
        strncpy(display_name, name_out, sizeof(display_name) - 1);
        free(name_out);
    } else {
        /* Fall back to shortened fingerprint */
        snprintf(display_name, sizeof(display_name), "%.16s...",
                 task->params.get_display_name.fingerprint);
    }

done:
    task->callback.display_name(task->request_id, error, display_name, task->user_data);
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

            contacts[i].is_online = false; /* TODO: Check P2P presence */
            contacts[i].last_seen = 0;
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

    /* Query balances via RPC for known tokens */
    const char *tokens[] = {"CPUNK", "CELL", "KEL"};
    const char *networks[] = {"Backbone", "Backbone", "KelVPN"};
    int token_count = 3;

    balances = calloc(token_count, sizeof(dna_balance_t));
    if (!balances) {
        error = DNA_ERROR_INTERNAL;
        goto done;
    }

    for (int i = 0; i < token_count; i++) {
        strncpy(balances[i].token, tokens[i], sizeof(balances[i].token) - 1);
        strncpy(balances[i].network, networks[i], sizeof(balances[i].network) - 1);

        cellframe_rpc_response_t *response = NULL;
        int rc = cellframe_rpc_get_balance(networks[i], address, tokens[i], &response);

        if (rc == 0 && response && response->result) {
            /* Parse balance from response */
            json_object *balance_obj = NULL;
            if (json_object_object_get_ex(response->result, "balance", &balance_obj)) {
                const char *bal_str = json_object_get_string(balance_obj);
                if (bal_str) {
                    strncpy(balances[i].balance, bal_str, sizeof(balances[i].balance) - 1);
                }
            }
            cellframe_rpc_response_free(response);
        }

        if (balances[i].balance[0] == '\0') {
            strcpy(balances[i].balance, "0.0");
        }
    }
    count = token_count;

done:
    task->callback.balances(task->request_id, error, balances, count, task->user_data);
}

void dna_handle_send_tokens(dna_engine_t *engine, dna_task_t *task) {
    int error = DNA_OK;

    if (!engine->wallets_loaded || !engine->wallet_list) {
        error = DNA_ENGINE_ERROR_NOT_INITIALIZED;
        goto done;
    }

    /* TODO: Implement transaction building and signing */
    /* This requires:
     * 1. Get UTXOs for wallet
     * 2. Build transaction with inputs/outputs
     * 3. Sign with Dilithium from wallet
     * 4. Submit via RPC
     */
    error = DNA_ERROR_INTERNAL; /* Not yet implemented */

done:
    task->callback.completion(task->request_id, error, task->user_data);
}

void dna_handle_get_transactions(dna_engine_t *engine, dna_task_t *task) {
    int error = DNA_OK;
    dna_transaction_t *transactions = NULL;
    int count = 0;

    if (!engine->wallets_loaded || !engine->wallet_list) {
        error = DNA_ENGINE_ERROR_NOT_INITIALIZED;
        goto done;
    }

    /* TODO: Query transaction history from RPC */
    /* Current Cellframe RPC doesn't have direct tx history endpoint */
    error = DNA_ERROR_INTERNAL; /* Not yet implemented */

done:
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
            if (dht_keyserver_reverse_lookup(dht_ctx, engine->fingerprint, &registered_name) == 0 && registered_name) {
                name = registered_name; /* Transfer ownership */
            }
            /* Not found is not an error - just returns NULL name */
        }
    }

    if (task->callback.display_name) {
        task->callback.display_name(task->request_id, error, name, task->user_data);
    }

    free(name);
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
