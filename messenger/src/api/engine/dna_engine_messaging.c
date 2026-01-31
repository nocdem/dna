/*
 * DNA Engine - Messaging Module
 *
 * Message handling extracted from dna_engine.c.
 * Contains send/receive, conversation retrieval, offline message checking,
 * and bulletproof message retry with exponential backoff.
 *
 * Functions:
 *   - dna_handle_send_message()           // Send message task handler
 *   - dna_handle_get_conversation()       // Get full conversation
 *   - dna_handle_get_conversation_page()  // Get paginated conversation
 *   - dna_handle_check_offline_messages() // Check DHT for offline messages
 *   - dna_engine_retry_pending_messages() // Retry all pending messages
 *   - dna_engine_retry_message()          // Retry single message by ID
 */

#define DNA_ENGINE_MESSAGING_IMPL
#include "engine_includes.h"

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
        0,  /* message_type = chat */
        task->params.send_message.queued_at
    );

    if (rc != 0) {
        /* Determine error type based on return code */
        if (rc == -3) {
            /* KEY_UNAVAILABLE: recipient key not cached and DHT lookup failed */
            error = DNA_ENGINE_ERROR_KEY_UNAVAILABLE;
            QGP_LOG_WARN(LOG_TAG, "[SEND] Key unavailable for recipient - message not saved (cannot encrypt)");
        } else {
            /* Network or other error */
            error = DNA_ENGINE_ERROR_NETWORK;
            QGP_LOG_WARN(LOG_TAG, "[SEND] Message send failed (rc=%d) - DHT queue unsuccessful", rc);
        }
        /* Emit MESSAGE_SENT event with FAILED status so UI can update spinner */
        dna_event_t event = {0};
        event.type = DNA_EVENT_MESSAGE_SENT;
        event.data.message_status.message_id = 0;  /* ID not available here */
        event.data.message_status.new_status = 3;  /* FAILED (v15: 0=pending, 1=sent, 2=received, 3=failed) */
        dna_dispatch_event(engine, &event);
    } else {
        /* Emit MESSAGE_SENT event so UI can update (triggers refresh)
         * Status is SENT (1) - DHT PUT succeeded, single tick in UI.
         * Will become RECEIVED (2) via ACK confirmation -> double tick. */
        QGP_LOG_INFO(LOG_TAG, "[SEND] Message stored on DHT (status=SENT, single tick)");
        dna_event_t event = {0};
        event.type = DNA_EVENT_MESSAGE_SENT;
        event.data.message_status.message_id = 0;  /* ID not available here */
        event.data.message_status.new_status = 1;  /* SENT - DHT PUT succeeded */
        dna_dispatch_event(engine, &event);
    }

    /* Clear message queue slot if this was a queued message */
    intptr_t slot_id = (intptr_t)task->user_data;
    if (slot_id > 0) {
        pthread_mutex_lock(&engine->message_queue.mutex);
        for (int i = 0; i < engine->message_queue.capacity; i++) {
            if (engine->message_queue.entries[i].in_use &&
                engine->message_queue.entries[i].slot_id == slot_id) {
                free(engine->message_queue.entries[i].message);
                engine->message_queue.entries[i].message = NULL;
                engine->message_queue.entries[i].in_use = false;
                engine->message_queue.size--;
                break;
            }
        }
        pthread_mutex_unlock(&engine->message_queue.mutex);
    }

done:
    /* Only call callback if one was provided (not for queued messages) */
    if (task->callback.completion) {
        task->callback.completion(task->request_id, error, task->user_data);
    }
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

            /* Use pre-decrypted plaintext from messenger_get_conversation */
            /* (Kyber key loaded once, not per-message - massive speedup) */
            if (msg_infos[i].plaintext) {
                messages[i].plaintext = strdup(msg_infos[i].plaintext);
            } else {
                messages[i].plaintext = strdup("[Decryption failed]");
            }

            /* Parse timestamp string (format: YYYY-MM-DD HH:MM:SS) */
            if (msg_infos[i].timestamp) {
                struct tm tm = {0};
                if (strptime(msg_infos[i].timestamp, "%Y-%m-%d %H:%M:%S", &tm) != NULL) {
                    messages[i].timestamp = (uint64_t)safe_timegm(&tm);
                } else {
                    messages[i].timestamp = (uint64_t)time(NULL);
                }
            } else {
                messages[i].timestamp = (uint64_t)time(NULL);
            }

            /* Determine if outgoing */
            messages[i].is_outgoing = (msg_infos[i].sender &&
                strcmp(msg_infos[i].sender, engine->fingerprint) == 0);

            /* Map status string to int (v15): 0=pending, 1=sent, 2=received, 3=failed */
            if (msg_infos[i].status) {
                if (strcmp(msg_infos[i].status, "failed") == 0) {
                    messages[i].status = 3;
                } else if (strcmp(msg_infos[i].status, "received") == 0) {
                    messages[i].status = 2;
                } else if (strcmp(msg_infos[i].status, "sent") == 0) {
                    messages[i].status = 1;
                } else if (strcmp(msg_infos[i].status, "pending") == 0) {
                    messages[i].status = 0;
                } else {
                    messages[i].status = 1;  /* default to sent for old messages */
                }
            } else {
                messages[i].status = 1;  /* default to sent if no status */
            }

            messages[i].message_type = msg_infos[i].message_type;
        }
        count = msg_count;

        messenger_free_messages(msg_infos, msg_count);
    }

done:
    task->callback.messages(task->request_id, error, messages, count, task->user_data);
}

void dna_handle_get_conversation_page(dna_engine_t *engine, dna_task_t *task) {
    int error = DNA_OK;
    dna_message_t *messages = NULL;
    int count = 0;
    int total = 0;

    if (!engine->identity_loaded || !engine->messenger) {
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
        goto done;
    }

    message_info_t *msg_infos = NULL;
    int msg_count = 0;

    int rc = messenger_get_conversation_page(
        engine->messenger,
        task->params.get_conversation_page.contact,
        task->params.get_conversation_page.limit,
        task->params.get_conversation_page.offset,
        &msg_infos,
        &msg_count,
        &total
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

            if (msg_infos[i].plaintext) {
                messages[i].plaintext = strdup(msg_infos[i].plaintext);
            } else {
                messages[i].plaintext = strdup("[Decryption failed]");
            }

            /* Parse timestamp string (format: YYYY-MM-DD HH:MM:SS) */
            if (msg_infos[i].timestamp) {
                struct tm tm = {0};
                if (strptime(msg_infos[i].timestamp, "%Y-%m-%d %H:%M:%S", &tm) != NULL) {
                    messages[i].timestamp = (uint64_t)safe_timegm(&tm);
                } else {
                    messages[i].timestamp = (uint64_t)time(NULL);
                }
            } else {
                messages[i].timestamp = (uint64_t)time(NULL);
            }

            messages[i].is_outgoing = (msg_infos[i].sender &&
                strcmp(msg_infos[i].sender, engine->fingerprint) == 0);

            /* Map status string to int (v15): 0=pending, 1=sent, 2=received, 3=failed */
            if (msg_infos[i].status) {
                if (strcmp(msg_infos[i].status, "failed") == 0) {
                    messages[i].status = 3;
                } else if (strcmp(msg_infos[i].status, "received") == 0) {
                    messages[i].status = 2;
                } else if (strcmp(msg_infos[i].status, "sent") == 0) {
                    messages[i].status = 1;
                } else if (strcmp(msg_infos[i].status, "pending") == 0) {
                    messages[i].status = 0;
                } else {
                    messages[i].status = 1;
                }
            } else {
                messages[i].status = 1;
            }

            messages[i].message_type = msg_infos[i].message_type;
        }
        count = msg_count;

        messenger_free_messages(msg_infos, msg_count);
    }

done:
    task->callback.messages_page(task->request_id, error, messages, count, total, task->user_data);
}

void dna_handle_check_offline_messages(dna_engine_t *engine, dna_task_t *task) {
    int error = DNA_OK;

    if (!engine->identity_loaded || !engine->messenger) {
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
        goto done;
    }

    /* Get contact list and track unread counts BEFORE fetch.
     * This allows us to detect which contacts have new messages and emit
     * OUTBOX_UPDATED events for Android notifications. */
    contact_list_t *contacts = NULL;
    int *counts_before = NULL;
    size_t contact_count = 0;

    if (contacts_db_list(&contacts) == 0 && contacts && contacts->count > 0) {
        contact_count = contacts->count;
        counts_before = calloc(contact_count, sizeof(int));
        if (counts_before) {
            for (size_t i = 0; i < contact_count; i++) {
                counts_before[i] = messenger_get_unread_count(
                    engine->messenger, contacts->contacts[i].identity);
            }
        }
    }

    /* First, sync any pending outboxes (our messages that failed to publish earlier) */
    dht_context_t *dht_ctx = dht_singleton_get();
    if (dht_ctx) {
        int synced = dht_offline_queue_sync_pending(dht_ctx);
        if (synced > 0) {
            QGP_LOG_INFO("DNA_ENGINE", "[OFFLINE] Synced %d pending outboxes to DHT", synced);
        }
    }

    /* Check DHT offline queue for messages from contacts.
     * publish_acks=true when user is active (notifies senders we received messages).
     * publish_acks=false for background caching (user hasn't read them yet).
     * force_full_sync=false: use smart sync (not startup, so incremental is fine). */
    bool publish_acks = task->params.check_offline_messages.publish_watermarks;  /* v15: param name kept for compat */
    size_t offline_count = 0;
    int rc = messenger_transport_check_offline_messages(engine->messenger, NULL, publish_acks, false, &offline_count);
    if (rc == 0) {
        QGP_LOG_INFO("DNA_ENGINE", "[OFFLINE] Direct messages check complete: %zu new (acks=%s)",
                     offline_count, publish_acks ? "yes" : "no");
    } else {
        QGP_LOG_WARN("DNA_ENGINE", "[OFFLINE] Direct messages check failed with rc=%d", rc);
    }

    /* Emit OUTBOX_UPDATED events for contacts with new messages.
     * This triggers Android notifications when Flutter is not attached. */
    if (counts_before && contacts && offline_count > 0) {
        for (size_t i = 0; i < contact_count; i++) {
            int count_after = messenger_get_unread_count(
                engine->messenger, contacts->contacts[i].identity);

            if (count_after > counts_before[i]) {
                /* This contact has new messages - emit event */
                QGP_LOG_INFO("DNA_ENGINE", "[OFFLINE] New messages from %.16s... (%d -> %d)",
                             contacts->contacts[i].identity, counts_before[i], count_after);

                dna_event_t event = {0};
                event.type = DNA_EVENT_OUTBOX_UPDATED;
                strncpy(event.data.outbox_updated.contact_fingerprint,
                        contacts->contacts[i].identity,
                        sizeof(event.data.outbox_updated.contact_fingerprint) - 1);
                dna_dispatch_event(engine, &event);
            }
        }
    }

    /* Cleanup contact tracking */
    if (counts_before) free(counts_before);
    if (contacts) contacts_db_free_list(contacts);

    /* Also sync group messages from DHT */
    if (dht_ctx) {
        size_t group_msg_count = 0;
        rc = dna_group_outbox_sync_all(dht_ctx, engine->fingerprint, &group_msg_count);
        if (rc == 0) {
            QGP_LOG_INFO("DNA_ENGINE", "[OFFLINE] Group messages sync complete: %zu new", group_msg_count);
        } else if (rc != DNA_GROUP_OUTBOX_ERR_NULL_PARAM) {
            /* NULL_PARAM just means no groups, not an error */
            QGP_LOG_WARN("DNA_ENGINE", "[OFFLINE] Group messages sync failed with rc=%d", rc);
        }
    }

done:
    task->callback.completion(task->request_id, error, task->user_data);
}

/* ============================================================================
 * MESSAGE RETRY (Bulletproof Message Delivery)
 * ============================================================================
 *
 * v0.4.59: "Never Give Up" retry system
 * - No max retry limit (keeps trying until delivered or stale)
 * - Exponential backoff: 30s, 60s, 120s, ... max 1 hour
 * - Stale marking: 30+ day old messages marked stale (shown differently in UI)
 * - DHT check: Only retry when DHT is connected with ≥1 peer
 */

#define MESSAGE_RETRY_MAX_RETRIES 0  /* 0 = unlimited retries (never give up) */
#define MESSAGE_STALE_DAYS 30        /* Mark as stale after 30 days */
#define MESSAGE_BACKOFF_BASE_SECS 30 /* Base backoff: 30 seconds */
#define MESSAGE_BACKOFF_MAX_SECS 3600 /* Max backoff: 1 hour */

/* Mutex to prevent concurrent retry calls (e.g., DHT reconnect + manual retry race) */
static pthread_mutex_t retry_mutex = PTHREAD_MUTEX_INITIALIZER;

/**
 * Calculate retry backoff interval based on retry_count
 * Exponential: 30s, 60s, 120s, 240s, 480s, 960s, 1920s, 3600s (max)
 */
static int get_retry_backoff_secs(int retry_count) {
    if (retry_count <= 0) return MESSAGE_BACKOFF_BASE_SECS;

    /* Cap the exponent to prevent overflow (2^7 = 128, 30*128 = 3840 > 3600) */
    int exp = retry_count < 7 ? retry_count : 7;
    int interval = MESSAGE_BACKOFF_BASE_SECS * (1 << exp);

    return interval > MESSAGE_BACKOFF_MAX_SECS ? MESSAGE_BACKOFF_MAX_SECS : interval;
}

/**
 * Check if message is ready for retry based on exponential backoff
 * Returns true if enough time has passed since message creation + backoff
 */
static bool is_ready_for_retry(backup_message_t *msg) {
    if (!msg) return false;

    /* First attempt (retry_count=0) always allowed */
    if (msg->retry_count == 0) return true;

    /* Calculate next retry time based on backoff */
    int backoff_secs = get_retry_backoff_secs(msg->retry_count);
    time_t next_retry_at = msg->timestamp + (msg->retry_count * backoff_secs);
    time_t now = time(NULL);

    return now >= next_retry_at;
}

/**
 * Retry a single pending/failed message
 *
 * v15: Re-encrypts plaintext and queues to DHT.
 * Uses messenger_send_message which handles encryption, DHT queueing, and duplicate detection.
 * Status stays PENDING until ACK confirms RECEIVED. Increments retry_count on failure.
 *
 * @param engine Engine instance
 * @param msg Message to retry (from message_backup_get_pending_messages)
 * @return 0 on success, -1 on failure
 */
static int retry_single_message(dna_engine_t *engine, backup_message_t *msg) {
    if (!engine || !msg) return -1;
    if (!engine->messenger) return -1;

    message_backup_context_t *backup_ctx = messenger_get_backup_ctx(engine->messenger);
    if (!backup_ctx) return -1;

    /* v14: Messages are stored as plaintext - need to re-encrypt before sending */
    if (!msg->plaintext || strlen(msg->plaintext) == 0) {
        QGP_LOG_WARN(LOG_TAG, "[RETRY] Message %d has no plaintext - cannot retry", msg->id);
        return -1;
    }

    /* Call messenger_send_message to re-encrypt and send
     * This handles:
     * - Loading recipient's Kyber public key
     * - Multi-recipient encryption
     * - DHT queueing
     * - Duplicate detection (skips DB save if message exists) */
    const char *recipients[] = { msg->recipient };
    int rc = messenger_send_message(
        engine->messenger,
        recipients,
        1,                      /* recipient_count */
        msg->plaintext,         /* message content */
        msg->group_id,          /* group_id (0 for direct) */
        msg->message_type,      /* message_type */
        msg->timestamp          /* preserve original timestamp for ordering */
    );

    if (rc == 0 || rc == 1) {
        /* Success - queued to DHT (rc=0) or duplicate skipped (rc=1)
         * Update status to SENT (1) using original message ID.
         * For duplicates, messenger_send_message() can't update status (message_id=0)
         * so we must do it here to prevent infinite retry loops. */
        message_backup_update_status(backup_ctx, msg->id, 1);
        QGP_LOG_INFO(LOG_TAG, "[RETRY] Message %d to %.20s... re-encrypted and queued, status=SENT",
                     msg->id, msg->recipient);
        return 0;
    } else if (rc == -3) {
        /* KEY_UNAVAILABLE - recipient's public key not cached and DHT unavailable
         * Don't increment retry count - will retry when DHT reconnects */
        QGP_LOG_WARN(LOG_TAG, "[RETRY] Message %d to %.20s... key unavailable (will retry later)",
                     msg->id, msg->recipient);
        return -1;
    } else {
        /* Failed - increment retry count */
        message_backup_increment_retry_count(backup_ctx, msg->id);
        QGP_LOG_WARN(LOG_TAG, "[RETRY] Message %d to %.20s... failed (retry_count=%d)",
                     msg->id, msg->recipient, msg->retry_count + 1);
        return -1;
    }
}

int dna_engine_retry_pending_messages(dna_engine_t *engine) {
    if (!engine) return -1;
    if (!engine->messenger) return -1;

    dht_context_t *dht_ctx = dna_get_dht_ctx(engine);
    if (!dht_ctx) return -1;

    /* Skip retry if DHT is not connected - retries will fail and block for timeout
     * Messages will be retried when DHT reconnects (triggers this function again) */
    if (!dht_context_is_ready(dht_ctx)) {
        QGP_LOG_INFO(LOG_TAG, "[RETRY] Skipping retry - DHT not connected");
        return 0;
    }

    message_backup_context_t *backup_ctx = messenger_get_backup_ctx(engine->messenger);
    if (!backup_ctx) return -1;

    /* Lock to prevent concurrent retry calls */
    pthread_mutex_lock(&retry_mutex);

    /* Get all pending/failed messages (0 = unlimited, no retry_count filter) */
    backup_message_t *messages = NULL;
    int count = 0;
    int rc = message_backup_get_pending_messages(
        backup_ctx,
        MESSAGE_RETRY_MAX_RETRIES,  /* 0 = unlimited */
        &messages,
        &count
    );

    if (rc != 0) {
        QGP_LOG_ERROR(LOG_TAG, "[RETRY] Failed to query pending messages");
        pthread_mutex_unlock(&retry_mutex);
        return -1;
    }

    if (count == 0) {
        QGP_LOG_DEBUG(LOG_TAG, "[RETRY] No pending messages to retry");
        pthread_mutex_unlock(&retry_mutex);
        return 0;
    }

    QGP_LOG_INFO(LOG_TAG, "[RETRY] Found %d pending/failed messages to process", count);

    int success_count = 0;
    int fail_count = 0;
    int skipped_backoff = 0;
    int marked_stale = 0;

    /* Process each message */
    for (int i = 0; i < count; i++) {
        backup_message_t *msg = &messages[i];

        /* Check if message is stale (30+ days old) - mark as FAILED in v15 */
        int age_days = message_backup_get_age_days(backup_ctx, msg->id);
        if (age_days >= MESSAGE_STALE_DAYS) {
            message_backup_update_status(backup_ctx, msg->id, MESSAGE_STATUS_FAILED);
            marked_stale++;
            QGP_LOG_INFO(LOG_TAG, "[RETRY] Message %d marked FAILED (stale, age=%d days)", msg->id, age_days);
            continue;
        }

        /* Check exponential backoff - skip if not ready for retry yet */
        if (!is_ready_for_retry(msg)) {
            skipped_backoff++;
            continue;
        }

        /* Retry the message */
        if (retry_single_message(engine, msg) == 0) {
            success_count++;
        } else {
            fail_count++;
        }
    }

    QGP_LOG_INFO(LOG_TAG, "[RETRY] Completed: %d succeeded, %d failed, %d backoff, %d stale",
                 success_count, fail_count, skipped_backoff, marked_stale);

    /* Note: Delivery confirmation handled by persistent ACK listeners (v15) */

    /* Free messages array */
    message_backup_free_messages(messages, count);

    pthread_mutex_unlock(&retry_mutex);
    return success_count;
}

int dna_engine_retry_message(dna_engine_t *engine, int message_id) {
    if (!engine || message_id <= 0) return -1;
    if (!engine->messenger) return -1;

    dht_context_t *dht_ctx = dna_get_dht_ctx(engine);
    if (!dht_ctx) return -1;
    (void)dht_ctx;  /* Used by retry_single_message via dna_get_dht_ctx */

    message_backup_context_t *backup_ctx = messenger_get_backup_ctx(engine->messenger);
    if (!backup_ctx) return -1;

    /* Lock to prevent concurrent retry calls */
    pthread_mutex_lock(&retry_mutex);

    /* Get all pending/failed messages (we'll filter by ID) */
    backup_message_t *messages = NULL;
    int count = 0;
    int rc = message_backup_get_pending_messages(
        backup_ctx,
        0,  /* 0 = unlimited - allow manual retry regardless of retry_count */
        &messages,
        &count
    );

    if (rc != 0 || count == 0) {
        pthread_mutex_unlock(&retry_mutex);
        return -1;
    }

    /* Find the specific message */
    int result = -1;
    for (int i = 0; i < count; i++) {
        if (messages[i].id == message_id) {
            result = retry_single_message(engine, &messages[i]);
            break;
        }
    }

    message_backup_free_messages(messages, count);

    if (result == -1) {
        QGP_LOG_WARN(LOG_TAG, "[RETRY] Message %d not found or not retryable", message_id);
    }

    pthread_mutex_unlock(&retry_mutex);
    return result;
}

/* ============================================================================
 * PUBLIC API - Messaging Functions
 * ============================================================================ */

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
    params.send_message.queued_at = time(NULL);  /* Capture send time */
    if (!params.send_message.message) {
        return DNA_REQUEST_ID_INVALID;
    }

    dna_task_callback_t cb = { .completion = callback };
    return dna_submit_task(engine, TASK_SEND_MESSAGE, &params, cb, user_data);
}

int dna_engine_queue_message(
    dna_engine_t *engine,
    const char *recipient_fingerprint,
    const char *message
) {
    if (!engine || !recipient_fingerprint || !message) {
        return -2; /* Invalid args */
    }
    if (!engine->identity_loaded) {
        return -2; /* No identity loaded */
    }

    /* Capture timestamp NOW - this is when user clicked send */
    time_t queued_at = time(NULL);

    pthread_mutex_lock(&engine->message_queue.mutex);

    /* Check if queue is full */
    if (engine->message_queue.size >= engine->message_queue.capacity) {
        pthread_mutex_unlock(&engine->message_queue.mutex);
        return -1; /* Queue full */
    }

    /* Find empty slot */
    int slot_index = -1;
    for (int i = 0; i < engine->message_queue.capacity; i++) {
        if (!engine->message_queue.entries[i].in_use) {
            slot_index = i;
            break;
        }
    }

    if (slot_index < 0) {
        pthread_mutex_unlock(&engine->message_queue.mutex);
        return -1; /* No slot available */
    }

    /* Fill the slot (DM message: recipient set, group_uuid empty) */
    dna_message_queue_entry_t *entry = &engine->message_queue.entries[slot_index];
    strncpy(entry->recipient, recipient_fingerprint, 128);
    entry->recipient[128] = '\0';
    entry->group_uuid[0] = '\0';  /* Empty for DM messages */
    entry->message = strdup(message);
    if (!entry->message) {
        pthread_mutex_unlock(&engine->message_queue.mutex);
        return -2; /* Memory error */
    }
    entry->slot_id = engine->message_queue.next_slot_id++;
    entry->in_use = true;
    entry->queued_at = queued_at;
    engine->message_queue.size++;

    int slot_id = entry->slot_id;
    pthread_mutex_unlock(&engine->message_queue.mutex);

    /* Submit task to worker queue (fire-and-forget, no callback) */
    dna_task_params_t params = {0};
    strncpy(params.send_message.recipient, recipient_fingerprint, 128);
    params.send_message.message = strdup(message);
    params.send_message.queued_at = queued_at;
    if (params.send_message.message) {
        dna_task_callback_t cb = { .completion = NULL };
        dna_submit_task(engine, TASK_SEND_MESSAGE, &params, cb, (void*)(intptr_t)slot_id);
    }

    return slot_id;
}

int dna_engine_get_message_queue_capacity(dna_engine_t *engine) {
    if (!engine) return 0;
    return engine->message_queue.capacity;
}

int dna_engine_get_message_queue_size(dna_engine_t *engine) {
    if (!engine) return 0;

    pthread_mutex_lock(&engine->message_queue.mutex);
    int size = engine->message_queue.size;
    pthread_mutex_unlock(&engine->message_queue.mutex);

    return size;
}

int dna_engine_set_message_queue_capacity(dna_engine_t *engine, int capacity) {
    if (!engine || capacity < 1 || capacity > DNA_MESSAGE_QUEUE_MAX_CAPACITY) {
        return -1;
    }

    pthread_mutex_lock(&engine->message_queue.mutex);

    /* Can't shrink below current size */
    if (capacity < engine->message_queue.size) {
        pthread_mutex_unlock(&engine->message_queue.mutex);
        return -1;
    }

    /* Reallocate if needed */
    if (capacity != engine->message_queue.capacity) {
        dna_message_queue_entry_t *new_entries = realloc(
            engine->message_queue.entries,
            capacity * sizeof(dna_message_queue_entry_t)
        );
        if (!new_entries) {
            pthread_mutex_unlock(&engine->message_queue.mutex);
            return -1;
        }
        /* Initialize new slots */
        for (int i = engine->message_queue.capacity; i < capacity; i++) {
            memset(&new_entries[i], 0, sizeof(dna_message_queue_entry_t));
        }
        engine->message_queue.entries = new_entries;
        engine->message_queue.capacity = capacity;
    }

    pthread_mutex_unlock(&engine->message_queue.mutex);
    return 0;
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

dna_request_id_t dna_engine_get_conversation_page(
    dna_engine_t *engine,
    const char *contact_fingerprint,
    int limit,
    int offset,
    dna_messages_page_cb callback,
    void *user_data
) {
    if (!engine || !contact_fingerprint || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.get_conversation_page.contact, contact_fingerprint, 128);
    params.get_conversation_page.limit = limit > 0 ? limit : 50;
    params.get_conversation_page.offset = offset >= 0 ? offset : 0;

    dna_task_callback_t cb = { .messages_page = callback };
    return dna_submit_task(engine, TASK_GET_CONVERSATION_PAGE, &params, cb, user_data);
}

dna_request_id_t dna_engine_check_offline_messages(
    dna_engine_t *engine,
    dna_completion_cb callback,
    void *user_data
) {
    if (!engine || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    params.check_offline_messages.publish_watermarks = true;  /* User is active */

    dna_task_callback_t cb = { .completion = callback };
    return dna_submit_task(engine, TASK_CHECK_OFFLINE_MESSAGES, &params, cb, user_data);
}

dna_request_id_t dna_engine_check_offline_messages_cached(
    dna_engine_t *engine,
    dna_completion_cb callback,
    void *user_data
) {
    if (!engine || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    params.check_offline_messages.publish_watermarks = false;  /* Background caching - don't notify senders */

    dna_task_callback_t cb = { .completion = callback };
    return dna_submit_task(engine, TASK_CHECK_OFFLINE_MESSAGES, &params, cb, user_data);
}

dna_request_id_t dna_engine_check_offline_messages_from(
    dna_engine_t *engine,
    const char *contact_fingerprint,
    dna_completion_cb callback,
    void *user_data
) {
    if (!engine || !contact_fingerprint || !callback) return DNA_REQUEST_ID_INVALID;

    size_t fp_len = strlen(contact_fingerprint);
    if (fp_len < 64) {
        QGP_LOG_ERROR(LOG_TAG, "[OFFLINE] Invalid fingerprint length: %zu", fp_len);
        return DNA_REQUEST_ID_INVALID;
    }

    /* Submit task to worker thread - avoids blocking Flutter main thread */
    dna_task_params_t params = {0};
    strncpy(params.check_offline_messages_from.contact_fingerprint, contact_fingerprint, 128);

    dna_task_callback_t cb = { .completion = callback };
    return dna_submit_task(engine, TASK_CHECK_OFFLINE_MESSAGES_FROM, &params, cb, user_data);
}

/* Handler for TASK_CHECK_OFFLINE_MESSAGES_FROM - runs on worker thread */
void dna_handle_check_offline_messages_from(dna_engine_t *engine, dna_task_t *task) {
    int error = DNA_OK;

    if (!engine->identity_loaded || !engine->messenger) {
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
        goto done;
    }

    const char *contact_fp = task->params.check_offline_messages_from.contact_fingerprint;

    /* Check offline messages from specific contact's outbox.
     * This is faster than checking all contacts and provides
     * immediate updates when entering a specific chat.
     * force_full_sync=false: use smart sync for single contact check. */
    QGP_LOG_INFO(LOG_TAG, "[OFFLINE] Checking messages from %.20s... (async)", contact_fp);

    size_t offline_count = 0;
    int rc = messenger_transport_check_offline_messages(engine->messenger, contact_fp, true, false, &offline_count);
    if (rc == 0) {
        QGP_LOG_INFO(LOG_TAG, "[OFFLINE] From %.20s...: %zu new messages", contact_fp, offline_count);
    } else {
        QGP_LOG_WARN(LOG_TAG, "[OFFLINE] Check from %.20s... failed: %d", contact_fp, rc);
        error = DNA_ENGINE_ERROR_NETWORK;
    }

done:
    task->callback.completion(task->request_id, error, task->user_data);
}

int dna_engine_get_unread_count(
    dna_engine_t *engine,
    const char *contact_fingerprint
) {
    if (!engine || !contact_fingerprint) return -1;
    if (!engine->messenger) return -1;

    return messenger_get_unread_count(engine->messenger, contact_fingerprint);
}

dna_request_id_t dna_engine_mark_conversation_read(
    dna_engine_t *engine,
    const char *contact_fingerprint,
    dna_completion_cb callback,
    void *user_data
) {
    if (!engine || !contact_fingerprint || !callback) return DNA_REQUEST_ID_INVALID;

    /* Mark as read synchronously since it's a fast local DB operation */
    int result = -1;
    if (engine->messenger) {
        result = messenger_mark_conversation_read(engine->messenger, contact_fingerprint);
    }

    /* Call callback immediately with result (0=success, negative=error) */
    callback(1, result == 0 ? 0 : -1, user_data);
    return 1; /* Return valid request ID */
}

int dna_engine_delete_message_sync(
    dna_engine_t *engine,
    int message_id
) {
    if (!engine || message_id <= 0) return -1;
    if (!engine->messenger) return -1;

    return messenger_delete_message(engine->messenger, message_id);
}
