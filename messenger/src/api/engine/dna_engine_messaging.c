/*
 * DNA Engine - Messaging Module
 *
 * Message handling extracted from dna_engine.c.
 * Contains send/receive, conversation retrieval, offline message checking.
 *
 * Functions:
 *   - dna_handle_send_message()
 *   - dna_handle_get_conversation()
 *   - dna_handle_get_conversation_page()
 *   - dna_handle_check_offline_messages()
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
        event.data.message_status.new_status = 2;  /* FAILED */
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

            /* Map status string to int: 0=pending, 1=sent, 2=failed, 3=delivered, 4=read */
            if (msg_infos[i].status) {
                if (strcmp(msg_infos[i].status, "read") == 0) {
                    messages[i].status = 4;
                } else if (strcmp(msg_infos[i].status, "delivered") == 0) {
                    messages[i].status = 3;
                } else if (strcmp(msg_infos[i].status, "failed") == 0) {
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

            /* Map status string to int */
            if (msg_infos[i].status) {
                if (strcmp(msg_infos[i].status, "read") == 0) {
                    messages[i].status = 4;
                } else if (strcmp(msg_infos[i].status, "delivered") == 0) {
                    messages[i].status = 3;
                } else if (strcmp(msg_infos[i].status, "failed") == 0) {
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
     * publish_acks=false for background caching (user hasn't read them yet). */
    bool publish_acks = task->params.check_offline_messages.publish_watermarks;  /* v15: param name kept for compat */
    size_t offline_count = 0;
    int rc = messenger_transport_check_offline_messages(engine->messenger, NULL, publish_acks, &offline_count);
    if (rc == 0) {
        QGP_LOG_INFO("DNA_ENGINE", "[OFFLINE] Direct messages check complete: %zu new (acks=%s)",
                     offline_count, publish_acks ? "yes" : "no");
    } else {
        QGP_LOG_WARN("DNA_ENGINE", "[OFFLINE] Direct messages check failed with rc=%d", rc);
    }

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
