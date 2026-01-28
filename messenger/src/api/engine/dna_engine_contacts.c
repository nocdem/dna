/*
 * DNA Engine - Contacts Module
 *
 * Contact management handlers extracted from dna_engine.c.
 * Handles contact CRUD operations, contact requests (ICQ-style), blocking.
 *
 * Functions:
 *   - dna_handle_get_contacts()
 *   - dna_handle_add_contact()
 *   - dna_handle_remove_contact()
 *   - dna_engine_set_contact_nickname_sync()
 *   - dna_handle_send_contact_request()
 *   - dna_handle_get_contact_requests()
 *   - dna_handle_approve_contact_request()
 *   - dna_handle_deny_contact_request()
 *   - dna_handle_block_user()
 *   - dna_handle_unblock_user()
 *   - dna_handle_get_blocked_users()
 */

#define DNA_ENGINE_CONTACTS_IMPL
#include "engine_includes.h"

/* Message used for reciprocal contact request auto-approval */
#define CONTACT_ACCEPTED_MSG "Contact request accepted"

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

        for (size_t i = 0; i < list->count; i++) {
            strncpy(contacts[i].fingerprint, list->contacts[i].identity, 128);

            /* Copy local nickname to contact struct (for Flutter to access) */
            if (list->contacts[i].nickname[0] != '\0') {
                strncpy(contacts[i].nickname, list->contacts[i].nickname, sizeof(contacts[i].nickname) - 1);
                contacts[i].nickname[sizeof(contacts[i].nickname) - 1] = '\0';
            } else {
                contacts[i].nickname[0] = '\0';
            }

            /* Get display name with fallback chain:
             * 0. Local nickname (NEW - highest priority)
             * 1. DHT profile (profile_manager)
             * 2. Registered name (keyserver_cache)
             * 3. Stored notes from contact request
             * 4. Fingerprint prefix as last resort */
            bool name_found = false;

            /* Try 0: Local nickname (highest priority) */
            if (list->contacts[i].nickname[0] != '\0') {
                strncpy(contacts[i].display_name, list->contacts[i].nickname, sizeof(contacts[i].display_name) - 1);
                name_found = true;
            }

            /* Try 1: DHT profile (registered_name) */
            if (!name_found) {
                dna_unified_identity_t *identity = NULL;
                if (profile_manager_get_profile(list->contacts[i].identity, &identity) == 0 && identity) {
                    if (identity->registered_name[0] != '\0') {
                        strncpy(contacts[i].display_name, identity->registered_name, sizeof(contacts[i].display_name) - 1);
                        name_found = true;
                    }
                    dna_identity_free(identity);
                }
            }

            /* Try 2: Registered name from keyserver cache */
            if (!name_found) {
                char cached_name[64] = {0};
                if (keyserver_cache_get_name(list->contacts[i].identity, cached_name, sizeof(cached_name)) == 0 &&
                    cached_name[0] != '\0') {
                    strncpy(contacts[i].display_name, cached_name, sizeof(contacts[i].display_name) - 1);
                    name_found = true;
                }
            }

            /* Try 3: Notes field (stored display name from contact request) */
            if (!name_found && list->contacts[i].notes[0] != '\0') {
                strncpy(contacts[i].display_name, list->contacts[i].notes, sizeof(contacts[i].display_name) - 1);
                name_found = true;
            }

            /* Fallback: fingerprint prefix */
            if (!name_found) {
                snprintf(contacts[i].display_name, sizeof(contacts[i].display_name),
                         "%.16s...", list->contacts[i].identity);
            }

            /* Check presence cache for online status and last seen */
            contacts[i].is_online = presence_cache_get(list->contacts[i].identity);

            /* Get last_seen: prefer cache (recent activity), fallback to database (persistent) */
            time_t cache_last_seen = presence_cache_last_seen(list->contacts[i].identity);
            if (cache_last_seen > 0) {
                contacts[i].last_seen = (uint64_t)cache_last_seen;
            } else {
                /* Use database value (persisted from previous sessions) */
                contacts[i].last_seen = list->contacts[i].last_seen;
            }
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
    QGP_LOG_WARN(LOG_TAG, "[CONTACTLIST_PUBLISH] add_contact: calling sync");
    messenger_sync_contacts_to_dht(engine->messenger);

    /* v0.6.26: Start outbox listener for new contact (previously done from Dart
     * but listenAllContacts() blocked UI for up to 30s waiting for DHT) */
    dna_engine_listen_outbox(engine, fingerprint);

done:
    task->callback.completion(task->request_id, error, task->user_data);
}

void dna_handle_remove_contact(dna_engine_t *engine, dna_task_t *task) {
    int error = DNA_OK;
    const char *fp = task->params.remove_contact.fingerprint;

    QGP_LOG_INFO(LOG_TAG, "REMOVE_CONTACT: Request to remove %.16s...\n", fp ? fp : "(null)");

    if (!engine->identity_loaded) {
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
        goto done;
    }

    /* Initialize contacts database for this identity */
    if (contacts_db_init(engine->fingerprint) != 0) {
        error = DNA_ENGINE_ERROR_DATABASE;
        goto done;
    }

    int db_result = contacts_db_remove(fp);
    if (db_result != 0) {
        QGP_LOG_WARN(LOG_TAG, "REMOVE_CONTACT: contacts_db_remove failed (rc=%d) for %.16s...\n", db_result, fp);
        error = DNA_ERROR_NOT_FOUND;
    } else {
        QGP_LOG_INFO(LOG_TAG, "REMOVE_CONTACT: Successfully removed %.16s... from local DB\n", fp);

        /* Cancel ACK listener for this contact (v15) */
        dna_engine_cancel_ack_listener(engine, fp);
    }

    /* Sync to DHT */
    if (error == DNA_OK) {
        QGP_LOG_WARN(LOG_TAG, "[CONTACTLIST_PUBLISH] remove_contact: calling sync");
        int sync_result = messenger_sync_contacts_to_dht(engine->messenger);
        if (sync_result != 0) {
            QGP_LOG_WARN(LOG_TAG, "REMOVE_CONTACT: DHT sync failed (rc=%d) - contact may reappear on next sync!\n", sync_result);
        } else {
            QGP_LOG_INFO(LOG_TAG, "REMOVE_CONTACT: DHT sync successful\n");
        }
    }

done:
    task->callback.completion(task->request_id, error, task->user_data);
}

/* ============================================================================
 * CONTACT NICKNAME (synchronous API)
 * ============================================================================ */

int dna_engine_set_contact_nickname_sync(
    dna_engine_t *engine,
    const char *fingerprint,
    const char *nickname
) {
    if (!engine) {
        return DNA_ENGINE_ERROR_NOT_INITIALIZED;
    }
    if (!fingerprint || strlen(fingerprint) != 128) {
        return DNA_ENGINE_ERROR_INVALID_PARAM;
    }
    if (!engine->identity_loaded) {
        return DNA_ENGINE_ERROR_NO_IDENTITY;
    }

    /* Initialize contacts DB if needed */
    if (contacts_db_init(engine->fingerprint) != 0) {
        return DNA_ENGINE_ERROR_DATABASE;
    }

    /* Check if contact exists */
    if (!contacts_db_exists(fingerprint)) {
        return DNA_ERROR_NOT_FOUND;
    }

    /* Update nickname in database */
    int result = contacts_db_update_nickname(fingerprint, nickname);
    if (result != 0) {
        return DNA_ENGINE_ERROR_DATABASE;
    }

    QGP_LOG_INFO(LOG_TAG, "Set nickname for %.16s... to '%s'\n",
                 fingerprint, nickname ? nickname : "(cleared)");
    return DNA_OK;
}

/* ============================================================================
 * CONTACT REQUEST TASK HANDLERS (ICQ-style)
 * ============================================================================ */

void dna_handle_send_contact_request(dna_engine_t *engine, dna_task_t *task) {
    int error = DNA_OK;
    qgp_key_t *privkey = NULL;

    QGP_LOG_INFO("DNA_ENGINE", "dna_handle_send_contact_request called for recipient: %.20s...",
                 task->params.send_contact_request.recipient);

    if (!engine->identity_loaded) {
        QGP_LOG_ERROR("DNA_ENGINE", "No identity loaded");
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
        goto done;
    }

    /* Get DHT context */
    dht_context_t *dht_ctx = dna_get_dht_ctx(engine);
    if (!dht_ctx) {
        error = DNA_ENGINE_ERROR_NETWORK;
        goto done;
    }

    /* Get sender keys */
    privkey = dna_load_private_key(engine);
    if (!privkey) {
        error = DNA_ENGINE_ERROR_DATABASE;
        goto done;
    }

    /* Get our registered display name from keyserver cache */
    char display_name_buf[64] = {0};
    char *display_name = NULL;
    if (keyserver_cache_get_name(engine->fingerprint, display_name_buf, sizeof(display_name_buf)) == 0 &&
        display_name_buf[0] != '\0') {
        display_name = display_name_buf;
    }

    /* Send the contact request via DHT */
    int rc = dht_send_contact_request(
        dht_ctx,
        engine->fingerprint,
        display_name,
        privkey->public_key,
        privkey->private_key,
        task->params.send_contact_request.recipient,
        task->params.send_contact_request.message[0] ? task->params.send_contact_request.message : NULL
    );

    if (rc != 0) {
        error = DNA_ENGINE_ERROR_NETWORK;
    }
    /* Contact will be added when the recipient approves and we approve their reciprocal request */

done:
    if (privkey) {
        qgp_key_free(privkey);
    }
    if (task->callback.completion) {
        task->callback.completion(task->request_id, error, task->user_data);
    }
}

void dna_handle_get_contact_requests(dna_engine_t *engine, dna_task_t *task) {
    int error = DNA_OK;
    dna_contact_request_t *requests = NULL;
    int count = 0;

    if (!engine->identity_loaded) {
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
        goto done;
    }

    /* Initialize contacts database */
    if (contacts_db_init(engine->fingerprint) != 0) {
        error = DNA_ENGINE_ERROR_DATABASE;
        goto done;
    }

    /* First, fetch new requests from DHT and store them */
    dht_context_t *dht_ctx = dna_get_dht_ctx(engine);
    bool contacts_changed = false;  /* Track if we need to sync */
    if (dht_ctx) {
        dht_contact_request_t *dht_requests = NULL;
        size_t dht_count = 0;

        if (dht_fetch_contact_requests(dht_ctx, engine->fingerprint, &dht_requests, &dht_count) == 0) {
            /* Store new requests in local database */
            for (size_t i = 0; i < dht_count; i++) {
                /* Skip if blocked */
                if (contacts_db_is_blocked(dht_requests[i].sender_fingerprint)) {
                    continue;
                }

                /* Skip if already a contact or already pending (avoids DHT lookups for old requests) */
                if (contacts_db_exists(dht_requests[i].sender_fingerprint) ||
                    contacts_db_request_exists(dht_requests[i].sender_fingerprint)) {
                    continue;
                }

                /* If sender_name is empty, lookup from DHT profile (reverse lookup) */
                char *looked_up_name = NULL;
                const char *sender_name = dht_requests[i].sender_name;
                if (sender_name[0] == '\0') {
                    QGP_LOG_INFO(LOG_TAG, "Sender name empty, doing reverse lookup for %.20s...",
                                 dht_requests[i].sender_fingerprint);
                    if (dht_keyserver_reverse_lookup(dht_ctx, dht_requests[i].sender_fingerprint,
                                                     &looked_up_name) == 0 && looked_up_name) {
                        sender_name = looked_up_name;
                        /* Cache the name for future use */
                        keyserver_cache_put_name(dht_requests[i].sender_fingerprint, looked_up_name, 0);
                        QGP_LOG_INFO(LOG_TAG, "Reverse lookup found: %s", looked_up_name);
                    }
                }

                /* Auto-approve reciprocal requests (they accepted our request) */
                if (dht_requests[i].message[0] &&
                    strcmp(dht_requests[i].message, CONTACT_ACCEPTED_MSG) == 0) {
                    QGP_LOG_INFO(LOG_TAG, "Auto-approving reciprocal request from %.20s...",
                                 dht_requests[i].sender_fingerprint);
                    /* Add directly as contact (notes = display name) */
                    contacts_db_add(
                        dht_requests[i].sender_fingerprint,
                        sender_name
                    );
                    contacts_changed = true;  /* Mark for sync AFTER loop */
                } else {
                    /* Regular request - add to pending */
                    contacts_db_add_incoming_request(
                        dht_requests[i].sender_fingerprint,
                        sender_name,
                        dht_requests[i].message,
                        dht_requests[i].timestamp
                    );
                }

                /* Free looked up name if allocated */
                if (looked_up_name) {
                    free(looked_up_name);
                }
            }
            dht_contact_requests_free(dht_requests, dht_count);
        }
    }

    /* Sync contacts to DHT ONCE after processing all requests */
    if (contacts_changed && engine->messenger) {
        QGP_LOG_WARN(LOG_TAG, "[CONTACTLIST_PUBLISH] auto_accept_requests: syncing ONCE after loop");
        messenger_sync_contacts_to_dht(engine->messenger);
    }

    /* Get all pending requests from database */
    incoming_request_t *db_requests = NULL;
    int db_count = 0;
    if (contacts_db_get_incoming_requests(&db_requests, &db_count) != 0) {
        error = DNA_ENGINE_ERROR_DATABASE;
        goto done;
    }

    /* Convert to dna_contact_request_t */
    if (db_count > 0) {
        requests = (dna_contact_request_t*)calloc(db_count, sizeof(dna_contact_request_t));
        if (!requests) {
            contacts_db_free_requests(db_requests, db_count);
            error = DNA_ENGINE_ERROR_DATABASE;
            goto done;
        }

        for (int i = 0; i < db_count; i++) {
            strncpy(requests[i].fingerprint, db_requests[i].fingerprint, 128);
            requests[i].fingerprint[128] = '\0';

            /* If display_name is empty, try reverse lookup from DHT */
            if (db_requests[i].display_name[0] == '\0' && dht_ctx) {
                char *looked_up_name = NULL;
                QGP_LOG_INFO("DNA_ENGINE", "DB request[%d] has empty name, doing reverse lookup", i);
                if (dht_keyserver_reverse_lookup(dht_ctx, db_requests[i].fingerprint,
                                                 &looked_up_name) == 0 && looked_up_name) {
                    strncpy(requests[i].display_name, looked_up_name, 63);
                    requests[i].display_name[63] = '\0';
                    /* Update the database for future retrievals */
                    contacts_db_update_request_name(db_requests[i].fingerprint, looked_up_name);
                    /* Cache for future use */
                    keyserver_cache_put_name(db_requests[i].fingerprint, looked_up_name, 0);
                    QGP_LOG_INFO("DNA_ENGINE", "Reverse lookup found: %s", looked_up_name);
                    free(looked_up_name);
                } else {
                    requests[i].display_name[0] = '\0';
                }
            } else {
                strncpy(requests[i].display_name, db_requests[i].display_name, 63);
                requests[i].display_name[63] = '\0';
            }

            strncpy(requests[i].message, db_requests[i].message, 255);
            requests[i].message[255] = '\0';
            requests[i].requested_at = db_requests[i].requested_at;
            requests[i].status = db_requests[i].status;
            QGP_LOG_INFO("DNA_ENGINE", "get_requests[%d]: fp='%.40s...' len=%zu name='%s'",
                         i, requests[i].fingerprint, strlen(requests[i].fingerprint), requests[i].display_name);
        }
        count = db_count;
    }

    contacts_db_free_requests(db_requests, db_count);

done:
    if (task->callback.contact_requests) {
        if (requests && count > 0) {
            QGP_LOG_INFO("DNA_ENGINE", "callback: ptr=%p, count=%d, first_fp='%.40s...'",
                         (void*)requests, count, requests[0].fingerprint);
        }
        task->callback.contact_requests(task->request_id, error, requests, count, task->user_data);
    }
    /* NOTE: Memory is freed by caller (Dart FFI) via dna_free_contact_requests() */
}

void dna_handle_approve_contact_request(dna_engine_t *engine, dna_task_t *task) {
    int error = DNA_OK;

    QGP_LOG_INFO("DNA_ENGINE", "handle_approve called: task fp='%.40s...' len=%zu",
                 task->params.contact_request.fingerprint,
                 strlen(task->params.contact_request.fingerprint));

    if (!engine->identity_loaded) {
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
        goto done;
    }

    if (contacts_db_init(engine->fingerprint) != 0) {
        error = DNA_ENGINE_ERROR_DATABASE;
        goto done;
    }

    /* Approve the request in database */
    QGP_LOG_INFO("DNA_ENGINE", "Calling contacts_db_approve_request with fp='%.40s...'",
                 task->params.contact_request.fingerprint);
    if (contacts_db_approve_request(task->params.contact_request.fingerprint) != 0) {
        error = DNA_ERROR_NOT_FOUND;
        goto done;
    }

    /* Start listeners for new contact (outbox, presence, ACK) */
    dna_engine_listen_outbox(engine, task->params.contact_request.fingerprint);
    dna_engine_start_presence_listener(engine, task->params.contact_request.fingerprint);
    dna_engine_start_ack_listener(engine, task->params.contact_request.fingerprint);

    /* Send a reciprocal request so they know we approved */
    dht_context_t *dht_ctx = dna_get_dht_ctx(engine);
    if (dht_ctx) {
        qgp_key_t *privkey = dna_load_private_key(engine);
        if (privkey) {
            /* Get our registered display name from keyserver cache */
            char display_name_buf[64] = {0};
            char *display_name = NULL;
            if (keyserver_cache_get_name(engine->fingerprint, display_name_buf, sizeof(display_name_buf)) == 0 &&
                display_name_buf[0] != '\0') {
                display_name = display_name_buf;
            }

            dht_send_contact_request(
                dht_ctx,
                engine->fingerprint,
                display_name,
                privkey->public_key,
                privkey->private_key,
                task->params.contact_request.fingerprint,
                CONTACT_ACCEPTED_MSG
            );
            qgp_key_free(privkey);
        }
    }

    /* Sync contacts to DHT */
    if (engine->messenger) {
        QGP_LOG_WARN(LOG_TAG, "[CONTACTLIST_PUBLISH] accept_contact_request: calling sync");
        messenger_sync_contacts_to_dht(engine->messenger);
    }

done:
    if (task->callback.completion) {
        task->callback.completion(task->request_id, error, task->user_data);
    }
}

void dna_handle_deny_contact_request(dna_engine_t *engine, dna_task_t *task) {
    int error = DNA_OK;

    if (!engine->identity_loaded) {
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
        goto done;
    }

    if (contacts_db_init(engine->fingerprint) != 0) {
        error = DNA_ENGINE_ERROR_DATABASE;
        goto done;
    }

    if (contacts_db_deny_request(task->params.contact_request.fingerprint) != 0) {
        error = DNA_ERROR_NOT_FOUND;
    }

done:
    if (task->callback.completion) {
        task->callback.completion(task->request_id, error, task->user_data);
    }
}

void dna_handle_block_user(dna_engine_t *engine, dna_task_t *task) {
    int error = DNA_OK;

    if (!engine->identity_loaded) {
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
        goto done;
    }

    if (contacts_db_init(engine->fingerprint) != 0) {
        error = DNA_ENGINE_ERROR_DATABASE;
        goto done;
    }

    int rc = contacts_db_block_user(
        task->params.block_user.fingerprint,
        task->params.block_user.reason[0] ? task->params.block_user.reason : NULL
    );

    if (rc == -2) {
        error = DNA_ENGINE_ERROR_ALREADY_EXISTS;
    } else if (rc != 0) {
        error = DNA_ENGINE_ERROR_DATABASE;
    }

done:
    if (task->callback.completion) {
        task->callback.completion(task->request_id, error, task->user_data);
    }
}

void dna_handle_unblock_user(dna_engine_t *engine, dna_task_t *task) {
    int error = DNA_OK;

    if (!engine->identity_loaded) {
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
        goto done;
    }

    if (contacts_db_init(engine->fingerprint) != 0) {
        error = DNA_ENGINE_ERROR_DATABASE;
        goto done;
    }

    if (contacts_db_unblock_user(task->params.unblock_user.fingerprint) != 0) {
        error = DNA_ERROR_NOT_FOUND;
    }

done:
    if (task->callback.completion) {
        task->callback.completion(task->request_id, error, task->user_data);
    }
}

void dna_handle_get_blocked_users(dna_engine_t *engine, dna_task_t *task) {
    int error = DNA_OK;
    dna_blocked_user_t *blocked = NULL;
    int count = 0;

    if (!engine->identity_loaded) {
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
        goto done;
    }

    if (contacts_db_init(engine->fingerprint) != 0) {
        error = DNA_ENGINE_ERROR_DATABASE;
        goto done;
    }

    blocked_user_t *db_blocked = NULL;
    int db_count = 0;
    if (contacts_db_get_blocked_users(&db_blocked, &db_count) != 0) {
        error = DNA_ENGINE_ERROR_DATABASE;
        goto done;
    }

    /* Convert to dna_blocked_user_t */
    if (db_count > 0) {
        blocked = (dna_blocked_user_t*)calloc(db_count, sizeof(dna_blocked_user_t));
        if (!blocked) {
            contacts_db_free_blocked(db_blocked, db_count);
            error = DNA_ENGINE_ERROR_DATABASE;
            goto done;
        }

        for (int i = 0; i < db_count; i++) {
            strncpy(blocked[i].fingerprint, db_blocked[i].fingerprint, 128);
            blocked[i].fingerprint[128] = '\0';
            blocked[i].blocked_at = db_blocked[i].blocked_at;
            strncpy(blocked[i].reason, db_blocked[i].reason, 255);
            blocked[i].reason[255] = '\0';
        }
        count = db_count;
    }

    contacts_db_free_blocked(db_blocked, db_count);

done:
    if (task->callback.blocked_users) {
        task->callback.blocked_users(task->request_id, error, blocked, count, task->user_data);
    }
    /* NOTE: Memory is freed by caller (Dart FFI) via dna_free_blocked_users() */
}
