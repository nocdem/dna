/*
 * DNA Engine - Groups Module
 *
 * Group management handlers extracted from dna_engine.c.
 * Contains group CRUD operations, conversations, invitations.
 *
 * Functions:
 *   - dna_handle_get_groups()
 *   - dna_handle_get_group_info()
 *   - dna_handle_get_group_members()
 *   - dna_handle_create_group()
 *   - dna_handle_send_group_message()
 *   - dna_handle_get_group_conversation()
 *   - dna_handle_add_group_member()
 *   - dna_handle_get_invitations()
 *   - dna_handle_accept_invitation()
 *   - dna_handle_reject_invitation()
 *
 * Note: Group subscription/rotation functions remain in dna_engine_unified.c
 * as they are used across modules.
 */

#define DNA_ENGINE_GROUPS_IMPL
#include "engine_includes.h"

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
        /* Sync all groups from DHT first to get latest data */
        dht_context_t *dht_ctx = dht_singleton_get();
        if (dht_ctx) {
            for (int i = 0; i < entry_count; i++) {
                dht_groups_sync_from_dht(dht_ctx, entries[i].group_uuid);
            }
        }

        /* Re-fetch after sync to get updated data */
        dht_groups_free_cache_entries(entries, entry_count);
        entries = NULL;
        entry_count = 0;
        if (dht_groups_list_for_user(engine->fingerprint, &entries, &entry_count) != 0) {
            error = DNA_ENGINE_ERROR_DATABASE;
            goto done;
        }

        groups = calloc(entry_count, sizeof(dna_group_t));
        if (!groups) {
            dht_groups_free_cache_entries(entries, entry_count);
            error = DNA_ERROR_INTERNAL;
            goto done;
        }

        for (int i = 0; i < entry_count; i++) {
            strncpy(groups[i].uuid, entries[i].group_uuid, sizeof(groups[i].uuid) - 1);
            strncpy(groups[i].name, entries[i].name, sizeof(groups[i].name) - 1);
            strncpy(groups[i].creator, entries[i].creator, sizeof(groups[i].creator) - 1);
            groups[i].created_at = entries[i].created_at;

            /* Get member count from dht_group_members table */
            int member_count = 0;
            if (dht_groups_get_member_count(entries[i].group_uuid, &member_count) == 0) {
                groups[i].member_count = member_count;
            } else {
                groups[i].member_count = 0;
            }
        }
        count = entry_count;

        dht_groups_free_cache_entries(entries, entry_count);
    }

done:
    task->callback.groups(task->request_id, error, groups, count, task->user_data);
    /* Note: caller (Flutter) owns the memory and frees via dna_free_groups() */
}

void dna_handle_get_group_info(dna_engine_t *engine, dna_task_t *task) {
    int error = DNA_OK;
    dna_group_info_t *info = NULL;
    dht_group_cache_entry_t *cache_entry = NULL;
    const char *group_uuid = task->params.get_group_info.group_uuid;

    if (!engine->identity_loaded) {
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
        goto done;
    }

    /* Sync from DHT first to get latest member list */
    dht_context_t *dht_ctx = dht_singleton_get();
    if (dht_ctx) {
        dht_groups_sync_from_dht(dht_ctx, group_uuid);
    }

    /* Get group from local cache (now up-to-date) */
    int rc = dht_groups_get_cache_entry(group_uuid, &cache_entry);
    if (rc != 0) {
        error = (rc == -2) ? DNA_ENGINE_ERROR_NOT_FOUND : DNA_ENGINE_ERROR_DATABASE;
        goto done;
    }

    info = calloc(1, sizeof(dna_group_info_t));
    if (!info) {
        error = DNA_ERROR_INTERNAL;
        goto done;
    }

    strncpy(info->uuid, cache_entry->group_uuid, sizeof(info->uuid) - 1);
    strncpy(info->name, cache_entry->name, sizeof(info->name) - 1);
    strncpy(info->creator, cache_entry->creator, sizeof(info->creator) - 1);
    info->created_at = cache_entry->created_at;

    /* Check if current user is the owner */
    info->is_owner = (strcmp(engine->fingerprint, cache_entry->creator) == 0);

    /* Get member count */
    int member_count = 0;
    dht_groups_get_member_count(group_uuid, &member_count);
    info->member_count = member_count;

    /* Get active GEK version */
    uint8_t gek[32];
    uint32_t gek_version = 0;
    if (gek_load_active(group_uuid, gek, &gek_version) == 0) {
        info->gek_version = gek_version;
        qgp_secure_memzero(gek, 32);
    }

done:
    if (cache_entry) free(cache_entry);
    task->callback.group_info(task->request_id, error, info, task->user_data);
}

void dna_handle_get_group_members(dna_engine_t *engine, dna_task_t *task) {
    int error = DNA_OK;
    dna_group_member_t *members = NULL;
    int count = 0;
    dht_group_cache_entry_t *cache_entry = NULL;
    char **dht_members = NULL;
    int dht_member_count = 0;
    const char *group_uuid = task->params.get_group_members.group_uuid;

    if (!engine->identity_loaded) {
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
        goto done;
    }

    /* Sync from DHT first to get latest member list */
    dht_context_t *dht_ctx = dht_singleton_get();
    if (dht_ctx) {
        dht_groups_sync_from_dht(dht_ctx, group_uuid);
    }

    /* Get group from local cache (now up-to-date) */
    int rc = dht_groups_get_cache_entry(group_uuid, &cache_entry);
    if (rc != 0) {
        error = (rc == -2) ? DNA_ENGINE_ERROR_NOT_FOUND : DNA_ENGINE_ERROR_DATABASE;
        goto done;
    }

    /* Get members from DHT group_members table */
    if (dht_groups_get_members(group_uuid, &dht_members, &dht_member_count) != 0 || dht_member_count == 0) {
        /* No members in DHT table, return just owner */
        members = calloc(1, sizeof(dna_group_member_t));
        if (members) {
            strncpy(members[0].fingerprint, cache_entry->creator, 128);
            members[0].added_at = cache_entry->created_at;
            members[0].is_owner = true;
            count = 1;
        }
        goto done;
    }

    /* Convert to dna_group_member_t */
    members = calloc(dht_member_count, sizeof(dna_group_member_t));
    if (!members) {
        dht_groups_free_members(dht_members, dht_member_count);
        error = DNA_ERROR_INTERNAL;
        goto done;
    }

    for (int i = 0; i < dht_member_count; i++) {
        strncpy(members[i].fingerprint, dht_members[i], 128);
        members[i].added_at = cache_entry->created_at;  /* DHT doesn't store per-member add time */
        members[i].is_owner = (strcmp(dht_members[i], cache_entry->creator) == 0);
    }
    count = dht_member_count;
    dht_groups_free_members(dht_members, dht_member_count);

done:
    if (cache_entry) free(cache_entry);
    task->callback.group_members(task->request_id, error, members, count, task->user_data);
}

void dna_handle_create_group(dna_engine_t *engine, dna_task_t *task) {
    int error = DNA_OK;
    char group_uuid[37] = {0};
    char *uuid_copy = NULL;  /* Heap-allocated for async callback */

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
        &group_id,
        group_uuid  /* Get real UUID */
    );

    if (rc != 0) {
        error = DNA_ERROR_INTERNAL;
        goto done;
    }

    /* Allocate heap copy for async callback (caller must free) */
    uuid_copy = strdup(group_uuid);

done:
    task->callback.group_created(task->request_id, error,
                                  uuid_copy,  /* Heap-allocated, callback must free */
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

void dna_handle_get_group_conversation(dna_engine_t *engine, dna_task_t *task) {
    int error = DNA_OK;
    dna_message_t *messages = NULL;
    int count = 0;

    if (!engine->identity_loaded || !engine->messenger) {
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
        goto done;
    }

    const char *group_uuid = task->params.get_group_conversation.group_uuid;

    /* Get group messages directly from group_messages table in groups.db */
    dna_group_message_t *group_msgs = NULL;
    size_t msg_count = 0;

    int rc = dna_group_outbox_db_get_messages(group_uuid, 0, 0, &group_msgs, &msg_count);

    if (rc != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to get group conversation: %d", rc);
        error = DNA_ENGINE_ERROR_DATABASE;
        goto done;
    }

    QGP_LOG_WARN(LOG_TAG, "[GROUP] Got %zu messages for group %s", msg_count, group_uuid);

    if (msg_count > 0) {
        messages = calloc(msg_count, sizeof(dna_message_t));
        if (!messages) {
            dna_group_outbox_free_messages(group_msgs, msg_count);
            error = DNA_ERROR_INTERNAL;
            goto done;
        }

        /* Messages from DB are in DESC order, reverse to ASC for UI */
        for (size_t i = 0; i < msg_count; i++) {
            size_t src_idx = msg_count - 1 - i;  /* Reverse order */
            dna_group_message_t *src = &group_msgs[src_idx];

            messages[i].id = (int64_t)i;  /* Use index as ID since message_id is string */
            strncpy(messages[i].sender, src->sender_fingerprint, 128);
            strncpy(messages[i].recipient, group_uuid, 36);

            /* Use decrypted plaintext */
            if (src->plaintext) {
                messages[i].plaintext = strdup(src->plaintext);
            } else {
                messages[i].plaintext = strdup("[Decryption failed]");
            }

            /* Convert timestamp_ms to seconds */
            messages[i].timestamp = src->timestamp_ms / 1000;

            /* Determine if outgoing */
            messages[i].is_outgoing = (strcmp(src->sender_fingerprint, engine->fingerprint) == 0);

            /* Group messages are always delivered */
            messages[i].status = 3;  /* delivered */
            messages[i].message_type = 0;  /* text */
        }
        count = (int)msg_count;

        dna_group_outbox_free_messages(group_msgs, msg_count);
    }

done:
    task->callback.messages(task->request_id, error, messages, count, task->user_data);
}

void dna_handle_add_group_member(dna_engine_t *engine, dna_task_t *task) {
    int error = DNA_OK;

    if (!engine->identity_loaded || !engine->messenger) {
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
        goto done;
    }

    /* Look up group_id from UUID using local cache */
    dht_group_cache_entry_t *entries = NULL;
    int entry_count = 0;
    if (dht_groups_list_for_user(engine->fingerprint, &entries, &entry_count) != 0) {
        error = DNA_ENGINE_ERROR_DATABASE;
        goto done;
    }

    int group_id = -1;
    for (int i = 0; i < entry_count; i++) {
        if (strcmp(entries[i].group_uuid, task->params.add_group_member.group_uuid) == 0) {
            group_id = entries[i].local_id;
            break;
        }
    }
    dht_groups_free_cache_entries(entries, entry_count);

    if (group_id < 0) {
        error = DNA_ENGINE_ERROR_NOT_FOUND;
        goto done;
    }

    /* Add member using messenger API */
    int rc = messenger_add_group_member(
        engine->messenger,
        group_id,
        task->params.add_group_member.fingerprint
    );

    if (rc == -3) {
        error = DNA_ENGINE_ERROR_ALREADY_EXISTS;  // Already a member
    } else if (rc != 0) {
        error = DNA_ENGINE_ERROR_NETWORK;
    }

done:
    task->callback.completion(task->request_id, error, task->user_data);
}

void dna_handle_remove_group_member(dna_engine_t *engine, dna_task_t *task) {
    int error = DNA_OK;

    if (!engine->identity_loaded || !engine->messenger) {
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
        goto done;
    }

    /* Look up group_id from UUID using local cache */
    dht_group_cache_entry_t *entries = NULL;
    int entry_count = 0;
    if (dht_groups_list_for_user(engine->fingerprint, &entries, &entry_count) != 0) {
        error = DNA_ENGINE_ERROR_DATABASE;
        goto done;
    }

    int group_id = -1;
    const char *group_creator = NULL;
    for (int i = 0; i < entry_count; i++) {
        if (strcmp(entries[i].group_uuid, task->params.add_group_member.group_uuid) == 0) {
            group_id = entries[i].local_id;
            group_creator = entries[i].creator;
            break;
        }
    }

    if (group_id < 0) {
        dht_groups_free_cache_entries(entries, entry_count);
        error = DNA_ENGINE_ERROR_NOT_FOUND;
        goto done;
    }

    /* Only owner can remove members */
    if (strcmp(engine->fingerprint, group_creator) != 0) {
        dht_groups_free_cache_entries(entries, entry_count);
        error = DNA_ENGINE_ERROR_PERMISSION;
        goto done;
    }

    dht_groups_free_cache_entries(entries, entry_count);

    /* Remove member using messenger API (handles GEK rotation) */
    int rc = messenger_remove_group_member(
        engine->messenger,
        group_id,
        task->params.add_group_member.fingerprint
    );

    if (rc == -2) {
        error = DNA_ENGINE_ERROR_NOT_FOUND;  /* Not a member */
    } else if (rc != 0) {
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

    QGP_LOG_DEBUG(LOG_TAG, "Accept invitation: group=%s", task->params.invitation.group_uuid);

    if (!engine->identity_loaded || !engine->messenger) {
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
        goto done;
    }

    int rc = messenger_accept_group_invitation(
        engine->messenger,
        task->params.invitation.group_uuid
    );

    if (rc != 0) {
        QGP_LOG_WARN(LOG_TAG, "Accept invitation failed: group=%s, rc=%d",
                     task->params.invitation.group_uuid, rc);
        error = DNA_ENGINE_ERROR_NETWORK;
    } else {
        /* Subscribe to the newly accepted group for real-time messages */
        dna_engine_subscribe_all_groups(engine);
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
 * PUBLIC API - Groups Functions
 * ============================================================================ */

dna_request_id_t dna_engine_get_groups(
    dna_engine_t *engine,
    dna_groups_cb callback,
    void *user_data
) {
    if (!engine || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_callback_t cb = { .groups = callback };
    return dna_submit_task(engine, TASK_GET_GROUPS, NULL, cb, user_data);
}

dna_request_id_t dna_engine_get_group_info(
    dna_engine_t *engine,
    const char *group_uuid,
    dna_group_info_cb callback,
    void *user_data
) {
    if (!engine || !group_uuid || !callback) return DNA_REQUEST_ID_INVALID;
    if (strlen(group_uuid) != 36) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.get_group_info.group_uuid, group_uuid, 36);

    dna_task_callback_t cb = { .group_info = callback };
    return dna_submit_task(engine, TASK_GET_GROUP_INFO, &params, cb, user_data);
}

dna_request_id_t dna_engine_get_group_members(
    dna_engine_t *engine,
    const char *group_uuid,
    dna_group_members_cb callback,
    void *user_data
) {
    if (!engine || !group_uuid || !callback) return DNA_REQUEST_ID_INVALID;
    if (strlen(group_uuid) != 36) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.get_group_members.group_uuid, group_uuid, 36);

    dna_task_callback_t cb = { .group_members = callback };
    return dna_submit_task(engine, TASK_GET_GROUP_MEMBERS, &params, cb, user_data);
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

dna_request_id_t dna_engine_get_group_conversation(
    dna_engine_t *engine,
    const char *group_uuid,
    dna_messages_cb callback,
    void *user_data
) {
    if (!engine || !group_uuid || !callback) {
        return DNA_REQUEST_ID_INVALID;
    }

    dna_task_params_t params = {0};
    strncpy(params.get_group_conversation.group_uuid, group_uuid, 36);

    dna_task_callback_t cb = { .messages = callback };
    return dna_submit_task(engine, TASK_GET_GROUP_CONVERSATION, &params, cb, user_data);
}

dna_request_id_t dna_engine_add_group_member(
    dna_engine_t *engine,
    const char *group_uuid,
    const char *fingerprint,
    dna_completion_cb callback,
    void *user_data
) {
    if (!engine || !group_uuid || !fingerprint || !callback) {
        return DNA_REQUEST_ID_INVALID;
    }

    dna_task_params_t params = {0};
    strncpy(params.add_group_member.group_uuid, group_uuid, 36);
    strncpy(params.add_group_member.fingerprint, fingerprint, 128);

    dna_task_callback_t cb = { .completion = callback };
    return dna_submit_task(engine, TASK_ADD_GROUP_MEMBER, &params, cb, user_data);
}

dna_request_id_t dna_engine_remove_group_member(
    dna_engine_t *engine,
    const char *group_uuid,
    const char *fingerprint,
    dna_completion_cb callback,
    void *user_data
) {
    if (!engine || !group_uuid || !fingerprint || !callback) {
        return DNA_REQUEST_ID_INVALID;
    }

    dna_task_params_t params = {0};
    strncpy(params.add_group_member.group_uuid, group_uuid, 36);
    strncpy(params.add_group_member.fingerprint, fingerprint, 128);

    dna_task_callback_t cb = { .completion = callback };
    return dna_submit_task(engine, TASK_REMOVE_GROUP_MEMBER, &params, cb, user_data);
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
