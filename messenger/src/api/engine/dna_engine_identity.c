/*
 * DNA Engine - Identity Module
 *
 * Contains identity management handlers:
 *   - dna_handle_create_identity()
 *   - dna_handle_load_identity()
 *   - dna_handle_register_name()
 *   - dna_handle_get_display_name()
 *   - dna_handle_get_avatar()
 *   - dna_handle_lookup_name()
 *   - dna_handle_get_profile()
 *   - dna_handle_lookup_profile()
 *   - dna_handle_refresh_contact_profile()
 *   - dna_handle_update_profile()
 *
 * STATUS: EXTRACTED - Functions moved from dna_engine.c
 */

#define DNA_ENGINE_IDENTITY_IMPL

#include "engine_includes.h"

/* ============================================================================
 * IDENTITY TASK HANDLERS
 * ============================================================================ */

/* v0.3.0: dna_scan_identities() and dna_handle_list_identities() removed
 * Single-user model - use dna_engine_has_identity() instead */

void dna_handle_create_identity(dna_engine_t *engine, dna_task_t *task) {
    char fingerprint_buf[129] = {0};

    int rc = messenger_generate_keys_from_seeds(
        task->params.create_identity.name,
        task->params.create_identity.signing_seed,
        task->params.create_identity.encryption_seed,
        task->params.create_identity.master_seed,  /* master_seed - for ETH/SOL wallets */
        task->params.create_identity.mnemonic,     /* mnemonic - for Cellframe wallet */
        engine->data_dir,
        task->params.create_identity.password,     /* password for key encryption */
        fingerprint_buf
    );

    int error = DNA_OK;
    char *fingerprint = NULL;
    if (rc != 0) {
        error = DNA_ERROR_CRYPTO;
    } else {
        /* Allocate on heap - caller must free via dna_free_string */
        fingerprint = strdup(fingerprint_buf);
        /* Mark profile as just published - skip DHT verification in load_identity */
        engine->profile_published_at = time(NULL);
    }

    task->callback.identity_created(
        task->request_id,
        error,
        fingerprint,
        task->user_data
    );
}

void dna_handle_load_identity(dna_engine_t *engine, dna_task_t *task) {
    const char *password = task->params.load_identity.password;
    int error = DNA_OK;

    /* v0.3.0: Compute fingerprint from flat key file if not provided */
    char fingerprint_buf[129] = {0};
    const char *fingerprint = task->params.load_identity.fingerprint;
    if (!fingerprint || fingerprint[0] == '\0' || strlen(fingerprint) != 128) {
        /* Compute from identity.dsa */
        if (messenger_compute_identity_fingerprint(NULL, fingerprint_buf) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "No identity found - cannot compute fingerprint");
            error = DNA_ENGINE_ERROR_NO_IDENTITY;
            goto done;
        }
        fingerprint = fingerprint_buf;
        QGP_LOG_INFO(LOG_TAG, "v0.3.0: Computed fingerprint from flat key file");
    }

    /* v0.6.0+: Acquire identity lock (single-owner model)
     * Prevents Flutter and ForegroundService from running simultaneously */
    if (engine->identity_lock_fd < 0) {
        engine->identity_lock_fd = qgp_platform_acquire_identity_lock(engine->data_dir);
        if (engine->identity_lock_fd < 0) {
            QGP_LOG_WARN(LOG_TAG, "Identity lock held by another process - cannot load");
            error = DNA_ENGINE_ERROR_IDENTITY_LOCKED;
            goto done;
        }
        QGP_LOG_INFO(LOG_TAG, "v0.6.0+: Identity lock acquired (fd=%d)", engine->identity_lock_fd);
    }

    /* Free existing session password if any */
    if (engine->session_password) {
        /* Secure clear before freeing */
        qgp_secure_memzero(engine->session_password, strlen(engine->session_password));
        free(engine->session_password);
        engine->session_password = NULL;
    }
    engine->keys_encrypted = false;

    /* Free existing messenger context if any */
    if (engine->messenger) {
        messenger_free(engine->messenger);
        engine->messenger = NULL;
        engine->identity_loaded = false;
        engine->state = DNA_ENGINE_STATE_UNLOADED;
    }

    /* Check if keys are encrypted and validate password */
    /* v0.3.0: Flat structure - keys/identity.kem */
    {
        char kem_path[512];
        snprintf(kem_path, sizeof(kem_path), "%s/keys/identity.kem", engine->data_dir);

        bool is_encrypted = qgp_key_file_is_encrypted(kem_path);
        engine->keys_encrypted = is_encrypted;

        if (is_encrypted) {
            if (!password) {
                QGP_LOG_ERROR(LOG_TAG, "Identity keys are encrypted but no password provided");
                error = DNA_ENGINE_ERROR_PASSWORD_REQUIRED;
                goto done;
            }

            /* Verify password by attempting to load key */
            qgp_key_t *test_key = NULL;
            int load_rc = qgp_key_load_encrypted(kem_path, password, &test_key);
            if (load_rc != 0 || !test_key) {
                QGP_LOG_ERROR(LOG_TAG, "Failed to decrypt keys - incorrect password");
                error = DNA_ENGINE_ERROR_WRONG_PASSWORD;
                goto done;
            }
            qgp_key_free(test_key);

            /* Store password for session (needed for sensitive operations) */
            engine->session_password = strdup(password);
            QGP_LOG_INFO(LOG_TAG, "Loaded password-protected identity");
        } else {
            QGP_LOG_INFO(LOG_TAG, "Loaded unprotected identity");
        }
    }

    /* Initialize messenger with fingerprint */
    engine->messenger = messenger_init(fingerprint);
    if (!engine->messenger) {
        error = DNA_ENGINE_ERROR_INIT;
        goto done;
    }

    /* Pass session password to messenger for encrypted key operations (v0.2.17+) */
    if (engine->keys_encrypted && engine->session_password) {
        messenger_set_session_password(engine->messenger, engine->session_password);
    }

    /* Copy fingerprint */
    strncpy(engine->fingerprint, fingerprint, 128);
    engine->fingerprint[128] = '\0';

    /* v0.6.0+: Load DHT identity and create engine-owned context */
    if (messenger_load_dht_identity_for_engine(fingerprint, &engine->dht_ctx) == 0) {
        QGP_LOG_INFO(LOG_TAG, "Engine-owned DHT context created");
        /* Lend context to singleton for backwards compatibility with code that
         * still uses dht_singleton_get() directly */
        dht_singleton_set_borrowed_context(engine->dht_ctx);
    } else {
        QGP_LOG_WARN(LOG_TAG, "Failed to create engine DHT context (falling back to singleton)");
        /* Fallback: try singleton-based load for compatibility */
        messenger_load_dht_identity(fingerprint);
    }

    /* Load KEM keys for GEK encryption (H3 security fix) */
    {
        char kem_path[512];
        snprintf(kem_path, sizeof(kem_path), "%s/keys/identity.kem", engine->data_dir);

        qgp_key_t *kem_key = NULL;
        int load_rc;
        if (engine->keys_encrypted && engine->session_password) {
            load_rc = qgp_key_load_encrypted(kem_path, engine->session_password, &kem_key);
        } else {
            load_rc = qgp_key_load(kem_path, &kem_key);
        }

        if (load_rc == 0 && kem_key && kem_key->public_key && kem_key->private_key) {
            if (gek_set_kem_keys(kem_key->public_key, kem_key->private_key) == 0) {
                QGP_LOG_INFO(LOG_TAG, "GEK KEM keys set successfully");
            } else {
                QGP_LOG_WARN(LOG_TAG, "Warning: Failed to set GEK KEM keys");
            }
            qgp_key_free(kem_key);
        } else {
            QGP_LOG_WARN(LOG_TAG, "Warning: Failed to load KEM keys for GEK encryption");
            if (kem_key) qgp_key_free(kem_key);
        }
    }

    /* Initialize contacts database BEFORE P2P/offline message check
     * This is required because offline message check queries contacts' outboxes */
    if (contacts_db_init(fingerprint) != 0) {
        QGP_LOG_INFO(LOG_TAG, "Warning: Failed to initialize contacts database\n");
        /* Non-fatal - continue, contacts will be initialized on first access */
    }

    /* Initialize group invitations database BEFORE P2P message processing
     * Required for storing incoming group invitations from P2P messages */
    if (group_invitations_init(fingerprint) != 0) {
        QGP_LOG_INFO(LOG_TAG, "Warning: Failed to initialize group invitations database\n");
        /* Non-fatal - continue, invitations will be initialized on first access */
    }

    /* Profile cache is now global - initialized in dna_engine_create() */

    /* Check if minimal mode (background service) - skip heavy initialization */
    bool minimal_mode = task->params.load_identity.minimal;
    if (minimal_mode) {
        QGP_LOG_INFO(LOG_TAG, "Minimal mode: skipping transport, presence, wallet init");
    }

    /* v0.6.54+: Contacts and GEKs are now synced in background after DHT stabilizes
     * (in dna_engine_stabilization_retry_thread). This makes identity load non-blocking.
     * Local SQLite cache is shown immediately, DHT sync happens in background. */

    /* Initialize P2P transport for DHT and messaging
     * - Full mode: includes presence registration + heartbeat
     * - Minimal mode: transport only for polling (no presence) */
    if (messenger_transport_init(engine->messenger, minimal_mode) != 0) {
        QGP_LOG_INFO(LOG_TAG, "Warning: Failed to initialize P2P transport");
        /* Non-fatal - continue without P2P, DHT operations will still work via singleton */
    } else if (!minimal_mode) {
        /* Full mode only: Start presence heartbeat thread (announces every 4 minutes) */
        if (dna_start_presence_heartbeat(engine) != 0) {
            QGP_LOG_WARN(LOG_TAG, "Warning: Failed to start presence heartbeat");
        }
    }

    /* Mark identity as loaded and set state to ACTIVE
     * BEFORE starting listeners (they check this flag) */
    engine->identity_loaded = true;
    engine->state = DNA_ENGINE_STATE_ACTIVE;
    QGP_LOG_WARN(LOG_TAG, "[LISTEN] Identity loaded, state=ACTIVE");

    /* v0.6.13+: Minimal mode skips ALL listeners (battery-optimized polling).
     * Full mode: start contact request listener and group subscriptions. */
    if (engine->messenger && !minimal_mode) {
        QGP_LOG_INFO(LOG_TAG, "[LISTEN] Full mode: starting listeners");
        dna_engine_start_contact_request_listener(engine);

        int group_count = dna_engine_subscribe_all_groups(engine);
        QGP_LOG_INFO(LOG_TAG, "[LISTEN] Subscribed to %d groups", group_count);

        /* Full mode only: Retry pending messages and spawn stabilization thread */
        {
            /* 3. Retry any pending/failed messages from previous sessions
             * Messages may have been queued while offline or failed to send.
             * Now that DHT is connected, retry them. */
            int retried = dna_engine_retry_pending_messages(engine);
            if (retried > 0) {
                QGP_LOG_INFO(LOG_TAG, "[RETRY] Identity load: retried %d pending messages", retried);
            }

            /* Spawn post-stabilization retry thread.
             * DHT callback's listener thread only spawns if identity_loaded was true
             * when callback fired. In the common case (DHT connects before identity
             * loads), we need this dedicated thread to retry after routing table fills.
             * v0.6.0+: Track thread for clean shutdown (no detach) */
            QGP_LOG_WARN(LOG_TAG, "[RETRY] About to spawn stabilization thread (engine=%p, messenger=%p)",
                         (void*)engine, (void*)engine->messenger);
            pthread_mutex_lock(&engine->background_threads_mutex);
            if (engine->stabilization_retry_running) {
                /* Previous thread still running - skip */
                pthread_mutex_unlock(&engine->background_threads_mutex);
                QGP_LOG_WARN(LOG_TAG, "[RETRY] Stabilization thread already running, skipping");
            } else {
                engine->stabilization_retry_running = true;
                pthread_mutex_unlock(&engine->background_threads_mutex);
                int spawn_rc = pthread_create(&engine->stabilization_retry_thread, NULL,
                                              dna_engine_stabilization_retry_thread, engine);
                QGP_LOG_WARN(LOG_TAG, "[RETRY] pthread_create returned %d", spawn_rc);
                if (spawn_rc == 0) {
                    QGP_LOG_WARN(LOG_TAG, "[RETRY] Stabilization thread spawned successfully");
                } else {
                    pthread_mutex_lock(&engine->background_threads_mutex);
                    engine->stabilization_retry_running = false;
                    pthread_mutex_unlock(&engine->background_threads_mutex);
                    QGP_LOG_ERROR(LOG_TAG, "[RETRY] FAILED to spawn stabilization thread: rc=%d", spawn_rc);
                }
            }
        }

        /* Note: Delivery confirmation is now handled by persistent ACK listeners (v15)
         * started in dna_engine_listen_all_contacts() for each contact. */
    }

    /* Full mode only: Create any missing blockchain wallets
     * This uses the encrypted seed stored during identity creation.
     * Non-fatal if seed doesn't exist or wallet creation fails.
     * v0.3.0: Flat structure - keys/identity.kem */
    if (!minimal_mode) {
        char kyber_path[512];
        snprintf(kyber_path, sizeof(kyber_path), "%s/keys/identity.kem", engine->data_dir);

        qgp_key_t *kem_key = NULL;
        int load_rc;
        if (engine->keys_encrypted && engine->session_password) {
            load_rc = qgp_key_load_encrypted(kyber_path, engine->session_password, &kem_key);
        } else {
            load_rc = qgp_key_load(kyber_path, &kem_key);
        }

        if (load_rc == 0 && kem_key &&
            kem_key->private_key && kem_key->private_key_size == 3168) {

            int wallets_created = 0;
            if (blockchain_create_missing_wallets(fingerprint, kem_key->private_key, &wallets_created) == 0) {
                if (wallets_created > 0) {
                    QGP_LOG_INFO(LOG_TAG, "Auto-created %d missing blockchain wallets", wallets_created);
                }
            }
            qgp_key_free(kem_key);
        }
    }

    /* NOTE: Removed blocking DHT profile verification (v0.3.141)
     *
     * Previously, this code did a blocking 30-second DHT lookup of OUR OWN
     * profile to verify it exists and has wallet addresses. This caused the
     * app to hang for 30 seconds on startup if the profile wasn't in DHT.
     *
     * Profile is now published on:
     * - Account creation (keygen)
     * - Name registration
     * - Profile edit
     *
     * If the profile is missing from DHT, user can re-register name or
     * edit profile to republish. No need for blocking verification on startup.
     */
    (void)0;  /* Empty statement to satisfy compiler */

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
    } else {
        /* Cache the registered name to SQLite for identity selector */
        keyserver_cache_put_name(engine->fingerprint, task->params.register_name.name, 0);
        QGP_LOG_INFO(LOG_TAG, "Name registered and cached: %.16s... -> %s\n",
               engine->fingerprint, task->params.register_name.name);
    }

done:
    task->callback.completion(task->request_id, error, task->user_data);
}

void dna_handle_get_display_name(dna_engine_t *engine, dna_task_t *task) {
    (void)engine;
    char display_name_buf[256] = {0};
    int error = DNA_OK;
    char *display_name = NULL;
    const char *fingerprint = task->params.get_display_name.fingerprint;

    /* Use profile_manager (cache first, then DHT) */
    dna_unified_identity_t *identity = NULL;
    int rc = profile_manager_get_profile(fingerprint, &identity);

    if (rc == 0 && identity) {
        if (identity->registered_name[0] != '\0') {
            strncpy(display_name_buf, identity->registered_name, sizeof(display_name_buf) - 1);
        } else {
            /* No registered name - use shortened fingerprint */
            snprintf(display_name_buf, sizeof(display_name_buf), "%.16s...", fingerprint);
        }
        dna_identity_free(identity);
    } else {
        /* Profile not found - use shortened fingerprint */
        snprintf(display_name_buf, sizeof(display_name_buf), "%.16s...", fingerprint);
    }

    /* Allocate on heap for thread-safe callback - caller frees via dna_free_string */
    display_name = strdup(display_name_buf);
    task->callback.display_name(task->request_id, error, display_name, task->user_data);
}

void dna_handle_get_avatar(dna_engine_t *engine, dna_task_t *task) {
    (void)engine;
    int error = DNA_OK;
    char *avatar = NULL;
    const char *fingerprint = task->params.get_avatar.fingerprint;

    /* Use profile_manager (cache first, then DHT) */
    dna_unified_identity_t *identity = NULL;
    int rc = profile_manager_get_profile(fingerprint, &identity);

    if (rc == 0 && identity) {
        if (identity->avatar_base64[0] != '\0') {
            avatar = strdup(identity->avatar_base64);
        }
        dna_identity_free(identity);
    }

    /* avatar may be NULL if no avatar set - that's OK */
    task->callback.display_name(task->request_id, error, avatar, task->user_data);
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

    QGP_LOG_DEBUG(LOG_TAG, "[AVATAR_DEBUG] dna_handle_get_profile called\n");

    if (!engine->identity_loaded || !engine->messenger) {
        QGP_LOG_DEBUG(LOG_TAG, "[AVATAR_DEBUG] get_profile: no identity loaded\n");
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
        goto done;
    }

    /* Get DHT context (needed for auto-publish later if wallet changed) */
    dht_context_t *dht = dna_get_dht_ctx(engine);

    /* Get own identity (cache first, then DHT via profile_manager) */
    dna_unified_identity_t *identity = NULL;
    int rc = profile_manager_get_profile(engine->fingerprint, &identity);

    if (rc != 0 || !identity) {
        if (rc == -2) {
            /* No profile yet - create empty profile, will auto-populate wallets below */
            profile = (dna_profile_t*)calloc(1, sizeof(dna_profile_t));
            if (!profile) {
                error = DNA_ERROR_INTERNAL;
                goto done;
            }
            goto populate_wallets;
        } else {
            error = DNA_ENGINE_ERROR_NETWORK;
            goto done;
        }
    }

    /* Copy identity data to profile struct */
    profile = (dna_profile_t*)calloc(1, sizeof(dna_profile_t));
    if (!profile) {
        error = DNA_ERROR_INTERNAL;
        dna_identity_free(identity);
        goto done;
    }

    /* Wallets - copy from DHT identity */
    strncpy(profile->backbone, identity->wallets.backbone, sizeof(profile->backbone) - 1);
    strncpy(profile->eth, identity->wallets.eth, sizeof(profile->eth) - 1);
    strncpy(profile->sol, identity->wallets.sol, sizeof(profile->sol) - 1);
    strncpy(profile->trx, identity->wallets.trx, sizeof(profile->trx) - 1);

    /* Socials */
    strncpy(profile->telegram, identity->socials.telegram, sizeof(profile->telegram) - 1);
    strncpy(profile->twitter, identity->socials.x, sizeof(profile->twitter) - 1);
    strncpy(profile->github, identity->socials.github, sizeof(profile->github) - 1);

    /* Bio and avatar */
    strncpy(profile->bio, identity->bio, sizeof(profile->bio) - 1);
    strncpy(profile->avatar_base64, identity->avatar_base64, sizeof(profile->avatar_base64) - 1);

    /* NOTE: display_name field removed in v0.6.24 - use registered_name only */

    /* Location and website */
    strncpy(profile->location, identity->location, sizeof(profile->location) - 1);
    strncpy(profile->website, identity->website, sizeof(profile->website) - 1);

    /* DEBUG: Log avatar data after copy to profile (WARN level to ensure visibility) */
    {
        size_t src_len = identity->avatar_base64[0] ? strlen(identity->avatar_base64) : 0;
        size_t dst_len = profile->avatar_base64[0] ? strlen(profile->avatar_base64) : 0;
        (void)src_len; (void)dst_len;  // Used only in debug builds
        QGP_LOG_DEBUG(LOG_TAG, "[AVATAR_DEBUG] get_profile: src_len=%zu, dst_len=%zu (first 20: %.20s)\n",
                     src_len, dst_len, dst_len > 0 ? profile->avatar_base64 : "(empty)");
    }

    dna_identity_free(identity);

populate_wallets:
    /* Auto-populate empty wallet fields from actual wallet files */
    {
        bool wallets_changed = false;
        blockchain_wallet_list_t *bc_wallets = NULL;
        if (blockchain_list_wallets(engine->fingerprint, &bc_wallets) == 0 && bc_wallets) {
            for (size_t i = 0; i < bc_wallets->count; i++) {
                blockchain_wallet_info_t *w = &bc_wallets->wallets[i];
                switch (w->type) {
                    case BLOCKCHAIN_CELLFRAME:
                        if (profile->backbone[0] == '\0' && w->address[0]) {
                            strncpy(profile->backbone, w->address, sizeof(profile->backbone) - 1);
                            wallets_changed = true;
                        }
                        break;
                    case BLOCKCHAIN_ETHEREUM:
                        if (profile->eth[0] == '\0' && w->address[0]) {
                            strncpy(profile->eth, w->address, sizeof(profile->eth) - 1);
                            wallets_changed = true;
                        }
                        break;
                    case BLOCKCHAIN_SOLANA:
                        if (profile->sol[0] == '\0' && w->address[0]) {
                            strncpy(profile->sol, w->address, sizeof(profile->sol) - 1);
                            wallets_changed = true;
                        }
                        break;
                    case BLOCKCHAIN_TRON:
                        if (profile->trx[0] == '\0' && w->address[0]) {
                            strncpy(profile->trx, w->address, sizeof(profile->trx) - 1);
                            wallets_changed = true;
                        }
                        break;
                    default:
                        break;
                }
            }
            blockchain_wallet_list_free(bc_wallets);
        }

        /* Auto-publish profile if wallets were populated */
        if (wallets_changed) {
            QGP_LOG_WARN(LOG_TAG, "[PROFILE_PUBLISH] get_profile: wallets changed, auto-publishing");

            /* Load keys for signing */
            qgp_key_t *sign_key = dna_load_private_key(engine);
            if (sign_key) {
                qgp_key_t *enc_key = dna_load_encryption_key(engine);
                if (enc_key) {
                    /* Update profile in DHT - profile is already a dna_profile_t* */
                    int update_rc = dna_update_profile(dht, engine->fingerprint, profile,
                                                       sign_key->private_key, sign_key->public_key,
                                                       enc_key->public_key);
                    if (update_rc == 0) {
                        QGP_LOG_INFO(LOG_TAG, "Profile auto-published with wallet addresses");
                    } else {
                        QGP_LOG_WARN(LOG_TAG, "Failed to auto-publish profile: %d", update_rc);
                    }
                    qgp_key_free(enc_key);
                }
                qgp_key_free(sign_key);
            }
        }
    }

done:
    /* DEBUG: Log before callback */
    if (profile) {
        size_t avatar_len = profile->avatar_base64[0] ? strlen(profile->avatar_base64) : 0;
        (void)avatar_len;  // Used only in debug builds
        QGP_LOG_DEBUG(LOG_TAG, "[AVATAR_DEBUG] get_profile CALLBACK: error=%d, avatar_len=%zu\n", error, avatar_len);
    } else {
        QGP_LOG_DEBUG(LOG_TAG, "[AVATAR_DEBUG] get_profile CALLBACK: error=%d, profile=NULL\n", error);
    }
    task->callback.profile(task->request_id, error, profile, task->user_data);
}

/**
 * Auto-republish own profile when signature verification fails
 * This happens when profile format changes (e.g., displayName removal in v0.6.24)
 * The old profile in DHT has a signature over different JSON, so we need to re-sign.
 */
static void dna_auto_republish_own_profile(dna_engine_t *engine) {
    if (!engine || !engine->identity_loaded) return;

    QGP_LOG_WARN(LOG_TAG, "[AUTO-REPUBLISH] Own profile signature invalid, republishing...");

    dht_context_t *dht = dna_get_dht_ctx(engine);
    if (!dht) {
        QGP_LOG_ERROR(LOG_TAG, "[AUTO-REPUBLISH] No DHT context");
        return;
    }

    /* Load profile from local cache */
    dna_unified_identity_t *cached = NULL;
    uint64_t cached_at = 0;
    int cache_rc = profile_cache_get(engine->fingerprint, &cached, &cached_at);

    if (cache_rc != 0 || !cached) {
        /* No cached profile - create minimal one */
        QGP_LOG_WARN(LOG_TAG, "[AUTO-REPUBLISH] No cached profile, creating minimal");
        cached = (dna_unified_identity_t*)calloc(1, sizeof(dna_unified_identity_t));
        if (!cached) return;
        strncpy(cached->fingerprint, engine->fingerprint, sizeof(cached->fingerprint) - 1);
    }

    /* Build dna_profile_t from cached identity */
    dna_profile_t profile = {0};
    strncpy(profile.backbone, cached->wallets.backbone, sizeof(profile.backbone) - 1);
    strncpy(profile.alvin, cached->wallets.alvin, sizeof(profile.alvin) - 1);
    strncpy(profile.eth, cached->wallets.eth, sizeof(profile.eth) - 1);
    strncpy(profile.sol, cached->wallets.sol, sizeof(profile.sol) - 1);
    strncpy(profile.trx, cached->wallets.trx, sizeof(profile.trx) - 1);
    strncpy(profile.telegram, cached->socials.telegram, sizeof(profile.telegram) - 1);
    strncpy(profile.twitter, cached->socials.x, sizeof(profile.twitter) - 1);
    strncpy(profile.github, cached->socials.github, sizeof(profile.github) - 1);
    strncpy(profile.facebook, cached->socials.facebook, sizeof(profile.facebook) - 1);
    strncpy(profile.instagram, cached->socials.instagram, sizeof(profile.instagram) - 1);
    strncpy(profile.linkedin, cached->socials.linkedin, sizeof(profile.linkedin) - 1);
    strncpy(profile.google, cached->socials.google, sizeof(profile.google) - 1);
    strncpy(profile.bio, cached->bio, sizeof(profile.bio) - 1);
    strncpy(profile.location, cached->location, sizeof(profile.location) - 1);
    strncpy(profile.website, cached->website, sizeof(profile.website) - 1);
    strncpy(profile.avatar_base64, cached->avatar_base64, sizeof(profile.avatar_base64) - 1);

    dna_identity_free(cached);

    /* Load keys for signing */
    qgp_key_t *sign_key = dna_load_private_key(engine);
    if (!sign_key) {
        QGP_LOG_ERROR(LOG_TAG, "[AUTO-REPUBLISH] Failed to load signing key");
        return;
    }

    qgp_key_t *enc_key = dna_load_encryption_key(engine);
    if (!enc_key) {
        QGP_LOG_ERROR(LOG_TAG, "[AUTO-REPUBLISH] Failed to load encryption key");
        qgp_key_free(sign_key);
        return;
    }

    /* Republish with fresh signature */
    int rc = dna_update_profile(dht, engine->fingerprint, &profile,
                                sign_key->private_key, sign_key->public_key,
                                enc_key->public_key);

    qgp_key_free(sign_key);
    qgp_key_free(enc_key);

    if (rc == 0) {
        QGP_LOG_INFO(LOG_TAG, "[AUTO-REPUBLISH] Profile republished successfully");
    } else {
        QGP_LOG_ERROR(LOG_TAG, "[AUTO-REPUBLISH] Failed to republish: %d", rc);
    }
}

void dna_handle_lookup_profile(dna_engine_t *engine, dna_task_t *task) {
    int error = DNA_OK;
    dna_profile_t *profile = NULL;

    /* lookupProfile only needs DHT context - it can lookup ANY profile by fingerprint
     * without requiring local identity to be loaded. This is needed for the restore
     * flow where we check if a profile exists in DHT before identity is loaded. */
    dht_context_t *dht = dna_get_dht_ctx(engine);
    if (!dht) {
        error = DNA_ENGINE_ERROR_NETWORK;
        goto done;
    }

    const char *fingerprint = task->params.lookup_profile.fingerprint;
    if (!fingerprint || strlen(fingerprint) != 128) {
        error = DNA_ENGINE_ERROR_INVALID_PARAM;
        goto done;
    }

    /* Get identity (cache first, then DHT via profile_manager) */
    dna_unified_identity_t *identity = NULL;
    int rc = profile_manager_get_profile(fingerprint, &identity);

    if (rc != 0 || !identity) {
        if (rc == -2) {
            /* Profile not found */
            error = DNA_ENGINE_ERROR_NOT_FOUND;
        } else if (rc == -3) {
            /* Signature verification failed - corrupted or stale DHT data */
            /* Check if this is our own profile - if so, auto-republish */
            if (engine->identity_loaded && engine->fingerprint[0] &&
                strcmp(fingerprint, engine->fingerprint) == 0) {
                QGP_LOG_WARN(LOG_TAG, "Own profile signature invalid - triggering auto-republish");
                dna_auto_republish_own_profile(engine);
                /* Return network error to trigger retry on next lookup */
                error = DNA_ENGINE_ERROR_NETWORK;
            } else {
                /* Not our profile - auto-remove this contact */
                QGP_LOG_WARN(LOG_TAG, "Invalid signature for %.16s... - auto-removing from contacts", fingerprint);
                contacts_db_remove(fingerprint);
                error = DNA_ENGINE_ERROR_INVALID_SIGNATURE;
            }
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

    /* Derive backbone address from Dilithium pubkey if not in profile */
    if (profile->backbone[0] == '\0' && identity->dilithium_pubkey[0] != 0) {
        /* Cellframe address is derived from SHA3-256 hash of serialized Dilithium pubkey
         * The pubkey in identity is raw 2592 bytes, but we need the serialized format
         * that includes length prefix (8 bytes) + kind (4 bytes) + key data.
         * For now, we build the serialized format matching wallet file structure. */
        uint8_t serialized[2604];  /* 8 + 4 + 2592 */
        uint64_t total_len = 2592 + 4;  /* key + kind */
        memcpy(serialized, &total_len, 8);  /* Little-endian length */
        uint32_t kind = 0x0102;  /* Dilithium signature type */
        memcpy(serialized + 8, &kind, 4);
        memcpy(serialized + 12, identity->dilithium_pubkey, 2592);

        char derived_addr[128] = {0};
        if (cellframe_addr_from_pubkey(serialized, sizeof(serialized),
                                       CELLFRAME_NET_BACKBONE, derived_addr) == 0) {
            strncpy(profile->backbone, derived_addr, sizeof(profile->backbone) - 1);
            QGP_LOG_INFO(LOG_TAG, "Derived backbone address from pubkey: %.20s...", derived_addr);
        }
    }

    strncpy(profile->eth, identity->wallets.eth, sizeof(profile->eth) - 1);
    strncpy(profile->sol, identity->wallets.sol, sizeof(profile->sol) - 1);
    strncpy(profile->trx, identity->wallets.trx, sizeof(profile->trx) - 1);

    /* Socials */
    strncpy(profile->telegram, identity->socials.telegram, sizeof(profile->telegram) - 1);
    strncpy(profile->twitter, identity->socials.x, sizeof(profile->twitter) - 1);
    strncpy(profile->github, identity->socials.github, sizeof(profile->github) - 1);

    /* Bio and avatar */
    strncpy(profile->bio, identity->bio, sizeof(profile->bio) - 1);
    strncpy(profile->avatar_base64, identity->avatar_base64, sizeof(profile->avatar_base64) - 1);

    /* DEBUG: Log avatar data after copy to profile (WARN level to ensure visibility) */
    {
        size_t src_len = identity->avatar_base64[0] ? strlen(identity->avatar_base64) : 0;
        size_t dst_len = profile->avatar_base64[0] ? strlen(profile->avatar_base64) : 0;
        (void)src_len; (void)dst_len;  // Used only in debug builds
        QGP_LOG_DEBUG(LOG_TAG, "[AVATAR_DEBUG] lookup_profile: src_len=%zu, dst_len=%zu (first 20: %.20s)\n",
                     src_len, dst_len, dst_len > 0 ? profile->avatar_base64 : "(empty)");
    }

    /* NOTE: display_name field removed in v0.6.24 - use registered_name only */

    dna_identity_free(identity);

done:
    task->callback.profile(task->request_id, error, profile, task->user_data);
}

void dna_handle_refresh_contact_profile(dna_engine_t *engine, dna_task_t *task) {
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

    const char *fingerprint = task->params.lookup_profile.fingerprint;
    if (!fingerprint || strlen(fingerprint) != 128) {
        error = DNA_ENGINE_ERROR_INVALID_PARAM;
        goto done;
    }

    QGP_LOG_INFO(LOG_TAG, "Force refresh contact profile: %.16s...\n", fingerprint);

    /* Force refresh from DHT (bypass cache) */
    dna_unified_identity_t *identity = NULL;
    int rc = profile_manager_refresh_profile(fingerprint, &identity);

    if (rc != 0 || !identity) {
        if (rc == -2) {
            error = DNA_ENGINE_ERROR_NOT_FOUND;
        } else if (rc == -3) {
            /* Signature verification failed - check if it's our own profile */
            if (engine->fingerprint[0] && strcmp(fingerprint, engine->fingerprint) == 0) {
                QGP_LOG_WARN(LOG_TAG, "Own profile signature invalid - triggering auto-republish");
                dna_auto_republish_own_profile(engine);
                error = DNA_ENGINE_ERROR_NETWORK;
            } else {
                QGP_LOG_WARN(LOG_TAG, "Invalid signature for %.16s... - auto-removing from contacts", fingerprint);
                contacts_db_remove(fingerprint);
                error = DNA_ENGINE_ERROR_INVALID_SIGNATURE;
            }
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
    strncpy(profile->eth, identity->wallets.eth, sizeof(profile->eth) - 1);
    strncpy(profile->sol, identity->wallets.sol, sizeof(profile->sol) - 1);
    strncpy(profile->trx, identity->wallets.trx, sizeof(profile->trx) - 1);

    /* Socials */
    strncpy(profile->telegram, identity->socials.telegram, sizeof(profile->telegram) - 1);
    strncpy(profile->twitter, identity->socials.x, sizeof(profile->twitter) - 1);
    strncpy(profile->github, identity->socials.github, sizeof(profile->github) - 1);

    /* Bio and avatar */
    strncpy(profile->bio, identity->bio, sizeof(profile->bio) - 1);
    strncpy(profile->avatar_base64, identity->avatar_base64, sizeof(profile->avatar_base64) - 1);

    QGP_LOG_INFO(LOG_TAG, "Refreshed profile avatar: %zu bytes\n",
                 identity->avatar_base64[0] ? strlen(identity->avatar_base64) : 0);

    /* NOTE: display_name field removed in v0.6.24 - use registered_name only */

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
    qgp_key_t *enc_key = dna_load_encryption_key(engine);
    if (!enc_key) {
        error = DNA_ENGINE_ERROR_PERMISSION;
        qgp_key_free(sign_key);
        goto done;
    }

    /* Pass profile directly to DHT update (no more dna_profile_data_t conversion) */
    const dna_profile_t *p = &task->params.update_profile.profile;

    size_t avatar_len = p->avatar_base64[0] ? strlen(p->avatar_base64) : 0;
    QGP_LOG_INFO(LOG_TAG, "update_profile: avatar=%zu bytes, location='%s', website='%s'\n",
                 avatar_len, p->location, p->website);

    /* Update profile in DHT */
    int rc = dna_update_profile(dht, engine->fingerprint, p,
                                 sign_key->private_key, sign_key->public_key,
                                 enc_key->public_key);

    /* Save public keys before freeing (needed for cache entry creation) */
    uint8_t dilithium_pubkey_copy[2592];
    uint8_t kyber_pubkey_copy[1568];
    memcpy(dilithium_pubkey_copy, sign_key->public_key, sizeof(dilithium_pubkey_copy));
    memcpy(kyber_pubkey_copy, enc_key->public_key, sizeof(kyber_pubkey_copy));

    qgp_key_free(sign_key);
    qgp_key_free(enc_key);

    if (rc != 0) {
        error = DNA_ENGINE_ERROR_NETWORK;
    } else {
        /* Update local cache directly (don't fetch from DHT - propagation delay) */
        dna_unified_identity_t *cached = NULL;
        uint64_t cached_at = 0;
        int cache_rc = profile_cache_get(engine->fingerprint, &cached, &cached_at);

        if (cache_rc != 0 || !cached) {
            /* No cached profile - create complete identity with public keys
             * This prevents data loss if DHT load fails on next update */
            cached = (dna_unified_identity_t*)calloc(1, sizeof(dna_unified_identity_t));
            if (cached) {
                strncpy(cached->fingerprint, engine->fingerprint, sizeof(cached->fingerprint) - 1);
                memcpy(cached->dilithium_pubkey, dilithium_pubkey_copy, sizeof(cached->dilithium_pubkey));
                memcpy(cached->kyber_pubkey, kyber_pubkey_copy, sizeof(cached->kyber_pubkey));
                cached->created_at = (uint64_t)time(NULL);
                QGP_LOG_INFO(LOG_TAG, "Created complete cache entry with public keys for %.16s...\n",
                            engine->fingerprint);
            }
        }

        if (cached) {
            /* Update all profile fields in cache */
            strncpy(cached->wallets.backbone, p->backbone, sizeof(cached->wallets.backbone) - 1);
            strncpy(cached->wallets.alvin, p->alvin, sizeof(cached->wallets.alvin) - 1);
            strncpy(cached->wallets.eth, p->eth, sizeof(cached->wallets.eth) - 1);
            strncpy(cached->wallets.sol, p->sol, sizeof(cached->wallets.sol) - 1);
            strncpy(cached->wallets.trx, p->trx, sizeof(cached->wallets.trx) - 1);

            strncpy(cached->socials.telegram, p->telegram, sizeof(cached->socials.telegram) - 1);
            strncpy(cached->socials.x, p->twitter, sizeof(cached->socials.x) - 1);
            strncpy(cached->socials.github, p->github, sizeof(cached->socials.github) - 1);
            strncpy(cached->socials.facebook, p->facebook, sizeof(cached->socials.facebook) - 1);
            strncpy(cached->socials.instagram, p->instagram, sizeof(cached->socials.instagram) - 1);
            strncpy(cached->socials.linkedin, p->linkedin, sizeof(cached->socials.linkedin) - 1);
            strncpy(cached->socials.google, p->google, sizeof(cached->socials.google) - 1);

            /* NOTE: display_name field removed in v0.6.24 */
            strncpy(cached->bio, p->bio, sizeof(cached->bio) - 1);
            strncpy(cached->location, p->location, sizeof(cached->location) - 1);
            strncpy(cached->website, p->website, sizeof(cached->website) - 1);
            strncpy(cached->avatar_base64, p->avatar_base64, sizeof(cached->avatar_base64) - 1);
            cached->updated_at = (uint64_t)time(NULL);

            profile_cache_add_or_update(engine->fingerprint, cached);
            QGP_LOG_INFO(LOG_TAG, "Profile cache updated: %.16s... avatar=%zu bytes\n",
                        engine->fingerprint, strlen(cached->avatar_base64));
            dna_identity_free(cached);
        }
    }

done:
    task->callback.completion(task->request_id, error, task->user_data);
}

/* ============================================================================
 * PUBLIC API - Identity Functions
 * ============================================================================ */

/**
 * Validate identity name - only lowercase letters, digits, underscore, hyphen allowed.
 * Not allowed: uppercase letters, spaces, special chars
 */
static int is_valid_identity_name(const char *name) {
    if (!name || !*name) return 0;
    for (const char *p = name; *p; p++) {
        char c = *p;
        if (c >= 'A' && c <= 'Z') return 0;  /* Reject uppercase */
        if (c >= 'a' && c <= 'z') continue;  /* Allow lowercase */
        if (c >= '0' && c <= '9') continue;  /* Allow digits */
        if (c == '_' || c == '-') continue;  /* Allow underscore/hyphen */
        return 0;  /* Reject other chars */
    }
    return 1;
}

const char* dna_engine_get_fingerprint(dna_engine_t *engine) {
    if (!engine || !engine->identity_loaded) {
        return NULL;
    }
    return engine->fingerprint;
}

/* v0.3.0: dna_engine_list_identities() removed - single-user model
 * Use dna_engine_has_identity() instead */

dna_request_id_t dna_engine_create_identity(
    dna_engine_t *engine,
    const char *name,
    const uint8_t signing_seed[32],
    const uint8_t encryption_seed[32],
    dna_identity_created_cb callback,
    void *user_data
) {
    if (!engine || !name || !signing_seed || !encryption_seed || !callback) {
        return DNA_REQUEST_ID_INVALID;
    }

    /* Enforce lowercase-only identity names */
    if (!is_valid_identity_name(name)) {
        QGP_LOG_ERROR(LOG_TAG, "Identity name must be lowercase (a-z, 0-9, underscore, hyphen only)");
        return DNA_REQUEST_ID_INVALID;
    }

    dna_task_params_t params = {0};
    strncpy(params.create_identity.name, name, sizeof(params.create_identity.name) - 1);
    memcpy(params.create_identity.signing_seed, signing_seed, 32);
    memcpy(params.create_identity.encryption_seed, encryption_seed, 32);

    dna_task_callback_t cb = { .identity_created = callback };
    return dna_submit_task(engine, TASK_CREATE_IDENTITY, &params, cb, user_data);
}

int dna_engine_create_identity_sync(
    dna_engine_t *engine,
    const char *name,
    const uint8_t signing_seed[32],
    const uint8_t encryption_seed[32],
    const uint8_t master_seed[64],
    const char *mnemonic,
    char fingerprint_out[129]
) {
    if (!engine || !name || !signing_seed || !encryption_seed || !fingerprint_out) {
        return DNA_ERROR_INVALID_ARG;
    }

    /* Enforce lowercase-only identity names */
    if (!is_valid_identity_name(name)) {
        QGP_LOG_ERROR(LOG_TAG, "Identity name must be lowercase (a-z, 0-9, underscore, hyphen only)");
        return DNA_ERROR_INVALID_ARG;
    }

    /* Step 1: Create keys locally */
    int rc = messenger_generate_keys_from_seeds(name, signing_seed, encryption_seed,
                                                 master_seed, mnemonic,
                                                 engine->data_dir, NULL, fingerprint_out);
    if (rc != 0) {
        return DNA_ERROR_CRYPTO;
    }

    /* Step 2: Create temporary messenger context for registration */
    messenger_context_t *temp_ctx = messenger_init(fingerprint_out);
    if (!temp_ctx) {
        /* Cleanup: v0.3.0 flat structure - delete keys/, db/, wallets/, mnemonic.enc */
        char path[512];
        snprintf(path, sizeof(path), "%s/keys", engine->data_dir);
        qgp_platform_rmdir_recursive(path);
        snprintf(path, sizeof(path), "%s/db", engine->data_dir);
        qgp_platform_rmdir_recursive(path);
        snprintf(path, sizeof(path), "%s/wallets", engine->data_dir);
        qgp_platform_rmdir_recursive(path);
        snprintf(path, sizeof(path), "%s/mnemonic.enc", engine->data_dir);
        remove(path);
        QGP_LOG_ERROR(LOG_TAG, "Failed to create messenger context for identity registration");
        return DNA_ERROR_INTERNAL;
    }

    /* DHT already started by prepare_dht_from_mnemonic() (both CLI and Flutter) */

    /* Step 3: Register name on DHT (atomic - if this fails, cleanup) */
    rc = messenger_register_name(temp_ctx, fingerprint_out, name);
    messenger_free(temp_ctx);

    if (rc != 0) {
        /* Cleanup: v0.3.0 flat structure - delete keys/, db/, wallets/, mnemonic.enc */
        char path[512];
        snprintf(path, sizeof(path), "%s/keys", engine->data_dir);
        qgp_platform_rmdir_recursive(path);
        snprintf(path, sizeof(path), "%s/db", engine->data_dir);
        qgp_platform_rmdir_recursive(path);
        snprintf(path, sizeof(path), "%s/wallets", engine->data_dir);
        qgp_platform_rmdir_recursive(path);
        snprintf(path, sizeof(path), "%s/mnemonic.enc", engine->data_dir);
        remove(path);
        QGP_LOG_ERROR(LOG_TAG, "Name registration failed for '%s', identity rolled back", name);
        return DNA_ENGINE_ERROR_NETWORK;
    }

    /* Step 5: Cache the registered name locally */
    keyserver_cache_put_name(fingerprint_out, name, 0);
    QGP_LOG_INFO(LOG_TAG, "Identity created and registered: %s -> %.16s...", name, fingerprint_out);

    return DNA_OK;
}

int dna_engine_restore_identity_sync(
    dna_engine_t *engine,
    const uint8_t signing_seed[32],
    const uint8_t encryption_seed[32],
    const uint8_t master_seed[64],
    const char *mnemonic,
    char fingerprint_out[129]
) {
    if (!engine || !signing_seed || !encryption_seed || !fingerprint_out) {
        return DNA_ERROR_INVALID_ARG;
    }

    /* Step 1: Create keys locally (uses fingerprint as directory name) */
    int rc = messenger_generate_keys_from_seeds(NULL, signing_seed, encryption_seed,
                                                 master_seed, mnemonic,
                                                 engine->data_dir, NULL, fingerprint_out);
    if (rc != 0) {
        return DNA_ERROR_CRYPTO;
    }

    /* Step 2: v0.6.0+: Load DHT identity into engine-owned context */
    if (messenger_load_dht_identity_for_engine(fingerprint_out, &engine->dht_ctx) == 0) {
        QGP_LOG_INFO(LOG_TAG, "Engine-owned DHT context created for restored identity");
        dht_singleton_set_borrowed_context(engine->dht_ctx);
    } else {
        QGP_LOG_WARN(LOG_TAG, "Fallback: using singleton DHT for restored identity");
        messenger_load_dht_identity(fingerprint_out);
    }

    QGP_LOG_INFO(LOG_TAG, "Identity restored from seed: %.16s...", fingerprint_out);

    return DNA_OK;
}

int dna_engine_delete_identity_sync(
    dna_engine_t *engine,
    const char *fingerprint
) {
    if (!engine || !fingerprint) {
        return DNA_ERROR_INVALID_ARG;
    }

    /* Validate fingerprint format (128 hex chars) */
    size_t fp_len = strlen(fingerprint);
    if (fp_len != 128) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid fingerprint length: %zu (expected 128)", fp_len);
        return DNA_ERROR_INVALID_ARG;
    }

    /* Check that fingerprint contains only hex characters */
    for (size_t i = 0; i < fp_len; i++) {
        char c = fingerprint[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
            QGP_LOG_ERROR(LOG_TAG, "Invalid character in fingerprint at position %zu", i);
            return DNA_ERROR_INVALID_ARG;
        }
    }

    /* If deleting the currently loaded identity, unload it first */
    if (engine->identity_loaded && engine->fingerprint[0] != '\0' &&
        strcmp(engine->fingerprint, fingerprint) == 0) {
        QGP_LOG_INFO(LOG_TAG, "Unloading current identity before deletion");

        /* Free messenger context */
        if (engine->messenger) {
            messenger_free(engine->messenger);
            engine->messenger = NULL;
        }

        /* Clear identity state */
        engine->identity_loaded = false;
        engine->state = DNA_ENGINE_STATE_UNLOADED;
        memset(engine->fingerprint, 0, sizeof(engine->fingerprint));
    }

    const char *data_dir = engine->data_dir;
    int errors = 0;

    QGP_LOG_INFO(LOG_TAG, "Deleting identity: %.16s...", fingerprint);
    (void)fingerprint;  // Unused in v0.3.0 flat structure

    /* v0.3.0: Flat structure - delete keys/, db/, wallets/ directories and root files */

    /* 1. Delete keys directory: <data_dir>/keys/ */
    char keys_dir[512];
    snprintf(keys_dir, sizeof(keys_dir), "%s/keys", data_dir);
    if (qgp_platform_file_exists(keys_dir)) {
        if (qgp_platform_rmdir_recursive(keys_dir) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to delete keys directory: %s", keys_dir);
            errors++;
        } else {
            QGP_LOG_DEBUG(LOG_TAG, "Deleted keys directory: %s", keys_dir);
        }
    }

    /* 2. Delete db directory: <data_dir>/db/ */
    /* Close profile cache first to release file handles before deletion */
    profile_cache_close();

    char db_dir[512];
    snprintf(db_dir, sizeof(db_dir), "%s/db", data_dir);
    if (qgp_platform_file_exists(db_dir)) {
        if (qgp_platform_rmdir_recursive(db_dir) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to delete db directory: %s", db_dir);
            errors++;
        } else {
            QGP_LOG_DEBUG(LOG_TAG, "Deleted db directory: %s", db_dir);
        }
    }

    /* 3. Delete wallets directory: <data_dir>/wallets/ */
    char wallets_dir[512];
    snprintf(wallets_dir, sizeof(wallets_dir), "%s/wallets", data_dir);
    if (qgp_platform_file_exists(wallets_dir)) {
        if (qgp_platform_rmdir_recursive(wallets_dir) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to delete wallets directory: %s", wallets_dir);
            errors++;
        } else {
            QGP_LOG_DEBUG(LOG_TAG, "Deleted wallets directory: %s", wallets_dir);
        }
    }

    /* 4. Delete mnemonic file: <data_dir>/mnemonic.enc */
    char mnemonic_path[512];
    snprintf(mnemonic_path, sizeof(mnemonic_path), "%s/mnemonic.enc", data_dir);
    if (qgp_platform_file_exists(mnemonic_path)) {
        if (remove(mnemonic_path) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to delete mnemonic: %s", mnemonic_path);
            errors++;
        } else {
            QGP_LOG_DEBUG(LOG_TAG, "Deleted mnemonic: %s", mnemonic_path);
        }
    }

    /* 5. Delete DHT identity file: <data_dir>/dht_identity.bin */
    char dht_id_path[512];
    snprintf(dht_id_path, sizeof(dht_id_path), "%s/dht_identity.bin", data_dir);
    if (qgp_platform_file_exists(dht_id_path)) {
        if (remove(dht_id_path) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to delete DHT identity: %s", dht_id_path);
            errors++;
        } else {
            QGP_LOG_DEBUG(LOG_TAG, "Deleted DHT identity: %s", dht_id_path);
        }
    }

    if (errors > 0) {
        QGP_LOG_WARN(LOG_TAG, "Identity deletion completed with %d errors", errors);
        return DNA_ERROR_INTERNAL;
    }

    QGP_LOG_INFO(LOG_TAG, "Identity deleted successfully: %.16s...", fingerprint);
    return DNA_OK;
}

/**
 * Check if an identity exists (v0.3.0 single-user model)
 *
 * Checks if keys/identity.dsa exists in the data directory.
 */
bool dna_engine_has_identity(dna_engine_t *engine) {
    if (!engine || !engine->data_dir) {
        return false;
    }

    char path[512];
    snprintf(path, sizeof(path), "%s/keys/identity.dsa", engine->data_dir);
    return qgp_platform_file_exists(path);
}

/**
 * Prepare DHT connection from mnemonic (before identity creation)
 */
int dna_engine_prepare_dht_from_mnemonic(dna_engine_t *engine, const char *mnemonic) {
    (void)engine;  // Engine not needed for this operation
    return messenger_prepare_dht_from_mnemonic(mnemonic);
}

dna_request_id_t dna_engine_load_identity(
    dna_engine_t *engine,
    const char *fingerprint,
    const char *password,
    dna_completion_cb callback,
    void *user_data
) {
    if (!engine || !fingerprint || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.load_identity.fingerprint, fingerprint, 128);
    params.load_identity.password = password ? strdup(password) : NULL;

    dna_task_callback_t cb = { .completion = callback };
    return dna_submit_task(engine, TASK_LOAD_IDENTITY, &params, cb, user_data);
}

bool dna_engine_is_identity_loaded(dna_engine_t *engine) {
    return engine && engine->identity_loaded;
}

bool dna_engine_is_transport_ready(dna_engine_t *engine) {
    return engine && engine->messenger && engine->messenger->transport_ctx != NULL;
}

dna_request_id_t dna_engine_load_identity_minimal(
    dna_engine_t *engine,
    const char *fingerprint,
    const char *password,
    dna_completion_cb callback,
    void *user_data
) {
    if (!engine || !fingerprint || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.load_identity.fingerprint, fingerprint, 128);
    params.load_identity.password = password ? strdup(password) : NULL;
    params.load_identity.minimal = true;

    QGP_LOG_INFO(LOG_TAG, "Load identity (minimal): DHT + polling only, no listeners");

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

dna_request_id_t dna_engine_get_avatar(
    dna_engine_t *engine,
    const char *fingerprint,
    dna_display_name_cb callback,  /* Reuses display_name callback (returns string) */
    void *user_data
) {
    if (!engine || !fingerprint || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.get_avatar.fingerprint, fingerprint, 128);

    dna_task_callback_t cb = { .display_name = callback };
    return dna_submit_task(engine, TASK_GET_AVATAR, &params, cb, user_data);
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

dna_request_id_t dna_engine_lookup_profile(
    dna_engine_t *engine,
    const char *fingerprint,
    dna_profile_cb callback,
    void *user_data
) {
    if (!engine || !fingerprint || !callback) return DNA_REQUEST_ID_INVALID;
    /* lookupProfile can work without identity loaded - only needs DHT context.
     * This is needed for restore flow to check if profile exists in DHT. */
    if (strlen(fingerprint) != 128) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.lookup_profile.fingerprint, fingerprint, 128);

    dna_task_callback_t cb = { .profile = callback };
    return dna_submit_task(engine, TASK_LOOKUP_PROFILE, &params, cb, user_data);
}

dna_request_id_t dna_engine_refresh_contact_profile(
    dna_engine_t *engine,
    const char *fingerprint,
    dna_profile_cb callback,
    void *user_data
) {
    if (!engine || !fingerprint || !callback) return DNA_REQUEST_ID_INVALID;
    if (!engine->identity_loaded) return DNA_REQUEST_ID_INVALID;
    if (strlen(fingerprint) != 128) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.lookup_profile.fingerprint, fingerprint, 128);

    dna_task_callback_t cb = { .profile = callback };
    return dna_submit_task(engine, TASK_REFRESH_CONTACT_PROFILE, &params, cb, user_data);
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

int dna_engine_get_mnemonic(
    dna_engine_t *engine,
    char *mnemonic_out,
    size_t mnemonic_size
) {
    if (!engine || !mnemonic_out || mnemonic_size < 256) {
        return DNA_ENGINE_ERROR_INVALID_PARAM;
    }
    if (!engine->identity_loaded) {
        return DNA_ENGINE_ERROR_NO_IDENTITY;
    }

    /* v0.3.0: Flat structure - keys/identity.kem, mnemonic.enc in root */
    char kyber_path[512];
    snprintf(kyber_path, sizeof(kyber_path), "%s/keys/identity.kem", engine->data_dir);

    /* Check if mnemonic file exists */
    if (!mnemonic_storage_exists(engine->data_dir)) {
        QGP_LOG_DEBUG(LOG_TAG, "Mnemonic file not found for identity %s",
                      engine->fingerprint);
        return DNA_ENGINE_ERROR_NOT_FOUND;
    }

    /* Load Kyber private key (use password if keys are encrypted) */
    qgp_key_t *kem_key = NULL;
    int load_rc;
    if (engine->keys_encrypted && engine->session_password) {
        load_rc = qgp_key_load_encrypted(kyber_path, engine->session_password, &kem_key);
    } else {
        load_rc = qgp_key_load(kyber_path, &kem_key);
    }
    if (load_rc != 0 || !kem_key) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to load Kyber private key");
        return DNA_ERROR_CRYPTO;
    }

    if (!kem_key->private_key || kem_key->private_key_size != 3168) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid Kyber private key size");
        qgp_key_free(kem_key);
        return DNA_ERROR_CRYPTO;
    }

    /* Decrypt and load mnemonic */
    int result = mnemonic_storage_load(mnemonic_out, mnemonic_size,
                                       kem_key->private_key, engine->data_dir);

    qgp_key_free(kem_key);

    if (result != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to decrypt mnemonic");
        return DNA_ERROR_CRYPTO;
    }

    QGP_LOG_INFO(LOG_TAG, "Mnemonic retrieved successfully");
    return DNA_OK;
}

int dna_engine_change_password_sync(
    dna_engine_t *engine,
    const char *old_password,
    const char *new_password
) {
    if (!engine) {
        return DNA_ENGINE_ERROR_INVALID_PARAM;
    }
    if (!engine->identity_loaded) {
        return DNA_ENGINE_ERROR_NO_IDENTITY;
    }

    /* Build paths to key files */
    /* v0.3.0: Flat structure - keys/identity.{dsa,kem}, mnemonic.enc in root */
    char dsa_path[512];
    char kem_path[512];
    char mnemonic_path[512];

    snprintf(dsa_path, sizeof(dsa_path), "%s/keys/identity.dsa", engine->data_dir);
    snprintf(kem_path, sizeof(kem_path), "%s/keys/identity.kem", engine->data_dir);
    snprintf(mnemonic_path, sizeof(mnemonic_path), "%s/mnemonic.enc", engine->data_dir);

    /* Verify old password is correct by trying to load a key */
    if (engine->keys_encrypted || old_password) {
        if (key_verify_password(dsa_path, old_password) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Old password is incorrect");
            return DNA_ENGINE_ERROR_WRONG_PASSWORD;
        }
    }

    QGP_LOG_INFO(LOG_TAG, "Changing password for identity %s", engine->fingerprint);

    /* Change password on DSA key */
    if (key_change_password(dsa_path, old_password, new_password) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to change password on DSA key");
        return DNA_ERROR_CRYPTO;
    }

    /* Change password on KEM key */
    if (key_change_password(kem_path, old_password, new_password) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to change password on KEM key");
        /* Try to rollback DSA key */
        key_change_password(dsa_path, new_password, old_password);
        return DNA_ERROR_CRYPTO;
    }

    /* Change password on mnemonic file if it exists */
    if (qgp_platform_file_exists(mnemonic_path)) {
        if (key_change_password(mnemonic_path, old_password, new_password) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to change password on mnemonic file");
            /* Try to rollback DSA and KEM keys */
            key_change_password(dsa_path, new_password, old_password);
            key_change_password(kem_path, new_password, old_password);
            return DNA_ERROR_CRYPTO;
        }
    }

    /* Update session password and encryption state */
    if (engine->session_password) {
        free(engine->session_password);
        engine->session_password = NULL;
    }

    if (new_password && new_password[0] != '\0') {
        engine->session_password = strdup(new_password);
        engine->keys_encrypted = true;
    } else {
        engine->keys_encrypted = false;
    }

    QGP_LOG_INFO(LOG_TAG, "Password changed successfully for identity %s", engine->fingerprint);
    return DNA_OK;
}
