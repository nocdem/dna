/**
 * @file background_tasks.cpp
 * @brief Background Task Manager Implementation
 *
 * Part of DNA Messenger v0.09 - GSK Upgrade
 *
 * @date 2025-11-21
 */

#include "background_tasks.h"
#include "notification_manager.h"
#include "../../messenger.h"
#include "../../p2p/p2p_transport.h"
#include "../../messenger/gsk.h"
#include "../../messenger/gsk_packet.h"
#include "../../messenger/group_ownership.h"
#include "../../dht/shared/dht_groups.h"
#include "../../dht/shared/dht_gsk_storage.h"
#include "../../dht/core/dht_context.h"
#include "../../p2p/p2p_transport.h"
#include <ctime>
#include <cstdio>
#include <cstring>
#include <cstdlib>

namespace DNA {

/**
 * Get singleton instance
 */
BackgroundTaskManager& BackgroundTaskManager::getInstance() {
    static BackgroundTaskManager instance;
    return instance;
}

/**
 * Initialize background tasks
 */
void BackgroundTaskManager::init(messenger_context_t* ctx, const std::string& identity) {
    ctx_ = ctx;
    identity_ = identity;
    initialized_ = true;

    // Initialize timestamps (stagger initial polls to avoid burst)
    uint64_t now = static_cast<uint64_t>(std::time(nullptr));
    last_gsk_poll_ = now - GSK_POLL_INTERVAL + 10;           // First poll in 10 seconds
    last_ownership_check_ = now - OWNERSHIP_CHECK_INTERVAL + 15; // First check in 15 seconds
    last_heartbeat_publish_ = now - HEARTBEAT_PUBLISH_INTERVAL + 30; // First publish in 30 seconds

    printf("[BACKGROUND] Initialized background tasks (identity=%s)\n", identity.c_str());
}

/**
 * Update background tasks (call every frame)
 */
void BackgroundTaskManager::update() {
    if (!initialized_ || !ctx_) {
        return;
    }

    uint64_t now = static_cast<uint64_t>(std::time(nullptr));

    // GSK discovery polling (every 2 minutes)
    if (now - last_gsk_poll_ >= GSK_POLL_INTERVAL) {
        pollGSKDiscovery();
        last_gsk_poll_ = now;
    }

    // Ownership liveness checks (every 2 minutes)
    if (now - last_ownership_check_ >= OWNERSHIP_CHECK_INTERVAL) {
        checkOwnershipLiveness();
        last_ownership_check_ = now;
    }

    // Heartbeat publishing (every 6 hours)
    if (now - last_heartbeat_publish_ >= HEARTBEAT_PUBLISH_INTERVAL) {
        publishOwnerHeartbeats();
        last_heartbeat_publish_ = now;
    }
}

/**
 * Poll for new GSK versions for all groups
 */
void BackgroundTaskManager::pollGSKDiscovery() {
    if (!ctx_) return;

    printf("[BACKGROUND] Polling for new GSK versions...\n");

    // Get DHT context
    dht_context_t* dht_ctx = ctx_->p2p_transport ?
        p2p_transport_get_dht_context(ctx_->p2p_transport) : nullptr;
    if (!dht_ctx) {
        fprintf(stderr, "[BACKGROUND] DHT context not available\n");
        return;
    }

    // Get list of all groups for this user from local cache
    dht_group_cache_entry_t* groups = nullptr;
    int group_count = 0;

    if (dht_groups_list_for_user(ctx_->identity, &groups, &group_count) != 0) {
        fprintf(stderr, "[BACKGROUND] Failed to list groups\n");
        return;
    }

    printf("[BACKGROUND] Checking %d groups for GSK updates...\n", group_count);

    // Check each group for new GSK versions
    for (int i = 0; i < group_count; i++) {
        dht_group_cache_entry_t* cached_group = &groups[i];

        // Get current local GSK version
        uint8_t current_gsk[GSK_KEY_SIZE];
        uint32_t current_version = 0;
        int has_local = (gsk_load_active(cached_group->group_uuid, current_gsk, &current_version) == 0);

        // Fetch latest metadata from DHT
        dht_group_metadata_t* latest_meta = nullptr;
        if (dht_groups_get(dht_ctx, cached_group->group_uuid, &latest_meta) != 0) {
            fprintf(stderr, "[BACKGROUND] Failed to fetch metadata for group %s\n", cached_group->group_uuid);
            continue;
        }

        // Check if there's a newer GSK version (stored in DHT metadata)
        // Note: GSK version is tracked separately, need to check DHT for latest
        printf("[BACKGROUND] Checking group %s for GSK updates...\n", cached_group->name);

        // Fetch Initial Key Packet from DHT (try to get latest version)
        // For now, we'll check version 1+ until fetch fails
        uint32_t check_version = current_version + 1;
        uint8_t* packet = nullptr;
        size_t packet_size = 0;

        if (dht_gsk_fetch(dht_ctx, cached_group->group_uuid, check_version,
                         &packet, &packet_size) == 0) {

            printf("[BACKGROUND] New GSK version %u available for group %s (current: %u)\n",
                   check_version, cached_group->name, current_version);

                // Convert my fingerprint hex to binary
                uint8_t my_fingerprint_bin[64];
                for (int j = 0; j < 64; j++) {
                    sscanf(ctx_->fingerprint + (j * 2), "%2hhx", &my_fingerprint_bin[j]);
                }

                // Load my Kyber private key
                uint8_t my_kyber_privkey[3168]; // QGP_KEM1024_SECRETKEYBYTES
                char kyber_path[512];
                snprintf(kyber_path, sizeof(kyber_path), "%s/.dna/%s.kem",
                        getenv("HOME"), ctx_->fingerprint);

                FILE* kf = fopen(kyber_path, "rb");
                if (kf && fread(my_kyber_privkey, 1, 3168, kf) == 3168) {
                    fclose(kf);

                    // Extract GSK from packet
                    uint8_t new_gsk[GSK_KEY_SIZE];
                    uint32_t extracted_version = 0;

                    if (gsk_packet_extract(packet, packet_size,
                                          my_fingerprint_bin,
                                          my_kyber_privkey,
                                          new_gsk,
                                          &extracted_version) == 0) {

            // Store new GSK locally
            if (gsk_store(cached_group->group_uuid, extracted_version, new_gsk) == 0) {
                printf("[BACKGROUND] GSK v%u stored for group %s\n",
                       extracted_version, cached_group->name);

                // Show native OS notification
                NotificationManager::showNativeNotification(
                    "Group Security Key Rotated",
                    "Group '" + std::string(cached_group->name) + "' security key updated to version " + std::to_string(extracted_version),
                    NotificationType::SUCCESS
                );
            } else {
                fprintf(stderr, "[BACKGROUND] Failed to store GSK\n");
            }
        } else {
            fprintf(stderr, "[BACKGROUND] Failed to extract GSK (not in member list?)\n");
        }
    } else {
        fprintf(stderr, "[BACKGROUND] Failed to load Kyber private key\n");
        if (kf) fclose(kf);
    }

    free(packet);
} else {
    // No new version available
}

dht_groups_free_metadata(latest_meta);
}

// Free group list
dht_groups_free_cache_entries(groups, group_count);

    printf("[BACKGROUND] GSK discovery poll complete\n");
}

/**
 * Check ownership liveness for all groups
 */
void BackgroundTaskManager::checkOwnershipLiveness() {
    if (!ctx_) return;

    printf("[BACKGROUND] Checking ownership liveness...\n");

    // Get DHT context
    dht_context_t* dht_ctx = ctx_->p2p_transport ?
        p2p_transport_get_dht_context(ctx_->p2p_transport) : nullptr;
    if (!dht_ctx) {
        fprintf(stderr, "[BACKGROUND] DHT context not available\n");
        return;
    }

    // Get list of all groups for this user
    dht_group_cache_entry_t* groups = nullptr;
    int group_count = 0;

    if (dht_groups_list_for_user(ctx_->identity, &groups, &group_count) != 0) {
        fprintf(stderr, "[BACKGROUND] Failed to list groups\n");
        return;
    }

    printf("[BACKGROUND] Checking %d groups for owner liveness...\n", group_count);

    // Check each group's owner liveness
    for (int i = 0; i < group_count; i++) {
        dht_group_cache_entry_t* cached_group = &groups[i];

        // Check if owner is still alive (heartbeat within 7 days)
        bool is_alive = false;
        char owner_fingerprint[129] = {0};

        if (group_ownership_check_liveness(dht_ctx, cached_group->group_uuid,
                                          &is_alive, owner_fingerprint) == 0) {

            if (!is_alive) {
                printf("[BACKGROUND] Owner offline for group %s, initiating transfer...\n",
                       cached_group->name);

                // Load my Dilithium private key for potential ownership
                uint8_t my_dilithium_privkey[4627]; // QGP_DSA87_SECRETKEYBYTES
                char dil_path[512];
                snprintf(dil_path, sizeof(dil_path), "%s/.dna/%s.dsa",
                        getenv("HOME"), ctx_->fingerprint);

                FILE* df = fopen(dil_path, "rb");
                if (df && fread(my_dilithium_privkey, 1, 4627, df) == 4627) {
                    fclose(df);

                    // Attempt ownership transfer
                    bool became_owner = false;
                    if (group_ownership_transfer(dht_ctx, cached_group->group_uuid,
                                                ctx_->fingerprint,
                                                my_dilithium_privkey,
                                                &became_owner) == 0) {

                        if (became_owner) {
                            printf("[BACKGROUND] I became owner of group %s!\n", cached_group->name);

                            // Notify user
                            NotificationManager::showNativeNotification(
                                "You Are Now Group Owner",
                                "You became owner of group '" + std::string(cached_group->name) + "' (previous owner offline for 7+ days)",
                                NotificationType::SUCCESS
                            );

                            // Rotate GSK as new owner (for security - old owner is gone)
                            printf("[BACKGROUND] Rotating GSK as new owner...\n");
                            if (gsk_rotate_on_member_remove(dht_ctx, cached_group->group_uuid, ctx_->identity) != 0) {
                                fprintf(stderr, "[BACKGROUND] Warning: GSK rotation failed\n");
                            }

                        } else {
                            // Someone else became owner
                            printf("[BACKGROUND] Ownership transferred to another member\n");

                            // Fetch updated metadata to get new owner
                            dht_group_metadata_t* updated_meta = nullptr;
                            if (dht_groups_get(dht_ctx, cached_group->group_uuid, &updated_meta) == 0) {
                                NotificationManager::showNativeNotification(
                                    "Group Owner Changed",
                                    "Group '" + std::string(cached_group->name) + "' now owned by " + std::string(updated_meta->creator),
                                    NotificationType::INFO
                                );
                                dht_groups_free_metadata(updated_meta);
                            }
                        }
                    } else {
                        fprintf(stderr, "[BACKGROUND] Ownership transfer failed\n");
                    }
                } else {
                    fprintf(stderr, "[BACKGROUND] Failed to load Dilithium private key\n");
                    if (df) fclose(df);
                }
            } else {
                // Owner is alive, all good
                printf("[BACKGROUND] Owner alive for group %s\n", cached_group->name);
            }
        } else {
            fprintf(stderr, "[BACKGROUND] Failed to check liveness for group %s\n", cached_group->group_uuid);
        }
    }

    // Free group list
    dht_groups_free_cache_entries(groups, group_count);

    printf("[BACKGROUND] Ownership liveness check complete\n");
}

/**
 * Publish heartbeat for groups I own
 */
void BackgroundTaskManager::publishOwnerHeartbeats() {
    if (!ctx_) return;

    printf("[BACKGROUND] Publishing owner heartbeats...\n");

    // Get DHT context
    dht_context_t* dht_ctx = ctx_->p2p_transport ?
        p2p_transport_get_dht_context(ctx_->p2p_transport) : nullptr;
    if (!dht_ctx) {
        fprintf(stderr, "[BACKGROUND] DHT context not available\n");
        return;
    }

    // Get list of all groups for this user
    dht_group_cache_entry_t* groups = nullptr;
    int group_count = 0;

    if (dht_groups_list_for_user(ctx_->identity, &groups, &group_count) != 0) {
        fprintf(stderr, "[BACKGROUND] Failed to list groups\n");
        return;
    }

    // Load my Dilithium private key (used for signing heartbeats)
    uint8_t my_dilithium_privkey[4627]; // QGP_DSA87_SECRETKEYBYTES
    char dil_path[512];
    snprintf(dil_path, sizeof(dil_path), "%s/.dna/%s.dsa",
            getenv("HOME"), ctx_->fingerprint);

    FILE* df = fopen(dil_path, "rb");
    if (!df || fread(my_dilithium_privkey, 1, 4627, df) != 4627) {
        fprintf(stderr, "[BACKGROUND] Failed to load Dilithium private key\n");
        if (df) fclose(df);

        // Free group list
        dht_groups_free_cache_entries(groups, group_count);
        return;
    }
    fclose(df);

    int heartbeats_published = 0;

    // Publish heartbeat for each group I own
    for (int i = 0; i < group_count; i++) {
        dht_group_cache_entry_t* cached_group = &groups[i];

        // Check if I'm the owner (compare with creator fingerprint)
        if (strcmp(cached_group->creator, identity_.c_str()) == 0 ||
            strcmp(cached_group->creator, ctx_->fingerprint) == 0) {

            printf("[BACKGROUND] Publishing heartbeat for group %s (I am owner)\n",
                   cached_group->name);

            // Publish heartbeat to DHT
            if (group_ownership_publish_heartbeat(dht_ctx,
                                                 cached_group->group_uuid,
                                                 ctx_->fingerprint,
                                                 my_dilithium_privkey) == 0) {
                printf("[BACKGROUND] Heartbeat published for %s\n", cached_group->name);
                heartbeats_published++;
            } else {
                fprintf(stderr, "[BACKGROUND] Failed to publish heartbeat for %s\n",
                       cached_group->name);
            }
        }
    }

    // Free group list
    dht_groups_free_cache_entries(groups, group_count);

    printf("[BACKGROUND] Heartbeat publishing complete (%d published)\n", heartbeats_published);
}

/**
 * Force immediate poll (for testing or manual refresh)
 */
void BackgroundTaskManager::forcePoll() {
    if (!initialized_ || !ctx_) {
        return;
    }

    printf("[BACKGROUND] Force polling all tasks...\n");

    pollGSKDiscovery();
    checkOwnershipLiveness();
    publishOwnerHeartbeats();

    // Update timestamps
    uint64_t now = static_cast<uint64_t>(std::time(nullptr));
    last_gsk_poll_ = now;
    last_ownership_check_ = now;
    last_heartbeat_publish_ = now;
}

} // namespace DNA
