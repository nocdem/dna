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
#include "../../messenger_p2p.h"
#include "../../p2p/p2p_transport.h"
#include "../../messenger/gsk.h"
#include "../../messenger/gsk_packet.h"
#include "../../dht/shared/dht_groups.h"
#include "../../dht/shared/dht_gsk_storage.h"
#include "../../dht/core/dht_context.h"
#include "../../dht/client/dna_group_outbox.h"
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
    fingerprint_ = ctx->fingerprint ? ctx->fingerprint : identity;
    initialized_ = true;

    // Initialize timestamps (stagger initial polls to avoid burst)
    uint64_t now = static_cast<uint64_t>(std::time(nullptr));
    last_gsk_poll_ = now - GSK_POLL_INTERVAL + 10;                     // First poll in 10 seconds
    last_group_outbox_poll_ = now - GROUP_OUTBOX_POLL_INTERVAL + 5;    // First poll in 5 seconds
    last_direct_msg_poll_ = now - DIRECT_MSG_POLL_INTERVAL + 15;       // First poll in 15 seconds

    printf("[BACKGROUND] Initialized background tasks (identity=%s, fingerprint=%s)\n",
           identity.c_str(), fingerprint_.c_str());
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

    // Group outbox sync (every 30 seconds)
    if (now - last_group_outbox_poll_ >= GROUP_OUTBOX_POLL_INTERVAL) {
        pollGroupOutbox();
        last_group_outbox_poll_ = now;
    }

    // Direct message DHT queue polling (every 2 minutes)
    // Catches messages when Tier 1 (TCP) and Tier 2 (ICE) fail
    if (now - last_direct_msg_poll_ >= DIRECT_MSG_POLL_INTERVAL) {
        pollDirectMessageQueue();
        last_direct_msg_poll_ = now;
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
 * Sync group message outboxes
 */
void BackgroundTaskManager::pollGroupOutbox() {
    if (!ctx_) return;

    printf("[BACKGROUND] Syncing group outboxes...\n");

    // Get DHT context
    dht_context_t* dht_ctx = ctx_->p2p_transport ?
        p2p_transport_get_dht_context(ctx_->p2p_transport) : nullptr;
    if (!dht_ctx) {
        fprintf(stderr, "[BACKGROUND] DHT context not available for group outbox sync\n");
        return;
    }

    // Sync all groups
    size_t new_message_count = 0;
    int result = dna_group_outbox_sync_all(dht_ctx, fingerprint_.c_str(), &new_message_count);

    if (result == DNA_GROUP_OUTBOX_OK) {
        if (new_message_count > 0) {
            printf("[BACKGROUND] Received %zu new group messages\n", new_message_count);

            // Show notification
            NotificationManager::showNativeNotification(
                "New Group Messages",
                std::to_string(new_message_count) + " new message(s) received",
                NotificationType::INFO
            );
        }
    } else if (result != DNA_GROUP_OUTBOX_ERR_NO_GSK) {
        // Only log errors that aren't "no GSK" (expected for new groups)
        fprintf(stderr, "[BACKGROUND] Group outbox sync failed: %s\n",
                dna_group_outbox_strerror(result));
    }

    printf("[BACKGROUND] Group outbox sync complete\n");
}

/**
 * Poll direct message DHT offline queue
 *
 * Queries each contact's outbox for messages addressed to this user.
 * This catches messages when Tier 1 (TCP) and Tier 2 (ICE) fail
 * but both users are online.
 */
void BackgroundTaskManager::pollDirectMessageQueue() {
    if (!ctx_) return;

    printf("[BACKGROUND] Polling direct message DHT queue...\n");

    size_t messages_received = 0;
    int result = messenger_p2p_check_offline_messages(ctx_, &messages_received);

    if (result == 0 && messages_received > 0) {
        printf("[BACKGROUND] Received %zu direct message(s) from DHT offline queue\n", messages_received);

        // Show native OS notification
        NotificationManager::showNativeNotification(
            "New Message",
            std::to_string(messages_received) + " new message(s) received",
            NotificationType::MESSAGE
        );
    } else if (result != 0) {
        fprintf(stderr, "[BACKGROUND] Direct message queue poll failed\n");
    }

    printf("[BACKGROUND] Direct message queue poll complete\n");
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
    pollGroupOutbox();
    pollDirectMessageQueue();

    // Update timestamps
    uint64_t now = static_cast<uint64_t>(std::time(nullptr));
    last_gsk_poll_ = now;
    last_group_outbox_poll_ = now;
    last_direct_msg_poll_ = now;
}

} // namespace DNA
