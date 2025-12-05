/**
 * @file background_tasks.h
 * @brief Background Task Manager for DNA Messenger GUI
 *
 * Manages periodic background tasks:
 * - GSK discovery polling (every 2 minutes)
 * - Group outbox sync (every 30 seconds)
 * - Direct message queue polling (every 2 minutes)
 *
 * Part of DNA Messenger v0.10 - Group Outbox
 *
 * @date 2025-11-29
 */

#ifndef BACKGROUND_TASKS_H
#define BACKGROUND_TASKS_H

#include <string>
#include <cstdint>

// Include messenger context (C header)
extern "C" {
    #include "../../messenger.h"
}

namespace DNA {

/**
 * Background Task Manager
 *
 * Singleton class managing periodic background tasks.
 * Call update() every frame to check if tasks need to run.
 */
class BackgroundTaskManager {
public:
    /**
     * Get singleton instance
     */
    static BackgroundTaskManager& getInstance();

    /**
     * Initialize background tasks
     *
     * @param ctx Messenger context (for DHT access)
     * @param identity Current user's identity
     */
    void init(messenger_context_t* ctx, const std::string& identity);

    /**
     * Update background tasks (call every frame)
     *
     * Checks elapsed time and runs tasks that are due.
     */
    void update();

    /**
     * Poll for new GSK versions for all groups
     *
     * Called every 2 minutes.
     * For each group I'm a member of:
     * - Fetch latest GSK version from DHT
     * - If new version found, fetch Initial Key Packet
     * - Extract GSK and store locally
     * - Trigger UI notification
     */
    void pollGSKDiscovery();

    /**
     * Sync group message outboxes
     *
     * Called every 30 seconds.
     * For each group I'm a member of:
     * - Fetch hour buckets since last sync
     * - Decrypt and store new messages
     * - Trigger UI notification for new messages
     */
    void pollGroupOutbox();

    /**
     * Poll direct message DHT offline queue
     *
     * Called every 2 minutes.
     * Queries each contact's outbox for messages addressed to this user.
     * This catches messages when Tier 1 (TCP) and Tier 2 (ICE) fail
     * but both users are online.
     */
    void pollDirectMessageQueue();

    /**
     * Force immediate poll (for testing or manual refresh)
     */
    void forcePoll();

private:
    BackgroundTaskManager()
        : ctx_(nullptr)
        , last_gsk_poll_(0)
        , last_group_outbox_poll_(0)
        , last_direct_msg_poll_(0)
        , initialized_(false)
    {}
    ~BackgroundTaskManager() = default;

    // Prevent copying
    BackgroundTaskManager(const BackgroundTaskManager&) = delete;
    BackgroundTaskManager& operator=(const BackgroundTaskManager&) = delete;

    messenger_context_t* ctx_;
    std::string identity_;
    std::string fingerprint_;

    uint64_t last_gsk_poll_;
    uint64_t last_group_outbox_poll_;
    uint64_t last_direct_msg_poll_;

    bool initialized_;

    // Poll intervals (seconds)
    static constexpr uint64_t GSK_POLL_INTERVAL = 120;              // 2 minutes
    static constexpr uint64_t GROUP_OUTBOX_POLL_INTERVAL = 30;      // 30 seconds
    static constexpr uint64_t DIRECT_MSG_POLL_INTERVAL = 120;       // 2 minutes
};

} // namespace DNA

#endif // BACKGROUND_TASKS_H
