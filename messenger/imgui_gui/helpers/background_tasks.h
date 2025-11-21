/**
 * @file background_tasks.h
 * @brief Background Task Manager for DNA Messenger GUI
 *
 * Manages periodic background tasks:
 * - GSK discovery polling (every 2 minutes)
 * - Ownership liveness checks (every 2 minutes)
 * - Owner heartbeat publishing (every 6 hours)
 *
 * Part of DNA Messenger v0.09 - GSK Upgrade
 *
 * @date 2025-11-21
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
     * Check ownership liveness for all groups
     *
     * Called every 2 minutes.
     * For each group I'm a member of:
     * - Check if owner's heartbeat is fresh
     * - If owner offline (7+ days), initiate transfer
     * - Trigger UI notification if ownership changes
     */
    void checkOwnershipLiveness();

    /**
     * Publish heartbeat for groups I own
     *
     * Called every 6 hours.
     * For each group I own:
     * - Publish heartbeat to DHT
     * - Prove I'm still online
     */
    void publishOwnerHeartbeats();

    /**
     * Force immediate poll (for testing or manual refresh)
     */
    void forcePoll();

private:
    BackgroundTaskManager()
        : ctx_(nullptr)
        , last_gsk_poll_(0)
        , last_ownership_check_(0)
        , last_heartbeat_publish_(0)
        , initialized_(false)
    {}
    ~BackgroundTaskManager() = default;

    // Prevent copying
    BackgroundTaskManager(const BackgroundTaskManager&) = delete;
    BackgroundTaskManager& operator=(const BackgroundTaskManager&) = delete;

    messenger_context_t* ctx_;
    std::string identity_;

    uint64_t last_gsk_poll_;
    uint64_t last_ownership_check_;
    uint64_t last_heartbeat_publish_;

    bool initialized_;

    // Poll intervals (seconds)
    static constexpr uint64_t GSK_POLL_INTERVAL = 120;          // 2 minutes
    static constexpr uint64_t OWNERSHIP_CHECK_INTERVAL = 120;   // 2 minutes
    static constexpr uint64_t HEARTBEAT_PUBLISH_INTERVAL = 21600; // 6 hours
};

} // namespace DNA

#endif // BACKGROUND_TASKS_H
