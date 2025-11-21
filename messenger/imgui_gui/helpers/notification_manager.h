/**
 * @file notification_manager.h
 * @brief Notification Manager for DNA Messenger GUI
 *
 * Manages banner notifications for:
 * - GSK rotations
 * - Ownership transfers
 * - Member changes
 * - System alerts
 *
 * Part of DNA Messenger v0.09 - GSK Upgrade
 *
 * @date 2025-11-21
 */

#ifndef NOTIFICATION_MANAGER_H
#define NOTIFICATION_MANAGER_H

#include <string>
#include <vector>
#include <cstdint>

namespace DNA {

/**
 * Notification types
 */
enum class NotificationType {
    INFO,           // Blue - General information
    SUCCESS,        // Green - Successful operation
    WARNING,        // Yellow - Warning/attention needed
    ERROR,          // Red - Error occurred
    OWNERSHIP       // Purple - Ownership change
};

/**
 * Notification structure
 */
struct Notification {
    uint64_t id;                    // Unique notification ID
    NotificationType type;          // Notification type (color)
    std::string title;              // Short title (e.g., "GSK Rotated")
    std::string message;            // Detailed message
    std::string group_name;         // Associated group name (optional)
    uint64_t timestamp;             // Unix timestamp when created
    bool dismissable;               // Can user dismiss this?
    bool auto_dismiss;              // Auto-dismiss after timeout?
    uint32_t auto_dismiss_seconds;  // Seconds until auto-dismiss (default: 10)

    // Internal state
    bool dismissed;                 // User dismissed this notification
    uint64_t dismissed_at;          // When was it dismissed
};

/**
 * Notification Manager
 *
 * Singleton class managing notification lifecycle
 */
class NotificationManager {
public:
    /**
     * Get singleton instance
     */
    static NotificationManager& getInstance();

    /**
     * Add a new notification
     *
     * @param type Notification type (determines color)
     * @param title Short title
     * @param message Detailed message
     * @param group_name Associated group (optional)
     * @param dismissable Can user dismiss? (default: true)
     * @param auto_dismiss Auto-dismiss after timeout? (default: true)
     * @param auto_dismiss_seconds Timeout in seconds (default: 10)
     * @return Notification ID
     */
    uint64_t addNotification(
        NotificationType type,
        const std::string& title,
        const std::string& message,
        const std::string& group_name = "",
        bool dismissable = true,
        bool auto_dismiss = true,
        uint32_t auto_dismiss_seconds = 10
    );

    /**
     * Add GSK rotation notification
     *
     * Convenience helper for GSK rotations.
     *
     * @param group_name Group name
     * @param new_version New GSK version
     * @param reason Reason for rotation (e.g., "Member added")
     * @return Notification ID
     */
    uint64_t addGSKRotationNotification(
        const std::string& group_name,
        uint32_t new_version,
        const std::string& reason
    );

    /**
     * Add ownership transfer notification
     *
     * Convenience helper for ownership changes.
     *
     * @param group_name Group name
     * @param new_owner_name New owner's name
     * @param i_am_new_owner Did I become the new owner?
     * @return Notification ID
     */
    uint64_t addOwnershipTransferNotification(
        const std::string& group_name,
        const std::string& new_owner_name,
        bool i_am_new_owner
    );

    /**
     * Add member change notification
     *
     * Convenience helper for member add/remove.
     *
     * @param group_name Group name
     * @param member_name Member's name
     * @param was_added true if added, false if removed
     * @return Notification ID
     */
    uint64_t addMemberChangeNotification(
        const std::string& group_name,
        const std::string& member_name,
        bool was_added
    );

    /**
     * Dismiss a notification
     *
     * @param notification_id Notification ID to dismiss
     */
    void dismissNotification(uint64_t notification_id);

    /**
     * Dismiss all notifications
     */
    void dismissAll();

    /**
     * Get all active (non-dismissed) notifications
     *
     * @return Vector of active notifications
     */
    std::vector<Notification> getActiveNotifications();

    /**
     * Update notification state (call every frame)
     *
     * Handles auto-dismiss logic.
     */
    void update();

    /**
     * Render notifications (call from ImGui render loop)
     *
     * Displays notifications as banners at the top of the screen.
     *
     * @param window_width Current window width (for positioning)
     */
    void render(float window_width);

private:
    NotificationManager() : next_id_(1) {}
    ~NotificationManager() = default;

    // Prevent copying
    NotificationManager(const NotificationManager&) = delete;
    NotificationManager& operator=(const NotificationManager&) = delete;

    std::vector<Notification> notifications_;
    uint64_t next_id_;
};

} // namespace DNA

#endif // NOTIFICATION_MANAGER_H
