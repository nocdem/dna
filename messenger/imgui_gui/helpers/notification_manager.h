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
    OWNERSHIP,      // Purple - Ownership change
    MESSAGE,        // Cyan - New message notification
    CONTACT,        // Orange - Contact-related notification
    WALLET          // Gold - Wallet/transaction notification
};

// REMOVED: In-app notification structure - not needed for native OS notifications

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

    // DEPRECATED: In-app notifications removed - use showNativeNotification() instead

    // DEPRECATED: Old convenience methods removed - use showNativeNotification() directly

    /**
     * Show native OS notification (cross-platform)
     *
     * This is the PRIMARY notification method - always shows native OS notifications.
     * Use this for messages, transactions, errors, etc.
     *
     * @param title Notification title
     * @param body Notification body
     * @param type Notification type (determines icon/urgency)
     * @param force_show If true, shows even when app is focused
     */
    static void showNativeNotification(
        const std::string& title,
        const std::string& body,
        NotificationType type = NotificationType::INFO,
        bool force_show = false
    );

    /**
     * Check if app window has focus
     * @return true if app window is focused, false otherwise
     */
    static bool isAppFocused();

    // DEPRECATED: In-app notification methods removed

private:
    NotificationManager() = default;
    ~NotificationManager() = default;

    // Prevent copying
    NotificationManager(const NotificationManager&) = delete;
    NotificationManager& operator=(const NotificationManager&) = delete;

    // No member variables needed - all methods are now static
};

} // namespace DNA

#endif // NOTIFICATION_MANAGER_H
