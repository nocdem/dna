/**
 * @file notification_manager.cpp
 * @brief Notification Manager Implementation
 *
 * Part of DNA Messenger v0.09 - GSK Upgrade
 *
 * @date 2025-11-21
 */

#include "notification_manager.h"
#include "../vendor/imgui/imgui.h"
#include <ctime>
#include <algorithm>
#include <sstream>
#include <iomanip>

namespace DNA {

/**
 * Get singleton instance
 */
NotificationManager& NotificationManager::getInstance() {
    static NotificationManager instance;
    return instance;
}

/**
 * Add a new notification
 */
uint64_t NotificationManager::addNotification(
    NotificationType type,
    const std::string& title,
    const std::string& message,
    const std::string& group_name,
    bool dismissable,
    bool auto_dismiss,
    uint32_t auto_dismiss_seconds
) {
    Notification notif;
    notif.id = next_id_++;
    notif.type = type;
    notif.title = title;
    notif.message = message;
    notif.group_name = group_name;
    notif.timestamp = static_cast<uint64_t>(std::time(nullptr));
    notif.dismissable = dismissable;
    notif.auto_dismiss = auto_dismiss;
    notif.auto_dismiss_seconds = auto_dismiss_seconds;
    notif.dismissed = false;
    notif.dismissed_at = 0;

    notifications_.push_back(notif);

    return notif.id;
}

/**
 * Add GSK rotation notification
 */
uint64_t NotificationManager::addGSKRotationNotification(
    const std::string& group_name,
    uint32_t new_version,
    const std::string& reason
) {
    std::stringstream msg;
    msg << "Group security key rotated to version " << new_version;
    if (!reason.empty()) {
        msg << " (" << reason << ")";
    }
    msg << ". Messages are now encrypted with the new key.";

    return addNotification(
        NotificationType::SUCCESS,
        "🔐 Security Key Rotated",
        msg.str(),
        group_name,
        true,   // dismissable
        true,   // auto_dismiss
        15      // 15 seconds
    );
}

/**
 * Add ownership transfer notification
 */
uint64_t NotificationManager::addOwnershipTransferNotification(
    const std::string& group_name,
    const std::string& new_owner_name,
    bool i_am_new_owner
) {
    std::string title;
    std::string message;
    NotificationType type;

    if (i_am_new_owner) {
        title = "👑 You Are Now Group Owner";
        message = "Previous owner was offline for 7+ days. You can now manage members and rotate security keys.";
        type = NotificationType::OWNERSHIP;
    } else {
        title = "👑 New Group Owner";
        message = "Group ownership transferred to " + new_owner_name + " (previous owner offline for 7+ days).";
        type = NotificationType::INFO;
    }

    return addNotification(
        type,
        title,
        message,
        group_name,
        true,   // dismissable
        !i_am_new_owner,  // auto-dismiss only if not me
        20      // 20 seconds
    );
}

/**
 * Add member change notification
 */
uint64_t NotificationManager::addMemberChangeNotification(
    const std::string& group_name,
    const std::string& member_name,
    bool was_added
) {
    std::string title = was_added ? "➕ Member Added" : "➖ Member Removed";
    std::string message = member_name + (was_added ? " joined " : " left ") + "the group.";

    return addNotification(
        NotificationType::INFO,
        title,
        message,
        group_name,
        true,   // dismissable
        true,   // auto_dismiss
        10      // 10 seconds
    );
}

/**
 * Dismiss a notification
 */
void NotificationManager::dismissNotification(uint64_t notification_id) {
    for (auto& notif : notifications_) {
        if (notif.id == notification_id && !notif.dismissed) {
            notif.dismissed = true;
            notif.dismissed_at = static_cast<uint64_t>(std::time(nullptr));
            break;
        }
    }
}

/**
 * Dismiss all notifications
 */
void NotificationManager::dismissAll() {
    uint64_t now = static_cast<uint64_t>(std::time(nullptr));
    for (auto& notif : notifications_) {
        if (!notif.dismissed) {
            notif.dismissed = true;
            notif.dismissed_at = now;
        }
    }
}

/**
 * Get all active (non-dismissed) notifications
 */
std::vector<Notification> NotificationManager::getActiveNotifications() {
    std::vector<Notification> active;
    for (const auto& notif : notifications_) {
        if (!notif.dismissed) {
            active.push_back(notif);
        }
    }
    return active;
}

/**
 * Update notification state (call every frame)
 */
void NotificationManager::update() {
    uint64_t now = static_cast<uint64_t>(std::time(nullptr));

    // Auto-dismiss expired notifications
    for (auto& notif : notifications_) {
        if (!notif.dismissed && notif.auto_dismiss) {
            uint64_t age = now - notif.timestamp;
            if (age >= notif.auto_dismiss_seconds) {
                notif.dismissed = true;
                notif.dismissed_at = now;
            }
        }
    }

    // Cleanup old dismissed notifications (keep last 50)
    if (notifications_.size() > 50) {
        // Remove oldest dismissed notifications
        notifications_.erase(
            std::remove_if(notifications_.begin(), notifications_.end(),
                [now](const Notification& n) {
                    return n.dismissed && (now - n.dismissed_at > 300);  // 5 minutes
                }),
            notifications_.end()
        );
    }
}

/**
 * Render notifications (call from ImGui render loop)
 */
void NotificationManager::render(float window_width) {
    auto active = getActiveNotifications();
    if (active.empty()) {
        return;
    }

    // Display notifications as stacked banners at the top
    ImGuiIO& io = ImGui::GetIO();
    const float banner_width = std::min(window_width * 0.9f, 600.0f);
    const float banner_x = (window_width - banner_width) * 0.5f;
    float banner_y = 10.0f;  // Start 10px from top

    ImGui::SetNextWindowPos(ImVec2(banner_x, banner_y));
    ImGui::SetNextWindowSize(ImVec2(banner_width, 0));  // Auto height

    ImGuiWindowFlags flags = ImGuiWindowFlags_NoTitleBar |
                              ImGuiWindowFlags_NoResize |
                              ImGuiWindowFlags_NoMove |
                              ImGuiWindowFlags_NoScrollbar |
                              ImGuiWindowFlags_NoCollapse |
                              ImGuiWindowFlags_AlwaysAutoResize;

    ImGui::Begin("##Notifications", nullptr, flags);

    // Render each notification
    for (const auto& notif : active) {
        // Choose color based on type
        ImVec4 bg_color, text_color;
        switch (notif.type) {
            case NotificationType::INFO:
                bg_color = ImVec4(0.2f, 0.5f, 0.9f, 0.95f);  // Blue
                text_color = ImVec4(1.0f, 1.0f, 1.0f, 1.0f);
                break;
            case NotificationType::SUCCESS:
                bg_color = ImVec4(0.2f, 0.8f, 0.3f, 0.95f);  // Green
                text_color = ImVec4(1.0f, 1.0f, 1.0f, 1.0f);
                break;
            case NotificationType::WARNING:
                bg_color = ImVec4(0.9f, 0.7f, 0.2f, 0.95f);  // Yellow
                text_color = ImVec4(0.0f, 0.0f, 0.0f, 1.0f);
                break;
            case NotificationType::ERROR:
                bg_color = ImVec4(0.9f, 0.2f, 0.2f, 0.95f);  // Red
                text_color = ImVec4(1.0f, 1.0f, 1.0f, 1.0f);
                break;
            case NotificationType::OWNERSHIP:
                bg_color = ImVec4(0.7f, 0.3f, 0.9f, 0.95f);  // Purple
                text_color = ImVec4(1.0f, 1.0f, 1.0f, 1.0f);
                break;
        }

        // Notification banner
        ImGui::PushStyleColor(ImGuiCol_ChildBg, bg_color);
        ImGui::PushStyleColor(ImGuiCol_Text, text_color);

        std::string child_id = "##notif_" + std::to_string(notif.id);
        ImGui::BeginChild(child_id.c_str(), ImVec2(banner_width - 20, 0), true, ImGuiWindowFlags_AlwaysAutoResize);

        // Title
        ImGui::PushFont(io.Fonts->Fonts[0]);  // Bold font (if available)
        ImGui::TextWrapped("%s", notif.title.c_str());
        ImGui::PopFont();

        // Group name (if present)
        if (!notif.group_name.empty()) {
            ImGui::SameLine();
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 1.0f, 1.0f, 0.7f));
            ImGui::TextWrapped("(%s)", notif.group_name.c_str());
            ImGui::PopStyleColor();
        }

        // Message
        ImGui::Spacing();
        ImGui::TextWrapped("%s", notif.message.c_str());

        // Dismiss button (if dismissable)
        if (notif.dismissable) {
            ImGui::Spacing();
            ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0, 0, 0, 0.3f));
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0, 0, 0, 0.5f));
            ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0, 0, 0, 0.7f));

            std::string button_id = "Dismiss##" + std::to_string(notif.id);
            if (ImGui::Button(button_id.c_str())) {
                dismissNotification(notif.id);
            }

            ImGui::PopStyleColor(3);
        }

        ImGui::EndChild();
        ImGui::PopStyleColor(2);

        ImGui::Spacing();
    }

    ImGui::End();
}

} // namespace DNA
