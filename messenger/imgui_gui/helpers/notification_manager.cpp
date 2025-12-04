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
#include "../font_awesome.h"
#include <ctime>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <cstdlib>
#ifdef _WIN32
#include <windows.h>
#include <shellapi.h>
#elif defined(__APPLE__)
#include <objc/objc-runtime.h>
#else
// Linux - use libnotify if available, fallback to notify-send
#include <cstdio>
#endif

namespace DNA {

/**
 * Get singleton instance
 */
NotificationManager& NotificationManager::getInstance() {
    static NotificationManager instance;
    return instance;
}

// REMOVED: In-app notifications - use showNativeNotification() instead

// REMOVED: All in-app notification methods - use showNativeNotification() instead

// REMOVED: Old convenience methods - use showNativeNotification() directly

/**
 * Check if app window has focus
 */
bool NotificationManager::isAppFocused() {
#ifdef __linux__
    // On Linux, check if our window has focus using xdotool
    FILE* pipe = popen("xdotool getwindowfocus getwindowname 2>/dev/null", "r");
    if (pipe) {
        char buffer[256];
        if (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
            pclose(pipe);
            // Check if our app name is in the focused window title
            std::string focused_window(buffer);
            return focused_window.find("DNA Messenger") != std::string::npos;
        }
        pclose(pipe);
    }
    return false; // Default to unfocused if we can't determine
#else
    // For now, assume unfocused on other platforms to always show notifications
    // TODO: Implement proper focus detection for Windows/macOS
    return false;
#endif
}

/**
 * Show native OS notification (cross-platform)
 */
void NotificationManager::showNativeNotification(
    const std::string& title,
    const std::string& body,
    NotificationType type,
    bool force_show
) {
    // Only show if app is not focused OR force_show is true
    if (!force_show && isAppFocused()) {
        printf("[Notifications] App has focus, skipping native notification: %s\n", title.c_str());
        return;
    }

    printf("[Notifications] Showing native notification: %s - %s\n", title.c_str(), body.c_str());

#ifdef _WIN32
    // Windows: Use proper toast notifications (Windows 10+)
    std::string ps_script = 
        "Add-Type -AssemblyName System.Windows.Forms; "
        "$notify = New-Object System.Windows.Forms.NotifyIcon; "
        "$notify.Icon = [System.Drawing.SystemIcons]::Information; "
        "$notify.BalloonTipTitle = '" + title + "'; "
        "$notify.BalloonTipText = '" + body + "'; "
        "$notify.Visible = $true; "
        "$notify.ShowBalloonTip(5000); "
        "Start-Sleep -Seconds 6; "
        "$notify.Dispose()";
    
    std::string command = "powershell -WindowStyle Hidden -Command \"" + ps_script + "\"";
    std::system(command.c_str());
    
#elif defined(__APPLE__)
    // macOS: Use proper NSUserNotification
    std::string safe_title = title;
    std::string safe_body = body;
    std::replace(safe_title.begin(), safe_title.end(), '"', '\\\"');
    std::replace(safe_body.begin(), safe_body.end(), '"', '\\\"');
    
    std::string script = "display notification \"" + safe_body + "\" with title \"" + safe_title + "\" sound name \"Ping\"";
    std::string command = "osascript -e '" + script + "'";
    std::system(command.c_str());
    
#else
    // Linux: Use libnotify (notify-send) with proper icons and urgency
    std::string icon;
    std::string urgency = "normal";
    
    switch (type) {
        case NotificationType::MESSAGE:
            icon = "mail-message-new";
            urgency = "normal";
            break;
        case NotificationType::ERROR:
            icon = "dialog-error";
            urgency = "critical";
            break;
        case NotificationType::SUCCESS:
            icon = "dialog-information";
            urgency = "low";
            break;
        case NotificationType::WARNING:
            icon = "dialog-warning";
            urgency = "normal";
            break;
        case NotificationType::WALLET:
            icon = "applications-office";
            urgency = "normal";
            break;
        default:
            icon = "dialog-information";
            urgency = "low";
            break;
    }
    
    // Escape quotes and special characters
    std::string safe_title = title;
    std::string safe_body = body;
    std::replace(safe_title.begin(), safe_title.end(), '"', '\'');
    std::replace(safe_body.begin(), safe_body.end(), '"', '\'');
    std::replace(safe_title.begin(), safe_title.end(), '`', '\'');
    std::replace(safe_body.begin(), safe_body.end(), '`', '\'');
    
    // Build notify-send command with proper options
    std::string command = "notify-send"
        " --urgency=" + urgency +
        " --icon=" + icon +
        " --app-name=\"DNA Messenger\"" +
        " --expire-time=5000" +
        " \"" + safe_title + "\"" +
        " \"" + safe_body + "\"";
    
    printf("[Notifications] Running: %s\n", command.c_str());
    int result = std::system(command.c_str());
    
    if (result != 0) {
        // Fallback to zenity if notify-send fails
        printf("[Notifications] notify-send failed, trying zenity fallback\n");
        std::string zenity_cmd = "zenity --info --no-wrap --timeout=5 --title=\"" + 
                               safe_title + "\" --text=\"" + safe_body + "\"";
        std::system(zenity_cmd.c_str());
    }
#endif
}

} // namespace DNA
