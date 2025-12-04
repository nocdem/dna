#include "settings_manager.h"
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <algorithm>

#ifndef _WIN32
#include <unistd.h>
#include <pwd.h>
#else
#include <windows.h>
#include <shlobj.h>
#include <direct.h>  // For _mkdir
#endif

std::string SettingsManager::GetSettingsPath() {
    std::string config_dir;
    
#ifndef _WIN32
    const char* home = getenv("HOME");
    if (!home) {
        struct passwd* pw = getpwuid(getuid());
        home = pw->pw_dir;
    }
    config_dir = std::string(home) + "/.dna";
#else
    char path[MAX_PATH];
    if (SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, path) == S_OK) {
        config_dir = std::string(path) + "\\DNA";
    } else {
        config_dir = ".\\dna";
    }
#endif

    // Create directory if it doesn't exist
    struct stat st = {0};
    if (stat(config_dir.c_str(), &st) == -1) {
#ifndef _WIN32
        mkdir(config_dir.c_str(), 0700);
#else
        _mkdir(config_dir.c_str()); // MinGW uses _mkdir from direct.h
#endif
    }
    
    return config_dir + 
#ifndef _WIN32
        "/imgui_settings.conf";
#else
        "\\imgui_settings.conf";
#endif
}

bool SettingsManager::Load(AppSettings& settings) {
    std::string path = GetSettingsPath();
    FILE* f = fopen(path.c_str(), "r");
    if (!f) {
        return false;
    }
    
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        // Remove newline
        line[strcspn(line, "\r\n")] = 0;
        
        if (strncmp(line, "theme=", 6) == 0) {
            settings.theme = atoi(line + 6);
        } else if (strncmp(line, "ui_scale=", 9) == 0) {
            settings.ui_scale = (float)atof(line + 9);
        } else if (strncmp(line, "font_scale=", 11) == 0) {
            // Legacy: convert old font_scale to ui_scale
            settings.ui_scale = (float)atof(line + 11);
        } else if (strncmp(line, "window_width=", 13) == 0) {
            settings.window_width = atoi(line + 13);
        } else if (strncmp(line, "window_height=", 14) == 0) {
            settings.window_height = atoi(line + 14);
        } else if (strncmp(line, "custom_wallet_path=", 19) == 0) {
            settings.custom_wallet_paths.push_back(std::string(line + 19));
        } else if (strncmp(line, "prefer_custom_wallets=", 22) == 0) {
            settings.prefer_custom_wallets = (atoi(line + 22) != 0);
        }
    }
    
    fclose(f);
    return true;
}

bool SettingsManager::Save(const AppSettings& settings) {
    std::string path = GetSettingsPath();
    FILE* f = fopen(path.c_str(), "w");
    if (!f) {
        return false;
    }
    
    fprintf(f, "theme=%d\n", settings.theme);
    fprintf(f, "ui_scale=%.2f\n", settings.ui_scale);
    fprintf(f, "window_width=%d\n", settings.window_width);
    fprintf(f, "window_height=%d\n", settings.window_height);
    
    // Save wallet settings
    fprintf(f, "prefer_custom_wallets=%d\n", settings.prefer_custom_wallets ? 1 : 0);
    for (const auto& path : settings.custom_wallet_paths) {
        fprintf(f, "custom_wallet_path=%s\n", path.c_str());
    }
    
    fclose(f);
    return true;
}

// Global settings instance for wallet path management
extern AppSettings g_app_settings;

void SettingsManager::AddWalletPath(const std::string& path) {
    // Check if path already exists
    for (const auto& existing : g_app_settings.custom_wallet_paths) {
        if (existing == path) {
            return; // Already exists
        }
    }
    
    g_app_settings.custom_wallet_paths.push_back(path);
    Save(g_app_settings);
    printf("[Settings] Added wallet path: %s\n", path.c_str());
}

void SettingsManager::RemoveWalletPath(const std::string& path) {
    auto it = std::find(g_app_settings.custom_wallet_paths.begin(), 
                       g_app_settings.custom_wallet_paths.end(), path);
    if (it != g_app_settings.custom_wallet_paths.end()) {
        g_app_settings.custom_wallet_paths.erase(it);
        Save(g_app_settings);
        printf("[Settings] Removed wallet path: %s\n", path.c_str());
    }
}

void SettingsManager::ClearWalletPaths() {
    g_app_settings.custom_wallet_paths.clear();
    Save(g_app_settings);
    printf("[Settings] Cleared all wallet paths\n");
}

bool SettingsManager::HasWalletPath(const std::string& path) {
    for (const auto& existing : g_app_settings.custom_wallet_paths) {
        if (existing == path) {
            return true;
        }
    }
    return false;
}
