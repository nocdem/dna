#ifndef SETTINGS_MANAGER_H
#define SETTINGS_MANAGER_H

#include <string>
#include <vector>

struct AppSettings {
    int theme;           // 0 = DNA, 1 = Club
    float ui_scale;      // 1.1 = Normal (100%), 1.375 = Large (125%)
    int window_width;    // Window width
    int window_height;   // Window height
    
    // Wallet settings
    std::vector<std::string> custom_wallet_paths;  // User-selected wallet file paths
    bool prefer_custom_wallets;  // Use custom paths over standard discovery
    
    AppSettings() : theme(0), ui_scale(1.1f), window_width(1280), window_height(720), 
                   prefer_custom_wallets(false) {}
};

class SettingsManager {
public:
    static bool Load(AppSettings& settings);
    static bool Save(const AppSettings& settings);
    static std::string GetSettingsPath();
    
    // Wallet path management
    static void AddWalletPath(const std::string& path);
    static void RemoveWalletPath(const std::string& path);
    static void ClearWalletPaths();
    static bool HasWalletPath(const std::string& path);
};

#endif // SETTINGS_MANAGER_H
