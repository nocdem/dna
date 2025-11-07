#ifndef SETTINGS_MANAGER_H
#define SETTINGS_MANAGER_H

#include <string>

struct AppSettings {
    int theme;           // 0 = DNA, 1 = Club
    float font_scale;    // 1.1 = Default, 1.5 = Bigger
    int window_width;    // Window width
    int window_height;   // Window height
    
    AppSettings() : theme(0), font_scale(1.1f), window_width(1280), window_height(720) {}
};

class SettingsManager {
public:
    static bool Load(AppSettings& settings);
    static bool Save(const AppSettings& settings);
    static std::string GetSettingsPath();
};

#endif // SETTINGS_MANAGER_H
