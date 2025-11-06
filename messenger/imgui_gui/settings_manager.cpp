#include "settings_manager.h"
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#ifndef _WIN32
#include <unistd.h>
#include <pwd.h>
#else
#include <windows.h>
#include <shlobj.h>
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
        _mkdir(config_dir.c_str());
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
        } else if (strncmp(line, "font_scale=", 11) == 0) {
            settings.font_scale = (float)atof(line + 11);
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
    fprintf(f, "font_scale=%.2f\n", settings.font_scale);
    
    fclose(f);
    return true;
}
