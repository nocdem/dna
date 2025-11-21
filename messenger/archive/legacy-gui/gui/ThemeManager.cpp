/*
 * ThemeManager.cpp - Global Theme Manager Implementation
 */

#include "ThemeManager.h"

ThemeManager* ThemeManager::instance() {
    static ThemeManager* inst = nullptr;
    if (!inst) {
        inst = new ThemeManager();
    }
    return inst;
}

ThemeManager::ThemeManager()
    : QObject(nullptr)
    , m_currentTheme(THEME_CPUNK_IO)
    , m_settings(nullptr) {

    m_settings = new QSettings("DNA Messenger", "GUI", this);

    // Load saved theme
    QString savedTheme = m_settings->value("theme", "io").toString();
    if (savedTheme == "club") {
        m_currentTheme = THEME_CPUNK_CLUB;
    } else {
        m_currentTheme = THEME_CPUNK_IO;
    }
}

ThemeManager::~ThemeManager() {
}

void ThemeManager::setTheme(CpunkTheme theme) {
    if (m_currentTheme == theme) {
        return;  // No change
    }

    m_currentTheme = theme;

    // Save to settings
    QString themeName = (theme == THEME_CPUNK_IO) ? "io" : "club";
    m_settings->setValue("theme", themeName);

    // Broadcast to all windows
    emit themeChanged(theme);
}

void ThemeManager::toggleTheme() {
    if (m_currentTheme == THEME_CPUNK_IO) {
        setTheme(THEME_CPUNK_CLUB);
    } else {
        setTheme(THEME_CPUNK_IO);
    }
}
