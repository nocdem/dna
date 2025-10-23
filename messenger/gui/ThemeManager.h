/*
 * ThemeManager.h - Global Theme Manager Singleton
 * Manages theme switching across all windows
 */

#ifndef THEMEMANAGER_H
#define THEMEMANAGER_H

#include <QObject>
#include <QSettings>
#include "cpunk_themes.h"

class ThemeManager : public QObject {
    Q_OBJECT

public:
    static ThemeManager* instance();

    CpunkTheme currentTheme() const { return m_currentTheme; }
    void setTheme(CpunkTheme theme);
    void toggleTheme();

signals:
    void themeChanged(CpunkTheme newTheme);

private:
    ThemeManager();
    ~ThemeManager();
    ThemeManager(const ThemeManager&) = delete;
    ThemeManager& operator=(const ThemeManager&) = delete;

    CpunkTheme m_currentTheme;
    QSettings* m_settings;
};

#endif // THEMEMANAGER_H
