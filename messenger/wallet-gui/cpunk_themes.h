/*
 * cpunk-wallet-gui - Theme Definitions
 *
 * Provides cpunk.io (cyan) and cpunk.club (orange) branding themes
 */

#ifndef CPUNK_THEMES_H
#define CPUNK_THEMES_H

#include <QString>

// ============================================================================
// THEME ENUM
// ============================================================================

enum CpunkTheme {
    THEME_CPUNK_IO,     // Cyan theme
    THEME_CPUNK_CLUB    // Orange theme
};

// ============================================================================
// THEME COLORS
// ============================================================================

// cpunk.io colors (cyan)
#define CPUNK_IO_PRIMARY      "#00D9FF"
#define CPUNK_IO_BACKGROUND   "#0A2428"
#define CPUNK_IO_SECONDARY    "#0D3438"
#define CPUNK_IO_BORDER       "rgba(0, 217, 255, 0.3)"
#define CPUNK_IO_HOVER        "rgba(0, 217, 255, 0.3)"
#define CPUNK_IO_PRESSED      "rgba(0, 217, 255, 0.4)"
#define CPUNK_IO_TEXT         "#FFFFFF"

// cpunk.club colors (orange)
#define CPUNK_CLUB_PRIMARY    "#FF8800"
#define CPUNK_CLUB_BACKGROUND "#281E0A"
#define CPUNK_CLUB_SECONDARY  "#38280D"
#define CPUNK_CLUB_BORDER     "rgba(255, 136, 0, 0.3)"
#define CPUNK_CLUB_HOVER      "rgba(255, 136, 0, 0.3)"
#define CPUNK_CLUB_PRESSED    "rgba(255, 136, 0, 0.4)"
#define CPUNK_CLUB_TEXT       "#FFFFFF"

// ============================================================================
// THEME STYLESHEET GENERATOR
// ============================================================================

inline QString getCpunkStyleSheet(CpunkTheme theme) {
    QString primary, background, secondary, border, hover, pressed, text;

    if (theme == THEME_CPUNK_IO) {
        primary = CPUNK_IO_PRIMARY;
        background = CPUNK_IO_BACKGROUND;
        secondary = CPUNK_IO_SECONDARY;
        border = CPUNK_IO_BORDER;
        hover = CPUNK_IO_HOVER;
        pressed = CPUNK_IO_PRESSED;
        text = CPUNK_IO_TEXT;
    } else {
        primary = CPUNK_CLUB_PRIMARY;
        background = CPUNK_CLUB_BACKGROUND;
        secondary = CPUNK_CLUB_SECONDARY;
        border = CPUNK_CLUB_BORDER;
        hover = CPUNK_CLUB_HOVER;
        pressed = CPUNK_CLUB_PRESSED;
        text = CPUNK_CLUB_TEXT;
    }

    return QString(
        "QMainWindow {"
        "   background: %1;"
        "   color: %7;"
        "}"
        "QWidget {"
        "   background: %1;"
        "   color: %7;"
        "}"
        "QMenuBar {"
        "   background: %2;"
        "   color: %7;"
        "   border-bottom: 1px solid %4;"
        "}"
        "QMenuBar::item:selected {"
        "   background: %5;"
        "}"
        "QMenu {"
        "   background: %2;"
        "   color: %7;"
        "   border: 1px solid %4;"
        "}"
        "QMenu::item:selected {"
        "   background: %5;"
        "}"
        "QTabWidget::pane {"
        "   border: 1px solid %4;"
        "   background: %2;"
        "}"
        "QTabBar::tab {"
        "   background: %2;"
        "   color: %7;"
        "   padding: 10px 20px;"
        "   border: 1px solid %4;"
        "   border-bottom: none;"
        "   margin-right: 2px;"
        "}"
        "QTabBar::tab:selected {"
        "   background: %3;"
        "   color: %0;"
        "   font-weight: bold;"
        "}"
        "QTableWidget {"
        "   background: %2;"
        "   color: %0;"
        "   gridline-color: %4;"
        "   border: 1px solid %4;"
        "}"
        "QTableWidget::item {"
        "   padding: 8px;"
        "}"
        "QTableWidget::item:selected {"
        "   background: %5;"
        "}"
        "QHeaderView::section {"
        "   background: %4;"
        "   color: %0;"
        "   padding: 8px;"
        "   border: 1px solid %4;"
        "   font-weight: bold;"
        "}"
        "QPushButton {"
        "   background: %4;"
        "   color: %0;"
        "   border: 1px solid %4;"
        "   border-radius: 4px;"
        "   padding: 10px 20px;"
        "   font-weight: bold;"
        "}"
        "QPushButton:hover {"
        "   background: %5;"
        "   border-color: %0;"
        "}"
        "QPushButton:pressed {"
        "   background: %6;"
        "}"
        "QPushButton:disabled {"
        "   background: rgba(128, 128, 128, 0.2);"
        "   color: rgba(255, 255, 255, 0.3);"
        "   border-color: rgba(128, 128, 128, 0.3);"
        "}"
        "QLineEdit, QTextEdit, QComboBox {"
        "   background: %2;"
        "   color: %7;"
        "   border: 1px solid %4;"
        "   border-radius: 4px;"
        "   padding: 8px;"
        "}"
        "QLineEdit:focus, QTextEdit:focus, QComboBox:focus {"
        "   border-color: %0;"
        "}"
        "QLabel {"
        "   color: %7;"
        "}"
        "QStatusBar {"
        "   background: %2;"
        "   color: %0;"
        "   border-top: 1px solid %4;"
        "}"
        "QGroupBox {"
        "   border: 1px solid %4;"
        "   border-radius: 4px;"
        "   margin-top: 10px;"
        "   padding-top: 10px;"
        "   color: %0;"
        "   font-weight: bold;"
        "}"
        "QGroupBox::title {"
        "   subcontrol-origin: margin;"
        "   left: 10px;"
        "   padding: 0 5px;"
        "}"
    ).arg(primary, background, secondary, border, hover, pressed, text);
}

#endif // CPUNK_THEMES_H
