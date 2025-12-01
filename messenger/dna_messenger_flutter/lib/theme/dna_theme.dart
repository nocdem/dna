// DNA Messenger Theme
// Colors from cpunk.io

import 'package:flutter/material.dart';

/// Cpunk theme colors (cpunk.io)
class DnaColors {
  // Backgrounds
  static const background = Color(0xFF050712);
  static const surface = Color(0xFF111426);
  static const panel = Color(0xFF151832);

  // Primary accent (cyan)
  static const primary = Color(0xFF00F0FF);
  static const primarySoft = Color(0x1400F0FF); // 8% alpha

  // Secondary accent (magenta)
  static const accent = Color(0xFFFF2CD8);

  // Text
  static const text = Color(0xFFF5F7FF);
  static const textMuted = Color(0xFF9AA4D4);

  // Status colors
  static const textSuccess = Color(0xFF40FF86);
  static const textWarning = Color(0xFFFF8080);
  static const textInfo = Color(0xFFFFCC66);

  // Borders
  static const border = Color(0x0FFFFFFF); // 6% white
  static const borderAccent = Color(0x4D00F0FF); // 30% cyan
}

class DnaTheme {
  static ThemeData get theme => ThemeData(
    useMaterial3: true,
    brightness: Brightness.dark,
    scaffoldBackgroundColor: DnaColors.background,
    colorScheme: ColorScheme.dark(
      surface: DnaColors.surface,
      primary: DnaColors.primary,
      onPrimary: DnaColors.background,
      secondary: DnaColors.accent,
      onSecondary: DnaColors.background,
      outline: DnaColors.borderAccent,
    ),
    appBarTheme: const AppBarTheme(
      backgroundColor: DnaColors.background,
      foregroundColor: DnaColors.primary,
      elevation: 0,
      centerTitle: false,
    ),
    cardTheme: CardThemeData(
      color: DnaColors.surface,
      elevation: 0,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(12),
        side: const BorderSide(color: DnaColors.border, width: 1),
      ),
    ),
    listTileTheme: const ListTileThemeData(
      textColor: DnaColors.text,
      iconColor: DnaColors.primary,
    ),
    inputDecorationTheme: InputDecorationTheme(
      filled: true,
      fillColor: DnaColors.surface,
      hintStyle: const TextStyle(color: DnaColors.textMuted),
      border: OutlineInputBorder(
        borderRadius: BorderRadius.circular(8),
        borderSide: const BorderSide(color: DnaColors.borderAccent),
      ),
      enabledBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(8),
        borderSide: const BorderSide(color: DnaColors.borderAccent),
      ),
      focusedBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(8),
        borderSide: const BorderSide(color: DnaColors.primary, width: 2),
      ),
    ),
    elevatedButtonTheme: ElevatedButtonThemeData(
      style: ElevatedButton.styleFrom(
        backgroundColor: DnaColors.primary,
        foregroundColor: DnaColors.background,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(8),
        ),
        padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 12),
      ),
    ),
    outlinedButtonTheme: OutlinedButtonThemeData(
      style: OutlinedButton.styleFrom(
        foregroundColor: DnaColors.primary,
        side: const BorderSide(color: DnaColors.primary),
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(8),
        ),
        padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 12),
      ),
    ),
    textButtonTheme: TextButtonThemeData(
      style: TextButton.styleFrom(
        foregroundColor: DnaColors.primary,
      ),
    ),
    floatingActionButtonTheme: const FloatingActionButtonThemeData(
      backgroundColor: DnaColors.primary,
      foregroundColor: DnaColors.background,
    ),
    dividerTheme: const DividerThemeData(
      color: DnaColors.border,
      thickness: 1,
    ),
    textTheme: const TextTheme(
      headlineLarge: TextStyle(color: DnaColors.text, fontWeight: FontWeight.bold),
      headlineMedium: TextStyle(color: DnaColors.text, fontWeight: FontWeight.bold),
      headlineSmall: TextStyle(color: DnaColors.text, fontWeight: FontWeight.bold),
      titleLarge: TextStyle(color: DnaColors.text),
      titleMedium: TextStyle(color: DnaColors.text),
      titleSmall: TextStyle(color: DnaColors.text),
      bodyLarge: TextStyle(color: DnaColors.text),
      bodyMedium: TextStyle(color: DnaColors.text),
      bodySmall: TextStyle(color: DnaColors.textMuted),
      labelLarge: TextStyle(color: DnaColors.text),
      labelMedium: TextStyle(color: DnaColors.text),
      labelSmall: TextStyle(color: DnaColors.textMuted),
    ),
    iconTheme: const IconThemeData(color: DnaColors.primary),
    snackBarTheme: const SnackBarThemeData(
      backgroundColor: DnaColors.surface,
      contentTextStyle: TextStyle(color: DnaColors.text),
      actionTextColor: DnaColors.primary,
    ),
    switchTheme: SwitchThemeData(
      thumbColor: WidgetStateProperty.resolveWith((states) {
        if (states.contains(WidgetState.selected)) {
          return DnaColors.primary;
        }
        return DnaColors.textMuted;
      }),
      trackColor: WidgetStateProperty.resolveWith((states) {
        if (states.contains(WidgetState.selected)) {
          return DnaColors.primarySoft;
        }
        return DnaColors.surface;
      }),
    ),
    dialogTheme: DialogThemeData(
      backgroundColor: DnaColors.surface,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(16),
        side: const BorderSide(color: DnaColors.border),
      ),
    ),
    bottomNavigationBarTheme: const BottomNavigationBarThemeData(
      backgroundColor: DnaColors.background,
      selectedItemColor: DnaColors.primary,
      unselectedItemColor: DnaColors.textMuted,
    ),
  );
}
