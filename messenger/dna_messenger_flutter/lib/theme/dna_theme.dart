// DNA Messenger Theme
// Ported from imgui_gui/theme_colors.h

import 'package:flutter/material.dart';

/// DNA Theme colors (cpunk.io)
class DnaColors {
  static const background = Color(0xFF191D21);
  static const surface = Color(0xFF1E2227);
  static const inputBackground = Color(0xFF1F2429);
  static const primary = Color(0xFF00FFCC);
  static const primaryDark = Color(0xFF00D9AD);
  static const primaryDarker = Color(0xFF00BF99);
  static const text = Color(0xFF00FFCC);
  static const textDisabled = Color(0xFFCCCCCC);
  static const textHint = Color(0xFFB3B3B3);
  static const textWarning = Color(0xFFFF8080);
  static const textSuccess = Color(0xFF80FF80);
  static const textInfo = Color(0xFFFFCC66);
  static const offline = Color(0xFFDDDDDD);
  static const separator = Color(0x4D00FFCC); // 30% alpha
  static const border = Color(0x4D00FFCC);
}

/// Club Theme colors (cpunk.club)
class ClubColors {
  static const background = Color(0xFF201D1C);
  static const surface = Color(0xFF262220);
  static const inputBackground = Color(0xFF262320);
  static const primary = Color(0xFFF97834);
  static const primaryDark = Color(0xFFDF662F);
  static const primaryDarker = Color(0xFFC6592A);
  static const text = Color(0xFFF97834);
  static const textDisabled = Color(0xFFCCCCCC);
  static const textHint = Color(0xFFB3B3B3);
  static const textWarning = Color(0xFFFF8080);
  static const textSuccess = Color(0xFF80FF80);
  static const textInfo = Color(0xFFFFCC66);
  static const offline = Color(0xFFDDDDDD);
  static const separator = Color(0x4DF97834); // 30% alpha
  static const border = Color(0x4DF97834);
}

enum AppTheme { dna, club }

class DnaTheme {
  static ThemeData get dna => _buildTheme(
        background: DnaColors.background,
        surface: DnaColors.surface,
        primary: DnaColors.primary,
        primaryDark: DnaColors.primaryDark,
        text: DnaColors.text,
        textHint: DnaColors.textHint,
      );

  static ThemeData get club => _buildTheme(
        background: ClubColors.background,
        surface: ClubColors.surface,
        primary: ClubColors.primary,
        primaryDark: ClubColors.primaryDark,
        text: ClubColors.text,
        textHint: ClubColors.textHint,
      );

  static ThemeData _buildTheme({
    required Color background,
    required Color surface,
    required Color primary,
    required Color primaryDark,
    required Color text,
    required Color textHint,
  }) {
    return ThemeData(
      useMaterial3: true,
      brightness: Brightness.dark,
      scaffoldBackgroundColor: background,
      colorScheme: ColorScheme.dark(
        surface: surface,
        primary: primary,
        onPrimary: background,
        secondary: primary,
        onSecondary: background,
        outline: primary.withAlpha(77), // 30%
      ),
      appBarTheme: AppBarTheme(
        backgroundColor: background,
        foregroundColor: primary,
        elevation: 0,
        centerTitle: false,
      ),
      cardTheme: CardThemeData(
        color: surface,
        elevation: 0,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(12),
          side: BorderSide(color: primary.withAlpha(51), width: 1),
        ),
      ),
      listTileTheme: ListTileThemeData(
        textColor: text,
        iconColor: primary,
      ),
      inputDecorationTheme: InputDecorationTheme(
        filled: true,
        fillColor: surface,
        hintStyle: TextStyle(color: textHint),
        border: OutlineInputBorder(
          borderRadius: BorderRadius.circular(8),
          borderSide: BorderSide(color: primary.withAlpha(77)),
        ),
        enabledBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(8),
          borderSide: BorderSide(color: primary.withAlpha(77)),
        ),
        focusedBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(8),
          borderSide: BorderSide(color: primary, width: 2),
        ),
      ),
      elevatedButtonTheme: ElevatedButtonThemeData(
        style: ElevatedButton.styleFrom(
          backgroundColor: primary,
          foregroundColor: background,
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(8),
          ),
          padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 12),
        ),
      ),
      outlinedButtonTheme: OutlinedButtonThemeData(
        style: OutlinedButton.styleFrom(
          foregroundColor: primary,
          side: BorderSide(color: primary),
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(8),
          ),
          padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 12),
        ),
      ),
      textButtonTheme: TextButtonThemeData(
        style: TextButton.styleFrom(
          foregroundColor: primary,
        ),
      ),
      floatingActionButtonTheme: FloatingActionButtonThemeData(
        backgroundColor: primary,
        foregroundColor: background,
      ),
      dividerTheme: DividerThemeData(
        color: primary.withAlpha(51),
        thickness: 1,
      ),
      textTheme: TextTheme(
        headlineLarge: TextStyle(color: text, fontWeight: FontWeight.bold),
        headlineMedium: TextStyle(color: text, fontWeight: FontWeight.bold),
        headlineSmall: TextStyle(color: text, fontWeight: FontWeight.bold),
        titleLarge: TextStyle(color: text),
        titleMedium: TextStyle(color: text),
        titleSmall: TextStyle(color: text),
        bodyLarge: TextStyle(color: text),
        bodyMedium: TextStyle(color: text),
        bodySmall: TextStyle(color: textHint),
        labelLarge: TextStyle(color: text),
        labelMedium: TextStyle(color: text),
        labelSmall: TextStyle(color: textHint),
      ),
      iconTheme: IconThemeData(color: primary),
      snackBarTheme: SnackBarThemeData(
        backgroundColor: surface,
        contentTextStyle: TextStyle(color: text),
        actionTextColor: primary,
      ),
    );
  }
}
