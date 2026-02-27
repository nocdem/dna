import 'package:flutter/material.dart';

/// Typography scale for DNA Messenger
/// Based on Material 3 type scale with custom weights
class DnaTypography {
  DnaTypography._();

  static TextTheme textTheme(Color textColor, Color mutedColor) {
    return TextTheme(
      // Display
      displayLarge: TextStyle(fontSize: 32, fontWeight: FontWeight.w700, color: textColor, height: 1.2),
      displayMedium: TextStyle(fontSize: 28, fontWeight: FontWeight.w700, color: textColor, height: 1.2),
      displaySmall: TextStyle(fontSize: 24, fontWeight: FontWeight.w700, color: textColor, height: 1.3),

      // Headlines
      headlineLarge: TextStyle(fontSize: 22, fontWeight: FontWeight.w700, color: textColor, height: 1.3),
      headlineMedium: TextStyle(fontSize: 20, fontWeight: FontWeight.w600, color: textColor, height: 1.3),
      headlineSmall: TextStyle(fontSize: 18, fontWeight: FontWeight.w600, color: textColor, height: 1.4),

      // Titles
      titleLarge: TextStyle(fontSize: 17, fontWeight: FontWeight.w600, color: textColor, height: 1.4),
      titleMedium: TextStyle(fontSize: 15, fontWeight: FontWeight.w600, color: textColor, height: 1.4),
      titleSmall: TextStyle(fontSize: 13, fontWeight: FontWeight.w600, color: textColor, height: 1.4),

      // Body
      bodyLarge: TextStyle(fontSize: 16, fontWeight: FontWeight.w400, color: textColor, height: 1.5),
      bodyMedium: TextStyle(fontSize: 14, fontWeight: FontWeight.w400, color: textColor, height: 1.5),
      bodySmall: TextStyle(fontSize: 12, fontWeight: FontWeight.w400, color: mutedColor, height: 1.5),

      // Labels
      labelLarge: TextStyle(fontSize: 14, fontWeight: FontWeight.w500, color: textColor, height: 1.4),
      labelMedium: TextStyle(fontSize: 12, fontWeight: FontWeight.w500, color: textColor, height: 1.4),
      labelSmall: TextStyle(fontSize: 11, fontWeight: FontWeight.w500, color: mutedColor, height: 1.4, letterSpacing: 0.5),
    );
  }
}
