import 'package:flutter/material.dart';
import 'dna_colors.dart';
import 'dna_typography.dart';
import 'dna_spacing.dart';

/// Builds ThemeData for dark and light modes
class DnaTheme {
  DnaTheme._();

  static ThemeData dark() => _build(Brightness.dark);
  static ThemeData light() => _build(Brightness.light);

  static ThemeData _build(Brightness brightness) {
    final isDark = brightness == Brightness.dark;

    final bg = isDark ? DnaColors.darkBackground : DnaColors.lightBackground;
    final surface = isDark ? DnaColors.darkSurface : DnaColors.lightSurface;
    final surfaceVariant = isDark ? DnaColors.darkSurfaceVariant : DnaColors.lightSurfaceVariant;
    final text = isDark ? DnaColors.darkText : DnaColors.lightText;
    final textSecondary = isDark ? DnaColors.darkTextSecondary : DnaColors.lightTextSecondary;
    final divider = isDark ? DnaColors.darkDivider : DnaColors.lightDivider;
    final dividerAccent = isDark ? DnaColors.darkDividerAccent : DnaColors.lightDividerAccent;

    return ThemeData(
      useMaterial3: true,
      brightness: brightness,
      scaffoldBackgroundColor: bg,
      colorScheme: ColorScheme(
        brightness: brightness,
        primary: DnaColors.primaryFixed,
        onPrimary: Colors.white,
        secondary: DnaColors.gradientStart,
        onSecondary: isDark ? DnaColors.darkBackground : Colors.white,
        error: DnaColors.error,
        onError: Colors.white,
        surface: surface,
        onSurface: text,
        surfaceContainerHighest: surfaceVariant,
        outline: dividerAccent,
        outlineVariant: divider,
      ),
      appBarTheme: AppBarTheme(
        backgroundColor: bg,
        foregroundColor: text,
        elevation: 0,
        scrolledUnderElevation: 0,
        centerTitle: false,
        titleTextStyle: TextStyle(
          color: text,
          fontSize: 20,
          fontWeight: FontWeight.w600,
        ),
      ),
      cardTheme: CardThemeData(
        color: surface,
        elevation: DnaSpacing.elevationLow,
        shadowColor: isDark ? Colors.black54 : Colors.black12,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(DnaSpacing.radiusMd),
        ),
      ),
      listTileTheme: ListTileThemeData(
        textColor: text,
        iconColor: DnaColors.primaryFixed,
        contentPadding: const EdgeInsets.symmetric(
          horizontal: DnaSpacing.lg,
          vertical: DnaSpacing.xs,
        ),
      ),
      inputDecorationTheme: InputDecorationTheme(
        filled: true,
        fillColor: surfaceVariant,
        hintStyle: TextStyle(color: textSecondary),
        border: OutlineInputBorder(
          borderRadius: BorderRadius.circular(DnaSpacing.radiusSm),
          borderSide: BorderSide.none,
        ),
        enabledBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(DnaSpacing.radiusSm),
          borderSide: BorderSide.none,
        ),
        focusedBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(DnaSpacing.radiusSm),
          borderSide: const BorderSide(color: DnaColors.primaryFixed, width: 2),
        ),
        contentPadding: const EdgeInsets.symmetric(
          horizontal: DnaSpacing.lg,
          vertical: DnaSpacing.md,
        ),
      ),
      elevatedButtonTheme: ElevatedButtonThemeData(
        style: ElevatedButton.styleFrom(
          backgroundColor: DnaColors.primaryFixed,
          foregroundColor: Colors.white,
          elevation: DnaSpacing.elevationLow,
          shadowColor: DnaColors.primaryFixed.withValues(alpha: 0.3),
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(DnaSpacing.radiusSm),
          ),
          padding: const EdgeInsets.symmetric(
            horizontal: DnaSpacing.xl,
            vertical: DnaSpacing.md,
          ),
        ),
      ),
      outlinedButtonTheme: OutlinedButtonThemeData(
        style: OutlinedButton.styleFrom(
          foregroundColor: DnaColors.primaryFixed,
          side: const BorderSide(color: DnaColors.primaryFixed),
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(DnaSpacing.radiusSm),
          ),
          padding: const EdgeInsets.symmetric(
            horizontal: DnaSpacing.xl,
            vertical: DnaSpacing.md,
          ),
        ),
      ),
      textButtonTheme: TextButtonThemeData(
        style: TextButton.styleFrom(
          foregroundColor: DnaColors.primaryFixed,
        ),
      ),
      floatingActionButtonTheme: FloatingActionButtonThemeData(
        backgroundColor: DnaColors.primaryFixed,
        foregroundColor: Colors.white,
        elevation: DnaSpacing.elevationMed,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(DnaSpacing.radiusLg),
        ),
      ),
      dividerTheme: DividerThemeData(
        color: divider,
        thickness: 1,
      ),
      textTheme: DnaTypography.textTheme(text, textSecondary),
      iconTheme: IconThemeData(color: text, size: DnaSpacing.iconLg),
      snackBarTheme: SnackBarThemeData(
        backgroundColor: surface,
        contentTextStyle: TextStyle(color: text),
        actionTextColor: DnaColors.primaryFixed,
        behavior: SnackBarBehavior.floating,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(DnaSpacing.radiusSm),
        ),
        insetPadding: const EdgeInsets.only(left: 16, right: 16, bottom: 120),
      ),
      switchTheme: SwitchThemeData(
        thumbColor: WidgetStateProperty.resolveWith((states) {
          if (states.contains(WidgetState.selected)) return Colors.white;
          return textSecondary;
        }),
        trackColor: WidgetStateProperty.resolveWith((states) {
          if (states.contains(WidgetState.selected)) return DnaColors.primaryFixed;
          return surfaceVariant;
        }),
      ),
      dialogTheme: DialogThemeData(
        backgroundColor: surface,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(DnaSpacing.radiusLg),
        ),
        elevation: DnaSpacing.elevationHigh,
      ),
      bottomNavigationBarTheme: BottomNavigationBarThemeData(
        backgroundColor: surface,
        selectedItemColor: DnaColors.primaryFixed,
        unselectedItemColor: textSecondary,
        elevation: DnaSpacing.elevationMed,
        type: BottomNavigationBarType.fixed,
      ),
      textSelectionTheme: TextSelectionThemeData(
        selectionColor: DnaColors.primaryFixed.withValues(alpha: 0.3),
        cursorColor: DnaColors.primaryFixed,
        selectionHandleColor: DnaColors.primaryFixed,
      ),
    );
  }
}
