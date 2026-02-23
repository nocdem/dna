import 'package:flutter/material.dart';
import 'dna_colors.dart';

/// Reusable gradient definitions for the DNA design system
class DnaGradients {
  DnaGradients._();

  /// Primary brand gradient (cyan → blue) — horizontal
  static const primary = LinearGradient(
    colors: [DnaColors.gradientStart, DnaColors.gradientEnd],
  );

  /// Primary gradient — vertical (for headers, cards)
  static const primaryVertical = LinearGradient(
    begin: Alignment.topCenter,
    end: Alignment.bottomCenter,
    colors: [DnaColors.gradientStart, DnaColors.gradientEnd],
  );

  /// Subtle gradient for backgrounds (very low opacity)
  static LinearGradient primarySoft(Brightness brightness) {
    final opacity = brightness == Brightness.dark ? 0.08 : 0.05;
    return LinearGradient(
      colors: [
        DnaColors.gradientStart.withValues(alpha: opacity),
        DnaColors.gradientEnd.withValues(alpha: opacity),
      ],
    );
  }

  /// Shader callback for gradient text/icons
  static Shader primaryShader(Rect bounds) {
    return primary.createShader(bounds);
  }
}
