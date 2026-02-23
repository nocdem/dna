import 'package:flutter/material.dart';

/// DNA Messenger color system
/// Supports both dark and light themes with consistent brand identity
class DnaColors {
  DnaColors._();

  // ─── Brand Gradient ───────────────────────────────────────────
  static const gradientStart = Color(0xFF00D4FF); // Cyan
  static const gradientEnd = Color(0xFF0066FF);   // Blue
  static const primaryFixed = Color(0xFF0066FF);  // Solid fallback

  // ─── Dark Theme ───────────────────────────────────────────────
  static const darkBackground = Color(0xFF0A0E1A);
  static const darkSurface = Color(0xFF131829);
  static const darkSurfaceVariant = Color(0xFF1A2035);
  static const darkText = Color(0xFFF0F2FA);
  static const darkTextSecondary = Color(0xFF8B95B8);
  static const darkDivider = Color(0x0FFFFFFF);      // 6% white
  static const darkDividerAccent = Color(0x4D00D4FF); // 30% cyan

  // ─── Light Theme ──────────────────────────────────────────────
  static const lightBackground = Color(0xFFF5F7FA);
  static const lightSurface = Color(0xFFFFFFFF);
  static const lightSurfaceVariant = Color(0xFFEEF1F6);
  static const lightText = Color(0xFF0F172A);
  static const lightTextSecondary = Color(0xFF64748B);
  static const lightDivider = Color(0x0F000000);      // 6% black
  static const lightDividerAccent = Color(0x4D0066FF); // 30% blue

  // ─── Semantic (shared across themes) ──────────────────────────
  static const success = Color(0xFF34D399);
  static const error = Color(0xFFEF4444);
  static const warning = Color(0xFFF59E0B);
  static const info = Color(0xFF3B82F6);
  static const offline = Color(0xFF6B7280);

  // ─── Snackbar backgrounds ─────────────────────────────────────
  static const snackbarSuccessDark = Color(0xFF0D3320);
  static const snackbarErrorDark = Color(0xFF3D1A1A);
  static const snackbarInfoDark = Color(0xFF1A2744);
  static const snackbarSuccessLight = Color(0xFFD1FAE5);
  static const snackbarErrorLight = Color(0xFFFEE2E2);
  static const snackbarInfoLight = Color(0xFFDBEAFE);

  // ─── Legacy aliases (dark-theme values) ─────────────────────
  // Maps old field names → dark theme equivalents so 23 existing
  // screens keep compiling via the theme/dna_theme.dart shim.
  // Will be removed once all screens migrate to design_system imports.
  static const background = darkBackground;
  static const surface = darkSurface;
  static const panel = darkSurfaceVariant;
  static const primary = Color(0xFF00F0FF);      // old cyan accent
  static const primarySoft = Color(0x1400F0FF);  // 8% alpha cyan
  static const accent = Color(0xFFFF2CD8);        // old magenta
  static const text = darkText;
  static const textMuted = darkTextSecondary;
  static const textSuccess = Color(0xFF40FF86);   // old green
  static const textWarning = Color(0xFFFF8080);   // old red/pink
  static const textError = Color(0xFFFF6B6B);     // old red
  static const textInfo = Color(0xFFFFCC66);      // old yellow/amber
  static const border = darkDivider;
  static const borderAccent = darkDividerAccent;
  static const snackbarSuccess = snackbarSuccessDark;
  static const snackbarError = snackbarErrorDark;
  static const snackbarInfo = snackbarInfoDark;
}
