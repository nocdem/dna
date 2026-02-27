// Platform Utilities - Central platform detection
// Separates Android-specific code from shared code

import 'dart:io' show Platform;

/// Platform detection utilities
class PlatformUtils {
  PlatformUtils._();

  /// True if running on Android
  static bool get isAndroid => Platform.isAndroid;

  /// True if running on iOS
  static bool get isIOS => Platform.isIOS;

  /// True if running on any mobile platform (Android or iOS)
  static bool get isMobile => Platform.isAndroid || Platform.isIOS;

  /// True if running on any desktop platform (Linux, Windows, macOS)
  static bool get isDesktop =>
      Platform.isLinux || Platform.isWindows || Platform.isMacOS;

  /// True if running on Linux
  static bool get isLinux => Platform.isLinux;

  /// True if running on Windows
  static bool get isWindows => Platform.isWindows;

  /// True if running on macOS
  static bool get isMacOS => Platform.isMacOS;
}
