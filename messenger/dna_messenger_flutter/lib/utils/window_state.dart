// Window State Manager - Persist window position and size on desktop
import 'dart:io';
import 'dart:ui';
import 'package:flutter/foundation.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:window_manager/window_manager.dart';

/// Manages window state persistence for desktop platforms
class WindowStateManager with WindowListener {
  static const _keyX = 'window_x';
  static const _keyY = 'window_y';
  static const _keyWidth = 'window_width';
  static const _keyHeight = 'window_height';
  static const _keyMaximized = 'window_maximized';

  static const _defaultWidth = 1200.0;
  static const _defaultHeight = 800.0;
  static const _minWidth = 400.0;
  static const _minHeight = 300.0;

  SharedPreferences? _prefs;
  bool _isInitialized = false;

  /// Check if running on a desktop platform
  static bool get isDesktop {
    if (kIsWeb) return false;
    return Platform.isLinux || Platform.isWindows || Platform.isMacOS;
  }

  /// Initialize window manager and restore saved state
  Future<void> init() async {
    if (!isDesktop || _isInitialized) return;

    print('[WindowState] Initializing...');
    _prefs = await SharedPreferences.getInstance();

    await windowManager.ensureInitialized();

    // Configure window options
    const windowOptions = WindowOptions(
      minimumSize: Size(_minWidth, _minHeight),
      titleBarStyle: TitleBarStyle.normal,
    );

    await windowManager.waitUntilReadyToShow(windowOptions, () async {
      // Restore saved position and size
      await _restoreWindowState();

      // Add listener to save state on changes
      windowManager.addListener(this);

      await windowManager.show();
      await windowManager.focus();
    });

    _isInitialized = true;
  }

  /// Restore window position and size from preferences
  Future<void> _restoreWindowState() async {
    final prefs = _prefs;
    if (prefs == null) return;

    final wasMaximized = prefs.getBool(_keyMaximized) ?? false;
    print('[WindowState] Restoring: maximized=$wasMaximized');

    if (wasMaximized) {
      await windowManager.maximize();
      return;
    }

    // Get saved position
    final x = prefs.getDouble(_keyX);
    final y = prefs.getDouble(_keyY);
    final width = prefs.getDouble(_keyWidth) ?? _defaultWidth;
    final height = prefs.getDouble(_keyHeight) ?? _defaultHeight;

    print('[WindowState] Restoring: x=$x, y=$y, w=$width, h=$height');

    // Set size first
    await windowManager.setSize(Size(width, height));

    // Set position if saved (otherwise center)
    if (x != null && y != null) {
      await windowManager.setPosition(Offset(x, y));
    } else {
      await windowManager.center();
    }
  }

  /// Save current window state to preferences
  Future<void> _saveWindowState() async {
    final prefs = _prefs;
    if (prefs == null) return;

    final isMaximized = await windowManager.isMaximized();
    await prefs.setBool(_keyMaximized, isMaximized);

    // Only save position/size if not maximized
    if (!isMaximized) {
      final position = await windowManager.getPosition();
      final size = await windowManager.getSize();

      await prefs.setDouble(_keyX, position.dx);
      await prefs.setDouble(_keyY, position.dy);
      await prefs.setDouble(_keyWidth, size.width);
      await prefs.setDouble(_keyHeight, size.height);

      print('[WindowState] Saved: x=${position.dx}, y=${position.dy}, w=${size.width}, h=${size.height}');
    } else {
      print('[WindowState] Saved: maximized=true');
    }
  }

  // WindowListener callbacks

  @override
  void onWindowResized() {
    _saveWindowState();
  }

  @override
  void onWindowMoved() {
    _saveWindowState();
  }

  @override
  void onWindowMaximize() {
    _saveWindowState();
  }

  @override
  void onWindowUnmaximize() {
    _saveWindowState();
  }

  @override
  void onWindowClose() {
    _saveWindowState();
  }

  // Required but unused callbacks
  @override
  void onWindowBlur() {}
  @override
  void onWindowFocus() {}
  @override
  void onWindowMinimize() {}
  @override
  void onWindowRestore() {}
  @override
  void onWindowEnterFullScreen() {}
  @override
  void onWindowLeaveFullScreen() {}
  @override
  void onWindowEvent(String eventName) {}
  @override
  void onWindowDocked() {}
  @override
  void onWindowUndocked() {}
}

/// Global instance
final windowStateManager = WindowStateManager();
