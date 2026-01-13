// Android Foreground Service - Background execution management
// Phase 14: DHT-only messaging with reliable Android background support
//
// This file is ANDROID-ONLY. It should only be imported on Android.

import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../../providers/engine_provider.dart';
import '../../providers/contacts_provider.dart';

/// MethodChannel for Android ForegroundService communication
class ForegroundServiceManager {
  static const _channel = MethodChannel('io.cpunk.dna_messenger/service');

  /// Start the foreground service
  static Future<bool> startService() async {
    try {
      final result = await _channel.invokeMethod<bool>('startService');
      return result ?? false;
    } on PlatformException {
      return false;
    }
  }

  /// Stop the foreground service
  static Future<bool> stopService() async {
    try {
      final result = await _channel.invokeMethod<bool>('stopService');
      return result ?? false;
    } on PlatformException {
      return false;
    }
  }

  /// Check if service is currently running
  static Future<bool> isServiceRunning() async {
    try {
      final result = await _channel.invokeMethod<bool>('isServiceRunning');
      return result ?? false;
    } on PlatformException {
      return false;
    }
  }

  /// Trigger immediate poll for offline messages
  static Future<void> pollNow() async {
    try {
      await _channel.invokeMethod<void>('pollNow');
    } on PlatformException {
      // Silently ignore
    }
  }

  /// Request notification permission (Android 13+)
  static Future<bool> requestNotificationPermission() async {
    try {
      final result = await _channel.invokeMethod<bool>('requestNotificationPermission');
      return result ?? false;
    } on PlatformException {
      return false;
    }
  }

  /// Set up handler for service callbacks
  static void setMethodCallHandler(
      Future<dynamic> Function(MethodCall call)? handler) {
    _channel.setMethodCallHandler(handler);
  }
}

/// Provider for foreground service running state (Android only)
final foregroundServiceProvider =
    StateNotifierProvider<ForegroundServiceNotifier, bool>(
  (ref) => ForegroundServiceNotifier(ref),
);

/// Notifier that manages foreground service lifecycle
class ForegroundServiceNotifier extends StateNotifier<bool> {
  final Ref _ref;
  bool _initialized = false;

  ForegroundServiceNotifier(this._ref) : super(false) {
    _init();
  }

  void _init() {
    if (_initialized) return;
    _initialized = true;

    // Listen for identity changes to start/stop service
    _ref.listen<String?>(currentFingerprintProvider, (previous, next) {
      if (next != null && next.isNotEmpty && (previous == null || previous.isEmpty)) {
        // Identity loaded - start service
        _startService();
      } else if ((next == null || next.isEmpty) && previous != null && previous.isNotEmpty) {
        // Identity unloaded - stop service
        _stopService();
      }
    }, fireImmediately: true);

    // Set up handler for service callbacks (e.g., new messages notification)
    ForegroundServiceManager.setMethodCallHandler(_handleServiceCall);
  }

  /// Handle callbacks from native service
  Future<dynamic> _handleServiceCall(MethodCall call) async {
    switch (call.method) {
      case 'onNewMessages':
        // Service detected new messages or requested poll
        await _pollOfflineMessages();
        // Refresh contacts to update UI
        _ref.invalidate(contactsProvider);
        break;
      case 'onNetworkChanged':
        // Network changed - Android service already reinited DHT via JNI.
        // Just refresh UI and poll for any messages that arrived.
        await _pollOfflineMessages();
        _ref.invalidate(contactsProvider);
        break;
    }
    return null;
  }

  /// Start the foreground service
  Future<void> _startService() async {
    final success = await ForegroundServiceManager.startService();
    state = success;
  }

  /// Stop the foreground service
  Future<void> _stopService() async {
    await ForegroundServiceManager.stopService();
    state = false;
  }

  /// Poll for offline messages via engine
  Future<void> _pollOfflineMessages() async {
    try {
      final engine = await _ref.read(engineProvider.future);
      await engine.checkOfflineMessages();
    } catch (_) {
      // Ignore errors during background poll
    }
  }

  /// Force an immediate poll (can be called from UI)
  Future<void> forcePoll() async {
    await ForegroundServiceManager.pollNow();
  }
}
