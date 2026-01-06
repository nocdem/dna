// Foreground Service Provider - Android background execution management
// Phase 14: DHT-only messaging with reliable Android background support

import 'dart:io';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'engine_provider.dart';
import 'contacts_provider.dart';

/// MethodChannel for Android ForegroundService communication
class ForegroundServiceManager {
  static const _channel = MethodChannel('io.cpunk.dna_messenger/service');

  /// Check if foreground service is supported (Android only)
  static bool get isSupported => Platform.isAndroid;

  /// Start the foreground service
  static Future<bool> startService() async {
    if (!isSupported) return false;
    try {
      final result = await _channel.invokeMethod<bool>('startService');
      return result ?? false;
    } on PlatformException {
      return false;
    }
  }

  /// Stop the foreground service
  static Future<bool> stopService() async {
    if (!isSupported) return false;
    try {
      final result = await _channel.invokeMethod<bool>('stopService');
      return result ?? false;
    } on PlatformException {
      return false;
    }
  }

  /// Check if service is currently running
  static Future<bool> isServiceRunning() async {
    if (!isSupported) return false;
    try {
      final result = await _channel.invokeMethod<bool>('isServiceRunning');
      return result ?? false;
    } on PlatformException {
      return false;
    }
  }

  /// Trigger immediate poll for offline messages
  static Future<void> pollNow() async {
    if (!isSupported) return;
    try {
      await _channel.invokeMethod<void>('pollNow');
    } on PlatformException {
      // Silently ignore
    }
  }

  /// Set up handler for service callbacks
  static void setMethodCallHandler(
      Future<dynamic> Function(MethodCall call)? handler) {
    _channel.setMethodCallHandler(handler);
  }
}

/// Provider for foreground service running state
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
        // Network changed (WiFi <-> Cellular) - reinitialize DHT
        await _handleNetworkChange();
        break;
    }
    return null;
  }

  /// Handle network connectivity change
  Future<void> _handleNetworkChange() async {
    try {
      final engine = await _ref.read(engineProvider.future);
      final result = engine.networkChanged();
      if (result == 0) {
        // Poll for any messages that arrived during network switch
        await _pollOfflineMessages();
        // Refresh contacts to update UI
        _ref.invalidate(contactsProvider);
      }
    } catch (_) {
      // Silently ignore network change errors
    }
  }

  /// Start the foreground service
  Future<void> _startService() async {
    if (!ForegroundServiceManager.isSupported) return;
    final success = await ForegroundServiceManager.startService();
    state = success;
  }

  /// Stop the foreground service
  Future<void> _stopService() async {
    if (!ForegroundServiceManager.isSupported) return;
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
    if (ForegroundServiceManager.isSupported) {
      await ForegroundServiceManager.pollNow();
    } else {
      await _pollOfflineMessages();
    }
  }
}
