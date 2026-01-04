// App Lifecycle Observer - handles app state changes
// Phase 14: DHT-only messaging with reliable Android background support

import 'package:flutter/widgets.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../providers/engine_provider.dart';
import '../providers/event_handler.dart';

/// Observer for app lifecycle state changes
///
/// Handles:
/// - onResume: Refresh presence and poll for offline messages
/// - onPause: Service continues running in background
/// - onDetached: Service may continue if logged in
class AppLifecycleObserver extends WidgetsBindingObserver {
  final WidgetRef ref;

  AppLifecycleObserver(this.ref);

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    print('AppLifecycle: State changed to $state');
    switch (state) {
      case AppLifecycleState.resumed:
        _onResume();
        break;
      case AppLifecycleState.paused:
        _onPause();
        break;
      case AppLifecycleState.detached:
        _onDetached();
        break;
      case AppLifecycleState.inactive:
        // App is inactive (e.g., phone call overlay)
        break;
      case AppLifecycleState.hidden:
        // App is hidden (Android 14+)
        break;
    }
  }

  /// Called when app comes to foreground
  void _onResume() async {
    print('AppLifecycle: App resumed');

    // Check if identity is loaded
    final fingerprint = ref.read(currentFingerprintProvider);
    if (fingerprint == null || fingerprint.isEmpty) {
      print('AppLifecycle: No identity loaded, skipping refresh');
      return;
    }

    try {
      final engine = await ref.read(engineProvider.future);

      // Resume Dart-side polling timers FIRST (starts 30-second periodic refresh)
      print('AppLifecycle: Resuming polling timers');
      ref.read(eventHandlerProvider).resumePolling();

      // Small delay to let DHT routing table stabilize after background resume
      // DHT may need time to reconnect to nodes after app was in background
      await Future.delayed(const Duration(milliseconds: 500));

      // Only push presence if DHT is actually connected
      if (engine.isDhtConnected()) {
        print('AppLifecycle: DHT connected, resuming C-side presence');
        engine.resumePresence();
      } else {
        print('AppLifecycle: DHT not connected, skipping immediate presence refresh');
        // Presence will be pushed when DHT connects (via DhtConnectedEvent handler)
      }

      // Note: Offline messages are handled by C-side push notification callback
      // (messenger_push_notification_callback) which triggers poll on DHT listen events
    } catch (e) {
      print('AppLifecycle: Error during resume - $e');
    }
  }

  /// Called when app goes to background
  void _onPause() async {
    print('AppLifecycle: App paused');

    // Pause Dart-side polling timers FIRST (prevents timer exceptions in background)
    print('AppLifecycle: Pausing polling timers');
    ref.read(eventHandlerProvider).pausePolling();

    // Check if identity is loaded
    final fingerprint = ref.read(currentFingerprintProvider);
    if (fingerprint == null || fingerprint.isEmpty) {
      print('AppLifecycle: No identity loaded, skipping C-side pause');
      return;
    }

    try {
      final engine = await ref.read(engineProvider.future);

      // Pause C-side presence heartbeat (stops marking us as online)
      print('AppLifecycle: Pausing C-side presence heartbeat');
      engine.pausePresence();
    } catch (e) {
      print('AppLifecycle: Error during pause - $e');
    }
  }

  /// Called when app is being killed
  void _onDetached() {
    print('AppLifecycle: App detached');
    // ForegroundService may continue running if logged in
    // System will eventually kill it if needed
  }
}

/// Mixin for StatefulWidget to easily add lifecycle observer
mixin AppLifecycleMixin<T extends StatefulWidget> on State<T> {
  AppLifecycleObserver? _lifecycleObserver;

  /// Call this in initState() with the WidgetRef
  void initLifecycleObserver(WidgetRef ref) {
    _lifecycleObserver = AppLifecycleObserver(ref);
    WidgetsBinding.instance.addObserver(_lifecycleObserver!);
  }

  /// Override dispose to clean up
  @override
  void dispose() {
    if (_lifecycleObserver != null) {
      WidgetsBinding.instance.removeObserver(_lifecycleObserver!);
    }
    super.dispose();
  }
}
