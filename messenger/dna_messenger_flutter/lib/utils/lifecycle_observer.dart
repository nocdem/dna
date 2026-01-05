// App Lifecycle Observer - handles app state changes
// Phase 14: DHT-only messaging with reliable Android background support

import 'package:flutter/widgets.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../providers/engine_provider.dart';
import '../providers/event_handler.dart';
import '../providers/contacts_provider.dart';
import '../providers/contact_profile_cache_provider.dart';

/// Provider that tracks whether the app is currently in foreground (resumed)
/// Used by event_handler to determine whether to show notifications
final appInForegroundProvider = StateProvider<bool>((ref) => true);

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
        // Don't pause here - might just be a brief interruption
        break;
      case AppLifecycleState.hidden:
        // App is hidden (Android 14+) - treat same as paused
        _onPause();
        break;
    }
  }

  /// Called when app comes to foreground
  void _onResume() async {
    print('AppLifecycle: App resumed');

    // Mark app as in foreground (for notification logic)
    ref.read(appInForegroundProvider.notifier).state = true;

    // Check if identity is loaded
    final fingerprint = ref.read(currentFingerprintProvider);
    if (fingerprint == null || fingerprint.isEmpty) {
      print('AppLifecycle: No identity loaded, skipping refresh');
      return;
    }

    try {
      final engine = await ref.read(engineProvider.future);

      // Re-attach event callback (was detached in _onPause to prevent crashes)
      print('AppLifecycle: Re-attaching event callback');
      engine.attachEventCallback();

      // Check if DHT is actually still connected (may have dropped while idle)
      final isDhtConnected = engine.isDhtConnected();
      print('AppLifecycle: DHT connected = $isDhtConnected');

      if (!isDhtConnected) {
        // DHT disconnected while idle - trigger reconnection
        print('AppLifecycle: DHT disconnected, triggering reconnection...');
        ref.read(dhtConnectionStateProvider.notifier).state =
            DhtConnectionState.connecting;

        final result = engine.networkChanged();
        if (result == 0) {
          print('AppLifecycle: DHT reconnection initiated successfully');
        } else {
          print('AppLifecycle: DHT reconnection failed with code $result');
        }
        // DHT connected event will update state and restart listeners
      } else {
        // DHT still connected - just resume normal operations
        // Resume C-side presence heartbeat (marks us as online)
        print('AppLifecycle: Resuming C-side presence heartbeat');
        engine.resumePresence();

        // Resume Dart-side polling timers (handles presence refresh + contact requests)
        print('AppLifecycle: Resuming polling timers');
        ref.read(eventHandlerProvider).resumePolling();
      }

      // Force refresh contact profiles from DHT (fixes stale display names)
      // This ensures users see up-to-date names when they open the app
      print('AppLifecycle: Refreshing contact profiles from DHT');
      await _refreshContactProfiles(engine);

      // Refresh contacts to get updated presence status
      print('AppLifecycle: Refreshing contacts for presence update');
      ref.invalidate(contactsProvider);

      // Note: Offline messages are handled by C-side push notification callback
      // (messenger_push_notification_callback) which triggers poll on DHT listen events
    } catch (e) {
      print('AppLifecycle: Error during resume - $e');
    }
  }

  /// Refresh all contact profiles from DHT
  /// Called on app resume to ensure display names are up-to-date
  Future<void> _refreshContactProfiles(dynamic engine) async {
    try {
      // Get current contacts
      final contacts = ref.read(contactsProvider).valueOrNull;
      if (contacts == null || contacts.isEmpty) {
        print('AppLifecycle: No contacts to refresh');
        return;
      }

      print('AppLifecycle: Refreshing ${contacts.length} contact profiles');

      // Refresh profiles in parallel (batched to avoid overloading DHT)
      const batchSize = 5;
      for (var i = 0; i < contacts.length; i += batchSize) {
        final batch = contacts.skip(i).take(batchSize).toList();
        await Future.wait(
          batch.map((contact) async {
            try {
              // Force refresh from DHT (bypasses cache)
              final profile = await engine.refreshContactProfile(contact.fingerprint);
              if (profile != null) {
                // Update Flutter-side cache too
                ref.read(contactProfileCacheProvider.notifier)
                    .updateProfile(contact.fingerprint, profile);
              }
            } catch (e) {
              // Individual profile refresh failed - continue with others
              print('AppLifecycle: Failed to refresh ${contact.fingerprint.substring(0, 16)}...: $e');
            }
          }),
        );
      }
      print('AppLifecycle: Contact profile refresh complete');
    } catch (e) {
      print('AppLifecycle: Error refreshing contact profiles: $e');
    }
  }

  /// Called when app goes to background
  void _onPause() async {
    print('AppLifecycle: App paused');

    // Mark app as in background (for notification logic - always show notifications when backgrounded)
    ref.read(appInForegroundProvider.notifier).state = false;

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

      // CRITICAL: Detach event callback to prevent crashes if Flutter is killed
      // while ForegroundService keeps the native library running. Events from
      // DHT listeners would try to invoke a deleted Dart callback.
      print('AppLifecycle: Detaching event callback');
      engine.detachEventCallback();
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
