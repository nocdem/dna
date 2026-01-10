// App Lifecycle Observer - handles app state changes
// Phase 14: DHT-only messaging with reliable Android background support

import 'dart:io' show Platform;
import 'package:flutter/widgets.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../providers/engine_provider.dart';
import '../providers/event_handler.dart';
import '../providers/contacts_provider.dart';
import '../providers/contact_profile_cache_provider.dart';
import '../services/cache_database.dart';

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
    // Mark app as in foreground (for notification logic)
    ref.read(appInForegroundProvider.notifier).state = true;

    // Check if identity is loaded
    final fingerprint = ref.read(currentFingerprintProvider);
    if (fingerprint == null || fingerprint.isEmpty) {
      return;
    }

    try {
      final engine = await ref.read(engineProvider.future);

      // Re-attach event callback on Android (was detached on pause for JNI to handle background)
      // Desktop platforms keep callback attached since they don't have JNI fallback
      if (Platform.isAndroid) {
        engine.attachEventCallback();
      }

      // Check if DHT is actually still connected (may have dropped while idle)
      final isDhtConnected = engine.isDhtConnected();

      if (!isDhtConnected) {
        // DHT disconnected while idle - trigger reconnection
        ref.read(dhtConnectionStateProvider.notifier).state =
            DhtConnectionState.connecting;

        engine.networkChanged();
        // DHT connected event will update state and restart listeners
      } else {
        // DHT still connected - just resume normal operations
        // Resume C-side presence heartbeat (marks us as online)
        engine.resumePresence();

        // Resume Dart-side polling timers (handles presence refresh + contact requests)
        ref.read(eventHandlerProvider).resumePolling();
      }

      // Force refresh contact profiles from DHT (fixes stale display names)
      // This ensures users see up-to-date names when they open the app
      await _refreshContactProfiles(engine);

      // Refresh contacts to get updated presence status (seamless update)
      await ref.read(contactsProvider.notifier).refresh();

      // Note: Offline messages are handled by C-side push notification callback
      // (messenger_push_notification_callback) which triggers poll on DHT listen events
    } catch (_) {
      // Error during resume - silently continue
    }
  }

  /// Refresh stale contact profiles from DHT
  /// Only refreshes profiles older than 1 hour to avoid hammering DHT on reconnect
  Future<void> _refreshContactProfiles(dynamic engine) async {
    try {
      // Get current contacts
      final contacts = ref.read(contactsProvider).valueOrNull;
      if (contacts == null || contacts.isEmpty) {
        return;
      }

      // Filter to only stale profiles (older than 1 hour)
      const maxAge = Duration(hours: 1);
      final db = CacheDatabase.instance;
      final staleContacts = <String>[];

      for (final contact in contacts) {
        if (await db.isProfileStale(contact.fingerprint, maxAge)) {
          staleContacts.add(contact.fingerprint);
        }
      }

      if (staleContacts.isEmpty) {
        return; // All profiles are fresh, nothing to refresh
      }

      // Refresh stale profiles in parallel (batched to avoid overloading DHT)
      const batchSize = 3;
      for (var i = 0; i < staleContacts.length; i += batchSize) {
        final batch = staleContacts.skip(i).take(batchSize).toList();
        await Future.wait(
          batch.map((fingerprint) async {
            try {
              // Force refresh from DHT (bypasses cache)
              final profile = await engine.refreshContactProfile(fingerprint);
              if (profile != null) {
                // Update Flutter-side cache too
                ref.read(contactProfileCacheProvider.notifier)
                    .updateProfile(fingerprint, profile);
              }
            } catch (_) {
              // Individual profile refresh failed - continue with others
            }
          }),
        );
      }
    } catch (_) {
      // Error refreshing contact profiles - silently continue
    }
  }

  /// Called when app goes to background
  void _onPause() async {
    // Mark app as in background (for notification logic - always show notifications when backgrounded)
    ref.read(appInForegroundProvider.notifier).state = false;

    // Pause Dart-side polling timers FIRST (prevents timer exceptions in background)
    ref.read(eventHandlerProvider).pausePolling();

    // Check if identity is loaded
    final fingerprint = ref.read(currentFingerprintProvider);
    if (fingerprint == null || fingerprint.isEmpty) {
      return;
    }

    try {
      final engine = await ref.read(engineProvider.future);

      // Pause C-side presence heartbeat (stops marking us as online)
      engine.pausePresence();

      // On Android: Detach Flutter event callback - JNI notification helper handles
      // background notifications directly via native Android NotificationManager.
      // On Desktop: Keep callback attached since there's no JNI fallback.
      if (Platform.isAndroid) {
        engine.detachEventCallback();
      }
    } catch (_) {
      // Error during pause - silently continue
    }
  }

  /// Called when app is being killed
  void _onDetached() {
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
