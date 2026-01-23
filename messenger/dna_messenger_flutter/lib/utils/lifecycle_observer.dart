// App Lifecycle Observer - handles app state changes
// Phase 14: DHT-only messaging with reliable Android background support
// v0.100.23+: Destroy engine on pause to cancel all listeners, reinit on resume

import 'dart:io' show Platform;
import 'package:flutter/widgets.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../platform/platform_handler.dart';
import '../providers/engine_provider.dart';
import '../providers/event_handler.dart';
import '../providers/identity_provider.dart';
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

    // Check if identity was loaded before going to background
    // currentFingerprintProvider is preserved across engine invalidation
    final fingerprint = ref.read(currentFingerprintProvider);
    if (fingerprint == null || fingerprint.isEmpty) {
      return;
    }

    try {
      // v0.100.23+: Notify service FIRST so it releases its engine
      // Service must release the DHT lock before Flutter can create new engine
      if (Platform.isAndroid) {
        await PlatformHandler.instance.onResumePreEngine();
      }

      // Get new engine (provider creates fresh instance after invalidation)
      final engine = await ref.read(engineProvider.future);

      // Reload identity into fresh engine
      // This reloads keys, initializes transport, and starts all listeners
      await ref.read(identitiesProvider.notifier).loadIdentity(fingerprint);

      // Platform-specific resume handling
      // Android: Fetch offline messages
      // Desktop: No-op
      await PlatformHandler.instance.onResume(engine);

      // Resume presence heartbeat (marks us as online)
      engine.resumePresence();

      // Resume Dart-side polling timers (handles presence refresh + contact requests)
      ref.read(eventHandlerProvider).resumePolling();

      // Refresh contact profiles from DHT in background
      // Don't await - let UI show cached data immediately, updates come async
      _refreshContactProfiles(engine);
    } catch (_) {
      // Error during resume - silently continue
    }
  }

  /// Refresh all contact profiles from DHT on resume
  /// Ensures profile changes (name, avatar) are visible immediately
  Future<void> _refreshContactProfiles(dynamic engine) async {
    try {
      final contacts = ref.read(contactsProvider).valueOrNull;
      if (contacts == null || contacts.isEmpty) {
        return;
      }

      // Refresh all profiles in parallel (batched to avoid overloading DHT)
      const batchSize = 3;
      for (var i = 0; i < contacts.length; i += batchSize) {
        final batch = contacts.skip(i).take(batchSize).toList();
        await Future.wait(
          batch.map((contact) async {
            try {
              final profile = await engine.refreshContactProfile(contact.fingerprint);
              if (profile != null) {
                ref.read(contactProfileCacheProvider.notifier)
                    .updateProfile(contact.fingerprint, profile);
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

      // Detach event callback before destroying engine
      engine.detachEventCallback();

      // Platform-specific pause handling
      // Android: Notify service that Flutter is pausing (service takes over)
      // Desktop: No-op
      PlatformHandler.instance.onPause(engine);

      // v0.100.24+: Explicitly dispose engine SYNCHRONOUSLY before invalidating
      // This ensures all DHT listeners are cancelled and lock is released
      // BEFORE the service tries to take over. ref.invalidate() is async and
      // won't wait for dispose to complete.
      engine.dispose();

      // Invalidate provider so next access creates fresh engine
      // NOTE: Do NOT clear currentFingerprintProvider - we need it to reload on resume
      ref.invalidate(engineProvider);
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
