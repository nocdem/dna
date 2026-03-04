// App Lifecycle Observer - handles app state changes
// v0.101.25+: Mobile uses pause/resume pattern (engine stays alive in background)
// Engine TCP stays connected → listeners get instant push → Android notification via JNI

import 'dart:async';
import 'dart:io' show Platform;
import 'package:flutter/widgets.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../platform/platform_handler.dart';
import '../providers/engine_provider.dart';
import '../providers/event_handler.dart';
import '../providers/identity_provider.dart';
import '../providers/contacts_provider.dart';
import '../providers/contact_profile_cache_provider.dart';
import '../ffi/dna_engine.dart';
import 'logger.dart';

/// Provider that tracks whether the app is currently in foreground (resumed)
/// Used by event_handler to determine whether to show notifications
final appInForegroundProvider = StateProvider<bool>((ref) => true);

/// Observer for app lifecycle state changes
///
/// v0.101.25+ Architecture (mobile only - desktop never pauses):
/// - On pause: detach Dart callback + engine.pause() (TCP stays alive, listeners active)
/// - On resume: engine.resume() + attach callback + checkOfflineMessages (~100ms)
/// - Android ForegroundService is just a process keep-alive (no engine management)
/// - Background notifications via JNI callback (g_android_notification_cb)
class AppLifecycleObserver extends WidgetsBindingObserver {
  final WidgetRef ref;

  /// Guard against concurrent resume/pause
  bool _busy = false;

  AppLifecycleObserver(this.ref);

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    switch (state) {
      case AppLifecycleState.resumed:
        // Desktop doesn't pause, so skip resume logic
        if (Platform.isAndroid || Platform.isIOS) {
          _onResume();
        }
        break;
      case AppLifecycleState.paused:
        // Only pause on mobile - desktop keeps running when minimized
        if (Platform.isAndroid || Platform.isIOS) {
          _onPause();
        }
        break;
      case AppLifecycleState.detached:
        // ForegroundService may continue running if logged in
        break;
      case AppLifecycleState.inactive:
        // App is inactive (e.g., phone call overlay)
        // Don't pause here - might just be a brief interruption
        break;
      case AppLifecycleState.hidden:
        // Android/iOS both fire hidden BEFORE paused - only handle paused
        break;
    }
  }

  /// Called when app comes to foreground
  void _onResume() async {
    // IMMEDIATE: Mark app as in foreground (for notification logic)
    ref.read(appInForegroundProvider.notifier).state = true;

    // Check if identity was loaded before going to background
    final fingerprint = ref.read(currentFingerprintProvider);
    if (fingerprint == null || fingerprint.isEmpty) {
      return;
    }

    // Guard: only one operation at a time
    if (_busy) {
      log('LIFECYCLE', '[RESUME] Already busy, ignoring');
      return;
    }
    _busy = true;

    try {
      // Get existing engine (should still be alive from before pause)
      final engine = ref.read(engineProvider).valueOrNull;

      if (engine == null || engine.isDisposed) {
        // Engine was killed by OS or something went wrong
        // Fall back to full engine creation
        log('LIFECYCLE', '[RESUME] Engine gone — full recreation needed');
        await _fullRecreate(fingerprint);
        return;
      }

      log('LIFECYCLE', '[RESUME] Resuming paused engine');

      // Resume engine (reconnects Nodus if needed, re-listens contacts, resubscribes groups)
      await engine.resume();

      // Re-attach Dart event callback (events flow to Dart again instead of JNI)
      engine.attachEventCallback();

      // Platform-specific resume (clears notifications, fetches offline messages)
      await PlatformHandler.instance.onResume(engine);

      // Resume Dart-side polling timers
      ref.read(eventHandlerProvider).resumePolling();

      log('LIFECYCLE', '[RESUME] Engine resumed (~instant)');

      // Refresh contact profiles in background (non-blocking)
      _refreshContactProfiles(engine);

    } catch (e) {
      logError('LIFECYCLE', '[RESUME] Error: $e');
    } finally {
      _busy = false;
    }
  }

  /// Fallback: full engine recreation when OS killed the process
  Future<void> _fullRecreate(String fingerprint) async {
    try {
      log('LIFECYCLE', '[RESUME] Creating fresh engine (OS killed previous)');

      // Get fresh engine (provider creates new one)
      ref.invalidate(engineProvider);
      final engine = await ref.read(engineProvider.future);

      // Load identity
      await ref.read(identitiesProvider.notifier).loadIdentity(fingerprint);

      // Platform-specific resume
      await PlatformHandler.instance.onResume(engine);

      // Resume Dart-side polling
      ref.read(eventHandlerProvider).resumePolling();

      log('LIFECYCLE', '[RESUME] Full recreation complete');
    } catch (e) {
      logError('LIFECYCLE', '[RESUME] Full recreation failed: $e');
      ref.read(identityReadyProvider.notifier).state = false;
    }
  }

  /// Refresh all contact profiles from DHT on resume
  Future<void> _refreshContactProfiles(DnaEngine engine) async {
    try {
      final contacts = ref.read(contactsProvider).valueOrNull;
      if (contacts == null || contacts.isEmpty) {
        return;
      }

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
            } catch (_) {}
          }),
        );
      }
    } catch (_) {}
  }

  /// Called when app goes to background
  void _onPause() async {
    // IMMEDIATE: Mark app as in background (for notification logic)
    ref.read(appInForegroundProvider.notifier).state = false;

    // Pause Dart-side polling timers FIRST (prevents timer exceptions in background)
    ref.read(eventHandlerProvider).pausePolling();

    // Guard against duplicate pause events
    if (_busy) {
      log('LIFECYCLE', '[PAUSE] Already busy, ignoring');
      return;
    }

    // Check if identity is loaded
    final fingerprint = ref.read(currentFingerprintProvider);
    if (fingerprint == null || fingerprint.isEmpty) {
      return;
    }

    _busy = true;

    try {
      final engine = ref.read(engineProvider).valueOrNull;

      if (engine == null || engine.isDisposed) {
        log('LIFECYCLE', '[PAUSE] Engine already disposed, skipping');
        return;
      }

      log('LIFECYCLE', '[PAUSE] Pausing engine (TCP stays alive)');

      // Detach Dart callback — events route to JNI notification callback
      engine.detachEventCallback();

      // Pause engine (suspends presence heartbeat, keeps TCP + listeners alive)
      engine.pause();

      // Notify service that Flutter is paused (service is keep-alive only)
      PlatformHandler.instance.onPauseComplete();

      log('LIFECYCLE', '[PAUSE] Engine paused — listeners active, notifications via JNI');

    } catch (e) {
      logError('LIFECYCLE', '[PAUSE] Error: $e');
    } finally {
      _busy = false;

      // Handle rapid switch — if already foreground, trigger resume
      final currentState = WidgetsBinding.instance.lifecycleState;
      if (currentState == AppLifecycleState.resumed) {
        log('LIFECYCLE', '[PAUSE] Already resumed during pause, triggering immediate resume');
        Future.microtask(() => _onResume());
      }
    }
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
