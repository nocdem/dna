// App Lifecycle Observer - handles app state changes
// Phase 14: DHT-only messaging with reliable Android background support
// v0.100.64+: Pause/Resume optimization - engine stays paused indefinitely (no timeout)

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

/// Lifecycle state machine to prevent concurrent resume/pause operations
enum _LifecycleState { idle, resuming, pausing }

/// Observer for app lifecycle state changes
///
/// v0.100.64+ Architecture:
/// - On pause: PAUSE engine (suspend listeners, keep DHT alive indefinitely)
/// - On resume: RESUME engine (resubscribe listeners) - <500ms
/// - Android ForegroundService polls on paused engine via nativeCheckOfflineMessages()
///
/// This eliminates the 2-40 second lag when returning from background.
class AppLifecycleObserver extends WidgetsBindingObserver {
  final WidgetRef ref;

  /// Current lifecycle operation state
  _LifecycleState _lifecycleState = _LifecycleState.idle;

  /// Abort flag: set by pause to signal resume should abort
  bool _pauseRequested = false;

  /// Operation ID to detect stale callbacks after abort
  int _operationId = 0;

  AppLifecycleObserver(this.ref);

  /// Check if current operation should abort
  /// Returns true if pause was requested or operation ID changed
  bool _shouldAbort(int myOpId) {
    return _pauseRequested || _operationId != myOpId;
  }

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
    // IMMEDIATE: Mark app as in foreground (for notification logic)
    // This must happen synchronously before any async work
    ref.read(appInForegroundProvider.notifier).state = true;

    // Check if identity was loaded before going to background
    // currentFingerprintProvider is preserved across engine invalidation
    final fingerprint = ref.read(currentFingerprintProvider);
    if (fingerprint == null || fingerprint.isEmpty) {
      return;
    }

    // State machine guard: only one resume at a time
    if (_lifecycleState != _LifecycleState.idle) {
      return;
    }

    // Enter resuming state
    _lifecycleState = _LifecycleState.resuming;
    _pauseRequested = false;
    final myOpId = ++_operationId;

    try {
      // Get engine - may be paused or may need fresh creation
      final engine = await ref.read(engineProvider.future);

      // Abort checkpoint
      if (_shouldAbort(myOpId)) {
        return;
      }

      // Check if engine is paused (fast path) or needs full reload (slow path)
      if (engine.isPaused) {
        // FAST PATH: Resume paused engine (<500ms)
        log('LIFECYCLE', '[RESUME] Fast path: resuming paused engine');

        // Resume the engine (resubscribes listeners, resumes presence)
        final success = await engine.resume();
        if (!success) {
          logError('LIFECYCLE', '[RESUME] Engine resume failed');
        }

        // Abort checkpoint
        if (_shouldAbort(myOpId)) {
          return;
        }

        // Reattach event callback
        ref.read(eventHandlerProvider).attachCallback(engine);

        // Resume Dart-side polling timers
        ref.read(eventHandlerProvider).resumePolling();

        // Mark identity as ready (hides spinner)
        ref.read(identityReadyProvider.notifier).state = true;

        log('LIFECYCLE', '[RESUME] Fast resume complete');
      } else if (!engine.isIdentityLoaded()) {
        // SLOW PATH: Engine was destroyed (background timeout), need full reload
        log('LIFECYCLE', '[RESUME] Slow path: full identity reload');

        // Notify service FIRST so it releases its engine (Android only)
        if (Platform.isAndroid) {
          await PlatformHandler.instance.onResumePreEngine();
        }

        // Abort checkpoint
        if (_shouldAbort(myOpId)) {
          return;
        }

        // Reload identity (keys, transport, listeners)
        await ref.read(identitiesProvider.notifier).loadIdentity(fingerprint);

        // Abort checkpoint
        if (_shouldAbort(myOpId)) {
          return;
        }

        // Platform-specific resume handling
        await PlatformHandler.instance.onResume(engine);

        // Abort checkpoint
        if (_shouldAbort(myOpId)) {
          return;
        }

        // Resume Dart-side polling timers
        ref.read(eventHandlerProvider).resumePolling();

        log('LIFECYCLE', '[RESUME] Full reload complete');
      } else {
        // Engine is active and identity loaded - just resume polling
        log('LIFECYCLE', '[RESUME] Engine already active');
        ref.read(eventHandlerProvider).resumePolling();
        ref.read(identityReadyProvider.notifier).state = true;
      }

      // Refresh contact profiles in background (non-blocking)
      if (!_shouldAbort(myOpId)) {
        _refreshContactProfiles(engine, myOpId);
      }
    } catch (e) {
      logError('LIFECYCLE', '[RESUME] Error: $e');
    } finally {
      // Only reset state if we're still the current operation
      if (_operationId == myOpId) {
        _lifecycleState = _LifecycleState.idle;
      }
    }
  }

  /// Refresh all contact profiles from DHT on resume
  /// Ensures profile changes (name, avatar) are visible immediately
  Future<void> _refreshContactProfiles(DnaEngine engine, int myOpId) async {
    try {
      final contacts = ref.read(contactsProvider).valueOrNull;
      if (contacts == null || contacts.isEmpty) {
        return;
      }

      // Refresh all profiles in parallel (batched to avoid overloading DHT)
      const batchSize = 3;
      for (var i = 0; i < contacts.length; i += batchSize) {
        // Check for abort before each batch
        if (_shouldAbort(myOpId)) {
          return;
        }

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
    // IMMEDIATE: Mark app as in background (for notification logic)
    // These must happen synchronously before any async work
    ref.read(appInForegroundProvider.notifier).state = false;

    // Pause Dart-side polling timers FIRST (prevents timer exceptions in background)
    ref.read(eventHandlerProvider).pausePolling();

    // If resume is in progress, signal it to abort and wait
    if (_lifecycleState == _LifecycleState.resuming) {
      _pauseRequested = true;

      // Wait up to 3 seconds for resume to abort
      final deadline = DateTime.now().add(const Duration(seconds: 3));
      while (_lifecycleState == _LifecycleState.resuming &&
             DateTime.now().isBefore(deadline)) {
        await Future.delayed(const Duration(milliseconds: 50));
      }

      // If resume still hasn't aborted, force it via operation ID
      if (_lifecycleState == _LifecycleState.resuming) {
        _operationId++;
        // Give it one more moment to notice the abort
        await Future.delayed(const Duration(milliseconds: 100));
      }
    }

    // State machine guard: don't re-enter pausing state
    if (_lifecycleState == _LifecycleState.pausing) {
      return;
    }

    // Check if identity is loaded
    final fingerprint = ref.read(currentFingerprintProvider);
    if (fingerprint == null || fingerprint.isEmpty) {
      return;
    }

    _lifecycleState = _LifecycleState.pausing;

    try {
      final engine = await ref.read(engineProvider.future);

      // v0.100.58+: PAUSE engine instead of destroying it
      // This suspends listeners but keeps DHT connection alive
      log('LIFECYCLE', '[PAUSE] Pausing engine (keeping DHT alive)');

      // Detach event callback (events will be ignored while paused)
      engine.detachEventCallback();

      // Pause the engine (suspends listeners, pauses presence)
      final success = engine.pause();
      if (success) {
        log('LIFECYCLE', '[PAUSE] Engine paused successfully');
      } else {
        logError('LIFECYCLE', '[PAUSE] Engine pause failed');
      }

      // Platform-specific pause handling
      // Android: Notify service that Flutter is paused (service monitors for notifications)
      PlatformHandler.instance.onPause(engine);

      // Mark identity as not ready (triggers spinner on next resume until fully resumed)
      ref.read(identityReadyProvider.notifier).state = false;

      // v0.100.64+: Engine stays paused indefinitely - no timeout destruction
      // Android ForegroundService polls on the paused engine via nativeCheckOfflineMessages()
      // which uses the global g_engine pointer (still valid when paused)

    } catch (e) {
      logError('LIFECYCLE', '[PAUSE] Error: $e');
    } finally {
      _lifecycleState = _LifecycleState.idle;
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
