// App Lifecycle Observer - handles app state changes
// Phase 14: DHT-only messaging with reliable Android background support
// v0.100.82+: Mobile uses destroy/create pattern (not pause/resume) for clean state on resume

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
/// v0.100.82+ Architecture (mobile only - desktop never pauses):
/// - On pause: DESTROY engine (clean shutdown, ForegroundService takes over)
/// - On resume: CREATE fresh engine + full identity load (~1.5s)
/// - Android ForegroundService has its own minimal engine for background polling
///
/// This provides clean state on every resume (no stale listeners or accumulated state).
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
        _onDetached();
        break;
      case AppLifecycleState.inactive:
        // App is inactive (e.g., phone call overlay)
        // Don't pause here - might just be a brief interruption
        break;
      case AppLifecycleState.hidden:
        // Only pause on mobile - desktop keeps running when minimized
        if (Platform.isAndroid || Platform.isIOS) {
          _onPause();
        }
        break;
    }
  }

  /// Called when app comes to foreground
  void _onResume() async {
    // IMMEDIATE: Mark app as in foreground (for notification logic)
    // This must happen synchronously before any async work
    ref.read(appInForegroundProvider.notifier).state = true;

    // Check if identity was loaded before going to background
    // currentFingerprintProvider is preserved across engine destroy/create
    final fingerprint = ref.read(currentFingerprintProvider);
    if (fingerprint == null || fingerprint.isEmpty) {
      return;
    }

    // State machine guard: only one resume at a time
    if (_lifecycleState != _LifecycleState.idle) {
      log('LIFECYCLE', '[RESUME] Already in state $_lifecycleState, ignoring');
      return;
    }

    // Enter resuming state
    _lifecycleState = _LifecycleState.resuming;
    _pauseRequested = false;
    final myOpId = ++_operationId;

    try {
      // v0.100.82+: Mobile uses destroy/create pattern
      // Engine was destroyed on pause, need fresh creation + full identity load
      log('LIFECYCLE', '[RESUME] Creating fresh engine and loading identity');

      // Notify service FIRST so it releases its engine (Android only)
      // Service must release DHT lock before Flutter can create new engine
      if (Platform.isAndroid) {
        await PlatformHandler.instance.onResumePreEngine();
      }

      // Abort checkpoint
      if (_shouldAbort(myOpId)) {
        log('LIFECYCLE', '[RESUME] Aborted after onResumePreEngine');
        return;
      }

      // Get fresh engine (provider was invalidated on pause, so this creates new one)
      final engine = await ref.read(engineProvider.future);

      // Abort checkpoint
      if (_shouldAbort(myOpId)) {
        log('LIFECYCLE', '[RESUME] Aborted after engine creation');
        return;
      }

      // Check if identity is already loaded (might happen if pause didn't complete)
      if (!engine.isIdentityLoaded()) {
        // Load identity (keys, transport, listeners) - full load for Flutter
        await ref.read(identitiesProvider.notifier).loadIdentity(fingerprint);
      } else {
        log('LIFECYCLE', '[RESUME] Identity already loaded, skipping loadIdentity');
      }

      // Abort checkpoint
      if (_shouldAbort(myOpId)) {
        log('LIFECYCLE', '[RESUME] Aborted after loadIdentity');
        return;
      }

      // Platform-specific resume handling (attaches callback, fetches offline messages)
      await PlatformHandler.instance.onResume(engine);

      // Abort checkpoint
      if (_shouldAbort(myOpId)) {
        log('LIFECYCLE', '[RESUME] Aborted after onResume');
        return;
      }

      // Resume Dart-side polling timers
      ref.read(eventHandlerProvider).resumePolling();

      log('LIFECYCLE', '[RESUME] Engine created and identity loaded');

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

    // State machine guard FIRST - before any async work
    // Android fires both 'hidden' and 'paused' events - must block second one immediately
    if (_lifecycleState == _LifecycleState.pausing) {
      log('LIFECYCLE', '[PAUSE] Already pausing, ignoring duplicate event');
      return;
    }

    // Check if identity is loaded (no need to destroy if nothing loaded)
    final fingerprint = ref.read(currentFingerprintProvider);
    if (fingerprint == null || fingerprint.isEmpty) {
      return;
    }

    // Set pausing state IMMEDIATELY to block concurrent pause attempts
    _lifecycleState = _LifecycleState.pausing;

    // If resume is in progress, signal it to abort and wait
    if (_pauseRequested == false) {
      _pauseRequested = true;

      // Wait up to 3 seconds for resume to abort
      final deadline = DateTime.now().add(const Duration(seconds: 3));
      while (_lifecycleState == _LifecycleState.resuming &&
             DateTime.now().isBefore(deadline)) {
        await Future.delayed(const Duration(milliseconds: 50));
      }

      // If resume still hasn't aborted, force it via operation ID
      _operationId++;
      await Future.delayed(const Duration(milliseconds: 100));
    }

    try {
      // Get current engine state - don't create new one if already disposed
      final engineAsync = ref.read(engineProvider);
      final engine = engineAsync.valueOrNull;

      if (engine == null || engine.isDisposed) {
        log('LIFECYCLE', '[PAUSE] Engine already disposed or null, skipping');
        ref.read(identityReadyProvider.notifier).state = false;
        return;
      }

      // v0.100.82+: DESTROY engine on background (mobile only)
      // Fresh engine will be created on resume for clean state
      log('LIFECYCLE', '[PAUSE] Destroying engine (mobile destroy/create pattern)');

      // Detach event callback before destroying
      engine.detachEventCallback();

      // Platform-specific pause handling BEFORE dispose
      // Android: Notify service that Flutter is paused (service takes over with its own engine)
      PlatformHandler.instance.onPause(engine);

      // Destroy the C engine
      engine.dispose();
      log('LIFECYCLE', '[PAUSE] Engine destroyed');

      // Invalidate provider so next access creates fresh engine
      ref.invalidate(engineProvider);

      // Mark identity as not ready (triggers spinner on next resume)
      ref.read(identityReadyProvider.notifier).state = false;

      // NOTE: currentFingerprintProvider is preserved - needed to reload identity on resume

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
