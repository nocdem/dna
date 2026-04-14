// App Lifecycle Observer - handles app state changes
// v0.9.11: Pause/resume presence on background/foreground for battery optimization.

import 'package:flutter/widgets.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../providers/engine_provider.dart';
import 'clipboard_utils.dart';
import 'logger.dart';

/// Provider that tracks whether the app is currently in foreground (resumed)
/// Used by event_handler to determine whether to show notifications
final appInForegroundProvider = StateProvider<bool>((ref) => true);

/// Observer for app lifecycle state changes
///
/// Tracks foreground/background state and pauses/resumes C-side presence
/// heartbeat for battery optimization on mobile.
class AppLifecycleObserver extends WidgetsBindingObserver {
  final WidgetRef ref;

  AppLifecycleObserver(this.ref);

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    switch (state) {
      case AppLifecycleState.resumed:
        ref.read(appInForegroundProvider.notifier).state = true;
        log('LIFECYCLE', 'App resumed (foreground)');
        _resumePresence();
        break;
      case AppLifecycleState.paused:
        ref.read(appInForegroundProvider.notifier).state = false;
        log('LIFECYCLE', 'App paused (background)');
        _pausePresence();
        // SEC-09: primary clipboard clear on backgrounding — paused is the
        // reliable state that fires before the OS removes the process from
        // the foreground on home/task-switch/lock.
        ClipboardUtils.clearIfSensitive();
        break;
      case AppLifecycleState.hidden:
        // SEC-09: defense in depth — hidden fires slightly earlier than
        // paused on Flutter 3.13+ on the same backgrounding transitions.
        ClipboardUtils.clearIfSensitive();
        break;
      case AppLifecycleState.detached:
        // SEC-09: best-effort clear on clean shutdown. May not get CPU time
        // on swipe-kill / OOM-kill; that residual risk is documented in
        // ClipboardUtils and accepted per user decision D-01/D-02.
        ClipboardUtils.clearIfSensitive();
        break;
      case AppLifecycleState.inactive:
        // No-op: inactive is a transient focus loss (phone call overlay,
        // permission dialog) — not a real backgrounding event. Clearing
        // here would wipe the clipboard on every in-app permission prompt.
        break;
    }
  }

  void _pausePresence() {
    final engine = ref.read(engineProvider).valueOrNull;
    if (engine != null) {
      engine.pausePresence();
    }
  }

  void _resumePresence() {
    final engine = ref.read(engineProvider).valueOrNull;
    if (engine != null) {
      engine.resumePresence();
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
