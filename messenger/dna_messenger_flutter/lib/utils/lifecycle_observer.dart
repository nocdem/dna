// App Lifecycle Observer - handles app state changes
// v0.9.11: Pause/resume presence on background/foreground for battery optimization.

import 'package:flutter/widgets.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../providers/engine_provider.dart';
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
        break;
      case AppLifecycleState.detached:
      case AppLifecycleState.inactive:
      case AppLifecycleState.hidden:
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
