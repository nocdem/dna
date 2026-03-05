// App Lifecycle Observer - handles app state changes
// v0.9.8+: Pauses/resumes presence heartbeat on mobile (battery optimization).

import 'package:flutter/widgets.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'logger.dart';
import 'platform_utils.dart';
import '../providers/engine_provider.dart';

/// Provider that tracks whether the app is currently in foreground (resumed)
/// Used by event_handler to determine whether to show notifications
final appInForegroundProvider = StateProvider<bool>((ref) => true);

/// Observer for app lifecycle state changes
///
/// Mobile: pauses presence heartbeat in background (30s→60s interval, skips
/// DB query + TCP presence). Resumes with immediate batch query on foreground.
/// Desktop: no-op (presence_active stays true).
class AppLifecycleObserver extends WidgetsBindingObserver {
  final WidgetRef ref;

  AppLifecycleObserver(this.ref);

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    switch (state) {
      case AppLifecycleState.resumed:
        ref.read(appInForegroundProvider.notifier).state = true;
        log('LIFECYCLE', 'App resumed (foreground)');
        if (PlatformUtils.isMobile) {
          ref.read(engineProvider).valueOrNull?.resumePresence();
        }
        break;
      case AppLifecycleState.paused:
        ref.read(appInForegroundProvider.notifier).state = false;
        log('LIFECYCLE', 'App paused (background)');
        if (PlatformUtils.isMobile) {
          ref.read(engineProvider).valueOrNull?.pausePresence();
        }
        break;
      case AppLifecycleState.detached:
      case AppLifecycleState.inactive:
      case AppLifecycleState.hidden:
        break;
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
