// Listener State Provider - Tracks which contacts have active DHT listeners
// v0.6.3: Mobile performance optimization - lazy loading of listeners

import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../utils/logger.dart' show log;

/// Tracks which contacts have active listeners set up.
/// Used for lazy loading optimization - only set up listeners for visible contacts.
class ListenerStateNotifier extends StateNotifier<Set<String>> {
  ListenerStateNotifier() : super({});

  /// Check if a contact has an active listener
  bool hasListener(String fingerprint) => state.contains(fingerprint);

  /// Mark a contact as having an active listener
  void markActive(String fingerprint) {
    if (!state.contains(fingerprint)) {
      state = {...state, fingerprint};
      log('LISTENER', 'Marked active: ${fingerprint.substring(0, 16)}...');
    }
  }

  /// Mark multiple contacts as having active listeners
  void markActiveMultiple(Iterable<String> fingerprints) {
    final newState = {...state};
    int added = 0;
    for (final fp in fingerprints) {
      if (!newState.contains(fp)) {
        newState.add(fp);
        added++;
      }
    }
    if (added > 0) {
      state = newState;
      log('LISTENER', 'Marked $added contacts active');
    }
  }

  /// Clear all listener state (e.g., on identity change or logout)
  void clear() {
    if (state.isNotEmpty) {
      log('LISTENER', 'Cleared ${state.length} listener states');
      state = {};
    }
  }

  /// Get count of active listeners
  int get activeCount => state.length;
}

/// Provider for listener state management
final listenerStateProvider =
    StateNotifierProvider<ListenerStateNotifier, Set<String>>(
  (ref) => ListenerStateNotifier(),
);
