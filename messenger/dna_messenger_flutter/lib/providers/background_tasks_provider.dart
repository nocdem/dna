// Background Tasks Provider - Periodic DHT polling for offline messages
import 'dart:async';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../ffi/dna_engine.dart';
import 'engine_provider.dart';
import 'identity_provider.dart';
import 'contacts_provider.dart';
import 'messages_provider.dart';

/// Poll interval for DHT offline messages (2 minutes)
const _pollInterval = Duration(minutes: 2);

/// Initial delay before first poll after identity load (15 seconds)
const _initialDelay = Duration(seconds: 15);

/// Delay before starting outbox listeners (let DHT stabilize)
const _listenerDelay = Duration(seconds: 10);

/// Background task manager state
class BackgroundTasksState {
  final bool isPolling;
  final DateTime? lastPollTime;
  final int messagesReceived;
  final int activeListeners;  // Number of active outbox listeners

  const BackgroundTasksState({
    this.isPolling = false,
    this.lastPollTime,
    this.messagesReceived = 0,
    this.activeListeners = 0,
  });

  BackgroundTasksState copyWith({
    bool? isPolling,
    DateTime? lastPollTime,
    int? messagesReceived,
    int? activeListeners,
  }) {
    return BackgroundTasksState(
      isPolling: isPolling ?? this.isPolling,
      lastPollTime: lastPollTime ?? this.lastPollTime,
      messagesReceived: messagesReceived ?? this.messagesReceived,
      activeListeners: activeListeners ?? this.activeListeners,
    );
  }
}

/// Background tasks manager - handles periodic DHT polling
final backgroundTasksProvider = StateNotifierProvider<BackgroundTasksNotifier, BackgroundTasksState>(
  (ref) => BackgroundTasksNotifier(ref),
);

class BackgroundTasksNotifier extends StateNotifier<BackgroundTasksState> {
  final Ref _ref;
  Timer? _pollTimer;
  bool _disposed = false;
  bool _listenersStarted = false;

  BackgroundTasksNotifier(this._ref) : super(const BackgroundTasksState()) {
    // Start polling when identity is loaded
    _ref.listen(currentFingerprintProvider, (previous, next) {
      if (next != null && previous == null) {
        // Identity just loaded - start polling after initial delay
        _startPolling();
        // Also start outbox listeners
        _startOutboxListeners();
      } else if (next == null && previous != null) {
        // Identity unloaded - stop polling and cancel listeners
        _stopPolling();
        _cancelOutboxListeners();
      }
    }, fireImmediately: true);
  }

  void _startPolling() {
    if (_disposed) return;

    // Cancel existing timer if any
    _pollTimer?.cancel();

    // Initial poll after delay
    Future.delayed(_initialDelay, () {
      if (!_disposed) {
        _pollOfflineMessages();
      }
    });

    // Set up periodic timer
    _pollTimer = Timer.periodic(_pollInterval, (_) {
      if (!_disposed) {
        _pollOfflineMessages();
      }
    });
  }

  void _stopPolling() {
    _pollTimer?.cancel();
    _pollTimer = null;
  }

  /// Start outbox listeners for all contacts
  void _startOutboxListeners() {
    if (_disposed || _listenersStarted) return;

    // Delay to let DHT connection stabilize
    Future.delayed(_listenerDelay, () async {
      if (_disposed) return;

      try {
        final engine = await _ref.read(engineProvider.future);
        final count = engine.listenAllContacts();
        _listenersStarted = true;
        state = state.copyWith(activeListeners: count);
      } catch (e) {
        // Ignore errors - listeners are optional optimization
      }
    });
  }

  /// Cancel all outbox listeners
  void _cancelOutboxListeners() {
    if (!_listenersStarted) return;

    try {
      _ref.read(engineProvider).whenData((engine) {
        engine.cancelAllOutboxListeners();
      });
    } catch (e) {
      // Ignore errors during cleanup
    }

    _listenersStarted = false;
    state = state.copyWith(activeListeners: 0);
  }

  /// Start listening for a specific contact's outbox (call when contact added)
  void listenToContact(String contactFingerprint) {
    if (_disposed || !_listenersStarted) return;

    _ref.read(engineProvider).whenData((engine) {
      final token = engine.listenOutbox(contactFingerprint);
      if (token > 0) {
        state = state.copyWith(activeListeners: state.activeListeners + 1);
      }
    });
  }

  /// Stop listening to a specific contact's outbox (call when contact removed)
  void stopListeningToContact(String contactFingerprint) {
    if (_disposed) return;

    _ref.read(engineProvider).whenData((engine) {
      engine.cancelOutboxListener(contactFingerprint);
      if (state.activeListeners > 0) {
        state = state.copyWith(activeListeners: state.activeListeners - 1);
      }
    });
  }

  Future<void> _pollOfflineMessages() async {
    if (state.isPolling) {
      return;
    }

    state = state.copyWith(isPolling: true);

    try {
      final engine = await _ref.read(engineProvider.future);
      await engine.checkOfflineMessages();

      state = state.copyWith(
        isPolling: false,
        lastPollTime: DateTime.now(),
      );

      // Refresh contacts and current conversation to show new messages
      _ref.invalidate(contactsProvider);

      // If a contact is selected, refresh their conversation
      final selectedContact = _ref.read(selectedContactProvider);
      if (selectedContact != null) {
        _ref.invalidate(conversationProvider(selectedContact.fingerprint));
      }

    } catch (e) {
      state = state.copyWith(isPolling: false);
    }
  }

  /// Force an immediate poll (for manual refresh)
  Future<void> forcePoll() async {
    await _pollOfflineMessages();
  }

  @override
  void dispose() {
    _disposed = true;
    _stopPolling();
    _cancelOutboxListeners();
    super.dispose();
  }
}

/// Provider to ensure background tasks are active
/// Add this to your main widget tree to start background polling
final backgroundTasksActiveProvider = Provider<bool>((ref) {
  // Just watching the provider ensures it's created and running
  ref.watch(backgroundTasksProvider);
  return true;
});
