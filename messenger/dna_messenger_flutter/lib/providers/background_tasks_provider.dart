// Background Tasks Provider - Manual refresh support
// Note: DHT listeners and initial offline check are handled by C code during identity load
// (messenger_transport_subscribe_to_contacts + messenger_transport_check_offline_messages)
import 'dart:async';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'engine_provider.dart';
import 'contacts_provider.dart';
import 'messages_provider.dart';

/// Background task manager state
class BackgroundTasksState {
  final bool isPolling;
  final DateTime? lastPollTime;
  final int messagesReceived;

  const BackgroundTasksState({
    this.isPolling = false,
    this.lastPollTime,
    this.messagesReceived = 0,
  });

  BackgroundTasksState copyWith({
    bool? isPolling,
    DateTime? lastPollTime,
    int? messagesReceived,
  }) {
    return BackgroundTasksState(
      isPolling: isPolling ?? this.isPolling,
      lastPollTime: lastPollTime ?? this.lastPollTime,
      messagesReceived: messagesReceived ?? this.messagesReceived,
    );
  }
}

/// Background tasks manager - provides manual refresh capability
/// Note: Automatic DHT listeners are set up by C code during identity load
final backgroundTasksProvider = StateNotifierProvider<BackgroundTasksNotifier, BackgroundTasksState>(
  (ref) => BackgroundTasksNotifier(ref),
);

class BackgroundTasksNotifier extends StateNotifier<BackgroundTasksState> {
  final Ref _ref;
  // ignore: unused_field
  bool _disposed = false; // Kept for potential future use in async guards

  BackgroundTasksNotifier(this._ref) : super(const BackgroundTasksState());

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
    super.dispose();
  }
}

/// Provider to ensure background tasks are active
/// Add this to your main widget tree to start DHT listeners
final backgroundTasksActiveProvider = Provider<bool>((ref) {
  // Just watching the provider ensures it's created and running
  ref.watch(backgroundTasksProvider);
  return true;
});
