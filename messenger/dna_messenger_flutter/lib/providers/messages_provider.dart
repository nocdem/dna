// Messages Provider - Chat messages state management
import 'dart:async';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../ffi/dna_engine.dart';
import 'engine_provider.dart';
import 'contacts_provider.dart';

/// Conversation provider - keyed by contact fingerprint
final conversationProvider = AsyncNotifierProviderFamily<ConversationNotifier, List<Message>, String>(
  ConversationNotifier.new,
);

class ConversationNotifier extends FamilyAsyncNotifier<List<Message>, String> {
  @override
  Future<List<Message>> build(String arg) async {
    final engine = await ref.watch(engineProvider.future);
    return engine.getConversation(arg);
  }

  Future<void> refresh() async {
    state = const AsyncValue.loading();
    state = await AsyncValue.guard(() async {
      final engine = await ref.read(engineProvider.future);
      return engine.getConversation(arg);
    });
  }

  /// Send message using async queue (fire-and-forget with optimistic UI)
  ///
  /// Returns:
  /// - >= 0: success (queue slot ID)
  /// - -1: queue full
  /// - -2: other error
  ///
  /// Transfer messages are sent as JSON with "type": "cpunk_transfer" tag.
  /// The UI detects this tag and displays them as transfer bubbles.
  int sendMessage(String text) {
    final engine = ref.read(engineProvider).valueOrNull;
    final fingerprint = engine?.fingerprint;
    if (fingerprint == null || engine == null) return -2;

    // Create pending message for optimistic UI
    final pendingMessage = Message.pending(
      sender: fingerprint,
      recipient: arg,
      plaintext: text,
    );

    // Add to UI immediately with pending status
    // Handle all state cases - not just when data is available
    final currentState = state;
    if (currentState is AsyncData<List<Message>>) {
      state = AsyncValue.data([...currentState.value, pendingMessage]);
    } else {
      // If loading or error, start fresh with just this message
      state = AsyncValue.data([pendingMessage]);
    }

    // Queue message for async sending (returns immediately)
    final result = engine.queueMessage(arg, text);

    if (result < 0) {
      // On error, remove the pending message
      state.whenData((messages) {
        final updated = messages.where((m) => m.id != pendingMessage.id).toList();
        state = AsyncValue.data(updated);
      });
    } else {
      // Start a background refresh to update message status
      _scheduleRefresh();
    }

    return result;
  }

  /// Schedule a delayed refresh to pick up sent message status
  void _scheduleRefresh() {
    Future.delayed(const Duration(milliseconds: 500), () {
      refresh();
    });
  }

  void addMessage(Message message) {
    state.whenData((messages) {
      final updated = List<Message>.from(messages)..add(message);
      state = AsyncValue.data(updated);
    });
  }

  void updateMessageStatus(int messageId, MessageStatus status) {
    state.whenData((messages) {
      final index = messages.indexWhere((m) => m.id == messageId);
      if (index != -1) {
        final updated = List<Message>.from(messages);
        final msg = updated[index];
        updated[index] = Message(
          id: msg.id,
          sender: msg.sender,
          recipient: msg.recipient,
          plaintext: msg.plaintext,
          timestamp: msg.timestamp,
          isOutgoing: msg.isOutgoing,
          status: status,
          type: msg.type,
        );
        state = AsyncValue.data(updated);
      }
    });
  }
}

/// Refresh trigger - increment to force conversation rebuild
final conversationRefreshTriggerProvider = StateProvider<int>((ref) => 0);

/// Current conversation provider (for the selected contact)
final currentConversationProvider = Provider<AsyncValue<List<Message>>>((ref) {
  // Watch the refresh trigger to force rebuilds
  ref.watch(conversationRefreshTriggerProvider);

  final contact = ref.watch(selectedContactProvider);
  if (contact == null) {
    return const AsyncValue.data([]);
  }
  return ref.watch(conversationProvider(contact.fingerprint));
});

/// Message input text
final messageInputProvider = StateProvider<String>((ref) => '');
