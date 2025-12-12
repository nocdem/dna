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
  /// For transfer messages (messageType: cpunkTransfer), the message is stored
  /// locally but not sent through the network (the transfer was already executed).
  int sendMessage(String text, {MessageType messageType = MessageType.chat}) {
    final engine = ref.read(engineProvider).valueOrNull;
    final fingerprint = engine?.fingerprint;
    if (fingerprint == null || engine == null) return -2;

    // Create pending message for optimistic UI
    final pendingMessage = Message.pending(
      sender: fingerprint,
      recipient: arg,
      plaintext: text,
      type: messageType,
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

    // For transfer messages, don't send through network - just record locally
    // Transfer messages are visual records of wallet transfers, not network messages
    if (messageType == MessageType.cpunkTransfer) {
      // Update the pending message to show as sent (transfer already completed)
      state.whenData((messages) {
        final updated = messages.map((m) {
          if (m.id == pendingMessage.id) {
            return Message(
              id: m.id,
              sender: m.sender,
              recipient: m.recipient,
              plaintext: m.plaintext,
              timestamp: m.timestamp,
              isOutgoing: m.isOutgoing,
              status: MessageStatus.sent,
              type: m.type,
            );
          }
          return m;
        }).toList();
        state = AsyncValue.data(updated);
      });
      return 0; // Success - transfer record added to chat
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
