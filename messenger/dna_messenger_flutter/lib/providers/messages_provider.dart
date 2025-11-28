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

  Future<void> sendMessage(String text) async {
    final engine = await ref.read(engineProvider.future);
    await engine.sendMessage(arg, text);
    await refresh();
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

/// Current conversation provider (for the selected contact)
final currentConversationProvider = Provider<AsyncValue<List<Message>>>((ref) {
  final contact = ref.watch(selectedContactProvider);
  if (contact == null) {
    return const AsyncValue.data([]);
  }
  return ref.watch(conversationProvider(contact.fingerprint));
});

/// Message input text
final messageInputProvider = StateProvider<String>((ref) => '');
