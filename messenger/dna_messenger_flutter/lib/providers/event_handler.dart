// Event Handler - Listens to engine events and updates UI state
import 'dart:async';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../ffi/dna_engine.dart';
import 'engine_provider.dart';
import 'contacts_provider.dart';
import 'messages_provider.dart';
import 'groups_provider.dart';

/// Connection state for DHT
enum DhtConnectionState { disconnected, connecting, connected }

final dhtConnectionStateProvider = StateProvider<DhtConnectionState>(
  (ref) => DhtConnectionState.disconnected,
);

/// Last error message for UI display (null = no error)
final lastErrorProvider = StateProvider<String?>((ref) => null);

/// Event handler provider - starts listening when watched
final eventHandlerProvider = Provider<EventHandler>((ref) {
  final handler = EventHandler(ref);

  // Start listening when provider is created
  ref.listen(engineProvider, (previous, next) {
    next.whenData((engine) {
      handler.startListening(engine);
    });
  }, fireImmediately: true);

  ref.onDispose(() {
    handler.dispose();
  });

  return handler;
});

class EventHandler {
  final Ref _ref;
  StreamSubscription<DnaEvent>? _subscription;

  EventHandler(this._ref);

  void startListening(DnaEngine engine) {
    // Cancel existing subscription if any
    _subscription?.cancel();

    // Listen to engine events
    _subscription = engine.events.listen(_handleEvent);
  }

  void _handleEvent(DnaEvent event) {
    switch (event) {
      case DhtConnectedEvent():
        _ref.read(dhtConnectionStateProvider.notifier).state =
            DhtConnectionState.connected;
        // Refresh contacts when DHT connects
        _ref.invalidate(contactsProvider);

      case DhtDisconnectedEvent():
        _ref.read(dhtConnectionStateProvider.notifier).state =
            DhtConnectionState.disconnected;

      case ContactOnlineEvent(fingerprint: final fp):
        _ref.read(contactsProvider.notifier).updateContactStatus(fp, true);

      case ContactOfflineEvent(fingerprint: final fp):
        _ref.read(contactsProvider.notifier).updateContactStatus(fp, false);

      case MessageReceivedEvent(message: final msg):
        // New message received - refresh conversation from DB (decrypts messages)
        final contactFp = msg.isOutgoing ? msg.recipient : msg.sender;
        final selectedContact = _ref.read(selectedContactProvider);
        final isChatOpen = selectedContact != null &&
            selectedContact.fingerprint == contactFp;

        // Debug: log fingerprint comparison
        print('[EVENT] MessageReceived: contactFp=${contactFp.length > 16 ? contactFp.substring(0, 16) : contactFp}...');
        print('[EVENT] selectedContact fp=${selectedContact?.fingerprint.substring(0, 16) ?? "null"}...');
        print('[EVENT] isChatOpen=$isChatOpen (match=${selectedContact?.fingerprint == contactFp})');

        // Always invalidate the conversation provider
        _ref.invalidate(conversationProvider(contactFp));

        // Always increment refresh trigger when message received (regardless of chat state)
        _ref.read(conversationRefreshTriggerProvider.notifier).state++;
        print('[EVENT] Incremented refresh trigger');

        if (!isChatOpen && !msg.isOutgoing) {
          // Increment unread count for incoming messages when chat not open
          _ref.read(unreadCountsProvider.notifier).incrementCount(contactFp);
        }

        // Always refresh contacts to update last message preview
        _ref.invalidate(contactsProvider);

      case MessageSentEvent():
        // Message was sent - status will be updated via delivered event
        break;

      case MessageDeliveredEvent(messageId: final id):
        // Update message status to delivered
        _updateMessageStatus(id, MessageStatus.delivered);

      case MessageReadEvent(messageId: final id):
        _updateMessageStatus(id, MessageStatus.read);

      case GroupInvitationReceivedEvent():
        // Refresh invitations list when new invitation received
        _ref.invalidate(invitationsProvider);
        break;

      case GroupMemberJoinedEvent():
      case GroupMemberLeftEvent():
        // Refresh groups to update member counts
        _ref.invalidate(groupsProvider);
        break;

      case IdentityLoadedEvent():
        // Identity loaded - refresh all data
        _ref.invalidate(contactsProvider);
        _ref.invalidate(groupsProvider);
        _ref.invalidate(invitationsProvider);
        break;

      case OutboxUpdatedEvent(contactFingerprint: final contactFp):
        // Contact's outbox has new messages - fetch them
        // Trigger offline message check, then refresh UI AFTER messages are in DB
        _ref.read(engineProvider).whenData((engine) async {
          await engine.checkOfflineMessages();
          // Now invalidate to refresh UI with new messages
          _ref.invalidate(conversationProvider(contactFp));
          _ref.invalidate(contactsProvider);
        });
        break;

      case ErrorEvent(message: final errorMsg):
        // Store error for UI to display
        _ref.read(lastErrorProvider.notifier).state = errorMsg;
        break;
    }
  }

  void _updateMessageStatus(int messageId, MessageStatus status) {
    // This is a bit tricky - we need to find which conversation has this message
    // For now, we'll rely on the conversation refreshing
    // A more sophisticated approach would track message IDs to conversations
  }

  void dispose() {
    _subscription?.cancel();
  }
}

/// Provider to ensure event handler is active
/// Add this to your main widget tree to start event handling
final eventHandlerActiveProvider = Provider<bool>((ref) {
  // Just watching the handler ensures it's created and listening
  ref.watch(eventHandlerProvider);
  return true;
});
