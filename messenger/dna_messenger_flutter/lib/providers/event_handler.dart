// Event Handler - Listens to engine events and updates UI state
import 'dart:async';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../ffi/dna_engine.dart';
import 'engine_provider.dart';
import 'contacts_provider.dart';
import 'messages_provider.dart';

/// Connection state for DHT
enum DhtConnectionState { disconnected, connecting, connected }

final dhtConnectionStateProvider = StateProvider<DhtConnectionState>(
  (ref) => DhtConnectionState.disconnected,
);

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
        // Add message to the conversation
        final contactFp = msg.isOutgoing ? msg.recipient : msg.sender;
        _ref.read(conversationProvider(contactFp).notifier).addMessage(msg);
        // Also refresh contacts to update last message preview if needed
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
        // TODO: Show notification, refresh invitations list
        break;

      case GroupMemberJoinedEvent():
      case GroupMemberLeftEvent():
        // TODO: Refresh group members
        break;

      case IdentityLoadedEvent():
        // Identity loaded - refresh all data
        _ref.invalidate(contactsProvider);
        break;

      case ErrorEvent():
        // TODO: Show error notification via snackbar service
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
