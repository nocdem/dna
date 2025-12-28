// Event Handler - Listens to engine events and updates UI state
import 'dart:async';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../ffi/dna_engine.dart';
import 'engine_provider.dart';
import 'contacts_provider.dart';
import 'messages_provider.dart';
import 'groups_provider.dart';
import 'contact_requests_provider.dart';

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
  Timer? _refreshTimer;
  Timer? _contactRequestsTimer;
  Timer? _presenceTimer;

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
        // Refresh contact requests when DHT connects
        _ref.invalidate(contactRequestsProvider);
        // Start periodic contact request polling (every 60 seconds)
        _startContactRequestsPolling();
        // Start periodic presence refresh (every 5 seconds)
        _startPresencePolling();

      case DhtDisconnectedEvent():
        _ref.read(dhtConnectionStateProvider.notifier).state =
            DhtConnectionState.disconnected;
        // Stop polling when disconnected
        _contactRequestsTimer?.cancel();
        _contactRequestsTimer = null;
        _presenceTimer?.cancel();
        _presenceTimer = null;

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
        // Debounced refresh - only once after last message sent
        _scheduleConversationRefresh();
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
        _ref.invalidate(contactRequestsProvider);
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
    // Update the message status in the current conversation
    final selectedContact = _ref.read(selectedContactProvider);
    if (selectedContact != null) {
      _ref.read(conversationProvider(selectedContact.fingerprint).notifier)
          .updateMessageStatus(messageId, status);
    }
  }

  /// Schedule a debounced conversation refresh
  /// Coalesces rapid MessageSentEvents into a single refresh
  void _scheduleConversationRefresh() {
    _refreshTimer?.cancel();
    _refreshTimer = Timer(const Duration(milliseconds: 300), () {
      final selectedContact = _ref.read(selectedContactProvider);
      if (selectedContact != null) {
        _ref.invalidate(conversationProvider(selectedContact.fingerprint));
      }
    });
  }

  /// Start periodic polling for contact requests (every 60 seconds)
  void _startContactRequestsPolling() {
    _contactRequestsTimer?.cancel();
    _contactRequestsTimer = Timer.periodic(const Duration(seconds: 60), (_) {
      _ref.invalidate(contactRequestsProvider);
    });
  }

  /// Start periodic presence refresh (every 30 seconds)
  /// Announces our presence to DHT (contact presence updated on demand)
  void _startPresencePolling() {
    _presenceTimer?.cancel();
    _presenceTimer = Timer.periodic(const Duration(seconds: 30), (_) {
      _ref.read(engineProvider).whenData((engine) async {
        // Announce our presence to DHT
        await engine.refreshPresence();
        // Note: Don't invalidate contactsProvider here - it causes excessive rebuilds
        // Contact presence is updated on demand when viewing contacts
      });
    });
  }

  void dispose() {
    _subscription?.cancel();
    _refreshTimer?.cancel();
    _contactRequestsTimer?.cancel();
    _presenceTimer?.cancel();
  }
}

/// Provider to ensure event handler is active
/// Add this to your main widget tree to start event handling
final eventHandlerActiveProvider = Provider<bool>((ref) {
  // Just watching the handler ensures it's created and listening
  ref.watch(eventHandlerProvider);
  return true;
});
