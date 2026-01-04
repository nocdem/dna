// Event Handler - Listens to engine events and updates UI state
import 'dart:async';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../ffi/dna_engine.dart';
import 'engine_provider.dart';
import 'contacts_provider.dart';
import 'messages_provider.dart';
import 'groups_provider.dart';
import 'contact_requests_provider.dart';
import 'identity_provider.dart';
import 'identity_profile_cache_provider.dart';

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

    // Sync initial DHT status - event may have been missed during startup race
    // Use Future.microtask to defer state modification until after provider build completes
    // (Riverpod doesn't allow modifying other providers during initialization)
    if (engine.isDhtConnected()) {
      Future.microtask(() {
        _ref.read(dhtConnectionStateProvider.notifier).state =
            DhtConnectionState.connected;
        // Start polling since we're connected
        _startContactRequestsPolling();
        _startPresencePolling();
        // Refresh identity profiles (display names/avatars) now that DHT is connected
        _refreshIdentityProfiles();
      });
    }
  }

  void _handleEvent(DnaEvent event) {
    switch (event) {
      case DhtConnectedEvent():
        _ref.read(dhtConnectionStateProvider.notifier).state =
            DhtConnectionState.connected;
        // Start DHT listeners for contacts' outboxes (push notifications)
        _startDhtListeners();
        // Refresh contacts when DHT connects
        _ref.invalidate(contactsProvider);
        // Refresh contact requests when DHT connects
        _ref.invalidate(contactRequestsProvider);
        // Refresh identity profiles (display names/avatars) now that DHT is connected
        // This fixes the race condition where prefetch fails on startup before DHT ready
        _refreshIdentityProfiles();
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
        // Also update selectedContactProvider if this contact is selected
        _updateSelectedContactPresence(fp, true);

      case ContactOfflineEvent(fingerprint: final fp):
        _ref.read(contactsProvider.notifier).updateContactStatus(fp, false);
        // Also update selectedContactProvider if this contact is selected
        _updateSelectedContactPresence(fp, false);

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
        print('[EVENT] OutboxUpdatedEvent received for: ${contactFp.length > 16 ? contactFp.substring(0, 16) : contactFp}...');

        // Check if chat is open for this contact BEFORE fetching
        final selectedContact = _ref.read(selectedContactProvider);
        final isChatOpen = selectedContact != null &&
            selectedContact.fingerprint == contactFp;
        print('[EVENT] isChatOpen for this contact: $isChatOpen');

        // Trigger offline message check, then refresh UI AFTER messages are in DB
        _ref.read(engineProvider).whenData((engine) async {
          print('[EVENT] Calling checkOfflineMessages...');
          await engine.checkOfflineMessages();
          print('[EVENT] checkOfflineMessages complete');

          // If chat is open, mark messages as read immediately
          // This prevents unread badge from showing for messages user is viewing
          if (isChatOpen) {
            print('[EVENT] Chat is open, marking messages as read');
            await engine.markConversationRead(contactFp);
            _ref.read(unreadCountsProvider.notifier).clearCount(contactFp);
          }

          // Refresh conversation UI
          _ref.invalidate(conversationProvider(contactFp));
          _ref.read(conversationRefreshTriggerProvider.notifier).state++;
          print('[EVENT] Conversation refreshed');
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

  /// Start DHT listeners for contacts' outboxes (push notifications)
  void _startDhtListeners() {
    _ref.read(engineProvider).whenData((engine) {
      final count = engine.listenAllContacts();
      print('[EventHandler] Started $count DHT outbox listeners');
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
  /// Announces our presence AND refreshes contact presence from DHT
  void _startPresencePolling() {
    _presenceTimer?.cancel();
    _presenceTimer = Timer.periodic(const Duration(seconds: 30), (_) {
      _ref.read(engineProvider).whenData((engine) async {
        // Announce our presence to DHT
        await engine.refreshPresence();
        // Refresh contacts to get updated presence status
        _ref.invalidate(contactsProvider);
      });
    });
  }

  /// Pause all polling timers (call when app goes to background)
  ///
  /// Prevents network calls while app is not active, avoiding:
  /// - Unnecessary battery/data usage
  /// - Exceptions from timer firing when app state is invalid
  void pausePolling() {
    print('[EventHandler] Pausing polling timers');
    _presenceTimer?.cancel();
    _presenceTimer = null;
    _contactRequestsTimer?.cancel();
    _contactRequestsTimer = null;
  }

  /// Resume all polling timers (call when app comes to foreground)
  ///
  /// Restarts periodic polling if DHT is connected.
  /// Note: Immediate presence refresh is handled by C-side resumePresence().
  void resumePolling() {
    print('[EventHandler] Resuming polling timers');
    final dhtState = _ref.read(dhtConnectionStateProvider);
    if (dhtState == DhtConnectionState.connected) {
      _startContactRequestsPolling();
      _startPresencePolling();
    }
  }

  /// Refresh identity profiles from DHT
  /// Called when DHT connects to fetch display names/avatars that may have
  /// failed during startup (race condition: prefetch before DHT ready)
  void _refreshIdentityProfiles() {
    final identities = _ref.read(identitiesProvider).valueOrNull;
    if (identities != null && identities.isNotEmpty) {
      _ref.read(identityProfileCacheProvider.notifier).prefetchIdentities(identities);
    }
  }

  /// Update selectedContactProvider when presence changes
  void _updateSelectedContactPresence(String fingerprint, bool isOnline) {
    final selectedContact = _ref.read(selectedContactProvider);
    if (selectedContact != null && selectedContact.fingerprint == fingerprint) {
      _ref.read(selectedContactProvider.notifier).state = Contact(
        fingerprint: selectedContact.fingerprint,
        displayName: selectedContact.displayName,
        isOnline: isOnline,
        lastSeen: isOnline ? DateTime.now() : selectedContact.lastSeen,
      );
    }
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
