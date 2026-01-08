// Event Handler - Listens to engine events and updates UI state
import 'dart:async';
import 'dart:io' show Platform;
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../ffi/dna_engine.dart';
import '../utils/lifecycle_observer.dart';
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
  Timer? _outboxDebounceTimer;
  final Set<String> _pendingOutboxFingerprints = {};

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
        // DHT listeners are started by C engine on DHT connect (dna_engine.c:195)
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
        // DHT listeners are started by C engine on DHT connect (dna_engine.c:195)
        // Refresh contacts when DHT connects (seamless update)
        _ref.read(contactsProvider.notifier).refresh();
        // Refresh contact requests when DHT connects
        _ref.invalidate(contactRequestsProvider);
        // Refresh identity profiles (display names/avatars) now that DHT is connected
        // This fixes the race condition where prefetch fails on startup before DHT ready
        _refreshIdentityProfiles();
        // Start periodic contact request polling (every 60 seconds)
        _startContactRequestsPolling();
        // Start periodic presence refresh (every 30 seconds)
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
        final appInForeground = _ref.read(appInForegroundProvider);

        // Always invalidate the conversation provider
        _ref.invalidate(conversationProvider(contactFp));

        // Always increment refresh trigger when message received (regardless of chat state)
        _ref.read(conversationRefreshTriggerProvider.notifier).state++;

        // Show notification for incoming messages when:
        // - App is in background (always), OR
        // - App is in foreground but chat is not open
        if (!msg.isOutgoing && (!appInForeground || !isChatOpen)) {
          // Increment unread count for incoming messages when chat not open
          _ref.read(unreadCountsProvider.notifier).incrementCount(contactFp);

          // Show notification for incoming message
          _showMessageNotification(contactFp, msg.plaintext);
        }

        // NOTE: We intentionally do NOT invalidate(contactsProvider) here.
        // Contact tiles don't show message previews - only avatar, name, online status, and unread count.
        // Unread counts are already updated via incrementCount() above.
        // Full contact list rebuilds cause unnecessary UI churn and presence bouncing.

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
        // Identity loaded - refresh all data (seamless update for contacts)
        _ref.read(contactsProvider.notifier).refresh();
        _ref.invalidate(groupsProvider);
        _ref.invalidate(invitationsProvider);
        _ref.invalidate(contactRequestsProvider);
        break;

      case OutboxUpdatedEvent(contactFingerprint: final contactFp):
        // Contact's outbox has new messages - debounce to coalesce rapid events
        _scheduleOutboxCheck(contactFp);
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

  /// Schedule a debounced outbox check
  /// On Android: Native code already fetched messages and shows JNI notifications.
  ///             Flutter just syncs unread counts from DB and refreshes UI.
  /// On Desktop: Flutter must call checkOfflineMessages() to fetch.
  void _scheduleOutboxCheck(String contactFp) {
    // Collect fingerprints during debounce window
    _pendingOutboxFingerprints.add(contactFp);

    // Reset debounce timer
    _outboxDebounceTimer?.cancel();
    _outboxDebounceTimer = Timer(const Duration(milliseconds: 400), () {
      // Capture fingerprints and clear pending set
      final fingerprints = Set<String>.from(_pendingOutboxFingerprints);
      _pendingOutboxFingerprints.clear();

      // Check which chats are open BEFORE processing
      final selectedContact = _ref.read(selectedContactProvider);
      final openChatFp = selectedContact?.fingerprint;

      _ref.read(engineProvider).whenData((engine) async {
        // On Desktop, we need to fetch messages ourselves.
        // On Android, native code already fetched via background_fetch_thread.
        if (!Platform.isAndroid) {
          await engine.checkOfflineMessages();
        }

        // Process each contact that had updates
        for (final fp in fingerprints) {
          // If chat is open for this contact, mark as read
          if (openChatFp == fp) {
            await engine.markConversationRead(fp);
            _ref.read(unreadCountsProvider.notifier).clearCount(fp);
          } else {
            // Sync unread count from database
            final dbCount = engine.getUnreadCount(fp);
            if (dbCount > 0) {
              _ref.read(unreadCountsProvider.notifier).setCount(fp, dbCount);
            }
          }

          // Refresh conversation UI for this contact
          _ref.invalidate(conversationProvider(fp));
        }

        // Single refresh trigger increment after all processing
        _ref.read(conversationRefreshTriggerProvider.notifier).state++;
      });
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
  /// Announces our presence to DHT
  void _startPresencePolling() {
    _presenceTimer?.cancel();
    _presenceTimer = Timer.periodic(const Duration(seconds: 30), (_) {
      _ref.read(engineProvider).whenData((engine) async {
        // Announce our presence to DHT
        // Phase 14: Works in DHT-only mode (no P2P transport required)
        await engine.refreshPresence();
        // NOTE: We do NOT invalidate(contactsProvider) here.
        // Contact presence updates come through via ContactOnline/ContactOffline events
        // which are handled by updateContactStatus() in ContactsNotifier.
        // Full invalidation causes unnecessary rebuilds and visual bouncing.
      });
    });
  }

  /// Pause all polling timers (call when app goes to background)
  ///
  /// Prevents network calls while app is not active, avoiding:
  /// - Unnecessary battery/data usage
  /// - Exceptions from timer firing when app state is invalid
  void pausePolling() {
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

  /// Show notification for incoming message
  /// NOTE: On Android, notifications are handled by native JNI service (DnaMessengerService)
  /// TODO: Add native notifications for Linux (libnotify) and Windows (Win32 Toast)
  /// For now, desktop notifications are disabled until native support is added
  void _showMessageNotification(String contactFingerprint, String messageText) {
    // Android: JNI handles notifications natively via DnaNotificationHelper
    // Desktop: Disabled for now - Flutter notifications don't work when app unfocused
    // Future: Add libnotify (Linux) and Win32 Toast (Windows) in C code
    return;
  }

  void dispose() {
    _subscription?.cancel();
    _refreshTimer?.cancel();
    _contactRequestsTimer?.cancel();
    _presenceTimer?.cancel();
    _outboxDebounceTimer?.cancel();
  }
}

/// Provider to ensure event handler is active
/// Add this to your main widget tree to start event handling
final eventHandlerActiveProvider = Provider<bool>((ref) {
  // Just watching the handler ensures it's created and listening
  ref.watch(eventHandlerProvider);
  return true;
});
