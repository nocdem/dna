// Event Handler - Listens to engine events and updates UI state
import 'dart:async';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../ffi/dna_engine.dart';
import '../platform/platform_handler.dart';
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

/// Timestamp when DHT last connected (for fetch cooldown logic)
final dhtConnectedAtProvider = StateProvider<DateTime?>((ref) => null);

/// Last offline fetch time per contact (fingerprint -> DateTime)
final _lastOfflineFetchProvider = StateProvider<Map<String, DateTime>>(
  (ref) => {},
);

/// Cooldown duration for offline message checks
const _offlineFetchCooldownSeconds = 30;

/// Check if we should fetch offline messages for a contact
/// Returns false if checked recently and DHT has been stable
bool shouldFetchOfflineMessages(dynamic ref, String contactFingerprint) {
  final lastFetchTimes = ref.read(_lastOfflineFetchProvider);
  final lastFetch = lastFetchTimes[contactFingerprint];
  final dhtConnectedAt = ref.read(dhtConnectedAtProvider);
  final now = DateTime.now();

  // Never fetched for this contact - always fetch
  if (lastFetch == null) return true;

  // DHT just reconnected (within 10 seconds) - fetch to catch missed messages
  if (dhtConnectedAt != null &&
      now.difference(dhtConnectedAt).inSeconds < 10) {
    return true;
  }

  // Cooldown not passed - skip fetch
  if (now.difference(lastFetch).inSeconds < _offlineFetchCooldownSeconds) {
    return false;
  }

  return true;
}

/// Record that we fetched offline messages for a contact
void recordOfflineFetch(dynamic ref, String contactFingerprint) {
  final notifier = ref.read(_lastOfflineFetchProvider.notifier);
  notifier.state = {
    ...notifier.state,
    contactFingerprint: DateTime.now(),
  };
}

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
        // Start presence polling since we're connected
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
        // Record connection time (for offline fetch cooldown logic)
        _ref.read(dhtConnectedAtProvider.notifier).state = DateTime.now();
        // DHT listeners are started by C engine on DHT connect (dna_engine.c:195)
        // Refresh contacts when DHT connects (seamless update)
        _ref.read(contactsProvider.notifier).refresh();
        // Refresh contact requests when DHT connects
        _ref.invalidate(contactRequestsProvider);
        // Refresh identity profiles (display names/avatars) now that DHT is connected
        // This fixes the race condition where prefetch fails on startup before DHT ready
        _refreshIdentityProfiles();
        // Start periodic presence refresh (every 30 seconds)
        _startPresencePolling();

      case DhtDisconnectedEvent():
        _ref.read(dhtConnectionStateProvider.notifier).state =
            DhtConnectionState.disconnected;
        // Stop polling when disconnected
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
        // Check if this is a group invitation - handle separately
        if (msg.type == MessageType.groupInvitation) {
          _ref.invalidate(invitationsProvider);
          break;
        }

        // New message received - refresh conversation from DB (decrypts messages)
        final contactFp = msg.isOutgoing ? msg.recipient : msg.sender;
        final selectedContact = _ref.read(selectedContactProvider);
        final isChatOpen = selectedContact != null &&
            selectedContact.fingerprint == contactFp;
        final appInForeground = _ref.read(appInForegroundProvider);

        // Debug logging for badge issue investigation
        final engine = _ref.read(engineProvider).valueOrNull;
        engine?.debugLog('EVENT', 'MESSAGE_RECEIVED: isOutgoing=${msg.isOutgoing}, contactFp=${contactFp.substring(0, 16)}..., isChatOpen=$isChatOpen, appInForeground=$appInForeground');

        // Merge new message without full reload (avoids UI flash)
        _ref.read(conversationProvider(contactFp).notifier).mergeLatest();

        // Show notification for incoming messages when:
        // - App is in background (always), OR
        // - App is in foreground but chat is not open
        if (!msg.isOutgoing && (!appInForeground || !isChatOpen)) {
          // Increment unread count for incoming messages when chat not open
          _ref.read(unreadCountsProvider.notifier).incrementCount(contactFp);
          engine?.debugLog('EVENT', 'MESSAGE_RECEIVED: Incremented unread count for $contactFp');

          // Show notification for incoming message
          _showMessageNotification(contactFp, msg.plaintext);
        } else {
          engine?.debugLog('EVENT', 'MESSAGE_RECEIVED: Skipped unread increment (outgoing=${msg.isOutgoing}, chatOpen=$isChatOpen)');
        }

        // NOTE: We intentionally do NOT invalidate(contactsProvider) here.
        // Contact tiles don't show message previews - only avatar, name, online status, and unread count.
        // Unread counts are already updated via incrementCount() above.
        // Full contact list rebuilds cause unnecessary UI churn and presence bouncing.

      case MessageSentEvent(messageId: final msgId):
        // Update the pending message status to sent (no full reload needed)
        // The message is already shown via optimistic UI
        print('[DART-HANDLER] MessageSentEvent received, msgId=$msgId');
        final selectedContact = _ref.read(selectedContactProvider);
        if (selectedContact != null) {
          _ref.read(conversationProvider(selectedContact.fingerprint).notifier)
              .markLastPendingSent();
        }
        break;

      case MessageDeliveredEvent(contactFingerprint: final contactFp):
        // Messages delivered to contact - update status without full reload
        _ref.read(conversationProvider(contactFp).notifier).markAllDelivered();
        break;

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

      case ContactRequestReceivedEvent():
        // New contact request received via DHT listener - refresh contact requests
        // Also refresh contacts since reciprocal requests are auto-approved (adds contact)
        // IMPORTANT: Must wait for request fetch to complete (triggers auto-approval)
        // before refreshing contacts, otherwise contacts refresh happens too early
        _ref.invalidate(contactRequestsProvider);
        _ref.read(contactRequestsProvider.future).then((_) {
          // Auto-approval completed, now refresh contacts to show new contact
          _ref.read(contactsProvider.notifier).refresh();
        });
        break;

      case GroupMessageReceivedEvent(groupUuid: final uuid, newCount: final count):
        // New group messages received via DHT listener
        // IMPORTANT: Callback fires immediately without fetching (to avoid DHT thread deadlock)
        // So we must sync messages from DHT here before refreshing the UI
        print('[GROUP-MSG] >>> GroupMessageReceivedEvent: uuid=$uuid count=$count');
        _ref.read(engineProvider).whenData((engine) async {
          print('[GROUP-MSG] Inside whenData - syncing group $uuid');
          // Sync messages from DHT to local DB (runs on worker thread, not DHT callback thread)
          await engine.syncGroupByUuid(uuid);
          print('[GROUP-MSG] Sync complete - invalidating providers');
          // Now refresh the conversation from local DB
          _ref.invalidate(groupConversationProvider(uuid));
          // Force UI rebuild via refresh trigger
          _ref.read(groupConversationRefreshTriggerProvider.notifier).state++;
          // Also refresh groups list to update any preview/badge
          _ref.invalidate(groupsProvider);
          print('[GROUP-MSG] Providers invalidated, trigger incremented');
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
    print('[DART-HANDLER] _scheduleConversationRefresh called');
    _refreshTimer?.cancel();
    _refreshTimer = Timer(const Duration(milliseconds: 300), () {
      final selectedContact = _ref.read(selectedContactProvider);
      print('[DART-HANDLER] Timer fired, selectedContact=${selectedContact?.fingerprint?.substring(0, 16) ?? "null"}');
      if (selectedContact != null) {
        print('[DART-HANDLER] Calling refresh() on conversation');
        // Use refresh() instead of invalidate() to force immediate rebuild
        // invalidate() only marks stale, doesn't trigger rebuild until next read
        _ref.read(conversationProvider(selectedContact.fingerprint).notifier).refresh();
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
        // Fetch messages only from contacts whose outboxes triggered the event.
        // Much faster than checkOfflineMessages() which checks ALL contacts.
        await PlatformHandler.instance.onOutboxUpdated(engine, fingerprints);

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
  }

  /// Resume all polling timers (call when app comes to foreground)
  ///
  /// Restarts periodic polling if DHT is connected.
  /// Note: Immediate presence refresh is handled by C-side resumePresence().
  void resumePolling() {
    final dhtState = _ref.read(dhtConnectionStateProvider);
    if (dhtState == DhtConnectionState.connected) {
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
        nickname: selectedContact.nickname,
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
