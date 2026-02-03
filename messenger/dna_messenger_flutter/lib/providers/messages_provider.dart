// Messages Provider - Chat messages state management
import 'dart:async';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../ffi/dna_engine.dart';
import '../utils/logger.dart';
import 'engine_provider.dart';
import 'contacts_provider.dart';

/// Page size for message loading
const int _pageSize = 50;

/// Conversation provider - keyed by contact fingerprint
final conversationProvider = AsyncNotifierProviderFamily<ConversationNotifier, List<Message>, String>(
  ConversationNotifier.new,
);

/// Pagination state for a conversation
class _PaginationState {
  final int total;
  final int loadedCount;
  final bool isLoadingMore;

  _PaginationState({
    this.total = 0,
    this.loadedCount = 0,
    this.isLoadingMore = false,
  });

  bool get hasMore => loadedCount < total;
}

/// Tracks pagination state per conversation
final _paginationStateProvider = StateProvider.family<_PaginationState, String>(
  (ref, fingerprint) => _PaginationState(),
);

/// Whether more messages can be loaded
final hasMoreMessagesProvider = Provider.family<bool, String>((ref, fingerprint) {
  return ref.watch(_paginationStateProvider(fingerprint)).hasMore;
});

/// Whether currently loading more messages
final isLoadingMoreProvider = Provider.family<bool, String>((ref, fingerprint) {
  return ref.watch(_paginationStateProvider(fingerprint)).isLoadingMore;
});

class ConversationNotifier extends FamilyAsyncNotifier<List<Message>, String> {
  @override
  Future<List<Message>> build(String arg) async {
    // Wait for identity to be ready (prevents "Failed to load" after app switch)
    final identityReady = ref.watch(identityReadyProvider);
    if (!identityReady) {
      // v0.100.87: STALE-WHILE-REVALIDATE - keep showing cached data during engine reload
      // Return previous data if available, empty list only on first load
      return state.valueOrNull ?? [];
    }

    // v0.100.87: Get engine without blocking UI if we already have cached data
    final engineAsync = ref.watch(engineProvider);
    final cachedMessages = state.valueOrNull;

    // If engine is loading but we have cached data, return cached (no spinner)
    if (engineAsync is AsyncLoading && cachedMessages != null && cachedMessages.isNotEmpty) {
      return cachedMessages;
    }

    // Wait for engine (shows spinner only on first load when no cache)
    final engine = await ref.watch(engineProvider.future);

    // Load initial page (newest messages)
    final page = await engine.getConversationPage(arg, _pageSize, 0);
    // Update pagination state
    ref.read(_paginationStateProvider(arg).notifier).state = _PaginationState(
      total: page.total,
      loadedCount: page.messages.length,
    );
    // Reverse to ASC order (oldest first) for UI
    return page.messages.reversed.toList();
  }

  Future<void> refresh() async {
    logPrint('[DART-REFRESH] refresh() called for $arg');
    // v0.100.87: STALE-WHILE-REVALIDATE - don't show loading spinner
    // Keep showing current messages while fetching new ones
    final previousMessages = state.valueOrNull;

    try {
      final engine = await ref.read(engineProvider.future);
      final page = await engine.getConversationPage(arg, _pageSize, 0);
      logPrint('[DART-REFRESH] Got ${page.messages.length} messages');
      // Log last 3 messages with status
      for (var i = 0; i < page.messages.length && i < 3; i++) {
        final m = page.messages[i];
        logPrint('[DART-REFRESH] msg[$i] id=${m.id} status=${m.status} outgoing=${m.isOutgoing}');
      }
      ref.read(_paginationStateProvider(arg).notifier).state = _PaginationState(
        total: page.total,
        loadedCount: page.messages.length,
      );
      state = AsyncValue.data(page.messages.reversed.toList());
    } catch (e, st) {
      // On error, keep previous data if available
      if (previousMessages != null && previousMessages.isNotEmpty) {
        logPrint('[DART-REFRESH] Error but keeping cached data: $e');
        state = AsyncValue.data(previousMessages);
      } else {
        state = AsyncValue.error(e, st);
      }
    }
  }

  /// Load more (older) messages
  Future<void> loadMore() async {
    final paginationNotifier = ref.read(_paginationStateProvider(arg).notifier);
    final pagination = paginationNotifier.state;

    if (!pagination.hasMore || pagination.isLoadingMore) return;

    paginationNotifier.state = _PaginationState(
      total: pagination.total,
      loadedCount: pagination.loadedCount,
      isLoadingMore: true,
    );

    try {
      final engine = await ref.read(engineProvider.future);
      final page = await engine.getConversationPage(
        arg,
        _pageSize,
        pagination.loadedCount,
      );

      // Prepend older messages (reversed to ASC) to the beginning
      state.whenData((messages) {
        final olderMessages = page.messages.reversed.toList();
        state = AsyncValue.data([...olderMessages, ...messages]);
      });

      paginationNotifier.state = _PaginationState(
        total: page.total,
        loadedCount: pagination.loadedCount + page.messages.length,
        isLoadingMore: false,
      );
    } catch (e) {
      paginationNotifier.state = _PaginationState(
        total: pagination.total,
        loadedCount: pagination.loadedCount,
        isLoadingMore: false,
      );
    }
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
    }
    // On success: message shown via optimistic UI
    // Status updated via MessageSentEvent in event_handler.dart

    return result;
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

  /// Mark all sent messages as received (v15: simplified status)
  /// Called when ACK received from recipient
  void markAllReceived() {
    state.whenData((messages) {
      bool changed = false;
      final updated = messages.map((msg) {
        if (msg.isOutgoing && msg.status == MessageStatus.sent) {
          changed = true;
          return Message(
            id: msg.id,
            sender: msg.sender,
            recipient: msg.recipient,
            plaintext: msg.plaintext,
            timestamp: msg.timestamp,
            isOutgoing: msg.isOutgoing,
            status: MessageStatus.received,
            type: msg.type,
          );
        }
        return msg;
      }).toList();

      if (changed) {
        state = AsyncValue.data(updated);
      }
    });
  }

  /// Update last pending outgoing message to sent status
  /// Called when MessageSentEvent fires - the pending message needs status update
  void markLastPendingSent() {
    state.whenData((messages) {
      // Find last outgoing message with pending status
      for (int i = messages.length - 1; i >= 0; i--) {
        final msg = messages[i];
        if (msg.isOutgoing && msg.status == MessageStatus.pending) {
          final updated = List<Message>.from(messages);
          updated[i] = Message(
            id: msg.id,
            sender: msg.sender,
            recipient: msg.recipient,
            plaintext: msg.plaintext,
            timestamp: msg.timestamp,
            isOutgoing: msg.isOutgoing,
            status: MessageStatus.sent,
            type: msg.type,
          );
          state = AsyncValue.data(updated);
          return;
        }
      }
    });
  }

  /// Merge new messages from DB without showing loading state
  /// Used when new message received - fetches from DB and adds to list
  Future<void> mergeLatest() async {
    final currentMessages = state.valueOrNull ?? [];

    try {
      final engine = await ref.read(engineProvider.future);
      final page = await engine.getConversationPage(arg, _pageSize, 0);
      final newMessages = page.messages.reversed.toList();

      // Find messages not in current list (by ID or by content+timestamp for pending)
      final currentIds = currentMessages.map((m) => m.id).toSet();
      final toAdd = <Message>[];

      for (final msg in newMessages) {
        if (!currentIds.contains(msg.id)) {
          // Check if it's not a pending message we already show
          final isDuplicate = currentMessages.any((m) =>
            m.plaintext == msg.plaintext &&
            m.sender == msg.sender &&
            m.recipient == msg.recipient &&
            m.timestamp.difference(msg.timestamp).abs().inSeconds < 5
          );
          if (!isDuplicate) {
            toAdd.add(msg);
          }
        }
      }

      if (toAdd.isNotEmpty) {
        // Merge and sort by timestamp
        final merged = [...currentMessages, ...toAdd];
        merged.sort((a, b) => a.timestamp.compareTo(b.timestamp));
        state = AsyncValue.data(merged);

        // Update pagination state
        ref.read(_paginationStateProvider(arg).notifier).state = _PaginationState(
          total: page.total,
          loadedCount: merged.length,
        );
      }
    } catch (e) {
      // On error, fall back to full refresh
      await refresh();
    }
  }

  /// Delete a message from local database
  /// Returns true on success
  Future<bool> deleteMessage(int messageId) async {
    final engine = ref.read(engineProvider).valueOrNull;
    if (engine == null) return false;

    final success = engine.deleteMessage(messageId);
    if (success) {
      // Remove from UI immediately (optimistic)
      state.whenData((messages) {
        final updated = messages.where((m) => m.id != messageId).toList();
        state = AsyncValue.data(updated);
      });
    }
    return success;
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
