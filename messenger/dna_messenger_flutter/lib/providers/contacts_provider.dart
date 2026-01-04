// Contacts Provider - Contact list state management
import 'dart:async';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../ffi/dna_engine.dart';
import 'engine_provider.dart';
import 'contact_profile_cache_provider.dart';

/// Contact list provider
final contactsProvider = AsyncNotifierProvider<ContactsNotifier, List<Contact>>(
  ContactsNotifier.new,
);

class ContactsNotifier extends AsyncNotifier<List<Contact>> {
  // Debounce timer for batching presence updates
  Timer? _presenceDebounceTimer;
  // Pending presence updates to apply
  final Map<String, DateTime> _pendingPresenceUpdates = {};

  @override
  Future<List<Contact>> build() async {
    // Only fetch if identity is loaded
    final identityLoaded = ref.watch(identityLoadedProvider);
    if (!identityLoaded) {
      return [];
    }

    final engine = await ref.watch(engineProvider.future);
    engine.debugLog('CONTACTS', 'build() - fetching contacts');
    final contacts = await engine.getContacts();
    engine.debugLog('CONTACTS', 'Got ${contacts.length} contacts');

    // Debug: log initial online status from C engine
    for (final c in contacts) {
      print('[Contacts] Loaded: ${c.fingerprint.substring(0, 16)}... isOnline=${c.isOnline} lastSeen=${c.lastSeen}');
    }

    // Stable sort: online first, then by name (won't change on presence updates)
    final sortedContacts = List<Contact>.from(contacts);
    sortedContacts.sort((a, b) {
      if (a.isOnline != b.isOnline) {
        return a.isOnline ? -1 : 1;
      }
      return a.displayName.compareTo(b.displayName);
    });

    // Prefetch contact profiles in background (for avatars, display names)
    if (sortedContacts.isNotEmpty) {
      final fingerprints = sortedContacts.map((c) => c.fingerprint).toList();
      engine.debugLog('CONTACTS', 'Prefetching ${fingerprints.length} profiles');
      ref.read(contactProfileCacheProvider.notifier).prefetchProfiles(fingerprints);
    }

    // Start presence lookups in background (non-blocking)
    _updatePresenceInBackground(engine, sortedContacts);

    return sortedContacts;
  }

  /// Update presence for contacts in background, updating state as data arrives
  Future<void> _updatePresenceInBackground(
    DnaEngine engine,
    List<Contact> contacts,
  ) async {
    if (contacts.isEmpty) return;

    // Track which contacts have been updated
    final presenceMap = <String, DateTime>{};

    // Query presence for all contacts in parallel
    for (final contact in contacts) {
      // Fire and forget - each lookup updates state independently
      _lookupSinglePresence(engine, contact.fingerprint).then((lastSeen) {
        if (lastSeen != null && lastSeen.millisecondsSinceEpoch > 0) {
          presenceMap[contact.fingerprint] = lastSeen;
          _updateContactPresence(contact.fingerprint, lastSeen);
        }
      });
    }
  }

  /// Lookup presence for a single contact with timeout
  Future<DateTime?> _lookupSinglePresence(DnaEngine engine, String fingerprint) async {
    try {
      return await engine
          .lookupPresence(fingerprint)
          .timeout(const Duration(seconds: 5));
    } catch (_) {
      return null;
    }
  }

  /// Queue a presence update and debounce the re-sort
  void _updateContactPresence(String fingerprint, DateTime lastSeen) {
    // Collect the update
    _pendingPresenceUpdates[fingerprint] = lastSeen;

    // Cancel existing timer and start a new one
    _presenceDebounceTimer?.cancel();
    _presenceDebounceTimer = Timer(const Duration(milliseconds: 300), () {
      _applyPendingPresenceUpdates();
    });
  }

  /// Apply all pending presence updates WITHOUT re-sorting
  /// This prevents the "bouncing" effect when presence data arrives
  void _applyPendingPresenceUpdates() {
    if (_pendingPresenceUpdates.isEmpty) return;

    final currentState = state.valueOrNull;
    if (currentState == null) {
      _pendingPresenceUpdates.clear();
      return;
    }

    // Check if any presence data actually changed
    bool hasChanges = false;
    for (final entry in _pendingPresenceUpdates.entries) {
      final fingerprint = entry.key;
      final lastSeen = entry.value;
      final contact = currentState.firstWhere(
        (c) => c.fingerprint == fingerprint,
        orElse: () => Contact(fingerprint: '', displayName: '', isOnline: false, lastSeen: DateTime.fromMillisecondsSinceEpoch(0)),
      );
      // Only count as change if lastSeen differs by more than 1 minute
      // This prevents unnecessary updates for small time differences
      if (contact.fingerprint.isNotEmpty &&
          (contact.lastSeen.millisecondsSinceEpoch == 0 ||
           (lastSeen.difference(contact.lastSeen).inMinutes.abs() > 1))) {
        hasChanges = true;
        break;
      }
    }

    if (!hasChanges) {
      _pendingPresenceUpdates.clear();
      return;
    }

    // Apply updates without changing order (preserve current sort)
    final updated = List<Contact>.from(currentState);
    for (final entry in _pendingPresenceUpdates.entries) {
      final fingerprint = entry.key;
      final lastSeen = entry.value;

      final index = updated.indexWhere((c) => c.fingerprint == fingerprint);
      if (index != -1) {
        final contact = updated[index];
        updated[index] = Contact(
          fingerprint: contact.fingerprint,
          displayName: contact.displayName,
          isOnline: contact.isOnline,
          lastSeen: lastSeen,
        );
      }
    }

    _pendingPresenceUpdates.clear();

    // DON'T re-sort here - keep stable order to prevent bouncing
    // Sort is only done on initial load and when online status changes
    state = AsyncValue.data(updated);
  }

  Future<void> refresh() async {
    state = const AsyncValue.loading();
    state = await AsyncValue.guard(() async {
      final engine = await ref.read(engineProvider.future);
      final contacts = await engine.getContacts();

      // Stable sort: online first, then by name
      final sortedContacts = List<Contact>.from(contacts);
      sortedContacts.sort((a, b) {
        if (a.isOnline != b.isOnline) {
          return a.isOnline ? -1 : 1;
        }
        return a.displayName.compareTo(b.displayName);
      });

      // Prefetch contact profiles in background
      if (sortedContacts.isNotEmpty) {
        final fingerprints = sortedContacts.map((c) => c.fingerprint).toList();
        ref.read(contactProfileCacheProvider.notifier).prefetchProfiles(fingerprints);
      }

      // Start presence lookups in background (non-blocking)
      _updatePresenceInBackground(engine, sortedContacts);

      return sortedContacts;
    });
  }

  Future<void> addContact(String identifier) async {
    final engine = await ref.read(engineProvider.future);
    await engine.addContact(identifier);
    await refresh();

    // Start DHT listener for the new contact's outbox (for push notifications)
    // This is needed because listenAllContacts() was called when DHT connected,
    // but this new contact wasn't in the list yet
    final listenerCount = engine.listenAllContacts();
    engine.debugLog('CONTACTS', 'Started $listenerCount DHT listeners after addContact');
  }

  Future<void> removeContact(String fingerprint) async {
    final engine = await ref.read(engineProvider.future);
    await engine.removeContact(fingerprint);
    await refresh();
  }

  void updateContactStatus(String fingerprint, bool isOnline) {
    final fpShort = fingerprint.length >= 16 ? fingerprint.substring(0, 16) : fingerprint;
    print('[Contacts] updateContactStatus: $fpShort... -> ${isOnline ? "ONLINE" : "OFFLINE"}');

    if (fingerprint.isEmpty) {
      print('[Contacts] ERROR: Empty fingerprint, ignoring');
      return;
    }

    state.whenData((contacts) {
      final index = contacts.indexWhere((c) => c.fingerprint == fingerprint);
      if (index != -1) {
        final contact = contacts[index];

        // Skip update if status hasn't actually changed
        if (contact.isOnline == isOnline) {
          print('[Contacts] Status unchanged, skipping update');
          return;
        }
        print('[Contacts] Status CHANGED: ${contact.isOnline} -> $isOnline');

        final updated = List<Contact>.from(contacts);
        updated[index] = Contact(
          fingerprint: contact.fingerprint,
          displayName: contact.displayName,
          isOnline: isOnline,
          lastSeen: isOnline ? DateTime.now() : contact.lastSeen,
        );

        // Only re-sort when online status changes (stable sort: online first, then by name)
        updated.sort((a, b) {
          if (a.isOnline != b.isOnline) {
            return a.isOnline ? -1 : 1;
          }
          return a.displayName.compareTo(b.displayName);
        });
        state = AsyncValue.data(updated);
      }
    });
  }
}

/// Currently selected contact for chat
final selectedContactProvider = StateProvider<Contact?>((ref) => null);

/// Unread message counts per contact (fingerprint -> count)
final unreadCountsProvider = AsyncNotifierProvider<UnreadCountsNotifier, Map<String, int>>(
  UnreadCountsNotifier.new,
);

class UnreadCountsNotifier extends AsyncNotifier<Map<String, int>> {
  @override
  Future<Map<String, int>> build() async {
    // Only fetch if identity is loaded
    final identityLoaded = ref.watch(identityLoadedProvider);
    if (!identityLoaded) {
      return {};
    }

    final engine = await ref.watch(engineProvider.future);
    // Use ref.read instead of ref.watch to prevent automatic rebuilds
    // when contacts change. We manage unread counts via incrementCount/clearCount.
    final contacts = await ref.read(contactsProvider.future);

    final counts = <String, int>{};
    for (final contact in contacts) {
      final count = engine.getUnreadCount(contact.fingerprint);
      if (count > 0) {
        counts[contact.fingerprint] = count;
      }
    }
    return counts;
  }

  Future<void> refresh() async {
    state = const AsyncValue.loading();
    state = await AsyncValue.guard(() async {
      final engine = await ref.read(engineProvider.future);
      final contacts = await ref.read(contactsProvider.future);

      final counts = <String, int>{};
      for (final contact in contacts) {
        final count = engine.getUnreadCount(contact.fingerprint);
        if (count > 0) {
          counts[contact.fingerprint] = count;
        }
      }
      return counts;
    });
  }

  /// Update count for a single contact (used when message received)
  void incrementCount(String fingerprint) {
    print('[UnreadCounts] incrementCount called for ${fingerprint.substring(0, 16)}...');
    print('[UnreadCounts] Current state: $state');

    final currentState = state;
    if (currentState is AsyncData<Map<String, int>>) {
      final counts = currentState.value;
      final updated = Map<String, int>.from(counts);
      updated[fingerprint] = (updated[fingerprint] ?? 0) + 1;
      state = AsyncValue.data(updated);
      print('[UnreadCounts] Updated count to ${updated[fingerprint]}');
    } else {
      // State not ready (loading/error) - initialize with this count
      // This ensures we don't lose the increment during startup race
      state = AsyncValue.data({fingerprint: 1});
      print('[UnreadCounts] State was not ready, initialized with count=1');
    }
  }

  /// Clear count for a contact (used when conversation opened)
  void clearCount(String fingerprint) {
    state.whenData((counts) {
      if (counts.containsKey(fingerprint)) {
        final updated = Map<String, int>.from(counts);
        updated.remove(fingerprint);
        state = AsyncValue.data(updated);
      }
    });
  }
}

/// Get total unread count across all contacts
final totalUnreadCountProvider = Provider<int>((ref) {
  final countsAsync = ref.watch(unreadCountsProvider);
  return countsAsync.maybeWhen(
    data: (counts) => counts.values.fold(0, (sum, count) => sum + count),
    orElse: () => 0,
  );
});
