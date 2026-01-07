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
  // Throttle presence lookups - don't re-lookup if recent
  static DateTime? _lastPresenceLookup;
  static const _presenceLookupThrottle = Duration(minutes: 5);

  @override
  Future<List<Contact>> build() async {
    // Only fetch if identity is loaded
    final identityLoaded = ref.watch(identityLoadedProvider);
    if (!identityLoaded) {
      return [];
    }

    final engine = await ref.watch(engineProvider.future);
    final contacts = await engine.getContacts();

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
      ref.read(contactProfileCacheProvider.notifier).prefetchProfiles(fingerprints);
    }

    // Start presence lookups in background (non-blocking)
    _updatePresenceInBackground(engine, sortedContacts);

    return sortedContacts;
  }

  /// Update presence for contacts in background, updating state as data arrives
  /// Throttled to avoid excessive DHT lookups on frequent provider rebuilds
  Future<void> _updatePresenceInBackground(
    DnaEngine engine,
    List<Contact> contacts, {
    bool forceRefresh = false,
  }) async {
    if (contacts.isEmpty) return;

    // Throttle: skip if we did a lookup recently (unless forced)
    final now = DateTime.now();
    if (!forceRefresh && _lastPresenceLookup != null) {
      final elapsed = now.difference(_lastPresenceLookup!);
      if (elapsed < _presenceLookupThrottle) {
        return; // Skip - too soon since last lookup
      }
    }
    _lastPresenceLookup = now;

    // Query presence for all contacts in parallel
    for (final contact in contacts) {
      // Fire and forget - each lookup updates state independently
      _lookupSinglePresence(engine, contact.fingerprint).then((lastSeen) {
        if (lastSeen != null && lastSeen.millisecondsSinceEpoch > 0) {
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
    final selectedContact = ref.read(selectedContactProvider);

    for (final entry in _pendingPresenceUpdates.entries) {
      final fingerprint = entry.key;
      final lastSeen = entry.value;

      final index = updated.indexWhere((c) => c.fingerprint == fingerprint);
      if (index != -1) {
        final contact = updated[index];
        final updatedContact = Contact(
          fingerprint: contact.fingerprint,
          displayName: contact.displayName,
          isOnline: contact.isOnline,
          lastSeen: lastSeen,
        );
        updated[index] = updatedContact;

        // Also update selectedContactProvider if this is the currently selected contact
        if (selectedContact != null && selectedContact.fingerprint == fingerprint) {
          ref.read(selectedContactProvider.notifier).state = updatedContact;
        }
      }
    }

    _pendingPresenceUpdates.clear();

    // DON'T re-sort here - keep stable order to prevent bouncing
    // Sort is only done on initial load and when online status changes
    state = AsyncValue.data(updated);
  }

  /// Refresh contacts without showing loading state (seamless update)
  /// Keeps existing data visible while fetching new data to prevent "bouncing"
  Future<void> refresh() async {
    try {
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
      // Force refresh on manual refresh to bypass throttle
      _updatePresenceInBackground(engine, sortedContacts, forceRefresh: true);

      // Sync selectedContactProvider with refreshed data (prevents showing stale lastSeen)
      final selectedContact = ref.read(selectedContactProvider);
      if (selectedContact != null) {
        final refreshedContact = sortedContacts.firstWhere(
          (c) => c.fingerprint == selectedContact.fingerprint,
          orElse: () => selectedContact,
        );
        if (refreshedContact.fingerprint == selectedContact.fingerprint) {
          ref.read(selectedContactProvider.notifier).state = refreshedContact;
        }
      }

      // Atomic swap - only update state once we have new data
      state = AsyncValue.data(sortedContacts);
    } catch (e, st) {
      // Only set error if we don't have existing data
      if (state.valueOrNull == null) {
        state = AsyncValue.error(e, st);
      }
      // Otherwise keep showing existing data (silent failure)
    }
  }

  Future<void> addContact(String identifier) async {
    final engine = await ref.read(engineProvider.future);
    await engine.addContact(identifier);
    await refresh();

    // Start DHT listener for the new contact's outbox (for push notifications)
    // If identifier is already a fingerprint (128 hex chars), use it directly
    // Otherwise fall back to listenAllContacts() since C resolves name->fingerprint
    final isFingerprint = identifier.length == 128 &&
        RegExp(r'^[0-9a-fA-F]+$').hasMatch(identifier);
    if (isFingerprint) {
      engine.listenOutbox(identifier);
    } else {
      engine.listenAllContacts();
    }
  }

  Future<void> removeContact(String fingerprint) async {
    final engine = await ref.read(engineProvider.future);
    await engine.removeContact(fingerprint);
    await refresh();
  }

  void updateContactStatus(String fingerprint, bool isOnline) {
    if (fingerprint.isEmpty) {
      return;
    }

    state.whenData((contacts) {
      final index = contacts.indexWhere((c) => c.fingerprint == fingerprint);
      if (index != -1) {
        final contact = contacts[index];

        // Skip update if status hasn't actually changed
        if (contact.isOnline == isOnline) {
          return;
        }

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
    final currentState = state;
    if (currentState is AsyncData<Map<String, int>>) {
      final counts = currentState.value;
      final updated = Map<String, int>.from(counts);
      updated[fingerprint] = (updated[fingerprint] ?? 0) + 1;
      state = AsyncValue.data(updated);
    } else {
      // State not ready (loading/error) - initialize with this count
      // This ensures we don't lose the increment during startup race
      state = AsyncValue.data({fingerprint: 1});
    }
  }

  /// Set count for a contact to a specific value (used when syncing from DB)
  void setCount(String fingerprint, int count) {
    final currentState = state;
    if (currentState is AsyncData<Map<String, int>>) {
      final counts = currentState.value;
      final currentCount = counts[fingerprint] ?? 0;
      // Only update if DB count is different (avoid unnecessary rebuilds)
      if (currentCount != count) {
        final updated = Map<String, int>.from(counts);
        if (count > 0) {
          updated[fingerprint] = count;
        } else {
          updated.remove(fingerprint);
        }
        state = AsyncValue.data(updated);
      }
    } else {
      // State not ready - initialize with this count
      if (count > 0) {
        state = AsyncValue.data({fingerprint: count});
      }
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
