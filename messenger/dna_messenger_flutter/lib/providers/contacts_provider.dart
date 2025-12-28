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

    // Sort by name initially (presence will update sort order later)
    final sortedContacts = List<Contact>.from(contacts);
    sortedContacts.sort((a, b) => a.displayName.compareTo(b.displayName));

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

  /// Update a single contact's presence and re-sort the list
  void _updateContactPresence(String fingerprint, DateTime lastSeen) {
    final currentState = state.valueOrNull;
    if (currentState == null) return;

    final index = currentState.indexWhere((c) => c.fingerprint == fingerprint);
    if (index == -1) return;

    final contact = currentState[index];
    final updated = List<Contact>.from(currentState);
    updated[index] = Contact(
      fingerprint: contact.fingerprint,
      displayName: contact.displayName,
      isOnline: contact.isOnline,
      lastSeen: lastSeen,
    );

    // Re-sort: by last seen (most recent first), then by name
    updated.sort((a, b) {
      final lastSeenCompare = b.lastSeen.compareTo(a.lastSeen);
      if (lastSeenCompare != 0) {
        return lastSeenCompare;
      }
      return a.displayName.compareTo(b.displayName);
    });

    state = AsyncValue.data(updated);
  }

  Future<void> refresh() async {
    state = const AsyncValue.loading();
    state = await AsyncValue.guard(() async {
      final engine = await ref.read(engineProvider.future);
      final contacts = await engine.getContacts();

      // Sort by name initially
      final sortedContacts = List<Contact>.from(contacts);
      sortedContacts.sort((a, b) => a.displayName.compareTo(b.displayName));

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
  }

  Future<void> removeContact(String fingerprint) async {
    final engine = await ref.read(engineProvider.future);
    await engine.removeContact(fingerprint);
    await refresh();
  }

  void updateContactStatus(String fingerprint, bool isOnline) {
    state.whenData((contacts) {
      final index = contacts.indexWhere((c) => c.fingerprint == fingerprint);
      if (index != -1) {
        final updated = List<Contact>.from(contacts);
        final contact = updated[index];
        updated[index] = Contact(
          fingerprint: contact.fingerprint,
          displayName: contact.displayName,
          isOnline: isOnline,
          lastSeen: isOnline ? DateTime.now() : contact.lastSeen,
        );
        // Re-sort
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
    final contacts = await ref.watch(contactsProvider.future);

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
    state.whenData((counts) {
      final updated = Map<String, int>.from(counts);
      updated[fingerprint] = (updated[fingerprint] ?? 0) + 1;
      state = AsyncValue.data(updated);
    });
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
