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
    final contacts = await engine.getContacts();

    // Lookup presence from DHT for each contact (in parallel, with timeout)
    final updatedContacts = await _updateContactsPresence(engine, contacts);

    // Sort: by last seen (most recent first), then by name
    updatedContacts.sort((a, b) {
      // Compare by lastSeen (more recent first)
      final lastSeenCompare = b.lastSeen.compareTo(a.lastSeen);
      if (lastSeenCompare != 0) {
        return lastSeenCompare;
      }
      return a.displayName.compareTo(b.displayName);
    });

    // Prefetch contact profiles in background (for avatars, display names)
    if (updatedContacts.isNotEmpty) {
      final fingerprints = updatedContacts.map((c) => c.fingerprint).toList();
      ref.read(contactProfileCacheProvider.notifier).prefetchProfiles(fingerprints);
    }

    return updatedContacts;
  }

  /// Update contacts with presence from DHT
  Future<List<Contact>> _updateContactsPresence(
    DnaEngine engine,
    List<Contact> contacts,
  ) async {
    final updated = <Contact>[];

    // Query presence for all contacts in parallel with timeout
    final futures = contacts.map((contact) async {
      try {
        final lastSeen = await engine
            .lookupPresence(contact.fingerprint)
            .timeout(const Duration(seconds: 5));

        // Only use DHT value if it's not epoch (i.e., presence was found)
        if (lastSeen.millisecondsSinceEpoch > 0) {
          return Contact(
            fingerprint: contact.fingerprint,
            displayName: contact.displayName,
            isOnline: contact.isOnline,
            lastSeen: lastSeen,
          );
        }
      } catch (e) {
        // Timeout or error - use original contact
      }
      return contact;
    }).toList();

    final results = await Future.wait(futures);
    updated.addAll(results);

    return updated;
  }

  Future<void> refresh() async {
    state = const AsyncValue.loading();
    state = await AsyncValue.guard(() async {
      final engine = await ref.read(engineProvider.future);
      final contacts = await engine.getContacts();

      // Lookup presence from DHT for each contact
      final updatedContacts = await _updateContactsPresence(engine, contacts);

      // Sort: by last seen (most recent first), then by name
      updatedContacts.sort((a, b) {
        final lastSeenCompare = b.lastSeen.compareTo(a.lastSeen);
        if (lastSeenCompare != 0) {
          return lastSeenCompare;
        }
        return a.displayName.compareTo(b.displayName);
      });

      // Prefetch contact profiles in background
      if (updatedContacts.isNotEmpty) {
        final fingerprints = updatedContacts.map((c) => c.fingerprint).toList();
        ref.read(contactProfileCacheProvider.notifier).prefetchProfiles(fingerprints);
      }

      return updatedContacts;
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
