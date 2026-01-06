// Contact Requests Provider - ICQ-style contact request state management
import 'dart:async';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../ffi/dna_engine.dart';
import 'engine_provider.dart';
import 'contacts_provider.dart';

/// Contact requests list provider
final contactRequestsProvider =
    AsyncNotifierProvider<ContactRequestsNotifier, List<ContactRequest>>(
  ContactRequestsNotifier.new,
);

class ContactRequestsNotifier extends AsyncNotifier<List<ContactRequest>> {
  @override
  Future<List<ContactRequest>> build() async {
    final identityLoaded = ref.watch(identityLoadedProvider);
    if (!identityLoaded) {
      return [];
    }

    final engine = await ref.watch(engineProvider.future);
    final requests = await engine.getContactRequests();

    // NOTE: Do NOT invalidate contactsProvider here - causes cascade rebuild every 60s
    // Contacts are refreshed when user approves/denies requests via approve()/deny()

    // Sort by requested_at (most recent first)
    requests.sort((a, b) => b.requestedAt.compareTo(a.requestedAt));

    return requests;
  }

  Future<void> refresh() async {
    state = const AsyncValue.loading();
    state = await AsyncValue.guard(() async {
      final engine = await ref.read(engineProvider.future);
      final requests = await engine.getContactRequests();
      requests.sort((a, b) => b.requestedAt.compareTo(a.requestedAt));
      return requests;
    });
  }

  /// Send a contact request to another user
  Future<void> sendRequest(String fingerprint, String? message) async {
    final engine = await ref.read(engineProvider.future);
    await engine.sendContactRequest(fingerprint, message);
  }

  /// Approve a contact request (makes mutual contact)
  Future<void> approve(String fingerprint) async {
    final engine = await ref.read(engineProvider.future);
    await engine.approveContactRequest(fingerprint);
    await refresh();

    // Start DHT listener for the new contact's outbox (for push notifications)
    // This is needed because listenAllContacts() was called when DHT connected,
    // but this new contact wasn't in the list yet
    engine.listenAllContacts();
  }

  /// Deny a contact request (can retry later)
  Future<void> deny(String fingerprint) async {
    final engine = await ref.read(engineProvider.future);
    await engine.denyContactRequest(fingerprint);
    await refresh();
  }

  /// Block a user permanently
  Future<void> block(String fingerprint, String? reason) async {
    final engine = await ref.read(engineProvider.future);
    await engine.blockUser(fingerprint, reason);
    await refresh();
  }
}

/// Pending contact request count provider (for badge display)
final pendingRequestCountProvider = Provider<int>((ref) {
  final requests = ref.watch(contactRequestsProvider);
  return requests.when(
    data: (list) => list.where((r) => r.status == ContactRequestStatus.pending).length,
    loading: () => 0,
    error: (_, __) => 0,
  );
});

/// Blocked users list provider
final blockedUsersProvider =
    AsyncNotifierProvider<BlockedUsersNotifier, List<BlockedUser>>(
  BlockedUsersNotifier.new,
);

class BlockedUsersNotifier extends AsyncNotifier<List<BlockedUser>> {
  @override
  Future<List<BlockedUser>> build() async {
    final identityLoaded = ref.watch(identityLoadedProvider);
    if (!identityLoaded) {
      return [];
    }

    final engine = await ref.watch(engineProvider.future);
    final blocked = await engine.getBlockedUsers();

    // Sort by blocked_at (most recent first)
    blocked.sort((a, b) => b.blockedAt.compareTo(a.blockedAt));

    return blocked;
  }

  Future<void> refresh() async {
    state = const AsyncValue.loading();
    state = await AsyncValue.guard(() async {
      final engine = await ref.read(engineProvider.future);
      final blocked = await engine.getBlockedUsers();
      blocked.sort((a, b) => b.blockedAt.compareTo(a.blockedAt));
      return blocked;
    });
  }

  /// Unblock a user
  Future<void> unblock(String fingerprint) async {
    final engine = await ref.read(engineProvider.future);
    await engine.unblockUser(fingerprint);
    await refresh();
  }

  /// Block a user
  Future<void> block(String fingerprint, String? reason) async {
    final engine = await ref.read(engineProvider.future);
    await engine.blockUser(fingerprint, reason);
    await refresh();
  }
}

/// Check if a specific user is blocked
final isUserBlockedProvider = Provider.family<bool, String>((ref, fingerprint) {
  final blocked = ref.watch(blockedUsersProvider);
  return blocked.when(
    data: (list) => list.any((b) => b.fingerprint == fingerprint),
    loading: () => false,
    error: (_, __) => false,
  );
});
