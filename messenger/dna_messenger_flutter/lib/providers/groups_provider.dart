// Groups Provider - Group and invitation state management
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:shared_preferences/shared_preferences.dart';
import '../ffi/dna_engine.dart';
import 'engine_provider.dart';

/// Groups list provider
final groupsProvider = AsyncNotifierProvider<GroupsNotifier, List<Group>>(
  GroupsNotifier.new,
);

class GroupsNotifier extends AsyncNotifier<List<Group>> {
  @override
  Future<List<Group>> build() async {
    final identityLoaded = ref.watch(identityLoadedProvider);
    if (!identityLoaded) {
      return [];
    }

    final engine = await ref.watch(engineProvider.future);
    return engine.getGroups();
  }

  Future<void> refresh() async {
    state = const AsyncValue.loading();
    state = await AsyncValue.guard(() async {
      final engine = await ref.read(engineProvider.future);
      return engine.getGroups();
    });
  }

  /// Create a new group
  Future<String> createGroup(String name, List<String> memberFingerprints) async {
    final engine = await ref.read(engineProvider.future);
    final uuid = await engine.createGroup(name, memberFingerprints);
    await refresh();
    return uuid;
  }

  /// Send message to a group
  Future<void> sendGroupMessage(String groupUuid, String message) async {
    final engine = await ref.read(engineProvider.future);
    await engine.sendGroupMessage(groupUuid, message);
  }

  /// Sync group metadata and GEK from DHT
  /// Use this to recover GEK after app reinstall or database loss
  Future<void> syncGroup(String groupUuid) async {
    final engine = await ref.read(engineProvider.future);
    await engine.syncGroupByUuid(groupUuid);
    await refresh();
  }

  /// Add a member to a group (owner only)
  /// Automatically rotates GEK for forward secrecy
  Future<void> addGroupMember(String groupUuid, String fingerprint) async {
    final engine = await ref.read(engineProvider.future);
    await engine.addGroupMember(groupUuid, fingerprint);
    await refresh();
  }

  /// Remove a member from a group (owner only)
  /// Automatically rotates GEK for forward secrecy
  Future<void> removeGroupMember(String groupUuid, String fingerprint) async {
    final engine = await ref.read(engineProvider.future);
    await engine.removeGroupMember(groupUuid, fingerprint);
    await refresh();
  }
}

/// Invitations list provider
final invitationsProvider = AsyncNotifierProvider<InvitationsNotifier, List<Invitation>>(
  InvitationsNotifier.new,
);

class InvitationsNotifier extends AsyncNotifier<List<Invitation>> {
  @override
  Future<List<Invitation>> build() async {
    final identityLoaded = ref.watch(identityLoadedProvider);
    if (!identityLoaded) {
      return [];
    }

    final engine = await ref.watch(engineProvider.future);
    return engine.getInvitations();
  }

  Future<void> refresh() async {
    state = const AsyncValue.loading();
    state = await AsyncValue.guard(() async {
      final engine = await ref.read(engineProvider.future);
      return engine.getInvitations();
    });
  }

  /// Accept a group invitation
  Future<void> acceptInvitation(String groupUuid) async {
    final engine = await ref.read(engineProvider.future);
    await engine.acceptInvitation(groupUuid);
    await refresh();
    // Also refresh groups list
    ref.invalidate(groupsProvider);
  }

  /// Reject a group invitation
  Future<void> rejectInvitation(String groupUuid) async {
    final engine = await ref.read(engineProvider.future);
    await engine.rejectInvitation(groupUuid);
    await refresh();
  }
}

/// Selected group for chat
final selectedGroupProvider = StateProvider<Group?>((ref) => null);

/// Refresh trigger for group conversations - increment to force rebuild
final groupConversationRefreshTriggerProvider = StateProvider<int>((ref) => 0);

/// Current group conversation provider (for the selected group)
/// Watches refresh trigger to force rebuilds when new messages arrive via listener
final currentGroupConversationProvider = Provider<AsyncValue<List<Message>>>((ref) {
  // Watch the refresh trigger to force rebuilds
  ref.watch(groupConversationRefreshTriggerProvider);

  final group = ref.watch(selectedGroupProvider);
  if (group == null) {
    return const AsyncValue.data([]);
  }
  return ref.watch(groupConversationProvider(group.uuid));
});

/// Group conversation provider - keyed by group UUID
final groupConversationProvider = AsyncNotifierProviderFamily<GroupConversationNotifier, List<Message>, String>(
  GroupConversationNotifier.new,
);

class GroupConversationNotifier extends FamilyAsyncNotifier<List<Message>, String> {
  @override
  Future<List<Message>> build(String arg) async {
    final identityLoaded = ref.watch(identityLoadedProvider);
    if (!identityLoaded) {
      return [];
    }

    final engine = await ref.watch(engineProvider.future);
    final messages = await engine.getGroupConversation(arg);
    // Messages already in ASC order from C layer
    return messages;
  }

  Future<void> refresh() async {
    state = const AsyncValue.loading();
    state = await AsyncValue.guard(() async {
      final engine = await ref.read(engineProvider.future);
      return engine.getGroupConversation(arg);
    });
  }

  /// Add a message to the conversation (for optimistic UI)
  void addMessage(Message message) {
    state.whenData((messages) {
      final updated = List<Message>.from(messages)..add(message);
      state = AsyncValue.data(updated);
    });
  }
}

/// Currently open group UUID (for determining if chat is open)
final openGroupUuidProvider = StateProvider<String?>((ref) => null);

/// Group unread message counts (groupUuid -> count)
/// Similar to unreadCountsProvider for 1-1 chats
final groupUnreadCountsProvider = AsyncNotifierProvider<GroupUnreadCountsNotifier, Map<String, int>>(
  GroupUnreadCountsNotifier.new,
);

class GroupUnreadCountsNotifier extends AsyncNotifier<Map<String, int>> {
  static const _prefsKey = 'group_unread_counts';

  @override
  Future<Map<String, int>> build() async {
    // Load persisted counts from SharedPreferences
    final prefs = await SharedPreferences.getInstance();
    final stored = prefs.getStringList(_prefsKey) ?? [];

    final counts = <String, int>{};
    for (final entry in stored) {
      final parts = entry.split(':');
      if (parts.length == 2) {
        final uuid = parts[0];
        final count = int.tryParse(parts[1]) ?? 0;
        if (count > 0) {
          counts[uuid] = count;
        }
      }
    }
    return counts;
  }

  /// Persist counts to SharedPreferences
  Future<void> _persist(Map<String, int> counts) async {
    final prefs = await SharedPreferences.getInstance();
    final entries = counts.entries
        .where((e) => e.value > 0)
        .map((e) => '${e.key}:${e.value}')
        .toList();
    await prefs.setStringList(_prefsKey, entries);
  }

  /// Increment unread count for a group (called when new messages received)
  void incrementCount(String groupUuid, [int amount = 1]) {
    final currentState = state;
    if (currentState is AsyncData<Map<String, int>>) {
      final counts = currentState.value;
      final updated = Map<String, int>.from(counts);
      updated[groupUuid] = (updated[groupUuid] ?? 0) + amount;
      state = AsyncValue.data(updated);
      _persist(updated);
    } else {
      // State not ready - initialize with this count
      final counts = {groupUuid: amount};
      state = AsyncValue.data(counts);
      _persist(counts);
    }
  }

  /// Set count for a group to a specific value
  void setCount(String groupUuid, int count) {
    final currentState = state;
    if (currentState is AsyncData<Map<String, int>>) {
      final counts = currentState.value;
      final updated = Map<String, int>.from(counts);
      if (count > 0) {
        updated[groupUuid] = count;
      } else {
        updated.remove(groupUuid);
      }
      state = AsyncValue.data(updated);
      _persist(updated);
    } else if (count > 0) {
      final counts = {groupUuid: count};
      state = AsyncValue.data(counts);
      _persist(counts);
    }
  }

  /// Clear count for a group (called when group chat is opened)
  void clearCount(String groupUuid) {
    state.whenData((counts) {
      if (counts.containsKey(groupUuid)) {
        final updated = Map<String, int>.from(counts);
        updated.remove(groupUuid);
        state = AsyncValue.data(updated);
        _persist(updated);
      }
    });
  }
}

/// Get total unread count across all groups
final totalGroupUnreadCountProvider = Provider<int>((ref) {
  final countsAsync = ref.watch(groupUnreadCountsProvider);
  return countsAsync.maybeWhen(
    data: (counts) => counts.values.fold(0, (sum, count) => sum + count),
    orElse: () => 0,
  );
});
