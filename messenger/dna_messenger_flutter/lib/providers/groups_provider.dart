// Groups Provider - Group and invitation state management
import 'package:flutter_riverpod/flutter_riverpod.dart';
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
