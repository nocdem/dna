// Channel Provider - RSS-like channel system state management
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../models/channel.dart';
import 'engine_provider.dart';

// =============================================================================
// CHANNEL SELECTION
// =============================================================================

/// Currently selected channel UUID for detail view
final selectedChannelUuidProvider = StateProvider<String?>((ref) => null);

// =============================================================================
// CHANNEL SUBSCRIPTIONS
// =============================================================================

/// Channel subscriptions provider
final channelSubscriptionsProvider =
    AsyncNotifierProvider<ChannelSubscriptionsNotifier, List<ChannelSubscription>>(
  ChannelSubscriptionsNotifier.new,
);

class ChannelSubscriptionsNotifier extends AsyncNotifier<List<ChannelSubscription>> {
  @override
  Future<List<ChannelSubscription>> build() async {
    final identityLoaded = ref.watch(identityLoadedProvider);
    if (!identityLoaded) {
      // Preserve previous data during engine lifecycle transitions
      return state.valueOrNull ?? [];
    }

    final engine = await ref.watch(engineProvider.future);
    return engine.channelGetSubscriptions();
  }

  Future<void> refresh() async {
    state = await AsyncValue.guard(() async {
      final engine = await ref.read(engineProvider.future);
      return engine.channelGetSubscriptions();
    });
  }

  /// Subscribe to a channel
  Future<bool> subscribe(String channelUuid) async {
    final engine = await ref.read(engineProvider.future);
    final result = engine.channelSubscribe(channelUuid);
    if (result == 0) {
      await refresh();
    }
    return result == 0;
  }

  /// Unsubscribe from a channel
  Future<bool> unsubscribe(String channelUuid) async {
    final engine = await ref.read(engineProvider.future);
    final result = engine.channelUnsubscribe(channelUuid);
    if (result == 0) {
      await refresh();
    }
    return result == 0;
  }

  /// Toggle subscription state
  Future<bool> toggleSubscription(String channelUuid) async {
    final engine = await ref.read(engineProvider.future);
    final isSubscribed = engine.channelIsSubscribed(channelUuid);
    if (isSubscribed) {
      return unsubscribe(channelUuid);
    } else {
      return subscribe(channelUuid);
    }
  }

  /// Sync subscriptions to DHT (for multi-device)
  Future<void> syncToDht() async {
    final engine = await ref.read(engineProvider.future);
    await engine.channelSyncSubsToDht();
  }

  /// Sync subscriptions from DHT (for multi-device)
  Future<void> syncFromDht() async {
    final engine = await ref.read(engineProvider.future);
    await engine.channelSyncSubsFromDht();
    await refresh();
  }
}

/// Check if subscribed to a specific channel (sync, returns immediately)
final isChannelSubscribedProvider = Provider.family<bool, String>((ref, channelUuid) {
  final subscriptions = ref.watch(channelSubscriptionsProvider);
  return subscriptions.when(
    data: (subs) => subs.any((s) => s.channelUuid == channelUuid),
    loading: () => false,
    error: (e, s) => false,
  );
});

// =============================================================================
// SUBSCRIBED CHANNELS LIST
// =============================================================================

/// Subscribed channels provider - fetches full channel info for subscribed UUIDs
final channelListProvider =
    AsyncNotifierProvider<ChannelListNotifier, List<Channel>>(
  ChannelListNotifier.new,
);

class ChannelListNotifier extends AsyncNotifier<List<Channel>> {
  @override
  Future<List<Channel>> build() async {
    // Watch subscriptions to rebuild when they change
    final subscriptionsAsync = ref.watch(channelSubscriptionsProvider);

    return subscriptionsAsync.when(
      data: (subscriptions) async {
        if (subscriptions.isEmpty) {
          return [];
        }

        final engine = await ref.read(engineProvider.future);
        final uuids = subscriptions.map((s) => s.channelUuid).toList();

        try {
          return await engine.channelGetBatch(uuids);
        } catch (e) {
          // Batch failed - return cached state if available
          return state.valueOrNull ?? [];
        }
      },
      loading: () async => state.valueOrNull ?? [],
      error: (e, s) async => state.valueOrNull ?? [],
    );
  }

  Future<void> refresh() async {
    ref.invalidate(channelSubscriptionsProvider);
    state = await AsyncValue.guard(() => build());
  }

  /// Create a new channel
  Future<Channel> createChannel(
    String name,
    String description, {
    bool isPublic = true,
  }) async {
    final engine = await ref.read(engineProvider.future);
    final channel = await engine.channelCreate(name, description, isPublic: isPublic);
    await refresh();
    return channel;
  }

  /// Delete a channel (soft delete - creator only)
  Future<void> deleteChannel(String uuid) async {
    final engine = await ref.read(engineProvider.future);
    await engine.channelDelete(uuid);
    await refresh();
  }
}

// =============================================================================
// CHANNEL POSTS (family by channel UUID)
// =============================================================================

/// Posts for a specific channel (family by UUID)
final channelPostsProvider =
    AsyncNotifierProviderFamily<ChannelPostsNotifier, List<ChannelPost>, String>(
  ChannelPostsNotifier.new,
);

class ChannelPostsNotifier extends FamilyAsyncNotifier<List<ChannelPost>, String> {
  int _daysBack = 3;

  @override
  Future<List<ChannelPost>> build(String arg) async {
    _daysBack = 3; // Reset on rebuild
    final identityLoaded = ref.watch(identityLoadedProvider);
    if (!identityLoaded) {
      // Preserve previous data during engine lifecycle transitions
      return state.valueOrNull ?? [];
    }

    final engine = await ref.watch(engineProvider.future);
    return engine.channelGetPosts(arg, daysBack: _daysBack);
  }

  Future<void> refresh() async {
    state = await AsyncValue.guard(() async {
      final engine = await ref.read(engineProvider.future);
      return engine.channelGetPosts(arg, daysBack: _daysBack);
    });
  }

  /// Load more days of posts
  Future<void> loadMore() async {
    _daysBack += 3;
    if (_daysBack > 30) _daysBack = 30;
    state = await AsyncValue.guard(() async {
      final engine = await ref.read(engineProvider.future);
      return engine.channelGetPosts(arg, daysBack: _daysBack);
    });
  }

  /// Whether more days can be loaded
  bool get canLoadMore => _daysBack < 30;

  /// Add a post to this channel
  Future<ChannelPost> addPost(String body) async {
    final engine = await ref.read(engineProvider.future);
    final post = await engine.channelPost(arg, body);
    await refresh();
    return post;
  }
}

// =============================================================================
// SELECTED CHANNEL DETAIL
// =============================================================================

/// Selected channel detail provider
final selectedChannelProvider =
    AsyncNotifierProvider<SelectedChannelNotifier, Channel?>(
  SelectedChannelNotifier.new,
);

class SelectedChannelNotifier extends AsyncNotifier<Channel?> {
  @override
  Future<Channel?> build() async {
    final uuid = ref.watch(selectedChannelUuidProvider);
    if (uuid == null) {
      return null;
    }

    final identityLoaded = ref.watch(identityLoadedProvider);
    if (!identityLoaded) {
      // Preserve previous data during engine lifecycle transitions
      return state.valueOrNull;
    }

    final engine = await ref.watch(engineProvider.future);
    try {
      return await engine.channelGet(uuid);
    } catch (e) {
      return null;
    }
  }

  Future<void> refresh() async {
    final uuid = ref.read(selectedChannelUuidProvider);
    if (uuid == null) return;

    state = await AsyncValue.guard(() async {
      final engine = await ref.read(engineProvider.future);
      return engine.channelGet(uuid);
    });
  }
}

/// Selected channel posts provider (convenience wrapper)
final selectedChannelPostsProvider = Provider<AsyncValue<List<ChannelPost>>>((ref) {
  final uuid = ref.watch(selectedChannelUuidProvider);
  if (uuid == null) {
    return const AsyncValue.data([]);
  }
  return ref.watch(channelPostsProvider(uuid));
});

// =============================================================================
// DISCOVER CHANNELS
// =============================================================================

/// Discover public channels from server
final discoverChannelsProvider =
    AsyncNotifierProvider<DiscoverChannelsNotifier, List<Channel>>(
  DiscoverChannelsNotifier.new,
);

class DiscoverChannelsNotifier extends AsyncNotifier<List<Channel>> {
  @override
  Future<List<Channel>> build() async {
    final identityLoaded = ref.watch(identityLoadedProvider);
    if (!identityLoaded) {
      return state.valueOrNull ?? [];
    }

    final engine = await ref.watch(engineProvider.future);
    return engine.channelDiscover();
  }

  Future<void> refresh() async {
    state = await AsyncValue.guard(() async {
      final engine = await ref.read(engineProvider.future);
      return engine.channelDiscover();
    });
  }
}

// =============================================================================
// SEARCH CHANNELS
// =============================================================================

/// Channel search query state
final channelSearchQueryProvider = StateProvider<String>((ref) => '');

/// Search channels from server (debounced via UI)
final searchChannelsProvider =
    AsyncNotifierProvider<SearchChannelsNotifier, List<Channel>>(
  SearchChannelsNotifier.new,
);

class SearchChannelsNotifier extends AsyncNotifier<List<Channel>> {
  @override
  Future<List<Channel>> build() async {
    final query = ref.watch(channelSearchQueryProvider);
    if (query.isEmpty) return [];

    final identityLoaded = ref.watch(identityLoadedProvider);
    if (!identityLoaded) return [];

    final engine = await ref.watch(engineProvider.future);
    return engine.channelSearch(query);
  }
}
