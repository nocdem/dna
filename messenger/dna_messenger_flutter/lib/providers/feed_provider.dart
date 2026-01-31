// Feed Provider v2 - Topic-based feeds with categories and subscriptions
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../ffi/dna_engine.dart';
import 'engine_provider.dart';

// =============================================================================
// FEED TOPICS
// =============================================================================

/// Selected category for feed listing (null = all categories)
final feedCategoryProvider = StateProvider<String?>((ref) => null);

/// Days back to look for topics (default 7)
final feedDaysBackProvider = StateProvider<int>((ref) => 7);

/// Feed topics provider - lists topics by category or all
final feedTopicsProvider = AsyncNotifierProvider<FeedTopicsNotifier, List<FeedTopic>>(
  FeedTopicsNotifier.new,
);

class FeedTopicsNotifier extends AsyncNotifier<List<FeedTopic>> {
  @override
  Future<List<FeedTopic>> build() async {
    final identityLoaded = ref.watch(identityLoadedProvider);
    if (!identityLoaded) {
      return [];
    }

    final category = ref.watch(feedCategoryProvider);
    final daysBack = ref.watch(feedDaysBackProvider);

    final engine = await ref.watch(engineProvider.future);

    if (category == null) {
      return engine.feedGetAll(daysBack: daysBack);
    } else {
      return engine.feedGetCategory(category, daysBack: daysBack);
    }
  }

  Future<void> refresh() async {
    state = const AsyncValue.loading();
    state = await AsyncValue.guard(() async {
      final category = ref.read(feedCategoryProvider);
      final daysBack = ref.read(feedDaysBackProvider);
      final engine = await ref.read(engineProvider.future);

      if (category == null) {
        return engine.feedGetAll(daysBack: daysBack);
      } else {
        return engine.feedGetCategory(category, daysBack: daysBack);
      }
    });
  }

  /// Create a new topic
  Future<FeedTopic> createTopic(
    String title,
    String body,
    String category, {
    List<String> tags = const [],
  }) async {
    final engine = await ref.read(engineProvider.future);
    final topic = await engine.feedCreateTopic(title, body, category, tags: tags);
    await refresh();
    return topic;
  }

  /// Delete a topic (soft delete - author only)
  Future<void> deleteTopic(String uuid) async {
    final engine = await ref.read(engineProvider.future);
    await engine.feedDeleteTopic(uuid);
    await refresh();
  }
}

// =============================================================================
// TOPIC DETAIL (single topic with comments)
// =============================================================================

/// Selected topic UUID for detail view
final selectedTopicUuidProvider = StateProvider<String?>((ref) => null);

/// Selected topic detail provider
final selectedTopicProvider = AsyncNotifierProvider<SelectedTopicNotifier, FeedTopic?>(
  SelectedTopicNotifier.new,
);

class SelectedTopicNotifier extends AsyncNotifier<FeedTopic?> {
  @override
  Future<FeedTopic?> build() async {
    final uuid = ref.watch(selectedTopicUuidProvider);
    if (uuid == null) {
      return null;
    }

    final identityLoaded = ref.watch(identityLoadedProvider);
    if (!identityLoaded) {
      return null;
    }

    final engine = await ref.watch(engineProvider.future);
    try {
      return await engine.feedGetTopic(uuid);
    } catch (e) {
      return null;
    }
  }

  Future<void> refresh() async {
    final uuid = ref.read(selectedTopicUuidProvider);
    if (uuid == null) return;

    state = const AsyncValue.loading();
    state = await AsyncValue.guard(() async {
      final engine = await ref.read(engineProvider.future);
      return engine.feedGetTopic(uuid);
    });
  }
}

/// Topic comments provider - keyed by topic UUID
final topicCommentsProvider = AsyncNotifierProviderFamily<TopicCommentsNotifier, List<FeedComment>, String>(
  TopicCommentsNotifier.new,
);

class TopicCommentsNotifier extends FamilyAsyncNotifier<List<FeedComment>, String> {
  @override
  Future<List<FeedComment>> build(String arg) async {
    final identityLoaded = ref.watch(identityLoadedProvider);
    if (!identityLoaded) {
      return [];
    }

    final engine = await ref.watch(engineProvider.future);
    return engine.feedGetComments(arg);
  }

  Future<void> refresh() async {
    state = const AsyncValue.loading();
    state = await AsyncValue.guard(() async {
      final engine = await ref.read(engineProvider.future);
      return engine.feedGetComments(arg);
    });
  }

  /// Add a comment to this topic (optionally as a reply)
  ///
  /// [body] - Comment text
  /// [parentCommentUuid] - Parent comment UUID for replies (null = top-level)
  /// [mentions] - List of fingerprints to @mention
  Future<FeedComment> addComment(
    String body, {
    String? parentCommentUuid,
    List<String> mentions = const [],
  }) async {
    final engine = await ref.read(engineProvider.future);
    final comment = await engine.feedAddComment(
      arg,
      body,
      parentCommentUuid: parentCommentUuid,
      mentions: mentions,
    );
    await refresh();
    return comment;
  }
}

/// Selected topic comments provider (convenience wrapper)
final selectedTopicCommentsProvider = Provider<AsyncValue<List<FeedComment>>>((ref) {
  final uuid = ref.watch(selectedTopicUuidProvider);
  if (uuid == null) {
    return const AsyncValue.data([]);
  }
  return ref.watch(topicCommentsProvider(uuid));
});

// =============================================================================
// FEED SUBSCRIPTIONS
// =============================================================================

/// Feed subscriptions provider
final feedSubscriptionsProvider = AsyncNotifierProvider<FeedSubscriptionsNotifier, List<FeedSubscription>>(
  FeedSubscriptionsNotifier.new,
);

class FeedSubscriptionsNotifier extends AsyncNotifier<List<FeedSubscription>> {
  @override
  Future<List<FeedSubscription>> build() async {
    final identityLoaded = ref.watch(identityLoadedProvider);
    if (!identityLoaded) {
      return [];
    }

    final engine = await ref.watch(engineProvider.future);
    return engine.feedGetSubscriptions();
  }

  Future<void> refresh() async {
    state = const AsyncValue.loading();
    state = await AsyncValue.guard(() async {
      final engine = await ref.read(engineProvider.future);
      return engine.feedGetSubscriptions();
    });
  }

  /// Subscribe to a topic
  Future<bool> subscribe(String topicUuid) async {
    final engine = await ref.read(engineProvider.future);
    final result = engine.feedSubscribe(topicUuid);
    if (result) {
      await refresh();
    }
    return result;
  }

  /// Unsubscribe from a topic
  Future<bool> unsubscribe(String topicUuid) async {
    final engine = await ref.read(engineProvider.future);
    final result = engine.feedUnsubscribe(topicUuid);
    if (result) {
      await refresh();
    }
    return result;
  }

  /// Toggle subscription state
  Future<bool> toggleSubscription(String topicUuid) async {
    final engine = await ref.read(engineProvider.future);
    final isSubscribed = engine.feedIsSubscribed(topicUuid);
    if (isSubscribed) {
      return unsubscribe(topicUuid);
    } else {
      return subscribe(topicUuid);
    }
  }

  /// Sync subscriptions to DHT (for multi-device)
  Future<void> syncToDht() async {
    final engine = await ref.read(engineProvider.future);
    await engine.feedSyncSubscriptionsToDht();
  }

  /// Sync subscriptions from DHT (for multi-device)
  Future<void> syncFromDht() async {
    final engine = await ref.read(engineProvider.future);
    await engine.feedSyncSubscriptionsFromDht();
    await refresh();
  }
}

/// Check if subscribed to a specific topic (sync, returns immediately)
final isSubscribedProvider = Provider.family<bool, String>((ref, topicUuid) {
  final subscriptions = ref.watch(feedSubscriptionsProvider);
  return subscriptions.when(
    data: (subs) => subs.any((s) => s.topicUuid == topicUuid),
    loading: () => false,
    error: (e, s) => false,
  );
});

// =============================================================================
// SUBSCRIBED TOPICS (topics user is subscribed to)
// =============================================================================

/// Subscribed topics provider - fetches full topic info for subscribed UUIDs
final subscribedTopicsProvider = AsyncNotifierProvider<SubscribedTopicsNotifier, List<FeedTopic>>(
  SubscribedTopicsNotifier.new,
);

class SubscribedTopicsNotifier extends AsyncNotifier<List<FeedTopic>> {
  @override
  Future<List<FeedTopic>> build() async {
    // Watch subscriptions to rebuild when they change
    final subscriptionsAsync = ref.watch(feedSubscriptionsProvider);

    return subscriptionsAsync.when(
      data: (subscriptions) async {
        if (subscriptions.isEmpty) {
          return [];
        }

        final engine = await ref.read(engineProvider.future);
        final topics = <FeedTopic>[];

        for (final sub in subscriptions) {
          try {
            final topic = await engine.feedGetTopic(sub.topicUuid);
            topics.add(topic);
          } catch (e) {
            // Topic may have expired or been deleted - skip it
          }
        }

        return topics;
      },
      loading: () async => [],
      error: (e, s) async => [],
    );
  }

  Future<void> refresh() async {
    state = const AsyncValue.loading();
    ref.invalidate(feedSubscriptionsProvider);
    state = await AsyncValue.guard(() => build());
  }
}
