// Feed Provider - Feed state management
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:intl/intl.dart';
import '../ffi/dna_engine.dart';
import 'engine_provider.dart';

/// Number of days of posts to fetch
const int _feedDaysToFetch = 7;

/// Generate date strings for the last N days (YYYY-MM-DD format)
List<String> _getRecentDates(int days) {
  final formatter = DateFormat('yyyy-MM-dd');
  final now = DateTime.now();
  return List.generate(days, (i) => formatter.format(now.subtract(Duration(days: i))));
}

// =============================================================================
// CHANNEL PROVIDERS
// =============================================================================

/// Feed channels list provider
final feedChannelsProvider = AsyncNotifierProvider<FeedChannelsNotifier, List<FeedChannel>>(
  FeedChannelsNotifier.new,
);

class FeedChannelsNotifier extends AsyncNotifier<List<FeedChannel>> {
  @override
  Future<List<FeedChannel>> build() async {
    final identityLoaded = ref.watch(identityLoadedProvider);
    if (!identityLoaded) {
      return [];
    }

    final engine = await ref.watch(engineProvider.future);
    final channels = await engine.getFeedChannels();

    // Sort by last activity (most recent first)
    channels.sort((a, b) => b.lastActivity.compareTo(a.lastActivity));
    return channels;
  }

  Future<void> refresh() async {
    state = const AsyncValue.loading();
    state = await AsyncValue.guard(() async {
      final engine = await ref.read(engineProvider.future);
      final channels = await engine.getFeedChannels();
      channels.sort((a, b) => b.lastActivity.compareTo(a.lastActivity));
      return channels;
    });
  }

  Future<FeedChannel> createChannel(String name, String description) async {
    final engine = await ref.read(engineProvider.future);
    final channel = await engine.createFeedChannel(name, description);
    await refresh();
    return channel;
  }

  Future<void> initDefaultChannels() async {
    final engine = await ref.read(engineProvider.future);
    await engine.initDefaultChannels();
    await refresh();
  }
}

/// Currently selected channel
final selectedChannelProvider = StateProvider<FeedChannel?>((ref) => null);

// =============================================================================
// POSTS PROVIDERS
// =============================================================================

/// Posts for selected channel
final channelPostsProvider = AsyncNotifierProviderFamily<ChannelPostsNotifier, List<FeedPost>, String>(
  ChannelPostsNotifier.new,
);

class ChannelPostsNotifier extends FamilyAsyncNotifier<List<FeedPost>, String> {
  @override
  Future<List<FeedPost>> build(String channelId) async {
    if (channelId.isEmpty) {
      return [];
    }

    final engine = await ref.watch(engineProvider.future);
    final posts = await _fetchPostsFromMultipleDays(engine, channelId);

    // Sort by timestamp (newest first)
    posts.sort((a, b) => b.timestamp.compareTo(a.timestamp));
    return posts;
  }

  /// Fetch posts from the last N days and merge/deduplicate
  Future<List<FeedPost>> _fetchPostsFromMultipleDays(DnaEngine engine, String channelId) async {
    final dates = _getRecentDates(_feedDaysToFetch);
    final allPosts = <FeedPost>[];
    final seenIds = <String>{};

    // Fetch posts for each date
    for (final date in dates) {
      try {
        final posts = await engine.getFeedPosts(channelId, date: date);
        for (final post in posts) {
          if (!seenIds.contains(post.postId)) {
            seenIds.add(post.postId);
            allPosts.add(post);
          }
        }
      } catch (e) {
        // Skip days with errors (e.g., no posts for that date)
      }
    }

    return allPosts;
  }

  Future<void> refresh() async {
    state = const AsyncValue.loading();
    state = await AsyncValue.guard(() async {
      final engine = await ref.read(engineProvider.future);
      final posts = await _fetchPostsFromMultipleDays(engine, arg);
      posts.sort((a, b) => b.timestamp.compareTo(a.timestamp));
      return posts;
    });
  }

  Future<FeedPost> createPost(String text, {String? replyTo}) async {
    final engine = await ref.read(engineProvider.future);
    final post = await engine.createFeedPost(arg, text, replyTo: replyTo);
    await refresh();
    return post;
  }
}

/// Post replies provider
final postRepliesProvider = AsyncNotifierProviderFamily<PostRepliesNotifier, List<FeedPost>, String>(
  PostRepliesNotifier.new,
);

class PostRepliesNotifier extends FamilyAsyncNotifier<List<FeedPost>, String> {
  @override
  Future<List<FeedPost>> build(String postId) async {
    if (postId.isEmpty) {
      return [];
    }

    final engine = await ref.watch(engineProvider.future);
    final replies = await engine.getFeedPostReplies(postId);

    // Sort by timestamp (oldest first for thread view)
    replies.sort((a, b) => a.timestamp.compareTo(b.timestamp));
    return replies;
  }

  Future<void> refresh() async {
    state = const AsyncValue.loading();
    state = await AsyncValue.guard(() async {
      final engine = await ref.read(engineProvider.future);
      final replies = await engine.getFeedPostReplies(arg);
      replies.sort((a, b) => a.timestamp.compareTo(b.timestamp));
      return replies;
    });
  }
}

// =============================================================================
// VOTING PROVIDERS
// =============================================================================

/// Cast a vote on a post
final castVoteProvider = FutureProvider.family<void, ({String postId, int value})>((ref, params) async {
  final engine = await ref.read(engineProvider.future);
  await engine.castFeedVote(params.postId, params.value);
});

/// Post vote state (for optimistic updates)
final postVoteProvider = StateProvider.family<int, String>((ref, postId) => 0);

// =============================================================================
// REPLY STATE
// =============================================================================

/// Post being replied to (null for new top-level post)
final replyToPostProvider = StateProvider<FeedPost?>((ref) => null);

/// Compose text controller state
final composeTextProvider = StateProvider<String>((ref) => '');
