// Wall Provider - Unified feed with batch-loaded data for performance
import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:shared_preferences/shared_preferences.dart';
import '../ffi/dna_engine.dart';
import 'engine_provider.dart';
import 'contact_profile_cache_provider.dart';
import 'identity_profile_cache_provider.dart';
import 'identity_provider.dart';
import 'profile_provider.dart';

// ---------------------------------------------------------------------------
// WallFeedItem — unified model containing everything a tile needs to render
// ---------------------------------------------------------------------------

class WallFeedItem {
  final WallPost post;
  final int commentCount;
  final List<WallComment> previewComments; // max 3
  final int likeCount;
  final bool isLikedByMe;
  final String authorDisplayName;
  final Uint8List? authorAvatar;
  final Uint8List? decodedImage; // cached base64 decode

  WallFeedItem({
    required this.post,
    this.commentCount = 0,
    this.previewComments = const [],
    this.likeCount = 0,
    this.isLikedByMe = false,
    required this.authorDisplayName,
    this.authorAvatar,
    this.decodedImage,
  });

  bool isOwn(String myFingerprint) => post.isOwn(myFingerprint);

  WallFeedItem copyWith({
    WallPost? post,
    int? commentCount,
    List<WallComment>? previewComments,
    int? likeCount,
    bool? isLikedByMe,
    String? authorDisplayName,
    Uint8List? authorAvatar,
    Uint8List? decodedImage,
  }) {
    return WallFeedItem(
      post: post ?? this.post,
      commentCount: commentCount ?? this.commentCount,
      previewComments: previewComments ?? this.previewComments,
      likeCount: likeCount ?? this.likeCount,
      isLikedByMe: isLikedByMe ?? this.isLikedByMe,
      authorDisplayName: authorDisplayName ?? this.authorDisplayName,
      authorAvatar: authorAvatar ?? this.authorAvatar,
      decodedImage: decodedImage ?? this.decodedImage,
    );
  }
}

// ---------------------------------------------------------------------------
// Image decode cache — LRU cache to avoid re-decoding base64 on every build
// ---------------------------------------------------------------------------

class _ImageCache {
  static const int _maxSize = 50;
  static final Map<String, Uint8List> _cache = {};
  static final List<String> _keys = [];

  static Uint8List? get(String uuid) => _cache[uuid];

  static void put(String uuid, Uint8List bytes) {
    if (_cache.containsKey(uuid)) {
      // Move to end (most recently used)
      _keys.remove(uuid);
      _keys.add(uuid);
      return;
    }
    // Evict oldest if at capacity
    while (_keys.length >= _maxSize) {
      final oldest = _keys.removeAt(0);
      _cache.remove(oldest);
    }
    _cache[uuid] = bytes;
    _keys.add(uuid);
  }

  static Uint8List? decodePostImage(String uuid, String? imageJson) {
    if (imageJson == null || imageJson.isEmpty) return null;
    final cached = get(uuid);
    if (cached != null) return cached;
    try {
      final map = jsonDecode(imageJson) as Map<String, dynamic>;
      final data = map['data'] as String?;
      if (data == null || data.isEmpty) return null;
      final bytes = base64Decode(data);
      put(uuid, bytes);
      return bytes;
    } catch (_) {
      return null;
    }
  }
}

/// Public accessor for image cache (used by WallPostTile)
Uint8List? wallImageCache(String uuid) => _ImageCache.get(uuid);

// ---------------------------------------------------------------------------
// Wall timeline provider — batch-loaded, paginated feed
// ---------------------------------------------------------------------------

final wallTimelineProvider =
    AsyncNotifierProvider<WallTimelineNotifier, List<WallFeedItem>>(
  WallTimelineNotifier.new,
);

class WallTimelineNotifier extends AsyncNotifier<List<WallFeedItem>> {
  bool _hasMore = true;
  bool _isLoadingMore = false;

  bool get hasMore => _hasMore;
  bool get isLoadingMore => _isLoadingMore;

  @override
  Future<List<WallFeedItem>> build() async {
    final identityLoaded = ref.watch(identityLoadedProvider);

    if (!identityLoaded) {
      // Cache-first: show cached wall posts instantly before identity loads
      final engine = await ref.watch(engineProvider.future);
      final prefs = await SharedPreferences.getInstance();
      final fp = prefs.getString('identity_fingerprint');
      if (fp != null && fp.length == 128) {
        try {
          final posts = await engine.wallTimelineCached(fp);
          return _assembleItems(posts, fp, cacheOnly: true);
        } catch (_) {
          return state.valueOrNull ?? [];
        }
      }
      return state.valueOrNull ?? [];
    }

    final engine = await ref.watch(engineProvider.future);
    final myFp = ref.read(currentFingerprintProvider) ?? '';
    return _fetchAndAssemble(engine, myFp);
  }

  /// Main fetch: get wall posts, batch-assemble with comments/likes/profiles
  Future<List<WallFeedItem>> _fetchAndAssemble(
      DnaEngine engine, String myFp) async {
    // Get wall posts
    final wallPosts = await engine.wallTimeline();

    // Fire-and-forget: fetch boosts in background, merge when ready
    engine.wallBoostTimeline().then((boostPosts) {
      if (boostPosts.isEmpty) return;
      _mergeBoosts(boostPosts, myFp);
    }).catchError((_) {});

    return _assembleItems(wallPosts, myFp);
  }

  /// Assemble WallFeedItems with batch-fetched comments, likes, profiles
  /// Assemble WallFeedItems. When [cacheOnly] is true (pre-identity load),
  /// skip likes/comments/profile DHT fetch — show posts only, no engagement data.
  /// This prevents caching "0 likes" from failed DHT fetches before identity is ready.
  Future<List<WallFeedItem>> _assembleItems(
      List<WallPost> posts, String myFp, {bool cacheOnly = false}) async {
    if (posts.isEmpty) return [];

    final engine = await ref.read(engineProvider.future);

    // Batch fetch comments and likes — only when identity is loaded (DHT ready)
    List<List<WallComment>> allComments;
    List<List<WallLike>> allLikes;

    if (cacheOnly) {
      // Pre-identity: no DHT fetch, show posts without engagement data
      allComments = List.filled(posts.length, const []);
      allLikes = List.filled(posts.length, const []);
    } else {
      final commentsFutures =
          posts.map((p) => _safeGetComments(engine, p.uuid));
      final likesFutures = posts.map((p) => _safeGetLikes(engine, p.uuid));
      allComments = await Future.wait(commentsFutures);
      allLikes = await Future.wait(likesFutures);
    }

    // Collect unique author fingerprints and batch prefetch profiles
    final uniqueAuthors = posts.map((p) => p.authorFingerprint).toSet().toList();
    final profileCache = ref.read(contactProfileCacheProvider.notifier);
    if (!cacheOnly) {
      await profileCache.prefetchProfiles(uniqueAuthors);
    }
    final profiles = ref.read(contactProfileCacheProvider);

    // Resolve own profile for own posts
    Uint8List? ownAvatar;
    String? ownName;
    if (myFp.isNotEmpty) {
      final ownIdentityCache = ref.read(identityProfileCacheProvider);
      final ownIdentity = ownIdentityCache[myFp];
      if (ownIdentity != null && ownIdentity.avatarBase64.isNotEmpty) {
        try {
          ownAvatar = base64Decode(ownIdentity.avatarBase64);
        } catch (_) {}
      }
      if (ownAvatar == null) {
        final ownProfile = ref.read(fullProfileProvider).valueOrNull;
        ownAvatar = ownProfile?.decodeAvatar();
      }
      ownName = ref.read(userProfileProvider).valueOrNull?.nickname;
    }

    // Assemble items
    final items = <WallFeedItem>[];
    for (var i = 0; i < posts.length; i++) {
      final post = posts[i];
      final comments = allComments[i];
      final likes = allLikes[i];
      final isOwn = post.isOwn(myFp);

      // Resolve author display name and avatar
      String displayName;
      Uint8List? avatar;

      if (isOwn) {
        displayName = ownName ??
            (post.authorName.isNotEmpty
                ? post.authorName
                : post.authorFingerprint.substring(0, 16));
        avatar = ownAvatar;
      } else {
        final profile = profiles[post.authorFingerprint];
        avatar = profile?.decodeAvatar();
        displayName = post.authorName.isNotEmpty
            ? post.authorName
            : post.authorFingerprint.substring(0, 16);
      }

      // Decode image once, cache it
      final decodedImage =
          _ImageCache.decodePostImage(post.uuid, post.imageJson);

      // Preview: up to 3 most recent comments
      final previewComments =
          comments.length <= 3 ? comments : comments.sublist(0, 3);

      items.add(WallFeedItem(
        post: post,
        commentCount: comments.length,
        previewComments: previewComments,
        likeCount: likes.length,
        isLikedByMe: likes.any((l) => l.authorFingerprint == myFp),
        authorDisplayName: displayName,
        authorAvatar: avatar,
        decodedImage: decodedImage,
      ));
    }

    return items;
  }

  /// Merge boost posts into existing state
  void _mergeBoosts(List<WallPost> boostPosts, String myFp) {
    final current = state.valueOrNull ?? [];
    final boostedUuids = {for (final p in boostPosts) p.uuid};
    final seenUuids = <String>{};
    final merged = <WallFeedItem>[];

    for (final item in current) {
      seenUuids.add(item.post.uuid);
      if (boostedUuids.contains(item.post.uuid)) {
        merged.add(item.copyWith(
            post: item.post.copyWith(isBoosted: true)));
      } else {
        merged.add(item);
      }
    }

    // Add new boost posts not already in timeline
    // These get minimal metadata — will be fully populated on next refresh
    for (final post in boostPosts) {
      if (!seenUuids.contains(post.uuid)) {
        seenUuids.add(post.uuid);
        final boostedPost = post.copyWith(isBoosted: true);
        merged.add(WallFeedItem(
          post: boostedPost,
          authorDisplayName: post.authorName.isNotEmpty
              ? post.authorName
              : post.authorFingerprint.substring(0, 16),
          decodedImage:
              _ImageCache.decodePostImage(post.uuid, post.imageJson),
        ));
      }
    }

    merged.sort((a, b) => b.post.timestamp.compareTo(a.post.timestamp));
    state = AsyncData(merged);
  }

  Future<void> refresh() async {
    state = await AsyncValue.guard(() async {
      final engine = await ref.read(engineProvider.future);
      final myFp = ref.read(currentFingerprintProvider) ?? '';
      return _fetchAndAssemble(engine, myFp);
    });
  }

  /// Create a text-only wall post
  Future<WallPost> createPost(String text, {bool boost = false}) async {
    final engine = await ref.read(engineProvider.future);
    final post = boost
        ? await engine.wallBoostPost(text)
        : await engine.wallPost(text);
    final result = boost ? post.copyWith(isBoosted: true) : post;
    _insertPostOptimistic(result);
    return result;
  }

  /// Create a wall post with image
  Future<WallPost> createPostWithImage(String text, String imageJson,
      {bool boost = false}) async {
    final engine = await ref.read(engineProvider.future);
    final post = boost
        ? await engine.wallBoostPostWithImage(text, imageJson)
        : await engine.wallPostWithImage(text, imageJson);
    final result = boost ? post.copyWith(isBoosted: true) : post;
    _insertPostOptimistic(result);
    return result;
  }

  void _insertPostOptimistic(WallPost post) {
    final myFp = ref.read(currentFingerprintProvider) ?? '';
    Uint8List? ownAvatar;
    final ownIdentityCache = ref.read(identityProfileCacheProvider);
    final ownIdentity = ownIdentityCache[myFp];
    if (ownIdentity != null && ownIdentity.avatarBase64.isNotEmpty) {
      try {
        ownAvatar = base64Decode(ownIdentity.avatarBase64);
      } catch (_) {}
    }

    final item = WallFeedItem(
      post: post,
      authorDisplayName: post.authorName.isNotEmpty
          ? post.authorName
          : ref.read(userProfileProvider).valueOrNull?.nickname ??
              post.authorFingerprint.substring(0, 16),
      authorAvatar: ownAvatar,
      decodedImage: _ImageCache.decodePostImage(post.uuid, post.imageJson),
    );

    final current = state.valueOrNull ?? [];
    state = AsyncData([item, ...current]);
  }

  Future<void> deletePost(String postUuid) async {
    final engine = await ref.read(engineProvider.future);
    await engine.wallDelete(postUuid);
    final current = state.valueOrNull ?? [];
    state = AsyncData(
        current.where((item) => item.post.uuid != postUuid).toList());
  }

  /// Like a post — updates the specific item in the list
  Future<void> likePost(String postUuid) async {
    final engine = await ref.read(engineProvider.future);
    final likes = await engine.wallLike(postUuid);
    final myFp = ref.read(currentFingerprintProvider) ?? '';

    final current = state.valueOrNull ?? [];
    state = AsyncData(current.map((item) {
      if (item.post.uuid == postUuid) {
        return item.copyWith(
          likeCount: likes.length,
          isLikedByMe: likes.any((l) => l.authorFingerprint == myFp),
        );
      }
      return item;
    }).toList());
  }

  /// Update comments for a specific post after adding a comment
  Future<void> refreshComments(String postUuid) async {
    final engine = await ref.read(engineProvider.future);
    final comments = await _safeGetComments(engine, postUuid);

    final current = state.valueOrNull ?? [];
    state = AsyncData(current.map((item) {
      if (item.post.uuid == postUuid) {
        return item.copyWith(
          commentCount: comments.length,
          previewComments:
              comments.length <= 3 ? comments : comments.sublist(0, 3),
        );
      }
      return item;
    }).toList());
  }

  /// Safe fetch helpers that return empty on error
  Future<List<WallComment>> _safeGetComments(
      DnaEngine engine, String postUuid) async {
    try {
      return await engine.wallGetComments(postUuid);
    } catch (_) {
      return [];
    }
  }

  Future<List<WallLike>> _safeGetLikes(
      DnaEngine engine, String postUuid) async {
    try {
      return await engine.wallGetLikes(postUuid);
    } catch (_) {
      return [];
    }
  }
}

// ---------------------------------------------------------------------------
// Wall comments provider — still needed for detail screen (full comment list)
// ---------------------------------------------------------------------------

final wallCommentsProvider =
    AsyncNotifierProviderFamily<WallCommentsNotifier, List<WallComment>, String>(
  WallCommentsNotifier.new,
);

class WallCommentsNotifier
    extends FamilyAsyncNotifier<List<WallComment>, String> {
  @override
  Future<List<WallComment>> build(String arg) async {
    final identityLoaded = ref.watch(identityLoadedProvider);
    if (!identityLoaded) {
      return state.valueOrNull ?? [];
    }

    final engine = await ref.watch(engineProvider.future);
    return engine.wallGetComments(arg);
  }

  Future<void> refresh() async {
    state = await AsyncValue.guard(() async {
      final engine = await ref.read(engineProvider.future);
      return engine.wallGetComments(arg);
    });
  }

  /// Add a comment to this wall post (optionally as a reply)
  Future<WallComment> addComment(
    String body, {
    String? parentCommentUuid,
  }) async {
    final engine = await ref.read(engineProvider.future);
    final comment = await engine.wallAddComment(
      arg,
      body,
      parentCommentUuid: parentCommentUuid,
    );
    await refresh();
    return comment;
  }
}
