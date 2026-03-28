// Wall Provider - Unified feed with batch-loaded data for performance
import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:shared_preferences/shared_preferences.dart';
import '../ffi/dna_engine.dart';
import 'engine_provider.dart';
import 'contact_profile_cache_provider.dart';
import 'contact_requests_provider.dart';
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

/// Public accessor to store in image cache (used by lazy image loader)
void wallImageCachePut(String uuid, Uint8List bytes) => _ImageCache.put(uuid, bytes);

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
  int _loadedDays = 2; // Start with today + yesterday (DNA_WALL_INITIAL_DAYS)

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
          return _assembleItems(posts, fp);
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

  /// Refresh from cache only (no DHT query, no boost, no engagement re-fetch).
  /// Called after bg-refresh updates the cache — avoids redundant full timeline query.
  /// Preserves existing engagement data (comments, likes) from current state.
  Future<void> refreshFromCache() async {
    try {
      final engine = await ref.read(engineProvider.future);
      final myFp = ref.read(currentFingerprintProvider) ?? '';
      if (myFp.isEmpty) return;
      final posts = await engine.wallTimelineCached(myFp);
      final items = await _assembleItems(posts, myFp);

      // Preserve engagement data from current state
      final current = state.valueOrNull;
      if (current != null && current.isNotEmpty) {
        final engMap = <String, WallFeedItem>{};
        for (final item in current) {
          engMap[item.post.uuid] = item;
        }
        final merged = items.map((item) {
          final prev = engMap[item.post.uuid];
          if (prev != null &&
              (prev.commentCount > 0 || prev.likeCount > 0)) {
            return item.copyWith(
              commentCount: prev.commentCount,
              previewComments: prev.previewComments,
              likeCount: prev.likeCount,
              isLikedByMe: prev.isLikedByMe,
            );
          }
          return item;
        }).toList();
        state = AsyncValue.data(merged);
      } else {
        state = AsyncValue.data(items);
      }
    } catch (_) {
      // Cache read failed — keep current state
    }
  }

  /// Main fetch: get wall posts, return immediately WITHOUT engagement data,
  /// then fetch comments/likes in background and update state when ready.
  Future<List<WallFeedItem>> _fetchAndAssemble(
      DnaEngine engine, String myFp) async {
    // Get wall posts (cache-first, returns quickly)
    final wallPosts = await engine.wallTimeline();

    // Fire-and-forget: fetch boosts in background, merge when ready
    engine.wallBoostTimeline().then((boostPosts) {
      if (boostPosts.isEmpty) return;
      _mergeBoosts(boostPosts, myFp);
    }).catchError((_) {});

    // Assemble items, preserving existing engagement data while bg-refresh runs
    var items = await _assembleItems(wallPosts, myFp);
    final current = state.valueOrNull;
    if (current != null && current.isNotEmpty) {
      final engMap = <String, WallFeedItem>{};
      for (final item in current) {
        engMap[item.post.uuid] = item;
      }
      items = items.map((item) {
        final prev = engMap[item.post.uuid];
        if (prev != null &&
            (prev.commentCount > 0 || prev.likeCount > 0)) {
          return item.copyWith(
            commentCount: prev.commentCount,
            previewComments: prev.previewComments,
            likeCount: prev.likeCount,
            isLikedByMe: prev.isLikedByMe,
          );
        }
        return item;
      }).toList();
    }
    // Fire-and-forget: engagement refresh in background.
    // C side serves stale cache immediately + fetches DHT for stale entries.
    // When done, update state with fresh data.
    _refreshEngagementBg(wallPosts, myFp, engine);
    return items;
  }

  /// Fetch engagement in background, update state when ready.
  /// C side serves stale cache + refreshes from DHT for stale entries.
  void _refreshEngagementBg(
      List<WallPost> posts, String myFp, DnaEngine engine) {
    () async {
      try {
        final uuids = posts.map((p) => p.uuid).toList();
        final engagements = await engine.wallGetEngagement(uuids);

        final current = state.valueOrNull;
        if (current == null || current.isEmpty) return;

        final engMap = <String, WallEngagement>{};
        for (final e in engagements) {
          engMap[e.postUuid] = e;
        }

        bool changed = false;
        final updated = current.map((item) {
          final eng = engMap[item.post.uuid];
          if (eng == null) return item;

          final newPreview = eng.comments.length <= 3
              ? eng.comments
              : eng.comments.sublist(0, 3);

          if (eng.likeCount != item.likeCount ||
              eng.comments.length != item.commentCount ||
              eng.isLikedByMe != item.isLikedByMe) {
            changed = true;
            return item.copyWith(
              likeCount: eng.likeCount,
              isLikedByMe: eng.isLikedByMe,
              commentCount: eng.comments.length,
              previewComments: newPreview,
            );
          }
          return item;
        }).toList();

        if (changed) {
          state = AsyncData(updated);
        }
      } catch (_) {
        // Silent fail — engagement refresh is best-effort
      }
    }();
  }

  /// Assemble WallFeedItems with profiles only — NO comment/like fetch.
  /// Engagement data is loaded separately via _refreshEngagement().
  Future<List<WallFeedItem>> _assembleItems(
      List<WallPost> posts, String myFp) async {
    if (posts.isEmpty) return [];

    // Filter out posts from blocked users
    final blockedList = ref.read(blockedUsersProvider).valueOrNull ?? [];
    if (blockedList.isNotEmpty) {
      final blockedFps = {for (final b in blockedList) b.fingerprint};
      posts = posts.where((p) => !blockedFps.contains(p.authorFingerprint)).toList();
      if (posts.isEmpty) return [];
    }

    // Collect unique author fingerprints and batch prefetch profiles
    final uniqueAuthors = posts.map((p) => p.authorFingerprint).toSet().toList();
    final profileCache = ref.read(contactProfileCacheProvider.notifier);
    await profileCache.prefetchProfiles(uniqueAuthors);
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

    // Assemble items — no engagement data, just posts + profiles + images
    final items = <WallFeedItem>[];
    for (var i = 0; i < posts.length; i++) {
      final post = posts[i];
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

      // Only check in-memory cache (image loaded lazily by tile)
      final decodedImage = _ImageCache.get(post.uuid);

      items.add(WallFeedItem(
        post: post,
        authorDisplayName: displayName,
        authorAvatar: avatar,
        decodedImage: decodedImage,
      ));
    }

    return items;
  }

  /// Merge boost posts into existing state (with full metadata)
  Future<void> _mergeBoosts(List<WallPost> boostPosts, String myFp) async {
    // Filter out blocked users' boosts
    final blockedList = ref.read(blockedUsersProvider).valueOrNull ?? [];
    if (blockedList.isNotEmpty) {
      final blockedFps = {for (final b in blockedList) b.fingerprint};
      boostPosts = boostPosts.where((p) => !blockedFps.contains(p.authorFingerprint)).toList();
      if (boostPosts.isEmpty) return;
    }

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

    // Add new boost posts not already in timeline — fetch full metadata
    final newBoosts = boostPosts
        .where((p) => !seenUuids.contains(p.uuid))
        .toList();

    if (newBoosts.isNotEmpty) {
      final engine = await ref.read(engineProvider.future);

      // Batch fetch comments, likes, and profiles for new boost posts
      final commentsFutures =
          newBoosts.map((p) => _safeGetComments(engine, p.uuid));
      final likesFutures =
          newBoosts.map((p) => _safeGetLikes(engine, p.uuid));
      final allComments = await Future.wait(commentsFutures);
      final allLikes = await Future.wait(likesFutures);

      // Prefetch profiles for boost post authors
      final uniqueAuthors =
          newBoosts.map((p) => p.authorFingerprint).toSet().toList();
      final profileCache = ref.read(contactProfileCacheProvider.notifier);
      await profileCache.prefetchProfiles(uniqueAuthors);
      final profiles = ref.read(contactProfileCacheProvider);

      for (var i = 0; i < newBoosts.length; i++) {
        final post = newBoosts[i];
        final comments = allComments[i];
        final likes = allLikes[i];
        final boostedPost = post.copyWith(isBoosted: true);
        final profile = profiles[post.authorFingerprint];
        final previewComments =
            comments.length <= 3 ? comments : comments.sublist(0, 3);

        seenUuids.add(post.uuid);
        merged.add(WallFeedItem(
          post: boostedPost,
          commentCount: comments.length,
          previewComments: previewComments,
          likeCount: likes.length,
          isLikedByMe: likes.any((l) => l.authorFingerprint == myFp),
          authorDisplayName: post.authorName.isNotEmpty
              ? post.authorName
              : post.authorFingerprint.substring(0, 16),
          authorAvatar: profile?.decodeAvatar(),
          decodedImage: _ImageCache.get(post.uuid),
        ));
      }
    }

    merged.sort((a, b) => b.post.timestamp.compareTo(a.post.timestamp));
    state = AsyncData(merged);
  }

  Future<void> refresh() async {
    _loadedDays = 2;
    _hasMore = true;
    state = await AsyncValue.guard(() async {
      final engine = await ref.read(engineProvider.future);
      final myFp = ref.read(currentFingerprintProvider) ?? '';
      return _fetchAndAssemble(engine, myFp);
    });
  }

  /// Load older days on scroll (lazy load).
  /// Fetches the next day's bucket for all contacts.
  Future<void> loadMoreDays() async {
    if (_isLoadingMore || !_hasMore) return;
    _isLoadingMore = true;

    try {
      final engine = await ref.read(engineProvider.future);
      final myFp = ref.read(currentFingerprintProvider) ?? '';
      if (myFp.isEmpty) return;

      // Calculate date string for the next day to load
      final targetDay = DateTime.now()
          .toUtc()
          .subtract(Duration(days: _loadedDays));
      if (_loadedDays >= 30) {
        _hasMore = false;
        return;
      }

      final dateStr =
          '${targetDay.year}-${targetDay.month.toString().padLeft(2, '0')}-${targetDay.day.toString().padLeft(2, '0')}';

      // Get contact + following fingerprints
      // Reuse cached timeline posts to extract unique authors
      final current = state.valueOrNull ?? [];
      final authors = current.map((i) => i.post.authorFingerprint).toSet();
      if (authors.isEmpty) authors.add(myFp);

      // Fetch this day's bucket for each author
      final newPosts = <WallPost>[];
      for (final fp in authors) {
        try {
          final posts = await engine.wallLoadDay(fp, dateStr);
          newPosts.addAll(posts);
        } catch (_) {
          // No bucket for this author on this day — normal
        }
      }

      _loadedDays++;

      if (newPosts.isEmpty) {
        // No posts found — try a few more days before giving up
        if (_loadedDays >= 30) _hasMore = false;
      } else {
        // Assemble and merge into existing state
        final newItems = await _assembleItems(newPosts, myFp);
        final existing = state.valueOrNull ?? [];
        final existingUuids = {for (final i in existing) i.post.uuid};
        final deduped =
            newItems.where((i) => !existingUuids.contains(i.post.uuid)).toList();

        if (deduped.isNotEmpty) {
          final merged = [...existing, ...deduped];
          merged.sort(
              (a, b) => b.post.timestamp.compareTo(a.post.timestamp));
          state = AsyncData(merged);
        }
      }
    } finally {
      _isLoadingMore = false;
    }
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
      decodedImage: _ImageCache.get(post.uuid),
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

  /// Remove all posts by a specific author (used after blocking)
  void removePostsByAuthor(String authorFingerprint) {
    final current = state.valueOrNull ?? [];
    state = AsyncData(
        current.where((item) => item.post.authorFingerprint != authorFingerprint).toList());
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
