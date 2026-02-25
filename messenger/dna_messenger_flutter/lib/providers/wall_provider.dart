// Wall Provider - Personal wall posts, timeline, and comments
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../ffi/dna_engine.dart';
import 'engine_provider.dart';

/// Wall timeline provider - all contacts' posts merged, sorted by timestamp desc
final wallTimelineProvider =
    AsyncNotifierProvider<WallTimelineNotifier, List<WallPost>>(
  WallTimelineNotifier.new,
);

class WallTimelineNotifier extends AsyncNotifier<List<WallPost>> {
  @override
  Future<List<WallPost>> build() async {
    final identityLoaded = ref.watch(identityLoadedProvider);
    if (!identityLoaded) {
      return state.valueOrNull ?? [];
    }

    final engine = await ref.watch(engineProvider.future);
    return engine.wallTimeline();
  }

  Future<void> refresh() async {
    state = await AsyncValue.guard(() async {
      final engine = await ref.read(engineProvider.future);
      return engine.wallTimeline();
    });
  }

  /// Create a text-only wall post
  Future<WallPost> createPost(String text) async {
    final engine = await ref.read(engineProvider.future);
    final post = await engine.wallPost(text);
    await refresh();
    return post;
  }

  /// Create a wall post with image (v0.7.0+)
  Future<WallPost> createPostWithImage(String text, String imageJson) async {
    final engine = await ref.read(engineProvider.future);
    final post = await engine.wallPostWithImage(text, imageJson);
    await refresh();
    return post;
  }

  Future<void> deletePost(String postUuid) async {
    final engine = await ref.read(engineProvider.future);
    await engine.wallDelete(postUuid);
    await refresh();
  }
}

/// Wall comments provider - keyed by post UUID (v0.7.0+)
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
