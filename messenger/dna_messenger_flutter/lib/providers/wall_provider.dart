// Wall Provider - Personal wall posts and timeline
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

  Future<WallPost> createPost(String text) async {
    final engine = await ref.read(engineProvider.future);
    final post = await engine.wallPost(text);
    await refresh();
    return post;
  }

  Future<void> deletePost(String postUuid) async {
    final engine = await ref.read(engineProvider.future);
    await engine.wallDelete(postUuid);
    await refresh();
  }
}
