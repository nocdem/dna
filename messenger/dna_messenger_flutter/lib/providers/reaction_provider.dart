import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../ffi/dna_engine.dart';
import 'engine_provider.dart';

/// Aggregated view of reactions on a message, grouped by emoji.
class ReactionGroup {
  final String emoji;
  final int count;
  final bool currentUserReacted;
  final List<String> reactorFps;
  final DateTime latestTimestamp;

  ReactionGroup({
    required this.emoji,
    required this.count,
    required this.currentUserReacted,
    required this.reactorFps,
    required this.latestTimestamp,
  });
}

/// Fetches the live reaction list for a target message hash and groups
/// entries by emoji for UI rendering (reaction chips under bubbles).
///
/// Parameter: 64-hex target content hash of the message being reacted to.
final reactionsForMessageProvider =
    FutureProvider.family<List<ReactionGroup>, String>((ref, targetHash) async {
  final engine = await ref.watch(engineProvider.future);
  final currentFp = ref.watch(currentFingerprintProvider);

  final entries = await engine.getReactions(targetHash);

  // Group by emoji, preserving insertion order of first occurrence.
  final groups = <String, List<ReactionEntry>>{};
  for (final e in entries) {
    groups.putIfAbsent(e.emoji, () => <ReactionEntry>[]).add(e);
  }

  return groups.entries.map((g) {
    final fps = g.value.map((e) => e.reactorFingerprint).toList();
    final latest = g.value
        .map((e) => e.timestamp)
        .reduce((a, b) => a.isAfter(b) ? a : b);
    return ReactionGroup(
      emoji: g.key,
      count: g.value.length,
      currentUserReacted: currentFp != null && fps.contains(currentFp),
      reactorFps: fps,
      latestTimestamp: latest,
    );
  }).toList();
});
