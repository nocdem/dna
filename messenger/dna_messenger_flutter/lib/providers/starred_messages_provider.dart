// Starred Messages Provider - Manages starred/bookmarked messages
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../services/cache_database.dart';

/// Provider for starred message IDs (keyed by contact fingerprint)
final starredMessagesProvider = StateNotifierProviderFamily<StarredMessagesNotifier, Set<int>, String>(
  (ref, contactFp) => StarredMessagesNotifier(contactFp),
);

class StarredMessagesNotifier extends StateNotifier<Set<int>> {
  final String contactFp;
  final _db = CacheDatabase.instance;

  StarredMessagesNotifier(this.contactFp) : super({}) {
    _loadStarredMessages();
  }

  Future<void> _loadStarredMessages() async {
    final starredIds = await _db.getStarredMessageIds(contactFp);
    state = starredIds;
  }

  /// Toggle star status for a message
  Future<void> toggleStar(int messageId) async {
    if (state.contains(messageId)) {
      await _db.unstarMessage(messageId);
      state = {...state}..remove(messageId);
    } else {
      await _db.starMessage(messageId, contactFp);
      state = {...state, messageId};
    }
  }

  /// Check if a message is starred
  bool isStarred(int messageId) => state.contains(messageId);

  /// Star a message
  Future<void> star(int messageId) async {
    if (!state.contains(messageId)) {
      await _db.starMessage(messageId, contactFp);
      state = {...state, messageId};
    }
  }

  /// Unstar a message
  Future<void> unstar(int messageId) async {
    if (state.contains(messageId)) {
      await _db.unstarMessage(messageId);
      state = {...state}..remove(messageId);
    }
  }
}
