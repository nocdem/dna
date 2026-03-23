import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';
import '../../design_system/design_system.dart';
import '../../ffi/dna_engine.dart';
import '../../providers/engine_provider.dart';
import '../../providers/wall_provider.dart';
import '../../widgets/wall_post_tile.dart';
import '../../l10n/app_localizations.dart';
import '../../widgets/wall_comment_tile.dart';
import 'wall_tip_dialog.dart';

/// Detail screen for a wall post with threaded comments.
/// Receives initial data from WallFeedItem to avoid redundant fetches.
class WallPostDetailScreen extends ConsumerStatefulWidget {
  final WallPost post;

  const WallPostDetailScreen({super.key, required this.post});

  @override
  ConsumerState<WallPostDetailScreen> createState() =>
      _WallPostDetailScreenState();
}

class _WallPostDetailScreenState extends ConsumerState<WallPostDetailScreen> {
  final _commentController = TextEditingController();
  String? _replyToUuid;
  String? _replyToAuthor;
  bool _sending = false;

  @override
  void dispose() {
    _commentController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final fingerprint = ref.watch(currentFingerprintProvider) ?? '';
    final commentsAsync = ref.watch(wallCommentsProvider(widget.post.uuid));

    // Get like data from the timeline provider (single source of truth)
    final timelineItems = ref.watch(wallTimelineProvider).valueOrNull ?? [];
    final feedItem = timelineItems
        .where((item) => item.post.uuid == widget.post.uuid)
        .firstOrNull;
    final likeCount = feedItem?.likeCount ?? 0;
    final isLiked = feedItem?.isLikedByMe ?? false;

    return Scaffold(
      appBar: DnaAppBar(
        title: AppLocalizations.of(context).wallPostDetail,
        actions: [
          IconButton(
            icon: const FaIcon(FontAwesomeIcons.arrowsRotate, size: 20),
            onPressed: () =>
                ref.invalidate(wallCommentsProvider(widget.post.uuid)),
            tooltip: 'Refresh',
          ),
        ],
      ),
      body: Column(
        children: [
          // Scrollable content: post + comments
          Expanded(
            child: CustomScrollView(
              slivers: [
                // The wall post
                SliverToBoxAdapter(
                  child: WallPostTile(
                    post: widget.post,
                    myFingerprint: fingerprint,
                    authorDisplayName: feedItem?.authorDisplayName,
                    authorAvatar: feedItem?.authorAvatar,
                    decodedImage: feedItem?.decodedImage,
                    likeCount: likeCount,
                    isLikedByMe: isLiked,
                    onLike: isLiked
                        ? null
                        : () => ref
                            .read(wallTimelineProvider.notifier)
                            .likePost(widget.post.uuid),
                    onTip: !widget.post.isOwn(fingerprint)
                        ? () => showWallTipDialog(
                              context: context,
                              ref: ref,
                              post: widget.post,
                            )
                        : null,
                  ),
                ),
                // Comments header
                SliverToBoxAdapter(
                  child: Padding(
                    padding: const EdgeInsets.symmetric(
                      horizontal: DnaSpacing.lg,
                      vertical: DnaSpacing.sm,
                    ),
                    child: commentsAsync.when(
                      skipLoadingOnReload: true,
                      skipLoadingOnRefresh: true,
                      data: (comments) => Text(
                        comments.isEmpty
                            ? AppLocalizations.of(context).wallNoComments
                            : '${comments.length} ${AppLocalizations.of(context).wallComments}',
                        style: theme.textTheme.titleSmall?.copyWith(
                          color: theme.colorScheme.onSurfaceVariant,
                        ),
                      ),
                      loading: () => Text(
                        AppLocalizations.of(context).wallLoadingComments,
                        style: theme.textTheme.titleSmall?.copyWith(
                          color: theme.colorScheme.onSurfaceVariant,
                        ),
                      ),
                      error: (e, _) => Text(
                        'Error loading comments',
                        style: theme.textTheme.titleSmall?.copyWith(
                          color: DnaColors.error,
                        ),
                      ),
                    ),
                  ),
                ),
                const SliverToBoxAdapter(
                  child: Divider(height: 1),
                ),
                // Comments list (threaded)
                commentsAsync.when(
                  skipLoadingOnReload: true,
                  skipLoadingOnRefresh: true,
                  data: (comments) => _buildCommentsList(comments),
                  loading: () => const SliverToBoxAdapter(
                    child: Padding(
                      padding: EdgeInsets.all(DnaSpacing.xl),
                      child: Center(child: CircularProgressIndicator()),
                    ),
                  ),
                  error: (e, _) => SliverToBoxAdapter(
                    child: Padding(
                      padding: const EdgeInsets.all(DnaSpacing.xl),
                      child: Center(child: Text('Error: $e')),
                    ),
                  ),
                ),
              ],
            ),
          ),
          // Reply indicator
          if (_replyToUuid != null)
            Container(
              padding: const EdgeInsets.symmetric(
                horizontal: DnaSpacing.lg,
                vertical: DnaSpacing.xs,
              ),
              color: theme.colorScheme.surfaceContainerHighest,
              child: Row(
                children: [
                  FaIcon(
                    FontAwesomeIcons.reply,
                    size: 12,
                    color: theme.colorScheme.primary,
                  ),
                  const SizedBox(width: DnaSpacing.sm),
                  Expanded(
                    child: Text(
                      'Replying to ${_replyToAuthor ?? 'comment'}',
                      style: theme.textTheme.bodySmall?.copyWith(
                        color: theme.colorScheme.primary,
                      ),
                    ),
                  ),
                  IconButton(
                    icon: const FaIcon(FontAwesomeIcons.xmark, size: 14),
                    onPressed: () => setState(() {
                      _replyToUuid = null;
                      _replyToAuthor = null;
                    }),
                    constraints: const BoxConstraints(),
                    padding: EdgeInsets.zero,
                  ),
                ],
              ),
            ),
          // Comment input
          SafeArea(
            child: Container(
              padding: const EdgeInsets.symmetric(
                horizontal: DnaSpacing.md,
                vertical: DnaSpacing.sm,
              ),
              decoration: BoxDecoration(
                color: theme.colorScheme.surface,
                border: Border(
                  top: BorderSide(
                    color: theme.colorScheme.outlineVariant.withAlpha(80),
                  ),
                ),
              ),
              child: Row(
                children: [
                  Expanded(
                    child: TextField(
                      controller: _commentController,
                      decoration: InputDecoration(
                        hintText: _replyToUuid != null
                            ? AppLocalizations.of(context).wallWriteReply
                            : AppLocalizations.of(context).wallWriteComment,
                        border: OutlineInputBorder(
                          borderRadius:
                              BorderRadius.circular(DnaSpacing.radiusMd),
                          borderSide: BorderSide.none,
                        ),
                        filled: true,
                        fillColor:
                            theme.colorScheme.surfaceContainerHighest,
                        contentPadding: const EdgeInsets.symmetric(
                          horizontal: DnaSpacing.md,
                          vertical: DnaSpacing.sm,
                        ),
                        isDense: true,
                      ),
                      maxLines: 3,
                      minLines: 1,
                      textInputAction: TextInputAction.send,
                      onSubmitted: (_) => _submitComment(),
                    ),
                  ),
                  const SizedBox(width: DnaSpacing.sm),
                  IconButton(
                    icon: _sending
                        ? const SizedBox(
                            width: 20,
                            height: 20,
                            child: CircularProgressIndicator(strokeWidth: 2),
                          )
                        : FaIcon(
                            FontAwesomeIcons.paperPlane,
                            size: 20,
                            color: theme.colorScheme.primary,
                          ),
                    onPressed: _sending ? null : _submitComment,
                  ),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }

  /// Build threaded comments: top-level first, replies indented under parent
  Widget _buildCommentsList(List<WallComment> comments) {
    // Separate top-level and replies
    final topLevel = comments.where((c) => !c.isReply).toList();
    final replies = <String, List<WallComment>>{};
    for (final c in comments.where((c) => c.isReply)) {
      replies.putIfAbsent(c.parentCommentUuid!, () => []).add(c);
    }

    // Build flat list with threading
    final items = <_CommentItem>[];
    for (final comment in topLevel) {
      items.add(_CommentItem(comment: comment, isReply: false));
      final childReplies = replies[comment.uuid];
      if (childReplies != null) {
        for (final reply in childReplies) {
          items.add(_CommentItem(comment: reply, isReply: true));
        }
      }
    }

    if (items.isEmpty) {
      return const SliverToBoxAdapter(child: SizedBox.shrink());
    }

    return SliverPadding(
      padding: const EdgeInsets.symmetric(
        horizontal: DnaSpacing.lg,
        vertical: DnaSpacing.sm,
      ),
      sliver: SliverList(
        delegate: SliverChildBuilderDelegate(
          (context, index) {
            final item = items[index];
            return WallCommentTile(
              comment: item.comment,
              isReply: item.isReply,
              onReply: item.isReply
                  ? null
                  : () => setState(() {
                        _replyToUuid = item.comment.uuid;
                        _replyToAuthor = item.comment.authorName.isNotEmpty
                            ? item.comment.authorName
                            : null;
                      }),
            );
          },
          childCount: items.length,
        ),
      ),
    );
  }

  Future<void> _submitComment() async {
    final text = _commentController.text.trim();
    if (text.isEmpty || _sending) return;

    setState(() => _sending = true);

    try {
      await ref
          .read(wallCommentsProvider(widget.post.uuid).notifier)
          .addComment(
            text,
            parentCommentUuid: _replyToUuid,
          );
      _commentController.clear();
      setState(() {
        _replyToUuid = null;
        _replyToAuthor = null;
      });
      // Also update the comment count in the timeline
      ref
          .read(wallTimelineProvider.notifier)
          .refreshComments(widget.post.uuid);
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Failed to add comment: $e')),
        );
      }
    } finally {
      if (mounted) setState(() => _sending = false);
    }
  }
}

/// Helper class for threaded comment list
class _CommentItem {
  final WallComment comment;
  final bool isReply;

  _CommentItem({required this.comment, required this.isReply});
}
