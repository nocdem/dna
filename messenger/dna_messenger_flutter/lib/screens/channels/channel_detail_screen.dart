// Channel Detail Screen - shows the post stream for a single channel
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';
import '../../design_system/design_system.dart';
import '../../providers/providers.dart';
import '../../models/channel.dart';
import '../../utils/time_format.dart';

class ChannelDetailScreen extends ConsumerStatefulWidget {
  final String channelUuid;
  final String channelName;

  const ChannelDetailScreen({
    super.key,
    required this.channelUuid,
    required this.channelName,
  });

  @override
  ConsumerState<ChannelDetailScreen> createState() =>
      _ChannelDetailScreenState();
}

class _ChannelDetailScreenState extends ConsumerState<ChannelDetailScreen> {
  final _postController = TextEditingController();
  bool _sending = false;

  @override
  void initState() {
    super.initState();
    // Mark channel as read when opened
    ref.listenManual(engineProvider, (_, next) {
      next.whenData((engine) => engine.channelMarkRead(widget.channelUuid));
    }, fireImmediately: true);
  }

  @override
  void dispose() {
    _postController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final postsAsync = ref.watch(channelPostsProvider(widget.channelUuid));
    final nameCache = ref.watch(nameResolverProvider);

    return Scaffold(
      appBar: DnaAppBar(
        title: widget.channelName,
        actions: [
          IconButton(
            icon: const FaIcon(FontAwesomeIcons.arrowsRotate, size: 20),
            onPressed: () => ref
                .read(channelPostsProvider(widget.channelUuid).notifier)
                .refresh(),
            tooltip: 'Refresh',
          ),
          IconButton(
            icon: const FaIcon(FontAwesomeIcons.rightFromBracket, size: 20),
            onPressed: () => _confirmUnsubscribe(context),
            tooltip: 'Unsubscribe',
          ),
        ],
      ),
      body: Column(
        children: [
          // Post list
          Expanded(
            child: postsAsync.when(
              skipLoadingOnReload: true,
              skipLoadingOnRefresh: true,
              data: (posts) {
                if (posts.isEmpty) {
                  return Center(
                    child: Column(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        FaIcon(
                          FontAwesomeIcons.commentSlash,
                          size: 48,
                          color: theme.colorScheme.onSurfaceVariant
                              .withAlpha(100),
                        ),
                        const SizedBox(height: DnaSpacing.lg),
                        Text(
                          'No posts yet \u2014 be the first to post!',
                          style: theme.textTheme.bodyLarge?.copyWith(
                            color: theme.colorScheme.onSurfaceVariant,
                          ),
                        ),
                      ],
                    ),
                  );
                }

                // Trigger name resolution for all authors
                final fingerprints =
                    posts.map((p) => p.authorFingerprint).toSet().toList();
                WidgetsBinding.instance.addPostFrameCallback((_) {
                  ref
                      .read(nameResolverProvider.notifier)
                      .resolveNames(fingerprints);
                });

                // Sort newest first
                final sorted = List<ChannelPost>.from(posts)
                  ..sort((a, b) => b.createdAt.compareTo(a.createdAt));

                final notifier = ref.read(
                    channelPostsProvider(widget.channelUuid).notifier);
                final canLoadMore = notifier.canLoadMore;

                return RefreshIndicator(
                  onRefresh: () => ref
                      .read(
                          channelPostsProvider(widget.channelUuid).notifier)
                      .refresh(),
                  child: ListView.builder(
                    reverse: true,
                    padding: const EdgeInsets.symmetric(
                      horizontal: DnaSpacing.md,
                      vertical: DnaSpacing.sm,
                    ),
                    itemCount: sorted.length + (canLoadMore ? 1 : 0),
                    itemBuilder: (context, index) {
                      // Last item in reversed list = top of screen = "Load older"
                      if (canLoadMore && index == sorted.length) {
                        return Padding(
                          padding: const EdgeInsets.symmetric(
                              vertical: DnaSpacing.md),
                          child: Center(
                            child: TextButton.icon(
                              icon: const FaIcon(
                                  FontAwesomeIcons.clockRotateLeft,
                                  size: 14),
                              label: const Text('Load older posts'),
                              onPressed: () => ref
                                  .read(channelPostsProvider(
                                          widget.channelUuid)
                                      .notifier)
                                  .loadMore(),
                            ),
                          ),
                        );
                      }
                      // Reverse index since list is reversed
                      final post = sorted[sorted.length - 1 - index];
                      return _PostCard(
                        post: post,
                        nameCache: nameCache,
                      );
                    },
                  ),
                );
              },
              loading: () => const Center(
                child: CircularProgressIndicator(),
              ),
              error: (e, _) => Center(
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    FaIcon(
                      FontAwesomeIcons.circleExclamation,
                      size: 48,
                      color: DnaColors.error,
                    ),
                    const SizedBox(height: DnaSpacing.lg),
                    Text(
                      'Failed to load posts',
                      style: theme.textTheme.bodyLarge,
                    ),
                    const SizedBox(height: DnaSpacing.sm),
                    TextButton.icon(
                      icon: const FaIcon(FontAwesomeIcons.arrowsRotate,
                          size: 14),
                      label: const Text('Retry'),
                      onPressed: () => ref
                          .read(channelPostsProvider(widget.channelUuid)
                              .notifier)
                          .refresh(),
                    ),
                  ],
                ),
              ),
            ),
          ),
          // Post input
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
                      controller: _postController,
                      decoration: InputDecoration(
                        hintText: 'Write a post...',
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
                      onSubmitted: (_) => _submitPost(),
                    ),
                  ),
                  const SizedBox(width: DnaSpacing.sm),
                  IconButton(
                    icon: _sending
                        ? const SizedBox(
                            width: 20,
                            height: 20,
                            child:
                                CircularProgressIndicator(strokeWidth: 2),
                          )
                        : FaIcon(
                            FontAwesomeIcons.paperPlane,
                            size: 20,
                            color: theme.colorScheme.primary,
                          ),
                    onPressed: _sending ? null : _submitPost,
                  ),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }

  Future<void> _submitPost() async {
    final text = _postController.text.trim();
    if (text.isEmpty || _sending) return;

    setState(() => _sending = true);

    try {
      await ref
          .read(channelPostsProvider(widget.channelUuid).notifier)
          .addPost(text);
      _postController.clear();
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Failed to post: $e')),
        );
      }
    } finally {
      if (mounted) setState(() => _sending = false);
    }
  }

  void _confirmUnsubscribe(BuildContext context) {
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Unsubscribe'),
        content: Text(
            'Unsubscribe from "${widget.channelName}"? You can re-subscribe later from Discover.'),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(),
            child: const Text('Cancel'),
          ),
          TextButton(
            onPressed: () async {
              final navigator = Navigator.of(context);
              Navigator.of(ctx).pop();
              final success = await ref
                  .read(channelSubscriptionsProvider.notifier)
                  .unsubscribe(widget.channelUuid);
              if (success && mounted) {
                navigator.pop();
              }
            },
            child: const Text('Unsubscribe'),
          ),
        ],
      ),
    );
  }
}

/// Card widget for displaying a single channel post
class _PostCard extends StatelessWidget {
  final ChannelPost post;
  final Map<String, String> nameCache;

  const _PostCard({
    required this.post,
    required this.nameCache,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final authorName = nameCache[post.authorFingerprint];
    final displayAuthor = authorName != null && authorName.isNotEmpty
        ? authorName
        : '${post.authorFingerprint.substring(0, 16)}...';

    return Card(
      margin: const EdgeInsets.only(bottom: DnaSpacing.sm),
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(DnaSpacing.radiusMd),
      ),
      child: Padding(
        padding: const EdgeInsets.all(DnaSpacing.md),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Author + time row
            Row(
              children: [
                FaIcon(
                  FontAwesomeIcons.solidUser,
                  size: 14,
                  color: theme.colorScheme.primary,
                ),
                const SizedBox(width: DnaSpacing.sm),
                Expanded(
                  child: Text(
                    displayAuthor,
                    style: theme.textTheme.labelLarge?.copyWith(
                      fontWeight: FontWeight.w600,
                    ),
                    overflow: TextOverflow.ellipsis,
                  ),
                ),
                if (post.verified)
                  Padding(
                    padding: const EdgeInsets.only(right: DnaSpacing.xs),
                    child: FaIcon(
                      FontAwesomeIcons.solidCircleCheck,
                      size: 14,
                      color: theme.colorScheme.primary,
                    ),
                  ),
                Text(
                  formatRelativeTime(post.createdAt),
                  style: theme.textTheme.bodySmall?.copyWith(
                    color: theme.colorScheme.onSurfaceVariant,
                  ),
                ),
              ],
            ),
            const SizedBox(height: DnaSpacing.sm),
            // Post body
            SelectableText(
              post.body,
              style: theme.textTheme.bodyMedium,
            ),
          ],
        ),
      ),
    );
  }
}
