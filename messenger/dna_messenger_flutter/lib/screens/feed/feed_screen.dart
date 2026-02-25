// Feed v2 Screen - Topic-based public feeds with categories and subscriptions
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';
import 'package:intl/intl.dart';
import '../../design_system/design_system.dart';
import '../../ffi/dna_engine.dart';
import '../../providers/providers.dart';
import '../../utils/time_format.dart';

class FeedScreen extends ConsumerWidget {
  const FeedScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final selectedCategory = ref.watch(feedCategoryProvider);
    final topics = ref.watch(feedTopicsProvider);

    return Scaffold(
      appBar: DnaAppBar(
        title: 'Feed',
        actions: [
          IconButton(
            icon: const FaIcon(FontAwesomeIcons.arrowsRotate),
            onPressed: () => ref.invalidate(feedTopicsProvider),
            tooltip: 'Refresh',
          ),
          PopupMenuButton<String>(
            icon: const FaIcon(FontAwesomeIcons.bookmark),
            tooltip: 'Subscriptions',
            onSelected: (value) {
              if (value == 'view_subscribed') {
                _showSubscribedTopics(context, ref);
              } else if (value == 'sync_to_dht') {
                _syncSubscriptionsToDht(context, ref);
              } else if (value == 'sync_from_dht') {
                _syncSubscriptionsFromDht(context, ref);
              }
            },
            itemBuilder: (context) => [
              const PopupMenuItem(
                value: 'view_subscribed',
                child: Row(
                  children: [
                    FaIcon(FontAwesomeIcons.solidBookmark, size: 16),
                    SizedBox(width: 12),
                    Text('My Subscriptions'),
                  ],
                ),
              ),
              const PopupMenuDivider(),
              const PopupMenuItem(
                value: 'sync_to_dht',
                child: Row(
                  children: [
                    FaIcon(FontAwesomeIcons.cloudArrowUp, size: 16),
                    SizedBox(width: 12),
                    Text('Sync to DHT'),
                  ],
                ),
              ),
              const PopupMenuItem(
                value: 'sync_from_dht',
                child: Row(
                  children: [
                    FaIcon(FontAwesomeIcons.cloudArrowDown, size: 16),
                    SizedBox(width: 12),
                    Text('Sync from DHT'),
                  ],
                ),
              ),
            ],
          ),
        ],
        bottom: PreferredSize(
          preferredSize: const Size.fromHeight(48),
          child: _CategoryTabs(
            selectedCategory: selectedCategory,
            onCategorySelected: (cat) => ref.read(feedCategoryProvider.notifier).state = cat,
          ),
        ),
      ),
      body: topics.when(
        skipLoadingOnReload: true,
        skipLoadingOnRefresh: true,
        data: (topicList) => _TopicsList(topics: topicList),
        loading: () => const Center(child: CircularProgressIndicator()),
        error: (error, stack) => _ErrorView(
          error: error,
          onRetry: () => ref.invalidate(feedTopicsProvider),
        ),
      ),
      floatingActionButton: FloatingActionButton(
        heroTag: 'feed_fab',
        onPressed: () => _showCreateTopicDialog(context, ref),
        tooltip: 'Create Topic',
        child: const FaIcon(FontAwesomeIcons.plus),
      ),
    );
  }

  void _showCreateTopicDialog(BuildContext context, WidgetRef ref) {
    showDialog(
      context: context,
      builder: (context) => _CreateTopicDialog(ref: ref),
    );
  }

  void _showSubscribedTopics(BuildContext context, WidgetRef ref) {
    Navigator.of(context).push(
      MaterialPageRoute(
        builder: (context) => const _SubscribedTopicsScreen(),
      ),
    );
  }

  Future<void> _syncSubscriptionsToDht(BuildContext context, WidgetRef ref) async {
    try {
      await ref.read(feedSubscriptionsProvider.notifier).syncToDht();
      if (context.mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Subscriptions synced to DHT')),
        );
      }
    } catch (e) {
      if (context.mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Sync failed: $e')),
        );
      }
    }
  }

  Future<void> _syncSubscriptionsFromDht(BuildContext context, WidgetRef ref) async {
    try {
      await ref.read(feedSubscriptionsProvider.notifier).syncFromDht();
      if (context.mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Subscriptions synced from DHT')),
        );
      }
    } catch (e) {
      if (context.mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Sync failed: $e')),
        );
      }
    }
  }
}

// =============================================================================
// CATEGORY TABS
// =============================================================================

class _CategoryTabs extends StatelessWidget {
  final String? selectedCategory;
  final ValueChanged<String?> onCategorySelected;

  const _CategoryTabs({
    required this.selectedCategory,
    required this.onCategorySelected,
  });

  @override
  Widget build(BuildContext context) {
    return SingleChildScrollView(
      scrollDirection: Axis.horizontal,
      padding: const EdgeInsets.symmetric(horizontal: 8),
      child: Row(
        children: [
          _CategoryChip(
            label: 'All',
            isSelected: selectedCategory == null,
            onTap: () => onCategorySelected(null),
          ),
          ...FeedCategories.all.map((cat) => _CategoryChip(
            label: FeedCategories.displayName(cat),
            isSelected: selectedCategory == cat,
            onTap: () => onCategorySelected(cat),
          )),
        ],
      ),
    );
  }
}

class _CategoryChip extends StatelessWidget {
  final String label;
  final bool isSelected;
  final VoidCallback onTap;

  const _CategoryChip({
    required this.label,
    required this.isSelected,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 4, vertical: 8),
      child: DnaChip(
        label: label,
        selected: isSelected,
        onTap: onTap,
      ),
    );
  }
}

// =============================================================================
// TOPICS LIST
// =============================================================================

class _TopicsList extends ConsumerWidget {
  final List<FeedTopic> topics;

  const _TopicsList({required this.topics});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final theme = Theme.of(context);

    if (topics.isEmpty) {
      return Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            FaIcon(
              FontAwesomeIcons.newspaper,
              size: 64,
              color: theme.colorScheme.primary.withAlpha(128),
            ),
            const SizedBox(height: 16),
            Text(
              'No topics yet',
              style: theme.textTheme.titleMedium,
            ),
            const SizedBox(height: 8),
            Text(
              'Tap + to create the first topic',
              style: theme.textTheme.bodySmall,
            ),
          ],
        ),
      );
    }

    // Filter out deleted topics
    final visibleTopics = topics.where((t) => !t.deleted).toList();

    if (visibleTopics.isEmpty) {
      return Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            FaIcon(FontAwesomeIcons.newspaper, size: 64, color: theme.colorScheme.outline),
            const SizedBox(height: 16),
            Text('No topics yet', style: theme.textTheme.titleMedium),
          ],
        ),
      );
    }

    return RefreshIndicator(
      onRefresh: () => ref.read(feedTopicsProvider.notifier).refresh(),
      child: ListView.builder(
        itemCount: visibleTopics.length,
        itemBuilder: (context, index) {
          final topic = visibleTopics[index];
          return _TopicTile(
            topic: topic,
            onTap: () => _openTopic(context, ref, topic),
          );
        },
      ),
    );
  }

  void _openTopic(BuildContext context, WidgetRef ref, FeedTopic topic) {
    ref.read(selectedTopicUuidProvider.notifier).state = topic.uuid;
    Navigator.of(context).push(
      MaterialPageRoute(
        builder: (context) => _TopicDetailScreen(topicUuid: topic.uuid),
      ),
    );
  }
}

class _TopicTile extends ConsumerWidget {
  final FeedTopic topic;
  final VoidCallback onTap;

  const _TopicTile({required this.topic, required this.onTap});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final theme = Theme.of(context);
    final isSubscribed = ref.watch(isSubscribedProvider(topic.uuid));

    // Resolve author name
    final authorName = ref.watch(nameResolverProvider)[topic.authorFingerprint]
        ?? '${topic.authorFingerprint.substring(0, 16)}...';

    // Trigger resolution if not cached
    ref.read(nameResolverProvider.notifier).resolveName(topic.authorFingerprint);

    return DnaCard(
      margin: const EdgeInsets.symmetric(
        horizontal: DnaSpacing.md,
        vertical: DnaSpacing.xs + 2,
      ),
      padding: const EdgeInsets.all(DnaSpacing.lg),
      onTap: onTap,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Author row (social media style - at top)
          Row(
            children: [
              DnaAvatar(
                name: authorName.isNotEmpty ? authorName : '?',
                size: DnaAvatarSize.sm,
              ),
              const SizedBox(width: DnaSpacing.sm),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      authorName,
                      style: theme.textTheme.bodySmall?.copyWith(
                        fontWeight: FontWeight.w600,
                      ),
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                    ),
                    Text(
                      formatRelativeTime(topic.createdAt),
                      style: theme.textTheme.bodySmall?.copyWith(
                        color: theme.colorScheme.onSurfaceVariant,
                        fontSize: 11,
                      ),
                    ),
                  ],
                ),
              ),
              if (isSubscribed)
                FaIcon(
                  FontAwesomeIcons.solidBookmark,
                  size: 13,
                  color: theme.colorScheme.primary,
                ),
            ],
          ),
          const SizedBox(height: DnaSpacing.md),
          // Title
          Text(
            topic.title,
            style: theme.textTheme.titleMedium?.copyWith(
              fontWeight: FontWeight.bold,
              decoration: topic.deleted ? TextDecoration.lineThrough : null,
            ),
            maxLines: 2,
            overflow: TextOverflow.ellipsis,
          ),
          const SizedBox(height: DnaSpacing.xs),
          // Body preview
          Text(
            topic.body,
            style: theme.textTheme.bodyMedium?.copyWith(
              color: theme.colorScheme.onSurfaceVariant,
              height: 1.3,
            ),
            maxLines: 3,
            overflow: TextOverflow.ellipsis,
          ),
          // Category + tags footer
          if (topic.categoryId.isNotEmpty || topic.tags.isNotEmpty) ...[
            const SizedBox(height: DnaSpacing.md),
            Wrap(
              spacing: DnaSpacing.xs,
              runSpacing: DnaSpacing.xs,
              children: [
                _CategoryBadge(category: topic.categoryId),
                ...topic.tags.take(3).map((tag) => DnaChip(label: tag)),
              ],
            ),
          ],
        ],
      ),
    );
  }
}

class _CategoryBadge extends StatelessWidget {
  final String category;

  const _CategoryBadge({required this.category});

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
      decoration: BoxDecoration(
        color: _getCategoryColor(category).withAlpha(50),
        borderRadius: BorderRadius.circular(4),
      ),
      child: Text(
        FeedCategories.displayName(category),
        style: TextStyle(
          fontSize: 10,
          color: _getCategoryColor(category),
          fontWeight: FontWeight.w600,
        ),
      ),
    );
  }

  Color _getCategoryColor(String category) {
    switch (category.toLowerCase()) {
      case 'general':
        return Colors.blue;
      case 'technology':
        return Colors.purple;
      case 'help':
        return Colors.orange;
      case 'announcements':
        return Colors.red;
      case 'trading':
        return Colors.green;
      case 'offtopic':
        return Colors.grey;
      default:
        return Colors.blue;
    }
  }
}

// =============================================================================
// TOPIC DETAIL SCREEN
// =============================================================================

class _TopicDetailScreen extends ConsumerWidget {
  final String topicUuid;

  const _TopicDetailScreen({required this.topicUuid});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final topic = ref.watch(selectedTopicProvider);
    final comments = ref.watch(topicCommentsProvider(topicUuid));
    final isSubscribed = ref.watch(isSubscribedProvider(topicUuid));

    return Scaffold(
      appBar: DnaAppBar(
        title: 'Topic',
        actions: [
          IconButton(
            icon: FaIcon(
              isSubscribed ? FontAwesomeIcons.solidBookmark : FontAwesomeIcons.bookmark,
              size: 20,
            ),
            onPressed: () => _toggleSubscription(context, ref),
            tooltip: isSubscribed ? 'Unsubscribe' : 'Subscribe',
          ),
          IconButton(
            icon: const FaIcon(FontAwesomeIcons.arrowsRotate, size: 20),
            onPressed: () {
              ref.invalidate(selectedTopicProvider);
              ref.invalidate(topicCommentsProvider(topicUuid));
            },
            tooltip: 'Refresh',
          ),
        ],
      ),
      body: topic.when(
        skipLoadingOnReload: true,
        skipLoadingOnRefresh: true,
        data: (t) => t != null
            ? _TopicDetailContent(
                topic: t,
                comments: comments,
              )
            : const Center(child: Text('Topic not found')),
        loading: () => const Center(child: CircularProgressIndicator()),
        error: (e, st) => Center(child: Text('Error: $e')),
      ),
      floatingActionButton: FloatingActionButton(
        heroTag: 'topic_comment_fab',
        onPressed: () => _showAddCommentDialog(context, ref),
        tooltip: 'Add Comment',
        child: const FaIcon(FontAwesomeIcons.comment),
      ),
    );
  }

  Future<void> _toggleSubscription(BuildContext context, WidgetRef ref) async {
    try {
      await ref.read(feedSubscriptionsProvider.notifier).toggleSubscription(topicUuid);
      final isNowSubscribed = ref.read(isSubscribedProvider(topicUuid));
      if (context.mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(isNowSubscribed ? 'Subscribed' : 'Unsubscribed'),
            duration: const Duration(seconds: 1),
          ),
        );
      }
    } catch (e) {
      if (context.mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Error: $e')),
        );
      }
    }
  }

  void _showAddCommentDialog(BuildContext context, WidgetRef ref) {
    showDialog(
      context: context,
      builder: (context) => _AddCommentDialog(topicUuid: topicUuid, ref: ref),
    );
  }
}

class _TopicDetailContent extends ConsumerWidget {
  final FeedTopic topic;
  final AsyncValue<List<FeedComment>> comments;

  const _TopicDetailContent({
    required this.topic,
    required this.comments,
  });

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final theme = Theme.of(context);
    final nameResolver = ref.watch(nameResolverProvider.notifier);

    // Trigger batch name resolution when comments load
    comments.whenData((commentList) {
      if (commentList.isNotEmpty) {
        final fingerprints = commentList.map((c) => c.authorFingerprint).toSet().toList();
        // Also resolve topic author
        fingerprints.add(topic.authorFingerprint);
        nameResolver.resolveNames(fingerprints);
      }
    });

    // Get resolved topic author name
    final topicAuthorName = ref.watch(nameResolverProvider)[topic.authorFingerprint]
        ?? '${topic.authorFingerprint.substring(0, 16)}...';

    return CustomScrollView(
      slivers: [
        // Topic header
        SliverToBoxAdapter(
          child: DnaCard(
            margin: const EdgeInsets.all(12),
            padding: const EdgeInsets.all(16),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  topic.title,
                  style: theme.textTheme.headlineSmall?.copyWith(
                    fontWeight: FontWeight.bold,
                    decoration: topic.deleted ? TextDecoration.lineThrough : null,
                  ),
                ),
                if (topic.deleted)
                  Padding(
                    padding: const EdgeInsets.only(top: 8),
                    child: Text(
                      '[Deleted]',
                      style: TextStyle(
                        color: DnaColors.textWarning,
                        fontStyle: FontStyle.italic,
                      ),
                    ),
                  ),
                const SizedBox(height: 16),
                Text(
                  topic.body,
                  style: theme.textTheme.bodyLarge,
                ),
                const SizedBox(height: 16),
                Wrap(
                  spacing: DnaSpacing.xs,
                  runSpacing: DnaSpacing.xs,
                  children: [
                    _CategoryBadge(category: topic.categoryId),
                    ...topic.tags.map((tag) => DnaChip(label: tag)),
                  ],
                ),
                const SizedBox(height: DnaSpacing.md),
                Row(
                  children: [
                    DnaAvatar(
                      name: topicAuthorName.isNotEmpty ? topicAuthorName : '?',
                      size: DnaAvatarSize.sm,
                    ),
                    const SizedBox(width: DnaSpacing.sm),
                    Expanded(
                      child: Text(
                        topicAuthorName,
                        style: theme.textTheme.bodySmall?.copyWith(
                          fontWeight: FontWeight.w600,
                        ),
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                      ),
                    ),
                    Text(
                      DateFormat('MMM d, yyyy h:mm a').format(topic.createdAt),
                      style: theme.textTheme.bodySmall?.copyWith(
                        color: theme.colorScheme.onSurfaceVariant,
                      ),
                    ),
                  ],
                ),
              ],
            ),
          ),
        ),
        // Comments header
        SliverToBoxAdapter(
          child: Padding(
            padding: const EdgeInsets.fromLTRB(16, 8, 16, 8),
            child: Text(
              'Comments',
              style: theme.textTheme.titleMedium?.copyWith(
                fontWeight: FontWeight.bold,
              ),
            ),
          ),
        ),
        // Comments list (threaded view)
        comments.when(
          skipLoadingOnReload: true,
          skipLoadingOnRefresh: true,
          data: (commentList) {
            if (commentList.isEmpty) {
              return SliverToBoxAdapter(
                child: Padding(
                  padding: const EdgeInsets.all(32),
                  child: Center(
                    child: Text(
                      'No comments yet',
                      style: theme.textTheme.bodyMedium?.copyWith(
                        color: theme.colorScheme.onSurfaceVariant,
                      ),
                    ),
                  ),
                ),
              );
            }

            // Build threaded comment list:
            // 1. Separate into top-level and replies
            // 2. Group replies under their parent
            final topLevel = commentList.where((c) => !c.isReply).toList();
            final replies = commentList.where((c) => c.isReply).toList();

            // Create map of parent -> replies
            final replyMap = <String, List<FeedComment>>{};
            for (final reply in replies) {
              final parent = reply.parentCommentUuid!;
              replyMap.putIfAbsent(parent, () => []);
              replyMap[parent]!.add(reply);
            }

            // Sort replies by time within each group (newest first)
            for (final list in replyMap.values) {
              list.sort((a, b) => b.createdAt.compareTo(a.createdAt));
            }

            // Build flat list with threading
            final threadedList = <_ThreadedComment>[];
            for (final comment in topLevel) {
              threadedList.add(_ThreadedComment(comment: comment, isReply: false));
              // Add any replies
              final commentReplies = replyMap[comment.uuid] ?? [];
              for (final reply in commentReplies) {
                threadedList.add(_ThreadedComment(comment: reply, isReply: true));
              }
            }

            return SliverList(
              delegate: SliverChildBuilderDelegate(
                (context, index) {
                  final item = threadedList[index];
                  return _CommentTile(
                    comment: item.comment,
                    isReply: item.isReply,
                    onReply: item.isReply ? null : () {
                      _showReplyDialog(context, ref, topic.uuid, item.comment);
                    },
                  );
                },
                childCount: threadedList.length,
              ),
            );
          },
          loading: () => const SliverToBoxAdapter(
            child: Center(child: Padding(
              padding: EdgeInsets.all(32),
              child: CircularProgressIndicator(),
            )),
          ),
          error: (e, st) => SliverToBoxAdapter(
            child: Center(child: Text('Error: $e')),
          ),
        ),
        // Bottom spacing
        const SliverToBoxAdapter(child: SizedBox(height: 80)),
      ],
    );
  }
}

/// Helper class for threaded comment display
class _ThreadedComment {
  final FeedComment comment;
  final bool isReply;

  const _ThreadedComment({required this.comment, required this.isReply});
}

/// Show reply dialog for a specific comment
void _showReplyDialog(BuildContext context, WidgetRef ref, String topicUuid, FeedComment parentComment) {
  showDialog(
    context: context,
    builder: (context) => _ReplyCommentDialog(
      topicUuid: topicUuid,
      parentComment: parentComment,
      ref: ref,
    ),
  );
}

class _CommentTile extends ConsumerWidget {
  final FeedComment comment;
  final VoidCallback? onReply;
  final bool isReply;

  const _CommentTile({
    required this.comment,
    this.onReply,
    this.isReply = false,
  });

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final theme = Theme.of(context);

    // Get resolved author name or fall back to fingerprint prefix
    final authorName = ref.watch(nameResolverProvider)[comment.authorFingerprint]
        ?? '${comment.authorFingerprint.substring(0, 16)}...';

    // Resolve mention names
    final resolvedNames = ref.watch(nameResolverProvider);

    Widget card = DnaCard(
      margin: EdgeInsets.only(
        left: isReply ? DnaSpacing.xl + DnaSpacing.md : DnaSpacing.md,
        right: DnaSpacing.md,
        top: DnaSpacing.xs,
        bottom: DnaSpacing.xs,
      ),
      padding: const EdgeInsets.all(DnaSpacing.md),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Author row with avatar
          Row(
            children: [
              DnaAvatar(
                name: authorName.isNotEmpty ? authorName : '?',
                size: DnaAvatarSize.sm,
              ),
              const SizedBox(width: DnaSpacing.sm),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      authorName,
                      style: theme.textTheme.bodySmall?.copyWith(
                        fontWeight: FontWeight.w600,
                      ),
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                    ),
                    Text(
                      formatRelativeTime(comment.createdAt),
                      style: theme.textTheme.bodySmall?.copyWith(
                        color: theme.colorScheme.onSurfaceVariant,
                        fontSize: 11,
                      ),
                    ),
                  ],
                ),
              ),
              if (isReply)
                FaIcon(
                  FontAwesomeIcons.reply,
                  size: 11,
                  color: theme.colorScheme.primary.withAlpha(160),
                ),
            ],
          ),
          const SizedBox(height: DnaSpacing.sm),
          // Comment body
          Text(
            comment.body,
            style: theme.textTheme.bodyMedium?.copyWith(height: 1.4),
          ),
          // Mentions
          if (comment.mentions.isNotEmpty) ...[
            const SizedBox(height: DnaSpacing.sm),
            Wrap(
              spacing: DnaSpacing.xs,
              runSpacing: DnaSpacing.xs,
              children: comment.mentions.map((m) {
                final mentionName = resolvedNames[m]
                    ?? '@${m.substring(0, 8)}...';
                return DnaChip(label: mentionName);
              }).toList(),
            ),
          ],
          // Reply button
          if (!isReply && onReply != null) ...[
            const SizedBox(height: DnaSpacing.xs),
            Align(
              alignment: Alignment.centerRight,
              child: InkWell(
                onTap: onReply,
                borderRadius: BorderRadius.circular(DnaSpacing.radiusSm),
                child: Padding(
                  padding: const EdgeInsets.symmetric(
                    horizontal: DnaSpacing.sm,
                    vertical: DnaSpacing.xs,
                  ),
                  child: Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      FaIcon(
                        FontAwesomeIcons.reply,
                        size: 12,
                        color: theme.colorScheme.onSurfaceVariant,
                      ),
                      const SizedBox(width: DnaSpacing.xs),
                      Text(
                        'Reply',
                        style: theme.textTheme.bodySmall?.copyWith(
                          color: theme.colorScheme.onSurfaceVariant,
                        ),
                      ),
                    ],
                  ),
                ),
              ),
            ),
          ],
        ],
      ),
    );

    // Add left border accent for replies
    if (isReply) {
      card = Stack(
        children: [
          card,
          Positioned(
            left: DnaSpacing.xl + DnaSpacing.md,
            top: DnaSpacing.xs,
            bottom: DnaSpacing.xs,
            child: Container(
              width: 3,
              decoration: BoxDecoration(
                color: theme.colorScheme.primary.withAlpha(120),
                borderRadius: BorderRadius.circular(2),
              ),
            ),
          ),
        ],
      );
    }

    return card;
  }
}

// =============================================================================
// CREATE TOPIC DIALOG
// =============================================================================

class _CreateTopicDialog extends ConsumerStatefulWidget {
  final WidgetRef ref;

  const _CreateTopicDialog({required this.ref});

  @override
  ConsumerState<_CreateTopicDialog> createState() => _CreateTopicDialogState();
}

class _CreateTopicDialogState extends ConsumerState<_CreateTopicDialog> {
  final _titleController = TextEditingController();
  final _bodyController = TextEditingController();
  final _tagsController = TextEditingController();
  String _selectedCategory = FeedCategories.general;
  bool _isLoading = false;

  @override
  void dispose() {
    _titleController.dispose();
    _bodyController.dispose();
    _tagsController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return AlertDialog(
      title: Row(
        children: [
          FaIcon(FontAwesomeIcons.squarePlus, size: 18, color: theme.colorScheme.primary),
          const SizedBox(width: DnaSpacing.sm),
          const Text('Create Topic'),
        ],
      ),
      content: SizedBox(
        width: double.maxFinite,
        child: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              TextField(
                controller: _titleController,
                decoration: const InputDecoration(
                  hintText: 'Topic title',
                  prefixIcon: Padding(
                    padding: EdgeInsets.only(left: DnaSpacing.md, right: DnaSpacing.sm),
                    child: FaIcon(FontAwesomeIcons.heading, size: 14),
                  ),
                  prefixIconConstraints: BoxConstraints(minWidth: 0, minHeight: 0),
                ),
                maxLength: 200,
              ),
              const SizedBox(height: DnaSpacing.md),
              TextField(
                controller: _bodyController,
                decoration: const InputDecoration(
                  hintText: 'What do you want to discuss?',
                ),
                maxLines: 5,
                maxLength: 4000,
              ),
              const SizedBox(height: DnaSpacing.md),
              DropdownButtonFormField<String>(
                initialValue: _selectedCategory,
                decoration: InputDecoration(
                  hintText: 'Category',
                  prefixIcon: Padding(
                    padding: const EdgeInsets.only(left: DnaSpacing.md, right: DnaSpacing.sm),
                    child: FaIcon(FontAwesomeIcons.layerGroup, size: 14, color: theme.hintColor),
                  ),
                  prefixIconConstraints: const BoxConstraints(minWidth: 0, minHeight: 0),
                ),
                items: FeedCategories.all.map((cat) => DropdownMenuItem(
                  value: cat,
                  child: Text(FeedCategories.displayName(cat)),
                )).toList(),
                onChanged: (value) {
                  if (value != null) {
                    setState(() => _selectedCategory = value);
                  }
                },
              ),
              const SizedBox(height: DnaSpacing.md),
              TextField(
                controller: _tagsController,
                decoration: const InputDecoration(
                  hintText: 'Tags (optional, comma-separated)',
                  prefixIcon: Padding(
                    padding: EdgeInsets.only(left: DnaSpacing.md, right: DnaSpacing.sm),
                    child: FaIcon(FontAwesomeIcons.tags, size: 14),
                  ),
                  prefixIconConstraints: BoxConstraints(minWidth: 0, minHeight: 0),
                ),
              ),
            ],
          ),
        ),
      ),
      actions: [
        DnaButton(
          label: 'Cancel',
          variant: DnaButtonVariant.ghost,
          onPressed: _isLoading ? null : () => Navigator.pop(context),
        ),
        DnaButton(
          label: 'Create',
          loading: _isLoading,
          icon: FontAwesomeIcons.paperPlane,
          onPressed: _isLoading ? null : _createTopic,
        ),
      ],
    );
  }

  Future<void> _createTopic() async {
    final title = _titleController.text.trim();
    final body = _bodyController.text.trim();

    if (title.isEmpty || body.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Title and body are required')),
      );
      return;
    }

    setState(() => _isLoading = true);

    try {
      final tags = _tagsController.text
          .split(',')
          .map((t) => t.trim())
          .where((t) => t.isNotEmpty)
          .take(5)
          .toList();

      await widget.ref.read(feedTopicsProvider.notifier).createTopic(
        title,
        body,
        _selectedCategory,
        tags: tags,
      );

      if (mounted) {
        Navigator.pop(context);
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Topic created')),
        );
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Error: $e')),
        );
      }
    } finally {
      if (mounted) {
        setState(() => _isLoading = false);
      }
    }
  }
}

// =============================================================================
// ADD COMMENT DIALOG
// =============================================================================

class _AddCommentDialog extends ConsumerStatefulWidget {
  final String topicUuid;
  final WidgetRef ref;

  const _AddCommentDialog({required this.topicUuid, required this.ref});

  @override
  ConsumerState<_AddCommentDialog> createState() => _AddCommentDialogState();
}

class _AddCommentDialogState extends ConsumerState<_AddCommentDialog> {
  final _bodyController = TextEditingController();
  bool _isLoading = false;

  @override
  void dispose() {
    _bodyController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return AlertDialog(
      title: Row(
        children: [
          FaIcon(FontAwesomeIcons.comment, size: 18, color: theme.colorScheme.primary),
          const SizedBox(width: DnaSpacing.sm),
          const Text('Add Comment'),
        ],
      ),
      content: SizedBox(
        width: double.maxFinite,
        child: TextField(
          controller: _bodyController,
          decoration: const InputDecoration(
            hintText: 'Share your thoughts...',
          ),
          maxLines: 4,
          maxLength: 2000,
          autofocus: true,
        ),
      ),
      actions: [
        DnaButton(
          label: 'Cancel',
          variant: DnaButtonVariant.ghost,
          onPressed: _isLoading ? null : () => Navigator.pop(context),
        ),
        DnaButton(
          label: 'Post',
          loading: _isLoading,
          icon: FontAwesomeIcons.paperPlane,
          onPressed: _isLoading ? null : _addComment,
        ),
      ],
    );
  }

  Future<void> _addComment() async {
    final body = _bodyController.text.trim();

    if (body.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Comment cannot be empty')),
      );
      return;
    }

    setState(() => _isLoading = true);

    try {
      await widget.ref.read(topicCommentsProvider(widget.topicUuid).notifier).addComment(body);

      if (mounted) {
        Navigator.pop(context);
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Comment posted')),
        );
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Error: $e')),
        );
      }
    } finally {
      if (mounted) {
        setState(() => _isLoading = false);
      }
    }
  }
}

// =============================================================================
// REPLY COMMENT DIALOG
// =============================================================================

class _ReplyCommentDialog extends ConsumerStatefulWidget {
  final String topicUuid;
  final FeedComment parentComment;
  final WidgetRef ref;

  const _ReplyCommentDialog({
    required this.topicUuid,
    required this.parentComment,
    required this.ref,
  });

  @override
  ConsumerState<_ReplyCommentDialog> createState() => _ReplyCommentDialogState();
}

class _ReplyCommentDialogState extends ConsumerState<_ReplyCommentDialog> {
  final _bodyController = TextEditingController();
  bool _isLoading = false;

  @override
  void dispose() {
    _bodyController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    // Get parent comment author name
    final parentAuthorName = ref.watch(nameResolverProvider)[widget.parentComment.authorFingerprint]
        ?? '${widget.parentComment.authorFingerprint.substring(0, 16)}...';

    return AlertDialog(
      title: Row(
        children: [
          FaIcon(FontAwesomeIcons.reply, size: 18, color: theme.colorScheme.primary),
          const SizedBox(width: DnaSpacing.sm),
          const Text('Reply'),
        ],
      ),
      content: SizedBox(
        width: double.maxFinite,
        child: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              // Parent comment preview
              Container(
                width: double.infinity,
                padding: const EdgeInsets.all(DnaSpacing.md),
                decoration: BoxDecoration(
                  color: theme.colorScheme.surfaceContainerHighest,
                  borderRadius: BorderRadius.circular(DnaSpacing.radiusSm),
                  border: Border(
                    left: BorderSide(
                      color: theme.colorScheme.primary,
                      width: 3,
                    ),
                  ),
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      parentAuthorName,
                      style: theme.textTheme.bodySmall?.copyWith(
                        fontWeight: FontWeight.w600,
                        color: theme.colorScheme.primary,
                      ),
                    ),
                    const SizedBox(height: DnaSpacing.xs),
                    Text(
                      widget.parentComment.body.length > 100
                          ? '${widget.parentComment.body.substring(0, 100)}...'
                          : widget.parentComment.body,
                      style: theme.textTheme.bodySmall?.copyWith(
                        color: theme.colorScheme.onSurfaceVariant,
                      ),
                      maxLines: 2,
                      overflow: TextOverflow.ellipsis,
                    ),
                  ],
                ),
              ),
              const SizedBox(height: DnaSpacing.lg),
              TextField(
                controller: _bodyController,
                decoration: const InputDecoration(
                  hintText: 'Write your reply...',
                ),
                maxLines: 4,
                maxLength: 2000,
                autofocus: true,
              ),
            ],
          ),
        ),
      ),
      actions: [
        DnaButton(
          label: 'Cancel',
          variant: DnaButtonVariant.ghost,
          onPressed: _isLoading ? null : () => Navigator.pop(context),
        ),
        DnaButton(
          label: 'Reply',
          loading: _isLoading,
          icon: FontAwesomeIcons.paperPlane,
          onPressed: _isLoading ? null : _addReply,
        ),
      ],
    );
  }

  Future<void> _addReply() async {
    final body = _bodyController.text.trim();

    if (body.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Reply cannot be empty')),
      );
      return;
    }

    setState(() => _isLoading = true);

    try {
      await widget.ref.read(topicCommentsProvider(widget.topicUuid).notifier).addComment(
        body,
        parentCommentUuid: widget.parentComment.uuid,
      );

      if (mounted) {
        Navigator.pop(context);
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Reply posted')),
        );
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Error: $e')),
        );
      }
    } finally {
      if (mounted) {
        setState(() => _isLoading = false);
      }
    }
  }
}

// =============================================================================
// SUBSCRIBED TOPICS SCREEN
// =============================================================================

class _SubscribedTopicsScreen extends ConsumerWidget {
  const _SubscribedTopicsScreen();

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final subscribedTopics = ref.watch(subscribedTopicsProvider);

    return Scaffold(
      appBar: DnaAppBar(
        title: 'My Subscriptions',
        actions: [
          IconButton(
            icon: const FaIcon(FontAwesomeIcons.arrowsRotate),
            onPressed: () => ref.invalidate(subscribedTopicsProvider),
            tooltip: 'Refresh',
          ),
        ],
      ),
      body: subscribedTopics.when(
        skipLoadingOnReload: true,
        skipLoadingOnRefresh: true,
        data: (topics) => topics.isEmpty
            ? Center(
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    FaIcon(
                      FontAwesomeIcons.bookmark,
                      size: 64,
                      color: Theme.of(context).colorScheme.primary.withAlpha(128),
                    ),
                    const SizedBox(height: 16),
                    Text(
                      'No subscriptions',
                      style: Theme.of(context).textTheme.titleMedium,
                    ),
                    const SizedBox(height: 8),
                    Text(
                      'Subscribe to topics to see them here',
                      style: Theme.of(context).textTheme.bodySmall,
                    ),
                  ],
                ),
              )
            : RefreshIndicator(
                onRefresh: () => ref.read(subscribedTopicsProvider.notifier).refresh(),
                child: ListView.builder(
                  itemCount: topics.length,
                  itemBuilder: (context, index) {
                    final topic = topics[index];
                    return _TopicTile(
                      topic: topic,
                      onTap: () {
                        ref.read(selectedTopicUuidProvider.notifier).state = topic.uuid;
                        Navigator.of(context).push(
                          MaterialPageRoute(
                            builder: (context) => _TopicDetailScreen(topicUuid: topic.uuid),
                          ),
                        );
                      },
                    );
                  },
                ),
              ),
        loading: () => const Center(child: CircularProgressIndicator()),
        error: (e, st) => Center(child: Text('Error: $e')),
      ),
    );
  }
}

// =============================================================================
// ERROR VIEW
// =============================================================================

class _ErrorView extends StatelessWidget {
  final Object error;
  final VoidCallback onRetry;

  const _ErrorView({required this.error, required this.onRetry});

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return Center(
      child: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            FaIcon(
              FontAwesomeIcons.circleExclamation,
              size: 48,
              color: DnaColors.textWarning,
            ),
            const SizedBox(height: 16),
            Text(
              'Failed to load feed',
              style: theme.textTheme.titleMedium,
            ),
            const SizedBox(height: 8),
            Text(
              error.toString(),
              style: theme.textTheme.bodySmall,
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 16),
            ElevatedButton(
              onPressed: onRetry,
              child: const Text('Retry'),
            ),
          ],
        ),
      ),
    );
  }
}
