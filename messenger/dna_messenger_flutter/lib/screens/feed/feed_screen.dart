// Feed Screen - Public social feed via DHT
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';
import 'package:intl/intl.dart';
import 'package:emoji_picker_flutter/emoji_picker_flutter.dart';
import '../../ffi/dna_engine.dart';
import '../../providers/providers.dart';
import '../../theme/dna_theme.dart';
import '../../widgets/emoji_shortcode_field.dart';
import '../../widgets/formatted_text.dart';

class FeedScreen extends ConsumerStatefulWidget {
  const FeedScreen({super.key});

  @override
  ConsumerState<FeedScreen> createState() => _FeedScreenState();
}

class _FeedScreenState extends ConsumerState<FeedScreen> {
  final _composeController = TextEditingController();
  final _commentControllers = <String, TextEditingController>{};
  bool _showEmojiPicker = false;

  TextEditingController _getCommentController(String postId) {
    return _commentControllers.putIfAbsent(postId, () => TextEditingController());
  }

  @override
  void dispose() {
    _composeController.dispose();
    for (final controller in _commentControllers.values) {
      controller.dispose();
    }
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final channels = ref.watch(feedChannelsProvider);
    final selectedChannel = ref.watch(selectedChannelProvider);
    final screenWidth = MediaQuery.of(context).size.width;
    final isWide = screenWidth > 700;

    return Scaffold(
      appBar: AppBar(
        title: Text(selectedChannel?.name ?? 'Feed'),
        leading: isWide ? null : Builder(
          builder: (ctx) => IconButton(
            icon: const FaIcon(FontAwesomeIcons.bars),
            onPressed: () => Scaffold.of(ctx).openDrawer(),
          ),
        ),
        actions: [
          IconButton(
            icon: const FaIcon(FontAwesomeIcons.arrowsRotate),
            onPressed: () {
              ref.invalidate(feedChannelsProvider);
              if (selectedChannel != null) {
                ref.invalidate(channelPostsProvider(selectedChannel.channelId));
              }
            },
            tooltip: 'Refresh',
          ),
        ],
      ),
      drawer: isWide ? null : _buildChannelDrawer(channels),
      body: Row(
        children: [
          // Channel sidebar (wide screens only)
          if (isWide)
            SizedBox(
              width: 260,
              child: _buildChannelList(channels),
            ),
          // Posts view
          Expanded(
            child: selectedChannel == null
                ? _buildNoChannelSelected()
                : _buildPostsView(selectedChannel),
          ),
        ],
      ),
    );
  }

  Widget _buildChannelDrawer(AsyncValue<List<FeedChannel>> channels) {
    return Drawer(
      child: _buildChannelList(channels),
    );
  }

  Widget _buildChannelList(AsyncValue<List<FeedChannel>> channels) {
    return Column(
      children: [
        // Header
        Container(
          padding: const EdgeInsets.all(16),
          decoration: const BoxDecoration(
            color: DnaColors.surface,
            border: Border(bottom: BorderSide(color: DnaColors.border)),
          ),
          child: Row(
            children: [
              const FaIcon(FontAwesomeIcons.hashtag, color: DnaColors.primary),
              const SizedBox(width: 8),
              const Expanded(
                child: Text(
                  'Channels',
                  style: TextStyle(fontWeight: FontWeight.bold),
                ),
              ),
              IconButton(
                icon: const FaIcon(FontAwesomeIcons.plus, size: 20),
                onPressed: () => _showCreateChannelDialog(),
                tooltip: 'Create Channel',
                padding: EdgeInsets.zero,
                constraints: const BoxConstraints(),
              ),
            ],
          ),
        ),
        // Channel list
        Expanded(
          child: channels.when(
            data: (list) {
              if (list.isEmpty) {
                return _buildEmptyChannels();
              }
              return ListView.builder(
                itemCount: list.length,
                itemBuilder: (context, index) {
                  final channel = list[index];
                  final isSelected = ref.watch(selectedChannelProvider)?.channelId == channel.channelId;
                  return _ChannelTile(
                    channel: channel,
                    isSelected: isSelected,
                    onTap: () {
                      ref.read(selectedChannelProvider.notifier).state = channel;
                      Navigator.of(context).maybePop();
                    },
                  );
                },
              );
            },
            loading: () => const Center(child: CircularProgressIndicator()),
            error: (e, st) => Center(child: Text('Error: $e')),
          ),
        ),
        // Init default channels button
        Padding(
          padding: const EdgeInsets.all(8),
          child: TextButton.icon(
            onPressed: () async {
              await ref.read(feedChannelsProvider.notifier).initDefaultChannels();
            },
            icon: const FaIcon(FontAwesomeIcons.circlePlus, size: 18),
            label: const Text('Init Default Channels'),
          ),
        ),
      ],
    );
  }

  Widget _buildEmptyChannels() {
    return Center(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          FaIcon(FontAwesomeIcons.hashtag, size: 48, color: DnaColors.primary.withAlpha(80)),
          const SizedBox(height: 12),
          const Text('No channels yet'),
          const SizedBox(height: 8),
          TextButton(
            onPressed: () async {
              await ref.read(feedChannelsProvider.notifier).initDefaultChannels();
            },
            child: const Text('Create Default Channels'),
          ),
        ],
      ),
    );
  }

  Widget _buildNoChannelSelected() {
    return Center(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          FaIcon(FontAwesomeIcons.comments, size: 64, color: DnaColors.primary.withAlpha(80)),
          const SizedBox(height: 16),
          const Text('Select a channel'),
          const SizedBox(height: 8),
          Text(
            'Choose a channel from the sidebar',
            style: TextStyle(color: DnaColors.textMuted),
          ),
        ],
      ),
    );
  }

  Widget _buildPostsView(FeedChannel channel) {
    final posts = ref.watch(channelPostsProvider(channel.channelId));

    return Column(
      children: [
        // Posts list
        Expanded(
          child: posts.when(
            data: (list) {
              if (list.isEmpty) {
                return _buildEmptyPosts();
              }
              final expandedPosts = ref.watch(expandedPostsProvider);

              return RefreshIndicator(
                onRefresh: () => ref.read(channelPostsProvider(channel.channelId).notifier).refresh(),
                child: ListView.builder(
                  reverse: true,
                  padding: const EdgeInsets.only(bottom: 8),
                  itemCount: list.length,
                  itemBuilder: (context, index) {
                    final post = list[index];
                    final isExpanded = expandedPosts.contains(post.postId);

                    final commentController = _getCommentController(post.postId);
                    return _ExpandablePostCard(
                      post: post,
                      isExpanded: isExpanded,
                      onTap: () => _toggleExpansion(post.postId),
                      onVote: (value) => _castPostVote(post, value),
                      commentController: commentController,
                      onSendComment: () => _sendComment(post.postId, channel.channelId, commentController),
                    );
                  },
                ),
              );
            },
            loading: () => const Center(child: CircularProgressIndicator()),
            error: (e, st) => Center(child: Text('Error: $e')),
          ),
        ),
        // Compose area for new posts
        _ComposeArea(
          controller: _composeController,
          hintText: 'Write a post...',
          onSend: () => _sendPost(channel),
          showEmojiPicker: _showEmojiPicker,
          onEmojiToggle: () {
            setState(() {
              _showEmojiPicker = !_showEmojiPicker;
            });
          },
          onEmojiSelected: (emoji) {
            final text = _composeController.text;
            final selection = _composeController.selection;
            final newText = text.replaceRange(
              selection.start,
              selection.end,
              emoji.emoji,
            );
            _composeController.value = TextEditingValue(
              text: newText,
              selection: TextSelection.collapsed(
                offset: selection.start + emoji.emoji.length,
              ),
            );
          },
          onTextFieldTap: () {
            if (_showEmojiPicker) {
              setState(() => _showEmojiPicker = false);
            }
          },
        ),
      ],
    );
  }

  Widget _buildEmptyPosts() {
    return Center(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          FaIcon(FontAwesomeIcons.comment, size: 48, color: DnaColors.primary.withAlpha(80)),
          const SizedBox(height: 12),
          const Text('No posts yet'),
          const SizedBox(height: 8),
          Text(
            'Be the first to post!',
            style: TextStyle(color: DnaColors.textMuted),
          ),
        ],
      ),
    );
  }

  Future<void> _sendPost(FeedChannel channel) async {
    final text = _composeController.text.trim();
    if (text.isEmpty) return;

    _composeController.clear();

    try {
      await ref.read(channelPostsProvider(channel.channelId).notifier)
          .createPost(text);
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Failed to post: $e')),
        );
      }
    }
  }

  Future<void> _sendComment(String postId, String channelId, TextEditingController controller) async {
    final text = controller.text.trim();
    if (text.isEmpty) return;

    controller.clear();

    try {
      await ref.read(postCommentsProvider(postId).notifier).addComment(text);
      // Also refresh posts to update comment count
      ref.invalidate(channelPostsProvider(channelId));
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Failed to comment: $e')),
        );
      }
    }
  }

  Future<void> _castPostVote(FeedPost post, int value) async {
    // Set loading state
    ref.read(votingPostProvider.notifier).state = post.postId;

    try {
      final engine = await ref.read(engineProvider.future);
      await engine.castFeedVote(post.postId, value);
      // Refresh the posts
      final channel = ref.read(selectedChannelProvider);
      if (channel != null) {
        ref.invalidate(channelPostsProvider(channel.channelId));
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Vote failed: $e')),
        );
      }
    } finally {
      // Clear loading state
      ref.read(votingPostProvider.notifier).state = null;
    }
  }

  void _toggleExpansion(String postId) {
    final current = ref.read(expandedPostsProvider);
    final newSet = Set<String>.from(current);
    if (newSet.contains(postId)) {
      newSet.remove(postId);
    } else {
      newSet.add(postId);
    }
    ref.read(expandedPostsProvider.notifier).state = newSet;
  }

  void _showCreateChannelDialog() {
    final nameController = TextEditingController();
    final descController = TextEditingController();

    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Create Channel'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            TextField(
              controller: nameController,
              decoration: const InputDecoration(
                labelText: 'Channel Name',
                hintText: 'general',
                prefixText: '#',
              ),
              autofocus: true,
            ),
            const SizedBox(height: 12),
            TextField(
              controller: descController,
              decoration: const InputDecoration(
                labelText: 'Description',
                hintText: 'What is this channel about?',
              ),
              maxLines: 2,
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () async {
              final name = nameController.text.trim();
              if (name.isEmpty) return;
              Navigator.pop(context);
              try {
                await ref.read(feedChannelsProvider.notifier)
                    .createChannel(name, descController.text.trim());
              } catch (e) {
                if (context.mounted) {
                  ScaffoldMessenger.of(context).showSnackBar(
                    SnackBar(content: Text('Failed: $e')),
                  );
                }
              }
            },
            child: const Text('Create'),
          ),
        ],
      ),
    );
  }
}

// =============================================================================
// CHANNEL TILE
// =============================================================================

class _ChannelTile extends StatelessWidget {
  final FeedChannel channel;
  final bool isSelected;
  final VoidCallback onTap;

  const _ChannelTile({
    required this.channel,
    required this.isSelected,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    return ListTile(
      leading: const FaIcon(FontAwesomeIcons.hashtag),
      title: Text(
        channel.name,
        maxLines: 1,
        overflow: TextOverflow.ellipsis,
      ),
      subtitle: Text(
        channel.description.isEmpty ? 'No description' : channel.description,
        maxLines: 1,
        overflow: TextOverflow.ellipsis,
        style: TextStyle(color: DnaColors.textMuted, fontSize: 12),
      ),
      trailing: Text(
        '${channel.postCount}',
        style: TextStyle(color: DnaColors.textMuted),
      ),
      selected: isSelected,
      selectedTileColor: DnaColors.primarySoft,
      onTap: onTap,
    );
  }
}

// =============================================================================
// POST CARD
// =============================================================================

class _PostCard extends ConsumerWidget {
  final FeedPost post;
  final void Function(int) onVote;
  final VoidCallback? onTap;
  final bool isExpanded;

  const _PostCard({
    required this.post,
    required this.onVote,
    this.onTap,
    this.isExpanded = false,
  });

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    // Look up display name for author
    final displayNameAsync = ref.watch(identityDisplayNameProvider(post.authorFingerprint));
    final authorName = displayNameAsync.valueOrNull ?? _shortenFingerprint(post.authorFingerprint);

    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(12),
      child: Container(
        margin: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
        decoration: BoxDecoration(
          color: DnaColors.surface,
          borderRadius: BorderRadius.circular(12),
          border: Border.all(color: isExpanded ? DnaColors.primary : DnaColors.border),
        ),
        child: Padding(
          padding: const EdgeInsets.all(12),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              // Header: author + time
              Row(
                children: [
                  Expanded(
                    child: Text(
                      authorName,
                      style: TextStyle(
                        color: DnaColors.primary,
                        fontWeight: FontWeight.w500,
                        fontSize: 13,
                      ),
                    ),
                  ),
                  Text(
                    _formatTimestamp(post.timestamp),
                    style: TextStyle(color: DnaColors.textMuted, fontSize: 12),
                  ),
                  if (post.verified)
                    Padding(
                      padding: const EdgeInsets.only(left: 4),
                      child: FaIcon(FontAwesomeIcons.circleCheck, size: 14, color: DnaColors.textSuccess),
                    ),
                  // Expand indicator
                  Padding(
                    padding: const EdgeInsets.only(left: 8),
                    child: FaIcon(
                      isExpanded ? FontAwesomeIcons.chevronUp : FontAwesomeIcons.chevronDown,
                      size: 20,
                      color: DnaColors.textMuted,
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 8),
              // Content
              FormattedText(post.text),
              const SizedBox(height: 8),
              // Actions: votes + comments
              Row(
                children: [
                  // Upvote
                  Builder(builder: (context) {
                    final votingPostId = ref.watch(votingPostProvider);
                    final isLoading = votingPostId == post.postId;
                    return _VoteButton(
                      icon: FontAwesomeIcons.thumbsUp,
                      activeIcon: FontAwesomeIcons.solidThumbsUp,
                      count: post.upvotes,
                      isActive: post.userVote == 1,
                      isLoading: isLoading,
                      onTap: post.hasVoted ? null : () => onVote(1),
                    );
                  }),
                  const SizedBox(width: 4),
                  // Downvote
                  Builder(builder: (context) {
                    final votingPostId = ref.watch(votingPostProvider);
                    final isLoading = votingPostId == post.postId;
                    return _VoteButton(
                      icon: FontAwesomeIcons.thumbsDown,
                      activeIcon: FontAwesomeIcons.solidThumbsDown,
                      count: post.downvotes,
                      isActive: post.userVote == -1,
                      isNegative: true,
                      isLoading: isLoading,
                      onTap: post.hasVoted ? null : () => onVote(-1),
                    );
                  }),
                  const Spacer(),
                  // Comment count
                  FaIcon(FontAwesomeIcons.comment, size: 16, color: DnaColors.textMuted),
                  const SizedBox(width: 4),
                  Text(
                    '${post.commentCount}',
                    style: TextStyle(color: DnaColors.textMuted, fontSize: 12),
                  ),
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }

  String _shortenFingerprint(String fp) {
    if (fp.length <= 16) return fp;
    return '${fp.substring(0, 8)}...${fp.substring(fp.length - 8)}';
  }

  String _formatTimestamp(DateTime ts) {
    final now = DateTime.now();
    final diff = now.difference(ts);

    if (diff.inMinutes < 1) return 'now';
    if (diff.inMinutes < 60) return '${diff.inMinutes}m ago';
    if (diff.inHours < 24) return '${diff.inHours}h ago';
    if (diff.inDays < 7) return '${diff.inDays}d ago';
    return DateFormat('MMM d').format(ts);
  }
}

// =============================================================================
// EXPANDABLE POST CARD (post + comments)
// =============================================================================

class _ExpandablePostCard extends ConsumerWidget {
  final FeedPost post;
  final bool isExpanded;
  final VoidCallback onTap;
  final void Function(int) onVote;
  final TextEditingController commentController;
  final VoidCallback onSendComment;

  const _ExpandablePostCard({
    required this.post,
    required this.isExpanded,
    required this.onTap,
    required this.onVote,
    required this.commentController,
    required this.onSendComment,
  });

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        // Post card
        _PostCard(
          post: post,
          onVote: onVote,
          onTap: onTap,
          isExpanded: isExpanded,
        ),
        // Comments section (when expanded)
        if (isExpanded)
          _CommentsSection(
            postId: post.postId,
            commentController: commentController,
            onSendComment: onSendComment,
          ),
      ],
    );
  }
}

// =============================================================================
// COMMENTS SECTION
// =============================================================================

class _CommentsSection extends ConsumerWidget {
  final String postId;
  final TextEditingController commentController;
  final VoidCallback onSendComment;

  const _CommentsSection({
    required this.postId,
    required this.commentController,
    required this.onSendComment,
  });

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final commentsAsync = ref.watch(postCommentsProvider(postId));

    return Container(
      margin: const EdgeInsets.only(left: 24, right: 8, bottom: 8),
      decoration: BoxDecoration(
        color: DnaColors.background,
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: DnaColors.border),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Comments list
          commentsAsync.when(
            data: (comments) {
              if (comments.isEmpty) {
                return Padding(
                  padding: const EdgeInsets.all(12),
                  child: Text(
                    'No comments yet. Be the first!',
                    style: TextStyle(color: DnaColors.textMuted, fontSize: 13),
                  ),
                );
              }
              return ListView.separated(
                shrinkWrap: true,
                physics: const NeverScrollableScrollPhysics(),
                itemCount: comments.length,
                separatorBuilder: (_, i) => Divider(
                  height: 1,
                  color: DnaColors.border,
                ),
                itemBuilder: (context, index) {
                  return _CommentCard(
                    comment: comments[index],
                    onMention: (authorName) {
                      final current = commentController.text;
                      final mention = '@$authorName ';
                      if (!current.startsWith(mention)) {
                        commentController.text = mention + current;
                        commentController.selection = TextSelection.collapsed(
                          offset: commentController.text.length,
                        );
                      }
                    },
                  );
                },
              );
            },
            loading: () => Padding(
              padding: const EdgeInsets.all(12),
              child: Row(
                children: [
                  SizedBox(
                    width: 16,
                    height: 16,
                    child: CircularProgressIndicator(strokeWidth: 2, color: DnaColors.textMuted),
                  ),
                  const SizedBox(width: 8),
                  Text('Loading comments...', style: TextStyle(color: DnaColors.textMuted, fontSize: 12)),
                ],
              ),
            ),
            error: (e, st) => Padding(
              padding: const EdgeInsets.all(12),
              child: Text('Failed to load comments', style: TextStyle(color: DnaColors.textWarning, fontSize: 12)),
            ),
          ),
          // Comment input
          Container(
            padding: const EdgeInsets.all(8),
            decoration: BoxDecoration(
              border: Border(top: BorderSide(color: DnaColors.border)),
            ),
            child: Row(
              children: [
                Expanded(
                  child: TextField(
                    controller: commentController,
                    decoration: InputDecoration(
                      hintText: 'Write a comment...',
                      border: OutlineInputBorder(
                        borderRadius: BorderRadius.circular(20),
                      ),
                      contentPadding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                      isDense: true,
                    ),
                    style: const TextStyle(fontSize: 13),
                    maxLines: 2,
                    minLines: 1,
                    textInputAction: TextInputAction.send,
                    onSubmitted: (_) => onSendComment(),
                  ),
                ),
                const SizedBox(width: 8),
                IconButton(
                  onPressed: onSendComment,
                  icon: const FaIcon(FontAwesomeIcons.paperPlane, size: 20),
                  padding: EdgeInsets.zero,
                  constraints: const BoxConstraints(minWidth: 36, minHeight: 36),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

// =============================================================================
// COMMENT CARD
// =============================================================================

class _CommentCard extends ConsumerWidget {
  final FeedComment comment;
  final void Function(String authorName) onMention;

  const _CommentCard({required this.comment, required this.onMention});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    // Look up display name for author
    final displayNameAsync = ref.watch(identityDisplayNameProvider(comment.authorFingerprint));
    final authorName = displayNameAsync.valueOrNull ?? _shortenFingerprint(comment.authorFingerprint);

    return Padding(
      padding: const EdgeInsets.all(10),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Header
          Row(
            children: [
              Text(
                authorName,
                style: TextStyle(
                  color: DnaColors.primary,
                  fontWeight: FontWeight.w500,
                  fontSize: 12,
                ),
              ),
              const SizedBox(width: 8),
              Text(
                _formatTimestamp(comment.timestamp),
                style: TextStyle(color: DnaColors.textMuted, fontSize: 11),
              ),
              if (comment.verified)
                Padding(
                  padding: const EdgeInsets.only(left: 4),
                  child: FaIcon(FontAwesomeIcons.circleCheck, size: 12, color: DnaColors.textSuccess),
                ),
            ],
          ),
          const SizedBox(height: 4),
          // Content
          FormattedText(comment.text, style: const TextStyle(fontSize: 13)),
          const SizedBox(height: 6),
          // Votes + mention
          Row(
            children: [
              Builder(builder: (context) {
                final votingCommentId = ref.watch(votingCommentProvider);
                final isLoading = votingCommentId == comment.commentId;
                return _VoteButton(
                  icon: FontAwesomeIcons.thumbsUp,
                  activeIcon: FontAwesomeIcons.solidThumbsUp,
                  count: comment.upvotes,
                  isActive: comment.userVote == 1,
                  isLoading: isLoading,
                  small: true,
                  onTap: comment.hasVoted ? null : () => _castCommentVote(ref, comment, 1),
                );
              }),
              const SizedBox(width: 4),
              Builder(builder: (context) {
                final votingCommentId = ref.watch(votingCommentProvider);
                final isLoading = votingCommentId == comment.commentId;
                return _VoteButton(
                  icon: FontAwesomeIcons.thumbsDown,
                  activeIcon: FontAwesomeIcons.solidThumbsDown,
                  count: comment.downvotes,
                  isActive: comment.userVote == -1,
                  isNegative: true,
                  isLoading: isLoading,
                  small: true,
                  onTap: comment.hasVoted ? null : () => _castCommentVote(ref, comment, -1),
                );
              }),
              const SizedBox(width: 8),
              // Mention button
              InkWell(
                onTap: () => onMention(authorName),
                borderRadius: BorderRadius.circular(12),
                child: Padding(
                  padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                  child: FaIcon(FontAwesomeIcons.reply, size: 14, color: DnaColors.textMuted),
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }

  Future<void> _castCommentVote(WidgetRef ref, FeedComment comment, int value) async {
    ref.read(votingCommentProvider.notifier).state = comment.commentId;

    try {
      final engine = await ref.read(engineProvider.future);
      await engine.castCommentVote(comment.commentId, value);
      // Refresh comments
      ref.invalidate(postCommentsProvider(comment.postId));
    } catch (e) {
      // Ignore errors for now
    } finally {
      ref.read(votingCommentProvider.notifier).state = null;
    }
  }

  String _shortenFingerprint(String fp) {
    if (fp.length <= 16) return fp;
    return '${fp.substring(0, 8)}...${fp.substring(fp.length - 8)}';
  }

  String _formatTimestamp(DateTime ts) {
    final now = DateTime.now();
    final diff = now.difference(ts);

    if (diff.inMinutes < 1) return 'now';
    if (diff.inMinutes < 60) return '${diff.inMinutes}m ago';
    if (diff.inHours < 24) return '${diff.inHours}h ago';
    if (diff.inDays < 7) return '${diff.inDays}d ago';
    return DateFormat('MMM d').format(ts);
  }
}

// =============================================================================
// VOTE BUTTON
// =============================================================================

class _VoteButton extends StatelessWidget {
  final IconData icon;
  final IconData activeIcon;
  final int count;
  final bool isActive;
  final bool isNegative;
  final bool isLoading;
  final bool small;
  final VoidCallback? onTap;

  const _VoteButton({
    required this.icon,
    required this.activeIcon,
    required this.count,
    required this.isActive,
    this.isNegative = false,
    this.isLoading = false,
    this.small = false,
    this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    final color = isActive
        ? (isNegative ? DnaColors.textWarning : DnaColors.textSuccess)
        : DnaColors.textMuted;

    final iconSize = small ? 14.0 : 16.0;
    final fontSize = small ? 11.0 : 12.0;

    return InkWell(
      onTap: isLoading ? null : onTap,
      borderRadius: BorderRadius.circular(16),
      child: Padding(
        padding: EdgeInsets.symmetric(
          horizontal: small ? 6 : 8,
          vertical: small ? 2 : 4,
        ),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            if (isLoading)
              SizedBox(
                width: iconSize,
                height: iconSize,
                child: CircularProgressIndicator(
                  strokeWidth: 2,
                  color: color,
                ),
              )
            else
              FaIcon(isActive ? activeIcon : icon, size: iconSize, color: color),
            if (count > 0) ...[
              const SizedBox(width: 4),
              Text(
                '$count',
                style: TextStyle(color: color, fontSize: fontSize),
              ),
            ],
          ],
        ),
      ),
    );
  }
}

// =============================================================================
// COMPOSE AREA
// =============================================================================

class _ComposeArea extends StatelessWidget {
  final TextEditingController controller;
  final String hintText;
  final VoidCallback onSend;
  final bool showEmojiPicker;
  final VoidCallback onEmojiToggle;
  final void Function(Emoji) onEmojiSelected;
  final VoidCallback onTextFieldTap;
  final bool autofocus;

  const _ComposeArea({
    required this.controller,
    required this.hintText,
    required this.onSend,
    required this.showEmojiPicker,
    required this.onEmojiToggle,
    required this.onEmojiSelected,
    required this.onTextFieldTap,
    this.autofocus = false,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return Stack(
      clipBehavior: Clip.none,
      children: [
        // Input area
        Container(
          padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(
            color: DnaColors.surface,
            border: Border(top: BorderSide(color: DnaColors.border)),
          ),
          child: SafeArea(
            top: false,
            child: Row(
              children: [
                // Emoji button
                IconButton(
                  icon: FaIcon(
                    showEmojiPicker
                        ? FontAwesomeIcons.keyboard
                        : FontAwesomeIcons.faceSmile,
                  ),
                  onPressed: onEmojiToggle,
                ),
                // Text input with :shortcode: support
                Expanded(
                  child: EmojiShortcodeField(
                    controller: controller,
                    hintText: hintText,
                    autofocus: autofocus,
                    minLines: 1,
                    maxLines: 3,
                    textInputAction: TextInputAction.send,
                    onSubmitted: onSend,
                    onEnterPressed: () {
                      if (controller.text.trim().isNotEmpty) {
                        onSend();
                      }
                    },
                    onTap: onTextFieldTap,
                    decoration: InputDecoration(
                      hintText: hintText,
                      border: OutlineInputBorder(
                        borderRadius: BorderRadius.circular(24),
                        borderSide: BorderSide.none,
                      ),
                      filled: true,
                      fillColor: theme.scaffoldBackgroundColor,
                      contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
                    ),
                  ),
                ),
                const SizedBox(width: 8),
                // Send button
                IconButton(
                  onPressed: onSend,
                  icon: const FaIcon(FontAwesomeIcons.paperPlane),
                ),
              ],
            ),
          ),
        ),
        // Emoji picker (overlays content, positioned above emoji button on left)
        if (showEmojiPicker)
          Positioned(
            left: 8,
            bottom: 70, // Above input area
            child: Material(
              elevation: 8,
              borderRadius: BorderRadius.circular(12),
              color: theme.colorScheme.surface,
              child: Container(
                constraints: const BoxConstraints(maxWidth: 380, maxHeight: 280),
                clipBehavior: Clip.antiAlias,
                decoration: BoxDecoration(
                  borderRadius: BorderRadius.circular(12),
                ),
                child: EmojiPicker(
                  onEmojiSelected: (category, emoji) {
                    onEmojiSelected(emoji);
                  },
                  config: Config(
                    checkPlatformCompatibility: true,
                    emojiViewConfig: EmojiViewConfig(
                      columns: 7,
                      emojiSizeMax: 28,
                      backgroundColor: theme.colorScheme.surface,
                    ),
                    categoryViewConfig: CategoryViewConfig(
                      indicatorColor: theme.colorScheme.primary,
                      iconColorSelected: theme.colorScheme.primary,
                      iconColor: DnaColors.textMuted,
                      backgroundColor: theme.colorScheme.surface,
                    ),
                    bottomActionBarConfig: BottomActionBarConfig(
                      backgroundColor: theme.colorScheme.surface,
                      buttonColor: theme.colorScheme.primary,
                    ),
                  ),
                ),
              ),
            ),
          ),
      ],
    );
  }
}
