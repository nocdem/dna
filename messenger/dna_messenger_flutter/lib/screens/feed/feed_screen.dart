// Feed Screen - Public social feed via DHT
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:intl/intl.dart';
import '../../ffi/dna_engine.dart';
import '../../providers/providers.dart';
import '../../theme/dna_theme.dart';

class FeedScreen extends ConsumerStatefulWidget {
  const FeedScreen({super.key});

  @override
  ConsumerState<FeedScreen> createState() => _FeedScreenState();
}

class _FeedScreenState extends ConsumerState<FeedScreen> {
  final _composeController = TextEditingController();

  @override
  void dispose() {
    _composeController.dispose();
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
            icon: const Icon(Icons.menu),
            onPressed: () => Scaffold.of(ctx).openDrawer(),
          ),
        ),
        actions: [
          IconButton(
            icon: const Icon(Icons.refresh),
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
              const Icon(Icons.tag, color: DnaColors.primary),
              const SizedBox(width: 8),
              const Expanded(
                child: Text(
                  'Channels',
                  style: TextStyle(fontWeight: FontWeight.bold),
                ),
              ),
              IconButton(
                icon: const Icon(Icons.add, size: 20),
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
            icon: const Icon(Icons.add_circle_outline, size: 18),
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
          Icon(Icons.tag, size: 48, color: DnaColors.primary.withAlpha(80)),
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
          Icon(Icons.forum_outlined, size: 64, color: DnaColors.primary.withAlpha(80)),
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
    final replyTo = ref.watch(replyToPostProvider);

    return Column(
      children: [
        // Posts list
        Expanded(
          child: posts.when(
            data: (list) {
              if (list.isEmpty) {
                return _buildEmptyPosts();
              }
              return RefreshIndicator(
                onRefresh: () => ref.read(channelPostsProvider(channel.channelId).notifier).refresh(),
                child: ListView.builder(
                  reverse: true,
                  padding: const EdgeInsets.only(bottom: 8),
                  itemCount: list.length,
                  itemBuilder: (context, index) {
                    final post = list[index];
                    return _PostCard(
                      post: post,
                      onReply: () => ref.read(replyToPostProvider.notifier).state = post,
                      onVote: (value) => _castVote(post, value),
                    );
                  },
                ),
              );
            },
            loading: () => const Center(child: CircularProgressIndicator()),
            error: (e, st) => Center(child: Text('Error: $e')),
          ),
        ),
        // Reply indicator
        if (replyTo != null)
          _ReplyIndicator(
            post: replyTo,
            onCancel: () => ref.read(replyToPostProvider.notifier).state = null,
          ),
        // Compose area
        _ComposeArea(
          controller: _composeController,
          onSend: () => _sendPost(channel, replyTo),
        ),
      ],
    );
  }

  Widget _buildEmptyPosts() {
    return Center(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(Icons.chat_bubble_outline, size: 48, color: DnaColors.primary.withAlpha(80)),
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

  Future<void> _sendPost(FeedChannel channel, FeedPost? replyTo) async {
    final text = _composeController.text.trim();
    if (text.isEmpty) return;

    _composeController.clear();
    ref.read(replyToPostProvider.notifier).state = null;

    try {
      await ref.read(channelPostsProvider(channel.channelId).notifier)
          .createPost(text, replyTo: replyTo?.postId);
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Failed to post: $e')),
        );
      }
    }
  }

  Future<void> _castVote(FeedPost post, int value) async {
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
    }
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
      leading: const Icon(Icons.tag),
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
  final VoidCallback onReply;
  final void Function(int) onVote;

  const _PostCard({
    required this.post,
    required this.onReply,
    required this.onVote,
  });

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final isReply = post.replyTo != null;

    // Look up display name for author
    final displayNameAsync = ref.watch(identityDisplayNameProvider(post.authorFingerprint));
    final authorName = displayNameAsync.valueOrNull ?? _shortenFingerprint(post.authorFingerprint);

    return Container(
      margin: EdgeInsets.only(
        left: isReply ? 24 + (post.replyDepth * 16) : 8,
        right: 8,
        top: 4,
        bottom: 4,
      ),
      decoration: BoxDecoration(
        color: DnaColors.surface,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: DnaColors.border),
      ),
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Header: author + time
            Row(
              children: [
                if (isReply)
                  Container(
                    width: 3,
                    height: 16,
                    margin: const EdgeInsets.only(right: 8),
                    decoration: BoxDecoration(
                      color: DnaColors.primary.withAlpha(100),
                      borderRadius: BorderRadius.circular(2),
                    ),
                  ),
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
                    child: Icon(Icons.verified, size: 14, color: DnaColors.textSuccess),
                  ),
              ],
            ),
            const SizedBox(height: 8),
            // Content
            Text(post.text),
            const SizedBox(height: 8),
            // Actions: votes + reply
            Row(
              children: [
                // Upvote
                _VoteButton(
                  icon: Icons.thumb_up_outlined,
                  activeIcon: Icons.thumb_up,
                  count: post.upvotes,
                  isActive: post.userVote == 1,
                  onTap: post.hasVoted ? null : () => onVote(1),
                ),
                const SizedBox(width: 4),
                // Downvote
                _VoteButton(
                  icon: Icons.thumb_down_outlined,
                  activeIcon: Icons.thumb_down,
                  count: post.downvotes,
                  isActive: post.userVote == -1,
                  isNegative: true,
                  onTap: post.hasVoted ? null : () => onVote(-1),
                ),
                const Spacer(),
                // Reply count
                if (post.replyCount > 0)
                  Padding(
                    padding: const EdgeInsets.only(right: 8),
                    child: Text(
                      '${post.replyCount} replies',
                      style: TextStyle(color: DnaColors.textMuted, fontSize: 12),
                    ),
                  ),
                // Reply button
                if (post.replyDepth < 2)
                  TextButton.icon(
                    onPressed: onReply,
                    icon: const Icon(Icons.reply, size: 16),
                    label: const Text('Reply'),
                    style: TextButton.styleFrom(
                      padding: const EdgeInsets.symmetric(horizontal: 8),
                      minimumSize: Size.zero,
                      tapTargetSize: MaterialTapTargetSize.shrinkWrap,
                    ),
                  ),
              ],
            ),
          ],
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
// VOTE BUTTON
// =============================================================================

class _VoteButton extends StatelessWidget {
  final IconData icon;
  final IconData activeIcon;
  final int count;
  final bool isActive;
  final bool isNegative;
  final VoidCallback? onTap;

  const _VoteButton({
    required this.icon,
    required this.activeIcon,
    required this.count,
    required this.isActive,
    this.isNegative = false,
    this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    final color = isActive
        ? (isNegative ? DnaColors.textWarning : DnaColors.textSuccess)
        : DnaColors.textMuted;

    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(16),
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(isActive ? activeIcon : icon, size: 16, color: color),
            if (count > 0) ...[
              const SizedBox(width: 4),
              Text(
                '$count',
                style: TextStyle(color: color, fontSize: 12),
              ),
            ],
          ],
        ),
      ),
    );
  }
}

// =============================================================================
// REPLY INDICATOR
// =============================================================================

class _ReplyIndicator extends StatelessWidget {
  final FeedPost post;
  final VoidCallback onCancel;

  const _ReplyIndicator({
    required this.post,
    required this.onCancel,
  });

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
      decoration: BoxDecoration(
        color: DnaColors.surface,
        border: Border(top: BorderSide(color: DnaColors.borderAccent)),
      ),
      child: Row(
        children: [
          Icon(Icons.reply, size: 16, color: DnaColors.primary),
          const SizedBox(width: 8),
          Expanded(
            child: Text(
              'Replying to: ${post.text.length > 40 ? '${post.text.substring(0, 40)}...' : post.text}',
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: TextStyle(color: DnaColors.textMuted, fontSize: 13),
            ),
          ),
          IconButton(
            icon: const Icon(Icons.close, size: 18),
            onPressed: onCancel,
            padding: EdgeInsets.zero,
            constraints: const BoxConstraints(),
          ),
        ],
      ),
    );
  }
}

// =============================================================================
// COMPOSE AREA
// =============================================================================

class _ComposeArea extends StatelessWidget {
  final TextEditingController controller;
  final VoidCallback onSend;

  const _ComposeArea({
    required this.controller,
    required this.onSend,
  });

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(8),
      decoration: BoxDecoration(
        color: DnaColors.surface,
        border: Border(top: BorderSide(color: DnaColors.border)),
      ),
      child: SafeArea(
        child: Row(
          children: [
            Expanded(
              child: TextField(
                controller: controller,
                decoration: const InputDecoration(
                  hintText: 'Write a post...',
                  border: OutlineInputBorder(),
                  contentPadding: EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                ),
                maxLines: 3,
                minLines: 1,
                textInputAction: TextInputAction.send,
                onSubmitted: (_) => onSend(),
              ),
            ),
            const SizedBox(width: 8),
            IconButton.filled(
              onPressed: onSend,
              icon: const Icon(Icons.send),
            ),
          ],
        ),
      ),
    );
  }
}
