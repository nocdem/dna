// Channel Detail Screen - shows the post stream for a single channel
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
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
  ChannelPost? _replyingTo;

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

  void _replyToPost(ChannelPost post) {
    setState(() => _replyingTo = post);
  }

  void _cancelReply() {
    setState(() => _replyingTo = null);
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
                        onReply: () => _replyToPost(post),
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
          // Reply preview banner
          if (_replyingTo != null)
            Container(
              width: double.infinity,
              padding: const EdgeInsets.symmetric(
                horizontal: DnaSpacing.md,
                vertical: DnaSpacing.sm,
              ),
              decoration: BoxDecoration(
                color: theme.colorScheme.primary.withAlpha(20),
                border: Border(
                  left: BorderSide(
                    color: theme.colorScheme.primary,
                    width: 3,
                  ),
                ),
              ),
              child: Row(
                children: [
                  FaIcon(
                    FontAwesomeIcons.reply,
                    size: 14,
                    color: theme.colorScheme.primary,
                  ),
                  const SizedBox(width: DnaSpacing.sm),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        Text(
                          'Replying to ${nameCache[_replyingTo!.authorFingerprint] ?? _replyingTo!.authorFingerprint.substring(0, 16)}',
                          style: theme.textTheme.bodySmall?.copyWith(
                            color: theme.colorScheme.primary,
                            fontWeight: FontWeight.w600,
                          ),
                        ),
                        Text(
                          _replyingTo!.body.length > 80
                              ? '${_replyingTo!.body.substring(0, 80)}...'
                              : _replyingTo!.body,
                          style: theme.textTheme.bodySmall,
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                        ),
                      ],
                    ),
                  ),
                  IconButton(
                    icon: const FaIcon(FontAwesomeIcons.xmark, size: 16),
                    onPressed: _cancelReply,
                    padding: EdgeInsets.zero,
                    constraints: const BoxConstraints(),
                  ),
                ],
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

  /// Build reply-formatted post body, respecting the 4000 char post limit.
  String _buildReplyBody(String replyText, ChannelPost replyPost) {
    const maxLen = 4000;
    final authorName =
        ref.read(nameResolverProvider)[replyPost.authorFingerprint] ??
            replyPost.authorFingerprint.substring(0, 16);
    final header = '↩ Re: $authorName\n';

    String quoteLines(String body) =>
        body.split('\n').map((l) => '> $l').join('\n');

    // Try full quote first
    final fullQuoted = quoteLines(replyPost.body);
    final fullPost = '$header$fullQuoted\n$replyText';
    if (fullPost.length <= maxLen) return fullPost;

    // Truncate quoted text to fit within limit
    final fixedLen = header.length + 1 + replyText.length; // +1 for \n
    final availableForQuote = maxLen - fixedLen - 3; // -3 for "..."

    if (availableForQuote <= 0) return replyText;

    final truncated = fullQuoted.length > availableForQuote
        ? '${fullQuoted.substring(0, availableForQuote)}...'
        : fullQuoted;

    return '$header$truncated\n$replyText';
  }

  Future<void> _submitPost() async {
    final text = _postController.text.trim();
    if (text.isEmpty || _sending) return;

    // Build post body with reply formatting if replying
    String postBody = text;
    if (_replyingTo != null) {
      postBody = _buildReplyBody(text, _replyingTo!);
      setState(() => _replyingTo = null);
    }

    setState(() => _sending = true);

    try {
      await ref
          .read(channelPostsProvider(widget.channelUuid).notifier)
          .addPost(postBody);
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
  final VoidCallback onReply;

  const _PostCard({
    required this.post,
    required this.nameCache,
    required this.onReply,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final authorName = nameCache[post.authorFingerprint];
    final displayAuthor = authorName != null && authorName.isNotEmpty
        ? authorName
        : '${post.authorFingerprint.substring(0, 16)}...';

    return GestureDetector(
      onLongPress: () => _showBottomSheet(context),
      onSecondaryTapUp: (details) =>
          _showContextMenu(context, details.globalPosition),
      child: Card(
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
              // Post body (with reply rendering)
              _buildBody(context, theme),
            ],
          ),
        ),
      ),
    );
  }

  /// Renders post body — parses reply format if present.
  Widget _buildBody(BuildContext context, ThemeData theme) {
    final body = post.body;

    // Check for reply format: "↩ Re: author\n> quoted\nreply"
    if (!body.startsWith('↩ Re: ')) {
      return SelectableText(body, style: theme.textTheme.bodyMedium);
    }

    final lines = body.split('\n');
    final replyAuthor = lines[0].substring('↩ Re: '.length);

    // Collect quoted lines (starting with "> ")
    final quotedLines = <String>[];
    int replyStartIndex = 1;
    for (int i = 1; i < lines.length; i++) {
      if (lines[i].startsWith('> ')) {
        quotedLines.add(lines[i].substring(2));
        replyStartIndex = i + 1;
      } else {
        break;
      }
    }

    final quotedText = quotedLines.join('\n');
    final replyText = lines.sublist(replyStartIndex).join('\n');

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        // Quoted block
        Container(
          width: double.infinity,
          padding: const EdgeInsets.all(DnaSpacing.sm),
          decoration: BoxDecoration(
            color: theme.colorScheme.primary.withAlpha(15),
            border: Border(
              left: BorderSide(
                color: theme.colorScheme.primary.withAlpha(150),
                width: 3,
              ),
            ),
            borderRadius: const BorderRadius.only(
              topRight: Radius.circular(4),
              bottomRight: Radius.circular(4),
            ),
          ),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                replyAuthor,
                style: theme.textTheme.labelSmall?.copyWith(
                  color: theme.colorScheme.primary,
                  fontWeight: FontWeight.w600,
                ),
              ),
              if (quotedText.isNotEmpty) ...[
                const SizedBox(height: 2),
                Text(
                  quotedText,
                  style: theme.textTheme.bodySmall?.copyWith(
                    color: theme.colorScheme.onSurfaceVariant,
                  ),
                ),
              ],
            ],
          ),
        ),
        if (replyText.isNotEmpty) ...[
          const SizedBox(height: DnaSpacing.sm),
          SelectableText(replyText, style: theme.textTheme.bodyMedium),
        ],
      ],
    );
  }

  /// Desktop right-click context menu
  void _showContextMenu(BuildContext context, Offset position) {
    final overlay =
        Overlay.of(context).context.findRenderObject() as RenderBox;
    showMenu<String>(
      context: context,
      position: RelativeRect.fromRect(
        position & const Size(1, 1),
        Offset.zero & overlay.size,
      ),
      elevation: 8,
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
      items: [
        _menuItem(FontAwesomeIcons.reply, 'Reply', 'reply'),
        _menuItem(FontAwesomeIcons.copy, 'Copy', 'copy'),
      ],
    ).then((value) {
      if (value == 'reply') onReply();
      if (value == 'copy') Clipboard.setData(ClipboardData(text: post.body));
    });
  }

  /// Mobile long-press bottom sheet
  void _showBottomSheet(BuildContext context) {
    final theme = Theme.of(context);
    showModalBottomSheet(
      context: context,
      builder: (ctx) => SafeArea(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            ListTile(
              leading: FaIcon(FontAwesomeIcons.reply,
                  size: 18, color: theme.colorScheme.primary),
              title: const Text('Reply'),
              onTap: () {
                Navigator.pop(ctx);
                onReply();
              },
            ),
            ListTile(
              leading: FaIcon(FontAwesomeIcons.copy,
                  size: 18, color: theme.colorScheme.onSurfaceVariant),
              title: const Text('Copy'),
              onTap: () {
                Navigator.pop(ctx);
                Clipboard.setData(ClipboardData(text: post.body));
              },
            ),
          ],
        ),
      ),
    );
  }

  static PopupMenuItem<String> _menuItem(
      IconData icon, String label, String value) {
    return PopupMenuItem<String>(
      value: value,
      height: 40,
      child: Row(
        children: [
          SizedBox(width: 24, child: FaIcon(icon, size: 16)),
          const SizedBox(width: 12),
          Text(label),
        ],
      ),
    );
  }
}
