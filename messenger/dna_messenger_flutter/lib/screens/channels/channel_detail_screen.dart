// Channel Detail Screen - shows the post stream for a single channel
import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';
import '../../design_system/design_system.dart';
import '../../ffi/dna_engine.dart' as ffi show UserProfile;
import '../../l10n/app_localizations.dart';
import '../../providers/providers.dart';
import '../../models/channel.dart';
import '../../utils/time_format.dart';

/// 8-color Telegram-style palette for channel members
const _memberColors = [
  Color(0xFFE57373), // red
  Color(0xFF81C784), // green
  Color(0xFF64B5F6), // blue
  Color(0xFFFFB74D), // orange
  Color(0xFFBA68C8), // purple
  Color(0xFF4DB6AC), // teal
  Color(0xFFFF8A65), // deep orange
  Color(0xFFA1887F), // brown
];

/// Get a stable color for a fingerprint
Color _memberColor(String fingerprint) {
  var hash = 0;
  for (var i = 0; i < fingerprint.length; i++) {
    hash = fingerprint.codeUnitAt(i) + ((hash << 5) - hash);
  }
  return _memberColors[hash.abs() % _memberColors.length];
}

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
    final profileCache = ref.watch(contactProfileCacheProvider);
    final currentFp = ref.watch(currentFingerprintProvider);

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
                          AppLocalizations.of(context).channelNoPosts,
                          style: theme.textTheme.bodyLarge?.copyWith(
                            color: theme.colorScheme.onSurfaceVariant,
                          ),
                        ),
                      ],
                    ),
                  );
                }

                // Trigger name + profile resolution for all authors
                final fingerprints =
                    posts.map((p) => p.authorFingerprint).toSet().toList();
                WidgetsBinding.instance.addPostFrameCallback((_) {
                  ref
                      .read(nameResolverProvider.notifier)
                      .resolveNames(fingerprints);
                  ref
                      .read(contactProfileCacheProvider.notifier)
                      .prefetchProfiles(fingerprints);
                });

                // Sort oldest first (ListView reverse:true puts newest at bottom)
                final sorted = List<ChannelPost>.from(posts)
                  ..sort((a, b) => a.createdAt.compareTo(b.createdAt));

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
                              label: Text(AppLocalizations.of(context).channelLoadOlderPosts),
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
                      final isOutgoing =
                          currentFp != null && post.authorFingerprint == currentFp;
                      return _PostBubble(
                        post: post,
                        nameCache: nameCache,
                        profileCache: profileCache,
                        isOutgoing: isOutgoing,
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
                      label: Text(AppLocalizations.of(context).retry),
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
                        hintText: AppLocalizations.of(context).channelWritePost,
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
        title: Text(AppLocalizations.of(context).channelUnsubscribe),
        content: Text(
            'Unsubscribe from "${widget.channelName}"? You can re-subscribe later from Discover.'),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(),
            child: Text(AppLocalizations.of(context).cancel),
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
            child: Text(AppLocalizations.of(context).channelUnsubscribe),
          ),
        ],
      ),
    );
  }
}

/// Telegram-style chat bubble for channel posts
class _PostBubble extends StatelessWidget {
  final ChannelPost post;
  final Map<String, String> nameCache;
  final Map<String, ffi.UserProfile> profileCache;
  final bool isOutgoing;
  final VoidCallback onReply;

  const _PostBubble({
    required this.post,
    required this.nameCache,
    required this.profileCache,
    required this.isOutgoing,
    required this.onReply,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final authorName = nameCache[post.authorFingerprint];
    final displayAuthor = authorName != null && authorName.isNotEmpty
        ? authorName
        : '${post.authorFingerprint.substring(0, 16)}...';
    final color = _memberColor(post.authorFingerprint);

    return GestureDetector(
      onLongPress: () => _showBottomSheet(context),
      onSecondaryTapUp: (details) =>
          _showContextMenu(context, details.globalPosition),
      child: Padding(
        padding: const EdgeInsets.only(bottom: 2),
        child: Row(
          mainAxisAlignment:
              isOutgoing ? MainAxisAlignment.end : MainAxisAlignment.start,
          crossAxisAlignment: CrossAxisAlignment.end,
          children: [
            // Avatar for incoming messages
            if (!isOutgoing) ...[
              _buildAvatar(displayAuthor, color),
              const SizedBox(width: DnaSpacing.sm),
            ],
            // Bubble
            Flexible(
              child: Container(
                constraints: BoxConstraints(
                  maxWidth: MediaQuery.of(context).size.width * 0.75,
                ),
                margin: EdgeInsets.only(
                  left: isOutgoing ? 48 : 0,
                  right: isOutgoing ? 0 : 48,
                ),
                padding:
                    const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                decoration: BoxDecoration(
                  color: isOutgoing
                      ? theme.colorScheme.primary
                      : theme.colorScheme.surface,
                  borderRadius: BorderRadius.only(
                    topLeft: const Radius.circular(16),
                    topRight: const Radius.circular(16),
                    bottomLeft: Radius.circular(isOutgoing ? 16 : 4),
                    bottomRight: Radius.circular(isOutgoing ? 4 : 16),
                  ),
                ),
                child: Column(
                  crossAxisAlignment: isOutgoing
                      ? CrossAxisAlignment.end
                      : CrossAxisAlignment.start,
                  children: [
                    // Author name (incoming only)
                    if (!isOutgoing) ...[
                      Row(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          Flexible(
                            child: Text(
                              displayAuthor,
                              style: theme.textTheme.labelMedium?.copyWith(
                                color: color,
                                fontWeight: FontWeight.w700,
                              ),
                              overflow: TextOverflow.ellipsis,
                            ),
                          ),
                          if (post.verified) ...[
                            const SizedBox(width: 4),
                            FaIcon(
                              FontAwesomeIcons.solidCircleCheck,
                              size: 12,
                              color: color,
                            ),
                          ],
                        ],
                      ),
                      const SizedBox(height: 2),
                    ],
                    // Post body (with reply rendering)
                    _buildBody(context, theme),
                    const SizedBox(height: 3),
                    // Timestamp row
                    Row(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        if (post.verified && isOutgoing) ...[
                          FaIcon(
                            FontAwesomeIcons.solidCircleCheck,
                            size: 10,
                            color: isOutgoing
                                ? theme.colorScheme.onPrimary.withAlpha(179)
                                : theme.colorScheme.onSurfaceVariant,
                          ),
                          const SizedBox(width: 4),
                        ],
                        Text(
                          formatRelativeTime(post.createdAt),
                          style: theme.textTheme.bodySmall?.copyWith(
                            fontSize: 10,
                            color: isOutgoing
                                ? theme.colorScheme.onPrimary.withAlpha(179)
                                : theme.colorScheme.onSurfaceVariant,
                          ),
                        ),
                      ],
                    ),
                  ],
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  /// Build avatar: real photo from DHT profile, or colored initial fallback
  Widget _buildAvatar(String displayAuthor, Color color) {
    final profile = profileCache[post.authorFingerprint];
    Uint8List? avatarBytes;
    if (profile != null) {
      avatarBytes = profile.decodeAvatar();
    }

    if (avatarBytes != null && avatarBytes.isNotEmpty) {
      return CircleAvatar(
        radius: 16,
        backgroundImage: MemoryImage(avatarBytes),
      );
    }

    // Colored initial fallback
    final initial = displayAuthor.isNotEmpty ? displayAuthor[0].toUpperCase() : '?';
    return CircleAvatar(
      radius: 16,
      backgroundColor: color,
      child: Text(
        initial,
        style: const TextStyle(
          color: Colors.white,
          fontSize: 14,
          fontWeight: FontWeight.w600,
        ),
      ),
    );
  }

  /// Renders post body — parses reply format if present.
  Widget _buildBody(BuildContext context, ThemeData theme) {
    final body = post.body;
    final textColor = isOutgoing
        ? theme.colorScheme.onPrimary
        : theme.colorScheme.onSurface;

    // Check for reply format: "↩ Re: author\n> quoted\nreply"
    if (!body.startsWith('↩ Re: ')) {
      return SelectableText(
        body,
        style: theme.textTheme.bodyMedium?.copyWith(color: textColor),
      );
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
    final quoteColor = isOutgoing
        ? theme.colorScheme.onPrimary
        : _memberColor(post.authorFingerprint);

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        // Quoted block
        Container(
          width: double.infinity,
          padding: const EdgeInsets.all(DnaSpacing.sm),
          decoration: BoxDecoration(
            color: isOutgoing
                ? theme.colorScheme.onPrimary.withAlpha(20)
                : quoteColor.withAlpha(15),
            border: Border(
              left: BorderSide(
                color: isOutgoing
                    ? theme.colorScheme.onPrimary.withAlpha(128)
                    : quoteColor.withAlpha(150),
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
                  color: isOutgoing
                      ? theme.colorScheme.onPrimary.withAlpha(220)
                      : quoteColor,
                  fontWeight: FontWeight.w600,
                ),
              ),
              if (quotedText.isNotEmpty) ...[
                const SizedBox(height: 2),
                Text(
                  quotedText,
                  style: theme.textTheme.bodySmall?.copyWith(
                    color: isOutgoing
                        ? theme.colorScheme.onPrimary.withAlpha(153)
                        : theme.colorScheme.onSurfaceVariant,
                  ),
                  maxLines: 3,
                  overflow: TextOverflow.ellipsis,
                ),
              ],
            ],
          ),
        ),
        if (replyText.isNotEmpty) ...[
          const SizedBox(height: DnaSpacing.sm),
          SelectableText(
            replyText,
            style: theme.textTheme.bodyMedium?.copyWith(color: textColor),
          ),
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
        _menuItem(FontAwesomeIcons.reply, AppLocalizations.of(context).channelReply, 'reply'),
        _menuItem(FontAwesomeIcons.copy, AppLocalizations.of(context).channelCopy, 'copy'),
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
              title: Text(AppLocalizations.of(context).channelReply),
              onTap: () {
                Navigator.pop(ctx);
                onReply();
              },
            ),
            ListTile(
              leading: FaIcon(FontAwesomeIcons.copy,
                  size: 18, color: theme.colorScheme.onSurfaceVariant),
              title: Text(AppLocalizations.of(context).channelCopy),
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
