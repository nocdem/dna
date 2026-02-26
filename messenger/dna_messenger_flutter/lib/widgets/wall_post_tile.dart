import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';
import '../design_system/design_system.dart';
import '../ffi/dna_engine.dart';
import '../providers/contact_profile_cache_provider.dart';
import '../providers/identity_profile_cache_provider.dart';
import '../utils/time_format.dart';

class WallPostTile extends ConsumerWidget {
  final WallPost post;
  final String myFingerprint;
  final VoidCallback? onDelete;
  final VoidCallback? onAuthorTap;
  final VoidCallback? onShare;
  final VoidCallback? onReply;
  final List<WallComment>? comments;
  final VoidCallback? onViewAllComments;

  const WallPostTile({
    super.key,
    required this.post,
    required this.myFingerprint,
    this.onDelete,
    this.onAuthorTap,
    this.onShare,
    this.onReply,
    this.comments,
    this.onViewAllComments,
  });

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final isOwn = post.isOwn(myFingerprint);
    final theme = Theme.of(context);
    final cachedProfile = ref.watch(
      contactProfileCacheProvider.select((cache) => cache[post.authorFingerprint]),
    );
    Uint8List? avatarBytes = cachedProfile?.decodeAvatar();

    // Own profile lives in identityProfileCacheProvider, not contactProfileCache
    if (avatarBytes == null && isOwn) {
      final cachedIdentity = ref.watch(
        identityProfileCacheProvider.select((cache) => cache[myFingerprint]),
      );
      if (cachedIdentity != null && cachedIdentity.avatarBase64.isNotEmpty) {
        try {
          avatarBytes = base64Decode(cachedIdentity.avatarBase64);
        } catch (_) {}
      }
    }

    return DnaCard(
      padding: const EdgeInsets.only(
        left: DnaSpacing.lg,
        right: DnaSpacing.lg,
        top: DnaSpacing.lg,
        bottom: DnaSpacing.sm,
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Author row
          Row(
            children: [
              GestureDetector(
                onTap: onAuthorTap,
                child: DnaAvatar(
                  imageBytes: avatarBytes,
                  name: post.authorName.isNotEmpty ? post.authorName : '?',
                  size: DnaAvatarSize.md,
                ),
              ),
              const SizedBox(width: DnaSpacing.md),
              Expanded(
                child: GestureDetector(
                  onTap: onAuthorTap,
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        post.authorName.isNotEmpty
                            ? post.authorName
                            : post.authorFingerprint.substring(0, 16),
                        style: theme.textTheme.titleSmall?.copyWith(
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                      const SizedBox(height: 2),
                      Text(
                        formatRelativeTime(post.timestamp),
                        style: theme.textTheme.bodySmall?.copyWith(
                          color: theme.colorScheme.onSurfaceVariant,
                          fontSize: 11,
                        ),
                      ),
                    ],
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: DnaSpacing.md),
          // Image (v0.7.0+)
          if (post.hasImage) _WallPostImage(imageJson: post.imageJson!),
          // Post text
          Text(
            post.text,
            style: theme.textTheme.bodyMedium?.copyWith(
              height: 1.4,
            ),
          ),
          const SizedBox(height: DnaSpacing.sm),
          // Inline comments preview
          if (comments != null && comments!.isNotEmpty) ...[
            Divider(
              height: 1,
              color: theme.colorScheme.outlineVariant.withAlpha(80),
            ),
            _InlineComments(
              comments: comments!,
              onViewAll: onViewAllComments ?? onReply,
            ),
          ],
          // Action bar
          Divider(
            height: 1,
            color: theme.colorScheme.outlineVariant.withAlpha(80),
          ),
          Row(
            children: [
              _ActionButton(
                icon: FontAwesomeIcons.copy,
                label: 'Copy',
                onTap: () {
                  Clipboard.setData(ClipboardData(text: post.text));
                  ScaffoldMessenger.of(context).showSnackBar(
                    const SnackBar(
                      content: Text('Copied to clipboard'),
                      duration: Duration(seconds: 1),
                    ),
                  );
                },
              ),
              _ActionButton(
                icon: FontAwesomeIcons.comment,
                label: comments != null && comments!.isNotEmpty
                    ? 'Reply (${comments!.length})'
                    : 'Reply',
                onTap: onReply,
              ),
              if (!isOwn && onShare != null)
                _ActionButton(
                  icon: FontAwesomeIcons.retweet,
                  label: 'Repost',
                  onTap: onShare,
                ),
              if (isOwn)
                _ActionButton(
                  icon: FontAwesomeIcons.trash,
                  label: 'Delete',
                  onTap: onDelete,
                  color: DnaColors.error,
                ),
            ],
          ),
        ],
      ),
    );
  }
}

/// Displays an image from wall post image_json
class _WallPostImage extends StatelessWidget {
  final String imageJson;

  const _WallPostImage({required this.imageJson});

  Uint8List? _decodeImage() {
    try {
      final map = jsonDecode(imageJson) as Map<String, dynamic>;
      final data = map['data'] as String?;
      if (data == null || data.isEmpty) return null;
      return base64Decode(data);
    } catch (e) {
      return null;
    }
  }

  @override
  Widget build(BuildContext context) {
    final bytes = _decodeImage();
    if (bytes == null) return const SizedBox.shrink();

    return Padding(
      padding: const EdgeInsets.only(bottom: DnaSpacing.sm),
      child: ClipRRect(
        borderRadius: BorderRadius.circular(DnaSpacing.radiusSm),
        child: GestureDetector(
          onTap: () => _showFullscreen(context, bytes),
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxHeight: 300),
            child: Image.memory(
              bytes,
              fit: BoxFit.cover,
              width: double.infinity,
              errorBuilder: (_, e, s) => const SizedBox.shrink(),
            ),
          ),
        ),
      ),
    );
  }

  void _showFullscreen(BuildContext context, Uint8List bytes) {
    Navigator.of(context).push(
      MaterialPageRoute(
        builder: (_) => Scaffold(
          backgroundColor: Colors.black,
          appBar: AppBar(
            backgroundColor: Colors.black,
            iconTheme: const IconThemeData(color: Colors.white),
          ),
          body: Center(
            child: InteractiveViewer(
              child: Image.memory(bytes),
            ),
          ),
        ),
      ),
    );
  }
}

/// Shows up to 3 most recent comments inline under a wall post
class _InlineComments extends StatelessWidget {
  final List<WallComment> comments;
  final VoidCallback? onViewAll;

  static const int _maxPreview = 3;

  const _InlineComments({
    required this.comments,
    this.onViewAll,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final preview = comments.length <= _maxPreview
        ? comments
        : comments.sublist(0, _maxPreview);

    return Padding(
      padding: const EdgeInsets.symmetric(vertical: DnaSpacing.sm),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          if (comments.length > _maxPreview)
            GestureDetector(
              onTap: onViewAll,
              child: Padding(
                padding: const EdgeInsets.only(bottom: DnaSpacing.xs),
                child: Text(
                  'View all ${comments.length} comments',
                  style: theme.textTheme.bodySmall?.copyWith(
                    color: theme.colorScheme.onSurfaceVariant,
                  ),
                ),
              ),
            ),
          for (final comment in preview)
            Padding(
              padding: const EdgeInsets.only(bottom: 2),
              child: Text.rich(
                TextSpan(
                  children: [
                    TextSpan(
                      text: comment.authorName.isNotEmpty
                          ? comment.authorName
                          : comment.authorFingerprint.substring(0, 12),
                      style: theme.textTheme.bodySmall?.copyWith(
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                    const TextSpan(text: '  '),
                    TextSpan(
                      text: comment.body,
                      style: theme.textTheme.bodySmall,
                    ),
                  ],
                ),
                maxLines: 2,
                overflow: TextOverflow.ellipsis,
              ),
            ),
        ],
      ),
    );
  }
}

class _ActionButton extends StatelessWidget {
  final IconData icon;
  final String label;
  final VoidCallback? onTap;
  final Color? color;

  const _ActionButton({
    required this.icon,
    required this.label,
    this.onTap,
    this.color,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final effectiveColor = color ?? theme.colorScheme.onSurfaceVariant;

    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(DnaSpacing.radiusSm),
      child: Padding(
        padding: const EdgeInsets.symmetric(
          horizontal: DnaSpacing.md,
          vertical: DnaSpacing.sm,
        ),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            FaIcon(icon, size: 13, color: effectiveColor),
            const SizedBox(width: 6),
            Text(
              label,
              style: theme.textTheme.bodySmall?.copyWith(
                color: effectiveColor,
                fontSize: 12,
              ),
            ),
          ],
        ),
      ),
    );
  }
}
