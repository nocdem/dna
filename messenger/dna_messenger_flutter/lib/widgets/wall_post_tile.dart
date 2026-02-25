import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';
import '../design_system/design_system.dart';
import '../ffi/dna_engine.dart';
import '../utils/time_format.dart';

class WallPostTile extends ConsumerWidget {
  final WallPost post;
  final String myFingerprint;
  final VoidCallback? onDelete;
  final VoidCallback? onAuthorTap;
  final VoidCallback? onShare;
  final VoidCallback? onReply;

  const WallPostTile({
    super.key,
    required this.post,
    required this.myFingerprint,
    this.onDelete,
    this.onAuthorTap,
    this.onShare,
    this.onReply,
  });

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final isOwn = post.isOwn(myFingerprint);
    final theme = Theme.of(context);

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
                label: 'Reply',
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
