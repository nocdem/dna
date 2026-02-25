import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';
import 'package:intl/intl.dart';
import '../design_system/design_system.dart';
import '../ffi/dna_engine.dart';

class WallPostTile extends ConsumerWidget {
  final WallPost post;
  final String myFingerprint;
  final VoidCallback? onDelete;
  final VoidCallback? onAuthorTap;

  const WallPostTile({
    super.key,
    required this.post,
    required this.myFingerprint,
    this.onDelete,
    this.onAuthorTap,
  });

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final isOwn = post.isOwn(myFingerprint);
    final theme = Theme.of(context);

    return DnaCard(
      padding: const EdgeInsets.all(DnaSpacing.md),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Author row
          Row(
            children: [
              DnaAvatar(
                name: post.authorName.isNotEmpty ? post.authorName : '?',
                size: DnaAvatarSize.md,
              ),
              const SizedBox(width: DnaSpacing.sm),
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
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                      Text(
                        _formatTime(post.timestamp),
                        style: theme.textTheme.bodySmall?.copyWith(
                          color: theme.colorScheme.onSurfaceVariant,
                        ),
                      ),
                    ],
                  ),
                ),
              ),
              if (isOwn)
                IconButton(
                  icon: const FaIcon(FontAwesomeIcons.trash, size: 14),
                  onPressed: onDelete,
                  tooltip: 'Delete post',
                  iconSize: 14,
                ),
            ],
          ),
          const SizedBox(height: DnaSpacing.sm),
          // Post text
          Text(
            post.text,
            style: theme.textTheme.bodyMedium,
          ),
        ],
      ),
    );
  }
}

String _formatTime(DateTime time) {
  final now = DateTime.now();
  final diff = now.difference(time);
  if (diff.inMinutes < 60) {
    return '${diff.inMinutes}m ago';
  } else if (diff.inHours < 24) {
    return '${diff.inHours}h ago';
  } else if (diff.inDays < 7) {
    return '${diff.inDays}d ago';
  } else {
    return DateFormat('MMM d').format(time);
  }
}
