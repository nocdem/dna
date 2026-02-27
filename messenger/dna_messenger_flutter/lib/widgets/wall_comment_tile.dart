import 'package:flutter/material.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';
import '../design_system/design_system.dart';
import '../ffi/dna_engine.dart';
import '../utils/time_format.dart';

/// Displays a single wall comment (top-level or reply)
class WallCommentTile extends StatelessWidget {
  final WallComment comment;
  final VoidCallback? onReply;
  final bool isReply;

  const WallCommentTile({
    super.key,
    required this.comment,
    this.onReply,
    this.isReply = false,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return Padding(
      padding: EdgeInsets.only(
        left: isReply ? DnaSpacing.xl : 0,
        bottom: DnaSpacing.sm,
      ),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          DnaAvatar(
            name: comment.authorName.isNotEmpty ? comment.authorName : '?',
            size: isReply ? DnaAvatarSize.sm : DnaAvatarSize.sm,
          ),
          const SizedBox(width: DnaSpacing.sm),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                // Author name + timestamp
                Row(
                  children: [
                    Text(
                      comment.authorName.isNotEmpty
                          ? comment.authorName
                          : comment.authorFingerprint.substring(0, 12),
                      style: theme.textTheme.bodySmall?.copyWith(
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                    const SizedBox(width: DnaSpacing.sm),
                    Text(
                      formatRelativeTime(comment.createdAt),
                      style: theme.textTheme.bodySmall?.copyWith(
                        color: theme.colorScheme.onSurfaceVariant,
                        fontSize: 11,
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 2),
                // Comment body
                Text(
                  comment.body,
                  style: theme.textTheme.bodyMedium?.copyWith(
                    height: 1.3,
                  ),
                ),
                const SizedBox(height: 2),
                // Reply button
                if (!isReply)
                  InkWell(
                    onTap: onReply,
                    borderRadius: BorderRadius.circular(4),
                    child: Padding(
                      padding: const EdgeInsets.symmetric(
                        vertical: 2,
                        horizontal: 4,
                      ),
                      child: Row(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          FaIcon(
                            FontAwesomeIcons.reply,
                            size: 11,
                            color: theme.colorScheme.onSurfaceVariant,
                          ),
                          const SizedBox(width: 4),
                          Text(
                            'Reply',
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
          ),
        ],
      ),
    );
  }
}
