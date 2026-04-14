import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../../../providers/reaction_provider.dart';

/// A horizontal row of reaction chips for a target message.
///
/// Each chip shows an emoji and (if count > 1) a count number. Tapping a chip
/// toggles the current user's reaction for that emoji. If the current user has
/// already reacted with this emoji, the chip is rendered in an "active" style.
class ReactionChips extends ConsumerWidget {
  final String contentHash;
  final void Function(String emoji) onTap;

  const ReactionChips({
    super.key,
    required this.contentHash,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    if (contentHash.isEmpty) return const SizedBox.shrink();

    final asyncGroups = ref.watch(reactionsForMessageProvider(contentHash));
    return asyncGroups.when(
      loading: () => const SizedBox.shrink(),
      error: (_, _) => const SizedBox.shrink(),
      data: (groups) {
        if (groups.isEmpty) return const SizedBox.shrink();
        final theme = Theme.of(context);
        return Padding(
          padding: const EdgeInsets.only(top: 4),
          child: Wrap(
            spacing: 4,
            runSpacing: 4,
            children: groups.map((group) {
              return InkWell(
                onTap: () => onTap(group.emoji),
                borderRadius: BorderRadius.circular(12),
                child: Container(
                  padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                  decoration: BoxDecoration(
                    color: group.currentUserReacted
                        ? theme.colorScheme.primary.withValues(alpha: 0.2)
                        : theme.colorScheme.surfaceContainerHighest,
                    borderRadius: BorderRadius.circular(12),
                    border: Border.all(
                      color: group.currentUserReacted
                          ? theme.colorScheme.primary
                          : theme.dividerColor,
                      width: 1,
                    ),
                  ),
                  child: Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Text(group.emoji, style: const TextStyle(fontSize: 14)),
                      if (group.count > 1) ...[
                        const SizedBox(width: 4),
                        Text(
                          '${group.count}',
                          style: theme.textTheme.bodySmall?.copyWith(
                            fontWeight: FontWeight.w600,
                          ),
                        ),
                      ],
                    ],
                  ),
                ),
              );
            }).toList(),
          ),
        );
      },
    );
  }
}
