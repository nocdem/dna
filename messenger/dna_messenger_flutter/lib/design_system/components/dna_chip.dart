import 'package:flutter/material.dart';

import '../theme/dna_colors.dart';
import '../theme/dna_gradients.dart';
import '../theme/dna_spacing.dart';

/// A filter/tag chip with selected and unselected states.
class DnaChip extends StatelessWidget {
  const DnaChip({
    super.key,
    required this.label,
    this.selected = false,
    this.onTap,
    this.count,
  });

  final String label;
  final bool selected;
  final VoidCallback? onTap;
  final int? count;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final isDark = theme.brightness == Brightness.dark;
    final mutedColor = isDark
        ? DnaColors.darkTextSecondary
        : DnaColors.lightTextSecondary;

    return GestureDetector(
      onTap: onTap,
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
        decoration: BoxDecoration(
          gradient: selected ? DnaGradients.primary : null,
          color: selected
              ? null
              : theme.colorScheme.surface,
          borderRadius: BorderRadius.circular(DnaSpacing.radiusFull),
          border: selected
              ? null
              : Border.all(
                  color: theme.colorScheme.outlineVariant,
                  width: 1,
                ),
        ),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Text(
              label,
              style: TextStyle(
                color: selected ? Colors.white : mutedColor,
                fontSize: 13,
                fontWeight: FontWeight.w500,
              ),
            ),
            if (count != null) ...[
              const SizedBox(width: 6),
              Container(
                padding:
                    const EdgeInsets.symmetric(horizontal: 6, vertical: 1),
                decoration: BoxDecoration(
                  color: selected
                      ? Colors.white.withValues(alpha: 0.25)
                      : DnaColors.primaryFixed.withValues(alpha: 0.15),
                  borderRadius:
                      BorderRadius.circular(DnaSpacing.radiusFull),
                ),
                child: Text(
                  count.toString(),
                  style: TextStyle(
                    color: selected ? Colors.white : DnaColors.primaryFixed,
                    fontSize: 11,
                    fontWeight: FontWeight.w600,
                  ),
                ),
              ),
            ],
          ],
        ),
      ),
    );
  }
}
