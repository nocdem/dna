import 'package:flutter/material.dart';

import '../theme/dna_spacing.dart';

/// A themed modal bottom sheet helper.
class DnaBottomSheet {
  DnaBottomSheet._();

  /// Shows a modal bottom sheet with rounded top corners and a drag handle.
  static Future<T?> show<T>(
    BuildContext context, {
    required Widget child,
    String? title,
  }) {
    final theme = Theme.of(context);

    return showModalBottomSheet<T>(
      context: context,
      backgroundColor: theme.colorScheme.surface,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(
          top: Radius.circular(DnaSpacing.radiusXl),
        ),
      ),
      isScrollControlled: true,
      builder: (context) {
        return SafeArea(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              const SizedBox(height: DnaSpacing.md),
              // Drag handle
              Container(
                width: 40,
                height: 4,
                decoration: BoxDecoration(
                  color: theme.colorScheme.onSurface.withValues(alpha: 0.2),
                  borderRadius: BorderRadius.circular(2),
                ),
              ),
              if (title != null) ...[
                const SizedBox(height: DnaSpacing.lg),
                Padding(
                  padding:
                      const EdgeInsets.symmetric(horizontal: DnaSpacing.lg),
                  child: Text(
                    title,
                    style: theme.textTheme.headlineSmall,
                  ),
                ),
              ],
              const SizedBox(height: DnaSpacing.lg),
              child,
            ],
          ),
        );
      },
    );
  }
}
