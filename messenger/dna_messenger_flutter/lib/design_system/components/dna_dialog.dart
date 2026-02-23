import 'package:flutter/material.dart';

import '../theme/dna_spacing.dart';
import 'dna_button.dart';

/// Themed dialog helpers for confirm and alert dialogs.
class DnaDialog {
  DnaDialog._();

  /// Shows a confirmation dialog and returns true if confirmed.
  static Future<bool> confirm(
    BuildContext context, {
    required String title,
    required String message,
    String confirmLabel = 'Confirm',
    String cancelLabel = 'Cancel',
  }) async {
    final result = await showDialog<bool>(
      context: context,
      builder: (context) {
        final theme = Theme.of(context);
        return AlertDialog(
          title: Text(
            title,
            style: theme.textTheme.headlineSmall,
          ),
          content: Text(
            message,
            style: theme.textTheme.bodyMedium,
          ),
          contentPadding: const EdgeInsets.fromLTRB(
            DnaSpacing.xl,
            DnaSpacing.lg,
            DnaSpacing.xl,
            0,
          ),
          actionsPadding: const EdgeInsets.all(DnaSpacing.lg),
          actions: [
            DnaButton(
              label: cancelLabel,
              variant: DnaButtonVariant.ghost,
              onPressed: () => Navigator.of(context).pop(false),
            ),
            DnaButton(
              label: confirmLabel,
              variant: DnaButtonVariant.primary,
              onPressed: () => Navigator.of(context).pop(true),
            ),
          ],
        );
      },
    );
    return result ?? false;
  }

  /// Shows an alert dialog with a single OK button.
  static Future<void> alert(
    BuildContext context, {
    required String title,
    required String message,
    String okLabel = 'OK',
  }) async {
    await showDialog<void>(
      context: context,
      builder: (context) {
        final theme = Theme.of(context);
        return AlertDialog(
          title: Text(
            title,
            style: theme.textTheme.headlineSmall,
          ),
          content: Text(
            message,
            style: theme.textTheme.bodyMedium,
          ),
          contentPadding: const EdgeInsets.fromLTRB(
            DnaSpacing.xl,
            DnaSpacing.lg,
            DnaSpacing.xl,
            0,
          ),
          actionsPadding: const EdgeInsets.all(DnaSpacing.lg),
          actions: [
            DnaButton(
              label: okLabel,
              variant: DnaButtonVariant.primary,
              onPressed: () => Navigator.of(context).pop(),
            ),
          ],
        );
      },
    );
  }
}
