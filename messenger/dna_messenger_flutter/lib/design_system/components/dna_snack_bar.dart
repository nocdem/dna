import 'package:flutter/material.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';

import '../theme/dna_colors.dart';
import '../theme/dna_spacing.dart';

/// Themed snackbar helpers for success, error, and info toasts.
class DnaSnackBar {
  DnaSnackBar._();

  /// Shows a success snackbar with a green check icon.
  static void success(BuildContext context, String message) {
    _show(
      context,
      message: message,
      icon: FontAwesomeIcons.solidCircleCheck,
      iconColor: DnaColors.success,
      type: _SnackType.success,
    );
  }

  /// Shows an error snackbar with a red exclamation icon.
  static void error(BuildContext context, String message) {
    _show(
      context,
      message: message,
      icon: FontAwesomeIcons.circleExclamation,
      iconColor: DnaColors.error,
      type: _SnackType.error,
    );
  }

  /// Shows an info snackbar with a blue info icon.
  static void info(BuildContext context, String message) {
    _show(
      context,
      message: message,
      icon: FontAwesomeIcons.circleInfo,
      iconColor: DnaColors.info,
      type: _SnackType.info,
    );
  }

  static void _show(
    BuildContext context, {
    required String message,
    required IconData icon,
    required Color iconColor,
    required _SnackType type,
  }) {
    final isDark = Theme.of(context).brightness == Brightness.dark;

    final Color background;
    switch (type) {
      case _SnackType.success:
        background = isDark
            ? DnaColors.snackbarSuccessDark
            : DnaColors.snackbarSuccessLight;
      case _SnackType.error:
        background = isDark
            ? DnaColors.snackbarErrorDark
            : DnaColors.snackbarErrorLight;
      case _SnackType.info:
        background = isDark
            ? DnaColors.snackbarInfoDark
            : DnaColors.snackbarInfoLight;
    }

    final textColor = isDark ? DnaColors.darkText : DnaColors.lightText;

    ScaffoldMessenger.of(context)
      ..hideCurrentSnackBar()
      ..showSnackBar(
        SnackBar(
          content: Row(
            children: [
              FaIcon(icon, size: DnaSpacing.iconMd, color: iconColor),
              const SizedBox(width: DnaSpacing.md),
              Expanded(
                child: Text(
                  message,
                  style: TextStyle(color: textColor, fontSize: 14),
                ),
              ),
            ],
          ),
          backgroundColor: background,
          behavior: SnackBarBehavior.floating,
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(DnaSpacing.radiusSm),
          ),
          duration: const Duration(seconds: 3),
        ),
      );
  }
}

enum _SnackType { success, error, info }
