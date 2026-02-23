import 'package:flutter/material.dart';

import '../theme/dna_gradients.dart';
import '../theme/dna_spacing.dart';

/// A themed card container with optional gradient header and tap support.
class DnaCard extends StatelessWidget {
  const DnaCard({
    super.key,
    required this.child,
    this.padding,
    this.margin,
    this.elevation,
    this.gradientHeader = false,
    this.onTap,
    this.borderRadius,
  });

  final Widget child;
  final EdgeInsetsGeometry? padding;
  final EdgeInsetsGeometry? margin;
  final double? elevation;
  final bool gradientHeader;
  final VoidCallback? onTap;
  final double? borderRadius;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final radius = borderRadius ?? DnaSpacing.radiusMd;
    final shape = RoundedRectangleBorder(
      borderRadius: BorderRadius.circular(radius),
    );

    Widget content = Padding(
      padding: padding ?? const EdgeInsets.all(DnaSpacing.lg),
      child: child,
    );

    if (onTap != null) {
      content = InkWell(
        onTap: onTap,
        borderRadius: BorderRadius.circular(radius),
        child: content,
      );
    }

    Widget card = Material(
      color: theme.colorScheme.surface,
      elevation: elevation ?? DnaSpacing.elevationLow,
      shadowColor: theme.cardTheme.shadowColor ?? Colors.black26,
      shape: shape,
      clipBehavior: Clip.antiAlias,
      child: content,
    );

    if (gradientHeader) {
      card = Container(
        decoration: BoxDecoration(
          gradient: DnaGradients.primary,
          borderRadius: BorderRadius.circular(radius),
        ),
        child: card,
      );
    }

    if (margin != null) {
      card = Padding(padding: margin!, child: card);
    }

    return card;
  }
}
