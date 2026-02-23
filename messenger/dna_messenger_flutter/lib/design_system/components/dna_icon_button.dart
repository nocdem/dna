import 'package:flutter/material.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';

import '../theme/dna_colors.dart';
import '../theme/dna_gradients.dart';

/// Icon button variant determines visual style.
enum DnaIconButtonVariant { solid, outlined, ghost }

/// A circular icon button with solid, outlined, and ghost variants.
class DnaIconButton extends StatelessWidget {
  const DnaIconButton({
    super.key,
    required this.icon,
    this.onPressed,
    this.variant = DnaIconButtonVariant.ghost,
    this.size = 40,
  });

  final IconData icon;
  final VoidCallback? onPressed;
  final DnaIconButtonVariant variant;
  final double size;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final iconSize = size * 0.45;

    return switch (variant) {
      DnaIconButtonVariant.solid => _buildSolid(iconSize),
      DnaIconButtonVariant.outlined => _buildOutlined(iconSize),
      DnaIconButtonVariant.ghost => _buildGhost(theme, iconSize),
    };
  }

  Widget _buildSolid(double iconSize) {
    return Container(
      width: size,
      height: size,
      decoration: BoxDecoration(
        gradient: DnaGradients.primary,
        shape: BoxShape.circle,
        boxShadow: [
          BoxShadow(
            color: DnaColors.primaryFixed.withValues(alpha: 0.3),
            blurRadius: 6,
            offset: const Offset(0, 2),
          ),
        ],
      ),
      child: Material(
        color: Colors.transparent,
        shape: const CircleBorder(),
        clipBehavior: Clip.antiAlias,
        child: InkWell(
          onTap: onPressed,
          customBorder: const CircleBorder(),
          child: Center(
            child: FaIcon(icon, size: iconSize, color: Colors.white),
          ),
        ),
      ),
    );
  }

  Widget _buildOutlined(double iconSize) {
    return Container(
      width: size,
      height: size,
      decoration: BoxDecoration(
        shape: BoxShape.circle,
        border: Border.all(color: DnaColors.primaryFixed, width: 1.5),
      ),
      child: Material(
        color: Colors.transparent,
        shape: const CircleBorder(),
        clipBehavior: Clip.antiAlias,
        child: InkWell(
          onTap: onPressed,
          customBorder: const CircleBorder(),
          child: Center(
            child: FaIcon(
              icon,
              size: iconSize,
              color: DnaColors.primaryFixed,
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildGhost(ThemeData theme, double iconSize) {
    return SizedBox(
      width: size,
      height: size,
      child: Material(
        color: Colors.transparent,
        shape: const CircleBorder(),
        clipBehavior: Clip.antiAlias,
        child: InkWell(
          onTap: onPressed,
          customBorder: const CircleBorder(),
          child: Center(
            child: FaIcon(
              icon,
              size: iconSize,
              color: theme.colorScheme.onSurface,
            ),
          ),
        ),
      ),
    );
  }
}
