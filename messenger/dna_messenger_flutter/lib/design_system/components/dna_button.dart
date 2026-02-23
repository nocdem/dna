import 'package:flutter/material.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';

import '../theme/dna_colors.dart';
import '../theme/dna_gradients.dart';
import '../theme/dna_spacing.dart';

/// Button variant determines visual style.
enum DnaButtonVariant { primary, secondary, ghost }

/// A themed button with gradient primary, outlined secondary, and ghost variants.
class DnaButton extends StatelessWidget {
  const DnaButton({
    super.key,
    required this.label,
    this.onPressed,
    this.variant = DnaButtonVariant.primary,
    this.loading = false,
    this.icon,
    this.expand = false,
  });

  final String label;
  final VoidCallback? onPressed;
  final DnaButtonVariant variant;
  final bool loading;
  final IconData? icon;
  final bool expand;

  bool get _enabled => onPressed != null && !loading;

  @override
  Widget build(BuildContext context) {
    return switch (variant) {
      DnaButtonVariant.primary => _buildPrimary(context),
      DnaButtonVariant.secondary => _buildSecondary(context),
      DnaButtonVariant.ghost => _buildGhost(context),
    };
  }

  Widget _buildPrimary(BuildContext context) {
    final borderRadius = BorderRadius.circular(DnaSpacing.radiusSm);

    Widget button = Container(
      decoration: BoxDecoration(
        gradient: _enabled ? DnaGradients.primary : null,
        color: _enabled ? null : Colors.grey.shade700,
        borderRadius: borderRadius,
        boxShadow: _enabled
            ? [
                BoxShadow(
                  color: DnaColors.primaryFixed.withValues(alpha: 0.3),
                  blurRadius: 8,
                  offset: const Offset(0, 2),
                ),
              ]
            : null,
      ),
      child: Material(
        color: Colors.transparent,
        child: InkWell(
          onTap: _enabled ? onPressed : null,
          borderRadius: borderRadius,
          child: Padding(
            padding: const EdgeInsets.symmetric(
              horizontal: DnaSpacing.xl,
              vertical: DnaSpacing.md,
            ),
            child: _buildContent(Colors.white),
          ),
        ),
      ),
    );

    if (expand) {
      button = SizedBox(width: double.infinity, child: button);
    }

    return button;
  }

  Widget _buildSecondary(BuildContext context) {
    final child = _buildContent(DnaColors.primaryFixed);

    if (expand) {
      return SizedBox(
        width: double.infinity,
        child: OutlinedButton(
          onPressed: _enabled ? onPressed : null,
          child: child,
        ),
      );
    }

    return OutlinedButton(
      onPressed: _enabled ? onPressed : null,
      child: child,
    );
  }

  Widget _buildGhost(BuildContext context) {
    final child = _buildContent(DnaColors.primaryFixed);

    if (expand) {
      return SizedBox(
        width: double.infinity,
        child: TextButton(
          onPressed: _enabled ? onPressed : null,
          child: child,
        ),
      );
    }

    return TextButton(
      onPressed: _enabled ? onPressed : null,
      child: child,
    );
  }

  Widget _buildContent(Color color) {
    final List<Widget> children = [];

    if (loading) {
      children.add(
        SizedBox(
          width: DnaSpacing.iconSm,
          height: DnaSpacing.iconSm,
          child: CircularProgressIndicator(
            strokeWidth: 2,
            color: color,
          ),
        ),
      );
      children.add(const SizedBox(width: DnaSpacing.sm));
    } else if (icon != null) {
      children.add(FaIcon(icon!, size: DnaSpacing.iconSm, color: color));
      children.add(const SizedBox(width: DnaSpacing.sm));
    }

    children.add(
      Text(
        label,
        style: TextStyle(
          color: color,
          fontWeight: FontWeight.w600,
          fontSize: 14,
        ),
      ),
    );

    return Row(
      mainAxisSize: MainAxisSize.min,
      mainAxisAlignment: MainAxisAlignment.center,
      children: children,
    );
  }
}
