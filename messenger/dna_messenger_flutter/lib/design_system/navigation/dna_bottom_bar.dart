import 'package:flutter/material.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';
import '../theme/dna_colors.dart';
import '../theme/dna_gradients.dart';
import '../theme/dna_spacing.dart';

/// Data class for a bottom bar tab item
class DnaBottomBarItem {
  final IconData icon;
  final IconData activeIcon;
  final String label;
  final int badgeCount;

  const DnaBottomBarItem({
    required this.icon,
    required this.activeIcon,
    required this.label,
    this.badgeCount = 0,
  });
}

/// Bottom navigation bar with gradient active state and badge support
class DnaBottomBar extends StatelessWidget {
  final int currentIndex;
  final ValueChanged<int> onTap;
  final List<DnaBottomBarItem> items;

  const DnaBottomBar({
    super.key,
    required this.currentIndex,
    required this.onTap,
    required this.items,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final isDark = theme.brightness == Brightness.dark;
    final surface = isDark ? DnaColors.darkSurface : DnaColors.lightSurface;
    final muted =
        isDark ? DnaColors.darkTextSecondary : DnaColors.lightTextSecondary;

    return Container(
      height:
          DnaSpacing.bottomBarHeight + MediaQuery.of(context).padding.bottom,
      decoration: BoxDecoration(
        color: surface,
        boxShadow: [
          BoxShadow(
            color: Colors.black.withValues(alpha: isDark ? 0.3 : 0.08),
            blurRadius: 8,
            offset: const Offset(0, -2),
          ),
        ],
      ),
      child: SafeArea(
        top: false,
        child: Row(
          children: List.generate(items.length, (i) {
            final item = items[i];
            final isActive = i == currentIndex;
            return Expanded(
              child: _BottomBarTab(
                item: item,
                isActive: isActive,
                mutedColor: muted,
                onTap: () => onTap(i),
              ),
            );
          }),
        ),
      ),
    );
  }
}

class _BottomBarTab extends StatelessWidget {
  final DnaBottomBarItem item;
  final bool isActive;
  final Color mutedColor;
  final VoidCallback onTap;

  const _BottomBarTab({
    required this.item,
    required this.isActive,
    required this.mutedColor,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      onTap: onTap,
      behavior: HitTestBehavior.opaque,
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          // Active indicator line
          if (isActive)
            Container(
              width: 24,
              height: 2,
              margin: const EdgeInsets.only(bottom: DnaSpacing.xs),
              decoration: BoxDecoration(
                gradient: DnaGradients.primary,
                borderRadius: BorderRadius.circular(1),
              ),
            )
          else
            const SizedBox(height: 2 + DnaSpacing.xs),

          // Icon with optional badge
          _buildIconWithBadge(),

          const SizedBox(height: DnaSpacing.xs),

          // Label
          Text(
            item.label,
            style: TextStyle(
              fontSize: 11,
              fontWeight: isActive ? FontWeight.w600 : FontWeight.w400,
              color: isActive ? DnaColors.primaryFixed : mutedColor,
            ),
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
          ),
        ],
      ),
    );
  }

  Widget _buildIconWithBadge() {
    final icon = isActive ? _buildGradientIcon() : _buildMutedIcon();

    if (item.badgeCount <= 0) return icon;

    return Stack(
      clipBehavior: Clip.none,
      children: [
        icon,
        Positioned(
          top: -4,
          right: -8,
          child: _buildBadge(),
        ),
      ],
    );
  }

  Widget _buildGradientIcon() {
    return ShaderMask(
      shaderCallback: DnaGradients.primaryShader,
      blendMode: BlendMode.srcIn,
      child: FaIcon(
        item.activeIcon,
        size: DnaSpacing.iconMd,
        color: Colors.white,
      ),
    );
  }

  Widget _buildMutedIcon() {
    return FaIcon(
      item.icon,
      size: DnaSpacing.iconMd,
      color: mutedColor,
    );
  }

  Widget _buildBadge() {
    final label = item.badgeCount > 99 ? '99+' : '${item.badgeCount}';
    return Container(
      padding: const EdgeInsets.symmetric(
        horizontal: DnaSpacing.xs,
        vertical: 1,
      ),
      constraints: const BoxConstraints(minWidth: 16),
      decoration: BoxDecoration(
        color: DnaColors.error,
        borderRadius: BorderRadius.circular(DnaSpacing.radiusFull),
      ),
      child: Text(
        label,
        textAlign: TextAlign.center,
        style: const TextStyle(
          color: Colors.white,
          fontSize: 10,
          fontWeight: FontWeight.w600,
          height: 1.2,
        ),
      ),
    );
  }
}
