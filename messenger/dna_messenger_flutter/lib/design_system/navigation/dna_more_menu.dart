import 'package:flutter/material.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';
import '../theme/dna_colors.dart';
import '../theme/dna_gradients.dart';
import '../theme/dna_spacing.dart';

/// Data class for a grid item in the More menu
class DnaMoreGridItem {
  final IconData icon;
  final String label;
  final VoidCallback onTap;
  final int badgeCount;

  const DnaMoreGridItem({
    required this.icon,
    required this.label,
    required this.onTap,
    this.badgeCount = 0,
  });
}

/// Data class for a list item in the More menu
class DnaMoreListItem {
  final IconData icon;
  final String label;
  final VoidCallback onTap;
  final Widget? trailing;

  const DnaMoreListItem({
    required this.icon,
    required this.label,
    required this.onTap,
    this.trailing,
  });
}

/// Grid + list layout for the More tab
class DnaMoreMenu extends StatelessWidget {
  final List<DnaMoreGridItem> gridItems;
  final List<DnaMoreListItem> listItems;
  final Widget? header;

  const DnaMoreMenu({
    super.key,
    required this.gridItems,
    required this.listItems,
    this.header,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final isDark = theme.brightness == Brightness.dark;

    return ListView(
      padding: const EdgeInsets.all(DnaSpacing.lg),
      children: [
        if (header != null) ...[
          header!,
          const SizedBox(height: DnaSpacing.lg),
        ],

        // Grid section
        if (gridItems.isNotEmpty)
          GridView.count(
            crossAxisCount: 3,
            shrinkWrap: true,
            physics: const NeverScrollableScrollPhysics(),
            mainAxisSpacing: DnaSpacing.md,
            crossAxisSpacing: DnaSpacing.md,
            children: gridItems
                .map((item) => _MoreGridTile(item: item, isDark: isDark))
                .toList(),
          ),

        if (gridItems.isNotEmpty && listItems.isNotEmpty) ...[
          const SizedBox(height: DnaSpacing.lg),
          Divider(
            color: isDark ? DnaColors.darkDivider : DnaColors.lightDivider,
            height: 1,
          ),
          const SizedBox(height: DnaSpacing.sm),
        ],

        // List section
        ...listItems.map((item) => _MoreListTile(item: item, isDark: isDark)),
      ],
    );
  }
}

class _MoreGridTile extends StatelessWidget {
  final DnaMoreGridItem item;
  final bool isDark;

  const _MoreGridTile({
    required this.item,
    required this.isDark,
  });

  @override
  Widget build(BuildContext context) {
    final surfaceVariant =
        isDark ? DnaColors.darkSurfaceVariant : DnaColors.lightSurfaceVariant;
    final textColor = isDark ? DnaColors.darkText : DnaColors.lightText;

    return Material(
      color: surfaceVariant,
      borderRadius: BorderRadius.circular(DnaSpacing.radiusMd),
      child: InkWell(
        onTap: item.onTap,
        borderRadius: BorderRadius.circular(DnaSpacing.radiusMd),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            _buildIconWithBadge(),
            const SizedBox(height: DnaSpacing.sm),
            Text(
              item.label,
              style: TextStyle(
                fontSize: 12,
                fontWeight: FontWeight.w500,
                color: textColor,
              ),
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              textAlign: TextAlign.center,
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildIconWithBadge() {
    final icon = Container(
      padding: const EdgeInsets.all(DnaSpacing.sm),
      decoration: BoxDecoration(
        gradient: DnaGradients.primarySoft(
          isDark ? Brightness.dark : Brightness.light,
        ),
        borderRadius: BorderRadius.circular(DnaSpacing.radiusSm),
      ),
      child: ShaderMask(
        shaderCallback: DnaGradients.primaryShader,
        blendMode: BlendMode.srcIn,
        child: FaIcon(
          item.icon,
          size: DnaSpacing.iconLg,
          color: Colors.white,
        ),
      ),
    );

    if (item.badgeCount <= 0) return icon;

    final label = item.badgeCount > 99 ? '99+' : '${item.badgeCount}';
    return Stack(
      clipBehavior: Clip.none,
      children: [
        icon,
        Positioned(
          top: -4,
          right: -8,
          child: Container(
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
          ),
        ),
      ],
    );
  }
}

class _MoreListTile extends StatelessWidget {
  final DnaMoreListItem item;
  final bool isDark;

  const _MoreListTile({
    required this.item,
    required this.isDark,
  });

  @override
  Widget build(BuildContext context) {
    final textColor = isDark ? DnaColors.darkText : DnaColors.lightText;
    final muted =
        isDark ? DnaColors.darkTextSecondary : DnaColors.lightTextSecondary;

    return ListTile(
      leading: FaIcon(
        item.icon,
        size: DnaSpacing.iconMd,
        color: muted,
      ),
      title: Text(
        item.label,
        style: TextStyle(
          fontSize: 15,
          fontWeight: FontWeight.w400,
          color: textColor,
        ),
      ),
      trailing: item.trailing ??
          FaIcon(
            FontAwesomeIcons.chevronRight,
            size: DnaSpacing.iconSm,
            color: muted,
          ),
      onTap: item.onTap,
      contentPadding: const EdgeInsets.symmetric(horizontal: DnaSpacing.xs),
    );
  }
}
