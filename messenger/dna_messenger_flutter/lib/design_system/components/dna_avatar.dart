import 'dart:typed_data';

import 'package:flutter/material.dart';

import '../theme/dna_colors.dart';
import '../theme/dna_spacing.dart';

/// Avatar size presets mapping to DnaSpacing avatar constants.
enum DnaAvatarSize {
  sm(DnaSpacing.avatarSm),
  md(DnaSpacing.avatarMd),
  lg(DnaSpacing.avatarLg),
  xl(DnaSpacing.avatarXl);

  const DnaAvatarSize(this.value);
  final double value;
}

/// An avatar widget with optional image, initials fallback, and online status dot.
class DnaAvatar extends StatelessWidget {
  const DnaAvatar({
    super.key,
    this.imageBytes,
    this.name,
    this.size = DnaAvatarSize.md,
    this.showOnlineStatus = false,
    this.isOnline = false,
  });

  final Uint8List? imageBytes;
  final String? name;
  final DnaAvatarSize size;
  final bool showOnlineStatus;
  final bool isOnline;

  String get _initials {
    if (name == null || name!.isEmpty) return '?';
    final parts = name!.trim().split(RegExp(r'\s+'));
    if (parts.length >= 2) {
      return '${parts[0][0]}${parts[1][0]}'.toUpperCase();
    }
    return parts[0][0].toUpperCase();
  }

  @override
  Widget build(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark;
    final diameter = size.value;
    final radius = diameter / 2;

    Widget avatar;

    if (imageBytes != null && imageBytes!.isNotEmpty) {
      avatar = CircleAvatar(
        radius: radius,
        backgroundImage: MemoryImage(imageBytes!),
      );
    } else {
      final bgOpacity = isDark ? 0.15 : 0.10;
      avatar = CircleAvatar(
        radius: radius,
        backgroundColor:
            DnaColors.primaryFixed.withValues(alpha: bgOpacity),
        child: Text(
          _initials,
          style: TextStyle(
            color: DnaColors.primaryFixed,
            fontSize: diameter * 0.38,
            fontWeight: FontWeight.w600,
          ),
        ),
      );
    }

    if (!showOnlineStatus) return avatar;

    final dotSize = diameter * 0.28;
    final scaffoldBg = Theme.of(context).scaffoldBackgroundColor;

    return SizedBox(
      width: diameter,
      height: diameter,
      child: Stack(
        children: [
          avatar,
          Positioned(
            right: 0,
            bottom: 0,
            child: Container(
              width: dotSize,
              height: dotSize,
              decoration: BoxDecoration(
                color: isOnline ? DnaColors.success : DnaColors.offline,
                shape: BoxShape.circle,
                border: Border.all(color: scaffoldBg, width: 2),
                boxShadow: isOnline
                    ? [
                        BoxShadow(
                          color: DnaColors.success.withValues(alpha: 0.5),
                          blurRadius: 4,
                        ),
                      ]
                    : null,
              ),
            ),
          ),
        ],
      ),
    );
  }
}
