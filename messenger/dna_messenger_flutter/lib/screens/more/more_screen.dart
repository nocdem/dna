// More Screen - Grid + list menu replacing the old navigation drawer
import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';
import '../../design_system/design_system.dart';
import '../../ffi/dna_engine.dart' as engine show UserProfile;
import '../../platform/platform_handler.dart';
import '../../providers/providers.dart' hide UserProfile;
import '../wallet/wallet_screen.dart';
import '../qr/qr_scanner_screen.dart';
import '../wallet/address_book_screen.dart';
import '../settings/starred_messages_screen.dart';
import '../contacts/contacts_hub_screen.dart';
import '../settings/settings_screen.dart';
import '../settings/app_lock_settings_screen.dart';
import '../profile/profile_editor_screen.dart';
import 'package:share_plus/share_plus.dart' show Share;
import '../../l10n/app_localizations.dart';

class MoreScreen extends ConsumerWidget {
  const MoreScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final fingerprint = ref.watch(currentFingerprintProvider) ?? '';
    final userProfile = ref.watch(userProfileProvider);
    final fullProfile = ref.watch(fullProfileProvider);
    final supportsCamera = PlatformHandler.instance.supportsCamera;

    final shortFp = fingerprint.length > 16
        ? '${fingerprint.substring(0, 8)}...${fingerprint.substring(fingerprint.length - 8)}'
        : fingerprint;

    // Build grid items
    final gridItems = <DnaMoreGridItem>[
      DnaMoreGridItem(
        icon: FontAwesomeIcons.wallet,
        label: AppLocalizations.of(context).moreWallet,
        onTap: () => Navigator.push(
          context,
          MaterialPageRoute(builder: (_) => const WalletScreen()),
        ),
      ),
      if (supportsCamera)
        DnaMoreGridItem(
          icon: FontAwesomeIcons.qrcode,
          label: AppLocalizations.of(context).moreQRScanner,
          onTap: () => Navigator.push(
            context,
            MaterialPageRoute(builder: (_) => const QrScannerScreen()),
          ),
        ),
      DnaMoreGridItem(
        icon: FontAwesomeIcons.addressBook,
        label: AppLocalizations.of(context).moreAddresses,
        onTap: () => Navigator.push(
          context,
          MaterialPageRoute(builder: (_) => const AddressBookScreen()),
        ),
      ),
      DnaMoreGridItem(
        icon: FontAwesomeIcons.solidStar,
        label: AppLocalizations.of(context).moreStarred,
        onTap: () => Navigator.push(
          context,
          MaterialPageRoute(builder: (_) => const StarredMessagesScreen()),
        ),
      ),
      DnaMoreGridItem(
        icon: FontAwesomeIcons.addressCard,
        label: AppLocalizations.of(context).moreContacts,
        badgeCount: ref.watch(pendingRequestCountProvider),
        onTap: () => Navigator.push(
          context,
          MaterialPageRoute(builder: (_) => const ContactsHubScreen()),
        ),
      ),
      DnaMoreGridItem(
        icon: FontAwesomeIcons.userPlus,
        label: AppLocalizations.of(context).moreInviteFriends,
        onTap: () {
          final nickname = ref.read(userProfileProvider).valueOrNull?.nickname as String?;
          final username = (nickname != null && nickname.isNotEmpty) ? nickname : 'me';
          final message = AppLocalizations.of(context).inviteFriendsMessage(username);
          Share.share(message);
        },
      ),
    ];

    // Build list items
    final listItems = <DnaMoreListItem>[
      DnaMoreListItem(
        icon: FontAwesomeIcons.gear,
        label: AppLocalizations.of(context).moreSettings,
        onTap: () => Navigator.push(
          context,
          MaterialPageRoute(builder: (_) => const SettingsScreen()),
        ),
      ),
      DnaMoreListItem(
        icon: FontAwesomeIcons.lock,
        label: AppLocalizations.of(context).moreAppLock,
        onTap: () => Navigator.push(
          context,
          MaterialPageRoute(builder: (_) => const AppLockSettingsScreen()),
        ),
      ),
    ];

    // Profile header
    final header = _ProfileHeader(
      fingerprint: shortFp,
      userProfile: userProfile,
      fullProfile: fullProfile,
      onTap: () => Navigator.push(
        context,
        MaterialPageRoute(builder: (_) => const ProfileEditorScreen()),
      ),
    );

    return Scaffold(
      appBar: DnaAppBar(title: AppLocalizations.of(context).moreTitle),
      body: DnaMoreMenu(
        header: header,
        gridItems: gridItems,
        listItems: listItems,
      ),
    );
  }
}

// =============================================================================
// PROFILE HEADER
// =============================================================================

class _ProfileHeader extends StatelessWidget {
  final String fingerprint;
  final AsyncValue<dynamic> userProfile;
  final AsyncValue<dynamic> fullProfile;
  final VoidCallback onTap;

  const _ProfileHeader({
    required this.fingerprint,
    required this.userProfile,
    required this.fullProfile,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final isDark = theme.brightness == Brightness.dark;

    // Resolve display name from userProfile
    final nickname = userProfile.whenOrNull(
      data: (profile) => profile?.nickname as String?,
    );
    final displayName = (nickname != null && nickname.isNotEmpty)
        ? nickname
        : 'Anonymous';

    // Resolve avatar bytes from fullProfile
    final Uint8List? avatarBytes = fullProfile.whenOrNull(
      data: (profile) {
        if (profile == null) return null;
        return (profile as engine.UserProfile).decodeAvatar();
      },
    );

    return GestureDetector(
      onTap: onTap,
      child: Container(
        padding: const EdgeInsets.all(DnaSpacing.md),
        decoration: BoxDecoration(
          color: isDark ? DnaColors.darkSurfaceVariant : DnaColors.lightSurfaceVariant,
          borderRadius: BorderRadius.circular(DnaSpacing.radiusMd),
        ),
        child: Row(
          children: [
            DnaAvatar(
              imageBytes: avatarBytes,
              name: displayName,
              size: DnaAvatarSize.lg,
            ),
            const SizedBox(width: DnaSpacing.md),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                mainAxisSize: MainAxisSize.min,
                children: [
                  Text(
                    displayName,
                    style: theme.textTheme.titleMedium?.copyWith(
                      fontWeight: FontWeight.bold,
                    ),
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                  ),
                  const SizedBox(height: 4),
                  Text(
                    fingerprint,
                    style: theme.textTheme.bodySmall?.copyWith(
                      color: isDark
                          ? DnaColors.darkTextSecondary
                          : DnaColors.lightTextSecondary,
                      fontFamily: 'monospace',
                    ),
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                  ),
                ],
              ),
            ),
            FaIcon(
              FontAwesomeIcons.chevronRight,
              size: DnaSpacing.iconSm,
              color: isDark
                  ? DnaColors.darkTextSecondary
                  : DnaColors.lightTextSecondary,
            ),
          ],
        ),
      ),
    );
  }
}
