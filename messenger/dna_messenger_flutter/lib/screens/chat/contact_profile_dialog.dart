// Contact Profile Dialog - View another user's profile from DHT
import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../ffi/dna_engine.dart' show UserProfile;
import '../../providers/providers.dart' show engineProvider;
import '../../theme/dna_theme.dart';

/// Shows a bottom sheet with the contact's profile fetched from DHT
Future<void> showContactProfileDialog(
  BuildContext context,
  WidgetRef ref,
  String fingerprint,
  String displayName,
) async {
  showModalBottomSheet(
    context: context,
    isScrollControlled: true,
    backgroundColor: Colors.transparent,
    builder: (context) => ContactProfileSheet(
      fingerprint: fingerprint,
      displayName: displayName,
    ),
  );
}

class ContactProfileSheet extends ConsumerStatefulWidget {
  final String fingerprint;
  final String displayName;

  const ContactProfileSheet({
    super.key,
    required this.fingerprint,
    required this.displayName,
  });

  @override
  ConsumerState<ContactProfileSheet> createState() => _ContactProfileSheetState();
}

class _ContactProfileSheetState extends ConsumerState<ContactProfileSheet> {
  UserProfile? _profile;
  bool _isLoading = true;
  String? _error;

  @override
  void initState() {
    super.initState();
    _loadProfile();
  }

  Future<void> _loadProfile() async {
    try {
      final engine = await ref.read(engineProvider.future);
      final profile = await engine.lookupProfile(widget.fingerprint);
      if (mounted) {
        setState(() {
          _profile = profile;
          _isLoading = false;
        });
      }
    } catch (e) {
      if (mounted) {
        setState(() {
          _error = e.toString();
          _isLoading = false;
        });
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return DraggableScrollableSheet(
      initialChildSize: 0.7,
      minChildSize: 0.5,
      maxChildSize: 0.95,
      builder: (context, scrollController) => Container(
        decoration: BoxDecoration(
          color: theme.scaffoldBackgroundColor,
          borderRadius: const BorderRadius.vertical(top: Radius.circular(20)),
        ),
        child: Column(
          children: [
            // Handle bar
            Container(
              margin: const EdgeInsets.symmetric(vertical: 12),
              width: 40,
              height: 4,
              decoration: BoxDecoration(
                color: theme.dividerColor,
                borderRadius: BorderRadius.circular(2),
              ),
            ),
            // Content
            Expanded(
              child: _isLoading
                  ? const Center(child: CircularProgressIndicator())
                  : _error != null
                      ? _buildError()
                      : _buildProfile(scrollController),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildError() {
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(Icons.error_outline, size: 48, color: DnaColors.textWarning),
            const SizedBox(height: 16),
            Text(
              'Failed to load profile',
              style: TextStyle(color: DnaColors.textWarning),
            ),
            const SizedBox(height: 8),
            Text(
              _error ?? 'Unknown error',
              style: TextStyle(color: DnaColors.textMuted, fontSize: 12),
              textAlign: TextAlign.center,
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildProfile(ScrollController scrollController) {
    final theme = Theme.of(context);
    final profile = _profile;

    return ListView(
      controller: scrollController,
      padding: const EdgeInsets.symmetric(horizontal: 20),
      children: [
        // Avatar and name header
        _buildHeader(theme),
        const SizedBox(height: 24),

        // Fingerprint
        _buildFingerprintSection(theme),
        const SizedBox(height: 16),

        // Bio (if available)
        if (profile != null && profile.bio.isNotEmpty) ...[
          _buildSection(
            theme,
            'Bio',
            Icons.info_outline,
            [_buildTextItem(profile.bio)],
          ),
          const SizedBox(height: 16),
        ],

        // Location & Website
        if (profile != null && (profile.location.isNotEmpty || profile.website.isNotEmpty)) ...[
          _buildSection(
            theme,
            'Info',
            Icons.location_on_outlined,
            [
              if (profile.location.isNotEmpty)
                _buildInfoRow(Icons.location_on_outlined, profile.location),
              if (profile.website.isNotEmpty)
                _buildLinkRow(Icons.language, profile.website, 'Website'),
            ],
          ),
          const SizedBox(height: 16),
        ],

        // Wallets
        if (profile != null && _hasWallets(profile)) ...[
          _buildSection(
            theme,
            'Wallets',
            Icons.account_balance_wallet_outlined,
            _buildWalletItems(profile),
          ),
          const SizedBox(height: 16),
        ],

        // Socials
        if (profile != null && _hasSocials(profile)) ...[
          _buildSection(
            theme,
            'Social',
            Icons.share_outlined,
            _buildSocialItems(profile),
          ),
          const SizedBox(height: 16),
        ],

        // No profile message
        if (profile == null) ...[
          Center(
            child: Padding(
              padding: const EdgeInsets.all(32),
              child: Column(
                children: [
                  Icon(Icons.person_off_outlined, size: 48, color: DnaColors.textMuted),
                  const SizedBox(height: 16),
                  Text(
                    'No profile published',
                    style: TextStyle(color: DnaColors.textMuted),
                  ),
                  const SizedBox(height: 8),
                  Text(
                    'This user has not published their profile to DHT yet.',
                    style: TextStyle(color: DnaColors.textMuted, fontSize: 12),
                    textAlign: TextAlign.center,
                  ),
                ],
              ),
            ),
          ),
        ],

        const SizedBox(height: 32),
      ],
    );
  }

  Widget _buildHeader(ThemeData theme) {
    final profile = _profile;
    final hasAvatar = profile != null && profile.avatarBase64.isNotEmpty;
    final name = profile?.displayName.isNotEmpty == true
        ? profile!.displayName
        : widget.displayName;

    return Column(
      children: [
        // Avatar
        CircleAvatar(
          radius: 48,
          backgroundColor: DnaColors.primary.withValues(alpha: 0.2),
          backgroundImage: hasAvatar
              ? MemoryImage(base64Decode(profile!.avatarBase64))
              : null,
          child: !hasAvatar
              ? Text(
                  _getInitials(name),
                  style: TextStyle(
                    fontSize: 32,
                    fontWeight: FontWeight.bold,
                    color: DnaColors.primary,
                  ),
                )
              : null,
        ),
        const SizedBox(height: 16),
        // Display name
        Text(
          name.isNotEmpty ? name : _shortenFingerprint(widget.fingerprint),
          style: theme.textTheme.headlineSmall?.copyWith(
            fontWeight: FontWeight.bold,
          ),
          textAlign: TextAlign.center,
        ),
      ],
    );
  }

  Widget _buildFingerprintSection(ThemeData theme) {
    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: theme.cardColor,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: theme.dividerColor),
      ),
      child: Row(
        children: [
          Icon(Icons.fingerprint, color: DnaColors.textMuted),
          const SizedBox(width: 12),
          Expanded(
            child: Text(
              _shortenFingerprint(widget.fingerprint),
              style: TextStyle(
                fontFamily: 'monospace',
                fontSize: 12,
                color: DnaColors.textMuted,
              ),
            ),
          ),
          IconButton(
            icon: const Icon(Icons.copy, size: 20),
            onPressed: () {
              Clipboard.setData(ClipboardData(text: widget.fingerprint));
              ScaffoldMessenger.of(context).showSnackBar(
                const SnackBar(content: Text('Fingerprint copied')),
              );
            },
            tooltip: 'Copy fingerprint',
          ),
        ],
      ),
    );
  }

  Widget _buildSection(ThemeData theme, String title, IconData icon, List<Widget> children) {
    return Container(
      decoration: BoxDecoration(
        color: theme.cardColor,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: theme.dividerColor),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Padding(
            padding: const EdgeInsets.all(12),
            child: Row(
              children: [
                Icon(icon, size: 20, color: DnaColors.primary),
                const SizedBox(width: 8),
                Text(
                  title,
                  style: theme.textTheme.titleSmall?.copyWith(
                    fontWeight: FontWeight.bold,
                    color: DnaColors.primary,
                  ),
                ),
              ],
            ),
          ),
          const Divider(height: 1),
          ...children,
        ],
      ),
    );
  }

  Widget _buildTextItem(String text) {
    return Padding(
      padding: const EdgeInsets.all(12),
      child: Text(text),
    );
  }

  Widget _buildInfoRow(IconData icon, String text) {
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
      child: Row(
        children: [
          Icon(icon, size: 18, color: DnaColors.textMuted),
          const SizedBox(width: 12),
          Expanded(child: Text(text)),
        ],
      ),
    );
  }

  Widget _buildLinkRow(IconData icon, String text, String label) {
    return InkWell(
      onTap: () => _copyToClipboard(text, label),
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
        child: Row(
          children: [
            Icon(icon, size: 18, color: DnaColors.primary),
            const SizedBox(width: 12),
            Expanded(
              child: Text(
                text,
                style: TextStyle(color: DnaColors.primary),
              ),
            ),
            Icon(Icons.copy, size: 16, color: DnaColors.textMuted),
          ],
        ),
      ),
    );
  }

  Widget _buildCopyableRow(String label, String value, {IconData? icon}) {
    return InkWell(
      onTap: () {
        Clipboard.setData(ClipboardData(text: value));
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('$label copied')),
        );
      },
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
        child: Row(
          children: [
            if (icon != null) ...[
              Icon(icon, size: 18, color: DnaColors.textMuted),
              const SizedBox(width: 12),
            ],
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    label,
                    style: TextStyle(
                      fontSize: 11,
                      color: DnaColors.textMuted,
                    ),
                  ),
                  Text(
                    _truncateAddress(value),
                    style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
                  ),
                ],
              ),
            ),
            Icon(Icons.copy, size: 16, color: DnaColors.textMuted),
          ],
        ),
      ),
    );
  }

  bool _hasWallets(UserProfile profile) {
    return profile.backbone.isNotEmpty ||
        profile.btc.isNotEmpty ||
        profile.eth.isNotEmpty ||
        profile.sol.isNotEmpty ||
        profile.trx.isNotEmpty;
  }

  List<Widget> _buildWalletItems(UserProfile profile) {
    final items = <Widget>[];
    if (profile.backbone.isNotEmpty) {
      items.add(_buildCopyableRow('Backbone (CPUNK)', profile.backbone));
    }
    if (profile.btc.isNotEmpty) {
      items.add(_buildCopyableRow('Bitcoin', profile.btc));
    }
    if (profile.eth.isNotEmpty) {
      items.add(_buildCopyableRow('Ethereum', profile.eth));
    }
    if (profile.sol.isNotEmpty) {
      items.add(_buildCopyableRow('Solana', profile.sol));
    }
    if (profile.trx.isNotEmpty) {
      items.add(_buildCopyableRow('TRON', profile.trx));
    }
    return items;
  }

  bool _hasSocials(UserProfile profile) {
    return profile.telegram.isNotEmpty ||
        profile.twitter.isNotEmpty ||
        profile.github.isNotEmpty ||
        profile.facebook.isNotEmpty ||
        profile.instagram.isNotEmpty ||
        profile.linkedin.isNotEmpty;
  }

  List<Widget> _buildSocialItems(UserProfile profile) {
    final items = <Widget>[];
    if (profile.telegram.isNotEmpty) {
      items.add(_buildSocialRow('Telegram', profile.telegram, 'https://t.me/${profile.telegram.replaceFirst('@', '')}'));
    }
    if (profile.twitter.isNotEmpty) {
      items.add(_buildSocialRow('X (Twitter)', profile.twitter, 'https://x.com/${profile.twitter.replaceFirst('@', '')}'));
    }
    if (profile.github.isNotEmpty) {
      items.add(_buildSocialRow('GitHub', profile.github, 'https://github.com/${profile.github}'));
    }
    if (profile.facebook.isNotEmpty) {
      items.add(_buildSocialRow('Facebook', profile.facebook, 'https://facebook.com/${profile.facebook}'));
    }
    if (profile.instagram.isNotEmpty) {
      items.add(_buildSocialRow('Instagram', profile.instagram, 'https://instagram.com/${profile.instagram.replaceFirst('@', '')}'));
    }
    if (profile.linkedin.isNotEmpty) {
      items.add(_buildSocialRow('LinkedIn', profile.linkedin, 'https://linkedin.com/in/${profile.linkedin}'));
    }
    return items;
  }

  Widget _buildSocialRow(String label, String handle, String url) {
    return InkWell(
      onTap: () => _copyToClipboard(url, label),
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
        child: Row(
          children: [
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    label,
                    style: TextStyle(
                      fontSize: 11,
                      color: DnaColors.textMuted,
                    ),
                  ),
                  Text(
                    handle,
                    style: TextStyle(color: DnaColors.primary),
                  ),
                ],
              ),
            ),
            Icon(Icons.copy, size: 16, color: DnaColors.textMuted),
          ],
        ),
      ),
    );
  }

  void _copyToClipboard(String text, String label) {
    Clipboard.setData(ClipboardData(text: text));
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text('$label copied')),
    );
  }

  String _getInitials(String name) {
    if (name.isEmpty) return '?';
    final words = name.split(' ');
    if (words.length >= 2) {
      return '${words[0][0]}${words[1][0]}'.toUpperCase();
    }
    return name.substring(0, name.length.clamp(0, 2)).toUpperCase();
  }

  String _shortenFingerprint(String fingerprint) {
    if (fingerprint.length <= 20) return fingerprint;
    return '${fingerprint.substring(0, 8)}...${fingerprint.substring(fingerprint.length - 8)}';
  }

  String _truncateAddress(String address) {
    if (address.length <= 24) return address;
    return '${address.substring(0, 12)}...${address.substring(address.length - 12)}';
  }
}
