// Profile Editor Screen - Edit user profile (wallets, bio, avatar)
import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';
import 'package:image_picker/image_picker.dart';
import 'package:image/image.dart' as img;
import 'package:qr_flutter/qr_flutter.dart';

import '../../ffi/dna_engine.dart' show decodeBase64WithPadding;
import '../../l10n/app_localizations.dart';
import '../../platform/platform_handler.dart';
import '../../providers/providers.dart';
import '../../design_system/theme/dna_colors.dart';
import 'avatar_crop_screen.dart';

class ProfileEditorScreen extends ConsumerStatefulWidget {
  const ProfileEditorScreen({super.key});

  @override
  ConsumerState<ProfileEditorScreen> createState() => _ProfileEditorScreenState();
}

class _ProfileEditorScreenState extends ConsumerState<ProfileEditorScreen> {
  final _formKey = GlobalKey<FormState>();

  // Controllers for text fields
  // Profile info (NOTE: displayName removed in v0.6.24 - use registered name only)
  late TextEditingController _bioController;
  late TextEditingController _locationController;
  late TextEditingController _websiteController;

  // Wallets
  late TextEditingController _backboneController;
  late TextEditingController _ethController;
  late TextEditingController _solController;
  late TextEditingController _trxController;

  // Expansion state
  bool _profileExpanded = true;
  bool _walletsExpanded = false;

  @override
  void initState() {
    super.initState();
    // Profile info (NOTE: displayName removed in v0.6.24 - use registered name only)
    _bioController = TextEditingController();
    _locationController = TextEditingController();
    _websiteController = TextEditingController();
    // Wallets
    _backboneController = TextEditingController();
    _ethController = TextEditingController();
    _solController = TextEditingController();
    _trxController = TextEditingController();
  }

  @override
  void dispose() {
    // Profile info (NOTE: displayName removed in v0.6.24 - use registered name only)
    _bioController.dispose();
    _locationController.dispose();
    _websiteController.dispose();
    // Wallets
    _backboneController.dispose();
    _ethController.dispose();
    _solController.dispose();
    _trxController.dispose();
    super.dispose();
  }

  void _syncControllersFromState(ProfileEditorState state) {
    final profile = state.profile;
    // Profile info (NOTE: displayName removed in v0.6.24 - use registered name only)
    if (_bioController.text != profile.bio) {
      _bioController.text = profile.bio;
    }
    if (_locationController.text != profile.location) {
      _locationController.text = profile.location;
    }
    if (_websiteController.text != profile.website) {
      _websiteController.text = profile.website;
    }
    // Wallets
    if (_backboneController.text != profile.backbone) {
      _backboneController.text = profile.backbone;
    }
    if (_ethController.text != profile.eth) {
      _ethController.text = profile.eth;
    }
    if (_solController.text != profile.sol) {
      _solController.text = profile.sol;
    }
    if (_trxController.text != profile.trx) {
      _trxController.text = profile.trx;
    }
  }

  @override
  Widget build(BuildContext context) {
    final state = ref.watch(profileEditorProvider);
    final notifier = ref.read(profileEditorProvider.notifier);

    // Sync controllers when state changes (e.g., after loading from DHT)
    WidgetsBinding.instance.addPostFrameCallback((_) {
      _syncControllersFromState(state);
    });

    // Show snackbar for success/error messages
    if (state.successMessage != null) {
      WidgetsBinding.instance.addPostFrameCallback((_) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(state.successMessage!),
            backgroundColor: DnaColors.snackbarSuccess,
          ),
        );
      });
    }
    if (state.error != null) {
      WidgetsBinding.instance.addPostFrameCallback((_) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(state.error!),
            backgroundColor: DnaColors.snackbarError,
          ),
        );
      });
    }

    return Scaffold(
      appBar: AppBar(
        title: Text(AppLocalizations.of(context).profileTitle),
        actions: [
          if (state.isSaving)
            const Padding(
              padding: EdgeInsets.all(16),
              child: SizedBox(
                width: 24,
                height: 24,
                child: CircularProgressIndicator(strokeWidth: 2),
              ),
            )
          else
            IconButton(
              icon: const FaIcon(FontAwesomeIcons.floppyDisk),
              onPressed: () => _saveProfile(notifier),
              tooltip: AppLocalizations.of(context).save,
            ),
        ],
      ),
      body: state.isLoading
          ? const Center(child: CircularProgressIndicator())
          : Form(
              key: _formKey,
              child: SafeArea(
                top: false,
                child: ListView(
                padding: const EdgeInsets.all(16),
                children: [
                  // Avatar section
                  _AvatarSection(
                    avatarBase64: state.profile.avatarBase64,
                    onPickImage: () => _pickAvatar(notifier),
                    onRemoveImage: () => notifier.removeAvatar(),
                  ),
                  const SizedBox(height: 24),

                  // QR Code section - share your identity
                  _QrCodeSection(),
                  const SizedBox(height: 24),

                  // Profile Info section
                  _buildExpansionSection(
                    title: AppLocalizations.of(context).profileInfo,
                    icon: FontAwesomeIcons.user,
                    isExpanded: _profileExpanded,
                    onExpansionChanged: (expanded) {
                      setState(() => _profileExpanded = expanded);
                    },
                    children: [
                      // NOTE: displayName removed in v0.6.24 - use registered name only
                      _buildBioField(notifier),
                      _buildTextField(
                        label: AppLocalizations.of(context).profileLocation,
                        controller: _locationController,
                        hint: 'City, Country',
                        prefixIcon: FontAwesomeIcons.locationDot,
                        onChanged: (v) => notifier.updateField('location', v),
                      ),
                      _buildTextField(
                        label: AppLocalizations.of(context).profileWebsite,
                        controller: _websiteController,
                        hint: 'https://yourwebsite.com',
                        prefixIcon: FontAwesomeIcons.globe,
                        onChanged: (v) => notifier.updateField('website', v),
                      ),
                    ],
                  ),
                  const SizedBox(height: 20),

                  // Wallet Addresses (read-only, derived from identity keys)
                  _buildExpansionSection(
                    title: AppLocalizations.of(context).profileWalletAddresses,
                    icon: FontAwesomeIcons.wallet,
                    isExpanded: _walletsExpanded,
                    onExpansionChanged: (expanded) {
                      setState(() => _walletsExpanded = expanded);
                    },
                    children: [
                      _buildWalletAddressDisplay(
                        label: 'Backbone (Cellframe)',
                        controller: _backboneController,
                        icon: FontAwesomeIcons.link,
                      ),
                      _buildWalletAddressDisplay(
                        label: 'Ethereum (ETH)',
                        controller: _ethController,
                        icon: FontAwesomeIcons.ethereum,
                      ),
                      _buildWalletAddressDisplay(
                        label: 'Solana (SOL)',
                        controller: _solController,
                        icon: FontAwesomeIcons.coins,
                      ),
                      _buildWalletAddressDisplay(
                        label: 'TRON (TRX)',
                        controller: _trxController,
                        icon: FontAwesomeIcons.bolt,
                      ),
                    ],
                  ),
                  const SizedBox(height: 32),

                  // Action buttons
                  Row(
                    children: [
                      Expanded(
                        child: OutlinedButton(
                          onPressed: state.isSaving ? null : () => Navigator.pop(context),
                          child: Text(AppLocalizations.of(context).cancel),
                        ),
                      ),
                      const SizedBox(width: 16),
                      Expanded(
                        child: ElevatedButton(
                          onPressed: state.isSaving ? null : () => _saveProfile(notifier),
                          child: state.isSaving
                              ? const SizedBox(
                                  width: 20,
                                  height: 20,
                                  child: CircularProgressIndicator(strokeWidth: 2),
                                )
                              : Text(AppLocalizations.of(context).profileSave),
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 16),
                ],
              ),
            ),
            ),
    );
  }

  Widget _buildBioField(ProfileEditorNotifier notifier) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 12),
      child: TextFormField(
        controller: _bioController,
        maxLines: 4,
        maxLength: 512,
        decoration: InputDecoration(
          labelText: AppLocalizations.of(context).profileBio,
          hintText: 'Tell people about yourself...',
          border: OutlineInputBorder(
            borderRadius: BorderRadius.circular(8),
          ),
          counterText: '${_bioController.text.length}/512',
        ),
        onChanged: (v) {
          notifier.updateField('bio', v);
          setState(() {}); // Update counter
        },
      ),
    );
  }

  Widget _buildExpansionSection({
    required String title,
    required IconData icon,
    required bool isExpanded,
    required ValueChanged<bool> onExpansionChanged,
    required List<Widget> children,
  }) {
    final theme = Theme.of(context);

    return Card(
      clipBehavior: Clip.antiAlias,
      child: ExpansionTile(
        leading: FaIcon(icon, color: theme.colorScheme.primary),
        title: Text(title, style: theme.textTheme.titleSmall),
        initiallyExpanded: isExpanded,
        onExpansionChanged: onExpansionChanged,
        // Remove the default dividers that look strange with rounded Card corners
        shape: const Border(),
        collapsedShape: const Border(),
        children: [
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 12, 16, 16),
            child: Column(children: children),
          ),
        ],
      ),
    );
  }

  Widget _buildTextField({
    required String label,
    required TextEditingController controller,
    required String hint,
    IconData? prefixIcon,
    required ValueChanged<String> onChanged,
  }) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 12),
      child: TextFormField(
        controller: controller,
        decoration: InputDecoration(
          labelText: label,
          hintText: hint,
          prefixIcon: prefixIcon != null
              ? SizedBox(
                  width: 48,
                  child: Center(child: FaIcon(prefixIcon, size: 18)),
                )
              : null,
          border: OutlineInputBorder(
            borderRadius: BorderRadius.circular(8),
          ),
        ),
        onChanged: onChanged,
      ),
    );
  }

  Widget _buildWalletAddressDisplay({
    required String label,
    required TextEditingController controller,
    required IconData icon,
  }) {
    final theme = Theme.of(context);
    final address = controller.text;

    if (address.isEmpty) {
      return const SizedBox.shrink();
    }

    // Truncate: first 10 + "..." + last 8
    final displayAddress = address.length > 22
        ? '${address.substring(0, 10)}\u2026${address.substring(address.length - 8)}'
        : address;

    return Padding(
      padding: const EdgeInsets.only(bottom: 8),
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
        decoration: BoxDecoration(
          color: theme.colorScheme.surfaceContainerHighest.withAlpha(80),
          borderRadius: BorderRadius.circular(10),
          border: Border.all(
            color: theme.colorScheme.outline.withAlpha(40),
          ),
        ),
        child: Row(
          children: [
            FaIcon(icon, size: 16, color: theme.colorScheme.primary.withAlpha(180)),
            const SizedBox(width: 10),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    label,
                    style: theme.textTheme.labelSmall?.copyWith(
                      color: theme.colorScheme.onSurface.withAlpha(150),
                      fontWeight: FontWeight.w500,
                    ),
                  ),
                  const SizedBox(height: 2),
                  Text(
                    displayAddress,
                    style: theme.textTheme.bodyMedium?.copyWith(
                      fontFamily: 'monospace',
                      letterSpacing: 0.5,
                    ),
                  ),
                ],
              ),
            ),
            SizedBox(
              width: 36,
              height: 36,
              child: IconButton(
                icon: FaIcon(FontAwesomeIcons.copy, size: 15,
                    color: theme.colorScheme.primary),
                onPressed: () {
                  Clipboard.setData(ClipboardData(text: address));
                  ScaffoldMessenger.of(context).showSnackBar(
                    SnackBar(
                      content: Text('$label address copied'),
                      duration: const Duration(seconds: 1),
                    ),
                  );
                },
                tooltip: 'Copy full address',
                padding: EdgeInsets.zero,
                visualDensity: VisualDensity.compact,
              ),
            ),
          ],
        ),
      ),
    );
  }

  Future<void> _pickAvatar(ProfileEditorNotifier notifier) async {
    final supportsCamera = PlatformHandler.instance.supportsCamera;

    // On desktop (no camera), skip the bottom sheet and go straight to gallery
    ImageSource? source;
    if (!supportsCamera) {
      source = ImageSource.gallery;
    } else {
      // Show bottom sheet to choose between camera and gallery
      source = await showModalBottomSheet<ImageSource>(
        context: context,
        builder: (context) => SafeArea(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              ListTile(
                leading: const FaIcon(FontAwesomeIcons.camera),
                title: Text(AppLocalizations.of(context).profileTakeSelfie),
                onTap: () => Navigator.pop(context, ImageSource.camera),
              ),
              ListTile(
                leading: const FaIcon(FontAwesomeIcons.images),
                title: Text(AppLocalizations.of(context).profileChooseFromGallery),
                onTap: () => Navigator.pop(context, ImageSource.gallery),
              ),
              const SizedBox(height: 8),
            ],
          ),
        ),
      );
    }

    if (source == null) return;

    final picker = ImagePicker();
    final image = await picker.pickImage(
      source: source,
      preferredCameraDevice: CameraDevice.front, // Front camera for selfies
    );

    if (image != null) {
      final bytes = await File(image.path).readAsBytes();

      // Navigate to crop screen for Telegram-style circular cropping
      if (!mounted) return;
      final croppedBytes = await Navigator.of(context).push<Uint8List>(
        MaterialPageRoute(
          builder: (context) => AvatarCropScreen(imageBytes: bytes),
        ),
      );

      // User cancelled cropping
      if (croppedBytes == null) return;

      // Decode cropped image and resize to 128x128
      final decoded = img.decodeImage(croppedBytes);
      if (decoded == null) {
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(content: Text('Failed to decode cropped image')),
          );
        }
        return;
      }

      // Resize to 128x128 (avatar size)
      final resized = img.copyResize(decoded, width: 128, height: 128);

      // Encode as JPEG with 80% quality (good quality for 128x128)
      final compressed = img.encodeJpg(resized, quality: 80);

      // Base64 encode - should be ~10-15KB for 128x128 JPEG
      final base64 = base64Encode(compressed);

      // Sanity check: avatar should be under 18KB base64 (buffer is 20KB)
      if (base64.length > 18000) {
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(content: Text('Avatar too large, please try a smaller image')),
          );
        }
        return;
      }

      notifier.setAvatar(base64);
    }
  }

  Future<void> _saveProfile(ProfileEditorNotifier notifier) async {
    if (!_formKey.currentState!.validate()) return;

    final success = await notifier.save();
    if (success && mounted) {
      Navigator.pop(context);
    }
  }
}

class _AvatarSection extends StatelessWidget {
  final String avatarBase64;
  final VoidCallback onPickImage;
  final VoidCallback onRemoveImage;

  const _AvatarSection({
    required this.avatarBase64,
    required this.onPickImage,
    required this.onRemoveImage,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final hasAvatar = avatarBase64.isNotEmpty;

    Widget avatarWidget;
    final bytes = hasAvatar ? decodeBase64WithPadding(avatarBase64) : null;
    if (bytes != null) {
      avatarWidget = CircleAvatar(
        radius: 48,
        backgroundImage: MemoryImage(bytes),
      );
    } else {
      avatarWidget = CircleAvatar(
        radius: 48,
        backgroundColor: theme.colorScheme.primary.withAlpha(51),
        child: FaIcon(
          FontAwesomeIcons.user,
          size: 48,
          color: theme.colorScheme.primary,
        ),
      );
    }

    return Center(
      child: Column(
        children: [
          Stack(
            children: [
              avatarWidget,
              Positioned(
                right: 0,
                bottom: 0,
                child: CircleAvatar(
                  radius: 16,
                  backgroundColor: theme.colorScheme.primary,
                  child: IconButton(
                    // Show camera icon on mobile, gallery icon on desktop
                    icon: FaIcon(
                      PlatformHandler.instance.supportsCamera
                          ? FontAwesomeIcons.camera
                          : FontAwesomeIcons.images,
                      size: 16,
                    ),
                    color: theme.colorScheme.onPrimary,
                    onPressed: onPickImage,
                    padding: EdgeInsets.zero,
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 8),
          Text(
            'Avatar (128x128)',
            style: theme.textTheme.bodySmall,
          ),
          if (hasAvatar)
            TextButton(
              onPressed: onRemoveImage,
              child: Text(
                'Remove Avatar',
                style: TextStyle(color: DnaColors.textWarning),
              ),
            ),
        ],
      ),
    );
  }
}

/// QR Code section - displays user's fingerprint as scannable QR code
class _QrCodeSection extends ConsumerWidget {
  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final theme = Theme.of(context);
    final fingerprint = ref.watch(currentFingerprintProvider);

    if (fingerprint == null || fingerprint.isEmpty) {
      return const SizedBox.shrink();
    }

    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          children: [
            Row(
              children: [
                FaIcon(
                  FontAwesomeIcons.qrcode,
                  color: theme.colorScheme.primary,
                ),
                const SizedBox(width: 8),
                Text(
                  AppLocalizations.of(context).profileShareQR,
                  style: theme.textTheme.titleMedium,
                ),
              ],
            ),
            const SizedBox(height: 16),
            Container(
              width: 200,
              height: 200,
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: Colors.white,
                borderRadius: BorderRadius.circular(12),
              ),
              child: QrImageView(
                data: fingerprint,
                version: QrVersions.auto,
                size: 176,
                backgroundColor: Colors.white,
              ),
            ),
            const SizedBox(height: 12),
            Text(
              'Scan to add me as a contact',
              style: theme.textTheme.bodySmall,
            ),
            const SizedBox(height: 8),
            Container(
              width: double.infinity,
              padding: const EdgeInsets.all(8),
              decoration: BoxDecoration(
                color: theme.colorScheme.surfaceContainerHighest,
                borderRadius: BorderRadius.circular(8),
              ),
              child: Text(
                fingerprint,
                style: theme.textTheme.bodySmall?.copyWith(
                  fontFamily: 'monospace',
                  fontSize: 8,
                ),
                textAlign: TextAlign.center,
              ),
            ),
          ],
        ),
      ),
    );
  }
}
