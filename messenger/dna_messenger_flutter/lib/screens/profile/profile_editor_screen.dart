// Profile Editor Screen - Edit user profile (wallets, socials, bio, avatar)
import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:image_picker/image_picker.dart';
import 'package:image/image.dart' as img;

import '../../ffi/dna_engine.dart' show decodeBase64WithPadding;
import '../../providers/profile_provider.dart';
import '../../theme/dna_theme.dart';

class ProfileEditorScreen extends ConsumerStatefulWidget {
  const ProfileEditorScreen({super.key});

  @override
  ConsumerState<ProfileEditorScreen> createState() => _ProfileEditorScreenState();
}

class _ProfileEditorScreenState extends ConsumerState<ProfileEditorScreen> {
  final _formKey = GlobalKey<FormState>();

  // Controllers for text fields
  // Profile info
  late TextEditingController _displayNameController;
  late TextEditingController _bioController;
  late TextEditingController _locationController;
  late TextEditingController _websiteController;

  // Wallets
  late TextEditingController _backboneController;
  late TextEditingController _btcController;
  late TextEditingController _ethController;
  late TextEditingController _solController;
  late TextEditingController _trxController;

  // Socials
  late TextEditingController _telegramController;
  late TextEditingController _twitterController;
  late TextEditingController _githubController;
  late TextEditingController _facebookController;
  late TextEditingController _instagramController;
  late TextEditingController _linkedinController;
  late TextEditingController _googleController;

  // Expansion state
  bool _profileExpanded = true;
  bool _walletsExpanded = false;
  bool _socialsExpanded = false;

  @override
  void initState() {
    super.initState();
    // Profile info
    _displayNameController = TextEditingController();
    _bioController = TextEditingController();
    _locationController = TextEditingController();
    _websiteController = TextEditingController();
    // Wallets
    _backboneController = TextEditingController();
    _btcController = TextEditingController();
    _ethController = TextEditingController();
    _solController = TextEditingController();
    _trxController = TextEditingController();
    // Socials
    _telegramController = TextEditingController();
    _twitterController = TextEditingController();
    _githubController = TextEditingController();
    _facebookController = TextEditingController();
    _instagramController = TextEditingController();
    _linkedinController = TextEditingController();
    _googleController = TextEditingController();
  }

  @override
  void dispose() {
    // Profile info
    _displayNameController.dispose();
    _bioController.dispose();
    _locationController.dispose();
    _websiteController.dispose();
    // Wallets
    _backboneController.dispose();
    _btcController.dispose();
    _ethController.dispose();
    _solController.dispose();
    _trxController.dispose();
    // Socials
    _telegramController.dispose();
    _twitterController.dispose();
    _githubController.dispose();
    _facebookController.dispose();
    _instagramController.dispose();
    _linkedinController.dispose();
    _googleController.dispose();
    super.dispose();
  }

  void _syncControllersFromState(ProfileEditorState state) {
    final profile = state.profile;
    // Profile info
    if (_displayNameController.text != profile.displayName) {
      _displayNameController.text = profile.displayName;
    }
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
    if (_btcController.text != profile.btc) {
      _btcController.text = profile.btc;
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
    // Socials
    if (_telegramController.text != profile.telegram) {
      _telegramController.text = profile.telegram;
    }
    if (_twitterController.text != profile.twitter) {
      _twitterController.text = profile.twitter;
    }
    if (_githubController.text != profile.github) {
      _githubController.text = profile.github;
    }
    if (_facebookController.text != profile.facebook) {
      _facebookController.text = profile.facebook;
    }
    if (_instagramController.text != profile.instagram) {
      _instagramController.text = profile.instagram;
    }
    if (_linkedinController.text != profile.linkedin) {
      _linkedinController.text = profile.linkedin;
    }
    if (_googleController.text != profile.google) {
      _googleController.text = profile.google;
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
        title: const Text('Edit Profile'),
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
              icon: const Icon(Icons.save),
              onPressed: () => _saveProfile(notifier),
              tooltip: 'Save',
            ),
        ],
      ),
      body: state.isLoading
          ? const Center(child: CircularProgressIndicator())
          : Form(
              key: _formKey,
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

                  // Profile Info section
                  _buildExpansionSection(
                    title: 'Profile Info',
                    icon: Icons.person,
                    isExpanded: _profileExpanded,
                    onExpansionChanged: (expanded) {
                      setState(() => _profileExpanded = expanded);
                    },
                    children: [
                      _buildTextField(
                        label: 'Display Name',
                        controller: _displayNameController,
                        hint: 'Your display name',
                        onChanged: (v) => notifier.updateField('displayName', v),
                      ),
                      _buildBioField(notifier),
                      _buildTextField(
                        label: 'Location',
                        controller: _locationController,
                        hint: 'City, Country',
                        prefixIcon: Icons.location_on,
                        onChanged: (v) => notifier.updateField('location', v),
                      ),
                      _buildTextField(
                        label: 'Website',
                        controller: _websiteController,
                        hint: 'https://yourwebsite.com',
                        prefixIcon: Icons.language,
                        onChanged: (v) => notifier.updateField('website', v),
                      ),
                    ],
                  ),
                  const SizedBox(height: 16),

                  // Wallet Addresses (read-only, derived from identity keys)
                  _buildExpansionSection(
                    title: 'Wallet Addresses',
                    icon: Icons.account_balance_wallet,
                    isExpanded: _walletsExpanded,
                    onExpansionChanged: (expanded) {
                      setState(() => _walletsExpanded = expanded);
                    },
                    children: [
                      _buildReadOnlyField(
                        label: 'Backbone (Cellframe)',
                        controller: _backboneController,
                      ),
                      _buildReadOnlyField(
                        label: 'Bitcoin (BTC)',
                        controller: _btcController,
                      ),
                      _buildReadOnlyField(
                        label: 'Ethereum (ETH)',
                        controller: _ethController,
                      ),
                      _buildReadOnlyField(
                        label: 'Solana (SOL)',
                        controller: _solController,
                      ),
                      _buildReadOnlyField(
                        label: 'TRON (TRX)',
                        controller: _trxController,
                      ),
                    ],
                  ),
                  const SizedBox(height: 16),

                  // Social Media Links
                  _buildExpansionSection(
                    title: 'Social Media Links',
                    icon: Icons.share,
                    isExpanded: _socialsExpanded,
                    onExpansionChanged: (expanded) {
                      setState(() => _socialsExpanded = expanded);
                    },
                    children: [
                      _buildTextField(
                        label: 'Telegram',
                        controller: _telegramController,
                        hint: '@username',
                        prefixIcon: Icons.telegram,
                        onChanged: (v) => notifier.updateField('telegram', v),
                      ),
                      _buildTextField(
                        label: 'X (Twitter)',
                        controller: _twitterController,
                        hint: '@username',
                        onChanged: (v) => notifier.updateField('twitter', v),
                      ),
                      _buildTextField(
                        label: 'GitHub',
                        controller: _githubController,
                        hint: 'username',
                        prefixIcon: Icons.code,
                        onChanged: (v) => notifier.updateField('github', v),
                      ),
                      _buildTextField(
                        label: 'Facebook',
                        controller: _facebookController,
                        hint: 'username',
                        prefixIcon: Icons.facebook,
                        onChanged: (v) => notifier.updateField('facebook', v),
                      ),
                      _buildTextField(
                        label: 'Instagram',
                        controller: _instagramController,
                        hint: '@username',
                        onChanged: (v) => notifier.updateField('instagram', v),
                      ),
                      _buildTextField(
                        label: 'LinkedIn',
                        controller: _linkedinController,
                        hint: 'profile URL or username',
                        onChanged: (v) => notifier.updateField('linkedin', v),
                      ),
                      _buildTextField(
                        label: 'Google',
                        controller: _googleController,
                        hint: 'email@gmail.com',
                        prefixIcon: Icons.email,
                        onChanged: (v) => notifier.updateField('google', v),
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
                          child: const Text('Cancel'),
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
                              : const Text('Save Profile'),
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 16),
                ],
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
          labelText: 'Bio',
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
      child: ExpansionTile(
        leading: Icon(icon, color: theme.colorScheme.primary),
        title: Text(title, style: theme.textTheme.titleSmall),
        initiallyExpanded: isExpanded,
        onExpansionChanged: onExpansionChanged,
        children: [
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 0, 16, 16),
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
          prefixIcon: prefixIcon != null ? Icon(prefixIcon) : null,
          border: OutlineInputBorder(
            borderRadius: BorderRadius.circular(8),
          ),
        ),
        onChanged: onChanged,
      ),
    );
  }

  Widget _buildReadOnlyField({
    required String label,
    required TextEditingController controller,
  }) {
    final theme = Theme.of(context);

    return Padding(
      padding: const EdgeInsets.only(bottom: 12),
      child: TextFormField(
        controller: controller,
        readOnly: true,
        style: TextStyle(color: theme.colorScheme.onSurface.withAlpha(180)),
        decoration: InputDecoration(
          labelText: label,
          filled: true,
          fillColor: theme.colorScheme.surfaceContainerHighest.withAlpha(100),
          border: OutlineInputBorder(
            borderRadius: BorderRadius.circular(8),
          ),
          suffixIcon: controller.text.isNotEmpty
              ? IconButton(
                  icon: const Icon(Icons.copy, size: 20),
                  onPressed: () {
                    Clipboard.setData(ClipboardData(text: controller.text));
                    ScaffoldMessenger.of(context).showSnackBar(
                      SnackBar(
                        content: Text('$label copied'),
                        duration: const Duration(seconds: 1),
                      ),
                    );
                  },
                  tooltip: 'Copy',
                )
              : null,
        ),
      ),
    );
  }

  Future<void> _pickAvatar(ProfileEditorNotifier notifier) async {
    // Show bottom sheet to choose between camera and gallery
    final source = await showModalBottomSheet<ImageSource>(
      context: context,
      builder: (context) => SafeArea(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            ListTile(
              leading: const Icon(Icons.camera_alt),
              title: const Text('Take a Selfie'),
              onTap: () => Navigator.pop(context, ImageSource.camera),
            ),
            ListTile(
              leading: const Icon(Icons.photo_library),
              title: const Text('Choose from Gallery'),
              onTap: () => Navigator.pop(context, ImageSource.gallery),
            ),
            const SizedBox(height: 8),
          ],
        ),
      ),
    );

    if (source == null) return;

    final picker = ImagePicker();
    final image = await picker.pickImage(
      source: source,
      preferredCameraDevice: CameraDevice.front, // Front camera for selfies
    );

    if (image != null) {
      final bytes = await File(image.path).readAsBytes();

      // Decode, resize to 64x64, and compress as JPEG
      // image_picker's maxWidth/maxHeight doesn't work reliably on all platforms
      final decoded = img.decodeImage(bytes);
      if (decoded == null) {
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(content: Text('Failed to decode image')),
          );
        }
        return;
      }

      // Resize to 64x64 (avatar size)
      final resized = img.copyResize(decoded, width: 64, height: 64);

      // Encode as JPEG with 70% quality (small file size)
      final compressed = img.encodeJpg(resized, quality: 70);

      // Base64 encode - should be ~2-5KB for 64x64 JPEG
      final base64 = base64Encode(compressed);

      // Sanity check: avatar should be under 15KB base64 (buffer is 20KB)
      if (base64.length > 15000) {
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
        child: Icon(
          Icons.person,
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
                    icon: const Icon(Icons.camera_alt, size: 16),
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
            'Avatar (64x64)',
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
