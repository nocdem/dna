// Profile Editor Screen - Edit user profile (wallets, socials, bio, avatar)
import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:image_picker/image_picker.dart';

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
  late TextEditingController _backboneController;
  late TextEditingController _kelvpnController;
  late TextEditingController _subzeroController;
  late TextEditingController _cpunkTestnetController;
  late TextEditingController _btcController;
  late TextEditingController _ethController;
  late TextEditingController _solController;
  late TextEditingController _telegramController;
  late TextEditingController _twitterController;
  late TextEditingController _githubController;
  late TextEditingController _bioController;

  // Expansion state
  bool _cellframeExpanded = true;
  bool _externalExpanded = false;
  bool _socialsExpanded = false;

  @override
  void initState() {
    super.initState();
    _backboneController = TextEditingController();
    _kelvpnController = TextEditingController();
    _subzeroController = TextEditingController();
    _cpunkTestnetController = TextEditingController();
    _btcController = TextEditingController();
    _ethController = TextEditingController();
    _solController = TextEditingController();
    _telegramController = TextEditingController();
    _twitterController = TextEditingController();
    _githubController = TextEditingController();
    _bioController = TextEditingController();
  }

  @override
  void dispose() {
    _backboneController.dispose();
    _kelvpnController.dispose();
    _subzeroController.dispose();
    _cpunkTestnetController.dispose();
    _btcController.dispose();
    _ethController.dispose();
    _solController.dispose();
    _telegramController.dispose();
    _twitterController.dispose();
    _githubController.dispose();
    _bioController.dispose();
    super.dispose();
  }

  void _syncControllersFromState(ProfileEditorState state) {
    final profile = state.profile;
    if (_backboneController.text != profile.backbone) {
      _backboneController.text = profile.backbone;
    }
    if (_kelvpnController.text != profile.kelvpn) {
      _kelvpnController.text = profile.kelvpn;
    }
    if (_subzeroController.text != profile.subzero) {
      _subzeroController.text = profile.subzero;
    }
    if (_cpunkTestnetController.text != profile.cpunkTestnet) {
      _cpunkTestnetController.text = profile.cpunkTestnet;
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
    if (_telegramController.text != profile.telegram) {
      _telegramController.text = profile.telegram;
    }
    if (_twitterController.text != profile.twitter) {
      _twitterController.text = profile.twitter;
    }
    if (_githubController.text != profile.github) {
      _githubController.text = profile.github;
    }
    if (_bioController.text != profile.bio) {
      _bioController.text = profile.bio;
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
            backgroundColor: DnaColors.textSuccess,
          ),
        );
      });
    }
    if (state.error != null) {
      WidgetsBinding.instance.addPostFrameCallback((_) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(state.error!),
            backgroundColor: DnaColors.textWarning,
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

                  // Bio section
                  _buildBioField(notifier),
                  const SizedBox(height: 24),

                  // Cellframe Network Addresses
                  _buildExpansionSection(
                    title: 'Cellframe Network Addresses',
                    icon: Icons.account_balance_wallet,
                    isExpanded: _cellframeExpanded,
                    onExpansionChanged: (expanded) {
                      setState(() => _cellframeExpanded = expanded);
                    },
                    children: [
                      _buildTextField(
                        label: 'Backbone',
                        controller: _backboneController,
                        hint: 'Backbone wallet address',
                        onChanged: (v) => notifier.updateField('backbone', v),
                      ),
                      _buildTextField(
                        label: 'KelVPN',
                        controller: _kelvpnController,
                        hint: 'KelVPN wallet address',
                        onChanged: (v) => notifier.updateField('kelvpn', v),
                      ),
                      _buildTextField(
                        label: 'Subzero',
                        controller: _subzeroController,
                        hint: 'Subzero wallet address',
                        onChanged: (v) => notifier.updateField('subzero', v),
                      ),
                      _buildTextField(
                        label: 'CPUNK Testnet',
                        controller: _cpunkTestnetController,
                        hint: 'CPUNK Testnet wallet address',
                        onChanged: (v) => notifier.updateField('cpunkTestnet', v),
                      ),
                    ],
                  ),
                  const SizedBox(height: 16),

                  // External Wallet Addresses
                  _buildExpansionSection(
                    title: 'External Wallet Addresses',
                    icon: Icons.currency_bitcoin,
                    isExpanded: _externalExpanded,
                    onExpansionChanged: (expanded) {
                      setState(() => _externalExpanded = expanded);
                    },
                    children: [
                      _buildTextField(
                        label: 'Bitcoin (BTC)',
                        controller: _btcController,
                        hint: 'Bitcoin wallet address',
                        onChanged: (v) => notifier.updateField('btc', v),
                      ),
                      _buildTextField(
                        label: 'Ethereum (ETH)',
                        controller: _ethController,
                        hint: 'Ethereum wallet address',
                        onChanged: (v) => notifier.updateField('eth', v),
                      ),
                      _buildTextField(
                        label: 'Solana (SOL)',
                        controller: _solController,
                        hint: 'Solana wallet address',
                        onChanged: (v) => notifier.updateField('sol', v),
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
                        prefixIcon: Icons.flutter_dash, // X icon not available
                        onChanged: (v) => notifier.updateField('twitter', v),
                      ),
                      _buildTextField(
                        label: 'GitHub',
                        controller: _githubController,
                        hint: 'username',
                        prefixIcon: Icons.code,
                        onChanged: (v) => notifier.updateField('github', v),
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
    final theme = Theme.of(context);

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          children: [
            Icon(Icons.edit_note, color: theme.colorScheme.primary),
            const SizedBox(width: 8),
            Text('Bio', style: theme.textTheme.titleMedium),
          ],
        ),
        const SizedBox(height: 8),
        TextFormField(
          controller: _bioController,
          maxLines: 4,
          maxLength: 512,
          decoration: InputDecoration(
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
      ],
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

  Future<void> _pickAvatar(ProfileEditorNotifier notifier) async {
    final picker = ImagePicker();
    final image = await picker.pickImage(
      source: ImageSource.gallery,
      maxWidth: 64,
      maxHeight: 64,
      imageQuality: 80,
    );

    if (image != null) {
      final bytes = await File(image.path).readAsBytes();
      final base64 = base64Encode(bytes);
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
    if (hasAvatar) {
      try {
        final bytes = base64Decode(avatarBase64);
        avatarWidget = CircleAvatar(
          radius: 48,
          backgroundImage: MemoryImage(bytes),
        );
      } catch (e) {
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
