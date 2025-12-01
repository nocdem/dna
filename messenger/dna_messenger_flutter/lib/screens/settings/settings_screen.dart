// Settings Screen - App settings and profile management
import 'dart:async';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../../providers/providers.dart';
import '../../theme/dna_theme.dart';

class SettingsScreen extends ConsumerWidget {
  const SettingsScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final fingerprint = ref.watch(currentFingerprintProvider);
    final profile = ref.watch(userProfileProvider);

    return Scaffold(
      appBar: AppBar(
        title: const Text('Settings'),
      ),
      body: ListView(
        children: [
          // Profile section
          _ProfileSection(
            fingerprint: fingerprint,
            profile: profile,
          ),
          const Divider(),
          // Nickname registration
          _NicknameSection(profile: profile),
          const Divider(),
          // Security
          _SecuritySection(),
          const Divider(),
          // About & Identity
          _IdentitySection(fingerprint: fingerprint),
        ],
      ),
    );
  }
}

class _ProfileSection extends StatelessWidget {
  final String? fingerprint;
  final AsyncValue<UserProfile?> profile;

  const _ProfileSection({
    required this.fingerprint,
    required this.profile,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return Padding(
      padding: const EdgeInsets.all(16),
      child: Row(
        children: [
          CircleAvatar(
            radius: 32,
            backgroundColor: theme.colorScheme.primary.withAlpha(51),
            child: Icon(
              Icons.person,
              size: 32,
              color: theme.colorScheme.primary,
            ),
          ),
          const SizedBox(width: 16),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                profile.when(
                  data: (p) => Text(
                    p?.nickname ?? 'Anonymous',
                    style: theme.textTheme.titleLarge,
                  ),
                  loading: () => const SizedBox(
                    width: 100,
                    height: 20,
                    child: LinearProgressIndicator(),
                  ),
                  error: (e, st) => Text(
                    'Anonymous',
                    style: theme.textTheme.titleLarge,
                  ),
                ),
                const SizedBox(height: 4),
                Text(
                  fingerprint != null
                      ? _shortenFingerprint(fingerprint!)
                      : 'Not loaded',
                  style: theme.textTheme.bodySmall,
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  String _shortenFingerprint(String fp) {
    if (fp.length <= 20) return fp;
    return '${fp.substring(0, 10)}...${fp.substring(fp.length - 10)}';
  }
}

class _NicknameSection extends ConsumerStatefulWidget {
  final AsyncValue<UserProfile?> profile;

  const _NicknameSection({required this.profile});

  @override
  ConsumerState<_NicknameSection> createState() => _NicknameSectionState();
}

class _NicknameSectionState extends ConsumerState<_NicknameSection> {
  final _controller = TextEditingController();
  bool _isRegistering = false;

  // Nickname availability checking
  Timer? _debounceTimer;
  bool _isCheckingAvailability = false;
  String? _availabilityStatus;
  bool _isNameAvailable = false;
  String _lastCheckedName = '';

  @override
  void dispose() {
    _debounceTimer?.cancel();
    _controller.dispose();
    super.dispose();
  }

  /// Validate nickname locally (3-20 chars, alphanumeric + underscore)
  String? _validateNicknameLocally(String name) {
    if (name.isEmpty) return null;
    if (name.length < 3) return 'At least 3 characters';
    if (name.length > 20) return 'Maximum 20 characters';
    final validChars = RegExp(r'^[a-zA-Z0-9_]+$');
    if (!validChars.hasMatch(name)) {
      return 'Only letters, numbers, underscore';
    }
    return null;
  }

  void _onNicknameChanged(String value) {
    setState(() {});

    _debounceTimer?.cancel();

    final name = value.trim().toLowerCase();

    final localError = _validateNicknameLocally(name);
    if (localError != null) {
      setState(() {
        _availabilityStatus = localError;
        _isNameAvailable = false;
        _isCheckingAvailability = false;
      });
      return;
    }

    if (name.isEmpty) {
      setState(() {
        _availabilityStatus = null;
        _isNameAvailable = false;
        _isCheckingAvailability = false;
      });
      return;
    }

    if (name == _lastCheckedName && _availabilityStatus != null) {
      return;
    }

    setState(() => _isCheckingAvailability = true);
    _debounceTimer = Timer(const Duration(milliseconds: 500), () {
      _checkNameAvailability(name);
    });
  }

  Future<void> _checkNameAvailability(String name) async {
    if (!mounted) return;

    try {
      final engine = ref.read(engineProvider).valueOrNull;
      if (engine == null) {
        setState(() {
          _availabilityStatus = 'Engine not ready';
          _isNameAvailable = false;
          _isCheckingAvailability = false;
        });
        return;
      }

      final result = await engine.lookupName(name);

      if (!mounted) return;

      _lastCheckedName = name;
      setState(() {
        _isCheckingAvailability = false;
        if (result.isEmpty) {
          _availabilityStatus = 'Available!';
          _isNameAvailable = true;
        } else {
          _availabilityStatus = 'Already taken';
          _isNameAvailable = false;
        }
      });
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _isCheckingAvailability = false;
        _availabilityStatus = 'Check failed';
        _isNameAvailable = false;
      });
    }
  }

  Widget? _buildAvailabilitySuffix() {
    if (_isCheckingAvailability) {
      return const Padding(
        padding: EdgeInsets.all(12),
        child: SizedBox(
          width: 20,
          height: 20,
          child: CircularProgressIndicator(strokeWidth: 2),
        ),
      );
    }
    if (_controller.text.trim().isEmpty) {
      return null;
    }
    if (_isNameAvailable) {
      return const Icon(Icons.check_circle, color: DnaColors.textSuccess);
    }
    if (_availabilityStatus != null) {
      return const Icon(Icons.cancel, color: DnaColors.textWarning);
    }
    return null;
  }

  Widget _buildAvailabilityStatus(ThemeData theme) {
    if (_isCheckingAvailability) {
      return Text(
        'Checking availability...',
        style: theme.textTheme.bodySmall?.copyWith(color: DnaColors.textMuted),
      );
    }
    if (_availabilityStatus == null || _controller.text.trim().isEmpty) {
      return Text(
        '3-20 characters, letters, numbers, underscore',
        style: theme.textTheme.bodySmall?.copyWith(color: DnaColors.textMuted),
      );
    }
    if (_isNameAvailable) {
      return Text(
        _availabilityStatus!,
        style: theme.textTheme.bodySmall?.copyWith(color: DnaColors.textSuccess),
      );
    }
    return Text(
      _availabilityStatus!,
      style: theme.textTheme.bodySmall?.copyWith(color: DnaColors.textWarning),
    );
  }

  bool _canRegister() {
    return _isNameAvailable && !_isCheckingAvailability && !_isRegistering;
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final hasNickname = widget.profile.valueOrNull?.nickname != null;

    return Padding(
      padding: const EdgeInsets.all(16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Icon(
                Icons.badge,
                color: theme.colorScheme.primary,
              ),
              const SizedBox(width: 8),
              Text(
                'Registered Nickname',
                style: theme.textTheme.titleMedium,
              ),
            ],
          ),
          const SizedBox(height: 8),
          Text(
            hasNickname
                ? 'Your nickname is registered on the DHT and allows others to find you.'
                : 'Register a nickname so others can find you easily without needing your full fingerprint.',
            style: theme.textTheme.bodySmall,
          ),
          const SizedBox(height: 16),
          if (hasNickname)
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: DnaColors.textSuccess.withAlpha(26),
                borderRadius: BorderRadius.circular(8),
              ),
              child: Row(
                children: [
                  Icon(Icons.check_circle, color: DnaColors.textSuccess),
                  const SizedBox(width: 8),
                  Text(
                    widget.profile.valueOrNull?.nickname ?? '',
                    style: theme.textTheme.bodyMedium?.copyWith(
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                ],
              ),
            )
          else
            Column(
              children: [
                TextField(
                  controller: _controller,
                  decoration: InputDecoration(
                    labelText: 'Nickname',
                    hintText: 'Choose a unique nickname',
                    prefixIcon: const Icon(Icons.alternate_email),
                    suffixIcon: _buildAvailabilitySuffix(),
                  ),
                  onChanged: _onNicknameChanged,
                ),
                const SizedBox(height: 8),
                _buildAvailabilityStatus(theme),
                const SizedBox(height: 12),
                SizedBox(
                  width: double.infinity,
                  child: ElevatedButton(
                    onPressed: _canRegister() ? _registerNickname : null,
                    child: _isRegistering
                        ? const SizedBox(
                            width: 20,
                            height: 20,
                            child: CircularProgressIndicator(strokeWidth: 2),
                          )
                        : const Text('Register Nickname'),
                  ),
                ),
              ],
            ),
        ],
      ),
    );
  }

  Future<void> _registerNickname() async {
    setState(() => _isRegistering = true);

    try {
      await ref.read(identitiesProvider.notifier).registerName(_controller.text.trim());

      if (mounted) {
        _controller.clear();
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Nickname "${_controller.text.trim()}" registered'),
            backgroundColor: DnaColors.textSuccess,
          ),
        );
        ref.invalidate(userProfileProvider);
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Failed to register: $e'),
            backgroundColor: DnaColors.textWarning,
          ),
        );
      }
    } finally {
      if (mounted) {
        setState(() => _isRegistering = false);
      }
    }
  }
}

class _SecuritySection extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(16, 16, 16, 8),
          child: Row(
            children: [
              Icon(
                Icons.security,
                color: theme.colorScheme.primary,
              ),
              const SizedBox(width: 8),
              Text(
                'Security',
                style: theme.textTheme.titleMedium,
              ),
            ],
          ),
        ),
        ListTile(
          leading: const Icon(Icons.vpn_key),
          title: const Text('Export Seed Phrase'),
          subtitle: const Text('Back up your recovery phrase'),
          trailing: const Icon(Icons.chevron_right),
          onTap: () => _showExportSeedDialog(context),
        ),
        ListTile(
          leading: const Icon(Icons.lock),
          title: const Text('App Lock'),
          subtitle: const Text('Require authentication'),
          trailing: const Icon(Icons.chevron_right),
          onTap: () {
            ScaffoldMessenger.of(context).showSnackBar(
              const SnackBar(content: Text('Coming soon')),
            );
          },
        ),
      ],
    );
  }

  void _showExportSeedDialog(BuildContext context) {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Export Seed Phrase'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(
              Icons.warning_amber,
              size: 48,
              color: DnaColors.textWarning,
            ),
            const SizedBox(height: 16),
            const Text(
              'Your seed phrase gives full access to your identity. Never share it with anyone.',
              textAlign: TextAlign.center,
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Cancel'),
          ),
          ElevatedButton(
            onPressed: () {
              Navigator.pop(context);
              // TODO: Show seed phrase with confirmation
              ScaffoldMessenger.of(context).showSnackBar(
                const SnackBar(content: Text('Feature coming soon')),
              );
            },
            child: const Text('Show Seed'),
          ),
        ],
      ),
    );
  }
}

class _IdentitySection extends ConsumerWidget {
  final String? fingerprint;

  const _IdentitySection({required this.fingerprint});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final theme = Theme.of(context);

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(16, 16, 16, 8),
          child: Row(
            children: [
              Icon(
                Icons.fingerprint,
                color: theme.colorScheme.primary,
              ),
              const SizedBox(width: 8),
              Text(
                'Identity',
                style: theme.textTheme.titleMedium,
              ),
            ],
          ),
        ),
        if (fingerprint != null)
          ListTile(
            leading: const Icon(Icons.content_copy),
            title: const Text('Copy Fingerprint'),
            subtitle: Text(
              fingerprint!,
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: theme.textTheme.bodySmall?.copyWith(
                fontFamily: 'monospace',
              ),
            ),
            onTap: () {
              Clipboard.setData(ClipboardData(text: fingerprint!));
              ScaffoldMessenger.of(context).showSnackBar(
                const SnackBar(content: Text('Fingerprint copied')),
              );
            },
          ),
        ListTile(
          leading: Icon(Icons.swap_horiz, color: theme.colorScheme.secondary),
          title: const Text('Switch Identity'),
          subtitle: const Text('Use a different identity'),
          trailing: const Icon(Icons.chevron_right),
          onTap: () => _confirmSwitchIdentity(context, ref),
        ),
        const SizedBox(height: 16),
        Padding(
          padding: const EdgeInsets.symmetric(horizontal: 16),
          child: Text(
            'DNA Messenger v1.0.0',
            style: theme.textTheme.bodySmall,
            textAlign: TextAlign.center,
          ),
        ),
        Padding(
          padding: const EdgeInsets.symmetric(horizontal: 16),
          child: Text(
            'Post-Quantum Encrypted',
            style: theme.textTheme.labelSmall?.copyWith(
              color: theme.colorScheme.primary,
            ),
            textAlign: TextAlign.center,
          ),
        ),
        const SizedBox(height: 16),
      ],
    );
  }

  void _confirmSwitchIdentity(BuildContext context, WidgetRef ref) {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Switch Identity'),
        content: const Text(
          'Are you sure you want to switch to a different identity? You will need to sign in again.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Cancel'),
          ),
          ElevatedButton(
            onPressed: () {
              Navigator.pop(context);
              ref.read(identitiesProvider.notifier).unloadIdentity();
            },
            child: const Text('Switch'),
          ),
        ],
      ),
    );
  }
}
