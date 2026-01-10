/// QR Auth Screen - Authorization/login confirmation
import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';
import 'package:share_plus/share_plus.dart';
import '../../providers/providers.dart';
import '../../theme/dna_theme.dart';
import '../../utils/qr_payload_parser.dart';
import '../home_screen.dart';

class QrAuthScreen extends ConsumerStatefulWidget {
  final QrPayload payload;

  const QrAuthScreen({super.key, required this.payload});

  @override
  ConsumerState<QrAuthScreen> createState() => _QrAuthScreenState();
}

class _QrAuthScreenState extends ConsumerState<QrAuthScreen> {
  bool _showRawPayload = false;
  bool _isApproving = false;
  String? _responseToken;
  bool _denied = false;

  /// URL-safe base64 encoding without padding
  String _base64UrlEncodeNoPadding(List<int> bytes) {
    return base64Url.encode(bytes).replaceAll('=', '');
  }

  /// Check if payload has a valid challenge
  bool get _hasChallenge {
    final challenge = widget.payload.challenge?.trim();
    return challenge != null && challenge.isNotEmpty;
  }

  /// Check if payload has domain or appName
  bool get _hasVerificationInfo {
    final domain = widget.payload.domain?.trim();
    final appName = widget.payload.appName?.trim();
    return (domain != null && domain.isNotEmpty) ||
        (appName != null && appName.isNotEmpty);
  }

  /// Close this screen - guaranteed to exit
  void _close() {
    final rootNav = Navigator.of(context, rootNavigator: true);
    final localNav = Navigator.of(context);

    final rootCanPop = rootNav.canPop();
    final localCanPop = localNav.canPop();

    debugPrint('QR_AUTH _close called:');
    debugPrint('  state: hasChallenge=$_hasChallenge, token=${_responseToken != null}, denied=$_denied');
    debugPrint('  nav: rootCanPop=$rootCanPop, localCanPop=$localCanPop');

    // Try root navigator first (this is where we were pushed from scanner)
    if (rootCanPop) {
      debugPrint('QR_AUTH _close: executing rootNav.pop()');
      rootNav.pop();
      return;
    }

    // Try local navigator
    if (localCanPop) {
      debugPrint('QR_AUTH _close: executing localNav.pop()');
      localNav.pop();
      return;
    }

    // FALLBACK: Neither can pop - force navigate to HomeScreen
    debugPrint('QR_AUTH _close: FALLBACK - neither can pop, forcing HomeScreen');
    rootNav.pushAndRemoveUntil(
      MaterialPageRoute(builder: (_) => const HomeScreen()),
      (route) => false,
    );
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final fingerprint = ref.watch(currentFingerprintProvider) ?? '';
    final hasIdentity = fingerprint.isNotEmpty;
    final canApprove = hasIdentity && _hasChallenge;

    // Debug: log state on every build
    debugPrint('QR_AUTH build:');
    debugPrint('  state: hasChallenge=$_hasChallenge, canApprove=$canApprove, token=${_responseToken != null}, denied=$_denied');
    debugPrint('  nav: rootCanPop=${Navigator.of(context, rootNavigator: true).canPop()}, localCanPop=${Navigator.of(context).canPop()}');

    // NO PopScope - let system back work naturally, we also have explicit X button
    return Scaffold(
      appBar: AppBar(
        automaticallyImplyLeading: false,
        leading: IconButton(
          icon: const FaIcon(FontAwesomeIcons.xmark),
          onPressed: () {
            debugPrint('QR_AUTH X button pressed');
            _close();
          },
          tooltip: 'Close',
        ),
        title: const Text('Authorization Request'),
        actions: [
          IconButton(
            icon: FaIcon(_showRawPayload ? FontAwesomeIcons.eyeSlash : FontAwesomeIcons.eye, size: 18),
            onPressed: () => setState(() => _showRawPayload = !_showRawPayload),
            tooltip: _showRawPayload ? 'Hide Raw Data' : 'Show Raw Data',
          ),
        ],
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(24),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            // Warning banner
            Container(
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: DnaColors.textWarning.withAlpha(30),
                borderRadius: BorderRadius.circular(12),
                border: Border.all(color: DnaColors.textWarning.withAlpha(100)),
              ),
              child: Row(
                children: [
                  const FaIcon(FontAwesomeIcons.triangleExclamation,
                      color: DnaColors.textWarning, size: 24),
                  const SizedBox(width: 12),
                  Expanded(
                    child: Text(
                      'An application is requesting to authenticate with your DNA identity',
                      style: theme.textTheme.bodyMedium?.copyWith(
                        color: DnaColors.textWarning,
                      ),
                    ),
                  ),
                ],
              ),
            ),

            // Unverified request warning
            if (!_hasVerificationInfo) ...[
              const SizedBox(height: 8),
              Text(
                'Unverified request (missing domain/app)',
                style: theme.textTheme.bodySmall?.copyWith(
                  color: DnaColors.textWarning,
                  fontStyle: FontStyle.italic,
                ),
                textAlign: TextAlign.center,
              ),
            ],

            const SizedBox(height: 24),

            // Missing challenge error card
            if (!_hasChallenge) ...[
              Container(
                padding: const EdgeInsets.all(16),
                decoration: BoxDecoration(
                  color: DnaColors.textWarning.withAlpha(30),
                  borderRadius: BorderRadius.circular(12),
                  border: Border.all(color: DnaColors.textWarning),
                ),
                child: Column(
                  children: [
                    const FaIcon(FontAwesomeIcons.circleExclamation,
                        color: DnaColors.textWarning, size: 32),
                    const SizedBox(height: 12),
                    Text(
                      'Invalid Authorization Request',
                      style: theme.textTheme.titleMedium?.copyWith(
                        color: DnaColors.textWarning,
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                    const SizedBox(height: 8),
                    Text(
                      'This request is missing a challenge token and cannot be securely approved.',
                      style: theme.textTheme.bodyMedium?.copyWith(
                        color: DnaColors.textMuted,
                      ),
                      textAlign: TextAlign.center,
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 24),
            ],

            // Request details card
            Container(
              padding: const EdgeInsets.all(20),
              decoration: BoxDecoration(
                color: DnaColors.surface,
                borderRadius: BorderRadius.circular(16),
                border: Border.all(color: DnaColors.border),
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  // App name
                  _buildInfoRow(
                    theme,
                    icon: FontAwesomeIcons.mobileScreenButton,
                    label: 'Application',
                    value: widget.payload.appName ?? 'Unknown App',
                  ),
                  const SizedBox(height: 16),

                  // Domain
                  _buildInfoRow(
                    theme,
                    icon: FontAwesomeIcons.globe,
                    label: 'Domain/Service',
                    value: widget.payload.domain ?? 'Unknown',
                  ),

                  // Scopes
                  if (widget.payload.scopes != null && widget.payload.scopes!.isNotEmpty) ...[
                    const SizedBox(height: 16),
                    _buildInfoRow(
                      theme,
                      icon: FontAwesomeIcons.key,
                      label: 'Requested Permissions',
                      value: widget.payload.scopes!.join(', '),
                    ),
                  ],

                  // Challenge
                  if (widget.payload.challenge != null) ...[
                    const SizedBox(height: 16),
                    _buildInfoRow(
                      theme,
                      icon: FontAwesomeIcons.fingerprint,
                      label: 'Challenge',
                      value: _truncate(widget.payload.challenge!, 40),
                      isMonospace: true,
                    ),
                  ],
                ],
              ),
            ),

            // Raw payload toggle
            if (_showRawPayload) ...[
              const SizedBox(height: 16),
              Container(
                padding: const EdgeInsets.all(16),
                decoration: BoxDecoration(
                  color: DnaColors.background,
                  borderRadius: BorderRadius.circular(12),
                  border: Border.all(color: DnaColors.border),
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      'Raw Payload',
                      style: theme.textTheme.labelMedium?.copyWith(
                        color: DnaColors.textMuted,
                      ),
                    ),
                    const SizedBox(height: 8),
                    SelectableText(
                      widget.payload.rawContent,
                      style: theme.textTheme.bodySmall?.copyWith(
                        fontFamily: 'monospace',
                        color: DnaColors.textMuted,
                      ),
                    ),
                  ],
                ),
              ),
            ],

            // Response token (after approval)
            if (_responseToken != null) ...[
              const SizedBox(height: 24),
              Container(
                padding: const EdgeInsets.all(16),
                decoration: BoxDecoration(
                  color: DnaColors.textSuccess.withAlpha(30),
                  borderRadius: BorderRadius.circular(12),
                  border: Border.all(color: DnaColors.textSuccess.withAlpha(100)),
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      children: [
                        const FaIcon(FontAwesomeIcons.circleCheck,
                            color: DnaColors.textSuccess, size: 20),
                        const SizedBox(width: 8),
                        Text(
                          'Authorization Approved',
                          style: theme.textTheme.titleMedium?.copyWith(
                            color: DnaColors.textSuccess,
                            fontWeight: FontWeight.bold,
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 12),
                    Text(
                      'Response Token:',
                      style: theme.textTheme.labelMedium?.copyWith(
                        color: DnaColors.textMuted,
                      ),
                    ),
                    const SizedBox(height: 8),
                    Container(
                      padding: const EdgeInsets.all(12),
                      decoration: BoxDecoration(
                        color: DnaColors.surface,
                        borderRadius: BorderRadius.circular(8),
                      ),
                      child: SelectableText(
                        _responseToken!,
                        style: theme.textTheme.bodySmall?.copyWith(
                          fontFamily: 'monospace',
                        ),
                      ),
                    ),
                    const SizedBox(height: 12),
                    Row(
                      children: [
                        Expanded(
                          child: OutlinedButton.icon(
                            onPressed: () {
                              Clipboard.setData(ClipboardData(text: _responseToken!));
                              ScaffoldMessenger.of(context).showSnackBar(
                                const SnackBar(content: Text('Token copied')),
                              );
                            },
                            icon: const FaIcon(FontAwesomeIcons.copy, size: 14),
                            label: const Text('Copy'),
                          ),
                        ),
                        const SizedBox(width: 12),
                        Expanded(
                          child: OutlinedButton.icon(
                            onPressed: () => Share.share(_responseToken!),
                            icon: const FaIcon(FontAwesomeIcons.shareNodes, size: 14),
                            label: const Text('Share'),
                          ),
                        ),
                      ],
                    ),
                  ],
                ),
              ),
            ],

            // Denied message
            if (_denied) ...[
              const SizedBox(height: 24),
              Container(
                padding: const EdgeInsets.all(16),
                decoration: BoxDecoration(
                  color: DnaColors.textWarning.withAlpha(30),
                  borderRadius: BorderRadius.circular(12),
                ),
                child: Row(
                  children: [
                    const FaIcon(FontAwesomeIcons.ban, color: DnaColors.textWarning, size: 20),
                    const SizedBox(width: 12),
                    Text(
                      'Authorization Denied',
                      style: theme.textTheme.titleMedium?.copyWith(
                        color: DnaColors.textWarning,
                      ),
                    ),
                  ],
                ),
              ),
            ],

            const SizedBox(height: 32),

            // Action buttons
            if (_responseToken == null && !_denied) ...[
              // Only show approve/deny if we have a valid challenge
              if (_hasChallenge) ...[
                ElevatedButton.icon(
                  onPressed: (_isApproving || !canApprove) ? null : _approve,
                  icon: _isApproving
                      ? const SizedBox(
                          width: 16,
                          height: 16,
                          child: CircularProgressIndicator(strokeWidth: 2),
                        )
                      : const FaIcon(FontAwesomeIcons.check, size: 16),
                  label: const Text('Approve'),
                  style: ElevatedButton.styleFrom(
                    padding: const EdgeInsets.symmetric(vertical: 16),
                    backgroundColor: DnaColors.textSuccess,
                  ),
                ),
                const SizedBox(height: 12),
                OutlinedButton.icon(
                  onPressed: _isApproving ? null : _deny,
                  icon: const FaIcon(FontAwesomeIcons.xmark, size: 16),
                  label: const Text('Deny'),
                  style: OutlinedButton.styleFrom(
                    padding: const EdgeInsets.symmetric(vertical: 16),
                    foregroundColor: DnaColors.textWarning,
                  ),
                ),
              ] else ...[
                // No challenge - only show Done button
                OutlinedButton(
                  onPressed: () {
                    debugPrint('QR_AUTH Done button pressed (no challenge path)');
                    _close();
                  },
                  child: const Text('Done'),
                ),
              ],
            ] else ...[
              OutlinedButton(
                onPressed: () {
                  debugPrint('QR_AUTH Done button pressed (after approve/deny)');
                  _close();
                },
                child: const Text('Done'),
              ),
            ],
          ],
        ),
      ),
    );
  }

  Widget _buildInfoRow(
    ThemeData theme, {
    required IconData icon,
    required String label,
    required String value,
    bool isMonospace = false,
  }) {
    return Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        FaIcon(icon, size: 16, color: DnaColors.primary),
        const SizedBox(width: 12),
        Expanded(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                label,
                style: theme.textTheme.labelMedium?.copyWith(
                  color: DnaColors.textMuted,
                ),
              ),
              const SizedBox(height: 4),
              Text(
                value,
                style: theme.textTheme.bodyLarge?.copyWith(
                  fontFamily: isMonospace ? 'monospace' : null,
                ),
              ),
            ],
          ),
        ),
      ],
    );
  }

  String _truncate(String text, int maxLength) {
    if (text.length <= maxLength) return text;
    return '${text.substring(0, maxLength)}...';
  }

  Future<void> _approve() async {
    // Check for valid identity first
    final fingerprint = ref.read(currentFingerprintProvider) ?? '';
    if (fingerprint.isEmpty) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text('No identity loaded'),
            backgroundColor: DnaColors.textWarning,
          ),
        );
      }
      return;
    }

    setState(() => _isApproving = true);

    try {
      final profile = ref.read(userProfileProvider).valueOrNull;
      final now = DateTime.now().toUtc();
      final exp = now.add(const Duration(seconds: 60));

      // Generate response token (v1: simple JSON with identity info)
      // TODO: Add Dilithium5 signature of the response payload
      final response = {
        'type': 'dna_auth_response',
        'version': 1,
        'status': 'approved',
        'iat': now.toIso8601String(),
        'exp': exp.toIso8601String(),
        'identity': {
          'fingerprint': fingerprint,
          'name': profile?.nickname,
        },
        'request': {
          'app': widget.payload.appName,
          'domain': widget.payload.domain,
          'challenge': widget.payload.challenge,
        },
        // TODO: Add cryptographic signature here
        // 'signature': '<dilithium5_signature_of_response>'
      };

      final token = _base64UrlEncodeNoPadding(utf8.encode(jsonEncode(response)));

      setState(() {
        _isApproving = false;
        _responseToken = token;
      });
    } catch (e) {
      setState(() => _isApproving = false);
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Error: $e'),
            backgroundColor: DnaColors.textWarning,
          ),
        );
      }
    }
  }

  void _deny() {
    setState(() => _denied = true);
  }
}
