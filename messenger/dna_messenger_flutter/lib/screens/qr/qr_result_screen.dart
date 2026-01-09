/// QR Result Screen - Display scanned QR content and actions
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';
import 'package:share_plus/share_plus.dart';
import 'package:url_launcher/url_launcher.dart';
import '../../providers/providers.dart';
import '../../providers/contact_requests_provider.dart';
import '../../theme/dna_theme.dart';
import '../../utils/qr_payload_parser.dart';
import 'qr_auth_screen.dart';

class QrResultScreen extends ConsumerStatefulWidget {
  final QrPayload payload;

  const QrResultScreen({super.key, required this.payload});

  @override
  ConsumerState<QrResultScreen> createState() => _QrResultScreenState();
}

class _QrResultScreenState extends ConsumerState<QrResultScreen> {
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text(_getTitle()),
      ),
      body: _buildBody(),
    );
  }

  String _getTitle() {
    switch (widget.payload.type) {
      case QrPayloadType.contact:
        return 'Add Contact';
      case QrPayloadType.auth:
        return 'Authorization Request';
      case QrPayloadType.plainText:
        return 'QR Content';
    }
  }

  Widget _buildBody() {
    switch (widget.payload.type) {
      case QrPayloadType.contact:
        return _ContactResult(payload: widget.payload);
      case QrPayloadType.auth:
        return _AuthResult(payload: widget.payload);
      case QrPayloadType.plainText:
        return _PlainTextResult(payload: widget.payload);
    }
  }
}

/// Contact result - show contact info and add button
class _ContactResult extends ConsumerStatefulWidget {
  final QrPayload payload;

  const _ContactResult({required this.payload});

  @override
  ConsumerState<_ContactResult> createState() => _ContactResultState();
}

class _ContactResultState extends ConsumerState<_ContactResult> {
  bool _isAdding = false;
  String? _errorMessage;
  bool _requestSent = false;

  Future<void> _addContact() async {
    if (widget.payload.fingerprint == null) return;

    setState(() {
      _isAdding = true;
      _errorMessage = null;
    });

    try {
      // Check if trying to add self
      final currentFp = ref.read(currentFingerprintProvider);
      if (widget.payload.fingerprint == currentFp) {
        setState(() {
          _isAdding = false;
          _errorMessage = 'You cannot add yourself as a contact';
        });
        return;
      }

      // Check if already in contacts
      final contacts = ref.read(contactsProvider).valueOrNull ?? [];
      final alreadyExists = contacts.any((c) => c.fingerprint == widget.payload.fingerprint);
      if (alreadyExists) {
        setState(() {
          _isAdding = false;
          _errorMessage = 'Contact already exists in your list';
        });
        return;
      }

      // Send contact request
      await ref.read(contactRequestsProvider.notifier).sendRequest(
            widget.payload.fingerprint!,
            null,
          );

      setState(() {
        _isAdding = false;
        _requestSent = true;
      });

      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Contact request sent to ${widget.payload.displayName ?? 'user'}'),
            backgroundColor: DnaColors.snackbarSuccess,
          ),
        );
      }
    } catch (e) {
      setState(() {
        _isAdding = false;
        _errorMessage = 'Failed to send request: $e';
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final fp = widget.payload.fingerprint ?? '';
    final shortFp = fp.length > 20 ? '${fp.substring(0, 10)}...${fp.substring(fp.length - 10)}' : fp;

    return SingleChildScrollView(
      padding: const EdgeInsets.all(24),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          // Contact card
          Container(
            padding: const EdgeInsets.all(20),
            decoration: BoxDecoration(
              color: DnaColors.surface,
              borderRadius: BorderRadius.circular(16),
              border: Border.all(color: DnaColors.border),
            ),
            child: Column(
              children: [
                // Avatar placeholder
                CircleAvatar(
                  radius: 48,
                  backgroundColor: DnaColors.primarySoft,
                  child: FaIcon(
                    FontAwesomeIcons.user,
                    size: 40,
                    color: DnaColors.primary,
                  ),
                ),
                const SizedBox(height: 16),
                // Display name
                Text(
                  widget.payload.displayName ?? 'Unknown',
                  style: theme.textTheme.headlineSmall?.copyWith(
                    fontWeight: FontWeight.bold,
                  ),
                ),
                const SizedBox(height: 8),
                // Fingerprint
                Text(
                  shortFp,
                  style: theme.textTheme.bodyMedium?.copyWith(
                    fontFamily: 'monospace',
                    color: DnaColors.textMuted,
                  ),
                ),
                const SizedBox(height: 8),
                // Copy fingerprint button
                TextButton.icon(
                  onPressed: () {
                    Clipboard.setData(ClipboardData(text: fp));
                    ScaffoldMessenger.of(context).showSnackBar(
                      const SnackBar(content: Text('Fingerprint copied')),
                    );
                  },
                  icon: const FaIcon(FontAwesomeIcons.copy, size: 14),
                  label: const Text('Copy Fingerprint'),
                ),
              ],
            ),
          ),
          const SizedBox(height: 24),

          // Error message
          if (_errorMessage != null) ...[
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: DnaColors.textWarning.withAlpha(30),
                borderRadius: BorderRadius.circular(8),
              ),
              child: Row(
                children: [
                  const FaIcon(FontAwesomeIcons.circleExclamation,
                      color: DnaColors.textWarning, size: 16),
                  const SizedBox(width: 8),
                  Expanded(
                    child: Text(
                      _errorMessage!,
                      style: theme.textTheme.bodyMedium?.copyWith(
                        color: DnaColors.textWarning,
                      ),
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 16),
          ],

          // Success message
          if (_requestSent) ...[
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: DnaColors.textSuccess.withAlpha(30),
                borderRadius: BorderRadius.circular(8),
              ),
              child: Row(
                children: [
                  const FaIcon(FontAwesomeIcons.circleCheck,
                      color: DnaColors.textSuccess, size: 16),
                  const SizedBox(width: 8),
                  Expanded(
                    child: Text(
                      'Contact request sent successfully!',
                      style: theme.textTheme.bodyMedium?.copyWith(
                        color: DnaColors.textSuccess,
                      ),
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 16),
          ],

          // Add contact button
          ElevatedButton.icon(
            onPressed: _isAdding || _requestSent ? null : _addContact,
            icon: _isAdding
                ? const SizedBox(
                    width: 16,
                    height: 16,
                    child: CircularProgressIndicator(strokeWidth: 2),
                  )
                : FaIcon(_requestSent ? FontAwesomeIcons.check : FontAwesomeIcons.userPlus, size: 16),
            label: Text(_requestSent ? 'Request Sent' : 'Send Contact Request'),
            style: ElevatedButton.styleFrom(
              padding: const EdgeInsets.symmetric(vertical: 16),
            ),
          ),
          const SizedBox(height: 12),

          // Back button
          OutlinedButton(
            onPressed: () => Navigator.of(context).pop(),
            child: const Text('Scan Another'),
          ),
        ],
      ),
    );
  }
}

/// Auth result - redirect to auth screen
class _AuthResult extends StatelessWidget {
  final QrPayload payload;

  const _AuthResult({required this.payload});

  @override
  Widget build(BuildContext context) {
    // Automatically navigate to auth screen
    WidgetsBinding.instance.addPostFrameCallback((_) {
      Navigator.of(context).pushReplacement(
        MaterialPageRoute(
          builder: (context) => QrAuthScreen(payload: payload),
        ),
      );
    });

    return const Center(
      child: CircularProgressIndicator(),
    );
  }
}

/// Plain text result - show content with actions
class _PlainTextResult extends StatelessWidget {
  final QrPayload payload;

  const _PlainTextResult({required this.payload});

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return SingleChildScrollView(
      padding: const EdgeInsets.all(24),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          // Content card
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
                Row(
                  children: [
                    const FaIcon(FontAwesomeIcons.qrcode, size: 20, color: DnaColors.primary),
                    const SizedBox(width: 8),
                    Text(
                      'QR Content',
                      style: theme.textTheme.titleMedium?.copyWith(
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 16),
                SelectableText(
                  payload.rawContent,
                  style: theme.textTheme.bodyMedium?.copyWith(
                    fontFamily: payload.looksLikeFingerprint ? 'monospace' : null,
                  ),
                ),
              ],
            ),
          ),
          const SizedBox(height: 24),

          // Actions
          _buildActionButton(
            context,
            icon: FontAwesomeIcons.copy,
            label: 'Copy to Clipboard',
            onPressed: () {
              Clipboard.setData(ClipboardData(text: payload.rawContent));
              ScaffoldMessenger.of(context).showSnackBar(
                const SnackBar(content: Text('Copied to clipboard')),
              );
            },
          ),
          const SizedBox(height: 12),

          _buildActionButton(
            context,
            icon: FontAwesomeIcons.shareNodes,
            label: 'Share',
            onPressed: () {
              Share.share(payload.rawContent);
            },
          ),

          // URL action
          if (payload.looksLikeUrl) ...[
            const SizedBox(height: 12),
            _buildActionButton(
              context,
              icon: FontAwesomeIcons.arrowUpRightFromSquare,
              label: 'Open in Browser',
              onPressed: () async {
                var url = payload.rawContent;
                if (!url.startsWith('http://') && !url.startsWith('https://')) {
                  url = 'https://$url';
                }
                final uri = Uri.tryParse(url);
                if (uri != null && await canLaunchUrl(uri)) {
                  await launchUrl(uri, mode: LaunchMode.externalApplication);
                }
              },
            ),
          ],

          // Fingerprint action
          if (payload.looksLikeFingerprint) ...[
            const SizedBox(height: 12),
            _buildActionButton(
              context,
              icon: FontAwesomeIcons.userPlus,
              label: 'Add as Contact',
              isPrimary: true,
              onPressed: () {
                // Navigate to contact result with parsed fingerprint
                Navigator.of(context).pushReplacement(
                  MaterialPageRoute(
                    builder: (context) => QrResultScreen(
                      payload: QrPayload(
                        type: QrPayloadType.contact,
                        rawContent: payload.rawContent,
                        fingerprint: payload.rawContent.toLowerCase(),
                      ),
                    ),
                  ),
                );
              },
            ),
          ],

          const SizedBox(height: 24),
          OutlinedButton(
            onPressed: () => Navigator.of(context).pop(),
            child: const Text('Scan Another'),
          ),
        ],
      ),
    );
  }

  Widget _buildActionButton(
    BuildContext context, {
    required IconData icon,
    required String label,
    required VoidCallback onPressed,
    bool isPrimary = false,
  }) {
    if (isPrimary) {
      return ElevatedButton.icon(
        onPressed: onPressed,
        icon: FaIcon(icon, size: 16),
        label: Text(label),
        style: ElevatedButton.styleFrom(
          padding: const EdgeInsets.symmetric(vertical: 14),
        ),
      );
    }

    return OutlinedButton.icon(
      onPressed: onPressed,
      icon: FaIcon(icon, size: 16),
      label: Text(label),
      style: OutlinedButton.styleFrom(
        padding: const EdgeInsets.symmetric(vertical: 14),
      ),
    );
  }
}
