// QR Auth Screen - Authorization/login confirmation
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';
import '../../providers/providers.dart';
import '../../services/qr_auth_service.dart';
import '../../theme/dna_theme.dart';
import '../../utils/qr_payload_parser.dart';
import '../home_screen.dart';

class QrAuthScreen extends ConsumerStatefulWidget {
  final QrPayload payload;

  const QrAuthScreen({super.key, required this.payload});

  @override
  ConsumerState<QrAuthScreen> createState() => _QrAuthScreenState();
}

enum _AuthState {
  pending,    // Waiting for user action
  approving,  // Sending to callback
  approved,   // Success
  failed,     // Network/server error (can retry)
  denied,     // User denied
}

class _QrAuthScreenState extends ConsumerState<QrAuthScreen> {
  bool _showRawPayload = false;
  _AuthState _state = _AuthState.pending;
  String? _errorMessage;

  /// Check if payload has valid required fields for auth
  bool get _hasRequiredFields => widget.payload.hasRequiredAuthFields;

  /// Check if payload has domain or appName for display
  bool get _hasVerificationInfo {
    final origin = widget.payload.origin?.trim();
    final appName = widget.payload.appName?.trim();
    return (origin != null && origin.isNotEmpty) ||
        (appName != null && appName.isNotEmpty);
  }

  /// Close this screen - guaranteed to exit
  void _close() {
    final rootNav = Navigator.of(context, rootNavigator: true);
    final localNav = Navigator.of(context);

    final rootCanPop = rootNav.canPop();
    final localCanPop = localNav.canPop();

    debugPrint('QR_AUTH _close: rootCanPop=$rootCanPop, localCanPop=$localCanPop');

    // Try root navigator first (this is where we were pushed from scanner)
    if (rootCanPop) {
      rootNav.pop();
      return;
    }

    // Try local navigator
    if (localCanPop) {
      localNav.pop();
      return;
    }

    // FALLBACK: Neither can pop - force navigate to HomeScreen
    debugPrint('QR_AUTH _close: FALLBACK - forcing HomeScreen');
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
    final canApprove = hasIdentity && _hasRequiredFields && !widget.payload.isExpired;

    // NO PopScope - let system back work naturally, we also have explicit X button
    return Scaffold(
      appBar: AppBar(
        automaticallyImplyLeading: false,
        leading: IconButton(
          icon: const FaIcon(FontAwesomeIcons.xmark),
          onPressed: _close,
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
                'Unverified request (missing origin/app)',
                style: theme.textTheme.bodySmall?.copyWith(
                  color: DnaColors.textWarning,
                  fontStyle: FontStyle.italic,
                ),
                textAlign: TextAlign.center,
              ),
            ],

            const SizedBox(height: 24),

            // Missing required fields error card
            if (!_hasRequiredFields) ...[
              _buildErrorCard(
                theme,
                title: 'Invalid Authorization Request',
                message: 'This request is missing required fields (origin, session_id, nonce, or callback) and cannot be approved.',
              ),
              const SizedBox(height: 24),
            ],

            // Expired request error card
            if (_hasRequiredFields && widget.payload.isExpired) ...[
              _buildErrorCard(
                theme,
                title: 'Request Expired',
                message: 'This authorization request has expired. Please scan a new QR code.',
              ),
              const SizedBox(height: 24),
            ],

            // Request details card
            _buildRequestDetailsCard(theme),

            // Raw payload toggle
            if (_showRawPayload) ...[
              const SizedBox(height: 16),
              _buildRawPayloadCard(theme),
            ],

            // Success state
            if (_state == _AuthState.approved) ...[
              const SizedBox(height: 24),
              _buildSuccessCard(theme),
            ],

            // Error state (can retry)
            if (_state == _AuthState.failed && _errorMessage != null) ...[
              const SizedBox(height: 24),
              _buildFailureCard(theme, _errorMessage!),
            ],

            // Denied message
            if (_state == _AuthState.denied) ...[
              const SizedBox(height: 24),
              _buildDeniedCard(theme),
            ],

            const SizedBox(height: 32),

            // Action buttons
            _buildActionButtons(theme, canApprove),
          ],
        ),
      ),
    );
  }

  Widget _buildErrorCard(ThemeData theme, {required String title, required String message}) {
    return Container(
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
            title,
            style: theme.textTheme.titleMedium?.copyWith(
              color: DnaColors.textWarning,
              fontWeight: FontWeight.bold,
            ),
          ),
          const SizedBox(height: 8),
          Text(
            message,
            style: theme.textTheme.bodyMedium?.copyWith(
              color: DnaColors.textMuted,
            ),
            textAlign: TextAlign.center,
          ),
        ],
      ),
    );
  }

  Widget _buildRequestDetailsCard(ThemeData theme) {
    return Container(
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

          // Origin/Domain
          _buildInfoRow(
            theme,
            icon: FontAwesomeIcons.globe,
            label: 'Origin',
            value: widget.payload.origin ?? 'Unknown',
          ),

          // Session ID
          if (widget.payload.sessionId != null) ...[
            const SizedBox(height: 16),
            _buildInfoRow(
              theme,
              icon: FontAwesomeIcons.hashtag,
              label: 'Session',
              value: _truncate(widget.payload.sessionId!, 32),
              isMonospace: true,
            ),
          ],

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

          // Nonce/Challenge
          if (widget.payload.nonce != null) ...[
            const SizedBox(height: 16),
            _buildInfoRow(
              theme,
              icon: FontAwesomeIcons.fingerprint,
              label: 'Nonce',
              value: _truncate(widget.payload.nonce!, 40),
              isMonospace: true,
            ),
          ],

          // Expiry
          if (widget.payload.expiresAt != null) ...[
            const SizedBox(height: 16),
            _buildInfoRow(
              theme,
              icon: FontAwesomeIcons.clock,
              label: 'Expires',
              value: _formatExpiry(widget.payload.expiresAt!),
            ),
          ],
        ],
      ),
    );
  }

  Widget _buildRawPayloadCard(ThemeData theme) {
    return Container(
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
    );
  }

  Widget _buildSuccessCard(ThemeData theme) {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: DnaColors.textSuccess.withAlpha(30),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: DnaColors.textSuccess.withAlpha(100)),
      ),
      child: Row(
        children: [
          const FaIcon(FontAwesomeIcons.circleCheck,
              color: DnaColors.textSuccess, size: 24),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'Authorization Approved',
                  style: theme.textTheme.titleMedium?.copyWith(
                    color: DnaColors.textSuccess,
                    fontWeight: FontWeight.bold,
                  ),
                ),
                const SizedBox(height: 4),
                Text(
                  'Successfully authenticated with ${widget.payload.origin ?? "the service"}',
                  style: theme.textTheme.bodySmall?.copyWith(
                    color: DnaColors.textMuted,
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildFailureCard(ThemeData theme, String error) {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: DnaColors.textWarning.withAlpha(30),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: DnaColors.textWarning.withAlpha(100)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              const FaIcon(FontAwesomeIcons.circleXmark,
                  color: DnaColors.textWarning, size: 24),
              const SizedBox(width: 12),
              Expanded(
                child: Text(
                  'Authorization Failed',
                  style: theme.textTheme.titleMedium?.copyWith(
                    color: DnaColors.textWarning,
                    fontWeight: FontWeight.bold,
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 8),
          Text(
            error,
            style: theme.textTheme.bodyMedium?.copyWith(
              color: DnaColors.textMuted,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildDeniedCard(ThemeData theme) {
    return Container(
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
    );
  }

  Widget _buildActionButtons(ThemeData theme, bool canApprove) {
    switch (_state) {
      case _AuthState.pending:
        if (_hasRequiredFields && !widget.payload.isExpired) {
          return Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              ElevatedButton.icon(
                onPressed: canApprove ? _approve : null,
                icon: const FaIcon(FontAwesomeIcons.check, size: 16),
                label: const Text('Approve'),
                style: ElevatedButton.styleFrom(
                  padding: const EdgeInsets.symmetric(vertical: 16),
                  backgroundColor: DnaColors.textSuccess,
                ),
              ),
              const SizedBox(height: 12),
              OutlinedButton.icon(
                onPressed: _deny,
                icon: const FaIcon(FontAwesomeIcons.xmark, size: 16),
                label: const Text('Deny'),
                style: OutlinedButton.styleFrom(
                  padding: const EdgeInsets.symmetric(vertical: 16),
                  foregroundColor: DnaColors.textWarning,
                ),
              ),
            ],
          );
        } else {
          // Invalid request - only show Done
          return OutlinedButton(
            onPressed: _close,
            child: const Text('Done'),
          );
        }

      case _AuthState.approving:
        return ElevatedButton.icon(
          onPressed: null,
          icon: const SizedBox(
            width: 16,
            height: 16,
            child: CircularProgressIndicator(strokeWidth: 2, color: Colors.white),
          ),
          label: const Text('Approving...'),
          style: ElevatedButton.styleFrom(
            padding: const EdgeInsets.symmetric(vertical: 16),
            backgroundColor: DnaColors.textSuccess,
          ),
        );

      case _AuthState.failed:
        return Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            ElevatedButton.icon(
              onPressed: _approve,
              icon: const FaIcon(FontAwesomeIcons.arrowsRotate, size: 16),
              label: const Text('Retry'),
              style: ElevatedButton.styleFrom(
                padding: const EdgeInsets.symmetric(vertical: 16),
              ),
            ),
            const SizedBox(height: 12),
            OutlinedButton(
              onPressed: _close,
              child: const Text('Cancel'),
            ),
          ],
        );

      case _AuthState.approved:
      case _AuthState.denied:
        return OutlinedButton(
          onPressed: _close,
          child: const Text('Done'),
        );
    }
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

  String _formatExpiry(int epochSeconds) {
    final expiry = DateTime.fromMillisecondsSinceEpoch(epochSeconds * 1000);
    final now = DateTime.now();
    final diff = expiry.difference(now);

    if (diff.isNegative) {
      return 'Expired';
    } else if (diff.inMinutes < 1) {
      return 'In ${diff.inSeconds} seconds';
    } else if (diff.inHours < 1) {
      return 'In ${diff.inMinutes} minutes';
    } else {
      return 'In ${diff.inHours} hours';
    }
  }

  Future<void> _approve() async {
    // Check for valid identity first
    final engine = ref.read(engineProvider).valueOrNull;
    if (engine == null) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text('Engine not initialized'),
            backgroundColor: DnaColors.textWarning,
          ),
        );
      }
      return;
    }

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

    setState(() {
      _state = _AuthState.approving;
      _errorMessage = null;
    });

    try {
      final authService = QrAuthService(engine);
      final result = await authService.approve(widget.payload);

      if (!mounted) return;

      if (result.success) {
        setState(() => _state = _AuthState.approved);
      } else {
        setState(() {
          _state = _AuthState.failed;
          _errorMessage = result.errorMessage ?? 'Unknown error';
        });
      }
    } catch (e) {
      debugPrint('QR_AUTH: Unexpected error during approve: $e');
      if (!mounted) return;
      setState(() {
        _state = _AuthState.failed;
        _errorMessage = 'Unexpected error: $e';
      });
    }
  }

  void _deny() {
    final engine = ref.read(engineProvider).valueOrNull;
    if (engine != null) {
      QrAuthService(engine).deny(widget.payload);
    }
    setState(() => _state = _AuthState.denied);
  }
}
