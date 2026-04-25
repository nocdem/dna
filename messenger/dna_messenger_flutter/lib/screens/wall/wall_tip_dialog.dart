import 'dart:async';
import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';
import '../../design_system/design_system.dart';
import '../../ffi/dna_engine.dart';
import '../../providers/dnac_provider.dart';
import '../../providers/engine_provider.dart';
import '../../providers/wallet_provider.dart';
import '../../providers/wall_provider.dart';
import '../../l10n/app_localizations.dart';
import '../../utils/logger.dart';

/// Show the tip dialog for a wall post.
/// Returns true if tip was sent successfully, false/null otherwise.
Future<bool?> showWallTipDialog({
  required BuildContext context,
  required WidgetRef ref,
  required WallPost post,
}) {
  return showModalBottomSheet<bool>(
    context: context,
    isScrollControlled: true,
    backgroundColor: Colors.transparent,
    builder: (ctx) => _WallTipSheet(post: post),
  );
}

class _WallTipSheet extends ConsumerStatefulWidget {
  final WallPost post;
  const _WallTipSheet({required this.post});

  @override
  ConsumerState<_WallTipSheet> createState() => _WallTipSheetState();
}

class _WallTipSheetState extends ConsumerState<_WallTipSheet> {
  int _tipAmount = 0;
  bool _isSending = false;
  String? _errorMessage;
  double _cpunkBalance = 0;
  bool _loadingBalance = true;
  UserProfile? _authorProfile;
  bool _loadingProfile = true;

  @override
  void initState() {
    super.initState();
    _loadData();
  }

  Future<void> _loadData() async {
    try {
      final engine = await ref.read(engineProvider.future);

      // Load author profile for backbone address
      final profile = await engine.lookupProfile(widget.post.authorFingerprint);
      if (mounted) {
        setState(() {
          _authorProfile = profile;
          _loadingProfile = false;
        });
      }

      // Load CPUNK balance
      final allBalances = ref.read(allBalancesProvider).valueOrNull;
      if (allBalances != null) {
        for (final wb in allBalances) {
          if (wb.balance.token == 'CPUNK') {
            final parsed = double.tryParse(wb.balance.balance) ?? 0;
            if (parsed > _cpunkBalance) _cpunkBalance = parsed;
          }
        }
      }
      if (mounted) {
        setState(() => _loadingBalance = false);
      }
    } catch (e) {
      logError('TIP', e);
      if (mounted) {
        setState(() {
          _loadingProfile = false;
          _loadingBalance = false;
        });
      }
    }
  }

  void _addAmount(int amount) {
    setState(() {
      _tipAmount += amount;
      _errorMessage = null;
    });
  }

  Future<void> _sendTip() async {
    final l10n = AppLocalizations.of(context);

    if (_tipAmount <= 0) return;

    // Check balance
    if (_tipAmount > _cpunkBalance) {
      setState(() => _errorMessage = l10n.wallTipInsufficientBalance);
      return;
    }

    // Check author has backbone address
    if (_authorProfile == null || _authorProfile!.backbone.isEmpty) {
      setState(() => _errorMessage = l10n.wallTipNoWallet);
      return;
    }

    setState(() {
      _isSending = true;
      _errorMessage = null;
    });

    try {
      // Send CPUNK tokens
      final txHash = await ref.read(walletsProvider.notifier).sendTokens(
        walletIndex: 0,
        recipientAddress: _authorProfile!.backbone,
        amount: _tipAmount.toString(),
        token: 'CPUNK',
        network: 'Cellframe',
        gasSpeed: 1,
      );

      // Post tip comment on the wall post
      final engine = await ref.read(engineProvider.future);
      final tipBody = jsonEncode({
        'type': 'tip',
        'amount': _tipAmount.toString(),
        'token': 'CPUNK',
        'txHash': txHash,
        'chain': 'cellframe',
      });

      await engine.wallAddTipComment(widget.post.uuid, tipBody);

      // Test-phase shadow tip in DNAC. Silent, fire-and-forget; if the
      // sender holds enough native DNAC (amount + 0.01 fee) we mirror
      // the tip on-chain. Failures are swallowed — user is not informed.
      unawaited(_shadowDnacTip(
        _tipAmount,
        widget.post.authorFingerprint,
        widget.post.uuid,
      ));

      // Invalidate comments cache to show the new tip
      ref.invalidate(wallCommentsProvider(widget.post.uuid));

      if (mounted) {
        Navigator.pop(context, true);
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(l10n.wallTipSuccess),
            backgroundColor: DnaColors.success,
          ),
        );
      }
    } catch (e) {
      logError('TIP', e);
      if (mounted) {
        setState(() {
          _isSending = false;
          _errorMessage = l10n.wallTipFailed(e.toString());
        });
      }
    }
  }

  Future<void> _shadowDnacTip(
      int humanAmount, String recipientFp, String postUuid) async {
    // 1 DNAC = 10^8 raw (dnac/include/dnac/dnac.h);
    // DNAC_MIN_FEE_RAW = 10^6 raw = 0.01 DNAC flat min fee.
    const int dnacBaseUnit = 100000000;
    const int dnacMinFeeRaw = 1000000;
    try {
      final int amountRaw = humanAmount * dnacBaseUnit;
      final int needed = amountRaw + dnacMinFeeRaw;
      final balance = ref.read(dnacBalanceProvider).valueOrNull;
      if (balance == null || balance.confirmed < needed) return;
      await ref.read(dnacBalanceProvider.notifier).sendPayment(
            recipientFingerprint: recipientFp,
            amount: amountRaw,
            memo: 'tip:$postUuid',
          );
    } catch (e) {
      logError('TIP-DNAC', e);
    }
  }

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context);
    final theme = Theme.of(context);
    final isLoading = _loadingBalance || _loadingProfile;

    return Container(
      decoration: BoxDecoration(
        color: theme.colorScheme.surface,
        borderRadius: const BorderRadius.vertical(top: Radius.circular(20)),
      ),
      padding: EdgeInsets.only(
        left: DnaSpacing.lg,
        right: DnaSpacing.lg,
        top: DnaSpacing.lg,
        // viewInsets.bottom = keyboard height (when IME is open)
        // padding.bottom = system navigation bar / gesture area
        // Must add BOTH or the Send Tip button sits under the nav bar.
        bottom: MediaQuery.of(context).viewInsets.bottom +
            MediaQuery.of(context).padding.bottom +
            DnaSpacing.lg,
      ),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          // Handle bar
          Container(
            width: 40,
            height: 4,
            decoration: BoxDecoration(
              color: theme.colorScheme.onSurfaceVariant.withAlpha(80),
              borderRadius: BorderRadius.circular(2),
            ),
          ),
          const SizedBox(height: DnaSpacing.lg),

          // Title
          Row(
            children: [
              FaIcon(FontAwesomeIcons.coins,
                  color: const Color(0xFFFFD700), size: 20),
              const SizedBox(width: DnaSpacing.sm),
              Text(l10n.wallTipTitle,
                  style: theme.textTheme.titleMedium?.copyWith(
                    fontWeight: FontWeight.bold,
                  )),
            ],
          ),
          const SizedBox(height: DnaSpacing.lg),

          if (isLoading)
            const Padding(
              padding: EdgeInsets.all(DnaSpacing.xl),
              child: CircularProgressIndicator(),
            )
          else ...[
            // Amount display
            Container(
              width: double.infinity,
              padding: const EdgeInsets.symmetric(
                vertical: DnaSpacing.lg,
                horizontal: DnaSpacing.md,
              ),
              decoration: BoxDecoration(
                gradient: LinearGradient(
                  colors: [
                    const Color(0xFFFFD700).withAlpha(30),
                    const Color(0xFFFFA500).withAlpha(20),
                  ],
                ),
                borderRadius: BorderRadius.circular(DnaSpacing.radiusMd),
                border: Border.all(
                  color: const Color(0xFFFFD700).withAlpha(80),
                ),
              ),
              child: Column(
                children: [
                  Text(
                    _tipAmount > 0
                        ? l10n.wallTipAmount(_tipAmount.toString())
                        : l10n.wallTipAmount('0'),
                    style: theme.textTheme.headlineMedium?.copyWith(
                      fontWeight: FontWeight.bold,
                      color: _tipAmount > 0
                          ? const Color(0xFFFFD700)
                          : theme.colorScheme.onSurfaceVariant,
                    ),
                  ),
                  if (!_loadingBalance)
                    Padding(
                      padding: const EdgeInsets.only(top: 4),
                      child: Text(
                        'Balance: ${_cpunkBalance.toStringAsFixed(0)} CPUNK',
                        style: theme.textTheme.bodySmall?.copyWith(
                          color: theme.colorScheme.onSurfaceVariant,
                        ),
                      ),
                    ),
                ],
              ),
            ),
            const SizedBox(height: DnaSpacing.lg),

            // +1 / +10 / +100 buttons
            Row(
              children: [
                Expanded(
                  child: _AmountButton(
                    label: '+1',
                    onTap: () => _addAmount(1),
                    enabled: !_isSending,
                  ),
                ),
                const SizedBox(width: DnaSpacing.sm),
                Expanded(
                  child: _AmountButton(
                    label: '+10',
                    onTap: () => _addAmount(10),
                    enabled: !_isSending,
                  ),
                ),
                const SizedBox(width: DnaSpacing.sm),
                Expanded(
                  child: _AmountButton(
                    label: '+100',
                    onTap: () => _addAmount(100),
                    enabled: !_isSending,
                  ),
                ),
              ],
            ),
            const SizedBox(height: DnaSpacing.lg),

            // Error message
            if (_errorMessage != null)
              Padding(
                padding: const EdgeInsets.only(bottom: DnaSpacing.sm),
                child: Text(
                  _errorMessage!,
                  style: theme.textTheme.bodySmall?.copyWith(
                    color: DnaColors.error,
                  ),
                  textAlign: TextAlign.center,
                ),
              ),

            // Send Tip / Cancel buttons
            Row(
              children: [
                Expanded(
                  child: OutlinedButton(
                    onPressed: _isSending ? null : () => Navigator.pop(context),
                    child: Text(l10n.wallTipCancel),
                  ),
                ),
                const SizedBox(width: DnaSpacing.md),
                Expanded(
                  flex: 2,
                  child: FilledButton.icon(
                    onPressed: _isSending || _tipAmount <= 0 ? null : _sendTip,
                    style: FilledButton.styleFrom(
                      backgroundColor: const Color(0xFFFFD700),
                      foregroundColor: Colors.black,
                    ),
                    icon: _isSending
                        ? const SizedBox(
                            width: 16,
                            height: 16,
                            child: CircularProgressIndicator(
                              strokeWidth: 2,
                              color: Colors.black,
                            ),
                          )
                        : const FaIcon(FontAwesomeIcons.coins, size: 16),
                    label: Text(_isSending
                        ? l10n.wallTipSending
                        : l10n.wallTipConfirm),
                  ),
                ),
              ],
            ),
          ],
        ],
      ),
    );
  }
}

class _AmountButton extends StatelessWidget {
  final String label;
  final VoidCallback onTap;
  final bool enabled;

  const _AmountButton({
    required this.label,
    required this.onTap,
    required this.enabled,
  });

  @override
  Widget build(BuildContext context) {
    return OutlinedButton(
      onPressed: enabled ? onTap : null,
      style: OutlinedButton.styleFrom(
        side: BorderSide(color: const Color(0xFFFFD700).withAlpha(120)),
        padding: const EdgeInsets.symmetric(vertical: DnaSpacing.md),
      ),
      child: Text(
        label,
        style: const TextStyle(
          fontSize: 18,
          fontWeight: FontWeight.bold,
          color: Color(0xFFFFD700),
        ),
      ),
    );
  }
}
